//! The move's copy from tenant 0's frozen D1 into the owner's root unit:
//! every imported table arrives row for row (the §3.2 changes aside), the
//! canary's rows stay behind, pages are bounded, and a crash or a lost
//! answer resumes from the unit's own progress.

mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use service_support::*;
use velmora_bridge::directory::fence::freeze;
use velmora_bridge::directory::move_copy::{
    bound, copy_all, key_columns, move_ordinal, seal, CopyError, CopyPlan, RowTransform, SealState,
    Sealed, TableCopy, UnitImport,
};
use velmora_bridge::directory::record::{Tenant, TenantRecord};
use velmora_bridge::directory::transition::{next, Actor, Change, Outcome, KEY_CHECK_LEN};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::import::{ImportBatch, ImportTable, ImportValue, Imported, MoveHead};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantState, Unit, UnitAnswer,
    UnitCall, UnitName, UnitOp,
};
use velmora_bridge::*;

const OWNER: &str = "t_00000000000000a1";
const UNIT_NOW: UnixMs = UnixMs(1_795_000_000_000);

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// A database call of the in-memory store, which never waits.
fn ready<F: std::future::Future>(f: F) -> F::Output {
    velmora_bridge::unit::object::poll_once(f).expect("an in-memory call is ready at once")
}

// ---------------------------------------------------------------------------
// The two heads
// ---------------------------------------------------------------------------

fn step(
    tenant: &Tenant,
    head: Option<&TenantRecord>,
    change: Change,
    actor: Actor,
) -> TenantRecord {
    match next(tenant, head, &change, actor, UNIT_NOW) {
        Ok(Outcome::Next(r)) => r,
        other => panic!("{other:?}"),
    }
}

/// Tenant 0 `moving` into the owner, and the owner's head with a
/// `restoring` entry for unit 0 at seq 5.
fn heads() -> (TenantRecord, TenantRecord) {
    let zero = Tenant::zero();
    let z = step(
        &zero,
        None,
        Change::CreateTenantZero {
            jurisdiction: "us".into(),
        },
        Actor::Operator,
    );
    let owner = Tenant::parse(OWNER).unwrap();
    let z = step(
        &zero,
        Some(&z),
        Change::StartMove {
            to: owner.clone(),
            catalogue_id_frozen: "main".into(),
        },
        Actor::MoveTool,
    );
    let mut o = step(
        &owner,
        None,
        Change::Create {
            jurisdiction: "us".into(),
            location_hint: None,
            synthetic: false,
            limits: Default::default(),
            rate_json: Default::default(),
            features_json: Default::default(),
        },
        Actor::TenantCreation,
    );
    for change in [
        Change::ClaimKeyVersion { version: 1 },
        Change::CommitKeyVersion {
            version: 1,
            kcv: [1; KEY_CHECK_LEN],
        },
        Change::Activate { external_ref: None },
    ] {
        o = step(&owner, Some(&o), change, Actor::TenantCreation);
    }
    let o = step(
        &owner,
        Some(&o),
        Change::SetRestoring { unit: 0 },
        Actor::Operator,
    );
    (z, o)
}

// ---------------------------------------------------------------------------
// The owner's unit
// ---------------------------------------------------------------------------

fn unit_name() -> UnitName {
    UnitName::new(velmora_bridge::unit::TenantId::parse(OWNER).unwrap(), 0)
}

fn worker(u: &Unit<RusqliteSql>, seqs: Option<Seqs>, op: UnitOp) -> UnitAnswer {
    u.handle(
        &UnitCall {
            name: unit_name(),
            kind: CallKind::Worker,
            seqs,
            authenticated: true,
            listed: true,
            op,
        },
        UNIT_NOW,
    )
}

fn seqs(state_seq: u64) -> Option<Seqs> {
    Some(Seqs {
        state_seq,
        keys_seq: 0,
    })
}

fn sync(u: &Unit<RusqliteSql>, state_seq: u64, restoring: Option<u64>) {
    let a = worker(
        u,
        None,
        UnitOp::Sync {
            head: SyncHead {
                seqs: Seqs {
                    state_seq,
                    keys_seq: 0,
                },
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: restoring,
                lift: None,
            },
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
}

/// The owner's root unit, born at seq 3 and closed for the move at the
/// owner head's `restoring` entry.
fn unit(since: u64) -> Unit<RusqliteSql> {
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), unit_name(), "");
    let token = BirthToken {
        name: unit_name(),
        jurisdiction: String::new(),
        record_seq: 3,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: 2,
        kind: BirthKind::Birth,
    };
    let a = worker(
        &u,
        seqs(3),
        UnitOp::Provision {
            token,
            sealed: b"sealed".to_vec(),
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    sync(&u, 3, None);
    sync(&u, since, Some(since));
    u
}

/// The Worker's side of the import: one call per batch, with faults.
/// `(ordinal, since, tables)` of a seal.
type SealCall = (u64, u64, Vec<(ImportTable, u64)>);

struct Adapter<'a> {
    unit: &'a Unit<RusqliteSql>,
    state_seq: u64,
    /// The next N imports are applied and then answer an error.
    lose: Cell<u32>,
    /// After this many more imports, every import fails unapplied.
    fail_after: Cell<Option<u32>>,
    imports: Cell<u32>,
    /// Batches the unit answered as applied before (sent again).
    resent: Cell<u32>,
    /// Imports per table.
    by_table: RefCell<BTreeMap<String, u32>>,
    /// The Nth import of this table fails unapplied (`false`) or is
    /// applied with its answer lost (`true`).
    fault: RefCell<Option<(String, u32, bool)>>,
    /// The seal the unit took: `(ordinal, since, tables)`. The unit call
    /// is L1's (AM-29); this stands in for it with the rule it states.
    sealed: RefCell<Option<SealCall>>,
    /// Seal answers to lose (the seal lands, the answer does not).
    lose_seal: Cell<u32>,
    seals: Cell<u32>,
}

impl<'a> Adapter<'a> {
    fn new(unit: &'a Unit<RusqliteSql>, state_seq: u64) -> Self {
        Adapter {
            unit,
            state_seq,
            lose: Cell::new(0),
            fail_after: Cell::new(None),
            imports: Cell::new(0),
            resent: Cell::new(0),
            by_table: RefCell::new(BTreeMap::new()),
            fault: RefCell::new(None),
            sealed: RefCell::new(None),
            lose_seal: Cell::new(0),
            seals: Cell::new(0),
        }
    }
}

impl UnitImport for Adapter<'_> {
    async fn import(&self, head: &MoveHead, since: u64, batch: &ImportBatch) -> Result<Imported> {
        if let Some(n) = self.fail_after.get() {
            if n == 0 {
                return Err(BridgeError::Blob("unit unreachable".into()));
            }
            self.fail_after.set(Some(n - 1));
        }
        let mut lose_this = false;
        {
            let mut fault = self.fault.borrow_mut();
            if let Some((table, n, lose)) = fault.as_mut() {
                if table == batch.table.name() {
                    if *n == 0 {
                        let lose = *lose;
                        *fault = None;
                        if !lose {
                            return Err(BridgeError::Blob("unit unreachable".into()));
                        }
                        lose_this = true;
                    } else {
                        *n -= 1;
                    }
                }
            }
        }
        self.imports.set(self.imports.get() + 1);
        *self
            .by_table
            .borrow_mut()
            .entry(batch.table.name().to_string())
            .or_default() += 1;
        let a = worker(
            self.unit,
            seqs(self.state_seq),
            UnitOp::Import {
                head: head.clone(),
                since,
                batch: batch.clone(),
            },
        );
        let answer = match a {
            UnitAnswer::Ok { body, .. } => {
                if body["applied"] == false {
                    self.resent.set(self.resent.get() + 1);
                }
                Imported::Done {
                    cursor: body["cursor"].as_str().unwrap().to_string(),
                    rows: body["rows"].as_u64().unwrap(),
                    applied: body["applied"].as_bool().unwrap(),
                }
            }
            UnitAnswer::Refused {
                reason: Refused::Import(r),
                ..
            } => Imported::Refused(r),
            other => panic!("{other:?}"),
        };
        if self.lose.get() > 0 || lose_this {
            self.lose.set(self.lose.get().saturating_sub(1));
            return Err(BridgeError::Blob("answer lost".into()));
        }
        Ok(answer)
    }

    async fn progress(&self) -> Result<Vec<(String, String, u64)>> {
        let a = worker(self.unit, seqs(self.state_seq), UnitOp::ImportProgress {});
        let UnitAnswer::Ok { body, .. } = a else {
            panic!("{a:?}")
        };
        Ok(body["tables"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["table"].as_str().unwrap().to_string(),
                    t["cursor"].as_str().unwrap().to_string(),
                    t["rows"].as_u64().unwrap(),
                )
            })
            .collect())
    }

    async fn seal(
        &self,
        _head: &MoveHead,
        ordinal: u64,
        since: u64,
        tables: &[(ImportTable, u64)],
    ) -> Result<Sealed> {
        self.seals.set(self.seals.get() + 1);
        // AM-29: every count equals the unit's own (a table with no
        // import row counts 0), and every import table is named once.
        let progress = self.progress().await?;
        let named: BTreeSet<&str> = tables.iter().map(|(t, _)| t.name()).collect();
        if named.len() != ImportTable::ALL.len() || tables.len() != named.len() {
            return Ok(Sealed::Refused("tables".into()));
        }
        for (table, rows) in tables {
            let unit = progress
                .iter()
                .find(|(t, _, _)| t == table.name())
                .map_or(0, |(_, _, n)| *n);
            if unit != *rows {
                return Ok(Sealed::Refused("count_mismatch".into()));
            }
        }
        let mut sealed = self.sealed.borrow_mut();
        match &*sealed {
            Some((o, s, t)) if (*o, *s, t.as_slice()) != (ordinal, since, tables) => {
                return Ok(Sealed::Refused("sealed".into()))
            }
            _ => *sealed = Some((ordinal, since, tables.to_vec())),
        }
        if self.lose_seal.get() > 0 {
            self.lose_seal.set(self.lose_seal.get() - 1);
            return Err(BridgeError::Blob("answer lost".into()));
        }
        Ok(Sealed::Done)
    }

    async fn seal_state(&self) -> Result<Option<SealState>> {
        Ok(self.sealed.borrow().as_ref().map(|(o, _, t)| SealState {
            move_ordinal: *o,
            tables: t.clone(),
        }))
    }
}

/// The key lane's changes, stood in for: a scheme-2 first byte on the
/// bucket key and the owner's principal; one extent's safety copy
/// re-homed.
struct Stub {
    rehomed: Option<String>,
}

const PRINCIPAL: &str = "p_owner";

impl RowTransform for Stub {
    fn bucket(&self, row: &[ImportValue]) -> Result<Vec<ImportValue>> {
        let mut row = row.to_vec();
        row[2] = ImportValue::Text(PRINCIPAL.into());
        if let ImportValue::Blob(b) = &mut row[3] {
            b[0] = 0x02;
        }
        Ok(row)
    }

    fn rehomed(&self, extent_id: &str) -> (bool, bool) {
        (self.rehomed.as_deref() == Some(extent_id), false)
    }
}

// ---------------------------------------------------------------------------
// The frozen catalogue
// ---------------------------------------------------------------------------

/// A catalogue with rows in every imported table, in two buckets, the
/// second the canary; then frozen.
async fn catalogue(rig: &Rig) -> (Bucket, Bucket) {
    catalogue_with_lease(rig, 1).await
}

async fn catalogue_with_lease(rig: &Rig, lease_until: i64) -> (Bucket, Bucket) {
    catalogue_with(rig, lease_until, 5, false, 0..23).await
}

/// As [`catalogue`], the vault's first outbox row leased until
/// `lease_until`, and the live counters' hour under way at `hour` (its
/// filed row dropped first when `own_row`).
async fn catalogue_with(
    rig: &Rig,
    lease_until: i64,
    hour: i64,
    own_row: bool,
    hours: std::ops::Range<i64>,
) -> (Bucket, Bucket) {
    let (vault, signer) = rig.standard("vault").await;
    let canary = rig.bucket("mq-canary", false).await;
    rig.grant(AKID, &canary, Perm::Rw).await;
    for (bucket, key, n) in [
        ("vault", "a.bin", 1_000usize),
        ("vault", "dir/b.bin", 300_000),
        ("vault", "dir/c.bin", 20),
        ("mq-canary", "probe", 50),
        ("mq-canary", "probe-2", 60),
        ("mq-canary", "probe-3", 70),
    ] {
        rig.put(&signer, bucket, key, &pattern(n as u8, n))
            .await
            .expect(200);
    }
    let sql = &rig.bridge.catalog.sql.inner;
    let (xv, xc) = (first_extent(sql, &vault), first_extent(sql, &canary));
    let (bv, bc) = (
        vault.id.as_str().to_string(),
        canary.id.as_str().to_string(),
    );
    let mut script = String::new();
    for (x, i) in [(&xv, 0), (&xv, 1), (&xc, 0)] {
        script.push_str(&format!(
            "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, cipher_offset, \
             cipher_len, payload_sha256, state, provider_id, posted_at, yenc_name) VALUES \
             ('{x}', {i}, 'm{i}-{x}', 'alt.binaries.test', x'0102', {i}, 10, x'aa', 'posted', 'p0', 5, NULL);\n"
        ));
    }
    for (x, at) in [(&xv, 7), (&xv, 8), (&xc, 7)] {
        script.push_str(&format!(
            "INSERT INTO verifications(extent_id, backbone, provider_id, verified_at, plan_rev, \
             articles_ok, articles_total, result) VALUES ('{x}', 'alpha', 'p0', {at}, 1, 2, 2, 'ok');\n"
        ));
    }
    script.push_str(&format!(
        "INSERT INTO verify_raises(extent_id, backbone, plan_rev, raised_at) VALUES ('{xv}', 'alpha', 1, 9);\n\
         INSERT INTO verify_escalations(backbone, until, raised_at, extent_id, result) VALUES ('alpha', 99, 9, '{xc}', 'missing');\n\
         INSERT INTO gc(id, extent_id, action, due_at) VALUES (1, '{xv}', 'delete_cache', 50), (2, '{xc}', 'delete_cache', 50);\n\
         INSERT INTO usage_recounts(id, started_at, finished_at, rows, adopted, drift, detail) VALUES (1, 1, 2, 3, 0, 0, NULL);\n\
         INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, initiated_at) VALUES \
           ('u_v', '{bv}', 'up.bin', '{{}}', '{{}}', 'open', 3), ('u_c', '{bc}', 'up.bin', '{{}}', '{{}}', 'open', 3), \
           ('u_a', '{bv}', 'up.bin', '{{}}', '{{}}', 'open', 3), ('u_c1', '{bc}', 'up.bin', '{{}}', '{{}}', 'open', 3), \
           ('u_c2', '{bc}', 'up.bin', '{{}}', '{{}}', 'open', 3);\n\
         INSERT INTO upload_parts(upload_id, part_number, extent_id, size, etag, uploaded_at) VALUES \
           ('u_v', 1, '{xv}', 5, 'e1', 4), ('u_v', 2, '{xv}', 5, 'e2', 4), ('u_c', 1, '{xc}', 5, 'e1', 4);\n\
         INSERT INTO upload_part_extents(upload_id, part_number, piece, extent_id) VALUES \
           ('u_v', 1, 1, '{xv}'), ('u_c', 1, 1, '{xc}');\n\
         UPDATE outbox SET lease_token = 7, lease_owner = 'gone-worker', lease_until = {lease_until} WHERE extent_id = '{xv}';\n"
    ));
    // The longest key, of the characters JSON escapes: its cursor is
    // more than twice its length.
    script.push_str(&format!(
        "INSERT INTO generations(id, bucket_id, key, state, size, etag, content_json, user_meta_json, \
         extent_count, created_at) VALUES ('g_long', '{bv}', '{LONG}', 'live', 0, '\"e\"', '{{}}', '{{}}', 0, 1);\n\
         INSERT INTO objects(bucket_id, key, generation_id) VALUES ('{bv}', '{LONG}', 'g_long');\n",
        LONG = long_key()
    ));
    // Enough hours for many pages.
    for h in hours {
        script.push_str(&format!(
            "INSERT INTO usage_hours(hour, posts, verifies, releases, dead, failures) VALUES ({h}, {h}, 0, 0, 0, 0);\n"
        ));
    }
    // The canary's extents in each safety state, its outbox rows in two
    // stages (for the excluded sums).
    script.push_str(&format!(
        "UPDATE extents SET safety_state = 'released' WHERE id = (SELECT id FROM extents \
           WHERE bucket_id = '{bc}' ORDER BY id LIMIT 1 OFFSET 1);\n\
         UPDATE extents SET safety_state = 'deleted' WHERE id = (SELECT id FROM extents \
           WHERE bucket_id = '{bc}' ORDER BY id LIMIT 1 OFFSET 2);\n\
         UPDATE outbox SET stage = 'done' WHERE extent_id = (SELECT id FROM extents \
           WHERE bucket_id = '{bc}' ORDER BY id LIMIT 1 OFFSET 1);\n"
    ));
    // Set last: an outbox update of a later hour files the hour under
    // way (the counters are on in this schema).
    script.push_str(&format!(
        "UPDATE usage_global SET hour = {hour}, h_posts = 7, h_failures = 1 WHERE id = 1;\n"
    ));
    if own_row {
        script.push_str(&format!("DELETE FROM usage_hours WHERE hour = {hour};\n"));
    }
    sql.apply(&script).unwrap();
    rig.bridge.raise_stamp().await.unwrap();
    freeze(&rig.bridge.catalog.sql, 1).await.unwrap();
    (vault, canary)
}

/// 1024 bytes of `"` and `\`.
fn long_key() -> String {
    "\"\\".repeat(512)
}

fn rows(sql: &RusqliteSql, table: ImportTable) -> Vec<Vec<SqlValue>> {
    let cols: Vec<String> = table.columns().iter().map(|c| format!("\"{c}\"")).collect();
    let keys: Vec<String> = key_columns(table)
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect();
    let q = format!(
        "SELECT {} FROM \"{}\" ORDER BY {}",
        cols.join(", "),
        table.name(),
        keys.join(", ")
    );
    ready(sql.query(&q, &[])).unwrap()
}

/// Every id that belongs to the canary, found by plain queries (not the
/// copy's own joins).
fn canary_ids(sql: &RusqliteSql, canary: &Bucket) -> BTreeSet<String> {
    let mut ids = BTreeSet::from([canary.id.as_str().to_string()]);
    for q in [
        "SELECT id FROM generations WHERE bucket_id = ?1",
        "SELECT id FROM extents WHERE bucket_id = ?1",
        "SELECT id FROM uploads WHERE bucket_id = ?1",
    ] {
        for r in ready(sql.query(q, &[SqlValue::Text(canary.id.as_str().into())])).unwrap() {
            if let SqlValue::Text(id) = &r[0] {
                ids.insert(id.clone());
            }
        }
    }
    ids
}

/// The frozen rows the unit should hold: the canary's left out, the §3.2
/// changes made as the stub makes them.
fn expected(
    sql: &RusqliteSql,
    table: ImportTable,
    canary: &BTreeSet<String>,
    rehomed: &str,
) -> Vec<Vec<SqlValue>> {
    let cols = table.columns();
    let at = |name: &str| cols.iter().position(|c| *c == name);
    let theirs = |row: &[SqlValue]| {
        let by = |name: &str| {
            at(name).is_some_and(|i| matches!(&row[i], SqlValue::Text(v) if canary.contains(v)))
        };
        match table {
            ImportTable::Buckets => by("id"),
            ImportTable::VerifyEscalations
            | ImportTable::UsageHours
            | ImportTable::UsageRecounts => false,
            _ => by("bucket_id") || by("generation_id") || by("extent_id") || by("upload_id"),
        }
    };
    let mut all = rows(sql, table);
    if table == ImportTable::UsageHours {
        // The hour under way, filed as `usage::off` files it.
        let g = ready(sql.query(
            "SELECT hour, h_posts, h_verifies, h_releases, h_dead, h_failures FROM usage_global WHERE id = 1",
            &[],
        ))
        .unwrap();
        let int = |v: &SqlValue| match v {
            SqlValue::Int(n) => *n,
            other => panic!("{other:?}"),
        };
        let g: Vec<i64> = g[0].iter().map(int).collect();
        if g[0] > 0 && g[1..].iter().sum::<i64>() > 0 {
            match all.iter_mut().find(|r| int(&r[0]) == g[0]) {
                Some(r) => {
                    for i in 1..6 {
                        r[i] = SqlValue::Int(int(&r[i]) + g[i]);
                    }
                }
                None => {
                    all.push(g.iter().map(|n| SqlValue::Int(*n)).collect());
                    all.sort_by_key(|r| int(&r[0]));
                }
            }
        }
    }
    all.into_iter()
        .filter(|r| !theirs(r))
        .map(|mut r| {
            match table {
                ImportTable::Buckets => {
                    r[2] = SqlValue::Text(PRINCIPAL.into());
                    if let SqlValue::Blob(b) = &mut r[3] {
                        b[0] = 0x02;
                    }
                }
                ImportTable::Extents => {
                    let id = &r[0];
                    if !matches!(id, SqlValue::Text(x) if x == rehomed) {
                        r[at("hot_safety_bytes").unwrap()] = SqlValue::Int(0);
                    }
                    r[at("hot_cache_bytes").unwrap()] = SqlValue::Int(0);
                }
                ImportTable::Outbox => {
                    r[at("lease_owner").unwrap()] = SqlValue::Null;
                    r[at("lease_until").unwrap()] = SqlValue::Null;
                }
                _ => {}
            }
            r
        })
        .collect()
}

fn first_extent(sql: &RusqliteSql, bucket: &Bucket) -> String {
    let r = ready(sql.query(
        "SELECT id FROM extents WHERE bucket_id = ?1 ORDER BY id LIMIT 1",
        &[SqlValue::Text(bucket.id.as_str().into())],
    ))
    .unwrap();
    match &r[0][0] {
        SqlValue::Text(id) => id.clone(),
        other => panic!("{other:?}"),
    }
}

fn plan(canary: &Bucket, page: usize) -> CopyPlan {
    CopyPlan {
        excluded: BTreeSet::from([canary.id.as_str().to_string()]),
        page,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn every_table_arrives_row_for_row_without_the_canary() {
    block_on(async {
        let rig = rig();
        let (vault, canary) = catalogue(&rig).await;
        let frozen = &rig.bridge.catalog.sql.inner;
        let (zero, owner) = heads();
        let (head, since) = bound(&zero.door, &owner.door).expect("bound");
        let u = unit(since);
        let adapter = Adapter::new(&u, since);
        let rehomed = first_extent(frozen, &vault);
        let stub = Stub {
            rehomed: Some(rehomed.clone()),
        };
        // Pages of 2 rows: every table takes several, and some pages
        // hold only canary rows.
        let done = copy_all(
            &rig.bridge.catalog.sql,
            &adapter,
            &stub,
            &plan(&canary, 2),
            &head,
            since,
            rig.now(),
        )
        .await
        .map_err(|e| format!("{e:?}"))
        .unwrap();
        let ids = canary_ids(frozen, &canary);
        for table in ImportTable::ALL {
            let want = expected(frozen, table, &ids, &rehomed);
            assert!(!want.is_empty(), "no rows to copy in {}", table.name());
            assert_eq!(rows(u.sql(), table), want, "{}", table.name());
            let d = done.iter().find(|d| d.table == table.name()).unwrap();
            assert_eq!(d.sent, want.len() as u64, "{}", table.name());
            assert_eq!(d.read, d.sent + d.excluded, "{}", table.name());
            assert_eq!(d.unit_rows, d.sent, "{}", table.name());
        }
        let by = |t: &str| done.iter().find(|d| d.table == t).unwrap().clone();
        assert!(!rows(frozen, ImportTable::Buckets).is_empty());
        assert_eq!(by("buckets").excluded, 1);
        assert_eq!(by("articles").excluded, 1);
        assert_eq!(by("upload_parts").excluded, 1);
        assert_eq!(by("verify_escalations").excluded, 0);
        assert_eq!(by("outbox").leases_cleared, 1);
        // The cleared lease kept its fencing token.
        let token = ready(u.sql().query(
            "SELECT lease_token, lease_owner FROM outbox WHERE lease_token = 7",
            &[],
        ))
        .unwrap();
        assert_eq!(token, vec![vec![SqlValue::Int(7), SqlValue::Null]]);
        assert_eq!(by("usage_hours").sent, 23);
        // Uploads sort u_a (vault), u_c, u_c1, u_c2 (canary), u_v (vault):
        // by 2, the middle page holds canary rows only and sends nothing,
        // and the last batch follows the first.
        assert_eq!((by("uploads").sent, by("uploads").excluded), (2, 3));
        assert_eq!(adapter.by_table.borrow()["uploads"], 2);
        // The longest key arrived.
        assert!(rows(u.sql(), ImportTable::Objects)
            .iter()
            .any(|r| r[1] == SqlValue::Text(long_key())));
        // The frozen D1 did not change: it still has every canary row.
        assert_eq!(rows(frozen, ImportTable::Buckets).len(), 2);
        // A second run sends nothing more.
        let again = copy_all(
            &rig.bridge.catalog.sql,
            &adapter,
            &stub,
            &plan(&canary, 2),
            &head,
            since,
            rig.now(),
        )
        .await
        .map_err(|e| format!("{e:?}"))
        .unwrap();
        assert!(again.iter().all(|d| d.sent == 0), "{again:?}");
        // The seal after the last batch, with the counts of every table;
        // the second run's answer (no batch sent) gives the same counts.
        let ordinal = move_ordinal(&zero.door).expect("moving");
        assert_eq!(ordinal, 1);
        seal(&adapter, &head, ordinal, since, &done)
            .await
            .map_err(|e| format!("{e:?}"))
            .unwrap();
        adapter.lose_seal.set(1);
        seal(&adapter, &head, ordinal, since, &again)
            .await
            .map_err(|e| format!("{e:?}"))
            .unwrap();
        let sealed = adapter.sealed.borrow().clone().unwrap();
        assert_eq!(sealed.2.len(), ImportTable::ALL.len());
        for (table, rows) in &sealed.2 {
            assert_eq!(*rows, rows_of(&done, *table), "{}", table.name());
        }
    });
}

fn rows_of(done: &[TableCopy], table: ImportTable) -> u64 {
    done.iter()
        .find(|d| d.table == table.name())
        .unwrap()
        .unit_rows
}

#[test]
fn the_seal_names_every_table_with_the_units_count() {
    block_on(async {
        let rig = rig();
        let (_, canary) = catalogue(&rig).await;
        let (zero, owner) = heads();
        let (head, since) = bound(&zero.door, &owner.door).unwrap();
        let u = unit(since);
        let adapter = Adapter::new(&u, since);
        let done = copy_all(
            &rig.bridge.catalog.sql,
            &adapter,
            &Stub { rehomed: None },
            &plan(&canary, 7),
            &head,
            since,
            rig.now(),
        )
        .await
        .map_err(|e| format!("{e:?}"))
        .unwrap();
        // A run that did not reach every table cannot seal.
        let short: Vec<TableCopy> = done[..done.len() - 1].to_vec();
        let r = seal(&adapter, &head, 1, since, &short).await;
        assert!(matches!(r, Err(CopyError::Incomplete)), "{r:?}");
        let mut twice = done.clone();
        twice.push(done[0].clone());
        let r = seal(&adapter, &head, 1, since, &twice).await;
        assert!(matches!(r, Err(CopyError::Incomplete)), "{r:?}");
        assert_eq!(adapter.seals.get(), 0);
        // A count the unit does not hold: refused, the import stays open.
        let mut off = done.clone();
        off[2].unit_rows += 1;
        let r = seal(&adapter, &head, 1, since, &off).await;
        assert!(
            matches!(&r, Err(CopyError::SealRefused(c)) if c == "count_mismatch"),
            "{r:?}"
        );
        assert!(adapter.sealed.borrow().is_none());
        // Lost answers are sent again, up to the tries.
        adapter.lose_seal.set(3);
        let r = seal(&adapter, &head, 1, since, &done).await;
        assert!(matches!(r, Err(CopyError::Store(_))), "{r:?}");
        assert_eq!(adapter.seals.get(), 4);
        seal(&adapter, &head, 1, since, &done).await.unwrap();
        // A repeat under a later restoring entry (AM-15's re-entry, which
        // the seal survives) is refused by the unit and found done.
        let before = adapter.seals.get();
        seal(&adapter, &head, 1, since + 1, &done).await.unwrap();
        assert_eq!(adapter.seals.get(), before + 1);
        // Sealed under another ordinal: not this window's import.
        let r = seal(&adapter, &head, 2, since + 1, &done).await;
        assert!(
            matches!(&r, Err(CopyError::SealRefused(c)) if c == "sealed"),
            "{r:?}"
        );
        // The ordinal is only a moving head's.
        let mut d1 = zero.clone();
        d1.door.tenant_zero.as_mut().unwrap().selector =
            velmora_bridge::directory::record::Selector::D1;
        assert_eq!(move_ordinal(&d1.door), None);
        assert_eq!(move_ordinal(&owner.door), None);
    });
}

#[test]
fn a_crash_or_a_lost_answer_resumes_from_the_units_progress() {
    block_on(async {
        let rig = rig();
        let (_, canary) = catalogue(&rig).await;
        let frozen = &rig.bridge.catalog.sql.inner;
        let (zero, owner) = heads();
        let (head, since) = bound(&zero.door, &owner.door).unwrap();
        let u = unit(since);
        let adapter = Adapter::new(&u, since);
        let stub = Stub { rehomed: None };
        // A lost answer: the batch was applied; sent again, it changes
        // nothing.
        adapter.lose.set(2);
        // Then the unit goes away after 9 more imports.
        adapter.fail_after.set(Some(11));
        let crashed = copy_all(
            &rig.bridge.catalog.sql,
            &adapter,
            &stub,
            &plan(&canary, 3),
            &head,
            since,
            rig.now(),
        )
        .await;
        assert!(matches!(crashed, Err(CopyError::Store(_))), "{crashed:?}");
        // Both lost answers were sent again and taken as applied before.
        assert_eq!(adapter.resent.get(), 2);
        assert_eq!(adapter.imports.get(), 11);
        let partial: usize = ImportTable::ALL
            .iter()
            .map(|t| rows(u.sql(), *t).len())
            .sum();
        assert!(partial > 0);
        adapter.fail_after.set(None);
        copy_all(
            &rig.bridge.catalog.sql,
            &adapter,
            &stub,
            &plan(&canary, 4),
            &head,
            since,
            rig.now(),
        )
        .await
        .map_err(|e| format!("{e:?}"))
        .unwrap();
        let ids = canary_ids(frozen, &canary);
        for table in ImportTable::ALL {
            assert_eq!(
                rows(u.sql(), table),
                expected(frozen, table, &ids, ""),
                "{}",
                table.name()
            );
        }
    });
}

#[test]
fn the_copy_runs_only_bound_to_the_move() {
    let (zero, owner) = heads();
    assert!(bound(&zero.door, &owner.door).is_some());
    // The owner's head before its restoring entry.
    let mut open = owner.clone();
    open.door.restoring.clear();
    assert!(bound(&zero.door, &open.door).is_none());
    // Tenant 0 not moving, or moving elsewhere.
    let mut d1 = zero.clone();
    d1.door.tenant_zero.as_mut().unwrap().moved = None;
    assert!(bound(&d1.door, &owner.door).is_none());
    let mut other = owner.clone();
    other.door.tenant = Tenant::parse("t_00000000000000b2").unwrap();
    assert!(bound(&zero.door, &other.door).is_none());
    // The unit refuses a head it was not bound to, and the copy stops.
    block_on(async {
        let rig = rig();
        let (_, canary) = catalogue(&rig).await;
        let (head, since) = bound(&zero.door, &owner.door).unwrap();
        let u = unit(since);
        let adapter = Adapter::new(&u, since);
        let stale = MoveHead {
            selector: "d1".into(),
            ..head
        };
        let r = copy_all(
            &rig.bridge.catalog.sql,
            &adapter,
            &Stub { rehomed: None },
            &plan(&canary, 500),
            &stale,
            since,
            rig.now(),
        )
        .await;
        assert!(
            matches!(
                r,
                Err(CopyError::Refused {
                    table: ImportTable::Buckets,
                    ..
                })
            ),
            "{r:?}"
        );
        assert!(rows(u.sql(), ImportTable::Buckets).is_empty());
    });
}

#[test]
fn a_live_lease_stops_the_copy_before_the_outbox() {
    block_on(async {
        let rig = rig();
        let (_, canary) = catalogue_with_lease(&rig, rig.now().0 + 60_000).await;
        let (zero, owner) = heads();
        let (head, since) = bound(&zero.door, &owner.door).unwrap();
        let u = unit(since);
        let adapter = Adapter::new(&u, since);
        let r = copy_all(
            &rig.bridge.catalog.sql,
            &adapter,
            &Stub { rehomed: None },
            &plan(&canary, 500),
            &head,
            since,
            rig.now(),
        )
        .await;
        assert!(matches!(r, Err(CopyError::LiveLease)), "{r:?}");
        assert!(rows(u.sql(), ImportTable::Outbox).is_empty());
        // The tables before the outbox were copied; a run after the
        // drain finishes goes on from there.
        assert!(!rows(u.sql(), ImportTable::Extents).is_empty());
    });
}

#[test]
fn a_lease_that_ends_now_is_still_live() {
    block_on(async {
        let rig = rig();
        let (_, canary) = catalogue_with_lease(&rig, rig.now().0).await;
        let (zero, owner) = heads();
        let (head, since) = bound(&zero.door, &owner.door).unwrap();
        let u = unit(since);
        let adapter = Adapter::new(&u, since);
        let r = copy_all(
            &rig.bridge.catalog.sql,
            &adapter,
            &Stub { rehomed: None },
            &plan(&canary, 500),
            &head,
            since,
            rig.now(),
        )
        .await;
        assert!(matches!(r, Err(CopyError::LiveLease)), "{r:?}");
    });
}

#[test]
fn the_hour_under_way_is_filed_where_it_falls() {
    for (hour, own_row) in [(5, false), (7, true), (40, true)] {
        block_on(async {
            let rig = rig();
            let (_, canary) = catalogue_with(&rig, 1, hour, own_row, 0..23).await;
            let frozen = &rig.bridge.catalog.sql.inner;
            let (zero, owner) = heads();
            let (head, since) = bound(&zero.door, &owner.door).unwrap();
            let u = unit(since);
            let adapter = Adapter::new(&u, since);
            for page in [2, 500] {
                copy_all(
                    &rig.bridge.catalog.sql,
                    &adapter,
                    &Stub { rehomed: None },
                    &plan(&canary, page),
                    &head,
                    since,
                    rig.now(),
                )
                .await
                .map_err(|e| format!("{e:?}"))
                .unwrap();
            }
            let ids = canary_ids(frozen, &canary);
            let got = rows(u.sql(), ImportTable::UsageHours);
            assert_eq!(
                got,
                expected(frozen, ImportTable::UsageHours, &ids, ""),
                "{hour}"
            );
            let filed = got
                .iter()
                .find(|r| r[0] == SqlValue::Int(hour))
                .expect("the hour under way is filed");
            let base = if own_row { 0 } else { hour };
            assert_eq!(filed[1], SqlValue::Int(base + 7), "{hour}");
            assert_eq!(filed[5], SqlValue::Int(1), "{hour}");
            assert_eq!(got.len(), if own_row && hour == 40 { 24 } else { 23 });
        });
    }
}

#[test]
fn the_excluded_rows_are_summed_for_v2() {
    use velmora_bridge::directory::move_copy::excluded_sums;
    block_on(async {
        let rig = rig();
        let (_, canary) = catalogue(&rig).await;
        let frozen = &rig.bridge.catalog.sql.inner;
        let id = SqlValue::Text(canary.id.as_str().into());
        let one = |q: &str| match &ready(frozen.query(q, std::slice::from_ref(&id))).unwrap()[0][0]
        {
            SqlValue::Int(n) => *n,
            SqlValue::Null => 0,
            other => panic!("{other:?}"),
        };
        let sums = excluded_sums(&rig.bridge.catalog.sql, &plan(&canary, 2))
            .await
            .map_err(|e| format!("{e:?}"))
            .unwrap();
        assert_eq!(
            sums.x_unreleased,
            one("SELECT count(*) FROM extents WHERE bucket_id = ?1 AND safety_state IN ('held', 'releasing')")
        );
        assert_eq!(
            sums.unreleased_bytes,
            one("SELECT sum(cipher_size) FROM extents WHERE bucket_id = ?1 AND safety_state IN ('held', 'releasing')")
        );
        assert_eq!(
            sums.x_released,
            one("SELECT count(*) FROM extents WHERE bucket_id = ?1 AND safety_state = 'released'")
        );
        assert_eq!(
            sums.released_bytes,
            one("SELECT sum(cipher_size) FROM extents WHERE bucket_id = ?1 AND safety_state = 'released'")
        );
        assert_eq!(
            sums.x_deleted,
            one("SELECT count(*) FROM extents WHERE bucket_id = ?1 AND safety_state = 'deleted'")
        );
        assert!(sums.x_unreleased > 0 && sums.x_released > 0 && sums.x_deleted > 0);
        for stage in ["post", "done"] {
            assert_eq!(
                sums.outbox.get(stage).copied().unwrap_or(0),
                one(&format!(
                    "SELECT count(*) FROM outbox o JOIN extents e ON e.id = o.extent_id \
                     WHERE e.bucket_id = ?1 AND o.stage = '{stage}'"
                )),
                "{stage}"
            );
        }
        assert_eq!(sums.outbox.len(), 2, "{:?}", sums.outbox);
        // The fixture's counters are on (row 1 covers every table).
        assert!(sums.covered);
        let outbox: i64 = sums.outbox.values().sum();
        assert_eq!(
            outbox,
            one("SELECT count(*) FROM outbox o JOIN extents e ON e.id = o.extent_id WHERE e.bucket_id = ?1")
        );
        assert!(outbox > 0);
        // Nothing excluded: nothing summed.
        let none = excluded_sums(&rig.bridge.catalog.sql, &CopyPlan::default())
            .await
            .map_err(|e| format!("{e:?}"))
            .unwrap();
        assert_eq!(none.outbox.len() + none.x_unreleased as usize, 0);
    });
}

/// Many hours: a full page plus the filed hour's own row, the hour before
/// every row, and a crash at every `usage_hours` batch, unapplied or with
/// its answer lost.
#[test]
fn the_hour_filing_survives_full_pages_and_every_crash() {
    for (hour, missing) in [(700, true), (300, false), (1, true)] {
        for (crash_at, lose) in [
            (None, false),
            (Some(0), false),
            (Some(1), true),
            (Some(2), false),
            (Some(2), true),
        ] {
            block_on(async {
                let rig = rig();
                // 1,200 filed hours (hour 2 upward, so hour 1 is before
                // every row), the hour under way's own row dropped when
                // `missing`.
                let (_, canary) = catalogue_with(&rig, 1, hour, missing, 2..1_202).await;
                let frozen = &rig.bridge.catalog.sql.inner;
                let (zero, owner) = heads();
                let (head, since) = bound(&zero.door, &owner.door).unwrap();
                let u = unit(since);
                let adapter = Adapter::new(&u, since);
                if let Some(n) = crash_at {
                    *adapter.fault.borrow_mut() = Some(("usage_hours".into(), n, lose));
                }
                for _ in 0..3 {
                    let _ = copy_all(
                        &rig.bridge.catalog.sql,
                        &adapter,
                        &Stub { rehomed: None },
                        &plan(&canary, 500),
                        &head,
                        since,
                        rig.now(),
                    )
                    .await;
                }
                let ids = canary_ids(frozen, &canary);
                assert_eq!(
                    rows(u.sql(), ImportTable::UsageHours),
                    expected(frozen, ImportTable::UsageHours, &ids, ""),
                    "hour {hour} missing {missing} crash {crash_at:?} lose {lose}"
                );
            });
        }
    }
}
