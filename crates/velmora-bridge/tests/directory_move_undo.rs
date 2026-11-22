//! The undo of a flipped move (DS1 §3.7, AM-28 with AM-54): the key
//! freeze, the fresh D1, the rows and keys paged back from the owner's
//! unit with the reverse transforms, the revocations, the routes, the
//! mirrored checks and the flip back; the fallback's key and flip steps
//! on the thawed D1; and the window step 2 of a later move (AM-53).

mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use service_support::*;
use velmora_bridge::directory::chain::{TenantChain, Written};
use velmora_bridge::directory::fence::{freeze, stamp_row, thaw};
use velmora_bridge::directory::move_copy::ImportState;
use velmora_bridge::directory::move_flip::{RouteRecords, Synced};
use velmora_bridge::directory::move_keys::{KeyFreeze, KeyHead, KeyPut, OwnerKeys};
use velmora_bridge::directory::move_undo::*;
use velmora_bridge::directory::move_window::{open_window, thaw_keys, WindowError, WindowUnit};
use velmora_bridge::directory::record::{KeysFrozen, Selector, Tenant, TenantDoor};
use velmora_bridge::directory::store::{KeyRoute, RouteKind, SqlDirectory};
use velmora_bridge::directory::tenant_zero::{database_facts, decide, Seen, ZeroServe};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change, KEY_CHECK_LEN};
use velmora_bridge::ports::{Sql, SqlValue};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::export::{export, ExportMode, ExportTable};
use velmora_bridge::unit::import::{ImportTable, ImportValue};
use velmora_bridge::unit::keys::{Access, ApplyEntry, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::lift::{LiftProof, ReplayId};
use velmora_bridge::*;

const OWNER: &str = "t_00000000000000a1";
const PRINCIPAL: &str = "PRowner";
const NARROW: &str = "PRnarrow";
const CLOSED: &str = "PRclosed";
/// A key made before the move and revoked after it.
const REVOKED: &str = "AKREVOKED00000000001";
/// Keys made after the move.
const NEW_KEY: &str = "AKNEWKEY000000000001";
const APP: &str = "APVLAPP0000000000001";
const LIMITED: &str = "AKLIMITED00000000001";
const UNDER_NARROW: &str = "AKNARROW000000000001";
const UNDER_CLOSED: &str = "AKCLOSED000000000001";
const INTERNAL: &str = "AKINTERNAL0000000001";
const FRESH_ID: &str = "undo1";

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn owner() -> Tenant {
    Tenant::parse(OWNER).unwrap()
}

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

/// The owner's unit: its catalogue rows in a database of the D1 schema,
/// read through L1's own `export`; closed while synced with an entry.
struct FakeUnit {
    db: RusqliteSql,
    closed: Cell<Option<u64>>,
    syncs: Cell<u32>,
    extra_tables: RefCell<Vec<String>>,
    import: RefCell<Option<ImportState>>,
    born: Cell<u32>,
}

impl FakeUnit {
    fn new() -> FakeUnit {
        FakeUnit {
            db: RusqliteSql::with_schema_unarmed().unwrap(),
            closed: Cell::new(None),
            syncs: Cell::new(0),
            extra_tables: RefCell::default(),
            import: RefCell::default(),
            born: Cell::new(0),
        }
    }
}

fn exported(v: serde_json::Value) -> Exported {
    let more = v["more"].as_bool().unwrap();
    match v["mode"].as_str().unwrap() {
        "rows" => Exported::Rows {
            rows: serde_json::from_value(v["rows"].clone()).unwrap(),
            more,
        },
        _ => Exported::Hash {
            count: v["count"].as_u64().unwrap(),
            last: serde_json::from_value(v["last"].clone()).unwrap(),
            sha256: v["sha256"].as_str().unwrap().to_string(),
            more,
        },
    }
}

impl UndoUnit for FakeUnit {
    async fn sync(&self, owner: &TenantDoor) -> Result<Synced> {
        self.syncs.set(self.syncs.get() + 1);
        self.closed
            .set(owner.restoring_entry(0).map(|e| e.since_seq));
        Ok(Synced::Ok)
    }

    async fn export(
        &self,
        table: ExportTable,
        after: Option<&[ImportValue]>,
        limit: u32,
        mode: ExportMode,
    ) -> Result<Exported> {
        Ok(
            match export(&self.db, self.closed.get(), table, after, limit, mode)? {
                Ok(v) => exported(v),
                Err(r) => Exported::Refused(r),
            },
        )
    }

    async fn tables(&self) -> Result<Vec<String>> {
        let rows = self
            .db
            .query("SELECT name FROM sqlite_master WHERE type = 'table'", &[])
            .await?;
        let mut out: Vec<String> = rows
            .into_iter()
            .filter_map(|r| match r.into_iter().next() {
                Some(SqlValue::Text(t)) => Some(t),
                _ => None,
            })
            .collect();
        out.push("unit_head".into());
        out.extend(self.extra_tables.borrow().iter().cloned());
        Ok(out)
    }
}

impl WindowUnit for FakeUnit {
    async fn sync(&self, owner: &TenantDoor) -> Result<Synced> {
        UndoUnit::sync(self, owner).await
    }

    async fn import_state(&self) -> Result<Option<ImportState>> {
        Ok(self.import.borrow().clone())
    }

    async fn ensure_born(&self, owner: &TenantDoor) -> Result<()> {
        assert!(owner.restoring_entry(0).is_some(), "born closed");
        self.born.set(self.born.get() + 1);
        Ok(())
    }
}

#[derive(Clone)]
enum KeyRecord {
    Entry(KeyEntry),
    Frozen(u64),
    Thawed(u64),
}

/// The owner's key chain: entries and the freeze records, seq = place.
#[derive(Default)]
struct FakeKeys {
    records: RefCell<Vec<KeyRecord>>,
    flat: RefCell<BTreeSet<String>>,
    tenant: RefCell<BTreeSet<String>>,
    flat_puts: RefCell<Vec<String>>,
    grants_revoked: RefCell<Vec<Vec<String>>>,
    /// The next N `KeysFrozen` puts land and answer an error.
    lose_freeze: Cell<u32>,
}

fn grant(bucket: &str, access: Access) -> KeyGrant {
    KeyGrant {
        bucket_id: bucket.into(),
        access,
        expires_at: None,
        prefix: None,
        ip_list: vec![],
    }
}

impl FakeKeys {
    fn frozen_at(&self) -> Option<u64> {
        let mut at = None;
        for r in self.records.borrow().iter() {
            match r {
                KeyRecord::Frozen(k) => at = Some(*k),
                KeyRecord::Thawed(_) => at = None,
                KeyRecord::Entry(_) => {}
            }
        }
        at
    }

    fn seq(&self) -> u64 {
        self.records.borrow().len() as u64
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &self,
        id: &str,
        kind: KeyKind,
        status: SubjectStatus,
        made_by: Option<&str>,
        grants: Vec<KeyGrant>,
    ) -> u64 {
        let seq = self.seq() + 1;
        self.records.borrow_mut().push(KeyRecord::Entry(KeyEntry {
            id: id.into(),
            kind,
            status,
            held: false,
            made_by: made_by.map(str::to_string),
            grants,
            created_at: 77,
            secret_wrapped: matches!(kind, KeyKind::S3 | KeyKind::AppPassword)
                .then(|| format!("v2:{id}").into_bytes()),
            secret_kek_version: Some(1),
            owner_ref: Some("m_owner".into()),
            last_seq: seq,
            rid: None,
        }));
        seq
    }
}

impl OwnerKeys for FakeKeys {
    async fn head(&self) -> Result<u64> {
        Ok(self.seq())
    }

    /// One item per record, no gap (AM-62): the freeze records as
    /// markers at their own seq.
    async fn entries(&self, after: u64, limit: usize) -> Result<Vec<ApplyEntry>> {
        use velmora_bridge::unit::keys::{KeyMarker, MarkerKind};
        Ok(self
            .records
            .borrow()
            .iter()
            .enumerate()
            .skip(after as usize)
            .map(|(i, r)| {
                let seq = i as u64 + 1;
                match r {
                    KeyRecord::Entry(e) => e.clone().into(),
                    KeyRecord::Frozen(_) => KeyMarker {
                        marker: MarkerKind::KeysFrozen,
                        seq,
                    }
                    .into(),
                    KeyRecord::Thawed(_) => KeyMarker {
                        marker: MarkerKind::KeysThawed,
                        seq,
                    }
                    .into(),
                }
            })
            .take(limit)
            .collect())
    }

    async fn flat_revoked(&self, akid: &str) -> Result<bool> {
        Ok(self.flat.borrow().contains(akid))
    }

    async fn tenant_revoked(&self, akid: &str) -> Result<bool> {
        Ok(self.tenant.borrow().contains(akid))
    }

    async fn put_tenant_revocation(&self, akid: &str) -> Result<()> {
        self.tenant.borrow_mut().insert(akid.into());
        Ok(())
    }

    async fn revoke(&self, _akid: &str) -> Result<()> {
        unreachable!("the undo writes no revoke record")
    }

    async fn revoke_grants(&self, buckets: &[String]) -> Result<()> {
        // The exit's own records: grant removals above the freeze.
        self.grants_revoked.borrow_mut().push(buckets.to_vec());
        let seq = self.seq() + 1;
        self.records.borrow_mut().push(KeyRecord::Entry(KeyEntry {
            id: PRINCIPAL.into(),
            kind: KeyKind::Principal,
            status: SubjectStatus::Active,
            held: false,
            made_by: None,
            grants: vec![],
            created_at: 1,
            secret_wrapped: None,
            secret_kek_version: None,
            owner_ref: None,
            last_seq: seq,
            rid: None,
        }));
        Ok(())
    }

    async fn flat_revocations(&self, after: Option<&str>) -> Result<(Vec<String>, Option<String>)> {
        Ok((
            self.flat
                .borrow()
                .iter()
                .filter(|id| after.is_none_or(|a| id.as_str() > a))
                .cloned()
                .collect(),
            None,
        ))
    }
}

impl KeyFreeze for FakeKeys {
    async fn key_head(&self) -> Result<KeyHead> {
        Ok(KeyHead {
            seq: self.seq(),
            frozen_at: self.frozen_at(),
        })
    }

    async fn put_keys_frozen(&self, at: u64) -> Result<KeyPut> {
        if at != self.seq() {
            return Ok(KeyPut::Lost);
        }
        if self.frozen_at().is_some() {
            return Ok(KeyPut::Refused("frozen"));
        }
        self.records.borrow_mut().push(KeyRecord::Frozen(at));
        if self.lose_freeze.get() > 0 {
            self.lose_freeze.set(self.lose_freeze.get() - 1);
            return Err(BridgeError::Blob("answer lost".into()));
        }
        Ok(KeyPut::Done)
    }

    async fn put_keys_thawed(&self, ends: u64) -> Result<KeyPut> {
        if self.frozen_at() != Some(ends) {
            return Ok(KeyPut::Refused("thaw_mismatch"));
        }
        self.records.borrow_mut().push(KeyRecord::Thawed(ends));
        Ok(KeyPut::Done)
    }
}

impl UndoKeys for FakeKeys {
    async fn tenant_revocations(
        &self,
        after: Option<&str>,
    ) -> Result<(Vec<String>, Option<String>)> {
        Ok((
            self.tenant
                .borrow()
                .iter()
                .filter(|id| after.is_none_or(|a| id.as_str() > a))
                .cloned()
                .collect(),
            None,
        ))
    }

    async fn put_flat_revocation(&self, akid: &str) -> Result<()> {
        self.flat.borrow_mut().insert(akid.into());
        self.flat_puts.borrow_mut().push(akid.into());
        Ok(())
    }
}

#[derive(Default)]
struct Receipt(Cell<Option<u64>>);

impl UndoReceipt for Receipt {
    async fn k_u(&self) -> Result<Option<u64>> {
        Ok(self.0.get())
    }

    async fn put_k_u(&self, k_u: u64) -> Result<()> {
        self.0.set(Some(k_u));
        Ok(())
    }
}

/// The reverse wraps, as plain markers; the checks compare them.
#[derive(Default)]
struct FakeTransform {
    bad_bdk: RefCell<BTreeSet<String>>,
    bad_file_key: RefCell<BTreeSet<String>>,
    bad_secret: RefCell<BTreeSet<String>>,
}

fn text_at(row: &[ImportValue], i: usize) -> String {
    match &row[i] {
        ImportValue::Text(t) => t.clone(),
        _ => panic!("text"),
    }
}

impl ReverseTransform for FakeTransform {
    async fn new_bucket(&self, row: &[ImportValue]) -> Result<BucketBack> {
        Ok(BucketBack {
            owner: "owner".into(),
            bdk_wrapped: format!("kek:{}", text_at(row, 0)).into_bytes(),
            kek_version: 1,
        })
    }

    async fn new_key(&self, entry: &KeyEntry) -> Result<KeyBack> {
        assert!(entry.secret_wrapped.is_some());
        Ok(KeyBack {
            principal: "owner".into(),
            secret_wrapped: format!("v1:{}", entry.id).into_bytes(),
            kek_version: 1,
        })
    }

    async fn same_bdk(&self, d1: &[ImportValue], unit: &[ImportValue]) -> Result<bool> {
        Ok(text_at(d1, 0) == text_at(unit, 0) && !self.bad_bdk.borrow().contains(&text_at(d1, 0)))
    }

    async fn file_keys_open(
        &self,
        _d1: &[ImportValue],
        extents: &[Vec<ImportValue>],
    ) -> Result<Vec<String>> {
        Ok(extents
            .iter()
            .map(|e| text_at(e, 0))
            .filter(|id| self.bad_file_key.borrow().contains(id))
            .collect())
    }

    async fn same_secret(&self, _d1: &[u8], _v: i64, entry: &KeyEntry) -> Result<bool> {
        Ok(!self.bad_secret.borrow().contains(&entry.id))
    }
}

/// Flat safety copies: the frozen D1's held extents have one already.
#[derive(Default)]
struct FakeBlobs {
    flat: RefCell<BTreeSet<String>>,
    copied: RefCell<Vec<String>>,
}

impl BlobsBack for FakeBlobs {
    async fn to_flat(&self, extent_id: &str, _sha: &[u8]) -> Result<()> {
        self.flat.borrow_mut().insert(extent_id.into());
        self.copied.borrow_mut().push(extent_id.into());
        Ok(())
    }

    async fn flat_ok(&self, extent_id: &str, _sha: &[u8]) -> Result<bool> {
        Ok(self.flat.borrow().contains(extent_id))
    }
}

#[derive(Default)]
struct FakeRecords(Cell<u32>);

impl RecordsBack for FakeRecords {
    async fn reseal_after_flip(&self, _flipped_at: UnixMs) -> Result<u64> {
        self.0.set(self.0.get() + 1);
        Ok(3)
    }
}

#[derive(Default)]
struct FakeRoutes(RefCell<BTreeMap<String, String>>);

impl RouteRecords for FakeRoutes {
    async fn put(&self, akid: &str, tenant: &Tenant, _kind: RouteKind) -> Result<bool> {
        let mut r = self.0.borrow_mut();
        let named = r
            .entry(akid.into())
            .or_insert_with(|| tenant.as_str().into());
        Ok(named == tenant.as_str())
    }

    async fn get(&self, akid: &str) -> Result<Option<String>> {
        Ok(self.0.borrow().get(akid).cloned())
    }

    async fn replace(
        &self,
        akid: &str,
        from: &Tenant,
        to: &Tenant,
        kind: RouteKind,
    ) -> Result<bool> {
        assert_eq!(kind == RouteKind::AppPassword, akid.starts_with("APVL"));
        let mut r = self.0.borrow_mut();
        match r.get(akid).map(String::as_str) {
            Some(t) if t == to.as_str() => Ok(true),
            Some(t) if t == from.as_str() => {
                r.insert(akid.into(), to.as_str().into());
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// A D1 whose batches fail after `budget` more.
struct Flaky<'a> {
    inner: &'a RusqliteSql,
    budget: Cell<Option<u32>>,
}

impl Sql for Flaky<'_> {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>> {
        self.inner.query(sql, params).await
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.inner.exec(sql, params).await
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if let Some(n) = self.budget.get() {
            if n == 0 {
                return Err(BridgeError::Sql("d1 unreachable".into()));
            }
            self.budget.set(Some(n - 1));
        }
        self.inner.batch(stmts).await
    }
}

// ---------------------------------------------------------------------------
// The flipped move this undoes
// ---------------------------------------------------------------------------

struct Undo {
    rig: Rig,
    store: HookedRecords,
    seal: PlainSeal,
    dir_db: RusqliteSql,
    unit: FakeUnit,
    keys: FakeKeys,
    receipt: Receipt,
    transform: FakeTransform,
    blobs: FakeBlobs,
    records: FakeRecords,
    routes: FakeRoutes,
    fresh: RusqliteSql,
    /// `K_u` of the last step 1.
    k_u: Cell<u64>,
    vault: String,
    canary: String,
    /// The bucket made after the move.
    photos: String,
    /// The extent made after the move (held).
    new_extent: String,
}

fn bucket_columns() -> &'static [&'static str] {
    ImportTable::Buckets.columns()
}

async fn rows_of(db: &RusqliteSql, table: ImportTable) -> Vec<Vec<SqlValue>> {
    let cols: Vec<String> = table.columns().iter().map(|c| format!("\"{c}\"")).collect();
    let order: Vec<String> = table
        .key_columns()
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect();
    db.query(
        &format!(
            "SELECT {} FROM \"{}\" ORDER BY {}",
            cols.join(", "),
            table.name(),
            order.join(", ")
        ),
        &[],
    )
    .await
    .unwrap()
}

fn col(table: ImportTable, name: &str) -> usize {
    table.columns().iter().position(|c| *c == name).unwrap()
}

impl Undo {
    fn chain(&self) -> TenantChain<'_, HookedRecords, PlainSeal> {
        TenantChain {
            store: &self.store,
            seal: &self.seal,
        }
    }

    fn dir(&self) -> SqlDirectory<'_, RusqliteSql> {
        SqlDirectory { sql: &self.dir_db }
    }

    fn frozen(&self) -> &impl Sql {
        &self.rig.bridge.catalog.sql
    }

    async fn write(&self, tenant: &Tenant, change: Change, actor: Actor) -> TenantDoor {
        match self
            .chain()
            .write(tenant, &change, actor, self.rig.now(), 0)
            .await
            .unwrap()
        {
            Written::Wrote(r) => r.door,
            Written::Unchanged(r) => r.door,
        }
    }

    async fn head(&self, tenant: &Tenant) -> TenantDoor {
        self.chain().head(tenant, 0).await.unwrap().unwrap().door
    }

    async fn freeze(&self) -> std::result::Result<u64, UndoError> {
        let k_u = freeze_keys(
            &self.chain(),
            &self.dir(),
            &self.unit,
            &self.keys,
            &self.receipt,
            &owner(),
            self.rig.now(),
        )
        .await?;
        self.k_u.set(k_u);
        Ok(k_u)
    }

    async fn prepare(&self, id: &str) -> std::result::Result<(), UndoError> {
        prepare_fresh(
            &self.chain(),
            self.frozen(),
            &self.fresh,
            &owner(),
            self.k_u.get(),
            id,
        )
        .await
    }

    async fn copy_into<D: Sql>(&self, fresh: &D) -> std::result::Result<Vec<TableBack>, UndoError> {
        let o = owner();
        let undo = velmora_bridge::directory::move_undo::Undo {
            owner: &o,
            k_u: self.k_u.get(),
            catalogue_id: FRESH_ID,
        };
        copy_back(
            &self.chain(),
            &self.unit,
            self.frozen(),
            fresh,
            &self.transform,
            &self.blobs,
            &undo,
            self.rig.now(),
        )
        .await
    }

    async fn copy(&self) -> std::result::Result<Vec<TableBack>, UndoError> {
        self.copy_into(&self.fresh).await
    }

    async fn build(&self, k_u: u64) -> std::result::Result<KeysBack, UndoError> {
        build_keys(
            &self.chain(),
            self.frozen(),
            &self.fresh,
            &self.keys,
            &self.transform,
            &owner(),
            k_u,
        )
        .await
    }

    async fn verify(&self, k_u: u64) -> std::result::Result<VerifiedBack, UndoError> {
        verify_back(
            &self.chain(),
            &self.unit,
            self.frozen(),
            &self.fresh,
            &self.keys,
            &self.transform,
            &self.blobs,
            &owner(),
            k_u,
        )
        .await
    }

    async fn flip(&self, k_u: u64) -> std::result::Result<FlippedBack, UndoError> {
        flip_back(
            &self.chain(),
            &self.dir(),
            &self.fresh,
            &self.keys,
            &owner(),
            k_u,
            FRESH_ID,
            self.rig.now(),
        )
        .await
    }

    /// Steps 1 to 7 of the reverse move. Answers `K_u`.
    async fn up_to_verify(&self) -> u64 {
        let k_u = self.freeze().await.unwrap();
        self.prepare(FRESH_ID).await.unwrap();
        self.copy().await.unwrap();
        self.build(k_u).await.unwrap();
        revocations_back(
            &self.chain(),
            self.frozen(),
            &self.keys,
            &self.records,
            &owner(),
            k_u,
        )
        .await
        .unwrap();
        routes_back(
            &self.chain(),
            &self.dir(),
            &self.routes,
            &self.keys,
            &owner(),
            k_u,
        )
        .await
        .unwrap();
        self.verify(k_u).await.unwrap();
        k_u
    }

    async fn fresh_key(&self, akid: &str) -> Option<(Vec<u8>, String, BTreeMap<String, String>)> {
        let rows = self
            .fresh
            .query(
                "SELECT secret_wrapped, status FROM access_keys WHERE access_key_id = ?1",
                &[SqlValue::Text(akid.into())],
            )
            .await
            .unwrap();
        let row = rows.first()?;
        let (SqlValue::Blob(s), SqlValue::Text(st)) = (&row[0], &row[1]) else {
            panic!("key row");
        };
        let grants = self
            .fresh
            .query(
                "SELECT bucket_id, perm FROM grants WHERE access_key_id = ?1",
                &[SqlValue::Text(akid.into())],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|g| match (&g[0], &g[1]) {
                (SqlValue::Text(b), SqlValue::Text(p)) => (b.clone(), p.clone()),
                _ => panic!("grant row"),
            })
            .collect();
        Some((s.clone(), st.clone(), grants))
    }
}

/// The unit's row of `table` with key `id` (a one-column key), changed by
/// `edit`, inserted under `new_id`.
async fn clone_row(
    db: &RusqliteSql,
    table: ImportTable,
    id: &str,
    edit: impl Fn(&mut Vec<SqlValue>),
) {
    let rows = rows_of(db, table).await;
    let i = col(table, "id");
    let mut row = rows
        .into_iter()
        .find(|r| r[i] == SqlValue::Text(id.into()))
        .unwrap();
    edit(&mut row);
    db.batch(vec![(insert_back(table), row)]).await.unwrap();
}

/// A flipped move of tenant 0's catalogue (one bucket and its object, the
/// canary left out) into the owner, the unit holding what the move copied
/// and what happened after it: a bucket and a held extent made after the
/// move, new keys, a revoke. The owner's key chain as the move wrote it
/// and as it went on.
async fn flipped() -> Undo {
    let rig = rig();
    let (vault, signer) = rig.standard("vault").await;
    rig.put(&signer, "vault", "a.bin", &pattern(1, 1_000))
        .await
        .expect(200);
    rig.key(REVOKED, secret(), KeyStatus::Active).await;
    rig.grant(REVOKED, &vault, Perm::Rw).await;
    let canary = rig.bucket("mq-canary", true).await;
    rig.bridge.raise_stamp().await.unwrap();
    let vault = vault.id.as_str().to_string();
    let canary = canary.id.as_str().to_string();
    let frozen = &rig.bridge.catalog.sql;
    // The frozen D1 carries the migration bookkeeping.
    frozen
        .exec(
            "CREATE TABLE d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, \
             name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)",
            &[],
        )
        .await
        .unwrap();
    for n in ["0001_init.sql", "0022_parity.sql"] {
        frozen
            .exec(
                "INSERT INTO d1_migrations (name) VALUES (?1)",
                &[SqlValue::Text(n.into())],
            )
            .await
            .unwrap();
    }
    freeze(frozen, 1).await.unwrap();

    let unit = FakeUnit::new();
    // The move's copy: every table but the canary's rows, with the
    // forward transforms.
    for table in ImportTable::ALL {
        for mut row in rows_of_sql(frozen, table).await {
            if table == ImportTable::Buckets {
                if row[col(table, "id")] == SqlValue::Text(canary.clone()) {
                    continue;
                }
                row[col(table, "owner")] = SqlValue::Text(PRINCIPAL.into());
                row[col(table, "bdk_wrapped")] = SqlValue::Blob(b"scheme2".to_vec());
                row[col(table, "kek_version")] = SqlValue::Int(1);
            }
            if table == ImportTable::GenerationExtents {
                unit.db
                    .batch(vec![(insert_back(table), row)])
                    .await
                    .unwrap();
                continue;
            }
            unit.db
                .batch(vec![(insert_back(table), row)])
                .await
                .unwrap();
        }
    }

    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let dir_db = RusqliteSql::open_in_memory().unwrap();
    dir_db
        .apply(include_str!(
            "../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
        ))
        .unwrap();
    let mut u = Undo {
        rig,
        store,
        seal,
        dir_db,
        unit,
        keys: FakeKeys::default(),
        receipt: Receipt::default(),
        transform: FakeTransform::default(),
        blobs: FakeBlobs::default(),
        records: FakeRecords::default(),
        routes: FakeRoutes::default(),
        fresh: RusqliteSql::with_schema_unarmed().unwrap(),
        k_u: Cell::new(0),
        vault,
        canary,
        photos: String::new(),
        new_extent: "x_000000000000000000000000000000ff".into(),
    };
    // The fresh D1, as the deploy tooling makes it.
    u.fresh
        .exec(
            "CREATE TABLE d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, \
             name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)",
            &[],
        )
        .await
        .unwrap();
    for n in ["0001_init.sql", "0022_parity.sql"] {
        u.fresh
            .exec(
                "INSERT INTO d1_migrations (name) VALUES (?1)",
                &[SqlValue::Text(n.into())],
            )
            .await
            .unwrap();
    }

    // The chains: tenant 0 `moving`, the owner's entry and placement, the
    // lift, the flip; then a bucket made after the move.
    let zero = Tenant::zero();
    u.write(
        &zero,
        Change::CreateTenantZero {
            jurisdiction: "us".into(),
        },
        Actor::Operator,
    )
    .await;
    let o = owner();
    for (change, actor) in [
        (
            Change::Create {
                jurisdiction: "us".into(),
                location_hint: None,
                synthetic: false,
                limits: Default::default(),
                rate_json: Default::default(),
                features_json: Default::default(),
            },
            Actor::TenantCreation,
        ),
        (
            Change::ClaimKeyVersion { version: 1 },
            Actor::TenantCreation,
        ),
        (
            Change::CommitKeyVersion {
                version: 1,
                kcv: [1; KEY_CHECK_LEN],
            },
            Actor::TenantCreation,
        ),
        (
            Change::Activate { external_ref: None },
            Actor::TenantCreation,
        ),
    ] {
        u.write(&o, change, actor).await;
    }
    let start = u
        .write(
            &zero,
            Change::StartMove {
                to: o.clone(),
                catalogue_id_frozen: "main".into(),
            },
            Actor::MoveTool,
        )
        .await;
    let entry = u
        .chain()
        .open_window_entry(&o, 0, start.seq, u.rig.now(), 0)
        .await
        .unwrap();
    let Written::Wrote(entry) = entry else {
        panic!("entry")
    };
    let since = entry.door.restoring_entry(0).unwrap().since_seq;
    u.chain()
        .place_moved_buckets(&o, std::slice::from_ref(&u.vault), 0, u.rig.now(), 0)
        .await
        .unwrap();
    u.write(
        &o,
        Change::LiftRestoring {
            unit: 0,
            since_seq: since,
            proof: LiftProof {
                replay_id: ReplayId {
                    since,
                    ordinal: 1,
                    nonce: "n".into(),
                },
                acknowledged: Default::default(),
            },
        },
        Actor::MoveTool,
    )
    .await;
    u.write(&zero, Change::FlipMove { stamp: 2 }, Actor::MoveTool)
        .await;

    // The owner's key chain: the move's records, then what came after.
    let k = &u.keys;
    k.push(
        PRINCIPAL,
        KeyKind::Principal,
        SubjectStatus::Active,
        None,
        vec![grant(&u.vault, Access::Rw)],
    );
    k.push(
        INTERNAL,
        KeyKind::Internal,
        SubjectStatus::Active,
        None,
        vec![],
    );
    k.push(
        AKID,
        KeyKind::S3,
        SubjectStatus::Active,
        Some(PRINCIPAL),
        vec![grant(&u.vault, Access::Rw)],
    );
    k.push(
        REVOKED,
        KeyKind::S3,
        SubjectStatus::Active,
        Some(PRINCIPAL),
        vec![grant(&u.vault, Access::Rw)],
    );
    // After the move: a bucket (its creator grant is the next record).
    let grant_seq = k.seq() + 1;
    let photos = velmora_bridge::records::bucket_id(o.managed().unwrap(), grant_seq)
        .as_str()
        .to_string();
    k.push(
        PRINCIPAL,
        KeyKind::Principal,
        SubjectStatus::Active,
        None,
        vec![grant(&u.vault, Access::Rw), grant(&photos, Access::Rw)],
    );
    u.write(
        &o,
        Change::CreateBucket {
            bucket: photos.clone(),
            unit: 0,
            creator: PRINCIPAL.into(),
            grant_seq,
            name: "photos".into(),
            bdk_wrapped: {
                let mut w = vec![5; velmora_bridge::crypto::WRAPPED_KEY_LEN];
                w[0] = velmora_bridge::crypto::scheme2::WRAP_VERSION_2;
                w
            },
            tk_version: u.head(&o).await.tk_version,
        },
        Actor::Customer,
    )
    .await;
    k.push(
        NEW_KEY,
        KeyKind::S3,
        SubjectStatus::Active,
        Some(PRINCIPAL),
        vec![grant(&photos, Access::Rw)],
    );
    k.push(
        APP,
        KeyKind::AppPassword,
        SubjectStatus::Active,
        Some(PRINCIPAL),
        vec![grant(&photos, Access::Ro)],
    );
    let mut limited = grant(&u.vault, Access::Ro);
    limited.prefix = Some("docs/".into());
    k.push(
        LIMITED,
        KeyKind::S3,
        SubjectStatus::Active,
        Some(PRINCIPAL),
        vec![limited],
    );
    k.push(
        NARROW,
        KeyKind::Principal,
        SubjectStatus::Active,
        Some(PRINCIPAL),
        vec![grant(&u.vault, Access::Ro)],
    );
    k.push(
        UNDER_NARROW,
        KeyKind::S3,
        SubjectStatus::Active,
        Some(NARROW),
        vec![grant(&u.vault, Access::Rw), grant(&photos, Access::Rw)],
    );
    k.push(
        CLOSED,
        KeyKind::Principal,
        SubjectStatus::Disabled,
        Some(PRINCIPAL),
        vec![grant(&u.vault, Access::Rw)],
    );
    k.push(
        UNDER_CLOSED,
        KeyKind::S3,
        SubjectStatus::Active,
        Some(CLOSED),
        vec![grant(&u.vault, Access::Rw)],
    );
    // The revoke after the move: its `m/rk/<t>/` first, then the record.
    k.tenant.borrow_mut().insert(REVOKED.into());
    k.push(
        REVOKED,
        KeyKind::S3,
        SubjectStatus::Revoked,
        Some(PRINCIPAL),
        vec![],
    );

    // The unit after the move: the new bucket, a held extent in it, a
    // warm copy count on the moved extent.
    let b = ImportTable::Buckets;
    let mut row: Vec<SqlValue> = vec![SqlValue::Null; bucket_columns().len()];
    row[col(b, "id")] = SqlValue::Text(photos.clone());
    row[col(b, "name")] = SqlValue::Text("photos".into());
    row[col(b, "owner")] = SqlValue::Text(PRINCIPAL.into());
    row[col(b, "bdk_wrapped")] = SqlValue::Blob(b"scheme2-new".to_vec());
    row[col(b, "kek_version")] = SqlValue::Int(1);
    row[col(b, "disposable")] = SqlValue::Int(0);
    row[col(b, "created_at")] = SqlValue::Int(5);
    u.unit.db.batch(vec![(insert_back(b), row)]).await.unwrap();
    let x = ImportTable::Extents;
    let moved_extent = match &rows_of(&u.unit.db, x).await[0][col(x, "id")] {
        SqlValue::Text(t) => t.clone(),
        _ => panic!("extent id"),
    };
    u.unit
        .db
        .exec(
            "UPDATE extents SET hot_cache_bytes = 1000 WHERE id = ?1",
            &[SqlValue::Text(moved_extent.clone())],
        )
        .await
        .unwrap();
    let new_extent = u.new_extent.clone();
    let photos_id = photos.clone();
    clone_row(&u.unit.db, x, &moved_extent, |r| {
        r[col(x, "id")] = SqlValue::Text(new_extent.clone());
        r[col(x, "bucket_id")] = SqlValue::Text(photos_id.clone());
        r[col(x, "generation_id")] = SqlValue::Null;
        r[col(x, "seq")] = SqlValue::Null;
        r[col(x, "plain_offset")] = SqlValue::Null;
        r[col(x, "safety_state")] = SqlValue::Text("held".into());
        r[col(x, "hot_safety_bytes")] = SqlValue::Int(1000);
    })
    .await;
    // The frozen D1's held extents have their flat copies.
    for row in rows_of_sql(u.frozen(), x).await {
        if let SqlValue::Text(id) = &row[col(x, "id")] {
            u.blobs.flat.borrow_mut().insert(id.clone());
        }
    }
    u.photos = photos;

    // Directory rows and route records: every key routes to the owner.
    let dir = u.dir();
    for t in [&zero, &o] {
        dir.apply_tenant(&u.head(t).await, u.rig.now())
            .await
            .unwrap();
    }
    for akid in [
        AKID,
        REVOKED,
        NEW_KEY,
        APP,
        LIMITED,
        UNDER_NARROW,
        UNDER_CLOSED,
    ] {
        let kind = match akid.starts_with("APVL") {
            true => RouteKind::AppPassword,
            false => RouteKind::S3,
        };
        dir.put_route(&KeyRoute {
            akid: akid.into(),
            tenant: o.clone(),
            kind,
            owner_ref: None,
            created_at: u.rig.now(),
        })
        .await
        .unwrap();
        u.routes.0.borrow_mut().insert(akid.into(), OWNER.into());
    }
    u
}

async fn rows_of_sql<S: Sql>(db: &S, table: ImportTable) -> Vec<Vec<SqlValue>> {
    let cols: Vec<String> = table.columns().iter().map(|c| format!("\"{c}\"")).collect();
    let order: Vec<String> = table
        .key_columns()
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect();
    db.query(
        &format!(
            "SELECT {} FROM \"{}\" ORDER BY {}",
            cols.join(", "),
            table.name(),
            order.join(", ")
        ),
        &[],
    )
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The insert statements name the import's columns in its order.
#[test]
fn every_insert_names_the_tables_columns_in_order() {
    for table in ImportTable::ALL {
        let sql = insert_back(table);
        let open = sql.find('(').unwrap();
        let close = sql[open..].find(')').unwrap() + open;
        let named: Vec<String> = sql[open + 1..close]
            .split(',')
            .map(|c| c.trim().to_string())
            .collect();
        let want: Vec<String> = table.columns().iter().map(|c| c.to_string()).collect();
        assert_eq!(named, want, "{}", table.name());
        assert!(sql.starts_with(&format!("INSERT INTO {}(", table.name())));
        let params = sql.matches('?').count();
        assert_eq!(params, want.len(), "{}", table.name());
    }
}

/// Step 1: `KeysFrozen` first, the receipt, then the owner's record with
/// the freeze and the entry, and the unit closed; a re-run adopts it.
#[test]
fn step_one_freezes_the_key_chain_then_the_tenant() {
    block_on(async {
        let u = flipped().await;
        let head_before = u.keys.seq();
        let k_u = u.freeze().await.unwrap();
        assert_eq!(k_u, head_before);
        assert_eq!(u.keys.frozen_at(), Some(k_u));
        assert_eq!(u.receipt.0.get(), Some(k_u));
        let o = u.head(&owner()).await;
        assert_eq!(o.keys_frozen, Some(KeysFrozen { at: k_u }));
        let since = o.restoring_entry(0).unwrap().since_seq;
        assert_eq!(u.unit.closed.get(), Some(since));
        assert_eq!(
            u.dir().tenant(&owner()).await.unwrap().unwrap().door.seq,
            o.seq
        );
        // A re-run: no second freeze, no second record.
        let records = u.keys.seq();
        let seq = o.seq;
        assert_eq!(u.freeze().await.unwrap(), k_u);
        assert_eq!(u.keys.seq(), records);
        assert_eq!(u.head(&owner()).await.seq, seq);
    });
}

/// A `KeysFrozen` whose answer was lost is this run's own and adopted; a
/// freeze no receipt names is ended by `KeysThawed` and a new one put
/// (AM-54 LOW 1).
#[test]
fn step_one_adopts_only_its_own_freeze() {
    block_on(async {
        let u = flipped().await;
        u.keys.lose_freeze.set(1);
        let k_u = u.freeze().await.unwrap();
        let frozen = u
            .keys
            .records
            .borrow()
            .iter()
            .filter(|r| matches!(r, KeyRecord::Frozen(_)))
            .count();
        assert_eq!(frozen, 1);
        assert_eq!(u.keys.frozen_at(), Some(k_u));

        // A stale freeze from an undo this receipt does not know.
        let u = flipped().await;
        u.keys.records.borrow_mut().push(KeyRecord::Frozen(3));
        let stale_head = u.keys.seq();
        let k_u = u.freeze().await.unwrap();
        let tail: Vec<String> = u.keys.records.borrow()[stale_head as usize..]
            .iter()
            .map(|r| match r {
                KeyRecord::Thawed(e) => format!("thawed {e}"),
                KeyRecord::Frozen(a) => format!("frozen {a}"),
                KeyRecord::Entry(_) => "entry".into(),
            })
            .collect();
        assert_eq!(tail, vec!["thawed 3".to_string(), format!("frozen {k_u}")]);
        assert_eq!(k_u, stale_head + 1);
        assert_eq!(u.receipt.0.get(), Some(k_u));
        // A receipt that names it: adopted.
        let u2 = flipped().await;
        let at = u2.keys.seq();
        u2.keys.records.borrow_mut().push(KeyRecord::Frozen(at));
        u2.receipt.0.set(Some(at));
        let before = u2.keys.seq();
        assert_eq!(u2.freeze().await.unwrap(), at);
        assert_eq!(u2.keys.seq(), before);
    });
}

/// Step 1 does not start for a tenant with a second unit, over an entry
/// without the freeze, or with no flip into the owner.
#[test]
fn step_one_refuses_what_the_undo_cannot_hold() {
    block_on(async {
        let u = flipped().await;
        u.write(&owner(), Change::SetRestoring { unit: 0 }, Actor::Operator)
            .await;
        assert!(matches!(
            u.freeze().await,
            Err(UndoError::EntryWithoutFreeze)
        ));
        assert_eq!(u.keys.frozen_at(), None);

        let u = flipped().await;
        let o = u.head(&owner()).await;
        u.write(
            &owner(),
            Change::SetUnits {
                base_seq: o.seq,
                units: vec![0, 1],
                placements: o.placements.clone(),
            },
            Actor::Operator,
        )
        .await;
        assert!(matches!(u.freeze().await, Err(UndoError::NotOnlyRootUnit)));
        assert_eq!(u.keys.frozen_at(), None);

        let u = flipped().await;
        let o2 = Tenant::parse("t_00000000000000b2").unwrap();
        // A live tenant that no move filled: tenant 0 is `moved` into the
        // owner, not into it.
        for (change, actor) in [
            (
                Change::Create {
                    jurisdiction: "us".into(),
                    location_hint: None,
                    synthetic: false,
                    limits: Default::default(),
                    rate_json: Default::default(),
                    features_json: Default::default(),
                },
                Actor::TenantCreation,
            ),
            (
                Change::ClaimKeyVersion { version: 1 },
                Actor::TenantCreation,
            ),
            (
                Change::CommitKeyVersion {
                    version: 1,
                    kcv: [2; KEY_CHECK_LEN],
                },
                Actor::TenantCreation,
            ),
            (
                Change::Activate { external_ref: None },
                Actor::TenantCreation,
            ),
        ] {
            u.write(&o2, change, actor).await;
        }
        let r = freeze_keys(
            &u.chain(),
            &u.dir(),
            &u.unit,
            &u.keys,
            &u.receipt,
            &o2,
            u.rig.now(),
        )
        .await;
        assert!(matches!(r, Err(UndoError::NotThisMove)), "{r:?}");
        assert_eq!(u.keys.frozen_at(), None);
    });
}

/// The whole reverse move: every row back with its reverse transform, the
/// keys at `K_u` with their effective grants, the revocations, the
/// routes, the mirrored checks, then tenant 0 `d1` on the fresh catalogue
/// and the owner's placements removed.
#[test]
fn the_reverse_move_gives_back_a_correct_d1() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.up_to_verify().await;
        let b = ImportTable::Buckets;
        // Buckets: the moved one with its frozen wrap byte for byte, the
        // new one with a fresh scheme-1 wrap; the canary is not there.
        let frozen_rows = rows_of_sql(u.frozen(), b).await;
        let fresh_rows = rows_of(&u.fresh, b).await;
        let by_id = |rows: &[Vec<SqlValue>], id: &str| {
            rows.iter()
                .find(|r| r[col(b, "id")] == SqlValue::Text(id.into()))
                .cloned()
        };
        let old = by_id(&frozen_rows, &u.vault).unwrap();
        let back = by_id(&fresh_rows, &u.vault).unwrap();
        assert_eq!(old, back);
        let new = by_id(&fresh_rows, &u.photos).unwrap();
        assert_eq!(
            new[col(b, "bdk_wrapped")],
            SqlValue::Blob(format!("kek:{}", u.photos).into_bytes())
        );
        assert_eq!(new[col(b, "owner")], SqlValue::Text("owner".into()));
        assert!(by_id(&fresh_rows, &u.canary).is_none());
        // Extents: no warm copy counted; the new held extent's safety copy
        // is under its flat name, and only it was copied.
        let x = ImportTable::Extents;
        for row in rows_of(&u.fresh, x).await {
            assert_eq!(row[col(x, "hot_cache_bytes")], SqlValue::Int(0));
        }
        assert_eq!(*u.blobs.copied.borrow(), vec![u.new_extent.clone()]);
        // Every other table, row for row as the unit holds it.
        for table in ImportTable::ALL {
            if matches!(table, ImportTable::Buckets | ImportTable::Extents) {
                continue;
            }
            assert_eq!(
                rows_of(&u.unit.db, table).await,
                rows_of(&u.fresh, table).await,
                "{}",
                table.name()
            );
        }
        // Keys at K_u.
        let (secret, status, grants) = u.fresh_key(AKID).await.unwrap();
        let frozen_secret = u
            .frozen()
            .query(
                "SELECT secret_wrapped FROM access_keys WHERE access_key_id = ?1",
                &[SqlValue::Text(AKID.into())],
            )
            .await
            .unwrap()[0][0]
            .clone();
        assert_eq!(SqlValue::Blob(secret), frozen_secret);
        assert_eq!(status, "active");
        assert_eq!(
            grants,
            BTreeMap::from([(u.vault.clone(), "rw".to_string())])
        );
        let (secret, status, grants) = u.fresh_key(NEW_KEY).await.unwrap();
        assert_eq!(secret, format!("v1:{NEW_KEY}").into_bytes());
        assert_eq!(status, "active");
        assert_eq!(
            grants,
            BTreeMap::from([(u.photos.clone(), "rw".to_string())])
        );
        // The lower access along the made_by chain; a closed principal
        // closes its key.
        let (_, status, grants) = u.fresh_key(UNDER_NARROW).await.unwrap();
        assert_eq!(status, "active");
        assert_eq!(
            grants,
            BTreeMap::from([(u.vault.clone(), "ro".to_string())])
        );
        let (_, status, _) = u.fresh_key(UNDER_CLOSED).await.unwrap();
        assert_eq!(status, "disabled");
        // Not carried: revoked, limited, app password made after the move,
        // the internal key, principals.
        for akid in [REVOKED, LIMITED, APP, INTERNAL, PRINCIPAL, NARROW, CLOSED] {
            assert!(u.fresh_key(akid).await.is_none(), "{akid}");
        }
        // Revoked for good (flat), so a later replay never makes them
        // again; the routes are tenant 0's.
        let flat = u.keys.flat.borrow().clone();
        for akid in [REVOKED, LIMITED, APP] {
            assert!(flat.contains(akid), "{akid}");
        }
        assert!(!flat.contains(AKID) && !flat.contains(NEW_KEY));
        assert_eq!(u.records.0.get(), 1);
        for akid in [
            AKID,
            REVOKED,
            NEW_KEY,
            APP,
            LIMITED,
            UNDER_NARROW,
            UNDER_CLOSED,
        ] {
            assert_eq!(u.routes.0.borrow()[akid], Tenant::zero().as_str());
            assert_eq!(
                u.dir().route(akid).await.unwrap().unwrap().tenant,
                Tenant::zero()
            );
        }
        // Step 8.
        let done = u.flip(k_u).await.unwrap();
        assert!(done.wrote && done.unplaced);
        assert_eq!(done.undo_stamp, 3);
        let z = u.head(&Tenant::zero()).await;
        let zz = z.tenant_zero.clone().unwrap();
        assert_eq!(zz.selector, Selector::D1);
        assert_eq!(zz.undo_stamp, Some(3));
        assert_eq!(zz.catalogue_id.as_deref(), Some(FRESH_ID));
        assert!(zz.undone());
        // The fresh D1 serves tenant 0; the frozen one does not.
        let facts = database_facts(&u.fresh).await.unwrap();
        assert_eq!(decide(&z, &facts, &mut Seen::default()), ZeroServe::Serve);
        let old = database_facts(u.frozen()).await.unwrap();
        assert!(!decide(&z, &old, &mut Seen::default()).serves_from_d1());
        // The exit: grants on every placed id revoked (in the frozen
        // chain, above K_u), then every placement removed; the unit stays
        // closed under its entry.
        let o = u.head(&owner()).await;
        assert!(o.placements.is_empty() && o.moved_in.is_none());
        assert!(o.restoring_entry(0).is_some());
        assert_eq!(o.keys_frozen, Some(KeysFrozen { at: k_u }));
        let revoked: BTreeSet<String> = u.keys.grants_revoked.borrow()[0].iter().cloned().collect();
        assert_eq!(revoked, BTreeSet::from([u.vault.clone(), u.photos.clone()]));
        // The exit's records are above K_u. Once tenant 0 is `d1` again,
        // D1 is the catalogue: no step of the undo runs on it again.
        assert!(u.keys.seq() > k_u);
        assert!(matches!(u.verify(k_u).await, Err(UndoError::NotThisMove)));
        assert!(matches!(u.copy().await, Err(UndoError::NotThisMove)));
        assert!(matches!(u.build(k_u).await, Err(UndoError::NotThisMove)));
        // The steps that write no D1 row can still be finished.
        routes_back(&u.chain(), &u.dir(), &u.routes, &u.keys, &owner(), k_u)
            .await
            .unwrap();
        revocations_back(&u.chain(), u.frozen(), &u.keys, &u.records, &owner(), k_u)
            .await
            .unwrap();
        // A re-run of step 8 writes nothing.
        let again = u.flip(k_u).await.unwrap();
        assert!(!again.wrote && !again.unplaced);
    });
}

/// Every revocation reaches the restored D1: one put during the freeze,
/// after the build, is caught by step 8's second override; a flat one
/// too.
#[test]
fn a_revoke_during_the_freeze_reaches_the_fresh_d1() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.up_to_verify().await;
        assert!(u.fresh_key(NEW_KEY).await.is_some());
        assert!(u.fresh_key(UNDER_NARROW).await.is_some());
        // The frozen chain refused the records; the `m/rk/` puts stand.
        u.keys.tenant.borrow_mut().insert(NEW_KEY.into());
        u.keys.flat.borrow_mut().insert(UNDER_NARROW.into());
        let done = u.flip(k_u).await.unwrap();
        let overridden: BTreeSet<String> = done.overridden.into_iter().collect();
        assert_eq!(
            overridden,
            BTreeSet::from([NEW_KEY.to_string(), UNDER_NARROW.to_string()])
        );
        assert!(u.fresh_key(NEW_KEY).await.is_none());
        assert!(u.fresh_key(UNDER_NARROW).await.is_none());
        // The owner's revocation is flat now too: a later restore of
        // tenant 0, which reads only flat ones, keeps it revoked.
        assert!(u.keys.flat.borrow().contains(NEW_KEY));
    });
}

/// The key build reads the chain up to `K_u` and never further: a record
/// above it (here: one the frozen writer should have refused) changes
/// nothing in D1.
#[test]
fn the_key_build_stops_at_k_u() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.copy().await.unwrap();
        u.keys.push(
            NEW_KEY,
            KeyKind::S3,
            SubjectStatus::Active,
            Some(PRINCIPAL),
            vec![grant(&u.vault, Access::Rw), grant(&u.photos, Access::Rw)],
        );
        u.build(k_u).await.unwrap();
        let (_, _, grants) = u.fresh_key(NEW_KEY).await.unwrap();
        assert_eq!(
            grants,
            BTreeMap::from([(u.photos.clone(), "rw".to_string())])
        );
        // A wrong K_u is refused.
        assert!(matches!(u.build(k_u + 1).await, Err(UndoError::NotFrozen)));
    });
}

/// A copy that stops part way (D1 unreachable) resumes from the fresh
/// D1's last key per table and ends with the same rows.
#[test]
fn a_copy_that_stopped_resumes_from_the_fresh_d1() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        for budget in [0u32, 1, 3, 5, 8] {
            let flaky = Flaky {
                inner: &u.fresh,
                budget: Cell::new(Some(budget)),
            };
            let r = u.copy_into(&flaky).await;
            if r.is_ok() {
                break;
            }
        }
        u.copy().await.unwrap();
        u.build(k_u).await.unwrap();
        u.verify(k_u).await.unwrap();
    });
}

/// The mirrored checks find what differs: a row, a missing flat copy, a
/// bucket key, a file key, a secret, an extra key row.
#[test]
fn the_mirrored_checks_find_each_difference() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.up_to_verify().await;
        let check = |r: std::result::Result<VerifiedBack, UndoError>| match r {
            Err(UndoError::Verify { check, ids }) => (check, ids),
            other => panic!("{other:?}"),
        };
        // V1: a changed row.
        u.fresh
            .exec(
                "UPDATE objects SET generation_id = generation_id || ''",
                &[],
            )
            .await
            .unwrap();
        u.fresh
            .exec(
                "UPDATE generations SET etag = 'x' WHERE id = (SELECT MIN(id) FROM generations)",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(check(u.verify(k_u).await).0, "v1");
        let u = flipped().await;
        let k_u = u.up_to_verify().await;
        // V3: a held extent without its flat copy.
        u.blobs.flat.borrow_mut().remove(&u.new_extent);
        assert_eq!(
            check(u.verify(k_u).await),
            ("v3", vec![u.new_extent.clone()])
        );
        u.blobs.flat.borrow_mut().insert(u.new_extent.clone());
        // V4: a bucket key, then a file key.
        u.transform.bad_bdk.borrow_mut().insert(u.photos.clone());
        assert_eq!(check(u.verify(k_u).await), ("v4", vec![u.photos.clone()]));
        u.transform.bad_bdk.borrow_mut().clear();
        u.transform
            .bad_file_key
            .borrow_mut()
            .insert(u.new_extent.clone());
        assert_eq!(
            check(u.verify(k_u).await),
            ("v4", vec![u.new_extent.clone()])
        );
        u.transform.bad_file_key.borrow_mut().clear();
        // V5: a secret.
        u.transform.bad_secret.borrow_mut().insert(AKID.into());
        assert_eq!(check(u.verify(k_u).await), ("v5", vec![AKID.to_string()]));
        u.transform.bad_secret.borrow_mut().clear();
        // V6: a key row no projection gives, and a widened grant.
        u.fresh
            .exec(
                "INSERT INTO access_keys VALUES ('AKSTRAY0000000000001', 'owner', x'00', 1, \
                 'active', 1)",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            check(u.verify(k_u).await),
            ("v6", vec!["AKSTRAY0000000000001".to_string()])
        );
        u.fresh
            .exec(
                "DELETE FROM access_keys WHERE access_key_id = 'AKSTRAY0000000000001'",
                &[],
            )
            .await
            .unwrap();
        u.fresh
            .exec(
                "UPDATE grants SET perm = 'rw' WHERE access_key_id = ?1",
                &[SqlValue::Text(UNDER_NARROW.into())],
            )
            .await
            .unwrap();
        assert_eq!(
            check(u.verify(k_u).await),
            ("v6", vec![UNDER_NARROW.to_string()])
        );
    });
}

/// A live outbox lease in the unit stops the copy; an expired one is
/// cleared with its fencing token kept.
#[test]
fn outbox_leases_are_judged_as_the_forward_copy_judges_them() {
    block_on(async {
        let u = flipped().await;
        u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        let now = u.rig.now().0;
        let expired = u
            .unit
            .db
            .exec(
                "UPDATE outbox SET lease_owner = 'w', lease_until = ?1, lease_token = 9",
                &[SqlValue::Int(now - 1)],
            )
            .await
            .unwrap();
        assert!(expired > 0);
        let done = u.copy().await.unwrap();
        let outbox = done.iter().find(|t| t.table == "outbox").unwrap();
        assert_eq!(outbox.leases_cleared, expired);
        let rows = u
            .fresh
            .query(
                "SELECT lease_owner, lease_until, lease_token FROM outbox",
                &[],
            )
            .await
            .unwrap();
        for r in rows {
            assert_eq!(r, vec![SqlValue::Null, SqlValue::Null, SqlValue::Int(9)]);
        }
        let u = flipped().await;
        u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.unit
            .db
            .exec(
                "UPDATE outbox SET lease_owner = 'w', lease_until = ?1",
                &[SqlValue::Int(now)],
            )
            .await
            .unwrap();
        assert!(matches!(u.copy().await, Err(UndoError::LiveLease)));
    });
}

/// A table of the unit that `Export` does not page stops the copy before
/// any row is written (AM-26); a closed unit is needed for any page.
#[test]
fn the_preflight_stops_on_a_table_left_behind() {
    block_on(async {
        let u = flipped().await;
        u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.unit.extra_tables.borrow_mut().push("photo_tags".into());
        match u.copy().await {
            Err(UndoError::UnknownTables(t)) => assert_eq!(t, vec!["photo_tags".to_string()]),
            other => panic!("{other:?}"),
        }
        assert!(last_rows(&u.fresh).await == 0);
        // Not before step 1; and an open unit refuses every page.
        let u = flipped().await;
        assert!(matches!(u.copy().await, Err(UndoError::NotFrozen)));
        u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.unit.closed.set(None);
        assert!(matches!(
            u.copy().await,
            Err(UndoError::ExportRefused { .. })
        ));
    });
}

async fn last_rows(db: &RusqliteSql) -> usize {
    let mut n = 0;
    for table in ImportTable::ALL {
        n += rows_of(db, table).await.len();
    }
    n
}

/// Step 2 refuses a catalogue id that is not fresh, a migration list that
/// is not the frozen D1's, and a fresh D1 with a marker; it writes the
/// stamp row at a fresh level under the new id.
#[test]
fn the_fresh_d1_is_checked_before_any_row() {
    block_on(async {
        let u = flipped().await;
        // Not before step 1.
        assert!(matches!(
            u.prepare(FRESH_ID).await,
            Err(UndoError::NotFrozen)
        ));
        u.freeze().await.unwrap();
        for id in ["main", "", "no/slash"] {
            assert!(matches!(
                u.prepare(id).await,
                Err(UndoError::FreshCatalogue("catalogue_id_not_fresh"))
            ));
        }
        u.fresh
            .exec(
                "DELETE FROM d1_migrations WHERE name = '0022_parity.sql'",
                &[],
            )
            .await
            .unwrap();
        u.fresh
            .exec(
                "INSERT INTO d1_migrations (name) VALUES ('0099_new.sql')",
                &[],
            )
            .await
            .unwrap();
        match u.prepare(FRESH_ID).await {
            Err(UndoError::Migrations { missing, extra }) => {
                assert_eq!(missing, vec!["0022_parity.sql".to_string()]);
                assert_eq!(extra, vec!["0099_new.sql".to_string()]);
            }
            other => panic!("{other:?}"),
        }
        let u = flipped().await;
        u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        assert_eq!(
            stamp_row(&u.fresh).await.unwrap(),
            Some((0, FRESH_ID.to_string()))
        );
        // Run again: unchanged.
        u.prepare(FRESH_ID).await.unwrap();
        assert!(matches!(
            u.prepare("undo2").await,
            Err(UndoError::FreshCatalogue("stamp_row_names_another_id"))
        ));
        let u = flipped().await;
        u.freeze().await.unwrap();
        u.fresh
            .exec("INSERT INTO meta (k, v) VALUES ('cutover_marker', 1)", &[])
            .await
            .unwrap();
        let r = u.prepare(FRESH_ID).await;
        assert!(matches!(r, Err(UndoError::FreshCatalogue(_))), "{r:?}");
    });
}

/// The fallback: the same key build and override on the thawed frozen D1
/// (a moved key revoked after the move loses its row there, a key made
/// after the move gets one), then `UndoMoveOntoFrozen` and the exit.
#[test]
fn the_fallback_builds_keys_on_the_thawed_d1_and_flips_onto_it() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.freeze().await.unwrap();
        let frozen = &u.rig.bridge.catalog.sql;
        thaw(frozen).await.unwrap();
        // The replay (record lane) brought the new bucket back; here, its
        // row.
        let b = ImportTable::Buckets;
        let mut row: Vec<SqlValue> = vec![SqlValue::Null; bucket_columns().len()];
        row[col(b, "id")] = SqlValue::Text(u.photos.clone());
        row[col(b, "name")] = SqlValue::Text("photos".into());
        row[col(b, "owner")] = SqlValue::Text("owner".into());
        row[col(b, "bdk_wrapped")] = SqlValue::Blob(b"kek".to_vec());
        row[col(b, "kek_version")] = SqlValue::Int(1);
        row[col(b, "disposable")] = SqlValue::Int(0);
        row[col(b, "created_at")] = SqlValue::Int(5);
        frozen.batch(vec![(insert_back(b), row)]).await.unwrap();
        let built = build_keys(
            &u.chain(),
            frozen,
            frozen,
            &u.keys,
            &u.transform,
            &owner(),
            k_u,
        )
        .await
        .unwrap();
        assert!(built.carried.contains_key(AKID) && built.carried.contains_key(NEW_KEY));
        let held = |akid: &str| {
            let akid = akid.to_string();
            async move {
                frozen
                    .query(
                        "SELECT status FROM access_keys WHERE access_key_id = ?1",
                        &[SqlValue::Text(akid)],
                    )
                    .await
                    .unwrap()
                    .first()
                    .cloned()
            }
        };
        assert!(held(REVOKED).await.is_none());
        assert_eq!(
            held(NEW_KEY).await,
            Some(vec![SqlValue::Text("active".into())])
        );
        // The flip onto the frozen catalogue, levelled to the flip's stamp
        // (the tool's `stamp_level`, here its end state).
        frozen
            .exec("UPDATE rollback_stamp SET counter = 2 WHERE id = 1", &[])
            .await
            .unwrap();
        let done = flip_back_onto_frozen(
            &u.chain(),
            &u.dir(),
            frozen,
            &u.keys,
            &owner(),
            k_u,
            2,
            u.rig.now(),
        )
        .await
        .unwrap();
        assert!(done.wrote && done.unplaced);
        let z = u.head(&Tenant::zero()).await.tenant_zero.unwrap();
        assert_eq!(z.selector, Selector::D1);
        assert_eq!(z.catalogue_id.as_deref(), Some("main"));
        assert_eq!(z.moved.unwrap().levelled_to, Some(2));
    });
}

/// The reverse move's step 8 waits for the undo: not before the freeze,
/// and never onto a catalogue a move froze.
#[test]
fn step_eight_needs_this_undos_freeze() {
    block_on(async {
        let u = flipped().await;
        assert!(matches!(u.flip(1).await, Err(UndoError::NotFrozen)));
        let k_u = u.freeze().await.unwrap();
        let r = flip_back(
            &u.chain(),
            &u.dir(),
            &u.fresh,
            &u.keys,
            &owner(),
            k_u,
            "main",
            u.rig.now(),
        )
        .await;
        assert!(matches!(r, Err(UndoError::FreshCatalogue(_))), "{r:?}");
        // A fresh D1 whose stamp row names "main" is refused by the record.
        u.fresh
            .exec(
                "INSERT INTO rollback_stamp VALUES (1, 0, 'main', NULL)",
                &[],
            )
            .await
            .unwrap();
        let r = flip_back(
            &u.chain(),
            &u.dir(),
            &u.fresh,
            &u.keys,
            &owner(),
            k_u,
            "main",
            u.rig.now(),
        )
        .await;
        assert!(matches!(r, Err(UndoError::Chain(_))), "{r:?}");
        assert_eq!(
            u.head(&Tenant::zero()).await.tenant_zero.unwrap().selector,
            Selector::Moved
        );
    });
}

// ---------------------------------------------------------------------------
// Window step 2 (AM-53) and the thaw
// ---------------------------------------------------------------------------

/// After an undo, the next move's step 2 re-sets the owner's entry with a
/// new since_seq, clears the freeze and writes `KeysThawed` for it; a
/// re-run writes nothing; an import left by an earlier window stops it.
#[test]
fn the_next_window_thaws_the_undo_and_sets_a_new_entry() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.up_to_verify().await;
        u.flip(k_u).await.unwrap();
        let before = u.head(&owner()).await;
        let old_since = before.restoring_entry(0).unwrap().since_seq;
        let fresh_catalogue = &u.fresh;
        fresh_catalogue
            .exec(
                "INSERT INTO rollback_stamp VALUES (1, 0, 'undo1', NULL) ON CONFLICT DO NOTHING",
                &[],
            )
            .await
            .unwrap();
        // The undone unit still holds the first window's import: step 2
        // does not start.
        *u.unit.import.borrow_mut() = Some(ImportState {
            move_lifted: None,
            t0_seq: Some(3),
            sealed: Some(1),
            lifted_at: None,
            tables: vec![],
        });
        let r = open_window(
            &u.chain(),
            fresh_catalogue,
            &u.dir(),
            &u.unit,
            &u.keys,
            &owner(),
            FRESH_ID,
            u.rig.now(),
        )
        .await;
        assert!(
            matches!(
                r,
                Err(WindowError::EarlierImport {
                    t0_seq: Some(3),
                    started: false
                })
            ),
            "{r:?}"
        );
        assert_eq!(
            u.head(&Tenant::zero()).await.tenant_zero.unwrap().selector,
            Selector::D1
        );
        // Emptied (`deleteAll()`): the window opens.
        *u.unit.import.borrow_mut() = None;
        let opened = open_window(
            &u.chain(),
            fresh_catalogue,
            &u.dir(),
            &u.unit,
            &u.keys,
            &owner(),
            FRESH_ID,
            u.rig.now(),
        )
        .await
        .unwrap();
        assert!(opened.since > old_since);
        assert_eq!(opened.thawed, Some(k_u));
        assert_eq!(u.keys.frozen_at(), None);
        let o = u.head(&owner()).await;
        assert_eq!(o.keys_frozen, None);
        assert_eq!(o.restoring.len(), 1);
        assert_eq!(o.restoring_entry(0).unwrap().since_seq, opened.since);
        assert_eq!(u.unit.closed.get(), Some(opened.since));
        // An emptied unit is created again (restore token) before it closes.
        assert_eq!(u.unit.born.get(), 1);
        let z = u.head(&Tenant::zero()).await;
        assert_eq!(z.seq, opened.zero_seq);
        assert_eq!(z.tenant_zero.unwrap().selector, Selector::Moving);
        // A re-run: nothing new, and the import of this window is its own.
        *u.unit.import.borrow_mut() = Some(ImportState {
            move_lifted: None,
            t0_seq: Some(opened.zero_seq),
            sealed: None,
            lifted_at: None,
            tables: vec![],
        });
        let seq = o.seq;
        let records = u.keys.seq();
        let again = open_window(
            &u.chain(),
            fresh_catalogue,
            &u.dir(),
            &u.unit,
            &u.keys,
            &owner(),
            FRESH_ID,
            u.rig.now(),
        )
        .await
        .unwrap();
        assert_eq!(again.since, opened.since);
        assert_eq!(again.thawed, None);
        assert_eq!(u.head(&owner()).await.seq, seq);
        assert_eq!(u.keys.seq(), records);
    });
}

/// The thaw waits while the tenant head still carries the freeze, and
/// ends exactly the freeze the key head names.
#[test]
fn the_thaw_waits_for_the_tenant_head() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.freeze().await.unwrap();
        assert_eq!(
            thaw_keys(&u.chain(), &u.keys, &owner()).await.unwrap(),
            None
        );
        assert_eq!(u.keys.frozen_at(), Some(k_u));
        // The gate's lift of the root unit's entry (an undo given up while
        // tenant 0 is still `moved`) clears the freeze.
        let o = u.head(&owner()).await;
        let since = o.restoring_entry(0).unwrap().since_seq;
        u.write(
            &owner(),
            Change::LiftRestoring {
                unit: 0,
                since_seq: since,
                proof: LiftProof {
                    replay_id: ReplayId {
                        since,
                        ordinal: 1,
                        nonce: "g".into(),
                    },
                    acknowledged: Default::default(),
                },
            },
            Actor::RestoreTool,
        )
        .await;
        assert_eq!(
            thaw_keys(&u.chain(), &u.keys, &owner()).await.unwrap(),
            Some(k_u)
        );
        assert_eq!(u.keys.frozen_at(), None);
        assert_eq!(
            thaw_keys(&u.chain(), &u.keys, &owner()).await.unwrap(),
            None
        );
    });
}

/// The two new changes go only through the chain's calls that read
/// tenant 0's head: the plain write refuses a hand-built one.
#[test]
fn a_hand_built_tenant_zero_head_is_refused() {
    block_on(async {
        let u = flipped().await;
        let z = u.head(&Tenant::zero()).await;
        for change in [
            Change::FreezeForUndo {
                unit: 0,
                at: 1,
                zero: Box::new(z.clone()),
            },
            Change::OpenWindowEntry {
                unit: 0,
                window: z.seq,
                zero: Box::new(z.clone()),
            },
        ] {
            assert!(u
                .chain()
                .write(&owner(), &change, Actor::MoveTool, u.rig.now(), 0)
                .await
                .is_err());
        }
    });
}

/// P12 (AM-47): what the target unit's import state means before step 0,
/// read with tenant 0's head and the owner's: only a closed unit while
/// tenant 0 is `d1` is ever emptied.
#[test]
fn p12_reads_both_heads_and_the_unit() {
    use velmora_bridge::directory::move_preflight::{p12, UnitView, P12};
    block_on(async {
        let u = flipped().await;
        let moved = u.head(&Tenant::zero()).await;
        let o = u.head(&owner()).await;
        // Tenant 0 flipped once (`flips` = 1): the flipped import sealed at
        // 1; a later window that was lifted and given up seals at 2.
        let sealed_at = |lifted, sealed, closed| UnitView::Import {
            state: ImportState {
                move_lifted: lifted,
                t0_seq: Some(1),
                sealed,
                lifted_at: None,
                tables: vec![],
            },
            closed,
        };
        let import = |lifted, closed| sealed_at(lifted, Some(1), closed);
        let with = |f: &dyn Fn(&mut velmora_bridge::directory::record::TenantZero)| {
            let mut z = moved.clone();
            f(z.tenant_zero.as_mut().unwrap());
            z
        };
        let moving = with(&|z| z.selector = Selector::Moving);
        let given_up = with(&|z| {
            z.selector = Selector::D1;
            z.moved = None;
        });
        let undone = with(&|z| {
            z.selector = Selector::D1;
            z.undo_stamp = Some(3);
            z.catalogue_id = Some(FRESH_ID.into());
        });
        assert_eq!(p12(&moved, &o, 0, &UnitView::Empty), P12::Empty);
        // A live unit is never emptied: tenant 0 moving or moved.
        for z in [&moved, &moving] {
            for v in [import(Some(false), true), import(Some(true), true)] {
                assert_eq!(p12(z, &o, 0, &v), P12::Stop);
            }
        }
        assert_eq!(
            p12(&given_up, &o, 0, &import(Some(false), true)),
            P12::FinishGiveUp
        );
        // Lifted and given up (V9): its seal is one above `flips`.
        assert_eq!(
            p12(&given_up, &o, 0, &sealed_at(Some(true), Some(2), true)),
            P12::FinishGiveUp
        );
        // An undone move's copy, after a later move into another tenant
        // gave up and cleared `move`: still the undo copy, never emptied
        // without the owner's G6.
        assert_eq!(
            p12(&given_up, &o, 0, &import(Some(true), true)),
            P12::UndoCopy
        );
        assert_eq!(
            p12(&given_up, &o, 0, &sealed_at(Some(true), None, true)),
            P12::Stop
        );
        assert_eq!(
            p12(&undone, &o, 0, &import(Some(true), true)),
            P12::UndoCopy
        );
        // Not closed, or not said: stop.
        assert_eq!(p12(&undone, &o, 0, &import(Some(true), false)), P12::Stop);
        assert_eq!(p12(&given_up, &o, 0, &import(None, true)), P12::Stop);
        // An unborn unit: empty only with its entry and the marker.
        let unborn = |marker| UnitView::Unborn { marker };
        assert_eq!(p12(&undone, &o, 0, &unborn(true)), P12::Stop);
        u.freeze().await.unwrap();
        let closed = u.head(&owner()).await;
        assert_eq!(p12(&undone, &closed, 0, &unborn(true)), P12::Empty);
        assert_eq!(p12(&undone, &closed, 0, &unborn(false)), P12::Stop);
    });
}

/// P2 (AM-44): a unit whose stamp prefix holds stamps stops the move
/// unless the stamp levelling is live; P8 (AM-28): an owner-mapped key
/// with the owner's revocation and a D1 row stops it.
#[test]
fn p2_and_p8_lines_of_a_second_move() {
    use velmora_bridge::directory::move_preflight::{p2_stamp_prefix_clear, p8_stale_revocations};
    use velmora_bridge::ports::{BlobMeta, BlobStore};
    use velmora_bridge::unit::name::UnitName;
    block_on(async {
        let u = flipped().await;
        let tid = velmora_bridge::unit::TenantId::parse(OWNER).unwrap();
        let unit = UnitName::new(tid.clone(), 0);
        let safety = &u.rig.bridge.safety;
        assert!(p2_stamp_prefix_clear(safety, &unit).await.unwrap());
        let bucket = BucketId::mint([1; 8]);
        let extent = ExtentId::mint([2; 13]);
        let meta = BlobMeta {
            bucket: &bucket,
            extent: &extent,
            cipher_sha256: &sha256(b"{}"),
        };
        safety
            .put(&format!("rs/{OWNER}.0/{:020}", 1), b"{}".to_vec(), &meta)
            .await
            .unwrap();
        assert!(!p2_stamp_prefix_clear(safety, &unit).await.unwrap());
        // Another unit's prefix is not this one's.
        let other = UnitName::new(tid, 1);
        assert!(p2_stamp_prefix_clear(safety, &other).await.unwrap());

        let mapped = vec![AKID.to_string(), REVOKED.to_string()];
        assert!(p8_stale_revocations(u.frozen(), &u.keys, &mapped)
            .await
            .unwrap()
            .iter()
            .eq([REVOKED.to_string()].iter()));
    });
}

/// A stale freeze ended by `KeysThawed` puts `K_u` on that thaw record,
/// which is no subject's entry: the build still reads every entry below
/// it (AM-54 LOW 1).
#[test]
fn k_u_on_a_thaw_record_is_read_to_the_end() {
    block_on(async {
        let u = flipped().await;
        let stale = u.keys.seq();
        u.keys.records.borrow_mut().push(KeyRecord::Frozen(stale));
        let k_u = u.up_to_verify().await;
        assert_eq!(k_u, stale + 2);
        assert!(u.fresh_key(AKID).await.is_some());
        u.flip(k_u).await.unwrap();
    });
}

/// No extent with a plan revision above the highest this code writes is
/// copied back into the catalogue.
#[test]
fn a_plan_revision_above_one_stops_the_copy() {
    block_on(async {
        let u = flipped().await;
        u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.unit
            .db
            .exec(
                "UPDATE extents SET plan_rev = 2 WHERE id = ?1",
                &[SqlValue::Text(u.new_extent.clone())],
            )
            .await
            .unwrap();
        assert!(matches!(u.copy().await, Err(UndoError::Store(_))));
        let n = u
            .fresh
            .query("SELECT 1 FROM extents WHERE plan_rev > 1", &[])
            .await
            .unwrap();
        assert!(n.is_empty());
    });
}

/// The first revocation override, the build's last act: a revocation put
/// before the build (its chain record refused by the freeze) removes the
/// key from the fresh D1 before V6.
#[test]
fn the_builds_own_override_removes_a_revoked_key() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.copy().await.unwrap();
        u.keys.tenant.borrow_mut().insert(AKID.into());
        let built = u.build(k_u).await.unwrap();
        assert_eq!(built.overridden, vec![AKID.to_string()]);
        assert!(!built.carried.contains_key(AKID));
        assert!(u.fresh_key(AKID).await.is_none());
    });
}

/// A table of several pages and write chunks copies back whole, resumes
/// after a stop between chunks, and V1 compares it page by page.
#[test]
fn a_table_of_many_pages_copies_back_and_verifies() {
    block_on(async {
        let u = flipped().await;
        for hour in 1..=1_234i64 {
            u.unit
                .db
                .exec(
                    "INSERT INTO usage_hours (hour, posts, verifies, releases, dead, failures) \
                     VALUES (?1, 1, 2, 3, 0, 0)",
                    &[SqlValue::Int(hour)],
                )
                .await
                .unwrap();
        }
        let k_u = u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        let flaky = Flaky {
            inner: &u.fresh,
            budget: Cell::new(Some(7)),
        };
        assert!(u.copy_into(&flaky).await.is_err());
        let done = u.copy().await.unwrap();
        let n = rows_of(&u.fresh, ImportTable::UsageHours).await.len();
        assert_eq!(n, rows_of(&u.unit.db, ImportTable::UsageHours).await.len());
        assert!(n > 1_000);
        assert!(done.iter().any(|t| t.table == "usage_hours"));
        u.build(k_u).await.unwrap();
        let v = u.verify(k_u).await.unwrap();
        assert_eq!(v.rows["usage_hours"], n as u64);
    });
}

/// The key build stops on a held entry and on a key chain that is no
/// longer frozen at `K_u` (a thaw that raced the undo).
#[test]
fn the_key_build_refuses_a_held_entry_and_a_thawed_chain() {
    block_on(async {
        let u = flipped().await;
        if let Some(KeyRecord::Entry(e)) = u.keys.records.borrow_mut().get_mut(2) {
            e.held = true;
        }
        let k_u = u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.copy().await.unwrap();
        assert!(matches!(u.build(k_u).await, Err(UndoError::Keys(_))));

        let u = flipped().await;
        let k_u = u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.copy().await.unwrap();
        u.keys.records.borrow_mut().push(KeyRecord::Thawed(k_u));
        assert!(matches!(u.build(k_u).await, Err(UndoError::NotFrozen)));
    });
}

/// The fallback's flip needs the frozen catalogue thawed.
#[test]
fn the_fallback_flip_needs_the_thawed_frozen_d1() {
    use velmora_bridge::directory::tenant_zero::CUTOVER_MARKER_KEY;
    block_on(async {
        let u = flipped().await;
        let k_u = u.freeze().await.unwrap();
        let frozen = &u.rig.bridge.catalog.sql;
        let chain = u.chain();
        let dir = u.dir();
        let o = owner();
        let flip = || flip_back_onto_frozen(&chain, &dir, frozen, &u.keys, &o, k_u, 2, u.rig.now());
        let code = |r: std::result::Result<FlippedBack, UndoError>| match r {
            Err(UndoError::FreshCatalogue(c)) => c,
            other => panic!("{other:?}"),
        };
        // Frozen, marker and triggers in place.
        assert_eq!(code(flip().await), "d1_has_marker");
        // The marker cleared, the triggers still there.
        frozen
            .exec(
                "DELETE FROM meta WHERE k = ?1",
                &[SqlValue::Text(CUTOVER_MARKER_KEY.into())],
            )
            .await
            .unwrap_err();
        thaw(frozen).await.unwrap();
        freeze(frozen, 1).await.unwrap();
        frozen
            .exec("DROP TRIGGER IF EXISTS move_freeze_meta_del", &[])
            .await
            .unwrap();
        frozen
            .exec(
                "DELETE FROM meta WHERE k = ?1",
                &[SqlValue::Text(CUTOVER_MARKER_KEY.into())],
            )
            .await
            .unwrap();
        assert_eq!(code(flip().await), "frozen_d1_not_thawed");
        // Thawed, not levelled to the stamp the record names.
        thaw(frozen).await.unwrap();
        assert_eq!(code(flip().await), "frozen_d1_not_levelled");
        assert_eq!(
            u.head(&Tenant::zero()).await.tenant_zero.unwrap().selector,
            Selector::Moved
        );
    });
}

/// The copy refuses a fresh D1 that a Worker already raised (it serves),
/// and step 1 refuses a receipt naming another freeze.
#[test]
fn the_copy_and_step_one_refuse_another_undos_state() {
    block_on(async {
        let u = flipped().await;
        u.freeze().await.unwrap();
        u.prepare(FRESH_ID).await.unwrap();
        u.fresh
            .exec("UPDATE rollback_stamp SET counter = 1 WHERE id = 1", &[])
            .await
            .unwrap();
        assert!(matches!(
            u.copy().await,
            Err(UndoError::FreshCatalogue("fresh_not_prepared_or_serving"))
        ));
        let u = flipped().await;
        let k_u = u.freeze().await.unwrap();
        u.receipt.0.set(Some(k_u + 7));
        assert!(matches!(
            u.freeze().await,
            Err(UndoError::ReceiptDiffers { .. })
        ));
    });
}

/// P8 counts a give-up's revocation (a `disabled` row with no grant) as
/// revoked.
#[test]
fn p8_takes_a_disabled_row_without_grants_as_revoked() {
    use velmora_bridge::directory::move_preflight::p8_stale_revocations;
    block_on(async {
        let u = flipped().await;
        let frozen = &u.rig.bridge.catalog.sql;
        thaw(frozen).await.unwrap();
        frozen
            .exec(
                "DELETE FROM grants WHERE access_key_id = ?1",
                &[SqlValue::Text(REVOKED.into())],
            )
            .await
            .unwrap();
        frozen
            .exec(
                "UPDATE access_keys SET status = 'disabled' WHERE access_key_id = ?1",
                &[SqlValue::Text(REVOKED.into())],
            )
            .await
            .unwrap();
        let mapped = vec![AKID.to_string(), REVOKED.to_string()];
        assert!(p8_stale_revocations(frozen, &u.keys, &mapped)
            .await
            .unwrap()
            .is_empty());
    });
}

/// AM-53: an import found after tenant 0's `moving` record and bound
/// below it stops step 2 for the give-up without `deleteAll()`.
#[test]
fn an_earlier_import_found_after_the_moving_record_stops_step_two() {
    block_on(async {
        let u = flipped().await;
        let k_u = u.up_to_verify().await;
        u.flip(k_u).await.unwrap();
        // The next window's tenant-0 record landed; step 2 then finds the
        // undone move's import (P12 skipped).
        u.write(
            &Tenant::zero(),
            Change::StartMove {
                to: owner(),
                catalogue_id_frozen: FRESH_ID.into(),
            },
            Actor::MoveTool,
        )
        .await;
        *u.unit.import.borrow_mut() = Some(ImportState {
            move_lifted: Some(true),
            t0_seq: Some(3),
            sealed: Some(1),
            lifted_at: None,
            tables: vec![],
        });
        let before = u.head(&owner()).await.seq;
        let r = open_window(
            &u.chain(),
            &u.fresh,
            &u.dir(),
            &u.unit,
            &u.keys,
            &owner(),
            FRESH_ID,
            u.rig.now(),
        )
        .await;
        assert!(
            matches!(
                r,
                Err(WindowError::EarlierImport {
                    t0_seq: Some(3),
                    started: true
                })
            ),
            "{r:?}"
        );
        assert_eq!(u.head(&owner()).await.seq, before);
    });
}

/// The undo's read of the owner's chain up to `K_u` (AM-62): the freeze
/// records come as markers in their place and are no entry; `K_u` may be
/// a marker; an entry above `K_u` is not read; a chain that answers less
/// than its head says diverged.
#[test]
fn the_chain_read_up_to_k_u_skips_markers_and_refuses_a_short_chain() {
    block_on(async {
        let keys = FakeKeys::default();
        let a = keys.push(
            "AKUNDO0000000001",
            KeyKind::S3,
            SubjectStatus::Active,
            None,
            vec![],
        );
        keys.records.borrow_mut().push(KeyRecord::Frozen(a));
        keys.records.borrow_mut().push(KeyRecord::Thawed(a));
        let b = keys.push(
            "AKUNDO0000000002",
            KeyKind::S3,
            SubjectStatus::Active,
            None,
            vec![],
        );
        keys.records.borrow_mut().push(KeyRecord::Frozen(b));
        let k_u = keys.seq();
        keys.push(
            "AKUNDO0000000003",
            KeyKind::S3,
            SubjectStatus::Active,
            None,
            vec![],
        );
        let ids = |v: Vec<KeyEntry>| v.into_iter().map(|e| e.id).collect::<Vec<_>>();
        assert_eq!(
            ids(entries_to(&keys, k_u).await.unwrap()),
            ["AKUNDO0000000001", "AKUNDO0000000002"]
        );
        assert_eq!(
            ids(entries_to(&keys, 3).await.unwrap()),
            ["AKUNDO0000000001"]
        );
        let r = entries_to(&keys, keys.seq() + 1).await;
        assert!(
            matches!(
                r,
                Err(UndoError::Keys(
                    velmora_bridge::directory::move_keys::KeyStepError::Diverged
                ))
            ),
            "{r:?}"
        );
    });
}
