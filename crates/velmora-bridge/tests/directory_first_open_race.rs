//! Interleavings of first-open calls from two isolates sharing only their stores.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;

use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use velmora::rng::FillRandom;
use velmora_bridge::directory::chain::{TenantChain, Written, TENANT_CHAIN_PREFIX};
use velmora_bridge::directory::first_open::{first_open, FirstOpenAnswer};
use velmora_bridge::directory::gate::{anchored_epoch, is_open, GATE_ANCHOR_PREFIX};
use velmora_bridge::directory::record::Tenant;
use velmora_bridge::directory::store::{ChainKind, PendingOp, SqlDirectory};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::keys::locations::{two_in_account, write_locations};
use velmora_bridge::ports::{Row, Sql, SqlLimits, SqlValue};
use velmora_bridge::records::RecordStore;
use velmora_bridge::testkit::TestKek;
use velmora_bridge::{Result, UnixMs};

mod directory_support;
use directory_support::{database, Db};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const A_NOW: UnixMs = UnixMs(NOW.0 - 2);
const B_NOW: UnixMs = UnixMs(NOW.0 - 1);
const A1: &str = "t_00000000000000a1";
const FIRST_ANCHOR: &str = "m/dg/00000000000000000001";
const SECOND_ANCHOR: &str = "m/dg/00000000000000000002";

fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let digest = Sha256::digest(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&digest[..block.len()]);
        }
        Ok(())
    }
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, Sha256::digest(b"first open kek").into())])
}

async fn locations(store: &HookedRecords, kek: &TestKek) {
    assert!(
        write_locations(store, kek, &two_in_account(), &mut TestRng(1))
            .await
            .unwrap()
    );
}

async fn note(dir: &SqlDirectory<'_, Db>, tenant: &str, kind: &str, created_at: UnixMs) {
    dir.add_pending(&PendingOp {
        tenant: Tenant::parse(tenant).unwrap(),
        chain: ChainKind::Tenant,
        seq: 1,
        kind: kind.into(),
        created_at,
    })
    .await
    .unwrap();
}

async fn seed(store: &HookedRecords, dir: &SqlDirectory<'_, Db>) {
    locations(store, &kek()).await;
    let chain = TenantChain {
        store,
        seal: &PlainSeal::new(),
    };
    chain
        .write(
            &Tenant::Zero,
            &Change::CreateTenantZero {
                jurisdiction: "us".into(),
            },
            Actor::Operator,
            NOW,
            0,
        )
        .await
        .unwrap();
    note(
        dir,
        "t_00000000000000b2",
        "before_first_open",
        UnixMs(A_NOW.0 - 1),
    )
    .await;
}

async fn create(store: &HookedRecords, dir: &SqlDirectory<'_, Db>) {
    let chain = TenantChain {
        store,
        seal: &PlainSeal::new(),
    };
    note(dir, A1, "tenant_create", NOW).await;
    let Written::Wrote(record) = chain
        .write(
            &Tenant::parse(A1).unwrap(),
            &Change::Create {
                jurisdiction: "none".into(),
                location_hint: None,
                synthetic: false,
                limits: Default::default(),
                rate_json: Default::default(),
                features_json: Default::default(),
            },
            Actor::TenantCreation,
            NOW,
            0,
        )
        .await
        .unwrap()
    else {
        panic!("expected a new tenant head");
    };
    // The finisher projects the door, including its unit rows; it does not
    // create a key route for a tenant create.
    dir.apply_tenant(&record.door, NOW).await.unwrap();
}

// Model a route and label written by ordinary activity after a tenant
// exists (not by tenant create itself).
async fn add_route_and_label(db: &Db) {
    let tenant = SqlValue::Text(A1.into());
    db.exec(
        "INSERT INTO key_routes (akid, tenant, kind, created_at) VALUES ('AKIA1', ?1, 's3', ?2)",
        &[tenant.clone(), SqlValue::Int(NOW.0)],
    )
    .await
    .unwrap();
    db.exec(
        "INSERT INTO bucket_index (label, tenant, bucket_id) VALUES ('fixture-bucket', ?1, 'b_1')",
        &[tenant],
    )
    .await
    .unwrap();
}

fn create_pending_row() -> Row {
    vec![
        SqlValue::Text(A1.into()),
        SqlValue::Text("t".into()),
        SqlValue::Int(1),
        SqlValue::Text("tenant_create".into()),
        SqlValue::Int(NOW.0),
    ]
}

#[derive(Clone, Copy)]
enum StopAt {
    Never,
    OpenGate,
    AfterOpenGate,
    FirstWrite,
    TenantCheck,
    TenantZeroRowSeq,
    AnchorList,
    Io(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Io {
    Other,
    Write,
    OpenGate,
    TenantCheck,
    TenantZeroRowSeq,
    AnchorList,
}

/// One stop shared by the two adapters of one attempt, not by both attempts.
struct Pause {
    stop_at: Cell<StopAt>,
    calls: Cell<usize>,
    writes: Cell<usize>,
    reached: Notify,
    release: Notify,
}

impl Pause {
    fn new(stop_at: StopAt) -> Self {
        Self {
            stop_at: Cell::new(stop_at),
            calls: Cell::new(0),
            writes: Cell::new(0),
            reached: Notify::new(),
            release: Notify::new(),
        }
    }

    async fn before(&self, io: Io) {
        let call = self.calls.get();
        self.calls.set(call + 1);
        if matches!(io, Io::Write | Io::OpenGate) {
            self.writes.set(self.writes.get() + 1);
        }
        let stop = match self.stop_at.get() {
            StopAt::Never | StopAt::AfterOpenGate => false,
            StopAt::OpenGate => io == Io::OpenGate,
            StopAt::FirstWrite => matches!(io, Io::Write | Io::OpenGate),
            StopAt::TenantCheck => io == Io::TenantCheck,
            StopAt::TenantZeroRowSeq => io == Io::TenantZeroRowSeq,
            StopAt::AnchorList => io == Io::AnchorList,
            StopAt::Io(k) => call == k,
        };
        if stop {
            self.stop().await;
        }
    }

    async fn stop(&self) {
        self.stop_at.set(StopAt::Never);
        self.reached.notify_one();
        self.release.notified().await;
    }

    /// Drive the pinned attempt to its stop or completion, without dropping it.
    async fn wait_or_finish<F: Future>(&self, attempt: Pin<&mut F>) -> Option<F::Output> {
        tokio::select! {
            () = self.reached.notified() => None,
            answer = attempt => Some(answer),
        }
    }
}

struct PausedRecords<'a> {
    records: &'a HookedRecords,
    pause: &'a Pause,
}

impl RecordStore for PausedRecords<'_> {
    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>) -> Result<bool> {
        let io = if key.starts_with(GATE_ANCHOR_PREFIX) {
            Io::Write
        } else {
            Io::Other
        };
        self.pause.before(io).await;
        self.records.put_if_absent(key, bytes).await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.pause.before(Io::Other).await;
        self.records.get(key).await
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        let io = match prefix {
            TENANT_CHAIN_PREFIX => Io::TenantCheck,
            GATE_ANCHOR_PREFIX => Io::AnchorList,
            _ => Io::Other,
        };
        self.pause.before(io).await;
        self.records.list(prefix, start_after, limit).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.pause.before(Io::Other).await;
        self.records.exists(key).await
    }
}

struct PausedSql<'a> {
    db: &'a Db,
    pause: &'a Pause,
}

impl Sql for PausedSql<'_> {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let io = match params {
            [SqlValue::Text(tenant)]
                if sql.starts_with("SELECT record_seq FROM tenants")
                    && tenant == Tenant::Zero.as_str() =>
            {
                Io::TenantZeroRowSeq
            }
            _ => Io::Other,
        };
        self.pause.before(io).await;
        self.db.query(sql, params).await
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let io = if sql.starts_with("UPDATE directory_gate SET closed = 0") {
            Io::OpenGate
        } else {
            Io::Write
        };
        self.pause.before(io).await;
        let changed = self.db.exec(sql, params).await?;
        if io == Io::OpenGate
            && changed == 1
            && matches!(self.pause.stop_at.get(), StopAt::AfterOpenGate)
        {
            self.pause.stop().await;
        }
        Ok(changed)
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        self.pause.before(Io::Write).await;
        self.db.batch(stmts).await
    }

    async fn query_after_refusal(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.pause.before(Io::Other).await;
        self.db.query_after_refusal(sql, params).await
    }

    fn limits(&self) -> SqlLimits {
        self.db.limits()
    }
}

async fn attempt(
    records: &HookedRecords,
    db: &Db,
    pause: &Pause,
    now: UnixMs,
) -> Result<FirstOpenAnswer> {
    let store = PausedRecords { records, pause };
    let sql = PausedSql { db, pause };
    let chain = TenantChain {
        store: &store,
        seal: &PlainSeal::new(),
    };
    let dir = SqlDirectory { sql: &sql };
    first_open(&chain, &dir, &kek(), now).await
}

#[derive(Debug, PartialEq, Eq)]
struct TenantTables {
    tenants: Vec<Row>,
    units: Vec<Row>,
    key_routes: Vec<Row>,
    bucket_index: Vec<Row>,
}

impl TenantTables {
    async fn read(db: &Db) -> Self {
        Self {
            tenants: db
                .query("SELECT * FROM tenants ORDER BY id", &[])
                .await
                .unwrap(),
            units: db
                .query("SELECT * FROM units ORDER BY tenant, unit", &[])
                .await
                .unwrap(),
            key_routes: db
                .query("SELECT * FROM key_routes ORDER BY akid", &[])
                .await
                .unwrap(),
            bucket_index: db
                .query("SELECT * FROM bucket_index ORDER BY label", &[])
                .await
                .unwrap(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    gate: Vec<Row>,
    pending: Vec<Row>,
    anchors: Vec<String>,
    tenant_tables: TenantTables,
}

impl Snapshot {
    async fn read(db: &Db, store: &HookedRecords) -> Self {
        Self {
            gate: db
                .query(
                    "SELECT id, closed, epoch, reason, closed_at, opened_at, pending_cleared FROM directory_gate WHERE id = 1",
                    &[],
                )
                .await
                .unwrap(),
            pending: db
                .query(
                    "SELECT tenant, chain, seq, kind, created_at FROM pending_ops ORDER BY tenant, chain, seq",
                    &[],
                )
                .await
                .unwrap(),
            anchors: store
                .keys()
                .into_iter()
                .filter(|key| key.starts_with(GATE_ANCHOR_PREFIX))
                .collect(),
            tenant_tables: TenantTables::read(db).await,
        }
    }
}

async fn gate_open_at_one(store: &HookedRecords, dir: &SqlDirectory<'_, Db>) -> bool {
    let row = dir.gate().await.unwrap();
    !row.closed && row.epoch == 1 && is_open(store, dir).await.unwrap()
}

#[test]
fn a_losing_first_open_never_closes_an_open_gate_or_empties_pending() {
    block_on(async {
        let db = database();
        let store = HookedRecords::new();
        let dir = SqlDirectory { sql: &db };
        seed(&store, &dir).await;

        let a_pause = Pause::new(StopAt::OpenGate);
        let mut a = std::pin::pin!(attempt(&store, &db, &a_pause, A_NOW));
        if let Some(answer) = a_pause.wait_or_finish(a.as_mut()).await {
            panic!("A completed before its gate-open write: {answer:?}");
        }
        let row = dir.gate().await.unwrap();
        assert!(row.closed);
        assert_eq!(row.epoch, 1);
        assert_eq!(anchored_epoch(&store).await.unwrap(), (1, 0));
        assert!(Snapshot::read(&db, &store).await.pending.is_empty());

        let b_pause = Pause::new(StopAt::FirstWrite);
        let mut b = std::pin::pin!(attempt(&store, &db, &b_pause, B_NOW));
        if let Some(answer) = b_pause.wait_or_finish(b.as_mut()).await {
            panic!("B completed before its first write: {answer:?}");
        }

        a_pause.release.notify_one();
        let a_answer = a.await;
        assert!(gate_open_at_one(&store, &dir).await, "A={a_answer:?}");
        create(&store, &dir).await;
        add_route_and_label(&db).await;
        let before = Snapshot::read(&db, &store).await;
        assert_eq!(before.anchors, [FIRST_ANCHOR]);
        assert_eq!(before.pending, [create_pending_row()]);

        b_pause.release.notify_one();
        assert_eq!(b.await.unwrap(), FirstOpenAnswer::AlreadyOpen);

        let after = Snapshot::read(&db, &store).await;
        assert_eq!(after, before, "B changed the open directory");
        assert!(gate_open_at_one(&store, &dir).await);
    });
}

#[test]
fn first_open_interleaved_at_every_await_point() {
    check_every_await_point("A", A_NOW, B_NOW);
    check_every_await_point("B", B_NOW, A_NOW);
}

fn check_every_await_point(paused: &str, paused_now: UnixMs, other_now: UnixMs) {
    let mut failures = Vec::new();
    let mut covered = 0;
    loop {
        let k = covered;
        let hit_pause = block_on(async {
            let db = database();
            let store = HookedRecords::new();
            let dir = SqlDirectory { sql: &db };
            seed(&store, &dir).await;

            let pause = Pause::new(StopAt::Io(k));
            let mut call = std::pin::pin!(attempt(&store, &db, &pause, paused_now));
            if pause.wait_or_finish(call.as_mut()).await.is_some() {
                return false;
            }

            let other_answer = attempt(&store, &db, &Pause::new(StopAt::Never), other_now).await;
            let before = if is_open(&store, &dir).await.unwrap() {
                create(&store, &dir).await;
                add_route_and_label(&db).await;
                Some(Snapshot::read(&db, &store).await)
            } else {
                None
            };

            pause.release.notify_one();
            let paused_answer = call.await;
            let after = Snapshot::read(&db, &store).await;
            let mut problems = Vec::new();
            for (answer, problem) in [
                (&paused_answer, "paused call did not report an open gate"),
                (&other_answer, "unpaused call did not report an open gate"),
            ] {
                if !(matches!(answer, Ok(FirstOpenAnswer::AlreadyOpen))
                    || matches!(answer, Ok(FirstOpenAnswer::Ran(run)) if run.opened && run.epoch == 1))
                {
                    problems.push(problem);
                }
            }
            if !gate_open_at_one(&store, &dir).await {
                problems.push("gate not open at epoch 1");
            }
            if after.anchors != [FIRST_ANCHOR] {
                problems.push("anchor keys are not exactly epoch 1");
            }
            if let Some(before) = before {
                if !after.pending.contains(&create_pending_row()) || after.pending != before.pending
                {
                    problems
                        .push("the create's pending row was lost or the loser changed pending_ops");
                }
                if after.gate != before.gate {
                    problems.push("the loser changed the open gate row after the create");
                }
                if after.tenant_tables != before.tenant_tables {
                    problems.push("the loser changed tenants, units, key_routes, or bucket_index");
                }
            }
            if !problems.is_empty() {
                failures.push(format!(
                    "k={k}, paused={paused}: {problems:?}; paused={paused_answer:?}; unpaused={other_answer:?}"
                ));
            }
            true
        });
        if !hit_pause {
            break;
        }
        covered += 1;
    }
    assert!(covered > 0, "did not pause at any I/O call");
    assert!(
        failures.is_empty(),
        "{} of {covered} await points violated the first-open invariant:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn first_open_retry_after_a_lost_success_outranks_a_landed_tenant_create() {
    block_on(async {
        let db = database();
        let store = HookedRecords::new();
        let dir = SqlDirectory { sql: &db };
        seed(&store, &dir).await;
        // Commit the first open, but model its 200 as lost in transit.
        let answer = attempt(&store, &db, &Pause::new(StopAt::Never), A_NOW)
            .await
            .unwrap();
        assert!(matches!(answer, FirstOpenAnswer::Ran(run) if run.opened && run.epoch == 1));
        create(&store, &dir).await;
        let before = Snapshot::read(&db, &store).await;
        assert_eq!(before.pending, [create_pending_row()]);
        let retry = Pause::new(StopAt::Never);
        assert_eq!(
            attempt(&store, &db, &retry, B_NOW).await.unwrap(),
            FirstOpenAnswer::AlreadyOpen
        );
        assert_eq!(
            retry.calls.get(),
            2,
            "an open gate must short-circuit before listing tenant chains"
        );
        assert_eq!(retry.writes.get(), 0);
        assert_eq!(Snapshot::read(&db, &store).await, before);
    });
}

#[test]
fn a_call_at_its_tenant_check_recognizes_an_open_and_create_since_its_reads() {
    block_on(async {
        let db = database();
        let store = HookedRecords::new();
        let dir = SqlDirectory { sql: &db };
        seed(&store, &dir).await;

        let pause = Pause::new(StopAt::TenantCheck);
        let mut call = std::pin::pin!(attempt(&store, &db, &pause, A_NOW));
        if let Some(answer) = pause.wait_or_finish(call.as_mut()).await {
            panic!("A completed before its tenant check: {answer:?}");
        }
        assert_eq!(
            pause.calls.get(),
            3,
            "A must have read the row and anchors first"
        );
        assert_eq!(dir.gate_row().await.unwrap(), None);
        assert!(store
            .list(GATE_ANCHOR_PREFIX, "", 2)
            .await
            .unwrap()
            .is_empty());

        let answer = attempt(&store, &db, &Pause::new(StopAt::Never), B_NOW)
            .await
            .unwrap();
        assert!(matches!(answer, FirstOpenAnswer::Ran(run) if run.opened && run.epoch == 1));
        create(&store, &dir).await;
        let before = Snapshot::read(&db, &store).await;
        assert_eq!(before.pending, [create_pending_row()]);
        pause.release.notify_one();
        assert_eq!(call.await.unwrap(), FirstOpenAnswer::AlreadyOpen);
        assert_eq!(pause.writes.get(), 0);
        assert_eq!(Snapshot::read(&db, &store).await, before);
    });
}

#[test]
fn a_loser_paused_before_tenant_zero_row_seq_does_not_rewrite_it() {
    block_on(async {
        let db = database();
        let store = HookedRecords::new();
        let dir = SqlDirectory { sql: &db };
        seed(&store, &dir).await;

        // A passed the tenant-step fence and found a missing tenant 0 row.
        let pause = Pause::new(StopAt::TenantZeroRowSeq);
        let mut a = std::pin::pin!(attempt(&store, &db, &pause, A_NOW));
        if let Some(answer) = pause.wait_or_finish(a.as_mut()).await {
            panic!("A completed before the pause: {answer:?}");
        }
        assert!(dir.gate().await.unwrap().closed);
        assert!(dir.tenant(&Tenant::Zero).await.unwrap().is_none());

        let b = attempt(&store, &db, &Pause::new(StopAt::Never), B_NOW)
            .await
            .unwrap();
        assert!(matches!(b, FirstOpenAnswer::Ran(run) if run.opened && run.epoch == 1));
        let before = TenantTables::read(&db).await;
        assert_eq!(before.tenants.len(), 1);
        let read_updated_at = || async {
            db.query("SELECT updated_at FROM tenants", &[])
                .await
                .unwrap()
        };
        let updated_at = read_updated_at().await;
        assert_eq!(updated_at, [vec![SqlValue::Int(B_NOW.0)]]);

        pause.release.notify_one();
        assert_eq!(a.await.unwrap(), FirstOpenAnswer::AlreadyOpen);
        assert_eq!(
            read_updated_at().await,
            updated_at,
            "A rewrote tenant 0's updated_at"
        );
        assert_eq!(TenantTables::read(&db).await, before);
    });
}

#[test]
fn first_open_removes_an_orphan_managed_tenant_and_its_dependents() {
    block_on(async {
        let db = database();
        let store = HookedRecords::new();
        let dir = SqlDirectory { sql: &db };
        locations(&store, &kek()).await;
        // Only the directory projection survives; the live record store
        // never contains the managed tenant's chain.
        create(&HookedRecords::new(), &dir).await;
        add_route_and_label(&db).await;
        let before = TenantTables::read(&db).await;
        assert_eq!(before.tenants.len(), 1);
        assert_eq!(before.units.len(), 1);
        assert_eq!(before.key_routes.len(), 1);
        assert_eq!(before.bucket_index.len(), 1);
        assert_eq!(dir.gate_row().await.unwrap(), None);

        let answer = attempt(&store, &db, &Pause::new(StopAt::Never), NOW)
            .await
            .unwrap();
        assert!(
            matches!(&answer, FirstOpenAnswer::Ran(run) if run.opened && run.epoch == 1 && run.tenants.removed == 1),
            "{answer:?}"
        );
        let after = TenantTables::read(&db).await;
        assert!(after.tenants.is_empty(), "{after:?}");
        assert!(after.units.is_empty(), "{after:?}");
        assert!(after.key_routes.is_empty(), "{after:?}");
        assert!(after.bucket_index.is_empty(), "{after:?}");
        assert!(gate_open_at_one(&store, &dir).await);
    });
}

#[test]
fn a_lost_open_cas_reports_moved_if_a_second_anchor_appears() {
    block_on(async {
        let db = database();
        let store = HookedRecords::new();
        let dir = SqlDirectory { sql: &db };
        seed(&store, &dir).await;

        let pause = Pause::new(StopAt::OpenGate);
        let mut a = std::pin::pin!(attempt(&store, &db, &pause, A_NOW));
        if let Some(answer) = pause.wait_or_finish(a.as_mut()).await {
            panic!("A completed before the pause: {answer:?}");
        }
        let b = attempt(&store, &db, &Pause::new(StopAt::Never), B_NOW)
            .await
            .unwrap();
        assert!(matches!(b, FirstOpenAnswer::Ran(run) if run.opened && run.epoch == 1));
        let before = Snapshot::read(&db, &store).await;
        assert_eq!(before.anchors, [FIRST_ANCHOR]);

        // A loses the CAS, reads B's open-at-one row, then reaches the
        // anchor listing in open_at_one. Insert anchor 2 at that boundary.
        pause.stop_at.set(StopAt::AnchorList);
        pause.release.notify_one();
        if let Some(answer) = pause.wait_or_finish(a.as_mut()).await {
            panic!("A completed before the pause: {answer:?}");
        }
        store.plant(SECOND_ANCHOR, vec![1]);
        pause.release.notify_one();
        assert_eq!(a.await.unwrap(), FirstOpenAnswer::Moved);
        let mut expected = before;
        expected.anchors.push(SECOND_ANCHOR.into());
        assert_eq!(Snapshot::read(&db, &store).await, expected);
    });
}

#[test]
fn a_first_open_does_not_report_an_epoch_two_open_as_its_own() {
    block_on(async {
        let db = database();
        let store = HookedRecords::new();
        let dir = SqlDirectory { sql: &db };
        seed(&store, &dir).await;

        let pause = Pause::new(StopAt::AfterOpenGate);
        let mut a = std::pin::pin!(attempt(&store, &db, &pause, A_NOW));
        if let Some(answer) = pause.wait_or_finish(a.as_mut()).await {
            panic!("A completed before the pause: {answer:?}");
        }
        assert!(gate_open_at_one(&store, &dir).await);

        // A opened epoch 1. A repair advances and reopens the gate before
        // A can confirm that its own open still holds.
        store.plant(SECOND_ANCHOR, vec![1]);
        assert_eq!(
            db.exec(
                "UPDATE directory_gate SET closed = 0, epoch = 2, opened_at = ?1 \
                 WHERE id = 1 AND closed = 0 AND epoch = 1",
                &[SqlValue::Int(B_NOW.0)],
            )
            .await
            .unwrap(),
            1
        );
        assert!(is_open(&store, &dir).await.unwrap());

        pause.release.notify_one();
        let answer = a.await.unwrap();
        println!("first-open answer: {answer:?}");
        assert!(
            matches!(&answer, FirstOpenAnswer::Ran(run) if !run.opened)
                || matches!(&answer, FirstOpenAnswer::Moved),
            "first open claimed epoch two as its own: {answer:?}"
        );
    });
}

#[test]
fn invalid_first_open_epochs_and_anchors_are_left_untouched() {
    block_on(async {
        for (row, anchors) in [
            (Some((1, 1)), &[][..]),
            (Some((1, 2)), &[FIRST_ANCHOR][..]),
            (Some((0, 2)), &[FIRST_ANCHOR][..]),
            (None, &[SECOND_ANCHOR][..]),
            (Some((0, 1)), &[FIRST_ANCHOR, SECOND_ANCHOR][..]),
            (Some((1, 1)), &["m/dg/0", FIRST_ANCHOR][..]),
            (Some((1, 1)), &[FIRST_ANCHOR, "m/dg/z"][..]),
            (Some((0, 1)), &[][..]),
            (Some((0, 0)), &[][..]),
        ] {
            let db = database();
            let store = HookedRecords::new();
            let dir = SqlDirectory { sql: &db };
            seed(&store, &dir).await;
            for key in anchors {
                store.plant(key, vec![1]);
            }
            if let Some((closed, epoch)) = row {
                db.exec(
                    "INSERT INTO directory_gate (id, closed, epoch, reason, closed_at, opened_at, pending_cleared) \
                     VALUES (1, ?1, ?2, 'fixture', 123, 456, 1)",
                    &[SqlValue::Int(closed), SqlValue::Int(epoch)],
                ).await.unwrap();
            }
            let before = Snapshot::read(&db, &store).await;
            let pause = Pause::new(StopAt::Never);
            let case = format!("row={row:?}, anchors={anchors:?}");
            assert_eq!(
                attempt(&store, &db, &pause, NOW).await.unwrap(),
                FirstOpenAnswer::EpochUnexpected,
                "{case}"
            );
            assert_eq!(pause.writes.get(), 0, "{case}");
            assert_eq!(Snapshot::read(&db, &store).await, before, "{case}");
        }
    });
}

#[test]
fn a_first_open_run_drops_its_fence_once_the_gate_opens() {
    use velmora_bridge::directory::gate::first_open_holds;

    block_on(async {
        let db = database();
        let store = HookedRecords::new();
        let dir = SqlDirectory { sql: &db };
        assert!(
            !first_open_holds(&store, &dir).await.unwrap(),
            "no gate row"
        );
        dir.first_close("fixture", NOW).await.unwrap();
        assert!(
            !first_open_holds(&store, &dir).await.unwrap(),
            "missing anchor"
        );
        store.plant(FIRST_ANCHOR, vec![1]);
        assert!(first_open_holds(&store, &dir).await.unwrap());
        assert!(dir.first_open_gate(NOW).await.unwrap());
        assert!(
            !first_open_holds(&store, &dir).await.unwrap(),
            "gate is open"
        );
    });
}
