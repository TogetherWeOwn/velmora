//! Interleavings of first-open calls from two isolates sharing only their stores.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;

use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use velmora::rng::FillRandom;
use velmora_bridge::directory::chain::TenantChain;
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
    chain
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
        .unwrap();
    note(dir, A1, "tenant_create", NOW).await;
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
    FirstWrite,
    Io(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Io {
    Other,
    Write,
    OpenGate,
}

/// One stop shared by the two adapters of one attempt, not by both attempts.
struct Pause {
    stop_at: Cell<StopAt>,
    calls: Cell<usize>,
    reached: Notify,
    release: Notify,
}

impl Pause {
    fn new(stop_at: StopAt) -> Self {
        Self {
            stop_at: Cell::new(stop_at),
            calls: Cell::new(0),
            reached: Notify::new(),
            release: Notify::new(),
        }
    }

    async fn before(&self, io: Io) {
        let call = self.calls.get();
        self.calls.set(call + 1);
        let stop = match self.stop_at.get() {
            StopAt::Never => false,
            StopAt::OpenGate => io == Io::OpenGate,
            StopAt::FirstWrite => matches!(io, Io::Write | Io::OpenGate),
            StopAt::Io(k) => call == k,
        };
        if stop {
            self.stop_at.set(StopAt::Never);
            self.reached.notify_one();
            self.release.notified().await;
        }
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
        self.pause.before(Io::Other).await;
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
        self.pause.before(Io::Other).await;
        self.db.query(sql, params).await
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let io = if sql.starts_with("UPDATE directory_gate SET closed = 0") {
            Io::OpenGate
        } else {
            Io::Write
        };
        self.pause.before(io).await;
        self.db.exec(sql, params).await
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

struct Snapshot {
    gate: Vec<Row>,
    pending: Vec<Row>,
    anchors: Vec<String>,
}

impl Snapshot {
    async fn read(db: &Db, store: &HookedRecords) -> Self {
        Self {
            gate: db
                .query(
                    "SELECT id, closed, epoch, reason, closed_at, opened_at FROM directory_gate",
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
        // A contender that finishes without a write is also safe. Otherwise
        // B's write cannot run until A opens and the create lands.
        let b_finished = b_pause.wait_or_finish(b.as_mut()).await;

        a_pause.release.notify_one();
        let a_answer = a.await;
        assert!(gate_open_at_one(&store, &dir).await, "A={a_answer:?}");
        create(&store, &dir).await;
        let before = Snapshot::read(&db, &store).await;
        assert_eq!(before.anchors, [FIRST_ANCHOR]);
        assert_eq!(before.pending, [create_pending_row()]);

        let b_answer = match b_finished {
            Some(answer) => answer,
            None => {
                b_pause.release.notify_one();
                b.await
            }
        };
        eprintln!("A={a_answer:?}; B={b_answer:?}");

        let after = Snapshot::read(&db, &store).await;
        assert_eq!(after.anchors, [FIRST_ANCHOR], "B added a gate anchor");
        assert_eq!(after.pending, before.pending, "B changed pending_ops");
        assert_eq!(after.gate, before.gate, "B changed the open gate row");
        assert!(gate_open_at_one(&store, &dir).await);
    });
}

#[test]
fn first_open_interleaved_at_every_await_point() {
    let mut failures = Vec::new();
    let mut covered = 0;
    loop {
        let k = covered;
        let hit_pause = block_on(async {
            let db = database();
            let store = HookedRecords::new();
            let dir = SqlDirectory { sql: &db };
            seed(&store, &dir).await;

            let a_pause = Pause::new(StopAt::Io(k));
            let mut a = std::pin::pin!(attempt(&store, &db, &a_pause, A_NOW));
            if a_pause.wait_or_finish(a.as_mut()).await.is_some() {
                return false;
            }

            let b_answer = attempt(&store, &db, &Pause::new(StopAt::Never), B_NOW).await;
            let before = if is_open(&store, &dir).await.unwrap() {
                create(&store, &dir).await;
                Some(Snapshot::read(&db, &store).await)
            } else {
                None
            };

            a_pause.release.notify_one();
            let a_answer = a.await;
            let after = Snapshot::read(&db, &store).await;
            let mut problems = Vec::new();
            if !gate_open_at_one(&store, &dir).await {
                problems.push("gate not open at epoch 1");
            }
            if after.anchors != [FIRST_ANCHOR] {
                problems.push("anchor keys are not exactly epoch 1");
            }
            if let Some(before) = before {
                if !after.pending.contains(&create_pending_row()) || after.pending != before.pending
                {
                    problems.push("the create's pending row was lost or A changed pending_ops");
                }
                if after.gate != before.gate {
                    problems.push("A changed the open gate row after the create");
                }
            }
            if !problems.is_empty() {
                failures.push(format!(
                    "k={k}: {problems:?}; A={a_answer:?}; B={b_answer:?}"
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
