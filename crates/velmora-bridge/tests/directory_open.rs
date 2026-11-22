//! The directory gate's first open (AM-78), the pending sweep's rows over
//! `pending_ops` (AM-75) and the per-token backstop counter (ADR §6.3).
//! Under `VELMORA_D1_PROBE` every directory here is a D1 database.

use std::cell::RefCell;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::TenantId;
use velmora_bridge::directory::caps::{
    day_window, CapTake, CAP_COUNT, PRUNE_CAPS, TAKE_CAP, TENANT_CREATE,
};
use velmora_bridge::directory::chain::{record_key, TenantChain, Written};
use velmora_bridge::directory::first_open::{
    first_open, managed_tenant_exists, FirstOpenAnswer, FIRST_OPEN_REASON, REGISTRY_PREFIX,
};
use velmora_bridge::directory::gate::{anchored_epoch, is_open, run_gate_if_closed, NotBuilt};
use velmora_bridge::directory::record::Tenant;
use velmora_bridge::directory::store::{ChainKind, PendingOp, SqlDirectory};
use velmora_bridge::directory::sweep::{
    DROP_ABOVE, NEXT_CHAIN, NEXT_CHAIN_SAME_TENANT, NEXT_TENANT,
};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::keys::locations::{two_in_account, write_locations};
use velmora_bridge::keys::ports::ControlChain;
use velmora_bridge::pending::{sweep, ChainFinisher, ChainHead, ChainKey, PendingRows};
use velmora_bridge::ports::{Sql, SqlValue};
use velmora_bridge::records::RecordStore;
use velmora_bridge::testkit::TestKek;
use velmora_bridge::{Result, UnixMs};

mod directory_support;
use directory_support::{database, on_d1, Db};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const A1: &str = "t_00000000000000a1";
const B2: &str = "t_00000000000000b2";
const C3: &str = "t_00000000000000c3";

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn tid(id: &str) -> TenantId {
    TenantId::parse(id).unwrap()
}

fn t(id: &str) -> Tenant {
    Tenant::parse(id).unwrap()
}

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, derived("first open kek"))])
}

async fn locations(store: &HookedRecords, kek: &TestKek) {
    assert!(
        write_locations(store, kek, &two_in_account(), &mut TestRng(1))
            .await
            .unwrap()
    );
}

/// Every plan line of `sql`, and none a scan of a whole table.
async fn plan(db: &Db, name: &str, sql: &str, params: &[SqlValue]) -> Vec<String> {
    let rows = db
        .query(&format!("EXPLAIN QUERY PLAN {sql}"), params)
        .await
        .unwrap();
    let lines: Vec<String> = rows
        .iter()
        .map(|r| match r.last() {
            Some(SqlValue::Text(s)) => s.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    println!(
        "plan {} {name}: {}",
        if on_d1() { "d1" } else { "sqlite" },
        lines.join(" | ")
    );
    for l in &lines {
        let scan = l.starts_with("SCAN ") && !l.starts_with("SCAN CONSTANT ROW");
        assert!(!scan, "{name}: {l}");
    }
    lines
}

// ---------------------------------------------------------------------------
// The first open
// ---------------------------------------------------------------------------

#[test]
fn managed_tenants_are_found_past_tenant_zero() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        assert!(!managed_tenant_exists(&store).await.unwrap());
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
        assert!(!managed_tenant_exists(&store).await.unwrap());
        store.plant(&record_key(&t(A1), 1), vec![1]);
        assert!(managed_tenant_exists(&store).await.unwrap());
        // A managed chain alone, and a stray name, count too.
        let other = HookedRecords::new();
        other.plant(&record_key(&t(B2), 1), vec![1]);
        assert!(managed_tenant_exists(&other).await.unwrap());
        let stray = HookedRecords::new();
        stray.plant("m/t/zz", vec![1]);
        assert!(managed_tenant_exists(&stray).await.unwrap());
    });
}

/// The first open of an empty directory: it opens once `m/kl/` has its
/// head, copies the locations, starts the feed at the run's epoch, and a
/// second call leaves the open gate and the pending rows alone.
#[test]
fn the_first_open_opens_an_empty_directory_once() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let kek = kek();
    block_on(async {
        // No key locations yet: the run closes and does not open.
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert!(!run.opened);
        let step = run
            .steps
            .iter()
            .find(|(n, _)| *n == "key_locations_and_registry")
            .unwrap();
        assert_eq!(step.1.problems, vec!["key_locations_absent".to_string()]);
        assert!(run
            .steps
            .iter()
            .filter(|(n, _)| *n != "key_locations_and_registry")
            .all(|(_, r)| r.done));
        assert!(!is_open(&store, &dir).await.unwrap());

        locations(&store, &kek).await;
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert!(run.opened, "{run:?}");
        assert_eq!(run.epoch, 2);
        assert!(is_open(&store, &dir).await.unwrap());
        assert_eq!(dir.feed_epoch().await.unwrap(), 2);
        assert_eq!(
            dir.key_locations().await.unwrap(),
            vec![
                ("KEYS_A".to_string(), "active".to_string(), 1),
                ("KEYS_B".to_string(), "active".to_string(), 1),
            ]
        );
        let reason = db
            .query("SELECT reason FROM directory_gate WHERE id = 1", &[])
            .await
            .unwrap();
        assert_eq!(reason[0][0], SqlValue::Text(FIRST_OPEN_REASON.into()));

        // Again: the open gate stays open, nothing is emptied.
        dir.add_pending(&PendingOp {
            tenant: t(A1),
            chain: ChainKind::Keys,
            seq: 1,
            kind: "test".into(),
            created_at: NOW,
        })
        .await
        .unwrap();
        assert_eq!(
            first_open(&chain, &dir, &kek, NOW).await.unwrap(),
            FirstOpenAnswer::AlreadyOpen
        );
        assert!(is_open(&store, &dir).await.unwrap());
        assert_eq!(anchored_epoch(&store).await.unwrap().0, 2);
        assert_eq!(dir.oldest_pending().await.unwrap(), Some(NOW));
    });
}

/// A managed tenant chain refuses the run before anything is written: no
/// anchor, no gate row.
#[test]
fn the_first_open_refuses_a_store_with_tenants() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let kek = kek();
    block_on(async {
        locations(&store, &kek).await;
        let w = chain
            .write(
                &t(A1),
                &Change::Create {
                    jurisdiction: "none".into(),
                    location_hint: None,
                    synthetic: false,
                    limits: BTreeMap::new(),
                    rate_json: Default::default(),
                    features_json: Default::default(),
                },
                Actor::TenantCreation,
                NOW,
                0,
            )
            .await
            .unwrap();
        assert!(matches!(w, Written::Wrote(_)));
        assert_eq!(
            first_open(&chain, &dir, &kek, NOW).await.unwrap(),
            FirstOpenAnswer::HasTenants
        );
        assert_eq!(anchored_epoch(&store).await.unwrap().0, 0);
        assert!(db
            .query("SELECT 1 FROM directory_gate", &[])
            .await
            .unwrap()
            .is_empty());
    });
}

/// Tenant 0's chain does not stop the first open; its row is written by
/// the run's tenant step. A registry chain keeps the gate closed (its copy
/// is not built in milestone 1).
#[test]
fn tenant_zero_opens_and_a_registry_keeps_it_closed() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let kek = kek();
    block_on(async {
        locations(&store, &kek).await;
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
        store.plant(&format!("{REGISTRY_PREFIX}00000000000000000001"), vec![1]);
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert!(!run.opened);
        assert_eq!(run.tenants.written, 1);
        assert!(store.lose(&format!("{REGISTRY_PREFIX}00000000000000000001")));
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert!(run.opened, "{run:?}");
        assert!(dir.tenant(&Tenant::Zero).await.unwrap().is_some());
    });
}

/// A head of `m/kl/` that does not open leaves the step not done.
#[test]
fn key_locations_that_do_not_open_keep_the_gate_closed() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    block_on(async {
        locations(&store, &kek()).await;
        let other = TestKek::with_versions(1, &[(1, derived("another kek"))]);
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &other, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert!(!run.opened);
        let step = run
            .steps
            .iter()
            .find(|(n, _)| *n == "key_locations_and_registry")
            .unwrap();
        assert_eq!(
            step.1.problems,
            vec!["key_locations_unreadable".to_string()]
        );
    });
}

/// A call whose guard passed before another run opened the gate finds it
/// open at its closing: `None` (the call answers `Moved`), no anchor, and
/// the gate stays open.
#[test]
fn a_stale_first_open_guard_writes_no_anchor() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let kek = kek();
    block_on(async {
        locations(&store, &kek).await;
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert!(run.opened);
        let anchors = store.keys();
        let run = run_gate_if_closed(&chain, &dir, &NotBuilt, FIRST_OPEN_REASON, NOW)
            .await
            .unwrap();
        assert!(run.is_none(), "{run:?}");
        assert_eq!(store.keys(), anchors);
        assert!(is_open(&store, &dir).await.unwrap());
        // A closing taken by another call first: `None` too.
        let other = HookedRecords::new();
        let other_chain = TenantChain {
            store: &other,
            seal: &seal,
        };
        let fresh = database();
        let fresh_dir = SqlDirectory { sql: &fresh };
        other.before_put(|key, map| {
            if key.starts_with("m/dg/") {
                map.insert(key.to_string(), vec![1]);
            }
        });
        let run = run_gate_if_closed(&other_chain, &fresh_dir, &NotBuilt, FIRST_OPEN_REASON, NOW)
            .await
            .unwrap();
        assert!(run.is_none());
        assert!(fresh_dir.gate().await.unwrap().epoch == 0);
    });
}

/// The answer of the closing's anchor put is lost after it landed: the row
/// is still closed below the newest anchor, and a call again closes over it
/// and opens.
#[test]
fn first_open_runs_again_after_a_lost_anchor_answer() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let kek = kek();
    block_on(async {
        locations(&store, &kek).await;
        store.lose_answers(1);
        assert!(first_open(&chain, &dir, &kek, NOW).await.is_err());
        assert_eq!(anchored_epoch(&store).await.unwrap().0, 1);
        let gate = dir.gate().await.unwrap();
        assert!(gate.closed && gate.epoch == 0);
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert!(run.opened, "{run:?}");
        assert_eq!(run.epoch, 2);
    });
}

/// A feed epoch ahead of the gate leaves the counters step undone and the gate closed.
#[test]
fn a_newer_feed_epoch_keeps_first_open_closed() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let kek = kek();
    block_on(async {
        locations(&store, &kek).await;
        assert!(dir.start_feed_epoch(50).await.unwrap());
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert_eq!(run.epoch, 1);
        assert!(!run.opened);
        let (_, step) = run.steps.iter().find(|(n, _)| *n == "counters").unwrap();
        assert!(!step.done);
        assert_eq!(step.problems, ["feed_epoch_newer"]);
        assert_eq!(dir.feed_epoch().await.unwrap(), 50);
        assert!(!is_open(&store, &dir).await.unwrap());
    });
}

/// A newer, divergent key location survives first open and leaves the location step undone.
#[test]
fn a_divergent_key_location_keeps_first_open_closed() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let kek = kek();
    block_on(async {
        locations(&store, &kek).await;
        db.exec(
            "INSERT INTO key_locations (location, status, kl_seq) VALUES ('KEYS_A', 'proposed', 2)",
            &[],
        )
        .await
        .unwrap();
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        assert!(!run.opened);
        let (_, step) = run
            .steps
            .iter()
            .find(|(n, _)| *n == "key_locations_and_registry")
            .unwrap();
        assert!(!step.done);
        assert_eq!(step.problems, ["key_locations_differ"]);
        assert_eq!(
            dir.key_locations().await.unwrap(),
            vec![
                ("KEYS_A".into(), "proposed".into(), 2),
                ("KEYS_B".into(), "active".into(), 1)
            ]
        );
        assert!(!is_open(&store, &dir).await.unwrap());
    });
}

// ---------------------------------------------------------------------------
// The pending sweep's rows
// ---------------------------------------------------------------------------

async fn note(dir: &SqlDirectory<'_, Db>, tenant: &str, chain: ChainKind, seq: u64, at: i64) {
    let tenant = Tenant::parse(tenant).unwrap_or(Tenant::Zero);
    dir.add_pending(&PendingOp {
        tenant,
        chain,
        seq,
        kind: format!("k{seq}"),
        created_at: UnixMs(at),
    })
    .await
    .unwrap();
}

fn key(tenant: &str, chain: ControlChain) -> ChainKey {
    ChainKey {
        tenant: tid(tenant),
        chain,
    }
}

/// Chains in key order (tenant, then its key chain before its tenant
/// chain), each with its oldest row; tenant 0's and damaged rows are
/// stepped over; a later note of a row sets its time and kind.
#[test]
fn chains_come_in_key_order_with_their_oldest_row() {
    let db = database();
    let dir = SqlDirectory { sql: &db };
    block_on(async {
        note(&dir, B2, ChainKind::Tenant, 3, 50).await;
        note(&dir, B2, ChainKind::Tenant, 4, 40).await;
        note(&dir, A1, ChainKind::Tenant, 1, 70).await;
        note(&dir, A1, ChainKind::Keys, 9, 60).await;
        note(&dir, A1, ChainKind::Keys, 10, 65).await;
        note(&dir, C3, ChainKind::Keys, 1, 10).await;
        note(&dir, "t_0000000000000000", ChainKind::Tenant, 1, 5).await;
        db.exec(
            "INSERT INTO pending_ops (tenant, chain, seq, kind, created_at) VALUES ('t_zz', 'k', 1, 'x', 1)",
            &[],
        )
        .await
        .unwrap();
        let all = dir.chains_after(None, 100).await.unwrap();
        assert_eq!(
            all,
            vec![
                (key(A1, ControlChain::Keys), UnixMs(60)),
                (key(A1, ControlChain::Tenant), UnixMs(70)),
                (key(B2, ControlChain::Tenant), UnixMs(40)),
                (key(C3, ControlChain::Keys), UnixMs(10)),
            ]
        );
        assert_eq!(dir.chains_after(None, 2).await.unwrap(), all[..2].to_vec());
        assert_eq!(
            dir.chains_after(Some(&all[1].0), 2).await.unwrap(),
            all[2..].to_vec()
        );
        assert!(dir
            .chains_after(Some(&all[3].0), 2)
            .await
            .unwrap()
            .is_empty());

        // DO UPDATE: the note again sets the row's time and kind.
        dir.add_pending(&PendingOp {
            tenant: t(B2),
            chain: ChainKind::Tenant,
            seq: 4,
            kind: "re-noted".into(),
            created_at: UnixMs(90),
        })
        .await
        .unwrap();
        let rows = db
            .query(
                "SELECT kind, created_at FROM pending_ops WHERE tenant = ?1 AND seq = 4",
                &[SqlValue::Text(B2.into())],
            )
            .await
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![SqlValue::Text("re-noted".into()), SqlValue::Int(90)]]
        );
        assert_eq!(
            dir.chains_after(Some(&all[1].0), 1).await.unwrap(),
            vec![(key(B2, ControlChain::Tenant), UnixMs(50))]
        );

        // Above the head and noted at or before the cutoff only.
        assert_eq!(
            dir.drop_above(&key(B2, ControlChain::Tenant), 2, UnixMs(60))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            dir.drop_above(&key(A1, ControlChain::Keys), 9, UnixMs(100))
                .await
                .unwrap(),
            1
        );
        let left = db
            .query(
                "SELECT tenant, chain, seq FROM pending_ops ORDER BY tenant, chain, seq",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(left.len(), 6, "{left:?}");
    });
}

struct Heads(RefCell<BTreeMap<String, ChainHead>>);

impl ChainFinisher for Heads {
    async fn finish(&self, chain: &ChainKey) -> Result<ChainHead> {
        let name = format!("{}/{:?}", chain.tenant.as_str(), chain.chain);
        Ok(self.0.borrow().get(&name).copied().unwrap_or(ChainHead {
            seq: 0,
            complete: true,
        }))
    }
}

/// The sweep over the directory's rows: rows above a complete head and
/// older than the cutoff are dropped; an incomplete head keeps them.
#[test]
fn the_sweep_runs_over_the_directory_rows() {
    let db = database();
    let dir = SqlDirectory { sql: &db };
    block_on(async {
        let old = NOW.0 - 10 * 60_000;
        note(&dir, A1, ChainKind::Tenant, 5, old).await;
        note(&dir, A1, ChainKind::Tenant, 6, old).await;
        note(&dir, B2, ChainKind::Keys, 3, old).await;
        note(&dir, C3, ChainKind::Keys, 2, NOW.0).await;
        let heads = Heads(RefCell::new(BTreeMap::from([
            (
                format!("{A1}/Tenant"),
                ChainHead {
                    seq: 5,
                    complete: true,
                },
            ),
            (
                format!("{B2}/Keys"),
                ChainHead {
                    seq: 2,
                    complete: false,
                },
            ),
        ])));
        let report = sweep(&dir, &heads, NOW, None).await.unwrap();
        assert_eq!(
            (report.finished, report.incomplete, report.dropped),
            (1, 1, 1)
        );
        assert_eq!(report.next_after, None);
        let left = db
            .query(
                "SELECT tenant, seq FROM pending_ops ORDER BY tenant, seq",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(left.len(), 3, "{left:?}");
    });
}

/// Pending-chain seek and clear use bounded primary-key ranges; sweep and cap queries do not scan.
#[test]
fn the_sweep_and_the_backstop_read_through_an_index() {
    let db = database();
    block_on(async {
        let text = |s: &str| SqlValue::Text(s.into());
        let next = plan(&db, "NEXT_CHAIN", NEXT_CHAIN, &[text(A1), text("k")]).await;
        assert!(
            next.iter().any(|l| l.contains("pending_ops_chain_created")),
            "{next:?}"
        );
        assert!(
            next.iter()
                .any(|l| l.contains("sqlite_autoindex_pending_ops_1 ((tenant,chain,seq)>(?,?,?))")),
            "{next:?}"
        );
        let clear = plan(
            &db,
            "clear_pending",
            velmora_bridge::directory::store::CLEAR_PENDING,
            &[text(A1), text("k"), SqlValue::Int(1)],
        )
        .await;
        assert!(
            clear
                .iter()
                .any(|l| l
                    .contains("sqlite_autoindex_pending_ops_1 (tenant=? AND chain=? AND seq<?)")),
            "{clear:?}"
        );
        let same = plan(
            &db,
            "NEXT_CHAIN_SAME_TENANT",
            NEXT_CHAIN_SAME_TENANT,
            &[text(A1), text("k")],
        )
        .await;
        assert!(
            same.iter().any(|l| l.contains("(tenant=? AND chain>?)")),
            "{same:?}"
        );
        let later = plan(&db, "NEXT_TENANT", NEXT_TENANT, &[text(A1), text("k")]).await;
        assert!(later.iter().any(|l| l.contains("(tenant>?)")), "{later:?}");
        plan(
            &db,
            "DROP_ABOVE",
            DROP_ABOVE,
            &[text(A1), text("t"), SqlValue::Int(1), SqlValue::Int(1)],
        )
        .await;
        plan(
            &db,
            "TAKE_CAP",
            TAKE_CAP,
            &[
                SqlValue::Int(1),
                text("tok"),
                text(TENANT_CREATE),
                SqlValue::Int(50),
            ],
        )
        .await;
        plan(
            &db,
            "CAP_COUNT",
            CAP_COUNT,
            &[SqlValue::Int(1), text("tok"), text(TENANT_CREATE)],
        )
        .await;
        plan(
            &db,
            "PRUNE_CAPS",
            PRUNE_CAPS,
            &[SqlValue::Int(1), SqlValue::Int(10)],
        )
        .await;
        plan(
            &db,
            "keys_seq_of",
            velmora_bridge::directory::store::KEYS_SEQ_OF,
            &[text(A1)],
        )
        .await;
    });
}

// ---------------------------------------------------------------------------
// The backstop
// ---------------------------------------------------------------------------

/// The window counts up to the cap and no further; tokens, actions and
/// windows count apart; old windows are pruned.
#[test]
fn the_backstop_counts_to_its_cap() {
    let db = database();
    let dir = SqlDirectory { sql: &db };
    block_on(async {
        let day = day_window(NOW);
        assert_eq!(day % (24 * 3_600_000), 0);
        assert!(day <= NOW.0 && NOW.0 - day < 24 * 3_600_000);
        for n in 1..=3 {
            assert_eq!(
                dir.take_token_cap("kofra_std", TENANT_CREATE, day, 3)
                    .await
                    .unwrap(),
                CapTake::Taken { count: n }
            );
        }
        assert_eq!(
            dir.take_token_cap("kofra_std", TENANT_CREATE, day, 3)
                .await
                .unwrap(),
            CapTake::Full
        );
        assert_eq!(
            dir.take_token_cap("kofra_billing", TENANT_CREATE, day, 3)
                .await
                .unwrap(),
            CapTake::Taken { count: 1 }
        );
        assert_eq!(
            dir.take_token_cap("kofra_std", "suspend", day, 3)
                .await
                .unwrap(),
            CapTake::Taken { count: 1 }
        );
        let tomorrow = day + 24 * 3_600_000;
        assert_eq!(
            dir.take_token_cap("kofra_std", TENANT_CREATE, tomorrow, 3)
                .await
                .unwrap(),
            CapTake::Taken { count: 1 }
        );
        assert_eq!(
            dir.take_token_cap("kofra_std", TENANT_CREATE, day, 0)
                .await
                .unwrap(),
            CapTake::Full
        );
        for bad in ["", "a b", &"x".repeat(65)] {
            assert!(dir
                .take_token_cap(bad, TENANT_CREATE, day, 3)
                .await
                .is_err());
            assert!(dir.take_token_cap("kofra_std", bad, day, 3).await.is_err());
        }
        assert_eq!(dir.prune_token_caps(tomorrow, 1000).await.unwrap(), 3);
        assert!(dir.prune_token_caps(tomorrow, 0).await.is_err());
        assert_eq!(
            dir.take_token_cap("kofra_std", TENANT_CREATE, tomorrow, 3)
                .await
                .unwrap(),
            CapTake::Taken { count: 2 }
        );
    });
}

/// A zero cap refuses a fresh window without creating its counter row.
#[test]
fn a_zero_cap_writes_no_counter_row() {
    let db = database();
    let dir = SqlDirectory { sql: &db };
    block_on(async {
        let day = day_window(NOW);
        assert_eq!(
            dir.take_token_cap("kofra_std", TENANT_CREATE, day, 0)
                .await
                .unwrap(),
            CapTake::Full
        );
        let rows = db
            .query(
                CAP_COUNT,
                &[
                    SqlValue::Int(day),
                    SqlValue::Text("kofra_std".into()),
                    SqlValue::Text(TENANT_CREATE.into()),
                ],
            )
            .await
            .unwrap();
        assert!(rows.is_empty(), "{rows:?}");
    });
}

/// Prune rejects a limit over 1000 and deletes at most the requested rows per call.
#[test]
fn cap_pruning_rejects_oversize_limits_and_bounds_each_delete() {
    let db = database();
    let dir = SqlDirectory { sql: &db };
    block_on(async {
        let day = day_window(NOW);
        for days_ago in 1..=3 {
            assert_eq!(
                dir.take_token_cap("kofra_std", TENANT_CREATE, day - days_ago * 86_400_000, 1)
                    .await
                    .unwrap(),
                CapTake::Taken { count: 1 }
            );
        }
        assert!(dir.prune_token_caps(day, 1001).await.is_err());
        assert_eq!(dir.prune_token_caps(day, 2).await.unwrap(), 2);
        assert_eq!(dir.prune_token_caps(day, 2).await.unwrap(), 1);
    });
}

/// A row whose seq the whole-key seek does not pass (damage: above
/// `MAX_SQL_INT`, or not an integer) is stepped past on the chain's first
/// two columns: the sweep moves on to the next chain, and a damaged tenant
/// id is stepped over without a loop.
#[test]
fn a_damaged_seq_does_not_stop_the_sweep() {
    let db = database();
    let dir = SqlDirectory { sql: &db };
    block_on(async {
        for (tenant, chain, seq) in [
            (A1, "k", "9223372036854775807"),
            (A1, "t", "'x'"),
            ("t_zz", "k", "9223372036854775807"),
        ] {
            db.exec(
                &format!(
                    "INSERT INTO pending_ops (tenant, chain, seq, kind, created_at) \
                     VALUES ('{tenant}', '{chain}', {seq}, 'x', 1)"
                ),
                &[],
            )
            .await
            .unwrap();
        }
        note(&dir, B2, ChainKind::Tenant, 1, 5).await;
        let all = dir.chains_after(None, 100).await.unwrap();
        assert_eq!(
            all,
            vec![
                (key(A1, ControlChain::Keys), UnixMs(1)),
                (key(A1, ControlChain::Tenant), UnixMs(1)),
                (key(B2, ControlChain::Tenant), UnixMs(5)),
            ]
        );
    });
}

/// A gate whose row says open under a newer anchor is closed (`is_open`),
/// and a first-open call closes over it and opens; a stray name before the
/// first anchor likewise.
#[test]
fn a_first_open_recovers_a_row_open_under_a_newer_anchor() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let kek = kek();
    block_on(async {
        locations(&store, &kek).await;
        store.plant("m/dg/0", vec![1]);
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run");
        };
        // The stray name keeps epoch 1 from opening.
        assert!(!run.opened);
        assert!(!is_open(&store, &dir).await.unwrap());
        let FirstOpenAnswer::Ran(run) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("a retry did not run");
        };
        assert!(run.opened, "{run:?}");
        assert!(is_open(&store, &dir).await.unwrap());
        // An anchor put whose row write was lost, over an open gate.
        store.plant(&format!("m/dg/{:020}", run.epoch + 1), vec![1]);
        assert!(!is_open(&store, &dir).await.unwrap());
        let FirstOpenAnswer::Ran(again) = first_open(&chain, &dir, &kek, NOW).await.unwrap() else {
            panic!("no run over the newer anchor");
        };
        assert!(again.opened);
        assert_eq!(again.epoch, run.epoch + 2);
    });
}

/// The store of these tests holds nothing but what they put.
#[test]
fn a_fresh_store_lists_nothing() {
    let store = HookedRecords::new();
    block_on(async {
        assert!(store.list("m/", "", 10).await.unwrap().is_empty());
    });
}
