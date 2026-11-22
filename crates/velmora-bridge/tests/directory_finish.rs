//! The directory as a store of both chains (AM-75): the key chain's
//! directory target (`DirectoryKeys`, `UnboundDirectory`) and the tenant
//! chain's finisher (`finish_tenant`), with the events each writes. Under
//! `VELMORA_D1_PROBE` every directory here is a D1 database.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{wrap_secret_v2, TenantId, TenantKey};
use velmora_bridge::directory::chain::{TenantChain, Written};
use velmora_bridge::directory::events::EVENT_TYPES;
use velmora_bridge::directory::finish::{
    finish_tenant, StoreStep, TenantFinisher, TenantUnits, UnitHolds, ERR_NOT_TENANT_CHAIN,
    MAX_FINISH_RECORDS,
};
use velmora_bridge::directory::keys::{
    is, pages, DirectoryKeys, UnboundDirectory, ERR_APPLY_SHAPE, ERR_NO_TENANT_ROW,
    ERR_ROUTE_CONFLICT, ERR_ROUTE_WRONG_KIND,
};
use velmora_bridge::directory::record::{
    DeletionReason, HoldMode, OperatorReason, Tenant, TenantState,
};
use velmora_bridge::directory::store::{ChainKind, KeyRoute, PendingOp, RouteKind, SqlDirectory};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::WriteOrder;
use velmora_bridge::directory::transition::{Actor, Change, OperatorHoldRequest, KEY_CHECK_LEN};
use velmora_bridge::keys::apply::{Feed, Mode};
use velmora_bridge::keys::chain::Put;
use velmora_bridge::keys::checkpoint::read_key_chain;
use velmora_bridge::keys::ports::{Applied, ApplyEntry, ControlChain, KeyTarget, MAX_APPLY};
use velmora_bridge::keys::record::{
    key_chain, seal_key_record, seal_marker_record, Access, Grant, KeyOp, Marker, OneKey, Subject,
    SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus,
};
use velmora_bridge::pending::{ChainFinisher, ChainKey};
use velmora_bridge::ports::{Row, Sql, SqlValue};
use velmora_bridge::testkit::TestKek;
use velmora_bridge::{BridgeError, Result, UnixMs};

mod directory_support;
use directory_support::{database, Db};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const DAY: i64 = 24 * 3_600_000;
const A1: &str = "t_00000000000000a1";
const B2: &str = "t_00000000000000b2";

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

fn hash(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

// ---------------------------------------------------------------------------
// The tenant chain
// ---------------------------------------------------------------------------

type Chain<'a> = TenantChain<'a, HookedRecords, PlainSeal>;

fn create() -> Change {
    Change::Create {
        jurisdiction: "none".into(),
        location_hint: None,
        synthetic: false,
        limits: BTreeMap::new(),
        rate_json: Default::default(),
        features_json: Default::default(),
    }
}

fn hold(mode: HoldMode) -> Change {
    Change::SetOperatorHold {
        hold: Some(OperatorHoldRequest {
            mode,
            reason: OperatorReason::Security,
            preserve: None,
        }),
    }
}

async fn write(chain: &Chain<'_>, tenant: &str, change: Change, actor: Actor) -> u64 {
    match chain.write(&t(tenant), &change, actor, NOW, 0).await {
        Ok(Written::Wrote(r)) => r.door.seq,
        other => panic!("{change:?}: {:?}", other.map(|_| ()).err()),
    }
}

/// `tenant` from its create to `active`: 4 records.
async fn active(chain: &Chain<'_>, tenant: &str) {
    for change in [
        create(),
        Change::ClaimKeyVersion { version: 1 },
        Change::CommitKeyVersion {
            version: 1,
            kcv: [1; KEY_CHECK_LEN],
        },
        Change::Activate {
            external_ref: Some("ws_1".into()),
        },
    ] {
        write(chain, tenant, change, Actor::TenantCreation).await;
    }
}

// ---------------------------------------------------------------------------
// The units
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Answer {
    /// The unit holds the head the test set in `head`.
    Head,
    Seq(u64),
    Unborn,
    Fail,
}

/// The tenant's units: each answers as told, and notes the directory
/// row's seq at the moment it is brought up.
struct Units<'a> {
    db: &'a Db,
    head: Cell<u64>,
    answers: RefCell<BTreeMap<u32, Answer>>,
    /// (unit, the directory row's seq when the unit was brought up).
    log: RefCell<Vec<(u32, Option<u64>)>>,
    born: RefCell<Vec<u32>>,
    born_fails: Cell<bool>,
}

impl<'a> Units<'a> {
    fn new(db: &'a Db) -> Self {
        Units {
            db,
            head: Cell::new(0),
            answers: RefCell::new(BTreeMap::new()),
            log: RefCell::new(Vec::new()),
            born: RefCell::new(Vec::new()),
            born_fails: Cell::new(false),
        }
    }

    fn answer(&self, unit: u32, a: Answer) {
        self.answers.borrow_mut().insert(unit, a);
    }

    fn take_log(&self) -> Vec<(u32, Option<u64>)> {
        std::mem::take(&mut *self.log.borrow_mut())
    }
}

impl TenantUnits for Units<'_> {
    async fn bring_up(&self, tenant: &TenantId, unit: u32) -> Result<UnitHolds> {
        let dir = SqlDirectory { sql: self.db };
        let row = dir
            .raw_tenant(&Tenant::Managed(tenant.clone()))
            .await
            .unwrap()
            .and_then(|r| r.record_seq);
        self.log.borrow_mut().push((unit, row));
        let a = self
            .answers
            .borrow()
            .get(&unit)
            .copied()
            .unwrap_or(Answer::Head);
        match a {
            Answer::Head => Ok(UnitHolds::Seq {
                state_seq: self.head.get(),
            }),
            Answer::Seq(n) => Ok(UnitHolds::Seq { state_seq: n }),
            Answer::Unborn => Ok(UnitHolds::Unborn),
            Answer::Fail => Err(BridgeError::Invalid("unit down")),
        }
    }

    async fn mark_born(&self, _tenant: &TenantId, unit: u32) -> Result<()> {
        if self.born_fails.get() {
            return Err(BridgeError::Invalid("marker put failed"));
        }
        self.born.borrow_mut().push(unit);
        Ok(())
    }
}

/// A directory database whose statements fail while they contain `fail`.
struct Flaky<'a> {
    db: &'a Db,
    fail: RefCell<Option<&'static str>>,
}

impl<'a> Flaky<'a> {
    fn new(db: &'a Db) -> Self {
        Flaky {
            db,
            fail: RefCell::new(None),
        }
    }

    fn fail(&self, on: Option<&'static str>) {
        *self.fail.borrow_mut() = on;
    }

    fn hit(&self, sql: &str) -> bool {
        self.fail.borrow().is_some_and(|f| sql.contains(f))
    }
}

impl Sql for Flaky<'_> {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        if self.hit(sql) {
            return Err(BridgeError::Sql("down".into()));
        }
        self.db.query(sql, params).await
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        if self.hit(sql) {
            return Err(BridgeError::Sql("down".into()));
        }
        self.db.exec(sql, params).await
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if stmts.iter().any(|(sql, _)| self.hit(sql)) {
            return Err(BridgeError::Sql("down".into()));
        }
        self.db.batch(stmts).await
    }
}

/// Every event of `tenant` in the feed: (type, source, data).
async fn events(db: &Db, tenant: &str) -> Vec<(String, String, Value)> {
    let rows = db
        .query(
            "SELECT type, source, data_json FROM tenant_events WHERE tenant = ?1 ORDER BY seq",
            &[SqlValue::Text(tenant.into())],
        )
        .await
        .unwrap();
    rows.into_iter()
        .map(|r| match r.as_slice() {
            [SqlValue::Text(k), SqlValue::Text(s), SqlValue::Text(d)] => {
                (k.clone(), s.clone(), serde_json::from_str(d).unwrap())
            }
            other => panic!("{other:?}"),
        })
        .collect()
}

async fn pending_seqs(db: &Db, tenant: &str, chain: &str) -> Vec<i64> {
    db.query(
        "SELECT seq FROM pending_ops WHERE tenant = ?1 AND chain = ?2 ORDER BY seq",
        &[SqlValue::Text(tenant.into()), SqlValue::Text(chain.into())],
    )
    .await
    .unwrap()
    .into_iter()
    .map(|r| match r.as_slice() {
        [SqlValue::Int(n)] => *n,
        other => panic!("{other:?}"),
    })
    .collect()
}

async fn note(dir: &SqlDirectory<'_, Db>, tenant: &str, chain: ChainKind, seq: u64) {
    dir.add_pending(&PendingOp {
        tenant: t(tenant),
        chain,
        seq,
        kind: "test".into(),
        created_at: NOW,
    })
    .await
    .unwrap();
}

async fn row_seq(db: &Db, tenant: &str) -> Option<u64> {
    SqlDirectory { sql: db }
        .raw_tenant(&t(tenant))
        .await
        .unwrap()
        .and_then(|r| r.record_seq)
}

// ---------------------------------------------------------------------------
// The tenant finisher
// ---------------------------------------------------------------------------

/// A new tenant's records all open: the directory takes the head before
/// any unit is brought up, the root unit's born marker is written, and the
/// rows up to the head are cleared.
#[test]
fn an_opening_reaches_the_directory_before_the_units() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let units = Units::new(&db);
    block_on(async {
        active(&chain, A1).await;
        units.head.set(4);
        for seq in 1..=4 {
            note(&dir, A1, ChainKind::Tenant, seq).await;
        }
        note(&dir, A1, ChainKind::Keys, 1).await;
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.head.seq, 4);
        assert!(run.head.complete);
        assert_eq!(run.order, Some(WriteOrder::Opening));
        assert_eq!(run.directory, StoreStep::Holds(4));
        assert_eq!(run.units, vec![(0, StoreStep::Holds(4))]);
        // The unit saw the directory at the head already.
        assert_eq!(units.take_log(), vec![(0, Some(4))]);
        assert_eq!(*units.born.borrow(), vec![0]);
        assert_eq!(run.cleared_to, Some(4));
        assert!(pending_seqs(&db, A1, "t").await.is_empty());
        // The key chain's row is not the tenant finisher's.
        assert_eq!(pending_seqs(&db, A1, "k").await, vec![1]);
        let row = dir.tenant(&t(A1)).await.unwrap().unwrap();
        assert_eq!(row.door.state(), TenantState::Active);
        // Creation makes no event.
        assert!(events(&db, A1).await.is_empty());
        assert!(run.pages.is_empty());

        // A second run changes nothing and appends nothing.
        let again = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(again.directory, StoreStep::Holds(4));
        assert_eq!(again.events, 0);
        assert!(events(&db, A1).await.is_empty());
    });
}

/// A hold closes: every unit is brought up while the directory still
/// holds the older head, then the directory; the event names the hold
/// and the call that made it.
#[test]
fn a_closing_reaches_the_units_before_the_directory() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let units = Units::new(&db);
    block_on(async {
        active(&chain, A1).await;
        // Two units: the root and unit 2.
        write(
            &chain,
            A1,
            Change::SetUnits {
                base_seq: 4,
                units: vec![0, 2],
                placements: vec![],
            },
            Actor::Operator,
        )
        .await;
        units.head.set(5);
        finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        units.take_log();
        let key = hash(9);
        let w = chain
            .write_keyed(
                &t(A1),
                &hold(HoldMode::Locked),
                Actor::Operator,
                NOW,
                0,
                Some(&key),
            )
            .await
            .unwrap();
        assert!(matches!(w, Written::Wrote(_)));
        units.head.set(6);
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.order, Some(WriteOrder::Closing));
        // Both units, the root first, while the row still said 5.
        assert_eq!(units.take_log(), vec![(0, Some(5)), (2, Some(5))]);
        assert_eq!(run.directory, StoreStep::Holds(6));
        assert_eq!(row_seq(&db, A1).await, Some(6));
        assert_eq!(
            events(&db, A1).await,
            vec![(
                "tenant.suspended".to_string(),
                "t/6".to_string(),
                json!({"mode": "locked", "key_hash": key}),
            )]
        );
        assert_eq!(run.events, 1);
    });
}

/// An opening whose directory step fails reaches no unit; a closing
/// whose directory step fails still reaches every unit. Nothing is
/// cleared while the directory is behind.
#[test]
fn an_opening_waits_for_the_directory_and_a_closing_does_not() {
    let db = database();
    let flaky = Flaky::new(&db);
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &flaky };
    let units = Units::new(&db);
    block_on(async {
        active(&chain, A1).await;
        units.head.set(4);
        note(&SqlDirectory { sql: &db }, A1, ChainKind::Tenant, 4).await;
        // The tenants row cannot be written.
        flaky.fail(Some("INSERT INTO tenants"));
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.order, Some(WriteOrder::Opening));
        assert_eq!(run.directory, StoreStep::Failed);
        assert_eq!(run.units, vec![(0, StoreStep::Waiting)]);
        assert!(
            units.take_log().is_empty(),
            "an opening reached a unit first"
        );
        assert_eq!(run.cleared_to, None);
        assert_eq!(pending_seqs(&db, A1, "t").await, vec![4]);

        flaky.fail(None);
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.units, vec![(0, StoreStep::Holds(4))]);
        assert_eq!(units.take_log(), vec![(0, Some(4))]);

        // A closing with the directory down: the unit still gets it.
        write(&chain, A1, hold(HoldMode::ReadOnly), Actor::Operator).await;
        units.head.set(5);
        flaky.fail(Some("tenant"));
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.order, Some(WriteOrder::Closing));
        assert_eq!(run.directory, StoreStep::Failed);
        assert_eq!(run.units, vec![(0, StoreStep::Holds(5))]);
        assert_eq!(run.cleared_to, None);
        flaky.fail(None);
        assert_eq!(row_seq(&db, A1).await, Some(4));
    });
}

/// With no directory bound, the units get every change at once, and
/// nothing is cleared (there is no table).
#[test]
fn with_no_directory_the_units_get_the_head() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let units = Units::new(&db);
    block_on(async {
        active(&chain, A1).await;
        units.head.set(4);
        let run = finish_tenant::<_, _, Db, _>(&chain, None, &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.directory, StoreStep::Unbound);
        assert_eq!(run.units, vec![(0, StoreStep::Holds(4))]);
        assert_eq!(run.cleared_to, None);
        assert_eq!(row_seq(&db, A1).await, None);
    });
}

/// The rows of the chain are cleared up to what every store holds: the
/// lowest of the directory and each unit.
#[test]
fn rows_are_cleared_at_what_every_store_holds() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let units = Units::new(&db);
    block_on(async {
        active(&chain, A1).await;
        for seq in 2..=6 {
            note(&dir, A1, ChainKind::Tenant, seq).await;
        }
        units.answer(0, Answer::Seq(3));
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.cleared_to, Some(3));
        assert_eq!(pending_seqs(&db, A1, "t").await, vec![4, 5, 6]);
        units.answer(0, Answer::Fail);
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.units, vec![(0, StoreStep::Failed)]);
        assert_eq!(run.cleared_to, None);
        units.answer(0, Answer::Seq(4));
        finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        // Rows above the head stay: the sweep drops them.
        assert_eq!(pending_seqs(&db, A1, "t").await, vec![5, 6]);
    });
}

/// Under a `provisioning` head an unborn root unit is expected: it counts
/// as holding the head, and no marker is written. Once the tenant is past
/// provisioning, an unborn unit holds nothing.
#[test]
fn an_unborn_unit_counts_only_while_provisioning() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let units = Units::new(&db);
    block_on(async {
        write(&chain, A1, create(), Actor::TenantCreation).await;
        note(&dir, A1, ChainKind::Tenant, 1).await;
        units.answer(0, Answer::Unborn);
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.units, vec![(0, StoreStep::Unborn)]);
        assert_eq!(run.cleared_to, Some(1));
        assert!(units.born.borrow().is_empty());
        for change in [
            Change::ClaimKeyVersion { version: 1 },
            Change::CommitKeyVersion {
                version: 1,
                kcv: [1; KEY_CHECK_LEN],
            },
            Change::Activate { external_ref: None },
        ] {
            write(&chain, A1, change, Actor::TenantCreation).await;
        }
        note(&dir, A1, ChainKind::Tenant, 4).await;
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.units, vec![(0, StoreStep::Unborn)]);
        assert_eq!(run.cleared_to, None);
        assert_eq!(pending_seqs(&db, A1, "t").await, vec![4]);
        // A marker that cannot be written is reported; the unit holds.
        units.answer(0, Answer::Head);
        units.head.set(4);
        units.born_fails.set(true);
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.units, vec![(0, StoreStep::Holds(4))]);
        assert_eq!(run.born_failed, vec![0]);
    });
}

/// Every record's events, in seq order, with their sources; a record with
/// more than one numbers them; a bucket create names the bucket from the
/// private part; a crash after the events and before the row repeats
/// them, and the feed keeps one row each.
#[test]
fn events_come_from_the_records_once_each() {
    let db = database();
    let flaky = Flaky::new(&db);
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &flaky };
    let units = Units::new(&db);
    block_on(async {
        active(&chain, A1).await;
        let bucket = velmora_bridge::records::bucket_id(&tid(A1), 3)
            .as_str()
            .to_owned();
        let mut wrap = vec![7; velmora_bridge::crypto::WRAPPED_KEY_LEN];
        wrap[0] = velmora_bridge::crypto::scheme2::WRAP_VERSION_2;
        let s5 = write(
            &chain,
            A1,
            Change::CreateBucket {
                bucket: bucket.clone(),
                unit: 0,
                creator: "p_00000000000000aa".into(),
                grant_seq: 3,
                name: "photos".into(),
                bdk_wrapped: wrap,
                tk_version: 1,
            },
            Actor::Customer,
        )
        .await;
        let s6 = write(
            &chain,
            A1,
            Change::SetBillingHold {
                mode: Some(HoldMode::ReadOnly),
            },
            Actor::Billing,
        )
        .await;
        let s7 = write(
            &chain,
            A1,
            Change::SetDeletion {
                shred_due_at: UnixMs(NOW.0 + 61 * DAY),
                reason: DeletionReason::NonPayment,
                key_hash: hash(1),
            },
            Actor::Billing,
        )
        .await;
        // Lifting the billing hold clears its deletion: two events.
        let s8 = write(
            &chain,
            A1,
            Change::SetBillingHold { mode: None },
            Actor::Billing,
        )
        .await;
        let s9 = write(
            &chain,
            A1,
            Change::DropBucket {
                bucket: bucket.clone(),
            },
            Actor::Customer,
        )
        .await;
        units.head.set(s9);
        // The row is not written: the events are, and stay once each.
        flaky.fail(Some("INSERT INTO tenants"));
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.directory, StoreStep::Failed);
        assert_eq!(run.events, 6);
        flaky.fail(None);
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.directory, StoreStep::Holds(s9));
        assert_eq!(run.events, 0, "a repeat wrote a row");
        let got = events(&db, A1).await;
        let want = vec![
            (
                "bucket.created",
                format!("t/{s5}"),
                json!({"bucket_id": bucket, "bucket": "photos"}),
            ),
            (
                "tenant.suspended",
                format!("t/{s6}"),
                json!({"mode": "read_only"}),
            ),
            (
                "tenant.deletion_scheduled",
                format!("t/{s7}"),
                json!({"shred_due_at_ms": NOW.0 + 61 * DAY}),
            ),
            ("tenant.resumed", format!("t/{s8}.1"), json!({})),
            ("tenant.deletion_cancelled", format!("t/{s8}.2"), json!({})),
            (
                "bucket.deleted",
                format!("t/{s9}"),
                json!({"bucket_id": bucket}),
            ),
        ];
        assert_eq!(got.len(), want.len(), "{got:?}");
        for ((k, s, d), (wk, ws, wd)) in got.iter().zip(&want) {
            assert_eq!((k.as_str(), s, d), (*wk, ws, wd));
            assert!(EVENT_TYPES.contains(&k.as_str()), "{k}");
        }
    });
}

/// A row more than `MAX_FINISH_RECORDS` behind is raised in steps; such a
/// run brings the units up first.
#[test]
fn a_row_far_behind_is_raised_in_steps() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let units = Units::new(&db);
    block_on(async {
        active(&chain, A1).await;
        let mut head = 4;
        while head < 4 + MAX_FINISH_RECORDS + 20 {
            let mode = match head % 2 {
                0 => Some(HoldMode::ReadOnly),
                _ => None,
            };
            head = write(&chain, A1, Change::SetBillingHold { mode }, Actor::Billing).await;
        }
        units.head.set(head);
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.order, Some(WriteOrder::Closing));
        assert_eq!(units.take_log(), vec![(0, None)]);
        assert_eq!(run.directory, StoreStep::Holds(MAX_FINISH_RECORDS));
        assert_eq!(run.cleared_to, Some(MAX_FINISH_RECORDS));
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.directory, StoreStep::Holds(head));
        let n = events(&db, A1).await.len() as u64;
        // One event per hold change: every record after activation.
        assert_eq!(n, head - 4);
    });
}

/// A row ahead of its chain is damage: it pages, the directory step does
/// not run, and the head's own record decides the order.
#[test]
fn a_row_ahead_of_the_chain_pages() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let dir = SqlDirectory { sql: &db };
    let units = Units::new(&db);
    block_on(async {
        active(&chain, A1).await;
        units.head.set(4);
        finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        units.take_log();
        // A record that the row holds goes missing from R2.
        assert!(store.lose(&velmora_bridge::directory::chain::record_key(&t(A1), 4)));
        units.head.set(3);
        let run = finish_tenant(&chain, Some(&dir), &units, &tid(A1), NOW)
            .await
            .unwrap();
        assert_eq!(run.head.seq, 3);
        assert!(
            run.pages.contains(&"directory_row_ahead"),
            "{:?}",
            run.pages
        );
        assert_eq!(run.directory, StoreStep::Failed);
        // The head's own record (a key commit) opens: the units wait.
        assert_eq!(run.order, Some(WriteOrder::Opening));
        assert_eq!(run.units, vec![(0, StoreStep::Waiting)]);
        assert!(units.take_log().is_empty());
        assert_eq!(row_seq(&db, A1).await, Some(4));
    });
}

/// The sweep's finisher: a tenant chain is finished; a key chain is not
/// this finisher's.
#[test]
fn the_tenant_finisher_takes_tenant_chains_only() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let units = Units::new(&db);
    block_on(async {
        active(
            &TenantChain {
                store: &store,
                seal: &seal,
            },
            A1,
        )
        .await;
        units.head.set(4);
        let finisher = TenantFinisher {
            chain: TenantChain {
                store: &store,
                seal: &seal,
            },
            dir: Some(SqlDirectory { sql: &db }),
            units: &units,
            now: NOW,
        };
        let head = finisher
            .finish(&ChainKey {
                tenant: tid(A1),
                chain: ControlChain::Tenant,
            })
            .await
            .unwrap();
        assert_eq!((head.seq, head.complete), (4, true));
        let e = finisher
            .finish(&ChainKey {
                tenant: tid(A1),
                chain: ControlChain::Keys,
            })
            .await
            .unwrap_err();
        assert!(is(&e, &ERR_NOT_TENANT_CHAIN));
        // No chain at all: an empty head, complete.
        let none = finisher
            .finish(&ChainKey {
                tenant: tid(B2),
                chain: ControlChain::Tenant,
            })
            .await
            .unwrap();
        assert_eq!((none.seq, none.complete), (0, true));
    });
}

// ---------------------------------------------------------------------------
// The key chain's directory target
// ---------------------------------------------------------------------------

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(self.counter.to_be_bytes());
            self.counter += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn rng(label: &str) -> TestRng {
    TestRng {
        seed: derived(label),
        counter: 0,
    }
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, derived("directory finish kek"))])
}

fn ring(tenant: &str) -> OneKey {
    OneKey(TenantKey::from_bytes(&tid(tenant), 1, derived("tk")).unwrap())
}

fn principal(id: &str) -> Subject {
    let mut s = Subject {
        door: SubjectDoor {
            id: id.into(),
            kind: SubjectKind::Principal,
            status: SubjectStatus::Active,
            made_by: None,
            grants: vec![],
            created_at: 10,
            secret_kek_version: None,
        },
        private: SubjectPrivate {
            owner_ref: Some(format!("owner-of-{id}")),
            label: None,
            grants: vec![],
            secret_wrapped: None,
        },
    };
    s.set_grants(&[grant("b_01")]);
    s
}

fn grant(bucket: &str) -> Grant {
    Grant {
        bucket_id: bucket.into(),
        access: Access::Rw,
        expires_at: None,
        prefix: None,
        ip_list: vec![],
    }
}

fn key(id: &str, kind: SubjectKind, made_by: &str, tenant: &str, kek: &TestKek) -> Subject {
    let (version, wrapped) = wrap_secret_v2(
        kek,
        &tid(tenant),
        id,
        format!("secret-of-{id}").as_bytes(),
        &mut rng(id),
    )
    .unwrap();
    let mut s = principal(id);
    s.door.kind = kind;
    s.door.made_by = Some(made_by.into());
    s.door.secret_kek_version = Some(version);
    s.door.created_at = 20;
    s.private.secret_wrapped = Some(wrapped);
    s
}

async fn put_key(
    store: &HookedRecords,
    kek: &TestKek,
    tenant: &str,
    seq: u64,
    op: KeyOp,
    subject: &Subject,
) {
    let bytes = seal_key_record(
        kek,
        &ring(tenant),
        &tid(tenant),
        seq,
        op,
        1_000 + seq,
        &subject.door,
        Some(&subject.private),
        op == KeyOp::Status && subject.door.status != SubjectStatus::Active,
        None,
        &mut rng(&format!("record {seq}")),
    )
    .unwrap();
    assert_eq!(
        key_chain(&tid(tenant))
            .put(store, seq, bytes)
            .await
            .unwrap(),
        Put::Written
    );
}

/// A1's key chain: 1 principal, 2 an S3 key, 3 an app password, 4 the key
/// disabled, 5 the principal's grants widened, 6 a freeze marker.
async fn key_chain_of_a1(store: &HookedRecords, kek: &TestKek) {
    let p = principal("p_00000000000000aa");
    put_key(store, kek, A1, 1, KeyOp::Create, &p).await;
    let k = key("AKVL0001", SubjectKind::S3, "p_00000000000000aa", A1, kek);
    put_key(store, kek, A1, 2, KeyOp::Create, &k).await;
    let a = key(
        "APVL0001",
        SubjectKind::AppPassword,
        "p_00000000000000aa",
        A1,
        kek,
    );
    put_key(store, kek, A1, 3, KeyOp::Create, &a).await;
    let mut off = k.clone();
    off.door.status = SubjectStatus::Disabled;
    put_key(store, kek, A1, 4, KeyOp::Status, &off).await;
    let mut wider = p.clone();
    wider.set_grants(&[grant("b_01"), grant("b_02")]);
    put_key(store, kek, A1, 5, KeyOp::Grants, &wider).await;
    let bytes = seal_marker_record(
        kek,
        &ring(A1),
        &tid(A1),
        6,
        1_006,
        Marker::KeysFrozen,
        &mut rng("marker"),
    )
    .unwrap();
    key_chain(&tid(A1)).put(store, 6, bytes).await.unwrap();
}

async fn tenant_row(db: &Db, store: &HookedRecords, seal: &PlainSeal, tenant: &str) {
    let chain = TenantChain { store, seal };
    active(&chain, tenant).await;
    let units = Units::new(db);
    units.head.set(4);
    finish_tenant(
        &chain,
        Some(&SqlDirectory { sql: db }),
        &units,
        &tid(tenant),
        NOW,
    )
    .await
    .unwrap();
}

fn target<'a>(
    db: &'a Db,
    tenant: &'a TenantId,
    store: &'a HookedRecords,
    kek: &'a TestKek,
    ring: &'a OneKey,
) -> DirectoryKeys<'a, Db, HookedRecords, TestKek, OneKey> {
    DirectoryKeys::new(SqlDirectory { sql: db }, tenant, store, kek, ring)
}

/// Brought up by the writer's own feed: one route per access key and app
/// password, none for the principal, events from the records (none for
/// the marker), and `keys_seq` at the head.
#[test]
fn the_directory_routes_each_key_once_and_writes_its_events() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let kek = kek();
    let ring = ring(A1);
    let a1 = tid(A1);
    block_on(async {
        tenant_row(&db, &store, &seal, A1).await;
        key_chain_of_a1(&store, &kek).await;
        let read = read_key_chain(&store, &kek, &ring, &a1).await.unwrap();
        assert_eq!(read.table.seq(), 6);
        let dk = target(&db, &a1, &store, &kek, &ring);
        assert_eq!(dk.keys_seq().await.unwrap(), 0);
        assert!(dk.closed().await.unwrap().is_empty());
        let feed = Feed::new(&store, &kek, &ring, &read.table, &read.revoked);
        feed.bring_up(&dk, Mode::Full).await.unwrap();
        assert_eq!(dk.keys_seq().await.unwrap(), 6);
        let dir = SqlDirectory { sql: &db };
        let r = dir.route("AKVL0001").await.unwrap().unwrap();
        assert_eq!(
            (r.tenant, r.kind, r.owner_ref.as_deref(), r.created_at),
            (t(A1), RouteKind::S3, Some("owner-of-AKVL0001"), UnixMs(20))
        );
        let a = dir.route("APVL0001").await.unwrap().unwrap();
        assert_eq!(a.kind, RouteKind::AppPassword);
        assert!(dir.route("p_00000000000000aa").await.unwrap().is_none());
        let got: Vec<(String, String, Value)> = events(&db, A1).await;
        assert_eq!(
            got,
            vec![
                (
                    "principal.created".into(),
                    "k/1".into(),
                    json!({"principal_id": "p_00000000000000aa"})
                ),
                (
                    "key.created".into(),
                    "k/2".into(),
                    json!({"key_id": "AKVL0001", "kind": "s3"})
                ),
                (
                    "key.created".into(),
                    "k/3".into(),
                    json!({"key_id": "APVL0001", "kind": "app_password"})
                ),
                (
                    "key.disabled".into(),
                    "k/4".into(),
                    json!({"key_id": "AKVL0001", "kind": "s3"})
                ),
                (
                    "principal.updated".into(),
                    "k/5".into(),
                    json!({"principal_id": "p_00000000000000aa"})
                ),
            ]
        );
        // Again: nothing more, from any base at or below the head.
        feed.bring_up(&dk, Mode::Full).await.unwrap();
        let entries = feed.entries(0, MAX_APPLY).await.unwrap();
        assert_eq!(
            dk.apply(0, &entries).await.unwrap(),
            Applied::Done { keys_seq: 6 }
        );
        assert_eq!(events(&db, A1).await.len(), 5);
        let n = db
            .query("SELECT COUNT(*) FROM key_routes", &[])
            .await
            .unwrap();
        assert_eq!(n[0][0], SqlValue::Int(2));
    });
}

/// The apply's base and shape rules, as a unit's: a base above the row
/// answers `Behind`; a gap, a wrong first seq or more than `MAX_APPLY`
/// entries is refused and keeps nothing.
#[test]
fn the_directory_follows_a_units_base_rules() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let kek = kek();
    let ring = ring(A1);
    let a1 = tid(A1);
    block_on(async {
        tenant_row(&db, &store, &seal, A1).await;
        key_chain_of_a1(&store, &kek).await;
        let read = read_key_chain(&store, &kek, &ring, &a1).await.unwrap();
        let feed = Feed::new(&store, &kek, &ring, &read.table, &read.revoked);
        let entries = feed.entries(0, MAX_APPLY).await.unwrap();
        let dk = target(&db, &a1, &store, &kek, &ring);
        assert_eq!(
            dk.apply(2, &entries[2..]).await.unwrap(),
            Applied::Behind { keys_seq: 0 }
        );
        let gap = [entries[0].clone(), entries[2].clone()];
        assert!(is(&dk.apply(0, &gap).await.unwrap_err(), &ERR_APPLY_SHAPE));
        assert!(is(
            &dk.apply(1, &entries[..2]).await.unwrap_err(),
            &ERR_APPLY_SHAPE
        ));
        let many: Vec<ApplyEntry> = (1..=(MAX_APPLY as u64 + 1))
            .map(|seq| ApplyEntry::Marker {
                seq,
                marker: Marker::KeysThawed { ends: 0 },
            })
            .collect();
        assert!(is(&dk.apply(0, &many).await.unwrap_err(), &ERR_APPLY_SHAPE));
        assert_eq!(dk.keys_seq().await.unwrap(), 0);
        assert!(events(&db, A1).await.is_empty());
        // Page by page, as the feed sends a long chain.
        assert_eq!(
            dk.apply(0, &entries[..3]).await.unwrap(),
            Applied::Done { keys_seq: 3 }
        );
        assert_eq!(
            dk.apply(3, &entries[3..]).await.unwrap(),
            Applied::Done { keys_seq: 6 }
        );
        assert_eq!(events(&db, A1).await.len(), 5);
    });
}

/// A tenant with no row: the target refuses, and writes nothing.
#[test]
fn a_tenant_with_no_row_takes_no_key() {
    let db = database();
    let store = HookedRecords::new();
    let kek = kek();
    let ring = ring(A1);
    let a1 = tid(A1);
    block_on(async {
        key_chain_of_a1(&store, &kek).await;
        let read = read_key_chain(&store, &kek, &ring, &a1).await.unwrap();
        let dk = target(&db, &a1, &store, &kek, &ring);
        assert!(is(&dk.keys_seq().await.unwrap_err(), &ERR_NO_TENANT_ROW));
        let feed = Feed::new(&store, &kek, &ring, &read.table, &read.revoked);
        assert!(feed.bring_up(&dk, Mode::Full).await.is_err());
        let entries = feed.entries(0, MAX_APPLY).await.unwrap();
        let e = dk.apply(0, &entries).await.unwrap_err();
        assert!(is(&e, &ERR_NO_TENANT_ROW) && !pages(&e));
        assert!(events(&db, A1).await.is_empty());
        assert!(SqlDirectory { sql: &db }
            .route("AKVL0001")
            .await
            .unwrap()
            .is_none());
    });
}

/// A route of the key to another tenant is damage: the apply fails and
/// pages, `keys_seq` stays, and a later run finds the same.
#[test]
fn a_conflicting_route_pages_and_keeps_keys_seq() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let kek = kek();
    let ring = ring(A1);
    let a1 = tid(A1);
    block_on(async {
        tenant_row(&db, &store, &seal, A1).await;
        tenant_row(&db, &store, &seal, B2).await;
        let dir = SqlDirectory { sql: &db };
        dir.put_route(&KeyRoute {
            akid: "AKVL0001".into(),
            tenant: t(B2),
            kind: RouteKind::S3,
            owner_ref: None,
            created_at: UnixMs(1),
        })
        .await
        .unwrap();
        key_chain_of_a1(&store, &kek).await;
        let read = read_key_chain(&store, &kek, &ring, &a1).await.unwrap();
        let feed = Feed::new(&store, &kek, &ring, &read.table, &read.revoked);
        let entries = feed.entries(0, MAX_APPLY).await.unwrap();
        let dk = target(&db, &a1, &store, &kek, &ring);
        for _ in 0..2 {
            let e = dk.apply(0, &entries).await.unwrap_err();
            assert!(is(&e, &ERR_ROUTE_CONFLICT) && pages(&e));
            assert_eq!(dk.keys_seq().await.unwrap(), 0);
        }
        // The events were written first, once.
        assert_eq!(events(&db, A1).await.len(), 5);
        assert_eq!(dir.route("AKVL0001").await.unwrap().unwrap().tenant, t(B2));
    });
}

/// A key id that does not fit its kind pages; a held entry's route keeps
/// its `owner_ref`.
#[test]
fn a_wrong_kind_pages_and_a_held_entry_keeps_its_owner() {
    let db = database();
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let kek = kek();
    let ring = ring(A1);
    let a1 = tid(A1);
    block_on(async {
        tenant_row(&db, &store, &seal, A1).await;
        key_chain_of_a1(&store, &kek).await;
        let read = read_key_chain(&store, &kek, &ring, &a1).await.unwrap();
        let feed = Feed::new(&store, &kek, &ring, &read.table, &read.revoked);
        let mut entries = feed.entries(0, 2).await.unwrap();
        // Entry 2 as a held entry.
        let ApplyEntry::Subject(e) = entries[1].clone() else {
            panic!("not a subject");
        };
        let mut held = e.clone();
        held.private = None;
        entries[1] = ApplyEntry::Held {
            entry: held,
            owner_ref: Some("held-owner".into()),
        };
        let dk = target(&db, &a1, &store, &kek, &ring);
        assert_eq!(
            dk.apply(0, &entries).await.unwrap(),
            Applied::Done { keys_seq: 2 }
        );
        let r = SqlDirectory { sql: &db }
            .route("AKVL0001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.owner_ref.as_deref(), Some("held-owner"));
        // An S3 key whose id is an app password's.
        let mut next = feed.entries(2, 1).await.unwrap();
        let ApplyEntry::Subject(e) = &mut next[0] else {
            panic!("not a subject");
        };
        e.door.kind = SubjectKind::S3;
        let err = dk.apply(2, &next).await.unwrap_err();
        assert!(is(&err, &ERR_ROUTE_WRONG_KIND) && pages(&err));
        assert_eq!(dk.keys_seq().await.unwrap(), 2);
    });
}

/// With no directory, the target acknowledges every seq and holds nothing
/// back.
#[test]
fn the_unbound_target_acknowledges_everything() {
    let store = HookedRecords::new();
    let kek = kek();
    let ring = ring(A1);
    let a1 = tid(A1);
    block_on(async {
        key_chain_of_a1(&store, &kek).await;
        let read = read_key_chain(&store, &kek, &ring, &a1).await.unwrap();
        let u = UnboundDirectory;
        assert_eq!(u.keys_seq().await.unwrap(), u64::MAX);
        assert!(u.closed().await.unwrap().is_empty());
        let feed = Feed::new(&store, &kek, &ring, &read.table, &read.revoked);
        feed.bring_up(&u, Mode::Full).await.unwrap();
        let entries = feed.entries(0, MAX_APPLY).await.unwrap();
        assert_eq!(
            u.apply(0, &entries).await.unwrap(),
            Applied::Done { keys_seq: u64::MAX }
        );
        // The closing step's hold, with the directory's `acked`: nothing held.
        let closed = BTreeSet::from(["AKVL0001".to_string()]);
        let out = feed
            .entries_for(0, MAX_APPLY, Mode::Closing { acked: u64::MAX }, &closed)
            .await
            .unwrap();
        assert!(out.iter().all(|e| !matches!(e, ApplyEntry::Held { .. })));
    });
}
