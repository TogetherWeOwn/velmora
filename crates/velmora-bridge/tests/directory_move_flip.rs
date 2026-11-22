//! The move's flip: the legacy stamp, the owner's unit opened, the routes
//! moved, tenant 0 `moved`; finished by a second run after a crash at any
//! sub-step; and the give-up before the flip.

mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use service_support::*;
use velmora_bridge::directory::chain::{TenantChain, Written};
use velmora_bridge::directory::fence::{freeze, legacy_stamp_key, stamp_row, thaw};
use velmora_bridge::directory::move_flip::MAX_WINDOW_RECORDS;
use velmora_bridge::directory::move_flip::{
    flip, give_up, FlipError, Flipped, GaveUp, RouteRecords, UnitSync, Window,
};
use velmora_bridge::directory::record::{HoldMode, OperatorReason};
use velmora_bridge::directory::record::{Selector, Tenant, TenantDoor};
use velmora_bridge::directory::store::{KeyRoute, RouteKind, SqlDirectory};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change, OperatorHoldRequest, KEY_CHECK_LEN};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::*;

const OWNER: &str = "t_00000000000000a1";
const KEYS: [&str; 2] = ["AKMOVE00000000000001", "AKMOVE00000000000002"];

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

fn keys() -> Vec<String> {
    KEYS.iter().map(|k| k.to_string()).collect()
}

/// The owner's root unit: the heads it was synced with.
#[derive(Default)]
struct FakeUnit {
    synced: RefCell<Vec<TenantDoor>>,
    fail: Cell<u32>,
}

impl UnitSync for FakeUnit {
    async fn apply_head(&self, owner: &TenantDoor) -> Result<()> {
        if self.fail.get() > 0 {
            self.fail.set(self.fail.get() - 1);
            return Err(BridgeError::Blob("unit unreachable".into()));
        }
        self.synced.borrow_mut().push(owner.clone());
        Ok(())
    }
}

/// Route records, put once.
#[derive(Default)]
struct FakeRoutes {
    records: RefCell<BTreeMap<String, String>>,
    /// Puts fail after this many more.
    fail_after: Cell<Option<u32>>,
    /// The next N puts store, then answer an error.
    lose: Cell<u32>,
}

impl RouteRecords for FakeRoutes {
    async fn put(&self, akid: &str, tenant: &Tenant, kind: RouteKind) -> Result<bool> {
        assert_eq!(kind, RouteKind::S3);
        if let Some(n) = self.fail_after.get() {
            if n == 0 {
                return Err(BridgeError::Blob("route store unreachable".into()));
            }
            self.fail_after.set(Some(n - 1));
        }
        let ours = {
            let mut records = self.records.borrow_mut();
            let named = records
                .entry(akid.to_string())
                .or_insert_with(|| tenant.as_str().to_string());
            named == tenant.as_str()
        };
        if self.lose.get() > 0 {
            self.lose.set(self.lose.get() - 1);
            return Err(BridgeError::Blob("answer lost".into()));
        }
        Ok(ours)
    }

    async fn get(&self, akid: &str) -> Result<Option<String>> {
        Ok(self.records.borrow().get(akid).cloned())
    }
}

struct Move {
    rig: Rig,
    store: HookedRecords,
    seal: PlainSeal,
    db: RusqliteSql,
    unit: FakeUnit,
    routes: FakeRoutes,
    since: u64,
    zero_seq: u64,
}

impl Move {
    fn chain(&self) -> TenantChain<'_, HookedRecords, PlainSeal> {
        TenantChain {
            store: &self.store,
            seal: &self.seal,
        }
    }

    fn dir(&self) -> SqlDirectory<'_, RusqliteSql> {
        SqlDirectory { sql: &self.db }
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

    async fn flip(&self) -> std::result::Result<Flipped, FlipError> {
        let k = keys();
        let window = Window {
            owner: &owner(),
            zero_seq: self.zero_seq,
            since: self.since,
            keys: &k,
        };
        flip(
            &self.chain(),
            &self.rig.bridge.catalog.sql,
            &self.rig.bridge.safety,
            &self.dir(),
            &self.unit,
            &self.routes,
            &window,
            self.rig.now(),
        )
        .await
    }

    async fn give_up(&self) -> std::result::Result<Option<GaveUp>, FlipError> {
        let k = keys();
        let window = Window {
            owner: &owner(),
            zero_seq: self.zero_seq,
            since: self.since,
            keys: &k,
        };
        give_up(
            &self.chain(),
            &self.rig.bridge.catalog.sql,
            &self.rig.bridge.safety,
            &self.dir(),
            &self.unit,
            &self.routes,
            &window,
            self.rig.now(),
        )
        .await
    }

    fn records(&self) -> usize {
        self.store.keys().len()
    }

    async fn route_row(&self, akid: &str) -> Tenant {
        self.dir().route(akid).await.unwrap().unwrap().tenant
    }

    async fn stamp_put(&self) -> bool {
        let counter = stamp_row(&self.rig.bridge.catalog.sql)
            .await
            .unwrap()
            .map(|(c, _)| c);
        self.rig
            .bridge
            .safety
            .head(&legacy_stamp_key("main", counter))
            .await
            .unwrap()
            .is_some()
    }

    async fn selector(&self) -> Selector {
        self.head(&Tenant::zero())
            .await
            .tenant_zero
            .unwrap()
            .selector
    }
}

/// The window up to step 7: tenant 0 frozen and `moving` into the owner,
/// the owner's unit 0 `restoring`, both tenants and tenant 0's key routes
/// in the directory.
async fn window() -> Move {
    let rig = rig();
    let (_, signer) = rig.standard("vault").await;
    rig.put(&signer, "vault", "a.bin", &pattern(1, 1_000))
        .await
        .expect(200);
    rig.bridge.raise_stamp().await.unwrap();
    freeze(&rig.bridge.catalog.sql, 1).await.unwrap();
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
    ))
    .unwrap();
    let mut m = Move {
        rig,
        store: HookedRecords::new(),
        seal: PlainSeal::new(),
        db,
        unit: FakeUnit::default(),
        routes: FakeRoutes::default(),
        since: 0,
        zero_seq: 0,
    };
    let zero = Tenant::zero();
    m.write(
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
        m.write(&o, change, actor).await;
    }
    m.zero_seq = m
        .write(
            &zero,
            Change::StartMove {
                to: o.clone(),
                catalogue_id_frozen: "main".into(),
            },
            Actor::MoveTool,
        )
        .await
        .seq;
    let closed = m
        .write(&o, Change::SetRestoring { unit: 0 }, Actor::Operator)
        .await;
    m.since = closed.restoring_entry(0).unwrap().since_seq;
    let dir = m.dir();
    for t in [&zero, &o] {
        dir.apply_tenant(&m.head(t).await, m.rig.now())
            .await
            .unwrap();
    }
    for akid in KEYS {
        dir.put_route(&KeyRoute {
            akid: akid.into(),
            tenant: zero.clone(),
            kind: RouteKind::S3,
            owner_ref: None,
            created_at: m.rig.now(),
        })
        .await
        .unwrap();
    }
    m
}

async fn assert_flipped(m: &Move, stamp: u64) {
    let z = m.head(&Tenant::zero()).await;
    let z = z.tenant_zero.unwrap();
    assert_eq!(z.selector, Selector::Moved);
    assert_eq!(z.moved.unwrap().stamp, Some(stamp));
    let o = m.head(&owner()).await;
    assert!(o.restoring.is_empty());
    // The unit last saw the lifted head.
    assert!(m.unit.synced.borrow().last().unwrap().restoring.is_empty());
    for akid in KEYS {
        assert_eq!(m.routes.records.borrow()[akid], OWNER);
        assert_eq!(m.route_row(akid).await, owner());
    }
    let key = legacy_stamp_key("main", Some(stamp - 1));
    assert!(m.rig.bridge.safety.head(&key).await.unwrap().is_some());
}

#[test]
fn the_flip_runs_its_four_steps_in_order() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        assert_flipped(&m, f.stamp).await;
        // Two records: the owner's lift and tenant 0's flip.
        assert_eq!(m.records(), before + 2);
        // Run again: found, nothing written.
        let again = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(
            again,
            Flipped {
                stamp: f.stamp,
                wrote: false
            }
        );
        assert_eq!(m.records(), before + 2);
        // No give-up after the flip: the way back is the reverse move.
        assert!(matches!(m.give_up().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn a_crash_at_any_step_is_finished_by_running_the_flip_again() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        // After (a) and the lift record: the unit is not reached.
        m.unit.fail.set(1);
        assert!(matches!(m.flip().await, Err(FlipError::Store(_))));
        assert!(m.head(&owner()).await.restoring.is_empty());
        assert_eq!(
            m.head(&Tenant::zero()).await.tenant_zero.unwrap().selector,
            Selector::Moving
        );
        // In (c): the second key's route record is not reached.
        m.routes.fail_after.set(Some(1));
        assert!(matches!(m.flip().await, Err(FlipError::Store(_))));
        assert_eq!(m.route_row(KEYS[0]).await, owner());
        assert!(m.route_row(KEYS[1]).await.is_zero());
        m.routes.fail_after.set(None);
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_flipped(&m, f.stamp).await;
        // Still one lift record and one flip record.
        assert_eq!(m.records(), before + 2);
    });
}

#[test]
fn a_route_record_of_another_tenant_stops_the_flip() {
    block_on(async {
        let m = window().await;
        m.routes
            .records
            .borrow_mut()
            .insert(KEYS[1].into(), "t_00000000000000b2".into());
        let r = m.flip().await;
        assert!(
            matches!(&r, Err(FlipError::RouteTaken(k)) if k == KEYS[1]),
            "{r:?}"
        );
        // Refused before the first write: no stamp, the unit still
        // closed, the first key's record not put.
        assert_eq!(m.selector().await, Selector::Moving);
        assert!(!m.stamp_put().await);
        assert!(m.head(&owner()).await.restoring_entry(0).is_some());
        assert!(!m.routes.records.borrow().contains_key(KEYS[0]));
        // So the move can still be given up.
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(
            g,
            Some(GaveUp {
                catalogue_id_frozen: "main".into(),
                stamp_put: false
            })
        );
        assert_eq!(m.selector().await, Selector::D1);
    });
}

#[test]
fn the_flip_acts_only_on_this_windows_entry() {
    block_on(async {
        let mut m = window().await;
        m.since += 1;
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::OtherWindow { .. })), "{r:?}");
        assert!(!m.head(&owner()).await.restoring.is_empty());
        assert!(m.routes.records.borrow().is_empty());
    });
}

#[test]
fn the_move_is_given_up_before_its_routes() {
    block_on(async {
        let m = window().await;
        // (a) and (b) done, (c) not reached.
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        assert!(m.head(&owner()).await.restoring.is_empty());
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        // (a) ran: the tool levels the thawed D1's stamp.
        assert_eq!(g.map(|g| g.stamp_put), Some(true));
        assert!(m.stamp_put().await);
        let o = m.head(&owner()).await;
        assert!(o.restoring_entry(0).is_some());
        assert_eq!(m.unit.synced.borrow().last().unwrap().seq, o.seq);
        let z = m.head(&Tenant::zero()).await.tenant_zero.unwrap();
        assert_eq!(z.selector, Selector::D1);
        assert!(z.moved.is_none());
        for akid in KEYS {
            assert!(m.route_row(akid).await.is_zero());
        }
        // Run again: nothing more is written, and the answer is the same
        // (a re-run after a lost answer still learns the level step).
        let n = m.records();
        assert_eq!(
            m.give_up().await.map_err(|e| format!("{e:?}")).unwrap(),
            Some(GaveUp {
                catalogue_id_frozen: "main".into(),
                stamp_put: true
            })
        );
        assert_eq!(m.records(), n);
        // And the flip no longer runs.
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn the_give_up_stops_once_a_route_record_names_the_owner() {
    block_on(async {
        let m = window().await;
        m.routes.fail_after.set(Some(1));
        assert!(m.flip().await.is_err());
        let r = m.give_up().await;
        assert!(
            matches!(&r, Err(FlipError::RoutesPut(k)) if k == &[KEYS[0].to_string()]),
            "{r:?}"
        );
        assert_eq!(
            m.head(&Tenant::zero()).await.tenant_zero.unwrap().selector,
            Selector::Moving
        );
    });
}

#[test]
fn lost_answers_in_the_routes_and_the_flip_record_are_read_back() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        // The first key's record is stored, its answer lost.
        m.routes.lose.set(1);
        assert!(matches!(m.flip().await, Err(FlipError::Store(_))));
        assert_eq!(m.routes.records.borrow()[KEYS[0]], OWNER);
        assert!(m.route_row(KEYS[0]).await.is_zero());
        // The flip record is stored, its answer lost: read back as
        // written. (The lift is already done, so the next record put is
        // the flip's.)
        m.store.lose_answers(1);
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        assert_flipped(&m, f.stamp).await;
        assert_eq!(m.records(), before + 2);
    });
}

#[test]
fn the_move_is_given_up_before_the_unit_opens() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        let o = m.head(&owner()).await;
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(g.map(|g| g.stamp_put), Some(false));
        // The entry stood: no new owner record, only tenant 0's.
        assert_eq!(m.head(&owner()).await.seq, o.seq);
        assert_eq!(m.records(), before + 1);
        assert_eq!(m.selector().await, Selector::D1);
    });
}

#[test]
fn a_give_up_that_crashed_after_closing_the_unit_runs_again() {
    block_on(async {
        let m = window().await;
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        // The unit is not reached after the new restoring entry.
        m.unit.fail.set(1);
        assert!(matches!(m.give_up().await, Err(FlipError::Store(_))));
        let closed = m.head(&owner()).await;
        let entry = closed.restoring_entry(0).unwrap().since_seq;
        assert!(entry > m.since);
        assert_eq!(m.selector().await, Selector::Moving);
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(g.map(|g| g.stamp_put), Some(true));
        // No second entry; the unit saw the closed head.
        let after = m.head(&owner()).await;
        assert_eq!(after.restoring_entry(0).unwrap().since_seq, entry);
        assert_eq!(m.unit.synced.borrow().last().unwrap().seq, after.seq);
        assert_eq!(m.selector().await, Selector::D1);
    });
}

#[test]
fn the_flip_needs_this_windows_marker_and_a_later_window_is_not_this_one() {
    block_on(async {
        let m = window().await;
        // A marker of another move ordinal.
        thaw(&m.rig.bridge.catalog.sql).await.unwrap();
        freeze(&m.rig.bridge.catalog.sql, 2).await.unwrap();
        assert!(matches!(m.flip().await, Err(FlipError::Marker)));
        assert!(!m.stamp_put().await);
        thaw(&m.rig.bridge.catalog.sql).await.unwrap();
        freeze(&m.rig.bridge.catalog.sql, 1).await.unwrap();
        // Opened, given up (a new restoring entry), then a new window into
        // the same owner: the old window's flip does not act on it. (A
        // window whose entry was never lifted keeps it, and the next window
        // takes the same one: the two cannot be told apart.)
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        m.routes.fail_after.set(None);
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        let w2 = m
            .write(
                &Tenant::zero(),
                Change::StartMove {
                    to: owner(),
                    catalogue_id_frozen: "main".into(),
                },
                Actor::MoveTool,
            )
            .await;
        let o = m.head(&owner()).await;
        assert!(o.restoring_entry(0).is_some());
        // A stale run of the first window acts on nothing: the flip does
        // not run, and the give-up does not answer a catalogue the second
        // window has frozen again.
        let n = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::NotThisMove)), "{r:?}");
        let r = m.give_up().await;
        assert!(matches!(r, Err(FlipError::NotThisMove)), "{r:?}");
        assert_eq!(m.records(), n);
        assert_eq!(m.selector().await, Selector::Moving);
        // The second window, named by its own record, is not the first's
        // entry either: the owner's entry is the give-up's, set after the
        // first window's lift.
        let mut m2 = m;
        m2.zero_seq = w2.seq;
        let r = m2.flip().await;
        assert!(matches!(r, Err(FlipError::OtherWindow { .. })), "{r:?}");
        m2.since = o.restoring_entry(0).unwrap().since_seq;
        let f = m2.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
    });
}

#[test]
fn the_pre_pass_refuses_a_key_with_no_route_row_before_any_write() {
    block_on(async {
        let m = window().await;
        m.db.apply(&format!(
            "DELETE FROM key_routes WHERE akid = '{}';",
            KEYS[1]
        ))
        .unwrap();
        let n = m.records();
        let r = m.flip().await;
        assert!(
            matches!(&r, Err(FlipError::RouteRow(k)) if k == KEYS[1]),
            "{r:?}"
        );
        assert_eq!(m.records(), n);
        assert!(!m.stamp_put().await);
        assert!(m.routes.records.borrow().is_empty());
    });
}

#[test]
fn a_missing_entry_counts_as_lifted_only_if_this_window_set_it() {
    block_on(async {
        let mut m = window().await;
        // Lifted by a run that stopped in (c).
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        m.routes.fail_after.set(None);
        // A window that names another seq for its entry: the record there
        // did not set one.
        let real = m.since;
        m.since = real - 1;
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::OtherWindow { .. })), "{r:?}");
        m.since = real;
        m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
    });
}

#[test]
fn a_give_up_landing_before_the_flip_record_stops_the_flip() {
    use velmora_bridge::directory::chain::{record_key, ControlSeal};
    use velmora_bridge::directory::record::TenantRecord;
    use velmora_bridge::directory::transition::{next, Outcome};
    block_on(async {
        let m = window().await;
        // A give-up of tenant 0, sealed as another writer would, put just
        // before this run's flip record.
        let head = m.chain().head(&Tenant::zero(), 0).await.unwrap().unwrap();
        let record = TenantRecord {
            door: head.door,
            private: head.private.unwrap(),
        };
        let Ok(Outcome::Next(gave_up)) = next(
            &Tenant::zero(),
            Some(&record),
            &Change::GiveUpMove,
            Actor::MoveTool,
            m.rig.now(),
        ) else {
            panic!("give-up record");
        };
        let name = record_key(&Tenant::zero(), gave_up.door.seq);
        let sealed = m
            .seal
            .seal(
                &name,
                &Tenant::zero(),
                gave_up.door.tk_version,
                &serde_json::to_vec(&gave_up.door).unwrap(),
                &serde_json::to_vec(&gave_up.private).unwrap(),
            )
            .unwrap();
        let mut planted = Some((name, sealed));
        let zero_prefix = "m/t/t_0000000000000000/".to_string();
        m.store.before_put(move |key, objects| {
            if key.starts_with(&zero_prefix) {
                if let Some((name, sealed)) = planted.take() {
                    objects.insert(name, sealed);
                }
            }
        });
        let r = m.flip().await;
        assert!(r.is_err(), "{r:?}");
        assert_eq!(m.selector().await, Selector::D1);
    });
}

fn hold(on: bool) -> Change {
    Change::SetOperatorHold {
        hold: on.then_some(OperatorHoldRequest {
            mode: HoldMode::ReadOnly,
            reason: OperatorReason::Security,
            preserve: None,
        }),
    }
}

#[test]
fn a_tenant_zero_record_during_the_run_stops_the_flip_record_until_run_again() {
    block_on(async {
        let m = window().await;
        // A record of tenant 0 that keeps the window open lands while the
        // flip runs (at the owner's lift): the re-walk before (d) sees a
        // head this run did not check.
        let head = m.chain().head(&Tenant::zero(), 0).await.unwrap().unwrap();
        let (name, sealed) = sealed_next(&m, head, hold(true));
        let mut planted = Some((name, sealed));
        let owner_prefix = format!("m/t/{OWNER}/");
        m.store.before_put(move |key, objects| {
            if key.starts_with(&owner_prefix) {
                if let Some((name, sealed)) = planted.take() {
                    objects.insert(name, sealed);
                }
            }
        });
        let n = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::NotThisMove)), "{r:?}");
        // The lift and the planted record; no flip record.
        assert_eq!(m.records(), n + 2);
        assert_eq!(m.selector().await, Selector::Moving);
        // The window is still this one: run again, it flips.
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
    });
}

/// The sealed record that `change` makes on `head` of tenant 0, as another
/// writer would put it.
fn sealed_next(
    m: &Move,
    head: velmora_bridge::directory::chain::ReadRecord,
    change: Change,
) -> (String, Vec<u8>) {
    use velmora_bridge::directory::chain::{record_key, ControlSeal};
    use velmora_bridge::directory::record::TenantRecord;
    use velmora_bridge::directory::transition::{next, Outcome};
    let record = TenantRecord {
        door: head.door,
        private: head.private.unwrap(),
    };
    let Ok(Outcome::Next(rec)) = next(
        &Tenant::zero(),
        Some(&record),
        &change,
        Actor::Operator,
        m.rig.now(),
    ) else {
        panic!("tenant-0 record");
    };
    let name = record_key(&Tenant::zero(), rec.door.seq);
    let sealed = m
        .seal
        .seal(
            &name,
            &Tenant::zero(),
            rec.door.tk_version,
            &serde_json::to_vec(&rec.door).unwrap(),
            &serde_json::to_vec(&rec.private).unwrap(),
        )
        .unwrap();
    (name, sealed)
}

#[test]
fn the_give_up_refuses_an_older_windows_entry() {
    block_on(async {
        let mut m = window().await;
        m.since += 1;
        let n = m.records();
        let r = m.give_up().await;
        assert!(matches!(r, Err(FlipError::OtherWindow { .. })), "{r:?}");
        assert_eq!(m.records(), n);
        assert_eq!(m.selector().await, Selector::Moving);
    });
}

#[test]
fn an_owner_without_a_live_directory_row_stops_the_flip_before_any_write() {
    block_on(async {
        let m = window().await;
        m.db.apply(&format!(
            "DELETE FROM units WHERE tenant = '{OWNER}';\n\
             DELETE FROM bucket_index WHERE tenant = '{OWNER}';\n\
             DELETE FROM tenants WHERE id = '{OWNER}';"
        ))
        .unwrap();
        let n = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::OwnerRow)), "{r:?}");
        assert_eq!(m.records(), n);
        assert!(!m.stamp_put().await);
    });
}

#[test]
fn a_window_named_by_a_record_outside_any_run_is_not_a_window() {
    block_on(async {
        let mut m = window().await;
        // Seq 1: tenant 0's first record, on its D1 with no move.
        m.zero_seq = 1;
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
        assert!(matches!(m.give_up().await, Err(FlipError::NotThisMove)));
        // Above the head.
        m.zero_seq = 99;
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn a_window_longer_than_the_bound_is_not_walked() {
    block_on(async {
        let m = window().await;
        let zero = Tenant::zero();
        // Records that keep the window open, up to the bound.
        let mut head = m.head(&zero).await.seq;
        let mut on = true;
        while head - m.zero_seq < MAX_WINDOW_RECORDS - 1 {
            head = m.write(&zero, hold(on), Actor::Operator).await.seq;
            on = !on;
        }
        // Inside the bound: still this window.
        assert!(matches!(m.give_up().await, Ok(Some(_))), "inside the bound");
        let m = window().await;
        let mut head = m.head(&zero).await.seq;
        let mut on = true;
        while head - m.zero_seq < MAX_WINDOW_RECORDS {
            head = m.write(&zero, hold(on), Actor::Operator).await.seq;
            on = !on;
        }
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn records_of_no_window_after_the_give_up_keep_its_answer() {
    block_on(async {
        let m = window().await;
        let first = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        let zero = Tenant::zero();
        m.write(&zero, hold(true), Actor::Operator).await;
        m.write(&zero, hold(false), Actor::Operator).await;
        let n = m.records();
        assert_eq!(
            m.give_up().await.map_err(|e| format!("{e:?}")).unwrap(),
            first
        );
        assert_eq!(m.records(), n);
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn a_shredded_owner_row_stops_the_flip_before_any_write() {
    use velmora_bridge::directory::record::Lifecycle;
    block_on(async {
        let m = window().await;
        let mut gone = m.head(&owner()).await;
        gone.seq += 1;
        gone.lifecycle = Lifecycle::Shredded;
        m.dir().apply_tenant(&gone, m.rig.now()).await.unwrap();
        let n = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::OwnerRow)), "{r:?}");
        assert_eq!(m.records(), n);
        assert!(!m.stamp_put().await);
    });
}
