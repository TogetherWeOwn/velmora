//! The move's flip: the legacy stamp, the owner's unit opened, the routes
//! moved, tenant 0 `moved`; finished by a second run after a crash at any
//! sub-step; and the give-up before the flip.

mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use service_support::*;
use velmora_bridge::directory::chain::{TenantChain, Written};
use velmora_bridge::directory::fence::{freeze, legacy_stamp_key};
use velmora_bridge::directory::move_flip::{
    flip, give_up, FlipError, Flipped, RouteRecords, UnitSync, Window,
};
use velmora_bridge::directory::record::{Selector, Tenant, TenantDoor};
use velmora_bridge::directory::store::{KeyRoute, RouteKind, SqlDirectory};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change, KEY_CHECK_LEN};
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
}

impl RouteRecords for FakeRoutes {
    async fn put(&self, akid: &str, tenant: &Tenant) -> Result<bool> {
        if let Some(n) = self.fail_after.get() {
            if n == 0 {
                return Err(BridgeError::Blob("route store unreachable".into()));
            }
            self.fail_after.set(Some(n - 1));
        }
        let mut records = self.records.borrow_mut();
        let named = records
            .entry(akid.to_string())
            .or_insert_with(|| tenant.as_str().to_string());
        Ok(named == tenant.as_str())
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

    async fn give_up(&self) -> std::result::Result<(), FlipError> {
        let k = keys();
        let window = Window {
            owner: &owner(),
            since: self.since,
            keys: &k,
        };
        give_up(
            &self.chain(),
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
    m.write(
        &zero,
        Change::StartMove {
            to: o.clone(),
            catalogue_id_frozen: "main".into(),
        },
        Actor::MoveTool,
    )
    .await;
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
        assert_eq!(
            m.head(&Tenant::zero()).await.tenant_zero.unwrap().selector,
            Selector::Moving
        );
        assert!(m.route_row(KEYS[1]).await.is_zero());
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
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        let o = m.head(&owner()).await;
        assert!(o.restoring_entry(0).is_some());
        assert_eq!(m.unit.synced.borrow().last().unwrap().seq, o.seq);
        let z = m.head(&Tenant::zero()).await.tenant_zero.unwrap();
        assert_eq!(z.selector, Selector::D1);
        assert!(z.moved.is_none());
        for akid in KEYS {
            assert!(m.route_row(akid).await.is_zero());
        }
        // Run again: nothing more.
        let n = m.records();
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
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
