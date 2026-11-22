//! The composition root (`velmora_bridge::root`) over test ports: a cold
//! isolate reads a tenant's head with its private part by loading the
//! committed key from the key buckets; a shredding tenant whose key is
//! gone reads with no private part, a live one does not read; the key
//! ring; the door reader; and the key routes, with ADR §8.4's failed
//! directory read (DUR-10).

use std::collections::BTreeMap;
use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{tk_blob_name, wrap_tenant_key, TenantId, TenantKey};
use velmora_bridge::directory::chain::{ChainError, Written};
use velmora_bridge::directory::record::{DeletionReason, Tenant, TenantState};
use velmora_bridge::directory::store::{KeyRoute, RouteKind, SqlDirectory};
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::keys::locations::{two_in_account, write_locations};
use velmora_bridge::keys::record::SubjectKind;
use velmora_bridge::keys::routes::put_route;
use velmora_bridge::keys::tk::{tk_prefix, KeyBuckets};
use velmora_bridge::ports::Catalog;
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::root::{Root, RootCache, RootPorts};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FixedClock, RusqliteSql, TestKek};
use velmora_bridge::types::{AccessKeyRow, KeyStatus};
use velmora_bridge::unit::Seqs;
use velmora_bridge::unit_router::{KeyRoutes, KeyTenant};
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const DAY: i64 = 24 * 3_600_000;
const T1: &str = "t_00000000000000a1";
const AKID: &str = "AKVL00000001";

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&hash.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn id() -> TenantId {
    TenantId::parse(T1).unwrap()
}

fn unit_id() -> velmora_bridge::unit::TenantId {
    velmora_bridge::unit::TenantId::parse(T1).unwrap()
}

fn key() -> TenantKey {
    TenantKey::from_bytes(&id(), 1, derived("tenant key 1")).unwrap()
}

struct Ports {
    records: Rc<MemRecords>,
    keys_a: MemRecords,
    keys_b: MemRecords,
    kek: TestKek,
    directory: Option<RusqliteSql>,
    clock: FixedClock,
}

impl RootPorts for Ports {
    type Records = MemRecords;
    type KeyStore = MemRecords;
    type Kek = TestKek;
    type Sql = RusqliteSql;
    type Clock = FixedClock;

    fn records(&self) -> &MemRecords {
        &self.records
    }
    fn key_buckets(&self) -> KeyBuckets<'_, MemRecords> {
        KeyBuckets {
            by_name: vec![("KEYS_A", &self.keys_a), ("KEYS_B", &self.keys_b)],
        }
    }
    fn kek(&self) -> &TestKek {
        &self.kek
    }
    fn directory(&self) -> Option<&RusqliteSql> {
        self.directory.as_ref()
    }
    fn clock(&self) -> &FixedClock {
        &self.clock
    }
}

fn directory_db() -> RusqliteSql {
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
    ))
    .unwrap();
    db
}

/// Ports over `records`, with key buckets that hold tenant key 1 when
/// `with_key`, and a directory when `directory`.
fn ports(records: Rc<MemRecords>, with_key: bool, directory: Option<RusqliteSql>) -> Ports {
    let ports = Ports {
        records,
        keys_a: MemRecords::default(),
        keys_b: MemRecords::default(),
        kek: TestKek::new(),
        directory,
        clock: FixedClock::new(NOW),
    };
    if with_key {
        let (kek_v, blob) = wrap_tenant_key(&ports.kek, &key(), &mut TestRng(7)).unwrap();
        let name = tk_blob_name(&id(), 1, kek_v);
        for store in [&ports.keys_a, &ports.keys_b] {
            assert!(block_on(store.put_if_absent(&name, blob.clone())).unwrap());
        }
    }
    ports
}

async fn wrote(root: &Root<'_, Ports, TestRng>, change: Change, actor: Actor, now: UnixMs) {
    let w = root
        .chain()
        .write(&Tenant::Managed(id()), &change, actor, now, 0)
        .await;
    assert!(matches!(w, Ok(Written::Wrote(_))), "{change:?}: {w:?}");
}

/// The safety bucket of a tenant made active under key 1 through a root,
/// with the key locations recorded.
fn active_records() -> Rc<MemRecords> {
    let records = Rc::new(MemRecords::default());
    let p = ports(records.clone(), true, None);
    block_on(async {
        assert!(
            write_locations(&*records, &p.kek, &two_in_account(), &mut TestRng(1))
                .await
                .unwrap()
        );
        let cache = RootCache::new();
        let root = Root::new(&p, &cache, TestRng(2));
        wrote(
            &root,
            Change::Create {
                jurisdiction: "us".into(),
                location_hint: None,
                synthetic: false,
                limits: BTreeMap::new(),
                rate_json: Default::default(),
                features_json: Default::default(),
            },
            Actor::TenantCreation,
            NOW,
        )
        .await;
        wrote(
            &root,
            Change::ClaimKeyVersion { version: 1 },
            Actor::TenantCreation,
            NOW,
        )
        .await;
        // The commit's writer loads the key it seals under by the check
        // value it commits.
        root.load_key(&id(), 1, key().check_value()).await.unwrap();
        wrote(
            &root,
            Change::CommitKeyVersion {
                version: 1,
                kcv: key().check_value(),
            },
            Actor::TenantCreation,
            NOW,
        )
        .await;
        wrote(
            &root,
            Change::Activate {
                external_ref: Some("ws_1".into()),
            },
            Actor::TenantCreation,
            NOW,
        )
        .await;
    });
    records
}

#[test]
fn a_cold_isolate_reads_the_head_with_its_private_part() {
    let records = active_records();
    let p = ports(records, true, None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    block_on(async {
        let head = root.tenant_head(&id()).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Active);
        assert_eq!(head.private.unwrap().external_ref.as_deref(), Some("ws_1"));
        // Held now: a second read loads nothing (the key buckets could be
        // gone).
        let p2 = ports(p.records.clone(), false, None);
        let root2 = Root::new(&p2, &cache, TestRng(4));
        assert!(root2
            .tenant_head(&id())
            .await
            .unwrap()
            .unwrap()
            .private
            .is_some());
        // The door reader needs no key at all.
        let cold = RootCache::new();
        let root3 = Root::new(&p2, &cold, TestRng(5));
        let door = root3
            .heads()
            .head(&Tenant::Managed(id()), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(door.door.seq, 4);
        assert!(door.private.is_none());
        // The key ring of the tenant.
        let ring = root.tenant_keys(&id()).await.unwrap();
        use velmora_bridge::keys::record::TkRing;
        assert_eq!(ring.current().unwrap().check_value(), key().check_value());
        // An unknown tenant.
        let other = TenantId::parse("t_00000000000000b2").unwrap();
        assert!(root.tenant_head(&other).await.unwrap().is_none());
    });
}

#[test]
fn a_live_tenant_whose_key_does_not_load_is_not_read() {
    let records = active_records();
    let p = ports(records, false, None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let e = block_on(root.tenant_head(&id())).unwrap_err();
    assert!(matches!(e, ChainError::Store(_)), "{e:?}");
    // No key locations recorded: nothing loads (fail closed).
    let bare = Rc::new(MemRecords::default());
    let p = ports(bare, true, None);
    let fresh = RootCache::new();
    let root = Root::new(&p, &fresh, TestRng(4));
    assert!(block_on(root.load_key(&id(), 1, key().check_value())).is_err());
}

#[test]
fn a_shredding_tenant_whose_key_is_gone_reads_with_no_private_part() {
    let records = active_records();
    let p = ports(records.clone(), true, None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let due = UnixMs(NOW.0 + 7 * DAY);
    block_on(async {
        root.load_key(&id(), 1, key().check_value()).await.unwrap();
        wrote(
            &root,
            Change::SetDeletion {
                shred_due_at: due,
                reason: DeletionReason::CustomerRequest,
                key_hash: "ab".repeat(32),
            },
            Actor::Customer,
            NOW,
        )
        .await;
        p.clock.set(due);
        root.load_key(&id(), 1, key().check_value()).await.unwrap();
        wrote(&root, Change::StartShred, Actor::ShredJob, due).await;
    });
    // Another isolate, after the shred destroyed the key blobs.
    let p = ports(records, false, None);
    p.clock.set(due);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(4));
    block_on(async {
        let head = root.tenant_head(&id()).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Shredding);
        assert!(head.private.is_none());
        // The shred's last record needs no key.
        wrote(&root, Change::FinishShred, Actor::ShredJob, due).await;
        let head = root.tenant_head(&id()).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Shredded);
    });
}

#[test]
fn key_routes_read_the_directory_then_the_route_record() {
    let records = active_records();
    let dir = directory_db();
    block_on(async {
        // The directory copies the head (seq 4), then takes the route.
        let p = ports(records.clone(), false, None);
        let cache = RootCache::new();
        let root = Root::new(&p, &cache, TestRng(9));
        let head = root
            .heads()
            .head(&Tenant::Managed(id()), 0)
            .await
            .unwrap()
            .unwrap();
        let d = SqlDirectory { sql: &dir };
        d.apply_tenant(&head.door, NOW).await.unwrap();
        d.set_keys_seq(&Tenant::Managed(id()), 3, 0).await.unwrap();
        assert_eq!(
            d.put_route(&KeyRoute {
                akid: AKID.into(),
                tenant: Tenant::Managed(id()),
                kind: RouteKind::S3,
                owner_ref: None,
                created_at: NOW,
            })
            .await
            .unwrap(),
            velmora_bridge::directory::store::RoutePut::Inserted
        );
    });
    let p = ports(records.clone(), false, Some(dir));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(1));
    let routes = root.key_routes();
    let db = p.directory.as_ref().unwrap();
    block_on(async {
        // The directory names the route: the tenant, with the numbers the
        // directory holds for it, in one read.
        db.reset_read_stats();
        let managed = KeyTenant::Managed {
            tenant: unit_id(),
            floor: Seqs {
                state_seq: 4,
                keys_seq: 3,
            },
        };
        assert_eq!(routes.tenant_of(AKID).await.unwrap(), managed);
        assert_eq!(db.read_stats().queries, 1);
        // Kept: the next request reads nothing (a route never changes).
        assert_eq!(routes.tenant_of(AKID).await.unwrap(), managed);
        assert_eq!(db.read_stats().queries, 1);
        // A key the directory names no route for: tenant 0's, and not
        // kept (a route may be made for it later).
        assert_eq!(
            routes.tenant_of("AKVL00000002").await.unwrap(),
            KeyTenant::Zero
        );
        assert_eq!(
            routes.tenant_of("AKVL00000002").await.unwrap(),
            KeyTenant::Zero
        );
        assert_eq!(db.read_stats().queries, 3);
    });
    // The cache is the isolate's: a fresh one for the rest.
    let cache = RootCache::new();

    // The directory cannot be read (no schema): the route record decides.
    let broken = RusqliteSql::open_in_memory().unwrap();
    let p = ports(records.clone(), false, Some(broken));
    let root = Root::new(&p, &cache, TestRng(2));
    block_on(async {
        assert_eq!(
            root.key_routes().tenant_of(AKID).await.unwrap(),
            KeyTenant::Unrouted
        );
        put_route(
            &*records,
            &p.kek,
            &id(),
            AKID,
            SubjectKind::S3,
            1,
            &mut TestRng(3),
        )
        .await
        .unwrap();
        assert_eq!(
            root.key_routes().tenant_of(AKID).await.unwrap(),
            KeyTenant::Managed {
                tenant: unit_id(),
                floor: Seqs {
                    state_seq: 0,
                    keys_seq: 0
                },
            }
        );
    });
    // A route read from its record is kept too: the record gone, the next
    // request still routes without a read.
    let kept = Rc::new(MemRecords::default());
    let p_kept = ports(kept.clone(), false, None);
    let kept_cache = RootCache::new();
    let root = Root::new(&p_kept, &kept_cache, TestRng(6));
    block_on(async {
        put_route(
            &*kept,
            &p_kept.kek,
            &id(),
            AKID,
            SubjectKind::S3,
            1,
            &mut TestRng(7),
        )
        .await
        .unwrap();
        assert!(matches!(
            root.key_routes().tenant_of(AKID).await.unwrap(),
            KeyTenant::Managed { .. }
        ));
    });
    let empty = ports(Rc::new(MemRecords::default()), false, None);
    let root = Root::new(&empty, &kept_cache, TestRng(8));
    assert!(matches!(
        block_on(root.key_routes().tenant_of(AKID)).unwrap(),
        KeyTenant::Managed { .. }
    ));
    // No directory bound, a cold isolate: the route record decides.
    let cache = RootCache::new();
    let p = ports(records, false, None);
    let root = Root::new(&p, &cache, TestRng(4));
    block_on(async {
        assert!(matches!(
            root.key_routes().tenant_of(AKID).await.unwrap(),
            KeyTenant::Managed { .. }
        ));
        assert_eq!(
            root.key_routes().tenant_of("AKVL00000002").await.unwrap(),
            KeyTenant::Unrouted
        );
    });
}

#[test]
fn an_unrouted_key_is_tenant_zeros_only_if_its_catalogue_holds_it() {
    let catalog = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
    block_on(async {
        catalog
            .create_access_key(&AccessKeyRow {
                access_key_id: "AKZERO000001".into(),
                principal: "owner".into(),
                secret_wrapped: vec![1; 40],
                kek_version: 1,
                status: KeyStatus::Disabled,
                created_at: NOW,
            })
            .await
            .unwrap();
        // Held (whatever its status): tenant 0's path, which checks it.
        assert!(
            velmora_bridge::service::serve_unrouted(&catalog, "AKZERO000001")
                .await
                .is_none()
        );
        // Not held: 503 with Retry-After, never 403.
        let (resp, line) = velmora_bridge::service::serve_unrouted(&catalog, "AKVL00000009")
            .await
            .unwrap();
        assert_eq!(resp.status, 503);
        assert!(resp
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("retry-after") && v == "30"));
        assert_eq!(line.code, "key_route_unreadable");
    });
}

/// Root review (general M-2): a retired version is left out of the ring;
/// any other failure to load a version fails the call.
#[test]
fn the_ring_leaves_out_only_a_retired_version() {
    let records = active_records();
    let key2 = TenantKey::from_bytes(&id(), 2, derived("tenant key 2")).unwrap();
    let p = ports(records.clone(), true, None);
    let put = |p: &Ports, key: &TenantKey, kek: &TestKek| {
        let (kek_v, blob) = wrap_tenant_key(kek, key, &mut TestRng(11)).unwrap();
        let name = tk_blob_name(&id(), key.version(), kek_v);
        for store in [&p.keys_a, &p.keys_b] {
            assert!(block_on(store.put_if_absent(&name, blob.clone())).unwrap());
        }
    };
    put(&p, &key2, &p.kek);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    block_on(async {
        root.load_key(&id(), 1, key().check_value()).await.unwrap();
        wrote(
            &root,
            Change::ClaimKeyVersion { version: 2 },
            Actor::RotationJob,
            NOW,
        )
        .await;
        root.load_key(&id(), 2, key2.check_value()).await.unwrap();
        wrote(
            &root,
            Change::CommitKeyVersion {
                version: 2,
                kcv: key2.check_value(),
            },
            Actor::RotationJob,
            NOW,
        )
        .await;
    });
    use velmora_bridge::keys::record::TkRing;
    // Version 1 retired (no blob anywhere): left out.
    let retired = ports(records.clone(), false, None);
    put(&retired, &key2, &retired.kek);
    let cache = RootCache::new();
    let root = Root::new(&retired, &cache, TestRng(4));
    let ring = block_on(root.tenant_keys(&id())).unwrap();
    assert_eq!(ring.current().unwrap().version(), 2);
    assert!(ring.key(1).is_none());
    // Version 1 there but under a KEK this Worker does not hold: the call
    // fails, it does not fold version 1's subjects as closed.
    let other_kek = ports(records, false, None);
    put(&other_kek, &key2, &other_kek.kek);
    let foreign_kek = TestKek::with_versions(9, &[(9, [0x99; 32])]);
    put(&other_kek, &key(), &foreign_kek);
    let cache = RootCache::new();
    let root = Root::new(&other_kek, &cache, TestRng(5));
    assert!(block_on(root.tenant_keys(&id())).is_err());
}

/// Root review (security LOW-B): a refused load drops the seal's keys of
/// the tenant.
#[test]
fn a_refused_load_drops_the_seals_keys() {
    let records = active_records();
    let p = ports(records, true, None);
    let k = Rc::new(key());
    // A foreign name in a key location (as a shred's marker).
    let stray = format!("{}junk", tk_prefix(&id()));
    assert!(block_on(p.keys_a.put_if_absent(&stray, vec![1])).unwrap());
    let fresh = RootCache::new();
    let cold = Root::new(&p, &fresh, TestRng(4));
    fresh.seal_keys.hold(k.clone(), NOW, NOW).unwrap();
    assert!(block_on(cold.load_key(&id(), 1, key().check_value())).is_err());
    assert!(!fresh.seal_keys.holds(&id(), 1, &key().check_value(), NOW));
}

/// Root review (security LOW-C): every root drops the isolate's expired
/// keys, also when it loads none.
#[test]
fn a_new_root_drops_expired_keys() {
    let records = active_records();
    let p = ports(records, true, None);
    let cache = RootCache::new();
    {
        let root = Root::new(&p, &cache, TestRng(3));
        block_on(root.load_key(&id(), 1, key().check_value())).unwrap();
    }
    assert_eq!((cache.tks.len(), cache.seal_keys.len()), (1, 1));
    p.clock.advance_ms(velmora_bridge::keys::tk::TK_CACHE_MS);
    let _root = Root::new(&p, &cache, TestRng(4));
    assert_eq!((cache.tks.len(), cache.seal_keys.len()), (0, 0));
}

/// Root review (general LOW-2): the router's dispatch of every route
/// answer.
#[test]
fn the_router_dispatches_every_route_answer() {
    use velmora_bridge::service::{dispatch_key_route, KeyDispatch};
    let catalog = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
    block_on(async {
        catalog
            .create_access_key(&AccessKeyRow {
                access_key_id: "AKZERO000001".into(),
                principal: "owner".into(),
                secret_wrapped: vec![1; 40],
                kek_version: 1,
                status: KeyStatus::Active,
                created_at: NOW,
            })
            .await
            .unwrap();
        let floor = Seqs {
            state_seq: 2,
            keys_seq: 1,
        };
        let managed = Ok(KeyTenant::Managed {
            tenant: unit_id(),
            floor,
        });
        assert!(matches!(
            dispatch_key_route(managed, &catalog, AKID).await,
            KeyDispatch::Managed { tenant, floor: f } if tenant == unit_id() && f == floor
        ));
        assert!(matches!(
            dispatch_key_route(Ok(KeyTenant::Zero), &catalog, "AKVL00000009").await,
            KeyDispatch::TenantZero
        ));
        // DUR-10: a key tenant 0 holds goes to its path ...
        for route in [
            Ok(KeyTenant::Unrouted),
            Err(velmora_bridge::BridgeError::Invalid("route read failed")),
        ] {
            assert!(matches!(
                dispatch_key_route(route, &catalog, "AKZERO000001").await,
                KeyDispatch::TenantZero
            ));
        }
        // ... any other answers 503.
        for route in [
            Ok(KeyTenant::Unrouted),
            Err(velmora_bridge::BridgeError::Invalid("route read failed")),
        ] {
            match dispatch_key_route(route, &catalog, "AKVL00000009").await {
                KeyDispatch::Answer(resp, line) => {
                    assert_eq!(resp.status, 503);
                    assert_eq!(line.code, "key_route_unreadable");
                }
                _ => panic!("a key no route names after a failed read is not tenant 0's"),
            }
        }
    });
    // A catalogue that cannot be read either: 503.
    let broken = SqlCatalog::new(RusqliteSql::open_in_memory().unwrap());
    match block_on(dispatch_key_route(
        Ok(KeyTenant::Unrouted),
        &broken,
        "AKZERO000001",
    )) {
        KeyDispatch::Answer(resp, line) => {
            assert_eq!(resp.status, 503);
            assert_eq!(line.code, "key_route_and_catalogue_unreadable");
        }
        _ => panic!("a failed catalogue read is not tenant 0's path"),
    }
}
