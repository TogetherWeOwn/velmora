//! A managed tenant's S3 requests served on its unit (package L6-6;
//! tenancy ADR §2.7, AM-64, AM-71), end to end in one process: the key
//! route's tenant, `service::managed::prepare` (the root unit's
//! `key_row`), the request catalogue over the request port, the router
//! and L2's unit client, a real unit on SQLite, and tenant 0's handlers
//! (`Bridge::handle`) over it. Then `service::managed::finish`.
//!
//! What it shows: a PUT and a GET round-trip through the unit, the
//! object's safety copy is named in the tenant's scope and its bucket key
//! is the tenant key's wrap (scheme 2); a bad signature reads nothing but
//! the `key_row`; a suspended read-only tenant serves GET and refuses PUT
//! `403 AccountProblem`; DeleteBucket over S3 answers `403` and writes
//! nothing; no request call is ever sent before the signature verified.

mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use service_support::{config, pattern, Jobs, NoNntp, Resp, Signer, AKID, T0};
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::config::Maintenance;
use velmora_bridge::crypto::scheme2::{
    tk_blob_name, wrap_bdk_v2, wrap_secret_v2, wrap_tenant_key, TenantId, TenantKey,
};
use velmora_bridge::crypto::DataKey;
use velmora_bridge::directory::chain::Written;
use velmora_bridge::directory::record::Tenant;
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::jobmsg::ControlIntent;
use velmora_bridge::keys::locations::{two_in_account, write_locations};
use velmora_bridge::keys::record::{
    key_chain, seal_key_record, Access, Grant, KeyOp, OneKey, Subject, SubjectDoor, SubjectKind,
    SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::tk::KeyBuckets;
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::recovery::Unpublished;
use velmora_bridge::request_catalog::RequestCatalog;
use velmora_bridge::root::request::RequestPort;
use velmora_bridge::root::{ControlSend, Root, RootCache, RootPorts, UnitPorts};
use velmora_bridge::service::managed::{finish, prepare, Prepared};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::unit::call::HoldMode;
use velmora_bridge::unit::request_client::RequestClient;
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Seqs, SyncHead, TenantState, Unit, UnitAnswer, UnitCall,
    UnitName, UnitOp, UnitReply,
};
use velmora_bridge::unit_lease::client::{Synced, UnitReplies};
use velmora_bridge::unit_lease::lease::Proven;
use velmora_bridge::{
    BlobMeta, BlobStore, Bridge, BucketId, ByteSpan, Method, Result, Sql, TenantScope,
};

const T1: &str = "t_00000000000000c1";
const SECRET: &str = "managed-request-secret-0123456789";
const BUCKET: &str = "alpha";
const PRINCIPAL: &str = "PR0001";

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

fn root_unit() -> UnitName {
    UnitName::new(unit_id(), 0)
}

fn key() -> TenantKey {
    TenantKey::from_bytes(&id(), 1, derived("tenant key 1")).unwrap()
}

fn bucket_id() -> BucketId {
    BucketId::mint([0xb1; 8])
}

/// The unit object: the real unit, at `T0`, with every call kept.
struct Object {
    unit: Rc<Unit<RusqliteSql>>,
    calls: Rc<RefCell<Vec<UnitCall>>>,
}

impl UnitReplies for Object {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply> {
        self.calls.borrow_mut().push(call.clone());
        Ok(self.unit.reply(call, T0))
    }
}

/// One blob store across the requests of a test (each request has a
/// bridge of its own).
#[derive(Clone, Default)]
struct Blobs(Rc<MemBlobStore>);

impl BlobStore for Blobs {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.0.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.0.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.0.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.0.delete(key).await
    }
    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.0.list(prefix, start_after, limit).await
    }
}

#[derive(Default)]
struct Control(RefCell<Vec<String>>);

impl ControlSend for Control {
    async fn send_control(&self, intent: &ControlIntent) -> Result<()> {
        self.0.borrow_mut().push(intent.message().to_json());
        Ok(())
    }
}

struct Ports {
    records: MemRecords,
    keys_a: MemRecords,
    keys_b: MemRecords,
    kek: TestKek,
    clock: FixedClock,
    unit: Rc<Unit<RusqliteSql>>,
    calls: Rc<RefCell<Vec<UnitCall>>>,
    safety: MemBlobStore,
    control: Control,
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
        None
    }
    fn clock(&self) -> &FixedClock {
        &self.clock
    }
}

impl UnitPorts for Ports {
    type Object = Object;
    type Safety = MemBlobStore;
    type Control = Control;
    fn object(&self, name: &UnitName) -> Result<Object> {
        assert_eq!(name, &root_unit());
        Ok(Object {
            unit: Rc::clone(&self.unit),
            calls: Rc::clone(&self.calls),
        })
    }
    fn safety(&self) -> &MemBlobStore {
        &self.safety
    }
    fn control(&self) -> &Control {
        &self.control
    }
}

async fn wrote(root: &Root<'_, Ports, TestRng>, change: Change) {
    let w = root
        .chain()
        .write(
            &Tenant::Managed(id()),
            &change,
            Actor::TenantCreation,
            T0,
            0,
        )
        .await;
    assert!(matches!(w, Ok(Written::Wrote(_))), "{change:?}: {w:?}");
}

fn worker(unit: &Unit<RusqliteSql>, op: UnitOp) -> UnitAnswer {
    unit.handle(
        &UnitCall {
            name: root_unit(),
            kind: CallKind::Worker,
            seqs: None,
            authenticated: true,
            listed: true,
            op,
        },
        T0,
    )
}

fn subject(id: &str, kind: SubjectKind) -> Subject {
    let mut s = Subject {
        door: SubjectDoor {
            id: id.to_owned(),
            kind,
            status: SubjectStatus::Active,
            made_by: None,
            grants: Vec::new(),
            created_at: 1_000,
            secret_kek_version: None,
        },
        private: SubjectPrivate {
            owner_ref: None,
            label: None,
            grants: Vec::new(),
            secret_wrapped: None,
        },
    };
    s.set_grants(&[Grant {
        bucket_id: bucket_id().as_str().to_owned(),
        access: Access::Rw,
        expires_at: None,
        prefix: None,
        ip_list: Vec::new(),
    }]);
    s
}

/// A managed tenant, active under key 1, with the key locations; its
/// root unit born, renewed and synced to the head (no directory: every
/// subject open), holding bucket `alpha` (its key wrapped under tenant
/// key 1) and an S3 key `AKID` of `PR0001` with `rw` on it.
struct World {
    ports: Rc<Ports>,
    cache: Rc<RootCache>,
    safety: Blobs,
    blobs: Blobs,
}

impl World {
    fn new() -> World {
        let kek = TestKek::new();
        let ports = Ports {
            records: MemRecords::default(),
            keys_a: MemRecords::default(),
            keys_b: MemRecords::default(),
            kek: TestKek::new(),
            clock: FixedClock::new(T0),
            unit: Rc::new(Unit::new(
                RusqliteSql::open_in_memory().unwrap(),
                root_unit(),
                "",
            )),
            calls: Rc::default(),
            safety: MemBlobStore::default(),
            control: Control::default(),
        };
        let (kek_v, blob) = wrap_tenant_key(&kek, &key(), &mut TestRng(7)).unwrap();
        for store in [&ports.keys_a, &ports.keys_b] {
            assert!(
                block_on(store.put_if_absent(&tk_blob_name(&id(), 1, kek_v), blob.clone()))
                    .unwrap()
            );
        }
        let cache = Rc::new(RootCache::new());
        let state_seq = block_on(async {
            assert!(write_locations(
                &ports.records,
                &ports.kek,
                &two_in_account(),
                &mut TestRng(1)
            )
            .await
            .unwrap());
            let root = Root::new(&ports, &cache, TestRng(2));
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
            )
            .await;
            wrote(&root, Change::ClaimKeyVersion { version: 1 }).await;
            root.load_key(&id(), 1, key().check_value()).await.unwrap();
            wrote(
                &root,
                Change::CommitKeyVersion {
                    version: 1,
                    kcv: key().check_value(),
                },
            )
            .await;
            wrote(
                &root,
                Change::Activate {
                    external_ref: Some("ws_1".into()),
                },
            )
            .await;
            root.heads()
                .head(&Tenant::Managed(id()), 0)
                .await
                .unwrap()
                .unwrap()
                .door
                .seq
        });
        // The key chain: the principal, then its S3 key.
        let seal = |seq: u64, s: &Subject| {
            seal_key_record(
                &ports.kek,
                &OneKey(key()),
                &id(),
                seq,
                KeyOp::Create,
                10 + seq,
                &s.door,
                Some(&s.private),
                false,
                None,
                &mut TestRng(100 + seq),
            )
            .unwrap()
        };
        let principal = subject(PRINCIPAL, SubjectKind::Principal);
        ports
            .records
            .plant(&key_chain(&id()).name(1), seal(1, &principal));
        let mut s3 = subject(AKID, SubjectKind::S3);
        let (v, wrapped) =
            wrap_secret_v2(&ports.kek, &id(), AKID, SECRET.as_bytes(), &mut TestRng(9)).unwrap();
        s3.door.made_by = Some(PRINCIPAL.into());
        s3.door.secret_kek_version = Some(v);
        s3.private.secret_wrapped = Some(wrapped);
        ports.records.plant(&key_chain(&id()).name(2), seal(2, &s3));
        // The unit: born at the head, its bucket row, renewed, synced.
        let born = ports.unit.handle(
            &UnitCall {
                name: root_unit(),
                kind: CallKind::Worker,
                seqs: Some(Seqs {
                    state_seq,
                    keys_seq: 0,
                }),
                authenticated: true,
                listed: true,
                op: UnitOp::Provision {
                    token: BirthToken {
                        name: root_unit(),
                        jurisdiction: String::new(),
                        record_seq: state_seq,
                        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
                        key_scheme: 2,
                        kind: BirthKind::Birth,
                    },
                    sealed: vec![1],
                },
            },
            T0,
        );
        assert!(matches!(born, UnitAnswer::Ok { .. }), "{born:?}");
        let bdk = DataKey::generate(&mut TestRng(11)).unwrap();
        // (The test reads the bytes back through the tenant key alone.)
        let bdk_wrapped = wrap_bdk_v2(&key(), &bucket_id(), &bdk, &mut TestRng(12)).unwrap();
        block_on(ports.unit.sql().exec(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
             VALUES (?1, ?2, ?3, ?4, 1, 1)",
            &[
                velmora_bridge::SqlValue::Text(bucket_id().as_str().to_owned()),
                velmora_bridge::SqlValue::Text(BUCKET.into()),
                velmora_bridge::SqlValue::Text(PRINCIPAL.into()),
                velmora_bridge::SqlValue::Blob(bdk_wrapped),
            ],
        ))
        .unwrap();
        let world = World {
            ports: Rc::new(ports),
            cache,
            safety: Blobs::default(),
            blobs: Blobs::default(),
        };
        world.renew();
        let root = Root::new(&*world.ports, &world.cache, TestRng(3));
        let client = root.unit_client(&root_unit(), false).unwrap();
        let synced = block_on(client.sync(Seqs {
            state_seq,
            keys_seq: 0,
        }))
        .unwrap();
        assert!(
            matches!(synced, Synced::Synced { seqs } if seqs.keys_seq == 2),
            "{synced:?}"
        );
        world.ports.calls.borrow_mut().clear();
        world
    }

    fn renew(&self) {
        let seqs = self.ports.unit.head().unwrap().seqs;
        let a = worker(
            &self.ports.unit,
            UnitOp::Renew {
                proof_start: T0,
                proven: Proven {
                    state_seq: seqs.state_seq,
                    keys_seq: seqs.keys_seq,
                    stamp_counter: None,
                    revoked: 0,
                },
                revocations: Vec::new(),
            },
        );
        assert!(matches!(a, UnitAnswer::Ok { .. }), "renew: {a:?}");
    }

    /// Holds the tenant suspended read-only at the unit (a `sync` of the
    /// unit's own head with that state).
    fn suspend(&self) {
        let seqs = self.ports.unit.head().unwrap().seqs;
        let a = worker(
            &self.ports.unit,
            UnitOp::Sync {
                head: SyncHead {
                    seqs: Seqs {
                        state_seq: seqs.state_seq + 1,
                        keys_seq: seqs.keys_seq,
                    },
                    tenant_state: TenantState::Suspended,
                    tenant_mode: Some(HoldMode::ReadOnly),
                    restoring_since: None,
                    lift: None,
                },
            },
        );
        assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
        self.renew();
    }

    /// One request through the whole managed path, as the Worker serves
    /// it (`units::route_request` and `serve_on_unit`).
    fn serve(&self, req: service_support::Req) -> (Resp, Vec<&'static str>) {
        let req = req.into_request();
        let floor = Seqs {
            state_seq: 0,
            keys_seq: 0,
        };
        let cfg = config(Vec::new());
        let prepared = block_on(async {
            let root = Root::new(&*self.ports, &self.cache, TestRng(4));
            let clients = root.clients();
            let heads = root.heads();
            let router = root.router(Maintenance::Off, &clients, &heads);
            prepare(&router, &cfg, &unit_id(), floor, AKID, &req).await
        });
        let request = match prepared {
            Prepared::Answer(resp, lines) => {
                let resp = block_on(Resp::collect(resp));
                return (resp, lines.iter().map(|l| l.code).collect());
            }
            Prepared::Serve(request) => request,
        };
        let unit = request.routed.as_ref().unwrap_or(&request.root).clone();
        let verified = Rc::new(Cell::new(false));
        let port = RequestPort::new(
            Rc::clone(&self.ports),
            Rc::clone(&self.cache),
            || TestRng(5),
            Maintenance::Off,
            request.routed,
            Rc::clone(&verified),
        );
        let client = RequestClient::new(port, unit.unit.clone(), unit.seqs);
        let shared = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
        let catalog = RequestCatalog::new(
            client,
            shared,
            request.scope,
            AKID,
            request.key_row,
            verified,
        );
        let ucfg = cfg.for_unit(&unit.unit).unwrap();
        let bridge = Rc::new(Bridge {
            catalog,
            safety: self.safety.clone(),
            cache: self.blobs.clone(),
            nntp: NoNntp,
            jobs: Jobs::default(),
            kek: TestKek::new(),
            clock: FixedClock::new(T0),
            budget: ByteBudget::new(ucfg.inflight_budget_bytes),
            cfg: ucfg,
        });
        let (resp, lines) = block_on(async {
            let resp = Box::pin(Rc::clone(&bridge).handle(req)).await;
            let finished = finish(bridge.catalog.client(), &bridge.safety, resp).await;
            (
                Resp::collect(finished.resp).await,
                finished.lines.iter().map(|l| l.code).collect::<Vec<_>>(),
            )
        });
        (resp, lines)
    }

    fn calls(&self) -> Vec<UnitCall> {
        self.ports.calls.borrow().clone()
    }
}

fn signer() -> Signer {
    Signer::new(AKID, SECRET)
}

fn object_path() -> String {
    format!("/{BUCKET}/photo.jpg")
}

/// Every request call carries `authenticated`, and no call but the
/// `key_row` is ever unauthenticated.
fn only_the_key_row_before_the_signature(calls: &[UnitCall]) {
    for call in calls {
        match &call.op {
            UnitOp::KeyRow { .. } => assert!(!call.authenticated, "{call:?}"),
            _ => assert!(call.authenticated, "{call:?}"),
        }
    }
}

#[test]
fn a_put_and_a_get_round_trip_through_the_unit() {
    let w = World::new();
    let body = pattern(7, 4096);
    let put = signer().sign(T0, Method::Put, &object_path(), &[], &[], body.clone());
    let (resp, lines) = w.serve(put);
    assert_eq!(
        resp.status,
        200,
        "{}: {lines:?}",
        String::from_utf8_lossy(&resp.body)
    );
    assert_eq!(lines[0], "served");
    let calls = w.calls();
    assert!(matches!(calls[0].op, UnitOp::KeyRow { .. }));
    assert!(calls.len() > 2, "{}", calls.len());
    only_the_key_row_before_the_signature(&calls);
    // The safety copy is in the tenant's scope, never tenant 0's flat
    // name.
    let names = block_on(w.safety.list("x/", "", 100)).unwrap();
    assert_eq!(names.len(), 1, "{names:?}");
    let scope = TenantScope::managed(&unit_id()).unwrap();
    assert!(
        names[0].starts_with(&format!("x/{}/", scope.tenant_id())),
        "{names:?}"
    );
    // The GET reads the unit's rows and the tenant's blobs, and opens the
    // bytes with the bucket key the tenant key unwraps.
    w.ports.calls.borrow_mut().clear();
    let get = signer().sign(T0, Method::Get, &object_path(), &[], &[], Vec::new());
    let (resp, lines) = w.serve(get);
    assert_eq!(resp.status, 200, "{lines:?}");
    assert_eq!(resp.body, body);
    only_the_key_row_before_the_signature(&w.calls());
    // A HEAD as well.
    let head = signer().sign(T0, Method::Head, &object_path(), &[], &[], Vec::new());
    assert_eq!(w.serve(head).0.status, 200);
}

#[test]
fn a_bad_signature_reads_nothing_but_the_key_row() {
    let w = World::new();
    let put = Signer::new(AKID, "not-the-secret").sign(
        T0,
        Method::Put,
        &object_path(),
        &[],
        &[],
        b"x".to_vec(),
    );
    let (resp, _) = w.serve(put);
    assert_eq!(resp.status, 403);
    assert!(String::from_utf8_lossy(&resp.body).contains("SignatureDoesNotMatch"));
    // The key row only (sent once more with the unit's numbers when the
    // isolate knew none: rule 5's one retry), unauthenticated.
    key_row_only(&w.calls());
}

/// Every call was the `key_row`, unauthenticated: nothing else was read.
fn key_row_only(calls: &[UnitCall]) {
    assert!(!calls.is_empty() && calls.len() <= 2, "{calls:?}");
    for call in calls {
        assert!(matches!(call.op, UnitOp::KeyRow { .. }), "{call:?}");
        assert!(!call.authenticated, "{call:?}");
    }
}

#[test]
fn a_suspended_read_only_tenant_serves_reads_and_refuses_writes() {
    let w = World::new();
    w.suspend();
    let put = signer().sign(T0, Method::Put, &object_path(), &[], &[], b"x".to_vec());
    let (resp, _) = w.serve(put);
    assert_eq!(resp.status, 403, "{}", String::from_utf8_lossy(&resp.body));
    assert!(String::from_utf8_lossy(&resp.body).contains("AccountProblem"));
    // Nothing but the key row: the state refused the request before any
    // other call.
    key_row_only(&w.calls());
    w.ports.calls.borrow_mut().clear();
    let list = signer().sign(T0, Method::Get, &format!("/{BUCKET}"), &[], &[], Vec::new());
    let (resp, lines) = w.serve(list);
    assert_eq!(resp.status, 200, "{lines:?}");
}

#[test]
fn delete_bucket_over_s3_is_refused_and_writes_nothing() {
    let w = World::new();
    let del = signer().sign(
        T0,
        Method::Delete,
        &format!("/{BUCKET}"),
        &[],
        &[],
        Vec::new(),
    );
    let (resp, _) = w.serve(del);
    assert_eq!(resp.status, 403);
    for call in w.calls() {
        assert!(call.op.is_read(), "{call:?}");
    }
    // A key that is not the tenant's: no key row, InvalidAccessKeyId
    // after the signature check.
    let other = Signer::new("AKIDOTHERKEY00000001", SECRET).sign(
        T0,
        Method::Get,
        &format!("/{BUCKET}"),
        &[],
        &[],
        Vec::new(),
    );
    let (resp, _) = w.serve(other);
    assert_eq!(resp.status, 403);
}
