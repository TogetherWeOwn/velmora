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

use service_support::{config, pattern, Jobs, Resp, Signer, AKID, T0};
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora::yenc::{encode_segment, SegmentParams};
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
use velmora_bridge::service::claimed_access_key;
use velmora_bridge::service::managed::{finish, prepare, Prepared};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::unit::call::{Closed, HoldMode};
use velmora_bridge::unit::request::RequestCall;
use velmora_bridge::unit::request_client::RequestClient;
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Seqs, SyncHead, TenantState, Unit, UnitAnswer, UnitCall,
    UnitName, UnitOp, UnitReply,
};
use velmora_bridge::unit_lease::client::{Synced, UnitReplies};
use velmora_bridge::unit_lease::lease::Proven;
use velmora_bridge::{
    BlobMeta, BlobStore, BodyOutcome, Bridge, BucketId, ByteSpan, Catalog, Method, NntpConnector,
    NntpSession, Permit, ProviderConfig, Result, Sql, SqlValue, TenantScope,
};

const T1: &str = "t_00000000000000c1";
const SECRET: &str = "managed-request-secret-0123456789";
const NO_GRANT_AKID: &str = "AKIDNOGRANT000000001";
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
    close_on_publication: Rc<Cell<bool>>,
    request_safety: Blobs,
}

impl UnitReplies for Object {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply> {
        self.calls.borrow_mut().push(call.clone());
        if let (true, UnitOp::Request { call: op }) = (self.close_on_publication.get(), &call.op) {
            if let RequestCall::commit_generation { record, .. } = op.as_ref() {
                assert!(self.request_safety.0.contains(&record.key));
                return Ok(UnitReply {
                    answer: UnitAnswer::Closed {
                        seqs: call.seqs.unwrap(),
                        why: Closed::Restoring,
                    },
                    lease_left_ms: 0,
                    revoked: None,
                });
            }
        }
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

const MESSAGE_ID: &str = "test-extent@example.invalid";

/// A single article available to a cold GET. No sockets are opened.
#[derive(Clone, Default)]
struct Article(Option<Rc<Vec<u8>>>);

impl NntpConnector for Article {
    type Session = Self;

    async fn connect(&self, _: &ProviderConfig, _: &Permit) -> Result<Self> {
        assert!(self.0.is_some(), "unexpected cold read");
        Ok(self.clone())
    }
}

impl NntpSession for Article {
    async fn post(&mut self, _: &str, _: &[u8]) -> Result<velmora::nntp::PostOutcome> {
        panic!("the article is read-only")
    }
    async fn stat(&mut self, _: &str) -> Result<bool> {
        panic!("a cold read needs only BODY")
    }
    async fn body(&mut self, id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome> {
        assert_eq!(id, MESSAGE_ID);
        out.extend_from_slice(self.0.as_ref().unwrap());
        Ok(BodyOutcome::Found)
    }
    async fn quit(self) {}
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
    close_on_publication: Rc<Cell<bool>>,
    request_safety: Blobs,
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
            close_on_publication: Rc::clone(&self.close_on_publication),
            request_safety: self.request_safety.clone(),
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
/// key 1) and two S3 keys of `PR0001`: `AKID` with `rw` on it, and
/// `NO_GRANT_AKID` with no grants.
struct World {
    ports: Rc<Ports>,
    cache: Rc<RootCache>,
    safety: Blobs,
    blobs: Blobs,
    article: Article,
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
            close_on_publication: Rc::default(),
            request_safety: Blobs::default(),
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
        // The key chain: the principal, then its two S3 keys.
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
        for (seq, akid) in [(2, AKID), (3, NO_GRANT_AKID)] {
            let mut s3 = subject(akid, SubjectKind::S3);
            if akid == NO_GRANT_AKID {
                s3.set_grants(&[]);
            }
            let (v, wrapped) = wrap_secret_v2(
                &ports.kek,
                &id(),
                akid,
                SECRET.as_bytes(),
                &mut TestRng(7 + seq),
            )
            .unwrap();
            s3.door.made_by = Some(PRINCIPAL.into());
            s3.door.secret_kek_version = Some(v);
            s3.private.secret_wrapped = Some(wrapped);
            ports
                .records
                .plant(&key_chain(&id()).name(seq), seal(seq, &s3));
        }
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
            safety: ports.request_safety.clone(),
            ports: Rc::new(ports),
            cache,
            blobs: Blobs::default(),
            article: Article::default(),
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
            matches!(synced, Synced::Synced { seqs } if seqs.keys_seq == 3),
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

    /// Put the existing ciphertext only in the fake provider, so a GET
    /// must verify it and fill the cache rather than read a warm copy.
    fn make_cold(&mut self, safety_key: &str, extent_id: &str) {
        let cipher = self.safety.0.stored(safety_key).unwrap().bytes;
        let size = cipher.len() as u64;
        let mut body = Vec::new();
        encode_segment(
            &mut body,
            &SegmentParams {
                name: "test".into(),
                part: 1,
                total: 1,
                begin: 1,
                end: size,
                file_size: size,
            },
            &cipher,
        )
        .unwrap();
        block_on(self.ports.unit.sql().exec(
            "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, \
             cipher_offset, cipher_len, payload_sha256, state, provider_id) \
             VALUES (?1, 0, ?2, 'test', x'', 0, ?3, ?4, 'posted', 'test')",
            &[
                SqlValue::Text(extent_id.into()),
                SqlValue::Text(MESSAGE_ID.into()),
                SqlValue::Int(i64::try_from(size).unwrap()),
                SqlValue::Blob(Sha256::digest(&cipher).to_vec()),
            ],
        ))
        .unwrap();
        self.article = Article(Some(Rc::new(body)));
        assert!(self.safety.0.lose(safety_key));
    }

    /// One request through the whole managed path, as the Worker serves
    /// it (`units::route_request` and `serve_on_unit`).
    fn serve(
        &self,
        req: service_support::Req,
        maintenance: Maintenance,
    ) -> (Resp, Vec<&'static str>) {
        let req = req.into_request();
        let floor = Seqs {
            state_seq: 0,
            keys_seq: 0,
        };
        let mut cfg = config(Vec::new());
        cfg.maintenance = maintenance;
        if self.article.0.is_some() {
            cfg.providers.push(
                serde_json::from_value(serde_json::json!({
                    "id": "test", "host": "example.invalid", "port": 563, "tls": true,
                    "user": "fixture", "pass": "fixture", "backbone": "test",
                    "post": false, "read": true, "max_conns": 1, "enabled": true
                }))
                .unwrap(),
            );
        }
        let akid = claimed_access_key(&cfg, &req).unwrap();
        let prepared = block_on(async {
            let root = Root::new(&*self.ports, &self.cache, TestRng(4));
            let clients = root.clients();
            let heads = root.heads();
            let router = root.router(maintenance, &clients, &heads);
            prepare(&router, &cfg, &unit_id(), floor, &akid, &req).await
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
            maintenance,
            request.root.clone(),
            request.root_renew,
            request.routed,
            Rc::clone(&verified),
        );
        let client = RequestClient::new(port, unit.unit.clone(), unit.seqs);
        let shared = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
        block_on(shared.seed_permits(&cfg.providers)).unwrap();
        let catalog = RequestCatalog::new(
            client,
            shared,
            request.scope,
            &akid,
            request.key_row,
            verified,
        );
        let ucfg = cfg.for_unit(&unit.unit).unwrap();
        let bridge = Rc::new(Bridge {
            catalog,
            safety: self.safety.clone(),
            cache: self.blobs.clone(),
            nntp: self.article.clone(),
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

fn put(signer: &Signer) -> service_support::Req {
    signer.sign(T0, Method::Put, &object_path(), &[], &[], b"x".to_vec())
}

fn create_multipart(signer: &Signer) -> service_support::Req {
    signer.sign(
        T0,
        Method::Post,
        &object_path(),
        &[("uploads", "")],
        &[],
        Vec::new(),
    )
}

fn assert_s3_error(resp: &Resp, status: u16, code: &str) {
    let body = String::from_utf8_lossy(&resp.body);
    assert_eq!(resp.status, status, "{body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
}

/// The initial key-row lookup (and any retry) is unauthenticated. Every
/// later call carries `authenticated`.
fn only_the_key_row_before_the_signature(calls: &[UnitCall]) {
    let initial = calls
        .iter()
        .take_while(|call| !call.authenticated && matches!(call.op, UnitOp::KeyRow { .. }))
        .count();
    key_row_only(&calls[..initial]);
    for call in &calls[initial..] {
        assert!(call.authenticated, "{call:?}");
    }
}

fn sent_create_upload(calls: &[UnitCall]) -> bool {
    calls.iter().any(|c| {
        matches!(&c.op, UnitOp::Request { call } if matches!(call.as_ref(), RequestCall::create_upload { .. }))
    })
}

fn assert_scoped_blobs(world: &World) {
    // List both entire stores, not just the expected prefixes. Safety
    // also holds the separately scoped recovery record, not extent data.
    let safety = block_on(world.safety.list("", "", u32::MAX)).unwrap();
    let extent_prefix = format!("x/{T1}/");
    let record_prefix = format!("m/{extent_prefix}");
    for name in safety {
        assert!(
            name.starts_with(&extent_prefix) || name.starts_with(&record_prefix),
            "unscoped safety blob: {name}"
        );
    }
    let cache_prefix = format!("c/{T1}/");
    for name in block_on(world.blobs.list("", "", u32::MAX)).unwrap() {
        assert!(
            name.starts_with(&cache_prefix),
            "unscoped cache blob: {name}"
        );
    }
}

#[test]
fn a_put_and_a_get_round_trip_through_the_unit() {
    let mut w = World::new();
    let body = pattern(7, 4096);
    let put = signer().sign(T0, Method::Put, &object_path(), &[], &[], body.clone());
    let (resp, lines) = w.serve(put, Maintenance::Off);
    assert_eq!(
        resp.status,
        200,
        "{}: {lines:?}",
        String::from_utf8_lossy(&resp.body)
    );
    assert_eq!(lines[0], "served");
    assert_scoped_blobs(&w);
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
    // Its recovery record is the tenant's: a VMR2 envelope under the
    // tenant key in `m/x/<t>/` (ADR §3.2), which the KEK does not open.
    let records = block_on(w.safety.list("m/", "", 100)).unwrap();
    assert_eq!(records.len(), 1, "{records:?}");
    assert!(records[0].starts_with(&format!("m/x/{T1}/")), "{records:?}");
    let sealed = block_on(w.safety.get(&records[0], None)).unwrap().unwrap();
    assert!(velmora_bridge::crypto::scheme2::is_record_v2(&sealed));
    assert!(velmora_bridge::crypto::open_manifest(&TestKek::new(), &records[0], &sealed).is_err());
    let plain =
        velmora_bridge::crypto::scheme2::open_record_v2(&key(), &id(), &records[0], &sealed)
            .unwrap();
    assert!(String::from_utf8_lossy(&plain).contains("photo.jpg"));
    // The GET reads the unit's rows and the tenant's blobs, and opens the
    // bytes with the bucket key the tenant key unwraps.
    w.ports.calls.borrow_mut().clear();
    let get = signer().sign(T0, Method::Get, &object_path(), &[], &[], Vec::new());
    let (resp, lines) = w.serve(get, Maintenance::Off);
    assert_eq!(resp.status, 200, "{lines:?}");
    assert_eq!(resp.body, body);
    assert_scoped_blobs(&w);
    only_the_key_row_before_the_signature(&w.calls());
    // Force a cold GET so the cache listing also checks a real write.
    let extent_id = names[0].strip_prefix(&format!("x/{T1}/")).unwrap();
    w.make_cold(&names[0], extent_id);
    w.ports.calls.borrow_mut().clear();
    let get = signer().sign(T0, Method::Get, &object_path(), &[], &[], Vec::new());
    let (resp, lines) = w.serve(get, Maintenance::Off);
    assert_eq!(resp.status, 200, "{lines:?}: {:?}", resp.stream_error);
    assert_eq!(resp.body, body);
    assert_scoped_blobs(&w);
    assert!(w.blobs.0.contains(&format!("c/{T1}/{extent_id}")));
    only_the_key_row_before_the_signature(&w.calls());
    // A HEAD as well.
    let head = signer().sign(T0, Method::Head, &object_path(), &[], &[], Vec::new());
    assert_eq!(w.serve(head, Maintenance::Off).0.status, 200);
}

#[test]
fn a_bad_signature_reads_nothing_but_the_key_row() {
    let w = World::new();
    let req = put(&Signer::new(AKID, "not-the-secret"));
    let (resp, _) = w.serve(req, Maintenance::Off);
    assert_s3_error(&resp, 403, "SignatureDoesNotMatch");
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
    let (resp, _) = w.serve(put(&signer()), Maintenance::Off);
    assert_eq!(resp.status, 403, "{}", String::from_utf8_lossy(&resp.body));
    assert!(String::from_utf8_lossy(&resp.body).contains("AccountProblem"));
    // Nothing but the key row: the state refused the request before any
    // other call.
    key_row_only(&w.calls());
    w.ports.calls.borrow_mut().clear();
    let list = signer().sign(T0, Method::Get, &format!("/{BUCKET}"), &[], &[], Vec::new());
    let (resp, lines) = w.serve(list, Maintenance::Off);
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
    let (resp, _) = w.serve(del, Maintenance::Off);
    assert_s3_error(&resp, 403, "AccessDenied");
    for call in w.calls() {
        assert!(call.op.is_read(), "{call:?}");
    }
    // A key that is not the tenant's: no key row, InvalidAccessKeyId.
    let other_akid = "AKIDOTHERKEY00000001";
    let other = Signer::new(other_akid, SECRET).sign(
        T0,
        Method::Get,
        &format!("/{BUCKET}"),
        &[],
        &[],
        Vec::new(),
    );
    let (resp, _) = w.serve(other, Maintenance::Off);
    assert_s3_error(&resp, 403, "InvalidAccessKeyId");
}

#[test]
fn create_multipart_checks_the_signature_before_request_calls() {
    let w = World::new();
    let bad = create_multipart(&Signer::new(AKID, "not-the-secret"));
    let (resp, _) = w.serve(bad, Maintenance::Off);
    assert_s3_error(&resp, 403, "SignatureDoesNotMatch");
    key_row_only(&w.calls());

    w.ports.calls.borrow_mut().clear();
    let (resp, _) = w.serve(create_multipart(&signer()), Maintenance::Off);
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    assert!(String::from_utf8_lossy(&resp.body).contains("<UploadId>"));
    let calls = w.calls();
    only_the_key_row_before_the_signature(&calls);
    assert!(sent_create_upload(&calls), "{calls:?}");
}

#[test]
fn create_multipart_without_a_grant_returns_no_such_bucket() {
    let w = World::new();
    let req = create_multipart(&Signer::new(NO_GRANT_AKID, SECRET));
    let (resp, _) = w.serve(req, Maintenance::Off);
    assert_s3_error(&resp, 404, "NoSuchBucket");
    let calls = w.calls();
    only_the_key_row_before_the_signature(&calls);
    assert!(!sent_create_upload(&calls), "{calls:?}");
}

#[track_caller]
fn assert_restore_checks_signature_then_refuses_write(
    request: fn(&Signer) -> service_support::Req,
) {
    let w = World::new();
    let bad = request(&Signer::new(AKID, "not-the-secret"));
    let (resp, _) = w.serve(bad, Maintenance::Restore);
    assert_s3_error(&resp, 403, "SignatureDoesNotMatch");
    key_row_only(&w.calls());

    w.ports.calls.borrow_mut().clear();
    let (resp, lines) = w.serve(request(&signer()), Maintenance::Restore);
    assert_eq!(resp.status, 503, "{}", String::from_utf8_lossy(&resp.body));
    // The handler gates the write; the router did not have to stop one.
    assert_eq!(lines, ["served"]);
    let calls = w.calls();
    only_the_key_row_before_the_signature(&calls);
    assert!(calls.iter().all(|c| c.op.is_read()), "{calls:?}");
    assert!(w.safety.0.keys().is_empty());
    assert!(w.blobs.0.keys().is_empty());
}

#[test]
fn restore_checks_a_put_signature_before_refusing_the_write() {
    assert_restore_checks_signature_then_refuses_write(put);
}

#[test]
fn restore_checks_a_create_multipart_signature_before_refusing_the_write() {
    assert_restore_checks_signature_then_refuses_write(create_multipart);
}

#[test]
fn delete_bucket_without_a_grant_returns_access_denied() {
    let w = World::new();
    let req = Signer::new(NO_GRANT_AKID, SECRET).sign(
        T0,
        Method::Delete,
        &format!("/{BUCKET}"),
        &[],
        &[],
        Vec::new(),
    );
    let (resp, _) = w.serve(req, Maintenance::Off);
    assert_s3_error(&resp, 403, "AccessDenied");
    let calls = w.calls();
    only_the_key_row_before_the_signature(&calls);
    assert!(calls.iter().all(|c| c.op.is_read()), "{calls:?}");
}

#[test]
fn a_publication_closed_on_the_unit_leaves_no_recovery_record() {
    let w = World::new();
    w.ports.close_on_publication.set(true);
    let (resp, lines) = w.serve(put(&signer()), Maintenance::Off);
    assert_eq!(resp.status, 503, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(lines, ["closed"]);
    let records = block_on(w.safety.list("m/", "", u32::MAX)).unwrap();
    assert!(
        records.is_empty(),
        "unpublished recovery records: {records:?}"
    );
}
