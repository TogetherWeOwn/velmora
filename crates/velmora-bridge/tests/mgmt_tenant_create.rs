//! `POST /v1/tenants` (`mgmt::tenant_create`, AM-58): create-or-adopt
//! through `m/tref/`, record 1, the birth token and `provision` on a real
//! root unit through the request router, the born marker, the tenant key
//! in both key buckets, and `live`, over the composition root with
//! in-memory stores; every step resumed by a retry.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use futures_util::StreamExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::config::Maintenance;
use velmora_bridge::crypto::scheme2::{tk_blob_name, wrap_tenant_key, TenantKey, TK_PREFIX};
use velmora_bridge::directory::gate;
use velmora_bridge::directory::record::{Lifecycle, Tenant};
use velmora_bridge::directory::store::SqlDirectory;
use velmora_bridge::keys::locations::{locations_chain, two_in_account, write_locations};
use velmora_bridge::keys::ports::{ControlChain, ControlIntents};
use velmora_bridge::keys::tk::{tk_prefix, KeyBuckets};
use velmora_bridge::mgmt::adapters::RoutedUnit;
use velmora_bridge::mgmt::serve::{serve_with, Answer, Either, MgmtRequest, NotBuilt};
use velmora_bridge::mgmt::tenant_create::{
    born_name, call_key_hash, put_tref, read_born, read_tref, tref_name, CreatePorts,
    TenantCreateHandler, LOCATION_HINT,
};
use velmora_bridge::mgmt::token::{DisabledTokens, TokenHashes};
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::root::{Root, RootCache, RootPorts};
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::types::Body;
use velmora_bridge::unit::{CallKind, Unit, UnitAnswer, UnitCall, UnitName, UnitOp, UnitReply};
use velmora_bridge::unit_lease::client::{Answered, Page};
use velmora_bridge::unit_router::{HeadCache, RequestClient, RequestClients, Routed, Router};
use velmora_bridge::{BridgeError, Result, TenantId, UnixMs};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const WS: &str = "ws_01JD2Q8V5X";
const STANDARD: &str = "std-token-0123456789abcdef0123456789abcdef";
const CONFIRMED: &str = "conf-token-0123456789abcdef0123456789abcdef";

fn hash(token: &str) -> String {
    Sha256::digest(token)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hashes() -> TokenHashes {
    let (standard, confirmed) = (hash(STANDARD), hash(CONFIRMED));
    TokenHashes::from_vars(|name| match name {
        "MGMT_TOKEN_SHA256_STANDARD" => Some(standard.clone()),
        "MGMT_TOKEN_SHA256_CONFIRMED" => Some(confirmed.clone()),
        _ => None,
    })
    .unwrap()
}

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(b"tenant create");
            h.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The root's ports
// ---------------------------------------------------------------------------

/// Records planted by another writer: (name, bytes).
type Planted = Vec<(String, Vec<u8>)>;

/// Puts counted across every store of a world, for a fault at the k-th.
#[derive(Default)]
struct Faults {
    puts: Cell<u64>,
    tref_reads: Cell<u64>,
    /// The put that fails: refused (nothing stored) or answer lost
    /// (stored, then an error).
    at: Cell<Option<(u64, bool)>>,
    /// Once a put under this prefix lands, these records land too (another
    /// writer between this put and the call's next read).
    plant_after: RefCell<Option<(String, Planted)>>,
}

/// An in-memory store that fails the world's k-th put.
struct Faulty {
    inner: MemRecords,
    faults: Rc<Faults>,
}

impl std::ops::Deref for Faulty {
    type Target = MemRecords;
    fn deref(&self) -> &MemRecords {
        &self.inner
    }
}

impl RecordStore for Faulty {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        let n = self.faults.puts.get() + 1;
        self.faults.puts.set(n);
        match self.faults.at.get() {
            Some((k, false)) if k == n => Err(BridgeError::Blob("fault: put refused".into())),
            Some((k, true)) if k == n => {
                let _ = self.inner.put_if_absent(name, bytes).await?;
                Err(BridgeError::Blob("fault: answer lost".into()))
            }
            _ => {
                let put = self.inner.put_if_absent(name, bytes).await?;
                let hook = {
                    let mut plant = self.faults.plant_after.borrow_mut();
                    match plant.as_ref() {
                        Some((prefix, _)) if name.starts_with(prefix.as_str()) => plant.take(),
                        _ => None,
                    }
                };
                if let Some((_, records)) = hook {
                    for (n, b) in records {
                        self.inner.plant(&n, b);
                    }
                }
                Ok(put)
            }
        }
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        if name.starts_with("m/tref/") {
            self.faults.tref_reads.set(self.faults.tref_reads.get() + 1);
        }
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
}

struct Ports {
    records: Faulty,
    keys_a: Faulty,
    keys_b: Faulty,
    kek: TestKek,
    clock: FixedClock,
    directory: Option<RusqliteSql>,
}

fn closed_directory() -> RusqliteSql {
    let sql = RusqliteSql::open_in_memory().unwrap();
    for migration in [
        include_str!("../../../workers/s3-bridge/migrations-directory/0001_directory.sql"),
        include_str!("../../../workers/s3-bridge/migrations-directory/0002_tenant_events.sql"),
        include_str!(
            "../../../workers/s3-bridge/migrations-directory/0003_pending_chains_and_caps.sql"
        ),
    ] {
        sql.apply(migration).unwrap();
    }
    sql
}

impl Ports {
    fn new(faults: &Rc<Faults>, directory: Option<RusqliteSql>) -> Ports {
        let store = || Faulty {
            inner: MemRecords::new(),
            faults: faults.clone(),
        };
        Ports {
            records: store(),
            keys_a: store(),
            keys_b: store(),
            kek: TestKek::new(),
            clock: FixedClock::new(NOW),
            directory,
        }
    }
}

impl RootPorts for Ports {
    type Records = Faulty;
    type KeyStore = Faulty;
    type Kek = TestKek;
    type Sql = RusqliteSql;
    type Clock = FixedClock;
    fn records(&self) -> &Faulty {
        &self.records
    }
    fn key_buckets(&self) -> KeyBuckets<'_, Faulty> {
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

fn tenant_record_name(tenant: &TenantId, seq: u64) -> String {
    format!("m/t/{}/{seq:020}", tenant.as_str())
}

#[derive(Debug, PartialEq, Eq)]
enum IntentKind {
    Send { record_exists: bool },
    Note { kind: String, record_exists: bool },
}

type IntentCall = (TenantId, ControlChain, u64, IntentKind);

#[derive(Default)]
struct IntentLog {
    calls: RefCell<Vec<IntentCall>>,
    fail_send_at: Cell<Option<u64>>,
    fail_note: Cell<bool>,
}

struct Intents<'a> {
    records: &'a Faulty,
    log: &'a IntentLog,
}

impl ControlIntents for Intents<'_> {
    async fn send(&self, tenant: &TenantId, chain: ControlChain, seq: u64) -> Result<()> {
        let record_exists = self.records.raw(&tenant_record_name(tenant, seq)).is_some();
        self.log.calls.borrow_mut().push((
            tenant.clone(),
            chain,
            seq,
            IntentKind::Send { record_exists },
        ));
        if self.log.fail_send_at.get() == Some(seq) {
            return Err(BridgeError::Sql("fault: intent not sent".into()));
        }
        Ok(())
    }

    async fn note(
        &self,
        tenant: &TenantId,
        chain: ControlChain,
        seq: u64,
        kind: &str,
    ) -> Result<()> {
        let record_exists = self.records.raw(&tenant_record_name(tenant, seq)).is_some();
        self.log.calls.borrow_mut().push((
            tenant.clone(),
            chain,
            seq,
            IntentKind::Note {
                kind: kind.to_owned(),
                record_exists,
            },
        ));
        if self.log.fail_note.get() {
            return Err(BridgeError::Sql("fault: intent not noted".into()));
        }
        Ok(())
    }

    async fn clear(&self, _: &TenantId, _: ControlChain, _: u64) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Units: one real unit per name, made on its first call
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Units {
    units: RefCell<HashMap<String, Rc<Unit<RusqliteSql>>>>,
    calls: RefCell<Vec<UnitCall>>,
    down: Cell<bool>,
    /// The jurisdiction of the units' namespace ("" for none).
    namespace: RefCell<String>,
}

impl Units {
    fn unit(&self, name: &UnitName) -> Rc<Unit<RusqliteSql>> {
        let key = format!("{}/{}", name.tenant.as_str(), name.unit);
        self.units
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| {
                Rc::new(Unit::new(
                    RusqliteSql::open_in_memory().unwrap(),
                    name.clone(),
                    &self.namespace.borrow(),
                ))
            })
            .clone()
    }

    fn born(&self, name: &UnitName) -> bool {
        let unit = self.unit(name);
        let a = unit.handle(
            &UnitCall {
                name: name.clone(),
                kind: CallKind::Worker,
                seqs: None,
                authenticated: true,
                listed: true,
                op: UnitOp::HeldKeys {},
            },
            NOW,
        );
        !matches!(a, UnitAnswer::Unborn { .. })
    }

    fn provisions(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|c| matches!(c.op, UnitOp::Provision { .. }))
            .count()
    }
}

#[derive(Clone, Copy)]
struct Direct<'a>(&'a Units);

impl RequestClient for Direct<'_> {
    async fn call(&self, call: UnitCall) -> (Result<Answered>, Vec<Page>) {
        if self.0.down.get() {
            return (
                Err(BridgeError::Sql("fake: unreachable".into())),
                Vec::new(),
            );
        }
        self.0.calls.borrow_mut().push(call.clone());
        let answer = self.0.unit(&call.name).handle(&call, NOW);
        (
            Ok(Answered {
                reply: UnitReply {
                    answer,
                    lease_left_ms: 1,
                    revoked: None,
                },
                refreshed: None,
                renew_due: false,
                renewal: None,
                synced: None,
            }),
            Vec::new(),
        )
    }
}

impl<'a> RequestClients for Direct<'a> {
    type Client = Direct<'a>;
    fn client(&self, _: &Routed) -> Result<Direct<'a>> {
        Ok(*self)
    }
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

struct World {
    faults: Rc<Faults>,
    ports: Ports,
    cache: RootCache,
    units: Units,
    intents: IntentLog,
    rng_seed: Cell<u64>,
}

impl World {
    fn new() -> World {
        Self::without_locations().with_locations()
    }

    /// An open gate, but no key locations have been recorded.
    fn without_locations() -> World {
        let w = Self::with_directory(Some(closed_directory()));
        futures_executor_block_on(w.open_gate());
        w.faults.puts.set(0);
        w
    }

    fn without_gate() -> World {
        Self::with_directory(Some(closed_directory())).with_locations()
    }

    fn without_directory() -> World {
        Self::with_directory(None).with_locations()
    }

    fn with_directory(directory: Option<RusqliteSql>) -> World {
        let faults = Rc::new(Faults::default());
        World {
            ports: Ports::new(&faults, directory),
            faults,
            cache: RootCache::new(),
            units: Units::default(),
            intents: IntentLog::default(),
            rng_seed: Cell::new(100),
        }
    }

    fn with_locations(self) -> Self {
        futures_executor_block_on(self.locations());
        self.faults.puts.set(0);
        self
    }

    fn directory(&self) -> SqlDirectory<'_, RusqliteSql> {
        SqlDirectory {
            sql: self.ports.directory().unwrap(),
        }
    }

    async fn close_gate(&self) -> u64 {
        gate::close(&self.ports.records, &self.directory(), "test_rebuild", NOW)
            .await
            .unwrap()
    }

    async fn open_gate(&self) {
        let epoch = self.close_gate().await;
        assert!(self.directory().open_gate(epoch, NOW).await.unwrap());
    }

    async fn locations(&self) {
        let done = write_locations(
            &self.ports.records,
            &self.ports.kek,
            &two_in_account(),
            &mut TestRng(1),
        )
        .await
        .unwrap();
        assert!(done);
    }

    async fn create(&self, body: &Value) -> Answer {
        self.create_with_key(body, WS).await
    }

    async fn create_with_key(&self, body: &Value, idempotency_key: &str) -> Answer {
        let root = Root::new(&self.ports, &self.cache, TestRng(9));
        let heads = root.heads();
        let clients = Direct(&self.units);
        let router = Router {
            maintenance: Maintenance::Off,
            clients: &clients,
            heads: &heads,
            cache: &HeadCache::default(),
            clock: &self.ports.clock,
        };
        let unit = RoutedUnit::new(&router);
        let intents = Intents {
            records: &self.ports.records,
            log: &self.intents,
        };
        let seed = self.rng_seed.get();
        self.rng_seed.set(seed + 1_000);
        let handlers = Either(
            TenantCreateHandler {
                ports: CreatePorts {
                    ports: &self.ports,
                    root: &root,
                    unit: &unit,
                    intents: &intents,
                },
                rng: RefCell::new(Some(TestRng(seed))),
            },
            NotBuilt,
        );
        let bytes = body.to_string().into_bytes();
        let body = Body::Stream {
            declared_len: Some(bytes.len() as u64),
            stream: futures_util::stream::iter(vec![Ok(bytes)]).boxed_local(),
        };
        let disabled = RefCell::new(DisabledTokens::default());
        let authorization = format!("Bearer {CONFIRMED}");
        let req = MgmtRequest {
            method: "POST",
            path: "/v1/tenants",
            query: "",
            authorization: Some(&authorization),
            acting: None,
            idempotency_key: Some(idempotency_key),
        };
        let a = serve_with(
            &disabled,
            &hashes(),
            &MemBlobStore::new(),
            &handlers,
            req,
            body,
            NOW,
        )
        .await;
        assert!(unit.take_pages().is_empty());
        a
    }

    async fn tenant_of(&self, external_ref: &str) -> Option<velmora_bridge::unit::TenantId> {
        read_tref(&self.ports.records, &self.ports.kek, external_ref)
            .await
            .unwrap()
    }

    fn chain_len(&self, t: &velmora_bridge::unit::TenantId) -> usize {
        self.ports
            .records
            .names_under(&format!("m/t/{}/", t.as_str()))
            .len()
    }
}

/// A small executor for the sync helpers (no I/O waits in these stores).
fn futures_executor_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn signup() -> Value {
    json!({"external_ref": WS})
}

fn json_of(a: &Answer) -> Value {
    serde_json::from_str(a.json.as_deref().expect("a JSON answer")).unwrap()
}

fn expect(a: &Answer, status: u16, code: &str) {
    assert_eq!((a.status, a.code), (status, code), "{a:?}");
}

fn assert_create_did_not_start(w: &World) {
    assert_eq!(w.faults.tref_reads.get(), 0, "no m/tref/ read");
    assert_eq!(w.faults.puts.get(), 0, "no put in any store");
    assert!(w.ports.records.names_under("m/tref/").is_empty());
    assert!(w.ports.records.names_under("m/t/").is_empty());
    assert!(w.intents.calls.borrow().is_empty());
    assert!(w.units.calls.borrow().is_empty());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn sign_up_creates_a_live_tenant_and_a_retry_adopts_it() {
    let w = World::new();
    futures_executor_block_on(async {
        let a = w.create(&signup()).await;
        expect(&a, 201, "ok");
        let t = json_of(&a);
        let id = t["id"].as_str().unwrap().to_string();
        assert!(id.starts_with("t_") && id.len() == 18, "{id}");
        assert_eq!(t["state"], "active");
        assert_eq!(t["access"], "full");
        assert_eq!(t["created_at_ms"], NOW.0);
        assert_eq!(t["suspension"], Value::Null);
        assert_eq!(t["deletion"], Value::Null);
        let _: velmora_mgmt_types::wire::Tenant = serde_json::from_value(t.clone()).unwrap();

        // m/tref/ names the tenant; the head is live, with the reference
        // in its private part and the root unit listed.
        let tenant = w.tenant_of(WS).await.unwrap();
        assert_eq!(tenant.as_str(), id);
        let root = Root::new(&w.ports, &w.cache, TestRng(3));
        let chain_t = velmora_bridge::TenantId::parse(&id).unwrap();
        let head = root.tenant_head(&chain_t).await.unwrap().unwrap();
        assert_eq!(head.door.lifecycle, Lifecycle::Live);
        assert_eq!(head.door.units, vec![0]);
        assert_eq!(head.door.jurisdiction, "none");
        assert_eq!(head.door.location_hint.as_deref(), Some(LOCATION_HINT));
        assert_eq!(head.door.tk_version, 1);
        assert_eq!(
            head.private.unwrap().external_ref.as_deref(),
            Some(WS),
            "the workspace is bound in the record sealed under the tenant key"
        );
        // Record 1, the claim, the commit, live.
        assert_eq!(w.chain_len(&tenant), 4);
        // The root unit is born from the birth token, and the marker holds
        // that token.
        let name = UnitName::new(tenant.clone(), 0);
        assert!(w.units.born(&name));
        assert_eq!(w.units.provisions(), 1);
        let token = read_born(&w.ports.records, &w.ports.kek, &tenant, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.record_seq, 1);
        assert_eq!(token.jurisdiction, "");
        assert_eq!(token.key_scheme, 2);
        // The key in both key buckets.
        for bucket in [&w.ports.keys_a, &w.ports.keys_b] {
            assert_eq!(bucket.names_under(&tk_prefix(&chain_t)).len(), 1);
        }

        // A retry adopts: 200, the same tenant, no record, no provision.
        let again = w.create(&signup()).await;
        expect(&again, 200, "ok");
        assert_eq!(json_of(&again), t);
        assert_eq!(w.chain_len(&tenant), 4);
        assert_eq!(w.units.provisions(), 1);

        // Another workspace is another tenant.
        let other = w.create(&json!({"external_ref": "ws_other"})).await;
        expect(&other, 201, "ok");
        assert_ne!(json_of(&other)["id"], t["id"]);
    });
}

#[test]
fn only_jurisdiction_none_is_served() {
    let w = World::without_gate();
    futures_executor_block_on(async {
        for j in ["eu", "us", "fedramp"] {
            let a = w
                .create(&json!({"external_ref": WS, "jurisdiction": j}))
                .await;
            expect(&a, 400, "jurisdiction_not_served");
        }
        assert_create_did_not_start(&w);
        w.open_gate().await;
        let a = w
            .create(&json!({"external_ref": WS, "jurisdiction": "none"}))
            .await;
        expect(&a, 201, "ok");
    });
}

#[test]
fn limits_are_refused_before_any_write() {
    let w = World::without_gate();
    futures_executor_block_on(async {
        let a = w
            .create(&json!({
                "external_ref": WS,
                "limits": {"storage_bytes": 5_000_000_000u64, "upload_24h_bytes": null,
                           "download_allowance_bytes": 7, "active_keys": 5}
            }))
            .await;
        expect(&a, 400, "limits_not_served");
        assert_create_did_not_start(&w);
    });
}

#[test]
fn rate_class_is_refused_before_any_write() {
    let w = World::without_gate();
    futures_executor_block_on(async {
        let a = w
            .create(&json!({"external_ref": WS, "rate_class": "free"}))
            .await;
        expect(&a, 400, "rate_class_not_served");
        assert_create_did_not_start(&w);
    });
}

#[test]
fn bad_bodies_are_refused_before_any_write() {
    let w = World::new();
    futures_executor_block_on(async {
        for body in [
            json!({}),
            json!({"external_ref": "has space"}),
            json!({"external_ref": WS, "role": "owner"}),
        ] {
            let a = w.create(&body).await;
            expect(&a, 400, "bad_request");
        }
        assert_create_did_not_start(&w);
    });
}

#[test]
fn missing_key_locations_stop_create_before_any_write() {
    let w = World::without_locations();
    futures_executor_block_on(async {
        let a = w.create(&signup()).await;
        expect(&a, 503, "service_unavailable");
        assert!(a.retry_after.is_some());
        assert_create_did_not_start(&w);

        w.locations().await;
        expect(&w.create(&signup()).await, 201, "ok");
        assert_one_live_tenant(&w).await;
        assert_eq!(w.units.provisions(), 1, "born once");
    });
}

#[test]
fn a_closed_gate_stops_create_until_it_opens() {
    let w = World::without_gate();
    futures_executor_block_on(async {
        expect(&w.create(&signup()).await, 503, "service_unavailable");
        assert_create_did_not_start(&w);

        w.open_gate().await;
        expect(&w.create(&signup()).await, 201, "ok");
        assert_one_live_tenant(&w).await;
    });
}

#[test]
fn an_unbound_directory_stops_create_before_any_write() {
    let w = World::without_directory();
    futures_executor_block_on(async {
        expect(&w.create(&signup()).await, 503, "service_unavailable");
        assert_create_did_not_start(&w);
    });
}

#[test]
fn closing_the_gate_again_blocks_even_a_retry_of_a_live_tenant() {
    let w = World::new();
    futures_executor_block_on(async {
        expect(&w.create(&signup()).await, 201, "ok");
        let tenant = assert_one_live_tenant(&w).await;
        w.close_gate().await;
        let puts = w.faults.puts.get();
        let tref_reads = w.faults.tref_reads.get();
        let intents = w.intents.calls.borrow().len();
        let unit_calls = w.units.calls.borrow().len();

        expect(&w.create(&signup()).await, 503, "service_unavailable");
        assert_eq!(w.faults.puts.get(), puts);
        assert_eq!(w.faults.tref_reads.get(), tref_reads);
        assert_eq!(w.intents.calls.borrow().len(), intents);
        assert_eq!(w.units.calls.borrow().len(), unit_calls);
        assert_eq!(w.chain_len(&tenant), 4);
    });
}

fn assert_intents_before_records(w: &World, t: &TenantId, head: u64) {
    let expected: Vec<_> = (1..=head)
        .flat_map(|seq| {
            [
                IntentKind::Send {
                    record_exists: false,
                },
                IntentKind::Note {
                    kind: "tenant.create".to_owned(),
                    record_exists: false,
                },
            ]
            .map(|kind| (t.clone(), ControlChain::Tenant, seq, kind))
        })
        .collect();
    assert_eq!(*w.intents.calls.borrow(), expected);
}

#[test]
fn each_tenant_record_has_a_send_and_note_before_it_is_written() {
    let w = World::new();
    futures_executor_block_on(async {
        expect(&w.create(&signup()).await, 201, "ok");
        let tenant = assert_one_live_tenant(&w).await;
        let t = TenantId::parse(tenant.as_str()).unwrap();
        let root = Root::new(&w.ports, &w.cache, TestRng(3));
        let head = root
            .heads()
            .head_seq(&Tenant::Managed(t.clone()), 0)
            .await
            .unwrap()
            .unwrap();
        assert_intents_before_records(&w, &t, head);
    });
}

#[test]
fn a_failed_intent_send_stops_the_record_and_a_retry_finishes() {
    let clean = World::new();
    let clean_len = futures_executor_block_on(async {
        expect(&clean.create(&signup()).await, 201, "ok");
        let clean_tenant = assert_one_live_tenant(&clean).await;
        clean.chain_len(&clean_tenant)
    });

    for seq in 1..=clean_len as u64 {
        let w = World::new();
        w.intents.fail_send_at.set(Some(seq));
        futures_executor_block_on(async {
            let first = w.create(&signup()).await;
            assert_eq!(
                (first.status, first.code),
                (503, "service_unavailable"),
                "failed send for seq {seq}"
            );
            let tenant = w.tenant_of(WS).await.unwrap();
            let t = TenantId::parse(tenant.as_str()).unwrap();
            assert_eq!(w.chain_len(&tenant) as u64, seq - 1);
            assert!(w.ports.records.raw(&tenant_record_name(&t, seq)).is_none());
            // No note or later intent follows the failed send.
            assert_eq!(
                w.intents.calls.borrow_mut().pop(),
                Some((
                    t.clone(),
                    ControlChain::Tenant,
                    seq,
                    IntentKind::Send {
                        record_exists: false,
                    },
                )),
            );
            assert_intents_before_records(&w, &t, seq - 1);

            w.intents.fail_send_at.set(None);
            // The reference was written before any of these intents, so the retry adopts.
            expect(&w.create(&signup()).await, 200, "ok");
            assert_eq!(assert_one_live_tenant(&w).await, tenant);
            assert_eq!(w.chain_len(&tenant), clean_len);
            assert_intents_before_records(&w, &t, clean_len as u64);
        });
    }
}

#[test]
fn a_failed_intent_note_does_not_stop_create() {
    let w = World::new();
    w.intents.fail_note.set(true);
    futures_executor_block_on(async {
        expect(&w.create(&signup()).await, 201, "ok");
        let tenant = assert_one_live_tenant(&w).await;
        let t = TenantId::parse(tenant.as_str()).unwrap();
        assert_intents_before_records(&w, &t, w.chain_len(&tenant) as u64);
    });
}

#[test]
fn every_tenant_record_has_the_idempotency_key_hash() {
    let w = World::new();
    futures_executor_block_on(async {
        // A distinct external reference catches hashing the body field instead of the header.
        let external_ref = "ws_other";
        expect(
            &w.create(&json!({"external_ref": external_ref})).await,
            201,
            "ok",
        );
        let tenant = w.tenant_of(external_ref).await.unwrap();
        let t = Tenant::parse(tenant.as_str()).unwrap();
        let root = Root::new(&w.ports, &w.cache, TestRng(3));
        let heads = root.heads();
        let head = heads.head_seq(&t, 0).await.unwrap().unwrap();
        assert_eq!(head, 4);
        let expected = call_key_hash(WS);
        assert_eq!(expected, hash(WS), "lowercase hex SHA-256");
        for seq in 1..=head {
            let door = heads.read(&t, seq).await.unwrap().unwrap().door;
            assert_eq!(
                door.call_key_hash.as_deref(),
                Some(expected.as_str()),
                "seq {seq}"
            );
        }
    });
}

#[test]
fn a_key_claim_voided_on_retry_also_has_an_intent_and_the_retry_hash() {
    let w = World::new();
    futures_executor_block_on(async {
        // Leave a claim and its arbiter copy, but no commit.
        w.ports.keys_b.refuse(TK_PREFIX);
        expect(&w.create(&signup()).await, 503, "service_unavailable");
        w.ports.keys_b.allow(TK_PREFIX);
        let tenant = w.tenant_of(WS).await.unwrap();
        assert_eq!(w.chain_len(&tenant), 2);
        let id = TenantId::parse(tenant.as_str()).unwrap();
        let name = tk_blob_name(&id, 1, 1);
        let arbiter_copy = w.ports.keys_a.raw(&name).unwrap();
        let other_key =
            TenantKey::from_bytes(&id, 1, Sha256::digest(b"other test key").into()).unwrap();
        let (_, other_copy) = wrap_tenant_key(&w.ports.kek, &other_key, &mut TestRng(8)).unwrap();
        assert_ne!(arbiter_copy, other_copy);
        w.ports.keys_b.plant(&name, other_copy);

        let retry_key = "ws_retry";
        expect(&w.create_with_key(&signup(), retry_key).await, 200, "ok");
        let t = Tenant::Managed(id.clone());
        let root = Root::new(&w.ports, &w.cache, TestRng(3));
        let heads = root.heads();
        let void = heads.read(&t, 3).await.unwrap().unwrap().door;
        assert_eq!(void.tk_version, 0, "v1 was not committed");
        assert_eq!(void.rotating_to, Some(2), "voiding v1 opens v2");
        let head = heads.head(&t, 0).await.unwrap().unwrap().door;
        assert_eq!(head.seq, 5);
        assert_eq!(head.tk_version, 2);
        assert_eq!(head.lifecycle, Lifecycle::Live);
        assert_intents_before_records(&w, &id, head.seq);
        for seq in 1..=head.seq {
            let expected = call_key_hash(if seq < 3 { WS } else { retry_key });
            let door = heads.read(&t, seq).await.unwrap().unwrap().door;
            assert_eq!(
                door.call_key_hash.as_deref(),
                Some(expected.as_str()),
                "seq {seq}"
            );
        }
    });
}

#[test]
fn record_one_and_the_provision_token_use_their_own_jurisdiction_forms() {
    let w = World::new();
    futures_executor_block_on(async {
        expect(&w.create(&signup()).await, 201, "ok");
        let tenant = w.tenant_of(WS).await.unwrap();
        let t = Tenant::parse(tenant.as_str()).unwrap();
        let root = Root::new(&w.ports, &w.cache, TestRng(3));
        let door = root.heads().read(&t, 1).await.unwrap().unwrap().door;
        assert_eq!(door.jurisdiction, "none");
        assert!(door.limits.is_empty());
        assert!(door.rate_json.is_empty());

        let calls = w.units.calls.borrow();
        let token = calls
            .iter()
            .find_map(|call| match &call.op {
                UnitOp::Provision { token, .. } => Some(token),
                _ => None,
            })
            .expect("a Provision call");
        assert_eq!(token.name, UnitName::new(tenant, 0));
        assert_eq!(token.record_seq, 1);
        assert_eq!(token.jurisdiction, "");
    });
}

#[test]
fn a_lost_marker_put_is_finished_by_the_retry() {
    let w = World::new();
    futures_executor_block_on(async {
        w.ports.records.refuse("m/ub/");
        let a = w.create(&signup()).await;
        expect(&a, 503, "service_unavailable");
        let tenant = w.tenant_of(WS).await.unwrap();
        assert!(w.units.born(&UnitName::new(tenant.clone(), 0)));
        assert!(w.ports.records.raw(&born_name(&tenant, 0)).is_none());
        assert_eq!(w.chain_len(&tenant), 1, "no key before the marker");
        w.ports.records.allow("m/ub/");
        // The unit answers `already_born`; the marker is written, and the
        // create goes on.
        let again = w.create(&signup()).await;
        // A retry adopts through `m/tref/` and finishes the create: `200`.
        expect(&again, 200, "ok");
        assert_eq!(w.units.provisions(), 2);
        assert!(w.ports.records.raw(&born_name(&tenant, 0)).is_some());
    });
}

#[test]
fn an_unreachable_root_unit_stops_after_record_1() {
    let w = World::new();
    futures_executor_block_on(async {
        w.units.down.set(true);
        let a = w.create(&signup()).await;
        expect(&a, 503, "service_unavailable");
        let tenant = w.tenant_of(WS).await.unwrap();
        assert_eq!(w.chain_len(&tenant), 1);
        assert!(w.ports.records.raw(&born_name(&tenant, 0)).is_none());
        w.units.down.set(false);
        let again = w.create(&signup()).await;
        // A retry adopts through `m/tref/` and finishes the create: `200`.
        expect(&again, 200, "ok");
        assert_eq!(json_of(&again)["id"], tenant.as_str());
    });
}

#[test]
fn a_unit_that_is_not_born_after_record_1_is_never_born_with_a_birth_token() {
    let w = World::new();
    futures_executor_block_on(async {
        w.units.down.set(true);
        let _ = w.create(&signup()).await;
        let tenant = w.tenant_of(WS).await.unwrap();
        // Something moved the head past record 1 (a claim), with the unit
        // still unborn: rule 6 forbids the birth token now.
        let root = Root::new(&w.ports, &w.cache, TestRng(4));
        root.chain()
            .write(
                &Tenant::parse(tenant.as_str()).unwrap(),
                &velmora_bridge::directory::transition::Change::ClaimKeyVersion { version: 1 },
                velmora_bridge::directory::transition::Actor::TenantCreation,
                NOW,
                0,
            )
            .await
            .unwrap();
        w.units.down.set(false);
        let a = w.create(&signup()).await;
        expect(&a, 503, "service_unavailable");
        assert_eq!(w.units.provisions(), 0);
        assert!(!w.units.born(&UnitName::new(tenant.clone(), 0)));
        assert!(w.ports.records.raw(&born_name(&tenant, 0)).is_none());
    });
}

#[test]
fn a_tref_record_that_does_not_verify_is_never_adopted() {
    let w = World::new();
    let w2 = World::new();
    futures_executor_block_on(async {
        // Another reference's record planted under this name.
        let a = w.create(&json!({"external_ref": "ws_other"})).await;
        expect(&a, 201, "ok");
        let theirs = w.ports.records.raw(&tref_name("ws_other")).unwrap();
        w.ports.records.plant(&tref_name(WS), theirs);
        // A record that does not verify: 500 (pages), never adopted.
        let b = w.create(&signup()).await;
        expect(&b, 500, "internal_error");
        // A flipped byte.
        let _ = w2.create(&signup()).await;
        let mut bytes = w2.ports.records.raw(&tref_name(WS)).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        w2.ports.records.lose(&tref_name(WS));
        w2.ports.records.plant(&tref_name(WS), bytes);
        expect(&w2.create(&signup()).await, 500, "internal_error");
    });
}

#[test]
fn the_records_carry_no_secret_and_the_marker_is_control_sealed() {
    let w = World::new();
    futures_executor_block_on(async {
        let _ = w.create(&signup()).await;
        let tenant = w.tenant_of(WS).await.unwrap();
        // The tref record and the marker are door-only control records:
        // the workspace id appears in neither in clear.
        for name in [tref_name(WS), born_name(&tenant, 0)] {
            let bytes = w.ports.records.raw(&name).unwrap();
            assert!(bytes.starts_with(b"VCR1"), "{name}");
            assert!(
                !bytes.windows(WS.len()).any(|win| win == WS.as_bytes()),
                "{name}"
            );
        }
        // A marker read under another name does not verify.
        let other = velmora_bridge::unit::TenantId::parse("t_00000000000000ee").unwrap();
        let bytes = w.ports.records.raw(&born_name(&tenant, 0)).unwrap();
        assert!(w
            .ports
            .records
            .put_if_absent(&born_name(&other, 0), bytes)
            .await
            .unwrap());
        assert!(read_born(&w.ports.records, &w.ports.kek, &other, 0)
            .await
            .is_err());
    });
}

/// The end state every create must reach for `WS`: one tenant, four
/// records, the unit born once (from the marker's token), one key blob in
/// each key bucket, the head live with the reference.
async fn assert_one_live_tenant(w: &World) -> velmora_bridge::unit::TenantId {
    let tenant = w.tenant_of(WS).await.unwrap();
    assert_eq!(w.ports.records.names_under("m/tref/").len(), 1);
    assert_eq!(w.chain_len(&tenant), 4, "record 1, claim, commit, live");
    assert!(w.units.born(&UnitName::new(tenant.clone(), 0)));
    assert!(w.ports.records.raw(&born_name(&tenant, 0)).is_some());
    let chain_t = velmora_bridge::TenantId::parse(tenant.as_str()).unwrap();
    for bucket in [&w.ports.keys_a, &w.ports.keys_b] {
        assert_eq!(bucket.names_under(&tk_prefix(&chain_t)).len(), 1);
    }
    let root = Root::new(&w.ports, &w.cache, TestRng(5));
    let head = root.tenant_head(&chain_t).await.unwrap().unwrap();
    assert_eq!(head.door.lifecycle, Lifecycle::Live);
    assert_eq!(head.private.unwrap().external_ref.as_deref(), Some(WS));
    tenant
}

/// A crash at any put (refused, or stored with its answer lost) is
/// finished by retries, with one tenant, one key version and one birth.
#[test]
fn a_fault_at_any_put_is_finished_by_a_retry() {
    // The puts of a clean create.
    let clean = World::new();
    let base = clean.faults.puts.get();
    futures_executor_block_on(async {
        expect(&clean.create(&signup()).await, 201, "ok");
    });
    let total = clean.faults.puts.get() - base;
    assert!(total >= 7, "{total}");
    for k in 1..=total {
        for lose in [false, true] {
            let w = World::new();
            let at = w.faults.puts.get() + k;
            w.faults.at.set(Some((at, lose)));
            futures_executor_block_on(async {
                let first = w.create(&signup()).await;
                assert!(w.faults.puts.get() >= at, "the fault at put {k} fired");
                w.faults.at.set(None);
                let mut last = first.clone();
                for _ in 0..3 {
                    if (200..300).contains(&last.status) {
                        break;
                    }
                    assert_eq!(last.status, 503, "put {k} lose {lose}: {last:?}");
                    last = w.create(&signup()).await;
                }
                assert!(
                    (200..300).contains(&last.status),
                    "put {k} lose {lose}: {last:?}"
                );
                assert_one_live_tenant(&w).await;
                assert!(w.units.provisions() <= 2, "put {k} lose {lose}");
            });
        }
    }
}

/// Two creates of one workspace, the second after the first's `m/tref/`:
/// the second adopts and finishes; the first's retry answers it.
#[test]
fn a_second_create_adopts_and_finishes_the_first() {
    let w = World::new();
    futures_executor_block_on(async {
        // The first stops right after naming the tenant.
        w.ports.records.refuse("m/t/");
        expect(&w.create(&signup()).await, 503, "service_unavailable");
        w.ports.records.allow("m/t/");
        let second = w.create(&signup()).await;
        expect(&second, 200, "ok");
        let first_retry = w.create(&signup()).await;
        expect(&first_retry, 200, "ok");
        assert_eq!(json_of(&first_retry), json_of(&second));
        assert_one_live_tenant(&w).await;
        assert_eq!(w.units.provisions(), 1);
    });
}

#[test]
fn a_deleting_tenant_is_adopted_and_a_shredding_one_is_retired() {
    use velmora_bridge::directory::record::DeletionReason;
    use velmora_bridge::directory::transition::{Actor, Change};
    let w = World::new();
    futures_executor_block_on(async {
        expect(&w.create(&signup()).await, 201, "ok");
        let tenant = w.tenant_of(WS).await.unwrap();
        let t = Tenant::parse(tenant.as_str()).unwrap();
        let chain_t = velmora_bridge::TenantId::parse(tenant.as_str()).unwrap();
        let root = Root::new(&w.ports, &w.cache, TestRng(6));
        root.tenant_head(&chain_t).await.unwrap();
        let due = UnixMs(NOW.0 + 60 * 24 * 3_600_000);
        root.chain()
            .write(
                &t,
                &Change::SetDeletion {
                    shred_due_at: due,
                    reason: DeletionReason::CustomerRequest,
                    key_hash: "ab".repeat(32),
                },
                Actor::Customer,
                NOW,
                0,
            )
            .await
            .unwrap();
        let a = w.create(&signup()).await;
        expect(&a, 200, "ok");
        assert_eq!(json_of(&a)["state"], "deleting");
        root.chain()
            .write(
                &t,
                &Change::StartShred,
                Actor::ShredJob,
                UnixMs(due.0 + 1),
                0,
            )
            .await
            .unwrap();
        expect(&w.create(&signup()).await, 409, "external_ref_retired");
    });
}

/// A drawn id that already has a chain is never named for another
/// workspace.
#[test]
fn a_drawn_id_with_a_chain_is_refused() {
    let w = World::new();
    futures_executor_block_on(async {
        expect(
            &w.create(&json!({"external_ref": "ws_first"})).await,
            201,
            "ok",
        );
    });
    // The same random seed again: the same id is drawn.
    w.rng_seed.set(100);
    futures_executor_block_on(async {
        let a = w.create(&signup()).await;
        expect(&a, 500, "internal_error");
        assert!(w.tenant_of(WS).await.is_none(), "nothing named");
    });
}

/// A birth token the unit refuses (here: another jurisdiction in its
/// namespace) stops with 500; no retry changes it.
#[test]
fn a_refused_birth_token_is_a_500() {
    let w = World::new();
    *w.units.namespace.borrow_mut() = "eu".to_string();
    futures_executor_block_on(async {
        expect(&w.create(&signup()).await, 500, "internal_error");
        let tenant = w.tenant_of(WS).await.unwrap();
        assert!(w.ports.records.raw(&born_name(&tenant, 0)).is_none());
        assert_eq!(w.chain_len(&tenant), 1);
    });
}

/// Another create of the same workspace writes record 1 between this
/// call's `m/tref/` put and its head read: this call goes on with it
/// (never a 500), and both end on one tenant.
#[test]
fn a_create_racing_between_the_tref_put_and_the_head_read_goes_on() {
    // Record 1 of the tenant the seed draws, from a world that stops
    // right after it.
    let other = World::new();
    futures_executor_block_on(async {
        other.ports.records.refuse("m/ub/");
        expect(&other.create(&signup()).await, 503, "service_unavailable");
    });
    let tenant = futures_executor_block_on(other.tenant_of(WS)).unwrap();
    let record_1: Vec<(String, Vec<u8>)> = other
        .ports
        .records
        .names_under(&format!("m/t/{}/", tenant.as_str()))
        .into_iter()
        .map(|n| {
            let b = other.ports.records.raw(&n).unwrap();
            (n, b)
        })
        .collect();
    assert_eq!(record_1.len(), 1);
    let w = World::new();
    *w.faults.plant_after.borrow_mut() = Some(("m/tref/".to_string(), record_1));
    futures_executor_block_on(async {
        let a = w.create(&signup()).await;
        expect(&a, 201, "ok");
        assert_eq!(json_of(&a)["id"], tenant.as_str());
        assert!(w.faults.plant_after.borrow().is_none(), "the race ran");
        assert_one_live_tenant(&w).await;
    });
}

thread_local! {
    static ALERTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn capture(line: &str) {
    ALERTS.with(|a| a.borrow_mut().push(line.to_string()));
}

/// A born marker that does not verify stops a resumed create with 500
/// and an alert of fixed words.
#[test]
fn a_damaged_born_marker_is_a_500_with_an_alert() {
    velmora_bridge::trace::log_alerts(capture);
    let w = World::new();
    futures_executor_block_on(async {
        // Stop after writing the marker, before the tenant becomes live.
        w.ports.keys_a.refuse(TK_PREFIX);
        expect(&w.create(&signup()).await, 503, "service_unavailable");
        w.ports.keys_a.allow(TK_PREFIX);
        let tenant = w.tenant_of(WS).await.unwrap();
        let name = born_name(&tenant, 0);
        let mut bytes = w.ports.records.raw(&name).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        w.ports.records.lose(&name);
        w.ports.records.plant(&name, bytes);
        ALERTS.with(|a| a.borrow_mut().clear());
        expect(&w.create(&signup()).await, 500, "internal_error");
        let alerts = ALERTS.with(|a| a.borrow().clone());
        assert_eq!(
            alerts,
            vec!["mgmt: tenant create stopped: born marker does not verify".to_string()]
        );
        assert!(alerts
            .iter()
            .all(|l| !l.contains(tenant.as_str()) && !l.contains(WS)));
    });
}

fn newer_kek() -> TestKek {
    TestKek::with_versions(
        2,
        &[
            (1, Sha256::digest(b"kek one").into()),
            (2, Sha256::digest(b"kek two").into()),
        ],
    )
}

#[test]
fn key_locations_under_a_newer_kek_stop_create_without_alerting() {
    velmora_bridge::trace::log_alerts(capture);
    let w = World::without_locations();
    futures_executor_block_on(async {
        let mem = MemRecords::new();
        assert!(
            write_locations(&mem, &newer_kek(), &two_in_account(), &mut TestRng(1))
                .await
                .unwrap()
        );
        let name = locations_chain().name(1);
        w.ports.records.plant(&name, mem.raw(&name).unwrap());

        ALERTS.with(|a| a.borrow_mut().clear());
        expect(&w.create(&signup()).await, 503, "service_unavailable");
        assert_create_did_not_start(&w);
        ALERTS.with(|a| assert!(a.borrow().is_empty(), "{:?}", a.borrow()));
    });
}

#[test]
fn damaged_key_locations_stop_create_and_alert() {
    velmora_bridge::trace::log_alerts(capture);
    let w = World::new();
    futures_executor_block_on(async {
        w.ports
            .records
            .plant(&locations_chain().name(1), b"not a control record".to_vec());

        ALERTS.with(|a| a.borrow_mut().clear());
        expect(&w.create(&signup()).await, 503, "service_unavailable");
        assert_create_did_not_start(&w);
        ALERTS.with(|a| {
            assert_eq!(
                *a.borrow(),
                ["mgmt: tenant create: key locations unreadable"]
            );
        });
    });
}

/// An `m/tref/` record under a KEK version this Worker does not hold yet
/// (a newer deploy's record) is a failure that may pass: 503, never 500.
#[test]
fn a_tref_record_under_a_newer_kek_is_a_503() {
    let newer = newer_kek();
    let w = World::new();
    futures_executor_block_on(async {
        let other = velmora_bridge::unit::TenantId::parse("t_00000000000000ee").unwrap();
        let mem = MemRecords::new();
        assert!(put_tref(&mem, &newer, WS, &other, &mut TestRng(8))
            .await
            .unwrap());
        w.ports
            .records
            .plant(&tref_name(WS), mem.raw(&tref_name(WS)).unwrap());
        expect(&w.create(&signup()).await, 503, "service_unavailable");
    });
}
