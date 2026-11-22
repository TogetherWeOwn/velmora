//! Native route tests for the two operator setup calls (AM-70, AM-78).

mod service_support;

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::ops::Deref;
use std::pin::pin;
use std::task::{Context, Waker};

use futures_util::stream;
use serde_json::{json, Value};
use velmora::rng::SystemRng;
use velmora_bridge::config::Maintenance;
use velmora_bridge::directory::gate::{anchored_epoch, close, is_open, GATE_ANCHOR_PREFIX};
use velmora_bridge::directory::record::Tenant;
use velmora_bridge::directory::store::{ChainKind, PendingOp, SqlDirectory};
use velmora_bridge::keys::locations::{
    locations_chain, read_locations, two_in_account, write_locations,
};
use velmora_bridge::keys::tk::KeyBuckets;
use velmora_bridge::mgmt::setup::{serve_setup, setup_call, SetupCall};
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::root::{Root, RootCache, RootPorts};
use velmora_bridge::testkit::{FixedClock, RusqliteSql, TestKek};
use velmora_bridge::{Body, BridgeConfig, Method, RespBody, S3Request, S3Response, Secret, UnixMs};

const KEY_PATH: &str = "/_admin/setup/key-locations";
const GATE_PATH: &str = "/_admin/setup/directory-gate";
const ADMIN_HOST: &str = "admin.example.test";
const ADMIN: &str = "admin-token-fixture-admin-token-fixture";
const READ: &str = "read-token-fixture-read-token-fixture";
const NOW: UnixMs = UnixMs(1_800_000_000_000);

// Pause after the first anchor is durable, before that caller can update SQL.
#[derive(Default)]
struct SetupRecords {
    inner: MemRecords,
    pause_after_anchor: Cell<bool>,
}

impl Deref for SetupRecords {
    type Target = MemRecords;

    fn deref(&self) -> &MemRecords {
        &self.inner
    }
}

impl RecordStore for SetupRecords {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> velmora_bridge::Result<bool> {
        let stored = self.inner.put_if_absent(name, bytes).await?;
        if stored && name.starts_with(GATE_ANCHOR_PREFIX) && self.pause_after_anchor.replace(false)
        {
            tokio::task::yield_now().await;
        }
        Ok(stored)
    }

    async fn get(&self, name: &str) -> velmora_bridge::Result<Option<Vec<u8>>> {
        self.inner.get(name).await
    }

    async fn list(
        &self,
        prefix: &str,
        start_after: &str,
        limit: u32,
    ) -> velmora_bridge::Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
}

struct Ports {
    cache: RootCache,
    records: SetupRecords,
    keys_a: MemRecords,
    keys_b: MemRecords,
    bind_keys_b: bool,
    maintenance: Maintenance,
    kek: TestKek,
    clock: FixedClock,
    sql: Option<RusqliteSql>,
}

impl Ports {
    fn new() -> Self {
        Self {
            cache: RootCache::new(),
            records: SetupRecords::default(),
            keys_a: MemRecords::new(),
            keys_b: MemRecords::new(),
            bind_keys_b: true,
            maintenance: Maintenance::Off,
            kek: TestKek::new(),
            clock: FixedClock::new(NOW),
            sql: None,
        }
    }

    fn with_closed_directory() -> Self {
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
        Self {
            sql: Some(sql),
            ..Self::new()
        }
    }

    fn dir(&self) -> SqlDirectory<'_, RusqliteSql> {
        SqlDirectory {
            sql: self.sql.as_ref().unwrap(),
        }
    }

    async fn serve(&self, req: S3Request) -> S3Response {
        let call = setup_call(&req.raw_target).expect("setup route");
        let root = Root::new(self, &self.cache, SystemRng);
        let cfg = config(self.maintenance);
        serve_setup(call, &req, &cfg, self, &root, &mut SystemRng).await
    }

    async fn post(&self, path: &str) -> S3Response {
        self.serve(request(
            Method::Post,
            path,
            ADMIN_HOST,
            Some(ADMIN),
            Body::Empty,
        ))
        .await
    }

    fn assert_writes(&self, record_puts: u64, record_names: &[&str]) {
        assert_eq!(self.records.puts(), record_puts);
        assert_eq!(self.records.names(), record_names);
        self.assert_key_buckets_untouched();
    }

    fn assert_key_buckets_untouched(&self) {
        for store in [&self.keys_a, &self.keys_b] {
            assert_eq!(store.puts(), 0);
            assert!(store.names().is_empty());
        }
    }
}

impl RootPorts for Ports {
    type Records = SetupRecords;
    type KeyStore = MemRecords;
    type Kek = TestKek;
    type Sql = RusqliteSql;
    type Clock = FixedClock;

    fn records(&self) -> &SetupRecords {
        &self.records
    }

    fn key_buckets(&self) -> KeyBuckets<'_, MemRecords> {
        let mut by_name = vec![("KEYS_A", &self.keys_a)];
        if self.bind_keys_b {
            by_name.push(("KEYS_B", &self.keys_b));
        }
        KeyBuckets { by_name }
    }

    fn kek(&self) -> &TestKek {
        &self.kek
    }

    fn directory(&self) -> Option<&RusqliteSql> {
        self.sql.as_ref()
    }

    fn clock(&self) -> &FixedClock {
        &self.clock
    }
}

fn config(maintenance: Maintenance) -> BridgeConfig {
    BridgeConfig {
        maintenance,
        admin_token: Secret::new(ADMIN.to_string()),
        admin_read_token: Some(Secret::new(READ.to_string())),
        admin_host: Some(ADMIN_HOST.to_string()),
        ..service_support::config(Vec::new())
    }
}

fn request(method: Method, target: &str, host: &str, token: Option<&str>, body: Body) -> S3Request {
    let mut headers = vec![("host".to_string(), host.to_string())];
    if let Some(token) = token {
        headers.push(("authorization".to_string(), format!("Bearer {token}")));
    }
    S3Request {
        method,
        raw_target: target.to_string(),
        headers,
        body,
    }
}

fn response_header<'a>(resp: &'a S3Response, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn response_bytes(resp: &S3Response) -> &[u8] {
    let RespBody::Bytes(bytes) = &resp.body else {
        panic!("expected a byte response")
    };
    bytes
}

fn assert_no_store(resp: &S3Response) {
    assert_eq!(response_header(resp, "cache-control"), Some("no-store"));
}

fn json_response(resp: &S3Response, status: u16) -> Value {
    assert_no_store(resp);
    assert_eq!(
        response_header(resp, "content-type"),
        Some("application/json")
    );
    let body: Value = serde_json::from_slice(response_bytes(resp)).expect("JSON response");
    assert_eq!(resp.status, status, "response: {body}");
    body
}

fn expect_error(resp: &S3Response, status: u16, code: &str) {
    assert_eq!(json_response(resp, status)["error"], code);
}

thread_local! {
    static ALERTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn capture(line: &str) {
    ALERTS.with(|alerts| alerts.borrow_mut().push(line.to_string()));
}

fn take_alerts() -> Vec<String> {
    ALERTS.with(|alerts| alerts.take())
}

fn watch_alerts() {
    take_alerts();
    velmora_bridge::trace::log_alerts(capture);
}

#[test]
fn setup_call_maps_only_the_two_setup_paths() {
    for (path, call) in [
        (KEY_PATH, SetupCall::KeyLocations),
        (GATE_PATH, SetupCall::GateFirstOpen),
    ] {
        assert_eq!(setup_call(path), Some(call), "{path}");
        assert_eq!(setup_call(&format!("{path}?x=1")), Some(call), "{path}");
    }
    for path in [
        "/_admin/setup",
        "/_admin/setup/key-locations/x",
        "/_admin/status",
    ] {
        assert_eq!(setup_call(path), None, "{path}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn auth_refusals_write_nothing_on_either_route() {
    let ports = Ports::with_closed_directory();
    let gate = ports.dir().gate().await.unwrap();
    for path in [KEY_PATH, GATE_PATH] {
        for (host, token, status, code) in [
            (ADMIN_HOST, None, 401, "Unauthorized"),
            (ADMIN_HOST, Some(READ), 403, "AccessDenied"),
            ("other.example.test", Some(ADMIN), 404, "NotFound"),
        ] {
            let resp = ports
                .serve(request(Method::Post, path, host, token, Body::Empty))
                .await;
            assert_no_store(&resp);
            assert_eq!(resp.status, status, "{path}: expected {code}");
            // The shared admin check returns S3 XML rather than setup JSON.
            assert!(std::str::from_utf8(response_bytes(&resp))
                .unwrap()
                .contains(&format!("<Code>{code}</Code>")));
            ports.assert_writes(0, &[]);
            assert_eq!(ports.dir().gate().await.unwrap(), gate);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn method_query_and_body_refusals_write_nothing_on_either_route() {
    let ports = Ports::with_closed_directory();
    let gate = ports.dir().gate().await.unwrap();
    for path in [KEY_PATH, GATE_PATH] {
        let query = format!("{path}?x=1");
        for (method, target, body, status, code) in [
            (Method::Get, path, Body::Empty, 405, "MethodNotAllowed"),
            (Method::Post, query.as_str(), Body::Empty, 400, "BadRequest"),
            (
                Method::Post,
                path,
                Body::Stream {
                    declared_len: Some(3),
                    stream: Box::pin(stream::iter([Ok(b"abc".to_vec())])),
                },
                400,
                "BadRequest",
            ),
            (
                Method::Post,
                path,
                Body::Stream {
                    declared_len: None,
                    stream: Box::pin(stream::empty()),
                },
                400,
                "BadRequest",
            ),
        ] {
            let resp = ports
                .serve(request(method, target, ADMIN_HOST, Some(ADMIN), body))
                .await;
            expect_error(&resp, status, code);
            ports.assert_writes(0, &[]);
            assert_eq!(ports.dir().gate().await.unwrap(), gate);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn restore_refuses_both_setup_routes_without_writing() {
    let ports = Ports {
        maintenance: Maintenance::Restore,
        ..Ports::with_closed_directory()
    };
    let sql = ports.directory().unwrap();
    let store_activity = || (ports.records.lists(), sql.read_stats(), sql.write_steps());
    let before = store_activity();
    for path in [KEY_PATH, GATE_PATH] {
        expect_error(&ports.post(path).await, 503, "ServiceUnavailable");
        ports.assert_writes(0, &[]);
        assert_eq!(store_activity(), before);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn zero_length_stream_is_accepted() {
    let ports = Ports::new();
    let body = Body::Stream {
        declared_len: Some(0),
        stream: Box::pin(stream::empty()),
    };
    let resp = ports
        .serve(request(
            Method::Post,
            KEY_PATH,
            ADMIN_HOST,
            Some(ADMIN),
            body,
        ))
        .await;
    assert_eq!(
        json_response(&resp, 200),
        json!({"key_locations": "written"})
    );
    ports.assert_writes(1, &[&locations_chain().name(1)]);
}

#[tokio::test(flavor = "current_thread")]
async fn key_locations_writes_seq_one_and_a_repeat_leaves_it_present() {
    let ports = Ports::new();
    let name = locations_chain().name(1);
    for outcome in ["written", "present"] {
        let resp = ports.post(KEY_PATH).await;
        assert_eq!(json_response(&resp, 200), json!({"key_locations": outcome}));
        let head = read_locations(&ports.records, &ports.kek, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.seq, 1);
        assert_eq!(head, two_in_account());
        ports.assert_writes(1, &[&name]);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn another_key_location_set_conflicts_and_alerts_without_writing() {
    let ports = Ports::new();
    let mut other = two_in_account();
    other.locations[0].arbiter = false;
    other.locations[1].arbiter = true;
    assert!(
        write_locations(&ports.records, &ports.kek, &other, &mut SystemRng)
            .await
            .unwrap()
    );

    watch_alerts();
    expect_error(&ports.post(KEY_PATH).await, 409, "locations_differ");
    assert_eq!(take_alerts().len(), 1);
    assert_eq!(
        read_locations(&ports.records, &ports.kek, 0).await.unwrap(),
        Some(other)
    );
    ports.assert_writes(1, &[&locations_chain().name(1)]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_damaged_key_location_head_alerts_without_writing() {
    let ports = Ports::new();
    let name = locations_chain().name(1);
    let garbage = b"not a control record";
    ports.records.plant(&name, garbage.to_vec());

    watch_alerts();
    expect_error(&ports.post(KEY_PATH).await, 503, "SlowDown");
    assert_eq!(take_alerts().len(), 1);
    assert_eq!(
        ports.records.raw(&name).as_deref(),
        Some(garbage.as_slice())
    );
    ports.assert_writes(0, &[&name]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_key_location_head_under_a_newer_kek_neither_alerts_nor_writes() {
    let ports = Ports::new();
    let newer = TestKek::with_versions(2, &[(1, [0x11; 32]), (2, [0x22; 32])]);
    let locations = two_in_account();
    assert!(
        write_locations(&ports.records, &newer, &locations, &mut SystemRng)
            .await
            .unwrap()
    );

    watch_alerts();
    expect_error(&ports.post(KEY_PATH).await, 503, "SlowDown");
    assert!(take_alerts().is_empty());
    assert_eq!(
        read_locations(&ports.records, &newer, 0).await.unwrap(),
        Some(locations)
    );
    ports.assert_writes(1, &[&locations_chain().name(1)]);
}

#[tokio::test(flavor = "current_thread")]
async fn matching_key_location_head_is_present_with_one_bucket_bound() {
    let ports = Ports {
        bind_keys_b: false,
        ..Ports::new()
    };
    let locations = two_in_account();
    assert!(
        write_locations(&ports.records, &ports.kek, &locations, &mut SystemRng)
            .await
            .unwrap()
    );

    watch_alerts();
    assert_eq!(
        json_response(&ports.post(KEY_PATH).await, 200),
        json!({"key_locations": "present"})
    );
    assert!(take_alerts().is_empty());
    ports.assert_writes(1, &[&locations_chain().name(1)]);
}

#[tokio::test(flavor = "current_thread")]
async fn different_key_location_head_conflicts_and_alerts_with_one_bucket_bound() {
    let ports = Ports {
        bind_keys_b: false,
        ..Ports::new()
    };
    let mut other = two_in_account();
    other.locations[1].name = "KEYS_OTHER".to_string();
    assert!(
        write_locations(&ports.records, &ports.kek, &other, &mut SystemRng)
            .await
            .unwrap()
    );

    watch_alerts();
    expect_error(&ports.post(KEY_PATH).await, 409, "locations_differ");
    assert_eq!(take_alerts().len(), 1);
    assert_eq!(
        read_locations(&ports.records, &ports.kek, 0).await.unwrap(),
        Some(other)
    );
    ports.assert_writes(1, &[&locations_chain().name(1)]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_key_location_head_lookup_takes_precedence_over_a_missing_binding() {
    let ports = Ports {
        bind_keys_b: false,
        ..Ports::new()
    };
    ports.records.refuse_lists(true);

    watch_alerts();
    expect_error(&ports.post(KEY_PATH).await, 503, "SlowDown");
    assert!(take_alerts().is_empty());
    assert_eq!(ports.records.lists(), 1, "stop after the failed lookup");
    ports.assert_writes(0, &[]);
}

#[tokio::test(flavor = "current_thread")]
async fn one_key_bucket_binding_is_not_enough_to_write_locations() {
    let ports = Ports {
        bind_keys_b: false,
        ..Ports::new()
    };
    expect_error(&ports.post(KEY_PATH).await, 503, "key_buckets_unbound");
    ports.assert_writes(0, &[]);
}

#[tokio::test(flavor = "current_thread")]
async fn an_unbound_directory_does_not_write_records() {
    let ports = Ports::new();
    expect_error(&ports.post(GATE_PATH).await, 503, "directory_unbound");
    ports.assert_writes(0, &[]);
}

#[tokio::test(flavor = "current_thread")]
async fn an_open_gate_stays_open_and_keeps_pending_ops() {
    let ports = Ports::with_closed_directory();
    let dir = ports.dir();
    let epoch = close(&ports.records, &dir, "first_rebuild", NOW)
        .await
        .unwrap();
    assert!(dir.open_gate(epoch, NOW).await.unwrap());
    assert!(is_open(&ports.records, &dir).await.unwrap());
    let pending = PendingOp {
        tenant: Tenant::parse("t_00000000000000a1").unwrap(),
        chain: ChainKind::Tenant,
        seq: 1,
        kind: "fixture".to_string(),
        created_at: UnixMs(NOW.0 - 1),
    };
    dir.add_pending(&pending).await.unwrap();
    let before = dir.gate().await.unwrap();
    let names = ports.records.names();
    let puts = ports.records.puts();

    let resp = ports.post(GATE_PATH).await;
    assert_eq!(
        json_response(&resp, 200),
        json!({"gate": "open", "ran": false})
    );
    assert!(is_open(&ports.records, &dir).await.unwrap());
    assert_eq!(dir.gate().await.unwrap(), before);
    assert_eq!(dir.pending_before(NOW, 2).await.unwrap(), [pending]);
    assert_eq!(ports.records.puts(), puts);
    assert_eq!(ports.records.names(), names);
    ports.assert_key_buckets_untouched();
}

#[tokio::test(flavor = "current_thread")]
async fn a_managed_tenant_chain_refuses_first_open_and_alerts() {
    let ports = Ports::with_closed_directory();
    let dir = ports.dir();
    let before = dir.gate().await.unwrap();
    let name = "m/t/t_00000000000000a1/00000000000000000001";
    ports.records.plant(name, b"a tenant-chain record".to_vec());

    watch_alerts();
    expect_error(&ports.post(GATE_PATH).await, 409, "gate_has_tenants");
    assert_eq!(take_alerts().len(), 1);
    assert!(!is_open(&ports.records, &dir).await.unwrap());
    assert_eq!(dir.gate().await.unwrap(), before);
    ports.assert_writes(0, &[name]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_closed_gate_without_tenants_runs_first_open() {
    let ports = Ports::with_closed_directory();
    let dir = ports.dir();
    assert!(!is_open(&ports.records, &dir).await.unwrap());

    let body = json_response(&ports.post(GATE_PATH).await, 503);
    assert_eq!(body["error"], "gate_not_opened");
    assert_eq!(body["epoch"], 1);
    assert_eq!(
        body["not_done"],
        json!([{"step": "key_locations_and_registry", "problems": ["key_locations_absent"]}])
    );
    assert_eq!(anchored_epoch(&ports.records).await.unwrap(), (1, 0));
    assert_eq!(dir.gate().await.unwrap().epoch, 1);
    assert!(!is_open(&ports.records, &dir).await.unwrap());
    assert_eq!(ports.records.puts(), 1);
    assert_eq!(ports.records.names().len(), 1);

    // Once the missing prerequisite is ready, a new call can run again.
    assert_eq!(ports.post(KEY_PATH).await.status, 200);
    assert_eq!(
        json_response(&ports.post(GATE_PATH).await, 200),
        json!({"gate": "open", "ran": true, "epoch": 2})
    );
    assert!(is_open(&ports.records, &dir).await.unwrap());
    ports.assert_key_buckets_untouched();
}

#[tokio::test(flavor = "current_thread")]
async fn a_stray_gate_anchor_leaves_first_open_closed_and_alerts() {
    let ports = Ports::with_closed_directory();
    assert_eq!(ports.post(KEY_PATH).await.status, 200);
    ports.records.plant("m/dg/x", Vec::new());

    watch_alerts();
    expect_error(&ports.post(GATE_PATH).await, 503, "gate_not_opened");
    assert_eq!(take_alerts().len(), 1);
    assert!(!is_open(&ports.records, &ports.dir()).await.unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn a_damaged_tenant_zero_chain_leaves_first_open_closed_and_alerts() {
    let ports = Ports::with_closed_directory();
    assert_eq!(ports.post(KEY_PATH).await.status, 200);
    ports.records.plant(
        "m/t/t_0000000000000000/00000000000000000001",
        b"damaged tenant record".to_vec(),
    );

    watch_alerts();
    expect_error(&ports.post(GATE_PATH).await, 503, "gate_not_opened");
    assert_eq!(take_alerts().len(), 1);
    assert!(!is_open(&ports.records, &ports.dir()).await.unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_first_open_calls_fail_fast_and_open_at_one_epoch() {
    let ports = Ports::with_closed_directory();
    let dir = ports.dir();
    assert_eq!(ports.post(KEY_PATH).await.status, 200);
    ports.records.pause_after_anchor.set(true);

    let mut cx = Context::from_waker(Waker::noop());
    let mut first = pin!(ports.post(GATE_PATH));
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert_eq!(anchored_epoch(&ports.records).await.unwrap(), (1, 0));
    assert_eq!(dir.gate().await.unwrap().epoch, 0);

    let activity = (ports.records.lists(), ports.records.puts());
    let mut second = pin!(ports.post(GATE_PATH));
    let std::task::Poll::Ready(response) = second.as_mut().poll(&mut cx) else {
        panic!("an overlapping request must answer without waiting on another request");
    };
    expect_error(&response, 503, "SlowDown");
    assert_eq!((ports.records.lists(), ports.records.puts()), activity);
    assert_eq!(
        json_response(&first.await, 200),
        json!({"gate": "open", "ran": true, "epoch": 1})
    );
    assert_eq!(
        json_response(&ports.post(GATE_PATH).await, 200),
        json!({"gate": "open", "ran": false})
    );
    assert_eq!(anchored_epoch(&ports.records).await.unwrap(), (1, 0));
    assert_eq!(dir.feed_epoch().await.unwrap(), 1);
    assert!(is_open(&ports.records, &dir).await.unwrap());
}
