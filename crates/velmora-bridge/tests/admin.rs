//! `/_admin/*` and S3 CreateBucket through `Bridge::handle`, over the SQL
//! catalogue (SQLite with the production schema) and the in-process NNTP
//! server.

mod nntp_support;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use futures_util::StreamExt;
use nntp_support::{hex, sha256, TcpConnector, PASS, USER};
use serde_json::{json, Value};
use velmora::rng::SystemRng;
use velmora_bridge::config::{Environment, GcMode, Maintenance};
use velmora_bridge::crypto::{seal_extent, unwrap_bdk, unwrap_secret, wrap_bdk, DataKey};
use velmora_bridge::fetch::{COLD_JITTER_MS, COLD_POLL_MS, COLD_WAIT_MS};
use velmora_bridge::ingress::{ByteBudget, Sleeper};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::PublishUnrecorded;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const T0: UnixMs = UnixMs(1_800_000_000_000);
const BUDGET: u64 = 48 * 1024 * 1024;
const TOKEN: &str = "admin-token-fixture-0123456789abcdef";

type TestBridge =
    Bridge<SqlCatalog<RacingSql>, MemBlobStore, TcpConnector, FakeJobs, TestKek, FixedClock>;

/// The SQLite catalogue, plus one test hook: with `race` set, the next
/// safety-state compare-and-set finds that another writer moved every
/// extent to that state first.
struct RacingSql {
    inner: RusqliteSql,
    race: RefCell<Option<&'static str>>,
    /// The next `n` statements whose text contains the string fail, as
    /// a catalogue that did not answer.
    fail: RefCell<Option<(&'static str, u32)>>,
}

impl RacingSql {
    fn injected(&self, sql: &str) -> Result<()> {
        let mut fail = self.fail.borrow_mut();
        match fail.as_mut() {
            Some((part, left)) if *left > 0 && sql.contains(*part) => {
                *left -= 1;
                Err(BridgeError::Sql("injected: statement failed".into()))
            }
            _ => Ok(()),
        }
    }
}

impl Sql for RacingSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.injected(sql)?;
        self.inner.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.injected(sql)?;
        if sql.starts_with("UPDATE extents SET safety_state") {
            if let Some(state) = self.race.take() {
                let first = "UPDATE extents SET safety_state = ?1";
                self.inner.exec(first, &[text(state)]).await?;
            }
        }
        self.inner.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        self.inner.batch(stmts).await
    }
}

/// Connections the fixture server gives its one account: enough for a
/// drill over the drill connections of two providers beside what the
/// providers' own slots allow.
const SERVER_CONNS: usize = 8;

struct Fx {
    bridge: Rc<TestBridge>,
    server: TestNntpServer,
    seed: Cell<u8>,
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// `Debug` of the response, as a log line would render it.
    debug: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).expect("a UTF-8 body")
    }
}

/// A committed single-extent object.
struct Obj {
    extent: ExtentId,
    generation: GenerationId,
    plain: Vec<u8>,
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

impl Fx {
    async fn new() -> Fx {
        Fx::with(Environment::Dev, Maintenance::Off).await
    }

    async fn with(environment: Environment, maintenance: Maintenance) -> Fx {
        Fx::with_providers(environment, maintenance, |_| {}).await
    }

    /// The fixture, with `edit` applied to its provider list (one
    /// provider, `p0`, on the fixture server).
    async fn with_providers(
        environment: Environment,
        maintenance: Maintenance,
        edit: impl FnOnce(&mut Vec<ProviderConfig>),
    ) -> Fx {
        Fx::build(environment, maintenance, edit, None).await
    }

    /// The fixture with a host timer: `sleeper` is made with the
    /// bridge's clock.
    async fn with_sleeper(sleeper: impl FnOnce(FixedClock) -> Sleeper + 'static) -> Fx {
        let sleeper: Box<dyn FnOnce(FixedClock) -> Sleeper> = Box::new(sleeper);
        Fx::build(Environment::Dev, Maintenance::Off, |_| {}, Some(sleeper)).await
    }

    async fn build(
        environment: Environment,
        maintenance: Maintenance,
        edit: impl FnOnce(&mut Vec<ProviderConfig>),
        sleeper: Option<Box<dyn FnOnce(FixedClock) -> Sleeper>>,
    ) -> Fx {
        let mut config = ServerConfig::for_test();
        config.articles = Vec::new();
        config.missing_ids.clear();
        config.users.insert(
            USER.to_string(),
            UserConfig {
                password: PASS.to_string(),
                max_connections: SERVER_CONNS,
            },
        );
        let server = TestNntpServer::spawn(config).await;
        let mut providers = vec![ProviderConfig {
            id: "p0".to_string(),
            host: server.addr().ip().to_string(),
            hosts: Vec::new(),
            host_select: Default::default(),
            port: server.addr().port(),
            tls: false,
            user: USER.to_string(),
            pass: PASS.to_string(),
            backbone: "bb0".to_string(),
            post: true,
            read: true,
            max_conns: 2,
            max_ips: None,
            drill_conns: 0,
            priority: 0,
            retention_days: None,
            pool: None,
            pool_max_conns: None,
            proxies: Vec::new(),
            enabled: true,
            release: true,
        }];
        edit(&mut providers);
        let cfg = BridgeConfig {
            environment,
            s3_host: "s3.test".to_string(),
            region: "auto".to_string(),
            max_extent_bytes: 16 * 1024 * 1024,
            max_put_bytes: 16 * 1024 * 1024,
            slice_bytes: 8 * 1024 * 1024,
            max_object_extents: 10_000,
            intent_sweep: false,
            records: velmora_bridge::recovery::Layout::flat(),
            packed_plans: false,
            parity: false,
            required_backbones: 1,
            safety_min_age_secs: 0,
            verify_delay_secs: 1,
            post_sockets: 4,
            cold_sockets: 4,
            propagation_grace_secs: 21_600,
            newsgroups: vec!["alt.binaries.test".to_string()],
            kek_active: 1,
            inflight_budget_bytes: BUDGET,
            job_budget_bytes: BUDGET,
            gc_mode: GcMode::Disposable,
            hot_cap_bytes: velmora_bridge::config::DEFAULT_HOT_CAP_BYTES,
            maintenance,
            server_side_copy: false,
            get_fanout_bytes: None,
            catalogue_id: "main".to_string(),
            dev_trust_http: false,
            verify: Default::default(),
            providers,
            admin_token: Secret::new(TOKEN.to_string()),
            admin_read_token: None,
            admin_host: None,
            metrics_sample: 10,
        };
        let clock = FixedClock::new(T0);
        let mut budget = ByteBudget::new(BUDGET);
        if let Some(sleeper) = sleeper {
            budget = budget.with_sleeper(sleeper(clock.clone()));
        }
        let bridge = Bridge {
            catalog: SqlCatalog::new(RacingSql {
                inner: RusqliteSql::with_schema().unwrap(),
                race: RefCell::new(None),
                fail: RefCell::new(None),
            }),
            safety: MemBlobStore::new(),
            cache: MemBlobStore::new(),
            nntp: TcpConnector::default(),
            jobs: FakeJobs::new(),
            kek: TestKek::new(),
            clock,
            budget,
            cfg,
        };
        Fx {
            bridge: Rc::new(bridge),
            server,
            seed: Cell::new(1),
        }
    }

    /// One request through the router. `auth` is the whole
    /// `Authorization` header value.
    async fn send(
        &self,
        method: &str,
        target: &str,
        auth: Option<&str>,
        body: Option<&str>,
    ) -> Resp {
        let mut headers = Vec::new();
        if let Some(auth) = auth {
            headers.push(("authorization".to_string(), auth.to_string()));
        }
        let body = match body {
            None => Body::Empty,
            Some(b) => {
                headers.push(("content-type".to_string(), "application/json".to_string()));
                headers.push(("content-length".to_string(), b.len().to_string()));
                let chunk: Result<Vec<u8>> = Ok(b.as_bytes().to_vec());
                Body::Stream {
                    declared_len: Some(b.len() as u64),
                    stream: futures_util::stream::iter(vec![chunk]).boxed_local(),
                }
            }
        };
        let req = S3Request {
            method: Method::parse(method),
            raw_target: target.to_string(),
            headers,
            body,
        };
        let resp = Rc::clone(&self.bridge).handle(req).await;
        let debug = format!("{resp:?}");
        let body = match resp.body {
            RespBody::Empty => Vec::new(),
            RespBody::Bytes(b) => b,
            RespBody::Stream(_) | RespBody::Deferred(_) | RespBody::Fanout(_) => {
                panic!("admin responses are never streamed")
            }
        };
        Resp {
            status: resp.status,
            headers: resp.headers,
            body,
            debug,
        }
    }

    /// An authenticated admin request.
    async fn admin(&self, method: &str, path: &str, body: Option<Value>) -> Resp {
        let auth = format!("Bearer {TOKEN}");
        let body = body.map(|b| b.to_string());
        self.send(
            method,
            &format!("/_admin{path}"),
            Some(&auth),
            body.as_deref(),
        )
        .await
    }

    async fn get(&self, path: &str) -> Resp {
        self.admin("GET", path, None).await
    }

    async fn post(&self, path: &str) -> Resp {
        self.admin("POST", path, None).await
    }

    fn next(&self) -> u8 {
        let n = self.seed.get();
        self.seed.set(n + 1);
        n
    }

    /// A disposable bucket, made through the API.
    async fn bucket(&self, name: &str) -> Bucket {
        let body = json!({ "name": name, "disposable": true });
        let r = self.admin("POST", "/buckets", Some(body)).await;
        assert_eq!(r.status, 200, "{}", r.text());
        self.bucket_row(name).await.expect("the bucket exists")
    }

    /// A bucket for real data, written directly.
    async fn real_bucket(&self, name: &str) -> Bucket {
        let id = BucketId::mint([self.next(); 8]);
        let bdk = DataKey::generate(&mut SystemRng).unwrap();
        let (kek_version, wrapped) = wrap_bdk(&self.bridge.kek, &id, &bdk, &mut SystemRng).unwrap();
        let bucket = Bucket {
            id,
            name: name.to_string(),
            owner: "owner".to_string(),
            bdk_wrapped: wrapped.to_vec(),
            kek_version,
            disposable: false,
            created_at: T0,
        };
        let created = self.bridge.catalog.create_bucket(&bucket).await.unwrap();
        assert_eq!(created, Guard::Applied(()));
        bucket
    }

    async fn bucket_row(&self, name: &str) -> Option<Bucket> {
        self.bridge.catalog.bucket_by_name(name).await.unwrap()
    }

    /// What a finished PUT leaves: the sealed extent in both blob stores
    /// and one committed generation.
    async fn put(&self, bucket: &Bucket, key: &str, plain: &[u8]) -> Obj {
        let mut extents = self.put_extents(bucket, key, &[plain]).await;
        extents.remove(0)
    }

    /// [`Self::put`] for an object of several extents, one per piece.
    async fn put_extents(&self, bucket: &Bucket, key: &str, pieces: &[&[u8]]) -> Vec<Obj> {
        let b = &self.bridge;
        let now = b.clock.now();
        let bdk = unwrap_bdk(&b.kek, bucket.kek_version, &bucket.id, &bucket.bdk_wrapped).unwrap();
        let size: usize = pieces.iter().map(|p| p.len()).sum();
        let generation = GenerationRow {
            id: GenerationId::mint(now, [self.next(); 8]),
            bucket_id: bucket.id.clone(),
            key: key.to_string(),
            state: GenerationState::Live,
            size: size as u64,
            etag: "\"etag\"".to_string(),
            checksum_json: None,
            content_json: "{}".to_string(),
            user_meta_json: "{}".to_string(),
            extent_count: pieces.len() as u32,
            created_at: now,
            retired_at: None,
        };
        let mut extents = Vec::new();
        let mut objs = Vec::new();
        let mut offset = 0u64;
        for (seq, plain) in pieces.iter().enumerate() {
            let extent_id = ExtentId::mint([self.next(); 13]);
            let sealed = seal_extent(&bdk, &bucket.id, &extent_id, plain, &mut SystemRng).unwrap();
            extents.push(ExtentRow {
                id: extent_id.clone(),
                bucket_id: bucket.id.clone(),
                generation_id: Some(generation.id.clone()),
                state: ExtentState::Committed,
                seq: Some(seq as u32),
                plain_offset: Some(offset),
                plain_size: plain.len() as u64,
                cipher_size: sealed.ciphertext.len() as u64,
                media_header: sealed.media_header.to_vec(),
                key_mode: 1,
                wrapped_file_key: Some(sealed.wrapped_file_key.to_vec()),
                plain_md5: sealed.plain_md5,
                plain_sha256: sealed.plain_sha256,
                cipher_sha256: sealed.cipher_sha256,
                safety_state: SafetyState::Held,
                article_count: None,
                plan_rev: 0,
                last_verified_at: None,
                release_evidence: None,
                released_at: None,
                created_at: now,
            });
            offset += plain.len() as u64;
            let meta = BlobMeta {
                bucket: &bucket.id,
                extent: &extent_id,
                cipher_sha256: &sealed.cipher_sha256,
            };
            b.safety
                .put(&extent_id.safety_key(), sealed.ciphertext.clone(), &meta)
                .await
                .unwrap();
            b.cache
                .put(&extent_id.cache_key(), sealed.ciphertext.clone(), &meta)
                .await
                .unwrap();
            objs.push(Obj {
                extent: extent_id,
                generation: generation.id.clone(),
                plain: plain.to_vec(),
            });
        }
        b.catalog
            .publish(&CommitGeneration {
                generation,
                extents,
                now,
            })
            .await
            .unwrap();
        objs
    }

    /// Runs the object's jobs until its outbox row is `stage`.
    async fn drive(&self, o: &Obj, until: OutboxStage) {
        let b = &self.bridge;
        for _ in 0..20 {
            let stage = self.stage(o).await;
            if stage == until.as_str() {
                return;
            }
            let job = Job::Extent {
                v: JOB_VERSION,
                extent: o.extent.clone(),
                generation: o.generation.clone(),
                stage: OutboxStage::parse(&stage).expect("a stage"),
            };
            b.clock.advance_secs(60);
            assert_eq!(
                b.run_job(&TENANT_ZERO, &job).await,
                JobOutcome::Ack,
                "{stage}"
            );
            b.jobs.take();
        }
        panic!("the object never reached {until}");
    }

    async fn stage(&self, o: &Obj) -> String {
        self.scalar(
            "SELECT stage FROM outbox WHERE extent_id = ?1",
            &[text(o.extent.as_str())],
        )
        .await
    }

    async fn safety_state(&self, o: &Obj) -> String {
        self.scalar(
            "SELECT safety_state FROM extents WHERE id = ?1",
            &[text(o.extent.as_str())],
        )
        .await
    }

    async fn scalar(&self, sql: &str, params: &[SqlValue]) -> String {
        let rows = self.bridge.catalog.sql.query(sql, params).await.unwrap();
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Text(s)) => s.clone(),
            Some(SqlValue::Int(n)) => n.to_string(),
            Some(SqlValue::Null) | None => "NULL".to_string(),
            Some(other) => panic!("unexpected {other:?}"),
        }
    }

    /// Every value stored in the tables the admin API writes, as bytes.
    async fn stored_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for table in ["buckets", "access_keys", "grants", "meta"] {
            let sql = format!("SELECT * FROM {table}");
            for row in self.bridge.catalog.sql.query(&sql, &[]).await.unwrap() {
                for value in row {
                    match value {
                        SqlValue::Text(s) => out.extend_from_slice(s.as_bytes()),
                        SqlValue::Blob(b) => out.extend_from_slice(&b),
                        SqlValue::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
                        SqlValue::Null => {}
                    }
                    out.push(b'|');
                }
            }
        }
        out
    }

    fn has_safety(&self, o: &Obj) -> bool {
        self.bridge.safety.contains(&o.extent.safety_key())
    }

    fn has_cache(&self, o: &Obj) -> bool {
        self.bridge.cache.contains(&o.extent.cache_key())
    }
}

/// Three articles' worth of plaintext.
fn plaintext() -> Vec<u8> {
    nntp_support::marked_plaintext(2 * 1024 * 1024 + 4321)
}

/// Every admin route, with a body where the route reads one.
fn routes() -> Vec<(&'static str, &'static str, Option<&'static str>)> {
    vec![
        ("GET", "/_admin/status", None),
        (
            "POST",
            "/_admin/buckets",
            Some(r#"{"name":"probe","disposable":true}"#),
        ),
        (
            "POST",
            "/_admin/keys",
            Some(r#"{"buckets":["scratch"],"perm":"rw"}"#),
        ),
        ("GET", "/_admin/keys", None),
        ("DELETE", "/_admin/keys/AKVLNOSUCHKEY0000000", None),
        ("GET", "/_admin/objects/scratch/k", None),
        ("POST", "/_admin/evict/scratch/k?include_safety=1", None),
        ("POST", "/_admin/drill/scratch/k", None),
        ("POST", "/_admin/pack-plans?limit=1", None),
        ("GET", "/_admin/ops-snapshot", None),
        ("GET", "/_admin/usage/buckets", None),
        ("GET", "/_admin/cost", None),
        ("POST", "/_admin/usage/recount", None),
        ("POST", "/_admin/usage/off", None),
        ("POST", "/_admin/dev/guard-selftest", None),
        ("POST", "/_admin/dev/suppress-notify?n=1", None),
        ("GET", "/_admin/no-such-route", None),
        ("GET", "/_admin", None),
    ]
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_without_or_with_a_wrong_bearer_is_refused() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", b"payload").await;
    let before = fx.stored_bytes().await;

    let missing: [Option<&str>; 4] = [None, Some(""), Some("Bearer "), Some("Basic dXNlcjpwYXNz")];
    let short = format!("Bearer {}", &TOKEN[..TOKEN.len() - 1]);
    let long = format!("Bearer {TOKEN}x");
    let upper = format!("Bearer {}", TOKEN.to_uppercase());
    let bare = TOKEN.to_string();
    let wrong = ["Bearer wrong", &short, &long, &upper, "Bearer x"];

    for (method, target, body) in routes() {
        for auth in missing {
            let r = fx.send(method, target, auth, body).await;
            assert_eq!(r.status, 401, "{method} {target} with {auth:?}");
            assert!(r.headers.iter().any(|(n, _)| n == "www-authenticate"));
            assert!(!r.text().contains(TOKEN));
        }
        for auth in wrong {
            let r = fx.send(method, target, Some(auth), body).await;
            assert_eq!(r.status, 403, "{method} {target} with a wrong token");
            assert!(!r.text().contains(TOKEN));
        }
        // The token without the scheme is not a bearer credential.
        let r = fx.send(method, target, Some(&bare), body).await;
        assert_eq!(r.status, 401, "{method} {target} with a bare token");
    }

    // None of the refused requests did anything.
    assert_eq!(fx.stored_bytes().await, before);
    assert!(fx.bucket_row("probe").await.is_none());
    assert!(fx.has_cache(&o) && fx.has_safety(&o));
    assert_eq!(fx.bridge.nntp.connects(), 0);

    // The right token opens the same routes.
    assert_eq!(fx.get("/status").await.status, 200);
    assert_eq!(fx.get("/objects/scratch/k").await.status, 200);
}

#[tokio::test]
async fn unknown_routes_and_methods_are_refused() {
    let fx = Fx::new().await;
    for path in [
        "",
        "/",
        "/nope",
        "/statusx",
        "/buckets/x",
        "/dev",
        "/dev/",
        "/dev/nope",
    ] {
        assert_eq!(fx.get(path).await.status, 404, "GET {path}");
    }
    for (method, path) in [
        ("POST", "/status"),
        ("GET", "/buckets"),
        ("DELETE", "/keys"),
        ("GET", "/keys/AKVLNOSUCHKEY0000000"),
        ("POST", "/keys/AKVLNOSUCHKEY0000000"),
        ("DELETE", "/buckets"),
        ("POST", "/objects/scratch/k"),
        ("GET", "/evict/scratch/k"),
        ("GET", "/drill/scratch/k"),
        ("GET", "/dev/guard-selftest"),
        ("POST", "/ops-snapshot"),
        ("POST", "/usage/buckets"),
        ("POST", "/cost"),
        ("GET", "/usage/recount"),
        ("GET", "/usage/off"),
    ] {
        assert_eq!(
            fx.admin(method, path, None).await.status,
            405,
            "{method} {path}"
        );
    }
    for path in [
        "/objects/scratch",
        "/objects/scratch/",
        "/objects//k",
        "/objects/scratch/%zz",
    ] {
        assert_eq!(fx.get(path).await.status, 400, "GET {path}");
    }
}

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_bucket_is_made_only_when_asked_for() {
    // This test describes the open gate; closing it must revisit it.
    const { assert!(REAL_DATA_READY) }
    let fx = Fx::new().await;

    // Leaving the flag out, or sending something that is not a boolean,
    // makes no bucket of either kind.
    let r = fx
        .admin("POST", "/buckets", Some(json!({ "name": "real-data" })))
        .await;
    assert_eq!(r.status, 400);
    for body in [
        json!({ "name": "real-data", "disposable": 0 }),
        json!({ "name": "real-data", "disposable": null }),
    ] {
        assert_eq!(fx.admin("POST", "/buckets", Some(body)).await.status, 400);
    }
    assert!(fx.bucket_row("real-data").await.is_none());

    // S3 CreateBucket makes real buckets only, and only with the admin
    // token.
    for auth in [None, Some("Bearer wrong")] {
        let r = fx.send("PUT", "/real-s3", auth, None).await;
        assert_eq!(r.status, 403, "PUT /real-s3 with {:?}", auth.is_some());
        assert!(r.text().contains("<Code>AccessDenied</Code>"));
    }
    assert_eq!(fx.scalar("SELECT COUNT(*) FROM buckets", &[]).await, "0");
    let auth = format!("Bearer {TOKEN}");
    let r = fx.send("PUT", "/real-s3", Some(auth.as_str()), None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let row = fx.bucket_row("real-s3").await.expect("the bucket exists");
    assert!(!row.disposable);

    let real = json!({ "name": "real-data", "disposable": false });
    let r = fx.admin("POST", "/buckets", Some(real)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let row = fx.bucket_row("real-data").await.expect("the bucket exists");
    assert!(!row.disposable);
}

#[tokio::test]
async fn create_bucket_wraps_a_fresh_data_key() {
    let fx = Fx::new().await;
    let a = fx.bucket("scratch").await;
    let b = fx.bucket("other").await;
    assert!(a.disposable && b.disposable);
    assert_ne!(a.id, b.id);

    // Each bucket has its own key, stored wrapped under the active KEK
    // and bound to the bucket id.
    assert_eq!(a.bdk_wrapped.len(), 73);
    assert_ne!(a.bdk_wrapped, b.bdk_wrapped);
    assert_eq!((a.kek_version, b.kek_version), (1, 1));
    let kek = &fx.bridge.kek;
    assert!(unwrap_bdk(kek, 1, &a.id, &a.bdk_wrapped).is_ok());
    assert!(unwrap_bdk(kek, 1, &b.id, &b.bdk_wrapped).is_ok());
    assert!(unwrap_bdk(kek, 1, &b.id, &a.bdk_wrapped).is_err());
    // The key works: an object sealed under it opens again.
    let o = fx.put(&a, "k", b"payload").await;
    assert!(fx.has_safety(&o));

    let again = json!({ "name": "scratch", "disposable": true });
    let r = fx.admin("POST", "/buckets", Some(again)).await;
    assert_eq!(r.status, 409);
    assert_eq!(
        fx.bucket_row("scratch").await.unwrap(),
        a,
        "the first bucket is unchanged"
    );

    let long = "a".repeat(64);
    for name in [
        "ab",
        "Upper",
        "-edge",
        "edge-",
        "under_score",
        "dot.ted",
        "_admin",
        "",
        &long,
    ] {
        let body = json!({ "name": name, "disposable": true });
        let r = fx.admin("POST", "/buckets", Some(body)).await;
        assert_eq!(r.status, 400, "bucket name {name:?}");
    }
    for body in [
        "",
        "{",
        "[]",
        r#"{"name":"x1y","disposable":true,"extra":1}"#,
    ] {
        let auth = format!("Bearer {TOKEN}");
        let r = fx
            .send("POST", "/_admin/buckets", Some(&auth), Some(body))
            .await;
        assert_eq!(r.status, 400, "body {body:?}");
    }
    assert_eq!(fx.scalar("SELECT COUNT(*) FROM buckets", &[]).await, "2");
}

// ---------------------------------------------------------------------------
// Access keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn key_secret_appears_exactly_once() {
    let fx = Fx::new().await;
    let scratch = fx.bucket("scratch").await;
    let other = fx.bucket("other").await;

    let body = json!({ "buckets": ["scratch", "other"], "perm": "rw" });
    let created = fx.admin("POST", "/keys", Some(body)).await;
    assert_eq!(created.status, 200);
    let v = created.json();
    let akid = v["access_key_id"]
        .as_str()
        .expect("access_key_id")
        .to_string();
    let secret = v["secret"].as_str().expect("secret").to_string();
    assert_eq!(akid.len(), 20);
    assert_eq!(secret.len(), 40);
    assert!(secret.bytes().all(|b| b.is_ascii_alphanumeric()));

    // Once in the response body, and nowhere else the response is shown.
    assert_eq!(count(&created.body, secret.as_bytes()), 1);
    assert!(!created.debug.contains(&secret));
    assert!(created
        .headers
        .iter()
        .all(|(n, v)| !n.contains(&secret) && !v.contains(&secret)));
    assert!(created
        .headers
        .contains(&("cache-control".to_string(), "no-store".to_string())));

    // The catalogue holds it only wrapped under the KEK.
    assert_eq!(count(&fx.stored_bytes().await, secret.as_bytes()), 0);
    let row = fx
        .bridge
        .catalog
        .access_key(&akid)
        .await
        .unwrap()
        .expect("key row");
    assert_eq!(row.status, KeyStatus::Active);
    assert_eq!(row.secret_wrapped.len(), secret.len() + 41);
    assert!(!format!("{row:?}").contains(&secret));
    let opened =
        unwrap_secret(&fx.bridge.kek, row.kek_version, &akid, &row.secret_wrapped).unwrap();
    assert_eq!(&opened[..], secret.as_bytes());
    for bucket in [&scratch, &other] {
        let grant = fx.bridge.catalog.grant(&akid, &bucket.id).await.unwrap();
        assert_eq!(grant, Some(Perm::Rw));
    }

    // No later response, error or success, ever shows it again.
    let later = [
        fx.get("/status").await,
        fx.get("/objects/scratch/missing").await,
        fx.admin(
            "POST",
            "/keys",
            Some(json!({ "buckets": ["nope"], "perm": "rw" })),
        )
        .await,
        fx.admin(
            "POST",
            "/keys",
            Some(json!({ "buckets": ["scratch"], "perm": "admin" })),
        )
        .await,
        fx.admin(
            "POST",
            "/keys",
            Some(json!({ "buckets": [], "perm": "rw" })),
        )
        .await,
        fx.admin(
            "POST",
            "/keys",
            Some(json!({ "buckets": ["scratch"], "perm": "ro", "secret": secret })),
        )
        .await,
        fx.send(
            "POST",
            "/_admin/keys",
            Some("Bearer wrong"),
            Some(r#"{"buckets":["scratch"],"perm":"rw"}"#),
        )
        .await,
    ];
    let statuses: Vec<u16> = later.iter().map(|r| r.status).collect();
    assert_eq!(statuses, [200, 404, 404, 400, 400, 400, 403]);
    for r in &later {
        assert_eq!(count(&r.body, secret.as_bytes()), 0);
        assert!(!r.debug.contains(&secret));
    }
    // The refused requests created no key.
    assert_eq!(
        fx.scalar("SELECT COUNT(*) FROM access_keys", &[]).await,
        "1"
    );

    // A second key is a different key, and read-only stays read-only.
    let second = fx
        .admin(
            "POST",
            "/keys",
            Some(json!({ "buckets": ["scratch"], "perm": "ro" })),
        )
        .await
        .json();
    assert_ne!(second["access_key_id"], akid.as_str());
    assert_ne!(second["secret"], secret.as_str());
    let akid2 = second["access_key_id"].as_str().unwrap();
    let grant = fx.bridge.catalog.grant(akid2, &scratch.id).await.unwrap();
    assert_eq!(grant, Some(Perm::Ro));
    assert_eq!(
        fx.bridge.catalog.grant(akid2, &other.id).await.unwrap(),
        None
    );
}

// ---------------------------------------------------------------------------
// Dev routes, maintenance, status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dev_routes_are_refused_outside_dev() {
    let dev = Fx::new().await;
    let r = dev.post("/dev/guard-selftest").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({ "rolled_back": true }));
    // Dropping queue sends is the queue adapter's business: no route.
    assert_eq!(dev.post("/dev/suppress-notify?n=1").await.status, 404);

    let prod = Fx::with(Environment::Prod, Maintenance::Off).await;
    for path in [
        "/dev/guard-selftest",
        "/dev/suppress-notify?n=1",
        "/dev/anything",
    ] {
        for method in ["POST", "GET"] {
            let r = prod.admin(method, path, None).await;
            assert_eq!(r.status, 404, "{method} {path} in prod");
        }
    }
    let marker = "SELECT COUNT(*) FROM meta";
    assert_eq!(
        prod.scalar(marker, &[]).await,
        "0",
        "the self-test did not run"
    );
    // Everything else still answers in prod.
    let r = prod.get("/status").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["environment"], "prod");
}

#[tokio::test]
async fn restore_maintenance_refuses_mutations() {
    let fx = Fx::with(Environment::Dev, Maintenance::Restore).await;
    let bucket = fx.real_bucket("scratch").await;
    let o = fx.put(&bucket, "k", b"payload").await;

    let create = json!({ "name": "new-bucket", "disposable": true });
    let key = json!({ "buckets": ["scratch"], "perm": "rw" });
    let refused = [
        fx.admin("POST", "/buckets", Some(create)).await,
        fx.admin("POST", "/keys", Some(key)).await,
        fx.post("/evict/scratch/k").await,
        fx.post("/drill/scratch/k").await,
    ];
    for r in &refused {
        assert_eq!(r.status, 503);
    }
    let auth = format!("Bearer {TOKEN}");
    assert_eq!(
        fx.send("PUT", "/new-bucket", Some(&auth), None)
            .await
            .status,
        503
    );
    assert!(fx.bucket_row("new-bucket").await.is_none());
    assert_eq!(
        fx.scalar("SELECT COUNT(*) FROM access_keys", &[]).await,
        "0"
    );
    assert!(fx.has_cache(&o));

    // Reads still work.
    let r = fx.get("/status").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["maintenance"], "restore");
    assert_eq!(fx.get("/objects/scratch/k").await.status, 200);
}

#[tokio::test]
async fn status_reports_outbox_dispatch_and_memory() {
    let fx = Fx::new().await;
    let r = fx.get("/status").await.json();
    assert_eq!(r["dead"], 0);
    assert_eq!(r["last_dispatch_at"], Value::Null);
    assert_eq!(r["inflight_peak_bytes"], 0);
    assert_eq!(r["outbox"], json!({}));
    assert_eq!(r["real_data_ready"], REAL_DATA_READY);
    assert_eq!(r["gc_mode"], "disposable");
    assert_eq!(r["required_backbones"], 1);

    let bucket = fx.bucket("scratch").await;
    let done = fx.put(&bucket, "done", &plaintext()).await;
    fx.drive(&done, OutboxStage::Done).await;
    let dead = fx.put(&bucket, "dead", b"x").await;
    fx.put(&bucket, "waiting", b"y").await;
    fx.bridge
        .catalog
        .sql
        .exec(
            "UPDATE outbox SET attempts = 51 WHERE extent_id = ?1",
            &[text(dead.extent.as_str())],
        )
        .await
        .unwrap();
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.buried, report.enqueued), (1, 1));

    let r = fx.get("/status").await.json();
    assert_eq!(r["outbox"], json!({ "post": 1, "done": 1, "dead": 1 }));
    assert_eq!(r["dead"], 1);
    assert_eq!(r["last_dispatch_at"], fx.bridge.clock.now().0);
    let peak = r["inflight_peak_bytes"].as_u64().unwrap();
    assert!(
        peak >= done.plain.len() as u64 && peak <= BUDGET,
        "peak {peak}"
    );
    assert_eq!(r["inflight_bytes"], 0);
    assert_eq!(r["inflight_budget_bytes"], BUDGET);
    assert_eq!(r["job_budget_bytes"], BUDGET);
}

// ---------------------------------------------------------------------------
// Object status, evict, drill
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evict_with_safety_is_refused_on_a_real_bucket() {
    let fx = Fx::new().await;
    let bucket = fx.real_bucket("real").await;
    let o = fx.put(&bucket, "a/doc.bin", &plaintext()).await;
    // Posted and verified: even then the pinned copy of real data stays.
    fx.drive(&o, OutboxStage::Release).await;
    assert_eq!(fx.safety_state(&o).await, "held");

    for target in [
        "/evict/real/a/doc.bin?include_safety=1",
        "/evict/real/a/doc.bin?include_safety=true",
        "/evict/real/a/doc.bin?x=1&include_safety=1",
    ] {
        let r = fx.post(target).await;
        assert_eq!(r.status, 403, "{target}");
        assert_eq!(r.json()["error"], "SafetyEvictRefused");
    }
    assert!(fx.has_cache(&o), "a refused evict deletes nothing at all");
    assert!(fx.has_safety(&o));
    assert_eq!(fx.safety_state(&o).await, "held");

    // The cache is only a cache: it can go, the pinned copy cannot.
    let r = fx.post("/evict/real/a/doc.bin").await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 0 })
    );
    assert!(!fx.has_cache(&o));
    assert!(fx.has_safety(&o));
    assert_eq!(fx.safety_state(&o).await, "held");
    let status = fx.get("/objects/real/a/doc.bin").await.json();
    assert_eq!(status["extents"][0]["cache"], "absent");
    assert_eq!(status["extents"][0]["safety_state"], "held");

    assert_eq!(fx.post("/evict/real/missing").await.status, 404);
    assert_eq!(fx.post("/evict/nope/k").await.status, 404);
}

#[tokio::test]
async fn evict_keeps_the_only_copy_of_an_unposted_extent() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;

    // Not posted yet: the pinned copy is the only copy, disposable or not.
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 1 })
    );
    assert!(!fx.has_cache(&o));
    assert!(fx.has_safety(&o));
    assert_eq!(fx.safety_state(&o).await, "held");

    // Posted but not yet read back from any backbone: still kept.
    fx.drive(&o, OutboxStage::Verify).await;
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.json()["safety_kept"], 1);
    assert!(fx.has_safety(&o));

    // The object is intact: its jobs still run to the end.
    fx.drive(&o, OutboxStage::Done).await;
    assert_eq!(fx.safety_state(&o).await, "released");
}

#[tokio::test]
async fn evict_gives_up_a_verified_pinned_copy_on_a_disposable_bucket() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    // Verified on a backbone, release not yet run: the copy is still held.
    fx.drive(&o, OutboxStage::Release).await;
    assert_eq!(fx.safety_state(&o).await, "held");
    assert!(fx.has_safety(&o));

    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 1, "safety_kept": 0 })
    );
    assert!(!fx.has_cache(&o) && !fx.has_safety(&o));
    // The catalogue knows the copy is gone before anyone looks for it.
    assert_eq!(fx.safety_state(&o).await, "deleted");

    // The pending release job finds nothing left to do and finishes.
    fx.drive(&o, OutboxStage::Done).await;
    assert_eq!(fx.safety_state(&o).await, "deleted");
    // The object is still whole on Usenet.
    let drill = fx.post("/drill/scratch/k").await.json();
    assert_eq!(drill["match"], true);
}

/// The drill reads like a cold read: never from a provider that does not
/// read (`read: false`), even one listed first that holds the articles.
#[tokio::test]
async fn drill_skips_a_provider_that_does_not_read() {
    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, |providers| {
        let mut post_only = providers[0].clone();
        post_only.id = "p6".to_string();
        post_only.read = false;
        post_only.post = false;
        providers.insert(0, post_only);
    })
    .await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Done).await;
    assert_eq!(fx.bridge.nntp.connects_to("p6"), 0);

    let drill = fx.post("/drill/scratch/k").await.json();
    assert_eq!(
        (&drill["provider"], &drill["match"]),
        (&json!("p0"), &json!(true))
    );
    assert_eq!(fx.bridge.nntp.connects_to("p6"), 0);
}

#[tokio::test]
async fn object_status_evict_and_drill_after_release() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("slice").await;
    let plain = plaintext();
    // A key with a reserved character, as a client would percent-encode it.
    let o = fx.put(&bucket, "a/big file.bin", &plain).await;
    let path = "slice/a/big%20file.bin";

    let status = fx.get(&format!("/objects/{path}")).await;
    assert_eq!(status.status, 200);
    let v = status.json();
    assert_eq!(v["size"], plain.len());
    assert_eq!(v["extents"].as_array().unwrap().len(), 1);
    let x = &v["extents"][0];
    assert_eq!(x["extent_id"], o.extent.as_str());
    assert_eq!((&x["stage"], &x["attempts"]), (&json!("post"), &json!(0)));
    assert_eq!(
        (&x["safety_state"], &x["cache"]),
        (&json!("held"), &json!("present"))
    );
    assert_eq!(x["backbones"], json!([]));
    // The status view never shows key material.
    let wrapped = hex(&bucket.bdk_wrapped);
    assert!(!status.text().contains(&wrapped) && !status.text().contains("wrapped"));

    fx.drive(&o, OutboxStage::Done).await;
    let v = fx.get(&format!("/objects/{path}")).await.json();
    let x = &v["extents"][0];
    assert_eq!(
        (&x["stage"], &x["safety_state"]),
        (&json!("done"), &json!("released"))
    );
    assert_eq!(x["last_error"], Value::Null);
    let backbone = &x["backbones"][0];
    assert_eq!(backbone["backbone"], "bb0");
    assert_eq!(backbone["provider"], "p0");
    assert_eq!(
        (&backbone["counts"], &backbone["ok"], &backbone["total"]),
        (&json!(true), &json!(3), &json!(3))
    );
    assert!(backbone["at"].as_i64().is_some_and(|at| at > T0.0));

    // Evict: after this the object exists on Usenet only.
    let r = fx.post(&format!("/evict/{path}?include_safety=1")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["evicted"], 1);
    assert!(!fx.has_cache(&o) && !fx.has_safety(&o));
    let v = fx.get(&format!("/objects/{path}")).await.json();
    assert_eq!(v["extents"][0]["cache"], "absent");

    // Drill: read back from Usenet, decrypted and compared.
    let connects = fx.bridge.nntp.connects();
    let slots = "SELECT group_concat(slot || ':' || token || ':' || background) \
                 FROM (SELECT * FROM provider_permits ORDER BY slot)";
    let before = fx.scalar(slots, &[]).await;
    let r = fx.post(&format!("/drill/{path}")).await;
    assert_eq!(r.status, 200);
    // It ran inside a request, so the slot it took was a read's: the
    // short permit, and the short calls.
    let after = fx.scalar(slots, &[]).await;
    let taken: Vec<&str> = after
        .split(',')
        .filter(|slot| !before.split(',').any(|b| b == *slot))
        .collect();
    assert_eq!(taken.len(), 1, "{before} -> {after}");
    assert!(taken[0].ends_with(":0"), "{before} -> {after}");
    let o_cipher_len: u64 = fx
        .scalar("SELECT cipher_size FROM extents", &[])
        .await
        .parse()
        .unwrap();
    let mut v = r.json();
    // The two that are not the same from run to run.
    let state = v.as_object_mut().unwrap().remove("state");
    let generation = v.as_object_mut().unwrap().remove("generation");
    assert!(state.is_some_and(|s| s.is_string()));
    assert_eq!(generation, Some(json!(o.generation.as_str())));
    let digests = json!({
        "bytes": plain.len(),
        "sha256": hex(&sha256(&plain)),
        "md5": hex(&md5::compute(&plain).0),
    });
    assert_eq!(
        v,
        json!({
            "source": "nntp",
            "provider": "p0",
            "providers": { "p0": { "articles": 3, "bytes": o_cipher_len } },
            "articles": 3,
            "extents": 1,
            "size": plain.len(),
            "range": { "first": 0, "last": plain.len() - 1 },
            "plaintext_sha256": digests["sha256"],
            "plaintext_md5": digests["md5"],
            "running": digests,
            "match": true,
            "retries": 0,
            // No provider has drill connections: one connection, taken
            // from the provider's own, whatever the request asks for.
            "sockets": 1,
            "sessions": 1,
        })
    );
    assert!(
        fx.bridge.nntp.connects() > connects,
        "the drill read from NNTP"
    );
    // It filled no cache and restored no pinned copy.
    assert!(fx.bridge.cache.keys().is_empty());
    assert!(fx.bridge.safety.keys().iter().all(|k| k.starts_with("m/")));
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);
    let held = "SELECT COUNT(*) FROM provider_permits WHERE holder IS NOT NULL";
    assert_eq!(fx.scalar(held, &[]).await, "0");

    // An article that is gone is reported, not papered over.
    let id = fx
        .scalar("SELECT message_id FROM articles WHERE idx = 1", &[])
        .await;
    fx.server.hide(&id).await;
    let r = fx.post(&format!("/drill/{path}")).await;
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["match"], false);
    assert_eq!(v["plaintext_sha256"], Value::Null);
    assert!(fx.bridge.cache.keys().is_empty());

    assert_eq!(fx.post("/drill/slice/missing").await.status, 404);
    assert_eq!(fx.post("/drill/nope/k").await.status, 404);
}

type Hook = Rc<dyn Fn(u32) -> futures_util::future::LocalBoxFuture<'static, ()>>;

/// A sleeper for the drill's waits: each one moves the bridge's clock
/// on by its length, counts in `polls`, checks that the drill holds no
/// budget while it waits, and then runs `hook` with the poll's number.
/// Any other sleep is a timer that watches over a call: it never fires.
fn drill_sleeper(
    polls: Rc<Cell<u32>>,
    weak: Rc<RefCell<std::rc::Weak<TestBridge>>>,
    hook: Hook,
) -> impl FnOnce(FixedClock) -> Sleeper {
    move |clock| {
        Rc::new(move |ms| {
            if !(COLD_POLL_MS..=COLD_POLL_MS + COLD_JITTER_MS).contains(&ms) {
                return Box::pin(std::future::pending());
            }
            let (polls, weak, hook, clock) =
                (polls.clone(), weak.clone(), hook.clone(), clock.clone());
            Box::pin(async move {
                let bridge = weak.borrow().upgrade().expect("fixture is alive");
                assert_eq!(bridge.budget.in_use(), 0, "a waiting drill holds budget");
                polls.set(polls.get() + 1);
                clock.advance_ms(i64::from(ms));
                hook(polls.get()).await;
            })
        })
    }
}

/// The fixture with [`drill_sleeper`].
async fn drill_fx(
    polls: &Rc<Cell<u32>>,
    hook: impl FnOnce(Rc<RefCell<std::rc::Weak<TestBridge>>>) -> Hook,
) -> Fx {
    let weak: Rc<RefCell<std::rc::Weak<TestBridge>>> = Rc::default();
    let fx = Fx::with_sleeper(drill_sleeper(
        polls.clone(),
        weak.clone(),
        hook(weak.clone()),
    ))
    .await;
    *weak.borrow_mut() = Rc::downgrade(&fx.bridge);
    fx
}

/// A drill whose read a provider broke off is begun again after a short
/// wait, as a cold read is: one bad moment of a provider or a proxy does
/// not fail a read-back of a large object. One that keeps breaking off
/// ends as `SlowDown` after the same number of tries as a cold read.
#[tokio::test]
async fn a_drill_reads_an_extent_again_after_a_broken_session() {
    for heals in [true, false] {
        let polls = Rc::new(Cell::new(0u32));
        let fx = drill_fx(&polls, |_| Rc::new(|_| Box::pin(async {}))).await;
        let bucket = fx.bucket("scratch").await;
        let o = fx.put(&bucket, "k", &plaintext()).await;
        fx.drive(&o, OutboxStage::Done).await;

        // The first read breaks off on its first article, and on both of
        // its reconnects: the provider is out of that pass.
        let breaks = match heals {
            true => 3,
            false => usize::MAX,
        };
        fx.server.drop_next_bodies(breaks).await;
        let cached = fx.bridge.cache.keys();
        let r = fx.post("/drill/scratch/k").await;
        match heals {
            true => {
                assert_eq!(r.status, 200, "{}", r.text());
                let v = r.json();
                assert_eq!((&v["match"], &v["retries"]), (&json!(true), &json!(1)));
                assert_eq!(v["plaintext_sha256"], hex(&sha256(&o.plain)));
                assert_eq!(polls.get(), 1);
            }
            false => {
                assert_eq!(r.status, 503, "{}", r.text());
                assert!(r.text().contains("SlowDown"));
                assert_eq!(polls.get(), service::INTERRUPTED_RETRIES);
            }
        }
        // Usenet only: nothing was written to the cache.
        assert_eq!(fx.bridge.cache.keys(), cached);
        assert_eq!(fx.bridge.nntp.live(), 0);
        assert_eq!(fx.bridge.budget.in_use(), 0);
        fx.server.drop_next_bodies(0).await;
    }
}

/// While every slot of the providers is held, a drill waits for one, as
/// a cold read does, holding no budget; it answers `SlowDown` once
/// `COLD_WAIT_MS` has passed.
#[tokio::test]
async fn a_drill_waits_for_a_slot_then_slows_down() {
    for frees in [true, false] {
        let polls = Rc::new(Cell::new(0u32));
        let held: Rc<RefCell<Vec<Permit>>> = Rc::default();
        let fx = drill_fx(&polls, |weak| {
            let held = held.clone();
            Rc::new(move |poll| {
                let (held, weak) = (held.clone(), weak.clone());
                Box::pin(async move {
                    // The other holder gives its slots back on the third
                    // poll, or keeps them, renewed, for good.
                    let bridge = weak.borrow().upgrade().expect("fixture is alive");
                    let permits: Vec<Permit> = held.borrow().clone();
                    for permit in &permits {
                        if frees && poll == 3 {
                            bridge.catalog.release_permit(permit).await.unwrap();
                        } else {
                            let now = bridge.clock.now();
                            bridge.catalog.renew_permit(permit, now).await.unwrap();
                        }
                    }
                })
            })
        })
        .await;
        let bucket = fx.bucket("scratch").await;
        let o = fx.put(&bucket, "k", &plaintext()).await;
        fx.drive(&o, OutboxStage::Done).await;
        let p = fx.bridge.cfg.providers[0].clone();
        let now = fx.bridge.clock.now();
        while let Some(permit) = fx
            .bridge
            .catalog
            .acquire_permit(&p, PermitClass::Read, "other", now)
            .await
            .unwrap()
        {
            held.borrow_mut().push(permit);
        }
        assert_eq!(held.borrow().len(), p.max_conns as usize);
        let started = fx.bridge.clock.now();

        let r = fx.post("/drill/scratch/k").await;
        match frees {
            true => {
                assert_eq!(r.status, 200, "{}", r.text());
                let v = r.json();
                assert_eq!((&v["match"], &v["retries"]), (&json!(true), &json!(3)));
                assert_eq!(polls.get(), 3);
            }
            false => {
                assert_eq!(r.status, 503, "{}", r.text());
                assert!(r.text().contains("SlowDown"));
                let waited = fx.bridge.clock.now().0 - started.0;
                assert!(
                    (i64::from(COLD_WAIT_MS)
                        ..i64::from(COLD_WAIT_MS + COLD_POLL_MS + COLD_JITTER_MS))
                        .contains(&waited),
                    "waited {waited} ms"
                );
            }
        }
        assert_eq!(fx.bridge.nntp.live(), 0);
        assert_eq!(fx.bridge.budget.in_use(), 0);
    }
}

/// A provider that refuses the login is not asked again within the
/// drill: one refused login, not one per try. While the provider that
/// has the articles has no free slot, the drill waits for it.
#[tokio::test]
async fn a_drill_asks_a_refusing_provider_once() {
    let polls = Rc::new(Cell::new(0u32));
    let held: Rc<RefCell<Vec<Permit>>> = Rc::default();
    let edit = |providers: &mut Vec<ProviderConfig>| {
        let mut wrong = providers[0].clone();
        wrong.id = "p1".to_string();
        wrong.pass = "not-the-password".to_string();
        wrong.post = false;
        providers.insert(0, wrong);
    };
    let weak: Rc<RefCell<std::rc::Weak<TestBridge>>> = Rc::default();
    let hook: Hook = {
        let (held, weak) = (held.clone(), weak.clone());
        Rc::new(move |poll| {
            let (held, weak) = (held.clone(), weak.clone());
            Box::pin(async move {
                // The reader that has the articles is free from the
                // fourth poll on.
                let bridge = weak.borrow().upgrade().expect("fixture is alive");
                let permits: Vec<Permit> = held.borrow().clone();
                for permit in &permits {
                    match poll {
                        4 => bridge.catalog.release_permit(permit).await.unwrap(),
                        _ => {
                            let now = bridge.clock.now();
                            let _ = bridge.catalog.renew_permit(permit, now).await.unwrap();
                        }
                    }
                }
            })
        })
    };
    let sleeper = drill_sleeper(polls.clone(), weak.clone(), hook);
    let sleeper: Box<dyn FnOnce(FixedClock) -> Sleeper> = Box::new(sleeper);
    let fx = Fx::build(Environment::Dev, Maintenance::Off, edit, Some(sleeper)).await;
    *weak.borrow_mut() = Rc::downgrade(&fx.bridge);
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Done).await;
    let p0 = fx.bridge.cfg.providers[1].clone();
    assert_eq!(p0.id, "p0");
    let now = fx.bridge.clock.now();
    while let Some(permit) = fx
        .bridge
        .catalog
        .acquire_permit(&p0, PermitClass::Read, "other", now)
        .await
        .unwrap()
    {
        held.borrow_mut().push(permit);
    }
    // The verify jobs asked p1 too, and were refused: a clean record.
    let p1 = &fx.bridge.cfg.providers[0];
    fx.bridge
        .catalog
        .provider_recovered(&p1.id, now)
        .await
        .unwrap();
    let dialed = fx.bridge.nntp.dials_to("p1");

    let r = fx.post("/drill/scratch/k").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!((&v["match"], &v["provider"]), (&json!(true), &json!("p0")));
    assert_eq!(v["retries"], 4);
    let refused = fx.bridge.nntp.dials_to("p1") - dialed;
    assert_eq!(refused, 1, "one refused login");
    assert_eq!(health_of(&fx, "p1").await, (json!(false), json!(1)));
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);
}

/// A pass that did not ask a provider (it refused the login earlier in
/// the drill) never makes the drill say the bytes are gone: that
/// provider may hold what the others lack. The drill answers `SlowDown`,
/// not `match: false`.
#[tokio::test]
async fn a_drill_that_skipped_a_refusing_provider_is_never_a_mismatch() {
    let polls = Rc::new(Cell::new(0u32));
    let edit = |providers: &mut Vec<ProviderConfig>| {
        let mut wrong = providers[0].clone();
        wrong.id = "p1".to_string();
        wrong.pass = "not-the-password".to_string();
        wrong.post = false;
        providers.insert(0, wrong);
    };
    let weak: Rc<RefCell<std::rc::Weak<TestBridge>>> = Rc::default();
    let sleeper = drill_sleeper(polls.clone(), weak.clone(), Rc::new(|_| Box::pin(async {})));
    let sleeper: Box<dyn FnOnce(FixedClock) -> Sleeper> = Box::new(sleeper);
    let fx = Fx::build(Environment::Dev, Maintenance::Off, edit, Some(sleeper)).await;
    *weak.borrow_mut() = Rc::downgrade(&fx.bridge);
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Done).await;
    // p0, the reader with the right login, lacks one article.
    let id = fx
        .scalar("SELECT message_id FROM articles WHERE idx = 1", &[])
        .await;
    fx.server.hide(&id).await;
    let dialed = fx.bridge.nntp.dials_to("p1");

    let r = fx.post("/drill/scratch/k").await;
    assert_eq!(r.status, 503, "{}", r.text());
    assert!(r.text().contains("SlowDown"));
    assert!(r.json().get("match").is_none());
    assert_eq!(fx.bridge.nntp.dials_to("p1") - dialed, 1);
    assert_eq!(polls.get(), service::INTERRUPTED_RETRIES);
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);
}

/// Sizes of the extents of [`drill_object`].
const PIECES: [usize; 3] = [700_001, 1_500_003, 300_007];

/// An object of three extents under `scratch/k`, posted, verified and
/// released, then evicted: it exists on Usenet only. Returns its extents
/// and its plaintext.
async fn drill_object(fx: &Fx) -> (Vec<Obj>, Vec<u8>) {
    let bucket = fx.bucket("scratch").await;
    let whole = nntp_support::marked_plaintext(PIECES.iter().sum());
    let (a, rest) = whole.split_at(PIECES[0]);
    let (b, c) = rest.split_at(PIECES[1]);
    let objs = fx.put_extents(&bucket, "k", &[a, b, c]).await;
    for o in &objs {
        fx.drive(o, OutboxStage::Done).await;
    }
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!((r.status, &r.json()["evicted"]), (200, &json!(3)));
    assert_eq!(blobs(fx), 0, "cache and pinned copies are gone");
    (objs, whole)
}

/// The blobs of extents in either store: cached ciphertext and pinned
/// safety copies. The manifests under `m/` are not counted.
fn blobs(fx: &Fx) -> usize {
    let pinned = fx.bridge.safety.keys();
    fx.bridge.cache.keys().len() + pinned.iter().filter(|k| !k.starts_with("m/")).count()
}

fn md5_hex(bytes: &[u8]) -> String {
    hex(&md5::compute(bytes).0)
}

/// Every row a drill could have changed, as one string.
async fn object_rows(fx: &Fx) -> String {
    let mut out = String::new();
    for sql in [
        "SELECT group_concat(id || ':' || state || ':' || safety_state || ':' || plan_rev || ':' \
           || coalesce(last_verified_at, '') || ':' || coalesce(released_at, '') || ':' \
           || coalesce(last_read_at, ''), ',') \
         FROM (SELECT * FROM extents ORDER BY id)",
        "SELECT group_concat(extent_id || ':' || idx || ':' || state, ',') \
         FROM (SELECT * FROM articles ORDER BY extent_id, idx)",
        "SELECT group_concat(extent_id || ':' || stage || ':' || attempts, ',') \
         FROM (SELECT * FROM outbox ORDER BY extent_id)",
        "SELECT group_concat(id || ':' || state, ',') FROM (SELECT * FROM generations ORDER BY id)",
    ] {
        out.push_str(&fx.scalar(sql, &[]).await);
        out.push('|');
    }
    out
}

/// A drill of a byte range reads the extents the bytes are in, whole,
/// and hashes the bytes of the range only. It writes nothing: no blob in
/// either store, and no row of the object.
#[tokio::test]
async fn a_drill_of_a_range_reads_its_extents_and_hashes_its_bytes() {
    let fx = Fx::new().await;
    let (objs, whole) = drill_object(&fx).await;
    let rows = object_rows(&fx).await;
    let articles_of = |extents: &[&Obj]| {
        let ids: Vec<String> = extents
            .iter()
            .map(|o| format!("'{}'", o.extent.as_str()))
            .collect();
        format!(
            "SELECT COUNT(*) FROM articles WHERE extent_id IN ({})",
            ids.join(",")
        )
    };

    // From inside the first extent to inside the second.
    let (first, last) = (650_000usize, 800_000usize);
    let r = fx
        .post(&format!("/drill/scratch/k?range={first}-{last}"))
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    let piece = &whole[first..=last];
    assert_eq!(v["match"], true);
    assert_eq!(v["range"], json!({ "first": first, "last": last }));
    assert_eq!(v["size"], whole.len());
    assert_eq!(v["extents"], 2);
    let expected = fx.scalar(&articles_of(&[&objs[0], &objs[1]]), &[]).await;
    assert_eq!(v["articles"].to_string(), expected);
    assert_eq!(v["plaintext_sha256"], hex(&sha256(piece)));
    assert_eq!(v["plaintext_md5"], md5_hex(piece));
    // A range past byte 0 that was handed no state hands none on: it
    // would stand for these bytes alone.
    assert_eq!((&v["running"], &v["state"]), (&Value::Null, &Value::Null));

    // To the end: the last extent alone. A last byte past the end is the end.
    let from = PIECES[0] + PIECES[1];
    for range in [format!("{from}-"), format!("{from}-99999999999")] {
        let v = fx
            .post(&format!("/drill/scratch/k?range={range}"))
            .await
            .json();
        assert_eq!(
            (&v["match"], &v["extents"]),
            (&json!(true), &json!(1)),
            "{range}"
        );
        assert_eq!(
            v["range"],
            json!({ "first": from, "last": whole.len() - 1 })
        );
        assert_eq!(v["plaintext_md5"], md5_hex(&whole[from..]));
        let expected = fx.scalar(&articles_of(&[&objs[2]]), &[]).await;
        assert_eq!(v["articles"].to_string(), expected);
    }

    // One byte, the last of an extent; and the whole object.
    let at = PIECES[0] - 1;
    let v = fx
        .post(&format!("/drill/scratch/k?range={at}-{at}"))
        .await
        .json();
    assert_eq!((&v["match"], &v["extents"]), (&json!(true), &json!(1)));
    assert_eq!(v["plaintext_md5"], md5_hex(&whole[at..=at]));
    let v = fx.post("/drill/scratch/k").await.json();
    assert_eq!((&v["match"], &v["extents"]), (&json!(true), &json!(3)));
    assert_eq!(v["plaintext_md5"], md5_hex(&whole));
    assert_eq!(v["plaintext_sha256"], hex(&sha256(&whole)));

    // Not a range of the object.
    for range in ["5-4", "a-b", "-5", "7", "1-2-3", "+1-2", ""] {
        let r = fx.post(&format!("/drill/scratch/k?range={range}")).await;
        assert_eq!(r.status, 400, "{range}: {}", r.text());
    }
    let r = fx
        .post(&format!("/drill/scratch/k?range={}-", whole.len()))
        .await;
    assert_eq!(r.status, 416, "{}", r.text());

    // Usenet only, and read only.
    assert_eq!(blobs(&fx), 0);
    assert_eq!(object_rows(&fx).await, rows);
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);
}

/// Ranges read one after the other, each handed the `state` of the one
/// before, end with the MD5 and the SHA-256 of the whole object: what
/// the caller has from the source of the bytes.
#[tokio::test]
async fn ranges_handed_their_state_give_the_digests_of_the_whole() {
    let fx = Fx::new().await;
    let (_, whole) = drill_object(&fx).await;
    // Cuts inside extents, not on their edges.
    let cuts = [0, 1_000_000, 2_300_000, whole.len()];
    let mut state: Option<String> = None;
    let mut last = Value::Null;
    for pair in cuts.windows(2) {
        let (from, to) = (pair[0], pair[1]);
        let state_arg = state.map(|s| format!("&state={s}")).unwrap_or_default();
        let path = format!("/drill/scratch/k?range={from}-{}{state_arg}", to - 1);
        let r = fx.post(&path).await;
        assert_eq!(r.status, 200, "{}", r.text());
        last = r.json();
        assert_eq!(last["match"], true);
        // Of this range alone, and of everything so far.
        assert_eq!(last["plaintext_md5"], md5_hex(&whole[from..to]));
        assert_eq!(last["running"]["bytes"], to);
        assert_eq!(last["running"]["md5"], md5_hex(&whole[..to]));
        state = Some(last["state"].as_str().expect("a state").to_string());
    }
    assert_eq!(
        last["running"],
        json!({ "bytes": whole.len(), "sha256": hex(&sha256(&whole)), "md5": md5_hex(&whole) })
    );

    // A state that is none is refused before anything is read.
    let connects = fx.bridge.nntp.connects();
    for state in ["x", "AAAA", &"A".repeat(600)] {
        let r = fx
            .post(&format!("/drill/scratch/k?range=0-9&state={state}"))
            .await;
        assert_eq!(r.status, 400, "{}", r.text());
    }
    assert_eq!(fx.bridge.nntp.connects(), connects);

    // Nor is the state of other bytes than those before the range: the
    // running digests would be of no object.
    let first = fx.post("/drill/scratch/k?range=0-999999").await.json();
    let state = first["state"].as_str().expect("a state");
    for range in ["0-9", "999999-", "1000001-"] {
        let r = fx
            .post(&format!("/drill/scratch/k?range={range}&state={state}"))
            .await;
        assert_eq!(r.status, 400, "{range}: {}", r.text());
    }
    let connects = fx.bridge.nntp.connects() - connects;
    assert_eq!(connects, 1, "only the range that gave the state was read");
    let r = fx
        .post(&format!("/drill/scratch/k?range=1000000-&state={state}"))
        .await;
    assert_eq!(r.json()["running"]["md5"], md5_hex(&whole));
}

/// A drill of many extents does not hold a request of the same isolate
/// off until it ends: between two extents it gives its room to a charge
/// that waits for it, and reads on after it.
#[tokio::test]
async fn a_drill_lets_a_waiting_request_in_between_extents() {
    use velmora_bridge::ingress::CHARGE_POLL_MS;
    // A wait for room is a short real one; any other sleep is a timer
    // that watches over a call, and never fires.
    let fx = Fx::with_sleeper(|_| {
        Rc::new(|ms| match ms == CHARGE_POLL_MS {
            true => Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1))),
            false => Box::pin(std::future::pending()),
        })
    })
    .await;
    let (_, whole) = drill_object(&fx).await;
    let drilled = Cell::new(false);
    let let_in = Cell::new(false);
    let drill = async {
        let r = fx.post("/drill/scratch/k").await;
        drilled.set(true);
        r
    };
    // Fits alone, and not beside the drill's charge.
    let other = async {
        let charge = fx.bridge.budget.charge(BUDGET - 1024).await;
        let_in.set(charge.is_ok() && !drilled.get());
    };
    let (r, ()) = tokio::join!(drill, other);
    assert!(let_in.get(), "the request waited for the whole drill");
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!((&v["match"], &v["extents"]), (&json!(true), &json!(3)));
    assert_eq!(v["plaintext_md5"], md5_hex(&whole));
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);
}

/// A drill logs in once and reads every extent over that session: not
/// once per extent.
#[tokio::test]
async fn a_drill_keeps_its_session_from_one_extent_to_the_next() {
    let fx = Fx::new().await;
    let (_, whole) = drill_object(&fx).await;
    let connects = fx.bridge.nntp.connects();
    let r = fx.post("/drill/scratch/k").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!((&v["match"], &v["extents"]), (&json!(true), &json!(3)));
    assert_eq!(v["plaintext_md5"], md5_hex(&whole));
    assert_eq!(v["sessions"], 1);
    assert_eq!(
        fx.bridge.nntp.connects() - connects,
        1,
        "one login for three extents"
    );
    assert_eq!(fx.bridge.nntp.live(), 0);
}

/// Two readers on the fixture server, each with `drill_conns` drill
/// connections; `p1` is of a lower tier, as a provider kept for
/// fallback is.
fn two_drill_providers(drill_conns: u32) -> impl FnOnce(&mut Vec<ProviderConfig>) {
    move |providers| {
        providers[0].drill_conns = drill_conns;
        let mut other = providers[0].clone();
        other.id = "p1".to_string();
        other.post = false;
        other.priority = 2;
        providers.push(other);
    }
}

const SLOTS: &str = "SELECT group_concat(provider_id || ':' || slot || ':' || token || ':' \
                       || (lease_until > 0), ',') \
                     FROM (SELECT * FROM provider_permits WHERE provider_id IN ('p0', 'p1') \
                           ORDER BY provider_id, slot)";

/// With drill connections the drill reads over several sockets, on the
/// providers of every tier at once, and takes no slot a read or a job
/// could have had: here every such slot is held by others, and the drill
/// neither waits nor changes one.
#[tokio::test]
async fn a_drill_reads_over_the_drill_connections_of_every_provider() {
    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, two_drill_providers(2)).await;
    let (_, whole) = drill_object(&fx).await;
    let now = fx.bridge.clock.now();
    for p in &fx.bridge.cfg.providers {
        let catalog = &fx.bridge.catalog;
        while let Ok(Some(_)) = catalog
            .acquire_permit(p, PermitClass::Read, "other", now)
            .await
        {}
    }
    let before = fx.scalar(SLOTS, &[]).await;
    assert_eq!(before.matches(":1,").count() + 1, 4, "{before}");

    let connects = fx.bridge.nntp.connects();
    let r = fx.post("/drill/scratch/k?sockets=4").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!((&v["match"], &v["retries"]), (&json!(true), &json!(0)));
    assert_eq!(v["plaintext_md5"], md5_hex(&whole));
    assert_eq!(v["plaintext_sha256"], hex(&sha256(&whole)));
    assert_eq!(v["sockets"], 4);
    // Both providers supplied articles, whatever their tier.
    let share = v["providers"].as_object().unwrap();
    assert!(
        share.contains_key("p0") && share.contains_key("p1"),
        "{share:?}"
    );
    let supplied: u64 = share
        .values()
        .map(|p| p["articles"].as_u64().unwrap())
        .sum();
    assert_eq!(supplied, v["articles"].as_u64().unwrap());
    // Never more slots than sockets, and never more logins than slots:
    // the connections were kept from extent to extent.
    let sessions = v["sessions"].as_u64().unwrap();
    assert!((2..=4).contains(&sessions), "{sessions}");
    let logins = u64::from(fx.bridge.nntp.connects() - connects);
    assert!((2..=sessions).contains(&logins), "{logins} of {sessions}");

    // The slots of reads and jobs: not one taken, renewed or freed.
    assert_eq!(fx.scalar(SLOTS, &[]).await, before);
    // The drill's own: at most `drill_conns` per provider, all free again.
    let drill = "SELECT provider_id || ':' || COUNT(*) || ':' || SUM(lease_until > 0) \
                 FROM provider_permits WHERE provider_id LIKE '%/drill' GROUP BY provider_id \
                 ORDER BY provider_id";
    let rows = fx.bridge.catalog.sql.query(drill, &[]).await.unwrap();
    let rows: Vec<String> = rows
        .into_iter()
        .map(|r| match &r[0] {
            SqlValue::Text(s) => s.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(rows, ["p0/drill:2:0", "p1/drill:2:0"]);
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);
}

/// `sockets` is a number from 1 to `COLD_SOCKETS`.
#[tokio::test]
async fn a_drill_refuses_a_socket_count_out_of_range() {
    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, two_drill_providers(2)).await;
    let (_, whole) = drill_object(&fx).await;
    for sockets in ["0", "5", "-1", "x", ""] {
        let r = fx
            .post(&format!("/drill/scratch/k?sockets={sockets}"))
            .await;
        assert_eq!(r.status, 400, "{sockets}: {}", r.text());
    }
    let v = fx.post("/drill/scratch/k?sockets=1").await.json();
    assert_eq!((&v["sockets"], &v["sessions"]), (&json!(1), &json!(1)));
    assert_eq!(v["plaintext_md5"], md5_hex(&whole));
}

/// A session that a provider breaks off in the middle of a drill over
/// several sockets costs the drill nothing but that session: the article
/// is read again, and the digests are those of the object.
#[tokio::test]
async fn a_drill_over_several_sockets_outlives_a_broken_session() {
    let polls = Rc::new(Cell::new(0u32));
    let weak: Rc<RefCell<std::rc::Weak<TestBridge>>> = Rc::default();
    let sleeper = drill_sleeper(polls.clone(), weak.clone(), Rc::new(|_| Box::pin(async {})));
    let sleeper: Box<dyn FnOnce(FixedClock) -> Sleeper> = Box::new(sleeper);
    let edit = two_drill_providers(2);
    let fx = Fx::build(Environment::Dev, Maintenance::Off, edit, Some(sleeper)).await;
    *weak.borrow_mut() = Rc::downgrade(&fx.bridge);
    let (_, whole) = drill_object(&fx).await;
    for breaks in [1, 2] {
        fx.server.drop_next_bodies(breaks).await;
        let r = fx.post("/drill/scratch/k?sockets=4").await;
        assert_eq!(r.status, 200, "{}", r.text());
        let v = r.json();
        assert_eq!(v["match"], true, "{v}");
        assert_eq!(v["plaintext_md5"], md5_hex(&whole));
        assert_eq!(v["plaintext_sha256"], hex(&sha256(&whole)));
        assert_eq!(fx.bridge.nntp.live(), 0);
        assert_eq!(fx.bridge.budget.in_use(), 0);
        // The slots of the sessions that broke are free as well.
        let held = "SELECT COUNT(*) FROM provider_permits WHERE lease_until > 0";
        assert_eq!(fx.scalar(held, &[]).await, "0");
    }
    assert_eq!(blobs(&fx), 0);
}

/// A catalogue statement that fails under a drill does not make the
/// drill a `500`. During the read the extent is read again, with the
/// tries of a broken session; a catalogue that keeps failing, there or
/// before the read began, is answered `503` with its class, which a
/// caller retries.
#[tokio::test]
async fn a_catalogue_failure_under_a_drill_is_retried_then_a_slow_down() {
    // The article rows of an extent; the renewal of a session's slot.
    for part in ["FROM articles", "SET lease_until = ?5"] {
        for heals in [true, false] {
            let polls = Rc::new(Cell::new(0u32));
            let fx = drill_fx(&polls, |_| Rc::new(|_| Box::pin(async {}))).await;
            let (_, whole) = drill_object(&fx).await;
            let fail = &fx.bridge.catalog.sql.fail;
            *fail.borrow_mut() = Some((part, if heals { 1 } else { u32::MAX }));
            let r = fx.post("/drill/scratch/k").await;
            let left = fail.borrow_mut().take().map(|f| f.1);
            match heals {
                true => {
                    assert_eq!(r.status, 200, "{part}: {}", r.text());
                    assert_eq!(left, Some(0), "{part}: the statement was not run");
                    let v = r.json();
                    assert_eq!((&v["match"], &v["retries"]), (&json!(true), &json!(1)));
                    assert_eq!(v["plaintext_md5"], md5_hex(&whole));
                    assert_eq!(polls.get(), 1);
                }
                false => {
                    assert_eq!(r.status, 503, "{part}: {}", r.text());
                    let v = r.json();
                    assert_eq!(
                        (&v["error"], &v["class"]),
                        (&json!("SlowDown"), &json!("catalog"))
                    );
                    assert!(v.get("match").is_none());
                    assert_eq!(polls.get(), service::INTERRUPTED_RETRIES);
                }
            }
            assert_eq!(fx.bridge.nntp.live(), 0, "{part}");
            assert_eq!(fx.bridge.budget.in_use(), 0, "{part}");
        }
    }

    // A row that cannot be read is no reason to ask again: it stays a
    // `500`, at once, so that it is seen.
    let polls = Rc::new(Cell::new(0u32));
    let fx = drill_fx(&polls, |_| Rc::new(|_| Box::pin(async {}))).await;
    drill_object(&fx).await;
    let sql = &fx.bridge.catalog.sql;
    let n = sql.exec("UPDATE articles SET cipher_len = 'x'", &[]).await;
    assert!(n.unwrap() > 0);
    let r = fx.post("/drill/scratch/k").await;
    assert_eq!(r.status, 500, "{}", r.text());
    assert_eq!(r.json()["class"], "catalog");
    assert_eq!(polls.get(), 0);
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);

    // Before anything is read: whether a replay is pending, the bucket,
    // the generation, the extents.
    let fx = Fx::new().await;
    drill_object(&fx).await;
    for part in [
        "FROM restore_state",
        "FROM buckets",
        "FROM objects o JOIN generations",
        "FROM generation_extents",
    ] {
        let connects = fx.bridge.nntp.connects();
        *fx.bridge.catalog.sql.fail.borrow_mut() = Some((part, 1));
        let r = fx.post("/drill/scratch/k").await;
        let left = fx.bridge.catalog.sql.fail.borrow_mut().take().map(|f| f.1);
        assert_eq!(left, Some(0), "{part}: the statement was not run");
        assert_eq!(r.status, 503, "{part}: {}", r.text());
        assert_eq!(r.json()["class"], "catalog", "{part}");
        assert_eq!(fx.bridge.nntp.connects(), connects);
    }
}

/// An empty object has an extent on Usenet too, and the drill reads it:
/// `match` is never said of an object nothing was asked for.
#[tokio::test]
async fn a_drill_of_an_empty_object_reads_its_extent() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", b"").await;
    fx.drive(&o, OutboxStage::Done).await;
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let connects = fx.bridge.nntp.connects();

    let r = fx.post("/drill/scratch/k").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!((&v["match"], &v["size"]), (&json!(true), &json!(0)));
    assert_eq!((&v["extents"], &v["articles"]), (&json!(1), &json!(1)));
    assert_eq!(v["range"], Value::Null);
    assert_eq!(v["plaintext_md5"], md5_hex(b""));
    assert_eq!(v["plaintext_sha256"], hex(&sha256(b"")));
    assert_eq!(fx.bridge.nntp.connects(), connects + 1);

    // Its article gone from Usenet: not a match.
    fx.server.set_hidden(fx.server.posted_ids().await).await;
    let v = fx.post("/drill/scratch/k").await.json();
    assert_eq!(v["match"], false, "{v}");
    assert_eq!(v["plaintext_md5"], Value::Null);
}

/// A drill with several drill connections on an account that refuses
/// the login asks it once, not once per connection: one strike, and the
/// other provider reads the object over its own.
#[tokio::test]
async fn a_drill_logs_in_once_before_it_opens_more_connections() {
    let edit = |providers: &mut Vec<ProviderConfig>| {
        providers[0].drill_conns = 4;
        let mut wrong = providers[0].clone();
        wrong.id = "p1".to_string();
        wrong.pass = "not-the-password".to_string();
        wrong.post = false;
        providers.push(wrong);
    };
    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, edit).await;
    // One extent of several articles: work for several connections.
    let bucket = fx.bucket("scratch").await;
    let whole = nntp_support::marked_plaintext(2_500_000);
    let o = fx.put(&bucket, "k", &whole).await;
    fx.drive(&o, OutboxStage::Done).await;
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.status, 200, "{}", r.text());
    // The verify jobs asked p1 too, and were refused until it cooled:
    // past the cooldown, a clean record.
    fx.bridge.clock.advance_secs(3600);
    let now = fx.bridge.clock.now();
    let p1 = &fx.bridge.cfg.providers[1];
    fx.bridge
        .catalog
        .provider_recovered(&p1.id, now)
        .await
        .unwrap();
    let (dialed, good) = (
        fx.bridge.nntp.dials_to("p1"),
        fx.bridge.nntp.connects_to("p0"),
    );

    let r = fx.post("/drill/scratch/k?sockets=4").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!((&v["match"], &v["provider"]), (&json!(true), &json!("p0")));
    assert_eq!(v["plaintext_md5"], md5_hex(&whole));
    assert_eq!(
        fx.bridge.nntp.dials_to("p1") - dialed,
        1,
        "one refused login"
    );
    assert_eq!(health_of(&fx, "p1").await, (json!(false), json!(1)));
    // The provider that took the first login was given more: as many
    // as an extent has articles, of its four.
    let more = fx.bridge.nntp.connects_to("p0") - good;
    assert!((2..=4).contains(&more), "{more}");
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);
}

/// Before a drill says the bytes are gone it asks every reader, also
/// one past the retention it states: here the reader that states enough
/// refuses the login, and the other, two days past its one day, has
/// every article.
#[tokio::test]
async fn a_drill_asks_a_reader_past_its_stated_retention() {
    let edit = |providers: &mut Vec<ProviderConfig>| {
        providers[0].retention_days = Some(1);
        let mut wrong = providers[0].clone();
        wrong.id = "p1".to_string();
        wrong.pass = "not-the-password".to_string();
        wrong.post = false;
        wrong.retention_days = None;
        providers.push(wrong);
    };
    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, edit).await;
    let (_, whole) = drill_object(&fx).await;
    fx.bridge.clock.advance_secs(2 * 24 * 3600);

    let r = fx.post("/drill/scratch/k").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!((&v["match"], &v["provider"]), (&json!(true), &json!("p0")));
    assert_eq!(v["plaintext_md5"], md5_hex(&whole));
    assert_eq!(fx.bridge.nntp.live(), 0);
}

/// "Not on Usenet" is said of the live object only. One that was
/// deleted while the drill read it (here during the wait after a broken
/// read) is asked for again: its rows and articles may have been taken
/// away under the drill. The same article gone from the object that is
/// still live is the mismatch it is.
#[tokio::test]
async fn a_drill_of_an_object_replaced_under_it_is_not_a_mismatch() {
    for replaced in [true, false] {
        let polls = Rc::new(Cell::new(0u32));
        let fx = drill_fx(&polls, |weak| {
            Rc::new(move |_| {
                let weak = weak.clone();
                Box::pin(async move {
                    let bridge = weak.borrow().upgrade().expect("fixture is alive");
                    if replaced {
                        let n = bridge.catalog.sql.exec("DELETE FROM objects", &[]).await;
                        assert_eq!(n.unwrap(), 1);
                    }
                })
            })
        })
        .await;
        let bucket = fx.bucket("scratch").await;
        let o = fx.put(&bucket, "k", &plaintext()).await;
        fx.drive(&o, OutboxStage::Done).await;
        let id = fx
            .scalar("SELECT message_id FROM articles WHERE idx = 1", &[])
            .await;
        fx.server.hide(&id).await;
        // The first read breaks off: the drill waits, then reads again
        // and finds the article gone.
        fx.server.drop_next_bodies(3).await;
        let r = fx.post("/drill/scratch/k").await;
        assert_eq!(polls.get(), 1);
        match replaced {
            true => {
                assert_eq!(r.status, 503, "{}", r.text());
                assert!(r.json().get("match").is_none());
            }
            false => {
                assert_eq!(r.status, 200, "{}", r.text());
                assert_eq!(r.json()["match"], false);
            }
        }
        assert_eq!(fx.bridge.nntp.live(), 0);
        assert_eq!(fx.bridge.budget.in_use(), 0);
    }
}

/// A first login that breaks off is one of the connects a pass may
/// spend on a provider, not one more: after three that broke, the
/// provider is out of the pass, and the drill reads again after its
/// wait.
#[tokio::test]
async fn a_drill_counts_a_broken_first_login_among_its_reconnects() {
    let polls = Rc::new(Cell::new(0u32));
    let fx = drill_fx(&polls, |_| Rc::new(|_| Box::pin(async {}))).await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Done).await;
    let dialed = fx.bridge.nntp.dials_to("p0");
    fx.server.drop_next_logins(3).await;
    let r = fx.post("/drill/scratch/k").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v = r.json();
    assert_eq!((&v["match"], &v["retries"]), (&json!(true), &json!(1)));
    assert_eq!(polls.get(), 1);
    assert_eq!(fx.bridge.nntp.dials_to("p0") - dialed, 4);
    assert_eq!(fx.bridge.nntp.live(), 0);
    assert_eq!(fx.bridge.budget.in_use(), 0);
}

#[tokio::test]
async fn drill_refuses_an_object_that_was_never_posted() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    fx.put(&bucket, "k", b"payload").await;
    let r = fx.post("/drill/scratch/k").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["match"], false);
    assert_eq!(r.json()["articles"], 0);
    assert_eq!(fx.bridge.nntp.connects(), 0);
}

#[tokio::test]
async fn evict_keeps_the_pinned_copy_while_a_release_is_running() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Release).await;
    // A release job has decided and is reading the copy for its last check.
    let id = [text(o.extent.as_str())];
    let sql = &fx.bridge.catalog.sql;
    sql.exec(
        "UPDATE extents SET safety_state = 'releasing' WHERE id = ?1",
        &id,
    )
    .await
    .unwrap();

    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 1 })
    );
    assert!(fx.has_safety(&o), "the release job still needs the copy");
    assert_eq!(fx.safety_state(&o).await, "releasing");
}

#[tokio::test]
async fn evict_keeps_the_pinned_copy_when_it_loses_the_state_race() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Release).await;
    assert_eq!(fx.safety_state(&o).await, "held");

    // Between the evict's read and its write, a release job takes the copy.
    *fx.bridge.catalog.sql.race.borrow_mut() = Some("releasing");
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 1 })
    );
    assert!(
        fx.bridge.catalog.sql.race.borrow().is_none(),
        "the race ran"
    );
    assert!(fx.has_safety(&o), "the loser deletes nothing");
    assert_eq!(fx.safety_state(&o).await, "releasing");
}

#[tokio::test]
async fn evict_keeps_the_pinned_copy_of_an_extent_being_reposted() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Release).await;
    // Back at the post stage: the old read-back is on record, but the
    // post job is about to read the pinned copy again.
    let id = [text(o.extent.as_str())];
    let sql = &fx.bridge.catalog.sql;
    sql.exec("UPDATE outbox SET stage = 'post' WHERE extent_id = ?1", &id)
        .await
        .unwrap();

    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 1 })
    );
    assert!(fx.has_safety(&o));
    assert_eq!(fx.safety_state(&o).await, "held");
}

#[tokio::test]
async fn evict_ignores_a_read_back_from_a_backbone_no_longer_configured() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Release).await;
    // The only read-back is from a backbone the configuration dropped.
    let sql = &fx.bridge.catalog.sql;
    sql.exec("UPDATE verifications SET backbone = 'gone'", &[])
        .await
        .unwrap();

    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 1 })
    );
    assert!(fx.has_safety(&o));
    assert_eq!(fx.safety_state(&o).await, "held");

    // The same backbone under another spelling is still the same backbone.
    sql.exec("UPDATE verifications SET backbone = ' BB0 '", &[])
        .await
        .unwrap();
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.json()["safety_deleted"], 1);
    assert!(!fx.has_safety(&o));
}

/// Status lists each provider's health by id and backbone, and nothing
/// that identifies the account behind it.
#[tokio::test]
async fn status_reports_provider_health_without_credentials() {
    let fx = Fx::new().await;
    let now = fx.bridge.clock.now();
    let p = fx.bridge.cfg.providers[0].clone();

    let r = fx.get("/status").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let providers = r.json()["providers"].clone();
    assert_eq!(providers.as_array().unwrap().len(), 1);
    let one = &providers[0];
    assert_eq!(one["id"], p.id.as_str());
    assert_eq!(one["backbone"], p.backbone.as_str());
    assert_eq!(
        (one["priority"].as_u64(), one["enabled"].as_bool()),
        (Some(0), Some(true))
    );
    assert_eq!(
        (one["held"].as_u64(), one["failures"].as_u64()),
        (Some(0), Some(0))
    );
    assert_eq!(one["cooling"], false);
    assert_eq!(
        (&one["healthy"], &one["reason"]),
        (&json!(true), &json!(null))
    );
    // The limits, as configured: no address limit is `null`.
    assert_eq!(one["max_conns"], p.max_conns);
    assert!(one["max_ips"].is_null());
    assert_eq!(one["release"], true);
    assert_eq!(one["holders"], 0);

    // A held slot and three failed sessions show up.
    let permit = fx
        .bridge
        .catalog
        .acquire_permit(&p, PermitClass::Read, "t", now)
        .await
        .unwrap()
        .unwrap();
    // The first strike already shows, with its reason as a code.
    let failed = |fault| fx.bridge.catalog.provider_failed(&p.id, fault, now);
    failed(ProviderFault::SessionFailed).await.unwrap();
    let one = fx.get("/status").await.json()["providers"][0].clone();
    assert_eq!(
        (&one["failures"], &one["cooling"]),
        (&json!(1), &json!(false))
    );
    assert_eq!(
        (&one["healthy"], &one["reason"]),
        (&json!(false), &json!("session_failed"))
    );
    for _ in 0..2 {
        failed(ProviderFault::LoginRefused).await.unwrap();
    }
    let r = fx.get("/status").await;
    let one = r.json()["providers"][0].clone();
    assert_eq!((&one["held"], &one["holders"]), (&json!(1), &json!(1)));
    assert_eq!(one["cooling"], true);
    assert_eq!(one["cooldown_until"], now.0 + 60_000);
    assert_eq!(
        (&one["healthy"], &one["reason"]),
        (&json!(false), &json!("login_refused"))
    );
    let body = r.text();
    for secret in [p.user.as_str(), p.pass.as_str(), p.host.as_str()] {
        assert!(!body.contains(secret), "status leaks provider details");
    }
    fx.bridge.catalog.release_permit(&permit).await.unwrap();
}

// ---------------------------------------------------------------------------
// Provider probes
// ---------------------------------------------------------------------------

/// `(healthy, failures)` of provider `id` in the status.
async fn health_of(fx: &Fx, id: &str) -> (Value, Value) {
    let status = fx.get("/status").await.json();
    let one = status["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
        .unwrap()
        .clone();
    (one["healthy"].clone(), one["failures"].clone())
}

/// A provider whose strikes stay below the cooldown threshold, and that
/// nothing picks, recovers by a probe once it has been quiet: one
/// session, given back, and no client read. The probe asks nothing of a
/// healthy provider.
#[tokio::test]
async fn a_provider_whose_strikes_nothing_clears_recovers_by_a_probe() {
    use velmora_bridge::probe::{Probed, PROBE_QUIET_MS};
    let fx = Fx::new().await;
    let b = &fx.bridge;
    let now = b.clock.now();
    for _ in 0..2 {
        let failed = b
            .catalog
            .provider_failed("p0", ProviderFault::SessionFailed, now);
        failed.await.unwrap();
    }
    assert_eq!(health_of(&fx, "p0").await, (json!(false), json!(2)));

    // Struck just now: not yet.
    assert!(b.probe_providers().await.unwrap().is_empty());
    b.clock.advance_ms(PROBE_QUIET_MS - 1);
    assert!(b.probe_providers().await.unwrap().is_empty());
    assert_eq!(b.nntp.connects(), 0);

    b.clock.advance_ms(1);
    let probed = b.probe_providers().await.unwrap();
    assert_eq!(probed, [("p0".to_string(), Probed::Recovered)]);
    assert_eq!(b.nntp.connects_to("p0"), 1);
    assert_eq!(b.nntp.live(), 0);
    assert_eq!(health_of(&fx, "p0").await, (json!(true), json!(0)));
    let held = fx.get("/status").await.json()["providers"][0]["held"].clone();
    assert_eq!(held, 0, "the probe gave its slot back");

    // Healthy now: nothing to ask.
    b.clock.advance_ms(PROBE_QUIET_MS);
    assert!(b.probe_providers().await.unwrap().is_empty());
    assert_eq!(b.nntp.connects(), 1);
}

/// A probe that fails is one more strike, with its reason, and the
/// quiet time starts again; a later probe that goes well clears them.
#[tokio::test]
async fn a_failed_probe_is_one_more_strike() {
    use velmora_bridge::probe::{Probed, PROBE_QUIET_MS};
    let fx = Fx::new().await;
    let b = &fx.bridge;
    let failed = b
        .catalog
        .provider_failed("p0", ProviderFault::SessionFailed, b.clock.now());
    failed.await.unwrap();
    b.clock.advance_ms(PROBE_QUIET_MS);

    fx.server.drop_next_stats(1).await;
    let probed = b.probe_providers().await.unwrap();
    let fault = Probed::Failed(ProviderFault::SessionFailed);
    assert_eq!(probed, [("p0".to_string(), fault)]);
    assert_eq!(health_of(&fx, "p0").await, (json!(false), json!(2)));
    assert!(b.probe_providers().await.unwrap().is_empty());

    b.clock.advance_ms(PROBE_QUIET_MS);
    let probed = b.probe_providers().await.unwrap();
    assert_eq!(probed, [("p0".to_string(), Probed::Recovered)]);
    assert_eq!(health_of(&fx, "p0").await, (json!(true), json!(0)));
    assert_eq!(b.nntp.live(), 0);
}

/// Only an enabled provider is probed, and only under a slot of its
/// own: one whose slots are all held is left as it is. A provider that
/// only posts is asked for its login and nothing else.
#[tokio::test]
async fn a_probe_needs_an_enabled_provider_and_a_free_slot() {
    use velmora_bridge::probe::{Probed, PROBE_QUIET_MS};
    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, |providers| {
        let mut off = providers[0].clone();
        off.id = "p1".to_string();
        off.enabled = false;
        let mut poster = providers[0].clone();
        poster.id = "p2".to_string();
        poster.read = false;
        providers.extend([off, poster]);
    })
    .await;
    let b = &fx.bridge;
    let now = b.clock.now();
    for id in ["p0", "p1", "p2"] {
        let failed = b
            .catalog
            .provider_failed(id, ProviderFault::SessionFailed, now);
        failed.await.unwrap();
    }
    b.clock.advance_ms(PROBE_QUIET_MS);
    let now = b.clock.now();
    let p0 = b.cfg.providers[0].clone();
    let mut held = Vec::new();
    while let Some(permit) = b
        .catalog
        .acquire_permit(&p0, PermitClass::Read, "other", now)
        .await
        .unwrap()
    {
        held.push(permit);
    }
    // A `STAT` now would break the connection: the poster is not asked one.
    fx.server.drop_next_stats(1).await;

    let probed = b.probe_providers().await.unwrap();
    assert_eq!(
        probed,
        [
            ("p0".to_string(), Probed::NoSlot),
            ("p2".to_string(), Probed::Recovered),
        ]
    );
    assert_eq!((b.nntp.connects_to("p0"), b.nntp.connects_to("p1")), (0, 0));
    assert_eq!(health_of(&fx, "p0").await, (json!(false), json!(1)));
    assert_eq!(health_of(&fx, "p1").await, (json!(false), json!(1)));
    assert_eq!(health_of(&fx, "p2").await, (json!(true), json!(0)));
    for permit in &held {
        b.catalog.release_permit(permit).await.unwrap();
    }
}

/// Under `MAINTENANCE=restore`, and while a replay is not finished,
/// nothing is probed, as the dispatcher sends nothing then either.
#[tokio::test]
async fn no_probe_under_restore_maintenance_or_during_a_replay() {
    for maintenance in [Maintenance::Restore, Maintenance::Off] {
        let fx = Fx::with(Environment::Dev, maintenance).await;
        let b = &fx.bridge;
        let failed = b
            .catalog
            .provider_failed("p0", ProviderFault::SessionFailed, b.clock.now());
        failed.await.unwrap();
        b.clock.advance_ms(velmora_bridge::probe::PROBE_QUIET_MS);
        if maintenance == Maintenance::Off {
            let arm = "INSERT INTO restore_state(id, state, since_ms, started_at) \
                       VALUES (1, 'replaying', -1, 0)";
            b.catalog.sql.exec(arm, &[]).await.unwrap();
        }
        assert!(b.probe_providers().await.unwrap().is_empty());
        assert_eq!(b.nntp.connects(), 0);
    }
}

/// A provider whose last strike was a refused login is probed only after
/// the long quiet time: each probe is one more refused login on the
/// account's record. A refused probe is that strike again, with its
/// reason, and the long quiet time starts over.
#[tokio::test]
async fn a_refused_login_is_probed_after_hours_only() {
    use velmora_bridge::probe::{Probed, LOGIN_REFUSED_QUIET_MS, PROBE_QUIET_MS};
    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, |providers| {
        let mut wrong = providers[0].clone();
        wrong.id = "p1".to_string();
        wrong.pass = "not-the-password".to_string();
        providers.push(wrong);
    })
    .await;
    let b = &fx.bridge;
    let refused = b
        .catalog
        .provider_failed("p1", ProviderFault::LoginRefused, b.clock.now());
    refused.await.unwrap();

    b.clock.advance_ms(PROBE_QUIET_MS);
    assert!(b.probe_providers().await.unwrap().is_empty());
    b.clock.advance_ms(LOGIN_REFUSED_QUIET_MS - PROBE_QUIET_MS);
    let probed = b.probe_providers().await.unwrap();
    let fault = Probed::Failed(ProviderFault::LoginRefused);
    assert_eq!(probed, [("p1".to_string(), fault)]);
    assert_eq!(b.nntp.dials_to("p1"), 1);
    assert_eq!(health_of(&fx, "p1").await, (json!(false), json!(2)));

    b.clock.advance_ms(LOGIN_REFUSED_QUIET_MS - 1);
    assert!(b.probe_providers().await.unwrap().is_empty());
    assert_eq!(b.nntp.dials_to("p1"), 1);
    assert_eq!(b.nntp.live(), 0);
}

/// The status says how each provider is reached: directly or through
/// its proxies. When the proxies cannot be used the provider is not
/// healthy, for the reason `proxy_failed`. Nothing of a proxy (host,
/// port, login) is in the status.
#[tokio::test]
async fn status_reports_the_route_and_a_proxy_failure() {
    let fx = Fx::new().await;
    let one = fx.get("/status").await.json()["providers"][0].clone();
    assert_eq!(one["route"], "direct");

    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, |providers| {
        providers[0].proxies = vec![serde_json::from_value(json!({
            "host": "status-proxy.example", "port": 41234,
            "user": "status-proxy-login", "pass": "status-proxy-secret"
        }))
        .unwrap()];
    })
    .await;
    let now = fx.bridge.clock.now();
    let one = fx.get("/status").await.json()["providers"][0].clone();
    assert_eq!(
        (&one["route"], &one["healthy"], &one["reason"]),
        (&json!("proxy"), &json!(true), &json!(null))
    );

    let p = fx.bridge.cfg.providers[0].clone();
    let failed = fx
        .bridge
        .catalog
        .provider_failed(&p.id, ProviderFault::ProxyFailed, now);
    failed.await.unwrap();
    let r = fx.get("/status").await;
    let one = r.json()["providers"][0].clone();
    assert_eq!(
        (&one["route"], &one["healthy"], &one["reason"]),
        (&json!("proxy"), &json!(false), &json!("proxy_failed"))
    );
    let body = r.text();
    for secret in [
        "status-proxy.example",
        "41234",
        "status-proxy-login",
        "status-proxy-secret",
    ] {
        assert!(!body.contains(secret), "status leaks proxy details");
    }
}

/// The address limit of a provider and the number of jobs and requests
/// that hold slots there are in the status.
#[tokio::test]
async fn status_reports_the_address_limit_and_its_holders() {
    let mut fx = Fx::new().await;
    Rc::get_mut(&mut fx.bridge)
        .expect("one owner")
        .cfg
        .providers[0]
        .max_ips = Some(2);
    let now = fx.bridge.clock.now();
    let p = fx.bridge.cfg.providers[0].clone();
    for holder in ["a", "a", "b"] {
        let permit = fx
            .bridge
            .catalog
            .acquire_permit(&p, PermitClass::Read, holder, now);
        // Two slots in the fixture: the third is refused.
        assert_eq!(permit.await.unwrap().is_some(), holder == "a");
    }
    let one = fx.get("/status").await.json()["providers"][0].clone();
    assert_eq!(one["max_ips"], 2);
    assert_eq!((&one["held"], &one["holders"]), (&json!(2), &json!(1)));
}

/// A `STAT` pass says the backbone lists the articles, not that it serves
/// them: it is no reason to give up the pinned copy.
#[tokio::test]
async fn evict_keeps_the_pinned_copy_when_the_only_pass_is_a_stat() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Release).await;
    let status = fx.get("/objects/scratch/k").await.json();
    let backbone = &status["extents"][0]["backbones"][0];
    assert_eq!(
        (&backbone["kind"], &backbone["counts"]),
        (&json!("body"), &json!(true))
    );

    let sql = &fx.bridge.catalog.sql;
    // As a `STAT` pass is stored: its tally in `articles_present`.
    sql.exec(
        "UPDATE verifications SET kind = 'stat', articles_present = articles_ok, articles_ok = 0",
        &[],
    )
    .await
    .unwrap();
    let status = fx.get("/objects/scratch/k").await.json();
    let backbone = &status["extents"][0]["backbones"][0];
    assert_eq!(
        (&backbone["kind"], &backbone["counts"]),
        (&json!("stat"), &json!(true))
    );

    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 1 })
    );
    assert!(fx.has_safety(&o));
    assert_eq!(fx.safety_state(&o).await, "held");

    // Read in full again: the copy can go.
    sql.exec(
        "UPDATE verifications SET kind = 'body', articles_ok = articles_present, articles_present = 0",
        &[],
    )
    .await
    .unwrap();
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.json()["safety_deleted"], 1);
    assert!(!fx.has_safety(&o));
}

/// Fewer backbones count toward a release than `REQUIRED_BACKBONES`: the
/// Worker serves as before, the status says that the release is paused,
/// and no pinned copy is given up, read back in full or not.
#[tokio::test]
async fn too_few_release_backbones_are_a_warning_and_keep_the_pinned_copy() {
    let mut fx = Fx::new().await;
    let status = fx.get("/status").await.json();
    assert_eq!(status["config_warnings"], json!([]));

    Rc::get_mut(&mut fx.bridge).unwrap().cfg.required_backbones = 2;
    let status = fx.get("/status").await.json();
    assert_eq!(
        status["config_warnings"],
        json!(["release paused: 1 backbone(s) count toward release, \
                REQUIRED_BACKBONES is 2; pinned copies stay held"])
    );

    // Writes and reads go on, and the upload is read back in full.
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Done).await;
    assert_eq!(fx.safety_state(&o).await, "held");
    let status = fx.get("/objects/scratch/k").await.json();
    let backbone = &status["extents"][0]["backbones"][0];
    assert_eq!(
        (&backbone["kind"], &backbone["counts"]),
        (&json!("body"), &json!(true))
    );

    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 1 })
    );
    assert!(fx.has_safety(&o));
    assert_eq!(fx.safety_state(&o).await, "held");

    // With the count put right, the same read-back is enough here.
    Rc::get_mut(&mut fx.bridge).unwrap().cfg.required_backbones = 1;
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.json()["safety_deleted"], 1);
}

/// A read-back from a backbone that does not count toward a release is no
/// reason to give up the pinned copy either.
#[tokio::test]
async fn evict_keeps_the_pinned_copy_when_the_read_back_is_on_a_backbone_that_does_not_count() {
    let fx = Fx::with_providers(Environment::Dev, Maintenance::Off, |providers| {
        let mut side = providers[0].clone();
        side.id = "p9".to_string();
        side.backbone = "side".to_string();
        side.post = false;
        side.release = false;
        providers.push(side);
    })
    .await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.drive(&o, OutboxStage::Release).await;
    let sql = &fx.bridge.catalog.sql;
    let home = fx.bridge.cfg.providers[0].backbone.clone();

    // The full read-back is on the backbone that does not count.
    sql.exec("UPDATE verifications SET backbone = 'side'", &[])
        .await
        .unwrap();
    let status = fx.get("/objects/scratch/k").await.json();
    let backbone = &status["extents"][0]["backbones"][0];
    assert_eq!(
        (
            &backbone["backbone"],
            &backbone["kind"],
            &backbone["counts"]
        ),
        (&json!("side"), &json!("body"), &json!(true))
    );
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(
        r.json(),
        json!({ "evicted": 1, "safety_deleted": 0, "safety_kept": 1 })
    );
    assert!(fx.has_safety(&o));

    // On the backbone that counts: the copy can go.
    sql.exec(
        "UPDATE verifications SET backbone = ?1",
        &[SqlValue::Text(home)],
    )
    .await
    .unwrap();
    let r = fx.post("/evict/scratch/k?include_safety=1").await;
    assert_eq!(r.json()["safety_deleted"], 1);
    assert!(!fx.has_safety(&o));
}

// ---------------------------------------------------------------------------
// Packing article plans
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pack_plans_packs_a_step_only_while_the_switch_is_on() {
    let mut fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let a = fx.put(&bucket, "a", &plaintext()).await;
    let b = fx.put(&bucket, "b", &plaintext()).await;
    fx.drive(&a, OutboxStage::Verify).await;
    fx.drive(&b, OutboxStage::Verify).await;
    let rows = "SELECT COUNT(*) FROM articles";
    let packed = "SELECT COUNT(*) FROM extents WHERE plan IS NOT NULL";
    assert_ne!(fx.scalar(rows, &[]).await, "0", "the plans are rows");

    // Off: a Worker that cannot read a packed plan may still be running.
    let r = fx.post("/pack-plans").await;
    assert_eq!(r.status, 409, "{}", r.text());
    assert!(r.text().contains("PackedPlansOff"), "{}", r.text());
    assert_eq!(fx.scalar(packed, &[]).await, "0");

    Rc::get_mut(&mut fx.bridge).unwrap().cfg.packed_plans = true;
    for bad in ["/pack-plans?limit=many", "/pack-plans?limit=-1"] {
        let r = fx.post(bad).await;
        assert_eq!(r.status, 400, "{bad}: {}", r.text());
    }
    assert_eq!(fx.scalar(packed, &[]).await, "0");
    assert_eq!(fx.get("/pack-plans").await.status, 405);

    let r = fx.post("/pack-plans?limit=1").await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json(), json!({ "looked": 1, "packed": 1, "end": false }));
    assert_eq!(fx.scalar(packed, &[]).await, "1");
    // No limit: the dispatcher's step, which is more than what is left.
    let r = fx.post("/pack-plans").await;
    assert_eq!(r.json(), json!({ "looked": 1, "packed": 1, "end": true }));
    assert_eq!(fx.scalar(rows, &[]).await, "0");
    assert_eq!(fx.scalar(packed, &[]).await, "2");
    // A limit of 0 or far too many is clamped, not refused.
    for path in ["/pack-plans?limit=0", "/pack-plans?limit=4000000000"] {
        let r = fx.post(path).await;
        assert_eq!(r.json(), json!({ "looked": 0, "packed": 0, "end": true }));
    }

    // Both objects still pass verification and release from their plans.
    fx.drive(&a, OutboxStage::Done).await;
    fx.drive(&b, OutboxStage::Done).await;
}

#[tokio::test]
async fn pack_plans_is_refused_in_restore_maintenance() {
    let mut fx = Fx::with(Environment::Dev, Maintenance::Restore).await;
    Rc::get_mut(&mut fx.bridge).unwrap().cfg.packed_plans = true;
    let r = fx.post("/pack-plans").await;
    assert_eq!(r.status, 503, "{}", r.text());
}

// ---------------------------------------------------------------------------
// Usage counters, the dashboard reads and who may make them
// ---------------------------------------------------------------------------

const READ_TOKEN: &str = "read-token-for-the-dashboard-0123456789";

/// The fixture with `edit` applied to its configuration.
async fn fx_with(edit: impl FnOnce(&mut BridgeConfig)) -> Fx {
    let mut fx = Fx::new().await;
    edit(&mut Rc::get_mut(&mut fx.bridge).expect("one owner").cfg);
    fx
}

#[tokio::test]
async fn ops_snapshot_reads_the_counters() {
    let fx = Fx::new().await;
    let r = fx.get("/ops-snapshot").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let empty = r.json();
    assert_eq!(empty["seeded"], true);
    assert_eq!(empty["live_objects"], 0);
    assert_eq!(
        empty["oldest_due_ms"],
        json!({ "post": null, "verify": null, "release": null })
    );
    assert_eq!(empty["recount"]["running"], false);
    assert_eq!(empty["last_recount"], Value::Null);

    let bucket = fx.bucket("scratch").await;
    let done = fx.put(&bucket, "done", &plaintext()).await;
    fx.drive(&done, OutboxStage::Done).await;
    fx.put(&bucket, "waiting", b"yy").await;
    fx.bridge.clock.advance_secs(90);

    let r = fx.get("/ops-snapshot?hours=1").await.json();
    let c = &r["counters"];
    assert_eq!(
        (&c["outbox_post"], &c["outbox_done"], &c["outbox_dead"]),
        (&json!(1), &json!(1), &json!(0))
    );
    assert_eq!(
        c["extents_unreleased"].as_i64().unwrap() + c["extents_released"].as_i64().unwrap(),
        2
    );
    assert_eq!(c["posts_total"], 1);
    assert_eq!(c["verifies_total"], 1);
    assert_eq!(r["live_objects"], 2);
    assert_eq!(r["live_bytes"], plaintext().len() as u64 + 2);
    assert_eq!(r["buckets_counted"], 1);
    // The row that waits to be posted has been due for 90 s.
    assert_eq!(r["oldest_due_ms"]["post"], 90_000);
    assert_eq!(r["oldest_due_ms"]["verify"], Value::Null);
    assert_eq!(r["now"], fx.bridge.clock.now().0);

    // The status page says where its totals come from, and agrees.
    let status = fx.get("/status").await.json();
    assert_eq!(status["usage_counters"], "on");
    assert_eq!(status["outbox"], json!({ "post": 1, "done": 1 }));
    assert_eq!(
        status["hot"]["pinned_extents"], c["extents_unreleased"],
        "{status}"
    );

    // Nothing of an object is in the snapshot: no key, no bucket name.
    let text = fx.get("/ops-snapshot").await.text();
    for (i, private) in ["waiting", "scratch", TOKEN].iter().enumerate() {
        assert!(
            !text.contains(private),
            "private text {i} is in the snapshot"
        );
    }
    assert_eq!(fx.get("/ops-snapshot?hours=x").await.status, 400);
}

#[tokio::test]
async fn usage_buckets_pages_in_id_order() {
    let fx = Fx::new().await;
    let mut ids = Vec::new();
    for name in ["bucket-a", "bucket-b", "bucket-c"] {
        let bucket = fx.bucket(name).await;
        fx.put(&bucket, "k", name.as_bytes()).await;
        ids.push(bucket.id.as_str().to_string());
    }
    ids.sort();

    let all = fx.get("/usage/buckets").await.json();
    assert_eq!(all["next_after"], Value::Null);
    assert_eq!(all["seeded"], true);
    // A page past the last bucket is empty, and still says so.
    let past = fx.get("/usage/buckets?after=zzzz").await.json();
    assert_eq!(
        (&past["seeded"], &past["buckets"]),
        (&json!(true), &json!([]))
    );
    let listed = all["buckets"].as_array().unwrap();
    assert_eq!(listed.len(), 3);
    for (row, id) in listed.iter().zip(&ids) {
        assert_eq!(row["bucket_id"], id.as_str());
        assert_eq!(
            (&row["live_objects"], &row["live_bytes"]),
            (&json!(1), &json!(8))
        );
    }

    let first = fx.get("/usage/buckets?limit=2").await.json();
    assert_eq!(first["buckets"].as_array().unwrap().len(), 2);
    assert_eq!(first["next_after"], ids[1].as_str());
    let rest = fx
        .get(&format!("/usage/buckets?limit=2&after={}", ids[1]))
        .await
        .json();
    assert_eq!(rest["buckets"][0]["bucket_id"], ids[2].as_str());
    assert_eq!(rest["next_after"], Value::Null);

    assert_eq!(fx.get("/usage/buckets?after=a%27b").await.status, 400);
    assert_eq!(fx.get("/usage/buckets?limit=many").await.status, 400);
}

#[tokio::test]
async fn cost_serves_the_meter_report_or_says_there_is_none() {
    let fx = Fx::new().await;
    let r = fx.get("/cost").await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (404, json!("NoCostReport"))
    );

    let id = BucketId::mint([9; 8]);
    let extent = ExtentId::mint([9; 13]);
    // As the cost meter writes it: a plain object in the cache bucket.
    let write = |bytes: Vec<u8>| {
        let (fx, id, extent) = (&fx, &id, &extent);
        async move {
            let digest: [u8; 32] = sha256(&bytes);
            let meta = BlobMeta {
                bucket: id,
                extent,
                cipher_sha256: &digest,
            };
            let key = "ops/cost/latest.json";
            fx.bridge.cache.put(key, bytes, &meta).await.unwrap();
        }
    };
    let report = json!({ "month_to_date_usd": 1.25, "lines": [{ "name": "d1_rows_written" }] });
    write(report.to_string().into_bytes()).await;
    let r = fx.get("/cost").await;
    assert_eq!((r.status, r.json()), (200, report));

    // Not JSON, or far larger than a report: refused, never passed on.
    write(b"<html>".to_vec()).await;
    let r = fx.get("/cost").await;
    assert_eq!(r.status, 502);
    assert!(!r.text().contains("html"));
    write(vec![b' '; 300 * 1024]).await;
    assert_eq!(fx.get("/cost").await.status, 502);
}

#[tokio::test]
async fn recount_runs_in_steps_and_off_switches_the_counters_off() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    for i in 0..5u8 {
        fx.put(&bucket, &format!("k{i}"), &[i; 10]).await;
    }
    let before = fx.get("/ops-snapshot").await.json()["counters"].clone();

    // Off: the status page reads the tables again and says so.
    let r = fx.post("/usage/off").await;
    assert_eq!((r.status, r.json()), (200, json!({ "counters": "off" })));
    let status = fx.get("/status").await.json();
    assert_eq!(status["usage_counters"], "off");
    assert_eq!(status["outbox"], json!({ "post": 5 }));
    assert_eq!(fx.get("/ops-snapshot").await.json()["seeded"], false);
    fx.put(&bucket, "while-off", b"z").await;
    // The bucket figures are marked as stale while the counters are off.
    let stale = fx.get("/usage/buckets").await.json();
    assert_eq!(stale["seeded"], false);
    assert_eq!(stale["buckets"][0]["live_objects"], 5);

    // One request, one bounded step: 2 of the 6 extents.
    let r = fx.post("/usage/recount?steps=1&chunk=2").await.json();
    assert_eq!((&r["started"], &r["rows"]), (&json!(true), &json!(2)));
    assert_eq!(r["finished"], Value::Null);
    assert_eq!(r["recount"]["table"], "extents");
    // The next goes on where that one stopped, and ends.
    let r = fx.post("/usage/recount?steps=16&chunk=4").await.json();
    assert_eq!((&r["started"], &r["rows"]), (&json!(false), &json!(16)));
    assert_eq!(r["finished"]["adopted"], true);
    assert_eq!(r["finished"]["drift"], 0);
    assert_eq!(r["recount"]["running"], false);

    let snap = fx.get("/ops-snapshot").await.json();
    assert_eq!(snap["seeded"], true);
    assert_eq!(snap["live_objects"], 6);
    assert_eq!(snap["counters"]["outbox_post"], 6);
    assert_eq!(
        snap["counters"]["extents_unreleased"].as_i64().unwrap(),
        before["extents_unreleased"].as_i64().unwrap() + 1
    );
    assert_eq!(snap["last_recount"]["rows"], 18);

    // A later one compares, and finds the counters right.
    let r = fx.post("/usage/recount?steps=16").await.json();
    assert_eq!(
        (&r["finished"]["adopted"], &r["finished"]["drift"]),
        (&json!(false), &json!(0))
    );
    assert_eq!(fx.post("/usage/recount?steps=x").await.status, 400);
}

#[tokio::test]
async fn the_cron_goes_on_with_a_recount_and_reports_its_end() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    fx.put(&bucket, "k", b"abc").await;

    // Nothing to do: no recount has ever run, and none is started here.
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.recount_rows, report.recount_drift), (0, None));

    // One that an operator began is carried to its end.
    let r = fx.post("/usage/recount?steps=1&chunk=1").await.json();
    assert_eq!(r["recount"]["running"], true);
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.recount_rows, report.recount_drift), (2, Some(0)));
    assert!(!report.recount_failed);

    // The next begins a week after that one ended, not before.
    fx.bridge.clock.advance_secs(6 * 24 * 3600);
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.recount_rows, report.recount_drift), (0, None));
    fx.bridge.clock.advance_secs(24 * 3600);
    // A counter that went wrong meanwhile is found, and left as it is.
    fx.bridge
        .catalog
        .sql
        .exec("UPDATE usage_global SET ob_dead = 4 WHERE id = 1", &[])
        .await
        .unwrap();
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.recount_rows, report.recount_drift), (3, Some(1)));
    let snap = fx.get("/ops-snapshot").await.json();
    assert_eq!(snap["counters"]["outbox_dead"], 4);
    assert_eq!(snap["last_recount"]["drift"], 1);
    assert_eq!(snap["last_recount"]["adopted"], false);
}

#[tokio::test]
async fn the_read_token_opens_only_the_read_routes() {
    let fx = fx_with(|cfg| cfg.admin_read_token = Some(Secret::new(READ_TOKEN.to_string()))).await;
    let bucket = fx.bucket("scratch").await;
    fx.put(&bucket, "k", b"payload").await;
    let read = format!("Bearer {READ_TOKEN}");

    for target in [
        "/_admin/status",
        "/_admin/ops-snapshot",
        "/_admin/ops-snapshot?hours=2",
        "/_admin/usage/buckets",
    ] {
        let r = fx.send("GET", target, Some(&read), None).await;
        assert_eq!(r.status, 200, "GET {target}: {}", r.text());
        assert!(!r.text().contains(READ_TOKEN) && !r.text().contains(TOKEN));
    }
    // Allowed and absent: the route answered, not the gate.
    assert_eq!(
        fx.send("GET", "/_admin/cost", Some(&read), None)
            .await
            .status,
        404
    );

    // Every other route, and every other method on a read route.
    for (method, target, body) in routes() {
        let allowed = method == "GET"
            && matches!(
                target,
                "/_admin/status"
                    | "/_admin/ops-snapshot"
                    | "/_admin/usage/buckets"
                    | "/_admin/cost"
            );
        if allowed {
            continue;
        }
        let r = fx.send(method, target, Some(&read), body).await;
        assert_eq!(r.status, 403, "{method} {target}");
    }
    for target in [
        "/_admin/status",
        "/_admin/ops-snapshot",
        "/_admin/usage/buckets",
    ] {
        let r = fx.send("POST", target, Some(&read), None).await;
        assert_eq!(r.status, 403, "POST {target}");
    }
    // Nothing was changed by any of it.
    assert!(fx.bucket_row("probe").await.is_none());
    assert_eq!(fx.get("/ops-snapshot").await.json()["seeded"], true);

    // The write token still opens everything, and without a read token
    // configured the read token is just a wrong one.
    assert_eq!(fx.post("/usage/off").await.status, 200);
    let plain = Fx::new().await;
    let r = plain.send("GET", "/_admin/status", Some(&read), None).await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn admin_answers_only_on_its_host_when_one_is_set() {
    let fx = fx_with(|cfg| cfg.admin_host = Some("admin.internal".to_string())).await;
    let auth = format!("Bearer {TOKEN}");
    let send = |host: Option<&'static str>, auth: Option<String>| {
        let fx = &fx;
        async move {
            let mut headers = Vec::new();
            if let Some(host) = host {
                headers.push(("host".to_string(), host.to_string()));
            }
            if let Some(auth) = auth {
                headers.push(("authorization".to_string(), auth));
            }
            let req = S3Request {
                method: Method::parse("GET"),
                raw_target: "/_admin/status".to_string(),
                headers,
                body: Body::Empty,
            };
            Rc::clone(&fx.bridge).handle(req).await.status
        }
    };
    // The public host: as if there were no such route, token or not.
    assert_eq!(send(Some("s3.test"), Some(auth.clone())).await, 404);
    assert_eq!(send(Some("s3.test"), None).await, 404);
    assert_eq!(send(None, Some(auth.clone())).await, 404);
    assert_eq!(
        send(Some("admin.internal.evil.test"), Some(auth.clone())).await,
        404
    );
    // Its own host: the token decides.
    assert_eq!(send(Some("admin.internal"), Some(auth.clone())).await, 200);
    assert_eq!(send(Some("ADMIN.internal:443"), Some(auth)).await, 200);
    assert_eq!(send(Some("admin.internal"), None).await, 401);
    assert_eq!(
        send(Some("admin.internal"), Some("Bearer wrong".to_string())).await,
        403
    );
}

/// The one tenant there is.
static TENANT_ZERO: velmora_bridge::TenantScope = velmora_bridge::TenantScope::tenant_zero();
