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
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::sql::SqlCatalog;
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
}

impl Sql for RacingSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.inner.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
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
        let mut config = ServerConfig::for_test();
        config.articles = Vec::new();
        config.missing_ids.clear();
        config.users.insert(
            USER.to_string(),
            UserConfig {
                password: PASS.to_string(),
                max_connections: 2,
            },
        );
        let server = TestNntpServer::spawn(config).await;
        let providers = vec![ProviderConfig {
            id: "p0".to_string(),
            host: server.addr().ip().to_string(),
            port: server.addr().port(),
            tls: false,
            user: USER.to_string(),
            pass: PASS.to_string(),
            backbone: "bb0".to_string(),
            post: true,
            read: true,
            max_conns: 2,
            priority: 0,
            retention_days: None,
            pool: None,
            pool_max_conns: None,
            enabled: true,
        }];
        let cfg = BridgeConfig {
            environment,
            s3_host: "s3.test".to_string(),
            region: "auto".to_string(),
            max_extent_bytes: 16 * 1024 * 1024,
            required_backbones: 1,
            safety_min_age_secs: 0,
            verify_delay_secs: 1,
            newsgroups: vec!["alt.binaries.test".to_string()],
            kek_active: 1,
            inflight_budget_bytes: BUDGET,
            gc_mode: GcMode::Disposable,
            maintenance,
            dev_trust_http: false,
            providers,
            admin_token: Secret::new(TOKEN.to_string()),
        };
        let bridge = Bridge {
            catalog: SqlCatalog::new(RacingSql {
                inner: RusqliteSql::with_schema().unwrap(),
                race: RefCell::new(None),
            }),
            safety: MemBlobStore::new(),
            cache: MemBlobStore::new(),
            nntp: TcpConnector::default(),
            jobs: FakeJobs::new(),
            kek: TestKek::new(),
            clock: FixedClock::new(T0),
            budget: ByteBudget::new(BUDGET),
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
            RespBody::Stream(_) => panic!("admin responses are never streamed"),
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
        let n = self.next();
        let b = &self.bridge;
        let now = b.clock.now();
        let bdk = unwrap_bdk(&b.kek, bucket.kek_version, &bucket.id, &bucket.bdk_wrapped).unwrap();
        let extent_id = ExtentId::mint([n; 13]);
        let sealed = seal_extent(&bdk, &bucket.id, &extent_id, plain, &mut SystemRng).unwrap();
        let generation = GenerationRow {
            id: GenerationId::mint(now, [n; 8]),
            bucket_id: bucket.id.clone(),
            key: key.to_string(),
            state: GenerationState::Live,
            size: plain.len() as u64,
            etag: "\"etag\"".to_string(),
            checksum_json: None,
            content_json: "{}".to_string(),
            user_meta_json: "{}".to_string(),
            extent_count: 1,
            created_at: now,
            retired_at: None,
        };
        let extent = ExtentRow {
            id: extent_id.clone(),
            bucket_id: bucket.id.clone(),
            generation_id: Some(generation.id.clone()),
            state: ExtentState::Committed,
            seq: Some(0),
            plain_offset: Some(0),
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
        };
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
        b.catalog
            .commit_generation(&CommitGeneration {
                generation: generation.clone(),
                extents: vec![extent],
                now,
            })
            .await
            .unwrap();
        Obj {
            extent: extent_id,
            generation: generation.id,
            plain: plain.to_vec(),
        }
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
            assert_eq!(b.run_job(&job).await, JobOutcome::Ack, "{stage}");
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
        ("GET", "/_admin/objects/scratch/k", None),
        ("POST", "/_admin/evict/scratch/k?include_safety=1", None),
        ("POST", "/_admin/drill/scratch/k", None),
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
        ("GET", "/keys"),
        ("DELETE", "/buckets"),
        ("POST", "/objects/scratch/k"),
        ("GET", "/evict/scratch/k"),
        ("GET", "/drill/scratch/k"),
        ("GET", "/dev/guard-selftest"),
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
    let r = fx.post(&format!("/drill/{path}")).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({
            "source": "nntp",
            "provider": "p0",
            "articles": 3,
            "extents": 1,
            "size": plain.len(),
            "plaintext_sha256": hex(&sha256(&plain)),
            "match": true,
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

    // A held slot and three failed sessions show up.
    let permit = fx
        .bridge
        .catalog
        .acquire_permit(&p, PermitClass::Read, "t", now)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..3 {
        fx.bridge.catalog.provider_failed(&p.id, now).await.unwrap();
    }
    let r = fx.get("/status").await;
    let one = r.json()["providers"][0].clone();
    assert_eq!(one["held"], 1);
    assert_eq!(one["cooling"], true);
    assert_eq!(one["cooldown_until"], now.0 + 60_000);
    let body = r.text();
    for secret in [p.user.as_str(), p.pass.as_str(), p.host.as_str()] {
        assert!(!body.contains(secret), "status leaks provider details");
    }
    fx.bridge.catalog.release_permit(&permit).await.unwrap();
}
