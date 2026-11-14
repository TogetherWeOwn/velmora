//! Slice acceptance, natively: the same seven properties `e2e/slice.sh`
//! proves through aws-cli under `wrangler dev`, here over the real
//! [`Bridge`] with the SQLite catalogue, in-memory blob stores and a real
//! NNTP client talking to the in-process fake server.
//!
//! 1. read-after-write (served from SAFETY);
//! 2. HEAD, LIST (prefix, delimiter, continuation), the multipart ETag
//!    shape and a key with reserved characters;
//! 3. a range read across an extent boundary, plus the safety rules: a
//!    conditional write is refused before anything is stored, and an
//!    upload ID is bound to its bucket and key;
//! 4. posting and verification reach `release`/`done` with a counting
//!    backbone; the fake server's spool equals the catalogue's message-id
//!    set, and no article carries plaintext or the object's name;
//! 5. a cold read after evicting CACHE and SAFETY comes from NNTP and
//!    refills the cache;
//! 6. delete;
//! 7. a lost queue notification is recovered by `Bridge::dispatch`.
//!
//! `permits_never_exceed_max_conns` checks that the fake's per-user
//! connection cap (set to the provider's `max_conns`) is never exceeded
//! while posts, verifies and a cold read overlap.
//!
//! Every failure names the step and shows the expected and actual value.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::{Debug, Display};
use std::rc::Rc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::future::{join, join_all};
use futures_util::stream::{self, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::transports::NativeTlsTransport;
use velmora_bridge::config::BridgeConfig;
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

// ---------------------------------------------------------------------------
// Fixed test values (none of them is a secret)
// ---------------------------------------------------------------------------

/// 2026-11-13T00:00:00Z.
const T0: UnixMs = UnixMs(1_794_528_000_000);
const S3_HOST: &str = "127.0.0.1:8798";
const REGION: &str = "auto";
const GROUP: &str = "alt.binaries.test";
const ADMIN_TOKEN: &str = "slice-test-admin-token-0123456789abcdef";
const POSTER_USER: &str = "testuser";
const POSTER_PASS: &str = "testpass";
/// A second login for the test's own article audit, so it never counts
/// against the poster's connection cap.
const AUDIT_USER: &str = "auditor";
const AUDIT_PASS: &str = "auditpass";
const MAX_CONNS: u32 = 2;
const MIB: usize = 1024 * 1024;
/// S3's smallest non-final part.
const PART: usize = 5 * MIB;
/// Plaintext size of `a/big.bin`: parts of 5, 5 and 1 MiB (3 extents).
const BIG_LEN: usize = 2 * PART + MIB;
/// Cron period of the dispatcher (`*/5 * * * *`).
const CRON_SECS: u32 = 300;
/// Upper bound on pump rounds; a round runs every due job once.
const MAX_ROUNDS: u32 = 400;

type TestBridge =
    Bridge<SqlCatalog<RusqliteSql>, MemBlobStore, CountingConnector, FakeJobs, TestKek, FixedClock>;

// ---------------------------------------------------------------------------
// Failure reporting: step, what, expected, actual
// ---------------------------------------------------------------------------

#[track_caller]
fn fail(step: &str, what: &str, expected: impl Display, actual: impl Display) -> ! {
    panic!("\nSLICE FAILED at step {step}: {what}\n  expected: {expected}\n  actual:   {actual}\n")
}

#[track_caller]
fn expect_eq<T: PartialEq + Debug>(step: &str, what: &str, expected: T, actual: T) {
    if expected != actual {
        fail(step, what, format!("{expected:?}"), format!("{actual:?}"));
    }
}

#[track_caller]
fn expect(step: &str, what: &str, ok: bool, actual: impl Display) {
    if !ok {
        fail(step, what, "true", actual);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Compares bodies without dumping them: lengths, digests, first difference.
#[track_caller]
fn expect_bytes(step: &str, what: &str, expected: &[u8], actual: &[u8]) {
    if expected == actual {
        return;
    }
    let first_diff = expected
        .iter()
        .zip(actual)
        .position(|(a, b)| a != b)
        .unwrap_or(expected.len().min(actual.len()));
    fail(
        step,
        what,
        format!(
            "{} bytes, sha256 {}",
            expected.len(),
            hex(&sha256(expected))
        ),
        format!(
            "{} bytes, sha256 {}, first difference at offset {first_diff}",
            actual.len(),
            hex(&sha256(actual))
        ),
    );
}

/// Deterministic incompressible test bytes.
fn test_bytes(seed: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut block: [u8; 32] = sha256(&[seed; 1]);
    while out.len() < len {
        out.extend_from_slice(&block);
        block = sha256(&block);
    }
    out.truncate(len);
    out
}

// ---------------------------------------------------------------------------
// Counting NNTP connector over the real client
// ---------------------------------------------------------------------------

fn nntp_config(host: &str, port: u16, user: &str, pass: &str) -> NntpConfig {
    NntpConfig {
        host: host.to_string(),
        port,
        tls: false,
        allow_insecure_plaintext: true,
        username: Some(user.to_string()),
        password: Some(pass.to_string()),
        timeout: Duration::from_secs(10),
        max_article_bytes: 4 * MIB,
        ..NntpConfig::default()
    }
}

async fn dial(cfg: &NntpConfig) -> velmora::Result<NntpClient<NativeTlsTransport>> {
    let transport = velmora::transports::tokio_tls::connect(cfg)
        .await
        .map_err(velmora::Error::Io)?;
    NntpClient::connect(transport, cfg).await
}

/// Session and command counters shared by the connector and its sessions.
#[derive(Default)]
struct NntpCounters {
    live: Cell<u32>,
    peak: Cell<u32>,
    connects: Cell<u32>,
    /// Connects the server refused (a cap breach answers `502`).
    refused: Cell<u32>,
    posts: Cell<u32>,
    bodies: Cell<u32>,
}

/// Dials the provider in plaintext (the fake only) and counts sessions.
#[derive(Default)]
struct CountingConnector {
    n: Rc<NntpCounters>,
}

struct CountingSession {
    client: Option<NntpClient<NativeTlsTransport>>,
    n: Rc<NntpCounters>,
}

impl Drop for CountingSession {
    fn drop(&mut self) {
        self.n.live.set(self.n.live.get() - 1);
    }
}

impl CountingSession {
    fn client(&mut self) -> Result<&mut NntpClient<NativeTlsTransport>> {
        self.client
            .as_mut()
            .ok_or(BridgeError::Invalid("session used after quit"))
    }
}

impl NntpSession for CountingSession {
    async fn post(&mut self, message_id: &str, article: &[u8]) -> Result<PostOutcome> {
        self.n.posts.set(self.n.posts.get() + 1);
        Ok(self.client()?.post_article(message_id, article).await?)
    }

    async fn stat(&mut self, message_id: &str) -> Result<bool> {
        match self.client()?.stat(message_id).await {
            Ok(_) => Ok(true),
            Err(velmora::Error::ArticleNotFound(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn body(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome> {
        self.n.bodies.set(self.n.bodies.get() + 1);
        match self.client()?.body_to(message_id, out).await {
            Ok(()) => Ok(BodyOutcome::Found),
            Err(velmora::Error::ArticleNotFound(_)) => Ok(BodyOutcome::Missing),
            Err(e) => Err(e.into()),
        }
    }

    async fn quit(mut self) {
        if let Some(client) = self.client.take() {
            client.quit().await;
        }
    }
}

impl NntpConnector for CountingConnector {
    type Session = CountingSession;

    async fn connect(&self, p: &ProviderConfig, _permit: &Permit) -> Result<CountingSession> {
        let client = match dial(&nntp_config(&p.host, p.port, &p.user, &p.pass)).await {
            Ok(c) => c,
            Err(e) => {
                self.n.refused.set(self.n.refused.get() + 1);
                return Err(e.into());
            }
        };
        let n = &self.n;
        n.connects.set(n.connects.get() + 1);
        n.live.set(n.live.get() + 1);
        n.peak.set(n.peak.get().max(n.live.get()));
        Ok(CountingSession {
            client: Some(client),
            n: Rc::clone(n),
        })
    }
}

// ---------------------------------------------------------------------------
// SigV4 header signing (independent of the server's verifier)
// ---------------------------------------------------------------------------

/// RFC 3986 unreserved bytes stay; everything else is `%XX` (uppercase).
fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `(yyyymmddThhmmssZ, yyyymmdd)`.
fn amz_date(now: UnixMs) -> (String, String) {
    let secs = now.0.div_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    let date = format!("{y:04}{mo:02}{d:02}");
    let stamp = format!("{date}T{:02}{:02}{:02}Z", t / 3600, t % 3600 / 60, t % 60);
    (stamp, date)
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

struct Signer {
    akid: String,
    secret: String,
    host: String,
    region: String,
}

/// One request: method, raw origin-form target, headers, body.
struct Req {
    method: Method,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Signer {
    /// Signs `method /bucket/key?query` with header auth. `path` is the
    /// decoded path; `query` the decoded pairs. Extra headers are signed.
    fn sign(
        &self,
        now: UnixMs,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Req {
        let canonical_uri = uri_encode(path, true);
        let mut q: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
            .collect();
        q.sort();
        let canonical_query = q
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        // aws-cli sends a bare `?uploads`; the canonical form has `uploads=`.
        let raw_query = q
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        let target = if raw_query.is_empty() {
            canonical_uri.clone()
        } else {
            format!("{canonical_uri}?{raw_query}")
        };

        let (stamp, date) = amz_date(now);
        let payload = hex(&sha256(&body));
        let mut signed: BTreeMap<String, String> = BTreeMap::new();
        signed.insert("host".into(), self.host.clone());
        signed.insert("x-amz-content-sha256".into(), payload.clone());
        signed.insert("x-amz-date".into(), stamp.clone());
        for (k, v) in extra {
            signed.insert(k.to_ascii_lowercase(), v.trim().to_string());
        }
        let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let signed_names = signed.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical_request = format!(
            "{}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_names}\n{payload}",
            method.as_str()
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex(&sha256(canonical_request.as_bytes()))
        );
        let k_date = hmac(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes());
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex(&hmac(&k_signing, to_sign.as_bytes()));

        let mut headers: Vec<(String, String)> = signed.into_iter().collect();
        headers.push((
            "authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_names}, Signature={signature}",
                self.akid
            ),
        ));
        if !body.is_empty() {
            headers.push(("content-length".into(), body.len().to_string()));
        }
        Req {
            method,
            target,
            headers,
            body,
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Status plus the S3 error code (or a short body excerpt).
    fn summary(&self) -> String {
        let text = self.text();
        match xml_values(&text, "Code").first() {
            Some(code) => format!("HTTP {} {code}", self.status),
            None => {
                let excerpt: String = text.chars().take(200).collect();
                format!("HTTP {} body {excerpt:?}", self.status)
            }
        }
    }

    fn json(&self, step: &str, what: &str) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| fail(step, what, "a JSON body", self.summary()))
    }
}

#[track_caller]
fn expect_status(step: &str, what: &str, want: u16, r: &Resp) {
    if r.status != want {
        fail(step, what, format!("HTTP {want}"), r.summary());
    }
}

/// Status and S3 error code, e.g. `404 NoSuchUpload`.
#[track_caller]
fn expect_error(step: &str, what: &str, want_status: u16, want_code: &str, r: &Resp) {
    let code = xml_values(&r.text(), "Code").into_iter().next();
    if r.status != want_status || code.as_deref() != Some(want_code) {
        fail(
            step,
            what,
            format!("HTTP {want_status} {want_code}"),
            r.summary(),
        );
    }
}

/// Every `<tag>…</tag>` text, XML entities decoded. Enough for the S3
/// documents the slice returns.
fn xml_values(xml: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(
            after[..j]
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&"),
        );
        rest = &after[j + close.len()..];
    }
    out
}

/// Common prefixes are `<CommonPrefixes><Prefix>p</Prefix></CommonPrefixes>`.
fn common_prefixes(xml: &str) -> Vec<String> {
    xml_values(xml, "CommonPrefixes")
        .iter()
        .flat_map(|block| xml_values(block, "Prefix"))
        .collect()
}

async fn collect(body: RespBody) -> std::result::Result<Vec<u8>, String> {
    match body {
        RespBody::Empty => Ok(Vec::new()),
        RespBody::Bytes(b) => Ok(b),
        RespBody::Stream(mut s) => {
            let mut out = Vec::new();
            while let Some(chunk) = s.next().await {
                out.extend(chunk.map_err(|e| format!("body stream error: {e}"))?);
            }
            Ok(out)
        }
    }
}

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

struct Rig {
    server: TestNntpServer,
    bridge: Rc<TestBridge>,
    n: Rc<NntpCounters>,
    signer: RefCell<Option<Signer>>,
}

impl Rig {
    async fn new() -> Rig {
        let mut cfg = ServerConfig::for_test();
        cfg.group = GROUP.to_string();
        cfg.users.clear();
        cfg.users.insert(
            POSTER_USER.to_string(),
            UserConfig {
                password: POSTER_PASS.to_string(),
                max_connections: MAX_CONNS as usize,
            },
        );
        cfg.users.insert(
            AUDIT_USER.to_string(),
            UserConfig {
                password: AUDIT_PASS.to_string(),
                max_connections: 4,
            },
        );
        let server = TestNntpServer::spawn(cfg).await;

        let providers = serde_json::json!([{
            "id": "fake1",
            "host": server.addr().ip().to_string(),
            "port": server.addr().port(),
            "tls": false,
            "user": POSTER_USER,
            "pass": POSTER_PASS,
            "backbone": "fake-backbone",
            "post": true,
            "read": true,
            "max_conns": MAX_CONNS,
        }])
        .to_string();
        // The `[env.dev]` vars of wrangler.toml, plus the dev secrets.
        let mut vars: BTreeMap<&str, String> = [
            ("ENVIRONMENT", "dev"),
            ("S3_HOST", S3_HOST),
            ("S3_REGION", REGION),
            ("MAX_EXTENT_BYTES", "16777216"),
            ("REQUIRED_BACKBONES", "1"),
            ("SAFETY_MIN_AGE_SECS", "0"),
            ("VERIFY_DELAY_SECS", "1"),
            ("DEV_TRUST_HTTP", "1"),
            ("NEWSGROUPS", GROUP),
            ("VELMORA_KEK_ACTIVE", "1"),
            ("INFLIGHT_BUDGET_BYTES", "50331648"),
            ("GC_MODE", "disposable"),
            ("MAINTENANCE", "off"),
            ("ADMIN_TOKEN", ADMIN_TOKEN),
        ]
        .into_iter()
        .map(|(k, v)| (k, v.to_string()))
        .collect();
        vars.insert("NNTP_PROVIDERS", providers);
        // TestKek's version 1; the config only checks its presence and shape.
        vars.insert(
            "VELMORA_KEK_1",
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
        );
        let cfg = BridgeConfig::from_vars(|k| vars.get(k).cloned())
            .unwrap_or_else(|e| fail("setup", "BridgeConfig::from_vars", "Ok", e));

        let connector = CountingConnector::default();
        let n = Rc::clone(&connector.n);
        let bridge = Rc::new(Bridge {
            catalog: SqlCatalog::new(RusqliteSql::with_schema().expect("schema applies")),
            safety: MemBlobStore::new(),
            cache: MemBlobStore::new(),
            nntp: connector,
            jobs: FakeJobs::new(),
            kek: TestKek::new(),
            clock: FixedClock::new(T0),
            budget: ByteBudget::new(cfg.inflight_budget_bytes),
            cfg,
        });
        Rig {
            server,
            bridge,
            n,
            signer: RefCell::new(None),
        }
    }

    async fn send(&self, r: Req) -> Resp {
        let req = S3Request {
            method: r.method,
            raw_target: r.target,
            headers: r.headers,
            body: if r.body.is_empty() {
                Body::Empty
            } else {
                let len = r.body.len() as u64;
                // Arrives in 1 MiB chunks, like a streamed request body.
                let chunks: Vec<Result<Vec<u8>>> =
                    r.body.chunks(MIB).map(|c| Ok(c.to_vec())).collect();
                Body::Stream {
                    declared_len: Some(len),
                    stream: stream::iter(chunks).boxed_local(),
                }
            },
        };
        let resp = Rc::clone(&self.bridge).handle(req).await;
        let body = collect(resp.body)
            .await
            .unwrap_or_else(|e| fail("http", "response body", "a complete body", e));
        Resp {
            status: resp.status,
            headers: resp.headers,
            body,
        }
    }

    // -- admin --------------------------------------------------------------

    async fn admin(&self, method: Method, path: &str, json: Option<serde_json::Value>) -> Resp {
        let body = json.map(|j| j.to_string().into_bytes()).unwrap_or_default();
        let mut headers = vec![
            ("host".to_string(), S3_HOST.to_string()),
            ("authorization".to_string(), format!("Bearer {ADMIN_TOKEN}")),
        ];
        if !body.is_empty() {
            headers.push(("content-type".into(), "application/json".into()));
            headers.push(("content-length".into(), body.len().to_string()));
        }
        self.send(Req {
            method,
            target: format!("/_admin{path}"),
            headers,
            body,
        })
        .await
    }

    async fn admin_json(
        &self,
        step: &str,
        method: Method,
        path: &str,
        json: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let r = self.admin(method, path, json).await;
        expect_status(step, &format!("admin {path}"), 200, &r);
        r.json(step, &format!("admin {path}"))
    }

    /// Creates the disposable buckets and one rw key for both.
    async fn setup_buckets_and_key(&self, step: &str) {
        for name in ["slice", "other"] {
            let r = self
                .admin(
                    Method::Post,
                    "/buckets",
                    Some(serde_json::json!({"name": name, "disposable": true})),
                )
                .await;
            expect(
                step,
                &format!("POST /_admin/buckets {name} succeeds"),
                (200..300).contains(&r.status),
                r.summary(),
            );
        }
        let key = self
            .admin_json(
                step,
                Method::Post,
                "/keys",
                Some(serde_json::json!({"buckets": ["slice", "other"], "perm": "rw"})),
            )
            .await;
        let field = |name: &str| {
            key[name].as_str().map(str::to_string).unwrap_or_else(|| {
                fail(
                    step,
                    "POST /_admin/keys response",
                    format!("a string field {name:?}"),
                    format!(
                        "fields {:?}",
                        key.as_object().map(|o| o.keys().collect::<Vec<_>>())
                    ),
                )
            })
        };
        *self.signer.borrow_mut() = Some(Signer {
            akid: field("access_key_id"),
            secret: field("secret"),
            host: S3_HOST.to_string(),
            region: REGION.to_string(),
        });
    }

    // -- S3 -----------------------------------------------------------------

    fn sign(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Req {
        let signer = self.signer.borrow();
        let signer = signer.as_ref().expect("setup_buckets_and_key ran first");
        signer.sign(self.bridge.clock.now(), method, path, query, extra, body)
    }

    async fn s3(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Resp {
        let req = self.sign(method, path, query, extra, body);
        self.send(req).await
    }

    async fn put(&self, path: &str, body: &[u8]) -> Resp {
        self.s3(Method::Put, path, &[], &[], body.to_vec()).await
    }

    async fn get(&self, path: &str) -> Resp {
        self.s3(Method::Get, path, &[], &[], Vec::new()).await
    }

    async fn head(&self, path: &str) -> Resp {
        self.s3(Method::Head, path, &[], &[], Vec::new()).await
    }

    /// Create, upload the parts concurrently, complete. Returns the
    /// Complete response.
    async fn multipart_put(&self, step: &str, path: &str, body: &[u8], part: usize) -> Resp {
        let r = self
            .s3(Method::Post, path, &[("uploads", "")], &[], Vec::new())
            .await;
        expect_status(step, "CreateMultipartUpload", 200, &r);
        let upload_id = xml_values(&r.text(), "UploadId")
            .into_iter()
            .next()
            .unwrap_or_else(|| fail(step, "CreateMultipartUpload", "an UploadId", r.text()));

        let parts: Vec<(String, Vec<u8>)> = body
            .chunks(part)
            .enumerate()
            .map(|(i, c)| ((i + 1).to_string(), c.to_vec()))
            .collect();
        let uploads = parts.iter().map(|(n, bytes)| {
            let req = self.sign(
                Method::Put,
                path,
                &[("partNumber", n), ("uploadId", &upload_id)],
                &[],
                bytes.clone(),
            );
            self.send(req)
        });
        let results = join_all(uploads).await;
        let mut xml = String::from("<CompleteMultipartUpload>");
        for ((n, _), r) in parts.iter().zip(&results) {
            expect_status(step, &format!("UploadPart {n}"), 200, r);
            let etag = r.header("etag").unwrap_or_else(|| {
                fail(step, &format!("UploadPart {n}"), "an ETag header", "none")
            });
            xml.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
                etag.replace('"', "&quot;")
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        self.s3(
            Method::Post,
            path,
            &[("uploadId", &upload_id)],
            &[("content-type", "application/xml")],
            xml.into_bytes(),
        )
        .await
    }

    // -- catalogue views ----------------------------------------------------

    async fn bucket_id(&self, name: &str) -> BucketId {
        self.bridge
            .catalog
            .bucket_by_name(name)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| fail("catalogue", "bucket exists", name, "absent"))
            .id
    }

    async fn status(&self, step: &str, bucket: &str, key: &str) -> ObjectStatus {
        let b = self.bucket_id(bucket).await;
        match self.bridge.catalog.object_status(&b, key).await {
            Ok(Some(s)) => s,
            Ok(None) => fail(
                step,
                &format!("object_status {bucket}/{key}"),
                "a live object",
                "none",
            ),
            Err(e) => fail(step, &format!("object_status {bucket}/{key}"), "Ok", e),
        }
    }

    fn sql_count(&self, sql: &str) -> i64 {
        self.bridge
            .catalog
            .sql
            .with_conn(|c| c.query_row(sql, [], |r| r.get(0)))
            .expect("count query")
    }

    /// One line per outbox row, for failure messages.
    fn outbox_dump(&self) -> String {
        self.bridge.catalog.sql.with_conn(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT extent_id, stage, attempts, IFNULL(last_error, '-') \
                     FROM outbox ORDER BY extent_id",
                )
                .expect("outbox query");
            let rows = stmt
                .query_map([], |r| {
                    Ok(format!(
                        "{} stage={} attempts={} last_error={}",
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?
                    ))
                })
                .expect("outbox rows")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("outbox rows");
            if rows.is_empty() {
                "no outbox rows".to_string()
            } else {
                rows.join("; ")
            }
        })
    }

    /// Outbox rows still owing work (`post` or `verify`).
    fn outbox_open(&self) -> i64 {
        self.sql_count("SELECT count(*) FROM outbox WHERE stage IN ('post', 'verify')")
    }

    fn outbox_dead(&self) -> i64 {
        self.sql_count("SELECT count(*) FROM outbox WHERE stage = 'dead'")
    }

    // -- the queue and the cron, driven by hand ------------------------------

    /// Runs queued jobs (concurrently within a round, so posts and
    /// verifies overlap) and the dispatcher on simulated cron ticks, until
    /// no outbox row is in `post` or `verify`. Queue delays are honoured by
    /// moving the fixed clock; nothing sleeps.
    async fn pump(&self, step: &str) {
        let b = &self.bridge;
        let mut pending: Vec<(UnixMs, Job)> = Vec::new();
        for _ in 0..MAX_ROUNDS {
            if self.outbox_dead() > 0 {
                fail(step, "no outbox row is dead", "0 dead", self.outbox_dump());
            }
            if self.outbox_open() == 0 {
                return;
            }
            let now = b.clock.now();
            for s in b.jobs.take() {
                pending.push((now.plus_secs(s.delay_secs), s.job));
            }
            let (due, later): (Vec<_>, Vec<_>) = pending.into_iter().partition(|(t, _)| *t <= now);
            pending = later;
            if due.is_empty() {
                let next = pending.iter().map(|(t, _)| *t).min();
                match next {
                    Some(t) if t <= now.plus_secs(CRON_SECS) => b.clock.set(t),
                    _ => {
                        b.clock.advance_secs(CRON_SECS);
                        if let Err(e) = b.dispatch().await {
                            fail(step, "Bridge::dispatch (cron tick)", "Ok", e);
                        }
                    }
                }
                continue;
            }
            let outcomes = join_all(due.iter().map(|(_, job)| b.run_job(job))).await;
            for ((_, job), outcome) in due.into_iter().zip(outcomes) {
                if let JobOutcome::Retry { delay_secs } = outcome {
                    pending.push((now.plus_secs(delay_secs), job));
                }
            }
        }
        fail(
            step,
            &format!("outbox drained within {MAX_ROUNDS} rounds"),
            "no row in post or verify",
            self.outbox_dump(),
        );
    }

    // -- the test's own NNTP audit -----------------------------------------

    async fn audit_client(&self) -> NntpClient<NativeTlsTransport> {
        let a = self.server.addr();
        dial(&nntp_config(
            &a.ip().to_string(),
            a.port(),
            AUDIT_USER,
            AUDIT_PASS,
        ))
        .await
        .expect("audit login to the fake server")
    }
}

/// Every 16-byte-aligned block of each plaintext. A plaintext run of 31 or
/// more bytes anywhere in an article contains one of them.
fn plaintext_blocks(plaintexts: &[&[u8]]) -> HashSet<[u8; 16]> {
    plaintexts
        .iter()
        .flat_map(|p| p.as_chunks::<16>().0.iter().copied())
        .collect()
}

fn find_block(haystack: &[u8], blocks: &HashSet<[u8; 16]>) -> Option<usize> {
    haystack
        .windows(16)
        .position(|w| blocks.contains(<&[u8; 16]>::try_from(w).expect("16-byte window")))
}

fn bare(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

// ---------------------------------------------------------------------------
// The slice
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn slice_acceptance() {
    let rig = Rig::new().await;
    let small = test_bytes(1, MIB);
    let big = test_bytes(2, BIG_LEN);

    // Setup: buckets, key, uploads, memory bound, guard self-test.
    let s = "0 setup";
    rig.setup_buckets_and_key(s).await;
    let r = rig.put("/slice/a/small.bin", &small).await;
    expect_status(s, "PUT a/small.bin", 200, &r);
    let r = rig.multipart_put(s, "/slice/a/big.bin", &big, PART).await;
    expect_status(s, "CompleteMultipartUpload a/big.bin", 200, &r);
    let st = rig.admin_json(s, Method::Get, "/status", None).await;
    let peak = st["inflight_peak_bytes"].as_u64();
    expect(
        s,
        "status.inflight_peak_bytes in 1..=INFLIGHT_BUDGET_BYTES (50331648)",
        peak.is_some_and(|p| p > 0 && p <= 50_331_648),
        format!("{peak:?}"),
    );
    let g = rig
        .admin_json(s, Method::Post, "/dev/guard-selftest", None)
        .await;
    expect_eq(
        s,
        "guard-selftest .rolled_back",
        Some(true),
        g["rolled_back"].as_bool(),
    );

    // 1 read-after-write, served from SAFETY.
    let s = "1 read-after-write";
    let slice_id = rig.bucket_id("slice").await;
    let (_, big_extents) = rig
        .bridge
        .catalog
        .live_object(&slice_id, "a/big.bin")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| fail(s, "a/big.bin is live in the catalogue", "live", "absent"));
    expect_eq(s, "a/big.bin extent count", 3, big_extents.len());
    for x in &big_extents {
        expect(
            s,
            &format!("SAFETY holds extent {}", x.id.as_str()),
            rig.bridge.safety.contains(&x.id.safety_key()),
            "absent",
        );
    }
    let r = rig.get("/slice/a/big.bin").await;
    expect_status(s, "GET a/big.bin", 200, &r);
    expect_bytes(s, "GET a/big.bin body", &big, &r.body);
    let r = rig.get("/slice/a/small.bin").await;
    expect_status(s, "GET a/small.bin", 200, &r);
    expect_bytes(s, "GET a/small.bin body", &small, &r.body);

    // 2 HEAD / LIST / multipart ETag / reserved-character key.
    let s = "2 head-list-etag";
    let r = rig.head("/slice/a/big.bin").await;
    expect_status(s, "HEAD a/big.bin", 200, &r);
    expect_eq(
        s,
        "HEAD a/big.bin Content-Length",
        Some(BIG_LEN.to_string().as_str()),
        r.header("content-length"),
    );
    let etag = r.header("etag").unwrap_or("").to_string();
    expect(
        s,
        "multipart ETag shape is \"<32 hex>-3\"",
        etag.len() == 36 && etag.starts_with('"') && etag.ends_with("-3\""),
        &etag,
    );
    let odd = "/slice/a/sp ace+plus%25/ü.bin";
    let r = rig.put(odd, &small).await;
    expect_status(s, "PUT a/sp ace+plus%25/ü.bin", 200, &r);
    let r = rig.head(odd).await;
    expect_status(s, "HEAD a/sp ace+plus%25/ü.bin", 200, &r);
    let r = rig
        .s3(
            Method::Get,
            "/slice",
            &[("list-type", "2"), ("prefix", "a/"), ("delimiter", "/")],
            &[],
            Vec::new(),
        )
        .await;
    expect_status(s, "ListObjectsV2 prefix=a/ delimiter=/", 200, &r);
    let xml = r.text();
    expect_eq(
        s,
        "ListObjectsV2 keys",
        vec!["a/big.bin".to_string(), "a/small.bin".to_string()],
        xml_values(&xml, "Key"),
    );
    expect_eq(
        s,
        "ListObjectsV2 common prefixes",
        vec!["a/sp ace+plus%25/".to_string()],
        common_prefixes(&xml),
    );
    // Continuation: one key per page, three pages in key order.
    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    for page in 1..=4 {
        let mut q: Vec<(&str, &str)> =
            vec![("list-type", "2"), ("prefix", "a/"), ("max-keys", "1")];
        if let Some(t) = token.as_deref() {
            q.push(("continuation-token", t));
        }
        let r = rig.s3(Method::Get, "/slice", &q, &[], Vec::new()).await;
        expect_status(s, &format!("ListObjectsV2 page {page}"), 200, &r);
        let xml = r.text();
        seen.extend(xml_values(&xml, "Key"));
        token = xml_values(&xml, "NextContinuationToken").into_iter().next();
        if token.is_none() {
            break;
        }
    }
    expect_eq(
        s,
        "ListObjectsV2 max-keys=1 pages",
        vec![
            "a/big.bin".to_string(),
            "a/small.bin".to_string(),
            "a/sp ace+plus%25/ü.bin".to_string(),
        ],
        seen,
    );

    // 3 range across the extent boundary at 5 MiB.
    let s = "3 range-across-extents";
    let (start, end) = (PART - 880, PART + 120);
    let range = format!("bytes={start}-{end}");
    let r = rig
        .s3(
            Method::Get,
            "/slice/a/big.bin",
            &[],
            &[("range", &range)],
            Vec::new(),
        )
        .await;
    expect_status(s, &format!("GET a/big.bin Range {range}"), 206, &r);
    expect_eq(
        s,
        "Content-Range",
        Some(format!("bytes {start}-{end}/{BIG_LEN}").as_str()),
        r.header("content-range"),
    );
    expect_bytes(s, "range body", &big[start..=end], &r.body);

    // 3b safety rules.
    let s = "3b safety-rules";
    let r = rig
        .s3(
            Method::Put,
            "/slice/a/cond",
            &[],
            &[("if-none-match", "*")],
            small.clone(),
        )
        .await;
    expect_error(s, "conditional PUT is refused", 501, "NotImplemented", &r);
    let r = rig.head("/slice/a/cond").await;
    expect_eq(s, "HEAD a/cond after the refused PUT", 404, r.status);
    let r = rig
        .s3(
            Method::Post,
            "/slice/a/mp",
            &[("uploads", "")],
            &[],
            Vec::new(),
        )
        .await;
    expect_status(s, "CreateMultipartUpload a/mp", 200, &r);
    let up = xml_values(&r.text(), "UploadId")
        .into_iter()
        .next()
        .unwrap_or_default();
    let r = rig
        .s3(
            Method::Put,
            "/other/a/mp",
            &[("partNumber", "1"), ("uploadId", &up)],
            &[],
            small.clone(),
        )
        .await;
    expect_error(
        s,
        "UploadPart under another bucket",
        404,
        "NoSuchUpload",
        &r,
    );
    let r = rig
        .s3(
            Method::Delete,
            "/other/a/mp",
            &[("uploadId", &up)],
            &[],
            Vec::new(),
        )
        .await;
    expect_error(s, "Abort under another bucket", 404, "NoSuchUpload", &r);
    let r = rig
        .s3(
            Method::Put,
            "/slice/a/mp2",
            &[("partNumber", "1"), ("uploadId", &up)],
            &[],
            small.clone(),
        )
        .await;
    expect_error(s, "UploadPart under another key", 404, "NoSuchUpload", &r);
    let r = rig
        .s3(
            Method::Delete,
            "/slice/a/mp",
            &[("uploadId", &up)],
            &[],
            Vec::new(),
        )
        .await;
    expect(
        s,
        "Abort a/mp under its own bucket and key",
        r.status == 204 || r.status == 200,
        r.summary(),
    );

    // 4 posting and verification reached.
    let s = "4 post-and-verify";
    rig.pump(s).await;
    let st = rig.status(s, "slice", "a/big.bin").await;
    for x in &st.extents {
        let id = x.extent_id.as_str();
        expect(
            s,
            &format!("extent {id} stage is release or done"),
            matches!(x.stage, Some(OutboxStage::Release | OutboxStage::Done)),
            format!("{:?}", x.stage),
        );
        expect(
            s,
            &format!("extent {id} has a counting backbone"),
            x.backbones.iter().any(|b| b.counts),
            format!("{:?}", x.backbones),
        );
    }
    let view = rig
        .admin_json(s, Method::Get, "/objects/slice/a/big.bin", None)
        .await;
    let ok = view["extents"].as_array().is_some_and(|xs| {
        !xs.is_empty()
            && xs.iter().all(|x| {
                matches!(x["stage"].as_str(), Some("release" | "done"))
                    && x["backbones"]
                        .as_array()
                        .is_some_and(|b| b.iter().any(|b| b["counts"] == true))
            })
    });
    expect(
        s,
        "admin object view: every extent released and counted",
        ok,
        view,
    );

    // The spool is exactly the catalogue's article set.
    let catalogued: BTreeSet<String> = rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c
            .prepare("SELECT message_id FROM articles")
            .expect("articles");
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("articles")
            .collect::<std::result::Result<BTreeSet<_>, _>>()
            .expect("articles");
        ids
    });
    let posted: BTreeSet<String> = rig
        .server
        .posted_ids()
        .await
        .iter()
        .map(|i| bare(i))
        .collect();
    expect(s, "articles were posted", !posted.is_empty(), "0 posted");
    if posted != catalogued {
        fail(
            s,
            "fake posted_ids() equals the articles.message_id set",
            format!("{} catalogued ids", catalogued.len()),
            format!(
                "{} posted; posted-only {:?}; catalogued-only {:?}",
                posted.len(),
                posted.difference(&catalogued).take(3).collect::<Vec<_>>(),
                catalogued.difference(&posted).take(3).collect::<Vec<_>>()
            ),
        );
    }
    // No article carries plaintext or the object's names.
    let blocks = plaintext_blocks(&[&small, &big]);
    let mut audit = rig.audit_client().await;
    for id in &posted {
        let mut article = Vec::new();
        audit
            .article_to(id, &mut article)
            .await
            .unwrap_or_else(|e| fail(s, "audit ARTICLE", "the posted article", e));
        let split = article
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap_or(article.len());
        let body = &article[split..];
        // Headers and the yEnc `=ybegin name=` line alike.
        for name in ["small.bin", "big.bin", "ü.bin", "slice"] {
            if article.windows(name.len()).any(|w| w == name.as_bytes()) {
                fail(
                    s,
                    "articles are obfuscated (headers and yEnc name)",
                    "no object name",
                    format!("<{id}> names {name:?}"),
                );
            }
        }
        let payload = velmora_test_nntp::yenc::decode(body);
        expect(
            s,
            &format!("<{id}> has a yEnc payload"),
            !payload.is_empty(),
            "empty",
        );
        // Raw body too: an unencoded post would be garbled by the decode.
        if let Some(at) = find_block(&payload, &blocks).or_else(|| find_block(body, &blocks)) {
            fail(
                s,
                "no article body contains plaintext",
                "ciphertext only",
                format!("<{id}> carries a plaintext block at payload offset {at}"),
            );
        }
    }
    audit.quit().await;

    // 5 cold read: wipe CACHE and SAFETY, then GET from NNTP.
    let s = "5 cold-read";
    let ev = rig
        .admin_json(
            s,
            Method::Post,
            "/evict/slice/a/big.bin?include_safety=1",
            None,
        )
        .await;
    expect(
        s,
        "evict .evicted > 0",
        ev["evicted"].as_u64().is_some_and(|n| n > 0),
        &ev,
    );
    for x in &big_extents {
        let id = x.id.as_str();
        expect(
            s,
            &format!("extent {id} is gone from CACHE and SAFETY"),
            !rig.bridge.cache.contains(&x.id.cache_key())
                && !rig.bridge.safety.contains(&x.id.safety_key()),
            "still stored",
        );
    }
    let bodies_before = rig.n.bodies.get();
    let r = rig.get("/slice/a/big.bin").await;
    expect_status(s, "cold GET a/big.bin", 200, &r);
    expect_bytes(s, "cold GET a/big.bin body", &big, &r.body);
    expect(
        s,
        "the cold GET read article bodies over NNTP",
        rig.n.bodies.get() > bodies_before,
        format!("{} BODY commands", rig.n.bodies.get() - bodies_before),
    );
    for x in &big_extents {
        expect(
            s,
            &format!("extent {} is back in CACHE", x.id.as_str()),
            rig.bridge.cache.contains(&x.id.cache_key()),
            "absent",
        );
    }
    let view = rig
        .admin_json(s, Method::Get, "/objects/slice/a/big.bin", None)
        .await;
    let ok = view["extents"]
        .as_array()
        .is_some_and(|xs| !xs.is_empty() && xs.iter().all(|x| x["cache"] == "present"));
    expect(
        s,
        "admin object view: every extent cache == present",
        ok,
        view,
    );

    // 6 delete.
    let s = "6 delete";
    let r = rig
        .s3(Method::Delete, "/slice/a/small.bin", &[], &[], Vec::new())
        .await;
    expect_eq(s, "DELETE a/small.bin status", 204, r.status);
    let r = rig.head("/slice/a/small.bin").await;
    expect_eq(s, "HEAD a/small.bin after delete", 404, r.status);
    let r = rig.get("/slice/a/small.bin").await;
    expect_error(s, "GET a/small.bin after delete", 404, "NoSuchKey", &r);

    // 7 dispatcher recovery: the queue notification is lost.
    let s = "7 dispatcher-recovery";
    rig.pump(s).await;
    rig.bridge.jobs.take();
    let dropped_before = rig.bridge.jobs.dropped();
    rig.bridge.jobs.drop_next(1);
    let r = rig.put("/slice/a/lost.bin", &small).await;
    expect_status(s, "PUT a/lost.bin", 200, &r);
    expect_eq(
        s,
        "queue sends lost by the PUT",
        dropped_before + 1,
        rig.bridge.jobs.dropped(),
    );
    expect_eq(
        s,
        "queue sends delivered by the PUT",
        0,
        rig.bridge.jobs.sent().len(),
    );
    let st = rig.status(s, "slice", "a/lost.bin").await;
    expect(
        s,
        "a/lost.bin is committed but never enqueued (stage post, 0 attempts)",
        !st.extents.is_empty()
            && st
                .extents
                .iter()
                .all(|x| x.stage == Some(OutboxStage::Post) && x.attempts == 0),
        format!(
            "{:?}",
            st.extents
                .iter()
                .map(|x| (x.stage, x.attempts))
                .collect::<Vec<_>>()
        ),
    );
    let report = rig
        .bridge
        .dispatch()
        .await
        .unwrap_or_else(|e| fail(s, "Bridge::dispatch", "Ok", e));
    expect(
        s,
        "the dispatcher re-enqueues the lost extent",
        report.enqueued >= 1,
        format!("{report:?}"),
    );
    rig.pump(s).await;
    let st = rig.status(s, "slice", "a/lost.bin").await;
    for x in &st.extents {
        let id = x.extent_id.as_str();
        expect(
            s,
            &format!("extent {id} stage is release or done"),
            matches!(x.stage, Some(OutboxStage::Release | OutboxStage::Done)),
            format!("{:?}", x.stage),
        );
        expect(
            s,
            &format!("extent {id} has a counting backbone"),
            x.backbones.iter().any(|b| b.counts),
            format!("{:?}", x.backbones),
        );
    }

    let s = "end";
    expect(
        s,
        "provider sessions never exceeded max_conns",
        rig.n.peak.get() <= MAX_CONNS && rig.n.refused.get() == 0,
        format!("peak {} refused {}", rig.n.peak.get(), rig.n.refused.get()),
    );
}

/// The fake enforces `max_connections = max_conns` for the poster login.
/// Posts, verifies and a cold read run concurrently; the bridge's permits
/// must keep the open sessions at or under the cap, and the server must
/// never refuse a login.
#[tokio::test(flavor = "current_thread")]
async fn permits_never_exceed_max_conns() {
    let rig = Rig::new().await;
    let s = "permits setup";
    rig.setup_buckets_and_key(s).await;

    // One object posted and verified, then evicted so its GET is cold.
    let cold = test_bytes(9, MIB);
    let r = rig.put("/slice/p/cold.bin", &cold).await;
    expect_status(s, "PUT p/cold.bin", 200, &r);
    rig.pump(s).await;
    let ev = rig
        .admin_json(
            s,
            Method::Post,
            "/evict/slice/p/cold.bin?include_safety=1",
            None,
        )
        .await;
    expect(
        s,
        "evict .evicted > 0",
        ev["evicted"].as_u64().is_some_and(|n| n > 0),
        &ev,
    );

    // Four more objects: four post jobs queued at once.
    let s = "permits overlap";
    let bodies: Vec<Vec<u8>> = (0..4).map(|i| test_bytes(10 + i, MIB)).collect();
    for (i, b) in bodies.iter().enumerate() {
        let r = rig.put(&format!("/slice/p/{i}.bin"), b).await;
        expect_status(s, &format!("PUT p/{i}.bin"), 200, &r);
    }
    let queued: Vec<Job> = rig.bridge.jobs.take().into_iter().map(|j| j.job).collect();
    expect(s, "post jobs are queued", queued.len() >= 4, queued.len());
    // All posts and the cold read at once; the clock stands still so no
    // lease or permit expires mid-flight.
    let posts = join_all(queued.iter().map(|j| rig.bridge.run_job(j)));
    let (_, r) = join(posts, rig.get("/slice/p/cold.bin")).await;
    expect_status(s, "cold GET p/cold.bin under load", 200, &r);
    expect_bytes(s, "cold GET p/cold.bin body", &cold, &r.body);

    // The rest (retries, verifies) also overlaps within each round.
    rig.pump(s).await;
    expect(
        s,
        "open provider sessions reached but never exceeded max_conns, and no login was refused",
        rig.n.peak.get() == MAX_CONNS && rig.n.refused.get() == 0,
        format!(
            "peak {} (max_conns {MAX_CONNS}), refused {}, connects {}",
            rig.n.peak.get(),
            rig.n.refused.get(),
            rig.n.connects.get()
        ),
    );
    expect(
        s,
        "every object was posted",
        rig.n.posts.get() >= 5,
        format!("{} POST commands", rig.n.posts.get()),
    );
}

/// Catalogue recovery with nothing but Usenet and the recovery records:
/// after posting, the catalogue, the cache and every pinned
/// extent are lost. A replay rebuilds the catalogue and the objects are
/// read back from NNTP, byte for byte.
#[tokio::test(flavor = "current_thread")]
async fn rebuild_from_usenet_after_losing_the_catalogue() {
    use velmora_bridge::replay::ReplayCursor;

    let rig = Rig::new().await;
    let s = "recovery setup";
    rig.setup_buckets_and_key(s).await;
    let small = test_bytes(11, 300_000);
    let big = test_bytes(12, BIG_LEN);
    expect_status(
        s,
        "PUT a/small.bin",
        200,
        &rig.put("/slice/a/small.bin", &small).await,
    );
    rig.bridge.clock.advance_ms(1000);
    let r = rig.multipart_put(s, "/slice/a/big.bin", &big, PART).await;
    expect_status(s, "Complete a/big.bin", 200, &r);
    rig.bridge.clock.advance_ms(1000);
    expect_status(
        s,
        "PUT a/gone.bin",
        200,
        &rig.put("/slice/a/gone.bin", &small).await,
    );
    rig.bridge.clock.advance_ms(1000);
    let r = rig
        .s3(Method::Delete, "/slice/a/gone.bin", &[], &[], Vec::new())
        .await;
    expect_eq(s, "DELETE a/gone.bin status", 204, r.status);
    let records_before_posting: BTreeSet<String> = rig
        .bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| k.starts_with("m/"))
        .collect();

    // Post, verify, release: the records stay and every posted extent
    // has an article plan record.
    let s = "recovery post-and-release";
    rig.pump(s).await;
    let extents: Vec<String> = rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c
            .prepare(
                "SELECT e.id FROM extents e JOIN objects o ON o.generation_id = e.generation_id",
            )
            .expect("extents");
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("extents")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("extents");
        ids
    });
    expect_eq(s, "live extents", 4, extents.len());
    for id in &extents {
        expect(
            s,
            &format!("extent {id} has an article plan record"),
            rig.bridge.safety.contains(&format!("m/art/{id}")),
            "absent",
        );
    }
    let records: BTreeSet<String> = rig
        .bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| k.starts_with("m/"))
        .collect();
    expect(
        s,
        "release deleted no recovery record",
        records.is_superset(&records_before_posting),
        format!("{:?}", records_before_posting.difference(&records)),
    );

    // First lose the catalogue alone. The replay puts every extent back
    // at the first stage of the pipeline, which finds the articles
    // already posted and verifies them again without posting twice.
    let s = "recovery catalogue-only loss";
    let posted_before = rig.server.posted_ids().await.len();
    let pinned = extents
        .iter()
        .filter(|id| rig.bridge.safety.contains(&format!("x/{id}")))
        .count() as i64;
    let released = extents.len() as i64 - pinned;
    expect(
        s,
        "some live extents were released and some are still pinned",
        pinned > 0 && released > 0,
        format!("{pinned} pinned, {released} released"),
    );
    let wipe = "DELETE FROM outbox; DELETE FROM verifications; DELETE FROM articles; \
                DELETE FROM upload_parts; DELETE FROM uploads; DELETE FROM gc; \
                DELETE FROM objects; DELETE FROM extents; DELETE FROM generations; \
                DELETE FROM grants; DELETE FROM access_keys; DELETE FROM buckets;";
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(wipe).expect("wipe"));
    let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
    let mut published = 0;
    while let Some(at) = cursor {
        let mut report = rig
            .bridge
            .replay_step(at)
            .await
            .unwrap_or_else(|e| fail(s, "Bridge::replay_step", "Ok", e));
        published += report.published;
        cursor = report.next.take();
    }
    expect_eq(s, "generations published", 3, published);
    expect_eq(
        s,
        "pinned live extents back in the pipeline",
        pinned,
        rig.sql_count(
            "SELECT COUNT(*) FROM outbox o JOIN objects l ON l.generation_id = o.generation_id \
             WHERE o.stage = 'post'",
        ),
    );
    rig.pump(s).await;
    expect_eq(s, "dead outbox rows", 0, rig.outbox_dead());
    expect_eq(
        s,
        "articles on the server (nothing posted twice)",
        posted_before,
        rig.server.posted_ids().await.len(),
    );
    expect_eq(
        s,
        "pinned live extents verified again",
        pinned,
        rig.sql_count(
            "SELECT COUNT(DISTINCT v.extent_id) FROM verifications v \
             JOIN extents e ON e.id = v.extent_id \
             JOIN objects l ON l.generation_id = e.generation_id",
        ),
    );

    // Then lose the catalogue, the cache and whatever SAFETY holds
    // besides the records.
    let s = "recovery loss";
    for key in rig.bridge.cache.keys() {
        rig.bridge.cache.delete(&key).await.expect("cache delete");
    }
    for key in rig.bridge.safety.keys() {
        if !key.starts_with("m/") {
            rig.bridge.safety.delete(&key).await.expect("safety delete");
        }
    }
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(wipe).expect("wipe"));
    expect_eq(
        s,
        "catalogue rows after the loss",
        0,
        rig.sql_count("SELECT COUNT(*) FROM generations")
            + rig.sql_count("SELECT COUNT(*) FROM articles"),
    );

    let s = "recovery replay";
    let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
    let (mut published, mut plans, mut deleted) = (0, 0, 0);
    let mut damaged = u64::MAX;
    while let Some(at) = cursor {
        let mut report = rig
            .bridge
            .replay_step(at)
            .await
            .unwrap_or_else(|e| fail(s, "Bridge::replay_step", "Ok", e));
        published += report.published;
        plans += report.article_plans;
        deleted += report.deleted;
        damaged = report.damaged_total;
        expect(
            s,
            "every record opens and publishes",
            report.unreadable.is_empty() && report.unpublishable.is_empty(),
            format!("{report:?}"),
        );
        cursor = report.next.take();
    }
    expect_eq(s, "generations published", 3, published);
    expect_eq(s, "extents with an article plan record", 4, plans);
    expect_eq(s, "objects deleted by a tombstone", 1, deleted);
    expect_eq(s, "damaged generations", 0, damaged);
    expect_eq(
        s,
        "restored plans without the revision of their record",
        0,
        rig.sql_count(
            "SELECT COUNT(*) FROM extents WHERE article_count IS NOT NULL AND plan_rev < 1",
        ),
    );
    expect_eq(
        s,
        "no restored extent waits in the pipeline",
        0,
        rig.outbox_open(),
    );

    // The key and its grants are issued again, then S3 reads work.
    let s = "recovery read-back";
    let key = rig
        .admin_json(
            s,
            Method::Post,
            "/keys",
            Some(serde_json::json!({"buckets": ["slice"], "perm": "rw"})),
        )
        .await;
    *rig.signer.borrow_mut() = Some(Signer {
        akid: key["access_key_id"].as_str().expect("akid").to_string(),
        secret: key["secret"].as_str().expect("secret").to_string(),
        host: S3_HOST.to_string(),
        region: REGION.to_string(),
    });
    let bodies_before = rig.n.bodies.get();
    let r = rig.get("/slice/a/small.bin").await;
    expect_status(s, "GET a/small.bin", 200, &r);
    expect_bytes(s, "GET a/small.bin body", &small, &r.body);
    let r = rig.get("/slice/a/big.bin").await;
    expect_status(s, "GET a/big.bin", 200, &r);
    expect_bytes(s, "GET a/big.bin body", &big, &r.body);
    expect(
        s,
        "the reads came from NNTP",
        rig.n.bodies.get() > bodies_before,
        format!("{} BODY commands", rig.n.bodies.get() - bodies_before),
    );
    let r = rig.get("/slice/a/gone.bin").await;
    expect_error(s, "GET a/gone.bin stays deleted", 404, "NoSuchKey", &r);
    // Nothing is left for the pipeline: a released extent comes back as
    // done, and its verification history is the scrub's to rebuild.
    let s = "recovery dispatch";
    rig.bridge.clock.advance_secs(CRON_SECS);
    if let Err(e) = rig.bridge.dispatch().await {
        fail(s, "Bridge::dispatch", "Ok", e);
    }
    rig.pump(s).await;
    expect_eq(s, "dead outbox rows", 0, rig.outbox_dead());
}

#[test]
fn signer_matches_the_published_aws_example() {
    // The GetObject example of the AWS SigV4 documentation: us-east-1,
    // examplebucket, `Range: bytes=0-9`, 2013-05-24T00:00:00Z, empty body.
    assert_eq!(amz_date(UnixMs(1_369_353_600_000)).0, "20130524T000000Z");
    assert_eq!(amz_date(T0).0, "20261113T000000Z");
    let signer = Signer {
        akid: "AKIAIOSFODNN7EXAMPLE".into(),
        secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        host: "examplebucket.s3.amazonaws.com".into(),
        region: "us-east-1".into(),
    };
    let req = signer.sign(
        UnixMs(1_369_353_600_000),
        Method::Get,
        "/test.txt",
        &[],
        &[("Range", "bytes=0-9")],
        Vec::new(),
    );
    let auth = req
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        auth,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
         SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
         Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert_eq!(req.target, "/test.txt");
    assert_eq!(
        uri_encode("a/sp ace+plus%25/ü.bin", true),
        "a/sp%20ace%2Bplus%2525/%C3%BC.bin"
    );
    let req = signer.sign(
        T0,
        Method::Post,
        "/b/k",
        &[("uploads", "")],
        &[],
        Vec::new(),
    );
    assert_eq!(req.target, "/b/k?uploads");
}
