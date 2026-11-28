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
use velmora_bridge::testkit::{
    FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek, NEXT_DROP_SUPERSEDED_INDEXES,
};
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
        RespBody::Deferred(d) => d
            .settle(Box::pin(std::future::pending()))
            .await
            .map_err(|_| "the window never elapses".to_string()),
        RespBody::Fanout(_) => Err("a body in sub-ranges".to_string()),
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
        Rig::with_vars(&[]).await
    }

    /// The dev configuration with `extra` variables set on top of it.
    async fn with_vars(extra: &[(&'static str, &str)]) -> Rig {
        Rig::with_backbones(extra, 1).await
    }

    /// As [`Rig::with_vars`], with `backbones` providers: each its own
    /// login and backbone, all on the one fake server (an article posted
    /// through one is at once readable through the others).
    async fn with_backbones(extra: &[(&'static str, &str)], backbones: usize) -> Rig {
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
        for i in 1..backbones {
            cfg.users.insert(
                format!("{POSTER_USER}{}", i + 1),
                UserConfig {
                    password: POSTER_PASS.to_string(),
                    max_connections: MAX_CONNS as usize,
                },
            );
        }
        let server = TestNntpServer::spawn(cfg).await;

        let providers: Vec<serde_json::Value> = (0..backbones)
            .map(|i| {
                let n = if i == 0 {
                    String::new()
                } else {
                    (i + 1).to_string()
                };
                serde_json::json!({
                    "id": format!("fake{}", i + 1),
                    "host": server.addr().ip().to_string(),
                    "port": server.addr().port(),
                    "tls": false,
                    "user": format!("{POSTER_USER}{n}"),
                    "pass": POSTER_PASS,
                    "backbone": format!("fake-backbone{n}"),
                    "post": true,
                    "read": true,
                    "max_conns": MAX_CONNS,
                })
            })
            .collect();
        let providers = serde_json::Value::Array(providers).to_string();
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
            ("SERVER_SIDE_COPY", "on"),
            ("ADMIN_TOKEN", ADMIN_TOKEN),
        ]
        .into_iter()
        .map(|(k, v)| (k, v.to_string()))
        .collect();
        vars.insert("NNTP_PROVIDERS", providers);
        for (k, v) in extra {
            vars.insert(k, v.to_string());
        }
        // TestKek's version 1; the config only checks its presence and shape.
        vars.insert(
            "VELMORA_KEK_1",
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
        );
        let cfg = BridgeConfig::from_vars(|k| vars.get(k).cloned())
            .unwrap_or_else(|e| fail("setup", "BridgeConfig::from_vars", "Ok", e));

        let connector = CountingConnector::default();
        let n = Rc::clone(&connector.n);
        let sql = RusqliteSql::with_schema().expect("schema applies");
        sql.meter_writes().expect("the write meter installs");
        let bridge = Rc::new(Bridge {
            catalog: SqlCatalog::new(sql),
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
        self.multipart_put_after(step, path, body, part, 0).await
    }

    /// [`Rig::multipart_put`] with `wait_secs` between the last part and
    /// the Complete.
    async fn multipart_put_after(
        &self,
        step: &str,
        path: &str,
        body: &[u8],
        part: usize,
        wait_secs: u32,
    ) -> Resp {
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
        self.bridge.clock.advance_secs(wait_secs);
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

    /// Bytes in use per table and index (`dbstat`: page size less the
    /// unused part of each page), largest first.
    fn db_used(&self) -> BTreeMap<String, i64> {
        self.bridge.catalog.sql.with_conn(|c| {
            let mut stmt = c
                .prepare("SELECT name, SUM(pgsize - unused) FROM dbstat GROUP BY name")
                .expect("dbstat");
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .expect("dbstat")
                .collect::<std::result::Result<BTreeMap<_, _>, _>>()
                .expect("dbstat");
            rows
        })
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
        self.pump_jobs(step, false).await;
    }

    /// `pump`, with the jobs that are due at one time run one after the
    /// other when `in_turn`: no job is ever put off because another one
    /// holds the provider's slots, so the catalogue writes of a run do
    /// not depend on how the jobs happen to interleave.
    async fn pump_jobs(&self, step: &str, in_turn: bool) {
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
            let outcomes = match in_turn {
                false => join_all(due.iter().map(|(_, job)| b.run_job(job))).await,
                true => {
                    let mut outcomes = Vec::new();
                    for (_, job) in &due {
                        outcomes.push(b.run_job(job).await);
                    }
                    outcomes
                }
            };
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

// Compile the Worker runner itself with a local table and recording sink.
// The Worker and its tests do not need any new bindings or dependencies.
#[path = "../../../workers/s3-bridge/src/queue_attempt.rs"]
mod worker_queue_attempt;

mod jobs {
    use super::{JobOutcome, UnixMs};
    use std::future::Future;

    pub(crate) async fn run(
        _now: UnixMs,
        _post: bool,
        job: impl Future<Output = JobOutcome> + 'static,
    ) -> Option<JobOutcome> {
        Some(job.await)
    }
}

mod metrics {
    use std::cell::RefCell;
    use velmora_bridge::metrics::Point;

    thread_local! {
        static POINTS: RefCell<Vec<Point>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn write(point: &Point) {
        POINTS.with(|points| points.borrow_mut().push(point.clone()));
    }

    pub(crate) fn take() -> Vec<Point> {
        POINTS.with(RefCell::take)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn sampled_job_points_follow_the_fake_nntp_post_verify_release() {
    use std::rc::Rc;

    async fn run(rig: Rc<Rig>, job: Job, queue: &str, post: bool) -> JobOutcome {
        worker_queue_attempt::run_in_table(
            rig.bridge.clock.clone(),
            post,
            Some((queue.to_string(), 1)),
            async move { rig.bridge.run_job(&job).await },
        )
        .await
    }

    let rig = Rc::new(Rig::new().await);
    let step = "sampled queue attempts";
    rig.setup_buckets_and_key(step).await;
    let body = test_bytes(31, MIB);
    expect_status(
        step,
        "PUT",
        200,
        &rig.put("/slice/private-key", &body).await,
    );
    let bridge = &rig.bridge;
    bridge.safety.advance_reads_on(&bridge.clock, 3);
    for (kind, queue, lane) in [
        ("post", "velmora-post-dev", "post1"),
        ("verify", "velmora-verify-dev", "verify1"),
        ("release", "velmora-verify-dev", "verify1"),
    ] {
        let mut sent = bridge.jobs.take();
        assert_eq!(sent.len(), 1, "{kind} should have one delivery");
        let sent = sent.remove(0);
        bridge.clock.advance_secs(sent.delay_secs);
        let post = kind == "post";
        assert_eq!(
            run(Rc::clone(&rig), sent.job.clone(), queue, post).await,
            JobOutcome::Ack
        );
        let points = metrics::take();
        assert_eq!(
            points.len(),
            1,
            "{kind}: one emitted point for a claimed job"
        );
        let point = &points[0];
        if post {
            assert_eq!(point.doubles[5], 3.0, "observable R2 wait");
            assert!(point.doubles[2] >= 3.0, "elapsed attempt time");
        }
        assert_eq!(
            point.analytics_blobs().collect::<Vec<_>>(),
            ["job.v1", kind, "ok", "le_1gib", lane, "-"]
        );
        assert_eq!(point.doubles[1], body.len() as f64);
        assert!(point.doubles[9] >= 1.0 && point.doubles[9] <= point.doubles[10]);
        assert!(point.doubles[11] >= 1.0);
        assert_eq!(
            &point.doubles[13..],
            &[0.0; 7],
            "fake provider ids must not appear"
        );
        assert_eq!(
            run(Rc::clone(&rig), sent.job, queue, post).await,
            JobOutcome::Ack
        );
        assert!(
            metrics::take().is_empty(),
            "duplicate delivery emitted a point"
        );
    }
}

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
            &[("if-unmodified-since", "Fri, 13 Nov 2026 00:00:00 GMT")],
            small.clone(),
        )
        .await;
    expect_error(
        s,
        "a condition no write evaluates is refused",
        501,
        "NotImplemented",
        &r,
    );
    let r = rig.head("/slice/a/cond").await;
    expect_eq(s, "HEAD a/cond after the refused PUT", 404, r.status);

    // 3a conditional writes: create once, replace only what is named.
    let s = "3a conditional-writes";
    let cond = |headers: &'static [(&'static str, &'static str)], body: Vec<u8>| {
        rig.s3(Method::Put, "/slice/a/cond", &[], headers, body)
    };
    let r = cond(&[("if-none-match", "*")], small.clone()).await;
    expect_eq(s, "PUT If-None-Match: * on a free key", 200, r.status);
    let first = r.header("etag").unwrap_or_default().to_string();
    let r = cond(&[("if-none-match", "*")], small.clone()).await;
    expect_error(
        s,
        "PUT If-None-Match: * on a live key",
        412,
        "PreconditionFailed",
        &r,
    );
    let r = cond(
        &[("if-match", "\"0123456789abcdef0123456789abcdef\"")],
        b"second".to_vec(),
    )
    .await;
    expect_error(
        s,
        "PUT If-Match with another ETag",
        412,
        "PreconditionFailed",
        &r,
    );
    let r = rig.get("/slice/a/cond").await;
    expect_bytes(s, "a/cond after the refused PUTs", &small, &r.body);
    let r = rig
        .s3(
            Method::Put,
            "/slice/a/cond",
            &[],
            &[("if-match", first.as_str())],
            b"second".to_vec(),
        )
        .await;
    expect_eq(s, "PUT If-Match with the live ETag", 200, r.status);
    let r = rig
        .s3(
            Method::Delete,
            "/slice/a/cond",
            &[],
            &[("if-match", first.as_str())],
            Vec::new(),
        )
        .await;
    expect_error(
        s,
        "DELETE If-Match with the replaced ETag",
        412,
        "PreconditionFailed",
        &r,
    );
    let r = rig
        .s3(
            Method::Delete,
            "/slice/a/cond",
            &[],
            &[("if-match", "*")],
            Vec::new(),
        )
        .await;
    expect_eq(s, "DELETE If-Match: *", 204, r.status);
    let r = rig.head("/slice/a/cond").await;
    expect_eq(s, "HEAD a/cond after the delete", 404, r.status);
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
    // The queue took the message, so the row is marked as sent: the
    // dispatcher leaves it alone until the mark has aged.
    let report = rig
        .bridge
        .dispatch()
        .await
        .unwrap_or_else(|e| fail(s, "Bridge::dispatch", "Ok", e));
    expect_eq(s, "jobs sent again at once", 0, report.enqueued);
    rig.bridge
        .clock
        .advance_secs(velmora_bridge::jobs::RESEND_SECS);
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

/// A copy shares the extents of its source. Deleting or overwriting the
/// source, before or after posting, must leave the copy readable from
/// Usenet alone, and garbage collection must wait for the last reference.
#[tokio::test(flavor = "current_thread")]
async fn copy_outlives_its_source() {
    let rig = Rig::new().await;
    let small = test_bytes(3, MIB);
    let big = test_bytes(4, BIG_LEN);
    let gc = Job::Gc { v: JOB_VERSION };

    let s = "copy 0 setup";
    rig.setup_buckets_and_key(s).await;
    let slice = rig.bucket_id("slice").await;
    let r = rig.put("/slice/c/small.bin", &small).await;
    expect_status(s, "PUT c/small.bin", 200, &r);
    let r = rig.multipart_put(s, "/slice/c/big.bin", &big, PART).await;
    expect_status(s, "CompleteMultipartUpload c/big.bin", 200, &r);
    let mut shared = Vec::new();
    for key in ["c/small.bin", "c/big.bin"] {
        let (_, extents) = rig
            .bridge
            .catalog
            .live_object(&slice, key)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| fail(s, "live object", key, "none"));
        shared.extend(extents.into_iter().map(|x| x.id));
    }
    expect_eq(s, "extents of both sources", 4, shared.len());

    let s = "copy 1 copy";
    for (from, to) in [
        ("/slice/c/small.bin", "/slice/d/small-copy.bin"),
        ("/slice/c/big.bin", "/slice/d/big-copy.bin"),
    ] {
        let r = rig
            .s3(
                Method::Put,
                to,
                &[],
                &[("x-amz-copy-source", from)],
                Vec::new(),
            )
            .await;
        expect_status(s, &format!("CopyObject {from} to {to}"), 200, &r);
        expect(
            s,
            "the copy answers with a CopyObjectResult",
            r.text().contains("<CopyObjectResult>"),
            r.summary(),
        );
    }
    expect_eq(
        s,
        "no extent was written for the copies",
        4,
        rig.sql_count("SELECT count(*) FROM extents"),
    );
    let r = rig.get("/slice/d/big-copy.bin").await;
    expect_status(s, "GET d/big-copy.bin", 200, &r);
    expect_bytes(s, "GET d/big-copy.bin body", &big, &r.body);
    let r = rig
        .s3(
            Method::Get,
            "/slice/d/big-copy.bin",
            &[],
            &[("range", "bytes=5242870-5242889")],
            Vec::new(),
        )
        .await;
    expect_status(
        s,
        "range GET across an extent boundary of the copy",
        206,
        &r,
    );
    expect_bytes(s, "range body", &big[5_242_870..5_242_890], &r.body);

    // The sources go before anything was posted: one deleted, one
    // overwritten. Posting must carry on for the copies.
    let s = "copy 2 sources-gone";
    let r = rig
        .s3(Method::Delete, "/slice/c/small.bin", &[], &[], Vec::new())
        .await;
    expect_eq(s, "DELETE c/small.bin status", 204, r.status);
    let other = test_bytes(5, 4096);
    let r = rig.put("/slice/c/big.bin", &other).await;
    expect_status(s, "overwrite c/big.bin", 200, &r);
    expect_eq(
        s,
        "posting obligations cancelled",
        0,
        rig.sql_count("SELECT count(*) FROM outbox WHERE stage = 'cancelled'"),
    );
    expect_eq(
        s,
        "garbage-collection rows queued",
        0,
        rig.sql_count("SELECT count(*) FROM gc"),
    );
    rig.pump(s).await;
    for key in ["d/small-copy.bin", "d/big-copy.bin"] {
        let st = rig.status(s, "slice", key).await;
        for x in &st.extents {
            expect(
                s,
                &format!(
                    "{key}: extent {} is posted, verified and counted",
                    x.extent_id.as_str()
                ),
                matches!(x.stage, Some(OutboxStage::Release | OutboxStage::Done))
                    && x.backbones.iter().any(|b| b.counts),
                format!("{:?} {:?}", x.stage, x.backbones),
            );
        }
    }
    rig.bridge.clock.advance_secs(2 * 86_400);
    expect_eq(
        s,
        "garbage-collection job",
        JobOutcome::Ack,
        rig.bridge.run_job(&gc).await,
    );

    // Only Usenet holds the bytes now.
    let s = "copy 3 cold-read";
    for key in ["d/small-copy.bin", "d/big-copy.bin"] {
        let ev = rig
            .admin_json(
                s,
                Method::Post,
                &format!("/evict/slice/{key}?include_safety=1"),
                None,
            )
            .await;
        expect(
            s,
            &format!("evict {key} .evicted > 0"),
            ev["evicted"].as_u64().is_some_and(|n| n > 0),
            &ev,
        );
    }
    for id in &shared {
        expect(
            s,
            &format!("extent {} is gone from CACHE and SAFETY", id.as_str()),
            !rig.bridge.cache.contains(&id.cache_key())
                && !rig.bridge.safety.contains(&id.safety_key()),
            "still stored",
        );
    }
    let bodies_before = rig.n.bodies.get();
    let r = rig.get("/slice/d/small-copy.bin").await;
    expect_status(s, "cold GET d/small-copy.bin", 200, &r);
    expect_bytes(s, "cold GET d/small-copy.bin body", &small, &r.body);
    let r = rig.get("/slice/d/big-copy.bin").await;
    expect_status(s, "cold GET d/big-copy.bin", 200, &r);
    expect_bytes(s, "cold GET d/big-copy.bin body", &big, &r.body);
    expect(
        s,
        "the cold GETs read article bodies over NNTP",
        rig.n.bodies.get() > bodies_before,
        format!("{} BODY commands", rig.n.bodies.get() - bodies_before),
    );
    let r = rig.get("/slice/c/small.bin").await;
    expect_error(s, "GET the deleted source", 404, "NoSuchKey", &r);
    let r = rig.get("/slice/c/big.bin").await;
    expect_bytes(s, "GET the overwritten source", &other, &r.body);

    // The last references go: now the extents are collected.
    let s = "copy 4 last-reference";
    for key in ["/slice/d/small-copy.bin", "/slice/d/big-copy.bin"] {
        let r = rig.s3(Method::Delete, key, &[], &[], Vec::new()).await;
        expect_eq(s, &format!("DELETE {key} status"), 204, r.status);
    }
    expect_eq(
        s,
        "extents with garbage-collection rows",
        4,
        rig.sql_count("SELECT count(DISTINCT extent_id) FROM gc"),
    );
    rig.bridge.clock.advance_secs(2 * 86_400);
    expect_eq(
        s,
        "garbage-collection job",
        JobOutcome::Ack,
        rig.bridge.run_job(&gc).await,
    );
    expect_eq(
        s,
        "open garbage-collection rows",
        0,
        rig.sql_count("SELECT count(*) FROM gc WHERE done_at IS NULL"),
    );
    for id in &shared {
        expect(
            s,
            &format!("extent {} is gone from CACHE", id.as_str()),
            !rig.bridge.cache.contains(&id.cache_key()),
            "still cached",
        );
    }
    expect_eq(
        s,
        "wrapped file keys left (the overwrite's extent)",
        1,
        rig.sql_count("SELECT count(*) FROM extents WHERE wrapped_file_key IS NOT NULL"),
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
    rebuild_from_usenet("off").await;
}

/// The same loss and rebuild with every article plan stored packed: the
/// replay restores the packed plans from their records, without a row
/// per article, and the objects read back from Usenet.
#[tokio::test(flavor = "current_thread")]
async fn rebuild_from_usenet_with_packed_plans() {
    rebuild_from_usenet("on").await;
}

/// Catalogue rows that a wipe of the catalogue removes.
const WIPE: &str = "DELETE FROM generation_extents; DELETE FROM outbox; DELETE FROM key_floors; \
     DELETE FROM verifications; DELETE FROM articles; \
     DELETE FROM upload_parts; DELETE FROM uploads; DELETE FROM gc; \
     DELETE FROM objects; DELETE FROM extents; DELETE FROM generations; \
     DELETE FROM grants; DELETE FROM access_keys; DELETE FROM buckets;";

async fn rebuild_from_usenet(packed_plans: &str) {
    use velmora_bridge::replay::ReplayCursor;

    let packed = packed_plans == "on";
    let rig = Rig::with_vars(&[("PACKED_PLANS", packed_plans)]).await;
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
    // A release keeps the copy in R2 until the hot tier evicts it. Evict
    // all that may go, so that the replay meets extents with a copy
    // (still pinned) and without one.
    // More than any tier holds, and still an integer the database takes.
    let all = MAX_SQL_INT as u64;
    rig.bridge
        .catalog
        .hot_drain_set(all)
        .await
        .unwrap_or_else(|e| fail(s, "Catalog::hot_drain_set", "Ok", e));
    rig.bridge
        .evict_batch(all)
        .await
        .unwrap_or_else(|e| fail(s, "Bridge::evict_batch", "Ok", e));
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
    let wipe = WIPE;
    // A packed plan is one value on its extent: no row per article at
    // any time. As rows there is one per article.
    let article_rows = rig.sql_count("SELECT COUNT(*) FROM articles");
    let packed_extents = rig
        .sql_count("SELECT COUNT(*) FROM extents WHERE plan IS NOT NULL AND posted_at IS NOT NULL");
    match packed {
        true => expect_eq(
            s,
            "(article rows, packed plans)",
            (0, 4),
            (article_rows, packed_extents),
        ),
        false => expect(
            s,
            "plans are rows",
            article_rows >= 4 && packed_extents == 0,
            format!("{article_rows} article rows, {packed_extents} packed plans"),
        ),
    }
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
    // besides the records and the rollback stamps (no delete removes
    // either).
    let s = "recovery loss";
    for key in rig.bridge.cache.keys() {
        rig.bridge.cache.delete(&key).await.expect("cache delete");
    }
    for key in rig.bridge.safety.keys() {
        if !velmora_bridge::recovery::is_protected_key(&key) {
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
    // The replay restores each plan in the form the catalogue stores
    // them in: packed from the seed in its record (well under a hundred
    // bytes per article), or one row per article.
    let article_rows = rig.sql_count("SELECT COUNT(*) FROM articles");
    let small_plans = rig.sql_count(
        "SELECT COUNT(*) FROM extents WHERE plan IS NOT NULL AND length(plan) < 1024 \
           AND posted_at IS NOT NULL",
    );
    match packed {
        true => expect_eq(
            s,
            "(article rows, packed plans)",
            (0, 4),
            (article_rows, small_plans),
        ),
        false => expect(
            s,
            "plans are rows again",
            article_rows >= 4 && small_plans == 0,
            format!("{article_rows} article rows, {small_plans} packed plans"),
        ),
    }

    if packed {
        // A catalogue that lost the packed plans alone (each extent
        // still has its article count) gets them back from the records.
        let s = "recovery of lost plans";
        rig.bridge.catalog.sql.with_conn(|c| {
            c.execute_batch(
                "DROP TRIGGER extents_keep_plan_in_service; UPDATE extents SET plan = NULL;",
            )
            .expect("lose the plans");
        });
        let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
        let mut damaged = u64::MAX;
        while let Some(at) = cursor {
            let mut report = rig
                .bridge
                .replay_step(at)
                .await
                .unwrap_or_else(|e| fail(s, "Bridge::replay_step", "Ok", e));
            damaged = report.damaged_total;
            cursor = report.next.take();
        }
        expect_eq(s, "damaged generations", 0, damaged);
        expect_eq(
            s,
            "packed plans",
            4,
            rig.sql_count(
                "SELECT COUNT(*) FROM extents WHERE plan IS NOT NULL AND length(plan) < 1024 \
                   AND posted_at IS NOT NULL",
            ),
        );
    }

    if packed {
        // A stored plan that cannot be read (a damaged value, the plan
        // of another extent) is no plan, and the schema keeps it on an
        // extent in service: the replay puts the record's plan in its
        // place. A plan that reads is left as it is.
        let s = "recovery of unreadable plans";
        let plans = |rig: &Rig| -> Vec<(String, Vec<u8>)> {
            rig.bridge.catalog.sql.with_conn(|c| {
                let mut q = c
                    .prepare("SELECT id, plan FROM extents WHERE plan IS NOT NULL ORDER BY id")
                    .expect("prepare");
                let rows = q
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .expect("query");
                rows.map(|r| r.expect("row")).collect()
            })
        };
        let mut before = plans(&rig);
        expect_eq(s, "packed plans before", 4, before.len());
        // The fourth plan reads, and is not what the replay would
        // store: the same articles in the other packed form.
        let other_form = {
            let (id, seeded) = &before[3];
            let id = ExtentId::new(id.clone());
            let size: i64 = rig.bridge.catalog.sql.with_conn(|c| {
                c.query_row(
                    "SELECT cipher_size FROM extents WHERE id = ?1",
                    [id.as_str()],
                    |r| r.get(0),
                )
                .expect("cipher size")
            });
            let size = u64::try_from(size).expect("a size");
            let rows = velmora_bridge::plan::expand(&id, size, seeded, None, None)
                .unwrap_or_else(|e| fail(s, "plan::expand", "Ok", e));
            velmora_bridge::plan::pack_explicit(&id, size, &rows)
                .unwrap_or_else(|e| fail(s, "plan::pack_explicit", "Ok", e))
        };
        expect(
            s,
            "the other form is another value",
            other_form != before[3].1,
            String::new(),
        );
        let mut cut = before[0].1.clone();
        cut.truncate(cut.len() - 1);
        let mut flipped = before[1].1.clone();
        *flipped.last_mut().expect("a plan") ^= 1;
        // The third extent gets the plan of the fourth.
        let damage = [
            (before[0].0.clone(), cut),
            (before[1].0.clone(), flipped),
            (before[2].0.clone(), before[3].1.clone()),
            (before[3].0.clone(), other_form.clone()),
        ];
        // What the replay must leave: three plans of the records, and
        // the fourth as it is now.
        before[3].1 = other_form;
        rig.bridge.catalog.sql.with_conn(|c| {
            for (id, plan) in &damage {
                let n = c
                    .execute(
                        "UPDATE extents SET plan = ?2 WHERE id = ?1",
                        rusqlite::params![id, plan],
                    )
                    .expect("damage a plan");
                assert_eq!(n, 1);
            }
        });
        expect(
            s,
            "the plans are damaged",
            plans(&rig) != before,
            String::new(),
        );
        let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
        while let Some(at) = cursor {
            let mut report = rig
                .bridge
                .replay_step(at)
                .await
                .unwrap_or_else(|e| fail(s, "Bridge::replay_step", "Ok", e));
            expect_eq(s, "unreadable", Vec::<String>::new(), report.unreadable);
            cursor = report.next.take();
        }
        expect(
            s,
            "unreadable plans are their record's again, a plan that reads is kept",
            plans(&rig) == before,
            String::new(),
        );
    }

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

/// A PutObject above one extent is stored in slices. Each slice is an
/// extent like any other: it is posted and verified, and the object is
/// rebuilt from its recovery record and read from Usenet.
#[tokio::test(flavor = "current_thread")]
async fn a_sliced_put_posts_verifies_and_reads_back_from_usenet() {
    use velmora_bridge::replay::ReplayCursor;

    let rig = Rig::with_vars(&[("MAX_PUT_BYTES", "103809024")]).await;
    let s = "sliced setup";
    rig.setup_buckets_and_key(s).await;
    // Three slices of the default 8 MiB: two full ones and 4 MiB + 1 B.
    let body = test_bytes(21, 20 * MIB + 1);
    let r = rig.put("/slice/a/sliced.bin", &body).await;
    expect_status(s, "PUT a/sliced.bin", 200, &r);
    expect_eq(
        s,
        "ETag is the MD5 of the body",
        Some(format!("\"{:x}\"", md5::compute(&body))),
        r.header("etag").map(str::to_string),
    );
    let sizes: Vec<i64> = rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c
            .prepare("SELECT plain_size FROM extents ORDER BY seq")
            .expect("extents");
        let sizes = stmt
            .query_map([], |r| r.get::<_, i64>(0))
            .expect("extents")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("extents");
        sizes
    });
    expect_eq(
        s,
        "slice sizes",
        vec![8 * MIB as i64, 8 * MIB as i64, 4 * MIB as i64 + 1],
        sizes,
    );
    expect_eq(
        s,
        "intent rows after the publish",
        0,
        rig.sql_count("SELECT COUNT(*) FROM write_intents"),
    );

    let s = "sliced post-and-verify";
    rig.pump(s).await;
    expect_eq(s, "dead outbox rows", 0, rig.outbox_dead());
    let extents: Vec<String> = rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c.prepare("SELECT id FROM extents").expect("extents");
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("extents")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("extents");
        ids
    });
    for id in &extents {
        expect(
            s,
            &format!("slice {id} has an article plan record"),
            rig.bridge.safety.contains(&format!("m/art/{id}")),
            "absent",
        );
    }
    expect_eq(
        s,
        "slices verified",
        3,
        rig.sql_count("SELECT COUNT(DISTINCT extent_id) FROM verifications"),
    );
    let st = rig.status(s, "slice", "a/sliced.bin").await;
    expect_eq(s, "slices of the live object", 3, st.extents.len());
    for x in &st.extents {
        let id = x.extent_id.as_str();
        expect(
            s,
            &format!("slice {id} stage is release or done"),
            matches!(x.stage, Some(OutboxStage::Release | OutboxStage::Done)),
            format!("{:?}", x.stage),
        );
        expect(
            s,
            &format!("slice {id} has a counting backbone"),
            x.backbones.iter().any(|b| b.counts),
            format!("{:?}", x.backbones),
        );
    }

    // Lose the catalogue, the cache and everything in SAFETY besides
    // the records and the rollback stamps.
    for key in rig.bridge.cache.keys() {
        rig.bridge.cache.delete(&key).await.expect("cache delete");
    }
    for key in rig.bridge.safety.keys() {
        if !velmora_bridge::recovery::is_protected_key(&key) {
            rig.bridge.safety.delete(&key).await.expect("safety delete");
        }
    }
    let wipe = WIPE;
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(wipe).expect("wipe"));

    let s = "sliced replay";
    let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
    let (mut published, mut plans) = (0, 0);
    let mut damaged = u64::MAX;
    while let Some(at) = cursor {
        let mut report = rig
            .bridge
            .replay_step(at)
            .await
            .unwrap_or_else(|e| fail(s, "Bridge::replay_step", "Ok", e));
        published += report.published;
        plans += report.article_plans;
        damaged = report.damaged_total;
        expect(
            s,
            "every record opens and publishes",
            report.unreadable.is_empty() && report.unpublishable.is_empty(),
            format!("{report:?}"),
        );
        cursor = report.next.take();
    }
    expect_eq(s, "generations published", 1, published);
    expect_eq(s, "slices with an article plan record", 3, plans);
    expect_eq(s, "damaged generations", 0, damaged);

    let s = "sliced read-back";
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
    // A range over the border of the first two slices.
    let (from, to) = (8 * MIB - 3, 8 * MIB + 2);
    let r = rig
        .s3(
            Method::Get,
            "/slice/a/sliced.bin",
            &[],
            &[("range", &format!("bytes={from}-{to}"))],
            Vec::new(),
        )
        .await;
    expect_status(s, "ranged GET a/sliced.bin", 206, &r);
    expect_bytes(s, "ranged GET body", &body[from..=to], &r.body);
    let r = rig.get("/slice/a/sliced.bin").await;
    expect_status(s, "GET a/sliced.bin", 200, &r);
    expect_bytes(s, "GET a/sliced.bin body", &body, &r.body);
    expect(
        s,
        "the reads came from NNTP",
        rig.n.bodies.get() > bodies_before,
        format!("{} BODY commands", rig.n.bodies.get() - bodies_before),
    );
    let r = rig.head("/slice/a/sliced.bin").await;
    expect_eq(
        s,
        "HEAD ETag after the replay",
        Some(format!("\"{:x}\"", md5::compute(&body))),
        r.header("etag").map(str::to_string),
    );
}

/// One row per extent: when it was stored, its outbox stage and due time,
/// when the newest of its articles was posted, and its safety state.
type Soak = (i64, String, i64, i64, String);

impl Rig {
    fn soaks(&self) -> Vec<Soak> {
        self.bridge.catalog.sql.with_conn(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT e.created_at, o.stage, o.next_at, \
                       (SELECT MAX(a.posted_at) FROM articles a WHERE a.extent_id = e.id), \
                       e.safety_state \
                     FROM extents e JOIN outbox o ON o.extent_id = e.id ORDER BY e.seq",
                )
                .expect("soak query");
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .expect("soak rows")
                .collect::<std::result::Result<Vec<Soak>, _>>()
                .expect("soak rows");
            rows
        })
    }

    /// One cron tick, and every job it sends run once.
    async fn tick(&self, step: &str) {
        let b = &self.bridge;
        if let Err(e) = b.dispatch().await {
            fail(step, "Bridge::dispatch (cron tick)", "Ok", e);
        }
        for sent in b.jobs.take() {
            b.run_job(&sent.job).await;
        }
    }
}

/// The parts of a multipart upload are stored when they are uploaded and
/// posted only once the upload is completed, here two days later. The
/// minimum age of their safety copies counts from the post: they are not
/// released the moment the articles are verified, although the extents
/// are twice the minimum age old by then.
#[tokio::test(flavor = "current_thread")]
async fn parts_completed_late_keep_their_safety_copy_for_the_minimum_age() {
    const DAY: u32 = 86_400;
    let rig = Rig::with_vars(&[("SAFETY_MIN_AGE_SECS", "86400")]).await;
    let s = "late complete";
    rig.setup_buckets_and_key(s).await;
    let body = test_bytes(31, BIG_LEN);
    let uploaded = rig.bridge.clock.now();
    let r = rig
        .multipart_put_after(s, "/slice/a/late.bin", &body, PART, 2 * DAY)
        .await;
    expect_status(s, "CompleteMultipartUpload a/late.bin", 200, &r);
    let completed = rig.bridge.clock.now();
    expect_eq(
        s,
        "the Complete is two days late",
        uploaded.plus_secs(2 * DAY),
        completed,
    );

    rig.pump(s).await;
    let soaks = rig.soaks();
    expect_eq(s, "extents", 3, soaks.len());
    for (created, stage, next_at, posted, safety) in &soaks {
        expect(s, "stored at UploadPart", *created <= uploaded.0, created);
        expect(
            s,
            "posted after the Complete",
            *posted >= completed.0,
            posted,
        );
        expect_eq(s, "stage", "release", stage.as_str());
        expect_eq(
            s,
            "release due the minimum age after the post",
            UnixMs(*posted).plus_secs(DAY).0,
            *next_at,
        );
        expect_eq(s, "safety copy", "held", safety.as_str());
    }

    // Up to the last cron tick before the first one is due, nothing is
    // released.
    let first = soaks.iter().map(|r| r.2).min().expect("extents");
    let last = soaks.iter().map(|r| r.2).max().expect("extents");
    rig.bridge.clock.set(UnixMs(first - 1));
    rig.tick(s).await;
    for (.., safety) in rig.soaks() {
        expect_eq(
            s,
            "safety copy before the minimum age",
            "held",
            safety.as_str(),
        );
    }

    // The pump above dropped the wake-ups the verify jobs sent, so the
    // releases are sent by the dispatcher, once their marks have aged.
    rig.bridge
        .clock
        .set(UnixMs(last).plus_secs(velmora_bridge::jobs::RESEND_SECS));
    rig.tick(s).await;
    for (_, stage, .., safety) in rig.soaks() {
        expect_eq(
            s,
            "safety copy after the minimum age",
            "released",
            safety.as_str(),
        );
        expect_eq(s, "stage after the release", "done", stage.as_str());
    }
}

/// Plans stored as rows are packed by the dispatcher once the switch is
/// on: every article stays what it was, no recovery record changes, the
/// objects read from Usenet through the packed plans, and a catalogue
/// rebuilt from the records gets them packed again.
#[tokio::test(flavor = "current_thread")]
async fn a_backfill_packs_posted_plans_and_they_read_from_usenet() {
    use velmora_bridge::replay::ReplayCursor;

    let mut rig = Rig::new().await;
    let s = "backfill setup";
    rig.setup_buckets_and_key(s).await;
    let small = test_bytes(21, 300_000);
    let big = test_bytes(22, BIG_LEN);
    expect_status(
        s,
        "PUT b/small.bin",
        200,
        &rig.put("/slice/b/small.bin", &small).await,
    );
    let r = rig.multipart_put(s, "/slice/b/big.bin", &big, PART).await;
    expect_status(s, "Complete b/big.bin", 200, &r);
    rig.pump(s).await;
    // Uploaded after the others were posted, and not posted itself when
    // the backfill runs: an extent without a plan is left alone.
    let late = test_bytes(23, 200_000);
    expect_status(
        s,
        "PUT b/late.bin",
        200,
        &rig.put("/slice/b/late.bin", &late).await,
    );

    let ids: Vec<String> = rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c
            .prepare("SELECT DISTINCT extent_id FROM articles ORDER BY extent_id")
            .expect("extents");
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("extents")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("extents");
        ids
    });
    expect_eq(s, "extents with a plan in rows", 4, ids.len());
    let mut before = Vec::new();
    for id in &ids {
        let id = ExtentId::new(id.as_str());
        let rows = rig
            .bridge
            .catalog
            .articles(&id)
            .await
            .unwrap_or_else(|e| fail(s, "Catalog::articles", "Ok", e));
        before.push((id, rows));
    }
    let records = |rig: &Rig| -> BTreeMap<String, [u8; 32]> {
        let keys = rig.bridge.safety.keys();
        let records = keys.into_iter().filter(|k| k.starts_with("m/"));
        records
            .map(|k| {
                let blob = rig.bridge.safety.stored(&k).expect("record");
                (k, sha256(&blob.bytes))
            })
            .collect()
    };
    let records_before = records(&rig);

    let s = "backfill";
    // Off: the dispatcher packs nothing.
    rig.bridge.clock.advance_secs(CRON_SECS);
    let report = rig
        .bridge
        .dispatch()
        .await
        .unwrap_or_else(|e| fail(s, "Bridge::dispatch", "Ok", e));
    expect_eq(
        s,
        "plans packed with the switch off",
        0,
        report.plans_packed,
    );
    Rc::get_mut(&mut rig.bridge)
        .expect("the rig holds the only bridge")
        .cfg
        .packed_plans = true;
    // In steps, as the rotation of the dispatcher does it.
    let step = |limit| {
        let rig = &rig;
        async move {
            rig.bridge
                .catalog
                .pack_plans(limit)
                .await
                .unwrap_or_else(|e| fail(s, "Catalog::pack_plans", "Ok", e))
        }
    };
    let first = step(3).await;
    expect_eq(
        s,
        "first step (looked, packed, end)",
        (3, 3, false),
        (first.looked, first.packed, first.end),
    );
    rig.bridge.clock.advance_secs(CRON_SECS);
    let report = rig
        .bridge
        .dispatch()
        .await
        .unwrap_or_else(|e| fail(s, "Bridge::dispatch", "Ok", e));
    expect_eq(s, "plans packed by the dispatcher", 1, report.plans_packed);
    let again = step(3).await;
    expect_eq(
        s,
        "nothing left (looked, packed, end)",
        (0, 0, true),
        (again.looked, again.packed, again.end),
    );
    expect_eq(
        s,
        "article rows",
        0,
        rig.sql_count("SELECT COUNT(*) FROM articles"),
    );
    expect_eq(
        s,
        "packed plans",
        4,
        rig.sql_count("SELECT COUNT(*) FROM extents WHERE plan IS NOT NULL AND posted_at > 0"),
    );
    for (id, rows) in &before {
        let now = rig
            .bridge
            .catalog
            .articles(id)
            .await
            .unwrap_or_else(|e| fail(s, "Catalog::articles", "Ok", e));
        // All of each article is kept but the provider that took it,
        // which nothing reads (a recovery record does not keep it either).
        let mut kept = rows.clone();
        kept.iter_mut().for_each(|a| a.provider_id = None);
        expect(
            s,
            &format!("extent {} keeps its articles", id.as_str()),
            now == kept,
            format!("{} articles before, {} now", rows.len(), now.len()),
        );
    }
    expect(
        s,
        "no recovery record changed",
        records(&rig) == records_before,
        "records differ",
    );

    // Cold: no cache, and no safety copy where the hot tier may drop it.
    let s = "backfill cold read";
    rig.pump(s).await;
    // More than any tier holds, and still an integer the database takes.
    let all = MAX_SQL_INT as u64;
    rig.bridge
        .catalog
        .hot_drain_set(all)
        .await
        .unwrap_or_else(|e| fail(s, "Catalog::hot_drain_set", "Ok", e));
    rig.bridge
        .evict_batch(all)
        .await
        .unwrap_or_else(|e| fail(s, "Bridge::evict_batch", "Ok", e));
    for key in rig.bridge.cache.keys() {
        rig.bridge.cache.delete(&key).await.expect("cache delete");
    }
    let bodies_before = rig.n.bodies.get();
    let r = rig.get("/slice/b/big.bin").await;
    expect_status(s, "GET b/big.bin", 200, &r);
    expect_bytes(s, "GET b/big.bin body", &big, &r.body);
    let r = rig.get("/slice/b/small.bin").await;
    expect_status(s, "GET b/small.bin", 200, &r);
    expect_bytes(s, "GET b/small.bin body", &small, &r.body);
    expect(
        s,
        "the reads came from NNTP",
        rig.n.bodies.get() > bodies_before,
        format!("{} BODY commands", rig.n.bodies.get() - bodies_before),
    );

    // Everything but the records and Usenet is lost. Their records say
    // nothing about packing: the replay packs each plan from its articles.
    let s = "backfill replay";
    for key in rig.bridge.cache.keys() {
        rig.bridge.cache.delete(&key).await.expect("cache delete");
    }
    for key in rig.bridge.safety.keys() {
        if !velmora_bridge::recovery::is_protected_key(&key) {
            rig.bridge.safety.delete(&key).await.expect("safety delete");
        }
    }
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(WIPE).expect("wipe"));
    let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
    while let Some(at) = cursor {
        let mut report = rig
            .bridge
            .replay_step(at)
            .await
            .unwrap_or_else(|e| fail(s, "Bridge::replay_step", "Ok", e));
        expect(
            s,
            "every record opens and publishes",
            report.unreadable.is_empty() && report.unpublishable.is_empty(),
            format!("{report:?}"),
        );
        cursor = report.next.take();
    }
    expect_eq(
        s,
        "article rows",
        0,
        rig.sql_count("SELECT COUNT(*) FROM articles"),
    );
    expect_eq(
        s,
        "packed plans",
        5,
        rig.sql_count("SELECT COUNT(*) FROM extents WHERE plan IS NOT NULL"),
    );
    for (id, rows) in &before {
        let now = rig
            .bridge
            .catalog
            .articles(id)
            .await
            .unwrap_or_else(|e| fail(s, "Catalog::articles", "Ok", e));
        expect(
            s,
            &format!("extent {} has the same articles", id.as_str()),
            velmora_bridge::plan::same_plan(rows, &now),
            format!("{} articles before, {} now", rows.len(), now.len()),
        );
    }
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
    for (path, body) in [
        ("/slice/b/big.bin", &big),
        ("/slice/b/small.bin", &small),
        ("/slice/b/late.bin", &late),
    ] {
        let r = rig.get(path).await;
        expect_status(s, &format!("GET {path}"), 200, &r);
        expect_bytes(s, &format!("GET {path} body"), body, &r.body);
    }
    expect(
        s,
        "the reads came from NNTP",
        rig.n.bodies.get() > bodies_before,
        format!("{} BODY commands", rig.n.bodies.get() - bodies_before),
    );
}

/// An article of a packed plan that a provider lost is posted again from
/// the safety copy: the repost is stamped on the extent, the release
/// waits for the minimum age after it, and the object reads back.
#[tokio::test(flavor = "current_thread")]
async fn a_packed_plan_is_repaired_by_a_repost() {
    let rig = Rig::with_vars(&[
        ("PACKED_PLANS", "on"),
        ("PROPAGATION_GRACE_SECS", "0"),
        ("SAFETY_MIN_AGE_SECS", "3600"),
    ])
    .await;
    let s = "repair setup";
    rig.setup_buckets_and_key(s).await;
    let body = test_bytes(31, 2 * MIB);
    expect_status(
        s,
        "PUT r/one.bin",
        200,
        &rig.put("/slice/r/one.bin", &body).await,
    );
    // The post job alone.
    let sent = rig.bridge.jobs.take();
    expect_eq(s, "jobs after the upload", 1, sent.len());
    let outcome = rig.bridge.run_job(&sent[0].job).await;
    expect(
        s,
        "the post job is done",
        outcome == JobOutcome::Ack,
        format!("{outcome:?}"),
    );
    let id: String = rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row("SELECT id FROM extents WHERE plan IS NOT NULL", [], |r| {
            r.get(0)
        })
        .expect("one packed extent")
    });
    let id = ExtentId::new(id);
    let plan = rig
        .bridge
        .catalog
        .articles(&id)
        .await
        .unwrap_or_else(|e| fail(s, "Catalog::articles", "Ok", e));
    expect(s, "several articles", plan.len() >= 3, plan.len());
    expect_eq(
        s,
        "article rows",
        0,
        rig.sql_count("SELECT COUNT(*) FROM articles"),
    );
    expect_eq(
        s,
        "reposts stamped before any",
        0,
        rig.sql_count("SELECT COUNT(*) FROM extents WHERE reposted_at IS NOT NULL"),
    );

    let s = "repair";
    let lost = &plan[1].message_id;
    rig.server.hide(lost).await;
    let posted_at = rig.sql_count("SELECT posted_at FROM extents WHERE plan IS NOT NULL");
    rig.pump(s).await;
    expect(
        s,
        "the article is back",
        !rig.server.is_hidden(lost).await,
        "still hidden",
    );
    let reposted_at = rig.sql_count("SELECT reposted_at FROM extents WHERE plan IS NOT NULL");
    expect(
        s,
        "the repost is stamped on the extent, after the post",
        reposted_at > posted_at,
        format!("posted {posted_at}, reposted {reposted_at}"),
    );
    let now = rig
        .bridge
        .catalog
        .articles(&id)
        .await
        .unwrap_or_else(|e| fail(s, "Catalog::articles", "Ok", e));
    expect(
        s,
        "the plan is the same articles",
        velmora_bridge::plan::same_plan(&plan, &now),
        "the plan changed",
    );
    expect(
        s,
        "every article carries the repost time (the plan has one stamp)",
        now.iter()
            .all(|a| a.reposted_at == Some(UnixMs(reposted_at))),
        format!(
            "{:?}",
            now.iter().map(|a| a.reposted_at).collect::<Vec<_>>()
        ),
    );
    // The pump stops once nothing is in post or verify: the release
    // waits for the minimum age after the repost, not after the post.
    expect_eq(
        s,
        "release due",
        reposted_at + 3_600_000,
        rig.sql_count("SELECT next_at FROM outbox WHERE stage = 'release'"),
    );
    expect_eq(
        s,
        "article rows",
        0,
        rig.sql_count("SELECT COUNT(*) FROM articles"),
    );
    let r = rig.get("/slice/r/one.bin").await;
    expect_status(s, "GET r/one.bin", 200, &r);
    expect_bytes(s, "GET r/one.bin body", &body, &r.body);
}

/// The crash window of a packed plan, on the SQL catalogue: the provider
/// accepts every article, and the job ends before the plan is recorded
/// as posted. The next job did not draw the plan, so it asks for every
/// article before it sends one: it finds them all and sends nothing. The
/// plan is stamped once, and a second delivery of the job at the same
/// time writes nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_packed_plan_posted_but_not_recorded_is_not_posted_twice() {
    let rig = Rig::with_vars(&[("PACKED_PLANS", "on")]).await;
    let s = "crash window setup";
    rig.setup_buckets_and_key(s).await;
    let body = test_bytes(37, 2 * MIB);
    expect_status(
        s,
        "PUT w/one.bin",
        200,
        &rig.put("/slice/w/one.bin", &body).await,
    );
    let sent = rig.bridge.jobs.take();
    expect_eq(s, "jobs after the upload", 1, sent.len());
    let job = &sent[0].job;
    let stamped = "SELECT COUNT(*) FROM extents WHERE posted_at IS NOT NULL";

    // The write that records the plan as posted fails, each time the
    // job tries it: the job ends as one that died there.
    let s = "crash window";
    rig.bridge.catalog.sql.with_conn(|c| {
        c.execute_batch(
            "CREATE TRIGGER the_job_dies BEFORE UPDATE OF posted_at ON extents \
             BEGIN SELECT RAISE(ABORT, 'the job dies here'); END;",
        )
        .expect("create trigger");
    });
    let outcome = rig.bridge.run_job(job).await;
    expect(
        s,
        "the post job did not finish",
        matches!(outcome, JobOutcome::Retry { .. }),
        format!("{outcome:?}"),
    );
    let articles = rig.server.posted_ids().await.len();
    expect(
        s,
        "the provider took several articles",
        articles >= 3,
        articles,
    );
    expect_eq(
        s,
        "(packed plans, article rows, plans recorded as posted)",
        (1, 0, 0),
        (
            rig.sql_count("SELECT COUNT(*) FROM extents WHERE plan IS NOT NULL"),
            rig.sql_count("SELECT COUNT(*) FROM articles"),
            rig.sql_count(stamped),
        ),
    );
    expect_eq(
        s,
        "outbox rows still to post",
        1,
        rig.sql_count("SELECT COUNT(*) FROM outbox WHERE stage = 'post'"),
    );

    // The provider takes no POST from here on: a job that sent an
    // article before it asked for it would fail.
    let s = "crash window, the next job";
    rig.bridge.catalog.sql.with_conn(|c| {
        c.execute_batch("DROP TRIGGER the_job_dies")
            .expect("drop trigger");
    });
    rig.server.set_posting_allowed(false).await;
    rig.bridge.clock.advance_secs(3600);
    let outcomes = join_all([rig.bridge.run_job(job), rig.bridge.run_job(job)]).await;
    expect(
        s,
        "the job is done, and its second delivery has nothing to do",
        outcomes.iter().all(|o| *o == JobOutcome::Ack),
        format!("{outcomes:?}"),
    );
    expect_eq(s, "plans recorded as posted", 1, rig.sql_count(stamped));
    expect_eq(
        s,
        "articles on the provider",
        articles,
        rig.server.posted_ids().await.len(),
    );
    expect_eq(
        s,
        "outbox rows still to post",
        0,
        rig.sql_count("SELECT COUNT(*) FROM outbox WHERE stage = 'post'"),
    );
    let posted_at = rig.sql_count("SELECT posted_at FROM extents WHERE plan IS NOT NULL");
    // Delivered once more, long after: the stamp stands.
    rig.bridge.clock.advance_secs(600);
    let outcome = rig.bridge.run_job(job).await;
    expect(
        s,
        "a late delivery",
        outcome == JobOutcome::Ack,
        format!("{outcome:?}"),
    );
    expect_eq(
        s,
        "the time the plan was posted",
        posted_at,
        rig.sql_count("SELECT posted_at FROM extents WHERE plan IS NOT NULL"),
    );

    // The rest of the pipeline, and the object from Usenet alone.
    let s = "crash window, read-back";
    rig.server.set_posting_allowed(true).await;
    rig.pump(s).await;
    expect_eq(
        s,
        "articles on the provider",
        articles,
        rig.server.posted_ids().await.len(),
    );
    for key in rig.bridge.cache.keys() {
        rig.bridge.cache.delete(&key).await.expect("cache delete");
    }
    let r = rig.get("/slice/w/one.bin").await;
    expect_status(s, "GET w/one.bin", 200, &r);
    expect_bytes(s, "GET w/one.bin body", &body, &r.body);
}

/// The post job with parity, on the SQL catalogue. The addendum is on the
/// extent's row before an article is sent, the plan is recorded as posted
/// by one write, made after the data articles and the parity articles
/// are all on the provider, and no article row is written.
#[tokio::test(flavor = "current_thread")]
async fn a_plan_with_parity_is_posted_and_recorded_as_a_whole() {
    let rig = Rig::with_vars(&[("PACKED_PLANS", "on"), ("PARITY", "on")]).await;
    let s = "parity setup";
    rig.setup_buckets_and_key(s).await;
    let body = test_bytes(41, 2 * MIB);
    expect_status(
        s,
        "PUT y/one.bin",
        200,
        &rig.put("/slice/y/one.bin", &body).await,
    );
    let sent = rig.bridge.jobs.take();
    expect_eq(s, "jobs after the upload", 1, sent.len());
    let job = &sent[0].job;
    let stamped = "SELECT COUNT(*) FROM extents WHERE posted_at IS NOT NULL";
    let id: String = rig
        .bridge
        .catalog
        .sql
        .with_conn(|c| c.query_row("SELECT id FROM extents", [], |r| r.get(0)))
        .expect("the extent");
    let id = ExtentId::new(id);

    // The provider takes no article: the addendum is stored, and in the
    // extent's recovery record, with nothing sent.
    let s = "parity, before the first POST";
    let planned = "SELECT COUNT(*) FROM extents WHERE parity IS NOT NULL";
    expect_eq(s, "addenda before the job", 0, rig.sql_count(planned));
    rig.server.set_posting_allowed(false).await;
    let outcome = rig.bridge.run_job(job).await;
    expect(
        s,
        "the post job did not finish",
        matches!(outcome, JobOutcome::Retry { .. }),
        format!("{outcome:?}"),
    );
    expect_eq(
        s,
        "articles on the provider",
        0,
        rig.server.posted_ids().await.len(),
    );
    expect_eq(
        s,
        "(addenda, parity articles planned, plans recorded as posted)",
        (1, 1, 0),
        (
            rig.sql_count(planned),
            rig.sql_count("SELECT parity_count FROM extents"),
            rig.sql_count(stamped),
        ),
    );
    let first: Vec<u8> = rig
        .bridge
        .catalog
        .sql
        .with_conn(|c| c.query_row("SELECT parity FROM extents", [], |r| r.get(0)))
        .expect("the addendum");
    expect(
        s,
        "the recovery record of the plan is written",
        rig.bridge.safety.contains(&format!("m/art/{id}")),
        &id,
    );
    rig.server.set_posting_allowed(true).await;
    rig.bridge.clock.advance_secs(3600);

    // The write that records the plan as posted fails: what the job had
    // done when it came to it is all there is.
    let s = "parity, before the plan is recorded";
    rig.bridge.catalog.sql.with_conn(|c| {
        c.execute_batch(
            "CREATE TRIGGER the_job_dies BEFORE UPDATE OF posted_at ON extents \
             BEGIN SELECT RAISE(ABORT, 'the job dies here'); END;",
        )
        .expect("create trigger");
    });
    let outcome = rig.bridge.run_job(job).await;
    expect(
        s,
        "the post job did not finish",
        matches!(outcome, JobOutcome::Retry { .. }),
        format!("{outcome:?}"),
    );
    expect_eq(
        s,
        "(data articles, parity articles) planned",
        (3, 1),
        (
            rig.sql_count("SELECT article_count FROM extents"),
            rig.sql_count("SELECT parity_count FROM extents"),
        ),
    );
    expect_eq(
        s,
        "articles on the provider: the data and the parity",
        4,
        rig.server.posted_ids().await.len(),
    );
    expect_eq(
        s,
        "(article rows, plans recorded as posted)",
        (0, 0),
        (
            rig.sql_count("SELECT COUNT(*) FROM articles"),
            rig.sql_count(stamped),
        ),
    );
    let plan = rig
        .bridge
        .catalog
        .stored_plan(&id)
        .await
        .unwrap_or_else(|e| fail(s, "Catalog::stored_plan", "Ok", e));
    expect(s, "the plan is packed", plan.packed.is_some(), "rows");
    expect_eq(s, "data articles of the plan", 3, plan.rows.len());
    let size = rig.sql_count("SELECT cipher_size FROM extents") as u64;
    let parity = match plan.parity_plan(&id, size) {
        Ok(Some(parity)) => parity,
        other => fail(s, "the stored plan has its addendum", "Some", other.is_ok()),
    };
    expect_eq(
        s,
        "parity articles of the addendum",
        1,
        parity.articles.len(),
    );
    let then: Vec<u8> = rig
        .bridge
        .catalog
        .sql
        .with_conn(|c| c.query_row("SELECT parity FROM extents", [], |r| r.get(0)))
        .expect("the addendum");
    expect(
        s,
        "the addendum is the one stored before the first POST",
        first == then,
        then.len(),
    );
    expect_eq(
        s,
        "(idx, state) of the parity article",
        (3, ArticleState::Planned),
        (parity.articles[0].idx, parity.articles[0].state),
    );
    let on_provider = rig.server.posted_ids().await;
    expect(
        s,
        "the parity article is on the provider",
        on_provider
            .iter()
            .any(|i| bare(i) == parity.articles[0].message_id),
        &parity.articles[0].message_id,
    );

    // The next job finds every article and sends none: the plan is
    // recorded, the parity articles with it.
    let s = "parity, the next job";
    rig.bridge.catalog.sql.with_conn(|c| {
        c.execute_batch("DROP TRIGGER the_job_dies")
            .expect("drop trigger");
    });
    rig.server.set_posting_allowed(false).await;
    rig.bridge.clock.advance_secs(3600);
    let outcome = rig.bridge.run_job(job).await;
    expect(
        s,
        "the job is done",
        outcome == JobOutcome::Ack,
        format!("{outcome:?}"),
    );
    expect_eq(
        s,
        "(article rows, plans recorded as posted)",
        (0, 1),
        (
            rig.sql_count("SELECT COUNT(*) FROM articles"),
            rig.sql_count(stamped),
        ),
    );
    let plan = rig
        .bridge
        .catalog
        .stored_plan(&id)
        .await
        .unwrap_or_else(|e| fail(s, "Catalog::stored_plan", "Ok", e));
    let posted = match plan.parity_plan(&id, size) {
        Ok(Some(parity)) => parity,
        other => fail(s, "the stored plan has its addendum", "Some", other.is_ok()),
    };
    expect(
        s,
        "the addendum did not change",
        posted.articles[0].message_id == parity.articles[0].message_id,
        &posted.articles[0].message_id,
    );
    expect_eq(
        s,
        "state of the parity article",
        ArticleState::Posted,
        posted.articles[0].state,
    );

    // The rest of the pipeline, and the object from Usenet alone.
    let s = "parity, read-back";
    rig.server.set_posting_allowed(true).await;
    rig.pump(s).await;
    expect_eq(
        s,
        "articles on the provider",
        4,
        rig.server.posted_ids().await.len(),
    );
    expect_eq(
        s,
        "article rows",
        0,
        rig.sql_count("SELECT COUNT(*) FROM articles"),
    );
    // Released: the safety copy goes too, so the GET has no source but
    // the articles.
    let ev = rig
        .admin_json(
            s,
            Method::Post,
            "/evict/slice/y/one.bin?include_safety=1",
            None,
        )
        .await;
    expect(
        s,
        "evict .evicted > 0",
        ev["evicted"].as_u64().is_some_and(|n| n > 0),
        &ev,
    );
    for key in rig.bridge.cache.keys() {
        rig.bridge.cache.delete(&key).await.expect("cache delete");
    }
    expect(
        s,
        "no safety copy of the extent",
        !rig.bridge.safety.contains(&id.safety_key()),
        &id,
    );
    let r = rig.get("/slice/y/one.bin").await;
    expect_status(s, "GET y/one.bin", 200, &r);
    expect_bytes(s, "GET y/one.bin body", &body, &r.body);
}

/// What D1 bills, in rows written, for an object over its whole life:
/// upload, post, verification on two backbones, a day's wait and the
/// release. Objects of one and of three 16 MiB extents give the cost of an
/// extent and the cost of an object apart from its extents. Returns
/// `(rows per extent, rows per object, bytes kept per extent)`: the bytes
/// are what the catalogue holds for a released extent (`dbstat`, without
/// the free space of its pages).
/// `counters`: with the usage counters on, as production runs once
/// counted. `dropped`: on the schema of the next release, without the
/// indexes `extents_safety` replaced.
async fn rows_written(packed_plans: &str, counters: bool, dropped: bool) -> (u64, u64, i64) {
    const DAY: u32 = 86_400;
    const EXTENT: usize = 16 * MIB;
    let rig = Rig::with_backbones(
        &[
            ("SAFETY_MIN_AGE_SECS", "86400"),
            ("REQUIRED_BACKBONES", "2"),
            ("VERIFY_DELAY_SECS", "120"),
            ("MAX_PUT_BYTES", "103809024"),
            ("PACKED_PLANS", packed_plans),
        ],
        2,
    )
    .await;
    let s = "rows written";
    // A catalogue whose first sweep of the eviction order has run: the
    // figures are the life of an object, not of the catalogue.
    rig.bridge
        .catalog
        .set_evict_rule_seen(&rig.bridge.rule_fingerprint())
        .await
        .unwrap();
    let sql = &rig.bridge.catalog.sql;
    if !counters {
        // The usage counters as the migration leaves them: off.
        sql.apply("UPDATE usage_global SET all_x = 0, all_o = 0, all_g = 0")
            .expect("counters off");
    }
    if dropped {
        sql.apply(NEXT_DROP_SUPERSEDED_INDEXES)
            .expect("the index drops apply");
        // The meter reads the schema again.
        sql.reset_writes();
    }
    rig.setup_buckets_and_key(s).await;

    let cases = [("multipart x1", 1usize), ("multipart x3", 3)];
    let mut totals = Vec::new();
    for (i, (label, extents)) in cases.iter().enumerate() {
        let body = test_bytes(40 + i as u8, extents * EXTENT);
        let path = format!("/slice/w/{i}.bin");
        let start = sql.writes();
        let used_before = rig.db_used();
        let r = rig.multipart_put(s, &path, &body, EXTENT).await;
        expect_status(s, "CompleteMultipartUpload", 200, &r);
        let uploaded = sql.writes();
        rig.pump_jobs(s, true).await;
        let verified = sql.writes();
        rig.bridge.clock.advance_secs(DAY + 600);
        for _ in 0..20 {
            if rig.sql_count("SELECT COUNT(*) FROM outbox WHERE stage <> 'done'") == 0 {
                break;
            }
            rig.tick(s).await;
            rig.bridge.clock.advance_secs(CRON_SECS);
        }
        expect_eq(
            s,
            "outbox rows not done",
            0,
            rig.sql_count("SELECT COUNT(*) FROM outbox WHERE stage <> 'done'"),
        );
        let released = sql.writes();
        println!("== PACKED_PLANS={packed_plans}, dropped={dropped}, {label}: {extents} extent(s)");
        println!("-- upload\n{}", uploaded.since(&start).render());
        println!("-- post and verify\n{}", verified.since(&uploaded).render());
        println!("-- release\n{}", released.since(&verified).render());
        println!(
            "== {label}: upload {} + post and verify {} + release {}",
            uploaded.since(&start).billed(),
            verified.since(&uploaded).billed(),
            released.since(&verified).billed()
        );
        let used = rig.db_used();
        let mut grew: Vec<(i64, &String)> = used
            .iter()
            .map(|(name, bytes)| (bytes - used_before.get(name).copied().unwrap_or(0), name))
            .filter(|(bytes, _)| *bytes != 0)
            .collect();
        grew.sort_by_key(|(bytes, _)| std::cmp::Reverse(*bytes));
        println!("-- bytes kept");
        for (bytes, name) in &grew {
            println!("{bytes:>8}  {name}");
        }
        let kept: i64 = grew.iter().map(|(bytes, _)| bytes).sum();
        totals.push((*extents as u64, released.since(&start).billed(), kept));
        // The object reads back whole from Usenet in either form.
        let r = rig.get(&path).await;
        expect_status(s, "GetObject after the release", 200, &r);
        expect_eq(
            s,
            "body after the release",
            hex(&sha256(&body)),
            hex(&sha256(&r.body)),
        );
    }
    let (e1, w1, b1) = totals[0];
    let (e3, w3, b3) = totals[1];
    let per_extent = (w3 - w1) / (e3 - e1);
    let per_object = w1 - per_extent * e1;
    let bytes = (b3 - b1) / (e3 - e1) as i64;
    println!(
        "rows written, PACKED_PLANS={packed_plans}, dropped={dropped}: {per_extent} per extent + {per_object} per object"
    );
    // 10^12 bytes of 16 MiB extents.
    let per_tb = 1_000_000_000_000 / EXTENT as i64;
    println!(
        "bytes kept, PACKED_PLANS={packed_plans}: {bytes} per extent, {:.3} GB per TB \
         ({:.2} M rows written per TB)",
        (bytes * per_tb) as f64 / 1e9,
        (per_extent as i64 * per_tb) as f64 / 1e6,
    );
    (per_extent, per_object, bytes)
}

#[tokio::test(flavor = "current_thread")]
async fn rows_written_per_extent() {
    let rows = rows_written("off", true, false).await;
    let packed = rows_written("on", true, false).await;
    let uncounted = rows_written("on", false, false).await;
    println!(
        "rows written per extent: {} as rows, {} packed",
        rows.0, packed.0
    );
    println!(
        "usage counters, packed: {} -> {} rows per extent, {} -> {} per object",
        uncounted.0, packed.0, uncounted.1, packed.1
    );
    // A packed plan costs two writes however many articles it has: the
    // plan and the stamp. As rows, every article is three (the row, its
    // message-id index entry, the posted mark).
    assert!(rows.0 >= packed.0 + 3 * 24 - 2, "{rows:?} {packed:?}");
    // The whole life of an extent and of an object: a change that adds a
    // write to either shows up here. The jobs run in turn, so none is
    // put off for a provider slot; each such put-off is four more (the
    // claim and the put-off, a row and an index entry each).
    // A verify job reads every backbone under one claim, and a job
    // that makes its calls within 20 s of its claim renews nothing.
    //
    // 48, not 46, while `extents_safety` and the two indexes it replaces
    // exist side by side: its entry at the upload and at the start of
    // the release. The drops give both back and three more.
    // 49 with the scrub's pending index (migration 0005): a released extent
    // has an entry there, written once by the release.
    assert!(
        uncounted.0 <= 49,
        "rows written per packed extent: {}",
        uncounted.0
    );
    assert!(
        uncounted.1 <= 21,
        "rows written per object: {}",
        uncounted.1
    );
    // The usage counters, once switched on, add one row per counted
    // change. An extent has six: its row and its outbox row are written,
    // the outbox row moves through three stages, and the safety copy is
    // released. An object measured two more here: the bound is what this
    // run wrote, and a regression guard rather than a derivation.
    assert!(
        packed.0 <= uncounted.0 + 6,
        "rows written per packed extent, counted: {}",
        packed.0
    );
    assert!(
        packed.1 <= uncounted.1 + 2,
        "rows written per object, counted: {}",
        packed.1
    );
    // What a 16 MiB extent keeps in the catalogue for good: 0.15 GB per
    // TB is 2,516 bytes an extent. A third of it is the record of its
    // checks, one row per backbone and check.
    assert!(
        packed.2 <= 2_516,
        "bytes kept per packed extent: {}",
        packed.2
    );
    assert!(rows.2 >= 5 * packed.2, "{rows:?} {packed:?}");
}

/// The same on the schema of the next release, without the indexes
/// `extents_safety` replaced: an extent of a multipart upload is three
/// writes cheaper than before this release (its part, twice, and its
/// adoption).
#[tokio::test(flavor = "current_thread")]
async fn rows_written_per_extent_after_the_index_drops() {
    let packed = rows_written("on", false, true).await;
    // 44 with the scrub's due index entry of a released extent.
    assert!(
        packed.0 <= 44,
        "rows written per packed extent: {}",
        packed.0
    );
    assert!(packed.1 <= 21, "rows written per object: {}", packed.1);
}

/// Rows written by one PutObject of one extent, the common upload.
async fn rows_written_per_put(dropped: bool) -> u64 {
    let rig = Rig::with_backbones(&[("PACKED_PLANS", "on")], 2).await;
    let s = "rows written per PutObject";
    let sql = &rig.bridge.catalog.sql;
    // The figures are without the usage counters, as the migration
    // leaves them (the `uncounted` case of `rows_written`).
    sql.apply("UPDATE usage_global SET all_x = 0, all_o = 0, all_g = 0")
        .expect("counters off");
    rig.setup_buckets_and_key(s).await;
    if dropped {
        sql.apply(NEXT_DROP_SUPERSEDED_INDEXES)
            .expect("the index drops apply");
        sql.reset_writes();
    }
    // The first write of a key and an overwrite cost the same here; the
    // second is measured, so nothing a first request sets up is counted.
    let r = rig.put("/slice/w/put.bin", &test_bytes(7, 4096)).await;
    expect_status(s, "PutObject", 200, &r);
    let before = sql.writes();
    let r = rig.put("/slice/w/put2.bin", &test_bytes(8, 4096)).await;
    expect_status(s, "PutObject", 200, &r);
    let written = sql.writes().since(&before);
    println!("-- PutObject, dropped={dropped}\n{}", written.render());
    written.billed()
}

/// What an upload writes: 16 rows before this release, 17 while the old
/// and the new index of the pinned set exist side by side, 14 once the
/// old ones are dropped.
#[tokio::test(flavor = "current_thread")]
async fn rows_written_per_put_object() {
    assert_eq!(rows_written_per_put(false).await, 17);
    assert_eq!(rows_written_per_put(true).await, 14);
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
