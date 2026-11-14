//! Shared harness for the S3 handler tests: a bridge over the SQL
//! catalogue (in-memory SQLite) and in-memory blob stores, an independent
//! SigV4 signer, and response helpers.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use futures_util::stream::{self, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;
use velmora_bridge::config::{BridgeConfig, Environment, GcMode, Maintenance};
use velmora_bridge::crypto::{wrap_bdk, wrap_secret, DataKey};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::*;

pub const T0: UnixMs = UnixMs(1_800_000_000_000);
pub const HOST: &str = "s3.test";
pub const REGION: &str = "auto";
pub const AKID: &str = "AKIDTESTKEY000000001";
pub const MIB: usize = 1024 * 1024;

/// A secret access key drawn fresh for each test thread, so no test
/// depends on a fixed credential.
pub fn secret() -> &'static str {
    thread_local! {
        static SECRET: &'static str = {
            let mut bytes = [0u8; 20];
            velmora::rng::FillRandom::fill_bytes(&mut SystemRng, &mut bytes).expect("os randomness");
            Box::leak(hex(&bytes).into_boxed_str())
        };
    }
    SECRET.with(|s| *s)
}

pub type TestCatalog = SqlCatalog<FailSql>;
pub type TestBridge<N> = Bridge<TestCatalog, Blobs, N, Jobs, TestKek, FixedClock>;

// ---------------------------------------------------------------------------
// A connector for tests that must never reach Usenet
// ---------------------------------------------------------------------------

pub struct NoNntp;
pub enum NoSession {}

impl NntpSession for NoSession {
    async fn post(&mut self, _: &str, _: &[u8]) -> Result<velmora::nntp::PostOutcome> {
        match *self {}
    }
    async fn stat(&mut self, _: &str) -> Result<bool> {
        match *self {}
    }
    async fn body(&mut self, _: &str, _: &mut Vec<u8>) -> Result<BodyOutcome> {
        match *self {}
    }
    async fn quit(self) {
        match self {}
    }
}

impl NntpConnector for NoNntp {
    type Session = NoSession;
    async fn connect(&self, _: &ProviderConfig, _: &Permit) -> Result<NoSession> {
        panic!("this test must not open an NNTP session");
    }
}

/// A job sink that records sends and can be made to fail.
#[derive(Default)]
pub struct Jobs {
    pub inner: FakeJobs,
    pub fail: Cell<bool>,
}

impl JobSink for Jobs {
    async fn send(&self, job: &Job, delay_secs: u32) -> Result<()> {
        if self.fail.get() {
            return Err(BridgeError::Queue("queue down".into()));
        }
        self.inner.send(job, delay_secs).await
    }
    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        if self.fail.get() {
            return Err(BridgeError::Queue("queue down".into()));
        }
        self.inner.send_many(jobs).await
    }
}

/// A blob store whose writes can be made to fail.
#[derive(Default)]
pub struct Blobs {
    pub inner: MemBlobStore,
    pub fail_put: Cell<bool>,
    /// Puts of keys with this prefix fail.
    pub fail_put_prefix: RefCell<Option<String>>,
}

impl std::ops::Deref for Blobs {
    type Target = MemBlobStore;
    fn deref(&self) -> &MemBlobStore {
        &self.inner
    }
}

impl BlobStore for Blobs {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        let refused = self
            .fail_put_prefix
            .borrow()
            .as_deref()
            .is_some_and(|p| key.starts_with(p));
        if self.fail_put.get() || refused {
            return Err(BridgeError::Blob("store down".into()));
        }
        self.inner.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.inner.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.inner.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
}

/// A database whose writes can be made to fail; reads keep working.
pub struct FailSql {
    pub inner: RusqliteSql,
    pub fail_writes: Cell<bool>,
}

impl std::ops::Deref for FailSql {
    type Target = RusqliteSql;
    fn deref(&self) -> &RusqliteSql {
        &self.inner
    }
}

impl Sql for FailSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.inner.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        if self.fail_writes.get() {
            return Err(BridgeError::Sql("database down".into()));
        }
        self.inner.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if self.fail_writes.get() {
            return Err(BridgeError::Sql("database down".into()));
        }
        self.inner.batch(stmts).await
    }
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

pub fn config(providers: Vec<ProviderConfig>) -> BridgeConfig {
    BridgeConfig {
        environment: Environment::Dev,
        s3_host: HOST.to_string(),
        region: REGION.to_string(),
        max_extent_bytes: 16 * 1024 * 1024,
        required_backbones: 1,
        safety_min_age_secs: 0,
        verify_delay_secs: 30,
        newsgroups: vec!["alt.binaries.test".to_string()],
        kek_active: 1,
        inflight_budget_bytes: 48 * 1024 * 1024,
        gc_mode: GcMode::Disposable,
        maintenance: Maintenance::Off,
        server_side_copy: true,
        dev_trust_http: false,
        providers,
        admin_token: Secret::new("admin-token-fixture-admin-token-fixture".to_string()),
    }
}

pub struct Rig<N: NntpConnector + 'static = NoNntp> {
    pub bridge: Rc<TestBridge<N>>,
}

pub fn rig() -> Rig {
    rig_with(NoNntp, config(Vec::new()))
}

pub fn rig_with<N: NntpConnector + 'static>(nntp: N, cfg: BridgeConfig) -> Rig<N> {
    let budget = ByteBudget::new(cfg.inflight_budget_bytes);
    rig_with_budget(nntp, cfg, budget)
}

/// A rig whose byte budget is `budget` (for example one with a sleeper).
pub fn rig_with_budget<N: NntpConnector + 'static>(
    nntp: N,
    cfg: BridgeConfig,
    budget: ByteBudget,
) -> Rig<N> {
    Rig {
        bridge: Rc::new(Bridge {
            catalog: SqlCatalog::new(FailSql {
                inner: RusqliteSql::with_schema().unwrap(),
                fail_writes: Cell::new(false),
            }),
            safety: Blobs::default(),
            cache: Blobs::default(),
            nntp,
            jobs: Jobs::default(),
            kek: TestKek::new(),
            clock: FixedClock::new(T0),
            budget,
            cfg,
        }),
    }
}

impl<N: NntpConnector + 'static> Rig<N> {
    /// Creates a bucket with a fresh data key.
    pub async fn bucket(&self, name: &str, disposable: bool) -> Bucket {
        let mut rng = SystemRng;
        let seed = sha256(name.as_bytes());
        let id = BucketId::mint(seed[..8].try_into().unwrap());
        let bdk = DataKey::generate(&mut rng).unwrap();
        let (kek_version, wrapped) = wrap_bdk(&self.bridge.kek, &id, &bdk, &mut rng).unwrap();
        let bucket = Bucket {
            id,
            name: name.to_string(),
            owner: "owner".to_string(),
            bdk_wrapped: wrapped.to_vec(),
            kek_version,
            disposable,
            created_at: T0,
        };
        assert_eq!(
            self.bridge.catalog.create_bucket(&bucket).await.unwrap(),
            Guard::Applied(())
        );
        bucket
    }

    /// Stores an access key and returns its signer.
    pub async fn key(&self, akid: &str, secret: &str, status: KeyStatus) -> Signer {
        let (kek_version, secret_wrapped) =
            wrap_secret(&self.bridge.kek, akid, secret.as_bytes(), &mut SystemRng).unwrap();
        self.bridge
            .catalog
            .create_access_key(&AccessKeyRow {
                access_key_id: akid.to_string(),
                principal: format!("principal-{akid}"),
                secret_wrapped,
                kek_version,
                status,
                created_at: T0,
            })
            .await
            .unwrap();
        Signer::new(akid, secret)
    }

    pub async fn grant(&self, akid: &str, bucket: &Bucket, perm: Perm) {
        self.bridge
            .catalog
            .put_grant(akid, &bucket.id, perm)
            .await
            .unwrap();
    }

    /// One disposable bucket and one read-write key on it.
    pub async fn standard(&self, bucket: &str) -> (Bucket, Signer) {
        let b = self.bucket(bucket, true).await;
        let signer = self.key(AKID, secret(), KeyStatus::Active).await;
        self.grant(AKID, &b, Perm::Rw).await;
        (b, signer)
    }

    pub fn now(&self) -> UnixMs {
        self.bridge.clock.now()
    }

    pub async fn send(&self, req: Req) -> Resp {
        let resp = Rc::clone(&self.bridge).handle(req.into_request()).await;
        Resp::collect(resp).await
    }

    /// Signs with `signer` at the rig's clock and sends.
    pub async fn call(
        &self,
        signer: &Signer,
        method: Method,
        raw_path: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Resp {
        self.send(signer.sign(self.now(), method, raw_path, query, headers, body.to_vec()))
            .await
    }

    pub async fn put(&self, signer: &Signer, bucket: &str, key: &str, body: &[u8]) -> Resp {
        self.call(signer, Method::Put, &path(bucket, key), &[], &[], body)
            .await
    }

    pub async fn head(&self, signer: &Signer, bucket: &str, key: &str) -> Resp {
        self.call(signer, Method::Head, &path(bucket, key), &[], &[], b"")
            .await
    }

    /// Sends `req` with a body that records whether it was ever polled.
    pub async fn send_watched(&self, req: Req) -> (Resp, bool) {
        let polled = Rc::new(Cell::new(false));
        let flag = Rc::clone(&polled);
        let declared_len = req
            .headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .and_then(|(_, v)| v.parse().ok());
        let body = req.body;
        let request = S3Request {
            method: req.method,
            raw_target: req.target,
            headers: req.headers,
            body: Body::Stream {
                declared_len,
                stream: stream::once(async move {
                    flag.set(true);
                    Ok(body)
                })
                .boxed_local(),
            },
        };
        let resp = Rc::clone(&self.bridge).handle(request).await;
        (Resp::collect(resp).await, polled.get())
    }

    /// The live generation and extents of a key, straight from the
    /// catalogue.
    pub async fn live(
        &self,
        bucket: &Bucket,
        key: &str,
    ) -> Option<(GenerationRow, Vec<ExtentRow>)> {
        self.bridge
            .catalog
            .live_object(&bucket.id, key)
            .await
            .unwrap()
    }

    /// Rows in a catalogue table.
    pub fn count(&self, table: &str) -> i64 {
        self.bridge.catalog.sql.with_conn(|c| {
            c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        })
    }
}

// ---------------------------------------------------------------------------
// SigV4 header signing (independent of the server's verifier)
// ---------------------------------------------------------------------------

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Deterministic bytes that do not repeat on a chunk boundary.
pub fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[seed as usize % 4] ^ seed)
        .collect()
}

/// Percent-encodes everything outside the RFC 3986 unreserved set
/// (uppercase hex); `/` is kept in paths.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `/bucket/key` with the key percent-encoded as SDKs send it.
pub fn path(bucket: &str, key: &str) -> String {
    format!("/{bucket}/{}", uri_encode(key, true))
}

/// Days since 1970-01-01 to (year, month, day).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[derive(Clone)]
pub struct Signer {
    pub akid: String,
    pub secret: String,
    pub region: String,
}

/// One request before it is handed to the bridge.
pub struct Req {
    pub method: Method,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(n, _)| n != name);
        self.headers.push((name.to_string(), value.to_string()));
    }

    pub fn into_request(self) -> S3Request {
        let declared_len = self
            .headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .and_then(|(_, v)| v.parse().ok());
        let body = if self.body.is_empty() && declared_len.is_none() {
            Body::Empty
        } else {
            Body::Stream {
                declared_len,
                stream: stream::iter(
                    self.body
                        .chunks(64 * 1024)
                        .map(|c| Ok(c.to_vec()))
                        .collect::<Vec<_>>(),
                )
                .boxed_local(),
            }
        };
        S3Request {
            method: self.method,
            raw_target: self.target,
            headers: self.headers,
            body,
        }
    }
}

impl Signer {
    pub fn new(akid: &str, secret: &str) -> Self {
        Signer {
            akid: akid.to_string(),
            secret: secret.to_string(),
            region: REGION.to_string(),
        }
    }

    /// Header-signs `method raw_path?query`. `raw_path` is sent and signed
    /// exactly as given; query pairs are given decoded. Every header in
    /// `extra` is signed. PUT always declares its length.
    pub fn sign(
        &self,
        now: UnixMs,
        method: Method,
        raw_path: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Req {
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
        let target = if q.is_empty() {
            raw_path.to_string()
        } else {
            format!("{raw_path}?{canonical_query}")
        };

        let secs = now.0.div_euclid(1000);
        let (y, mo, d) = civil(secs.div_euclid(86_400));
        let t = secs.rem_euclid(86_400);
        let date = format!("{y:04}{mo:02}{d:02}");
        let stamp = format!("{date}T{:02}{:02}{:02}Z", t / 3600, t % 3600 / 60, t % 60);

        let payload = hex(&sha256(&body));
        let mut signed: BTreeMap<String, String> = BTreeMap::new();
        signed.insert("host".into(), HOST.into());
        signed.insert("x-amz-content-sha256".into(), payload.clone());
        signed.insert("x-amz-date".into(), stamp.clone());
        for (k, v) in extra {
            signed.insert(k.to_ascii_lowercase(), v.trim().to_string());
        }
        let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let names = signed.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical = format!(
            "{}\n{raw_path}\n{canonical_query}\n{canonical_headers}\n{names}\n{payload}",
            method.as_str()
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex(&sha256(canonical.as_bytes()))
        );
        let mut key = hmac(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes());
        for part in [self.region.as_str(), "s3", "aws4_request"] {
            key = hmac(&key, part.as_bytes());
        }
        let signature = hex(&hmac(&key, to_sign.as_bytes()));

        let mut headers: Vec<(String, String)> = signed.into_iter().collect();
        headers.push((
            "authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
                self.akid
            ),
        ));
        if method == Method::Put || !body.is_empty() {
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

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Set when a streamed body ended with an error.
    pub stream_error: Option<String>,
}

impl Resp {
    pub async fn collect(resp: S3Response) -> Resp {
        let mut body = Vec::new();
        let mut stream_error = None;
        match resp.body {
            RespBody::Empty => {}
            RespBody::Bytes(b) => body = b,
            RespBody::Stream(mut s) => {
                while let Some(item) = s.next().await {
                    match item {
                        Ok(chunk) => body.extend_from_slice(&chunk),
                        Err(e) => {
                            stream_error = Some(e.to_string());
                            break;
                        }
                    }
                }
            }
        }
        Resp {
            status: resp.status,
            headers: resp.headers,
            body,
            stream_error,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The `<Code>` of an S3 error body.
    pub fn code(&self) -> String {
        self.values("Code").into_iter().next().unwrap_or_default()
    }

    /// The text of every `<tag>…</tag>` in the body, in order.
    pub fn values(&self, tag: &str) -> Vec<String> {
        let text = self.text();
        let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
        let mut out = Vec::new();
        let mut rest = text.as_str();
        while let Some(i) = rest.find(&open) {
            rest = &rest[i + open.len()..];
            let Some(j) = rest.find(&close) else { break };
            out.push(rest[..j].to_string());
            rest = &rest[j + close.len()..];
        }
        out
    }

    #[track_caller]
    pub fn expect(&self, status: u16) -> &Self {
        assert_eq!(self.status, status, "body: {}", self.text());
        self
    }

    #[track_caller]
    pub fn expect_error(&self, status: u16, code: &str) -> &Self {
        assert_eq!(
            (self.status, self.code().as_str()),
            (status, code),
            "body: {}",
            self.text()
        );
        self
    }
}
