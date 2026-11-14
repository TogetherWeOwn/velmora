//! Multipart uploads through `Bridge::handle`: SigV4-signed requests over
//! the SQLite catalogue with the D1 schema and in-memory blob stores.
//!
//! The catalogue is single-writer per statement batch, so a race is two
//! batches in either order. [`Probe`] can yield to the other request right
//! before every batch; joining two requests then runs both up to their
//! write and lets them commit in join order, each way round.
//!
//! Objects are checked through the catalogue and the safety store: the
//! committed extents are decrypted and compared with the uploaded bytes.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

use base64::Engine as _;
use futures_util::future::join;
use futures_util::stream::{self, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use velmora::nntp::PostOutcome;
use velmora::rng::SystemRng;
use velmora_bridge::config::BridgeConfig;
use velmora_bridge::crypto::{open_range, unwrap_bdk, wrap_bdk, wrap_secret, DataKey};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::*;

// None of these values is a secret: they exist only inside this test.
/// 2026-11-13T00:00:00Z.
const T0: UnixMs = UnixMs(1_794_528_000_000);
const S3_HOST: &str = "127.0.0.1:8798";
const REGION: &str = "auto";
const RW_KEY: &str = "AKIDMULTIPARTRW00001";
/// `rw` on bucket `alpha` only.
const ALPHA_KEY: &str = "AKIDMULTIPARTALPHA01";
/// `ro` on bucket `alpha`.
const RO_KEY: &str = "AKIDMULTIPARTRO00001";
const SIGNING_SECRET: &str = "multipart-test-signing-secret-0123456789";
const MIB: usize = 1024 * 1024;
const KEY: &str = "dir/big file+@.bin";

// ---------------------------------------------------------------------------
// Catalogue probe and unused NNTP
// ---------------------------------------------------------------------------

struct Probe {
    db: RusqliteSql,
    /// When set, every batch first yields to the other request.
    yield_before_batch: Cell<bool>,
}

impl Sql for Probe {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.db.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.db.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if self.yield_before_batch.get() {
            tokio::task::yield_now().await;
        }
        self.db.batch(stmts).await
    }
}

/// Multipart handlers never open an NNTP session.
struct NoNntp;
struct NoSession;

impl NntpSession for NoSession {
    async fn post(&mut self, _: &str, _: &[u8]) -> Result<PostOutcome> {
        Err(BridgeError::Invalid("no NNTP in this test"))
    }
    async fn stat(&mut self, _: &str) -> Result<bool> {
        Err(BridgeError::Invalid("no NNTP in this test"))
    }
    async fn body(&mut self, _: &str, _: &mut Vec<u8>) -> Result<BodyOutcome> {
        Err(BridgeError::Invalid("no NNTP in this test"))
    }
    async fn quit(self) {}
}

impl NntpConnector for NoNntp {
    type Session = NoSession;
    async fn connect(&self, _: &ProviderConfig, _: &Permit) -> Result<NoSession> {
        Err(BridgeError::Invalid("no NNTP in this test"))
    }
}

type TestBridge = Bridge<SqlCatalog<Probe>, MemBlobStore, NoNntp, FakeJobs, TestKek, FixedClock>;

// ---------------------------------------------------------------------------
// Bytes, hashes, SigV4
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Deterministic incompressible test bytes.
fn test_bytes(seed: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut block = sha256(&[seed]);
    while out.len() < len {
        out.extend_from_slice(&block);
        block = sha256(&block);
    }
    out.truncate(len);
    out
}

/// `"<md5 of the concatenated part MD5s>-<parts>"`.
fn multipart_etag(parts: &[&[u8]]) -> String {
    let md5s: Vec<u8> = parts.iter().flat_map(|p| md5::compute(p).0).collect();
    format!("\"{}-{}\"", hex(&md5::compute(&md5s).0), parts.len())
}

/// RFC 3986 unreserved bytes stay; everything else is `%XX` (uppercase).
fn uri_encode(s: &str, keep_slash: bool) -> String {
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
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

struct Req {
    method: Method,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Signs `method path?query` with header auth, independent of the server's
/// verifier. `path` and `query` are decoded; extra headers are signed.
fn sign(
    akid: &str,
    method: Method,
    path: &str,
    query: &[(&str, &str)],
    extra: &[(&str, &str)],
    body: Vec<u8>,
) -> Req {
    sign_as(akid, method, path, query, extra, body, None).0
}

/// [`sign`] with an explicit `x-amz-content-sha256` (a `STREAMING-*`
/// value): no `Content-Length` is added. Returns the request and its
/// signature, the seed of a chunk-signature chain.
fn sign_as(
    akid: &str,
    method: Method,
    path: &str,
    query: &[(&str, &str)],
    extra: &[(&str, &str)],
    body: Vec<u8>,
    streaming: Option<&str>,
) -> (Req, String) {
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
    // Clients send a bare `?uploads`; the canonical form has `uploads=`.
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

    let secs = T0.0.div_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    let date = format!("{y:04}{mo:02}{d:02}");
    let stamp = format!("{date}T{:02}{:02}{:02}Z", t / 3600, t % 3600 / 60, t % 60);

    let payload = streaming.map_or_else(|| hex(&sha256(&body)), str::to_owned);
    let mut signed: BTreeMap<String, String> = BTreeMap::new();
    signed.insert("host".into(), S3_HOST.into());
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
    let scope = format!("{date}/{REGION}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&sha256(canonical_request.as_bytes()))
    );
    let k_date = hmac(format!("AWS4{SIGNING_SECRET}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, REGION.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex(&hmac(&k_signing, to_sign.as_bytes()));

    let mut headers: Vec<(String, String)> = signed.into_iter().collect();
    headers.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={signed_names}, \
             Signature={signature}"
        ),
    ));
    if !body.is_empty() && streaming.is_none() {
        headers.push(("content-length".into(), body.len().to_string()));
    }
    (
        Req {
            method,
            target,
            headers,
            body,
        },
        signature,
    )
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `"<status> <S3 error code>"`, e.g. `404 NoSuchUpload`.
    fn outcome(&self) -> String {
        match xml_value(&self.body, "Code") {
            Some(code) => format!("{} {code}", self.status),
            None => self.status.to_string(),
        }
    }
}

fn xml_value(xml: &str, tag: &str) -> Option<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(
        xml[start..end]
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
    )
}

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

struct Rig {
    bridge: Rc<TestBridge>,
    alpha: Bucket,
    beta: Bucket,
}

fn config(maintenance: &str) -> BridgeConfig {
    let providers = serde_json::json!([{
        "id": "unused", "host": "127.0.0.1", "port": 1, "tls": false,
        "user": "nobody", "pass": "unused", "backbone": "none",
        "post": true, "read": true, "max_conns": 1,
    }])
    .to_string();
    let vars: BTreeMap<&str, String> = [
        ("ENVIRONMENT", "dev".to_string()),
        ("S3_HOST", S3_HOST.to_string()),
        ("S3_REGION", REGION.to_string()),
        ("MAX_EXTENT_BYTES", "16777216".to_string()),
        ("REQUIRED_BACKBONES", "1".to_string()),
        ("SAFETY_MIN_AGE_SECS", "0".to_string()),
        ("VERIFY_DELAY_SECS", "1".to_string()),
        ("DEV_TRUST_HTTP", "1".to_string()),
        ("NEWSGROUPS", "alt.binaries.test".to_string()),
        ("VELMORA_KEK_ACTIVE", "1".to_string()),
        ("INFLIGHT_BUDGET_BYTES", "50331648".to_string()),
        ("GC_MODE", "disposable".to_string()),
        ("MAINTENANCE", maintenance.to_string()),
        ("SERVER_SIDE_COPY", "on".to_string()),
        (
            "ADMIN_TOKEN",
            "multipart-test-admin-token-0123456789abcdef".to_string(),
        ),
        ("NNTP_PROVIDERS", providers),
        (
            "VELMORA_KEK_1",
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
        ),
    ]
    .into_iter()
    .collect();
    BridgeConfig::from_vars(|k| vars.get(k).cloned()).expect("test configuration is valid")
}

impl Rig {
    async fn new() -> Rig {
        Rig::with_maintenance("off").await
    }

    async fn with_maintenance(maintenance: &str) -> Rig {
        let cfg = config(maintenance);
        let kek = TestKek::new();
        let catalog = SqlCatalog::new(Probe {
            db: RusqliteSql::with_schema().expect("schema applies"),
            yield_before_batch: Cell::new(false),
        });
        let mut buckets = Vec::new();
        for (name, seed) in [("alpha", 0xa1u8), ("beta", 0xb2)] {
            let id = BucketId::mint([seed; 8]);
            let bdk = DataKey::generate(&mut SystemRng).unwrap();
            let (kek_version, wrapped) = wrap_bdk(&kek, &id, &bdk, &mut SystemRng).unwrap();
            let bucket = Bucket {
                id,
                name: name.to_string(),
                owner: "owner".to_string(),
                bdk_wrapped: wrapped.to_vec(),
                kek_version,
                disposable: true,
                created_at: T0,
            };
            assert_eq!(
                catalog.create_bucket(&bucket).await.unwrap(),
                Guard::Applied(())
            );
            buckets.push(bucket);
        }
        let beta = buckets.pop().unwrap();
        let alpha = buckets.pop().unwrap();
        for (akid, grants) in [
            (RW_KEY, vec![(&alpha, Perm::Rw), (&beta, Perm::Rw)]),
            (ALPHA_KEY, vec![(&alpha, Perm::Rw)]),
            (RO_KEY, vec![(&alpha, Perm::Ro)]),
        ] {
            let (kek_version, secret_wrapped) =
                wrap_secret(&kek, akid, SIGNING_SECRET.as_bytes(), &mut SystemRng).unwrap();
            catalog
                .create_access_key(&AccessKeyRow {
                    access_key_id: akid.to_string(),
                    principal: format!("principal-{akid}"),
                    secret_wrapped,
                    kek_version,
                    status: KeyStatus::Active,
                    created_at: T0,
                })
                .await
                .unwrap();
            for (bucket, perm) in grants {
                catalog.put_grant(akid, &bucket.id, perm).await.unwrap();
            }
        }
        let bridge = Rc::new(Bridge {
            catalog,
            safety: MemBlobStore::new(),
            cache: MemBlobStore::new(),
            nntp: NoNntp,
            jobs: FakeJobs::new(),
            kek,
            clock: FixedClock::new(T0),
            budget: ByteBudget::new(cfg.inflight_budget_bytes),
            cfg,
        });
        Rig {
            bridge,
            alpha,
            beta,
        }
    }

    async fn send(&self, r: Req) -> Resp {
        // Arrives in 1 MiB chunks, like a streamed request body.
        self.send_in(r, MIB).await
    }

    async fn send_in(&self, r: Req, piece: usize) -> Resp {
        let body = if r.body.is_empty() {
            Body::Empty
        } else {
            let len = r.body.len() as u64;
            let chunks: Vec<Result<Vec<u8>>> =
                r.body.chunks(piece).map(|c| Ok(c.to_vec())).collect();
            Body::Stream {
                declared_len: Some(len),
                stream: stream::iter(chunks).boxed_local(),
            }
        };
        let resp = Rc::clone(&self.bridge)
            .handle(S3Request {
                method: r.method,
                raw_target: r.target,
                headers: r.headers,
                body,
            })
            .await;
        let body = match resp.body {
            RespBody::Empty => Vec::new(),
            RespBody::Bytes(b) => b,
            RespBody::Stream(_) => panic!("multipart responses are never streamed"),
        };
        Resp {
            status: resp.status,
            headers: resp.headers,
            body: String::from_utf8(body).expect("response body is UTF-8"),
        }
    }

    async fn create(&self, bucket: &str, key: &str) -> String {
        let r = self.send(create_req(RW_KEY, bucket, key, &[])).await;
        assert_eq!(r.outcome(), "200", "CreateMultipartUpload: {}", r.body);
        assert_eq!(xml_value(&r.body, "Bucket").as_deref(), Some(bucket));
        assert_eq!(xml_value(&r.body, "Key").as_deref(), Some(key));
        let id = xml_value(&r.body, "UploadId").expect("an UploadId");
        assert_eq!(id.len(), 32);
        id
    }

    /// Uploads one part and returns its ETag (quoted).
    async fn part(&self, bucket: &str, key: &str, id: &str, n: u16, bytes: &[u8]) -> String {
        let r = self.send(part_req(RW_KEY, bucket, key, id, n, bytes)).await;
        assert_eq!(r.outcome(), "200", "UploadPart {n}: {}", r.body);
        let etag = r.header("etag").expect("an ETag header").to_string();
        assert_eq!(etag, format!("\"{}\"", hex(&md5::compute(bytes).0)));
        etag
    }

    async fn complete(&self, bucket: &str, key: &str, id: &str, parts: &[(u16, &str)]) -> Resp {
        self.send(complete_req(RW_KEY, bucket, key, id, parts, &[]))
            .await
    }

    async fn abort(&self, bucket: &str, key: &str, id: &str) -> Resp {
        self.send(abort_req(RW_KEY, bucket, key, id)).await
    }

    // -- catalogue and store views --------------------------------------------

    async fn count(&self, sql: &str) -> i64 {
        let rows = self.bridge.catalog.sql.query(sql, &[]).await.unwrap();
        match rows[0][0] {
            SqlValue::Int(n) => n,
            ref other => panic!("{sql}: not a count: {other:?}"),
        }
    }

    async fn upload_state(&self, bucket: &Bucket, key: &str, id: &str) -> Option<UploadState> {
        let id = UploadId::new(id);
        let target = UploadTarget {
            bucket: &bucket.id,
            key,
            id: &id,
        };
        let found = self.bridge.catalog.upload(&target).await.unwrap();
        found.map(|(upload, _)| upload.state)
    }

    /// The live object of `key`: its generation and decrypted bytes, read
    /// from the catalogue and the safety store.
    async fn object(&self, bucket: &Bucket, key: &str) -> Option<(GenerationRow, Vec<u8>)> {
        let (generation, extents) = self
            .bridge
            .catalog
            .live_object(&bucket.id, key)
            .await
            .unwrap()?;
        assert_eq!(extents.len(), generation.extent_count as usize);
        let bdk = unwrap_bdk(
            &self.bridge.kek,
            bucket.kek_version,
            &bucket.id,
            &bucket.bdk_wrapped,
        )
        .unwrap();
        let mut plain = Vec::new();
        for (i, extent) in extents.iter().enumerate() {
            assert_eq!(extent.state, ExtentState::Committed);
            assert_eq!(extent.generation_id.as_ref(), Some(&generation.id));
            assert_eq!(extent.seq, Some(i as u32));
            assert_eq!(extent.plain_offset, Some(plain.len() as u64));
            assert_eq!(extent.safety_state, SafetyState::Held);
            let blob = self
                .bridge
                .safety
                .stored(&extent.id.safety_key())
                .expect("a committed extent is in the safety store");
            assert_eq!(blob.bucket, bucket.id);
            assert_eq!(blob.cipher_sha256, extent.cipher_sha256);
            assert_eq!(sha256(&blob.bytes), extent.cipher_sha256);
            let mut part = vec![0u8; extent.plain_size as usize];
            let n = open_range(&bdk, &bucket.id, extent, 0, &blob.bytes, 0, &mut part).unwrap();
            assert_eq!(n, part.len());
            plain.extend_from_slice(&part);
        }
        assert_eq!(plain.len() as u64, generation.size);
        Some((generation, plain))
    }

    /// Runs two requests with every catalogue batch yielding first, so
    /// both reach their write before either commits; `first` commits first.
    async fn race(&self, first: Req, second: Req) -> (Resp, Resp) {
        self.bridge.catalog.sql.yield_before_batch.set(true);
        let out = join(self.send(first), self.send(second)).await;
        self.bridge.catalog.sql.yield_before_batch.set(false);
        out
    }
}

fn object_path(bucket: &str, key: &str) -> String {
    format!("/{bucket}/{key}")
}

fn create_req(akid: &str, bucket: &str, key: &str, extra: &[(&str, &str)]) -> Req {
    sign(
        akid,
        Method::Post,
        &object_path(bucket, key),
        &[("uploads", "")],
        extra,
        Vec::new(),
    )
}

fn part_req(akid: &str, bucket: &str, key: &str, id: &str, n: u16, bytes: &[u8]) -> Req {
    sign(
        akid,
        Method::Put,
        &object_path(bucket, key),
        &[("partNumber", &n.to_string()), ("uploadId", id)],
        &[],
        bytes.to_vec(),
    )
}

fn complete_xml(parts: &[(u16, &str)]) -> Vec<u8> {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (n, etag) in parts {
        let etag = etag.replace('"', "&quot;");
        xml.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml.into_bytes()
}

fn complete_req(
    akid: &str,
    bucket: &str,
    key: &str,
    id: &str,
    parts: &[(u16, &str)],
    extra: &[(&str, &str)],
) -> Req {
    sign(
        akid,
        Method::Post,
        &object_path(bucket, key),
        &[("uploadId", id)],
        extra,
        complete_xml(parts),
    )
}

fn abort_req(akid: &str, bucket: &str, key: &str, id: &str) -> Req {
    sign(
        akid,
        Method::Delete,
        &object_path(bucket, key),
        &[("uploadId", id)],
        &[],
        Vec::new(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forty_mib_in_five_parts_round_trips() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let parts: Vec<Vec<u8>> = (1..=5u8).map(|n| test_bytes(n, 8 * MIB)).collect();
    let mut etags = Vec::new();
    for (i, bytes) in parts.iter().enumerate() {
        etags.push(rig.part("alpha", KEY, &id, i as u16 + 1, bytes).await);
    }
    // Parts are sealed into the safety store; nothing is published or
    // queued for posting before Complete.
    assert_eq!(rig.bridge.safety.keys().len(), 5);
    assert!(rig.bridge.cache.keys().is_empty());
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM extents WHERE state <> 'staged'")
            .await,
        0
    );
    assert!(rig.bridge.jobs.sent().is_empty());
    assert!(rig.object(&rig.alpha, KEY).await.is_none());

    let listed: Vec<(u16, &str)> = etags
        .iter()
        .enumerate()
        .map(|(i, e)| (i as u16 + 1, e.as_str()))
        .collect();
    let r = rig.complete("alpha", KEY, &id, &listed).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let want_etag = multipart_etag(&slices);
    assert!(want_etag.ends_with("-5\""));
    assert_eq!(
        xml_value(&r.body, "ETag").as_deref(),
        Some(want_etag.as_str())
    );
    assert_eq!(xml_value(&r.body, "Bucket").as_deref(), Some("alpha"));
    assert_eq!(xml_value(&r.body, "Key").as_deref(), Some(KEY));

    let (generation, plain) = rig.object(&rig.alpha, KEY).await.expect("a live object");
    assert_eq!(generation.etag, want_etag);
    assert_eq!(generation.size, 40 * MIB as u64);
    assert_eq!(generation.extent_count, 5);
    assert!(plain == parts.concat(), "object bytes differ");

    // One outbox row and one notification per extent.
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM outbox WHERE stage = 'post'")
            .await,
        5
    );
    assert_eq!(
        rig.count("SELECT COUNT(DISTINCT extent_id) FROM outbox")
            .await,
        5
    );
    assert_eq!(rig.bridge.jobs.sent().len(), 5);
    assert_eq!(rig.count("SELECT COUNT(*) FROM gc").await, 0);
    assert_eq!(
        rig.upload_state(&rig.alpha, KEY, &id).await,
        Some(UploadState::Completed)
    );
    // The same key in the other bucket is untouched.
    assert!(rig.object(&rig.beta, KEY).await.is_none());
}

#[tokio::test]
async fn create_stores_metadata_for_the_object() {
    let rig = Rig::new().await;
    let r = rig
        .send(create_req(
            RW_KEY,
            "alpha",
            KEY,
            &[
                ("content-type", "text/plain"),
                ("x-amz-meta-colour", "blue"),
            ],
        ))
        .await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let id = xml_value(&r.body, "UploadId").unwrap();
    let etag = rig.part("alpha", KEY, &id, 1, b"hello").await;
    let r = rig.complete("alpha", KEY, &id, &[(1, &etag)]).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let (generation, plain) = rig.object(&rig.alpha, KEY).await.unwrap();
    assert_eq!(plain, b"hello");
    let content: BTreeMap<String, String> = serde_json::from_str(&generation.content_json).unwrap();
    let user: BTreeMap<String, String> = serde_json::from_str(&generation.user_meta_json).unwrap();
    assert_eq!(
        content.get("content-type").map(String::as_str),
        Some("text/plain")
    );
    assert_eq!(
        user.get("x-amz-meta-colour").map(String::as_str),
        Some("blue")
    );
}

#[tokio::test]
async fn part_replace_before_complete_and_unlisted_parts_are_collected() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let old = test_bytes(1, 5 * MIB);
    let new = test_bytes(2, 5 * MIB + 7);
    let tail = test_bytes(3, 1000);
    let unlisted = test_bytes(4, 2000);
    let old_etag = rig.part("alpha", KEY, &id, 1, &old).await;
    let new_etag = rig.part("alpha", KEY, &id, 1, &new).await;
    let tail_etag = rig.part("alpha", KEY, &id, 2, &tail).await;
    rig.part("alpha", KEY, &id, 7, &unlisted).await;
    assert_ne!(old_etag, new_etag);
    // The replaced extent is queued for collection at once.
    assert_eq!(
        rig.count("SELECT COUNT(DISTINCT extent_id) FROM gc").await,
        1
    );

    // The ETag of the replaced part no longer names a part.
    let r = rig
        .complete("alpha", KEY, &id, &[(1, &old_etag), (2, &tail_etag)])
        .await;
    assert_eq!(r.outcome(), "400 InvalidPart");
    assert!(rig.object(&rig.alpha, KEY).await.is_none());
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 0);

    // ETags are accepted with or without quotes.
    let r = rig
        .complete(
            "alpha",
            KEY,
            &id,
            &[(1, new_etag.trim_matches('"')), (2, &tail_etag)],
        )
        .await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let (generation, plain) = rig.object(&rig.alpha, KEY).await.unwrap();
    assert_eq!(generation.etag, multipart_etag(&[&new, &tail]));
    assert!(plain == [new.as_slice(), tail.as_slice()].concat());
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 2);
    // The replaced part and the unlisted part 7 are collected; the two
    // published extents are not.
    assert_eq!(
        rig.count("SELECT COUNT(DISTINCT extent_id) FROM gc").await,
        2
    );
    assert_eq!(
        rig.count(
            "SELECT COUNT(*) FROM gc WHERE extent_id IN \
             (SELECT id FROM extents WHERE state = 'committed')"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn complete_vs_abort_race() {
    for complete_first in [true, false] {
        let rig = Rig::new().await;
        let id = rig.create("alpha", KEY).await;
        let bytes = test_bytes(9, 4096);
        let etag = rig.part("alpha", KEY, &id, 1, &bytes).await;
        let complete = complete_req(RW_KEY, "alpha", KEY, &id, &[(1, &etag)], &[]);
        let abort = abort_req(RW_KEY, "alpha", KEY, &id);
        let (completed, aborted) = if complete_first {
            rig.race(complete, abort).await
        } else {
            let (a, c) = rig.race(abort, complete).await;
            (c, a)
        };
        let object = rig.object(&rig.alpha, KEY).await;
        let state = rig.upload_state(&rig.alpha, KEY, &id).await;
        if complete_first {
            assert_eq!(completed.outcome(), "200", "{}", completed.body);
            assert_eq!(aborted.outcome(), "404 NoSuchUpload");
            assert_eq!(state, Some(UploadState::Completed));
            assert!(object.expect("the object is published").1 == bytes);
            assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 1);
            assert_eq!(rig.count("SELECT COUNT(*) FROM gc").await, 0);
        } else {
            assert_eq!(aborted.outcome(), "204");
            assert_eq!(completed.outcome(), "404 NoSuchUpload");
            assert_eq!(state, Some(UploadState::Aborted));
            assert!(object.is_none(), "an aborted upload published an object");
            assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 0);
            assert_eq!(
                rig.count("SELECT COUNT(DISTINCT extent_id) FROM gc").await,
                1
            );
            assert!(rig.bridge.jobs.sent().is_empty());
        }
    }
}

#[tokio::test]
async fn complete_vs_upload_part_race() {
    // UploadPart commits first: Complete validated the old part 1, loses
    // its guard, re-reads and refuses the stale ETag. Nothing is published.
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let old = test_bytes(1, 4096);
    let new = test_bytes(2, 8192);
    let old_etag = rig.part("alpha", KEY, &id, 1, &old).await;
    let (part, complete) = rig
        .race(
            part_req(RW_KEY, "alpha", KEY, &id, 1, &new),
            complete_req(RW_KEY, "alpha", KEY, &id, &[(1, &old_etag)], &[]),
        )
        .await;
    assert_eq!(part.outcome(), "200", "{}", part.body);
    assert_eq!(complete.outcome(), "400 InvalidPart");
    assert!(rig.object(&rig.alpha, KEY).await.is_none());
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(
        rig.upload_state(&rig.alpha, KEY, &id).await,
        Some(UploadState::Open)
    );
    let new_etag = part.header("etag").unwrap().to_string();
    let r = rig.complete("alpha", KEY, &id, &[(1, &new_etag)]).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    assert!(rig.object(&rig.alpha, KEY).await.unwrap().1 == new);

    // Complete commits first: the part arrives at a closed upload and is
    // refused.
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let old_etag = rig.part("alpha", KEY, &id, 1, &old).await;
    let (complete, part) = rig
        .race(
            complete_req(RW_KEY, "alpha", KEY, &id, &[(1, &old_etag)], &[]),
            part_req(RW_KEY, "alpha", KEY, &id, 1, &new),
        )
        .await;
    assert_eq!(complete.outcome(), "200", "{}", complete.body);
    assert_eq!(part.outcome(), "404 NoSuchUpload");
    assert!(rig.object(&rig.alpha, KEY).await.unwrap().1 == old);
    // The refused part's blob stays as an orphan for garbage collection:
    // the handler never deletes from the safety store. No row names it.
    let pinned = rig.bridge.safety.keys();
    assert_eq!(pinned.iter().filter(|k| k.starts_with("x/")).count(), 2);
    assert_eq!(rig.count("SELECT COUNT(*) FROM extents").await, 1);
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 1);
}

#[tokio::test]
async fn complete_retry_returns_receipt() {
    let rig = Rig::new().await;
    let first = test_bytes(1, 3000);
    let id = rig.create("alpha", KEY).await;
    let etag = rig.part("alpha", KEY, &id, 1, &first).await;
    let r = rig.complete("alpha", KEY, &id, &[(1, &etag)]).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let first_etag = xml_value(&r.body, "ETag").unwrap();

    // A later write to the same key.
    let later = test_bytes(2, 5000);
    let id2 = rig.create("alpha", KEY).await;
    let etag2 = rig.part("alpha", KEY, &id2, 1, &later).await;
    let r = rig.complete("alpha", KEY, &id2, &[(1, &etag2)]).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let (later_generation, _) = rig.object(&rig.alpha, KEY).await.unwrap();
    let outbox = rig.count("SELECT COUNT(*) FROM outbox").await;
    let generations = rig.count("SELECT COUNT(*) FROM generations").await;
    let sent = rig.bridge.jobs.sent().len();

    // The retried Complete answers from its receipt and publishes nothing:
    // the later object stays live.
    rig.bridge.clock.advance_secs(30);
    let retry = rig.complete("alpha", KEY, &id, &[(1, &etag)]).await;
    assert_eq!(retry.outcome(), "200", "{}", retry.body);
    assert_eq!(
        xml_value(&retry.body, "ETag").as_deref(),
        Some(first_etag.as_str())
    );
    let (generation, plain) = rig.object(&rig.alpha, KEY).await.unwrap();
    assert_eq!(generation.id, later_generation.id);
    assert!(plain == later);
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, outbox);
    assert_eq!(
        rig.count("SELECT COUNT(*) FROM generations").await,
        generations
    );
    assert_eq!(rig.bridge.jobs.sent().len(), sent);

    // A different part list is not that Complete.
    let other = rig
        .complete("alpha", KEY, &id, &[(1, &etag), (2, &etag)])
        .await;
    assert_eq!(other.outcome(), "404 NoSuchUpload");
    // A completed upload takes no parts and cannot be aborted.
    let r = rig
        .send(part_req(RW_KEY, "alpha", KEY, &id, 2, b"late"))
        .await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");
    assert_eq!(
        rig.abort("alpha", KEY, &id).await.outcome(),
        "404 NoSuchUpload"
    );
    assert_eq!(
        generation.id,
        rig.object(&rig.alpha, KEY).await.unwrap().0.id
    );
}

#[tokio::test]
async fn upload_id_cross_bucket_is_nosuchupload() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let bytes = test_bytes(1, 2048);
    let etag = rig.part("alpha", KEY, &id, 1, &bytes).await;
    let blobs = rig.bridge.safety.keys();

    // A key that may write to both buckets presents alpha's upload id
    // under beta.
    let r = rig
        .send(part_req(RW_KEY, "beta", KEY, &id, 2, &bytes))
        .await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");
    let r = rig.complete("beta", KEY, &id, &[(1, &etag)]).await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");
    let r = rig.abort("beta", KEY, &id).await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");

    // A key without a grant on beta is refused before the id is looked at;
    // so is a read-only key on its own bucket.
    let beta_id = rig.create("beta", KEY).await;
    for req in [
        part_req(ALPHA_KEY, "beta", KEY, &beta_id, 1, &bytes),
        complete_req(ALPHA_KEY, "beta", KEY, &beta_id, &[(1, &etag)], &[]),
        abort_req(ALPHA_KEY, "beta", KEY, &beta_id),
        create_req(ALPHA_KEY, "beta", KEY, &[]),
        part_req(RO_KEY, "alpha", KEY, &id, 2, &bytes),
        abort_req(RO_KEY, "alpha", KEY, &id),
        create_req(RO_KEY, "alpha", KEY, &[]),
    ] {
        let target = req.target.clone();
        assert_eq!(
            rig.send(req).await.outcome(),
            "403 AccessDenied",
            "{target}"
        );
    }

    // Nothing was stored, published or closed by any of it.
    assert_eq!(rig.bridge.safety.keys(), blobs);
    assert!(rig.object(&rig.alpha, KEY).await.is_none());
    assert!(rig.object(&rig.beta, KEY).await.is_none());
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(rig.count("SELECT COUNT(*) FROM gc").await, 0);
    assert_eq!(
        rig.upload_state(&rig.beta, KEY, &beta_id).await,
        Some(UploadState::Open)
    );
    assert_eq!(
        rig.upload_state(&rig.alpha, KEY, &id).await,
        Some(UploadState::Open)
    );
    // The upload still completes where it belongs.
    let r = rig.complete("alpha", KEY, &id, &[(1, &etag)]).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    assert!(rig.object(&rig.alpha, KEY).await.unwrap().1 == bytes);
}

#[tokio::test]
async fn upload_id_cross_key_is_nosuchupload() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let bytes = test_bytes(1, 2048);
    let etag = rig.part("alpha", KEY, &id, 1, &bytes).await;
    let other = "dir/other.bin";

    let r = rig
        .send(part_req(RW_KEY, "alpha", other, &id, 2, &bytes))
        .await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");
    let r = rig.complete("alpha", other, &id, &[(1, &etag)]).await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");
    let r = rig.abort("alpha", other, &id).await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");
    // An id this service never issued, and one that is not an id at all.
    for bad in ["00000000000000000000000000000000", "nope", "' OR 1=1 --"] {
        let r = rig.complete("alpha", KEY, bad, &[(1, &etag)]).await;
        assert_eq!(r.outcome(), "404 NoSuchUpload", "{bad}");
        let r = rig.abort("alpha", KEY, bad).await;
        assert_eq!(r.outcome(), "404 NoSuchUpload", "{bad}");
    }

    assert_eq!(rig.bridge.safety.keys().len(), 1);
    assert!(rig.object(&rig.alpha, other).await.is_none());
    assert!(rig.object(&rig.alpha, KEY).await.is_none());
    assert_eq!(
        rig.upload_state(&rig.alpha, KEY, &id).await,
        Some(UploadState::Open)
    );
}

#[tokio::test]
async fn conditional_write_is_501_and_stores_nothing() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let bytes = test_bytes(1, 2048);
    let etag = rig.part("alpha", KEY, &id, 1, &bytes).await;

    for header in [
        ("if-none-match", "*"),
        ("if-match", "\"0123456789abcdef0123456789abcdef\""),
        ("if-modified-since", "Fri, 13 Nov 2026 00:00:00 GMT"),
        ("if-unmodified-since", "Fri, 13 Nov 2026 00:00:00 GMT"),
    ] {
        let r = rig
            .send(complete_req(
                RW_KEY,
                "alpha",
                KEY,
                &id,
                &[(1, &etag)],
                &[header],
            ))
            .await;
        assert_eq!(r.outcome(), "501 NotImplemented", "{}", header.0);
    }
    assert!(rig.object(&rig.alpha, KEY).await.is_none());
    assert_eq!(rig.count("SELECT COUNT(*) FROM generations").await, 0);
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(
        rig.upload_state(&rig.alpha, KEY, &id).await,
        Some(UploadState::Open)
    );

    // Create with a condition opens no upload.
    let r = rig
        .send(create_req(
            RW_KEY,
            "alpha",
            "x.bin",
            &[("if-none-match", "*")],
        ))
        .await;
    assert_eq!(r.outcome(), "501 NotImplemented");
    assert_eq!(rig.count("SELECT COUNT(*) FROM uploads").await, 1);

    // The upload is unharmed.
    let r = rig.complete("alpha", KEY, &id, &[(1, &etag)]).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
}

#[tokio::test]
async fn complete_validates_the_part_list() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let small = test_bytes(1, 5 * MIB - 1);
    let tail = test_bytes(2, 100);
    let small_etag = rig.part("alpha", KEY, &id, 1, &small).await;
    let tail_etag = rig.part("alpha", KEY, &id, 2, &tail).await;

    // A non-final part under 5 MiB.
    let r = rig
        .complete("alpha", KEY, &id, &[(1, &small_etag), (2, &tail_etag)])
        .await;
    assert_eq!(r.outcome(), "400 EntityTooSmall");
    // Parts out of order, and a repeated part.
    let r = rig
        .complete("alpha", KEY, &id, &[(2, &tail_etag), (1, &small_etag)])
        .await;
    assert_eq!(r.outcome(), "400 InvalidPartOrder");
    let r = rig
        .complete("alpha", KEY, &id, &[(1, &small_etag), (1, &small_etag)])
        .await;
    assert_eq!(r.outcome(), "400 InvalidPartOrder");
    // A part that was never uploaded, and a wrong ETag.
    let r = rig
        .complete("alpha", KEY, &id, &[(2, &tail_etag), (3, &tail_etag)])
        .await;
    assert_eq!(r.outcome(), "400 InvalidPart");
    let r = rig.complete("alpha", KEY, &id, &[(2, &small_etag)]).await;
    assert_eq!(r.outcome(), "400 InvalidPart");
    // Not a part list.
    let r = rig
        .send(sign(
            RW_KEY,
            Method::Post,
            &object_path("alpha", KEY),
            &[("uploadId", &id)],
            &[],
            b"<CompleteMultipartUpload><Part>".to_vec(),
        ))
        .await;
    assert_eq!(r.outcome(), "400 MalformedXML");
    // A part list without parts.
    for empty in [
        "<CompleteMultipartUpload/>",
        "<CompleteMultipartUpload></CompleteMultipartUpload>",
    ] {
        let r = rig
            .send(sign(
                RW_KEY,
                Method::Post,
                &object_path("alpha", KEY),
                &[("uploadId", &id)],
                &[],
                empty.as_bytes().to_vec(),
            ))
            .await;
        assert_eq!(r.outcome(), "400 MalformedXML", "{empty}");
    }

    // None of the refusals published or closed anything.
    assert!(rig.object(&rig.alpha, KEY).await.is_none());
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(rig.count("SELECT COUNT(*) FROM gc").await, 0);
    assert_eq!(
        rig.upload_state(&rig.alpha, KEY, &id).await,
        Some(UploadState::Open)
    );
    // The small part alone is a valid (final) part.
    let r = rig.complete("alpha", KEY, &id, &[(1, &small_etag)]).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    assert!(rig.object(&rig.alpha, KEY).await.unwrap().1 == small);
}

#[tokio::test]
async fn upload_part_refuses_bad_input_and_stores_nothing() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let bytes = test_bytes(1, 2048);
    let path = object_path("alpha", KEY);

    for number in ["0", "10001", "x", "-1"] {
        let r = rig
            .send(sign(
                RW_KEY,
                Method::Put,
                &path,
                &[("partNumber", number), ("uploadId", &id)],
                &[],
                bytes.clone(),
            ))
            .await;
        assert_eq!(r.outcome(), "400 InvalidArgument", "partNumber={number}");
    }
    // Body does not match the signed payload hash.
    let mut tampered = part_req(RW_KEY, "alpha", KEY, &id, 1, &bytes);
    tampered.body[0] ^= 1;
    assert_eq!(rig.send(tampered).await.outcome(), "400 BadDigest");
    // Wrong Content-MD5.
    let wrong_md5 = base64::engine::general_purpose::STANDARD.encode(md5::compute(b"other").0);
    let r = rig
        .send(sign(
            RW_KEY,
            Method::Put,
            &path,
            &[("partNumber", "1"), ("uploadId", &id)],
            &[("content-md5", &wrong_md5)],
            bytes.clone(),
        ))
        .await;
    assert_eq!(r.outcome(), "400 BadDigest");
    // A forged signature.
    let mut forged = part_req(RW_KEY, "alpha", KEY, &id, 1, &bytes);
    for (name, value) in &mut forged.headers {
        if name == "authorization" {
            let flipped = if value.ends_with('0') { "1" } else { "0" };
            value.replace_range(value.len() - 1.., flipped);
        }
    }
    assert_eq!(
        rig.send(forged).await.outcome(),
        "403 SignatureDoesNotMatch"
    );
    // Larger than one extent: refused from the declared length.
    let r = rig
        .send(part_req(
            RW_KEY,
            "alpha",
            KEY,
            &id,
            1,
            &vec![0u8; 16 * MIB + 1],
        ))
        .await;
    assert_eq!(r.outcome(), "400 EntityTooLarge");
    // UploadPartCopy is not built.
    let r = rig
        .send(sign(
            RW_KEY,
            Method::Put,
            &path,
            &[("partNumber", "1"), ("uploadId", &id)],
            &[("x-amz-copy-source", "/alpha/src")],
            Vec::new(),
        ))
        .await;
    assert_eq!(r.outcome(), "501 NotImplemented");

    assert!(rig.bridge.safety.keys().is_empty());
    assert_eq!(rig.count("SELECT COUNT(*) FROM extents").await, 0);
    assert_eq!(rig.count("SELECT COUNT(*) FROM upload_parts").await, 0);
    // All in-flight bytes were released.
    let r = rig
        .send(part_req(
            RW_KEY,
            "alpha",
            KEY,
            &id,
            1,
            &test_bytes(3, 16 * MIB),
        ))
        .await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
}

#[tokio::test]
async fn abort_collects_parts_and_closes_the_upload() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let bytes = test_bytes(1, 2048);
    let etag = rig.part("alpha", KEY, &id, 1, &bytes).await;
    rig.part("alpha", KEY, &id, 2, &bytes).await;

    assert_eq!(rig.abort("alpha", KEY, &id).await.outcome(), "204");
    assert_eq!(
        rig.upload_state(&rig.alpha, KEY, &id).await,
        Some(UploadState::Aborted)
    );
    assert_eq!(
        rig.count("SELECT COUNT(DISTINCT extent_id) FROM gc").await,
        2
    );
    // Aborting again is harmless; everything else finds no upload.
    assert_eq!(rig.abort("alpha", KEY, &id).await.outcome(), "204");
    let r = rig
        .send(part_req(RW_KEY, "alpha", KEY, &id, 3, &bytes))
        .await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");
    let r = rig.complete("alpha", KEY, &id, &[(1, &etag)]).await;
    assert_eq!(r.outcome(), "404 NoSuchUpload");
    assert!(rig.object(&rig.alpha, KEY).await.is_none());
    assert_eq!(rig.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(rig.bridge.safety.keys().len(), 2);
}

#[tokio::test]
async fn restore_maintenance_refuses_every_call() {
    let rig = Rig::with_maintenance("restore").await;
    let id = "0123456789abcdef0123456789abcdef";
    for req in [
        create_req(RW_KEY, "alpha", KEY, &[]),
        part_req(RW_KEY, "alpha", KEY, id, 1, b"data"),
        complete_req(RW_KEY, "alpha", KEY, id, &[(1, "\"etag\"")], &[]),
        abort_req(RW_KEY, "alpha", KEY, id),
    ] {
        let target = req.target.clone();
        assert_eq!(rig.send(req).await.status, 503, "{target}");
    }
    assert_eq!(rig.count("SELECT COUNT(*) FROM uploads").await, 0);
    assert!(rig.bridge.safety.keys().is_empty());
}

// ---------------------------------------------------------------------------
// aws-chunked bodies (PutObject and UploadPart)
// ---------------------------------------------------------------------------

const SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
const SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
const UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn crc32c(data: &[u8]) -> [u8; 4] {
    let mut table = [0u32; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
        }
        *t = c;
    }
    let mut c = !0u32;
    for b in data {
        c = table[((c ^ u32::from(*b)) & 0xff) as usize] ^ (c >> 8);
    }
    (!c).to_be_bytes()
}

/// The scope and timestamp `sign_as` uses.
fn stamp_scope() -> (String, String) {
    let secs = T0.0.div_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    let date = format!("{y:04}{mo:02}{d:02}");
    (
        format!("{date}T{:02}{:02}{:02}Z", t / 3600, t % 3600 / 60, t % 60),
        format!("{date}/{REGION}/s3/aws4_request"),
    )
}

fn signing_key() -> Vec<u8> {
    let (stamp, _) = stamp_scope();
    let k = hmac(
        format!("AWS4{SIGNING_SECRET}").as_bytes(),
        &stamp.as_bytes()[..8],
    );
    let k = hmac(&k, REGION.as_bytes());
    let k = hmac(&k, b"s3");
    hmac(&k, b"aws4_request")
}

/// A signed aws-chunked body chained from `seed`, with an optional signed
/// trailer.
fn signed_chunks(
    seed: &str,
    data: &[u8],
    chunk: usize,
    trailer: Option<(&str, String)>,
) -> Vec<u8> {
    let (stamp, scope) = stamp_scope();
    let key = signing_key();
    let empty = hex(&sha256(b""));
    let mut previous = seed.to_owned();
    let mut out = Vec::new();
    for c in data.chunks(chunk).chain([&b""[..]]) {
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{stamp}\n{scope}\n{previous}\n{empty}\n{}",
            hex(&sha256(c))
        );
        previous = hex(&hmac(&key, sts.as_bytes()));
        out.extend_from_slice(format!("{:x};chunk-signature={previous}\r\n", c.len()).as_bytes());
        if !c.is_empty() {
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
    }
    if let Some((name, value)) = trailer {
        let sts = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{stamp}\n{scope}\n{previous}\n{}",
            hex(&sha256(format!("{name}:{value}\n").as_bytes()))
        );
        let sig = hex(&hmac(&key, sts.as_bytes()));
        out.extend_from_slice(
            format!("{name}:{value}\r\nx-amz-trailer-signature:{sig}\r\n").as_bytes(),
        );
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// An unsigned aws-chunked body, the way aws-cli sends it.
fn unsigned_chunks(data: &[u8], chunk: usize, trailer: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for c in data.chunks(chunk) {
        out.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        out.extend_from_slice(c);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n");
    if !trailer.is_empty() {
        out.extend_from_slice(format!("{trailer}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// A streaming request: `extra` plus the aws-chunked headers, signed with
/// `payload`. Returns the request without a body and the seed signature.
fn chunked_req(
    path: &str,
    query: &[(&str, &str)],
    payload: &str,
    decoded: usize,
    extra: &[(&str, &str)],
) -> (Req, String) {
    let decoded = decoded.to_string();
    let mut all = vec![
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", decoded.as_str()),
    ];
    all.extend_from_slice(extra);
    sign_as(
        RW_KEY,
        Method::Put,
        path,
        query,
        &all,
        Vec::new(),
        Some(payload),
    )
}

fn with_body(mut r: Req, body: Vec<u8>, content_length: bool) -> Req {
    if content_length {
        r.headers
            .push(("content-length".into(), body.len().to_string()));
    } else {
        r.headers
            .push(("transfer-encoding".into(), "chunked".into()));
    }
    r.body = body;
    r
}

#[tokio::test]
async fn aws_chunked_put_and_upload_part_round_trip() {
    let rig = Rig::new().await;

    // PutObject as aws-cli sends it by default over HTTPS: unsigned
    // trailer, CRC64NVME, HTTP chunked without Content-Length.
    let small = b"hello world, this is a test body\n".to_vec();
    let path = object_path("alpha", "small.txt");
    let (r, _) = chunked_req(
        &path,
        &[],
        UNSIGNED_TRAILER,
        small.len(),
        &[
            ("x-amz-trailer", "x-amz-checksum-crc64nvme"),
            ("x-amz-sdk-checksum-algorithm", "CRC64NVME"),
        ],
    );
    let body = unsigned_chunks(&small, 7, "x-amz-checksum-crc64nvme:bgGah9vCkZ4=");
    let r = rig.send_in(with_body(r, body, false), 5).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    assert_eq!(r.header("x-amz-checksum-crc64nvme"), Some("bgGah9vCkZ4="));
    let (generation, plain) = rig.object(&rig.alpha, "small.txt").await.unwrap();
    assert_eq!(plain, small);
    // The trailer checksum is stored for GET/HEAD with checksum mode, and
    // aws-chunked is not stored as a content coding.
    let stored: serde_json::Value =
        serde_json::from_str(generation.checksum_json.as_deref().unwrap()).unwrap();
    assert_eq!(stored["algorithm"], "CRC64NVME");
    assert_eq!(stored["value"], "bgGah9vCkZ4=");
    assert!(!generation.content_json.contains("aws-chunked"));

    // A full 16 MiB extent: the encoded body is larger than the cap, the
    // decoded body is not. Signed chunks, with Content-Length.
    let full = test_bytes(7, 16 * MIB);
    let path = object_path("alpha", "full.bin");
    let (r, seed) = chunked_req(&path, &[], SIGNED, full.len(), &[]);
    let body = signed_chunks(&seed, &full, 64 * 1024, None);
    assert!(body.len() > 16 * MIB);
    let r = rig.send_in(with_body(r, body, true), 100_003).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    assert_eq!(rig.object(&rig.alpha, "full.bin").await.unwrap().1, full);
    // Charged by the decoded length (2 x 16 MiB), not the encoded one.
    assert_eq!(rig.bridge.budget.peak(), 32 * MIB as u64);

    // Multipart, as s3transfer sends it: Create names an algorithm.
    let r = rig
        .send(create_req(
            RW_KEY,
            "alpha",
            KEY,
            &[("x-amz-checksum-algorithm", "CRC32C")],
        ))
        .await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let id = xml_value(&r.body, "UploadId").unwrap();
    let path = object_path("alpha", KEY);
    let one = test_bytes(1, 5 * MIB);
    let two = test_bytes(2, 12345);
    let q1 = [("partNumber", "1"), ("uploadId", id.as_str())];
    let (r, _) = chunked_req(
        &path,
        &q1,
        UNSIGNED_TRAILER,
        one.len(),
        &[("x-amz-trailer", "x-amz-checksum-crc32c")],
    );
    let body = unsigned_chunks(
        &one,
        MIB,
        &format!("x-amz-checksum-crc32c:{}", b64(&crc32c(&one))),
    );
    let r = rig.send_in(with_body(r, body, false), 65_536).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let etag1 = r.header("etag").unwrap().to_string();
    assert_eq!(etag1, format!("\"{}\"", hex(&md5::compute(&one).0)));
    // No part checksum is echoed, so clients list none in Complete.
    assert!(r
        .headers
        .iter()
        .all(|(n, _)| !n.starts_with("x-amz-checksum")));
    let q2 = [("partNumber", "2"), ("uploadId", id.as_str())];
    let (r, seed) = chunked_req(
        &path,
        &q2,
        SIGNED_TRAILER,
        two.len(),
        &[("x-amz-trailer", "x-amz-checksum-crc32c")],
    );
    let crc = b64(&crc32c(&two));
    let body = signed_chunks(&seed, &two, 8192, Some(("x-amz-checksum-crc32c", crc)));
    let r = rig.send_in(with_body(r, body, true), 999).await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    let etag2 = r.header("etag").unwrap().to_string();
    let r = rig
        .complete("alpha", KEY, &id, &[(1, &etag1), (2, &etag2)])
        .await;
    assert_eq!(r.outcome(), "200", "{}", r.body);
    assert_eq!(
        xml_value(&r.body, "ETag").unwrap(),
        multipart_etag(&[&one, &two])
    );
    let (generation, plain) = rig.object(&rig.alpha, KEY).await.unwrap();
    assert_eq!(plain, [one, two].concat());
    assert_eq!(generation.checksum_json, None);
}

#[tokio::test]
async fn aws_chunked_refusals_store_nothing() {
    let rig = Rig::new().await;
    let id = rig.create("alpha", KEY).await;
    let path = object_path("alpha", KEY);
    let q = [("partNumber", "1"), ("uploadId", id.as_str())];
    let data = test_bytes(4, 20_000);

    // A tampered chunk signature.
    let (r, seed) = chunked_req(&path, &q, SIGNED, data.len(), &[]);
    let mut body = signed_chunks(&seed, &data, 8192, None);
    let at = body.iter().position(|&b| b == b'=').unwrap() + 1;
    body[at] = if body[at] == b'0' { b'1' } else { b'0' };
    let r = rig.send(with_body(r, body, true)).await;
    assert_eq!(r.outcome(), "403 SignatureDoesNotMatch");

    // A decoded length that does not match the chunks.
    let (r, seed) = chunked_req(&path, &q, SIGNED, data.len() + 1, &[]);
    let body = signed_chunks(&seed, &data, 8192, None);
    let r = rig.send(with_body(r, body, false)).await;
    assert_eq!(r.outcome(), "400 IncompleteBody");

    // A trailer checksum that does not match the data.
    let (r, _) = chunked_req(
        &path,
        &q,
        UNSIGNED_TRAILER,
        data.len(),
        &[("x-amz-trailer", "x-amz-checksum-crc32c")],
    );
    let body = unsigned_chunks(
        &data,
        4096,
        &format!("x-amz-checksum-crc32c:{}", b64(&crc32c(b"x"))),
    );
    let r = rig.send(with_body(r, body, false)).await;
    assert_eq!(r.outcome(), "400 BadDigest");

    // Unsigned streams must declare a checksum; these cases declare a
    // correct one so they fail for their own reason.
    let crc = [("x-amz-trailer", "x-amz-checksum-crc32c")];
    let good_trailer = format!("x-amz-checksum-crc32c:{}", b64(&crc32c(&data)));

    // The final 0-chunk never arrives.
    let (r, _) = chunked_req(&path, &q, UNSIGNED_TRAILER, data.len(), &crc);
    let mut body = unsigned_chunks(&data, 4096, &good_trailer);
    let end = body.windows(5).rposition(|w| w == b"\r\n0\r\n").unwrap() + 2;
    body.truncate(end);
    let r = rig.send(with_body(r, body, false)).await;
    assert_eq!(r.outcome(), "400 IncompleteBody");

    // Content-Length longer than what is sent.
    let (r, _) = chunked_req(&path, &q, UNSIGNED_TRAILER, data.len(), &crc);
    let body = unsigned_chunks(&data, 4096, &good_trailer);
    let mut r = with_body(r, body, true);
    for (n, v) in &mut r.headers {
        if n == "content-length" {
            *v = (v.parse::<u64>().unwrap() + 1).to_string();
        }
    }
    assert_eq!(rig.send(r).await.outcome(), "400 IncompleteBody");

    // Over the cap by the decoded length, and no decoded length at all:
    // refused before any byte is read.
    let (r, _) = chunked_req(&path, &q, UNSIGNED_TRAILER, 16 * MIB + 1, &crc);
    let r = rig.send(with_body(r, b"0\r\n\r\n".to_vec(), false)).await;
    assert_eq!(r.outcome(), "400 EntityTooLarge");
    let (r, _) = sign_as(
        RW_KEY,
        Method::Put,
        &path,
        &q,
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-trailer", "x-amz-checksum-crc32c"),
        ],
        Vec::new(),
        Some(UNSIGNED_TRAILER),
    );
    let r = rig.send(with_body(r, b"0\r\n\r\n".to_vec(), false)).await;
    assert_eq!(r.outcome(), "411 MissingContentLength");

    // Complete with an object checksum, Create with COMPOSITE: 501.
    let r = rig
        .send(complete_req(
            RW_KEY,
            "alpha",
            KEY,
            &id,
            &[(1, "\"00000000000000000000000000000000\"")],
            &[("x-amz-checksum-crc32c", "AAAAAA==")],
        ))
        .await;
    assert_eq!(r.outcome(), "501 NotImplemented");
    let r = rig
        .send(create_req(
            RW_KEY,
            "alpha",
            "c.bin",
            &[
                ("x-amz-checksum-algorithm", "CRC32C"),
                ("x-amz-checksum-type", "COMPOSITE"),
            ],
        ))
        .await;
    assert_eq!(r.outcome(), "501 NotImplemented");

    // An unsigned stream that declares no checksum at all is refused.
    let (r, _) = chunked_req(&path, &q, UNSIGNED_TRAILER, data.len(), &[]);
    let body = unsigned_chunks(&data, 4096, "");
    let r = rig.send(with_body(r, body, false)).await;
    assert_eq!(r.outcome(), "400 InvalidRequest");

    assert!(rig.bridge.safety.keys().is_empty());
    assert_eq!(rig.count("SELECT COUNT(*) FROM extents").await, 0);
    assert_eq!(rig.count("SELECT COUNT(*) FROM upload_parts").await, 0);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}
