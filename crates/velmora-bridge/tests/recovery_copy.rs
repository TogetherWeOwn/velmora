//! The recovery copy: the store adapter (signing, retries, proof of a
//! put) and the pass that copies every recovery record out, against an
//! in-memory S3 store that speaks HTTP.
//!
//! The fake store panics on any method but GET, HEAD and PUT, in every
//! test of this file: nothing here may ever send a DELETE.

mod segmented_support;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use base64::Engine;
use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;
use velmora_bridge::config::{ConfigError, Maintenance};
use velmora_bridge::copy::{
    pass_due, plan_hint, Copier, CopyCounts, StepError, BEGAN_KEY, DOWN_KEY, FRESH_MS,
    HINT_PAUSE_MS, HINT_RETRY_MS, HINT_RETRY_SECS, JOB_COPIES, MIN_AGE_MS, PASS_INTERVAL_MS,
    RETRY_WINDOW_MS, STORE_KEY, SWEEP_KEY, SWEEP_MS, SWEEP_RECORDS, SWEEP_RETRY_MS, SWEPT_KEY,
    WALKED_KEY, WALK_INTERVAL_MS, WALK_KEY, WALK_SOON_MS, WANT_KEY,
};
use velmora_bridge::crypto::seal_manifest;
use velmora_bridge::remote::{
    md5_hex, HttpRequest, HttpResponse, HttpSend, NoAnswer, RemoteConfig, RemoteError, S3Remote,
    MAX_ANSWER_BYTES, MAX_LIST_BYTES,
};
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, TestKek};
use velmora_bridge::*;
use velmora_s3_proto::{verify, Authority, Credential, ErrorCode, Headers, Limits, Policy, Target};

const NOW: i64 = 1_800_000_000_000;
const ACCESS_KEY: &str = "AKTESTTESTTESTTEST00";
const SECRET_KEY: &str = "test-secret-that-must-never-be-formatted";
const ROOT: &str = "/records/drill-1/";

type Sent = std::result::Result<HttpResponse, NoAnswer>;

// ---------------------------------------------------------------------------
// The fake store
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeE2 {
    /// The store's own time: a pause moves it, and a request signed for
    /// a time more than one second from it is refused.
    clock: Option<FixedClock>,
    /// By key, without bucket and prefix.
    objects: RefCell<BTreeMap<String, Vec<u8>>>,
    /// `METHOD key` of every request that got an answer or was dropped.
    log: RefCell<Vec<String>>,
    pauses: RefCell<Vec<u64>>,
    /// The next n PUTs answer 500.
    put_500: Cell<u32>,
    /// The next n requests get no answer.
    drop_next: Cell<u32>,
    /// Every PUT of one of these keys answers 500.
    put_500_keys: RefCell<Vec<String>>,
    /// Every PUT answers this status.
    put_status: Cell<Option<u16>>,
    /// A PUT stores other bytes than it was sent.
    damage_puts: Cell<bool>,
    /// Keys per list answer (0 = as asked).
    page: Cell<usize>,
    /// Every request answers this status.
    status: Cell<Option<u16>>,
    /// Every HEAD gets this answer.
    head_answer: RefCell<Option<HttpResponse>>,
    /// Every list answer has these elements in its root.
    list_inner: RefCell<Option<String>>,
    /// The next n answers have a body one byte longer than was asked for.
    long_next: Cell<u32>,
    /// A pause takes no time.
    still: Cell<bool>,
    /// `start-after` of every list request, without the store's prefix.
    asked: RefCell<Vec<String>>,
}

fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The store's side of SigV4: this crate's own verifier, with the
/// store's host, region and secret, at the store's time: a request
/// dated two seconds or more from it is refused.
struct StoreKeys;
impl Authority for StoreKeys {
    fn credential(&self, key: &str) -> Option<Credential<'_>> {
        (key == ACCESS_KEY).then_some(Credential {
            secret: SECRET_KEY.as_bytes(),
            principal: "p",
        })
    }
    fn authorize(&self, _: &str, _: &str, _: &Target) -> bool {
        true
    }
}

fn check_signature(
    method: &str,
    target: &str,
    sent: &[(String, String)],
    now_ms: i64,
) -> std::result::Result<(), ErrorCode> {
    let policy = Policy::new(
        "e2.test".into(),
        "us-west-1".into(),
        Limits {
            target_bytes: 8192,
            control_xml_bytes: 4096,
            header_bytes: 16384,
            header_count: 64,
            query_pairs: 64,
            upload_bytes: 1 << 20,
            clock_skew_seconds: 1,
            presign_seconds: 60,
        },
    )
    .unwrap();
    let mut fields: Vec<(&str, &str)> = vec![("host", "e2.test")];
    fields.extend(sent.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let headers = Headers::new(&fields, &policy)?;
    let target = Target::parse(target, &policy)?;
    verify(
        method,
        &target,
        &headers,
        true,
        now_ms / 1000,
        &policy,
        &StoreKeys,
    )
    .map(|_| ())
}

fn answer(status: u16) -> Sent {
    Ok(HttpResponse {
        status,
        ..HttpResponse::default()
    })
}

/// A HEAD answer that reports `size` and `etag`.
fn head_of(size: &str, etag: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![
            ("content-length".into(), size.into()),
            ("etag".into(), etag.into()),
        ],
        body: vec![],
    }
}

/// One object of a list answer, by its full key in the bucket.
fn contents(full_key: &str) -> String {
    format!(
        "<Contents><Key>{full_key}</Key><ETag>&quot;{}&quot;</ETag><Size>1</Size></Contents>",
        md5_hex(b"1")
    )
}

impl FakeE2 {
    fn puts(&self) -> usize {
        self.count("PUT ")
    }
    fn count(&self, start: &str) -> usize {
        self.log
            .borrow()
            .iter()
            .filter(|l| l.starts_with(start))
            .count()
    }
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.borrow().get(key).cloned()
    }
    fn set(&self, key: &str, bytes: &[u8]) {
        self.objects.borrow_mut().insert(key.into(), bytes.to_vec());
    }

    fn list(&self, query: &str) -> Sent {
        let q: BTreeMap<String, String> = query
            .split('&')
            .map(|pair| pair.split_once('=').unwrap())
            .map(|(k, v)| (unescape(k), unescape(v)))
            .collect();
        assert_eq!(q["list-type"], "2");
        let own = &ROOT["/records/".len()..];
        let prefix = q["prefix"].strip_prefix(own).expect("own prefix");
        let after = match q.get("start-after") {
            Some(a) => a.strip_prefix(own).expect("own prefix").to_string(),
            None => String::new(),
        };
        self.asked.borrow_mut().push(after.clone());
        let mut limit: usize = q["max-keys"].parse().unwrap();
        if self.page.get() > 0 {
            limit = limit.min(self.page.get());
        }
        if let Some(inner) = self.list_inner.borrow().as_ref() {
            return Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: format!("<ListBucketResult>{inner}</ListBucketResult>").into_bytes(),
            });
        }
        let objects = self.objects.borrow();
        let all: Vec<_> = objects
            .iter()
            .filter(|(k, _)| k.starts_with(prefix) && k.as_str() > after.as_str())
            .collect();
        let mut xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><IsTruncated>{}</IsTruncated>",
            all.len() > limit
        );
        for (key, bytes) in all.into_iter().take(limit) {
            xml.push_str(&format!(
                "<Contents><Key>{own}{key}</Key><ETag>&quot;{}&quot;</ETag><Size>{}</Size></Contents>",
                md5_hex(bytes),
                bytes.len()
            ));
        }
        xml.push_str("</ListBucketResult>");
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: xml.into_bytes(),
        })
    }
}

impl HttpSend for &FakeE2 {
    async fn send(&self, request: &HttpRequest) -> Sent {
        let method = request.method;
        assert!(
            matches!(method, "GET" | "HEAD" | "PUT"),
            "{method} sent to the recovery store"
        );
        let target = request
            .url
            .strip_prefix("https://e2.test")
            .expect("the configured endpoint, https");
        let header = |name: &str| {
            request
                .headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let auth = header("authorization").expect("signed");
        assert!(auth.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/")));
        let now_ms = self.clock.as_ref().expect("a clock").now().0;
        assert_eq!(
            check_signature(method, target, &request.headers, now_ms),
            Ok(()),
            "{method} {target}"
        );
        let most = if method == "GET" {
            MAX_LIST_BYTES
        } else {
            MAX_ANSWER_BYTES
        };
        assert_eq!(request.max_answer, most, "{method} {target}");
        let key = match method {
            "GET" => "list",
            _ => target.strip_prefix(ROOT).expect("bucket and prefix"),
        };
        self.log.borrow_mut().push(format!("{method} {key}"));
        if self.drop_next.get() > 0 {
            self.drop_next.set(self.drop_next.get() - 1);
            return Err(NoAnswer);
        }
        if self.long_next.get() > 0 {
            self.long_next.set(self.long_next.get() - 1);
            return Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![b' '; request.max_answer + 1],
            });
        }
        if let Some(status) = self.status.get() {
            return answer(status);
        }
        if method == "GET" {
            let query = target.strip_prefix("/records?").expect("bucket list");
            return self.list(query);
        }
        if method == "HEAD" {
            if let Some(forced) = self.head_answer.borrow().as_ref() {
                return Ok(forced.clone());
            }
            return match self.get(key) {
                None => answer(404),
                Some(bytes) => Ok(HttpResponse {
                    status: 200,
                    headers: vec![
                        ("content-length".into(), bytes.len().to_string()),
                        ("etag".into(), format!("\"{}\"", md5_hex(&bytes))),
                    ],
                    body: vec![],
                }),
            };
        }
        if let Some(status) = self.put_status.get() {
            return answer(status);
        }
        if self.put_500_keys.borrow().iter().any(|k| k == key) {
            return answer(500);
        }
        if self.put_500.get() > 0 {
            self.put_500.set(self.put_500.get() - 1);
            return answer(500);
        }
        let md5 = base64::engine::general_purpose::STANDARD.encode(md5::compute(&request.body).0);
        let sha256: String = Sha256::digest(&request.body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if header("content-md5") != Some(md5.as_str())
            || header("x-amz-content-sha256") != Some(sha256.as_str())
            || header("x-amz-meta-sha256") != Some(sha256.as_str())
        {
            return answer(400);
        }
        let mut stored = request.body.clone();
        if self.damage_puts.get() {
            stored[0] ^= 1;
        }
        self.set(key, &stored);
        answer(200)
    }

    async fn pause(&self, ms: u64) {
        self.pauses.borrow_mut().push(ms);
        if self.still.get() {
            return;
        }
        self.clock.as_ref().expect("a clock").advance_ms(ms as i64);
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn vars(name: &str) -> Option<String> {
    Some(
        match name {
            "RECOVERY_COPY" => "on",
            "E2_ENDPOINT" => "https://e2.test",
            "E2_REGION" => "us-west-1",
            "E2_BUCKET" => "records",
            "RECOVERY_PREFIX" => "drill-1/",
            "E2_ACCESS_KEY" => ACCESS_KEY,
            "E2_SECRET_KEY" => SECRET_KEY,
            _ => return None,
        }
        .to_string(),
    )
}

struct World {
    safety: MemBlobStore,
    kek: TestKek,
    clock: FixedClock,
    jobs: FakeJobs,
    e2: &'static FakeE2,
    remote: S3Remote<&'static FakeE2>,
}

impl World {
    fn new() -> World {
        let clock = FixedClock::new(UnixMs(NOW));
        let e2: &'static FakeE2 = Box::leak(Box::new(FakeE2 {
            clock: Some(clock.clone()),
            ..FakeE2::default()
        }));
        let cfg = RemoteConfig::from_vars(vars).unwrap().unwrap();
        World {
            safety: MemBlobStore::new(),
            kek: TestKek::new(),
            clock,
            jobs: FakeJobs::new(),
            e2,
            remote: S3Remote::new(cfg, e2),
        }
    }

    fn copier(&self) -> Copier<'_, MemBlobStore, TestKek, FixedClock, &'static FakeE2> {
        Copier {
            safety: &self.safety,
            kek: &self.kek,
            clock: &self.clock,
            remote: &self.remote,
            maintenance: Maintenance::Off,
        }
    }

    /// Stores a record that opens under the KEK at `key`.
    async fn record(&self, key: &str, plain: &[u8]) -> Vec<u8> {
        let sealed = seal_manifest(&self.kek, key, plain, &mut SystemRng).unwrap();
        self.raw(key, sealed.clone()).await;
        sealed
    }

    /// Stores a generation record that names the extents `ids`.
    async fn generation(&self, key: &str, ids: &[&str]) -> Vec<u8> {
        let extents: Vec<String> = ids
            .iter()
            .map(|id| format!("{{\"id\":\"{id}\"}}"))
            .collect();
        let plain = format!("{{\"v\":1,\"extents\":[{}]}}", extents.join(","));
        self.record(key, plain.as_bytes()).await
    }

    async fn raw(&self, key: &str, bytes: Vec<u8>) {
        let sha: [u8; 32] = Sha256::digest(&bytes).into();
        let meta = BlobMeta {
            bucket: &BucketId::new("b_0123456789abcdef"),
            extent: &ExtentId::new("x_0"),
            cipher_sha256: &sha,
        };
        self.safety.put(key, bytes, &meta).await.unwrap();
    }

    /// A whole pass, job after job. Returns the counts summed.
    async fn pass(&self) -> CopyCounts {
        let mut total = CopyCounts::default();
        let pass = self.clock.now();
        let mut cursor = Some(String::new());
        while let Some(at) = cursor {
            let step = self.copier().step(pass, &at).await.unwrap();
            let c = step.counts;
            total.records += c.records;
            total.bytes += c.bytes;
            total.same += c.same;
            total.copied += c.copied;
            total.failed += c.failed;
            total.refused += c.refused;
            total.source_unreadable += c.source_unreadable;
            total.young += c.young;
            total.pending += c.pending;
            total.extra += c.extra;
            total.foreign += c.foreign;
            cursor = step.next;
        }
        total
    }
}

/// Key of a generation record minted `age_ms` ago.
fn generation(age_ms: i64, tail: &str) -> String {
    format!("m/g_{:013x}{tail}", NOW - age_ms)
}

/// The cursor of a job of the walk that goes on after `key`.
fn walk(key: &str) -> String {
    format!("{{\"p\":\"a\",\"k\":\"{key}\"}}")
}

/// The cursor of a job of the fresh sweep that goes on after `key`.
fn sweep(key: &str) -> String {
    format!("{{\"p\":\"g\",\"k\":\"{key}\"}}")
}

/// What the fresh sweep lists: the tombstones and the generation
/// records of the flat layout and of the tenant layout.
const FRESH: [&str; 4] = [
    "m/del/g_",
    "m/g_",
    "m/x/t_0000000000000000/del/g_",
    "m/x/t_0000000000000000/g_",
];

/// Older than the fresh sweep reaches: a record of the walk.
const OLD: i64 = 2 * 3_600_000;

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn e2_put_retries_on_500_then_succeeds() {
    let w = World::new();
    w.e2.put_500.set(2);
    w.remote.put(&w.clock, "m/art/x_1", b"body").await.unwrap();
    assert_eq!(w.e2.puts(), 3);
    assert_eq!(w.e2.get("m/art/x_1").unwrap(), b"body");
    // Two pauses, the second four times the first, each with up to half
    // as much again (the part that depends on the time).
    assert_eq!(*w.e2.pauses.borrow(), [222, 967]);

    // No answer at all (network, timeout) is retried the same way.
    w.e2.drop_next.set(3);
    w.remote.put(&w.clock, "m/art/x_2", b"other").await.unwrap();
    assert_eq!(w.e2.get("m/art/x_2").unwrap(), b"other");
}

#[tokio::test(flavor = "current_thread")]
async fn e2_put_gives_up_after_four_tries() {
    let w = World::new();
    w.e2.put_status.set(Some(503));
    let e = w.remote.put(&w.clock, "m/art/x_1", b"body").await;
    assert_eq!(e, Err(RemoteError::Unavailable));
    assert_eq!(w.e2.puts(), 4);
    assert_eq!(w.e2.pauses.borrow().len(), 3);
    assert!(w.e2.get("m/art/x_1").is_none());

    // 429 asks for a later try; it is not a refusal.
    w.e2.put_status.set(Some(429));
    let e = w.remote.put(&w.clock, "m/art/x_1", b"body").await;
    assert_eq!(e, Err(RemoteError::Unavailable));
    assert_eq!(w.e2.puts(), 8);
}

#[tokio::test(flavor = "current_thread")]
async fn e2_put_4xx_is_refused_without_retry() {
    let w = World::new();
    for status in [400, 403, 404, 409] {
        let before = w.e2.puts();
        w.e2.put_status.set(Some(status));
        let e = w.remote.put(&w.clock, "m/art/x_1", b"body").await;
        assert_eq!(e, Err(RemoteError::Refused(status)));
        assert_eq!(w.e2.puts(), before + 1);
    }
    assert!(w.e2.pauses.borrow().is_empty());

    // A key outside the safe alphabet is refused before it is sent.
    w.e2.put_status.set(None);
    let e = w.remote.put(&w.clock, "m/art/x 1?", b"body").await;
    assert_eq!(e, Err(RemoteError::Unsignable));
}

#[tokio::test(flavor = "current_thread")]
async fn head_and_list_report_what_the_store_holds() {
    let w = World::new();
    assert_eq!(w.remote.head(&w.clock, "m/art/x_1").await, Ok(None));
    for i in 0..5 {
        w.e2.set(&format!("m/art/x_{i}"), &[i; 3]);
    }
    w.e2.set("rs/main/00000000000000000001", b"1");
    let head = w.remote.head(&w.clock, "m/art/x_2").await.unwrap().unwrap();
    assert_eq!((head.size, head.etag), (3, md5_hex(&[2; 3])));

    w.e2.page.set(2);
    let page = w.remote.list(&w.clock, "m/", "").await.unwrap();
    assert!(page.truncated);
    let keys: Vec<_> = page.objects.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["m/art/x_0", "m/art/x_1"]);
    w.e2.page.set(0);
    let page = w.remote.list(&w.clock, "m/", "m/art/x_2").await.unwrap();
    assert!(!page.truncated);
    let keys: Vec<_> = page.objects.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["m/art/x_3", "m/art/x_4"]);

    // Every character a key may have can be put and read back.
    let wide = "m/art/A-b_c.d~0";
    w.remote.put(&w.clock, wide, b"wide").await.unwrap();
    let head = w.remote.head(&w.clock, wide).await.unwrap().unwrap();
    assert_eq!((head.size, head.etag), (4, md5_hex(b"wide")));
    assert_eq!(w.e2.get(wide).unwrap(), b"wide");
}

#[tokio::test(flavor = "current_thread")]
async fn e2_authorization_never_logged() {
    struct Spy(RefCell<Vec<String>>);
    impl HttpSend for &Spy {
        async fn send(&self, request: &HttpRequest) -> Sent {
            assert!(request.headers.iter().any(|(n, _)| n == "authorization"));
            self.0.borrow_mut().push(format!("{request:?}"));
            Err(NoAnswer)
        }
        async fn pause(&self, _: u64) {}
    }
    let spy: &'static Spy = Box::leak(Box::new(Spy(RefCell::new(vec![]))));
    let cfg = RemoteConfig::from_vars(vars).unwrap().unwrap();
    let shown = format!("{cfg:?}");
    assert_eq!(shown.matches("<redacted>").count(), 2, "{shown}");
    let remote = S3Remote::new(cfg, spy);
    let clock = FixedClock::new(UnixMs(NOW));
    let e = remote.put(&clock, "m/art/x_1", b"body").await.unwrap_err();
    let mut shown = format!("{shown} {e:?} {:?}", spy.0.borrow());
    shown.make_ascii_lowercase();
    assert!(shown.contains("put https://e2.test/records/drill-1/m/art/x_1"));
    // An answer: the error text of a store can name the access key.
    let answer = HttpResponse {
        status: 403,
        headers: vec![("x-key".into(), ACCESS_KEY.into())],
        body: format!("<AWSAccessKeyId>{ACCESS_KEY}</AWSAccessKeyId>").into_bytes(),
    };
    assert_eq!(format!("{answer:?}"), "403 (53 bytes)");
    let access_key = ACCESS_KEY.to_ascii_lowercase();
    // A failure names the place in this list only: the message of a
    // failed test is a log too.
    let hidden = [SECRET_KEY, &access_key, "signature", "aws4", "credential"];
    for (at, text) in hidden.iter().enumerate() {
        assert!(!shown.contains(text), "text {at} of the list is shown");
    }
}

#[test]
fn config_is_off_unless_asked_and_refuses_what_is_unsafe() {
    assert!(RemoteConfig::from_vars(|_| None).unwrap().is_none());
    let with = |name: &'static str, value: Option<&'static str>| {
        RemoteConfig::from_vars(move |n| {
            if n == name {
                value.map(str::to_string)
            } else {
                vars(n)
            }
        })
    };
    assert!(with("RECOVERY_COPY", Some("off")).unwrap().is_none());
    assert!(with("RECOVERY_COPY", Some("yes")).is_err());
    let cfg = with("E2_ENDPOINT", Some("https://e2.test/")).unwrap();
    assert_eq!(cfg.unwrap().host, "e2.test");
    for (name, value) in [
        ("E2_ENDPOINT", "http://e2.test"),
        ("E2_ENDPOINT", "https://e2.test/path"),
        // What a URL parser would rewrite, so that another request is
        // sent than was signed.
        ("E2_ENDPOINT", "https://e2.test:443"),
        ("E2_ENDPOINT", "https://e2.test:8443"),
        ("E2_ENDPOINT", "https://e2..test"),
        ("E2_ENDPOINT", "https://.e2.test"),
        ("E2_BUCKET", "."),
        ("E2_BUCKET", ".."),
        ("E2_BUCKET", "a..b"),
        ("E2_BUCKET", "-records"),
        ("E2_ENDPOINT", "https://user@e2.test"),
        // What a URL parser reads as an address, or a name with no dot.
        ("E2_ENDPOINT", "https://1.2.3"),
        ("E2_ENDPOINT", "https://0x7f.1"),
        ("E2_ENDPOINT", "https://2130706433"),
        ("E2_ENDPOINT", "https://127.0.0.1"),
        ("E2_ENDPOINT", "https://localhost"),
        ("E2_ENDPOINT", "https://e2.t3st"),
        ("E2_ENDPOINT", "https://e2.test."),
        ("E2_ENDPOINT", "https://E2.test"),
        ("E2_REGION", "-"),
        ("E2_REGION", "us-"),
        ("E2_REGION", "us.west"),
        ("E2_REGION", "us west"),
        ("E2_BUCKET", "Records/x"),
        ("RECOVERY_PREFIX", "drill"),
        ("RECOVERY_PREFIX", "/drill/"),
        ("RECOVERY_PREFIX", "dr ill/"),
        ("RECOVERY_PREFIX", "a//"),
        ("RECOVERY_PREFIX", "a//b/"),
        ("RECOVERY_PREFIX", "a/../b/"),
        ("RECOVERY_PREFIX", "/"),
        ("E2_ACCESS_KEY", "AK/1"),
    ] {
        assert_eq!(
            with(name, Some(value)).unwrap_err(),
            ConfigError::Invalid(name.into())
        );
    }
    for name in [
        "E2_ENDPOINT",
        "E2_REGION",
        "E2_BUCKET",
        "E2_ACCESS_KEY",
        "E2_SECRET_KEY",
        "RECOVERY_PREFIX",
    ] {
        assert_eq!(
            with(name, None).unwrap_err(),
            ConfigError::Missing(name.into())
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn each_try_is_signed_anew_and_the_pauses_grow() {
    // The store refuses a date two seconds old, and the pauses before
    // the fourth try are more than five seconds: it is signed for the
    // time at which it is sent.
    let w = World::new();
    w.e2.put_500.set(3);
    w.remote.put(&w.clock, "m/art/x_1", b"body").await.unwrap();
    assert_eq!(w.e2.puts(), 4);
    // 200, 800 and 3200 ms, each with its part of up to half as much.
    assert_eq!(*w.e2.pauses.borrow(), [222, 967, 4675]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_put_counts_only_after_a_head_showed_the_same_bytes() {
    let w = World::new();
    w.remote.put(&w.clock, "m/art/x_1", b"body").await.unwrap();
    assert_eq!(*w.e2.log.borrow(), ["PUT m/art/x_1", "HEAD m/art/x_1"]);

    // The store took the put and holds other bytes.
    w.e2.damage_puts.set(true);
    let e = w.remote.put(&w.clock, "m/art/x_2", b"body").await;
    assert_eq!(e, Err(RemoteError::Mismatch));
    w.e2.damage_puts.set(false);

    let md5 = md5_hex(b"body");
    let quoted = format!("\"{md5}\"");
    let upper = quoted.to_ascii_uppercase();
    // The ETag may be quoted or not, in either case.
    for etag in [&md5, &quoted, &upper] {
        *w.e2.head_answer.borrow_mut() = Some(head_of("4", etag));
        assert_eq!(w.remote.put(&w.clock, "m/art/x_3", b"body").await, Ok(()));
    }
    let other = format!("\"{}\"", md5_hex(b"bodx"));
    let mut no_etag = head_of("4", &quoted);
    no_etag.headers.pop();
    let mut no_size = head_of("4", &quoted);
    no_size.headers.remove(0);
    for (what, wrong) in [
        ("another size", head_of("5", &quoted)),
        ("another ETag", head_of("4", &other)),
        ("an empty ETag", head_of("4", "")),
        ("a size that is no number", head_of("4 ", &quoted)),
        ("a negative size", head_of("-4", &quoted)),
        ("no ETag", no_etag.clone()),
        ("no size", no_size.clone()),
        (
            "no object",
            HttpResponse {
                status: 404,
                ..HttpResponse::default()
            },
        ),
    ] {
        let before = w.e2.count("HEAD ");
        *w.e2.head_answer.borrow_mut() = Some(wrong);
        let e = w.remote.put(&w.clock, "m/art/x_3", b"body").await;
        assert_eq!(e, Err(RemoteError::Mismatch), "{what}");
        assert_eq!(w.e2.count("HEAD "), before + 1, "{what}");
    }
    // A HEAD of its own that lacks either is no answer about the copy.
    for wrong in [no_etag, no_size] {
        *w.e2.head_answer.borrow_mut() = Some(wrong);
        let e = w.remote.head(&w.clock, "m/art/x_3").await;
        assert_eq!(e, Err(RemoteError::Mismatch));
    }
    assert!(w.e2.pauses.borrow().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_list_answer_is_checked_against_what_was_asked() {
    let w = World::new();
    let own = "drill-1/";
    let token = "<NextContinuationToken>t</NextContinuationToken>";
    // The last page, unless the case says otherwise.
    let set = |mut inner: String| {
        if !inner.contains("<IsTruncated>") {
            inner.insert_str(0, "<IsTruncated>false</IsTruncated>");
        }
        *w.e2.list_inner.borrow_mut() = Some(inner);
    };
    let k = |key: &str| contents(&format!("{own}{key}"));

    // In order, inside the prefix, after the start: accepted.
    set(format!(
        "<IsTruncated>true</IsTruncated>{}{}",
        k("m/b"),
        k("m/c.D-e~f_0")
    ));
    let page = w.remote.list(&w.clock, "m/", "m/a").await.unwrap();
    let keys: Vec<_> = page.objects.iter().map(|o| o.key.as_str()).collect();
    // Every character a key may have is accepted.
    assert_eq!(keys, ["m/b", "m/c.D-e~f_0"]);
    assert!(page.truncated);

    for (what, after, inner, kind) in [
        (
            "outside the store prefix",
            "",
            contents("other/m/a"),
            RemoteError::Mismatch,
        ),
        (
            "the bucket root",
            "",
            contents("m/a"),
            RemoteError::Mismatch,
        ),
        (
            "outside the prefix asked for",
            "",
            k("rs/a"),
            RemoteError::Mismatch,
        ),
        (
            "out of order",
            "",
            k("m/b") + &k("m/a"),
            RemoteError::Mismatch,
        ),
        (
            "a key twice",
            "",
            k("m/a") + &k("m/a"),
            RemoteError::Mismatch,
        ),
        ("the start itself", "m/b", k("m/b"), RemoteError::Mismatch),
        (
            "a key longer than a store may have",
            "",
            k(&format!("m/{}", "a".repeat(1024 - own.len() - 1))),
            RemoteError::Mismatch,
        ),
        ("before the start", "m/b", k("m/a"), RemoteError::Mismatch),
        (
            "a foreign key out of order",
            "",
            k("m/b b") + &k("m/a"),
            RemoteError::Mismatch,
        ),
        (
            "a foreign key outside the prefix",
            "",
            k("rs/a b"),
            RemoteError::Mismatch,
        ),
        (
            "more to come and no key",
            "",
            format!("<IsTruncated>true</IsTruncated>{token}"),
            RemoteError::Mismatch,
        ),
        (
            "more to come and the folder object only",
            "",
            format!("<IsTruncated>true</IsTruncated>{token}{}", contents(own)),
            RemoteError::Mismatch,
        ),
        (
            "no listing",
            "",
            "<Contents>".to_string(),
            RemoteError::Mismatch,
        ),
    ] {
        set(inner);
        let e = w.remote.list(&w.clock, "m/", after).await;
        assert_eq!(e.err(), Some(kind), "{what}");
    }

    // A key this module would not sign was written by something else:
    // it is given apart, never as a copy, and the listing goes on.
    for key in [
        "m/../a",
        "m/./a",
        "m//a",
        "m/a/",
        "m/a b",
        "m/%2e%2e/x",
        "m/a?x#y",
        "m/a\\..\\b",
        "m/\u{e9}\u{202e}",
    ] {
        set(format!("<IsTruncated>true</IsTruncated>{}", k(key)));
        let page = w.remote.list(&w.clock, "m/", "").await.unwrap();
        assert!(page.objects.is_empty(), "{key}");
        assert_eq!(page.foreign, [key]);
        // The caller goes on from it.
        assert_eq!(page.last.as_deref(), Some(key));
        assert!(page.truncated);
    }
    // The longest key a store may have is accepted.
    let longest = format!("m/{}", "a".repeat(1024 - own.len() - 2));
    set(k(&longest));
    let page = w.remote.list(&w.clock, "m/", "").await.unwrap();
    assert_eq!(page.last, Some(longest));
    set(k("m/a") + &k("m/a b") + &k("m/b"));
    let page = w.remote.list(&w.clock, "m/", "").await.unwrap();
    let keys: Vec<_> = page.objects.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["m/a", "m/b"]);
    assert_eq!(page.foreign, ["m/a b"]);
    assert_eq!(page.last.as_deref(), Some("m/b"));

    // An object that is the store prefix itself (a folder made in a
    // console) is no copy: it is left out and the listing goes on.
    set(contents(own) + &k("m/a"));
    let page = w.remote.list(&w.clock, "", "").await.unwrap();
    let keys: Vec<_> = page.objects.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["m/a"]);
    set(contents(own));
    let page = w.remote.list(&w.clock, "", "").await.unwrap();
    assert!(page.objects.is_empty() && !page.truncated);
    assert_eq!((page.foreign.len(), page.last), (0, None));

    // No bucket.
    w.e2.status.set(Some(404));
    let e = w.remote.list(&w.clock, "m/", "").await;
    assert_eq!(e.err(), Some(RemoteError::Refused(404)));
    assert!(w.e2.pauses.borrow().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn only_what_a_retry_can_help_is_tried_again() {
    // Neither a 2xx nor a 5xx nor a 429: refused at once. A redirect is
    // among them; it is never followed.
    for status in [
        100, 199, 300, 301, 302, 304, 307, 308, 400, 403, 428, 430, 499, 600,
    ] {
        let w = World::new();
        w.e2.status.set(Some(status));
        let refused = Some(RemoteError::Refused(status));
        assert_eq!(w.remote.head(&w.clock, "m/a").await.err(), refused);
        assert_eq!(w.remote.list(&w.clock, "m/", "").await.err(), refused);
        assert_eq!(w.remote.put(&w.clock, "m/a", b"1").await.err(), refused);
        assert_eq!(w.e2.log.borrow().len(), 3, "{status}");
        assert!(w.e2.pauses.borrow().is_empty(), "{status}");
    }
    for status in [429, 500, 503, 599] {
        let w = World::new();
        w.e2.status.set(Some(status));
        let gone = Some(RemoteError::Unavailable);
        assert_eq!(w.remote.head(&w.clock, "m/a").await.err(), gone);
        assert_eq!(w.e2.log.borrow().len(), 4, "{status}");
        assert_eq!(w.e2.pauses.borrow().len(), 3, "{status}");
    }
    // A 2xx is an answer, and so is a 404 to a HEAD.
    for status in [200, 204, 299] {
        let w = World::new();
        w.e2.status.set(Some(status));
        let e = w.remote.head(&w.clock, "m/a").await;
        assert_eq!(e.err(), Some(RemoteError::Mismatch), "{status}");
        assert_eq!(w.e2.log.borrow().len(), 1);
    }
    let w = World::new();
    w.e2.status.set(Some(404));
    assert_eq!(w.remote.head(&w.clock, "m/a").await, Ok(None));
    assert_eq!(w.e2.log.borrow().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn an_answer_longer_than_was_asked_for_is_no_answer() {
    let w = World::new();
    w.e2.set("m/a", b"1");
    // Once: tried again.
    w.e2.long_next.set(1);
    let head = w.remote.head(&w.clock, "m/a").await.unwrap().unwrap();
    assert_eq!(head.size, 1);
    assert_eq!(*w.e2.log.borrow(), ["HEAD m/a", "HEAD m/a"]);
    assert_eq!(w.e2.pauses.borrow().len(), 1);
    // As long as was asked for, and no longer: an answer.
    let mut full = head_of("1", &md5_hex(b"1"));
    full.body = vec![b' '; MAX_ANSWER_BYTES];
    *w.e2.head_answer.borrow_mut() = Some(full);
    assert!(w.remote.head(&w.clock, "m/a").await.unwrap().is_some());
    assert_eq!(w.e2.pauses.borrow().len(), 1);
    // Every time: no answer. A list is bounded as well.
    w.e2.long_next.set(4);
    let e = w.remote.list(&w.clock, "m/", "").await;
    assert_eq!(e.err(), Some(RemoteError::Unavailable));
    assert_eq!(w.e2.count("GET "), 4);
    w.e2.long_next.set(4);
    let e = w.remote.put(&w.clock, "m/b", b"1").await;
    assert_eq!(e, Err(RemoteError::Unavailable));
    assert!(w.e2.get("m/b").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn a_key_that_could_leave_the_prefix_is_never_sent() {
    let w = World::new();
    for key in [
        "",
        ".",
        "..",
        "../x",
        "./x",
        "/abs",
        "a//b",
        "a/",
        "a/.",
        "a/..",
        "a/../b",
        "a/./b",
        "m/../../x",
        "/",
    ] {
        let e = w.remote.put(&w.clock, key, b"body").await;
        assert_eq!(e, Err(RemoteError::Unsignable), "put {key:?}");
        let e = w.remote.head(&w.clock, key).await;
        assert_eq!(e, Err(RemoteError::Unsignable), "head {key:?}");
    }
    assert!(w.e2.log.borrow().is_empty());
    // A dot inside a name is no segment of dots.
    w.remote
        .put(&w.clock, "m/..x/.y/z..", b"body")
        .await
        .unwrap();
    assert_eq!(w.e2.get("m/..x/.y/z..").unwrap(), b"body");
}

// ---------------------------------------------------------------------------
// The listing with sizes, as every store has it by default
// ---------------------------------------------------------------------------

/// A store whose listing still names keys that are gone.
struct Shelf {
    inner: MemBlobStore,
    gone: Vec<&'static str>,
    lists: Cell<u32>,
}

impl BlobStore for Shelf {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.inner.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        if self.gone.contains(&key) {
            return Ok(None);
        }
        self.inner.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.inner.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn delete_record(&self, refused: &recovery::Unpublished) -> Result<()> {
        self.inner.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.lists.set(self.lists.get() + 1);
        self.inner.list(prefix, start_after, limit).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn default_listing_with_sizes_ends_only_on_an_empty_answer() {
    let mut shelf = Shelf {
        inner: MemBlobStore::new(),
        gone: vec![],
        lists: Cell::new(0),
    };
    let (bucket, extent) = (BucketId::new("b"), ExtentId::new("e"));
    for (key, bytes) in [("m/a", "1"), ("m/b", "22"), ("m/c", "333"), ("x/d", "4")] {
        let meta = BlobMeta {
            bucket: &bucket,
            extent: &extent,
            cipher_sha256: &Sha256::digest(bytes).into(),
        };
        shelf.inner.put(key, bytes.into(), &meta).await.unwrap();
    }
    let entry = |key: &str, bytes: &str| BlobEntry {
        key: key.into(),
        size: bytes.len() as u64,
        md5: md5_hex(bytes.as_bytes()),
    };
    let page = shelf.list_entries("m/", "", 2).await.unwrap();
    assert_eq!(page, [entry("m/a", "1"), entry("m/b", "22")]);
    let page = shelf.list_entries("m/", "m/b", 2).await.unwrap();
    assert_eq!(page, [entry("m/c", "333")]);
    assert!(shelf.list_entries("m/", "m/c", 2).await.unwrap().is_empty());
    // A limit of 0 is read as 1: it cannot look like the end.
    let page = shelf.list_entries("m/", "", 0).await.unwrap();
    assert_eq!(page, [entry("m/a", "1")]);

    // Keys that went away after they were listed are left out, and the
    // answer is not empty while later keys exist.
    shelf.gone = vec!["m/a", "m/b"];
    shelf.lists.set(0);
    let page = shelf.list_entries("m/", "", 1).await.unwrap();
    assert_eq!(page, [entry("m/c", "333")]);
    assert_eq!(shelf.lists.get(), 3);
    let page = shelf.list_entries("m/", "", 2).await.unwrap();
    assert_eq!(page, [entry("m/c", "333")]);
    shelf.gone.push("m/c");
    assert!(shelf.list_entries("m/", "", 2).await.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// The pass
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn pass_copies_every_record_kind_byte_equal() {
    let w = World::new();
    let keys = [
        generation(OLD, "aaaa"),
        format!("m/del/g_{:013x}bbbb", NOW - OLD),
        "m/art/x_00112233".to_string(),
    ];
    let mut bytes = 0;
    for key in &keys {
        bytes += w.record(key, key.as_bytes()).await.len() as u64;
    }
    let counts = w.pass().await;
    assert_eq!((counts.records, counts.copied, counts.bytes), (3, 3, bytes));
    assert!(counts.clean());
    for key in &keys {
        assert_eq!(w.e2.get(key), Some(w.safety.stored(key).unwrap().bytes));
    }
    assert_eq!(w.e2.objects.borrow().len(), 3);
}

/// Neither a tenant key nor its name leaves: where the source page ends
/// in tenant keys, the store is asked for what follows all of them.
#[tokio::test(flavor = "current_thread")]
async fn pass_never_copies_tenant_keys() {
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    w.record("m/tk/t_1", b"tenant key").await;
    w.record("m/tk/t_2", b"tenant key").await;
    let counts = w.pass().await;
    assert_eq!((counts.records, counts.copied), (1, 1));
    let there: Vec<String> = w.e2.objects.borrow().keys().cloned().collect();
    assert_eq!(there, ["m/art/x_1"]);
    assert_eq!(w.e2.count("PUT m/tk/"), 0);
    // The fresh sweep goes to the end of the keys, so it is the part
    // of a pass that meets them.
    assert!(w.e2.asked.borrow().iter().any(|a| a == "m/tk0"));

    // A record behind the tenant keys is still reached, and a job that
    // stops among them goes on without naming one.
    w.record("m/x_9", b"plan").await;
    let (_, counts, why) = w
        .copier()
        .run_job(&w.jobs, UnixMs(NOW), &sweep("m/tk0"))
        .await;
    assert_eq!((counts.unwrap().copied, why), (1, None));
    assert!(w.e2.get("m/x_9").is_some());
    for line in w.e2.log.borrow().iter().chain(w.e2.asked.borrow().iter()) {
        assert!(!line.contains("m/tk/"), "{line}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pass_skips_generation_records_younger_than_two_minutes() {
    let w = World::new();
    let young = generation(MIN_AGE_MS - 1, "aaaa");
    let ahead = generation(-5_000, "bbbb");
    let old = generation(MIN_AGE_MS, "cccc");
    for key in [&young, &ahead, &old] {
        w.generation(key, &[]).await;
    }
    // The rule is for generation records only: only they are ever removed.
    w.record(&format!("m/del/g_{:013x}dddd", NOW), b"t").await;
    w.record("m/art/x_1", b"a").await;
    let counts = w.pass().await;
    assert_eq!((counts.young, counts.copied), (2, 3));
    assert!(w.e2.get(&young).is_none() && w.e2.get(&ahead).is_none());

    // The record of a refused publication is removed in its own
    // request: it is gone before it is old enough, and never copied.
    w.safety.lose(&young);
    w.clock.advance_ms(MIN_AGE_MS + 5_000);
    let counts = w.pass().await;
    assert_eq!((counts.young, counts.copied, counts.extra), (0, 1, 0));
    assert!(w.e2.get(&young).is_none() && w.e2.get(&ahead).is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn pass_is_idempotent_second_pass_copies_nothing() {
    let w = World::new();
    for i in 0..7 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    assert_eq!(w.pass().await.copied, 7);
    let (puts, gets) = (w.e2.puts(), w.safety.gets());
    let lists = w.e2.count("GET ");
    let counts = w.pass().await;
    assert_eq!((counts.copied, counts.same, counts.records), (0, 7, 7));
    assert_eq!(w.e2.puts(), puts);
    // Ten list requests: the range of the source page and what
    // follows it, and one for each of the eight parts of a pass that
    // find no record (three of the flat layout, five of the tenant
    // layout and what follows it). An answer that is not cut is the
    // last one.
    assert_eq!(w.e2.count("GET "), lists + 10);
    assert_eq!(w.e2.count("HEAD "), 7);
    // MemBlobStore lists by reading (the port's default). What is
    // saved of the walk is asked for by its size first, and nothing of
    // it is there (this pass saves none): no read of it.
    assert_eq!(w.safety.gets(), gets + 7);
}

#[tokio::test(flavor = "current_thread")]
async fn pass_recopies_a_record_whose_md5_changed() {
    let w = World::new();
    let first = w.record("m/art/x_1", b"plan").await;
    w.pass().await;
    // The same plan sealed again: same size, a new nonce.
    let second = w.record("m/art/x_1", b"plan").await;
    assert_eq!(first.len(), second.len());
    assert_ne!(first, second);
    let counts = w.pass().await;
    assert_eq!(counts.copied, 1);
    assert_eq!(w.e2.get("m/art/x_1").unwrap(), second);
}

#[tokio::test(flavor = "current_thread")]
async fn pass_repairs_a_damaged_copy_at_e2() {
    let w = World::new();
    let sealed = w.record("m/art/x_1", b"plan").await;
    let other = w.record("m/art/x_2", b"plan").await;
    w.pass().await;
    let mut damaged = sealed.clone();
    damaged[9] ^= 0x40;
    w.e2.set("m/art/x_1", &damaged);
    w.e2.objects.borrow_mut().remove("m/art/x_2");
    let counts = w.pass().await;
    assert_eq!((counts.copied, counts.same), (2, 0));
    assert_eq!(w.e2.get("m/art/x_1").unwrap(), sealed);
    assert_eq!(w.e2.get("m/art/x_2").unwrap(), other);
}

#[tokio::test(flavor = "current_thread")]
async fn pass_keeps_good_copy_when_source_no_longer_opens() {
    let w = World::new();
    let good = w.record("m/art/x_1", b"plan").await;
    w.pass().await;
    assert!(w.safety.corrupt("m/art/x_1", |b| b[12] ^= 1));
    // A record under another name, and one that was never a record.
    let moved = seal_manifest(&w.kek, "m/art/x_other", b"plan", &mut SystemRng).unwrap();
    w.raw("m/art/x_2", moved).await;
    w.raw("m/art/x_3", b"not sealed".to_vec()).await;
    let puts = w.e2.puts();
    let counts = w.pass().await;
    assert_eq!((counts.source_unreadable, counts.copied), (3, 0));
    // Unreadable is not a failure of the copy, but it is named.
    assert!(counts.clean());
    assert_eq!(w.e2.puts(), puts);
    assert_eq!(w.e2.get("m/art/x_1").unwrap(), good);
    assert_eq!(w.e2.objects.borrow().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn pass_never_deletes_extra_at_e2_and_counts_it() {
    let w = World::new();
    w.record("m/art/x_3", b"plan").await;
    w.record("m/art/x_5", b"plan").await;
    // Before, between and after the source keys.
    for key in ["m/art/x_1", "m/art/x_4", "m/g_zzzz"] {
        w.e2.set(key, b"left over");
    }
    // Outside `m/`: not this pass's business, and not counted.
    w.e2.set("hb", b"1");
    let counts = w.pass().await;
    assert_eq!((counts.copied, counts.extra), (2, 3));
    for key in ["m/art/x_1", "m/art/x_4", "m/g_zzzz", "hb"] {
        assert!(w.e2.get(key).is_some());
    }
    assert_eq!(w.e2.objects.borrow().len(), 6);
    // No list request more than is needed: one for the range of the
    // source page, one for what follows it, which is not cut, and one
    // for each of the eight parts of a pass that find no record.
    assert_eq!(w.e2.count("GET "), 10);

    // The same when an answer is cut exactly at the end of the page.
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    w.record("m/art/x_2", b"plan").await;
    w.pass().await;
    w.e2.set("m/zz", b"left over");
    w.e2.page.set(2);
    let lists = w.e2.count("GET ");
    let counts = w.pass().await;
    assert_eq!((counts.same, counts.extra), (2, 1));
    assert_eq!(w.e2.count("GET "), lists + 10);
}

#[tokio::test(flavor = "current_thread")]
async fn pass_with_empty_safety_deletes_nothing_at_e2() {
    let w = World::new();
    for i in 0..5 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    w.pass().await;
    // The safety bucket is lost: this is the event the copy is for.
    for key in w.safety.keys() {
        w.safety.lose(&key);
    }
    w.e2.page.set(2);
    let counts = w.pass().await;
    assert_eq!((counts.records, counts.extra), (0, 5));
    assert_eq!(w.e2.objects.borrow().len(), 5);
    assert_eq!(w.e2.count("PUT "), 5);
}

#[tokio::test(flavor = "current_thread")]
async fn head_mismatch_after_put_counts_as_failed() {
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    w.e2.damage_puts.set(true);
    let counts = w.pass().await;
    assert_eq!((counts.failed, counts.copied), (1, 0));
    assert!(!counts.clean());
    // Not retried within the pass: the store answered. The next pass
    // sees a different MD5 and copies again.
    assert_eq!(w.e2.puts(), 1);
    w.e2.damage_puts.set(false);
    assert_eq!(w.pass().await.copied, 1);
    assert_eq!(
        w.e2.get("m/art/x_1"),
        Some(w.safety.stored("m/art/x_1").unwrap().bytes)
    );

    // A refusal is counted apart.
    w.record("m/art/x_2", b"plan").await;
    w.e2.put_status.set(Some(403));
    let counts = w.pass().await;
    assert_eq!((counts.refused, counts.failed), (1, 0));
    assert!(!counts.clean());
}

/// A job stops at its bound and names where the next one goes on; a job
/// that died is simply run again from the cursor it was sent with.
#[tokio::test(flavor = "current_thread")]
async fn pass_resumes_from_cursor_after_job_death() {
    let w = World::new();
    let n = JOB_COPIES + 30;
    for i in 0..n {
        w.record(&format!("m/art/x_{i:04}"), b"plan").await;
    }
    w.e2.page.set(100);
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(why, None);
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(counts.unwrap().copied as usize, JOB_COPIES);
    assert_eq!(w.e2.objects.borrow().len(), JOB_COPIES);

    // The chain: the job sent the next one, with its cursor.
    let sent = w.jobs.take();
    assert_eq!(sent.len(), 1);
    let Job::RecoveryCopy { pass, cursor, .. } = &sent[0].job else {
        panic!("{:?}", sent[0].job);
    };
    let last = format!("m/art/x_{:04}", JOB_COPIES - 1);
    assert_eq!((*pass, cursor), (UnixMs(NOW), &walk(&last)));

    // The second job dies after its work: its message comes again and
    // finds everything done. The last job of a pass sends none.
    let died = w.copier().step(UnixMs(NOW), cursor).await.unwrap();
    assert_eq!((died.counts.copied, died.next), (30, None));
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, *pass, cursor).await;
    assert_eq!(why, None);
    assert_eq!(outcome, JobOutcome::Ack);
    let counts = counts.unwrap();
    assert_eq!((counts.copied, counts.same), (0, 30));
    assert_eq!(w.e2.objects.borrow().len(), n);
    assert!(w.jobs.take().is_empty());

    // The message survives its queue: it is plain JSON.
    let job = Job::from_json(&sent[0].job.to_json()).unwrap();
    assert_eq!(job, sent[0].job);
}

/// The copier holds no catalogue port at all (see its fields), so no
/// state of the catalogue can stop or mislead a pass. Here: the cron
/// hook, the first job, and one start per interval.
#[tokio::test(flavor = "current_thread")]
async fn pass_needs_no_catalogue_and_starts_once_per_interval() {
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    w.record("rs/main/00000000000000000009", b"1").await;
    let slot = NOW - NOW % 900_000;
    assert!(pass_due(UnixMs(slot)));
    // The cron run was set for the slot and started late: the pass is
    // that of the slot.
    w.clock.set(UnixMs(slot + 400_000));
    assert!(w.copier().start_pass(&w.jobs, UnixMs(slot)).await.unwrap());
    let sent = w.jobs.take();
    let Job::RecoveryCopy { pass, cursor, .. } = &sent[0].job else {
        panic!("{:?}", sent[0].job);
    };
    assert_eq!(*pass, UnixMs(slot));
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, *pass, cursor).await;
    assert_eq!(why, None);
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(counts.unwrap().copied, 1);
    assert!(w.e2.get("m/art/x_1").is_some());
    assert!(w.e2.get("rs/main/00000000000000000009").is_none());

    // One start per interval: the two later cron runs send nothing.
    for minutes in [5, 10] {
        let at = UnixMs(slot + minutes * 60_000);
        assert!(!w.copier().start_pass(&w.jobs, at).await.unwrap());
    }
    let at = UnixMs(slot + 900_000);
    assert!(w.copier().start_pass(&w.jobs, at).await.unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn pass_does_not_run_in_maintenance_restore() {
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    let slot = UnixMs(NOW - NOW % 900_000);
    let mut copier = w.copier();
    copier.maintenance = Maintenance::Restore;
    assert!(!copier.start_pass(&w.jobs, slot).await.unwrap());
    let (outcome, counts, why) = copier.run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(why, None);
    assert_eq!((outcome, counts), (JobOutcome::Ack, None));
    assert!(w.jobs.take().is_empty());
    assert!(w.e2.log.borrow().is_empty());
}

/// The store is down: the job is retried with its cursor unmoved while
/// the pass is young. After that the pass goes on, and it ends when the
/// next pass has started.
#[tokio::test(flavor = "current_thread")]
async fn an_outage_retries_the_job_then_leaves_it_to_the_next_pass() {
    let w = World::new();
    for i in 0..4 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    w.e2.put_status.set(Some(500));
    let down = Some(StepError::Store(RemoteError::Unavailable));
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), &walk("")).await;
    assert_eq!(why, down);
    assert_eq!(outcome, JobOutcome::Retry { delay_secs: 60 });
    assert_eq!(counts.unwrap().failed, 4);
    assert!(w.jobs.take().is_empty());
    // The place of the walk does not move while the job may come again.
    assert_eq!(saved(&w).await, None);

    // A list request that gets no answer: the same, with no counts.
    w.e2.put_status.set(None);
    w.e2.drop_next.set(4);
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), &walk("")).await;
    assert_eq!(why, Some(StepError::Store(RemoteError::Unavailable)));
    assert_eq!(outcome, JobOutcome::Retry { delay_secs: 60 });
    assert_eq!(counts, None);
    assert_eq!(w.e2.puts(), 16);
    w.e2.put_status.set(Some(500));

    // To the last millisecond of the retry window. (The pauses between
    // tries have moved the clock.)
    w.clock.set(UnixMs(NOW + RETRY_WINDOW_MS - 1));
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), &walk("")).await;
    assert_eq!(why, down);
    assert_eq!(outcome, JobOutcome::Retry { delay_secs: 60 });
    assert_eq!(counts.unwrap().failed, 4);
    assert!(w.jobs.take().is_empty());

    // Past the retry window the job is not retried; the pass goes on.
    w.clock.set(UnixMs(NOW + RETRY_WINDOW_MS));
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), &walk("")).await;
    assert_eq!(why, None);
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(counts.unwrap().failed, 4);
    let sent = w.jobs.take();
    assert!(
        matches!(&sent[0].job, Job::RecoveryCopy { cursor, .. } if *cursor == walk("m/art/x_3")),
        "{:?}",
        sent[0].job
    );

    // A step that fails is not retried any more either, and says why.
    w.e2.drop_next.set(4);
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), &walk("")).await;
    assert_eq!((outcome, counts, why), (JobOutcome::Ack, None, down));
    assert!(w.jobs.take().is_empty());

    // To the last millisecond of its interval the pass still works.
    w.clock.set(UnixMs(NOW + PASS_INTERVAL_MS - 1));
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), &walk("")).await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!(counts.unwrap().failed, 4);
    assert_eq!(w.jobs.take().len(), 1);

    // The next pass has started: a job of this one does nothing more.
    // A job of the fresh sweep says that it left work undone. One of
    // the walk does not: the next pass goes on from the saved place.
    w.clock.set(UnixMs(NOW + PASS_INTERVAL_MS));
    let before = w.e2.log.borrow().len();
    for (cursor, late) in [
        (String::new(), Some(StepError::Expired)),
        (sweep("m/g_1"), Some(StepError::Expired)),
        (
            "{\"p\":\"d\",\"k\":\"m/del/g_1\"}".to_string(),
            Some(StepError::Expired),
        ),
        ("not a cursor".to_string(), Some(StepError::Expired)),
        (walk("m/art/x_1"), None),
        ("{\"p\":\"b\",\"k\":\"m/del0\"}".to_string(), None),
    ] {
        let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), &cursor).await;
        assert_eq!(why, late, "{cursor}");
        assert_eq!((outcome, counts), (JobOutcome::Ack, None));
    }
    assert!(w.jobs.take().is_empty());
    assert_eq!(w.e2.log.borrow().len(), before);
    w.safety.lose(WALK_KEY);

    w.e2.put_status.set(None);
    assert_eq!(w.pass().await.copied, 4);
}

/// What something else wrote under the prefix (a note, a folder made
/// in a console) is counted and passed: the records before and behind
/// it are copied, and it is left as it is.
#[tokio::test(flavor = "current_thread")]
async fn a_key_written_by_something_else_is_counted_and_passed() {
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    w.record("m/art/x_3", b"plan").await;
    let foreign = ["m/art/", "m/art/note 1.txt", "m/art/x_2/", "m/zz zz"];
    for key in foreign {
        w.e2.set(key, b"note");
    }
    // One key per answer: the listing goes on from each of them.
    w.e2.page.set(1);
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    let counts = counts.unwrap();
    assert_eq!(
        (counts.records, counts.copied, counts.foreign, counts.extra),
        (2, 2, 4, 0)
    );
    assert!(counts.clean());
    assert!(w.jobs.take().is_empty());
    // The next walk, a day later.
    w.clock.advance_ms(WALK_INTERVAL_MS);
    let total = w.pass().await;
    assert_eq!(
        (total.same, total.copied, total.foreign, total.extra),
        (2, 0, 4, 0)
    );
    for key in foreign {
        assert_eq!(w.e2.get(key).unwrap(), b"note", "{key}");
        // No request ever named it.
        let log = w.e2.log.borrow();
        assert!(
            !log.iter().any(|l| l.ends_with(&format!(" {key}"))),
            "{key}"
        );
    }
    assert_eq!(w.e2.objects.borrow().len(), 6);
    assert_eq!(w.e2.puts(), 2);
}

/// A queue that takes no job.
struct NoQueue;
impl JobSink for NoQueue {
    async fn send(&self, _: &Job, _: u32) -> Result<()> {
        Err(BridgeError::Queue("down".into()))
    }
    async fn send_many(&self, _: &[Job]) -> Result<()> {
        Err(BridgeError::Queue("down".into()))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_next_job_that_cannot_be_sent_is_retried_and_reported() {
    let w = World::new();
    for i in 0..=JOB_COPIES {
        w.record(&format!("m/art/x_{i:04}"), b"plan").await;
    }
    // The step is done and the pass has more to do, but the job for the
    // next step is not taken: this job comes again, and says why.
    let (outcome, counts, why) = w.copier().run_job(&NoQueue, UnixMs(NOW), &walk("")).await;
    assert_eq!(outcome, JobOutcome::Retry { delay_secs: 60 });
    assert_eq!(counts.unwrap().copied as usize, JOB_COPIES);
    assert_eq!(why, Some(StepError::Queue));
    // Past the retry window it is acknowledged; the reason stays.
    w.clock.advance_ms(10 * 60 * 1000);
    w.e2.objects.borrow_mut().clear();
    let (outcome, counts, why) = w.copier().run_job(&NoQueue, UnixMs(NOW), &walk("")).await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(counts.unwrap().copied as usize, JOB_COPIES);
    assert_eq!(why, Some(StepError::Queue));
    // The start of a pass that cannot be sent is an error of the cron.
    let start = w.copier().start_pass(&NoQueue, UnixMs(0)).await;
    assert!(matches!(start, Err(BridgeError::Queue(_))));
}

/// Records that fail every time (here two, among others that copy) are
/// counted and passed: every record behind them is still copied, in the
/// same job, with no retry of the job.
#[tokio::test(flavor = "current_thread")]
async fn a_record_that_always_fails_does_not_hold_back_the_others() {
    let w = World::new();
    for i in 0..20 {
        w.record(&format!("m/art/x_{i:02}"), b"plan").await;
    }
    *w.e2.put_500_keys.borrow_mut() = vec!["m/art/x_00".into(), "m/art/x_07".into()];
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(why, None);
    let counts = counts.unwrap();
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!((counts.copied, counts.failed), (18, 2));
    assert!(!counts.clean());
    assert!(w.e2.get("m/art/x_19").is_some());

    // Alone in its job (the steady state: everything else is copied),
    // one failing record is not taken for an outage either. The walk
    // comes again soon, because of what the last one left undone.
    w.clock.advance_ms(WALK_SOON_MS);
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, w.clock.now(), "").await;
    assert_eq!(why, None);
    let counts = counts.unwrap();
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!((counts.same, counts.failed), (18, 2));
}

/// A clock that moves by a second each time it is read.
/// It moves the clock of the store with it, so a request is checked
/// at the time it was signed for.
struct TickClock(FixedClock);
impl Clock for TickClock {
    fn now(&self) -> UnixMs {
        self.0.advance_ms(1_000);
        self.0.now()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_job_stops_at_its_time_bound_and_the_next_goes_on() {
    let w = World::new();
    for i in 0..40 {
        w.record(&format!("m/art/x_{i:02}"), b"plan").await;
    }
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    // Every request reads the clock, so a few groups of copies take
    // the job past its 20 seconds: it stops after a whole group, with
    // the cursor at the last record of that group.
    let first = copier.step(UnixMs(NOW), &walk("")).await.unwrap();
    let copied = first.counts.copied as usize;
    assert!(
        copied > 0 && copied < 40 && copied.is_multiple_of(6),
        "{copied}"
    );
    assert_eq!(
        first.next,
        Some(walk(&format!("m/art/x_{:02}", copied - 1)))
    );
    assert_eq!(w.e2.objects.borrow().len(), copied);
    let mut jobs = 1;
    let mut cursor = first.next;
    while let Some(at) = cursor {
        cursor = copier.step(UnixMs(NOW), &at).await.unwrap().next;
        jobs += 1;
    }
    assert!(jobs >= 3, "{jobs}");
    assert_eq!(w.e2.objects.borrow().len(), 40);
}

/// A source of several pages against a store that answers 100 keys at a
/// time, so that the store's listing is cut inside every source page.
#[tokio::test(flavor = "current_thread")]
async fn pass_walks_a_source_of_several_pages() {
    let w = World::new();
    let n = 2_300;
    for i in 0..n {
        w.record(&format!("m/art/x_{i:05}"), b"p").await;
    }
    w.e2.page.set(100);
    let first = w.pass().await;
    assert_eq!((first.records, first.copied, first.extra), (n, n, 0));
    let second = w.pass().await;
    assert_eq!((second.records, second.same, second.copied), (n, n, 0));
    assert_eq!(w.e2.objects.borrow().len(), n as usize);

    // One copy lost in the middle is found and put back.
    w.e2.objects.borrow_mut().remove("m/art/x_01234");
    let third = w.pass().await;
    assert_eq!((third.same, third.copied), (n - 1, 1));
}

/// The store holds thousands of keys that the source lacks, before the
/// source's only record. One job lists a bounded part of them; the pass
/// still reaches the record, and counts the rest.
#[tokio::test(flavor = "current_thread")]
async fn a_store_far_larger_than_the_source_is_listed_in_bounded_parts() {
    let w = World::new();
    for i in 0..5_000 {
        w.e2.set(&format!("m/art/x_{i:05}"), b"old");
    }
    let key = "m/art/y_1";
    w.record(key, b"plan").await;
    w.e2.page.set(10);

    // 40 rounds of at most 10 list requests, 10 keys each: the job ends
    // 4,000 keys in, and the next one goes on from there.
    let first = w.copier().step(UnixMs(NOW), &walk("")).await.unwrap();
    assert_eq!(w.e2.count("GET "), 400);
    assert_eq!(first.next, Some(walk("m/art/x_03999")));
    assert_eq!((first.counts.copied, first.counts.extra), (0, 4_000));

    let w2 = World::new();
    for i in 0..5_000 {
        w2.e2.set(&format!("m/art/x_{i:05}"), b"old");
    }
    w2.record(key, b"plan").await;
    w2.e2.page.set(100);
    let total = w2.pass().await;
    assert_eq!((total.records, total.copied, total.extra), (1, 1, 5_000));
    assert_eq!(w2.e2.objects.borrow().len(), 5_001);
}

/// The store holds more keys inside one source page than a job lists
/// for it, at seven keys an answer: the page ends at the last key
/// listed, which here is a source record whose copy is damaged. Every
/// record is looked at exactly once, on either side of each cut.
#[tokio::test(flavor = "current_thread")]
async fn a_source_page_cut_by_the_store_listing_loses_no_record() {
    let w = World::new();
    let n = 100;
    // In key order: one key before all, then for each record its copy
    // (damaged for the even ones) and a key the source lacks.
    w.e2.set("m/art/a", b"left over");
    for i in 0..n {
        let key = format!("m/art/s_{i:03}");
        let sealed = w.record(&key, b"plan").await;
        if i % 2 == 0 {
            w.e2.set(&key, b"damaged");
        } else {
            w.e2.set(&key, &sealed);
        }
        w.e2.set(&format!("{key}x"), b"left over");
    }
    // One more, so that the second cut falls on a key the source lacks.
    w.e2.set("m/art/s_034y", b"left over");
    w.e2.page.set(7);

    // Ten answers of seven keys: the first round ends at the 70th key.
    let cut = w.e2.objects.borrow().keys().nth(69).cloned().unwrap();
    assert_eq!(cut, "m/art/s_034");
    let first = w.copier().step(UnixMs(NOW), &walk("")).await.unwrap();
    assert!(w.e2.asked.borrow().contains(&cut));
    assert_eq!(w.e2.get(&cut), w.safety.get(&cut, None).await.unwrap());
    assert!(w.e2.asked.borrow().iter().any(|a| a == "m/art/s_068x"));
    // One job walked all of it, cut after cut.
    assert_eq!(first.next, None);
    let total = first.counts;
    assert_eq!(
        (total.records, total.same, total.copied, total.extra),
        (n, n / 2, n / 2, n + 2)
    );
    for key in w.safety.keys() {
        assert_eq!(w.e2.get(&key), w.safety.get(&key, None).await.unwrap());
    }
    let second = w.pass().await;
    assert_eq!(
        (second.records, second.same, second.copied, second.extra),
        (n, n, 0, n + 2)
    );
}

/// The numbers the description of the copy gives.
#[test]
fn the_bounds_are_the_ones_described() {
    use velmora_bridge::copy::*;
    assert_eq!(PASS_INTERVAL_MS, 15 * 60 * 1000);
    assert_eq!(START_WINDOW_MS, 5 * 60 * 1000);
    assert_eq!(MIN_AGE_MS, 2 * 60 * 1000);
    assert_eq!(RETRY_WINDOW_MS, 10 * 60 * 1000);
    assert_eq!((JOB_COPIES, JOB_PAGES, JOB_MS), (250, 40, 20_000));
    assert_eq!((CONCURRENCY, PAGE, LIST_PAGES), (6, 1000, 10));
    assert_eq!((RETRY_SECS, OUTAGE_MIN), (60, 3));
}

/// The store's listing is cut at keys that something else wrote, and a
/// job ends at one: the next job, the source listing and the store
/// listing all go on from it, and each such key is counted once.
#[tokio::test(flavor = "current_thread")]
async fn a_pass_goes_on_from_a_key_that_something_else_wrote() {
    let w = World::new();
    for i in 0..25 {
        w.e2.set(&format!("m/art/a {i:02}"), b"note");
    }
    w.record("m/art/x_1", b"plan").await;
    w.e2.page.set(1);
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    // Ten list requests take the job to its cut and past half of its
    // time; the second cut ends it.
    let first = copier.step(UnixMs(NOW), &walk("")).await.unwrap();
    assert_eq!(first.next, Some(walk("m/art/a 19")));
    assert_eq!((first.counts.foreign, first.counts.records), (20, 0));
    assert!(w.e2.asked.borrow().iter().any(|a| a == "m/art/a 09"));
    let mut foreign = first.counts.foreign;
    let mut copied = 0;
    let mut cursor = first.next;
    while let Some(at) = cursor {
        let step = copier.step(UnixMs(NOW), &at).await.unwrap();
        foreign += step.counts.foreign;
        copied += step.counts.copied;
        cursor = step.next;
    }
    assert_eq!((foreign, copied), (25, 1));
    assert_eq!(w.e2.objects.borrow().len(), 26);
}

/// A job that ends where a source page ends in tenant keys sends a
/// cursor that names none of them.
#[tokio::test(flavor = "current_thread")]
async fn a_job_that_ends_at_tenant_keys_sends_no_name_of_one() {
    let w = World::new();
    // Five copies and ten list requests take the job past its time
    // before the next page.
    for i in 0..5 {
        w.generation(&generation(600_000, &format!("_{i}")), &[])
            .await;
    }
    // More tenant keys than fill the first source page.
    for i in 0..1_000 {
        w.raw(&format!("m/tk/t_{i:04}"), b"tenant key".to_vec())
            .await;
    }
    w.record("m/x_9", b"plan").await;
    for i in 0..9 {
        w.e2.set(&format!("m/g_zz{i}"), b"left over");
    }
    w.e2.page.set(1);
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let (outcome, counts, why) = copier.run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    let counts = counts.unwrap();
    assert_eq!((counts.records, counts.copied), (5, 5));
    assert!(w.e2.get("m/x_9").is_none());
    let sent = w.jobs.take();
    assert_eq!(sent.len(), 1);
    assert!(
        matches!(&sent[0].job, Job::RecoveryCopy { cursor, .. } if *cursor == sweep("m/tk0")),
        "{:?}",
        sent[0].job
    );
}

/// A copy with the MD5 of the record and another size is not equal: the
/// record is sent.
#[tokio::test(flavor = "current_thread")]
async fn a_copy_of_another_size_is_not_equal() {
    let w = World::new();
    let sealed = w.record("m/art/x_1", b"plan").await;
    assert_ne!(sealed.len(), 1);
    *w.e2.list_inner.borrow_mut() = Some(format!(
        "<IsTruncated>false</IsTruncated><Contents><Key>drill-1/m/art/x_1</Key>\
         <ETag>&quot;{}&quot;</ETag><Size>1</Size></Contents>",
        md5_hex(&sealed)
    ));
    // The forced answer is wrong for the listing that follows the
    // page, so the step ends in an error; the copy was made before.
    let _ = w.copier().step(UnixMs(NOW), &walk("")).await;
    assert_eq!(w.e2.puts(), 1);
    assert_eq!(w.e2.get("m/art/x_1"), Some(sealed));
}

/// The store is found down by the last copies of a page: the step ends
/// there for that reason, not because the tries took its time, and does
/// not go on to the next page (where the source ends, and the outage
/// would be forgotten).
#[tokio::test(flavor = "current_thread")]
async fn a_step_that_finds_the_store_down_does_not_read_the_next_page() {
    let w = World::new();
    for i in 0..4 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    w.e2.put_status.set(Some(500));
    w.e2.still.set(true);
    let step = w.copier().step(UnixMs(NOW), &walk("")).await.unwrap();
    assert!(step.outage);
    assert_eq!(step.next, Some(walk("m/art/x_3")));
    assert_eq!(step.counts.failed, 4);
    assert_eq!(w.e2.count("GET "), 1);
}

/// The store goes down in the middle of a page: the step stops after
/// the group that got no answer, with the cursor at its last record,
/// and counts only what lies before it. The rest is counted once, by
/// the steps that follow.
#[tokio::test(flavor = "current_thread")]
async fn a_step_that_finds_the_store_down_stops_inside_the_page() {
    let w = World::new();
    for i in 0..20 {
        w.record(&format!("m/art/x_{i:02}"), b"plan").await;
    }
    for key in ["m/art/x_03a", "m/art/x_10a", "m/art/zz"] {
        w.e2.set(key, b"left over");
    }
    for key in ["m/art/x_02 b", "m/art/x_10 b"] {
        w.e2.set(key, b"note");
    }
    w.e2.put_status.set(Some(500));
    let first = w.copier().step(UnixMs(NOW), &walk("")).await.unwrap();
    assert!(first.outage);
    assert_eq!(first.next, Some(walk("m/art/x_05")));
    let c = &first.counts;
    assert_eq!((c.records, c.failed, c.extra, c.foreign), (6, 6, 1, 1));
    // Six records, four tries each, and no more.
    assert_eq!(w.e2.puts(), 24);

    w.e2.put_status.set(None);
    let mut extra = first.counts.extra;
    let mut foreign = first.counts.foreign;
    let mut records = first.counts.records;
    let mut cursor = first.next;
    while let Some(at) = cursor {
        let step = w.copier().step(UnixMs(NOW), &at).await.unwrap();
        assert!(!step.outage);
        extra += step.counts.extra;
        foreign += step.counts.foreign;
        records += step.counts.records;
        cursor = step.next;
    }
    assert_eq!((records, extra, foreign), (20, 3, 2));
}

/// A source whose listing is not to be believed: it still names keys
/// that are gone, and its digests are not the MD5 of the bytes.
struct Stale<'a> {
    inner: &'a MemBlobStore,
    gone: Vec<&'static str>,
    md5: Option<&'static str>,
}

impl BlobStore for Stale<'_> {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.inner.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        if self.gone.contains(&key) {
            return Ok(None);
        }
        self.inner.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.inner.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn delete_record(&self, refused: &recovery::Unpublished) -> Result<()> {
        self.inner.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
    async fn list_entries(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<BlobEntry>> {
        let mut entries = self.inner.list_entries(prefix, after, limit).await?;
        if let Some(md5) = self.md5 {
            for entry in &mut entries {
                entry.md5 = md5.into();
            }
        }
        Ok(entries)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_record_removed_after_it_was_listed_is_not_counted() {
    let w = World::new();
    w.record("m/art/x_1", b"a plan that is gone").await;
    let kept = w.record("m/art/x_2", b"plan").await;
    let safety = Stale {
        inner: &w.safety,
        gone: vec!["m/art/x_1"],
        md5: None,
    };
    let copier = Copier {
        safety: &safety,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let step = copier.step(UnixMs(NOW), &walk("")).await.unwrap();
    let c = step.counts;
    assert_eq!((c.records, c.bytes, c.copied), (1, kept.len() as u64, 1));
    assert!(c.clean());
    assert!(w.e2.get("m/art/x_1").is_none());
}

/// The source's listing names a digest that is not the MD5 of the bytes
/// (a record stored in parts): the bytes are read and compared, and an
/// equal copy is not sent again.
#[tokio::test(flavor = "current_thread")]
async fn an_equal_copy_is_not_sent_again_when_the_listing_names_another_digest() {
    let w = World::new();
    for i in 0..3 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    let fresh = generation(600_000, "_a");
    w.generation(&fresh, &["x_0"]).await;
    let safety = Stale {
        inner: &w.safety,
        gone: vec![],
        md5: Some("0123456789abcdef0123456789abcdef-2"),
    };
    let copier = Copier {
        safety: &safety,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let first = copier.step(UnixMs(NOW), &walk("")).await.unwrap().counts;
    assert_eq!((first.copied, first.same), (3, 0));
    let second = copier.step(UnixMs(NOW), &walk("")).await.unwrap().counts;
    assert_eq!((second.copied, second.same), (0, 3));
    assert_eq!(w.e2.puts(), 3);
    // A copy that differs is still mended.
    w.e2.set("m/art/x_1", b"damaged");
    let third = copier.step(UnixMs(NOW), &walk("")).await.unwrap().counts;
    assert_eq!((third.copied, third.same), (1, 2));
    // The same for a record of the fresh sweep.
    let sweep = copier.step(UnixMs(NOW), "").await.unwrap().counts;
    assert_eq!((sweep.copied, sweep.same), (1, 3));
    let sweep = copier.step(UnixMs(NOW), "").await.unwrap().counts;
    assert_eq!((sweep.copied, sweep.same), (0, 4));
    assert_eq!(w.e2.puts(), 5);
}

#[tokio::test(flavor = "current_thread")]
async fn no_delete_request_is_ever_sent_to_e2() {
    // Every situation in which a mirror would delete.
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    w.record(&generation(OLD, "aaaa"), b"g").await;
    w.pass().await;
    w.safety.lose("m/art/x_1");
    w.safety
        .corrupt(&generation(OLD, "aaaa"), |b| b.truncate(3));
    w.e2.set("m/zz", b"unknown");
    w.pass().await;
    let log = w.e2.log.borrow();
    assert!(!log.is_empty());
    assert!(log
        .iter()
        .all(|l| l.starts_with("GET ") || l.starts_with("HEAD ") || l.starts_with("PUT ")));
    assert_eq!(w.e2.objects.borrow().len(), 3);
}

// ---------------------------------------------------------------------------
// The fresh sweep and the walk that goes on from where it stopped
// ---------------------------------------------------------------------------

/// Where `key` was put, among the requests the store got.
fn put_at(e2: &FakeE2, key: &str) -> Option<usize> {
    let log = e2.log.borrow();
    log.iter()
        .position(|l| l.starts_with("PUT ") && l.ends_with(key))
}

/// The place the walk is saved at.
async fn saved(w: &World) -> Option<String> {
    let bytes = w.safety.get(WALK_KEY, None).await.unwrap()?;
    Some(String::from_utf8(bytes).unwrap())
}

/// More records than a pass can even list: the store answers one key at
/// a time and every request takes a second, so a pass of 15 minutes
/// gets through a few hundred of them. Every record is over there
/// within a bounded number of passes, because each pass goes on where
/// the last one stopped. And what is written or deleted while that goes
/// on is over there by the end of the next pass, article plan included,
/// however far the walk is from it.
#[tokio::test(flavor = "current_thread")]
async fn a_backfill_longer_than_a_pass_reaches_every_key_and_new_ones_first() {
    const OLD_RECORDS: usize = 1_300;
    const PASSES: i64 = 10;
    let w = World::new();
    for i in 0..1_000 {
        w.record(&format!("m/art/x_{i:04}"), b"plan").await;
    }
    for i in 0..150 {
        let id = format!("{:013x}_{i:03}", NOW - OLD - i64::from(i));
        w.record(&format!("m/del/g_{id}"), b"gone").await;
        w.record(&format!("m/g_{id}"), b"old").await;
    }
    w.e2.page.set(1);
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let old: Vec<String> = w.safety.keys();
    assert_eq!(old.len(), OLD_RECORDS);
    let behind = |e2: &FakeE2| old.iter().filter(|k| e2.get(k).is_none()).count();

    let mut left = Vec::new();
    let mut places = Vec::new();
    for n in 0..PASSES {
        let start = UnixMs(NOW + n * PASS_INTERVAL_MS);
        if w.clock.now().0 < start.0 {
            w.clock.set(start);
        }
        // A write and a delete, three minutes before the pass. The plan
        // sorts after every key the walk has to go through.
        let minted = start.0 - 180_000;
        let plan = format!("m/art/x_zz{n:02}");
        let written = format!("m/g_{minted:013x}_new");
        let deleted = format!("m/del/g_{minted:013x}_new");
        w.record(&plan, b"plan").await;
        w.generation(&written, &[&plan["m/art/".len()..]]).await;
        w.record(&deleted, b"gone").await;

        assert!(copier.start_pass(&w.jobs, start).await.unwrap());
        let mut jobs = 0;
        loop {
            let sent = w.jobs.take();
            if sent.is_empty() {
                break;
            }
            assert_eq!(sent.len(), 1);
            let Job::RecoveryCopy { pass, cursor, .. } = &sent[0].job else {
                panic!("another job");
            };
            let (outcome, _, why) = copier.run_job(&w.jobs, *pass, cursor).await;
            assert_eq!((outcome, why), (JobOutcome::Ack, None), "pass {n}");
            jobs += 1;
        }
        assert!(jobs > 1);
        // The pass ended, or the next one is due: never much later.
        let now = w.clock.now().0;
        assert!(now < start.0 + PASS_INTERVAL_MS + 60_000, "pass {n}");
        // What was new is over there, whole, within the bound.
        for key in [&plan, &written, &deleted] {
            assert_eq!(
                w.e2.get(key),
                w.safety.stored(key).map(|b| b.bytes),
                "{key}"
            );
        }
        assert!(put_at(w.e2, &plan) < put_at(w.e2, &written));
        assert!(now - minted <= 180_000 + PASS_INTERVAL_MS + 60_000);
        left.push(behind(w.e2));
        places.push(saved(&w).await.unwrap());
    }
    // One pass was not enough, by far, and no pass was idle.
    let done = left.iter().position(|n| *n == 0).expect("every key");
    assert!((3..=5).contains(&done), "{left:?}");
    assert!(left[..done].windows(2).all(|w| w[1] < w[0]), "{left:?}");
    // The walk went on from pass to pass: the place moved forward, and
    // went back to the start only at the end of the keys.
    assert!(places[..done].windows(2).all(|w| w[0] < w[1]), "{places:?}");
    assert!(places[done..].iter().any(String::is_empty), "{places:?}");
    // Nothing but what the source holds, each byte equal.
    for key in w.safety.keys().iter().filter(|k| k.starts_with("m/")) {
        assert_eq!(
            w.e2.get(key),
            w.safety.stored(key).map(|b| b.bytes),
            "{key}"
        );
    }
    assert_eq!(w.e2.puts(), OLD_RECORDS + 3 * PASSES as usize);
}

/// A fresh generation record goes after the article plans it names.
/// While one of them is not written, the record is held back and
/// counted; the pass after the plan appears sends both, plan first.
#[tokio::test(flavor = "current_thread")]
async fn a_fresh_generation_record_is_sent_after_its_article_plans() {
    let w = World::new();
    let key = generation(600_000, "_a");
    let sealed = w.generation(&key, &["x_1", "x_2"]).await;
    w.record("m/art/x_1", b"plan").await;
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.copied), (1, 1));
    assert_eq!((counts.failed, counts.refused), (0, 0));
    // The record itself and the plan that is there; the plan was sent
    // by the sweep, so the walk found it equal.
    assert_eq!((counts.records, counts.same), (2, 1));
    assert!(w.e2.get(&key).is_none() && w.e2.get("m/art/x_1").is_some());

    w.record("m/art/x_2", b"plan").await;
    w.clock.advance_ms(PASS_INTERVAL_MS);
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.copied), (0, 2));
    assert_eq!(w.e2.get(&key), Some(sealed));
    assert!(put_at(w.e2, "m/art/x_2") < put_at(w.e2, &key));
    // Each plan was sent once.
    assert_eq!(w.e2.puts(), 3);

    // A record that names no extent has nothing to wait for.
    let empty = generation(500_000, "_b");
    w.generation(&empty, &[]).await;
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.copied), (0, 1));
    assert!(w.e2.get(&empty).is_some());
}

/// A record that was held back for an hour is no longer fresh: the walk
/// copies it as it is. The same for one whose extents cannot be read.
#[tokio::test(flavor = "current_thread")]
async fn a_generation_record_held_back_is_copied_by_the_walk_once_old() {
    let w = World::new();
    let held = generation(600_000, "_a");
    let odd = generation(600_000, "_b");
    let bad = generation(600_000, "_c");
    w.generation(&held, &["x_never"]).await;
    w.record(&odd, b"not a manifest").await;
    w.record(&bad, br#"{"extents":[{"id":"../x_1"}]}"#).await;
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.source_unreadable), (1, 2));
    assert_eq!((counts.copied, w.e2.puts()), (0, 0));
    // No request named a key that the record made up.
    assert!(w.e2.log.borrow().iter().all(|l| !l.contains("..")));

    w.clock.advance_ms(FRESH_MS);
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.source_unreadable), (0, 0));
    assert_eq!(counts.copied, 3);
    for key in [&held, &odd, &bad] {
        assert!(w.e2.get(key).is_some());
    }
}

/// A generation record with more article plans than a job has room for
/// is done over several jobs: the cursor keeps how many plans are over
/// there, no plan is sent twice, and the record goes last.
#[tokio::test(flavor = "current_thread")]
async fn a_generation_record_with_more_plans_than_a_job_takes_several() {
    let w = World::new();
    let ids: Vec<String> = (0..600).map(|i| format!("x_{i:04}")).collect();
    for id in &ids {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    let key = generation(600_000, "_big");
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    w.generation(&key, &ids).await;
    let after = generation(500_000, "_next");
    w.generation(&after, &[]).await;
    let start = format!("m/g_{:013x}", NOW - FRESH_MS);
    let at = |n: u32| format!("{{\"p\":\"g\",\"k\":\"{start}\",\"g\":\"{key}\",\"n\":{n}}}");

    // The two records take two of the 250.
    let first = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert_eq!(first.next, Some(at(248)));
    assert_eq!((first.counts.copied, first.counts.records), (248, 0));
    assert_eq!(first.walk, None);
    let second = w.copier().step(UnixMs(NOW), &at(248)).await.unwrap();
    assert_eq!(second.next, Some(at(496)));
    assert_eq!(w.e2.puts(), 496);
    // Neither it nor the record after it is over there yet.
    assert!(w.e2.get(&key).is_none() && w.e2.get(&after).is_none());

    let mut total = second.counts.copied + first.counts.copied;
    let mut same = 0;
    let mut cursor = second.next;
    while let Some(at) = cursor {
        let step = w.copier().step(UnixMs(NOW), &at).await.unwrap();
        total += step.counts.copied;
        same += step.counts.same;
        cursor = step.next;
    }
    // 600 plans and two records, once each; the walk found the plans.
    assert_eq!((total, same, w.e2.puts()), (602, 600, 602));
    assert!(put_at(w.e2, "m/art/x_0599") < put_at(w.e2, &key));
    assert!(w.e2.get(&after).is_some());

    // A count in the cursor for another record, or one that leaves no
    // plan of this record to look at, is not believed.
    let small = generation(600_000, "_s");
    for (named, n) in [
        (format!("{small}x"), 1),
        (small.clone(), 2),
        (small.clone(), 3),
    ] {
        let w = World::new();
        w.generation(&small, &["x_1", "x_2"]).await;
        w.record("m/art/x_1", b"plan").await;
        w.record("m/art/x_2", b"plan").await;
        let lie = format!("{{\"p\":\"g\",\"k\":\"{start}\",\"g\":\"{named}\",\"n\":{n}}}");
        w.copier().step(UnixMs(NOW), &lie).await.unwrap();
        assert!(put_at(w.e2, "m/art/x_1").is_some(), "{n}");
        assert!(put_at(w.e2, "m/art/x_1") < put_at(w.e2, &small), "{n}");
    }
}

/// A plan that is absent while an earlier job's count says it is over
/// there cannot happen through the queue; a plan that fails, though,
/// holds its record back and is counted.
#[tokio::test(flavor = "current_thread")]
async fn an_article_plan_that_cannot_be_sent_holds_the_record_back() {
    let w = World::new();
    let key = generation(600_000, "_a");
    w.generation(&key, &["x_1", "x_2", "x_3"]).await;
    for id in ["x_1", "x_2", "x_3"] {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    w.e2.put_500_keys.borrow_mut().push("m/art/x_2".into());
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(!step.outage);
    let c = &step.counts;
    // The plan fails for the sweep, and again for the walk.
    assert_eq!((c.pending, c.failed, c.copied), (1, 2, 2));
    assert!(w.e2.get(&key).is_none());

    // A plan that does not open is never sent, and neither is the
    // record while it is fresh.
    let w = World::new();
    w.generation(&key, &["x_1"]).await;
    w.raw("m/art/x_1", b"not sealed".to_vec()).await;
    let counts = w.pass().await;
    // Counted by the sweep and again by the walk.
    assert_eq!((counts.pending, counts.source_unreadable), (1, 2));
    assert_eq!(w.e2.puts(), 0);

    // The store is down while the plans are sent: the step says so,
    // and the job comes again from the same cursor.
    let w = World::new();
    w.generation(&key, &["x_1", "x_2", "x_3"]).await;
    for id in ["x_1", "x_2", "x_3"] {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    w.e2.put_status.set(Some(500));
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(step.outage);
    assert_eq!((step.counts.pending, step.counts.failed), (1, 3));
    let (outcome, _, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(outcome, JobOutcome::Retry { delay_secs: 60 });
    assert_eq!(why, Some(StepError::Store(RemoteError::Unavailable)));
    assert!(w.jobs.take().is_empty());
    assert!(w.e2.get(&key).is_none());
    w.e2.put_status.set(None);
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.copied), (0, 4));
}

/// The saved place only says where the walk starts. Whatever it holds,
/// every record is reached: at once when the place is not one of the
/// walk, and by the pass after the next when it lies in the middle.
#[tokio::test(flavor = "current_thread")]
async fn any_saved_place_of_the_walk_is_safe() {
    let fresh_tombstone = format!("m/del/g_{:013x}_x", NOW - 600_000);
    let fresh_generation = generation(600_000, "_x");
    // Too long to be asked of the store; it sorts before every record.
    let long = format!("m/a{}", "a".repeat(2_000));
    let places: [&[u8]; 7] = [
        b"",
        b"\xff\xfe",
        long.as_bytes(),
        b"m/zzzz",
        b"zzzz",
        fresh_tombstone.as_bytes(),
        fresh_generation.as_bytes(),
    ];
    for place in places {
        let w = World::new();
        let old = generation(OLD, "_o");
        for key in ["m/art/x_1", "m/art/x_5", "m/del/g_0000000000001_t", &old] {
            w.record(key, b"record").await;
        }
        w.raw(WALK_KEY, place.to_vec()).await;
        let counts = w.pass().await;
        assert_eq!(counts.copied, 4, "{place:?}");
        // The saved place is not a record: never sent, never counted.
        assert_eq!((counts.records, w.e2.objects.borrow().len()), (4, 4));
    }

    // In the middle. A place that no walk saved (none began since the
    // last one ended) is not gone on from: the walk starts from the
    // first key, so that a walk that ends has been through all of them.
    // The place of a walk that is under way is gone on from; what lies
    // before it was done by the passes before.
    for (place, rest) in [
        ("m/art/x_3", 3),
        ("m/del0", 1),
        ("m/del/g_0000000000001_t", 1),
    ] {
        let began = (NOW - PASS_INTERVAL_MS).to_string().into_bytes();
        let ended = (NOW - 2 * PASS_INTERVAL_MS).to_string().into_bytes();
        let stale: [&[(&str, &[u8])]; 3] = [
            &[],
            &[(WALKED_KEY, b"0")],
            &[(BEGAN_KEY, b"0"), (WALKED_KEY, b"0")],
        ];
        let under_way: [&[(&str, &[u8])]; 2] = [
            &[(BEGAN_KEY, &began)],
            &[(BEGAN_KEY, &began), (WALKED_KEY, &ended)],
        ];
        for (times, all) in stale
            .iter()
            .map(|t| (t, true))
            .chain(under_way.iter().map(|t| (t, false)))
        {
            let w = World::new();
            let old = generation(OLD, "_o");
            for key in ["m/art/x_1", "m/art/x_5", "m/del/g_0000000000001_t", &old] {
                w.record(key, b"record").await;
            }
            known_store(&w).await;
            w.raw(WALK_KEY, place.as_bytes().to_vec()).await;
            for (key, body) in times.iter() {
                w.raw(key, body.to_vec()).await;
            }
            let (_, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
            assert_eq!(why, None);
            let copied = if all { 4 } else { rest };
            assert_eq!(counts.unwrap().copied, copied, "{place} {all}");
            assert!(w.jobs.take().is_empty());
            assert_eq!(saved(&w).await.as_deref(), Some(""));
            assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
        }
        // With a walk that ended a while ago, and none begun since, the
        // place is as good as none: the walk rests, and comes a day
        // after that end, from the first key.
        for times in [[&ended, &ended], [&ended, &began]] {
            let w = World::new();
            for key in ["m/art/x_1", "m/art/x_5"] {
                w.record(key, b"record").await;
            }
            w.raw(WALK_KEY, place.as_bytes().to_vec()).await;
            w.raw(BEGAN_KEY, times[0].clone()).await;
            w.raw(WALKED_KEY, times[1].clone()).await;
            no_gap(&w, UnixMs(NOW)).await;
            known_store(&w).await;
            let (_, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
            assert_eq!((counts.unwrap().records, why), (0, None), "{place}");
            let day = UnixMs(NOW + WALK_INTERVAL_MS - PASS_INTERVAL_MS);
            w.clock.set(day);
            no_gap(&w, day).await;
            let (_, counts, _) = w.copier().run_job(&w.jobs, day, "").await;
            assert_eq!(counts.unwrap().copied, 2, "{place}");
        }
    }
}

/// A job of the walk saves its place when it is done, and only then; a
/// pass that starts later goes on from it.
#[tokio::test(flavor = "current_thread")]
async fn the_walk_is_saved_job_by_job_and_a_later_pass_goes_on_from_it() {
    let w = World::new();
    for i in 0..=JOB_COPIES {
        w.record(&format!("m/art/x_{i:04}"), b"plan").await;
    }
    let (_, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((counts.unwrap().copied as usize, why), (JOB_COPIES, None));
    let last = format!("m/art/x_{:04}", JOB_COPIES - 1);
    assert_eq!(saved(&w).await.as_deref(), Some(last.as_str()));
    let sent = w.jobs.take();
    assert!(matches!(&sent[0].job, Job::RecoveryCopy { cursor, .. } if *cursor == walk(&last)));

    // That job is lost. The next pass copies the one record left, and
    // lists nothing of what lies before the place.
    w.clock.advance_ms(PASS_INTERVAL_MS);
    w.e2.asked.borrow_mut().clear();
    let pass = w.clock.now();
    let (_, counts, why) = w.copier().run_job(&w.jobs, pass, "").await;
    let counts = counts.unwrap();
    assert_eq!((counts.copied, counts.same, why), (1, 0, None));
    assert!(
        w.e2.asked.borrow().iter().all(|a| *a >= last),
        "{:?}",
        w.e2.asked
    );
    assert_eq!(saved(&w).await.as_deref(), Some(""));

    // A job of the fresh sweep saves nothing.
    let w = World::new();
    for i in 0..=JOB_COPIES {
        w.generation(&generation(600_000, &format!("_{i:04}")), &[])
            .await;
    }
    let (_, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((counts.unwrap().copied as usize, why), (JOB_COPIES, None));
    assert_eq!(saved(&w).await, None);
}

/// A safety bucket that takes no write of the saved place.
struct NoMark<'a>(&'a MemBlobStore, &'static str);

impl BlobStore for NoMark<'_> {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        if key == self.1 {
            return Err(BridgeError::Blob("down".into()));
        }
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
    async fn delete_record(&self, refused: &recovery::Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.0.list(prefix, start_after, limit).await
    }
}

/// A place that cannot be saved is reported, and the pass goes on.
#[tokio::test(flavor = "current_thread")]
async fn a_place_that_cannot_be_saved_is_reported_and_the_pass_goes_on() {
    let w = World::new();
    for i in 0..=JOB_COPIES {
        w.record(&format!("m/art/x_{i:04}"), b"plan").await;
    }
    let source = NoMark(&w.safety, WALK_KEY);
    let copier = Copier {
        safety: &source,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let (outcome, counts, why) = copier.run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(counts.unwrap().copied as usize, JOB_COPIES);
    assert_eq!(why, Some(StepError::Mark));
    let sent = w.jobs.take();
    let Job::RecoveryCopy { cursor, .. } = &sent[0].job else {
        panic!("another job");
    };
    let (outcome, counts, why) = copier.run_job(&w.jobs, UnixMs(NOW), cursor).await;
    assert_eq!((outcome, why), (JobOutcome::Ack, Some(StepError::Mark)));
    assert_eq!(counts.unwrap().copied, 1);
    assert_eq!(w.e2.objects.borrow().len(), JOB_COPIES + 1);
}

/// The parts of a pass meet without a gap and without an overlap: a
/// record whose key is the very bound between two of them is looked at
/// once.
#[tokio::test(flavor = "current_thread")]
async fn a_record_at_a_bound_between_two_parts_is_copied_once() {
    let w = World::new();
    let bounds = [
        "m/del0".to_string(),
        format!("m/del/g_{:013x}", NOW - FRESH_MS),
        format!("m/g_{:013x}", NOW - FRESH_MS),
    ];
    for key in &bounds {
        w.record(key, b"record").await;
    }
    let counts = w.pass().await;
    assert_eq!((counts.records, counts.copied, counts.same), (3, 3, 0));
    assert_eq!(w.e2.puts(), 3);
    // A copy without a source at a bound is counted once, too.
    let w = World::new();
    for key in &bounds {
        w.e2.set(key, b"left over");
    }
    assert_eq!(w.pass().await.extra, 3);
}

/// Checks of article plans count against the bound of a job like
/// copies do.
#[tokio::test(flavor = "current_thread")]
async fn article_plans_count_against_the_bound_of_a_job() {
    let w = World::new();
    for g in 0..100 {
        let ids: Vec<String> = (0..5).map(|i| format!("x_{g:03}{i}")).collect();
        for id in &ids {
            w.record(&format!("m/art/{id}"), b"plan").await;
        }
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        w.generation(&generation(600_000, &format!("_{g:03}")), &ids)
            .await;
    }
    let first = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(first.next.is_some());
    // The last group of six records may take the job a little past it.
    let did = first.counts.copied as usize;
    assert!((JOB_COPIES - 36..JOB_COPIES + 36).contains(&did), "{did}");
    assert_eq!(w.e2.puts(), did);
    let counts = w.pass().await;
    assert_eq!(counts.copied as usize + did, 600);
    assert_eq!(counts.pending, 0);
}

/// A plan that fails, or is refused, holds its record back: no put of
/// the record is tried.
#[tokio::test(flavor = "current_thread")]
async fn a_record_is_not_tried_while_a_plan_failed_or_was_refused() {
    let key = generation(600_000, "_a");
    for refused in [false, true] {
        let w = World::new();
        w.generation(&key, &["x_1"]).await;
        w.record("m/art/x_1", b"plan").await;
        if refused {
            w.e2.put_status.set(Some(403));
        } else {
            w.e2.damage_puts.set(true);
        }
        let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
        assert_eq!(step.counts.pending, 1, "{refused}");
        assert!(put_at(w.e2, "m/art/x_1").is_some());
        assert_eq!(put_at(w.e2, &key), None, "{refused}");
    }

    // The store goes down when the records themselves are sent.
    let w = World::new();
    for i in 0..3 {
        w.generation(&generation(600_000, &format!("_{i}")), &[])
            .await;
    }
    w.e2.put_status.set(Some(500));
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(step.outage);
    assert_eq!(step.counts.failed, 3);
}

/// A record with more plans than a job takes, one of which is not
/// written: it is held back once, the pass goes on past it, and the
/// record is not sent however many of its plans are over there.
#[tokio::test(flavor = "current_thread")]
async fn a_large_record_with_a_plan_missing_is_passed_and_not_sent() {
    let w = World::new();
    let ids: Vec<String> = (0..300).map(|i| format!("x_{i:04}")).collect();
    for id in &ids[1..] {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    let key = generation(600_000, "_big");
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    w.generation(&key, &ids).await;
    let after = generation(500_000, "_next");
    w.generation(&after, &[]).await;

    let mut pending = 0;
    let mut cursor = Some(String::new());
    let mut jobs = 0;
    while let Some(at) = cursor {
        let step = w.copier().step(UnixMs(NOW), &at).await.unwrap();
        pending += step.counts.pending;
        cursor = step.next;
        jobs += 1;
        assert!(jobs < 10, "the pass does not get past the record");
    }
    assert_eq!(pending, 1);
    assert_eq!(put_at(w.e2, &key), None);
    assert!(w.e2.get(&after).is_some());
    // Every plan that is there was sent once: by the sweep or the walk.
    assert_eq!(w.e2.puts(), 300);
}

/// What the sweep saved of the records it could not send yet.
async fn known(w: &World) -> String {
    let bytes = w.safety.get(SWEEP_KEY, None).await.unwrap();
    String::from_utf8(bytes.unwrap_or_default()).unwrap()
}

/// Requests of one method for one key.
fn asked_for(e2: &FakeE2, method: &str, key: &str) -> usize {
    let log = e2.log.borrow();
    log.iter()
        .filter(|l| l.starts_with(method) && l.ends_with(key))
        .count()
}

/// A pass through the queue, job after job: why its jobs fell short.
async fn queued_pass<B: BlobStore, T: Clock>(
    w: &World,
    copier: &Copier<'_, B, TestKek, T, &'static FakeE2>,
    start: UnixMs,
) -> Vec<StepError> {
    assert!(copier.start_pass(&w.jobs, start).await.unwrap());
    let mut whys = Vec::new();
    loop {
        let sent = w.jobs.take();
        if sent.is_empty() {
            return whys;
        }
        assert_eq!((sent.len(), sent[0].delay_secs), (1, 0));
        let Job::RecoveryCopy { pass, cursor, .. } = &sent[0].job else {
            panic!("another job");
        };
        let (outcome, _, why) = copier.run_job(&w.jobs, *pass, cursor).await;
        assert_eq!(outcome, JobOutcome::Ack);
        whys.extend(why);
    }
}

/// One fresh record with more article plans than the sweep of a pass
/// gets through (every request takes a second). The sweep stops when
/// its time is up and says so, the walk has the rest of the pass, and
/// the next pass goes on after the plans that are over there: no plan
/// is asked for twice, and the record is sent after the last of them.
#[tokio::test(flavor = "current_thread")]
async fn a_record_larger_than_a_sweep_is_finished_over_passes_and_the_walk_goes_on() {
    const PLANS: usize = 400;
    const OLD_RECORDS: usize = 600;
    let w = World::new();
    for i in 0..OLD_RECORDS {
        w.record(&format!("m/art/x_0{i:04}"), b"old").await;
    }
    let ids: Vec<String> = (0..PLANS).map(|i| format!("x_p{i:04}")).collect();
    for id in &ids {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    let key = generation(180_000, "_big");
    let names: Vec<&str> = ids.iter().map(String::as_str).collect();
    w.generation(&key, &names).await;
    let tombstone = format!("m/del/g_{:013x}_t", NOW - 180_000);
    w.record(&tombstone, b"gone").await;
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let there = |prefix: &str| {
        let objects = w.e2.objects.borrow();
        objects.keys().filter(|k| k.starts_with(prefix)).count()
    };

    let mut passes = 0;
    let (mut plans, mut old) = (0, 0);
    while w.e2.get(&key).is_none() {
        let start = UnixMs(NOW + passes * PASS_INTERVAL_MS);
        if w.clock.now().0 < start.0 {
            w.clock.set(start);
        }
        let whys = queued_pass(&w, &copier, start).await;
        passes += 1;
        assert!(passes <= 3, "{plans} plans after {passes} passes");
        // The tombstone did not wait for the record.
        assert!(w.e2.get(&tombstone).is_some());
        if w.e2.get(&key).is_none() {
            // Cut short, and said once; the walk had its turn all the
            // same, and has not come to the plans.
            assert_eq!(whys, [StepError::Expired], "pass {passes}");
            assert!(there("m/art/x_0") > old, "pass {passes}");
            assert!(there("m/art/x_0") < OLD_RECORDS);
        }
        assert!(there("m/art/x_p") > plans, "pass {passes}");
        (plans, old) = (there("m/art/x_p"), there("m/art/x_0"));
    }
    assert!(passes > 1);
    assert_eq!(plans, PLANS);
    let sent = put_at(w.e2, &key).unwrap();
    for id in &ids {
        let plan = format!("m/art/{id}");
        assert!(put_at(w.e2, &plan).unwrap() < sent, "{id}");
        // Once before it was sent, once to see that it arrived.
        assert_eq!(asked_for(w.e2, "HEAD", &plan), 2, "{id}");
        assert_eq!(asked_for(w.e2, "PUT", &plan), 1, "{id}");
    }
    assert_eq!(known(&w).await, "{}");
}

/// A record held back for a plan is looked at again by the next pass
/// from the plans that are over there, not from its first.
#[tokio::test(flavor = "current_thread")]
async fn a_record_held_back_goes_on_after_the_plans_that_are_over_there() {
    let w = World::new();
    let key = generation(600_000, "_a");
    let ids: Vec<String> = (0..300).map(|i| format!("x_{i:04}")).collect();
    for id in ids.iter().filter(|id| *id != "x_0260") {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    let names: Vec<&str> = ids.iter().map(String::as_str).collect();
    let sealed = w.generation(&key, &names).await;
    // More plans than one job takes: the missing one is met by the
    // second job, which goes on from the cursor.
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.failed), (1, 0));
    assert_eq!(put_at(w.e2, &key), None);
    assert_eq!(known(&w).await, format!("{{\"{key}\":260}}"));
    assert_eq!(asked_for(w.e2, "HEAD", "m/art/x_0000"), 2);
    assert_eq!(asked_for(w.e2, "HEAD", "m/art/x_0259"), 2);
    // Nothing behind the missing plan was asked for by the sweep; the
    // walk sent those (it does not ask first).
    assert_eq!(asked_for(w.e2, "HEAD", "m/art/x_0261"), 1);

    // The next pass asks for none of the 260 again: only for the rest
    // of the six that the missing one is in.
    w.clock.advance_ms(PASS_INTERVAL_MS);
    w.e2.log.borrow_mut().clear();
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.copied), (1, 0));
    let asked: Vec<String> = (w.e2.log.borrow().iter())
        .filter(|l| !l.starts_with("GET "))
        .cloned()
        .collect();
    let rest: Vec<String> = (261..266).map(|i| format!("HEAD m/art/x_{i:04}")).collect();
    assert_eq!(asked, rest);
    assert_eq!(known(&w).await, format!("{{\"{key}\":260}}"));

    // The plan is written: it is sent, the rest is found, the record
    // goes last, and nothing is kept of it.
    w.record("m/art/x_0260", b"plan").await;
    w.clock.advance_ms(PASS_INTERVAL_MS);
    w.e2.log.borrow_mut().clear();
    let counts = w.pass().await;
    assert_eq!((counts.pending, counts.copied), (0, 2));
    assert_eq!(w.e2.get(&key), Some(sealed));
    assert!(put_at(w.e2, "m/art/x_0260") < put_at(w.e2, &key));
    assert_eq!(asked_for(w.e2, "HEAD", "m/art/x_0259"), 0);
    assert_eq!(asked_for(w.e2, "HEAD", "m/art/x_0261"), 1);
    assert_eq!(known(&w).await, "{}");
}

/// What is saved of the sweep is a hint. Whatever it holds, every
/// record and every plan is over there after the pass; and a count
/// that is not one for this record is not believed, so the plans still
/// go first.
#[tokio::test(flavor = "current_thread")]
async fn anything_saved_of_the_sweep_is_safe() {
    let key = generation(600_000, "_a");
    let long = format!("{{\"{key}\":1{}}}", " ".repeat(1024 * 1024));
    let lies = [
        "not json".to_string(),
        "[1,2]".to_string(),
        format!("{{\"{key}\":\"1\"}}"),
        format!("{{\"{key}\":2}}"),
        format!("{{\"{key}\":7}}"),
        format!("{{\"{key}x\":1}}"),
        format!("{{\"{key}\":-1}}"),
        long,
    ];
    for lie in &lies {
        let w = World::new();
        w.generation(&key, &["x_1", "x_2"]).await;
        w.record("m/art/x_1", b"plan").await;
        w.record("m/art/x_2", b"plan").await;
        w.raw(SWEEP_KEY, lie.clone().into_bytes()).await;
        let counts = w.pass().await;
        let lie = &lie[..lie.len().min(40)];
        assert_eq!((counts.copied, counts.pending), (3, 0), "{lie}");
        assert!(put_at(w.e2, "m/art/x_1") < put_at(w.e2, &key), "{lie}");
        assert!(put_at(w.e2, "m/art/x_2") < put_at(w.e2, &key), "{lie}");
    }
    // A count that could be true is believed: the record may then go
    // before a plan. The walk of the same pass sends the plan.
    let w = World::new();
    w.generation(&key, &["x_1", "x_2"]).await;
    w.record("m/art/x_1", b"plan").await;
    w.record("m/art/x_2", b"plan").await;
    w.raw(SWEEP_KEY, format!("{{\"{key}\":1}}").into_bytes())
        .await;
    let counts = w.pass().await;
    assert_eq!((counts.copied, counts.pending), (3, 0));
    assert!(put_at(w.e2, "m/art/x_2") < put_at(w.e2, &key));
    assert!(w.e2.get("m/art/x_1").is_some());
    // Nothing of what is saved is ever sent.
    assert!(w.e2.log.borrow().iter().all(|l| !l.contains("rc/")));
}

/// What is saved of the sweep is bounded, and a record that is not
/// fresh any more is dropped from it.
#[tokio::test(flavor = "current_thread")]
async fn what_is_saved_of_the_sweep_is_bounded_and_forgets_old_records() {
    let w = World::new();
    for g in 0..SWEEP_RECORDS + 5 {
        w.record(&format!("m/art/x_{g:04}"), b"plan").await;
        let ids = [format!("x_{g:04}"), "x_never".to_string()];
        w.generation(
            &generation(600_000, &format!("_{g:04}")),
            &[&ids[0], &ids[1]],
        )
        .await;
    }
    let counts = w.pass().await;
    assert_eq!(counts.pending as usize, SWEEP_RECORDS + 5);
    let saved: BTreeMap<String, u32> = serde_json::from_str(&known(&w).await).unwrap();
    assert_eq!(saved.len(), SWEEP_RECORDS);
    assert!(saved.values().all(|n| *n == 1));

    // An hour later none of them is fresh; one new record is.
    w.clock.advance_ms(FRESH_MS);
    let new = format!("m/g_{:013x}_new", w.clock.now().0 - 600_000);
    w.record("m/art/x_new", b"plan").await;
    w.generation(&new, &["x_new", "x_never"]).await;
    let counts = w.pass().await;
    assert_eq!(counts.pending, 1);
    assert_eq!(known(&w).await, format!("{{\"{new}\":1}}"));

    // More than the bound, written by something else: the rest is
    // dropped when it is read.
    let many: BTreeMap<String, u32> = (0..SWEEP_RECORDS + 200)
        .map(|i| (format!("{new}{i:04}"), 1))
        .collect();
    w.raw(SWEEP_KEY, serde_json::to_vec(&many).unwrap()).await;
    w.pass().await;
    let saved: BTreeMap<String, u32> = serde_json::from_str(&known(&w).await).unwrap();
    assert_eq!(saved.len(), SWEEP_RECORDS);
}

/// A record whose plans are all over there, and that could not be sent
/// itself, leaves nothing saved: the next pass asks for its plans.
#[tokio::test(flavor = "current_thread")]
async fn nothing_is_saved_of_a_record_whose_plans_are_all_over_there() {
    let w = World::new();
    let key = generation(600_000, "_a");
    w.generation(&key, &["x_1"]).await;
    w.record("m/art/x_1", b"plan").await;
    w.e2.put_500_keys.borrow_mut().push(key.clone());
    let counts = w.pass().await;
    assert_eq!((counts.failed, counts.copied), (1, 1));
    assert_eq!(known(&w).await, "");
}

/// The count in the cursor carries a large record from job to job by
/// itself: also when nothing of the sweep can be saved.
#[tokio::test(flavor = "current_thread")]
async fn a_large_record_is_finished_when_the_sweep_cannot_be_saved() {
    let w = World::new();
    let ids: Vec<String> = (0..600).map(|i| format!("x_{i:04}")).collect();
    for id in &ids {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    let key = generation(600_000, "_big");
    let names: Vec<&str> = ids.iter().map(String::as_str).collect();
    w.generation(&key, &names).await;
    let source = NoMark(&w.safety, SWEEP_KEY);
    let copier = Copier {
        safety: &source,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let mut cursor = Some(String::new());
    let mut jobs = 0;
    while let Some(at) = cursor {
        let step = copier.step(UnixMs(NOW), &at).await.unwrap();
        cursor = step.next;
        jobs += 1;
        assert!(jobs < 10, "the pass does not get past the record");
    }
    assert!(w.e2.get(&key).is_some());
    assert_eq!(asked_for(w.e2, "HEAD", "m/art/x_0000"), 2);
}

/// Three plans in a row without an answer are an outage; fewer are a
/// fault of those plans. An answer in between starts the count again,
/// and a plan that is not written asked nothing of the store.
#[tokio::test(flavor = "current_thread")]
async fn plans_without_an_answer_are_an_outage_only_three_in_a_row() {
    // One plan each: no answer, an answer, no answer, no answer, an
    // answer. The sweep goes on to the last record.
    let w = World::new();
    for (i, down) in [true, false, true, true, false].into_iter().enumerate() {
        let id = format!("x_{i}");
        w.record(&format!("m/art/{id}"), b"plan").await;
        w.generation(&generation(600_000, &format!("_{i}")), &[&id])
            .await;
        if down {
            w.e2.put_500_keys.borrow_mut().push(format!("m/art/{id}"));
        }
    }
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert_eq!(step.counts.pending, 3);
    assert!(w.e2.get(&generation(600_000, "_1")).is_some());
    assert!(w.e2.get(&generation(600_000, "_4")).is_some());
    // The walk of the same step then meets the three in one group.
    assert!(step.outage);

    // A plan that is not written, then three without an answer, in
    // one group.
    let w = World::new();
    let key = generation(600_000, "_a");
    w.generation(&key, &["x_never", "x_1", "x_2", "x_3"]).await;
    for id in ["x_1", "x_2", "x_3"] {
        w.record(&format!("m/art/{id}"), b"plan").await;
        w.e2.put_500_keys.borrow_mut().push(format!("m/art/{id}"));
    }
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(step.outage);
    assert_eq!((step.counts.pending, step.counts.failed), (1, 3));
}

/// What the sweep learned and could not save is reported; the pass
/// goes on.
#[tokio::test(flavor = "current_thread")]
async fn a_sweep_that_cannot_be_saved_is_reported_and_the_pass_goes_on() {
    let w = World::new();
    let key = generation(600_000, "_a");
    w.generation(&key, &["x_1", "x_2"]).await;
    w.record("m/art/x_1", b"plan").await;
    let source = NoMark(&w.safety, SWEEP_KEY);
    let copier = Copier {
        safety: &source,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let (outcome, counts, why) = copier.run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((outcome, why), (JobOutcome::Ack, Some(StepError::Mark)));
    let counts = counts.unwrap();
    assert_eq!((counts.pending, counts.copied), (1, 1));
    assert_eq!(known(&w).await, "");
    // With nothing to save, nothing is written and nothing reported.
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    let source = NoMark(&w.safety, SWEEP_KEY);
    let copier = Copier {
        safety: &source,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let (_, _, why) = copier.run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(why, None);
}

/// The sweep has the first ten minutes of a pass. A job of it that
/// starts later goes on with the walk, and says that the sweep was
/// left unfinished.
#[tokio::test(flavor = "current_thread")]
async fn a_sweep_whose_time_is_up_leaves_the_pass_to_the_walk() {
    let w = World::new();
    let key = generation(600_000, "_a");
    w.generation(&key, &[]).await;
    w.record("m/art/x_1", b"old").await;
    let start = format!("m/g_{:013x}", NOW - FRESH_MS);
    for cursor in [String::new(), sweep(&start)] {
        // One millisecond before: the sweep.
        let w2 = World::new();
        w2.generation(&key, &[]).await;
        w2.clock.advance_ms(SWEEP_MS - 1);
        let step = w2.copier().step(UnixMs(NOW), &cursor).await.unwrap();
        assert!(!step.late && w2.e2.get(&key).is_some());
    }
    w.clock.advance_ms(SWEEP_MS);
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(step.late);
    assert_eq!((step.next, step.walk), (None, Some(String::new())));
    assert!(w.e2.get(&key).is_none() && w.e2.get("m/art/x_1").is_some());
    // A job of the walk is not late, whenever it starts.
    let step = w.copier().step(UnixMs(NOW), &walk("")).await.unwrap();
    assert!(!step.late);

    let (outcome, counts, why) = w
        .copier()
        .run_job(&w.jobs, UnixMs(NOW), &sweep(&start))
        .await;
    assert_eq!((outcome, why), (JobOutcome::Ack, Some(StepError::Expired)));
    assert_eq!(counts.unwrap().same, 1);
    assert_eq!(saved(&w).await.as_deref(), Some(""));
    // The next pass sends what this one did not come to.
    w.clock.set(UnixMs(NOW + PASS_INTERVAL_MS));
    assert_eq!(w.pass().await.copied, 1);
    assert!(w.e2.get(&key).is_some());

    // The walk it hands over to goes on from the saved place.
    let w = World::new();
    w.record("m/art/x_1", b"old").await;
    w.record("m/art/x_2", b"old").await;
    w.raw(WALK_KEY, b"m/art/x_1".to_vec()).await;
    w.raw(BEGAN_KEY, (NOW - PASS_INTERVAL_MS).to_string().into_bytes())
        .await;
    known_store(&w).await;
    w.clock.advance_ms(SWEEP_MS);
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(step.late);
    assert!(w.e2.get("m/art/x_1").is_none() && w.e2.get("m/art/x_2").is_some());
}

/// The plans of a record are looked at six at a time, and the clock
/// and the answers of the store after each six: a job does not go on
/// for long past its time, nor against a store that is down.
#[tokio::test(flavor = "current_thread")]
async fn the_plans_of_a_record_stop_at_the_bounds_of_a_job() {
    let world = || async {
        let w = World::new();
        let ids: Vec<String> = (0..600).map(|i| format!("x_{i:04}")).collect();
        for id in &ids {
            w.record(&format!("m/art/{id}"), b"plan").await;
        }
        let names: Vec<&str> = ids.iter().map(String::as_str).collect();
        w.generation(&generation(600_000, "_big"), &names).await;
        w
    };
    let key = generation(600_000, "_big");
    let start = format!("m/g_{:013x}", NOW - FRESH_MS);

    // Every request takes a second: the job stops after a whole group.
    let w = world().await;
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let began = w.clock.now().0;
    let step = copier.step(UnixMs(NOW), "").await.unwrap();
    let did = step.counts.copied as usize;
    assert!(did > 0 && did < 60 && did.is_multiple_of(6), "{did}");
    assert!(w.clock.now().0 - began < 20_000 + 6 * 4_000);
    let next = format!("{{\"p\":\"g\",\"k\":\"{start}\",\"g\":\"{key}\",\"n\":{did}}}");
    assert_eq!(step.next, Some(next));
    assert_eq!(w.e2.puts(), did);

    // The store takes no put: the first six plans show it.
    let w = world().await;
    w.e2.put_status.set(Some(500));
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(step.outage);
    assert_eq!((step.counts.failed, step.counts.pending), (6, 1));
    let puts =
        w.e2.log
            .borrow()
            .iter()
            .filter(|l| l.starts_with("PUT "))
            .count();
    assert_eq!(puts, 6 * 4);
    assert_eq!(put_at(w.e2, "m/art/x_0006"), None);

    // The store is found down by the records before any plan is looked
    // at: no plan is asked for, and the record is held back. The cursor
    // of the step goes past it: a job that is retried does not use it.
    let w = World::new();
    w.generation(&key, &["x_1"]).await;
    w.record("m/art/x_1", b"plan").await;
    for i in 0..3 {
        // After the generation records, and in the same part of the
        // sweep: before the tenant layout.
        w.record(&format!("m/sz{i}"), b"other").await;
        w.e2.put_500_keys.borrow_mut().push(format!("m/sz{i}"));
    }
    let step = w.copier().step(UnixMs(NOW), &sweep(&start)).await.unwrap();
    assert!(step.outage);
    assert_eq!(step.next, Some(sweep("m/sz2")));
    assert!(w.e2.log.borrow().iter().all(|l| !l.contains("m/art/")));
    assert_eq!((step.counts.failed, step.counts.pending), (3, 1));
    assert_eq!(put_at(w.e2, &key), None);
}

/// A record that asked nothing of the store says nothing about it: three
/// puts without an answer are an outage, whatever else is in the group.
#[tokio::test(flavor = "current_thread")]
async fn records_that_asked_nothing_of_the_store_do_not_hide_an_outage() {
    let w = World::new();
    for i in 0..3 {
        w.raw(&format!("m/art/x_{i}"), b"not sealed".to_vec()).await;
    }
    for i in 3..6 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
        w.e2.put_500_keys.borrow_mut().push(format!("m/art/x_{i}"));
    }
    let step = w.copier().step(UnixMs(NOW), &walk("")).await.unwrap();
    assert!(step.outage);
    assert_eq!((step.counts.source_unreadable, step.counts.failed), (3, 3));
}

/// In the last pass in which a record is fresh it is not held back: the
/// walk would send it as it is, a walk later. Its plans that are there
/// still go first.
#[tokio::test(flavor = "current_thread")]
async fn a_record_fresh_for_the_last_time_is_sent_as_it_is() {
    let w = World::new();
    // Fresh in the next pass too, by one millisecond; and not. The
    // key the next sweep starts after is not fresh then either.
    let stays = generation(FRESH_MS - PASS_INTERVAL_MS, "_a");
    let goes = generation(FRESH_MS - PASS_INTERVAL_MS + 1, "_z");
    let bound = generation(FRESH_MS - PASS_INTERVAL_MS, "");
    w.generation(&stays, &["x_1", "x_never"]).await;
    w.generation(&goes, &["x_2", "x_never", "x_3"]).await;
    w.generation(&bound, &["x_never"]).await;
    for id in ["x_1", "x_2", "x_3"] {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    // Three plans and two records.
    assert_eq!((step.counts.pending, step.counts.copied), (1, 5));
    assert!(w.e2.get(&stays).is_none() && w.e2.get(&bound).is_some());
    assert!(put_at(w.e2, "m/art/x_2") < put_at(w.e2, &goes));

    // Not while the store is down.
    let w = World::new();
    w.generation(&goes, &["x_1", "x_2", "x_3"]).await;
    for id in ["x_1", "x_2", "x_3"] {
        w.record(&format!("m/art/{id}"), b"plan").await;
    }
    w.e2.put_status.set(Some(500));
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(step.outage);
    assert_eq!(put_at(w.e2, &goes), None);

    // A plan the store did not take, and one that does not open: the
    // record goes all the same, after the plan that is there.
    let w = World::new();
    w.generation(&goes, &["x_1", "x_2", "x_3"]).await;
    w.record("m/art/x_1", b"plan").await;
    w.record("m/art/x_2", b"plan").await;
    w.raw("m/art/x_3", b"not sealed".to_vec()).await;
    w.e2.put_500_keys.borrow_mut().push("m/art/x_2".into());
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(!step.outage);
    assert!(put_at(w.e2, "m/art/x_1") < put_at(w.e2, &goes));
    assert!(w.e2.get(&goes).is_some() && w.e2.get("m/art/x_2").is_none());
    // The same record, fresh in the next pass too, waits for it.
    let w = World::new();
    w.generation(&stays, &["x_1", "x_2"]).await;
    w.record("m/art/x_1", b"plan").await;
    w.record("m/art/x_2", b"plan").await;
    w.e2.put_500_keys.borrow_mut().push("m/art/x_2".into());
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert_eq!((step.outage, step.counts.pending), (false, 1));
    assert_eq!(put_at(w.e2, &stays), None);
}

/// A pass through the queue, a job that is retried coming again after
/// its delay: why its jobs fell short, and how often one was retried.
async fn retried_pass(w: &World, start: UnixMs) -> (Vec<StepError>, usize) {
    assert!(w.copier().start_pass(&w.jobs, start).await.unwrap());
    let (mut whys, mut retries) = (Vec::new(), 0);
    let mut sent = w.jobs.take();
    while let Some(job) = sent.pop() {
        assert!(sent.is_empty());
        let Job::RecoveryCopy { pass, cursor, .. } = &job.job else {
            panic!("another job");
        };
        loop {
            let (outcome, _, why) = w.copier().run_job(&w.jobs, *pass, cursor).await;
            whys.extend(why);
            let JobOutcome::Retry { delay_secs } = outcome else {
                break;
            };
            assert!(w.jobs.take().is_empty());
            retries += 1;
            w.clock
                .set(UnixMs(w.clock.now().0 + i64::from(delay_secs) * 1000));
        }
        sent = w.jobs.take();
        if let Some(next) = sent.first() {
            w.clock
                .set(UnixMs(w.clock.now().0 + i64::from(next.delay_secs) * 1000));
        }
    }
    (whys, retries)
}

/// Records of the sweep that the store never takes do not keep the
/// sweep from those behind them: its job is retried for less long than
/// the sweep has, and then goes on. Three tombstones without an answer,
/// and the generation record behind them is over there in that pass.
#[tokio::test(flavor = "current_thread")]
async fn records_without_an_answer_do_not_keep_the_sweep_from_those_behind() {
    let w = World::new();
    for i in 0..3 {
        let key = format!("m/del/g_{:013x}_t{i}", NOW - 600_000);
        w.record(&key, b"gone").await;
        w.e2.put_500_keys.borrow_mut().push(key);
    }
    let key = generation(600_000, "_a");
    w.generation(&key, &["x_1"]).await;
    w.record("m/art/x_1", b"plan").await;

    let (whys, retries) = retried_pass(&w, UnixMs(NOW)).await;
    assert!(retries > 0);
    let down = StepError::Store(RemoteError::Unavailable);
    assert!(whys.iter().all(|why| *why == down), "{whys:?}");
    assert!(put_at(w.e2, "m/art/x_1") < put_at(w.e2, &key));
    assert!(w.e2.get(&key).is_some());

    // The job was retried first, and the tombstones wait for the sweep
    // of the next pass: the walk does not go where records are fresh.
    let log = w.e2.log.borrow();
    let sent = log.iter().position(|l| *l == format!("PUT {key}")).unwrap();
    let tries = |upto: &[String]| upto.iter().filter(|l| l.ends_with("_t0")).count();
    let before = tries(&log[..sent]);
    assert!(before >= 8 && tries(&log) == before, "{before}");
    assert!(w.clock.now().0 - NOW < SWEEP_MS);
    const { assert!(SWEEP_RETRY_MS < SWEEP_MS && SWEEP_RETRY_MS < RETRY_WINDOW_MS) };
}

/// To the last millisecond a job of the sweep that found the store down
/// is retried with its cursor; after it the job is done and the next
/// one goes on behind the records that got no answer.
#[tokio::test(flavor = "current_thread")]
async fn a_job_of_the_sweep_is_retried_for_half_the_time_of_the_sweep() {
    let w = World::new();
    for i in 0..3 {
        let key = format!("m/del/g_{:013x}_t{i}", NOW - 600_000);
        w.record(&key, b"gone").await;
        w.e2.put_500_keys.borrow_mut().push(key);
    }
    let down = Some(StepError::Store(RemoteError::Unavailable));

    w.clock.set(UnixMs(NOW + SWEEP_RETRY_MS - 1));
    let (outcome, _, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((outcome, why), (JobOutcome::Retry { delay_secs: 60 }, down));
    assert!(w.jobs.take().is_empty());

    w.clock.set(UnixMs(NOW + SWEEP_RETRY_MS));
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!(counts.unwrap().failed, 3);
    let sent = w.jobs.take();
    // The next job waits: the store may be back by then.
    assert_eq!(sent[0].delay_secs, 60);
    let Job::RecoveryCopy { cursor, .. } = &sent[0].job else {
        panic!("another job");
    };
    assert!(
        cursor.starts_with("{\"p\":\"d\",\"k\":\"m/del/g_"),
        "{cursor}"
    );
    assert!(cursor.contains("_t2"), "{cursor}");

    // A job that begins in the sweep and finds the store down in the
    // walk is retried as long as a job of the walk is.
    let w = World::new();
    for i in 0..3 {
        w.record(&format!("m/art/x_{i}"), b"old").await;
        w.e2.put_500_keys.borrow_mut().push(format!("m/art/x_{i}"));
    }
    w.clock.set(UnixMs(NOW + SWEEP_RETRY_MS));
    let (outcome, _, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((outcome, why), (JobOutcome::Retry { delay_secs: 60 }, down));
    assert!(w.jobs.take().is_empty());
    assert_eq!(saved(&w).await, None);
}

/// A group of plans that asked nothing of the store says nothing about
/// it: two plans without an answer, a record whose plan is not written
/// yet, and a third plan without an answer are an outage.
#[tokio::test(flavor = "current_thread")]
async fn plans_that_asked_nothing_do_not_hide_an_outage() {
    let w = World::new();
    w.generation(&generation(600_000, "_a"), &["x_1", "x_2"])
        .await;
    w.generation(&generation(500_000, "_b"), &["x_never"]).await;
    w.generation(&generation(400_000, "_c"), &["x_3"]).await;
    for id in ["x_1", "x_2", "x_3"] {
        w.record(&format!("m/art/{id}"), b"plan").await;
        w.e2.put_500_keys.borrow_mut().push(format!("m/art/{id}"));
    }
    // The record behind the one that found it is not looked at, and is
    // held back, although the store would take it and its plan.
    let behind = generation(300_000, "_d");
    w.generation(&behind, &["x_4"]).await;
    w.record("m/art/x_4", b"plan").await;
    let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
    assert!(step.outage);
    // Found in the sweep: the walk was not begun.
    assert!(step.next.unwrap().starts_with("{\"p\":\"g\""));
    assert_eq!((step.counts.failed, step.counts.pending), (3, 4));
    assert_eq!(asked_for(w.e2, "HEAD", "m/art/x_4"), 0);
    assert_eq!(put_at(w.e2, &behind), None);
    for id in ["x_1", "x_2", "x_3"] {
        assert_eq!(asked_for(w.e2, "PUT", &format!("m/art/{id}")), 4);
    }
}

/// Refuses to read the named key: its size (`true`), or its bytes.
struct NoRead<'a>(&'a MemBlobStore, &'static str, bool);

impl BlobStore for NoRead<'_> {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.0.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        if key == self.1 && !self.2 {
            return Err(BridgeError::Blob("down".into()));
        }
        self.0.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        if key == self.1 && self.2 {
            return Err(BridgeError::Blob("down".into()));
        }
        self.0.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.0.delete(key).await
    }
    async fn delete_record(&self, refused: &recovery::Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.0.list(prefix, start_after, limit).await
    }
}

/// What is saved of the sweep and could not be read is not written
/// over: the job knows less than is saved. The pass goes on without it,
/// and says that what it found is not saved.
#[tokio::test(flavor = "current_thread")]
async fn a_sweep_that_cannot_be_read_is_not_written_over() {
    let other = generation(700_000, "_other");
    let before = format!("{{\"{other}\":5}}");
    let key = generation(600_000, "_a");
    for head in [false, true] {
        let w = World::new();
        w.raw(SWEEP_KEY, before.clone().into_bytes()).await;
        w.generation(&key, &["x_1", "x_2"]).await;
        w.record("m/art/x_1", b"plan").await;
        w.record("m/art/x_2", b"plan").await;
        w.e2.put_500_keys.borrow_mut().push("m/art/x_2".into());

        let store = NoRead(&w.safety, SWEEP_KEY, head);
        let copier = Copier {
            safety: &store,
            kek: &w.kek,
            clock: &w.clock,
            remote: &w.remote,
            maintenance: Maintenance::Off,
        };
        let step = copier.step(UnixMs(NOW), "").await.unwrap();
        assert_eq!((step.counts.copied, step.counts.pending), (1, 1));
        assert!(step.unsaved, "{head}");
        assert_eq!(known(&w).await, before);
        // A job that found nothing to save has nothing to report.
        let step = copier.step(UnixMs(NOW), &walk("")).await.unwrap();
        assert!(!step.unsaved);

        // Read, the same job saves what it found beside what was there.
        let step = w.copier().step(UnixMs(NOW), "").await.unwrap();
        assert_eq!((step.counts.pending, step.unsaved), (1, false));
        assert_eq!(known(&w).await, format!("{{\"{other}\":5,\"{key}\":1}}"));
    }
}

// ---------------------------------------------------------------------------
// The walk rests; the sweep and the hints bring over what is new
// ---------------------------------------------------------------------------

/// A safety bucket that counts the list requests it gets.
struct Counted<'a>(&'a MemBlobStore, Cell<u64>);

impl BlobStore for Counted<'_> {
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
    async fn delete_record(&self, refused: &recovery::Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.1.set(self.1.get() + 1);
        self.0.list(prefix, start_after, limit).await
    }
    // One request, as in the adapter whose listing carries size and MD5.
    async fn list_entries(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<BlobEntry>> {
        self.1.set(self.1.get() + 1);
        self.0.list_entries(prefix, after, limit).await
    }
}

/// The time saved at `key`, as it is stored.
async fn time_at(w: &World, key: &str) -> Option<String> {
    let bytes = w.safety.get(key, None).await.unwrap()?;
    Some(String::from_utf8(bytes).unwrap())
}

/// The times of the walk that are saved are about the store of `w`.
async fn known_store(w: &World) {
    w.raw(STORE_KEY, w.remote.place().into_bytes()).await;
}

/// The pass before the one at `pass` came to the end of its sweep.
async fn no_gap(w: &World, pass: UnixMs) {
    let before = (pass.0 - PASS_INTERVAL_MS).to_string();
    w.raw(SWEPT_KEY, before.into_bytes()).await;
}

fn ms(at: i64) -> Option<String> {
    Some(at.to_string())
}

/// The post job of `extent`.
fn post_job(extent: &str) -> Job {
    Job::Extent {
        v: JOB_VERSION,
        extent: ExtentId::new(extent),
        generation: GenerationId::new("g_0000000000001_a"),
        stage: OutboxStage::Post,
    }
}

/// The hint for the article plan of `extent`, made now: pass and cursor.
fn hint_for(w: &World, extent: &str) -> (UnixMs, String) {
    match plan_hint(&post_job(extent), &JobOutcome::Ack, w.clock.now()) {
        Some(Job::RecoveryCopy { pass, cursor, .. }) => (pass, cursor),
        other => panic!("{other:?}"),
    }
}

/// List requests of a day of passes, 96 of them, over a store that is
/// equal already and gets a write and a delete before every pass:
/// to the safety bucket, to the recovery store, and to both in a pass
/// in which nothing is walked. `every_pass` is the walk as it was
/// before it rested: started again by every pass.
async fn lists_of_a_day(plans: usize, every_pass: bool) -> (u64, usize, u64) {
    let w = World::new();
    for i in 0..plans {
        w.record(&format!("m/art/x_{i:05}"), b"plan").await;
    }
    for i in 0..plans / 10 {
        let id = format!("{:013x}_{i:05}", NOW - OLD - i as i64);
        w.record(&format!("m/del/g_{id}"), b"gone").await;
        w.generation(&format!("m/g_{id}"), &[]).await;
    }
    let safety = Counted(&w.safety, Cell::new(0));
    let copier = Copier {
        safety: &safety,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    // The first pass fills the store and ends the walk.
    assert!(queued_pass(&w, &copier, UnixMs(NOW)).await.is_empty());
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
    safety.1.set(0);
    w.e2.asked.borrow_mut().clear();
    let mut resting = 0;
    for n in 1..=96 {
        let start = UnixMs(NOW + n * PASS_INTERVAL_MS);
        w.clock.set(start);
        let minted = start.0 - 180_000;
        let plan = format!("m/art/x_new{n:02}");
        let written = format!("m/g_{minted:013x}_new");
        let deleted = format!("m/del/g_{minted:013x}_new");
        w.generation(&written, &[&plan["m/art/".len()..]]).await;
        w.record(&deleted, b"gone").await;
        // The extent is posted, and its hint is the job before the pass.
        w.record(&plan, b"plan").await;
        let (pass, cursor) = hint_for(&w, &plan["m/art/".len()..]);
        let (_, _, why) = copier.run_job(&w.jobs, pass, &cursor).await;
        assert_eq!(why, None);
        if every_pass {
            assert!(w.safety.lose(WALKED_KEY));
        }
        let before = (safety.1.get(), w.e2.asked.borrow().len() as u64);
        assert!(queued_pass(&w, &copier, start).await.is_empty());
        if n == 1 {
            resting = safety.1.get() - before.0 + w.e2.asked.borrow().len() as u64 - before.1;
        }
        for key in [&plan, &written, &deleted] {
            assert!(w.e2.get(key).is_some(), "{key}");
        }
    }
    (safety.1.get(), w.e2.asked.borrow().len(), resting)
}

/// What the copy asks follows what is written, not what is stored. A
/// day of passes over a store five times the size lists five times as
/// much when every pass walks, as before. With the walk at rest a pass
/// lists the same few pages whatever the store holds, and the day has
/// one walk in it.
#[tokio::test(flavor = "current_thread")]
async fn a_day_of_passes_lists_what_is_new_and_walks_once() {
    let mut days = Vec::new();
    for plans in [2_000, 10_000] {
        let before = lists_of_a_day(plans, true).await;
        let after = lists_of_a_day(plans, false).await;
        println!(
            "LIST requests of 96 passes, {} records: before safety={} store={}; after safety={} store={} (a pass at rest: {} to both)",
            plans + 2 * (plans / 10),
            before.0,
            before.1,
            after.0,
            after.1,
            after.2
        );
        days.push((before, after));
    }
    let (small, large) = (days[0], days[1]);
    // Before: with the records. What a pass lists of the fresh records
    // (at most six pages of each side: two for each kind of record of
    // the flat layout, which has them, and one for each kind of the
    // tenant layout, which has none) is the same in both.
    let walked = |day: (u64, usize, u64)| (day.0 - 96 * 6, day.1 as u64 - 96 * 6);
    assert!(walked(large.0).0 > 2 * walked(small.0).0, "{days:?}");
    assert!(walked(large.0).1 > 2 * walked(small.0).1, "{days:?}");
    // After: a pass at rest asks the same of both sizes, and little.
    assert_eq!(small.1 .2, large.1 .2, "{days:?}");
    assert!(small.1 .2 <= 12, "{days:?}");
    // A day is 95 such passes and one walk.
    // The walk has five parts; three of them hold no record here.
    let pages = |records: u64| records.div_ceil(1000) + 4 + 3;
    for ((_, after), records) in days.iter().zip([2_400, 12_000]) {
        assert!(after.0 <= 96 * 6 + pages(records), "{days:?}");
        assert!(after.1 as u64 <= 96 * 6 + pages(records), "{days:?}");
    }
    assert!(large.1 .0 * 4 < large.0 .0, "{days:?}");
}

/// An article plan written long after its generation record, between
/// two walks: no listing finds it (its key is random, and the walk
/// rests), so the post job that is done sends a hint, and the job of
/// the hint sends the plan. It is over there before the next pass.
#[tokio::test(flavor = "current_thread")]
async fn an_article_plan_written_between_walks_is_over_there_by_its_hint() {
    let w = World::new();
    w.generation(&generation(OLD, "_o"), &["x_late"]).await;
    w.record("m/art/x_0001", b"plan").await;
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
    assert_eq!(time_at(&w, BEGAN_KEY).await, ms(NOW));
    assert_eq!(w.e2.puts(), 2);

    // The extent is posted an hour later. The passes of that hour, and
    // the one after, do not find the plan: the walk rests, and they
    // list nothing below the fresh records.
    w.clock.advance_ms(4 * PASS_INTERVAL_MS);
    let plan = w.record("m/art/x_late", b"late plan").await;
    w.e2.asked.borrow_mut().clear();
    assert!(queued_pass(&w, &w.copier(), w.clock.now()).await.is_empty());
    assert_eq!(w.e2.get("m/art/x_late"), None);
    assert!(
        w.e2.asked
            .borrow()
            .iter()
            .all(|a| FRESH.iter().any(|fresh| a.starts_with(fresh))),
        "{:?}",
        w.e2.asked
    );
    let lists = w.e2.asked.borrow().len();

    // Only a post job that is done has a hint.
    let post = post_job("x_late");
    let Job::Extent {
        extent, generation, ..
    } = post.clone()
    else {
        unreachable!()
    };
    for stage in [OutboxStage::Verify, OutboxStage::Release] {
        let other = Job::Extent {
            v: JOB_VERSION,
            extent: extent.clone(),
            generation: generation.clone(),
            stage,
        };
        assert!(!w.copier().hint(&w.jobs, &other, &JobOutcome::Ack).await);
    }
    let retried = JobOutcome::Retry { delay_secs: 30 };
    assert!(!w.copier().hint(&w.jobs, &post, &retried).await);
    assert!(
        !w.copier()
            .hint(&w.jobs, &Job::Gc { v: JOB_VERSION }, &JobOutcome::Ack)
            .await
    );
    assert!(w.jobs.take().is_empty());

    assert!(w.copier().hint(&w.jobs, &post, &JobOutcome::Ack).await);
    let sent = w.jobs.take();
    assert_eq!((sent.len(), sent[0].delay_secs), (1, 0));
    let Job::RecoveryCopy { v, pass, cursor } = &sent[0].job else {
        panic!("another job");
    };
    // Pass 0: a version that knows no hints takes it for a job of a
    // pass that ended long ago, and does nothing.
    assert_eq!((*v, *pass), (JOB_VERSION, UnixMs(0)));
    assert!(!pass_due(*pass) || w.clock.now().0 - pass.0 >= PASS_INTERVAL_MS);
    let wanted = time_at(&w, WANT_KEY).await;
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, *pass, cursor).await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!(counts.unwrap().copied, 1);
    assert_eq!(w.e2.get("m/art/x_late"), Some(plan));
    // One record: no list, no next job, and nothing saved of it.
    assert_eq!(w.e2.asked.borrow().len(), lists);
    assert!(w.jobs.take().is_empty());
    assert_eq!(time_at(&w, WANT_KEY).await, wanted);

    // A second hint for it (a post job that came twice) sends nothing.
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, *pass, cursor).await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!((counts.unwrap().same, w.e2.puts()), (1, 3));
}

/// A hint is only a hint: it names one article plan, sends nothing
/// else, and whatever becomes of it the walk is not put off.
#[tokio::test(flavor = "current_thread")]
async fn a_hint_names_one_article_plan_and_nothing_else() {
    let w = World::new();
    let g = generation(OLD, "_o");
    w.record(&g, b"old").await;
    w.record("m/tk/tenant", b"a key").await;
    w.raw("m/art/x_bad", b"does not open".to_vec()).await;
    let cursor = |key: &str| format!("{{\"p\":\"x\",\"k\":\"{key}\",\"t\":{NOW}}}");
    // Not article plans: nothing is read, nothing is asked.
    for key in [g.as_str(), "m/tk/tenant", "m/art/", "rc/walk", "", "x/x_1"] {
        let (outcome, counts, why) = w.copier().run_job(&w.jobs, UnixMs(0), &cursor(key)).await;
        assert_eq!(
            (outcome, counts, why),
            (JobOutcome::Ack, None, None),
            "{key}"
        );
    }
    // Not written (or the hint of a job that posted nothing).
    let (outcome, counts, why) = w
        .copier()
        .run_job(&w.jobs, UnixMs(0), &cursor("m/art/x_none"))
        .await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!(counts.unwrap(), CopyCounts::default());
    // One that does not open is not sent.
    let (outcome, counts, why) = w
        .copier()
        .run_job(&w.jobs, UnixMs(0), &cursor("m/art/x_bad"))
        .await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!(counts.unwrap().source_unreadable, 1);
    assert!(w.e2.log.borrow().is_empty(), "{:?}", w.e2.log);
    assert!(w.jobs.take().is_empty());
    assert_eq!(time_at(&w, WANT_KEY).await, None);

    // The step of a pass does nothing with the cursor of a hint.
    let step = w
        .copier()
        .step(UnixMs(0), &cursor("m/art/x_bad"))
        .await
        .unwrap();
    assert_eq!(
        (step.counts, step.next, step.walk),
        (CopyCounts::default(), None, None)
    );
    assert!(w.e2.log.borrow().is_empty());

    // In a restore no hint is sent, and none is done.
    let mut restoring = w.copier();
    restoring.maintenance = Maintenance::Restore;
    assert!(
        !restoring
            .hint(&w.jobs, &post_job("x_1"), &JobOutcome::Ack)
            .await
    );
    let (outcome, counts, why) = restoring
        .run_job(&w.jobs, UnixMs(0), &cursor("m/art/x_bad"))
        .await;
    assert_eq!((outcome, counts, why), (JobOutcome::Ack, None, None));
    assert!(w.jobs.take().is_empty());

    // A hint that cannot be sent asks for the walk.
    assert!(
        !w.copier()
            .hint(&NoQueue, &post_job("x_1"), &JobOutcome::Ack)
            .await
    );
    assert_eq!(time_at(&w, WANT_KEY).await, ms(NOW));

    // A plan the store refuses: not tried again, and the walk is asked.
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    w.e2.put_status.set(Some(403));
    let (pass, at) = hint_for(&w, "x_1");
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, pass, &at).await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!(counts.unwrap().refused, 1);
    assert_eq!(time_at(&w, WANT_KEY).await, ms(NOW));
}

/// The store is down for longer than a record is fresh. The sweep
/// cannot send what was written meanwhile, and the hints are given up;
/// the walk that comes soon after sends all of it. While the store is
/// down, the hints ask it once in five minutes; the others ask nothing.
#[tokio::test(flavor = "current_thread")]
async fn what_the_sweep_and_the_hints_missed_in_an_outage_is_caught_by_the_walk() {
    let w = World::new();
    w.record("m/art/x_0001", b"plan").await;
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    assert_eq!(w.e2.puts(), 1);

    // Down from minute 14. A delete and a write at minute 16; the
    // extent of the write is posted at minute 20, another at minute 21.
    w.e2.status.set(Some(503));
    let minted = NOW + 16 * 60_000;
    let deleted = format!("m/del/g_{minted:013x}_t");
    let written = format!("m/g_{minted:013x}_w");
    w.record(&deleted, b"gone").await;
    w.generation(&written, &["x_out1", "x_out2"]).await;
    let missed = [
        deleted.as_str(),
        written.as_str(),
        "m/art/x_out1",
        "m/art/x_out2",
    ];
    let behind = |e2: &FakeE2| missed.iter().filter(|k| e2.get(k).is_none()).count();

    let down = StepError::Store(RemoteError::Unavailable);
    let (whys, retries) = retried_pass(&w, UnixMs(NOW + PASS_INTERVAL_MS)).await;
    assert!(
        retries > 0
            && whys
                .iter()
                .all(|why| *why == down || *why == StepError::Expired),
        "{whys:?}"
    );

    w.clock.set(UnixMs(NOW + 20 * 60_000));
    w.record("m/art/x_out1", b"plan one").await;
    let (pass, first) = hint_for(&w, "x_out1");
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, pass, &first).await;
    let again = JobOutcome::Retry {
        delay_secs: HINT_RETRY_SECS,
    };
    assert_eq!((outcome, why), (again, Some(down)));
    assert_eq!(counts.unwrap().failed, 1);
    // The time after its tries, which took seconds.
    let found_down = w.clock.now().0;
    assert!(found_down > NOW + 20 * 60_000);
    assert_eq!(time_at(&w, DOWN_KEY).await, ms(found_down));

    // The next hint, a minute later, asks nothing of the store.
    w.clock.set(UnixMs(NOW + 21 * 60_000));
    assert!(w.clock.now().0 - found_down < HINT_PAUSE_MS);
    w.record("m/art/x_out2", b"plan two").await;
    let (pass, second) = hint_for(&w, "x_out2");
    let asked = w.e2.log.borrow().len();
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, pass, &second).await;
    assert_eq!((outcome, counts, why), (again, None, Some(down)));
    assert_eq!(w.e2.log.borrow().len(), asked);
    // After the pause one asks again, and finds it down again.
    w.clock.set(UnixMs(found_down + HINT_PAUSE_MS));
    let (outcome, _, _) = w.copier().run_job(&w.jobs, pass, &second).await;
    assert_eq!(outcome, again);
    assert!(w.e2.log.borrow().len() > asked);
    // A hint is given up when it is ten minutes old, held back or not.
    w.safety.lose(WANT_KEY);
    for (made, cursor) in [(NOW + 20 * 60_000, &first), (NOW + 21 * 60_000, &second)] {
        w.clock.set(UnixMs(made + HINT_RETRY_MS - 1));
        let (outcome, _, _) = w.copier().run_job(&w.jobs, pass, cursor).await;
        assert_eq!(outcome, again);
        assert_eq!(time_at(&w, WANT_KEY).await, None);
        w.clock.set(UnixMs(made + HINT_RETRY_MS));
        let (outcome, _, why) = w.copier().run_job(&w.jobs, pass, cursor).await;
        assert_eq!((outcome, why), (JobOutcome::Ack, Some(down)));
        // (The time after the tries of the one that asked the store.)
        let wanted: i64 = time_at(&w, WANT_KEY).await.unwrap().parse().unwrap();
        assert!((0..60_000).contains(&(wanted - made - HINT_RETRY_MS)));
        w.safety.lose(WANT_KEY);
    }
    assert!(w.jobs.take().is_empty());

    // Down until minute 100: the passes get nowhere, and say so.
    for n in 2..=6 {
        let (whys, _) = retried_pass(&w, UnixMs(NOW + n * PASS_INTERVAL_MS)).await;
        assert!(
            whys.contains(&down)
                && whys
                    .iter()
                    .all(|why| *why == down || *why == StepError::Expired),
            "{whys:?}"
        );
    }
    let wanted: i64 = time_at(&w, WANT_KEY).await.unwrap().parse().unwrap();
    assert!(wanted > NOW + 6 * PASS_INTERVAL_MS);
    assert_eq!(behind(w.e2), 4);

    // The store is back. What was written at minute 16 is not fresh any
    // more: the sweep does not see it, and the walk rests.
    w.e2.status.set(None);
    let last_rest = WALK_SOON_MS / PASS_INTERVAL_MS - 1;
    for n in 7..=last_rest {
        let start = UnixMs(NOW + n * PASS_INTERVAL_MS);
        w.clock.set(start);
        assert!(queued_pass(&w, &w.copier(), start).await.is_empty());
        assert_eq!(behind(w.e2), 4, "pass {n}");
    }
    // Three hours after the last walk ended the walk comes, because it
    // was asked for: a day is not waited.
    let start = UnixMs(NOW + WALK_SOON_MS);
    w.clock.set(start);
    assert!(queued_pass(&w, &w.copier(), start).await.is_empty());
    assert_eq!(behind(w.e2), 0);
    for key in missed {
        assert_eq!(
            w.e2.get(key),
            w.safety.stored(key).map(|b| b.bytes),
            "{key}"
        );
    }
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(start.0));
    assert_eq!(time_at(&w, BEGAN_KEY).await, ms(start.0));

    // That walk answered what was asked: the next one is a day later.
    w.e2.set("m/art/x_0001", b"damaged over there");
    for (after, mended) in [
        (WALK_SOON_MS, false),
        (WALK_INTERVAL_MS - PASS_INTERVAL_MS, false),
        (WALK_INTERVAL_MS, true),
    ] {
        let at = UnixMs(start.0 + after);
        w.clock.set(at);
        no_gap(&w, at).await;
        assert!(queued_pass(&w, &w.copier(), at).await.is_empty());
        let equal = w.e2.get("m/art/x_0001") == w.safety.stored("m/art/x_0001").map(|b| b.bytes);
        assert_eq!(equal, mended, "{after}");
    }
}

/// A record nobody knows is missing over there (no job failed, nothing
/// asked for the walk) is sent by the walk of the next day; so is one
/// whose copy was damaged over there.
#[tokio::test(flavor = "current_thread")]
async fn what_nobody_knows_is_missing_is_caught_by_the_daily_walk() {
    let w = World::new();
    w.record("m/art/x_0001", b"plan").await;
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    // A plan whose hint was lost, and a copy that went bad.
    w.clock.advance_ms(PASS_INTERVAL_MS);
    w.record("m/art/x_0002", b"plan without a hint").await;
    w.e2.set("m/art/x_0001", b"damaged");
    let whole = |e2: &FakeE2| {
        ["m/art/x_0001", "m/art/x_0002"]
            .iter()
            .all(|k| e2.get(k) == w.safety.stored(k).map(|b| b.bytes))
    };
    let mut walks = 0;
    for n in 1..=96 {
        let start = UnixMs(NOW + n * PASS_INTERVAL_MS);
        w.clock.set(start);
        w.e2.asked.borrow_mut().clear();
        assert!(queued_pass(&w, &w.copier(), start).await.is_empty());
        let walked = w.e2.asked.borrow().iter().any(|a| a.is_empty());
        walks += usize::from(walked);
        assert_eq!(whole(w.e2), n == 96, "pass {n}");
        assert_eq!(walked, n == 96, "pass {n}");
    }
    assert_eq!(walks, 1);
    // Asked once, by the first pass there ever was, before its walk.
    assert_eq!(time_at(&w, WANT_KEY).await, ms(NOW - 1));
}

/// A walk longer than a pass goes on from pass to pass, and through a
/// job that is lost, from the place that was saved. Its start is saved
/// once, its end when it comes to the end of the keys; then it rests
/// for a day, and starts again from the first key.
#[tokio::test(flavor = "current_thread")]
async fn the_walk_goes_on_across_passes_then_rests_for_a_day() {
    const RECORDS: usize = 900;
    let w = World::new();
    for i in 0..RECORDS {
        w.record(&format!("m/art/x_{i:04}"), b"plan").await;
    }
    // One key per answer of the store, a second per request.
    w.e2.page.set(1);
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let behind = |e2: &FakeE2| RECORDS - e2.objects.borrow().len();
    let mut places: Vec<String> = Vec::new();
    let mut ended_in = None;
    for n in 0..8 {
        let start = UnixMs(NOW + n * PASS_INTERVAL_MS);
        if w.clock.now().0 < start.0 {
            w.clock.set(start);
        }
        assert!(copier.start_pass(&w.jobs, start).await.unwrap());
        let mut jobs = 0;
        loop {
            let sent = w.jobs.take();
            if sent.is_empty() {
                break;
            }
            let Job::RecoveryCopy { pass, cursor, .. } = &sent[0].job else {
                panic!("another job");
            };
            jobs += 1;
            // The third job of the second pass is lost.
            if (n, jobs) == (1, 3) {
                break;
            }
            let (outcome, _, why) = copier.run_job(&w.jobs, *pass, cursor).await;
            assert_eq!((outcome, why), (JobOutcome::Ack, None), "pass {n}");
        }
        if ended_in.is_some() {
            // At rest: one job, the sweep, and nothing of the walk.
            assert_eq!(jobs, 1, "pass {n}");
            continue;
        }
        // The start is the first pass, whichever pass goes on.
        assert_eq!(time_at(&w, BEGAN_KEY).await, ms(NOW), "pass {n}");
        let place = saved(&w).await.unwrap();
        if behind(w.e2) == 0 && place.is_empty() {
            assert_eq!(time_at(&w, WALKED_KEY).await, ms(start.0));
            ended_in = Some(n);
        } else {
            // Under way: no end is saved, and the place moved on.
            assert_eq!(time_at(&w, WALKED_KEY).await, None, "pass {n}");
            assert!(places.last().is_none_or(|last| *last < place), "{places:?}");
            places.push(place);
        }
    }
    let ended_in = ended_in.expect("the walk ended");
    assert!((3..=6).contains(&ended_in), "{ended_in} {places:?}");
    // Each record was sent once: no pass went back over what was done.
    assert_eq!(w.e2.puts(), RECORDS);
    let ended = NOW + ended_in * PASS_INTERVAL_MS;
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(ended));
    assert_eq!(time_at(&w, WANT_KEY).await, ms(NOW - 1));

    // A day after the pass that ended it, and not a pass sooner, the
    // walk starts from the first key again.
    for (at, starts) in [
        (ended + WALK_INTERVAL_MS - PASS_INTERVAL_MS, false),
        (ended + WALK_INTERVAL_MS, true),
    ] {
        w.clock.set(UnixMs(at));
        no_gap(&w, UnixMs(at)).await;
        w.e2.asked.borrow_mut().clear();
        let (_, counts, why) = copier.run_job(&w.jobs, UnixMs(at), "").await;
        assert_eq!(why, None);
        assert_eq!(counts.unwrap().same > 0, starts);
        assert_eq!(w.e2.asked.borrow().iter().any(|a| a.is_empty()), starts);
        let began = if starts { at } else { NOW };
        assert_eq!(time_at(&w, BEGAN_KEY).await, ms(began));
        w.jobs.take();
    }
}

/// The times saved of the walk are hints. Whatever stands in them, the
/// walk starts a day after the last end that is believed, at the
/// latest; the others can only bring it forward.
#[tokio::test(flavor = "current_thread")]
async fn any_saved_time_of_the_walk_is_safe() {
    /// A world with one record of the walk, and these times saved.
    async fn world(times: &[(&str, &[u8])]) -> World {
        let w = World::new();
        w.record("m/art/x_1", b"plan").await;
        for (key, body) in times {
            w.raw(key, body.to_vec()).await;
        }
        known_store(&w).await;
        w
    }
    async fn walks(w: &World, at: i64) -> bool {
        w.clock.set(UnixMs(at));
        no_gap(w, UnixMs(at)).await;
        let (_, counts, why) = w.copier().run_job(&w.jobs, UnixMs(at), "").await;
        assert_eq!(why, None);
        w.jobs.take();
        counts.unwrap().records > 0
    }
    let t = |at: i64| at.to_string().into_bytes();
    let hour = 3_600_000;
    let long = vec![b'1'; 1024 * 1024];

    // An end that is no time, or has not come: the walk starts now.
    let not_times: [&[u8]; 9] = [
        b"",
        b"soon",
        b"-5",
        b"+5",
        b" 1800000000000",
        b"1.8e12",
        b"\xff\xfe",
        b"999999999999999999999",
        &long,
    ];
    for body in not_times {
        let w = world(&[(WALKED_KEY, body)]).await;
        assert!(walks(&w, NOW).await, "{:?}", &body[..body.len().min(24)]);
    }
    for ahead in [PASS_INTERVAL_MS, hour, 400 * 24 * hour] {
        let w = world(&[(WALKED_KEY, &t(NOW + ahead))]).await;
        assert!(walks(&w, NOW).await, "{ahead}");
    }
    let w = world(&[]).await;
    assert!(walks(&w, NOW).await);

    // An end that is past is believed, and for a day only, whatever the
    // other times say.
    let far = t(NOW + 400 * 24 * hour);
    let others: [&[u8]; 5] = [b"", b"soon", &far, &t(0), &long];
    for want in others {
        for began in others {
            let times = [
                (WALKED_KEY, t(NOW - hour)),
                (WANT_KEY, want.to_vec()),
                (BEGAN_KEY, began.to_vec()),
                (DOWN_KEY, want.to_vec()),
            ];
            let times: Vec<(&str, &[u8])> = times.iter().map(|(k, b)| (*k, b.as_slice())).collect();
            let w = world(&times).await;
            assert!(!walks(&w, NOW).await);
            assert!(walks(&w, NOW + 23 * hour).await);
        }
    }

    // Between three hours and a day after the end, the walk starts
    // when it was asked for since the last one began.
    let ended = NOW - 4 * hour;
    let cases: [(Option<i64>, Option<i64>, bool); 7] = [
        (None, None, false),
        (None, Some(ended), false),
        // Asked, and no start is known: taken as asked since.
        (Some(NOW - hour), None, true),
        (Some(NOW - hour), Some(ended), true),
        (Some(ended), Some(ended), true),
        // Asked before the last walk began: that walk answered it.
        (Some(ended - hour), Some(ended), false),
        // A time that has not come asks for nothing.
        (Some(NOW + PASS_INTERVAL_MS), Some(ended), false),
    ];
    for (want, began, starts) in cases {
        let mut times = vec![(WALKED_KEY, t(ended))];
        times.extend(want.map(|at| (WANT_KEY, t(at))));
        times.extend(began.map(|at| (BEGAN_KEY, t(at))));
        let times: Vec<(&str, &[u8])> = times.iter().map(|(k, b)| (*k, b.as_slice())).collect();
        let w = world(&times).await;
        assert_eq!(walks(&w, NOW).await, starts, "{want:?} {began:?}");
        // Asked or not, it does not start in the first three hours.
        let w = world(&times).await;
        w.raw(WALKED_KEY, t(NOW - 3 * hour + 1)).await;
        assert!(!walks(&w, NOW).await, "{want:?} {began:?}");
    }

    // A walk that is under way (one began after the last ended) goes
    // on, and one whose place was lost begins again, however short the
    // rest was. A place alone does not make a walk.
    for (place, began, goes) in [
        (Some("m/art/x_0"), Some(NOW - PASS_INTERVAL_MS), true),
        (None, Some(NOW - PASS_INTERVAL_MS), true),
        (Some("m/art/x_0"), Some(NOW - 2 * hour), false),
        (Some("m/art/x_0"), None, false),
        // A start that has not come is none.
        (Some("m/art/x_0"), Some(NOW + PASS_INTERVAL_MS), false),
    ] {
        let w = world(&[(WALKED_KEY, &t(NOW - hour))]).await;
        if let Some(place) = place {
            w.raw(WALK_KEY, place.as_bytes().to_vec()).await;
        }
        if let Some(began) = began {
            w.raw(BEGAN_KEY, t(began)).await;
        }
        assert_eq!(walks(&w, NOW).await, goes, "{place:?} {began:?}");
    }

    // The time the store was found down holds a hint back for five
    // minutes after it, and no other value holds one back.
    let held: [(&[u8], bool); 7] = [
        (&t(NOW), true),
        (&t(NOW - HINT_PAUSE_MS + 1), true),
        (&t(NOW - HINT_PAUSE_MS), false),
        (&t(NOW + 1), false),
        (&far, false),
        (b"down", false),
        (&long, false),
    ];
    for (body, holds) in held {
        let w = world(&[(DOWN_KEY, body)]).await;
        let (pass, cursor) = hint_for(&w, "x_1");
        let (outcome, counts, _) = w.copier().run_job(&w.jobs, pass, &cursor).await;
        assert_eq!(outcome != JobOutcome::Ack, holds);
        assert_eq!(counts.is_none(), holds);
        assert_eq!(w.e2.get("m/art/x_1").is_none(), holds);
    }
}

/// A walk that was asked for begins, and the job dies before its place
/// is saved: the walk is not taken as done. The next pass begins it
/// again, though what asked for it is older than its start.
#[tokio::test(flavor = "current_thread")]
async fn a_walk_that_began_and_saved_no_place_begins_again() {
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    w.record("m/art/x_2", b"a plan nothing sent").await;
    let asked = NOW + PASS_INTERVAL_MS;
    w.raw(WANT_KEY, asked.to_string().into_bytes()).await;
    // The walk comes three hours after the last; its start is saved,
    // and nothing else of it.
    let begins = NOW + WALK_SOON_MS;
    w.raw(BEGAN_KEY, begins.to_string().into_bytes()).await;
    assert_eq!(saved(&w).await.as_deref(), Some(""));
    let next = UnixMs(begins + PASS_INTERVAL_MS);
    w.clock.set(next);
    no_gap(&w, next).await;
    assert!(queued_pass(&w, &w.copier(), next).await.is_empty());
    assert!(w.e2.get("m/art/x_2").is_some());
    assert_eq!(time_at(&w, BEGAN_KEY).await, ms(next.0));
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(next.0));
}

/// Passes that did not run are a gap nobody saw: what was written in
/// it may be too old for the sweep. The first pass after it asks for
/// the walk, which comes three hours after the last one and not a day.
/// So does a pass after one whose sweep did not come to its end.
#[tokio::test(flavor = "current_thread")]
async fn a_gap_in_the_passes_asks_for_the_walk() {
    let w = World::new();
    w.record("m/art/x_1", b"plan").await;
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    assert_eq!(time_at(&w, SWEPT_KEY).await, ms(NOW));
    // A delete, and then no pass for two hours (the copy was off).
    let deleted = format!("m/del/g_{:013x}_t", NOW + 60_000);
    w.record(&deleted, b"gone").await;
    let pass = |n: i64| UnixMs(NOW + n * PASS_INTERVAL_MS);
    for n in 8..=96 {
        w.clock.set(pass(n));
        assert!(queued_pass(&w, &w.copier(), pass(n)).await.is_empty());
        assert_eq!(time_at(&w, SWEPT_KEY).await, ms(pass(n).0));
        // Asked by the first pass after the gap, and only by it.
        assert_eq!(time_at(&w, WANT_KEY).await, ms(pass(8).0 - 1), "pass {n}");
        let walked = n * PASS_INTERVAL_MS >= WALK_SOON_MS;
        assert_eq!(w.e2.get(&deleted).is_some(), walked, "pass {n}");
        let ended = if walked { NOW + WALK_SOON_MS } else { NOW };
        assert_eq!(time_at(&w, WALKED_KEY).await, ms(ended), "pass {n}");
    }

    // A pass whose jobs were lost in the sweep saved no end of it.
    let w = World::new();
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    w.clock.set(pass(1));
    assert!(w.copier().start_pass(&w.jobs, pass(1)).await.unwrap());
    assert_eq!(w.jobs.take().len(), 1);
    w.clock.set(pass(2));
    assert!(queued_pass(&w, &w.copier(), pass(2)).await.is_empty());
    assert_eq!(time_at(&w, WANT_KEY).await, ms(pass(2).0 - 1));
    // Any value there that is not the pass before asks; one that has
    // not come yet does not, and is written over.
    for (body, asks) in [
        (&b"soon"[..], true),
        (b"0", true),
        (b"9999999999999999", true),
    ] {
        let w = World::new();
        w.raw(SWEPT_KEY, body.to_vec()).await;
        assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
        assert_eq!(time_at(&w, WANT_KEY).await.is_some(), asks);
        assert_eq!(time_at(&w, SWEPT_KEY).await, ms(NOW));
    }
}

/// An end of the walk that has not come yet is no end. A walk longer
/// than a pass still goes on from its place, and comes to its end; it
/// does not begin again in every pass.
#[tokio::test(flavor = "current_thread")]
async fn an_end_in_the_future_does_not_begin_the_walk_in_every_pass() {
    let w = World::new();
    for i in 0..(2 * JOB_COPIES + 1) {
        w.record(&format!("m/art/x_{i:04}"), b"plan").await;
    }
    let far = (NOW + 400 * 24 * 3_600_000).to_string();
    w.raw(WALKED_KEY, far.into_bytes()).await;
    // One job of the walk in a pass; the rest of its jobs are lost.
    let mut passes = 0;
    while time_at(&w, WALKED_KEY).await != ms(w.clock.now().0) {
        passes += 1;
        assert!(passes <= 4, "the walk does not end");
        let pass = UnixMs(NOW + passes * PASS_INTERVAL_MS);
        w.clock.set(pass);
        let (_, _, why) = w.copier().run_job(&w.jobs, pass, "").await;
        assert_eq!(why, None);
        w.jobs.take();
        assert_eq!(time_at(&w, BEGAN_KEY).await, ms(NOW + PASS_INTERVAL_MS));
    }
    assert_eq!((passes, w.e2.puts()), (3, 2 * JOB_COPIES + 1));
}

/// A walk begins over the place of an earlier one, and its job dies
/// when its start is saved and its own place is not. The job that
/// comes again does not go on from the old place: the walk begins
/// again, and ends only when it has been through every key.
#[tokio::test(flavor = "current_thread")]
async fn a_start_saved_over_an_old_place_does_not_go_on_from_it() {
    let w = World::new();
    for i in 0..4 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    w.raw(WALK_KEY, b"m/art/x_2".to_vec()).await;
    // The start is saved after the old place is cleared: with the place
    // not writable, no start is saved either.
    let stuck = NoMark(&w.safety, WALK_KEY);
    let copier = Copier {
        safety: &stuck,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let (_, _, why) = copier.run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(why, Some(StepError::Mark));
    assert_eq!(time_at(&w, BEGAN_KEY).await, None);
    w.jobs.take();
    // And a start that is there with the old place still under it (a
    // job of the version before died there) is never trusted with it
    // again once a walk begins: the place is cleared first.
    let w = World::new();
    for i in 0..4 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    w.raw(WALK_KEY, b"m/art/x_2".to_vec()).await;
    let (_, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((counts.unwrap().copied, why), (4, None));
    assert_eq!(saved(&w).await.as_deref(), Some(""));
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
}

/// The end of the walk cannot be saved. The place does not stay near
/// the end, where every later pass would walk the last keys only: it
/// goes back to the first key, and the next pass goes through every
/// key again. It is reported each time.
#[tokio::test(flavor = "current_thread")]
async fn an_end_that_cannot_be_saved_does_not_leave_the_walk_at_its_end() {
    let w = World::new();
    for i in 0..(2 * JOB_COPIES + 1) {
        w.record(&format!("m/art/x_{i:04}"), b"plan").await;
    }
    let stuck = NoMark(&w.safety, WALKED_KEY);
    let copier = Copier {
        safety: &stuck,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    for n in 0..3 {
        let pass = UnixMs(NOW + n * PASS_INTERVAL_MS);
        w.clock.set(pass);
        // The copy of the first key is damaged at the store: only a
        // walk from the first key finds it.
        w.e2.set("m/art/x_0000", b"other");
        let whys = queued_pass(&w, &copier, pass).await;
        assert!(whys.contains(&StepError::Mark), "pass {n}: {whys:?}");
        assert_ne!(w.e2.get("m/art/x_0000").as_deref(), Some(&b"other"[..]));
        assert_eq!(saved(&w).await.as_deref(), Some(""), "pass {n}");
        assert_eq!(time_at(&w, WALKED_KEY).await, None);
        assert_eq!(time_at(&w, BEGAN_KEY).await, ms(pass.0), "pass {n}");
    }
}

/// A place that lies under a walk at rest is cleared, so that a start
/// that turns up later does not go on from it and rest for a day with
/// the keys before it not walked.
#[tokio::test(flavor = "current_thread")]
async fn a_place_under_a_walk_at_rest_is_cleared() {
    let w = World::new();
    for i in 0..4 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
    w.raw(WALK_KEY, b"m/art/x_2".to_vec()).await;
    let pass = |n: i64| UnixMs(NOW + n * PASS_INTERVAL_MS);
    w.clock.set(pass(1));
    assert!(queued_pass(&w, &w.copier(), pass(1)).await.is_empty());
    assert_eq!(saved(&w).await.as_deref(), Some(""));
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
    // The start turns up: the walk goes through every key.
    w.raw(BEGAN_KEY, (pass(1).0 + 1).to_string().into_bytes())
        .await;
    w.e2.set("m/art/x_0", b"other");
    w.clock.set(pass(2));
    assert!(queued_pass(&w, &w.copier(), pass(2)).await.is_empty());
    assert_ne!(w.e2.get("m/art/x_0").as_deref(), Some(&b"other"[..]));
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(pass(2).0));
}

/// The first job of a pass after a gap does not write its time over a
/// later one: a job that asked for the walk after the pass started is
/// not forgotten.
#[tokio::test(flavor = "current_thread")]
async fn a_gap_does_not_write_over_a_later_time_that_asks_for_the_walk() {
    let w = World::new();
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    let pass = UnixMs(NOW + 8 * PASS_INTERVAL_MS);
    w.clock.set(pass);
    let asked = (pass.0 + 5).to_string();
    w.raw(WANT_KEY, asked.clone().into_bytes()).await;
    assert!(queued_pass(&w, &w.copier(), pass).await.is_empty());
    assert_eq!(time_at(&w, WANT_KEY).await, Some(asked));
    // An older one, or one that has not come yet, is written over.
    for old in [pass.0 - 2, pass.0 + PASS_INTERVAL_MS] {
        let later = UnixMs(pass.0 + 8 * PASS_INTERVAL_MS);
        w.clock.set(later);
        w.raw(WANT_KEY, old.to_string().into_bytes()).await;
        w.raw(SWEPT_KEY, b"0".to_vec()).await;
        assert!(queued_pass(&w, &w.copier(), later).await.is_empty());
        assert_eq!(time_at(&w, WANT_KEY).await, ms(later.0 - 1));
    }
}

/// The copy is pointed at another bucket or prefix, which holds
/// nothing. The times of the walk are about the store before: they
/// count for nothing, and the next pass walks every key.
#[tokio::test(flavor = "current_thread")]
async fn the_times_of_the_walk_are_about_one_store_only() {
    for other in [Some(&b"0123456789abcdef"[..]), Some(b""), None] {
        let w = World::new();
        for i in 0..4 {
            w.record(&format!("m/art/x_{i}"), b"plan").await;
        }
        assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
        assert_eq!(time_at(&w, STORE_KEY).await, Some(w.remote.place()));
        // The walk rests, and does not see a copy that is not right.
        w.e2.set("m/art/x_0", b"other");
        let pass = |n: i64| UnixMs(NOW + n * PASS_INTERVAL_MS);
        w.clock.set(pass(1));
        assert!(queued_pass(&w, &w.copier(), pass(1)).await.is_empty());
        assert_eq!(w.e2.get("m/art/x_0").as_deref(), Some(&b"other"[..]));
        // What is saved names another store, or none.
        match other {
            Some(name) => w.raw(STORE_KEY, name.to_vec()).await,
            None => w.safety.delete(STORE_KEY).await.unwrap(),
        }
        w.clock.set(pass(2));
        assert!(queued_pass(&w, &w.copier(), pass(2)).await.is_empty());
        assert_ne!(w.e2.get("m/art/x_0").as_deref(), Some(&b"other"[..]));
        assert_eq!(time_at(&w, STORE_KEY).await, Some(w.remote.place()));
        assert_eq!(time_at(&w, WALKED_KEY).await, ms(pass(2).0));
    }
}

/// A walk is under way, with its place saved, when the copy is pointed
/// at another store: the place counts for nothing there, and the walk
/// goes through every key. And while the name of the store cannot be
/// saved, every pass does, and says so.
#[tokio::test(flavor = "current_thread")]
async fn a_walk_under_way_begins_again_at_another_store() {
    let w = World::new();
    for i in 0..4 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    w.raw(WALK_KEY, b"m/art/x_2".to_vec()).await;
    w.raw(BEGAN_KEY, (NOW - PASS_INTERVAL_MS).to_string().into_bytes())
        .await;
    w.raw(STORE_KEY, b"0123456789abcdef".to_vec()).await;
    let (_, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((counts.unwrap().copied, why), (4, None));
    assert_eq!(time_at(&w, STORE_KEY).await, Some(w.remote.place()));
    // A body there that is far too large is not read, and is another store.
    w.raw(STORE_KEY, vec![b'a'; 4096]).await;
    let gets = w.safety.gets();
    let pass = UnixMs(NOW + PASS_INTERVAL_MS);
    w.clock.set(pass);
    w.e2.set("m/art/x_0", b"other");
    let (_, counts, why) = w.copier().run_job(&w.jobs, pass, "").await;
    assert_eq!((counts.unwrap().copied, why), (1, None));
    assert!(w.safety.gets() > gets);
    assert_eq!(time_at(&w, STORE_KEY).await, Some(w.remote.place()));

    let w = World::new();
    for i in 0..4 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
    }
    let stuck = NoMark(&w.safety, STORE_KEY);
    let copier = Copier {
        safety: &stuck,
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    for n in 0..3 {
        let pass = UnixMs(NOW + n * PASS_INTERVAL_MS);
        w.clock.set(pass);
        w.e2.set("m/art/x_0", b"other");
        let whys = queued_pass(&w, &copier, pass).await;
        assert!(whys.contains(&StepError::Mark), "pass {n}: {whys:?}");
        assert_ne!(w.e2.get("m/art/x_0").as_deref(), Some(&b"other"[..]));
    }
}

/// A mark of the walk that cannot be read is not a mark that is not
/// there: the job stops and comes again, and no mark is written. Taken
/// as absent, a start that cannot be read would end a walk under way.
#[tokio::test(flavor = "current_thread")]
async fn a_mark_of_the_walk_that_cannot_be_read_stops_the_job() {
    for key in [WALK_KEY, WALKED_KEY, BEGAN_KEY, STORE_KEY] {
        for head in [false, true] {
            let w = World::new();
            for i in 0..4 {
                w.record(&format!("m/art/x_{i}"), b"plan").await;
            }
            // A walk under way, at this store.
            known_store(&w).await;
            w.raw(WALK_KEY, b"m/art/x_1".to_vec()).await;
            w.raw(
                WALKED_KEY,
                (NOW - 3 * PASS_INTERVAL_MS).to_string().into_bytes(),
            )
            .await;
            w.raw(BEGAN_KEY, (NOW - PASS_INTERVAL_MS).to_string().into_bytes())
                .await;
            let down = NoRead(&w.safety, key, head);
            let copier = Copier {
                safety: &down,
                kek: &w.kek,
                clock: &w.clock,
                remote: &w.remote,
                maintenance: Maintenance::Off,
            };
            let (outcome, counts, why) = copier.run_job(&w.jobs, UnixMs(NOW), "").await;
            assert!(
                matches!(outcome, JobOutcome::Retry { .. }),
                "{key} head={head}: {outcome:?}"
            );
            assert_eq!((counts, why), (None, Some(StepError::Source)), "{key}");
            assert_eq!(time_at(&w, WALK_KEY).await.as_deref(), Some("m/art/x_1"));
            assert_eq!(
                time_at(&w, BEGAN_KEY).await,
                Some((NOW - PASS_INTERVAL_MS).to_string())
            );
            assert_eq!(w.e2.get("m/art/x_2"), None, "{key} head={head}");
        }
    }
}

// ---------------------------------------------------------------------------
// The two layouts of record names: `m/…` and `m/x/<tenant id>/…`
// ---------------------------------------------------------------------------

/// The directory of the tenant layout as this version writes it.
const TENANT: &str = "m/x/t_0000000000000000/";

/// The key of the tenant layout for the same record as `flat`.
fn in_tenant(flat: &str) -> String {
    format!("{TENANT}{}", &flat["m/".len()..])
}

/// A pass copies the records of the flat layout and of the tenant
/// layout, each under the name it has: old and fresh, of every kind,
/// and also what this version cannot name (the records of another
/// tenant, a kind of record a later version adds, the keys on the
/// bounds of the parts of a pass). Tenant keys stay.
#[tokio::test(flavor = "current_thread")]
async fn a_pass_copies_the_records_of_both_layouts_under_their_names() {
    let w = World::new();
    let old = generation(OLD, "_o");
    let fresh = generation(600_000, "_f");
    let mut keys = Vec::new();
    for dir in ["m/", TENANT, "m/x/t_1/", "m/x/t_zz/"] {
        let of = |flat: &str| format!("{dir}{}", &flat["m/".len()..]);
        for key in [
            "m/art/x_1".to_string(),
            "m/del/g_0000000000001_t".to_string(),
            format!("m/del/{}", &fresh["m/".len()..]),
        ] {
            w.record(&of(&key), b"record").await;
            keys.push(of(&key));
        }
        for key in [&old, &fresh] {
            w.generation(&of(key), &[]).await;
            keys.push(of(key));
        }
    }
    for key in [
        "m/rk/AK1".to_string(),
        "m/sz".to_string(),
        "m/x/a".to_string(),
        "m/zz".to_string(),
        in_tenant("m/seg/s_1/0"),
        in_tenant("m/del0"),
        in_tenant("m/h"),
        in_tenant("m/zz"),
    ] {
        w.record(&key, b"record").await;
        keys.push(key);
    }
    w.raw("m/tk/t_1", b"tenant key".to_vec()).await;

    let counts = w.pass().await;
    assert_eq!(counts.copied as usize, keys.len(), "{counts:?}");
    assert_eq!((counts.failed, counts.pending, counts.young), (0, 0, 0));
    for key in &keys {
        let source = w.safety.get(key, None).await.unwrap().unwrap();
        assert_eq!(w.e2.get(key), Some(source), "{key}");
    }
    assert_eq!(w.e2.objects.borrow().len(), keys.len());
    assert_eq!(w.e2.get("m/tk/t_1"), None);

    // And once: the next pass finds every one of them equal.
    let puts = w.e2.puts();
    let counts = w.pass().await;
    assert_eq!(
        (counts.copied, counts.same as usize, counts.extra),
        (0, keys.len(), 0),
        "{counts:?}"
    );
    assert_eq!(w.e2.puts(), puts);
}

/// The fresh records of the tenant layout are over there by the next
/// pass, as those of the flat layout are, with the walk at rest: the
/// pass lists the fresh tombstones and generation records of both
/// layouts and nothing else. A generation record goes after the
/// article plans it names, under whichever name each plan is stored.
#[tokio::test(flavor = "current_thread")]
async fn a_pass_at_rest_copies_the_fresh_records_of_the_tenant_layout() {
    let w = World::new();
    w.record("m/art/x_0001", b"plan").await;
    w.record(&in_tenant("m/art/x_0002"), b"plan").await;
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
    assert_eq!(w.e2.puts(), 2);

    let start = UnixMs(NOW + PASS_INTERVAL_MS);
    w.clock.set(start);
    let id = format!("{:013x}_new", start.0 - 180_000);
    // A record of the tenant layout: a plan under the name of its
    // layout, one under the flat name (its extent was posted before the
    // layout changed, or is shared with an older object).
    let record = format!("{TENANT}g_{id}");
    w.generation(&record, &["x_t", "x_f"]).await;
    let plan_t = in_tenant("m/art/x_t");
    w.record(&plan_t, b"plan t").await;
    w.record("m/art/x_f", b"plan f").await;
    let gone = format!("{TENANT}del/g_{id}");
    w.record(&gone, b"gone").await;
    // A record of the flat layout whose plan is in the tenant layout.
    let flat = format!("m/g_{id}");
    w.generation(&flat, &["x_o"]).await;
    let plan_o = in_tenant("m/art/x_o");
    w.record(&plan_o, b"plan o").await;

    w.e2.asked.borrow_mut().clear();
    assert!(queued_pass(&w, &w.copier(), start).await.is_empty());
    for key in [&record, &plan_t, &gone, &flat, &plan_o] {
        let source = w.safety.get(key, None).await.unwrap().unwrap();
        assert_eq!(w.e2.get(key), Some(source), "{key}");
    }
    assert!(w.e2.get("m/art/x_f").is_some());
    for (plan, record) in [
        (plan_t.as_str(), &record),
        ("m/art/x_f", &record),
        (plan_o.as_str(), &flat),
    ] {
        assert!(put_at(w.e2, plan) < put_at(w.e2, record), "{plan}");
    }
    // No plan was made up under a name it is not stored under.
    for key in [
        "m/art/x_t".to_string(),
        "m/art/x_o".to_string(),
        in_tenant("m/art/x_f"),
    ] {
        assert_eq!(w.e2.get(&key), None, "{key}");
    }
    // The walk rested: only the fresh records were listed.
    assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
    assert!(
        w.e2.asked
            .borrow()
            .iter()
            .all(|a| FRESH.iter().any(|fresh| a.starts_with(fresh))),
        "{:?}",
        w.e2.asked
    );
}

/// A fresh generation record whose article plan cannot be sent is held
/// back, in the tenant layout as in the flat one, and under whichever
/// name the plan is stored.
#[tokio::test(flavor = "current_thread")]
async fn a_plan_of_the_other_layout_that_cannot_be_sent_holds_the_record_back() {
    for (record, plan) in [
        (
            in_tenant(&generation(600_000, "_r")),
            "m/art/x_1".to_string(),
        ),
        (generation(600_000, "_r"), in_tenant("m/art/x_1")),
        (
            in_tenant(&generation(600_000, "_r")),
            in_tenant("m/art/x_1"),
        ),
    ] {
        let w = World::new();
        w.generation(&record, &["x_1"]).await;
        w.record(&plan, b"plan").await;
        w.e2.put_500_keys.borrow_mut().push(plan.clone());
        let counts = w.pass().await;
        assert!(counts.pending >= 1, "{record}: {counts:?}");
        assert_eq!(w.e2.get(&record), None, "{record}");
        assert_eq!(w.e2.get(&plan), None, "{record}");

        w.e2.put_500_keys.borrow_mut().clear();
        w.clock.advance_ms(PASS_INTERVAL_MS);
        w.pass().await;
        assert!(put_at(w.e2, &plan) < put_at(w.e2, &record), "{record}");
        assert!(w.e2.get(&record).is_some(), "{record}");
    }
}

/// The hint of a post job names the article plan by its flat name. The
/// plan is sent under the name it is stored under, also when that is
/// the one of the tenant layout; and a hint that names it so is one.
#[tokio::test(flavor = "current_thread")]
async fn a_hint_finds_the_article_plan_in_the_tenant_layout() {
    let w = World::new();
    assert!(queued_pass(&w, &w.copier(), UnixMs(NOW)).await.is_empty());
    w.clock.advance_ms(4 * PASS_INTERVAL_MS);
    let key = in_tenant("m/art/x_late");
    let plan = w.record(&key, b"late plan").await;
    let (pass, cursor) = hint_for(&w, "x_late");
    assert!(cursor.contains("m/art/x_late") && !cursor.contains(TENANT));
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, pass, &cursor).await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!(counts.unwrap().copied, 1);
    assert_eq!(w.e2.get(&key), Some(plan));
    assert_eq!(w.e2.get("m/art/x_late"), None);
    assert!(w.jobs.take().is_empty());

    let other = in_tenant("m/art/x_more");
    let more = w.record(&other, b"more").await;
    let named = cursor.replace("m/art/x_late", &other);
    let (outcome, counts, why) = w.copier().run_job(&w.jobs, pass, &named).await;
    assert_eq!((outcome, why), (JobOutcome::Ack, None));
    assert_eq!(counts.unwrap().copied, 1);
    assert_eq!(w.e2.get(&other), Some(more));

    // Nothing but an article plan: a generation record, a tombstone
    // and a key of the directory are no hint.
    let puts = w.e2.puts();
    for not in [
        in_tenant(&generation(OLD, "_o")),
        in_tenant("m/del/g_0000000000001_t"),
        in_tenant("m/art/"),
        "m/x/art/x_1".to_string(),
    ] {
        w.record(&not, b"record").await;
        let named = cursor.replace("m/art/x_late", &not);
        let (_, counts, _) = w.copier().run_job(&w.jobs, pass, &named).await;
        assert_eq!(counts.map(|c| c.copied), None, "{not}");
    }
    assert_eq!(w.e2.puts(), puts);
}

/// The saved place of a walk can be a key of the tenant layout: the
/// walk that is under way goes on from it, and what lies before it was
/// done by the passes before. A place that no walk saved, or one inside
/// what the sweep lists, starts the walk from the first key.
#[tokio::test(flavor = "current_thread")]
async fn a_saved_place_in_the_tenant_layout_is_safe() {
    let old = generation(OLD, "_o");
    let flat = ["m/art/x_1", "m/art/x_5", "m/del/g_0000000000001_t", &old];
    let world = || async {
        let w = World::new();
        for key in flat {
            w.record(key, b"record").await;
            w.record(&in_tenant(key), b"record").await;
        }
        w.record("m/x/t_1/art/x_1", b"record").await;
        w
    };
    let began = (NOW - PASS_INTERVAL_MS).to_string().into_bytes();
    let fresh_tombstone = in_tenant(&format!("m/del/g_{:013x}_x", NOW - 600_000));
    let fresh_generation = in_tenant(&generation(600_000, "_x"));
    // (the place, and the records after it when the walk goes on)
    for (place, rest) in [
        ("m/x/".to_string(), 5),
        (TENANT.to_string(), 5),
        (in_tenant("m/art/x_3"), 4),
        (in_tenant("m/del0"), 2),
        (in_tenant(&old), 1),
        (in_tenant("m/g`"), 1),
        ("m/x/t_1/art/x_1".to_string(), 0),
        // Inside the sweep: no walk saves it.
        (fresh_tombstone, 9),
        (fresh_generation, 9),
    ] {
        // No walk is under way: all of them, from the first key.
        let w = world().await;
        w.raw(WALK_KEY, place.as_bytes().to_vec()).await;
        let counts = w.pass().await;
        assert_eq!(counts.copied, 9, "{place}");
        assert_eq!(w.e2.objects.borrow().len(), 9);

        // A walk is under way.
        let w = world().await;
        known_store(&w).await;
        w.raw(WALK_KEY, place.as_bytes().to_vec()).await;
        w.raw(BEGAN_KEY, began.clone()).await;
        let (_, counts, why) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
        assert_eq!(why, None);
        assert_eq!(counts.unwrap().copied, rest, "{place}");
        assert!(w.jobs.take().is_empty());
        assert_eq!(saved(&w).await.as_deref(), Some(""));
        assert_eq!(time_at(&w, WALKED_KEY).await, ms(NOW));
    }
}

/// The cursors of the parts of a pass that this version adds are not
/// known to a version before it, which starts the pass again from them
/// (the same as from a cursor it cannot read); this version reads the
/// cursors of that one. So the names are fixed: `d`, `g`, `a`, `b` and
/// `x` as before, `e`, `h`, `c`, `f` and `z` for the tenant layout.
#[tokio::test(flavor = "current_thread")]
async fn the_cursors_of_a_pass_keep_their_names() {
    // Old and fresh records of both layouts and of another tenant: the
    // jobs of the pass name the parts in order.
    let w = World::new();
    for i in 0..3 {
        w.record(&format!("m/art/x_{i}"), b"plan").await;
        w.record(&in_tenant(&format!("m/art/x_{i}")), b"plan").await;
        w.record(&format!("m/x/t_1/art/x_{i}"), b"plan").await;
        let id = format!("{:013x}_{i}", NOW - 600_000);
        for dir in ["m/", TENANT] {
            w.record(&format!("{dir}del/g_{id}"), b"gone").await;
            w.generation(&format!("{dir}g_{id}"), &[]).await;
            let id = format!("{:013x}_{i}", NOW - OLD);
            w.generation(&format!("{dir}g_{id}"), &[]).await;
        }
    }
    // One copy to a job: every part with a record ends a job.
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let mut parts = Vec::new();
    let mut cursor = Some(String::new());
    let mut jobs = 0;
    while let Some(at) = cursor {
        jobs += 1;
        assert!(jobs < 1_000);
        let step = copier.step(UnixMs(NOW), &at).await.unwrap();
        cursor = step.next;
        if let Some(next) = &cursor {
            let value: serde_json::Value = serde_json::from_str(next).unwrap();
            let part = value["p"].as_str().unwrap().to_string();
            let key = value["k"].as_str().unwrap().to_string();
            // The part says which keys the cursor is in.
            let tenant = key.starts_with("m/x/");
            assert_eq!(tenant, "ehcfz".contains(&part), "{next}");
            if parts.last() != Some(&part) {
                parts.push(part);
            }
        }
    }
    assert_eq!(w.e2.objects.borrow().len(), 27);
    let order: Vec<&str> = "d g e h a b c f z".split(' ').collect();
    let mut last = 0;
    for part in &parts {
        let at = order.iter().position(|p| p == part).expect("a known part");
        assert!(at >= last, "{parts:?}");
        last = at;
    }
    let named = |names: &str| parts.iter().any(|p| names.contains(p.as_str()));
    assert!(named("dgab") && named("ehcfz"), "{parts:?}");
}

// ---------------------------------------------------------------------------
// Segmented generation records
// ---------------------------------------------------------------------------

use segmented_support::Sealed;
use velmora_bridge::recovery::{
    record_name, BucketRecord, ExtentRecord, GenerationManifest, GenerationRecord, Layout,
    MAX_SEGMENTS,
};

/// A record of `extents` extents of 10 bytes for the generation `id`;
/// `tail` makes the ids of its extents its own.
fn manifest(id: &str, tail: &str, extents: usize) -> GenerationManifest {
    GenerationManifest {
        v: 1,
        bucket: BucketRecord {
            id: "b_0123456789abcdef".into(),
            name: "vault".into(),
            owner: "o_1".into(),
            bdk_wrapped: vec![0x42; 40],
            kek_version: 1,
            disposable: false,
            created_at: NOW - 86_400_000,
        },
        generation: GenerationRecord {
            id: id.into(),
            key: "big".into(),
            size: extents as u64 * 10,
            etag: "\"etag\"".into(),
            checksum_json: None,
            content_json: "{}".into(),
            user_meta_json: "{}".into(),
            created_at: NOW,
        },
        extents: (0..extents)
            .map(|seq| ExtentRecord {
                id: format!("x_{tail}{seq:05}"),
                seq: seq as u32,
                plain_offset: seq as u64 * 10,
                plain_size: 10,
                cipher_size: 50,
                media_header: vec![1, 2, 3],
                key_mode: 1,
                wrapped_file_key: vec![7; 40],
                plain_md5: vec![1; 16],
                plain_sha256: vec![2; 32],
                cipher_sha256: vec![3; 32],
                created_at: NOW,
            })
            .collect(),
    }
}

/// Key of a generation record of `layout` minted `age_ms` ago.
fn generation_in(layout: &Layout, age_ms: i64, tail: &str) -> String {
    layout.of_flat(&generation(age_ms, tail))
}

impl World {
    /// Stores a segmented generation record of `extents` extents at
    /// `key`, in segments of `per`, segments first; with `plans`, the
    /// article plan of every extent as well.
    async fn segmented(&self, key: &str, extents: usize, per: usize, plans: bool) -> Sealed {
        let name = record_name(key).expect("a generation record");
        let m = manifest(name.id, &name.id[name.id.len() - 2..], extents);
        if plans {
            for e in &m.extents {
                let plan = name.layout.article_key(&ExtentId::new(e.id.clone()));
                self.record(&plan, b"plan").await;
            }
        }
        // A set of its own for every record.
        let digest = Sha256::digest(key.as_bytes());
        let tail = u64::from_be_bytes(digest[..8].try_into().unwrap());
        let set = segmented_support::set_id(NOW, tail);
        let sealed = segmented_support::seal(&self.kek, &name.layout, key, &m, &set, per);
        for (name, bytes) in &sealed.segments {
            self.raw(name, bytes.clone()).await;
        }
        self.raw(key, sealed.head_sealed.clone()).await;
        sealed
    }
}

/// How many PUTs of `key` the store was sent.
fn puts_of(e2: &FakeE2, key: &str) -> usize {
    let line = format!("PUT {key}");
    e2.log.borrow().iter().filter(|l| **l == line).count()
}

/// Every segment is over there, was sent once and before the head, in
/// order, and the head was sent once.
fn assert_segments_then_head(w: &World, key: &str, sealed: &Sealed) {
    let mut before = None;
    for (name, bytes) in &sealed.segments {
        assert_eq!(w.e2.get(name).as_ref(), Some(bytes), "{name}");
        assert_eq!(puts_of(w.e2, name), 1, "{name}");
        let at = put_at(w.e2, name);
        assert!(before < at, "{name}");
        before = at;
    }
    assert_eq!(w.e2.get(key).as_ref(), Some(&sealed.head_sealed));
    assert_eq!(puts_of(w.e2, key), 1);
    assert!(before < put_at(w.e2, key));
}

/// A fresh segmented record: the article plans and the segments go
/// first, the segments in order, and the head last, in both layouts.
/// The next pass sends nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_segmented_record_is_sent_after_its_plans_and_its_segments() {
    for layout in Layout::all() {
        let w = World::new();
        let key = generation_in(&layout, 600_000, "_a");
        let sealed = w.segmented(&key, 10, 4, true).await;
        assert_eq!(sealed.segments.len(), 3);
        let counts = w.pass().await;
        assert_eq!((counts.copied, w.e2.puts()), (14, 14), "{counts:?}");
        assert_eq!((counts.failed, counts.refused, counts.pending), (0, 0, 0));
        assert_eq!(counts.source_unreadable, 0);
        assert_segments_then_head(&w, &key, &sealed);
        let head = put_at(w.e2, &key);
        for e in sealed.plain.iter().flat_map(|s| &s.extents) {
            let plan = layout.article_key(&ExtentId::new(e.id.clone()));
            assert!(put_at(w.e2, &plan).is_some());
            assert!(put_at(w.e2, &plan) < head, "{plan}");
        }

        w.clock.advance_ms(PASS_INTERVAL_MS);
        let counts = w.pass().await;
        assert_eq!((counts.copied, w.e2.puts()), (0, 14), "{counts:?}");
    }
}

/// A fresh segmented record with a plan that is not written is held
/// back: its head is not sent. Once it is old, the walk sends it as it
/// is, segments first.
#[tokio::test(flavor = "current_thread")]
async fn a_segmented_record_is_held_back_for_an_article_plan() {
    let w = World::new();
    let key = generation(600_000, "_a");
    let sealed = w.segmented(&key, 10, 4, true).await;
    // An extent of the second segment has no plan.
    let missing = format!("m/art/{}", sealed.plain[1].extents[2].id);
    assert!(w.safety.lose(&missing));
    let counts = w.pass().await;
    assert_eq!(counts.pending, 1, "{counts:?}");
    assert!(w.e2.get(&key).is_none());
    // The nine plans, and the segments as the keys under `m/` they
    // are: without its head a segment says nothing to a reader.
    assert_eq!(w.e2.puts(), 9 + 3, "{counts:?}");

    w.clock.advance_ms(FRESH_MS);
    let counts = w.pass().await;
    assert_eq!(counts.pending, 0, "{counts:?}");
    assert_eq!(w.e2.get(&key), Some(sealed.head_sealed.clone()));
    for (name, bytes) in &sealed.segments {
        assert_eq!(w.e2.get(name).as_ref(), Some(bytes));
        assert!(put_at(w.e2, name) < put_at(w.e2, &key));
    }
}

/// The walk sends an old segmented record after its segments, with no
/// look at its plans, in both layouts.
#[tokio::test(flavor = "current_thread")]
async fn the_walk_sends_a_segmented_record_after_its_segments() {
    for layout in Layout::all() {
        let w = World::new();
        let key = generation_in(&layout, OLD, "_a");
        let sealed = w.segmented(&key, 10, 4, false).await;
        let counts = w.pass().await;
        assert_eq!((counts.copied, w.e2.puts()), (4, 4), "{counts:?}");
        assert_eq!((counts.failed, counts.source_unreadable), (0, 0));
        assert_segments_then_head(&w, &key, &sealed);
    }
}

/// A head is not sent unless every segment is stored, opens under its
/// own name and is the one the head names. The record is counted, the
/// records around it are copied, and once the segment is back the
/// record goes over.
#[tokio::test(flavor = "current_thread")]
async fn a_head_is_not_sent_when_a_segment_is_missing_or_wrong() {
    for layout in Layout::all() {
        for age in [600_000, OLD] {
            for (what, at) in [
                ("missing", 0),
                ("missing", 1),
                ("missing", 2),
                ("changed", 1),
                ("other set", 1),
                ("other index", 2),
            ] {
                let case = format!("{layout:?} age {age}: {what} {at}");
                let w = World::new();
                let key = generation_in(&layout, age, "_a");
                let sealed = w.segmented(&key, 10, 4, true).await;
                let neighbour = generation_in(&layout, age, "_b");
                w.generation(&neighbour, &[]).await;
                let (name, good) = sealed.segments[at].clone();
                assert!(w.safety.lose(&name));
                match what {
                    "missing" => {}
                    "changed" => {
                        let mut bytes = good.clone();
                        let last = bytes.len() - 1;
                        bytes[last] ^= 1;
                        w.raw(&name, bytes).await;
                    }
                    // A segment that opens under this name, and is the
                    // one of another head. The head names its digest:
                    // only what the segment says of itself is wrong.
                    _ => {
                        let mut segment = sealed.plain[at].clone();
                        if what == "other set" {
                            segment.set = "s_other".into();
                        } else {
                            segment.index = 0;
                        }
                        let plain = serde_json::to_vec(&segment).unwrap();
                        let stored = w.record(&name, &plain).await;
                        let mut head = sealed.head.clone();
                        head.segments[at].sha256 = Sha256::digest(&stored).to_vec();
                        let plain = serde_json::to_vec(&head).unwrap();
                        velmora_bridge::recovery::GenerationHead::parse(&key, &plain).expect(what);
                        w.record(&key, &plain).await;
                    }
                }
                let counts = w.pass().await;
                assert!(w.e2.get(&key).is_none(), "{case}");
                assert_eq!(puts_of(w.e2, &key), 0, "{case}");
                assert!(counts.source_unreadable >= 1, "{case}: {counts:?}");
                assert!(w.e2.get(&neighbour).is_some(), "{case}");

                // The segment is back: the walk comes round and sends
                // the record.
                assert!(w.safety.lose(&name) || what == "missing");
                w.raw(&name, good).await;
                w.raw(&key, sealed.head_sealed.clone()).await;
                w.clock.advance_ms(WALK_INTERVAL_MS + FRESH_MS);
                let counts = w.pass().await;
                assert_eq!(counts.source_unreadable, 0, "{case}: {counts:?}");
                assert_eq!(w.e2.get(&key), Some(sealed.head_sealed.clone()), "{case}");
                for (name, bytes) in &sealed.segments {
                    assert_eq!(w.e2.get(name).as_ref(), Some(bytes), "{case}");
                    assert!(put_at(w.e2, name) < put_at(w.e2, &key), "{case}");
                }
            }
        }
    }
}

/// A head that does not say which segments it has is never sent, by
/// the sweep or by the walk.
#[tokio::test(flavor = "current_thread")]
async fn a_head_that_does_not_tile_its_object_is_not_sent() {
    for age in [600_000, OLD] {
        let w = World::new();
        let key = generation(age, "_a");
        let mut sealed = w.segmented(&key, 10, 4, true).await;
        sealed.head.segments[1].seq += 1;
        sealed.reseal_head(&w.kek);
        assert!(w.safety.lose(&key));
        w.raw(&key, sealed.head_sealed.clone()).await;
        let counts = w.pass().await;
        assert_eq!(counts.source_unreadable, 1, "{counts:?}");
        assert!(w.e2.get(&key).is_none());
    }
}

/// A segment that is damaged or missing over there is made equal
/// before the head is sent; one that is equal is not sent again. And a
/// segment that is missing over there under a head that is equal is
/// sent by the walk, as any key under `m/` is.
#[tokio::test(flavor = "current_thread")]
async fn segments_over_there_are_made_equal_before_the_head() {
    let w = World::new();
    let key = generation(OLD, "_a");
    let sealed = w.segmented(&key, 10, 4, false).await;
    w.e2.set(&sealed.segments[0].0, &sealed.segments[0].1);
    w.e2.set(&sealed.segments[1].0, b"damaged");
    let counts = w.pass().await;
    assert_eq!((counts.copied, w.e2.puts()), (3, 3), "{counts:?}");
    assert_eq!(puts_of(w.e2, &sealed.segments[0].0), 0);
    for (name, bytes) in &sealed.segments {
        assert_eq!(w.e2.get(name).as_ref(), Some(bytes));
        assert!(put_at(w.e2, name) < put_at(w.e2, &key));
    }
    assert_eq!(w.e2.get(&key), Some(sealed.head_sealed.clone()));

    assert!(w
        .e2
        .objects
        .borrow_mut()
        .remove(&sealed.segments[2].0)
        .is_some());
    w.clock.advance_ms(WALK_INTERVAL_MS + FRESH_MS);
    let counts = w.pass().await;
    assert_eq!((counts.copied, w.e2.puts()), (1, 4), "{counts:?}");
    assert_eq!(
        w.e2.get(&sealed.segments[2].0).as_ref(),
        Some(&sealed.segments[2].1)
    );
}

/// A job that runs out of time among the segments stops, and the next
/// one goes on: every segment is sent once, and the head last.
#[tokio::test(flavor = "current_thread")]
async fn a_segmented_record_that_takes_several_jobs_is_sent_once() {
    let w = World::new();
    let key = generation(OLD, "_a");
    let sealed = w.segmented(&key, 40, 1, false).await;
    assert_eq!(sealed.segments.len(), 40);
    let clock = TickClock(w.clock.clone());
    let copier = Copier {
        safety: &w.safety,
        kek: &w.kek,
        clock: &clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    let mut jobs = 0;
    let mut cursor = Some(walk(""));
    while let Some(at) = cursor {
        jobs += 1;
        assert!(jobs < 200, "the walk does not end");
        let step = copier.step(UnixMs(NOW), &at).await.unwrap();
        if w.e2.get(&key).is_none() {
            // Not finished: the cursor has not passed the head.
            let next = step.next.as_deref().expect("the walk goes on");
            assert!(!next.contains(&format!("\"k\":\"{key}\"")), "{next}");
            // Each job got at least one segment over.
            assert!(w.e2.puts() >= jobs, "{jobs} jobs, {} puts", w.e2.puts());
        }
        cursor = step.next;
    }
    assert!(jobs >= 3, "{jobs}");
    assert_segments_then_head(&w, &key, &sealed);
    assert_eq!(w.e2.puts(), 41);
}

/// A segmented record with more plans than a job takes: the plans over
/// several jobs, no plan and no segment twice, and the head last.
#[tokio::test(flavor = "current_thread")]
async fn a_segmented_record_with_more_plans_than_a_job_takes_several() {
    let w = World::new();
    let key = generation(600_000, "_a");
    let sealed = w.segmented(&key, 600, 64, true).await;
    assert_eq!(sealed.segments.len(), 10);
    let mut jobs = 0;
    let mut cursor = Some(String::new());
    let mut copied = 0;
    while let Some(at) = cursor {
        jobs += 1;
        assert!(jobs < 100, "the pass does not end");
        let step = w.copier().step(UnixMs(NOW), &at).await.unwrap();
        copied += step.counts.copied;
        assert_eq!(step.counts.failed + step.counts.source_unreadable, 0);
        cursor = step.next;
    }
    assert!(jobs >= 3, "{jobs}");
    // Every key was put once. A job that stops at the head does not
    // count what it sent of the keys after it: those are the segments,
    // which the sweep also comes to as keys of their own.
    assert_eq!(w.e2.puts(), 611);
    assert!((601..=611).contains(&copied), "{copied}");
    assert_segments_then_head(&w, &key, &sealed);
    let head = put_at(w.e2, &key);
    for e in sealed.plain.iter().flat_map(|s| &s.extents) {
        let plan = format!("m/art/{}", e.id);
        assert_eq!(puts_of(w.e2, &plan), 1, "{plan}");
        assert!(put_at(w.e2, &plan) < head, "{plan}");
    }
}

/// A head with the most segments there are is sent, in the sweep and
/// in the walk; one with more is no head, and holds nothing back.
#[tokio::test(flavor = "current_thread")]
async fn a_head_with_the_most_segments_is_sent_and_one_with_more_is_none() {
    for age in [600_000, OLD] {
        let w = World::new();
        let key = generation(age, "_a");
        let fresh = age != OLD;
        w.segmented(&key, MAX_SEGMENTS + 1, 1, fresh).await;
        let most = generation(age, "_b");
        let sealed = w.segmented(&most, MAX_SEGMENTS, 1, fresh).await;
        let counts = w.pass().await;
        assert_eq!(counts.source_unreadable, 1, "{counts:?}");
        assert_eq!(counts.failed, 0, "{counts:?}");
        assert!(w.e2.get(&key).is_none());
        assert_eq!(puts_of(w.e2, &key), 0);
        assert_eq!(w.e2.get(&most), Some(sealed.head_sealed.clone()));
        assert_eq!(puts_of(w.e2, &most), 1);
        for (name, bytes) in &sealed.segments {
            assert_eq!(w.e2.get(name).as_ref(), Some(bytes));
            assert!(put_at(w.e2, name) < put_at(w.e2, &most), "{name}");
        }
    }
}

/// A head the job comes to with too little room left for its segments
/// is left to the next job, which sends it: after some plans that were
/// still to look at, and after a group of plans looked at again for a
/// record that is fresh for the last time.
#[tokio::test(flavor = "current_thread")]
async fn a_head_that_does_not_fit_into_the_rest_of_a_job_is_sent_by_the_next() {
    // Fresh with every plan written, and fresh for the last time with
    // one plan that is not.
    for (age, lost) in [(600_000, false), (FRESH_MS - 60_000, true)] {
        let case = format!("age {age}");
        let w = World::new();
        let key = generation(age, "_a");
        // 192 segments, and 192 plans of which 70 are still to send:
        // the job that sends those has no room for the segments.
        let sealed = w.segmented(&key, MAX_SEGMENTS, 1, true).await;
        let plans: Vec<String> = sealed
            .plain
            .iter()
            .flat_map(|s| &s.extents)
            .map(|e| format!("m/art/{}", e.id))
            .collect();
        for plan in &plans[..MAX_SEGMENTS - 70] {
            w.e2.set(plan, &w.safety.stored(plan).unwrap().bytes);
        }
        if lost {
            assert!(w.safety.lose(&plans[MAX_SEGMENTS - 1]));
        }
        let mut jobs = 0;
        let mut head_job = None;
        let mut cursor = Some(String::new());
        let pass = w.clock.now();
        while let Some(at) = cursor {
            jobs += 1;
            assert!(jobs < 50, "{case}: the pass does not end");
            let step = w.copier().step(pass, &at).await.unwrap();
            assert_eq!(step.counts.failed, 0, "{case}");
            if head_job.is_none() && w.e2.get(&key).is_some() {
                head_job = Some(jobs);
            }
            cursor = step.next;
        }
        assert!(head_job.is_some_and(|job| job > 1), "{case}: {head_job:?}");
        // The head once, after every segment. A segment may go twice:
        // the pass also comes to it as a key of its own, and sends it
        // again when it listed the store before the head's job did.
        assert_eq!(w.e2.get(&key), Some(sealed.head_sealed.clone()), "{case}");
        assert_eq!(puts_of(w.e2, &key), 1, "{case}");
        for (name, bytes) in &sealed.segments {
            assert_eq!(w.e2.get(name).as_ref(), Some(bytes), "{case}");
            assert!(put_at(w.e2, name) < put_at(w.e2, &key), "{case}: {name}");
            assert!(puts_of(w.e2, name) <= 2, "{case}: {name}");
        }
        for plan in &plans {
            assert!(puts_of(w.e2, plan) <= 1, "{case}: {plan}");
        }
    }
}

// ---------------------------------------------------------------------------
// Memory of a pass over segmented records
// ---------------------------------------------------------------------------

mod heap {
    //! Counts the bytes each thread has allocated and not freed, and the
    //! most it had at once. A test on a current-thread runtime reads its
    //! own numbers, whatever the tests beside it do.

    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static LIVE: Cell<isize> = const { Cell::new(0) };
        static PEAK: Cell<isize> = const { Cell::new(0) };
    }

    pub struct Counting;

    fn moved(by: isize) {
        let _ = LIVE.try_with(|live| {
            let now = live.get() + by;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    // SAFETY: every call goes to the system allocator unchanged; the
    // counters are plain thread-local cells that allocate nothing.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            moved(layout.size() as isize);
            System.alloc(layout)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            moved(-(layout.size() as isize));
            System.dealloc(ptr, layout)
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            moved(new_size as isize - layout.size() as isize);
            System.realloc(ptr, layout, new_size)
        }
    }

    /// Bytes this thread holds now.
    pub fn live() -> isize {
        LIVE.with(Cell::get)
    }

    /// Starts a new measurement: the peak is what is held now.
    pub fn mark() -> isize {
        let now = live();
        PEAK.with(|peak| peak.set(now));
        now
    }

    /// The most this thread held since the last [`mark`].
    pub fn peak() -> isize {
        PEAK.with(Cell::get)
    }
}

#[global_allocator]
static HEAP: heap::Counting = heap::Counting;

/// Six heads of 32 segments each, in both layouts: what a pass holds at
/// once, above what it held before, is a few segments and not a
/// record. Measured with segments of 256 extents and scaled to the
/// 4,096 a writer may fill, it stays inside the 48 MiB a request may
/// hold. The records are old, so the walk sends them; the sweep reads
/// the segments of a fresh one the same way.
#[tokio::test(flavor = "current_thread")]
async fn a_pass_over_six_segmented_records_holds_a_few_segments_at_once() {
    const PER: usize = 256;
    const SEGMENTS: usize = 32;
    const FULL: usize = 4096;
    const BUDGET: isize = 48 << 20;
    for layout in Layout::all() {
        // Every segment is over there already, and every segment is
        // to send.
        for there in [true, false] {
            let case = format!("{layout:?} there {there}");
            let w = World::new();
            let mut heads = Vec::new();
            let mut segment_bytes = 0;
            let mut sent = 0;
            for n in 0..6 {
                let key = generation_in(&layout, OLD + n, &format!("_{n}"));
                let sealed = w.segmented(&key, PER * SEGMENTS, PER, false).await;
                assert_eq!(sealed.segments.len(), SEGMENTS);
                for (name, bytes) in &sealed.segments {
                    segment_bytes = segment_bytes.max(bytes.len() as isize);
                    if there {
                        w.e2.set(name, bytes);
                    } else {
                        sent += bytes.len() as isize;
                    }
                }
                heads.push((key, sealed.head_sealed));
            }
            let before = heap::mark();
            let counts = w.pass().await;
            let peak = heap::peak() - before;
            assert_eq!(counts.failed + counts.source_unreadable, 0, "{case}");
            for (key, head) in &heads {
                assert_eq!(w.e2.get(key).as_ref(), Some(head), "{case}");
            }
            // What the fake store kept of the segments it was sent is
            // not the pass's own.
            let held = peak - sent;
            // Six keys are read at once, as any six records are. A
            // record of 32 segments held whole would be 32, and six of
            // them 192.
            assert!(
                held < 12 * segment_bytes,
                "{case}: {held} bytes, segments of {segment_bytes}"
            );
            let scaled = held * (FULL / PER) as isize;
            assert!(scaled < BUDGET, "{case}: {scaled} bytes at {FULL} extents");
        }
    }
}
