//! The recovery copy: the store adapter (signing, retries, proof of a
//! put) and the pass that copies every recovery record out, against an
//! in-memory S3 store that speaks HTTP.
//!
//! The fake store panics on any method but GET, HEAD and PUT, in every
//! test of this file: nothing here may ever send a DELETE.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use base64::Engine;
use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;
use velmora_bridge::config::{ConfigError, Maintenance};
use velmora_bridge::copy::{pass_due, Copier, CopyCounts, JOB_COPIES, MIN_AGE_MS};
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
        let mut cursor = Some(String::new());
        while let Some(at) = cursor {
            let step = self.copier().step(&at).await.unwrap();
            let c = step.counts;
            total.records += c.records;
            total.bytes += c.bytes;
            total.same += c.same;
            total.copied += c.copied;
            total.failed += c.failed;
            total.refused += c.refused;
            total.source_unreadable += c.source_unreadable;
            total.young += c.young;
            total.extra += c.extra;
            cursor = step.next;
        }
        total
    }
}

/// Key of a generation record minted `age_ms` ago.
fn generation(age_ms: i64, tail: &str) -> String {
    format!("m/g_{:013x}{tail}", NOW - age_ms)
}

const OLD: i64 = 3_600_000;

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
    for secret in [SECRET_KEY, &access_key, "signature", "aws4", "credential"] {
        assert!(!shown.contains(secret), "{secret} in {shown}");
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
        k("m/c")
    ));
    let page = w.remote.list(&w.clock, "m/", "m/a").await.unwrap();
    let keys: Vec<_> = page.objects.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["m/b", "m/c"]);
    assert!(page.truncated);

    for (what, after, inner) in [
        ("outside the store prefix", "", contents("other/m/a")),
        ("the bucket root", "", contents("m/a")),
        ("outside the prefix asked for", "", k("rs/a")),
        ("out of order", "", k("m/b") + &k("m/a")),
        ("a key twice", "", k("m/a") + &k("m/a")),
        ("the start itself", "m/b", k("m/b")),
        ("before the start", "m/b", k("m/a")),
        ("a .. segment", "", k("m/../a")),
        ("a . segment", "", k("m/./a")),
        ("an empty segment", "", k("m//a")),
        ("a key that ends in /", "", k("m/a/")),
        // Characters this module would not sign.
        ("a space", "", k("m/a b")),
        ("an escape", "", k("m/%2e%2e/x")),
        ("a query", "", k("m/a?x#y")),
        ("a backslash", "", k("m/a\\..\\b")),
        ("not ASCII", "", k("m/\u{e9}\u{202e}")),
        (
            "more to come and no key",
            "",
            format!("<IsTruncated>true</IsTruncated>{token}"),
        ),
        (
            "more to come and the folder object only",
            "",
            format!("<IsTruncated>true</IsTruncated>{token}{}", contents(own)),
        ),
        ("no listing", "", "<Contents>".to_string()),
    ] {
        set(inner);
        let e = w.remote.list(&w.clock, "m/", after).await;
        assert_eq!(e.err(), Some(RemoteError::Mismatch), "{what}");
    }

    // An object that is the store prefix itself (a folder made in a
    // console) is no copy: it is left out and the listing goes on.
    set(contents(own) + &k("m/a"));
    let page = w.remote.list(&w.clock, "", "").await.unwrap();
    let keys: Vec<_> = page.objects.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["m/a"]);
    set(contents(own));
    let page = w.remote.list(&w.clock, "", "").await.unwrap();
    assert!(page.objects.is_empty() && !page.truncated);

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

#[tokio::test(flavor = "current_thread")]
async fn pass_never_copies_tenant_keys() {
    let w = World::new();
    w.record("m/tk/t_1", b"tenant key").await;
    w.record("m/art/x_1", b"plan").await;
    let counts = w.pass().await;
    assert_eq!((counts.records, counts.copied), (1, 1));
    let there: Vec<String> = w.e2.objects.borrow().keys().cloned().collect();
    assert_eq!(there, ["m/art/x_1"]);
    assert_eq!(w.e2.count("PUT m/tk/"), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn pass_skips_generation_records_younger_than_two_minutes() {
    let w = World::new();
    let young = generation(MIN_AGE_MS - 1, "aaaa");
    let ahead = generation(-5_000, "bbbb");
    let old = generation(MIN_AGE_MS, "cccc");
    for key in [&young, &ahead, &old] {
        w.record(key, b"g").await;
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
    let counts = w.pass().await;
    assert_eq!((counts.copied, counts.same, counts.records), (0, 7, 7));
    assert_eq!(w.e2.puts(), puts);
    // MemBlobStore lists by reading (the port's default); nothing more.
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
    let (outcome, counts) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
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
    assert_eq!((*pass, cursor), (UnixMs(NOW), &last));

    // The second job dies after its work: its message comes again and
    // finds everything done. The last job of a pass sends none.
    let died = w.copier().step(cursor).await.unwrap();
    assert_eq!((died.counts.copied, died.next), (30, None));
    let (outcome, counts) = w.copier().run_job(&w.jobs, *pass, cursor).await;
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
    let (outcome, counts) = w.copier().run_job(&w.jobs, *pass, cursor).await;
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
    let (outcome, counts) = copier.run_job(&w.jobs, UnixMs(NOW), "").await;
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
    let (outcome, counts) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(outcome, JobOutcome::Retry { delay_secs: 60 });
    assert_eq!(counts.unwrap().failed, 4);
    assert!(w.jobs.take().is_empty());

    // A list request that gets no answer: the same, with no counts.
    w.e2.put_status.set(None);
    w.e2.drop_next.set(4);
    let (outcome, counts) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(outcome, JobOutcome::Retry { delay_secs: 60 });
    assert_eq!(counts, None);
    assert_eq!(w.e2.puts(), 16);
    w.e2.put_status.set(Some(500));

    // Past the retry window the job is not retried; the pass goes on.
    w.clock.advance_ms(10 * 60 * 1000);
    let (outcome, counts) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(counts.unwrap().failed, 4);
    let sent = w.jobs.take();
    assert!(
        matches!(&sent[0].job, Job::RecoveryCopy { cursor, .. } if cursor == "m/art/x_3"),
        "{:?}",
        sent[0].job
    );

    // The next pass has started: a job of this one does nothing more.
    w.clock.advance_ms(5 * 60 * 1000);
    let before = w.e2.log.borrow().len();
    let (outcome, counts) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    assert_eq!((outcome, counts), (JobOutcome::Ack, None));
    assert!(w.jobs.take().is_empty());
    assert_eq!(w.e2.log.borrow().len(), before);

    w.e2.put_status.set(None);
    assert_eq!(w.pass().await.copied, 4);
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
    let (outcome, counts) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
    let counts = counts.unwrap();
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!((counts.copied, counts.failed), (18, 2));
    assert!(!counts.clean());
    assert!(w.e2.get("m/art/x_19").is_some());

    // Alone in its job (the steady state: everything else is copied),
    // one failing record is not taken for an outage either.
    let (outcome, counts) = w.copier().run_job(&w.jobs, UnixMs(NOW), "").await;
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
    let first = copier.step("").await.unwrap();
    let copied = first.counts.copied as usize;
    assert!(
        copied > 0 && copied < 40 && copied.is_multiple_of(6),
        "{copied}"
    );
    assert_eq!(first.next, Some(format!("m/art/x_{:02}", copied - 1)));
    assert_eq!(w.e2.objects.borrow().len(), copied);
    let mut jobs = 1;
    let mut cursor = first.next;
    while let Some(at) = cursor {
        cursor = copier.step(&at).await.unwrap().next;
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
    let key = generation(OLD, "aaaa");
    w.record(&key, b"g").await;
    w.e2.page.set(10);

    // 40 rounds of at most 10 list requests, 10 keys each: the job ends
    // 4,000 keys in, and the next one goes on from there.
    let first = w.copier().step("").await.unwrap();
    assert_eq!(w.e2.count("GET "), 400);
    assert_eq!(first.next.as_deref(), Some("m/art/x_03999"));
    assert_eq!((first.counts.copied, first.counts.extra), (0, 4_000));

    let w2 = World::new();
    for i in 0..5_000 {
        w2.e2.set(&format!("m/art/x_{i:05}"), b"old");
    }
    w2.record(&key, b"g").await;
    w2.e2.page.set(100);
    let total = w2.pass().await;
    assert_eq!((total.records, total.copied, total.extra), (1, 1, 5_000));
    assert_eq!(w2.e2.objects.borrow().len(), 5_001);
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
