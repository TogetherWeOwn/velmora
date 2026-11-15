//! The recovery copy: the store adapter (signing, retries, proof of a
//! put), against an in-memory S3 store that speaks HTTP.
//!
//! The fake store panics on any method but GET, HEAD and PUT, in every
//! test of this file: nothing here may ever send a DELETE.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use base64::Engine;
use sha2::{Digest, Sha256};
use velmora_bridge::config::ConfigError;
use velmora_bridge::remote::{
    md5_hex, HttpRequest, HttpResponse, HttpSend, NoAnswer, RemoteConfig, RemoteError, S3Remote,
    MAX_ANSWER_BYTES, MAX_LIST_BYTES,
};
use velmora_bridge::testkit::{FixedClock, MemBlobStore};
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
    /// another second than this one is refused.
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
    clock: FixedClock,
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
            clock,
            e2,
            remote: S3Remote::new(cfg, e2),
        }
    }
}

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
