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
};
use velmora_bridge::testkit::FixedClock;
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
/// store's host, region and secret. The time is not checked here (the
/// tests move the clock); the signature over the date is.
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
            clock_skew_seconds: 4_000_000_000,
            presign_seconds: 60,
        },
    )
    .unwrap();
    let mut fields: Vec<(&str, &str)> = vec![("host", "e2.test")];
    fields.extend(sent.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let headers = Headers::new(&fields, &policy)?;
    let target = Target::parse(target, &policy)?;
    verify(method, &target, &headers, true, 0, &policy, &StoreKeys).map(|_| ())
}

fn answer(status: u16) -> Sent {
    Ok(HttpResponse {
        status,
        ..HttpResponse::default()
    })
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
        assert_eq!(
            check_signature(method, target, &request.headers),
            Ok(()),
            "{method} {target}"
        );
        let key = match method {
            "GET" => "list",
            _ => target.strip_prefix(ROOT).expect("bucket and prefix"),
        };
        self.log.borrow_mut().push(format!("{method} {key}"));
        if self.drop_next.get() > 0 {
            self.drop_next.set(self.drop_next.get() - 1);
            return Err(NoAnswer);
        }
        if method == "GET" {
            let query = target.strip_prefix("/records?").expect("bucket list");
            return self.list(query);
        }
        if method == "HEAD" {
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
        let e2: &'static FakeE2 = Box::leak(Box::default());
        let cfg = RemoteConfig::from_vars(vars).unwrap().unwrap();
        World {
            clock: FixedClock::new(UnixMs(NOW)),
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
    // as much again.
    let pauses = w.e2.pauses.borrow().clone();
    assert_eq!(pauses.len(), 2);
    assert!((200..=300).contains(&pauses[0]) && (800..=1200).contains(&pauses[1]));

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
    let remote = S3Remote::new(cfg, spy);
    let clock = FixedClock::new(UnixMs(NOW));
    let e = remote.put(&clock, "m/art/x_1", b"body").await.unwrap_err();
    let mut shown = format!("{shown} {e:?} {:?}", spy.0.borrow());
    shown.make_ascii_lowercase();
    assert!(shown.contains("put https://e2.test/records/drill-1/m/art/x_1"));
    for secret in [SECRET_KEY, "signature", "aws4", "credential"] {
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
        ("E2_REGION", "us west"),
        ("E2_BUCKET", "Records/x"),
        ("RECOVERY_PREFIX", "drill"),
        ("RECOVERY_PREFIX", "/drill/"),
        ("RECOVERY_PREFIX", "dr ill/"),
        ("E2_ACCESS_KEY", "AK/1"),
    ] {
        assert_eq!(
            with(name, Some(value)).unwrap_err(),
            ConfigError::Invalid(name.into())
        );
    }
    for name in [
        "E2_ENDPOINT",
        "E2_BUCKET",
        "E2_SECRET_KEY",
        "RECOVERY_PREFIX",
    ] {
        assert_eq!(
            with(name, None).unwrap_err(),
            ConfigError::Missing(name.into())
        );
    }
}
