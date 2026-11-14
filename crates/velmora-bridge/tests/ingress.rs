//! Ingress: raw target, headers-only precheck, counted read, byte budget,
//! redacted log line, and the `VELMORA_KEK_ACTIVE` bound.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use base64::Engine as _;
use futures_util::stream;
use futures_util::StreamExt as _;
use velmora_bridge::config::{BridgeConfig, ConfigError, KekRing, MAX_KEK_VERSION};
use velmora_bridge::ingress::{
    self, declared_length, origin_form, precheck, read_capped, ByteBudget, Charge, IngressError,
    Sleeper, CHARGE_POLL_MS, CHARGE_WAIT_MS,
};
use velmora_bridge::service::{classify, Route};
use velmora_bridge::{Body, BridgeError, Method, S3Request};

const HOST: &str = "https://velmora-s3.example.workers.dev";
const ADMIN: &str = "admin-token-fixture-admin-token-fixture";
const MAX: u64 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn vars(dev_trust_http: bool) -> BTreeMap<String, String> {
    let mut v = BTreeMap::new();
    for (k, val) in [
        ("ENVIRONMENT", "dev"),
        ("S3_HOST", "127.0.0.1:8787"),
        ("S3_REGION", "auto"),
        ("MAX_EXTENT_BYTES", "16777216"),
        ("REQUIRED_BACKBONES", "1"),
        ("SAFETY_MIN_AGE_SECS", "0"),
        ("VERIFY_DELAY_SECS", "1"),
        ("NEWSGROUPS", "alt.binaries.test"),
        ("VELMORA_KEK_ACTIVE", "1"),
        ("INFLIGHT_BUDGET_BYTES", "50331648"),
        ("GC_MODE", "disposable"),
        ("MAINTENANCE", "off"),
        ("SERVER_SIDE_COPY", "off"),
        ("ADMIN_TOKEN", ADMIN),
        (
            "NNTP_PROVIDERS",
            r#"[{"id":"p1","host":"127.0.0.1","port":11119,"tls":false,"user":"u","pass":"p","backbone":"fake","post":true,"read":true,"max_conns":2}]"#,
        ),
    ] {
        v.insert(k.to_string(), val.to_string());
    }
    v.insert(
        "VELMORA_KEK_1".into(),
        base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
    );
    if dev_trust_http {
        v.insert("DEV_TRUST_HTTP".into(), "1".into());
    }
    v
}

fn cfg(dev_trust_http: bool) -> BridgeConfig {
    let v = vars(dev_trust_http);
    BridgeConfig::from_vars(|k| v.get(k).cloned()).expect("fixture config")
}

/// A body stream that records whether anyone polled it.
fn watched_body(declared_len: Option<u64>, chunks: Vec<Vec<u8>>, polled: Rc<Cell<u32>>) -> Body {
    let s = stream::iter(chunks).map(move |c| {
        polled.set(polled.get() + 1);
        Ok::<_, BridgeError>(c)
    });
    Body::Stream {
        declared_len,
        stream: Box::pin(s),
    }
}

fn request(method: Method, target: &str, headers: &[(&str, &str)], body: Body) -> S3Request {
    S3Request {
        method,
        raw_target: target.to_string(),
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        body,
    }
}

const SIGV4: &str = "AWS4-HMAC-SHA256 Credential=AKVLEXAMPLEEXAMPLE00/20261113/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=00";

fn check(req: &S3Request, cfg: &BridgeConfig, https: bool) -> Result<(), IngressError> {
    let route = classify(&req.method, &req.raw_target);
    precheck(&route, req, cfg, https)
}

// ---------------------------------------------------------------------------
// Raw target
// ---------------------------------------------------------------------------

/// The measured workers.dev table: what `req.inner().url()` delivered for
/// each target sent. `origin_form` must return the path and query byte for
/// byte (no dot-segment removal, no `//` collapse, no decoding, no case
/// change of escapes, query untouched).
#[test]
fn raw_target_vectors() {
    let table: &[(&str, &str)] = &[
        ("/raw/b/a/../k", "/raw/b/a/../k"),
        ("/raw/b/a/%2E%2E/k", "/raw/b/a/%2E%2E/k"),
        ("/raw/b/a/%2e%2e/k", "/raw/b/a/%2e%2e/k"),
        ("/raw/b/a/./k", "/raw/b/a/./k"),
        ("/raw/b/a/%2E/k", "/raw/b/a/%2E/k"),
        ("/raw/b/x%2Fy", "/raw/b/x%2Fy"),
        ("/raw/b/a+b%20c", "/raw/b/a+b%20c"),
        ("/raw/b//double", "/raw/b//double"),
        ("/raw/b/%E2%82%AC", "/raw/b/%E2%82%AC"),
        // Raw UTF-8 `€` arrives percent-encoded in lowercase hex.
        ("/raw/b/€", "/raw/b/%e2%82%ac"),
        ("/raw/b/%41%7e", "/raw/b/%41%7e"),
        ("/raw/b/a\\b", "/raw/b/a\\b"),
        ("/raw/b/a%5Cb", "/raw/b/a%5Cb"),
        ("/raw/b/a;b,c$d", "/raw/b/a;b,c$d"),
        ("/raw/b/sp%20ace%3A%40%21", "/raw/b/sp%20ace%3A%40%21"),
        ("/raw/b/k?x=a%2Bb&y=a+b", "/raw/b/k?x=a%2Bb&y=a+b"),
        ("/raw/b/k?uploads", "/raw/b/k?uploads"),
        ("/raw/b/k?x=a%2fb&z=%7E~", "/raw/b/k?x=a%2fb&z=%7E~"),
        ("/raw/b/k?a=%20&b=c%3Dd&&e", "/raw/b/k?a=%20&b=c%3Dd&&e"),
    ];
    for (sent, inner_url_target) in table {
        let url = format!("{HOST}{inner_url_target}");
        assert_eq!(
            origin_form(&url),
            Ok(*inner_url_target),
            "sent {sent:?}, runtime url {url:?}"
        );
    }
    // Other URL shapes the runtime can produce.
    assert_eq!(origin_form("http://127.0.0.1:8798/b/k?x"), Ok("/b/k?x"));
    assert_eq!(origin_form("https://h/"), Ok("/"));
    assert_eq!(
        origin_form("https://h:443/?list-type=2"),
        Ok("/?list-type=2")
    );
}

/// `%00` is refused by the edge; the parser still refuses raw NUL, other
/// controls, space, DEL, raw non-ASCII, fragments and non-absolute input.
#[test]
fn origin_form_refuses_malformed_urls() {
    for bad in [
        "https://h/b/a\0b",
        "https://h/b/a\rb",
        "https://h/b/a\nb",
        "https://h/b/a\tb",
        "https://h/b/a b",
        "https://h/b/a\x7fb",
        "https://h/b/€",
        "https://h/b/k#frag",
        "/b/k",
        "b/k",
        "",
        "https://",
        "https:///b/k",
        "https://h",
        "https://h?x",
        "ht tp://h/b",
    ] {
        assert_eq!(
            origin_form(bad),
            Err(IngressError::InvalidTarget),
            "{bad:?}"
        );
    }
    // Literal `%00` text is three printable bytes; the edge rejects it
    // before the Worker runs, and the key parser refuses the decoded NUL.
    assert_eq!(origin_form("https://h/b/a%00b"), Ok("/b/a%00b"));
}

#[test]
fn https_comes_from_the_runtime_scheme() {
    assert!(ingress::is_https("https://h/b"));
    assert!(ingress::is_https("HTTPS://h/b"));
    assert!(!ingress::is_https("http://h/b"));
    assert!(!ingress::is_https("http"));
    // Never panics on a multi-byte character across byte 8.
    assert!(!ingress::is_https("https:/€/h"));
    assert!(!ingress::is_https("httpsé://h/"));
}

// ---------------------------------------------------------------------------
// Headers-only precheck
// ---------------------------------------------------------------------------

#[test]
fn declared_length_is_strict() {
    let h = |v: &str| vec![("content-length".to_string(), v.to_string())];
    assert_eq!(declared_length(&[]), Ok(None));
    assert_eq!(declared_length(&h("0")), Ok(Some(0)));
    assert_eq!(declared_length(&h("16777216")), Ok(Some(16_777_216)));
    for bad in [
        "",
        "-1",
        "+5",
        "5, 5",
        "5,5",
        "0x10",
        "1e3",
        "18446744073709551616",
        "123456789012345678901",
    ] {
        assert_eq!(
            declared_length(&h(bad)),
            Err(IngressError::InvalidContentLength),
            "{bad:?}"
        );
    }
    let twice = vec![
        ("content-length".to_string(), "5".to_string()),
        ("content-length".to_string(), "5".to_string()),
    ];
    assert_eq!(
        declared_length(&twice),
        Err(IngressError::InvalidContentLength)
    );
}

#[test]
fn unauthenticated_body_never_read() {
    let cfg = cfg(true);
    let polled = Rc::new(Cell::new(0));
    let req = request(
        Method::Put,
        "/bucket/key",
        &[("content-length", "4")],
        watched_body(Some(4), vec![b"abcd".to_vec()], polled.clone()),
    );
    let err = check(&req, &cfg, true).unwrap_err();
    assert_eq!(err, IngressError::AccessDenied);
    let resp = err.response();
    assert_eq!(resp.status, 403);
    assert_eq!(polled.get(), 0, "body must not be read");

    // Every unsigned S3 shape is AccessDenied, not NotImplemented.
    for (m, t) in [
        (Method::Get, "/"),
        (Method::Get, "/bucket"),
        (Method::Get, "/bucket/key"),
        (Method::Head, "/bucket/key"),
        (Method::Delete, "/bucket/key"),
        (Method::Post, "/bucket/key?uploads"),
        (Method::Get, "/bucket/key?acl"),
    ] {
        let req = request(m.clone(), t, &[], Body::Empty);
        assert_eq!(
            check(&req, &cfg, true),
            Err(IngressError::AccessDenied),
            "{m:?} {t}"
        );
    }

    // A credential (header or presigned query) passes the presence gate;
    // the handler verifies it.
    let signed = request(
        Method::Get,
        "/bucket/key",
        &[("authorization", SIGV4)],
        Body::Empty,
    );
    assert_eq!(check(&signed, &cfg, true), Ok(()));
    let presigned = request(
        Method::Get,
        "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=00",
        &[],
        Body::Empty,
    );
    assert_eq!(check(&presigned, &cfg, true), Ok(()));
    // Names are matched decoded, as the SigV4 target parser reads them.
    let encoded = request(
        Method::Get,
        "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signatur%65=00",
        &[],
        Body::Empty,
    );
    assert_eq!(check(&encoded, &cfg, true), Ok(()));
    let lookalike = request(
        Method::Get,
        "/bucket/key?x-amz-signature=00&X-Amz-Signature-x=1",
        &[],
        Body::Empty,
    );
    assert_eq!(
        check(&lookalike, &cfg, true),
        Err(IngressError::AccessDenied)
    );
}

#[test]
fn oversized_declared_length_rejected_unread() {
    let cfg = cfg(true);
    let over = (MAX + 1).to_string();
    for (method, target) in [
        (Method::Put, "/bucket/key"),
        (Method::Put, "/bucket/key?partNumber=1&uploadId=u"),
        (Method::Post, "/bucket/key?uploadId=u"),
    ] {
        let polled = Rc::new(Cell::new(0));
        let req = request(
            method.clone(),
            target,
            &[("authorization", SIGV4), ("content-length", &over)],
            watched_body(Some(MAX + 1), vec![vec![0; 8]], polled.clone()),
        );
        let err = check(&req, &cfg, true).unwrap_err();
        assert_eq!(err, IngressError::EntityTooLarge, "{method:?} {target}");
        assert_eq!(err.response().status, 400);
        assert_eq!(polled.get(), 0, "body must not be read");
    }

    // At the cap is fine.
    let at = MAX.to_string();
    let req = request(
        Method::Put,
        "/bucket/key",
        &[("authorization", SIGV4), ("content-length", &at)],
        Body::Empty,
    );
    assert_eq!(check(&req, &cfg, true), Ok(()));
}

#[test]
fn aws_chunked_uploads_are_capped_by_the_decoded_length() {
    let cfg = cfg(true);
    let h = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let max = MAX.to_string();
    let over = (MAX + 1).to_string();
    let encoded = (MAX + 4096).to_string();
    // Decoded at the cap, encoded above it or absent: accepted.
    for pairs in [
        vec![
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", max.as_str()),
        ],
        vec![
            ("content-encoding", "gzip, aws-chunked"),
            ("x-amz-decoded-content-length", max.as_str()),
            ("content-length", encoded.as_str()),
        ],
    ] {
        let lengths = ingress::upload_lengths(&h(&pairs), MAX).unwrap();
        assert_eq!(lengths.decoded, MAX);
        let mut all = vec![("authorization", SIGV4)];
        all.extend(pairs.iter().copied());
        let req = request(Method::Put, "/bucket/key", &all, Body::Empty);
        assert_eq!(check(&req, &cfg, true), Ok(()), "{pairs:?}");
    }
    for (pairs, err) in [
        (
            vec![
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", over.as_str()),
            ],
            IngressError::EntityTooLarge,
        ),
        (
            vec![
                ("content-encoding", "aws-chunked"),
                ("content-length", "10"),
            ],
            IngressError::MissingContentLength,
        ),
        (
            vec![
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", "11"),
                ("content-length", "10"),
            ],
            IngressError::InvalidContentLength,
        ),
        (
            vec![
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", "+1"),
            ],
            IngressError::InvalidContentLength,
        ),
        // Without aws-chunked the decoded-length header does not count.
        (
            vec![("x-amz-decoded-content-length", "10")],
            IngressError::MissingContentLength,
        ),
    ] {
        assert_eq!(
            ingress::upload_lengths(&h(&pairs), MAX),
            Err(err),
            "{pairs:?}"
        );
        let mut all = vec![("authorization", SIGV4)];
        all.extend(pairs.iter().copied());
        let req = request(
            Method::Put,
            "/bucket/key?partNumber=1&uploadId=u",
            &all,
            Body::Empty,
        );
        assert_eq!(check(&req, &cfg, true), Err(err), "{pairs:?}");
    }
}

/// A copy names its source in a header and sends no body, so it passes
/// without a declared length. One that declares a body is the handler's
/// to refuse; a declared body over the cap is still refused here.
#[test]
fn a_copy_needs_no_declared_length() {
    let cfg = cfg(false);
    for target in ["/bucket/key", "/bucket/key?partNumber=1&uploadId=u"] {
        let plain = request(
            Method::Put,
            target,
            &[("authorization", SIGV4)],
            Body::Empty,
        );
        assert_eq!(
            check(&plain, &cfg, true),
            Err(IngressError::MissingContentLength)
        );
        let copy = [
            ("authorization", SIGV4),
            ("x-amz-copy-source", "/bucket/src"),
        ];
        let req = request(Method::Put, target, &copy, Body::Empty);
        assert_eq!(check(&req, &cfg, true), Ok(()), "{target}");
        let mut over = copy.to_vec();
        let len = (cfg.max_extent_bytes + 1).to_string();
        over.push(("content-length", &len));
        let req = request(Method::Put, target, &over, Body::Empty);
        assert_eq!(
            check(&req, &cfg, true),
            Err(IngressError::EntityTooLarge),
            "{target}"
        );
    }
}

#[test]
fn upload_without_content_length_is_411() {
    let cfg = cfg(true);
    for target in ["/bucket/key", "/bucket/key?partNumber=1&uploadId=u"] {
        let polled = Rc::new(Cell::new(0));
        let req = request(
            Method::Put,
            target,
            &[("authorization", SIGV4)],
            watched_body(None, vec![vec![0; 8]], polled.clone()),
        );
        let err = check(&req, &cfg, true).unwrap_err();
        assert_eq!(err, IngressError::MissingContentLength, "{target}");
        assert_eq!(err.response().status, 411);
        assert_eq!(polled.get(), 0);
    }
    // A merged duplicate is refused rather than guessed.
    let req = request(
        Method::Put,
        "/bucket/key",
        &[("authorization", SIGV4), ("content-length", "4, 4")],
        Body::Empty,
    );
    assert_eq!(
        check(&req, &cfg, true),
        Err(IngressError::InvalidContentLength)
    );
}

#[test]
fn admin_requires_the_bearer() {
    let cfg = cfg(true);
    let admin = |headers: &[(&str, &str)]| {
        let req = request(Method::Get, "/_admin/status", headers, Body::Empty);
        assert!(matches!(
            classify(&req.method, &req.raw_target),
            Route::Admin { .. }
        ));
        check(&req, &cfg, true)
    };
    let missing = admin(&[]).unwrap_err();
    assert_eq!(missing, IngressError::AdminUnauthenticated);
    let resp = missing.response();
    assert_eq!(resp.status, 401);
    assert!(resp
        .headers
        .iter()
        .any(|(n, v)| n == "www-authenticate" && v == "Bearer"));

    assert_eq!(
        admin(&[("authorization", "Bearer ")]),
        Err(IngressError::AdminUnauthenticated)
    );
    assert_eq!(
        admin(&[("authorization", SIGV4)]),
        Err(IngressError::AdminUnauthenticated)
    );
    let wrong = format!("Bearer {}x", ADMIN);
    assert_eq!(
        admin(&[("authorization", &wrong)]),
        Err(IngressError::AdminForbidden)
    );
    assert_eq!(
        admin(&[("authorization", "Bearer admin-token-fixture")]),
        Err(IngressError::AdminForbidden)
    );
    assert_eq!(IngressError::AdminForbidden.response().status, 403);
    let right = format!("Bearer {ADMIN}");
    assert_eq!(admin(&[("authorization", &right)]), Ok(()));
    let right_lower = format!("bearer {ADMIN}");
    assert_eq!(admin(&[("authorization", &right_lower)]), Ok(()));
}

#[test]
fn plain_http_needs_dev_trust() {
    let req = request(
        Method::Get,
        "/bucket/key",
        &[("authorization", SIGV4)],
        Body::Empty,
    );
    assert_eq!(
        check(&req, &cfg(false), false),
        Err(IngressError::InsecureTransport)
    );
    assert_eq!(check(&req, &cfg(false), true), Ok(()));
    assert_eq!(check(&req, &cfg(true), false), Ok(()));
    // Admin too.
    let right = format!("Bearer {ADMIN}");
    let admin = request(
        Method::Get,
        "/_admin/status",
        &[("authorization", &right)],
        Body::Empty,
    );
    assert_eq!(
        check(&admin, &cfg(false), false),
        Err(IngressError::InsecureTransport)
    );
}

#[test]
fn error_responses_never_echo_request_data() {
    for e in [
        IngressError::InvalidTarget,
        IngressError::InsecureTransport,
        IngressError::AccessDenied,
        IngressError::AdminUnauthenticated,
        IngressError::AdminForbidden,
        IngressError::InvalidContentLength,
        IngressError::MissingContentLength,
        IngressError::EntityTooLarge,
        IngressError::IncompleteBody,
        IngressError::SlowDown,
        IngressError::Internal,
    ] {
        let resp = e.response();
        assert_eq!(resp.status, e.status());
        let velmora_bridge::RespBody::Bytes(body) = resp.body else {
            panic!("xml body");
        };
        let body = String::from_utf8(body).unwrap();
        assert!(
            body.contains(&format!("<Code>{}</Code>", e.code())),
            "{body}"
        );
    }
    let slow = IngressError::SlowDown.response();
    assert_eq!(slow.status, 503);
    assert!(slow.headers.iter().any(|(n, _)| n == "retry-after"));
}

// ---------------------------------------------------------------------------
// Counted read
// ---------------------------------------------------------------------------

fn charge_for(budget: &ByteBudget, len: u64) -> Charge {
    budget.try_charge(len * 2).expect("fits")
}

#[tokio::test]
async fn read_capped_reads_exactly_the_declared_length() {
    let budget = ByteBudget::new(1 << 20);
    let charge = charge_for(&budget, 10);
    let polled = Rc::new(Cell::new(0));
    let body = watched_body(
        Some(10),
        vec![b"0123".to_vec(), vec![], b"456789".to_vec()],
        polled,
    );
    assert_eq!(
        read_capped(body, 10, &charge).await.unwrap(),
        b"0123456789".to_vec()
    );
    assert_eq!(read_capped(Body::Empty, 0, &charge).await.unwrap(), b"");
    let empty_stream = watched_body(Some(0), vec![], Rc::new(Cell::new(0)));
    assert_eq!(read_capped(empty_stream, 0, &charge).await.unwrap(), b"");
}

/// The cap holds whatever the header (or its absence) says: the read stops
/// at the first byte past `declared_len`, and the surplus is not kept.
#[tokio::test]
async fn read_capped_enforces_the_cap_with_and_without_content_length() {
    let budget = ByteBudget::new(1 << 20);
    let charge = charge_for(&budget, 8);
    for header in [Some(8), None, Some(4), Some(1 << 30)] {
        // Long: an endless stream is cut on the chunk that crosses the cap.
        let polled = Rc::new(Cell::new(0u32));
        let p = polled.clone();
        let endless = stream::repeat_with(move || {
            p.set(p.get() + 1);
            Ok::<_, BridgeError>(vec![7u8; 3])
        });
        let body = Body::Stream {
            declared_len: header,
            stream: Box::pin(endless),
        };
        assert_eq!(
            read_capped(body, 8, &charge).await,
            Err(IngressError::EntityTooLarge),
            "header {header:?}"
        );
        assert_eq!(polled.get(), 3, "stops at the chunk crossing the cap");

        // One byte over in a single chunk.
        let body = watched_body(header, vec![vec![1; 9]], Rc::new(Cell::new(0)));
        assert_eq!(
            read_capped(body, 8, &charge).await,
            Err(IngressError::EntityTooLarge)
        );

        // Short.
        let body = watched_body(header, vec![vec![1; 7]], Rc::new(Cell::new(0)));
        assert_eq!(
            read_capped(body, 8, &charge).await,
            Err(IngressError::IncompleteBody)
        );
    }
    assert_eq!(
        read_capped(Body::Empty, 8, &charge).await,
        Err(IngressError::IncompleteBody)
    );
}

#[tokio::test]
async fn read_capped_maps_stream_failure_and_needs_a_covering_charge() {
    let budget = ByteBudget::new(1 << 20);
    let charge = charge_for(&budget, 8);
    let failing = stream::iter(vec![
        Ok(vec![1u8; 4]),
        Err(BridgeError::Invalid("request body stream")),
    ]);
    let body = Body::Stream {
        declared_len: Some(8),
        stream: Box::pin(failing),
    };
    assert_eq!(
        read_capped(body, 8, &charge).await,
        Err(IngressError::IncompleteBody)
    );

    // A charge smaller than the body is a caller bug: refuse, read nothing.
    let small = budget.try_charge(4).unwrap();
    let polled = Rc::new(Cell::new(0));
    let body = watched_body(Some(8), vec![vec![1; 8]], polled.clone());
    assert_eq!(
        read_capped(body, 8, &small).await,
        Err(IngressError::Internal)
    );
    assert_eq!(polled.get(), 0);
}

// ---------------------------------------------------------------------------
// Byte budget
// ---------------------------------------------------------------------------

#[tokio::test]
async fn byte_budget_caps_inflight() {
    const MIB: u64 = 1024 * 1024;
    let budget = ByteBudget::new(48 * MIB);
    // Three 8 MiB parts (2 x 8 MiB each) fill it.
    let a = budget.charge_body(8 * MIB).await.unwrap();
    let b = budget.charge_body(8 * MIB).await.unwrap();
    let c = budget.charge_body(8 * MIB).await.unwrap();
    assert_eq!(budget.in_use(), 48 * MIB);
    // A fourth is refused without waiting (no sleeper): 503 SlowDown.
    let err = budget.charge_body(8 * MIB).await.unwrap_err();
    assert_eq!(err, IngressError::SlowDown);
    assert_eq!(err.response().status, 503);
    assert!(budget.try_charge(1).is_none());
    assert_eq!(budget.in_use(), 48 * MIB);
    drop((a, b, c));
    // One 16 MiB plus one 8 MiB body also fits.
    let big = budget.charge_body(16 * MIB).await.unwrap();
    let part = budget.charge_body(8 * MIB).await.unwrap();
    assert_eq!(budget.in_use(), 48 * MIB);
    assert_eq!(budget.peak(), 48 * MIB);
    drop((big, part));
    // A charge over the whole capacity can never fit.
    assert_eq!(
        budget.charge(48 * MIB + 1).await.unwrap_err(),
        IngressError::SlowDown
    );
    assert!(budget.try_charge(u64::MAX).is_none());
}

#[tokio::test]
async fn byte_budget_releases_on_drop() {
    let budget = ByteBudget::new(100);
    {
        let _a = budget.try_charge(60).unwrap();
        assert_eq!(budget.in_use(), 60);
        assert!(budget.try_charge(41).is_none());
        let b = budget.try_charge(40).unwrap();
        assert_eq!(b.bytes(), 40);
        assert_eq!(budget.in_use(), 100);
    }
    assert_eq!(budget.in_use(), 0);
    assert_eq!(budget.peak(), 100);

    // Released on an early return / error path too.
    async fn fails_after_charging(budget: &ByteBudget) -> Result<(), IngressError> {
        let charge = budget.charge(50).await?;
        let body = watched_body(Some(10), vec![vec![0; 3]], Rc::new(Cell::new(0)));
        read_capped(body, 10, &charge).await?;
        Ok(())
    }
    assert_eq!(
        fails_after_charging(&budget).await,
        Err(IngressError::IncompleteBody)
    );
    assert_eq!(budget.in_use(), 0);
}

/// Sleeper that records each wait and runs a hook (no real time passes).
fn fake_sleeper(calls: Rc<Cell<u32>>, on_sleep: Rc<dyn Fn(u32)>) -> Sleeper {
    Rc::new(move |ms| {
        assert_eq!(ms, CHARGE_POLL_MS);
        calls.set(calls.get() + 1);
        on_sleep(calls.get());
        Box::pin(async {})
    })
}

#[tokio::test]
async fn byte_budget_waits_then_slows_down() {
    let calls = Rc::new(Cell::new(0));
    let budget = ByteBudget::new(100).with_sleeper(fake_sleeper(calls.clone(), Rc::new(|_| {})));
    let _held = budget.try_charge(100).unwrap();
    assert_eq!(budget.charge(1).await.unwrap_err(), IngressError::SlowDown);
    assert_eq!(calls.get(), CHARGE_WAIT_MS / CHARGE_POLL_MS);
}

#[tokio::test]
async fn byte_budget_waiter_gets_released_bytes() {
    let held: Rc<RefCell<Option<Charge>>> = Rc::new(RefCell::new(None));
    let calls = Rc::new(Cell::new(0));
    let h = held.clone();
    let budget = ByteBudget::new(100).with_sleeper(fake_sleeper(
        calls.clone(),
        Rc::new(move |n| {
            if n == 3 {
                h.borrow_mut().take();
            }
        }),
    ));
    *held.borrow_mut() = Some(budget.try_charge(80).unwrap());
    let c = budget.charge(50).await.unwrap();
    assert_eq!(calls.get(), 3);
    assert_eq!(budget.in_use(), 50);
    drop(c);
    assert_eq!(budget.in_use(), 0);
}

// ---------------------------------------------------------------------------
// Log redaction
// ---------------------------------------------------------------------------

#[test]
fn log_redacts_credentials() {
    let presigned = "/photos/2026/a.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKVLSECRETID0000000%2F20261113%2Fauto%2Fs3%2Faws4_request&X-Amz-Signature=deadbeefcafe&x-amz-security-token=tok";
    let line = ingress::log_line("GET", presigned, 200, "8f1c2a3b4c5d6e7f-AMS");
    assert!(
        line.starts_with("req method=GET bucket=photos key#="),
        "{line}"
    );
    assert!(
        line.ends_with("status=200 id=8f1c2a3b4c5d6e7f-AMS"),
        "{line}"
    );
    for leak in [
        "X-Amz",
        "AKVL",
        "deadbeef",
        "tok",
        "2026/a.jpg",
        "a.jpg",
        "Signature",
    ] {
        assert!(!line.contains(leak), "{leak} leaked: {line}");
    }
    // Same key, same hash; different key, different hash.
    let a = ingress::log_line("PUT", "/b/k1", 200, "-");
    assert_eq!(a, ingress::log_line("PUT", "/b/k1?x=1", 200, "-"));
    assert_ne!(a, ingress::log_line("PUT", "/b/k2", 200, "-"));

    // Hostile bucket, method or request id never reach the log verbatim.
    let line = ingress::log_line("G\nET", "/b%0A=evil/k", 403, "id\r\nx");
    assert_eq!(line, {
        let key = ingress::log_line("GET", "/b/k", 403, "-");
        let hash = key
            .split("key#=")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .to_string();
        format!("req method=- bucket=- key#={hash} status=403 id=-")
    });
    let admin = ingress::log_line("POST", "/_admin/keys", 201, "-");
    assert!(admin.contains("bucket=_admin"), "{admin}");
}

// ---------------------------------------------------------------------------
// Config bound
// ---------------------------------------------------------------------------

#[test]
fn kek_active_is_bounded() {
    let key = base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]);
    let mut v = vars(true);
    v.insert(
        "VELMORA_KEK_ACTIVE".into(),
        (MAX_KEK_VERSION + 1).to_string(),
    );
    v.insert(format!("VELMORA_KEK_{}", MAX_KEK_VERSION + 1), key.clone());
    assert_eq!(
        BridgeConfig::from_vars(|k| v.get(k).cloned()).unwrap_err(),
        ConfigError::Invalid("VELMORA_KEK_ACTIVE".into())
    );
    let probes = Cell::new(0u32);
    let err = KekRing::from_vars(u32::MAX, |_| {
        probes.set(probes.get() + 1);
        Some(key.clone())
    })
    .unwrap_err();
    assert_eq!(err, ConfigError::Invalid("VELMORA_KEK_ACTIVE".into()));
    assert_eq!(probes.get(), 0, "no lookups for an out-of-range version");

    // The highest allowed version loads.
    let mut v = vars(true);
    v.insert("VELMORA_KEK_ACTIVE".into(), MAX_KEK_VERSION.to_string());
    v.insert(format!("VELMORA_KEK_{MAX_KEK_VERSION}"), key.clone());
    let cfg = BridgeConfig::from_vars(|k| v.get(k).cloned()).unwrap();
    assert_eq!(cfg.kek_active, MAX_KEK_VERSION);
    let ring = KekRing::from_vars(cfg.kek_active, |k| v.get(k).cloned()).unwrap();
    use velmora_bridge::Kek as _;
    assert_eq!(ring.active().0, MAX_KEK_VERSION);
    assert!(ring.version(1).is_some());
}

#[test]
fn tls_provider_port_must_be_119_or_563() {
    let provider = |port: u16, tls: bool| {
        format!(
            r#"[{{"id":"p1","host":"nntp.invalid","port":{port},"tls":{tls},"user":"u","pass":"p","backbone":"bb1","post":true,"read":true,"max_conns":2}}]"#
        )
    };
    let load = |providers: String| {
        let mut v = vars(true);
        v.insert("NNTP_PROVIDERS".into(), providers);
        BridgeConfig::from_vars(|k| v.get(k).cloned())
    };
    assert_eq!(velmora_bridge::config::TLS_PORTS, [119, 563]);
    for port in [119, 563] {
        assert!(load(provider(port, true)).is_ok(), "tls port {port}");
    }
    for port in [1, 443, 562, 564, 8563, 11119, 65535] {
        assert_eq!(
            load(provider(port, true)).unwrap_err(),
            ConfigError::Invalid("NNTP_PROVIDERS".into()),
            "tls port {port}"
        );
    }
    // Plaintext (dev only) is not bound by the TLS policy.
    assert!(load(provider(11119, false)).is_ok());
}
