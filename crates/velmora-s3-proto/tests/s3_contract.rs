// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/tests/s3_contract.rs. License: MIT.
// Copied verbatim except: line 1 `use qerith_core::s3::*;` -> `use velmora_s3_proto::*;`, which rustfmt then sorts after `use serde_json::Value;`; this header.
// Changed for S3 STANDARD semantics and the signed comma-value rule: the cold-archive
// (restore/unavailable) cases are removed, `plan_read` lost its `available` argument,
// storage-class assertions expect STANDARD, and the `signed-metadata` vector (signed
// Cache-Control and Expires values contain commas) now expects InvalidRequest.

use serde_json::Value;
use velmora_s3_proto::*;

const NOW: i64 = 1369353600;
const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC_SHA_B64: &str = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";

fn limits() -> Limits {
    // Synthetic fixture values ONLY, not selected production/admission limits.
    Limits {
        target_bytes: 8192,
        control_xml_bytes: 4096,
        header_bytes: 16384,
        header_count: 64,
        query_pairs: 64,
        upload_bytes: 1024,
        clock_skew_seconds: 900,
        presign_seconds: 60,
    }
}
fn policy() -> Policy {
    Policy::new(
        "s3.us-east-1.amazonaws.com".into(),
        "us-east-1".into(),
        limits(),
    )
    .unwrap()
}
fn fixture(name: &str) -> Value {
    let all: Vec<Value> = serde_json::from_str(include_str!("fixtures/s3-static.json")).unwrap();
    all.into_iter().find(|v| v["name"] == name).unwrap()
}
fn fields(v: &Value) -> Vec<(String, String)> {
    v["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p[0].as_str().unwrap().into(), p[1].as_str().unwrap().into()))
        .collect()
}
fn headers(fields: &[(String, String)]) -> Headers {
    Headers::new(
        &fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
        &policy(),
    )
    .unwrap()
}
fn set(fields: &mut Vec<(String, String)>, key: &str, value: &str) {
    fields.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    fields.push((key.into(), value.into()));
}
struct Auth {
    active: bool,
    allowed: bool,
}
impl Authority for Auth {
    fn credential(&self, key: &str) -> Option<Credential<'_>> {
        (self.active && key == "AKIDEXAMPLE").then_some(Credential {
            secret: b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            principal: "fixture-tenant",
        })
    }
    fn authorize(&self, principal: &str, _: &str, target: &Target) -> bool {
        self.allowed && principal == "fixture-tenant" && target.bucket == "bucket"
    }
}
fn authority() -> Auth {
    Auth {
        active: true,
        allowed: true,
    }
}
fn verified(name: &str) -> VerifiedRequest {
    let v = fixture(name);
    verify(
        v["method"].as_str().unwrap(),
        &Target::parse(v["target"].as_str().unwrap(), &policy()).unwrap(),
        &headers(&fields(&v)),
        true,
        NOW,
        &policy(),
        &authority(),
    )
    .unwrap()
}

#[test]
fn static_botocore_canonical_and_signature_goldens() {
    let all: Vec<Value> = serde_json::from_str(include_str!("fixtures/s3-static.json")).unwrap();
    for v in all {
        let h = headers(&fields(&v));
        let p = Policy::new(
            h.get("host").unwrap().to_ascii_lowercase(),
            "us-east-1".into(),
            limits(),
        )
        .unwrap();
        let target = Target::parse(v["target"].as_str().unwrap(), &p).unwrap();
        let presigned = v["presigned"].as_bool().unwrap();
        assert_eq!(
            canonical_request(
                v["method"].as_str().unwrap(),
                &target,
                &h,
                v["signed_headers"].as_str().unwrap(),
                h.get("x-amz-content-sha256").unwrap_or("UNSIGNED-PAYLOAD"),
                presigned
            )
            .unwrap(),
            v["canonical"].as_str().unwrap(),
            "{}",
            v["name"]
        );
        if v["name"] == "signed-metadata" {
            // Signed comma-bearing values off the single-value allow-list are
            // refused before the signature is computed (possible merged duplicates).
            assert_eq!(
                verify(
                    v["method"].as_str().unwrap(),
                    &target,
                    &h,
                    true,
                    NOW,
                    &p,
                    &authority()
                )
                .unwrap_err(),
                ErrorCode::InvalidRequest
            );
        } else if !v["canonical_only"].as_bool().unwrap() {
            let result = verify(
                v["method"].as_str().unwrap(),
                &target,
                &h,
                true,
                NOW,
                &p,
                &authority(),
            )
            .unwrap();
            assert_eq!(
                result.mode,
                if presigned {
                    AuthMode::Presigned
                } else {
                    AuthMode::Header
                }
            );
            // Mutating any signed method/path/header cannot authenticate.
            assert!(verify("DELETE", &target, &h, true, NOW, &policy(), &authority()).is_err());
            let changed =
                Target::parse(&format!("{}x", v["target"].as_str().unwrap()), &policy()).unwrap();
            assert!(verify(
                v["method"].as_str().unwrap(),
                &changed,
                &h,
                true,
                NOW,
                &policy(),
                &authority()
            )
            .is_err());
            let mut f = fields(&v);
            set(&mut f, "host", "other.invalid");
            assert!(verify(
                v["method"].as_str().unwrap(),
                &target,
                &headers(&f),
                true,
                NOW,
                &policy(),
                &authority()
            )
            .is_err());
        }
    }
}

#[test]
fn endpoint_host_casing_preserves_signed_bytes_and_port() {
    for name in [
        "header-empty",
        "presign-get",
        "header-mixed-host",
        "presign-mixed-host",
        "header-host-port",
        "presign-host-port",
    ] {
        let v = fixture(name);
        let h = headers(&fields(&v));
        let host = h.get("host").unwrap();
        let target = Target::parse(v["target"].as_str().unwrap(), &policy()).unwrap();
        for endpoint in [host.to_ascii_lowercase(), host.to_ascii_uppercase()] {
            let p = Policy::new(endpoint, "us-east-1".into(), limits()).unwrap();
            assert!(
                verify("GET", &target, &h, true, NOW, &p, &authority()).is_ok(),
                "{name}"
            );
            assert_eq!(
                verify("GET", &target, &h, false, NOW, &p, &authority()).unwrap_err(),
                ErrorCode::AccessDenied
            );
        }
        for endpoint in [
            "other.invalid".to_owned(),
            format!("{}:443", host.split(':').next().unwrap()),
            format!("{}:9443", host.split(':').next().unwrap()),
        ] {
            let p = Policy::new(endpoint, "us-east-1".into(), limits()).unwrap();
            assert_eq!(
                verify("GET", &target, &h, true, NOW, &p, &authority()).unwrap_err(),
                ErrorCode::AccessDenied,
                "{name}"
            );
        }
        if name.contains("mixed-host") || name.contains("host-port") {
            let p = Policy::new(host.to_ascii_lowercase(), "us-east-1".into(), limits()).unwrap();
            let mut f = fields(&v);
            set(&mut f, "Host", &host.to_ascii_lowercase());
            assert_eq!(
                verify("GET", &target, &headers(&f), true, NOW, &p, &authority()).unwrap_err(),
                ErrorCode::SignatureDoesNotMatch,
                "casing the signed Host bytes must invalidate {name}"
            );
        }
    }
}

#[test]
fn raw_paths_and_queries_are_not_generic_url_normalized() {
    let target = Target::parse(
        "/bucket/A//./../%E9%9B%AA+%2B%25%2f?z=2&z=1&Z=&=x&&plus=+&percent=%25",
        &policy(),
    )
    .unwrap();
    assert_eq!(target.key.as_deref(), Some("A//./../雪++%/"));
    assert_eq!(
        target.canonical_path(),
        "/bucket/A//./../%E9%9B%AA+%2B%25%2f"
    );
    assert_eq!(
        target.canonical_query(false),
        "=&=x&Z=&percent=%25&plus=+&z=1&z=2"
    );
    assert_eq!(target.query().len(), 7);
    for target in [
        "https://s3.invalid/bucket/key",
        "/Bucket/key",
        "/bucket/k%",
        "/bucket/k%0Z",
        "/bucket/雪",
        "/bucket/key#fragment",
        "/bucket/key?q=%",
        "/127.0.0.1/key",
        "/bu..cket/key",
    ] {
        assert!(Target::parse(target, &policy()).is_err(), "{target}");
    }
    assert_ne!(
        Target::parse("/bucket/Key", &policy()).unwrap(),
        Target::parse("/bucket/key", &policy()).unwrap()
    );
    assert_eq!(
        Target::parse("/bucket/", &policy()).unwrap().key,
        Some(String::new())
    );
}

#[test]
fn signature_clock_scope_tls_and_revocation_boundaries() {
    let v = fixture("header-empty");
    let target = Target::parse(v["target"].as_str().unwrap(), &policy()).unwrap();
    let f = fields(&v);
    let h = headers(&f);
    for time in [NOW - 900, NOW, NOW + 900] {
        assert!(verify("GET", &target, &h, true, time, &policy(), &authority()).is_ok());
    }
    for time in [NOW - 901, NOW + 901, i64::MAX, i64::MIN] {
        assert_eq!(
            verify("GET", &target, &h, true, time, &policy(), &authority()).unwrap_err(),
            ErrorCode::RequestTimeTooSkewed
        );
    }
    assert_eq!(
        verify("GET", &target, &h, false, NOW, &policy(), &authority()).unwrap_err(),
        ErrorCode::AccessDenied
    );
    assert!(verify(
        "GET",
        &target,
        &h,
        true,
        NOW,
        &policy(),
        &Auth {
            active: false,
            allowed: true
        }
    )
    .is_err());
    assert!(verify(
        "GET",
        &target,
        &h,
        true,
        NOW,
        &policy(),
        &Auth {
            active: true,
            allowed: false
        }
    )
    .is_err());
    verified("header-empty")
        .recheck(&authority(), "GET", &target)
        .unwrap();
    assert!(verified("header-empty")
        .recheck(
            &Auth {
                active: false,
                allowed: true
            },
            "GET",
            &target
        )
        .is_err());
    for replacement in ["us-west-2/s3", "us-east-1/sts", "us-east-1/S3"] {
        let mut f = f.clone();
        let auth = h
            .get("authorization")
            .unwrap()
            .replace("us-east-1/s3", replacement);
        set(&mut f, "authorization", &auth);
        assert!(verify(
            "GET",
            &target,
            &headers(&f),
            true,
            NOW,
            &policy(),
            &authority()
        )
        .is_err());
    }
    let p = fixture("presign-get");
    let raw = p["target"].as_str().unwrap();
    let target = Target::parse(raw, &policy()).unwrap();
    let h = headers(&fields(&p));
    assert!(verify("GET", &target, &h, true, NOW + 59, &policy(), &authority()).is_ok());
    assert!(verify("GET", &target, &h, true, NOW + 60, &policy(), &authority()).is_err());
    assert!(verify("GET", &target, &h, false, NOW, &policy(), &authority()).is_err());
    for extra in [
        "&X-Amz-Expires=60",
        "&X-Amz-Security-Token=unknown",
        "&X-Amz-Date=20130524T000000Z",
    ] {
        assert!(verify(
            "GET",
            &Target::parse(&format!("{raw}{extra}"), &policy()).unwrap(),
            &h,
            true,
            NOW,
            &policy(),
            &authority()
        )
        .is_err());
    }
    let mut f = fields(&p);
    set(&mut f, "authorization", "AWS4-HMAC-SHA256 Credential=other");
    assert!(verify(
        "GET",
        &target,
        &headers(&f),
        true,
        NOW,
        &policy(),
        &authority()
    )
    .is_err());
}

#[test]
fn unknown_integrity_encryption_tokens_and_policy_fields_fail_closed() {
    let v = fixture("header-empty");
    let target = Target::parse(v["target"].as_str().unwrap(), &policy()).unwrap();
    for (key, value) in [
        ("x-amz-security-token", "unknown"),
        ("x-amz-s3session-token", "unknown"),
        ("x-amz-server-side-encryption", "AES256"),
        ("x-amz-checksum-crc64nvme", "AAAA"),
        ("x-amz-object-lock-mode", "GOVERNANCE"),
        ("x-amz-acl", "public-read"),
        ("x-amz-unknown", "value"),
        ("x-amz-storage-class", "GLACIER"),
        ("x-amz-checksum-mode", "DISABLED"),
    ] {
        let mut f = fields(&v);
        set(&mut f, key, value);
        assert!(
            verify(
                "GET",
                &target,
                &headers(&f),
                true,
                NOW,
                &policy(),
                &authority()
            )
            .is_err(),
            "{key}"
        );
    }
    for query in [
        "policy",
        "acl",
        "retention",
        "X-Amz-Security-Token=x",
        "x-amz-algorithm=x",
        "prefix=a&prefix=b",
    ] {
        let target = Target::parse(&format!("/bucket/key?{query}"), &policy()).unwrap();
        assert!(verify(
            "GET",
            &target,
            &headers(&fields(&v)),
            true,
            NOW,
            &policy(),
            &authority()
        )
        .is_err());
    }
    let mut f = fields(&v);
    set(
        &mut f,
        "x-amz-content-sha256",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
    );
    assert_eq!(
        verify(
            "GET",
            &target,
            &headers(&f),
            true,
            NOW,
            &policy(),
            &authority()
        )
        .unwrap_err(),
        ErrorCode::InvalidRequest
    );
    assert_eq!(storage_class(None), Ok("STANDARD"));
    assert_eq!(storage_class(Some("STANDARD")), Ok("STANDARD"));
    for class in ["standard", "GLACIER", "DEEP_ARCHIVE", "STANDARD_IA", ""] {
        assert_eq!(storage_class(Some(class)), Err(ErrorCode::InvalidRequest));
    }
}

#[test]
fn header_duplicates_bounds_case_and_signed_order() {
    for pairs in [
        vec![("Host", "a"), ("host", "a")],
        vec![("Content-Length", "3"), ("content-length", "3")],
        vec![("x-amz-date", "x"), ("X-Amz-Date", "y")],
        vec![("x", "a\r\nb")],
    ] {
        assert!(Headers::new(&pairs, &policy()).is_err());
    }
    let h = Headers::new(
        &[
            ("HOST", "s3.us-east-1.amazonaws.com"),
            ("X-Test", "  a\t b  "),
            ("x-test", "c"),
        ],
        &policy(),
    )
    .unwrap();
    let t = Target::parse("/bucket/key", &policy()).unwrap();
    assert!(
        canonical_request("GET", &t, &h, "host;x-test", EMPTY_SHA, false)
            .unwrap()
            .contains("x-test:a b,c\n")
    );
    for names in ["x-test;host", "host;host", "Host", "host;missing"] {
        assert!(canonical_request("GET", &t, &h, names, EMPTY_SHA, false).is_err());
    }
    let mut l = limits();
    l.target_bytes = 3;
    let p = Policy::new("s3.us-east-1.amazonaws.com".into(), "us-east-1".into(), l).unwrap();
    assert!(Target::parse("/bucket/key", &p).is_err());
    let mut l = limits();
    l.header_count = 1;
    let p = Policy::new("s3.us-east-1.amazonaws.com".into(), "us-east-1".into(), l).unwrap();
    assert!(Headers::new(&[("host", "s3.invalid"), ("x", "y")], &p).is_err());
}

#[test]
fn repeated_etag_conditions_combine_in_order_before_cold_state() {
    let m = metadata(None);
    let t = Target::parse("/bucket/key", &policy()).unwrap();
    for (name, second, matches) in [
        ("If-Match", "\"opaque,not-md5\"", true),
        ("If-Match", "\"other\"", false),
        ("If-Match", "W/\"opaque,not-md5\"", false),
        ("If-None-Match", "\"opaque,not-md5\"", true),
        ("If-None-Match", "W/\"opaque,not-md5\"", true),
        ("If-None-Match", "\"other\"", false),
    ] {
        let first = "\"miss,inside\"";
        let joined = format!("{first},{second}");
        let repeated = Headers::new(
            &[
                ("Host", "s3.us-east-1.amazonaws.com"),
                (name, first),
                (&name.to_ascii_lowercase(), second),
            ],
            &policy(),
        )
        .unwrap();
        let single = Headers::new(
            &[("Host", "s3.us-east-1.amazonaws.com"), (name, &joined)],
            &policy(),
        )
        .unwrap();
        assert_eq!(repeated.get(name), Some(joined.as_str()));
        let signed = format!("host;{}", name.to_ascii_lowercase());
        assert_eq!(
            canonical_request("GET", &t, &repeated, &signed, EMPTY_SHA, false).unwrap(),
            canonical_request("GET", &t, &single, &signed, EMPTY_SHA, false).unwrap()
        );
        for head in [false, true] {
            let c = Conditions::from_headers(&repeated);
            let result = plan_read(&m, head, &c, None, false).map(|p| p.status);
            let expected = if name == "If-Match" && !matches {
                Err(ErrorCode::PreconditionFailed)
            } else if name == "If-None-Match" && matches {
                Ok(304)
            } else {
                Ok(200)
            };
            assert_eq!(result, expected, "{name}: {joined}, head={head}");
        }
    }
    for name in [
        "Range",
        "If-Modified-Since",
        "If-Unmodified-Since",
        "Authorization",
    ] {
        assert!(
            Headers::new(&[(name, "x"), (name, "y")], &policy()).is_err(),
            "{name}"
        );
    }
}

#[test]
fn public_header_lookup_is_case_insensitive_without_changing_signing() {
    let h = Headers::new(
        &[
            ("Host", "s3.us-east-1.amazonaws.com"),
            ("Cache-Control", "public"),
            ("CACHE-control", "no-store"),
        ],
        &policy(),
    )
    .unwrap();
    for name in ["host", "Host", "HOST", "hOsT"] {
        assert_eq!(h.get(name), Some("s3.us-east-1.amazonaws.com"));
    }
    for name in ["cache-control", "Cache-Control", "CACHE-CONTROL"] {
        assert_eq!(h.get(name), Some("public,no-store"));
    }
    assert_eq!(h.get("Missing"), None);
    let t = Target::parse("/bucket/key", &policy()).unwrap();
    let canonical =
        canonical_request("GET", &t, &h, "cache-control;host", EMPTY_SHA, false).unwrap();
    assert!(canonical.contains("cache-control:public,no-store\nhost:s3.us-east-1.amazonaws.com\n"));
    assert!(canonical_request("GET", &t, &h, "Cache-Control;Host", EMPTY_SHA, false).is_err());
}

#[test]
fn upload_validates_decoded_bytes_length_sha256_md5_and_crc32() {
    let v = fixture("header-put");
    let f = fields(&v);
    let verified = verified("header-put");
    let mut upload = UploadValidator::new(&headers(&f), &verified, &policy()).unwrap();
    upload.push_decoded(b"a").unwrap();
    upload.push_decoded(b"bc").unwrap();
    let result = upload.finish().unwrap();
    assert_eq!(result.length(), 3);
    for (algorithm, value) in [("SHA256", ABC_SHA_B64), ("CRC32", "NSRBwg==")] {
        let mut f = f.clone();
        set(&mut f, "x-amz-sdk-checksum-algorithm", algorithm);
        set(
            &mut f,
            if algorithm == "SHA256" {
                "x-amz-checksum-sha256"
            } else {
                "x-amz-checksum-crc32"
            },
            value,
        );
        set(&mut f, "x-amz-checksum-type", "FULL_OBJECT");
        let mut upload = UploadValidator::new(&headers(&f), &verified, &policy()).unwrap();
        upload.push_decoded(b"abc").unwrap();
        assert!(upload.finish().unwrap().checksum().is_some());
    }
    let v = fixture("presign-put");
    let mut upload =
        UploadValidator::new(&headers(&fields(&v)), &super_verified(), &policy()).unwrap();
    upload.push_decoded(b"abc").unwrap();
    upload.finish().unwrap();
}
fn super_verified() -> VerifiedRequest {
    verified("presign-put")
}

#[test]
fn upload_errors_never_produce_a_commit_receipt() {
    let f = fields(&fixture("header-put"));
    let verified = verified("header-put");
    for length in ["-1", "+3", "3,3", "3 3", "18446744073709551616", ""] {
        let mut f = f.clone();
        set(&mut f, "content-length", length);
        assert!(UploadValidator::new(&headers(&f), &verified, &policy()).is_err());
    }
    for (k, v) in [
        ("transfer-encoding", "chunked"),
        ("content-encoding", "gzip, aws-chunked"),
        ("trailer", "x-amz-checksum-sha256"),
        ("x-amz-checksum-sha256", "not base64"),
        ("x-amz-checksum-crc32", "AAAA"),
        ("x-amz-sdk-checksum-algorithm", "CRC64NVME"),
        ("x-amz-checksum-type", "COMPOSITE"),
        ("content-md5", "AAAA"),
        ("content-length", "1025"),
    ] {
        let mut f = f.clone();
        set(&mut f, k, v);
        assert!(
            UploadValidator::new(&headers(&f), &verified, &policy()).is_err(),
            "{k}={v}"
        );
    }
    let mut short = UploadValidator::new(&headers(&f), &verified, &policy()).unwrap();
    short.push_decoded(b"ab").unwrap();
    assert_eq!(short.finish().unwrap_err(), ErrorCode::IncompleteBody);
    let mut long = UploadValidator::new(&headers(&f), &verified, &policy()).unwrap();
    assert!(long.push_decoded(b"4\r\nabc\r\n0\r\n\r\n").is_err());
    assert!(long.push_decoded(b"abc").is_err());
    assert!(long.finish().is_err());
    let mut wrong = UploadValidator::new(&headers(&f), &verified, &policy()).unwrap();
    wrong.push_decoded(b"abd").unwrap();
    assert_eq!(wrong.finish().unwrap_err(), ErrorCode::BadDigest);
    let mut f = fields(&fixture("presign-put"));
    set(&mut f, "content-md5", "AAAAAAAAAAAAAAAAAAAAAA==");
    let mut wrong = UploadValidator::new(&headers(&f), &super_verified(), &policy()).unwrap();
    wrong.push_decoded(b"abc").unwrap();
    assert_eq!(wrong.finish().unwrap_err(), ErrorCode::BadDigest);
}

fn metadata(checksum: Option<StoredChecksum>) -> ObjectMetadata {
    ObjectMetadata::new(
        "immutable-generation".into(),
        10,
        "\"opaque,not-md5\"".into(),
        NOW,
        vec![("content-encoding".into(), "customer-envelope".into())],
        checksum,
    )
    .unwrap()
}
fn header<'a>(plan: &'a ReadPlan, name: &str) -> Option<&'a str> {
    plan.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn authenticated_metadata_survives_commit_and_read_without_whitespace_folding() {
    for (name, expected) in [
        ("header-whitespace", vec![("x-amz-meta-name", "a\t b   c")]),
        (
            "metadata-token-name",
            vec![("x-amz-meta-file_name!#$%&'*+-.^`|~", "a\t b   c")],
        ),
    ] {
        let v = fixture(name);
        let h = headers(&fields(&v));
        let t = Target::parse(v["target"].as_str().unwrap(), &policy()).unwrap();
        let auth = verify("PUT", &t, &h, true, NOW, &policy(), &authority()).unwrap();
        let mut upload = UploadValidator::new(&h, &auth, &policy()).unwrap();
        upload
            .push_decoded(v["body"].as_str().unwrap().as_bytes())
            .unwrap();
        let receipt = upload.finish().unwrap();
        let content_headers = expected
            .iter()
            .map(|(k, value)| {
                assert_eq!(h.get(k), Some(*value));
                (k.to_string(), h.get(k).unwrap().to_owned())
            })
            .collect();
        let m = ObjectMetadata::new(
            "g".into(),
            receipt.length(),
            "\"opaque\"".into(),
            NOW,
            content_headers,
            None,
        )
        .unwrap();
        for head in [false, true] {
            for range in [None, Some("bytes=0-1")] {
                let plan = plan_read(&m, head, &Conditions::default(), range, false).unwrap();
                for (k, value) in &expected {
                    assert_eq!(header(&plan, k), Some(*value), "{name}: {k}");
                }
                assert_eq!(plan.body.is_none(), head);
            }
        }
    }
}

#[test]
fn metadata_rejects_unsafe_header_bytes_at_ingress_and_storage() {
    let stored = |name: &str, value: &str| {
        ObjectMetadata::new(
            "g".into(),
            3,
            "\"opaque\"".into(),
            NOW,
            vec![(name.into(), value.into())],
            None,
        )
    };
    for byte in (0u8..=31).filter(|b| *b != b'\t').chain([127]) {
        let value = format!("a{}b", char::from(byte));
        assert!(Headers::new(&[("x-amz-meta-name", &value)], &policy()).is_err());
        assert_eq!(
            stored("x-amz-meta-name", &value).unwrap_err(),
            ErrorCode::InvalidArgument
        );
    }
    for value in ["a\r\nb", "café", "雪"] {
        assert!(Headers::new(&[("x-amz-meta-name", value)], &policy()).is_err());
        assert!(stored("x-amz-meta-name", value).is_err());
    }
    for suffix in [
        " ", "\t", "\r", "\n", "\0", "\u{7f}", "(", ")", "<", ">", "@", ",", ";", ":", "\\", "\"",
        "/", "[", "]", "?", "=", "{", "}", "雪",
    ] {
        let name = format!("x-amz-meta-file{suffix}name");
        assert!(
            Headers::new(&[(&name, "value")], &policy()).is_err(),
            "{name:?}"
        );
        assert!(stored(&name, "value").is_err(), "{name:?}");
    }
    for name in [
        "x-amz-meta-",
        "x-amz-meta-Name",
        "X-Amz-Meta-Name",
        "etag",
        "content-length",
    ] {
        assert!(stored(name, "value").is_err(), "{name}");
    }
}

#[test]
fn condition_precedence_and_range_validation_precede_cold_state() {
    let m = metadata(None);
    let c = Conditions {
        if_match: Some(m.etag().into()),
        if_unmodified_since: Some("Thu, 23 May 2013 00:00:00 GMT".into()),
        ..Default::default()
    };
    assert_eq!(plan_read(&m, false, &c, None, false).unwrap().status, 200);
    let c = Conditions {
        if_none_match: Some("\"different\"".into()),
        if_modified_since: Some("Sat, 25 May 2013 00:00:00 GMT".into()),
        ..Default::default()
    };
    assert_eq!(plan_read(&m, false, &c, None, false).unwrap().status, 200);
    let c = Conditions {
        if_none_match: Some("W/\"opaque,not-md5\"".into()),
        ..Default::default()
    };
    let p = plan_read(&m, false, &c, Some("bytes=99-"), false).unwrap();
    assert_eq!(p.status, 304);
    assert!(p.body.is_none());
    let c = Conditions {
        if_match: Some("W/\"opaque,not-md5\"".into()),
        ..Default::default()
    };
    assert_eq!(
        plan_read(&m, false, &c, None, false).unwrap_err(),
        ErrorCode::PreconditionFailed
    );
    let c = Conditions {
        if_match: Some("\"other\", \"opaque,not-md5\"".into()),
        ..Default::default()
    };
    assert!(plan_read(&m, true, &c, None, false).is_ok());
    assert_eq!(
        plan_read(&m, false, &Conditions::default(), Some("bytes=99-"), false).unwrap_err(),
        ErrorCode::InvalidRange
    );
    assert_eq!(
        plan_read(
            &m,
            false,
            &Conditions::default(),
            Some("bytes=0-1,3-4"),
            false
        )
        .unwrap_err(),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        plan_read(&m, true, &Conditions::default(), Some("bytes=99-"), false).unwrap_err(),
        ErrorCode::InvalidRange
    );
}

#[test]
fn range_goldens_and_head_are_bodyless() {
    let m = metadata(None);
    for (value, start, end) in [
        ("bytes=0-0", 0, 0),
        ("bytes=2-", 2, 9),
        ("bytes=-3", 7, 9),
        ("bytes=-99", 0, 9),
        ("bytes=2-999", 2, 9),
    ] {
        let plan = plan_read(&m, false, &Conditions::default(), Some(value), false).unwrap();
        assert_eq!(plan.status, 206);
        assert_eq!(plan.body, Some(ByteRange { start, end }));
        assert_eq!(
            header(&plan, "content-length"),
            Some((end - start + 1).to_string().as_str())
        );
        assert_eq!(
            header(&plan, "content-range"),
            Some(format!("bytes {start}-{end}/10").as_str())
        );
        let head = plan_read(&m, true, &Conditions::default(), Some(value), false).unwrap();
        assert_eq!(head.status, 200);
        assert!(head.body.is_none());
        assert_eq!(header(&head, "content-range"), None);
    }
    for value in [
        "bytes=-0",
        "bytes=10-",
        "bytes=3-2",
        "bytes=+1-2",
        "bytes=0-18446744073709551616",
        "items=0-1",
        "bytes=1-2-3",
    ] {
        assert_eq!(
            ByteRange::parse(value, 10).unwrap_err(),
            ErrorCode::InvalidRange,
            "{value}"
        );
    }
    assert!(ByteRange::parse("bytes=0-0", 0).is_err());
    assert_eq!(
        ByteRange::parse("bytes=0-", u64::MAX).unwrap().length(),
        u64::MAX
    );
    assert!(plan_read(&m, true, &Conditions::default(), None, false)
        .unwrap()
        .body
        .is_none());
    assert_eq!(m.generation(), "immutable-generation");
    assert_eq!(m.length(), 10);
}

#[test]
fn opaque_etag_and_checksum_type_are_preserved_not_reinterpreted() {
    let full = StoredChecksum::full(ChecksumAlgorithm::Sha256, ABC_SHA_B64.into()).unwrap();
    let composite =
        StoredChecksum::composite_sha256(vec![ABC_SHA_B64.into(), ABC_SHA_B64.into()]).unwrap();
    assert_eq!(composite.checksum_type(), "COMPOSITE");
    assert!(composite.value().ends_with("-2"));
    assert_eq!(composite.parts().len(), 2);
    assert!(StoredChecksum::full(ChecksumAlgorithm::Sha256, composite.value().into()).is_err());
    assert!(StoredChecksum::composite_sha256(vec![]).is_err());
    for checksum in [full, composite] {
        let kind = checksum.checksum_type();
        let value = checksum.value().to_owned();
        let m = metadata(Some(checksum));
        let plan = plan_read(&m, false, &Conditions::default(), None, true).unwrap();
        assert_eq!(header(&plan, "etag"), Some("\"opaque,not-md5\""));
        assert_eq!(header(&plan, "x-amz-checksum-type"), Some(kind));
        assert_eq!(header(&plan, "x-amz-checksum-sha256"), Some(value.as_str()));
        assert_eq!(header(&plan, "content-encoding"), Some("customer-envelope"));
        let range = plan_read(&m, false, &Conditions::default(), Some("bytes=0-1"), true).unwrap();
        assert_eq!(header(&range, "x-amz-checksum-type"), None);
        assert_eq!(header(&range, "x-amz-checksum-sha256"), None);
        let head = plan_read(&m, true, &Conditions::default(), None, true).unwrap();
        assert_eq!(header(&head, "x-amz-checksum-type"), Some(kind));
    }
    assert!(ObjectMetadata::new("g".into(), 1, "not-quoted".into(), NOW, vec![], None).is_err());
    assert!(ObjectMetadata::new(
        "g".into(),
        1,
        "\"opaque\"".into(),
        NOW,
        vec![("etag".into(), "replacement".into())],
        None
    )
    .is_err());
}

#[test]
fn repeated_and_quoted_metadata_have_one_authenticated_semantics() {
    let h = Headers::new(
        &[
            ("host", "s3.us-east-1.amazonaws.com"),
            ("cache-control", "public"),
            ("Cache-Control", "no-store"),
            ("content-disposition", "attachment; filename=\"a  b.txt\""),
        ],
        &policy(),
    )
    .unwrap();
    assert_eq!(h.get("cache-control"), Some("public,no-store"));
    assert_eq!(
        h.get("content-disposition"),
        Some("attachment; filename=\"a  b.txt\"")
    );
    let t = Target::parse("/bucket/key", &policy()).unwrap();
    let canonical = canonical_request(
        "PUT",
        &t,
        &h,
        "cache-control;content-disposition;host",
        EMPTY_SHA,
        false,
    )
    .unwrap();
    assert!(canonical.contains("cache-control:public,no-store\n"));
    assert!(canonical.contains("content-disposition:attachment; filename=\"a b.txt\"\n"));
    for name in ["content-type", "content-disposition", "expires"] {
        assert!(Headers::new(&[(name, "a"), (name, "b")], &policy()).is_err());
    }
}

#[test]
fn persistent_metadata_cannot_be_added_to_an_existing_presign() {
    let v = fixture("presign-put");
    let t = Target::parse(v["target"].as_str().unwrap(), &policy()).unwrap();
    for (name, value) in [
        ("content-disposition", "attachment"),
        ("content-language", "en"),
        ("cache-control", "public"),
        ("expires", "Sat, 25 May 2013 00:00:00 GMT"),
    ] {
        let mut f = fields(&v);
        set(&mut f, name, value);
        assert_eq!(
            verify("PUT", &t, &headers(&f), true, NOW, &policy(), &authority()).unwrap_err(),
            ErrorCode::AccessDenied
        );
    }
}

#[test]
fn all_http_date_forms_enforce_conditions_before_cold_state() {
    let m = metadata(None);
    for value in [
        "Fri, 24 May 2013 00:00:00 GMT",
        "Friday, 24-May-13 00:00:00 GMT",
        "Fri May 24 00:00:00 2013",
    ] {
        let c = Conditions {
            if_modified_since: Some(value.into()),
            ..Default::default()
        };
        assert_eq!(
            plan_read(&m, false, &c, None, false).unwrap().status,
            304,
            "{value}"
        );
    }
    for value in [
        "Thu, 23 May 2013 00:00:00 GMT",
        "Thursday, 23-May-13 00:00:00 GMT",
        "Thu May 23 00:00:00 2013",
    ] {
        let c = Conditions {
            if_unmodified_since: Some(value.into()),
            ..Default::default()
        };
        assert_eq!(
            plan_read(&m, false, &c, None, false).unwrap_err(),
            ErrorCode::PreconditionFailed,
            "{value}"
        );
    }
}

#[test]
fn pre_epoch_dates_enforce_conditions_before_cold_state() {
    let m = metadata(None);
    for value in [
        "Wed, 31 Dec 1969 23:59:59 GMT",
        "Wed Dec 31 23:59:59 1969",
        "Mon, 01 Jan 1900 00:00:00 GMT",
        "Mon Jan  1 00:00:00 1900",
        "Thu, 29 Feb 1968 00:00:00 GMT",
    ] {
        let c = Conditions {
            if_unmodified_since: Some(value.into()),
            ..Default::default()
        };
        for head in [false, true] {
            assert_eq!(
                plan_read(&m, head, &c, None, false).unwrap_err(),
                ErrorCode::PreconditionFailed,
                "{value}: head={head}"
            );
        }
        let c = Conditions {
            if_match: Some(m.etag().into()),
            ..c
        };
        assert_eq!(plan_read(&m, false, &c, None, false).unwrap().status, 200);
    }
    let m = ObjectMetadata::new("g".into(), 10, "\"opaque\"".into(), -2, vec![], None).unwrap();
    let value = "Wed, 31 Dec 1969 23:59:59 GMT";
    let c = Conditions {
        if_modified_since: Some(value.into()),
        ..Default::default()
    };
    assert_eq!(plan_read(&m, false, &c, None, false).unwrap().status, 304);
    let c = Conditions {
        if_unmodified_since: Some(value.into()),
        ..Default::default()
    };
    assert_eq!(plan_read(&m, false, &c, None, false).unwrap().status, 200);
    for value in [
        "Thu, 31 Dec 1969 23:59:59 GMT",
        "Wed, 31 Dec 1969 23:59:59 UTC",
        "Mon, 29 Feb 1900 00:00:00 GMT",
        "Wed, 31 Dec 1969 23:59:60 GMT",
        "Wed, 31 Dec 1969 23:59:59 GMT trailing",
    ] {
        let c = Conditions {
            if_unmodified_since: Some(value.into()),
            ..Default::default()
        };
        assert_eq!(
            plan_read(&metadata(None), false, &c, None, false)
                .unwrap()
                .status,
            200,
            "{value}"
        );
    }
}

#[test]
fn signed_or_expanded_http_date_years_are_ignored() {
    for value in [
        "Fri, 01 Jan -0001 00:00:00 GMT",
        "Fri Jan  1 00:00:00 -0001",
        "Wed, 31 Dec +1969 23:59:59 GMT",
        "Wed Dec 31 23:59:59 +1969",
        "Sat, 01 Jan +10000 00:00:00 GMT",
        "Sat Jan  1 00:00:00 +10000",
    ] {
        let c = Conditions {
            if_unmodified_since: Some(value.into()),
            ..Default::default()
        };
        for head in [false, true] {
            assert_eq!(
                plan_read(&metadata(None), head, &c, None, false)
                    .unwrap()
                    .status,
                200,
                "{value}"
            );
        }
        let before = chrono::NaiveDate::from_ymd_opt(-2, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        let m =
            ObjectMetadata::new("g".into(), 10, "\"opaque\"".into(), before, vec![], None).unwrap();
        let c = Conditions {
            if_modified_since: Some(value.into()),
            ..Default::default()
        };
        for head in [false, true] {
            assert_eq!(
                plan_read(&m, head, &c, None, false).unwrap().status,
                200,
                "{value}"
            );
        }
    }
}

#[test]
fn not_modified_retains_corresponding_cache_policy() {
    let m = ObjectMetadata::new(
        "g".into(),
        10,
        "\"opaque\"".into(),
        NOW,
        vec![
            ("cache-control".into(), "private, no-store".into()),
            ("expires".into(), "Sat, 25 May 2013 00:00:00 GMT".into()),
        ],
        None,
    )
    .unwrap();
    let c = Conditions {
        if_none_match: Some("\"opaque\"".into()),
        ..Default::default()
    };
    let p = plan_read(&m, false, &c, None, false).unwrap();
    assert_eq!(p.status, 304);
    assert!(p.body.is_none());
    assert_eq!(header(&p, "cache-control"), Some("private, no-store"));
    assert_eq!(header(&p, "expires"), Some("Sat, 25 May 2013 00:00:00 GMT"));
}

#[test]
fn explicit_policy_is_required_and_errors_are_s3_xml_except_head() {
    let mut l = limits();
    l.clock_skew_seconds = 0;
    assert!(Policy::new("s3.invalid".into(), "r".into(), l).is_err());
    let mut l = limits();
    l.presign_seconds = 604801;
    assert!(Policy::new("s3.invalid".into(), "r".into(), l).is_err());
    assert!(Policy::new("https://s3.invalid".into(), "r".into(), limits()).is_err());
    for (error, status) in [
        (ErrorCode::AccessDenied, 403),
        (ErrorCode::InvalidRange, 416),
        (ErrorCode::PreconditionFailed, 412),
        (ErrorCode::BadDigest, 400),
        (ErrorCode::NoSuchKey, 404),
        (ErrorCode::BucketNotEmpty, 409),
        (ErrorCode::NotImplemented, 501),
        (ErrorCode::SlowDown, 503),
    ] {
        let get = error.response(false, "id<&\"\u{1}");
        assert_eq!(get.status, status);
        let body = String::from_utf8(get.body).unwrap();
        assert!(body.contains(&format!("<Code>{error:?}</Code>")));
        assert!(body.contains("id&lt;&amp;&quot;�"));
        let head = error.response(true, "request-id");
        assert_eq!(head.status, status);
        assert!(head.body.is_empty());
    }
}
