//! The client-side signer against the published AWS examples and against
//! this crate's own verifier.

use sha2::{Digest, Sha256};
use velmora_s3_proto::sign::{sign_request, SignedRequest, SigningKey, Unsigned, EMPTY_SHA256};
use velmora_s3_proto::{verify, Authority, Credential, ErrorCode, Headers, Limits, Policy, Target};

/// 2013-05-24T00:00:00Z, the time of the published examples.
const NOW: i64 = 1_369_353_600;
const HOST: &str = "store.example";

/// The example credentials of the AWS SigV4 documentation ("Signature
/// Calculations for the Authorization Header"): published test values,
/// not credentials.
const DOC_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const DOC_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const DOC_HOST: &str = "examplebucket.s3.amazonaws.com";

fn doc_key() -> SigningKey<'static> {
    SigningKey {
        access_key: DOC_ACCESS_KEY,
        secret: DOC_SECRET,
        region: "us-east-1",
    }
}

fn header<'a>(signed: &'a SignedRequest, name: &str) -> &'a str {
    signed
        .headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap()
}

fn signature(signed: &SignedRequest) -> &str {
    header(signed, "authorization")
        .rsplit_once("Signature=")
        .unwrap()
        .1
}

#[test]
fn sigv4_get_matches_aws_test_vector() {
    let signed = sign_request(
        &doc_key(),
        DOC_HOST,
        NOW,
        &Unsigned {
            method: "GET",
            path: "/test.txt",
            query: &[],
            headers: &[("range", "bytes=0-9")],
            payload_sha256: EMPTY_SHA256,
        },
    )
    .unwrap();
    assert_eq!(
        signature(&signed),
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert_eq!(
        header(&signed, "authorization"),
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
         SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
         Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert_eq!(header(&signed, "x-amz-date"), "20130524T000000Z");
    assert!(signed.headers.iter().all(|(k, _)| k != "host"));
}

#[test]
fn sigv4_list_query_is_canonical_and_sorted() {
    // Given out of order: the signer sorts.
    let signed = sign_request(
        &doc_key(),
        DOC_HOST,
        NOW,
        &Unsigned {
            method: "GET",
            path: "/",
            query: &[("prefix", "J"), ("max-keys", "2")],
            headers: &[],
            payload_sha256: EMPTY_SHA256,
        },
    )
    .unwrap();
    assert_eq!(signed.target, "/?max-keys=2&prefix=J");
    assert_eq!(
        signature(&signed),
        "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
    );
}

fn policy() -> Policy {
    Policy::new(
        HOST.into(),
        "us-east-1".into(),
        Limits {
            target_bytes: 8192,
            control_xml_bytes: 4096,
            header_bytes: 16384,
            header_count: 64,
            query_pairs: 64,
            upload_bytes: 1 << 20,
            clock_skew_seconds: 900,
            presign_seconds: 60,
        },
    )
    .unwrap()
}

fn secret() -> Vec<u8> {
    Sha256::digest(b"sign test").to_vec()
}

struct Auth(Vec<u8>);
impl Authority for Auth {
    fn credential(&self, key: &str) -> Option<Credential<'_>> {
        (key == "AKIDEXAMPLE").then_some(Credential {
            secret: &self.0,
            principal: "p",
        })
    }
    fn authorize(&self, _: &str, _: &str, _: &Target) -> bool {
        true
    }
}

/// Runs a signed request through the server-side verifier.
fn check(method: &str, signed: &SignedRequest) -> Result<(), ErrorCode> {
    let mut fields: Vec<(&str, &str)> = vec![("host", HOST)];
    fields.extend(signed.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let policy = policy();
    let headers = Headers::new(&fields, &policy)?;
    let target = Target::parse(&signed.target, &policy)?;
    verify(
        method,
        &target,
        &headers,
        true,
        NOW,
        &policy,
        &Auth(secret()),
    )
    .map(|_| ())
}

fn sign(request: &Unsigned<'_>) -> SignedRequest {
    let secret = secret();
    let key = SigningKey {
        access_key: "AKIDEXAMPLE",
        secret: &secret,
        region: "us-east-1",
    };
    sign_request(&key, HOST, NOW, request).unwrap()
}

#[test]
fn sigv4_signed_request_passes_own_verifier() {
    let body = b"sealed record";
    let sha = Sha256::digest(body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let put = sign(&Unsigned {
        method: "PUT",
        path: "/bucket/prefix/m/art/x_0123abcd",
        query: &[],
        headers: &[
            ("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg=="),
            ("x-amz-meta-sha256", &sha),
        ],
        payload_sha256: &sha,
    });
    assert_eq!(check("PUT", &put), Ok(()));

    let head = sign(&Unsigned {
        method: "HEAD",
        path: "/bucket/prefix/m/g_0193abc",
        query: &[],
        headers: &[],
        payload_sha256: EMPTY_SHA256,
    });
    assert_eq!(check("HEAD", &head), Ok(()));

    // Query values with `/` are escaped the way the verifier reads them.
    let list = sign(&Unsigned {
        method: "GET",
        path: "/bucket",
        query: &[
            ("list-type", "2"),
            ("prefix", "prefix/m/"),
            ("start-after", "prefix/m/del/g_01"),
            ("max-keys", "1000"),
        ],
        headers: &[],
        payload_sha256: EMPTY_SHA256,
    });
    assert!(list.target.contains("prefix=prefix%2Fm%2F"));
    assert_eq!(check("GET", &list), Ok(()));
}

/// The published "GET Bucket Lifecycle" example: a query key without a
/// value is signed as `lifecycle=`.
#[test]
fn sigv4_empty_query_value_matches_aws_test_vector() {
    let signed = sign_request(
        &doc_key(),
        DOC_HOST,
        NOW,
        &Unsigned {
            method: "GET",
            path: "/",
            query: &[("lifecycle", "")],
            headers: &[],
            payload_sha256: EMPTY_SHA256,
        },
    )
    .unwrap();
    assert_eq!(signed.target, "/?lifecycle=");
    assert_eq!(
        signature(&signed),
        "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
    );
}

/// Unreserved characters are sent as they are, everything else escaped
/// in upper-case hex.
#[test]
fn sigv4_query_escapes_all_but_unreserved() {
    let signed = sign(&Unsigned {
        method: "GET",
        path: "/bucket",
        query: &[("start-after", "a-b_c.d~e/f g+h=i&j")],
        headers: &[],
        payload_sha256: EMPTY_SHA256,
    });
    assert_eq!(
        signed.target,
        "/bucket?start-after=a-b_c.d~e%2Ff%20g%2Bh%3Di%26j"
    );
    assert_eq!(check("GET", &signed), Ok(()));
}

/// Every signed part is covered by the signature: a request changed
/// after signing fails the verifier.
#[test]
fn a_changed_request_fails_the_verifier() {
    let mismatch = Err(ErrorCode::SignatureDoesNotMatch);
    let sha = "ab".repeat(32);
    let put = Unsigned {
        method: "PUT",
        path: "/bucket/a",
        query: &[],
        headers: &[("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")],
        payload_sha256: &sha,
    };
    assert_eq!(check("PUT", &sign(&put)), Ok(()));
    assert_eq!(check("GET", &sign(&put)), mismatch, "method");

    let mut changed = sign(&put);
    changed.target = "/bucket/b".into();
    assert_eq!(check("PUT", &changed), mismatch, "path");

    for (name, value) in [
        ("content-md5", "XrY7u+Ae7tCTyyK7j1rNww==".to_owned()),
        ("x-amz-content-sha256", "cd".repeat(32)),
        ("x-amz-date", "20130524T000001Z".to_owned()),
    ] {
        let mut changed = sign(&put);
        let slot = changed.headers.iter_mut().find(|(k, _)| k == name);
        slot.unwrap().1 = value;
        assert_eq!(check("PUT", &changed), mismatch, "{name}");
    }

    let list = Unsigned {
        method: "GET",
        path: "/bucket",
        query: &[("list-type", "2"), ("prefix", "a/")],
        headers: &[],
        payload_sha256: EMPTY_SHA256,
    };
    assert_eq!(check("GET", &sign(&list)), Ok(()));
    for target in [
        "/bucket?list-type=2&prefix=b%2F",
        "/bucket?list-type=2",
        "/bucket?list-type=2&prefix=a%2F&start-after=a%2Fz",
    ] {
        let mut changed = sign(&list);
        changed.target = target.into();
        assert_eq!(check("GET", &changed), mismatch, "{target}");
    }
}

fn test_key(secret: &[u8]) -> SigningKey<'_> {
    SigningKey {
        access_key: "AKIDEXAMPLE",
        secret,
        region: "us-east-1",
    }
}

const BASE: Unsigned<'static> = Unsigned {
    method: "PUT",
    path: "/bucket/a",
    query: &[],
    headers: &[],
    payload_sha256: EMPTY_SHA256,
};

fn signs(request: &Unsigned<'_>) -> bool {
    sign_request(&test_key(&secret()), HOST, NOW, request).is_ok()
}

/// The signed path is the sent path: a path a URL parser would rewrite,
/// or that needs an escape, is refused.
#[test]
fn a_path_that_a_client_would_rewrite_is_refused() {
    for path in [
        "/",
        "/bucket",
        "/bucket/a",
        "/bucket/a.b/c-d_e~f",
        "/b/..a",
        "/b/a..",
        "/b/...",
    ] {
        assert!(signs(&Unsigned { path, ..BASE }), "{path}");
    }
    for path in [
        "",
        "bucket/a",
        "/bucket/../other/a",
        "/bucket/a/..",
        "/..",
        "/bucket/./a",
        "/bucket/a/.",
        "/.",
        "//other.example/a",
        "/bucket//a",
        "/bucket/a/",
        "/bucket/",
        "/bucket/a b",
        "/bucket/a%2Fb",
        "/bucket/a%2e%2e",
        "/bucket/a?x",
        "/bucket/a#x",
        "/bucket/a\\b",
        "/bucket/a\r\nb",
        "/bucket/a\u{e9}",
        "/bucket/a:b",
        "/bucket/a@b",
        "/bucket/a;b",
    ] {
        assert!(!signs(&Unsigned { path, ..BASE }), "{path:?}");
    }
}

/// Only headers of the allow-list are signed, with values that are
/// their own canonical form.
#[test]
fn only_allowed_headers_are_signed() {
    for name in [
        "content-md5",
        "content-type",
        "range",
        "x-amz-meta-sha256",
        "x-amz-meta-a-1",
    ] {
        let headers = [(name, "v")];
        assert!(
            signs(&Unsigned {
                headers: &headers,
                ..BASE
            }),
            "{name}"
        );
    }
    for name in [
        "authorization",
        "host",
        "x-amz-date",
        "x-amz-content-sha256",
        "content-length",
        "transfer-encoding",
        "connection",
        "accept-encoding",
        "expect",
        "x-amz-security-token",
        "x-amz-acl",
        "x-amz-meta-",
        "x-amz-meta-a_b",
        "x-amz-meta-A",
        "Content-MD5",
        "content-md5 ",
        "",
        "x-other",
    ] {
        let headers = [(name, "v")];
        assert!(
            !signs(&Unsigned {
                headers: &headers,
                ..BASE
            }),
            "{name:?}"
        );
    }
    // The same header twice.
    let twice = [("content-md5", "a"), ("content-md5", "b")];
    assert!(!signs(&Unsigned {
        headers: &twice,
        ..BASE
    }));

    for value in ["a b", "bytes=0-9", "~!@#$%^&*()"] {
        let headers = [("x-amz-meta-a", value)];
        assert!(
            signs(&Unsigned {
                headers: &headers,
                ..BASE
            }),
            "{value}"
        );
    }
    for value in [
        "",
        " a",
        "a ",
        "two  spaces",
        "a\r\nx-evil: 1",
        "a\nb",
        "a\tb",
        "a\u{7f}",
        "caf\u{e9}",
    ] {
        let headers = [("x-amz-meta-a", value)];
        assert!(
            !signs(&Unsigned {
                headers: &headers,
                ..BASE
            }),
            "{value:?}"
        );
    }
}

#[test]
fn what_cannot_be_signed_unambiguously_is_refused() {
    assert!(signs(&BASE));
    for method in ["GET", "HEAD", "PUT"] {
        assert!(signs(&Unsigned { method, ..BASE }));
    }
    for method in ["DELETE", "POST", "get", "", "PUT "] {
        assert!(!signs(&Unsigned { method, ..BASE }), "{method:?}");
    }

    // The payload hash: 64 lower-case hex digits, nothing else.
    let upper = EMPTY_SHA256.to_uppercase();
    let not_hex = "g".repeat(64);
    let short = &EMPTY_SHA256[..63];
    for payload_sha256 in [
        "UNSIGNED-PAYLOAD",
        "",
        upper.as_str(),
        not_hex.as_str(),
        short,
    ] {
        assert!(
            !signs(&Unsigned {
                payload_sha256,
                ..BASE
            }),
            "{payload_sha256:?}"
        );
    }

    // A query key once, not empty, and no signing parameter.
    for query in [
        &[("prefix", "a/"), ("prefix", "b/")][..],
        &[("", "v")],
        &[("X-Amz-Algorithm", "AWS4-HMAC-SHA256")],
        &[("x-amz-signature", "00")],
    ] {
        assert!(!signs(&Unsigned { query, ..BASE }), "{query:?}");
    }
    assert!(signs(&Unsigned {
        query: &[("prefix", "a/"), ("start-after", "a/")],
        ..BASE
    }));

    // The host: a lower-case name, no port, nothing a URL parser changes.
    let secret = secret();
    let host_signs = |host: &str| sign_request(&test_key(&secret), host, NOW, &BASE).is_ok();
    for host in ["store.example", "a-1.b2.example", "localhost", "1.a2"] {
        assert!(host_signs(host), "{host}");
    }
    for host in [
        // A last label that a URL parser reads as a number.
        "127.0.0.1",
        "127.1",
        "0x7f.1",
        "1.2.3",
        "2130706433",
        "010",
        "09",
        "a.1",
        "a.0x",
        "a.1b",
        "a.-b",
        "",
        "Store.Example",
        "store.example:443",
        "store.example.",
        ".store.example",
        "store..example",
        "store.example/x",
        "user@store.example",
        "a b",
        "store.example\r\nx: y",
        "[::1]",
        "st\u{f6}re.example",
    ] {
        assert!(!host_signs(host), "{host:?}");
    }

    // The key and the region.
    let with = |access_key: &str, region: &str| {
        let key = SigningKey {
            access_key,
            secret: &secret,
            region,
        };
        sign_request(&key, HOST, NOW, &BASE).is_ok()
    };
    assert!(with("AKIDEXAMPLE", "us-east-1"));
    for access_key in [
        "",
        "AKID/EXAMPLE",
        "AKID EXAMPLE",
        "AKID,EXAMPLE",
        "AKID=EXAMPLE",
        "AKID\nEXAMPLE",
    ] {
        assert!(!with(access_key, "us-east-1"), "{access_key:?}");
    }
    for region in [
        "",
        "us/east",
        "US-EAST-1",
        "us east",
        "us-east-1\n",
        "us.east",
    ] {
        assert!(!with("AKIDEXAMPLE", region), "{region:?}");
    }

    // The time: seconds, of a year of four digits.
    let at = |unix_secs: i64| sign_request(&test_key(&secret), HOST, unix_secs, &BASE).is_ok();
    for ok in [0, NOW, 253_402_300_799] {
        assert!(at(ok), "{ok}");
    }
    for bad in [-1, 253_402_300_800, NOW * 1000, i64::MIN, i64::MAX] {
        assert!(!at(bad), "{bad}");
    }
}

fn list_of(inner: &str) -> Vec<u8> {
    format!("<ListBucketResult>{inner}</ListBucketResult>").into_bytes()
}

const ENTRY: &str = "<Contents><Key>k</Key><ETag>e</ETag><Size>1</Size></Contents>";
const END: &str = "<IsTruncated>false</IsTruncated>";

#[test]
fn e2_list_parses_keys_sizes_etags_and_truncation() {
    use velmora_s3_proto::sign::{parse_list, Listed};
    let body = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>p/</Prefix>
<KeyCount>2</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>true</IsTruncated>
<Contents><Key>p/m/g_0001</Key><LastModified>2026-11-15T00:00:00.000Z</LastModified>
<ETag>&quot;9e107d9d372bb6826bd81d3542a419d6&quot;</ETag><Size>4096</Size>
<Owner><ID>1</ID><DisplayName>x</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents>
<Contents><Key>p/m/art/x_a&amp;b</Key><ETag>"e4d909c290d0fb1ca068ffaddf22cbd0"</ETag><Size>0</Size></Contents>
</ListBucketResult>"#;
    let page = parse_list(body).unwrap();
    assert!(page.truncated);
    assert_eq!(
        page.objects,
        vec![
            Listed {
                key: "p/m/g_0001".into(),
                size: 4096,
                etag: "9e107d9d372bb6826bd81d3542a419d6".into()
            },
            Listed {
                key: "p/m/art/x_a&b".into(),
                size: 0,
                etag: "e4d909c290d0fb1ca068ffaddf22cbd0".into()
            },
        ]
    );
    let empty = br#"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"#;
    assert_eq!(parse_list(empty).unwrap().objects.len(), 0);
    assert!(!parse_list(empty).unwrap().truncated);

    assert_eq!(page.next_token, None);
    assert_eq!(
        parse_list(&list_of(&format!("{ENTRY}{END}")))
            .unwrap()
            .objects
            .len(),
        1
    );
}

#[test]
fn e2_list_reads_references_and_the_continuation_token() {
    use velmora_s3_proto::sign::parse_list;
    // Character references, decimal and hex, and the five named ones.
    let page = parse_list(&list_of(&format!(
        "<Contents><Key>&#65;&#x42;&#x63;&amp;&lt;&gt;&quot;&apos;&#233;</Key><ETag>e</ETag><Size>1</Size></Contents>{END}"
    )))
    .unwrap();
    assert_eq!(page.objects[0].key, "ABc&<>\"'\u{e9}");

    // A truncated page says where to go on: an object or the token.
    let token =
        "<IsTruncated>true</IsTruncated><NextContinuationToken>t&amp;1</NextContinuationToken>";
    let page = parse_list(&list_of(&format!(
        "<CommonPrefixes><Prefix>p/</Prefix></CommonPrefixes>{token}"
    )))
    .unwrap();
    assert!(page.truncated && page.objects.is_empty());
    assert_eq!(page.next_token.as_deref(), Some("t&1"));
    let page = parse_list(&list_of(&format!("{ENTRY}<IsTruncated>true</IsTruncated>"))).unwrap();
    assert!(page.truncated && page.next_token.is_none());
    assert!(parse_list(&list_of("<IsTruncated>true</IsTruncated>")).is_err());

    // Only an entry right under the root is an entry.
    let nested = format!("<Other>{ENTRY}<IsTruncated>true</IsTruncated></Other>{END}");
    let page = parse_list(&list_of(&nested)).unwrap();
    assert!(page.objects.is_empty() && !page.truncated);

    // Eight levels are read, nine are not.
    let deep = |levels: usize| {
        list_of(&format!(
            "{}{}{END}",
            "<a>".repeat(levels - 1),
            "</a>".repeat(levels - 1)
        ))
    };
    assert!(parse_list(&deep(8)).is_ok());
    assert!(parse_list(&deep(9)).is_err());

    // The size bound: a body of the limit is read, one byte more is not.
    let mut body = list_of(&format!("{ENTRY}{END}"));
    let pad = velmora_s3_proto::sign::MAX_LIST_BYTES - body.len();
    body.extend(std::iter::repeat_n(b' ', pad));
    assert_eq!(parse_list(&body).unwrap().objects.len(), 1);
    body.push(b' ');
    assert_eq!(parse_list(&body), Err(ErrorCode::InvalidRequest));
}

/// Never a shorter or another list: what a lenient parser would skip or
/// guess is an error.
#[test]
fn e2_list_refuses_what_it_cannot_read_exactly() {
    use velmora_s3_proto::sign::parse_list;
    let good = format!("{ENTRY}{END}");
    assert!(parse_list(&list_of(&good)).is_ok());
    let entry = |fields: &str| format!("<Contents>{fields}</Contents>{END}");
    for inner in [
        // An entry without one of its fields.
        entry("<ETag>e</ETag><Size>1</Size>"),
        entry("<Key>k</Key><Size>1</Size>"),
        entry("<Key>k</Key><ETag>e</ETag>"),
        "<Contents/>".to_owned() + END,
        // An empty field, as text or as an empty element.
        entry("<Key></Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key/><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>k</Key><ETag></ETag><Size>1</Size>"),
        entry("<Key>k</Key><ETag>\"\"</ETag><Size>1</Size>"),
        entry("<Key>k</Key><ETag/><Size>1</Size>"),
        entry("<Key>k</Key><ETag>e</ETag><Size></Size>"),
        entry("<Key>k</Key><ETag>e</ETag><Size/>"),
        // A field given twice.
        entry("<Key>k</Key><Key>l</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>k</Key><ETag>e</ETag><ETag>f</ETag><Size>1</Size>"),
        entry("<Key>k</Key><ETag>e</ETag><Size>1</Size><Size>2</Size>"),
        format!("{ENTRY}{END}<IsTruncated>true</IsTruncated>"),
        format!("{ENTRY}<IsTruncated>true</IsTruncated>{END}"),
        format!("{ENTRY}{END}<NextContinuationToken>a</NextContinuationToken><NextContinuationToken>b</NextContinuationToken>"),
        // Keys that the store says it encoded: none was asked for.
        format!("{ENTRY}{END}<EncodingType>url</EncodingType>"),
        format!("<EncodingType>url</EncodingType>{ENTRY}{END}"),
        format!("{ENTRY}{END}<EncodingType/>"),
        // An element inside a field.
        entry("<Key>a<x>b</x>c</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>a<x/>c</Key><ETag>e</ETag><Size>1</Size>"),
        format!("{ENTRY}<IsTruncated>false<x/></IsTruncated>"),
        // A size that is not digits only.
        entry("<Key>k</Key><ETag>e</ETag><Size>-1</Size>"),
        entry("<Key>k</Key><ETag>e</ETag><Size>+5</Size>"),
        entry("<Key>k</Key><ETag>e</ETag><Size> 5</Size>"),
        entry("<Key>k</Key><ETag>e</ETag><Size>1e3</Size>"),
        entry("<Key>k</Key><ETag>e</ETag><Size>99999999999999999999</Size>"),
        // References: a sign, a control character, an unknown name, a surrogate.
        entry("<Key>&#+65;</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>&#x+41;</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>a&#0;</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>a&#10;b</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>a&#x1f;b</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>a&nbsp;b</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>a&#xD800;b</Key><ETag>e</ETag><Size>1</Size>"),
        entry("<Key>a&#;b</Key><ETag>e</ETag><Size>1</Size>"),
        // No IsTruncated, or one that is not true or false.
        ENTRY.to_owned(),
        format!("{ENTRY}<IsTruncated>TRUE</IsTruncated>"),
        format!("{ENTRY}<IsTruncated></IsTruncated>"),
        format!("{ENTRY}<IsTruncated/>"),
        format!("{ENTRY}{END}<NextContinuationToken></NextContinuationToken>"),
        format!("{ENTRY}{END}<NextContinuationToken/>"),
        // CDATA and a processing instruction.
        entry("<Key><![CDATA[k]]></Key><ETag>e</ETag><Size>1</Size>"),
        format!("<?pi x?>{good}"),
    ] {
        assert!(parse_list(&list_of(&inner)).is_err(), "{inner}");
    }
    // Around the root: another root, a second root, text, a cut body, a DTD.
    let whole = String::from_utf8(list_of(&good)).unwrap();
    for body in [
        "<Error><Code>AccessDenied</Code></Error>".to_owned(),
        format!("<Other>{good}</Other>"),
        format!("{whole}{whole}"),
        format!("{whole}<x/>"),
        format!("<x/>{whole}"),
        format!("{whole}<x></x>"),
        format!("{whole}<ListBucketResult></ListBucketResult>"),
        format!("<x></x>{whole}"),
        format!("text{whole}"),
        format!("{whole}text"),
        format!("&amp;{whole}"),
        "<ListBucketResult/>".to_owned(),
        whole[..whole.len() - 5].to_owned(),
        format!("<ListBucketResult>{END}<Contents><Key>k</Key>"),
        format!("<!DOCTYPE x>{whole}"),
        String::new(),
        " ".to_owned(),
    ] {
        assert!(parse_list(body.as_bytes()).is_err(), "{body}");
    }
    // White space and a declaration around the root are fine.
    assert!(parse_list(format!("<?xml version=\"1.0\"?>\n{whole}\n").as_bytes()).is_ok());
}

/// The set of characters that are neither refused in a path nor escaped
/// in a query is exactly the unreserved set of SigV4.
#[test]
fn the_unreserved_set_is_exact() {
    for c in 0u8..=0x7f {
        let ch = c as char;
        let plain = ch.is_ascii_alphanumeric() || "-_.~".contains(ch);
        let path = format!("/bucket/a{ch}b");
        // `/` only starts another segment.
        assert_eq!(
            signs(&Unsigned {
                path: &path,
                ..BASE
            }),
            plain || ch == '/',
            "path {c:#04x}"
        );
        let value = format!("a{ch}b");
        let query = [("prefix", value.as_str())];
        let signed = sign(&Unsigned {
            method: "GET",
            query: &query,
            ..BASE
        });
        let want = if plain {
            format!("/bucket/a?prefix=a{ch}b")
        } else {
            format!("/bucket/a?prefix=a%{c:02X}b")
        };
        assert_eq!(signed.target, want, "query {c:#04x}");
    }
    // Without a query the target is the path alone.
    assert_eq!(sign(&BASE).target, "/bucket/a");
}

/// A value this crate's own verifier would read as two merged values.
#[test]
fn a_comma_in_metadata_is_refused() {
    for (name, value, ok) in [
        ("x-amz-meta-a", "a,b", false),
        ("x-amz-meta-a", ",", false),
        ("x-amz-meta-a", "a;b", true),
        ("content-type", "a,b", true),
    ] {
        let headers = [(name, value)];
        let request = Unsigned {
            headers: &headers,
            ..BASE
        };
        assert_eq!(signs(&request), ok, "{name}: {value}");
        if ok {
            assert_eq!(check("PUT", &sign(&request)), Ok(()), "{name}: {value}");
        }
    }
}

/// A field is read at its own place only, whatever else an answer holds.
#[test]
fn e2_list_reads_a_field_only_at_its_place() {
    use velmora_s3_proto::sign::parse_list;
    // The same names elsewhere are not the fields.
    let page = parse_list(&list_of(&format!(
        "<Other><NextContinuationToken>t</NextContinuationToken>\
         <EncodingType>url</EncodingType><IsTruncated>true</IsTruncated>\
         <Key>x</Key><Size>9</Size><ETag>z</ETag></Other>\
         <Contents><Owner><Key>x</Key><Size>9</Size><ETag>z</ETag>\
         <Contents><Key>y</Key></Contents></Owner>\
         <Key>k</Key><ETag>e</ETag><Size>1</Size></Contents>{END}"
    )))
    .unwrap();
    assert_eq!(page.objects.len(), 1);
    let o = &page.objects[0];
    assert_eq!((o.key.as_str(), o.size, o.etag.as_str()), ("k", 1, "e"));
    assert!(!page.truncated && page.next_token.is_none());

    // Names with a prefix, a comment and a declaration where XML has them.
    let body = "<?xml version=\"1.0\"?><!-- a --><s:ListBucketResult xmlns:s=\"u\">\
         <!-- b --><s:Contents><s:Key>k&#32;1</s:Key><!-- c --><s:ETag>e</s:ETag>\
         <s:Size>1</s:Size></s:Contents><s:IsTruncated>false</s:IsTruncated>\
         </s:ListBucketResult><!-- d -->";
    let page = parse_list(body.as_bytes()).unwrap();
    assert_eq!(page.objects[0].key, "k 1");

    let entry = |key: &str| {
        list_of(&format!(
            "<Contents><Key>{key}</Key><ETag>e</ETag><Size>1</Size></Contents>{END}"
        ))
    };
    assert!(parse_list(&entry("a b")).is_ok());
    for key in [
        // A comment or a declaration inside a field.
        "a<!-- x -->b",
        "a<?xml version=\"1.0\"?>b",
        // A control character written as it is.
        "a\u{1}b",
        "a\tb",
        "a\nb",
        "a\r\nb",
        "a\u{0}b",
    ] {
        assert!(parse_list(&entry(key)).is_err(), "{key:?}");
    }
    for body in [
        // A declaration after the root has opened, or after it.
        format!("<ListBucketResult><?xml version=\"1.0\"?>{ENTRY}{END}</ListBucketResult>"),
        format!("<ListBucketResult>{ENTRY}{END}</ListBucketResult><?xml version=\"1.0\"?>"),
        format!(
            "<ListBucketResult>{ENTRY}<IsTruncated>fal<!-- -->se</IsTruncated></ListBucketResult>"
        ),
    ] {
        assert!(parse_list(body.as_bytes()).is_err(), "{body}");
    }
}
