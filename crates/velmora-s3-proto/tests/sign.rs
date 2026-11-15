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

#[test]
fn a_changed_request_fails_the_verifier() {
    let mut put = sign(&Unsigned {
        method: "PUT",
        path: "/bucket/a",
        query: &[],
        headers: &[],
        payload_sha256: EMPTY_SHA256,
    });
    put.target = "/bucket/b".into();
    assert_eq!(check("PUT", &put), Err(ErrorCode::SignatureDoesNotMatch));
}

#[test]
fn what_cannot_be_signed_unambiguously_is_refused() {
    let refuse = |request: Unsigned<'_>| {
        let secret = secret();
        let key = SigningKey {
            access_key: "AKIDEXAMPLE",
            secret: &secret,
            region: "us-east-1",
        };
        assert!(sign_request(&key, HOST, NOW, &request).is_err());
    };
    let base = Unsigned {
        method: "PUT",
        path: "/bucket/a",
        query: &[],
        headers: &[],
        payload_sha256: EMPTY_SHA256,
    };
    refuse(Unsigned {
        method: "DELETE",
        ..base
    });
    refuse(Unsigned {
        path: "/bucket/a b",
        ..base
    });
    refuse(Unsigned {
        path: "/bucket/a%2Fb",
        ..base
    });
    refuse(Unsigned {
        path: "bucket/a",
        ..base
    });
    refuse(Unsigned {
        payload_sha256: "UNSIGNED-PAYLOAD",
        ..base
    });
    refuse(Unsigned {
        headers: &[("Content-MD5", "x")],
        ..base
    });
    refuse(Unsigned {
        headers: &[("x-amz-meta-a", "two  spaces")],
        ..base
    });
    refuse(Unsigned {
        headers: &[("host", "other.example")],
        ..base
    });
}

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

    // Never a shorter list: an entry without a size, an answer without
    // IsTruncated, another root, a cut body and a DTD are all errors.
    for bad in [
        &br#"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>k</Key><ETag>e</ETag></Contents></ListBucketResult>"#[..],
        br#"<ListBucketResult><Contents><Key>k</Key><ETag>e</ETag><Size>1</Size></Contents></ListBucketResult>"#,
        br#"<Error><Code>AccessDenied</Code></Error>"#,
        br#"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>k</Key>"#,
        br#"<!DOCTYPE x><ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"#,
        br#"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>k</Key><ETag>e</ETag><Size>-1</Size></Contents></ListBucketResult>"#,
        b"",
    ] {
        assert!(parse_list(bad).is_err(), "{}", String::from_utf8_lossy(bad));
    }
}
