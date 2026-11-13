//! S3 STANDARD semantics, the signed comma-value rule, ListObjectsV2 paging and
//! tokens, ListBuckets, and the commit renderers.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use velmora_s3_proto::listing::*;
use velmora_s3_proto::mutation::{CommitResult, UploadMetadata};
use velmora_s3_proto::*;

const NOW: i64 = 1369353600; // 2013-05-24T00:00:00Z
const DATE: &str = "20130524T000000Z";
const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HOST: &str = "s3.us-east-1.amazonaws.com";
const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

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
            upload_bytes: 1024,
            clock_skew_seconds: 900,
            presign_seconds: 60,
        },
    )
    .unwrap()
}

struct Auth;
impl Authority for Auth {
    fn credential(&self, key: &str) -> Option<Credential<'_>> {
        (key == "AKIDEXAMPLE").then_some(Credential {
            secret: SECRET,
            principal: "p",
        })
    }
    fn authorize(&self, _: &str, _: &str, _: &Target) -> bool {
        true
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().to_vec()
}
/// Test-only token key, derived per label so no key literal is needed.
fn key(label: &str) -> Vec<u8> {
    Sha256::digest(label.as_bytes()).to_vec()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// Header-mode SigV4 over `fields`; returns the headers with Authorization added.
fn sign(
    method: &str,
    target: &Target,
    fields: &[(&str, &str)],
    signed: &str,
) -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = vec![
        ("host".into(), HOST.into()),
        ("x-amz-date".into(), DATE.into()),
        ("x-amz-content-sha256".into(), EMPTY_SHA.into()),
    ];
    all.extend(fields.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let h = headers(&all);
    let canonical = canonical_request(method, target, &h, signed, EMPTY_SHA, false).unwrap();
    let sts = format!(
        "AWS4-HMAC-SHA256\n{DATE}\n20130524/us-east-1/s3/aws4_request\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(&[b"AWS4", SECRET].concat(), b"20130524");
    for part in [&b"us-east-1"[..], b"s3", b"aws4_request"] {
        key = hmac(&key, part);
    }
    all.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders={signed}, Signature={}",
            hex(&hmac(&key, sts.as_bytes()))
        ),
    ));
    all
}
fn headers(all: &[(String, String)]) -> Headers {
    let pairs: Vec<_> = all.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    Headers::new(&pairs, &policy()).unwrap()
}
fn check(method: &str, target: &Target, all: &[(String, String)]) -> Result<VerifiedRequest> {
    verify(method, target, &headers(all), true, NOW, &policy(), &Auth)
}

#[test]
fn signed_comma_duplicate_rejected() {
    let t = Target::parse("/bucket/key", &policy()).unwrap();
    let base = "host;x-amz-content-sha256;x-amz-date";
    // A merged duplicate arrives as one comma-joined value, and two fields with
    // the same name are combined the same way: both are refused when signed.
    for fields in [
        vec![("x-amz-meta-a", "1, 2")],
        vec![("x-amz-meta-b", "a,b")],
        vec![("x-test", "one"), ("x-test", "two")],
    ] {
        let signed = format!("{};{base}", fields[0].0);
        let signed = {
            let mut n: Vec<_> = signed.split(';').collect();
            n.sort();
            n.join(";")
        };
        let mut all = sign("PUT", &t, &fields, &signed);
        assert_eq!(
            check("PUT", &t, &all).unwrap_err(),
            ErrorCode::InvalidRequest,
            "{fields:?}"
        );
        // Refused before signature work: a forged signature gets the same answer.
        let auth = all.pop().unwrap().1;
        all.push((
            "authorization".into(),
            format!("{}0000", &auth[..auth.len() - 4]),
        ));
        assert_eq!(
            check("PUT", &t, &all).unwrap_err(),
            ErrorCode::InvalidRequest
        );
    }
    // Unsigned comma values are not the auth layer's concern.
    let all = sign("GET", &t, &[("user-agent", "a, b")], base);
    assert!(check("GET", &t, &all).is_ok());
    // Presigned: the signed-header list comes from the query; same rule.
    let t = Target::parse(
        "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host%3Bx-amz-meta-a&X-Amz-Signature=00",
        &policy(),
    )
    .unwrap();
    let h = Headers::new(&[("host", HOST), ("x-amz-meta-a", "1, 2")], &policy()).unwrap();
    assert_eq!(
        verify("GET", &t, &h, true, NOW, &policy(), &Auth).unwrap_err(),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn single_value_headers_keep_literal_commas() {
    assert_eq!(
        SINGLE_VALUE_HEADERS,
        [
            "host",
            "content-type",
            "content-md5",
            "content-length",
            "range",
            "x-amz-date",
            "x-amz-content-sha256",
            "x-amz-security-token",
            "x-amz-copy-source",
            "expires",
            "date",
            "if-modified-since",
            "if-unmodified-since",
            "if-match",
            "if-none-match",
            "cache-control",
            "content-disposition",
            "content-encoding",
            "content-language",
        ]
    );
    let t = Target::parse("/bucket/key", &policy()).unwrap();
    let all = sign(
        "GET",
        &t,
        &[
            ("content-type", "text/plain; a=1, b=2"),
            ("range", "bytes=0-1, 3-4"),
        ],
        "content-type;host;range;x-amz-content-sha256;x-amz-date",
    );
    assert_eq!(check("GET", &t, &all).unwrap().principal, "p");
}

#[test]
fn signed_cache_control_with_commas_verifies() {
    let t = Target::parse("/bucket/key", &policy()).unwrap();
    let signed = "cache-control;host;x-amz-content-sha256;x-amz-date";
    let all = sign(
        "GET",
        &t,
        &[("cache-control", "public, max-age=60")],
        signed,
    );
    assert_eq!(check("GET", &t, &all).unwrap().principal, "p");
    // A duplicate the client signed as two fields ("public,no-store") but the
    // edge merged into one ("public, no-store") fails closed, never verifies.
    let mut all = sign(
        "GET",
        &t,
        &[("cache-control", "public"), ("cache-control", "no-store")],
        signed,
    );
    all.retain(|(k, _)| k != "cache-control");
    all.push(("cache-control".into(), "public, no-store".into()));
    assert_eq!(
        check("GET", &t, &all).unwrap_err(),
        ErrorCode::SignatureDoesNotMatch
    );
}

#[test]
fn storage_class_and_read_plan_are_standard() {
    assert_eq!(storage_class(None), Ok("STANDARD"));
    assert_eq!(
        storage_class(Some("GLACIER")),
        Err(ErrorCode::InvalidRequest)
    );
    let m = ObjectMetadata::new("g".into(), 10, "\"e\"".into(), NOW, vec![], None).unwrap();
    // No availability gate: a GET plans a body straight away.
    let plan = plan_read(&m, false, &Conditions::default(), None, false).unwrap();
    assert_eq!(plan.status, 200);
    assert_eq!(plan.body, Some(ByteRange { start: 0, end: 9 }));
    assert!(plan
        .headers
        .contains(&("x-amz-storage-class".into(), "STANDARD".into())));
    // The restore subresource is gone with the archive semantics.
    let t = Target::parse("/bucket/key?restore", &policy()).unwrap();
    let all = sign("POST", &t, &[], "host;x-amz-content-sha256;x-amz-date");
    assert_eq!(
        check("POST", &t, &all).unwrap_err(),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn upload_metadata_from_headers_keeps_persistent_fields_only() {
    let t = Target::parse("/bucket/key", &policy()).unwrap();
    let all = sign(
        "PUT",
        &t,
        &[
            ("content-disposition", "attachment; filename=\"a  b.txt\""),
            ("cache-control", "no-store"),
            ("content-language", "en"),
            ("content-type", "text/plain"),
            ("x-amz-meta-name", "a\t b   c"),
            ("x-amz-storage-class", "STANDARD"),
        ],
        "cache-control;content-disposition;content-language;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-name;x-amz-storage-class",
    );
    check("PUT", &t, &all).unwrap();
    let meta = UploadMetadata::from_headers(&headers(&all)).unwrap();
    let got: Vec<_> = meta
        .headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("cache-control", "no-store"),
            ("content-disposition", "attachment; filename=\"a  b.txt\""),
            ("content-language", "en"),
            ("content-type", "text/plain"),
            ("x-amz-meta-name", "a\t b   c"),
        ]
    );
    for (k, v) in [
        ("x-amz-storage-class", "GLACIER"),
        ("x-amz-acl", "public-read"),
        ("x-amz-checksum-algorithm", "CRC64NVME"),
    ] {
        let h = Headers::new(&[("host", HOST), (k, v)], &policy()).unwrap();
        assert_eq!(
            UploadMetadata::from_headers(&h).unwrap_err(),
            ErrorCode::InvalidRequest,
            "{k}"
        );
    }
}

// ---- ListObjectsV2 ----

fn row(key: &str) -> ObjectEntry {
    ObjectEntry {
        key: key.into(),
        size: key.len() as u64,
        etag: format!("\"{key}\""),
        last_modified_ms: NOW * 1000 + 7,
    }
}

fn between<'a>(xml: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    xml.split(open)
        .skip(1)
        .map(|s| &s[..s.find(close).unwrap()])
        .collect()
}

/// One page against an in-memory "catalogue": `batch` rows per query, at most
/// `queries` queries, like the service does against D1.
fn page(rows: &[&str], query: &str, batch: usize, queries: usize) -> String {
    let t = Target::parse(&format!("/bucket?list-type=2{query}"), &policy()).unwrap();
    let mut list = ListObjectsV2::parse(&t, &key("list")).unwrap();
    let mut exhausted = false;
    for _ in 0..queries {
        let after = list.after().map(str::to_owned);
        let found: Vec<_> = rows
            .iter()
            .filter(|k| k.starts_with(list.prefix()) && after.as_deref().is_none_or(|a| **k > a))
            .take(batch)
            .collect();
        for k in &found {
            if !list.wants_more() {
                break;
            }
            list.push(row(k)).unwrap();
        }
        if found.len() < batch {
            exhausted = true;
            break;
        }
        if !list.wants_more() {
            break;
        }
    }
    String::from_utf8(list.finish(exhausted, &key("list")).unwrap().body).unwrap()
}

/// Follow continuation tokens to the end; returns every emitted Key/Prefix.
fn walk(rows: &[&str], query: &str, batch: usize, queries: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..100 {
        let q = match &token {
            Some(t) => format!("{query}&continuation-token={t}"),
            None => query.to_owned(),
        };
        let xml = page(rows, &q, batch, queries);
        for k in between(&xml, "<Contents><Key>", "</Key>") {
            out.push(k.to_owned());
        }
        for p in between(&xml, "<CommonPrefixes><Prefix>", "</Prefix>") {
            out.push(p.to_owned());
        }
        token = between(&xml, "<NextContinuationToken>", "<")
            .first()
            .map(|t| t.to_string());
        assert_eq!(xml.contains("<IsTruncated>true"), token.is_some());
        if token.is_none() {
            return out;
        }
    }
    panic!("listing did not terminate");
}

#[test]
fn delimiter_listing_never_reemits_common_prefix() {
    let rows = ["a/1", "a/2", "b/1"];
    let first = page(&rows, "&delimiter=%2F&max-keys=1", 1000, 1);
    assert_eq!(between(&first, "<Prefix>", "</Prefix>"), ["", "a/"]);
    assert!(first.contains("<KeyCount>1</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>true</IsTruncated><Delimiter>/</Delimiter>"));
    assert_eq!(
        walk(&rows, "&delimiter=%2F&max-keys=1", 1000, 200),
        ["a/", "b/"]
    );
    // Same answer when every page runs out of query budget mid-group.
    for batch in [1, 2, 3] {
        for queries in [1, 2, 200] {
            for max in [1, 2, 1000] {
                assert_eq!(
                    walk(
                        &rows,
                        &format!("&delimiter=%2F&max-keys={max}"),
                        batch,
                        queries
                    ),
                    ["a/", "b/"],
                    "batch={batch} queries={queries} max={max}"
                );
            }
        }
    }
}

#[test]
fn listing_pages_match_a_reference_listing() {
    let rows = ["a", "a/1", "a/2", "a/b/1", "ab", "b/1", "b/2", "c", "c/x/y"];
    let reference = |prefix: &str, delimiter: &str, start_after: &str| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for k in rows
            .iter()
            .filter(|k| k.starts_with(prefix) && **k > start_after)
        {
            let entry = match (!delimiter.is_empty())
                .then(|| k[prefix.len()..].find(delimiter))
                .flatten()
            {
                Some(i) => k[..prefix.len() + i + delimiter.len()].to_owned(),
                None => k.to_string(),
            };
            if !(entry.ends_with(delimiter) && !delimiter.is_empty() && *entry <= *start_after)
                && out.last() != Some(&entry)
            {
                out.push(entry);
            }
        }
        out
    };
    for (prefix, p_q) in [
        ("", ""),
        ("a", "a"),
        ("a/", "a%2F"),
        ("c/", "c%2F"),
        ("z", "z"),
    ] {
        for (delimiter, d_q) in [("", ""), ("/", "%2F"), ("b", "b")] {
            for start_after in ["", "a/1", "a/", "b/9"] {
                for (batch, queries, max) in [(1000, 200, 1000), (1, 1, 1), (2, 3, 2), (1, 200, 3)]
                {
                    let mut q = format!("&prefix={p_q}&delimiter={d_q}&max-keys={max}");
                    if !start_after.is_empty() {
                        q.push_str(&format!("&start-after={}", start_after.replace('/', "%2F")));
                    }
                    let mut got = walk(&rows, &q, batch, queries);
                    got.sort();
                    let mut want = reference(prefix, delimiter, start_after);
                    want.sort();
                    assert_eq!(got, want, "{q} batch={batch} queries={queries}");
                }
            }
        }
    }
}

#[test]
fn continuation_token_is_bound_to_scope_and_key() {
    let scope = |prefix: &str| TokenScope {
        bucket: "bucket".into(),
        prefix: prefix.into(),
        delimiter: "/".into(),
        start_after: None,
        url_encoding: false,
    };
    let cursor = Cursor {
        after: "a/1".into(),
        skip_prefix: Some("a/".into()),
    };
    let token = issue_token(&key("list"), &scope("a"), &cursor).unwrap();
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)));
    assert_eq!(
        resolve_token(&key("list"), &token, &scope("a")),
        Ok(cursor.clone())
    );
    let other_scopes = [
        scope("b"),
        TokenScope {
            bucket: "other".into(),
            ..scope("a")
        },
        TokenScope {
            delimiter: "".into(),
            ..scope("a")
        },
        TokenScope {
            start_after: Some("".into()),
            ..scope("a")
        },
        TokenScope {
            url_encoding: true,
            ..scope("a")
        },
    ];
    for s in &other_scopes {
        assert_eq!(
            resolve_token(&key("list"), &token, s),
            Err(ErrorCode::InvalidArgument),
            "{s:?}"
        );
    }
    assert_eq!(
        resolve_token(&key("other"), &token, &scope("a")),
        Err(ErrorCode::InvalidArgument)
    );
    let mut bytes = token.clone().into_bytes();
    bytes[3] = if bytes[3] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    for bad in [tampered.as_str(), "", "!!", "AAAA", &"A".repeat(9000)] {
        assert_eq!(
            resolve_token(&key("list"), bad, &scope("a")),
            Err(ErrorCode::InvalidArgument)
        );
    }
    // A short key is a caller bug, not a client error.
    assert_eq!(
        issue_token(&key("short")[..16], &scope("a"), &cursor),
        Err(ErrorCode::InternalError)
    );
    // Through the request parser: same token, different listing parameters.
    let t = Target::parse(
        &format!("/bucket?list-type=2&prefix=b&delimiter=%2F&continuation-token={token}"),
        &policy(),
    )
    .unwrap();
    assert_eq!(
        ListObjectsV2::parse(&t, &key("list")).unwrap_err(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn list_objects_xml_fields() {
    let xml = page(&["k&<\"", "x"], "&max-keys=5000", 1000, 1);
    assert_eq!(
        xml,
        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>bucket</Name><Prefix></Prefix><KeyCount>2</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>\
<Contents><Key>k&amp;&lt;&quot;</Key><LastModified>2013-05-24T00:00:00.007Z</LastModified><ETag>&quot;k&amp;&lt;&quot;&quot;</ETag><Size>4</Size><StorageClass>STANDARD</StorageClass></Contents>\
<Contents><Key>x</Key><LastModified>2013-05-24T00:00:00.007Z</LastModified><ETag>&quot;x&quot;</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"
    );
    // Keys that XML 1.0 cannot carry need encoding-type=url.
    let control = ["a\u{1}b"];
    let t = Target::parse("/bucket?list-type=2", &policy()).unwrap();
    let mut list = ListObjectsV2::parse(&t, &key("list")).unwrap();
    list.push(row(control[0])).unwrap();
    assert_eq!(
        list.finish(true, &key("list")).unwrap_err(),
        ErrorCode::InvalidArgument
    );
    let xml = page(
        &control,
        "&encoding-type=url&prefix=a&start-after=a",
        1000,
        1,
    );
    assert!(xml.contains(
        "<StartAfter>a</StartAfter><EncodingType>url</EncodingType><Contents><Key>a%01b</Key>"
    ));
    for (query, err) in [
        ("&max-keys=x", ErrorCode::InvalidRequest),
        ("&encoding-type=xml", ErrorCode::InvalidArgument),
        ("&prefix=a&prefix=b", ErrorCode::InvalidRequest),
    ] {
        let t = Target::parse(&format!("/bucket?list-type=2{query}"), &policy()).unwrap();
        assert_eq!(
            ListObjectsV2::parse(&t, &key("list")).unwrap_err(),
            err,
            "{query}"
        );
    }
    // The caller must feed in-prefix rows in ascending order, and a page that
    // scanned nothing cannot be truncated (it would loop the client).
    let t = Target::parse("/bucket?list-type=2&prefix=b", &policy()).unwrap();
    let mut list = ListObjectsV2::parse(&t, &key("list")).unwrap();
    assert_eq!(list.push(row("a")), Err(ErrorCode::InternalError));
    list.push(row("b2")).unwrap();
    assert_eq!(list.push(row("b1")), Err(ErrorCode::InternalError));
    let list = ListObjectsV2::parse(&t, &key("list")).unwrap();
    assert_eq!(
        list.finish(false, &key("list")).unwrap_err(),
        ErrorCode::InternalError
    );
    // max-keys=0 is an empty, untruncated page.
    let xml = page(&["a"], "&max-keys=0", 1000, 1);
    assert!(
        xml.contains("<KeyCount>0</KeyCount><MaxKeys>0</MaxKeys><IsTruncated>false</IsTruncated>")
    );
}

#[test]
fn list_buckets_xml() {
    let body = list_buckets_response(&[
        BucketEntry {
            name: "alpha".into(),
            created_ms: NOW * 1000,
        },
        BucketEntry {
            name: "beta".into(),
            created_ms: NOW * 1000 + 1500,
        },
    ])
    .unwrap();
    assert_eq!(body.status, 200);
    assert_eq!(
        body.headers,
        [("content-type".to_string(), "application/xml".to_string())]
    );
    assert_eq!(
        String::from_utf8(body.body).unwrap(),
        "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Buckets>\
<Bucket><Name>alpha</Name><CreationDate>2013-05-24T00:00:00.000Z</CreationDate></Bucket>\
<Bucket><Name>beta</Name><CreationDate>2013-05-24T00:00:01.500Z</CreationDate></Bucket>\
</Buckets></ListAllMyBucketsResult>"
    );
    assert!(list_buckets_response(&[BucketEntry {
        name: "x".into(),
        created_ms: i64::MAX
    }])
    .is_err());
}

// ---- Commit renderers ----

const ABC_SHA_B64: &str = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";

fn commit(checksum: Option<StoredChecksum>) -> CommitResult {
    CommitResult {
        bucket: "bucket".into(),
        key: "dir/a b&c".into(),
        etag: "\"abc-2\"".into(),
        checksum,
        modified_ms: NOW * 1000 + 250,
    }
}

#[test]
fn complete_multipart_result_renders_committed_destination() {
    let composite =
        StoredChecksum::composite_sha256(vec![ABC_SHA_B64.into(), ABC_SHA_B64.into()]).unwrap();
    let value = composite.value().to_owned();
    let t = Target::parse("/bucket/dir/a%20b%26c?uploadId=u", &policy()).unwrap();
    let r = commit(Some(composite))
        .complete_response(&t, &policy())
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        String::from_utf8(r.body).unwrap(),
        format!(
            "<CompleteMultipartUploadResult><Location>https://{HOST}/bucket/dir/a%20b%26c</Location><Bucket>bucket</Bucket><Key>dir/a b&amp;c</Key><ETag>&quot;abc-2&quot;</ETag><ChecksumSHA256>{value}</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType></CompleteMultipartUploadResult>"
        )
    );
    // Never renders a destination other than the one committed.
    for other in [
        "/bucket/dir/other?uploadId=u",
        "/other/dir/a%20b%26c?uploadId=u",
        "/bucket?uploadId=u",
    ] {
        let t = Target::parse(other, &policy()).unwrap();
        assert_eq!(
            commit(None).complete_response(&t, &policy()).unwrap_err(),
            ErrorCode::InvalidArgument,
            "{other}"
        );
    }
}

#[test]
fn put_and_copy_results_render_etag_and_checksum() {
    let full = StoredChecksum::full(ChecksumAlgorithm::Sha256, ABC_SHA_B64.into()).unwrap();
    let put = commit(Some(full.clone())).put_response();
    assert_eq!(put.status, 200);
    assert!(put.body.is_empty());
    assert_eq!(
        put.headers,
        [
            ("etag".to_string(), "\"abc-2\"".to_string()),
            ("x-amz-checksum-sha256".to_string(), ABC_SHA_B64.to_string()),
            ("x-amz-checksum-type".to_string(), "FULL_OBJECT".to_string()),
        ]
    );
    assert_eq!(
        commit(None).put_response().headers,
        [("etag".to_string(), "\"abc-2\"".to_string())]
    );
    let copy = commit(Some(full)).copy_response().unwrap();
    assert_eq!(
        String::from_utf8(copy.body).unwrap(),
        format!("<CopyObjectResult><LastModified>2013-05-24T00:00:00.250Z</LastModified><ETag>&quot;abc-2&quot;</ETag><ChecksumSHA256>{ABC_SHA_B64}</ChecksumSHA256><ChecksumType>FULL_OBJECT</ChecksumType></CopyObjectResult>")
    );
    let crc = StoredChecksum::full(ChecksumAlgorithm::Crc32, "NSRBwg==".into()).unwrap();
    let put = commit(Some(crc)).put_response();
    assert_eq!(
        put.headers[1],
        ("x-amz-checksum-crc32".to_string(), "NSRBwg==".to_string())
    );
}
