//! What a client is told when a request is refused, and what it is not
//! refused for: harmless `x-amz-*` headers, the region of the credential
//! scope, the host, a bucket that is not there, and the request id every
//! answer carries.

mod service_support;

use service_support::*;
use velmora_bridge::*;

const BUCKET: &str = "bkt-cx";

fn field(resp: &Resp, tag: &str) -> Option<String> {
    resp.values(tag).pop()
}

#[tokio::test(flavor = "current_thread")]
async fn harmless_headers_are_accepted_signed_and_change_nothing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    for (i, (name, value)) in [
        ("x-amz-user-agent", "aws-sdk-js/3.600.0, extra/1"),
        ("x-amz-acl", "private"),
        ("x-amz-acl", "bucket-owner-full-control"),
        ("x-amz-server-side-encryption", "AES256"),
        ("x-amz-request-payer", "requester"),
        ("x-amz-mp-object-size", "7"),
        ("x-amz-storage-class", "STANDARD"),
        ("x-amz-storage-class", "STANDARD_IA"),
        ("x-amz-storage-class", "ONEZONE_IA"),
        ("x-amz-storage-class", "INTELLIGENT_TIERING"),
        ("x-amz-storage-class", "GLACIER_IR"),
        ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("k{i}");
        let req = signer.sign(
            rig.now(),
            Method::Put,
            &path(BUCKET, &key),
            &[],
            &[(name, value)],
            b"payload".to_vec(),
        );
        // The header is part of what the client signed.
        let auth = &req.headers.iter().find(|(n, _)| n == "authorization");
        assert!(auth.unwrap().1.contains(name), "{name}");
        let put = rig.send(req).await;
        assert_eq!(put.status, 200, "{name}: {value}: {}", put.text());

        // Stored like any object, and reported as what it is: STANDARD,
        // with none of the ignored headers echoed back.
        let head = rig.head(&signer, BUCKET, &key).await;
        head.expect(200);
        assert_eq!(head.header("x-amz-storage-class"), Some("STANDARD"));
        assert_eq!(head.header("content-length"), Some("7"));
        for gone in [
            "x-amz-user-agent",
            "x-amz-acl",
            "x-amz-server-side-encryption",
            "x-amz-request-payer",
            "x-amz-mp-object-size",
        ] {
            assert_eq!(head.header(gone), None, "{name}: {gone}");
        }
    }
    assert_eq!(rig.count("objects"), 12);

    // `x-amz-sdk-checksum-algorithm` announces the checksum the request
    // carries, and is held to it: with the checksum it names it is
    // accepted, alone or naming another it is refused (an integrity
    // declaration is never ignored).
    let crc = crc32c_b64(b"payload");
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "sum"),
        &[],
        &[
            ("x-amz-sdk-checksum-algorithm", "CRC32C"),
            ("x-amz-checksum-crc32c", crc.as_str()),
        ],
        b"payload",
    )
    .await
    .expect(200);
    for headers in [
        vec![("x-amz-sdk-checksum-algorithm", "CRC32C")],
        vec![
            ("x-amz-sdk-checksum-algorithm", "SHA256"),
            ("x-amz-checksum-crc32c", crc.as_str()),
        ],
    ] {
        let resp = rig
            .call(
                &signer,
                Method::Put,
                &path(BUCKET, "sum2"),
                &[],
                &headers,
                b"payload",
            )
            .await;
        assert_eq!(resp.status, 400);
    }
    assert_eq!(rig.count("objects"), 13);
}

#[tokio::test(flavor = "current_thread")]
async fn an_ignored_header_still_has_to_be_signed() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    // Added after signing: an `x-amz-*` header outside the signature is
    // refused whether or not its value would be acted on.
    let mut req = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    req.set_header("x-amz-user-agent", "aws-sdk-js/3.600.0");
    assert_eq!(rig.send(req).await.status, 403);
    // Signed with one value and sent with another.
    let mut req = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[("x-amz-user-agent", "aws-sdk-js/3.600.0")],
        b"payload".to_vec(),
    );
    req.set_header("x-amz-user-agent", "aws-sdk-js/3.601.0");
    rig.send(req)
        .await
        .expect_error(403, "SignatureDoesNotMatch");
    assert_eq!(rig.count("objects"), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_header_that_is_not_served_is_refused_by_name() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    for (name, value, status, code, element) in [
        ("x-amz-tagging", "a=b", 501, "NotImplemented", "Header"),
        (
            "x-amz-object-lock-mode",
            "GOVERNANCE",
            501,
            "NotImplemented",
            "Header",
        ),
        (
            "x-amz-website-redirect-location",
            "/x",
            501,
            "NotImplemented",
            "Header",
        ),
        (
            "x-amz-server-side-encryption-customer-algorithm",
            "AES256",
            501,
            "NotImplemented",
            "Header",
        ),
        // A guard the service cannot check is refused, never ignored.
        (
            "x-amz-expected-bucket-owner",
            "123456789012",
            501,
            "NotImplemented",
            "Header",
        ),
        (
            "x-amz-bucket-object-lock-enabled",
            "true",
            501,
            "NotImplemented",
            "Header",
        ),
        ("x-amz-made-up", "1", 501, "NotImplemented", "Header"),
        (
            "x-amz-acl",
            "public-read",
            400,
            "AccessControlListNotSupported",
            "Header",
        ),
        (
            "x-amz-grant-read",
            "id=abc",
            400,
            "AccessControlListNotSupported",
            "Header",
        ),
        (
            "x-amz-storage-class",
            "GLACIER",
            400,
            "InvalidStorageClass",
            "Header",
        ),
        (
            "x-amz-storage-class",
            "DEEP_ARCHIVE",
            400,
            "InvalidStorageClass",
            "Header",
        ),
        (
            "x-amz-storage-class",
            "standard",
            400,
            "InvalidStorageClass",
            "Header",
        ),
        (
            "x-amz-server-side-encryption",
            "aws:kms",
            400,
            "InvalidArgument",
            "ArgumentName",
        ),
        (
            "x-amz-request-payer",
            "someone",
            400,
            "InvalidArgument",
            "ArgumentName",
        ),
        (
            "x-amz-mp-object-size",
            "seven",
            400,
            "InvalidArgument",
            "ArgumentName",
        ),
    ] {
        let resp = rig
            .call(
                &signer,
                Method::Put,
                &path(BUCKET, "k"),
                &[],
                &[(name, value)],
                b"payload",
            )
            .await;
        resp.expect_error(status, code);
        assert_eq!(field(&resp, element).as_deref(), Some(name), "{name}");
        let message = resp.message();
        assert!(message.contains(name), "{name}: {message}");
        assert!(!message.contains(value), "{name}: {message}");
    }
    assert_eq!(rig.count("objects"), 0);
    assert_eq!(rig.count("generations"), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn the_region_aliases_sign_as_well_as_the_configured_region() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    assert_eq!(REGION, "auto");
    for region in ["auto", "us-east-1"] {
        let signer = Signer {
            region: region.to_string(),
            ..signer.clone()
        };
        let key = format!("k-{region}");
        rig.put(&signer, BUCKET, &key, b"payload").await.expect(200);
        rig.head(&signer, BUCKET, &key).await.expect(200);
    }
    // The alias is a name for the scope, not a way around the signature.
    let wrong = Signer {
        region: "us-east-1".to_string(),
        secret: signer.secret.chars().rev().collect(),
        ..signer.clone()
    };
    rig.put(&wrong, BUCKET, "k", b"payload")
        .await
        .expect_error(403, "SignatureDoesNotMatch");
}

#[tokio::test(flavor = "current_thread")]
async fn a_wrong_region_is_told_the_region_to_use() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let unknown = Signer::new("AKIDUNKNOWN000000000", secret());

    let mut answers = Vec::new();
    // Whoever asks and whatever it names: the scope is read before any
    // key or bucket is looked up, so the answer tells nothing of either.
    for (who, bucket) in [
        (&signer, BUCKET),
        (&signer, "bkt-absent"),
        (&unknown, BUCKET),
    ] {
        let who = Signer {
            region: "eu-west-1".to_string(),
            ..who.clone()
        };
        let resp = rig
            .call(&who, Method::Get, &path(bucket, "k"), &[], &[], b"")
            .await;
        resp.expect_error(400, "AuthorizationHeaderMalformed");
        assert_eq!(field(&resp, "Region").as_deref(), Some(REGION));
        assert_eq!(
            resp.message().replace("&apos;", "'"),
            "The authorization header is malformed; the region 'eu-west-1' is wrong; \
             expecting 'auto'"
        );
        answers.push(resp.body);
    }
    answers.dedup();
    assert_eq!(answers.len(), 1);

    // A presigned URL names its scope in the query.
    let good = signer.presign(rig.now(), &path(BUCKET, "k"));
    rig.send(good).await.expect(200);
    let east = Signer {
        region: "us-east-1".to_string(),
        ..signer.clone()
    };
    rig.send(east.presign(rig.now(), &path(BUCKET, "k")))
        .await
        .expect(200);
    let west = Signer {
        region: "us-west-2".to_string(),
        ..signer.clone()
    };
    let resp = rig.send(west.presign(rig.now(), &path(BUCKET, "k"))).await;
    resp.expect_error(400, "AuthorizationQueryParametersError");
    assert_eq!(field(&resp, "Region").as_deref(), Some(REGION));
    assert_eq!(
        resp.message().replace("&apos;", "'"),
        "Error parsing the X-Amz-Credential parameter; the region 'us-west-2' is wrong; \
         expecting 'auto'"
    );

    // A region that is not fit to be echoed is not echoed.
    let odd = Signer {
        region: "eu<west>".to_string(),
        ..signer.clone()
    };
    let resp = rig
        .call(&odd, Method::Get, &path(BUCKET, "k"), &[], &[], b"")
        .await;
    assert_eq!(resp.status, 400);
    assert!(!resp.text().contains("eu<west>"));
    assert!(!resp.text().contains("west"));
}

#[tokio::test(flavor = "current_thread")]
async fn a_wrong_host_is_told_so() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let sign = || signer.sign(rig.now(), Method::Get, &path(BUCKET, "k"), &[], &[], vec![]);

    let mut req = sign();
    req.set_header("host", &format!("{BUCKET}.{HOST}"));
    let resp = rig.send(req).await;
    resp.expect_error(400, "InvalidRequest");
    assert!(resp.message().starts_with("Virtual-hosted-style requests"));
    assert!(resp.message().contains("path-style"));

    let mut req = sign();
    req.set_header("host", "elsewhere.test");
    let resp = rig.send(req).await;
    resp.expect_error(400, "InvalidRequest");
    assert!(resp.message().starts_with("The Host header does not name"));
    // Neither answer names the endpoint a caller should have used.
    assert!(!resp.text().contains(HOST));

    // On a virtual-hosted request the first path segment is a key. One
    // that could not be a bucket name still gets the answer about the
    // host, for a multipart call as well.
    for query in [&[][..], &[("uploads", "")][..]] {
        let method = if query.is_empty() {
            Method::Get
        } else {
            Method::Post
        };
        let mut req = signer.sign(rig.now(), method, "/Photos/image.jpg", query, &[], vec![]);
        req.set_header("host", &format!("{BUCKET}.{HOST}"));
        let resp = rig.send(req).await;
        resp.expect_error(400, "InvalidRequest");
        assert!(resp.message().starts_with("Virtual-hosted-style requests"));
    }
    // A one-segment key or the root, which route to no operation, gets
    // the same answer about the host rather than a bare 501.
    type Call<'a> = (Method, &'a str, &'a [(&'a str, &'a str)]);
    let calls: &[Call<'_>] = &[
        (Method::Post, "/big.bin", &[("uploads", "")]),
        (Method::Delete, "/big.bin", &[("uploadId", "u")]),
        (Method::Get, "/", &[("uploads", "")]),
    ];
    for (method, target, query) in calls {
        let mut req = signer.sign(rig.now(), method.clone(), target, query, &[], vec![]);
        req.set_header("host", &format!("{BUCKET}.{HOST}"));
        let resp = rig.send(req).await;
        resp.expect_error(400, "InvalidRequest");
        assert!(resp.message().starts_with("Virtual-hosted-style requests"));
        // With the right host the same call is an operation not offered.
        let req = signer.sign(rig.now(), method.clone(), target, query, &[], vec![]);
        rig.send(req).await.expect_error(501, "NotImplemented");
    }
    // With the right host the path is what is refused.
    let req = signer.sign(
        rig.now(),
        Method::Get,
        "/Photos/image.jpg",
        &[],
        &[],
        vec![],
    );
    let plain = rig.send(req).await;
    plain.expect(400);
    assert!(!plain.message().contains("Host"));
    assert!(!plain.message().contains("hosted"));

    // The answer is the same for a request that names nothing real.
    let ghost = Signer::new("AKIDUNKNOWN000000000", secret());
    let mut req = ghost.sign(
        rig.now(),
        Method::Get,
        &path("bkt-absent", "k"),
        &[],
        &[],
        vec![],
    );
    req.set_header("host", "elsewhere.test");
    assert_eq!(rig.send(req).await.body, resp.body);
}

#[tokio::test(flavor = "current_thread")]
async fn only_a_verified_caller_learns_that_a_bucket_is_missing() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    rig.bucket("bkt-other", true).await;
    let reader = rig
        .key("AKIDREADONLY00000000", secret(), KeyStatus::Active)
        .await;
    rig.grant("AKIDREADONLY00000000", &bucket, Perm::Ro).await;

    // Verified: no bucket by that name for this key, existing or not.
    for name in ["bkt-absent", "bkt-other"] {
        let resp = rig.put(&signer, name, "k", b"payload").await;
        resp.expect_error(404, "NoSuchBucket");
        assert_eq!(resp.message(), "The specified bucket does not exist.");
    }
    // A grant that does not cover the operation is still a denial.
    rig.put(&reader, BUCKET, "k", b"payload")
        .await
        .expect_error(403, "AccessDenied");

    // Not verified: the same answer whatever bucket is named.
    let forged = Signer {
        secret: signer.secret.chars().rev().collect(),
        ..signer.clone()
    };
    let unknown = Signer::new("AKIDUNKNOWN000000000", secret());
    for (who, code) in [
        (&forged, "SignatureDoesNotMatch"),
        (&unknown, "InvalidAccessKeyId"),
    ] {
        let mut answers = Vec::new();
        for name in [BUCKET, "bkt-absent", "bkt-other"] {
            let resp = rig
                .call(who, Method::Get, &path(name, "k"), &[], &[], b"")
                .await;
            resp.expect_error(403, code);
            answers.push(resp.body);
        }
        answers.dedup();
        assert_eq!(answers.len(), 1, "{code}");
    }
    // No signature at all.
    let mut answers = Vec::new();
    for name in [BUCKET, "bkt-absent", "bkt-other"] {
        let mut req = signer.sign(rig.now(), Method::Get, &path(name, "k"), &[], &[], vec![]);
        req.headers.retain(|(n, _)| n != "authorization");
        let resp = rig.send(req).await;
        assert_eq!(resp.status, 403, "{name}");
        answers.push(resp.body);
    }
    answers.dedup();
    assert_eq!(answers.len(), 1);
}

async fn body_of(resp: S3Response) -> (u16, Vec<(String, String)>, String) {
    let status = resp.status;
    let headers = resp.headers.clone();
    let collected = Resp::collect(resp).await;
    (status, headers, collected.text())
}

#[tokio::test(flavor = "current_thread")]
async fn every_answer_carries_the_request_id() {
    let get = |headers: &[(String, String)], name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };

    // An error names the id in its headers and in its body.
    let (status, headers, text) = body_of(
        S3Response::error(404, "NoSuchKey", "The specified key does not exist.")
            .with_request_id("8a1b2c3d4e5f6071-AMS"),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(
        get(&headers, "x-amz-request-id").as_deref(),
        Some("8a1b2c3d4e5f6071-AMS")
    );
    assert_eq!(
        get(&headers, "x-amz-id-2").as_deref(),
        Some("8a1b2c3d4e5f6071-AMS")
    );
    assert_eq!(
        text,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchKey</Code>\
         <Message>The specified key does not exist.</Message>\
         <RequestId>8a1b2c3d4e5f6071-AMS</RequestId><HostId>8a1b2c3d4e5f6071-AMS</HostId>\
         </Error>"
    );

    // A success carries it in the headers; its body is never touched,
    // even one that looks like an error document.
    let lookalike = S3Response::error(400, "X", "y");
    let RespBody::Bytes(bytes) = lookalike.body else {
        panic!("an error has a body")
    };
    let ok = S3Response {
        status: 200,
        headers: vec![("content-type".into(), "application/xml".into())],
        body: RespBody::Bytes(bytes.clone()),
    };
    let (status, headers, text) = body_of(ok.with_request_id("abc")).await;
    assert_eq!(status, 200);
    assert_eq!(get(&headers, "x-amz-request-id").as_deref(), Some("abc"));
    assert_eq!(text.as_bytes(), bytes);

    // An error body that is not the service's own document is left alone.
    let foreign = S3Response {
        status: 500,
        headers: vec![("content-type".into(), "text/plain".into())],
        body: RespBody::Bytes(b"<Error></Error>".to_vec()),
    };
    let (_, headers, text) = body_of(foreign.with_request_id("abc")).await;
    assert_eq!(get(&headers, "x-amz-request-id").as_deref(), Some("abc"));
    assert_eq!(text, "<Error></Error>");

    // An id that is not plainly an id is not put anywhere.
    for bad in ["", "a b", "a<b", "a\r\nx-evil: 1", &"a".repeat(65), "é"] {
        assert_eq!(safe_request_id(bad), None, "{bad:?}");
        let (_, headers, text) =
            body_of(S3Response::error(403, "AccessDenied", "Access Denied").with_request_id(bad))
                .await;
        assert_eq!(get(&headers, "x-amz-request-id"), None, "{bad:?}");
        assert!(!text.contains("RequestId"), "{bad:?}");
    }
    assert_eq!(safe_request_id("Ab0._-"), Some("Ab0._-"));
    // The ID a request without a ray ID is given is always one that is
    // kept, at the extremes of its inputs as well.
    for (now, random) in [
        (0, 0),
        (1_763_500_000_000, 0xdead_beef),
        (u64::MAX, u32::MAX),
    ] {
        let id = local_request_id(now, random);
        assert_eq!(safe_request_id(&id), Some(id.as_str()), "{id}");
    }

    // The same holds for an answer of the service itself.
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let req = signer.sign(
        rig.now(),
        Method::Get,
        &path(BUCKET, "none"),
        &[],
        &[],
        vec![],
    );
    let resp = std::rc::Rc::clone(&rig.bridge)
        .handle(req.into_request())
        .await;
    let (status, headers, text) = body_of(resp.with_request_id("ray-1")).await;
    assert_eq!(status, 404);
    assert_eq!(get(&headers, "x-amz-request-id").as_deref(), Some("ray-1"));
    assert!(text.ends_with("<RequestId>ray-1</RequestId><HostId>ray-1</HostId></Error>"));
}

/// The multipart calls authenticate on a path of their own; a client
/// gets the same answers there.
#[tokio::test(flavor = "current_thread")]
async fn multipart_calls_answer_the_same_way() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bucket("bkt-other", true).await;
    let east = Signer {
        region: "us-east-1".to_string(),
        ..signer.clone()
    };
    let object = path(BUCKET, "big");

    // Signed for the alias region, with the headers SDKs add.
    let created = rig
        .call(
            &east,
            Method::Post,
            &object,
            &[("uploads", "")],
            &[
                ("x-amz-acl", "private"),
                ("x-amz-server-side-encryption", "AES256"),
                ("x-amz-storage-class", "STANDARD_IA"),
                ("x-amz-user-agent", "aws-sdk-js/3.600.0"),
            ],
            b"",
        )
        .await;
    created.expect(200);
    let id = field(&created, "UploadId").unwrap();
    let part = rig
        .call(
            &east,
            Method::Put,
            &object,
            &[("partNumber", "1"), ("uploadId", &id)],
            &[],
            b"payload",
        )
        .await;
    part.expect(200);
    let etag = part.header("etag").unwrap().replace('"', "&quot;");
    let xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    // A declared size that is not the size of the listed parts is the
    // client's sign that a part is missing: nothing is published, and the
    // upload stays open.
    let wrong = rig
        .call(
            &east,
            Method::Post,
            &object,
            &[("uploadId", &id)],
            &[("x-amz-mp-object-size", "999")],
            xml.as_bytes(),
        )
        .await;
    wrong.expect(400);
    assert_eq!(field(&wrong, "Code").as_deref(), Some("InvalidRequest"));
    assert_eq!(
        field(&wrong, "Header").as_deref(),
        Some("x-amz-mp-object-size")
    );
    let message = field(&wrong, "Message").unwrap();
    assert!(
        message.contains("999") && message.contains(" 7 bytes"),
        "{message}"
    );
    rig.head(&signer, BUCKET, "big").await.expect(404);
    rig.call(
        &east,
        Method::Post,
        &object,
        &[("uploadId", &id)],
        &[("x-amz-mp-object-size", "7")],
        xml.as_bytes(),
    )
    .await
    .expect(200);
    let head = rig.head(&signer, BUCKET, "big").await;
    head.expect(200);
    assert_eq!(head.header("content-length"), Some("7"));
    assert_eq!(head.header("x-amz-storage-class"), Some("STANDARD"));

    let create = |who: &Signer, bucket: &str, extra: &[(&str, &str)]| {
        who.sign(
            rig.now(),
            Method::Post,
            &path(bucket, "k"),
            &[("uploads", "")],
            extra,
            Vec::new(),
        )
    };
    let uploads = rig.count("uploads");

    let resp = rig
        .send(create(&signer, BUCKET, &[("x-amz-tagging", "a=b")]))
        .await;
    resp.expect_error(501, "NotImplemented");
    assert_eq!(field(&resp, "Header").as_deref(), Some("x-amz-tagging"));
    let resp = rig
        .send(create(
            &signer,
            BUCKET,
            &[("x-amz-storage-class", "GLACIER")],
        ))
        .await;
    resp.expect_error(400, "InvalidStorageClass");
    assert!(resp.message().contains("x-amz-storage-class"));

    let west = Signer {
        region: "us-west-2".to_string(),
        ..signer.clone()
    };
    let resp = rig.send(create(&west, BUCKET, &[])).await;
    resp.expect_error(400, "AuthorizationHeaderMalformed");
    assert_eq!(field(&resp, "Region").as_deref(), Some(REGION));
    assert!(resp.message().contains("us-west-2"));

    let mut req = create(&signer, BUCKET, &[]);
    req.set_header("host", &format!("{BUCKET}.{HOST}"));
    let resp = rig.send(req).await;
    resp.expect_error(400, "InvalidRequest");
    assert!(resp.message().starts_with("Virtual-hosted-style requests"));

    for name in ["bkt-absent", "bkt-other"] {
        rig.send(create(&signer, name, &[]))
            .await
            .expect_error(404, "NoSuchBucket");
    }
    let forged = Signer {
        secret: signer.secret.chars().rev().collect(),
        ..signer.clone()
    };
    let unknown = Signer::new("AKIDUNKNOWN000000000", secret());
    for (who, code) in [
        (&forged, "SignatureDoesNotMatch"),
        (&unknown, "InvalidAccessKeyId"),
    ] {
        let mut answers = Vec::new();
        for name in [BUCKET, "bkt-absent", "bkt-other"] {
            let resp = rig.send(create(who, name, &[])).await;
            resp.expect_error(403, code);
            answers.push(resp.body);
        }
        answers.dedup();
        assert_eq!(answers.len(), 1, "{code}");
    }
    assert_eq!(rig.count("uploads"), uploads);
}
