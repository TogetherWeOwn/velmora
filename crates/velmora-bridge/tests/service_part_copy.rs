//! UploadPartCopy: a part whose bytes are a range of a live object in the
//! same bucket. The range is read the way a GET reads it and sealed as a
//! new extent of the upload, so the part does not depend on the source
//! afterwards.

mod service_support;

use service_support::*;
use velmora_bridge::*;

const BUCKET: &str = "bkt-part-copy";

fn source(key: &str) -> String {
    format!("/{BUCKET}/{}", uri_encode(key, true))
}

fn md5_hex(bytes: &[u8]) -> String {
    hex(&md5::compute(bytes).0)
}

async fn create(rig: &Rig, signer: &Signer, key: &str) -> String {
    let created = rig
        .call(
            signer,
            Method::Post,
            &path(BUCKET, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    created.expect(200);
    created.values("UploadId").remove(0)
}

async fn part(rig: &Rig, signer: &Signer, key: &str, id: &str, n: u16, bytes: &[u8]) -> String {
    let n = n.to_string();
    let sent = rig
        .call(
            signer,
            Method::Put,
            &path(BUCKET, key),
            &[("partNumber", &n), ("uploadId", id)],
            &[],
            bytes,
        )
        .await;
    sent.expect(200);
    sent.header("etag").unwrap().to_owned()
}

async fn part_copy(
    rig: &Rig,
    signer: &Signer,
    key: &str,
    id: &str,
    n: u16,
    headers: &[(&str, &str)],
) -> Resp {
    let n = n.to_string();
    rig.call(
        signer,
        Method::Put,
        &path(BUCKET, key),
        &[("partNumber", &n), ("uploadId", id)],
        headers,
        b"",
    )
    .await
}

/// The ETag in a `CopyPartResult` body.
fn copied_etag(resp: &Resp) -> String {
    resp.values("ETag").remove(0).replace("&quot;", "\"")
}

async fn complete(rig: &Rig, signer: &Signer, key: &str, id: &str, etags: &[String]) -> Resp {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in etags.iter().enumerate() {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
            i + 1
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        signer,
        Method::Post,
        &path(BUCKET, key),
        &[("uploadId", id)],
        &[("content-type", "application/xml")],
        xml.as_bytes(),
    )
    .await
}

async fn get(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
        .await
}

/// A two-extent source (`5 MiB` + `70 000` bytes) and a one-extent one.
async fn sources(rig: &Rig, signer: &Signer) -> (Vec<u8>, Vec<u8>) {
    let a = pattern(1, 5 * MIB);
    let b = pattern(2, 70_000);
    let id = create(rig, signer, "big").await;
    let etags = [
        part(rig, signer, "big", &id, 1, &a).await,
        part(rig, signer, "big", &id, 2, &b).await,
    ];
    complete(rig, signer, "big", &id, &etags).await.expect(200);
    let one = pattern(3, 300_000);
    rig.put(signer, BUCKET, "one", &one).await.expect(200);
    ([a, b].concat(), one)
}

#[tokio::test(flavor = "current_thread")]
async fn parts_copied_by_range_read_back_and_outlive_the_source() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let (big, one) = sources(&rig, &signer).await;
    let (_, big_extents) = rig.live(&bucket, "big").await.unwrap();
    assert_eq!(rig.count("extents"), 3);

    let id = create(&rig, &signer, "dst").await;
    // 1: exactly the first extent of the source.
    let aligned = format!("bytes=0-{}", 5 * MIB - 1);
    // 2: starts inside the first extent and ends inside the second.
    let (from, to) = (1000, 5 * MIB + 60_000);
    let unaligned = format!("bytes={from}-{}", to - 1);
    let src_big = source("big");
    let src_one = source("one");
    let requests: [Vec<(&str, &str)>; 3] = [
        vec![
            ("x-amz-copy-source", &src_big),
            ("x-amz-copy-source-range", &aligned),
        ],
        vec![
            ("x-amz-copy-source", &src_big),
            ("x-amz-copy-source-range", &unaligned),
        ],
        // 3: no range is the whole object.
        vec![("x-amz-copy-source", &src_one)],
    ];
    let expected = [&big[..5 * MIB], &big[from..to], &one[..]];
    let mut etags = Vec::new();
    for (i, headers) in requests.iter().enumerate() {
        let r = part_copy(&rig, &signer, "dst", &id, i as u16 + 1, headers).await;
        r.expect(200);
        assert!(r.text().starts_with("<CopyPartResult><LastModified>"));
        let etag = copied_etag(&r);
        assert_eq!(etag, format!("\"{}\"", md5_hex(expected[i])));
        etags.push(etag);
    }
    // Each part is an extent of its own, never one of the source's.
    assert_eq!(rig.count("extents"), 6);
    // Two rows are the parts the source was uploaded in.
    assert_eq!(rig.count("upload_parts"), 2 + 3);
    let reused: i64 = rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row(
            "SELECT COUNT(*) FROM upload_parts p JOIN generation_extents g \
               ON g.extent_id = p.extent_id WHERE p.upload_id = ?1",
            [id.as_str()],
            |r| r.get(0),
        )
        .unwrap()
    });
    assert_eq!(reused, 0);

    complete(&rig, &signer, "dst", &id, &etags)
        .await
        .expect(200);
    let whole = expected.concat();
    assert_eq!(get(&rig, &signer, "dst").await.body, whole);
    let (generation, extents) = rig.live(&bucket, "dst").await.unwrap();
    assert_eq!(generation.size, whole.len() as u64);
    assert!(extents
        .iter()
        .all(|e| big_extents.iter().all(|s| s.id != e.id)));

    // The sources go away, cache and safety copies included.
    for key in ["big", "one"] {
        rig.call(&signer, Method::Delete, &path(BUCKET, key), &[], &[], b"")
            .await
            .expect(204);
    }
    rig.bridge.clock.advance_secs(7 * 86_400);
    assert_eq!(
        rig.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert_eq!(get(&rig, &signer, "big").await.status, 404);
    assert_eq!(get(&rig, &signer, "dst").await.body, whole);
}

#[tokio::test(flavor = "current_thread")]
async fn a_copied_part_can_replace_an_uploaded_one() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let (_, one) = sources(&rig, &signer).await;
    let id = create(&rig, &signer, "dst").await;
    part(&rig, &signer, "dst", &id, 1, &pattern(9, 4000)).await;
    let r = part_copy(
        &rig,
        &signer,
        "dst",
        &id,
        1,
        &[
            ("x-amz-copy-source", &source("one")),
            ("x-amz-copy-source-range", "bytes=10-109"),
        ],
    )
    .await;
    r.expect(200);
    let etag = copied_etag(&r);
    assert_eq!(rig.count("upload_parts"), 2 + 1);
    complete(&rig, &signer, "dst", &id, &[etag])
        .await
        .expect(200);
    assert_eq!(get(&rig, &signer, "dst").await.body, &one[10..110]);
}

#[tokio::test(flavor = "current_thread")]
async fn requests_the_part_copy_cannot_honour_store_nothing() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.bucket("bkt-other", true).await;
    let (big, _) = sources(&rig, &signer).await;
    let id = create(&rig, &signer, "dst").await;
    let src = source("big");
    let size = big.len();
    let copy = |extra: Vec<(&'static str, String)>| {
        let (rig, signer, id, src) = (&rig, &signer, &id, &src);
        async move {
            let mut headers = vec![("x-amz-copy-source", src.as_str())];
            headers.extend(extra.iter().map(|(n, v)| (*n, v.as_str())));
            part_copy(rig, signer, "dst", id, 1, &headers).await
        }
    };
    let range = |value: &str| vec![("x-amz-copy-source-range", value.to_owned())];

    // Ranges that are not `bytes=first-last` inside the object.
    for bad in [
        format!("bytes=0-{size}"),
        format!("bytes={size}-{size}"),
        "bytes=5-4".to_owned(),
        "bytes=-5".to_owned(),
        "bytes=5-".to_owned(),
        "0-5".to_owned(),
        "bytes=+1-5".to_owned(),
    ] {
        copy(range(&bad)).await.expect_error(400, "InvalidArgument");
    }
    // Source conditions that do not hold.
    copy(vec![(
        "x-amz-copy-source-if-match",
        "\"00000000000000000000000000000000\"".to_owned(),
    )])
    .await
    .expect_error(412, "PreconditionFailed");
    copy(vec![(
        "x-amz-copy-source-if-unmodified-since",
        "Sat, 01 Jan 2000 00:00:00 GMT".to_owned(),
    )])
    .await
    .expect_error(412, "PreconditionFailed");

    for (from, status, code) in [
        ("/bkt-other/big".to_owned(), 501, "NotImplemented"),
        (format!("/{BUCKET}/big?versionId=1"), 501, "NotImplemented"),
        (source("missing"), 404, "NoSuchKey"),
    ] {
        part_copy(
            &rig,
            &signer,
            "dst",
            &id,
            1,
            &[("x-amz-copy-source", &from)],
        )
        .await
        .expect_error(status, code);
    }
    // A body, or a range without a source.
    let query = [("partNumber", "1"), ("uploadId", id.as_str())];
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "dst"),
        &query,
        &[("x-amz-copy-source", &src)],
        b"body",
    )
    .await
    .expect_error(400, "InvalidRequest");
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "dst"),
        &query,
        &[("x-amz-copy-source-range", "bytes=0-3")],
        b"body",
    )
    .await
    .expect_error(400, "InvalidRequest");
    // A checksum value has no bytes to be checked against.
    part_copy(
        &rig,
        &signer,
        "dst",
        &id,
        1,
        &[
            ("x-amz-copy-source", &src),
            (
                "x-amz-checksum-sha256",
                "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            ),
        ],
    )
    .await
    .expect_error(400, "InvalidRequest");
    // An upload that does not exist.
    part_copy(
        &rig,
        &signer,
        "dst",
        "u_00000000000000000000000000",
        1,
        &[("x-amz-copy-source", &src)],
    )
    .await
    .expect_error(404, "NoSuchUpload");
    // A read-only grant cannot write a part.
    let reader = rig
        .key("AKIDTESTKEY000000002", secret(), KeyStatus::Active)
        .await;
    rig.grant("AKIDTESTKEY000000002", &bucket, Perm::Ro).await;
    part_copy(&rig, &reader, "dst", &id, 1, &[("x-amz-copy-source", &src)])
        .await
        .expect_error(403, "AccessDenied");

    // Only what the sources were stored as.
    assert_eq!(rig.count("upload_parts"), 2);
    assert_eq!(rig.count("extents"), 3);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// A part is one extent, so a range larger than one extent is refused
/// before anything is read.
#[tokio::test(flavor = "current_thread")]
async fn a_range_larger_than_one_extent_is_refused() {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = 6 * MIB as u64;
    let rig = rig_with(NoNntp, cfg);
    let (_, signer) = rig.standard(BUCKET).await;
    let a = pattern(1, 6 * MIB);
    let b = pattern(2, 100);
    for (key, bytes) in [("a", &a), ("b", &b)] {
        rig.put(&signer, BUCKET, key, bytes).await.expect(200);
    }
    // "ab": 6 MiB + 100 bytes in two extents.
    let id = create(&rig, &signer, "ab").await;
    let mut etags = Vec::new();
    for (n, key) in [(1, "a"), (2, "b")] {
        let r = part_copy(
            &rig,
            &signer,
            "ab",
            &id,
            n,
            &[("x-amz-copy-source", &source(key))],
        )
        .await;
        r.expect(200);
        etags.push(copied_etag(&r));
    }
    complete(&rig, &signer, "ab", &id, &etags).await.expect(200);

    let id = create(&rig, &signer, "dst").await;
    let src = source("ab");
    part_copy(&rig, &signer, "dst", &id, 1, &[("x-amz-copy-source", &src)])
        .await
        .expect_error(400, "EntityTooLarge");
    let over = format!("bytes=0-{}", 6 * MIB);
    part_copy(
        &rig,
        &signer,
        "dst",
        &id,
        1,
        &[
            ("x-amz-copy-source", &src),
            ("x-amz-copy-source-range", &over),
        ],
    )
    .await
    .expect_error(400, "EntityTooLarge");
    // Exactly the cap, across the extent boundary, is fine.
    let most = format!("bytes=100-{}", 6 * MIB + 99);
    let r = part_copy(
        &rig,
        &signer,
        "dst",
        &id,
        1,
        &[
            ("x-amz-copy-source", &src),
            ("x-amz-copy-source-range", &most),
        ],
    )
    .await;
    r.expect(200);
    let etag = copied_etag(&r);
    complete(&rig, &signer, "dst", &id, &[etag])
        .await
        .expect(200);
    assert_eq!(
        get(&rig, &signer, "dst").await.body,
        [&a[100..], &b[..]].concat()
    );
}
