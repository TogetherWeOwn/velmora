//! GetObject: only authenticated plaintext is served, from the cache, the
//! safety copy or a verified cold read, in that order.

mod nntp_support;
mod service_support;

use nntp_support::{TcpConnector, PASS, USER};
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use futures_util::future::LocalBoxFuture;
use futures_util::StreamExt;
use service_support::*;
use velmora::rng::SystemRng;
use velmora_bridge::crypto::{seal_extent, unwrap_bdk};
use velmora_bridge::fetch::{COLD_JITTER_MS, COLD_POLL_MS, COLD_WAIT_MS};
use velmora_bridge::ingress::{
    ByteBudget, Charge, Sleeper, Spawner, CHARGE_POLL_MS, CHARGE_WAIT_MS,
};
use velmora_bridge::metrics::{request_point, GetObservation, Request};
use velmora_bridge::service::PIECE_WAIT_MS;
use velmora_bridge::testkit::PublishUnrecorded;
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const BUCKET: &str = "bkt-get";

fn md5_etag(body: &[u8]) -> String {
    format!("\"{}\"", hex(&md5::compute(body).0))
}

async fn get<N: NntpConnector + 'static>(
    rig: &Rig<N>,
    signer: &Signer,
    key: &str,
    headers: &[(&str, &str)],
) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], headers, b"")
        .await
}

async fn get_range<N: NntpConnector + 'static>(
    rig: &Rig<N>,
    signer: &Signer,
    key: &str,
    range: &str,
) -> Resp {
    get(rig, signer, key, &[("range", range)]).await
}

async fn observed_get<N: NntpConnector + 'static>(
    rig: &Rig<N>,
    req: S3Request,
    stage: &str,
    size: &str,
) -> Resp {
    let mut get = GetObservation::default();
    let resp = Rc::clone(&rig.bridge).handle_observed(req, &mut get).await;
    let point = request_point(
        &Request {
            method: "GET",
            admin: false,
            sub: false,
            status: resp.status,
            latency_ms: 0,
            bytes_in: 0,
            bytes_out: 0,
            colo: "IAD",
            get,
        },
        1,
    );
    assert_eq!(
        point.analytics_blobs().skip(5).collect::<Vec<_>>(),
        [stage, size]
    );
    Resp::collect(resp).await
}

#[tokio::test(flavor = "current_thread")]
async fn get_catalogue_and_range_planning_failures_keep_their_error_responses() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let key = "object-lookup-fixture";
    rig.put(&signer, BUCKET, key, b"payload").await.expect(200);
    let (generation, _) = rig.live(&bucket, key).await.unwrap();
    let req = || {
        signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, key),
            &[],
            &[("range", "bytes=0-1")],
            Vec::new(),
        )
    };
    let sql = &rig.bridge.catalog.sql;
    *sql.fail_matching.borrow_mut() = Some(("FROM access_keys WHERE access_key_id", 0));
    observed_get(&rig, req().into_request(), "auth", "unknown")
        .await
        .expect_error(500, "InternalError");
    *sql.fail_matching.borrow_mut() = Some(("FROM objects o JOIN generations g", 0));
    observed_get(&rig, req().into_request(), "lookup", "unknown")
        .await
        .expect_error(500, "InternalError");
    sql.fail_matching.borrow_mut().take();

    // A two-byte range of a large object is classed by the object, not
    // by the Range header or the XML response's length.
    sql.inner
        .fixture_exec(
            "UPDATE generations SET size = ?1, content_json = 'null' WHERE id = ?2",
            &[
                SqlValue::Int((1_i64 << 30) + 1),
                SqlValue::Text(generation.id.as_str().into()),
            ],
        )
        .await
        .unwrap();
    observed_get(&rig, req().into_request(), "plan", "gt_1gib")
        .await
        .expect_error(500, "InternalError");

    let mut unsigned = req().into_request();
    unsigned
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("authorization"));
    observed_get(&rig, unsigned, "auth", "unknown")
        .await
        .expect(403);
}

/// Commits `parts` as one object of several extents, the way a completed
/// multipart upload leaves it, and returns the extents.
async fn commit_parts<N: NntpConnector + 'static>(
    rig: &Rig<N>,
    signer: &Signer,
    bucket: &Bucket,
    key: &str,
    parts: &[&[u8]],
) -> Vec<ExtentRow> {
    // A one-extent PUT supplies the row shapes.
    rig.put(signer, BUCKET, "template", b"t").await.expect(200);
    let (template, template_extents) = rig.live(bucket, "template").await.unwrap();
    let bridge = &rig.bridge;
    let bdk = unwrap_bdk(
        &bridge.kek,
        bucket.kek_version,
        &bucket.id,
        &bucket.bdk_wrapped,
    )
    .unwrap();
    let now = rig.now();
    let mut extents = Vec::new();
    let mut offset = 0u64;
    let mut whole = Vec::new();
    let generation_id = GenerationId::mint(now, [0xab; 8]);
    for (seq, part) in parts.iter().enumerate() {
        let id = ExtentId::mint([seq as u8 + 1; 13]);
        let sealed = seal_extent(&bdk, &bucket.id, &id, part, &mut SystemRng).unwrap();
        let row = ExtentRow {
            id: id.clone(),
            generation_id: Some(generation_id.clone()),
            seq: Some(seq as u32),
            plain_offset: Some(offset),
            plain_size: part.len() as u64,
            cipher_size: sealed.ciphertext.len() as u64,
            media_header: sealed.media_header.to_vec(),
            wrapped_file_key: Some(sealed.wrapped_file_key.to_vec()),
            plain_md5: sealed.plain_md5,
            plain_sha256: sealed.plain_sha256,
            cipher_sha256: sealed.cipher_sha256,
            ..template_extents[0].clone()
        };
        bridge
            .safety
            .put(
                &id.safety_key(),
                sealed.ciphertext,
                &BlobMeta {
                    bucket: &bucket.id,
                    extent: &id,
                    cipher_sha256: &row.cipher_sha256,
                },
            )
            .await
            .unwrap();
        offset += part.len() as u64;
        whole.extend_from_slice(part);
        extents.push(row);
    }
    let generation = GenerationRow {
        id: generation_id,
        key: key.to_owned(),
        size: offset,
        etag: md5_etag(&whole),
        extent_count: extents.len() as u32,
        ..template
    };
    bridge
        .catalog
        .publish(&CommitGeneration {
            generation,
            extents: extents.clone(),
            now,
        })
        .await
        .unwrap();
    extents
}

/// Copies an extent's safety blob into the cache.
async fn warm_cache<N: NntpConnector + 'static>(rig: &Rig<N>, bucket: &Bucket, extent: &ExtentRow) {
    let blob = rig.bridge.safety.stored(&extent.id.safety_key()).unwrap();
    rig.bridge
        .cache
        .put(
            &extent.id.cache_key(),
            blob.bytes,
            &BlobMeta {
                bucket: &bucket.id,
                extent: &extent.id,
                cipher_sha256: &extent.cipher_sha256,
            },
        )
        .await
        .unwrap();
}

async fn evict<N: NntpConnector + 'static>(rig: &Rig<N>, extent: &ExtentRow) {
    rig.bridge
        .cache
        .delete(&extent.id.cache_key())
        .await
        .unwrap();
    rig.bridge
        .safety
        .delete(&extent.id.safety_key())
        .await
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn put_get_round_trip() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(7, 300_000);
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "a/b.bin"),
        &[],
        &[
            ("content-type", "application/x-test"),
            ("x-amz-meta-origin", "unit test"),
        ],
        &body,
    )
    .await
    .expect(200);

    let resp = get(&rig, &signer, "a/b.bin", &[]).await;
    resp.expect(200);
    assert_eq!(resp.body, body);
    assert!(resp.stream_error.is_none());
    assert_eq!(resp.header("content-length"), Some("300000"));
    assert_eq!(resp.header("etag"), Some(md5_etag(&body).as_str()));
    assert_eq!(resp.header("content-type"), Some("application/x-test"));
    assert_eq!(resp.header("x-amz-meta-origin"), Some("unit test"));
    assert_eq!(
        resp.header("last-modified"),
        Some("Fri, 15 Jan 2027 08:00:00 GMT")
    );
    assert_eq!(rig.bridge.budget.in_use(), 0);

    // An empty object.
    rig.put(&signer, BUCKET, "empty", b"").await.expect(200);
    let resp = get(&rig, &signer, "empty", &[]).await;
    resp.expect(200);
    assert!(resp.body.is_empty());
    assert_eq!(resp.header("content-length"), Some("0"));

    // A key that was never written, and one that was deleted.
    get(&rig, &signer, "absent", &[])
        .await
        .expect_error(404, "NoSuchKey");
    rig.call(
        &signer,
        Method::Delete,
        &path(BUCKET, "a/b.bin"),
        &[],
        &[],
        b"",
    )
    .await
    .expect(204);
    get(&rig, &signer, "a/b.bin", &[])
        .await
        .expect_error(404, "NoSuchKey");
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_key_roundtrip() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys = [
        "with space/and more.txt",
        "plus+sign+key",
        "percent%25literal%zz",
        "ünïcödé/日本語/🙂.bin",
        "double//slash///key",
        "/leading-slash",
        "trailing/",
        "dots/../up/./here",
        "query?looking&key=1#frag",
    ];
    for (i, key) in keys.iter().enumerate() {
        rig.put(&signer, BUCKET, key, format!("body {i}").as_bytes())
            .await
            .expect(200);
    }
    // Every key reads back its own bytes, so no two collapsed together.
    for (i, key) in keys.iter().enumerate() {
        let resp = get(&rig, &signer, key, &[]).await;
        resp.expect(200);
        assert_eq!(resp.text(), format!("body {i}"), "{key}");
    }
    // Near misses are different keys.
    for near in [
        "with+space/and+more.txt",
        "plus sign key",
        "percent%literal%zz",
        "double/slash/key",
        "leading-slash",
        "trailing",
        "up/here",
    ] {
        get(&rig, &signer, near, &[])
            .await
            .expect_error(404, "NoSuchKey");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ranges_within_one_extent() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    // Several encryption chunks.
    let body = pattern(11, 400_000);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);

    for (range, start, end) in [
        ("bytes=0-0", 0usize, 0usize),
        ("bytes=10-19", 10, 19),
        ("bytes=65530-65545", 65_530, 65_545),
        ("bytes=131071-262144", 131_071, 262_144),
        ("bytes=399999-", 399_999, 399_999),
        ("bytes=-7", 399_993, 399_999),
        ("bytes=100-999999999", 100, 399_999),
        ("bytes=0-399999", 0, 399_999),
    ] {
        let resp = get_range(&rig, &signer, "k", range).await;
        resp.expect(206);
        assert_eq!(resp.body, body[start..=end], "{range}");
        assert_eq!(
            resp.header("content-range"),
            Some(format!("bytes {start}-{end}/400000").as_str()),
            "{range}"
        );
        assert_eq!(
            resp.header("content-length"),
            Some((end - start + 1).to_string().as_str())
        );
    }

    let resp = get_range(&rig, &signer, "k", "bytes=400000-").await;
    resp.expect_error(416, "InvalidRange");
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn ranges_across_extent_boundaries() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let parts = [pattern(1, 150_000), pattern(2, 70_001), pattern(3, 90_000)];
    let whole: Vec<u8> = parts.concat();
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    commit_parts(&rig, &signer, &bucket, "multi", &slices).await;

    let resp = get(&rig, &signer, "multi", &[]).await;
    resp.expect(200);
    assert!(resp.stream_error.is_none());
    assert_eq!(resp.body, whole);
    assert_eq!(resp.header("content-length"), Some("310001"));

    for (range, start, end) in [
        ("bytes=149999-150000", 149_999usize, 150_000usize), // first boundary
        ("bytes=149990-220010", 149_990, 220_010),           // all three
        ("bytes=150000-220000", 150_000, 220_000),           // exactly the middle
        ("bytes=220000-220001", 220_000, 220_001),           // second boundary
        ("bytes=0-149999", 0, 149_999),                      // exactly the first
        ("bytes=220001-", 220_001, 310_000),                 // exactly the last
        ("bytes=-100000", 210_001, 310_000),
    ] {
        let resp = get_range(&rig, &signer, "multi", range).await;
        resp.expect(206);
        assert!(resp.stream_error.is_none(), "{range}");
        assert_eq!(resp.body.len(), end - start + 1, "{range}");
        assert_eq!(resp.body, whole[start..=end], "{range}");
        assert_eq!(
            resp.header("content-range"),
            Some(format!("bytes {start}-{end}/310001").as_str())
        );
    }
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn read_conditions() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let etag = md5_etag(b"payload");

    let resp = get(&rig, &signer, "k", &[("if-none-match", &etag)]).await;
    resp.expect(304);
    assert!(resp.body.is_empty());
    get(&rig, &signer, "k", &[("if-match", &etag)])
        .await
        .expect(200);
    get(
        &rig,
        &signer,
        "k",
        &[("if-match", "\"00000000000000000000000000000000\"")],
    )
    .await
    .expect_error(412, "PreconditionFailed");
    get(
        &rig,
        &signer,
        "k",
        &[("if-modified-since", "Fri, 15 Jan 2027 08:00:00 GMT")],
    )
    .await
    .expect(304);
    get(
        &rig,
        &signer,
        "k",
        &[("if-unmodified-since", "Fri, 15 Jan 2027 07:59:59 GMT")],
    )
    .await
    .expect_error(412, "PreconditionFailed");
}

/// Every `cache-control` value of `resp`.
fn cache_controls(resp: &Resp) -> Vec<&str> {
    resp.headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("cache-control"))
        .map(|(_, v)| v.as_str())
        .collect()
}

/// The edge in front of the Worker compresses or rewrites text responses
/// and then drops `Content-Length` and drops or weakens `ETag`. Every
/// object answer (HEAD, GET, range GET, 304) is marked `no-transform`,
/// with the exact length and the strong ETag beside it.
#[tokio::test(flavor = "current_thread")]
async fn object_responses_forbid_edge_transforms() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    let html = b"<!doctype html><p>mail someone@example.com</p>".repeat(50);
    let etag = md5_etag(&html);
    let len = html.len().to_string();
    for (key, stored, served) in [
        ("plain.html", None, "no-transform"),
        ("cc.html", Some("max-age=60"), "max-age=60, no-transform"),
        ("nt.html", Some("no-transform"), "no-transform"),
    ] {
        let mut headers = vec![("content-type", "text/html")];
        headers.extend(stored.map(|v| ("cache-control", v)));
        rig.call(
            &signer,
            Method::Put,
            &path(BUCKET, key),
            &[],
            &headers,
            &html,
        )
        .await
        .expect(200);

        let head = rig.head(&signer, BUCKET, key).await;
        head.expect(200);
        assert_eq!(cache_controls(&head), [served], "HEAD {key}");
        assert_eq!(
            head.header("content-length"),
            Some(len.as_str()),
            "HEAD {key}"
        );
        assert_eq!(head.header("etag"), Some(etag.as_str()), "HEAD {key}");

        let resp = get(&rig, &signer, key, &[]).await;
        resp.expect(200);
        assert_eq!(resp.body, html);
        assert_eq!(cache_controls(&resp), [served], "GET {key}");
        assert_eq!(
            resp.header("content-length"),
            Some(len.as_str()),
            "GET {key}"
        );
        assert_eq!(resp.header("etag"), Some(etag.as_str()), "GET {key}");
        assert!(resp.header("content-encoding").is_none(), "GET {key}");

        let resp = get_range(&rig, &signer, key, "bytes=10-109").await;
        resp.expect(206);
        assert_eq!(resp.body, html[10..110]);
        assert_eq!(cache_controls(&resp), [served], "range GET {key}");
        assert_eq!(
            resp.header("content-length"),
            Some("100"),
            "range GET {key}"
        );
        assert_eq!(resp.header("etag"), Some(etag.as_str()), "range GET {key}");

        let resp = get(&rig, &signer, key, &[("if-none-match", &etag)]).await;
        resp.expect(304);
        assert_eq!(cache_controls(&resp), [served], "304 {key}");
        assert_eq!(resp.header("etag"), Some(etag.as_str()), "304 {key}");

        let resp = rig
            .call(
                &signer,
                Method::Head,
                &path(BUCKET, key),
                &[],
                &[("if-none-match", &etag)],
                b"",
            )
            .await;
        resp.expect(304);
        assert_eq!(cache_controls(&resp), [served], "HEAD 304 {key}");
        assert_eq!(resp.header("etag"), Some(etag.as_str()), "HEAD 304 {key}");
    }

    // Other content types are marked too; an empty object as well.
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "data.json"),
        &[],
        &[("content-type", "application/json")],
        b"{\"k\":1}",
    )
    .await
    .expect(200);
    rig.put(&signer, BUCKET, "empty", b"").await.expect(200);
    for key in ["data.json", "empty"] {
        let head = rig.head(&signer, BUCKET, key).await;
        head.expect(200);
        assert_eq!(cache_controls(&head), ["no-transform"], "HEAD {key}");
        let resp = get(&rig, &signer, key, &[]).await;
        resp.expect(200);
        assert_eq!(cache_controls(&resp), ["no-transform"], "GET {key}");
    }
}

/// Every object response carries nosniff and a sandbox policy, whatever the
/// object's stored type: an object is never a page of the host that serves it.
#[tokio::test(flavor = "current_thread")]
async fn object_responses_are_sandboxed_and_unsniffed() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    for (key, content_type, disposition, body) in [
        (
            "page.html",
            Some("text/html"),
            None,
            b"<script>alert(1)</script>".as_slice(),
        ),
        ("image.svg", Some("image/svg+xml"), None, b"<svg/>"),
        ("untyped", None, None, b"data"),
        ("inline", None, Some("inline"), b"data"),
    ] {
        let mut headers = Vec::new();
        headers.extend(content_type.map(|v| ("content-type", v)));
        headers.extend(disposition.map(|v| ("content-disposition", v)));
        rig.call(
            &signer,
            Method::Put,
            &path(BUCKET, key),
            &[],
            &headers,
            body,
        )
        .await
        .expect(200);

        let head = rig.head(&signer, BUCKET, key).await;
        let resp = get(&rig, &signer, key, &[]).await;
        let range = get_range(&rig, &signer, key, "bytes=0-3").await;
        let etag = md5_etag(body);
        let conditional = get(&rig, &signer, key, &[("if-none-match", &etag)]).await;
        for (request, response, status) in [
            ("HEAD", head, 200),
            ("GET", resp, 200),
            ("range GET", range, 206),
            ("conditional GET", conditional, 304),
        ] {
            response.expect(status);
            for (name, value) in [
                ("x-content-type-options", "nosniff"),
                ("content-security-policy", "sandbox"),
            ] {
                let values: Vec<_> = response
                    .headers
                    .iter()
                    .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
                    .collect();
                assert_eq!(values, [value], "{request} {key}: {name}");
            }
            if status != 304 {
                assert_eq!(
                    response.header("content-type"),
                    content_type,
                    "{request} {key}"
                );
                assert_eq!(
                    response.header("content-disposition"),
                    disposition,
                    "{request} {key}"
                );
            }
        }
    }

    let missing = get(&rig, &signer, "missing", &[]).await;
    missing.expect_error(404, "NoSuchKey");
    assert!(missing.header("content-security-policy").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn cache_is_tried_before_the_safety_copy() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(5, 200_000);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);
    let (_, extents) = rig.live(&bucket, "k").await.unwrap();
    let extent = &extents[0];

    // With only the cache copy left, the read still succeeds.
    warm_cache(&rig, &bucket, extent).await;
    rig.bridge
        .safety
        .delete(&extent.id.safety_key())
        .await
        .unwrap();
    let resp = get(&rig, &signer, "k", &[]).await;
    resp.expect(200);
    assert_eq!(resp.body, body);
    let resp = get_range(&rig, &signer, "k", "bytes=70000-140000").await;
    assert_eq!(resp.expect(206).body, body[70_000..=140_000]);
}

#[tokio::test(flavor = "current_thread")]
async fn tampered_copy_is_never_served() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(9, 200_000);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);
    let (_, extents) = rig.live(&bucket, "k").await.unwrap();
    let extent = &extents[0];
    warm_cache(&rig, &bucket, extent).await;

    // A flipped bit in the cache copy: the safety copy answers instead.
    assert!(rig
        .bridge
        .cache
        .corrupt(&extent.id.cache_key(), |b| b[1000] ^= 1));
    let resp = get(&rig, &signer, "k", &[]).await;
    resp.expect(200);
    assert_eq!(resp.body, body);
    let resp = get_range(&rig, &signer, "k", "bytes=0-99").await;
    assert_eq!(resp.expect(206).body, body[..100]);

    // A truncated cache copy is a miss as well.
    assert!(rig
        .bridge
        .cache
        .corrupt(&extent.id.cache_key(), |b| b.truncate(500)));
    assert_eq!(get(&rig, &signer, "k", &[]).await.expect(200).body, body);

    // Both copies tampered and nothing posted: an error, never the bytes.
    assert!(rig
        .bridge
        .safety
        .corrupt(&extent.id.safety_key(), |b| b[1000] ^= 1));
    let resp = get(&rig, &signer, "k", &[]).await;
    resp.expect_error(503, "ServiceUnavailable");
    assert_eq!(
        resp.message(),
        "The object cannot be read right now. Please try again."
    );
    assert!(resp.header("retry-after").is_some());
    // A range that avoids the damaged chunk still authenticates.
    let resp = get_range(&rig, &signer, "k", "bytes=199000-199999").await;
    assert_eq!(resp.expect(206).body, body[199_000..]);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_later_extent_that_cannot_be_read_ends_the_stream_with_an_error() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let parts = [pattern(1, 100_000), pattern(2, 100_000)];
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let extents = commit_parts(&rig, &signer, &bucket, "multi", &slices).await;

    evict(&rig, &extents[1]).await;
    let resp = get(&rig, &signer, "multi", &[]).await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.stream_error.is_some(),
        "the stream must end in an error"
    );
    assert_eq!(resp.body, parts[0], "only verified bytes were sent");
    assert_eq!(resp.header("content-length"), Some("200000"));

    // When the first extent is the unreadable one, the status says so.
    let resp = get_range(&rig, &signer, "multi", "bytes=100000-100009").await;
    resp.expect_error(503, "ServiceUnavailable");
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn full_budget_is_slow_down() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let _held = rig
        .bridge
        .budget
        .try_charge(rig.bridge.cfg.inflight_budget_bytes)
        .unwrap();
    let resp = get(&rig, &signer, "k", &[]).await;
    resp.expect_error(503, "SlowDown");
    assert!(resp.header("retry-after").is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn unread_body_stays_charged_to_the_budget() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let parts = [pattern(1, 100_000), pattern(2, 60_000)];
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    commit_parts(&rig, &signer, &bucket, "multi", &slices).await;
    rig.put(&signer, BUCKET, "single", &parts[0])
        .await
        .expect(200);
    let budget = &rig.bridge.budget;
    let open = |key: &str, range: Option<&str>| {
        let headers: Vec<(&str, &str)> = range.iter().map(|r| ("range", *r)).collect();
        let req = signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, key),
            &[],
            &headers,
            Vec::new(),
        );
        Rc::clone(&rig.bridge).handle(req.into_request())
    };

    // One extent: the plaintext waiting to be pulled is charged, exactly.
    let resp = open("single", None).await;
    assert_eq!(resp.status, 200);
    assert_eq!(budget.in_use(), 100_000);
    let RespBody::Stream(mut body) = resp.body else {
        panic!("a GET body is a stream");
    };
    assert_eq!(body.next().await.unwrap().unwrap(), parts[0]);
    assert_eq!(budget.in_use(), 0, "released once the bytes are pulled");
    assert!(body.next().await.is_none());

    // A range holds only the range.
    let resp = open("single", Some("bytes=10-19")).await;
    assert_eq!(budget.in_use(), 10);
    drop(resp);
    assert_eq!(budget.in_use(), 0, "released when the body is dropped");

    // Several extents: only the piece that is ready is held, one at a time.
    let resp = open("multi", None).await;
    assert_eq!(budget.in_use(), 100_000);
    let RespBody::Stream(mut body) = resp.body else {
        panic!("a GET body is a stream");
    };
    assert_eq!(body.next().await.unwrap().unwrap(), parts[0]);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(body.next().await.unwrap().unwrap(), parts[1]);
    assert_eq!(budget.in_use(), 0);
    assert!(body.next().await.is_none());

    // Unread bodies count against later requests.
    let held: Vec<_> = [open("single", None).await, open("multi", None).await]
        .into_iter()
        .collect();
    assert_eq!(budget.in_use(), 200_000);
    let _rest = budget.try_charge(rig.bridge.cfg.inflight_budget_bytes - 200_000 - 1);
    assert!(_rest.is_some());
    get(&rig, &signer, "single", &[])
        .await
        .expect_error(503, "SlowDown");
    drop(held);
    drop(_rest);
    assert_eq!(budget.in_use(), 0);
    get(&rig, &signer, "single", &[]).await.expect(200);
}

// ---------------------------------------------------------------------------
// Cold reads
// ---------------------------------------------------------------------------

struct Cold {
    rig: Rig<TcpConnector>,
    server: TestNntpServer,
    bucket: Bucket,
    signer: Signer,
}

fn provider(server: &TestNntpServer) -> ProviderConfig {
    provider_at(server.addr())
}

fn provider_at(addr: std::net::SocketAddr) -> ProviderConfig {
    ProviderConfig {
        id: "p0".to_string(),
        host: addr.ip().to_string(),
        hosts: Vec::new(),
        host_select: Default::default(),
        port: addr.port(),
        tls: false,
        user: USER.to_string(),
        pass: PASS.to_string(),
        backbone: "alpha".to_string(),
        post: true,
        read: true,
        max_conns: 2,
        max_ips: None,
        drill_conns: 0,
        priority: 0,
        retention_days: None,
        pool: None,
        pool_max_conns: None,
        proxies: Vec::new(),
        enabled: true,
        release: true,
    }
}

#[tokio::test]
async fn frozen_get_refuses_cold_extents_before_headers_or_writes() {
    use velmora_bridge::gate::{
        GateClient, GateReply, GateRequest, GateSession, GateSharding, GateTransport, PermitMode,
    };
    use velmora_bridge::sql::SqlCatalog;

    struct FrozenGate(Rc<Cell<u32>>);
    enum NoGateSession {}
    impl GateSession for NoGateSession {
        async fn call(&self, _: GateRequest) -> Result<GateReply> {
            match *self {}
        }
        fn close(&self) {
            match *self {}
        }
    }
    impl GateTransport for FrozenGate {
        type Session = NoGateSession;
        async fn open(&self, _: GateRequest) -> Result<(NoGateSession, GateReply)> {
            self.0.set(self.0.get() + 1);
            Err(BridgeError::Sql("catalog: frozen".into()))
        }
        async fn call(&self, _: GateRequest) -> Result<GateReply> {
            panic!("a frozen GET must not call the gate")
        }
    }

    // A seeded plan and an active DO client are enough to exercise the
    // permit failure. No fixture server or NNTP socket is needed.
    let mut cfg = config(vec![provider_at("127.0.0.1:9".parse().unwrap())]);
    // The mixed request would ordinarily fan out, the single cold one would not.
    cfg.get_fanout_bytes = Some(4);
    let rig = rig_with(NoNntp, cfg);
    let bridge = Rc::try_unwrap(rig.bridge).ok().unwrap();
    let gate_calls = Rc::new(Cell::new(0));
    let gate = GateClient::new(
        FrozenGate(gate_calls.clone()),
        || T0,
        PermitMode::Gate,
        GateSharding::Account,
        1,
        &bridge.cfg.providers,
    )
    .into_gate();
    let rig = Rig {
        bridge: Rc::new(Bridge {
            catalog: SqlCatalog::with_gate(bridge.catalog.sql, gate),
            ..bridge
        }),
    };
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "cold", b"cold").await.expect(200);
    let (generation, extents) = rig.live(&bucket, "cold").await.unwrap();
    let extent = &extents[0];
    let lease = rig
        .bridge
        .catalog
        .claim(
            &extent.id,
            &generation.id,
            OutboxStage::Post,
            "fixture",
            rig.now(),
        )
        .await
        .unwrap()
        .unwrap();
    rig.bridge
        .catalog
        .plan_articles(
            &lease,
            &[ArticleRow {
                extent_id: extent.id.clone(),
                idx: 0,
                message_id: "test@example.invalid".into(),
                newsgroup: "alt.binaries.test".into(),
                headers: vec![],
                cipher_offset: 0,
                cipher_len: extent.cipher_size,
                payload_sha256: extent.cipher_sha256,
                yenc_name: None,
                state: ArticleState::Planned,
                provider_id: None,
                posted_at: None,
                reposted_at: None,
            }],
        )
        .await
        .unwrap()
        .unwrap();
    rig.bridge
        .catalog
        .mark_posted(&lease, 0, "p0", rig.now())
        .await
        .unwrap();
    evict(&rig, extent).await;

    let mixed = commit_parts(&rig, &signer, &bucket, "mixed", &[b"warm", b"missing"]).await;
    warm_cache(&rig, &bucket, &mixed[0]).await;
    evict(&rig, &mixed[1]).await;
    let sql = &rig.bridge.catalog.sql;
    sql.frozen.set(true);
    let safety_puts = rig.bridge.safety.puts.borrow().len();
    let cache_puts = rig.bridge.cache.puts.borrow().len();
    for key in ["cold", "mixed"] {
        let response = get(&rig, &signer, key, &[]).await;
        assert_eq!(response.status, 503, "{key}: {}", response.text());
        assert_eq!(response.code(), "ServiceUnavailable");
        assert_eq!(
            response
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                .count(),
            1
        );
    }
    let warm = get_range(&rig, &signer, "mixed", "bytes=0-3").await;
    assert_eq!(warm.status, 206);
    assert_eq!(warm.body, b"warm");
    assert_eq!(gate_calls.get(), 0);
    assert_eq!(sql.frozen_write_attempts.get(), 0);
    assert_eq!(rig.bridge.safety.puts.borrow().len(), safety_puts);
    assert_eq!(rig.bridge.cache.puts.borrow().len(), cache_puts);
}

#[tokio::test]
async fn frozen_warm_get_skips_a_due_hot_hit_flush() {
    let mut cfg = config(Vec::new());
    cfg.hot_ctl.mode = velmora_bridge::config::HotCtlMode::Shadow;
    let rig = rig_with(NoNntp, cfg);
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "hot", b"hot").await.expect(200);
    let sql = &rig.bridge.catalog.sql;
    let flushes = Rc::new(RefCell::new(Vec::new()));
    let spawner: Spawner = {
        let flushes = Rc::clone(&flushes);
        Rc::new(move |work| flushes.borrow_mut().push(work))
    };
    // The first hit on this test thread would flush immediately. Run the
    // identical request unfrozen afterwards to prove the flush was due.
    for frozen in [true, false] {
        sql.frozen.set(frozen);
        let req = signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "hot"),
            &[],
            &[],
            vec![],
        );
        let resp = Rc::clone(&rig.bridge)
            .handle_observed_with_hit_flush(
                req.into_request(),
                &mut Default::default(),
                Some(Rc::clone(&spawner)),
            )
            .await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut stream) = resp.body else {
            panic!("expected the warm body");
        };
        assert_eq!(stream.next().await.unwrap().unwrap(), b"hot");
        assert!(stream.next().await.is_none());
        assert_eq!(flushes.borrow().len(), usize::from(!frozen));
        assert_eq!(sql.frozen_write_attempts.get(), 0);
    }
}

#[tokio::test]
async fn frozen_test_catalogue_refuses_writes_sent_as_queries() {
    let rig = rig();
    let sql = &rig.bridge.catalog.sql;
    sql.frozen.set(true);
    let before = sql.query("SELECT ok FROM tx_guard", &[]).await.unwrap();
    let err = sql
        .query(
            "WITH value(ok) AS (SELECT 1) INSERT INTO tx_guard(ok) SELECT ok FROM value RETURNING ok",
            &[],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Sql(message) if message == "catalog: frozen"));
    assert_eq!(sql.frozen_write_attempts.get(), 1);
    assert_eq!(
        sql.query("SELECT ok FROM tx_guard", &[]).await.unwrap(),
        before
    );
}

#[tokio::test]
async fn frozen_revocation_does_not_leave_a_durable_record() {
    use velmora_bridge::config::Maintenance;
    use velmora_bridge::recovery::revocation_recorded;
    let mut rig = rig();
    let _ = rig.standard(BUCKET).await;
    Rc::get_mut(&mut rig.bridge).unwrap().cfg.maintenance = Maintenance::Restore;
    let sql = &rig.bridge.catalog.sql;
    sql.frozen.set(true);
    let revoke = || S3Request {
        method: Method::Delete,
        raw_target: format!("/_admin/keys/{AKID}"),
        headers: vec![(
            "authorization".into(),
            format!("Bearer {}", rig.bridge.cfg.admin_token.expose()),
        )],
        body: Body::Empty,
    };
    let response = Rc::clone(&rig.bridge).handle(revoke()).await;
    assert!(
        !revocation_recorded(&rig.bridge.safety, AKID).await.unwrap(),
        "frozen revocation left its record (HTTP {})",
        response.status
    );
    assert_eq!(response.status, 503);
    assert_eq!(sql.frozen_write_attempts.get(), 0);
    assert!(rig.bridge.catalog.access_key_exists(AKID).await.unwrap());

    // Restore maintenance alone intentionally still permits revocation.
    sql.frozen.set(false);
    assert_eq!(Rc::clone(&rig.bridge).handle(revoke()).await.status, 204);
    assert!(revocation_recorded(&rig.bridge.safety, AKID).await.unwrap());
    assert!(!rig.bridge.catalog.access_key_exists(AKID).await.unwrap());
}

async fn cold_rig() -> Cold {
    cold_rig_with(2, None).await
}

/// A cold-read rig whose provider allows `max_conns` connections and whose
/// byte budget polls with `sleeper` (none: nothing ever waits).
async fn cold_rig_with(max_conns: u32, sleeper: Option<Sleeper>) -> Cold {
    cold_rig_on(max_conns, sleeper, None).await
}

/// The same, on a host that runs the body of a GET as a task of its own
/// when there is a `spawner`.
async fn cold_rig_on(max_conns: u32, sleeper: Option<Sleeper>, spawner: Option<Spawner>) -> Cold {
    let mut server_cfg = ServerConfig::for_test();
    server_cfg.articles = Vec::new();
    server_cfg.missing_ids.clear();
    server_cfg.users.insert(
        USER.to_string(),
        UserConfig {
            password: PASS.to_string(),
            max_connections: 4,
        },
    );
    let server = TestNntpServer::spawn(server_cfg).await;
    let mut p = provider(&server);
    p.max_conns = max_conns;
    let cfg = config(vec![p]);
    let mut budget = ByteBudget::new(cfg.inflight_budget_bytes);
    if let Some(sleeper) = sleeper {
        budget = budget.with_sleeper(sleeper);
    }
    if let Some(spawner) = spawner {
        budget = budget.with_spawner(spawner);
    }
    let rig = rig_with_budget_selected(TcpConnector::default(), cfg, budget);
    rig.bridge
        .catalog
        .seed_permits(&rig.bridge.cfg.providers)
        .await
        .unwrap();
    let (bucket, signer) = rig.standard(BUCKET).await;
    Cold {
        rig,
        server,
        bucket,
        signer,
    }
}

impl Cold {
    /// PUTs `body` and runs the posting stage for its extent.
    async fn put_and_post(&self, key: &str, body: &[u8]) -> ExtentRow {
        let rig = &self.rig;
        rig.put(&self.signer, BUCKET, key, body).await.expect(200);
        let (generation, extents) = rig.live(&self.bucket, key).await.unwrap();
        let extent = extents.into_iter().next().unwrap();
        self.post(&generation.id, &extent).await;
        extent
    }

    /// Runs the posting stage for one extent of a committed generation.
    async fn post(&self, generation: &GenerationId, extent: &ExtentRow) {
        let rig = &self.rig;
        let catalog = &rig.bridge.catalog;
        let lease = catalog
            .claim(
                &extent.id,
                generation,
                OutboxStage::Post,
                "test-worker",
                rig.now(),
            )
            .await
            .unwrap()
            .expect("the commit left a claimable posting obligation");
        let job = catalog
            .job_extent(&extent.id, generation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rig.bridge.post_stage(&lease, &job).await, JobOutcome::Ack);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cold_read_refills_the_cache_from_usenet() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    // Three articles.
    let body = pattern(13, 1_500_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    assert_eq!(cold.server.posted_count().await, 3);

    evict(rig, &extent).await;
    assert!(rig.bridge.cache.keys().is_empty());
    assert!(rig.bridge.safety.keys().iter().all(|k| k.starts_with("m/")));
    let connects = rig.bridge.nntp.connects();

    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect(200);
    assert!(resp.body == body, "cold read returned other bytes");
    // Every slot the provider has (two) was used, under four sockets.
    assert_eq!(rig.bridge.nntp.connects(), connects + 2);
    assert_eq!(rig.bridge.nntp.live(), 0);

    // The verified ciphertext is now in the cache, and only there.
    let cached = rig.bridge.cache.stored(&extent.id.cache_key()).unwrap();
    assert_eq!(sha256(&cached.bytes), extent.cipher_sha256);
    assert!(rig.bridge.safety.keys().iter().all(|k| k.starts_with("m/")));

    // The next reads are served from the cache without a session.
    let resp = get_range(rig, &cold.signer, "cold.bin", "bytes=999990-1000009").await;
    assert_eq!(resp.expect(206).body, body[999_990..=1_000_009]);
    assert!(get(rig, &cold.signer, "cold.bin", &[]).await.body == body);
    assert_eq!(rig.bridge.nntp.connects(), connects + 2);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// An object of several extents on Usenet only: every extent posted and
/// evicted, except those of `keep` (left in the cache) and of `lost`
/// (evicted without ever being posted).
async fn cold_parts(
    cold: &Cold,
    key: &str,
    parts: &[Vec<u8>],
    keep: &[usize],
    lost: &[usize],
) -> Vec<ExtentRow> {
    let rig = &cold.rig;
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let extents = commit_parts(rig, &cold.signer, &cold.bucket, key, &slices).await;
    for (i, extent) in extents.iter().enumerate() {
        if !lost.contains(&i) {
            cold.post(extent.generation_id.as_ref().unwrap(), extent)
                .await;
        }
        if !keep.contains(&i) {
            evict(rig, extent).await;
        }
    }
    extents
}

fn cached(rig: &Rig<TcpConnector>, extent: &ExtentRow) -> bool {
    rig.bridge
        .cache
        .stored(&extent.id.cache_key())
        .is_some_and(|blob| sha256(&blob.bytes) == extent.cipher_sha256)
}

/// A body of several cold extents is read over one set of connections
/// where it is produced ahead of its reader, and every extent is in the
/// cache when the body ends.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_body_keeps_its_connections_from_extent_to_extent() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        // Two articles each.
        let parts = [
            pattern(71, 1_000_000),
            pattern(72, 900_000),
            pattern(73, 1_100_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
        assert!(rig.bridge.cache.keys().is_empty());
        let connects = rig.bridge.nntp.connects();

        let resp = get(rig, &cold.signer, "multi", &[]).await;
        resp.expect(200);
        assert!(resp.stream_error.is_none(), "{:?}", resp.stream_error);
        assert!(resp.body == parts.concat());
        // Both slots of the provider, once: not once per extent.
        assert_eq!(rig.bridge.nntp.connects(), connects + 2);
        assert_eq!(rig.bridge.nntp.live(), 0);
        assert!(extents.iter().all(|e| cached(rig, e)));
        assert_eq!(rig.bridge.budget.in_use(), 0);
    };
    local.run_until(test).await;
}

/// Where the body runs only while its reader asks, nobody watches the
/// time between two pieces: the connections are ended before each piece
/// is handed over, so none sits idle on a slot that runs out.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_body_read_on_demand_keeps_no_connection_between_pieces() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let parts = [
        pattern(71, 1_000_000),
        pattern(72, 900_000),
        pattern(73, 1_100_000),
    ];
    let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
    let connects = rig.bridge.nntp.connects();

    let resp = get(rig, &cold.signer, "multi", &[]).await;
    resp.expect(200);
    assert!(resp.stream_error.is_none(), "{:?}", resp.stream_error);
    assert!(resp.body == parts.concat());
    assert_eq!(rig.bridge.nntp.connects(), connects + 6);
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert!(extents.iter().all(|e| cached(rig, e)));
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// An extent that is in the cache, between two that are not, ends the
/// connections: they are not kept idle past their slots.
#[tokio::test(flavor = "current_thread")]
async fn a_warm_extent_ends_the_connections_of_a_cold_body() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let parts = [
        pattern(74, 1_000_000),
        pattern(75, 100_000),
        pattern(76, 1_000_000),
    ];
    let extents = cold_parts(&cold, "multi", &parts, &[1], &[]).await;
    let connects = rig.bridge.nntp.connects();

    let resp = get(rig, &cold.signer, "multi", &[]).await;
    resp.expect(200);
    assert!(resp.stream_error.is_none(), "{:?}", resp.stream_error);
    assert!(resp.body == parts.concat());
    assert_eq!(rig.bridge.nntp.connects(), connects + 4);
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert!(cached(rig, &extents[0]) && cached(rig, &extents[2]));
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// The piece handed over is charged until it is pulled, and nothing
/// else is: its ciphertext went to the cache beside the hand-over. No
/// connection is open while a piece waits for a reader that nobody
/// watches. The last piece comes after its cache write; a body that is
/// dropped gives everything back.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_body_holds_one_piece_and_no_connection_while_it_waits() {
    tokio::task::LocalSet::new()
        .run_until(cold_body_waits_for_reader())
        .await;
}

async fn cold_body_waits_for_reader() {
    // Without a spawner, this producer is only polled by the reader, so
    // waiting after the headers cannot finish its outstanding cache write.
    // A spawner without a sleeper lets the write finish but does not enable
    // read-ahead: the producer settles and waits for the next pull.
    let cold = cold_rig_on(2, None, Some(local_spawner())).await;
    let rig = &cold.rig;
    let parts = [
        pattern(77, 300_000),
        pattern(78, 200_000),
        pattern(79, 250_000),
    ];
    let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
    let budget = &rig.bridge.budget;
    let settle = |piece_bytes| async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if budget.in_use() <= piece_bytes
                    && rig.bridge.nntp.live() == 0
                    && free_slots(rig).await == 2
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cache write, connections, and slots settle before the next pull");
    };
    let open = || {
        let req = cold.signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "multi"),
            &[],
            &[],
            Vec::new(),
        );
        Rc::clone(&rig.bridge).handle(req.into_request())
    };

    let resp = open().await;
    assert_eq!(resp.status, 200);
    settle(300_000).await;
    assert_eq!(budget.in_use(), 300_000);
    assert!(cached(rig, &extents[0]) && !cached(rig, &extents[1]));
    assert_eq!(rig.bridge.nntp.live(), 0, "no connection sits idle");
    assert_eq!(free_slots(rig).await, 2);
    let RespBody::Stream(mut body) = resp.body else {
        panic!("a GET body is a stream");
    };
    assert_eq!(body.next().await.unwrap().unwrap(), parts[0]);
    assert_eq!(budget.in_use(), 0);
    assert!(
        !cached(rig, &extents[1]),
        "nothing is read ahead of the pull"
    );

    assert_eq!(body.next().await.unwrap().unwrap(), parts[1]);
    settle(0).await;
    assert!(cached(rig, &extents[1]) && !cached(rig, &extents[2]));
    assert_eq!(rig.bridge.nntp.live(), 0);

    // The last piece: nothing is left to do after it.
    assert_eq!(body.next().await.unwrap().unwrap(), parts[2]);
    assert!(extents.iter().all(|e| cached(rig, e)));
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert_eq!(budget.in_use(), 0);
    assert!(body.next().await.is_none());

    // A reader that goes away after the first piece.
    for extent in &extents {
        evict(rig, extent).await;
    }
    let resp = open().await;
    let RespBody::Stream(mut body) = resp.body else {
        panic!("a GET body is a stream");
    };
    assert_eq!(body.next().await.unwrap().unwrap(), parts[0]);
    drop(body);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(rig.bridge.nntp.live(), 0);
    // Its slots are free again at the latest when they expire; the next
    // read does not depend on them.
    rig.bridge.clock.advance_secs(60);
    let resp = get(rig, &cold.signer, "multi", &[]).await;
    assert!(resp.expect(200).body == parts.concat());
}

/// With room for one extent and no more, the body is read all the same:
/// each cache write ends before the next extent is read.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_body_without_room_beside_the_cache_write_reads_one_extent_at_a_time() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let parts = [
        pattern(80, 300_000),
        pattern(81, 300_000),
        pattern(82, 300_000),
    ];
    let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
    let step = extents
        .iter()
        .map(|e| velmora_bridge::fetch::cold_step_bytes(e.cipher_size, rig.bridge.cfg.cold_sockets))
        .max()
        .unwrap();
    let held = rig
        .bridge
        .budget
        .try_charge(rig.bridge.cfg.inflight_budget_bytes - step)
        .unwrap();

    let resp = get(rig, &cold.signer, "multi", &[]).await;
    resp.expect(200);
    assert!(resp.stream_error.is_none(), "{:?}", resp.stream_error);
    assert!(resp.body == parts.concat());
    assert!(extents.iter().all(|e| cached(rig, e)));
    drop(held);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// A later extent that Usenet does not have ends the body with an error
/// after the bytes before it. What was read is in the cache, and the
/// connections are ended before the error is handed over.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_body_that_fails_leaves_the_cache_what_it_read_and_no_connection() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let parts = [
        pattern(83, 300_000),
        pattern(84, 300_000),
        pattern(85, 300_000),
    ];
    let extents = cold_parts(&cold, "multi", &parts, &[], &[1]).await;

    let resp = get(rig, &cold.signer, "multi", &[]).await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.stream_error.is_some(),
        "the stream must end in an error"
    );
    assert!(resp.body == parts[0], "only verified bytes were sent");
    assert!(cached(rig, &extents[0]));
    assert!(!cached(rig, &extents[1]) && !cached(rig, &extents[2]));
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// Spawns on the `LocalSet` the test runs in.
fn local_spawner() -> Spawner {
    Rc::new(|task| {
        tokio::task::spawn_local(task);
    })
}

/// On a host that can spawn, the body is produced by a task beside its
/// reader: the bytes, the cache and what is held at the end are the same.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_body_produced_by_a_task_is_the_same_body() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, None, Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [
            pattern(91, 1_000_000),
            pattern(92, 900_000),
            pattern(93, 1_100_000),
            pattern(94, 300_000),
        ];
        // The third still has a copy, the others are on Usenet only.
        let extents = cold_parts(&cold, "multi", &parts, &[2], &[]).await;

        let resp = get(rig, &cold.signer, "multi", &[]).await;
        resp.expect(200);
        assert!(resp.stream_error.is_none(), "{:?}", resp.stream_error);
        assert!(resp.body == parts.concat());
        for (i, extent) in extents.iter().enumerate() {
            // The third was served from the copy it had.
            assert!(i == 2 || cached(rig, extent));
        }
        assert_eq!(rig.bridge.nntp.live(), 0);
        assert_eq!(rig.bridge.budget.in_use(), 0);

        // A range that begins inside one extent and ends inside another.
        for extent in &extents {
            evict(rig, extent).await;
        }
        let resp = get_range(rig, &cold.signer, "multi", "bytes=999990-1900009").await;
        resp.expect(206);
        assert!(resp.body == parts.concat()[999_990..1_900_010]);
    };
    local.run_until(test).await;
}

/// The task runs one piece ahead of its reader and no further, and a
/// body that is dropped takes the task's work along at once: nothing
/// stays charged for a client that went away.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_body_produced_by_a_task_stops_with_its_reader() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [
            pattern(95, 300_000),
            pattern(96, 300_000),
            pattern(97, 300_000),
            pattern(98, 300_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
        let req = cold.signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "multi"),
            &[],
            &[],
            Vec::new(),
        );
        let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut body) = resp.body else {
            panic!("a GET body is a stream");
        };
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        // The reader is away: the task goes on to the second piece and
        // stays there.
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            if cached(rig, &extents[1]) {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(cached(rig, &extents[0]) && cached(rig, &extents[1]));
        assert!(!cached(rig, &extents[2]), "one piece ahead, not two");
        assert_eq!(
            rig.bridge.budget.in_use(),
            parts[1].len() as u64,
            "the piece that waits is charged"
        );
        drop(body);
        assert_eq!(rig.bridge.budget.in_use(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!cached(rig, &extents[2]) && !cached(rig, &extents[3]));
    };
    local.run_until(test).await;
}

/// Polls until `done` holds, for two seconds at most.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    for _ in 0..400 {
        if done() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("never happened: {what}");
}

/// A piece that was produced ahead and is not taken in time is taken
/// back: a reader that stalls holds none of the byte budget and no
/// provider slot, and nothing more is read for it. When it asks again,
/// the piece is produced again and the body is the same.
#[tokio::test(flavor = "current_thread")]
async fn a_piece_that_waits_too_long_is_taken_back_and_produced_again() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        // The wait for the reader is 20 ms here; the other timers take
        // the time they say.
        let sleeper = timed_sleeper(|ms| match ms == PIECE_WAIT_MS {
            true => 20,
            false => ms.into(),
        });
        let mut cold = cold_rig_on(2, Some(sleeper), Some(local_spawner())).await;
        Rc::get_mut(&mut cold.rig.bridge).unwrap().cfg.hot_ctl.mode =
            velmora_bridge::config::HotCtlMode::Shadow;
        let hit_flushes = Rc::new(RefCell::new(Vec::new()));
        let flush: Spawner = {
            let hit_flushes = Rc::clone(&hit_flushes);
            Rc::new(move |work| hit_flushes.borrow_mut().push(work))
        };
        let rig = &cold.rig;
        let parts = [
            pattern(101, 300_000),
            pattern(102, 300_000),
            pattern(103, 300_000),
            pattern(104, 300_000),
            pattern(111, 300_000),
            pattern(112, 300_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
        let req = cold.signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "multi"),
            &[],
            &[],
            Vec::new(),
        );
        let resp = Rc::clone(&rig.bridge)
            .handle_observed_with_hit_flush(
                req.into_request(),
                &mut Default::default(),
                Some(flush),
            )
            .await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut body) = resp.body else {
            panic!("a GET body is a stream");
        };
        // The answer holds the first piece. The reader stalls before
        // it takes that one, and again later.
        let mut next = 0;
        for (ahead, held) in [(1, parts[0].len() as u64), (3, 0)] {
            eventually("the piece is taken back", || {
                cached(rig, &extents[ahead])
                    && rig.bridge.budget.in_use() == held
                    && rig.bridge.nntp.live() == 0
            })
            .await;
            assert_eq!(free_slots(rig).await, 2);
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            assert_eq!(rig.bridge.budget.in_use(), held);
            assert!(
                !cached(rig, &extents[ahead + 1]),
                "nothing is read for a reader that is away"
            );
            // It takes all there is, and one more that it waits for.
            while next <= ahead {
                assert!(body.next().await.unwrap().unwrap() == parts[next]);
                next += 1;
            }
            assert!(body.next().await.unwrap().unwrap() == parts[next]);
            next += 1;
        }
        for part in &parts[next..] {
            assert!(body.next().await.unwrap().unwrap() == *part);
        }
        assert!(body.next().await.is_none());
        assert!(extents.iter().all(|e| cached(rig, e)));
        assert_eq!(rig.bridge.nntp.live(), 0);
        assert_eq!(rig.bridge.budget.in_use(), 0);
        let flushed = std::mem::take(&mut *hit_flushes.borrow_mut());
        for work in flushed {
            work.await;
        }
        let cat = &rig.bridge.catalog;
        assert_eq!(
            cat.hot_ctl_load(&[velmora_bridge::hotctl::HIT_KEY])
                .await
                .unwrap(),
            vec![None]
        );
        let missed: i64 = cat
            .hot_ctl_load(&velmora_bridge::hotctl::MISS_KEYS)
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .sum();
        assert_eq!(
            missed as u64,
            extents.iter().map(|x| x.cipher_size).sum::<u64>()
        );
    };
    local.run_until(test).await;
}

/// A reader that let a piece wait too long gets nothing ahead until it
/// asks for a piece soon after it took the one before: each piece is
/// then made when it is asked for, so a slow reader does not have every
/// extent read once to be taken back and once more to be served. A
/// reader that is quick again gets pieces ahead again.
#[tokio::test(flavor = "current_thread")]
async fn a_slow_reader_gets_each_piece_when_it_asks_until_it_is_quick_again() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        // The wait for the reader is 20 ms here.
        let sleeper = timed_sleeper(|ms| match ms == PIECE_WAIT_MS {
            true => 20,
            false => ms.into(),
        });
        let cold = cold_rig_on(2, Some(sleeper), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [
            pattern(113, 300_000),
            pattern(114, 300_000),
            pattern(115, 300_000),
            pattern(116, 300_000),
            pattern(117, 300_000),
            pattern(118, 300_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
        let req = cold.signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "multi"),
            &[],
            &[],
            Vec::new(),
        );
        let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut body) = resp.body else {
            panic!("a GET body is a stream");
        };
        eventually("the second piece is taken back", || {
            cached(rig, &extents[1])
                && rig.bridge.budget.in_use() == parts[0].len() as u64
                && rig.bridge.nntp.live() == 0
        })
        .await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        assert!(body.next().await.unwrap().unwrap() == parts[1]);
        // The reader is slow again: nothing is read for it meanwhile.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert!(!cached(rig, &extents[2]), "nothing is made ahead");
        assert_eq!(rig.bridge.budget.in_use(), 0);
        assert_eq!(rig.bridge.nntp.live(), 0);
        // It asks for two pieces one right after the other: the pieces
        // after them are made ahead again.
        assert!(body.next().await.unwrap().unwrap() == parts[2]);
        assert!(body.next().await.unwrap().unwrap() == parts[3]);
        eventually("the next piece is made ahead", || cached(rig, &extents[4])).await;
        assert!(body.next().await.unwrap().unwrap() == parts[4]);
        assert!(body.next().await.unwrap().unwrap() == parts[5]);
        assert!(body.next().await.is_none());
        assert!(extents.iter().all(|e| cached(rig, e)));
        assert_eq!(rig.bridge.nntp.live(), 0);
        assert_eq!(rig.bridge.budget.in_use(), 0);
    };
    local.run_until(test).await;
}

/// A body that is produced ahead of a reader that keeps up holds a
/// piece or the room for the next one at every moment. A request that
/// waits for more room than is left beside one piece is served all the
/// same: the body charges for its next piece in turn, after the request
/// that waited before it, and goes on when there is room again.
#[tokio::test(flavor = "current_thread")]
async fn a_body_ahead_of_its_reader_lets_a_waiting_request_have_its_room() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        // A look for room takes the 100 ms it says, the other timers as
        // in `real_sleeper`.
        let real = real_sleeper();
        let sleeper: Sleeper = Rc::new(move |ms| match ms {
            CHARGE_POLL_MS => Box::pin(tokio::time::sleep(std::time::Duration::from_millis(100))),
            _ => real(ms),
        });
        let cold = cold_rig_on(2, Some(sleeper), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts: Vec<Vec<u8>> = (0..8u8).map(|n| pattern(120 + n, 300_000)).collect();
        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let extents = commit_parts(rig, &cold.signer, &cold.bucket, "warm", &slices).await;
        let cipher = extents.iter().map(|e| e.cipher_size).max().unwrap();
        let budget = &rig.bridge.budget;
        // Room for one piece that waits and for making one more; the
        // other request needs all of it but 100,000 bytes, so it fits
        // only while the body holds nothing.
        let room = cipher + 650_000;
        let other = budget.try_charge(budget.capacity() - room).unwrap();
        let req = cold.signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "warm"),
            &[],
            &[],
            Vec::new(),
        );
        let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut body) = resp.body else {
            panic!("a GET body is a stream");
        };
        eventually("a piece is made ahead", || {
            budget.in_use() == other.bytes() + 600_000
        })
        .await;
        // The other request is served once and gives its room back.
        let served = Rc::new(Cell::new(false));
        let (bridge, slot) = (Rc::clone(&rig.bridge), Rc::clone(&served));
        tokio::task::spawn_local(async move {
            let charge = bridge.budget.charge(room - 100_000).await.unwrap();
            assert_eq!(charge.bytes(), room - 100_000);
            slot.set(true);
        });
        // It waits by now, and looks for room every 100 ms. The reader
        // takes a piece every 50 ms, between those looks: a body that
        // did not wait its turn would have made the next piece each
        // time before the other request looked, which would never see
        // the room.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!served.get());
        for part in &parts[..7] {
            assert!(body.next().await.unwrap().unwrap() == *part);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(served.get(), "served before the body ended");
        assert!(body.next().await.unwrap().unwrap() == parts[7]);
        assert!(body.next().await.is_none());
        assert_eq!(budget.in_use(), other.bytes());
    };
    local.run_until(test).await;
}

/// A request that waits for nearly the whole budget does not hold back
/// a body it has room beside: a small object is read at once, piece
/// after piece, while the large request still waits.
#[tokio::test(flavor = "current_thread")]
async fn a_small_body_does_not_wait_for_a_large_request_that_waits() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts: Vec<Vec<u8>> = (0..6u8).map(|n| pattern(130 + n, 1_000)).collect();
        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        commit_parts(rig, &cold.signer, &cold.bucket, "small", &slices).await;
        let budget = &rig.bridge.budget;
        // The large request has no room beside the other one, and all
        // of the small body fits beside it.
        let other = budget.try_charge(200_000).unwrap();
        let large = budget.capacity() - 100_000;
        let served = Rc::new(Cell::new(false));
        let (bridge, slot) = (Rc::clone(&rig.bridge), Rc::clone(&served));
        let waiting = tokio::task::spawn_local(async move {
            let charge = bridge.budget.charge(large).await;
            slot.set(true);
            charge
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let began = std::time::Instant::now();
        let req = cold.signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "small"),
            &[],
            &[],
            Vec::new(),
        );
        let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut body) = resp.body else {
            panic!("a GET body is a stream");
        };
        for part in &parts {
            assert!(body.next().await.unwrap().unwrap() == *part);
        }
        assert!(body.next().await.is_none());
        // No piece waited a turn (5 s) or for room (20 s).
        assert!(began.elapsed() < std::time::Duration::from_secs(2));
        assert!(!served.get(), "the large request still waits");
        drop(other);
        assert_eq!(waiting.await.unwrap().unwrap().bytes(), large);
    };
    local.run_until(test).await;
}

/// A body that has begun waits for room longer than a request that has
/// sent nothing: its reader has a part already, and an end after one
/// wait would be an error in the middle of a download.
#[tokio::test(flavor = "current_thread")]
async fn a_body_that_has_begun_waits_longer_for_room() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        // The room is given back at the 300th look for it: a wait and a
        // half.
        let looks = Rc::new(Cell::new(0u32));
        let taken: Rc<RefCell<Option<Charge>>> = Rc::default();
        let real = real_sleeper();
        let (n, slot) = (Rc::clone(&looks), Rc::clone(&taken));
        let sleeper: Sleeper = Rc::new(move |ms| {
            if ms == CHARGE_POLL_MS {
                n.set(n.get() + 1);
                if n.get() == 300 {
                    slot.borrow_mut().take();
                }
            }
            real(ms)
        });
        let cold = cold_rig_on(2, Some(sleeper), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts: Vec<Vec<u8>> = (0..3u8).map(|n| pattern(140 + n, 300_000)).collect();
        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        commit_parts(rig, &cold.signer, &cold.bucket, "begun", &slices).await;
        let budget = &rig.bridge.budget;
        let req = cold.signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "begun"),
            &[],
            &[],
            Vec::new(),
        );
        let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut body) = resp.body else {
            panic!("a GET body is a stream");
        };
        eventually("a piece is made ahead", || budget.in_use() == 600_000).await;
        // Another request takes all the rest: the last piece has no
        // room, also once the two before it are taken.
        *taken.borrow_mut() = budget.try_charge(budget.capacity() - 600_000);
        assert!(taken.borrow().is_some());
        looks.set(0);
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        assert!(body.next().await.unwrap().unwrap() == parts[1]);
        assert!(body.next().await.unwrap().unwrap() == parts[2]);
        assert!(looks.get() >= 300, "it waited: {}", looks.get());
        assert!(body.next().await.is_none());
        assert_eq!(budget.in_use(), 0);
    };
    local.run_until(test).await;
}

/// A request that has sent nothing waits for room once and is then told
/// to slow down: only a body that has begun waits longer.
#[tokio::test(flavor = "current_thread")]
async fn a_request_that_has_sent_nothing_waits_for_room_once() {
    let looks = Rc::new(Cell::new(0u32));
    let real = real_sleeper();
    let n = Rc::clone(&looks);
    let sleeper: Sleeper = Rc::new(move |ms| {
        if ms == CHARGE_POLL_MS {
            n.set(n.get() + 1);
        }
        real(ms)
    });
    let cold = cold_rig_with(2, Some(sleeper)).await;
    let rig = &cold.rig;
    let body = pattern(150, 300_000);
    rig.put(&cold.signer, BUCKET, "k", &body).await.expect(200);
    let budget = &rig.bridge.budget;
    let held = budget.try_charge(budget.capacity()).unwrap();
    looks.set(0);
    let resp = get(rig, &cold.signer, "k", &[]).await;
    resp.expect_error(503, "SlowDown");
    let once = CHARGE_WAIT_MS / CHARGE_POLL_MS;
    assert!(
        (once..once + 10).contains(&looks.get()),
        "it looked {} times",
        looks.get()
    );
    drop(held);
    assert!(get(rig, &cold.signer, "k", &[]).await.expect(200).body == body);
}

/// A read that found every provider slot taken waits for room in turn
/// before it tries again, as a request that waits for room: a body that
/// runs ahead of its reader, and holds a piece or the room for the next
/// one at every moment, lets it have the room, and it is served while
/// that body still runs.
#[tokio::test(flavor = "current_thread")]
async fn a_read_that_waits_for_a_slot_gets_its_room_beside_a_body_ahead_of_its_reader() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        // A look for room and a look for a slot take 100 ms; the looks
        // for a slot are counted.
        let slot_looks = Rc::new(Cell::new(0u32));
        let real = real_sleeper();
        let n = Rc::clone(&slot_looks);
        let sleeper: Sleeper = Rc::new(move |ms| {
            if ms > CHARGE_POLL_MS {
                return real(ms);
            }
            if ms != CHARGE_POLL_MS {
                n.set(n.get() + 1);
            }
            Box::pin(tokio::time::sleep(std::time::Duration::from_millis(100)))
        });
        let cold = cold_rig_on(4, Some(sleeper), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts: Vec<Vec<u8>> = (0..32u8).map(|n| pattern(160 + n, 100_000)).collect();
        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let extents = commit_parts(rig, &cold.signer, &cold.bucket, "warm", &slices).await;
        let cipher = extents.iter().map(|e| e.cipher_size).max().unwrap();
        let lone = pattern(159, 200_000);
        let extent = cold.put_and_post("cold.bin", &lone).await;
        evict(rig, &extent).await;
        let held = hold_all_slots(rig).await;
        let budget = &rig.bridge.budget;
        // The cold read fits only while the body holds nothing; the
        // body has room for one piece that waits and for making one
        // more.
        let need =
            velmora_bridge::fetch::cold_step_bytes(extent.cipher_size, rig.bridge.cfg.cold_sockets);
        let room = need + 50_000;
        assert!(room >= cipher + 250_000, "room {room}, cipher {cipher}");
        let other = budget.try_charge(budget.capacity() - room).unwrap();
        let sign = |key: &str| {
            cold.signer.sign(
                rig.now(),
                Method::Get,
                &path(BUCKET, key),
                &[],
                &[],
                Vec::new(),
            )
        };
        let resp = Rc::clone(&rig.bridge)
            .handle(sign("warm").into_request())
            .await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut body) = resp.body else {
            panic!("a GET body is a stream");
        };
        eventually("a piece is made ahead", || {
            budget.in_use() == other.bytes() + 200_000
        })
        .await;
        let read: Rc<RefCell<Option<Vec<u8>>>> = Rc::default();
        let (bridge, slot, req) = (Rc::clone(&rig.bridge), Rc::clone(&read), sign("cold.bin"));
        tokio::task::spawn_local(async move {
            let resp = bridge.handle(req.into_request()).await;
            assert_eq!(resp.status, 200);
            let RespBody::Stream(mut body) = resp.body else {
                panic!("a GET body is a stream");
            };
            let mut all = Vec::new();
            while let Some(chunk) = body.next().await {
                all.extend_from_slice(&chunk.unwrap());
            }
            *slot.borrow_mut() = Some(all);
        });
        // The reader of the body takes a piece every 50 ms, between the
        // looks of the cold read. Once that has found no slot, the
        // slots are given back. A read that only looked for room, and
        // was not waited for, would find it by chance after some
        // forty pieces or when the body has ended; this one has it
        // after six.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let mut held = Some(held);
        let mut taken = 0;
        for part in &parts[..20] {
            if read.borrow().is_some() {
                break;
            }
            if slot_looks.get() > 0 {
                for permit in held.take().into_iter().flatten() {
                    rig.bridge.catalog.release_permit(&permit).await.unwrap();
                }
            }
            assert!(body.next().await.unwrap().unwrap() == *part);
            taken += 1;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(slot_looks.get() > 0, "the cold read found a slot at once");
        assert!(
            read.borrow().as_deref() == Some(&lone[..]),
            "not served while the body ran ({taken} pieces taken)"
        );
        for part in &parts[taken..] {
            assert!(body.next().await.unwrap().unwrap() == *part);
        }
        assert!(body.next().await.is_none());
        assert_eq!(budget.in_use(), other.bytes());
    };
    local.run_until(test).await;
}

/// A body that waits for room in the byte budget ends its connections
/// before their slots run out, and reads on once the room is there.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_body_that_waits_for_room_does_not_sit_on_its_slots() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        // Expire the idle connections after the reader consumes the first
        // piece and another request holds the budget. Real catalogue I/O
        // must not make the idle timer fire before the test reaches that state.
        let idle = Rc::new(tokio::sync::Notify::new());
        let timer = idle.clone();
        let sleeper: Sleeper = Rc::new(move |ms| {
            let timer = timer.clone();
            Box::pin(async move {
                if ms > 20_000 {
                    timer.notified().await;
                } else {
                    tokio::time::sleep(std::time::Duration::from_millis(u64::from(ms))).await;
                }
            })
        });
        let cold = cold_rig_on(2, Some(sleeper), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [
            pattern(105, 300_000),
            pattern(106, 300_000),
            pattern(107, 300_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
        let budget = &rig.bridge.budget;
        // Reserve room for exactly one cold fetch before the producer can
        // run ahead. Both engines must reach the same one-piece state.
        let need = velmora_bridge::fetch::cold_step_bytes(
            extents[0].cipher_size,
            rig.bridge.cfg.cold_sockets,
        );
        let reserved = budget.capacity() - need;
        let other = budget.try_charge(reserved).unwrap();
        let req = cold.signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "multi"),
            &[],
            &[],
            Vec::new(),
        );
        let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
        assert_eq!(resp.status, 200);
        let RespBody::Stream(mut body) = resp.body else {
            panic!("a GET body is a stream");
        };
        let ready = || cached(rig, &extents[0]) && budget.in_use() == reserved + 300_000;
        for _ in 0..400 {
            if ready() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            ready(),
            "first piece did not wait: cache={}, budget={}, held={}, connects={}",
            cached(rig, &extents[0]),
            budget.in_use(),
            rig.bridge.nntp.live(),
            rig.bridge.nntp.connects()
        );
        assert!(rig.bridge.nntp.live() > 0, "kept for the next extent");
        let connects = rig.bridge.nntp.connects();
        // The other request takes the rest of the room too.
        let rest = budget.try_charge(need - 300_000).unwrap();
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        idle.notify_one();
        eventually("the connections are ended", || rig.bridge.nntp.live() == 0).await;
        assert!(!cached(rig, &extents[1]));
        assert_eq!(free_slots(rig).await, 2);
        drop(rest);
        drop(other);
        assert!(body.next().await.unwrap().unwrap() == parts[1]);
        assert!(body.next().await.unwrap().unwrap() == parts[2]);
        assert!(body.next().await.is_none());
        assert!(rig.bridge.nntp.connects() > connects, "it connected again");
        assert_eq!(rig.bridge.nntp.live(), 0);
        assert_eq!(budget.in_use(), 0);
    };
    local.run_until(test).await;
}

/// Two bodies of extents that have a copy, with room for the ciphertext
/// of both and the plaintext of neither beside it: each takes all it
/// needs at once or nothing, so one of them always goes on. Neither
/// holds a part and waits for the rest.
#[tokio::test(flavor = "current_thread")]
async fn two_warm_bodies_do_not_wait_for_each_other_s_room() {
    let asked = Rc::new(Cell::new(0u64));
    let polls = Rc::new(Cell::new(0u32));
    let cold = cold_rig_with(2, Some(short_sleeper(asked.clone(), polls.clone()))).await;
    let rig = &cold.rig;
    let parts = [
        pattern(108, 300_000),
        pattern(109, 300_000),
        pattern(110, 300_000),
    ];
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let extents = commit_parts(rig, &cold.signer, &cold.bucket, "warm", &slices).await;
    let cipher = extents.iter().map(|e| e.cipher_size).max().unwrap();
    let budget = &rig.bridge.budget;
    let room = 2 * cipher + 200_000;
    let other = budget.try_charge(budget.capacity() - room).unwrap();

    let (a, b) = futures_util::future::join(
        get(rig, &cold.signer, "warm", &[]),
        get(rig, &cold.signer, "warm", &[]),
    )
    .await;
    for resp in [a, b] {
        resp.expect(200);
        assert!(resp.stream_error.is_none(), "{:?}", resp.stream_error);
        assert!(resp.body == parts.concat());
    }
    assert!(
        asked.get() < u64::from(velmora_bridge::ingress::CHARGE_WAIT_MS),
        "neither waited as long as a request may"
    );
    drop(other);
    assert_eq!(budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn cold_range_read_serves_only_the_range() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let body = pattern(17, 900_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;

    let resp = get_range(rig, &cold.signer, "cold.bin", "bytes=700000-700099").await;
    resp.expect(206);
    assert_eq!(resp.body, body[700_000..700_100]);
    assert!(rig.bridge.cache.contains(&extent.id.cache_key()));
}

#[tokio::test(flavor = "current_thread")]
async fn cold_read_never_serves_a_damaged_article() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let body = pattern(19, 1_500_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;

    // One article is gone from the only provider.
    let plan = rig.bridge.catalog.articles(&extent.id).await.unwrap();
    cold.server.hide(&format!("<{}>", plan[1].message_id)).await;
    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect_error(503, "ServiceUnavailable");
    assert!(resp.header("retry-after").is_some());
    assert!(!resp.body.windows(32).any(|w| w == &body[..32]));
    assert!(
        rig.bridge.cache.keys().is_empty(),
        "nothing partial is cached"
    );
    assert_eq!(rig.bridge.nntp.live(), 0);

    // Once it is back the same request succeeds.
    cold.server
        .unhide(&format!("<{}>", plan[1].message_id))
        .await;
    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect(200);
    assert!(resp.body == body);
}

#[tokio::test(flavor = "current_thread")]
async fn cold_read_without_a_free_connection_is_slow_down() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let body = pattern(23, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;

    // Other readers hold every connection slot of the provider.
    let provider = &rig.bridge.cfg.providers[0];
    let mut held = Vec::new();
    while let Some(permit) = rig
        .bridge
        .catalog
        .acquire_permit(
            provider,
            PermitClass::Read,
            &format!("other-{}", held.len()),
            rig.now(),
        )
        .await
        .unwrap()
    {
        held.push(permit);
        assert!(held.len() <= 16, "permits are bounded");
    }
    assert!(!held.is_empty());
    let connects = rig.bridge.nntp.connects();

    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect_error(503, "SlowDown");
    assert!(resp.header("retry-after").is_some());
    assert_eq!(
        rig.bridge.nntp.connects(),
        connects,
        "no session was opened"
    );
    assert!(rig.bridge.cache.keys().is_empty());

    for permit in &held {
        rig.bridge.catalog.release_permit(permit).await.unwrap();
    }
    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect(200);
    assert!(resp.body == body);
}

/// Whether a sleeper is asked for a timer that watches over something
/// else (a renewal, a piece that waits, connections that sit idle), and
/// not for the pause between two polls: those are short.
fn is_watch(ms: u32) -> bool {
    ms > CHARGE_POLL_MS
}

/// Sleeper for a rig on real time: a poll is 1 ms. `watch` gives the
/// real milliseconds of a timer that watches over something.
fn timed_sleeper(watch: impl Fn(u32) -> u64 + 'static) -> Sleeper {
    Rc::new(move |ms| {
        let real = match is_watch(ms) {
            true => watch(ms),
            false => 1,
        };
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(real)))
    })
}

/// [`timed_sleeper`] whose watching timers take the time they say: none
/// of them fires in a test that does not wait for it.
fn real_sleeper() -> Sleeper {
    timed_sleeper(u64::from)
}

/// How many read slots of the rig's provider are free.
async fn free_slots(rig: &Rig<TcpConnector>) -> usize {
    let provider = &rig.bridge.cfg.providers[0];
    let mut held = Vec::new();
    while let Some(permit) = rig
        .bridge
        .catalog
        .acquire_permit(provider, PermitClass::Read, "other", rig.now())
        .await
        .unwrap()
    {
        held.push(permit);
    }
    for permit in &held {
        rig.bridge.catalog.release_permit(permit).await.unwrap();
    }
    held.len()
}

/// Sleeper that really sleeps 1 ms per poll (so sessions in flight make
/// progress) and adds up the milliseconds the bridge asked for.
fn short_sleeper(asked: Rc<Cell<u64>>, polls: Rc<Cell<u32>>) -> Sleeper {
    Rc::new(move |ms| {
        if is_watch(ms) {
            return Box::pin(tokio::time::sleep(std::time::Duration::from_millis(
                ms.into(),
            )));
        }
        assert!(
            (COLD_POLL_MS..=COLD_POLL_MS + COLD_JITTER_MS).contains(&ms) || ms == CHARGE_POLL_MS
        );
        asked.set(asked.get() + u64::from(ms));
        polls.set(polls.get() + 1);
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1)))
    })
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_cold_range_reads_wait_for_a_provider_slot() {
    // The way aws-cli downloads: ten range GETs at once, more than the
    // provider's four connections.
    let asked = Rc::new(Cell::new(0u64));
    let polls = Rc::new(Cell::new(0u32));
    let cold = cold_rig_with(4, Some(short_sleeper(asked.clone(), polls.clone()))).await;
    let rig = &cold.rig;
    let parts = [
        pattern(41, 1_300_000),
        pattern(42, 900_001),
        pattern(43, 1_100_000),
    ];
    let whole: Vec<u8> = parts.concat();
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let extents = commit_parts(rig, &cold.signer, &cold.bucket, "multi", &slices).await;
    for extent in &extents {
        cold.post(extent.generation_id.as_ref().unwrap(), extent)
            .await;
        evict(rig, extent).await;
    }
    assert!(rig.bridge.cache.keys().is_empty());
    let template = rig.live(&cold.bucket, "template").await.unwrap().1;
    evict(rig, &template[0]).await;
    assert!(rig.bridge.safety.keys().iter().all(|k| k.starts_with("m/")));
    let connects = rig.bridge.nntp.connects();

    let total = whole.len();
    let step = total / 10;
    let ranges: Vec<(usize, usize)> = (0..10)
        .map(|i| {
            (
                i * step,
                if i == 9 {
                    total - 1
                } else {
                    (i + 1) * step - 1
                },
            )
        })
        .collect();
    let gets = ranges.iter().map(|(start, end)| {
        let range = format!("bytes={start}-{end}");
        let signer = &cold.signer;
        async move { get_range(rig, signer, "multi", &range).await }
    });
    let resps = futures_util::future::join_all(gets).await;
    for ((start, end), resp) in ranges.iter().zip(&resps) {
        resp.expect(206);
        assert!(resp.stream_error.is_none(), "{start}-{end}");
        assert!(
            resp.body == whole[*start..=*end],
            "{start}-{end}: other bytes"
        );
    }

    // Some readers found every slot taken and waited for one; at no point
    // were more sessions open than the provider allows.
    assert!(polls.get() > 0, "no reader had to wait");
    assert!(asked.get() < u64::from(COLD_WAIT_MS));
    assert!(rig.bridge.nntp.connects() > connects);
    assert!(
        rig.bridge.nntp.peak() <= 4,
        "peak {}",
        rig.bridge.nntp.peak()
    );
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert_eq!(rig.bridge.budget.in_use(), 0);
    for extent in &extents {
        assert!(rig.bridge.cache.contains(&extent.id.cache_key()));
    }
    // Every slot is free again.
    let provider = &rig.bridge.cfg.providers[0];
    let mut held = Vec::new();
    while let Some(permit) = rig
        .bridge
        .catalog
        .acquire_permit(provider, PermitClass::Read, "check", rig.now())
        .await
        .unwrap()
    {
        held.push(permit);
        assert!(held.len() <= 4, "more permits than max_conns");
    }
    assert_eq!(held.len(), 4);
}

/// What a fake sleeper runs on each poll once the rig exists: gets the
/// poll number, may inspect or change the rig.
type OnPoll = Box<dyn Fn(u32, Rc<TestBridge<TcpConnector>>) -> LocalBoxFuture<'static, ()>>;
type PollHook = Rc<RefCell<Option<OnPoll>>>;

/// Sleeper that lets no real time pass. It adds up the milliseconds asked
/// for, moves the rig's clock by them plus `overhead_ms` (the round trips
/// of a poll), checks that the waiting read holds no budget, and runs
/// `hook`.
fn fake_cold_sleeper(
    asked: Rc<Cell<u64>>,
    polls: Rc<Cell<u32>>,
    bridge: Rc<RefCell<Weak<TestBridge<TcpConnector>>>>,
    hook: PollHook,
    overhead_ms: i64,
) -> Sleeper {
    Rc::new(move |ms| {
        if is_watch(ms) {
            // No real time passes here: nothing is watched.
            return Box::pin(std::future::pending());
        }
        assert!((COLD_POLL_MS..=COLD_POLL_MS + COLD_JITTER_MS).contains(&ms));
        asked.set(asked.get() + u64::from(ms));
        polls.set(polls.get() + 1);
        let bridge = bridge.borrow().upgrade().expect("rig is alive");
        assert_eq!(bridge.budget.in_use(), 0, "a waiting read holds budget");
        bridge.clock.advance_ms(i64::from(ms) + overhead_ms);
        match hook.borrow().as_ref() {
            Some(hook) => hook(polls.get(), bridge),
            None => Box::pin(async {}),
        }
    })
}

/// Takes every read slot of the rig's provider.
async fn hold_all_slots(rig: &Rig<TcpConnector>) -> Vec<Permit> {
    let provider = &rig.bridge.cfg.providers[0];
    let mut held = Vec::new();
    while let Some(permit) = rig
        .bridge
        .catalog
        .acquire_permit(provider, PermitClass::Read, "other", rig.now())
        .await
        .unwrap()
    {
        held.push(permit);
        assert!(held.len() <= 4, "more permits than max_conns");
    }
    assert_eq!(held.len(), 4);
    held
}

/// A poll hook under which the holders of `held` are at work: they renew
/// on every poll, as a read does before every call to the provider.
fn renewing(held: Vec<Permit>) -> OnPoll {
    Box::new(move |_, bridge| {
        let held = held.clone();
        Box::pin(async move {
            for permit in &held {
                let now = bridge.clock.now();
                assert!(bridge.catalog.renew_permit(permit, now).await.unwrap());
            }
        })
    })
}

/// A read that every provider broke off is begun again after a wait: a
/// provider's or a proxy's bad moment does not end the response. One
/// that keeps breaking off ends as `SlowDown` after a few tries.
#[tokio::test(flavor = "current_thread")]
async fn an_interrupted_cold_read_is_begun_again() {
    for heals in [true, false] {
        let asked = Rc::new(Cell::new(0u64));
        let polls = Rc::new(Cell::new(0u32));
        let weak = Rc::new(RefCell::new(Weak::new()));
        let hook = PollHook::default();
        let sleeper =
            fake_cold_sleeper(asked.clone(), polls.clone(), weak.clone(), hook.clone(), 0);
        let cold = cold_rig_with(2, Some(sleeper)).await;
        *weak.borrow_mut() = Rc::downgrade(&cold.rig.bridge);
        let body = pattern(53, 1_500_000);
        let extent = cold.put_and_post("cold.bin", &body).await;
        evict(&cold.rig, &extent).await;
        // Every `BODY` breaks off.
        cold.server.drop_next_bodies(usize::MAX).await;
        let Cold {
            rig,
            server,
            signer,
            ..
        } = cold;
        let server = Rc::new(server);
        if heals {
            // The provider is well again by the time the read has waited.
            let server = Rc::clone(&server);
            *hook.borrow_mut() = Some(Box::new(move |_, _| {
                let server = Rc::clone(&server);
                Box::pin(async move { server.drop_next_bodies(0).await })
            }));
        }

        let resp = if heals {
            get(&rig, &signer, "cold.bin", &[]).await
        } else {
            let req = signer.sign(
                rig.now(),
                Method::Get,
                &path(BUCKET, "cold.bin"),
                &[],
                &[],
                Vec::new(),
            );
            observed_get(&rig, req.into_request(), "nntp", "le_1gib").await
        };
        match heals {
            true => {
                resp.expect(200);
                assert!(resp.body == body, "the read returned other bytes");
                assert_eq!(polls.get(), 1);
                let cached = rig.bridge.cache.stored(&extent.id.cache_key()).unwrap();
                assert_eq!(sha256(&cached.bytes), extent.cipher_sha256);
            }
            false => {
                resp.expect_error(503, "SlowDown");
                assert!(resp.header("retry-after").is_some());
                assert_eq!(polls.get(), service::INTERRUPTED_RETRIES);
                assert!(rig.bridge.cache.keys().is_empty());
            }
        }
        assert_eq!(rig.bridge.nntp.live(), 0);
        assert_eq!(rig.bridge.budget.in_use(), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cold_read_waits_for_a_slot_then_slows_down() {
    let asked = Rc::new(Cell::new(0u64));
    let polls = Rc::new(Cell::new(0u32));
    let weak = Rc::new(RefCell::new(Weak::new()));
    let hook = PollHook::default();
    let sleeper = fake_cold_sleeper(asked.clone(), polls.clone(), weak.clone(), hook.clone(), 0);
    let cold = cold_rig_with(4, Some(sleeper)).await;
    let rig = &cold.rig;
    *weak.borrow_mut() = Rc::downgrade(&rig.bridge);
    let body = pattern(47, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;

    // Other readers hold every slot for longer than the bound. They are
    // at work: they renew, as a read does before every call.
    let held = hold_all_slots(rig).await;
    *hook.borrow_mut() = Some(renewing(held.clone()));
    let connects = rig.bridge.nntp.connects();

    let req = cold.signer.sign(
        rig.now(),
        Method::Get,
        &path(BUCKET, "cold.bin"),
        &[],
        &[],
        Vec::new(),
    );
    let resp = observed_get(rig, req.into_request(), "slot_wait", "le_1gib").await;
    resp.expect_error(503, "SlowDown");
    assert!(resp.header("retry-after").is_some());
    let bound = u64::from(COLD_WAIT_MS);
    assert!(asked.get() >= bound, "gave up after {} ms", asked.get());
    assert!(
        asked.get() < bound + u64::from(COLD_POLL_MS + COLD_JITTER_MS),
        "waited {} ms",
        asked.get()
    );
    assert!(polls.get() > 1);
    assert_eq!(
        rig.bridge.nntp.connects(),
        connects,
        "no session was opened"
    );
    assert!(rig.bridge.cache.keys().is_empty());
    assert_eq!(rig.bridge.budget.in_use(), 0);

    for permit in &held {
        rig.bridge.catalog.release_permit(permit).await.unwrap();
    }
    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect(200);
    assert!(resp.body == body);
}

/// The room is gone when the last wait for a slot is over: the read
/// ends as `SlowDown` there, and begins no wait for room.
#[tokio::test(flavor = "current_thread")]
async fn a_wait_for_a_slot_that_is_over_does_not_go_on_as_a_wait_for_room() {
    let asked = Rc::new(Cell::new(0u64));
    let polls = Rc::new(Cell::new(0u32));
    let weak = Rc::new(RefCell::new(Weak::new()));
    let hook = PollHook::default();
    let sleeper = fake_cold_sleeper(asked.clone(), polls.clone(), weak.clone(), hook.clone(), 0);
    let cold = cold_rig_with(4, Some(sleeper)).await;
    let rig = &cold.rig;
    *weak.borrow_mut() = Rc::downgrade(&rig.bridge);
    let body = pattern(48, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;

    // The slots are held throughout, and another request takes the
    // whole budget during the wait that reaches the bound.
    let held = hold_all_slots(rig).await;
    let taken: Rc<RefCell<Option<Charge>>> = Rc::default();
    let (renew, total, slot) = (renewing(held), Rc::clone(&asked), Rc::clone(&taken));
    *hook.borrow_mut() = Some(Box::new(move |poll, bridge| {
        if total.get() >= u64::from(COLD_WAIT_MS) {
            *slot.borrow_mut() = bridge.budget.try_charge(bridge.budget.capacity());
        }
        renew(poll, bridge)
    }));

    let req = cold.signer.sign(
        rig.now(),
        Method::Get,
        &path(BUCKET, "cold.bin"),
        &[],
        &[],
        Vec::new(),
    );
    let resp = observed_get(rig, req.into_request(), "budget", "le_1gib").await;
    resp.expect_error(503, "SlowDown");
    assert!(taken.borrow().is_some(), "the budget was not taken");
    assert!(asked.get() < u64::from(COLD_WAIT_MS + COLD_POLL_MS + COLD_JITTER_MS));
    assert!(rig.bridge.cache.keys().is_empty());
}

/// Readers that were cut off (their clients hung up) release nothing:
/// their slots run out by themselves. A read that finds every slot held
/// by them waits that out and is served; it does not give up first.
#[tokio::test(flavor = "current_thread")]
async fn a_waiting_read_outlasts_the_slots_of_dropped_reads() {
    let asked = Rc::new(Cell::new(0u64));
    let polls = Rc::new(Cell::new(0u32));
    let weak = Rc::new(RefCell::new(Weak::new()));
    let sleeper = fake_cold_sleeper(
        asked.clone(),
        polls.clone(),
        weak.clone(),
        PollHook::default(),
        0,
    );
    let cold = cold_rig_with(4, Some(sleeper)).await;
    let rig = &cold.rig;
    *weak.borrow_mut() = Rc::downgrade(&rig.bridge);
    let body = pattern(48, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;

    // Taken and never renewed or released.
    let _dropped = hold_all_slots(rig).await;

    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect(200);
    assert!(resp.body == body);
    let permit_ms = u64::from(PermitClass::Read.permit_secs()) * 1000;
    assert!(asked.get() >= permit_ms, "served after {} ms", asked.get());
    assert!(asked.get() < u64::from(COLD_WAIT_MS));
}

#[tokio::test(flavor = "current_thread")]
async fn waiting_cold_read_is_served_from_a_cache_filled_meanwhile() {
    let asked = Rc::new(Cell::new(0u64));
    let polls = Rc::new(Cell::new(0u32));
    let weak = Rc::new(RefCell::new(Weak::new()));
    let hook = PollHook::default();
    let sleeper = fake_cold_sleeper(asked.clone(), polls.clone(), weak.clone(), hook.clone(), 0);
    let cold = cold_rig_with(4, Some(sleeper)).await;
    let rig = &cold.rig;
    *weak.borrow_mut() = Rc::downgrade(&rig.bridge);
    let body = pattern(53, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    let blob = rig
        .bridge
        .safety
        .stored(&extent.id.safety_key())
        .unwrap()
        .bytes;
    evict(rig, &extent).await;
    let _held = hold_all_slots(rig).await;
    let connects = rig.bridge.nntp.connects();

    // On the third poll another reader's fill lands in the cache.
    let bucket = cold.bucket.id.clone();
    *hook.borrow_mut() = Some(Box::new(move |n, bridge| {
        let (blob, bucket, extent) = (blob.clone(), bucket.clone(), extent.clone());
        Box::pin(async move {
            if n == 3 {
                let meta = BlobMeta {
                    bucket: &bucket,
                    extent: &extent.id,
                    cipher_sha256: &extent.cipher_sha256,
                };
                bridge
                    .cache
                    .put(&extent.id.cache_key(), blob, &meta)
                    .await
                    .unwrap();
            }
        })
    }));

    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect(200);
    assert!(resp.body == body);
    assert_eq!(polls.get(), 3);
    assert_eq!(
        rig.bridge.nntp.connects(),
        connects,
        "no session was opened"
    );
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn slow_polls_end_the_wait_by_the_clock() {
    // Each poll also spends a second on round trips: the bound is elapsed
    // time, not the sum of the sleeps asked for.
    let asked = Rc::new(Cell::new(0u64));
    let polls = Rc::new(Cell::new(0u32));
    let weak = Rc::new(RefCell::new(Weak::new()));
    let hook = PollHook::default();
    let sleeper = fake_cold_sleeper(
        asked.clone(),
        polls.clone(),
        weak.clone(),
        hook.clone(),
        1_000,
    );
    let cold = cold_rig_with(4, Some(sleeper)).await;
    let rig = &cold.rig;
    *weak.borrow_mut() = Rc::downgrade(&rig.bridge);
    let body = pattern(59, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;
    *hook.borrow_mut() = Some(renewing(hold_all_slots(rig).await));

    let start = rig.now();
    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect_error(503, "SlowDown");
    let elapsed = rig.now().0 - start.0;
    let bound = i64::from(COLD_WAIT_MS);
    let poll_max = i64::from(COLD_POLL_MS + COLD_JITTER_MS) + 1_000;
    assert!(elapsed >= bound, "gave up after {elapsed} ms");
    assert!(elapsed < bound + poll_max, "waited {elapsed} ms");
    assert!(asked.get() < u64::from(COLD_WAIT_MS) / 10);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn each_extent_of_a_stream_gets_its_own_wait() {
    // The first extent is served after a 20 s wait; the second, read
    // mid-stream, still gets a full allowance of its own.
    let asked = Rc::new(Cell::new(0u64));
    let polls = Rc::new(Cell::new(0u32));
    let weak = Rc::new(RefCell::new(Weak::new()));
    let hook = PollHook::default();
    let sleeper = fake_cold_sleeper(asked.clone(), polls.clone(), weak.clone(), hook.clone(), 0);
    let cold = cold_rig_with(4, Some(sleeper)).await;
    let rig = &cold.rig;
    *weak.borrow_mut() = Rc::downgrade(&rig.bridge);
    let parts = [pattern(61, 200_000), pattern(62, 150_000)];
    let whole: Vec<u8> = parts.concat();
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let extents = commit_parts(rig, &cold.signer, &cold.bucket, "multi", &slices).await;
    let blobs: Vec<Vec<u8>> = extents
        .iter()
        .map(|e| rig.bridge.safety.stored(&e.id.safety_key()).unwrap().bytes)
        .collect();
    for extent in &extents {
        cold.post(extent.generation_id.as_ref().unwrap(), extent)
            .await;
        evict(rig, extent).await;
    }
    // The readers that hold the slots are at work all the while: they
    // renew, as a read does before every call to the provider.
    let held = hold_all_slots(rig).await;

    // Another reader's fill of extent i lands in the cache once 20 s
    // (first) and 40 s (second) have passed since the GET began.
    let start = rig.now();
    let bucket = cold.bucket.id.clone();
    let fills: Vec<(i64, ExtentRow, Vec<u8>)> = extents
        .iter()
        .zip(blobs)
        .enumerate()
        .map(|(i, (e, b))| (20_000 * (i as i64 + 1), e.clone(), b))
        .collect();
    *hook.borrow_mut() = Some(Box::new(move |_, bridge| {
        let elapsed = bridge.clock.now().0 - start.0;
        let due: Vec<(ExtentRow, Vec<u8>)> = fills
            .iter()
            .filter(|(at, e, _)| elapsed >= *at && !bridge.cache.contains(&e.id.cache_key()))
            .map(|(_, e, b)| (e.clone(), b.clone()))
            .collect();
        let bucket = bucket.clone();
        let held = held.clone();
        Box::pin(async move {
            for permit in &held {
                let now = bridge.clock.now();
                assert!(bridge.catalog.renew_permit(permit, now).await.unwrap());
            }
            for (extent, blob) in due {
                let meta = BlobMeta {
                    bucket: &bucket,
                    extent: &extent.id,
                    cipher_sha256: &extent.cipher_sha256,
                };
                bridge
                    .cache
                    .put(&extent.id.cache_key(), blob, &meta)
                    .await
                    .unwrap();
            }
        })
    }));

    let resp = get(rig, &cold.signer, "multi", &[]).await;
    resp.expect(200);
    assert!(resp.stream_error.is_none(), "{:?}", resp.stream_error);
    assert!(resp.body == whole);
    let elapsed = rig.now().0 - start.0;
    assert!(elapsed >= 40_000, "only {elapsed} ms passed");
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn never_posted_object_without_copies_is_unavailable() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let (_, extents) = rig.live(&bucket, "k").await.unwrap();
    let req = || {
        signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, "k"),
            &[],
            &[],
            Vec::new(),
        )
    };
    let held = rig
        .bridge
        .budget
        .try_charge(rig.bridge.budget.capacity())
        .unwrap();
    observed_get(&rig, req().into_request(), "budget", "le_1gib")
        .await
        .expect_error(503, "SlowDown");
    drop(held);

    evict(&rig, &extents[0]).await;
    observed_get(&rig, req().into_request(), "r2", "le_1gib")
        .await
        .expect_error(503, "ServiceUnavailable");

    // A failure while looking for the articles is still a 500.
    let sql = &rig.bridge.catalog.sql;
    *sql.fail_matching.borrow_mut() = Some(("plan AS headers", 0));
    observed_get(&rig, req().into_request(), "lookup", "le_1gib")
        .await
        .expect_error(500, "InternalError");
    sql.fail_matching.borrow_mut().take();
    // The catalogue still knows the object.
    rig.head(&signer, BUCKET, "k").await.expect(200);
}

#[tokio::test(flavor = "current_thread")]
async fn a_verified_cold_extent_that_cannot_be_opened_reports_decrypt() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let extent = cold.put_and_post("cold.bin", &pattern(29, 300_000)).await;
    evict(rig, &extent).await;
    let db = &rig.bridge.catalog.sql.inner;
    let update = db.fixture(
        "UPDATE extents SET wrapped_file_key = zeroblob(length(wrapped_file_key)) WHERE id = ?1",
        "UPDATE extents SET wrapped_file_key = decode(repeat('00', octet_length(wrapped_file_key)), 'hex') WHERE id = ?1",
    );
    db.fixture_exec(update, &[SqlValue::Text(extent.id.as_str().into())])
        .await
        .unwrap();
    let req = cold.signer.sign(
        rig.now(),
        Method::Get,
        &path(BUCKET, "cold.bin"),
        &[],
        &[],
        Vec::new(),
    );
    observed_get(rig, req.into_request(), "decrypt", "le_1gib")
        .await
        .expect_error(503, "ServiceUnavailable");
}

#[tokio::test(flavor = "current_thread")]
async fn cold_read_without_budget_for_the_extent_is_slow_down() {
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let body = pattern(29, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;
    let connects = rig.bridge.nntp.connects();
    let capacity = rig.bridge.cfg.inflight_budget_bytes;
    // A cold read holds the ciphertext and, while it reads, the wire
    // text of an article on every socket after the first: more, for an
    // extent this small, than the plaintext it holds afterwards.
    let need =
        velmora_bridge::fetch::cold_step_bytes(extent.cipher_size, rig.bridge.cfg.cold_sockets);
    assert!(need > 2 * extent.cipher_size);

    // One byte short: the small range is affordable warm, the extent is not.
    let held = rig.bridge.budget.try_charge(capacity - need + 1).unwrap();
    for range in [None, Some("bytes=0-9")] {
        let headers: Vec<(&str, &str)> = range.iter().map(|r| ("range", *r)).collect();
        let resp = get(rig, &cold.signer, "cold.bin", &headers).await;
        resp.expect_error(503, "SlowDown");
        assert!(resp.header("retry-after").is_some());
    }
    assert_eq!(
        rig.bridge.nntp.connects(),
        connects,
        "no session was opened"
    );
    assert!(rig.bridge.cache.keys().is_empty());
    assert_eq!(rig.bridge.budget.in_use(), capacity - need + 1);
    drop(held);

    // With exactly enough room it goes through.
    let held = rig.bridge.budget.try_charge(capacity - need).unwrap();
    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect(200);
    assert!(resp.body == body);
    drop(held);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn largest_extent_fits_the_smallest_allowed_budget_cold() {
    // At the shipped ratio (a budget of three times the extent limit) a
    // cold read of a full extent has to fit.
    let mut server_cfg = ServerConfig::for_test();
    server_cfg.articles = Vec::new();
    server_cfg.missing_ids.clear();
    server_cfg.users.insert(
        USER.to_string(),
        UserConfig {
            password: PASS.to_string(),
            max_connections: 4,
        },
    );
    let server = TestNntpServer::spawn(server_cfg).await;
    let mut cfg = config(vec![provider(&server)]);
    cfg.max_extent_bytes = MIB as u64;
    cfg.inflight_budget_bytes = 3 * MIB as u64;
    // What a deployment with this budget reads over: the configuration
    // lowers `COLD_SOCKETS` to what fits beside the extent and its copy.
    cfg.cold_sockets = 1;
    let rig = rig_with_selected(TcpConnector::default(), cfg);
    rig.bridge
        .catalog
        .seed_permits(&rig.bridge.cfg.providers)
        .await
        .unwrap();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let cold = Cold {
        rig,
        server,
        bucket,
        signer,
    };
    let body = pattern(31, MIB);
    let extent = cold.put_and_post("full.bin", &body).await;
    evict(&cold.rig, &extent).await;
    let resp = get(&cold.rig, &cold.signer, "full.bin", &[]).await;
    resp.expect(200);
    assert!(resp.body == body);
    assert_eq!(cold.rig.bridge.budget.in_use(), 0);
}

// ---------------------------------------------------------------------------
// Cold reads that rebuild lost articles from the extent's parity
// ---------------------------------------------------------------------------

/// 24 data articles and 4 parity articles.
const FULL_EXTENT: usize = 16 * 1024 * 1024;

/// A cold-read rig that plans parity for what it posts.
async fn parity_cold() -> Cold {
    parity_cold_with(None).await
}

/// The same, whose byte budget polls with `sleeper`.
async fn parity_cold_with(sleeper: Option<Sleeper>) -> Cold {
    let mut cold = cold_rig_with(2, sleeper).await;
    let bridge = Rc::get_mut(&mut cold.rig.bridge).expect("the rig alone holds the bridge");
    bridge.cfg.packed_plans = true;
    bridge.cfg.parity = true;
    // Every `BODY` is noted, with no time passing.
    bridge.nntp.slow(&bridge.clock, 0);
    cold
}

/// The data articles of the extent, then its parity articles.
async fn stripe(cold: &Cold, extent: &ExtentRow) -> (Vec<ArticleRow>, Vec<ArticleRow>) {
    let stored = cold
        .rig
        .bridge
        .catalog
        .stored_plan(&extent.id)
        .await
        .unwrap();
    let parity = stored
        .parity_plan(&extent.id, extent.cipher_size)
        .unwrap()
        .expect("the extent has parity");
    (stored.rows, parity.articles)
}

impl Cold {
    /// The provider no longer has these articles.
    async fn lose<'a>(&self, rows: impl IntoIterator<Item = &'a ArticleRow>) {
        for row in rows {
            self.server.hide(&format!("<{}>", row.message_id)).await;
        }
    }

    /// The provider has `row` again.
    async fn restore(&self, row: &ArticleRow) {
        self.server.unhide(&format!("<{}>", row.message_id)).await;
    }

    /// The provider now holds, under the message-id of `row`, a
    /// well-formed article of the right length with other bytes.
    async fn damage(&self, extent: &ExtentRow, rows: &[ArticleRow], row: &ArticleRow) {
        let end = (row.cipher_offset + row.cipher_len).max(extent.cipher_size);
        let other = vec![0x5au8; end as usize];
        let article = nntp_support::render(rows, row, &other, true);
        self.server.hide(&format!("<{}>", row.message_id)).await;
        let addr = self.server.addr();
        let cfg = nntp_support::nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
        let mut client = nntp_support::dial(&cfg).await.unwrap();
        client
            .post_article(&row.message_id, &article)
            .await
            .unwrap();
        client.quit().await;
    }

    /// `BODY` commands sent so far.
    fn bodies(&self) -> usize {
        let calls = self.rig.bridge.nntp.calls();
        calls.iter().filter(|call| call.0 == "body").count()
    }

    /// A GET of the whole object with nothing in the cache.
    async fn cold_get(&self, key: &str, extent: &ExtentRow) -> Resp {
        evict(&self.rig, extent).await;
        get(&self.rig, &self.signer, key, &[]).await
    }

    /// The GET failed, served nothing of `body` and cached nothing.
    fn nothing_served(&self, resp: &Resp, body: &[u8]) {
        resp.expect_error(503, "ServiceUnavailable");
        assert!(!resp.body.windows(32).any(|w| w == &body[..32]));
        assert!(self.rig.bridge.cache.keys().is_empty(), "nothing is cached");
        assert_eq!(self.rig.bridge.nntp.live(), 0);
        assert_eq!(self.rig.bridge.budget.in_use(), 0);
    }
}

/// A full extent with one, two, three and four of its data articles gone
/// from the provider reads back bit for bit, and the rebuilt extent is
/// cached. With five gone nothing is served and nothing is cached.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_read_rebuilds_up_to_as_many_lost_articles_as_the_extent_has_parity() {
    let cold = parity_cold().await;
    let body = pattern(41, FULL_EXTENT);
    let extent = cold.put_and_post("full.bin", &body).await;
    let (data, parity) = stripe(&cold, &extent).await;
    assert_eq!((data.len(), parity.len()), (24, 4));

    // The first article, the last (shorter than a shard), and others.
    for lost in [23usize, 0, 7, 16] {
        cold.lose([&data[lost]]).await;
        let resp = cold.cold_get("full.bin", &extent).await;
        resp.expect(200);
        assert_eq!(sha256(&resp.body), sha256(&body));
        assert!(cached(&cold.rig, &extent));
        assert_eq!(cold.rig.bridge.budget.in_use(), 0);
    }

    cold.lose([&data[11]]).await;
    let resp = cold.cold_get("full.bin", &extent).await;
    cold.nothing_served(&resp, &body);

    // With one of the five back, the same request succeeds.
    cold.restore(&data[0]).await;
    let resp = cold.cold_get("full.bin", &extent).await;
    resp.expect(200);
    assert_eq!(sha256(&resp.body), sha256(&body));
}

/// Parity is read only for an extent that lost an article: a read that
/// finds every data article sends one `BODY` each and no other, and one
/// that lost a single article reads a single parity article.
#[tokio::test(flavor = "current_thread")]
async fn parity_is_read_only_when_an_article_is_lost() {
    let cold = parity_cold().await;
    let body = pattern(43, 6_500_000);
    let extent = cold.put_and_post("ten.bin", &body).await;
    let (data, parity) = stripe(&cold, &extent).await;
    assert_eq!((data.len(), parity.len()), (10, 2));

    let before = cold.bodies();
    let resp = cold.cold_get("ten.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);
    assert_eq!(cold.bodies() - before, data.len());

    // The lost article is asked for twice, then one parity article.
    cold.lose([&data[4]]).await;
    let before = cold.bodies();
    let resp = cold.cold_get("ten.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);
    assert_eq!(cold.bodies() - before, data.len() + 1 + 1);
}

/// An article the provider holds with other bytes is a lost article: it
/// is rebuilt, and the bytes the provider sent are not served.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_read_rebuilds_an_article_that_fails_its_hash() {
    let cold = parity_cold().await;
    let body = pattern(47, 6_500_000);
    let extent = cold.put_and_post("ten.bin", &body).await;
    let (data, _) = stripe(&cold, &extent).await;
    cold.damage(&extent, &data, &data[3]).await;
    cold.lose([&data[8]]).await;

    let resp = cold.cold_get("ten.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);
    assert!(cached(&cold.rig, &extent));
}

/// A parity article that fails its hash is not given to the codec: the
/// next one is read in its place. When no other is left, nothing is
/// served.
#[tokio::test(flavor = "current_thread")]
async fn a_parity_article_that_fails_its_hash_is_not_used() {
    let cold = parity_cold().await;
    let body = pattern(53, 6_500_000);
    let extent = cold.put_and_post("ten.bin", &body).await;
    let (data, parity) = stripe(&cold, &extent).await;
    cold.lose([&data[2]]).await;
    let all = [data.clone(), parity.clone()].concat();
    cold.damage(&extent, &all, &parity[0]).await;

    // A rebuild from the damaged article would not match the plan.
    let before = cold.bodies();
    let resp = cold.cold_get("ten.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);
    // Ten data articles, the lost one once more, and both parity
    // articles.
    assert_eq!(cold.bodies() - before, data.len() + 1 + 2);

    // The other parity article is gone as well: within the margin by
    // count, but only one of the two shards needed is intact.
    cold.lose([&parity[1]]).await;
    let resp = cold.cold_get("ten.bin", &extent).await;
    cold.nothing_served(&resp, &body);

    // Two data articles lost and one parity article left: not enough.
    cold.restore(&parity[1]).await;
    cold.lose([&parity[0], &data[9]]).await;
    let resp = cold.cold_get("ten.bin", &extent).await;
    cold.nothing_served(&resp, &body);
}

/// A lost data article and a lost parity article, within what the parity
/// left can rebuild.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_read_rebuilds_with_a_parity_article_lost_too() {
    let cold = parity_cold().await;
    let body = pattern(59, 6_500_000);
    let extent = cold.put_and_post("ten.bin", &body).await;
    let (data, parity) = stripe(&cold, &extent).await;
    cold.lose([&data[0], &parity[0]]).await;

    let resp = cold.cold_get("ten.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);
}

/// A small extent has one parity article: its one lost article is
/// rebuilt, for a ranged GET that needs it as for a whole one; two lost
/// articles are not.
#[tokio::test(flavor = "current_thread")]
async fn a_small_extent_is_rebuilt_from_its_one_parity_article() {
    let cold = parity_cold().await;
    let body = pattern(61, 1_500_000);
    let extent = cold.put_and_post("small.bin", &body).await;
    let (data, parity) = stripe(&cold, &extent).await;
    assert_eq!((data.len(), parity.len()), (3, 1));
    cold.lose([&data[1]]).await;

    evict(&cold.rig, &extent).await;
    let resp = get_range(&cold.rig, &cold.signer, "small.bin", "bytes=900000-900099").await;
    assert_eq!(resp.expect(206).body, body[900_000..900_100]);
    let resp = cold.cold_get("small.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);

    cold.lose([&data[2]]).await;
    let resp = cold.cold_get("small.bin", &extent).await;
    cold.nothing_served(&resp, &body);
}

/// An extent of a single article.
#[tokio::test(flavor = "current_thread")]
async fn an_extent_of_one_article_is_rebuilt_from_its_parity_article() {
    let cold = parity_cold().await;
    let body = pattern(67, 40_000);
    let extent = cold.put_and_post("one.bin", &body).await;
    let (data, parity) = stripe(&cold, &extent).await;
    assert_eq!((data.len(), parity.len()), (1, 1));
    cold.lose([&data[0]]).await;

    let resp = cold.cold_get("one.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);
}

/// An addendum that cannot be read rebuilds nothing: the read of an
/// extent that lost an article fails, and the read of one that lost
/// none is not touched by it.
#[tokio::test(flavor = "current_thread")]
async fn an_addendum_that_cannot_be_read_rebuilds_nothing() {
    let cold = parity_cold().await;
    let body = pattern(71, 1_500_000);
    let extent = cold.put_and_post("small.bin", &body).await;
    let (data, _) = stripe(&cold, &extent).await;
    let changed = cold
        .rig
        .bridge
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET parity = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(extent.id.as_str().into()),
                SqlValue::Blob(vec![1, 0]),
            ],
        )
        .await
        .unwrap();
    assert_eq!(changed, 1);

    let resp = cold.cold_get("small.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);

    cold.lose([&data[1]]).await;
    let resp = cold.cold_get("small.bin", &extent).await;
    cold.nothing_served(&resp, &body);
}

/// A rebuild is a read: it posts nothing, and the GET writes to the
/// catalogue what a cold GET of an extent that lost nothing writes.
#[tokio::test(flavor = "current_thread")]
async fn a_rebuild_posts_nothing_and_writes_nothing_more() {
    let cold = parity_cold().await;
    let body = pattern(73, 1_500_000);
    let extent = cold.put_and_post("small.bin", &body).await;
    let (data, _) = stripe(&cold, &extent).await;
    let db = &cold.rig.bridge.catalog.sql.inner;
    let sqlite = (db.dialect() == Dialect::Sqlite).then(|| db.sqlite());
    if let Some(sql) = sqlite {
        sql.meter_writes().unwrap();
    }
    let posts = |cold: &Cold| {
        let calls = cold.rig.bridge.nntp.calls();
        calls.iter().filter(|call| call.0 == "post").count()
    };

    let before = sqlite.map(|sql| sql.writes());
    cold.cold_get("small.bin", &extent).await.expect(200);
    let plain = sqlite
        .zip(before)
        .map(|(sql, before)| sql.writes().since(&before));

    cold.lose([&data[2]]).await;
    let (posted, held) = (posts(&cold), cold.server.posted_count().await);
    let before = sqlite.map(|sql| sql.writes());
    let resp = cold.cold_get("small.bin", &extent).await;
    resp.expect(200);
    assert!(resp.body == body);
    // sqlite_only: preupdate-hook billing; both engines check output and posts.
    if let (Some(sql), Some(before), Some(plain)) = (sqlite, before, plain) {
        let rebuilt = sql.writes().since(&before);
        assert_eq!(rebuilt.writing_statements, plain.writing_statements);
        assert_eq!(rebuilt.billed(), plain.billed());
    }
    assert_eq!(posts(&cold), posted);
    assert_eq!(cold.server.posted_count().await, held);
}

/// A read whose rebuild found no room waits until there is room for the
/// extent and for the rebuild together, and holds nothing meanwhile. It
/// is not made again as soon as the extent alone fits: that read would
/// be refused its rebuild again, every time.
#[tokio::test(flavor = "current_thread")]
async fn a_read_refused_its_rebuild_waits_for_room_for_both() {
    let polls = Rc::new(Cell::new(0u32));
    let weak: Rc<RefCell<Weak<TestBridge<TcpConnector>>>> = Rc::new(RefCell::new(Weak::new()));
    let taken: Rc<RefCell<Option<Charge>>> = Rc::default();
    let sleeper: Sleeper = {
        let (polls, weak, taken) = (polls.clone(), weak.clone(), taken.clone());
        Rc::new(move |ms| {
            if is_watch(ms) {
                return Box::pin(std::future::pending());
            }
            let bridge = weak.borrow().upgrade().expect("rig is alive");
            let held = taken.borrow().as_ref().map_or(0, Charge::bytes);
            assert_eq!(bridge.budget.in_use(), held, "a waiting read holds budget");
            bridge.clock.advance_ms(i64::from(ms));
            polls.set(polls.get() + 1);
            // Room is made after a few looks.
            if polls.get() == 3 {
                taken.borrow_mut().take();
            }
            Box::pin(async {})
        })
    };
    let cold = parity_cold_with(Some(sleeper)).await;
    *weak.borrow_mut() = Rc::downgrade(&cold.rig.bridge);
    let body = pattern(79, 1_500_000);
    let extent = cold.put_and_post("small.bin", &body).await;
    let (data, parity) = stripe(&cold, &extent).await;
    cold.lose([&data[1]]).await;
    evict(&cold.rig, &extent).await;

    // Room for the read of the extent, one byte short of the rebuild.
    let budget = &cold.rig.bridge.budget;
    let step = velmora_bridge::fetch::cold_step_bytes(
        extent.cipher_size,
        cold.rig.bridge.cfg.cold_sockets,
    );
    let rebuild = velmora_bridge::fetch::cold_rebuild_bytes(parity[0].cipher_len, 1);
    *taken.borrow_mut() = budget.try_charge(budget.capacity() - step - rebuild + 1);
    assert!(taken.borrow().is_some());

    let before = cold.bodies();
    let resp = get(&cold.rig, &cold.signer, "small.bin", &[]).await;

    resp.expect(200);
    assert!(resp.body == body);
    assert!(polls.get() >= 3, "it looked {} times", polls.get());
    // Two reads of the extent: the one that was refused its rebuild
    // (three articles, the lost one asked for twice), and the one that
    // rebuilt (the same and one parity article).
    assert_eq!(cold.bodies() - before, 4 + 5);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(cold.rig.bridge.nntp.live(), 0);
}

thread_local! {
    static COLD_LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The log line of an extent that cannot be rebuilt names the extent.
#[tokio::test(flavor = "current_thread")]
async fn an_unrecoverable_extent_is_named_in_the_log() {
    velmora_bridge::trace::log_cold_reads(|line| {
        COLD_LINES.with(|lines| lines.borrow_mut().push(line.to_owned()));
    });
    let cold = parity_cold().await;
    let body = pattern(83, 1_500_000);
    let extent = cold.put_and_post("small.bin", &body).await;
    let (data, _) = stripe(&cold, &extent).await;
    cold.lose([&data[0], &data[1]]).await;

    let resp = cold.cold_get("small.bin", &extent).await;

    cold.nothing_served(&resp, &body);
    let lines = COLD_LINES.with(|lines| lines.borrow().clone());
    let named = format!("extent-unrecoverable extent={}", extent.id);
    assert_eq!(lines.iter().filter(|line| **line == named).count(), 1);
    assert!(lines
        .iter()
        .any(|line| line.contains(" extent-unrecoverable=1 ")));
}
