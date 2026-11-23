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
use velmora_bridge::service::{detached_bodies, PIECE_WAIT_MS};
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
    let rig = rig();
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
    let rig = rig();
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
    let rig = rig();
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
    let rig = rig();
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
    let rig = rig();
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
    let rig = rig();
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

#[tokio::test(flavor = "current_thread")]
async fn cache_is_tried_before_the_safety_copy() {
    let rig = rig();
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
    let rig = rig();
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
    let rig = rig();
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
    let rig = rig();
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
    let rig = rig();
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
    ProviderConfig {
        id: "p0".to_string(),
        host: server.addr().ip().to_string(),
        hosts: Vec::new(),
        host_select: Default::default(),
        port: server.addr().port(),
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
    let rig = rig_with_budget(TcpConnector::default(), cfg, budget);
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
    let cold = cold_rig().await;
    let rig = &cold.rig;
    let parts = [
        pattern(77, 300_000),
        pattern(78, 200_000),
        pattern(79, 250_000),
    ];
    let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
    let budget = &rig.bridge.budget;
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

// ---------------------------------------------------------------------------
// A client that goes away: the fill under way survives, nothing new starts
// ---------------------------------------------------------------------------

thread_local! {
    /// The cold-read log lines of this test's thread.
    static COLD_LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn note_cold_read(line: &str) {
    COLD_LINES.with(|lines| lines.borrow_mut().push(line.to_string()));
}

/// The cold-read lines logged since the last call.
fn cold_lines() -> Vec<String> {
    COLD_LINES.with(|lines| std::mem::take(&mut *lines.borrow_mut()))
}

/// What the catalogue counts of the extent's cache copy.
fn cache_counted(rig: &Rig<TcpConnector>, extent: &ExtentRow) -> i64 {
    rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row(
            "SELECT hot_cache_bytes FROM extents WHERE id = ?1",
            [extent.id.as_str()],
            |r| r.get(0),
        )
        .unwrap()
    })
}

/// The catalogue counts a cache copy exactly when the cache has it.
fn counted_as_cached(rig: &Rig<TcpConnector>, extent: &ExtentRow) -> bool {
    match cached(rig, extent) {
        true => cache_counted(rig, extent) == extent.cipher_size as i64,
        false => cache_counted(rig, extent) == 0,
    }
}

/// A GET of `key` on the rig, the body not read yet.
async fn open_body(
    cold: &Cold,
    key: &str,
) -> futures_util::stream::LocalBoxStream<'static, Result<Vec<u8>>> {
    let rig = &cold.rig;
    let req = cold.signer.sign(
        rig.now(),
        Method::Get,
        &path(BUCKET, key),
        &[],
        &[],
        Vec::new(),
    );
    let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
    assert_eq!(resp.status, 200);
    let RespBody::Stream(body) = resp.body else {
        panic!("a GET body is a stream");
    };
    body
}

/// Everything a body held is given back once its detached work ended:
/// no connection, every read slot free, nothing of the byte budget.
async fn all_given_back(rig: &Rig<TcpConnector>) {
    eventually("the detached body ends", || detached_bodies() == 0).await;
    assert_eq!(rig.bridge.nntp.live(), 0, "no connection is left open");
    assert_eq!(free_slots(rig).await, 2, "every read slot is free");
    assert_eq!(rig.bridge.budget.in_use(), 0, "the budget is given back");
}

/// A client that goes away while the cache write of a verified extent is
/// under way: the write completes, and the catalogue counts the copy
/// that the cache has. The connections end at once, and no other extent
/// is read.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_lets_the_cache_write_under_way_finish() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [
            pattern(101, 300_000),
            pattern(102, 300_000),
            pattern(103, 300_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
        let cache = &rig.bridge.cache;
        *cache.hold_put_prefix.borrow_mut() = Some(extents[1].id.cache_key());

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        // The task reads the second extent ahead; its cache write waits.
        eventually("the second cache write is under way", || cache.held.get()).await;
        assert!(!cached(rig, &extents[1]));
        assert_eq!(detached_bodies(), 0);

        let connects = rig.bridge.nntp.connects();
        drop(body);
        assert_eq!(detached_bodies(), 1, "counted at once");
        // The piece nobody takes is given up; the ciphertext being
        // written stays charged until the write ends.
        assert_eq!(rig.bridge.budget.in_use(), extents[1].cipher_size);
        eventually("the connections end before the write", || {
            rig.bridge.nntp.live() == 0
        })
        .await;
        assert_eq!(free_slots(rig).await, 2);
        assert_eq!(detached_bodies(), 1, "the write is still under way");
        assert!(!cached(rig, &extents[1]));

        *cache.hold_put_prefix.borrow_mut() = None;
        all_given_back(rig).await;
        assert!(cached(rig, &extents[1]), "the write completed");
        for extent in &extents {
            assert!(counted_as_cached(rig, extent));
        }
        assert!(!cached(rig, &extents[2]), "no other extent was read");
        assert!(cache
            .puts
            .borrow()
            .iter()
            .all(|(key, _)| *key != extents[2].id.cache_key()));
        assert_eq!(rig.bridge.nntp.connects(), connects, "no new connection");
    };
    local.run_until(test).await;
}

/// A client that goes away while an extent is read from Usenet: that
/// read finishes, is verified and lands in the cache, counted; no other
/// extent is begun, and the slots and the budget are given back once,
/// when the read and its write have ended.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_lets_the_usenet_read_under_way_finish_and_starts_no_other() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        velmora_bridge::trace::log_cold_reads(note_cold_read);
        let parts = [
            pattern(111, 300_000),
            pattern(112, 300_000),
            pattern(113, 300_000),
        ];
        // The first piece comes from the cache: every BODY after this
        // point reads the second extent or a later one.
        let extents = cold_parts(&cold, "multi", &parts, &[0], &[]).await;
        let server = &cold.server;
        server.set_hold_bodies(true).await;
        let asked = server.bodies_asked().await;
        cold_lines();

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        for _ in 0..400 {
            if server.bodies_asked().await > asked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let reading = server.bodies_asked().await;
        assert!(reading > asked, "the second extent is being read");
        assert!(!cached(rig, &extents[1]));

        drop(body);
        assert_eq!(detached_bodies(), 1);
        // Nothing gives up the read: it is still waiting for its BODY.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(detached_bodies(), 1);
        assert!(!cached(rig, &extents[1]));
        server.set_hold_bodies(false).await;

        all_given_back(rig).await;
        assert!(cached(rig, &extents[1]), "the read under way was cached");
        for extent in &extents {
            assert!(counted_as_cached(rig, extent));
        }
        assert!(!cached(rig, &extents[2]), "no other extent was read");
        // Every BODY after the disconnect belongs to the read under way.
        let read = server.bodies_asked().await - asked;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            server.bodies_asked().await - asked,
            read,
            "nothing more is read"
        );
        let lines = cold_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("extents=1 begun=1 "), "{lines:?}");
        assert!(lines[0].ends_with(" reader_gone=1"), "{lines:?}");
    };
    local.run_until(test).await;
}

/// A client that goes away while its body waits for a provider slot: the
/// wait ends then, and no read from Usenet is begun when a slot frees.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_ends_a_wait_for_a_slot_without_a_read() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [pattern(141, 300_000), pattern(142, 300_000)];
        let extents = cold_parts(&cold, "multi", &parts, &[0], &[]).await;
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
        assert_eq!(held.len(), 2);
        let asked = cold.server.bodies_asked().await;

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        // The second extent waits for a slot, well inside its wait.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(detached_bodies(), 0);
        drop(body);
        assert_eq!(detached_bodies(), 1);
        // The slots free while the wait would still go on.
        for permit in &held {
            rig.bridge.catalog.release_permit(permit).await.unwrap();
        }
        eventually("the wait for a slot ends", || detached_bodies() == 0).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(cold.server.bodies_asked().await, asked, "no read was begun");
        all_given_back(rig).await;
        assert!(!cached(rig, &extents[1]));
        assert!(counted_as_cached(rig, &extents[1]));
    };
    local.run_until(test).await;
}

/// A client that goes away while its body opens the connections for the
/// next extent: the extent is not begun, no BODY is sent, and the
/// connections it opened are ended.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_before_the_first_body_of_an_extent_begins_no_read() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [pattern(161, 300_000), pattern(162, 300_000)];
        // The first piece comes from the cache: the second extent's read
        // opens its connections first.
        let extents = cold_parts(&cold, "multi", &parts, &[0], &[]).await;
        let server = &cold.server;
        server.set_hold_logins(true).await;
        let asked = server.bodies_asked().await;

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        for _ in 0..400 {
            if server.logins_held().await > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            server.logins_held().await > 0,
            "a connection is being opened"
        );
        drop(body);
        assert_eq!(detached_bodies(), 1);
        server.set_hold_logins(false).await;
        all_given_back(rig).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(server.bodies_asked().await, asked, "no BODY was sent");
        assert!(!cached(rig, &extents[1]));
        assert!(counted_as_cached(rig, &extents[1]));
    };
    local.run_until(test).await;
}

/// A client that goes away while an extent is read beside the cache
/// write of the one before, under the part of its charge that reading
/// needs: when the write ends, another request takes the room it gave
/// back. The read still finishes and lands in the cache, since nobody
/// takes its plaintext: it is authenticated without making it.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_keeps_the_fill_when_the_room_to_open_it_is_taken() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        // The second extent is larger than the wire text of the sockets
        // after the first: beside a write it is read under the lean
        // charge only.
        let parts = [
            pattern(171, 300_000),
            pattern(172, 5_000_000),
            pattern(173, 300_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;
        let (server, cache, budget) = (&cold.server, &rig.bridge.cache, &rig.bridge.budget);
        *cache.hold_put_prefix.borrow_mut() = Some(extents[0].id.cache_key());
        let first = rig
            .bridge
            .catalog
            .articles(&extents[0].id)
            .await
            .unwrap()
            .len();
        let asked = server.bodies_asked().await;
        server.set_hold_bodies_after(Some(asked + first)).await;

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        for _ in 0..400 {
            if server.bodies_asked().await > asked + first {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            server.bodies_asked().await > asked + first,
            "the second extent is read"
        );
        assert!(cache.held.get(), "beside the first extent's write");
        drop(body);
        *cache.hold_put_prefix.borrow_mut() = None;
        eventually("the first write ends", || cached(rig, &extents[0])).await;
        // Another request takes every byte of room that is left.
        let hog = budget
            .try_charge(budget.capacity() - budget.in_use())
            .expect("the room that is left");
        server.set_hold_bodies_after(None).await;
        eventually("the detached body ends", || detached_bodies() == 0).await;
        assert!(cached(rig, &extents[1]), "the read under way was cached");
        assert!(!cached(rig, &extents[2]));
        drop(hog);
        all_given_back(rig).await;
        for extent in &extents {
            assert!(counted_as_cached(rig, extent));
        }
    };
    local.run_until(test).await;
}

/// A client that goes away while an extent is read, and the provider
/// then breaks off every BODY: the read is not tried again for nobody,
/// nothing is cached, and everything is given back once.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_racing_a_provider_error_gives_everything_back_once() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [
            pattern(181, 300_000),
            pattern(182, 300_000),
            pattern(183, 300_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[0], &[]).await;
        let server = &cold.server;
        server.set_hold_bodies(true).await;
        let asked = server.bodies_asked().await;

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        for _ in 0..400 {
            if server.bodies_asked().await > asked {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(server.bodies_asked().await > asked);
        // The provider error and the disconnect land together.
        server.drop_next_bodies(1_000).await;
        drop(body);
        server.set_hold_bodies(false).await;
        all_given_back(rig).await;
        server.drop_next_bodies(0).await;
        let read = server.bodies_asked().await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(server.bodies_asked().await, read, "not tried again");
        assert!(!cached(rig, &extents[1]) && !cached(rig, &extents[2]));
        for extent in &extents {
            assert!(counted_as_cached(rig, extent));
        }
    };
    local.run_until(test).await;
}

/// A client that goes away while a piece waits for room behind the cache
/// write of an extent read earlier, with no connection open: the wait
/// ends, and the write it waited for still completes and is counted.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_during_a_wait_for_room_keeps_the_write_it_waited_for() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [
            pattern(191, 300_000),
            pattern(192, 300_000),
            pattern(193, 300_000),
            pattern(194, 300_000),
        ];
        // The third is in the cache: serving it ends the connections.
        let extents = cold_parts(&cold, "multi", &parts, &[2], &[]).await;
        let (cache, budget) = (&rig.bridge.cache, &rig.bridge.budget);
        *cache.hold_put_prefix.borrow_mut() = Some(extents[1].id.cache_key());

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        assert!(body.next().await.unwrap().unwrap() == parts[1]);
        eventually("the third piece waits, beside the held write", || {
            cache.held.get()
                && rig.bridge.nntp.live() == 0
                && budget.in_use() == parts[2].len() as u64 + extents[1].cipher_size
        })
        .await;
        // Every byte of room that is left goes to another request: the
        // fourth piece waits for the held write to give its room back.
        let hog = budget
            .try_charge(budget.capacity() - budget.in_use())
            .expect("the room that is left");
        assert!(body.next().await.unwrap().unwrap() == parts[2]);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!cached(rig, &extents[1]));
        drop(body);
        assert_eq!(detached_bodies(), 1);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        *cache.hold_put_prefix.borrow_mut() = None;
        eventually("the detached body ends", || detached_bodies() == 0).await;
        assert!(cached(rig, &extents[1]), "the write waited for completed");
        assert!(!cached(rig, &extents[3]));
        drop(hog);
        all_given_back(rig).await;
        for extent in &extents {
            assert!(counted_as_cached(rig, extent));
        }
    };
    local.run_until(test).await;
}

/// A client that goes away just as its body has ended, with only the last
/// piece left to take: nothing is left to do, and everything is given
/// back once.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_that_races_the_end_of_a_body_gives_everything_back_once() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [pattern(121, 300_000), pattern(122, 300_000)];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[]).await;

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        // The last piece is made, its write and connections have ended,
        // and it waits to be taken.
        eventually("the last piece waits", || {
            cached(rig, &extents[1])
                && rig.bridge.nntp.live() == 0
                && rig.bridge.budget.in_use() == parts[1].len() as u64
        })
        .await;
        drop(body);
        all_given_back(rig).await;
        for extent in &extents {
            assert!(cached(rig, extent) && counted_as_cached(rig, extent));
        }

        // A body read to its end and then dropped leaves nothing behind.
        for extent in &extents {
            evict(rig, extent).await;
        }
        let mut body = open_body(&cold, "multi").await;
        while let Some(piece) = body.next().await {
            piece.unwrap();
        }
        drop(body);
        assert_eq!(detached_bodies(), 0);
        all_given_back(rig).await;
    };
    local.run_until(test).await;
}

/// A client that goes away after the body failed (an extent no provider
/// has), with the error not taken yet: everything is given back once,
/// and what was read before is in the cache, counted.
#[tokio::test(flavor = "current_thread")]
async fn a_disconnect_after_a_failed_extent_gives_everything_back_once() {
    let local = tokio::task::LocalSet::new();
    let test = async {
        let cold = cold_rig_on(2, Some(real_sleeper()), Some(local_spawner())).await;
        let rig = &cold.rig;
        let parts = [
            pattern(131, 300_000),
            pattern(132, 300_000),
            pattern(133, 300_000),
        ];
        let extents = cold_parts(&cold, "multi", &parts, &[], &[1]).await;

        let mut body = open_body(&cold, "multi").await;
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        // The second extent fails; the error waits to be taken.
        eventually("the error waits", || {
            rig.bridge.nntp.live() == 0 && rig.bridge.budget.in_use() == 0
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(body);
        all_given_back(rig).await;
        assert!(cached(rig, &extents[0]));
        assert!(!cached(rig, &extents[1]) && !cached(rig, &extents[2]));
        for extent in &extents {
            assert!(counted_as_cached(rig, extent));
        }
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
        let cold = cold_rig_on(2, Some(sleeper), Some(local_spawner())).await;
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
        let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
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
        // The time the connections may sit idle is 20 ms here; a piece
        // waits for its reader as long as it says.
        let sleeper = timed_sleeper(|ms| match ms > 20_000 {
            true => 20,
            false => ms.into(),
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
        eventually("the first piece waits", || {
            cached(rig, &extents[0]) && budget.in_use() == 300_000
        })
        .await;
        assert!(rig.bridge.nntp.live() > 0, "kept for the next extent");
        let connects = rig.bridge.nntp.connects();
        // Another request takes all the room there is.
        let other = budget.try_charge(budget.capacity() - 300_000).unwrap();
        assert!(body.next().await.unwrap().unwrap() == parts[0]);
        eventually("the connections are ended", || rig.bridge.nntp.live() == 0).await;
        assert!(!cached(rig, &extents[1]));
        assert_eq!(free_slots(rig).await, 2);
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

        let resp = get(&rig, &signer, "cold.bin", &[]).await;
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

    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
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

    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
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
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let (_, extents) = rig.live(&bucket, "k").await.unwrap();
    evict(&rig, &extents[0]).await;
    let resp = get(&rig, &signer, "k", &[]).await;
    resp.expect_error(503, "ServiceUnavailable");
    // The catalogue still knows the object.
    rig.head(&signer, BUCKET, "k").await.expect(200);
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
    let rig = rig_with(TcpConnector::default(), cfg);
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
