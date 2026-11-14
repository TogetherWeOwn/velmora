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
use velmora_bridge::ingress::{ByteBudget, Sleeper, CHARGE_POLL_MS};
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
        .commit_generation(&CommitGeneration {
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
        port: server.addr().port(),
        tls: false,
        user: USER.to_string(),
        pass: PASS.to_string(),
        backbone: "alpha".to_string(),
        post: true,
        read: true,
        max_conns: 2,
        max_ips: None,
        priority: 0,
        retention_days: None,
        pool: None,
        pool_max_conns: None,
        enabled: true,
    }
}

async fn cold_rig() -> Cold {
    cold_rig_with(2, None).await
}

/// A cold-read rig whose provider allows `max_conns` connections and whose
/// byte budget polls with `sleeper` (none: nothing ever waits).
async fn cold_rig_with(max_conns: u32, sleeper: Option<Sleeper>) -> Cold {
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
    assert_eq!(rig.bridge.nntp.connects(), connects + 1);
    assert_eq!(rig.bridge.nntp.live(), 0);

    // The verified ciphertext is now in the cache, and only there.
    let cached = rig.bridge.cache.stored(&extent.id.cache_key()).unwrap();
    assert_eq!(sha256(&cached.bytes), extent.cipher_sha256);
    assert!(rig.bridge.safety.keys().iter().all(|k| k.starts_with("m/")));

    // The next reads are served from the cache without a session.
    let resp = get_range(rig, &cold.signer, "cold.bin", "bytes=999990-1000009").await;
    assert_eq!(resp.expect(206).body, body[999_990..=1_000_009]);
    assert!(get(rig, &cold.signer, "cold.bin", &[]).await.body == body);
    assert_eq!(rig.bridge.nntp.connects(), connects + 1);
    assert_eq!(rig.bridge.budget.in_use(), 0);
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

/// Sleeper that really sleeps 1 ms per poll (so sessions in flight make
/// progress) and adds up the milliseconds the bridge asked for.
fn short_sleeper(asked: Rc<Cell<u64>>, polls: Rc<Cell<u32>>) -> Sleeper {
    Rc::new(move |ms| {
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
type PollHook = Rc<
    RefCell<Option<Box<dyn Fn(u32, Rc<TestBridge<TcpConnector>>) -> LocalBoxFuture<'static, ()>>>>,
>;

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

#[tokio::test(flavor = "current_thread")]
async fn cold_read_waits_for_a_slot_then_slows_down() {
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
    let body = pattern(47, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;

    // Other readers hold every slot for longer than the bound.
    let held = hold_all_slots(rig).await;
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
    let sleeper = fake_cold_sleeper(
        asked.clone(),
        polls.clone(),
        weak.clone(),
        PollHook::default(),
        1_000,
    );
    let cold = cold_rig_with(4, Some(sleeper)).await;
    let rig = &cold.rig;
    *weak.borrow_mut() = Rc::downgrade(&rig.bridge);
    let body = pattern(59, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;
    let _held = hold_all_slots(rig).await;

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
async fn interrupted_cold_read_is_slow_down_without_waiting() {
    // A read that breaks off in transit is not slot contention: it is
    // SlowDown at once, never retried in the wait loop.
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
    let body = pattern(67, 300_000);
    let extent = cold.put_and_post("cold.bin", &body).await;
    evict(rig, &extent).await;
    let connects = rig.bridge.nntp.connects();

    // Every reconnect the read is allowed breaks off mid-body.
    cold.server.drop_next_bodies(3).await;
    let resp = get(rig, &cold.signer, "cold.bin", &[]).await;
    resp.expect_error(503, "SlowDown");
    assert!(resp.header("retry-after").is_some());
    assert_eq!(polls.get(), 0, "an interrupted read was retried");
    assert_eq!(rig.bridge.nntp.connects() - connects, 3, "one fetch only");
    assert!(rig.bridge.cache.keys().is_empty());
    assert_eq!(rig.bridge.nntp.live(), 0);
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
    // A cold read holds the ciphertext twice: once while it is verified
    // and once more for the cache write.
    let need = 2 * extent.cipher_size;

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
