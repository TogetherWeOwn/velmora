//! GetObject as it reads from the cache and the safety copy: one round
//! trip to the catalogue, and a body that goes out block by block as its
//! ciphertext arrives, each block authenticated before it leaves.

mod service_support;

use std::rc::Rc;

use futures_util::future::{ready, FutureExt};
use futures_util::StreamExt;
use service_support::*;
use velmora::media::{CIPHER_CHUNK_SIZE, HEADER_SIZE, PLAIN_CHUNK_SIZE};
use velmora_bridge::ingress::{ByteBudget, Sleeper};
use velmora_bridge::*;

const BUCKET: &str = "bkt-flow";
const CHUNK: usize = PLAIN_CHUNK_SIZE as usize;

/// Offset in an extent's ciphertext of byte `at` of sealed chunk `index`.
fn sealed_at(index: u64, at: u64) -> usize {
    (HEADER_SIZE + index * CIPHER_CHUNK_SIZE + at) as usize
}

async fn get(rig: &Rig, signer: &Signer, key: &str, headers: &[(&str, &str)]) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], headers, b"")
        .await
}

/// The items of a GET body as the service hands them over.
async fn items(rig: &Rig, signer: &Signer, key: &str) -> (Vec<Vec<u8>>, bool) {
    let req = signer.sign(
        rig.now(),
        Method::Get,
        &path(BUCKET, key),
        &[],
        &[],
        Vec::new(),
    );
    let resp = Rc::clone(&rig.bridge).handle(req.into_request()).await;
    assert_eq!(resp.status, 200);
    let RespBody::Stream(mut body) = resp.body else {
        panic!("a GET body is a stream");
    };
    let mut out = Vec::new();
    while let Some(item) = body.next().await {
        match item {
            Ok(bytes) => out.push(bytes),
            Err(_) => return (out, false),
        }
    }
    (out, true)
}

/// A rig whose puts are cut into extents of two sealed chunks.
fn small_extents() -> Rig {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = 2 * PLAIN_CHUNK_SIZE;
    cfg.slice_bytes = 2 * PLAIN_CHUNK_SIZE;
    rig_with(NoNntp, cfg)
}

fn round_trips(rig: &Rig) -> u64 {
    rig.bridge.catalog.sql.trips.get()
}

#[tokio::test(flavor = "current_thread")]
async fn a_read_is_one_round_trip_to_the_catalogue() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(3, 300_000);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);

    // The first read stamps the extent as read, beside the body.
    let before = round_trips(&rig);
    assert_eq!(get(&rig, &signer, "k", &[]).await.expect(200).body, body);
    let first = round_trips(&rig) - before;
    assert!((2..=3).contains(&first), "lookup and stamp: {first}");

    // From then on, within the hour: the lookup alone.
    let before = round_trips(&rig);
    assert_eq!(get(&rig, &signer, "k", &[]).await.expect(200).body, body);
    assert_eq!(round_trips(&rig) - before, 1, "full GET");

    let before = round_trips(&rig);
    let resp = get(&rig, &signer, "k", &[("range", "bytes=70000-140000")]).await;
    assert_eq!(resp.expect(206).body, body[70_000..=140_000]);
    assert_eq!(round_trips(&rig) - before, 1, "ranged GET");

    let before = round_trips(&rig);
    let resp = get(&rig, &signer, "k", &[("range", "bytes=-5")]).await;
    assert_eq!(resp.expect(206).body, body[299_995..]);
    assert_eq!(round_trips(&rig) - before, 1, "suffix range");

    let before = round_trips(&rig);
    rig.head(&signer, BUCKET, "k").await.expect(200);
    assert_eq!(round_trips(&rig) - before, 1, "HEAD");

    // Answers that need no extent cost the same one.
    let before = round_trips(&rig);
    get(&rig, &signer, "absent", &[])
        .await
        .expect_error(404, "NoSuchKey");
    let resp = get(&rig, &signer, "k", &[("if-match", "\"nope\"")]).await;
    resp.expect_error(412, "PreconditionFailed");
    let resp = get(&rig, &signer, "k", &[("range", "bytes=300000-")]).await;
    resp.expect_error(416, "InvalidRange");
    assert_eq!(round_trips(&rig) - before, 3);
}

/// Ranges over an object of several extents: the lookup brings the
/// extents of the range it reads from the header, and a header it
/// cannot read is left to the parser of ranges.
#[tokio::test(flavor = "current_thread")]
async fn ranges_over_several_extents_and_headers_the_lookup_cannot_read() {
    let rig = small_extents();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(4, 9 * CHUNK + 1234);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);
    let (_, extents) = rig.live(&bucket, "k").await.unwrap();
    assert_eq!(extents.len(), 5);
    let end = body.len() - 1;
    for (range, want) in [
        ("bytes=131072-262144", &body[131_072..=262_144]),
        ("bytes=131071-131072", &body[131_071..=131_072]),
        ("bytes=590000-99999999", &body[590_000..]),
        ("bytes=-1", &body[end..]),
        ("bytes=-99999999", &body[..]),
        ("bytes=0-", &body[..]),
    ] {
        let resp = get(&rig, &signer, "k", &[("range", range)]).await;
        assert!(resp.expect(206).body == want, "{range}");
    }
    // Range headers the lookup cannot read are judged as they always
    // were, by the one parser of ranges.
    for (range, status, code) in [
        ("bytes=0-0,5-9", 400, "InvalidRequest"),
        ("bytes= 5 - 9", 416, "InvalidRange"),
        ("lines=1-2", 416, "InvalidRange"),
        ("bytes=9-5", 416, "InvalidRange"),
        ("bytes=-0", 416, "InvalidRange"),
        ("bytes=18446744073709551615-", 416, "InvalidRange"),
    ] {
        let resp = get(&rig, &signer, "k", &[("range", range)]).await;
        resp.expect_error(status, code);
    }
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_body_leaves_in_blocks_as_its_ciphertext_arrives() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(7, 20 * CHUNK + 777);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);
    for chunk in [1_000, 65_551, 65_552, 65_553, 500_000] {
        rig.bridge.safety.inner.stream_in(chunk);
        let (blocks, whole) = items(&rig, &signer, "k").await;
        assert!(whole, "{chunk}");
        assert!(blocks.concat() == body, "{chunk}");
        // The first block is out as soon as its chunks are there, long
        // before the extent is.
        let first = blocks[0].len();
        assert!(first % CHUNK == 0 && first <= 8 * CHUNK, "{chunk}: {first}");
        assert!(blocks.len() > 2, "{chunk}: {}", blocks.len());
        assert_eq!(rig.bridge.budget.in_use(), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn range_edges_of_a_body_that_arrives_in_chunks() {
    let rig = small_extents();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(8, 7 * CHUNK + 4321);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);
    let n = body.len();
    let edges = [
        (0, 0),
        (0, CHUNK - 1),
        (0, CHUNK),
        (CHUNK - 1, CHUNK),
        (CHUNK, CHUNK),
        (2 * CHUNK - 1, 2 * CHUNK),
        (2 * CHUNK, 4 * CHUNK - 1),
        (1, n - 2),
        (3 * CHUNK + 5, 6 * CHUNK + 5),
        (n - 1, n - 1),
        (7 * CHUNK, n - 1),
        (0, n - 1),
    ];
    for chunk in [0, 4_097, 65_552, 70_000] {
        rig.bridge.safety.inner.stream_in(chunk);
        for (first, last) in edges {
            let range = format!("bytes={first}-{last}");
            let resp = get(&rig, &signer, "k", &[("range", &range)]).await;
            assert!(
                resp.expect(206).body == body[first..=last],
                "{chunk} {range}"
            );
            let want = format!("bytes {first}-{last}/{n}");
            assert_eq!(resp.header("content-range"), Some(want.as_str()));
        }
        let resp = get(&rig, &signer, "k", &[]).await;
        assert!(resp.expect(200).body == body, "{chunk}");
        let resp = get(&rig, &signer, "k", &[("range", "bytes=-4322")]).await;
        assert!(resp.expect(206).body == body[n - 4322..], "{chunk}");
        assert_eq!(rig.bridge.budget.in_use(), 0);
    }
}

/// Copies an extent's safety blob into the cache.
async fn warm_cache(rig: &Rig, bucket: &Bucket, extent: &ExtentRow) {
    let blob = rig.bridge.safety.stored(&extent.id.safety_key()).unwrap();
    let meta = BlobMeta {
        bucket: &bucket.id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    let key = extent.id.cache_key();
    rig.bridge.cache.put(&key, blob.bytes, &meta).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_chunk_that_fails_in_mid_stream_is_never_sent() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(9, 12 * CHUNK + 99);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);
    let (_, extents) = rig.live(&bucket, "k").await.unwrap();
    let extent = &extents[0];
    warm_cache(&rig, &bucket, extent).await;
    rig.bridge.cache.inner.stream_in(30_000);
    rig.bridge.safety.inner.stream_in(30_000);
    let (cache_key, safety_key) = (extent.id.cache_key(), extent.id.safety_key());

    // Chunk 6 of the cache copy is damaged, in its text and then in its
    // tag: the blocks before it leave, and the rest comes from the
    // safety copy. The body is whole, each byte once.
    for at in [10, CIPHER_CHUNK_SIZE - 1] {
        let flip = |b: &mut Vec<u8>| b[sealed_at(6, at)] ^= 0x40;
        assert!(rig.bridge.cache.inner.corrupt(&cache_key, flip));
        let (blocks, whole) = items(&rig, &signer, "k").await;
        assert!(whole && blocks.len() > 1);
        assert!(blocks.concat() == body);
        assert!(rig.bridge.cache.inner.corrupt(&cache_key, flip));
    }

    // Two chunks of the cache copy swapped: each is authentic, neither
    // is where it belongs.
    let swap = |b: &mut Vec<u8>| {
        let (a, z) = (sealed_at(4, 0), sealed_at(5, 0));
        let (head, tail) = b.split_at_mut(z);
        head[a..].swap_with_slice(&mut tail[..CIPHER_CHUNK_SIZE as usize]);
    };
    assert!(rig.bridge.cache.inner.corrupt(&cache_key, swap));
    let (blocks, whole) = items(&rig, &signer, "k").await;
    assert!(whole && blocks.concat() == body);
    assert!(rig.bridge.cache.inner.corrupt(&cache_key, swap));

    // A cache copy cut short in the middle, and one with bytes added.
    assert!(rig
        .bridge
        .cache
        .inner
        .corrupt(&cache_key, |b| b.truncate(sealed_at(7, 500))));
    let (blocks, whole) = items(&rig, &signer, "k").await;
    assert!(whole && blocks.concat() == body);

    // The same chunk damaged in both copies, and nothing posted: what
    // was authenticated before it is sent, nothing of it or after it,
    // and the body ends as an error, short of its length.
    warm_cache(&rig, &bucket, extent).await;
    let flip = |b: &mut Vec<u8>| b[sealed_at(6, 10)] ^= 1;
    assert!(rig.bridge.cache.inner.corrupt(&cache_key, flip));
    assert!(rig.bridge.safety.inner.corrupt(&safety_key, flip));
    let (blocks, whole) = items(&rig, &signer, "k").await;
    assert!(!whole, "the body must end in an error");
    let sent = blocks.concat();
    assert!(
        sent.len() >= CHUNK && sent.len() <= 6 * CHUNK,
        "{}",
        sent.len()
    );
    assert!(sent == body[..sent.len()], "only authenticated bytes left");
    let resp = get(&rig, &signer, "k", &[]).await;
    assert_eq!(resp.status, 200);
    assert!(resp.stream_error.is_some());
    assert_eq!(resp.header("content-length"), Some("786531"));
    assert!(resp.body.len() <= 6 * CHUNK && resp.body == body[..resp.body.len()]);
    // A range of the damaged chunk alone has sent nothing: an error
    // response, not a body.
    let range = format!("bytes={}-{}", 6 * CHUNK + 5, 6 * CHUNK + 9);
    get(&rig, &signer, "k", &[("range", &range)])
        .await
        .expect_error(503, "ServiceUnavailable");
    // And so has a body whose first chunk is the damaged one.
    let flip = |b: &mut Vec<u8>| b[sealed_at(0, 10)] ^= 1;
    assert!(rig.bridge.cache.inner.corrupt(&cache_key, flip));
    assert!(rig.bridge.safety.inner.corrupt(&safety_key, flip));
    get(&rig, &signer, "k", &[])
        .await
        .expect_error(503, "ServiceUnavailable");
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// A timer that is over at once: a store that does not answer when it
/// is first asked counts as stalled.
fn at_once() -> Sleeper {
    Rc::new(|_| ready(()).boxed_local())
}

#[tokio::test(flavor = "current_thread")]
async fn a_body_that_stalls_is_read_on_from_a_second_read_without_a_byte_twice() {
    let cfg = config(Vec::new());
    let budget = ByteBudget::new(cfg.inflight_budget_bytes).with_sleeper(at_once());
    let rig = rig_with_budget(NoNntp, cfg, budget);
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(11, 10 * CHUNK + 5);
    rig.put(&signer, BUCKET, "k", &body).await.expect(200);
    let safety = &rig.bridge.safety.inner;
    safety.stream_in(20_000);

    // The body stops after 150 000 bytes, in the middle of a chunk.
    let before = safety.gets();
    safety.stall_next_body_after(150_000);
    let (blocks, whole) = items(&rig, &signer, "k").await;
    assert!(whole);
    assert!(blocks.concat() == body);
    assert_eq!(safety.gets() - before, 2, "the read and one second read");

    // A range, stalled before its first byte.
    let before = safety.gets();
    safety.stall_next_body_after(0);
    let resp = get(&rig, &signer, "k", &[("range", "bytes=100000-400000")]).await;
    assert!(resp.expect(206).body == body[100_000..=400_000]);
    assert_eq!(safety.gets() - before, 2);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}
