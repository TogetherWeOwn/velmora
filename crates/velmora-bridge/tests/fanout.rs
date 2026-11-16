//! Large GETs in sub-ranges (`velmora_bridge::fanout`): the front's
//! response is the one a single invocation would give, each sub-request
//! is admitted by its token alone, all sub-ranges come from the
//! generation the front planned, and a failing sub-range fails the
//! download instead of shortening it.

mod service_support;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use futures_util::StreamExt;
use service_support::*;
use velmora_bridge::fanout::{
    self, Fanout, FanoutError, Grant, Refused, SubPipe, SubRequest, SubResponse, INTERNAL_TARGET,
    MAX_SUBRANGES, TOKEN_HEADER, TOKEN_TTL_MS,
};
use velmora_bridge::testkit::TestKek;
use velmora_bridge::*;

const BUCKET: &str = "bkt-fan";
/// Extents of 256 bytes, sub-ranges of 1000: no sub-range boundary falls
/// on an extent boundary.
const SLICE: u64 = 256;
const CHUNK: u64 = 1000;
const SIZE: usize = 4000;

fn fan_rig(chunk: Option<u64>) -> Rig {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = 1024;
    cfg.slice_bytes = SLICE;
    cfg.max_put_bytes = 16 * SLICE;
    cfg.get_fanout_bytes = chunk;
    rig_with(NoNntp, cfg)
}

type Before = Box<dyn Fn(u64)>;
type Forge = Box<dyn Fn(&SubRequest) -> String>;

/// What the test does to the service binding.
#[derive(Default)]
struct Faults {
    /// Runs before sub-request `n` is sent (0-based, counting retries).
    before: RefCell<Option<Before>>,
    /// Rewrites the token of every sub-request.
    forge: RefCell<Option<Forge>>,
    /// Extra headers on every sub-request.
    headers: RefCell<Vec<(String, String)>>,
}

/// The service binding and the client's stream, in memory: a sub-request
/// is handled by the same bridge, and a piped body is appended to `out`.
struct Loopback<'a> {
    rig: &'a Rig,
    faults: Faults,
    sent: RefCell<Vec<SubRequest>>,
    slept: RefCell<Vec<u32>>,
    out: RefCell<Vec<u8>>,
    closed: Cell<bool>,
    aborted: Cell<bool>,
    discarded: Cell<u32>,
}

impl<'a> Loopback<'a> {
    fn new(rig: &'a Rig) -> Self {
        Loopback {
            rig,
            faults: Faults::default(),
            sent: RefCell::default(),
            slept: RefCell::default(),
            out: RefCell::default(),
            closed: Cell::new(false),
            aborted: Cell::new(false),
            discarded: Cell::new(0),
        }
    }
}

fn sub_request(token: &str, extra: &[(String, String)]) -> S3Request {
    let mut headers = vec![(TOKEN_HEADER.to_string(), token.to_string())];
    headers.extend(extra.iter().cloned());
    S3Request {
        method: Method::Get,
        raw_target: INTERNAL_TARGET.to_string(),
        headers,
        body: Body::Empty,
    }
}

impl SubPipe for Loopback<'_> {
    type Body = (RespBody, Option<u64>);

    async fn open(
        &self,
        sub: &SubRequest,
    ) -> std::result::Result<SubResponse<Self::Body>, FanoutError> {
        let n = self.sent.borrow().len() as u64;
        if let Some(before) = self.faults.before.borrow().as_ref() {
            before(n);
        }
        self.sent.borrow_mut().push(sub.clone());
        let token = match self.faults.forge.borrow().as_ref() {
            Some(forge) => forge(sub),
            None => sub.token.clone(),
        };
        let req = sub_request(&token, &self.faults.headers.borrow());
        let resp = Rc::clone(&self.rig.bridge).handle(req).await;
        let length = resp
            .headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .and_then(|(_, v)| v.parse().ok());
        Ok(SubResponse {
            status: resp.status,
            length,
            body: (resp.body, length),
        })
    }

    /// As the runtime does it: the body must run to its declared length.
    async fn pipe(&self, (body, length): Self::Body) -> std::result::Result<(), FanoutError> {
        let RespBody::Stream(mut stream) = body else {
            return Err(FanoutError::Pipe);
        };
        let mut got = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| FanoutError::Pipe)?;
            got += chunk.len() as u64;
            self.out.borrow_mut().extend_from_slice(&chunk);
        }
        (Some(got) == length).then_some(()).ok_or(FanoutError::Pipe)
    }

    async fn refusal(&self, (body, _): Self::Body, cap: usize) -> Vec<u8> {
        match body {
            RespBody::Bytes(mut bytes) => {
                bytes.truncate(cap);
                bytes
            }
            _ => Vec::new(),
        }
    }

    async fn discard(&self, _: Self::Body) {
        self.discarded.set(self.discarded.get() + 1);
    }

    async fn sleep(&self, ms: u32) {
        self.slept.borrow_mut().push(ms);
    }

    async fn close(&self) -> std::result::Result<(), FanoutError> {
        self.closed.set(true);
        Ok(())
    }

    async fn abort(&self) {
        self.aborted.set(true);
    }
}

/// The front's answer to a signed GET: status, headers and the body plan.
async fn front(rig: &Rig, signer: &Signer, key: &str, headers: &[(&str, &str)]) -> S3Response {
    let req = signer.sign(
        rig.now(),
        Method::Get,
        &path(BUCKET, key),
        &[],
        headers,
        Vec::new(),
    );
    Rc::clone(&rig.bridge).handle(req.into_request()).await
}

fn fanout_of(resp: S3Response) -> (u16, Vec<(String, String)>, Fanout) {
    match resp.body {
        RespBody::Fanout(fan) => (resp.status, resp.headers, fan),
        _ => panic!("status {}: not a body in sub-ranges", resp.status),
    }
}

/// Drives a planned body to its end through `pipe`.
async fn drive(fan: &Fanout, pipe: &Loopback<'_>) -> std::result::Result<(), FanoutError> {
    let first = fan
        .open_first(pipe, || S3Response::error(500, "InternalError", "x"))
        .await
        .map_err(|resp| FanoutError::Status(resp.status))?;
    fan.pump(pipe, first).await
}

fn sorted(mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers.sort();
    headers
}

async fn seeded(chunk: Option<u64>) -> (Rig, Bucket, Signer, Vec<u8>) {
    let rig = fan_rig(chunk);
    let (bucket, signer) = rig.standard(BUCKET).await;
    let data = pattern(7, SIZE);
    rig.put(&signer, BUCKET, "big", &data).await.expect(200);
    (rig, bucket, signer, data)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn full_get_is_served_in_sub_ranges_with_the_same_headers() {
    let (rig, bucket, signer, data) = seeded(Some(CHUNK)).await;
    assert_eq!(rig.live(&bucket, "big").await.unwrap().1.len(), 16);

    let (status, headers, fan) = fanout_of(front(&rig, &signer, "big", &[]).await);
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "content-length"), Some("4000"));
    assert_eq!((fan.len(), fan.count()), (4000, 4));

    let pipe = Loopback::new(&rig);
    drive(&fan, &pipe).await.unwrap();
    assert_eq!(*pipe.out.borrow(), data);
    assert!(pipe.closed.get() && !pipe.aborted.get());
    let spans: Vec<(u64, u64, u64)> = pipe
        .sent
        .borrow()
        .iter()
        .map(|s| (s.index, s.start, s.len))
        .collect();
    assert_eq!(
        spans,
        [
            (0, 0, 1000),
            (1, 1000, 1000),
            (2, 2000, 1000),
            (3, 3000, 1000)
        ]
    );

    // The same object from a bridge that serves it in one invocation:
    // the same status and headers.
    let (plain, _, plain_signer, _) = seeded(None).await;
    let one = front(&plain, &plain_signer, "big", &[]).await;
    assert!(matches!(one.body, RespBody::Stream(_)));
    assert_eq!(one.status, 200);
    let strip = |h: Vec<(String, String)>| {
        sorted(
            h.into_iter()
                .filter(|(n, _)| n != "last-modified" && n != "x-amz-request-id")
                .collect(),
        )
    };
    assert_eq!(strip(headers), strip(one.headers));
}

#[tokio::test]
async fn ranged_get_spans_sub_ranges_and_keeps_its_206() {
    let (rig, _, signer, data) = seeded(Some(CHUNK)).await;
    // 3,499 bytes from 301: three full sub-ranges and one of 499.
    let (status, headers, fan) =
        fanout_of(front(&rig, &signer, "big", &[("range", "bytes=301-3799")]).await);
    assert_eq!(status, 206);
    assert_eq!(
        header(&headers, "content-range"),
        Some("bytes 301-3799/4000")
    );
    assert_eq!(header(&headers, "content-length"), Some("3499"));
    let pipe = Loopback::new(&rig);
    drive(&fan, &pipe).await.unwrap();
    assert_eq!(*pipe.out.borrow(), data[301..3800]);
    assert_eq!(
        pipe.sent
            .borrow()
            .iter()
            .map(|s| (s.start, s.len))
            .collect::<Vec<_>>(),
        [(301, 1000), (1301, 1000), (2301, 1000), (3301, 499)]
    );

    // A suffix range of exactly one sub-range more one byte.
    let (_, headers, fan) =
        fanout_of(front(&rig, &signer, "big", &[("range", "bytes=-1001")]).await);
    assert_eq!(
        header(&headers, "content-range"),
        Some("bytes 2999-3999/4000")
    );
    let pipe = Loopback::new(&rig);
    drive(&fan, &pipe).await.unwrap();
    assert_eq!(*pipe.out.borrow(), data[2999..]);
    assert_eq!(
        pipe.sent.borrow().last().map(|s| (s.start, s.len)),
        Some((3999, 1))
    );
}

#[tokio::test]
async fn a_body_of_one_sub_range_or_less_is_served_by_the_front() {
    let (rig, _, signer, data) = seeded(Some(CHUNK)).await;
    for (range, want) in [
        ("bytes=0-999", &data[0..1000]),
        ("bytes=255-256", &data[255..257]),
        ("bytes=3000-3999", &data[3000..]),
        ("bytes=3999-", &data[3999..]),
    ] {
        let resp = front(&rig, &signer, "big", &[("range", range)]).await;
        assert!(matches!(resp.body, RespBody::Stream(_)), "{range}");
        let got = Resp::collect(resp).await;
        got.expect(206);
        assert_eq!(got.body, want, "{range}");
        assert_eq!(got.stream_error, None);
    }
    // HEAD never has a body to split, and a failed condition is answered
    // by the front.
    let head = rig.head(&signer, BUCKET, "big").await;
    head.expect(200);
    assert_eq!(head.header("content-length"), Some("4000"));
    let etag = head.header("etag").unwrap().to_string();
    let not_modified = front(&rig, &signer, "big", &[("if-none-match", &etag)]).await;
    assert_eq!(not_modified.status, 304);
    assert!(matches!(not_modified.body, RespBody::Empty));
}

#[test]
fn sub_range_arithmetic_at_the_boundaries() {
    let mint: Rc<dyn Fn(u64, u64) -> Option<String>> = Rc::new(|_, _| Some("t".into()));
    let fan = |start, len, chunk| Fanout::new(start, len, chunk, Rc::clone(&mint));
    // Not above one sub-range: not split.
    assert!(fan(0, 10, 10).is_none());
    assert!(fan(0, 9, 10).is_none());
    assert!(fan(0, 0, 10).is_none());
    assert!(fan(0, 11, 0).is_none());
    // One byte more than a sub-range.
    let f = fan(5, 11, 10).unwrap();
    assert_eq!(f.count(), 2);
    assert_eq!(
        (f.span(0), f.span(1), f.span(2)),
        (Some((5, 10)), Some((15, 1)), None)
    );
    // An exact multiple: no empty tail.
    let f = fan(0, 30, 10).unwrap();
    assert_eq!(f.count(), 3);
    assert_eq!((f.span(2), f.span(3)), (Some((20, 10)), None));
    // The spans tile the range exactly, whatever the sizes.
    for (start, len, chunk) in [
        (0u64, 4000u64, 1000u64),
        (301, 3499, 1000),
        (7, 1 << 40, 1 << 30),
    ] {
        let f = fan(start, len, chunk).unwrap();
        let mut at = start;
        for i in 0..f.count() {
            let (s, l) = f.span(i).unwrap();
            assert_eq!(s, at);
            assert!(l > 0 && l <= chunk);
            at += l;
        }
        assert_eq!(at, start + len);
        assert_eq!(f.span(f.count()), None);
        assert_eq!(f.span(u64::MAX), None);
    }
    // 1 TiB at 1 GiB is 1,024 sub-ranges; the most one GET may have is a
    // bound, and a range that would need more is refused whole.
    assert_eq!(fan(0, 1 << 40, 1 << 30).unwrap().count(), 1024);
    assert!(fan(0, MAX_SUBRANGES * 10, 10).is_some());
    assert!(fan(0, MAX_SUBRANGES * 10 + 1, 10).is_none());
    assert!(fan(u64::MAX - 5, 11, 10).is_none());
}

#[tokio::test]
async fn a_range_with_too_many_sub_ranges_is_refused_whole() {
    let rig = fan_rig(Some(1));
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "big", &pattern(1, SIZE))
        .await
        .expect(200);
    // 4,000 one-byte sub-ranges are fine; the bound is on their number.
    assert!(matches!(
        front(&rig, &signer, "big", &[]).await.body,
        RespBody::Fanout(_)
    ));
    assert!(SIZE as u64 <= MAX_SUBRANGES);
}

#[tokio::test]
async fn a_failing_sub_range_aborts_the_download() {
    let (rig, bucket, signer, data) = seeded(Some(CHUNK)).await;
    let extents = rig.live(&bucket, "big").await.unwrap().1;
    // The extent at 2,304..2,560 lies in the third sub-range: lost from
    // both stores, with no provider to read it from.
    let lost = &extents[9];
    assert_eq!(lost.plain_offset, Some(2304));
    assert!(rig.bridge.safety.lose(&lost.id.safety_key()));
    rig.bridge.cache.lose(&lost.id.cache_key());

    let (_, _, fan) = fanout_of(front(&rig, &signer, "big", &[]).await);
    let pipe = Loopback::new(&rig);
    let err = drive(&fan, &pipe).await.unwrap_err();
    // The third sub-range began (its first extent was readable) and
    // broke while it was piped.
    assert_eq!(err, FanoutError::Pipe);
    assert!(pipe.aborted.get() && !pipe.closed.get());
    // What was sent is a true prefix, and nothing was asked for after
    // the failure.
    let out = pipe.out.borrow();
    assert!(out.len() < data.len() && data.starts_with(&out));
    assert_eq!(pipe.sent.borrow().len(), 3);
}

#[tokio::test]
async fn a_sub_range_that_cannot_start_is_retried_then_aborts() {
    let (rig, bucket, signer, _) = seeded(Some(CHUNK)).await;
    let extents = rig.live(&bucket, "big").await.unwrap().1;
    // From byte 24 the second sub-range begins at 1,024, the first byte
    // of the fifth extent: that sub-request is a 503 before any byte.
    let lost = &extents[4];
    assert_eq!(lost.plain_offset, Some(1024));
    assert!(rig.bridge.safety.lose(&lost.id.safety_key()));
    let (_, _, fan) = fanout_of(front(&rig, &signer, "big", &[("range", "bytes=24-")]).await);
    let pipe = Loopback::new(&rig);
    let err = drive(&fan, &pipe).await.unwrap_err();
    assert_eq!(err, FanoutError::Status(503));
    assert!(pipe.aborted.get() && !pipe.closed.get());
    // Sub-range 0 once, sub-range 1 three times, each with its own token.
    let sent = pipe.sent.borrow();
    assert_eq!(
        sent.iter().map(|s| s.index).collect::<Vec<_>>(),
        [0, 1, 1, 1]
    );
    assert_eq!(*pipe.slept.borrow(), [500, 2000]);
    // No refusal is left unread: each of the three was cancelled.
    assert_eq!(pipe.discarded.get(), 3);
}

#[tokio::test]
async fn a_transient_refusal_is_retried_and_the_download_completes() {
    let (rig, bucket, signer, data) = seeded(Some(CHUNK)).await;
    let extents = rig.live(&bucket, "big").await.unwrap().1;
    let key = extents[4].id.safety_key();
    let blob = rig.bridge.safety.stored(&key).unwrap();
    assert!(rig.bridge.safety.lose(&key));
    let (_, _, fan) = fanout_of(front(&rig, &signer, "big", &[("range", "bytes=24-")]).await);
    let pipe = Loopback::new(&rig);
    // Back in the cache before the third request (the first retry).
    let bridge = Rc::clone(&rig.bridge);
    let (cache_key, bucket_id, extent) = (
        extents[4].id.cache_key(),
        bucket.id.clone(),
        extents[4].clone(),
    );
    *pipe.faults.before.borrow_mut() = Some(Box::new(move |n| {
        if n == 2 {
            let meta = BlobMeta {
                bucket: &bucket_id,
                extent: &extent.id,
                cipher_sha256: &extent.cipher_sha256,
            };
            let put = bridge.cache.put(&cache_key, blob.bytes.clone(), &meta);
            futures_util::FutureExt::now_or_never(put).unwrap().unwrap();
        }
    }));
    drive(&fan, &pipe).await.unwrap();
    assert_eq!(*pipe.out.borrow(), data[24..]);
    assert_eq!(*pipe.slept.borrow(), [500]);
    assert!(pipe.closed.get());
}

#[tokio::test]
async fn an_unreadable_first_sub_range_is_an_error_response() {
    let (rig, bucket, signer, _) = seeded(Some(CHUNK)).await;
    let extents = rig.live(&bucket, "big").await.unwrap().1;
    assert!(rig.bridge.safety.lose(&extents[0].id.safety_key()));
    let (_, _, fan) = fanout_of(front(&rig, &signer, "big", &[]).await);
    let pipe = Loopback::new(&rig);
    let Err(resp) = fan
        .open_first(&pipe, || S3Response::error(500, "InternalError", "x"))
        .await
    else {
        panic!("the first sub-range cannot be read");
    };
    // The 503 a GET in one invocation gives for it, with its document.
    assert_eq!(resp.status, 503);
    assert_eq!(header(&resp.headers, "retry-after"), Some("30"));
    let RespBody::Bytes(doc) = resp.body else {
        panic!("a buffered document")
    };
    assert!(String::from_utf8(doc)
        .unwrap()
        .contains("<Code>ServiceUnavailable</Code>"));
    assert!(pipe.out.borrow().is_empty());

    // A refused token on the first sub-range is the front's 500, never
    // the sub-request's 403.
    let (_, _, fan) = fanout_of(front(&rig, &signer, "big", &[]).await);
    let pipe = Loopback::new(&rig);
    *pipe.faults.forge.borrow_mut() = Some(Box::new(|_| "v1.1.1.0.1.b.g.00".into()));
    let Err(resp) = fan
        .open_first(&pipe, || S3Response::error(500, "InternalError", "x"))
        .await
    else {
        panic!("a forged token is refused");
    };
    assert_eq!(resp.status, 500);
    assert_eq!(pipe.sent.borrow().len(), 1, "a 403 is not retried");
}

#[tokio::test]
async fn every_sub_range_comes_from_the_generation_the_front_planned() {
    let (rig, bucket, signer, old) = seeded(Some(CHUNK)).await;
    let planned = rig.live(&bucket, "big").await.unwrap().0.id;
    let (_, _, fan) = fanout_of(front(&rig, &signer, "big", &[]).await);
    let pipe = Loopback::new(&rig);
    let first = fan
        .open_first(&pipe, || S3Response::error(500, "InternalError", "x"))
        .await
        .unwrap();

    // With the download under way (the first sub-range is open, no other
    // has been asked for) the key is overwritten with other bytes of the
    // same length.
    let new = pattern(99, SIZE);
    rig.bridge.clock.advance_ms(5);
    rig.put(&signer, BUCKET, "big", &new).await.expect(200);
    let live = rig.live(&bucket, "big").await.unwrap().0.id;
    assert_ne!(live, planned);

    fan.pump(&pipe, first).await.unwrap();
    assert!(pipe.sent.borrow().len() > 2);
    // Every byte is the old object's: no sub-range saw the new one.
    assert_eq!(*pipe.out.borrow(), old);
    let now = rig.now();
    for sub in pipe.sent.borrow().iter() {
        let grant = Grant::open(&rig.bridge.kek, &sub.token, now).unwrap();
        assert_eq!(grant.generation, planned);
        assert_eq!(grant.bucket, bucket.id);
        assert_eq!((grant.start, grant.len), (sub.start, sub.len));
    }
    // A GET planned now is pinned to the new one.
    let (_, _, fan) = fanout_of(front(&rig, &signer, "big", &[]).await);
    let pipe = Loopback::new(&rig);
    drive(&fan, &pipe).await.unwrap();
    assert_eq!(*pipe.out.borrow(), new);
}

/// Sends one sub-request with exactly these headers.
async fn sub(rig: &Rig, method: Method, target: &str, headers: &[(&str, &str)]) -> Resp {
    let req = S3Request {
        method,
        raw_target: target.to_string(),
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        body: Body::Empty,
    };
    // Through the front of every fetch, as the Worker calls it.
    let resp = ingress::front(req, &rig.bridge.cfg, true, |req| {
        Rc::clone(&rig.bridge).handle(req)
    })
    .await;
    Resp::collect(resp).await
}

fn grant_for(
    bucket: &Bucket,
    generation: &GenerationId,
    start: u64,
    len: u64,
    now: UnixMs,
) -> Grant {
    Grant {
        bucket: bucket.id.clone(),
        generation: generation.clone(),
        start,
        len,
        expires: now.plus_ms(TOKEN_TTL_MS),
    }
}

#[tokio::test]
async fn a_forged_sub_request_is_refused() {
    let (rig, bucket, signer, data) = seeded(Some(CHUNK)).await;
    let generation = rig.live(&bucket, "big").await.unwrap().0.id;
    let kek = &rig.bridge.kek;
    let now = rig.now();
    let good = grant_for(&bucket, &generation, 100, 300, now);
    let token = good.seal(kek).unwrap();

    // The real thing: exactly the granted bytes.
    let ok = sub(
        &rig,
        Method::Get,
        INTERNAL_TARGET,
        &[(TOKEN_HEADER, &token)],
    )
    .await;
    ok.expect(200);
    assert_eq!(ok.body, data[100..400]);
    assert_eq!(ok.header("content-length"), Some("300"));

    let denied = |resp: Resp, what: &str| {
        assert_eq!(resp.status, 403, "{what}");
        assert_eq!(resp.code(), "AccessDenied", "{what}");
        assert!(
            !resp
                .body
                .windows(8)
                .any(|w| data.windows(8).any(|d| d == w)),
            "{what}"
        );
    };

    // No token; an empty one; garbage.
    denied(
        sub(&rig, Method::Get, INTERNAL_TARGET, &[]).await,
        "no token",
    );
    for bad in ["", "v1", "x", "v1.1.1.1.1.b.g.zz", &"a".repeat(4096)] {
        denied(
            sub(&rig, Method::Get, INTERNAL_TARGET, &[(TOKEN_HEADER, bad)]).await,
            bad,
        );
    }
    // A valid S3 signature is no authority here.
    let signed = signer.sign(now, Method::Get, INTERNAL_TARGET, &[], &[], Vec::new());
    let headers: Vec<(&str, &str)> = signed
        .headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    denied(
        sub(&rig, Method::Get, INTERNAL_TARGET, &headers).await,
        "sigv4 only",
    );
    // The admin bearer neither.
    denied(
        sub(
            &rig,
            Method::Get,
            INTERNAL_TARGET,
            &[(
                "authorization",
                "Bearer admin-token-fixture-admin-token-fixture",
            )],
        )
        .await,
        "admin bearer",
    );

    // Each field changed under the same tag.
    let fields: Vec<&str> = token.split('.').collect();
    assert_eq!(fields.len(), 8);
    let other_generation = GenerationId::mint(now, [9; 8]);
    let other_bucket = BucketId::mint([9; 8]);
    let swaps: [(usize, String); 7] = [
        (1, "2".into()),
        (2, (now.0 + 10 * TOKEN_TTL_MS).to_string()),
        (3, "0".into()),
        (4, "4000".into()),
        (5, other_bucket.as_str().to_string()),
        (6, other_generation.as_str().to_string()),
        (7, "00".repeat(32)),
    ];
    for (at, value) in swaps {
        let mut forged = fields.clone();
        forged[at] = &value;
        let forged = forged.join(".");
        denied(
            sub(
                &rig,
                Method::Get,
                INTERNAL_TARGET,
                &[(TOKEN_HEADER, &forged)],
            )
            .await,
            &format!("field {at}"),
        );
    }
    // One bit of the tag; a non-canonical number; a ninth field.
    let mut flipped = token.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'0' { b'1' } else { b'0' };
    let flipped = String::from_utf8(flipped).unwrap();
    assert_eq!(Grant::open(kek, &flipped, now), Err(Refused::BadTag));
    denied(
        sub(
            &rig,
            Method::Get,
            INTERNAL_TARGET,
            &[(TOKEN_HEADER, &flipped)],
        )
        .await,
        "tag bit",
    );
    let padded = token.replacen(".100.", ".0100.", 1);
    assert_eq!(Grant::open(kek, &padded, now), Err(Refused::Malformed));
    assert_eq!(
        Grant::open(kek, &format!("{token}.x"), now),
        Err(Refused::Malformed)
    );

    // A tag under another key: a KEK the ring does not hold, and one it
    // holds under another version.
    let foreign = TestKek::with_versions(1, &[(1, [0x22; 32])]);
    let foreign_token = good.seal(&foreign).unwrap();
    assert_eq!(Grant::open(kek, &foreign_token, now), Err(Refused::BadTag));
    denied(
        sub(
            &rig,
            Method::Get,
            INTERNAL_TARGET,
            &[(TOKEN_HEADER, &foreign_token)],
        )
        .await,
        "foreign key",
    );
    let v7 = TestKek::with_versions(7, &[(7, [0x11; 32])]);
    assert_eq!(
        Grant::open(kek, &good.seal(&v7).unwrap(), now),
        Err(Refused::UnknownKey)
    );

    // Two tokens; another method; a request that came through the edge,
    // valid token and all.
    denied(
        sub(
            &rig,
            Method::Get,
            INTERNAL_TARGET,
            &[(TOKEN_HEADER, &token), (TOKEN_HEADER, &token)],
        )
        .await,
        "two tokens",
    );
    for method in [Method::Head, Method::Put, Method::Post, Method::Delete] {
        let resp = sub(&rig, method, INTERNAL_TARGET, &[(TOKEN_HEADER, &token)]).await;
        assert_eq!(resp.status, 403);
    }
    for edge in [
        "cf-connecting-ip",
        "cf-ray",
        "x-forwarded-for",
        "x-real-ip",
        "cf-worker",
        "CF-Visitor",
    ] {
        denied(
            sub(
                &rig,
                Method::Get,
                INTERNAL_TARGET,
                &[(TOKEN_HEADER, &token), (edge, "203.0.113.9")],
            )
            .await,
            edge,
        );
    }

    // Expired: good until the last millisecond, then never again.
    rig.bridge.clock.advance_ms(TOKEN_TTL_MS - 1);
    sub(
        &rig,
        Method::Get,
        INTERNAL_TARGET,
        &[(TOKEN_HEADER, &token)],
    )
    .await
    .expect(200);
    rig.bridge.clock.advance_ms(1);
    assert_eq!(Grant::open(kek, &token, rig.now()), Err(Refused::Expired));
    denied(
        sub(
            &rig,
            Method::Get,
            INTERNAL_TARGET,
            &[(TOKEN_HEADER, &token)],
        )
        .await,
        "expired",
    );

    // The token is not an S3 credential for anything else.
    let fresh = grant_for(&bucket, &generation, 0, 10, rig.now())
        .seal(kek)
        .unwrap();
    let resp = sub(
        &rig,
        Method::Get,
        &path(BUCKET, "big"),
        &[(TOKEN_HEADER, &fresh)],
    )
    .await;
    assert_eq!(resp.status, 403);
    assert!(resp.body.len() < 400);
}

#[tokio::test]
async fn a_grant_outside_its_generation_is_not_served() {
    let (rig, bucket, _, _) = seeded(Some(CHUNK)).await;
    let generation = rig.live(&bucket, "big").await.unwrap().0.id;
    let kek = &rig.bridge.kek;
    let now = rig.now();
    // Sealed grants that the front would never mint: past the end, an
    // unknown generation, a generation of another bucket.
    let past = grant_for(&bucket, &generation, 3990, 11, now)
        .seal(kek)
        .unwrap();
    let unknown = grant_for(&bucket, &GenerationId::mint(now, [3; 8]), 0, 10, now)
        .seal(kek)
        .unwrap();
    let other = rig.bucket("bkt-other", true).await;
    let crossed = grant_for(&other, &generation, 0, 10, now)
        .seal(kek)
        .unwrap();
    for token in [past, unknown, crossed] {
        let resp = sub(
            &rig,
            Method::Get,
            INTERNAL_TARGET,
            &[(TOKEN_HEADER, &token)],
        )
        .await;
        assert_eq!(resp.status, 500);
        assert_eq!(resp.code(), "InternalError");
    }
    // A grant cannot be sealed for nothing, for an overflowing range or
    // with an id that would not survive the token's framing.
    assert!(grant_for(&bucket, &generation, 0, 0, now)
        .seal(kek)
        .is_none());
    assert!(grant_for(&bucket, &generation, u64::MAX, 1, now)
        .seal(kek)
        .is_none());
    let mut dotted = grant_for(&bucket, &generation, 0, 1, now);
    dotted.generation = GenerationId::new("a.b".to_string());
    assert!(dotted.seal(kek).is_none());
}

#[tokio::test]
async fn extents_in_returns_the_run_that_holds_the_range() {
    let (rig, bucket, _, _) = seeded(None).await;
    let (generation, all) = rig.live(&bucket, "big").await.unwrap();
    let catalog = &rig.bridge.catalog;
    for (start, end, want) in [
        (0u64, 1u64, 0..1usize),
        (0, 256, 0..1),
        (0, 257, 0..2),
        (255, 257, 0..2),
        (256, 512, 1..2),
        (300, 3800, 1..15),
        (3840, 4000, 15..16),
        (3999, 4000, 15..16),
        (0, 4000, 0..16),
    ] {
        let got = catalog
            .extents_in(&generation.id, start, end)
            .await
            .unwrap();
        assert_eq!(got, all[want], "{start}..{end}");
    }
    // Nothing for an empty range at 0 or an unknown generation.
    assert!(catalog
        .extents_in(&generation.id, 0, 0)
        .await
        .unwrap()
        .is_empty());
    let unknown = GenerationId::mint(rig.now(), [5; 8]);
    assert!(catalog
        .extents_in(&unknown, 0, 10)
        .await
        .unwrap()
        .is_empty());

    let live = catalog
        .live_generation(&bucket.id, "big")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(live, generation);
    assert!(catalog
        .live_generation(&bucket.id, "absent")
        .await
        .unwrap()
        .is_none());
    let (b, g) = catalog
        .generation_by_id(&bucket.id, &generation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((b, g), (bucket.clone(), generation.clone()));
    let other = rig.bucket("bkt-other", true).await;
    assert!(catalog
        .generation_by_id(&other.id, &generation.id)
        .await
        .unwrap()
        .is_none());
}

#[test]
fn only_requests_from_the_edge_carry_edge_headers() {
    let with = |name: &str| S3Request {
        method: Method::Get,
        raw_target: INTERNAL_TARGET.into(),
        headers: vec![(name.to_string(), "x".to_string())],
        body: Body::Empty,
    };
    assert!(!fanout::from_edge(&with(TOKEN_HEADER)));
    assert!(!fanout::from_edge(&with("host")));
    for name in [
        "cf-connecting-ip",
        "cf-ray",
        "cf-ipcountry",
        "cf-visitor",
        "x-forwarded-proto",
        "x-real-ip",
    ] {
        assert!(fanout::from_edge(&with(name)), "{name}");
    }
    assert!(fanout::is_internal_target("/_fanout"));
    assert!(fanout::is_internal_target("/_fanout?x=1"));
    for target in [
        "/_fanout/",
        "/_fanout/x",
        "/_fanoutx",
        "/bkt/_fanout",
        "/",
        "/_admin",
    ] {
        assert!(!fanout::is_internal_target(target), "{target}");
    }
}
