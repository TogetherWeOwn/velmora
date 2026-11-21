//! An upload of at most one extent is sealed and stored while its body
//! arrives: what is stored is what was sent, nothing whole is stored of
//! a body that is refused, and only a window of the body is charged.

mod intent_support;
mod service_support;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use futures_util::stream::{self, StreamExt as _};
use intent_support::*;
use service_support::*;
use velmora::media::{ciphertext_size, PLAIN_CHUNK_SIZE};
use velmora_bridge::ingress::{stream_charge, ByteBudget, STREAM_CHARGE_BYTES};
use velmora_bridge::*;

const CHUNK_64K: usize = PLAIN_CHUNK_SIZE as usize;
const KEY: &str = "k";

/// Catalogue rows that name bytes of an upload.
fn rows(rig: &Rig) -> (i64, i64, i64) {
    (
        rig.count("extents"),
        rig.count("generations"),
        rig.count("upload_parts"),
    )
}

/// The request with its body given in pieces of `piece` bytes.
fn in_pieces(req: Req, piece: usize) -> S3Request {
    let declared_len = req
        .headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok());
    let pieces: Vec<_> = req.body.chunks(piece).map(|c| Ok(c.to_vec())).collect();
    S3Request {
        method: req.method,
        raw_target: req.target,
        headers: req.headers,
        body: Body::Stream {
            declared_len,
            stream: stream::iter(pieces).boxed_local(),
        },
    }
}

async fn create(rig: &Rig, signer: &Signer) -> String {
    let created = rig
        .call(
            signer,
            Method::Post,
            &path(BUCKET, KEY),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    created.expect(200);
    created.values("UploadId").remove(0)
}

async fn complete(rig: &Rig, signer: &Signer, id: &str, etag: &str) -> Resp {
    let xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    rig.call(
        signer,
        Method::Post,
        &path(BUCKET, KEY),
        &[("uploadId", id)],
        &[],
        xml.as_bytes(),
    )
    .await
}

/// What the only stream put of the rig's safety store saw.
fn only_stream(rig: &Rig) -> StreamSeen {
    let streams = rig.bridge.safety.streams.borrow();
    assert_eq!(streams.len(), 1, "{streams:?}");
    streams[0].clone()
}

// ---------------------------------------------------------------------------
// What is stored is what was sent
// ---------------------------------------------------------------------------

/// The sizes around the chunk of the sealed stream, in every body mode
/// and in pieces of every kind: the object reads back, the catalogue
/// has the digests of the plaintext and of the blob that is stored, and
/// the store was given one sealed chunk at a time.
#[tokio::test(flavor = "current_thread")]
async fn every_mode_and_size_is_stored_as_it_was_sent() {
    let sizes = [
        0,
        1,
        CHUNK_64K - 1,
        CHUNK_64K,
        CHUNK_64K + 1,
        2 * CHUNK_64K,
        3 * CHUNK_64K + 17,
    ];
    for mode in MODES {
        for (seed, len) in sizes.into_iter().enumerate() {
            for piece in [1 << 30, 4099] {
                let rig = rig();
                let (bucket, signer) = rig.standard(BUCKET).await;
                let body = pattern(seed as u8, len);
                let what = format!("{mode:?} {len} in {piece}");

                let req = mode_req(&rig, &signer, KEY, &body, mode);
                let r = send_in_pieces(&rig, req, piece).await;
                assert_eq!(r.status, 200, "{what}: {}", r.text());
                assert_eq!(r.header("etag"), Some(md5_etag(&body).as_str()), "{what}");

                let (generation, extents) = rig.live(&bucket, KEY).await.unwrap();
                assert_eq!(generation.size, len as u64, "{what}");
                assert_eq!(generation.etag, md5_etag(&body), "{what}");
                assert_eq!(extents.len(), 1, "{what}");
                let extent = &extents[0];
                let blob = rig.bridge.safety.stored(&extent.id.safety_key()).unwrap();
                assert_eq!(extent.plain_size, len as u64, "{what}");
                assert_eq!(extent.plain_md5, md5::compute(&body).0, "{what}");
                assert_eq!(extent.plain_sha256, sha256(&body), "{what}");
                assert_eq!(extent.cipher_size, blob.bytes.len() as u64, "{what}");
                assert_eq!(
                    Some(extent.cipher_size),
                    ciphertext_size(len as u64),
                    "{what}"
                );
                assert_eq!(extent.cipher_sha256, sha256(&blob.bytes), "{what}");
                assert_eq!(extent.media_header, blob.bytes[..48], "{what}");
                assert_eq!(blob.bucket, bucket.id, "{what}");
                assert_eq!(blob.extent, extent.id, "{what}");

                // One sealed chunk per piece, the header with the first.
                let seen = only_stream(&rig);
                assert_eq!(seen.len, extent.cipher_size, "{what}");
                assert_eq!(seen.taken(), extent.cipher_size, "{what}");
                assert_eq!(seen.pieces.len(), len.div_ceil(CHUNK_64K).max(1), "{what}");
                assert!(seen.stored && !seen.failed, "{what}");
                assert_eq!(rig.bridge.budget.peak(), stream_charge(len as u64));
                assert_eq!(rig.bridge.budget.in_use(), 0, "{what}");

                let got = get(&rig, &signer, KEY).await;
                assert_eq!(got.status, 200, "{what}");
                assert!(got.body == body, "{what}");
                assert!(orphans(&rig).is_empty() && broken(&rig).is_empty());
            }
        }
    }
}

/// The same for a part, and for a whole extent of 16 MiB.
#[tokio::test(flavor = "current_thread")]
async fn a_part_of_a_whole_extent_is_stored_as_it_was_sent() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer).await;
    let body = pattern(9, 16 * MIB);
    let query = [("partNumber", "1"), ("uploadId", id.as_str())];

    let req = mode_req_at(&rig, &signer, KEY, &query, &body, Mode::UnsignedTrailer);
    let r = send_in_pieces(&rig, req, 100_003).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let etag = r.header("etag").unwrap().to_owned();
    assert_eq!(etag, md5_etag(&body));
    assert_eq!(rig.bridge.budget.peak(), STREAM_CHARGE_BYTES);
    assert_eq!(rig.bridge.budget.in_use(), 0);
    let seen = only_stream(&rig);
    assert_eq!(Some(seen.taken()), ciphertext_size(body.len() as u64));
    assert_eq!(seen.pieces.len(), 256);

    complete(&rig, &signer, &id, &etag).await.expect(200);
    let (generation, extents) = rig.live(&bucket, KEY).await.unwrap();
    assert_eq!(generation.size, body.len() as u64);
    assert_eq!(extents.len(), 1);
    let blob = rig
        .bridge
        .safety
        .stored(&extents[0].id.safety_key())
        .unwrap();
    assert_eq!(extents[0].plain_md5, md5::compute(&body).0);
    assert_eq!(extents[0].plain_sha256, sha256(&body));
    assert_eq!(extents[0].cipher_sha256, sha256(&blob.bytes));
    assert!(get(&rig, &signer, KEY).await.body == body);
    assert!(orphans(&rig).is_empty() && broken(&rig).is_empty());
}

// ---------------------------------------------------------------------------
// Nothing whole is stored of a body that is refused
// ---------------------------------------------------------------------------

/// After a refused upload: the store was not given the whole stream, it
/// holds no blob of it and no row names one.
fn assert_nothing_stored(rig: &Rig, before: (i64, i64, i64), blobs_before: &[String], what: &str) {
    let seen = rig.bridge.safety.streams.borrow().last().cloned();
    if let Some(seen) = seen {
        assert!(!seen.stored, "{what}: {seen:?}");
        assert!(seen.taken() < seen.len, "{what}: the final piece was given");
    }
    assert_eq!(blobs(rig), blobs_before, "{what}");
    assert_eq!(rows(rig), before, "{what}");
    assert_eq!(rig.bridge.budget.in_use(), 0, "{what}");
    assert!(orphans(rig).is_empty() && broken(rig).is_empty(), "{what}");
}

/// One case per way a body is refused (wrong Content-MD5, payload hash
/// or checksum, a bad chunk signature, a short or long body), each sent
/// whole and in small pieces: S3's error, no blob, no row, and the
/// object that was there is still the one that is read.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_put_stores_no_blob() {
    let body = pattern(2, 3 * CHUNK_64K + 17);
    let count = refused_bodies(&rig(), &Signer::new(AKID, secret()), KEY, &body).len();
    assert_eq!(count, 9);
    for case in 0..count {
        for piece in [1 << 30, 4099] {
            let rig = rig();
            let (_, signer) = rig.standard(BUCKET).await;
            let old = pattern(1, 100);
            rig.put(&signer, BUCKET, KEY, &old).await.expect(200);
            let (before, held) = (rows(&rig), blobs(&rig));
            rig.bridge.safety.streams.borrow_mut().clear();
            let puts = rig.bridge.safety.puts.borrow().len();

            let (what, req, http, code) =
                refused_bodies(&rig, &signer, KEY, &body).swap_remove(case);
            send_in_pieces(&rig, req, piece)
                .await
                .expect_error(http, code);

            let what = format!("{what} in {piece}");
            let seen = only_stream(&rig);
            // The stream ended in an error. Sent in small pieces, the
            // store was given what was sealed before the refusal: every
            // chunk but the final one, or one less when the last chunk
            // signature is the bad one.
            assert!(seen.failed, "{what}: {seen:?}");
            let given = seen.pieces.len();
            assert!(piece > 4099 || (2..=3).contains(&given), "{what}: {seen:?}");
            assert_eq!(rig.bridge.safety.puts.borrow().len(), puts, "{what}");
            assert_nothing_stored(&rig, before, &held, &what);
            assert!(get(&rig, &signer, KEY).await.body == old, "{what}");

            // The same key takes the body when it is sent as it should be.
            rig.put(&signer, BUCKET, KEY, &body).await.expect(200);
            assert!(get(&rig, &signer, KEY).await.body == body, "{what}");
        }
    }
}

/// The same cases for a part: no blob, no part, and the upload still
/// takes the part afterwards.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_part_stores_no_blob() {
    let body = pattern(3, 3 * CHUNK_64K + 17);
    let count = refused_bodies(&rig(), &Signer::new(AKID, secret()), KEY, &body).len();
    for case in 0..count {
        for piece in [1 << 30, 4099] {
            let rig = rig();
            let (_, signer) = rig.standard(BUCKET).await;
            let id = create(&rig, &signer).await;
            let query = [("partNumber", "1"), ("uploadId", id.as_str())];
            let (before, held) = (rows(&rig), blobs(&rig));
            assert_eq!(before, (0, 0, 0));

            let (what, req, http, code) =
                refused_bodies_at(&rig, &signer, KEY, &query, &body).swap_remove(case);
            send_in_pieces(&rig, req, piece)
                .await
                .expect_error(http, code);

            let what = format!("{what} in {piece}");
            let seen = only_stream(&rig);
            assert!(seen.failed, "{what}: {seen:?}");
            let given = seen.pieces.len();
            assert!(piece > 4099 || (2..=3).contains(&given), "{what}: {seen:?}");
            assert!(rig.bridge.safety.puts.borrow().is_empty(), "{what}");
            assert_nothing_stored(&rig, before, &held, &what);

            let req = mode_req_at(&rig, &signer, KEY, &query, &body, Mode::Literal);
            let sent = rig.send(req).await;
            assert_eq!(sent.status, 200, "{what}: {}", sent.text());
            let etag = sent.header("etag").unwrap().to_owned();
            complete(&rig, &signer, &id, &etag).await.expect(200);
            assert!(get(&rig, &signer, KEY).await.body == body, "{what}");
        }
    }
}

/// A refusal in the very first bytes (framing that is not aws-chunked)
/// and one of a body of a single chunk: the store is given an error and
/// no piece at all.
#[tokio::test(flavor = "current_thread")]
async fn a_body_refused_before_its_first_chunk_gives_the_store_nothing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let before = rows(&rig);

    let body = pattern(4, 3 * CHUNK_64K);
    let mut req = mode_req(&rig, &signer, KEY, &body, Mode::SignedChunks);
    req.body[0] = b'z';
    let r = rig.send(req).await;
    assert_eq!(r.status / 100, 4, "{}", r.text());
    let seen = only_stream(&rig);
    assert!(seen.failed && seen.pieces.is_empty(), "{seen:?}");
    assert_nothing_stored(&rig, before, &[], "bad framing");

    // One chunk or less is all final chunk: nothing leaves before the
    // body is judged.
    rig.bridge.safety.streams.borrow_mut().clear();
    let body = pattern(5, CHUNK_64K);
    let (what, req, http, code) = refused_bodies(&rig, &signer, KEY, &body).swap_remove(0);
    rig.send(req).await.expect_error(http, code);
    let seen = only_stream(&rig);
    assert!(seen.failed && seen.pieces.is_empty(), "{what}: {seen:?}");
    assert_nothing_stored(&rig, before, &[], what);
}

/// A body whose stream fails (the client went away) is an incomplete
/// body, at any point of it.
#[tokio::test(flavor = "current_thread")]
async fn a_body_that_fails_on_its_way_stores_no_blob() {
    let body = pattern(6, 3 * CHUNK_64K + 17);
    for good in [0, 1, 20, 49] {
        let rig = rig();
        let (_, signer) = rig.standard(BUCKET).await;
        let before = rows(&rig);
        let mut request = in_pieces(mode_req(&rig, &signer, KEY, &body, Mode::Unsigned), 4099);
        let Body::Stream {
            declared_len,
            stream,
        } = request.body
        else {
            panic!("no body");
        };
        let cut = stream
            .take(good)
            .chain(stream::iter([Err(BridgeError::Invalid("client gone"))]));
        request.body = Body::Stream {
            declared_len,
            stream: cut.boxed_local(),
        };
        let r = Resp::collect(Rc::clone(&rig.bridge).handle(request).await).await;
        r.expect_error(400, "IncompleteBody");
        assert_nothing_stored(&rig, before, &[], &format!("after {good} pieces"));
    }
}

// ---------------------------------------------------------------------------
// A store that fails, or that holds something else
// ---------------------------------------------------------------------------

/// The store fails while it takes the stream, or when the stream has
/// ended: `500`, no row, the budget is given back, and the same request
/// is taken afterwards. The rest of the body is not read for a store
/// that has failed.
#[tokio::test(flavor = "current_thread")]
async fn a_store_that_fails_is_a_500_without_a_row() {
    let body = pattern(7, 3 * CHUNK_64K + 17);
    for stop in [Some(0), Some(2), None] {
        let rig = rig();
        let (_, signer) = rig.standard(BUCKET).await;
        let before = rows(&rig);
        rig.bridge.safety.stop_stream_after.set(stop);
        rig.bridge.safety.fail_put.set(stop.is_none());

        let pulled = Rc::new(Cell::new(0usize));
        let mut request = in_pieces(mode_req(&rig, &signer, KEY, &body, Mode::Unsigned), 4099);
        let Body::Stream {
            declared_len,
            stream,
        } = request.body
        else {
            panic!("no body");
        };
        let count = Rc::clone(&pulled);
        request.body = Body::Stream {
            declared_len,
            stream: stream
                .inspect(move |_| count.set(count.get() + 1))
                .boxed_local(),
        };
        let r = Resp::collect(Rc::clone(&rig.bridge).handle(request).await).await;
        r.expect_error(500, "InternalError");
        assert_eq!(rows(&rig), before, "{stop:?}");
        assert!(blobs(&rig).is_empty(), "{stop:?}");
        assert_eq!(rig.bridge.budget.in_use(), 0, "{stop:?}");
        let all = body.len().div_ceil(4099);
        match stop {
            // Two sealed chunks need under three chunks of the body.
            Some(n) => assert!(pulled.get() <= (n + 1) * CHUNK_64K / 4099 + 2, "{stop:?}"),
            None => assert_eq!(pulled.get(), all),
        }

        rig.bridge.safety.stop_stream_after.set(None);
        rig.bridge.safety.fail_put.set(false);
        rig.put(&signer, BUCKET, KEY, &body).await.expect(200);
        assert!(get(&rig, &signer, KEY).await.body == body, "{stop:?}");
    }
}

/// The store answers `Ok` for bytes other than the sealed ones (another
/// size, another MD5): the catalogue never names that blob.
#[tokio::test(flavor = "current_thread")]
async fn a_blob_the_store_reports_differently_is_never_named() {
    let lies: [ReceiptLie; 2] = [
        |r| PutReceipt {
            size: r.size - 1,
            ..r
        },
        |mut r| {
            r.md5[15] ^= 1;
            r
        },
    ];
    let body = pattern(8, 3 * CHUNK_64K + 17);
    for (case, lie) in lies.into_iter().enumerate() {
        let rig = rig();
        let (bucket, signer) = rig.standard(BUCKET).await;
        let id = create(&rig, &signer).await;
        let query = [("partNumber", "1"), ("uploadId", id.as_str())];
        let before = rows(&rig);
        rig.bridge.safety.false_receipt.set(Some(lie));

        rig.put(&signer, BUCKET, "object", &body)
            .await
            .expect_error(500, "InternalError");
        let req = mode_req_at(&rig, &signer, KEY, &query, &body, Mode::Literal);
        rig.send(req).await.expect_error(500, "InternalError");

        assert_eq!(rows(&rig), before, "case {case}");
        assert!(rig.live(&bucket, "object").await.is_none(), "case {case}");
        assert_eq!(rig.bridge.budget.in_use(), 0, "case {case}");
        // The handler deletes nothing from the safety store: both blobs
        // are orphans no row names, as after a failed catalogue write.
        assert_eq!(orphans(&rig).len(), 2, "case {case}");
        assert!(broken(&rig).is_empty(), "case {case}");
    }
}

// ---------------------------------------------------------------------------
// The body is stored while it arrives, through a window
// ---------------------------------------------------------------------------

/// The store is given sealed chunks while the body is still arriving,
/// the body is asked for more only as the store takes them, and the
/// final chunk leaves only when the body has ended.
#[tokio::test(flavor = "current_thread")]
async fn the_store_is_fed_while_the_body_arrives() {
    for piece in [1021, 4099, CHUNK_64K, 5 * CHUNK_64K] {
        let rig = rig();
        let (_, signer) = rig.standard(BUCKET).await;
        let body = pattern(10, 16 * CHUNK_64K + 5);

        // Bytes of the body read so far, and that count at every piece
        // the store takes.
        let read = Rc::new(Cell::new(0usize));
        let at_piece = Rc::new(RefCell::new(Vec::new()));
        let (count, log) = (Rc::clone(&read), Rc::clone(&at_piece));
        *rig.bridge.safety.on_piece.borrow_mut() =
            Some(Box::new(move |_| log.borrow_mut().push(count.get())));

        let mut request = in_pieces(mode_req(&rig, &signer, KEY, &body, Mode::Unsigned), piece);
        let Body::Stream {
            declared_len,
            stream,
        } = request.body
        else {
            panic!("no body");
        };
        let count = Rc::clone(&read);
        request.body = Body::Stream {
            declared_len,
            stream: stream
                .inspect(move |bytes| {
                    count.set(count.get() + bytes.as_ref().map_or(0, Vec::len));
                })
                .boxed_local(),
        };
        let r = Resp::collect(Rc::clone(&rig.bridge).handle(request).await).await;
        assert_eq!(r.status, 200, "{}", r.text());

        let at_piece = at_piece.borrow().clone();
        assert_eq!(at_piece.len(), 17, "pieces of {piece}");
        for (i, read) in at_piece.iter().enumerate() {
            let sealed = (i + 1) * CHUNK_64K;
            if i + 1 < at_piece.len() {
                // Read ahead of what the store has been given: under one
                // chunk waiting to be sealed and the body piece being
                // decoded. So the first chunks are with the store while
                // most of the body has not been read.
                assert!(
                    *read < sealed + CHUNK_64K + piece,
                    "piece {i} of {piece}: {read} read, {sealed} given"
                );
            } else {
                assert_eq!(*read, body.len(), "the final piece waits for the end");
            }
        }
        assert!(at_piece[0] < body.len() / 2, "pieces of {piece}");
        assert!(get(&rig, &signer, KEY).await.body == body);
    }
}

// ---------------------------------------------------------------------------
// The charge
// ---------------------------------------------------------------------------

#[test]
fn the_charge_is_a_window_and_never_more_than_a_held_body() {
    assert_eq!(stream_charge(0), 0);
    assert_eq!(stream_charge(1), 2);
    assert_eq!(stream_charge(100_000), 200_000);
    assert_eq!(stream_charge(STREAM_CHARGE_BYTES / 2), STREAM_CHARGE_BYTES);
    assert_eq!(stream_charge(16 * MIB as u64), STREAM_CHARGE_BYTES);
    assert_eq!(stream_charge(u64::MAX), STREAM_CHARGE_BYTES);
    assert_eq!(STREAM_CHARGE_BYTES, 8 * (64 * 1024 + 16));
}

/// Uploads of a whole extent each are under way at once in a budget
/// that a single held body of that size would not fit, each charged its
/// window until its store call returns.
#[tokio::test(flavor = "current_thread")]
async fn whole_extents_are_stored_at_once_within_a_small_budget() {
    const AT_ONCE: u64 = 4;
    let budget = ByteBudget::new(AT_ONCE * STREAM_CHARGE_BYTES);
    let rig = rig_with_budget(NoNntp, config(Vec::new()), budget);
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(11, 16 * MIB);

    *rig.bridge.safety.hold_put_prefix.borrow_mut() = Some("x/".into());
    let sends = (0..AT_ONCE).map(|i| {
        let req = mode_req(&rig, &signer, &format!("k{i}"), &body, Mode::Unsigned);
        start(&rig, req)
    });
    let all = futures_util::future::join_all(sends);
    let release = async {
        // Every upload has given its whole stream and waits in the store.
        while rig.bridge.safety.streams.borrow().len() < AT_ONCE as usize
            || rig
                .bridge
                .safety
                .streams
                .borrow()
                .iter()
                .any(|s| s.taken() < s.len)
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(rig.bridge.budget.in_use(), AT_ONCE * STREAM_CHARGE_BYTES);
        *rig.bridge.safety.hold_put_prefix.borrow_mut() = None;
    };
    let (answers, ()) = futures_util::future::join(all, release).await;
    for r in &answers {
        assert_eq!(r.status, 200, "{}", r.text());
    }
    assert_eq!(rig.bridge.budget.peak(), AT_ONCE * STREAM_CHARGE_BYTES);
    assert_eq!(rig.bridge.budget.in_use(), 0);
    let digest = sha256(&body);
    for i in 0..AT_ONCE {
        let (_, extents) = rig.live(&bucket, &format!("k{i}")).await.unwrap();
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].plain_sha256, digest);
        assert!(rig.bridge.safety.contains(&extents[0].id.safety_key()));
    }
}
