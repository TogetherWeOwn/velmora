//! GetObject and HeadObject.
//!
//! HEAD answers from the catalogue alone. GET serves each extent from the
//! cache, else the safety copy, else Usenet (which fills the cache before
//! any byte is released). Whatever the source, only plaintext whose
//! sealed chunks authenticated is returned.

use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures_util::stream::{self, StreamExt};
use velmora_s3_proto::{plan_read, Conditions, ErrorCode, ObjectMetadata};

use super::common::{
    authenticate, internal, s3_error, stored_checksum, stored_headers, unavailable,
};
use crate::crypto::{cipher_span, open_range, unwrap_bdk};
use crate::fetch::{cold_poll_ms, ColdFetch, COLD_WAIT_MS};
use crate::ingress::{ByteBudget, Charge};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{
    BridgeError, Bucket, ByteSpan, ExtentRow, RespBody, Result, S3Request, S3Response,
};

/// The part of one extent a read needs: `len` plaintext bytes from
/// plaintext offset `off` within the extent.
struct Piece {
    extent: ExtentRow,
    off: u64,
    len: u64,
}

/// Why a piece could not be produced.
enum ReadFail {
    /// Out of byte budget or provider slots: `503 SlowDown`.
    Busy,
    /// No source holds the extent intact: `503 ServiceUnavailable`.
    Unavailable,
    Internal,
}

impl ReadFail {
    fn response(&self) -> S3Response {
        match self {
            ReadFail::Busy => s3_error(ErrorCode::SlowDown),
            ReadFail::Unavailable => unavailable(),
            ReadFail::Internal => internal(),
        }
    }

    /// The error that ends a body stream already in flight.
    fn stream_error(&self) -> BridgeError {
        match self {
            ReadFail::Busy => BridgeError::Invalid("read interrupted: busy"),
            ReadFail::Unavailable => BridgeError::Invalid("read interrupted: extent unavailable"),
            ReadFail::Internal => BridgeError::Invalid("read interrupted"),
        }
    }
}

pub(super) async fn get_object<
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
    _key: &str,
) -> S3Response {
    match read(bridge, req, false).await {
        Ok(resp) | Err(resp) => resp,
    }
}

pub(super) async fn head_object<
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
    _key: &str,
) -> S3Response {
    match read(bridge, req, true).await {
        Ok(resp) => resp,
        // A HEAD response has no body, errors included.
        Err(mut resp) => {
            resp.headers.retain(|(name, _)| name != "content-type");
            resp.body = RespBody::Empty;
            resp
        }
    }
}

/// The pieces of `extents` that cover plaintext `[start, start + len)` of
/// the object, in order. `None` unless the extents tile that range
/// exactly: a gap would otherwise be served as a short or shifted body.
fn pieces(extents: Vec<ExtentRow>, start: u64, len: u64) -> Option<Vec<Piece>> {
    let end = start.checked_add(len)?;
    let mut out = Vec::new();
    let mut expect = 0u64; // where the next extent must begin
    let mut covered = 0u64;
    for extent in extents {
        if extent.plain_offset != Some(expect) {
            return None;
        }
        let ext_end = expect.checked_add(extent.plain_size)?;
        let from = start.max(expect);
        let to = end.min(ext_end);
        if from < to {
            covered += to - from;
            out.push(Piece {
                off: from - expect,
                len: to - from,
                extent,
            });
        }
        expect = ext_end;
    }
    (covered == len).then_some(out)
}

async fn read<
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    head: bool,
) -> core::result::Result<S3Response, S3Response> {
    let authed = authenticate(bridge, &req).await?;
    let (bucket, key) = authed.object()?;
    let Some((generation, extents)) = bridge
        .catalog
        .live_object(&bucket.id, key)
        .await
        .map_err(|_| internal())?
    else {
        return Err(s3_error(ErrorCode::NoSuchKey));
    };

    let metadata = ObjectMetadata::new(
        generation.id.as_str().to_owned(),
        generation.size,
        generation.etag.clone(),
        generation.created_at.secs().0,
        stored_headers(&generation).ok_or_else(internal)?,
        stored_checksum(&generation),
    )
    .map_err(|_| internal())?;
    let plan = plan_read(
        &metadata,
        head,
        &Conditions::from_headers(&authed.headers),
        // HEAD has no ranges: a `Range` header is ignored.
        if head {
            None
        } else {
            authed.headers.get("range")
        },
        authed.headers.get("x-amz-checksum-mode").is_some(),
    )
    .map_err(s3_error)?;
    let mut resp = S3Response {
        status: plan.status,
        headers: plan.headers,
        body: RespBody::Empty,
    };
    let Some(range) = plan.body else {
        return Ok(resp);
    };

    let mut todo = pieces(extents, range.start, range.length())
        .ok_or_else(internal)?
        .into_iter();
    let Some(first) = todo.next() else {
        return Err(internal());
    };
    // The first piece is produced before the status line goes out, so an
    // object that cannot be read is an error response, not a cut-off 200.
    let bucket = bucket.clone();
    let ready = read_piece(bridge, &bucket, &first)
        .await
        .map_err(|fail| fail.response())?;
    // One item per extent, also for a single extent: the plaintext that
    // is waiting to be pulled stays charged to the byte budget, and the
    // charge is released when the item is handed over or the body is
    // dropped. A later failure ends the stream with an error; the client
    // sees a body shorter than Content-Length.
    resp.body = RespBody::Stream(
        stream::unfold(
            (Rc::clone(bridge), bucket, todo, Some(ready)),
            |(bridge, bucket, mut todo, ready)| async move {
                let item = match ready {
                    Some(held) => Ok(held),
                    None => read_piece(&bridge, &bucket, &todo.next()?).await,
                };
                if item.is_err() {
                    todo = Vec::new().into_iter();
                }
                Some((
                    // The charge ends here, with the bytes leaving.
                    item.map(|(bytes, _charge)| bytes)
                        .map_err(|fail| fail.stream_error()),
                    (bridge, bucket, todo, None),
                ))
            },
        )
        .boxed_local(),
    );
    Ok(resp)
}

/// Plaintext `[start, start + len)` of an object, in memory, for a copy
/// that seals it again. Every byte comes through [`read_piece`], so it was
/// authenticated exactly as a GET would have it. Comes with the charge
/// for the result. Nothing else may be held for it while it runs: one
/// full-size extent needs most of an isolate's budget to be read.
pub(super) async fn read_range<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    extents: Vec<ExtentRow>,
    start: u64,
    len: u64,
) -> core::result::Result<(Vec<u8>, Charge), S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let todo = pieces(extents, start, len).ok_or_else(internal)?;
    // A cold extent comes back whole and needs twice its size while it
    // does. Beside the pieces already held that can be more than the
    // budget has, however long the read waits. Such an extent is read
    // once on its own first: that leaves it in the cache, and the read
    // below then needs room for its piece only.
    let mut held = 0u64;
    for piece in &todo {
        let cold = piece.extent.cipher_size.saturating_mul(2);
        if held > 0 && held.saturating_add(cold) > bridge.budget.capacity() {
            drop(
                read_piece(bridge, bucket, piece)
                    .await
                    .map_err(|fail| fail.response())?,
            );
        }
        held = held.saturating_add(piece.len);
    }
    let mut parts = Vec::with_capacity(todo.len());
    for piece in &todo {
        parts.push(
            read_piece(bridge, bucket, piece)
                .await
                .map_err(|fail| fail.response())?,
        );
    }
    if parts.len() == 1 {
        return parts.pop().ok_or_else(internal);
    }
    // Several pieces: they and the joined copy are live together.
    let held = bridge
        .budget
        .charge(len)
        .await
        .map_err(|_| ReadFail::Busy.response())?;
    let mut out = Vec::with_capacity(usize::try_from(len).map_err(|_| internal())?);
    for (bytes, _) in &parts {
        out.extend_from_slice(bytes);
    }
    Ok((out, held))
}

/// Decrypts one piece from ciphertext `src` that starts at stream offset
/// `base`. `None` if any chunk fails to authenticate.
fn open<K: Kek>(kek: &K, bucket: &Bucket, piece: &Piece, base: u64, src: &[u8]) -> Option<Vec<u8>> {
    let bdk = unwrap_bdk(kek, bucket.kek_version, &bucket.id, &bucket.bdk_wrapped).ok()?;
    let mut plain = vec![0u8; usize::try_from(piece.len).ok()?];
    let n = open_range(
        &bdk,
        &bucket.id,
        &piece.extent,
        base,
        src,
        piece.off,
        &mut plain,
    )
    .ok()?;
    (n == plain.len()).then_some(plain)
}

/// A blob-store read of exactly `span`. A missing, short or failing read
/// is a miss.
async fn warm<B: BlobStore>(store: &B, key: &str, span: ByteSpan) -> Option<Vec<u8>> {
    let got: Result<Option<Vec<u8>>> = store.get(key, Some(span)).await;
    got.ok()
        .flatten()
        .filter(|bytes| bytes.len() as u64 == span.len)
}

/// Swaps the working charge of a finished piece for one that covers
/// just its plaintext. Nothing can run between the release and the new
/// charge, and the plaintext is never larger than what was released.
fn retain(budget: &ByteBudget, work: Charge, plain: Vec<u8>) -> Option<(Vec<u8>, Charge)> {
    drop(work);
    let held = budget.try_charge(plain.len() as u64)?;
    Some((plain, held))
}

/// The piece's plaintext from the cache or else the safety copy. A copy
/// that is absent, short or fails authentication is skipped, never
/// served: the next source is tried instead. The caller holds a charge
/// for the ciphertext span and the plaintext.
async fn warm_piece<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    piece: &Piece,
    span: ByteSpan,
) -> Option<Vec<u8>>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let extent = &piece.extent;
    for (store, key) in [
        (&bridge.cache, extent.id.cache_key()),
        (&bridge.safety, extent.id.safety_key()),
    ] {
        if let Some(src) = warm(store, &key, span).await {
            if let Some(plain) = open(&bridge.kek, bucket, piece, span.start, &src) {
                return Some(plain);
            }
        }
    }
    None
}

/// Tells concurrent waiters apart in the poll jitter.
static WAITERS: AtomicU64 = AtomicU64::new(0);

/// Produces one piece of plaintext together with the byte-budget charge
/// that covers it; the caller keeps the charge for as long as it keeps
/// the bytes.
async fn read_piece<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    piece: &Piece,
) -> core::result::Result<(Vec<u8>, Charge), ReadFail>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let extent = &piece.extent;
    let span = cipher_span(extent.plain_size, piece.off, piece.len).ok_or(ReadFail::Internal)?;
    {
        // The ciphertext span and the plaintext are live together.
        let work = bridge
            .budget
            .charge(span.len.saturating_add(piece.len))
            .await
            .map_err(|_| ReadFail::Busy)?;
        if let Some(plain) = warm_piece(bridge, bucket, piece, span).await {
            return retain(&bridge.budget, work, plain).ok_or(ReadFail::Internal);
        }
    }

    // Cold: the whole extent comes back verified against the catalogue
    // digest and is already written to the cache. Two extents' worth is
    // live at the peak: the ciphertext and its copy for the cache while
    // it is being written, then the ciphertext and the plaintext. The
    // warm span and its plaintext are never larger than that.
    let need = extent.cipher_size.saturating_mul(2);
    let mut work = bridge
        .budget
        .charge(need)
        .await
        .map_err(|_| ReadFail::Busy)?;
    // While every provider slot is taken (more concurrent misses than
    // connections) the read waits and retries until COLD_WAIT_MS after
    // the first miss, per piece, so a later extent of a stream gets the
    // same allowance as the first. The deadline is wall-clock time, which
    // includes the catalogue and blob round trips of each poll; the sum of
    // the sleeps is a backstop in case the clock does not move. The
    // budget charge is released for each wait so
    // waiting readers do not starve the budget, and taken again without
    // waiting: each retry only sleeps here, inside the same bound. After
    // each wait the cache is checked again: another reader may have
    // filled it in the meantime.
    let waiter = WAITERS.fetch_add(1, Ordering::Relaxed);
    let deadline = bridge.clock.now().plus_ms(i64::from(COLD_WAIT_MS));
    let mut slept = 0u32;
    let mut attempt = 0u64;
    loop {
        match bridge.fetch_cold(extent).await {
            Ok(ColdFetch::Filled(cipher)) => {
                let plain =
                    open(&bridge.kek, bucket, piece, 0, &cipher).ok_or(ReadFail::Unavailable)?;
                drop(cipher);
                return retain(&bridge.budget, work, plain).ok_or(ReadFail::Internal);
            }
            Ok(ColdFetch::Busy) => {}
            Ok(ColdFetch::Interrupted) => return Err(ReadFail::Busy),
            Ok(ColdFetch::Unavailable) => return Err(ReadFail::Unavailable),
            Err(_) => return Err(ReadFail::Internal),
        }
        drop(work);
        let sleep = bridge.budget.sleeper().ok_or(ReadFail::Busy)?;
        work = loop {
            if bridge.clock.now() >= deadline || slept >= COLD_WAIT_MS {
                return Err(ReadFail::Busy);
            }
            attempt += 1;
            let seed = (bridge.clock.now().0 as u64) ^ waiter.rotate_left(32) ^ attempt;
            let ms = cold_poll_ms(seed);
            sleep(ms).await;
            slept = slept.saturating_add(ms);
            if let Some(charge) = bridge.budget.try_charge(need) {
                break charge;
            }
        };
        if let Some(plain) = warm_piece(bridge, bucket, piece, span).await {
            return retain(&bridge.budget, work, plain).ok_or(ReadFail::Internal);
        }
    }
}
