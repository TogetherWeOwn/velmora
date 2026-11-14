//! GetObject and HeadObject.
//!
//! HEAD answers from the catalogue alone. GET serves each extent from the
//! cache, else the safety copy, else Usenet (which fills the cache before
//! any byte is released). Whatever the source, only plaintext whose
//! sealed chunks authenticated is returned. A read stamps the extent's
//! `last_read_at`, at most once an hour: the hot-tier eviction order.

use std::cell::RefCell;
use std::collections::HashMap;
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
    BridgeError, Bucket, ByteSpan, ExtentId, ExtentRow, RespBody, Result, S3Request, S3Response,
};

/// Least time between two `last_read_at` writes for one extent. The
/// eviction order only needs to be this fine.
pub const READ_STAMP_MS: i64 = 3_600_000;
/// Extents whose last stamp this isolate remembers.
const STAMP_MEMO: usize = 4096;

thread_local! {
    /// The `last_read_at` this isolate last saw per extent, so that a hot
    /// extent costs one catalogue statement an hour instead of one per
    /// read. The catalogue applies the same gap across isolates.
    static STAMPED: RefCell<HashMap<String, i64>> = RefCell::new(HashMap::new());
}

/// Records that `extent` served a read, for the eviction order. Best
/// effort: a failed stamp never fails the read. `from_cache`: the bytes
/// came from the cache fill; the same write counts a fill that the
/// catalogue did not know about.
async fn stamp_read<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    extent: &ExtentId,
    from_cache: bool,
) where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let now = bridge.clock.now();
    let recent = STAMPED.with(|memo| {
        memo.borrow()
            .get(extent.as_str())
            .is_some_and(|&at| (0..READ_STAMP_MS).contains(&(now.0 - at)))
    });
    if recent {
        return;
    }
    let stamped = bridge
        .catalog
        .touch_read(extent, now, READ_STAMP_MS, from_cache);
    if let Ok(at) = stamped.await {
        // Another isolate may have stamped it: remember the stamp the
        // catalogue holds, not the time of this read.
        STAMPED.with(|memo| {
            let mut memo = memo.borrow_mut();
            if memo.len() >= STAMP_MEMO {
                memo.clear();
            }
            memo.insert(extent.as_str().to_owned(), at.0);
        });
    }
}

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

/// The piece's plaintext from the cache or else the safety copy, and
/// whether it came from the cache. A copy
/// that is absent, short or fails authentication is skipped, never
/// served: the next source is tried instead. The caller holds a charge
/// for the ciphertext span and the plaintext.
async fn warm_piece<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    piece: &Piece,
    span: ByteSpan,
) -> Option<(Vec<u8>, bool)>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let extent = &piece.extent;
    for (store, key, from_cache) in [
        (&bridge.cache, extent.id.cache_key(), true),
        (&bridge.safety, extent.id.safety_key(), false),
    ] {
        if let Some(src) = warm(store, &key, span).await {
            if let Some(plain) = open(&bridge.kek, bucket, piece, span.start, &src) {
                return Some((plain, from_cache));
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
        if let Some((plain, from_cache)) = warm_piece(bridge, bucket, piece, span).await {
            let held = retain(&bridge.budget, work, plain).ok_or(ReadFail::Internal)?;
            stamp_read(bridge, &extent.id, from_cache).await;
            return Ok(held);
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
        if let Some((plain, from_cache)) = warm_piece(bridge, bucket, piece, span).await {
            let held = retain(&bridge.budget, work, plain).ok_or(ReadFail::Internal)?;
            stamp_read(bridge, &extent.id, from_cache).await;
            return Ok(held);
        }
    }
}
