//! GetObject and HeadObject.
//!
//! HEAD answers from the catalogue alone. GET serves each extent from the
//! cache, else the safety copy, else Usenet (which fills the cache before
//! any byte is released). Whatever the source, only plaintext whose
//! sealed chunks authenticated is returned. A read stamps the extent's
//! `last_read_at`, at most once an hour: the hot-tier eviction order.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures_util::future::{poll_fn, FutureExt, LocalBoxFuture};
use futures_util::stream::{self, Stream, StreamExt};
use velmora_s3_proto::{plan_read, Conditions, ErrorCode, ObjectMetadata};

use super::common::{
    authenticate, internal, s3_error, stored_checksum, stored_headers, unavailable,
};
use crate::crypto::{cipher_span, open_range, unwrap_bdk};
use crate::fanout::{admit, Fanout, Grant, TOKEN_TTL_MS};
use crate::fetch::{
    cold_fetch_bytes, cold_poll_ms, cold_read_bytes, cold_step_bytes, ColdFetch, ColdReader,
    COLD_WAIT_MS,
};
use crate::ingress::{ByteBudget, Charge, Spawner};
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
/// the object, in order. `extents` is a run of the object's extents: all
/// of them, or those of the range alone ([`Catalog::extents_in`]). `None`
/// unless they tile the range exactly, the first beginning at or before
/// `start` and each next one where the last ended: a gap would otherwise
/// be served as a short or shifted body.
fn pieces(extents: Vec<ExtentRow>, start: u64, len: u64) -> Option<Vec<Piece>> {
    let end = start.checked_add(len)?;
    let mut out = Vec::new();
    // Where the next extent must begin.
    let mut expect = extents.first()?.plain_offset.filter(|&at| at <= start)?;
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

/// Marks an object response `no-transform` so the edge in front of the
/// Worker passes it on as it is.
///
/// Without it, the edge compresses responses of compressible types
/// (`text/*`, JSON, JavaScript, SVG, ...) when the client accepts gzip or
/// brotli, and rewrites `text/html` (email obfuscation and similar)
/// whatever the client accepts. Either way it drops `Content-Length` and
/// drops or weakens the `ETag`, also on HEAD. S3 clients read the size
/// and the MD5 from exactly those two headers; rclone, for one, takes the
/// missing length as size 0, calls the upload corrupt and deletes it.
///
/// The stored metadata is not changed. A stored `Cache-Control` is kept
/// and `no-transform` is appended to it (`max-age=60` is served as
/// `max-age=60, no-transform`), unless it already has the directive; an
/// object without one is served `Cache-Control: no-transform`.
fn forbid_edge_transform(headers: &mut Vec<(String, String)>) {
    const DIRECTIVE: &str = "no-transform";
    match headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
    {
        Some((_, value)) => {
            let present = directives(value)
                .iter()
                .any(|d| d.trim().eq_ignore_ascii_case(DIRECTIVE));
            if !present {
                // Trailing commas are dropped rather than doubled.
                let base = value
                    .trim()
                    .trim_end_matches(|c: char| c == ',' || c.is_ascii_whitespace());
                *value = if base.is_empty() {
                    DIRECTIVE.to_string()
                } else {
                    format!("{base}, {DIRECTIVE}")
                };
            }
        }
        None => headers.push(("cache-control".to_string(), DIRECTIVE.to_string())),
    }
}

/// The directives of a `Cache-Control` value: split at the commas outside
/// quoted strings (`private="a, b"` is one directive), a backslash escaping
/// the next character inside one.
fn directives(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&value[start..]);
    out
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
    let Some(generation) = bridge
        .catalog
        .live_generation(&bucket.id, key)
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
    let mut headers = plan.headers;
    forbid_edge_transform(&mut headers);
    let mut resp = S3Response {
        status: plan.status,
        headers,
        body: RespBody::Empty,
    };
    let Some(range) = plan.body else {
        return Ok(resp);
    };

    // A body above the fan-out size is not read here: the runtime asks
    // for it in sub-ranges, each from an invocation of its own, all
    // pinned to this generation.
    if let Some(chunk) = bridge.cfg.get_fanout_bytes {
        if range.length() > chunk {
            let mint = {
                let bridge = Rc::clone(bridge);
                let (bucket, generation) = (bucket.id.clone(), generation.id.clone());
                Rc::new(move |start: u64, len: u64| {
                    Grant {
                        bucket: bucket.clone(),
                        generation: generation.clone(),
                        start,
                        len,
                        expires: bridge.clock.now().plus_ms(TOKEN_TTL_MS),
                    }
                    .seal(&bridge.kek)
                })
            };
            // A range with more sub-ranges than one invocation may ask
            // for is refused, never served in part.
            let fanout =
                Fanout::new(range.start, range.length(), chunk, mint).ok_or_else(internal)?;
            resp.body = RespBody::Fanout(fanout);
            return Ok(resp);
        }
    }
    let end = range
        .start
        .checked_add(range.length())
        .ok_or_else(internal)?;
    let extents = bridge
        .catalog
        .extents_in(&generation.id, range.start, end)
        .await
        .map_err(|_| internal())?;
    resp.body = body(bridge, bucket.clone(), extents, range.start, range.length()).await?;
    Ok(resp)
}

/// Serves one sub-range of a large GET (see [`crate::fanout`]): the
/// plaintext the request's token grants, from the generation it names,
/// as a `200` of exactly that length. A request without a valid token is
/// `403`, whatever is wrong with it.
pub(super) async fn fanout_piece<
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
) -> S3Response {
    let Ok(grant) = admit(&bridge.kek, &req, bridge.clock.now()) else {
        return s3_error(ErrorCode::AccessDenied);
    };
    match granted(bridge, &grant).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn granted<
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    grant: &Grant,
) -> core::result::Result<S3Response, S3Response> {
    // The grant was minted for a generation that existed and a range
    // inside it; anything else here is a fault, not a client error.
    let (bucket, generation) = bridge
        .catalog
        .generation_by_id(&grant.bucket, &grant.generation)
        .await
        .map_err(|_| internal())?
        .ok_or_else(internal)?;
    let end = grant
        .start
        .checked_add(grant.len)
        .filter(|&end| end <= generation.size)
        .ok_or_else(internal)?;
    let extents = bridge
        .catalog
        .extents_in(&generation.id, grant.start, end)
        .await
        .map_err(|_| internal())?;
    Ok(S3Response {
        status: 200,
        headers: vec![
            ("content-length".into(), grant.len.to_string()),
            ("content-type".into(), "application/octet-stream".into()),
        ],
        body: body(bridge, bucket, extents, grant.start, grant.len).await?,
    })
}

/// The stream of plaintext `[start, start + len)` from `extents`, which
/// must tile it.
async fn body<
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    bucket: Bucket,
    extents: Vec<ExtentRow>,
    start: u64,
    len: u64,
) -> core::result::Result<RespBody, S3Response> {
    let todo = pieces(extents, start, len).ok_or_else(internal)?;
    if todo.is_empty() {
        return Err(internal());
    }
    // One item per extent, also for a single extent: the plaintext that
    // is waiting to be pulled stays charged to the byte budget, and the
    // charge is released when the item is handed over or the body is
    // dropped. A later failure ends the stream with an error; the client
    // sees a body shorter than Content-Length.
    let bridge = Rc::clone(bridge);
    let spawner = bridge.budget.spawner().cloned();
    let mut items = driven(spawner.as_ref(), move |out| {
        relay(bridge, bucket, todo, out)
    });
    // The first piece is produced before the status line goes out, so an
    // object that cannot be read is an error response, not a cut-off 200.
    let first = match items.next().await {
        Some(Ok(held)) => held,
        Some(Err(fail)) => return Err(fail.response()),
        None => return Err(internal()),
    };
    Ok(RespBody::Stream(
        stream::once(async move { Ok(first) })
            .chain(items)
            // The charge ends here, with the bytes leaving.
            .map(|item| {
                item.map(|(bytes, _charge)| bytes)
                    .map_err(|fail| fail.stream_error())
            })
            .boxed_local(),
    ))
}

/// One produced piece, or why the body ends here.
type Item = core::result::Result<(Vec<u8>, Charge), ReadFail>;

/// What a [`Driven`] stream shares with the future that feeds it.
struct Shared<T> {
    /// The one item that was produced and not taken yet.
    slot: RefCell<Option<T>>,
    /// The feeding future, until it returned or its stream was dropped.
    work: RefCell<Option<LocalBoxFuture<'static, ()>>>,
    /// The reader of the stream, waiting for an item of a spawned future.
    reader: RefCell<Option<Waker>>,
    /// The spawned task, waiting for its item to be taken.
    task: RefCell<Option<Waker>>,
}

impl<T> Shared<T> {
    /// Polls the feeding future once, if it is still there.
    fn run(&self, cx: &mut Context<'_>) {
        let mut work = self.work.borrow_mut();
        if let Some(running) = work.as_mut() {
            if running.as_mut().poll(cx).is_ready() {
                *work = None;
            }
        }
    }
}

/// The hand-over from the future that produces a body to the stream that
/// carries it: one item at a time.
struct Out<T> {
    shared: Rc<Shared<T>>,
}

impl<T> Out<T> {
    /// Hands `item` to the stream and returns once it was taken. The
    /// future is polled again after that: by the stream when it is asked
    /// for the next item, or by its task, which the stream wakes.
    async fn send(&self, item: T) {
        *self.shared.slot.borrow_mut() = Some(item);
        poll_fn(|_| match self.shared.slot.borrow().is_some() {
            true => Poll::Pending,
            false => Poll::Ready(()),
        })
        .await;
    }
}

/// A stream of what one future hands to its [`Out`]. The future never
/// runs past an item that was not taken, so at most one item waits, and
/// it ends the stream by returning.
///
/// Without a spawner the future runs only while the stream is polled.
/// With one it runs as a task of the host, so the next item is produced
/// while the reader is busy with the one it took (a client takes about as
/// long to receive an extent as Usenet takes to deliver the next).
///
/// Dropping the stream drops the future and the waiting item right then,
/// spawned or not: nothing they hold outlives the body.
struct Driven<T> {
    shared: Rc<Shared<T>>,
    spawned: bool,
}

fn driven<T: 'static, F: Future<Output = ()> + 'static>(
    spawner: Option<&Spawner>,
    make: impl FnOnce(Out<T>) -> F,
) -> Driven<T> {
    let shared = Rc::new(Shared {
        slot: RefCell::new(None),
        work: RefCell::new(None),
        reader: RefCell::new(None),
        task: RefCell::new(None),
    });
    let work = make(Out {
        shared: Rc::clone(&shared),
    });
    *shared.work.borrow_mut() = Some(work.boxed_local());
    if let Some(spawn) = spawner {
        let shared = Rc::clone(&shared);
        spawn(
            poll_fn(move |cx| {
                *shared.task.borrow_mut() = Some(cx.waker().clone());
                shared.run(cx);
                let over = shared.work.borrow().is_none();
                if over || shared.slot.borrow().is_some() {
                    if let Some(reader) = shared.reader.borrow_mut().take() {
                        reader.wake();
                    }
                }
                match over {
                    true => Poll::Ready(()),
                    false => Poll::Pending,
                }
            })
            .boxed_local(),
        );
    }
    Driven {
        shared,
        spawned: spawner.is_some(),
    }
}

impl<T> Stream for Driven<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let shared = &self.shared;
        let take = || {
            let item = shared.slot.borrow_mut().take()?;
            // The task may go on to the next item.
            if let Some(task) = shared.task.borrow_mut().take() {
                task.wake();
            }
            Some(item)
        };
        if let Some(item) = take() {
            return Poll::Ready(Some(item));
        }
        if !self.spawned {
            shared.run(cx);
            if let Some(item) = take() {
                return Poll::Ready(Some(item));
            }
        }
        if shared.work.borrow().is_none() {
            return Poll::Ready(None);
        }
        if self.spawned {
            *shared.reader.borrow_mut() = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl<T> Drop for Driven<T> {
    fn drop(&mut self) {
        // Taken out first: what the future holds is dropped after the
        // borrow ended.
        let work = self.shared.work.borrow_mut().take();
        drop(work);
        let item = self.shared.slot.borrow_mut().take();
        drop(item);
        // The task finds its future gone and ends.
        if let Some(task) = self.shared.task.borrow_mut().take() {
            task.wake();
        }
    }
}

/// Runs `f` and, beside it, the cache write that is under way, if any.
async fn beside<F: Future>(put: &mut Option<LocalBoxFuture<'_, ()>>, f: F) -> F::Output {
    let mut f = core::pin::pin!(f);
    poll_fn(|cx| {
        if let Some(writing) = put.as_mut() {
            if writing.as_mut().poll(cx).is_ready() {
                *put = None;
            }
        }
        f.as_mut().poll(cx)
    })
    .await
}

/// Produces the pieces of one body in order. The connections to Usenet
/// stay open from one cold extent to the next, and the cache write of an
/// extent runs while the next one is read (see [`Cold`]).
async fn relay<C, B, N, J, K, T>(
    bridge: Rc<Bridge<C, B, N, J, K, T>>,
    bucket: Bucket,
    todo: Vec<Piece>,
    out: Out<Item>,
) where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let mut cold = Cold::new(&bridge);
    let last = todo.len() - 1;
    for (at, piece) in todo.iter().enumerate() {
        let item = cold.piece(&bucket, piece).await;
        // Before the last item and before an error: the reader of the
        // body may never ask again after either, and the last extent
        // would then be missing from the cache and the provider slots
        // would be held until they expire.
        if at == last || item.is_err() {
            cold.end().await;
        }
        let failed = item.is_err();
        let sent = Spent::time(&bridge.clock, &cold.spent.send, out.send(item));
        beside(&mut cold.put, sent).await;
        if failed {
            return;
        }
    }
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
        let cold = cold_read_bytes(piece.extent.cipher_size, bridge.cfg.cold_sockets);
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

/// How often the read of one extent is begun again after every provider
/// broke off in the middle of it. A download in sub-ranges that fails
/// after its first byte is lost whole, so one bad moment of a provider
/// or a proxy should not be the end of it.
pub const INTERRUPTED_RETRIES: u32 = 2;

/// Tells concurrent waiters apart in the poll jitter.
static WAITERS: AtomicU64 = AtomicU64::new(0);

/// Produces one piece of plaintext together with the byte-budget charge
/// that covers it; the caller keeps the charge for as long as it keeps
/// the bytes. An extent that came from Usenet is in the cache when this
/// returns, unless the cache refused it.
async fn read_piece<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    piece: &Piece,
) -> Item
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let mut cold = Cold::new(bridge);
    let item = cold.piece(bucket, piece).await;
    cold.end().await;
    item
}

/// What a read keeps from one extent to the next while it reads from
/// Usenet: the connections, and the cache write of the extent before.
///
/// An extent from Usenet is verified against the catalogue digest by the
/// reader, opened, and then handed on while its ciphertext is written to
/// the cache. The write runs beside whatever the read does next, and one
/// write is under way at most: the next extent is opened only after the
/// write before it has ended. Beside a write the budget holds the
/// ciphertext being written and what reading the next extent needs
/// ([`cold_fetch_bytes`]); the rest of what opening it needs
/// ([`cold_step_bytes`]) is charged when the write has ended. When the
/// first does not fit, the read waits for the write. A write that fails costs the cache its copy and the read
/// nothing: the bytes were verified before.
struct Cold<'b, C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    bridge: &'b Bridge<C, B, N, J, K, T>,
    reader: Option<ColdReader<'b, C, N, T>>,
    put: Option<LocalBoxFuture<'b, ()>>,
    spent: Rc<Spent>,
}

/// Milliseconds of one cold body by what it was waiting for, for the log.
/// The clock of a Worker stands still while code runs, so each number is
/// time spent waiting, and what runs beside something is counted twice.
#[derive(Default)]
struct Spent {
    /// Asking the cache and the safety copy first.
    warm: Cell<i64>,
    /// Reading extents from Usenet.
    read: Cell<i64>,
    /// Waiting for the cache write before, or for room in the budget.
    wait: Cell<i64>,
    /// Waiting for the reader of the body to take a piece.
    send: Cell<i64>,
    /// Writing extents to the cache.
    put: Cell<i64>,
}

impl Spent {
    /// Runs `f` and adds the time it took to `to`.
    async fn time<F: Future>(clock: &impl Clock, to: &Cell<i64>, f: F) -> F::Output {
        let began = clock.now();
        let out = f.await;
        to.set(to.get() + clock.now().0 - began.0);
        out
    }
}

impl<'b, C, B, N, J, K, T> Cold<'b, C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    fn new(bridge: &'b Bridge<C, B, N, J, K, T>) -> Self {
        Self {
            bridge,
            reader: None,
            put: None,
            spent: Rc::default(),
        }
    }

    /// Ends the connections and frees their slots, while the cache write
    /// goes on.
    async fn hang_up(&mut self) {
        if let Some(reader) = self.reader.take() {
            let stats = reader.stats();
            beside(&mut self.put, reader.close()).await;
            let ms = &self.spent;
            crate::trace::cold_read(|| {
                format!(
                    "{stats} warm_ms={} read_ms={} wait_ms={} send_ms={} put_ms={}",
                    ms.warm.get(),
                    ms.read.get(),
                    ms.wait.get(),
                    ms.send.get(),
                    ms.put.get()
                )
            });
        }
    }

    /// Lets the cache write end, then the connections.
    async fn end(&mut self) {
        if let Some(writing) = self.put.take() {
            writing.await;
        }
        self.hang_up().await;
    }

    /// Room for the next step. When it is not there beside the cache
    /// write that is under way, the write ends first: the read then
    /// needs no more than it would alone.
    async fn charge(&mut self, need: u64) -> core::result::Result<Charge, ReadFail> {
        let budget = &self.bridge.budget;
        if let Some(charge) = budget.try_charge(need) {
            return Ok(charge);
        }
        let put = self.put.take();
        let wait = async {
            if let Some(writing) = put {
                writing.await;
            }
            budget.charge(need).await.map_err(|_| ReadFail::Busy)
        };
        Spent::time(&self.bridge.clock, &self.spent.wait, wait).await
    }

    /// Room for reading one extent: all of `need` when no cache write
    /// is under way, and beside one only `lean`, what is live until the
    /// extent is opened. The write ends before that.
    async fn step(&mut self, need: u64, lean: u64) -> core::result::Result<Charge, ReadFail> {
        if self.put.is_some() && lean < need {
            if let Some(charge) = self.bridge.budget.try_charge(lean) {
                return Ok(charge);
            }
        }
        self.charge(need).await
    }

    /// The piece from the cache or else the safety copy, stamped as
    /// read. A copy that is absent, short or fails authentication is
    /// skipped, never served: the next source is tried instead, and
    /// `Unavailable` says that neither has it.
    ///
    /// The ciphertext span is charged before a store is asked and the
    /// plaintext only when a copy is there, so asking for an extent that
    /// turns out to be cold fits beside the cache write of the one
    /// before it.
    async fn warm(&mut self, bucket: &Bucket, piece: &Piece, span: ByteSpan) -> Item {
        let bridge = self.bridge;
        let extent = &piece.extent;
        let mut work = self.charge(span.len).await?;
        let mut whole = false;
        for from_cache in [true, false] {
            let asked = async {
                match from_cache {
                    true => warm(&bridge.cache, &extent.id.cache_key(), span).await,
                    false => warm(&bridge.safety, &extent.id.safety_key(), span).await,
                }
            };
            let asked = Spent::time(&bridge.clock, &self.spent.warm, asked);
            let Some(src) = beside(&mut self.put, asked).await else {
                continue;
            };
            if !core::mem::replace(&mut whole, true) {
                let more = self.charge(piece.len).await?;
                work.absorb(more);
            }
            let Some(plain) = open(&bridge.kek, bucket, piece, span.start, &src) else {
                continue;
            };
            drop(src);
            let held = retain(&bridge.budget, work, plain).ok_or(ReadFail::Internal)?;
            beside(&mut self.put, stamp_read(bridge, &extent.id, from_cache)).await;
            return Ok(held);
        }
        Err(ReadFail::Unavailable)
    }

    async fn piece(&mut self, bucket: &Bucket, piece: &Piece) -> Item {
        let bridge = self.bridge;
        let extent = &piece.extent;
        let span =
            cipher_span(extent.plain_size, piece.off, piece.len).ok_or(ReadFail::Internal)?;
        match self.warm(bucket, piece, span).await {
            Err(ReadFail::Unavailable) => {}
            found => {
                // Idle connections would outlive their slots.
                self.hang_up().await;
                return found;
            }
        }

        // Cold: the whole extent comes back verified against the
        // catalogue digest. While it is read, the ciphertext and the wire
        // text on the sockets are live; while it is opened, the
        // ciphertext and the plaintext. The warm span and its plaintext
        // are never larger than that.
        let need = cold_step_bytes(extent.cipher_size, bridge.cfg.cold_sockets);
        let lean = cold_fetch_bytes(extent.cipher_size, bridge.cfg.cold_sockets);
        let mut work = self.step(need, lean).await?;
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
        let mut interrupted = 0u32;
        loop {
            let reader = match &mut self.reader {
                Some(reader) => reader,
                none => none.insert(bridge.cold_reader().map_err(|_| ReadFail::Internal)?),
            };
            let fetched = Spent::time(&bridge.clock, &self.spent.read, reader.fetch(extent));
            let read = beside(&mut self.put, fetched).await;
            match read {
                Ok(ColdFetch::Filled(cipher)) => {
                    // One cache write at a time.
                    if let Some(writing) = self.put.take() {
                        Spent::time(&bridge.clock, &self.spent.wait, writing).await;
                    }
                    // What a read beside that write left uncharged. The
                    // write has just released at least as much.
                    let short = need.saturating_sub(work.bytes());
                    if short > 0 {
                        let more = match bridge.budget.try_charge(short) {
                            Some(more) => more,
                            None => {
                                let room = bridge.budget.charge(short);
                                Spent::time(&bridge.clock, &self.spent.wait, room)
                                    .await
                                    .map_err(|_| ReadFail::Busy)?
                            }
                        };
                        work.absorb(more);
                    }
                    let plain = open(&bridge.kek, bucket, piece, 0, &cipher)
                        .ok_or(ReadFail::Unavailable)?;
                    // The charge is split between the plaintext, which
                    // leaves with the piece, and the ciphertext, which
                    // stays until it is written. Nothing runs between the
                    // release and the two charges, and together they are
                    // never more than what was released.
                    drop(work);
                    let held = bridge
                        .budget
                        .try_charge(plain.len() as u64)
                        .ok_or(ReadFail::Internal)?;
                    if let Some(copy) = bridge.budget.try_charge(cipher.len() as u64) {
                        let (extent, spent) = (extent.clone(), Rc::clone(&self.spent));
                        let write = async move {
                            // Verified already: a cache that does not
                            // take the copy does not fail the read.
                            let fill = bridge.cache_fill(&extent, cipher);
                            let _ = Spent::time(&bridge.clock, &spent.put, fill).await;
                            drop(copy);
                        };
                        self.put = Some(write.boxed_local());
                    }
                    return Ok((plain, held));
                }
                Ok(ColdFetch::Busy) => {}
                // Every provider that was asked broke off (a proxy that
                // went away, a provider that hung up): the read is tried
                // again after a wait, on new connections, a few times.
                Ok(ColdFetch::Interrupted) if interrupted < INTERRUPTED_RETRIES => interrupted += 1,
                Ok(ColdFetch::Interrupted) => return Err(ReadFail::Busy),
                Ok(ColdFetch::Unavailable) => return Err(ReadFail::Unavailable),
                Err(_) => return Err(ReadFail::Internal),
            }
            // Nothing is held while waiting: neither slots nor budget.
            self.hang_up().await;
            drop(work);
            let sleep = bridge.budget.sleeper().ok_or(ReadFail::Busy)?;
            loop {
                if bridge.clock.now() >= deadline || slept >= COLD_WAIT_MS {
                    return Err(ReadFail::Busy);
                }
                attempt += 1;
                let seed = (bridge.clock.now().0 as u64) ^ waiter.rotate_left(32) ^ attempt;
                let ms = cold_poll_ms(seed);
                beside(&mut self.put, sleep(ms)).await;
                slept = slept.saturating_add(ms);
                // Until there is room for the read, which is released
                // again here: what follows takes what it needs.
                if bridge.budget.try_charge(need).is_some() {
                    break;
                }
            }
            // Another reader may have filled the cache in the meantime.
            match self.warm(bucket, piece, span).await {
                Err(ReadFail::Unavailable) => {}
                found => return found,
            }
            // Not in the cache: read it, under a charge taken as above.
            work = self.step(need, lean).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use futures_util::task::{noop_waker, waker, ArcWake};

    /// Polls `stream` once for its next item.
    fn pull<S: Stream + Unpin>(stream: &mut S) -> Poll<Option<S::Item>> {
        stream.poll_next_unpin(&mut Context::from_waker(&noop_waker()))
    }

    /// The items come out in the order they were handed over, and the
    /// future that produces them never runs past one that was not taken.
    #[test]
    fn a_driven_stream_is_paced_by_its_reader() {
        let made = Rc::new(Cell::new(0u32));
        let count = Rc::clone(&made);
        let mut items = Box::pin(driven(None, move |out: Out<u32>| async move {
            for n in 1..=3u32 {
                count.set(n);
                out.send(n).await;
            }
            count.set(99);
        }));
        assert_eq!(made.get(), 0, "nothing runs before the first pull");
        assert_eq!(pull(&mut items), Poll::Ready(Some(1)));
        assert_eq!(made.get(), 1, "the second item waits for the next pull");
        assert_eq!(pull(&mut items), Poll::Ready(Some(2)));
        assert_eq!(pull(&mut items), Poll::Ready(Some(3)));
        assert_eq!(made.get(), 3);
        // What the future does after its last item runs with the pull
        // that finds the end.
        assert_eq!(pull(&mut items), Poll::Ready(None));
        assert_eq!(made.get(), 99);
        assert_eq!(pull(&mut items), Poll::Ready(None));
    }

    /// A future that waits is asked again with each pull; one that is
    /// dropped with its stream runs no further.
    #[test]
    fn a_driven_stream_waits_with_its_future_and_ends_with_its_reader() {
        let gate = Rc::new(Cell::new(false));
        let done = Rc::new(Cell::new(false));
        let (open, ended) = (Rc::clone(&gate), Rc::clone(&done));
        let mut items = Box::pin(driven(None, move |out: Out<u32>| async move {
            poll_fn(|_| match open.get() {
                true => Poll::Ready(()),
                false => Poll::Pending,
            })
            .await;
            out.send(7u32).await;
            out.send(8u32).await;
            ended.set(true);
        }));
        assert_eq!(pull(&mut items), Poll::Pending);
        gate.set(true);
        assert_eq!(pull(&mut items), Poll::Ready(Some(7)));
        drop(items);
        assert!(!done.get());
    }

    /// Counts how often it was woken.
    #[derive(Default)]
    struct Woken(AtomicUsize);

    impl ArcWake for Woken {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Woken {
        fn times(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// A host that runs what is spawned on it only when the test says so.
    #[derive(Default)]
    struct Host {
        tasks: Rc<RefCell<Vec<LocalBoxFuture<'static, ()>>>>,
        woken: Arc<Woken>,
    }

    impl Host {
        fn spawner(&self) -> Spawner {
            let tasks = Rc::clone(&self.tasks);
            Rc::new(move |task| tasks.borrow_mut().push(task))
        }

        /// Polls every task once; the ones that ended are gone.
        fn turn(&self) {
            let waker = waker(Arc::clone(&self.woken));
            let mut cx = Context::from_waker(&waker);
            self.tasks
                .borrow_mut()
                .retain_mut(|task| task.as_mut().poll(&mut cx).is_pending());
        }

        fn running(&self) -> usize {
            self.tasks.borrow().len()
        }
    }

    /// Polls `stream` once with a waker that counts.
    fn pull_with<S: Stream + Unpin>(stream: &mut S, reader: &Arc<Woken>) -> Poll<Option<S::Item>> {
        stream.poll_next_unpin(&mut Context::from_waker(&waker(Arc::clone(reader))))
    }

    /// A spawned future runs without its reader, one item ahead and no
    /// further, and the items come out in order.
    #[test]
    fn a_spawned_stream_is_one_item_ahead_of_its_reader() {
        let host = Host::default();
        let reader = Arc::new(Woken::default());
        let made = Rc::new(Cell::new(0u32));
        let count = Rc::clone(&made);
        let mut items = Box::pin(driven(
            Some(&host.spawner()),
            move |out: Out<u32>| async move {
                for n in 1..=3u32 {
                    count.set(n);
                    out.send(n).await;
                }
                count.set(99);
            },
        ));
        assert_eq!(made.get(), 0, "the future runs on the host only");
        // A pull does not run it either: the reader waits to be woken.
        assert_eq!(pull_with(&mut items, &reader), Poll::Pending);
        assert_eq!(made.get(), 0);
        host.turn();
        assert_eq!(made.get(), 1);
        assert_eq!(reader.times(), 1, "the waiting reader is told");
        // However often the host runs it, it stays at the item not taken.
        host.turn();
        host.turn();
        assert_eq!(made.get(), 1);
        assert_eq!(pull_with(&mut items, &reader), Poll::Ready(Some(1)));
        assert_eq!(host.woken.times(), 1, "taking an item wakes the task");
        // The next one is produced while the reader is away.
        host.turn();
        assert_eq!(made.get(), 2);
        assert_eq!(pull_with(&mut items, &reader), Poll::Ready(Some(2)));
        assert_eq!(made.get(), 2, "a pull does not run the future");
        host.turn();
        assert_eq!(pull_with(&mut items, &reader), Poll::Ready(Some(3)));
        // The end is not there before the future returned.
        assert_eq!(pull_with(&mut items, &reader), Poll::Pending);
        host.turn();
        assert_eq!(made.get(), 99);
        assert_eq!(reader.times(), 2, "the waiting reader is told of the end");
        assert_eq!(host.running(), 0, "the task ends with its future");
        assert_eq!(pull_with(&mut items, &reader), Poll::Ready(None));
        assert_eq!(pull_with(&mut items, &reader), Poll::Ready(None));
    }

    /// Dropping the stream drops the spawned future and the item that
    /// waits right then, not when the host next runs the task.
    #[test]
    fn a_spawned_stream_that_is_dropped_takes_its_future_along() {
        /// Says when it was dropped.
        struct Held(Rc<Cell<u32>>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let host = Host::default();
        let dropped = Rc::new(Cell::new(0u32));
        let done = Rc::new(Cell::new(false));
        let (in_item, in_future) = (Held(Rc::clone(&dropped)), Held(Rc::clone(&dropped)));
        let ended = Rc::clone(&done);
        let items = Box::pin(driven(
            Some(&host.spawner()),
            move |out: Out<Held>| async move {
                let _held = in_future;
                out.send(in_item).await;
                ended.set(true);
            },
        ));
        host.turn();
        assert_eq!(dropped.get(), 0);
        assert_eq!(host.running(), 1);
        drop(items);
        assert_eq!(dropped.get(), 2, "the item and what the future held");
        assert_eq!(host.woken.times(), 1, "the task is woken to end");
        host.turn();
        assert_eq!(host.running(), 0);
        assert!(!done.get(), "the future ran no further");
    }

    /// The same for a stream that is dropped before the host ever ran
    /// its task.
    #[test]
    fn a_spawned_stream_dropped_before_it_ran_never_runs() {
        let host = Host::default();
        let ran = Rc::new(Cell::new(false));
        let run = Rc::clone(&ran);
        let items = Box::pin(driven(
            Some(&host.spawner()),
            move |out: Out<u32>| async move {
                run.set(true);
                out.send(1).await;
            },
        ));
        drop(items);
        host.turn();
        assert!(!ran.get());
        assert_eq!(host.running(), 0);
    }

    /// The cache write runs beside the other work and is not polled
    /// again once it has ended.
    #[test]
    fn a_write_under_way_runs_beside_the_next_step() {
        let steps = Rc::new(Cell::new(0u32));
        let wrote = Rc::clone(&steps);
        let mut put: Option<LocalBoxFuture<'_, ()>> = Some(
            async move {
                for _ in 0..2 {
                    wrote.set(wrote.get() + 1);
                    let mut waited = false;
                    poll_fn(|_| match core::mem::replace(&mut waited, true) {
                        true => Poll::Ready(()),
                        false => Poll::Pending,
                    })
                    .await;
                }
            }
            .boxed_local(),
        );
        let mut turns = 0u32;
        let mut step = Box::pin(beside(
            &mut put,
            poll_fn(|_| {
                turns += 1;
                match turns < 5 {
                    true => Poll::Pending,
                    false => Poll::Ready(turns),
                }
            }),
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..4 {
            assert!(step.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(step.as_mut().poll(&mut cx), Poll::Ready(5));
        drop(step);
        assert_eq!(steps.get(), 2);
        assert!(put.is_none(), "the write ended while the step ran");
    }

    fn served(stored: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut headers = stored
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        forbid_edge_transform(&mut headers);
        headers
    }

    fn cache_control(headers: &[(String, String)]) -> Vec<&str> {
        headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("cache-control"))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    #[test]
    fn an_object_without_cache_control_gets_no_transform() {
        let h = served(&[("content-type", "text/html"), ("etag", "\"e\"")]);
        assert_eq!(cache_control(&h), ["no-transform"]);
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn a_stored_cache_control_is_kept_and_extended() {
        let h = served(&[("cache-control", "max-age=60, private")]);
        assert_eq!(cache_control(&h), ["max-age=60, private, no-transform"]);
    }

    #[test]
    fn a_stored_no_transform_is_not_repeated() {
        for stored in [
            "no-transform",
            "max-age=60, No-Transform",
            " no-transform ,public",
        ] {
            let h = served(&[("cache-control", stored)]);
            assert_eq!(cache_control(&h), [stored], "{stored:?}");
        }
        // A directive that only contains the word does not count.
        let h = served(&[("cache-control", "x-no-transform-ish")]);
        assert_eq!(cache_control(&h), ["x-no-transform-ish, no-transform"]);
    }

    #[test]
    fn a_quoted_argument_is_not_a_directive() {
        // RFC 9111 field-name lists: the quoted `no-transform` is a name.
        let stored = r#"private="x-a,no-transform,x-b""#;
        let h = served(&[("cache-control", stored)]);
        assert_eq!(cache_control(&h), [format!("{stored}, no-transform")]);
        // An escaped quote does not end the quoted string.
        let stored = r#"private="a\",no-transform", max-age=5"#;
        let h = served(&[("cache-control", stored)]);
        assert_eq!(cache_control(&h), [format!("{stored}, no-transform")]);
        // A real directive after a quoted argument counts.
        let stored = r#"no-cache="set-cookie, x", no-transform"#;
        let h = served(&[("cache-control", stored)]);
        assert_eq!(cache_control(&h), [stored]);
    }

    #[test]
    fn an_empty_stored_cache_control_becomes_no_transform() {
        for stored in ["", " ", ","] {
            let h = served(&[("Cache-Control", stored)]);
            assert_eq!(cache_control(&h), ["no-transform"], "{stored:?}");
        }
    }

    #[test]
    fn a_trailing_comma_is_not_doubled() {
        for stored in ["max-age=60, ", "max-age=60, ,", "max-age=60,,"] {
            let h = served(&[("cache-control", stored)]);
            assert_eq!(
                cache_control(&h),
                ["max-age=60, no-transform"],
                "{stored:?}"
            );
        }
    }
}
