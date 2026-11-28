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

use futures_util::future::{poll_fn, select, Either, FutureExt, LocalBoxFuture};
use futures_util::stream::{self, Stream, StreamExt};
use velmora_s3_proto::{plan_read, Conditions, ErrorCode, ObjectMetadata};

use super::common::{
    authenticate_observed, internal, s3_error, stored_checksum, stored_headers, unavailable,
};
use crate::config::MAX_EXTENT_BYTES_LIMIT;
use crate::crypto::{cipher_span, open_range, unwrap_bdk};
use crate::fanout::{admit, Fanout, Grant, FRONT_SUBREQUEST_BUDGET, MAX_RETRIES, TOKEN_TTL_MS};
use crate::fetch::{
    beside, cold_fetch_bytes, cold_poll_ms, cold_read_bytes, cold_rebuild_most, cold_step_bytes,
    ColdFetch, ColdReader, COLD_WAIT_MS,
};
use crate::ingress::{ByteBudget, Charge, Spawner, CHARGE_WAIT_MS};
use crate::metrics::{Fault, GetFailureStage as Stage, GetObservation};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{
    BridgeError, Bucket, ByteSpan, ExtentId, ExtentRow, GenerationId, RespBody, Result, S3Request,
    S3Response, UnixMs,
};

/// Least time between two `last_read_at` writes for one extent. The
/// eviction order only needs to be this fine.
pub const READ_STAMP_MS: i64 = 3_600_000;
const HIT_FLUSH_MS: i64 = 15 * 60 * 1_000;
// Bound the unflushed traffic when a busy isolate is retired before the
// time gate. Sparse traffic can still lose its last best-effort batch.
const HIT_FLUSH_BYTES: u64 = 1 << 30;

#[derive(Clone, Copy, Default)]
struct HitAccumulator {
    bytes: u64,
    last_flush: Option<UnixMs>,
}

impl HitAccumulator {
    fn record(&mut self, bytes: u64, now: UnixMs) -> Option<u64> {
        self.bytes = self.bytes.saturating_add(bytes);
        let not_due = self
            .last_flush
            .is_some_and(|at| now.0.saturating_sub(at.0) < HIT_FLUSH_MS);
        if self.bytes == 0 || (self.bytes < HIT_FLUSH_BYTES && not_due) {
            return None;
        }
        self.last_flush = Some(now);
        Some(std::mem::take(&mut self.bytes))
    }
}

thread_local! {
    static HOT_HITS: Cell<HitAccumulator> = const { Cell::new(HitAccumulator { bytes: 0, last_flush: None }) };
}

/// With zero bytes, only drains an existing batch that aged out.
pub(super) fn record_hit<C, B, N, J, K, T>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    spawner: &Spawner,
    bytes: u64,
) where
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
{
    if bridge.catalog.is_frozen() {
        return;
    }
    let flush = HOT_HITS.with(|slot| {
        let mut pending = slot.get();
        let flush = pending.record(bytes, bridge.clock.now());
        slot.set(pending);
        flush
    });
    if let Some(bytes) = flush {
        let bridge = Rc::clone(bridge);
        // A transport error may have committed. Never retry an add.
        spawner(
            async move {
                let _ = bridge.catalog.hot_counters_add(bytes).await;
            }
            .boxed_local(),
        );
    }
}
/// Extents whose last stamp this isolate remembers.
const STAMP_MEMO: usize = 4096;

thread_local! {
    /// The `last_read_at` this isolate last saw per extent, so that a hot
    /// extent costs one catalogue statement an hour instead of one per
    /// read. The catalogue applies the same gap across isolates.
    static STAMPED: RefCell<HashMap<String, i64>> = RefCell::new(HashMap::new());
}

/// Whether a stamp `at` this isolate remembers is recent enough at `now`
/// to skip the catalogue. The stamp is the catalogue's, written by any
/// invocation or isolate, so it can be a moment ahead of this clock: that
/// is recent, not a reason to stamp again (see [`UnixMs::within`]).
fn stamped_recently(now: UnixMs, at: i64) -> bool {
    now.within(UnixMs(at), READ_STAMP_MS)
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
    if bridge.catalog.is_frozen() {
        return;
    }
    let now = bridge.clock.now();
    let recent = STAMPED.with(|memo| {
        memo.borrow()
            .get(extent.as_str())
            .is_some_and(|&at| stamped_recently(now, at))
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
    /// Out of byte budget or provider slots, or interrupted: `503 SlowDown`.
    Busy(Stage),
    /// No source holds the extent intact: `503 ServiceUnavailable`.
    Unavailable(Stage),
    /// With the port error behind it, when there was one.
    Internal(Stage, Option<Fault>),
}

impl ReadFail {
    fn cold_error(error: BridgeError) -> Self {
        let stage = match error {
            BridgeError::Sql(_) | BridgeError::GuardFailed => Stage::Lookup,
            BridgeError::Blob(_) => Stage::R2,
            BridgeError::Nntp(_) => Stage::Nntp,
            BridgeError::Crypto(_) => Stage::Decrypt,
            _ => Stage::Other,
        };
        Self::Internal(stage, Some(Fault::of(&error)))
    }

    /// Marks this failure on `observed`: its stage, and its error if known.
    fn mark(&self, observed: &mut GetObservation) {
        match *self {
            Self::Internal(stage, Some(fault)) => observed.mark_fault(stage, fault),
            _ => observed.mark_stage(self.stage()),
        }
    }

    fn stage(&self) -> Stage {
        match *self {
            Self::Busy(stage) | Self::Unavailable(stage) | Self::Internal(stage, _) => stage,
        }
    }

    fn response(&self) -> S3Response {
        match self {
            ReadFail::Busy(_) => s3_error(ErrorCode::SlowDown),
            ReadFail::Unavailable(_) => unavailable(),
            ReadFail::Internal(..) => internal(),
        }
    }

    /// The error that ends a body stream already in flight.
    fn stream_error(&self) -> BridgeError {
        match self {
            ReadFail::Busy(_) => BridgeError::Invalid("read interrupted: busy"),
            ReadFail::Unavailable(_) => {
                BridgeError::Invalid("read interrupted: extent unavailable")
            }
            ReadFail::Internal(..) => BridgeError::Invalid("read interrupted"),
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
    observed: &mut GetObservation,
    hit_flush: Option<Spawner>,
) -> S3Response {
    match read(bridge, req, false, observed, hit_flush).await {
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
    observed: &mut GetObservation,
) -> S3Response {
    match read(bridge, req, true, observed, None).await {
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

/// Headers that keep an object from acting as a page of the host that
/// serves it: `X-Content-Type-Options: nosniff` (the browser takes the
/// stored type as it is) and `Content-Security-Policy: sandbox` (an
/// object opened as a document runs no script, submits no form and has
/// an origin of its own, so it reads no cookie and no storage of the
/// host's site). An S3 object is data, never a page of the service.
///
/// Media and downloads are not affected: `sandbox` applies to a
/// document, and `Content-Disposition` is left as stored. A stored
/// header of either name (an object stores neither today) is replaced,
/// so an object cannot opt out.
fn sandbox_object(headers: &mut Vec<(String, String)>) {
    const SET: [(&str, &str); 2] = [
        ("x-content-type-options", "nosniff"),
        ("content-security-policy", "sandbox"),
    ];
    headers.retain(|(name, _)| !SET.iter().any(|(set, _)| name.eq_ignore_ascii_case(set)));
    headers.extend(SET.iter().map(|(n, v)| (n.to_string(), v.to_string())));
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
    observed: &mut GetObservation,
    hit_flush: Option<Spawner>,
) -> core::result::Result<S3Response, S3Response> {
    observed.mark_stage(Stage::Auth);
    let authed = authenticate_observed(bridge, &req, observed).await?;
    let (bucket, key) = authed.object()?;
    observed.mark_stage(Stage::Lookup);
    let Some(generation) = bridge
        .catalog
        .live_generation(&bucket.id, key)
        .await
        .map_err(|e| lookup_failed(observed, &e))?
    else {
        return Err(s3_error(ErrorCode::NoSuchKey));
    };

    observed.record_size(generation.size);
    observed.mark_stage(if head { Stage::Other } else { Stage::Plan });
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
    sandbox_object(&mut headers);
    let mut resp = S3Response {
        status: plan.status,
        headers,
        body: RespBody::Empty,
    };
    let Some(range) = plan.body else {
        return Ok(resp);
    };

    let end = range
        .start
        .checked_add(range.length())
        .ok_or_else(internal)?;
    // A body above the fan-out size is not read here: the runtime asks
    // for it in sub-ranges, each from an invocation of its own, all
    // pinned to this generation.
    if let Some(chunk) = bridge.cfg.get_fanout_bytes.filter(|&n| range.length() > n) {
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
        let frozen = bridge.catalog.is_frozen();
        let fanout = Fanout::new(range.start, range.length(), chunk, mint).ok_or_else(|| {
            if frozen {
                unavailable()
            } else {
                internal()
            }
        })?;
        if frozen {
            // No uploaded extent can exceed MAX_EXTENT_BYTES_LIMIT. If
            // even the fewest possible rows cannot fit, don't ask for a
            // potentially huge range from the frozen catalogue.
            let least_extents = range.length().div_ceil(MAX_EXTENT_BYTES_LIMIT);
            if !frozen_front_fits(least_extents, fanout.count()) {
                return Err(unavailable());
            }
            // One catalogue lookup for the whole range; no extent data is
            // fetched or decrypted in the parent. Both tiers are read-only.
            let todo =
                plan_pieces(&bridge.catalog, &generation.id, range.start, end, observed).await?;
            if !frozen_front_fits(todo.len() as u64, fanout.count())
                || !frozen_children_fit(&todo, chunk)
            {
                return Err(unavailable());
            }
            preflight(bridge, &todo, observed).await?;
        }
        resp.body = RespBody::Fanout(fanout);
        return Ok(resp);
    }
    let todo = plan_pieces(&bridge.catalog, &generation.id, range.start, end, observed).await?;
    resp.body = body(bridge, bucket.clone(), todo, observed, hit_flush, false).await?;
    Ok(resp)
}

// A frozen extent may need a probe of both the cache and the safety copy.
const FROZEN_HEADS_PER_EXTENT: u64 = 2;
// A child can also GET from both tiers, then do so once more if relay
// took back a piece while the client stalled. It makes no cold fills.
const FROZEN_CHILD_CALLS_PER_EXTENT: u64 = FROZEN_HEADS_PER_EXTENT + 2 * 2;

fn frozen_front_fits(extents: u64, children: u64) -> bool {
    extents * FROZEN_HEADS_PER_EXTENT + children + u64::from(MAX_RETRIES) <= FRONT_SUBREQUEST_BUDGET
}

/// Count every piece overlapping each child, splitting at the same chunk
/// boundaries as the fan-out plan. A boundary can cut an extent in two.
fn frozen_children_fit(todo: &[Piece], chunk: u64) -> bool {
    let mut child_room = chunk;
    let mut child_extents = 0;
    for piece in todo {
        let mut left = piece.len;
        while left != 0 {
            child_extents += 1;
            if child_extents * FROZEN_CHILD_CALLS_PER_EXTENT > FRONT_SUBREQUEST_BUDGET {
                return false;
            }
            let taken = left.min(child_room);
            left -= taken;
            child_room -= taken;
            if child_room == 0 {
                child_room = chunk;
                child_extents = 0;
            }
        }
    }
    true
}

/// One catalogue query, then validate that its extent rows tile the range.
async fn plan_pieces(
    catalog: &impl Catalog,
    generation: &GenerationId,
    start: u64,
    end: u64,
    observed: &mut GetObservation,
) -> core::result::Result<Vec<Piece>, S3Response> {
    observed.mark_stage(Stage::Lookup);
    let extents = catalog
        .extents_in(generation, start, end)
        .await
        .map_err(|e| lookup_failed(observed, &e))?;
    observed.mark_stage(Stage::Plan);
    pieces(extents, start, end - start)
        .filter(|todo| !todo.is_empty())
        .ok_or_else(internal)
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
    observed: &mut GetObservation,
    hit_flush: Option<Spawner>,
) -> S3Response {
    let grant = match admit(&bridge.kek, &req, bridge.clock.now()) {
        Ok(grant) => grant,
        Err(reason) => {
            if bridge.cfg.grant_refusal_reasons {
                observed.mark_grant_refusal(reason);
            } else {
                observed.mark_stage(Stage::Grant);
            }
            return s3_error(ErrorCode::AccessDenied);
        }
    };
    match granted(bridge, &grant, observed, hit_flush).await {
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
    observed: &mut GetObservation,
    hit_flush: Option<Spawner>,
) -> core::result::Result<S3Response, S3Response> {
    // The grant was minted for a generation that existed and a range
    // inside it; anything else here is a fault, not a client error.
    observed.mark_stage(Stage::Lookup);
    let generation = bridge
        .catalog
        .generation_by_id(&grant.bucket, &grant.generation)
        .await
        .map_err(|e| lookup_failed(observed, &e))?;
    observed.mark_stage(Stage::Grant);
    let (bucket, generation) = generation.ok_or_else(internal)?;
    observed.record_size(generation.size);
    let end = grant
        .start
        .checked_add(grant.len)
        .filter(|&end| end <= generation.size)
        .ok_or_else(internal)?;
    let todo = plan_pieces(&bridge.catalog, &generation.id, grant.start, end, observed).await?;
    // A local copy can disappear after the parent's HEAD. Frozen
    // children try both read-only tiers but never try a cold fill.
    let no_cold_fill = bridge.catalog.is_frozen();
    Ok(S3Response {
        status: 200,
        headers: vec![
            ("content-length".into(), grant.len.to_string()),
            ("content-type".into(), "application/octet-stream".into()),
        ],
        body: body(bridge, bucket, todo, observed, hit_flush, no_cold_fill).await?,
    })
}

/// Check full ciphertext lengths using metadata only. The read still
/// authenticates every piece; HEAD does not pin a cache copy in place.
async fn preflight<B: BlobStore>(
    bridge: &Bridge<impl Catalog, B, impl NntpConnector, impl JobSink, impl Kek, impl Clock>,
    todo: &[Piece],
    observed: &mut GetObservation,
) -> core::result::Result<(), S3Response> {
    // A failed head counts as a miss, as before; its error is kept for
    // the request log when the piece is missing from both tiers.
    let fault = std::cell::Cell::new(None);
    let fault = &fault;
    let missing = stream::iter(todo)
        .map(|piece| async move {
            let extent = &piece.extent;
            let size = Some(extent.cipher_size);
            let mut failed = None;
            let mut seen = |head: Result<Option<u64>>| match head {
                Ok(found) => found,
                Err(error) => {
                    failed = Some(Fault::of(&error));
                    None
                }
            };
            let missing = seen(bridge.cache.head(&extent.id.cache_key()).await) != size
                && seen(bridge.safety.head(&extent.id.safety_key()).await) != size;
            if missing {
                fault.set(failed.or_else(|| fault.get()));
            }
            missing
        })
        .buffer_unordered(4)
        .any(futures_util::future::ready)
        .await;
    if missing {
        let fault = fault.get().unwrap_or(Fault::named("ExtentMissing"));
        observed.mark_fault(Stage::R2, fault);
        return Err(unavailable());
    }
    Ok(())
}

/// `500` for a catalogue read of the GET path, marked with its error.
fn lookup_failed(observed: &mut GetObservation, error: &BridgeError) -> S3Response {
    observed.mark_error(Stage::Lookup, error);
    internal()
}

/// Streams plaintext from the validated pieces in order.
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
    todo: Vec<Piece>,
    observed: &mut GetObservation,
    hit_flush: Option<Spawner>,
    no_cold_fill: bool,
) -> core::result::Result<RespBody, S3Response> {
    // Check all pieces before headers when frozen. For a single piece,
    // its read below already does this without a separate probe.
    if (no_cold_fill || bridge.catalog.is_frozen()) && todo.len() > 1 {
        preflight(bridge, &todo, observed).await?;
    }
    // One item per extent, also for a single extent: the plaintext that
    // is waiting to be pulled stays charged to the byte budget, and the
    // charge is released when the item is handed over or the body is
    // dropped. A later failure ends the stream with an error; the client
    // sees a body shorter than Content-Length.
    let measure = !no_cold_fill && bridge.cfg.hot_ctl.mode != crate::config::HotCtlMode::Fixed;
    let hits = hit_flush
        .filter(|_| measure)
        .map(|spawner| (Rc::clone(bridge), spawner));
    let bridge = Rc::clone(bridge);
    let spawner = bridge.budget.spawner().cloned();
    let mut items = driven(spawner.as_ref(), move |out| {
        relay(bridge, bucket, todo, out, measure, no_cold_fill)
    });
    // The first piece is produced before the status line goes out, so an
    // object that cannot be read is an error response, not a cut-off 200.
    let first = match items.next().await {
        Some((Ok(held), hit_bytes)) => (Ok(held), hit_bytes),
        Some((Err(fail), _)) => {
            fail.mark(observed);
            return Err(fail.response());
        }
        None => {
            observed.mark_stage(Stage::Other);
            return Err(internal());
        }
    };
    Ok(RespBody::Stream(
        stream::once(async move { first })
            .chain(items)
            // Count R2 pieces only when pulled, not when read ahead or
            // taken back from a stalled stream. The charge ends here too.
            .map(move |(item, hit_bytes)| {
                if hit_bytes != 0 {
                    if let Some((bridge, spawner)) = &hits {
                        record_hit(bridge, spawner, hit_bytes);
                    }
                }
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
    /// The reader asked for an item and found none: it is waiting.
    wanted: Cell<bool>,
    /// The future runs as a task of the host.
    spawned: bool,
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

    /// Wakes whoever waits in `who`. The waker is taken out first, so it
    /// runs after the borrow ended.
    fn wake(who: &RefCell<Option<Waker>>) {
        let waker = who.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
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
        self.shared.wanted.set(false);
        *self.shared.slot.borrow_mut() = Some(item);
        poll_fn(|_| match self.shared.slot.borrow().is_some() {
            true => Poll::Pending,
            false => Poll::Ready(()),
        })
        .await;
    }

    /// As [`Self::send`], but only until `patience` is over: an item
    /// that was not taken by then is taken back and dropped, with all it
    /// holds. `false` = taken back; the caller produces it again when
    /// the reader asks ([`Self::wanted`]).
    async fn send_within(&self, item: T, patience: impl Future<Output = ()>) -> bool {
        let sent = core::pin::pin!(self.send(item));
        let patience = core::pin::pin!(patience);
        if let Either::Left(_) = select(sent, patience).await {
            return true;
        }
        let back = self.shared.slot.borrow_mut().take();
        back.is_none()
    }

    /// Whether the future runs ahead of its reader, as a task of the
    /// host. Otherwise it runs only while the reader asks.
    fn ahead(&self) -> bool {
        self.shared.spawned
    }

    /// Whether the reader is waiting for an item now.
    fn is_wanted(&self) -> bool {
        self.shared.wanted.get()
    }

    /// Returns once the reader is waiting for an item.
    async fn wanted(&self) {
        poll_fn(|_| match self.is_wanted() {
            true => Poll::Ready(()),
            false => Poll::Pending,
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
        wanted: Cell::new(false),
        spawned: spawner.is_some(),
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
                    Shared::<T>::wake(&shared.reader);
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
            Shared::<T>::wake(&shared.task);
            Some(item)
        };
        if let Some(item) = take() {
            return Poll::Ready(Some(item));
        }
        if !self.spawned {
            shared.wanted.set(true);
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
            // A task that holds an item back until it is asked for
            // learns here that it is.
            if !shared.wanted.replace(true) {
                Shared::<T>::wake(&shared.task);
            }
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
        Shared::<T>::wake(&self.shared.task);
    }
}

/// Produces the pieces of one body in order. The connections to Usenet
/// stay open from one cold extent to the next, and the cache write of an
/// extent runs while the next one is read (see [`Cold`]).
async fn relay<C, B, N, J, K, T>(
    bridge: Rc<Bridge<C, B, N, J, K, T>>,
    bucket: Bucket,
    todo: Vec<Piece>,
    out: Out<(Item, u64)>,
    measure: bool,
    no_cold_fill: bool,
) where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let mut cold = Cold::new(&bridge);
    cold.measure = measure;
    cold.no_cold_fill = no_cold_fill;
    let last = todo.len() - 1;
    let timer = bridge.budget.sleeper();
    // Whether pieces are produced ahead of the reader: on a host that
    // runs this as a task and has a timer to watch a piece that waits.
    let can_run_ahead = out.ahead() && timer.is_some();
    // After a piece waited too long for the reader, it is produced
    // again when the reader asks, and the body runs ahead again once
    // the reader asks for a piece soon after it took the one before.
    let mut eager = can_run_ahead;
    for (at, piece) in todo.iter().enumerate() {
        // A piece taken back after a client stall is still the same read.
        let mut first_eligible_at = None;
        let mut read_from_usenet = false;
        loop {
            if out.ahead() && !eager && !out.is_wanted() {
                // Nothing is held while the reader is busy: neither a
                // piece nor a provider slot.
                cold.end().await;
                out.wanted().await;
            }
            cold.mid = at > 0;
            let first = *first_eligible_at.get_or_insert_with(|| bridge.clock.now());
            let item = cold.piece(&bucket, piece, first).await;
            let failed = item.is_err();
            // An abandoned cold attempt still cost a verified fetch. A
            // warm retry of this same piece is not a separate customer hit.
            read_from_usenet |= !failed && !cold.from_r2;
            let hit_bytes = if measure && !failed && !read_from_usenet {
                piece.extent.cipher_size
            } else {
                0
            };
            let item = (item, hit_bytes);
            // Before the last item and before an error: the reader of
            // the body may never ask again after either, and the last
            // extent would then be missing from the cache and the
            // provider slots would be held until they expire.
            if at == last || failed {
                cold.end().await;
            }
            let spent = Rc::clone(&cold.spent);
            match timer {
                // A piece that is not taken in time is taken back, with
                // its charge: a reader that stalls must not keep an
                // extent of the byte budget from every other request.
                // The connections are ended earlier if their slots run
                // out first.
                Some(sleep) if eager && !failed => {
                    let sent = out.send_within(item, sleep(PIECE_WAIT_MS));
                    let sent = Spent::time(&bridge.clock, &spent.send, sent);
                    if !cold.wait(sent).await {
                        eager = false;
                        continue;
                    }
                }
                _ => {
                    // The reader is waiting on a host that runs this as
                    // a task. On any other host this runs only while
                    // the reader asks, and nobody watches the time
                    // until then: the connections do not stay open.
                    if !out.ahead() {
                        cold.hang_up().await;
                    }
                    let sent = Spent::time(&bridge.clock, &spent.send, out.send(item));
                    beside(&mut cold.put, sent).await;
                    // A reader that let a piece wait too long gets
                    // pieces ahead again once it asks for the next one
                    // in less than that time. Until then each piece is
                    // made when it is asked for: a slow reader would
                    // otherwise have every extent read twice, once to
                    // be taken back and once to be served.
                    eager = match timer {
                        Some(sleep) if can_run_ahead && at != last && !failed => {
                            let asked = async {
                                let asked = core::pin::pin!(out.wanted());
                                let late = sleep(PIECE_WAIT_MS);
                                matches!(select(asked, late).await, Either::Left(_))
                            };
                            cold.wait(asked).await
                        }
                        _ => false,
                    };
                }
            }
            if failed {
                return;
            }
            break;
        }
    }
}

/// How long a piece that was produced ahead waits for the reader of the
/// body before it is taken back. Well under the time a request waits for
/// room in the byte budget, so a reader that stalls costs another
/// request this wait and not its answer.
pub const PIECE_WAIT_MS: u32 = 5_000;

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
    observed: &mut GetObservation,
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
    // does, and more if articles of it are lost and rebuilt from its
    // parity. Beside the pieces already held that can be more than the
    // budget has, however long the read waits. Such an extent is read
    // once on its own first: that leaves it in the cache, and the read
    // below then needs room for its piece only.
    let mut held = 0u64;
    let mut prewarmed_at = vec![None; todo.len()];
    for (piece, first_eligible_at) in todo.iter().zip(&mut prewarmed_at) {
        let (size, sockets) = (piece.extent.cipher_size, bridge.cfg.cold_sockets);
        // Whether the extent has parity, and lost anything, is not
        // known before it is read: the most a rebuild of it may hold.
        let rebuilt = cold_step_bytes(size, sockets).saturating_add(cold_rebuild_most(size));
        let cold = cold_read_bytes(size, sockets).max(rebuilt);
        if held > 0 && held.saturating_add(cold) > bridge.budget.capacity() {
            drop(
                read_piece(
                    bridge,
                    bucket,
                    piece,
                    *first_eligible_at.insert(bridge.clock.now()),
                )
                .await
                .map_err(|fail| {
                    fail.mark(observed);
                    fail.response()
                })?,
            );
        }
        held = held.saturating_add(piece.len);
    }
    let mut parts = Vec::with_capacity(todo.len());
    for (piece, prewarmed) in todo.iter().zip(prewarmed_at) {
        let first_eligible_at = prewarmed.unwrap_or_else(|| bridge.clock.now());
        parts.push(
            read_piece(bridge, bucket, piece, first_eligible_at)
                .await
                .map_err(|fail| {
                    fail.mark(observed);
                    fail.response()
                })?,
        );
    }
    if parts.len() == 1 {
        return parts.pop().ok_or_else(internal);
    }
    // Several pieces: they and the joined copy are live together.
    let held = bridge.budget.charge(len).await.map_err(|_| {
        observed.mark_stage(Stage::Budget);
        ReadFail::Busy(Stage::Budget).response()
    })?;
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
    first_eligible_at: UnixMs,
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
    let item = cold.piece(bucket, piece, first_eligible_at).await;
    cold.end().await;
    item
}

/// A verified miss is recorded whether or not there is room for a refill.
/// The refill is returned unpolled so it cannot overwrite the stamp
/// before observation settles, or is dropped if observation timed out.
async fn prepare_verified_fill<F: Future<Output = ()>, O: Future<Output = bool>>(
    room: &ByteBudget,
    cipher: Vec<u8>,
    measure: bool,
    write: impl FnOnce(Vec<u8>, Charge) -> F,
    observe: impl FnOnce() -> O,
) -> Option<F> {
    let put = room
        .try_charge(cipher.len() as u64)
        .map(|copy| write(cipher, copy));
    if measure && !observe().await {
        return None;
    }
    put
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
    /// The byte budget, counting what this body holds: its charges are
    /// taken through it.
    room: Rc<ByteBudget>,
    /// Whether a piece of the body was made before: its reader has part
    /// of it already.
    mid: bool,
    /// When the wait of the piece being made for a provider ends, once
    /// it has begun: no wait for room is begun after it.
    until: Option<UnixMs>,
    // Only customer GET (possibly a granted subrange), never a copy.
    measure: bool,
    /// Frozen fan-out children never refill the cache or stamp reads.
    no_cold_fill: bool,
    from_r2: bool,
}

/// How many times a body that has begun waits
/// [`CHARGE_WAIT_MS`](crate::ingress::CHARGE_WAIT_MS) for
/// room before it ends short. Its reader has a part already and gets
/// an error if the rest does not come; a request that has sent nothing
/// waits once and is told to slow down.
const MID_BODY_WAITS: u32 = 3;

/// Milliseconds of one cold body by what it was waiting for, for the log.
/// The clock of a Worker stands still while code runs, so each number is
/// time spent waiting, and what runs beside something is counted twice.
#[derive(Default)]
struct Spent {
    /// Asking the cache and the safety copy first.
    warm: Cell<i64>,
    /// Reading extents from Usenet, including a rebuild's wait for
    /// the previous cache write when it holds the room the rebuild needs.
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
            room: Rc::new(bridge.budget.for_request()),
            mid: false,
            until: None,
            measure: false,
            no_cold_fill: false,
            from_r2: false,
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

    /// Lets the cache write end, then the connections (or the
    /// connections first, if the write takes longer than their slots
    /// allow).
    async fn end(&mut self) {
        self.settle().await;
        self.hang_up().await;
    }

    /// A timer for the time the connections may still sit idle
    /// ([`ColdReader::idle_ms`]). `None`: none is open, or the host has
    /// no timer.
    fn limit(&self) -> Option<LocalBoxFuture<'static, ()>> {
        let ms = self.reader.as_ref()?.idle_ms()?;
        Some(self.bridge.budget.sleeper()?(ms))
    }

    /// Runs `f` beside the cache write. `f` is something the read waits
    /// for that is not a provider: if the slots of the open connections
    /// would run out meanwhile, the connections are ended.
    async fn wait<F: Future>(&mut self, f: F) -> F::Output {
        let mut f = core::pin::pin!(f);
        let over = match self.limit() {
            None => false,
            Some(limit) => {
                let first = core::pin::pin!(beside(&mut self.put, f.as_mut()));
                match select(first, limit).await {
                    Either::Left((out, _)) => return out,
                    Either::Right(_) => true,
                }
            }
        };
        if over {
            self.hang_up().await;
        }
        beside(&mut self.put, f).await
    }

    /// Observe a verified customer miss before its optional refill. A
    /// timed-out D1 request can still land after its Rust future is
    /// dropped, so don't start any fill or stamp for this attempt then.
    async fn observe_miss(&mut self, extent: &ExtentId) -> bool {
        let bridge = self.bridge;
        let ghost = bridge.catalog.hot_ghost(extent, bridge.clock.now());
        let Some(sleep) = bridge.budget.sleeper() else {
            // Hosts without timers may take an immediate observation,
            // but must not await a new unbounded write on the GET path.
            return ghost.now_or_never().is_some();
        };
        let completed = matches!(
            self.wait(select(core::pin::pin!(ghost), sleep(COLD_WAIT_MS)))
                .await,
            Either::Left(_)
        );
        if !completed {
            // If both deadlines were ready on the same poll, the ghost
            // deadline may have won before `wait` closed the sessions.
            self.hang_up().await;
        }
        completed
    }

    /// Lets the cache write end, with the connections watched as in
    /// [`Self::wait`].
    async fn settle(&mut self) {
        if let (Some(limit), Some(put)) = (self.limit(), self.put.as_mut()) {
            if matches!(select(put, limit).await, Either::Left(_)) {
                self.put = None;
                return;
            }
            self.hang_up().await;
        }
        // A timed charge can stop waiting here; leave the write in
        // place for the reader's cleanup unless it has finished.
        if let Some(writing) = self.put.as_mut() {
            writing.await;
            self.put = None;
        }
    }

    /// Room for the next step, all of it at once: nothing is held while
    /// this waits. When it is not there beside the cache write that is
    /// under way, the write ends first: the read then needs no more than
    /// it would alone. Taken in turn, after every request that waits
    /// for room already and has none beside what this body holds: a
    /// body that runs ahead of its reader charges again as soon as a
    /// piece is taken, and would otherwise take the room of a request
    /// that waits every time.
    async fn charge(&mut self, need: u64) -> core::result::Result<Charge, ReadFail> {
        let bridge = self.bridge;
        let budget = Rc::clone(&self.room);
        if let Some(charge) = budget.try_charge_in_turn(need) {
            return Ok(charge);
        }
        let spent = Rc::clone(&self.spent);
        let began = bridge.clock.now();
        self.settle().await;
        let mut room = self.wait(budget.charge_in_turn(need)).await;
        let mut waits = 1;
        while room.is_err() && self.mid && waits < MID_BODY_WAITS {
            if self.until.is_some_and(|end| bridge.clock.now() >= end) {
                break;
            }
            room = self.wait(budget.charge_in_turn(need)).await;
            waits += 1;
        }
        spent
            .wait
            .set(spent.wait.get() + bridge.clock.now().0 - began.0);
        room.map_err(|_| ReadFail::Busy(Stage::Budget))
    }

    /// Room for reading one extent: all of `need` when no cache write
    /// is under way, and beside one only `lean`, what is live until the
    /// extent is opened. The write ends before that.
    async fn step(&mut self, need: u64, lean: u64) -> core::result::Result<Charge, ReadFail> {
        if self.put.is_some() && lean < need {
            if let Some(charge) = self.room.try_charge_in_turn(lean) {
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
    /// The ciphertext span and the plaintext are one charge, taken
    /// before a store is asked. Beside the cache write of the extent
    /// before there may be room for the span only: then the span is
    /// charged and the rest when a copy is there, if it fits at once.
    /// If it does not, the copy and the charge are given up, all of it
    /// is waited for with nothing held, and the store is asked again:
    /// two reads that each held a part and waited for the rest would
    /// wait for each other.
    async fn warm(&mut self, bucket: &Bucket, piece: &Piece, span: ByteSpan) -> Item {
        let bridge = self.bridge;
        let extent = &piece.extent;
        let spent = Rc::clone(&self.spent);
        let all = span.len + piece.len;
        let room = Rc::clone(&self.room);
        let mut work = match room.try_charge_in_turn(all) {
            Some(work) => work,
            None => {
                let lean = match self.put.is_some() {
                    true => room.try_charge_in_turn(span.len),
                    false => None,
                };
                match lean {
                    Some(work) => work,
                    None => self.charge(all).await?,
                }
            }
        };
        for from_cache in [true, false] {
            loop {
                let asked = async {
                    match from_cache {
                        true => warm(&bridge.cache, &extent.id.cache_key(), span).await,
                        false => warm(&bridge.safety, &extent.id.safety_key(), span).await,
                    }
                };
                let asked = Spent::time(&bridge.clock, &spent.warm, asked);
                let Some(src) = self.wait(asked).await else {
                    break;
                };
                let short = all.saturating_sub(work.bytes());
                if short > 0 {
                    match room.try_charge(short) {
                        Some(more) => work.absorb(more),
                        None => {
                            drop(src);
                            drop(work);
                            work = self.charge(all).await?;
                            continue;
                        }
                    }
                }
                let Some(plain) = open(&bridge.kek, bucket, piece, span.start, &src) else {
                    break;
                };
                drop(src);
                let held =
                    retain(&room, work, plain).ok_or(ReadFail::Internal(Stage::Budget, None))?;
                if !self.no_cold_fill {
                    self.wait(stamp_read(bridge, &extent.id, from_cache)).await;
                }
                self.from_r2 = true;
                return Ok(held);
            }
        }
        Err(ReadFail::Unavailable(Stage::R2))
    }

    async fn piece(&mut self, bucket: &Bucket, piece: &Piece, first_eligible_at: UnixMs) -> Item {
        let bridge = self.bridge;
        let extent = &piece.extent;
        self.until = None;
        self.from_r2 = false;
        let span = cipher_span(extent.plain_size, piece.off, piece.len)
            .ok_or(ReadFail::Internal(Stage::Plan, None))?;
        match self.warm(bucket, piece, span).await {
            Err(ReadFail::Unavailable(_)) => {}
            found => {
                // Idle connections would outlive their slots.
                self.hang_up().await;
                return found;
            }
        }

        // A cold fill needs provider permits and catalogue writes, both
        // unavailable during the freeze. Refuse before opening a session.
        if self.no_cold_fill || bridge.catalog.is_frozen() {
            return Err(ReadFail::Unavailable(Stage::R2));
        }

        // Cold: the whole extent comes back verified against the
        // catalogue digest. While it is read, the ciphertext and the wire
        // text on the sockets are live; while it is opened, the
        // ciphertext and the plaintext. The warm span and its plaintext
        // are never larger than that.
        let room = Rc::clone(&self.room);
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
        // waiting readers do not starve the budget. Before the next try
        // there must be room for the read again: that is waited for in
        // turn, as a request that waits for room, inside the same bound,
        // so that a body that runs ahead of its reader lets this read
        // have it. After
        // each wait the cache is checked again: another reader may have
        // filled it in the meantime.
        let waiter = WAITERS.fetch_add(1, Ordering::Relaxed);
        let deadline = bridge.clock.now().plus_ms(i64::from(COLD_WAIT_MS));
        let remaining = |slept| {
            (deadline.0 - bridge.clock.now().0).min(i64::from(COLD_WAIT_MS.saturating_sub(slept)))
        };
        self.until = Some(deadline);
        let mut slept = 0u32;
        let mut attempt = 0u64;
        let mut interrupted = 0u32;
        // The largest known rebuild shortfall, kept across this
        // piece's retries. A later Busy for slots says nothing about
        // how much room the rebuild still needs.
        let mut rebuild = 0u64;
        let mut spare: Option<Charge> = None;
        loop {
            let reader = match &mut self.reader {
                Some(reader) => reader,
                // A rebuild from parity is charged to this request.
                none => none.insert(
                    bridge
                        .cold_reader()
                        .map_err(ReadFail::cold_error)?
                        .charged_to(Rc::clone(&room)),
                ),
            };
            if let Some(spare) = spare.take() {
                reader.fund(spare);
            }
            let fetched = reader.fetch_beside(extent, &mut self.put, first_eligible_at);
            let read = Spent::time(&bridge.clock, &self.spent.read, fetched).await;
            let shortfall = reader.settle();
            rebuild = rebuild.max(shortfall);
            let wait_stage = match read {
                Ok(ColdFetch::Filled(cipher)) => {
                    // One cache write at a time.
                    let began = bridge.clock.now();
                    self.settle().await;
                    let waited = bridge.clock.now().0 - began.0;
                    self.spent.wait.set(self.spent.wait.get() + waited);
                    // What a read beside that write left uncharged. The
                    // write has released as much, but another request
                    // may have taken it. Then the extent is given up
                    // and read again under a charge for all of it, taken
                    // with nothing held: a read never waits for room
                    // while it holds some.
                    let short = need.saturating_sub(work.bytes());
                    if short > 0 {
                        match room.try_charge(short) {
                            Some(more) => work.absorb(more),
                            None => {
                                drop(cipher);
                                drop(work);
                                work = self.charge(need.saturating_add(rebuild)).await?;
                                if rebuild > 0 {
                                    spare = Some(work.split_off(rebuild));
                                }
                                continue;
                            }
                        }
                    }
                    let plain = open(&bridge.kek, bucket, piece, 0, &cipher)
                        .ok_or(ReadFail::Unavailable(Stage::Decrypt))?;
                    // The charge is split between the plaintext, which
                    // leaves with the piece, and the ciphertext, which
                    // stays until it is written. Nothing runs between the
                    // release and the two charges, and together they are
                    // never more than what was released.
                    drop(work);
                    let held = room
                        .try_charge(plain.len() as u64)
                        .ok_or(ReadFail::Internal(Stage::Budget, None))?;
                    let spent = Rc::clone(&self.spent);
                    self.put = prepare_verified_fill(
                        &room,
                        cipher,
                        self.measure,
                        |cipher, copy| {
                            let extent = extent.clone();
                            async move {
                                // A cache that refuses a verified copy
                                // does not fail the read.
                                let fill = bridge.cache_fill(&extent, cipher);
                                let _ = Spent::time(&bridge.clock, &spent.put, fill).await;
                                drop(copy);
                            }
                            .boxed_local()
                        },
                        || self.observe_miss(&extent.id),
                    )
                    .await;
                    return Ok((plain, held));
                }
                Ok(ColdFetch::Busy) if shortfall > 0 => Stage::Budget,
                Ok(ColdFetch::Busy) => Stage::SlotWait,
                // Every provider that was asked broke off (a proxy that
                // went away, a provider that hung up): the read is tried
                // again after a wait, on new connections, a few times.
                Ok(ColdFetch::Interrupted) if interrupted < INTERRUPTED_RETRIES => {
                    interrupted += 1;
                    Stage::Nntp
                }
                Ok(ColdFetch::Interrupted) => return Err(ReadFail::Busy(Stage::Nntp)),
                // An extent that lost more than its parity rebuilds is
                // as unavailable as one without parity.
                Ok(ColdFetch::Unrecoverable) => {
                    crate::trace::cold_read(|| {
                        format!("extent-unrecoverable extent={}", extent.id)
                    });
                    return Err(ReadFail::Unavailable(Stage::Nntp));
                }
                Ok(ColdFetch::Unavailable) => {
                    // If nothing was published to Usenet yet, the lost
                    // warm copies are the reason the extent is unavailable.
                    let stage = if extent.article_count.is_none() {
                        Stage::R2
                    } else {
                        Stage::Nntp
                    };
                    return Err(ReadFail::Unavailable(stage));
                }
                Err(error) => return Err(ReadFail::cold_error(error)),
            };
            // Nothing is held while waiting: neither slots nor budget.
            self.hang_up().await;
            drop(work);
            let sleep = bridge.budget.sleeper().ok_or(ReadFail::Busy(wait_stage))?;
            // With a rebuild to come, room for both: the two are held
            // together.
            let both = need.saturating_add(rebuild);
            let mut stage = wait_stage;
            loop {
                if bridge.clock.now() >= deadline || slept >= COLD_WAIT_MS {
                    return Err(ReadFail::Busy(stage));
                }
                attempt += 1;
                let seed = (bridge.clock.now().0 as u64) ^ waiter.rotate_left(32) ^ attempt;
                let ms = cold_poll_ms(seed);
                beside(&mut self.put, sleep(ms)).await;
                slept = slept.saturating_add(ms);
                // Until there is room for the read, which is released
                // again here: what follows takes what it needs.
                if room.try_charge_in_turn(both).is_some() {
                    break;
                }
                // Until room becomes available, the byte budget is
                // what prevents the next attempt, not the last result.
                stage = Stage::Budget;
                let Ok(left @ 1..) = u32::try_from(remaining(slept)) else {
                    return Err(ReadFail::Busy(stage));
                };
                let listed = async {
                    let listed = core::pin::pin!(room.charge_in_turn(both));
                    match select(listed, sleep(left)).await {
                        Either::Left((found, _)) => Some(found.is_ok()),
                        Either::Right(_) => None,
                    }
                };
                match beside(&mut self.put, listed).await {
                    Some(true) => break,
                    Some(false) => {}
                    None => return Err(ReadFail::Busy(Stage::Budget)),
                }
                // The clock may stand still: the wait is counted too.
                slept = slept.saturating_add(CHARGE_WAIT_MS);
            }
            // Another reader may have filled the cache in the meantime.
            match self.warm(bucket, piece, span).await {
                Err(ReadFail::Unavailable(_)) => {}
                found => return found,
            }
            if bridge.clock.now() >= deadline {
                return Err(ReadFail::Busy(stage));
            }
            if rebuild == 0 {
                work = self.step(need, lean).await?;
                continue;
            }
            // Another request may have taken the room while the cache
            // was checked. Bound this wait by the same retry allowance.
            let Ok(left @ 1..) = u32::try_from(remaining(slept)) else {
                return Err(ReadFail::Busy(stage));
            };
            {
                let charge = core::pin::pin!(self.step(both, lean.saturating_add(rebuild)));
                let timeout = core::pin::pin!(async { sleep(left).await });
                work = match select(charge, timeout).await {
                    Either::Left((found, _)) => found?,
                    Either::Right(_) => return Err(ReadFail::Busy(Stage::Budget)),
                };
            }
            if bridge.clock.now() >= deadline {
                return Err(ReadFail::Busy(Stage::Budget));
            }
            spare = Some(work.split_off(rebuild));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use futures_util::task::{noop_waker, waker, ArcWake};

    #[cfg(feature = "testkit")]
    #[tokio::test]
    async fn a_verified_miss_is_counted_when_the_cache_copy_does_not_fit() {
        use crate::ports::BlobMeta;
        use crate::sql::SqlCatalog;
        use crate::testkit::{MemBlobStore, RusqliteSql};
        use crate::types::BucketId;

        let db = RusqliteSql::with_schema().unwrap();
        db.apply("INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) \
                 VALUES ('b_c','cold','o',x'00',1,1); \
                 INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) \
                 VALUES ('x_c','b_c','staged',1,4096,x'00',x'00',x'00',x'00','held',1);").unwrap();
        let catalog = SqlCatalog::new(db);
        let cache = MemBlobStore::new();
        let extent = ExtentId::new("x_c");
        let bucket = BucketId::new("b_c");
        let room = ByteBudget::new(4096);
        let _plaintext = room.try_charge(1).expect("plaintext fits");
        let fill = prepare_verified_fill(
            &room,
            vec![0; 4096],
            true,
            |cipher, _copy| async {
                let hash = crate::post::sha256(&cipher);
                cache
                    .put(
                        &extent.cache_key(),
                        cipher,
                        &BlobMeta {
                            bucket: &bucket,
                            extent: &extent,
                            cipher_sha256: &hash,
                        },
                    )
                    .await
                    .unwrap();
            },
            || async {
                catalog.hot_ghost(&extent, UnixMs(1)).await.unwrap();
                true
            },
        )
        .await;
        if let Some(fill) = fill {
            fill.await;
        }
        assert!(!cache.contains(&extent.cache_key()));
        assert_eq!(
            catalog.hot_ctl_load(&["hotg_first"]).await.unwrap(),
            vec![Some(4096)]
        );
    }

    #[test]
    fn busy_hit_accumulator_flushes_at_one_gib_without_waiting_fifteen_minutes() {
        const GIB: u64 = 1 << 30;
        let mut pending = HitAccumulator::default();
        assert_eq!(pending.record(1, UnixMs(0)), Some(1));
        assert_eq!(pending.record(GIB - 1, UnixMs(1)), None);
        assert_eq!(pending.record(1, UnixMs(2)), Some(GIB));
        assert_eq!(pending.record(0, UnixMs(HIT_FLUSH_MS + 2)), None);
    }

    #[test]
    fn cold_read_port_errors_keep_their_dependency_stage() {
        for (error, expected, fields) in [
            (
                BridgeError::Sql("d1: network lost: statement failed".into()),
                Stage::Lookup,
                "stage=lookup err=Sql code=d1_network_lost",
            ),
            (
                BridgeError::Sql(crate::fetch::CATALOGUE_FAILED.into()),
                Stage::Lookup,
                "stage=lookup err=Sql code=cold_catalogue",
            ),
            (
                BridgeError::GuardFailed,
                Stage::Lookup,
                "stage=lookup err=GuardFailed code=-",
            ),
            (
                BridgeError::Blob("r2: get failed (10001)".into()),
                Stage::R2,
                "stage=r2 err=Blob code=r2_get_10001",
            ),
            (
                BridgeError::Nntp(velmora::Error::Io(std::io::ErrorKind::TimedOut.into())),
                Stage::Nntp,
                "stage=nntp err=Nntp code=nntp_io_timed_out",
            ),
            (
                BridgeError::Crypto("fixture"),
                Stage::Decrypt,
                "stage=decrypt err=Crypto code=-",
            ),
            (
                BridgeError::Invalid("fixture"),
                Stage::Other,
                "stage=other err=Invalid code=-",
            ),
        ] {
            let fail = ReadFail::cold_error(error);
            assert_eq!(fail.stage(), expected);
            assert_eq!(fail.response().status, 500);
            let mut observed = GetObservation::default();
            fail.mark(&mut observed);
            assert_eq!(observed.log_fields(), fields);
        }
    }

    /// The stamp the catalogue holds may come from a clock a moment
    /// ahead of this one: it is recent, and the read is not stamped
    /// again. One a whole gap ahead is old, so a clock that jumped cannot
    /// keep an extent from being stamped.
    #[test]
    fn a_stamp_a_moment_ahead_is_recent_and_one_far_ahead_is_not() {
        let now = UnixMs(10_000_000);
        for ahead in [1, 24, 5_000] {
            assert!(stamped_recently(now, now.0 + ahead), "{ahead} ms ahead");
        }
        assert!(stamped_recently(now, now.0 - (READ_STAMP_MS - 1)));
        assert!(!stamped_recently(now, now.0 - READ_STAMP_MS));
        assert!(!stamped_recently(now, now.0 + READ_STAMP_MS));
    }

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

    /// An item that is not taken before the patience is over is taken
    /// back and dropped with what it holds, the reader finds nothing,
    /// and the future is woken when the reader asks: it hands the item
    /// over again. An item that was taken in time is not handed over
    /// twice.
    #[test]
    fn an_item_that_is_not_taken_in_time_is_taken_back() {
        let host = Host::default();
        let reader = Arc::new(Woken::default());
        let patience = Rc::new(Cell::new(false));
        let held = Rc::new(());
        let log = Rc::new(RefCell::new(Vec::new()));
        let (over, item, notes) = (Rc::clone(&patience), Rc::clone(&held), Rc::clone(&log));
        let mut items = Box::pin(driven(
            Some(&host.spawner()),
            move |out: Out<(u32, Rc<()>)>| async move {
                for n in 1..=2u32 {
                    loop {
                        let wait = poll_fn(|_| match over.get() {
                            true => Poll::Ready(()),
                            false => Poll::Pending,
                        });
                        if out.send_within((n, Rc::clone(&item)), wait).await {
                            notes.borrow_mut().push(("sent", n));
                            break;
                        }
                        notes.borrow_mut().push(("back", n));
                        assert!(!out.is_wanted());
                        out.wanted().await;
                        over.set(false);
                    }
                }
            },
        ));
        host.turn();
        assert_eq!(Rc::strong_count(&held), 3, "the item waits");
        patience.set(true);
        host.turn();
        assert_eq!(*log.borrow(), [("back", 1)]);
        assert_eq!(Rc::strong_count(&held), 2, "what it held is given up");
        host.turn();
        assert_eq!(Rc::strong_count(&held), 2, "nothing is made unasked");
        let woken = host.woken.times();
        assert_eq!(pull_with(&mut items, &reader), Poll::Pending);
        assert_eq!(host.woken.times(), woken + 1, "asking wakes the task");
        host.turn();
        assert!(matches!(
            pull_with(&mut items, &reader),
            Poll::Ready(Some((1, _)))
        ));
        host.turn();
        assert_eq!(*log.borrow(), [("back", 1), ("sent", 1)]);
        // Taken just as the patience ends: not handed over again.
        patience.set(true);
        assert!(matches!(
            pull_with(&mut items, &reader),
            Poll::Ready(Some((2, _)))
        ));
        host.turn();
        assert_eq!(*log.borrow(), [("back", 1), ("sent", 1), ("sent", 2)]);
        assert_eq!(pull_with(&mut items, &reader), Poll::Ready(None));
        assert_eq!(host.running(), 0);
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
    fn an_object_is_served_sandboxed_and_unsniffed() {
        let mut h = vec![
            ("content-type".to_string(), "text/html".to_string()),
            (
                "Content-Security-Policy".to_string(),
                "default-src *".to_string(),
            ),
            ("content-disposition".to_string(), "inline".to_string()),
        ];
        sandbox_object(&mut h);
        fn get(h: &[(String, String)], n: &str) -> Vec<String> {
            h.iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.clone())
                .collect()
        }
        assert_eq!(get(&h, "content-security-policy"), ["sandbox"]);
        assert_eq!(get(&h, "x-content-type-options"), ["nosniff"]);
        assert_eq!(get(&h, "content-type"), ["text/html"]);
        assert_eq!(get(&h, "content-disposition"), ["inline"]);
        sandbox_object(&mut h);
        assert_eq!(get(&h, "content-security-policy"), ["sandbox"]);
        assert_eq!(h.len(), 4);
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
