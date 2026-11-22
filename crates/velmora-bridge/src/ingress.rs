//! Request ingress: the raw target, the edge precheck, the declared body
//! length, the counted body read and the per-isolate [`ByteBudget`].
//!
//! Order for every request that carries a body (nothing unauthenticated or
//! oversized is ever buffered):
//!
//! 1. [`origin_form`] takes the target from the runtime's own URL string,
//!    byte for byte (no URL parser: it would resolve `..` and rewrite `\`).
//! 2. [`precheck`] (headers only): transport, admin bearer or S3 credential
//!    presence, `Content-Length` shape and the declared-length cap.
//! 3. The handler authenticates (SigV4) from headers only.
//! 4. [`ByteBudget::charge`] reserves what the request will hold, waiting
//!    a bounded time without reading the body, then `503 SlowDown`: `2 ×
//!    declared_len` for a body that is held whole
//!    ([`ByteBudget::charge_body`]), a fixed window for one that is sealed
//!    and stored while it arrives ([`ByteBudget::charge_stream`]).
//! 5. [`read_capped`] reads at most `declared_len + 1` bytes; uploads use
//!    [`read_upload`], which decodes as it reads, or [`seal_upload`],
//!    which decodes, seals and hands on each chunk as it reads.
//!
//! For an `aws-chunked` upload the declared length is the **decoded** one,
//! `x-amz-decoded-content-length`: the cap, the charge and the buffer are
//! sized by it. `Content-Length`, when present, is the encoded length and
//! is only checked against the bytes received (clients that stream with
//! HTTP `Transfer-Encoding: chunked` send none).
//!
//! Transport: [`precheck`] refuses plain `http` unless `DEV_TRUST_HTTP`
//! (dev only) is set, so every request that reaches a handler arrived over
//! trusted transport and the handler passes `https = true` to SigV4.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use velmora::media::{CIPHER_CHUNK_SIZE, PLAIN_CHUNK_SIZE};
use velmora_s3_proto::{is_aws_chunked, DecodedUpload, ErrorCode, UploadValidator};

use crate::config::BridgeConfig;
use crate::crypto::{ExtentSealer, SealedStream};
use crate::service::{classify, Route};
use crate::types::{Body, BridgeError, ByteStream, S3Request, S3Response};

/// How long a request may wait for budget before `503 SlowDown`.
pub const CHARGE_WAIT_MS: u32 = 20_000;

/// Poll interval while waiting for budget.
pub const CHARGE_POLL_MS: u32 = 100;

/// How long a charge taken in turn ([`ByteBudget::charge_in_turn`]) lets
/// the charges that waited before it go first. One that is polled takes
/// the room within a poll of it being free; one that is listed but not
/// polled any more (its request is stopped, or busy elsewhere) holds
/// the others back no longer than this.
pub const TURN_WAIT_MS: u32 = 5_000;

/// What a body that is sealed and stored while it arrives
/// ([`seal_upload`]) is charged at most, whatever its length: eight
/// sealed chunks (512 KiB). Counted in sealed chunks of 64 KiB, such a
/// request holds at any moment: under two of plaintext waiting to be
/// sealed, the piece just sealed, its copy for the store, and the pieces
/// the store's writer has queued and not yet sent (one waiting and one
/// under way). That is six; a request holds up to 1.5 bytes per byte it
/// charges (see [`ByteBudget`]), so eight chunks charged cover twelve
/// held.
///
/// The body item being decoded is the runtime's. The six chunks of
/// slack cover it and its copy up to [`STREAM_ITEM_ALLOWANCE`] each; a
/// longer item is charged on top for as long as it is held
/// ([`stream_item_charge`]). A deployed Worker gets its request body in
/// items of 4 KiB (measured: 4,097 items for a part of 16 MiB, 257 for
/// 1 MiB), so the fixed charge is all a request is charged today.
pub const STREAM_CHARGE_BYTES: u64 = 8 * CIPHER_CHUNK_SIZE;

/// The largest body item the fixed charge of a streamed upload
/// ([`STREAM_CHARGE_BYTES`]) covers, held twice: 128 KiB.
pub const STREAM_ITEM_ALLOWANCE: u64 = 2 * PLAIN_CHUNK_SIZE;
// Six sealed chunks and two such items fit in what eight charged chunks
// may hold (1.5 bytes per byte charged).
const _: () =
    assert!(6 * CIPHER_CHUNK_SIZE + 2 * STREAM_ITEM_ALLOWANCE <= STREAM_CHARGE_BYTES / 2 * 3);

/// Longest accepted `Content-Length` value (digits). `u64::MAX` has 20.
const MAX_LENGTH_DIGITS: usize = 20;
/// Largest accepted DeleteObjects body: 1000 keys of 1024 bytes, each
/// byte possibly a character reference, stay below it in practice; a
/// larger document is refused before it is read.
pub const MAX_DELETE_BODY_BYTES: u64 = 2 * 1024 * 1024;

/// An ingress refusal. Each maps to one fixed S3 error; no request data is
/// ever echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressError {
    /// Target with control bytes, no scheme or no path: `400 InvalidRequest`.
    InvalidTarget,
    /// Plain `http` without `DEV_TRUST_HTTP`: `403 AccessDenied`.
    InsecureTransport,
    /// S3 request with no SigV4 credential at all: `403 AccessDenied`.
    AccessDenied,
    /// Admin request without a bearer token: `401`.
    AdminUnauthenticated,
    /// Admin request with a wrong bearer token: `403`.
    AdminForbidden,
    /// Admin request on a host the admin routes do not answer on
    /// (`ADMIN_HOST`): `404`, as for a route that does not exist.
    AdminHidden,
    /// `Content-Length` repeated, merged or not a decimal number: `400`.
    InvalidContentLength,
    /// PUT or UploadPart without `Content-Length`: `411`.
    MissingContentLength,
    /// Declared or actual body over the cap: `400 EntityTooLarge`.
    EntityTooLarge,
    /// Body shorter than declared, or the stream failed: `400 IncompleteBody`.
    IncompleteBody,
    /// Budget not available in time: `503 SlowDown` (SDKs retry).
    SlowDown,
    /// A caller broke the ingress order (e.g. read without a charge).
    Internal,
}

impl IngressError {
    pub fn status(self) -> u16 {
        match self {
            IngressError::InsecureTransport
            | IngressError::AccessDenied
            | IngressError::AdminForbidden => 403,
            IngressError::AdminUnauthenticated => 401,
            IngressError::AdminHidden => 404,
            IngressError::MissingContentLength => 411,
            IngressError::SlowDown => 503,
            IngressError::Internal => 500,
            IngressError::InvalidTarget
            | IngressError::InvalidContentLength
            | IngressError::EntityTooLarge
            | IngressError::IncompleteBody => 400,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            IngressError::InvalidTarget | IngressError::InvalidContentLength => "InvalidRequest",
            IngressError::InsecureTransport
            | IngressError::AccessDenied
            | IngressError::AdminForbidden => "AccessDenied",
            IngressError::AdminUnauthenticated => "Unauthorized",
            IngressError::AdminHidden => "NotFound",
            IngressError::MissingContentLength => "MissingContentLength",
            IngressError::EntityTooLarge => "EntityTooLarge",
            IngressError::IncompleteBody => "IncompleteBody",
            IngressError::SlowDown => "SlowDown",
            IngressError::Internal => "InternalError",
        }
    }

    fn message(self) -> &'static str {
        match self {
            IngressError::InvalidTarget => "The request target is not valid.",
            IngressError::InsecureTransport => "Requests must use HTTPS.",
            IngressError::AccessDenied => "Access Denied",
            IngressError::AdminUnauthenticated => "A bearer token is required.",
            IngressError::AdminForbidden => "Access Denied",
            IngressError::AdminHidden => "Not found.",
            IngressError::InvalidContentLength => "The Content-Length header is not valid.",
            IngressError::MissingContentLength => "You must provide the Content-Length HTTP header.",
            IngressError::EntityTooLarge => {
                "Your proposed upload exceeds the maximum allowed size."
            }
            IngressError::IncompleteBody => {
                "You did not provide the number of bytes specified by the Content-Length HTTP header."
            }
            IngressError::SlowDown => "Please reduce your request rate.",
            IngressError::Internal => "We encountered an internal error. Please try again.",
        }
    }

    /// The S3 XML error response.
    pub fn response(self) -> S3Response {
        let mut resp = S3Response::error(self.status(), self.code(), self.message());
        match self {
            IngressError::AdminUnauthenticated => resp
                .headers
                .push(("www-authenticate".into(), "Bearer".into())),
            IngressError::SlowDown => resp.headers.push(("retry-after".into(), "1".into())),
            _ => {}
        }
        resp
    }
}

impl fmt::Display for IngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for IngressError {}

// ---------------------------------------------------------------------------
// Raw target
// ---------------------------------------------------------------------------

/// Cuts `scheme://authority` off an absolute URL by byte scanning and
/// returns the path and query **unchanged**. Refuses anything that is not
/// printable ASCII (NUL, controls, space, DEL, raw non-ASCII, which the
/// runtime percent-encodes anyway), a `#`, a missing scheme or a target that
/// does not start with `/`.
pub fn origin_form(url: &str) -> Result<&str, IngressError> {
    if !url.bytes().all(|b| b.is_ascii_graphic() && b != b'#') {
        return Err(IngressError::InvalidTarget);
    }
    let scheme_end = url.find("://").ok_or(IngressError::InvalidTarget)?;
    let scheme = &url[..scheme_end];
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return Err(IngressError::InvalidTarget);
    }
    let rest = &url[scheme_end + 3..];
    let target_start = rest.find(['/', '?']).ok_or(IngressError::InvalidTarget)?;
    if target_start == 0 {
        // Empty authority.
        return Err(IngressError::InvalidTarget);
    }
    let target = &rest[target_start..];
    if !target.starts_with('/') {
        return Err(IngressError::InvalidTarget);
    }
    Ok(target)
}

/// Puts back the `Accept-Encoding` value the client sent, so a client that
/// signed it (rclone does by default) verifies.
///
/// Cloudflare's edge overwrites an incoming `Accept-Encoding` with its own
/// value (`gzip, br` in production, `br, gzip` under `wrangler dev`) before
/// the Worker runs. It reports the client's value, lightly normalised
/// (lowercased, codings it knows reordered, a repeated field cut to the first),
/// as `request.cf.clientAcceptEncoding`. That value is runtime metadata: a
/// client cannot set it except through its own `Accept-Encoding` header.
///
/// `client` is that value, or `None` when the runtime has none. When it is a
/// non-empty string, every `Accept-Encoding` field is replaced by exactly that
/// one value. Otherwise the headers stay as received. That covers no client
/// header, a coding the edge does not report, and a runtime that does not
/// rewrite.
///
/// Why this keeps SigV4 sound:
/// - Only this one header changes. The target, every other header and the
///   payload hash are verified exactly as received.
/// - There is exactly one value to verify against, so no candidate search
///   gives an attacker extra tries.
/// - Nothing is relaxed in the verifier. A request without a valid signature
///   is refused as before, and a signed value that differs from the restored
///   one fails with `SignatureDoesNotMatch`.
/// - The comma rule still applies: a multi-coding value is refused as
///   possibly merged.
/// - velmora never acts on `Accept-Encoding`.
///
/// Rules for anyone touching this later:
/// - The restored value is an authentication input only. It must never drive
///   response compression, caching, a cache key or `Vary`: it is the client's
///   claim, and the edge negotiates the response encoding itself.
/// - The signature binds the edge-normalised value, not the client's raw
///   bytes. A client that signed a value the edge reports differently fails
///   closed: `GZIP` reported as `gzip`, or a repeated field cut to the first,
///   is `SignatureDoesNotMatch`; a multi-coding value such as `br, gzip`
///   (reported as `gzip, br`) is already refused by the comma guard with
///   `InvalidRequest` before the signature is checked.
pub fn restore_accept_encoding(headers: &mut Vec<(String, String)>, client: Option<&str>) {
    let Some(client) = client.filter(|v| !v.is_empty()) else {
        return;
    };
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case("accept-encoding"));
    headers.push(("accept-encoding".to_owned(), client.to_owned()));
}

/// `true` when the runtime's URL says `https`. Only the runtime's own URL is
/// trusted, never `X-Forwarded-Proto` or `Forwarded`.
pub fn is_https(url: &str) -> bool {
    url.as_bytes()
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"https://"))
}

// ---------------------------------------------------------------------------
// Headers-only precheck
// ---------------------------------------------------------------------------

/// `Content-Length` as declared. `None` when absent. Repeated or merged
/// values (`5, 5`) and anything but plain decimal digits are refused.
pub fn declared_length(headers: &[(String, String)]) -> Result<Option<u64>, IngressError> {
    strict_length(headers, "content-length")
}

/// A length header: absent, or exactly one plain decimal value.
fn strict_length(headers: &[(String, String)], name: &str) -> Result<Option<u64>, IngressError> {
    let mut values = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim());
    let Some(v) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some()
        || v.is_empty()
        || v.len() > MAX_LENGTH_DIGITS
        || !v.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(IngressError::InvalidContentLength);
    }
    v.parse::<u64>()
        .map(Some)
        .map_err(|_| IngressError::InvalidContentLength)
}

/// The declared length a body-carrying upload must have: present
/// (`411` otherwise) and at most `max` (`EntityTooLarge` otherwise).
pub fn require_length(declared: Option<u64>, max: u64) -> Result<u64, IngressError> {
    let len = declared.ok_or(IngressError::MissingContentLength)?;
    if len > max {
        return Err(IngressError::EntityTooLarge);
    }
    Ok(len)
}

/// The lengths of an upload body: what the client sends (`encoded`,
/// `Content-Length`) and what it decodes to (`decoded`, the length the cap,
/// the budget and the validator apply to).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadLengths {
    pub encoded: Option<u64>,
    pub decoded: u64,
}

/// The lengths of a body-carrying upload, checked against `max` before any
/// byte is read. Identity framing needs `Content-Length` (`411`
/// otherwise). `aws-chunked` needs `x-amz-decoded-content-length` (`411`
/// otherwise) and may omit `Content-Length`.
pub fn upload_lengths(
    headers: &[(String, String)],
    max: u64,
) -> Result<UploadLengths, IngressError> {
    let encoded = declared_length(headers)?;
    let chunked = headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("content-encoding") && is_aws_chunked(v));
    if !chunked {
        let decoded = require_length(encoded, max)?;
        return Ok(UploadLengths { encoded, decoded });
    }
    let decoded = require_length(strict_length(headers, "x-amz-decoded-content-length")?, max)?;
    if encoded.is_some_and(|n| n < decoded) {
        return Err(IngressError::InvalidContentLength);
    }
    Ok(UploadLengths { encoded, decoded })
}

pub(crate) fn header<'a>(req: &'a S3Request, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Constant-time check of `Authorization: Bearer <token>` against the
/// configured admin token. `Ok(())` only on an exact match.
pub fn check_admin_bearer(req: &S3Request, token: &str) -> Result<(), IngressError> {
    let presented = header(req, "authorization").and_then(|v| {
        let (scheme, rest) = v.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
    });
    let Some(presented) = presented.filter(|p| !p.is_empty()) else {
        return Err(IngressError::AdminUnauthenticated);
    };
    if token.is_empty() || !bool::from(presented.as_bytes().ct_eq(token.as_bytes())) {
        return Err(IngressError::AdminForbidden);
    }
    Ok(())
}

/// The admin routes a read-only token may `GET`, without the query.
/// None of them changes anything or returns a secret.
pub const ADMIN_READ_ROUTES: [&str; 4] = [
    "/_admin/status",
    "/_admin/ops-snapshot",
    "/_admin/usage/buckets",
    "/_admin/cost",
];

/// The whole check of an admin request, in this order:
///
/// 1. With `ADMIN_HOST` set, the request must name that host; any other
///    is answered as if the route did not exist, token or not.
/// 2. `ADMIN_TOKEN` opens every route.
/// 3. `ADMIN_READ_TOKEN`, when one is configured, opens a `GET` of
///    [`ADMIN_READ_ROUTES`] and nothing else.
///
/// Both tokens are compared in constant time, and both are compared
/// whichever matches.
pub fn check_admin(req: &S3Request, cfg: &BridgeConfig) -> Result<(), IngressError> {
    if let Some(only) = &cfg.admin_host {
        let host = header(req, "host").unwrap_or("");
        // Without a port: the name is what is configured.
        let host = host.rsplit_once(':').map_or(host, |(name, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                name
            } else {
                host
            }
        });
        if !host.eq_ignore_ascii_case(only) {
            return Err(IngressError::AdminHidden);
        }
    }
    let presented = header(req, "authorization").and_then(|v| {
        let (scheme, rest) = v.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
    });
    let Some(presented) = presented.filter(|p| !p.is_empty()) else {
        return Err(IngressError::AdminUnauthenticated);
    };
    let matches =
        |token: &str| !token.is_empty() && bool::from(presented.as_bytes().ct_eq(token.as_bytes()));
    let write = matches(cfg.admin_token.expose());
    let read = cfg
        .admin_read_token
        .as_ref()
        .is_some_and(|t| matches(t.expose()));
    if write {
        return Ok(());
    }
    let path = req
        .raw_target
        .split_once('?')
        .map_or(req.raw_target.as_str(), |(p, _)| p);
    if read && req.method == crate::types::Method::Get && ADMIN_READ_ROUTES.contains(&path) {
        return Ok(());
    }
    Err(IngressError::AdminForbidden)
}

/// `true` when the request carries some SigV4 credential: an
/// `Authorization` header or a presigned `X-Amz-Signature`/`X-Amz-Credential`
/// query parameter. Presence only; the handler verifies it.
pub fn has_s3_credential(req: &S3Request) -> bool {
    if header(req, "authorization").is_some_and(|v| !v.trim().is_empty()) {
        return true;
    }
    // Names decoded as the router and the SigV4 target parser decode them.
    let query = req.raw_target.split_once('?').map_or("", |(_, q)| q);
    crate::service::query_names(query).is_some_and(|names| {
        names
            .iter()
            .any(|n| n.as_slice() == b"X-Amz-Signature" || n.as_slice() == b"X-Amz-Credential")
    })
}

/// Whether an origin-form target (`/path?query`) is an admin route:
/// `/_admin` or below it.
pub fn is_admin_target(raw_target: &str) -> bool {
    matches!(
        classify(&crate::types::Method::Get, raw_target),
        Route::Admin { .. }
    )
}

/// The host and port of a full request URL, as a `Host` header has
/// them. A request that came through a service binding may carry no
/// `Host` header; its URL names the host it was sent to.
pub fn url_authority(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    (!authority.is_empty()).then_some(authority)
}

/// [`is_admin_target`] of a full request URL. A URL whose target cannot
/// be read counts as an admin one, so its refusal is not cached either.
pub fn is_admin_url(url: &str) -> bool {
    origin_form(url).map_or(true, is_admin_target)
}

/// Adds `cache-control: no-store` unless the response has a
/// `cache-control` already. Every admin answer gets it.
pub fn no_store(resp: &mut S3Response) {
    if !resp
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("cache-control"))
    {
        resp.headers
            .push(("cache-control".to_string(), "no-store".to_string()));
    }
}

/// The front of every fetch once the request is parsed: [`precheck`],
/// then `handle` (the bridge, however the runtime drives it). Every
/// answer for an admin route, a refusal of the precheck too, carries
/// `cache-control: no-store`.
pub async fn front<F, Fut>(req: S3Request, cfg: &BridgeConfig, https: bool, handle: F) -> S3Response
where
    F: FnOnce(S3Request) -> Fut,
    Fut: core::future::Future<Output = S3Response>,
{
    // A sub-range request between invocations carries no S3 credential:
    // its token is its whole authority, and the handler checks it.
    if crate::fanout::is_internal_target(&req.raw_target) {
        return handle(req).await;
    }
    if let Some(resp) = crate::cors::preflight(&req, cfg) {
        return resp;
    }
    let admin = is_admin_target(&req.raw_target);
    let checked = {
        let route = classify(&req.method, &req.raw_target);
        precheck(&route, &req, cfg, https)
    };
    let mut resp = match checked {
        Err(e) => {
            let mut resp = e.response();
            if crate::cors::applies(&req, cfg) {
                crate::cors::merge_vary_origin(&mut resp);
            }
            if let Some(origin) = crate::cors::allowed_origin(&req, cfg) {
                crate::cors::decorate_origin(origin, &mut resp);
            }
            resp
        }
        Ok(()) => handle(req).await,
    };
    if admin {
        no_store(&mut resp);
    }
    resp
}

/// Headers-only checks run before routing into the bridge. Never reads the
/// body. `https` comes from [`is_https`] on the runtime's URL.
///
/// Anonymous S3 access does not exist in velmora, so a request with no
/// credential is `AccessDenied` here; the handler still verifies the
/// signature of everything else.
pub fn precheck(
    route: &Route<'_>,
    req: &S3Request,
    cfg: &BridgeConfig,
    https: bool,
) -> Result<(), IngressError> {
    if !https && !cfg.dev_trust_http {
        return Err(IngressError::InsecureTransport);
    }
    match route {
        Route::Admin { .. } => check_admin(req, cfg)?,
        _ if !has_s3_credential(req) => return Err(IngressError::AccessDenied),
        _ => {}
    }
    // A copy names its source in a header and has no body, so it need not
    // declare a length. The handler refuses one that declares a body.
    let copy = header(req, "x-amz-copy-source").is_some();
    match route {
        // A PutObject or UploadPart body above one extent is stored as
        // slices.
        Route::PutObject { .. } | Route::UploadPart { .. } if !copy => {
            upload_lengths(&req.headers, cfg.max_put_bytes)?;
        }
        // A control document with its own limit, whatever an extent is.
        Route::DeleteObjects { .. } => {
            upload_lengths(&req.headers, MAX_DELETE_BODY_BYTES)?;
        }
        _ => {
            let declared = declared_length(&req.headers)?;
            if declared.is_some_and(|n| n > cfg.max_extent_bytes) {
                return Err(IngressError::EntityTooLarge);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Byte budget
// ---------------------------------------------------------------------------

/// Sleeps the given number of milliseconds on the host runtime.
pub type Sleeper = Rc<dyn Fn(u32) -> LocalBoxFuture<'static, ()>>;

/// Runs a future to its end on the host runtime, beside the caller.
pub type Spawner = Rc<dyn Fn(LocalBoxFuture<'static, ()>)>;

#[derive(Debug)]
struct BudgetState {
    capacity: u64,
    /// The limit of what background jobs charge, at least `capacity`.
    job_capacity: u64,
    /// Bytes charged by requests.
    requests: Cell<u64>,
    /// Bytes charged by background jobs.
    jobs: Cell<u64>,
    peak: Cell<u64>,
    /// Charges that waited the full time and found no room.
    refused: Cell<u64>,
    /// What waiting for room has cost so far.
    pressure: Cell<Pressure>,
    /// The number the next charge that waits is given.
    next_wait: Cell<u64>,
    /// The charges that wait for room now: the lowest number came
    /// first.
    waiting: RefCell<Vec<Listed>>,
}

/// What the shared budget has cost the work of one isolate since it
/// began: counts and milliseconds, read by [`ByteBudget::pressure`].
/// Requests and background jobs are counted apart, because the budget
/// is one for both and the question is which of them waits for the
/// other. Nothing here changes what a charge does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pressure {
    /// Request charges that found no room at once and slept.
    pub request_waits: u64,
    /// The time request charges slept for room, in milliseconds,
    /// whether they were served, refused or dropped in the end. Counted
    /// in whole polls of [`CHARGE_POLL_MS`] as each one ends: a poll cut
    /// short because its charge was dropped is not counted.
    pub request_wait_ms: u64,
    /// Request charges that waited [`CHARGE_WAIT_MS`] and were refused
    /// (`SlowDown`).
    pub request_refused: u64,
    /// As `request_waits`, for background jobs.
    pub job_waits: u64,
    /// As `request_wait_ms`, for background jobs.
    pub job_wait_ms: u64,
    /// As `request_refused`, for background jobs.
    pub job_refused: u64,
    /// Charges above the whole limit of their kind, refused at once.
    pub too_large: u64,
}

impl BudgetState {
    /// Adds to the pressure counters.
    fn press(&self, f: impl FnOnce(&mut Pressure)) {
        let mut p = self.pressure.get();
        f(&mut p);
        self.pressure.set(p);
    }
}

/// A charge that waits for room, as the others see it.
#[derive(Clone, Copy, Debug)]
struct Listed {
    number: u64,
    requests: u64,
    jobs: u64,
}

/// One charge that waits for room, from its first wait until it is
/// served, gives up or is dropped.
struct Waiting {
    state: Rc<BudgetState>,
    number: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.state
            .waiting
            .borrow_mut()
            .retain(|w| w.number != self.number);
    }
}

impl BudgetState {
    /// Whether `requests` and `jobs` bytes may be charged together: each
    /// kind takes its share of its own limit and the shares sum to at
    /// most one, `requests / capacity + jobs / job_capacity <= 1`. With
    /// equal limits that is `requests + jobs <= capacity`.
    fn fits(&self, requests: u64, jobs: u64) -> bool {
        let (cap, job_cap) = (u128::from(self.capacity), u128::from(self.job_capacity));
        // A budget of nothing holds nothing (the products below are 0).
        if cap == 0 || job_cap == 0 {
            return requests == 0 && jobs == 0;
        }
        u128::from(requests) * job_cap + u128::from(jobs) * cap <= cap * job_cap
    }

    /// Whether a charge of `requests` and `jobs` bytes, of a request
    /// that holds `held` bytes already, would keep out a charge that
    /// waited before it (before `mine`, when this one is listed too):
    /// one that has room beside what all the others hold, and none when
    /// this request is counted too. A charge that the others keep out
    /// is not waiting for this request, and one that fits beside all of
    /// it is not kept out: neither is waited for.
    fn in_the_way(&self, requests: u64, jobs: u64, held: u64, mine: Option<u64>) -> bool {
        let others = self.requests.get().saturating_sub(held);
        let own = requests.saturating_add(held);
        self.waiting
            .borrow()
            .iter()
            .filter(|w| mine.is_none_or(|mine| w.number < mine))
            .any(|w| {
                let (requests, all_jobs) = (
                    others.saturating_add(w.requests),
                    self.jobs.get().saturating_add(w.jobs),
                );
                self.fits(requests, all_jobs)
                    && !self.fits(requests.saturating_add(own), all_jobs.saturating_add(jobs))
            })
    }
}

/// Per-isolate in-flight byte budget (`INFLIGHT_BUDGET_BYTES`). One per
/// isolate in the Worker (the bridge is built once per isolate), an `Rc` in
/// native tests. A [`Charge`] releases its bytes when dropped.
///
/// Two kinds of charge share it. A request charges against `capacity`. A
/// background job charges against `job_capacity` (`JOB_BUDGET_BYTES`),
/// which may be larger: a request holds more memory than it charges (an
/// upload's ciphertext is copied once more on its way to the blob store),
/// a job holds about what it charges. A charge fits while the two shares
/// sum to at most one: `requests / capacity + jobs / job_capacity <= 1`.
/// So with requests weighed at `job_capacity / capacity` bytes of memory
/// per byte charged, requests and jobs together never stand for more than
/// `job_capacity` bytes, in any mix.
pub struct ByteBudget {
    state: Rc<BudgetState>,
    sleeper: Option<Sleeper>,
    spawner: Option<Spawner>,
    /// The bytes held by the charges taken through this handle, when it
    /// stands for one request ([`ByteBudget::for_request`]).
    held: Option<Rc<Cell<u64>>>,
}

impl fmt::Debug for ByteBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByteBudget")
            .field("capacity", &self.state.capacity)
            .field("job_capacity", &self.state.job_capacity)
            .field("requests", &self.state.requests.get())
            .field("jobs", &self.state.jobs.get())
            .field("peak", &self.state.peak.get())
            .finish_non_exhaustive()
    }
}

impl ByteBudget {
    /// A budget that never waits: a charge that does not fit right away is
    /// `SlowDown`. Add a sleeper with [`ByteBudget::with_sleeper`]. Jobs
    /// and requests share the one `capacity` until
    /// [`ByteBudget::with_job_capacity`] says otherwise.
    pub fn new(capacity: u64) -> Self {
        ByteBudget {
            state: Rc::new(BudgetState {
                capacity,
                job_capacity: capacity,
                requests: Cell::new(0),
                jobs: Cell::new(0),
                peak: Cell::new(0),
                refused: Cell::new(0),
                pressure: Cell::new(Pressure::default()),
                next_wait: Cell::new(0),
                waiting: RefCell::new(Vec::new()),
            }),
            sleeper: None,
            spawner: None,
            held: None,
        }
    }

    /// Sets the limit of [`ByteBudget::charge_job`]. A value under the
    /// capacity is raised to it: a job is never held to less than a
    /// request. Call it while building the budget, before any charge.
    pub fn with_job_capacity(self, job_capacity: u64) -> Self {
        let s = &self.state;
        ByteBudget {
            state: Rc::new(BudgetState {
                capacity: s.capacity,
                job_capacity: job_capacity.max(s.capacity),
                requests: Cell::new(0),
                jobs: Cell::new(0),
                peak: Cell::new(0),
                refused: Cell::new(0),
                pressure: Cell::new(Pressure::default()),
                next_wait: Cell::new(0),
                waiting: RefCell::new(Vec::new()),
            }),
            sleeper: self.sleeper,
            spawner: self.spawner,
            held: None,
        }
    }

    /// The same budget for one request: what is charged through the
    /// handle returned is counted as held by that request, until each
    /// charge is dropped. A charge taken in turn through it
    /// ([`Self::charge_in_turn`]) is weighed together with what the
    /// request holds.
    pub fn for_request(&self) -> ByteBudget {
        ByteBudget {
            state: Rc::clone(&self.state),
            sleeper: self.sleeper.clone(),
            spawner: self.spawner.clone(),
            held: Some(Rc::default()),
        }
    }

    /// Lets [`ByteBudget::charge`] wait up to [`CHARGE_WAIT_MS`] for room.
    pub fn with_sleeper(mut self, sleeper: Sleeper) -> Self {
        self.sleeper = Some(sleeper);
        self
    }

    /// Lets the body of a GET be produced beside the client that reads
    /// it, one piece ahead (see [`ByteBudget::spawner`]).
    pub fn with_spawner(mut self, spawner: Spawner) -> Self {
        self.spawner = Some(spawner);
        self
    }

    pub fn capacity(&self) -> u64 {
        self.state.capacity
    }

    /// The limit of what background jobs charge
    /// ([`ByteBudget::charge_job`]).
    pub fn job_capacity(&self) -> u64 {
        self.state.job_capacity
    }

    /// The host sleeper, if this budget may wait. Other bounded waits on
    /// the same request path (a cold read waiting for a provider slot)
    /// poll with it too, so a budget without one never waits anywhere.
    pub fn sleeper(&self) -> Option<&Sleeper> {
        self.sleeper.as_ref()
    }

    /// The host spawner, if there is one. It sits here beside the sleeper
    /// as the other thing only the host runtime can do. Without one a
    /// body is produced only while its reader asks for the next piece.
    pub fn spawner(&self) -> Option<&Spawner> {
        self.spawner.as_ref()
    }

    /// Bytes charged right now, by requests and jobs together.
    pub fn in_use(&self) -> u64 {
        self.state
            .requests
            .get()
            .saturating_add(self.state.jobs.get())
    }

    /// Bytes charged right now by background jobs.
    pub fn jobs_in_use(&self) -> u64 {
        self.state.jobs.get()
    }

    /// Charges that waited [`CHARGE_WAIT_MS`] and found no room, since
    /// the isolate began: each is a moment at which the budget had been
    /// full for that long. A count that keeps rising while little is
    /// charged and released says that bytes are held by work that no
    /// longer runs.
    pub fn refused(&self) -> u64 {
        self.state.refused.get()
    }

    /// What waiting for room has cost the requests and the jobs of
    /// this isolate since it began.
    pub fn pressure(&self) -> Pressure {
        self.state.pressure.get()
    }

    /// Charges that wait for room now.
    pub fn waiting(&self) -> usize {
        self.state.waiting.borrow().len()
    }

    /// Highest `in_use` seen by this isolate (`inflight_peak_bytes`).
    pub fn peak(&self) -> u64 {
        self.state.peak.get()
    }

    /// Charges `bytes` for a request if they fit now.
    pub fn try_charge(&self, bytes: u64) -> Option<Charge> {
        self.try_charge_as(bytes, false)
    }

    /// Charges `bytes` for a background job if they fit now.
    pub fn try_charge_job(&self, bytes: u64) -> Option<Charge> {
        self.try_charge_as(bytes, true)
    }

    fn try_charge_as(&self, bytes: u64, job: bool) -> Option<Charge> {
        let s = &self.state;
        let (requests, jobs) = if job { (0, bytes) } else { (bytes, 0) };
        let next_requests = s.requests.get().checked_add(requests)?;
        let next_jobs = s.jobs.get().checked_add(jobs)?;
        if !s.fits(next_requests, next_jobs) {
            return None;
        }
        s.requests.set(next_requests);
        s.jobs.set(next_jobs);
        let in_use = next_requests.saturating_add(next_jobs);
        if in_use > s.peak.get() {
            s.peak.set(in_use);
        }
        if let Some(held) = &self.held {
            held.set(held.get().saturating_add(bytes));
        }
        Some(Charge {
            state: Rc::clone(&self.state),
            requests,
            jobs,
            held: self.held.clone(),
        })
    }

    /// The bytes the request of this handle holds now
    /// ([`Self::for_request`]), 0 for the budget itself.
    fn held(&self) -> u64 {
        self.held.as_ref().map_or(0, |held| held.get())
    }

    /// As [`Self::try_charge`], but not while a charge waits that this
    /// request alone keeps out: one that has room beside what the other
    /// requests hold, and none beside these bytes and what this request
    /// holds already (see [`Self::for_request`]). For a caller that
    /// would otherwise take, again and again, the room a waiting request
    /// needs (a body that is produced ahead of its reader). A charge
    /// that fits beside this request, or that others keep out, is not
    /// waited for: a small read goes on while a large upload waits.
    pub fn try_charge_in_turn(&self, bytes: u64) -> Option<Charge> {
        match self.state.in_the_way(bytes, 0, self.held(), None) {
            true => None,
            false => self.try_charge(bytes),
        }
    }

    /// As [`Self::charge`], but after the charges that were waiting
    /// before this one and that this request alone keeps out: see
    /// [`Self::try_charge_in_turn`]. They are let first for
    /// [`TURN_WAIT_MS`] at most, then this charge takes what is free
    /// like any other.
    pub async fn charge_in_turn(&self, bytes: u64) -> Result<Charge, IngressError> {
        self.charge_as(bytes, false, true).await
    }

    /// Charges `bytes` for a request, waiting up to [`CHARGE_WAIT_MS`] for
    /// room (only with a sleeper), then `SlowDown`. A charge larger than
    /// the whole capacity can never fit and fails at once. The caller has
    /// not read the body.
    pub async fn charge(&self, bytes: u64) -> Result<Charge, IngressError> {
        self.charge_as(bytes, false, false).await
    }

    /// [`ByteBudget::charge`] for a background job: the same wait, against
    /// the job limit.
    pub async fn charge_job(&self, bytes: u64) -> Result<Charge, IngressError> {
        self.charge_as(bytes, true, false).await
    }

    async fn charge_as(
        &self,
        bytes: u64,
        job: bool,
        in_turn: bool,
    ) -> Result<Charge, IngressError> {
        let limit = if job {
            self.state.job_capacity
        } else {
            self.state.capacity
        };
        if bytes > limit {
            let s = &self.state;
            s.press(|p| p.too_large = p.too_large.saturating_add(1));
            return Err(IngressError::SlowDown);
        }
        let mut waited = 0u32;
        // Listed while this waits, so a charge that takes its turn sees
        // it; taken off the list when this returns or is dropped.
        let mut waiting: Option<Waiting> = None;
        loop {
            // Someone who waited before this one, and whom only its
            // request keeps out, is served first: for a bounded time.
            let behind = in_turn && waited < TURN_WAIT_MS && {
                let mine = waiting.as_ref().map(|w| w.number);
                let (requests, jobs) = if job { (0, bytes) } else { (bytes, 0) };
                self.state.in_the_way(requests, jobs, self.held(), mine)
            };
            if !behind {
                if let Some(c) = self.try_charge_as(bytes, job) {
                    return Ok(c);
                }
            }
            let Some(sleep) = &self.sleeper else {
                return Err(IngressError::SlowDown);
            };
            if waited >= CHARGE_WAIT_MS {
                let s = &self.state;
                s.refused.set(s.refused.get().saturating_add(1));
                s.press(|p| {
                    let n = if job {
                        &mut p.job_refused
                    } else {
                        &mut p.request_refused
                    };
                    *n = n.saturating_add(1);
                });
                return Err(IngressError::SlowDown);
            }
            if waiting.is_none() {
                self.state.press(|p| {
                    let n = if job {
                        &mut p.job_waits
                    } else {
                        &mut p.request_waits
                    };
                    *n = n.saturating_add(1);
                });
                let number = self.state.next_wait.get();
                self.state.next_wait.set(number.wrapping_add(1));
                let (requests, jobs) = if job { (0, bytes) } else { (bytes, 0) };
                self.state.waiting.borrow_mut().push(Listed {
                    number,
                    requests,
                    jobs,
                });
                waiting = Some(Waiting {
                    state: Rc::clone(&self.state),
                    number,
                });
            }
            sleep(CHARGE_POLL_MS).await;
            waited = waited.saturating_add(CHARGE_POLL_MS);
            self.state.press(|p| {
                let ms = if job {
                    &mut p.job_wait_ms
                } else {
                    &mut p.request_wait_ms
                };
                *ms = ms.saturating_add(u64::from(CHARGE_POLL_MS));
            });
        }
    }

    /// The charge for a request body of `declared_len` bytes: plaintext and
    /// ciphertext live together while sealing.
    pub async fn charge_body(&self, declared_len: u64) -> Result<Charge, IngressError> {
        self.charge(declared_len.saturating_mul(2)).await
    }

    /// The charge for a request body of `declared_len` bytes that is
    /// sealed and stored while it arrives ([`seal_upload`]): never more
    /// than the same body held whole, and at most
    /// [`STREAM_CHARGE_BYTES`], because only a window of it is in memory.
    pub async fn charge_stream(&self, declared_len: u64) -> Result<Charge, IngressError> {
        self.charge(stream_charge(declared_len)).await
    }
}

/// Bytes held against a [`ByteBudget`]; released on drop.
#[must_use = "dropping a charge releases it"]
pub struct Charge {
    state: Rc<BudgetState>,
    /// Bytes charged as a request.
    requests: u64,
    /// Bytes charged as a background job.
    jobs: u64,
    /// The count of what its request holds, which these bytes are in.
    held: Option<Rc<Cell<u64>>>,
}

impl Charge {
    /// Takes `bytes` off the count of the request, or puts them on.
    fn count(&self, bytes: u64, on: bool) {
        if let Some(held) = &self.held {
            held.set(match on {
                true => held.get().saturating_add(bytes),
                false => held.get().saturating_sub(bytes),
            });
        }
    }

    pub fn bytes(&self) -> u64 {
        self.requests.saturating_add(self.jobs)
    }

    /// A charge of nothing on the same budget, in the count of the same
    /// request: the place for bytes that are charged only once they are
    /// in memory ([`Charge::hold`]).
    pub fn beside(&self) -> Charge {
        Charge {
            state: Rc::clone(&self.state),
            requests: 0,
            jobs: 0,
            held: self.held.clone(),
        }
    }

    /// Makes this charge stand for `bytes` of a request, **whether or
    /// not the budget has room**: for bytes that are in memory already,
    /// where waiting for room would free nothing. Room taken this way is
    /// not there for the next charge, which waits as for any other.
    pub fn hold(&mut self, bytes: u64) {
        let s = &self.state;
        self.count(self.requests, false);
        let others = s.requests.get().saturating_sub(self.requests);
        s.requests.set(others.saturating_add(bytes));
        self.requests = bytes;
        self.count(bytes, true);
        let in_use = s.requests.get().saturating_add(s.jobs.get());
        if in_use > s.peak.get() {
            s.peak.set(in_use);
        }
    }

    /// Takes over what `other` holds, so that one charge stands for both.
    /// A charge against another budget is released instead.
    pub fn absorb(&mut self, mut other: Charge) {
        if Rc::ptr_eq(&self.state, &other.state) {
            other.count(other.bytes(), false);
            self.count(other.bytes(), true);
            self.requests = self.requests.saturating_add(other.requests);
            self.jobs = self.jobs.saturating_add(other.jobs);
            other.requests = 0;
            other.jobs = 0;
        }
    }
}

impl fmt::Debug for Charge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Charge")
            .field("bytes", &self.bytes())
            .finish()
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.count(self.bytes(), false);
        let s = &self.state;
        s.requests
            .set(s.requests.get().saturating_sub(self.requests));
        s.jobs.set(s.jobs.get().saturating_sub(self.jobs));
    }
}

// ---------------------------------------------------------------------------
// Counted read
// ---------------------------------------------------------------------------

/// For a request that takes no body: whether none was sent.
///
/// A body can arrive without a `Content-Length` (chunked transfer), so
/// the header alone does not answer this. The stream is read until its
/// first byte or its end and nothing is kept. A stream that fails counts
/// as a body.
pub async fn body_is_empty(body: Body) -> bool {
    let Body::Stream { mut stream, .. } = body else {
        return true;
    };
    while let Some(chunk) = stream.next().await {
        if !chunk.is_ok_and(|bytes| bytes.is_empty()) {
            return false;
        }
    }
    true
}

/// Reads the body only after the budget charge: at most `declared_len + 1`
/// bytes, whatever the stream does. Short is `IncompleteBody` (as is a
/// failed stream), long is `EntityTooLarge`; the surplus chunk is never
/// kept. The `charge` must cover the declared length.
pub async fn read_capped(
    body: Body,
    declared_len: u64,
    charge: &Charge,
) -> Result<Vec<u8>, IngressError> {
    if charge.bytes() < declared_len {
        return Err(IngressError::Internal);
    }
    let cap = usize::try_from(declared_len).map_err(|_| IngressError::EntityTooLarge)?;
    let mut stream = match body {
        Body::Empty if cap == 0 => return Ok(Vec::new()),
        Body::Empty => return Err(IngressError::IncompleteBody),
        Body::Stream { stream, .. } => stream,
    };
    let mut out = Vec::with_capacity(cap);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| IngressError::IncompleteBody)?;
        if chunk.len() > cap - out.len() {
            return Err(IngressError::EntityTooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    if out.len() != cap {
        return Err(IngressError::IncompleteBody);
    }
    Ok(out)
}

/// Why [`read_upload`] failed: a transport/length refusal or a protocol
/// error from the validator (framing, signature, digest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadReadError {
    Ingress(IngressError),
    Proto(ErrorCode),
}

impl From<IngressError> for UploadReadError {
    fn from(e: IngressError) -> Self {
        UploadReadError::Ingress(e)
    }
}

impl From<ErrorCode> for UploadReadError {
    fn from(e: ErrorCode) -> Self {
        UploadReadError::Proto(e)
    }
}

/// Reads an upload body through `validator`, only after the budget charge,
/// and returns the decoded bytes. Only the decoded body is kept (at most
/// `lengths.decoded` bytes, the validator refuses more); encoded bytes are
/// dropped as they are decoded. With `Content-Length` the stream must carry
/// exactly that many bytes: short is `IncompleteBody`, long is
/// `EntityTooLarge`. The caller still calls `validator.finish()`.
pub async fn read_upload(
    body: Body,
    lengths: UploadLengths,
    charge: &Charge,
    validator: &mut UploadValidator,
) -> Result<Vec<u8>, UploadReadError> {
    if charge.bytes() < lengths.decoded || validator.decoded_length() != lengths.decoded {
        return Err(IngressError::Internal.into());
    }
    let cap = usize::try_from(lengths.decoded).map_err(|_| IngressError::EntityTooLarge)?;
    let mut out = Vec::with_capacity(cap);
    let mut received: u64 = 0;
    if let Body::Stream { mut stream, .. } = body {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| IngressError::IncompleteBody)?;
            received = received.saturating_add(chunk.len() as u64);
            if lengths.encoded.is_some_and(|n| received > n) {
                return Err(IngressError::EntityTooLarge.into());
            }
            validator.push_body(&chunk, &mut |decoded| out.extend_from_slice(decoded))?;
        }
    }
    if lengths.encoded.is_some_and(|n| received != n) {
        return Err(IngressError::IncompleteBody.into());
    }
    Ok(out)
}

/// Bytes [`ByteBudget::charge_stream`] charges for a body of
/// `declared_len` bytes.
pub fn stream_charge(declared_len: u64) -> u64 {
    declared_len.saturating_mul(2).min(STREAM_CHARGE_BYTES)
}

/// Bytes a streamed upload is charged on top of its fixed charge while
/// it holds a body item of `item_len` bytes: nothing up to
/// [`STREAM_ITEM_ALLOWANCE`], and the item and its copy above that.
pub fn stream_item_charge(item_len: u64) -> u64 {
    match item_len > STREAM_ITEM_ALLOWANCE {
        true => item_len.saturating_mul(2),
        false => 0,
    }
}

// ---------------------------------------------------------------------------
// An upload sealed while it arrives
// ---------------------------------------------------------------------------

/// A body that [`seal_upload`] read to its end, the validator accepted
/// and the sealer sealed whole.
#[derive(Debug)]
pub struct SealedUpload {
    /// The validator's account of the decoded body: its length, MD5,
    /// SHA-256 and checksum. These are the digests of the plaintext that
    /// was sealed: every decoded byte goes from the validator, which
    /// hashes it, straight to the sealer and nowhere else.
    pub decoded: DecodedUpload,
    pub sealed: SealedStream,
}

/// Where a [`seal_upload`] stream stands.
enum SealState {
    /// Not at its end yet. If the stream is gone, whoever read it gave up.
    Open,
    /// The body was refused; the stream ended with an error instead of
    /// its last piece.
    Refused(UploadReadError),
    /// The last piece was given out.
    Sealed(Box<SealedUpload>),
}

/// The caller's end of a [`seal_upload`] stream: how it ended.
pub struct UploadSeal(Rc<RefCell<SealState>>);

impl fmt::Debug for UploadSeal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UploadSeal")
    }
}

impl UploadSeal {
    /// How the stream ended, asked once its reader has returned.
    ///
    /// - `Ok`: the body was accepted and every piece was given out.
    /// - `Err(Some(_))`: the body was refused, with the answer for the
    ///   client. The stream gave an error in place of its last piece.
    /// - `Err(None)`: the reader stopped before the end (a store that
    ///   failed). The body is neither accepted nor refused.
    pub fn outcome(self) -> Result<SealedUpload, Option<UploadReadError>> {
        match self.0.replace(SealState::Open) {
            SealState::Sealed(upload) => Ok(*upload),
            SealState::Refused(e) => Err(Some(e)),
            SealState::Open => Err(None),
        }
    }
}

/// The item a refused [`seal_upload`] stream ends with. The reason is in
/// the [`UploadSeal`]; this only stops the store.
fn upload_refused() -> BridgeError {
    BridgeError::Invalid("upload refused before its last piece")
}

struct SealPump {
    body: Option<ByteStream>,
    validator: Option<UploadValidator>,
    sealer: Option<ExtentSealer>,
    lengths: UploadLengths,
    /// Encoded bytes received.
    received: u64,
    /// The body chunk being decoded, and how much of it already is.
    incoming: Vec<u8>,
    taken: usize,
    /// What `incoming` is charged beyond the request's fixed charge
    /// ([`stream_item_charge`]).
    item: Charge,
    /// Decoded bytes not sealed yet: under two chunks.
    plain: Vec<u8>,
    state: Rc<RefCell<SealState>>,
    done: bool,
}

impl SealPump {
    async fn next(&mut self) -> Option<crate::types::Result<Vec<u8>>> {
        if self.done {
            return None;
        }
        match self.piece().await {
            Ok(piece) => Some(Ok(piece)),
            Err(e) => {
                self.done = true;
                // Nothing of a refused body is kept, and its sealer is
                // dropped without a final chunk.
                self.body = None;
                self.validator = None;
                self.sealer = None;
                self.incoming = Vec::new();
                self.item.hold(0);
                self.plain = Vec::new();
                *self.state.borrow_mut() = SealState::Refused(e);
                Some(Err(upload_refused()))
            }
        }
    }

    /// The next piece of the sealed stream. The final piece is given
    /// only by [`SealPump::end`], after the validator accepted the body.
    async fn piece(&mut self) -> Result<Vec<u8>, UploadReadError> {
        let chunk = PLAIN_CHUNK_SIZE as usize;
        loop {
            let (Some(sealer), Some(validator)) = (self.sealer.as_mut(), self.validator.as_mut())
            else {
                return Err(IngressError::Internal.into());
            };
            // A whole chunk leaves at once while plaintext is due after
            // it. The final chunk waits for the end of the body.
            if self.plain.len() >= chunk && sealer.remaining() > PLAIN_CHUNK_SIZE {
                let piece = sealer
                    .seal_next(&self.plain[..chunk])
                    .map_err(|_| IngressError::Internal)?;
                self.plain.drain(..chunk);
                return Ok(piece);
            }
            if self.taken < self.incoming.len() {
                // At most one chunk is decoded per step, so `plain` stays
                // under two chunks whatever size the body arrives in.
                let end = self.incoming.len().min(self.taken.saturating_add(chunk));
                let plain = &mut self.plain;
                validator.push_body(&self.incoming[self.taken..end], &mut |decoded| {
                    plain.extend_from_slice(decoded)
                })?;
                self.taken = end;
                if self.plain.len() as u64 > sealer.remaining() {
                    return Err(IngressError::EntityTooLarge.into());
                }
                continue;
            }
            let next = match self.body.as_mut() {
                Some(body) => body.next().await,
                None => None,
            };
            match next {
                Some(Ok(bytes)) => {
                    self.received = self.received.saturating_add(bytes.len() as u64);
                    if self.lengths.encoded.is_some_and(|n| self.received > n) {
                        return Err(IngressError::EntityTooLarge.into());
                    }
                    // The item is in memory whatever the budget says,
                    // so a long one is charged without waiting.
                    self.item.hold(stream_item_charge(bytes.len() as u64));
                    self.incoming = bytes;
                    self.taken = 0;
                }
                Some(Err(_)) => return Err(IngressError::IncompleteBody.into()),
                None => return self.end(),
            }
        }
    }

    /// The body has ended: judge it, then seal and give the final chunk.
    fn end(&mut self) -> Result<Vec<u8>, UploadReadError> {
        self.body = None;
        self.incoming = Vec::new();
        self.item.hold(0);
        if self.lengths.encoded.is_some_and(|n| self.received != n) {
            return Err(IngressError::IncompleteBody.into());
        }
        let (Some(validator), Some(mut sealer)) = (self.validator.take(), self.sealer.take())
        else {
            return Err(IngressError::Internal.into());
        };
        // Signature chain, declared digests and decoded length.
        let decoded = validator.finish()?;
        if decoded.length() != self.lengths.decoded || self.plain.len() as u64 != sealer.remaining()
        {
            return Err(IngressError::IncompleteBody.into());
        }
        let piece = sealer
            .seal_next(&self.plain)
            .map_err(|_| IngressError::Internal)?;
        let sealed = sealer.finish().map_err(|_| IngressError::Internal)?;
        self.plain = Vec::new();
        self.done = true;
        *self.state.borrow_mut() = SealState::Sealed(Box::new(SealedUpload { decoded, sealed }));
        Ok(piece)
    }
}

/// Seals an upload body while it arrives: the returned stream gives the
/// sealed extent piece by piece (what [`crate::crypto::seal_extent`]
/// would build from the decoded body), for a store that writes it as it
/// comes ([`crate::ports::BlobStore::put_stream`]). Only a window of the
/// body is in memory: the body chunk being decoded, under two chunks of
/// plaintext and one sealed piece. Call it only after the budget charge
/// ([`ByteBudget::charge_stream`]), and give it that `charge`: a body
/// item longer than the charge allows for is charged beside it while it
/// is held ([`stream_item_charge`]).
///
/// The stream is read only as fast as its reader asks, and it asks the
/// body for more only then.
///
/// **A refused body never becomes a whole stream.** The final chunk of
/// the stream is sealed and given out only after the body has ended, its
/// length matched (`Content-Length`, when present, and the decoded
/// length) and `validator.finish()` accepted it (signature chain,
/// `Content-MD5`, checksums). Until then at least the final chunk is
/// missing, so the stream is shorter than `sealer.cipher_size()` and a
/// store that keeps the `put_stream` contract holds no object. On a
/// refusal (bad framing or chunk signature, wrong digest, short or long
/// body, a body that fails) the stream gives an error and ends, and the
/// [`UploadSeal`] names the answer.
pub fn seal_upload(
    body: Body,
    lengths: UploadLengths,
    validator: UploadValidator,
    sealer: ExtentSealer,
    charge: &Charge,
) -> Result<(ByteStream, UploadSeal), IngressError> {
    // A sealer that already gave out a piece would make a stream that
    // lacks it.
    if validator.decoded_length() != lengths.decoded
        || sealer.remaining() != lengths.decoded
        || !sealer.is_new()
    {
        return Err(IngressError::Internal);
    }
    let state = Rc::new(RefCell::new(SealState::Open));
    let pump = SealPump {
        body: match body {
            Body::Stream { stream, .. } => Some(stream),
            _ => None,
        },
        validator: Some(validator),
        sealer: Some(sealer),
        lengths,
        received: 0,
        incoming: Vec::new(),
        taken: 0,
        item: charge.beside(),
        plain: Vec::new(),
        state: Rc::clone(&state),
        done: false,
    };
    let stream = futures_util::stream::unfold(pump, |mut pump| async move {
        let item = pump.next().await?;
        Some((item, pump))
    });
    Ok((stream.boxed_local(), UploadSeal(state)))
}

// ---------------------------------------------------------------------------
// Redacted request log
// ---------------------------------------------------------------------------

/// One request log line: method, bucket, a hash of the raw key, status and
/// request ID. Never the query (presigned credentials), headers
/// (`Authorization`, tokens) or bodies.
pub fn log_line(method: &str, raw_target: &str, status: u16, request_id: &str) -> String {
    let path = raw_target.split_once('?').map_or(raw_target, |(p, _)| p);
    let path = path.strip_prefix('/').unwrap_or(path);
    let (bucket, key) = path
        .split_once('/')
        .map_or((path, None), |(b, k)| (b, Some(k)));
    let safe = |s: &str, max: usize| {
        !s.is_empty()
            && s.len() <= max
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    let method = if safe(method, 16) { method } else { "-" };
    let bucket = if safe(bucket, 63) { bucket } else { "-" };
    let key = match key {
        Some(k) if !k.is_empty() => {
            let digest = Sha256::digest(k.as_bytes());
            digest[..8].iter().map(|b| format!("{b:02x}")).collect()
        }
        _ => "-".to_string(),
    };
    let request_id = if safe(request_id, 64) {
        request_id
    } else {
        "-"
    };
    format!("req method={method} bucket={bucket} key#={key} status={status} id={request_id}")
}
