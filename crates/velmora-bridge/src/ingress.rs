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
//! 4. [`ByteBudget::charge`] reserves `2 × declared_len`, waiting a bounded
//!    time without reading the body, then `503 SlowDown`.
//! 5. [`read_capped`] reads at most `declared_len + 1` bytes; uploads use
//!    [`read_upload`], which decodes as it reads.
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

use velmora_s3_proto::{is_aws_chunked, ErrorCode, UploadValidator};

use crate::config::BridgeConfig;
use crate::service::{classify, Route};
use crate::types::{Body, S3Request, S3Response};

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

/// How long a charge that lets another one go first (a job behind a
/// charge that goes ahead of the jobs, [`ByteBudget::charge_ahead`]; a
/// charge that takes its turn, [`ByteBudget::charge_in_turn`]) is kept
/// waiting by one that is not polled: its request was stopped and
/// nothing took it off the list. One that is polled marks itself every
/// [`CHARGE_POLL_MS`] and is waited for as long as the rule says.
pub const WAIT_QUIET_MS: u32 = 2_000;

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

fn header<'a>(req: &'a S3Request, name: &str) -> Option<&'a str> {
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
    let admin = is_admin_target(&req.raw_target);
    let checked = {
        let route = classify(&req.method, &req.raw_target);
        precheck(&route, &req, cfg, https)
    };
    let mut resp = match checked {
        Err(e) => e.response(),
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
        Route::Admin { .. } => check_admin_bearer(req, cfg.admin_token.expose())?,
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
    /// The number the next charge that waits is given.
    next_wait: Cell<u64>,
    /// The charges that wait for room now: the lowest number came
    /// first.
    waiting: RefCell<Vec<Listed>>,
}

/// A charge that waits for room, as the others see it.
#[derive(Clone, Copy, Debug)]
struct Listed {
    number: u64,
    requests: u64,
    jobs: u64,
    /// Whether the jobs let this one go first
    /// ([`ByteBudget::charge_ahead`]).
    ahead: bool,
    /// How often this one was polled while it waited.
    mark: u64,
    /// Set by a charge that waited for this one and saw no new mark for
    /// [`WAIT_QUIET_MS`]: nobody waits for this one until it is polled
    /// again.
    quiet: bool,
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
    /// it is not kept out: neither is waited for. Nor is one that is
    /// quiet. The first such charge, with its mark.
    fn in_the_way(
        &self,
        requests: u64,
        jobs: u64,
        held: u64,
        mine: Option<u64>,
    ) -> Option<(u64, u64)> {
        let others = self.requests.get().saturating_sub(held);
        let own = requests.saturating_add(held);
        self.waiting
            .borrow()
            .iter()
            .filter(|w| !w.quiet && mine.is_none_or(|mine| w.number < mine))
            .find(|w| {
                let (requests, all_jobs) = (
                    others.saturating_add(w.requests),
                    self.jobs.get().saturating_add(w.jobs),
                );
                self.fits(requests, all_jobs)
                    && !self.fits(requests.saturating_add(own), all_jobs.saturating_add(jobs))
            })
            .map(|w| (w.number, w.mark))
    }
}

impl BudgetState {
    /// The charge ahead that a job charge of `bytes` would keep out, if
    /// there is one, with its mark: one that has room beside the
    /// requests that run, and none beside the jobs that run and these
    /// bytes. A job that leaves room for every such charge is not held
    /// back, nor is one behind a charge that the requests keep out (the
    /// jobs are not what it waits for), and nobody is while none waits.
    fn ahead_of(&self, bytes: u64) -> Option<(u64, u64)> {
        let jobs = self.jobs.get().saturating_add(bytes);
        self.waiting
            .borrow()
            .iter()
            .filter(|w| w.ahead && !w.quiet)
            .find(|w| {
                let requests = self.requests.get().saturating_add(w.requests);
                self.fits(requests, 0) && !self.fits(requests, jobs)
            })
            .map(|w| (w.number, w.mark))
    }

    /// One round of waiting for the charge that was `seen` to be in
    /// front (its number and mark), by a charge that keeps in `watched`
    /// whom it waits for, the mark that one had when first seen so, and
    /// the time since. Whether to wait on; `None` when that charge
    /// showed no new mark for [`WAIT_QUIET_MS`]: it was stopped, is
    /// quiet from now on, and the caller looks again (there may be
    /// another one behind it).
    fn wait_for(
        &self,
        seen: Option<(u64, u64)>,
        watched: &mut Option<(u64, u64, u32)>,
    ) -> Option<bool> {
        *watched = match (seen, *watched) {
            (Some(now), Some((n, m, since))) if (n, m) == now => {
                Some((n, m, since.saturating_add(CHARGE_POLL_MS)))
            }
            (Some((number, mark)), _) => Some((number, mark, 0)),
            (None, _) => None,
        };
        match *watched {
            Some((number, _, since)) if since >= WAIT_QUIET_MS => {
                self.relist(number, |w| w.quiet = true);
                *watched = None;
                None
            }
            held_back => Some(held_back.is_some()),
        }
    }

    /// Changes the listing of the charge that waits under `number`.
    fn relist(&self, number: u64, change: impl FnOnce(&mut Listed)) {
        if let Some(w) = self
            .waiting
            .borrow_mut()
            .iter_mut()
            .find(|w| w.number == number)
        {
            change(w);
        }
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
        match self.state.in_the_way(bytes, 0, self.held(), None).is_some() {
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
        self.charge_as(bytes, false, true, false).await
    }

    /// Charges `bytes` for a request, waiting up to [`CHARGE_WAIT_MS`] for
    /// room (only with a sleeper), then `SlowDown`. A charge larger than
    /// the whole capacity can never fit and fails at once. The caller has
    /// not read the body.
    pub async fn charge(&self, bytes: u64) -> Result<Charge, IngressError> {
        self.charge_as(bytes, false, false, false).await
    }

    /// As [`Self::charge`], and the jobs let it go first: while it
    /// waits, a job charge that would keep it out
    /// ([`Self::charge_job`]) waits too, so the room the running jobs
    /// give back is not taken by the next job. For a large fixed charge
    /// of a request that is rare and that a client waits for (the
    /// Complete of an upload with a segmented record): jobs that come
    /// one after another would otherwise never leave room for it. A job
    /// that leaves room beside it is not held back, and no job is while
    /// the requests that run are what keeps it out. One whose request
    /// was stopped holds the jobs back for [`WAIT_QUIET_MS`] at most.
    pub async fn charge_ahead(&self, bytes: u64) -> Result<Charge, IngressError> {
        self.charge_as(bytes, false, false, true).await
    }

    /// [`ByteBudget::charge`] for a background job: the same wait, against
    /// the job limit, and after a charge that goes ahead of the jobs
    /// ([`Self::charge_ahead`]) and that these bytes would keep out.
    pub async fn charge_job(&self, bytes: u64) -> Result<Charge, IngressError> {
        self.charge_as(bytes, true, false, false).await
    }

    /// [`Self::charge_job`] for a job that runs already and needs more
    /// (a repost within a verify job): it waits for room and for nobody.
    /// What it holds already may be what keeps a charge ahead out, and
    /// it gives that back only when it is done: held back, the two
    /// would wait for each other until both give up.
    pub async fn charge_job_more(&self, bytes: u64) -> Result<Charge, IngressError> {
        self.charge_with(bytes, true, false, false, false).await
    }

    async fn charge_as(
        &self,
        bytes: u64,
        job: bool,
        in_turn: bool,
        ahead: bool,
    ) -> Result<Charge, IngressError> {
        self.charge_with(bytes, job, in_turn, ahead, job).await
    }

    /// `lets_ahead`: whether this charge waits for a charge ahead that
    /// it would keep out (a job that is about to start).
    async fn charge_with(
        &self,
        bytes: u64,
        job: bool,
        in_turn: bool,
        ahead: bool,
        lets_ahead: bool,
    ) -> Result<Charge, IngressError> {
        let limit = if job {
            self.state.job_capacity
        } else {
            self.state.capacity
        };
        if bytes > limit {
            return Err(IngressError::SlowDown);
        }
        let mut waited = 0u32;
        // Listed while this waits, so a charge that takes its turn sees
        // it; taken off the list when this returns or is dropped.
        let mut waiting: Option<Waiting> = None;
        // The charge ahead that holds this job back, and the one in
        // front of a charge that takes its turn (`BudgetState::wait_for`).
        let (mut ahead_watched, mut turn_watched) = (None, None);
        loop {
            // A job lets a charge ahead go first while that one is
            // polled: one that shows no new mark for long enough was
            // stopped, and is waited for by nobody from then on.
            let yields = lets_ahead && {
                let seen = self.state.ahead_of(bytes);
                match self.state.wait_for(seen, &mut ahead_watched) {
                    Some(held_back) => held_back,
                    None => continue,
                }
            };
            // Someone who waited before this one, and whom only its
            // request keeps out, is served first: for a bounded time,
            // and while that one is polled.
            let behind = in_turn && waited < TURN_WAIT_MS && {
                let mine = waiting.as_ref().map(|w| w.number);
                let (requests, jobs) = if job { (0, bytes) } else { (bytes, 0) };
                let seen = self.state.in_the_way(requests, jobs, self.held(), mine);
                match self.state.wait_for(seen, &mut turn_watched) {
                    Some(held_back) => held_back,
                    None => continue,
                }
            };
            if !behind && !yields {
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
                return Err(IngressError::SlowDown);
            }
            if waiting.is_none() {
                let number = self.state.next_wait.get();
                self.state.next_wait.set(number.wrapping_add(1));
                let (requests, jobs) = if job { (0, bytes) } else { (bytes, 0) };
                self.state.waiting.borrow_mut().push(Listed {
                    number,
                    requests,
                    jobs,
                    ahead,
                    mark: 0,
                    quiet: false,
                });
                waiting = Some(Waiting {
                    state: Rc::clone(&self.state),
                    number,
                });
            }
            sleep(CHARGE_POLL_MS).await;
            waited = waited.saturating_add(CHARGE_POLL_MS);
            if let Some(w) = &waiting {
                // Polled again: the others see that this one is alive.
                self.state.relist(w.number, |w| {
                    w.mark = w.mark.wrapping_add(1);
                    w.quiet = false;
                });
            }
        }
    }

    /// The charge for a request body of `declared_len` bytes: plaintext and
    /// ciphertext live together while sealing.
    pub async fn charge_body(&self, declared_len: u64) -> Result<Charge, IngressError> {
        self.charge(declared_len.saturating_mul(2)).await
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
