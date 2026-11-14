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

use std::cell::Cell;
use std::fmt;
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use velmora_s3_proto::{is_aws_chunked, ErrorCode, UploadValidator};

use crate::config::BridgeConfig;
use crate::service::Route;
use crate::types::{Body, S3Request, S3Response};

/// How long a request may wait for budget before `503 SlowDown`.
pub const CHARGE_WAIT_MS: u32 = 20_000;

/// Poll interval while waiting for budget.
pub const CHARGE_POLL_MS: u32 = 100;

/// Longest accepted `Content-Length` value (digits). `u64::MAX` has 20.
const MAX_LENGTH_DIGITS: usize = 20;

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
        Route::PutObject { .. } | Route::UploadPart { .. } if !copy => {
            upload_lengths(&req.headers, cfg.max_extent_bytes)?;
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

#[derive(Debug)]
struct BudgetState {
    capacity: u64,
    in_use: Cell<u64>,
    peak: Cell<u64>,
}

/// Per-isolate in-flight byte budget (`INFLIGHT_BUDGET_BYTES`). One per
/// isolate in the Worker (the bridge is built once per isolate), an `Rc` in
/// native tests. A [`Charge`] releases its bytes when dropped.
pub struct ByteBudget {
    state: Rc<BudgetState>,
    sleeper: Option<Sleeper>,
}

impl fmt::Debug for ByteBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByteBudget")
            .field("capacity", &self.state.capacity)
            .field("in_use", &self.state.in_use.get())
            .field("peak", &self.state.peak.get())
            .finish_non_exhaustive()
    }
}

impl ByteBudget {
    /// A budget that never waits: a charge that does not fit right away is
    /// `SlowDown`. Add a sleeper with [`ByteBudget::with_sleeper`].
    pub fn new(capacity: u64) -> Self {
        ByteBudget {
            state: Rc::new(BudgetState {
                capacity,
                in_use: Cell::new(0),
                peak: Cell::new(0),
            }),
            sleeper: None,
        }
    }

    /// Lets [`ByteBudget::charge`] wait up to [`CHARGE_WAIT_MS`] for room.
    pub fn with_sleeper(mut self, sleeper: Sleeper) -> Self {
        self.sleeper = Some(sleeper);
        self
    }

    pub fn capacity(&self) -> u64 {
        self.state.capacity
    }

    /// The host sleeper, if this budget may wait. Other bounded waits on
    /// the same request path (a cold read waiting for a provider slot)
    /// poll with it too, so a budget without one never waits anywhere.
    pub fn sleeper(&self) -> Option<&Sleeper> {
        self.sleeper.as_ref()
    }

    /// Bytes charged right now.
    pub fn in_use(&self) -> u64 {
        self.state.in_use.get()
    }

    /// Highest `in_use` seen by this isolate (`inflight_peak_bytes`).
    pub fn peak(&self) -> u64 {
        self.state.peak.get()
    }

    /// Charges `bytes` if they fit now.
    pub fn try_charge(&self, bytes: u64) -> Option<Charge> {
        let s = &self.state;
        let next = s.in_use.get().checked_add(bytes)?;
        if next > s.capacity {
            return None;
        }
        s.in_use.set(next);
        if next > s.peak.get() {
            s.peak.set(next);
        }
        Some(Charge {
            state: Rc::clone(&self.state),
            bytes,
        })
    }

    /// Charges `bytes`, waiting up to [`CHARGE_WAIT_MS`] for room (only with
    /// a sleeper), then `SlowDown`. A charge larger than the whole capacity
    /// can never fit and fails at once. The caller has not read the body.
    pub async fn charge(&self, bytes: u64) -> Result<Charge, IngressError> {
        if bytes > self.state.capacity {
            return Err(IngressError::SlowDown);
        }
        let mut waited = 0u32;
        loop {
            if let Some(c) = self.try_charge(bytes) {
                return Ok(c);
            }
            let Some(sleep) = &self.sleeper else {
                return Err(IngressError::SlowDown);
            };
            if waited >= CHARGE_WAIT_MS {
                return Err(IngressError::SlowDown);
            }
            sleep(CHARGE_POLL_MS).await;
            waited = waited.saturating_add(CHARGE_POLL_MS);
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
    bytes: u64,
}

impl Charge {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl fmt::Debug for Charge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Charge")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        let s = &self.state;
        s.in_use.set(s.in_use.get().saturating_sub(self.bytes));
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
