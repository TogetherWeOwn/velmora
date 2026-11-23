//! Large GETs served by several invocations.
//!
//! One invocation has a bounded CPU budget, and every byte of a GET is
//! decrypted in it, so one invocation can only serve so much plaintext. A
//! GET whose body is larger than `GET_FANOUT_BYTES` is therefore split:
//! the invocation that received it (the *front*) authenticates it, plans
//! the response and its headers as for any GET, and then asks for the body
//! in consecutive sub-ranges, one at a time, each from an invocation of
//! its own. The front never reads those bytes: the runtime pipes each
//! sub-response into the response of the client ([`SubPipe`]).
//!
//! # The sub-request
//!
//! A sub-request is `GET /_fanout` with one header, [`TOKEN_HEADER`]. It
//! carries no S3 credential. What it may read is in the token, a
//! [`Grant`]: bucket id, generation id, plaintext offset and length, and
//! an expiry, under an HMAC-SHA256 whose key is derived from the active
//! KEK (HKDF, its own label). A request is served only when
//!
//! 1. it carries no header that the edge adds to a request from the
//!    Internet ([`from_edge`]): the front reaches the Worker through its
//!    service binding, and such a request carries only the headers the
//!    front set;
//! 2. the tag verifies, in constant time, under the KEK version the token
//!    names;
//! 3. the token has not expired.
//!
//! Anything else is `403`, with one answer for every cause. The tag is the
//! guard; the header rule only narrows who can even present one.
//!
//! The grant names a generation, not a key: every sub-range of one
//! download comes from the generation the front planned, whatever is
//! published to the key meanwhile. A generation whose extents are no
//! longer readable fails the sub-request, and with it the download.
//!
//! # Failure
//!
//! The front opens the first sub-range before its own status line goes
//! out, so an object that cannot be read is an error response
//! ([`Fanout::open_first`]). Later, a sub-range that is refused, has
//! another length than asked, or breaks while it is piped aborts the
//! client's stream ([`Fanout::pump`]): the response has a declared
//! length, so the client sees a failed transfer, never a short success. A
//! `503` is retried a few times first, since nothing of that sub-range
//! has been sent yet.

use std::cell::Cell;
use std::fmt;
use std::rc::Rc;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::metrics::{GetFailureStage as Stage, GetObservation};
use crate::ports::Kek;
use crate::types::{BucketId, GenerationId, KekBytes, RespBody, S3Request, S3Response, UnixMs};

/// Origin-form target of a sub-request.
pub const INTERNAL_TARGET: &str = "/_fanout";
/// The header that carries the token. Its name has `token` in it: the
/// platform's request logs leave out the value of such a header.
pub const TOKEN_HEADER: &str = "x-velmora-fanout-token";
/// How long a token is good for, from the moment the front mints it. It
/// only has to cover the start of one sub-request; the front mints one
/// per sub-request, just before it is sent.
pub const TOKEN_TTL_MS: i64 = 120_000;
/// Smallest and largest `GET_FANOUT_BYTES`. The upper bound keeps one
/// sub-range well inside the CPU budget of one invocation (300 s): a
/// sub-range read from Usenet took 50 to 90 s of CPU per GiB on a
/// deployed Worker, one read from the cache 20 to 40 s.
pub const MIN_FANOUT_BYTES: u64 = 1024 * 1024;
pub const MAX_FANOUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Most sub-ranges one GET may have. With [`MAX_RETRIES`] and the
/// catalogue round trips of the front it stays under the subrequest
/// limit of an invocation (10,000). Calls through a service binding one
/// after the other count against that limit and no other: one request
/// to a deployed Worker made 9,000 of them.
pub const MAX_SUBRANGES: u64 = 8192;
/// Most retries in one download, over all its sub-ranges.
pub const MAX_RETRIES: u32 = 1024;
const _: () = assert!(MAX_SUBRANGES + (MAX_RETRIES as u64) < 9_500);

/// Attempts at one sub-request before the download is given up, and the
/// pause before the second and the third.
const ATTEMPTS: usize = 3;
const RETRY_PAUSE_MS: [u32; ATTEMPTS - 1] = [500, 2_000];
/// Most bytes of a refusal that are handed on to the client.
pub const MAX_REFUSAL_BYTES: usize = 16 * 1024;

const KEY_INFO: &[u8] = b"velmora/fanout/v1/mac-key";
const MAC_DOMAIN: &[u8] = b"velmora/fanout/v1/grant";
const VERSION: &str = "v1";

/// `true` for the target of a sub-request, whatever else the request is.
pub fn is_internal_target(raw_target: &str) -> bool {
    let path = raw_target.split_once('?').map_or(raw_target, |(p, _)| p);
    path == INTERNAL_TARGET
}

/// `true` if the request carries a header that the edge adds to every
/// request it takes from the Internet (or from another Worker's global
/// `fetch`). A client cannot remove them. A request through the service
/// binding has none.
pub fn from_edge(req: &S3Request) -> bool {
    req.headers.iter().any(|(name, _)| {
        let name = name.to_ascii_lowercase();
        name.starts_with("cf-")
            || name.starts_with("x-forwarded-")
            || name == "x-real-ip"
            || name == "forwarded"
            || name == "via"
            || name == "true-client-ip"
    })
}

/// What one sub-request may read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub bucket: BucketId,
    pub generation: GenerationId,
    /// Plaintext offset within the generation.
    pub start: u64,
    /// Plaintext bytes, at least one.
    pub len: u64,
    pub expires: UnixMs,
}

/// Why a token was refused. Never told to the caller: every refusal is
/// the same `403`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Malformed,
    UnknownKey,
    BadTag,
    Expired,
}

/// An id that can stand in a token: the separator and anything outside
/// the unreserved set are refused.
fn token_safe(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

struct MacKey(Zeroizing<[u8; 32]>);

impl MacKey {
    fn derive(kek: &KekBytes) -> MacKey {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, kek.expose())
            .expand(KEY_INFO, key.as_mut())
            .expect("HKDF-SHA256 output of 32 bytes");
        MacKey(key)
    }

    /// The tag over every field, each with its length in front, so no two
    /// grants share a message.
    fn tag(&self, kek_version: u32, grant: &Grant) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&self.0[..])
            .expect("HMAC accepts a key of any length");
        let mut field = |bytes: &[u8]| {
            mac.update(&(bytes.len() as u64).to_be_bytes());
            mac.update(bytes);
        };
        field(MAC_DOMAIN);
        field(&kek_version.to_be_bytes());
        field(grant.bucket.as_str().as_bytes());
        field(grant.generation.as_str().as_bytes());
        field(&grant.start.to_be_bytes());
        field(&grant.len.to_be_bytes());
        field(&grant.expires.0.to_be_bytes());
        mac.finalize().into_bytes().into()
    }
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// A canonical decimal: digits only, no sign, no leading zero.
fn decimal<N: core::str::FromStr>(text: &str) -> Option<N> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text.len() == 1 || !text.starts_with('0'));
    canonical.then(|| text.parse().ok()).flatten()
}

impl Grant {
    /// The token for this grant under the active KEK. `None` for a grant
    /// that cannot be written as one (an id with a reserved character, an
    /// empty range).
    pub fn seal<K: Kek>(&self, kek: &K) -> Option<String> {
        if !token_safe(self.bucket.as_str())
            || !token_safe(self.generation.as_str())
            || self.len == 0
            || self.start.checked_add(self.len).is_none()
            || self.expires.0 < 0
        {
            return None;
        }
        let (version, key) = kek.active();
        let tag = MacKey::derive(key).tag(version, self);
        Some(format!(
            "{VERSION}.{version}.{}.{}.{}.{}.{}.{}",
            self.expires.0,
            self.start,
            self.len,
            self.bucket.as_str(),
            self.generation.as_str(),
            hex(&tag)
        ))
    }

    /// The grant of a token, if its tag verifies and it has not expired.
    pub fn open<K: Kek>(kek: &K, token: &str, now: UnixMs) -> Result<Grant, Refused> {
        let fields: Vec<&str> = token.split('.').collect();
        let [VERSION, version, expires, start, len, bucket, generation, tag] = fields[..] else {
            return Err(Refused::Malformed);
        };
        let version: u32 = decimal(version).ok_or(Refused::Malformed)?;
        let expires: i64 = decimal(expires).ok_or(Refused::Malformed)?;
        let start: u64 = decimal(start).ok_or(Refused::Malformed)?;
        let len: u64 = decimal(len).ok_or(Refused::Malformed)?;
        if !token_safe(bucket)
            || !token_safe(generation)
            || len == 0
            || start.checked_add(len).is_none()
        {
            return Err(Refused::Malformed);
        }
        let tag = unhex(tag).ok_or(Refused::Malformed)?;
        let grant = Grant {
            bucket: BucketId::new(bucket.to_owned()),
            generation: GenerationId::new(generation.to_owned()),
            start,
            len,
            expires: UnixMs(expires),
        };
        let key = kek.version(version).ok_or(Refused::UnknownKey)?;
        let want = MacKey::derive(key).tag(version, &grant);
        if tag.len() != want.len() || !bool::from(want[..].ct_eq(&tag)) {
            return Err(Refused::BadTag);
        }
        // Only a token that verified is told apart by its age.
        if now >= grant.expires {
            return Err(Refused::Expired);
        }
        Ok(grant)
    }
}

/// The grant a sub-request presents: the request must not come through
/// the edge, must be a `GET` of [`INTERNAL_TARGET`] and must carry
/// exactly one token, which must verify.
pub fn admit<K: Kek>(kek: &K, req: &S3Request, now: UnixMs) -> Result<Grant, Refused> {
    if from_edge(req) || req.method != crate::types::Method::Get {
        return Err(Refused::Malformed);
    }
    let mut tokens = req
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(TOKEN_HEADER))
        .map(|(_, value)| value.as_str());
    match (tokens.next(), tokens.next()) {
        (Some(token), None) => Grant::open(kek, token, now),
        _ => Err(Refused::Malformed),
    }
}

/// One sub-request, ready to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubRequest {
    /// Position in the download, from 0.
    pub index: u64,
    /// Plaintext offset within the generation.
    pub start: u64,
    /// The exact length of the body a `200` must have.
    pub len: u64,
    /// The value of [`TOKEN_HEADER`].
    pub token: String,
}

/// The body of a GET that is served in sub-ranges: plaintext
/// `[start, start + len)` of one generation, `chunk` bytes at a time.
pub struct Fanout {
    start: u64,
    len: u64,
    chunk: u64,
    /// Mints the token for `(start, len)`; `None` if it cannot.
    mint: Rc<dyn Fn(u64, u64) -> Option<String>>,
    /// Retries left to this download ([`MAX_RETRIES`]).
    retries: Cell<u32>,
}

impl fmt::Debug for Fanout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fanout")
            .field("start", &self.start)
            .field("len", &self.len)
            .field("chunk", &self.chunk)
            .finish_non_exhaustive()
    }
}

/// Why a download in sub-ranges stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FanoutError {
    /// No token could be minted.
    Mint,
    /// The sub-request could not be sent or its answer not read.
    Transport,
    /// Answered with this status, not `200`.
    Status(u16),
    /// A `200` whose declared length is not the one asked for.
    Length,
    /// The body broke while it was piped, or the client went away.
    Pipe,
}

/// The answer to one sub-request, body unread.
pub struct SubResponse<B> {
    pub status: u16,
    /// `Content-Length`, if declared.
    pub length: Option<u64>,
    pub body: B,
}

/// How the front sends sub-requests and moves their bodies. The Worker
/// implements it over its service binding and the client's response
/// stream; the bytes never pass through this crate.
#[allow(async_fn_in_trait)]
pub trait SubPipe {
    type Body;
    /// Sends one sub-request and returns its answer with the body unread.
    async fn open(&self, sub: &SubRequest) -> Result<SubResponse<Self::Body>, FanoutError>;
    /// Moves the whole body into the client's stream and leaves the
    /// stream open. An error if the body ends early or fails.
    async fn pipe(&self, body: Self::Body) -> Result<(), FanoutError>;
    /// At most `cap` bytes of a refusal's body. Best effort.
    async fn refusal(&self, body: Self::Body, cap: usize) -> Vec<u8>;
    /// Cancels a body that will not be read, so the invocation that
    /// makes it stops now and gives back what it holds.
    async fn discard(&self, body: Self::Body);
    async fn sleep(&self, ms: u32);
    /// Ends the client's stream as complete.
    async fn close(&self) -> Result<(), FanoutError>;
    /// Ends the client's stream as failed.
    async fn abort(&self);
}

impl Fanout {
    /// `None` unless the range is one that is served in sub-ranges: more
    /// than one `chunk`, and no more sub-ranges than one invocation may
    /// ask for.
    pub fn new(
        start: u64,
        len: u64,
        chunk: u64,
        mint: Rc<dyn Fn(u64, u64) -> Option<String>>,
    ) -> Option<Fanout> {
        let fits = chunk > 0
            && len > chunk
            && start.checked_add(len).is_some()
            && len.div_ceil(chunk) <= MAX_SUBRANGES;
        fits.then_some(Fanout {
            start,
            len,
            chunk,
            mint,
            retries: Cell::new(MAX_RETRIES),
        })
    }

    /// Total plaintext bytes: the `Content-Length` of the response.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many sub-ranges the body has.
    pub fn count(&self) -> u64 {
        self.len.div_ceil(self.chunk)
    }

    /// Offset and length of sub-range `index`: consecutive, each `chunk`
    /// long but the last, together exactly the range.
    pub fn span(&self, index: u64) -> Option<(u64, u64)> {
        let skip = index.checked_mul(self.chunk)?;
        if skip >= self.len {
            return None;
        }
        Some((self.start + skip, self.chunk.min(self.len - skip)))
    }

    /// Sub-request `index` with a token minted now.
    pub fn request(&self, index: u64) -> Result<SubRequest, FanoutError> {
        let (start, len) = self.span(index).ok_or(FanoutError::Mint)?;
        let token = (self.mint)(start, len).ok_or(FanoutError::Mint)?;
        Ok(SubRequest {
            index,
            start,
            len,
            token,
        })
    }

    /// Opens sub-range `index`: a `200` of exactly its length, body
    /// unread. A `503` is tried again after a pause, with a fresh token:
    /// nothing of this sub-range has been sent. Any other answer is
    /// final. The first sub-range is not tried again: the client has no
    /// status line yet and is better served by the `503` now, as a GET
    /// in one invocation gives it, than by a longer wait.
    async fn open<P: SubPipe>(
        &self,
        pipe: &P,
        index: u64,
    ) -> Result<P::Body, (FanoutError, Option<P::Body>)> {
        let mut attempt = 0;
        loop {
            let sub = self.request(index).map_err(|e| (e, None))?;
            let resp = pipe.open(&sub).await.map_err(|e| (e, None))?;
            match resp.status {
                200 if resp.length == Some(sub.len) => return Ok(resp.body),
                200 => {
                    pipe.discard(resp.body).await;
                    return Err((FanoutError::Length, None));
                }
                503 if index > 0 && attempt < RETRY_PAUSE_MS.len() && self.retries.get() > 0 => {
                    self.retries.set(self.retries.get() - 1);
                    pipe.discard(resp.body).await;
                    pipe.sleep(RETRY_PAUSE_MS[attempt]).await;
                    attempt += 1;
                }
                status => return Err((FanoutError::Status(status), Some(resp.body))),
            }
        }
    }

    /// Opens the first sub-range, before the response of the client has a
    /// status line. A `503` is handed on as it is (it is the
    /// answer a GET in one invocation would have given); every other
    /// failure is `fallback`, the caller's `500`.
    pub async fn open_first<P: SubPipe>(
        &self,
        pipe: &P,
        fallback: impl FnOnce() -> S3Response,
    ) -> Result<P::Body, S3Response> {
        self.open_first_observed(pipe, fallback, &mut GetObservation::default())
            .await
    }

    /// As `open_first`, with redacted diagnostics for the request datapoint.
    pub async fn open_first_observed<P: SubPipe>(
        &self,
        pipe: &P,
        fallback: impl FnOnce() -> S3Response,
        observed: &mut GetObservation,
    ) -> Result<P::Body, S3Response> {
        match self.open(pipe, 0).await {
            Ok(body) => Ok(body),
            Err((FanoutError::Status(503), Some(body))) => {
                observed.mark_stage(Stage::SubrangeStatus);
                let bytes = pipe.refusal(body, MAX_REFUSAL_BYTES).await;
                let mut resp = S3Response {
                    status: 503,
                    headers: vec![("content-type".into(), "application/xml".into())],
                    body: RespBody::Bytes(bytes),
                };
                resp.headers.push(("retry-after".into(), "30".into()));
                Err(resp)
            }
            Err((cause, body)) => {
                if let Some(body) = body {
                    pipe.discard(body).await;
                }
                observed.mark_stage(match cause {
                    FanoutError::Mint | FanoutError::Status(403) => Stage::Grant,
                    FanoutError::Transport => Stage::SubrangeTransport,
                    FanoutError::Length => Stage::SubrangeLength,
                    FanoutError::Status(_) => Stage::SubrangeStatus,
                    FanoutError::Pipe => Stage::Other,
                });
                Err(fallback())
            }
        }
    }

    /// Pipes `first` and then every further sub-range, in order, into the
    /// client's stream, and closes it. On the first failure the stream is
    /// aborted and nothing more is asked for.
    pub async fn pump<P: SubPipe>(&self, pipe: &P, first: P::Body) -> Result<(), FanoutError> {
        let run = async {
            pipe.pipe(first).await?;
            for index in 1..self.count() {
                match self.open(pipe, index).await {
                    Ok(body) => pipe.pipe(body).await?,
                    Err((e, body)) => {
                        if let Some(body) = body {
                            pipe.discard(body).await;
                        }
                        return Err(e);
                    }
                }
            }
            pipe.close().await
        };
        let done = run.await;
        if done.is_err() {
            pipe.abort().await;
        }
        done
    }
}
