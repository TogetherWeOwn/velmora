//! The store of the recovery copy: a bucket at another S3-compatible
//! provider, outside the account that holds everything else.
//!
//! This module can `PUT`, `HEAD` and list. It has no delete: a copy that
//! could be removed from here would be lost together with its source.
//!
//! - Every request is signed (SigV4, signed payload hash) and sent over
//!   the [`HttpSend`] port; the endpoint is `https` only.
//! - A network error, a timeout, a 5xx or a 429 is tried again, four
//!   tries in all with a growing pause. Every other status that is not
//!   a 2xx (a 4xx, and also a redirect, which is never followed) is
//!   [`RemoteError::Refused`] at once: a retry cannot help.
//! - An answer is bounded: the request names the longest body that is
//!   read ([`HttpRequest::max_answer`]).
//! - A key is checked before it is signed: segments of letters, digits
//!   and `-_.~`, none empty, `.` or `..`, so a request never leaves the
//!   store's prefix. A listed key that does not pass the same check
//!   is never taken for a copy.
//! - A `PUT` carries `Content-MD5`, so the store refuses a body damaged
//!   on the way, and is followed by a `HEAD` whose size and ETag must be
//!   those of the bytes sent.
//! - Neither key of the store nor an `Authorization` header is ever
//!   formatted: [`RemoteConfig`]'s `Debug` shows `<redacted>` for the
//!   access key and for the secret, and [`HttpRequest`]'s `Debug` shows
//!   the method and the target only. [`HttpResponse`]'s `Debug` shows
//!   the status and the length of the body, never the body or a header.

// No `Send` bound is intended (see `ports`).
#![allow(async_fn_in_trait)]

use std::fmt;

use base64::Engine;
use sha2::{Digest, Sha256};
/// The longest list answer that is read.
pub use velmora_s3_proto::sign::MAX_LIST_BYTES;
use velmora_s3_proto::sign::{
    parse_list, sign_request, Listed, SigningKey, Unsigned, EMPTY_SHA256,
};

use crate::config::ConfigError;
use crate::ports::Clock;
use crate::types::Secret;

/// Tries of one request, the first included.
pub const TRIES: u32 = 4;
/// Pause before the second try; each later pause is four times longer.
pub const FIRST_PAUSE_MS: u64 = 200;
/// Keys asked for in one list request.
pub const LIST_LIMIT: u32 = 1000;
/// The longest key a store may name. A listed key becomes the place a
/// caller goes on from, so its length is bounded here.
pub const MAX_KEY_BYTES: usize = 1024;
/// The longest answer body that is read to a `HEAD` or a `PUT`: none is
/// used, an error text is small.
pub const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// A request for the [`HttpSend`] port. `Debug` leaves the headers out.
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The longest answer body to read, in bytes.
    pub max_answer: usize,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.url)
    }
}

/// An answer. Header names are lowercase. `Debug` shows the status and
/// the length of the body only: the error text of a store can name the
/// access key.
#[derive(Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} bytes)", self.status, self.body.len())
    }
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// No answer came: a network error or the adapter's timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoAnswer;

/// Outbound HTTPS. An implementation:
/// - bounds every request by a timeout;
/// - never follows a redirect (the request is signed for one host): it
///   returns the 3xx as the answer;
/// - reads at most [`HttpRequest::max_answer`] bytes of the body, and
///   returns [`NoAnswer`] when the body is longer.
pub trait HttpSend {
    async fn send(&self, request: &HttpRequest) -> Result<HttpResponse, NoAnswer>;
    async fn pause(&self, ms: u64);
}

/// Why a request to the store did not do what was asked. Carries a
/// status at most, never text from the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteError {
    /// The request itself is refused (key, quota, permission): a 4xx,
    /// or any other status that is neither a 2xx nor worth another try,
    /// such as a redirect.
    Refused(u16),
    /// No usable answer after every try.
    Unavailable,
    /// The store answered, and what it holds is not what was sent.
    Mismatch,
    /// The request cannot be signed: a key outside the safe alphabet, or
    /// with an empty, `.` or `..` segment. Nothing was sent.
    Unsignable,
}

/// One page of what the store holds under the prefix, in key order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyPage {
    /// The copies, named by their key here.
    pub objects: Vec<Listed>,
    /// Keys that this module would not sign, so something else wrote
    /// them (a console, another tool). None of them is a copy.
    pub foreign: Vec<String>,
    /// There is more after this page.
    pub truncated: bool,
    /// The last key of the page, of either kind: the next page starts
    /// after it.
    pub last: Option<String>,
}

/// `RECOVERY_COPY` and the `E2_*` values, validated. `Debug` shows
/// neither the access key nor the secret.
#[derive(Clone, Debug)]
pub struct RemoteConfig {
    /// Host of the endpoint. A port is refused.
    pub host: String,
    pub region: String,
    pub bucket: String,
    /// Put before every key; ends with `/`.
    pub prefix: String,
    pub access_key: Secret,
    pub secret_key: Secret,
}

fn safe(value: &str, extra: &[u8]) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(&c))
}

/// A bucket or region name that a URL parser leaves as it is: no port,
/// no `..`, a letter or digit at both ends. What is signed is what is
/// sent.
fn name(value: &str) -> bool {
    let ends = |c: Option<u8>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    safe(value, b".-")
        && !value.contains("..")
        && ends(value.bytes().next())
        && ends(value.bytes().last())
}

/// A host name that a URL parser neither rewrites nor reads as an
/// address: a [`name`] of two labels or more whose last label is
/// letters only (`1.2.3`, `0x7f.1` and `127.0.0.1` are refused, and so
/// is a single label such as `localhost`).
fn host_name(value: &str) -> bool {
    name(value)
        && value
            .rsplit_once('.')
            .is_some_and(|(_, last)| last.bytes().all(|c| c.is_ascii_lowercase()))
}

/// A key of this module (without bucket and store prefix) that stays
/// under the store prefix whatever reads the path: segments of
/// unreserved characters (letters, digits, `-`, `_`, `.`, `~`), none
/// empty, `.` or `..`. The signer has the same rule for a path; this
/// one also holds for a key that a listing names, which is not signed.
fn key_ok(key: &str) -> bool {
    key.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.~".contains(&c))
    })
}

impl RemoteConfig {
    /// `None` = the copy is off (`RECOVERY_COPY` unset or `off`). With
    /// `on`, every other value is required and checked.
    pub fn from_vars(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<RemoteConfig>, ConfigError> {
        let invalid = |name: &str| ConfigError::Invalid(name.to_string());
        match get("RECOVERY_COPY").as_deref().map(str::trim) {
            None | Some("") | Some("off") => return Ok(None),
            Some("on") => {}
            Some(_) => return Err(invalid("RECOVERY_COPY")),
        }
        let need = |name: &str| match get(name) {
            Some(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
            _ => Err(ConfigError::Missing(name.to_string())),
        };
        let endpoint = need("E2_ENDPOINT")?;
        let host = endpoint
            .strip_prefix("https://")
            .map(|h| h.trim_end_matches('/'))
            .filter(|h| host_name(h))
            .ok_or_else(|| invalid("E2_ENDPOINT"))?
            .to_string();
        let region = need("E2_REGION")?;
        let bucket = need("E2_BUCKET")?;
        let prefix = need("RECOVERY_PREFIX")?;
        let access_key = Secret::new(need("E2_ACCESS_KEY")?);
        let secret_key = Secret::new(need("E2_SECRET_KEY")?);
        if !name(&region) || region.contains('.') {
            return Err(invalid("E2_REGION"));
        }
        if !name(&bucket) {
            return Err(invalid("E2_BUCKET"));
        }
        if !prefix.ends_with('/')
            || prefix.starts_with('/')
            || prefix.contains("//")
            || !safe(&prefix, b"-_/")
        {
            return Err(invalid("RECOVERY_PREFIX"));
        }
        if !access_key
            .expose()
            .bytes()
            .all(|c| c.is_ascii_alphanumeric())
        {
            return Err(invalid("E2_ACCESS_KEY"));
        }
        Ok(Some(RemoteConfig {
            host,
            region,
            bucket,
            prefix,
            access_key,
            secret_key,
        }))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// MD5 of `bytes` in hex: what a store reports as the ETag of a single put.
pub fn md5_hex(bytes: &[u8]) -> String {
    hex(&md5::compute(bytes).0)
}

/// The recovery store behind an [`HttpSend`].
pub struct S3Remote<H: HttpSend> {
    cfg: RemoteConfig,
    http: H,
}

impl<H: HttpSend> S3Remote<H> {
    pub fn new(cfg: RemoteConfig, http: H) -> Self {
        S3Remote { cfg, http }
    }

    /// Signs and sends, with the retries of the module doc. A 2xx or a
    /// 404 is returned; every other status is an error.
    #[allow(clippy::too_many_arguments)]
    async fn call<T: Clock>(
        &self,
        clock: &T,
        method: &'static str,
        path: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: &[u8],
        max_answer: usize,
    ) -> Result<HttpResponse, RemoteError> {
        let payload_sha256 = if body.is_empty() {
            EMPTY_SHA256.to_string()
        } else {
            hex(&Sha256::digest(body))
        };
        let key = SigningKey {
            access_key: self.cfg.access_key.expose(),
            secret: self.cfg.secret_key.expose().as_bytes(),
            region: &self.cfg.region,
        };
        let unsigned = Unsigned {
            method,
            path,
            query,
            headers,
            payload_sha256: &payload_sha256,
        };
        let mut pause = FIRST_PAUSE_MS;
        for attempt in 1..=TRIES {
            // Signed anew for each try: the date is part of the signature.
            let now = clock.now().0;
            let signed = sign_request(&key, &self.cfg.host, now.div_euclid(1000), &unsigned)
                .map_err(|_| RemoteError::Unsignable)?;
            let request = HttpRequest {
                method,
                url: format!("https://{}{}", self.cfg.host, signed.target),
                headers: signed.headers,
                body: body.to_vec(),
                max_answer,
            };
            match self.http.send(&request).await {
                // No answer, an answer longer than was asked for, a 5xx
                // or a 429: tried again.
                Err(NoAnswer) => {}
                Ok(r) if r.body.len() > max_answer => {}
                Ok(r) if (500..600).contains(&r.status) || r.status == 429 => {}
                Ok(r) if (200..300).contains(&r.status) || r.status == 404 => return Ok(r),
                Ok(r) => return Err(RemoteError::Refused(r.status)),
            }
            if attempt < TRIES {
                // Up to half as long again, so that jobs do not retry in step.
                let jitter = now.rem_euclid(1 + (pause / 2) as i64) as u64;
                self.http.pause(pause + jitter).await;
                pause *= 4;
            }
        }
        Err(RemoteError::Unavailable)
    }

    /// The path of `key` in the store, under the bucket and the prefix.
    fn path(&self, key: &str) -> Result<String, RemoteError> {
        if !key_ok(key) {
            return Err(RemoteError::Unsignable);
        }
        Ok(format!("/{}/{}{key}", self.cfg.bucket, self.cfg.prefix))
    }

    /// Size and ETag of the copy of `key`; `None` = there is none.
    pub async fn head<T: Clock>(
        &self,
        clock: &T,
        key: &str,
    ) -> Result<Option<Listed>, RemoteError> {
        let r = self
            .call(
                clock,
                "HEAD",
                &self.path(key)?,
                &[],
                &[],
                &[],
                MAX_ANSWER_BYTES,
            )
            .await?;
        if r.status == 404 {
            return Ok(None);
        }
        let size = r.header("content-length").and_then(|v| v.parse().ok());
        let etag = r.header("etag").map(|v| v.trim_matches('"').to_string());
        match (size, etag) {
            (Some(size), Some(etag)) => Ok(Some(Listed {
                key: key.to_string(),
                size,
                etag,
            })),
            _ => Err(RemoteError::Mismatch),
        }
    }

    /// Stores `bytes` as the copy of `key` and proves that the store
    /// holds exactly them: `Ok` only after a `HEAD` showed their size
    /// and MD5.
    pub async fn put<T: Clock>(
        &self,
        clock: &T,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), RemoteError> {
        let md5 = md5::compute(bytes).0;
        let content_md5 = base64::engine::general_purpose::STANDARD.encode(md5);
        let sha256 = hex(&Sha256::digest(bytes));
        let headers = [
            ("content-md5", content_md5.as_str()),
            ("x-amz-meta-sha256", sha256.as_str()),
        ];
        let path = self.path(key)?;
        let r = self
            .call(clock, "PUT", &path, &[], &headers, bytes, MAX_ANSWER_BYTES)
            .await?;
        if r.status == 404 {
            // The bucket is not there.
            return Err(RemoteError::Refused(404));
        }
        match self.head(clock, key).await? {
            Some(stored)
                if stored.size == bytes.len() as u64
                    && stored.etag.eq_ignore_ascii_case(&hex(&md5)) =>
            {
                Ok(())
            }
            _ => Err(RemoteError::Mismatch),
        }
    }

    /// Up to [`LIST_LIMIT`] keys that start with `prefix` and sort after
    /// `start_after`, in key order, named by their key here (without
    /// the store's own prefix). An answer that is out of order or names
    /// a key outside the range or longer than [`MAX_KEY_BYTES`] is an
    /// error. A key this module would not
    /// sign is no copy: it is given apart ([`CopyPage::foreign`]) and
    /// the listing goes on. An object that is the store's prefix itself
    /// (a "folder" made in a console) is left out altogether.
    pub async fn list<T: Clock>(
        &self,
        clock: &T,
        prefix: &str,
        start_after: &str,
    ) -> Result<CopyPage, RemoteError> {
        let own = &self.cfg.prefix;
        let full_prefix = format!("{own}{prefix}");
        let full_after = format!("{own}{start_after}");
        let limit = LIST_LIMIT.to_string();
        let mut query = vec![
            ("list-type", "2"),
            ("max-keys", limit.as_str()),
            ("prefix", full_prefix.as_str()),
        ];
        if !start_after.is_empty() {
            query.push(("start-after", full_after.as_str()));
        }
        let path = format!("/{}", self.cfg.bucket);
        let r = self
            .call(clock, "GET", &path, &query, &[], &[], MAX_LIST_BYTES)
            .await?;
        if r.status == 404 {
            return Err(RemoteError::Refused(404));
        }
        let listed = parse_list(&r.body).map_err(|_| RemoteError::Mismatch)?;
        let mut page = CopyPage {
            truncated: listed.truncated,
            ..CopyPage::default()
        };
        let mut last = start_after.to_string();
        for object in listed.objects {
            if object.key == *own {
                continue;
            }
            let key = Some(object.key.as_str())
                .filter(|k| k.len() <= MAX_KEY_BYTES)
                .and_then(|k| k.strip_prefix(own.as_str()))
                .filter(|k| k.starts_with(prefix) && *k > last.as_str())
                .ok_or(RemoteError::Mismatch)?
                .to_string();
            last.clone_from(&key);
            if key_ok(&key) {
                page.objects.push(Listed { key, ..object });
            } else {
                page.foreign.push(key);
            }
            page.last = Some(last.clone());
        }
        // The caller goes on from the last key, so a page that says
        // "more" must name one.
        if page.truncated && page.last.is_none() {
            return Err(RemoteError::Mismatch);
        }
        Ok(page)
    }
}
