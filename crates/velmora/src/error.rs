//! Crate-wide error type.

use std::{fmt, io};

/// Documented worker/API error code for stale provider credentials (S7).
/// Every NNTP path that observes `480`/`481` (or `482` on `AUTHINFO`) maps
/// to this code; the web app renders an inline re-auth prompt
/// on it instead of a generic error page. The code is safe to log and to
/// return in error bodies: it carries no credential material.
pub const PROVIDER_AUTH_EXPIRED_CODE: &str = "provider_auth_expired";

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Every failure this crate can report. Transport I/O surfaces as
/// [`Error::Io`]; NNTP protocol failures carry their numeric reply code.
///
/// `Debug` is manual, not derived: the [`Error::AuthFailed`] and
/// [`Error::NoPermission`] payloads are attacker-influenced server reply
/// text from the auth exchange that may carry reflected
/// credential material, so `{:?}` must redact it exactly like `Display`
/// does (threat-model §3/§6; precedent: redacted `Debug` for credential
/// configs in `workers/api/src/vault.rs`).
pub enum Error {
    /// Underlying transport I/O failure (includes timeouts, which each
    /// transport implementation enforces and reports as [`io::ErrorKind::TimedOut`]).
    Io(io::Error),
    /// Unexpected NNTP reply: (numeric code, human-readable text).
    NntpReply { code: u16, text: String },
    /// Server rejected our credentials (`480`/`481`, `482` on `AUTHINFO`)
    /// or demands auth first.
    AuthFailed(String),
    /// Server refused the command (`502`: no permission / access denied).
    /// Deliberately NOT an auth-failure signal: `502` also covers service
    /// unavailability, so it must not trigger the re-auth prompt.
    NoPermission(String),
    /// Article does not exist (`430`).
    ArticleNotFound(String),
    /// Malformed yEnc article, NZB document, PAR2 set, or ciphertext.
    Malformed(String),
    /// yEnc CRC32 mismatch after a successful structural decode.
    CrcMismatch {
        message_id: String,
        want: u32,
        got: u32,
    },
    /// An NZB/PAR2 resource bound from [`crate::nzb::Limits`] was exceeded.
    Bounds { bound: &'static str, limit: i64 },
    /// Decryption/authentication failure (bad key, bad nonce, bad padding,
    /// secretbox authentication failure, range outside the plaintext).
    Decrypt(String),
    /// PAR2 verification found damaged blocks (verify-only path, no repair).
    Par2Unhealthy { filename: String, detail: String },
    /// Operation needs a native target (e.g. spawning the `par2` repair binary).
    UnsupportedOnWasm(&'static str),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => f.debug_tuple("Io").field(e).finish(),
            Error::NntpReply { code, text } => f
                .debug_struct("NntpReply")
                .field("code", code)
                .field("text", text)
                .finish(),
            // Redacted: never print the server reply text (see enum docs).
            Error::AuthFailed(_) => f.debug_tuple("AuthFailed").field(&"<redacted>").finish(),
            // Redacted like AuthFailed: 502 replies inside the auth
            // exchange are the same attacker-influenced reply text.
            Error::NoPermission(_) => f.debug_tuple("NoPermission").field(&"<redacted>").finish(),
            Error::ArticleNotFound(id) => f.debug_tuple("ArticleNotFound").field(id).finish(),
            Error::Malformed(r) => f.debug_tuple("Malformed").field(r).finish(),
            Error::CrcMismatch {
                message_id,
                want,
                got,
            } => f
                .debug_struct("CrcMismatch")
                .field("message_id", message_id)
                .field("want", want)
                .field("got", got)
                .finish(),
            Error::Bounds { bound, limit } => f
                .debug_struct("Bounds")
                .field("bound", bound)
                .field("limit", limit)
                .finish(),
            Error::Decrypt(r) => f.debug_tuple("Decrypt").field(r).finish(),
            Error::Par2Unhealthy { filename, detail } => f
                .debug_struct("Par2Unhealthy")
                .field("filename", filename)
                .field("detail", detail)
                .finish(),
            Error::UnsupportedOnWasm(op) => f.debug_tuple("UnsupportedOnWasm").field(op).finish(),
        }
    }
}

impl Error {
    /// Stable worker/API code for this failure. Only authentication failures
    /// map to [`PROVIDER_AUTH_EXPIRED_CODE`]; every other variant is a
    /// generic protocol error that must not trigger the re-auth prompt.
    pub fn code(&self) -> &'static str {
        match self {
            Error::AuthFailed(_) => PROVIDER_AUTH_EXPIRED_CODE,
            _ => "request_failed",
        }
    }

    /// True when the provider rejected our credentials (`480`/`481`, or
    /// `482` on `AUTHINFO`) or demands auth first. The caller must surface
    /// [`PROVIDER_AUTH_EXPIRED_CODE`] (HTTP 401) with no credential material.
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Error::AuthFailed(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "transport I/O: {e}"),
            Error::NntpReply { code, text } => write!(f, "NNTP reply {code}: {text}"),
            // Generic by construction (threat-model §3/§6: no credential
            // material in logs or error bodies). The server reply text is
            // deliberately not echoed: it is attacker-influenced and could
            // carry reflected credential material. Log/return `code()` instead.
            Error::AuthFailed(_) => write!(
                f,
                "NNTP authentication failed: {PROVIDER_AUTH_EXPIRED_CODE}"
            ),
            Error::NoPermission(_) => write!(f, "NNTP permission denied: <redacted>"),
            Error::ArticleNotFound(id) => write!(f, "article not found: {id}"),
            Error::Malformed(r) => write!(f, "malformed input: {r}"),
            Error::CrcMismatch {
                message_id,
                want,
                got,
            } => write!(
                f,
                "yEnc CRC32 mismatch for segment {message_id}: want {want:08x} got {got:08x}"
            ),
            Error::Bounds { bound, limit } => {
                write!(f, "NZB/PAR2 {bound} exceeds the hard limit of {limit}")
            }
            Error::Decrypt(r) => write!(f, "decrypt: {r}"),
            Error::Par2Unhealthy { filename, detail } => {
                write!(f, "par2 verify failed for {filename}: {detail}")
            }
            Error::UnsupportedOnWasm(op) => {
                write!(f, "{op} is only available on native targets")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
