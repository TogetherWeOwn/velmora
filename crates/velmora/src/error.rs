//! Crate-wide error type.

use std::{fmt, io};

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Every failure this crate can report. Transport I/O surfaces as
/// [`Error::Io`]; NNTP protocol failures carry their numeric reply code.
#[derive(Debug)]
pub enum Error {
    /// Underlying transport I/O failure (includes timeouts, which each
    /// transport implementation enforces and reports as [`io::ErrorKind::TimedOut`]).
    Io(io::Error),
    /// Unexpected NNTP reply: (numeric code, human-readable text).
    NntpReply { code: u16, text: String },
    /// Server rejected our credentials (`481`/`482`) or demands auth first.
    AuthFailed(String),
    /// Server refused the command (`502`: no permission / access denied).
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "transport I/O: {e}"),
            Error::NntpReply { code, text } => write!(f, "NNTP reply {code}: {text}"),
            Error::AuthFailed(t) => write!(f, "NNTP authentication failed: {t}"),
            Error::NoPermission(t) => write!(f, "NNTP permission denied: {t}"),
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
