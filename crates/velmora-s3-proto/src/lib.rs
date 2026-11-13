// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/mod.rs. License: MIT.
// Copied verbatim except: removed line 9 `pub mod archive;` (the archive module is not copied); this header.

//! Restricted archive S3 wire primitives, not an HTTP service or an IAM implementation.
//!
//! Adapters must preserve the raw origin-form request target and header order,
//! establish TLS themselves, authenticate before catalogue lookup, and recheck
//! authorization at mutation/publication/serving boundaries. Only fully validated
//! decoded upload bytes may enter the retained-cache commit. These types neither
//! prove encryption nor grant a restore lease or durable commit.

mod auth;
pub mod mutation;
mod read;
mod restore;
mod upload;
mod wire;

pub use auth::{verify, AuthMode, Authority, Credential, VerifiedRequest};
pub use read::{plan_read, ByteRange, Conditions, ObjectMetadata, ReadPlan, StoredChecksum};
pub use restore::{parse_restore, RestoreStatus};
pub use upload::{ChecksumAlgorithm, DecodedUpload, UploadValidator};
pub use wire::{canonical_request, Headers, Target};

pub type Result<T> = std::result::Result<T, ErrorCode>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    AccessDenied,
    SignatureDoesNotMatch,
    RequestTimeTooSkewed,
    InvalidRequest,
    InvalidArgument,
    InvalidDigest,
    BadDigest,
    IncompleteBody,
    EntityTooLarge,
    MalformedXML,
    PreconditionFailed,
    InvalidRange,
    InvalidObjectState,
    NoSuchBucket,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    NoSuchKey,
    NoSuchUpload,
    InvalidPart,
    InvalidPartOrder,
    EntityTooSmall,
    ConditionalRequestConflict,
    RestoreAlreadyInProgress,
    NotImplemented,
    SlowDown,
    InternalError,
}

impl ErrorCode {
    pub fn status(self) -> u16 {
        match self {
            Self::AccessDenied
            | Self::SignatureDoesNotMatch
            | Self::RequestTimeTooSkewed
            | Self::InvalidObjectState => 403,
            Self::PreconditionFailed => 412,
            Self::InvalidRange => 416,
            Self::NoSuchBucket | Self::NoSuchKey | Self::NoSuchUpload => 404,
            Self::RestoreAlreadyInProgress
            | Self::BucketAlreadyOwnedByYou
            | Self::BucketNotEmpty
            | Self::ConditionalRequestConflict => 409,
            Self::NotImplemented => 501,
            Self::SlowDown => 503,
            Self::InternalError => 500,
            _ => 400,
        }
    }

    pub fn response(self, head: bool, request_id: &str) -> Response {
        let body = if head {
            Vec::new()
        } else {
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{self:?}</Code><Message>Request failed</Message><RequestId>{}</RequestId></Error>", xml(request_id)).into_bytes()
        };
        Response {
            status: self.status(),
            headers: vec![("content-type".into(), "application/xml".into())],
            body,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn xml(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&apos;".into(),
            '\r' => "&#13;".into(),
            c if c == '\t' || c == '\n' || c >= ' ' => c.to_string(),
            _ => "\u{fffd}".into(),
        })
        .collect()
}

/// No Default: production numbers must be explicitly selected and validated.
#[derive(Clone, Debug)]
pub struct Policy {
    pub(crate) limits: Limits,
    pub(crate) host: String,
    pub(crate) region: String,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub target_bytes: usize,
    pub control_xml_bytes: usize,
    pub header_bytes: usize,
    pub header_count: usize,
    pub query_pairs: usize,
    pub upload_bytes: u64,
    pub min_restore_days: u32,
    pub max_restore_days: u32,
    pub clock_skew_seconds: u32,
    pub presign_seconds: u32,
}

impl Policy {
    pub fn new(host: String, region: String, limits: Limits) -> Result<Self> {
        if host.is_empty()
            || !host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-:".contains(&c))
            || region.is_empty()
            || !region
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || limits.target_bytes == 0
            || limits.control_xml_bytes == 0
            || limits.header_bytes == 0
            || limits.header_count == 0
            || limits.query_pairs == 0
            || limits.upload_bytes == 0
            || limits.min_restore_days == 0
            || limits.min_restore_days > limits.max_restore_days
            || limits.clock_skew_seconds == 0
            || limits.presign_seconds == 0
            || limits.presign_seconds > 604800
        {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(Self {
            limits,
            host,
            region,
        })
    }

    /// Validate typed restore parameters. Wire callers use parse_restore, which
    /// also rejects unknown XML features before any downstream effects.
    pub fn restore(&self, days: &str, tier: Option<&str>) -> Result<u32> {
        let days = decimal(days).map_err(|_| ErrorCode::InvalidArgument)?;
        if days < u64::from(self.limits.min_restore_days)
            || days > u64::from(self.limits.max_restore_days)
            || !matches!(tier, None | Some("Standard"))
        {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(days as u32)
    }
}

pub(crate) fn decimal(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ErrorCode::InvalidRequest);
    }
    value.parse().map_err(|_| ErrorCode::InvalidRequest)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}

pub(crate) fn unhex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(ErrorCode::InvalidRequest);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let a = (pair[0] as char)
                .to_digit(16)
                .ok_or(ErrorCode::InvalidRequest)?;
            let b = (pair[1] as char)
                .to_digit(16)
                .ok_or(ErrorCode::InvalidRequest)?;
            Ok((a * 16 + b) as u8)
        })
        .collect()
}

/// Archive B never silently maps an unsupported class to STANDARD.
pub fn storage_class(value: Option<&str>) -> Result<&'static str> {
    match value {
        None | Some("GLACIER") => Ok("GLACIER"),
        _ => Err(ErrorCode::InvalidRequest),
    }
}
