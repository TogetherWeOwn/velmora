// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/mod.rs. License: MIT.
// Copied verbatim except: removed line 9 `pub mod archive;` (the archive module is not copied); this header.
// Re-typed for S3 STANDARD semantics: the cold-archive restore module, its error codes,
// limits and `Policy::restore` are removed; `storage_class` stores every class it
// accepts as STANDARD and refuses the archive classes;
// the `listing` module is added; `xml` also maps U+FFFE/U+FFFF to U+FFFD;
// the `checksum` and `chunked` (aws-chunked) modules are added.

//! Restricted archive S3 wire primitives, not an HTTP service or an IAM implementation.
//!
//! Adapters must preserve the raw origin-form request target and header order,
//! establish TLS themselves, authenticate before catalogue lookup, and recheck
//! authorization at mutation/publication/serving boundaries. Only fully validated
//! decoded upload bytes may enter the retained-cache commit. These types neither
//! prove encryption nor grant a durable commit.

mod auth;
mod checksum;
pub mod chunked;
mod civil;
pub mod listing;
pub mod multipart_listing;
pub mod mutation;
mod read;
pub mod sign;
mod upload;
mod wire;

pub use auth::{verify, AuthMode, Authority, Credential, VerifiedRequest, SINGLE_VALUE_HEADERS};
pub use read::{plan_read, ByteRange, Conditions, ObjectMetadata, ReadPlan, StoredChecksum};
pub use upload::{is_aws_chunked, ChecksumAlgorithm, DecodedUpload, UploadValidator};
pub use wire::{
    canonical_request, storable_key, HeaderRefusal, Headers, Target, IGNORED_HEADERS, MAX_KEY_BYTES,
};

pub type Result<T> = std::result::Result<T, ErrorCode>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    AccessDenied,
    /// The access key id names no usable key: unknown, disabled or
    /// revoked. Says nothing of buckets or objects.
    InvalidAccessKeyId,
    SignatureDoesNotMatch,
    RequestTimeTooSkewed,
    /// The `Authorization` header names a region this endpoint does not
    /// answer for. Says only what the endpoint is configured with.
    AuthorizationHeaderMalformed,
    /// The same for the credential of a presigned URL.
    AuthorizationQueryParametersError,
    /// `x-amz-storage-class` names a class that is not offered.
    InvalidStorageClass,
    /// An ACL that would grant access (`x-amz-acl`, `x-amz-grant-*`).
    AccessControlListNotSupported,
    InvalidRequest,
    InvalidArgument,
    InvalidDigest,
    BadDigest,
    IncompleteBody,
    EntityTooLarge,
    MalformedXML,
    PreconditionFailed,
    InvalidRange,
    NoSuchBucket,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    NoSuchKey,
    NoSuchUpload,
    InvalidPart,
    InvalidPartOrder,
    EntityTooSmall,
    ConditionalRequestConflict,
    NotImplemented,
    SlowDown,
    InternalError,
}

impl ErrorCode {
    pub fn status(self) -> u16 {
        match self {
            Self::AccessDenied
            | Self::InvalidAccessKeyId
            | Self::SignatureDoesNotMatch
            | Self::RequestTimeTooSkewed => 403,
            Self::PreconditionFailed => 412,
            Self::InvalidRange => 416,
            Self::NoSuchBucket | Self::NoSuchKey | Self::NoSuchUpload => 404,
            Self::BucketAlreadyOwnedByYou
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
            '\u{fffe}' | '\u{ffff}' => "\u{fffd}".into(),
            c if c == '\t' || c == '\n' || c >= ' ' => c.to_string(),
            _ => "\u{fffd}".into(),
        })
        .collect()
}

pub(crate) fn xml_response(body: String) -> Response {
    Response {
        status: 200,
        headers: vec![("content-type".into(), "application/xml".into())],
        body: body.into_bytes(),
    }
}

/// ISO 8601 with milliseconds, as S3 renders `LastModified` and `CreationDate`.
pub(crate) fn iso_date_ms(unix_ms: i64) -> Result<String> {
    civil::iso_ms(unix_ms).ok_or(ErrorCode::InternalError)
}

/// No Default: production numbers must be explicitly selected and validated.
#[derive(Clone, Debug)]
pub struct Policy {
    pub(crate) limits: Limits,
    pub(crate) host: String,
    pub(crate) region: String,
    /// Other regions a credential scope may name, see
    /// [`Policy::with_region_aliases`].
    pub(crate) region_aliases: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub target_bytes: usize,
    pub control_xml_bytes: usize,
    pub header_bytes: usize,
    pub header_count: usize,
    pub query_pairs: usize,
    pub upload_bytes: u64,
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
            region_aliases: Vec::new(),
        })
    }

    /// Also accepts a credential scope that names one of `aliases` in
    /// place of the configured region. The signature is then checked
    /// with the region the client named: the client derived its signing
    /// key from that name, and the name is all a region is here (one
    /// endpoint, no per-region data). The signed `host` still binds the
    /// request to this endpoint, so a request signed for another service
    /// that shares the alias cannot be replayed here.
    pub fn with_region_aliases(mut self, aliases: &[&str]) -> Result<Self> {
        if aliases
            .iter()
            .any(|a| a.is_empty() || !a.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
        {
            return Err(ErrorCode::InvalidArgument);
        }
        self.region_aliases = aliases.iter().map(|a| (*a).to_owned()).collect();
        Ok(self)
    }

    /// The configured region: what a refused scope is told to use.
    pub fn region(&self) -> &str {
        &self.region
    }

    pub(crate) fn accepts_region(&self, region: &str) -> bool {
        region == self.region || self.region_aliases.iter().any(|a| a == region)
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

/// The class an object is stored and reported as, for the class a
/// request names. Only STANDARD is offered.
///
/// The classes S3 reads synchronously (`STANDARD_IA`, `ONEZONE_IA`,
/// `INTELLIGENT_TIERING`, `GLACIER_IR`, `REDUCED_REDUNDANCY`) are accepted
/// and stored as STANDARD. They differ from STANDARD only in price and
/// placement, which a client cannot observe through the API: every call
/// behaves as it does at S3, and the object is honestly reported as
/// STANDARD by HEAD, GET and the listings. Backup tools ship presets
/// with these classes, and S3 itself accepts them, so refusing them
/// would fail a request that S3 serves.
///
/// The archive classes (`GLACIER`, `DEEP_ARCHIVE`) are refused with
/// `InvalidStorageClass`: a client that picks one expects GET to fail
/// until `RestoreObject`, which is not offered. Anything else is not a
/// class this service knows, and S3 answers `InvalidStorageClass` to an
/// unknown class too.
pub fn storage_class(value: Option<&str>) -> Result<&'static str> {
    match value {
        None
        | Some(
            "STANDARD"
            | "STANDARD_IA"
            | "ONEZONE_IA"
            | "INTELLIGENT_TIERING"
            | "GLACIER_IR"
            | "REDUCED_REDUNDANCY",
        ) => Ok("STANDARD"),
        _ => Err(ErrorCode::InvalidStorageClass),
    }
}
