// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/read.rs. License: MIT.
// Copied verbatim except: this header; for S3 STANDARD semantics `plan_read` loses its
// `available` parameter and the `!available -> InvalidObjectState` branch, emits
// `x-amz-storage-class: STANDARD`, and two doc comments drop cold-archive wording;
// `StoredChecksum::algorithm()` is added for the commit renderers.

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use super::{decimal, upload::digest_value, ChecksumAlgorithm, ErrorCode, Headers, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredChecksum {
    algorithm: ChecksumAlgorithm,
    value: String,
    parts: Vec<String>,
    composite: bool,
}

impl StoredChecksum {
    pub fn full(algorithm: ChecksumAlgorithm, value: String) -> Result<Self> {
        Self::full_with_parts(algorithm, value, Vec::new())
    }

    /// FULL_OBJECT may retain ordered multipart evidence without becoming a
    /// composite checksum. Full-C verification belongs to the commit boundary;
    /// part digests alone cannot reconstruct the SHA256 of the complete body.
    pub fn full_with_parts(
        algorithm: ChecksumAlgorithm,
        value: String,
        parts: Vec<String>,
    ) -> Result<Self> {
        digest_value(&value, algorithm.size())?;
        if parts.len() > 10_000 {
            return Err(ErrorCode::InvalidDigest);
        }
        for part in &parts {
            digest_value(part, algorithm.size())?;
        }
        Ok(Self {
            algorithm,
            value,
            parts,
            composite: false,
        })
    }

    /// SHA256 COMPOSITE is SHA256 of binary part digests, with the part-count
    /// suffix, NOT SHA256(C). CRC32 COMPOSITE is deliberately not qualified.
    /// Part evidence must be stored with the same immutable generation.
    pub fn composite_sha256(parts: Vec<String>) -> Result<Self> {
        if parts.is_empty() {
            return Err(ErrorCode::InvalidDigest);
        }
        let mut digest = Sha256::new();
        for value in &parts {
            digest.update(digest_value(value, 32)?);
        }
        let value = format!("{}-{}", STANDARD.encode(digest.finalize()), parts.len());
        Ok(Self {
            algorithm: ChecksumAlgorithm::Sha256,
            value,
            parts,
            composite: true,
        })
    }

    pub fn algorithm(&self) -> ChecksumAlgorithm {
        self.algorithm
    }
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn parts(&self) -> &[String] {
        &self.parts
    }
    pub fn checksum_type(&self) -> &'static str {
        if self.composite {
            "COMPOSITE"
        } else {
            "FULL_OBJECT"
        }
    }
}

/// Persist verbatim with G. Reads must not regenerate ETags or last-modified.
/// This is a reference value type, not a durable catalogue implementation.
#[derive(Clone, Debug)]
pub struct ObjectMetadata {
    generation: String,
    length: u64,
    etag: String,
    modified: i64,
    content_headers: Vec<(String, String)>,
    checksum: Option<StoredChecksum>,
}

impl ObjectMetadata {
    pub fn new(
        generation: String,
        length: u64,
        etag: String,
        modified: i64,
        content_headers: Vec<(String, String)>,
        checksum: Option<StoredChecksum>,
    ) -> Result<Self> {
        if generation.is_empty()
            || !valid_tag(&etag)
            || DateTime::from_timestamp(modified, 0).is_none()
            || content_headers.iter().any(|(k, v)| {
                !super::wire::persistent_metadata(k)
                    || !super::wire::valid_header_name(k)
                    || k.bytes().any(|c| c.is_ascii_uppercase())
                    || !super::wire::valid_header_value(v)
            })
        {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(Self {
            generation,
            length,
            etag,
            modified,
            content_headers,
            checksum,
        })
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn etag(&self) -> &str {
        &self.etag
    }
}

#[derive(Clone, Debug, Default)]
pub struct Conditions {
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
    pub if_modified_since: Option<String>,
    pub if_unmodified_since: Option<String>,
}

impl Conditions {
    pub fn from_headers(headers: &Headers) -> Self {
        Self {
            if_match: headers.get("if-match").map(str::to_owned),
            if_none_match: headers.get("if-none-match").map(str::to_owned),
            if_modified_since: headers.get("if-modified-since").map(str::to_owned),
            if_unmodified_since: headers.get("if-unmodified-since").map(str::to_owned),
        }
    }

    pub(super) fn evaluate(&self, metadata: &ObjectMetadata) -> Result<bool> {
        if let Some(tags) = &self.if_match {
            if !matches_tag(tags, &metadata.etag, false)? {
                return Err(ErrorCode::PreconditionFailed);
            }
        } else if self
            .if_unmodified_since
            .as_deref()
            .and_then(http_date)
            .is_some_and(|t| metadata.modified > t)
        {
            return Err(ErrorCode::PreconditionFailed);
        }
        if let Some(tags) = &self.if_none_match {
            if matches_tag(tags, &metadata.etag, true)? {
                return Ok(false);
            }
        } else if self
            .if_modified_since
            .as_deref()
            .and_then(http_date)
            .is_some_and(|t| metadata.modified <= t)
        {
            return Ok(false);
        }
        Ok(true)
    }
}

fn valid_tag(tag: &str) -> bool {
    tag.len() >= 2
        && tag.starts_with('"')
        && tag.ends_with('"')
        && tag.as_bytes()[1..tag.len() - 1]
            .iter()
            .all(|c| *c == 0x21 || (0x23..=0x7e).contains(c))
}

fn matches_tag(list: &str, etag: &str, weak: bool) -> Result<bool> {
    if list.trim() == "*" {
        return Ok(true);
    }
    let mut rest = list.trim();
    let mut found = false;
    loop {
        let is_weak = rest.starts_with("W/");
        let tag = if is_weak { &rest[2..] } else { rest };
        if !tag.starts_with('"') {
            return Err(ErrorCode::InvalidRequest);
        }
        let end = tag[1..].find('"').ok_or(ErrorCode::InvalidRequest)? + 2;
        let current = &tag[..end];
        if !valid_tag(current) {
            return Err(ErrorCode::InvalidRequest);
        }
        found |= (weak || !is_weak) && current == etag;
        rest = tag[end..].trim_start();
        if rest.is_empty() {
            break;
        }
        rest = rest
            .strip_prefix(',')
            .ok_or(ErrorCode::InvalidRequest)?
            .trim_start();
        if rest.is_empty() {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    Ok(found)
}

fn http_date(value: &str) -> Option<i64> {
    if let Ok(parsed) = httpdate::parse_http_date(value) {
        let seconds = parsed.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        return i64::try_from(seconds).ok();
    }
    // httpdate 1.0.3 rejects years before 1970 before producing SystemTime.
    // Use the existing calendar parser for the four-digit pre-epoch forms;
    // round-trip to retain the HTTP grammar, weekday and non-leap-second rules.
    let value = value.trim();
    [
        ("%a, %d %b %Y %H:%M:%S GMT", 29, 12..16),
        ("%a %b %e %H:%M:%S %Y", 24, 20..24),
    ]
    .into_iter()
    .find_map(|(format, length, year)| {
        if value.len() != length || !value.as_bytes().get(year)?.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let parsed = chrono::NaiveDateTime::parse_from_str(value, format).ok()?;
        let utc = parsed.and_utc();
        (utc.timestamp() < 0
            && utc.timestamp_subsec_nanos() == 0
            && parsed.format(format).to_string() == value)
            .then_some(utc.timestamp())
    })
}

fn format_date(value: i64) -> String {
    DateTime::<Utc>::from_timestamp(value, 0)
        .expect("metadata timestamp validated")
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn parse(value: &str, length: u64) -> Result<Self> {
        if value.contains(',') {
            return Err(ErrorCode::InvalidRequest);
        }
        let value = value
            .strip_prefix("bytes=")
            .ok_or(ErrorCode::InvalidRange)?;
        let (start, end) = value.split_once('-').ok_or(ErrorCode::InvalidRange)?;
        let number = |v| decimal(v).map_err(|_| ErrorCode::InvalidRange);
        if length == 0 {
            return Err(ErrorCode::InvalidRange);
        }
        if start.is_empty() {
            let suffix = number(end)?;
            if suffix == 0 {
                return Err(ErrorCode::InvalidRange);
            }
            return Ok(Self {
                start: length.saturating_sub(suffix),
                end: length - 1,
            });
        }
        let start = number(start)?;
        let end = if end.is_empty() {
            length - 1
        } else {
            number(end)?
        };
        if start >= length || end < start {
            return Err(ErrorCode::InvalidRange);
        }
        Ok(Self {
            start,
            end: end.min(length - 1),
        })
    }
    pub fn length(self) -> u64 {
        self.end - self.start + 1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadPlan {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// None for HEAD and 304. Adapter reads exactly this slice from pinned G.
    pub body: Option<ByteRange>,
}

/// Call only after authentication/authorization and resolving the exact G.
/// Preconditions and range validation precede any body fetch. HEAD never
/// downloads.
pub fn plan_read(
    metadata: &ObjectMetadata,
    head: bool,
    conditions: &Conditions,
    range: Option<&str>,
    checksum_mode: bool,
) -> Result<ReadPlan> {
    if !conditions.evaluate(metadata)? {
        let mut headers: Vec<_> = metadata
            .content_headers
            .iter()
            .filter(|(k, _)| matches!(k.as_str(), "cache-control" | "expires"))
            .cloned()
            .collect();
        headers.extend([
            ("etag".into(), metadata.etag.clone()),
            ("last-modified".into(), format_date(metadata.modified)),
        ]);
        return Ok(ReadPlan {
            status: 304,
            headers,
            body: None,
        });
    }
    let range = range
        .map(|v| ByteRange::parse(v, metadata.length))
        .transpose()?;
    let length = range.map_or(metadata.length, ByteRange::length);
    let mut headers = metadata.content_headers.clone();
    headers.extend([
        ("content-length".into(), length.to_string()),
        ("etag".into(), metadata.etag.clone()),
        ("last-modified".into(), format_date(metadata.modified)),
        ("x-amz-storage-class".into(), "STANDARD".into()),
        ("accept-ranges".into(), "bytes".into()),
    ]);
    if let Some(r) = range {
        if !head {
            headers.push((
                "content-range".into(),
                format!("bytes {}-{}/{}", r.start, r.end, metadata.length),
            ));
        }
    } else if checksum_mode {
        if let Some(checksum) = &metadata.checksum {
            headers.extend([
                (checksum.algorithm.header().into(), checksum.value.clone()),
                (
                    "x-amz-checksum-type".into(),
                    checksum.checksum_type().into(),
                ),
            ]);
        }
    }
    Ok(ReadPlan {
        status: if !head && range.is_some() { 206 } else { 200 },
        headers,
        body: if head || metadata.length == 0 {
            None
        } else {
            Some(range.unwrap_or(ByteRange {
                start: 0,
                end: metadata.length - 1,
            }))
        },
    })
}
