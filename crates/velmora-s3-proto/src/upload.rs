// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/upload.rs. License: MIT.
// Changed (not from qerith): the CRC32C, CRC64NVME and SHA1 algorithms, the
// aws-chunked framing (`push_body`, trailing checksums) and the
// `decoded_length`/`chunked` accessors.

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::checksum::Running;
use super::chunked::{ChunkedDecoder, Streaming};
use super::{decimal, unhex, ErrorCode, Headers, Policy, Result, VerifiedRequest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumAlgorithm {
    Sha256,
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
}

impl ChecksumAlgorithm {
    pub const ALL: [Self; 5] = [
        Self::Sha256,
        Self::Crc32,
        Self::Crc32c,
        Self::Crc64Nvme,
        Self::Sha1,
    ];

    pub fn header(self) -> &'static str {
        match self {
            Self::Sha256 => "x-amz-checksum-sha256",
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
        }
    }

    /// The `x-amz-checksum-algorithm` value and the XML name suffix
    /// (`Checksum<NAME>`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA256",
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Crc64Nvme => "CRC64NVME",
            Self::Sha1 => "SHA1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == name)
    }

    pub(crate) fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Crc32 | Self::Crc32c => 4,
            Self::Crc64Nvme => 8,
            Self::Sha1 => 20,
        }
    }
}

pub(crate) fn digest_value(value: &str, size: usize) -> Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| ErrorCode::InvalidDigest)?;
    if bytes.len() != size || STANDARD.encode(&bytes) != value {
        return Err(ErrorCode::InvalidDigest);
    }
    Ok(bytes)
}

/// Running digests over the decoded body.
struct Digests {
    expected_length: u64,
    length: u64,
    sha256: Sha256,
    md5: md5::Context,
    checksum: Option<Running>,
}

impl Digests {
    fn update(&mut self, bytes: &[u8]) -> Result<()> {
        let length = self.length.checked_add(bytes.len() as u64);
        if length.is_none_or(|n| n > self.expected_length) {
            return Err(ErrorCode::InvalidRequest);
        }
        self.length = length.ok_or(ErrorCode::InvalidRequest)?;
        self.sha256.update(bytes);
        self.md5.consume(bytes);
        if let Some(c) = &mut self.checksum {
            c.update(bytes);
        }
        Ok(())
    }
}

/// Incremental verification over decoded C only. No durable mutation or allocation
/// happens here. An adapter may stage bytes, but must not publish/commit them
/// until finish succeeds; drop/error must discard the staging object.
///
/// Framing is either identity (`Content-Length` bytes, fed through
/// [`UploadValidator::push_decoded`] or [`UploadValidator::push_body`]) or
/// `aws-chunked`, selected by the signed `x-amz-content-sha256` `STREAMING-*`
/// value together with `Content-Encoding: aws-chunked` (fed through
/// [`UploadValidator::push_body`] only). The length limit and every digest
/// apply to the decoded bytes; for aws-chunked the length is
/// `x-amz-decoded-content-length`. HTTP `Transfer-Encoding: chunked` is
/// accepted only under aws-chunked (the runtime has removed it); HTTP
/// trailers are not.
pub struct UploadValidator {
    digests: Digests,
    payload: Option<Vec<u8>>,
    content_md5: Option<Vec<u8>>,
    checksum: Option<(ChecksumAlgorithm, Vec<u8>)>,
    decoder: Option<ChunkedDecoder>,
    failed: bool,
}

/// A validation receipt, not proof of encryption, durability or archival success.
#[derive(Clone, Debug)]
pub struct DecodedUpload {
    length: u64,
    sha256: [u8; 32],
    checksum: Option<(ChecksumAlgorithm, String)>,
}

impl DecodedUpload {
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn checksum(&self) -> Option<&(ChecksumAlgorithm, String)> {
        self.checksum.as_ref()
    }
}

/// `true` when a `Content-Encoding` value lists the `aws-chunked` coding.
pub fn is_aws_chunked(content_encoding: &str) -> bool {
    content_encoding
        .split(',')
        .any(|e| e.trim().eq_ignore_ascii_case("aws-chunked"))
}

impl UploadValidator {
    pub fn new(headers: &Headers, verified: &VerifiedRequest, policy: &Policy) -> Result<Self> {
        headers.validate_features()?;
        let streaming = verified.streaming();
        let aws_chunked = headers.get("content-encoding").is_some_and(is_aws_chunked);
        if aws_chunked != streaming.is_some()
            || headers.get("trailer").is_some()
            || headers
                .get("transfer-encoding")
                .is_some_and(|v| streaming.is_none() || !v.eq_ignore_ascii_case("chunked"))
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let length_header = if streaming.is_some() {
            if let Some(encoded) = headers.get("content-length") {
                decimal(encoded)?;
            }
            "x-amz-decoded-content-length"
        } else {
            if headers.get("x-amz-decoded-content-length").is_some() {
                return Err(ErrorCode::InvalidRequest);
            }
            "content-length"
        };
        let expected_length = decimal(
            headers
                .get(length_header)
                .ok_or(ErrorCode::InvalidRequest)?,
        )?;
        if expected_length > policy.limits.upload_bytes {
            return Err(ErrorCode::EntityTooLarge);
        }
        if headers
            .get("x-amz-checksum-type")
            .is_some_and(|v| v != "FULL_OBJECT")
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let content_md5 = headers
            .get("content-md5")
            .map(|v| digest_value(v, 16))
            .transpose()?;
        let mut checksum = None;
        for algorithm in ChecksumAlgorithm::ALL {
            if let Some(value) = headers.get(algorithm.header()) {
                if checksum.is_some() {
                    return Err(ErrorCode::InvalidRequest);
                }
                checksum = Some((algorithm, digest_value(value, algorithm.size())?));
            }
        }
        let trailer = match headers.get("x-amz-trailer") {
            None => None,
            Some(name) => {
                let algorithm = ChecksumAlgorithm::ALL
                    .into_iter()
                    .find(|a| a.header() == name)
                    .ok_or(ErrorCode::InvalidRequest)?;
                if !streaming.is_some_and(Streaming::trailer) || checksum.is_some() {
                    return Err(ErrorCode::InvalidRequest);
                }
                Some(algorithm)
            }
        };
        let algorithm = checksum.as_ref().map(|(a, _)| *a).or(trailer);
        if let Some(requested) = headers
            .get("x-amz-checksum-algorithm")
            .or_else(|| headers.get("x-amz-sdk-checksum-algorithm"))
        {
            if algorithm != ChecksumAlgorithm::from_name(requested) {
                return Err(ErrorCode::InvalidRequest);
            }
        }
        if headers.get("x-amz-checksum-type").is_some() && algorithm.is_none() {
            return Err(ErrorCode::InvalidRequest);
        }
        let payload = if streaming.is_some() || verified.payload_hash() == "UNSIGNED-PAYLOAD" {
            None
        } else {
            Some(unhex(verified.payload_hash())?)
        };
        let decoder = streaming
            .map(|mode| {
                ChunkedDecoder::new(
                    mode,
                    verified.streaming_seed().cloned(),
                    trailer,
                    expected_length,
                )
            })
            .transpose()?;
        Ok(Self {
            digests: Digests {
                expected_length,
                length: 0,
                sha256: Sha256::new(),
                md5: md5::Context::new(),
                checksum: algorithm.map(Running::new),
            },
            payload,
            content_md5,
            checksum,
            decoder,
            failed: false,
        })
    }

    /// The decoded body length the request declared and the limit applied to.
    pub fn decoded_length(&self) -> u64 {
        self.digests.expected_length
    }

    /// `true` when the body is aws-chunked encoded.
    pub fn chunked(&self) -> bool {
        self.decoder.is_some()
    }

    /// Feeds decoded bytes of an identity-framed body.
    pub fn push_decoded(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed || self.decoder.is_some() {
            self.failed = true;
            return Err(ErrorCode::InvalidRequest);
        }
        let result = self.digests.update(bytes);
        self.failed = result.is_err();
        result
    }

    /// Feeds the next piece of the body as received, in either framing.
    /// Decoded bytes go to `sink` as they are validated; nothing encoded
    /// is retained beyond one bounded chunk-header or trailer line.
    pub fn push_body(&mut self, bytes: &[u8], sink: &mut dyn FnMut(&[u8])) -> Result<()> {
        if self.failed {
            return Err(ErrorCode::InvalidRequest);
        }
        let digests = &mut self.digests;
        let result = match &mut self.decoder {
            None => digests.update(bytes).map(|()| sink(bytes)),
            Some(decoder) => decoder.push(bytes, &mut |decoded| {
                digests.update(decoded)?;
                sink(decoded);
                Ok(())
            }),
        };
        self.failed = result.is_err();
        result
    }

    pub fn finish(self) -> Result<DecodedUpload> {
        if self.failed {
            return Err(ErrorCode::InvalidRequest);
        }
        let trailer = self
            .decoder
            .map(ChunkedDecoder::finish)
            .transpose()?
            .flatten();
        let digests = self.digests;
        if digests.length != digests.expected_length {
            return Err(ErrorCode::IncompleteBody);
        }
        let sha256: [u8; 32] = digests.sha256.finalize().into();
        let md5 = digests.md5.finalize().0;
        if self
            .payload
            .as_ref()
            .is_some_and(|p| !bool::from(p.as_slice().ct_eq(&sha256)))
            || self
                .content_md5
                .as_ref()
                .is_some_and(|p| !bool::from(p.as_slice().ct_eq(&md5)))
        {
            return Err(ErrorCode::BadDigest);
        }
        let expected = match (self.checksum, trailer) {
            (Some(header), _) => Some(header),
            (None, Some(t)) => Some((t.algorithm, digest_value(&t.value, t.algorithm.size())?)),
            (None, None) => None,
        };
        let checksum = match (expected, digests.checksum) {
            (Some((algorithm, expected)), Some(running)) => {
                let actual = running.finish();
                if !bool::from(expected.ct_eq(&actual)) {
                    return Err(ErrorCode::BadDigest);
                }
                Some((algorithm, STANDARD.encode(actual)))
            }
            (None, _) => None,
            (Some(_), None) => return Err(ErrorCode::InternalError),
        };
        Ok(DecodedUpload {
            length: digests.length,
            sha256,
            checksum,
        })
    }
}
