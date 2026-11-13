// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/upload.rs. License: MIT.
// Copied verbatim except: this header only.

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{decimal, unhex, ErrorCode, Headers, Policy, Result, VerifiedRequest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumAlgorithm {
    Sha256,
    Crc32,
}

impl ChecksumAlgorithm {
    pub fn header(self) -> &'static str {
        match self {
            Self::Sha256 => "x-amz-checksum-sha256",
            Self::Crc32 => "x-amz-checksum-crc32",
        }
    }
    pub(crate) fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Crc32 => 4,
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

/// Incremental verification over decoded C only. No durable mutation or allocation
/// happens here. An adapter may stage bytes, but must not publish/commit them
/// until finish succeeds; drop/error must discard the staging object.
///
/// Initial qualified framing is Content-Length with optional metadata encoding.
/// All transfer-encoding, aws-chunked and trailers are explicitly unsupported,
/// not mistaken for encrypted object bytes. This is NOT default streaming-client
/// compatibility. An HTTP adapter must enforce identical framing at ingress.
pub struct UploadValidator {
    expected_length: u64,
    length: u64,
    sha256: Sha256,
    md5: md5::Context,
    crc32: crc32fast::Hasher,
    payload: Option<Vec<u8>>,
    content_md5: Option<Vec<u8>>,
    checksum: Option<(ChecksumAlgorithm, Vec<u8>)>,
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

impl UploadValidator {
    pub fn new(headers: &Headers, verified: &VerifiedRequest, policy: &Policy) -> Result<Self> {
        headers.validate_features()?;
        if headers.get("transfer-encoding").is_some()
            || headers.get("trailer").is_some()
            || headers.get("content-encoding").is_some_and(|v| {
                v.split(',')
                    .any(|e| e.trim().eq_ignore_ascii_case("aws-chunked"))
            })
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let expected_length = decimal(
            headers
                .get("content-length")
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
        for algorithm in [ChecksumAlgorithm::Sha256, ChecksumAlgorithm::Crc32] {
            if let Some(value) = headers.get(algorithm.header()) {
                if checksum.is_some() {
                    return Err(ErrorCode::InvalidRequest);
                }
                checksum = Some((algorithm, digest_value(value, algorithm.size())?));
            }
        }
        if let Some(requested) = headers
            .get("x-amz-checksum-algorithm")
            .or_else(|| headers.get("x-amz-sdk-checksum-algorithm"))
        {
            let expected = match requested {
                "SHA256" => ChecksumAlgorithm::Sha256,
                "CRC32" => ChecksumAlgorithm::Crc32,
                _ => return Err(ErrorCode::InvalidRequest),
            };
            if checksum.as_ref().map(|(a, _)| *a) != Some(expected) {
                return Err(ErrorCode::InvalidRequest);
            }
        }
        if headers.get("x-amz-checksum-type").is_some() && checksum.is_none() {
            return Err(ErrorCode::InvalidRequest);
        }
        let payload = if verified.payload_hash() == "UNSIGNED-PAYLOAD" {
            None
        } else {
            Some(unhex(verified.payload_hash())?)
        };
        Ok(Self {
            expected_length,
            length: 0,
            sha256: Sha256::new(),
            md5: md5::Context::new(),
            crc32: crc32fast::Hasher::new(),
            payload,
            content_md5,
            checksum,
            failed: false,
        })
    }

    pub fn push_decoded(&mut self, bytes: &[u8]) -> Result<()> {
        let length = self.length.checked_add(bytes.len() as u64);
        if self.failed || length.is_none_or(|n| n > self.expected_length) {
            self.failed = true;
            return Err(ErrorCode::InvalidRequest);
        }
        self.length = length.ok_or(ErrorCode::InvalidRequest)?;
        self.sha256.update(bytes);
        self.md5.consume(bytes);
        self.crc32.update(bytes);
        Ok(())
    }

    pub fn finish(self) -> Result<DecodedUpload> {
        if self.failed {
            return Err(ErrorCode::InvalidRequest);
        }
        if self.length != self.expected_length {
            return Err(ErrorCode::IncompleteBody);
        }
        let sha256: [u8; 32] = self.sha256.finalize().into();
        let md5 = self.md5.finalize().0;
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
        let checksum = if let Some((algorithm, expected)) = self.checksum {
            let actual = match algorithm {
                ChecksumAlgorithm::Sha256 => sha256.to_vec(),
                ChecksumAlgorithm::Crc32 => self.crc32.finalize().to_be_bytes().to_vec(),
            };
            if !bool::from(expected.ct_eq(&actual)) {
                return Err(ErrorCode::BadDigest);
            }
            Some((algorithm, STANDARD.encode(actual)))
        } else {
            None
        };
        Ok(DecodedUpload {
            length: self.length,
            sha256,
            checksum,
        })
    }
}
