//! Incremental S3 checksums: the one algorithm a request asked for.
//!
//! CRC-32C and CRC-64/NVME are reflected, table-driven CRCs with an
//! all-ones initial value and final XOR, as S3 and the AWS SDKs compute
//! them. Values are the big-endian bytes of the CRC, base64-encoded on the
//! wire.

use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::ChecksumAlgorithm;

const fn table32(poly: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 { (c >> 1) ^ poly } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

const fn table64(poly: u64) -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 { (c >> 1) ^ poly } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

/// CRC-32C (Castagnoli), reflected polynomial.
static CRC32C: [u32; 256] = table32(0x82F6_3B78);
/// CRC-64/NVME, reflected polynomial.
static CRC64NVME: [u64; 256] = table64(0x9A6C_9329_AC4B_C9B5);

/// The running state of one checksum.
pub(crate) enum Running {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Crc64Nvme(u64),
    Sha1(Sha1),
    Sha256(Sha256),
}

impl Running {
    pub(crate) fn new(algorithm: ChecksumAlgorithm) -> Self {
        match algorithm {
            ChecksumAlgorithm::Crc32 => Self::Crc32(crc32fast::Hasher::new()),
            ChecksumAlgorithm::Crc32c => Self::Crc32c(!0),
            ChecksumAlgorithm::Crc64Nvme => Self::Crc64Nvme(!0),
            ChecksumAlgorithm::Sha1 => Self::Sha1(Sha1::new()),
            ChecksumAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(bytes),
            Self::Crc32c(c) => {
                for b in bytes {
                    *c = CRC32C[((*c ^ u32::from(*b)) & 0xff) as usize] ^ (*c >> 8);
                }
            }
            Self::Crc64Nvme(c) => {
                for b in bytes {
                    *c = CRC64NVME[((*c ^ u64::from(*b)) & 0xff) as usize] ^ (*c >> 8);
                }
            }
            Self::Sha1(h) => h.update(bytes),
            Self::Sha256(h) => h.update(bytes),
        }
    }

    /// The raw digest bytes (CRCs big-endian).
    pub(crate) fn finish(self) -> Vec<u8> {
        match self {
            Self::Crc32(h) => h.finalize().to_be_bytes().to_vec(),
            Self::Crc32c(c) => (!c).to_be_bytes().to_vec(),
            Self::Crc64Nvme(c) => (!c).to_be_bytes().to_vec(),
            Self::Sha1(h) => h.finalize().to_vec(),
            Self::Sha256(h) => h.finalize().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn digest(algorithm: ChecksumAlgorithm, parts: &[&[u8]]) -> Vec<u8> {
        let mut r = Running::new(algorithm);
        for p in parts {
            r.update(p);
        }
        r.finish()
    }

    #[test]
    fn crc_check_values() {
        // The catalogue "check" value of each CRC: the CRC of "123456789".
        let check = b"123456789";
        assert_eq!(
            digest(ChecksumAlgorithm::Crc32, &[check]),
            0xCBF4_3926u32.to_be_bytes()
        );
        assert_eq!(
            digest(ChecksumAlgorithm::Crc32c, &[check]),
            0xE306_9283u32.to_be_bytes()
        );
        assert_eq!(
            digest(ChecksumAlgorithm::Crc64Nvme, &[check]),
            0xAE8B_1486_0A79_9888u64.to_be_bytes()
        );
    }

    #[test]
    fn values_match_aws_clients() {
        // CRC64NVME header aws-cli 2.31.23 sent for this body.
        let body: &[u8] = b"hello world, this is a test body\n";
        assert_eq!(
            STANDARD.encode(digest(
                ChecksumAlgorithm::Crc64Nvme,
                &[&body[..5], &body[5..]]
            )),
            "bgGah9vCkZ4="
        );
        // CRC32C trailer of the AWS signed-trailer example (66560 x 'a').
        let a = vec![b'a'; 66560];
        assert_eq!(
            STANDARD.encode(digest(ChecksumAlgorithm::Crc32c, &[&a])),
            "sOO8/Q=="
        );
        assert_eq!(
            STANDARD.encode(digest(ChecksumAlgorithm::Sha1, &[b"abc"])),
            "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
        );
    }
}
