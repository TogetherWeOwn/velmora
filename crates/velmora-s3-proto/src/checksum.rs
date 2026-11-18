//! Incremental S3 checksums: the one algorithm a request asked for.
//!
//! CRC-32C and CRC-64/NVME are reflected, table-driven CRCs with an
//! all-ones initial value and final XOR, as S3 and the AWS SDKs compute
//! them. Values are the big-endian bytes of the CRC, base64-encoded on the
//! wire.

use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::ChecksumAlgorithm;

/// Eight tables for one reflected CRC. `[0]` is the usual byte table;
/// `[k][i]` is the CRC of byte `i` followed by `k` zero bytes, so eight
/// input bytes are folded in with eight lookups that do not wait on each
/// other ("slicing by 8"). The value is the same as a byte at a time.
const fn tables32(poly: u32) -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 { (c >> 1) ^ poly } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[k - 1][i];
            t[k][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        k += 1;
    }
    t
}

const fn tables64(poly: u64) -> [[u64; 256]; 8] {
    let mut t = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 { (c >> 1) ^ poly } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[k - 1][i];
            t[k][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        k += 1;
    }
    t
}

/// CRC-32C (Castagnoli), reflected polynomial.
static CRC32C: [[u32; 256]; 8] = tables32(0x82F6_3B78);
/// CRC-64/NVME, reflected polynomial.
static CRC64NVME: [[u64; 256]; 8] = tables64(0x9A6C_9329_AC4B_C9B5);

/// One byte at a time: the definition, and the tail of [`crc32c`].
fn crc32c_bytes(mut c: u32, bytes: &[u8]) -> u32 {
    for b in bytes {
        c = CRC32C[0][((c ^ u32::from(*b)) & 0xff) as usize] ^ (c >> 8);
    }
    c
}

/// One byte at a time: the definition, and the tail of [`crc64nvme`].
fn crc64nvme_bytes(mut c: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        c = CRC64NVME[0][((c ^ u64::from(*b)) & 0xff) as usize] ^ (c >> 8);
    }
    c
}

/// Folds `bytes` into the running CRC-32C `c`, eight bytes a step.
fn crc32c(mut c: u32, bytes: &[u8]) -> u32 {
    let t = &CRC32C;
    let (words, tail) = bytes.as_chunks::<8>();
    for w in words {
        let lo = c ^ u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        let hi = u32::from_le_bytes([w[4], w[5], w[6], w[7]]);
        c = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xff) as usize]
            ^ t[2][((hi >> 8) & 0xff) as usize]
            ^ t[1][((hi >> 16) & 0xff) as usize]
            ^ t[0][(hi >> 24) as usize];
    }
    crc32c_bytes(c, tail)
}

/// Folds `bytes` into the running CRC-64/NVME `c`, eight bytes a step.
fn crc64nvme(mut c: u64, bytes: &[u8]) -> u64 {
    let t = &CRC64NVME;
    let (words, tail) = bytes.as_chunks::<8>();
    for w in words {
        let x = c ^ u64::from_le_bytes(*w);
        c = t[7][(x & 0xff) as usize]
            ^ t[6][((x >> 8) & 0xff) as usize]
            ^ t[5][((x >> 16) & 0xff) as usize]
            ^ t[4][((x >> 24) & 0xff) as usize]
            ^ t[3][((x >> 32) & 0xff) as usize]
            ^ t[2][((x >> 40) & 0xff) as usize]
            ^ t[1][((x >> 48) & 0xff) as usize]
            ^ t[0][(x >> 56) as usize];
    }
    crc64nvme_bytes(c, tail)
}

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
            Self::Crc32c(c) => *c = crc32c(*c, bytes),
            Self::Crc64Nvme(c) => *c = crc64nvme(*c, bytes),
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
    fn eight_bytes_a_step_is_a_byte_at_a_time() {
        // Every length around the step, every alignment of the start, any
        // split into updates, and any running value carried in.
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let data: Vec<u8> = (0..4200).map(|_| next() as u8).collect();
        for len in (0..=70).chain([255, 256, 257, 1023, 4096, 4199]) {
            for start in 0..9 {
                let bytes = &data[start..start + len.min(data.len() - start)];
                let c32 = next() as u32;
                let c64 = next();
                assert_eq!(
                    crc32c(c32, bytes),
                    crc32c_bytes(c32, bytes),
                    "{len}/{start}"
                );
                assert_eq!(
                    crc64nvme(c64, bytes),
                    crc64nvme_bytes(c64, bytes),
                    "{len}/{start}"
                );
                let cut = if bytes.is_empty() {
                    0
                } else {
                    next() as usize % bytes.len()
                };
                let (a, b) = bytes.split_at(cut);
                assert_eq!(crc32c(crc32c(c32, a), b), crc32c_bytes(c32, bytes));
                assert_eq!(crc64nvme(crc64nvme(c64, a), b), crc64nvme_bytes(c64, bytes));
            }
        }
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
