//! Streaming whole-object verification shared by restores and read-only checks.

use base64::{engine::general_purpose::STANDARD, Engine};
use crc::{Crc, CRC_32_ISCSI, CRC_32_ISO_HDLC, CRC_64_NVME};
use sha2::Digest;
use velmora_s3_proto::{ChecksumAlgorithm, StoredChecksum};

static CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
static CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);
static CRC64: Crc<u64> = Crc::<u64>::new(&CRC_64_NVME);

enum Running {
    Crc32(crc::Digest<'static, u32>),
    Crc64(crc::Digest<'static, u64>),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl Running {
    fn new(algorithm: ChecksumAlgorithm) -> Self {
        match algorithm {
            ChecksumAlgorithm::Crc32 => Self::Crc32(CRC32.digest()),
            ChecksumAlgorithm::Crc32c => Self::Crc32(CRC32C.digest()),
            ChecksumAlgorithm::Crc64Nvme => Self::Crc64(CRC64.digest()),
            ChecksumAlgorithm::Sha1 => Self::Sha1(sha1::Sha1::new()),
            ChecksumAlgorithm::Sha256 => Self::Sha256(sha2::Sha256::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(bytes),
            Self::Crc64(h) => h.update(bytes),
            Self::Sha1(h) => h.update(bytes),
            Self::Sha256(h) => h.update(bytes),
        }
    }

    fn finish(self) -> String {
        match self {
            Self::Crc32(h) => STANDARD.encode(h.finalize().to_be_bytes()),
            Self::Crc64(h) => STANDARD.encode(h.finalize().to_be_bytes()),
            Self::Sha1(h) => STANDARD.encode(h.finalize()),
            Self::Sha256(h) => STANDARD.encode(h.finalize()),
        }
    }
}

pub(crate) struct ObjectHashes<'a> {
    md5: md5::Context,
    checksum: Option<(&'a StoredChecksum, Running)>,
}

impl<'a> ObjectHashes<'a> {
    pub(crate) fn new(checksum: Option<&'a StoredChecksum>) -> Self {
        Self {
            md5: md5::Context::new(),
            checksum: checksum.map(|c| (c, Running::new(c.algorithm()))),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.md5.consume(bytes);
        if let Some((_, hash)) = &mut self.checksum {
            hash.update(bytes);
        }
    }

    pub(crate) fn finish(self, expected_md5: Option<[u8; 16]>) -> Option<[u8; 16]> {
        let md5 = self.md5.finalize().0;
        if expected_md5.is_some_and(|expected| expected != md5) {
            return None;
        }
        if self
            .checksum
            .is_some_and(|(expected, hash)| expected.value() != hash.finish())
        {
            return None;
        }
        Some(md5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_known_s3_vectors_across_chunk_boundaries() {
        for (algorithm, digest) in [
            (ChecksumAlgorithm::Crc32, "y/Q5Jg=="),
            (ChecksumAlgorithm::Crc32c, "4waSgw=="),
            (ChecksumAlgorithm::Crc64Nvme, "rosUhgp5mIg="),
            (ChecksumAlgorithm::Sha1, "98O8HYCOBHMq32eZZczDTKeuNEE="),
            (
                ChecksumAlgorithm::Sha256,
                "FeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiU=",
            ),
        ] {
            let checksum = StoredChecksum::full(algorithm, digest.into()).unwrap();
            let mut verify = ObjectHashes::new(Some(&checksum));
            verify.update(b"1234");
            verify.update(b"56789");
            assert_eq!(
                verify.finish(None),
                Some(md5::compute(b"123456789").0),
                "{algorithm:?}"
            );
        }
    }
}
