//! Ranged-decrypt interop tests.
//!
//! The two embedded vectors were produced by the v1 Go worker's own crypto
//! (Go stdlib AES-CBC, `x/crypto/nacl/secretbox` for rclone-crypt), so they
//! pin the wire format independently of this implementation. Multi-block and
//! range-edge behaviour is covered by round-trips through `seal_block` plus
//! targeted AES-CBC range tests.

use nntune_core::decrypt::rclone::{seal_block, CIPHER_OVERHEAD, HEADER_SIZE, PLAIN_BLOCK_SIZE};
use nntune_core::decrypt::{aes_cbc, rclone, ReadAt};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// AES-CBC (Go stdlib oracle)
// ---------------------------------------------------------------------------

const AES_KEY: &str = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";
const AES_IV: &str = "11111111111111111111111111111111";
const AES_PLAIN: &str = "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9";
const AES_CIPHER: &str = "b839028f0addc203334b984fc525b2de459ac23cc5264bbe3c7df61e5a70367a7b2cb46efbe1741170226f5abf74f87ce6dc318eee67593d559f4357edfa3c44";

#[test]
fn aes_cbc_go_ciphertext_decrypts() {
    let key = hex(AES_KEY);
    let iv: [u8; 16] = hex(AES_IV).try_into().unwrap();
    let cipher = hex(AES_CIPHER);
    let plain = hex(AES_PLAIN);
    let mut dst = vec![0u8; plain.len()];
    let n = aes_cbc::read_at(&cipher, &key, &iv, &mut dst, 0).unwrap();
    assert_eq!(n, plain.len());
    assert_eq!(dst, plain);
}

#[test]
fn aes_cbc_unaligned_ranges_use_preceding_block_as_iv() {
    let key = hex(AES_KEY);
    let iv: [u8; 16] = hex(AES_IV).try_into().unwrap();
    let cipher = hex(AES_CIPHER);
    let plain = hex(AES_PLAIN);
    // Every offset/length combo, including single bytes straddling blocks.
    for off in [0usize, 1, 7, 15, 16, 17, 31, 32, 33, 47, 48, 63] {
        for len in [1usize, 2, 15, 16, 17, 31] {
            if off + len > plain.len() {
                continue;
            }
            let mut dst = vec![0u8; len];
            let n = aes_cbc::read_at(&cipher, &key, &iv, &mut dst, off as u64).unwrap();
            assert_eq!(n, len, "off={off} len={len}");
            assert_eq!(&dst, &plain[off..off + len], "off={off} len={len}");
        }
    }
}

#[test]
fn aes_cbc_rejects_bad_key_and_short_source() {
    let iv = [0x11u8; 16];
    let cipher = hex(AES_CIPHER);
    let mut dst = vec![0u8; 16];
    assert!(aes_cbc::read_at(&cipher, &[0u8; 10], &iv, &mut dst, 0).is_err());
    assert!(aes_cbc::read_at(&cipher[..16].to_vec(), &hex(AES_KEY), &iv, &mut dst, 16).is_err());
    let mut empty = [];
    assert_eq!(
        aes_cbc::read_at(&cipher, &hex(AES_KEY), &iv, &mut empty, 0).unwrap(),
        0
    );
}

// ---------------------------------------------------------------------------
// rclone-crypt (x/crypto oracle, single-block embedded vector)
// ---------------------------------------------------------------------------

const RCLONE_DERIVED: &str = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";
const RCLONE_PLAIN: &str = "d5fc05d0e7aaed64f6b604c29c6eb66e6a5101670a7b9e76faf85fb06eab78482766a32b634e53f327d1731f889a5bb7b768ecbbf6b11afdb760405a8738025f978fadd3ec7946be9a96bdd693170270e1a5d9616055bc724bc02c3f2fe92ab6209ed39530604b7a971865880915d6ac1d22c1ebcfb0f36a77582fffcb414285b11fd74411e23b1cd9498459e8e8d544935bafedfeaf81be7350ebc170e774c52c0091b6a27c44e19003c4efe00bd1d36031c6ffdbe57d8be6b2962feda5bb346696e9c72d53e7475f016576581970ba93eb38be8b885433ee6cfb74c06be9542c96e0552e2ff9115de33b9f6bd42d1c323250cb6270c3591d5175451d4ba06b3a1e8841577ca347162fae9ce51f55e2351269c9ee1ddfe87716f7d4ed7d598344ab07738c496232894cba2549040ab888fdf562ebaf0e0d785607ddcb59616af02199d6e74a08642987ed75cdb1440e0bc878414eed0c370b8fbf9d0761d7b3d8c88b57b4d7b9addf0f6c4d5a74cc1794ad8a193d40e71d9224cbd5a536b0b38b4a41e974ebef2605faeeef8fc43fcce949d99c13b603b8e35a6ecb5d9eb3848bb83184dc2777296b3fbf23bd3811e9c99d258460001744465d7d489a867d044e83e520d5ce725654babf34eb8f88ede30e428de5762e427b3a629a7efc7fd63f85fdbe7cc8558f782d61f3d1a8bd1edb661a789910a878b1e31b92db31fb5fbdf72c5f21a1eafc013bacb2df889f824ad2a809a96c36ee8e3039873a7e0bca1979370a4a884d07916d3e4a3659f0e7bde3ff0872cbe2f22cdae250d65e9a049a0ef9c9b052f060392e4415ac6645dbb48f414388150515187fcf4da06d69c07b1f62ac407697f981cf84f4ca210ab3a32ea98ab1d24f2b53a24f5f3b710c73ea7573c419105d0a6585544acf1f7d87f27f82b1e930c34e53a942eaff4feb570940442892dfad0e5468a0fdad17af34ffa22d905d02b9da02de1fd9f812426bef14fff234484ac33173e87b0ae88758181d1f0672bcda71bc70ef99e7e82171a6e8e242ba52482e548840b23f92be5984d8e0f1be7928f85371501c3e266cee2d17413a16a91194896b4f165a39e45d7a220e360cf6f4980dd674d72641dd2d756082ff6d9d62800ec3509e1e275a5227ab59be5b96e6bda37c1fc47ad4fe3c66e720bd19224cc3981d14c7ffc756e7ab8a8576dd5df81a421fac60cc9f2fedda32a9a3a4cf346e4de9fe8f29ace3911a366b4efbf67ba28b6209ac5e83a6d59f2ec0e2d2e0d2dac87d067a7989de867d8df93b4eaf128f95cbb72f28886b4f772a1bb2963436a01a0fb88f8138fac4d1d12d34a579b25ee8c5ccf2d6d858781ad8864d1951bfa0c6bc325b86b5bd0a05a71e3704eaa9d0829ef183c9c21f343150dff1b95d22fd";

#[test]
fn rclone_go_blob_decrypts() {
    // Rebuild the blob: header (magic + nonce) + sealed block produced by Go.
    // The sealed block hex is long; it lives in testdata to keep this file
    // readable.
    let sealed = hex(include_str!("../testdata/rclone_small_sealed.hex").trim());
    let derived = hex(RCLONE_DERIVED);
    let nonce: [u8; 24] = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7")
        .try_into()
        .unwrap();
    let plain = hex(RCLONE_PLAIN);

    let mut blob = Vec::new();
    blob.extend_from_slice(b"RCLONE\x00\x00");
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed);
    assert_eq!(blob.len(), 32 + plain.len() + 16);

    // Full read.
    let mut dst = vec![0u8; plain.len()];
    let n = rclone::read_at(&blob, &derived, plain.len() as u64, &mut dst, 0).unwrap();
    assert_eq!(n, plain.len());
    assert_eq!(dst, plain);

    // Ranged reads, including a 1-byte read and a tail-clamped read.
    for (off, len) in [(0, 7), (1, 1), (99, 50), (500, 200), (999, 1)] {
        let mut dst = vec![0u8; len];
        let n = rclone::read_at(&blob, &derived, plain.len() as u64, &mut dst, off as u64).unwrap();
        let want = (plain.len() - off).min(len);
        assert_eq!(n, want, "off={off} len={len}");
        assert_eq!(&dst[..n], &plain[off..off + n], "off={off} len={len}");
    }

    // Tampered ciphertext fails authentication instead of returning garbage.
    let mut evil = blob.clone();
    evil[40] ^= 0x01;
    let mut dst = vec![0u8; plain.len()];
    assert!(rclone::read_at(&evil, &derived, plain.len() as u64, &mut dst, 0).is_err());

    // Bad magic, bad key length, offset past end.
    let mut bad_magic = blob.clone();
    bad_magic[0] = b'X';
    assert!(rclone::read_at(&bad_magic, &derived, plain.len() as u64, &mut dst, 0).is_err());
    assert!(rclone::read_at(&blob, &derived[..32], plain.len() as u64, &mut dst, 0).is_err());
    assert!(rclone::read_at(
        &blob,
        &derived,
        plain.len() as u64,
        &mut dst,
        plain.len() as u64 + 1
    )
    .is_err());
    assert_eq!(
        rclone::read_at(
            &blob,
            &derived,
            plain.len() as u64,
            &mut dst,
            plain.len() as u64
        )
        .unwrap(),
        0
    );
}

// ---------------------------------------------------------------------------
// Multi-block round-trips (seal_block -> read_at)
// ---------------------------------------------------------------------------

/// Builds a two-block rclone file in memory and checks every range reads back.
#[test]
fn rclone_multiblock_ranges() {
    let derived = vec![0x77u8; 80];
    let header_nonce = [0x42u8; 24];
    let file_len = PLAIN_BLOCK_SIZE + 12345;
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut file = vec![0u8; file_len as usize];
    for b in file.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 32) as u8;
    }
    let mut blob = Vec::new();
    blob.extend_from_slice(b"RCLONE\x00\x00");
    blob.extend_from_slice(&header_nonce);
    for (bn, chunk) in file.chunks(PLAIN_BLOCK_SIZE as usize).enumerate() {
        let mut sealed = vec![0u8; chunk.len() + CIPHER_OVERHEAD as usize];
        seal_block(&derived, &header_nonce, bn as u64, chunk, &mut sealed).unwrap();
        blob.extend_from_slice(&sealed);
    }

    // Full read.
    let mut dst = vec![0u8; file.len()];
    let n = rclone::read_at(&blob, &derived, file_len, &mut dst, 0).unwrap();
    assert_eq!(n, file.len());
    assert_eq!(dst, file);

    // Ranges: block-aligned, straddling the block boundary, tail, 1 byte.
    let ranges = [
        (0u64, 0usize, PLAIN_BLOCK_SIZE as usize),
        (PLAIN_BLOCK_SIZE - 7, (PLAIN_BLOCK_SIZE - 7) as usize, 14),
        (PLAIN_BLOCK_SIZE, PLAIN_BLOCK_SIZE as usize, 12345),
        (file_len - 1, (file_len - 1) as usize, 1),
        (100, 100, 70000),
    ];
    for (off, start, len) in ranges {
        let mut dst = vec![0u8; len];
        let n = rclone::read_at(&blob, &derived, file_len, &mut dst, off).unwrap();
        assert_eq!(n, len, "off={off} len={len}");
        assert_eq!(&dst, &file[start..start + len], "off={off} len={len}");
    }

    // A tampered second block fails only when that block is touched.
    let mut evil = blob.clone();
    let second = HEADER_SIZE as usize + (PLAIN_BLOCK_SIZE + CIPHER_OVERHEAD) as usize + 100;
    evil[second] ^= 0x01;
    let mut dst = vec![0u8; 100];
    assert!(rclone::read_at(&evil, &derived, file_len, &mut dst, PLAIN_BLOCK_SIZE).is_err());
    // First block still reads fine.
    let n = rclone::read_at(&evil, &derived, file_len, &mut dst, 0).unwrap();
    assert_eq!(n, 100);
    assert_eq!(&dst, &file[..100]);
}

/// Offsets beyond the source end report end-of-source even past 32 bits
/// (guards the `u64`-before-cast comparison used by the slice impl; on
/// 32-bit targets a plain `as usize` cast would wrap and return wrong data).
#[test]
fn slice_read_at_huge_offset_is_end_of_source() {
    let src = vec![0xabu8; 10];
    let mut dst = [0u8; 4];
    assert_eq!(src.read_at(&mut dst, u64::from(u32::MAX) + 10).unwrap(), 0);
    assert_eq!(src.read_at(&mut dst, 10).unwrap(), 0);
    assert_eq!(src.read_at(&mut dst, 9).unwrap(), 1);
    assert_eq!(dst[0], 0xab);
}

/// `ReadAt` over a source that returns short reads (exercises `read_exact_at`).
#[test]
fn decrypt_tolerates_short_reads() {
    struct Short(Vec<u8>);
    impl ReadAt for Short {
        fn read_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
            let off = off as usize;
            if off >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - off).min(3);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
    }
    let key = hex(AES_KEY);
    let iv: [u8; 16] = hex(AES_IV).try_into().unwrap();
    let src = Short(hex(AES_CIPHER));
    let mut dst = vec![0u8; 64];
    let n = aes_cbc::read_at(&src, &key, &iv, &mut dst, 0).unwrap();
    assert_eq!(&dst, &hex(AES_PLAIN));
    assert_eq!(n, 64);
}
