//! Regression pins: hostile-source overlong reads and `seal_block` rejections.
//!
//! Contract under test (unchanged implementation in `src/decrypt.rs`):
//!
//! - `read_exact_at` rejects a source that returns `n > dst.len()` with
//!   `io::ErrorKind::InvalidData` ("lying-source arm"). Honest sources that
//!   return `n <= dst.len()` (exact fills, short reads, EOF) are untouched.
//! - `rclone::seal_block` returns `Err` when the derived key is not 80 bytes
//!   or when `sealed.len() != plaintext.len() + CIPHER_OVERHEAD`.
//!
//! All fixtures are synthetic and offline: no network, no keys, no files.

use std::io;

use nntune_core::decrypt::rclone::{seal_block, CIPHER_OVERHEAD};
use nntune_core::decrypt::{aes_cbc, rclone, ReadAt};
use nntune_core::Error;

/// Source that always lies: fills what it can, then reports one byte more
/// than requested. `read_exact_at` must reject this with `InvalidData`
/// instead of slicing `dst[n..]` out of bounds (panic) or advancing past
/// the lie.
struct LyingSource;

impl ReadAt for LyingSource {
    fn read_at(&self, buf: &mut [u8], _off: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        buf.fill(0xAA);
        // One more than requested: the exact condition the guard checks.
        Ok(buf.len() + 1)
    }
}

/// AES-CBC surfaces the shared helper's `io` error unchanged, so the
/// `InvalidData` kind is directly observable here.
#[test]
fn lying_source_overlong_read_yields_invalid_data() {
    let src = LyingSource;
    let key = [0x2bu8; 32];
    let iv = [0x11u8; 16];
    let mut dst = [0u8; 16];

    let err = aes_cbc::read_at(&src, &key, &iv, &mut dst, 0)
        .expect_err("lying source returning n > dst.len() must be rejected, not decrypted");
    match err {
        Error::Io(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::InvalidData,
            "lying-source arm must yield InvalidData, got: {e}"
        ),
        other => panic!("lying-source arm must surface as Error::Io, got {other:?}"),
    }
}

/// The same lie through the rclone path must also fail (as an error, never
/// partial success or a panic). The `io` error is wrapped in `Decrypt`
/// there, so assert on the rejection plus the preserved message.
#[test]
fn rclone_lying_source_is_rejected_not_decrypted() {
    let src = LyingSource;
    let derived = vec![0x3cu8; 80];
    // Plaintext extent large enough that the block read is attempted; the
    // header read itself already trips the lying guard.
    let mut dst = [0u8; 16];

    let err = rclone::read_at(&src, &derived, 1024, &mut dst, 0)
        .expect_err("rclone must reject a lying source, not decrypt it");
    match err {
        Error::Decrypt(msg) => assert!(
            msg.contains("more bytes than requested"),
            "rclone lying-source rejection must preserve the InvalidData reason, got: {msg}"
        ),
        Error::Io(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::InvalidData,
            "rclone lying-source arm must yield InvalidData, got: {e}"
        ),
        other => panic!("expected Decrypt/Io rejection for lying source, got {other:?}"),
    }
}

/// Honest exact-fill source is untouched by the lying-source guard: the
/// known AES-CBC vector still decrypts through a plain slice source.
#[test]
fn honest_exact_source_still_decrypts() {
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let key = hex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
    let iv: [u8; 16] = hex("11111111111111111111111111111111").try_into().unwrap();
    let cipher = hex("b839028f0addc203334b984fc525b2de459ac23cc5264bbe3c7df61e5a70367a7b2cb46efbe1741170226f5abf74f87ce6dc318eee67593d559f4357edfa3c44");
    let plain = hex("00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9");

    let mut dst = vec![0u8; plain.len()];
    let n = aes_cbc::read_at(&cipher, &key, &iv, &mut dst, 0).unwrap();
    assert_eq!(n, plain.len());
    assert_eq!(dst, plain);
}

/// `seal_block` with a derived key that is not 80 bytes returns `Err`
/// (asserted as an error value, not merely "does not panic").
#[test]
fn seal_block_rejects_wrong_derived_len() {
    let header_nonce = [0x42u8; 24];
    let plaintext = [0xABu8; 32];
    let mut sealed = vec![0u8; plaintext.len() + CIPHER_OVERHEAD as usize];

    for len in [0usize, 32, 79, 81, 160] {
        let derived = vec![0x77u8; len];
        let err = seal_block(&derived, &header_nonce, 0, &plaintext, &mut sealed)
            .expect_err(&format!("derived len {len} must be rejected"));
        assert!(
            matches!(err, Error::Decrypt(_)),
            "wrong derived len {len} must yield Error::Decrypt, got {err:?}"
        );
    }
}

/// `seal_block` with a wrong-size output buffer returns `Err` in both
/// directions (too short and too long). Exact size still succeeds.
#[test]
fn seal_block_rejects_wrong_sealed_len() {
    let derived = vec![0x77u8; 80];
    let header_nonce = [0x42u8; 24];
    let plaintext = [0xABu8; 32];
    let exact = plaintext.len() + CIPHER_OVERHEAD as usize;

    for len in [0usize, 1, exact - 1, exact + 1, exact * 2] {
        let mut sealed = vec![0u8; len];
        let err = seal_block(&derived, &header_nonce, 0, &plaintext, &mut sealed)
            .expect_err(&format!("sealed len {len} (want {exact}) must be rejected"));
        assert!(
            matches!(err, Error::Decrypt(_)),
            "wrong sealed len {len} must yield Error::Decrypt, got {err:?}"
        );
    }

    // Honest sizes untouched: the exact buffer seals successfully.
    let mut sealed = vec![0u8; exact];
    seal_block(&derived, &header_nonce, 0, &plaintext, &mut sealed).unwrap();
    assert_eq!(sealed.len(), exact);
}
