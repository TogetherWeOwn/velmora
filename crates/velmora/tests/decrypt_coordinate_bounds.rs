//! Acceptance tests: ranged decryption must reject ciphertext coordinates
//! that are not representable in `u64`, in debug and release builds alike.
//!
//! Contract under test (existing public seam, no new API required):
//!
//! - `aes_cbc::read_at` and `rclone::read_at` return an existing error
//!   (`Error::Decrypt` or `Error::Io`) when a ciphertext cursor, a
//!   block-range expansion (`block_number * CIPHER_BLOCK_SIZE`), or the
//!   extent `cipher_off..cipher_off + len` of a block read would exceed
//!   `u64::MAX`.
//! - They must not wrap, must not panic (debug overflow checks), and must
//!   never issue a source request at a wrapped (small) offset in release
//!   builds. The virtual sources below record every requested offset so a
//!   wrapped request is observable behaviour, not source-text matching.
//! - Validation must happen before the wrapped source request would be
//!   issued (checking each cursor advance in the shared exact-read helper
//!   satisfies this just as an up-front extent check does).
//! - Valid large-but-representable coordinates, short reads, EOF and
//!   empty-read semantics stay exactly as they are today.
//!
//! All fixtures are synthetic and offline: tiny destinations, no large
//! allocations, no real keys. The implementation fix belongs in
//! `src/decrypt.rs` (checked arithmetic in the shared exact-read helper
//! and in both scheme's coordinate paths); this file and
//! `decrypt_vectors.rs` are the protected test surface for that fix.

use std::cell::RefCell;
use std::io;

use nntune_core::decrypt::rclone::{
    seal_block, CIPHER_BLOCK_SIZE, CIPHER_OVERHEAD, HEADER_SIZE, PLAIN_BLOCK_SIZE,
};
use nntune_core::decrypt::{aes_cbc, rclone, ReadAt};
use nntune_core::{Error, Result};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A rejection is acceptable only through the existing error surface.
/// Anything else -- success on garbage, or a new error kind -- fails, and a
/// panic fails the test thread outright.
fn expect_coordinate_rejection(result: Result<usize>) {
    match result {
        Err(Error::Decrypt(_)) | Err(Error::Io(_)) => {}
        Err(other) => panic!("expected existing Decrypt/Io error, got {other:?}"),
        Ok(n) => panic!("expected unrepresentable coordinate to be rejected, got Ok({n})"),
    }
}

/// Once a read at or beyond `threshold` has been issued, no later read may
/// fall below it: a later small offset is a wrapped cursor made visible.
/// Vacuously true when the implementation rejects before any such read,
/// which is also acceptable.
fn assert_no_wrapped_request_after(recorded: &[u64], threshold: u64, what: &str) {
    if let Some(first_high) = recorded.iter().position(|&off| off >= threshold) {
        assert!(
            recorded[first_high..].iter().all(|&off| off >= threshold),
            "{what}: source was asked for a wrapped offset; requests: {recorded:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Virtual sources (record every requested offset)
// ---------------------------------------------------------------------------

/// Endless source: always fills up to `chunk` bytes, whatever the offset.
/// It is the release-mode wrap detector: unchecked cursor arithmetic keeps
/// "succeeding" past `u64::MAX` and comes back asking for small offsets.
struct EndlessShortRead {
    chunk: usize,
    fill: u8,
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for EndlessShortRead {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        let n = buf.len().min(self.chunk);
        buf[..n].fill(self.fill);
        Ok(n)
    }
}

/// Serves a valid 32-byte rclone header at offset 0, then end-of-source.
/// Any recorded offset >= 32 is a block read; for an unrepresentable block
/// coordinate there must be none (validation precedes the block request).
struct HeaderOnly {
    header: [u8; HEADER_SIZE as usize],
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for HeaderOnly {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        if off >= HEADER_SIZE {
            return Ok(0);
        }
        let off = off as usize;
        let n = buf.len().min(self.header.len() - off);
        buf[..n].copy_from_slice(&self.header[off..off + n]);
        Ok(n)
    }
}

/// Valid rclone header at 0, endless short reads everywhere else.
struct HeaderPlusEndless {
    header: [u8; HEADER_SIZE as usize],
    chunk: usize,
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for HeaderPlusEndless {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        if off < HEADER_SIZE {
            let off = off as usize;
            let n = buf.len().min(self.header.len() - off);
            buf[..n].copy_from_slice(&self.header[off..off + n]);
            return Ok(n);
        }
        let n = buf.len().min(self.chunk);
        buf[..n].fill(0x5a);
        Ok(n)
    }
}

/// A finite byte window presented at a large virtual base offset, served in
/// short reads. Proves large-but-representable coordinates still work.
struct WindowAtBase {
    base: u64,
    bytes: Vec<u8>,
    chunk: usize,
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for WindowAtBase {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        let Some(rel) = off.checked_sub(self.base) else {
            return Ok(0);
        };
        if rel >= self.bytes.len() as u64 {
            return Ok(0);
        }
        let rel = rel as usize;
        let n = buf.len().min(self.chunk).min(self.bytes.len() - rel);
        buf[..n].copy_from_slice(&self.bytes[rel..rel + n]);
        Ok(n)
    }
}

/// Plain in-memory source with a per-call byte cap (short reads).
struct ShortSlice {
    bytes: Vec<u8>,
    chunk: usize,
}

impl ReadAt for ShortSlice {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        if off >= self.bytes.len() as u64 {
            return Ok(0);
        }
        let off = off as usize;
        let n = buf.len().min(self.chunk).min(self.bytes.len() - off);
        buf[..n].copy_from_slice(&self.bytes[off..off + n]);
        Ok(n)
    }
}

/// Records requests and always reports end-of-source.
struct CountingEof {
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for CountingEof {
    fn read_at(&self, _buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        Ok(0)
    }
}

fn rclone_header(nonce: &[u8; 24]) -> [u8; HEADER_SIZE as usize] {
    let mut header = [0u8; HEADER_SIZE as usize];
    header[..8].copy_from_slice(b"RCLONE\x00\x00");
    header[8..].copy_from_slice(nonce);
    header
}

// ---------------------------------------------------------------------------
// RED: unrepresentable coordinates must be rejected without wrapping
// ---------------------------------------------------------------------------

/// AES-CBC at `off = u64::MAX`: the preceding-block IV read lands at
/// `u64::MAX - 31` and the ciphertext read at `u64::MAX - 15`, so a
/// 64-byte destination forces the exact-read cursor past `u64::MAX`
/// through many short reads. Today that panics in debug builds and wraps
/// (then happily "decrypts" filler) in release builds.
#[test]
fn aes_read_at_u64_max_rejects_without_wrapped_source_request() {
    let src = EndlessShortRead {
        chunk: 7,
        fill: 0x42,
        recorded: RefCell::new(Vec::new()),
    };
    let key = [0x2bu8; 32];
    let iv = [0x11u8; 16];
    let mut dst = [0u8; 64];

    let result = aes_cbc::read_at(&src, &key, &iv, &mut dst, u64::MAX);

    expect_coordinate_rejection(result);
    let recorded = src.recorded.borrow();
    assert!(
        recorded.iter().all(|&off| off >= u64::MAX - 1024),
        "aes-cbc: source was asked for a wrapped offset; requests: {recorded:?}"
    );
}

/// rclone near-`u64::MAX` plaintext: `block_number * CIPHER_BLOCK_SIZE`
/// (and the `HEADER_SIZE +` on top of it) is not representable even though
/// `block_number * PLAIN_BLOCK_SIZE` is. The block coordinate must be
/// rejected before any block bytes are requested; an authentication error
/// after reading a wrapped offset does not satisfy the contract, which the
/// header-only recording makes visible. Today this panics in debug and
/// reads a wrapped offset in release.
#[test]
fn rclone_near_u64_block_expansion_rejects_without_block_source_request() {
    let nonce = [0xa0u8; 24];
    let src = HeaderOnly {
        header: rclone_header(&nonce),
        recorded: RefCell::new(Vec::new()),
    };
    let derived = vec![0x3cu8; 80];
    let mut dst = [0u8; 16];

    // off + kept_len and block_number * PLAIN_BLOCK_SIZE stay in range, so
    // the ciphertext expansion is the only unrepresentable step.
    let off = u64::MAX - 5;
    let block_number = off / PLAIN_BLOCK_SIZE;
    assert!(
        (block_number as u128) * (CIPHER_BLOCK_SIZE as u128) + (HEADER_SIZE as u128)
            > u64::MAX as u128,
        "fixture must actually make the ciphertext offset unrepresentable"
    );

    let result = rclone::read_at(&src, &derived, u64::MAX, &mut dst, off);

    expect_coordinate_rejection(result);
    let recorded = src.recorded.borrow();
    assert!(
        recorded.iter().all(|&off| off < HEADER_SIZE),
        "rclone: block bytes were requested despite unrepresentable \
         ciphertext coordinate; requests: {recorded:?}"
    );
}

/// The largest block whose ciphertext *start* is still representable, but
/// whose full sealed-block extent crosses `u64::MAX`. A fix that only
/// checks the start offset still wraps the exact-read cursor mid-block;
/// the recording requires rejection with no wrapped request, whether the
/// check is up-front or per cursor advance. Today this panics in debug
/// and wraps in release.
#[test]
fn rclone_block_extent_crossing_u64_max_rejects_without_wrapped_request() {
    let block_number = (u64::MAX - HEADER_SIZE) / CIPHER_BLOCK_SIZE;
    let cipher_off = HEADER_SIZE + block_number * CIPHER_BLOCK_SIZE;
    assert!(
        cipher_off as u128 + (PLAIN_BLOCK_SIZE + CIPHER_OVERHEAD) as u128 > u64::MAX as u128,
        "fixture block extent must cross u64::MAX (cipher_off={cipher_off})"
    );
    let plain_start = block_number * PLAIN_BLOCK_SIZE;
    let plaintext_size = plain_start
        .checked_add(PLAIN_BLOCK_SIZE)
        .expect("fixture plaintext extent must stay representable");

    let nonce = [0xb1u8; 24];
    let src = HeaderPlusEndless {
        header: rclone_header(&nonce),
        chunk: 1024,
        recorded: RefCell::new(Vec::new()),
    };
    let derived = vec![0x3cu8; 80];
    let mut dst = [0u8; 8];

    let result = rclone::read_at(&src, &derived, plaintext_size, &mut dst, plain_start);

    expect_coordinate_rejection(result);
    assert_no_wrapped_request_after(&src.recorded.borrow(), cipher_off, "rclone extent");
}

// ---------------------------------------------------------------------------
// Positive controls: representable behaviour must not change
// ---------------------------------------------------------------------------

const AES_KEY: &str = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";
const AES_IV: &str = "11111111111111111111111111111111";
const AES_PLAIN: &str = "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9";
const AES_CIPHER: &str = "b839028f0addc203334b984fc525b2de459ac23cc5264bbe3c7df61e5a70367a7b2cb46efbe1741170226f5abf74f87ce6dc318eee67593d559f4357edfa3c44";

/// The known AES-CBC vector presented at a 1 TiB virtual base and read
/// unaligned through 3-byte short reads. Guards against "fixes" that cap
/// or reject merely-large offsets.
#[test]
fn aes_large_representable_offset_still_decrypts_with_short_reads() {
    let base: u64 = 1 << 40;
    let cipher = hex(AES_CIPHER);
    let plain = hex(AES_PLAIN);
    let src = WindowAtBase {
        base,
        bytes: cipher.clone(),
        chunk: 3,
        recorded: RefCell::new(Vec::new()),
    };
    let key = hex(AES_KEY);
    let iv: [u8; 16] = hex(AES_IV).try_into().unwrap();

    let mut dst = [0u8; 24];
    let n = aes_cbc::read_at(&src, &key, &iv, &mut dst, base + 17).unwrap();

    assert_eq!(n, 24);
    assert_eq!(&dst, &plain[17..41]);
    assert!(
        src.recorded
            .borrow()
            .iter()
            .all(|&off| (base..base + cipher.len() as u64).contains(&off)),
        "aes-cbc positive control read outside its virtual window"
    );
}

/// One sealed rclone block at block number 2^20 (plaintext start ~64 GiB,
/// ciphertext start well past `u32`), served in 13-byte short reads.
#[test]
fn rclone_large_representable_block_still_decrypts_with_short_reads() {
    let derived = vec![0x77u8; 80];
    let header_nonce = [0x42u8; 24];
    let block_number: u64 = 1 << 20;
    let plain_start = block_number * PLAIN_BLOCK_SIZE;
    let cipher_off = HEADER_SIZE + block_number * CIPHER_BLOCK_SIZE;

    let plain_block: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let mut sealed = vec![0u8; plain_block.len() + CIPHER_OVERHEAD as usize];
    seal_block(
        &derived,
        &header_nonce,
        block_number,
        &plain_block,
        &mut sealed,
    )
    .unwrap();

    // One virtual file: header window at 0, sealed block at cipher_off.
    struct VirtualRclone {
        header: [u8; HEADER_SIZE as usize],
        cipher_off: u64,
        sealed: Vec<u8>,
    }
    impl ReadAt for VirtualRclone {
        fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
            if off < HEADER_SIZE {
                let off = off as usize;
                let n = buf.len().min(13).min(self.header.len() - off);
                buf[..n].copy_from_slice(&self.header[off..off + n]);
                return Ok(n);
            }
            let Some(rel) = off.checked_sub(self.cipher_off) else {
                return Ok(0);
            };
            if rel >= self.sealed.len() as u64 {
                return Ok(0);
            }
            let rel = rel as usize;
            let n = buf.len().min(13).min(self.sealed.len() - rel);
            buf[..n].copy_from_slice(&self.sealed[rel..rel + n]);
            Ok(n)
        }
    }
    let src = VirtualRclone {
        header: rclone_header(&header_nonce),
        cipher_off,
        sealed,
    };
    let plaintext_size = plain_start + plain_block.len() as u64;

    let mut dst = [0u8; 32];
    let n = rclone::read_at(&src, &derived, plaintext_size, &mut dst, plain_start + 10).unwrap();
    assert_eq!(n, 32);
    assert_eq!(&dst, &plain_block[10..42]);

    // Last plaintext byte of the virtual file.
    let mut one = [0u8; 1];
    let n = rclone::read_at(&src, &derived, plaintext_size, &mut one, plaintext_size - 1).unwrap();
    assert_eq!(n, 1);
    assert_eq!(one[0], *plain_block.last().unwrap());
}

/// Ordinary small-blob behaviour through short reads, and a truncated
/// sealed block still fails as an error (EOF semantics unchanged).
#[test]
fn rclone_normal_blob_short_reads_and_truncation_semantics_unchanged() {
    let derived = vec![0x77u8; 80];
    let header_nonce = [0x24u8; 24];
    let plain: Vec<u8> = (0..300u32).map(|i| (i * 7 % 256) as u8).collect();
    let mut sealed = vec![0u8; plain.len() + CIPHER_OVERHEAD as usize];
    seal_block(&derived, &header_nonce, 0, &plain, &mut sealed).unwrap();
    let mut blob = rclone_header(&header_nonce).to_vec();
    blob.extend_from_slice(&sealed);

    let src = ShortSlice {
        bytes: blob.clone(),
        chunk: 3,
    };
    let mut dst = [0u8; 50];
    let n = rclone::read_at(&src, &derived, plain.len() as u64, &mut dst, 5).unwrap();
    assert_eq!(n, 50);
    assert_eq!(&dst, &plain[5..55]);

    // Truncation mid-block: an error, never partial success or a panic.
    let truncated = ShortSlice {
        bytes: blob[..blob.len() - 10].to_vec(),
        chunk: 3,
    };
    let mut dst = vec![0u8; plain.len()];
    expect_coordinate_rejection(rclone::read_at(
        &truncated,
        &derived,
        plain.len() as u64,
        &mut dst,
        0,
    ));
}

/// Empty destinations and reads exactly at EOF return `Ok(0)` without
/// touching the source -- including at `u64::MAX`, where no coordinate
/// arithmetic may be performed at all for a zero-length result.
#[test]
fn empty_and_eof_reads_at_u64_max_do_not_touch_source() {
    let src = CountingEof {
        recorded: RefCell::new(Vec::new()),
    };

    let key = [0x2bu8; 32];
    let iv = [0x11u8; 16];
    let mut empty: [u8; 0] = [];
    assert_eq!(
        aes_cbc::read_at(&src, &key, &iv, &mut empty, u64::MAX).unwrap(),
        0
    );

    let derived = vec![0x3cu8; 80];
    let mut dst = [0u8; 4];
    assert_eq!(
        rclone::read_at(&src, &derived, u64::MAX, &mut dst, u64::MAX).unwrap(),
        0
    );
    assert_eq!(
        rclone::read_at(&src, &derived, 10, &mut empty, 0).unwrap(),
        0
    );

    assert!(
        src.recorded.borrow().is_empty(),
        "empty/EOF reads must not touch the source; requests: {:?}",
        src.recorded.borrow()
    );
}
