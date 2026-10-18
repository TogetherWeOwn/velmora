//! PAR2 Main-packet `MAX_BLOCK_SIZE` boundary pin.
//!
//! Contract under test (`crates/nntune-core/src/par2.rs`, `parse_main_body`):
//!
//! - `MAX_BLOCK_SIZE` is `256 << 20` (256 MiB). A Main packet declaring
//!   exactly that slice size parses and its file verifies.
//! - The next representable slice size above the cap (the smallest multiple
//!   of 4 over the cap) and the largest multiple of 4 are rejected at parse
//!   with `exceeds the supported bound` — without allocating or hashing.
//! - The literal `cap + 1` and `u64::MAX` values are NOT multiples of 4, so
//!   the pre-existing non-zero-multiple-of-4 guard fires first (source order:
//!   alignment, then bound). They are still safely rejected at parse; this
//!   file pins that ordering explicitly so a future guard reorder shows up
//!   as a test failure rather than a silent message change.
//!
//! All packets are constructed byte-for-byte in this file (magic, lengths,
//! checksums, set-ID derivation) and never via the parser under test. The
//! only imports from the crate are the parser entry point (`RecoverySet`),
//! the public cap constant (asserted equal to the local literal), and the
//! hash crates the format itself requires (`md5`, `crc32fast`).

use nntune_core::par2::{RecoverySet, MAX_BLOCK_SIZE};

/// Local literal: the cap value under test. Packets below are built from
/// this, not from the crate constant, so a cap-value change fails the
/// `cap_value_is_pinned` assertion instead of silently following the code.
const CAP: u64 = 256 << 20;
const FILENAME: &str = "cap-bound.flac";
/// Smallest multiple of 4 above the cap: the first slice size that can reach
/// the exceeds-bound branch (cap + 1 itself is 1 mod 4 and hits the
/// alignment guard first).
const CAP_NEXT_ALIGNED: u64 = (256 << 20) + 4;
/// Largest multiple of 4: the aligned equivalent of `u64::MAX` (which is
/// 3 mod 4 and likewise hits the alignment guard first).
const ALIGNED_U64_MAX: u64 = u64::MAX - 3;
/// 8 KiB zero chunks, mirroring the crate's streaming hasher so verification
/// never holds a slice-sized zero allocation in the test either.
const ZERO_CHUNK: usize = 8192;

fn file_bytes() -> Vec<u8> {
    // Deterministic 100-byte payload; small enough that MD5/CRC setup is
    // trivial. Verification still hashes CAP - len zero padding (~256 MiB
    // through crc32fast, well under a second), which is the point: the cap
    // keeps that padding bounded.
    let mut x = 0x51ab_3c7d_29e1_04f5u64;
    let mut out = vec![0u8; 100];
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
    out
}

/// CRC32 of `data` zero-padded to `block_size`, hashed in fixed chunks.
fn padded_block_crc(data: &[u8], block_size: u64) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    let zeros = [0u8; ZERO_CHUNK];
    let mut n = block_size - data.len() as u64;
    while n > 0 {
        let take = n.min(ZERO_CHUNK as u64) as usize;
        h.update(&zeros[..take]);
        n -= take as u64;
    }
    h.finalize()
}

fn packet(set_id: &[u8; 16], kind: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut aligned = body.to_vec();
    while aligned.len() % 4 != 0 {
        aligned.push(0);
    }
    let mut p = Vec::new();
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&((64 + aligned.len()) as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5 placeholder
    p.extend_from_slice(set_id);
    p.extend_from_slice(kind);
    p.extend_from_slice(&aligned);
    let digest = md5::compute(&p[32..]).0;
    p[16..32].copy_from_slice(&digest);
    p
}

fn ptype(suffix: &[u8]) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(b"PAR 2.0\0");
    t[8..8 + suffix.len().min(8)].copy_from_slice(&suffix[..suffix.len().min(8)]);
    t
}

fn derive_file_id(first16k: &[u8; 16], len: u64, name: &[u8]) -> [u8; 16] {
    let mut seed = Vec::with_capacity(24 + name.len());
    seed.extend_from_slice(first16k);
    seed.extend_from_slice(&len.to_le_bytes());
    seed.extend_from_slice(name);
    md5::compute(&seed).0
}

/// A complete minimal set (FileDesc + IFSC + Main) around `block_size`.
/// `block_crc` is the caller-supplied single-block checksum (exactly one
/// block for every small file at these sizes:
/// `ceil(len / block_size) == 1`).
fn set_bytes_for(block_size: u64, block_crc: u32) -> Vec<u8> {
    let data = file_bytes();
    let whole_md5 = md5::compute(&data).0;
    let first16k = md5::compute(&data[..data.len().min(16 * 1024)]).0;
    let file_id = derive_file_id(&first16k, data.len() as u64, FILENAME.as_bytes());

    let mut main_body = Vec::new();
    main_body.extend_from_slice(&block_size.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes());
    main_body.extend_from_slice(&file_id);
    let set_id = md5::compute(&main_body).0;

    let mut fd_body = Vec::new();
    fd_body.extend_from_slice(&file_id);
    fd_body.extend_from_slice(&whole_md5);
    fd_body.extend_from_slice(&first16k);
    fd_body.extend_from_slice(&(data.len() as u64).to_le_bytes());
    fd_body.extend_from_slice(FILENAME.as_bytes());

    let mut ifsc_body = Vec::new();
    ifsc_body.extend_from_slice(&file_id);
    ifsc_body.extend_from_slice(&[0u8; 16]);
    ifsc_body.extend_from_slice(&block_crc.to_le_bytes());

    let mut set_bytes = Vec::new();
    set_bytes.extend(packet(&set_id, &ptype(b"FileDesc"), &fd_body));
    set_bytes.extend(packet(&set_id, &ptype(b"IFSC\0\0\0\0"), &ifsc_body));
    set_bytes.extend(packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body));
    set_bytes
}

/// A lone Main packet declaring `block_size` for `file_id`, with a
/// self-consistent set ID so only the slice-size guards can fire.
fn main_only_bytes(block_size: u64, file_id: &[u8; 16]) -> Vec<u8> {
    let mut main_body = Vec::new();
    main_body.extend_from_slice(&block_size.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes());
    main_body.extend_from_slice(file_id);
    let set_id = md5::compute(&main_body).0;
    packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body)
}

fn fixture_file_id() -> [u8; 16] {
    let data = file_bytes();
    let first16k = md5::compute(&data[..data.len().min(16 * 1024)]).0;
    derive_file_id(&first16k, data.len() as u64, FILENAME.as_bytes())
}

#[test]
fn cap_value_is_pinned() {
    assert_eq!(CAP, 256 << 20, "local literal must be 256 MiB");
    assert_eq!(
        MAX_BLOCK_SIZE, CAP,
        "crate cap moved; this pin exists to catch exactly that"
    );
    assert_eq!(CAP % 4, 0, "cap must stay a multiple of 4");
    assert_eq!(CAP_NEXT_ALIGNED, CAP + 4);
    assert_eq!(ALIGNED_U64_MAX % 4, 0);
}

#[test]
fn main_packet_at_cap_is_accepted_and_verifies() {
    let data = file_bytes();
    let crc = padded_block_crc(&data, CAP);
    let set_bytes = set_bytes_for(CAP, crc);
    let set = RecoverySet::parse(&set_bytes).expect("cap-sized Main must parse");
    assert_eq!(set.block_size, CAP);
    set.verify(FILENAME, &data)
        .expect("cap-sized set must verify");
}

#[test]
fn just_over_cap_is_rejected_with_bound_message() {
    let file_id = fixture_file_id();
    for block_size in [CAP_NEXT_ALIGNED, ALIGNED_U64_MAX] {
        let bytes = main_only_bytes(block_size, &file_id);
        let err = RecoverySet::parse(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("exceeds the supported bound"),
            "block size {block_size}: want exceeds-bound rejection, got: {err}"
        );
    }
}

#[test]
fn unaligned_over_cap_values_hit_the_alignment_guard_first() {
    // CAP + 1 (1 mod 4) and u64::MAX (3 mod 4) never reach the bound
    // branch: the multiple-of-4 guard runs first in source order. Both are
    // still bounded parse-time rejections — no allocation, no hashing.
    let file_id = fixture_file_id();
    assert_eq!((CAP + 1) % 4, 1);
    assert_eq!(u64::MAX % 4, 3);
    for block_size in [CAP + 1, u64::MAX] {
        let bytes = main_only_bytes(block_size, &file_id);
        let err = RecoverySet::parse(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("not a non-zero multiple of 4"),
            "block size {block_size}: want alignment-guard rejection, got: {err}"
        );
    }
}
