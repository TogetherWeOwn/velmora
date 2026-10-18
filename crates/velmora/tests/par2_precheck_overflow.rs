//! Pin for the PAR2 precheck segment-sum overflow arm
//! (`crates/nntune-core/src/par2.rs:457-458`): segment lengths summing past
//! `u64::MAX` must surface the exact overflow message, never wrap.
//!
//! Controls:
//! - just below `u64::MAX` avoids the overflow arm (length-mismatch arm
//!   fires instead);
//! - an empty IFSC (no block checksums) hits the adjacent early return.

use nntune_core::error::Error;
use nntune_core::par2::RecoverySet;

const BLOCK_SIZE: u64 = 256;
const FILENAME: &str = "track.flac";
const OVERFLOW_MSG: &str = "par2 precheck: segment length sum overflows u64";
const LENGTH_MISMATCH_MSG: &str =
    "par2 precheck: segment lengths do not sum to the recovery set's file length";
const NO_BLOCKS_MSG: &str = "par2 precheck: recovery set carries no block checksums for this file";

fn file_bytes() -> Vec<u8> {
    let mut x = 0x51ab_3c7d_29e1_04f5u64;
    let mut out = vec![0u8; 1000];
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
    out
}

fn block_crcs(data: &[u8]) -> Vec<u32> {
    data.chunks(BLOCK_SIZE as usize)
        .map(|block| {
            let mut h = crc32fast::Hasher::new();
            h.update(block);
            if block.len() < BLOCK_SIZE as usize {
                h.update(&vec![0u8; BLOCK_SIZE as usize - block.len()]);
            }
            h.finalize()
        })
        .collect()
}

fn packet(set_id: &[u8; 16], kind: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut aligned = body.to_vec();
    while aligned.len() % 4 != 0 {
        aligned.push(0);
    }
    let mut p = Vec::new();
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&((64 + aligned.len()) as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
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

fn fixture_with_crcs(crcs: Vec<u32>, block_size: u64) -> Vec<u8> {
    let data = file_bytes();
    let whole_md5 = md5::compute(&data).0;
    let first16k = md5::compute(&data[..data.len().min(16 * 1024)]).0;
    let mut seed = Vec::new();
    seed.extend_from_slice(&first16k);
    seed.extend_from_slice(&(data.len() as u64).to_le_bytes());
    seed.extend_from_slice(FILENAME.as_bytes());
    let file_id = md5::compute(&seed).0;

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
    while fd_body.len() % 4 != 0 {
        fd_body.push(0);
    }

    let mut ifsc_body = Vec::new();
    ifsc_body.extend_from_slice(&file_id);
    for crc in crcs {
        ifsc_body.extend_from_slice(&[0u8; 16]);
        ifsc_body.extend_from_slice(&crc.to_le_bytes());
    }

    let mut rs_body = Vec::new();
    rs_body.extend_from_slice(&7u32.to_le_bytes());

    let mut set_bytes = Vec::new();
    set_bytes.extend(packet(&set_id, &ptype(b"FileDesc"), &fd_body));
    set_bytes.extend(packet(&set_id, &ptype(b"RecvSlic"), &rs_body));
    set_bytes.extend(packet(&set_id, &ptype(b"IFSC\0\0\0\0"), &ifsc_body));
    set_bytes.extend(packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body));
    set_bytes
}

fn healthy_set_bytes() -> Vec<u8> {
    fixture_with_crcs(block_crcs(&file_bytes()), BLOCK_SIZE)
}

fn malformed_message(err: &Error) -> &str {
    match err {
        Error::Malformed(msg) => msg.as_str(),
        other => panic!("expected Error::Malformed, got {other:?}"),
    }
}

#[test]
fn segment_lengths_summing_past_u64_max_yield_exact_overflow_message() {
    let set = RecoverySet::parse(&healthy_set_bytes()).expect("valid set parses");
    // 0 + u64::MAX fits; +1 more wraps past u64::MAX.
    let segments = [(0x1234_5678u32, u64::MAX), (0x9abc_def0u32, 1u64)];
    let err = set.precheck(FILENAME, &segments).unwrap_err();
    assert_eq!(
        malformed_message(&err),
        OVERFLOW_MSG,
        "overflow arm must pin the exact message, got: {err}"
    );
}

#[test]
fn just_below_u64_max_avoids_the_overflow_arm() {
    let set = RecoverySet::parse(&healthy_set_bytes()).expect("valid set parses");
    // Sums to u64::MAX - 1: no checked_add can fail, so the length-mismatch
    // arm (not the overflow arm) must fire.
    let segments = [(0x1234_5678u32, u64::MAX - 1)];
    let err = set.precheck(FILENAME, &segments).unwrap_err();
    assert_eq!(
        malformed_message(&err),
        LENGTH_MISMATCH_MSG,
        "just-below-MAX must miss the overflow arm, got: {err}"
    );
}

#[test]
fn empty_block_checksums_hit_the_adjacent_early_return() {
    let set = RecoverySet::parse(&fixture_with_crcs(Vec::new(), BLOCK_SIZE)).expect("set parses");
    let err = set.precheck(FILENAME, &[]).unwrap_err();
    assert_eq!(
        malformed_message(&err),
        NO_BLOCKS_MSG,
        "empty IFSC must hit the no-checksums early return, got: {err}"
    );
}
