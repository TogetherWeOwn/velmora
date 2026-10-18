//! Pin for the PAR2 packet-framing rejections
//! (`crates/nntune-core/src/par2.rs:169-180`, via [`RecoverySet::parse`]):
//! a stream shorter than the 64-byte header, a wrong magic, and a bad length
//! must each fail closed with the exact framing message, while a minimal
//! well-formed single-packet (lone Main) set parses to `Ok`.
//!
//! Sensitivity: every rejection asserts the exact `Error::Malformed` payload
//! (including the `offset 0` suffix), so any rewording, reorder of the three
//! guards, or silent skip shows up as a test failure rather than a silent
//! behavior change. The bad-length test covers all three disjuncts
//! (`< 64`, non-multiple of 4, past end of stream) because they share one
//! error string.
//!
//! All packets are constructed byte-for-byte in this file (magic, lengths,
//! checksums, set-ID derivation) with the `packet()` builder copied from
//! `par2_precheck_overflow.rs`, never via the parser under test. The only
//! imports from the crate are the parser entry point (`RecoverySet`) and the
//! error type; hashes come from the format's own crates (`md5`).

use nntune_core::error::Error;
use nntune_core::par2::RecoverySet;

const TRUNCATED_MSG: &str = "par2: malformed recovery set: truncated packet header at offset 0";
const BAD_MAGIC_MSG: &str = "par2: malformed recovery set: bad magic at offset 0";
const BAD_LENGTH_MSG: &str = "par2: malformed recovery set: invalid packet length at offset 0";

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

/// A lone Main packet declaring `block_size` for `file_id`, with a
/// self-consistent set ID so only the framing guards can fire.
fn main_only_bytes(block_size: u64, file_id: &[u8; 16]) -> Vec<u8> {
    let mut main_body = Vec::new();
    main_body.extend_from_slice(&block_size.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes());
    main_body.extend_from_slice(file_id);
    let set_id = md5::compute(&main_body).0;
    packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body)
}

fn malformed_message(err: &Error) -> &str {
    match err {
        Error::Malformed(msg) => msg.as_str(),
        other => panic!("expected Error::Malformed, got {other:?}"),
    }
}

#[test]
fn seven_byte_input_yields_truncated_header() {
    // A magic prefix that never reaches the 64-byte header.
    let err = RecoverySet::parse(b"PAR2\0PK").unwrap_err();
    assert_eq!(
        malformed_message(&err),
        TRUNCATED_MSG,
        "7-byte input must pin the truncated-header message, got: {err}"
    );
}

#[test]
fn wrong_magic_yields_bad_magic() {
    let mut bytes = main_only_bytes(256, &[0x42u8; 16]);
    assert!(
        bytes.len() >= 64,
        "fixture must clear the header-length guard"
    );
    bytes[0] = b'X';
    let err = RecoverySet::parse(&bytes).unwrap_err();
    assert_eq!(
        malformed_message(&err),
        BAD_MAGIC_MSG,
        "wrong magic must pin the bad-magic message, got: {err}"
    );
}

#[test]
fn bad_lengths_yield_invalid_length() {
    let good = main_only_bytes(256, &[0x42u8; 16]);
    // (label, replacement length field): short (< 64), unaligned (% 4 != 0
    // but otherwise in range), and overrunning the stream.
    let cases: &[(&str, u64)] = &[
        ("short", 60),
        ("unaligned", 66),
        ("overrun", good.len() as u64 + 4),
    ];
    for (label, length) in cases {
        let mut bytes = good.clone();
        bytes[8..16].copy_from_slice(&length.to_le_bytes());
        let err = RecoverySet::parse(&bytes).unwrap_err();
        assert_eq!(
            malformed_message(&err),
            BAD_LENGTH_MSG,
            "{label} length ({length}) must pin the invalid-length message, got: {err}"
        );
    }
}

#[test]
fn minimal_well_formed_single_packet_set_parses() {
    let bytes = main_only_bytes(256, &[0x42u8; 16]);
    let set = RecoverySet::parse(&bytes).expect("lone well-formed Main packet must parse");
    assert_eq!(
        set.block_size, 256,
        "framing must preserve the Main slice size"
    );
    assert_eq!(
        set.recovery_blocks, 0,
        "lone Main carries no recovery slices"
    );
}
