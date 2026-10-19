//! Acceptance tests: single-part yEnc checksum precedence is
//! `crc32=` then `pcrc32=` (matching the stream decoder comment).
//!
//! A single-part article carrying both checksums with disagreeing values
//! (matching `crc32=`, mismatching `pcrc32=`) must decode: the whole-file
//! `crc32=` covers the payload here (part == whole file), so it governs and
//! the disagreeing `pcrc32=` must not veto it. Field order in the trailer
//! must not matter. This is assertion-RED on the pre-fix core decoder,
//! which prefers `pcrc32=` then `crc32=` for single-part articles.
//!
//! Multipart articles stay `pcrc32=`-only: a matching `pcrc32=` decodes even
//! next to a differing whole-file `crc32=`, and a mismatching `pcrc32=` is
//! rejected even when a `crc32=` that equals the part CRC is present.
//! A present-but-malformed selected field fails closed (no fall-through to
//! the other field or to success).
//!
//! Each article is produced by the crate's own encoder and then mutated only
//! in its `=yend` trailer checksum tokens. The payload is a tiny synthetic
//! two-part file (`abcdef` = `abc` + `def`) whose whole-file CRC differs
//! from each part CRC. No real Usenet articles and no external endpoints.

use nntune_core::yenc::{decode_to, encode_segment, SegmentParams};
use nntune_core::Error;

const WHOLE: &[u8] = b"abcdef";
const PART1: &[u8] = b"abc";
const PART2: &[u8] = b"def";

fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

fn single(payload: &[u8]) -> Vec<u8> {
    let mut article = Vec::new();
    encode_segment(&mut article, &SegmentParams::single("t.bin"), payload).unwrap();
    article
}

/// One part of the two-part `WHOLE` file; `payload` must be `PART1`/`PART2`.
fn multipart(part: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u64;
    let begin = if part == 1 { 1 } else { 1 + PART1.len() as u64 };
    let mut article = Vec::new();
    let params = SegmentParams {
        name: "m.bin".into(),
        part,
        total: 2,
        begin,
        end: begin + len - 1,
        file_size: WHOLE.len() as u64,
    };
    encode_segment(&mut article, &params, payload).unwrap();
    article
}

/// Replace everything from `=yend` onward with `trailer`, leaving the
/// header, `=ypart` line and encoded body byte-identical.
fn with_trailer(article: &[u8], trailer: &str) -> Vec<u8> {
    let start = article
        .windows(5)
        .position(|w| w == b"=yend")
        .expect("encoded article has a =yend trailer");
    let mut out = article[..start].to_vec();
    out.extend_from_slice(trailer.as_bytes());
    out
}

/// Single-part article with both checksums disagreeing: `crc32=` matches the
/// payload, `pcrc32=` does not. The `crc_first` flag selects trailer order.
fn single_both_disagreeing(crc_first: bool) -> Vec<u8> {
    let good = crc32(WHOLE);
    let bad = good ^ 1;
    let trailer = if crc_first {
        format!(
            "=yend size={} crc32={good:08x} pcrc32={bad:08x}\r\n",
            WHOLE.len()
        )
    } else {
        format!(
            "=yend size={} pcrc32={bad:08x} crc32={good:08x}\r\n",
            WHOLE.len()
        )
    };
    with_trailer(&single(WHOLE), &trailer)
}

fn assert_decodes_to(article: &[u8], payload: &[u8], label: &str) {
    let mut dst = vec![0u8; payload.len() + 64];
    let n = decode_to("single-part-crc-precedence", article, &mut dst)
        .unwrap_or_else(|e| panic!("{label}: expected successful decode, got {e}"));
    assert_eq!(n, payload.len(), "{label}: decoded length");
    assert_eq!(&dst[..n], payload, "{label}: decoded bytes");
}

fn assert_crc_mismatch(article: &[u8], payload_len: usize, want: u32, got: u32, label: &str) {
    let mut dst = vec![0u8; payload_len + 64];
    match decode_to("single-part-crc-precedence", article, &mut dst) {
        Err(Error::CrcMismatch {
            want: w, got: g, ..
        }) => {
            assert_eq!((w, g), (want, got), "{label}: CrcMismatch want/got");
        }
        Err(other) => panic!("{label}: expected Error::CrcMismatch, got {other}"),
        Ok(n) => panic!("{label}: expected Error::CrcMismatch, decoded {n} bytes instead"),
    }
}

fn assert_malformed(article: &[u8], payload_len: usize, label: &str) {
    let mut dst = vec![0u8; payload_len + 64];
    match decode_to("single-part-crc-precedence", article, &mut dst) {
        Err(Error::Malformed(_)) => {}
        Err(other) => panic!("{label}: expected Error::Malformed, got {other}"),
        Ok(n) => panic!("{label}: expected Error::Malformed, decoded {n} bytes instead"),
    }
}

#[test]
fn disagreeing_checksums_differ() {
    assert_ne!(
        crc32(WHOLE),
        crc32(WHOLE) ^ 1,
        "fixture premise: crc32 and pcrc32 values must disagree"
    );
    assert_ne!(crc32(WHOLE), crc32(PART1), "whole vs part 1 CRC");
    assert_ne!(crc32(WHOLE), crc32(PART2), "whole vs part 2 CRC");
}

#[test]
fn single_matching_crc_with_mismatching_pcrc_decodes_crc_first() {
    assert_decodes_to(
        &single_both_disagreeing(true),
        WHOLE,
        "single-part crc32 then pcrc32, crc32 matches",
    );
}

#[test]
fn single_matching_crc_with_mismatching_pcrc_decodes_pcrc_first() {
    assert_decodes_to(
        &single_both_disagreeing(false),
        WHOLE,
        "single-part pcrc32 then crc32, crc32 matches",
    );
}

#[test]
fn single_mismatching_crc_with_matching_pcrc_is_rejected() {
    // `crc32=` is the selected single-part field: a valid-but-mismatching
    // `crc32=` must be rejected even when `pcrc32=` matches. The selected
    // field governs and never falls through to the other field.
    let good = crc32(WHOLE);
    let bad = good ^ 1;
    for trailer in [
        format!(
            "=yend size={} crc32={bad:08x} pcrc32={good:08x}\r\n",
            WHOLE.len()
        ),
        format!(
            "=yend size={} pcrc32={good:08x} crc32={bad:08x}\r\n",
            WHOLE.len()
        ),
    ] {
        let article = with_trailer(&single(WHOLE), &trailer);
        assert_crc_mismatch(
            &article,
            WHOLE.len(),
            bad,
            good,
            &format!("single-part mismatching crc32 with matching pcrc32: {trailer}"),
        );
    }
}

#[test]
fn multipart_matching_pcrc_with_differing_whole_crc_decodes() {
    // `pcrc32=` governs the part; the whole-file `crc32=` must not veto it.
    for (part, payload) in [(1, PART1), (2, PART2)] {
        for trailer in [
            format!(
                "=yend size={} part={part} pcrc32={:08x} crc32={:08x}\r\n",
                payload.len(),
                crc32(payload),
                crc32(WHOLE)
            ),
            format!(
                "=yend size={} part={part} crc32={:08x} pcrc32={:08x}\r\n",
                payload.len(),
                crc32(WHOLE),
                crc32(payload)
            ),
        ] {
            let article = with_trailer(&multipart(part, payload), &trailer);
            assert_decodes_to(
                &article,
                payload,
                &format!("multipart part {part} both checksums: {trailer}"),
            );
        }
    }
}

#[test]
fn multipart_mismatching_pcrc_with_matching_crc_is_rejected() {
    // Even a `crc32=` that equals the part CRC must not rescue a part whose
    // `pcrc32=` mismatches.
    let wrong = crc32(PART1) ^ 1;
    let article = with_trailer(
        &multipart(1, PART1),
        &format!(
            "=yend size={} part=1 pcrc32={wrong:08x} crc32={:08x}\r\n",
            PART1.len(),
            crc32(PART1)
        ),
    );
    assert_crc_mismatch(
        &article,
        PART1.len(),
        wrong,
        crc32(PART1),
        "multipart mismatching pcrc32 with part-crc crc32 present",
    );
}

#[test]
fn single_malformed_crc_with_valid_pcrc_is_rejected() {
    // `crc32=` is the selected single-part field: bad syntax there must not
    // fall through to a good `pcrc32=` next to it.
    let good = crc32(WHOLE);
    for (label, value) in [
        ("non-hex", "zzzzzzzz".to_string()),
        ("empty", String::new()),
        ("overflow", "100000000".to_string()),
    ] {
        for trailer in [
            format!(
                "=yend size={} crc32={value} pcrc32={good:08x}\r\n",
                WHOLE.len()
            ),
            format!(
                "=yend size={} pcrc32={good:08x} crc32={value}\r\n",
                WHOLE.len()
            ),
        ] {
            let article = with_trailer(&single(WHOLE), &trailer);
            assert_malformed(
                &article,
                WHOLE.len(),
                &format!("single-part crc32 {label}: {trailer}"),
            );
        }
    }
}

#[test]
fn multipart_malformed_pcrc_with_valid_crc_is_rejected() {
    // `pcrc32=` is the selected multipart field: bad syntax there must not
    // fall through to `crc32=` or to success.
    for (label, value) in [
        ("non-hex", "zzzzzzzz".to_string()),
        ("empty", String::new()),
        ("overflow", "100000000".to_string()),
    ] {
        let article = with_trailer(
            &multipart(1, PART1),
            &format!(
                "=yend size={} part=1 pcrc32={value} crc32={:08x}\r\n",
                PART1.len(),
                crc32(PART1)
            ),
        );
        assert_malformed(&article, PART1.len(), &format!("multipart pcrc32 {label}"));
    }
}
