//! Acceptance tests: a multipart yEnc article is validated against its
//! *part* checksum (`pcrc32=`) only. The whole-file checksum (`crc32=`)
//! covers bytes this article does not contain, so it must never be compared
//! against the decoded part alone.
//!
//! Contract under test (for the Builder), via `nntune_core::yenc::decode_to`:
//! - Multipart, `pcrc32=` present: it is checked against the decoded part
//!   (match decodes, mismatch is `Error::CrcMismatch`), whether or not a
//!   whole-file `crc32=` is also present, in either field order.
//! - Multipart, only whole-file `crc32=` present (no optional `pcrc32=`):
//!   the article still decodes. The whole-file value cannot be verified
//!   from one part and must not be used as if it were the part checksum.
//! - Multipart, neither checksum present: still decodes (checksums stay
//!   optional; none becomes mandatory).
//! - A present but malformed applicable checksum (non-hex, empty, trailing
//!   junk) is still rejected as `Error::Malformed`; uppercase hex stays
//!   acceptable.
//! - Single-part checksum behaviour is unchanged: `crc32=` (and a lone
//!   `pcrc32=`, where part == whole file) is checked against the payload,
//!   and an absent checksum stays optional.
//! - Declared trailer size and destination bounds are still enforced on
//!   multipart articles.
//!
//! The payload is a tiny synthetic two-part file (`abcdef` = `abc` + `def`)
//! whose whole-file CRC differs from each part CRC (pinned by
//! `whole_file_crc_differs_from_each_part_crc`). Each article is produced
//! by the crate's own encoder and then mutated only in its `=yend` trailer
//! checksum tokens, so header size, `=ypart` range, trailer size, part
//! number and encoded body all pass on their own merits. No real Usenet
//! articles and no external endpoints are used.
//!
//! Deliberately not pinned: the *syntax* handling of a whole-file `crc32=`
//! token on a multipart article whose value is not compared, and any
//! whole-file reassembly/verification feature (out of scope).

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

fn assert_decodes_to(article: &[u8], payload: &[u8], label: &str) {
    let mut dst = vec![0u8; payload.len() + 64];
    let n = decode_to("part-crc-scope", article, &mut dst)
        .unwrap_or_else(|e| panic!("{label}: expected successful decode, got {e}"));
    assert_eq!(n, payload.len(), "{label}: decoded length");
    assert_eq!(&dst[..n], payload, "{label}: decoded bytes");
}

fn assert_crc_mismatch(article: &[u8], payload_len: usize, want: u32, got: u32, label: &str) {
    let mut dst = vec![0u8; payload_len + 64];
    match decode_to("part-crc-scope", article, &mut dst) {
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
    match decode_to("part-crc-scope", article, &mut dst) {
        Err(Error::Malformed(_)) => {}
        Err(other) => panic!("{label}: expected Error::Malformed, got {other}"),
        Ok(n) => panic!("{label}: expected Error::Malformed, decoded {n} bytes instead"),
    }
}

/// Present-but-malformed checksum values: not valid hex for a CRC32. None
/// may be silently treated as an omitted (optional) checksum.
const MALFORMED_CHECKSUMS: &[(&str, &str)] = &[
    ("non-hex", "zzzzzzzz"),
    ("empty", ""),
    ("trailing junk", "352441c2junk"),
];

#[test]
fn whole_file_crc_differs_from_each_part_crc() {
    // Premise of every case below: if the whole-file CRC happened to equal
    // a part CRC, a decoder that wrongly falls back to `crc32=` for a part
    // could pass by accident.
    assert_ne!(crc32(WHOLE), crc32(PART1), "whole vs part 1 CRC");
    assert_ne!(crc32(WHOLE), crc32(PART2), "whole vs part 2 CRC");
    assert_ne!(crc32(PART1), crc32(PART2), "part 1 vs part 2 CRC");
}

#[test]
fn multipart_whole_file_crc_without_pcrc_decodes_each_part() {
    // Core regression: `crc32=` here is the *whole-file* CRC and the
    // optional `pcrc32=` is absent, so there is no part checksum to check.
    // Both parts must decode and reassemble to the whole file. All part
    // results are reported in one run instead of stopping at the first.
    let whole_crc = crc32(WHOLE);
    let mut reassembled = Vec::new();
    let mut failures = Vec::new();
    for (part, payload) in [(1, PART1), (2, PART2)] {
        let article = with_trailer(
            &multipart(part, payload),
            &format!(
                "=yend size={} part={part} crc32={whole_crc:08x}\r\n",
                payload.len()
            ),
        );
        let mut dst = vec![0u8; payload.len() + 64];
        match decode_to("part-crc-scope", &article, &mut dst) {
            Ok(n) if &dst[..n] == payload => reassembled.extend_from_slice(&dst[..n]),
            Ok(n) => failures.push(format!("part {part}: decoded wrong bytes {n}")),
            Err(e) => failures.push(format!("part {part}: {e}")),
        }
    }
    assert!(
        failures.is_empty(),
        "multipart whole-file-crc-only articles must decode:\n  {}",
        failures.join("\n  ")
    );
    assert_eq!(reassembled, WHOLE, "parts reassemble to the whole file");
}

#[test]
fn multipart_matching_pcrc_without_whole_crc_decodes() {
    // Positive control: this is also the encoder's own multipart framing.
    for (part, payload) in [(1, PART1), (2, PART2)] {
        assert_decodes_to(
            &multipart(part, payload),
            payload,
            &format!("multipart part {part} encoder-default pcrc32"),
        );
        let article = with_trailer(
            &multipart(part, payload),
            &format!(
                "=yend size={} part={part} pcrc32={:08x}\r\n",
                payload.len(),
                crc32(payload)
            ),
        );
        assert_decodes_to(
            &article,
            payload,
            &format!("multipart part {part} pcrc32 only"),
        );
    }
}

#[test]
fn multipart_mismatching_pcrc_without_whole_crc_is_rejected() {
    // The applicable part checksum must not be skipped: a pcrc32 that does
    // not match the decoded part fails, naming the part CRC as `got`.
    for (part, payload) in [(1, PART1), (2, PART2)] {
        let wrong = crc32(payload) ^ 1;
        let article = with_trailer(
            &multipart(part, payload),
            &format!(
                "=yend size={} part={part} pcrc32={wrong:08x}\r\n",
                payload.len()
            ),
        );
        assert_crc_mismatch(
            &article,
            payload.len(),
            wrong,
            crc32(payload),
            &format!("multipart part {part} mismatching pcrc32"),
        );
    }
}

#[test]
fn multipart_both_checksums_with_matching_pcrc_decodes() {
    // Both fields present: the matching pcrc32 governs; the whole-file
    // crc32 (which differs from the part CRC) must not veto the part.
    // Field order in the trailer must not matter.
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
fn multipart_both_checksums_with_mismatching_pcrc_is_rejected() {
    // A correct whole-file crc32 must not rescue a part whose pcrc32
    // mismatches: the part checksum is the one that applies.
    let wrong = crc32(PART1) ^ 1;
    let article = with_trailer(
        &multipart(1, PART1),
        &format!(
            "=yend size={} part=1 pcrc32={wrong:08x} crc32={:08x}\r\n",
            PART1.len(),
            crc32(WHOLE)
        ),
    );
    assert_crc_mismatch(
        &article,
        PART1.len(),
        wrong,
        crc32(PART1),
        "multipart mismatching pcrc32 with whole-file crc32 present",
    );
}

#[test]
fn multipart_without_any_checksum_decodes() {
    // Optional-field compatibility: no checksum becomes mandatory.
    for (part, payload) in [(1, PART1), (2, PART2)] {
        let article = with_trailer(
            &multipart(part, payload),
            &format!("=yend size={} part={part}\r\n", payload.len()),
        );
        assert_decodes_to(
            &article,
            payload,
            &format!("multipart part {part} no checksums"),
        );
    }
}

#[test]
fn multipart_malformed_pcrc_is_rejected_as_malformed() {
    for (label, value) in MALFORMED_CHECKSUMS {
        let article = with_trailer(
            &multipart(1, PART1),
            &format!("=yend size={} part=1 pcrc32={value}\r\n", PART1.len()),
        );
        assert_malformed(&article, PART1.len(), &format!("multipart pcrc32 {label}"));
    }
}

#[test]
fn multipart_uppercase_hex_pcrc_decodes() {
    let article = with_trailer(
        &multipart(1, PART1),
        &format!(
            "=yend size={} part=1 pcrc32={:08X}\r\n",
            PART1.len(),
            crc32(PART1)
        ),
    );
    assert_decodes_to(&article, PART1, "multipart uppercase pcrc32");
}

#[test]
fn multipart_size_and_destination_bounds_still_enforced() {
    // Preserved guards: fixing checksum scope must not bypass the declared
    // part size (here the whole-file size is a *wrong* trailer size for a
    // part) or the destination bound.
    let wrong_size = with_trailer(
        &multipart(1, PART1),
        &format!(
            "=yend size={} part=1 crc32={:08x}\r\n",
            WHOLE.len(),
            crc32(WHOLE)
        ),
    );
    let mut dst = vec![0u8; WHOLE.len() + 64];
    assert!(
        decode_to("part-crc-scope", &wrong_size, &mut dst).is_err(),
        "trailer size naming the whole file must still be rejected for a part"
    );

    let mut too_small = vec![0u8; PART1.len() - 1];
    assert!(
        decode_to("part-crc-scope", &multipart(1, PART1), &mut too_small).is_err(),
        "destination smaller than the part must still be rejected"
    );
}

#[test]
fn single_part_matching_crc_decodes() {
    assert_decodes_to(&single(WHOLE), WHOLE, "single-part encoder-default crc32");
}

#[test]
fn single_part_mismatching_crc_is_rejected() {
    // Single-part scope is unchanged: crc32 covers the whole payload here,
    // so a mismatch is still a CrcMismatch against the payload CRC.
    let wrong = crc32(WHOLE) ^ 1;
    let article = with_trailer(
        &single(WHOLE),
        &format!("=yend size={} crc32={wrong:08x}\r\n", WHOLE.len()),
    );
    assert_crc_mismatch(
        &article,
        WHOLE.len(),
        wrong,
        crc32(WHOLE),
        "single-part crc32",
    );
}

#[test]
fn single_part_without_crc_decodes() {
    let article = with_trailer(&single(WHOLE), &format!("=yend size={}\r\n", WHOLE.len()));
    assert_decodes_to(&article, WHOLE, "single-part no checksum");
}

#[test]
fn single_part_malformed_crc_is_rejected_as_malformed() {
    for (label, value) in MALFORMED_CHECKSUMS {
        let article = with_trailer(
            &single(WHOLE),
            &format!("=yend size={} crc32={value}\r\n", WHOLE.len()),
        );
        assert_malformed(&article, WHOLE.len(), &format!("single-part crc32 {label}"));
    }
}

#[test]
fn single_part_pcrc_only_is_still_checked() {
    // Preserves existing single-part behaviour: with no `crc32=`, a lone
    // `pcrc32=` covers the payload (part == whole file), so a match
    // decodes and a mismatch is rejected.
    let matching = with_trailer(
        &single(WHOLE),
        &format!("=yend size={} pcrc32={:08x}\r\n", WHOLE.len(), crc32(WHOLE)),
    );
    assert_decodes_to(&matching, WHOLE, "single-part matching pcrc32 only");

    let wrong = crc32(WHOLE) ^ 1;
    let mismatching = with_trailer(
        &single(WHOLE),
        &format!("=yend size={} pcrc32={wrong:08x}\r\n", WHOLE.len()),
    );
    assert_crc_mismatch(
        &mismatching,
        WHOLE.len(),
        wrong,
        crc32(WHOLE),
        "single-part mismatching pcrc32 only",
    );
}
