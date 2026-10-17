//! Acceptance tests: a *present* but malformed `=yend size=` declaration must
//! be rejected, while an *absent* trailer size stays optional.
//!
//! Contract under test (for the Builder):
//! - Decoder entry point: `nntune_core::yenc::decode_to` (single-part and
//!   multi-part paths).
//! - Present-but-invalid trailer sizes — empty, non-numeric, trailing-junk,
//!   negative, or out-of-range/overflowing decimals — fail with the existing
//!   malformed-article taxonomy: `nntune_core::Error::Malformed`. They must
//!   not be silently treated as an omitted (optional) size.
//! - A present valid trailer size must equal the decoded payload length.
//! - An absent trailer size (and the existing optional CRC behaviour) is
//!   preserved: such articles still decode to the original bytes.
//!
//! Each article below is produced by the crate's own encoder and then mutated
//! only in the `=yend size=` token, so every other check (header size,
//! `=ypart` range, CRC, destination bounds) passes on its own merits.

use nntune_core::yenc::{decode_to, encode_segment, SegmentParams};
use nntune_core::Error;

fn single(payload: &[u8]) -> Vec<u8> {
    let mut article = Vec::new();
    encode_segment(&mut article, &SegmentParams::single("t.bin"), payload).unwrap();
    article
}

fn multipart(payload: &[u8]) -> Vec<u8> {
    // Part 1 of 2 covering the first `payload.len()` bytes of a file twice
    // that size, so the =ypart range is consistent with the payload.
    let len = payload.len() as u64;
    let mut article = Vec::new();
    let params = SegmentParams {
        name: "m.bin".into(),
        part: 1,
        total: 2,
        begin: 1,
        end: len,
        file_size: 2 * len,
    };
    encode_segment(&mut article, &params, payload).unwrap();
    article
}

/// Replace only the `=yend size=` value. `None` removes the whole
/// `size=<value> ` token, leaving the rest of the trailer untouched.
fn with_trailer_size(article: &[u8], size: Option<&str>) -> Vec<u8> {
    let needle = b"=yend size=";
    let start = article
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("encoded article has a =yend size= trailer")
        + needle.len();
    let mut end = start;
    while end < article.len() && article[end] != b' ' && article[end] != b'\r' {
        end += 1;
    }
    let mut out = Vec::new();
    match size {
        Some(value) => {
            out.extend_from_slice(&article[..start]);
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(&article[end..]);
        }
        None => {
            // Drop `size=<value>` and the single separator that follows it.
            out.extend_from_slice(&article[..start - "size=".len()]);
            let rest = if article.get(end) == Some(&b' ') {
                &article[end + 1..]
            } else {
                &article[end..]
            };
            out.extend_from_slice(rest);
        }
    }
    out
}

fn assert_decodes_to(article: &[u8], payload: &[u8], label: &str) {
    let mut dst = vec![0u8; payload.len() + 64];
    let n = decode_to("trailer-size", article, &mut dst)
        .unwrap_or_else(|e| panic!("{label}: expected successful decode, got {e}"));
    assert_eq!(n, payload.len(), "{label}: decoded length");
    assert_eq!(&dst[..n], payload, "{label}: decoded bytes");
}

fn assert_malformed(article: &[u8], payload_len: usize, label: &str) {
    let mut dst = vec![0u8; payload_len + 64];
    match decode_to("trailer-size", article, &mut dst) {
        Err(Error::Malformed(_)) => {}
        Err(other) => panic!("{label}: expected Error::Malformed, got {other}"),
        Ok(n) => panic!("{label}: expected Error::Malformed, decoded {n} bytes instead"),
    }
}

/// As [`assert_malformed`] for every [`INVALID_SIZES`] value, but reports all
/// values that slip through in one run instead of stopping at the first.
fn assert_all_invalid_sizes_malformed(good: &[u8], payload_len: usize, prefix: &str) {
    let mut slipped = Vec::new();
    for (label, value) in INVALID_SIZES {
        let article = with_trailer_size(good, Some(value));
        let mut dst = vec![0u8; payload_len + 64];
        match decode_to("trailer-size", &article, &mut dst) {
            Err(Error::Malformed(_)) => {}
            Err(other) => slipped.push(format!("{label} size={value:?}: got {other}")),
            Ok(n) => slipped.push(format!("{label} size={value:?}: decoded {n} bytes")),
        }
    }
    assert!(
        slipped.is_empty(),
        "{prefix}: present-but-invalid trailer sizes not rejected as Error::Malformed:\n  {}",
        slipped.join("\n  ")
    );
}

/// Trailer `size=` values that are present but not a valid in-range,
/// non-negative decimal. Every one must be rejected as malformed — none may
/// fall back to the "no trailer size declared" path.
const INVALID_SIZES: &[(&str, &str)] = &[
    ("empty", ""),
    ("non-numeric", "bogus"),
    ("trailing junk", "5junk"),
    ("decimal point", "5.0"),
    ("hex-like", "0x5"),
    ("negative", "-1"),
    ("negative equal magnitude", "-5"),
    ("i64 overflow by one", "9223372036854775808"),
    ("u64 overflow by one", "18446744073709551616"),
    ("huge overflow", "999999999999999999999999999999999999999"),
    ("negative underflow", "-9223372036854775809"),
];

#[test]
fn single_part_valid_trailer_size_is_accepted() {
    let payload = b"hello";
    assert_decodes_to(&single(payload), payload, "single valid control");
}

#[test]
fn single_part_absent_trailer_size_stays_optional() {
    let payload = b"hello";
    let article = with_trailer_size(&single(payload), None);
    assert_decodes_to(&article, payload, "single absent trailer size");
}

#[test]
fn single_part_absent_trailer_size_and_crc_stay_optional() {
    // Preserves the existing optional-metadata contract wholesale: a bare
    // `=yend` trailer still decodes.
    // Build via the encoder, then strip everything after `=yend`.
    let mut encoded = single(b"hello");
    let yend = encoded
        .windows(5)
        .position(|w| w == b"=yend")
        .expect("trailer present");
    encoded.truncate(yend);
    encoded.extend_from_slice(b"=yend\r\n");
    assert_decodes_to(&encoded, b"hello", "single bare =yend");
}

#[test]
fn single_part_malformed_trailer_sizes_are_rejected() {
    let payload = b"hello";
    let good = single(payload);
    assert_all_invalid_sizes_malformed(&good, payload.len(), "single");
}

#[test]
fn single_part_wrong_but_numeric_trailer_sizes_are_rejected() {
    let payload = b"hello";
    let good = single(payload);
    for value in ["0", "4", "6", "500"] {
        let article = with_trailer_size(&good, Some(value));
        assert_malformed(
            &article,
            payload.len(),
            &format!("single wrong size={value}"),
        );
    }
}

#[test]
fn multipart_valid_trailer_size_is_accepted() {
    let payload = b"hello";
    assert_decodes_to(&multipart(payload), payload, "multipart valid control");
}

#[test]
fn multipart_absent_trailer_size_stays_optional() {
    let payload = b"hello";
    let article = with_trailer_size(&multipart(payload), None);
    assert_decodes_to(&article, payload, "multipart absent trailer size");
}

#[test]
fn multipart_malformed_trailer_sizes_are_rejected() {
    let payload = b"hello";
    let good = multipart(payload);
    assert_all_invalid_sizes_malformed(&good, payload.len(), "multipart");
}

#[test]
fn multipart_wrong_but_numeric_trailer_sizes_are_rejected() {
    let payload = b"hello";
    let good = multipart(payload);
    // 10 is the whole-file size: the trailer declares the *part* size, so
    // even the file size is a wrong trailer size here.
    for value in ["0", "4", "6", "10"] {
        let article = with_trailer_size(&good, Some(value));
        assert_malformed(
            &article,
            payload.len(),
            &format!("multipart wrong size={value}"),
        );
    }
}

#[test]
fn malformed_trailer_size_is_rejected_for_empty_payload_too() {
    let good = single(b"");
    // Valid control: size=0 on an empty payload decodes.
    assert_decodes_to(&good, b"", "empty valid control");
    assert_all_invalid_sizes_malformed(&good, 0, "empty payload");
}
