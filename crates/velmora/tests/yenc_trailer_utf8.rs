//! Regression tests: a non-UTF-8 byte anywhere in the `=yend` trailer line
//! must not silently disable trailer validation.
//!
//! `header_value` converts the whole line with `from_utf8` and yields `None`
//! on failure, so a stray `0xFF` previously made the trailer look like it
//! declared no `size=` and no CRC at all: a wrong size or a wrong CRC next
//! to the stray byte decoded successfully. The trailer is a pure ASCII
//! `key=value` control line (no filename or free text), so a non-UTF-8
//! trailer is rejected as [`Error::Malformed`] before the size and CRC
//! lookups run.
//!
//! Each article is produced by the crate's own encoder and mutated only in
//! the `=yend` line, so every other check passes on its own merits.

use nntune_core::yenc::{decode_to, encode_segment, SegmentParams};
use nntune_core::Error;

fn single(payload: &[u8]) -> Vec<u8> {
    let mut article = Vec::new();
    encode_segment(&mut article, &SegmentParams::single("t.bin"), payload).unwrap();
    article
}

fn multipart(payload: &[u8]) -> Vec<u8> {
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

fn find(article: &[u8], needle: &[u8]) -> usize {
    article
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present in encoded article")
}

/// Append ` 0xFF` to the `=yend` trailer line, leaving every declared
/// value (correct size, correct CRC) untouched.
fn with_stray_trailer_byte(article: &[u8]) -> Vec<u8> {
    let trailer_start = find(article, b"=yend");
    let eol = trailer_start
        + article[trailer_start..]
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .expect("trailer line is terminated");
    let mut out = article[..eol].to_vec();
    out.extend_from_slice(b" \xff");
    out.extend_from_slice(&article[eol..]);
    out
}

/// Replace the value of the first `key` occurrence after `=yend` with raw
/// bytes (delimited by the next space or end of the trailer line).
fn with_trailer_value(article: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
    let trailer_start = find(article, b"=yend");
    let value_start = trailer_start + find(&article[trailer_start..], key) + key.len();
    let mut value_end = value_start;
    while value_end < article.len()
        && article[value_end] != b' '
        && article[value_end] != b'\r'
        && article[value_end] != b'\n'
    {
        value_end += 1;
    }
    let mut out = article[..value_start].to_vec();
    out.extend_from_slice(value);
    out.extend_from_slice(&article[value_end..]);
    out
}

fn assert_malformed(article: &[u8], payload_len: usize, label: &str) {
    let mut dst = vec![0u8; payload_len + 64];
    match decode_to("trailer-utf8", article, &mut dst) {
        Err(Error::Malformed(_)) => {}
        Err(other) => panic!("{label}: expected Error::Malformed, got {other}"),
        Ok(n) => panic!("{label}: expected Error::Malformed, decoded {n} bytes instead"),
    }
}

#[test]
fn single_part_stray_trailer_byte_is_rejected_despite_valid_size_and_crc() {
    let payload = b"hello";
    let article = with_stray_trailer_byte(&single(payload));
    assert_malformed(&article, payload.len(), "single stray 0xFF trailer byte");
}

#[test]
fn single_part_non_utf8_trailer_size_value_is_rejected() {
    let payload = b"hello";
    let article = with_trailer_value(&single(payload), b"size=", b"\xff");
    assert_malformed(&article, payload.len(), "single size=<0xFF>");
}

#[test]
fn single_part_wrong_size_with_stray_trailer_byte_is_rejected() {
    let payload = b"hello";
    let wrong_size = with_trailer_value(&single(payload), b"size=", b"99");
    let article = with_stray_trailer_byte(&wrong_size);
    assert_malformed(&article, payload.len(), "single size=99 + stray 0xFF");
}

#[test]
fn single_part_wrong_crc_with_stray_trailer_byte_is_rejected() {
    let payload = b"hello";
    // Control: the same wrong CRC without the stray byte is a CRC mismatch,
    // so the mutated article genuinely exercises the CRC check.
    let wrong_crc = with_trailer_value(&single(payload), b"crc32=", b"deadbeef");
    let mut dst = vec![0u8; payload.len() + 64];
    match decode_to("trailer-utf8", &wrong_crc, &mut dst) {
        Err(Error::CrcMismatch { .. }) => {}
        other => panic!("single crc32=deadbeef control: expected CrcMismatch, got {other:?}"),
    }
    let article = with_stray_trailer_byte(&wrong_crc);
    assert_malformed(
        &article,
        payload.len(),
        "single crc32=deadbeef + stray 0xFF",
    );
}

#[test]
fn multipart_stray_trailer_byte_is_rejected_despite_valid_size_and_pcrc() {
    let payload = b"hello";
    let article = with_stray_trailer_byte(&multipart(payload));
    assert_malformed(&article, payload.len(), "multipart stray 0xFF trailer byte");
}

#[test]
fn multipart_wrong_pcrc_with_stray_trailer_byte_is_rejected() {
    let payload = b"hello";
    let wrong_pcrc = with_trailer_value(&multipart(payload), b"pcrc32=", b"deadbeef");
    let article = with_stray_trailer_byte(&wrong_pcrc);
    assert_malformed(
        &article,
        payload.len(),
        "multipart pcrc32=deadbeef + stray 0xFF",
    );
}
