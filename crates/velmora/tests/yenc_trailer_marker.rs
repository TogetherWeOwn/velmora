//! Regression tests: the `=yend` trailer keyword must match as a whole
//! token.
//!
//! The decoder previously took any line starting with `=yend` as the
//! trailer, so a malformed `=yending` line ended the body. That line has no
//! `size=` or `crc32=`, so a corrupted body whose decoded length matched the
//! `=ybegin size=` decoded as success with no checksum. The trailer is now
//! `=yend` alone or `=yend` followed by a space or tab; any other `=yend…`
//! line is not a trailer, and an article without one is
//! [`Error::Malformed`].
//!
//! Each article is produced by the crate's own encoder and mutated only in
//! one body byte and the `=yend` line.

use velmora::yenc::{decode_to, encode_segment, SegmentParams};
use velmora::Error;

fn single(payload: &[u8]) -> Vec<u8> {
    let mut article = Vec::new();
    encode_segment(&mut article, &SegmentParams::single("t.bin"), payload).unwrap();
    article
}

fn find(article: &[u8], needle: &[u8]) -> usize {
    article
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present in encoded article")
}

/// Flip the first encoded byte of the body line (the line after `=ybegin`).
fn with_corrupted_body(article: &[u8]) -> Vec<u8> {
    let body_start = find(article, b"\r\n") + 2;
    let mut out = article.to_vec();
    out[body_start] ^= 0x01;
    out
}

/// Replace the whole `=yend` line (up to its terminator) with `line`.
fn with_trailer_line(article: &[u8], line: &[u8]) -> Vec<u8> {
    let trailer_start = find(article, b"=yend");
    let eol = trailer_start
        + article[trailer_start..]
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .expect("trailer line is terminated");
    let mut out = article[..trailer_start].to_vec();
    out.extend_from_slice(line);
    out.extend_from_slice(&article[eol..]);
    out
}

fn trailer_line(article: &[u8]) -> Vec<u8> {
    let trailer_start = find(article, b"=yend");
    let eol = trailer_start
        + article[trailer_start..]
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .expect("trailer line is terminated");
    article[trailer_start..eol].to_vec()
}

fn assert_malformed(article: &[u8], payload_len: usize, label: &str) {
    let mut dst = vec![0u8; payload_len + 64];
    match decode_to("trailer-marker", article, &mut dst) {
        Err(Error::Malformed(_)) => {}
        Err(other) => panic!("{label}: expected Error::Malformed, got {other}"),
        Ok(n) => panic!("{label}: expected Error::Malformed, decoded {n} bytes instead"),
    }
}

#[test]
fn corrupted_body_with_yending_trailer_is_rejected() {
    let payload = b"hello";
    let corrupted = with_corrupted_body(&single(payload));
    // Control: with the real trailer, the corruption is a CRC mismatch.
    let mut dst = vec![0u8; payload.len() + 64];
    match decode_to("trailer-marker", &corrupted, &mut dst) {
        Err(Error::CrcMismatch { .. }) => {}
        other => panic!("corrupted body control: expected CrcMismatch, got {other:?}"),
    }
    let article = with_trailer_line(&corrupted, b"=yending");
    assert_malformed(&article, payload.len(), "corrupted body + =yending");
}

#[test]
fn yend_prefixed_keyword_with_valid_fields_is_not_a_trailer() {
    let payload = b"hello";
    let article = single(payload);
    let mut line = trailer_line(&article);
    line.splice(5..5, b"x".iter().copied());
    assert!(line.starts_with(b"=yendx "));
    let article = with_trailer_line(&article, &line);
    assert_malformed(&article, payload.len(), "=yendx size=… crc32=…");
}

#[test]
fn tab_separated_trailer_is_still_accepted() {
    let payload = b"hello";
    let article = single(payload);
    let mut line = trailer_line(&article);
    line[5] = b'\t';
    let article = with_trailer_line(&article, &line);
    let mut dst = vec![0u8; payload.len() + 64];
    let n = decode_to("trailer-marker", &article, &mut dst).expect("=yend<TAB> trailer decodes");
    assert_eq!(&dst[..n], payload);
}
