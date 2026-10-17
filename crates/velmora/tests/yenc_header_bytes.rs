//! Acceptance tests: valid ASCII yEnc control fields in the `=ybegin`
//! header must be read without requiring the `name=` filename suffix to
//! be valid UTF-8.
//!
//! Contract under test (for the Builder):
//! - Decoder entry point: `nntune_core::yenc::decode_to` (single-part and
//!   multi-part paths).
//! - An otherwise valid article whose filename carries legacy
//!   Latin-1/CP1252 bytes (or other invalid-UTF-8 byte sequences) decodes
//!   to the exact expected payload. The ASCII control fields before
//!   `name=` (`line=`, `size=`, and for multipart `part=`/`total=`) keep
//!   their meaning.
//! - The filename is the last field on the `=ybegin` line: bytes after
//!   `name=` are filename bytes only and must never be reinterpreted as
//!   new control tags (`size=`, `part=`, …), even when they contain
//!   tag-looking ASCII after a non-UTF-8 byte.
//! - Nothing else loosens: malformed or wrong numeric header fields,
//!   destination bounds, checksum mismatches, and the strict
//!   malformed-trailer-size behaviour are all preserved when the
//!   filename is non-UTF-8.
//! - Filenames are not transcoded or rewritten by these tests; only the
//!   decoded payload is asserted, so no display/encoding policy is pinned.
//!
//! Each article is produced by the crate's own encoder and then mutated
//! only in the `name=` bytes of the `=ybegin` line (except the rejection
//! controls, which additionally mutate exactly the field named by the
//! test), so header/ypart/trailer sizes and CRCs stay self-consistent.

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

/// Replace only the filename bytes after `name=` on the `=ybegin` line
/// (up to the line's `\r`). Every other byte of the article is untouched.
fn with_name_bytes(article: &[u8], name: &[u8]) -> Vec<u8> {
    assert!(
        !name.contains(&b'\r') && !name.contains(&b'\n'),
        "test bug: filename bytes must stay on the =ybegin line"
    );
    let needle = b" name=";
    let start = article
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("encoded article has a =ybegin name= field")
        + needle.len();
    let end = article[start..]
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .map(|p| start + p)
        .expect("=ybegin line is terminated");
    let mut out = Vec::with_capacity(article.len() - (end - start) + name.len());
    out.extend_from_slice(&article[..start]);
    out.extend_from_slice(name);
    out.extend_from_slice(&article[end..]);
    out
}

/// Replace the `=ybegin … size=` value (the header size, not the trailer).
fn with_header_size(article: &[u8], size: &str) -> Vec<u8> {
    let needle = b"=ybegin";
    let begin = article
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("encoded article has =ybegin");
    let tag = b" size=";
    let start = begin
        + article[begin..]
            .windows(tag.len())
            .position(|w| w == tag)
            .expect("=ybegin line has size=")
        + tag.len();
    let mut end = start;
    while end < article.len() && article[end] != b' ' && article[end] != b'\r' {
        end += 1;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&article[..start]);
    out.extend_from_slice(size.as_bytes());
    out.extend_from_slice(&article[end..]);
    out
}

fn assert_decodes_to(article: &[u8], payload: &[u8], label: &str) {
    let mut dst = vec![0u8; payload.len() + 64];
    let n = decode_to("header-bytes", article, &mut dst)
        .unwrap_or_else(|e| panic!("{label}: expected successful decode, got {e}"));
    assert_eq!(n, payload.len(), "{label}: decoded length");
    assert_eq!(&dst[..n], payload, "{label}: decoded bytes");
}

fn assert_rejected(article: &[u8], payload_len: usize, label: &str) {
    let mut dst = vec![0u8; payload_len + 64];
    match decode_to("header-bytes", article, &mut dst) {
        Err(_) => {}
        Ok(n) => panic!("{label}: expected rejection, decoded {n} bytes instead"),
    }
}

/// Filename byte sequences that are not valid UTF-8 but occur in legacy
/// postings. Each must decode exactly like the ASCII control.
const NON_UTF8_NAMES: &[(&str, &[u8])] = &[
    // Latin-1 ö (0xF6) — the motivating example.
    ("latin-1 o-umlaut", b"Bj\xf6rk.flac"),
    // Latin-1 é (0xE9) and ü (0xFC).
    ("latin-1 e-acute", b"caf\xe9.flac"),
    ("latin-1 u-umlaut", b"\xfcber.flac"),
    // CP1252-only bytes: € (0x80) and curly quotes (0x93/0x94), which are
    // bare continuation bytes in UTF-8 terms.
    ("cp1252 euro sign", b"price \x805.flac"),
    ("cp1252 curly quotes", b"\x93song\x94.flac"),
    // Bytes that are never valid UTF-8 anywhere.
    ("0xff 0xfe", b"\xff\xfetrack.flac"),
    // Truncated UTF-8: lead byte at end of name, and lead byte followed by
    // a non-continuation byte.
    ("truncated utf-8 lead at end", b"track\xc3"),
    ("invalid utf-8 continuation", b"track\xc3(.flac"),
    // Overlong / lone continuation runs.
    ("lone continuations", b"\x80\x80\x80.flac"),
];

#[test]
fn ascii_and_utf8_names_still_decode() {
    let payload = b"hello";
    // Positive controls: plain ASCII and valid UTF-8 (ö as 0xC3 0xB6)
    // names already work and must keep working.
    assert_decodes_to(&single(payload), payload, "ascii name control");
    let utf8 = with_name_bytes(&single(payload), "Björk.flac".as_bytes());
    assert_decodes_to(&utf8, payload, "valid utf-8 name control");
}

#[test]
fn single_part_non_utf8_names_decode_to_payload() {
    let payload = b"hello yEnc";
    let good = single(payload);
    let mut failures = Vec::new();
    for (label, name) in NON_UTF8_NAMES {
        let article = with_name_bytes(&good, name);
        let mut dst = vec![0u8; payload.len() + 64];
        match decode_to("header-bytes", &article, &mut dst) {
            Ok(n) if &dst[..n] == payload => {}
            Ok(n) => failures.push(format!(
                "{label} name={name:?}: decoded {n} wrong bytes {:?}",
                &dst[..n]
            )),
            Err(e) => failures.push(format!("{label} name={name:?}: got {e}")),
        }
    }
    assert!(
        failures.is_empty(),
        "single-part articles with non-UTF-8 filename bytes must decode:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn tiny_single_byte_article_with_latin1_name_decodes() {
    // The smallest motivating case: size=1 followed by a Latin-1 name.
    let payload = b"X";
    let article = with_name_bytes(&single(payload), b"Bj\xf6rk.flac");
    assert_decodes_to(&article, payload, "size=1 latin-1 name");
}

#[test]
fn empty_payload_with_non_utf8_name_decodes() {
    let article = with_name_bytes(&single(b""), b"Bj\xf6rk.flac");
    assert_decodes_to(&article, b"", "empty payload latin-1 name");
}

#[test]
fn multipart_non_utf8_name_decodes_to_payload() {
    let payload = b"hello";
    let article = with_name_bytes(&multipart(payload), b"Bj\xf6rk.flac");
    assert_decodes_to(&article, payload, "multipart latin-1 name");
}

#[test]
fn tag_looking_bytes_inside_filename_are_not_control_fields() {
    let payload = b"hello";
    let good = single(payload);
    // Everything after name= is filename, even ASCII that looks like a
    // control tag after a non-UTF-8 byte. The real size=5 before name=
    // must win over the size=999 inside the filename.
    let article = with_name_bytes(&good, b"Bj\xf6rk size=999 part=9 total=9 line=1.flac");
    assert_decodes_to(&article, payload, "tag-looking filename after space");
    // Same without a separating space.
    let article = with_name_bytes(&good, b"\xf6size=999.flac");
    assert_decodes_to(&article, payload, "tag-looking filename no space");
    // A filename containing =ypart text must not turn a single-part
    // article into a multipart one.
    let article = with_name_bytes(&good, b"\xf6 =ypart begin=1 end=999.flac");
    assert_decodes_to(&article, payload, "ypart-looking filename");
}

#[test]
fn malformed_header_sizes_stay_rejected_with_non_utf8_name() {
    let payload = b"hello";
    for (label, size) in [
        ("empty", ""),
        ("non-numeric", "bogus"),
        ("trailing junk", "5junk"),
        ("negative", "-1"),
        ("overflow", "999999999999999999999999999999999999999"),
    ] {
        // ASCII-name control and Latin-1-name variant must both reject:
        // tolerating non-UTF-8 filenames must not soften numeric parsing.
        let ascii = with_header_size(&single(payload), size);
        assert_rejected(&ascii, payload.len(), &format!("ascii size {label}"));
        let latin1 = with_name_bytes(&ascii, b"Bj\xf6rk.flac");
        assert_rejected(&latin1, payload.len(), &format!("latin-1 size {label}"));
    }
}

#[test]
fn wrong_but_numeric_header_size_stays_rejected_with_non_utf8_name() {
    let payload = b"hello";
    for size in ["0", "4", "6", "500"] {
        let article = with_name_bytes(&with_header_size(&single(payload), size), b"Bj\xf6rk.flac");
        assert_rejected(
            &article,
            payload.len(),
            &format!("latin-1 wrong header size={size}"),
        );
    }
}

#[test]
fn destination_bounds_stay_enforced_with_non_utf8_name() {
    let payload = b"hello";
    let article = with_name_bytes(&single(payload), b"Bj\xf6rk.flac");
    // One byte short: must error, never panic or overrun.
    let mut dst = vec![0u8; payload.len() - 1];
    assert!(
        decode_to("header-bytes", &article, &mut dst).is_err(),
        "short destination must be rejected"
    );
    // Exact fit still decodes.
    let mut dst = vec![0u8; payload.len()];
    let n = decode_to("header-bytes", &article, &mut dst).expect("exact-fit destination decodes");
    assert_eq!(&dst[..n], payload);
}

#[test]
fn crc_mismatch_stays_reported_with_non_utf8_name() {
    let payload = b"hello";
    let mut article = with_name_bytes(&single(payload), b"Bj\xf6rk.flac");
    let pos = article
        .windows(6)
        .position(|w| w == b"crc32=")
        .expect("trailer has crc32=")
        + 6;
    article[pos] = if article[pos] == b'0' { b'1' } else { b'0' };
    let mut dst = vec![0u8; payload.len() + 64];
    match decode_to("header-bytes", &article, &mut dst) {
        Err(Error::CrcMismatch { .. }) => {}
        Err(other) => panic!("expected Error::CrcMismatch, got {other}"),
        Ok(n) => panic!("expected Error::CrcMismatch, decoded {n} bytes instead"),
    }
}

#[test]
fn malformed_trailer_size_stays_malformed_with_non_utf8_name() {
    // The strict malformed-trailer correction must be preserved: a
    // present-but-invalid =yend size= is Error::Malformed even when the
    // header filename is non-UTF-8.
    let payload = b"hello";
    let mut article = with_name_bytes(&single(payload), b"Bj\xf6rk.flac");
    let needle = b"=yend size=";
    let start = article
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("trailer has =yend size=")
        + needle.len();
    let mut end = start;
    while end < article.len() && article[end] != b' ' && article[end] != b'\r' {
        end += 1;
    }
    article.splice(start..end, b"bogus".iter().copied());
    let mut dst = vec![0u8; payload.len() + 64];
    match decode_to("header-bytes", &article, &mut dst) {
        Err(Error::Malformed(_)) => {}
        Err(other) => panic!("expected Error::Malformed, got {other}"),
        Ok(n) => panic!("expected Error::Malformed, decoded {n} bytes instead"),
    }
}
