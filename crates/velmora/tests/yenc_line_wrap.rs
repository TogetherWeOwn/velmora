//! 128-column wrap and trailer line-length pin
//! (`crates/nntune-core/src/yenc.rs`, `LINE_LENGTH`, `LineBuf`, `encode_body`,
//! `encode_segment`).
//!
//! Contract under test (tests only; the implementation is untouched):
//!
//! - [`LINE_LENGTH`] is 128.
//! - `encode_segment` records that width on the wire: the `=ybegin` header
//!   carries `line=128` for single-part
//!   (`=ybegin line=128 size=.. name=..`) and multi-part
//!   (`=ybegin part=.. total=.. line=128 size=.. name=..`) segments.
//! - `encode_body` wraps the encoded body at 128 output columns before CRLF.
//!   Every emitted byte counts one column — including the `=` introducer of
//!   an escape pair — so no body line exceeds 128 bytes before its CRLF.
//! - An escape pair is never split across lines: the encoder flushes a
//!   127-column line before starting an escape, so no body line ends with a
//!   bare `=`.
//!
//! Sensitivity (verified by running this suite against local mutants and
//! restoring the source afterwards; `git status` shows only this new test
//! file, the implementation is untouched):
//!
//! - changing `LINE_LENGTH` to 64 fails 6/9 tests (constant pin, both
//!   `line=128` header pins, exact plain splits, both escape pins);
//! - not counting the `=` introducer as a column lets escape-heavy bodies
//!   pack more than 128 bytes per line (e.g. 100 all-escaping bytes collapse
//!   toward fewer, over-width lines), failing the max-width sweep, which also
//!   asserts total columns equal plain bytes plus twice the escapable count;
//! - deleting the `column >= LINE_LENGTH - 1` pre-flush turns the
//!   127-plain-plus-escape case from `[127, 2]` into `[128, 1]` whose first
//!   line ends with a bare `=`, failing the exact-split and the
//!   never-stranded pins (the width pin alone still passes, so both pins are
//!   needed);
//! - relaxing the flush threshold (`>` instead of `>=`) overflows the
//!   `LINE_LENGTH + 2` line buffer and panics (`index out of bounds: len 130`)
//!   on the plain-boundary case instead of wrapping.
//!
//! Uses only the public `yenc::{LINE_LENGTH, encode_body, encode_segment,
//! SegmentParams, decode_to}` surface; the implementation is untouched.

use nntune_core::yenc::{decode_to, encode_body, encode_segment, SegmentParams, LINE_LENGTH};

/// Raw bytes whose `+42` value needs escaping (NUL, LF, CR, `=` map to
/// `0xD6, 0xE0, 0xE3, 0x13` respectively). Each encodes to two columns.
const ESCAPABLE_RAW: [u8; 4] = [0xD6, 0xE0, 0xE3, 0x13];

/// Plain raw byte whose `+42` value (`b'k'`) needs no escape: one raw byte
/// is exactly one column.
const PLAIN_RAW: u8 = 0x41;

/// Split an encoded body (the raw `encode_body` output) into its CRLF
/// content lines. Asserts the body uses CRLF exclusively: every `\n` is
/// preceded by `\r`, and the body ends with CRLF (unless empty).
fn body_lines(body: &[u8]) -> Vec<&[u8]> {
    if body.is_empty() {
        return Vec::new();
    }
    for (i, &b) in body.iter().enumerate() {
        if b == b'\n' {
            assert!(
                i > 0 && body[i - 1] == b'\r',
                "body must use CRLF, found bare LF at offset {i}"
            );
        }
    }
    assert!(
        body.ends_with(b"\r\n"),
        "non-empty body must end with CRLF, got trailing {:?}",
        &body[body.len().saturating_sub(4)..]
    );
    let mut lines = Vec::new();
    for chunk in body.split(|&b| b == b'\n') {
        if chunk.is_empty() {
            continue;
        }
        let line = chunk.strip_suffix(b"\r").unwrap_or(chunk);
        lines.push(line);
    }
    lines
}

/// Body lines of a full `encode_segment` article: lines between `=ybegin`
/// (plus the `=ypart` range line for multi-part) and `=yend`.
fn segment_body_lines(article: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = Vec::new();
    for chunk in article.split(|&b| b == b'\n') {
        if chunk.is_empty() {
            continue;
        }
        lines.push(chunk.strip_suffix(b"\r").unwrap_or(chunk));
    }
    let begin = lines
        .iter()
        .position(|l| l.starts_with(b"=ybegin "))
        .expect("article has =ybegin");
    let end = lines
        .iter()
        .position(|l| l.starts_with(b"=yend"))
        .expect("article has =yend");
    assert!(end > begin, "=yend must follow =ybegin");
    lines[begin + 1..end]
        .iter()
        .filter(|l| !l.starts_with(b"=ypart "))
        .copied()
        .collect()
}

fn encode(payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    encode_body(&mut body, payload).expect("encode_body must succeed");
    body
}

fn assert_width_and_no_stranded_escape(lines: &[&[u8]], label: &str) {
    for (i, line) in lines.iter().enumerate() {
        assert!(
            line.len() <= LINE_LENGTH,
            "{label}: line {i} is {} columns, over the 128-column limit",
            line.len()
        );
        assert!(
            *line.last().unwrap_or(&b'x') != b'=',
            "{label}: line {i} ends with a stranded `=` escape introducer"
        );
    }
}

#[test]
fn line_length_constant_is_128() {
    assert_eq!(LINE_LENGTH, 128, "LINE_LENGTH must stay 128 columns");
}

#[test]
fn single_part_header_records_line_128() {
    let mut out = Vec::new();
    encode_segment(&mut out, &SegmentParams::single("a.bin"), b"abc").unwrap();
    assert!(
        out.starts_with(b"=ybegin line=128 size=3 name=a.bin\r\n"),
        "single-part header must record line=128, got {:?}",
        String::from_utf8_lossy(
            &out[..out.iter().position(|&b| b == b'\n').unwrap_or(out.len()) + 1]
        )
    );
}

#[test]
fn multipart_header_records_line_128() {
    let params = SegmentParams {
        name: "m.bin".into(),
        part: 2,
        total: 3,
        begin: 101,
        end: 200,
        file_size: 300,
    };
    let mut out = Vec::new();
    encode_segment(&mut out, &params, &[PLAIN_RAW; 100]).unwrap();
    assert!(
        out.starts_with(b"=ybegin part=2 total=3 line=128 size=300 name=m.bin\r\n"),
        "multi-part header must record line=128, got {:?}",
        String::from_utf8_lossy(
            &out[..out.iter().position(|&b| b == b'\n').unwrap_or(out.len()) + 1]
        )
    );
}

#[test]
fn plain_body_wraps_at_exact_128_boundaries() {
    // Below, at, and just over one line, plus two-line boundaries. Each
    // plain byte is one column, so the splits are exact.
    for (len, expected) in [
        (0usize, vec![]),
        (1, vec![1]),
        (127, vec![127]),
        (128, vec![128]),
        (129, vec![128, 1]),
        (255, vec![128, 127]),
        (256, vec![128, 128]),
        (257, vec![128, 128, 1]),
        (1000, vec![128, 128, 128, 128, 128, 128, 128, 104]),
    ] {
        let body = encode(&vec![PLAIN_RAW; len]);
        let lines = body_lines(&body);
        let widths: Vec<usize> = lines.iter().map(|l| l.len()).collect();
        assert_eq!(widths, expected, "plain payload of {len} bytes");
        assert_width_and_no_stranded_escape(&lines, &format!("plain len={len}"));
    }
}

#[test]
fn escape_introducer_counts_as_one_column() {
    // 64 all-escaping bytes are exactly 128 columns (2 each): one full line.
    let body = encode(&[ESCAPABLE_RAW[3]; 64]);
    let lines = body_lines(&body);
    assert_eq!(
        lines.iter().map(|l| l.len()).collect::<Vec<_>>(),
        vec![128],
        "64 escapes must fill exactly one 128-column line"
    );
    assert_width_and_no_stranded_escape(&lines, "64 escapes");

    // One more escape needs a second line: 65 * 2 = 130 columns.
    let body = encode(&[ESCAPABLE_RAW[3]; 65]);
    let lines = body_lines(&body);
    assert_eq!(
        lines.iter().map(|l| l.len()).collect::<Vec<_>>(),
        vec![128, 2],
        "65 escapes must wrap to [128, 2]"
    );
    assert_width_and_no_stranded_escape(&lines, "65 escapes");

    // If `=` did not count as a column, 100 escapes (200 bytes) would fit
    // in far fewer byte-lines; the width pin forces every byte to count.
    let body = encode(&[ESCAPABLE_RAW[3]; 100]);
    let lines = body_lines(&body);
    assert!(
        lines.iter().all(|l| l.len() <= 128),
        "100 escapes must still wrap at 128 columns"
    );
    assert_eq!(lines.len(), 2, "100 escapes (200 columns) need 2 lines");
    assert_width_and_no_stranded_escape(&lines, "100 escapes");
}

#[test]
fn escape_pair_never_stranded_at_end_of_line() {
    // 127 plain columns followed by one escaping byte: the pair must start
    // a fresh line ([127, 2]), never strand `=` as column 128.
    let mut payload = vec![PLAIN_RAW; 127];
    payload.push(ESCAPABLE_RAW[3]);
    let body = encode(&payload);
    let lines = body_lines(&body);
    assert_eq!(
        lines.iter().map(|l| l.len()).collect::<Vec<_>>(),
        vec![127, 2],
        "escape after 127 columns must wrap before the pair"
    );
    assert_width_and_no_stranded_escape(&lines, "127 plain + escape");

    // 126 plain columns + escape fills the line exactly ([128]).
    let mut payload = vec![PLAIN_RAW; 126];
    payload.push(ESCAPABLE_RAW[3]);
    let body = encode(&payload);
    let lines = body_lines(&body);
    assert_eq!(
        lines.iter().map(|l| l.len()).collect::<Vec<_>>(),
        vec![128],
        "escape after 126 columns must fill the line exactly"
    );
    assert_width_and_no_stranded_escape(&lines, "126 plain + escape");

    // Every escapable value behaves the same at the boundary.
    for &raw in &ESCAPABLE_RAW {
        let mut payload = vec![PLAIN_RAW; 127];
        payload.push(raw);
        let body = encode(&payload);
        let lines = body_lines(&body);
        assert_eq!(
            lines.iter().map(|l| l.len()).collect::<Vec<_>>(),
            vec![127, 2],
            "escapable raw 0x{raw:02x} after 127 columns must wrap"
        );
        assert_width_and_no_stranded_escape(&lines, &format!("escape 0x{raw:02x}"));
    }
}

#[test]
fn body_lines_never_exceed_128_across_payloads() {
    // Sweep plain, escape-heavy, mixed, and deterministic-pseudorandom
    // payloads across several wrap boundaries.
    let mut x = 0x243f_6a88_85a3_08d3u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![PLAIN_RAW; 1],
        vec![ESCAPABLE_RAW[3]; 1],
        vec![PLAIN_RAW; 300],
        vec![ESCAPABLE_RAW[0]; 300],
    ];
    for len in [63, 64, 65, 127, 128, 129, 255, 256, 1000, 4096] {
        cases.push(
            (0..len)
                .map(|i| {
                    if i % 3 == 0 {
                        ESCAPABLE_RAW[i % 4]
                    } else {
                        PLAIN_RAW
                    }
                })
                .collect(),
        );
    }
    for _ in 0..20 {
        let len = (next() % 600) as usize;
        cases.push((0..len).map(|_| (next() & 0xff) as u8).collect());
    }
    let mut checked = 0usize;
    for (i, payload) in cases.iter().enumerate() {
        let body = encode(payload);
        let lines = body_lines(&body);
        assert_width_and_no_stranded_escape(&lines, &format!("case {i} len={}", payload.len()));
        // Column accounting is exact: total columns equal plain bytes plus
        // twice the escapable count.
        let escapables = payload
            .iter()
            .filter(|b| {
                let v = b.wrapping_add(42);
                v == 0 || v == b'\n' || v == b'\r' || v == b'='
            })
            .count();
        let columns: usize = lines.iter().map(|l| l.len()).sum();
        assert_eq!(
            columns,
            payload.len() + escapables,
            "case {i}: every emitted byte (including `=`) counts one column"
        );
        checked += 1;
    }
    assert!(checked >= 30, "sweep must cover mixed payloads");
}

#[test]
fn wrapped_bodies_still_roundtrip() {
    // Positive control: wrapping never corrupts the payload.
    let cases: Vec<Vec<u8>> = vec![
        vec![PLAIN_RAW; 1000],
        vec![ESCAPABLE_RAW[3]; 500],
        (0u8..=255u8).cycle().take(2048).collect(),
    ];
    for (i, payload) in cases.iter().enumerate() {
        let mut article = Vec::new();
        encode_segment(&mut article, &SegmentParams::single("w.bin"), payload).unwrap();
        let mut dst = vec![0u8; payload.len() + 64];
        let n = decode_to(&format!("wrap{i}"), &article, &mut dst)
            .unwrap_or_else(|e| panic!("case {i} must decode: {e}"));
        assert_eq!(&dst[..n], payload, "case {i} roundtrip bytes");
    }
}

#[test]
fn full_segment_bodies_never_exceed_128() {
    // The same width guarantee through the full article framing, for both
    // single-part and multi-part segments.
    let payload: Vec<u8> = (0..1000u32)
        .map(|i| {
            if i % 5 == 0 {
                ESCAPABLE_RAW[(i as usize) % 4]
            } else {
                (i & 0xff) as u8
            }
        })
        .collect();
    let mut single = Vec::new();
    encode_segment(&mut single, &SegmentParams::single("s.bin"), &payload).unwrap();
    let lines = segment_body_lines(&single);
    assert!(
        !lines.is_empty(),
        "1000-byte payload must produce body lines"
    );
    assert_width_and_no_stranded_escape(&lines, "single-part segment");

    let params = SegmentParams {
        name: "m.bin".into(),
        part: 1,
        total: 2,
        begin: 1,
        end: payload.len() as u64,
        file_size: 2 * payload.len() as u64,
    };
    let mut multi = Vec::new();
    encode_segment(&mut multi, &params, &payload).unwrap();
    let lines = segment_body_lines(&multi);
    assert!(
        !lines.is_empty(),
        "multi-part payload must produce body lines"
    );
    assert_width_and_no_stranded_escape(&lines, "multi-part segment");
}
