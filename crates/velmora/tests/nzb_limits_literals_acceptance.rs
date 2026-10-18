//! NZB parse-limits literal pins (tests-only).
//!
//! Contract under test (`crates/nntune-core/src/nzb.rs:32,34,38,42`):
//!
//! - `MAX_FILES == 1024` — most `<file>` elements one document holds.
//! - `MAX_SEGMENTS_PER_FILE == 4096` — most `<segment>` elements in one file.
//! - `MAX_DOCUMENT_BYTES == 32 << 20` (33_554_432) — most input bytes fed to
//!   the parser, enforced at the `BufRead` boundary.
//! - `MAX_SEGMENT_BYTES == (1 << 31) - 1` (2_147_483_647) — most declared
//!   `bytes=` on a single `<segment>`.
//!
//! Pins in this file:
//!
//! - each literal stays exactly its value above (spelled as a local `const`
//!   plus an arithmetic form, never by aliasing the crate symbol, so a silent
//!   value change fails the pin instead of following the code);
//! - exactly-at-cap documents validate through `Parser::new(Limits { .. })`
//!   and parse through the default limits, while cap+1 fails closed —
//!   `Bounds` on the parse path, construction error on the `Limits` validate
//!   path (`MAX_SEGMENT_BYTES` has no `Limits` field, so only the parse path
//!   applies there).
//!
//! Sensitivity (implementation stays untouched):
//!
//! - lowering any cap (e.g. files to 1023) turns the corresponding at-cap
//!   parse test red (`Bounds` where success is expected) and the validate
//!   construction red;
//! - raising any cap (e.g. files to 1025) turns the corresponding cap+1 test
//!   red (the over-cap document parses instead of failing with `Bounds`);
//! - rewording a bound name fails the exact `expect_bounds` match;
//! - moving a check (e.g. counting files after parsing) still fails the
//!   cap+1 test on the missing `Bounds`, but with a different error shape.
//!
//! Out of scope: `MAX_ENCODED_BYTES` (different const, total declared bytes),
//! ingest-side transport byte/count caps, prolog/metadata/segment-text caps
//! (pinned elsewhere). Fixtures are synthetic only; no I/O is touched.
//!
//! Run only this file:
//!
//! ```sh
//! cargo test -p nntune-core --test nzb_limits_literals_acceptance
//! ```

use nntune_core::error::Error;
use nntune_core::nzb::{
    Limits, Parser, MAX_DOCUMENT_BYTES, MAX_FILES, MAX_SEGMENTS_PER_FILE, MAX_SEGMENT_BYTES,
};

/// Local literals: the bounds under test. Fixtures below are built from
/// these, never from the crate constants, so a bound-value change fails the
/// `literals_are_pinned` assertion instead of silently following the code.
const FILES_CAP: usize = 1024;
const SEGMENTS_CAP: usize = 4096;
const DOCUMENT_CAP: u64 = 32 << 20;
const SEGMENT_BYTES_CAP: i64 = (1 << 31) - 1;

fn expect_bounds(err: Error, bound: &str, limit: i64) {
    match err {
        Error::Bounds {
            bound: got,
            limit: got_limit,
        } => {
            assert_eq!(got, bound, "wrong bound name: {got:?}");
            assert_eq!(got_limit, limit, "wrong bound limit: {got_limit}");
        }
        other => panic!("expected Bounds({bound:?}/{limit}), got {other:?}"),
    }
}

/// One single-segment file with a unique Message-ID per index.
fn one_file(index: usize) -> String {
    format!(
        "<file poster=\"p\" date=\"1\" subject=\"s\">\
         <segments><segment bytes=\"1\" number=\"1\">f{index}@x</segment></segments></file>"
    )
}

fn doc_with_n_files(n: usize) -> Vec<u8> {
    let mut doc = String::with_capacity(n * 128 + 16);
    doc.push_str("<nzb>");
    for i in 0..n {
        doc.push_str(&one_file(i));
    }
    doc.push_str("</nzb>");
    doc.into_bytes()
}

fn doc_with_n_segments(n: usize) -> Vec<u8> {
    let mut doc = String::with_capacity(n * 56 + 128);
    doc.push_str("<nzb><file poster=\"p\" date=\"1\" subject=\"s\"><segments>");
    for i in 1..=n {
        doc.push_str(&format!(
            "<segment bytes=\"1\" number=\"{i}\">seg{i}@x</segment>"
        ));
    }
    doc.push_str("</segments></file></nzb>");
    doc.into_bytes()
}

fn doc_with_segment_bytes(declared: i64) -> Vec<u8> {
    format!(
        "<nzb><file poster=\"p\" date=\"1\" subject=\"s\">\
         <segments><segment bytes=\"{declared}\" number=\"1\">a@b</segment></segments>\
         </file></nzb>"
    )
    .into_bytes()
}

const DOC_PAD_PREFIX: &str = "<nzb>";
const DOC_PAD_REST: &str = "<file poster=\"p\" date=\"1\" subject=\"s\">\
    <segments><segment bytes=\"1\" number=\"1\">a@b</segment></segments></file></nzb>";

/// Pads with spaces between `<nzb>` and `<file>` (a `Text` event the parser
/// ignores) so the total length is exactly `total` bytes.
fn doc_padded_to(total: usize) -> Vec<u8> {
    let base = DOC_PAD_PREFIX.len() + DOC_PAD_REST.len();
    assert!(total >= base, "pad target {total} below base {base}");
    let pad = total - base;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(DOC_PAD_PREFIX.as_bytes());
    out.extend(std::iter::repeat(b' ').take(pad));
    out.extend_from_slice(DOC_PAD_REST.as_bytes());
    debug_assert_eq!(out.len(), total);
    out
}

#[test]
fn literals_are_pinned() {
    assert_eq!(FILES_CAP, 1024, "local files literal must be 1024");
    assert_eq!(SEGMENTS_CAP, 4096, "local segments literal must be 4096");
    assert_eq!(
        DOCUMENT_CAP, 33_554_432,
        "local document-bytes literal must be 33_554_432"
    );
    assert_eq!(
        DOCUMENT_CAP,
        32 << 20,
        "document cap must stay expressible as 32 MiB"
    );
    assert_eq!(
        SEGMENT_BYTES_CAP, 2_147_483_647,
        "local segment-bytes literal must be 2_147_483_647"
    );
    assert_eq!(
        SEGMENT_BYTES_CAP,
        (1 << 31) - 1,
        "segment-bytes cap must stay expressible as i32::MAX"
    );
    assert_eq!(
        MAX_FILES, FILES_CAP,
        "crate files cap moved; this pin exists to catch exactly that"
    );
    assert_eq!(
        MAX_SEGMENTS_PER_FILE, SEGMENTS_CAP,
        "crate segments cap moved; this pin exists to catch exactly that"
    );
    assert_eq!(
        MAX_DOCUMENT_BYTES, DOCUMENT_CAP,
        "crate document-bytes cap moved; this pin exists to catch exactly that"
    );
    assert_eq!(
        MAX_SEGMENT_BYTES, SEGMENT_BYTES_CAP,
        "crate segment-bytes cap moved; this pin exists to catch exactly that"
    );
    assert_eq!(
        Limits::default().files,
        FILES_CAP,
        "default Limits must carry the files cap"
    );
    assert_eq!(
        Limits::default().segments_per_file,
        SEGMENTS_CAP,
        "default Limits must carry the segments cap"
    );
    assert_eq!(
        Limits::default().document_bytes,
        DOCUMENT_CAP,
        "default Limits must carry the document-bytes cap"
    );
}

#[test]
fn files_at_cap_parses() {
    let xml = doc_with_n_files(FILES_CAP);
    let doc = Parser::with_default_limits()
        .unwrap()
        .parse(xml.as_slice())
        .expect("exactly 1024 files must parse");
    assert_eq!(doc.files.len(), FILES_CAP);
}

#[test]
fn files_cap_plus_one_fails_bounds() {
    let xml = doc_with_n_files(FILES_CAP + 1);
    let err = Parser::with_default_limits()
        .unwrap()
        .parse(xml.as_slice())
        .unwrap_err();
    expect_bounds(err, "file count", FILES_CAP as i64);
}

#[test]
fn files_limits_validate_boundary() {
    Parser::new(Limits {
        files: FILES_CAP,
        ..Limits::default()
    })
    .expect("at-cap files limit must validate");
    assert!(
        Parser::new(Limits {
            files: FILES_CAP + 1,
            ..Limits::default()
        })
        .is_err(),
        "one past the files cap must fail Limits validation"
    );
}

#[test]
fn segments_at_cap_parses() {
    let xml = doc_with_n_segments(SEGMENTS_CAP);
    let doc = Parser::with_default_limits()
        .unwrap()
        .parse(xml.as_slice())
        .expect("exactly 4096 segments must parse");
    assert_eq!(doc.files.len(), 1);
    assert_eq!(doc.files[0].segments.len(), SEGMENTS_CAP);
}

#[test]
fn segments_cap_plus_one_fails_bounds() {
    let xml = doc_with_n_segments(SEGMENTS_CAP + 1);
    let err = Parser::with_default_limits()
        .unwrap()
        .parse(xml.as_slice())
        .unwrap_err();
    expect_bounds(err, "segments in file", SEGMENTS_CAP as i64);
}

#[test]
fn segments_limits_validate_boundary() {
    Parser::new(Limits {
        segments_per_file: SEGMENTS_CAP,
        ..Limits::default()
    })
    .expect("at-cap segments limit must validate");
    assert!(
        Parser::new(Limits {
            segments_per_file: SEGMENTS_CAP + 1,
            ..Limits::default()
        })
        .is_err(),
        "one past the segments cap must fail Limits validation"
    );
}

#[test]
fn document_at_cap_parses() {
    let xml = doc_padded_to(DOCUMENT_CAP as usize);
    assert_eq!(xml.len() as u64, DOCUMENT_CAP);
    let doc = Parser::with_default_limits()
        .unwrap()
        .parse(xml.as_slice())
        .expect("exactly 32 MiB document must parse");
    assert_eq!(doc.files.len(), 1);
    assert_eq!(doc.files[0].segments[0].message_id, "a@b");
}

#[test]
fn document_cap_plus_one_fails_bounds() {
    let xml = doc_padded_to(DOCUMENT_CAP as usize + 1);
    assert_eq!(xml.len() as u64, DOCUMENT_CAP + 1);
    let err = Parser::with_default_limits()
        .unwrap()
        .parse(xml.as_slice())
        .unwrap_err();
    expect_bounds(err, "document bytes", DOCUMENT_CAP as i64);
}

#[test]
fn document_limits_validate_boundary() {
    Parser::new(Limits {
        document_bytes: DOCUMENT_CAP,
        ..Limits::default()
    })
    .expect("at-cap document limit must validate");
    assert!(
        Parser::new(Limits {
            document_bytes: DOCUMENT_CAP + 1,
            ..Limits::default()
        })
        .is_err(),
        "one past the document cap must fail Limits validation"
    );
}

#[test]
fn segment_bytes_at_cap_parses() {
    let xml = doc_with_segment_bytes(SEGMENT_BYTES_CAP);
    let doc = Parser::with_default_limits()
        .unwrap()
        .parse(xml.as_slice())
        .expect("segment at exactly i32::MAX bytes must parse");
    assert_eq!(doc.files[0].segments[0].encoded_bytes, SEGMENT_BYTES_CAP);
    assert_eq!(doc.encoded_bytes, SEGMENT_BYTES_CAP);
}

#[test]
fn segment_bytes_cap_plus_one_fails_bounds() {
    let xml = doc_with_segment_bytes(SEGMENT_BYTES_CAP + 1);
    let err = Parser::with_default_limits()
        .unwrap()
        .parse(xml.as_slice())
        .unwrap_err();
    expect_bounds(err, "encoded bytes in one segment", SEGMENT_BYTES_CAP);
}
