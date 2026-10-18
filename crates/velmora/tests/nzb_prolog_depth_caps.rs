//! Pin for the NZB prolog bound and the metadata-depth bound
//! (`crates/nntune-core/src/nzb.rs`): `MAX_PROLOG_BYTES` (4096) and
//! `MAX_METADATA_DEPTH` (64). Tests only; the parser is untouched.
//!
//! Contract under test:
//!
//! - The root element must end at or before byte 4096 of the stream. A
//!   comment-padded prolog whose root opener ends exactly at 4096 parses;
//!   one byte more is `Error::Bounds { bound: "XML prolog bytes",
//!   limit: 4096 }`.
//! - Metadata nesting of 64 elements inside `<head>` parses; 65 nested
//!   elements are `Error::Bounds { bound: "metadata nesting depth",
//!   limit: 64 }`.
//! - A `DOCTYPE` is `Error::Malformed` containing
//!   `"directives are not allowed"` (directives posture, never fetched).
//!
//! Sensitivity (what flips each test): raising `MAX_PROLOG_BYTES` turns the
//! over-bound rejection into a parse success; lowering it turns the at-bound
//! parse into a `Bounds` rejection. Raising `MAX_METADATA_DEPTH` turns the
//! 65-deep rejection into a parse success; lowering it turns the 64-deep
//! parse into a `Bounds` rejection. Relaxing the directive rejection turns
//! the DOCTYPE test into a parse result instead of `Malformed`.
//!
//! All fixtures are built byte-for-byte in this file and parsed only through
//! the public `nzb::{parse, MAX_PROLOG_BYTES, MAX_METADATA_DEPTH}` seam
//! plus `Error` for variant matching.

use nntune_core::error::Error;
use nntune_core::nzb::{parse, MAX_METADATA_DEPTH, MAX_PROLOG_BYTES};

/// Local literals: the bounds under test. Fixtures below are built from
/// these, not from the crate constants, so a bound-value change fails the
/// `bounds_are_pinned` assertion instead of silently following the code.
const PROLOG_CAP: u64 = 4096;
const DEPTH_CAP: usize = 64;

/// Minimal valid file body appended after `<head>` / prolog fixtures.
const FILE_BODY: &str = "<file poster=\"p\" date=\"1\" subject=\"s\"><segments>\
     <segment bytes=\"1\" number=\"1\">a@b</segment>\
     </segments></file>";

/// Root opener used in the prolog fixtures; its length is part of the
/// exact-bound arithmetic (`buffer_position` is measured at the end of it).
const ROOT_OPEN: &str = "<nzb>";
const ROOT_CLOSE: &str = "</nzb>";

/// Builds `<comment><nzb>{FILE_BODY}</nzb>` where the comment is
/// `<!--` + `fill` x `'X'` + `-->`. The root opener therefore ends at
/// `fill + 12` (`fill + 7` comment bytes + 5 root bytes).
fn doc_with_comment_fill(fill: usize) -> Vec<u8> {
    let mut doc = String::with_capacity(fill + 256);
    doc.push_str("<!--");
    doc.push_str(&"X".repeat(fill));
    doc.push_str("-->");
    doc.push_str(ROOT_OPEN);
    doc.push_str(FILE_BODY);
    doc.push_str(ROOT_CLOSE);
    doc.into_bytes()
}

/// `depth` nested `<m{i}>` elements around `x`, closed in reverse.
fn nesting(depth: usize) -> String {
    let mut s = String::new();
    for i in 0..depth {
        s.push_str(&format!("<m{i}>"));
    }
    s.push('x');
    for i in (0..depth).rev() {
        s.push_str(&format!("</m{i}>"));
    }
    s
}

fn doc_with_head_inner(inner: &str) -> Vec<u8> {
    format!("<nzb><head>{inner}</head>{FILE_BODY}</nzb>").into_bytes()
}

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

#[test]
fn bounds_are_pinned() {
    assert_eq!(PROLOG_CAP, 4096, "local prolog literal must be 4096");
    assert_eq!(DEPTH_CAP, 64, "local depth literal must be 64");
    assert_eq!(
        MAX_PROLOG_BYTES, PROLOG_CAP,
        "crate prolog cap moved; this pin exists to catch exactly that"
    );
    assert_eq!(
        MAX_METADATA_DEPTH, DEPTH_CAP,
        "crate metadata-depth cap moved; this pin exists to catch exactly that"
    );
}

#[test]
fn prolog_over_bound_is_rejected_with_bounds() {
    // fill + 12 = 4097: the root opener ends one byte past the cap.
    let fill = PROLOG_CAP as usize - 12 + 1;
    assert_eq!(fill + 12, 4097);
    let err = parse(&doc_with_comment_fill(fill)).unwrap_err();
    expect_bounds(err, "XML prolog bytes", PROLOG_CAP as i64);
}

#[test]
fn prolog_at_bound_parses() {
    // fill + 12 = 4096: the root opener ends exactly on the cap (`>` check,
    // so equality passes) and the document parses.
    let fill = PROLOG_CAP as usize - 12;
    assert_eq!(fill + 12, 4096);
    let doc = parse(&doc_with_comment_fill(fill)).expect("at-bound prolog must parse");
    assert_eq!(doc.files.len(), 1);
    assert_eq!(doc.files[0].segments[0].message_id, "a@b");
}

#[test]
fn metadata_65_deep_is_rejected_with_bounds() {
    let err = parse(&doc_with_head_inner(&nesting(DEPTH_CAP + 1))).unwrap_err();
    expect_bounds(err, "metadata nesting depth", DEPTH_CAP as i64);
}

#[test]
fn metadata_64_deep_passes() {
    let doc =
        parse(&doc_with_head_inner(&nesting(DEPTH_CAP))).expect("64-deep metadata must parse");
    assert_eq!(doc.files.len(), 1);
    assert!(!doc.has_password);
}

#[test]
fn doctype_is_rejected_as_directives_not_allowed() {
    let mut xml = b"<!DOCTYPE nzb>".to_vec();
    xml.extend_from_slice(b"<nzb>");
    xml.extend_from_slice(FILE_BODY.as_bytes());
    xml.extend_from_slice(ROOT_CLOSE.as_bytes());
    let err = parse(&xml).unwrap_err();
    match err {
        Error::Malformed(msg) => assert!(
            msg.contains("directives are not allowed"),
            "want directives-not-allowed rejection, got: {msg}"
        ),
        other => panic!("expected Malformed directives rejection, got {other:?}"),
    }
}
