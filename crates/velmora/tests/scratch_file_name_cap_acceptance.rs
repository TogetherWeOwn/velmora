//! Par2 scratch file-name cap pin (`crates/nntune-core/src/par2/scratch.rs`).
//!
//! Contract under test (`MAX_FILE_NAME_BYTES` at `:36`, enforced by
//! `validate_file_name` at `:67-75`):
//!
//! - `MAX_FILE_NAME_BYTES` is `255`. A single-component name of exactly 255
//!   bytes validates; 256 bytes fail.
//! - Separators (`/`, `\`), `.`, `..`, and NUL still fail through the same
//!   `validate_file_name` entry point.
//!
//! The value pin compares the crate constant against a local literal, so a
//! cap-value change fails the pin instead of silently following the code. The
//! boundary fixtures are built from the local literal (not the crate
//! constant), so a cap move flips the at-bound or over-bound assertion.
//!
//! Sensitivity (2026-10-18): temporarily changed `MAX_FILE_NAME_BYTES` to 254;
//! `cap_value_is_pinned` and `boundary_255_accepts_256_rejects` failed, then
//! restored to green. Lowering the cap flips the 255-byte accept; raising it
//! flips the 256-byte reject.

use nntune_core::par2::scratch::{validate_file_name, MAX_FILE_NAME_BYTES};

/// Local literal: the cap value under test. Boundary fixtures below are built
/// from this, not from the crate constant, so a cap-value change fails the
/// `cap_value_is_pinned` assertion instead of silently following the code.
const FILE_NAME_CAP: usize = 255;

#[test]
fn cap_value_is_pinned() {
    assert_eq!(FILE_NAME_CAP, 255, "local literal must be 255 bytes");
    assert_eq!(
        MAX_FILE_NAME_BYTES, FILE_NAME_CAP,
        "crate cap moved; this pin exists to catch exactly that"
    );
}

#[test]
fn boundary_255_accepts_256_rejects() {
    let at_cap = "a".repeat(FILE_NAME_CAP);
    assert_eq!(at_cap.len(), 255);
    assert!(
        validate_file_name(&at_cap),
        "exactly 255 bytes must validate"
    );
    let over_cap = "a".repeat(FILE_NAME_CAP + 1);
    assert_eq!(over_cap.len(), 256);
    assert!(
        !validate_file_name(&over_cap),
        "256 bytes must fail validation"
    );
}

#[test]
fn hostile_single_component_shapes_still_reject() {
    assert!(!validate_file_name(""), "empty rejects");
    assert!(!validate_file_name("."), "dot rejects");
    assert!(!validate_file_name(".."), "dot-dot rejects");
    assert!(
        !validate_file_name("dir/track.flac"),
        "forward-slash separator rejects"
    );
    assert!(
        !validate_file_name("dir\\track.flac"),
        "backslash separator rejects"
    );
    assert!(!validate_file_name("track\0.flac"), "embedded NUL rejects");
    // Sanity: an ordinary single-component name still validates through the
    // same entry point, so the rejections above pin the guard, not a blanket
    // deny.
    assert!(validate_file_name("track01.flac"));
}
