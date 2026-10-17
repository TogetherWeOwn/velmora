//! Acceptance tests: XML character/entity references inside `<segment>`
//! text must be resolved before Message-ID normalisation, never silently
//! dropped.
//!
//! Contract under test:
//! - predefined references (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`) and
//!   decimal/hex character references (`&#64;`, `&#x40;`) resolve to their
//!   character before the existing Message-ID normalisation runs;
//! - unknown named references and invalid Unicode character references are
//!   explicit errors, not empty text;
//! - DTDs, external entities and processing instructions stay rejected and
//!   nothing enables external/network entity resolution;
//! - escaped and literal forms of the same ID normalise identically and
//!   produce the same segment digest (so an escaped duplicate of a literal
//!   segment is a duplicate);
//! - surrounding-whitespace/bracket normalisation and the embedded
//!   whitespace/control rejection keep applying to the *resolved* text;
//! - CDATA content is literal and is not reference-expanded;
//! - document and segment-text bounds apply to the expanded output.
//!
//! Assertions are behavioural only (parsed IDs, digests, `Err`); error
//! message wording is the implementer's choice.

use nntune_core::nzb::{parse, Limits, Parser, MAX_SEGMENT_TEXT_BYTES};

fn doc_with_segment(segment_inner: &str) -> String {
    format!(
        "<nzb><file poster=\"p\" date=\"1\" subject=\"s\"><segments>\
         <segment bytes=\"1\" number=\"1\">{segment_inner}</segment>\
         </segments></file></nzb>"
    )
}

/// Parses a one-segment document and returns the segment's Message-ID.
fn message_id(segment_inner: &str) -> nntune_core::Result<String> {
    parse(doc_with_segment(segment_inner).as_bytes())
        .map(|doc| doc.files[0].segments[0].message_id.clone())
}

#[test]
fn valid_literal_segment_is_unchanged() {
    // Positive control: literal text, brackets and surrounding whitespace
    // behave exactly as before.
    assert_eq!(message_id("a@b").unwrap(), "a@b");
    assert_eq!(message_id("  a@b  ").unwrap(), "a@b");
    assert_eq!(
        message_id("seg-1@example.com").unwrap(),
        "seg-1@example.com"
    );
}

#[test]
fn decimal_character_reference_resolves_before_normalization() {
    assert_eq!(message_id("a&#64;b").unwrap(), "a@b");
}

#[test]
fn hex_character_reference_resolves_before_normalization() {
    assert_eq!(message_id("a&#x40;b").unwrap(), "a@b");
    assert_eq!(message_id("a&#x0040;b").unwrap(), "a@b");
}

#[test]
fn consecutive_references_resolve_in_order() {
    assert_eq!(message_id("a&#64;b&#x2e;c").unwrap(), "a@b.c");
    assert_eq!(message_id("&#97;&#64;&#98;").unwrap(), "a@b");
}

#[test]
fn predefined_ampersand_reference_resolves() {
    assert_eq!(message_id("a&amp;b@c").unwrap(), "a&b@c");
    // The character reference for '&' is the same character as &amp;.
    assert_eq!(message_id("a&#38;b@c").unwrap(), "a&b@c");
}

#[test]
fn predefined_quote_references_resolve() {
    assert_eq!(message_id("a&quot;b@c").unwrap(), "a\"b@c");
    assert_eq!(message_id("a&apos;b@c").unwrap(), "a'b@c");
}

#[test]
fn non_ascii_character_reference_resolves() {
    assert_eq!(message_id("caf&#xe9;@b").unwrap(), "café@b");
    assert_eq!(message_id("caf&#233;@b").unwrap(), "café@b");
}

#[test]
fn unknown_named_reference_is_rejected() {
    assert!(message_id("a&nosuchentity;b@c").is_err());
    // An entity-shaped name with no DTD to define it is likewise unknown.
    assert!(message_id("a&xxe;b@c").is_err());
}

#[test]
fn invalid_unicode_character_references_are_rejected() {
    for inner in ["a&#xD800;b@c", "a&#x110000;b@c", "a&#0;b@c"] {
        assert!(message_id(inner).is_err(), "expected Err for {inner}");
    }
}

#[test]
fn malformed_character_reference_is_rejected() {
    assert!(message_id("a&#xZZ;b@c").is_err());
    assert!(message_id("a&#;b@c").is_err());
}

#[test]
fn reference_to_embedded_whitespace_or_control_is_rejected() {
    // Resolution happens before normalisation, so a referenced space, tab,
    // newline or DEL is embedded whitespace/control just like the literal.
    for inner in ["a&#32;b@c", "a&#9;b@c", "a&#10;b@c", "a&#x7f;b@c"] {
        assert!(message_id(inner).is_err(), "expected Err for {inner}");
    }
}

#[test]
fn reference_to_embedded_bracket_is_rejected() {
    assert!(message_id("a&lt;b@c").is_err());
    assert!(message_id("a&#62;b@c").is_err());
}

#[test]
fn escaped_brackets_and_surrounding_whitespace_still_normalize() {
    assert_eq!(message_id("&#60;a@b&#62;").unwrap(), "a@b");
    assert_eq!(message_id("&lt;a@b&gt;").unwrap(), "a@b");
    assert_eq!(message_id("&#32;a@b&#32;").unwrap(), "a@b");
}

#[test]
fn escaped_and_literal_forms_produce_same_id_and_digest() {
    let literal = parse(doc_with_segment("a@b.example").as_bytes()).unwrap();
    let decimal = parse(doc_with_segment("a&#64;b.example").as_bytes())
        .unwrap_or_else(|e| panic!("escaped form failed to parse: {e}"));
    let hex = parse(doc_with_segment("a&#x40;b.example").as_bytes()).unwrap();

    assert_eq!(
        literal.files[0].segments[0].message_id,
        decimal.files[0].segments[0].message_id
    );
    assert_eq!(
        literal.files[0].segments[0].message_id,
        hex.files[0].segments[0].message_id
    );
    assert_eq!(literal.segment_digest, decimal.segment_digest);
    assert_eq!(literal.segment_digest, hex.segment_digest);
}

#[test]
fn escaped_duplicate_of_literal_segment_is_rejected_as_duplicate() {
    let xml = "<nzb><file poster=\"p\" date=\"1\" subject=\"s\"><segments>\
               <segment bytes=\"1\" number=\"1\">a@b</segment>\
               <segment bytes=\"1\" number=\"2\">a&#64;b</segment>\
               </segments></file></nzb>";
    assert!(parse(xml.as_bytes()).is_err());
}

#[test]
fn cdata_content_is_not_reference_expanded() {
    // CDATA is literal character data: the reference spelling itself is
    // the ID, exactly as a literal "a&#64;b" ID would be spelled.
    assert_eq!(message_id("<![CDATA[a&#64;b]]>").unwrap(), "a&#64;b");
    assert_eq!(message_id("<![CDATA[a&amp;b]]>").unwrap(), "a&amp;b");
}

#[test]
fn doctype_and_external_entity_remain_rejected() {
    let xml = "<?xml version=\"1.0\"?><!DOCTYPE nzb [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\
               <nzb><file poster=\"p\" date=\"1\" subject=\"s\"><segments>\
               <segment bytes=\"1\" number=\"1\">&xxe;</segment>\
               </segments></file></nzb>";
    assert!(parse(xml.as_bytes()).is_err());
}

#[test]
fn processing_instruction_inside_segment_remains_rejected() {
    assert!(message_id("a<?pi data?>@b").is_err());
}

#[test]
fn segment_text_bound_applies_to_expanded_references() {
    // A short literal prefix keeps this a would-be-valid ID if references
    // were dropped, so only the expanded-text bound can reject it.
    let inner = format!("a@b{}", "&#97;".repeat(MAX_SEGMENT_TEXT_BYTES));
    assert!(parse(doc_with_segment(&inner).as_bytes()).is_err());
}

#[test]
fn document_byte_limit_still_applies_with_references() {
    let limits = Limits {
        document_bytes: 64,
        ..Limits::default()
    };
    assert!(Parser::new(limits)
        .unwrap()
        .parse(doc_with_segment("a&#64;b").as_bytes())
        .is_err());
}
