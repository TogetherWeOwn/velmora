//! Segment identity: the one shared message-id rule for ingest, probe,
//! body, play, and the NNTP wire adapters.
//!
//! Every stage that touches a segment id — NZB intake
//! (`workers/ingest`), the probe/body JSON envelopes (both sides), the
//! play path, and the `STAT`/`ARTICLE`/`BODY <id>` wire adapters —
//! enforces exactly this rule, documented here and nowhere else:
//!
//! - 1..=[`MAX_SEGMENT_ID_BYTES`] bytes (the 250-byte wire ceiling — see
//!   below), printable ASCII (`0x21..=0x7E`) only, no `<`/`>`;
//! - exactly one `@` with non-empty local and domain sides
//!   (RFC 5536 `msg-id`, bracketless form — the wire layer adds `<…>`);
//! - **no normalization**: the id is validated byte-for-byte as given.
//!   Outer whitespace, `<…>` brackets, or any other refused spelling is
//!   refused, never trimmed or unbracketed into an accepted identity, so
//!   every spelling is treated identically at every stage.
//!
//! The ceiling is the wire adapter's: a longer id can never be fetched,
//! so intake and the envelopes refuse it before any pool lease or dial
//! instead of failing late with wasted provider connections. Each stage
//! still re-validates on receipt (defense in depth) — the rule is shared,
//! the checks are not skipped.

/// Longest segment id any stage accepts, in bytes.
///
/// This is the NNTP wire ceiling: the `BODY <id>` adapter refuses longer
/// ids without writing a byte, so every earlier stage refuses them too
/// (before leases and dials) instead of failing late at the provider.
pub const MAX_SEGMENT_ID_BYTES: usize = 250;

/// Whether `id` is a usable segment identity under the shared rule.
///
/// Bare printable ASCII with exactly one non-edge `@`, at most
/// [`MAX_SEGMENT_ID_BYTES`] bytes, validated exactly as given — never
/// trimmed, unbracketed, or otherwise normalized.
pub fn valid_segment_id(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_SEGMENT_ID_BYTES {
        return false;
    }
    if !id.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return false;
    }
    if id.contains('<') || id.contains('>') {
        return false;
    }
    let mut parts = id.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(local), Some(domain), None) if !local.is_empty() && !domain.is_empty()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(bytes: usize) -> String {
        format!("{}@b", "a".repeat(bytes - 2))
    }

    #[test]
    fn shared_rule_pins_the_wire_ceiling_and_bare_shape() {
        assert!(valid_segment_id("a@b"));
        assert!(valid_segment_id("!~@synthetic.invalid"));
        assert!(valid_segment_id(&id(249)));
        assert!(valid_segment_id(&id(250)));
        assert!(!valid_segment_id(&id(251)));
        assert!(!valid_segment_id(&id(512)));
        assert!(!valid_segment_id(&id(513)));
        // Refused spellings are refused, never normalized into acceptance.
        assert!(!valid_segment_id("<seg@synthetic.invalid>"));
        assert!(!valid_segment_id(" seg@synthetic.invalid"));
        assert!(!valid_segment_id("seg@synthetic.invalid "));
        assert!(!valid_segment_id("  <seg@synthetic.invalid>  "));
        assert!(!valid_segment_id("\tseg@synthetic.invalid"));
        assert!(!valid_segment_id("seg@synthetic.invalid\r"));
        assert!(!valid_segment_id("\nseg@synthetic.invalid"));
        // Injection, malformed, and non-ASCII shapes stay refused.
        assert!(!valid_segment_id("x@y>\r\nQUIT\r\n<z"));
        assert!(!valid_segment_id("se g@synthetic.invalid"));
        assert!(!valid_segment_id("seg@@synthetic.invalid"));
        assert!(!valid_segment_id("@synthetic.invalid"));
        assert!(!valid_segment_id("seg@"));
        assert!(!valid_segment_id("not-a-message-id"));
        assert!(!valid_segment_id(""));
        assert!(!valid_segment_id("se\0g@synthetic.invalid"));
        assert!(!valid_segment_id("seg@synthetic.\x7finvalid"));
        assert!(!valid_segment_id("s\u{e9}g@synthetic.invalid"));
    }
}
