//! Behavioral contract for subject-derived NZB metadata, through the public parser.
//!
//! Select the first complete, nonempty double-quoted filename span, never a
//! first-to-last-quote join. That span alone supplies role/container hints via
//! its case-insensitive terminal extension; unrelated prose cannot override it.
//! An unsupported terminal suffix stays unknown/other, even when an earlier
//! suffix is recognized. PAR2 around an audio name is par2/par2, not audio.
//!
//! With no complete nonempty quoted span, filename stays None (the existing
//! unquoted-fixture contract); ordinary unquoted filename tokens still supply
//! hints. Empty pairs and dangling quotes without a filename token fall back
//! to None/unknown/other without panicking. A dangling quote after a complete
//! filename cannot invalidate or extend that filename. No new formats implied.
//!
//! Controls retain raw subjects, Message-IDs, segment accounting, limits and
//! the existing length-prefixed segment fingerprint. All fixtures are local.
//! Builder must preserve this acceptance file and add production parser docs
//! alongside the implementation; these tests intentionally precede that work.

use nntune_core::nzb::{parse, Document, Limits, Parser};

fn document(subject: &str) -> String {
    let escaped = subject
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        "<nzb><file poster=\"p@example.com\" date=\"1700000000\" subject=\"{escaped}\">\
         <groups><group>alt.binaries.test</group></groups><segments>\
         <segment bytes=\"100\" number=\"1\">&lt;seg2@example.com&gt;</segment>\
         <segment bytes=\"200\" number=\"2\">seg1@example.com</segment>\
         <segment bytes=\"300\" number=\"3\">seg10@example.com</segment>\
         </segments></file></nzb>"
    )
}

fn parsed(subject: &str) -> Document {
    parse(document(subject).as_bytes()).expect("valid synthetic NZB must parse")
}

fn expect_metadata(subject: &str, filename: Option<&str>, role: &str, container: &str) {
    let doc = parsed(subject);
    assert_eq!(doc.files.len(), 1);
    let file = &doc.files[0];
    assert_eq!(
        (
            file.filename.as_deref(),
            file.role.as_str(),
            file.container.as_str()
        ),
        (filename, role, container),
        "subject: {subject:?}"
    );
}

#[test]
fn separate_quoted_commentary_is_not_joined_to_filename() {
    expect_metadata(
        r#"Album [01/02] - "01 track.flac" yEnc "upload note" (1/3)"#,
        Some("01 track.flac"),
        "content",
        "flac",
    );
}

#[test]
fn second_quoted_filename_cannot_replace_or_extend_the_selected_one() {
    expect_metadata(
        r#"Album - "track.flac" note "repair.par2""#,
        Some("track.flac"),
        "content",
        "flac",
    );
}

#[test]
fn empty_quote_pair_before_a_filename_is_skipped() {
    expect_metadata(
        r#"Album "" - "track.flac" yEnc"#,
        Some("track.flac"),
        "content",
        "flac",
    );
}

#[test]
fn dangling_quote_after_complete_filename_does_not_extend_it() {
    expect_metadata(
        r#"Album - "track.flac" yEnc "unfinished note"#,
        Some("track.flac"),
        "content",
        "flac",
    );
}

#[test]
fn par2_in_prose_cannot_reclassify_quoted_audio() {
    expect_metadata(
        r#"Album .par2 recovery available - "track.flac" yEnc"#,
        Some("track.flac"),
        "content",
        "flac",
    );
}

#[test]
fn rar_in_prose_cannot_reclassify_quoted_audio() {
    expect_metadata(
        r#"Album - "track.flac" yEnc; .rar archive available"#,
        Some("track.flac"),
        "content",
        "flac",
    );
}

#[test]
fn audio_container_in_prose_cannot_override_quoted_mp3() {
    expect_metadata(
        r#"Source .flac - "track.mp3" yEnc"#,
        Some("track.mp3"),
        "content",
        "mp3",
    );
}

#[test]
fn audio_named_par2_has_consistent_repair_role_and_container() {
    expect_metadata(
        r#"Album - "track.flac.par2" yEnc (1/3)"#,
        Some("track.flac.par2"),
        "par2",
        "par2",
    );
}

#[test]
fn audio_named_rar_has_consistent_archive_role_and_container() {
    expect_metadata(
        r#"Album - "track.mp3.rar" yEnc"#,
        Some("track.mp3.rar"),
        "archive",
        "rar",
    );
}

#[test]
fn earlier_repair_suffix_does_not_override_terminal_audio_extension() {
    expect_metadata(
        r#"Album - "repair.par2.flac" yEnc"#,
        Some("repair.par2.flac"),
        "content",
        "flac",
    );
}

#[test]
fn earlier_archive_suffix_does_not_override_terminal_audio_extension() {
    expect_metadata(
        r#"Album - "archive.rar.mp3" yEnc"#,
        Some("archive.rar.mp3"),
        "content",
        "mp3",
    );
}

#[test]
fn audio_extension_substring_is_not_a_terminal_extension() {
    expect_metadata(
        r#"Album - "track.flac.bak" yEnc"#,
        Some("track.flac.bak"),
        "unknown",
        "other",
    );
}

#[test]
fn repair_extension_substring_is_not_a_terminal_extension() {
    expect_metadata(
        r#"Album - "repair.par2-notes" yEnc"#,
        Some("repair.par2-notes"),
        "unknown",
        "other",
    );
}

#[test]
fn unsupported_quoted_filename_does_not_borrow_hints_from_prose() {
    expect_metadata(
        r#"Source .flac and .par2 - "readme.txt" yEnc"#,
        Some("readme.txt"),
        "unknown",
        "other",
    );
}

#[test]
fn ordinary_quoted_supported_extensions_keep_existing_hints() {
    for (subject, filename, role, container) in [
        (
            r#"Album - "track.flac" yEnc"#,
            "track.flac",
            "content",
            "flac",
        ),
        (r#"Album - "track.mp3" yEnc"#, "track.mp3", "content", "mp3"),
        (
            r#"Album - "repair.par2" yEnc"#,
            "repair.par2",
            "par2",
            "par2",
        ),
        (
            r#"Album - "archive.rar" yEnc"#,
            "archive.rar",
            "archive",
            "rar",
        ),
    ] {
        expect_metadata(subject, Some(filename), role, container);
    }
}

#[test]
fn supported_terminal_extensions_are_case_insensitive_without_renaming_file() {
    for (subject, filename, role, container) in [
        (
            r#"Album - "Track.FlAc" yEnc"#,
            "Track.FlAc",
            "content",
            "flac",
        ),
        (r#"Album - "Track.MP3" yEnc"#, "Track.MP3", "content", "mp3"),
        (
            r#"Album - "Repair.PaR2" yEnc"#,
            "Repair.PaR2",
            "par2",
            "par2",
        ),
        (
            r#"Album - "Archive.RaR" yEnc"#,
            "Archive.RaR",
            "archive",
            "rar",
        ),
    ] {
        expect_metadata(subject, Some(filename), role, container);
    }
}

#[test]
fn unquoted_fixtures_retain_hints_without_inventing_a_quoted_filename() {
    for (subject, role, container) in [
        ("Some Album - 01 track.flac (1/2)", "content", "flac"),
        ("Some Album - track.mp3 yEnc (1/3)", "content", "mp3"),
        ("Some Album - repair.par2 yEnc (1/3)", "par2", "par2"),
        ("Some Album - archive.rar yEnc (1/3)", "archive", "rar"),
    ] {
        expect_metadata(subject, None, role, container);
    }
}

#[test]
fn unquoted_extension_substring_does_not_create_audio_work() {
    expect_metadata(
        "Some Album - track.flac.bak (1/3)",
        None,
        "unknown",
        "other",
    );
}

#[test]
fn empty_and_unmatched_quotes_have_deterministic_safe_fallback() {
    for subject in [
        "Album without a filename",
        r#"Album "" yEnc"#,
        r#"Album "" yEnc """#,
        r#"Album "unfinished"#,
        r#"Album "" yEnc "unfinished"#,
    ] {
        for _ in 0..2 {
            expect_metadata(subject, None, "unknown", "other");
        }
    }
}

#[test]
fn unicode_filename_and_raw_subject_are_preserved() {
    let subject = r#"Album & Artist - "01 café live.FlAc" yEnc (1/3)"#;
    expect_metadata(subject, Some("01 café live.FlAc"), "content", "flac");
    assert_eq!(parsed(subject).files[0].subject, subject);
}

#[test]
fn subject_metadata_does_not_change_ids_accounting_or_fingerprint() {
    for subject in [
        r#"Album - "track.flac" yEnc"#,
        r#"Album .rar - "track.flac" yEnc "note .par2""#,
        "Some Album - 01 track.flac (1/2)",
        r#"Album "unfinished"#,
    ] {
        let doc = parsed(subject);
        let file = &doc.files[0];
        assert_eq!(file.subject, subject);
        assert_eq!(file.ordinal, 0);
        assert_eq!(file.posted_at_unix, 1_700_000_000);
        assert_eq!(doc.posted_at_unix, 1_700_000_000);
        assert!(!doc.has_password);
        assert_eq!(doc.encoded_bytes, 600);
        assert_eq!(file.segments.len(), 3);
        for (segment, (ordinal, number, id, bytes)) in file.segments.iter().zip([
            (0, 1, "seg2@example.com", 100),
            (1, 2, "seg1@example.com", 200),
            (2, 3, "seg10@example.com", 300),
        ]) {
            assert_eq!(segment.ordinal, ordinal);
            assert_eq!(segment.number, number);
            assert_eq!(segment.message_id, id);
            assert_eq!(segment.encoded_bytes, bytes);
        }
        // Existing Go-reference vector in tests/nzb.rs; independent of subject.
        let hex: String = doc
            .segment_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "5d46c9b1ce0c9f4c3618b12618d2223760453c5d61555e5cf26400aab6acbf42"
        );
    }
}

#[test]
fn metadata_candidates_do_not_bypass_resource_limits() {
    let xml = document(r#"Album - "track.flac" yEnc "note .par2""#);
    for limits in [
        Limits {
            segments_per_file: 2,
            ..Limits::default()
        },
        Limits {
            encoded_bytes: 599,
            ..Limits::default()
        },
        Limits {
            document_bytes: xml.len() as u64 - 1,
            ..Limits::default()
        },
    ] {
        assert!(Parser::new(limits).unwrap().parse(xml.as_bytes()).is_err());
    }
}

#[test]
fn metadata_candidates_do_not_relax_invalid_or_duplicate_message_ids() {
    let xml = document(r#"Album - "track.flac" yEnc "note .par2""#);
    assert!(parse(
        xml.replace("seg1@example.com", "not a message id")
            .as_bytes()
    )
    .is_err());
    assert!(parse(
        xml.replace("seg1@example.com", "seg2@example.com")
            .as_bytes()
    )
    .is_err());
}
