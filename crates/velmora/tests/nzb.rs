//! NZB parser tests: golden-file parsing, cross-implementation digest check,
//! and the resource-bound / malformation rejections ported from v1.

use nntune_core::nzb::{digest_message_ids, normalize_message_id, parse, Limits, Parser};

// NOTE: no DOCTYPE — like v1, this parser rejects ALL directives (even a
// bare `<!DOCTYPE nzb>` with no entities) as a hard XXE/billion-laughs
// posture. Real-world NZBs often carry one; stripping or policy-relaxing is
// an ingest-worker decision, flagged in the PR, not done here.
const BASIC: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<head>
<meta type="title">Some Album</meta>
</head>
<file poster="p@example.com" date="1700000000" subject="Some Album - 01 track.flac (1/2)">
<groups><group>alt.binaries.music</group></groups>
<segments>
<segment bytes="100" number="1">seg-1@example.com</segment>
<segment bytes="100" number="2">seg-2@example.com</segment>
</segments>
</file>
<file poster="p@example.com" date="1699999999" subject="Some Album [03/10] - &quot;02 track.flac&quot; yEnc (1/1)">
<groups><group>alt.binaries.music</group></groups>
<segments>
<segment bytes="200" number="1">seg-3@example.com</segment>
</segments>
</file>
</nzb>
"#;

#[test]
fn parses_basic_document() {
    let doc = parse(BASIC.as_bytes()).unwrap();
    assert_eq!(doc.files.len(), 2);
    assert!(!doc.has_password);
    assert_eq!(doc.encoded_bytes, 400);
    // Earliest file date wins.
    assert_eq!(doc.posted_at_unix, 1699999999);

    let f0 = &doc.files[0];
    assert_eq!(f0.ordinal, 0);
    assert_eq!(f0.segments.len(), 2);
    assert_eq!(f0.segments[0].message_id, "seg-1@example.com");
    // Bare segment text parses to the identical bare identity.
    assert_eq!(f0.segments[1].message_id, "seg-2@example.com");
    assert_eq!(f0.role, "content");
    assert_eq!(f0.container, "flac");
    assert!(f0.filename.is_none(), "no quoted span in subject");

    let f1 = &doc.files[1];
    assert_eq!(f1.filename.as_deref(), Some("02 track.flac"));
    assert_eq!(f1.role, "content");
}

#[test]
fn segment_digest_matches_go_implementation() {
    // Reference value produced by v1 `DigestMessageIDs` over the same IDs.
    let ids = vec![
        "seg2@example.com".to_string(),
        "seg1@example.com".to_string(),
        "seg10@example.com".to_string(),
    ];
    let digest = digest_message_ids(&ids).unwrap();
    assert_eq!(
        hex(&digest),
        "5d46c9b1ce0c9f4c3618b12618d2223760453c5d61555e5cf26400aab6acbf42"
    );

    // And the document digest covers exactly the parsed segment set.
    let doc = parse(BASIC.as_bytes()).unwrap();
    let mut ids: Vec<String> = doc
        .files
        .iter()
        .flat_map(|f| f.segments.iter().map(|s| s.message_id.clone()))
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "seg-1@example.com",
            "seg-2@example.com",
            "seg-3@example.com"
        ]
    );
    let _ = digest_message_ids(&ids).unwrap();
    assert_eq!(doc.segment_digest, digest_message_ids(&ids).unwrap());

    // Duplicates are an error, like v1.
    assert!(digest_message_ids(&["a@x".to_string(), "a@x".to_string()]).is_err());
}

#[test]
fn password_meta_sets_flag_and_is_kept_out_of_files() {
    let xml = BASIC.replace(
        "<meta type=\"title\">Some Album</meta>",
        "<meta type=\"title\">Some Album</meta><meta type=\"password\">secret</meta>",
    );
    let doc = parse(xml.as_bytes()).unwrap();
    assert!(doc.has_password);

    // Password metadata outside <head> is rejected.
    let xml = BASIC.replace(
        "<groups><group>alt.binaries.music</group></groups>",
        "<groups><group>alt.binaries.music</group></groups><meta type=\"password\">x</meta>",
    );
    assert!(parse(xml.as_bytes()).is_err());
}

#[test]
fn rejects_malformations() {
    // No files.
    assert!(parse(b"<nzb></nzb>").is_err());
    // Wrong root.
    assert!(parse(b"<rss></rss>").is_err());
    // Directives are not allowed, even a bare DOCTYPE with no entities.
    assert!(parse(b"<!DOCTYPE nzb><nzb></nzb>").is_err());
    // Trailing data after root.
    assert!(parse(b"<nzb><file poster=\"p\" date=\"1\" subject=\"s\"><segments><segment bytes=\"1\" number=\"1\">a@b</segment></segments></file></nzb>trailing").is_err());
    // Non-contiguous segment numbers.
    let xml = "<nzb><file poster=\"p\" date=\"1\" subject=\"s\"><segments><segment bytes=\"1\" number=\"2\">a@b</segment></segments></file></nzb>";
    assert!(parse(xml.as_bytes()).is_err());
    // Empty subject.
    let xml = "<nzb><file poster=\"p\" date=\"1\" subject=\"\"><segments><segment bytes=\"1\" number=\"1\">a@b</segment></segments></file></nzb>";
    assert!(parse(xml.as_bytes()).is_err());
    // Bad message-id.
    let xml = "<nzb><file poster=\"p\" date=\"1\" subject=\"s\"><segments><segment bytes=\"1\" number=\"1\">not a message id</segment></segments></file></nzb>";
    assert!(parse(xml.as_bytes()).is_err());
    // Truncated input.
    assert!(parse(b"<nzb><file ").is_err());
}

#[test]
fn enforces_limits() {
    // File count.
    let limits = Limits {
        files: 1,
        ..Limits::default()
    };
    assert!(Parser::new(limits)
        .unwrap()
        .parse(BASIC.as_bytes())
        .is_err());
    // Segments per file.
    let limits = Limits {
        segments_per_file: 1,
        ..Limits::default()
    };
    assert!(Parser::new(limits)
        .unwrap()
        .parse(BASIC.as_bytes())
        .is_err());
    // Declared bytes.
    let limits = Limits {
        encoded_bytes: 100,
        ..Limits::default()
    };
    assert!(Parser::new(limits)
        .unwrap()
        .parse(BASIC.as_bytes())
        .is_err());
    // Document bytes.
    let limits = Limits {
        document_bytes: 64,
        ..Limits::default()
    };
    assert!(Parser::new(limits)
        .unwrap()
        .parse(BASIC.as_bytes())
        .is_err());
    // Invalid limits are rejected at construction.
    assert!(Parser::new(Limits {
        files: 0,
        ..Limits::default()
    })
    .is_err());
    assert!(Parser::new(Limits {
        files: 99999,
        ..Limits::default()
    })
    .is_err());
}

#[test]
fn xxee_and_billion_laughs_are_rejected() {
    // External entities are directives/doctypes -> rejected, never fetched.
    let xml = "<?xml version=\"1.0\"?><!DOCTYPE nzb [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><nzb><file poster=\"p\" date=\"1\" subject=\"s\"><segments><segment bytes=\"1\" number=\"1\">&xxe;</segment></segments></file></nzb>";
    let err = parse(xml.as_bytes()).unwrap_err();
    assert!(err.to_string().contains("directives"), "got: {err}");

    // Deep metadata nesting is bounded.
    let mut xml = String::from("<nzb><head>");
    for i in 0..200 {
        xml.push_str(&format!("<a{i}>"));
    }
    xml.push('x');
    for i in (0..200).rev() {
        xml.push_str(&format!("</a{i}>"));
    }
    xml.push_str("</head><file poster=\"p\" date=\"1\" subject=\"s\"><segments><segment bytes=\"1\" number=\"1\">a@b</segment></segments></file></nzb>");
    assert!(parse(xml.as_bytes()).is_err());
}

#[test]
fn normalize_message_id_rules() {
    // Strict: only already-bare ids pass; brackets and padding are refused,
    // never trimmed or stripped into acceptance.
    assert_eq!(normalize_message_id("a@b").unwrap(), "a@b");
    assert!(normalize_message_id("<a@b>").is_err());
    assert!(normalize_message_id("  a@b  ").is_err());
    assert!(normalize_message_id("< a@b >").is_err());
    assert!(normalize_message_id("").is_err());
    assert!(normalize_message_id("a b@c").is_err());
    assert!(normalize_message_id("a<b@c>").is_err());
    assert!(normalize_message_id(&"a".repeat(999)).is_err());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
