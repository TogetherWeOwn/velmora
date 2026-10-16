//! Large-NZB stress corpus at the parser's encoded-bytes cap.
//!
//! The large corpus is 64 files x 1024 segments = 65,536 Message-IDs, each
//! declaring a 1 MiB payload: 64 GiB declared, exactly
//! [`nntune_core::nzb::MAX_ENCODED_BYTES`], in ~5 MiB of XML. Declared bytes
//! are O(1) arithmetic per segment; what scales is the segment count (XML
//! size, ID collection, digest), so the corpus is sized on ID count, not on
//! declared gigabytes.
//!
//! Two gates, neither vacuous:
//! - [`STRESS_TIME_BOUND`]: an absolute bound for the full-cap corpus
//!   (measured ~0.43 s in a debug build, so 5 s is ~10x headroom while a
//!   quadratic regression at 65,536 IDs takes minutes).
//! - a scaling assertion: parsing 4x the IDs must cost less than 8x the time
//!   (best-of-3, machine-normalised). Linear parsing costs ~4x; a quadratic
//!   regression costs ~16x and fails regardless of host speed.
//!
//! The digest is checked against an expected value computed independently
//! in this file from the generated IDs, never against the parser's own
//! digest helper.

use std::time::{Duration, Instant};

use nntune_core::nzb::Parser;
use sha2::{Digest, Sha256};

/// Stated CI time bound for parsing the full-cap stress corpus (debug build).
const STRESS_TIME_BOUND: Duration = Duration::from_secs(5);

/// Declared wire bytes per synthetic segment (1 MiB of encoded payload).
const BYTES_PER_SEGMENT: i64 = 1 << 20;

/// The full-cap corpus shape: 65,536 IDs declaring 64 GiB.
const LARGE_FILES: usize = 64;
const LARGE_SEGMENTS_PER_FILE: usize = 1024;

fn message_id(file: usize, segment: usize) -> String {
    format!("msg-{file}-{segment}@stress.example.com")
}

fn build_corpus(files: usize, segments_per_file: usize) -> Vec<u8> {
    let mut xml = String::from("<nzb>");
    for f in 0..files {
        xml.push_str(&format!(
            "<file poster=\"p\" date=\"1700000000\" subject=\"stress vol{f} (1/1)\"><segments>"
        ));
        for s in 0..segments_per_file {
            let number = s + 1;
            let id = message_id(f, s);
            xml.push_str(&format!(
                "<segment bytes=\"{BYTES_PER_SEGMENT}\" number=\"{number}\">{id}</segment>"
            ));
        }
        xml.push_str("</segments></file>");
    }
    xml.push_str("</nzb>");
    xml.into_bytes()
}

/// Expected segment digest, computed from first principles: sort the IDs
/// this corpus generates, then SHA-256 over each ID's 4-byte big-endian
/// length followed by its bytes. Deliberately does not call
/// `nntune_core::nzb::digest_message_ids`, so a truncated or mis-ordered
/// production digest fails the equality assertions below.
fn expected_digest(files: usize, segments_per_file: usize) -> [u8; 32] {
    let mut ids: Vec<String> = (0..files)
        .flat_map(|f| (0..segments_per_file).map(move |s| message_id(f, s)))
        .collect();
    ids.sort();
    let mut hash = Sha256::new();
    for id in &ids {
        hash.update((id.len() as u32).to_be_bytes());
        hash.update(id.as_bytes());
    }
    hash.finalize().into()
}

fn parse_timed(xml: &[u8]) -> (nntune_core::nzb::Document, Duration) {
    let started = Instant::now();
    let doc = Parser::with_default_limits()
        .unwrap()
        .parse(xml)
        .expect("stress corpus parses within default limits");
    (doc, started.elapsed())
}

fn parse_best_of(xml: &[u8], runs: usize) -> Duration {
    (0..runs)
        .map(|_| parse_timed(xml).1)
        .min()
        .expect("at least one run")
}

#[test]
fn stress_corpus_at_encoded_bytes_cap_parses_under_time_bound() {
    // 64 files x 1024 segments x 1 MiB = 64 GiB declared (the cap),
    // 65,536 Message-IDs in ~5 MiB of XML.
    let xml = build_corpus(LARGE_FILES, LARGE_SEGMENTS_PER_FILE);
    assert!(
        (xml.len() as u64) < nntune_core::nzb::MAX_DOCUMENT_BYTES,
        "corpus XML {} bytes must stay under the document bound",
        xml.len()
    );
    let (doc, elapsed) = parse_timed(&xml);
    assert_eq!(doc.files.len(), LARGE_FILES);
    assert!(doc
        .files
        .iter()
        .all(|f| f.segments.len() == LARGE_SEGMENTS_PER_FILE));
    let declared = LARGE_FILES as i64 * LARGE_SEGMENTS_PER_FILE as i64 * BYTES_PER_SEGMENT;
    assert_eq!(declared, nntune_core::nzb::MAX_ENCODED_BYTES);
    assert_eq!(doc.encoded_bytes, declared);
    let ids: usize = doc.files.iter().map(|f| f.segments.len()).sum();
    assert_eq!(ids, LARGE_FILES * LARGE_SEGMENTS_PER_FILE);
    assert_eq!(
        doc.segment_digest,
        expected_digest(LARGE_FILES, LARGE_SEGMENTS_PER_FILE),
        "digest must cover every one of the {ids} IDs, in sorted order"
    );
    assert_ne!(
        doc.segment_digest,
        expected_digest(1, 2048),
        "different corpora must not collapse to the same digest"
    );
    assert!(
        elapsed <= STRESS_TIME_BOUND,
        "stress parse took {elapsed:?}, bound is {STRESS_TIME_BOUND:?} ({} KiB XML, {} segments)",
        xml.len() / 1024,
        ids,
    );
}

#[test]
fn parse_time_scales_sub_quadratically_with_segment_count() {
    // 16,384 IDs vs 65,536 IDs (4x). Linear parsing costs ~4x; the bound
    // allows 8x for constant-factor noise. A quadratic step in parsing or
    // digesting costs ~16x and fails on any host speed.
    let small = build_corpus(LARGE_FILES, LARGE_SEGMENTS_PER_FILE / 4);
    let large = build_corpus(LARGE_FILES, LARGE_SEGMENTS_PER_FILE);
    let small_time = parse_best_of(&small, 3);
    let large_time = parse_best_of(&large, 3);
    let ratio = large_time.as_secs_f64() / small_time.as_secs_f64();
    assert!(
        ratio < 8.0,
        "4x the segments cost {ratio:.2}x the time (small {small_time:?}, large {large_time:?}); \
         expected near-linear (~4x), quadratic would be ~16x"
    );
}

#[test]
fn single_file_two_gib_declared_parses_under_time_bound() {
    // 1 file x 2048 segments x 1 MiB = 2 GiB declared: the segments-per-file
    // scaling axis, still under the 4096 cap.
    let xml = build_corpus(1, 2048);
    let (doc, elapsed) = parse_timed(&xml);
    assert_eq!(doc.files.len(), 1);
    assert_eq!(doc.files[0].segments.len(), 2048);
    assert_eq!(doc.encoded_bytes, 2048 * BYTES_PER_SEGMENT);
    assert_eq!(doc.segment_digest, expected_digest(1, 2048));
    assert!(
        elapsed <= STRESS_TIME_BOUND,
        "stress parse took {elapsed:?}, bound is {STRESS_TIME_BOUND:?}"
    );
}
