//! Cross-directory corpus-consistency regression for the staging E2E NZB.
//!
//! `e2e/fixtures/synthetic.nzb` claims its segment message-IDs "match the
//! synthetic NNTP fixture server corpus". The pre-existing
//! `nzb_fixtures_match_served_ids` test only checks this crate's own
//! `fixtures/nzb/` directory, so the staging fixture could (and did) drift
//! to IDs the corpus never serves. These tests close that gap:
//!
//! * every segment ID and group in the checked-in staging NZB must resolve
//!   in `default_corpus()` (no invented/external provider data);
//! * segment numbering and declared `bytes=` must agree with the corpus
//!   payloads and their yEnc framing (`=ybegin`/`=ypart` ranges);
//! * fetching the segments from a live in-process fixture server and
//!   yEnc-decoding them must reconstruct one complete canonical synthetic
//!   WAV (a generated sine tone, byte-for-byte);
//! * positive/negative controls prove the validator itself catches a
//!   missing/renamed ID and accepts a known-good canonical NZB.
//!
//! * the production NZB parser accepts the fixture and the production
//!   NNTP client + yEnc decoder reproduce the canonical WAV, so a fixture
//!   ingest itself would reject cannot pass here.
//!
//! Offline and deterministic: loopback fixture server only, synthetic
//! `@nntune.test` data only.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transports::connect_native;
use nntune_test_nntp::{default_corpus, generate_wav_bytes, Article, TestNntpServer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Minimal NZB parsing (shared by the controls and the staging-fixture tests)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Segment {
    bytes: u64,
    number: u32,
    /// Normalized message-ID, angle brackets included.
    id: String,
}

#[derive(Debug)]
struct ParsedFile {
    groups: Vec<String>,
    segments: Vec<Segment>,
}

#[derive(Debug)]
struct ParsedNzb {
    files: Vec<ParsedFile>,
}

impl ParsedNzb {
    fn groups(&self) -> Vec<String> {
        self.files.iter().flat_map(|f| f.groups.clone()).collect()
    }
    fn segments(&self) -> Vec<Segment> {
        self.files.iter().flat_map(|f| f.segments.clone()).collect()
    }
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let start = tag.find(&format!("{name}=\""))? + name.len() + 2;
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn parse_nzb(text: &str) -> ParsedNzb {
    // NZB groups/segments are scoped per <file>; segment numbering restarts
    // at 1 for each file. Split into file blocks first (a document with no
    // <file> is treated as one anonymous file).
    let mut blocks: Vec<&str> = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("<file") {
        rest = &rest[i..];
        match rest.find("</file>") {
            Some(end) => {
                blocks.push(&rest[..end]);
                rest = &rest[end..];
            }
            None => break,
        }
    }
    if blocks.is_empty() {
        blocks.push(text);
    }

    let files = blocks
        .into_iter()
        .map(|block| {
            let mut groups = Vec::new();
            let mut r = block;
            while let Some(i) = r.find("<group>") {
                r = &r[i + "<group>".len()..];
                let end = r.find("</group>").expect("unterminated <group>");
                groups.push(xml_unescape(r[..end].trim()));
                r = &r[end..];
            }

            let mut segments = Vec::new();
            let mut r = block;
            while let Some(i) = r.find("<segment ") {
                r = &r[i..];
                let tag_end = r.find('>').expect("unterminated <segment> tag");
                let tag = &r[..tag_end];
                let bytes: u64 = attr(tag, "bytes")
                    .expect("segment missing bytes=")
                    .parse()
                    .expect("segment bytes= not a number");
                let number: u32 = attr(tag, "number")
                    .expect("segment missing number=")
                    .parse()
                    .expect("segment number= not a number");
                let body_start = tag_end + 1;
                let body_end = r[body_start..]
                    .find("</segment>")
                    .expect("unterminated </segment>")
                    + body_start;
                let raw_id = xml_unescape(r[body_start..body_end].trim());
                let id = if raw_id.starts_with('<') {
                    raw_id
                } else {
                    format!("<{raw_id}>")
                };
                segments.push(Segment { bytes, number, id });
                r = &r[body_end..];
            }
            ParsedFile { groups, segments }
        })
        .collect();
    ParsedNzb { files }
}

fn corpus_by_id() -> HashMap<String, Article> {
    default_corpus()
        .into_iter()
        .map(|a| (a.message_id.clone(), a))
        .collect()
}

/// Validate an NZB document against the default corpus. Returns every
/// inconsistency found (empty = consistent) so controls can assert on the
/// failure mode, not just on pass/fail.
fn validate_nzb_against_corpus(text: &str) -> Vec<String> {
    let corpus = corpus_by_id();
    let parsed = parse_nzb(text);
    let mut errors = Vec::new();

    let all_segments = parsed.segments();
    if all_segments.is_empty() {
        errors.push("NZB declares no <segment>s".to_string());
        return errors;
    }
    let all_groups = parsed.groups();
    if all_groups.is_empty() {
        errors.push("NZB declares no <group>s".to_string());
    }

    // Per file, segment numbers must be 1..=N, contiguous, each exactly
    // once, in ascending document order (a reordered NZB would silently
    // scramble the reconstructed payload for order-based consumers).
    for (fi, file) in parsed.files.iter().enumerate() {
        let numbers: Vec<u32> = file.segments.iter().map(|s| s.number).collect();
        let expected: Vec<u32> = (1..=file.segments.len() as u32).collect();
        if numbers != expected {
            errors.push(format!(
                "file {} segment numbers {numbers:?} are not contiguous 1..=N in order (expected {expected:?})",
                fi + 1
            ));
        }
    }

    for seg in &all_segments {
        match corpus.get(&seg.id) {
            None => errors.push(format!(
                "segment {} references {} which the default synthetic corpus does not serve",
                seg.number, seg.id
            )),
            Some(article) => {
                if seg.bytes != article.payload.len() as u64 {
                    errors.push(format!(
                        "segment {} ({}) declares bytes={} but the corpus payload is {} bytes",
                        seg.number,
                        seg.id,
                        seg.bytes,
                        article.payload.len()
                    ));
                }
                if !all_groups.iter().any(|g| g == &article.group) {
                    errors.push(format!(
                        "segment {} ({}) is served in group {} which the NZB does not list (groups: {:?})",
                        seg.number, seg.id, article.group, all_groups
                    ));
                }
            }
        }
        if !seg.id.ends_with("@nntune.test>") {
            errors.push(format!(
                "segment {} ({}) is not synthetic @nntune.test data",
                seg.number, seg.id
            ));
        }
    }
    errors
}

fn staging_nzb_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../e2e/fixtures/synthetic.nzb")
}

fn staging_nzb_text() -> String {
    let path = staging_nzb_path();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("staging NZB unreadable at {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Controls: the validator accepts a canonical NZB and rejects drift
// ---------------------------------------------------------------------------

#[test]
fn validator_accepts_canonical_crate_nzb_fixtures() {
    // Positive control: this crate's own NZBs are corpus-consistent, so a
    // failure on the staging fixture below is the fixture's drift, not a
    // broken validator.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/nzb");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let errors = validate_nzb_against_corpus(&text);
        assert!(errors.is_empty(), "{}: {errors:?}", path.display());
        checked += 1;
    }
    assert!(checked > 0, "no canonical NZBs found under fixtures/nzb");
}

#[test]
fn validator_rejects_unknown_and_renamed_ids() {
    // Negative control standing in for the current staging drift: plausible
    // synthetic-looking IDs that the corpus simply does not serve.
    let stale = r#"<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="e2e@nntune.test" date="1798761600" subject="stale">
    <groups><group>alt.binaries.nntune.test</group></groups>
    <segments>
      <segment bytes="9" number="1">synthetic-e2e-part1@nntune.test</segment>
      <segment bytes="9" number="2">synthetic-e2e-part2@nntune.test</segment>
    </segments>
  </file>
</nzb>"#;
    let errors = validate_nzb_against_corpus(stale);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("<synthetic-e2e-part1@nntune.test>")),
        "stale ID not reported: {errors:?}"
    );

    // A renamed canonical ID (one character off) and a wrong byte count on
    // a real ID must both be caught too.
    let renamed = stale.replace(
        "synthetic-e2e-part1@nntune.test",
        "single-yenc-002@nntune.test",
    );
    let errors = validate_nzb_against_corpus(&renamed);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("<single-yenc-002@nntune.test>")),
        "renamed ID not reported: {errors:?}"
    );
    let wrong_bytes = r#"<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="fixture@nntune.test" date="1760313600" subject="x">
    <groups><group>alt.binaries.nntune.test</group></groups>
    <segments>
      <segment bytes="9" number="1">&lt;single-yenc-001@nntune.test&gt;</segment>
    </segments>
  </file>
</nzb>"#;
    let errors = validate_nzb_against_corpus(wrong_bytes);
    assert!(
        errors.iter().any(|e| e.contains("declares bytes=9")),
        "byte-count drift not reported: {errors:?}"
    );
}

// ---------------------------------------------------------------------------
// The staging fixture itself
// ---------------------------------------------------------------------------

#[test]
fn staging_nzb_every_segment_and_group_resolves_in_default_corpus() {
    let errors = validate_nzb_against_corpus(&staging_nzb_text());
    assert!(
        errors.is_empty(),
        "e2e/fixtures/synthetic.nzb is inconsistent with the default synthetic corpus:\n- {}",
        errors.join("\n- ")
    );
}

#[test]
fn staging_nzb_has_no_stale_two_nine_byte_text_claim() {
    // The NZB header comment is the contract staging readers follow; the
    // "two tiny text segments / each segment is 9 bytes" description does
    // not describe any canonical corpus article and must not survive the
    // alignment (checked here as text because the claim itself is text —
    // the executable payload contract is pinned by the other tests).
    let text = staging_nzb_text();
    assert!(
        !text.contains("two tiny text segments") && !text.contains("each segment is 9 bytes"),
        "staging NZB still carries the stale two-nine-byte-text claim"
    );
}

// ---------------------------------------------------------------------------
// Executable end-to-end (offline): fetch via NNTP, decode, reconstruct
// ---------------------------------------------------------------------------

struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Client {
    async fn connect(server: &TestNntpServer) -> Self {
        let stream = TcpStream::connect(server.addr()).await.unwrap();
        let (r, w) = stream.into_split();
        let mut c = Self {
            reader: BufReader::new(r),
            writer: w,
        };
        assert!(c.read_line().await.starts_with("200"));
        let u = c.cmd("AUTHINFO USER testuser").await;
        assert!(u.starts_with("381"), "AUTHINFO USER: {u:?}");
        let p = c.cmd("AUTHINFO PASS testpass").await;
        assert!(p.starts_with("281"), "AUTHINFO PASS: {p:?}");
        c
    }

    async fn read_line(&mut self) -> String {
        let mut s = String::new();
        assert!(self.reader.read_line(&mut s).await.unwrap() > 0);
        s
    }

    async fn cmd(&mut self, cmd: &str) -> String {
        self.writer
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        self.read_line().await
    }

    async fn cmd_block(&mut self, cmd: &str) -> (String, Vec<u8>) {
        self.writer
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        let first = self.read_line().await;
        // An error status (e.g. 430 for an unknown message-ID) is a
        // single line with no dot-terminated block following it.
        if first.starts_with(['4', '5']) {
            return (first, Vec::new());
        }
        let mut raw = Vec::new();
        loop {
            let mut line: Vec<u8> = Vec::new();
            assert!(self.reader.read_until(b'\n', &mut line).await.unwrap() > 0);
            if line.ends_with(b"\n") {
                line.pop();
                if line.ends_with(b"\r") {
                    line.pop();
                }
            }
            if line == b"." {
                break;
            }
            if line.starts_with(b"..") {
                raw.extend_from_slice(&line[1..]);
            } else {
                raw.extend_from_slice(&line);
            }
            raw.extend_from_slice(b"\r\n");
        }
        (first, raw)
    }
}

fn article_body(block: &[u8]) -> &[u8] {
    let pos = block
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header/body sep");
    &block[pos + 4..]
}

fn framing_param(body: &[u8], framing: &str, key: &str) -> Option<String> {
    String::from_utf8_lossy(body).lines().find_map(|line| {
        line.starts_with(framing).then(|| {
            line.split_whitespace()
                .find_map(|t| t.strip_prefix(&format!("{key}=")).map(str::to_string))
        })?
    })
}

#[tokio::test]
async fn staging_nzb_reconstructs_one_complete_canonical_wav_via_nntp() {
    let text = staging_nzb_text();
    let parsed = parse_nzb(&text);
    assert!(
        !parsed.segments().is_empty(),
        "staging NZB declares no segments"
    );
    assert_eq!(
        parsed.files.len(),
        1,
        "staging NZB must carry exactly one file (one reconstructable track)"
    );

    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    for group in &parsed.groups() {
        let g = c.cmd(&format!("GROUP {group}")).await;
        assert!(g.starts_with("211"), "GROUP {group}: {g:?}");
    }

    let mut ordered = parsed.segments();
    ordered.sort_by_key(|s| s.number);

    let mut file_name: Option<String> = None;
    let mut file_size: Option<u64> = None;
    let mut total_parts: Option<u32> = None;
    let mut placed: Vec<(u64, Vec<u8>)> = Vec::new(); // (1-based begin, decoded)

    for seg in &ordered {
        let (first, block) = c.cmd_block(&format!("ARTICLE {}", seg.id)).await;
        assert!(
            first.starts_with("220"),
            "staging NZB segment {} ({}) is not served by the synthetic corpus: {first:?}",
            seg.number,
            seg.id
        );
        let body = article_body(&block);

        // One NZB file = one yEnc file: shared name/size across segments.
        let name = framing_param(body, "=ybegin", "name")
            .unwrap_or_else(|| panic!("segment {} has no =ybegin name", seg.number));
        match &file_name {
            None => file_name = Some(name),
            Some(prev) => assert_eq!(&name, prev, "staging NZB mixes yEnc files"),
        }
        let size: u64 = framing_param(body, "=ybegin", "size")
            .unwrap_or_else(|| panic!("segment {} has no =ybegin size", seg.number))
            .parse()
            .expect("=ybegin size");
        match file_size {
            None => file_size = Some(size),
            Some(prev) => assert_eq!(size, prev, "=ybegin size changes across segments"),
        }

        // NZB segment number must be the yEnc part number (single-part
        // framing has no part=/total= and is part 1 of 1).
        let part: u32 = framing_param(body, "=ybegin", "part")
            .map(|p| p.parse().expect("=ybegin part"))
            .unwrap_or(1);
        assert_eq!(
            part, seg.number,
            "NZB number= disagrees with yEnc part= for {}",
            seg.id
        );
        let total: u32 = framing_param(body, "=ybegin", "total")
            .map(|p| p.parse().expect("=ybegin total"))
            .unwrap_or(1);
        match total_parts {
            None => total_parts = Some(total),
            Some(prev) => assert_eq!(total, prev, "=ybegin total changes across segments"),
        }

        let decoded = nntune_test_nntp::yenc::decode(body);
        assert_eq!(
            decoded.len() as u64,
            seg.bytes,
            "decoded payload length disagrees with NZB bytes= for {}",
            seg.id
        );

        // Placement comes from the advertised =ypart range, whose length
        // must also equal the declared/decoded byte count.
        let (begin, end) = match (
            framing_param(body, "=ypart", "begin"),
            framing_param(body, "=ypart", "end"),
        ) {
            (Some(b), Some(e)) => (
                b.parse::<u64>().expect("=ypart begin"),
                e.parse::<u64>().expect("=ypart end"),
            ),
            _ => (1, decoded.len() as u64),
        };
        assert_eq!(
            end + 1 - begin,
            decoded.len() as u64,
            "=ypart range length disagrees with payload for {}",
            seg.id
        );
        placed.push((begin, decoded));
    }

    // The NZB must carry the *complete* file, not a subset of its parts.
    assert_eq!(
        total_parts,
        Some(ordered.len() as u32),
        "staging NZB does not carry every part of its yEnc file"
    );

    let size = file_size.expect("no segments") as usize;
    let mut reassembled = vec![0u8; size];
    let mut covered = vec![false; size];
    for (begin, bytes) in &placed {
        let start = (*begin - 1) as usize;
        for (i, b) in bytes.iter().enumerate() {
            assert!(!covered[start + i], "overlapping =ypart ranges");
            covered[start + i] = true;
            reassembled[start + i] = *b;
        }
    }
    assert!(
        covered.iter().all(|&c| c),
        "=ypart ranges do not cover the whole file"
    );

    // The reconstructed payload is a real canonical synthetic tone — one
    // of the generated WAV fixtures, byte-for-byte. It must also be long
    // enough for the staging spec's Range seeks (bytes=0-8 and 9-17 in
    // e2e/tests/ingest-play-meter.spec.ts), i.e. at least 18 bytes.
    assert!(reassembled.len() >= 18, "payload too short for Range seeks");
    assert_eq!(&reassembled[0..4], b"RIFF", "payload is not a WAV");
    assert_eq!(&reassembled[8..12], b"WAVE", "payload is not a WAV");
    let canonical = [
        generate_wav_bytes(440.0, 120, 8000),
        generate_wav_bytes(660.0, 210, 8000),
        generate_wav_bytes(550.0, 180, 8000),
    ];
    assert!(
        canonical.iter().any(|w| w == &reassembled),
        "reconstructed payload ({} bytes) is not a canonical generated sine WAV",
        reassembled.len()
    );
}

// ---------------------------------------------------------------------------
// Production path: the parser, NNTP client and yEnc decoder ingest uses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn staging_nzb_parses_fetches_and_decodes_via_production_pipeline() {
    // Corpus consistency alone is not ingestability: the hand-rolled scanner
    // above accepts documents the production parser rejects (it refuses every
    // DOCTYPE as XXE hardening). This test runs the production components —
    // `nntune_core::nzb::parse` (the parser the ingest upload handler calls),
    // `NntpClient` and `yenc::decode_to` — so a fixture the upload would
    // reject with a 400 fails here.
    let text = staging_nzb_text();
    let document = nntune_core::nzb::parse(text.as_bytes())
        .expect("production NZB parser accepts the staging fixture");
    assert_eq!(document.files.len(), 1, "staging NZB carries one file");
    let file = &document.files[0];
    assert!(
        !file.segments.is_empty(),
        "staging NZB declares no segments"
    );

    // The production parse must agree with the corpus view: the same segment
    // IDs (production IDs are bare, corpus IDs are bracketed), in order.
    let corpus_ids: Vec<String> = parse_nzb(&text)
        .segments()
        .into_iter()
        .map(|s| s.id.trim_matches(['<', '>']).to_string())
        .collect();
    let production_ids: Vec<&str> = file
        .segments
        .iter()
        .map(|s| s.message_id.as_str())
        .collect();
    assert_eq!(production_ids, corpus_ids);

    let server = TestNntpServer::spawn_for_test().await;
    let config = NntpConfig {
        host: "127.0.0.1".into(),
        port: server.addr().port(),
        tls: false,
        username: Some("testuser".into()),
        password: Some("testpass".into()),
        timeout: Duration::from_secs(2),
        max_pipelined: 4,
        ..NntpConfig::default()
    };
    let transport = connect_native(&config)
        .await
        .expect("connect to fixture server");
    let mut client = NntpClient::connect(transport, &config)
        .await
        .expect("NNTP handshake");
    let fetched = client
        .fetch_many(&production_ids)
        .await
        .expect("fetch staging segments via production NNTP client");
    client.quit().await;
    assert_eq!(fetched.len(), file.segments.len());

    // Decode each fetched article with the production decoder (which also
    // verifies CRC) into a buffer sized by the declared segment bytes, and
    // reassemble in segment-number order.
    let mut reassembled = Vec::new();
    for segment in &file.segments {
        let article = fetched
            .iter()
            .find(|f| f.message_id == segment.message_id)
            .unwrap_or_else(|| panic!("no fetched article for {}", segment.message_id));
        let mut decoded = vec![0u8; segment.encoded_bytes as usize];
        let decoded_len =
            nntune_core::yenc::decode_to(&segment.message_id, &article.article, &mut decoded)
                .unwrap_or_else(|e| {
                    panic!(
                        "production yEnc decoder rejects {}: {e:?}",
                        segment.message_id
                    )
                });
        assert_eq!(
            decoded_len,
            decoded.len(),
            "decoded length disagrees with NZB bytes= for {}",
            segment.message_id
        );
        reassembled.extend_from_slice(&decoded);
    }

    assert_eq!(
        reassembled,
        generate_wav_bytes(660.0, 210, 8000),
        "production pipeline does not reproduce the canonical 660 Hz WAV"
    );
}
