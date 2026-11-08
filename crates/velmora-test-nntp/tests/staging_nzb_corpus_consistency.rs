//! Corpus-consistency regression for the in-memory generated NZBs.
//!
//! There are no checked-in NZB files anywhere: every NZB under test is built
//! in memory with [`velmora_test_nntp::nzb_for`] from the served corpus. These
//! tests close the gap the old checked-in staging fixture used to leave:
//!
//! * every generated segment ID and group must resolve in
//!   `default_corpus()` (no invented/external provider data);
//! * segment numbering must agree with yEnc part numbers; declared `bytes=`
//!   counts encoded articles (headers + body, before NNTP dot-stuffing),
//!   while decoded lengths agree with yEnc `=yend size=` / `=ypart` ranges;
//! * fetching the segments from a live in-process fixture server and
//!   yEnc-decoding them must reconstruct one complete canonical synthetic
//!   WAV (a generated sine tone, byte-for-byte);
//! * positive/negative controls prove the validator itself catches a
//!   missing/renamed ID and accepts a known-good canonical NZB.
//!
//! * the production NZB parser accepts the generated document and the
//!   production NNTP client + yEnc decoder reproduce the canonical WAV, so
//!   a generated ingest itself would reject fails here.
//!
//! Offline and deterministic: loopback fixture server only, synthetic
//! `@nntune.test` data only.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use velmora::nntp::{NntpClient, NntpConfig};
use velmora::transports::connect_native;
use velmora_test_nntp::{default_corpus, generate_wav_bytes, Article, TestNntpServer};

// ---------------------------------------------------------------------------
// Minimal NZB parsing (shared by the controls and the corpus tests)
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

/// Build an in-memory NZB for the given corpus message-IDs, in order. The
/// only NZB source under test: no file reads, no checked-in fixtures.
fn generated_nzb(ids: &[&str]) -> String {
    let corpus = corpus_by_id();
    velmora_test_nntp::nzb_for(&corpus_articles(&corpus, ids), "alt.binaries.nntune.test")
}

/// Build an in-memory TRUE multipart NZB: one `<file>` element with the
/// given corpus message-IDs as sequentially numbered segments. The shape
/// the production parser must accept for multi-part posts (one file per
/// segment never exercises it).
fn generated_multipart_nzb(ids: &[&str]) -> String {
    let corpus = corpus_by_id();
    velmora_test_nntp::nzb_for_multipart(&corpus_articles(&corpus, ids), "alt.binaries.nntune.test")
}

fn corpus_articles<'a>(corpus: &'a HashMap<String, Article>, ids: &[&str]) -> Vec<&'a Article> {
    ids.iter()
        .map(|id| {
            corpus
                .get(*id)
                .unwrap_or_else(|| panic!("unknown corpus id {id}"))
        })
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

    for (file, seg) in parsed
        .files
        .iter()
        .flat_map(|file| file.segments.iter().map(move |seg| (file, seg)))
    {
        match corpus.get(&seg.id) {
            None => errors.push(format!(
                "segment {} references {} which the default synthetic corpus does not serve",
                seg.number, seg.id
            )),
            Some(article) => {
                if seg.bytes != article.raw.len() as u64 {
                    errors.push(format!(
                        "segment {} ({}) declares bytes={} but the encoded corpus article is {} bytes",
                        seg.number,
                        seg.id,
                        seg.bytes,
                        article.raw.len()
                    ));
                }
                if !file.groups.iter().any(|g| g == &article.group) {
                    errors.push(format!(
                        "segment {} ({}) is served in group {} which its NZB file does not list (groups: {:?})",
                        seg.number, seg.id, article.group, file.groups
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

// ---------------------------------------------------------------------------
// Controls: the validator accepts canonical in-memory NZBs and rejects drift
// ---------------------------------------------------------------------------

#[test]
fn validator_accepts_canonical_generated_corpus_nzbs() {
    // Positive control: in-memory NZBs built from the corpus are
    // corpus-consistent, so a failure below is real drift, not a broken
    // validator.
    for ids in [
        &["<single-yenc-001@nntune.test>"][..],
        &[
            "<multi-660-part1-of-3@nntune.test>",
            "<multi-660-part2-of-3@nntune.test>",
            "<multi-660-part3-of-3@nntune.test>",
        ][..],
        &[
            "<obf-550-part1-of-3@nntune.test>",
            "<obf-550-part2-of-3@nntune.test>",
            "<obf-550-part3-of-3@nntune.test>",
        ][..],
        &["<enc-rar-001@nntune.test>", "<enc-7z-001@nntune.test>"][..],
    ] {
        let errors = validate_nzb_against_corpus(&generated_nzb(ids));
        assert!(errors.is_empty(), "{ids:?}: {errors:?}");
    }
}

#[test]
fn validator_accepts_canonical_two_file_nzb() {
    let text = generated_nzb(&["<enc-rar-001@nntune.test>", "<enc-7z-001@nntune.test>"]);
    assert_eq!(parse_nzb(&text).files.len(), 2);
    let errors = validate_nzb_against_corpus(&text);
    assert!(errors.is_empty(), "canonical two-file NZB: {errors:?}");
}

#[test]
fn validator_rejects_wrong_or_missing_first_file_group() {
    let text = generated_nzb(&["<enc-rar-001@nntune.test>", "<enc-7z-001@nntune.test>"]);
    for replacement in ["<group>alt.binaries.nonexistent</group>", ""] {
        // Leave the second file's valid group intact: its group must not
        // satisfy the first file's article membership check.
        let drifted = text.replacen("<group>alt.binaries.nntune.test</group>", replacement, 1);
        let parsed = parse_nzb(&drifted);
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files[1].groups, ["alt.binaries.nntune.test"]);
        let errors = validate_nzb_against_corpus(&drifted);
        assert!(
            errors.iter().any(|e| {
                e.contains("<enc-rar-001@nntune.test>") && e.contains("is served in group")
            }),
            "first-file group drift not reported: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .all(|e| !e.contains("<enc-7z-001@nntune.test>")),
            "valid second file incorrectly rejected: {errors:?}"
        );
    }
}

#[test]
fn generated_nzb_sizes_distinguish_encoded_articles_from_decoded_payloads() {
    let corpus = default_corpus();
    let single = &corpus[0];
    for text in [
        velmora_test_nntp::nzb_for(&[single], &single.group),
        velmora_test_nntp::nzb_for_multipart(&[single], &single.group),
    ] {
        assert_ne!(single.raw.len(), single.payload.len());
        let document = velmora::nzb::parse(text.as_bytes()).unwrap();
        let segment = &document.files[0].segments[0];
        assert_eq!(segment.encoded_bytes, single.raw.len() as i64);
        assert_ne!(segment.encoded_bytes, single.payload.len() as i64);
        assert!(validate_nzb_against_corpus(&text).is_empty());

        let decoded_size = text.replace(
            &format!("bytes=\"{}\"", single.raw.len()),
            &format!("bytes=\"{}\"", single.payload.len()),
        );
        assert!(
            validate_nzb_against_corpus(&decoded_size)
                .iter()
                .any(|error| error.contains("encoded corpus article")),
            "decoded-size substitution must fail corpus validation"
        );
    }
}

#[test]
fn validator_rejects_unknown_and_renamed_ids() {
    // Negative control standing in for fixture drift: plausible
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

#[test]
fn validator_rejects_reordered_segment_numbers() {
    // A hand-built NZB listing the multipart segments as 3, 2, 1: every ID
    // resolves, bytes agree, but the numbers are not contiguous 1..=N in
    // document order. Order-based consumers would silently descramble the
    // payload, so the validator must flag the document, not pass it.
    let text = generated_multipart_nzb(&[
        "<multi-660-part1-of-3@nntune.test>",
        "<multi-660-part2-of-3@nntune.test>",
        "<multi-660-part3-of-3@nntune.test>",
    ]);
    let reordered = text
        .replace(r#"number="1""#, r#"number="X""#)
        .replace(r#"number="3""#, r#"number="1""#)
        .replace(r#"number="X""#, r#"number="3""#);
    let errors = validate_nzb_against_corpus(&reordered);
    assert!(
        errors.iter().any(|e| e.contains("contiguous")),
        "reordered numbers not reported: {errors:?}"
    );
}

// ---------------------------------------------------------------------------
// The generated corpus itself
// ---------------------------------------------------------------------------

#[test]
fn generated_nzb_every_segment_and_group_resolves_in_default_corpus() {
    for ids in [
        &["<single-yenc-001@nntune.test>"][..],
        &[
            "<multi-660-part1-of-3@nntune.test>",
            "<multi-660-part2-of-3@nntune.test>",
            "<multi-660-part3-of-3@nntune.test>",
        ][..],
    ] {
        let errors = validate_nzb_against_corpus(&generated_nzb(ids));
        assert!(
            errors.is_empty(),
            "generated NZB for {ids:?} is inconsistent with the default synthetic corpus:\n- {}",
            errors.join("\n- ")
        );
    }
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

/// Fetch every segment of an in-memory generated NZB via NNTP, decode each
/// article body, and place it by its advertised `=ypart` range (single-part
/// framing has no `=ypart` and lands at offset 0). Returns the reassembled
/// file bytes in `ids` order.
async fn fetch_and_reassemble(ids: &[&str]) -> Vec<u8> {
    fetch_and_reassemble_doc(&generated_nzb(ids)).await
}

/// Document variant: reassemble a caller-built NZB (e.g. a true multipart
/// document from [`generated_multipart_nzb`]) instead of a per-ID build.
async fn fetch_and_reassemble_doc(text: &str) -> Vec<u8> {
    let parsed = parse_nzb(text);
    assert!(
        !parsed.segments().is_empty(),
        "generated NZB declares no segments"
    );

    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    for group in &parsed.groups() {
        let g = c.cmd(&format!("GROUP {group}")).await;
        assert!(g.starts_with("211"), "GROUP {group}: {g:?}");
    }

    // The generated documents under test each carry one yEnc file per NZB
    // `<file>`: shared name/size/total across its segments, checked in
    // document order below after sorting by number.
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
            "generated NZB segment {} ({}) is not served by the synthetic corpus: {first:?}",
            seg.number,
            seg.id
        );
        assert_eq!(block.len() as u64, seg.bytes, "encoded article size");
        let body = article_body(&block);

        // One NZB file = one yEnc file: shared name/size across segments.
        let name = framing_param(body, "=ybegin", "name")
            .unwrap_or_else(|| panic!("segment {} has no =ybegin name", seg.number));
        match &file_name {
            None => file_name = Some(name),
            Some(prev) => assert_eq!(&name, prev, "generated NZB mixes yEnc files"),
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

        let decoded = velmora_test_nntp::yenc::decode(body);
        let declared_decoded: usize = framing_param(body, "=yend", "size")
            .expect("=yend size")
            .parse()
            .expect("numeric =yend size");
        assert_eq!(decoded.len(), declared_decoded, "decoded part size");

        // Placement comes from the advertised =ypart range, whose length
        // must equal the decoded byte count, not the encoded NZB bytes.
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
        "generated NZB does not carry every part of its yEnc file"
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
    reassembled
}

#[tokio::test]
async fn generated_single_part_nzb_reconstructs_canonical_wav_via_nntp() {
    let reassembled = fetch_and_reassemble(&["<single-yenc-001@nntune.test>"]).await;

    // The reconstructed payload is a real canonical synthetic tone, and long
    // enough for short Range seeks over it.
    assert!(reassembled.len() >= 18, "payload too short for Range seeks");
    assert_eq!(&reassembled[0..4], b"RIFF", "payload is not a WAV");
    assert_eq!(&reassembled[8..12], b"WAVE", "payload is not a WAV");
    assert_eq!(
        reassembled,
        generate_wav_bytes(440.0, 120, 8000),
        "reconstructed payload is not the canonical 440 Hz sine WAV"
    );
}

#[tokio::test]
async fn generated_multi_part_nzb_reconstructs_canonical_wav_via_nntp() {
    // True multipart shape: ONE file, THREE numbered segments. One file
    // per segment would pass even if the parser rejected multi-segment
    // files, so the shape itself is asserted first.
    let text = generated_multipart_nzb(&[
        "<multi-660-part1-of-3@nntune.test>",
        "<multi-660-part2-of-3@nntune.test>",
        "<multi-660-part3-of-3@nntune.test>",
    ]);
    let parsed = parse_nzb(&text);
    assert_eq!(parsed.files.len(), 1, "multipart NZB must carry one file");
    let numbers: Vec<u32> = parsed.files[0].segments.iter().map(|s| s.number).collect();
    assert_eq!(
        numbers,
        vec![1, 2, 3],
        "segments must number 1..=3 in order"
    );
    let reassembled = fetch_and_reassemble_doc(&text).await;

    assert_eq!(&reassembled[0..4], b"RIFF", "payload is not a WAV");
    assert_eq!(&reassembled[8..12], b"WAVE", "payload is not a WAV");
    assert_eq!(
        reassembled,
        generate_wav_bytes(660.0, 210, 8000),
        "reconstructed payload is not the canonical 660 Hz sine WAV"
    );
}

// ---------------------------------------------------------------------------
// Production path: the parser, NNTP client and yEnc decoder ingest uses
// ---------------------------------------------------------------------------

fn assert_xml_sensitive_ids_round_trip(render: fn(&[&Article], &str) -> String) {
    let bare_ids = [
        "a&b@nntune.test",
        "a&amp;b@nntune.test",
        "a&#64;b@nntune.test",
        "a&#x40;b@nntune.test",
        "a&apos;b@nntune.test",
        "a\"'b@nntune.test",
    ];
    let mut articles = Vec::new();
    for id in bare_ids {
        assert_eq!(velmora::nzb::normalize_message_id(id).unwrap(), id);
        let mut article = default_corpus().remove(0);
        article.message_id = format!("<{id}>");
        article.subject = "fixture & <tag> \"quoted.wav\"".to_string();
        articles.push(article);
    }
    let refs: Vec<&Article> = articles.iter().collect();
    let text = render(&refs, "alt.binaries.nntune.test");
    let document = velmora::nzb::parse(text.as_bytes())
        .expect("production parser accepts XML-sensitive fixture identities");
    let parsed_ids: Vec<&str> = document
        .files
        .iter()
        .flat_map(|f| f.segments.iter().map(|s| s.message_id.as_str()))
        .collect();
    assert_eq!(
        parsed_ids, bare_ids,
        "XML references must remain literal ID text"
    );
    for file in &document.files {
        assert_eq!(file.subject, articles[0].subject);
        for segment in &file.segments {
            assert_eq!(segment.encoded_bytes, articles[0].raw.len() as i64);
        }
    }
}

#[test]
fn generated_nzb_xml_sensitive_ids_round_trip_via_production_parser() {
    assert_xml_sensitive_ids_round_trip(velmora_test_nntp::nzb_for);
}

#[test]
fn generated_multipart_nzb_xml_sensitive_ids_round_trip_via_production_parser() {
    assert_xml_sensitive_ids_round_trip(velmora_test_nntp::nzb_for_multipart);
}

#[test]
fn generated_nzb_group_text_is_xml_escaped_in_both_shapes() {
    let corpus = default_corpus();
    let articles = [&corpus[0], &corpus[1]];
    let group = "alt.binaries.a&<b>\"'";
    for text in [
        velmora_test_nntp::nzb_for(&articles, group),
        velmora_test_nntp::nzb_for_multipart(&articles, group),
    ] {
        assert!(text.contains("<group>alt.binaries.a&amp;&lt;b&gt;&quot;'</group>"));
        let parsed = parse_nzb(&text);
        for file in parsed.files {
            assert_eq!(file.groups, [group]);
        }
        velmora::nzb::parse(text.as_bytes()).expect("escaped group text is valid XML");
    }
}

#[tokio::test]
async fn generated_nzb_parses_fetches_and_decodes_via_production_pipeline() {
    // Corpus consistency alone is not ingestability: the hand-rolled scanner
    // above accepts documents the production parser rejects (it refuses every
    // DOCTYPE as XXE hardening). This test runs the production components —
    // `velmora::nzb::parse` (the parser the ingest upload handler calls),
    // `NntpClient` and `yenc::decode_to` — so a generated document the upload
    // would reject with a 400 fails here. The document is the true
    // multipart shape (one file, three numbered segments): a production
    // parser that rejected multi-segment files must fail this test, which
    // a single-part document could never catch.
    let ids = [
        "<multi-660-part1-of-3@nntune.test>",
        "<multi-660-part2-of-3@nntune.test>",
        "<multi-660-part3-of-3@nntune.test>",
    ];
    let text = generated_multipart_nzb(&ids);
    let document = velmora::nzb::parse(text.as_bytes())
        .expect("production NZB parser accepts the generated fixture");
    assert_eq!(document.files.len(), 1, "generated NZB carries one file");
    let file = &document.files[0];
    assert_eq!(
        file.segments.len(),
        3,
        "multipart file must carry three segments"
    );
    assert_eq!(
        file.segments.iter().map(|s| s.number).collect::<Vec<_>>(),
        vec![1usize, 2, 3],
        "production segments must number 1..=3 in order"
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
        .expect("fetch generated segments via production NNTP client");
    client.quit().await;
    assert_eq!(fetched.len(), file.segments.len());

    // NZB bytes count the encoded article. Decode into a buffer sized by
    // the yEnc part range instead; the production decoder also verifies CRC.
    let mut reassembled = Vec::new();
    for segment in &file.segments {
        let article = fetched
            .iter()
            .find(|f| f.message_id == segment.message_id)
            .unwrap_or_else(|| panic!("no fetched article for {}", segment.message_id));
        assert_eq!(article.article.len() as i64, segment.encoded_bytes);
        let body = article_body(&article.article);
        let begin: usize = framing_param(body, "=ypart", "begin")
            .expect("multipart begin")
            .parse()
            .unwrap();
        let end: usize = framing_param(body, "=ypart", "end")
            .expect("multipart end")
            .parse()
            .unwrap();
        let part_len = end + 1 - begin;
        let mut decoded = vec![0u8; part_len];
        let decoded_len =
            velmora::yenc::decode_to(&segment.message_id, &article.article, &mut decoded)
                .unwrap_or_else(|e| {
                    panic!(
                        "production yEnc decoder rejects {}: {e:?}",
                        segment.message_id
                    )
                });
        assert_eq!(
            decoded_len,
            decoded.len(),
            "decoded length disagrees with yEnc part range for {}",
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
