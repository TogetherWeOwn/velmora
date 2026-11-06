//! Posting obfuscation, header building, and article-scale yEnc round trips.
//!
//! Covers the re-post pipeline contract: cipher-block payload sizing,
//! per-article obfuscation shapes (lengths, charsets, segment-identity
//! message-IDs, ±6h date jitter, allow-list group picks), header render and
//! parse-back (order, folding, brackets), fail-closed framing validation,
//! single-part encode→decode at the full article payload size, a two-part
//! multipart round trip, and a loopback POST against an inline fake server
//! (post → STAT → fetch → decode, re-post duplicate, 440 toggle).
//! All IDs, subjects, groups, and dates are synthetic placeholders. No real
//! provider is contacted.

use std::collections::HashSet;

use velmora::article::{
    assemble_article, obfuscate_article, render_obfuscated_headers, select_newsgroup,
    ArticleHeaders, ARTICLE_CIPHER_BLOCKS, ARTICLE_PAYLOAD_BYTES, ARTICLE_PLAINTEXT_BYTES,
    DATE_JITTER_SECS, MSGID_DOMAIN_LEFT_LEN, MSGID_DOMAIN_RIGHT_LEN, MSGID_LOCAL_LEN,
    OBFUSCATED_FROM_LOCAL_LEN, OBFUSCATED_SUBJECT_LEN, OBFUSCATED_YENC_NAME_LEN,
};
use velmora::decrypt::rclone::{CIPHER_BLOCK_SIZE, PLAIN_BLOCK_SIZE};
use velmora::error::Error;
use velmora::rng::{FillRandom, SystemRng};
use velmora::segment_identity::valid_segment_id;
use velmora::yenc::{decode_to, encode_segment, SegmentParams};
use velmora::Result;

/// Deterministic xorshift64* byte source (test-only stand-in for `SystemRng`).
struct TestRng(u64);

impl TestRng {
    fn new(seed: u64) -> Self {
        TestRng(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }
}

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        let mut i = 0;
        while i < dest.len() {
            // xorshift64*: nonzero state, full-period for any nonzero seed.
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
            for b in v.to_le_bytes() {
                if i == dest.len() {
                    break;
                }
                dest[i] = b;
                i += 1;
            }
        }
        Ok(())
    }
}

const ALLOW: &[&str] = &[
    "example.test.alpha",
    "example.test.beta",
    "example.test.gamma",
];
const NOW: i64 = 1793707200; // Tue, 03 Nov 2026 12:00:00 UTC.

// ---------------------------------------------------------------------------
// Payload sizing
// ---------------------------------------------------------------------------

#[test]
fn payload_consts_match_rclone_block_layout() {
    assert_eq!(ARTICLE_CIPHER_BLOCKS, 11);
    assert_eq!(ARTICLE_PAYLOAD_BYTES, 11 * CIPHER_BLOCK_SIZE);
    assert_eq!(ARTICLE_PAYLOAD_BYTES, 721_072);
    assert_eq!(ARTICLE_PLAINTEXT_BYTES, 11 * PLAIN_BLOCK_SIZE);
    assert_eq!(ARTICLE_PLAINTEXT_BYTES, 720_896);
}

// ---------------------------------------------------------------------------
// Obfuscation shapes
// ---------------------------------------------------------------------------

fn is_lower_alnum(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn is_subject_charset(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[test]
fn obfuscated_fields_have_shapes_and_valid_id() {
    let mut rng = TestRng::new(1);
    let ob = obfuscate_article(&mut rng, NOW, ALLOW).expect("obfuscate");
    assert_eq!(ob.subject.len(), OBFUSCATED_SUBJECT_LEN);
    assert!(is_subject_charset(&ob.subject), "{}", ob.subject);
    assert_eq!(ob.yenc_name.len(), OBFUSCATED_YENC_NAME_LEN);
    assert!(is_lower_alnum(&ob.yenc_name), "{}", ob.yenc_name);
    assert!(
        !ob.yenc_name.contains('.'),
        "no extension: {}",
        ob.yenc_name
    );

    let (from_local, from_domain) = ob.from.split_once('@').expect("From has @");
    assert_eq!(from_local.len(), OBFUSCATED_FROM_LOCAL_LEN);
    assert!(is_lower_alnum(from_local));
    let (dl, dr) = from_domain.split_once('.').expect("From domain has dot");
    assert_eq!(dl.len(), MSGID_DOMAIN_LEFT_LEN);
    assert_eq!(dr.len(), MSGID_DOMAIN_RIGHT_LEN);

    // {rand32}@{rand8}.{rand3}: 32 + 1 + 8 + 1 + 3 = 45 bytes.
    assert_eq!(
        ob.message_id.len(),
        MSGID_LOCAL_LEN + 1 + MSGID_DOMAIN_LEFT_LEN + 1 + MSGID_DOMAIN_RIGHT_LEN
    );
    let (local, domain) = ob.message_id.split_once('@').expect("ID has @");
    assert_eq!(local.len(), MSGID_LOCAL_LEN);
    assert!(is_lower_alnum(local));
    let (domain_left, domain_right) = domain.split_once('.').expect("ID domain has dot");
    assert_eq!(domain_left.len(), MSGID_DOMAIN_LEFT_LEN);
    assert_eq!(domain_right.len(), MSGID_DOMAIN_RIGHT_LEN);
    assert!(is_lower_alnum(domain_left));
    assert!(is_lower_alnum(domain_right));
    assert!(valid_segment_id(&ob.message_id), "{}", ob.message_id);
    assert!(ALLOW.contains(&ob.newsgroup.as_str()), "{}", ob.newsgroup);

    // Jittered date parses back inside ±6h of `now`.
    let jittered = parse_nntp_date(&ob.date);
    assert!(
        (jittered - NOW).abs() <= DATE_JITTER_SECS,
        "date {} out of jitter window",
        ob.date
    );
}

#[test]
fn obfuscation_draws_are_unique() {
    let mut rng = TestRng::new(42);
    let a = obfuscate_article(&mut rng, NOW, ALLOW).expect("first");
    let b = obfuscate_article(&mut rng, NOW, ALLOW).expect("second");
    assert_ne!(a.message_id, b.message_id);
    assert_ne!(a.from, b.from);
    assert_ne!(a.subject, b.subject);
    assert_ne!(a.yenc_name, b.yenc_name);

    // The production CSPRNG path mints distinct metadata too.
    let mut sys = SystemRng;
    let x = obfuscate_article(&mut sys, NOW, ALLOW).expect("system rng");
    let y = obfuscate_article(&mut sys, NOW, ALLOW).expect("system rng");
    assert_ne!(x.message_id, y.message_id);
    assert_ne!(x.subject, y.subject);
    assert!(valid_segment_id(&x.message_id));
    assert!(valid_segment_id(&y.message_id));
}

#[test]
fn jitter_covers_the_window() {
    // 400 deterministic draws: every date inside ±6h, and both extremes of
    // the window observed (span > 11h proves the jitter is not pinned).
    let mut rng = TestRng::new(7);
    let mut min = i64::MAX;
    let mut max = i64::MIN;
    for _ in 0..400 {
        let ob = obfuscate_article(&mut rng, NOW, ALLOW).expect("obfuscate");
        let t = parse_nntp_date(&ob.date);
        assert!(
            (t - NOW).abs() <= DATE_JITTER_SECS,
            "date {} outside ±6h",
            ob.date
        );
        min = min.min(t);
        max = max.max(t);
    }
    assert!(
        max - min > 11 * 3600,
        "jitter span too narrow: {min}..{max}"
    );
}

#[test]
fn clock_before_jitter_window_fails_closed() {
    let mut rng = TestRng::new(1);
    let err = obfuscate_article(&mut rng, i64::MIN, ALLOW).expect_err("underflow must fail");
    assert!(matches!(err, Error::Malformed(_)), "got {err}");
}

// ---------------------------------------------------------------------------
// Allow-list selection
// ---------------------------------------------------------------------------

#[test]
fn allow_list_empty_fails_closed() {
    let mut rng = TestRng::new(1);
    let err = select_newsgroup(&mut rng, &[]).expect_err("empty list must fail");
    assert!(matches!(err, Error::Malformed(_)), "got {err}");
}

#[test]
fn allow_list_invalid_entries_fail_closed() {
    let long = "a".repeat(999);
    for list in [
        vec!["has space"],
        vec!["has\ttab"],
        vec!["<angle>"],
        vec![""],
        vec!["ok.group", "bad group"],
        vec![long.as_str()],
    ] {
        let mut rng = TestRng::new(1);
        let err = select_newsgroup(&mut rng, &list).expect_err("bad entry must fail");
        assert!(matches!(err, Error::Malformed(_)), "got {err} for {list:?}");
    }
}

#[test]
fn single_group_allow_list_always_picks_it() {
    let mut rng = TestRng::new(3);
    for _ in 0..10 {
        assert_eq!(
            select_newsgroup(&mut rng, &["example.test.only"]).unwrap(),
            "example.test.only"
        );
    }
}

#[test]
fn group_picks_cover_the_list() {
    // Deterministic draws over three groups must visit every group: the
    // pick is uniform over the list, not stuck on one entry.
    let mut rng = TestRng::new(11);
    let mut seen = HashSet::new();
    for _ in 0..300 {
        seen.insert(select_newsgroup(&mut rng, ALLOW).unwrap());
    }
    assert_eq!(
        seen.len(),
        ALLOW.len(),
        "picks never left a group: {seen:?}"
    );
}

// ---------------------------------------------------------------------------
// Header render + parse-back
// ---------------------------------------------------------------------------

/// Splits a rendered header block into (name, unfolded value) pairs.
fn parse_headers(block: &[u8]) -> Vec<(String, String)> {
    let text = std::str::from_utf8(block).expect("headers are ASCII");
    let mut out = Vec::new();
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue; // trailing CRLF leaves a final empty split
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Unfolding removes the CRLF only: the continuation's leading
            // space is the word separator the fold split at, so it stays.
            let (_, last) = out.last_mut().expect("continuation has a header");
            *last = format!("{last}{line}");
        } else {
            let (name, value) = line.split_once(": ").expect("Name: value shape");
            out.push((name.to_string(), value.to_string()));
        }
    }
    out
}

#[test]
fn headers_render_in_order_and_parse_back() {
    let headers = ArticleHeaders::new(
        "poster@example.invalid",
        &["example.test.alpha", "example.test.beta"],
        "synthetic subject 001",
        "Tue, 03 Nov 2026 12:00:00 +0000",
        "post-id-001@example.invalid",
    )
    .expect("valid headers");
    let block = headers.render().expect("render");
    let parsed = parse_headers(&block);
    let names: Vec<&str> = parsed.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["From", "Newsgroups", "Subject", "Date", "Message-ID"]
    );
    let values: Vec<&str> = parsed.iter().map(|(_, v)| v.as_str()).collect();
    assert_eq!(
        values,
        [
            "poster@example.invalid",
            "example.test.alpha, example.test.beta",
            "synthetic subject 001",
            "Tue, 03 Nov 2026 12:00:00 +0000",
            "<post-id-001@example.invalid>",
        ]
    );
    // Short values stay on single physical lines.
    for line in std::str::from_utf8(&block).unwrap().split("\r\n") {
        assert!(line.len() <= 78, "unfolded line too long: {line:?}");
    }
}

#[test]
fn long_subject_folds_and_unfolds_losslessly() {
    let subject = ["alpha"; 40].join(" ");
    let headers = ArticleHeaders::new(
        "poster@example.invalid",
        &["example.test.alpha"],
        &subject,
        "Tue, 03 Nov 2026 12:00:00 +0000",
        "post-id-002@example.invalid",
    )
    .expect("valid headers");
    let block = headers.render().expect("render");
    let text = std::str::from_utf8(&block).unwrap();
    let subject_lines: Vec<&str> = text
        .split("\r\n")
        .skip_while(|l| !l.starts_with("Subject:"))
        .take_while(|l| *l != "Date: Tue, 03 Nov 2026 12:00:00 +0000")
        .collect();
    assert!(subject_lines.len() > 1, "must fold: {text:?}");
    for line in &subject_lines {
        assert!(line.len() <= 78, "folded line too long: {line:?}");
    }
    let parsed = parse_headers(&block);
    let (_, unfolded) = parsed
        .iter()
        .find(|(n, _)| n == "Subject")
        .expect("Subject present");
    assert_eq!(unfolded, &subject);
}

#[test]
fn folded_repeated_spaces_unfold_losslessly() {
    // A fold consumes exactly one separator space (the continuation's
    // leading space replaces it); the rest of a space run must stay
    // literal, so unfolding restores every space.
    for subject in [
        format!("{}  b", "a".repeat(70)),
        "  leading spaces stay literal".to_string(),
        "trailing spaces stay literal  ".to_string(),
        format!("{}   {}", "c".repeat(70), "d"),
    ] {
        let headers = ArticleHeaders::new(
            "poster@example.invalid",
            &["example.test.alpha"],
            &subject,
            "Tue, 03 Nov 2026 12:00:00 +0000",
            "post-id-004@example.invalid",
        )
        .expect("valid headers");
        let block = headers.render().expect("render");
        let text = std::str::from_utf8(&block).unwrap();
        let subject_lines: Vec<&str> = text
            .split("\r\n")
            .skip_while(|l| !l.starts_with("Subject:"))
            .take_while(|l| *l != "Date: Tue, 03 Nov 2026 12:00:00 +0000")
            .collect();
        // An overlong first word cannot fold: only that first line may
        // exceed 78 (the 998-byte ceiling is enforced at render).
        for (i, line) in subject_lines.iter().enumerate() {
            assert!(line.len() <= 998, "folded line too long: {line:?}");
            if i > 0 || subject.split(' ').next().is_some_and(|w| w.len() <= 69) {
                assert!(line.len() <= 78, "folded line too long: {line:?}");
            }
        }
        let parsed = parse_headers(&block);
        let (_, unfolded) = parsed
            .iter()
            .find(|(n, _)| n == "Subject")
            .expect("Subject present");
        assert_eq!(unfolded, &subject, "round trip lost whitespace");
    }
}

#[test]
fn folded_trailing_space_at_boundary_unfolds_losslessly() {
    // A trailing space that lands exactly on the 78-byte fold boundary must
    // survive the round trip byte-for-byte: the continuation's leading space
    // IS the trailing space after unfolding (CRLF is removed, the space
    // stays), so folding must not add another one.
    for subject in [
        format!("{} ", "a".repeat(69)),
        format!("{}  ", "a".repeat(69)),
        format!("{} ", "a".repeat(70)),
    ] {
        let headers = ArticleHeaders::new(
            "poster@example.invalid",
            &["example.test.alpha"],
            &subject,
            "Tue, 03 Nov 2026 12:00:00 +0000",
            "post-id-005@example.invalid",
        )
        .expect("valid headers");
        let block = headers.render().expect("render");
        let parsed = parse_headers(&block);
        let (_, unfolded) = parsed
            .iter()
            .find(|(n, _)| n == "Subject")
            .expect("Subject present");
        assert_eq!(unfolded, &subject, "round trip changed trailing spaces");
    }
}

#[test]
fn unfittable_single_token_fails_closed() {
    // No spaces to fold at and over 998 bytes: refuse rather than emit an
    // over-long line.
    let subject = "x".repeat(1000);
    let headers = ArticleHeaders::new(
        "poster@example.invalid",
        &["example.test.alpha"],
        &subject,
        "Tue, 03 Nov 2026 12:00:00 +0000",
        "post-id-003@example.invalid",
    )
    .expect("construction allows it; render refuses");
    let err = headers.render().expect_err("over-long line must fail");
    assert!(matches!(err, Error::Malformed(_)), "got {err}");
}

#[test]
fn header_values_reject_framing_breaks() {
    let good_date = "Tue, 03 Nov 2026 12:00:00 +0000";
    for (from, groups, subject, date, id) in [
        (
            "bad\r@example.invalid",
            &["example.test.alpha"] as &[&str],
            "s",
            good_date,
            "a@example.invalid",
        ),
        (
            "bad\n@example.invalid",
            &["example.test.alpha"],
            "s",
            good_date,
            "a@example.invalid",
        ),
        (
            "poster@example.invalid",
            &["bad group"],
            "s",
            good_date,
            "a@example.invalid",
        ),
        (
            "poster@example.invalid",
            &["example.test.alpha"],
            "bad\rs",
            good_date,
            "a@example.invalid",
        ),
        (
            "poster@example.invalid",
            &["example.test.alpha"],
            "s",
            "bad\ndate",
            "a@example.invalid",
        ),
        (
            "poster@example.invalid",
            &["example.test.alpha"],
            "s",
            good_date,
            "not an id",
        ),
        (
            "poster@example.invalid",
            &["example.test.alpha"],
            "s",
            good_date,
            "<bracketed@example.invalid>",
        ),
        (
            "no-at-sign",
            &["example.test.alpha"],
            "s",
            good_date,
            "a@example.invalid",
        ),
    ] {
        let err = ArticleHeaders::new(from, groups, subject, date, id).expect_err("must refuse");
        assert!(matches!(err, Error::Malformed(_)), "got {err}");
    }
    let err = ArticleHeaders::new(
        "poster@example.invalid",
        &[],
        "s",
        good_date,
        "a@example.invalid",
    )
    .expect_err("empty newsgroups must fail");
    assert!(matches!(err, Error::Malformed(_)), "got {err}");
}

#[test]
fn assemble_article_is_headers_blank_body() {
    let headers = ArticleHeaders::new(
        "poster@example.invalid",
        &["example.test.alpha"],
        "s",
        "Tue, 03 Nov 2026 12:00:00 +0000",
        "post-id-004@example.invalid",
    )
    .expect("valid")
    .render()
    .expect("render");
    let body = b"=ybegin line=128 size=3 name=abcdefgh\r\nabc\r\n=yend size=3 crc32=00000000\r\n";
    let article = assemble_article(&headers, body).expect("assemble");
    assert_eq!(
        article,
        [headers.as_slice(), b"\r\n", body.as_slice()].concat()
    );
    for bad in [b"bare\nlf\r\n".as_slice(), b"bare\rcr\r\n".as_slice()] {
        let err = assemble_article(&headers, bad).expect_err("bad framing must fail");
        assert!(matches!(err, Error::Malformed(_)), "got {err}");
    }
}

// ---------------------------------------------------------------------------
// yEnc round trips at article scale
// ---------------------------------------------------------------------------

/// Deterministic payload covering every byte value (step 7 is coprime to 256).
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u64 * 7 + 13) as u8).collect()
}

/// Deterministic payload whose yEnc encoding stays pure printable ASCII:
/// inputs are uppercase hex digits, so every encoded byte lands in
/// `0x5A..=0x70` (never `=`, never a control, never a high byte). The
/// loopback test uses this because the synthetic server reads the POST
/// block with UTF-8 line I/O, which rejects arbitrary binary yEnc bodies;
/// the full-binary path is covered by the round-trip tests above, which
/// never touch the server.
fn ascii_payload(len: usize) -> Vec<u8> {
    const HEX: &[u8] = b"0123456789ABCDEF";
    (0..len).map(|i| HEX[i % HEX.len()]).collect()
}

#[test]
fn single_part_round_trip_at_full_payload_size() {
    let data = payload(ARTICLE_PAYLOAD_BYTES as usize);
    let mut rng = TestRng::new(99);
    let ob = obfuscate_article(&mut rng, NOW, ALLOW).expect("obfuscate");
    let mut body = Vec::new();
    encode_segment(
        &mut body,
        &SegmentParams::single(ob.yenc_name.clone()),
        &data,
    )
    .expect("encode");
    assert!(
        body.windows(ob.yenc_name.len() + 5)
            .any(|w| w == format!("name={}", ob.yenc_name).as_bytes()),
        "yEnc name label carries the obfuscated name"
    );
    let headers = render_obfuscated_headers(&ob).expect("headers");
    let article = assemble_article(&headers, &body).expect("assemble");

    let mut dst = vec![0u8; data.len()];
    let n = decode_to(&ob.message_id, &article, &mut dst).expect("decode");
    assert_eq!(n, data.len());
    assert_eq!(dst, data);
}

#[test]
fn two_part_multipart_round_trip() {
    let file = payload(3000);
    let (first, second) = file.split_at(1000);
    let mut part1 = Vec::new();
    encode_segment(
        &mut part1,
        &SegmentParams {
            name: "obfuscated-part".into(),
            part: 1,
            total: 2,
            begin: 1,
            end: 1000,
            file_size: 3000,
        },
        first,
    )
    .expect("encode part 1");
    let mut part2 = Vec::new();
    encode_segment(
        &mut part2,
        &SegmentParams {
            name: "obfuscated-part".into(),
            part: 2,
            total: 2,
            begin: 1001,
            end: 3000,
            file_size: 3000,
        },
        second,
    )
    .expect("encode part 2");

    let mut dst1 = vec![0u8; 1000];
    let n1 = decode_to("multipart-test-1@example.invalid", &part1, &mut dst1).expect("decode 1");
    let mut dst2 = vec![0u8; 2000];
    let n2 = decode_to("multipart-test-2@example.invalid", &part2, &mut dst2).expect("decode 2");
    assert_eq!((n1, n2), (1000, 2000));
    assert_eq!([dst1.as_slice(), dst2.as_slice()].concat(), file);
}

// ---------------------------------------------------------------------------
// Loopback POST against the synthetic NNTP server
// ---------------------------------------------------------------------------

/// Minimal RFC 5322 date parser (test-side; the core owns `format_nntp_date`).
/// Returns Unix seconds for a `Tue, 03 Nov 2026 12:00:00 +0000` GMT date.
fn parse_nntp_date(s: &str) -> i64 {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: Vec<&str> = s.split(' ').collect();
    assert_eq!(parts.len(), 6, "date shape: {s}");
    let day: i64 = parts[1].parse().expect("day");
    let month = MONTHS.iter().position(|&m| m == parts[2]).expect("month") as i64 + 1;
    let year: i64 = parts[3].parse().expect("year");
    let time: Vec<i64> = parts[4]
        .split(':')
        .map(|x| x.parse().expect("time"))
        .collect();
    assert_eq!(time.len(), 3);
    assert_eq!(parts[5], "+0000", "GMT only: {s}");
    days_from_civil(year, month, day) * 86400 + time[0] * 3600 + time[1] * 60 + time[2]
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[test]
fn date_parser_agrees_with_known_weekday() {
    // Cross-checks the test-side parser against the anchored module test
    // value (Tue 2026-11-03 12:00 UTC).
    assert_eq!(parse_nntp_date("Tue, 03 Nov 2026 12:00:00 +0000"), NOW);
    assert_eq!(
        parse_nntp_date("Thu, 29 Feb 2024 00:00:00 +0000"),
        1709164800
    );
}

/// Minimal inline `POST`-capable fake NNTP server for the loopback test.
///
/// Kept inside this test file so the suite compiles and runs standalone:
/// the shared `velmora-test-nntp` fake server answers retrieval commands
/// only, so posting tests script their own transport (see `tests/post.rs`)
/// or serve a loopback here. Speaks just enough NNTP — greeting,
/// `MODE READER`, `AUTHINFO USER`, `POST` (`340`/`240`, `435` duplicate,
/// `440` while disabled), `STAT` (`223`/`430`), `ARTICLE` (`220` + the
/// dot-stuffed stored bytes, `430` when missing), `QUIT`. Received articles
/// are dot-unstuffed on store, so fetching returns the posted bytes.
#[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
mod loopback {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    struct State {
        /// `(bracketed message-ID, unstuffed article bytes)` in arrival order.
        posted: Vec<(String, Vec<u8>)>,
        posting_allowed: bool,
    }

    pub struct LoopbackServer {
        addr: SocketAddr,
        state: Arc<Mutex<State>>,
    }

    impl LoopbackServer {
        pub async fn spawn() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let state = Arc::new(Mutex::new(State {
                posted: Vec::new(),
                posting_allowed: true,
            }));
            let serve = Arc::clone(&state);
            tokio::spawn(async move {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                serve_connection(stream, serve).await;
            });
            LoopbackServer { addr, state }
        }

        pub fn addr(&self) -> SocketAddr {
            self.addr
        }

        pub async fn is_stored(&self, message_id: &str) -> bool {
            let want = bracket(message_id);
            self.state
                .lock()
                .await
                .posted
                .iter()
                .any(|(id, _)| *id == want)
        }

        pub async fn posted_ids(&self) -> Vec<String> {
            self.state
                .lock()
                .await
                .posted
                .iter()
                .map(|(id, _)| id.clone())
                .collect()
        }

        pub async fn set_posting_allowed(&self, allowed: bool) {
            self.state.lock().await.posting_allowed = allowed;
        }
    }

    fn bracket(id: &str) -> String {
        let id = id.trim();
        if id.starts_with('<') {
            id.to_string()
        } else {
            format!("<{id}>")
        }
    }

    fn message_id_of(raw: &[u8]) -> Option<String> {
        let head_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(raw.len());
        for line in String::from_utf8_lossy(&raw[..head_end]).split("\r\n") {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            if k.trim().eq_ignore_ascii_case("message-id") {
                return Some(bracket(v.trim()));
            }
        }
        None
    }

    async fn read_line(
        lines: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        buf: &mut Vec<u8>,
    ) -> Option<Vec<u8>> {
        buf.clear();
        match lines.read_until(b'\n', buf).await {
            Ok(0) | Err(_) => None,
            Ok(_) => {
                let mut line = buf.as_slice();
                if line.ends_with(b"\n") {
                    line = &line[..line.len() - 1];
                    if line.ends_with(b"\r") {
                        line = &line[..line.len() - 1];
                    }
                }
                Some(line.to_vec())
            }
        }
    }

    async fn serve_connection(stream: tokio::net::TcpStream, state: Arc<Mutex<State>>) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader);
        let mut buf = Vec::new();
        writer.write_all(b"200 loopback ready\r\n").await.ok();
        loop {
            let Some(raw_line) = read_line(&mut lines, &mut buf).await else {
                break;
            };
            let text = String::from_utf8_lossy(&raw_line);
            let (cmd, arg) = match text.find(' ') {
                Some(i) => (
                    text[..i].to_ascii_uppercase(),
                    text[i + 1..].trim().to_string(),
                ),
                None => (text.to_ascii_uppercase(), String::new()),
            };
            match cmd.as_str() {
                "MODE" => {
                    writer.write_all(b"500 no\r\n").await.ok();
                }
                "AUTHINFO" => {
                    writer.write_all(b"281 ok\r\n").await.ok();
                }
                "POST" => {
                    if !state.lock().await.posting_allowed {
                        writer.write_all(b"440 Posting not allowed\r\n").await.ok();
                        continue;
                    }
                    writer.write_all(b"340 Send article\r\n").await.ok();
                    let mut raw = Vec::new();
                    loop {
                        let Some(line) = read_line(&mut lines, &mut buf).await else {
                            break;
                        };
                        if line == b"." {
                            break;
                        }
                        // Dot-unstuff: strip one dot from any dotted line.
                        let start = usize::from(line.first() == Some(&b'.'));
                        raw.extend_from_slice(&line[start..]);
                        raw.extend_from_slice(b"\r\n");
                    }
                    if raw.is_empty() {
                        writer.write_all(b"441 Posting failed\r\n").await.ok();
                        continue;
                    }
                    let id = message_id_of(&raw)
                        .unwrap_or_else(|| format!("<posted-{}@loopback.test>", raw.len()));
                    let mut st = state.lock().await;
                    if st.posted.iter().any(|(existing, _)| *existing == id) {
                        writer
                            .write_all(format!("435 Duplicate article {id}\r\n").as_bytes())
                            .await
                            .ok();
                    } else {
                        st.posted.push((id.clone(), raw));
                        writer
                            .write_all(format!("240 Article received {id}\r\n").as_bytes())
                            .await
                            .ok();
                    }
                }
                "STAT" => {
                    let st = state.lock().await;
                    let found = st
                        .posted
                        .iter()
                        .position(|(existing, _)| *existing == bracket(&arg))
                        .map(|i| i + 1);
                    match found {
                        Some(n) => {
                            writer
                                .write_all(format!("223 {n} {}\r\n", bracket(&arg)).as_bytes())
                                .await
                                .ok();
                        }
                        None => {
                            writer.write_all(b"430 No such article\r\n").await.ok();
                        }
                    }
                }
                "ARTICLE" => {
                    let found = {
                        let st = state.lock().await;
                        st.posted
                            .iter()
                            .position(|(existing, _)| *existing == bracket(&arg))
                            .map(|i| (i + 1, st.posted[i].clone()))
                    };
                    match found {
                        Some((n, (id, raw))) => {
                            writer
                                .write_all(format!("220 {n} {id}\r\n").as_bytes())
                                .await
                                .ok();
                            // Dot-stuff on serve so the client's
                            // dot-unstuffing restores the stored bytes.
                            let mut segs: Vec<&[u8]> = raw.split(|&b| b == b'\n').collect();
                            if segs.last() == Some(&b"".as_slice()) {
                                segs.pop();
                            }
                            for seg in segs {
                                let seg = seg.strip_suffix(b"\r").unwrap_or(seg);
                                if seg.starts_with(b".") {
                                    writer.write_all(b".").await.ok();
                                }
                                writer.write_all(seg).await.ok();
                                writer.write_all(b"\r\n").await.ok();
                            }
                            writer.write_all(b".\r\n").await.ok();
                        }
                        None => {
                            writer.write_all(b"430 No such article\r\n").await.ok();
                        }
                    }
                }
                "QUIT" => {
                    writer.write_all(b"205 Bye\r\n").await.ok();
                    break;
                }
                _ => {
                    writer.write_all(b"500 Unknown command\r\n").await.ok();
                }
            }
        }
    }
}

#[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
#[tokio::test]
async fn loopback_post_stat_fetch_and_duplicate() {
    use std::time::Duration;

    use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
    use velmora::transports::connect_native;

    use self::loopback::LoopbackServer;

    let server = LoopbackServer::spawn().await;
    let config = NntpConfig {
        host: "127.0.0.1".into(),
        port: server.addr().port(),
        tls: false,
        username: Some("testuser".into()),
        password: Some("testpass".into()),
        timeout: Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    };
    let transport = connect_native(&config).await.expect("connect");
    let mut client = NntpClient::connect(transport, &config)
        .await
        .expect("handshake");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let mut rng = SystemRng;
    let ob = obfuscate_article(&mut rng, now, &["example.test.loopback"]).expect("obfuscate");
    let data = ascii_payload(2048);
    let mut body = Vec::new();
    encode_segment(
        &mut body,
        &SegmentParams::single(ob.yenc_name.clone()),
        &data,
    )
    .expect("encode");
    let article = assemble_article(&render_obfuscated_headers(&ob).expect("headers"), &body)
        .expect("assemble");

    // Post → the spool holds the bracketed ID.
    let outcome = client
        .post_article(&ob.message_id, &article)
        .await
        .expect("post");
    assert_eq!(outcome, PostOutcome::Posted);
    assert!(server.is_stored(&ob.message_id).await);
    assert_eq!(server.posted_ids().await, [format!("<{}>", ob.message_id)]);

    // STAT, then fetch the spooled article and decode it back to the payload.
    let number = client.stat(&ob.message_id).await.expect("stat");
    assert!(number >= 1, "server assigns an article number");
    let mut fetched = Vec::new();
    client
        .article_to(&ob.message_id, &mut fetched)
        .await
        .expect("fetch posted article");
    assert_eq!(fetched, article);
    let mut dst = vec![0u8; data.len()];
    let n = decode_to(&ob.message_id, &fetched, &mut dst).expect("decode");
    assert_eq!(n, data.len());
    assert_eq!(dst, data);

    // Re-posting the same ID is a confirmed duplicate, not an error.
    let outcome = client
        .post_article(&ob.message_id, &article)
        .await
        .expect("re-post");
    assert_eq!(outcome, PostOutcome::Duplicate);

    // Posting disabled mid-session: a fresh ID gets a typed 440 refusal.
    server.set_posting_allowed(false).await;
    let ob2 = obfuscate_article(&mut rng, now, &["example.test.loopback"]).expect("obfuscate");
    let mut body2 = Vec::new();
    encode_segment(
        &mut body2,
        &SegmentParams::single(ob2.yenc_name.clone()),
        &data[..64],
    )
    .expect("encode");
    let article2 = assemble_article(&render_obfuscated_headers(&ob2).expect("headers"), &body2)
        .expect("assemble");
    let err = client
        .post_article(&ob2.message_id, &article2)
        .await
        .expect_err("disabled posting must fail");
    assert!(matches!(err, Error::PostProhibited(_)), "got {err}");

    client.quit().await;
}
