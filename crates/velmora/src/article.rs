//! Article assembly for the re-post pipeline: header builder, per-article
//! obfuscation, newsgroup allow-list selection, and cipher-block payload
//! sizing.
//!
//! Every posted article carries fully opaque wire metadata (design §5): a
//! random 32-character [`Subject`](ObfuscatedArticle::subject), a random
//! yEnc name with no extension, a random [`From`](ObfuscatedArticle::from),
//! a [`Date`](ObfuscatedArticle::date) jittered within ±6 h, one newsgroup
//! drawn CSPRNG-uniform from the operator allow-list, and a random
//! `{rand32}@{rand8}.{rand3}` message-ID inside the
//! [`segment_identity`](crate::segment_identity) contract. All of it is new
//! per article and comes from a [`FillRandom`](crate::rng::FillRandom)
//! source — production uses [`SystemRng`](crate::rng::SystemRng).
//!
//! The newsgroup allow-list is operator configuration (pool/app config rows),
//! never hardcoded names: [`select_newsgroup`] takes the list as input and
//! fails closed on an empty (or malformed) list. Examples and tests use
//! placeholder names only.
//!
//! No account hostnames, usernames, NZB bytes, file names, or segment lists
//! appear here: the caller records the chosen group and minted message-IDs
//! in the DB posted-file record only.

use crate::decrypt::rclone::{CIPHER_BLOCK_SIZE, PLAIN_BLOCK_SIZE};
use crate::error::{Error, Result};
use crate::rng::{fill_alphabet, uniform_below, FillRandom};
use crate::segment_identity::valid_segment_id;

// ---------------------------------------------------------------------------
// Obfuscation alphabet and field sizes (design §5)
// ---------------------------------------------------------------------------

/// Lowercase alphanumeric alphabet for generated identifiers (message-ID
/// parts, yEnc names, From lines): printable ASCII, no whitespace, no
/// specials that need header quoting.
const LOWER_ALNUM: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Mixed-case alphanumeric alphabet for generated subjects.
const SUBJECT_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Length of the random per-article Subject.
pub const OBFUSCATED_SUBJECT_LEN: usize = 32;
/// Length of the random per-article yEnc `name=` (no extension).
pub const OBFUSCATED_YENC_NAME_LEN: usize = 12;
/// Length of the random From local part (`{local}@{8}.{3}`).
pub const OBFUSCATED_FROM_LOCAL_LEN: usize = 16;

/// Message-ID shape `{rand32}@{rand8}.{rand3}` (design §5): 45 bytes, well
/// inside the 250-byte [`segment_identity`](crate::segment_identity) ceiling.
pub const MSGID_LOCAL_LEN: usize = 32;
/// Domain half-widths of the generated message-ID domain.
pub const MSGID_DOMAIN_LEFT_LEN: usize = 8;
/// Domain half-widths of the generated message-ID domain.
pub const MSGID_DOMAIN_RIGHT_LEN: usize = 3;

/// Date jitter half-window in seconds (±6 h, uniform, design §3.1/§5).
pub const DATE_JITTER_SECS: i64 = 6 * 3600;

// ---------------------------------------------------------------------------
// Article payload sizing (design §4)
// ---------------------------------------------------------------------------

/// Cipher blocks per posted article. Payload bytes are the rclone-crypt
/// ciphertext (64 KiB plaintext blocks plus 16-byte tags, header in front of
/// article 0), so every article decrypts on its own and an HTTP range maps
/// to whole articles via the stored plaintext/ciphertext offsets.
pub const ARTICLE_CIPHER_BLOCKS: usize = 11;

/// Encoded article payload size: `k` ciphertext blocks
/// (`11 * 65,552 = 721,072` B). yEnc article `size=` values and segment
/// ranges for a full article equal this; the last article of a file holds
/// the remainder.
pub const ARTICLE_PAYLOAD_BYTES: u64 = ARTICLE_CIPHER_BLOCKS as u64 * CIPHER_BLOCK_SIZE;

/// Plaintext covered by one full article (`11 * 65,536 = 720,896` B).
pub const ARTICLE_PLAINTEXT_BYTES: u64 = ARTICLE_CIPHER_BLOCKS as u64 * PLAIN_BLOCK_SIZE;

// ---------------------------------------------------------------------------
// Newsgroup allow-list selection
// ---------------------------------------------------------------------------

/// Draws one group for a file, CSPRNG-uniform over `allow_list`.
///
/// The list is operator configuration, passed in — never a hardcoded name.
/// An empty list fails closed ([`Error::Malformed`]: refusing to post is
/// safer than posting to a default group), as does any entry that is not a
/// bare group token (printable ASCII, no whitespace, controls, or
/// delimiter-escaping characters).
pub fn select_newsgroup<R: FillRandom>(rng: &mut R, allow_list: &[&str]) -> Result<String> {
    if allow_list.is_empty() {
        return Err(Error::Malformed(
            "newsgroup allow-list is empty: refusing to post".into(),
        ));
    }
    for (i, group) in allow_list.iter().enumerate() {
        if !valid_group_token(group) {
            return Err(Error::Malformed(format!(
                "newsgroup allow-list entry {i} is not a valid group name"
            )));
        }
    }
    let index = uniform_below(rng, allow_list.len() as u64)? as usize;
    Ok(allow_list[index].to_string())
}

/// Bare group token: non-empty printable ASCII (`0x21..=0x7E`) minus
/// `<`/`>`, so no whitespace, controls, or framing delimiters that could
/// break the `Newsgroups` header or the NNTP command line. Newsgroup names
/// carry no other structure this layer needs to enforce.
fn valid_group_token(group: &str) -> bool {
    !group.is_empty()
        && group.len() <= 998
        && group
            .bytes()
            .all(|b| (0x21..=0x7E).contains(&b) && b != b'<' && b != b'>')
}

// ---------------------------------------------------------------------------
// Per-article obfuscation
// ---------------------------------------------------------------------------

/// Fully obfuscated wire metadata for one article. Render with
/// [`ArticleHeaders`] (or [`render_obfuscated_headers`]); the caller pairs
/// the headers with the yEnc body built under [`ObfuscatedArticle::yenc_name`].
#[derive(Debug, Clone)]
pub struct ObfuscatedArticle {
    /// Bare message-ID (`{rand32}@{rand8}.{rand3}`, no brackets — the
    /// header renderer and the NNTP wire layer add `<…>`).
    pub message_id: String,
    /// Bare addr-spec From (`{rand16}@{rand8}.{rand3}`).
    pub from: String,
    /// Random 32-character Subject.
    pub subject: String,
    /// Random yEnc `name=`, no extension.
    pub yenc_name: String,
    /// Jittered posting date, already RFC 5322 formatted.
    pub date: String,
    /// The chosen newsgroup (recorded in the DB posted-file record only).
    pub newsgroup: String,
}

/// Mints fresh obfuscated metadata for one article: uniform draws for every
/// field, the newsgroup drawn uniform over `allow_list`, the date jittered
/// uniform in `[now-6h, now+6h]`. `now_unix_secs` is caller-supplied (Unix
/// time) so the core owns no clock and stays deterministic under test.
///
/// Fails closed on an empty/malformed allow-list, on a clock before the
/// jitter window, or — defense in depth, unreachable by construction — if a
/// minted message-ID ever fell outside the segment-identity contract.
pub fn obfuscate_article<R: FillRandom>(
    rng: &mut R,
    now_unix_secs: i64,
    allow_list: &[&str],
) -> Result<ObfuscatedArticle> {
    let newsgroup = select_newsgroup(rng, allow_list)?;

    let mut local = [0u8; MSGID_LOCAL_LEN];
    let mut domain_left = [0u8; MSGID_DOMAIN_LEFT_LEN];
    let mut domain_right = [0u8; MSGID_DOMAIN_RIGHT_LEN];
    fill_alphabet(rng, &mut local, LOWER_ALNUM)?;
    fill_alphabet(rng, &mut domain_left, LOWER_ALNUM)?;
    fill_alphabet(rng, &mut domain_right, LOWER_ALNUM)?;
    let message_id = format!(
        "{}@{}.{}",
        std::str::from_utf8(&local[..])
            .map_err(|_| Error::Malformed("generated message-id is not valid text".into()))?,
        std::str::from_utf8(&domain_left[..])
            .map_err(|_| Error::Malformed("generated message-id is not valid text".into()))?,
        std::str::from_utf8(&domain_right[..])
            .map_err(|_| Error::Malformed("generated message-id is not valid text".into()))?,
    );
    if !valid_segment_id(&message_id) {
        return Err(Error::Malformed(
            "generated message-id falls outside the segment-identity contract".into(),
        ));
    }

    let mut from_local = [0u8; OBFUSCATED_FROM_LOCAL_LEN];
    let mut from_domain_left = [0u8; MSGID_DOMAIN_LEFT_LEN];
    let mut from_domain_right = [0u8; MSGID_DOMAIN_RIGHT_LEN];
    fill_alphabet(rng, &mut from_local, LOWER_ALNUM)?;
    fill_alphabet(rng, &mut from_domain_left, LOWER_ALNUM)?;
    fill_alphabet(rng, &mut from_domain_right, LOWER_ALNUM)?;
    // SAFETY: every byte comes from the ASCII alphabet above.
    let from = format!(
        "{}@{}.{}",
        std::str::from_utf8(&from_local[..]).expect("alphabet is ASCII"),
        std::str::from_utf8(&from_domain_left[..]).expect("alphabet is ASCII"),
        std::str::from_utf8(&from_domain_right[..]).expect("alphabet is ASCII"),
    );

    let mut subject = [0u8; OBFUSCATED_SUBJECT_LEN];
    fill_alphabet(rng, &mut subject, SUBJECT_ALPHABET)?;
    // SAFETY: every byte comes from the ASCII alphabet above.
    let subject = std::str::from_utf8(&subject[..])
        .expect("alphabet is ASCII")
        .to_string();

    let mut yenc_name = [0u8; OBFUSCATED_YENC_NAME_LEN];
    fill_alphabet(rng, &mut yenc_name, LOWER_ALNUM)?;
    // SAFETY: every byte comes from the ASCII alphabet above.
    let yenc_name = std::str::from_utf8(&yenc_name[..])
        .expect("alphabet is ASCII")
        .to_string();

    let jitter_span = DATE_JITTER_SECS * 2 + 1;
    let offset = uniform_below(rng, jitter_span as u64)? as i64 - DATE_JITTER_SECS;
    let date = format_nntp_date(
        now_unix_secs
            .checked_add(offset)
            .ok_or_else(|| Error::Malformed("posting clock plus date jitter overflows".into()))?,
    )?;

    Ok(ObfuscatedArticle {
        message_id,
        from,
        subject,
        yenc_name,
        date,
        newsgroup,
    })
}

// ---------------------------------------------------------------------------
// Header builder with folding
// ---------------------------------------------------------------------------

/// Outgoing article headers: From, Newsgroups, Subject, Date, Message-ID.
/// Values are caller- or obfuscation-supplied; construction validates that
/// no value can break NNTP framing (no CR, LF, or control characters) and
/// that the message-ID is a bare segment-identity id (brackets are added at
/// render). [`render`](ArticleHeaders::render) folds over-long lines per RFC
/// 5322 §2.2.3 and refuses any line that cannot fit 998 bytes.
#[derive(Debug, Clone)]
pub struct ArticleHeaders {
    from: String,
    newsgroups: Vec<String>,
    subject: String,
    date: String,
    message_id: String,
}

impl ArticleHeaders {
    /// Builds the five posting headers. `date` is an already-formatted RFC
    /// 5322 date (see [`format_nntp_date`]); `message_id` is bare. Every
    /// value is checked for framing-breaking characters before it is stored.
    pub fn new(
        from: &str,
        newsgroups: &[&str],
        subject: &str,
        date: &str,
        message_id: &str,
    ) -> Result<Self> {
        check_header_value("From", from)?;
        if !from.contains('@') {
            return Err(Error::Malformed("From header is not an addr-spec".into()));
        }
        if newsgroups.is_empty() {
            return Err(Error::Malformed(
                "Newsgroups header needs at least one group".into(),
            ));
        }
        let mut groups = Vec::with_capacity(newsgroups.len());
        for group in newsgroups {
            check_header_value("Newsgroups", group)?;
            if !valid_group_token(group) {
                return Err(Error::Malformed(
                    "Newsgroups header holds an invalid group name".into(),
                ));
            }
            groups.push(group.to_string());
        }
        check_header_value("Subject", subject)?;
        check_header_value("Date", date)?;
        if !valid_segment_id(message_id) {
            return Err(Error::Malformed(
                "Message-ID is not a valid segment identity".into(),
            ));
        }
        Ok(ArticleHeaders {
            from: from.to_string(),
            newsgroups: groups,
            subject: subject.to_string(),
            date: date.to_string(),
            message_id: message_id.to_string(),
        })
    }

    /// Builds directly from obfuscated metadata.
    pub fn obfuscated(ob: &ObfuscatedArticle) -> Result<Self> {
        ArticleHeaders::new(
            &ob.from,
            &[ob.newsgroup.as_str()],
            &ob.subject,
            &ob.date,
            &ob.message_id,
        )
    }

    /// Renders the header block (no trailing blank line): one CRLF-joined,
    /// correctly folded `Name: value` line per header, in posting order
    /// (From, Newsgroups, Subject, Date, Message-ID).
    pub fn render(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&fold_header("From", &self.from)?);
        out.extend_from_slice(&fold_header("Newsgroups", &self.newsgroups.join(", "))?);
        out.extend_from_slice(&fold_header("Subject", &self.subject)?);
        out.extend_from_slice(&fold_header("Date", &self.date)?);
        out.extend_from_slice(&fold_header(
            "Message-ID",
            &format!("<{}>", self.message_id),
        )?);
        // Every line ends with CRLF; `assemble_article` appends the blank line.
        Ok(out)
    }
}

/// Renders obfuscated metadata straight to a header block.
pub fn render_obfuscated_headers(ob: &ObfuscatedArticle) -> Result<Vec<u8>> {
    ArticleHeaders::obfuscated(ob)?.render()
}

/// Assembles a complete POST body: the header block, the header/body blank
/// line, then the (yEnc) body bytes. Fails closed when the body framing is
/// not clean CRLF lines: a bare CR or LF would corrupt NNTP dot-stuffing.
///
/// The returned bytes are ready for `NntpClient::post_article`, which
/// dot-stuffs and terminates them.
pub fn assemble_article(headers: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    check_body_framing(body)?;
    let mut out = Vec::with_capacity(headers.len() + 2 + body.len());
    out.extend_from_slice(headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(out)
}

/// Fails closed on framing-breaking header values: CR, LF, or any control
/// character (which includes DEL via `is_control`). Printable values pass;
/// the 998-byte ceiling is enforced at render.
fn check_header_value(name: &str, value: &str) -> Result<()> {
    if value
        .chars()
        .any(|c| c == '\r' || c == '\n' || c.is_control())
    {
        return Err(Error::Malformed(format!(
            "{name} header value carries a framing-breaking character"
        )));
    }
    Ok(())
}

/// Fails closed on bodies that would corrupt dot-stuffing: every CR must be
/// part of a CRLF pair and every LF must follow a CR. Callers build bodies
/// with CRLF line endings (headers via [`ArticleHeaders::render`], yEnc via
/// `yenc::encode_segment`).
fn check_body_framing(body: &[u8]) -> Result<()> {
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'\r' => {
                if body.get(i + 1) != Some(&b'\n') {
                    return Err(Error::Malformed(
                        "article body holds a bare CR outside CRLF".into(),
                    ));
                }
                i += 2;
            }
            b'\n' => {
                return Err(Error::Malformed(
                    "article body holds a bare LF outside CRLF".into(),
                ));
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// Folds one `Name: value` line per RFC 5322 §2.2.3: lines SHOULD fit 78
/// bytes (excluding CRLF) and MUST fit 998. Folding splits at spaces with
/// continuation lines starting with one space. A single token with no
/// spaces (a long group name, the bracketed message-ID) cannot fold and is
/// emitted whole; anything that still exceeds 998 bytes fails closed.
///
/// A fold consumes exactly one separator space (the continuation's leading
/// space replaces it on unfolding), so the extra spaces of a run stay
/// literal: unfolding restores the value byte-for-byte, including repeated,
/// leading and trailing spaces.
///
/// The returned bytes end with CRLF.
fn fold_header(name: &str, value: &str) -> Result<Vec<u8>> {
    if name.is_empty() || name.bytes().any(|b| b <= b' ' || b == b':' || b >= 0x7F) {
        return Err(Error::Malformed(
            "header name is not a valid field name".into(),
        ));
    }
    let first_prefix = format!("{name}: ");
    let mut lines: Vec<String> = Vec::new();
    if first_prefix.len() + value.len() <= 78 {
        lines.push(format!("{first_prefix}{value}"));
    } else {
        // Greedy word packing; words are split on spaces only, so commas
        // stay glued to their group token and folding lands after ", ".
        let words: Vec<&str> = value.split(' ').collect();
        let mut current = first_prefix.clone();
        // Whether the space run currently being folded already broke onto
        // a continuation line: unfolding removes only the CRLF, so that
        // leading space already IS one literal space. The run's final
        // (trailing) space must not add another, or the round trip gains
        // one; reset by every non-space word.
        let mut run_folded = false;
        for (i, &word) in words.iter().enumerate() {
            if word.is_empty() {
                // Extra space from a run of consecutive spaces: keep it
                // literal on this line. Folding here would drop it (the
                // continuation's leading space already accounts for one
                // separator), so break first when the line is full and
                // carry the space onto the new line — except the run's
                // final space after a fold, which the leading space
                // already represents.
                if current.len() >= 78 {
                    lines.push(current);
                    current = String::from(" ");
                    run_folded = true;
                }
                if !(i + 1 == words.len() && run_folded) {
                    current.push(' ');
                }
                continue;
            }
            run_folded = false;
            if current.len() + word.len() < 78 {
                if !current.ends_with(' ') && !current.ends_with(": ") {
                    current.push(' ');
                }
                current.push_str(word);
            } else if current == first_prefix || current.trim() == first_prefix.trim() {
                // First word already overlong (or the value has no spaces):
                // emit whole — the 998-byte ceiling below is the backstop.
                current.push_str(word);
            } else {
                lines.push(current);
                current = format!(" {word}");
            }
        }
        lines.push(current);
    }
    let mut out = Vec::new();
    for line in lines {
        if line.len() > 998 {
            return Err(Error::Malformed(format!(
                "{name} header line exceeds the 998-byte limit"
            )));
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// RFC 5322 dates (always GMT)
// ---------------------------------------------------------------------------

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Formats Unix time as an RFC 5322 date in GMT
/// (`Tue, 03 Nov 2026 12:00:00 +0000`). The weekday is derived from the date
/// itself, so jittered dates stay self-consistent. Rejects pre-epoch and
/// past-9999 inputs (fail closed; posting clocks never legitimately land
/// there).
pub fn format_nntp_date(unix_secs: i64) -> Result<String> {
    // 9999-12-31 23:59:59 UTC; past that the 4-digit year rendering breaks.
    const MAX_UNIX: i64 = 253_402_300_799;
    if !(0..=MAX_UNIX).contains(&unix_secs) {
        return Err(Error::Malformed(
            "posting clock is outside the formattable date range".into(),
        ));
    }
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    // 1970-01-01 was a Thursday (index 3 with Monday 0).
    let weekday = WEEKDAYS[(days + 3).rem_euclid(7) as usize];
    let (year, month, day) = civil_from_days(days);
    Ok(format!(
        "{weekday}, {day:02} {} {year:04} {:02}:{:02}:{:02} +0000",
        MONTHS[(month - 1) as usize],
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    ))
}

/// Days since the Unix epoch to (year, month, day): Howard Hinnant's
/// `civil_from_days`, integer arithmetic only (no date dependency).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_constants_match_design_section_4() {
        assert_eq!(ARTICLE_CIPHER_BLOCKS, 11);
        assert_eq!(CIPHER_BLOCK_SIZE, 65_552);
        assert_eq!(PLAIN_BLOCK_SIZE, 65_536);
        assert_eq!(ARTICLE_PAYLOAD_BYTES, 721_072);
        assert_eq!(ARTICLE_PLAINTEXT_BYTES, 720_896);
    }

    #[test]
    fn dates_format_gmt_with_correct_weekday() {
        // 1970-01-01 00:00:00 UTC was a Thursday.
        assert_eq!(
            format_nntp_date(0).unwrap(),
            "Thu, 01 Jan 1970 00:00:00 +0000"
        );
        // 2026-11-03 12:00:00 UTC is a Tuesday.
        assert_eq!(
            format_nntp_date(1_793_707_200).unwrap(),
            "Tue, 03 Nov 2026 12:00:00 +0000"
        );
        // Leap day renders (2024-02-29 00:00:00 UTC was a Thursday).
        assert_eq!(
            format_nntp_date(1_709_164_800).unwrap(),
            "Thu, 29 Feb 2024 00:00:00 +0000"
        );
        assert!(format_nntp_date(-1).is_err());
    }

    #[test]
    fn folding_keeps_short_lines_and_wraps_long_newsgroups() {
        let single = fold_header("Subject", "short value").unwrap();
        assert_eq!(single, b"Subject: short value\r\n");
        // Three long groups (116 chars with the prefix) force a fold: two
        // short groups would fit 78 and never wrap.
        let long_groups = [
            "example.first.posting.group.name",
            "example.second.posting.group.name",
            "example.third.posting.group.name",
        ];
        let folded = fold_header("Newsgroups", &long_groups.join(", ")).unwrap();
        for line in folded.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let content = line.strip_suffix(b"\r").unwrap_or(line);
            assert!(content.len() <= 78, "overlong: {content:?}");
        }
        // Continuation lines start with whitespace.
        let text = String::from_utf8(folded).unwrap();
        assert!(text.starts_with("Newsgroups: "));
        assert!(text.contains("\r\n "));
    }
}
