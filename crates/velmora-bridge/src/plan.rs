//! The packed article plan: one value on the extent's row instead of one
//! `articles` row per article.
//!
//! A plan says where the extent's ciphertext is on Usenet: per article a
//! message-id, a newsgroup, the headers it is posted under, its yEnc name
//! and the SHA-256 of its payload. The cuts are not stored: they are the
//! engine's fixed boundaries ([`article_spans`]).
//!
//! Two forms, told apart by the first byte:
//!
//! - **Seeded** ([`TAG_SEEDED`]): a 16-byte random seed, the posting clock
//!   and the newsgroup list the plan was made from, plus the payload
//!   hashes. Every identifier is derived from the seed by the same
//!   obfuscation code that draws them at random ([`obfuscate_article`]),
//!   fed from a keyed stream ([`SeedRng`]).
//! - **Explicit** ([`TAG_EXPLICIT`]): the identifiers themselves, for a
//!   plan that was drawn at random before plans were seeded. The headers
//!   are stored as their three variable fields when the stored bytes are
//!   exactly what those fields render to, and as they are otherwise.
//!
//! Either form carries a digest of the plan it expands to and of the id
//! of the extent it was made for. A value that expands to anything else
//! (a derivation that came out different, a changed byte, the plan of
//! another extent) is an error, never a different plan.
//!
//! Both expand to the same [`ArticleRow`]s the catalogue used to store,
//! byte for byte, so every reader of a plan is unchanged. The sealed
//! recovery record of a plan (`m/art/<extent_id>`) keeps the explicit
//! rows whatever the form in the catalogue.

use sha2::{Digest, Sha256};
use velmora::article::{obfuscate_article, render_obfuscated_headers, ArticleHeaders};
use velmora::rng::FillRandom;

use crate::articles::article_spans;
use crate::post::sha256;
use crate::types::{
    valid_yenc_name, ArticleRow, ArticleState, BridgeError, ByteSpan, ExtentId, Result, UnixMs,
};

/// First byte of a seeded plan.
pub const TAG_SEEDED: u8 = 1;
/// First byte of an explicit plan.
pub const TAG_EXPLICIT: u8 = 2;

/// Bytes of the seed of a seeded plan.
pub const SEED_LEN: usize = 16;
const CHECK_LEN: usize = 16;

/// `extents.posted_at` of a plan that is posted at a time nobody knows
/// (a catalogue replayed for an extent whose pinned copy is gone).
pub const POSTED_AT_UNKNOWN: i64 = 0;

const ERR_PLAN: BridgeError = BridgeError::Invalid("packed article plan");

/// The keyed stream a seeded plan draws from: block `n` of article `idx`
/// is `HMAC-SHA256(seed, "velmora article plan v1" || idx || n)`. One
/// stream per article, so an article's identifiers do not depend on how
/// many bytes the articles before it drew.
struct SeedRng {
    seed: [u8; SEED_LEN],
    idx: u32,
    block: u32,
    buf: [u8; 32],
    used: usize,
}

const STREAM_LABEL: &[u8; 23] = b"velmora article plan v1";

impl SeedRng {
    fn new(seed: &[u8; SEED_LEN], idx: u32) -> Self {
        SeedRng {
            seed: *seed,
            idx,
            block: 0,
            buf: [0; 32],
            used: 32,
        }
    }
}

/// `HMAC-SHA256(seed, STREAM_LABEL || idx || block)` (RFC 2104), as two
/// plain SHA-256 calls: the key is shorter than a hash block and the
/// message is short and of one length, so both hashes are over a small
/// buffer on the stack.
fn stream_block(seed: &[u8; SEED_LEN], idx: u32, block: u32) -> [u8; 32] {
    const BLOCK: usize = 64;
    const LABEL: usize = STREAM_LABEL.len();
    let mut inner = [0x36u8; BLOCK + LABEL + 8];
    let mut outer = [0x5cu8; BLOCK + 32];
    for (at, k) in seed.iter().enumerate() {
        inner[at] ^= k;
        outer[at] ^= k;
    }
    inner[BLOCK..BLOCK + LABEL].copy_from_slice(STREAM_LABEL);
    inner[BLOCK + LABEL..BLOCK + LABEL + 4].copy_from_slice(&idx.to_be_bytes());
    inner[BLOCK + LABEL + 4..].copy_from_slice(&block.to_be_bytes());
    outer[BLOCK..].copy_from_slice(&sha256(&inner));
    sha256(&outer)
}

impl FillRandom for SeedRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for byte in dest {
            if self.used == self.buf.len() {
                self.buf = stream_block(&self.seed, self.idx, self.block);
                self.block = self.block.checked_add(1).ok_or_else(|| {
                    velmora::Error::Malformed("article plan stream is exhausted".into())
                })?;
                self.used = 0;
            }
            *byte = self.buf[self.used];
            self.used += 1;
        }
        Ok(())
    }
}

/// What one call of [`crate::ports::Catalog::pack_plans`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct PackReport {
    /// Extents with article rows that the call looked at.
    pub looked: u32,
    /// Of those, the ones whose plan is packed now, their rows deleted.
    pub packed: u32,
    /// The call reached the last extent with article rows: the next one
    /// starts over. A call that ends with nothing looked at found no
    /// article row at all.
    pub end: bool,
}

/// The plan of an extent as the catalogue holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredPlan {
    /// The articles, in `idx` order. Empty = the extent has no plan.
    pub rows: Vec<ArticleRow>,
    /// The packed form, when the plan is stored packed.
    pub packed: Option<Vec<u8>>,
}

/// What a seeded plan is derived from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanSeed<'a> {
    pub seed: [u8; SEED_LEN],
    /// The posting clock the `Date` headers are spread around, in seconds.
    pub planned_secs: i64,
    /// The newsgroup list each article picks its group from.
    pub groups: Vec<&'a str>,
}

/// The identifiers of every article of a `cipher_size`-byte extent as the
/// seed gives them, with the payload hashes `hashes` (32 bytes each, one
/// after the other).
fn derive(
    seed: &PlanSeed,
    extent: &ExtentId,
    cipher_size: u64,
    hashes: &[u8],
) -> Result<Vec<ArticleRow>> {
    let spans = article_spans(cipher_size);
    let (hashes, rest) = hashes.as_chunks::<32>();
    if spans.is_empty() || spans.len() != hashes.len() || !rest.is_empty() {
        return Err(ERR_PLAN);
    }
    let mut rows = Vec::with_capacity(spans.len());
    for ((idx, span), hash) in (0u32..).zip(&spans).zip(hashes) {
        let mut rng = SeedRng::new(&seed.seed, idx);
        let meta =
            obfuscate_article(&mut rng, seed.planned_secs, &seed.groups).map_err(|_| ERR_PLAN)?;
        let headers = render_obfuscated_headers(&meta).map_err(|_| ERR_PLAN)?;
        rows.push(ArticleRow {
            extent_id: extent.clone(),
            idx,
            message_id: meta.message_id,
            newsgroup: meta.newsgroup,
            headers,
            cipher_offset: span.start,
            cipher_len: span.len,
            payload_sha256: *hash,
            yenc_name: Some(meta.yenc_name),
            state: ArticleState::Planned,
            provider_id: None,
            posted_at: None,
            reposted_at: None,
        });
    }
    Ok(rows)
}

/// Digest of the plan `rows` of extent `extent`: the extent's id and
/// everything its articles are posted and read back with. It is stored
/// with the packed plan, so that a derivation that ever changed, a
/// changed byte or a plan that is on another extent's row is noticed.
fn check_of(extent: &ExtentId, rows: &[ArticleRow]) -> [u8; CHECK_LEN] {
    let mut h = Sha256::new();
    h.update(b"velmora article plan v1 check");
    let mut field = |bytes: &[u8]| {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    };
    field(extent.as_str().as_bytes());
    for a in rows {
        field(a.message_id.as_bytes());
        field(a.newsgroup.as_bytes());
        field(&a.headers);
        field(a.yenc_name.as_deref().unwrap_or("").as_bytes());
        field(&a.payload_sha256);
    }
    let full: [u8; 32] = h.finalize().into();
    let mut out = [0u8; CHECK_LEN];
    out.copy_from_slice(&full[..CHECK_LEN]);
    out
}

#[inline(never)]
fn put_str8(out: &mut Vec<u8>, s: &[u8]) -> Result<()> {
    out.push(u8::try_from(s.len()).map_err(|_| ERR_PLAN)?);
    out.extend_from_slice(s);
    Ok(())
}

fn put_groups(out: &mut Vec<u8>, groups: &[&str]) -> Result<()> {
    if groups.is_empty() {
        return Err(ERR_PLAN);
    }
    out.push(u8::try_from(groups.len()).map_err(|_| ERR_PLAN)?);
    for g in groups {
        put_str8(out, g.as_bytes())?;
    }
    Ok(())
}

/// A new plan for a `cipher_size`-byte extent, drawn from a fresh seed:
/// the seed and the rows it gives (all `planned`). `hash_of` gives the
/// SHA-256 of the ciphertext of one article.
///
/// Every new plan is drawn this way, whether it is then stored packed
/// ([`pack_seeded`]) or as rows.
pub fn draw<'a, R: FillRandom>(
    rng: &mut R,
    now_secs: i64,
    groups: &[&'a str],
    extent: &ExtentId,
    cipher_size: u64,
    mut hash_of: impl FnMut(&ByteSpan) -> Option<[u8; 32]>,
) -> Result<(PlanSeed<'a>, Vec<ArticleRow>)> {
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed).map_err(|_| ERR_PLAN)?;
    let seed = PlanSeed {
        seed,
        planned_secs: now_secs,
        groups: groups.to_vec(),
    };
    let spans = article_spans(cipher_size);
    let mut hashes = Vec::with_capacity(spans.len() * 32);
    for span in &spans {
        hashes.extend_from_slice(&hash_of(span).ok_or(ERR_PLAN)?);
    }
    let rows = derive(&seed, extent, cipher_size, &hashes)?;
    Ok((seed, rows))
}

/// The packed form of the plan `rows` that [`draw`] made from `seed`.
///
/// The packed form is expanded again before it is returned, so what is
/// handed out is what a reader will get. Fails for a newsgroup list the
/// form does not hold; such a plan is stored as rows.
pub fn pack_seeded(
    seed: &PlanSeed,
    extent: &ExtentId,
    cipher_size: u64,
    rows: &[ArticleRow],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64 + rows.len() * 32);
    out.push(TAG_SEEDED);
    out.extend_from_slice(&seed.seed);
    out.extend_from_slice(&seed.planned_secs.to_be_bytes());
    out.extend_from_slice(&check_of(extent, rows));
    put_groups(&mut out, &seed.groups)?;
    out.extend_from_slice(
        &u32::try_from(rows.len())
            .map_err(|_| ERR_PLAN)?
            .to_be_bytes(),
    );
    for a in rows {
        out.extend_from_slice(&a.payload_sha256);
    }
    let again = expand(extent, cipher_size, &out, None, None)?;
    if !same_plan(&again, rows) {
        return Err(ERR_PLAN);
    }
    Ok(out)
}

/// [`draw`] and [`pack_seeded`] in one: the packed form and its rows.
pub fn plan_seeded<R: FillRandom>(
    rng: &mut R,
    now_secs: i64,
    groups: &[&str],
    extent: &ExtentId,
    cipher_size: u64,
    hash_of: impl FnMut(&ByteSpan) -> Option<[u8; 32]>,
) -> Result<(Vec<u8>, Vec<ArticleRow>)> {
    let (seed, rows) = draw(rng, now_secs, groups, extent, cipher_size, hash_of)?;
    let packed = pack_seeded(&seed, extent, cipher_size, &rows)?;
    Ok((packed, rows))
}

/// The three header fields a stored header block renders from, when it
/// is exactly their rendering.
fn header_fields(a: &ArticleRow) -> Option<[&str; 3]> {
    let text = core::str::from_utf8(&a.headers).ok()?;
    let mut lines = text.split("\r\n");
    let from = lines.next()?.strip_prefix("From: ")?;
    let _groups = lines.next()?;
    let subject = lines.next()?.strip_prefix("Subject: ")?;
    let date = lines.next()?.strip_prefix("Date: ")?;
    let fields = [from, subject, date];
    (render_fields(&a.message_id, &a.newsgroup, fields)? == a.headers).then_some(fields)
}

fn render_fields(
    message_id: &str,
    group: &str,
    [from, subject, date]: [&str; 3],
) -> Option<Vec<u8>> {
    ArticleHeaders::new(from, &[group], subject, date, message_id)
        .and_then(|h| h.render())
        .ok()
}

const HEADERS_FIELDS: u8 = 0;
const HEADERS_RAW: u8 = 1;

/// The explicit packed form of `rows`, the stored plan of a
/// `cipher_size`-byte extent. Fails when the rows are not that plan, or
/// when the packed form would not expand to the same rows; nothing is
/// ever packed with a loss.
pub fn pack_explicit(extent: &ExtentId, cipher_size: u64, rows: &[ArticleRow]) -> Result<Vec<u8>> {
    let mut groups: Vec<&str> = Vec::new();
    for a in rows {
        if !groups.contains(&a.newsgroup.as_str()) {
            groups.push(&a.newsgroup);
        }
    }
    let mut out = Vec::with_capacity(16 + rows.len() * 176);
    out.push(TAG_EXPLICIT);
    out.extend_from_slice(&check_of(extent, rows));
    put_groups(&mut out, &groups)?;
    out.extend_from_slice(
        &u32::try_from(rows.len())
            .map_err(|_| ERR_PLAN)?
            .to_be_bytes(),
    );
    for a in rows {
        let group = groups
            .iter()
            .position(|g| *g == a.newsgroup)
            .ok_or(ERR_PLAN)?;
        out.push(u8::try_from(group).map_err(|_| ERR_PLAN)?);
        put_str8(&mut out, a.message_id.as_bytes())?;
        match header_fields(a) {
            Some(fields) => {
                out.push(HEADERS_FIELDS);
                for f in fields {
                    put_str8(&mut out, f.as_bytes())?;
                }
            }
            None => {
                out.push(HEADERS_RAW);
                out.extend_from_slice(
                    &u16::try_from(a.headers.len())
                        .map_err(|_| ERR_PLAN)?
                        .to_be_bytes(),
                );
                out.extend_from_slice(&a.headers);
            }
        }
        match &a.yenc_name {
            Some(name) => {
                out.push(1);
                put_str8(&mut out, name.as_bytes())?;
            }
            None => out.push(0),
        }
        out.extend_from_slice(&a.payload_sha256);
    }
    let again = expand(extent, cipher_size, &out, None, None)?;
    if !same_plan(&again, rows) {
        return Err(ERR_PLAN);
    }
    Ok(out)
}

/// Whether two plans are the same articles: everything that is posted
/// and read back, not the posting state.
pub fn same_plan(a: &[ArticleRow], b: &[ArticleRow]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            a.extent_id == b.extent_id
                && a.idx == b.idx
                && a.message_id == b.message_id
                && a.newsgroup == b.newsgroup
                && a.headers == b.headers
                && a.cipher_offset == b.cipher_offset
                && a.cipher_len == b.cipher_len
                && a.payload_sha256 == b.payload_sha256
                && a.yenc_name == b.yenc_name
        })
}

/// The packed form of `rows` for a catalogue that is given them again
/// (a replay, or rows that are packed where they are). `seeded` is the
/// seeded form their record carries: it is used when it expands to
/// these very rows, and the explicit form otherwise. `None` = the rows
/// cannot be packed, and stay rows.
pub fn repack(
    extent: &ExtentId,
    cipher_size: u64,
    rows: &[ArticleRow],
    seeded: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let seeded = seeded.filter(|blob| {
        seed_of(blob).is_some()
            && expand(extent, cipher_size, blob, None, None)
                .is_ok_and(|expanded| same_plan(&expanded, rows))
    });
    match seeded {
        Some(blob) => Some(blob.to_vec()),
        None => pack_explicit(extent, cipher_size, rows).ok(),
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    #[inline(never)]
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(ERR_PLAN);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| ERR_PLAN)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    #[inline(never)]
    fn str8(&mut self) -> Result<&'a str> {
        let len = usize::from(self.u8()?);
        core::str::from_utf8(self.take(len)?).map_err(|_| ERR_PLAN)
    }

    fn groups(&mut self) -> Result<Vec<&'a str>> {
        let n = usize::from(self.u8()?);
        if n == 0 {
            return Err(ERR_PLAN);
        }
        let mut groups = Vec::with_capacity(n);
        for _ in 0..n {
            groups.push(self.str8()?);
        }
        Ok(groups)
    }

    fn end(&self) -> Result<()> {
        match self.0.is_empty() {
            true => Ok(()),
            false => Err(ERR_PLAN),
        }
    }
}

/// The rows of the packed plan `blob` of extent `extent` (`cipher_size`
/// bytes of ciphertext), in `idx` order.
///
/// `posted_at` and `reposted_at` are the extent's own columns: a plan is
/// posted as a whole. With `posted_at` unset every article is `planned`;
/// otherwise every one is `posted` at that time
/// ([`POSTED_AT_UNKNOWN`] = at a time nobody knows) and was last posted
/// again at `reposted_at`.
///
/// Anything that is not exactly a plan of this extent is an error: a
/// truncated or overlong value, an article count that does not match the
/// extent's cuts, a plan that does not match its digest (a seed whose
/// derivation came out different, a changed byte, the plan of another
/// extent).
pub fn expand(
    extent: &ExtentId,
    cipher_size: u64,
    blob: &[u8],
    posted_at: Option<i64>,
    reposted_at: Option<i64>,
) -> Result<Vec<ArticleRow>> {
    let mut r = Reader(blob);
    let (check, mut rows): ([u8; CHECK_LEN], _) = match r.u8()? {
        TAG_SEEDED => {
            let seed: [u8; SEED_LEN] = r.array()?;
            let planned_secs = i64::from_be_bytes(r.array()?);
            let check = r.array()?;
            let groups = r.groups()?;
            let n = r.u32()? as usize;
            // Bounded by what is there, before anything is allocated.
            let hashes = r.take(n.checked_mul(32).ok_or(ERR_PLAN)?)?;
            let seed = PlanSeed {
                seed,
                planned_secs,
                groups,
            };
            (check, derive(&seed, extent, cipher_size, hashes)?)
        }
        TAG_EXPLICIT => {
            let check = r.array()?;
            let groups = r.groups()?;
            let n = r.u32()? as usize;
            let spans = article_spans(cipher_size);
            if spans.is_empty() || spans.len() != n {
                return Err(ERR_PLAN);
            }
            let mut rows = Vec::with_capacity(n);
            for (idx, span) in (0u32..).zip(&spans) {
                let group = *groups.get(usize::from(r.u8()?)).ok_or(ERR_PLAN)?;
                let message_id = r.str8()?;
                let headers = match r.u8()? {
                    HEADERS_FIELDS => {
                        let fields = [r.str8()?, r.str8()?, r.str8()?];
                        render_fields(message_id, group, fields).ok_or(ERR_PLAN)?
                    }
                    HEADERS_RAW => {
                        let len = usize::from(u16::from_be_bytes(r.array()?));
                        r.take(len)?.to_vec()
                    }
                    _ => return Err(ERR_PLAN),
                };
                let yenc_name = match r.u8()? {
                    0 => None,
                    1 => Some(r.str8()?),
                    _ => return Err(ERR_PLAN),
                };
                if yenc_name.is_some_and(|name| !valid_yenc_name(name)) {
                    return Err(ERR_PLAN);
                }
                rows.push(ArticleRow {
                    extent_id: extent.clone(),
                    idx,
                    message_id: message_id.to_owned(),
                    newsgroup: group.to_owned(),
                    headers,
                    cipher_offset: span.start,
                    cipher_len: span.len,
                    payload_sha256: r.array()?,
                    yenc_name: yenc_name.map(str::to_owned),
                    state: ArticleState::Planned,
                    provider_id: None,
                    posted_at: None,
                    reposted_at: None,
                });
            }
            (check, rows)
        }
        _ => return Err(ERR_PLAN),
    };
    r.end()?;
    if check_of(extent, &rows) != check {
        return Err(ERR_PLAN);
    }
    if let Some(at) = posted_at {
        let at = (at != POSTED_AT_UNKNOWN).then_some(UnixMs(at));
        for a in &mut rows {
            a.state = ArticleState::Posted;
            a.posted_at = at;
            a.reposted_at = reposted_at.map(UnixMs);
        }
    }
    Ok(rows)
}

/// The seed of a seeded plan, for a test or a report. `None` = the plan
/// is explicit or not a plan.
pub fn seed_of(blob: &[u8]) -> Option<[u8; SEED_LEN]> {
    match blob.split_first() {
        Some((&TAG_SEEDED, rest)) => rest.get(..SEED_LEN)?.try_into().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora::rng::SystemRng;

    const MIB: u64 = 1024 * 1024;
    const NOW: i64 = 1_800_000_000;

    /// A byte source that counts up: the same seed every time.
    struct Counting(u8);

    impl FillRandom for Counting {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
            for b in dest {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn cipher_size(plain: u64) -> u64 {
        velmora::media::ciphertext_size(plain).expect("fits")
    }

    fn hash_of(span: &ByteSpan) -> Option<[u8; 32]> {
        Some(Sha256::digest(span.start.to_be_bytes()).into())
    }

    fn extent() -> ExtentId {
        ExtentId::new("0123456789abcdef0123456789abcdef")
    }

    /// A plan drawn at random, as plans were before they were seeded.
    fn random_plan(cipher: u64, groups: &[&str]) -> Vec<ArticleRow> {
        (0u32..)
            .zip(article_spans(cipher))
            .map(|(idx, span)| {
                let meta = obfuscate_article(&mut SystemRng, 1_800_000_000, groups).unwrap();
                ArticleRow {
                    extent_id: extent(),
                    idx,
                    headers: render_obfuscated_headers(&meta).unwrap(),
                    message_id: meta.message_id,
                    newsgroup: meta.newsgroup,
                    cipher_offset: span.start,
                    cipher_len: span.len,
                    payload_sha256: hash_of(&span).unwrap(),
                    yenc_name: Some(meta.yenc_name),
                    state: ArticleState::Planned,
                    provider_id: None,
                    posted_at: None,
                    reposted_at: None,
                }
            })
            .collect()
    }

    #[test]
    fn a_seeded_plan_expands_to_the_rows_it_was_made_with() {
        let cipher = cipher_size(16 * MIB);
        let (blob, rows) = plan_seeded(
            &mut SystemRng,
            1_800_000_000,
            &["alt.binaries.test", "alt.binaries.misc"],
            &extent(),
            cipher,
            hash_of,
        )
        .unwrap();
        assert_eq!(rows.len(), article_spans(cipher).len());
        let again = expand(&extent(), cipher, &blob, None, None).unwrap();
        assert_eq!(again, rows);
        // Every identifier is its own.
        let mut ids: Vec<&str> = rows.iter().map(|a| a.message_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), rows.len());
        // 16 MiB: under 1 KiB in the catalogue.
        assert!(blob.len() < 1024, "{} bytes", blob.len());
        assert_eq!(seed_of(&blob).map(|s| s.len()), Some(SEED_LEN));
    }

    /// The stream block is HMAC-SHA256 (RFC 2104) of the label, the article
    /// index and the block number, keyed with the seed. The answers were
    /// computed by another implementation of HMAC-SHA256.
    #[test]
    fn a_stream_block_is_hmac_sha256() {
        let vectors: [([u8; SEED_LEN], u32, u32, &str); 4] = [
            (
                [0u8; SEED_LEN],
                0,
                0,
                "2658ca661df07cf693d2791b5e4fa16f924a056166397e31fca0c544a911c06a",
            ),
            (
                core::array::from_fn(|i| i as u8),
                1,
                2,
                "9aee911709c77fc5f504584c8bdcdf89f6bdfb842480eaa1503d57dab7e29a5c",
            ),
            (
                [0xff; SEED_LEN],
                u32::MAX,
                u32::MAX - 1,
                "8c0276871911f2fff975e9d917089192f2ecbbb936d5dc7d025cf3ca6b455d3d",
            ),
            (
                core::array::from_fn(|i| (i * 37 + 11) as u8),
                70_000,
                9,
                "24539d2c031a676465c4f5326686d55c88ace8f222050ad18a169015a05f3346",
            ),
        ];
        for (seed, idx, block, want) in vectors {
            let got: String = stream_block(&seed, idx, block)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(got, want, "idx {idx}, block {block}");
        }
    }

    /// The derivation is part of the stored format: this plan must expand
    /// to these identifiers for as long as a catalogue holds a version-1
    /// seed. A change here means stored plans no longer open.
    #[test]
    fn the_derivation_of_a_seed_is_pinned() {
        let cipher = cipher_size(MIB);
        let (blob, rows) = plan_seeded(
            &mut Counting(0),
            1_800_000_000,
            &["alt.binaries.test"],
            &extent(),
            cipher,
            hash_of,
        )
        .unwrap();
        assert_eq!(seed_of(&blob), Some(core::array::from_fn(|i| i as u8)));
        let first = &rows[0];
        let pinned = (
            first.message_id.as_str(),
            first.yenc_name.as_deref().unwrap(),
            core::str::from_utf8(&first.headers).unwrap(),
        );
        assert_eq!(pinned, PINNED, "the derivation of a version-1 seed changed");
        let last = rows.last().unwrap();
        assert_eq!(last.message_id, PINNED_LAST);
        // The stored bytes of both forms, digest included.
        let explicit = pack_explicit(&extent(), cipher, &rows).unwrap();
        let hex = |bytes: &[u8]| -> String {
            Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        assert_eq!(
            (hex(&blob), hex(&explicit)),
            (PINNED_SEEDED.to_owned(), PINNED_EXPLICIT.to_owned()),
            "the stored form of a version-1 plan changed"
        );
    }

    const PINNED: (&str, &str, &str) = (
        "q9yy2r3oct0dqhkvsazqmeefn0ulktk5@nzij7j50.gq2",
        "vzf5zelc77ix",
        "From: wybpikzkp8t9es9y@djironw6.lu1\r\nNewsgroups: alt.binaries.test\r\n\
         Subject: uKGS0KanwsgKO9TdKeGplHWabxuHXHB7\r\nDate: Fri, 15 Jan 2027 13:45:56 +0000\r\n\
         Message-ID: <q9yy2r3oct0dqhkvsazqmeefn0ulktk5@nzij7j50.gq2>\r\n",
    );
    /// SHA-256 of the seeded and of the explicit form of the pinned plan.
    const PINNED_SEEDED: &str = "4c0f239031457b405a03c20d83cdd14970477c67674550345c2d26bd3ca45b07";
    const PINNED_EXPLICIT: &str =
        "3510e3893ec99c6234835d2b5fcb96fc6ae6e1dbe29544d1c987e1193b73be8f";
    const PINNED_LAST: &str = "nsuzl0xtch3x8o6m8ajfxm15moyfa8du@idmg8en1.48q";

    #[test]
    fn the_posting_state_is_the_extents() {
        let cipher = cipher_size(3 * MIB);
        let (blob, _) =
            plan_seeded(&mut SystemRng, NOW, &["a.b"], &extent(), cipher, hash_of).unwrap();
        let planned = expand(&extent(), cipher, &blob, None, Some(9)).unwrap();
        assert!(planned.iter().all(|a| a.state == ArticleState::Planned
            && a.posted_at.is_none()
            && a.reposted_at.is_none()));
        let posted = expand(&extent(), cipher, &blob, Some(5), Some(9)).unwrap();
        assert!(posted.iter().all(|a| a.state == ArticleState::Posted
            && a.posted_at == Some(UnixMs(5))
            && a.reposted_at == Some(UnixMs(9))));
        let unknown = expand(&extent(), cipher, &blob, Some(POSTED_AT_UNKNOWN), None).unwrap();
        assert!(unknown
            .iter()
            .all(|a| a.state == ArticleState::Posted && a.posted_at.is_none()));
    }

    #[test]
    fn an_explicit_plan_is_packed_without_a_loss() {
        let cipher = cipher_size(16 * MIB);
        let groups = ["alt.binaries.test", "alt.binaries.misc"];
        let mut rows = random_plan(cipher, &groups);
        // A row from before articles had their own yEnc name.
        rows[1].yenc_name = None;
        // Headers that are not the rendering of their fields stay as
        // they are.
        rows[2].headers.extend_from_slice(b"X-Extra: 1\r\n");
        let blob = pack_explicit(&extent(), cipher, &rows).unwrap();
        assert_eq!(expand(&extent(), cipher, &blob, None, None).unwrap(), rows);
        assert_eq!(seed_of(&blob), None);
        // Under 200 bytes an article, against more than 320 as rows.
        assert!(blob.len() < rows.len() * 200, "{} bytes", blob.len());
    }

    #[test]
    fn a_plan_of_another_extent_is_refused() {
        let cipher = cipher_size(16 * MIB);
        let rows = random_plan(cipher, &["a.b"]);
        // Not the cuts of this size.
        assert!(pack_explicit(&extent(), cipher_size(8 * MIB), &rows).is_err());
        let blob = pack_explicit(&extent(), cipher, &rows).unwrap();
        assert!(expand(&extent(), cipher_size(8 * MIB), &blob, None, None).is_err());
        let (seeded, _) =
            plan_seeded(&mut SystemRng, NOW, &["a.b"], &extent(), cipher, hash_of).unwrap();
        assert!(expand(&extent(), cipher_size(8 * MIB), &seeded, None, None).is_err());
        // Rows out of order are not a plan.
        let mut swapped = rows.clone();
        swapped.swap(0, 1);
        assert!(pack_explicit(&extent(), cipher, &swapped).is_err());
        // The plan of an extent of the same size is not this extent's.
        let other = ExtentId::new("fedcba9876543210fedcba9876543210");
        assert!(expand(&extent(), cipher, &blob, None, None).is_ok());
        assert!(expand(&other, cipher, &blob, None, None).is_err());
        assert!(expand(&extent(), cipher, &seeded, None, None).is_ok());
        assert!(expand(&other, cipher, &seeded, None, None).is_err());
    }

    #[test]
    fn a_damaged_plan_is_an_error() {
        let cipher = cipher_size(2 * MIB);
        let (seeded, _) =
            plan_seeded(&mut SystemRng, NOW, &["a.b"], &extent(), cipher, hash_of).unwrap();
        let explicit = pack_explicit(&extent(), cipher, &random_plan(cipher, &["a.b"])).unwrap();
        for blob in [&seeded, &explicit] {
            assert!(expand(&extent(), cipher, blob, None, None).is_ok());
            // Cut short anywhere, or with a byte too many.
            for len in 0..blob.len() {
                assert!(expand(&extent(), cipher, &blob[..len], None, None).is_err());
            }
            let mut longer = blob.to_vec();
            longer.push(0);
            assert!(expand(&extent(), cipher, &longer, None, None).is_err());
            // A changed byte anywhere: a seed that no longer derives what
            // its digest says, another identifier, another payload hash.
            for at in 0..blob.len() {
                let mut flipped = blob.to_vec();
                flipped[at] ^= 1;
                assert!(
                    expand(&extent(), cipher, &flipped, None, None).is_err(),
                    "byte {at} of form {}",
                    blob[0]
                );
            }
        }
        // An unknown form.
        let mut other = seeded.clone();
        other[0] = 9;
        assert!(expand(&extent(), cipher, &other, None, None).is_err());
    }
}
