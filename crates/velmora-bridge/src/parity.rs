//! The parity addendum: the plan of an extent's repair parity, one value
//! beside its packed article plan ([`crate::plan`]).
//!
//! An extent's articles are the data shards of one stripe
//! ([`velmora::rs`]): shard `i` is the ciphertext payload of article `i`.
//! A few parity shards computed over them are posted as articles of their
//! own, so that as many lost articles as there are parity articles can be
//! rebuilt from the rest. The addendum says where the parity articles
//! are: per parity article its row number in the code and the SHA-256 of
//! its payload, plus a 16-byte random seed, the posting clock and the
//! newsgroup list its identifiers are derived from, exactly as a seeded
//! plan derives those of a data article ([`SeedRng`], keyed by the row
//! number).
//!
//! The data plan is not changed by it, byte for byte. A reader takes the
//! stripe from the addendum, never from [`parity_count`]: the number of
//! data shards, the shard length and the row numbers are all stored.
//!
//! The form, big-endian:
//!
//! ```text
//! tag u8 = 1 | kind u8 = 0 | parity_rev u16 | k u16 | L u32 | seed [16]
//!   | planned_secs i64 | check [16] | groups | m u8 | m x (row u16, sha256 [32])
//! ```
//!
//! `groups` is a count byte and then one length byte and the name per
//! group, as in a packed plan. `check` is a digest of the extent's id, of
//! the digest of the data plan the addendum is beside, and of everything
//! each parity article is posted and read back with. A value that is not
//! exactly the addendum of this plan of this extent (a changed byte, a
//! derivation that came out different, the addendum of another extent or
//! of another plan) is an error, never other parity.

use sha2::{Digest, Sha256};
use velmora::article::{obfuscate_article, render_obfuscated_headers};
use velmora::rng::FillRandom;
use velmora::rs::{shard_len, MAX_PARITY_ROW, MAX_PARITY_SHARDS};

use crate::articles::article_spans;
use crate::plan::{check_digest, put_groups, Reader, SeedRng, CHECK_LEN, SEED_LEN};
use crate::types::{ArticleRow, ArticleState, BridgeError, ExtentId, Result};

/// First byte of a parity addendum.
pub const TAG: u8 = 1;
/// Second byte of the addendum of parity over the extent's own articles.
pub const KIND_IN_EXTENT: u8 = 0;
/// `parity_rev` of an addendum that was never rewritten.
pub const FIRST_REV: u16 = 1;

pub(crate) const ERR_PARITY: BridgeError = BridgeError::Invalid("parity addendum");

/// How many parity articles a new extent of `k` data articles gets: one
/// per six data articles, rounded up, and at least one.
///
/// Only the writer of a new addendum asks. What an extent has is in its
/// addendum.
pub fn parity_count(k: usize) -> usize {
    k.div_ceil(6).max(1)
}

/// The row numbers of the parity articles of a new extent of `k` data
/// articles: `0..parity_count(k)`.
pub fn new_rows(k: usize) -> Vec<u16> {
    (0..parity_count(k))
        .map_while(|row| u16::try_from(row).ok())
        .collect()
}

/// The stripe of a `cipher_size`-byte extent: how many data shards it
/// has (its articles) and the shard length (its longest article, rounded
/// up to an even number). `None` = the extent has no article, or more
/// than an addendum counts.
pub fn stripe_of(cipher_size: u64) -> Option<(u16, u32)> {
    let spans = article_spans(cipher_size);
    let k = u16::try_from(spans.len()).ok()?;
    let lens = spans.iter().map(|s| usize::try_from(s.len).ok());
    let len = shard_len(lens.collect::<Option<Vec<usize>>>()?)?;
    Some((k, u32::try_from(len).ok()?))
}

/// What an addendum expands to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityPlan {
    /// How often the addendum was rewritten, from [`FIRST_REV`].
    pub rev: u16,
    /// The shard length of the stripe: the payload length of every
    /// parity article.
    pub shard_len: u32,
    /// The row number in the code of each parity article, in the order
    /// of `articles`. No two are the same.
    pub rows: Vec<u16>,
    /// The parity articles. With `k` data articles in a `cipher_size`
    /// byte extent, the one in place `slot` has `idx = k + slot`, and its
    /// payload is addressed as the `shard_len` bytes from
    /// `cipher_size + slot * shard_len`: past the ciphertext, where no
    /// data article is.
    pub articles: Vec<ArticleRow>,
}

/// The identifiers of the parity articles `rows` (row number and payload
/// hash each) of the stripe (`k`, `len`) of `extent`.
fn derive(
    seed: &[u8; SEED_LEN],
    planned_secs: i64,
    groups: &[&str],
    extent: &ExtentId,
    cipher_size: u64,
    (k, len): (u16, u32),
    rows: &[(u16, [u8; 32])],
) -> Result<Vec<ArticleRow>> {
    let mut out = Vec::with_capacity(rows.len());
    for ((slot, idx), (row, hash)) in (0u64..).zip(u32::from(k)..).zip(rows) {
        let mut rng = SeedRng::new(seed, u32::from(*row));
        let meta = obfuscate_article(&mut rng, planned_secs, groups).map_err(|_| ERR_PARITY)?;
        let headers = render_obfuscated_headers(&meta).map_err(|_| ERR_PARITY)?;
        let cipher_offset = slot
            .checked_mul(u64::from(len))
            .and_then(|at| at.checked_add(cipher_size))
            .ok_or(ERR_PARITY)?;
        out.push(ArticleRow {
            extent_id: extent.clone(),
            idx,
            message_id: meta.message_id,
            newsgroup: meta.newsgroup,
            headers,
            cipher_offset,
            cipher_len: u64::from(len),
            payload_sha256: *hash,
            yenc_name: Some(meta.yenc_name),
            state: ArticleState::Planned,
            provider_id: None,
            posted_at: None,
            reposted_at: None,
        });
    }
    Ok(out)
}

/// Digest of an addendum: the extent's id, the digest of the data plan
/// it is beside, the stripe, and everything each parity article is posted
/// and read back with.
fn check_of(
    extent: &ExtentId,
    plan_check: &[u8; CHECK_LEN],
    rev: u16,
    (k, len): (u16, u32),
    rows: &[(u16, [u8; 32])],
    articles: &[ArticleRow],
) -> [u8; CHECK_LEN] {
    let mut h = Sha256::new();
    h.update(b"velmora parity addendum v1 check");
    let mut field = |bytes: &[u8]| {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    };
    field(extent.as_str().as_bytes());
    field(plan_check);
    field(&rev.to_be_bytes());
    field(&k.to_be_bytes());
    field(&len.to_be_bytes());
    for ((row, _), a) in rows.iter().zip(articles) {
        field(&row.to_be_bytes());
        field(a.message_id.as_bytes());
        field(a.newsgroup.as_bytes());
        field(&a.headers);
        field(a.yenc_name.as_deref().unwrap_or("").as_bytes());
        field(&a.payload_sha256);
        field(&a.cipher_len.to_be_bytes());
    }
    let full: [u8; 32] = h.finalize().into();
    let mut out = [0u8; CHECK_LEN];
    out.copy_from_slice(&full[..CHECK_LEN]);
    out
}

/// Row numbers an addendum may hold: at least one, no more than one call
/// of the codec takes, none above its highest row, none twice.
fn check_rows(rows: &[(u16, [u8; 32])]) -> Result<()> {
    let twice = |at: usize, row: u16| rows[..at].iter().any(|(other, _)| *other == row);
    let bad = rows
        .iter()
        .enumerate()
        .any(|(at, (row, _))| *row > MAX_PARITY_ROW || twice(at, *row));
    if rows.is_empty() || rows.len() > MAX_PARITY_SHARDS || bad {
        return Err(ERR_PARITY);
    }
    Ok(())
}

/// A new addendum for the `cipher_size`-byte extent `extent`, beside its
/// packed plan `plan`: the parity articles `rows` (row number and
/// SHA-256 of the parity shard each), their identifiers derived from a
/// fresh seed.
///
/// The addendum is expanded again before it is returned, so what is
/// handed out is what a reader will get. Fails for a plan that is not
/// packed and for a newsgroup list the form does not hold; such an
/// extent gets no parity.
pub fn build<R: FillRandom>(
    rng: &mut R,
    now_secs: i64,
    groups: &[&str],
    extent: &ExtentId,
    cipher_size: u64,
    plan: &[u8],
    rows: &[(u16, [u8; 32])],
) -> Result<Vec<u8>> {
    check_rows(rows)?;
    let stripe = stripe_of(cipher_size).ok_or(ERR_PARITY)?;
    let plan_check = check_digest(plan).ok_or(ERR_PARITY)?;
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed).map_err(|_| ERR_PARITY)?;
    let articles = derive(&seed, now_secs, groups, extent, cipher_size, stripe, rows)?;
    let check = check_of(extent, &plan_check, FIRST_REV, stripe, rows, &articles);

    let mut out = Vec::with_capacity(64 + rows.len() * 34);
    out.push(TAG);
    out.push(KIND_IN_EXTENT);
    out.extend_from_slice(&FIRST_REV.to_be_bytes());
    out.extend_from_slice(&stripe.0.to_be_bytes());
    out.extend_from_slice(&stripe.1.to_be_bytes());
    out.extend_from_slice(&seed);
    out.extend_from_slice(&now_secs.to_be_bytes());
    out.extend_from_slice(&check);
    put_groups(&mut out, groups).map_err(|_| ERR_PARITY)?;
    out.push(u8::try_from(rows.len()).map_err(|_| ERR_PARITY)?);
    for (row, hash) in rows {
        out.extend_from_slice(&row.to_be_bytes());
        out.extend_from_slice(hash);
    }
    let again = expand(extent, cipher_size, plan, &out)?;
    if again.articles != articles {
        return Err(ERR_PARITY);
    }
    Ok(out)
}

/// The parity articles of the addendum `blob` of extent `extent`
/// (`cipher_size` bytes of ciphertext), which is beside the packed plan
/// `plan`. Every article is `planned`: the posting state is the plan's
/// ([`crate::plan::StoredPlan::parity_plan`]).
///
/// Anything that is not exactly an addendum of this plan of this extent
/// is an error: another tag or kind, a truncated or overlong value, a
/// stripe that is not the extent's (the number of data articles, the
/// shard length), no parity article or more than one call of the codec
/// takes, a row number twice or above the codec's highest, an addendum
/// that does not match its digest.
pub fn expand(extent: &ExtentId, cipher_size: u64, plan: &[u8], blob: &[u8]) -> Result<ParityPlan> {
    parse(extent, cipher_size, plan, blob).map_err(|_| ERR_PARITY)
}

fn parse(extent: &ExtentId, cipher_size: u64, plan: &[u8], blob: &[u8]) -> Result<ParityPlan> {
    let mut r = Reader(blob);
    if r.u8()? != TAG || r.u8()? != KIND_IN_EXTENT {
        return Err(ERR_PARITY);
    }
    let rev = u16::from_be_bytes(r.array()?);
    let stripe = (u16::from_be_bytes(r.array()?), r.u32()?);
    if rev < FIRST_REV || stripe_of(cipher_size) != Some(stripe) {
        return Err(ERR_PARITY);
    }
    let seed: [u8; SEED_LEN] = r.array()?;
    let planned_secs = i64::from_be_bytes(r.array()?);
    let check: [u8; CHECK_LEN] = r.array()?;
    let groups = r.groups()?;
    let m = usize::from(r.u8()?);
    // Bounded by what is there, before anything is allocated.
    let (entries, rest) = r
        .take(m.checked_mul(34).ok_or(ERR_PARITY)?)?
        .as_chunks::<34>();
    r.end()?;
    if !rest.is_empty() {
        return Err(ERR_PARITY);
    }
    let mut rows = Vec::with_capacity(m);
    for entry in entries {
        let (row, hash) = entry.split_at(2);
        let row = u16::from_be_bytes(row.try_into().map_err(|_| ERR_PARITY)?);
        rows.push((row, hash.try_into().map_err(|_| ERR_PARITY)?));
    }
    check_rows(&rows)?;
    let articles = derive(
        &seed,
        planned_secs,
        &groups,
        extent,
        cipher_size,
        stripe,
        &rows,
    )?;
    let plan_check = check_digest(plan).ok_or(ERR_PARITY)?;
    if check_of(extent, &plan_check, rev, stripe, &rows, &articles) != check {
        return Err(ERR_PARITY);
    }
    Ok(ParityPlan {
        rev,
        shard_len: stripe.1,
        rows: rows.iter().map(|(row, _)| *row).collect(),
        articles,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan;
    use crate::types::ByteSpan;

    const MIB: u64 = 1024 * 1024;
    const NOW: i64 = 1_800_000_000;
    const GROUPS: [&str; 1] = ["alt.binaries.test"];

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

    /// Refused as no addendum of the plan, whatever is wrong with it.
    fn refused<T>(result: Result<T>) -> bool {
        matches!(result, Err(BridgeError::Invalid("parity addendum")))
    }

    fn extent() -> ExtentId {
        ExtentId::new("0123456789abcdef0123456789abcdef")
    }

    /// The packed plan of a `cipher`-byte extent, the same every time.
    fn data_plan(extent: &ExtentId, cipher: u64) -> Vec<u8> {
        plan::plan_seeded(&mut Counting(0), NOW, &GROUPS, extent, cipher, hash_of)
            .unwrap()
            .0
    }

    /// Row numbers `0..m`, each with a hash made from its number.
    fn rows(m: u16) -> Vec<(u16, [u8; 32])> {
        (0..m)
            .map(|row| (row, Sha256::digest(row.to_be_bytes()).into()))
            .collect()
    }

    fn addendum(extent: &ExtentId, cipher: u64, m: u16) -> Vec<u8> {
        let plan = data_plan(extent, cipher);
        build(
            &mut Counting(100),
            NOW,
            &GROUPS,
            extent,
            cipher,
            &plan,
            &rows(m),
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn one_parity_article_per_six_data_articles_and_at_least_one() {
        for (k, m) in [(1, 1), (2, 1), (6, 1), (7, 2), (12, 2), (13, 3), (24, 4)] {
            assert_eq!(parity_count(k), m, "k = {k}");
            assert_eq!(new_rows(k), (0..m as u16).collect::<Vec<_>>());
        }
    }

    #[test]
    fn the_stripe_is_the_extents_articles_and_its_longest_one() {
        assert_eq!(stripe_of(0), None);
        assert_eq!(stripe_of(1), Some((1, 2)));
        assert_eq!(stripe_of(1000), Some((1, 1000)));
        let cipher = cipher_size(16 * MIB);
        let spans = article_spans(cipher);
        let longest = spans.iter().map(|s| s.len).max().unwrap();
        assert_eq!(spans.len(), 24);
        assert_eq!(
            stripe_of(cipher),
            Some((24, u32::try_from(longest + longest % 2).unwrap()))
        );
    }

    #[test]
    fn an_addendum_expands_to_articles_past_the_ciphertext() {
        let extent = extent();
        let cipher = cipher_size(16 * MIB);
        let (k, len) = stripe_of(cipher).unwrap();
        let blob = addendum(&extent, cipher, 4);
        let parity = expand(&extent, cipher, &data_plan(&extent, cipher), &blob).unwrap();

        assert_eq!(parity.rev, FIRST_REV);
        assert_eq!(parity.shard_len, len);
        assert_eq!(parity.rows, [0, 1, 2, 3]);
        assert_eq!(parity.articles.len(), 4);
        let data = plan::expand(&extent, cipher, &data_plan(&extent, cipher), None, None).unwrap();
        for (slot, (a, (_, hash))) in parity.articles.iter().zip(rows(4)).enumerate() {
            assert_eq!(a.extent_id, extent);
            assert_eq!(a.idx, u32::from(k) + slot as u32);
            assert_eq!(a.cipher_offset, cipher + slot as u64 * u64::from(len));
            assert_eq!(a.cipher_len, u64::from(len));
            assert_eq!(a.payload_sha256, hash);
            assert_eq!(a.newsgroup, GROUPS[0]);
            assert!(a.yenc_name.is_some());
            assert_eq!(a.state, ArticleState::Planned);
            // No identifier of a data article, and none twice.
            assert!(data.iter().all(|d| d.message_id != a.message_id));
            assert!(parity.articles[..slot]
                .iter()
                .all(|b| b.message_id != a.message_id));
        }
    }

    /// The addendum of a fixed seed, byte for byte, and what it expands
    /// to. A change of the form or of the derivation shows here: a
    /// stored addendum would not expand to the articles that were posted.
    #[test]
    fn the_addendum_of_a_seed_is_pinned() {
        let extent = extent();
        let cipher = cipher_size(2 * MIB);
        assert_eq!(stripe_of(cipher), Some((3, 721_120)));
        let blob = addendum(&extent, cipher, 2);
        assert_eq!(hex(&blob), PINNED_ADDENDUM);
        let parity = expand(&extent, cipher, &data_plan(&extent, cipher), &blob).unwrap();
        let ids: Vec<&str> = parity
            .articles
            .iter()
            .map(|a| a.message_id.as_str())
            .collect();
        assert_eq!(ids, PINNED_MESSAGE_IDS);
        assert_eq!(
            hex(&Sha256::digest(&parity.articles[0].headers)),
            PINNED_HEADERS_SHA256
        );
        assert_eq!(
            parity.articles[1].yenc_name.as_deref(),
            Some(PINNED_YENC_NAME)
        );
    }

    const PINNED_ADDENDUM: &str = "010000010003000b00e06465666768696a6b6c6d6e6f70717273000000006b49d200696f6fcf0ffe79346e0b89105d33c9ce0111616c742e62696e61726965732e7465737402000096a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc70001b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2";
    const PINNED_MESSAGE_IDS: [&str; 2] = [
        "tiwmail08p63eulnl3v8sr4tkex0z51g@dwgssjtf.gxu",
        "gjcipfe0b9db5v4fsud0pk5a0o21u7k2@g2txe8cx.xkj",
    ];
    const PINNED_HEADERS_SHA256: &str =
        "47e41c0bd8909ea111eb018cbf6b19fa9ac31ee235f2db61a551a6dffbec0948";
    const PINNED_YENC_NAME: &str = "mxt6rlpbtrpk";

    /// The size of an addendum: 50 bytes, the newsgroup list, and 34
    /// bytes per parity article.
    #[test]
    fn an_addendum_is_small() {
        let extent = extent();
        for (plain, m, bytes) in [(MIB, 1, 104), (8 * MIB, 2, 138), (16 * MIB, 4, 206)] {
            let cipher = cipher_size(plain);
            assert_eq!(
                parity_count(article_spans(cipher).len()),
                usize::from(m),
                "{plain} bytes"
            );
            assert_eq!(addendum(&extent, cipher, m).len(), bytes, "m = {m}");
        }
    }

    #[test]
    fn the_identifiers_of_a_row_do_not_depend_on_the_other_rows() {
        let extent = extent();
        let cipher = cipher_size(16 * MIB);
        let plan = data_plan(&extent, cipher);
        let all = rows(4);
        let some = [all[3], all[1]];
        let of = |rows: &[(u16, [u8; 32])]| {
            let blob = build(
                &mut Counting(100),
                NOW,
                &GROUPS,
                &extent,
                cipher,
                &plan,
                rows,
            );
            expand(&extent, cipher, &plan, &blob.unwrap()).unwrap()
        };
        let (all, some) = (of(&all), of(&some));
        assert_eq!(some.rows, [3, 1]);
        assert_eq!(some.articles[0].message_id, all.articles[3].message_id);
        assert_eq!(some.articles[1].headers, all.articles[1].headers);
        // The place in the addendum, not the row number, says where the
        // payload is addressed.
        assert_eq!(some.articles[0].idx, all.articles[0].idx);
        assert_eq!(
            some.articles[0].cipher_offset,
            all.articles[0].cipher_offset
        );
    }

    #[test]
    fn an_addendum_of_another_extent_or_plan_is_refused() {
        let extent = extent();
        let cipher = cipher_size(2 * MIB);
        let plan = data_plan(&extent, cipher);
        let blob = addendum(&extent, cipher, 1);
        assert!(expand(&extent, cipher, &plan, &blob).is_ok());

        let other = ExtentId::new("fedcba9876543210fedcba9876543210");
        assert!(refused(expand(
            &other,
            cipher,
            &data_plan(&other, cipher),
            &blob
        )));
        // Another plan of the same extent: other identifiers, so another
        // digest.
        let redrawn = plan::plan_seeded(&mut Counting(7), NOW, &GROUPS, &extent, cipher, hash_of)
            .unwrap()
            .0;
        assert!(refused(expand(&extent, cipher, &redrawn, &blob)));
        // Not a packed plan at all.
        assert!(refused(expand(&extent, cipher, &[], &blob)));
        assert!(refused(expand(&extent, cipher, &blob, &blob)));
    }

    /// The same plan in its explicit form has the same digest: an
    /// addendum stays good when a catalogue is given its plan again.
    #[test]
    fn an_addendum_holds_beside_either_form_of_its_plan() {
        let extent = extent();
        let cipher = cipher_size(2 * MIB);
        let seeded = data_plan(&extent, cipher);
        let rows = plan::expand(&extent, cipher, &seeded, None, None).unwrap();
        let explicit = plan::pack_explicit(&extent, cipher, &rows).unwrap();
        assert_ne!(explicit, seeded);
        let blob = addendum(&extent, cipher, 1);
        assert_eq!(
            expand(&extent, cipher, &explicit, &blob).unwrap(),
            expand(&extent, cipher, &seeded, &blob).unwrap()
        );
    }

    #[test]
    fn an_addendum_of_another_stripe_is_refused() {
        let extent = extent();
        let cipher = cipher_size(2 * MIB);
        let blob = addendum(&extent, cipher, 1);
        // One byte less of ciphertext: as many articles, a shorter last
        // one, the same shard length. The data plan is another, though.
        for other in [
            cipher - 1,
            cipher + 1,
            cipher_size(MIB),
            cipher_size(4 * MIB),
        ] {
            assert!(
                refused(expand(&extent, other, &data_plan(&extent, other), &blob)),
                "{other} bytes"
            );
        }
        // The stripe fields themselves: k at 4..6, L at 6..10.
        for at in 4..10 {
            let mut bad = blob.clone();
            bad[at] ^= 1;
            assert!(
                refused(expand(&extent, cipher, &data_plan(&extent, cipher), &bad)),
                "byte {at}"
            );
        }
    }

    #[test]
    fn rows_that_the_codec_does_not_take_are_refused() {
        let extent = extent();
        let cipher = cipher_size(2 * MIB);
        let plan = data_plan(&extent, cipher);
        let make = |rows: &[(u16, [u8; 32])]| {
            build(
                &mut Counting(100),
                NOW,
                &GROUPS,
                &extent,
                cipher,
                &plan,
                rows,
            )
        };
        let hash = [7u8; 32];
        assert!(refused(make(&[])));
        assert!(refused(make(&[(1, hash), (0, hash), (1, hash)])));
        assert!(refused(make(&[(MAX_PARITY_ROW + 1, hash)])));
        assert!(make(&[(MAX_PARITY_ROW, hash)]).is_ok());
        let many: Vec<(u16, [u8; 32])> =
            (0..=MAX_PARITY_SHARDS as u16).map(|r| (r, hash)).collect();
        assert!(refused(make(&many)));
        assert!(make(&many[1..]).is_ok());

        // The same in a stored value: the digest is not what refuses it.
        let blob = make(&[(0, hash), (1, hash)]).unwrap();
        let at = blob.len() - 2 * 34;
        let mut twice = blob.clone();
        twice[at + 34..at + 36].copy_from_slice(&0u16.to_be_bytes());
        assert!(refused(expand(&extent, cipher, &plan, &twice)));
        let mut none = blob[..at].to_vec();
        *none.last_mut().unwrap() = 0;
        assert!(refused(expand(&extent, cipher, &plan, &none)));
    }

    #[test]
    fn a_damaged_addendum_is_an_error() {
        let extent = extent();
        let cipher = cipher_size(2 * MIB);
        let plan = data_plan(&extent, cipher);
        let blob = addendum(&extent, cipher, 2);
        assert!(expand(&extent, cipher, &plan, &blob).is_ok());

        assert!(refused(expand(&extent, cipher, &plan, &[])));
        // Every truncation, and a byte too many.
        for len in 0..blob.len() {
            assert!(
                refused(expand(&extent, cipher, &plan, &blob[..len])),
                "{len} bytes"
            );
        }
        let mut long = blob.clone();
        long.push(0);
        assert!(refused(expand(&extent, cipher, &plan, &long)));
        // Every single changed bit, the tag, the kind and the revision
        // included.
        for at in 0..blob.len() {
            for bit in 0..8 {
                let mut bad = blob.clone();
                bad[at] ^= 1 << bit;
                assert!(
                    refused(expand(&extent, cipher, &plan, &bad)),
                    "byte {at} bit {bit}"
                );
            }
        }
    }
}
