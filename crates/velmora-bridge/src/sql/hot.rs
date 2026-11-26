//! Hot-tier accounting and eviction (catalogue lane B).
//!
//! R2 holds two kinds of copy of an extent:
//! - the safety copy (`x/`). While the extent is `held` or `releasing` it
//!   is *pinned*: not yet proven on enough backbones, or too young. Once
//!   released it is evictable, and `hot_safety_bytes` counts it.
//! - the cache fill (`c/`), counted by `hot_cache_bytes`. It only ever
//!   comes from a verified read from Usenet, so it is evictable whatever
//!   the state of the safety copy.
//!
//! The totals are recomputed from the rows, never kept as a counter, so
//! they cannot drift from what the rows say and cannot go negative. The
//! sums run over partial covering indexes.
//!
//! An eviction is fenced by `extents.evict_seq`:
//! - `begin_evict` is one statement that re-checks the extent (pinned or
//!   not, byte counts, sequence) against the listing and bumps the
//!   sequence. Two jobs cannot both begin, and the safety copy of a
//!   pinned extent is never part of an eviction.
//! - The job deletes the blobs.
//! - `finish_evict` zeroes the byte counts only if the sequence is still
//!   the one `begin_evict` left. A cache fill in between bumps it, so the
//!   fill stays counted.
//!
//! Every statement that changes `safety_state` bumps the sequence too, so
//! a listing never survives a state change.
//!
//! The job asks once more right before it deletes the safety copy
//! (`evict_safety_still_ok`): a moved sequence (a re-pin, a refill) or a
//! scrub loss recorded after the listing deletes nothing.
//!
//! The job lists bounded windows of the eviction order (`evict_window`):
//! a row that would delete an extent's last R2 copy may go only while the
//! extent is releasable under the backbones that count now and, with
//! `SCRUB` on, has no loss on record there.
//!
//! The counts are not exact, and they are not a bound in either
//! direction. Each error is limited to one extent's bytes and repairs
//! itself:
//! - counted but already gone (a delete raced a fill, the bucket's
//!   lifecycle rule expired the blob, or a read that was served from the
//!   cache blob counted it with `touch_read` after an eviction of the
//!   same extent had finished and deleted it): the next eviction of the
//!   extent zeroes the count;
//! - a cache blob that exists but is not counted (written before these
//!   columns existed, or by a request that was cancelled between its
//!   write and its second count while an eviction or a garbage
//!   collection of the same extent ran): a read served from it
//!   counts it again (`touch_read`; an isolate asks at most once an hour
//!   per extent), and an eviction of the extent deletes
//!   both keys whatever the counts say. One that is never read again and
//!   never evicted is left to the cache bucket's lifecycle rule.

use super::uploads::{int, ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Sql, SqlValue};
use crate::types::{
    EvictCandidate, EvictCursor, EvictRule, EvictWindow, ExtentId, HotStats, Result, UnixMs,
};

/// True for an extent whose safety copy is pinned. The text matches the
/// `extents_safety` index.
macro_rules! pinned {
    () => {
        "safety_state IN ('held', 'releasing')"
    };
}

/// True for an extent with bytes that may be evicted. The text matches
/// the `extents_evictable` index.
macro_rules! evictable {
    () => {
        "(hot_cache_bytes > 0 \
          OR (hot_safety_bytes > 0 AND safety_state NOT IN ('held', 'releasing')))"
    };
}

/// The evictable bytes of one row: the cache fill, and the safety copy
/// unless it is pinned.
macro_rules! evictable_bytes {
    () => {
        "hot_cache_bytes + CASE WHEN safety_state IN ('held', 'releasing') \
                                THEN 0 ELSE hot_safety_bytes END"
    };
}

async fn total<S: Sql>(c: &SqlCatalog<S>, sql: &str) -> Result<(u64, u64)> {
    let rows = c.sql.query(sql, &[]).await?;
    match rows.into_iter().next() {
        Some(row) => {
            let mut r = Cols::new(row);
            Ok((r.num()?, r.num()?))
        }
        None => Ok((0, 0)),
    }
}

const EVICTABLE_TOTAL: &str = concat!(
    "SELECT COALESCE(SUM(",
    evictable_bytes!(),
    "), 0), COUNT(*) FROM extents WHERE ",
    evictable!()
);
const PINNED_TOTAL: &str = concat!(
    "SELECT COALESCE(SUM(cipher_size), 0), COUNT(*) FROM extents WHERE ",
    pinned!()
);
const CANDIDATES: &str = concat!(
    "SELECT id, hot_safety_bytes, hot_cache_bytes, evict_seq, ",
    pinned!(),
    " FROM extents WHERE ",
    evictable!(),
    " ORDER BY last_read_at, id LIMIT ?1"
);

/// True while the scrub has a loss of the extent `extents.id` on record:
/// one key lookup in `scrub_copies` per row.
/// True while the scrub has a loss of the extent `$x` on record on one of
/// the backbones that count now (`$labels`, a JSON array, as the scrub's
/// own `HAS_LOSS` reads it): key lookups in `scrub_copies`. A loss on a
/// backbone that no longer counts is never checked again, so it must not
/// keep the extent's copies.
// A scalar subquery with LIMIT 1, not EXISTS: PostgreSQL may turn an
// EXISTS into one hashed pass over all of `scrub_copies`; this stays one
// key lookup per row on both engines.
macro_rules! scrub_loss_on_record {
    ($x:literal, $labels:literal) => {
        concat!(
            "(SELECT 1 FROM scrub_copies s WHERE s.extent_id = ",
            $x,
            " AND s.backbone IN (SELECT ",
            $labels,
            ") AND (s.stat_loss_at IS NOT NULL OR s.full_loss_at IS NOT NULL) LIMIT 1) IS NOT NULL"
        )
    };
}

/// One bounded window of the eviction order: `?1` rows of the
/// `extents_evictable` index after the keyset, read before anything is
/// decided about them, so a long run of rows that may not go costs one
/// window per step, not a scan. Each row carries what the job needs to
/// decide in one place (`crate::verify::evidence_releasable`, the
/// release rule itself): its release evidence and plan, and, with the
/// scrub on, whether a loss of it is on record on a counting backbone.
macro_rules! evict_window {
    ($loss:expr, $keyset:literal, $order:literal) => {
        concat!(
            "SELECT id, hot_safety_bytes, hot_cache_bytes, evict_seq, ",
            pinned!(),
            " AS pinned, last_read_at, release_evidence, plan_rev, safety_state, ",
            $loss,
            " FROM extents WHERE ",
            evictable!(),
            $keyset,
            " ORDER BY ",
            $order,
            " LIMIT ?1"
        )
    };
}
macro_rules! loss_flag {
    ($labels:literal) => {
        concat!(
            "CASE WHEN ",
            scrub_loss_on_record!("extents.id", $labels),
            " THEN 1 ELSE 0 END"
        )
    };
}
pub const EVICT_WINDOW: &str = evict_window!("0", "", "last_read_at, id");
pub const EVICT_WINDOW_AFTER: &str = evict_window!(
    "0",
    " AND (last_read_at, id) > (?2, ?3)",
    "last_read_at, id"
);
pub const EVICT_WINDOW_SCRUB: &str = evict_window!(
    loss_flag!("value FROM json_each(?2)"),
    "",
    "last_read_at, id"
);
pub const EVICT_WINDOW_SCRUB_AFTER: &str = evict_window!(
    loss_flag!("value FROM json_each(?4)"),
    " AND (last_read_at, id) > (?2, ?3)",
    "last_read_at, id"
);
pub const EVICT_WINDOW_PG: &str = evict_window!("0", "", "last_read_at ASC NULLS FIRST, id");
pub const EVICT_WINDOW_AFTER_PG: &str = evict_window!(
    "0",
    " AND (last_read_at, id) > (?2, ?3)",
    "last_read_at ASC NULLS FIRST, id"
);
pub const EVICT_WINDOW_SCRUB_PG: &str = evict_window!(
    loss_flag!("jsonb_array_elements_text(CAST(?2 AS jsonb))"),
    "",
    "last_read_at ASC NULLS FIRST, id"
);
pub const EVICT_WINDOW_SCRUB_AFTER_PG: &str = evict_window!(
    loss_flag!("jsonb_array_elements_text(CAST(?4 AS jsonb))"),
    " AND (last_read_at, id) > (?2, ?3)",
    "last_read_at ASC NULLS FIRST, id"
);

// With the scrub on, an extent eviction keeps for want of a release under
// the backbones that count now is looked at by the scrub soon (its own
// deadline, unless it has one): the re-verify writes a safety copy, which
// no lifecycle rule expires, rather than leaving the extent to a cache
// fill that the cache bucket's lifecycle rule may expire.
const WATCH_SOON: &str = "UPDATE extents SET scrub_next_at = ?2 \
    WHERE id = ?1 AND scrub_next_at IS NULL AND safety_state = 'released'";

// The scrub deleted a released extent's safety object (its bytes were
// not the extent's): it is no longer counted, so it adds no phantom bytes
// to the tier's total. The sequence moves, so an eviction listed before
// cannot claim the bytes either.
const SAFETY_GONE: &str = "UPDATE extents SET hot_safety_bytes = 0, evict_seq = evict_seq + 1 \
    WHERE id = ?1 AND safety_state = 'released' AND hot_safety_bytes > 0";

// Right before the scrub deletes a safety object whose bytes are not the
// extent's: the sequence moves first, so an eviction that claimed the row
// before finds it moved at its check and deletes nothing.
const SAFETY_FENCE: &str = "UPDATE extents SET evict_seq = evict_seq + 1 WHERE id = ?1";

// The extent's ciphertext as recorded: what a blob must be to be its copy.
const EXTENT_CIPHER: &str =
    "SELECT bucket_id, cipher_size, cipher_sha256, safety_state FROM extents WHERE id = ?1";

// Eviction wrote a released extent's verified cache fill to the safety
// store (kept for want of a release): it is counted, if the row is as
// listed.
const EVICT_PROMOTED: &str = "UPDATE extents SET hot_safety_bytes = cipher_size, \
    evict_seq = evict_seq + 1 \
    WHERE id = ?1 AND evict_seq = ?2 AND safety_state = 'released' AND hot_safety_bytes = 0";

// The extents of a generation, as the window reads them: whether each may
// lose its last R2 copy now, and its ciphertext. One read for an object.
macro_rules! evict_generation {
    ($loss:expr) => {
        concat!(
            "SELECT extents.id, ",
            pinned!(),
            " AS pinned, release_evidence, plan_rev, safety_state, ",
            $loss,
            ", bucket_id, cipher_size, cipher_sha256 \
             FROM generation_extents r JOIN extents ON extents.id = r.extent_id \
             WHERE r.generation_id = ?1"
        )
    };
}
const EVICT_GENERATION: &str = evict_generation!("0");
const EVICT_GENERATION_SCRUB: &str = evict_generation!(loss_flag!("value FROM json_each(?2)"));
const EVICT_GENERATION_SCRUB_PG: &str =
    evict_generation!(loss_flag!("jsonb_array_elements_text(CAST(?2 AS jsonb))"));

const EVICT_CURSOR: &str = "SELECT v FROM scan_cursors WHERE k = 'evict'";
const SET_EVICT_CURSOR: &str = "INSERT OR REPLACE INTO scan_cursors(k, v) VALUES ('evict', ?1)";
const SET_EVICT_CURSOR_PG: &str =
    "INSERT INTO scan_cursors(k, v) VALUES ('evict', ?1) ON CONFLICT (k) DO UPDATE SET v = excluded.v";

/// The periodic statements with the index each must be answered from
/// alone, without touching the table or sorting. Tests hold them to it.
pub const INDEX_ONLY: [(&str, &str); 3] = [
    (EVICTABLE_TOTAL, "extents_evictable"),
    (CANDIDATES, "extents_evictable"),
    (PINNED_TOTAL, "extents_safety"),
];

/// Evictable bytes and the extents that hold them.
async fn evictable<S: Sql>(c: &SqlCatalog<S>) -> Result<(u64, u64)> {
    total(c, EVICTABLE_TOTAL).await
}

pub(super) async fn evictable_bytes<S: Sql>(c: &SqlCatalog<S>) -> Result<u64> {
    Ok(evictable(c).await?.0)
}

/// Pinned and evictable totals. Pinned bytes are safety copies only: a
/// cache fill is evictable even while the extent's safety copy is pinned.
pub(super) async fn hot_stats<S: Sql>(c: &SqlCatalog<S>) -> Result<HotStats> {
    // Pinned totals from the usage counters once they are switched on:
    // one row read instead of every pinned extent. The evictable total
    // stays a read of its partial index, which holds only what the hot
    // tier holds and is bounded by the tier's cap, not by the catalogue.
    let usage = super::usage::counters(c).await?;
    let (pinned_bytes, pinned_extents) = if usage.seeded {
        (
            u64::try_from(usage.unreleased_bytes).unwrap_or(0),
            u64::try_from(usage.extents_unreleased).unwrap_or(0),
        )
    } else {
        total(c, PINNED_TOTAL).await?
    };
    let (evictable_bytes, evictable_extents) = evictable(c).await?;
    Ok(HotStats {
        pinned_bytes,
        pinned_extents,
        evictable_bytes,
        evictable_extents,
    })
}

/// Extents with evictable bytes, least recently read first.
pub(super) async fn evict_candidates<S: Sql>(
    c: &SqlCatalog<S>,
    limit: u32,
) -> Result<Vec<EvictCandidate>> {
    let rows = c
        .sql
        .query(
            c.sql.dialect().pick(CANDIDATES, CANDIDATES_PG),
            &[SqlValue::Int(i64::from(limit))],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(EvictCandidate {
            extent: ExtentId::new(r.text()?),
            safety_bytes: r.num()?,
            cache_bytes: r.num()?,
            seq: r.num()?,
            pinned: r.num::<i64>()? != 0,
        });
    }
    Ok(out)
}

/// One bounded window of the eviction order after `cursor`, and of it at
/// most `take` rows that may go under `rule`:
/// - a pinned extent's cache fill (the job checks that its safety copy is
///   in place before it deletes the fill);
/// - any other row deletes the extent's last R2 copy, so only while the
///   extent is releasable under the backbones that count now, by the
///   release rule itself over its stored evidence
///   ([`crate::verify::evidence_releasable`]), and, with the scrub on,
///   has no loss on record there.
///
/// The cursor that comes back is past the last row looked at, whether or
/// not any could go; `more` is false once the window reached the end.
/// `unproven` names the rows kept for want of a release.
pub(super) async fn evict_window<S: Sql>(
    c: &SqlCatalog<S>,
    cursor: &EvictCursor,
    window: u32,
    take: u32,
    rule: &EvictRule,
) -> Result<EvictWindow> {
    let pg = c.sql.dialect() == crate::ports::Dialect::Postgres;
    let mut params = vec![SqlValue::Int(i64::from(window))];
    if let EvictCursor::After(read, id) = cursor {
        params.push(SqlValue::Int(*read));
        params.push(text(id));
    }
    if rule.scrub {
        params.push(labels(&rule.counting)?);
    }
    let after = matches!(cursor, EvictCursor::After(..));
    let sql = match (rule.scrub, after, pg) {
        (false, false, false) => EVICT_WINDOW,
        (false, true, false) => EVICT_WINDOW_AFTER,
        (true, false, false) => EVICT_WINDOW_SCRUB,
        (true, true, false) => EVICT_WINDOW_SCRUB_AFTER,
        (false, false, true) => EVICT_WINDOW_PG,
        (false, true, true) => EVICT_WINDOW_AFTER_PG,
        (true, false, true) => EVICT_WINDOW_SCRUB_PG,
        (true, true, true) => EVICT_WINDOW_SCRUB_AFTER_PG,
    };
    let rows = c.sql.query(sql, &params).await?;
    let full = rows.len() as u64 >= u64::from(window);
    let mut out = EvictWindow {
        rows: Vec::new(),
        next: EvictCursor::Start,
        more: full,
        unproven: Vec::new(),
    };
    let mut last = None;
    for row in rows {
        let mut r = Cols::new(row);
        let candidate = EvictCandidate {
            extent: ExtentId::new(r.text()?),
            safety_bytes: r.num()?,
            cache_bytes: r.num()?,
            seq: r.num()?,
            pinned: r.num::<i64>()? != 0,
        };
        let read: Option<i64> = r.opt_num()?;
        let evidence = r.opt_text()?;
        let plan_rev: u32 = r.num()?;
        let state = r.text()?;
        let loss = r.num::<i64>()? != 0;
        // Where a later step reads this row again: past the row before
        // it, or from the head for a row without a read stamp.
        let resume = match read {
            None => EvictCursor::Start,
            Some(_) => last.clone().unwrap_or_else(|| cursor.clone()),
        };
        // A row without a read stamp sorts first; the next window starts
        // at the stamped rows (only a legacy row has none).
        last = Some(EvictCursor::After(
            read.unwrap_or(i64::MIN),
            match read {
                Some(_) => candidate.extent.as_str().to_owned(),
                None => String::new(),
            },
        ));
        // A deleted extent's copies are no longer in service: they go.
        let may = candidate.pinned
            || state == "deleted"
            || releasable_now(evidence.as_deref(), plan_rev, loss, rule);
        if !may {
            if state == "released" && !loss {
                out.unproven.push(crate::types::EvictKept {
                    row: candidate.clone(),
                    resume: resume.clone(),
                });
            }
            continue;
        }
        out.rows.push(candidate);
        if out.rows.len() as u64 >= u64::from(take) {
            // Stopped inside the window: the rest of it is next.
            out.more = true;
            break;
        }
    }
    if out.more {
        out.next = last.unwrap_or(EvictCursor::Start);
    }
    Ok(out)
}

/// The last-copy rule: an extent's last R2 copy may go only while it is
/// releasable under the backbones that count now, by the release rule
/// over its stored evidence, and, with the scrub on, has no loss on
/// record there.
fn releasable_now(evidence: Option<&str>, plan_rev: u32, loss: bool, rule: &EvictRule) -> bool {
    !loss
        && crate::verify::evidence_releasable(
            evidence,
            plan_rev,
            &rule.counting,
            rule.required,
            rule.mode,
        )
}

/// The extents of `generation`: for each, whether its last R2 copy may go
/// now under `rule`, as the window decides it (never while pinned; a
/// deleted extent's always), and its ciphertext.
pub(super) async fn evict_generation<S: Sql>(
    c: &SqlCatalog<S>,
    generation: &crate::types::GenerationId,
    rule: &EvictRule,
) -> Result<Vec<(ExtentId, bool, crate::types::ExtentCipher)>> {
    let mut params = vec![text(generation.as_str())];
    let sql = if rule.scrub {
        params.push(labels(&rule.counting)?);
        c.sql
            .dialect()
            .pick(EVICT_GENERATION_SCRUB, EVICT_GENERATION_SCRUB_PG)
    } else {
        EVICT_GENERATION
    };
    let rows = c.sql.query(sql, &params).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        let extent = ExtentId::new(r.text()?);
        let pinned = r.num::<i64>()? != 0;
        let evidence = r.opt_text()?;
        let plan_rev: u32 = r.num()?;
        let state = r.text()?;
        let loss = r.num::<i64>()? != 0;
        let may = !pinned
            && (state == "deleted" || releasable_now(evidence.as_deref(), plan_rev, loss, rule));
        let cipher = cipher_cols(&mut r)?;
        out.push((extent, may, cipher));
    }
    Ok(out)
}

fn cipher_cols(r: &mut Cols) -> Result<crate::types::ExtentCipher> {
    let bucket = crate::types::BucketId::new(r.text()?);
    let size: u64 = r.num()?;
    let sha256: [u8; 32] = r.blob()?.try_into().map_err(|_| {
        crate::types::BridgeError::Sql("extent cipher_sha256 is not 32 bytes".into())
    })?;
    Ok(crate::types::ExtentCipher {
        bucket,
        size,
        sha256,
        released: false,
    })
}

/// The extent's ciphertext as recorded ([`EXTENT_CIPHER`]).
pub(super) async fn extent_cipher<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
) -> Result<Option<crate::types::ExtentCipher>> {
    let Some(row) = c
        .sql
        .query(EXTENT_CIPHER, &[text(extent.as_str())])
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let mut r = Cols::new(row);
    let mut cipher = cipher_cols(&mut r)?;
    cipher.released = r.text()? == "released";
    Ok(Some(cipher))
}

/// Eviction wrote the verified cache fill of a kept extent to the safety
/// store: counted if the row is as listed ([`EVICT_PROMOTED`]).
pub(super) async fn evict_promoted<S: Sql>(c: &SqlCatalog<S>, x: &EvictCandidate) -> Result<bool> {
    let changed = c
        .sql
        .exec(EVICT_PROMOTED, &[text(x.extent.as_str()), int(x.seq)?])
        .await?;
    Ok(changed == 1)
}

/// The sequence moves before the scrub deletes a safety object
/// ([`SAFETY_FENCE`]).
pub(super) async fn scrub_safety_fence<S: Sql>(c: &SqlCatalog<S>, extent: &ExtentId) -> Result<()> {
    c.sql.exec(SAFETY_FENCE, &[text(extent.as_str())]).await?;
    Ok(())
}

/// Gives each of `extents` (released, kept by eviction for want of a
/// release) a scrub deadline of `at` unless it has one ([`WATCH_SOON`]).
pub(super) async fn scrub_watch_soon<S: Sql>(
    c: &SqlCatalog<S>,
    extents: &[ExtentId],
    at: UnixMs,
) -> Result<()> {
    for extent in extents {
        c.sql
            .exec(WATCH_SOON, &[text(extent.as_str()), ms(at)])
            .await?;
    }
    Ok(())
}

/// A released extent's safety object is gone: no longer counted
/// ([`SAFETY_GONE`]).
pub(super) async fn scrub_safety_gone<S: Sql>(c: &SqlCatalog<S>, extent: &ExtentId) -> Result<()> {
    c.sql.exec(SAFETY_GONE, &[text(extent.as_str())]).await?;
    Ok(())
}

pub(super) async fn evict_cursor<S: Sql>(c: &SqlCatalog<S>) -> Result<EvictCursor> {
    let rows = c.sql.query(EVICT_CURSOR, &[]).await?;
    Ok(match rows.into_iter().next() {
        Some(row) => EvictCursor::parse(&Cols::new(row).text()?),
        None => EvictCursor::Start,
    })
}

pub(super) async fn set_evict_cursor<S: Sql>(
    c: &SqlCatalog<S>,
    cursor: &EvictCursor,
) -> Result<()> {
    c.sql
        .exec(
            c.sql.dialect().pick(SET_EVICT_CURSOR, SET_EVICT_CURSOR_PG),
            &[text(&cursor.encode())],
        )
        .await?;
    Ok(())
}

/// Starts an eviction: `true` only if the extent is exactly as `x`
/// describes it. One statement, so the check and the claim cannot be
/// separated.
///
/// - `x.pinned == false` claims both copies and requires that the safety
///   copy is not pinned now.
/// - `x.pinned == true` claims the cache fill only and requires a counted
///   one. The caller must not touch the safety copy.
pub(super) async fn begin_evict<S: Sql>(c: &SqlCatalog<S>, x: &EvictCandidate) -> Result<bool> {
    let sql = if x.pinned {
        BEGIN_EVICT_PINNED
    } else {
        BEGIN_EVICT_UNPINNED
    };
    let changed = c
        .sql
        .exec(
            sql,
            &[
                text(x.extent.as_str()),
                int(x.seq)?,
                int(x.safety_bytes)?,
                int(x.cache_bytes)?,
            ],
        )
        .await?;
    Ok(changed == 1)
}

/// No row: the sequence moved. `0`: pinned (or, with `SCRUB` on, a loss
/// on record), so nothing goes. `1`: the copies go.
const EVICT_SAFETY_STILL_OK: &str = concat!(
    "SELECT CASE WHEN ",
    pinned!(),
    " THEN 0 ELSE 1 END FROM extents WHERE id = ?1 AND evict_seq = ?2"
);
/// With `SCRUB` on: and no loss of the extent on a counting backbone is
/// on the scrub's record (`?3`, as for `CANDIDATES_SCRUB`). Only with it
/// on, so that eviction does not need the scrub's tables before they are
/// applied.
const EVICT_SAFETY_STILL_OK_SCRUB: &str = concat!(
    "SELECT CASE WHEN ",
    pinned!(),
    " OR ",
    scrub_loss_on_record!("?1", "value FROM json_each(?3)"),
    " THEN 0 ELSE 1 END FROM extents WHERE id = ?1 AND evict_seq = ?2"
);
const EVICT_SAFETY_STILL_OK_SCRUB_PG: &str = concat!(
    "SELECT CASE WHEN ",
    pinned!(),
    " OR ",
    scrub_loss_on_record!("?1", "jsonb_array_elements_text(CAST(?3 AS jsonb))"),
    " THEN 0 ELSE 1 END FROM extents WHERE id = ?1 AND evict_seq = ?2"
);

fn labels(backbones: &[String]) -> Result<SqlValue> {
    serde_json::to_string(backbones)
        .map(SqlValue::Text)
        .map_err(|_| crate::types::BridgeError::Invalid("backbone labels"))
}

/// Whether the safety copy of an eviction that `begin_evict` started may
/// still go: the extent is not pinned, nothing moved its sequence since
/// the begin (a re-pin by the scrub moves it), and, with `scrub` (the
/// backbones that count now), the scrub has no loss of it on record
/// there.
///
/// The last condition is the fence against a re-pin made after this
/// check: the scrub re-pins only a loss whose record is older than two
/// queue invocations (`scrub::REPIN_MIN_LOSS_AGE_MS`), so an eviction
/// that passed this check without seeing that record deleted within its
/// invocation, before the re-pin, and the re-pin then finds the copy
/// gone and writes it again. One that sees the record keeps the copy.
pub(super) async fn evict_safety_still_ok<S: Sql>(
    c: &SqlCatalog<S>,
    x: &EvictCandidate,
    scrub: Option<&[String]>,
) -> Result<crate::types::EvictCheck> {
    use crate::types::EvictCheck;
    let mut params = vec![text(x.extent.as_str()), int(x.seq.saturating_add(1))?];
    let sql = match scrub {
        Some(backbones) => {
            params.push(labels(backbones)?);
            c.sql
                .dialect()
                .pick(EVICT_SAFETY_STILL_OK_SCRUB, EVICT_SAFETY_STILL_OK_SCRUB_PG)
        }
        None => EVICT_SAFETY_STILL_OK,
    };
    let rows = c.sql.query(sql, &params).await?;
    match rows.into_iter().next() {
        Some(row) => Ok(match Cols::new(row).num::<i64>()? {
            1 => EvictCheck::Delete,
            _ => EvictCheck::Keep,
        }),
        None => Ok(EvictCheck::Moved),
    }
}

/// Ends an eviction after the blobs are deleted: the claimed copies are
/// no longer counted. `false` when a hot copy was recorded since
/// `begin_evict`; the counts then stand.
pub(super) async fn finish_evict<S: Sql>(c: &SqlCatalog<S>, x: &EvictCandidate) -> Result<bool> {
    let sql = if x.pinned {
        FINISH_EVICT_PINNED
    } else {
        FINISH_EVICT_UNPINNED
    };
    let changed = c
        .sql
        .exec(
            sql,
            &[text(x.extent.as_str()), int(x.seq.saturating_add(1))?],
        )
        .await?;
    Ok(changed == 1)
}

/// Counts the extent's cache fill and stamps the read that caused it.
/// Called before the write (so that a request cancelled right after the
/// write leaves a counted blob) and again after it (so that an eviction
/// that ran in between does not leave it uncounted).
pub(super) async fn record_cache_fill<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    now: UnixMs,
) -> Result<()> {
    c.sql
        .exec(RECORD_CACHE_FILL, &[text(extent.as_str()), ms(now)])
        .await?;
    Ok(())
}

/// Stamps a read, unless the last stamp is less than `min_gap_ms` old.
/// Returns the stamp the extent has afterwards, so the caller knows when
/// the next write is due without asking again.
///
/// With `from_cache` the read was served from the cache fill, so one
/// exists: the same write counts it if it was not counted, and an
/// uncounted one is counted whatever the age of the stamp.
pub(super) async fn touch_read<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    now: UnixMs,
    min_gap_ms: i64,
    from_cache: bool,
) -> Result<UnixMs> {
    let changed = c
        .sql
        .exec(
            TOUCH_READ,
            &[
                text(extent.as_str()),
                ms(now),
                SqlValue::Int(now.0.saturating_sub(min_gap_ms)),
                SqlValue::Int(i64::from(from_cache)),
            ],
        )
        .await?;
    if changed == 1 {
        return Ok(now);
    }
    let rows = c.sql.query(LAST_READ_AT, &[text(extent.as_str())]).await?;
    let stored = match rows.into_iter().next() {
        Some(row) => Cols::new(row).opt_num()?.map(UnixMs),
        None => None,
    };
    Ok(stored.unwrap_or(now))
}

/// Whether the dispatcher's periodic total is due: none was taken in the
/// last `every_ms`.
pub(super) async fn hot_check_due<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    every_ms: i64,
) -> Result<bool> {
    let rows = c
        .sql
        .query(
            RECENT_SWEEP,
            &[SqlValue::Int(now.0.saturating_sub(every_ms)), ms(now)],
        )
        .await?;
    Ok(rows.is_empty())
}

/// Records that the periodic total was taken at `now`.
pub(super) async fn hot_checked<S: Sql>(c: &SqlCatalog<S>, now: UnixMs) -> Result<()> {
    c.sql
        .exec(
            c.sql.dialect().pick(RECORD_HOT_SWEEP, RECORD_HOT_SWEEP_PG),
            &[ms(now)],
        )
        .await?;
    Ok(())
}

/// Records what a drain step leaves for the next one.
pub(super) async fn hot_drain_set<S: Sql>(c: &SqlCatalog<S>, left: u64) -> Result<()> {
    c.sql
        .exec(
            c.sql.dialect().pick(SET_HOT_DRAIN, SET_HOT_DRAIN_PG),
            &[int(left)?],
        )
        .await?;
    Ok(())
}

/// Takes up the drain where the last step left it. One statement, so
/// only one delivery of the job that carries `left` gets `true`.
pub(super) async fn hot_drain_claim<S: Sql>(c: &SqlCatalog<S>, left: u64) -> Result<bool> {
    if left == 0 {
        return Ok(false);
    }
    let changed = c.sql.exec(CLEAR_DRAIN, &[int(left)?]).await?;
    Ok(changed == 1)
}

/// The extent's fencing token now (0 for an unknown extent). Read it
/// before deleting blobs outside an eviction, then pass it to `hot_forget`.
pub(super) async fn hot_seq<S: Sql>(c: &SqlCatalog<S>, extent: &ExtentId) -> Result<u64> {
    let rows = c.sql.query(EVICTION_SEQ, &[text(extent.as_str())]).await?;
    match rows.into_iter().next() {
        Some(row) => Cols::new(row).num(),
        None => Ok(0),
    }
}

/// Blobs were deleted outside an eviction (admin evict): stop counting
/// them, and fence any eviction in flight. `seq` is `hot_seq` from before
/// the deletes: if a cold read recorded a fill (or an eviction ran) since
/// then, the counts stand, because the copy they count may exist. `false`
/// then.
pub(super) async fn hot_forget<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    seq: u64,
    safety: bool,
    cache: bool,
) -> Result<bool> {
    let changed = c
        .sql
        .exec(
            CLEAR_HOT_IF_SEQ,
            &[
                text(extent.as_str()),
                SqlValue::Int(i64::from(safety)),
                SqlValue::Int(i64::from(cache)),
                int(seq)?,
            ],
        )
        .await?;
    Ok(changed == 1)
}

const CANDIDATES_PG: &str = concat!(
    "SELECT id, hot_safety_bytes, hot_cache_bytes, evict_seq, ",
    pinned!(),
    " FROM extents WHERE ",
    evictable!(),
    " ORDER BY last_read_at ASC NULLS FIRST, id LIMIT ?1"
);

const BEGIN_EVICT_PINNED: &str = concat!(
    "UPDATE extents SET evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND evict_seq = ?2 \
               AND hot_safety_bytes = ?3 AND hot_cache_bytes = ?4 \
               AND hot_cache_bytes > 0 AND ",
    pinned!()
);

const BEGIN_EVICT_UNPINNED: &str = concat!(
    "UPDATE extents SET evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND evict_seq = ?2 \
               AND hot_safety_bytes = ?3 AND hot_cache_bytes = ?4 \
               AND NOT ",
    pinned!(),
    " AND ",
    evictable!()
);

const FINISH_EVICT_PINNED: &str =
    "UPDATE extents SET hot_cache_bytes = 0, evict_seq = evict_seq + 1 \
         WHERE id = ?1 AND evict_seq = ?2";

const FINISH_EVICT_UNPINNED: &str =
    "UPDATE extents SET hot_safety_bytes = 0, hot_cache_bytes = 0, \
           evict_seq = evict_seq + 1 \
         WHERE id = ?1 AND evict_seq = ?2";

const RECORD_CACHE_FILL: &str =
    "UPDATE extents SET hot_cache_bytes = cipher_size, last_read_at = ?2, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1";

const TOUCH_READ: &str = "UPDATE extents SET last_read_at = ?2, \
               evict_seq = evict_seq + \
                 CASE WHEN ?4 = 1 AND hot_cache_bytes = 0 THEN 1 ELSE 0 END, \
               hot_cache_bytes = CASE WHEN ?4 = 1 THEN cipher_size ELSE hot_cache_bytes END \
             WHERE id = ?1 AND (last_read_at IS NULL OR last_read_at <= ?3 \
                                OR (?4 = 1 AND hot_cache_bytes = 0))";

const LAST_READ_AT: &str = "SELECT last_read_at FROM extents WHERE id = ?1";

const RECENT_SWEEP: &str = "SELECT 1 FROM meta WHERE k = 'hot_checked_at' AND v > ?1 AND v <= ?2";

const CLEAR_DRAIN: &str = "UPDATE meta SET v = 0 WHERE k = 'hot_drain_left' AND v = ?1";

const EVICTION_SEQ: &str = "SELECT evict_seq FROM extents WHERE id = ?1";

const CLEAR_HOT_IF_SEQ: &str = "UPDATE extents SET \
               hot_safety_bytes = CASE WHEN ?2 = 1 THEN 0 ELSE hot_safety_bytes END, \
               hot_cache_bytes = CASE WHEN ?3 = 1 THEN 0 ELSE hot_cache_bytes END, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND evict_seq = ?4";

const RECORD_HOT_SWEEP: &str = "INSERT OR REPLACE INTO meta(k, v) VALUES ('hot_checked_at', ?1)";

const RECORD_HOT_SWEEP_PG: &str = "INSERT INTO meta(k, v) VALUES ('hot_checked_at', ?1) ON CONFLICT (k) DO UPDATE SET v = excluded.v";

const SET_HOT_DRAIN: &str = "INSERT OR REPLACE INTO meta(k, v) VALUES ('hot_drain_left', ?1)";

const SET_HOT_DRAIN_PG: &str = "INSERT INTO meta(k, v) VALUES ('hot_drain_left', ?1) ON CONFLICT (k) DO UPDATE SET v = excluded.v";

/// Actual Postgres texts and representative wire types for typed PREPARE.
#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(String, Vec<SqlValue>)> {
    const I: SqlValue = SqlValue::Int(0);
    const T: SqlValue = SqlValue::Text(String::new());
    vec![
        (EVICTABLE_TOTAL.to_owned(), vec![]),
        (PINNED_TOTAL.to_owned(), vec![]),
        (CANDIDATES_PG.to_owned(), vec![I]),
        (BEGIN_EVICT_PINNED.to_owned(), vec![T, I, I, I]),
        (BEGIN_EVICT_UNPINNED.to_owned(), vec![T, I, I, I]),
        (EVICT_SAFETY_STILL_OK.to_owned(), vec![T, I]),
        (EVICT_SAFETY_STILL_OK_SCRUB_PG.to_owned(), vec![T, I, T]),
        (EVICT_WINDOW_PG.to_owned(), vec![I]),
        (EVICT_WINDOW_AFTER_PG.to_owned(), vec![I, I, T]),
        (EVICT_WINDOW_SCRUB_PG.to_owned(), vec![I, T]),
        (EVICT_WINDOW_SCRUB_AFTER_PG.to_owned(), vec![I, I, T, T]),
        (WATCH_SOON.to_owned(), vec![T, I]),
        (SAFETY_GONE.to_owned(), vec![T]),
        (SAFETY_FENCE.to_owned(), vec![T]),
        (EXTENT_CIPHER.to_owned(), vec![T]),
        (EVICT_PROMOTED.to_owned(), vec![T, I]),
        (EVICT_GENERATION.to_owned(), vec![T]),
        (EVICT_GENERATION_SCRUB_PG.to_owned(), vec![T, T]),
        (EVICT_CURSOR.to_owned(), vec![]),
        (SET_EVICT_CURSOR_PG.to_owned(), vec![T]),
        (FINISH_EVICT_PINNED.to_owned(), vec![T, I]),
        (FINISH_EVICT_UNPINNED.to_owned(), vec![T, I]),
        (RECORD_CACHE_FILL.to_owned(), vec![T, I]),
        (TOUCH_READ.to_owned(), vec![T, I, I, I]),
        (LAST_READ_AT.to_owned(), vec![T]),
        (RECENT_SWEEP.to_owned(), vec![I, I]),
        (CLEAR_DRAIN.to_owned(), vec![I]),
        (EVICTION_SEQ.to_owned(), vec![T]),
        (CLEAR_HOT_IF_SEQ.to_owned(), vec![T, I, I, I]),
        (RECORD_HOT_SWEEP_PG.to_owned(), vec![I]),
        (SET_HOT_DRAIN_PG.to_owned(), vec![I]),
    ]
}
