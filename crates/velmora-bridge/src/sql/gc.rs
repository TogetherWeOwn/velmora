//! Garbage-collection rows (catalogue lane B).
//!
//! GC rows are only ever queued for extents that left service: a replaced,
//! unlisted or aborted upload part, or an extent of a retired generation
//! that no other live generation references. `gc_begin` still re-checks
//! that at execution time and refuses to act on an extent any live
//! generation or an open upload references. An extent that left service
//! cannot come back while requests and jobs run: a copy is only published
//! from a generation that is live in the same batch. A restore replay can
//! bring one back (a copy's record sorts after the record that retired
//! its source); nothing collects while a restore runs, and afterwards the
//! re-check here refuses the rows the replay left open.
//!
//! # Orphaned upload parts (`GC_ORPHANS`)
//!
//! A second, narrower collector takes only the safety copies of upload
//! parts that left their upload and were never part of an object. It
//! runs in every bucket, whatever `GC_MODE` says, so its rule is stated
//! here in full. The safety copy of an extent may go when all of these
//! hold in one batch of the catalogue ([`gc_orphan_claim`]):
//!
//! 1. an open `delete_safety` row names the extent. Only three writes
//!    queue one for an extent that is still `staged`: a part that was
//!    uploaded again under the same number, an abort, and a completion
//!    that left the part out of its list. Each queues it in the batch
//!    that takes the part out of the upload, dated with that moment;
//! 2. that moment is at least `ORPHAN_GRACE_MS` ago;
//! 3. the extent is `staged` and has no generation: it was never
//!    adopted, so no object was ever made of it;
//! 4. no `generation_extents` row names it, of a live generation or any
//!    other: no object and no server-side copy reads it or ever did;
//! 5. no part of an open upload names it (`upload_parts`,
//!    `upload_part_extents`): an upload in progress keeps every part it
//!    lists, however old;
//! 6. no replay is under way and no rollback is waiting for one;
//! 7. no recovery record that a replay could make the live object of
//!    its key names it. A CompleteMultipartUpload stores its record,
//!    which names every part it was given, before its batch runs. When
//!    the batch does not run and the record could not be removed, the
//!    record stays, the upload stays open, and the same parts can then
//!    be aborted or uploaded again. The catalogue marks the key of
//!    every record it may not have published (`key_floors.unpublished`,
//!    raised before the record is stored), and only an acknowledged
//!    write or delete of the key takes the mark away. While the key of
//!    the part's upload carries it, the part stays: a replay would
//!    publish that record, and its object must read. Without it every
//!    record of the key lies under an acknowledged one, and a replay,
//!    which folds the records of a key in id order, never leaves such
//!    a record live.
//!
//! Once 1 and 3 to 5 hold they keep holding while requests and jobs
//! run, which is why the scan may read them first and the claim later.
//! An extent id is minted from random bytes for one stored part and is
//! never issued again; a part enters `upload_parts` only in the batch
//! that inserts its extent; CompleteMultipartUpload adopts only extents
//! its open upload lists at the revision it validated; a copy
//! references only extents of a live generation; UploadPartCopy stores
//! new extents. A replay is the exception (it inserts `staged` extents
//! without a `gc` row before it publishes them, and closes the open
//! rows of every extent it publishes), and 1 and 6 keep the collector
//! away from it. A catalogue taken back to before the part was dropped
//! is the other one, and 2 is for that.
//!
//! 7 is decided by the claim alone. Only a completion of the part's own
//! upload stores a record that names it, and only one that read the
//! part list before the part was dropped. Such a request raises the
//! mark and stores its record within the life of one request, which
//! `ORPHAN_GRACE_MS` exceeds many times over: by the time 2 holds, every
//! record that names the part is stored and its mark is set or was
//! taken away by an acknowledged record above it.
//!
//! What the mark does not cover: a record stored before the catalogue
//! had `key_floors` (migration 0007). Such a record names only parts
//! that were stored before it was, so the switch may be turned on in a
//! catalogue whose `staged` extents were all created after that
//! migration was applied (the ops notes give the query).

// The rule above in SQL, for the extent id expression `$x`: 3, 4 and 5.
// `deleted` is the state the claim itself wrote: a row whose blob
// delete then failed is claimed again and the delete repeated.
macro_rules! orphan {
    ($x:literal) => {
        concat!(
            "(EXISTS (SELECT 1 FROM extents oe WHERE oe.id = ",
            $x,
            " AND oe.state = 'staged' AND oe.generation_id IS NULL \
               AND oe.safety_state IN ('held', 'deleted')) \
             AND NOT EXISTS (SELECT 1 FROM generation_extents og WHERE og.extent_id = ",
            $x,
            ") AND NOT ",
            part_ref!($x),
            ")"
        )
    };
}

// Point 7 of the rule for an extent whose upload is known, for the
// extent id expression `$x`. The first extent of a part that an abort
// or a completion dropped is still named by its `upload_parts` row,
// which is never deleted: the key is that upload's, and the check is
// one row of `key_floors`.
macro_rules! no_stale_record_of_upload {
    ($x:literal) => {
        concat!(
            "NOT EXISTS (SELECT 1 FROM upload_parts sp \
               JOIN uploads su ON su.id = sp.upload_id \
               JOIN key_floors sf ON sf.bucket_id = su.bucket_id AND sf.key = su.key \
               WHERE sp.extent_id = ",
            $x,
            " AND sf.unpublished <> 0)"
        )
    };
}

// Point 7 for the extents whose upload is not known. A part that was
// uploaded again lost its `upload_parts` row to its successor, and the
// further extents of a sliced part lost theirs when the part was
// dropped. For those every key an upload of the bucket (`?1`) was ever
// made on must be free of the mark. `uploads` has no index that serves
// this and no row of it is ever deleted, so the statement reads every
// upload of the catalogue: it is a guard of its own, run once for all
// the claims of a batch and never once per extent.
const GUARD_NO_STALE_RECORD_IN_BUCKET: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS \
       (SELECT 1 FROM uploads su WHERE su.bucket_id = ?1 AND EXISTS \
          (SELECT 1 FROM key_floors sf WHERE sf.bucket_id = su.bucket_id \
              AND sf.key = su.key AND sf.unpublished <> 0))";

// One claim: points 1 to 5 and the first half of 7 for the row `?2` of
// the extent `?1`, due at or before `?3`, and the record that the copy
// is gone. It changes one row or none, and the count is the answer.
// `deleted` is written again over itself for that reason: a claim that
// is repeated after its blob delete failed must read as granted. The
// repeat bumps the eviction fence again, which only refuses an eviction
// listing taken before it.
macro_rules! claim {
    ($upload:literal) => {
        concat!(
            "UPDATE extents SET safety_state = 'deleted', hot_safety_bytes = 0, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND EXISTS \
               (SELECT 1 FROM gc WHERE id = ?2 AND extent_id = ?1 \
                  AND action = 'delete_safety' AND done_at IS NULL AND due_at <= ?3) AND ",
            orphan!("?1"),
            " AND ",
            no_stale_record_of_upload!("?1"),
            " AND ",
            $upload
        )
    };
}

// The upload of the extent is known: its `upload_parts` row is there,
// and the key that row leads to is the only one a record that names
// the extent can be of.
const CLAIM_OF_UPLOAD: &str =
    claim!("EXISTS (SELECT 1 FROM upload_parts kp WHERE kp.extent_id = ?1)");

// It is not known: the claim holds only in a batch that carries
// `GUARD_NO_STALE_RECORD_IN_BUCKET` for the bucket `?4`, which must be
// the extent's own.
const CLAIM_IN_BUCKET: &str = claim!("extents.bucket_id = ?4");

use super::replay::guard_no_replay;
use super::uploads::{guarded, ms, text, Cols, Stmt};
use super::SqlCatalog;
use crate::ports::{Guard, Sql, SqlValue, MAX_SQL_INT};
use crate::types::{BlobStoreKind, BridgeError, ExtentId, GcAction, GcRow, GcStep, Result, UnixMs};
use std::collections::BTreeMap;

/// A refused row is looked at again after this long, so it cannot keep
/// newer work out of the bounded `gc_due` window.
const SKIP_RETRY_MS: i64 = 60 * 60 * 1000;

/// After a pass over every due row, the scan for orphaned parts starts
/// the next one this much later. A part waits `ORPHAN_GRACE_MS` before
/// it may go, so an hour more changes nothing, and a catalogue with
/// nothing to collect costs one row read per dispatcher run in between.
const ORPHAN_REST_MS: i64 = 60 * 60 * 1000;

/// True while the extent `?1` must not be touched: a live generation
/// references it (its own, or a copy), or an open upload does.
macro_rules! in_use {
    () => {
        concat!(
            "(EXISTS (SELECT 1 FROM extents e JOIN generations g ON g.id = e.generation_id \
                      WHERE e.id = ?1 AND g.state = 'live') OR ",
            live_ref!("?1"),
            " OR ",
            part_ref!("?1"),
            ")"
        )
    };
}

/// True while `?2` is an open row for exactly this extent (`?1`) and
/// action (`?3`): the caller's copy of the row is not trusted.
macro_rules! open_row {
    () => {
        "EXISTS (SELECT 1 FROM gc WHERE id = ?2 AND extent_id = ?1 AND action = ?3 \
                 AND done_at IS NULL)"
    };
}

/// Open rows that are due, oldest first. With `disposable_only`, only rows
/// whose extent belongs to a bucket flagged `disposable`.
pub(super) async fn gc_due<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    limit: u32,
    disposable_only: bool,
) -> Result<Vec<GcRow>> {
    let rows = c
        .sql
        .query(
            "SELECT gc.id, gc.extent_id, gc.action, gc.due_at FROM gc \
             WHERE gc.done_at IS NULL AND gc.due_at <= ?1 \
               AND (?2 = 0 OR EXISTS (SELECT 1 FROM extents e JOIN buckets b ON b.id = e.bucket_id \
                    WHERE e.id = gc.extent_id AND b.disposable = 1)) \
             ORDER BY gc.due_at, gc.id LIMIT ?3",
            &[
                ms(now),
                SqlValue::Int(i64::from(disposable_only)),
                SqlValue::Int(i64::from(limit)),
            ],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(GcRow {
            id: r.num()?,
            extent_id: ExtentId::new(r.text()?),
            action: r.parsed(GcAction::parse)?,
            due_at: UnixMs(r.num()?),
            done_at: None,
        });
    }
    Ok(out)
}

/// Decides one row. Blob actions are returned to the caller, who deletes
/// the blob and then calls `gc_done`. Catalogue-only actions are applied
/// and closed here, in one batch guarded by the in-use check.
pub(super) async fn gc_begin<S: Sql>(
    c: &SqlCatalog<S>,
    row: &GcRow,
    now: UnixMs,
) -> Result<GcStep> {
    let ident = || {
        vec![
            text(row.extent_id.as_str()),
            SqlValue::Int(row.id),
            text(row.action.as_str()),
        ]
    };
    let close: Stmt = (
        "UPDATE gc SET done_at = ?2 WHERE id = ?1 AND done_at IS NULL",
        vec![SqlValue::Int(row.id), ms(now)],
    );
    let free = match row.action {
        GcAction::DeleteCache | GcAction::DeleteSafety => {
            let rows = c
                .sql
                .query(
                    concat!("SELECT ", open_row!(), " AND NOT ", in_use!()),
                    &ident(),
                )
                .await?;
            let free = match rows.into_iter().next() {
                Some(r) => Cols::new(r).num::<i64>()? != 0,
                None => false,
            };
            if free && row.action == GcAction::DeleteCache {
                // The cache fill stops being counted before its blob is
                // deleted, never after: a cold read that fills the cache
                // while this delete runs records its copy after this
                // statement, so the copy stays counted. It is this order
                // that protects the fill, not the sequence. (A count left
                // for a blob that the delete then removed is corrected by
                // the next eviction.) The sequence is bumped only so that
                // every change to the counts ends outstanding listings.
                c.sql
                    .exec(
                        "UPDATE extents SET hot_cache_bytes = 0, evict_seq = evict_seq + 1 \
                         WHERE id = ?1 AND hot_cache_bytes > 0",
                        &[text(row.extent_id.as_str())],
                    )
                    .await?;
            }
            free
        }
        GcAction::ShredKey | GcAction::DropArticlesMeta => {
            let apply = if row.action == GcAction::ShredKey {
                "UPDATE extents SET wrapped_file_key = NULL WHERE id = ?1"
            } else {
                "DELETE FROM articles WHERE extent_id = ?1"
            };
            let stmts = vec![
                (
                    concat!(
                        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ",
                        open_row!(),
                        " OR ",
                        in_use!()
                    ),
                    ident(),
                ),
                (apply, vec![text(row.extent_id.as_str())]),
                // The article metadata of a packed plan is the plan, and
                // the parity addendum beside it.
                (
                    "UPDATE extents SET plan = NULL, parity = NULL, parity_count = NULL \
                     WHERE id = ?1 AND ?2 = 'drop_articles_meta'",
                    vec![text(row.extent_id.as_str()), text(row.action.as_str())],
                ),
                close,
            ];
            if guarded(c, stmts).await? == Guard::Applied(()) {
                return Ok(GcStep::Done);
            }
            false
        }
    };
    if !free {
        c.sql
            .exec(
                "UPDATE gc SET due_at = ?4 WHERE id = ?2 AND extent_id = ?1 AND action = ?3 \
                   AND done_at IS NULL",
                &[ident(), vec![ms(now.plus_ms(SKIP_RETRY_MS))]].concat(),
            )
            .await?;
        return Ok(GcStep::Skipped);
    }
    Ok(match row.action {
        GcAction::DeleteCache => GcStep::DeleteBlob {
            store: BlobStoreKind::Cache,
            key: row.extent_id.cache_key(),
        },
        _ => GcStep::DeleteBlob {
            store: BlobStoreKind::Safety,
            key: row.extent_id.safety_key(),
        },
    })
}

/// Closes a blob row after its delete; a safety delete also records that
/// the extent no longer has a safety copy and ends the hot-tier count of
/// it. (The count of a cache fill ended in `gc_begin`, before the delete.)
pub(super) async fn gc_done<S: Sql>(c: &SqlCatalog<S>, id: i64, now: UnixMs) -> Result<()> {
    c.sql
        .batch(vec![
            (
                "UPDATE extents SET safety_state = 'deleted', hot_safety_bytes = 0, \
                   evict_seq = evict_seq + 1 \
                 WHERE id = (SELECT extent_id FROM gc \
                 WHERE id = ?1 AND action = 'delete_safety' AND done_at IS NULL)",
                vec![SqlValue::Int(id)],
            ),
            (
                "UPDATE gc SET done_at = ?2 WHERE id = ?1 AND done_at IS NULL",
                vec![SqlValue::Int(id), ms(now)],
            ),
        ])
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Orphaned upload parts
// ---------------------------------------------------------------------------

/// Where the scan for orphaned parts is (`scan_cursors`, key `orphans`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrphanCursor {
    /// The last open row read: `(due_at, id)`.
    At(i64, i64),
    /// A pass ended; the next one starts at this time.
    Rest(i64),
}

impl OrphanCursor {
    /// Before every row: the lowest `due_at` the database takes as a
    /// bound value ([`MAX_SQL_INT`]), so no row can be due earlier.
    const START: OrphanCursor = OrphanCursor::At(-MAX_SQL_INT, 0);

    /// A value this code did not write reads as the start: the scan
    /// decides nothing, so reading rows again costs only the reads. So
    /// does a number the database would refuse as a bound value.
    fn parse(v: &str) -> OrphanCursor {
        let num = |s: &str| {
            s.parse::<i64>()
                .ok()
                .filter(|n| (-MAX_SQL_INT..=MAX_SQL_INT).contains(n))
        };
        let parsed = match v.split(':').collect::<Vec<_>>().as_slice() {
            ["at", due, id] => num(due).zip(num(id)).map(|(d, i)| OrphanCursor::At(d, i)),
            ["rest", until] => num(until).map(OrphanCursor::Rest),
            _ => None,
        };
        parsed.unwrap_or(OrphanCursor::START)
    }

    fn encode(self) -> String {
        match self {
            OrphanCursor::At(due, id) => format!("at:{due}:{id}"),
            OrphanCursor::Rest(until) => format!("rest:{until}"),
        }
    }
}

async fn orphan_cursor<S: Sql>(c: &SqlCatalog<S>) -> Result<OrphanCursor> {
    let rows = c
        .sql
        .query("SELECT v FROM scan_cursors WHERE k = 'orphans'", &[])
        .await?;
    Ok(match rows.into_iter().next() {
        Some(row) => OrphanCursor::parse(&Cols::new(row).text()?),
        None => OrphanCursor::START,
    })
}

pub(super) async fn gc_orphans_due<S: Sql>(c: &SqlCatalog<S>, now: UnixMs) -> Result<bool> {
    Ok(!matches!(orphan_cursor(c).await?, OrphanCursor::Rest(until) if until > now.0))
}

/// One window of the scan. The open rows are read in `(due_at, id)`
/// order from where the last window ended, `scan` of them at most, so a
/// run costs the same however many rows are open: the rows of deleted
/// objects, which this collector never takes, are stepped over a window
/// at a time and not read whole in search of a part. The scan is moved
/// past what it returns before the caller acts on it: a row whose blob
/// delete fails is met again by the next pass.
pub(super) async fn gc_orphans<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    cutoff: UnixMs,
    scan: u32,
    limit: u32,
) -> Result<Vec<GcRow>> {
    let (due, id) = match orphan_cursor(c).await? {
        OrphanCursor::Rest(until) if until > now.0 => return Ok(Vec::new()),
        OrphanCursor::Rest(_) => (-MAX_SQL_INT, 0),
        OrphanCursor::At(due, id) => (due, id),
    };
    // Two ranges of the index of open rows: the rest of the rows due at
    // the same millisecond as the last one read (one abort queues a row
    // for every part at once), then the rows due later.
    let rows = c
        .sql
        .query(
            concat!(
                "SELECT w.id, w.extent_id, w.due_at, \
                   (w.action = 'delete_safety' AND ",
                orphan!("w.extent_id"),
                ") FROM (SELECT id, extent_id, action, due_at FROM \
                   (SELECT id, extent_id, action, due_at FROM gc \
                     WHERE done_at IS NULL AND due_at = ?2 AND id > ?3 AND due_at <= ?1 \
                     ORDER BY id LIMIT ?4) \
                  UNION ALL SELECT id, extent_id, action, due_at FROM \
                   (SELECT id, extent_id, action, due_at FROM gc \
                     WHERE done_at IS NULL AND due_at > ?2 AND due_at <= ?1 \
                     ORDER BY due_at, id LIMIT ?4) \
                  ORDER BY due_at, id LIMIT ?4) w \
                 ORDER BY w.due_at, w.id"
            ),
            &[
                ms(cutoff),
                SqlValue::Int(due),
                SqlValue::Int(id),
                SqlValue::Int(i64::from(scan)),
            ],
        )
        .await?;
    let read = rows.len();
    let mut out = Vec::new();
    let mut next = OrphanCursor::Rest(now.plus_ms(ORPHAN_REST_MS).0);
    for (i, row) in rows.into_iter().enumerate() {
        let mut r = Cols::new(row);
        let row = GcRow {
            id: r.num()?,
            extent_id: ExtentId::new(r.text()?),
            action: GcAction::DeleteSafety,
            due_at: UnixMs(r.num()?),
            done_at: None,
        };
        let orphan = r.num::<i64>()? != 0;
        let at = OrphanCursor::At(row.due_at.0, row.id);
        if orphan {
            out.push(row);
        }
        // The pass goes on from here unless this was the last due row.
        let full = out.len() >= limit as usize;
        if read >= scan as usize || (full && i + 1 < read) {
            next = at;
        }
        if full {
            break;
        }
    }
    c.sql
        .exec(
            "INSERT INTO scan_cursors(k, v) VALUES ('orphans', ?1) \
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            &[text(&next.encode())],
        )
        .await?;
    Ok(out)
}

/// The decision, for the rows of one window; the answers are in the
/// order of `rows`. Each batch proves the whole rule of the module doc
/// for every row it grants and records that the copy is gone; `false` =
/// refused, and nothing was written for that row. The caller's copy of
/// a row is not trusted: the id, the extent and the action must be those
/// of one open row.
///
/// The rows are claimed in groups, so that what a claim costs does not
/// grow with the number of rows: the extents whose upload is known in
/// one batch, and the others in one batch per bucket, behind the one
/// statement that reads the uploads (`GUARD_NO_STALE_RECORD_IN_BUCKET`).
/// The read that sorts them is a hint and proves nothing. An extent
/// never gains an `upload_parts` row after the batch that inserted it;
/// one that lost its row since the read is refused here and sorted
/// right by the next pass.
pub(super) async fn gc_orphan_claim<S: Sql>(
    c: &SqlCatalog<S>,
    rows: &[GcRow],
    cutoff: UnixMs,
) -> Result<Vec<bool>> {
    let mut granted = vec![false; rows.len()];
    if rows.is_empty() {
        return Ok(granted);
    }
    let ids: Vec<&str> = rows.iter().map(|r| r.extent_id.as_str()).collect();
    let ids = serde_json::to_string(&ids)
        .map_err(|_| BridgeError::Sql("gc_orphan_claim: encode".into()))?;
    let found = c
        .sql
        .query(
            "SELECT e.id, e.bucket_id, \
               EXISTS (SELECT 1 FROM upload_parts kp WHERE kp.extent_id = e.id) \
             FROM extents e WHERE e.id IN (SELECT value FROM json_each(?1))",
            &[text(&ids)],
        )
        .await?;
    // Extent id -> its bucket, or `None` when its upload is known.
    let mut hint: BTreeMap<String, Option<String>> = BTreeMap::new();
    for row in found {
        let mut r = Cols::new(row);
        let (id, bucket, known) = (r.text()?, r.text()?, r.num::<i64>()? != 0);
        hint.insert(id, (!known).then_some(bucket));
    }
    // `None`: the group of the known uploads. An extent that does not
    // exist is in no group and stays refused.
    let mut groups: BTreeMap<Option<&str>, Vec<usize>> = BTreeMap::new();
    for (i, row) in rows.iter().enumerate() {
        if let Some(bucket) = hint.get(row.extent_id.as_str()) {
            groups.entry(bucket.as_deref()).or_default().push(i);
        }
    }
    for (bucket, members) in groups {
        let mut stmts: Vec<Stmt> = vec![guard_no_replay()];
        if let Some(bucket) = bucket {
            stmts.push((GUARD_NO_STALE_RECORD_IN_BUCKET, vec![text(bucket)]));
        }
        let guards = stmts.len();
        // The catalogue says the copy is gone before it goes, never
        // after: from this batch on nothing is told that a pinned copy
        // exists. The row stays open until the delete is known to have
        // happened, so a delete that failed is repeated.
        for i in &members {
            let row = &rows[*i];
            let mut params = vec![
                text(row.extent_id.as_str()),
                SqlValue::Int(row.id),
                ms(cutoff),
            ];
            stmts.push(match bucket {
                None => (CLAIM_OF_UPLOAD, params),
                Some(bucket) => {
                    params.push(text(bucket));
                    (CLAIM_IN_BUCKET, params)
                }
            });
        }
        let changed = match c.sql.batch(stmts).await {
            Ok(changed) => changed,
            // A replay or a rollback, or a marked key in the bucket:
            // the batch wrote nothing and every row of it is refused.
            Err(BridgeError::GuardFailed) => continue,
            Err(e) => return Err(e),
        };
        for (i, n) in members.iter().zip(changed.iter().skip(guards)) {
            granted[*i] = *n != 0;
        }
    }
    Ok(granted)
}

/// Closes the row of a part whose safety copy is deleted.
pub(super) async fn gc_orphan_done<S: Sql>(c: &SqlCatalog<S>, id: i64, now: UnixMs) -> Result<()> {
    c.sql
        .exec(
            "UPDATE gc SET done_at = ?2 WHERE id = ?1 AND action = 'delete_safety' \
               AND done_at IS NULL",
            &[SqlValue::Int(id), ms(now)],
        )
        .await?;
    Ok(())
}
