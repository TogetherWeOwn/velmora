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
//! 6. no replay is under way, no rollback is waiting for one, and no
//!    replay ended less than `ORPHAN_GRACE_MS` ago (below);
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
//!    a record live. Where the catalogue no longer knows the upload of
//!    the part, no key of its bucket that an upload was ever begun on
//!    may carry the mark (below).
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
//! For a part whose upload is not known, the marks of the bucket are
//! not read by the claim itself. Reading them is a read of every row of
//! `uploads`, so it is done once for a bucket and its answer is kept
//! for `ORPHAN_VERDICT_MS` (a row of `scan_cursors`, written by the
//! statement that reads them). The claim proves in its own batch that
//! the bucket was found free of marks no longer ago than that. This is
//! as good as reading them in the batch: the answer is at most a day
//! old, so it was given 30 days or more after the part was dropped,
//! and the marks that matter to the part were all raised within one
//! request of its drop, so they were there to be found, or were
//! already taken away for good. A mark
//! raised after the answer was written is of a record that was stored
//! then, from a part list the part had long left.
//!
//! # After a replay
//!
//! 2 is enough on one history of the database: no state it can be taken
//! back to (30 days, D1 Time Travel) lists a part that was dropped 31
//! days ago. A restore that is undone later leaves a second history:
//! the states between the restore and its undoing can be returned to
//! for 30 days more, and they are states of before the restore point,
//! in which a part dropped just after it is listed by its upload. So a
//! claim is also refused until `ORPHAN_GRACE_MS` after the last replay
//! ended (`restore_state.finished_at`): a catalogue that was taken back
//! takes no write and collects nothing before a replay has run to its
//! end, the replay ends after the restore it follows, and 31 days after
//! it every state of a history that was left before it is out of reach.
//!
//! What this cannot see: a restore that was undone before a replay ended
//! on it, or after one did and before the rollback stamp was next raised
//! (a cron run, minutes). The catalogue that is brought back holds no
//! trace of the history that was left, and no stamp is ahead of it, so
//! nothing tells it that it was away. Nor can it see a restore that was
//! never replayed where the stamp did not show it: a mark of point 7
//! raised after the restore point is gone with it, while its record
//! stays. The ops notes keep the rules for these cases (a replay after
//! every restore; the switch off for 31 days after any restore).
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
// dropped. For those every key an upload of the bucket (`?2`) was ever
// made on must be free of the mark. `uploads` has no index that serves
// this and no row of it is ever deleted, so the statement reads every
// upload of the catalogue. It is therefore not part of a claim: it
// writes what it found, with the time (`?3` when a key is marked, `?4`
// when none is), to the row `?1` of `scan_cursors`, and the claims of
// the next `ORPHAN_VERDICT_MS` are made behind that row. Jobs that run
// at the same moment on an old answer each ask once.
const BUCKET_VERDICT: &str = "INSERT INTO scan_cursors(k, v) VALUES (?1, CASE WHEN EXISTS \
       (SELECT 1 FROM uploads su WHERE su.bucket_id = ?2 AND EXISTS \
          (SELECT 1 FROM key_floors sf WHERE sf.bucket_id = su.bucket_id \
              AND sf.key = su.key AND sf.unpublished <> 0)) THEN ?3 ELSE ?4 END) \
     ON CONFLICT(k) DO UPDATE SET v = excluded.v";

// The claims of such extents hold only behind this: the row `?1` says
// that the bucket was found free of marks, later than `?2`.
const GUARD_BUCKET_FOUND_CLEAN: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS \
       (SELECT 1 FROM scan_cursors WHERE k = ?1 AND v GLOB 'clean:[0-9]*' \
          AND CAST(substr(v, 7) AS INTEGER) > ?2)";

// Point 6, its last part: no replay ended after `?1`. A row that says
// `complete` without the time it ended is read by the time it began.
const GUARD_NO_REPLAY_SINCE: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS \
       (SELECT 1 FROM restore_state WHERE id = 1 AND COALESCE(finished_at, started_at) > ?1)";

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
// `GUARD_BUCKET_FOUND_CLEAN` for the bucket `?4`, which must be the
// extent's own.
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
/// it may go, so a day more changes nothing, and a catalogue with
/// nothing to collect costs one row read per dispatcher run in between.
/// A pass reads every open row that is old enough, also the rows of
/// deleted objects, which stay open for good while `GC_MODE` is off:
/// once a day bounds what those cost.
const ORPHAN_REST_MS: i64 = 24 * 60 * 60 * 1000;

/// How long the answer of `BUCKET_VERDICT` is used: the uploads of a
/// bucket are read once in this time, however many jobs claim parts of
/// it, and a bucket with a marked key is asked again only after it.
/// It must stay far below `ORPHAN_GRACE_MS` less the life of a request
/// (module doc, point 7).
const ORPHAN_VERDICT_MS: i64 = 24 * 60 * 60 * 1000;

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

const ENQUEUE_SCRUB_SAFETY: &str = concat!(
    "INSERT INTO gc(extent_id, action, due_at) \
     SELECT e.id, 'delete_safety', ?2 FROM extents e \
     JOIN buckets b ON b.id = e.bucket_id \
     WHERE e.id = ?1 AND e.generation_id IS NOT NULL \
       AND b.disposable = 1 AND NOT ",
    in_use!()
);

/// The old row may already have deleted its blob, even if it is still
/// open. Insert a new row with its own ID so completing the old delete
/// cannot close this one. `gc_begin` rechecks the references at execution.
pub(super) async fn gc_enqueue_scrub_safety<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    now: UnixMs,
) -> Result<()> {
    let params = [text(extent.as_str()), ms(now)];
    // Scrub will not visit a retired extent again. Retry once on error;
    // if the first insert committed but lost its reply, both rows are
    // safe to run: each rechecks references before an idempotent delete.
    if c.sql.exec(ENQUEUE_SCRUB_SAFETY, &params).await.is_err() {
        c.sql.exec(ENQUEUE_SCRUB_SAFETY, &params).await?;
    }
    Ok(())
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
            GC_DUE,
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
    let close: Stmt = (MARK_KEY_GC_DONE, vec![SqlValue::Int(row.id), ms(now)]);
    let free = match row.action {
        GcAction::DeleteCache | GcAction::DeleteSafety => {
            let rows = c.sql.query(GC_OPEN_QUERY, &ident()).await?;
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
                    .exec(CLEAR_DELETED_CACHE, &[text(row.extent_id.as_str())])
                    .await?;
            }
            free
        }
        GcAction::ShredKey | GcAction::DropArticlesMeta => {
            let apply = if row.action == GcAction::ShredKey {
                SHRED_KEY
            } else {
                DROP_ARTICLES
            };
            let stmts = vec![
                (GUARD_GC_OPEN, ident()),
                (apply, vec![text(row.extent_id.as_str())]),
                // The article metadata of a packed plan is the plan, and
                // the parity addendum beside it.
                (
                    DROP_PLAN,
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
                DEFER_GC,
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
            (DELETE_GC_SAFETY, vec![SqlValue::Int(id)]),
            (MARK_SAFETY_GC_DONE, vec![SqlValue::Int(id), ms(now)]),
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
    let rows = c.sql.query(GC_ORPHAN_CURSOR, &[]).await?;
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
            c.sql.dialect().pick(GC_ORPHAN_WINDOW, GC_ORPHAN_WINDOW_PG),
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
        .exec(SET_GC_ORPHAN_CURSOR, &[text(&next.encode())])
        .await?;
    Ok(out)
}

/// What `BUCKET_VERDICT` last wrote for a bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// No key an upload was begun on carried the mark at this time.
    Clean(i64),
    /// One did.
    Marked(i64),
}

impl Verdict {
    /// The row of the bucket in `scan_cursors`.
    fn key(bucket: &str) -> String {
        format!("orphans:bucket:{bucket}")
    }

    /// A value this code did not write reads as no answer: the bucket
    /// is asked again.
    fn parse(v: &str) -> Option<Verdict> {
        let (what, at) = v.split_once(':')?;
        let at = at.parse::<i64>().ok()?;
        match what {
            "clean" => Some(Verdict::Clean(at)),
            "marked" => Some(Verdict::Marked(at)),
            _ => None,
        }
    }

    fn encode(self) -> String {
        match self {
            Verdict::Clean(at) => format!("clean:{at}"),
            Verdict::Marked(at) => format!("marked:{at}"),
        }
    }
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
/// one batch, and the others in one batch per bucket, behind the answer
/// of the one statement that reads the uploads (`BUCKET_VERDICT`),
/// which runs when the bucket has no answer younger than
/// `ORPHAN_VERDICT_MS`. A bucket whose answer of that age is that a key
/// is marked costs nothing more: its rows are refused unread.
/// The read that sorts the rows is a hint and proves nothing. An extent
/// never gains an `upload_parts` row after the batch that inserted it;
/// one that lost its row since the read is refused here and sorted
/// right by the next pass.
///
/// An error ends the claims of its group only: the other groups are
/// still decided, so that a bucket whose batch keeps failing does not
/// hold up the buckets after it. Every answer stands, and what they
/// grant is recorded: the caller deletes those copies whatever the
/// second value says, which is the first error met.
pub(super) async fn gc_orphan_claim<S: Sql>(
    c: &SqlCatalog<S>,
    rows: &[GcRow],
    now: UnixMs,
    cutoff: UnixMs,
) -> (Vec<bool>, Result<()>) {
    let mut granted = vec![false; rows.len()];
    let claimed = orphan_claims(c, rows, now, cutoff, &mut granted).await;
    (granted, claimed)
}

async fn orphan_claims<S: Sql>(
    c: &SqlCatalog<S>,
    rows: &[GcRow],
    now: UnixMs,
    cutoff: UnixMs,
    granted: &mut [bool],
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let ids: Vec<&str> = rows.iter().map(|r| r.extent_id.as_str()).collect();
    let ids = serde_json::to_string(&ids)
        .map_err(|_| BridgeError::Sql("gc_orphan_claim: encode".into()))?;
    let found = c
        .sql
        .query(
            c.sql
                .dialect()
                .pick(ORPHAN_CLAIM_INPUTS, ORPHAN_CLAIM_INPUTS_PG),
            &[text(&ids)],
        )
        .await?;
    // Extent id -> its bucket, or `None` when its upload is known.
    let mut hint: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut verdicts: BTreeMap<String, Verdict> = BTreeMap::new();
    for row in found {
        let mut r = Cols::new(row);
        let (id, bucket, known) = (r.text()?, r.text()?, r.num::<i64>()? != 0);
        if let Some(verdict) = r.opt_text()?.as_deref().and_then(Verdict::parse) {
            verdicts.insert(bucket.clone(), verdict);
        }
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
    // An answer about a bucket counts when it is younger than this,
    // and not from a time that is still to come (a clock that was set
    // back): such a one is asked for again.
    let fresh = now.plus_ms(-ORPHAN_VERDICT_MS).0;
    let young = |at: i64| fresh < at && at <= now.0;
    // Point 6, in every batch.
    let replay_guards = || vec![guard_no_replay(), (GUARD_NO_REPLAY_SINCE, vec![ms(cutoff)])];
    let mut failed: Option<BridgeError> = None;
    for (bucket, members) in groups {
        let mut stmts: Vec<Stmt> = replay_guards();
        if let Some(bucket) = bucket {
            let row = Verdict::key(bucket);
            match verdicts.get(bucket) {
                // Asked within the day, and a key was marked: refused,
                // at the cost of nothing.
                Some(Verdict::Marked(at)) if young(*at) => continue,
                Some(Verdict::Clean(at)) if young(*at) => {}
                // The uploads are read, once, and the answer is kept.
                // What it is, the batch below finds out for itself.
                _ => {
                    let mut ask = replay_guards();
                    ask.push((
                        BUCKET_VERDICT,
                        vec![
                            text(&row),
                            text(bucket),
                            text(&Verdict::Marked(now.0).encode()),
                            text(&Verdict::Clean(now.0).encode()),
                        ],
                    ));
                    match c.sql.batch(ask).await {
                        Ok(_) => {}
                        Err(BridgeError::GuardFailed) => continue,
                        Err(e) => {
                            failed.get_or_insert(e);
                            continue;
                        }
                    }
                }
            }
            stmts.push((
                c.sql
                    .dialect()
                    .pick(GUARD_BUCKET_FOUND_CLEAN, GUARD_BUCKET_FOUND_CLEAN_PG),
                vec![text(&row), SqlValue::Int(fresh)],
            ));
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
            // A replay, a rollback, or a replay that ended too short a
            // time ago; or a marked key in the bucket: the batch wrote
            // nothing and every row of it is refused.
            Err(BridgeError::GuardFailed) => continue,
            // This group is refused; the next one is still decided.
            Err(e) => {
                failed.get_or_insert(e);
                continue;
            }
        };
        for (i, n) in members.iter().zip(changed.iter().skip(guards)) {
            granted[*i] = *n != 0;
        }
    }
    failed.map_or(Ok(()), Err)
}

/// Closes the row of a part whose safety copy is deleted.
///
/// Only where the catalogue says so. One that was taken back to before
/// the claim says `held` again: the row stays open there, and a later
/// pass claims it once more, which sets the state and the usage right.
pub(super) async fn gc_orphan_done<S: Sql>(c: &SqlCatalog<S>, id: i64, now: UnixMs) -> Result<()> {
    c.sql
        .exec(MARK_ORPHAN_DONE, &[SqlValue::Int(id), ms(now)])
        .await?;
    Ok(())
}

// Match SQLite's integer cast: take the decimal prefix, discard leading
// zeroes before the overflow check, and saturate positive overflow.
const GUARD_BUCKET_FOUND_CLEAN_PG: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS \
       (SELECT 1 FROM scan_cursors \
          CROSS JOIN LATERAL (SELECT ltrim(substring(v from '^clean:([0-9]+)'), '0') AS digits) d \
          WHERE k = ?1 AND v ~ '^clean:[0-9]' AND CASE \
            WHEN d.digits = '' THEN 0 \
            WHEN length(d.digits) > 19 OR (length(d.digits) = 19 \
              AND d.digits COLLATE \"C\" > '9223372036854775807') THEN 9223372036854775807 \
            ELSE d.digits::bigint END > ?2)";

const GC_DUE: &str = "SELECT gc.id, gc.extent_id, gc.action, gc.due_at FROM gc \
             WHERE gc.done_at IS NULL AND gc.due_at <= ?1 \
               AND (?2 = 0 OR EXISTS (SELECT 1 FROM extents e JOIN buckets b ON b.id = e.bucket_id \
                    WHERE e.id = gc.extent_id AND b.disposable = 1)) \
             ORDER BY gc.due_at, gc.id LIMIT ?3";

const MARK_KEY_GC_DONE: &str = "UPDATE gc SET done_at = ?2 WHERE id = ?1 AND done_at IS NULL";

const GC_OPEN_QUERY: &str = concat!("SELECT ", open_row!(), " AND NOT ", in_use!());

const CLEAR_DELETED_CACHE: &str =
    "UPDATE extents SET hot_cache_bytes = 0, evict_seq = evict_seq + 1 \
                         WHERE id = ?1 AND hot_cache_bytes > 0";

const SHRED_KEY: &str = "UPDATE extents SET wrapped_file_key = NULL WHERE id = ?1";

const DROP_ARTICLES: &str = "DELETE FROM articles WHERE extent_id = ?1";

const GUARD_GC_OPEN: &str = concat!(
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ",
    open_row!(),
    " OR ",
    in_use!()
);

const DROP_PLAN: &str = "UPDATE extents SET plan = NULL, parity = NULL, parity_count = NULL \
                     WHERE id = ?1 AND ?2 = 'drop_articles_meta'";

const DEFER_GC: &str =
    "UPDATE gc SET due_at = ?4 WHERE id = ?2 AND extent_id = ?1 AND action = ?3 \
                   AND done_at IS NULL";

const DELETE_GC_SAFETY: &str =
    "UPDATE extents SET safety_state = 'deleted', hot_safety_bytes = 0, \
                   evict_seq = evict_seq + 1 \
                 WHERE id = (SELECT extent_id FROM gc \
                 WHERE id = ?1 AND action = 'delete_safety' AND done_at IS NULL)";

const MARK_SAFETY_GC_DONE: &str = "UPDATE gc SET done_at = ?2 WHERE id = ?1 AND done_at IS NULL";

const GC_ORPHAN_CURSOR: &str = "SELECT v FROM scan_cursors WHERE k = 'orphans'";

macro_rules! gc_orphan_window {
    ($orphan:expr) => {
        concat!(
            "SELECT w.id, w.extent_id, w.due_at, \
                   (w.action = 'delete_safety' AND ",
            $orphan,
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
        )
    };
}

const GC_ORPHAN_WINDOW: &str = gc_orphan_window!(orphan!("w.extent_id"));

// Projected EXISTS checks can become hashed subplans over every reference
// in the catalogue. Scalar, correlated one-row probes only consult the
// current candidate. The claim batch still rechecks the original guards.
pub(super) const GC_ORPHAN_WINDOW_PG: &str = gc_orphan_window!(
    "((SELECT 1 FROM extents oe WHERE oe.id = w.extent_id \
      AND oe.state = 'staged' AND oe.generation_id IS NULL \
      AND oe.safety_state IN ('held', 'deleted')) IS NOT NULL \
      AND (SELECT 1 FROM generation_extents og WHERE og.extent_id = w.extent_id LIMIT 1) IS NULL \
      AND (SELECT 1 FROM upload_parts pr JOIN uploads pu ON pu.id = pr.upload_id \
           WHERE pr.extent_id = w.extent_id AND pu.state = 'open' LIMIT 1) IS NULL \
      AND (SELECT 1 FROM upload_part_extents px JOIN uploads pu ON pu.id = px.upload_id \
           WHERE px.extent_id = w.extent_id AND pu.state = 'open' LIMIT 1) IS NULL)"
);

const SET_GC_ORPHAN_CURSOR: &str = "INSERT INTO scan_cursors(k, v) VALUES ('orphans', ?1) \
             ON CONFLICT(k) DO UPDATE SET v = excluded.v";

const MARK_ORPHAN_DONE: &str =
    "UPDATE gc SET done_at = ?2 WHERE id = ?1 AND action = 'delete_safety' \
               AND done_at IS NULL AND EXISTS \
               (SELECT 1 FROM extents de WHERE de.id = gc.extent_id \
                  AND de.safety_state = 'deleted')";

const ORPHAN_CLAIM_INPUTS: &str = "SELECT e.id, e.bucket_id, \
               EXISTS (SELECT 1 FROM upload_parts kp WHERE kp.extent_id = e.id), \
               (SELECT v FROM scan_cursors WHERE k = 'orphans:bucket:' || e.bucket_id) \
             FROM extents e WHERE e.id IN (SELECT value FROM json_each(?1))";

const ORPHAN_CLAIM_INPUTS_PG: &str = "SELECT e.id, e.bucket_id, \
               EXISTS (SELECT 1 FROM upload_parts kp WHERE kp.extent_id = e.id), \
               (SELECT v FROM scan_cursors WHERE k = 'orphans:bucket:' || e.bucket_id) \
             FROM extents e WHERE e.id IN (SELECT value FROM jsonb_array_elements_text(?1::jsonb) AS j(value))";

/// Actual Postgres texts and representative wire types for typed PREPARE.
#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(String, Vec<SqlValue>)> {
    const I: SqlValue = SqlValue::Int(0);
    const T: SqlValue = SqlValue::Text(String::new());
    vec![
        (BUCKET_VERDICT.to_owned(), vec![T, T, T, T]),
        (GUARD_NO_REPLAY_SINCE.to_owned(), vec![I]),
        (CLAIM_OF_UPLOAD.to_owned(), vec![T, I, I]),
        (CLAIM_IN_BUCKET.to_owned(), vec![T, I, I, T]),
        (GUARD_BUCKET_FOUND_CLEAN_PG.to_owned(), vec![T, I]),
        (GC_DUE.to_owned(), vec![I, I, I]),
        (ENQUEUE_SCRUB_SAFETY.to_owned(), vec![T, I]),
        (MARK_KEY_GC_DONE.to_owned(), vec![I, I]),
        (GC_OPEN_QUERY.to_owned(), vec![T, I, T]),
        (CLEAR_DELETED_CACHE.to_owned(), vec![T]),
        (SHRED_KEY.to_owned(), vec![T]),
        (DROP_ARTICLES.to_owned(), vec![T]),
        (GUARD_GC_OPEN.to_owned(), vec![T, I, T]),
        (DROP_PLAN.to_owned(), vec![T, T]),
        (DEFER_GC.to_owned(), vec![T, I, T, I]),
        (DELETE_GC_SAFETY.to_owned(), vec![I]),
        (MARK_SAFETY_GC_DONE.to_owned(), vec![I, I]),
        (GC_ORPHAN_CURSOR.to_owned(), vec![]),
        (GC_ORPHAN_WINDOW_PG.to_owned(), vec![I, I, I, I]),
        (SET_GC_ORPHAN_CURSOR.to_owned(), vec![T]),
        (MARK_ORPHAN_DONE.to_owned(), vec![I, I]),
        (ORPHAN_CLAIM_INPUTS_PG.to_owned(), vec![T]),
    ]
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::GUARD_BUCKET_FOUND_CLEAN;
    use rusqlite::{params, Connection};

    #[test]
    fn bucket_verdict_uses_strict_saturating_decimal_prefix() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE scan_cursors (k TEXT PRIMARY KEY, v TEXT NOT NULL);\
             CREATE TABLE tx_guard (ok INTEGER NOT NULL CHECK (ok = 1));",
        )
        .unwrap();
        for (value, cutoff, allowed) in verdict_cases() {
            db.execute(
                "INSERT OR REPLACE INTO scan_cursors VALUES ('bucket', ?1)",
                [value],
            )
            .unwrap();
            let result = db.execute(GUARD_BUCKET_FOUND_CLEAN, params!["bucket", cutoff]);
            if allowed {
                assert_eq!(result.unwrap(), 0, "{value} at {cutoff}");
            } else {
                assert_eq!(
                    result.unwrap_err().sqlite_error_code(),
                    Some(rusqlite::ErrorCode::ConstraintViolation),
                    "{value} at {cutoff}"
                );
            }
        }
    }

    fn verdict_cases() -> impl Iterator<Item = (&'static str, i64, bool)> {
        [
            ("clean:123", Some(123)),
            ("clean:123x", Some(123)),
            ("clean:", None),
            ("clean:0000000000000000001", Some(1)),
            ("clean:00000000000000000001", Some(1)),
            ("clean:000000000000000000000123", Some(123)),
            (
                "clean:00000000000000000000009223372036854775807",
                Some(i64::MAX),
            ),
            ("clean:9223372036854775808", Some(i64::MAX)),
            ("clean:99999999999999999999", Some(i64::MAX)),
            ("dirty", None),
            ("clean:0", Some(0)),
            ("clean:-5", None),
            ("clean: 5", None),
            ("clean:+5", None),
            ("clean:12.9", Some(12)),
            ("clean:1e5", Some(1)),
            ("CLEAN:5", None),
            ("clean:١", None),
            ("clean:0000x", Some(0)),
        ]
        .into_iter()
        .flat_map(|(value, parsed)| {
            [-1, 0, 1, 11, 122, 123, i64::MAX - 1, i64::MAX]
                .into_iter()
                .map(move |cutoff| (value, cutoff, parsed.is_some_and(|time| time > cutoff)))
        })
    }

    #[cfg(all(feature = "pg-test-record", feature = "testkit-pg"))]
    #[tokio::test]
    async fn postgres_bucket_verdict_matches_sqlite_cases() {
        use crate::gate::pg_background_fixture as pg;
        let Some(mut db) = pg::connect().await else {
            return;
        };
        let mut tx = pg::transaction(&mut db).await;
        let guard = pg::sql(super::GUARD_BUCKET_FOUND_CLEAN_PG);
        for (value, cutoff, allowed) in verdict_cases() {
            let case = tx.transaction().await.unwrap();
            case.execute("INSERT INTO scan_cursors VALUES ('bucket', $1)", &[&value])
                .await
                .unwrap();
            let result = case.execute(&guard, &[&"bucket", &cutoff]).await;
            if allowed {
                assert_eq!(result.unwrap(), 0, "{value} at {cutoff}");
            } else {
                let Err(error) = result else {
                    panic!("{value} at {cutoff} should be refused");
                };
                assert_eq!(
                    error.as_db_error().and_then(|e| e.constraint()),
                    Some("tx_guard_ok"),
                    "{value} at {cutoff}: {error:?}"
                );
            }
            case.rollback().await.unwrap();
        }
        tx.rollback().await.unwrap();
    }
}
