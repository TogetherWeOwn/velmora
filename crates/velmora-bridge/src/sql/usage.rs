//! Usage counters: what the status page and the dashboard read instead
//! of scanning `extents`, `outbox` and `generations`.
//!
//! The counters are moved by triggers (migration 0020), in the statement
//! that changes the row they count: no code path here or elsewhere has
//! to remember them, and a batch that rolls back takes its counter
//! changes with it.
//!
//! What this module adds is the recount. It walks the three tables in
//! id order, a bounded chunk per statement, and adds each chunk to row 2
//! of `usage_global` in the same statement that moves the cursor past
//! it. The triggers keep the part behind the cursor current, so when the
//! last chunk is counted row 2 is exact at that instant, however long
//! the walk took and whatever was written meanwhile.
//!
//! - The first recount switches the counters on: row 2 is copied to
//!   row 1 (the backfill).
//! - Every later one compares the rows and records the difference in
//!   `usage_recounts`. It replaces row 1 only when asked to (`adopt`):
//!   a difference is a bug to look at, not something to paper over.
//!
//! All of its state is in the catalogue, so a recount goes on from
//! where it stopped, whoever runs the next step.

use super::uploads::{ms, text, Cols, Stmt};
use super::SqlCatalog;
use crate::ports::{Sql, SqlValue};
use crate::types::{
    BucketUsage, RecountState, RecountStep, Result, UnixMs, UsageCounters, UsageHour, UsageRecount,
    UsageSnapshot,
};

/// Rows one recount statement counts when the caller names no figure.
pub const RECOUNT_CHUNK: u32 = 2_000;
/// Most rows one recount statement counts. A row is read twice, once in
/// the primary-key index and once in the table: 8,000 rows read.
pub const RECOUNT_CHUNK_MAX: u32 = 4_000;

/// The live counters, in the order [`counters`] reads them.
pub const COUNTERS: &str = "SELECT all_x AND all_o AND all_g, \
       x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted, \
       ob_post, ob_verify, ob_release, ob_done, ob_cancelled, ob_dead, \
       posts_total, verifies_total, releases_total, dead_total, failures_total, \
       hour, h_posts, h_verifies, h_releases, h_dead, h_failures \
  FROM usage_global WHERE id = 1";

pub(super) async fn counters<S: Sql>(c: &SqlCatalog<S>) -> Result<UsageCounters> {
    let rows = c
        .sql
        .query(c.sql.dialect().pick(COUNTERS, COUNTERS_PG), &[])
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(UsageCounters::default());
    };
    let mut r = Cols::new(row);
    Ok(UsageCounters {
        seeded: r.num::<i64>()? != 0,
        extents_unreleased: r.num()?,
        unreleased_bytes: r.num()?,
        extents_released: r.num()?,
        released_bytes: r.num()?,
        extents_deleted: r.num()?,
        outbox_post: r.num()?,
        outbox_verify: r.num()?,
        outbox_release: r.num()?,
        outbox_done: r.num()?,
        outbox_cancelled: r.num()?,
        outbox_dead: r.num()?,
        posts_total: r.num()?,
        verifies_total: r.num()?,
        releases_total: r.num()?,
        dead_total: r.num()?,
        failures_total: r.num()?,
        current: hour(&mut r)?,
    })
}

fn hour(r: &mut Cols) -> Result<UsageHour> {
    Ok(UsageHour {
        hour: r.num()?,
        posts: r.num()?,
        verifies: r.num()?,
        releases: r.num()?,
        dead: r.num()?,
        failures: r.num()?,
    })
}

async fn recount_state<S: Sql>(c: &SqlCatalog<S>) -> Result<RecountState> {
    let rows = c.sql.query(SELECT_RECOUNT_STATE, &[]).await?;
    let idle = RecountState {
        running: false,
        started_at: UnixMs(0),
        rows_seen: 0,
        table: "",
        adopt: false,
    };
    let Some(row) = rows.into_iter().next() else {
        return Ok(idle);
    };
    let mut r = Cols::new(row);
    if r.num::<i64>()? == 0 {
        return Ok(idle);
    }
    let started_at = UnixMs(r.num()?);
    let rows_seen = r.num()?;
    let done = [r.num::<i64>()?, r.num::<i64>()?, r.num::<i64>()?];
    let table = match done {
        [0, ..] => "extents",
        [_, 0, _] => "outbox",
        [_, _, 0] => "generations",
        _ => "finish",
    };
    Ok(RecountState {
        running: true,
        started_at,
        rows_seen,
        table,
        adopt: r.num::<i64>()? != 0,
    })
}

async fn last_recount<S: Sql>(c: &SqlCatalog<S>) -> Result<Option<UsageRecount>> {
    recount_record(c, None).await
}

/// The last recount, or with `started_at` the last one that began then:
/// the record of one pass, whatever has ended since.
async fn recount_record<S: Sql>(
    c: &SqlCatalog<S>,
    started_at: Option<UnixMs>,
) -> Result<Option<UsageRecount>> {
    let rows = c
        .sql
        .query(
            c.sql.dialect().pick(RECOUNT_RECORD, RECOUNT_RECORD_PG),
            &[started_at.map_or(SqlValue::Null, ms)],
        )
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let mut r = Cols::new(row);
    Ok(Some(UsageRecount {
        started_at: UnixMs(r.num()?),
        finished_at: UnixMs(r.num()?),
        rows: r.num()?,
        adopted: r.num::<i64>()? != 0,
        drift: r.num()?,
        detail: r.opt_text()?,
    }))
}

/// Each `MIN` is one seek in `outbox_due(stage, next_at)`.
pub const OLDEST: &str = OLDEST_BY_STAGE;

/// One row per bucket with a counted object (a bucket emptied since
/// keeps a row of zeros until a recount is adopted): the bucket count,
/// not the object count, bounds this read.
pub const BUCKET_TOTALS: &str = "SELECT COALESCE(SUM(live_objects), 0), \
   COALESCE(SUM(live_bytes), 0), COUNT(*) FROM usage_buckets WHERE kind = 1";

pub(super) async fn snapshot<S: Sql>(c: &SqlCatalog<S>, hours: u32) -> Result<UsageSnapshot> {
    let mut counters = counters(c).await?;
    // The hour under way, with what is already filed for it: counters
    // switched off and on again within an hour filed its first part.
    // One statement, so no event is in both or in neither.
    let current = c.sql.query(CURRENT_HOUR, &[]).await?;
    counters.current = hour(&mut Cols::new(first(current)?))?;
    let mut totals = Cols::new(first(c.sql.query(BUCKET_TOTALS, &[]).await?)?);
    let (live_objects, live_bytes, buckets_counted) = (totals.num()?, totals.num()?, totals.num()?);
    let mut oldest = Cols::new(first(c.sql.query(OLDEST, &[]).await?)?);
    let mut due = || oldest.opt_num::<i64>().map(|v| v.map(UnixMs));
    let (oldest_post, oldest_verify, oldest_release) = (due()?, due()?, due()?);
    let rows = c
        .sql
        .query(
            PREVIOUS_HOURS,
            // Not the current hour: what is filed for it is in the
            // current figures above, and one filed between the two
            // reads would be there twice.
            &[
                SqlValue::Int(i64::from(hours)),
                SqlValue::Int(counters.current.hour),
            ],
        )
        .await?;
    let mut filed = Vec::with_capacity(rows.len());
    for row in rows {
        filed.push(hour(&mut Cols::new(row))?);
    }
    Ok(UsageSnapshot {
        counters,
        live_objects,
        live_bytes,
        buckets_counted,
        oldest_post,
        oldest_verify,
        oldest_release,
        hours: filed,
        recount: recount_state(c).await?,
        last_recount: last_recount(c).await?,
    })
}

fn first(rows: Vec<crate::ports::Row>) -> Result<crate::ports::Row> {
    rows.into_iter()
        .next()
        .ok_or_else(|| crate::types::BridgeError::Sql("usage: no row".into()))
}

/// Buckets after `after` (a bucket id, or empty), in id order.
pub(super) async fn buckets<S: Sql>(
    c: &SqlCatalog<S>,
    after: &str,
    limit: u32,
) -> Result<(bool, Vec<BucketUsage>)> {
    // One statement, so the page and the answer to "are the counters
    // on" are of the same moment. Its first row is there for an empty
    // page too, with no bucket in it.
    let rows = c
        .sql
        .query(BUCKET_PAGE, &[text(after), SqlValue::Int(i64::from(limit))])
        .await?;
    let mut seeded = false;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        seeded = r.num::<i64>()? != 0;
        let Some(bucket_id) = r.opt_text()? else {
            continue;
        };
        out.push(BucketUsage {
            bucket_id,
            name: r.text()?,
            live_objects: r.num()?,
            live_bytes: r.num()?,
        });
    }
    Ok((seeded, out))
}

// ---------------------------------------------------------------------------
// Recount
// ---------------------------------------------------------------------------

/// Starts a recount. `false` when one is running and `restart` is not
/// set, and with `only_on` when the counters are off: that is checked
/// in the statement that starts it, so a start cannot follow an `off`
/// it did not see. With `adopt` its figures replace the live counters at the end;
/// the first recount does that anyway.
pub(super) async fn recount_start<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    adopt: bool,
    restart: bool,
    only_on: bool,
) -> Result<bool> {
    let restart = SqlValue::Int(i64::from(restart));
    let only_on = SqlValue::Int(i64::from(only_on));
    let changed = c
        .sql
        .batch(vec![
            (
                RECOUNT_CLEAR_OLD_BUCKETS,
                vec![restart.clone(), only_on.clone()],
            ),
            (
                RECOUNT_START,
                vec![restart, ms(now), SqlValue::Int(i64::from(adopt)), only_on],
            ),
        ])
        .await?;
    Ok(changed.get(1).copied().unwrap_or(0) == 1)
}

/// One chunk of `extents`: counted into row 2 and the cursor moved past
/// it, in one statement. A chunk shorter than asked for was the last.
pub const STEP_EXTENTS: &str = "UPDATE usage_global SET \
   x_unreleased = x_unreleased + p.unrel, unreleased_bytes = unreleased_bytes + p.unrel_b, \
   x_released = x_released + p.rel, released_bytes = released_bytes + p.rel_b, \
   x_deleted = x_deleted + p.del, \
   rows_seen = rows_seen + p.n, cur_x = COALESCE(p.last, cur_x), all_x = (p.n < ?1) \
 FROM (SELECT COUNT(*) AS n, MAX(id) AS last, \
         COALESCE(SUM(safety_state IN ('held', 'releasing')), 0) AS unrel, \
         COALESCE(SUM(CASE WHEN safety_state IN ('held', 'releasing') \
                           THEN cipher_size ELSE 0 END), 0) AS unrel_b, \
         COALESCE(SUM(safety_state = 'released'), 0) AS rel, \
         COALESCE(SUM(CASE WHEN safety_state = 'released' \
                           THEN cipher_size ELSE 0 END), 0) AS rel_b, \
         COALESCE(SUM(safety_state = 'deleted'), 0) AS del \
       FROM (SELECT id, safety_state, cipher_size FROM extents \
              WHERE id > (SELECT cur_x FROM usage_global WHERE id = 2) \
              ORDER BY id LIMIT ?1)) AS p \
 WHERE usage_global.id = 2 AND pass = 1 AND all_x = 0";

/// One chunk of `outbox`, as [`STEP_EXTENTS`].
pub const STEP_OUTBOX: &str = "UPDATE usage_global SET \
   ob_post = ob_post + p.post, ob_verify = ob_verify + p.verify, \
   ob_release = ob_release + p.release, ob_done = ob_done + p.done, \
   ob_cancelled = ob_cancelled + p.cancelled, ob_dead = ob_dead + p.dead, \
   rows_seen = rows_seen + p.n, cur_o = COALESCE(p.last, cur_o), all_o = (p.n < ?1) \
 FROM (SELECT COUNT(*) AS n, MAX(extent_id) AS last, \
         COALESCE(SUM(stage = 'post'), 0) AS post, \
         COALESCE(SUM(stage = 'verify'), 0) AS verify, \
         COALESCE(SUM(stage = 'release'), 0) AS release, \
         COALESCE(SUM(stage = 'done'), 0) AS done, \
         COALESCE(SUM(stage = 'cancelled'), 0) AS cancelled, \
         COALESCE(SUM(stage = 'dead'), 0) AS dead \
       FROM (SELECT extent_id, stage FROM outbox \
              WHERE extent_id > (SELECT cur_o FROM usage_global WHERE id = 2) \
              ORDER BY extent_id LIMIT ?1)) AS p \
 WHERE usage_global.id = 2 AND pass = 1 AND all_x = 1 AND all_o = 0";

/// The chunk of `generations` after the cursor. Its two statements run
/// in one batch and read the same chunk: the cursor row is only moved
/// by the second. A recount that is not at this table has no cursor
/// here (`NULL`), and the chunk is empty.
macro_rules! generations_chunk {
    ($cols:literal) => {
        concat!(
            "SELECT ",
            $cols,
            " FROM generations WHERE id > (SELECT cur_g FROM usage_global \
               WHERE id = 2 AND pass = 1 AND all_x = 1 AND all_o = 1 AND all_g = 0) \
             ORDER BY id LIMIT ?1"
        )
    };
}

pub const STEP_GENERATIONS_BUCKETS: &str = concat!(
    "INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes) \
     SELECT 2, bucket_id, COUNT(*), SUM(size) FROM (",
    generations_chunk!("bucket_id, state, size"),
    ") WHERE state = 'live' GROUP BY bucket_id \
     ON CONFLICT (kind, bucket_id) DO UPDATE SET \
       live_objects = live_objects + excluded.live_objects, \
       live_bytes = live_bytes + excluded.live_bytes"
);

pub const STEP_GENERATIONS_CURSOR: &str = concat!(
    "UPDATE usage_global SET rows_seen = rows_seen + p.n, \
       cur_g = COALESCE(p.last, cur_g), all_g = (p.n < ?1) \
     FROM (SELECT COUNT(*) AS n, MAX(id) AS last FROM (",
    generations_chunk!("id"),
    ")) AS p \
     WHERE usage_global.id = 2 AND pass = 1 AND all_x = 1 AND all_o = 1 AND all_g = 0"
);

/// True while row 2 holds a complete count.
macro_rules! counted {
    () => {
        "EXISTS (SELECT 1 FROM usage_global WHERE id = 2 AND pass = 1 \
                   AND all_x = 1 AND all_o = 1 AND all_g = 1)"
    };
}

/// True while row 2 holds a complete count that is to replace row 1:
/// asked for, or row 1 is not switched on yet.
macro_rules! adopting {
    () => {
        "EXISTS (SELECT 1 FROM usage_global s, usage_global l \
                  WHERE s.id = 2 AND l.id = 1 AND s.pass = 1 \
                    AND s.all_x = 1 AND s.all_o = 1 AND s.all_g = 1 \
                    AND (s.adopt = 1 OR l.all_x = 0 OR l.all_o = 0 OR l.all_g = 0))"
    };
}

/// Buckets whose live and counted rows differ. A row of zeros is a
/// bucket without live objects, the same as no row.
macro_rules! bucket_drift {
    () => {
        "(SELECT COUNT(DISTINCT bucket_id) FROM ( \
            SELECT * FROM (SELECT bucket_id, live_objects, live_bytes FROM usage_buckets \
                            WHERE kind = 1 AND (live_objects <> 0 OR live_bytes <> 0) \
                           EXCEPT \
                           SELECT bucket_id, live_objects, live_bytes FROM usage_buckets \
                            WHERE kind = 2 AND (live_objects <> 0 OR live_bytes <> 0)) \
            UNION ALL \
            SELECT * FROM (SELECT bucket_id, live_objects, live_bytes FROM usage_buckets \
                            WHERE kind = 2 AND (live_objects <> 0 OR live_bytes <> 0) \
                           EXCEPT \
                           SELECT bucket_id, live_objects, live_bytes FROM usage_buckets \
                            WHERE kind = 1 AND (live_objects <> 0 OR live_bytes <> 0))))"
    };
}

/// The counters a recount can check, as a JSON object of row `$r`.
macro_rules! levels_json {
    ($r:literal, $ctor:literal) => {
        concat!(
            $ctor,
            "('extents_unreleased', ",
            $r,
            ".x_unreleased, ",
            "'unreleased_bytes', ",
            $r,
            ".unreleased_bytes, ",
            "'extents_released', ",
            $r,
            ".x_released, ",
            "'released_bytes', ",
            $r,
            ".released_bytes, ",
            "'extents_deleted', ",
            $r,
            ".x_deleted, ",
            "'outbox_post', ",
            $r,
            ".ob_post, 'outbox_verify', ",
            $r,
            ".ob_verify, ",
            "'outbox_release', ",
            $r,
            ".ob_release, 'outbox_done', ",
            $r,
            ".ob_done, ",
            "'outbox_cancelled', ",
            $r,
            ".ob_cancelled, 'outbox_dead', ",
            $r,
            ".ob_dead)"
        )
    };
}

/// The record of the recount: nothing to compare when row 1 was not
/// switched on.
const FINISH_RECORD: &str = concat!(
    "INSERT INTO usage_recounts (started_at, finished_at, rows, adopted, drift, detail) \
     SELECT s.started_at, ?1, s.rows_seen, \
            (s.adopt = 1 OR l.all_x = 0 OR l.all_o = 0 OR l.all_g = 0), \
            CASE WHEN l.all_x = 1 AND l.all_o = 1 AND l.all_g = 1 THEN \
              (l.x_unreleased <> s.x_unreleased) + (l.unreleased_bytes <> s.unreleased_bytes) \
              + (l.x_released <> s.x_released) + (l.released_bytes <> s.released_bytes) \
              + (l.x_deleted <> s.x_deleted) + (l.ob_post <> s.ob_post) \
              + (l.ob_verify <> s.ob_verify) + (l.ob_release <> s.ob_release) \
              + (l.ob_done <> s.ob_done) + (l.ob_cancelled <> s.ob_cancelled) \
              + (l.ob_dead <> s.ob_dead) + ",
    bucket_drift!(),
    "       ELSE 0 END, \
            CASE WHEN l.all_x = 1 AND l.all_o = 1 AND l.all_g = 1 THEN \
              json_object('live', ",
    levels_json!("l", "json_object"),
    ", 'recount', ",
    levels_json!("s", "json_object"),
    ", 'buckets_differing', ",
    bucket_drift!(),
    ") END \
       FROM usage_global s, usage_global l \
      WHERE s.id = 2 AND l.id = 1 AND s.pass = 1 \
        AND s.all_x = 1 AND s.all_o = 1 AND s.all_g = 1"
);

/// Ends a counted recount: one batch, so the comparison, the adoption
/// and the reset of row 2 see the same counters.
fn finish_stmts(dialect: crate::ports::Dialect, now: UnixMs) -> Vec<Stmt> {
    vec![
        (dialect.pick(FINISH_RECORD, FINISH_RECORD_PG), vec![ms(now)]),
        (FINISH_REMOVE_UNCOUNTED_BUCKETS, vec![]),
        (FINISH_ADOPT_BUCKETS, vec![]),
        // Last of the three that read `adopting`: it ends it.
        (FINISH_ADOPT_GLOBAL, vec![]),
        (FINISH_CLEAR_COUNTED, vec![]),
        (FINISH_RESET, vec![]),
    ]
}

/// One step of the running recount: a chunk of at most `chunk` rows of
/// the table it is at, or the end of it. Safe to call from two places at
/// once: each statement finds the cursor itself and moves it in the same
/// statement, so a chunk is counted once.
pub(super) async fn recount_step<S: Sql>(
    c: &SqlCatalog<S>,
    chunk: u32,
    now: UnixMs,
) -> Result<RecountStep> {
    let chunk = chunk.clamp(1, RECOUNT_CHUNK_MAX);
    let limit = || vec![SqlValue::Int(i64::from(chunk))];
    let state = recount_state(c).await?;
    let mut step = RecountStep {
        idle: !state.running,
        rows: 0,
        finished: None,
    };
    match state.table {
        "extents" => {
            c.sql
                .exec(
                    c.sql.dialect().pick(STEP_EXTENTS, STEP_EXTENTS_PG),
                    &limit(),
                )
                .await?;
        }
        "outbox" => {
            c.sql
                .exec(c.sql.dialect().pick(STEP_OUTBOX, STEP_OUTBOX_PG), &limit())
                .await?;
        }
        "generations" => {
            c.sql
                .batch(vec![
                    (
                        c.sql
                            .dialect()
                            .pick(STEP_GENERATIONS_BUCKETS, STEP_GENERATIONS_BUCKETS_PG),
                        limit(),
                    ),
                    (
                        c.sql
                            .dialect()
                            .pick(STEP_GENERATIONS_CURSOR, STEP_GENERATIONS_CURSOR_PG),
                        limit(),
                    ),
                ])
                .await?;
        }
        "finish" => {
            let changed = c.sql.batch(finish_stmts(c.sql.dialect(), now)).await?;
            // Ended by this call, not by another that ran beside it.
            if changed.last().copied().unwrap_or(0) == 1 {
                // The record of the pass this step saw; after a restart
                // in between there is none, and the last one is it.
                step.finished = match recount_record(c, Some(state.started_at)).await? {
                    Some(record) => Some(record),
                    None => last_recount(c).await?,
                };
            }
            return Ok(step);
        }
        _ => return Ok(step),
    }
    // A statement cannot return what it counted (its figures come from
    // the FROM clause), so the rows seen before and after say it.
    let after = recount_state(c).await?;
    if after.running && after.started_at == state.started_at {
        step.rows = after.rows_seen.saturating_sub(state.rows_seen);
    }
    Ok(step)
}

/// Switches the counters off: every trigger writes nothing again, and a
/// running recount is dropped. The figures are stale from here on; the
/// next recount replaces them.
pub(super) async fn off<S: Sql>(c: &SqlCatalog<S>) -> Result<()> {
    c.sql
        .batch(vec![
            (RESET_RECOUNT_STATE, vec![]),
            // The event totals and the hour under way count "since the
            // counters were switched on": they start again with the
            // next recount, and do not span the time in between. The
            // hour under way is filed first, so its events are kept.
            (
                c.sql
                    .dialect()
                    .pick(SAVE_CURRENT_HOUR, SAVE_CURRENT_HOUR_PG),
                vec![],
            ),
            (CLEAR_ACTIVITY_COUNTERS, vec![]),
            (RESET_COUNTED_BUCKETS, vec![]),
        ])
        .await?;
    Ok(())
}

/// The recount under way and the last one that ended: what the cron
/// reads before it goes on with one or starts the weekly one.
pub(super) async fn recounts<S: Sql>(
    c: &SqlCatalog<S>,
) -> Result<(RecountState, Option<UsageRecount>)> {
    Ok((recount_state(c).await?, last_recount(c).await?))
}

const SELECT_RECOUNT_STATE: &str =
    "SELECT pass, started_at, rows_seen, all_x, all_o, all_g, adopt \
               FROM usage_global WHERE id = 2";

const OLDEST_BY_STAGE: &str = "SELECT \
   (SELECT MIN(next_at) FROM outbox WHERE stage = 'post'), \
   (SELECT MIN(next_at) FROM outbox WHERE stage = 'verify'), \
   (SELECT MIN(next_at) FROM outbox WHERE stage = 'release')";

const CURRENT_HOUR: &str = "SELECT g.hour, g.h_posts + COALESCE(h.posts, 0), \
                    g.h_verifies + COALESCE(h.verifies, 0), \
                    g.h_releases + COALESCE(h.releases, 0), \
                    g.h_dead + COALESCE(h.dead, 0), \
                    g.h_failures + COALESCE(h.failures, 0) \
               FROM usage_global g LEFT JOIN usage_hours h ON h.hour = g.hour \
              WHERE g.id = 1";

const PREVIOUS_HOURS: &str = "SELECT hour, posts, verifies, releases, dead, failures \
               FROM usage_hours WHERE hour <> ?2 ORDER BY hour DESC LIMIT ?1";

const BUCKET_PAGE: &str = "SELECT g.ok, p.bucket_id, p.name, p.live_objects, p.live_bytes \
               FROM (SELECT (all_x = 1 AND all_o = 1 AND all_g = 1) AS ok \
                       FROM usage_global WHERE id = 1) g \
               LEFT JOIN (SELECT u.bucket_id, b.name, u.live_objects, u.live_bytes \
                            FROM usage_buckets u JOIN buckets b ON b.id = u.bucket_id \
                           WHERE u.kind = 1 AND u.bucket_id > ?1 \
                           ORDER BY u.bucket_id LIMIT ?2) p ON 1 = 1 \
              ORDER BY p.bucket_id";

const RECOUNT_CLEAR_OLD_BUCKETS: &str = "DELETE FROM usage_buckets WHERE kind = 2 AND EXISTS \
                   (SELECT 1 FROM usage_global WHERE id = 2 AND (pass = 0 OR ?1 = 1)) \
                   AND (?2 = 0 OR EXISTS (SELECT 1 FROM usage_global \
                         WHERE id = 1 AND all_x = 1 AND all_o = 1 AND all_g = 1))";

const RECOUNT_START: &str = "UPDATE usage_global SET \
                   cur_x = '', all_x = 0, cur_o = '', all_o = 0, cur_g = '', all_g = 0, \
                   x_unreleased = 0, unreleased_bytes = 0, x_released = 0, \
                   released_bytes = 0, x_deleted = 0, \
                   ob_post = 0, ob_verify = 0, ob_release = 0, ob_done = 0, \
                   ob_cancelled = 0, ob_dead = 0, \
                   pass = 1, started_at = ?2, rows_seen = 0, adopt = ?3 \
                 WHERE id = 2 AND (pass = 0 OR ?1 = 1) \
                   AND (?4 = 0 OR EXISTS (SELECT 1 FROM usage_global \
                         WHERE id = 1 AND all_x = 1 AND all_o = 1 AND all_g = 1))";

const FINISH_RESET: &str = "UPDATE usage_global SET pass = 0, adopt = 0, \
               cur_x = '', all_x = 0, cur_o = '', all_o = 0, cur_g = '', all_g = 0 \
             WHERE id = 2 AND pass = 1 AND all_x = 1 AND all_o = 1 AND all_g = 1";

const RESET_RECOUNT_STATE: &str = "UPDATE usage_global SET all_x = 0, all_o = 0, all_g = 0, \
                   cur_x = '', cur_o = '', cur_g = '', pass = 0, adopt = 0";

const CLEAR_ACTIVITY_COUNTERS: &str =
    "UPDATE usage_global SET posts_total = 0, verifies_total = 0, \
                   releases_total = 0, dead_total = 0, failures_total = 0, \
                   hour = 0, h_posts = 0, h_verifies = 0, h_releases = 0, \
                   h_dead = 0, h_failures = 0 WHERE id = 1";

const RESET_COUNTED_BUCKETS: &str = "DELETE FROM usage_buckets WHERE kind = 2";

const COUNTERS_PG: &str = "SELECT all_x <> 0 AND all_o <> 0 AND all_g <> 0, \
       x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted, \
       ob_post, ob_verify, ob_release, ob_done, ob_cancelled, ob_dead, \
       posts_total, verifies_total, releases_total, dead_total, failures_total, \
       hour, h_posts, h_verifies, h_releases, h_dead, h_failures \
  FROM usage_global WHERE id = 1";

const SAVE_CURRENT_HOUR: &str = "INSERT INTO usage_hours \
                   (hour, posts, verifies, releases, dead, failures) \
                 SELECT hour, h_posts, h_verifies, h_releases, h_dead, h_failures \
                   FROM usage_global WHERE id = 1 AND hour > 0 \
                    AND h_posts + h_verifies + h_releases + h_dead + h_failures > 0 \
                 ON CONFLICT (hour) DO UPDATE SET \
                   posts = posts + excluded.posts, verifies = verifies + excluded.verifies, \
                   releases = releases + excluded.releases, dead = dead + excluded.dead, \
                   failures = failures + excluded.failures";

const SAVE_CURRENT_HOUR_PG: &str = "INSERT INTO usage_hours \
                   (hour, posts, verifies, releases, dead, failures) \
                 SELECT hour, h_posts, h_verifies, h_releases, h_dead, h_failures \
                   FROM usage_global WHERE id = 1 AND hour > 0 \
                    AND h_posts + h_verifies + h_releases + h_dead + h_failures > 0 \
                 ON CONFLICT (hour) DO UPDATE SET \
                   posts = usage_hours.posts + excluded.posts, verifies = usage_hours.verifies + excluded.verifies, \
                   releases = usage_hours.releases + excluded.releases, dead = usage_hours.dead + excluded.dead, \
                   failures = usage_hours.failures + excluded.failures";

const RECOUNT_RECORD: &str = "SELECT started_at, finished_at, rows, adopted, drift, detail \
               FROM usage_recounts WHERE ?1 IS NULL OR started_at = ?1 \
              ORDER BY id DESC LIMIT 1";

const RECOUNT_RECORD_PG: &str = "SELECT started_at, finished_at, rows, adopted, drift, detail \
               FROM usage_recounts WHERE ?1::bigint IS NULL OR started_at = ?1 \
              ORDER BY id DESC LIMIT 1";

const STEP_EXTENTS_PG: &str = "UPDATE usage_global SET \
   x_unreleased = x_unreleased + p.unrel, unreleased_bytes = unreleased_bytes + p.unrel_b, \
   x_released = x_released + p.rel, released_bytes = released_bytes + p.rel_b, \
   x_deleted = x_deleted + p.del, \
   rows_seen = rows_seen + p.n, cur_x = COALESCE(p.last, cur_x), all_x = (p.n < ?1)::int \
 FROM (SELECT COUNT(*) AS n, MAX(id) AS last, \
         COALESCE(SUM((safety_state IN ('held', 'releasing'))::int), 0) AS unrel, \
         COALESCE(SUM(CASE WHEN safety_state IN ('held', 'releasing') \
                           THEN cipher_size ELSE 0 END), 0) AS unrel_b, \
         COALESCE(SUM((safety_state = 'released')::int), 0) AS rel, \
         COALESCE(SUM(CASE WHEN safety_state = 'released' \
                           THEN cipher_size ELSE 0 END), 0) AS rel_b, \
         COALESCE(SUM((safety_state = 'deleted')::int), 0) AS del \
       FROM (SELECT id, safety_state, cipher_size FROM extents \
              WHERE id > (SELECT cur_x FROM usage_global WHERE id = 2) \
              ORDER BY id LIMIT ?1)) AS p \
 WHERE usage_global.id = 2 AND pass = 1 AND all_x = 0";

const STEP_OUTBOX_PG: &str = "UPDATE usage_global SET \
   ob_post = ob_post + p.post, ob_verify = ob_verify + p.verify, \
   ob_release = ob_release + p.release, ob_done = ob_done + p.done, \
   ob_cancelled = ob_cancelled + p.cancelled, ob_dead = ob_dead + p.dead, \
   rows_seen = rows_seen + p.n, cur_o = COALESCE(p.last, cur_o), all_o = (p.n < ?1)::int \
 FROM (SELECT COUNT(*) AS n, MAX(extent_id) AS last, \
         COALESCE(SUM((stage = 'post')::int), 0) AS post, \
         COALESCE(SUM((stage = 'verify')::int), 0) AS verify, \
         COALESCE(SUM((stage = 'release')::int), 0) AS release, \
         COALESCE(SUM((stage = 'done')::int), 0) AS done, \
         COALESCE(SUM((stage = 'cancelled')::int), 0) AS cancelled, \
         COALESCE(SUM((stage = 'dead')::int), 0) AS dead \
       FROM (SELECT extent_id, stage FROM outbox \
              WHERE extent_id > (SELECT cur_o FROM usage_global WHERE id = 2) \
              ORDER BY extent_id LIMIT ?1)) AS p \
 WHERE usage_global.id = 2 AND pass = 1 AND all_x = 1 AND all_o = 0";

const STEP_GENERATIONS_BUCKETS_PG: &str = concat!(
    "INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes) \
     SELECT 2, bucket_id, COUNT(*), SUM(size) FROM (",
    generations_chunk!("bucket_id, state, size"),
    ") WHERE state = 'live' GROUP BY bucket_id \
     ON CONFLICT (kind, bucket_id) DO UPDATE SET \
       live_objects = usage_buckets.live_objects + excluded.live_objects, \
       live_bytes = usage_buckets.live_bytes + excluded.live_bytes"
);

const STEP_GENERATIONS_CURSOR_PG: &str = concat!(
    "UPDATE usage_global SET rows_seen = rows_seen + p.n, \
       cur_g = COALESCE(p.last, cur_g), all_g = (p.n < ?1)::int \
     FROM (SELECT COUNT(*) AS n, MAX(id) AS last FROM (",
    generations_chunk!("id"),
    ")) AS p \
     WHERE usage_global.id = 2 AND pass = 1 AND all_x = 1 AND all_o = 1 AND all_g = 0"
);

const FINISH_RECORD_PG: &str = concat!(
    "INSERT INTO usage_recounts (started_at, finished_at, rows, adopted, drift, detail) \
     SELECT s.started_at, ?1, s.rows_seen, \
            (s.adopt = 1 OR l.all_x = 0 OR l.all_o = 0 OR l.all_g = 0)::int, \
            CASE WHEN l.all_x = 1 AND l.all_o = 1 AND l.all_g = 1 THEN \
              (l.x_unreleased <> s.x_unreleased)::int + (l.unreleased_bytes <> s.unreleased_bytes)::int \
              + (l.x_released <> s.x_released)::int + (l.released_bytes <> s.released_bytes)::int \
              + (l.x_deleted <> s.x_deleted)::int + (l.ob_post <> s.ob_post)::int \
              + (l.ob_verify <> s.ob_verify)::int + (l.ob_release <> s.ob_release)::int \
              + (l.ob_done <> s.ob_done)::int + (l.ob_cancelled <> s.ob_cancelled)::int \
              + (l.ob_dead <> s.ob_dead)::int + ",
    bucket_drift!(),
    "       ELSE 0 END, \
            CASE WHEN l.all_x = 1 AND l.all_o = 1 AND l.all_g = 1 THEN \
              json_build_object('live', ",
    levels_json!("l", "json_build_object"),
    ", 'recount', ",
    levels_json!("s", "json_build_object"),
    ", 'buckets_differing', ",
    bucket_drift!(),
    ")::text END \
       FROM usage_global s, usage_global l \
      WHERE s.id = 2 AND l.id = 1 AND s.pass = 1 \
        AND s.all_x = 1 AND s.all_o = 1 AND s.all_g = 1"
);

const FINISH_REMOVE_UNCOUNTED_BUCKETS: &str =
    concat!("DELETE FROM usage_buckets WHERE kind = 1 AND ", adopting!());

const FINISH_ADOPT_BUCKETS: &str = concat!(
    "INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes) \
                 SELECT 1, bucket_id, live_objects, live_bytes FROM usage_buckets \
                  WHERE kind = 2 AND ",
    adopting!()
);

const FINISH_ADOPT_GLOBAL: &str = concat!(
    "UPDATE usage_global SET \
                   (x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted, \
                    ob_post, ob_verify, ob_release, ob_done, ob_cancelled, ob_dead) = \
                   (SELECT x_unreleased, unreleased_bytes, x_released, released_bytes, \
                           x_deleted, ob_post, ob_verify, ob_release, ob_done, \
                           ob_cancelled, ob_dead FROM usage_global WHERE id = 2), \
                   all_x = 1, all_o = 1, all_g = 1 \
                 WHERE id = 1 AND ",
    adopting!()
);

const FINISH_CLEAR_COUNTED: &str =
    concat!("DELETE FROM usage_buckets WHERE kind = 2 AND ", counted!());

/// Actual Postgres texts and representative wire types for typed PREPARE.
#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(String, Vec<SqlValue>)> {
    const I: SqlValue = SqlValue::Int(0);
    const T: SqlValue = SqlValue::Text(String::new());
    vec![
        (BUCKET_TOTALS.to_owned(), vec![]),
        (SELECT_RECOUNT_STATE.to_owned(), vec![]),
        (OLDEST_BY_STAGE.to_owned(), vec![]),
        (CURRENT_HOUR.to_owned(), vec![]),
        (PREVIOUS_HOURS.to_owned(), vec![I, I]),
        (BUCKET_PAGE.to_owned(), vec![T, I]),
        (RECOUNT_CLEAR_OLD_BUCKETS.to_owned(), vec![I, I]),
        (RECOUNT_START.to_owned(), vec![I, I, I, I]),
        (FINISH_RESET.to_owned(), vec![]),
        (RESET_RECOUNT_STATE.to_owned(), vec![]),
        (CLEAR_ACTIVITY_COUNTERS.to_owned(), vec![]),
        (RESET_COUNTED_BUCKETS.to_owned(), vec![]),
        (COUNTERS_PG.to_owned(), vec![]),
        (SAVE_CURRENT_HOUR_PG.to_owned(), vec![]),
        (RECOUNT_RECORD_PG.to_owned(), vec![I]),
        (STEP_EXTENTS_PG.to_owned(), vec![I]),
        (STEP_OUTBOX_PG.to_owned(), vec![I]),
        (STEP_GENERATIONS_BUCKETS_PG.to_owned(), vec![I]),
        (STEP_GENERATIONS_CURSOR_PG.to_owned(), vec![I]),
        (FINISH_RECORD_PG.to_owned(), vec![I]),
        (FINISH_REMOVE_UNCOUNTED_BUCKETS.to_owned(), vec![]),
        (FINISH_ADOPT_BUCKETS.to_owned(), vec![]),
        (FINISH_ADOPT_GLOBAL.to_owned(), vec![]),
        (FINISH_CLEAR_COUNTED.to_owned(), vec![]),
    ]
}
