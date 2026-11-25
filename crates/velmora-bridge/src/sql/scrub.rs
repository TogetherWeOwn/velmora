//! The scrub's catalogue ([`crate::scrub`]).
//!
//! One run at a time owns the scrub lease. Enrollment, due-time changes
//! and repairs are fenced by its token. Each list uses an indexed range
//! with a hard page size; extent rows are joined by primary key.

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};

use super::objects::{extent_cols, extent_row, ms, text, uint, Cols, Stmt};
use super::uploads::guarded;
use super::SqlCatalog;
use crate::ports::{Dialect, Guard, Sql, SqlValue};
use crate::types::{
    BridgeError, ExtentId, Result, ScrubCandidate, ScrubCheck, ScrubResult, ScrubRun, ScrubState,
    UnixMs,
};

const ENROLL_PAGE: i64 = 128;
const EXTENT_COLS: &str = extent_cols!();

macro_rules! pending_sql {
    ($index:literal) => {
        concat!(
            "SELECT id, COALESCE(released_at, created_at), \
             CASE WHEN scrub_result IN ('suspect', 'unrecoverable', 'deferred') \
                  THEN COALESCE(scrub_next_at, last_scrubbed_at, created_at) END \
             FROM extents", $index,
            " WHERE safety_state = 'released' AND scrub_enrolled = 0 AND id > ?1 ORDER BY id LIMIT ?2"
        )
    };
}
const PENDING: &str = pending_sql!(" INDEXED BY extents_scrub_pending");
const PENDING_PG: &str = pending_sql!("");

macro_rules! backfill_sql {
    ($null:literal, $index:literal) => {
        concat!(
            "SELECT id, COALESCE(released_at, created_at), ", $null, " FROM extents", $index,
            " WHERE scrub_enrolled = 1 AND safety_state <> 'deleted' AND id > ?1 ORDER BY id LIMIT ?2"
        )
    };
}
const BACKFILL: &str = backfill_sql!("NULL", " INDEXED BY extents_scrub_enrolled");
const BACKFILL_PG: &str = backfill_sql!("CAST(NULL AS bigint)", "");

/// The run that holds the lease is the one with token `?2`.
macro_rules! run_holds {
    () => {
        "EXISTS (SELECT 1 FROM scrub_state WHERE id = 1 AND lease_token = ?2)"
    };
}

const TAKE: &str = "UPDATE scrub_state SET lease_token = lease_token + 1, lease_until = ?2 \
              WHERE id = 1 AND (lease_until IS NULL OR lease_until < ?1) RETURNING lease_token";
const STATE: &str = "SELECT lease_token, lease_until, runs, checked, ok, suspect, repaired, unrecoverable, stalled, \
               incidents, bytes_read, last_run_at, last_unrecoverable_at, last_incident_at, \
               last_incident, incident_clean, incident_clean_by, incident_body_by FROM scrub_state WHERE id = 1";
const ENROLL_STATE: &str = "SELECT cadence_backbones, cadence_after, cadence_epoch FROM scrub_state WHERE id = 1 AND lease_token = ?1";
const ENROLL_PROGRESS: &str = "UPDATE scrub_state SET cadence_backbones = ?1, cadence_after = ?3, cadence_epoch = ?4 WHERE id = 1 AND lease_token = ?2";

macro_rules! enroll_copies {
    ($projection:literal, $items:literal, $extent:literal) => {
        concat!(
            "INSERT INTO scrub_copies(extent_id, backbone, stat_at, full_at, stat_phase_at, full_phase_at) \
             SELECT e.id, ?1, ", $projection, " FROM ", $items, " JOIN extents e ON e.id = ", $extent,
            " WHERE e.safety_state <> 'deleted' AND (e.safety_state = 'released' OR e.scrub_enrolled = 1) AND ",
            run_holds!(), " ON CONFLICT(extent_id, backbone) DO NOTHING"
        )
    };
}
const ENROLL_COPIES: &str = enroll_copies!(
    "json_extract(j.value, '$[1]'), json_extract(j.value, '$[2]'), \
     json_extract(j.value, '$[1]'), json_extract(j.value, '$[3]')",
    "json_each(?3) j CROSS",
    "json_extract(j.value, '$[0]')"
);
const ENROLL_COPIES_PG: &str = enroll_copies!(
    "CAST(j.value ->> 1 AS bigint), CAST(j.value ->> 2 AS bigint), \
     CAST(j.value ->> 1 AS bigint), CAST(j.value ->> 3 AS bigint)",
    "jsonb_array_elements(CAST(?3 AS jsonb)) j",
    "j.value ->> 0"
);

macro_rules! enroll_extents {
    ($items:literal) => {
        concat!(
            "UPDATE extents SET scrub_enrolled = 1 WHERE safety_state = 'released' \
             AND scrub_enrolled = 0 AND id IN (SELECT value FROM ",
            $items,
            ") AND ",
            run_holds!()
        )
    };
}
const ENROLL_EXTENTS: &str = enroll_extents!("json_each(?1)");
const ENROLL_EXTENTS_PG: &str = enroll_extents!("jsonb_array_elements_text(CAST(?1 AS jsonb))");

pub(super) async fn take<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    until: UnixMs,
) -> Result<Option<u64>> {
    let rows = c.sql.query(TAKE, &[ms(now), ms(until)]).await?;
    match rows.into_iter().next() {
        Some(row) => Ok(Some(Cols::new(row).num()?)),
        None => Ok(None),
    }
}

pub(super) async fn state<S: Sql>(c: &SqlCatalog<S>) -> Result<ScrubState> {
    let rows = c.sql.query(STATE, &[]).await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(ScrubState::default());
    };
    let mut r = Cols::new(row);
    Ok(ScrubState {
        lease_token: r.num()?,
        lease_until: r.opt_ms()?,
        runs: r.num()?,
        checked: r.num()?,
        ok: r.num()?,
        suspect: r.num()?,
        repaired: r.num()?,
        unrecoverable: r.num()?,
        stalled: r.num()?,
        incidents: r.num()?,
        bytes_read: r.num()?,
        last_run_at: r.opt_ms()?,
        last_unrecoverable_at: r.opt_ms()?,
        last_incident_at: r.opt_ms()?,
        last_incident: r.opt_text()?,
        incident_clean: r.num()?,
        incident_clean_by: r
            .opt_text()?
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default(),
        incident_body_by: r.opt_text()?.map_or_else(Vec::new, |raw| {
            serde_json::from_str(&raw).unwrap_or_else(|_| vec![raw])
        }),
    })
}

fn json(value: &impl serde::Serialize) -> Result<SqlValue> {
    serde_json::to_string(value)
        .map(SqlValue::Text)
        .map_err(|_| BridgeError::Invalid("scrub schedule"))
}

/// Spread extents across the intervals, but group one extent's copies
/// so a run can check them with one plan load. When full is a multiple
/// of STAT, choose one of its STAT slots within the full interval.
fn phase(id: &str, [stat, full]: [i64; 2]) -> [i64; 2] {
    let bytes = Sha256::digest(id.as_bytes());
    let stat_seed = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let full_seed = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
    let a = (stat_seed % stat as u64) as i64;
    let b = if full % stat == 0 {
        a + (full_seed % (full / stat) as u64) as i64 * stat
    } else {
        (full_seed % full as u64) as i64
    };
    [a, b]
}

pub(super) async fn enroll<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    backbones: &[String],
    now: UnixMs,
    intervals: [i64; 2],
) -> Result<bool> {
    if intervals.iter().any(|&interval| interval <= 0) {
        return Err(BridgeError::Invalid("scrub interval"));
    }
    if backbones.is_empty() {
        return Ok(false);
    }
    let mut labels = backbones.to_vec();
    labels.sort_unstable();
    labels.dedup();
    let labels_json = json(&labels)?;
    let dialect = c.sql.dialect();
    let mut state = Cols::new(
        c.sql
            .query(ENROLL_STATE, &[uint(token)?])
            .await?
            .into_iter()
            .next()
            .ok_or(BridgeError::Invalid("scrub lease"))?,
    );
    let previous = state.opt_text()?.map(SqlValue::Text);
    let changed = previous.as_ref() != Some(&labels_json);
    let mut after = state.opt_text()?;
    let mut epoch = state.opt_ms()?.unwrap_or(now);
    if changed {
        // Anchor the whole first pass, not each page, to the same epoch.
        // On first enable the pending index holds the whole inventory.
        epoch = now;
        after = previous.map(|_| String::new());
    }
    let ids = |rows: Vec<crate::ports::Row>| -> Result<Vec<_>> {
        rows.into_iter()
            .map(|r| {
                let mut row = Cols::new(r);
                Ok((row.text()?, (row.ms()?, row.opt_ms()?)))
            })
            .collect()
    };
    let pending = ids(c
        .sql
        .query(
            dialect.pick(PENDING, PENDING_PG),
            &[text(""), SqlValue::Int(ENROLL_PAGE)],
        )
        .await?)?;
    let mut advance = changed;
    let mut work: BTreeMap<_, _> = pending.iter().cloned().collect();
    if let Some(cursor) = &after {
        let page = ids(c
            .sql
            .query(
                dialect.pick(BACKFILL, BACKFILL_PG),
                &[text(cursor), SqlValue::Int(ENROLL_PAGE)],
            )
            .await?)?;
        after = if page.len() as i64 == ENROLL_PAGE {
            page.last().map(|(id, _)| id.clone())
        } else {
            None
        };
        work.extend(page);
        advance = true;
    }
    let mut stmts = Vec::<Stmt>::new();
    if !work.is_empty() {
        // One small statement per backbone, with the same bounded extent page.
        // Conflict means a prior enrollment already established the clocks.
        let entries: Vec<_> = work
            .iter()
            .map(|(id, (released, legacy_retry))| {
                let start = epoch.max(*released);
                let [stat, full] = phase(id, intervals);
                let full = start.plus_ms(full);
                // A legacy result does not identify a backbone. Recheck
                // every copy in full without marking any loss confirmed.
                let first_full = legacy_retry.map_or(full, |retry| retry.min(full));
                (id, start.plus_ms(stat).0, first_full.0, full.0)
            })
            .collect();
        let entries = json(&entries)?;
        for label in &labels {
            stmts.push((
                dialect.pick(ENROLL_COPIES, ENROLL_COPIES_PG),
                vec![text(label), uint(token)?, entries.clone()],
            ));
        }
        stmts.push((
            dialect.pick(ENROLL_EXTENTS, ENROLL_EXTENTS_PG),
            vec![
                json(&pending.iter().map(|(id, _)| id).collect::<Vec<_>>())?,
                uint(token)?,
            ],
        ));
    }
    if advance {
        stmts.push((
            ENROLL_PROGRESS,
            vec![
                labels_json,
                uint(token)?,
                after.as_deref().map_or(SqlValue::Null, text),
                ms(epoch),
            ],
        ));
    }
    if !stmts.is_empty() {
        c.sql.batch(stmts).await?;
    }
    Ok(pending.len() as i64 == ENROLL_PAGE || after.is_some())
}

const DUE: &str = concat!(
    "SELECT ",
    extent_cols!(),
    ", scrub_result, last_scrubbed_at, scrub_next_at, stat_at, full_at, \
       stat_loss_at, full_loss_at, stat_phase_at, full_phase_at \
     FROM scrub_copies s INDEXED BY scrub_copies_due CROSS JOIN extents e ON e.id = s.extent_id \
     WHERE s.backbone = ?1 AND MIN(stat_at, full_at) <= ?2 \
     ORDER BY MIN(stat_at, full_at), s.extent_id LIMIT ?3"
);
// LIMIT the schedule before joining to extents. The cascading FK ensures
// that this cannot drop a schedule that the SQLite join would have skipped.
const DUE_PG: &str = concat!(
    "SELECT ", extent_cols!(), ", scrub_result, last_scrubbed_at, scrub_next_at, stat_at, full_at, \
       stat_loss_at, full_loss_at, stat_phase_at, full_phase_at \
     FROM (SELECT extent_id, stat_at, full_at, stat_loss_at, full_loss_at, stat_phase_at, full_phase_at \
           FROM scrub_copies WHERE backbone = ?1 AND LEAST(stat_at, full_at) <= ?2 \
           ORDER BY LEAST(stat_at, full_at), extent_id LIMIT ?3) s \
     JOIN extents e ON e.id = s.extent_id \
     ORDER BY LEAST(stat_at, full_at), s.extent_id"
);

macro_rules! watch_sql {
    ($index:literal) => {
        concat!(
            "SELECT ",
            extent_cols!(),
            ", scrub_result, last_scrubbed_at, scrub_next_at \
             FROM extents",
            $index,
            " WHERE scrub_next_at <= ?1 ORDER BY scrub_next_at, id LIMIT ?2"
        )
    };
}
const WATCH: &str = watch_sql!(" INDEXED BY extents_scrub_watch");
const WATCH_PG: &str = watch_sql!("");

pub(super) fn range_queries(dialect: Dialect) -> [&'static str; 4] {
    [
        dialect.pick(DUE, DUE_PG),
        dialect.pick(WATCH, WATCH_PG),
        dialect.pick(PENDING, PENDING_PG),
        dialect.pick(BACKFILL, BACKFILL_PG),
    ]
}

fn parse_candidate(mut row: crate::ports::Row) -> Result<(ScrubCandidate, Cols)> {
    let width = EXTENT_COLS.split(',').count();
    if row.len() < width + 3 {
        return Err(BridgeError::Sql("row decode: scrub columns".into()));
    }
    let mut extra = Cols::new(row.split_off(width));
    let last = extra.opt_text()?.as_deref().and_then(ScrubResult::parse);
    let last_scrubbed_at = extra.opt_ms()?;
    let watch_at = extra.opt_ms()?;
    Ok((
        ScrubCandidate {
            extent: extent_row(row)?,
            last,
            last_scrubbed_at,
            watch_at,
            checks: Vec::new(),
        },
        extra,
    ))
}

pub(super) async fn due<S: Sql>(
    c: &SqlCatalog<S>,
    backbones: &[String],
    now: UnixMs,
    limit: u32,
) -> Result<Vec<ScrubCandidate>> {
    let limit = limit.min(crate::scrub::SCRUB_PAGE);
    let page = SqlValue::Int(i64::from(limit));
    let [due, watch, ..] = range_queries(c.sql.dialect());
    let mut grouped = HashMap::new();
    for row in c.sql.query(watch, &[ms(now), page.clone()]).await? {
        let (candidate, _) = parse_candidate(row)?;
        let watch_at = candidate.watch_at.ok_or_else(|| {
            BridgeError::Sql("row decode: due repair watch has no deadline".into())
        })?;
        grouped.insert(candidate.extent.id.clone(), (watch_at, candidate));
    }
    for backbone in backbones {
        for row in c
            .sql
            .query(due, &[text(backbone), ms(now), page.clone()])
            .await?
        {
            let (candidate, mut extra) = parse_candidate(row)?;
            let stat = UnixMs(extra.num()?);
            let full = UnixMs(extra.num()?);
            let stat_loss = extra.opt_ms()?;
            let full_loss = extra.opt_ms()?;
            let stat_phase = extra.ms()?;
            let full_phase = extra.ms()?;
            let (oldest, candidate) = grouped
                .entry(candidate.extent.id.clone())
                .or_insert((stat.min(full), candidate));
            *oldest = (*oldest).min(stat.min(full));
            for (due_at, phase_at, loss_at, full) in [
                (stat, stat_phase, stat_loss, false),
                (full, full_phase, full_loss, true),
            ] {
                if due_at <= now {
                    candidate.checks.push(ScrubCheck {
                        backbone: backbone.clone(),
                        full,
                        due_at,
                        phase_at,
                        loss_at,
                    });
                }
            }
        }
    }
    let mut grouped: Vec<_> = grouped.into_values().collect();
    grouped.sort_unstable_by(|(a, left), (b, right)| {
        a.cmp(b)
            .then_with(|| left.extent.id.as_str().cmp(right.extent.id.as_str()))
    });
    Ok(grouped
        .into_iter()
        .take(limit as usize)
        .map(|(_, candidate)| candidate)
        .collect())
}

const ADVANCE_GUARD: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT \
    EXISTS (SELECT 1 FROM scrub_state WHERE id = 1 AND lease_token = ?1)";
const ADVANCE_FULL: &str =
    "UPDATE scrub_copies SET full_at = ?4, full_loss_at = ?5, full_phase_at = ?6 \
             WHERE extent_id = ?1 AND backbone = ?2 AND full_at = ?3";
const ADVANCE_STAT: &str =
    "UPDATE scrub_copies SET stat_at = ?4, stat_loss_at = ?5, stat_phase_at = ?6 \
             WHERE extent_id = ?1 AND backbone = ?2 AND stat_at = ?3";

pub(super) async fn advance<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    updates: &[(ScrubCheck, UnixMs, Option<UnixMs>)],
) -> Result<bool> {
    let mut stmts = Vec::with_capacity(updates.len() + 1);
    stmts.push((ADVANCE_GUARD, vec![uint(token)?]));
    for (check, next, loss) in updates {
        let sql = if check.full {
            ADVANCE_FULL
        } else {
            ADVANCE_STAT
        };
        stmts.push((
            sql,
            vec![
                text(extent.as_str()),
                text(&check.backbone),
                ms(check.due_at),
                ms(*next),
                loss.map_or(SqlValue::Null, ms),
                ms(check.phase_at),
            ],
        ));
    }
    Ok(guarded(c, stmts).await? == Guard::Applied(()))
}

const HAS_LOSS: &str = "SELECT s.backbone FROM json_each(?2) j CROSS JOIN scrub_copies s \
    ON s.extent_id = ?1 AND s.backbone = j.value \
    WHERE s.stat_loss_at IS NOT NULL OR s.full_loss_at IS NOT NULL ORDER BY j.key";
const HAS_LOSS_PG: &str = "SELECT s.backbone FROM \
    jsonb_array_elements_text(CAST(?2 AS jsonb)) WITH ORDINALITY j(value, ordinal) \
    JOIN scrub_copies s ON s.extent_id = ?1 AND s.backbone = j.value \
    WHERE s.stat_loss_at IS NOT NULL OR s.full_loss_at IS NOT NULL ORDER BY j.ordinal";

pub(super) async fn has_loss<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    backbones: &[String],
) -> Result<Vec<String>> {
    let rows = c
        .sql
        .query(
            c.sql.dialect().pick(HAS_LOSS, HAS_LOSS_PG),
            &[text(extent.as_str()), json(&backbones)?],
        )
        .await?;
    rows.into_iter().map(|row| Cols::new(row).text()).collect()
}

const RETIRE_GUARD: &str = concat!(
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ",
    run_holds!(),
    " OR NOT EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND safety_state = 'deleted')"
);
const RETIRE_COPIES: &str = "DELETE FROM scrub_copies WHERE extent_id = ?1";
const RETIRE_EXTENT: &str =
    "UPDATE extents SET scrub_enrolled = 0, scrub_next_at = NULL WHERE id = ?1";

pub(super) async fn retire<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
) -> Result<bool> {
    let key = text(extent.as_str());
    let stmts = vec![
        (RETIRE_GUARD, vec![key.clone(), uint(token)?]),
        (RETIRE_COPIES, vec![key.clone()]),
        (RETIRE_EXTENT, vec![key]),
    ];
    Ok(guarded(c, stmts).await? == Guard::Applied(()))
}

const RECORD: &str = concat!(
    "UPDATE extents SET scrub_result = ?3, last_scrubbed_at = ?4, scrub_next_at = ?5 \
     WHERE id = ?1 AND safety_state IN ('released', 'held', 'releasing') AND ",
    run_holds!()
);
const LIVE: &str = concat!("SELECT ", live_ref!("?1"));
const DROP_DUE: &str = concat!(
    "UPDATE extents SET scrub_next_at = NULL WHERE id = ?1 AND ",
    run_holds!()
);
const FREE: &str = "UPDATE scrub_state SET lease_until = NULL WHERE id = 1 AND lease_token = ?1";
const BLOCK: &str =
    "UPDATE scrub_state SET last_incident = ?2, incident_clean = 0, incident_clean_by = NULL, \
               incident_body_by = ?3 WHERE id = 1 AND lease_token = ?1";
const DEFER: &str = concat!(
    "UPDATE extents SET scrub_next_at = ?3 WHERE id = ?1 AND ",
    run_holds!()
);

pub(super) async fn record<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    result: ScrubResult,
    now: UnixMs,
    next_at: Option<UnixMs>,
) -> Result<bool> {
    let changed = c
        .sql
        .exec(
            RECORD,
            &[
                text(extent.as_str()),
                uint(token)?,
                text(result.as_str()),
                ms(now),
                next_at.map_or(SqlValue::Null, ms),
            ],
        )
        .await?;
    Ok(changed == 1)
}

pub(super) async fn live<S: Sql>(c: &SqlCatalog<S>, extent: &ExtentId) -> Result<bool> {
    let rows = c.sql.query(LIVE, &[text(extent.as_str())]).await?;
    match rows.into_iter().next() {
        Some(row) => Ok(Cols::new(row).num::<i64>()? != 0),
        None => Ok(false),
    }
}

pub(super) async fn drop_due<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
) -> Result<bool> {
    let changed = c
        .sql
        .exec(DROP_DUE, &[text(extent.as_str()), uint(token)?])
        .await?;
    Ok(changed == 1)
}

pub(super) async fn free<S: Sql>(c: &SqlCatalog<S>, token: u64, _now: UnixMs) -> Result<bool> {
    let changed = c.sql.exec(FREE, &[uint(token)?]).await?;
    Ok(changed == 1)
}

pub(super) async fn block<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    blocked: &[String],
    body: &[String],
) -> Result<bool> {
    let changed = c
        .sql
        .exec(BLOCK, &[uint(token)?, json(&blocked)?, json(&body)?])
        .await?;
    Ok(changed == 1)
}

pub(super) async fn defer<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    next_at: UnixMs,
) -> Result<bool> {
    let changed = c
        .sql
        .exec(DEFER, &[text(extent.as_str()), uint(token)?, ms(next_at)])
        .await?;
    Ok(changed == 1)
}

// A repair cannot resurrect a deleted or overwritten generation.
const REPIN_GUARD: &str = concat!(
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ",
    run_holds!(),
    " OR NOT EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND safety_state = 'released') \
      OR NOT EXISTS (SELECT 1 FROM outbox WHERE extent_id = ?1 AND stage = 'done') OR NOT ",
    live_ref!("?1")
);
const REPIN_EXTENT: &str = "UPDATE extents SET safety_state = 'held', evict_seq = evict_seq + 1, \
               hot_safety_bytes = cipher_size, scrub_result = 'repairing', \
               last_scrubbed_at = ?2, scrub_next_at = ?3 WHERE id = ?1";
const REPIN_OUTBOX: &str =
    "UPDATE outbox SET stage = 'verify', next_at = ?2, cursor = 0, attempts = 0, \
    last_error = NULL, updated_at = ?2, lease_token = lease_token + 1, lease_owner = NULL, \
    lease_until = NULL WHERE extent_id = ?1 AND stage = 'done'";

macro_rules! repin_verifications {
    ($items:literal) => {
        concat!(
            "INSERT INTO verifications(extent_id, backbone, provider_id, verified_at, plan_rev, \
             articles_ok, articles_present, articles_total, result, kind) \
             SELECT e.id, j.value, 'scrub', ?3, e.plan_rev, 0, 0, COALESCE(e.article_count, 0), \
               'missing', 'body' FROM extents e, ", $items, " j WHERE e.id = ?1 \
             ON CONFLICT(extent_id, backbone, verified_at) DO NOTHING"
        )
    };
}
const REPIN_VERIFICATIONS: &str = repin_verifications!("json_each(?2)");
const REPIN_VERIFICATIONS_PG: &str =
    repin_verifications!("jsonb_array_elements_text(CAST(?2 AS jsonb))");

macro_rules! repin_copies {
    ($min:literal, $items:literal) => {
        concat!(
            "UPDATE scrub_copies SET stat_loss_at = NULL, full_loss_at = NULL, full_at = ",
            $min,
            "(full_at, ?3) WHERE extent_id = ?1 AND backbone IN (SELECT value FROM ",
            $items,
            ")"
        )
    };
}
const REPIN_COPIES: &str = repin_copies!("MIN", "json_each(?2)");
const REPIN_COPIES_PG: &str =
    repin_copies!("LEAST", "jsonb_array_elements_text(CAST(?2 AS jsonb))");

pub(super) async fn repin<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    (now, next_at): (UnixMs, UnixMs),
    unread: &[String],
) -> Result<bool> {
    let dialect = c.sql.dialect();
    let mut stmts: Vec<Stmt> = vec![
        (REPIN_GUARD, vec![text(extent.as_str()), uint(token)?]),
        // Pinned again: no eviction listing from before can begin on it
        // (`evict_seq`), and the copy it holds is counted.
        (
            REPIN_EXTENT,
            vec![text(extent.as_str()), ms(now), ms(next_at)],
        ),
        // Back to verify, at once, from the first backbone, with its
        // attempts counted afresh. Any lease on the row is dead.
        (REPIN_OUTBOX, vec![text(extent.as_str()), ms(now)]),
    ];
    if !unread.is_empty() {
        // No provider served the bytes: a failed full read of the current
        // plan on each of these backbones, so verify reads them in full
        // and no release counts them until that read passes (whatever
        // `STAT` says, under either VERIFY_MODE).
        let labels =
            serde_json::to_string(unread).map_err(|_| BridgeError::Invalid("backbone labels"))?;
        stmts.push((
            dialect.pick(REPIN_VERIFICATIONS, REPIN_VERIFICATIONS_PG),
            vec![text(extent.as_str()), text(&labels), ms(now)],
        ));
        // The existing verify job now owns these failures. If the repair
        // releases, require a fresh finding before another re-pin, and
        // still give the repaired copy its own scheduled BODY pass.
        stmts.push((
            dialect.pick(REPIN_COPIES, REPIN_COPIES_PG),
            vec![text(extent.as_str()), text(&labels), ms(next_at)],
        ));
    }
    Ok(guarded(c, stmts).await? == Guard::Applied(()))
}

#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(String, Vec<SqlValue>)> {
    super::pg_manifest(&[
        (TAKE, "II"),
        (STATE, ""),
        (ENROLL_STATE, "I"),
        (PENDING_PG, "TI"),
        (BACKFILL_PG, "TI"),
        (ENROLL_COPIES_PG, "TIT"),
        (ENROLL_EXTENTS_PG, "TI"),
        (ENROLL_PROGRESS, "TINI"),
        (DUE_PG, "TII"),
        (WATCH_PG, "II"),
        (ADVANCE_GUARD, "I"),
        (ADVANCE_FULL, "TTIINI"),
        (ADVANCE_STAT, "TTIINI"),
        (HAS_LOSS_PG, "TT"),
        (RETIRE_GUARD, "TI"),
        (RETIRE_COPIES, "T"),
        (RETIRE_EXTENT, "T"),
        (RECORD, "TITIN"),
        (LIVE, "T"),
        (DROP_DUE, "TI"),
        (FREE, "I"),
        (BLOCK, "ITT"),
        (DEFER, "TII"),
        (REPIN_GUARD, "TI"),
        (REPIN_EXTENT, "TII"),
        (REPIN_OUTBOX, "TI"),
        (REPIN_VERIFICATIONS_PG, "TTI"),
        (REPIN_COPIES_PG, "TTI"),
        (END, "IIIIIIIIIINNINN"),
    ])
    .into_iter()
    .map(|(sql, params)| (sql.to_owned(), params))
    .collect()
}

const END: &str = "UPDATE scrub_state SET lease_until = NULL, runs = runs + 1, \
    checked = checked + ?3, ok = ok + ?4, suspect = suspect + ?5, repaired = repaired + ?6, \
    unrecoverable = unrecoverable + ?7, stalled = stalled + ?8, incidents = incidents + ?9, \
    bytes_read = bytes_read + ?10, last_run_at = ?1, \
    last_unrecoverable_at = CASE WHEN ?7 > 0 THEN ?1 ELSE last_unrecoverable_at END, \
    last_incident_at = CASE WHEN CAST(?11 AS TEXT) IS NOT NULL THEN ?1 ELSE last_incident_at END, \
    last_incident = ?12, incident_clean = ?13, incident_clean_by = ?14, incident_body_by = ?15 \
    WHERE id = 1 AND lease_token = ?2";

/// Adds a run's totals and frees the lease, and stores the backbones no
/// loss is repaired on (`last_incident`, a JSON array; NULL = none), as
/// the run worked them out ([`ScrubRun::blocked`]). One run at a time
/// holds the lease, so the read at its start and this write are not
/// raced.
pub(super) async fn end<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    run: &ScrubRun,
    now: UnixMs,
) -> Result<bool> {
    let changed = c
        .sql
        .exec(
            END,
            &[
                ms(now),
                uint(token)?,
                uint(u64::from(run.checked))?,
                uint(u64::from(run.ok))?,
                uint(u64::from(run.suspect))?,
                uint(u64::from(run.repaired))?,
                uint(u64::from(run.unrecoverable))?,
                uint(u64::from(run.stalled))?,
                uint(u64::from(run.incident.is_some()))?,
                uint(run.bytes_read)?,
                run.incident.as_deref().map_or(SqlValue::Null, text),
                match run.blocked.is_empty() {
                    true => SqlValue::Null,
                    false => text(
                        &serde_json::to_string(&run.blocked)
                            .map_err(|_| BridgeError::Invalid("backbone labels"))?,
                    ),
                },
                uint(run.incident_clean)?,
                if run.incident_clean_by.is_empty() {
                    SqlValue::Null
                } else {
                    json(&run.incident_clean_by)?
                },
                if run.incident_body_by.is_empty() {
                    SqlValue::Null
                } else {
                    json(&run.incident_body_by)?
                },
            ],
        )
        .await?;
    Ok(changed == 1)
}
