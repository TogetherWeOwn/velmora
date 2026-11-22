//! The scrub's catalogue ([`crate::scrub`]).
//!
//! One run at a time owns the scrub lease. Enrollment, due-time changes
//! and repairs are fenced by its token. Each list uses an indexed range
//! with a hard page size; extent rows are joined by primary key.

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};

use super::objects::{extent_row, ms, text, uint, Cols, Stmt, EXTENT_COLS};
use super::uploads::guarded;
use super::SqlCatalog;
use crate::ports::{Guard, Sql, SqlValue};
use crate::types::{
    BridgeError, ExtentId, Result, ScrubCandidate, ScrubCheck, ScrubResult, ScrubRun, ScrubState,
    UnixMs,
};

const ENROLL_PAGE: i64 = 128;
const PENDING_SQL: &str = "SELECT id, COALESCE(released_at, created_at), \
       CASE WHEN scrub_result IN ('suspect', 'unrecoverable', 'deferred') \
            THEN COALESCE(scrub_next_at, last_scrubbed_at, created_at) END \
     FROM extents INDEXED BY extents_scrub_pending \
    WHERE safety_state = 'released' AND scrub_enrolled = 0 AND id > ?1 ORDER BY id LIMIT ?2";
const BACKFILL_SQL: &str =
    "SELECT id, COALESCE(released_at, created_at), NULL FROM extents INDEXED BY extents_scrub_enrolled \
    WHERE scrub_enrolled = 1 AND safety_state <> 'deleted' AND id > ?1 ORDER BY id LIMIT ?2";

/// The run that holds the lease is the one with token `?2`.
macro_rules! run_holds {
    () => {
        "EXISTS (SELECT 1 FROM scrub_state WHERE id = 1 AND lease_token = ?2)"
    };
}

pub(super) async fn take<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    until: UnixMs,
) -> Result<Option<u64>> {
    let rows = c
        .sql
        .query(
            "UPDATE scrub_state SET lease_token = lease_token + 1, lease_until = ?2 \
              WHERE id = 1 AND (lease_until IS NULL OR lease_until < ?1) \
              RETURNING lease_token",
            &[ms(now), ms(until)],
        )
        .await?;
    match rows.into_iter().next() {
        Some(row) => Ok(Some(Cols::new(row).num()?)),
        None => Ok(None),
    }
}

pub(super) async fn state<S: Sql>(c: &SqlCatalog<S>) -> Result<ScrubState> {
    let rows = c
        .sql
        .query(
            "SELECT lease_token, lease_until, runs, checked, ok, suspect, repaired, unrecoverable, stalled, \
               incidents, bytes_read, last_run_at, last_unrecoverable_at, last_incident_at, \
               last_incident, incident_clean, incident_clean_by, incident_body_by FROM scrub_state WHERE id = 1",
            &[],
        )
        .await?;
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
    let mut state = Cols::new(
        c.sql.query(
            "SELECT cadence_backbones, cadence_after, cadence_epoch FROM scrub_state WHERE id = 1 AND lease_token = ?1",
            &[uint(token)?],
        ).await?.into_iter().next().ok_or(BridgeError::Invalid("scrub lease"))?,
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
        .query(PENDING_SQL, &[text(""), SqlValue::Int(ENROLL_PAGE)])
        .await?)?;
    let mut advance = changed;
    let mut work: BTreeMap<_, _> = pending.iter().cloned().collect();
    if let Some(cursor) = &after {
        let page = ids(c
            .sql
            .query(BACKFILL_SQL, &[text(cursor), SqlValue::Int(ENROLL_PAGE)])
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
                concat!(
                    "INSERT INTO scrub_copies(extent_id, backbone, stat_at, full_at, stat_phase_at, full_phase_at) \
                 SELECT e.id, ?1, json_extract(j.value, '$[1]'), json_extract(j.value, '$[2]'), \
                    json_extract(j.value, '$[1]'), json_extract(j.value, '$[3]') \
                 FROM json_each(?3) j CROSS JOIN extents e ON e.id = json_extract(j.value, '$[0]') \
                 WHERE e.safety_state <> 'deleted' AND (e.safety_state = 'released' OR e.scrub_enrolled = 1) AND ",
                    run_holds!(),
                    " ON CONFLICT(extent_id, backbone) DO NOTHING"
                ),
                vec![text(label), uint(token)?, entries.clone()],
            ));
        }
        stmts.push((
            concat!(
                "UPDATE extents SET scrub_enrolled = 1 WHERE safety_state = 'released' \
             AND scrub_enrolled = 0 AND id IN (SELECT value FROM json_each(?1)) AND ",
                run_holds!()
            ),
            vec![
                json(&pending.iter().map(|(id, _)| id).collect::<Vec<_>>())?,
                uint(token)?,
            ],
        ));
    }
    if advance {
        stmts.push((
            "UPDATE scrub_state SET cadence_backbones = ?1, cadence_after = ?3, cadence_epoch = ?4 WHERE id = 1 AND lease_token = ?2",
            vec![labels_json, uint(token)?, after.as_deref().map_or(SqlValue::Null, text), ms(epoch)],
        ));
    }
    if !stmts.is_empty() {
        c.sql.batch(stmts).await?;
    }
    Ok(pending.len() as i64 == ENROLL_PAGE || after.is_some())
}

pub(crate) fn due_sql() -> String {
    format!(
        "SELECT {EXTENT_COLS}, scrub_result, last_scrubbed_at, stat_at, full_at, \
           stat_loss_at, full_loss_at, stat_phase_at, full_phase_at \
         FROM scrub_copies s INDEXED BY scrub_copies_due CROSS JOIN extents e ON e.id = s.extent_id \
         WHERE s.backbone = ?1 AND MIN(stat_at, full_at) <= ?2 \
         ORDER BY MIN(stat_at, full_at), s.extent_id LIMIT ?3"
    )
}

fn watch_sql() -> String {
    format!(
        "SELECT {EXTENT_COLS}, scrub_result, last_scrubbed_at, scrub_next_at \
         FROM extents INDEXED BY extents_scrub_watch WHERE scrub_next_at <= ?1 \
         ORDER BY scrub_next_at, id LIMIT ?2"
    )
}

pub(crate) fn range_queries() -> [String; 4] {
    [
        due_sql(),
        watch_sql(),
        PENDING_SQL.into(),
        BACKFILL_SQL.into(),
    ]
}

fn parse_candidate(mut row: crate::ports::Row) -> Result<(ScrubCandidate, Cols)> {
    let width = EXTENT_COLS.split(',').count();
    if row.len() < width + 2 {
        return Err(BridgeError::Sql("row decode: scrub columns".into()));
    }
    let mut extra = Cols::new(row.split_off(width));
    let last = extra.opt_text()?.as_deref().and_then(ScrubResult::parse);
    let last_scrubbed_at = extra.opt_ms()?;
    Ok((
        ScrubCandidate {
            extent: extent_row(row)?,
            last,
            last_scrubbed_at,
            watch: false,
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
    let mut grouped = HashMap::new();
    for row in c.sql.query(&watch_sql(), &[ms(now), page.clone()]).await? {
        let (mut candidate, mut extra) = parse_candidate(row)?;
        candidate.watch = true;
        grouped.insert(
            candidate.extent.id.clone(),
            (UnixMs(extra.num()?), candidate),
        );
    }
    let sql = due_sql();
    for backbone in backbones {
        for row in c
            .sql
            .query(&sql, &[text(backbone), ms(now), page.clone()])
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

pub(super) async fn advance<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    updates: &[(ScrubCheck, UnixMs, Option<UnixMs>)],
) -> Result<bool> {
    let mut stmts = Vec::with_capacity(updates.len() + 1);
    stmts.push((
        concat!("INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ", run_holds!()),
        vec![text(extent.as_str()), uint(token)?],
    ));
    for (check, next, loss) in updates {
        let sql = if check.full {
            "UPDATE scrub_copies SET full_at = ?4, full_loss_at = ?5, full_phase_at = ?6 \
             WHERE extent_id = ?1 AND backbone = ?2 AND full_at = ?3"
        } else {
            "UPDATE scrub_copies SET stat_at = ?4, stat_loss_at = ?5, stat_phase_at = ?6 \
             WHERE extent_id = ?1 AND backbone = ?2 AND stat_at = ?3"
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

pub(super) async fn has_loss<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    backbones: &[String],
) -> Result<bool> {
    let rows = c
        .sql
        .query(
            "SELECT 1 FROM json_each(?2) j CROSS JOIN scrub_copies s \
         ON s.extent_id = ?1 AND s.backbone = j.value \
         WHERE s.stat_loss_at IS NOT NULL OR s.full_loss_at IS NOT NULL LIMIT 1",
            &[text(extent.as_str()), json(&backbones)?],
        )
        .await?;
    Ok(!rows.is_empty())
}

pub(super) async fn retire<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
) -> Result<bool> {
    let guard = concat!(
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ",
        run_holds!(),
        " OR NOT EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND safety_state = 'deleted')"
    );
    let key = text(extent.as_str());
    let stmts = vec![
        (guard, vec![key.clone(), uint(token)?]),
        (
            "DELETE FROM scrub_copies WHERE extent_id = ?1",
            vec![key.clone()],
        ),
        (
            "UPDATE extents SET scrub_enrolled = 0, scrub_next_at = NULL WHERE id = ?1",
            vec![key],
        ),
    ];
    Ok(guarded(c, stmts).await? == Guard::Applied(()))
}

pub(super) async fn record<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    result: ScrubResult,
    now: UnixMs,
    next_at: Option<UnixMs>,
) -> Result<bool> {
    let sql = concat!(
        "UPDATE extents SET scrub_result = ?3, last_scrubbed_at = ?4, scrub_next_at = ?5 \
          WHERE id = ?1 AND safety_state IN ('released', 'held', 'releasing') AND ",
        run_holds!()
    );
    let changed = c
        .sql
        .exec(
            sql,
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
    let rows = c
        .sql
        .query(
            concat!("SELECT ", live_ref!("?1")),
            &[text(extent.as_str())],
        )
        .await?;
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
    let sql = concat!(
        "UPDATE extents SET scrub_next_at = NULL WHERE id = ?1 AND ",
        run_holds!()
    );
    let changed = c
        .sql
        .exec(sql, &[text(extent.as_str()), uint(token)?])
        .await?;
    Ok(changed == 1)
}

pub(super) async fn free<S: Sql>(c: &SqlCatalog<S>, token: u64, _now: UnixMs) -> Result<bool> {
    let changed = c
        .sql
        .exec(
            "UPDATE scrub_state SET lease_until = NULL WHERE id = 1 AND lease_token = ?1",
            &[uint(token)?],
        )
        .await?;
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
        .exec(
            "UPDATE scrub_state SET last_incident = ?2, incident_clean = 0, incident_clean_by = NULL, \
               incident_body_by = ?3 WHERE id = 1 AND lease_token = ?1",
            &[uint(token)?, json(&blocked)?, json(&body)?],
        )
        .await?;
    Ok(changed == 1)
}

pub(super) async fn defer<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    next_at: UnixMs,
) -> Result<bool> {
    let sql = concat!(
        "UPDATE extents SET scrub_next_at = ?3 WHERE id = ?1 AND ",
        run_holds!()
    );
    let changed = c
        .sql
        .exec(sql, &[text(extent.as_str()), uint(token)?, ms(next_at)])
        .await?;
    Ok(changed == 1)
}

pub(super) async fn repin<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    (now, next_at): (UnixMs, UnixMs),
    unread: &[String],
) -> Result<bool> {
    // Fires unless this run holds the lease, the extent is released, its
    // posting is done, and a live generation references it: an extent of
    // a deleted or overwritten object is not brought back.
    let guard = concat!(
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ",
        run_holds!(),
        " OR NOT EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND safety_state = 'released') \
          OR NOT EXISTS (SELECT 1 FROM outbox WHERE extent_id = ?1 AND stage = 'done') \
          OR NOT ",
        live_ref!("?1")
    );
    let mut stmts: Vec<Stmt> = vec![
        (guard, vec![text(extent.as_str()), uint(token)?]),
        // Pinned again: no eviction listing from before can begin on it
        // (`evict_seq`), and the copy it holds is counted.
        (
            "UPDATE extents SET safety_state = 'held', evict_seq = evict_seq + 1, \
               hot_safety_bytes = cipher_size, scrub_result = 'repairing', \
               last_scrubbed_at = ?2, scrub_next_at = ?3 \
             WHERE id = ?1",
            vec![text(extent.as_str()), ms(now), ms(next_at)],
        ),
        // Back to verify, at once, from the first backbone, with its
        // attempts counted afresh. Any lease on the row is dead.
        (
            concat!(
                "UPDATE outbox SET stage = 'verify', next_at = ?2, cursor = 0, attempts = 0, \
                   last_error = NULL, updated_at = ?2, ",
                "lease_token = lease_token + 1, lease_owner = NULL, lease_until = NULL",
                " WHERE extent_id = ?1 AND stage = 'done'"
            ),
            vec![text(extent.as_str()), ms(now)],
        ),
    ];
    if !unread.is_empty() {
        // No provider served the bytes: a failed full read of the current
        // plan on each of these backbones, so verify reads them in full
        // and no release counts them until that read passes (whatever
        // `STAT` says, under either VERIFY_MODE).
        let labels =
            serde_json::to_string(unread).map_err(|_| BridgeError::Invalid("backbone labels"))?;
        stmts.push((
            "INSERT INTO verifications(extent_id, backbone, provider_id, verified_at, plan_rev, \
               articles_ok, articles_present, articles_total, result, kind) \
             SELECT e.id, j.value, 'scrub', ?3, e.plan_rev, 0, 0, COALESCE(e.article_count, 0), \
               'missing', 'body' FROM extents e, json_each(?2) j WHERE e.id = ?1 \
             ON CONFLICT(extent_id, backbone, verified_at) DO NOTHING",
            vec![text(extent.as_str()), text(&labels), ms(now)],
        ));
        // The existing verify job now owns these failures. If the repair
        // releases, require a fresh finding before another re-pin, and
        // still give the repaired copy its own scheduled BODY pass.
        stmts.push((
            "UPDATE scrub_copies SET stat_loss_at = NULL, full_loss_at = NULL, \
             full_at = MIN(full_at, ?3) WHERE extent_id = ?1 \
             AND backbone IN (SELECT value FROM json_each(?2))",
            vec![text(extent.as_str()), text(&labels), ms(next_at)],
        ));
    }
    Ok(guarded(c, stmts).await? == Guard::Applied(()))
}

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
            "UPDATE scrub_state SET lease_until = NULL, runs = runs + 1, \
               checked = checked + ?3, ok = ok + ?4, suspect = suspect + ?5, \
               repaired = repaired + ?6, unrecoverable = unrecoverable + ?7, \
               stalled = stalled + ?8, incidents = incidents + ?9, \
               bytes_read = bytes_read + ?10, last_run_at = ?1, \
               last_unrecoverable_at = CASE WHEN ?7 > 0 THEN ?1 ELSE last_unrecoverable_at END, \
               last_incident_at = CASE WHEN ?11 IS NOT NULL THEN ?1 ELSE last_incident_at END, \
               last_incident = ?12, incident_clean = ?13, incident_clean_by = ?14, incident_body_by = ?15 \
             WHERE id = 1 AND lease_token = ?2",
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
                if run.incident_body_by.is_empty() { SqlValue::Null } else { json(&run.incident_body_by)? },
            ],
        )
        .await?;
    Ok(changed == 1)
}
