//! The scrub's catalogue (migration 0023, [`crate::scrub`]).
//!
//! - One run at a time: `scrub_state.lease_token` moves on with every
//!   take, and every write of a run names the token it took. A run whose
//!   lease was taken over writes nothing more.
//! - The due list is read from `extents_scrub_due` alone, a page at a
//!   time: no statement reads more than its page of extents.
//! - A result is one `UPDATE` of one extent. A healthy extent costs that
//!   row and its index entry, nothing else.
//! - The re-pin is one guarded batch: the extent goes back to `held` and
//!   its outbox row back to `verify` together, or neither does.

use super::objects::{extent_row, ms, text, uint, Cols, Stmt, EXTENT_COLS};
use super::uploads::guarded;
use super::SqlCatalog;
use crate::ports::{Guard, Sql, SqlValue};
use crate::types::{
    BridgeError, ExtentId, Result, ScrubCandidate, ScrubResult, ScrubRun, ScrubState, UnixMs,
};

/// The due key of the index, word for word.
macro_rules! due_key {
    () => {
        "COALESCE(scrub_next_at, \
                  COALESCE(last_verified_at, released_at, created_at) + 2592000000)"
    };
}

/// The condition of the index, word for word.
macro_rules! scrubbed {
    () => {
        "(safety_state = 'released' OR scrub_next_at IS NOT NULL)"
    };
}

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
               last_incident, incident_clean FROM scrub_state WHERE id = 1",
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
    })
}

/// The due query, as it runs.
pub(crate) fn due_sql() -> String {
    format!(
        "SELECT {EXTENT_COLS}, scrub_result, last_scrubbed_at FROM extents \
          INDEXED BY extents_scrub_due \
          WHERE {scrubbed} AND {key} <= ?1 \
          ORDER BY {key} LIMIT ?2",
        scrubbed = scrubbed!(),
        key = due_key!(),
    )
}

pub(super) async fn due<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    limit: u32,
) -> Result<Vec<ScrubCandidate>> {
    let sql = due_sql();
    let rows = c
        .sql
        .query(&sql, &[ms(now), SqlValue::Int(i64::from(limit))])
        .await?;
    let width = EXTENT_COLS.split(',').count();
    let mut out = Vec::with_capacity(rows.len());
    for mut row in rows {
        if row.len() != width + 2 {
            return Err(crate::types::BridgeError::Sql(
                "row decode: scrub columns".into(),
            ));
        }
        let extra = row.split_off(width);
        let mut r = Cols::new(extra);
        let last = r.opt_text()?.as_deref().and_then(ScrubResult::parse);
        let last_scrubbed_at = r.opt_ms()?;
        out.push(ScrubCandidate {
            extent: extent_row(row)?,
            last,
            last_scrubbed_at,
        });
    }
    Ok(out)
}

pub(super) async fn record<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    extent: &ExtentId,
    result: ScrubResult,
    now: UnixMs,
    next_at: UnixMs,
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
                ms(next_at),
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

pub(super) async fn block<S: Sql>(
    c: &SqlCatalog<S>,
    token: u64,
    blocked: &[String],
) -> Result<bool> {
    let labels =
        serde_json::to_string(blocked).map_err(|_| BridgeError::Invalid("backbone labels"))?;
    let changed = c
        .sql
        .exec(
            "UPDATE scrub_state SET last_incident = ?2, incident_clean = 0 \
             WHERE id = 1 AND lease_token = ?1",
            &[uint(token)?, text(&labels)],
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
               last_incident = ?12, incident_clean = ?13 \
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
            ],
        )
        .await?;
    Ok(changed == 1)
}
