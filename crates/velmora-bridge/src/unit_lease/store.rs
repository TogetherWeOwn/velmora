//! The lease's rows in a unit: `unit_lease` and `unit_revoked_ids`
//! (migration `u0002_lease.sql`; `docs/units.md`, rules 8 and 12).
//!
//! The unit object calls these inside its own transactions, over its
//! marked database. They only read and write the unit's SQLite: no I/O
//! (rule 4), every future is polled once.
//!
//! - [`read`]: the lease row, `None` when the unit has no lease table (a
//!   unit born before `u0002`): its lease is not known, so it is treated
//!   as expired and its `renew` fails (fail closed).
//! - [`renewed`], [`close`]: the two moves of `fresh_until`. `lease_hi`
//!   only grows, and a close keeps it (AM-2 check 3).
//! - [`note_write`]: the first write since the last stamp raise the alarm
//!   asked for (the due time of [`super::alarm::Duty::StampRaise`]).
//! - [`revoked`]: the revoked keys the unit holds, counted once per id:
//!   revoked key rows and listed ids it holds no row for. This is the
//!   number every answer carries and the renewal proof compares with the
//!   listing of `m/rk/<t>/` (SEC-6).
//! - [`revoke_listed`]: applies the ids a renewal listed: a key row is
//!   revoked, an id without a row is kept as listed.
//! - [`enforce_listed`]: after a key-chain apply, a row of a listed id is
//!   revoked whatever its record says (a revocation overrides every
//!   `m/k/` status, ADR §8.5).

use std::collections::BTreeSet;

use crate::ports::{Sql, SqlValue};
use crate::recovery::valid_key_id;
use crate::types::{BridgeError, Result, UnixMs};
use crate::unit::keys;
use crate::unit::object::poll_once;

use super::alarm::UnitAt;
use super::lease::FreshLease;

/// The most ids one `renew` may list (est). The proof lists every id of
/// the tenant's revocation directory when the counts differ; this bounds
/// the work of one call, and a tenant past it is refused, never served.
pub const MAX_LISTED: usize = 100_000;

/// The lease row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeaseRow {
    pub fresh_until: Option<UnixMs>,
    pub lease_hi: Option<UnixMs>,
    pub renew_tries: u32,
    pub failed_runs: u32,
    pub first_write_at: Option<UnixMs>,
}

impl LeaseRow {
    /// The lease it holds.
    pub fn lease(&self) -> FreshLease {
        FreshLease::from_stored(self.fresh_until)
    }

    /// What the alarm planner reads of it. `closed`: the unit refuses
    /// `renew` and every job (a `restoring` entry, a recorded rollback).
    pub fn at<'a>(&self, lease: &'a FreshLease, closed: bool) -> UnitAt<'a> {
        UnitAt {
            lease,
            closed,
            renew_tries: self.renew_tries,
            failed_runs: self.failed_runs,
        }
    }
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}

fn has_table<S: Sql>(sql: &S, name: &str) -> Result<bool> {
    let rows = poll_once(sql.query(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        &[SqlValue::Text(name.into())],
    ))??;
    Ok(matches!(
        rows.first().and_then(|r| r.first()),
        Some(SqlValue::Int(1))
    ))
}

fn time(v: &SqlValue) -> Result<Option<UnixMs>> {
    match v {
        SqlValue::Null => Ok(None),
        SqlValue::Int(n) => Ok(Some(UnixMs(*n))),
        _ => Err(decode("unit_lease time")),
    }
}

fn count(v: &SqlValue) -> Result<u32> {
    match v {
        SqlValue::Int(n) => u32::try_from(*n).map_err(|_| decode("unit_lease count")),
        _ => Err(decode("unit_lease count")),
    }
}

/// The lease row. `None` = no lease table: a unit born before `u0002`.
/// A table without its row reads as a lease never issued.
pub fn read<S: Sql>(sql: &S) -> Result<Option<LeaseRow>> {
    if !has_table(sql, "unit_lease")? {
        return Ok(None);
    }
    let rows = poll_once(sql.query(
        "SELECT fresh_until, lease_hi, renew_tries, failed_runs, first_write_at \
           FROM unit_lease WHERE id = 1",
        &[],
    ))??;
    let Some(r) = rows.first() else {
        return Ok(Some(LeaseRow::default()));
    };
    if r.len() != 5 {
        return Err(decode("unit_lease"));
    }
    Ok(Some(LeaseRow {
        fresh_until: time(&r[0])?,
        lease_hi: time(&r[1])?,
        renew_tries: count(&r[2])?,
        failed_runs: count(&r[3])?,
        first_write_at: time(&r[4])?,
    }))
}

fn write_one<S: Sql>(sql: &S, stmt: &str, params: &[SqlValue]) -> Result<()> {
    let n = poll_once(sql.exec(stmt, params))??;
    if n != 1 {
        return Err(decode("unit_lease"));
    }
    Ok(())
}

/// A renewal set the lease to `until`: `lease_hi` follows it up, and the
/// alarm's count of renew tries starts again.
pub fn renewed<S: Sql>(sql: &S, until: UnixMs) -> Result<()> {
    write_one(
        sql,
        "UPDATE unit_lease SET fresh_until = ?1, \
           lease_hi = CASE WHEN lease_hi IS NULL OR lease_hi < ?1 THEN ?1 ELSE lease_hi END, \
           renew_tries = 0 WHERE id = 1",
        &[SqlValue::Int(until.0)],
    )
}

/// Ends the lease at once (the `sync` that sets a `restoring` entry,
/// §8.6 step 2). `lease_hi` is kept, and moved up to the lease that
/// ended if it lagged.
pub fn close<S: Sql>(sql: &S) -> Result<()> {
    write_one(
        sql,
        "UPDATE unit_lease SET \
           lease_hi = CASE WHEN fresh_until IS NOT NULL AND (lease_hi IS NULL OR lease_hi < fresh_until) \
                      THEN fresh_until ELSE lease_hi END, \
           fresh_until = NULL WHERE id = 1",
        &[],
    )
}

/// A call changed rows at `now`. `true` = it is the first write since
/// the last stamp raise of the alarm: the raise is due one period from
/// now, and the caller makes sure the alarm is armed for it.
pub fn note_write<S: Sql>(sql: &S, now: UnixMs) -> Result<bool> {
    let n = poll_once(sql.exec(
        "UPDATE unit_lease SET first_write_at = ?1 WHERE id = 1 AND first_write_at IS NULL",
        &[SqlValue::Int(now.0)],
    ))??;
    Ok(n == 1)
}

/// What one alarm run did, as the row keeps it: a renew job sent (one
/// more try), the stamp raise asked for (no write since), a duty that
/// failed (one more failed run) or none (reset).
pub fn alarm_ran<S: Sql>(sql: &S, sent_renew: bool, raised: bool, failed: bool) -> Result<()> {
    write_one(
        sql,
        "UPDATE unit_lease SET \
           renew_tries = renew_tries + ?1, \
           first_write_at = CASE WHEN ?2 = 1 THEN NULL ELSE first_write_at END, \
           failed_runs = CASE WHEN ?3 = 1 THEN failed_runs + 1 ELSE 0 END \
         WHERE id = 1",
        &[
            SqlValue::Int(i64::from(sent_renew)),
            SqlValue::Int(i64::from(raised)),
            SqlValue::Int(i64::from(failed)),
        ],
    )
}

/// The revoked keys the unit holds, each id once: key rows that are
/// `revoked`, and listed ids without a row. `None` = the unit holds no
/// key and no listed id (its answers carry no `revoked`).
pub fn revoked<S: Sql>(sql: &S) -> Result<Option<u64>> {
    if !has_table(sql, "unit_revoked_ids")? || !has_table(sql, "unit_keys")? {
        return Ok(None);
    }
    let rows = poll_once(sql.query(
        "SELECT (SELECT count(*) FROM ( \
                   SELECT id FROM unit_keys WHERE status = 'revoked' \
                   UNION SELECT id FROM unit_revoked_ids)), \
                EXISTS (SELECT 1 FROM unit_keys) OR EXISTS (SELECT 1 FROM unit_revoked_ids)",
        &[],
    ))??;
    let r = rows.first().ok_or_else(|| decode("revoked count"))?;
    match (r.first(), r.get(1)) {
        (Some(SqlValue::Int(_)), Some(SqlValue::Int(0))) => Ok(None),
        (Some(SqlValue::Int(n)), Some(SqlValue::Int(_))) if *n >= 0 => Ok(Some(*n as u64)),
        _ => Err(decode("revoked count")),
    }
}

/// Whether the unit holds `id` as revoked: a `revoked` key row, or a
/// listed id.
pub fn holds_revoked<S: Sql>(sql: &S, id: &str) -> Result<bool> {
    let rows = poll_once(sql.query(
        "SELECT EXISTS (SELECT 1 FROM unit_keys WHERE id = ?1 AND status = 'revoked') \
             OR EXISTS (SELECT 1 FROM unit_revoked_ids WHERE id = ?1)",
        &[SqlValue::Text(id.to_string())],
    ))??;
    match rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Int(n)) => Ok(*n == 1),
        _ => Err(decode("holds revoked")),
    }
}

/// Why a list of revocations was not applied. Nothing was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListRefused {
    /// More than [`MAX_LISTED`] ids.
    TooMany,
    /// An id that is not an access key id (the Worker skips those when
    /// it lists, so one here is a bug in the caller).
    Malformed,
}

/// Applies the ids a renewal listed (`m/rk/<t>/<id>`): a key row is
/// revoked (and the catalogue's served rows rebuilt, down its `made_by`
/// chain), an id without a row is kept in `unit_revoked_ids`. Setting
/// `revoked` twice changes nothing. Answers how many ids changed.
pub fn revoke_listed<S: Sql>(
    sql: &S,
    ids: &[String],
    now: UnixMs,
) -> Result<std::result::Result<usize, ListRefused>> {
    if ids.len() > MAX_LISTED {
        return Ok(Err(ListRefused::TooMany));
    }
    if !ids.iter().all(|id| valid_key_id(id)) {
        return Ok(Err(ListRefused::Malformed));
    }
    let mut touched = BTreeSet::new();
    let mut changed = 0;
    for id in ids {
        let rows = poll_once(sql.query(
            "SELECT status FROM unit_keys WHERE id = ?1",
            &[SqlValue::Text(id.clone())],
        ))??;
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Text(status)) if status == "revoked" => {}
            Some(SqlValue::Text(_)) => {
                poll_once(sql.exec(
                    "UPDATE unit_keys SET status = 'revoked' WHERE id = ?1",
                    &[SqlValue::Text(id.clone())],
                ))??;
                touched.insert(id.clone());
                changed += 1;
            }
            Some(_) => return Err(decode("unit_keys status")),
            None => {
                changed += poll_once(sql.exec(
                    "INSERT INTO unit_revoked_ids(id, listed_at) VALUES (?1, ?2) \
                     ON CONFLICT(id) DO NOTHING",
                    &[SqlValue::Text(id.clone()), SqlValue::Int(now.0)],
                ))?? as usize;
            }
        }
    }
    keys::project(sql, &touched)?;
    Ok(Ok(changed))
}

/// After a key-chain apply: every key row whose id a renewal listed is
/// revoked, whatever the record said, and its served rows rebuilt.
pub fn enforce_listed<S: Sql>(sql: &S) -> Result<usize> {
    let rows = poll_once(sql.query(
        "SELECT k.id FROM unit_revoked_ids r JOIN unit_keys k ON k.id = r.id \
          WHERE k.status <> 'revoked'",
        &[],
    ))??;
    let mut touched = BTreeSet::new();
    for r in rows {
        let Some(SqlValue::Text(id)) = r.into_iter().next() else {
            return Err(decode("unit_revoked_ids id"));
        };
        poll_once(sql.exec(
            "UPDATE unit_keys SET status = 'revoked' WHERE id = ?1",
            &[SqlValue::Text(id.clone())],
        ))??;
        touched.insert(id);
    }
    keys::project(sql, &touched)?;
    Ok(touched.len())
}
