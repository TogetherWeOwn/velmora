//! `Recount` (`docs/units.md`, "Recount"; amendment AM-27): the recount
//! of migration 0020 as a unit call, for a closed unit.
//!
//! A unit born from a `restore` token starts with its usage counters off
//! (AM-3), and so does a unit whose counters the move switched off; the
//! lift is refused while any counter is off. Jobs are refused while the
//! unit is closed, so the cron's recount job cannot turn them on. The
//! restore gate (ADR §8.6 step 7.6) and the move tool (before V2) call
//! `Recount` instead:
//!
//! - `start` begins a pass that adopts its figures (a pass under way is
//!   started again); `step` runs one bounded chunk, in one transaction
//!   each. The pass's last step adopts row 2 into row 1 and sets
//!   `all_x = all_o = all_g = 1`: the catalogue's own recount
//!   (`usage_recount_start`, `usage_recount_step`).
//! - It is accepted only while the unit's `restoring` entry is set.
//! - It is the **move's** when `unit_import_move.since_seq` equals the
//!   current `restoring_since`. Then it also needs the import's seal
//!   (AM-29), tenant 0's verified head moving to this tenant and not
//!   older than the import's, with `flips + 1` equal to the sealed
//!   `move_ordinal`, the caller's numbers equal to the unit's (as an
//!   import batch's), and no `move` report having lifted the unit yet.
//! - Any other `Recount` is the restore gate's and needs none of these.

use serde::{Deserialize, Serialize};

use super::import::{self, MoveHead};
use super::name::TenantId;
use crate::ports::Sql;
use crate::types::Result;

/// The two steps of a recount.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecountCall {
    /// Begins a pass (again, if one is under way).
    Start {},
    /// One chunk of at most `chunk` rows (clamped to the catalogue's
    /// chunk bound), or the end of the pass.
    Step { chunk: u32 },
}

/// Why a `Recount` was refused. Nothing was counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecountRefusal {
    /// The unit has no `restoring` entry: its counters are the cron's.
    NotRestoring,
    /// A move's recount before the import's seal, or for another window.
    ImportNotSealed,
    /// A move's recount without tenant 0's head moving to this tenant, or
    /// with an older head than the import's, or after the move's lift.
    MoveNotBound,
}

/// Whether a `Recount` now would be the move's: the import filled the
/// entry the unit is closed under.
pub fn is_move<S: Sql>(sql: &S, restoring_since: Option<u64>) -> Result<bool> {
    Ok(restoring_since.is_some() && import::import_since(sql)? == restoring_since)
}

/// The binding of a `Recount` (module doc), inside the caller's
/// transaction. For the move's, raises the tenant-0 seq the unit has
/// seen to `head`'s.
pub fn bound<S: Sql>(
    sql: &S,
    own_tenant: &TenantId,
    own_unit: u32,
    restoring_since: Option<u64>,
    head: Option<&MoveHead>,
) -> Result<std::result::Result<(), RecountRefusal>> {
    let Some(since) = restoring_since else {
        return Ok(Err(RecountRefusal::NotRestoring));
    };
    if !is_move(sql, restoring_since)? {
        return Ok(Ok(()));
    }
    let Some(head) = head else {
        return Ok(Err(RecountRefusal::MoveNotBound));
    };
    if import::move_lifted(sql)? {
        return Ok(Err(RecountRefusal::MoveNotBound));
    }
    let Some(move_ordinal) = import::sealed(sql)? else {
        return Ok(Err(RecountRefusal::ImportNotSealed));
    };
    if head.flips.checked_add(1) != Some(move_ordinal) {
        return Ok(Err(RecountRefusal::ImportNotSealed));
    }
    let not_older = import::seen_t0_seq(sql)?.is_some_and(|seen| head.seq >= seen);
    if !import::bound_to_move(own_tenant, own_unit, restoring_since, since, head) || !not_older {
        return Ok(Err(RecountRefusal::MoveNotBound));
    }
    import::see_t0_seq(sql, head.seq)?;
    Ok(Ok(()))
}
