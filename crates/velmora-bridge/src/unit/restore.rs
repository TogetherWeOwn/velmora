//! The restore calls (`docs/units.md`, "Restore"; ADR §8.6 step 5,
//! amendment AM-2).
//!
//! A unit is rolled back only by the restore procedure, in two calls:
//!
//! 1. `restore_prepare(since)` answers the unit's current bookmark, the
//!    **undo bookmark**. The tool seals it under the tenant key to
//!    `cb/<t>/<unit>/undo/<S>-<n+1>` before it makes the second call
//!    (AM-1: a bookmark leaves the unit only sealed; the unit holds no
//!    key, so the Worker seals it, and nothing stores or logs it in
//!    clear).
//! 2. `restore(token, target, expect_undo)`. The target is a time (the
//!    unit turns it into a bookmark itself) or an unsealed undo bookmark,
//!    when an earlier restore is being undone.
//!
//! **The unit never closes itself for a restore; both calls are refused
//! unless it is already closed.** Before anything is armed, the unit
//! checks:
//!
//! 1. its `restoring` entry is set, at the `since_seq` the call names (for
//!    `restore`, the seq of its `restore` token);
//! 2. its lease has expired (a missing lease counts as expired: a unit
//!    that never issued one);
//! 3. its clock is at least max(`closed_at` + T, `lease_hi`) + 60 s, where
//!    `closed_at` is the unit's own time of the `sync` that set the entry
//!    and `lease_hi` the latest `fresh_until` it ever held;
//! 4. (`restore` only) its current bookmark is still `expect_undo`: the
//!    unit wrote nothing since `restore_prepare`. A refusal here means the
//!    tool runs `restore_prepare` again.
//! 5. (AM-46) both calls are refused while an import exists that no
//!    `move` report has lifted (`move_not_lifted`), so no undo bookmark
//!    is taken once a move's first batch landed (in the span between the
//!    move's close and its first batch the unit cannot tell the move's
//!    entry from a restore's); `restore` refuses a time target before the
//!    move floor, the later of the unit's own lift and the `floor_ms` the
//!    tenant chain keeps for it (AM-67; `before_move_lift`), or before
//!    the unit's birth (`before_birth`), each with [`LIFT_SLACK_MS`].
//!
//! Checks 1 to 3 run in the unit's own code over its tables
//! ([`Unit::pitr_step`](super::object::Unit::pitr_step)); check 4 and the
//! bookmark calls need the object's storage, which only the object class
//! reaches ([`drive`], with [`PointInTimePort`]). A unit born from a
//! `restore` token has `closed_at = born_at` and no lease row, so a unit
//! that was gone or unborn passes checks 2 and 3 at T + 60 s after its
//! birth. A unit without a lease table is refused: its lease is unknown.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::call::{Refused, UnitAnswer};
use super::identity::Seqs;
use super::object::poll_once;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result, UnixMs};

/// The lease term T (ADR §2.4 rule 12, est 10 min). A restore waits at
/// least this long after the close, so no lease issued before the close
/// is still valid.
pub const LEASE_TERM_MS: i64 = 600_000;
/// The margin after T and after the latest lease, before a restore.
pub const RESTORE_MARGIN_MS: i64 = 60_000;
/// The margin after the owner move's lift, and after the unit's birth,
/// within which a restore to a time is still refused: each recorded time
/// is its call's clock, a little before the commit (est; the S3 drill
/// measures `getBookmarkForTime`'s offset, AM-46).
pub const LIFT_SLACK_MS: i64 = 60_000;
/// The longest bookmark the unit takes back (est).
pub const MAX_BOOKMARK: usize = 1024;

/// A point-in-time bookmark of this object. Opaque; `Debug` shows its
/// length only, so a log line never holds one in clear (AM-1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bookmark(pub String);

impl fmt::Debug for Bookmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bookmark({} bytes)", self.0.len())
    }
}

/// What a restore goes back to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "to", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreTarget {
    /// A time within the platform's history; the unit turns it into a
    /// bookmark (`getBookmarkForTime`).
    Time { at_ms: i64 },
    /// An undo bookmark that the tool unsealed, to undo an earlier
    /// restore.
    Bookmark { bookmark: Bookmark },
}

/// Why a restore call was refused. Nothing was armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreRefusal {
    /// The unit's `restoring` entry is not set, or not at the seq named.
    NotRestoring,
    /// The token is not a `restore` token for this unit and entry.
    WrongToken,
    /// The unit's lease has not expired.
    LeaseLive,
    /// The unit keeps no lease table: whether a lease is live is not
    /// known.
    LeaseUnknown,
    /// Less than max(`closed_at` + T, `lease_hi`) + 60 s since the close.
    TooSoon,
    /// The unit's bookmark is no longer `expect_undo`: it wrote since
    /// `restore_prepare`. Prepare again.
    Moved,
    /// A bookmark too long to be one.
    Malformed,
    /// The call reached a unit without point-in-time storage (natively,
    /// through `handle`): restores go through the object class.
    NoPointInTime,
    /// A time target before the owner move's lift (the move's window).
    BeforeMoveLift,
    /// An import exists that no `move` report has lifted yet (AM-46): no
    /// undo bookmark is taken, so none from before the lift can exist.
    /// The unit is closed mid-move and has never served a request; the
    /// move's own give-up or lift ends this.
    MoveNotLifted,
    /// A time target before this incarnation's birth (AM-46): it would
    /// bring back the unit that was replaced (a dump restore into a gone
    /// or unborn unit, or a re-creation after `deleteAll()`).
    BeforeBirth,
}

/// The lease as the restore checks read it: `fresh_until` and the latest
/// `fresh_until` the unit ever held. Kept by the lease's own table
/// (`unit_lease`); a unit without it never issued a lease.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeaseView {
    pub fresh_until: Option<i64>,
    pub lease_hi: Option<i64>,
}

/// Reads the lease view: `None` when the unit has no `unit_lease` table
/// (its lease is not known, so no restore is armed); a table without its
/// row is a unit that never issued a lease.
pub fn lease_view<S: Sql>(sql: &S) -> Result<Option<LeaseView>> {
    let has = poll_once(sql.query(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'unit_lease'",
        &[],
    ))??;
    if !matches!(has.first().and_then(|r| r.first()), Some(SqlValue::Int(1))) {
        return Ok(None);
    }
    let rows = poll_once(sql.query(
        "SELECT fresh_until, lease_hi FROM unit_lease WHERE id = 1",
        &[],
    ))??;
    let Some(r) = rows.first() else {
        return Ok(Some(LeaseView::default()));
    };
    let opt = |v: &SqlValue| match v {
        SqlValue::Null => Ok(None),
        SqlValue::Int(n) => Ok(Some(*n)),
        _ => Err(BridgeError::Sql("unit: row decode: unit_lease".into())),
    };
    Ok(Some(LeaseView {
        fresh_until: opt(&r[0])?,
        lease_hi: opt(&r[1])?,
    }))
}

/// Checks 1 to 3. `restoring_since` and `closed_at` are the unit's own;
/// `since` the seq the call names.
pub fn closed_long_enough(
    restoring_since: Option<u64>,
    closed_at: Option<i64>,
    lease: Option<LeaseView>,
    since: u64,
    now: UnixMs,
) -> std::result::Result<(), RestoreRefusal> {
    if restoring_since != Some(since) {
        return Err(RestoreRefusal::NotRestoring);
    }
    let Some(lease) = lease else {
        return Err(RestoreRefusal::LeaseUnknown);
    };
    if lease.fresh_until.is_some_and(|until| now.0 < until) {
        return Err(RestoreRefusal::LeaseLive);
    }
    // A closed unit always has its close time; without one it is not
    // known to be closed long enough.
    let Some(closed_at) = closed_at else {
        return Err(RestoreRefusal::TooSoon);
    };
    // The latest lease the unit held: `lease_hi`, and `fresh_until` in
    // case the high mark lags it.
    let latest = lease.lease_hi.max(lease.fresh_until).unwrap_or(i64::MIN);
    let from = closed_at.saturating_add(LEASE_TERM_MS).max(latest);
    if now.0 < from.saturating_add(RESTORE_MARGIN_MS) {
        return Err(RestoreRefusal::TooSoon);
    }
    Ok(())
}

/// What the object class does after the unit's own checks.
#[derive(Clone, Debug, PartialEq)]
pub enum PitrStep {
    /// The answer, with no storage call.
    Answer(UnitAnswer),
    /// `restore_prepare` passed: answer the current bookmark.
    Prepare { seqs: Seqs },
    /// `restore` passed checks 1 to 3: check 4, resolve the target, arm.
    Restore {
        target: RestoreTarget,
        expect_undo: Bookmark,
    },
}

/// The object's point-in-time calls (`workers/unit/src/pitr.rs`).
#[allow(async_fn_in_trait)]
pub trait PointInTimePort {
    /// The bookmark of the current state.
    async fn current(&self) -> Result<String>;
    /// The bookmark of `unix_ms`.
    async fn at(&self, unix_ms: i64) -> Result<String>;
    /// Arms the restore and ends the session in one step. Returns only
    /// when the runtime refused the bookmark (then with an error).
    async fn restore_now(&self, bookmark: &str) -> Result<()>;
}

/// Runs a [`PitrStep`] against the object's storage.
pub async fn drive<P: PointInTimePort>(step: PitrStep, pitr: &P) -> UnitAnswer {
    match step {
        PitrStep::Answer(a) => a,
        PitrStep::Prepare { seqs } => match pitr.current().await {
            Ok(b) => UnitAnswer::UndoBookmark {
                seqs,
                bookmark: Bookmark(b),
            },
            Err(_) => pitr_failed(),
        },
        PitrStep::Restore {
            target,
            expect_undo,
        } => {
            match pitr.current().await {
                Ok(now) if now == expect_undo.0 => {}
                Ok(_) => {
                    return UnitAnswer::Refused {
                        reason: Refused::Restore(RestoreRefusal::Moved),
                        alarm: false,
                    }
                }
                Err(_) => return pitr_failed(),
            }
            let to = match target {
                RestoreTarget::Time { at_ms } => match pitr.at(at_ms).await {
                    Ok(b) => b,
                    Err(_) => return pitr_failed(),
                },
                RestoreTarget::Bookmark { bookmark } => bookmark.0,
            };
            // On success the object restarts and this request never
            // answers. An error is the runtime refusing the bookmark:
            // nothing is armed. A plain return means armed without the
            // restart: the tool must treat the unit as restored.
            match pitr.restore_now(&to).await {
                Ok(()) => UnitAnswer::Failed {
                    class: "pitr_armed".into(),
                },
                Err(_) => pitr_failed(),
            }
        }
    }
}

fn pitr_failed() -> UnitAnswer {
    UnitAnswer::Failed {
        class: "pitr".into(),
    }
}
