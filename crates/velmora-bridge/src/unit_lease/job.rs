//! The two jobs a unit's alarm sends for itself (ADR-TENANCY §2.4 rules
//! 4 and 12, §8.5): `renew` (prove the unit's lease
//! from the stores and renew it) and `stamp_raise` (one raise of its
//! stamp per period with writes).
//!
//! Both are format 2 of the job message (W0b) only, and both name their
//! tenant **and** their unit. The bytes here are those of W0b's writer
//! (`jobmsg::UnitJob::message`, PR #190): `t`, `v` = 2, `at`, `tenant`,
//! `unit`, `state_seq`, `keys_seq`, in that order. A test pins them. Once
//! W0b is on `main` the alarm calls its writer and this copy goes.
//!
//! `at` is the unit's clock when the alarm sent the job: a hint for the
//! lag line only. The renewal's proof starts at the Worker's own clock
//! (RD-12), never at `at`.

use serde::Serialize;

use crate::types::UnixMs;
use crate::unit::name::UnitName;
use crate::unit::Seqs;

/// The format of a job message that names its tenant (W0b).
pub const UNIT_JOB_FORMAT: u8 = 2;

/// Which of the two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitJobKind {
    Renew,
    StampRaise,
}

impl UnitJobKind {
    /// The kind (`t`) as W0b's reader knows it (`UNIT_JOB_KINDS`).
    pub const fn as_str(self) -> &'static str {
        match self {
            UnitJobKind::Renew => "renew",
            UnitJobKind::StampRaise => "stamp_raise",
        }
    }
}

#[derive(Serialize)]
struct Message<'a> {
    t: &'static str,
    v: u8,
    at: UnixMs,
    tenant: &'a str,
    unit: u32,
    state_seq: u64,
    keys_seq: u64,
}

/// The message of job `kind` of the unit `own` at its numbers `seqs`,
/// sent at `at`. `None` for tenant 0, which has no unit (W0b refuses a
/// unit job of tenant 0).
pub fn message(kind: UnitJobKind, own: &UnitName, seqs: Seqs, at: UnixMs) -> Option<String> {
    if own.tenant.is_zero() {
        return None;
    }
    serde_json::to_string(&Message {
        t: kind.as_str(),
        v: UNIT_JOB_FORMAT,
        at,
        tenant: own.tenant.as_str(),
        unit: own.unit,
        state_seq: seqs.state_seq,
        keys_seq: seqs.keys_seq,
    })
    .ok()
}
