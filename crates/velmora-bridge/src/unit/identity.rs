//! The identity check of every call (`docs/units.md`, rule 5).
//!
//! A call carries the tenant and unit it is addressed to and the two
//! chain numbers the caller knows: `state_seq` (the tenant chain
//! `m/t/<t>/`) and `keys_seq` (the key chain `m/k/<t>/`). The unit
//! compares them with its own:
//!
//! | Case | Verdict |
//! |---|---|
//! | a name that is not the object's own | refuse and alarm |
//! | either number above the unit's | `sync_needed`: the Worker verifies the records up to the head and calls `sync` first |
//! | a request with a lower number | answer the unit's own numbers and do nothing; the Worker refreshes and retries once |
//! | a job with a lower number | answer `Stale` with the unit's own numbers and do nothing; the consumer runs the job once more with them (AM-50) |
//! | a job with no number | refuse (`stale_job`): no writer sends a job without numbers, so the consumer pages |
//! | a fan-out sub-request with lower numbers | serve only if the unit's own tables still allow this reader (`fanout`) |
//! | both numbers equal | proceed |
//!
//! A higher number wins over a lower one: a call with `state_seq` above
//! and `keys_seq` below the unit's is `sync_needed`. The Worker's own
//! calls (`provision`, `sync`, `renew`) carry verified records, not a
//! caller's view, and are not judged here.

use serde::{Deserialize, Serialize};

use super::name::UnitName;

/// Who made a call, for the identity check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    /// An S3 request (or a management request) as it arrives.
    Request,
    /// A queue job.
    Job,
    /// A sub-request of a large GET, under a grant made earlier.
    Fanout,
    /// The Worker's own calls: `provision`, `sync`, `renew`.
    Worker,
}

/// The two chain numbers of a unit, or of a caller's view of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seqs {
    pub state_seq: u64,
    pub keys_seq: u64,
}

/// The outcome of [`check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The numbers agree: run the call.
    Proceed,
    /// The caller knows a newer record: it must `sync` first.
    SyncNeeded,
    /// A request or a job from a caller behind the unit: answer the
    /// unit's own numbers and do nothing else (a job runs once more with
    /// them, AM-50).
    Stale,
    /// A fan-out sub-request behind the unit: serve only after the
    /// unit's own tables allow the reader, in the same transaction.
    FanoutCheck,
    /// Refused. `alarm`: the Worker pages (a name that is not ours).
    Refused { reason: Refusal, alarm: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// The call names another tenant or unit than this object.
    WrongName,
    /// A job without numbers. (A job with lower ones is answered
    /// [`Verdict::Stale`], AM-50; the name is the wire form's.)
    StaleJob,
    /// A call that is not a Worker call carried no numbers.
    NoNumbers,
}

/// Rule 5. `own_name` is the object's name; `own` its numbers.
pub fn check(
    own_name: &UnitName,
    own: Seqs,
    called: &UnitName,
    kind: CallKind,
    seqs: Option<Seqs>,
) -> Verdict {
    if called != own_name {
        return Verdict::Refused {
            reason: Refusal::WrongName,
            alarm: true,
        };
    }
    if kind == CallKind::Worker {
        return Verdict::Proceed;
    }
    let Some(seqs) = seqs else {
        let reason = match kind {
            CallKind::Job => Refusal::StaleJob,
            _ => Refusal::NoNumbers,
        };
        return Verdict::Refused {
            reason,
            alarm: false,
        };
    };
    if seqs.state_seq > own.state_seq || seqs.keys_seq > own.keys_seq {
        return Verdict::SyncNeeded;
    }
    if seqs == own {
        return Verdict::Proceed;
    }
    match kind {
        CallKind::Request | CallKind::Job => Verdict::Stale,
        CallKind::Fanout => Verdict::FanoutCheck,
        CallKind::Worker => Verdict::Proceed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::name::TenantId;

    fn name(unit: u32) -> UnitName {
        UnitName::new(TenantId::parse("t_00000000000000a1").unwrap(), unit)
    }

    fn s(state_seq: u64, keys_seq: u64) -> Option<Seqs> {
        Some(Seqs {
            state_seq,
            keys_seq,
        })
    }

    const OWN: Seqs = Seqs {
        state_seq: 5,
        keys_seq: 9,
    };

    #[test]
    fn another_name_is_refused_with_an_alarm_for_every_kind() {
        let other_tenant = UnitName::new(TenantId::parse("t_00000000000000a2").unwrap(), 0);
        for kind in [
            CallKind::Request,
            CallKind::Job,
            CallKind::Fanout,
            CallKind::Worker,
        ] {
            for called in [name(1), other_tenant.clone()] {
                assert_eq!(
                    check(&name(0), OWN, &called, kind, s(5, 9)),
                    Verdict::Refused {
                        reason: Refusal::WrongName,
                        alarm: true
                    }
                );
            }
        }
    }

    #[test]
    fn equal_numbers_proceed() {
        for kind in [CallKind::Request, CallKind::Job, CallKind::Fanout] {
            assert_eq!(
                check(&name(0), OWN, &name(0), kind, s(5, 9)),
                Verdict::Proceed
            );
        }
    }

    #[test]
    fn a_higher_number_needs_a_sync_whatever_the_other_says() {
        for kind in [CallKind::Request, CallKind::Job, CallKind::Fanout] {
            for seqs in [s(6, 9), s(5, 10), s(6, 1), s(0, 10)] {
                assert_eq!(
                    check(&name(0), OWN, &name(0), kind, seqs),
                    Verdict::SyncNeeded,
                    "{kind:?} {seqs:?}"
                );
            }
        }
    }

    #[test]
    fn a_lower_number_depends_on_who_calls() {
        for seqs in [s(4, 9), s(5, 8), s(0, 0)] {
            assert_eq!(
                check(&name(0), OWN, &name(0), CallKind::Request, seqs),
                Verdict::Stale
            );
            // AM-50: a job behind the unit gets the unit's numbers.
            assert_eq!(
                check(&name(0), OWN, &name(0), CallKind::Job, seqs),
                Verdict::Stale
            );
            assert_eq!(
                check(&name(0), OWN, &name(0), CallKind::Fanout, seqs),
                Verdict::FanoutCheck
            );
        }
    }

    #[test]
    fn a_job_without_numbers_is_refused() {
        assert_eq!(
            check(&name(0), OWN, &name(0), CallKind::Job, None),
            Verdict::Refused {
                reason: Refusal::StaleJob,
                alarm: false
            }
        );
        for kind in [CallKind::Request, CallKind::Fanout] {
            assert_eq!(
                check(&name(0), OWN, &name(0), kind, None),
                Verdict::Refused {
                    reason: Refusal::NoNumbers,
                    alarm: false
                }
            );
        }
    }

    #[test]
    fn the_workers_own_calls_are_not_judged_by_numbers() {
        for seqs in [None, s(0, 0), s(99, 99)] {
            assert_eq!(
                check(&name(0), OWN, &name(0), CallKind::Worker, seqs),
                Verdict::Proceed
            );
        }
    }
}
