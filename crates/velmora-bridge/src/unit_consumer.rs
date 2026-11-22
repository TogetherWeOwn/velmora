//! What the queue consumer does with a managed tenant's job after it ran
//! against the tenant's unit (round 3 L1-Q7; ADR-TENANCY §2.4 rule 5).
//!
//! The job runs over a [`crate::tenant_catalog::TenantCatalog`], which
//! keeps the first refusal the unit gave
//! ([`crate::tenant_catalog::TenantCatalog::refusal`]). When there is
//! one, it decides the delivery, whatever `run_job` answered:
//!
//! | Refusal | Delivery | Why |
//! |---|---|---|
//! | stale job (the job's numbers are below the unit's, or missing) | acknowledged | rule 5: "runs the job again or drops it". The message only names an outbox row in the unit; the unit's dispatcher sends the row again with its current numbers |
//! | closed (restoring, or the lease ran out) | acknowledged | jobs are refused while the unit is closed; its outbox rows stay and are sent again once it opens |
//! | sync needed (the unit is behind the chain) | handed back until the dead-letter queue, which pages | the Worker must read the chain and call `sync` first (rule 5); this build has no consumer-side sync, so an operator must look |
//! | unborn | dead-letter queue, alert | rule 7: a listed unit with no certificate is "catalogue lost" and pages |
//! | any other refusal | dead-letter queue, alert | the unit alarms; the Worker says so too |
//!
//! No delivery is dropped in silence: each refusal is one log line with a
//! fixed code, and an alert for the ones that page. Nothing here reads
//! or writes a catalogue.

use crate::jobmsg::REFUSED_RETRY_DELAY_SECS;
use crate::tenant_catalog::{UNIT_CLOSED, UNIT_STALE_JOB, UNIT_SYNC_NEEDED, UNIT_UNBORN};
use crate::types::JobOutcome;

/// The delivery of a job the unit refused, and its log line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AfterRefusal {
    pub outcome: JobOutcome,
    /// A fixed word: never a field of the message or a unit's text.
    pub code: &'static str,
    /// The line is an alert (the delivery goes to the dead-letter queue).
    pub alert: bool,
}

/// The delivery of a job whose unit refused it with `refusal` (one of the
/// `UNIT_*` texts of [`crate::tenant_catalog`]). See the
/// [module](self).
pub fn after_refusal(refusal: &str) -> AfterRefusal {
    let dead_letter = |code| AfterRefusal {
        outcome: JobOutcome::Retry {
            delay_secs: REFUSED_RETRY_DELAY_SECS,
        },
        code,
        alert: true,
    };
    let drop = |code| AfterRefusal {
        outcome: JobOutcome::Ack,
        code,
        alert: false,
    };
    match refusal {
        UNIT_STALE_JOB => drop("stale_job"),
        UNIT_CLOSED => drop("closed"),
        UNIT_SYNC_NEEDED => dead_letter("sync_needed"),
        UNIT_UNBORN => dead_letter("unborn"),
        _ => dead_letter("refused"),
    }
}

/// The delivery of a managed tenant's job: `outcome` as `run_job` gave
/// it when the unit refused nothing, else [`after_refusal`].
pub fn delivery(outcome: JobOutcome, refusal: Option<&str>) -> (JobOutcome, Option<AfterRefusal>) {
    match refusal {
        None => (outcome, None),
        Some(r) => {
            let after = after_refusal(r);
            (after.outcome, Some(after))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant_catalog::UNIT_REFUSED;

    #[test]
    fn stale_and_closed_are_dropped_the_rest_pages() {
        for (refusal, ack, code) in [
            (UNIT_STALE_JOB, true, "stale_job"),
            (UNIT_CLOSED, true, "closed"),
            (UNIT_SYNC_NEEDED, false, "sync_needed"),
            (UNIT_UNBORN, false, "unborn"),
            (UNIT_REFUSED, false, "refused"),
            ("anything else", false, "refused"),
        ] {
            let after = after_refusal(refusal);
            assert_eq!(after.code, code, "{refusal}");
            assert_eq!(after.alert, !ack, "{refusal}");
            let want = match ack {
                true => JobOutcome::Ack,
                false => JobOutcome::Retry {
                    delay_secs: REFUSED_RETRY_DELAY_SECS,
                },
            };
            assert_eq!(after.outcome, want, "{refusal}");
        }
    }

    /// A refusal decides the delivery whatever `run_job` answered; with
    /// none, its answer stands.
    #[test]
    fn a_refusal_overrides_the_jobs_outcome() {
        let retry = JobOutcome::Retry { delay_secs: 30 };
        assert_eq!(delivery(retry, None), (retry, None));
        assert_eq!(delivery(JobOutcome::Ack, None).0, JobOutcome::Ack);
        assert_eq!(delivery(retry, Some(UNIT_STALE_JOB)).0, JobOutcome::Ack);
        assert_eq!(
            delivery(JobOutcome::Ack, Some(UNIT_UNBORN)).0,
            JobOutcome::Retry {
                delay_secs: REFUSED_RETRY_DELAY_SECS
            }
        );
    }
}
