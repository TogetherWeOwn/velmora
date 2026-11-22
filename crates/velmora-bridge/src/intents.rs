//! Sliced writes that were never published: the sweep of their slices.
//!
//! A PutObject body above one extent is stored as slices before the
//! request knows whether it will publish them. Each slice has a
//! `write_intents` row from before its blob is stored, so a request that
//! dies leaves rows that name every blob it wrote. The sweep deletes
//! those blobs, one write per job:
//!
//! 1. the rollback check: no delete from a catalogue that is behind its
//!    stamp;
//! 2. the fence: one batch moves the rows to `sweeping`, and fails under
//!    a replay, when the write has a catalogue row, or when the stamp
//!    counter is below the one step 1 compared. The publish batch
//!    commits only over `open` rows, so a fenced write is never
//!    published afterwards;
//! 3. a recovery record of the write exists: the rows become `kept`,
//!    nothing is deleted, and an anomaly is counted. A record without a
//!    catalogue row is the mark of a commit this catalogue no longer
//!    holds;
//! 4. both checks again, then the blobs, then the rows.
//!
//! A job that dies between two steps leaves `sweeping` rows; the next
//! job starts at step 1 with them.

use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::recovery::{delete_blob, generation_recorded};
use crate::tenant::TenantScope;
use crate::types::{
    DispatchReport, IntentFence, Job, JobOutcome, Result, UnixMs, WriteId, JOB_VERSION,
};

/// How long the `open` rows of a write wait before the sweep takes them.
/// A request lives minutes; the distance to [`WRITER_MAX_AGE_MS`] is the
/// time a writer that passed its age check may still take to publish.
pub const SWEEP_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

/// A sliced write older than this does not write a recovery record any
/// more: it gives up and leaves its rows to the sweep.
pub const WRITER_MAX_AGE_MS: i64 = 12 * 60 * 60 * 1000;

/// Writes one dispatcher run hands to the sweep.
pub const SWEEP_BATCH: u32 = 20;

/// The start of the grace period that ends at `now`.
pub fn open_before(now: UnixMs) -> UnixMs {
    UnixMs(now.0.saturating_sub(SWEEP_GRACE_MS))
}

impl<C, B, N, J, K, T> Bridge<C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    /// Whether a delete may go ahead: `Err(outcome)` ends the job.
    /// `Ok` holds the stamp counter the check found level with the
    /// stamp objects; the batch that follows fails below it.
    async fn sweep_allowed(&self) -> std::result::Result<Option<u64>, JobOutcome> {
        match self.stamp_checked().await {
            Ok(Some(counter)) => Ok(counter),
            // Behind its stamp: the rows may be those of acknowledged
            // objects. Nothing is deleted until the replay has run.
            Ok(None) => Err(JobOutcome::Ack),
            // The check could not be made: the same as a rollback for
            // this run.
            Err(_) => Err(crate::jobs::RETRY),
        }
    }

    /// The sweep of one write. Every step is safe to run again.
    pub(crate) async fn sweep_write(&self, scope: &TenantScope, write: &WriteId) -> JobOutcome {
        if !self.cfg.intent_sweep {
            return JobOutcome::Ack;
        }
        match self.sweep(scope, write).await {
            Ok(outcome) => outcome,
            Err(_) => crate::jobs::RETRY,
        }
    }

    async fn sweep(&self, scope: &TenantScope, write: &WriteId) -> Result<JobOutcome> {
        let stamp = match self.sweep_allowed().await {
            Ok(stamp) => stamp,
            Err(outcome) => return Ok(outcome),
        };
        let fence = self
            .catalog
            .fence_intents(write, open_before(self.clock.now()), stamp)
            .await?;
        let IntentFence::Fenced {
            generation,
            extents,
        } = fence
        else {
            // Nothing due under this id, a replay under way, or a
            // published write whose rows were removed.
            return Ok(JobOutcome::Ack);
        };
        if let Some(generation) = &generation {
            // Under the name of either layout: the record may be of a
            // Worker that was set to the other one.
            if generation_recorded(&self.safety, scope, generation).await? {
                self.catalog.keep_intents(write).await?;
                return Ok(JobOutcome::Ack);
            }
        }
        // The checks once more, as late as possible: a restore of the
        // catalogue or a replay may have started since the fence.
        let stamp = match self.sweep_allowed().await {
            Ok(stamp) => stamp,
            Err(outcome) => return Ok(outcome),
        };
        if !self
            .catalog
            .hold_intent_fence(write, extents.len(), stamp)
            .await?
        {
            return Ok(JobOutcome::Ack);
        }
        for extent in &extents {
            // Absent is success: an earlier run of this job got here.
            delete_blob(&self.safety, &scope.safety_key(extent)).await?;
        }
        self.catalog.drop_intents(write).await?;
        Ok(JobOutcome::Ack)
    }

    /// The dispatcher's part: one job per write that is due. An extra,
    /// its failure does not stop the run.
    pub(crate) async fn sweep_check(&self, now: UnixMs, report: &mut DispatchReport) {
        if !self.cfg.intent_sweep {
            return;
        }
        let sent = async {
            let due = self
                .catalog
                .due_intents(open_before(now), SWEEP_BATCH)
                .await?;
            let jobs: Vec<Job> = due
                .into_iter()
                .map(|write| Job::Sweep {
                    v: JOB_VERSION,
                    write,
                })
                .collect();
            if !jobs.is_empty() {
                self.jobs.send_many(&jobs).await?;
            }
            Ok::<_, crate::types::BridgeError>(u32::try_from(jobs.len()).unwrap_or(u32::MAX))
        };
        match sent.await {
            Ok(n) => report.sweeps_enqueued = n,
            Err(_) => report.sweep_failed = true,
        }
    }
}
