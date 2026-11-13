//! Queue jobs (`run_job`: post, verify, release, gc) and the cron
//! dispatcher.
//!
//! The `outbox` row is the obligation; a queue message is only a hint that
//! a row may be due. So:
//! - `run_job` claims the row before it does anything. A duplicate, early,
//!   stale or unknown message claims nothing and is acked.
//! - `dispatch` re-sends a message for every due row, which covers lost
//!   messages, expired retries and restarts. It reads the catalogue and
//!   sends to the queue; it never claims a lease, opens a socket, touches a
//!   blob store or runs crypto.
//! - The GC job deletes a blob only when the catalogue hands it the key
//!   (`gc_begin`), and only in the mode `GC_MODE` allows.

use crate::config::{GcMode, Maintenance};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::post::{settle, Stop};
use crate::types::{
    BlobStoreKind, DispatchReport, ExtentId, FailClass, GcStep, GenerationId, Job, JobOutcome,
    OutboxStage, Result, JOB_VERSION,
};

/// Outbox rows one dispatcher run re-sends (one queue batch).
pub const DISPATCH_LIMIT: u32 = 100;
/// Claims after which the dispatcher moves an unleased row to `dead`.
pub const MAX_ATTEMPTS: u32 = 50;
/// GC rows one GC job handles before it re-enqueues itself.
pub const GC_BATCH: u32 = 50;
/// Retry delay when the catalogue, a blob store or the queue failed before
/// anything could be recorded.
pub const INFRA_RETRY_SECS: u32 = 60;
/// Working memory of a job besides the extent itself: one article on the
/// wire and one decoded.
const JOB_OVERHEAD_BYTES: u64 = 2 * 1024 * 1024;

const RETRY: JobOutcome = JobOutcome::Retry {
    delay_secs: INFRA_RETRY_SECS,
};

impl<C, B, N, J, K, T> Bridge<C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    /// Runs one queue job to an outcome. Never panics on a stale job.
    pub async fn run_job(&self, job: &Job) -> JobOutcome {
        if self.cfg.maintenance == Maintenance::Restore {
            // The outbox keeps the obligation; the dispatcher re-sends it
            // once maintenance ends.
            return JobOutcome::Ack;
        }
        match job {
            Job::Extent {
                v,
                extent,
                generation,
                stage,
            } if *v == JOB_VERSION => self.run_extent(extent, generation, *stage).await,
            Job::Gc { v } if *v == JOB_VERSION => self.run_gc().await,
            // A message from another version: its outbox row is re-sent in
            // the current format.
            _ => JobOutcome::Ack,
        }
    }

    async fn run_extent(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
        stage: OutboxStage,
    ) -> JobOutcome {
        if !matches!(
            stage,
            OutboxStage::Post | OutboxStage::Verify | OutboxStage::Release
        ) {
            return JobOutcome::Ack;
        }
        let owner = format!("job:{stage}");
        let lease = match self
            .catalog
            .claim(extent, generation, stage, &owner, self.clock.now())
            .await
        {
            Ok(Some(lease)) => lease,
            // Duplicate delivery, not yet due, leased by a running job,
            // cancelled or already advanced.
            Ok(None) => return JobOutcome::Ack,
            Err(_) => return RETRY,
        };
        let row = match self.catalog.job_extent(extent, generation).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                let stop = Stop::fail(FailClass::Internal);
                return settle(&self.catalog, &self.clock, &lease, stop).await;
            }
            Err(e) => return settle(&self.catalog, &self.clock, &lease, e.into()).await,
        };
        // Only the post stage holds the whole extent; verify and release
        // hold one article at a time.
        let bytes = match stage {
            OutboxStage::Post => row.extent.cipher_size.saturating_add(JOB_OVERHEAD_BYTES),
            _ => JOB_OVERHEAD_BYTES,
        };
        // A job larger than the whole budget still has to run: alone.
        let bytes = bytes.min(self.budget.capacity());
        let Ok(_charge) = self.budget.charge(bytes).await else {
            // No memory right now is not a failure of the extent: give the
            // lease back without spending an attempt.
            return settle(&self.catalog, &self.clock, &lease, Stop::NoPermit).await;
        };
        match stage {
            OutboxStage::Post => self.post_stage(&lease, &row).await,
            OutboxStage::Verify => self.verify_stage(&lease, &row).await,
            _ => self.release_stage(&lease, &row).await,
        }
    }

    /// Handles up to [`GC_BATCH`] due `gc` rows.
    async fn run_gc(&self) -> JobOutcome {
        let disposable_only = match self.cfg.gc_mode {
            GcMode::Off => return JobOutcome::Ack,
            GcMode::Disposable => true,
        };
        match self.gc_batch(disposable_only).await {
            Ok(()) => JobOutcome::Ack,
            // Every step is idempotent, so the batch simply runs again.
            Err(_) => RETRY,
        }
    }

    async fn gc_batch(&self, disposable_only: bool) -> Result<()> {
        let now = self.clock.now();
        let rows = self.catalog.gc_due(now, GC_BATCH, disposable_only).await?;
        for row in &rows {
            // The catalogue re-checks that no live generation uses the
            // extent and names the one blob that may go.
            match self.catalog.gc_begin(row, now).await? {
                GcStep::DeleteBlob { store, key } => {
                    match store {
                        BlobStoreKind::Safety => self.safety.delete(&key).await?,
                        BlobStoreKind::Cache => self.cache.delete(&key).await?,
                    }
                    self.catalog.gc_done(row.id, self.clock.now()).await?;
                }
                GcStep::Done | GcStep::Skipped => {}
            }
        }
        if rows.len() >= GC_BATCH as usize {
            // More may be due. If this send is lost, the dispatcher sends
            // the next one.
            self.jobs.send(&Job::Gc { v: JOB_VERSION }, 0).await?;
        }
        Ok(())
    }

    /// The whole cron handler: bounded catalogue reads and queue sends
    /// only.
    pub async fn dispatch(&self) -> Result<DispatchReport> {
        let mut report = DispatchReport::default();
        if self.cfg.maintenance == Maintenance::Restore {
            return Ok(report);
        }
        let now = self.clock.now();

        self.catalog.seed_permits(&self.cfg.providers).await?;
        report.permits_seeded = true;

        // Buried first, so an exhausted row is not sent once more.
        report.buried = self.catalog.bury_exhausted(MAX_ATTEMPTS, now).await?;

        let due = self.catalog.due(now, DISPATCH_LIMIT).await?;
        let jobs: Vec<Job> = due
            .into_iter()
            .map(|row| Job::Extent {
                v: JOB_VERSION,
                extent: row.extent_id,
                generation: row.generation_id,
                stage: row.stage,
            })
            .collect();
        if !jobs.is_empty() {
            self.jobs.send_many(&jobs).await?;
        }
        report.enqueued = u32::try_from(jobs.len()).unwrap_or(u32::MAX);

        let gc_due = match self.cfg.gc_mode {
            GcMode::Off => false,
            GcMode::Disposable => !self.catalog.gc_due(now, 1, true).await?.is_empty(),
        };
        if gc_due {
            self.jobs.send(&Job::Gc { v: JOB_VERSION }, 0).await?;
            report.gc_enqueued = true;
        }

        self.catalog.record_dispatch(now).await?;
        Ok(report)
    }
}
