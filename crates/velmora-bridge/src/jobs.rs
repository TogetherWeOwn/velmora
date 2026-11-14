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
//! - The eviction job keeps R2 a bounded hot tier. It deletes R2 copies
//!   of extents that Usenet is proven to hold, never a catalogue row and
//!   never a pinned copy, so it is not data deletion and `GC_MODE` does
//!   not apply to it. The only keys it can name are an extent's
//!   `x/<extent>` and `c/<extent>`.

use crate::config::{GcMode, Maintenance};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::post::{settle, Stop};
use crate::recovery::delete_blob;
use crate::types::{
    BlobStoreKind, DispatchReport, EvictCandidate, ExtentId, FailClass, GcRow, GcStep,
    GenerationId, Job, JobOutcome, OutboxStage, Result, JOB_VERSION,
};
use crate::verify::backbones;

/// Outbox rows one dispatcher run re-sends (one queue batch).
pub const DISPATCH_LIMIT: u32 = 100;
/// Held extents one dispatcher run checks for the re-drive.
pub const REDRIVE_LIMIT: u32 = 500;
/// Claims after which the dispatcher moves an unleased row to `dead`.
pub const MAX_ATTEMPTS: u32 = 50;
/// GC rows one GC job handles before it re-enqueues itself.
pub const GC_BATCH: u32 = 50;
/// Extents one eviction job handles before it re-enqueues itself.
pub const EVICT_BATCH: u32 = 50;
/// Least time between two totals of the evictable bytes by the
/// dispatcher. The total reads one index entry per evictable extent, so
/// it is not taken on every run; the tier may sit over the cap for this
/// long before a drain starts.
pub const EVICT_CHECK_SECS: u32 = 1800;
/// Retry delay when the catalogue, a blob store or the queue failed before
/// anything could be recorded.
pub const INFRA_RETRY_SECS: u32 = 60;
/// Working memory of a job besides the extent itself: one article on the
/// wire and one decoded.
const JOB_OVERHEAD_BYTES: u64 = 2 * 1024 * 1024;

/// Where a drain stops: 90 % of the cap, so that a tier sitting at the
/// cap is not evicted a little on every run.
pub fn low_watermark(cap: u64) -> u64 {
    cap - cap / 10
}

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
            Job::Evict { v, remaining } if *v == JOB_VERSION => {
                match self.evict_batch(*remaining).await {
                    Ok(_) => JobOutcome::Ack,
                    // Every step is idempotent, so the batch simply runs again.
                    Err(_) => RETRY,
                }
            }
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
        // One row that fails must not hold up the rows behind it. The row
        // stays due, and the first error makes the job retry.
        let mut failed = None;
        for row in &rows {
            if let Err(e) = self.gc_row(row).await {
                failed.get_or_insert(e);
            }
        }
        if rows.len() >= GC_BATCH as usize {
            // More may be due. If this send is lost, the dispatcher sends
            // the next one.
            self.jobs.send(&Job::Gc { v: JOB_VERSION }, 0).await?;
        }
        failed.map_or(Ok(()), Err)
    }

    /// One `gc` row: the catalogue re-checks that no live generation uses
    /// the extent and names the one blob that may go.
    async fn gc_row(&self, row: &GcRow) -> Result<()> {
        match self.catalog.gc_begin(row, self.clock.now()).await? {
            GcStep::DeleteBlob { store, key } => {
                match store {
                    BlobStoreKind::Safety => delete_blob(&self.safety, &key).await?,
                    BlobStoreKind::Cache => delete_blob(&self.cache, &key).await?,
                }
                self.catalog.gc_done(row.id, self.clock.now()).await
            }
            GcStep::Done | GcStep::Skipped => Ok(()),
        }
    }

    /// One bounded step of the hot-tier drain; returns the bytes it freed.
    ///
    /// `remaining == 0` starts a drain: the job totals the evictable
    /// bytes and, if they exceed the cap, has the excess over the low
    /// watermark to evict. Otherwise `remaining` is what an earlier step
    /// left, and nothing is totalled. Least recently read extents go
    /// first, until the excess is gone or the batch is used up; then the
    /// rest is handed to the next step.
    ///
    /// The safety copy of a pinned extent is never deleted: `begin_evict`
    /// claims it only for an extent that is not pinned in the very
    /// statement that makes the claim.
    ///
    /// A later step acts only once, however often its job is delivered:
    /// it must claim what the step before it recorded. So a duplicate, or
    /// the retry of a later step that failed part way, does nothing, and
    /// the dispatcher starts a new drain if the tier is still over the
    /// cap. Only a first step that is retried after an error totals the
    /// tier again and goes on from there.
    pub async fn evict_batch(&self, remaining: u64) -> Result<u64> {
        let mut excess = remaining;
        if excess == 0 {
            let cap = self.cfg.hot_cap_bytes;
            let total = self.catalog.evictable_bytes().await?;
            if total <= cap {
                return Ok(0);
            }
            excess = total - low_watermark(cap);
        } else if !self.catalog.hot_drain_claim(remaining).await? {
            // A second delivery of a step that already ran, or a step of
            // a drain that another one replaced: its `remaining` is stale.
            return Ok(0);
        }
        let mut freed = 0u64;
        let rows = self.catalog.evict_candidates(EVICT_BATCH).await?;
        let mut more = rows.len() >= EVICT_BATCH as usize;
        // One extent that fails must not hold up the ones behind it. It
        // stays counted, and the first error makes the job retry.
        let mut failed = None;
        for row in &rows {
            if excess == 0 {
                break;
            }
            match self.evict_one(row).await {
                Ok(Some(bytes)) => {
                    freed = freed.saturating_add(bytes);
                    excess = excess.saturating_sub(bytes);
                }
                // Another eviction job is at work on the same list, or a
                // read just refilled the extent. Stop here rather than
                // evict past the low watermark together; if the tier is
                // still over the cap, the dispatcher starts a new drain.
                Ok(None) => {
                    more = false;
                    break;
                }
                Err(e) => {
                    failed.get_or_insert(e);
                }
            }
        }
        if let Some(e) = failed {
            return Err(e);
        }
        if excess > 0 && more {
            // The next step runs once: it has to claim this record. If the
            // send is lost, the dispatcher starts a new drain once the
            // cap is exceeded.
            self.catalog.hot_drain_set(excess).await?;
            let next = Job::Evict {
                v: JOB_VERSION,
                remaining: excess,
            };
            self.jobs.send(&next, 0).await?;
        }
        Ok(freed)
    }

    /// Evicts one extent's evictable R2 copies and returns the bytes it
    /// freed. `None` when something else changed the extent meanwhile:
    /// either the catalogue refused the eviction (nothing was deleted), or
    /// it could not be finished as begun.
    async fn evict_one(&self, row: &EvictCandidate) -> Result<Option<u64>> {
        if !self.catalog.begin_evict(row).await? {
            return Ok(None);
        }
        // Both keys go whatever the counts say, so a copy the catalogue
        // did not count goes too. The one exception is the safety copy of
        // a pinned extent, which is not part of the claim.
        if !row.pinned {
            delete_blob(&self.safety, &row.extent.safety_key()).await?;
        }
        delete_blob(&self.cache, &row.extent.cache_key()).await?;
        // `false`: a cold read refilled the cache, or another eviction
        // took the extent, since `begin_evict`. The counts stand, and
        // what this drain still has to evict is no longer known.
        Ok(match self.catalog.finish_evict(row).await? {
            true => Some(row.evictable_bytes()),
            false => None,
        })
    }

    /// The dispatcher's hot-tier check: at most one total per
    /// [`EVICT_CHECK_SECS`], and an eviction job if it exceeds the cap.
    /// `GC_MODE` does not gate it: eviction removes no data.
    async fn evict_check(&self, now: crate::types::UnixMs) -> Result<bool> {
        let every_ms = i64::from(EVICT_CHECK_SECS) * 1000;
        if !self.catalog.hot_check_due(now, every_ms).await? {
            return Ok(false);
        }
        let over = self.catalog.evictable_bytes().await? > self.cfg.hot_cap_bytes;
        if over {
            let job = Job::Evict {
                v: JOB_VERSION,
                remaining: 0,
            };
            self.jobs.send(&job, 0).await?;
        }
        // Recorded last: a check that failed is due again on the next run.
        self.catalog.hot_checked(now).await?;
        Ok(over)
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

        // A cancelled posting of an extent that a live generation
        // references is armed again: an older Worker can leave one after
        // a rollback. The rows moved here are due at once and sent below.
        // Like the re-drive that follows, an extra that must not stop
        // the send.
        match self.catalog.revive_referenced(REDRIVE_LIMIT, now).await {
            Ok(n) => report.redriven = n,
            Err(_) => report.redrive_failed = true,
        }

        // A `done` extent whose safety copy is held was short of backbones
        // when it was verified. Once enough are configured it is verified
        // again; the rows moved here are due at once and sent below.
        let labels: Vec<String> = backbones(&self.cfg.providers)
            .into_iter()
            .map(|(label, _)| label)
            .collect();
        let required = self.cfg.required_backbones;
        if labels.len() >= required as usize {
            // The re-drive is an extra: its failure must not keep the
            // due rows below from being sent.
            let redriven =
                self.catalog
                    .redrive_underverified(&labels, required, REDRIVE_LIMIT, now);
            match redriven.await {
                Ok(n) => report.redriven += n,
                Err(_) => report.redrive_failed = true,
            }
        }

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

        // The hot-tier check is an extra, like the re-drive: its failure
        // must not keep the run from being recorded.
        match self.evict_check(now).await {
            Ok(sent) => report.evict_enqueued = sent,
            Err(_) => report.evict_failed = true,
        }

        self.catalog.record_dispatch(now).await?;
        Ok(report)
    }
}
