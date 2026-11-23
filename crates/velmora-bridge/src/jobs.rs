//! Queue jobs (`run_job`: post, verify, release, gc) and the cron
//! dispatcher.
//!
//! The `outbox` row is the obligation; a queue message is only a hint that
//! a row may be due. So:
//! - `run_job` claims the row before it does anything. A duplicate, early,
//!   stale or unknown message claims nothing and is acked.
//! - `dispatch` sends a message for every due row that no job holds,
//!   which covers lost messages, expired retries and restarts. It marks
//!   each row it sent and leaves a marked row alone for [`RESEND_SECS`],
//!   and for longer while its queues still hold messages from before
//!   the mark ([`resend_secs`]), so a row waiting in a queue is not
//!   sent again. It
//!   reads the catalogue, writes that mark and sends to the queue; it
//!   never claims a lease, opens a socket, touches a blob store (but for
//!   the rollback stamp) or runs crypto.
//! - A job that is due further out than a queue delay reaches (a release
//!   after the minimum age) travels as a `Wake` message, which is sent
//!   on until its time has come. So a release does not wait for the
//!   dispatcher, whose run is bounded.
//! - The GC job deletes a blob only when the catalogue hands it the key
//!   (`gc_begin`), and only in the mode `GC_MODE` allows. With
//!   `GC_ORPHANS` it also deletes the safety copies of upload parts
//!   that left their upload and never became part of an object, in
//!   every bucket and only after the catalogue recorded the delete
//!   against its proof (`gc_orphan_claim`).
//! - The eviction job keeps R2 a bounded hot tier. It deletes R2 copies
//!   of extents that Usenet is proven to hold, never a catalogue row and
//!   never a pinned copy, so it is not data deletion and `GC_MODE` does
//!   not apply to it. The only keys it can name are an extent's
//!   `x/<extent>` and `c/<extent>`.

use crate::config::{GcMode, Maintenance, ORPHAN_GRACE_MS};
use crate::fetch::job_holder;
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, JobSink, Kek, Lease, NntpConnector, SlotWait,
    SlotWaitWindow, LEASE_SECS, MAX_QUEUE_DELAY_SECS, PERMIT_SECS,
};
use crate::post::{check_extent_size, settle, Stop, POST_SOCKET_BYTES};
use crate::recovery::delete_blob;
use crate::stamp::Advance;
use crate::types::{
    BlobStoreKind, DispatchReport, EvictCandidate, ExtentId, FailClass, GcRow, GcStep,
    GenerationId, Job, JobOutcome, Oldest, OutboxStage, ProviderConfig, Resend, Result, UnixMs,
    JOB_VERSION,
};
use crate::verify::release_labels;

/// Recount steps one cron run takes: 5 chunks of 4,000 rows, about
/// 5.7 million table rows a day.
pub const RECOUNT_STEPS: u32 = 5;
/// A recount of the usage counters starts this long after the last one
/// ended: a week.
pub const RECOUNT_EVERY_MS: i64 = 7 * 24 * 3600 * 1000;

/// Jobs in one queue batch of the dispatcher (the bound of
/// [`JobSink::send_many`]).
pub const DISPATCH_BATCH: u32 = 100;
/// Queue batches one dispatcher run sends at most.
pub const DISPATCH_BATCHES: u32 = 20;
/// Outbox rows one dispatcher run sends at most: 2,000, which at a run
/// every five minutes is 576,000 a day.
///
/// What bounds it is the calls a single invocation may make. A run with
/// this many rows makes three catalogue reads for them (one per stage),
/// and per batch one catalogue write (the marks) and one queue call per
/// bound queue: with the most queues a deployment may bind (8 of each
/// kind, and the one of the jobs without an extent) that is at most
/// 3 + 20 + 20 * 17 = 363 calls, and one more per queue of an extent's
/// jobs to ask what it holds (16), beside the two dozen of the rest of
/// the run. The platform allows 1,000.
pub const DISPATCH_LIMIT: u32 = DISPATCH_BATCH * DISPATCH_BATCHES;
/// How long the dispatcher leaves a row alone after it sent a job for
/// it, unless a job claimed the row meanwhile or its due time moved.
///
/// Until a job claims the row, the job the dispatcher sent is taken to
/// be waiting in its queue; sending another on every run would only add
/// duplicates, each one a queue delivery and a claim that finds nothing.
/// A message that was really lost (dropped after its retries, say) costs
/// its row this long, or longer while its queues are behind
/// ([`resend_secs`]). Nothing but time is at stake: the outbox row
/// stays, and a release that is late only keeps its safety copy longer.
pub const RESEND_SECS: u32 = 3600;
/// The longest the dispatcher leaves a sent row alone, whatever its
/// queues hold: a job whose message was lost is sent again within this
/// time and one dispatcher run.
///
/// A queue that is more than this behind gets a second message for a
/// row that waits in it, at most one per row in this time.
pub const RESEND_MAX_SECS: u32 = 86_400;
/// How much older than the oldest message in its queues a mark must be
/// before its message counts as gone.
///
/// A mark carries the time its dispatcher run began, the time of the
/// commit that made the row, or the due time a handler gave the row
/// before it sent the job itself. The message carries the time the
/// queue took it, later in that run or request: that takes well under
/// this, so a message still in a queue is never newer than its row's
/// mark by this much. It also covers a clock of the queues that
/// is not this one, and a message that was delivered and whose job has
/// not claimed its row yet.
pub const RESEND_SLACK_SECS: u32 = 600;

/// The oldest a message in a queue can be: the longest a queue keeps
/// one (14 days). A queue that names an older time for its oldest
/// message is not believed.
pub const QUEUE_RETENTION_MAX_SECS: u32 = 14 * 86_400;

/// How long the dispatcher leaves a sent row alone at `now`, given the
/// oldest message its queues still hold.
///
/// A queue hands its messages out oldest first, near enough. While it
/// holds one from before a row's mark (less [`RESEND_SLACK_SECS`]), the
/// row's own message may wait behind it, and sending another would only
/// make the queue longer. Once every message left is from after the
/// mark and the row is still unclaimed, its message is gone. So the
/// wait is the age of the oldest message plus the slack, never under
/// [`RESEND_SECS`] and never over [`RESEND_MAX_SECS`].
///
/// The oldest message may be one that waits out a delay or a retry and
/// holds nothing up. Then the wait is longer than it had to be, within
/// the same bound.
///
/// An empty queue, one that does not say, and one that names a time no
/// message of its can have (older than [`QUEUE_RETENTION_MAX_SECS`])
/// give [`RESEND_SECS`]: as before there was anything to ask.
pub fn resend_secs(now: UnixMs, oldest: Oldest) -> u32 {
    let Oldest::At(at) = oldest else {
        return RESEND_SECS;
    };
    // Rounded up, and a time ahead of `now` is no age at all.
    let age_secs = now.0.saturating_sub(at.0).max(0).saturating_add(999) / 1000;
    if age_secs > i64::from(QUEUE_RETENTION_MAX_SECS) {
        return RESEND_SECS;
    }
    let wait = age_secs.saturating_add(i64::from(RESEND_SLACK_SECS));
    u32::try_from(wait)
        .unwrap_or(RESEND_MAX_SECS)
        .clamp(RESEND_SECS, RESEND_MAX_SECS)
}
/// Held extents one dispatcher run checks for the re-drive.
pub const REDRIVE_LIMIT: u32 = 500;
/// Extents with article rows one dispatcher run looks at to pack their
/// plans. A run packs at most this many: each is one read, and a share
/// of a write that deletes its rows.
pub const PACK_LIMIT: u32 = 50;
/// Claims after which the dispatcher moves an unleased row to `dead`.
pub const MAX_ATTEMPTS: u32 = 50;
/// GC rows one GC job handles before it re-enqueues itself.
pub const GC_BATCH: u32 = 50;
/// Open `gc` rows one run of the scan for orphaned upload parts reads.
/// Most of them are rows of deleted objects, which it steps over.
pub const ORPHAN_SCAN: u32 = 500;
/// Orphaned parts one GC job deletes: the claims of all of them in a
/// few batches, then a blob delete and a close each, which keeps a job
/// well inside its subrequests.
pub const ORPHAN_BATCH: u32 = 100;
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
pub(crate) const JOB_OVERHEAD_BYTES: u64 = 2 * 1024 * 1024;

/// What a job of `stage` charges to the isolate's byte budget for an
/// extent of `cipher_size` bytes. Only the post stage holds the whole
/// extent, and a rendered article and its copy on the wire per socket
/// ([`POST_SOCKET_BYTES`]); verify and release hold
/// one article at a time (a repost charges for itself).
pub fn job_bytes(stage: OutboxStage, cipher_size: u64, post_sockets: u32) -> u64 {
    match stage {
        OutboxStage::Post => cipher_size
            .saturating_add(JOB_OVERHEAD_BYTES.max(u64::from(post_sockets) * POST_SOCKET_BYTES)),
        _ => JOB_OVERHEAD_BYTES,
    }
}

/// What a job that holds the parity shards of an extent charges on top:
/// the `parity` shards themselves, and two more that the codec works in
/// while it computes them (`velmora::rs::encode` builds the shards in
/// place, beside one data shard and the shard it is converting). Each is
/// as long as the extent's longest article. Nothing for an extent without
/// parity. Measured on a deployed Worker, a post job with parity held
/// 2.8 MiB more than one without: its 4 shards.
pub fn parity_job_bytes(cipher_size: u64, parity: usize) -> u64 {
    if parity == 0 {
        return 0;
    }
    let Some((_, shard)) = crate::parity::stripe_of(cipher_size) else {
        return 0;
    };
    (parity as u64)
        .saturating_add(2)
        .saturating_mul(u64::from(shard))
}

fn post_job_bytes(cipher_size: u64, post_sockets: u32, parity: usize) -> u64 {
    job_bytes(OutboxStage::Post, cipher_size, post_sockets)
        .saturating_add(parity_job_bytes(cipher_size, parity))
}

pub(crate) fn repost_job_bytes(cipher_size: u64, post_sockets: u32, parity: usize) -> u64 {
    cipher_size
        .saturating_add(u64::from(post_sockets) * POST_SOCKET_BYTES)
        .saturating_add(parity_job_bytes(cipher_size, parity))
}

fn new_plan_parity_count(cipher_size: u64) -> usize {
    crate::parity::parity_count(crate::articles::article_spans(cipher_size).len())
}

/// Room for either a post or a repost beside its verify job. Count parity
/// even with PARITY off: existing extents can still have parity shards.
pub(crate) fn extent_job_budget_floor(cipher_size: u64, post_sockets: u32) -> u64 {
    let parity = new_plan_parity_count(cipher_size);
    let post = post_job_bytes(cipher_size, post_sockets, parity);
    let verify = job_bytes(OutboxStage::Verify, cipher_size, post_sockets);
    let repost = repost_job_bytes(cipher_size, post_sockets, parity);
    post.max(verify.saturating_add(repost))
}

/// The extent buffers an isolate keeps between post jobs
/// ([`crate::ingress::ByteBudget::with_extent_pool`]): as many as post
/// jobs of the largest extent fit its job budget at once, at least one.
pub fn extent_pool_buffers(
    job_budget_bytes: u64,
    max_extent_bytes: u64,
    post_sockets: u32,
    parity: bool,
) -> usize {
    let Some(cipher_size) = velmora::media::ciphertext_size(max_extent_bytes) else {
        return 1;
    };
    let parity = if parity {
        new_plan_parity_count(cipher_size)
    } else {
        0
    };
    let job = post_job_bytes(cipher_size, post_sockets, parity).max(1);
    usize::try_from(job_budget_bytes / job)
        .unwrap_or(usize::MAX)
        .max(1)
}

/// Where a drain stops: 90 % of the cap, so that a tier sitting at the
/// cap is not evicted a little on every run.
pub fn low_watermark(cap: u64) -> u64 {
    cap - cap / 10
}

/// Ordinary slot-wait budget, counted from the job's claim across all
/// the backbones it asks. One permit lifetime, the gate's restart skew
/// allowance, and one polling interval. A gate that starts later than
/// the claim can report a hold that ends later than this budget.
pub const SLOT_WAIT_MS: i64 =
    PERMIT_SECS as i64 * 1000 + crate::gate::SKEW_MS + SLOT_POLL_MS as i64;
/// Leave the longest successful production run measured (393 s) for
/// the stage, within both the initial claim lease and the invocation's
/// longer deadline ([`JOB_WAIT_MS`](crate::jobtable::JOB_WAIT_MS)).
const SLOT_WAIT_HARD_MS: i64 = LEASE_SECS as i64 * 1000 - 393_000;
const _: () = assert!(SLOT_WAIT_MS < SLOT_WAIT_HARD_MS);
const _: () = assert!(LEASE_SECS as i64 * 1000 < crate::jobtable::JOB_WAIT_MS);
/// How long a job that waits for a slot sleeps at least before it asks
/// again. A slot is held for a second or more by the shortest job there
/// is (a connect, a login and one pass of a light check), so asking
/// more often than this finds little.
pub const SLOT_POLL_MS: u32 = 2_000;
/// Catalogue calls the asks of one wait may make together, after the
/// first ask (the one a job always made). D1 allows 1,000 queries per
/// invocation, and a job that ran out of them could not even hand its
/// claim back: the wait gets half, the job's own work the rest (a drill
/// job made 13 calls on average). One ask is a read of the pool and at
/// most three calls per provider (the sweep of expired permits, the
/// take, the seeding of missing slots), so a job that asks many
/// providers sleeps longer between asks ([`slot_poll_ms`]).
pub const SLOT_WAIT_CALLS: i64 = 500;

/// The sleep before the next ask of `providers` providers: at least
/// [`SLOT_POLL_MS`], and long enough that the asks that follow such
/// sleeps make no more than [`SLOT_WAIT_CALLS`] calls in
/// [`SLOT_WAIT_MS`]: as many asks as fit in the calls, spread over the
/// wait.
pub fn slot_poll_ms(providers: usize) -> u32 {
    let asks = (SLOT_WAIT_CALLS / (1 + 3 * providers as i64)).max(1);
    let ms = (SLOT_WAIT_MS + asks - 1) / asks;
    u32::try_from(ms).unwrap_or(u32::MAX).max(SLOT_POLL_MS)
}

pub(crate) const RETRY: JobOutcome = JobOutcome::Retry {
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
            // once maintenance has ended and the row's mark has aged.
            return JobOutcome::Ack;
        }
        // A wake-up that came before its time is sent on for the rest
        // of the wait, before anything is read: no catalogue call. A
        // new message rather than a retry of this one, so that a long
        // wait does not use up the deliveries a message is allowed. If
        // the send fails, the retry is the fallback.
        if let Some(delay_secs) = self.wake_early(job) {
            return match self.jobs.send(job, delay_secs).await {
                Ok(()) => JobOutcome::Ack,
                Err(_) => JobOutcome::Retry { delay_secs },
            };
        }
        // The same while a replay of the recovery records is not
        // finished: the catalogue holds only a part of them, and a job
        // could release or delete what a record still to come needs.
        match self.catalog.restore_pending().await {
            Ok(false) => {}
            Ok(true) => return JobOutcome::Ack,
            Err(e) => {
                // The other kinds of job show in the outbox figures; a
                // sweep that never gets past this check shows nowhere.
                // With the switch off a sweep job does nothing, so
                // nothing of it failed.
                if self.cfg.intent_sweep && matches!(job, Job::Sweep { .. }) {
                    crate::intents::job_failed(&e);
                }
                return RETRY;
            }
        }
        match job {
            Job::Extent {
                v,
                extent,
                generation,
                stage,
            } if *v == JOB_VERSION => self.run_extent(extent, generation, *stage).await,
            Job::Wake {
                v,
                extent,
                generation,
                stage,
                ..
            } if *v == JOB_VERSION => self.run_extent(extent, generation, *stage).await,
            Job::Gc { v } if *v == JOB_VERSION => self.run_gc().await,
            Job::Evict { v, remaining } if *v == JOB_VERSION => {
                match self.evict_batch(*remaining).await {
                    Ok(_) => JobOutcome::Ack,
                    // Every step is idempotent, so the batch simply runs again.
                    Err(_) => RETRY,
                }
            }
            Job::Sweep { v, write } if *v == JOB_VERSION => self.sweep_write(write).await,
            // Run by the adapter that holds the recovery store
            // (`crate::copy`), never here: one that arrives all the same
            // is dropped, and the next pass does its work.
            Job::RecoveryCopy { .. } => JobOutcome::Ack,
            // A message from another version: its outbox row is re-sent in
            // the current format.
            _ => JobOutcome::Ack,
        }
    }

    /// The wait still ahead of a `Wake` job that was delivered before
    /// its time, as a queue delay. `None` for any other job, and once
    /// the time has come. Rounded up to a second: a job that arrives
    /// early cannot claim its row.
    fn wake_early(&self, job: &Job) -> Option<u32> {
        let Job::Wake { v, at, .. } = job else {
            return None;
        };
        if *v != JOB_VERSION {
            return None;
        }
        let ahead_ms = at.0.saturating_sub(self.clock.now().0);
        if ahead_ms <= 0 {
            return None;
        }
        let secs = ahead_ms.saturating_add(999).div_euclid(1000);
        Some(u32::try_from(secs).map_or(MAX_QUEUE_DELAY_SECS, |s| s.min(MAX_QUEUE_DELAY_SECS)))
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
        let started = self.clock.now();
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
        if stage != OutboxStage::Post {
            return self.run_leased(&lease, extent, generation, stage).await;
        }
        crate::trace::begin(extent, started);
        let outcome = self.run_leased(&lease, extent, generation, stage).await;
        crate::trace::finish(extent, self.clock.now());
        outcome
    }

    /// The part of [`Self::run_extent`] after a successful claim.
    async fn run_leased(
        &self,
        lease: &Lease,
        extent: &ExtentId,
        generation: &GenerationId,
        stage: OutboxStage,
    ) -> JobOutcome {
        let row = match self.catalog.job_extent(extent, generation).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                let stop = Stop::fail(FailClass::Internal);
                return settle(&self.catalog, &self.clock, lease, stop).await;
            }
            Err(e) => return settle(&self.catalog, &self.clock, lease, e.into()).await,
        };
        let cipher_size = row.extent.cipher_size;
        let bytes = if stage == OutboxStage::Post {
            if let Err(stop) = check_extent_size(cipher_size) {
                return settle(&self.catalog, &self.clock, lease, stop).await;
            }
            if cipher_size > self.budget.job_capacity() {
                // Even a job running alone must have room for the extent itself.
                let stop = Stop::fail(FailClass::Corrupt);
                return settle(&self.catalog, &self.clock, lease, stop).await;
            }
            // Charge the stored parity or the shards of the plan about to be drawn.
            let parity = match (row.parity_count, row.extent.article_count) {
                (Some(parity), _) => parity as usize,
                (None, None) if self.cfg.packed_plans && self.cfg.parity => {
                    new_plan_parity_count(cipher_size)
                }
                _ => 0,
            };
            post_job_bytes(cipher_size, self.cfg.post_sockets, parity)
        } else {
            job_bytes(stage, cipher_size, self.cfg.post_sockets)
        };
        // A job larger than the whole budget still has to run: alone.
        let bytes = bytes.min(self.budget.job_capacity());
        let waited_from = self.clock.now();
        // A post job reads its extent into the buffer of its charge: a
        // spare one of the isolate when one fits.
        let charged = match stage {
            OutboxStage::Post => {
                self.budget
                    .charge_job_extent(bytes, row.extent.cipher_size)
                    .await
            }
            _ => self.budget.charge_job(bytes).await,
        };
        let wait_ms = self.clock.now().0 - waited_from.0;
        crate::trace::note(extent, |t| t.wait_ms = wait_ms);
        let Ok(charge) = charged else {
            // No memory right now is not a failure of the extent: give the
            // lease back without spending an attempt.
            return settle(&self.catalog, &self.clock, lease, Stop::NoPermit).await;
        };
        match stage {
            OutboxStage::Post => self.post_stage_in(lease, &row, Some(&charge)).await,
            OutboxStage::Verify => self.verify_stage(lease, &row).await,
            _ => self.release_stage(lease, &row).await,
        }
    }

    /// For a job that just found no slot on `providers`: waits for one
    /// and says the job may ask again, while its claim is younger than
    /// [`SLOT_WAIT_MS`]. `false`, with nothing awaited, once it is not,
    /// and on a host without a timer: the job is put off as before.
    ///
    /// Where the slots have a line ([`Catalog::await_permit`]) the job
    /// stands in it for the rest of that time, with no call and no
    /// sleep of its own, and asks again when a slot is its own; the
    /// time over, it is put off. A reported restart hold can extend
    /// the stand, but the stage still has time left on the claim. The
    /// line knows only the providers the job asked: `back`, when one
    /// that was cooling can be asked again, ends the stand there, and
    /// the job asks with the pool as it is then. Elsewhere it sleeps
    /// [`slot_poll_ms`]: longer the more providers it asks.
    /// The lease is not renewed here: a job that connects after a wait
    /// renews it first, as after any wait ([`Lease::fresh_at`]).
    pub(crate) async fn slot_wait(
        &self,
        lease: &Lease,
        providers: &[&ProviderConfig],
        back: Option<UnixMs>,
    ) -> bool {
        let now = self.clock.now().0;
        let age = now - lease.claimed_at.0;
        let sleep = match self.budget.sleeper() {
            Some(sleep) if (0..SLOT_WAIT_MS).contains(&age) => sleep,
            _ => return false,
        };
        let (holder, left) = (job_holder(lease), SLOT_WAIT_MS - age);
        let poll = slot_poll_ms(providers.len());
        // Never shorter than the sleep between two asks without a line,
        // except at the job's hard limit.
        let hard_at = lease.claimed_at.0 + SLOT_WAIT_HARD_MS;
        let back_at = back.map(|at| at.0.max(now + i64::from(poll)));
        let limit = back_at.map_or(hard_at, |at| at.min(hard_at)) - now;
        let window = SlotWaitWindow {
            normal_ms: left.min(limit),
            hard_ms: limit,
        };
        let line = self.catalog.await_permit(providers, &holder, window, sleep);
        match line.await {
            Ok(SlotWait::Granted) => true,
            // A cooldown can end during either the ordinary wait or
            // a restart extension. Refresh the pool if time remains.
            Ok(SlotWait::Elapsed) => {
                let now = self.clock.now().0;
                now < hard_at && back_at.is_some_and(|at| at <= now)
            }
            // No line here, or it could not be stood in: as before.
            Ok(SlotWait::Unsupported) | Err(_) => {
                if hard_at - self.clock.now().0 < i64::from(poll) {
                    return false;
                }
                sleep(poll).await;
                self.clock.now().0 < hard_at
            }
        }
    }

    /// Handles up to [`GC_BATCH`] due `gc` rows in the mode `GC_MODE`
    /// allows, and one window of orphaned upload parts with `GC_ORPHANS`.
    async fn run_gc(&self) -> JobOutcome {
        // Every step of both is idempotent, so a failed job simply runs
        // again.
        let mut outcome = JobOutcome::Ack;
        let rows = match self.cfg.gc_mode {
            GcMode::Off => Ok(()),
            GcMode::Disposable => self.gc_batch(true).await,
        };
        if rows.is_err() {
            outcome = RETRY;
        }
        if self.cfg.gc_orphans && self.orphan_batch().await.is_err() {
            outcome = RETRY;
        }
        outcome
    }

    async fn gc_batch(&self, disposable_only: bool) -> Result<()> {
        // Nothing is deleted on a catalogue that is behind its stamp:
        // its rows may name as garbage what a later commit used. A check
        // that could not be made retries the job.
        if self.catalogue_rolled_back().await? {
            return Ok(());
        }
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

    /// One window of the scan for orphaned upload parts: deletes the
    /// safety copies of the parts it finds (the rule is in `sql/gc.rs`).
    /// The scan has already moved past the window, so a job that runs
    /// again after an error reads the next one, and the rows that failed
    /// wait for the next pass.
    async fn orphan_batch(&self) -> Result<()> {
        // As in `gc_batch`: nothing is deleted on a catalogue that is
        // behind its stamp.
        if self.catalogue_rolled_back().await? {
            return Ok(());
        }
        let now = self.clock.now();
        let cutoff = now.plus_ms(-ORPHAN_GRACE_MS);
        let rows = self
            .catalog
            .gc_orphans(now, cutoff, ORPHAN_SCAN, ORPHAN_BATCH)
            .await?;
        // The scan read the rows a moment ago; the claim proves each
        // again in the batch that records its delete, and only then
        // does a blob go. Claims that an error cut short still granted
        // what they granted: those blobs go now, and the job fails
        // after.
        let (granted, claimed) = self.catalog.gc_orphan_claim(&rows, now, cutoff).await;
        let mut failed = claimed.err();
        for (row, _) in rows.iter().zip(granted).filter(|(_, granted)| *granted) {
            if let Err(e) = self.orphan_row(row).await {
                failed.get_or_insert(e);
            }
        }
        failed.map_or(Ok(()), Err)
    }

    /// One orphaned part whose claim was granted.
    async fn orphan_row(&self, row: &GcRow) -> Result<()> {
        delete_blob(&self.safety, &row.extent_id.safety_key()).await?;
        self.catalog.gc_orphan_done(row.id, self.clock.now()).await
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
        // As in garbage collection: no delete on a catalogue that is
        // behind its stamp.
        if self.catalogue_rolled_back().await? {
            return Ok(0);
        }
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
    async fn evict_check(&self, now: UnixMs) -> Result<bool> {
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

    /// The whole cron handler: bounded catalogue reads and queue sends,
    /// plus the rollback stamp (one list call of one key and one small
    /// put in the safety bucket).
    pub async fn dispatch(&self) -> Result<DispatchReport> {
        let mut report = DispatchReport::default();
        if self.cfg.maintenance == Maintenance::Restore {
            return Ok(report);
        }
        if self.catalog.restore_pending().await? {
            // Said on every run until the replay has ended. Checked
            // against the bucket here too: a catalogue that was restored
            // to a point where a replay ran is found now, not only by
            // the last step of that replay.
            report.rolled_back = self.catalogue_rolled_back().await?;
            return Ok(report);
        }
        // The rollback stamp, before anything else: on a catalogue that
        // was restored to an earlier point this run must send no job. A
        // check that could not be made ends the run as well.
        match self.stamp_advance(false).await? {
            Advance::RolledBack => {
                report.rolled_back = true;
                return Ok(report);
            }
            // The check passed. A stamp object that could not be put is
            // made up for by the next run.
            Advance::Raised(counter) => {
                report.stamp_failed = self.stamp_store(counter).await.is_err();
            }
            // The check passed and a write raised the stamp meanwhile:
            // the run goes on without a raise of its own.
            Advance::Checked => {}
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
        // Only the backbones that count toward a release are asked for.
        let labels = release_labels(&self.cfg.providers);
        let required = self.cfg.required_backbones;
        report.release_paused = self.cfg.release_paused().is_some();
        if self.cfg.verify.mode == crate::config::VerifyMode::Light {
            // Read fresh: the report is how an operator learns of it.
            // A failed read here leaves the list empty, not the run.
            if let Ok(raised) = self.catalog.verify_escalations(now).await {
                report.verify_escalated = raised
                    .into_iter()
                    .map(|e| crate::verify::label(&e.backbone))
                    .filter(|name| labels.contains(name))
                    .collect();
            }
        }
        if !report.release_paused {
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

        // Every due row that no job holds and that has no fresh mark,
        // oldest first, in queue batches. A batch is marked as soon as
        // it is sent, so the next run does not send it again. A send
        // that fails ends the sending: the rows not yet sent stay
        // unmarked, the checks below still run, and then the run fails
        // unrecorded. A mark that fails ends nothing: its batch is sent
        // again by the next run, and a duplicate job only finds its row
        // claimed.
        //
        // How long a mark counts as fresh depends on what the queues
        // still hold: a row is not sent again while its message can be
        // waiting behind older ones.
        let mut send_failed = None;
        let backlog = self.jobs.backlog().await;
        let resend = Resend {
            post_secs: resend_secs(now, backlog.post),
            verify_secs: resend_secs(now, backlog.verify),
        };
        report.resend_post_secs = resend.post_secs;
        report.resend_verify_secs = resend.verify_secs;
        let due = self.catalog.due(now, resend, DISPATCH_LIMIT).await?;
        for rows in due.chunks(DISPATCH_BATCH as usize) {
            let jobs: Vec<Job> = rows
                .iter()
                .map(|row| Job::Extent {
                    v: JOB_VERSION,
                    extent: row.extent_id.clone(),
                    generation: row.generation_id.clone(),
                    stage: row.stage,
                })
                .collect();
            if let Err(e) = self.jobs.send_many(&jobs).await {
                send_failed = Some(e);
                break;
            }
            report.enqueued += u32::try_from(jobs.len()).unwrap_or(u32::MAX);
            let sent: Vec<ExtentId> = rows.iter().map(|row| row.extent_id.clone()).collect();
            if self.catalog.mark_sent(&sent, now).await.is_err() {
                report.mark_failed = true;
            }
        }

        let gc_due = match self.cfg.gc_mode {
            GcMode::Off => false,
            GcMode::Disposable => !self.catalog.gc_due(now, 1, true).await?.is_empty(),
        };
        // One window of orphaned parts per run, until a pass is through.
        let orphans_due = self.cfg.gc_orphans && self.catalog.gc_orphans_due(now).await?;
        if gc_due || orphans_due {
            self.jobs.send(&Job::Gc { v: JOB_VERSION }, 0).await?;
            report.gc_enqueued = true;
        }

        // The hot-tier check is an extra, like the re-drive: its failure
        // must not keep the run from being recorded.
        match self.evict_check(now).await {
            Ok(sent) => report.evict_enqueued = sent,
            Err(_) => report.evict_failed = true,
        }

        // Unpublished sliced writes whose slices are due for deletion.
        self.sweep_check(now, &mut report).await;

        // Plans from before packed plans are packed a few at a time,
        // once the switch says that every Worker reads a packed plan.
        // An extra, like the checks above.
        if self.cfg.packed_plans {
            match self.catalog.pack_plans(PACK_LIMIT).await {
                Ok(packed) => report.plans_packed = packed.packed,
                Err(_) => report.pack_failed = true,
            }
        }

        // The usage counters are checked against the tables a few
        // bounded chunks at a time. An extra, like the checks above.
        if self.recount_check(now, &mut report).await.is_err() {
            report.recount_failed = true;
        }

        if let Some(e) = send_failed {
            return Err(e);
        }

        self.catalog.record_dispatch(now).await?;
        Ok(report)
    }

    /// Goes on with a recount of the usage counters, or starts the
    /// weekly one. The first recount, which switches the counters on, is
    /// started by an operator (`POST /_admin/usage/recount`), never here.
    async fn recount_check(&self, now: UnixMs, report: &mut DispatchReport) -> Result<()> {
        let (state, last) = self.catalog.usage_recounts().await?;
        if !state.running {
            // Only a catalogue whose counters a recount switched on has
            // a last one: nothing is started before the operator's.
            let due = last.is_some_and(|l| now.0 - l.finished_at.0 >= RECOUNT_EVERY_MS);
            // Started only while the counters are on, which the
            // statement that starts it checks: not after an `off`.
            if !due
                || !self
                    .catalog
                    .usage_recount_start(now, false, false, true)
                    .await?
            {
                return Ok(());
            }
        }
        for _ in 0..RECOUNT_STEPS {
            let step = self
                .catalog
                .usage_recount_step(crate::sql::usage::RECOUNT_CHUNK_MAX, now)
                .await?;
            report.recount_rows += step.rows;
            if let Some(done) = step.finished {
                report.recount_drift = Some(done.drift);
            }
            if step.idle || report.recount_drift.is_some() {
                break;
            }
        }
        Ok(())
    }
}
