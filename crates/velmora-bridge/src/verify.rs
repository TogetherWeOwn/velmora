//! Verify and release stages.
//!
//! Verify proves, per backbone, that every article of an extent can be
//! read back intact with `BODY` (a `STAT` only proves headers). Release
//! deletes the safety copy, and only on evidence read in the same job.
//!
//! Rules:
//! - Only a complete pass over all articles is recorded. A transport
//!   failure records nothing and the job retries.
//! - A `430` is not loss by itself: a fresh article can be invisible for a
//!   while. Missing articles are retried after 2 min, 10 min, 1 h and 6 h
//!   before a `missing` result is recorded.
//! - A corrupt article is recorded at once.

use serde::Serialize;

use crate::fetch::{read_articles, ProviderSession, ReadTally};
use crate::pool::Pool;
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, Lease, NntpConnector, PermitClass,
    MAX_QUEUE_DELAY_SECS,
};
use crate::post::{settle, Stop};
use crate::types::{
    ArticleRow, ArticleState, ExtentRow, FailClass, GenerationState, Job, JobExtent, JobOutcome,
    OutboxStage, ProviderConfig, SafetyState, UnixMs, VerificationRow, VerifyResult, JOB_VERSION,
};

/// Waits before a backbone with missing articles is read again. After the
/// last one the backbone is recorded as `missing`.
pub const MISSING_BACKOFF_SECS: [u32; 4] = [120, 600, 3600, 21_600];
/// Wait before an extent with a failed backbone is verified again.
pub const REVERIFY_SECS: u32 = 21_600;
/// `Lease::cursor` = `backbone index * CURSOR_STEPS + missing retries used`.
const CURSOR_STEPS: u32 = 8;

type Staged<V> = core::result::Result<V, Stop>;

/// One backbone's entry in `extents.release_evidence`.
#[derive(Serialize)]
struct Evidence<'a> {
    backbone: &'a str,
    provider: &'a str,
    verified_at: UnixMs,
    ok: u32,
    total: u32,
    plan_rev: u32,
}

/// A backbone label as it is compared and recorded: trimmed, lower case.
/// Two spellings of one backbone must never count as two copies.
fn label(backbone: &str) -> String {
    backbone.trim().to_lowercase()
}

/// Enabled `read` providers grouped by backbone, in configuration order. Two
/// providers on one backbone are one copy, so they share an entry.
pub(crate) fn backbones(providers: &[ProviderConfig]) -> Vec<(String, Vec<&ProviderConfig>)> {
    let mut groups: Vec<(String, Vec<&ProviderConfig>)> = Vec::new();
    for p in providers.iter().filter(|p| p.read && p.enabled) {
        let name = label(&p.backbone);
        match groups.iter_mut().find(|(b, _)| *b == name) {
            Some((_, members)) => members.push(p),
            None => groups.push((name, vec![p])),
        }
    }
    groups
}

fn result_of(tally: &ReadTally) -> VerifyResult {
    if !tally.corrupt.is_empty() {
        VerifyResult::Corrupt
    } else if !tally.missing.is_empty() {
        VerifyResult::Missing
    } else {
        VerifyResult::Ok
    }
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
    /// Runs the verify stage for a claimed extent: one backbone per job,
    /// then the decision once every backbone has a recorded result.
    pub async fn verify_stage(&self, lease: &Lease, job: &JobExtent) -> JobOutcome {
        match self.verify_extent(lease, &job.extent).await {
            Ok(()) => JobOutcome::Ack,
            Err(stop) => settle(&self.catalog, &self.clock, lease, stop).await,
        }
    }

    /// Runs the release stage for a claimed extent: re-verify every
    /// backbone now, then delete the safety copy.
    pub async fn release_stage(&self, lease: &Lease, job: &JobExtent) -> JobOutcome {
        match self.release_extent(lease, job).await {
            Ok(()) => JobOutcome::Ack,
            Err(stop) => settle(&self.catalog, &self.clock, lease, stop).await,
        }
    }

    /// The posted plan, or a failure if the extent is not fully posted.
    async fn posted_plan(&self, extent: &ExtentRow) -> Staged<Vec<ArticleRow>> {
        let plan = self.catalog.articles(&extent.id).await?;
        let posted = !plan.is_empty()
            && u32::try_from(plan.len()).ok() == extent.article_count
            && plan.iter().all(|a| a.state == ArticleState::Posted);
        if !posted {
            return Err(Stop::fail(FailClass::Internal));
        }
        Ok(plan)
    }

    /// Reads every article from one backbone, through its first provider
    /// in pool order with a free slot. Providers that still retain the
    /// oldest article are preferred; when none does, the others answer,
    /// because a result needs a read.
    async fn read_backbone<'p>(
        &self,
        lease: &Lease,
        plan: &[ArticleRow],
        providers: &[&'p ProviderConfig],
    ) -> Staged<(&'p ProviderConfig, ReadTally)> {
        let holder = format!("verify:{}", lease.extent);
        let rows: Vec<&ArticleRow> = plan.iter().collect();
        let now = self.clock.now();
        let oldest = plan.iter().filter_map(|a| a.posted_at).min();
        let (mut fresh, expired): (Vec<_>, Vec<_>) = providers
            .iter()
            .copied()
            .partition(|p| p.retains(oldest, now));
        if fresh.is_empty() {
            fresh = expired;
        }
        let pool = Pool::load(&self.catalog, &self.cfg.providers, now).await?;
        let usable = pool.order(fresh.clone());
        if usable.is_empty() {
            if let Some(until) = pool.cooling_until(&fresh) {
                return Err(Stop::Cooling(until));
            }
        }
        for provider in usable {
            let Some(mut session) = ProviderSession::open(
                &self.catalog,
                &self.nntp,
                &self.clock,
                provider,
                PermitClass::Background,
                &holder,
            )
            .await?
            else {
                continue;
            };
            let tally = read_articles(&mut session, Some(lease), &rows, |_, _| {}).await;
            session.close().await;
            return Ok((provider, tally?));
        }
        Err(Stop::NoPermit)
    }

    async fn record(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        provider: &ProviderConfig,
        tally: &ReadTally,
    ) -> Staged<VerificationRow> {
        let total = extent.article_count.unwrap_or(0);
        let row = VerificationRow {
            extent_id: extent.id.clone(),
            backbone: label(&provider.backbone),
            provider_id: provider.id.clone(),
            verified_at: self.clock.now(),
            plan_rev: extent.plan_rev,
            articles_ok: tally.ok,
            articles_total: total,
            result: result_of(tally),
        };
        if !self.catalog.record_verification(lease, &row).await? {
            return Err(Stop::Fenced);
        }
        Ok(row)
    }

    async fn cursor(&self, lease: &Lease, cursor: u32) -> Staged<()> {
        match self
            .catalog
            .set_cursor(lease, cursor, self.clock.now())
            .await?
        {
            true => Ok(()),
            false => Err(Stop::Fenced),
        }
    }

    async fn advance(&self, lease: &Lease, to: OutboxStage, next_at: UnixMs) -> Staged<()> {
        match self
            .catalog
            .advance(lease, to, next_at, self.clock.now())
            .await?
        {
            true => Ok(()),
            false => Err(Stop::Fenced),
        }
    }

    /// Queue notification for this extent. The outbox row is the
    /// obligation: the dispatcher re-sends one that is lost or too far out.
    async fn notify(&self, lease: &Lease, stage: OutboxStage, delay_secs: u32) {
        if delay_secs > MAX_QUEUE_DELAY_SECS {
            return;
        }
        let job = Job::Extent {
            v: JOB_VERSION,
            extent: lease.extent.clone(),
            generation: lease.generation.clone(),
            stage,
        };
        let _ = self.jobs.send(&job, delay_secs).await;
    }

    async fn verify_extent(&self, lease: &Lease, extent: &ExtentRow) -> Staged<()> {
        let plan = self.posted_plan(extent).await?;
        let groups = backbones(&self.cfg.providers);
        let index = (lease.cursor / CURSOR_STEPS) as usize;
        let retries = (lease.cursor % CURSOR_STEPS) as usize;

        if let Some((_, providers)) = groups.get(index) {
            let (provider, tally) = self.read_backbone(lease, &plan, providers).await?;
            if result_of(&tally) == VerifyResult::Missing {
                if let Some(&wait) = MISSING_BACKOFF_SECS.get(retries) {
                    // Not recorded yet: read this backbone again later.
                    self.cursor(lease, lease.cursor + 1).await?;
                    return Err(Stop::Fail(FailClass::MissingPending, Some(wait)));
                }
            }
            self.record(lease, extent, provider, &tally).await?;
            let next = index as u32 + 1;
            self.cursor(lease, next * CURSOR_STEPS).await?;
            if (next as usize) < groups.len() {
                // The next backbone gets its own job; this is progress,
                // not a failure, so no attempt is spent.
                let now = self.clock.now();
                if !self.catalog.defer(lease, now, now).await? {
                    return Err(Stop::Fenced);
                }
                self.notify(lease, OutboxStage::Verify, 0).await;
                return Ok(());
            }
        }

        // Every backbone has a recorded result for this round.
        self.cursor(lease, 0).await?;
        // Results for backbones that are no longer configured do not count.
        let mut status = self.catalog.backbone_status(&extent.id).await?;
        status.retain(|s| groups.iter().any(|(b, _)| *b == label(&s.backbone)));
        let counting = status.iter().filter(|s| s.counts).count();
        let now = self.clock.now();
        if counting >= self.cfg.required_backbones as usize && counting > 0 {
            let ready = extent
                .created_at
                .plus_secs(self.cfg.safety_min_age_secs)
                .max(now);
            self.advance(lease, OutboxStage::Release, ready).await?;
            // Rounded up: a job that arrives early cannot claim the row.
            let delay = (ready.0 - now.0).saturating_add(999).div_euclid(1000);
            self.notify(
                lease,
                OutboxStage::Release,
                u32::try_from(delay).unwrap_or(u32::MAX),
            )
            .await;
            return Ok(());
        }
        let failed = |r| status.iter().any(|s| s.result == r);
        if failed(VerifyResult::Corrupt) {
            return Err(Stop::Fail(FailClass::Corrupt, Some(REVERIFY_SECS)));
        }
        if status.iter().any(|s| !s.counts) || status.len() < groups.len() || status.is_empty() {
            return Err(Stop::Fail(FailClass::MissingPending, Some(REVERIFY_SECS)));
        }
        // Every configured backbone holds the extent, but there are fewer
        // backbones than a release needs: the safety copy stays held.
        self.advance(lease, OutboxStage::Done, now).await
    }

    async fn release_extent(&self, lease: &Lease, job: &JobExtent) -> Staged<()> {
        let extent = &job.extent;
        let now = self.clock.now();
        if job.generation_state == GenerationState::Deleted {
            // Garbage collection owns a deleted generation's blobs.
            return self.advance(lease, OutboxStage::Cancelled, now).await;
        }
        let required = self.cfg.required_backbones;
        match extent.safety_state {
            SafetyState::Held => {}
            // A job died between the release decision and the delete.
            SafetyState::Releasing => return self.finish_release(lease, extent).await,
            SafetyState::Released | SafetyState::Deleted => {
                return self.advance(lease, OutboxStage::Done, now).await;
            }
        }
        // One backbone is never enough outside development.
        if required == 0 || !(required >= 2 || self.cfg.is_dev()) {
            return self.advance(lease, OutboxStage::Done, now).await;
        }
        let ready = extent.created_at.plus_secs(self.cfg.safety_min_age_secs);
        if now < ready {
            if !self.catalog.defer(lease, ready, now).await? {
                return Err(Stop::Fenced);
            }
            return Ok(());
        }

        // Only what this job reads now counts as evidence. Every
        // backbone is read: one that lacks the extent does not hold the
        // release up while `required` others pass.
        let plan = self.posted_plan(extent).await?;
        let mut read = Vec::new();
        for (_, providers) in backbones(&self.cfg.providers) {
            read.push(self.read_backbone(lease, &plan, &providers).await?);
        }
        let result = |r| read.iter().filter(|(_, t)| result_of(t) == r).count();
        let (passed, missing) = (result(VerifyResult::Ok), result(VerifyResult::Missing));
        let enough = passed >= required as usize;
        if !enough && passed + missing == read.len() && missing > 0 {
            // Not releasable after all, and nothing worse than missing:
            // back to verify, which owns the retry waits and the record.
            self.cursor(lease, 0).await?;
            self.advance(lease, OutboxStage::Verify, now).await?;
            self.notify(lease, OutboxStage::Verify, 0).await;
            return Ok(());
        }
        let mut rows = Vec::new();
        for (provider, tally) in &read {
            let row = self.record(lease, extent, provider, tally).await?;
            if row.result == VerifyResult::Ok {
                rows.push(row);
            }
        }
        if !enough && rows.len() < read.len() {
            // A backbone serves damaged articles: verify again later.
            self.cursor(lease, 0).await?;
            let again = self.clock.now().plus_secs(REVERIFY_SECS);
            return self.advance(lease, OutboxStage::Verify, again).await;
        }
        if !enough {
            return Err(Stop::Fail(FailClass::Internal, Some(REVERIFY_SECS)));
        }
        let evidence: Vec<Evidence<'_>> = rows
            .iter()
            .map(|r| Evidence {
                backbone: &r.backbone,
                provider: &r.provider_id,
                verified_at: r.verified_at,
                ok: r.articles_ok,
                total: r.articles_total,
                plan_rev: r.plan_rev,
            })
            .collect();
        let evidence =
            serde_json::to_string(&evidence).map_err(|_| Stop::fail(FailClass::Internal))?;
        match self
            .catalog
            .begin_release(lease, required, &evidence, self.clock.now())
            .await?
        {
            Guard::Applied(()) => self.finish_release(lease, extent).await,
            // The lease is gone or a newer result cancelled a pass. If the
            // lease still holds, the job comes back and reads again.
            Guard::Lost => Err(Stop::fail(FailClass::Internal)),
        }
    }

    /// Deletes the safety copy of an extent already marked `releasing`.
    /// Both steps are idempotent, so a re-driven job finishes the release.
    async fn finish_release(&self, lease: &Lease, extent: &ExtentRow) -> Staged<()> {
        if !self.catalog.renew(lease, self.clock.now()).await? {
            return Err(Stop::Fenced);
        }
        self.safety.delete(&extent.id.safety_key()).await?;
        match self.catalog.finish_release(lease, self.clock.now()).await? {
            true => Ok(()),
            false => Err(Stop::Fenced),
        }
    }
}
