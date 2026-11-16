//! Verify and release stages.
//!
//! Verify checks an extent's articles on every backbone that counts
//! toward a release. Release unpins the safety copy, and only on evidence
//! read in the same job. The copy stays in R2 and keeps serving reads;
//! from then on the hot-tier eviction may drop it.
//!
//! The release rule ([`releasable`]), the same for the verify decision,
//! the release job and the catalogue's guard:
//! - Only a backbone that counts is evidence ([`release_backbones`]): it
//!   has an enabled `read` provider, and none of its providers says
//!   `release: false`. The others are neither read nor counted here.
//! - On at least one of them every article was read back with `BODY` and
//!   its payload hash matched (the full check).
//! - `REQUIRED_BACKBONES` distinct ones in all hold every article, the
//!   others by `BODY` or by `STAT`.
//! - A `STAT` pass is never the full check: a provider can answer `STAT`
//!   for an article whose `BODY` it no longer serves. So `STAT` passes
//!   alone, on however many backbones, release nothing.
//!
//! Backbones are checked in configuration order: `BODY` until one has
//! passed it, `STAT` on the ones after.
//!
//! Rules of a check:
//! - Only a complete pass over all articles is recorded. A transport
//!   failure records nothing and the job retries.
//! - A `430` is not loss by itself: an article is posted to one provider
//!   and reaches the other backbones by propagation. Missing articles are
//!   read again after 2 min, 10 min, 1 h and 6 h before a `missing` result
//!   is recorded.
//! - An article a backbone still lacks when the propagation grace is over
//!   (`PROPAGATION_GRACE_SECS` after posting) is posted straight to a
//!   provider of that backbone, under its stored message-id, while the
//!   safety copy exists; the backbone is then read again.
//! - A corrupt article is recorded at once.

use serde::Serialize;

use crate::fetch::{job_holder, read_articles, stat_articles, ProviderSession, ReadTally};
use crate::pool::Pool;
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, Lease, NntpConnector, PermitClass,
    MAX_QUEUE_DELAY_SECS,
};
use crate::post::{settle, Stop};
use crate::types::{
    ArticleRow, ArticleState, BackboneStatus, ExtentRow, FailClass, GenerationState, Job,
    JobExtent, JobOutcome, OutboxStage, ProviderConfig, SafetyState, UnixMs, VerificationRow,
    VerifyKind, VerifyResult, JOB_VERSION,
};

/// Waits before a backbone with missing articles is read again. After the
/// last one the backbone is recorded as `missing`.
pub const MISSING_BACKOFF_SECS: [u32; 4] = [120, 600, 3600, 21_600];
/// Wait before an extent with a failed backbone is verified again.
pub const REVERIFY_SECS: u32 = 21_600;
/// `Lease::cursor` = `backbone index * CURSOR_STEPS + missing retries used`.
const CURSOR_STEPS: u32 = 8;
/// In place of the retries used: the missing articles were posted to the
/// backbone itself, and the next read is the one that is recorded.
const REPOSTED: u32 = CURSOR_STEPS - 1;

type Staged<V> = core::result::Result<V, Stop>;

/// One backbone's entry in `extents.release_evidence`.
#[derive(Serialize)]
struct Evidence<'a> {
    backbone: &'a str,
    provider: &'a str,
    verified_at: UnixMs,
    kind: VerifyKind,
    ok: u32,
    total: u32,
    plan_rev: u32,
}

/// A backbone label as it is compared and recorded: trimmed, lower case.
/// Two spellings of one backbone must never count as two copies.
pub(crate) fn label(backbone: &str) -> String {
    backbone.trim().to_lowercase()
}

/// The backbones that count toward a release, each with its enabled
/// `read` providers, in configuration order. Two providers on one
/// backbone are one copy, so they share an entry.
///
/// A backbone counts only if none of its providers says `release: false`,
/// whether that provider reads, posts or is disabled: one statement that
/// the backbone is not a durable copy is enough.
pub(crate) fn release_backbones(
    providers: &[ProviderConfig],
) -> Vec<(String, Vec<&ProviderConfig>)> {
    let excluded: Vec<String> = providers
        .iter()
        .filter(|p| !p.release)
        .map(|p| label(&p.backbone))
        .collect();
    let mut groups: Vec<(String, Vec<&ProviderConfig>)> = Vec::new();
    for p in providers.iter().filter(|p| p.read && p.enabled) {
        let name = label(&p.backbone);
        if excluded.contains(&name) {
            continue;
        }
        match groups.iter_mut().find(|(b, _)| *b == name) {
            Some((_, members)) => members.push(p),
            None => groups.push((name, vec![p])),
        }
    }
    groups
}

/// The labels of [`release_backbones`].
pub(crate) fn release_labels(providers: &[ProviderConfig]) -> Vec<String> {
    release_backbones(providers)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// The release rule. `passes` are complete passes (every article of the
/// current plan), one per backbone and kind of check; `counting` are the
/// labels of the backbones that count ([`release_backbones`]).
///
/// True only if, among the backbones that count, at least one has a
/// `BODY` pass and `required` distinct ones have a pass of either kind.
/// Two passes on one backbone are one copy, and a pass on a backbone that
/// does not count is nothing.
pub fn releasable<'a>(
    passes: impl IntoIterator<Item = (&'a str, VerifyKind)>,
    counting: &[String],
    required: u32,
) -> bool {
    let mut holding: Vec<String> = Vec::new();
    let mut full = false;
    for (backbone, kind) in passes {
        let name = label(backbone);
        if !counting.contains(&name) {
            continue;
        }
        full |= kind == VerifyKind::Body;
        if !holding.contains(&name) {
            holding.push(name);
        }
    }
    required > 0 && full && holding.len() >= required as usize
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

    /// Runs the release stage for a claimed extent: check every backbone
    /// that counts again now, by the same rule as at verify, then mark
    /// the safety copy evictable.
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

    /// When the minimum age of the extent's safety copy is over: the
    /// minimum age after the newest time any of its articles was posted,
    /// a repost included. The safety copy has to outlast a soak of the
    /// articles on Usenet, and an article may be posted long after its
    /// extent was stored: a multipart upload completed days after its
    /// parts, a posting backlog, a repost to a backbone that lacked it.
    /// Never earlier than the minimum age after the extent was stored.
    fn min_age_over(&self, extent: &ExtentRow, plan: &[ArticleRow]) -> UnixMs {
        let posted = plan.iter().filter_map(ArticleRow::last_posted_at).max();
        posted
            .map_or(extent.created_at, |at| at.max(extent.created_at))
            .plus_secs(self.cfg.safety_min_age_secs)
    }

    /// Checks every article on one backbone, with `BODY` and the payload
    /// hash or with `STAT` (`kind`), through its first provider in pool
    /// order with a free slot. Providers that still retain the
    /// oldest article are preferred; when none does, the others answer,
    /// because a result needs a read.
    async fn read_backbone<'p>(
        &self,
        lease: &Lease,
        plan: &[ArticleRow],
        providers: &[&'p ProviderConfig],
        kind: VerifyKind,
    ) -> Staged<(&'p ProviderConfig, ReadTally)> {
        let holder = job_holder(lease);
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
        let usable = pool.order(fresh.clone(), PermitClass::Background);
        if usable.is_empty() {
            if let Some(until) = pool.cooling_until(&fresh) {
                return Err(Stop::Cooling(until));
            }
        }
        let mut refused = false;
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
            let tally = match kind {
                VerifyKind::Body => {
                    read_articles(&mut session, Some(lease), &rows, |_, _| {}).await
                }
                VerifyKind::Stat => stat_articles(&mut session, Some(lease), &rows).await,
            };
            session.close().await;
            match tally {
                // The provider refused the account: the next one of the
                // backbone is asked.
                Err(Stop::Refused) => refused = true,
                tally => return Ok((provider, tally?)),
            }
        }
        Err(match refused {
            true => Stop::Refused,
            false => Stop::NoPermit,
        })
    }

    async fn record(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        provider: &ProviderConfig,
        tally: &ReadTally,
        kind: VerifyKind,
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
            kind,
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

    /// Queue notification for this extent, due now. The outbox row is
    /// the obligation: the dispatcher sends again for one that is lost.
    async fn notify(&self, lease: &Lease, stage: OutboxStage) {
        self.notify_at(lease, stage, self.clock.now()).await;
    }

    /// Queue notification for this extent, due at `at`. Within the
    /// longest queue delay it is the job itself, delayed until then.
    /// Further out it is a `Wake` job with the longest delay, which is
    /// sent on until `at` when it is delivered: a release, due a
    /// minimum age after the post, is on its way from here on and does
    /// not wait for the dispatcher to find it.
    async fn notify_at(&self, lease: &Lease, stage: OutboxStage, at: UnixMs) {
        // Rounded up: a job that arrives early cannot claim the row.
        let ahead_ms = at.0.saturating_sub(self.clock.now().0).max(0);
        let secs = ahead_ms.saturating_add(999).div_euclid(1000);
        let delay_secs = u32::try_from(secs).unwrap_or(u32::MAX);
        let (v, extent, generation) = (JOB_VERSION, lease.extent.clone(), lease.generation.clone());
        let job = match delay_secs > MAX_QUEUE_DELAY_SECS {
            false => Job::Extent {
                v,
                extent,
                generation,
                stage,
            },
            true => Job::Wake {
                v,
                extent,
                generation,
                stage,
                at,
            },
        };
        let _ = self
            .jobs
            .send(&job, delay_secs.min(MAX_QUEUE_DELAY_SECS))
            .await;
    }

    /// A backbone lacks articles. `Some` = the wait before it is read
    /// again; `None` = record the result now.
    ///
    /// Until the propagation grace is over the articles may still arrive
    /// on their own, so the backbone is only read again. Once it is over
    /// they are posted straight to a provider of this backbone, once per
    /// round, and read again; what that read finds is recorded.
    async fn missing_wait(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        plan: &[ArticleRow],
        backbone: &str,
        missing: &[u32],
    ) -> Staged<Option<u32>> {
        let retries = lease.cursor % CURSOR_STEPS;
        if retries == REPOSTED {
            return Ok(None);
        }
        let now = self.clock.now();
        let grace_ends = plan
            .iter()
            .filter_map(|a| a.posted_at)
            .max()
            .map(|at| at.plus_secs(self.cfg.propagation_grace_secs))
            .filter(|ends| *ends > now);
        if grace_ends.is_none() {
            let posters: Vec<&ProviderConfig> = self
                .cfg
                .providers
                .iter()
                .filter(|p| p.post && p.enabled && label(&p.backbone) == backbone)
                .collect();
            if self.repost(lease, extent, plan, missing, &posters).await? {
                self.cursor(lease, lease.cursor - retries + REPOSTED)
                    .await?;
                return Ok(Some(self.cfg.verify_delay_secs.max(1)));
            }
        }
        let Some(&wait) = MISSING_BACKOFF_SECS.get(retries as usize) else {
            return Ok(None);
        };
        self.cursor(lease, lease.cursor + 1).await?;
        // Never past the end of the grace: the repost is due then.
        let left = grace_ends.map(|ends| (ends.0 - now.0).saturating_add(999).div_euclid(1000));
        let left = left.map_or(u32::MAX, |secs| u32::try_from(secs).unwrap_or(u32::MAX));
        Ok(Some(wait.min(left.max(1))))
    }

    async fn verify_extent(&self, lease: &Lease, extent: &ExtentRow) -> Staged<()> {
        let plan = self.posted_plan(extent).await?;
        let groups = release_backbones(&self.cfg.providers);
        let labels: Vec<String> = groups.iter().map(|(name, _)| name.clone()).collect();
        let index = (lease.cursor / CURSOR_STEPS) as usize;

        if let Some((name, providers)) = groups.get(index) {
            // `BODY` until a backbone before this one has passed it.
            let mut kind = VerifyKind::Body;
            if index > 0 {
                let status = self.catalog.backbone_status(&extent.id).await?;
                let full = |s: &BackboneStatus| {
                    s.counts
                        && s.kind == VerifyKind::Body
                        && labels[..index].contains(&label(&s.backbone))
                };
                if status.iter().any(full) {
                    kind = VerifyKind::Stat;
                }
            }
            let (provider, tally) = self.read_backbone(lease, &plan, providers, kind).await?;
            if result_of(&tally) == VerifyResult::Missing {
                let wait = self
                    .missing_wait(lease, extent, &plan, name, &tally.missing)
                    .await?;
                if let Some(wait) = wait {
                    // Not recorded yet: read this backbone again later.
                    return Err(Stop::Fail(FailClass::MissingPending, Some(wait)));
                }
            }
            self.record(lease, extent, provider, &tally, kind).await?;
            let next = index as u32 + 1;
            self.cursor(lease, next * CURSOR_STEPS).await?;
            if (next as usize) < groups.len() {
                // The next backbone gets its own job; this is progress,
                // not a failure, so no attempt is spent.
                let now = self.clock.now();
                if !self.catalog.defer(lease, now, now).await? {
                    return Err(Stop::Fenced);
                }
                self.notify(lease, OutboxStage::Verify).await;
                return Ok(());
            }
        }

        // Every backbone has a recorded result for this round.
        self.cursor(lease, 0).await?;
        // Results for backbones that are no longer configured, or that do
        // not count toward a release, are not looked at.
        let mut status = self.catalog.backbone_status(&extent.id).await?;
        status.retain(|s| labels.contains(&label(&s.backbone)));
        let passes = status
            .iter()
            .filter(|s| s.counts)
            .map(|s| (s.backbone.as_str(), s.kind));
        let now = self.clock.now();
        if releasable(passes, &labels, self.cfg.required_backbones) {
            // Read again: a repost by this job stamped its articles after
            // the plan was loaded. The release job reads the plan itself
            // and is the gate; this only keeps the due time right.
            let plan = self.posted_plan(extent).await?;
            let ready = self.min_age_over(extent, &plan).max(now);
            self.advance(lease, OutboxStage::Release, ready).await?;
            self.notify_at(lease, OutboxStage::Release, ready).await;
            return Ok(());
        }
        if groups.is_empty() {
            // No backbone counts toward a release: nothing was checked
            // and nothing can be. The safety copy stays held.
            return self.advance(lease, OutboxStage::Done, now).await;
        }
        let failed = |r| status.iter().any(|s| s.result == r);
        if failed(VerifyResult::Corrupt) {
            return Err(Stop::Fail(FailClass::Corrupt, Some(REVERIFY_SECS)));
        }
        if status.iter().any(|s| !s.counts) || status.len() < groups.len() || status.is_empty() {
            return Err(Stop::Fail(FailClass::MissingPending, Some(REVERIFY_SECS)));
        }
        if !status.iter().any(|s| s.kind == VerifyKind::Body) {
            // Passes, but none of them the full check: read again.
            return Err(Stop::Fail(FailClass::Internal, Some(REVERIFY_SECS)));
        }
        // Every backbone that counts holds the extent, but there are fewer
        // of them than a release needs: the safety copy stays held.
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
            // A job died between the release decision and its last step.
            SafetyState::Releasing => return self.finish_release(lease, extent).await,
            SafetyState::Released | SafetyState::Deleted => {
                return self.advance(lease, OutboxStage::Done, now).await;
            }
        }
        // One backbone is never enough outside development.
        if required == 0 || !(required >= 2 || self.cfg.is_dev()) {
            return self.advance(lease, OutboxStage::Done, now).await;
        }
        // Too few backbones count toward a release: nothing is released
        // and nothing is read for it. The safety copy stays held and the
        // row stays in this stage, looked at again later without an
        // attempt spent. Parked as `done` it would stay there for good:
        // its earlier passes still count, so the re-drive of the
        // dispatcher would never pick it up once the list is put right.
        if self.cfg.release_paused().is_some() {
            if !self
                .catalog
                .defer(lease, now.plus_secs(REVERIFY_SECS), now)
                .await?
            {
                return Err(Stop::Fenced);
            }
            return Ok(());
        }
        // The plan first: the minimum age counts from its newest post.
        let plan = self.posted_plan(extent).await?;
        let ready = self.min_age_over(extent, &plan);
        if now < ready {
            if !self.catalog.defer(lease, ready, now).await? {
                return Err(Stop::Fenced);
            }
            return Ok(());
        }

        // Only what this job finds now counts as evidence. Every backbone
        // that counts is checked: one that lacks the extent does not hold
        // the release up while enough others pass. `BODY` until one
        // backbone has passed it, `STAT` on the ones after.
        let groups = release_backbones(&self.cfg.providers);
        let labels: Vec<String> = groups.iter().map(|(name, _)| name.clone()).collect();
        let mut read = Vec::new();
        let mut full = false;
        for (_, providers) in &groups {
            let kind = match full {
                true => VerifyKind::Stat,
                false => VerifyKind::Body,
            };
            let (provider, tally) = self.read_backbone(lease, &plan, providers, kind).await?;
            full |= kind == VerifyKind::Body && result_of(&tally) == VerifyResult::Ok;
            read.push((provider, tally, kind));
        }
        let result = |r| read.iter().filter(|(_, t, _)| result_of(t) == r).count();
        let (passed, missing) = (result(VerifyResult::Ok), result(VerifyResult::Missing));
        let passes = read
            .iter()
            .filter(|(_, t, _)| result_of(t) == VerifyResult::Ok)
            .map(|(p, _, kind)| (p.backbone.as_str(), *kind));
        let enough = releasable(passes, &labels, required);
        if !enough && passed + missing == read.len() && missing > 0 {
            // Not releasable after all, and nothing worse than missing:
            // back to verify, which owns the retry waits and the record.
            self.cursor(lease, 0).await?;
            self.advance(lease, OutboxStage::Verify, now).await?;
            self.notify(lease, OutboxStage::Verify).await;
            return Ok(());
        }
        let mut rows = Vec::new();
        for (provider, tally, kind) in &read {
            let row = self.record(lease, extent, provider, tally, *kind).await?;
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
                kind: r.kind,
                ok: r.articles_ok,
                total: r.articles_total,
                plan_rev: r.plan_rev,
            })
            .collect();
        let evidence =
            serde_json::to_string(&evidence).map_err(|_| Stop::fail(FailClass::Internal))?;
        match self
            .catalog
            .begin_release(lease, required, &labels, &evidence, self.clock.now())
            .await?
        {
            Guard::Applied(()) => self.finish_release(lease, extent).await,
            // The lease is gone or a newer result cancelled a pass. If the
            // lease still holds, the job comes back and reads again.
            Guard::Lost => Err(Stop::fail(FailClass::Internal)),
        }
    }

    /// Completes the release of an extent already marked `releasing`: the
    /// safety copy becomes evictable. Nothing is deleted here.
    async fn finish_release(&self, lease: &Lease, _extent: &ExtentRow) -> Staged<()> {
        match self.catalog.finish_release(lease, self.clock.now()).await? {
            true => Ok(()),
            false => Err(Stop::Fenced),
        }
    }
}
