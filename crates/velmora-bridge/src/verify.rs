//! Verify and release stages.
//!
//! Verify checks an extent's articles on every backbone that counts
//! toward a release. Release unpins the safety copy, and only on evidence
//! of presence asked for in the same job. The copy stays in R2 and keeps
//! serving reads; from then on the hot-tier eviction may drop it.
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
//! Where the two kinds of check happen (an operator decision, taken to
//! halve the read volume asked of the providers):
//! - The full `BODY` read happens once, at verify. Verify checks the
//!   backbones in configuration order: `BODY` until one has passed it,
//!   `STAT` on the ones after.
//! - Release reads no `BODY`. Once the minimum age is over it asks every
//!   backbone that counts for every article with `STAT`, and only what
//!   that job finds counts as presence. The full check it takes from the
//!   record: a complete `BODY` pass of the extent's current `plan_rev`
//!   that no later check has cancelled, on a backbone whose `STAT` pass
//!   it has just seen. A backbone counts as the full check only so.
//! - A backbone whose last `BODY` read of the current plan failed
//!   (missing or corrupt) holds no copy at release, whatever it answers
//!   to `STAT`, until verify has read it in full again and it passed.
//!   Verify therefore reads such a backbone with `BODY`, not `STAT`,
//!   also when an earlier backbone has passed the full check.
//! - A plan that changed (a new `plan_rev`) has no full check on record:
//!   it goes back to verify and is read in full before any release.
//! - A release that finds an article missing where it is needed records
//!   nothing and goes back to verify after `VERIFY_DELAY_SECS`: verify
//!   owns the waits, the repost and the record.
//! - What this gives up: a body that a backbone stopped serving between
//!   verify and release, while it still answers `STAT`, is not seen by
//!   the release. Only a later read of the bodies would find it.
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
//!
//! # The light check (`VERIFY_MODE=light`)
//!
//! An operator decision, taken because the full read of every extent is
//! what bounds the verify stage. Under `light`, verify reads no `BODY`
//! for most extents:
//! - Every backbone that counts is asked for every article, with the
//!   size command of its provider where it has one
//!   (`VERIFY_SIZE_COMMANDS`, [`crate::types::SizeCommand`]) and with
//!   `STAT` where it has none. A size command says that the article is
//!   there and what size the provider reports for it; that size has to
//!   be one the posted article can have ([`crate::fetch::size_bounds`]).
//!   A pass where every article had a size that fits is recorded as
//!   `size`; one where a size was missing is recorded as the `stat` pass
//!   it is; a size that does not fit is recorded as `corrupt`.
//! - A sample of the extents is read in full on one backbone, as above
//!   (`sampled`). Which extents, and on which backbone, follows from the
//!   extent id and a key derived from the active KEK ([`in_sample`]), so
//!   a retry and the release job come to the same answer for as long as
//!   the active KEK is the same one, and a provider cannot tell which
//!   articles will be read. A new active KEK draws the sample anew: an
//!   extent that waits then may be read in full on another backbone, or
//!   on none if a full read of it is on record. The rate is
//!   `VERIFY_SAMPLE_PERCENT`.
//! - A backbone whose last check of the bytes failed (a full read, or a
//!   size that did not fit) is read in full, as under `body`, and holds
//!   no copy until that read passes.
//! - A full read under `light` that finds an article corrupt, or missing
//!   where `STAT` says it is there and a second read still does not get
//!   it, raises the sample to every extent for that backbone for
//!   `VERIFY_ESCALATE_SECS` ([`Catalog::escalate_verify`]): the provider
//!   answered for bytes it does not serve. A missing article is held
//!   against `STAT` by the read that finds it, before the waits for a
//!   missing article. An extent raises a backbone once for a plan: the
//!   same failure found again by its retries does not move the end,
//!   another extent's does. The cron report names such backbones.
//!
//! The release under `light`:
//! - The lease, the minimum age, the `STAT` of every article on every
//!   backbone in the release job, and `REQUIRED_BACKBONES` distinct
//!   backbones that hold every article are as under `body`.
//! - An extent in the sample needs the full check on record, as under
//!   `body`. So does every extent while a backbone that counts is under
//!   full reads, and that backbone holds a copy only with its own full
//!   check on record.
//! - An extent outside the sample is released without a full check
//!   ([`Catalog::begin_release_light`]). What this gives up: for such an
//!   extent no byte was read back from any provider. A provider that
//!   answers for articles whose bytes it does not serve is found by the
//!   sample, not for each extent.
//!
//! The two modes side by side (a rollout, a rollback): each job follows
//! the mode of the Worker it runs in. A full check recorded under either
//! mode counts under both. An extent verified under `light` and released
//! under `body` has no full check on record, so it goes back to verify
//! and is read in full.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::config::VerifyMode;
use crate::fetch::{
    ask_articles_together, job_holder, read_articles, stat_articles, ProviderSession, ReadTally,
};
use crate::pool::Pool;
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, Lease, NntpConnector, PermitClass,
    MAX_QUEUE_DELAY_SECS,
};
use crate::post::{settle, settle_at, Stop};
use crate::types::{
    ArticleRow, ArticleState, BackboneStatus, ExtentId, ExtentRow, FailClass, GenerationState, Job,
    JobExtent, JobOutcome, KekBytes, OutboxStage, ProviderConfig, SafetyState, SizeCommand, UnixMs,
    VerificationRow, VerifyEscalation, VerifyKind, VerifyResult, JOB_VERSION,
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
    /// For a `size` entry: the size command set for its provider
    /// (`VERIFY_SIZE_COMMANDS`) when the release ran. The verification
    /// row does not keep the command: after a change of that setting
    /// between an extent's verify and its release, this names the new
    /// one. Nothing decides on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    size_command: Option<SizeCommand>,
}

const SAMPLE_KEY_INFO: &[u8] = b"velmora/verify-sample/v1";
/// The sample is drawn in parts per million.
const SAMPLE_SCALE: u64 = 1_000_000;

/// The draw of an extent for the sample of the light check:
/// HMAC-SHA256 of its id under a key derived from `kek` (HKDF-SHA256).
/// It depends on nothing else, so every job comes to the same answer for
/// an extent while the active KEK is the same. Without the key the
/// sample cannot be told from the ids.
fn sample_draw(kek: &KekBytes, extent: &ExtentId) -> [u8; 32] {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, kek.expose())
        .expand(SAMPLE_KEY_INFO, key.as_mut())
        .expect("HKDF-SHA256 output of 32 bytes");
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key[..])
        .expect("HMAC-SHA256 takes a key of any length");
    mac.update(extent.as_str().as_bytes());
    mac.finalize().into_bytes().into()
}

fn draw_word(draw: &[u8; 32], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&draw[at..at + 8]);
    u64::from_be_bytes(word)
}

/// Whether `extent` is in the sample that the light check reads in full,
/// at a rate of `ppm` parts per million.
pub fn in_sample(kek: &KekBytes, extent: &ExtentId, ppm: u32) -> bool {
    draw_word(&sample_draw(kek, extent), 0) % SAMPLE_SCALE < u64::from(ppm)
}

/// Which of `backbones` backbones (an index below it) a sampled extent
/// is read in full on. It is drawn too, so every backbone is sampled.
pub fn sample_backbone(kek: &KekBytes, extent: &ExtentId, backbones: usize) -> usize {
    let count = u64::try_from(backbones.max(1)).unwrap_or(u64::MAX);
    // Below `backbones`, so it fits a `usize`.
    (draw_word(&sample_draw(kek, extent), 8) % count) as usize
}

/// What the light check asks for one extent.
struct Light {
    /// The extent is in the sample.
    sampled: bool,
    /// Index of the backbone a sampled extent is read in full on.
    sample_index: usize,
    /// The backbones that count and are read in full for every extent.
    escalated: Vec<String>,
}

impl Light {
    /// Whether a release of this extent needs the full check on record.
    fn need_full(&self) -> bool {
        self.sampled || !self.escalated.is_empty()
    }

    /// Whether the backbone `name`, at `index` among those that count,
    /// is one this extent is read in full on.
    fn names(&self, index: usize, name: &str) -> bool {
        self.escalated.iter().any(|e| e == name) || (self.sampled && index == self.sample_index)
    }
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
    release_rule(passes, counting, required, true)
}

/// [`releasable`], with the full check asked for or not. `need_full` is
/// false only under the light check, for an extent outside the sample:
/// then `required` distinct backbones that count, each with a pass of
/// any kind, are enough.
pub fn release_rule<'a>(
    passes: impl IntoIterator<Item = (&'a str, VerifyKind)>,
    counting: &[String],
    required: u32,
    need_full: bool,
) -> bool {
    let mut holding: Vec<String> = Vec::new();
    let mut full = false;
    for (backbone, kind) in passes {
        let name = label(backbone);
        if !counting.contains(&name) {
            continue;
        }
        full |= kind.is_full();
        if !holding.contains(&name) {
            holding.push(name);
        }
    }
    required > 0 && (full || !need_full) && holding.len() >= required as usize
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
    /// Runs the verify stage for a claimed extent: every backbone that
    /// counts, one after the other in this job, then the decision once
    /// each has a recorded result.
    ///
    /// A job that stops part way (no slot on the next backbone, a broken
    /// connection) leaves the row at the first backbone without a
    /// result, so the next job does not read the ones before it again:
    /// the resume point goes with the write that gives the lease back.
    pub async fn verify_stage(&self, lease: &Lease, job: &JobExtent) -> JobOutcome {
        let mut reached = None;
        match self.verify_extent(lease, &job.extent, &mut reached).await {
            Ok(()) => JobOutcome::Ack,
            Err(stop) => settle_at(&self.catalog, &self.clock, lease, stop, reached).await,
        }
    }

    /// Runs the release stage for a claimed extent: ask every backbone
    /// that counts for every article now (`STAT`), require the full check
    /// on record from verify, then mark the safety copy evictable.
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

    /// What the light check asks for `extent`; `None` under
    /// `VERIFY_MODE=body`. `labels` are the backbones that count.
    async fn light(&self, extent: &ExtentRow, labels: &[String]) -> Staged<Option<Light>> {
        if self.cfg.verify.mode != VerifyMode::Light {
            return Ok(None);
        }
        let (_, kek) = self.kek.active();
        // Every escalation that had not ended when the extent was
        // stored, not only those that run now: an extent that waited
        // through one (a backlog, a release that came late) is read in
        // full all the same.
        let raised = self.catalog.verify_escalations(extent.created_at).await?;
        let escalated = raised
            .into_iter()
            .map(|e| label(&e.backbone))
            .filter(|name| labels.contains(name))
            .collect();
        Ok(Some(Light {
            sampled: in_sample(kek, &extent.id, self.cfg.verify.sample_ppm),
            sample_index: sample_backbone(kek, &extent.id, labels.len()),
            escalated,
        }))
    }

    /// Whether a group of providers has a size command at all.
    fn has_size_command(&self, providers: &[&ProviderConfig]) -> bool {
        let known = |p: &&ProviderConfig| self.cfg.verify.size_command(&p.id).is_some();
        providers.iter().any(known)
    }

    /// The kind a pass that was asked for as `asked` is recorded as. A
    /// size pass is one only if every article that is there had a size:
    /// one that fits, or one that does not (then the result is
    /// `corrupt`). Without a size it is the `STAT` pass it was.
    fn recorded_kind(asked: VerifyKind, tally: &ReadTally) -> VerifyKind {
        match asked {
            VerifyKind::Size if tally.corrupt.is_empty() => {
                match tally.ok > 0 && tally.sized == tally.ok {
                    true => VerifyKind::Size,
                    false => VerifyKind::Stat,
                }
            }
            asked => asked,
        }
    }

    /// Checks every article on one backbone, with `BODY` and the payload
    /// hash, with the provider's size command, or with `STAT` (`kind`),
    /// through its first provider in pool order with a free slot. A
    /// provider without a size command answers a size pass with `STAT`. Providers that still retain the
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
        let together = self.cfg.verify.mode == VerifyMode::Light;
        let now = self.clock.now();
        let oldest = plan.iter().filter_map(|a| a.posted_at).min();
        let (mut fresh, expired): (Vec<_>, Vec<_>) = providers
            .iter()
            .copied()
            .partition(|p| p.retains(oldest, now));
        if fresh.is_empty() {
            fresh = expired;
        }
        let mut waited = false;
        loop {
            // The pool as it is now: a wait may have outlasted a cooldown,
            // or seen one begin.
            let at = self.clock.now();
            let pool = match Pool::load(&self.catalog, &self.cfg.providers, at).await {
                // A later ask that cannot read the pool ends the wait as
                // a put-off: the attempt of the claim is handed back.
                Err(_) if waited => return Err(Stop::NoPermit),
                pool => pool?,
            };
            let usable = pool.order(fresh.clone(), PermitClass::Background);
            if usable.is_empty() {
                return Err(match pool.cooling_until(&fresh) {
                    Some(until) => Stop::Cooling(until),
                    None => Stop::NoPermit,
                });
            }
            let asked = usable.len();
            let mut refused = false;
            for provider in usable {
                let opened = ProviderSession::open(
                    &self.catalog,
                    &self.nntp,
                    &self.clock,
                    provider,
                    PermitClass::Background,
                    &holder,
                )
                .await;
                let Some(mut session) = (match opened {
                    Err(_) if waited => return Err(Stop::NoPermit),
                    opened => opened?,
                }) else {
                    continue;
                };
                let tally = match kind {
                    VerifyKind::Body | VerifyKind::Sampled => {
                        read_articles(&mut session, Some(lease), &rows, |_, _| {}).await
                    }
                    // Under the light check the articles of an extent are
                    // asked for together; under `body` one by one, as before.
                    VerifyKind::Stat if together => {
                        ask_articles_together(&mut session, Some(lease), &rows, None).await
                    }
                    VerifyKind::Stat => stat_articles(&mut session, Some(lease), &rows).await,
                    VerifyKind::Size => {
                        let how = self.cfg.verify.size_command(&provider.id);
                        ask_articles_together(&mut session, Some(lease), &rows, how).await
                    }
                };
                session.close().await;
                match tally {
                    // The provider refused the account: the next one of the
                    // backbone is asked.
                    Err(Stop::Refused) => refused = true,
                    tally => return Ok((provider, tally?)),
                }
            }
            if refused {
                return Err(Stop::Refused);
            }
            // No slot on this backbone. It is waited for under the claim
            // for a bounded time ([`crate::jobs::SLOT_WAIT_MS`]): the
            // row is not given back and delivered again for a slot
            // that comes free in seconds.
            if !self.slot_wait(lease, asked).await {
                return Err(Stop::NoPermit);
            }
            waited = true;
        }
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

    /// Ends a verify round that did not pass: the next one reads every
    /// backbone again, from the first.
    async fn round_failed(&self, lease: &Lease, class: FailClass) -> Staged<()> {
        if lease.cursor != 0 {
            self.cursor(lease, 0).await?;
        }
        Err(Stop::Fail(class, Some(REVERIFY_SECS)))
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

    /// Queue notification for this extent, due at `at`. The outbox row
    /// is the obligation: the dispatcher sends again for one that is
    /// lost. Within the
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
    /// again; `None` = record the result now. `cursor` is the resume
    /// point of that backbone in this job: the row's own for the
    /// backbone the job started at, without retries for a later one.
    /// What is stored here names the backbone and its retries both.
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
        cursor: u32,
    ) -> Staged<Option<u32>> {
        let retries = cursor % CURSOR_STEPS;
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
            if self
                .repost(lease, extent, plan, missing, &posters, None)
                .await?
            {
                self.cursor(lease, cursor - retries + REPOSTED).await?;
                return Ok(Some(self.cfg.verify_delay_secs.max(1)));
            }
        }
        let Some(&wait) = MISSING_BACKOFF_SECS.get(retries as usize) else {
            return Ok(None);
        };
        self.cursor(lease, cursor + 1).await?;
        // Never past the end of the grace: the repost is due then.
        let left = grace_ends.map(|ends| (ends.0 - now.0).saturating_add(999).div_euclid(1000));
        let left = left.map_or(u32::MAX, |secs| u32::try_from(secs).unwrap_or(u32::MAX));
        Ok(Some(wait.min(left.max(1))))
    }

    /// A full read under the light check failed on `backbone`: decides
    /// whether the provider answered for bytes it does not serve, and if
    /// so raises the sample to every extent there for a while.
    ///
    /// A corrupt article is that at once. A missing one is that only if
    /// the same provider (`providers`) says with `STAT` that it has it
    /// and then still does not serve it: an article that is simply not
    /// there is found by every check, the light one too, and one that
    /// arrived between the read and the `STAT` is read the second time.
    /// What that second read finds is the word on those articles, and
    /// `tally` is brought up to it: one it read and checked is no longer
    /// missing, one it found with other bytes is corrupt.
    ///
    /// An extent raises a backbone once for a plan
    /// ([`Catalog::verify_raised`]): its bytes are as bad on a retry as
    /// they were, and what another extent finds there is what is news.
    /// That is stored with the escalation and nowhere else, so a raise
    /// that was not stored is made by the next job that fails the read,
    /// whatever the record of the reads says by then.
    async fn sample_failed(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        plan: &[ArticleRow],
        providers: &[&ProviderConfig],
        backbone: &str,
        tally: &mut ReadTally,
    ) -> Staged<()> {
        let raised = self
            .catalog
            .verify_raised(&extent.id, backbone, extent.plan_rev);
        if raised.await? {
            return Ok(());
        }
        let mut result = VerifyResult::Corrupt;
        if tally.corrupt.is_empty() {
            let rows = |of: &[u32], keep: bool| -> Vec<ArticleRow> {
                let pick = |a: &&ArticleRow| of.contains(&a.idx) == keep;
                plan.iter().filter(pick).cloned().collect()
            };
            let gone = rows(&tally.missing, true);
            let (_, stat) = self
                .read_backbone(lease, &gone, providers, VerifyKind::Stat)
                .await?;
            // Those the provider says it has, read once more.
            let listed: Vec<ArticleRow> = gone
                .into_iter()
                .filter(|a| !stat.missing.contains(&a.idx))
                .collect();
            if listed.is_empty() {
                return Ok(());
            }
            let (_, again) = self
                .read_backbone(lease, &listed, providers, VerifyKind::Body)
                .await?;
            for a in &listed {
                if again.missing.contains(&a.idx) {
                    continue;
                }
                tally.missing.retain(|idx| *idx != a.idx);
                match again.corrupt.contains(&a.idx) {
                    true => tally.corrupt.push(a.idx),
                    false => tally.ok += 1,
                }
            }
            result = result_of(&again);
            if result == VerifyResult::Ok {
                return Ok(());
            }
        }
        let now = self.clock.now();
        let raised = VerifyEscalation {
            backbone: backbone.to_string(),
            until: now.plus_secs(self.cfg.verify.escalate_secs),
            raised_at: now,
            extent_id: extent.id.clone(),
            result,
        };
        self.catalog
            .escalate_verify(&raised, extent.plan_rev)
            .await?;
        crate::trace::alert(|| {
            format!(
                "verify: full read of a sampled extent failed ({}) on backbone {backbone}; \
                 every extent is read in full there for {} s",
                result.as_str(),
                self.cfg.verify.escalate_secs
            )
        });
        Ok(())
    }

    /// Whether the last check of the bytes of `backbone` for the current
    /// plan is on record as a failure: a full read, or a size that did
    /// not fit ([`Catalog::body_checks`]).
    async fn full_read_failed(&self, extent: &ExtentRow, backbone: &str) -> Staged<bool> {
        let checks = self.catalog.body_checks(&extent.id).await?;
        Ok(checks.iter().any(|b| {
            b.plan_rev == extent.plan_rev
                && label(&b.backbone) == backbone
                && (b.result != VerifyResult::Ok || b.articles_ok != b.articles_total)
        }))
    }

    /// Whether a backbone the light check does not name for `extent` is
    /// read in full all the same: the release needs a full check, none
    /// is on record for the current plan, and every backbone that was
    /// named has failed its own. Without this an extent whose named
    /// backbone lacks it would wait for that backbone for good, however
    /// many others hold it.
    async fn full_read_owed(
        &self,
        extent: &ExtentRow,
        labels: &[String],
        light: &Light,
    ) -> Staged<bool> {
        let mut checks = self.catalog.body_checks(&extent.id).await?;
        checks.retain(|b| b.plan_rev == extent.plan_rev && labels.contains(&label(&b.backbone)));
        if checks.iter().any(|b| b.counts) {
            return Ok(false);
        }
        let failed = |name: &String| checks.iter().any(|b| label(&b.backbone) == *name);
        let mut named = labels
            .iter()
            .enumerate()
            .filter(|(i, n)| light.names(*i, n));
        Ok(named.all(|(_, name)| failed(name)))
    }

    /// `reached` is the resume point the job has got to and the row does
    /// not say yet: `Some` once a backbone has its result and until a
    /// write stores a resume point or the reads are over. The caller
    /// stores it when the job stops ([`settle_at`]).
    async fn verify_extent(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        reached: &mut Option<u32>,
    ) -> Staged<()> {
        let plan = self.posted_plan(extent).await?;
        let groups = release_backbones(&self.cfg.providers);
        let labels: Vec<String> = groups.iter().map(|(name, _)| name.clone()).collect();
        let first = (lease.cursor / CURSOR_STEPS) as usize;
        let light = self.light(extent, &labels).await?;
        let need_full = light.as_ref().is_none_or(Light::need_full);

        for (index, (name, providers)) in groups.iter().enumerate().skip(first) {
            // The retries used count for the backbone the row names;
            // a later one starts without.
            let cursor = match index == first {
                true => lease.cursor,
                false => index as u32 * CURSOR_STEPS,
            };
            // `BODY` until a backbone before this one has passed it, and
            // `BODY` again on a backbone whose last full read failed: the
            // release takes no `STAT` answer from it until it has passed
            // one, so `STAT` here would send the extent round for ever.
            let mut kind = VerifyKind::Body;
            if let Some(light) = &light {
                // The light check: a full read only where the last check
                // of the bytes failed, where the backbone is under full
                // reads, and for the sample; the size or `STAT` else.
                kind = if self.full_read_failed(extent, name).await? {
                    VerifyKind::Body
                } else if light.names(index, name)
                    || (need_full && self.full_read_owed(extent, &labels, light).await?)
                {
                    VerifyKind::Sampled
                } else if self.has_size_command(providers) {
                    VerifyKind::Size
                } else {
                    VerifyKind::Stat
                };
            } else if index > 0 {
                let status = self.catalog.backbone_status(&extent.id).await?;
                let full = |s: &BackboneStatus| {
                    s.counts && s.kind.is_full() && labels[..index].contains(&label(&s.backbone))
                };
                if status.iter().any(full) && !self.full_read_failed(extent, name).await? {
                    kind = VerifyKind::Stat;
                }
            }
            // Under the light check a full read that fails may raise the
            // backbone to full reads, once for this extent and plan
            // ([`Self::sample_failed`]).
            let watched = light.is_some() && kind.is_full();
            let mut asked = false;
            let (provider, mut tally) = self.read_backbone(lease, &plan, providers, kind).await?;
            if watched && result_of(&tally) == VerifyResult::Missing {
                // Before the waits for a missing article, which may take
                // hours: a provider that says with `STAT` it has what it
                // does not serve is answering for other extents all that
                // time. An article this reads after all is not missing.
                self.sample_failed(lease, extent, &plan, &[provider], name, &mut tally)
                    .await?;
                asked = true;
            }
            if result_of(&tally) == VerifyResult::Missing {
                // What this stores is the resume point of this backbone.
                let stored = reached.take();
                let wait = self
                    .missing_wait(lease, extent, &plan, name, &tally.missing, cursor)
                    .await;
                let wait = match wait {
                    Ok(wait) => wait,
                    Err(stop) => {
                        // Nothing may have been stored: the job still
                        // has to say where it got to.
                        *reached = stored;
                        return Err(stop);
                    }
                };
                if let Some(wait) = wait {
                    // Not recorded yet: read this backbone again later.
                    return Err(Stop::Fail(FailClass::MissingPending, Some(wait)));
                }
                *reached = stored;
            }
            let kind = Self::recorded_kind(kind, &tally);
            let row = self.record(lease, extent, provider, &tally, kind).await?;
            if watched && !asked && row.result != VerifyResult::Ok {
                // Recorded first: the failure stands whatever comes of
                // this. A raise that is not stored is made by the next
                // job that fails this read.
                // Asked of the provider that failed the read: another
                // provider of the backbone may answer differently.
                // A backbone read in place of a named one is raised like
                // any other: the rows do not say which articles failed,
                // so bytes that were bad when posted cannot be told from
                // damage of its own.
                self.sample_failed(lease, extent, &plan, &[provider], name, &mut tally)
                    .await?;
            }
            // The next backbone is read by this job, under the same
            // claim. Its resume point is stored only if the job stops
            // before the round is over.
            *reached = Some((index as u32 + 1) * CURSOR_STEPS);
        }
        // The reads are over: a stop from here on stores no resume
        // point. A job that comes back finds the row where its claim
        // found it and reads again from there.
        *reached = None;

        // Every backbone has a recorded result for this round. The next
        // round starts at the first backbone: a move to another stage
        // resets the resume point itself ([`Catalog::advance`]), a round
        // that fails resets it first ([`Self::round_failed`]).
        // Results for backbones that are no longer configured, or that do
        // not count toward a release, are not looked at.
        let mut status = self.catalog.backbone_status(&extent.id).await?;
        status.retain(|s| labels.contains(&label(&s.backbone)));
        let full_now = status.iter().any(|s| s.counts && s.kind.is_full());
        if light.is_some() && need_full && !full_now {
            // Under the light check a backbone that was read in full
            // before is asked for presence in a later round, and that
            // row is its latest. The full read on record still stands,
            // as it does for the release: a pass now on a backbone with
            // a complete full read of this plan is the full check.
            let checks = self.catalog.body_checks(&extent.id).await?;
            let read = |s: &BackboneStatus| {
                let on = |b: &&BackboneStatus| label(&b.backbone) == label(&s.backbone);
                let mut of_plan = checks.iter().filter(|b| b.plan_rev == extent.plan_rev);
                of_plan.any(|b| b.counts && on(&b))
            };
            for s in status.iter_mut().filter(|s| s.counts && !s.kind.is_full()) {
                if read(s) {
                    s.kind = VerifyKind::Body;
                }
            }
        }
        let passes = status
            .iter()
            .filter(|s| s.counts)
            .map(|s| (s.backbone.as_str(), s.kind));
        let now = self.clock.now();
        if release_rule(passes, &labels, self.cfg.required_backbones, need_full) {
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
            return self.round_failed(lease, FailClass::Corrupt).await;
        }
        if status.iter().any(|s| !s.counts) || status.len() < groups.len() || status.is_empty() {
            return self.round_failed(lease, FailClass::MissingPending).await;
        }
        if need_full && !status.iter().any(|s| s.kind.is_full()) {
            // Passes, but none of them the full check: read again.
            return self.round_failed(lease, FailClass::Internal).await;
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

        let groups = release_backbones(&self.cfg.providers);
        let labels: Vec<String> = groups.iter().map(|(name, _)| name.clone()).collect();
        // The full check is not repeated here: it is taken from the
        // record, a complete `BODY` pass of the current plan on a
        // backbone that counts. A plan without one was never read in
        // full (or its pass was cancelled since): back to verify, which
        // reads it, and nothing is asked of a provider here.
        let mut checks = self.catalog.body_checks(&extent.id).await?;
        checks.retain(|b| b.plan_rev == extent.plan_rev && labels.contains(&label(&b.backbone)));
        // A backbone whose last full read failed holds no copy, whatever
        // it answers to `STAT`, until verify reads it in full again.
        let (full, failed): (Vec<_>, Vec<_>) = checks.into_iter().partition(|b| b.counts);
        let mut failed: Vec<String> = failed
            .iter()
            .filter(|b| b.result != VerifyResult::Ok || b.articles_ok != b.articles_total)
            .map(|b| label(&b.backbone))
            .collect();
        // The light check asks for the full check only for the sample
        // and while a backbone is under full reads; `body` always does.
        let light = self.light(extent, &labels).await?;
        let need_full = light.as_ref().is_none_or(Light::need_full);
        if need_full && full.is_empty() {
            return self.back_to_verify(lease, now, 0).await;
        }
        // A backbone under full reads holds a copy only with its own
        // full check on record.
        for name in light.iter().flat_map(|l| &l.escalated) {
            let read = full.iter().any(|b| label(&b.backbone) == *name);
            if !read && !failed.contains(name) {
                failed.push(name.clone());
            }
        }
        // What verify recorded last for each backbone, for the evidence:
        // read before this job's own rows hide it.
        let mut verified = self.catalog.backbone_status(&extent.id).await?;
        if light.is_some() {
            // Under the light check a backbone holds a copy only if
            // verify's last word on it was a complete pass: an answer to
            // `STAT` here does not stand in for a size check that failed
            // or was never made (a backbone that lacked the extent at
            // verify and has it now).
            for name in &labels {
                let passed = verified
                    .iter()
                    .any(|s| s.counts && label(&s.backbone) == *name);
                if !passed && !failed.contains(name) {
                    failed.push(name.clone());
                }
            }
        }
        verified.retain(|s| {
            s.counts && s.kind == VerifyKind::Size && labels.contains(&label(&s.backbone))
        });
        // Presence: only what this job finds now counts. Every backbone
        // that counts is asked with `STAT`, and no `BODY` is read: one
        // that lacks the extent does not hold the release up while enough
        // others pass.
        let mut read = Vec::new();
        for (_, providers) in &groups {
            read.push(
                self.read_backbone(lease, &plan, providers, VerifyKind::Stat)
                    .await?,
            );
        }
        // A backbone is the full check only if it was read in full on
        // record and still answers for every article now.
        let read_in_full = |backbone: &str| {
            let name = label(backbone);
            full.iter().any(|b| label(&b.backbone) == name)
        };
        let holds = |(p, t): &(&ProviderConfig, ReadTally)| {
            result_of(t) == VerifyResult::Ok && !failed.contains(&label(&p.backbone))
        };
        let passes =
            read.iter()
                .filter(|r| holds(r))
                .map(|(p, _)| match read_in_full(&p.backbone) {
                    true => (p.backbone.as_str(), VerifyKind::Body),
                    false => (p.backbone.as_str(), VerifyKind::Stat),
                });
        if !release_rule(passes, &labels, required, need_full) {
            if read.iter().all(holds) {
                return Err(Stop::Fail(FailClass::Internal, Some(REVERIFY_SECS)));
            }
            // An article is missing where it has to be, or a backbone
            // that is needed was last read in full and failed. Nothing is
            // recorded: back to verify, which owns the retry waits, the
            // repost, the record, and the next full read. It starts
            // after the usual wait before a verify, so a provider that
            // answers `STAT` wrongly cannot make the two stages take
            // turns without a pause, one full read each time.
            let wait = self.cfg.verify_delay_secs.max(1);
            return self.back_to_verify(lease, now, wait).await;
        }
        let mut rows = Vec::new();
        for (provider, tally) in &read {
            let held = failed.contains(&label(&provider.backbone));
            if light.is_some() && held && result_of(tally) == VerifyResult::Ok {
                // Under the light check the last row of a backbone is
                // what verify found there. A `STAT` pass of this job on a
                // backbone verify did not pass would hide that, and a
                // release that is tried again would count it. A failure
                // is recorded: it counts for nothing and cancels nothing.
                continue;
            }
            let row = self
                .record(lease, extent, provider, tally, VerifyKind::Stat)
                .await?;
            if row.result == VerifyResult::Ok && !failed.contains(&label(&row.backbone)) {
                rows.push(row);
            }
        }
        // The evidence: this job's `STAT` passes, then the full checks on
        // record of the backbones among them.
        let on_record = full.iter().filter(|b| {
            let name = label(&b.backbone);
            rows.iter().any(|r| r.backbone == name)
        });
        // Then the size passes verify recorded on those backbones, each
        // with the command its provider was asked with.
        let on_record = on_record.chain(verified.iter().filter(|s| {
            let name = label(&s.backbone);
            rows.iter().any(|r| r.backbone == name)
        }));
        let on_record = on_record.map(|b| Evidence {
            backbone: &b.backbone,
            provider: &b.provider_id,
            verified_at: b.verified_at,
            kind: b.kind,
            ok: b.articles_ok,
            total: b.articles_total,
            plan_rev: b.plan_rev,
            size_command: match b.kind {
                VerifyKind::Size => self.cfg.verify.size_command(&b.provider_id),
                _ => None,
            },
        });
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
                size_command: None,
            })
            .chain(on_record)
            .collect();
        let evidence =
            serde_json::to_string(&evidence).map_err(|_| Stop::fail(FailClass::Internal))?;
        let at = self.clock.now();
        let begun = match light {
            None => {
                self.catalog
                    .begin_release(lease, required, &labels, &evidence, at)
                    .await?
            }
            Some(_) => {
                self.catalog
                    .begin_release_light(lease, required, &labels, &evidence, at, need_full)
                    .await?
            }
        };
        match begun {
            Guard::Applied(()) => self.finish_release(lease, extent).await,
            // The lease is gone or a newer result cancelled a pass. If the
            // lease still holds, the job comes back and reads again.
            Guard::Lost => Err(Stop::fail(FailClass::Internal)),
        }
    }

    /// Sends a release that cannot go through back to the start of verify,
    /// due in `wait_secs` and without an attempt spent.
    async fn back_to_verify(&self, lease: &Lease, now: UnixMs, wait_secs: u32) -> Staged<()> {
        // The move resets the resume point itself ([`Catalog::advance`]).
        let due = now.plus_secs(wait_secs);
        self.advance(lease, OutboxStage::Verify, due).await?;
        self.notify_at(lease, OutboxStage::Verify, due).await;
        Ok(())
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
