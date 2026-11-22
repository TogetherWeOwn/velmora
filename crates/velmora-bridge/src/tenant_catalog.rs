//! A tenant's catalogue as the job path sees it (package W2-jobs;
//! `docs/units.md`, "Jobs").
//!
//! [`TenantCatalog`] is a [`Catalog`] for the jobs of a managed tenant:
//! every catalogue method of the job path is a [`JobCall`] to the tenant's
//! unit, through a [`UnitPort`] (the unit's `fetch` in the Worker, the unit
//! itself in tests); provider permits and provider health go to the shared
//! database, which keeps them for every tenant (ADR §7.2). The job code
//! (`jobs.rs`, `post.rs`, `verify.rs`) runs unchanged over it.
//!
//! The S3 request path does not use it: every other method answers
//! [`NOT_ON_UNIT`]. A job call that the unit does not take comes back as a
//! typed error (see the `UNIT_*` constants), so the consumer can read the
//! unit's state and the chain heads, then run the job again or drop it
//! (ADR §2.4 rule 5).

use serde::de::DeserializeOwned;

use crate::plan::{PackReport, StoredPlan};
use crate::ports::*;
use crate::recovery::Recorded;
use crate::replay::{ReplayExtent, ReplayMark, ReplayProbe, ReplayPublish, RestoreProgress};
use crate::types::*;
use crate::unit::identity::{self, CallKind, Seqs};
use crate::unit::jobcall::JobCall;
use crate::unit::{Refused, UnitAnswer, UnitCall, UnitName, UnitOp};

/// A method the job path does not use: not served through a unit.
pub const NOT_ON_UNIT: &str = "not on the unit job path";
/// The unit holds a newer record than the job: `sync` first.
pub const UNIT_SYNC_NEEDED: &str = "unit: sync needed";
/// The job's numbers are below the unit's, or missing: run it again with
/// fresh numbers, or drop it.
pub const UNIT_STALE_JOB: &str = "unit: stale job";
/// The unit's lease has run out: `renew` first (rule 12).
pub const UNIT_RENEW_NEEDED: &str = "unit: renew needed";
/// The unit is closed (restoring or provisioning).
pub const UNIT_CLOSED: &str = "unit: closed";
/// The unit has no certificate.
pub const UNIT_UNBORN: &str = "unit: unborn";
/// The tenant's state does not allow the call (a shred, for a job).
pub const UNIT_ACCOUNT_PROBLEM: &str = "unit: account problem";
/// The unit refused the call for another reason; the Worker alarms.
pub const UNIT_REFUSED: &str = "unit: refused";

/// Why the unit refused a job call: what the consumer needs to decide the
/// delivery (`crate::unit_consumer`, ADR §2.4 rule 5 as AM-50 states it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitRefusal {
    /// `Stale{seqs}`: the job's numbers are below the unit's, which come
    /// with the answer.
    Stale(Seqs),
    /// `Refused{stale_job}`: a job call with no numbers, or (before the
    /// unit answers `Stale{seqs}` to job calls) with lower ones.
    StaleJob,
    /// `SyncNeeded`: the job knows a newer record than the unit, whose
    /// numbers come with the answer.
    SyncNeeded(Seqs),
    /// `renew_needed`: the unit's lease has run out; its numbers.
    RenewNeeded(Seqs),
    /// `Closed` (restoring or provisioning).
    Closed,
    /// `Unborn`: the unit has no certificate.
    Unborn,
    /// `Refused{account_problem}`: the tenant's state refuses jobs.
    AccountProblem,
    /// Any other refusal.
    Other,
}

impl UnitRefusal {
    /// The text of the error the job code sees (one of the `UNIT_*`).
    pub fn text(self) -> &'static str {
        match self {
            UnitRefusal::Stale(_) | UnitRefusal::StaleJob => UNIT_STALE_JOB,
            UnitRefusal::SyncNeeded(_) => UNIT_SYNC_NEEDED,
            UnitRefusal::RenewNeeded(_) => UNIT_RENEW_NEEDED,
            UnitRefusal::Closed => UNIT_CLOSED,
            UnitRefusal::Unborn => UNIT_UNBORN,
            UnitRefusal::AccountProblem => UNIT_ACCOUNT_PROBLEM,
            UnitRefusal::Other => UNIT_REFUSED,
        }
    }
}

/// The highest numbers a unit has answered in a job's run, shared between
/// the job's catalogue and its queue sink: a follow-up job carries them
/// (AM-50, L6-7d), never lower ones than the job came with.
#[derive(Clone, Debug)]
pub struct LatestSeqs(std::rc::Rc<std::cell::Cell<Seqs>>);

impl LatestSeqs {
    pub fn new(seqs: Seqs) -> LatestSeqs {
        LatestSeqs(std::rc::Rc::new(std::cell::Cell::new(seqs)))
    }

    pub fn get(&self) -> Seqs {
        self.0.get()
    }

    /// Each number to the higher of the two.
    pub fn raise(&self, seqs: Seqs) {
        let now = self.0.get();
        self.0.set(Seqs {
            state_seq: now.state_seq.max(seqs.state_seq),
            keys_seq: now.keys_seq.max(seqs.keys_seq),
        });
    }
}

/// The way to a unit: one call, one answer.
#[allow(async_fn_in_trait)]
pub trait UnitPort {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer>;
}

/// The catalogue of one managed tenant's unit, for its jobs.
pub struct TenantCatalog<P: UnitPort, S: Catalog> {
    port: P,
    shared: S,
    name: UnitName,
    /// The numbers the job calls carry: the message's, or the unit's for a
    /// run again ([`TenantCatalog::run_again_with`]).
    seqs: std::cell::Cell<Seqs>,
    /// The first refusal the unit gave in this run.
    refusal: std::cell::Cell<Option<UnitRefusal>>,
    latest: LatestSeqs,
    /// The outbox leases this run claimed: given back before the job runs
    /// once more ([`TenantCatalog::give_back`]).
    claimed: std::cell::RefCell<Vec<Lease>>,
}

impl<P: UnitPort, S: Catalog> TenantCatalog<P, S> {
    /// `seqs`: the job's numbers (its message names them, ADR §2.4 rule 9).
    pub fn new(port: P, shared: S, name: UnitName, seqs: Seqs) -> Self {
        Self::with_latest(port, shared, name, seqs, LatestSeqs::new(seqs))
    }

    /// As [`TenantCatalog::new`], raising `latest` with the numbers of
    /// every answer (the job's queue sink reads it).
    pub fn with_latest(port: P, shared: S, name: UnitName, seqs: Seqs, latest: LatestSeqs) -> Self {
        latest.raise(seqs);
        TenantCatalog {
            port,
            shared,
            name,
            seqs: std::cell::Cell::new(seqs),
            refusal: std::cell::Cell::new(None),
            latest,
            claimed: std::cell::RefCell::default(),
        }
    }

    /// The unit the job calls go to.
    pub fn name(&self) -> &UnitName {
        &self.name
    }

    /// The numbers the job calls carry now.
    pub fn seqs(&self) -> Seqs {
        self.seqs.get()
    }

    /// The highest numbers the unit answered so far.
    pub fn latest(&self) -> &LatestSeqs {
        &self.latest
    }

    /// Before the job runs once more (AM-50): its calls carry `seqs`, and
    /// the refusal of the last run is forgotten.
    pub fn run_again_with(&self, seqs: Seqs) {
        self.seqs.set(seqs);
        self.latest.raise(seqs);
        self.refusal.set(None);
    }

    /// Gives back, with the current numbers, every outbox lease the last
    /// run claimed (`defer` to `now`, fenced by the lease's token: a lease
    /// that run already freed or advanced is left as it is). A run that
    /// the unit refused after its claim kept the row leased, and its
    /// `fail` went out with the refused numbers too; without this the run
    /// once more would find the row leased and acknowledge having done
    /// nothing. `Err`: a lease is still held; the refusal of that call is
    /// kept.
    pub async fn give_back(&self, now: UnixMs) -> Result<()> {
        let claimed = std::mem::take(&mut *self.claimed.borrow_mut());
        for (at, lease) in claimed.iter().enumerate() {
            if let Err(e) = Catalog::defer(self, lease, now, now).await {
                self.claimed
                    .borrow_mut()
                    .extend(claimed[at..].iter().cloned());
                return Err(e);
            }
        }
        Ok(())
    }

    /// The first refusal the unit gave since this catalogue was made: the
    /// job code turns every error into a retry, so the consumer reads it
    /// here after `run_job` and re-reads the heads, then runs the job
    /// again with fresh numbers or drops it (ADR §2.4 rule 5).
    pub fn refusal(&self) -> Option<UnitRefusal> {
        self.refusal.get()
    }

    fn refused(&self, why: UnitRefusal) -> BridgeError {
        if self.refusal.get().is_none() {
            self.refusal.set(Some(why));
        }
        BridgeError::Invalid(why.text())
    }

    pub fn shared(&self) -> &S {
        &self.shared
    }

    async fn unit<T: DeserializeOwned>(&self, call: JobCall) -> Result<T> {
        let c = UnitCall {
            name: self.name.clone(),
            kind: CallKind::Job,
            seqs: Some(self.seqs.get()),
            authenticated: true,
            // A job reaches its unit through its message, not through a
            // record that lists it: an unborn unit answers `Unborn`, and
            // the consumer reads the tenant's head to tell a lost
            // catalogue from a unit that was removed (AM-50, rule 7).
            listed: false,
            op: UnitOp::Job { call },
        };
        let answer = self.port.call(&c).await?;
        if let Some(seqs) = answer_seqs(&answer) {
            self.latest.raise(seqs);
        }
        match answer {
            UnitAnswer::Ok { body, .. } => serde_json::from_value(body)
                .map_err(|_| BridgeError::Sql("unit: job answer does not decode".into())),
            UnitAnswer::SyncNeeded { seqs } => Err(self.refused(UnitRefusal::SyncNeeded(seqs))),
            UnitAnswer::Stale { seqs } => Err(self.refused(UnitRefusal::Stale(seqs))),
            UnitAnswer::Refused {
                reason: Refused::Identity(identity::Refusal::StaleJob),
                ..
            } => Err(self.refused(UnitRefusal::StaleJob)),
            UnitAnswer::Refused {
                reason: Refused::AccountProblem,
                ..
            } => Err(self.refused(UnitRefusal::AccountProblem)),
            UnitAnswer::Closed { .. } => Err(self.refused(UnitRefusal::Closed)),
            UnitAnswer::RenewNeeded { seqs, .. } => {
                Err(self.refused(UnitRefusal::RenewNeeded(seqs)))
            }
            UnitAnswer::Unborn { .. } => Err(self.refused(UnitRefusal::Unborn)),
            UnitAnswer::Failed { class } => Err(match class.as_str() {
                "guard" => BridgeError::GuardFailed,
                "catalogue_id" => crate::stamp::ERR_CATALOGUE_ID,
                "invalid" => BridgeError::Invalid("unit: invalid"),
                _ => BridgeError::Sql(format!("unit: {class}")),
            }),
            UnitAnswer::Refused { .. }
            | UnitAnswer::KeysBehind { .. }
            | UnitAnswer::UndoBookmark { .. } => Err(self.refused(UnitRefusal::Other)),
        }
    }
}

/// The unit's own numbers in an answer that carries them. `SyncNeeded`
/// carries numbers below the job's: raising with them changes nothing.
fn answer_seqs(answer: &UnitAnswer) -> Option<Seqs> {
    match answer {
        UnitAnswer::Ok { seqs, .. }
        | UnitAnswer::SyncNeeded { seqs }
        | UnitAnswer::Stale { seqs }
        | UnitAnswer::RenewNeeded { seqs, .. }
        | UnitAnswer::KeysBehind { seqs }
        | UnitAnswer::UndoBookmark { seqs, .. }
        | UnitAnswer::Closed { seqs, .. } => Some(*seqs),
        UnitAnswer::Refused { .. } | UnitAnswer::Unborn { .. } | UnitAnswer::Failed { .. } => None,
    }
}

// The methods off the job path keep the trait's argument names.
#[allow(unused_variables)]
impl<P: UnitPort, S: Catalog> Catalog for TenantCatalog<P, S> {
    async fn advance(
        &self,
        l: &Lease,
        to: OutboxStage,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool> {
        self.unit(JobCall::advance {
            l: l.clone(),
            to,
            next_at,
            now,
        })
        .await
    }
    async fn articles(&self, extent: &ExtentId) -> Result<Vec<ArticleRow>> {
        self.unit(JobCall::articles {
            extent: extent.clone(),
        })
        .await
    }
    async fn backbone_status(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>> {
        self.unit(JobCall::backbone_status {
            extent: extent.clone(),
        })
        .await
    }
    async fn begin_evict(&self, x: &EvictCandidate) -> Result<bool> {
        self.unit(JobCall::begin_evict { x: x.clone() }).await
    }
    async fn begin_release(
        &self,
        l: &Lease,
        required: u32,
        counting: &[String],
        evidence_json: &str,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        self.unit(JobCall::begin_release {
            l: l.clone(),
            required,
            counting: counting.to_vec(),
            evidence_json: evidence_json.to_string(),
            now,
        })
        .await
    }
    async fn begin_release_light(
        &self,
        l: &Lease,
        required: u32,
        counting: &[String],
        evidence_json: &str,
        now: UnixMs,
        need_full: bool,
    ) -> Result<Guard<()>> {
        self.unit(JobCall::begin_release_light {
            l: l.clone(),
            required,
            counting: counting.to_vec(),
            evidence_json: evidence_json.to_string(),
            now,
            need_full,
        })
        .await
    }
    async fn body_checks(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>> {
        self.unit(JobCall::body_checks {
            extent: extent.clone(),
        })
        .await
    }
    async fn bury_exhausted(&self, max_attempts: u32, now: UnixMs) -> Result<u64> {
        self.unit(JobCall::bury_exhausted { max_attempts, now })
            .await
    }
    async fn claim(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
        stage: OutboxStage,
        owner: &str,
        now: UnixMs,
    ) -> Result<Option<Lease>> {
        let lease: Option<Lease> = self
            .unit(JobCall::claim {
                extent: extent.clone(),
                generation: generation.clone(),
                stage,
                owner: owner.to_string(),
                now,
            })
            .await?;
        if let Some(lease) = &lease {
            self.claimed.borrow_mut().push(lease.clone());
        }
        Ok(lease)
    }
    async fn defer(&self, l: &Lease, next_at: UnixMs, now: UnixMs) -> Result<bool> {
        self.unit(JobCall::defer {
            l: l.clone(),
            next_at,
            now,
        })
        .await
    }
    async fn defer_at(&self, l: &Lease, cursor: u32, next_at: UnixMs, now: UnixMs) -> Result<bool> {
        self.unit(JobCall::defer_at {
            l: l.clone(),
            cursor,
            next_at,
            now,
        })
        .await
    }
    async fn drop_intents(&self, write: &WriteId) -> Result<()> {
        self.unit(JobCall::drop_intents {
            write: write.clone(),
        })
        .await
    }
    async fn due(&self, now: UnixMs, resend: Resend, limit: u32) -> Result<Vec<DueRow>> {
        self.unit(JobCall::due { now, resend, limit }).await
    }
    async fn due_intents(&self, open_before: UnixMs, limit: u32) -> Result<Vec<WriteId>> {
        self.unit(JobCall::due_intents { open_before, limit }).await
    }
    async fn escalate_verify(&self, e: &VerifyEscalation, plan_rev: u32) -> Result<()> {
        self.unit(JobCall::escalate_verify {
            e: e.clone(),
            plan_rev,
        })
        .await
    }
    async fn evict_candidates(&self, limit: u32) -> Result<Vec<EvictCandidate>> {
        self.unit(JobCall::evict_candidates { limit }).await
    }
    async fn evictable_bytes(&self) -> Result<u64> {
        self.unit(JobCall::evictable_bytes {}).await
    }
    async fn fail(
        &self,
        l: &Lease,
        class: FailClass,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool> {
        self.unit(JobCall::fail {
            l: l.clone(),
            class,
            next_at,
            now,
        })
        .await
    }
    async fn fence_intents(
        &self,
        write: &WriteId,
        open_before: UnixMs,
        stamp: Option<u64>,
    ) -> Result<IntentFence> {
        self.unit(JobCall::fence_intents {
            write: write.clone(),
            open_before,
            stamp,
        })
        .await
    }
    async fn finish_evict(&self, x: &EvictCandidate) -> Result<bool> {
        self.unit(JobCall::finish_evict { x: x.clone() }).await
    }
    async fn finish_release(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        self.unit(JobCall::finish_release { l: l.clone(), now })
            .await
    }
    async fn gc_begin(&self, row: &GcRow, now: UnixMs) -> Result<GcStep> {
        self.unit(JobCall::gc_begin {
            row: row.clone(),
            now,
        })
        .await
    }
    async fn gc_done(&self, id: i64, now: UnixMs) -> Result<()> {
        self.unit(JobCall::gc_done { id, now }).await
    }
    // The orphaned-part scan (`GC_ORPHANS`, main's #166) is not a unit job
    // call yet: on a unit it is never due and finds nothing, so a unit's
    // orphaned parts stay (stored, never lost) until the unit lanes add
    // the call. Nothing is claimed or deleted for a unit here.
    async fn gc_orphans_due(&self, _now: UnixMs) -> Result<bool> {
        Ok(false)
    }
    async fn gc_orphans(
        &self,
        _now: UnixMs,
        _cutoff: UnixMs,
        _scan: u32,
        _limit: u32,
    ) -> Result<Vec<GcRow>> {
        Ok(Vec::new())
    }
    async fn gc_orphan_claim(
        &self,
        rows: &[GcRow],
        _now: UnixMs,
        _cutoff: UnixMs,
    ) -> (Vec<bool>, Result<()>) {
        (
            vec![false; rows.len()],
            Err(BridgeError::NotImplemented(NOT_ON_UNIT)),
        )
    }
    async fn gc_orphan_done(&self, _id: i64, _now: UnixMs) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn gc_due(&self, now: UnixMs, limit: u32, disposable_only: bool) -> Result<Vec<GcRow>> {
        self.unit(JobCall::gc_due {
            now,
            limit,
            disposable_only,
        })
        .await
    }
    async fn hold_intent_fence(
        &self,
        write: &WriteId,
        slices: usize,
        stamp: Option<u64>,
    ) -> Result<bool> {
        self.unit(JobCall::hold_intent_fence {
            write: write.clone(),
            slices,
            stamp,
        })
        .await
    }
    async fn hot_check_due(&self, now: UnixMs, every_ms: i64) -> Result<bool> {
        self.unit(JobCall::hot_check_due { now, every_ms }).await
    }
    async fn hot_checked(&self, now: UnixMs) -> Result<()> {
        self.unit(JobCall::hot_checked { now }).await
    }
    async fn hot_drain_claim(&self, left: u64) -> Result<bool> {
        self.unit(JobCall::hot_drain_claim { left }).await
    }
    async fn hot_drain_set(&self, left: u64) -> Result<()> {
        self.unit(JobCall::hot_drain_set { left }).await
    }
    async fn job_extent(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
    ) -> Result<Option<JobExtent>> {
        self.unit(JobCall::job_extent {
            extent: extent.clone(),
            generation: generation.clone(),
        })
        .await
    }
    async fn keep_intents(&self, write: &WriteId) -> Result<()> {
        self.unit(JobCall::keep_intents {
            write: write.clone(),
        })
        .await
    }
    async fn mark_posted_many(
        &self,
        l: &Lease,
        posted: &[(u32, &str)],
        now: UnixMs,
    ) -> Result<bool> {
        self.unit(JobCall::mark_posted_many {
            l: l.clone(),
            posted: posted.iter().map(|(i, s)| (*i, s.to_string())).collect(),
            now,
        })
        .await
    }
    async fn mark_reposted_many(&self, l: &Lease, idxs: &[u32], now: UnixMs) -> Result<bool> {
        self.unit(JobCall::mark_reposted_many {
            l: l.clone(),
            idxs: idxs.to_vec(),
            now,
        })
        .await
    }
    async fn mark_sent(&self, extents: &[ExtentId], now: UnixMs) -> Result<u64> {
        self.unit(JobCall::mark_sent {
            extents: extents.to_vec(),
            now,
        })
        .await
    }
    async fn unmark_sent(&self, jobs: &[Job], mark: UnixMs) -> Result<u64> {
        self.unit(JobCall::unmark_sent {
            jobs: jobs.to_vec(),
            mark,
        })
        .await
    }
    async fn pack_plans(&self, limit: u32) -> Result<PackReport> {
        self.unit(JobCall::pack_plans { limit }).await
    }
    async fn plan_articles(
        &self,
        l: &Lease,
        rows: &[ArticleRow],
    ) -> Result<Option<Vec<ArticleRow>>> {
        self.unit(JobCall::plan_articles {
            l: l.clone(),
            rows: rows.to_vec(),
        })
        .await
    }
    async fn plan_packed(
        &self,
        l: &Lease,
        cipher_size: u64,
        plan: &[u8],
        parity: Option<&[u8]>,
    ) -> Result<Option<StoredPlan>> {
        self.unit(JobCall::plan_packed {
            l: l.clone(),
            cipher_size,
            plan: plan.to_vec(),
            parity: parity.map(<[u8]>::to_vec),
        })
        .await
    }
    async fn record_cache_fill(&self, extent: &ExtentId, now: UnixMs) -> Result<()> {
        self.unit(JobCall::record_cache_fill {
            extent: extent.clone(),
            now,
        })
        .await
    }
    async fn record_dispatch(&self, now: UnixMs) -> Result<()> {
        self.unit(JobCall::record_dispatch { now }).await
    }
    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool> {
        self.unit(JobCall::record_verification {
            l: l.clone(),
            v: v.clone(),
        })
        .await
    }
    async fn redrive_underverified(
        &self,
        backbones: &[String],
        required: u32,
        limit: u32,
        now: UnixMs,
    ) -> Result<u64> {
        self.unit(JobCall::redrive_underverified {
            backbones: backbones.to_vec(),
            required,
            limit,
            now,
        })
        .await
    }
    async fn renew(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        self.unit(JobCall::renew { l: l.clone(), now }).await
    }
    async fn restore_pending(&self) -> Result<bool> {
        self.unit(JobCall::restore_pending {}).await
    }
    async fn revive_referenced(&self, limit: u32, now: UnixMs) -> Result<u64> {
        self.unit(JobCall::revive_referenced { limit, now }).await
    }
    async fn set_cursor(&self, l: &Lease, cursor: u32, now: UnixMs) -> Result<bool> {
        self.unit(JobCall::set_cursor {
            l: l.clone(),
            cursor,
            now,
        })
        .await
    }
    async fn stamp(&self, catalogue: &str) -> Result<crate::stamp::StampRow> {
        self.unit(JobCall::stamp {
            catalogue: catalogue.to_string(),
        })
        .await
    }
    async fn stamp_advance(&self, from: Option<u64>, catalogue: &str) -> Result<bool> {
        self.unit(JobCall::stamp_advance {
            from,
            catalogue: catalogue.to_string(),
        })
        .await
    }
    async fn stamp_rolled_back(
        &self,
        seen: Option<u64>,
        now: UnixMs,
        catalogue: &str,
    ) -> Result<bool> {
        self.unit(JobCall::stamp_rolled_back {
            seen,
            now,
            catalogue: catalogue.to_string(),
        })
        .await
    }
    async fn stored_plan(&self, extent: &ExtentId) -> Result<StoredPlan> {
        self.unit(JobCall::stored_plan {
            extent: extent.clone(),
        })
        .await
    }
    async fn usage_recount_start(
        &self,
        now: UnixMs,
        adopt: bool,
        restart: bool,
        only_on: bool,
    ) -> Result<bool> {
        self.unit(JobCall::usage_recount_start {
            now,
            adopt,
            restart,
            only_on,
        })
        .await
    }
    async fn usage_recount_step(&self, chunk: u32, now: UnixMs) -> Result<RecountStep> {
        self.unit(JobCall::usage_recount_step { chunk, now }).await
    }
    async fn usage_recounts(&self) -> Result<(RecountState, Option<UsageRecount>)> {
        self.unit(JobCall::usage_recounts {}).await
    }
    async fn verify_escalations(&self, at: UnixMs) -> Result<Vec<VerifyEscalation>> {
        self.unit(JobCall::verify_escalations { at }).await
    }
    async fn verify_raised(
        &self,
        extent: &ExtentId,
        backbone: &str,
        plan_rev: u32,
    ) -> Result<bool> {
        self.unit(JobCall::verify_raised {
            extent: extent.clone(),
            backbone: backbone.to_string(),
            plan_rev,
        })
        .await
    }
    async fn mark_posted(&self, l: &Lease, idx: u32, provider: &str, now: UnixMs) -> Result<bool> {
        self.unit(JobCall::mark_posted {
            l: l.clone(),
            idx,
            provider: provider.to_string(),
            now,
        })
        .await
    }

    /// The lease is the unit's, the permits the shared database's.
    async fn renew_all(
        &self,
        l: &Lease,
        permits: &[Permit],
        now: UnixMs,
    ) -> Result<(bool, Vec<bool>)> {
        debug_assert!(permits.iter().all(|p| p.class != PermitClass::Drill));
        let held = async {
            let mut held = Vec::with_capacity(permits.len());
            for p in permits {
                held.push(self.shared.renew_permit(p, now).await?);
            }
            Ok::<_, BridgeError>(held)
        };
        let (lease, held) = futures_util::future::join(self.renew(l, now), held).await;
        Ok((lease?, held?))
    }

    /// A permit's gate is told at once, as the shared catalogue does.
    fn forget_permit(&self, p: &Permit) {
        self.shared.forget_permit(p)
    }

    async fn provider_status(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        self.shared.provider_status(now).await
    }

    async fn create_bucket(&self, b: &Bucket) -> Result<Guard<()>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn create_access_key(&self, k: &AccessKeyRow) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn put_grant(&self, akid: &str, bucket: &BucketId, perm: Perm) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn put_grant_if_present(
        &self,
        akid: &str,
        bucket: &BucketId,
        perm: Perm,
    ) -> Result<GrantPut> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn bucket_by_name(&self, name: &str) -> Result<Option<Bucket>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn bucket_in_use(&self, bucket: &BucketId) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn delete_bucket(&self, bucket: &Bucket) -> Result<Guard<()>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn buckets_for(&self, akid: &str) -> Result<Vec<Bucket>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn access_key(&self, akid: &str) -> Result<Option<AccessKeyRow>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn grant(&self, akid: &str, bucket: &BucketId) -> Result<Option<Perm>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn access_key_exists(&self, akid: &str) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn list_access_keys(&self, after: &str, limit: u32) -> Result<Vec<AccessKeySummary>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn delete_access_keys(&self, akids: &[String]) -> Result<u64> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn live_object(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn live_generation(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationRow>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn generation_by_id(
        &self,
        bucket: &BucketId,
        generation: &GenerationId,
    ) -> Result<Option<(Bucket, GenerationRow)>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn extents_in(
        &self,
        generation: &GenerationId,
        start: u64,
        end: u64,
    ) -> Result<Vec<ExtentRow>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn commit_generation(
        &self,
        c: &CommitGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn commit_sliced(
        &self,
        c: &CommitGeneration,
        write: &WriteId,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn open_intents(
        &self,
        write: &WriteId,
        extents: &[ExtentId],
        now: UnixMs,
    ) -> Result<Guard<()>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn intents_generation(
        &self,
        write: &WriteId,
        generation: &GenerationId,
        slices: usize,
    ) -> Result<Guard<()>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn abandon_intents(&self, write: &WriteId) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn intent_stats(&self, open_before: UnixMs) -> Result<IntentStats> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn newest_id(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationId>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn raise_floor(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        generation: bool,
    ) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn settle_floor(&self, bucket: &BucketId, key: &str, id: &GenerationId) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn unpublished_floor(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<GenerationId>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn copy_generation(
        &self,
        c: &CopyGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn delete_object_before(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        now: UnixMs,
    ) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn delete_object_if(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        condition: &Precondition,
        now: UnixMs,
    ) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn key_heads(&self, bucket: &BucketId, keys: &[&str]) -> Result<Vec<KeyHead>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn raise_floors(&self, bucket: &BucketId, ids: &[(&str, &GenerationId)]) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn settle_floors(&self, bucket: &BucketId, ids: &[(&str, &GenerationId)]) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn delete_objects_before(
        &self,
        bucket: &BucketId,
        deletes: &[(&str, &GenerationId, UnixMs)],
    ) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn list(&self, bucket: &BucketId, q: &ListQuery) -> Result<ListPage> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn list_heads(&self, bucket: &BucketId, q: &ListQuery) -> Result<Vec<ListEntry>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn object_status(&self, bucket: &BucketId, key: &str) -> Result<Option<ObjectStatus>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn set_safety_state(
        &self,
        extent: &ExtentId,
        from: SafetyState,
        to: SafetyState,
    ) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn create_upload(&self, u: &UploadRow) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn upload(
        &self,
        t: &UploadTarget<'_>,
    ) -> Result<Option<(UploadRow, Vec<UploadPartRow>)>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn upload_state(&self, t: &UploadTarget<'_>) -> Result<Option<UploadState>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn list_uploads(
        &self,
        bucket: &BucketId,
        q: &UploadListQuery,
    ) -> Result<Vec<OpenUpload>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn put_upload_part(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extent: &ExtentRow,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn put_upload_part_sliced(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extents: &[ExtentRow],
        write: &WriteId,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn complete_upload(
        &self,
        t: &UploadTarget<'_>,
        revision: u64,
        digest: &[u8; 32],
        c: &CompleteUpload,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn upload_extents(&self, t: &UploadTarget<'_>, limit: u32) -> Result<Vec<PartExtent>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn upload_extents_held(&self, upload: &UploadId, except: u16) -> Result<u64> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn abort_upload(&self, t: &UploadTarget<'_>, now: UnixMs) -> Result<Guard<()>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn outbox_stats(&self) -> Result<OutboxStats> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn guard_selftest(&self) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn replay_probe(&self, g: &GenerationRow) -> Result<ReplayProbe> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn replay_extents(
        &self,
        bucket: &Bucket,
        extents: &[ReplayExtent],
        now: UnixMs,
    ) -> Result<Vec<ExtentId>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn held_extents(&self, after: &str, limit: u32) -> Result<Vec<ExtentId>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn restore_begin(
        &self,
        since: UnixMs,
        now: UnixMs,
    ) -> Result<std::result::Result<UnixMs, UnixMs>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn restore_finish(
        &self,
        run: UnixMs,
        now: UnixMs,
        stamp: u64,
        seen: Option<u64>,
        catalogue: &str,
    ) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn restore_progress(&self, run: UnixMs) -> Result<Option<RestoreProgress>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn restore_advance(&self, run: UnixMs, next: &ReplayMark) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn replay_tombstone(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        now: UnixMs,
    ) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn replay_damaged(&self, limit: u32) -> Result<(u64, Vec<GenerationId>)> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn replay_publish(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
        now: UnixMs,
    ) -> Result<ReplayPublish> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn replay_twin(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
    ) -> Result<Option<GenerationId>> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn seed_permits(&self, providers: &[ProviderConfig]) -> Result<()> {
        self.shared.seed_permits(providers).await
    }
    async fn acquire_permit(
        &self,
        p: &ProviderConfig,
        class: PermitClass,
        holder: &str,
        now: UnixMs,
    ) -> Result<Option<Permit>> {
        self.shared.acquire_permit(p, class, holder, now).await
    }
    async fn renew_permit(&self, p: &Permit, now: UnixMs) -> Result<bool> {
        self.shared.renew_permit(p, now).await
    }
    async fn release_permit(&self, p: &Permit) -> Result<()> {
        self.shared.release_permit(p).await
    }
    async fn provider_load(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        self.shared.provider_load(now).await
    }
    async fn provider_failed(
        &self,
        provider: &str,
        fault: ProviderFault,
        now: UnixMs,
    ) -> Result<()> {
        self.shared.provider_failed(provider, fault, now).await
    }
    async fn provider_recovered(&self, provider: &str, now: UnixMs) -> Result<()> {
        self.shared.provider_recovered(provider, now).await
    }
    async fn providers_to_probe(
        &self,
        now: UnixMs,
        quiet_since: UnixMs,
        login_quiet_since: UnixMs,
    ) -> Result<Vec<String>> {
        self.shared
            .providers_to_probe(now, quiet_since, login_quiet_since)
            .await
    }
    async fn usage_counters(&self) -> Result<UsageCounters> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn usage_snapshot(&self, hours: u32) -> Result<UsageSnapshot> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn usage_buckets(&self, after: &str, limit: u32) -> Result<(bool, Vec<BucketUsage>)> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn usage_off(&self) -> Result<()> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn hot_stats(&self) -> Result<HotStats> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn touch_read(
        &self,
        extent: &ExtentId,
        now: UnixMs,
        min_gap_ms: i64,
        from_cache: bool,
    ) -> Result<UnixMs> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn hot_seq(&self, extent: &ExtentId) -> Result<u64> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
    async fn hot_forget(
        &self,
        extent: &ExtentId,
        seq: u64,
        safety: bool,
        cache: bool,
    ) -> Result<bool> {
        Err(BridgeError::NotImplemented(NOT_ON_UNIT))
    }
}
