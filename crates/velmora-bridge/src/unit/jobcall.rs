//! The job calls of a unit (`docs/units.md`, "Jobs"; package W2-jobs).
//!
//! Post, verify, release, GC, eviction and the dispatcher run in the
//! Worker, as today: they hold the NNTP sessions, the blob stores and the
//! keys (rules 3 and 4). What they ask of the catalogue, a unit answers:
//! each [`JobCall`] is one method of [`Catalog`], with its arguments as
//! they cross `fetch`, run by the unit's own [`SqlCatalog`] in one
//! transaction (rules 1 and 2). The Worker's side is
//! [`crate::tenant_catalog::TenantCatalog`], a [`Catalog`] whose job
//! methods are these calls, so the job code runs unchanged against a unit.
//!
//! A job call is a `job` call: it carries the job's numbers and must match
//! the unit's (rule 5), and it is `authenticated` (the consumer's own). It
//! is refused while the unit is closed, and for a tenant that is being
//! shredded. Provider permits and provider health are not a unit's: they
//! stay in the shared database (ADR §7.2).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ports::{Catalog, Lease, Sql};
use crate::sql::SqlCatalog;
use crate::types::*;

/// One catalogue method of the job path, with its arguments.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "m", deny_unknown_fields)]
pub enum JobCall {
    advance {
        l: Lease,
        to: OutboxStage,
        next_at: UnixMs,
        now: UnixMs,
    },
    articles {
        extent: ExtentId,
    },
    backbone_status {
        extent: ExtentId,
    },
    begin_evict {
        x: EvictCandidate,
    },
    begin_release {
        l: Lease,
        required: u32,
        counting: Vec<String>,
        evidence_json: String,
        now: UnixMs,
    },
    begin_release_light {
        l: Lease,
        required: u32,
        counting: Vec<String>,
        evidence_json: String,
        now: UnixMs,
        need_full: bool,
    },
    body_checks {
        extent: ExtentId,
    },
    bury_exhausted {
        max_attempts: u32,
        now: UnixMs,
    },
    claim {
        extent: ExtentId,
        generation: GenerationId,
        stage: OutboxStage,
        owner: String,
        now: UnixMs,
    },
    defer {
        l: Lease,
        next_at: UnixMs,
        now: UnixMs,
    },
    defer_at {
        l: Lease,
        cursor: u32,
        next_at: UnixMs,
        now: UnixMs,
    },
    drop_intents {
        write: WriteId,
    },
    due {
        now: UnixMs,
        resend: Resend,
        limit: u32,
    },
    due_intents {
        open_before: UnixMs,
        limit: u32,
    },
    escalate_verify {
        e: VerifyEscalation,
        plan_rev: u32,
    },
    evict_candidates {
        limit: u32,
    },
    evictable_bytes {},
    fail {
        l: Lease,
        class: FailClass,
        next_at: UnixMs,
        now: UnixMs,
    },
    fence_intents {
        write: WriteId,
        open_before: UnixMs,
        stamp: Option<u64>,
    },
    finish_evict {
        x: EvictCandidate,
    },
    finish_release {
        l: Lease,
        now: UnixMs,
    },
    gc_begin {
        row: GcRow,
        now: UnixMs,
    },
    gc_done {
        id: i64,
        now: UnixMs,
    },
    gc_due {
        now: UnixMs,
        limit: u32,
        disposable_only: bool,
    },
    hold_intent_fence {
        write: WriteId,
        slices: usize,
        stamp: Option<u64>,
    },
    hot_check_due {
        now: UnixMs,
        every_ms: i64,
    },
    hot_checked {
        now: UnixMs,
    },
    hot_drain_claim {
        left: u64,
    },
    hot_drain_set {
        left: u64,
    },
    job_extent {
        extent: ExtentId,
        generation: GenerationId,
    },
    keep_intents {
        write: WriteId,
    },
    mark_posted_many {
        l: Lease,
        posted: Vec<(u32, String)>,
        now: UnixMs,
    },
    mark_reposted_many {
        l: Lease,
        idxs: Vec<u32>,
        now: UnixMs,
    },
    mark_sent {
        extents: Vec<ExtentId>,
        now: UnixMs,
    },
    /// The mark of a send that failed, taken back (#172).
    unmark_sent {
        jobs: Vec<Job>,
        mark: UnixMs,
    },
    pack_plans {
        limit: u32,
    },
    plan_articles {
        l: Lease,
        rows: Vec<ArticleRow>,
    },
    plan_packed {
        l: Lease,
        cipher_size: u64,
        plan: Vec<u8>,
        parity: Option<Vec<u8>>,
    },
    record_cache_fill {
        extent: ExtentId,
        now: UnixMs,
    },
    record_dispatch {
        now: UnixMs,
    },
    record_verification {
        l: Lease,
        v: VerificationRow,
    },
    redrive_underverified {
        backbones: Vec<String>,
        required: u32,
        limit: u32,
        now: UnixMs,
    },
    renew {
        l: Lease,
        now: UnixMs,
    },
    restore_pending {},
    revive_referenced {
        limit: u32,
        now: UnixMs,
    },
    set_cursor {
        l: Lease,
        cursor: u32,
        now: UnixMs,
    },
    stamp {
        catalogue: String,
    },
    stamp_advance {
        from: Option<u64>,
        catalogue: String,
    },
    stamp_rolled_back {
        seen: Option<u64>,
        now: UnixMs,
        catalogue: String,
    },
    stored_plan {
        extent: ExtentId,
    },
    usage_recount_start {
        now: UnixMs,
        adopt: bool,
        restart: bool,
        only_on: bool,
    },
    usage_recount_step {
        chunk: u32,
        now: UnixMs,
    },
    usage_recounts {},
    verify_escalations {
        at: UnixMs,
    },
    verify_raised {
        extent: ExtentId,
        backbone: String,
        plan_rev: u32,
    },
    mark_posted {
        l: Lease,
        idx: u32,
        provider: String,
        now: UnixMs,
    },
}

impl JobCall {
    /// The rollback-stamp id a stamp call names, if it is one: it must be
    /// the unit's own (ADR §8.5).
    pub fn stamp_id(&self) -> Option<&str> {
        match self {
            JobCall::stamp { catalogue }
            | JobCall::stamp_advance { catalogue, .. }
            | JobCall::stamp_rolled_back { catalogue, .. } => Some(catalogue),
            _ => None,
        }
    }

    /// The method's name.
    pub fn name(&self) -> &'static str {
        match self {
            JobCall::advance { .. } => "advance",
            JobCall::articles { .. } => "articles",
            JobCall::backbone_status { .. } => "backbone_status",
            JobCall::begin_evict { .. } => "begin_evict",
            JobCall::begin_release { .. } => "begin_release",
            JobCall::begin_release_light { .. } => "begin_release_light",
            JobCall::body_checks { .. } => "body_checks",
            JobCall::bury_exhausted { .. } => "bury_exhausted",
            JobCall::claim { .. } => "claim",
            JobCall::defer { .. } => "defer",
            JobCall::defer_at { .. } => "defer_at",
            JobCall::drop_intents { .. } => "drop_intents",
            JobCall::due { .. } => "due",
            JobCall::due_intents { .. } => "due_intents",
            JobCall::escalate_verify { .. } => "escalate_verify",
            JobCall::evict_candidates { .. } => "evict_candidates",
            JobCall::evictable_bytes { .. } => "evictable_bytes",
            JobCall::fail { .. } => "fail",
            JobCall::fence_intents { .. } => "fence_intents",
            JobCall::finish_evict { .. } => "finish_evict",
            JobCall::finish_release { .. } => "finish_release",
            JobCall::gc_begin { .. } => "gc_begin",
            JobCall::gc_done { .. } => "gc_done",
            JobCall::gc_due { .. } => "gc_due",
            JobCall::hold_intent_fence { .. } => "hold_intent_fence",
            JobCall::hot_check_due { .. } => "hot_check_due",
            JobCall::hot_checked { .. } => "hot_checked",
            JobCall::hot_drain_claim { .. } => "hot_drain_claim",
            JobCall::hot_drain_set { .. } => "hot_drain_set",
            JobCall::job_extent { .. } => "job_extent",
            JobCall::keep_intents { .. } => "keep_intents",
            JobCall::mark_posted_many { .. } => "mark_posted_many",
            JobCall::mark_reposted_many { .. } => "mark_reposted_many",
            JobCall::mark_sent { .. } => "mark_sent",
            JobCall::unmark_sent { .. } => "unmark_sent",
            JobCall::pack_plans { .. } => "pack_plans",
            JobCall::plan_articles { .. } => "plan_articles",
            JobCall::plan_packed { .. } => "plan_packed",
            JobCall::record_cache_fill { .. } => "record_cache_fill",
            JobCall::record_dispatch { .. } => "record_dispatch",
            JobCall::record_verification { .. } => "record_verification",
            JobCall::redrive_underverified { .. } => "redrive_underverified",
            JobCall::renew { .. } => "renew",
            JobCall::restore_pending { .. } => "restore_pending",
            JobCall::revive_referenced { .. } => "revive_referenced",
            JobCall::set_cursor { .. } => "set_cursor",
            JobCall::stamp { .. } => "stamp",
            JobCall::stamp_advance { .. } => "stamp_advance",
            JobCall::stamp_rolled_back { .. } => "stamp_rolled_back",
            JobCall::stored_plan { .. } => "stored_plan",
            JobCall::usage_recount_start { .. } => "usage_recount_start",
            JobCall::usage_recount_step { .. } => "usage_recount_step",
            JobCall::usage_recounts { .. } => "usage_recounts",
            JobCall::verify_escalations { .. } => "verify_escalations",
            JobCall::verify_raised { .. } => "verify_raised",
            JobCall::mark_posted { .. } => "mark_posted",
        }
    }

    /// Runs the method on the unit's catalogue. Its answer is the
    /// method's return value as JSON.
    pub async fn run<S: Sql>(self, cat: &SqlCatalog<S>) -> Result<Value> {
        match self {
            JobCall::advance {
                l,
                to,
                next_at,
                now,
            } => answer(Catalog::advance(cat, &l, to, next_at, now).await?),
            JobCall::articles { extent } => answer(Catalog::articles(cat, &extent).await?),
            JobCall::backbone_status { extent } => {
                answer(Catalog::backbone_status(cat, &extent).await?)
            }
            JobCall::begin_evict { x } => answer(Catalog::begin_evict(cat, &x).await?),
            JobCall::begin_release {
                l,
                required,
                counting,
                evidence_json,
                now,
            } => answer(
                Catalog::begin_release(cat, &l, required, &counting, &evidence_json, now).await?,
            ),
            JobCall::begin_release_light {
                l,
                required,
                counting,
                evidence_json,
                now,
                need_full,
            } => answer(
                Catalog::begin_release_light(
                    cat,
                    &l,
                    required,
                    &counting,
                    &evidence_json,
                    now,
                    need_full,
                )
                .await?,
            ),
            JobCall::body_checks { extent } => answer(Catalog::body_checks(cat, &extent).await?),
            JobCall::bury_exhausted { max_attempts, now } => {
                answer(Catalog::bury_exhausted(cat, max_attempts, now).await?)
            }
            JobCall::claim {
                extent,
                generation,
                stage,
                owner,
                now,
            } => answer(Catalog::claim(cat, &extent, &generation, stage, &owner, now).await?),
            JobCall::defer { l, next_at, now } => {
                answer(Catalog::defer(cat, &l, next_at, now).await?)
            }
            JobCall::defer_at {
                l,
                cursor,
                next_at,
                now,
            } => answer(Catalog::defer_at(cat, &l, cursor, next_at, now).await?),
            JobCall::drop_intents { write } => answer(Catalog::drop_intents(cat, &write).await?),
            JobCall::due { now, resend, limit } => {
                answer(Catalog::due(cat, now, resend, limit).await?)
            }
            JobCall::due_intents { open_before, limit } => {
                answer(Catalog::due_intents(cat, open_before, limit).await?)
            }
            JobCall::escalate_verify { e, plan_rev } => {
                answer(Catalog::escalate_verify(cat, &e, plan_rev).await?)
            }
            JobCall::evict_candidates { limit } => {
                answer(Catalog::evict_candidates(cat, limit).await?)
            }
            JobCall::evictable_bytes {} => answer(Catalog::evictable_bytes(cat).await?),
            JobCall::fail {
                l,
                class,
                next_at,
                now,
            } => answer(Catalog::fail(cat, &l, class, next_at, now).await?),
            JobCall::fence_intents {
                write,
                open_before,
                stamp,
            } => answer(Catalog::fence_intents(cat, &write, open_before, stamp).await?),
            JobCall::finish_evict { x } => answer(Catalog::finish_evict(cat, &x).await?),
            JobCall::finish_release { l, now } => {
                answer(Catalog::finish_release(cat, &l, now).await?)
            }
            JobCall::gc_begin { row, now } => answer(Catalog::gc_begin(cat, &row, now).await?),
            JobCall::gc_done { id, now } => answer(Catalog::gc_done(cat, id, now).await?),
            JobCall::gc_due {
                now,
                limit,
                disposable_only,
            } => answer(Catalog::gc_due(cat, now, limit, disposable_only).await?),
            JobCall::hold_intent_fence {
                write,
                slices,
                stamp,
            } => answer(Catalog::hold_intent_fence(cat, &write, slices, stamp).await?),
            JobCall::hot_check_due { now, every_ms } => {
                answer(Catalog::hot_check_due(cat, now, every_ms).await?)
            }
            JobCall::hot_checked { now } => answer(Catalog::hot_checked(cat, now).await?),
            JobCall::hot_drain_claim { left } => answer(Catalog::hot_drain_claim(cat, left).await?),
            JobCall::hot_drain_set { left } => answer(Catalog::hot_drain_set(cat, left).await?),
            JobCall::job_extent { extent, generation } => {
                answer(Catalog::job_extent(cat, &extent, &generation).await?)
            }
            JobCall::keep_intents { write } => answer(Catalog::keep_intents(cat, &write).await?),
            JobCall::mark_posted_many { l, posted, now } => answer(
                Catalog::mark_posted_many(
                    cat,
                    &l,
                    &posted
                        .iter()
                        .map(|(i, s)| (*i, s.as_str()))
                        .collect::<Vec<_>>(),
                    now,
                )
                .await?,
            ),
            JobCall::mark_reposted_many { l, idxs, now } => {
                answer(Catalog::mark_reposted_many(cat, &l, &idxs, now).await?)
            }
            JobCall::mark_sent { extents, now } => {
                answer(Catalog::mark_sent(cat, &extents, now).await?)
            }
            JobCall::unmark_sent { jobs, mark } => {
                answer(Catalog::unmark_sent(cat, &jobs, mark).await?)
            }
            JobCall::pack_plans { limit } => answer(Catalog::pack_plans(cat, limit).await?),
            JobCall::plan_articles { l, rows } => {
                answer(Catalog::plan_articles(cat, &l, &rows).await?)
            }
            JobCall::plan_packed {
                l,
                cipher_size,
                plan,
                parity,
            } => {
                answer(Catalog::plan_packed(cat, &l, cipher_size, &plan, parity.as_deref()).await?)
            }
            JobCall::record_cache_fill { extent, now } => {
                answer(Catalog::record_cache_fill(cat, &extent, now).await?)
            }
            JobCall::record_dispatch { now } => answer(Catalog::record_dispatch(cat, now).await?),
            JobCall::record_verification { l, v } => {
                answer(Catalog::record_verification(cat, &l, &v).await?)
            }
            JobCall::redrive_underverified {
                backbones,
                required,
                limit,
                now,
            } => {
                answer(Catalog::redrive_underverified(cat, &backbones, required, limit, now).await?)
            }
            JobCall::renew { l, now } => answer(Catalog::renew(cat, &l, now).await?),
            JobCall::restore_pending {} => answer(Catalog::restore_pending(cat).await?),
            JobCall::revive_referenced { limit, now } => {
                answer(Catalog::revive_referenced(cat, limit, now).await?)
            }
            JobCall::set_cursor { l, cursor, now } => {
                answer(Catalog::set_cursor(cat, &l, cursor, now).await?)
            }
            JobCall::stamp { catalogue } => answer(Catalog::stamp(cat, &catalogue).await?),
            JobCall::stamp_advance { from, catalogue } => {
                answer(Catalog::stamp_advance(cat, from, &catalogue).await?)
            }
            JobCall::stamp_rolled_back {
                seen,
                now,
                catalogue,
            } => answer(Catalog::stamp_rolled_back(cat, seen, now, &catalogue).await?),
            JobCall::stored_plan { extent } => answer(Catalog::stored_plan(cat, &extent).await?),
            JobCall::usage_recount_start {
                now,
                adopt,
                restart,
                only_on,
            } => answer(Catalog::usage_recount_start(cat, now, adopt, restart, only_on).await?),
            JobCall::usage_recount_step { chunk, now } => {
                answer(Catalog::usage_recount_step(cat, chunk, now).await?)
            }
            JobCall::usage_recounts {} => answer(Catalog::usage_recounts(cat).await?),
            JobCall::verify_escalations { at } => {
                answer(Catalog::verify_escalations(cat, at).await?)
            }
            JobCall::verify_raised {
                extent,
                backbone,
                plan_rev,
            } => answer(Catalog::verify_raised(cat, &extent, &backbone, plan_rev).await?),
            JobCall::mark_posted {
                l,
                idx,
                provider,
                now,
            } => answer(Catalog::mark_posted(cat, &l, idx, &provider, now).await?),
        }
    }
}

/// A unit's rollback-stamp id: `<tenant>.<unit>` (ADR §8.5).
pub fn stamp_id(name: &super::name::UnitName) -> String {
    format!("{}.{}", name.tenant, name.unit)
}

fn answer<T: Serialize>(v: T) -> Result<Value> {
    serde_json::to_value(v).map_err(|_| BridgeError::Invalid("unit: job answer"))
}
