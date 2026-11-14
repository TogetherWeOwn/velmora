//! `SqlCatalog<S: Sql>`: the one `Catalog` implementation (DESIGN §A.11).
//!
//! A trait impl cannot be split across files, so this module holds the
//! whole `impl Catalog` and forwards each method to a free function in the
//! submodule that owns it. Each submodule belongs to one lane:
//!
//! | module | methods |
//! |---|---|
//! | `auth` | buckets, access keys, grants |
//! | `objects` | live object, commit, copy, delete, list, admin status, safety CAS |
//! | `uploads` | multipart (guarded batches, receipt) |
//! | `outbox` | leases, article plan, verification, release, dispatcher reads |
//! | `gc` | due rows, begin, done |
//! | `permits` | provider connection slots, pool-shared limits |
//! | `health` | provider load, failures and cooldown |
//! | `recovery` | tombstone-ordered delete, upload extent rows |
//! | `replay` | recovery replay: extents, article plans, publication |
//!
//! An extent is in service while a live generation references it through
//! `generation_extents`, or a part of an open upload names it. A copy adds
//! such a reference, so every statement that retires a generation, queues
//! or runs garbage collection, or decides a release asks that question
//! (`live_ref!`, `part_ref!`) instead of looking at the one generation the
//! extent was first written for.

/// True while a live generation references the extent `$x` (an SQL
/// expression). With `except`, references from that generation do not
/// count: it is the one being retired.
macro_rules! live_ref {
    ($x:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM generation_extents lr \
               JOIN generations lg ON lg.id = lr.generation_id \
              WHERE lr.extent_id = ",
            $x,
            " AND lg.state = 'live')"
        )
    };
    ($x:literal, except $g:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM generation_extents lr \
               JOIN generations lg ON lg.id = lr.generation_id \
              WHERE lr.extent_id = ",
            $x,
            " AND lg.state = 'live' AND lg.id <> ",
            $g,
            ")"
        )
    };
}

/// True while a part of an open upload references the extent `$x`.
macro_rules! part_ref {
    ($x:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM upload_parts pr JOIN uploads pu ON pu.id = pr.upload_id \
              WHERE pr.extent_id = ",
            $x,
            " AND pu.state = 'open')"
        )
    };
}

mod auth;
mod gc;
mod health;
mod hot;
mod objects;
mod outbox;
mod permits;
mod recovery;
mod replay;
mod uploads;

pub use hot::INDEX_ONLY as HOT_INDEX_ONLY;

use crate::ports::{Catalog, Guard, Lease, Permit, PermitClass, Sql, SqlValue, UploadTarget};
use crate::replay::{ReplayExtent, ReplayProbe};
use crate::types::{
    AccessKeyRow, ArticleRow, BackboneStatus, BridgeError, Bucket, BucketId, CommitGeneration,
    CompleteUpload, CopyGeneration, DueRow, EvictCandidate, ExtentId, ExtentPlacement, ExtentRow,
    FailClass, GcRow, GcStep, GenerationId, GenerationRow, HotStats, JobExtent, ListPage,
    ListQuery, ObjectStatus, OutboxStage, OutboxStats, Perm, ProviderConfig, ProviderLoad, Result,
    SafetyState, UnixMs, UploadPartRow, UploadRow, VerificationRow,
};

/// `meta` key the guard self-test writes inside its failing batch.
const GUARD_SELFTEST_KEY: &str = "guard_selftest_marker";

/// The catalogue over any [`Sql`] backend.
pub struct SqlCatalog<S: Sql> {
    pub sql: S,
}

impl<S: Sql> SqlCatalog<S> {
    pub fn new(sql: S) -> Self {
        SqlCatalog { sql }
    }
}

impl<S: Sql> Catalog for SqlCatalog<S> {
    // admin + auth
    async fn create_bucket(&self, b: &Bucket) -> Result<Guard<()>> {
        auth::create_bucket(self, b).await
    }
    async fn create_access_key(&self, k: &AccessKeyRow) -> Result<()> {
        auth::create_access_key(self, k).await
    }
    async fn put_grant(&self, akid: &str, bucket: &BucketId, perm: Perm) -> Result<()> {
        auth::put_grant(self, akid, bucket, perm).await
    }
    async fn bucket_by_name(&self, name: &str) -> Result<Option<Bucket>> {
        auth::bucket_by_name(self, name).await
    }
    async fn buckets_for(&self, akid: &str) -> Result<Vec<Bucket>> {
        auth::buckets_for(self, akid).await
    }
    async fn access_key(&self, akid: &str) -> Result<Option<AccessKeyRow>> {
        auth::access_key(self, akid).await
    }
    async fn grant(&self, akid: &str, bucket: &BucketId) -> Result<Option<Perm>> {
        auth::grant(self, akid, bucket).await
    }

    // objects
    async fn live_object(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
        objects::live_object(self, bucket, key).await
    }
    async fn commit_generation(&self, c: &CommitGeneration) -> Result<Guard<()>> {
        objects::commit_generation(self, c).await
    }
    async fn newest_id(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationId>> {
        objects::newest_id(self, bucket, key).await
    }
    async fn copy_generation(&self, c: &CopyGeneration) -> Result<Guard<()>> {
        objects::copy_generation(self, c).await
    }
    async fn delete_object(&self, bucket: &BucketId, key: &str, now: UnixMs) -> Result<()> {
        objects::delete_object(self, bucket, key, now).await
    }
    async fn delete_object_before(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        now: UnixMs,
    ) -> Result<bool> {
        recovery::delete_object_before(self, bucket, key, before, now).await
    }
    async fn list(&self, bucket: &BucketId, q: &ListQuery) -> Result<ListPage> {
        objects::list(self, bucket, q).await
    }
    async fn object_status(&self, bucket: &BucketId, key: &str) -> Result<Option<ObjectStatus>> {
        objects::object_status(self, bucket, key).await
    }
    async fn set_safety_state(
        &self,
        extent: &ExtentId,
        from: SafetyState,
        to: SafetyState,
    ) -> Result<bool> {
        objects::set_safety_state(self, extent, from, to).await
    }

    // uploads
    async fn create_upload(&self, u: &UploadRow) -> Result<()> {
        uploads::create_upload(self, u).await
    }
    async fn upload(
        &self,
        t: &UploadTarget<'_>,
    ) -> Result<Option<(UploadRow, Vec<UploadPartRow>)>> {
        uploads::upload(self, t).await
    }
    async fn put_upload_part(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extent: &ExtentRow,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        uploads::put_upload_part(self, t, part, extent, now).await
    }
    async fn complete_upload(
        &self,
        t: &UploadTarget<'_>,
        revision: u64,
        digest: &[u8; 32],
        c: &CompleteUpload,
    ) -> Result<Guard<()>> {
        uploads::complete_upload(self, t, revision, digest, c).await
    }
    async fn upload_extents(&self, t: &UploadTarget<'_>) -> Result<Vec<ExtentRow>> {
        recovery::upload_extents(self, t).await
    }
    async fn abort_upload(&self, t: &UploadTarget<'_>, now: UnixMs) -> Result<Guard<()>> {
        uploads::abort_upload(self, t, now).await
    }

    // outbox
    async fn claim(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
        stage: OutboxStage,
        owner: &str,
        now: UnixMs,
    ) -> Result<Option<Lease>> {
        outbox::claim(self, extent, generation, stage, owner, now).await
    }
    async fn renew(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        outbox::renew(self, l, now).await
    }
    async fn advance(
        &self,
        l: &Lease,
        to: OutboxStage,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool> {
        outbox::advance(self, l, to, next_at, now).await
    }
    async fn fail(
        &self,
        l: &Lease,
        class: FailClass,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool> {
        outbox::fail(self, l, class, next_at, now).await
    }
    async fn set_cursor(&self, l: &Lease, cursor: u32, now: UnixMs) -> Result<bool> {
        outbox::set_cursor(self, l, cursor, now).await
    }
    async fn defer(&self, l: &Lease, next_at: UnixMs, now: UnixMs) -> Result<bool> {
        outbox::defer(self, l, next_at, now).await
    }
    async fn job_extent(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
    ) -> Result<Option<JobExtent>> {
        outbox::job_extent(self, extent, generation).await
    }
    async fn plan_articles(
        &self,
        l: &Lease,
        rows: &[ArticleRow],
    ) -> Result<Option<Vec<ArticleRow>>> {
        outbox::plan_articles(self, l, rows).await
    }
    async fn articles(&self, extent: &ExtentId) -> Result<Vec<ArticleRow>> {
        outbox::articles(self, extent).await
    }
    async fn mark_posted(&self, l: &Lease, idx: u32, provider: &str, now: UnixMs) -> Result<bool> {
        outbox::mark_posted(self, l, idx, provider, now).await
    }
    async fn mark_posted_many(
        &self,
        l: &Lease,
        posted: &[(u32, &str)],
        now: UnixMs,
    ) -> Result<bool> {
        outbox::mark_posted_many(self, l, posted, now).await
    }
    async fn renew_all(
        &self,
        l: &Lease,
        permits: &[Permit],
        now: UnixMs,
    ) -> Result<(bool, Vec<bool>)> {
        outbox::renew_all(self, l, permits, now).await
    }
    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool> {
        outbox::record_verification(self, l, v).await
    }
    async fn backbone_status(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>> {
        outbox::backbone_status(self, extent).await
    }
    async fn begin_release(
        &self,
        l: &Lease,
        required: u32,
        evidence_json: &str,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        outbox::begin_release(self, l, required, evidence_json, now).await
    }
    async fn finish_release(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        outbox::finish_release(self, l, now).await
    }
    async fn due(&self, now: UnixMs, limit: u32) -> Result<Vec<DueRow>> {
        outbox::due(self, now, limit).await
    }
    async fn bury_exhausted(&self, max_attempts: u32, now: UnixMs) -> Result<u64> {
        outbox::bury_exhausted(self, max_attempts, now).await
    }
    async fn record_dispatch(&self, now: UnixMs) -> Result<()> {
        outbox::record_dispatch(self, now).await
    }
    async fn outbox_stats(&self) -> Result<OutboxStats> {
        outbox::outbox_stats(self).await
    }

    /// Writes a marker, then fires the guard, in one batch. Rolled back
    /// means: the batch reported `GuardFailed` and the marker is absent.
    async fn guard_selftest(&self) -> Result<bool> {
        let key = || vec![SqlValue::Text(GUARD_SELFTEST_KEY.to_string())];
        let outcome = self
            .sql
            .batch(vec![
                ("INSERT OR REPLACE INTO meta(k, v) VALUES (?1, 1)", key()),
                ("INSERT INTO tx_guard(ok) SELECT 0", vec![]),
            ])
            .await;
        let guard_fired = match outcome {
            Err(BridgeError::GuardFailed) => true,
            Ok(_) => false,
            Err(e) => return Err(e),
        };
        let marker = self
            .sql
            .query("SELECT 1 FROM meta WHERE k = ?1", &key())
            .await?;
        if !marker.is_empty() {
            // Atomicity is broken; leave no residue for the next run.
            self.sql
                .exec("DELETE FROM meta WHERE k = ?1", &key())
                .await?;
        }
        Ok(guard_fired && marker.is_empty())
    }

    // gc
    async fn gc_due(&self, now: UnixMs, limit: u32, disposable_only: bool) -> Result<Vec<GcRow>> {
        gc::gc_due(self, now, limit, disposable_only).await
    }
    async fn gc_begin(&self, row: &GcRow, now: UnixMs) -> Result<GcStep> {
        gc::gc_begin(self, row, now).await
    }
    async fn gc_done(&self, id: i64, now: UnixMs) -> Result<()> {
        gc::gc_done(self, id, now).await
    }

    // recovery replay
    async fn replay_probe(&self, g: &GenerationRow) -> Result<ReplayProbe> {
        replay::replay_probe(self, g).await
    }
    async fn replay_extents(
        &self,
        bucket: &Bucket,
        extents: &[ReplayExtent],
        now: UnixMs,
    ) -> Result<()> {
        replay::replay_extents(self, bucket, extents, now).await
    }
    async fn replay_damaged(&self, limit: u32) -> Result<(u64, Vec<GenerationId>)> {
        replay::replay_damaged(self, limit).await
    }
    async fn replay_publish(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
        now: UnixMs,
    ) -> Result<Guard<()>> {
        replay::replay_publish(self, g, placements, now).await
    }

    // provider permits
    async fn seed_permits(&self, providers: &[ProviderConfig]) -> Result<()> {
        permits::seed_permits(self, providers).await
    }
    async fn acquire_permit(
        &self,
        p: &ProviderConfig,
        class: PermitClass,
        holder: &str,
        now: UnixMs,
    ) -> Result<Option<Permit>> {
        permits::acquire_permit(self, p, class, holder, now).await
    }
    async fn renew_permit(&self, p: &Permit, now: UnixMs) -> Result<bool> {
        permits::renew_permit(self, p, now).await
    }
    async fn release_permit(&self, p: &Permit) -> Result<()> {
        permits::release_permit(self, p).await
    }

    // provider pool
    async fn provider_load(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        health::provider_load(self, now).await
    }
    async fn provider_failed(&self, provider: &str, now: UnixMs) -> Result<()> {
        health::provider_failed(self, provider, now).await
    }
    async fn provider_recovered(&self, provider: &str, now: UnixMs) -> Result<()> {
        health::provider_recovered(self, provider, now).await
    }
    async fn redrive_underverified(
        &self,
        backbones: &[String],
        required: u32,
        limit: u32,
        now: UnixMs,
    ) -> Result<u64> {
        outbox::redrive_underverified(self, backbones, required, limit, now).await
    }
    async fn revive_referenced(&self, limit: u32, now: UnixMs) -> Result<u64> {
        outbox::revive_referenced(self, limit, now).await
    }

    // hot tier
    async fn hot_stats(&self) -> Result<HotStats> {
        hot::hot_stats(self).await
    }
    async fn evictable_bytes(&self) -> Result<u64> {
        hot::evictable_bytes(self).await
    }
    async fn evict_candidates(&self, limit: u32) -> Result<Vec<EvictCandidate>> {
        hot::evict_candidates(self, limit).await
    }
    async fn begin_evict(&self, x: &EvictCandidate) -> Result<bool> {
        hot::begin_evict(self, x).await
    }
    async fn finish_evict(&self, x: &EvictCandidate) -> Result<bool> {
        hot::finish_evict(self, x).await
    }
    async fn record_cache_fill(&self, extent: &ExtentId, now: UnixMs) -> Result<()> {
        hot::record_cache_fill(self, extent, now).await
    }
    async fn touch_read(
        &self,
        extent: &ExtentId,
        now: UnixMs,
        min_gap_ms: i64,
        from_cache: bool,
    ) -> Result<UnixMs> {
        hot::touch_read(self, extent, now, min_gap_ms, from_cache).await
    }
    async fn hot_check_due(&self, now: UnixMs, every_ms: i64) -> Result<bool> {
        hot::hot_check_due(self, now, every_ms).await
    }
    async fn hot_checked(&self, now: UnixMs) -> Result<()> {
        hot::hot_checked(self, now).await
    }
    async fn hot_drain_set(&self, left: u64) -> Result<()> {
        hot::hot_drain_set(self, left).await
    }
    async fn hot_drain_claim(&self, left: u64) -> Result<bool> {
        hot::hot_drain_claim(self, left).await
    }
    async fn hot_seq(&self, extent: &ExtentId) -> Result<u64> {
        hot::hot_seq(self, extent).await
    }
    async fn hot_forget(
        &self,
        extent: &ExtentId,
        seq: u64,
        safety: bool,
        cache: bool,
    ) -> Result<bool> {
        hot::hot_forget(self, extent, seq, safety, cache).await
    }
}
