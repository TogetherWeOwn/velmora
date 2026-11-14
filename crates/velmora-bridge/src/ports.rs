//! Ports: the traits every runtime adapter implements (frozen with the
//! contract, DESIGN §B.1).
//!
//! These are native `async fn`s in traits with no `Send` bound, because the
//! workers-rs futures are `!Send`. Code is generic over the ports, never
//! `dyn`. Native tests drive them on a current-thread runtime.

// No `Send` bound is intended (see module docs).
#![allow(async_fn_in_trait)]

use crate::config::BridgeConfig;
use crate::ingress::ByteBudget;
use crate::replay::{ReplayExtent, ReplayProbe};
pub use crate::types::Result;
use crate::types::{
    AccessKeyRow, ArticleRow, BackboneStatus, Bucket, BucketId, ByteSpan, CommitGeneration,
    CompleteUpload, CopyGeneration, DueRow, EvictCandidate, ExtentId, ExtentPlacement, ExtentRow,
    FailClass, GcRow, GcStep, GenerationId, GenerationRow, HotStats, Job, JobExtent, KekBytes,
    ListPage, ListQuery, ObjectStatus, OutboxStage, OutboxStats, Perm, ProviderConfig,
    ProviderLoad, SafetyState, UnixMs, UploadId, UploadPartRow, UploadRow, VerificationRow,
};

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

/// One bound statement parameter or result column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Text(String),
    Blob(Vec<u8>),
}

/// One result row, columns in statement order.
pub type Row = Vec<SqlValue>;

/// The catalogue database: D1 (`workers/s3-bridge/src/d1.rs`), rusqlite
/// (`testkit`), later Hyperdrive.
///
/// `batch` is all-or-nothing. A `tx_guard` CHECK failure is
/// `Err(BridgeError::GuardFailed)` (DESIGN §A.11); any other failing
/// statement is an error too, and in both cases nothing was written.
///
/// As on D1: at most [`MAX_SQL_PARAMS`] bound parameters per statement
/// (more is an error), and `exec`/`batch` run every statement to
/// completion, so `RETURNING` and `SELECT` statements are accepted (their
/// rows are discarded; a `SELECT` changes 0 rows).
pub trait Sql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>>;
    /// Returns the number of rows changed.
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64>;
    /// Atomic. Returns rows changed per statement.
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>>;
}

/// D1's bound-parameter limit per statement.
pub const MAX_SQL_PARAMS: usize = 100;

/// Whether a database error message is the `tx_guard` CHECK firing
/// (`CHECK (ok = 1)` in `0001_init.sql`). SQLite and D1 both report
/// `CHECK constraint failed: ok = 1`. Every `Sql` adapter maps such an
/// error to `BridgeError::GuardFailed` with this one rule.
pub fn is_tx_guard_violation(message: &str) -> bool {
    message.contains("CHECK constraint failed") && message.contains("ok = 1")
}

// ---------------------------------------------------------------------------
// Blobs
// ---------------------------------------------------------------------------

/// Custom metadata stored with every ciphertext blob.
#[derive(Clone, Copy, Debug)]
pub struct BlobMeta<'a> {
    pub bucket: &'a BucketId,
    pub extent: &'a ExtentId,
    pub cipher_sha256: &'a [u8; 32],
}

/// R2 `SAFETY`/`CACHE` now; any S3-compatible store later.
pub trait BlobStore {
    /// H2 adds `put_stream(len)`.
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()>;
    /// `None` = absent. With a span, exactly that range.
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>>;
    /// Object size, `None` = absent.
    async fn head(&self, key: &str) -> Result<Option<u64>>;
    /// Idempotent.
    async fn delete(&self, key: &str) -> Result<()>;
    /// Up to `limit` keys that start with `prefix` and sort after
    /// `start_after`, in key order. Fewer than `limit` = no more keys.
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>>;
}

// ---------------------------------------------------------------------------
// NNTP
// ---------------------------------------------------------------------------

/// Result of one `BODY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyOutcome {
    Found,
    /// `430`; the session stays usable.
    Missing,
}

/// One authenticated NNTP session. Blanket impl for
/// `velmora::nntp::NntpClient<T: Transport>` lands with the poster lane.
///
/// Any `Err` from a session: drop it (no reuse, no quit) and reconnect.
/// No batch or pipelined read exists.
pub trait NntpSession {
    /// `post_article`.
    async fn post(
        &mut self,
        message_id: &str,
        article: &[u8],
    ) -> Result<velmora::nntp::PostOutcome>;
    /// `false` = 430.
    async fn stat(&mut self, message_id: &str) -> Result<bool>;
    /// One `body_to`; appends to `out`.
    async fn body(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome>;
    async fn quit(self);
}

/// Opens sessions. No permit, no socket.
pub trait NntpConnector {
    type Session: NntpSession;
    async fn connect(&self, provider: &ProviderConfig, permit: &Permit) -> Result<Self::Session>;
}

// ---------------------------------------------------------------------------
// Queues, clock, keys
// ---------------------------------------------------------------------------

/// Longest queue delivery delay Queues accepts (12 h).
pub const MAX_QUEUE_DELAY_SECS: u32 = 43_200;

pub trait JobSink {
    /// `delay_secs` above [`MAX_QUEUE_DELAY_SECS`] is an error.
    async fn send(&self, job: &Job, delay_secs: u32) -> Result<()>;
    /// Dispatcher only; at most 100 jobs.
    async fn send_many(&self, jobs: &[Job]) -> Result<()>;
}

pub trait Clock {
    fn now(&self) -> UnixMs;
}

/// Key-encryption keys from Worker secrets.
pub trait Kek {
    /// `(VELMORA_KEK_ACTIVE, its key)`.
    fn active(&self) -> (u32, &KekBytes);
    fn version(&self, v: u32) -> Option<&KekBytes>;
}

// ---------------------------------------------------------------------------
// Catalogue
// ---------------------------------------------------------------------------

/// Multipart target, built only from the authorized request target. The
/// SQL always filters on all three (DESIGN §A.4).
#[derive(Clone, Copy, Debug)]
pub struct UploadTarget<'a> {
    pub bucket: &'a BucketId,
    pub key: &'a str,
    pub id: &'a UploadId,
}

/// A claimed outbox row. Every later mutation carries it and writes only
/// while `token` still matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub extent: ExtentId,
    pub generation: GenerationId,
    pub stage: OutboxStage,
    pub token: u64,
    /// `outbox.attempts` after this claim (the claim counts as one), so
    /// retry backoff is derived from it.
    pub attempts: u32,
    /// `outbox.cursor` at claim time (verify/release: backbone index).
    pub cursor: u32,
}

/// A held provider connection slot (fenced by `token`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    pub provider: String,
    pub slot: u32,
    pub token: u64,
}

/// Background jobs leave `READ_RESERVE` slots for cold GETs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermitClass {
    Background,
    Read,
}

/// Outcome of a guarded batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Guard<T> {
    Applied(T),
    /// The guard failed; the batch wrote nothing.
    Lost,
}

// Fenced methods return Ok(false) (or None) when the lease token no longer
// matches: the caller stops and acks.

/// The catalogue, implemented once: `sql::SqlCatalog<S: Sql>`.
pub trait Catalog {
    // admin + auth
    /// `Lost` = name taken.
    async fn create_bucket(&self, b: &Bucket) -> Result<Guard<()>>;
    async fn create_access_key(&self, k: &AccessKeyRow) -> Result<()>;
    async fn put_grant(&self, akid: &str, bucket: &BucketId, perm: Perm) -> Result<()>;
    async fn bucket_by_name(&self, name: &str) -> Result<Option<Bucket>>;
    async fn buckets_for(&self, akid: &str) -> Result<Vec<Bucket>>;
    async fn access_key(&self, akid: &str) -> Result<Option<AccessKeyRow>>;
    async fn grant(&self, akid: &str, bucket: &BucketId) -> Result<Option<Perm>>;

    // objects
    async fn live_object(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>>;
    /// Single PUT; one batch (DESIGN §A.3 step 6).
    async fn commit_generation(&self, c: &CommitGeneration) -> Result<()>;
    /// Publishes a generation that references the extents of the source
    /// generation; no extent is written. `Lost` = the source is no longer
    /// the live object of its key, or the live generation of the
    /// destination key does not sort before the new one by id; nothing
    /// was published.
    async fn copy_generation(&self, c: &CopyGeneration) -> Result<Guard<()>>;
    async fn delete_object(&self, bucket: &BucketId, key: &str, now: UnixMs) -> Result<()>;
    /// DeleteObject as the service runs it: retires the live generation
    /// of the key only if its id sorts before `before`, the id of the
    /// tombstone written for this delete. `false` = nothing was live, or
    /// the live generation is newer than the tombstone. A replay of the
    /// tombstone decides the same way.
    async fn delete_object_before(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        now: UnixMs,
    ) -> Result<bool>;
    async fn list(&self, bucket: &BucketId, q: &ListQuery) -> Result<ListPage>;
    /// Admin view.
    async fn object_status(&self, bucket: &BucketId, key: &str) -> Result<Option<ObjectStatus>>;
    /// Compare-and-set; admin evict.
    async fn set_safety_state(
        &self,
        extent: &ExtentId,
        from: SafetyState,
        to: SafetyState,
    ) -> Result<bool>;

    // uploads: every call is bound to the authorized target
    async fn create_upload(&self, u: &UploadRow) -> Result<()>;
    /// The row carries state, revision and the completion receipt.
    async fn upload(&self, t: &UploadTarget<'_>)
        -> Result<Option<(UploadRow, Vec<UploadPartRow>)>>;
    async fn put_upload_part(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extent: &ExtentRow,
        now: UnixMs,
    ) -> Result<Guard<()>>;
    /// Publishes the staged part extents in place (see [`CompleteUpload`]).
    async fn complete_upload(
        &self,
        t: &UploadTarget<'_>,
        revision: u64,
        digest: &[u8; 32],
        c: &CompleteUpload,
    ) -> Result<Guard<()>>;
    /// The extent rows of the upload's current parts, in no order.
    async fn upload_extents(&self, t: &UploadTarget<'_>) -> Result<Vec<ExtentRow>>;
    async fn abort_upload(&self, t: &UploadTarget<'_>, now: UnixMs) -> Result<Guard<()>>;

    // outbox: claim returns the fencing token; everything after takes the Lease
    async fn claim(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
        stage: OutboxStage,
        owner: &str,
        now: UnixMs,
    ) -> Result<Option<Lease>>;
    async fn renew(&self, l: &Lease, now: UnixMs) -> Result<bool>;
    async fn advance(
        &self,
        l: &Lease,
        to: OutboxStage,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool>;
    /// Releases the lease with `next_at`; stores `class` only.
    async fn fail(&self, l: &Lease, class: FailClass, next_at: UnixMs, now: UnixMs)
        -> Result<bool>;
    /// Fenced resume point (verify/release: next backbone index).
    async fn set_cursor(&self, l: &Lease, cursor: u32, now: UnixMs) -> Result<bool>;
    /// No permit: frees the lease without consuming an attempt.
    async fn defer(&self, l: &Lease, next_at: UnixMs, now: UnixMs) -> Result<bool>;
    /// Extent + bucket + generation state: `live` while any live
    /// generation references the extent, else the state of the generation
    /// it was written for.
    async fn job_extent(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
    ) -> Result<Option<JobExtent>>;
    /// Insert-if-absent; returns the STORED plan (`None` = fenced).
    async fn plan_articles(
        &self,
        l: &Lease,
        rows: &[ArticleRow],
    ) -> Result<Option<Vec<ArticleRow>>>;
    async fn articles(&self, extent: &ExtentId) -> Result<Vec<ArticleRow>>;
    async fn mark_posted(&self, l: &Lease, idx: u32, provider: &str, now: UnixMs) -> Result<bool>;
    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool>;
    /// Latest row per backbone for the current `plan_rev`, with `counts`.
    async fn backbone_status(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>>;
    async fn begin_release(
        &self,
        l: &Lease,
        required: u32,
        evidence_json: &str,
        now: UnixMs,
    ) -> Result<Guard<()>>;
    async fn finish_release(&self, l: &Lease, now: UnixMs) -> Result<bool>;
    async fn due(&self, now: UnixMs, limit: u32) -> Result<Vec<DueRow>>;
    async fn bury_exhausted(&self, max_attempts: u32, now: UnixMs) -> Result<u64>;
    /// Stamps `meta.last_dispatch_at` (the dispatcher, once per run).
    async fn record_dispatch(&self, now: UnixMs) -> Result<()>;
    /// Counts per stage, dead count, last dispatch time.
    async fn outbox_stats(&self) -> Result<OutboxStats>;
    /// Dev self-test: a batch of `[marker write, failing tx_guard]`.
    /// `true` = the batch failed with `GuardFailed` and the marker is absent.
    async fn guard_selftest(&self) -> Result<bool>;

    // gc
    async fn gc_due(&self, now: UnixMs, limit: u32, disposable_only: bool) -> Result<Vec<GcRow>>;
    /// Re-checks that no live generation and no open upload references
    /// the extent; applies catalogue-only actions.
    async fn gc_begin(&self, row: &GcRow, now: UnixMs) -> Result<GcStep>;
    /// After the blob delete that `GcStep::DeleteBlob` asked for.
    async fn gc_done(&self, id: i64, now: UnixMs) -> Result<()>;

    // recovery replay (DESIGN §A.8); every call is idempotent
    /// Where a manifest's generation stands in this catalogue.
    async fn replay_probe(&self, g: &GenerationRow) -> Result<ReplayProbe>;
    /// Makes the bucket, the extents (new ones staged, without a
    /// generation) and their article plans exist, and records a pinned
    /// copy that is gone.
    async fn replay_extents(
        &self,
        bucket: &Bucket,
        extents: &[ReplayExtent],
        now: UnixMs,
    ) -> Result<()>;
    /// Live generations with an extent that has neither a pinned copy
    /// nor an article plan: their number and the first `limit` ids.
    async fn replay_damaged(&self, limit: u32) -> Result<(u64, Vec<GenerationId>)>;
    /// Publishes the generation over the extents `replay_extents` left.
    /// `Lost` = already present, a newer generation of the key is live,
    /// or the extents do not tile it; nothing was written.
    async fn replay_publish(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
        now: UnixMs,
    ) -> Result<Guard<()>>;

    // provider permits
    async fn seed_permits(&self, providers: &[ProviderConfig]) -> Result<()>;
    async fn acquire_permit(
        &self,
        p: &ProviderConfig,
        class: PermitClass,
        holder: &str,
        now: UnixMs,
    ) -> Result<Option<Permit>>;
    async fn renew_permit(&self, p: &Permit, now: UnixMs) -> Result<bool>;
    async fn release_permit(&self, p: &Permit) -> Result<()>;

    // provider pool
    /// Held slots, slots ever handed out and health, per provider that
    /// has a permit or a health row.
    async fn provider_load(&self, now: UnixMs) -> Result<Vec<ProviderLoad>>;
    /// One failed session. Repeated failures start a cooldown; a failure
    /// reported while the provider is cooling changes nothing.
    async fn provider_failed(&self, provider: &str, now: UnixMs) -> Result<()>;
    /// One good session: clears failures and the cooldown history, unless
    /// the provider is cooling now.
    async fn provider_recovered(&self, provider: &str, now: UnixMs) -> Result<()>;
    /// Sends `done` extents of live generations back to verify: safety copy still
    /// `held`, fewer than `required` of `backbones` counting. One call
    /// looks at the next `limit` held extents, in a rotation over all of
    /// them. Returns how many moved.
    async fn redrive_underverified(
        &self,
        backbones: &[String],
        required: u32,
        limit: u32,
        now: UnixMs,
    ) -> Result<u64>;
    /// Re-arms cancelled obligations of extents that a live generation
    /// references. Only a Worker from before extent references leaves
    /// one, after a rollback. One call looks at the next `limit` outbox
    /// rows, in a rotation over all of them. Returns how many it re-armed.
    async fn revive_referenced(&self, limit: u32, now: UnixMs) -> Result<u64>;

    // hot tier
    /// Pinned and evictable byte totals (`GET /_admin/status`).
    async fn hot_stats(&self) -> Result<HotStats>;
    /// Bytes R2 holds that may be evicted: released safety copies and
    /// cache fills. One index scan over the evictable extents.
    async fn evictable_bytes(&self) -> Result<u64>;
    /// Extents with evictable bytes, least recently read first.
    async fn evict_candidates(&self, limit: u32) -> Result<Vec<EvictCandidate>>;
    /// Starts an eviction in one statement that re-checks the extent:
    /// `true` only if it is exactly as listed (sequence, byte counts,
    /// pinned or not). With `x.pinned` only the cache fill is claimed.
    async fn begin_evict(&self, x: &EvictCandidate) -> Result<bool>;
    /// Ends an eviction after the blob deletes. `false` when a hot copy
    /// was recorded since `begin_evict`; the counts then stand.
    async fn finish_evict(&self, x: &EvictCandidate) -> Result<bool>;
    /// Counts the extent's cache fill and stamps the read. Called before
    /// and after the cache write.
    async fn record_cache_fill(&self, extent: &ExtentId, now: UnixMs) -> Result<()>;
    /// Stamps a read unless the last stamp is younger than `min_gap_ms`.
    /// `from_cache`: the read was served from the cache fill, which is
    /// counted by the same write if it was not.
    /// Returns the stamp the extent has afterwards.
    async fn touch_read(
        &self,
        extent: &ExtentId,
        now: UnixMs,
        min_gap_ms: i64,
        from_cache: bool,
    ) -> Result<UnixMs>;
    /// Whether no evictable total was recorded in the last `every_ms`.
    async fn hot_check_due(&self, now: UnixMs, every_ms: i64) -> Result<bool>;
    /// Records that the dispatcher took the evictable total at `now`.
    async fn hot_checked(&self, now: UnixMs) -> Result<()>;
    /// Records what a drain step leaves for the next one, before the
    /// step sends that job.
    async fn hot_drain_set(&self, left: u64) -> Result<()>;
    /// Takes up a drain where the last step left it: `true` once per
    /// `hot_drain_set(left)`. A duplicate of the job, or one from a drain
    /// that another has replaced, gets `false` and must do nothing.
    async fn hot_drain_claim(&self, left: u64) -> Result<bool>;
    /// The extent's eviction fencing token now. Read it before deleting
    /// blobs outside an eviction (admin evict) and pass it to `hot_forget`.
    async fn hot_seq(&self, extent: &ExtentId) -> Result<u64>;
    /// After blob deletes outside an eviction: stops counting the named
    /// copies, unless a hot copy was recorded or an eviction ran since
    /// `seq` was read (`false`; the counts stand, since the copy they
    /// count may exist).
    async fn hot_forget(
        &self,
        extent: &ExtentId,
        seq: u64,
        safety: bool,
        cache: bool,
    ) -> Result<bool>;
}

// ---------------------------------------------------------------------------
// The service core
// ---------------------------------------------------------------------------

/// Everything a handler or job touches. `handle` lives in `service`,
/// `run_job` and `dispatch` in `jobs`.
pub struct Bridge<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock> {
    pub catalog: C,
    pub safety: B,
    pub cache: B,
    pub nntp: N,
    pub jobs: J,
    pub kek: K,
    pub clock: T,
    /// Per-isolate in-flight bytes (DESIGN §A.2).
    pub budget: ByteBudget,
    /// Validated configuration.
    pub cfg: BridgeConfig,
}
