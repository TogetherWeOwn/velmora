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
use crate::recovery::{Recorded, Unpublished};
use crate::replay::{ReplayExtent, ReplayMark, ReplayProbe, ReplayPublish, RestoreProgress};
pub use crate::types::Result;
use crate::types::{
    AccessKeyRow, AccessKeySummary, ArticleRow, BackboneStatus, Bucket, BucketId, ByteSpan,
    CommitGeneration, CompleteUpload, CopyGeneration, DueRow, EvictCandidate, ExtentId,
    ExtentPlacement, ExtentRow, FailClass, GcRow, GcStep, GenerationId, GenerationRow, HotStats,
    IntentFence, IntentStats, Job, JobExtent, KekBytes, ListPage, ListQuery, ObjectStatus,
    OpenUpload, OutboxStage, OutboxStats, Perm, Precondition, ProviderConfig, ProviderFault,
    ProviderLoad, SafetyState, UnixMs, UploadId, UploadListQuery, UploadPartRow, UploadRow,
    VerificationRow, WriteId,
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

/// One key of a listing with what identifies its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobEntry {
    pub key: String,
    pub size: u64,
    /// MD5 of the bytes in lowercase hex, as the store reports it for an
    /// object written by one put.
    pub md5: String,
}

/// R2 `SAFETY`/`CACHE` now; any S3-compatible store later.
pub trait BlobStore {
    /// H2 adds `put_stream(len)`.
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()>;
    /// `None` = absent. With a span, exactly that range.
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>>;
    /// Object size, `None` = absent.
    async fn head(&self, key: &str) -> Result<Option<u64>>;
    /// Idempotent. Refuses a recovery record (any key under `m/`, which
    /// includes the tenant keys under `m/tk/`) and a rollback stamp (any
    /// key under `rs/`) with [`crate::recovery::ERR_RECORD_DELETE`]
    /// before the store is asked: no caller can remove one through this
    /// method.
    async fn delete(&self, key: &str) -> Result<()>;
    /// Removes the record of a generation that the catalogue refused to
    /// publish. The only delete of a key under `m/`; the argument exists
    /// only for a record this request wrote and did not publish.
    async fn delete_record(&self, refused: &Unpublished) -> Result<()>;
    /// Up to `limit` keys that start with `prefix` and sort after
    /// `start_after`, in key order. Fewer than `limit` = no more keys.
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>>;
    /// Keys as [`BlobStore::list`] gives them, with the size and MD5 of
    /// each. The end rule is not that of `list`: only an **empty** answer
    /// means no more keys. A short answer is not the end (a key removed
    /// since it was listed is left out); the caller goes on from the
    /// last key returned. A `limit` of 0 is read as 1.
    ///
    /// This default reads every blob; an adapter whose listing carries
    /// size and MD5 overrides it.
    async fn list_entries(
        &self,
        prefix: &str,
        start_after: &str,
        limit: u32,
    ) -> Result<Vec<BlobEntry>> {
        let mut entries = Vec::new();
        let mut after = start_after.to_string();
        // A key removed since it was listed is left out; an answer is
        // empty only when the listing itself has ended.
        while entries.is_empty() {
            let keys = self.list(prefix, &after, limit.max(1)).await?;
            let Some(last) = keys.last().cloned() else {
                break;
            };
            for key in keys {
                if let Some(bytes) = self.get(&key, None).await? {
                    entries.push(BlobEntry {
                        size: bytes.len() as u64,
                        md5: crate::remote::md5_hex(&bytes),
                        key,
                    });
                }
            }
            after = last;
        }
        Ok(entries)
    }
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

/// The longest one `connect`, `post`, `stat`, `body` or `quit` may take, whatever its
/// per-operation timeouts add up to: a connector gives the call up with
/// a transport error once this is over. A posting job counts on it, so
/// that no call outlasts the lease and the permit it started under.
pub const NNTP_CALL_SECS: u32 = 80;

/// The same bound under a permit of a read ([`PermitClass::Read`]): a
/// cold read gives a `connect` or a `body` up after this long. It is
/// short so that the permit can be ([`READ_PERMIT_SECS`]). One article
/// in this time is about 40 KB/s; a provider slower than that fails the
/// call, and the read goes on to the next one.
pub const READ_CALL_SECS: u32 = 20;

/// The longest a `quit` may take, under a permit of any class. The
/// goodbye comes after the last renewal, so it counts against the
/// permit too, and nothing is lost when nobody answers it.
pub const QUIT_SECS: u32 = 5;

/// Opens sessions. No permit, no socket. A `connect` ends within
/// [`PermitClass::call_secs`] of the permit's class, and so does every
/// call on its sessions; a `quit` ends within [`QUIT_SECS`].
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

/// How long a claim or a renewal holds an outbox row. Every [`Catalog`]
/// grants exactly this, so a job can tell from its own clock how long the
/// lease it last renewed is still safe from a takeover.
pub const LEASE_SECS: u32 = 600;

/// How long an acquired or renewed provider permit of a background job
/// holds its slot.
pub const PERMIT_SECS: u32 = 120;

/// The longest the renewal of a read's permit may take. The new expiry
/// counts from the time read before the catalogue round trip, so a slow
/// round trip eats into the permit: after a slower one the read gives
/// the slot up rather than count on what is left.
pub const READ_RENEW_SECS: u32 = 5;

/// Time a read's permit has to spare beyond its renewal, one call and
/// the goodbye: for the steps in between, and for a timer that fires
/// late.
pub const READ_SLACK_SECS: u32 = 5;

/// How long an acquired or renewed permit of a read holds its slot. A
/// read whose client went away is dropped where it waits and releases
/// nothing, so this is how long its slot, and its source address, stay
/// taken. A read renews before every `connect` and every `body`, so the
/// permit has to outlast one such call and the `quit` after the last.
pub const READ_PERMIT_SECS: u32 = 35;
const _: () =
    assert!(READ_PERMIT_SECS >= READ_RENEW_SECS + READ_CALL_SECS + QUIT_SECS + READ_SLACK_SECS);
const _: () = assert!(READ_CALL_SECS <= NNTP_CALL_SECS && READ_PERMIT_SECS <= PERMIT_SECS);

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
    /// The class it was acquired for: how long it holds the slot, and
    /// how long a call under it may take.
    pub class: PermitClass,
}

/// Who takes a slot. Background jobs leave `READ_RESERVE` slots for
/// cold GETs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermitClass {
    /// A queue job: post, verify, repost.
    Background,
    /// Work done inside a request: a cold read, a drill.
    Read,
}

impl PermitClass {
    /// How long a permit of this class holds its slot after an acquire
    /// or a renewal.
    pub const fn permit_secs(self) -> u32 {
        match self {
            PermitClass::Background => PERMIT_SECS,
            PermitClass::Read => READ_PERMIT_SECS,
        }
    }

    /// The longest one `connect`, `post`, `stat` or `body` may take
    /// under a permit of this class.
    pub const fn call_secs(self) -> u32 {
        match self {
            PermitClass::Background => NNTP_CALL_SECS,
            PermitClass::Read => READ_CALL_SECS,
        }
    }

    /// The longest a renewal may take for the permit to be counted on
    /// afterwards. `None`: not bounded. A background permit outlasts
    /// one call by [`PERMIT_SECS`] - [`NNTP_CALL_SECS`], and that margin
    /// is what covers a slow renewal of a job.
    pub const fn renew_secs(self) -> Option<u32> {
        match self {
            PermitClass::Background => None,
            PermitClass::Read => Some(READ_RENEW_SECS),
        }
    }
}

/// Outcome of a guarded batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Guard<T> {
    Applied(T),
    /// The guard failed; the batch wrote nothing.
    Lost,
}

/// Outcome of a publication batch. The batch takes the proof of the
/// generation's recovery record and turns it into an [`Unpublished`] only
/// when it wrote nothing, so only then can the record be discarded.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    Applied,
    /// The guard failed; the batch wrote nothing.
    Refused(Unpublished),
    /// CompleteMultipartUpload only. The batch failed with an unknown
    /// outcome and the upload was then moved to its next revision: the
    /// batch had not applied, and its guard can never pass again.
    Fenced(Unpublished),
}

// Fenced methods return Ok(false) (or None) when the lease token no longer
// matches: the caller stops and acks.

/// The ids the catalogue holds on one key ([`Catalog::key_heads`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyHead {
    /// The id of the live generation.
    pub live: Option<GenerationId>,
    /// The floor of the key.
    pub floor: Option<GenerationId>,
    /// The floor stands for a generation record that may exist, was
    /// never published and is covered by no tombstone
    /// ([`Catalog::unpublished_floor`]).
    pub unpublished: bool,
}

/// The catalogue, implemented once: `sql::SqlCatalog<S: Sql>`.
pub trait Catalog {
    // admin + auth
    /// `Lost` = name taken.
    async fn create_bucket(&self, b: &Bucket) -> Result<Guard<()>>;
    async fn create_access_key(&self, k: &AccessKeyRow) -> Result<()>;
    async fn put_grant(&self, akid: &str, bucket: &BucketId, perm: Perm) -> Result<()>;
    async fn bucket_by_name(&self, name: &str) -> Result<Option<Bucket>>;
    /// `true` while anything of the bucket is on record: a generation
    /// (live or not; none is ever removed), a key floor, an upload in any
    /// state, an extent. Such a bucket is never deleted.
    async fn bucket_in_use(&self, bucket: &BucketId) -> Result<bool>;
    /// Removes the bucket row and its grants in one guarded batch.
    /// `Lost` = nothing was changed: the bucket is in use
    /// ([`Self::bucket_in_use`]), is not there under this id and name any
    /// more, or a replay of the recovery records is under way.
    ///
    /// Only a bucket without history goes. A recovery record is never
    /// removed, and a replay re-creates the bucket of every record it
    /// reads, under the name the record carries: the records of a deleted
    /// bucket would bring it back and, once the name is in use again,
    /// stand against the records of the bucket that now holds it. A
    /// bucket that never had a record has none to leave behind: the floor
    /// of a key is raised before a record is stored
    /// ([`Self::raise_floor`]), it fails once the bucket is gone, and a
    /// floor is only taken away by the publication that leaves a
    /// generation row.
    async fn delete_bucket(&self, bucket: &Bucket) -> Result<Guard<()>>;
    async fn buckets_for(&self, akid: &str) -> Result<Vec<Bucket>>;
    async fn access_key(&self, akid: &str) -> Result<Option<AccessKeyRow>>;
    async fn grant(&self, akid: &str, bucket: &BucketId) -> Result<Option<Perm>>;
    /// `true` while the key has a row, whatever its status.
    async fn access_key_exists(&self, akid: &str) -> Result<bool>;
    /// Up to `limit` keys whose id sorts after `after`, in id order, each
    /// with its grants. Never the wrapped secret.
    async fn list_access_keys(&self, after: &str, limit: u32) -> Result<Vec<AccessKeySummary>>;
    /// Deletes the rows of these keys and their grants in one batch, so a
    /// lookup finds either the key with all its grants or nothing.
    /// Returns how many key rows went; unknown ids are no error.
    async fn delete_access_keys(&self, akids: &[String]) -> Result<u64>;

    // objects
    async fn live_object(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>>;
    /// Single PUT; one batch (DESIGN §A.3 step 6). `Lost` = the key's
    /// live generation carries a newer id or its floor a higher one; nothing
    /// was written. The caller takes a newer id and tries again.
    ///
    /// `condition`, here and on the other publications: the batch also
    /// publishes only while the live object of the key meets it. It is a
    /// guard statement of the batch, judged against the very object the
    /// batch retires. A batch refused for it wrote nothing and is
    /// `Refused` like one refused for its id; the caller tells the two
    /// apart by looking at the key again.
    async fn commit_generation(
        &self,
        c: &CommitGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome>;
    /// [`Self::commit_generation`] for a body stored as the slices of
    /// `write`. The batch also commits only while every intent of the
    /// write is `open` under this generation id, and deletes them. So a
    /// write the sweep has taken is refused like one with an older id.
    async fn commit_sliced(
        &self,
        c: &CommitGeneration,
        write: &WriteId,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome>;

    // write intents (the slices of a multi-extent write)
    /// Records the slices of `write` before the first of them is
    /// stored: one `open` row per extent id, in one batch. `Lost` = a
    /// replay is under way; nothing was written.
    async fn open_intents(
        &self,
        write: &WriteId,
        extents: &[ExtentId],
        now: UnixMs,
    ) -> Result<Guard<()>>;
    /// Stores the id of the recovery record that is written next. A
    /// record of the write is then always found from its rows. `Lost` =
    /// the write no longer has `slices` open rows (the sweep took it, or
    /// a replay emptied the table) or a replay is under way: the request
    /// must stop before it writes a record.
    async fn intents_generation(
        &self,
        write: &WriteId,
        generation: &GenerationId,
        slices: usize,
    ) -> Result<Guard<()>>;
    /// The request gave up and no recovery record of the write exists:
    /// its `open` rows become `abandoned`, and the sweep takes them
    /// without waiting for the grace period.
    async fn abandon_intents(&self, write: &WriteId) -> Result<()>;
    /// Writes the sweep has to look at, oldest first: `abandoned`, left
    /// `sweeping` by a job that died, or `open` and created before
    /// `open_before`.
    async fn due_intents(&self, open_before: UnixMs, limit: u32) -> Result<Vec<WriteId>>;
    /// Takes `write` for the sweep in one batch that fails while a
    /// replay is under way, the write has a generation or extent row,
    /// or the stamp counter is below `stamp`: the counter the caller's
    /// rollback check found level with the stamp objects (`None` = it
    /// found no stamp object).
    async fn fence_intents(
        &self,
        write: &WriteId,
        open_before: UnixMs,
        stamp: Option<u64>,
    ) -> Result<IntentFence>;
    /// The checks of the fence once more, just before blobs are
    /// deleted. `true` = all `slices` rows are still `sweeping`, no
    /// replay runs, the write has no catalogue row, and the stamp
    /// counter is not below `stamp` (as for the fence).
    async fn hold_intent_fence(
        &self,
        write: &WriteId,
        slices: usize,
        stamp: Option<u64>,
    ) -> Result<bool>;
    /// A recovery record of the fenced write exists: its rows become
    /// `kept` and one anomaly is counted. Nothing is deleted.
    async fn keep_intents(&self, write: &WriteId) -> Result<()>;
    /// The blobs of the fenced write are gone: its rows go.
    async fn drop_intents(&self, write: &WriteId) -> Result<()>;
    /// Counts for `GET /_admin/status`.
    async fn intent_stats(&self, open_before: UnixMs) -> Result<IntentStats>;
    /// The newest id on `(bucket, key)`: its live generation or its
    /// floor. A publication or a tombstone must sort after it.
    async fn newest_id(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationId>>;
    /// Raises the floor of `(bucket, key)` to `id`, if it is lower: the
    /// highest id a recovery record of the key may be stored under. The
    /// record writers call it before they store anything
    /// ([`crate::recovery::write_generation`],
    /// [`crate::recovery::write_tombstone`]), and it stands whatever
    /// becomes of the write: every later id on the key sorts after `id`.
    /// `generation` = the record is a generation manifest, which a
    /// replay publishes if nothing on record sorts after it.
    /// An error when the catalogue has no such bucket (it was deleted):
    /// no record is then stored for it.
    async fn raise_floor(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        generation: bool,
    ) -> Result<()>;
    /// The tombstone `id` of the key is stored. It covers the generation
    /// records the floor was raised for, unless the floor is above it.
    async fn settle_floor(&self, bucket: &BucketId, key: &str, id: &GenerationId) -> Result<()>;
    /// The floor of the key, if a generation record may exist under it
    /// that was never published and that no tombstone covers.
    async fn unpublished_floor(&self, bucket: &BucketId, key: &str)
        -> Result<Option<GenerationId>>;
    /// Publishes a generation that references the extents of the source
    /// generation; no extent is written. `Refused` = the source is no
    /// longer the live object of its key, or the destination key's live
    /// generation carries a newer id or its floor a higher one; nothing was
    /// published.
    async fn copy_generation(
        &self,
        c: &CopyGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome>;
    /// DeleteObject as the service runs it: retires the live generation
    /// of the key only if its id sorts before `before`, the id of the
    /// tombstone written for this delete. `false` = nothing was changed:
    /// nothing was live, the live generation is newer than the
    /// tombstone, the floor of the key is above the tombstone (a write
    /// began after the tombstone was chosen: the caller starts again
    /// above it), or a replay of the recovery records is under way. A
    /// replay applies the tombstone with [`Self::replay_tombstone`].
    async fn delete_object_before(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        now: UnixMs,
    ) -> Result<bool>;
    /// [`Self::delete_object_before`] for a conditional DeleteObject:
    /// the batch also retires the live generation only while it meets
    /// `condition`.
    async fn delete_object_if(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        condition: &Precondition,
        now: UnixMs,
    ) -> Result<bool>;
    /// What [`Self::live_object`] and the floor of each key say, for
    /// every key of `keys` in its order, read in one statement: all keys
    /// as of one moment.
    async fn key_heads(&self, bucket: &BucketId, keys: &[&str]) -> Result<Vec<KeyHead>>;
    /// [`Self::raise_floor`] for the tombstone of every `(key, id)`, in
    /// one batch: all floors are raised or, on an error, none.
    async fn raise_floors(&self, bucket: &BucketId, ids: &[(&str, &GenerationId)]) -> Result<()>;
    /// [`Self::settle_floor`] for every `(key, id)`, in one batch.
    async fn settle_floors(&self, bucket: &BucketId, ids: &[(&str, &GenerationId)]) -> Result<()>;
    /// [`Self::delete_object_before`] for every `(key, id, now)` (each
    /// key once), in one batch: every key is deleted as that call
    /// deletes it, in the order given, or nothing is changed. `false` =
    /// nothing was changed, because for at least one key that call would
    /// have answered `false`; the caller then asks key by key.
    async fn delete_objects_before(
        &self,
        bucket: &BucketId,
        deletes: &[(&str, &GenerationId, UnixMs)],
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
    /// The open uploads of the bucket in `(key, upload id)` order, at
    /// most `q.limit`.
    async fn list_uploads(&self, bucket: &BucketId, q: &UploadListQuery)
        -> Result<Vec<OpenUpload>>;
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
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome>;
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
    /// Marks several articles posted in one atomic write; each entry is
    /// `(idx, provider)`. `false` = fenced, and then nothing was written.
    async fn mark_posted_many(
        &self,
        l: &Lease,
        posted: &[(u32, &str)],
        now: UnixMs,
    ) -> Result<bool>;
    /// Stamps the articles `idxs` as posted again at `now`
    /// (`ArticleRow::reposted_at`), in one atomic write. A stamp never
    /// moves back. `false` = fenced, and then nothing was written.
    async fn mark_reposted_many(&self, l: &Lease, idxs: &[u32], now: UnixMs) -> Result<bool>;
    /// Renews the lease and every permit in one round trip. `.0` = the
    /// lease still holds; `.1[i]` = `permits[i]` is still held. Each
    /// renewal stands on its own: a lost lease does not undo the permits.
    async fn renew_all(
        &self,
        l: &Lease,
        permits: &[Permit],
        now: UnixMs,
    ) -> Result<(bool, Vec<bool>)>;
    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool>;
    /// Latest row per backbone for the current `plan_rev`, with `counts`.
    async fn backbone_status(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>>;
    /// `counting` = the labels of the backbones that count toward a
    /// release. The guard is the release rule over rows recorded under
    /// this claim: `required` of those backbones with a complete pass,
    /// at least one of them a `body` pass.
    async fn begin_release(
        &self,
        l: &Lease,
        required: u32,
        counting: &[String],
        evidence_json: &str,
        now: UnixMs,
    ) -> Result<Guard<()>>;
    async fn finish_release(&self, l: &Lease, now: UnixMs) -> Result<bool>;
    /// Up to `limit` rows in `post`, `verify` or `release` that are due
    /// and held by no job, oldest due time first. A row marked by
    /// [`Self::mark_sent`] is left out until `resend_secs` after the
    /// mark, unless a job claimed it since (a claim clears the mark) or
    /// it was given a due time later than the mark.
    async fn due(&self, now: UnixMs, resend_secs: u32, limit: u32) -> Result<Vec<DueRow>>;
    /// The dispatcher has sent a job for each of `extents`: marks the
    /// ones that are still due and held by no job, and returns how many.
    /// The mark is a hint for [`Self::due`] alone; it gates no claim.
    async fn mark_sent(&self, extents: &[ExtentId], now: UnixMs) -> Result<u64>;
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
    /// Extents whose row says the pinned copy is held, in id order after
    /// `after`.
    async fn held_extents(&self, after: &str, limit: u32) -> Result<Vec<ExtentId>>;
    /// A replay starts: writes are refused until [`Self::restore_finish`].
    /// `Ok` = the mark of this replay: later than that of every replay
    /// before it. `Err` = refused: a replay from the restore point in
    /// the `Err` has not ended, and `since` is later than that point.
    /// The start removes the write intents in its own batch, all but
    /// the `kept` rows whose record the replay does not read (a record
    /// from before `since`).
    async fn restore_begin(
        &self,
        since: UnixMs,
        now: UnixMs,
    ) -> Result<std::result::Result<UnixMs, UnixMs>>;
    /// The replay with the mark `run` ran to its end. `false` = another
    /// replay was started since; that one is not ended by this.
    /// In the same batch the rollback stamp is made level: the counter
    /// becomes at least `stamp` (the newest stamp object) and a recorded
    /// rollback is cleared. Only the call that ends the replay does
    /// that; a repeated call for a replay that has ended does not.
    /// `seen` is the counter the caller read when it chose `stamp`: if
    /// the catalogue holds another one by now (it was brought back to
    /// an earlier point in between), nothing is changed and the answer
    /// is `false`.
    async fn restore_finish(
        &self,
        run: UnixMs,
        now: UnixMs,
        stamp: u64,
        seen: Option<u64>,
        catalogue: &str,
    ) -> Result<bool>;
    /// Whether writes and jobs must be refused: a replay was started and
    /// has not ended, or a rollback of the catalogue was found and no
    /// replay has ended since.
    async fn restore_pending(&self) -> Result<bool>;
    /// The rollback stamp row ([`crate::stamp`]). `catalogue` is the id
    /// this Worker keys the stamp objects by; the row keeps the id it
    /// was created with. [`crate::stamp::ERR_CATALOGUE_ID`] = the two
    /// differ.
    async fn stamp(&self, catalogue: &str) -> Result<crate::stamp::StampRow>;
    /// Moves the stamp counter from `from` to the next value (`None` =
    /// creates the row at 1). `false` = the counter is not at `from`, or
    /// a rollback is recorded: nothing changed.
    async fn stamp_advance(&self, from: Option<u64>, catalogue: &str) -> Result<bool>;
    /// Records that the catalogue was found behind its stamp, if its
    /// counter is still `seen` (`None` = there is no row) and no
    /// rollback is on record. `false` = nothing was recorded: the
    /// counter moved since the caller read it, or another caller
    /// recorded the rollback. The caller reads again.
    async fn stamp_rolled_back(
        &self,
        seen: Option<u64>,
        now: UnixMs,
        catalogue: &str,
    ) -> Result<bool>;
    /// The replay with the mark `run`: its restore point and how far it
    /// has come. `None` = `run` is not the replay that was started last.
    async fn restore_progress(&self, run: UnixMs) -> Result<Option<RestoreProgress>>;
    /// The replay with the mark `run` has come as far as `next`. Never
    /// moves the place backwards.
    async fn restore_advance(&self, run: UnixMs, next: &ReplayMark) -> Result<()>;
    /// Applies a tombstone record in a replay: raises the floor of the
    /// key to `id`, then retires the live generation if its id sorts
    /// before `id`. `true` = a generation was retired.
    async fn replay_tombstone(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        now: UnixMs,
    ) -> Result<bool>;
    /// Live generations with an extent that has neither a pinned copy
    /// nor an article plan: their number and the first `limit` ids.
    async fn replay_damaged(&self, limit: u32) -> Result<(u64, Vec<GenerationId>)>;
    /// Publishes the generation over the extents `replay_extents` left.
    /// A generation with an extent that has no copy anywhere is not
    /// published on a key that has an older generation.
    async fn replay_publish(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
        now: UnixMs,
    ) -> Result<ReplayPublish>;

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
    /// One failed session, and why. Repeated failures start a cooldown; a
    /// failure reported while the provider is cooling changes nothing.
    async fn provider_failed(
        &self,
        provider: &str,
        fault: ProviderFault,
        now: UnixMs,
    ) -> Result<()>;
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
