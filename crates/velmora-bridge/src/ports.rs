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
use crate::plan::{PackReport, StoredPlan};
use crate::recovery::{Recorded, Unpublished};
use crate::replay::{ReplayExtent, ReplayMark, ReplayProbe, ReplayPublish, RestoreProgress};
pub use crate::types::Result;
use crate::types::{
    AccessKeyRow, AccessKeySummary, ArticleRow, BackboneStatus, Backlog, Bucket, BucketId,
    ByteSpan, CommitGeneration, CompleteUpload, CopyGeneration, DueRow, EvictCandidate, ExtentId,
    ExtentPlacement, ExtentRow, FailClass, GcRow, GcStep, GenerationId, GenerationRow, HotStats,
    IntentFence, IntentStats, Job, JobExtent, KekBytes, ListEntry, ListPage, ListQuery,
    ObjectStatus, OpenUpload, OutboxStage, OutboxStats, PartExtent, Perm, Precondition,
    ProviderConfig, ProviderFault, ProviderLoad, Resend, SafetyState, SizeCommand, UnixMs,
    UploadId, UploadListQuery, UploadPartRow, UploadRow, UploadState, VerificationRow,
    VerifyEscalation, WriteId,
};
use crate::types::{
    BucketUsage, RecountState, RecountStep, UsageCounters, UsageRecount, UsageSnapshot,
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
/// and [`MAX_SQL_VALUE_BYTES`] per bound value (more is an error), and `exec`/`batch` run every statement to
/// completion, so `RETURNING` and `SELECT` statements are accepted (their
/// rows are discarded; a `SELECT` changes 0 rows).
pub trait Sql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>>;
    /// Returns the number of rows changed.
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64>;
    /// Atomic. Returns rows changed per statement.
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>>;
    /// [`Self::query`] for a read that is asked right after a batch was
    /// refused: the read that finds out which guard refused it.
    ///
    /// A database may charge a refused batch in full and answer the
    /// statements after a large one with an error for some seconds (D1
    /// does: "D1 DB is overloaded", measured at 65,536 extents). An
    /// adapter for such a database waits and asks again here, a bounded
    /// number of times. A read is repeated safely; no write goes this
    /// way. The default asks once.
    async fn query_after_refusal(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.query(sql, params).await
    }
    /// What one statement may carry on this database. An adapter for a
    /// database with other limits says so here; catalogue code never
    /// writes such a figure down itself.
    fn limits(&self) -> SqlLimits {
        SqlLimits::D1
    }
}

// The limits of the database behind [`Sql`] live here and nowhere else:
// [`MAX_SQL_PARAMS`], [`MAX_SQL_VALUE_BYTES`], [`MAX_SQL_INT`] and
// [`SqlLimits`]. They are
// D1's. The statements themselves are plain SQLite and run unchanged on
// any SQLite behind the port.

/// D1's bound-parameter limit per statement.
pub const MAX_SQL_PARAMS: usize = 100;

/// D1's limit on one bound text or blob value, in bytes. More is an error.
pub const MAX_SQL_VALUE_BYTES: usize = 2_000_000;

/// The largest integer D1 takes or returns, and the negative of the
/// smallest: a value crosses to D1 as a JS number, which is exact up to
/// `Number.MAX_SAFE_INTEGER` only. A bound integer outside
/// `-MAX_SQL_INT..=MAX_SQL_INT` is an error, before the statement runs.
pub const MAX_SQL_INT: i64 = (1 << 53) - 1;

/// How much a set-based statement may carry: one that takes its rows from
/// a single JSON parameter (the publish of a generation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlLimits {
    /// Largest bound value such a statement is built with, in bytes.
    pub value_bytes: usize,
    /// Most rows one such value describes.
    pub set_rows: usize,
    /// Most bytes of stored values (the packed plans of extents) one
    /// query is asked to return. A row count does not bound them: a plan
    /// grows with the articles of its extent.
    pub result_bytes: usize,
}

impl SqlLimits {
    /// D1. 25,000 rows a value is what a publish of 65,536 extents was
    /// measured with there, in values of up to 1.3 MB. The byte limit is
    /// not from that measurement: it is D1's documented limit of a bound
    /// value ([`MAX_SQL_VALUE_BYTES`]) less a margin, and no value of
    /// 25,000 placements comes near it. Nor are the 8 MiB of a result:
    /// they are far below what D1 returns for one query, and far above
    /// the plan of one extent.
    pub const D1: SqlLimits = SqlLimits {
        value_bytes: 1_900_000,
        set_rows: 25_000,
        result_bytes: 8 * 1024 * 1024,
    };
}

// A value the publish builds is one D1 takes.
const _: () = assert!(SqlLimits::D1.value_bytes < MAX_SQL_VALUE_BYTES);

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
    /// Up to `limit` directories directly below `prefix` (which ends with
    /// `/`) that sort after `start_after`, in key order, each as
    /// `prefix` + its name + `/`: the common prefixes of a listing with
    /// the delimiter `/`. Keys directly at `prefix` + a name with no `/`
    /// are no directory. Fewer than `limit` = no more.
    ///
    /// This default lists one key per directory, starting after each
    /// directory it found; an adapter whose listing takes a delimiter
    /// overrides it (one request per 1,000 directories).
    async fn list_dirs(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        let mut dirs: Vec<String> = Vec::new();
        let mut after = start_after.to_string();
        while dirs.len() < limit as usize {
            let Some(key) = self.list(prefix, &after, 1).await?.pop() else {
                break;
            };
            let rest = key.strip_prefix(prefix).unwrap_or_default();
            match rest.split_once('/') {
                Some((name, _)) => {
                    let dir = format!("{prefix}{name}/");
                    after = past_dir(&dir);
                    if dir.as_str() > start_after {
                        dirs.push(dir);
                    }
                }
                None => after = key,
            }
        }
        Ok(dirs)
    }
}

/// A key that sorts after every key below `dir` (which ends with `/`)
/// and before the next directory beside it: `/` is followed by `0`.
pub fn past_dir(dir: &str) -> String {
    match dir.strip_suffix('/') {
        Some(stem) => format!("{stem}0"),
        None => dir.to_string(),
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

/// Result of one size command ([`NntpSession::size`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeOutcome {
    /// `430`; the session stays usable.
    Missing,
    /// The provider has the article. `Some` = the size in bytes it
    /// reported for it; `None` = it reported none (the command is not
    /// supported, or the article has no such header), so nothing more
    /// than a `STAT` is known.
    Present(Option<u64>),
    /// The provider has the article, and its answer carries a size that
    /// is not the provider's own count: a header written where the
    /// article was first received, which travels with it. It says what
    /// arrived there, not what this provider stores.
    Carried(u64),
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
    /// Asks whether the article is there and for the size the provider
    /// reports for it, with `how`. A session that has no such command
    /// asks with `STAT`: present, size unknown.
    async fn size(&mut self, message_id: &str, how: SizeCommand) -> Result<SizeOutcome> {
        let _ = how;
        Ok(match self.stat(message_id).await? {
            true => SizeOutcome::Present(None),
            false => SizeOutcome::Missing,
        })
    }
    /// The answers of [`stat`](Self::stat) (`how` is `None`: present
    /// without a size, or missing) or of [`size`](Self::size) for each
    /// of `message_ids`, in that order. A session may write the commands
    /// ahead of their replies; the answers are the same as one by one.
    /// It is one call: no more than [`ASK_MANY`] articles. After an
    /// `Err` no answer counts and the session is dropped.
    async fn ask_many(
        &mut self,
        message_ids: &[&str],
        how: Option<SizeCommand>,
    ) -> Result<Vec<SizeOutcome>> {
        let mut out = Vec::with_capacity(message_ids.len());
        for id in message_ids {
            out.push(match how {
                Some(how) => self.size(id, how).await?,
                None => match self.stat(id).await? {
                    true => SizeOutcome::Present(None),
                    false => SizeOutcome::Missing,
                },
            });
        }
        Ok(out)
    }
    /// One `body_to`; appends to `out`.
    async fn body(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome>;
    async fn quit(self);
}

/// Most articles in one [`NntpSession::ask_many`]: the articles of a
/// whole extent of the largest size, so its check is one call per
/// provider. A size command writes all of them ahead of their replies;
/// `STAT` writes them in the client's groups (16 at a time), so a full
/// call of `STAT` is two round trips. The commands of that many are a
/// few kilobytes, the answers (a header block each at most) well under
/// a megabyte.
pub const ASK_MANY: usize = 32;

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
    /// Dispatcher only: the oldest message that still waits in the
    /// queues of each kind. Never an error: what is not known is
    /// [`Oldest::Unknown`], which is also the answer of a sink that
    /// cannot tell. It sends nothing.
    async fn backlog(&self) -> Backlog {
        Backlog::default()
    }
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

/// The keys of one managed tenant that the recovery copy proves its
/// `VMR2` records with (AM-80 item 2, AM-80b), read from the tenant's
/// own records in R2 and never from a catalogue.
///
/// **Its contract:** every version that the verified head of the tenant
/// chain names, committed (`key_checks`) or claimed (`rotating_to`), and
/// that no record marks destroyed. It may be **partial**: a named version
/// whose blob did not load is missing from it, and the others still serve
/// ([`CopyRing::named`] without [`CopyRing::key`]).
pub struct CopyRing {
    tenant: crate::crypto::scheme2::TenantId,
    keys: std::collections::BTreeMap<u32, std::rc::Rc<crate::crypto::scheme2::TenantKey>>,
    named: std::collections::BTreeSet<u32>,
    destroyed: std::collections::BTreeSet<u32>,
}

impl CopyRing {
    /// `keys`: the versions that loaded, each a key of `tenant` and of a
    /// version in `named`. `named`: every committed or claimed version.
    /// `destroyed`: the versions a record of the chain marks destroyed;
    /// none of them is named or has a key.
    pub fn new(
        tenant: crate::crypto::scheme2::TenantId,
        keys: Vec<std::rc::Rc<crate::crypto::scheme2::TenantKey>>,
        named: std::collections::BTreeSet<u32>,
        destroyed: std::collections::BTreeSet<u32>,
    ) -> Result<CopyRing> {
        const ERR_RING: crate::types::BridgeError =
            crate::types::BridgeError::Crypto("copy ring: a key of another tenant or version");
        let mut by_version = std::collections::BTreeMap::new();
        for key in keys {
            let version = key.version();
            if key.tenant() != &tenant
                || !named.contains(&version)
                || by_version.insert(version, key).is_some()
            {
                return Err(ERR_RING);
            }
        }
        if destroyed.iter().any(|v| named.contains(v)) {
            return Err(ERR_RING);
        }
        Ok(CopyRing {
            tenant,
            keys: by_version,
            named,
            destroyed,
        })
    }

    pub fn tenant(&self) -> &crate::crypto::scheme2::TenantId {
        &self.tenant
    }

    /// The key of `version`, when it loaded.
    pub fn key(&self, version: u32) -> Option<&crate::crypto::scheme2::TenantKey> {
        self.keys.get(&version).map(|k| &**k)
    }

    /// Whether the chain names `version`, committed or claimed.
    pub fn named(&self, version: u32) -> bool {
        self.named.contains(&version)
    }

    /// Whether a record of the chain marks `version` destroyed.
    pub fn destroyed(&self, version: u32) -> bool {
        self.destroyed.contains(&version)
    }

    /// Whether a named version did not load.
    pub fn partial(&self) -> bool {
        self.named.len() > self.keys.len()
    }
}

/// What [`TenantRings::ring`] answers for one managed tenant.
#[derive(Clone)]
pub enum TenantRingState {
    /// Its ring, maybe partial.
    Ring(std::rc::Rc<CopyRing>),
    /// The head is `shredding` or `shredded`: its keys are destroyed, or
    /// about to be. Applies to `VMR2` records only.
    Shredded,
    /// The head names no key version yet (or the tenant has no chain).
    NoKeyYet,
}

/// The port of the recovery copy's tenant keys (AM-80 item 2): the
/// Worker implements it from the root's parts (`root::RootRings`). Each
/// call loads again; [`crate::recovery::check::JobRings`] keeps one answer
/// per job and tenant.
///
/// `Err`: the ring could not be read now (the head, the key locations or
/// the current version failed for a store or KEK error). The record then
/// counts `failed`, never `source_unreadable`.
pub trait TenantRings {
    async fn ring(&self, tenant: &crate::crypto::scheme2::TenantId) -> Result<TenantRingState>;
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// The time the claim was made with, read before its round trip:
    /// the row is held for [`LEASE_SECS`] from it, as after a renewal
    /// at that time.
    pub claimed_at: UnixMs,
}

impl Lease {
    /// Whether the claim itself still stands for a renewal: it is less
    /// than the renewal interval old at `now`, so the row is held for as
    /// long from here as a renewal that old would hold it. A job that
    /// starts its work right after its claim does not write the same
    /// expiry a second time.
    ///
    /// The claim says the row was this job's at `claimed_at`, and no
    /// other job can claim it before the lease expires. A row that was
    /// moved without a claim meanwhile (a cancelled posting) is found by
    /// the next renewal, at most one renewal interval later, as it is
    /// between any two renewals; every write of the job is fenced by
    /// the token whatever its renewals say.
    pub fn fresh_at(&self, now: UnixMs) -> bool {
        (0..crate::post::KEEP_EVERY_MS).contains(&(now.0 - self.claimed_at.0))
    }
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
    /// Work done inside a request: a cold read, and a drill on a
    /// provider without drill connections.
    Read,
    /// A drill (`POST /_admin/drill`) on a provider with
    /// [`ProviderConfig::drill_conns`]: a slot from that range, which is
    /// apart from `max_conns`. It runs inside a request, with the
    /// lifetime and the call bounds of [`PermitClass::Read`].
    Drill,
}

impl PermitClass {
    /// How long a permit of this class holds its slot after an acquire
    /// or a renewal.
    pub const fn permit_secs(self) -> u32 {
        match self {
            PermitClass::Background => PERMIT_SECS,
            PermitClass::Read | PermitClass::Drill => READ_PERMIT_SECS,
        }
    }

    /// The longest one `connect`, `post`, `stat` or `body` may take
    /// under a permit of this class.
    pub const fn call_secs(self) -> u32 {
        match self {
            PermitClass::Background => NNTP_CALL_SECS,
            PermitClass::Read | PermitClass::Drill => READ_CALL_SECS,
        }
    }

    /// The longest a renewal may take for the permit to be counted on
    /// afterwards. `None`: not bounded. A background permit outlasts
    /// one call by [`PERMIT_SECS`] - [`NNTP_CALL_SECS`], and that margin
    /// is what covers a slow renewal of a job.
    pub const fn renew_secs(self) -> Option<u32> {
        match self {
            PermitClass::Background => None,
            PermitClass::Read | PermitClass::Drill => Some(READ_RENEW_SECS),
        }
    }
}

/// Outcome of a guarded batch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Guard<T> {
    Applied(T),
    /// The guard failed; the batch wrote nothing.
    Lost,
}

/// Outcome of [`Catalog::put_grant_if_present`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantPut {
    /// The grant is stored (inserted, or replaced by an equal or wider one).
    Applied,
    /// Nothing was written: the key has `rw` on the bucket and `ro` was
    /// asked for.
    Narrowing,
    /// Nothing was written: the key or the bucket does not exist.
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
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// Sets the key's permission on the bucket in one statement that
    /// writes only while both the key row and the bucket row exist, and
    /// never narrows a grant: an `rw` grant is not replaced by `ro`.
    /// Revocation and bucket deletion each remove their row and its
    /// grants in one batch, so a grant stored through this is never left
    /// behind by either, whichever commits first.
    async fn put_grant_if_present(
        &self,
        akid: &str,
        bucket: &BucketId,
        perm: Perm,
    ) -> Result<GrantPut>;
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
    /// `Some(scope)`: this catalogue serves the S3 requests of the managed
    /// tenant of `scope` on its unit (tenancy ADR §2.7, AM-64).
    /// `authenticate` then checks the signature before any read but
    /// [`Self::access_key`] (whose secret is a scheme-2 wrap bound to the
    /// tenant), calls [`Self::signature_verified`], and only then reads
    /// the bucket and the grant; the handlers name the tenant's blobs
    /// through the scope; a bucket delete over S3 is refused. Tenant 0's
    /// catalogue: `None`, and nothing changes.
    fn request_scope(&self) -> Option<&crate::tenant::TenantScope> {
        None
    }
    /// The data key of `bucket` when this catalogue's buckets are wrapped
    /// under another key than the KEK: a managed tenant's under its
    /// tenant key (scheme 2; the row's `kek_version` is the tenant key
    /// version). `None`: the KEK's wrap, tenant 0's
    /// ([`crate::crypto::unwrap_bdk`]).
    async fn bucket_key(&self, bucket: &Bucket) -> Option<Result<crate::crypto::DataKey>> {
        let _ = bucket;
        None
    }
    /// The key ring that seals this catalogue's recovery records when they
    /// are a managed tenant's (VMR2 under the current tenant key, ADR
    /// §3.2). `None`: the KEK seals them (tenant 0).
    async fn record_ring(&self) -> Option<Result<std::rc::Rc<crate::keys::tk::LoadedRing>>> {
        None
    }
    /// Called once by `authenticate`, after the signature verified and
    /// before any other read (AM-64): every call after it is
    /// authenticated. `read`: the request is a GET or a HEAD. An `Err` is
    /// the request's answer, `403 AccountProblem`: the tenant's state
    /// refuses it. Tenant 0's catalogue: nothing to do.
    async fn signature_verified(&self, read: bool) -> Result<()> {
        let _ = read;
        Ok(())
    }
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
    /// The live generation of the key without its extents: all a HEAD
    /// needs, and what a GET plans from before it reads
    /// [`Self::extents_in`] for the bytes it serves.
    async fn live_generation(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationRow>>;
    /// The generation with this id in this bucket, whatever its state,
    /// with the bucket row. A read that was planned against a generation
    /// is finished against the same one.
    async fn generation_by_id(
        &self,
        bucket: &BucketId,
        generation: &GenerationId,
    ) -> Result<Option<(Bucket, GenerationRow)>>;
    /// The extents of the generation that hold plaintext
    /// `[start, end)`, in order and placed as the generation has them:
    /// from the one that contains `start` to the last that begins before
    /// `end`. The caller checks that they tile the range.
    async fn extents_in(
        &self,
        generation: &GenerationId,
        start: u64,
        end: u64,
    ) -> Result<Vec<ExtentRow>>;
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
    ///
    /// The posting obligations (outbox rows) of every publication, this
    /// one, [`Self::commit_sliced`] and [`Self::complete_upload`], are
    /// inserted marked as sent at the commit's `now`: the caller sends
    /// the post job of each extent right after an `Applied`, and takes
    /// the mark back with [`Self::unmark_sent`] where that send failed.
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
    /// The rows a listing page has to see, in key order, at most
    /// `q.max_keys` of them: the keys of the range `q` describes (as
    /// [`Self::list`] reads `prefix`, `after` and `skip_prefix`), except
    /// that after a key that holds `q.delimiter` past the prefix, the
    /// other keys of its group (those that start with that key up to and
    /// including the delimiter) may be left out. The caller folds: it
    /// gets the first key of every group and never needs the rest. Fewer
    /// than `q.max_keys` rows means the range is exhausted.
    ///
    /// One call reads one batch: `q.max_keys` above 1,001 (a full S3
    /// page of 1,000 plus the one row that shows whether it is
    /// truncated) is refused with `Invalid`. A caller that wants more
    /// rows pages, as both listing versions do.
    async fn list_heads(&self, bucket: &BucketId, q: &ListQuery) -> Result<Vec<ListEntry>>;
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
    /// The upload's state alone, without its parts: one key lookup.
    async fn upload_state(&self, t: &UploadTarget<'_>) -> Result<Option<UploadState>>;
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
    /// Stores a part whose body was stored as the slices of `write`:
    /// `extents` in body order, the first of them `part.extent_id`. The
    /// intents of the write go in the same batch. `Lost` when the upload
    /// is not open, or the intents are no longer this write's (the sweep
    /// took them, or a replay began).
    async fn put_upload_part_sliced(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extents: &[ExtentRow],
        write: &WriteId,
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
    /// The extent rows of the upload's current parts, ordered by part
    /// number and, within a part, in body order; at most `limit` of them.
    async fn upload_extents(&self, t: &UploadTarget<'_>, limit: u32) -> Result<Vec<PartExtent>>;
    /// How many extents the upload holds under part numbers other than
    /// `except`. A count without a guard: Complete decides for real.
    async fn upload_extents_held(&self, upload: &UploadId, except: u16) -> Result<u64>;
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
    /// Moves the row to stage `to`, due at `next_at`, and frees the
    /// lease. The new stage starts at its first step: attempts and
    /// cursor are 0 again.
    ///
    /// The caller sends the job of a stage that has work (`post`,
    /// `verify`, `release`) itself, right after this call: the same
    /// write marks the row as sent for `next_at`, so the dispatcher does
    /// not send a second job while that one is on its way
    /// ([`Self::due`]). If the send fails, the caller takes the mark
    /// back with [`Self::unmark_sent`] and `next_at`. A job that never
    /// arrives although its send was answered is sent again by the
    /// dispatcher once the mark has aged (`Resend`), counted from
    /// `next_at`. A row moved to an end stage keeps no mark.
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
    /// [`Self::set_cursor`] and [`Self::defer`] as one fenced write: the
    /// row is not written twice for one step of progress.
    async fn defer_at(&self, l: &Lease, cursor: u32, next_at: UnixMs, now: UnixMs) -> Result<bool> {
        Ok(self.set_cursor(l, cursor, now).await? && self.defer(l, next_at, now).await?)
    }
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
    /// [`Catalog::plan_articles`] for a packed plan ([`crate::plan`]):
    /// stored as one value on the extent's row unless the extent already
    /// has a plan. `cipher_size` is the extent's. Returns the STORED plan
    /// (`None` = fenced).
    ///
    /// `parity` is the parity addendum of the plan ([`crate::parity`]),
    /// stored in the same write as the plan or not at all: the plan that
    /// was stored first keeps the addendum it was stored with, or none.
    async fn plan_packed(
        &self,
        l: &Lease,
        cipher_size: u64,
        plan: &[u8],
        parity: Option<&[u8]>,
    ) -> Result<Option<StoredPlan>>;
    /// The plan of the extent, in `idx` order: its packed plan when it
    /// has one, else its rows. A packed plan is posted as a whole, so
    /// its articles all have the state and the stamps of their extent.
    /// The data articles only: the parity articles of a plan are in its
    /// addendum ([`StoredPlan::parity_plan`]).
    async fn articles(&self, extent: &ExtentId) -> Result<Vec<ArticleRow>>;
    /// [`Catalog::articles`], with the packed form when the plan is
    /// stored packed, and the parity addendum beside it as it is stored.
    async fn stored_plan(&self, extent: &ExtentId) -> Result<StoredPlan> {
        Ok(StoredPlan {
            rows: self.articles(extent).await?,
            packed: None,
            parity: None,
        })
    }
    /// Marks one article row posted. A packed plan has no row to mark
    /// and is posted only as a whole ([`Catalog::mark_posted_many`]):
    /// on one, nothing is written and the answer is `false`.
    async fn mark_posted(&self, l: &Lease, idx: u32, provider: &str, now: UnixMs) -> Result<bool>;
    /// Marks several articles posted in one atomic write; each entry is
    /// `(idx, provider)`. `false` = fenced, and then nothing was written.
    /// A packed plan is marked only as a whole: by a call that lists
    /// every one of its articles, the parity articles of its addendum
    /// (`idx` from the number of data articles on) included. A call
    /// that lists fewer writes
    /// nothing and is an error: `false` is a lost lease and nothing
    /// else.
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
    /// The permits are those of a lease's job: none of
    /// [`PermitClass::Drill`], which no lease holds and which is renewed
    /// by [`Self::renew_permit`] alone.
    async fn renew_all(
        &self,
        l: &Lease,
        permits: &[Permit],
        now: UnixMs,
    ) -> Result<(bool, Vec<bool>)>;
    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool>;
    /// Latest row per backbone for the current `plan_rev`, with `counts`.
    async fn backbone_status(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>>;
    /// The last full read per backbone: its latest `body` row for the
    /// current `plan_rev`, pass or failure. `counts` is true where it is
    /// the full check on record: a complete pass that no later check of
    /// that backbone has cancelled (a later `stat` pass does not hide
    /// it). A row that is not a complete pass means the backbone holds
    /// no copy until it is read in full again. A plan that changed (a
    /// new `plan_rev`) has no rows until it is read again.
    async fn body_checks(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>>;
    /// `counting` = the labels of the backbones that count toward a
    /// release. The guard is the release rule: `required` of those
    /// backbones with a complete pass recorded under this claim (a
    /// `stat` pass is enough, but none counts on a backbone whose last
    /// full read failed), and at least one of these also has the full
    /// check on record ([`Catalog::body_checks`]).
    async fn begin_release(
        &self,
        l: &Lease,
        required: u32,
        counting: &[String],
        evidence_json: &str,
        now: UnixMs,
    ) -> Result<Guard<()>>;
    /// [`Catalog::begin_release`] under the light check
    /// (`VERIFY_MODE=light`). `required` backbones with a complete pass
    /// under this claim are needed, and none counts on a backbone whose
    /// last check of the bytes failed. With `need_full` false (an extent
    /// outside the sample) the full check on record is not asked for.
    ///
    /// The guard reads the escalations itself
    /// ([`Catalog::verify_escalations`] at the time the extent was
    /// stored), so one raised while the job asked the providers holds:
    /// a backbone under full reads counts only with its own full check
    /// on record, and with any counting backbone under full reads the
    /// full check is asked for whatever `need_full` says.
    async fn begin_release_light(
        &self,
        l: &Lease,
        required: u32,
        counting: &[String],
        evidence_json: &str,
        now: UnixMs,
        need_full: bool,
    ) -> Result<Guard<()>>;
    /// Notes that a full read of a sampled extent failed on `backbone`:
    /// until `until` every extent is read in full there. An earlier end
    /// never replaces a later one. An extent raises a backbone once for
    /// a plan (`plan_rev`): that it did is stored with the escalation,
    /// both or neither, and a second call for the same three changes
    /// nothing.
    async fn escalate_verify(&self, e: &VerifyEscalation, plan_rev: u32) -> Result<()>;
    /// Whether `extent` has raised `backbone` for `plan_rev`
    /// ([`Catalog::escalate_verify`]).
    async fn verify_raised(&self, extent: &ExtentId, backbone: &str, plan_rev: u32)
        -> Result<bool>;
    /// The escalations that have not ended at `at`
    /// ([`Catalog::escalate_verify`]). An extent is read in full on the
    /// backbones of those that had not ended when it was stored (`at` =
    /// its `created_at`), whenever its job runs.
    async fn verify_escalations(&self, at: UnixMs) -> Result<Vec<VerifyEscalation>>;
    async fn finish_release(&self, l: &Lease, now: UnixMs) -> Result<bool>;
    /// Up to `limit` rows in `post`, `verify` or `release` that are due
    /// and held by no job, oldest due time first. Each stage has a third
    /// of `limit` to itself, so these are not always the oldest `limit`
    /// rows of all stages: a stage with fewer due rows than its share
    /// gets all of them listed. A row marked by
    /// [`Self::mark_sent`] is left out until the seconds `resend` has
    /// for its stage after the mark, unless a job claimed it since (a
    /// claim clears the mark) or it was given a due time later than the
    /// mark.
    async fn due(&self, now: UnixMs, resend: Resend, limit: u32) -> Result<Vec<DueRow>>;
    /// The dispatcher has sent a job for each of `extents`: marks the
    /// ones that are still due and held by no job, and returns how many.
    /// The mark is a hint for [`Self::due`] alone; it gates no claim.
    async fn mark_sent(&self, extents: &[ExtentId], now: UnixMs) -> Result<u64>;
    /// `jobs`, each for an outbox row, were not sent: takes
    /// back the mark `mark` their rows were given by
    /// [`Self::advance`] (its `next_at`) or by the publication that
    /// inserted them (its `now`), and returns how many rows had it. A
    /// row that a job claimed since, or that was marked again, is left
    /// as it is. The next dispatcher run sends a row without a mark.
    async fn unmark_sent(&self, jobs: &[Job], mark: UnixMs) -> Result<u64>;
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

    // orphaned upload parts (`GC_ORPHANS`)
    /// False while the scan for orphaned parts rests after a full pass:
    /// the dispatcher sends no job for it.
    async fn gc_orphans_due(&self, now: UnixMs) -> Result<bool>;
    /// Reads the next `scan` open `gc` rows due at or before `cutoff`
    /// and moves the scan past them. Returns the `delete_safety` rows
    /// among them whose extent is an orphaned upload part, at most
    /// `limit` (the scan then stops at the last one returned).
    async fn gc_orphans(
        &self,
        now: UnixMs,
        cutoff: UnixMs,
        scan: u32,
        limit: u32,
    ) -> Result<Vec<GcRow>>;
    /// Records that the safety copies of the rows' extents are gone,
    /// each in one batch with the proof that it may go: the row is open
    /// and was due at or before `cutoff`, the extent is still an
    /// orphaned upload part, no replay or rollback is being handled,
    /// and none ended after `cutoff`. One answer per row, in order;
    /// `false`: nothing was written for it and its blob must stay.
    /// The second value is the first error that left rows undecided
    /// (answered `false`): every answer stands all the same, and the
    /// blobs they grant must go.
    async fn gc_orphan_claim(
        &self,
        rows: &[GcRow],
        now: UnixMs,
        cutoff: UnixMs,
    ) -> (Vec<bool>, Result<()>);
    /// Closes the row after the blob delete that a claim allowed. A row
    /// whose extent the catalogue does not say is deleted stays open.
    async fn gc_orphan_done(&self, id: i64, now: UnixMs) -> Result<()>;

    // recovery replay (DESIGN §A.8); every call is idempotent
    /// Where a manifest's generation stands in this catalogue.
    async fn replay_probe(&self, g: &GenerationRow) -> Result<ReplayProbe>;
    /// Makes the bucket, the extents (new ones staged, without a
    /// generation) and their article plans exist, and records a pinned
    /// copy that is gone.
    ///
    /// A plan the catalogue has is kept as long as it can be read. A
    /// packed plan that cannot gives way to the plan of the extent's
    /// record; the extents returned are those whose record has none to
    /// give, so that their plan stays unreadable.
    async fn replay_extents(
        &self,
        bucket: &Bucket,
        extents: &[ReplayExtent],
        now: UnixMs,
    ) -> Result<Vec<ExtentId>>;
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
    /// The id of the live generation of the key of `g`, if it is the
    /// same object: the same size and ETag, and exactly these extents at
    /// these places. No extent row is loaded.
    async fn replay_twin(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
    ) -> Result<Option<GenerationId>>;

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
    /// The holder of `p` is gone without releasing it: whatever is
    /// kept open for it on this side is dropped, with nothing awaited.
    /// The slot itself frees when its permit expires, or sooner.
    fn forget_permit(&self, _p: &Permit) {}

    // provider pool
    /// Held slots, slots ever handed out and health, per provider that
    /// has a permit or a health row.
    async fn provider_load(&self, now: UnixMs) -> Result<Vec<ProviderLoad>>;
    /// [`Self::provider_load`] for the operator's status: what is held
    /// at this moment, where `provider_load` may go by what its caller
    /// last heard.
    async fn provider_status(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        self.provider_load(now).await
    }
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
    /// The providers due for a probe session ([`crate::probe`]): a
    /// strike or a cooldown on record, not cooling at `now`, and neither
    /// a strike nor the end of a cooldown after `quiet_since`; when the
    /// last strike was a refused login, no strike after
    /// `login_quiet_since`.
    async fn providers_to_probe(
        &self,
        now: UnixMs,
        quiet_since: UnixMs,
        login_quiet_since: UnixMs,
    ) -> Result<Vec<String>>;
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
    /// Packs plans that are still rows in `articles`: looks at the next
    /// `limit` extents with article rows, in a rotation over all of
    /// them, and for each whose articles are all posted stores the
    /// packed plan on the extent's row and deletes its rows, in one
    /// atomic write. A plan that is not posted in full stays rows: a
    /// packed plan is posted as a whole.
    async fn pack_plans(&self, limit: u32) -> Result<PackReport>;

    // usage counters
    /// The catalogue-wide counters: one row read.
    async fn usage_counters(&self) -> Result<UsageCounters>;
    /// The counters, the oldest waiting row of each stage, the last
    /// `hours` completed hours that had an event and the state of the recount. No read
    /// here grows with the tables.
    async fn usage_snapshot(&self, hours: u32) -> Result<UsageSnapshot>;
    /// Live objects per bucket, in bucket-id order after `after`, and
    /// whether the counters were on when the page was read: the figures
    /// of counters that are off are stale.
    async fn usage_buckets(&self, after: &str, limit: u32) -> Result<(bool, Vec<BucketUsage>)>;
    /// Starts a recount of the counters from the tables. `false` when
    /// one is running and `restart` is not set. The first recount
    /// switches the counters on; a later one replaces them only with
    /// `adopt`, and records what differed either way.
    async fn usage_recount_start(
        &self,
        now: UnixMs,
        adopt: bool,
        restart: bool,
        only_on: bool,
    ) -> Result<bool>;
    /// One bounded step of the running recount: at most `chunk` table
    /// rows, or its end.
    async fn usage_recount_step(&self, chunk: u32, now: UnixMs) -> Result<RecountStep>;
    /// The recount under way and the last one that ended.
    async fn usage_recounts(&self) -> Result<(RecountState, Option<UsageRecount>)>;
    /// Switches the counters off: their triggers write nothing again.
    async fn usage_off(&self) -> Result<()>;

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
