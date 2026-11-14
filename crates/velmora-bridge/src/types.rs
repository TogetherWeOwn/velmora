//! Contract types shared by every bridge lane (frozen with the contract).
//!
//! Conventions:
//! - Every stored or compared time is [`UnixMs`]. [`UnixSecs`] exists only at
//!   protocol edges (SigV4, `Last-Modified`, NNTP dates). No bare `i64`
//!   timestamp crosses a port.
//! - Enums that mirror a D1 `CHECK (… IN (…))` column carry the exact
//!   column strings (`as_str` / `parse` / `ALL`); `tests/contract.rs` checks
//!   them against `migrations/0001_init.sql`.
//! - Nothing here holds plaintext secrets in `Debug` output.

use core::fmt;

use futures_util::stream::LocalBoxStream;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Result type of every port and service call.
pub type Result<T> = core::result::Result<T, BridgeError>;

/// Every failure a port or the service core reports. Messages are classes
/// or SQL text only: never request secrets, key material or provider reply
/// text with credentials.
#[derive(Debug)]
#[non_exhaustive]
pub enum BridgeError {
    /// The `tx_guard` CHECK of a guarded batch fired; the batch wrote
    /// nothing (`Catalog` maps this to [`crate::ports::Guard::Lost`]).
    GuardFailed,
    /// A stub that a later lane implements.
    NotImplemented(&'static str),
    /// Catalogue failure (statement error, constraint, decode of a row).
    Sql(String),
    /// Blob store failure (R2 or another S3-compatible store).
    Blob(String),
    /// NNTP failure from the engine. Its `Debug` redacts auth reply text.
    Nntp(velmora::Error),
    /// Queue send failure.
    Queue(String),
    /// Key wrap / unwrap / seal / open failure (class only).
    Crypto(&'static str),
    /// Invalid or missing configuration.
    Config(crate::config::ConfigError),
    /// Malformed input that is not an S3 protocol error (e.g. a bad job).
    Invalid(&'static str),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeError::GuardFailed => f.write_str("guarded batch lost its guard"),
            BridgeError::NotImplemented(what) => write!(f, "not implemented: {what}"),
            BridgeError::Sql(m) => write!(f, "sql: {m}"),
            BridgeError::Blob(m) => write!(f, "blob: {m}"),
            BridgeError::Nntp(e) => write!(f, "nntp: {e}"),
            BridgeError::Queue(m) => write!(f, "queue: {m}"),
            BridgeError::Crypto(c) => write!(f, "crypto: {c}"),
            BridgeError::Config(e) => write!(f, "config: {e}"),
            BridgeError::Invalid(c) => write!(f, "invalid: {c}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<velmora::Error> for BridgeError {
    fn from(e: velmora::Error) -> Self {
        BridgeError::Nntp(e)
    }
}

impl From<crate::config::ConfigError> for BridgeError {
    fn from(e: crate::config::ConfigError) -> Self {
        BridgeError::Config(e)
    }
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Unix time in milliseconds: the only time unit stored in D1 or passed
/// through a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixMs(pub i64);

/// Unix time in seconds: protocol edges only (SigV4, `Last-Modified`, NNTP).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixSecs(pub i64);

impl UnixMs {
    pub const ZERO: UnixMs = UnixMs(0);

    /// Whole seconds, rounded toward negative infinity (so a time just
    /// before an instant never formats as that instant).
    pub fn secs(self) -> UnixSecs {
        UnixSecs(self.0.div_euclid(1000))
    }

    /// `self + secs` seconds, saturating.
    pub fn plus_secs(self, secs: u32) -> UnixMs {
        UnixMs(self.0.saturating_add(i64::from(secs) * 1000))
    }

    /// `self + ms` milliseconds, saturating (negative moves back).
    pub fn plus_ms(self, ms: i64) -> UnixMs {
        UnixMs(self.0.saturating_add(ms))
    }
}

impl UnixSecs {
    /// The same instant in milliseconds, saturating.
    pub fn ms(self) -> UnixMs {
        UnixMs(self.0.saturating_mul(1000))
    }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
}

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps an id read from the catalogue or a job. Not validated:
            /// the catalogue is trusted and jobs only name rows.
            pub fn new(s: impl Into<String>) -> Self {
                $name(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(
    /// `b_<16 hex>`.
    BucketId
);
id_type!(
    /// `g_<13 hex ms><16 hex rand>`: sorts by creation time.
    GenerationId
);
id_type!(
    /// `x_<26 hex>`.
    ExtentId
);
id_type!(
    /// 32 hex, random. Never an authorization boundary (§A.4).
    UploadId
);

impl BucketId {
    pub fn mint(rand: [u8; 8]) -> Self {
        let mut s = String::with_capacity(18);
        s.push_str("b_");
        push_hex(&mut s, &rand);
        BucketId(s)
    }
}

impl GenerationId {
    /// `now` is clamped to `0..16^13` so the id is always 31 characters.
    pub fn mint(now: UnixMs, rand: [u8; 8]) -> Self {
        let ms = now.0.clamp(0, 0x000f_ffff_ffff_ffff);
        let mut s = format!("g_{ms:013x}");
        push_hex(&mut s, &rand);
        GenerationId(s)
    }
}

impl ExtentId {
    pub fn mint(rand: [u8; 13]) -> Self {
        let mut s = String::with_capacity(28);
        s.push_str("x_");
        push_hex(&mut s, &rand);
        ExtentId(s)
    }

    /// Key of the pinned ciphertext in `SAFETY`.
    pub fn safety_key(&self) -> String {
        format!("x/{}", self.0)
    }

    /// Key of the evictable ciphertext in `CACHE`.
    pub fn cache_key(&self) -> String {
        format!("c/{}", self.0)
    }
}

impl UploadId {
    pub fn mint(rand: [u8; 16]) -> Self {
        let mut s = String::with_capacity(32);
        push_hex(&mut s, &rand);
        UploadId(s)
    }
}

// ---------------------------------------------------------------------------
// Column enums (strings = the D1 CHECK lists)
// ---------------------------------------------------------------------------

macro_rules! db_enum {
    ($(#[$doc:meta])* $name:ident { $($variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name {
            $(#[serde(rename = $s)] $variant),+
        }

        impl $name {
            /// Every variant, in DDL order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The exact column string.
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $s),+ }
            }

            /// Parses the exact column string; anything else is `None`.
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some($name::$variant),)+ _ => None }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

db_enum!(
    /// `outbox.stage`.
    OutboxStage { Post => "post", Verify => "verify", Release => "release", Done => "done", Cancelled => "cancelled", Dead => "dead" }
);
db_enum!(
    /// `extents.safety_state`.
    SafetyState { Held => "held", Releasing => "releasing", Released => "released", Deleted => "deleted" }
);
db_enum!(
    /// `grants.perm`.
    Perm { Rw => "rw", Ro => "ro" }
);
db_enum!(
    /// `access_keys.status`.
    KeyStatus { Active => "active", Disabled => "disabled" }
);
db_enum!(
    /// `generations.state`.
    GenerationState { Live => "live", Superseded => "superseded", Deleted => "deleted" }
);
db_enum!(
    /// `extents.state`: `staged` = an upload part not yet in a generation.
    ExtentState { Staged => "staged", Committed => "committed" }
);
db_enum!(
    /// `articles.state`.
    ArticleState { Planned => "planned", Posted => "posted" }
);
db_enum!(
    /// `verifications.result`.
    VerifyResult { Ok => "ok", Missing => "missing", Corrupt => "corrupt", Error => "error" }
);
db_enum!(
    /// `uploads.state`.
    UploadState { Open => "open", Completed => "completed", Aborted => "aborted" }
);
db_enum!(
    /// `gc.action`.
    GcAction { DeleteCache => "delete_cache", DeleteSafety => "delete_safety", ShredKey => "shred_key", DropArticlesMeta => "drop_articles_meta" }
);

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// One key-encryption key (32 bytes). Zeroed on drop; `Debug` is redacted.
#[derive(Clone)]
pub struct KekBytes([u8; 32]);

impl KekBytes {
    pub fn new(bytes: [u8; 32]) -> Self {
        KekBytes(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for KekBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for KekBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KekBytes(<redacted>)")
    }
}

/// A secret string (admin token). Zeroed on drop; `Debug` is redacted.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Self {
        Secret(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

/// One entry of the `NNTP_PROVIDERS` secret (JSON array). Deserialize
/// only: credentials are never serialized back out.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub user: String,
    pub pass: String,
    /// Backbone owner. Two providers with the same string count once.
    pub backbone: String,
    pub post: bool,
    pub read: bool,
    /// Concurrent connections allowed; the number of permit slots.
    pub max_conns: u32,
    /// Source addresses the account may be connected from at once. One
    /// job or request (one Worker invocation) leaves from one address
    /// with all its connections, so this caps the jobs and requests that
    /// hold connections on the provider together, each with as many as
    /// `max_conns` leaves. `None` = no such limit: `max_conns` alone.
    #[serde(default)]
    pub max_ips: Option<u32>,
    /// Tier, `0` = tried first. Providers of one tier share the load.
    #[serde(default)]
    pub priority: u8,
    /// Days the provider keeps an article; `None` = no known limit. An
    /// article older than this is not asked of the provider.
    #[serde(default)]
    pub retention_days: Option<u32>,
    /// Accounts with the same pool name share one connection limit,
    /// `pool_max_conns` (accounts sold as a bundle may).
    #[serde(default)]
    pub pool: Option<String>,
    /// Connections all accounts of `pool` may hold together. Required on
    /// every member of a pool, with one value; refused without `pool`.
    #[serde(default)]
    pub pool_max_conns: Option<u32>,
    /// `false` = configured but never used.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

/// Milliseconds in one day.
const DAY_MS: i64 = 86_400_000;

impl ProviderConfig {
    /// Whether an article posted at `posted_at` is still inside this
    /// provider's retention at `now`. An unknown age or limit is "yes".
    pub fn retains(&self, posted_at: Option<UnixMs>, now: UnixMs) -> bool {
        match (self.retention_days, posted_at) {
            (Some(days), Some(at)) => {
                now.0.saturating_sub(at.0) <= i64::from(days).saturating_mul(DAY_MS)
            }
            _ => true,
        }
    }
}

impl ProviderConfig {
    /// Connections background jobs may hold together: one is left for a
    /// cold read when the provider allows two or more. Not on an account
    /// with one address, where a read cannot connect next to a job
    /// anyway and a connection kept back would only be lost.
    pub fn background_conns(&self) -> u32 {
        let reserve = self.max_conns >= 2 && self.max_ips != Some(1);
        self.max_conns - u32::from(reserve)
    }

    /// Addresses background jobs may use together: one is left for a
    /// cold read when the provider allows two or more. `None` = the
    /// provider has no address limit.
    pub fn background_ips(&self) -> Option<u32> {
        self.max_ips.map(|max| max - u32::from(max >= 2))
    }
}

/// One provider's connection load and health (`Catalog::provider_load`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProviderLoad {
    pub provider_id: String,
    /// Connection slots held now.
    pub held: u32,
    /// Jobs and requests that hold those slots: one source address each.
    pub holders: u32,
    /// The background jobs among `holders`.
    pub background_holders: u32,
    /// Slots ever handed out; the least-used provider wins a tie.
    pub uses: u64,
    /// Failed sessions in a row since the last good one or cooldown.
    pub failures: u32,
    /// Cooldowns in a row; each one doubles the next.
    pub cooldowns: u32,
    /// The provider is skipped until this time (`0` = not cooling).
    pub cooldown_until: UnixMs,
}

/// Redacts host and credentials: provider identity in logs is `id` and
/// `backbone` only.
impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("id", &self.id)
            .field("host", &"<redacted>")
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("user", &"<redacted>")
            .field("pass", &"<redacted>")
            .field("backbone", &self.backbone)
            .field("post", &self.post)
            .field("read", &self.read)
            .field("max_conns", &self.max_conns)
            .field("max_ips", &self.max_ips)
            .field("priority", &self.priority)
            .field("retention_days", &self.retention_days)
            .field("pool", &self.pool)
            .field("pool_max_conns", &self.pool_max_conns)
            .field("enabled", &self.enabled)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Catalogue rows
// ---------------------------------------------------------------------------

/// Half-open byte range `[start, start + len)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteSpan {
    pub start: u64,
    pub len: u64,
}

impl ByteSpan {
    /// Exclusive end, saturating.
    pub fn end(self) -> u64 {
        self.start.saturating_add(self.len)
    }
}

/// `buckets` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub id: BucketId,
    pub name: String,
    pub owner: String,
    /// `WrappedKey` (73 B) of the bucket data key.
    pub bdk_wrapped: Vec<u8>,
    pub kek_version: u32,
    pub disposable: bool,
    pub created_at: UnixMs,
}

/// `access_keys` row. `Debug` hides the wrapped secret.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessKeyRow {
    pub access_key_id: String,
    pub principal: String,
    pub secret_wrapped: Vec<u8>,
    pub kek_version: u32,
    pub status: KeyStatus,
    pub created_at: UnixMs,
}

impl fmt::Debug for AccessKeyRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessKeyRow")
            .field("access_key_id", &self.access_key_id)
            .field("principal", &self.principal)
            .field("secret_wrapped", &"<redacted>")
            .field("kek_version", &self.kek_version)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// `generations` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationRow {
    pub id: GenerationId,
    pub bucket_id: BucketId,
    pub key: String,
    pub state: GenerationState,
    /// Plaintext bytes.
    pub size: u64,
    /// Quoted S3 ETag.
    pub etag: String,
    pub checksum_json: Option<String>,
    pub content_json: String,
    pub user_meta_json: String,
    pub extent_count: u32,
    /// `Last-Modified`.
    pub created_at: UnixMs,
    pub retired_at: Option<UnixMs>,
}

/// `extents` row. `Debug` hides the wrapped file key.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtentRow {
    pub id: ExtentId,
    pub bucket_id: BucketId,
    /// `None` while the extent is only an upload part.
    pub generation_id: Option<GenerationId>,
    pub state: ExtentState,
    pub seq: Option<u32>,
    pub plain_offset: Option<u64>,
    pub plain_size: u64,
    /// `media::ciphertext_size(plain_size)`.
    pub cipher_size: u64,
    /// 48-byte `media.v1` header.
    pub media_header: Vec<u8>,
    /// `1` = `KeyMode::Random`.
    pub key_mode: u8,
    /// `None` = shredded.
    pub wrapped_file_key: Option<Vec<u8>>,
    pub plain_md5: [u8; 16],
    pub plain_sha256: [u8; 32],
    pub cipher_sha256: [u8; 32],
    pub safety_state: SafetyState,
    /// Set by `plan_articles`; a verification counts only if it matches.
    pub article_count: Option<u32>,
    pub plan_rev: u32,
    pub last_verified_at: Option<UnixMs>,
    pub release_evidence: Option<String>,
    pub released_at: Option<UnixMs>,
    pub created_at: UnixMs,
}

impl fmt::Debug for ExtentRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtentRow")
            .field("id", &self.id)
            .field("bucket_id", &self.bucket_id)
            .field("generation_id", &self.generation_id)
            .field("state", &self.state)
            .field("seq", &self.seq)
            .field("plain_offset", &self.plain_offset)
            .field("plain_size", &self.plain_size)
            .field("cipher_size", &self.cipher_size)
            .field("key_mode", &self.key_mode)
            .field(
                "wrapped_file_key",
                &self.wrapped_file_key.as_ref().map(|_| "<redacted>"),
            )
            .field("safety_state", &self.safety_state)
            .field("article_count", &self.article_count)
            .field("plan_rev", &self.plan_rev)
            .field("last_verified_at", &self.last_verified_at)
            .field("released_at", &self.released_at)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// `articles` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArticleRow {
    pub extent_id: ExtentId,
    pub idx: u32,
    /// Bare, without `<>`.
    pub message_id: String,
    pub newsgroup: String,
    /// Rendered obfuscated headers: a repost is byte-identical.
    pub headers: Vec<u8>,
    pub cipher_offset: u64,
    pub cipher_len: u64,
    /// SHA-256 of the decoded article payload.
    pub payload_sha256: [u8; 32],
    pub state: ArticleState,
    pub provider_id: Option<String>,
    pub posted_at: Option<UnixMs>,
}

/// `verifications` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationRow {
    pub extent_id: ExtentId,
    pub backbone: String,
    pub provider_id: String,
    pub verified_at: UnixMs,
    pub plan_rev: u32,
    pub articles_ok: u32,
    pub articles_total: u32,
    pub result: VerifyResult,
}

/// Latest verification per backbone for the extent's current `plan_rev`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackboneStatus {
    pub backbone: String,
    pub provider_id: String,
    pub verified_at: UnixMs,
    pub plan_rev: u32,
    pub articles_ok: u32,
    pub articles_total: u32,
    pub result: VerifyResult,
    /// `result = ok` and `articles_ok = articles_total = article_count`.
    pub counts: bool,
}

/// `uploads` row (state, revision and completion receipt).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadRow {
    pub id: UploadId,
    pub bucket_id: BucketId,
    pub key: String,
    pub content_json: String,
    pub user_meta_json: String,
    pub state: UploadState,
    pub revision: u64,
    pub completed_generation_id: Option<GenerationId>,
    /// SHA-256 of the canonical `(part_number, etag)` list.
    pub complete_digest: Option<[u8; 32]>,
    pub result_etag: Option<String>,
    pub initiated_at: UnixMs,
}

/// `upload_parts` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadPartRow {
    pub upload_id: UploadId,
    /// 1..=10000.
    pub part_number: u16,
    pub extent_id: ExtentId,
    pub size: u64,
    pub etag: String,
    pub uploaded_at: UnixMs,
}

/// `gc` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcRow {
    pub id: i64,
    pub extent_id: ExtentId,
    pub action: GcAction,
    pub due_at: UnixMs,
    pub done_at: Option<UnixMs>,
}

/// Which blob store a GC step addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobStoreKind {
    Safety,
    Cache,
}

/// What `Catalog::gc_begin` decided for one row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcStep {
    /// Delete this blob, then call `gc_done`.
    DeleteBlob { store: BlobStoreKind, key: String },
    /// A catalogue-only action was applied and the row closed.
    Done,
    /// A live generation still references the extent: nothing was done.
    Skipped,
}

/// One due outbox row (dispatcher input).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueRow {
    pub extent_id: ExtentId,
    pub generation_id: GenerationId,
    pub stage: OutboxStage,
}

/// What a queue job needs about its extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobExtent {
    pub extent: ExtentRow,
    pub bucket: Bucket,
    pub generation_state: GenerationState,
}

/// Admin view of one extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtentStatus {
    pub extent_id: ExtentId,
    pub seq: Option<u32>,
    /// `None` when the extent has no outbox row.
    pub stage: Option<OutboxStage>,
    pub attempts: u32,
    pub safety_state: SafetyState,
    /// Failure class only.
    pub last_error: Option<String>,
    pub backbones: Vec<BackboneStatus>,
}

/// Admin view of a live object (`GET /_admin/objects/<b>/<k>`). Cache
/// presence is not catalogue state; the admin handler adds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStatus {
    pub generation: GenerationRow,
    pub extents: Vec<ExtentStatus>,
}

/// Input of a single-PUT publication batch: the new generation and its
/// freshly sealed extents (inserted as `committed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitGeneration {
    pub generation: GenerationRow,
    pub extents: Vec<ExtentRow>,
    pub now: UnixMs,
}

/// Input of a copy publication batch: the new generation, and the
/// generation whose extents it references. The source must still be the
/// live object of `(generation.bucket_id, source_key)` when the batch
/// runs; `generation` repeats its size, ETag and extent count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyGeneration {
    pub generation: GenerationRow,
    pub source: GenerationId,
    pub source_key: String,
    pub now: UnixMs,
}

/// Where one staged part extent lands in the completed object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtentPlacement {
    pub extent_id: ExtentId,
    pub seq: u32,
    pub plain_offset: u64,
}

/// Input of a multipart Complete publication batch. The catalogue only
/// sets `generation_id`, `seq`, `plain_offset` and `state = 'committed'` on
/// the existing staged extents; it never rewrites their hashes, keys or
/// headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteUpload {
    pub generation: GenerationRow,
    /// In part order.
    pub placements: Vec<ExtentPlacement>,
    pub now: UnixMs,
}

/// `GET /_admin/status` catalogue figures.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OutboxStats {
    /// Row count per stage; stages with no rows are omitted.
    pub by_stage: Vec<(OutboxStage, u64)>,
    pub dead: u64,
    /// Last `Catalog::record_dispatch` (`meta.last_dispatch_at`).
    pub last_dispatch_at: Option<UnixMs>,
}

/// Hot-tier totals. Pinned bytes are safety copies that are not yet
/// released; evictable bytes are released safety copies and cache fills.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HotStats {
    pub pinned_bytes: u64,
    pub pinned_extents: u64,
    pub evictable_bytes: u64,
    pub evictable_extents: u64,
}

/// An evictable extent as the catalogue listed it. `begin_evict` refuses
/// it if anything here has changed since.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvictCandidate {
    pub extent: ExtentId,
    /// Bytes of the released safety copy still in R2.
    pub safety_bytes: u64,
    /// Bytes of the cache fill in R2.
    pub cache_bytes: u64,
    /// `extents.evict_seq` when listed.
    pub seq: u64,
    /// The safety copy was pinned when listed: only the cache fill may
    /// go, and the eviction must not touch the safety copy.
    pub pinned: bool,
}

impl EvictCandidate {
    /// Bytes an eviction of this candidate frees.
    pub fn evictable_bytes(&self) -> u64 {
        match self.pinned {
            true => self.cache_bytes,
            false => self.safety_bytes.saturating_add(self.cache_bytes),
        }
    }
}

db_enum!(
    /// Failure class stored in `outbox.last_error`. A class only: provider
    /// reply text can carry credentials and is never stored.
    FailClass {
        DupUnconfirmed => "dup-unconfirmed",
        MissingPending => "missing-pending",
        Corrupt => "corrupt",
        NntpError => "nntp-error",
        PostRefused => "post-refused",
        BlobError => "blob-error",
        CryptoError => "crypto-error",
        QueueError => "queue-error",
        Internal => "internal",
    }
);

/// ListObjectsV2 catalogue query. The service turns a prefix into the
/// `[prefix, successor(prefix))` range and folds delimiters in Rust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListQuery {
    pub prefix: String,
    pub delimiter: Option<String>,
    /// Exclusive lower bound (`start-after` or the token's `after`).
    pub after: Option<String>,
    /// Common prefix already emitted; the scan resumes at its successor.
    pub skip_prefix: Option<String>,
    pub max_keys: u32,
}

/// One listed object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListEntry {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub last_modified: UnixMs,
}

/// Where the next page starts (the service tags it into a token).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListCursor {
    pub after: String,
    pub skip_prefix: Option<String>,
}

/// One page of a listing; `next` is `Some` iff truncated.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ListPage {
    pub entries: Vec<ListEntry>,
    pub common_prefixes: Vec<String>,
    pub next: Option<ListCursor>,
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/// Current job message version.
pub const JOB_VERSION: u8 = 1;

/// Queue message: a reference only (under 200 bytes of JSON). The D1
/// `outbox` row is the durable obligation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum Job {
    Extent {
        v: u8,
        extent: ExtentId,
        generation: GenerationId,
        stage: OutboxStage,
    },
    Gc {
        v: u8,
    },
    /// Hot-tier eviction. `remaining` is the number of bytes a drain
    /// still has to evict, carried from one step to the next so that only
    /// its first step totals the evictable bytes. 0 starts a drain: the
    /// job totals them and acts only if they exceed the cap.
    Evict {
        v: u8,
        remaining: u64,
    },
}

impl Job {
    pub fn to_json(&self) -> String {
        // Serializing plain strings and integers cannot fail.
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Result<Job> {
        serde_json::from_str(s).map_err(|_| BridgeError::Invalid("job json"))
    }
}

/// What the queue consumer does with a message after `run_job`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    Ack,
    Retry { delay_secs: u32 },
}

/// Result of one cron dispatcher run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DispatchReport {
    pub enqueued: u32,
    pub gc_enqueued: bool,
    /// Evictable bytes exceeded the hot-tier cap: an eviction job was sent.
    pub evict_enqueued: bool,
    pub buried: u64,
    pub permits_seeded: bool,
    /// `done` extents with too few verified backbones sent back to verify,
    /// and cancelled postings of referenced extents re-armed.
    pub redriven: u64,
    /// The re-drive failed; the rest of the run went on without it.
    pub redrive_failed: bool,
    /// The hot-tier check failed; the rest of the run went on without it.
    pub evict_failed: bool,
}

// ---------------------------------------------------------------------------
// HTTP boundary
// ---------------------------------------------------------------------------

/// Request method as the router needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Put,
    Post,
    Delete,
    Other(String),
}

impl Method {
    pub fn parse(s: &str) -> Method {
        match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "PUT" => Method::Put,
            "POST" => Method::Post,
            "DELETE" => Method::Delete,
            other => Method::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Put => "PUT",
            Method::Post => "POST",
            Method::Delete => "DELETE",
            Method::Other(s) => s,
        }
    }
}

/// A streamed body chunk sequence. `!Send` (workers-rs streams are).
pub type ByteStream = LocalBoxStream<'static, Result<Vec<u8>>>;

/// Request body. The adapter never buffers it; only
/// `ingress::read_capped` or `ingress::read_upload` does, after auth and the
/// budget charge.
#[non_exhaustive]
pub enum Body {
    Empty,
    Stream {
        /// `Content-Length` as declared (not trusted).
        declared_len: Option<u64>,
        stream: ByteStream,
    },
}

/// One S3 or admin request as the Worker received it.
pub struct S3Request {
    pub method: Method,
    /// Origin-form target (path and query) exactly as received.
    pub raw_target: String,
    /// Header names lowercase; values untouched.
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl S3Request {
    /// First header with this (lowercase) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// `Debug` lists header names only: values may carry credentials.
impl fmt::Debug for S3Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("S3Request")
            .field("method", &self.method)
            .field("header_names", &names)
            .finish_non_exhaustive()
    }
}

/// Response body.
pub enum RespBody {
    Empty,
    Bytes(Vec<u8>),
    Stream(ByteStream),
}

/// One response.
pub struct S3Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: RespBody,
}

impl S3Response {
    /// S3 XML error document. `code` and `message` must be static text,
    /// never request data.
    pub fn error(status: u16, code: &str, message: &str) -> S3Response {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code><Message>{message}</Message></Error>"
        );
        S3Response {
            status,
            headers: vec![("content-type".to_string(), "application/xml".to_string())],
            body: RespBody::Bytes(body.into_bytes()),
        }
    }

    /// `501 NotImplemented`.
    pub fn not_implemented() -> S3Response {
        S3Response::error(
            501,
            "NotImplemented",
            "A header or operation you provided implies functionality that is not implemented.",
        )
    }
}

impl fmt::Debug for S3Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Response")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}
