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

impl BridgeError {
    /// A classified PostgreSQL overload, not a guard refusal or an unknown
    /// COMMIT outcome. Existing D1 error handling is unchanged.
    pub fn is_pg_overloaded(&self) -> bool {
        matches!(self, Self::Sql(class) if class == "pg: overloaded")
    }
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

    /// Whether a time `at` stamped by another invocation of this isolate
    /// (or by another isolate) is less than `window` ms from `self`, on
    /// either side.
    ///
    /// The invocations of one isolate each read a clock of their own,
    /// which stands still between that invocation's events, so `self`
    /// can be a few milliseconds less than an `at` written a moment
    /// before: a negative age is recent, not old. An `at` a whole
    /// `window` or more ahead is no such reading order but a clock that
    /// jumped, and counts as old, so it cannot be kept forever.
    pub fn within(self, at: UnixMs, window: i64) -> bool {
        self.0.saturating_sub(at.0).saturating_abs() < window
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
id_type!(
    /// `w_<32 hex>`, random: one request that stores its body as several
    /// slices.
    WriteId
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

impl WriteId {
    pub fn mint(rand: [u8; 16]) -> Self {
        let mut s = String::with_capacity(34);
        s.push_str("w_");
        push_hex(&mut s, &rand);
        WriteId(s)
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
    /// How a verification row checked the articles.
    ///
    /// - `Body`: every article was read and its payload hash compared.
    /// - `Sampled`: the same full read, made because the extent fell in
    ///   the sample of the light check (`VERIFY_MODE=light`) or because
    ///   its backbone is read in full for a while after a failed read.
    /// - `Stat`: the provider only said that it has the articles.
    /// - `Size`: the provider has every article and the size it stores
    ///   for each is the size of the article that was posted
    ///   ([`crate::verify::size_bounds`]).
    ///
    /// A `Stat` pass is never a check of the bytes: a provider can answer
    /// `STAT` for an article whose `BODY` it no longer serves. A `Size`
    /// pass says that the provider stores articles of the right length,
    /// not that their bytes were read.
    ///
    /// In the catalogue the `kind` column keeps its two values: `Body`
    /// and `Sampled` are `body` rows, `Stat` and `Size` are `stat` rows,
    /// and the `mode` column tells them apart
    /// ([`VerifyKind::column`], [`VerifyKind::mode_column`]). So a Worker
    /// from before the light check reads every row as what it also is.
    VerifyKind { Body => "body", Stat => "stat", Size => "size", Sampled => "sampled" }
);

impl VerifyKind {
    /// Whether every article was read and its payload hash compared.
    pub fn is_full(self) -> bool {
        matches!(self, VerifyKind::Body | VerifyKind::Sampled)
    }

    /// The value of `verifications.kind`.
    pub fn column(self) -> &'static str {
        match self.is_full() {
            true => "body",
            false => "stat",
        }
    }

    /// The value of `verifications.mode`; `None` = a row as from before
    /// the column.
    pub fn mode_column(self) -> Option<&'static str> {
        match self {
            VerifyKind::Body | VerifyKind::Stat => None,
            VerifyKind::Size => Some("size"),
            VerifyKind::Sampled => Some("sampled"),
        }
    }

    /// From the two columns. A `mode` this code does not know (a row of
    /// a later version) leaves what `kind` says, which every version
    /// wrote the same way.
    pub fn from_columns(kind: &str, mode: Option<&str>) -> Option<Self> {
        match (kind, mode) {
            ("body", Some("sampled")) => Some(VerifyKind::Sampled),
            ("body", _) => Some(VerifyKind::Body),
            ("stat", Some("size")) => Some(VerifyKind::Size),
            ("stat", _) => Some(VerifyKind::Stat),
            _ => None,
        }
    }
}

/// A backbone that is read in full for every extent for a while
/// (`verify_escalations`): a full read of a sampled extent failed there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyEscalation {
    /// The label as it is compared: trimmed, lower case.
    pub backbone: String,
    pub until: UnixMs,
    pub raised_at: UnixMs,
    /// The extent whose read failed, and how.
    pub extent_id: ExtentId,
    pub result: VerifyResult,
}

db_enum!(
    /// The command that asks a provider for the size it stores for one
    /// article, by message-id (`VERIFY_SIZE_COMMANDS`). Each one also
    /// says whether the article is there, so it replaces the `STAT`.
    ///
    /// - `Hdr`: `HDR :bytes <message-id>` (RFC 3977).
    /// - `Over`: `OVER <message-id>`, the bytes field of the overview
    ///   line, taken only if the line names the message-id asked for.
    /// - `Head`: `HEAD <message-id>` and its `Bytes:` header, or else its
    ///   `X-Received-Bytes:` header. The second one is written by the
    ///   server that took the post and travels with the article, so it
    ///   says what was posted, not what this provider stores.
    ///
    /// `XHDR` and `XOVER` are not offered: asked by message-id, one
    /// provider answered them for another article.
    SizeCommand { Hdr => "hdr", Over => "over", Head => "head" }
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

/// What [`ProviderConfig::drill_key`] adds to a provider id.
pub const DRILL_KEY_SUFFIX: &str = "/drill";

/// One entry of the `NNTP_PROVIDERS` secret (JSON array). Deserialize
/// only: credentials are never serialized back out.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub id: String,
    pub host: String,
    /// More host names of the same account, on the same `port`. With them
    /// the bridge picks one endpoint of `host` and these per isolate (see
    /// `host_select` and `hosts::HostPicker`) and falls back to the others
    /// when it cannot be reached. Empty = `host` only.
    ///
    /// Rollout: deploy a Worker that knows this field before the secret
    /// carries it; an older Worker refuses the whole secret. Rollback:
    /// take `hosts` (and `host_select`) out of the secret first.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// How the endpoint is picked when `hosts` is set.
    #[serde(default)]
    pub host_select: HostSelect,
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
    /// Connections a drill (`POST /_admin/drill`) may hold on this
    /// account beside `max_conns`: what the account allows less what
    /// `max_conns` already hands out. `0` (the default) = none: a drill
    /// then reads this provider over one connection taken from
    /// `max_conns`, as a read does.
    ///
    /// These are slots of their own ([`PermitClass::Drill`]). No read
    /// and no job ever takes one, and a drill that has them takes none
    /// of `max_conns`, so a drill of any size leaves every slot of
    /// `max_conns` to reads and jobs. They are outside `pool_max_conns`.
    ///
    /// A drill is one more invocation, so on an account with `max_ips`
    /// this needs `proxies`: the provider then sees the proxies'
    /// addresses, however many invocations there are.
    ///
    /// Rollout and rollback as for `hosts`: an older Worker refuses a
    /// secret that carries this field.
    ///
    /// [`PermitClass::Drill`]: crate::ports::PermitClass::Drill
    #[serde(default)]
    pub drill_conns: u32,
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
    /// SOCKS5 proxies every connection to this provider goes through,
    /// tried in order: the next one when one cannot be used. The
    /// provider then counts the proxy's address, not the changing
    /// address of each invocation. TLS runs from the bridge to the
    /// provider through the proxy, which relays ciphertext.
    ///
    /// With this set the provider is never connected directly: when no
    /// proxy can be used the connect fails
    /// ([`ProviderFault::ProxyFailed`]). Absent = direct connections; a
    /// list that is there and empty is refused, so that a list emptied
    /// by mistake does not turn into direct connections.
    ///
    /// The provider sees one address per proxy in use, whatever the
    /// number of invocations, and all the proxies may be in use at the
    /// same time. So `max_ips`, the number of addresses the provider
    /// allows, must be stated with this field, and a list longer than
    /// it is refused. `max_ips` goes on counting invocations, which is
    /// never the looser count.
    ///
    /// Rollout and rollback as for `hosts`: an older Worker refuses a
    /// secret that carries this field.
    #[serde(default, deserialize_with = "some_proxies")]
    pub proxies: Vec<ProxyConfig>,
    /// `false` = configured but never used.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Whether this provider's backbone counts toward the release of a
    /// safety copy. `false` for a backbone that does not keep articles
    /// long enough to be a durable copy: it is still posted to and read
    /// from, but it is never verified and never evidence. One provider
    /// that says `false` takes its whole backbone out, whatever the
    /// backbone's other providers say.
    ///
    /// The default is `true`: every provider added without the field
    /// counts. A provider on a short-retention backbone must say
    /// `"release": false`, or its copy is taken for a durable one.
    ///
    /// With fewer backbones that count than `REQUIRED_BACKBONES` the
    /// Worker keeps serving and releases nothing
    /// ([`crate::config::Config::release_paused`]).
    ///
    /// Rollout: deploy a Worker that knows this field before the secret
    /// carries it; an older Worker refuses the whole secret. Rollback:
    /// take `release` out of the secret first.
    #[serde(default = "enabled_by_default")]
    pub release: bool,
}

/// A `proxies` list as written: one entry at least.
fn some_proxies<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> core::result::Result<Vec<ProxyConfig>, D::Error> {
    let list = Vec::<ProxyConfig>::deserialize(d)?;
    if list.is_empty() {
        return Err(serde::de::Error::custom("proxies: empty list"));
    }
    Ok(list)
}

/// One SOCKS5 proxy of a provider (`proxies`), with its
/// username/password login (RFC 1929). Deserialize only. `Debug` shows
/// no field: the address of a proxy is as private as its login.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// A DNS name or a public IP address.
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyConfig(<redacted>)")
    }
}

/// How a provider with several endpoints (`host` and `hosts`) picks the
/// one it connects to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostSelect {
    /// The endpoint with the quickest TLS handshake and greeting, measured
    /// once per isolate.
    #[default]
    Fastest,
    /// The configuration order, with no measuring: `host` first, then
    /// `hosts`, the next one when one cannot be reached. For a provider
    /// whose nearest server is not its fastest one.
    Ordered,
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
    /// Every host name of the account: `host`, then `hosts`, in order.
    pub fn endpoints(&self) -> Vec<&str> {
        core::iter::once(self.host.as_str())
            .chain(self.hosts.iter().map(String::as_str))
            .collect()
    }

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

    /// The name the drill's slots are kept under in the permit table
    /// (`drill_conns`): not a provider id, so nothing that counts a
    /// provider's slots, holders or uses sees them.
    pub fn drill_key(&self) -> String {
        format!("{}{DRILL_KEY_SUFFIX}", self.id)
    }
}

/// Why a session with a provider counts as a strike. The code is all
/// that is stored and shown: never the provider's own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFault {
    /// The provider refused the connection at its greeting, before any
    /// login, and not for a connection limit: the service or the address
    /// is turned away.
    ConnectRefused,
    /// The provider refused the login, and not because the account was
    /// at a connection limit: the account is denied, suspended, out of
    /// quota, or its credentials are no longer taken.
    LoginRefused,
    /// Any other failure of a session: no connection, a broken one, a
    /// reply out of protocol.
    SessionFailed,
    /// None of the provider's proxies (`proxies`) could be used: not
    /// reached, or it refused the bridge or answered out of protocol.
    /// The provider itself was not asked, and is not connected directly.
    ProxyFailed,
}

impl ProviderFault {
    const ALL: [ProviderFault; 4] = [
        ProviderFault::ConnectRefused,
        ProviderFault::LoginRefused,
        ProviderFault::SessionFailed,
        ProviderFault::ProxyFailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ProviderFault::ConnectRefused => "connect_refused",
            ProviderFault::LoginRefused => "login_refused",
            ProviderFault::SessionFailed => "session_failed",
            ProviderFault::ProxyFailed => "proxy_failed",
        }
    }

    /// The fault a stored code names; `None` for an unknown code.
    pub fn parse(code: &str) -> Option<ProviderFault> {
        Self::ALL.into_iter().find(|f| f.as_str() == code)
    }

    /// The caller was turned away before any work: by the provider, at
    /// the greeting or at the login, or by having no proxy to reach it
    /// through. Asking again at once gets the same answer.
    pub fn is_refusal(self) -> bool {
        match self {
            ProviderFault::ConnectRefused
            | ProviderFault::LoginRefused
            | ProviderFault::ProxyFailed => true,
            ProviderFault::SessionFailed => false,
        }
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
    /// Why the last strike was one; `None` once a good session cleared
    /// the strikes.
    pub fault: Option<ProviderFault>,
}

impl ProviderLoad {
    /// No strike and no cooldown on record since the last good session.
    pub fn healthy(&self) -> bool {
        self.failures == 0 && self.cooldowns == 0
    }
}

/// Redacts host and credentials: provider identity in logs is `id` and
/// `backbone` only.
impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("id", &self.id)
            .field("host", &"<redacted>")
            .field("hosts", &self.hosts.len())
            .field("host_select", &self.host_select)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("user", &"<redacted>")
            .field("pass", &"<redacted>")
            .field("backbone", &self.backbone)
            .field("post", &self.post)
            .field("read", &self.read)
            .field("max_conns", &self.max_conns)
            .field("max_ips", &self.max_ips)
            .field("drill_conns", &self.drill_conns)
            .field("priority", &self.priority)
            .field("retention_days", &self.retention_days)
            .field("pool", &self.pool)
            .field("pool_max_conns", &self.pool_max_conns)
            .field("proxies", &self.proxies.len())
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

/// What the admin API lists of an access key: never its secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessKeySummary {
    pub access_key_id: String,
    pub status: KeyStatus,
    pub created_at: UnixMs,
    /// Bucket name and permission, by bucket name.
    pub grants: Vec<(String, Perm)>,
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
    /// The article's own random yEnc name: it is posted as one standalone
    /// single-part yEnc file. `None` is a row planned before standalone
    /// articles, posted (and reposted) in the multi-part form under a name
    /// taken from the message-id. See `post::render_article`.
    pub yenc_name: Option<String>,
    pub state: ArticleState,
    pub provider_id: Option<String>,
    /// The first post. The provider's retention counts from here.
    pub posted_at: Option<UnixMs>,
    /// The last time the article was posted again (a repost to a
    /// backbone that lacked it). `None` = never.
    pub reposted_at: Option<UnixMs>,
}

impl ArticleRow {
    /// The newest time the article was posted anywhere: the first post or
    /// a later repost. `None` = no post time is recorded.
    pub fn last_posted_at(&self) -> Option<UnixMs> {
        self.posted_at.max(self.reposted_at)
    }
}

/// Longest yEnc name an article row may carry (the catalogue's CHECK).
pub const MAX_YENC_NAME_LEN: usize = 64;

/// A stored yEnc name is 1 to [`MAX_YENC_NAME_LEN`] lowercase ASCII
/// letters and digits, as the `articles.yenc_name` CHECK requires. The
/// post stage renders only such a name, and a plan record with any other
/// is not read.
pub fn valid_yenc_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_YENC_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
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
    pub kind: VerifyKind,
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
    /// How the articles were checked. Only a `Body` pass is a full check.
    pub kind: VerifyKind,
    /// `result = ok` and `articles_ok = articles_total` = every article
    /// of the plan (`article_count`, and `parity_count` when the plan has
    /// parity articles): a complete pass of its `kind`. Whether that is enough for a
    /// release is `verify::releasable`'s decision, never this flag's.
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

/// One extent of a part of an open upload. A part body above one extent
/// is stored as several, numbered in body order from 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartExtent {
    pub part_number: u16,
    pub piece: u32,
    pub extent: ExtentRow,
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
    /// How many parity articles the extent's plan has
    /// (`extents.parity_count`). `None` = no parity.
    pub parity_count: Option<u32>,
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

/// The condition of a conditional write (`If-None-Match: *`, `If-Match`)
/// on the live object of the key it writes or deletes. A publication or
/// delete batch that carries one holds it in a guard statement of the
/// batch itself, so it is judged against the object the batch replaces
/// and not against one read earlier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Precondition {
    /// `If-None-Match: *`: the key has no live object.
    Absent,
    /// `If-Match: *`: the key has a live object.
    Exists,
    /// `If-Match: <etag>`: the key's live object has this ETag, stored
    /// form (with its quotes).
    Etag(String),
}

/// Why a [`Precondition`] does not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreconditionError {
    /// `412 PreconditionFailed`.
    Failed,
    /// `404 NoSuchKey`: `If-Match`, and the key has no live object.
    NoSuchKey,
}

impl Precondition {
    /// The condition against the ETag of the key's live object (`None` =
    /// the key has none). The guard of the batch
    /// (`sql::objects::guard_precondition`) decides the same way.
    pub fn check(&self, live_etag: Option<&str>) -> std::result::Result<(), PreconditionError> {
        match (self, live_etag) {
            (Precondition::Absent, None) | (Precondition::Exists, Some(_)) => Ok(()),
            (Precondition::Absent, Some(_)) => Err(PreconditionError::Failed),
            (Precondition::Exists | Precondition::Etag(_), None) => {
                Err(PreconditionError::NoSuchKey)
            }
            (Precondition::Etag(want), Some(live)) if want == live => Ok(()),
            (Precondition::Etag(_), Some(_)) => Err(PreconditionError::Failed),
        }
    }
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

/// Evictable cache occupancy and age, excluding pinned safety copies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotShape {
    pub evictable_bytes: u64,
    pub never_read_bytes: u64,
    pub oldest_read_at: Option<UnixMs>,
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

/// ListMultipartUploads catalogue query: the open uploads of a bucket in
/// `(key, upload id)` order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadListQuery {
    pub prefix: String,
    /// Exclusive lower bound: every key after this one and, with an
    /// upload id, also the later uploads of the key itself.
    pub after: Option<(String, Option<String>)>,
    /// Common prefix already emitted; the scan resumes at its successor.
    pub skip_prefix: Option<String>,
    pub limit: u32,
}

/// One open multipart upload, as a listing shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenUpload {
    pub key: String,
    pub id: UploadId,
    pub initiated_at: UnixMs,
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
    /// An extent job that is due at `at`, further out than a queue
    /// delay reaches. It is sent with the longest delay; delivered
    /// before `at` it is sent on for the rest of the wait, at `at` or
    /// later it runs as the `Extent` job of the same fields. `at` is a
    /// hint only: the claim of the outbox row decides what is due.
    Wake {
        v: u8,
        extent: ExtentId,
        generation: GenerationId,
        stage: OutboxStage,
        at: UnixMs,
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
    /// Sweep of one sliced write that was never published: its
    /// `write_intents` rows name the safety blobs to delete.
    Sweep {
        v: u8,
        write: WriteId,
    },
    /// One step of a pass of the recovery copy (`crate::copy`), from
    /// `cursor`. `pass` is the time the pass started. Run by the adapter
    /// that holds the recovery store, not by `run_job`: it needs no
    /// catalogue and runs while the catalogue is closed.
    RecoveryCopy {
        v: u8,
        pass: UnixMs,
        cursor: String,
    },
}

impl Job {
    /// The extent whose outbox row this job is for, if it is for one.
    pub fn extent(&self) -> Option<&ExtentId> {
        match self {
            Job::Extent { extent, .. } | Job::Wake { extent, .. } => Some(extent),
            _ => None,
        }
    }
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
    /// Marking sent rows failed: those rows are sent again by the next
    /// run. The rest of the run went on.
    pub mark_failed: bool,
    /// The re-drive failed; the rest of the run went on without it.
    pub redrive_failed: bool,
    /// The hot-tier check failed; the rest of the run went on without it.
    pub evict_failed: bool,
    /// The catalogue is behind its rollback stamp: nothing else was done.
    pub rolled_back: bool,
    /// The rollback stamp was not raised; the rest of the run went on.
    pub stamp_failed: bool,
    /// Sliced writes that were never published and were sent to the sweep.
    pub sweeps_enqueued: u32,
    /// Listing those writes failed; the rest of the run went on without it.
    pub sweep_failed: bool,
    /// Fewer backbones count toward a release than `REQUIRED_BACKBONES`:
    /// nothing is released until the provider list is put right.
    pub release_paused: bool,
    /// The backbones that are read in full for every extent just now,
    /// because a full read of a sampled extent failed there
    /// (`VERIFY_MODE=light`). Empty is the normal state.
    pub verify_escalated: Vec<String>,
    /// Plans that were rows in `articles` and are packed now.
    pub plans_packed: u32,
    /// Packing failed; the rest of the run went on without it.
    pub pack_failed: bool,
    /// How long this run left a sent post row alone, in seconds: the
    /// resend timeout, or longer while the post queues still held
    /// messages from before the row's mark. 0: the run did not get as
    /// far as the send.
    pub resend_post_secs: u32,
    /// The same for a sent verify or release row and the verify queues.
    pub resend_verify_secs: u32,
    /// Table rows this run counted for a recount of the usage counters.
    pub recount_rows: u64,
    /// A recount ended in this run and found this many counters that
    /// differed from the tables. 0 is the expected figure.
    pub recount_drift: Option<u64>,
    /// The recount step failed; the rest of the run went on without it.
    pub recount_failed: bool,
}

/// The oldest message that waits in the queues of one kind, as far as
/// the queues say.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Oldest {
    /// Not known: a queue of the kind did not say, or what it said
    /// could not be used.
    #[default]
    Unknown,
    /// No queue of the kind holds a message.
    Empty,
    /// When the oldest message still in a queue of the kind was sent.
    At(UnixMs),
}

/// What waits in the queues the dispatcher sends an extent's jobs to
/// (`JobSink::backlog`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Backlog {
    /// The queues of the post jobs.
    pub post: Oldest,
    /// The queues of the verify and release jobs.
    pub verify: Oldest,
}

/// How long the dispatcher leaves a row alone after it sent a job for
/// it (`Catalog::due`), by the kind of queue the job went to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resend {
    /// Seconds for a row in `post`.
    pub post_secs: u32,
    /// Seconds for a row in `verify` or `release`.
    pub verify_secs: u32,
}

impl Resend {
    /// The same wait for every stage.
    pub fn after(secs: u32) -> Self {
        Resend {
            post_secs: secs,
            verify_secs: secs,
        }
    }
}

// ---------------------------------------------------------------------------
// Write intents
// ---------------------------------------------------------------------------

/// What the fence of a sweep found (`Catalog::fence_intents`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentFence {
    /// The rows are `sweeping`: no publication of this write can commit
    /// any more. `generation` is the id its recovery record would have.
    Fenced {
        generation: Option<GenerationId>,
        extents: Vec<ExtentId>,
    },
    /// No row of the write is due: published, swept, kept or too young.
    Gone,
    /// A replay is under way; nothing was changed.
    Refused,
    /// The write has a generation or an extent row: it was published
    /// after all. Its intent rows were deleted; no blob may be touched.
    Published,
}

/// `write_intents` as `GET /_admin/status` reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct IntentStats {
    /// Writes whose blobs the sweep left in place because a recovery
    /// record of the write exists. Nothing reclaims them yet.
    pub kept_writes: u64,
    /// Safety blobs of those writes, at most one slice each.
    pub kept_slices: u64,
    /// `created_at` of the oldest of them: its request began then, and
    /// its recovery record is not older. A replay that starts no later
    /// reads the record of every kept write.
    pub oldest_kept_at: Option<UnixMs>,
    /// Writes the sweep has still to look at: given up by their request,
    /// or older than the grace period.
    pub waiting_writes: u64,
    /// `created_at` of the oldest of them.
    pub oldest_waiting_at: Option<UnixMs>,
    /// Writes of requests that can still be running.
    pub open_writes: u64,
    /// Times the sweep met a write it could not explain: one it kept, or
    /// one that had catalogue rows next to its intents.
    pub anomalies: u64,
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
    /// An XML document that is still being computed: buffered when it is
    /// done soon, else streamed with keepalive whitespace (see
    /// [`crate::keepalive`]).
    Deferred(crate::keepalive::Deferred),
    /// A large GET body that the runtime fetches in sub-ranges, each from
    /// an invocation of its own (see [`crate::fanout`]).
    Fanout(crate::fanout::Fanout),
}

/// One response.
pub struct S3Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: RespBody,
}

/// Text as XML character data. Whatever XML 1.0 cannot carry becomes
/// U+FFFD.
fn xml_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\u{fffe}' | '\u{ffff}' => out.push('\u{fffd}'),
            c if c >= ' ' => out.push(c),
            _ => out.push('\u{fffd}'),
        }
    }
    out
}

/// What an S3 XML error document starts with ([`S3Response::error`]).
const ERROR_OPEN: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>";
const ERROR_CLOSE: &str = "</Error>";

/// The ID a request is logged under, if it is fit to be sent back: 1 to
/// 64 ASCII letters, digits, `.`, `_` or `-`, which is also what the log
/// line prints. Anything else is no ID (it would not match a log line,
/// and it is request data that must not reach a header or a document).
pub fn safe_request_id(id: &str) -> Option<&str> {
    (!id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
    .then_some(id)
}

/// The ID of a request that came with no ray ID (a service binding):
/// the time in milliseconds and 32 random bits, in hex, then `-local`.
/// Always a [`safe_request_id`], so it reaches the header and the log.
pub fn local_request_id(now_ms: u64, random: u32) -> String {
    format!("{now_ms:011x}{random:08x}-local")
}

impl S3Response {
    /// S3 XML error document. `code` and `message` must be static text,
    /// never request data.
    pub fn error(status: u16, code: &str, message: &str) -> S3Response {
        S3Response::error_with(status, code, message, &[])
    }

    /// [`S3Response::error`] with more elements, as S3 adds them to some
    /// errors (`<Header>`, `<Region>`, `<ArgumentName>`). `code` and the
    /// element names must be static text. The message and the element
    /// values may hold request data: they are escaped here.
    pub fn error_with(
        status: u16,
        code: &str,
        message: &str,
        fields: &[(&str, &str)],
    ) -> S3Response {
        let mut body = format!(
            "{ERROR_OPEN}{code}</Code><Message>{}</Message>",
            xml_text(message)
        );
        for (name, value) in fields {
            body.push_str(&format!("<{name}>{}</{name}>", xml_text(value)));
        }
        body.push_str(ERROR_CLOSE);
        S3Response {
            status,
            headers: vec![("content-type".to_string(), "application/xml".to_string())],
            body: RespBody::Bytes(body.into_bytes()),
        }
    }

    /// The response as it leaves the service: with `x-amz-request-id`
    /// and `x-amz-id-2`, and, when it is an error document, with
    /// `<RequestId>` and `<HostId>` in it. `id` is the ID the request is
    /// logged under; one that is not [`safe_request_id`] adds nothing.
    ///
    /// Only an error status with an XML body that [`S3Response::error`]
    /// built is rewritten. An object body is never touched: no object is
    /// served with an error status.
    pub fn with_request_id(mut self, id: &str) -> S3Response {
        let Some(id) = safe_request_id(id) else {
            return self;
        };
        self.headers.retain(|(n, _)| {
            !n.eq_ignore_ascii_case("x-amz-request-id") && !n.eq_ignore_ascii_case("x-amz-id-2")
        });
        self.headers
            .push(("x-amz-request-id".to_string(), id.to_string()));
        self.headers
            .push(("x-amz-id-2".to_string(), id.to_string()));
        let xml = self.headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("content-type") && v.eq_ignore_ascii_case("application/xml")
        });
        if let (true, true, RespBody::Bytes(body)) = (self.status >= 400, xml, &mut self.body) {
            if body.starts_with(ERROR_OPEN.as_bytes())
                && body.ends_with(ERROR_CLOSE.as_bytes())
                && !body
                    .windows(b"<RequestId>".len())
                    .any(|w| w == b"<RequestId>")
            {
                body.truncate(body.len() - ERROR_CLOSE.len());
                body.extend_from_slice(
                    format!("<RequestId>{id}</RequestId><HostId>{id}</HostId>{ERROR_CLOSE}")
                        .as_bytes(),
                );
                // A length set for the shorter document no longer holds.
                self.headers
                    .retain(|(n, _)| !n.eq_ignore_ascii_case("content-length"));
            }
        }
        self
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

// ---------------------------------------------------------------------------
// Usage counters
// ---------------------------------------------------------------------------

/// The catalogue-wide usage counters (`usage_global`, row 1). Signed: a
/// counter that has drifted below zero is reported as it is, for the
/// recount to explain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UsageCounters {
    /// `false` until a recount has switched the counters on. The figures
    /// mean nothing before that.
    pub seeded: bool,
    /// Extents whose safety copy is held or releasing, and their
    /// ciphertext bytes: what R2 must keep.
    pub extents_unreleased: i64,
    pub unreleased_bytes: i64,
    pub extents_released: i64,
    pub released_bytes: i64,
    pub extents_deleted: i64,
    pub outbox_post: i64,
    pub outbox_verify: i64,
    pub outbox_release: i64,
    pub outbox_done: i64,
    pub outbox_cancelled: i64,
    pub outbox_dead: i64,
    /// Events since the counters were switched on.
    pub posts_total: i64,
    pub verifies_total: i64,
    pub releases_total: i64,
    pub dead_total: i64,
    pub failures_total: i64,
    /// The hour still being counted, as `UnixMs / 3_600_000`.
    pub current: UsageHour,
}

impl UsageCounters {
    /// Outbox rows of `stage`.
    pub fn outbox(&self, stage: OutboxStage) -> i64 {
        match stage {
            OutboxStage::Post => self.outbox_post,
            OutboxStage::Verify => self.outbox_verify,
            OutboxStage::Release => self.outbox_release,
            OutboxStage::Done => self.outbox_done,
            OutboxStage::Cancelled => self.outbox_cancelled,
            OutboxStage::Dead => self.outbox_dead,
        }
    }
}

/// Events of one hour (`hour` = `UnixMs / 3_600_000`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct UsageHour {
    pub hour: i64,
    pub posts: i64,
    pub verifies: i64,
    pub releases: i64,
    pub dead: i64,
    pub failures: i64,
}

/// A finished recount of the usage counters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageRecount {
    pub started_at: UnixMs,
    pub finished_at: UnixMs,
    /// Table rows it counted.
    pub rows: u64,
    /// Whether its figures replaced the live counters.
    pub adopted: bool,
    /// Counters (and buckets) whose live value differed from the count.
    pub drift: u64,
    /// The live and the counted values, as JSON, when it compared them.
    pub detail: Option<String>,
}

/// A recount under way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RecountState {
    pub running: bool,
    pub started_at: UnixMs,
    pub rows_seen: u64,
    /// The table being counted: `extents`, `outbox`, `generations`, or
    /// `finish` when all three are counted.
    pub table: &'static str,
    pub adopt: bool,
}

/// What one step of a recount did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecountStep {
    /// No recount is running; nothing was done.
    pub idle: bool,
    /// Table rows counted while this step ran: this step's, and those
    /// of a step that ran beside it. A progress figure; the record of
    /// the recount has the exact total.
    pub rows: u64,
    /// The recount ended with this step.
    pub finished: Option<UsageRecount>,
}

/// Everything the operations page reads, without a table scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageSnapshot {
    pub counters: UsageCounters,
    /// Live objects and their plaintext bytes, over all buckets.
    pub live_objects: i64,
    pub live_bytes: i64,
    /// Bucket rows in the counters: buckets with a live object, and
    /// those emptied since the last adopted recount.
    pub buckets_counted: u64,
    /// The earliest `next_at` of the rows waiting in each stage.
    pub oldest_post: Option<UnixMs>,
    pub oldest_verify: Option<UnixMs>,
    pub oldest_release: Option<UnixMs>,
    /// Completed hours that had an event, newest first: `hour` says
    /// which, and an hour without events has no entry.
    pub hours: Vec<UsageHour>,
    pub recount: RecountState,
    pub last_recount: Option<UsageRecount>,
}

/// Live objects of one bucket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BucketUsage {
    pub bucket_id: String,
    pub name: String,
    pub live_objects: i64,
    pub live_bytes: i64,
}

#[cfg(test)]
mod tests {
    use super::UnixMs;

    /// Two invocations of one isolate read their clocks out of order by a
    /// few milliseconds: a stamp a little ahead of `now` is recent.
    #[test]
    fn a_stamp_a_moment_ahead_is_within_the_window() {
        let now = UnixMs(1_000_000);
        for ahead in [1, 2, 24, 5_000] {
            assert!(now.within(now.plus_ms(ahead), 10_000), "{ahead} ms ahead");
        }
        assert!(now.within(now, 10_000));
        assert!(now.within(now.plus_ms(-9_999), 10_000));
        assert!(!now.within(now.plus_ms(-10_000), 10_000), "old");
    }

    /// A stamp a whole window or more ahead is a clock that jumped, not a
    /// reading order, and counts as old: it is bounded, never kept forever.
    #[test]
    fn a_stamp_far_ahead_is_bounded() {
        let now = UnixMs(1_000_000);
        assert!(now.within(now.plus_ms(9_999), 10_000));
        assert!(!now.within(now.plus_ms(10_000), 10_000));
        assert!(!now.within(UnixMs(i64::MAX), 10_000));
        assert!(!UnixMs(i64::MIN).within(UnixMs(i64::MAX), 10_000));
        assert!(!UnixMs(i64::MAX).within(UnixMs(i64::MIN), 10_000));
    }
}
