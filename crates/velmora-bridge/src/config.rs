//! Validated configuration (frozen with the contract, DESIGN §A.8, §A.12).
//!
//! [`BridgeConfig::from_vars`] reads Worker vars and secrets through one
//! lookup function and fails closed: a missing, unparsable or unsafe value
//! is an error naming the variable, never echoing its value.

use core::fmt;
use core::net::IpAddr;
use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;

use crate::ports::Kek;
use crate::types::{KekBytes, ProviderConfig, Secret, SizeCommand};

/// Real-data gate. While `false`, `create_bucket` refuses
/// `disposable = false` and `GC_MODE=full` is rejected. Open since the
/// catalogue recovery protocol landed and its drills passed (see
/// `workers/s3-bridge/ops/README.md`).
pub const REAL_DATA_READY: bool = true;

/// Largest extent, and largest UploadPart body. Raised when streaming
/// bodies land.
pub const MAX_EXTENT_BYTES_LIMIT: u64 = 16 * 1024 * 1024;

/// Largest PutObject body `MAX_PUT_BYTES` may allow. The edge refuses a
/// request of 100 MiB before the Worker runs; the last MiB is left for
/// the framing of a chunked body. It is enough for signed chunks of
/// 16 KiB or more; with signed chunks of 8 KiB, the smallest S3 allows,
/// the edge refuses a body above about 98.9 MiB.
pub const MAX_PUT_BYTES_LIMIT: u64 = 99 * 1024 * 1024;

/// `SLICE_BYTES` when the variable is absent: 8 MiB, or one extent when
/// that is smaller.
pub const DEFAULT_SLICE_BYTES: u64 = 8 * 1024 * 1024;

/// Most slices one PutObject is cut into. Their ids travel in single
/// catalogue batches, and one generation holds them.
pub const MAX_WRITE_SLICES: u64 = 16;

/// Most extents one recovery record names in a single document. A
/// CopyObject writes such a record for all the extents of its source, so
/// a source of more is refused (`service/copy.rs`); it is copied in parts.
/// While [`MAX_OBJECT_EXTENTS_LIMIT`] is the same number no object is
/// larger, and the refusal is there for when that limit is raised.
pub const SINGLE_RECORD_EXTENTS: u32 = 10_000;

/// Most extents one object may be made of, and `MAX_OBJECT_EXTENTS`
/// when the variable is absent. One recovery record names them all and
/// one catalogue batch publishes them, so CompleteMultipartUpload
/// refuses an upload that holds more, in listed parts or not, and
/// UploadPart refuses a part of several extents that would take it there.
pub const MAX_OBJECT_EXTENTS_LIMIT: u32 = 10_000;

/// Upper bound for `max_conns` of one provider.
pub const MAX_CONNS_LIMIT: u32 = 64;

/// Most entries `NNTP_PROVIDERS` may hold.
pub const MAX_PROVIDERS: usize = 32;

/// Most entries a provider's `hosts` may hold (next to `host`).
pub const MAX_HOSTS: usize = 8;

/// Most entries a provider's `proxies` may hold. Each one that cannot
/// be used costs the callers its time limit
/// ([`crate::hosts::PROXY_CONNECT_SECS`]) once, over all the connects
/// and probes that wait for it: the time a probe gave up after counts
/// into it. No try is shorter than a probe's limit
/// ([`crate::hosts::PROBE_TIMEOUT_MS`]), so the last one may end that
/// much late at most. All of that together must leave room inside one
/// call of a read.
pub const MAX_PROXIES: usize = 3;
const _: () = assert!(
    MAX_PROXIES as u32
        * (crate::hosts::PROXY_CONNECT_SECS * 1_000 + crate::hosts::PROBE_TIMEOUT_MS)
        < crate::ports::READ_CALL_SECS * 1_000
);

/// Longest name, user name or password SOCKS5 carries, in bytes.
const SOCKS_FIELD_MAX: usize = 255;

/// Longest accepted provider `pool` name (bytes).
pub const MAX_POOL_NAME_LEN: usize = 64;

/// Highest accepted `VELMORA_KEK_ACTIVE`. `KekRing::from_vars` probes every
/// version up to the active one, so the loop must stay bounded.
pub const MAX_KEK_VERSION: u32 = 1024;

/// Ports a TLS provider may use (the engine's pinned-TLS policy).
pub const TLS_PORTS: [u16; 2] = [119, 563];

/// Shortest accepted `ADMIN_TOKEN` (characters).
pub const MIN_ADMIN_TOKEN_LEN: usize = 32;

/// Deployment environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Dev,
    Prod,
}

/// `GC_MODE`. There is no `full` mode: nothing collects the extents of a
/// non-disposable bucket, so `full` is refused as an invalid value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcMode {
    /// `gc` rows accumulate; nothing is deleted.
    Off,
    /// The GC job acts only for extents in `disposable = 1` buckets.
    Disposable,
}

/// What a host name the service answers on is for. `S3_HOST` is always
/// [`HostClass::Legacy`]; the hosts of `S3_HOSTS` name their class.
///
/// For now both classes admit every key: there is one tenant, so the
/// class changes no answer yet. It is parsed, validated and resolved
/// per request now, so that binding tenants to classes later is a
/// change to one rule and not to the configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostClass {
    /// The endpoint the existing keys were given.
    Legacy,
    /// The endpoint for customer tenants.
    Customer,
}

/// One more host the S3 surface answers on, besides `S3_HOST`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Host {
    /// As configured: lowercase, with an optional `:port`.
    pub name: String,
    pub class: HostClass,
}

/// Most hosts `S3_HOSTS` may list.
pub const MAX_EXTRA_S3_HOSTS: usize = 8;

/// How long an upload part stays after it stopped being part of its
/// upload (replaced, aborted, or left out of the part list at
/// completion) before `GC_ORPHANS` deletes its safety copy: 31 days.
///
/// Requests and jobs never bring such a part back: its extent id is
/// never issued again and only an open upload that lists an extent can
/// publish it. A catalogue from before the drop does list it, and its
/// upload is open there. The database can be taken back at most 30 days
/// (D1 Time Travel), so once a part has been dropped for longer, no
/// state the database can return to lists it. The 31st day is the
/// margin between the clocks compared: the Worker's, which dated the
/// drop and runs the collector, and the database's.
///
/// The same wait makes a deletion safe to lose: a catalogue taken back
/// to before a part was collected still has the part dropped, with its
/// row open, and the collector deletes the absent copy once more.
/// And it ends every request that could still name the part: a
/// completion that read the part list before the drop has stored its
/// recovery record, or never will, long before the wait is over.
///
/// What it assumes: the database stayed on one history for that long.
/// A restore that is undone leaves a second history that Time Travel
/// can still return to for 30 days, with states of before the restore
/// point in it. So the collector waits the same time once more after
/// every replay: no claim is granted until this long after the last
/// one ended (`sql/gc.rs`, "After a replay"). A restore that was undone
/// before a replay ended on it, or within the minutes before the
/// rollback stamp was next raised, leaves nothing in the catalogue to
/// tell by: for that one the ops notes keep the rule that the switch
/// stays off for this long ("After a restore").
pub const ORPHAN_GRACE_MS: i64 = 31 * 24 * 60 * 60 * 1000;

/// `MAINTENANCE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Maintenance {
    Off,
    /// Every mutation answers 503; jobs and the dispatcher no-op.
    Restore,
}

/// Why configuration was refused. Carries variable names only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A required var or secret is absent or empty.
    Missing(String),
    /// A value does not parse or is out of range.
    Invalid(String),
    /// A value is well-formed but refused by a safety rule.
    Refused(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Missing(name) => write!(f, "missing {name}"),
            ConfigError::Invalid(name) => write!(f, "invalid {name}"),
            ConfigError::Refused(rule) => write!(f, "refused: {rule}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// `HOT_CAP_BYTES` when the variable is absent: 100 GiB.
pub const DEFAULT_HOT_CAP_BYTES: u64 = 100 * 1024 * 1024 * 1024;

/// Sockets of one post job when `POST_SOCKETS` is unset. The sockets of
/// one job leave from one address, which matters for providers that limit
/// the addresses an account connects from; each socket also holds one
/// article in memory.
pub const DEFAULT_POST_SOCKETS: u32 = 4;
/// Sockets of one invocation's cold reads when `COLD_SOCKETS` is unset
/// (see [`crate::fetch::ColdFetch`]). They leave from one address, as a
/// post job's do, and each holds the wire text of one article
/// ([`crate::fetch::COLD_SOCKET_BYTES`]).
pub const DEFAULT_COLD_SOCKETS: u32 = 4;
/// Most `COLD_SOCKETS`. A deployment whose `INFLIGHT_BUDGET_BYTES` has
/// no room for that many beside one extent and its copy for the cache
/// reads over as many as fit ([`crate::fetch::cold_read_bytes`]).
pub const MAX_COLD_SOCKETS: u32 = 8;
/// `JOB_BUDGET_BYTES` may be at most `INFLIGHT_BUDGET_BYTES` times this
/// ratio (3/2).
///
/// A request holds up to 1.5 bytes for each byte it charges: an upload
/// charges plaintext plus ciphertext and the ciphertext is copied once
/// more when it is handed to the blob store. A job holds about what it
/// charges. The budget weighs a request byte at `JOB_BUDGET_BYTES /
/// INFLIGHT_BUDGET_BYTES` job bytes, so a ratio above 3/2 would only let
/// jobs charge memory that requests alone could never reach.
pub const MAX_JOB_BUDGET_NUM: u64 = 3;
pub const MAX_JOB_BUDGET_DEN: u64 = 2;

/// Propagation grace when `PROPAGATION_GRACE_SECS` is unset: six hours.
pub const DEFAULT_PROPAGATION_GRACE_SECS: u32 = 21_600;

/// Validated settings for one isolate.
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub environment: Environment,
    /// The host clients sign (`policy.host`), class
    /// [`HostClass::Legacy`].
    pub s3_host: String,
    /// More hosts clients may sign for (`S3_HOSTS`), each with its
    /// class. Empty when the variable is unset: the service answers on
    /// `s3_host` alone, as before the variable existed.
    pub s3_hosts: Vec<S3Host>,
    pub region: String,
    pub max_extent_bytes: u64,
    /// Largest PutObject body. A body above `max_extent_bytes` is cut
    /// into slices of `slice_bytes`, each its own extent. Equal to
    /// `max_extent_bytes` = no body is sliced.
    pub max_put_bytes: u64,
    /// Plaintext bytes of one slice of a sliced body.
    pub slice_bytes: u64,
    /// Most extents CompleteMultipartUpload publishes as one object.
    pub max_object_extents: u32,
    /// Delete the safety blobs of sliced writes that were never
    /// published. Off: their `write_intents` rows stay and can be swept
    /// later.
    pub intent_sweep: bool,
    /// Delete the safety copies of upload parts that no upload and no
    /// object refers to, [`ORPHAN_GRACE_MS`] after they were dropped
    /// (`GC_ORPHANS`). Independent of `gc_mode`. Off: they stay, and a
    /// later run with the switch on takes them.
    pub gc_orphans: bool,
    /// Store the article plan of a new extent packed on its row
    /// (`PACKED_PLANS`, [`crate::plan`]) instead of as one row per
    /// article. Every Worker from the one that knows this switch reads
    /// both forms; one from before cannot read a packed plan. So the
    /// switch goes on only once no older version can come back, and a
    /// rollback after that is to a version that knows it, with it off.
    pub packed_plans: bool,
    /// Give the plan of a new extent a parity addendum (`PARITY`,
    /// [`crate::parity`]) and post its parity articles with the data
    /// articles. Only a plan that is stored packed gets one. The switch
    /// says nothing about an addendum that is stored: that one is always
    /// posted and read. A Worker from before the switch ignores an
    /// addendum, so a rollback past it posts and releases extents
    /// without their parity.
    pub parity: bool,
    /// The layout of new recovery records (`RECORD_LAYOUT`,
    /// [`crate::recovery::Layout`]): `flat`, or `tenant` for the
    /// directory of the tenant. It names what is written only. Every
    /// Worker from the one that knows this switch reads both layouts,
    /// whatever its value; one from before reads the flat one alone. So
    /// `tenant` goes on only once no older version can come back, and a
    /// rollback after that is to a version that knows the switch.
    pub records: crate::recovery::Layout,
    pub required_backbones: u32,
    pub safety_min_age_secs: u32,
    pub verify_delay_secs: u32,
    /// How the verify stage checks an extent (`VERIFY_MODE` and its
    /// companions).
    pub verify: VerifyConfig,
    /// NNTP sockets one post job opens at most, over all its providers.
    pub post_sockets: u32,
    /// Connections one invocation reads cold extents over
    /// (`COLD_SOCKETS`, 1 to [`MAX_COLD_SOCKETS`]).
    pub cold_sockets: u32,
    /// How long a posted article may take to reach another backbone on
    /// its own. Past it, verification posts an article a backbone still
    /// lacks straight to a provider of that backbone.
    pub propagation_grace_secs: u32,
    /// Posting allow-list; the poster picks from it.
    pub newsgroups: Vec<String>,
    pub kek_active: u32,
    pub inflight_budget_bytes: u64,
    /// What the isolate's background jobs and requests may charge to the
    /// byte budget together (`JOB_BUDGET_BYTES`); a job charges under
    /// this limit, a request under `inflight_budget_bytes`. Unset = the
    /// same as `inflight_budget_bytes`.
    pub job_budget_bytes: u64,
    pub gc_mode: GcMode,
    /// Cap on evictable bytes in R2 (released safety copies and cache
    /// fills). Pinned bytes are outside it: uploads are never throttled.
    pub hot_cap_bytes: u64,
    pub maintenance: Maintenance,
    /// Names this catalogue in the keys of its rollback stamp
    /// (`rs/<catalogue id>/<counter>`). Two catalogues over one safety
    /// bucket need two ids. Never change it for a catalogue in use: its
    /// stamp objects would no longer be found.
    pub catalogue_id: String,
    /// Serve CopyObject (`SERVER_SIDE_COPY`); off, it answers 501.
    /// UploadPartCopy does not read it. With it on, never roll back to a
    /// version that predates extent references (migration 0005): such a
    /// Worker cannot read a copy and does not know that the source's
    /// extents are shared. Cloudflare still offers such versions, so the
    /// rule is "Rollback floor" in `workers/s3-bridge/ops/README.md`.
    pub server_side_copy: bool,
    /// A GET body above this many plaintext bytes is served in
    /// sub-ranges of this size, each by an invocation of its own
    /// (`GET_FANOUT_BYTES`, see [`crate::fanout`]). `None` (unset, empty
    /// or `0`) = every GET is served by the invocation that received it.
    /// Needs the Worker's service binding to itself.
    pub get_fanout_bytes: Option<u64>,
    /// Accept `http://` as if it were HTTPS (`wrangler dev` only).
    pub dev_trust_http: bool,
    pub providers: Vec<ProviderConfig>,
    pub admin_token: Secret,
    /// A second admin token that may only read (`ADMIN_READ_TOKEN`):
    /// `GET` on the routes of [`crate::ingress::ADMIN_READ_ROUTES`]. What
    /// a dashboard holds. `None` = only `ADMIN_TOKEN` is accepted.
    pub admin_read_token: Option<Secret>,
    /// The only host `/_admin` answers on (`ADMIN_HOST`). Meant to be a
    /// name no public route of the Worker has, so that the admin routes
    /// are reached through a service binding alone. `None` = on every
    /// host the Worker serves.
    pub admin_host: Option<String>,
    /// One request in this many is written to the metrics dataset
    /// (`METRICS_SAMPLE`, default 10); every one that ended in a 5xx is.
    pub metrics_sample: u32,
}

/// `METRICS_SAMPLE` when unset: one request in ten.
pub const DEFAULT_METRICS_SAMPLE: u32 = 10;

fn required(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<String, ConfigError> {
    match get(name) {
        Some(v) if !v.trim().is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(name.to_string())),
    }
}

/// How the verify stage checks an extent (`VERIFY_MODE`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VerifyMode {
    /// Every extent is read in full (`BODY`) on one backbone.
    #[default]
    Body,
    /// Presence and stored size of every article on every backbone, and
    /// a full read of a sample of the extents ([`crate::verify`]).
    Light,
}

/// Default of `VERIFY_SAMPLE_PERCENT`, in parts per million: 2 %.
pub const DEFAULT_VERIFY_SAMPLE_PPM: u32 = 20_000;
/// The smallest sample outside development: 1 %.
pub const MIN_VERIFY_SAMPLE_PPM: u32 = 10_000;
/// Default of `VERIFY_ESCALATE_SECS`: a day.
pub const DEFAULT_VERIFY_ESCALATE_SECS: u32 = 86_400;

/// The switches of the verify stage.
///
/// Rollout: every value is read by the job that runs, so Workers with
/// different values may run side by side. An extent verified under
/// `light` and released by a Worker under `body` is not released: it goes
/// back to verify and is read in full. One verified under `body` is
/// released by either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyConfig {
    pub mode: VerifyMode,
    /// Extents read in full under `light`, in parts per million
    /// (`VERIFY_SAMPLE_PERCENT`, a decimal number of percent).
    pub sample_ppm: u32,
    /// How long a backbone is read in full after a full read of it
    /// failed under `light` (`VERIFY_ESCALATE_SECS`): for every extent
    /// stored before the period ends, whenever its job runs.
    pub escalate_secs: u32,
    /// The size command of each provider that has one
    /// (`VERIFY_SIZE_COMMANDS`, a JSON object of provider id to `hdr`,
    /// `over` or `head`). A provider without an entry is only
    /// asked with `STAT`.
    pub size_commands: Vec<(String, SizeCommand)>,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        VerifyConfig {
            mode: VerifyMode::Body,
            sample_ppm: DEFAULT_VERIFY_SAMPLE_PPM,
            escalate_secs: DEFAULT_VERIFY_ESCALATE_SECS,
            size_commands: Vec::new(),
        }
    }
}

impl VerifyConfig {
    /// The size command of provider `id`, if it has one.
    pub fn size_command(&self, id: &str) -> Option<SizeCommand> {
        self.size_commands
            .iter()
            .find(|(p, _)| p == id)
            .map(|(_, c)| *c)
    }

    fn from_env(
        get: &impl Fn(&str) -> Option<String>,
        providers: &[ProviderConfig],
        dev: bool,
    ) -> Result<Self, ConfigError> {
        let mode = match get("VERIFY_MODE").as_deref().map(str::trim) {
            None | Some("") | Some("body") => VerifyMode::Body,
            Some("light") => VerifyMode::Light,
            Some(_) => return Err(ConfigError::Invalid("VERIFY_MODE".into())),
        };
        let sample_ppm = match get("VERIFY_SAMPLE_PERCENT").as_deref().map(str::trim) {
            None | Some("") => DEFAULT_VERIFY_SAMPLE_PPM,
            Some(v) => percent_ppm(v)
                .ok_or_else(|| ConfigError::Invalid("VERIFY_SAMPLE_PERCENT".into()))?,
        };
        if sample_ppm < MIN_VERIFY_SAMPLE_PPM && !dev {
            return Err(ConfigError::Refused(
                "VERIFY_SAMPLE_PERCENT below 1 outside dev",
            ));
        }
        let escalate_secs = number_or(
            get,
            "VERIFY_ESCALATE_SECS",
            DEFAULT_VERIFY_ESCALATE_SECS,
            (60, 30 * 86_400),
        )?;
        let invalid = || ConfigError::Invalid("VERIFY_SIZE_COMMANDS".into());
        let size_commands = match get("VERIFY_SIZE_COMMANDS").as_deref().map(str::trim) {
            None | Some("") => Vec::new(),
            Some(json) => {
                let map: BTreeMap<String, String> =
                    serde_json::from_str(json).map_err(|_| invalid())?;
                let mut out = Vec::with_capacity(map.len());
                for (id, command) in map {
                    // A name that is no provider is a typo: the provider
                    // meant would silently stay on `STAT`.
                    if !providers.iter().any(|p| p.id == id) {
                        return Err(invalid());
                    }
                    out.push((id, SizeCommand::parse(&command).ok_or_else(invalid)?));
                }
                out
            }
        };
        Ok(VerifyConfig {
            mode,
            sample_ppm,
            escalate_secs,
            size_commands,
        })
    }
}

/// A decimal number of percent, `0` to `100` with up to four decimals,
/// in parts per million.
fn percent_ppm(v: &str) -> Option<u32> {
    let (whole, frac) = v.split_once('.').unwrap_or((v, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || whole.len() > 3 || frac.len() > 4 || (!frac.is_empty() && !digits(frac)) {
        return None;
    }
    if v.contains('.') && frac.is_empty() {
        return None;
    }
    let whole: u32 = whole.parse().ok()?;
    let frac: u32 = format!("{frac:0<4}").parse().ok()?;
    let ppm = whole.checked_mul(10_000)?.checked_add(frac)?;
    (ppm <= 1_000_000).then_some(ppm)
}

/// An optional number in `min..=max`; unset or empty = `default`.
fn number_or(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: u32,
    (min, max): (u32, u32),
) -> Result<u32, ConfigError> {
    match get(name) {
        Some(v) if !v.trim().is_empty() => match v.trim().parse::<u32>() {
            Ok(n) if (min..=max).contains(&n) => Ok(n),
            _ => Err(ConfigError::Invalid(name.to_string())),
        },
        _ => Ok(default),
    }
}

/// An optional `u64`; unset or empty = `None`.
fn optional_u64(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<Option<u64>, ConfigError> {
    match get(name) {
        Some(v) if !v.trim().is_empty() => v
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| ConfigError::Invalid(name.to_string())),
        _ => Ok(None),
    }
}

fn number<N: core::str::FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<N, ConfigError> {
    required(get, name)?
        .trim()
        .parse::<N>()
        .map_err(|_| ConfigError::Invalid(name.to_string()))
}

/// `[A-Za-z0-9.-]+` with an optional `:port` (1..=65535).
fn valid_s3_host(h: &str) -> bool {
    let (name, port) = match h.split_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (h, None),
    };
    let name_ok = !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let port_ok = port.is_none_or(|p| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65_535).contains(&n))
    });
    name_ok && port_ok
}

/// The catalogue id when `CATALOGUE_ID` is not set.
pub const DEFAULT_CATALOGUE_ID: &str = "main";

/// `[a-z0-9_-]{1,32}`: one path segment of a blob key.
fn valid_catalogue_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A DNS name: at most 253 bytes of two or more dot-separated labels,
/// each 1 to 63 of `[A-Za-z0-9-]` and not starting or ending with `-`,
/// the last one not all digits (so no IPv4 address and no single-label
/// name). An entry of a provider's `hosts`.
fn valid_host_name(h: &str) -> bool {
    let labels: Vec<&str> = h.split('.').collect();
    h.len() <= 253
        && labels.len() >= 2
        && labels
            .last()
            .is_some_and(|last| !last.bytes().all(|b| b.is_ascii_digit()))
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// A provider's `hosts`: at most [`MAX_HOSTS`] valid names, none twice
/// and none the same as `host` (case does not make two hosts), and only
/// on TLS: a plaintext provider is the local fake server, one host.
fn hosts_ok(p: &ProviderConfig) -> bool {
    if p.hosts.is_empty() {
        return true;
    }
    if !p.tls || p.hosts.len() > MAX_HOSTS || !p.hosts.iter().all(|h| valid_host_name(h)) {
        return false;
    }
    let mut seen = BTreeSet::new();
    p.endpoints()
        .into_iter()
        .all(|h| seen.insert(h.to_ascii_lowercase()))
}

/// An address a proxy may have: not loopback, private, shared
/// (100.64.0.0/10, as overlay networks hand out), link-local,
/// unspecified, multicast or broadcast. The runtime does not connect to
/// those either; here they are a configuration mistake.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || (v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64)
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.to_ipv4_mapped().is_some()
                // Unique local fc00::/7, link-local fe80::/10.
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80)
        }
    }
}

/// A provider's `proxies`: at most [`MAX_PROXIES`], each a DNS name or a
/// public IP address with a port and a login SOCKS5 can carry, none
/// twice. Only on a TLS provider, whose every host name fits a SOCKS5
/// request: through a proxy there is no plaintext.
///
/// The provider sees one address per proxy in use, and all of them may
/// be in use together (each isolate keeps its own order). So the
/// provider's address limit, `max_ips`, must be stated with `proxies`,
/// and the list is no longer than it: without the limit nothing here
/// could tell a list that is too long.
fn proxies_ok(p: &ProviderConfig) -> bool {
    if p.proxies.is_empty() {
        return true;
    }
    let field = |s: &str| (1..=SOCKS_FIELD_MAX).contains(&s.len());
    let mut seen = BTreeSet::new();
    p.tls
        && p.proxies.len() <= MAX_PROXIES
        && p.max_ips
            .is_some_and(|ips| p.proxies.len() as u64 <= u64::from(ips))
        && p.endpoints().into_iter().all(valid_host_name)
        && p.proxies.iter().all(|x| {
            (valid_host_name(&x.host) || x.host.parse::<IpAddr>().is_ok_and(public_ip))
                && x.port != 0
                && field(&x.user)
                && field(&x.pass)
                && seen.insert((x.host.to_ascii_lowercase(), x.port))
        })
}

fn valid_newsgroup(g: &str) -> bool {
    !g.is_empty()
        && g.len() <= 128
        && !g.starts_with('.')
        && !g.ends_with('.')
        && g.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b))
}

/// `S3_HOSTS`: absent or empty is no extra host. Otherwise a comma
/// separated list of `<host>=<class>`, class `legacy` or `customer`,
/// at most [`MAX_EXTRA_S3_HOSTS`] entries. Each host is a valid
/// `S3_HOST` value in lowercase, and no host is listed twice or equals
/// `S3_HOST` (compared without case). Anything else refuses the whole
/// configuration: a host typed wrong must not leave a second endpoint
/// half-configured.
fn parse_s3_hosts(raw: Option<&str>, primary: &str) -> Result<Vec<S3Host>, ConfigError> {
    let invalid = || ConfigError::Invalid("S3_HOSTS".into());
    let raw = match raw.map(str::trim) {
        None | Some("") => return Ok(Vec::new()),
        Some(raw) => raw,
    };
    let mut out: Vec<S3Host> = Vec::new();
    for entry in raw.split(',') {
        let (name, class) = entry.trim().split_once('=').ok_or_else(invalid)?;
        let (name, class) = (name.trim(), class.trim());
        let class = match class {
            "legacy" => HostClass::Legacy,
            "customer" => HostClass::Customer,
            _ => return Err(invalid()),
        };
        if !valid_s3_host(name)
            || name.bytes().any(|b| b.is_ascii_uppercase())
            || name.eq_ignore_ascii_case(primary)
            || out.iter().any(|h| h.name == name)
        {
            return Err(invalid());
        }
        out.push(S3Host {
            name: name.to_owned(),
            class,
        });
    }
    if out.len() > MAX_EXTRA_S3_HOSTS {
        return Err(invalid());
    }
    Ok(out)
}

/// `VELMORA_KEK_<v>`: base64 (standard, padded) of exactly 32 bytes.
fn parse_kek(get: &impl Fn(&str) -> Option<String>, v: u32) -> Result<KekBytes, ConfigError> {
    let name = format!("VELMORA_KEK_{v}");
    let raw = required(get, &name)?;
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|_| ConfigError::Invalid(name.clone()))?;
    let out = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ConfigError::Invalid(name));
    zeroize::Zeroize::zeroize(&mut bytes);
    out.map(KekBytes::new)
}

impl BridgeConfig {
    /// The configuration of the jobs of one managed tenant's unit, made
    /// from this isolate's (tenant 0's) configuration. It takes the
    /// unit's name, never a string: `CATALOGUE_ID` stays tenant 0's and
    /// keeps its validator ([`valid_catalogue_id`] refuses a dot, so no
    /// deploy variable can name a unit's stamp prefix, round 3 L1-Q7).
    /// Two settings differ from tenant 0's:
    ///
    /// - `catalogue_id` is the unit's stamp id `<tenant>.<unit>`, made by
    ///   [`crate::unit::jobcall::stamp_id`], the one producer of that
    ///   form, which the unit's job calls check against (`rs/<t>.<u>/`).
    /// - `records` is the tenant's own layout (`m/x/<tenant>/`), whatever
    ///   tenant 0's is: a managed tenant's records never go into the flat
    ///   layout, which the recovery copy and the replay read as tenant
    ///   0's.
    ///
    /// Every other setting is tenant 0's, `maintenance` included (AM-50):
    /// under `restore` a unit's jobs make no unit call and its writes
    /// answer `503`, which the owner move's window depends on (DS1 §3.4
    /// from 8(b) to step 9).
    ///
    /// Refused for tenant 0, which has no unit.
    pub fn for_unit(&self, unit: &crate::unit::UnitName) -> Result<BridgeConfig, ConfigError> {
        if unit.tenant.is_zero() {
            return Err(ConfigError::Refused("tenant 0 has no unit"));
        }
        let records = crate::recovery::Layout::tenant(unit.tenant.as_str())
            .ok_or(ConfigError::Refused("not a tenant id"))?;
        let catalogue_id = crate::unit::jobcall::stamp_id(unit);
        debug_assert!(
            !valid_catalogue_id(&catalogue_id),
            "a unit id is never a catalogue id"
        );
        Ok(BridgeConfig {
            catalogue_id,
            records,
            ..self.clone()
        })
    }

    /// The configured host a request's `Host` names, as configured, and
    /// its class; `None` when it names none of them. Compared without
    /// case, port included: `s3.example` does not match `s3.example:443`.
    pub fn s3_host_for(&self, host: &str) -> Option<(&str, HostClass)> {
        if host.eq_ignore_ascii_case(&self.s3_host) {
            return Some((self.s3_host.as_str(), HostClass::Legacy));
        }
        self.s3_hosts
            .iter()
            .find(|h| host.eq_ignore_ascii_case(&h.name))
            .map(|h| (h.name.as_str(), h.class))
    }

    /// Every host the S3 surface answers on: `S3_HOST` first.
    pub fn all_s3_hosts(&self) -> impl Iterator<Item = &str> {
        core::iter::once(self.s3_host.as_str()).chain(self.s3_hosts.iter().map(|h| h.name.as_str()))
    }

    /// Builds and validates the configuration from vars and secrets.
    /// `get` returns a var or secret by name (`None` = absent).
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<BridgeConfig, ConfigError> {
        let environment = match required(&get, "ENVIRONMENT")?.as_str() {
            "dev" => Environment::Dev,
            "prod" => Environment::Prod,
            _ => return Err(ConfigError::Invalid("ENVIRONMENT".into())),
        };
        let dev = environment == Environment::Dev;

        let s3_host = required(&get, "S3_HOST")?;
        if !valid_s3_host(&s3_host) {
            return Err(ConfigError::Invalid("S3_HOST".into()));
        }
        let s3_hosts = parse_s3_hosts(get("S3_HOSTS").as_deref(), &s3_host)?;
        let region = required(&get, "S3_REGION")?;

        let max_extent_bytes: u64 = number(&get, "MAX_EXTENT_BYTES")?;
        if max_extent_bytes == 0 || max_extent_bytes > MAX_EXTENT_BYTES_LIMIT {
            return Err(ConfigError::Invalid("MAX_EXTENT_BYTES".into()));
        }

        // Optional: absent or empty keeps every PUT at one extent.
        let max_put_bytes = optional_u64(&get, "MAX_PUT_BYTES")?.unwrap_or(max_extent_bytes);
        if max_put_bytes < max_extent_bytes || max_put_bytes > MAX_PUT_BYTES_LIMIT {
            return Err(ConfigError::Invalid("MAX_PUT_BYTES".into()));
        }
        let set_slice_bytes = optional_u64(&get, "SLICE_BYTES")?;
        let slice_bytes = set_slice_bytes.unwrap_or(DEFAULT_SLICE_BYTES.min(max_extent_bytes));
        // A slice is an extent, and a maximal body stays within the
        // slice count one write may have.
        if slice_bytes == 0 || slice_bytes > max_extent_bytes {
            return Err(ConfigError::Invalid("SLICE_BYTES".into()));
        }
        if max_put_bytes.div_ceil(slice_bytes) > MAX_WRITE_SLICES {
            // With `SLICE_BYTES` unset the slice follows from
            // `MAX_EXTENT_BYTES`, and the limit that asks too much of it
            // is the one that was set.
            let cause = match set_slice_bytes {
                Some(_) => "SLICE_BYTES",
                None => "MAX_PUT_BYTES",
            };
            return Err(ConfigError::Invalid(cause.into()));
        }
        let max_object_extents = match optional_u64(&get, "MAX_OBJECT_EXTENTS")? {
            None => MAX_OBJECT_EXTENTS_LIMIT,
            Some(n) => u32::try_from(n)
                .ok()
                .filter(|n| (1..=MAX_OBJECT_EXTENTS_LIMIT).contains(n))
                .ok_or_else(|| ConfigError::Invalid("MAX_OBJECT_EXTENTS".into()))?,
        };
        let intent_sweep = match get("INTENT_SWEEP").as_deref().map(str::trim) {
            None | Some("") | Some("off") => false,
            Some("on") => true,
            Some(_) => return Err(ConfigError::Invalid("INTENT_SWEEP".into())),
        };
        let gc_orphans = match get("GC_ORPHANS").as_deref().map(str::trim) {
            None | Some("") | Some("off") => false,
            Some("on") => true,
            Some(_) => return Err(ConfigError::Invalid("GC_ORPHANS".into())),
        };
        let packed_plans = match get("PACKED_PLANS").as_deref().map(str::trim) {
            None | Some("") | Some("off") => false,
            Some("on") => true,
            Some(_) => return Err(ConfigError::Invalid("PACKED_PLANS".into())),
        };
        let parity = match get("PARITY").as_deref().map(str::trim) {
            None | Some("") | Some("off") => false,
            Some("on") => true,
            Some(_) => return Err(ConfigError::Invalid("PARITY".into())),
        };
        // The addendum is stored beside a packed plan only: with plans
        // of rows the switch would be on and no extent would get parity.
        if parity && !packed_plans {
            return Err(ConfigError::Refused("PARITY without PACKED_PLANS"));
        }
        let records = match get("RECORD_LAYOUT").as_deref().map(str::trim) {
            None | Some("") | Some("flat") => crate::recovery::Layout::flat(),
            Some("tenant") => {
                crate::recovery::Layout::of(&crate::tenant::TenantScope::tenant_zero())
            }
            Some(_) => return Err(ConfigError::Invalid("RECORD_LAYOUT".into())),
        };

        let required_backbones: u32 = number(&get, "REQUIRED_BACKBONES")?;
        if required_backbones == 0 {
            return Err(ConfigError::Invalid("REQUIRED_BACKBONES".into()));
        }
        if required_backbones < 2 && !dev {
            return Err(ConfigError::Refused("REQUIRED_BACKBONES < 2 outside dev"));
        }

        let safety_min_age_secs: u32 = number(&get, "SAFETY_MIN_AGE_SECS")?;
        let verify_delay_secs: u32 = number(&get, "VERIFY_DELAY_SECS")?;

        let post_sockets = number_or(&get, "POST_SOCKETS", DEFAULT_POST_SOCKETS, (1, 8))?;
        let cold_sockets = number_or(
            &get,
            "COLD_SOCKETS",
            DEFAULT_COLD_SOCKETS,
            (1, MAX_COLD_SOCKETS),
        )?;
        let propagation_grace_secs = number_or(
            &get,
            "PROPAGATION_GRACE_SECS",
            DEFAULT_PROPAGATION_GRACE_SECS,
            (0, u32::MAX),
        )?;

        let newsgroups: Vec<String> = required(&get, "NEWSGROUPS")?
            .split(',')
            .map(|g| g.trim().to_string())
            .collect();
        if !newsgroups.iter().all(|g| valid_newsgroup(g)) {
            return Err(ConfigError::Invalid("NEWSGROUPS".into()));
        }
        // A packed plan holds the newsgroup count in one byte. Past that a
        // new plan is stored as rows, which carry no parity addendum, so
        // with parity on such a list would post extents without parity.
        if parity && newsgroups.len() > usize::from(u8::MAX) {
            return Err(ConfigError::Refused("PARITY with more than 255 NEWSGROUPS"));
        }

        let kek_active: u32 = number(&get, "VELMORA_KEK_ACTIVE")?;
        if kek_active == 0 || kek_active > MAX_KEK_VERSION {
            return Err(ConfigError::Invalid("VELMORA_KEK_ACTIVE".into()));
        }
        // Presence and shape only; the key itself is held by `KekRing`.
        drop(parse_kek(&get, kek_active)?);

        let inflight_budget_bytes: u64 = number(&get, "INFLIGHT_BUDGET_BYTES")?;
        // Plaintext and ciphertext of one maximal body must fit.
        if inflight_budget_bytes < max_extent_bytes.saturating_mul(2) {
            return Err(ConfigError::Invalid("INFLIGHT_BUDGET_BYTES".into()));
        }
        // Only as many sockets as the budget has room for: what a cold
        // read of the largest extent charges is counted from the
        // ciphertext, which is a little larger than the plaintext. A
        // read that could never be charged would fail every time.
        let cipher = velmora::media::ciphertext_size(max_extent_bytes)
            .ok_or_else(|| ConfigError::Invalid("MAX_EXTENT_BYTES".into()))?;
        let fits = |sockets: &u32| {
            crate::fetch::cold_read_bytes(cipher, *sockets) <= inflight_budget_bytes
        };
        // Not even one socket: the budget is under twice the ciphertext.
        let cold_sockets = (1..=cold_sockets)
            .rev()
            .find(fits)
            .ok_or_else(|| ConfigError::Invalid("INFLIGHT_BUDGET_BYTES".into()))?;
        // Never under the request limit, and never more than half as much
        // again (see `MAX_JOB_BUDGET_NUM`).
        let job_budget_bytes: u64 = match get("JOB_BUDGET_BYTES") {
            Some(v) if !v.trim().is_empty() => v
                .trim()
                .parse()
                .map_err(|_| ConfigError::Invalid("JOB_BUDGET_BYTES".into()))?,
            _ => inflight_budget_bytes,
        };
        let job_budget_max = inflight_budget_bytes / MAX_JOB_BUDGET_DEN * MAX_JOB_BUDGET_NUM;
        if job_budget_bytes < inflight_budget_bytes || job_budget_bytes > job_budget_max {
            return Err(ConfigError::Invalid("JOB_BUDGET_BYTES".into()));
        }

        let gc_mode = match required(&get, "GC_MODE")?.as_str() {
            "off" => GcMode::Off,
            "disposable" => GcMode::Disposable,
            "full" if !REAL_DATA_READY => {
                return Err(ConfigError::Refused(
                    "GC_MODE=full while REAL_DATA_READY=false",
                ))
            }
            _ => return Err(ConfigError::Invalid("GC_MODE".into())),
        };

        // Optional: absent or empty is the default. 0 keeps nothing hot.
        let hot_cap_bytes = match get("HOT_CAP_BYTES") {
            Some(v) if !v.trim().is_empty() => v
                .trim()
                .parse::<u64>()
                .map_err(|_| ConfigError::Invalid("HOT_CAP_BYTES".into()))?,
            _ => DEFAULT_HOT_CAP_BYTES,
        };
        // SQLite sums are signed 64-bit.
        if i64::try_from(hot_cap_bytes).is_err() {
            return Err(ConfigError::Invalid("HOT_CAP_BYTES".into()));
        }

        let maintenance = match required(&get, "MAINTENANCE")?.as_str() {
            "off" => Maintenance::Off,
            "restore" => Maintenance::Restore,
            _ => return Err(ConfigError::Invalid("MAINTENANCE".into())),
        };

        // Optional: absent or empty is the default.
        let catalogue_id = match get("CATALOGUE_ID") {
            Some(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => DEFAULT_CATALOGUE_ID.to_string(),
        };
        if !valid_catalogue_id(&catalogue_id) {
            return Err(ConfigError::Invalid("CATALOGUE_ID".into()));
        }

        let get_fanout_bytes = match optional_u64(&get, "GET_FANOUT_BYTES")? {
            None | Some(0) => None,
            Some(n)
                if (crate::fanout::MIN_FANOUT_BYTES..=crate::fanout::MAX_FANOUT_BYTES)
                    .contains(&n) =>
            {
                Some(n)
            }
            Some(_) => return Err(ConfigError::Invalid("GET_FANOUT_BYTES".into())),
        };
        let server_side_copy = match required(&get, "SERVER_SIDE_COPY")?.as_str() {
            "off" => false,
            "on" => true,
            _ => return Err(ConfigError::Invalid("SERVER_SIDE_COPY".into())),
        };

        let dev_trust_http = match get("DEV_TRUST_HTTP").as_deref() {
            None | Some("") | Some("0") => false,
            Some("1") => true,
            Some(_) => return Err(ConfigError::Invalid("DEV_TRUST_HTTP".into())),
        };
        if dev_trust_http && !dev {
            return Err(ConfigError::Refused("DEV_TRUST_HTTP outside dev"));
        }

        let mut providers: Vec<ProviderConfig> =
            serde_json::from_str(&required(&get, "NNTP_PROVIDERS")?)
                .map_err(|_| ConfigError::Invalid("NNTP_PROVIDERS".into()))?;
        // Two spellings of one pool name must never be two pools, each
        // with the full shared limit: trimmed, lower case, like backbones.
        for pool in providers.iter_mut().filter_map(|p| p.pool.as_mut()) {
            *pool = pool.trim().to_lowercase();
        }
        validate_providers(&providers, dev, required_backbones)?;
        let verify = VerifyConfig::from_env(&get, &providers, dev)?;

        let admin_token = required(&get, "ADMIN_TOKEN")?;
        if admin_token.len() < MIN_ADMIN_TOKEN_LEN {
            return Err(ConfigError::Invalid("ADMIN_TOKEN".into()));
        }

        // Optional, and held to the same length as the main token. The
        // same value twice would make the read token a write token.
        let admin_read_token = match get("ADMIN_READ_TOKEN") {
            None => None,
            Some(t) if t.is_empty() => None,
            Some(t) if t.len() < MIN_ADMIN_TOKEN_LEN || t == admin_token => {
                return Err(ConfigError::Invalid("ADMIN_READ_TOKEN".into()));
            }
            Some(t) => Some(Secret::new(t)),
        };
        let admin_host = match get("ADMIN_HOST").as_deref().map(str::trim) {
            None | Some("") => None,
            Some(h)
                if h.len() <= 253
                    && h.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                    }) =>
            {
                Some(h.to_string())
            }
            Some(_) => return Err(ConfigError::Invalid("ADMIN_HOST".into())),
        };
        let metrics_sample = match get("METRICS_SAMPLE").as_deref().map(str::trim) {
            None | Some("") => DEFAULT_METRICS_SAMPLE,
            Some(v) => match v.parse::<u32>() {
                Ok(n @ 1..=10_000) => n,
                _ => return Err(ConfigError::Invalid("METRICS_SAMPLE".into())),
            },
        };

        Ok(BridgeConfig {
            environment,
            s3_host,
            s3_hosts,
            region,
            max_extent_bytes,
            max_put_bytes,
            slice_bytes,
            max_object_extents,
            intent_sweep,
            gc_orphans,
            packed_plans,
            parity,
            records,
            required_backbones,
            safety_min_age_secs,
            verify_delay_secs,
            verify,
            post_sockets,
            cold_sockets,
            propagation_grace_secs,
            newsgroups,
            kek_active,
            inflight_budget_bytes,
            job_budget_bytes,
            gc_mode,
            hot_cap_bytes,
            maintenance,
            catalogue_id,
            server_side_copy,
            get_fanout_bytes,
            dev_trust_http,
            providers,
            admin_token: Secret::new(admin_token),
            admin_read_token,
            admin_host,
            metrics_sample,
        })
    }

    pub fn is_dev(&self) -> bool {
        self.environment == Environment::Dev
    }

    /// `Some(warning)` while the provider list has fewer backbones that
    /// count toward a release than `REQUIRED_BACKBONES`. Reads and writes
    /// go on; no pinned copy is released or given up, so everything
    /// uploaded stays held until the list is put right. The text names
    /// counts only, never a provider.
    pub fn release_paused(&self) -> Option<String> {
        let counting = crate::verify::release_labels(&self.providers).len();
        (counting < self.required_backbones as usize).then(|| {
            format!(
                "release paused: {counting} backbone(s) count toward release, \
                 REQUIRED_BACKBONES is {}; pinned copies stay held",
                self.required_backbones
            )
        })
    }
}

fn validate_providers(
    providers: &[ProviderConfig],
    dev: bool,
    required_backbones: u32,
) -> Result<(), ConfigError> {
    let bad = || ConfigError::Invalid("NNTP_PROVIDERS".into());
    if providers.is_empty() {
        return Err(bad());
    }
    if providers.len() > MAX_PROVIDERS {
        return Err(bad());
    }
    let mut ids = BTreeSet::new();
    let mut pools: BTreeMap<&str, u32> = BTreeMap::new();
    for p in providers {
        // A pool limit is stated by every member, with one value, and
        // never without a pool: a shared cap is not left to guesswork.
        let pool_ok = match (p.pool.as_deref(), p.pool_max_conns) {
            (None, None) => true,
            (Some(name), Some(max)) => {
                !name.is_empty()
                    && name.len() <= MAX_POOL_NAME_LEN
                    && (1..=MAX_CONNS_LIMIT).contains(&max)
                    && *pools.entry(name).or_insert(max) == max
            }
            _ => false,
        };
        // Stated, the address limit is a real one: `0` would shut the
        // provider out without saying so (`enabled` does that).
        let ips_ok = p.max_ips.is_none_or(|n| (1..=MAX_CONNS_LIMIT).contains(&n));
        if !pool_ok || !ips_ok || !hosts_ok(p) || !proxies_ok(p) || p.retention_days == Some(0) {
            return Err(bad());
        }
        // Drill connections come from a provider that reads, and from an
        // account with an address limit only through its proxies: a
        // drill run directly would be one more address on the account,
        // and could shut a read out of it. Their slots are kept under a
        // name that no provider may have as its id.
        let drill_ok = p.drill_conns == 0
            || (p.read
                && p.drill_conns <= MAX_CONNS_LIMIT
                && (p.max_ips.is_none() || !p.proxies.is_empty()));
        if !drill_ok || p.id.ends_with(crate::types::DRILL_KEY_SUFFIX) {
            return Err(bad());
        }
        if p.id.is_empty()
            || p.host.is_empty()
            || p.backbone.is_empty()
            || p.port == 0
            || p.max_conns == 0
            || p.max_conns > MAX_CONNS_LIMIT
            || !ids.insert(p.id.as_str())
        {
            return Err(bad());
        }
        if !p.tls && !dev {
            return Err(ConfigError::Refused("plaintext NNTP provider outside dev"));
        }
        // The engine's pinned-TLS policy connects to these ports only; refuse
        // anything else here rather than failing on every connect.
        if p.tls && !TLS_PORTS.contains(&p.port) {
            return Err(bad());
        }
    }
    let usable = |role: fn(&ProviderConfig) -> bool| providers.iter().any(|p| p.enabled && role(p));
    if !usable(|p| p.post) || !usable(|p| p.read) {
        return Err(bad());
    }
    // Fewer backbones that count toward a release than
    // `REQUIRED_BACKBONES` is not refused here: the Worker has to keep
    // serving. See [`Config::release_paused`].
    let _ = required_backbones;
    Ok(())
}

/// The Worker's KEKs (`VELMORA_KEK_<v>` secrets). Only the active version
/// is loaded until a rotation adds more.
#[derive(Clone, Debug)]
pub struct KekRing {
    active: u32,
    keys: BTreeMap<u32, KekBytes>,
}

impl KekRing {
    /// Loads every `VELMORA_KEK_<v>` for `v` in `1..=active`, so data
    /// wrapped under an older version stays readable after a rotation.
    /// Fails closed when the active version is absent, or when any present
    /// version is not 32 bytes of base64. Absent older versions are skipped.
    pub fn from_vars(
        active: u32,
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<KekRing, ConfigError> {
        if active == 0 || active > MAX_KEK_VERSION {
            return Err(ConfigError::Invalid("VELMORA_KEK_ACTIVE".into()));
        }
        let mut keys = BTreeMap::new();
        keys.insert(active, parse_kek(&get, active)?);
        for v in 1..active {
            match parse_kek(&get, v) {
                Ok(key) => {
                    keys.insert(v, key);
                }
                Err(ConfigError::Missing(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(KekRing { active, keys })
    }
}

impl Kek for KekRing {
    fn active(&self) -> (u32, &KekBytes) {
        // `from_vars` always inserts the active version.
        let key = &self.keys[&self.active];
        (self.active, key)
    }

    fn version(&self, v: u32) -> Option<&KekBytes> {
        self.keys.get(&v)
    }
}
