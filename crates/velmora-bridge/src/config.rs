//! Validated configuration (frozen with the contract, DESIGN §A.8, §A.12).
//!
//! [`BridgeConfig::from_vars`] reads Worker vars and secrets through one
//! lookup function and fails closed: a missing, unparsable or unsafe value
//! is an error naming the variable, never echoing its value.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;

use crate::ports::Kek;
use crate::types::{KekBytes, ProviderConfig, Secret};

/// Real-data gate. While `false`, `create_bucket` refuses
/// `disposable = false` and `GC_MODE=full` is rejected. Only the PR that
/// lands the catalogue recovery protocol and its drill may flip it.
pub const REAL_DATA_READY: bool = false;

/// Largest request body (one extent) the slice accepts. Raised when
/// streaming bodies land.
pub const MAX_EXTENT_BYTES_LIMIT: u64 = 16 * 1024 * 1024;

/// Upper bound for `max_conns` of one provider.
pub const MAX_CONNS_LIMIT: u32 = 64;

/// Most entries `NNTP_PROVIDERS` may hold.
pub const MAX_PROVIDERS: usize = 32;

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

/// `GC_MODE`. `full` exists only once `REAL_DATA_READY` is true.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcMode {
    /// `gc` rows accumulate; nothing is deleted.
    Off,
    /// The GC job acts only for extents in `disposable = 1` buckets.
    Disposable,
}

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

/// Validated settings for one isolate.
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub environment: Environment,
    /// The host clients sign (`policy.host`).
    pub s3_host: String,
    pub region: String,
    pub max_extent_bytes: u64,
    pub required_backbones: u32,
    pub safety_min_age_secs: u32,
    pub verify_delay_secs: u32,
    /// Posting allow-list; the poster picks from it.
    pub newsgroups: Vec<String>,
    pub kek_active: u32,
    pub inflight_budget_bytes: u64,
    pub gc_mode: GcMode,
    pub maintenance: Maintenance,
    /// Accept `http://` as if it were HTTPS (`wrangler dev` only).
    pub dev_trust_http: bool,
    pub providers: Vec<ProviderConfig>,
    pub admin_token: Secret,
}

fn required(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<String, ConfigError> {
    match get(name) {
        Some(v) if !v.trim().is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(name.to_string())),
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

fn valid_newsgroup(g: &str) -> bool {
    !g.is_empty()
        && g.len() <= 128
        && !g.starts_with('.')
        && !g.ends_with('.')
        && g.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b))
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
        let region = required(&get, "S3_REGION")?;

        let max_extent_bytes: u64 = number(&get, "MAX_EXTENT_BYTES")?;
        if max_extent_bytes == 0 || max_extent_bytes > MAX_EXTENT_BYTES_LIMIT {
            return Err(ConfigError::Invalid("MAX_EXTENT_BYTES".into()));
        }

        let required_backbones: u32 = number(&get, "REQUIRED_BACKBONES")?;
        if required_backbones == 0 {
            return Err(ConfigError::Invalid("REQUIRED_BACKBONES".into()));
        }
        if required_backbones < 2 && !dev {
            return Err(ConfigError::Refused("REQUIRED_BACKBONES < 2 outside dev"));
        }

        let safety_min_age_secs: u32 = number(&get, "SAFETY_MIN_AGE_SECS")?;
        let verify_delay_secs: u32 = number(&get, "VERIFY_DELAY_SECS")?;

        let newsgroups: Vec<String> = required(&get, "NEWSGROUPS")?
            .split(',')
            .map(|g| g.trim().to_string())
            .collect();
        if !newsgroups.iter().all(|g| valid_newsgroup(g)) {
            return Err(ConfigError::Invalid("NEWSGROUPS".into()));
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

        let maintenance = match required(&get, "MAINTENANCE")?.as_str() {
            "off" => Maintenance::Off,
            "restore" => Maintenance::Restore,
            _ => return Err(ConfigError::Invalid("MAINTENANCE".into())),
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
        validate_providers(&providers, dev)?;

        let admin_token = required(&get, "ADMIN_TOKEN")?;
        if admin_token.len() < MIN_ADMIN_TOKEN_LEN {
            return Err(ConfigError::Invalid("ADMIN_TOKEN".into()));
        }

        Ok(BridgeConfig {
            environment,
            s3_host,
            region,
            max_extent_bytes,
            required_backbones,
            safety_min_age_secs,
            verify_delay_secs,
            newsgroups,
            kek_active,
            inflight_budget_bytes,
            gc_mode,
            maintenance,
            dev_trust_http,
            providers,
            admin_token: Secret::new(admin_token),
        })
    }

    pub fn is_dev(&self) -> bool {
        self.environment == Environment::Dev
    }
}

fn validate_providers(providers: &[ProviderConfig], dev: bool) -> Result<(), ConfigError> {
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
        if !pool_ok || p.retention_days == Some(0) {
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
