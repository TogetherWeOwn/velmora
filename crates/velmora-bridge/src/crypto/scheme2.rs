//! Key scheme 2: the keys of a managed tenant.
//!
//! Tenant 0 (`t_0000000000000000`) keeps scheme 1, the functions of the
//! parent module, for good. Every other tenant uses scheme 2, and only
//! scheme 2. Nothing here is called by the request path yet.
//!
//! # Key hierarchy
//!
//! ```text
//! KEK_v (deployment secret, unchanged)
//!   ├─ wraps TenantKey TK_n (32 random bytes per tenant and version n)
//!   │     blob in the key buckets only: m/tk/<t>/<n>.<v>
//!   │     AAD "velmora/tk/v1|<t>|<n>|<v>|<kcv hex>"
//!   │     ├─ HKDF "velmora/tk-wrap/v1"         → wraps BDK   AAD "velmora/bdk/v2|<t>|<bucket_id>|<n>"
//!   │     │     └─ wraps FileKey (unchanged)               AAD "velmora/fk/v1|<bucket_id>|<extent_id>"
//!   │     ├─ HKDF "velmora/manifest/v2"        → seals VMR2 data records under m/x/<t>/
//!   │     ├─ HKDF "velmora/control-private/v1" → seals the private part of a control record
//!   │     └─ HKDF "velmora/tk-check/v1"        → key check value (8 bytes)
//!   ├─ wraps S3 secrets of a managed tenant                AAD "velmora/ak/v2|<akid>|<t>|<v>"
//!   ├─ HKDF "velmora/control/v1"               → seals the door part of every control record
//!   └─ HKDF "velmora/control-private/v1"       → seals the private part of tenant 0's control records
//! ```
//!
//! - **The TK is never used directly.** Each use is its own HKDF-SHA256
//!   output (no salt, the info string above), the key check value too.
//! - **FileKey wraps do not change.** Their AAD binds bucket and extent,
//!   and a bucket id is never reused across tenants.
//! - **S3 secrets stay under the KEK.** They are needed before a tenant
//!   key is loaded. The v2 AAD adds the tenant, so a row moved to another
//!   tenant does not open.
//!
//! # Formats
//!
//! | What | Bytes |
//! |---|---|
//! | BDK wrap, scheme 2 | `0x02 ‖ nonce[24] ‖ ct[32] ‖ tag[16]` (73) |
//! | S3 secret wrap, `ak/v2` | `0x02 ‖ nonce[24] ‖ ct ‖ tag[16]` |
//! | TK blob | `kcv[8] ‖ 0x01 ‖ nonce[24] ‖ ct[32] ‖ tag[16]` (81) |
//! | VMR2 data record | `"VMR2" ‖ tenant[18] ‖ tk_version (u32 BE) ‖ 0x01 ‖ nonce[24] ‖ ct ‖ tag[16]` |
//! | Control record | `"VCR1" ‖ kek_v ‖ kind ‖ priv_v ‖ door_len ‖ priv_len ‖ door wrap ‖ private wrap` |
//!
//! A VMR2 record cannot be taken for a v1 record: a v1 record starts
//! with its KEK version as a big-endian `u32`, and versions are capped
//! far below `0x56000000`, so its first byte is always zero.
//!
//! # What selects the scheme
//!
//! The tenant id, and nothing else ([`Scheme::of`]). A version byte read
//! from a row or an envelope is only checked against the scheme the
//! tenant has ([`Scheme::check`]); it never picks the code path. A
//! scheme-1 wrap inside a managed tenant would open under the KEK alone
//! and survive that tenant's shred, so a mismatch is an error, never a
//! fallback.
//!
//! # Control records
//!
//! A control record (tenant chain `m/t/`, key chain `m/k/`, key-chain
//! checkpoints `m/kc/`, key locations `m/kl/`) has two parts:
//!
//! - the **door part**, under the control key (KEK-derived): what a gate
//!   needs to close a door without the tenant key;
//! - the **private part**, under a key the header names: the TK-derived
//!   key of a managed tenant, a KEK-derived key for tenant 0, or nothing
//!   for a global record.
//!
//! The 21-byte header names the KEK version of the door part, the kind
//! and version of the private key and both lengths. The private part is
//! sealed first, with the record name, the owner and the header as AAD.
//! The door part is sealed with the same AAD **plus the SHA-256 of the
//! sealed private part**, so opening the door with the control key alone
//! proves the whole record: no private part can be swapped in from
//! another record, and none can be cut off. The private part is reached
//! only through an opened door ([`OpenedControl`]).
//!
//! The name of a control record must lie in its owner's directories:
//! [`MANAGED_CONTROL_DIRS`] followed by the tenant id for a tenant's own
//! records (tenant 0's too), [`GLOBAL_CONTROL_DIRS`] for a record sealed
//! with a door part only. Sealing and opening both refuse any other name.
//!
//! # A tenant key knows whose it is
//!
//! A [`TenantKey`] carries its tenant and its key version, and every
//! function takes them from the key. A key of one tenant can therefore
//! not wrap or seal for another tenant, nor under another version label;
//! and every open function compares the tenant and the version that the
//! data names with the key's.

use core::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use velmora::rng::FillRandom;
use zeroize::Zeroizing;

use super::{
    binding_id, kek_version, unwrap_bytes_as, wrap_bytes_as, DataKey, ERR_RNG, ERR_SECRET_LEN,
    ERR_UNWRAP, ERR_WRAP, KEY_LEN, MAX_SECRET_LEN, WRAPPED_KEY_LEN, WRAP_OVERHEAD, WRAP_VERSION,
};
use crate::ports::Kek;
use crate::recovery::{DEFAULT_TENANT, TENANT_DIR};
use crate::types::{BridgeError, BucketId, KekBytes, Result};

/// First byte of every scheme-2 wrap of a key or a secret.
pub const WRAP_VERSION_2: u8 = 0x02;
/// A managed tenant id: `t_` and 16 lowercase hex digits.
pub const TENANT_ID_LEN: usize = 18;
/// Length of a key check value.
pub const KCV_LEN: usize = 8;
/// Length of a TK blob: `kcv ‖ 0x01 ‖ nonce ‖ ct ‖ tag`.
pub const TK_BLOB_LEN: usize = KCV_LEN + WRAPPED_KEY_LEN;
/// First four bytes of a VMR2 data record.
pub const RECORD_V2_MAGIC: &[u8; 4] = b"VMR2";
/// Bytes before the wrap of a VMR2 record: magic, tenant, TK version.
pub const RECORD_V2_HEADER_LEN: usize = 4 + TENANT_ID_LEN + 4;
/// First four bytes of a control record.
pub const CONTROL_MAGIC: &[u8; 4] = b"VCR1";
/// Length of a control record's header.
pub const CONTROL_HEADER_LEN: usize = 4 + 4 + 1 + 4 + 4 + 4;
/// Where the wrapped tenant keys live, in the key buckets only.
pub const TK_PREFIX: &str = "m/tk/";
/// The directories of a tenant's own control records, each followed by
/// the tenant id and `/`: the tenant chain, the key chain, the key-chain
/// checkpoints, and the bucket configuration chains below the tenant's
/// record directory (`m/x/<t>/b/`).
pub const MANAGED_CONTROL_DIRS: [&str; 4] = ["m/t/", "m/k/", "m/kc/", "m/x/"];
/// The directories of control records with a door part only: key
/// locations, the registry, routes, revocations of keys and of service
/// tokens, born markers and external references.
pub const GLOBAL_CONTROL_DIRS: [&str; 7] = [
    "m/kl/", "m/reg/", "m/kr/", "m/rk/", "m/rst/", "m/ub/", "m/tref/",
];

const TK_DOMAIN: &str = "velmora/tk/v1";
const TK_WRAP_INFO: &[u8] = b"velmora/tk-wrap/v1";
const TK_CHECK_INFO: &[u8] = b"velmora/tk-check/v1";
const MANIFEST_V2_DOMAIN: &str = "velmora/manifest/v2";
const CONTROL_DOOR_DOMAIN: &str = "velmora/control/v1";
const CONTROL_PRIVATE_DOMAIN: &str = "velmora/control-private/v1";
const BDK_V2_DOMAIN: &str = "velmora/bdk/v2";
const AK_V2_DOMAIN: &str = "velmora/ak/v2";
/// The bucket configuration directory below `m/x/<t>/`.
const BUCKET_CONFIG_DIR: &str = "b/";
/// The owner of a global control record in an AAD. No tenant id can be
/// it.
const GLOBAL_OWNER: &str = "-";

const PRIVATE_NONE: u8 = 0;
const PRIVATE_KEK: u8 = 1;
const PRIVATE_TENANT: u8 = 2;

// Fixed strings only: no key, id or ciphertext byte reaches an error.
const ERR_TENANT_ID: BridgeError = BridgeError::Invalid("not a managed tenant id");
const ERR_SCHEME: BridgeError = BridgeError::Crypto("key scheme does not match the tenant");
const ERR_TK_VERSION: BridgeError = BridgeError::Crypto("tenant key version invalid");
const ERR_TK_BLOB: BridgeError = BridgeError::Crypto("tenant key blob invalid");
const ERR_TK_CHECK: BridgeError = BridgeError::Crypto("tenant key check value mismatch");
const ERR_TK_OTHER: BridgeError = BridgeError::Crypto("tenant key is not the one the data names");
const ERR_RECORD_V2: BridgeError = BridgeError::Crypto("v2 record authentication failed");
const ERR_RECORD_TENANT: BridgeError = BridgeError::Crypto("record names another tenant");
const ERR_CONTROL: BridgeError = BridgeError::Crypto("control record authentication failed");
const ERR_CONTROL_FORMAT: BridgeError = BridgeError::Crypto("control record malformed");
const ERR_CONTROL_KIND: BridgeError =
    BridgeError::Crypto("control record private key does not match its owner");
const ERR_CONTROL_NAME: BridgeError =
    BridgeError::Crypto("control record name does not match its owner");

// ---------------------------------------------------------------------------
// Tenant ids and the scheme
// ---------------------------------------------------------------------------

/// The id of a managed tenant: `t_` and 16 lowercase hex digits, and not
/// tenant 0. Holding one proves the id is well formed; it says nothing
/// about whether the tenant exists.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(String);

impl TenantId {
    /// Accepts a managed tenant id. Refuses tenant 0, which is scheme 1.
    pub fn parse(id: &str) -> Result<TenantId> {
        let hex = id.strip_prefix("t_").ok_or(ERR_TENANT_ID)?;
        let well_formed = hex.len() == TENANT_ID_LEN - 2
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !well_formed || id == DEFAULT_TENANT {
            return Err(ERR_TENANT_ID);
        }
        Ok(TenantId(id.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key scheme of a tenant, chosen by its id alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Tenant 0: KEK-wrapped BDKs, `ak/v1`, v1 record bodies.
    One,
    /// A managed tenant: TK-wrapped BDKs, `ak/v2`, VMR2 envelopes.
    Two(TenantId),
}

impl Scheme {
    /// The scheme of `tenant`: tenant 0 is scheme 1, a managed tenant id
    /// is scheme 2, and anything else is an error.
    pub fn of(tenant: &str) -> Result<Scheme> {
        if tenant == DEFAULT_TENANT {
            return Ok(Scheme::One);
        }
        TenantId::parse(tenant).map(Scheme::Two)
    }

    /// The first byte every wrap of this scheme has.
    pub fn wrap_byte(&self) -> u8 {
        match self {
            Scheme::One => WRAP_VERSION,
            Scheme::Two(_) => WRAP_VERSION_2,
        }
    }

    /// Refuses a wrapped column whose first byte is not this scheme's.
    /// The caller alarms on the error: a wrap of the other scheme in a
    /// tenant's row is a bug or a planted row, never a fallback.
    pub fn check(&self, wrapped: &[u8]) -> Result<()> {
        match wrapped.first() {
            Some(&b) if b == self.wrap_byte() => Ok(()),
            _ => Err(ERR_SCHEME),
        }
    }
}

// ---------------------------------------------------------------------------
// Tenant keys
// ---------------------------------------------------------------------------

/// A tenant key (TK): 32 random bytes for one tenant and one key
/// version, which the key carries. Zeroed on drop; never rendered by
/// `Debug`; never used directly, only through the HKDF outputs of this
/// module.
pub struct TenantKey {
    tenant: TenantId,
    version: u32,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl TenantKey {
    /// A fresh random key for key version `version` of `tenant`.
    pub fn generate<R: FillRandom>(tenant: &TenantId, version: u32, rng: &mut R) -> Result<Self> {
        let version = valid_tk_version(version)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        rng.fill_bytes(key.as_mut()).map_err(|_| ERR_RNG)?;
        Ok(TenantKey {
            tenant: tenant.clone(),
            version,
            key,
        })
    }

    /// Existing key bytes for key version `version` of `tenant`. Tests
    /// only: nothing checks that the bytes are that tenant's key. A key
    /// from a key bucket or an escrow copy comes from
    /// [`unwrap_tenant_key`], which checks the blob's name and check
    /// value. The caller's copy is its own to wipe.
    #[cfg(any(test, feature = "testkit"))]
    pub fn from_bytes(tenant: &TenantId, version: u32, bytes: [u8; KEY_LEN]) -> Result<Self> {
        Ok(TenantKey {
            tenant: tenant.clone(),
            version: valid_tk_version(version)?,
            key: Zeroizing::new(bytes),
        })
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// The key check value: the first 8 bytes of
    /// `HKDF-SHA256(TK, "velmora/tk-check/v1")`. The same for every KEK
    /// wrap of the same key, and it reveals nothing about the key.
    pub fn check_value(&self) -> [u8; KCV_LEN] {
        let full = self.derive(TK_CHECK_INFO);
        let mut kcv = [0u8; KCV_LEN];
        kcv.copy_from_slice(&full[..KCV_LEN]);
        kcv
    }

    fn derive(&self, info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
        derive_key(&self.key, info)
    }

    /// Refuses a key that is not version `version` of `tenant`.
    fn is(&self, tenant: &TenantId, version: u32) -> Result<()> {
        if self.tenant != *tenant || self.version != version {
            return Err(ERR_TK_OTHER);
        }
        Ok(())
    }
}

impl fmt::Debug for TenantKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantKey")
            .field("tenant", &self.tenant)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

fn derive_key(ikm: &[u8; KEY_LEN], info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, key.as_mut())
        .expect("HKDF-SHA256 output of 32 bytes");
    key
}

/// Copies an opened 32-byte key into wiped-on-drop storage, with no
/// plain copy on the way.
fn key_bytes(plain: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if plain.len() != KEY_LEN {
        return Err(ERR_UNWRAP);
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(plain);
    Ok(out)
}

fn valid_tk_version(tk_version: u32) -> Result<u32> {
    // Version 0 is tenant 0's "no tenant key".
    if tk_version == 0 {
        return Err(ERR_TK_VERSION);
    }
    Ok(tk_version)
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The name of a TK blob in a key bucket: `m/tk/<t>/<n>.<v>`, with `n`
/// the key version and `v` the KEK version that wraps it. Names are
/// write-once: a KEK rotation writes new names and never overwrites.
pub fn tk_blob_name(tenant: &TenantId, tk_version: u32, kek_version: u32) -> String {
    format!("{TK_PREFIX}{tenant}/{tk_version}.{kek_version}")
}

fn tk_aad(tenant: &TenantId, tk_version: u32, kek_version: u32, kcv: &[u8; KCV_LEN]) -> String {
    format!(
        "{TK_DOMAIN}|{tenant}|{tk_version}|{kek_version}|{}",
        hex(kcv)
    )
}

/// Wraps a tenant key under the **active** KEK. Returns the KEK version
/// (it is part of the blob's name) and the 81-byte blob.
pub fn wrap_tenant_key<K: Kek, R: FillRandom>(
    kek: &K,
    tk: &TenantKey,
    rng: &mut R,
) -> Result<(u32, Vec<u8>)> {
    let (version, _) = kek.active();
    let blob = wrap_tenant_key_as(kek, version, tk, rng)?;
    Ok((version, blob))
}

/// Wraps a tenant key under KEK version `kek_version_to_use`, which need
/// not be the active one: a KEK rotation writes `<n>.<v+1>` beside
/// `<n>.<v>`.
pub fn wrap_tenant_key_as<K: Kek, R: FillRandom>(
    kek: &K,
    kek_version_to_use: u32,
    tk: &TenantKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let key = kek_version(kek, kek_version_to_use)?;
    let kcv = tk.check_value();
    let aad = tk_aad(&tk.tenant, tk.version, kek_version_to_use, &kcv);
    let wrapped = wrap_bytes_as(WRAP_VERSION, key.expose(), aad.as_bytes(), &tk.key[..], rng)?;
    let mut blob = Vec::with_capacity(TK_BLOB_LEN);
    blob.extend_from_slice(&kcv);
    blob.extend_from_slice(&wrapped);
    if blob.len() != TK_BLOB_LEN {
        return Err(ERR_WRAP);
    }
    Ok(blob)
}

/// The key check value a TK blob carries, read without any key. Used to
/// compare the copies of one key version across key locations.
pub fn tk_blob_check_value(blob: &[u8]) -> Result<[u8; KCV_LEN]> {
    if blob.len() != TK_BLOB_LEN || blob[KCV_LEN] != WRAP_VERSION {
        return Err(ERR_TK_BLOB);
    }
    let mut kcv = [0u8; KCV_LEN];
    kcv.copy_from_slice(&blob[..KCV_LEN]);
    Ok(kcv)
}

/// Opens a TK blob stored as `m/tk/<tenant>/<tk_version>.<kek_version>`.
/// Fails unless the blob was made for exactly that name, and unless the
/// key inside has the check value the blob carries. The key it returns
/// is bound to `tenant` and `tk_version`.
pub fn unwrap_tenant_key<K: Kek>(
    kek: &K,
    kek_version_stored: u32,
    tenant: &TenantId,
    tk_version: u32,
    blob: &[u8],
) -> Result<TenantKey> {
    let tk_version = valid_tk_version(tk_version)?;
    let kcv = tk_blob_check_value(blob)?;
    let key = kek_version(kek, kek_version_stored)?;
    let aad = tk_aad(tenant, tk_version, kek_version_stored, &kcv);
    let plain = unwrap_bytes_as(WRAP_VERSION, key.expose(), aad.as_bytes(), &blob[KCV_LEN..])?;
    let tk = TenantKey {
        tenant: tenant.clone(),
        version: tk_version,
        key: key_bytes(&plain)?,
    };
    // The AAD already binds the check value; this proves the writer put
    // the check value of this key and not of another one.
    if !bool::from(tk.check_value()[..].ct_eq(&kcv)) {
        return Err(ERR_TK_CHECK);
    }
    Ok(tk)
}

// ---------------------------------------------------------------------------
// Bucket data keys, scheme 2
// ---------------------------------------------------------------------------

fn bdk_v2_aad(tenant: &TenantId, bucket: &BucketId, tk_version: u32) -> Result<String> {
    Ok(format!(
        "{BDK_V2_DOMAIN}|{tenant}|{}|{tk_version}",
        binding_id(bucket.as_str())?
    ))
}

/// Wraps a bucket data key under the tenant key `tk` (its tenant and its
/// version): `0x02 ‖ nonce ‖ ct ‖ tag`, 73 bytes. The row stores
/// `tk.version()` beside it.
pub fn wrap_bdk_v2<R: FillRandom>(
    tk: &TenantKey,
    bucket: &BucketId,
    bdk: &DataKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let aad = bdk_v2_aad(&tk.tenant, bucket, tk.version)?;
    let wrap_key = tk.derive(TK_WRAP_INFO);
    let wrapped = wrap_bytes_as(WRAP_VERSION_2, &wrap_key, aad.as_bytes(), &bdk.0[..], rng)?;
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(ERR_WRAP);
    }
    Ok(wrapped)
}

/// Unwraps a scheme-2 bucket data key of `tenant`'s bucket `bucket`,
/// stored with key version `tk_version`. Refuses a key that is not that
/// version of that tenant's key, a scheme-1 wrap, a wrap of another
/// tenant, bucket or version, and any changed byte.
pub fn unwrap_bdk_v2(
    tk: &TenantKey,
    tenant: &TenantId,
    tk_version: u32,
    bucket: &BucketId,
    wrapped: &[u8],
) -> Result<DataKey> {
    tk.is(tenant, tk_version)?;
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(ERR_UNWRAP);
    }
    let aad = bdk_v2_aad(tenant, bucket, tk_version)?;
    let wrap_key = tk.derive(TK_WRAP_INFO);
    let plain = unwrap_bytes_as(WRAP_VERSION_2, &wrap_key, aad.as_bytes(), wrapped)?;
    Ok(DataKey(key_bytes(&plain)?))
}

// ---------------------------------------------------------------------------
// S3 secret access keys, ak/v2
// ---------------------------------------------------------------------------

fn access_key_v2_aad(access_key_id: &str, tenant: &TenantId, kek_version: u32) -> Result<String> {
    Ok(format!(
        "{AK_V2_DOMAIN}|{}|{tenant}|{kek_version}",
        binding_id(access_key_id)?
    ))
}

/// Wraps an S3 secret access key of `tenant` under the **active** KEK:
/// `0x02 ‖ nonce ‖ ct ‖ tag`. Returns the KEK version to store with it.
pub fn wrap_secret_v2<K: Kek, R: FillRandom>(
    kek: &K,
    tenant: &TenantId,
    access_key_id: &str,
    secret: &[u8],
    rng: &mut R,
) -> Result<(u32, Vec<u8>)> {
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(ERR_SECRET_LEN);
    }
    let (version, key) = kek.active();
    let aad = access_key_v2_aad(access_key_id, tenant, version)?;
    let wrapped = wrap_bytes_as(WRAP_VERSION_2, key.expose(), aad.as_bytes(), secret, rng)?;
    Ok((version, wrapped))
}

/// Unwraps an `ak/v2` secret with the KEK version stored with it. Fails
/// for an `ak/v1` wrap and for a wrap of another key id or tenant.
pub fn unwrap_secret_v2<K: Kek>(
    kek: &K,
    kek_version_stored: u32,
    tenant: &TenantId,
    access_key_id: &str,
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if wrapped.len() <= WRAP_OVERHEAD || wrapped.len() > MAX_SECRET_LEN + WRAP_OVERHEAD {
        return Err(ERR_UNWRAP);
    }
    let key = kek_version(kek, kek_version_stored)?;
    let aad = access_key_v2_aad(access_key_id, tenant, kek_version_stored)?;
    unwrap_bytes_as(WRAP_VERSION_2, key.expose(), aad.as_bytes(), wrapped)
}

// ---------------------------------------------------------------------------
// VMR2 data records
// ---------------------------------------------------------------------------

fn record_v2_aad(name: &str, tenant: &TenantId, tk_version: u32) -> Result<String> {
    Ok(format!(
        "{MANIFEST_V2_DOMAIN}|{}|{tenant}|{tk_version}",
        binding_id(name)?
    ))
}

/// The part of `name` after `<dir><tenant>/`; `None` when `name` does not
/// lie below that directory or nothing follows it.
fn below<'a>(name: &'a str, dir: &str, tenant: &str) -> Option<&'a str> {
    name.strip_prefix(dir)?
        .strip_prefix(tenant)?
        .strip_prefix('/')
        .filter(|rest| !rest.is_empty())
}

/// Whether `name` is a data record of `tenant`: below `m/x/<t>/`, and
/// not below its bucket configuration directory `m/x/<t>/b/`, which
/// holds control records.
fn under_tenant_dir(name: &str, tenant: &TenantId) -> bool {
    below(name, TENANT_DIR, tenant.as_str())
        .is_some_and(|rest| !rest.starts_with(BUCKET_CONFIG_DIR))
}

/// Whether `sealed` starts like a VMR2 record. Says nothing about
/// whether it opens.
pub fn is_record_v2(sealed: &[u8]) -> bool {
    sealed.starts_with(RECORD_V2_MAGIC)
}

/// The tenant and the TK version a VMR2 envelope names, read without any
/// key. The reader compares the tenant with the one in the record's name
/// and loads the key version from it.
pub fn record_v2_header(sealed: &[u8]) -> Result<(TenantId, u32)> {
    if sealed.len() < RECORD_V2_HEADER_LEN + WRAP_OVERHEAD || !is_record_v2(sealed) {
        return Err(ERR_RECORD_V2);
    }
    // An envelope that names no managed tenant (tenant 0, or bytes that
    // are no id) is another tenant's record for every reader: the alarm
    // error, not the generic one.
    let tenant = core::str::from_utf8(&sealed[4..4 + TENANT_ID_LEN])
        .ok()
        .and_then(|t| TenantId::parse(t).ok())
        .ok_or(ERR_RECORD_TENANT)?;
    Ok((tenant, header_version(sealed)))
}

fn header_version(sealed: &[u8]) -> u32 {
    let mut version = [0u8; 4];
    version.copy_from_slice(&sealed[4 + TENANT_ID_LEN..RECORD_V2_HEADER_LEN]);
    u32::from_be_bytes(version)
}

/// Seals a data record of `tk`'s tenant stored under `name`, which must
/// lie in `m/x/<tenant>/`, under `tk`'s version.
pub fn seal_record_v2<R: FillRandom>(
    tk: &TenantKey,
    name: &str,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    if !under_tenant_dir(name, &tk.tenant) {
        return Err(ERR_RECORD_TENANT);
    }
    let aad = record_v2_aad(name, &tk.tenant, tk.version)?;
    let key = tk.derive(MANIFEST_V2_DOMAIN.as_bytes());
    let wrapped = wrap_bytes_as(WRAP_VERSION, &key, aad.as_bytes(), plaintext, rng)?;
    let mut out = Vec::with_capacity(RECORD_V2_HEADER_LEN + wrapped.len());
    out.extend_from_slice(RECORD_V2_MAGIC);
    out.extend_from_slice(tk.tenant.as_str().as_bytes());
    out.extend_from_slice(&tk.version.to_be_bytes());
    out.extend_from_slice(&wrapped);
    Ok(out)
}

/// Opens a VMR2 record stored under `name` for `tenant`. Refuses, with
/// its own error that the reader alarms on, a record whose name or
/// envelope names another tenant (tenant 0, or an id that does not
/// parse, included); then refuses a key that is not the version the
/// envelope names, and any record that does not authenticate.
pub fn open_record_v2(
    tk: &TenantKey,
    tenant: &TenantId,
    name: &str,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < RECORD_V2_HEADER_LEN + WRAP_OVERHEAD || !is_record_v2(sealed) {
        return Err(ERR_RECORD_V2);
    }
    // The raw bytes, before any parse: an envelope that names tenant 0
    // or no tenant at all is another tenant's too.
    let envelope_tenant = &sealed[4..4 + TENANT_ID_LEN];
    if envelope_tenant != tenant.as_str().as_bytes() || !under_tenant_dir(name, tenant) {
        return Err(ERR_RECORD_TENANT);
    }
    let version = header_version(sealed);
    tk.is(tenant, version)?;
    let aad = record_v2_aad(name, tenant, version)?;
    let key = tk.derive(MANIFEST_V2_DOMAIN.as_bytes());
    unwrap_bytes_as(
        WRAP_VERSION,
        &key,
        aad.as_bytes(),
        &sealed[RECORD_V2_HEADER_LEN..],
    )
    .map_err(|_| ERR_RECORD_V2)
}

// ---------------------------------------------------------------------------
// Two-part control records
// ---------------------------------------------------------------------------

/// Who a control record belongs to, with the key its private part is
/// sealed under.
pub enum ControlSealer<'a> {
    /// A global record: a door part only.
    Global,
    /// Tenant 0: the private part under a KEK-derived key (the active
    /// KEK).
    TenantZero,
    /// A managed tenant: the private part under its tenant key, whose
    /// tenant and version the record names.
    Managed(&'a TenantKey),
}

/// Who a control record belongs to, as a reader names it. The reader
/// takes it from the record's name, never from the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlOwner<'a> {
    Global,
    TenantZero,
    Managed(&'a TenantId),
}

impl ControlOwner<'_> {
    fn label(&self) -> &str {
        match self {
            ControlOwner::Global => GLOBAL_OWNER,
            ControlOwner::TenantZero => DEFAULT_TENANT,
            ControlOwner::Managed(t) => t.as_str(),
        }
    }

    fn private_kind(&self) -> u8 {
        match self {
            ControlOwner::Global => PRIVATE_NONE,
            ControlOwner::TenantZero => PRIVATE_KEK,
            ControlOwner::Managed(_) => PRIVATE_TENANT,
        }
    }

    /// Whether `name` lies in this owner's directories.
    fn owns(&self, name: &str) -> bool {
        match self {
            ControlOwner::Global => GLOBAL_CONTROL_DIRS
                .iter()
                .any(|dir| name.strip_prefix(dir).is_some_and(|rest| !rest.is_empty())),
            ControlOwner::TenantZero | ControlOwner::Managed(_) => {
                MANAGED_CONTROL_DIRS.iter().any(|dir| {
                    below(name, dir, self.label()).is_some_and(|rest| {
                        // Below `m/x/<t>/` only the bucket configuration
                        // chains `b/<bucket>/...` are control records; the
                        // rest are data records.
                        *dir != TENANT_DIR
                            || rest
                                .strip_prefix(BUCKET_CONFIG_DIR)
                                .is_some_and(|r| !r.is_empty())
                    })
                })
            }
        }
    }
}

impl ControlSealer<'_> {
    fn owner(&self) -> ControlOwner<'_> {
        match self {
            ControlSealer::Global => ControlOwner::Global,
            ControlSealer::TenantZero => ControlOwner::TenantZero,
            ControlSealer::Managed(tk) => ControlOwner::Managed(&tk.tenant),
        }
    }
}

/// The key a control record's private part is sealed under, as its
/// header names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateKeyRef {
    /// No private part (a global record).
    None,
    /// Tenant 0: the KEK of this version.
    Kek(u32),
    /// A managed tenant: its tenant key of this version.
    Tenant(u32),
}

fn control_door_key(kek: &KekBytes) -> Zeroizing<[u8; KEY_LEN]> {
    derive_key(kek.expose(), CONTROL_DOOR_DOMAIN.as_bytes())
}

fn control_private_kek_key(kek: &KekBytes) -> Zeroizing<[u8; KEY_LEN]> {
    derive_key(kek.expose(), CONTROL_PRIVATE_DOMAIN.as_bytes())
}

fn control_aad(domain: &str, name: &str, owner: &str, header: &[u8]) -> Result<Vec<u8>> {
    let name = binding_id(name)?;
    let mut aad = Vec::with_capacity(domain.len() + name.len() + owner.len() + 3 + header.len());
    aad.extend_from_slice(domain.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(name.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(owner.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(header);
    Ok(aad)
}

fn len_u32(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| ERR_CONTROL_FORMAT)
}

/// Seals a control record stored under `name`, which must lie in the
/// owner's directories: the door part under the control key of the
/// active KEK, the private part under the key of `sealer`. A global
/// record takes no private part; tenant 0 and a managed tenant always
/// have one (it may be empty).
pub fn seal_control<K: Kek, R: FillRandom>(
    kek: &K,
    name: &str,
    sealer: &ControlSealer<'_>,
    door: &[u8],
    private: Option<&[u8]>,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let owner = sealer.owner();
    if !owner.owns(name) {
        return Err(ERR_CONTROL_NAME);
    }
    let (kek_v, kek_bytes) = kek.active();
    let (kind, priv_v) = match sealer {
        ControlSealer::Global => (PRIVATE_NONE, 0),
        ControlSealer::TenantZero => (PRIVATE_KEK, kek_v),
        ControlSealer::Managed(tk) => (PRIVATE_TENANT, tk.version),
    };
    let private = match (kind, private) {
        (PRIVATE_NONE, None) => None,
        (PRIVATE_NONE, Some(_)) | (_, None) => return Err(ERR_CONTROL_KIND),
        (_, Some(p)) => Some(p),
    };
    let door_len = len_u32(door.len() + WRAP_OVERHEAD)?;
    let priv_len = match private {
        None => 0,
        Some(p) => len_u32(p.len() + WRAP_OVERHEAD)?,
    };

    let mut header = Vec::with_capacity(CONTROL_HEADER_LEN);
    header.extend_from_slice(CONTROL_MAGIC);
    header.extend_from_slice(&kek_v.to_be_bytes());
    header.push(kind);
    header.extend_from_slice(&priv_v.to_be_bytes());
    header.extend_from_slice(&door_len.to_be_bytes());
    header.extend_from_slice(&priv_len.to_be_bytes());

    let private_sealed = match (private, sealer) {
        (None, _) => Vec::new(),
        (Some(p), ControlSealer::Managed(tk)) => {
            let aad = control_aad(CONTROL_PRIVATE_DOMAIN, name, owner.label(), &header)?;
            let key = tk.derive(CONTROL_PRIVATE_DOMAIN.as_bytes());
            wrap_bytes_as(WRAP_VERSION, &key, &aad, p, rng)?
        }
        (Some(p), _) => {
            let aad = control_aad(CONTROL_PRIVATE_DOMAIN, name, owner.label(), &header)?;
            let key = control_private_kek_key(kek_bytes);
            wrap_bytes_as(WRAP_VERSION, &key, &aad, p, rng)?
        }
    };

    let mut door_aad = control_aad(CONTROL_DOOR_DOMAIN, name, owner.label(), &header)?;
    door_aad.extend_from_slice(&Sha256::digest(&private_sealed));
    let door_sealed = wrap_bytes_as(
        WRAP_VERSION,
        &control_door_key(kek_bytes),
        &door_aad,
        door,
        rng,
    )?;

    let mut out = header;
    out.extend_from_slice(&door_sealed);
    out.extend_from_slice(&private_sealed);
    Ok(out)
}

/// A control record split into its parts. Nothing in it is trusted
/// before [`ControlEnvelope::open_door`] succeeded, and its private part
/// is reached only through what that returns.
pub struct ControlEnvelope<'a> {
    header: &'a [u8],
    kek_version: u32,
    kind: u8,
    private_version: u32,
    door: &'a [u8],
    private: &'a [u8],
}

impl fmt::Debug for ControlEnvelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlEnvelope")
            .field("kek_version", &self.kek_version)
            .field("private_key", &self.private_key())
            .finish_non_exhaustive()
    }
}

fn be_u32(bytes: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&bytes[at..at + 4]);
    u32::from_be_bytes(b)
}

/// Splits a control record. Refuses one whose lengths do not add up to
/// its size or whose private-key kind is unknown or does not fit its
/// lengths.
pub fn parse_control(bytes: &[u8]) -> Result<ControlEnvelope<'_>> {
    if bytes.len() < CONTROL_HEADER_LEN || !bytes.starts_with(CONTROL_MAGIC) {
        return Err(ERR_CONTROL_FORMAT);
    }
    let kek_version = be_u32(bytes, 4);
    let kind = bytes[8];
    let private_version = be_u32(bytes, 9);
    let door_len = be_u32(bytes, 13) as usize;
    let priv_len = be_u32(bytes, 17) as usize;
    let body = &bytes[CONTROL_HEADER_LEN..];
    let lengths_fit = door_len >= WRAP_OVERHEAD
        && door_len
            .checked_add(priv_len)
            .is_some_and(|n| n == body.len());
    let kind_fits = match kind {
        PRIVATE_NONE => priv_len == 0 && private_version == 0,
        PRIVATE_KEK | PRIVATE_TENANT => priv_len >= WRAP_OVERHEAD && private_version != 0,
        _ => false,
    };
    if !lengths_fit || !kind_fits {
        return Err(ERR_CONTROL_FORMAT);
    }
    let (door, private) = body.split_at(door_len);
    Ok(ControlEnvelope {
        header: &bytes[..CONTROL_HEADER_LEN],
        kek_version,
        kind,
        private_version,
        door,
        private,
    })
}

impl<'a> ControlEnvelope<'a> {
    /// The KEK version the door part is sealed under.
    pub fn kek_version(&self) -> u32 {
        self.kek_version
    }

    /// The key the private part is sealed under. Not authenticated
    /// before [`Self::open_door`] succeeded.
    pub fn private_key(&self) -> PrivateKeyRef {
        match self.kind {
            PRIVATE_KEK => PrivateKeyRef::Kek(self.private_version),
            PRIVATE_TENANT => PrivateKeyRef::Tenant(self.private_version),
            _ => PrivateKeyRef::None,
        }
    }

    /// Opens the door part of a record stored under `name` for `owner`.
    /// Success proves the whole record, the private part included, with
    /// the control key alone.
    pub fn open_door<K: Kek>(
        self,
        kek: &K,
        name: &'a str,
        owner: ControlOwner<'a>,
    ) -> Result<OpenedControl<'a>> {
        if self.kind != owner.private_kind() {
            return Err(ERR_CONTROL_KIND);
        }
        if !owner.owns(name) {
            return Err(ERR_CONTROL_NAME);
        }
        let key = kek_version(kek, self.kek_version)?;
        let mut aad = control_aad(CONTROL_DOOR_DOMAIN, name, owner.label(), self.header)?;
        aad.extend_from_slice(&Sha256::digest(self.private));
        let door = unwrap_bytes_as(WRAP_VERSION, &control_door_key(key), &aad, self.door)
            .map_err(|_| ERR_CONTROL)?;
        Ok(OpenedControl {
            env: self,
            name,
            owner,
            door,
        })
    }
}

/// A control record whose door part opened: the whole record is proven.
pub struct OpenedControl<'a> {
    env: ControlEnvelope<'a>,
    name: &'a str,
    owner: ControlOwner<'a>,
    door: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for OpenedControl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedControl")
            .field("env", &self.env)
            .finish_non_exhaustive()
    }
}

impl OpenedControl<'_> {
    /// The door part's plaintext.
    pub fn door(&self) -> &[u8] {
        &self.door
    }

    /// The key the private part is sealed under, now authenticated.
    pub fn private_key(&self) -> PrivateKeyRef {
        self.env.private_key()
    }

    /// Opens the private part of a managed tenant's record. Refuses a key
    /// that is not of this record's tenant and of the version its header
    /// names.
    pub fn open_private_managed(&self, tk: &TenantKey) -> Result<Zeroizing<Vec<u8>>> {
        let ControlOwner::Managed(tenant) = self.owner else {
            return Err(ERR_CONTROL_KIND);
        };
        tk.is(tenant, self.env.private_version)?;
        let aad = control_aad(
            CONTROL_PRIVATE_DOMAIN,
            self.name,
            tenant.as_str(),
            self.env.header,
        )?;
        let key = tk.derive(CONTROL_PRIVATE_DOMAIN.as_bytes());
        unwrap_bytes_as(WRAP_VERSION, &key, &aad, self.env.private).map_err(|_| ERR_CONTROL)
    }

    /// Opens the private part of a tenant-0 record with the KEK version
    /// its header names.
    pub fn open_private_tenant_zero<K: Kek>(&self, kek: &K) -> Result<Zeroizing<Vec<u8>>> {
        if self.owner != ControlOwner::TenantZero {
            return Err(ERR_CONTROL_KIND);
        }
        let key = kek_version(kek, self.env.private_version)?;
        let aad = control_aad(
            CONTROL_PRIVATE_DOMAIN,
            self.name,
            DEFAULT_TENANT,
            self.env.header,
        )?;
        unwrap_bytes_as(
            WRAP_VERSION,
            &control_private_kek_key(key),
            &aad,
            self.env.private,
        )
        .map_err(|_| ERR_CONTROL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_ids_are_managed_ids_only() {
        assert!(TenantId::parse("t_0123456789abcdef").is_ok());
        for bad in [
            DEFAULT_TENANT,
            "t_0123456789ABCDEF",
            "t_0123456789abcde",
            "t_0123456789abcdef0",
            "x_0123456789abcdef",
            "t_0123456789abcdeg",
            "",
            "t_",
        ] {
            assert!(TenantId::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_scheme_follows_the_tenant_id() {
        assert_eq!(Scheme::of(DEFAULT_TENANT).unwrap(), Scheme::One);
        let t = TenantId::parse("t_00000000000000a1").unwrap();
        assert_eq!(Scheme::of(t.as_str()).unwrap(), Scheme::Two(t.clone()));
        assert!(Scheme::of("t_1").is_err());
        assert!(Scheme::One.check(&[0x01, 0]).is_ok());
        assert!(Scheme::One.check(&[0x02, 0]).is_err());
        assert!(Scheme::Two(t.clone()).check(&[0x02]).is_ok());
        assert!(Scheme::Two(t).check(&[0x01]).is_err());
        assert!(Scheme::One.check(&[]).is_err());
    }

    #[test]
    fn a_name_lies_in_the_tenant_dir_only_below_it() {
        let t = TenantId::parse("t_00000000000000a1").unwrap();
        assert!(under_tenant_dir("m/x/t_00000000000000a1/g_1", &t));
        assert!(!under_tenant_dir("m/x/t_00000000000000a1/", &t));
        assert!(!under_tenant_dir("m/x/t_00000000000000a1", &t));
        assert!(!under_tenant_dir("m/x/t_00000000000000a10/g_1", &t));
        assert!(!under_tenant_dir("m/g_1", &t));
        // The bucket configuration directory holds control records.
        assert!(!under_tenant_dir("m/x/t_00000000000000a1/b/b_01/1", &t));
        assert!(under_tenant_dir("m/x/t_00000000000000a1/bb", &t));
    }

    #[test]
    fn control_names_lie_in_their_owners_directories() {
        let t = TenantId::parse("t_00000000000000a1").unwrap();
        let m = ControlOwner::Managed(&t);
        for name in [
            "m/t/t_00000000000000a1/00000000000000000001",
            "m/k/t_00000000000000a1/00000000000000000001",
            "m/kc/t_00000000000000a1/00000000000000000256",
            "m/x/t_00000000000000a1/b/b_01/00000000000000000001",
        ] {
            assert!(m.owns(name), "{name}");
            assert!(!ControlOwner::TenantZero.owns(name), "{name}");
            assert!(!ControlOwner::Global.owns(name), "{name}");
        }
        for name in [
            "m/k/t_00000000000000a2/00000000000000000001",
            "m/k/t_00000000000000a1/",
            "m/k/t_00000000000000a1",
            "m/x/t_00000000000000a1/g_1",
            "m/x/t_00000000000000a1/b/",
            "m/kl/00000000000000000001",
            "m/g_1",
        ] {
            assert!(!m.owns(name), "{name}");
        }
        assert!(ControlOwner::TenantZero.owns("m/k/t_0000000000000000/00000000000000000001"));
        for name in [
            "m/kl/00000000000000000001",
            "m/kr/AKVL0001",
            "m/rk/t_00000000000000a1/AKVL0001",
            "m/rst/0011223344556677",
        ] {
            assert!(ControlOwner::Global.owns(name), "{name}");
        }
        assert!(!ControlOwner::Global.owns("m/kl/"));
        assert!(!ControlOwner::Global.owns("m/t/t_00000000000000a1/00000000000000000001"));
    }
}
