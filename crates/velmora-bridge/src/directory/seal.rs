//! The tenant chain's [`ControlSeal`] over key scheme 2: the real seal.
//!
//! A tenant record `m/t/<t>/<seq>` is a two-part control record
//! ([`crate::crypto::scheme2::seal_control`]):
//!
//! - the **door part** under the control key, derived from the active KEK;
//! - the **private part** under `HKDF(TK_v, control-private/v1)` for a
//!   managed tenant at key version `v`, under a KEK-derived key for tenant
//!   0, and **none** for a managed tenant's record with no tenant key
//!   (`key_version` 0: the records before its version 1, and the
//!   `shredded` stub). Such a record may carry only the empty private part
//!   (the chain's rule), so nothing private is ever sealed under the KEK
//!   alone for a managed tenant: the seal refuses any other bytes, and a
//!   reader gets the empty private part back.
//!
//! The record name, the owner (tenant 0, or the managed tenant's id) and
//! the header are in the AAD of both parts, and the door's AAD also holds
//! the hash of the sealed private part. A record therefore opens only
//! under its own name and for its own tenant, and no private part can be
//! swapped in or cut off.
//!
//! # Keys
//!
//! The KEK comes only from the Worker's KEK ring ([`crate::ports::Kek`],
//! `VELMORA_KEK_<v>`). Tenant keys come only from [`SealKeys`], which the
//! composition root fills with keys that the key loader
//! ([`crate::keys::tk::TkCache::load`]) unwrapped from the key buckets
//! under the check value the chain committed. That holds for the record
//! that commits a new version too: `keys::tk::create_key_version` stores
//! the new key's blobs before it asks the chain to commit, so the commit's
//! writer loads the key it seals under by the check value it commits.
//!
//! **A key is used only for the check value its record names.** Each
//! record under version `v` carries the committed check value of `v` in
//! its door part (`key_checks`, set by the record that commits `v`). The
//! seal takes only a held key with that check value, and refuses to seal
//! otherwise; the reader opens only with it, and asks for a load
//! ([`SealError::KeyNotHeld`]) when no held key has it. So no record is
//! ever sealed under a key that a pinned loader would not give back, and
//! no other key of the version is ever tried.
//!
//! **A key is held for at most [`TK_CACHE_MS`] after it was unwrapped**,
//! as in the loader's own cache, which it is dated from
//! (`keys::tk::TkCache::loaded_at`; the shred's settle time counts on it,
//! ADR §3.3). Every use drops every older key, of every tenant, and a
//! record under a dropped key asks for a load.
//!
//! The seal does no I/O ([`ControlSeal`]): the root loads the version a
//! record asks for and reads again. [`ChainSeal::door`] opens a door part
//! alone, so that the root can read which version and check value to load.
//!
//! [`DoorSeal`] is the read-only form for readers that need door parts
//! only (the router's tenant heads): the KEK alone, no tenant key, no
//! private part, and no seal.
//!
//! No key byte, plaintext or ciphertext reaches an error or a log line:
//! every error here is a fixed string.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use velmora::rng::FillRandom;
use zeroize::Zeroizing;

use super::chain::{seal_version, ControlSeal, OpenedParts, SealError};
use super::record::{Tenant, TenantDoor, TenantPrivate, RECORD_FORMAT};
use crate::config::MAX_KEK_VERSION;
use crate::crypto::scheme2::{
    parse_control, seal_control, ControlOwner, ControlSealer, OpenedControl, PrivateKeyRef,
    TenantKey, KCV_LEN,
};
use crate::keys::tk::TK_CACHE_MS;
use crate::ports::{Clock, Kek};
use crate::types::{BridgeError, Result, UnixMs};
use crate::TenantId;

const ERR_KEY_NOT_HELD: BridgeError = BridgeError::Crypto("tenant key version not held");
const ERR_KEY_GONE: BridgeError = BridgeError::Crypto("tenant key version is gone");
const ERR_ZERO_VERSION: BridgeError =
    BridgeError::Crypto("tenant 0 seals under the KEK, not a tenant key version");
const ERR_PRIVATE_WITHOUT_KEY: BridgeError =
    BridgeError::Crypto("private part without a tenant key");
const ERR_KEK_NOT_HELD: BridgeError =
    BridgeError::Crypto("control record names a KEK version not held yet");
const ERR_KEY_VERSION_ZERO: BridgeError = BridgeError::Crypto("tenant key version 0 is no key");
const ERR_KEY_STALE: BridgeError = BridgeError::Crypto("tenant key is past its cache time");
const ERR_ENCODE: BridgeError = BridgeError::Crypto("empty private part does not encode");
const ERR_DOOR: BridgeError =
    BridgeError::Crypto("door part is not a record of this tenant at this key version");
const ERR_NO_CHECK: BridgeError =
    BridgeError::Crypto("door part names no committed check value for its key version");

/// The tenant keys a [`ChainSeal`] may use, by tenant, version and check
/// value, each with the time it was held, and the versions known to be
/// gone for good (retired, or destroyed by a shred). The composition root
/// fills it. Holds `Rc`s of the loader's keys, so a key is never copied
/// here.
#[derive(Default)]
pub struct SealKeys {
    tenants: RefCell<BTreeMap<TenantId, Held>>,
}

/// The keys of one version, by check value, each with when it was held.
type ByCheck = BTreeMap<[u8; KCV_LEN], (Rc<TenantKey>, UnixMs)>;

#[derive(Default)]
struct Held {
    /// By version, then check value.
    keys: BTreeMap<u32, ByCheck>,
    gone: BTreeSet<u32>,
}

/// What [`SealKeys`] knows of one version and check value.
enum Version {
    Held(Rc<TenantKey>),
    Gone,
    Unknown,
}

fn fresh(at: UnixMs, now: UnixMs) -> bool {
    now.0 >= at.0 && now.0 - at.0 < TK_CACHE_MS
}

impl SealKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds `key` as its own tenant's key of its own version and check
    /// value (the key carries all three), for at most [`TK_CACHE_MS`]
    /// after `loaded_at`, the time it was unwrapped
    /// (`keys::tk::TkCache::loaded_at`). A key already held keeps its
    /// earlier time. A key whose time has passed is not taken, and a
    /// version marked gone is not taken back: `Err` for both.
    pub fn hold(&self, key: Rc<TenantKey>, loaded_at: UnixMs, now: UnixMs) -> Result<()> {
        if key.version() == 0 {
            return Err(ERR_KEY_VERSION_ZERO);
        }
        let mut tenants = self.tenants.borrow_mut();
        prune(&mut tenants, now);
        if !fresh(loaded_at, now) {
            return Err(ERR_KEY_STALE);
        }
        let held = tenants.entry(key.tenant().clone()).or_default();
        if held.gone.contains(&key.version()) {
            return Err(ERR_KEY_GONE);
        }
        held.keys
            .entry(key.version())
            .or_default()
            .entry(key.check_value())
            .or_insert((key, loaded_at));
        Ok(())
    }

    /// Marks `version` of `tenant` gone for good: a record under it opens
    /// its door part only, and nothing is sealed under it again. Drops
    /// every key held for it. Version 0 is no key and is ignored.
    pub fn gone(&self, tenant: &TenantId, version: u32) {
        if version == 0 {
            return;
        }
        let mut tenants = self.tenants.borrow_mut();
        let held = tenants.entry(tenant.clone()).or_default();
        held.keys.remove(&version);
        held.gone.insert(version);
    }

    /// Drops every key held for `tenant` (a refused load). The versions
    /// marked gone stay gone.
    pub fn forget(&self, tenant: &TenantId) {
        if let Some(held) = self.tenants.borrow_mut().get_mut(tenant) {
            held.keys.clear();
        }
    }

    /// How many keys are held, of every tenant (tests).
    pub fn len(&self) -> usize {
        self.tenants
            .borrow()
            .values()
            .map(|held| held.keys.values().map(BTreeMap::len).sum::<usize>())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether a key of `version` of `tenant` with check value `kcv` is
    /// held and fresh at `now`.
    pub fn holds(&self, tenant: &TenantId, version: u32, kcv: &[u8; KCV_LEN], now: UnixMs) -> bool {
        matches!(self.version(tenant, version, kcv, now), Version::Held(_))
    }

    fn version(
        &self,
        tenant: &TenantId,
        version: u32,
        kcv: &[u8; KCV_LEN],
        now: UnixMs,
    ) -> Version {
        let mut tenants = self.tenants.borrow_mut();
        prune(&mut tenants, now);
        let Some(held) = tenants.get(tenant) else {
            return Version::Unknown;
        };
        if held.gone.contains(&version) {
            return Version::Gone;
        }
        match held.keys.get(&version).and_then(|keys| keys.get(kcv)) {
            Some((key, _)) => Version::Held(key.clone()),
            None => Version::Unknown,
        }
    }
}

/// No key outlives its time here, whoever it belongs to: every use drops
/// every key past [`TK_CACHE_MS`] after its unwrap, of every tenant, as
/// the loader's cache does.
fn prune(tenants: &mut BTreeMap<TenantId, Held>, now: UnixMs) {
    for held in tenants.values_mut() {
        for keys in held.keys.values_mut() {
            keys.retain(|_, (_, at)| fresh(*at, now));
        }
        held.keys.retain(|_, keys| !keys.is_empty());
    }
    tenants.retain(|_, held| !held.keys.is_empty() || !held.gone.is_empty());
}

/// The tenant chain's seal: the KEK ring, the tenant keys the root
/// loaded, the clock their age is judged by, and the system CSPRNG (any
/// [`FillRandom`] in tests).
pub struct ChainSeal<'a, K, R, T> {
    kek: &'a K,
    keys: &'a SealKeys,
    clock: &'a T,
    rng: RefCell<R>,
}

impl<'a, K: Kek, R: FillRandom, T: Clock> ChainSeal<'a, K, R, T> {
    pub fn new(kek: &'a K, keys: &'a SealKeys, clock: &'a T, rng: R) -> Self {
        ChainSeal {
            kek,
            keys,
            clock,
            rng: RefCell::new(rng),
        }
    }

    /// The door part of the record stored under `name` of `tenant`'s
    /// chain, opened with the control key alone: what a loader reads to
    /// learn the key version and check value to load. Proves the whole
    /// record, as [`ControlSeal::open`] does.
    pub fn door(
        &self,
        name: &str,
        tenant: &Tenant,
        sealed: &[u8],
    ) -> std::result::Result<Vec<u8>, SealError> {
        let opened = open_door(self.kek, name, tenant, sealed)?;
        Ok(opened.door().to_vec())
    }
}

/// A read-only seal for readers that need door parts only (the router's
/// tenant heads, `unit_lease::client::TenantHeads`): it opens every door
/// part with the control key, proving the whole record, and returns no
/// private part, so no tenant key is loaded on the request path. It seals
/// nothing, and a head read through it takes no next record
/// (`ChainError::PrivateUnreadable`), so it cannot write a chain.
pub struct DoorSeal<'a, K> {
    kek: &'a K,
}

impl<'a, K: Kek> DoorSeal<'a, K> {
    pub fn new(kek: &'a K) -> Self {
        DoorSeal { kek }
    }
}

const ERR_DOORS_ONLY: BridgeError = BridgeError::Crypto("a door reader seals nothing");

impl<K: Kek> ControlSeal for DoorSeal<'_, K> {
    fn seal(&self, _: &str, _: &Tenant, _: u32, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(ERR_DOORS_ONLY)
    }

    fn open(
        &self,
        name: &str,
        tenant: &Tenant,
        sealed: &[u8],
    ) -> std::result::Result<OpenedParts, SealError> {
        let opened = open_door(self.kek, name, tenant, sealed)?;
        let key_version = match (tenant, opened.private_key()) {
            (Tenant::Zero, PrivateKeyRef::Kek(v))
            | (Tenant::Managed(_), PrivateKeyRef::Tenant(v)) => v,
            (Tenant::Managed(_), PrivateKeyRef::None) => 0,
            _ => return Err(SealError::Damaged),
        };
        Ok(OpenedParts {
            door: opened.door().to_vec(),
            private: None,
            key_version,
        })
    }
}

/// A KEK version this Worker does not hold. Newer than its active one,
/// and one a deploy can have (`config::MAX_KEK_VERSION`): a record of a
/// newer deploy, a failure that may pass. Any other: a version this
/// deploy no longer carries, or a changed header byte; either way the
/// record cannot be read here, which is damage and pages.
fn kek_not_held<K: Kek>(kek: &K, v: u32) -> SealError {
    match v > kek.active().0 && v <= MAX_KEK_VERSION {
        true => SealError::Failed(ERR_KEK_NOT_HELD),
        false => SealError::Damaged,
    }
}

/// Opens the door part of a chain record: the whole record is proven.
fn open_door<'b, K: Kek>(
    kek: &K,
    name: &'b str,
    tenant: &'b Tenant,
    sealed: &'b [u8],
) -> std::result::Result<OpenedControl<'b>, SealError> {
    let env = parse_control(sealed).map_err(|_| SealError::Damaged)?;
    if kek.version(env.kek_version()).is_none() {
        return Err(kek_not_held(kek, env.kek_version()));
    }
    env.open_door(kek, name, owner(tenant))
        .map_err(|_| SealError::Damaged)
}

fn owner(tenant: &Tenant) -> ControlOwner<'_> {
    match tenant {
        Tenant::Zero => ControlOwner::TenantZero,
        Tenant::Managed(t) => ControlOwner::Managed(t),
    }
}

/// The one private part a record with no tenant key may carry.
fn empty_private() -> Result<Vec<u8>> {
    serde_json::to_vec(&TenantPrivate {
        v: RECORD_FORMAT,
        external_ref: None,
    })
    .map_err(|_| ERR_ENCODE)
}

/// The check value a door part names for key version `v` (`key_checks`,
/// lowercase hex); `None` when it names none or not in that form.
pub fn committed_check(door: &TenantDoor, v: u32) -> Option<[u8; KCV_LEN]> {
    let text = door.key_checks.get(&v)?;
    if text.len() != 2 * KCV_LEN {
        return None;
    }
    let mut out = [0u8; KCV_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = text.get(2 * i..2 * i + 2)?;
        if !pair
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

impl<K: Kek, R: FillRandom, T: Clock> ControlSeal for ChainSeal<'_, K, R, T> {
    fn seal(
        &self,
        name: &str,
        tenant: &Tenant,
        key_version: u32,
        door: &[u8],
        private: &[u8],
    ) -> Result<Vec<u8>> {
        // The seal checks what it is asked to seal against the door part:
        // the tenant, and the key version the door's own fields name.
        let parsed: TenantDoor = serde_json::from_slice(door).map_err(|_| ERR_DOOR)?;
        if &parsed.tenant != tenant || seal_version(&parsed) != key_version {
            return Err(ERR_DOOR);
        }
        let mut rng = self.rng.borrow_mut();
        let rng = &mut *rng;
        match tenant {
            Tenant::Zero => {
                if key_version != 0 {
                    return Err(ERR_ZERO_VERSION);
                }
                seal_control(
                    self.kek,
                    name,
                    &ControlSealer::TenantZero,
                    door,
                    Some(private),
                    rng,
                )
            }
            Tenant::Managed(t) if key_version == 0 => {
                if private != empty_private()?.as_slice() {
                    return Err(ERR_PRIVATE_WITHOUT_KEY);
                }
                seal_control(
                    self.kek,
                    name,
                    &ControlSealer::ManagedKeyless(t),
                    door,
                    None,
                    rng,
                )
            }
            Tenant::Managed(t) => {
                let kcv = committed_check(&parsed, key_version).ok_or(ERR_NO_CHECK)?;
                match self.keys.version(t, key_version, &kcv, self.clock.now()) {
                    Version::Held(tk) => seal_control(
                        self.kek,
                        name,
                        &ControlSealer::Managed(&tk),
                        door,
                        Some(private),
                        rng,
                    ),
                    Version::Gone => Err(ERR_KEY_GONE),
                    Version::Unknown => Err(ERR_KEY_NOT_HELD),
                }
            }
        }
    }

    fn open(
        &self,
        name: &str,
        tenant: &Tenant,
        sealed: &[u8],
    ) -> std::result::Result<OpenedParts, SealError> {
        let opened = open_door(self.kek, name, tenant, sealed)?;
        let door = opened.door().to_vec();
        // The door opened, so the header (and the kind it names) is
        // authenticated, and `open_door` admitted the kind for the owner.
        match (tenant, opened.private_key()) {
            (Tenant::Zero, PrivateKeyRef::Kek(v)) => {
                if self.kek.version(v).is_none() {
                    return Err(kek_not_held(self.kek, v));
                }
                let private = opened
                    .open_private_tenant_zero(self.kek)
                    .map_err(|_| SealError::Damaged)?;
                Ok(OpenedParts {
                    door,
                    private: Some(private),
                    key_version: v,
                })
            }
            (Tenant::Managed(_), PrivateKeyRef::None) => Ok(OpenedParts {
                door,
                private: Some(Zeroizing::new(empty_private().map_err(SealError::Failed)?)),
                key_version: 0,
            }),
            (Tenant::Managed(t), PrivateKeyRef::Tenant(v)) => {
                // A record under `v` names the check value committed for
                // `v`; only the key with that value is tried. A record
                // that names none was not written by this seal.
                let parsed: TenantDoor =
                    serde_json::from_slice(&door).map_err(|_| SealError::Damaged)?;
                let kcv = committed_check(&parsed, v).ok_or(SealError::Damaged)?;
                match self.keys.version(t, v, &kcv, self.clock.now()) {
                    Version::Held(tk) => {
                        // The door proves the whole record, and this is the
                        // key the chain committed for `v`: a private part
                        // that does not open under it is damage.
                        let private = opened
                            .open_private_managed(&tk)
                            .map_err(|_| SealError::Damaged)?;
                        Ok(OpenedParts {
                            door,
                            private: Some(private),
                            key_version: v,
                        })
                    }
                    Version::Gone => Ok(OpenedParts {
                        door,
                        private: None,
                        key_version: v,
                    }),
                    Version::Unknown => Err(SealError::KeyNotHeld { version: v }),
                }
            }
            // `open_door` admits no other kind for these owners.
            _ => Err(SealError::Damaged),
        }
    }
}
