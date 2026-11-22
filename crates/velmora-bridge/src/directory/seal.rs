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
//! under the check value the chain committed. The seal itself does no I/O
//! ([`ControlSeal`]): a record under a version it does not hold answers
//! [`SealError::KeyNotHeld`], the root loads that version, and reads
//! again. [`ChainSeal::door`] opens a door part alone, so that the root
//! can read which version and check value to load.
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

use super::chain::{ControlSeal, OpenedParts, SealError};
use super::record::{Tenant, TenantPrivate, RECORD_FORMAT};
use crate::crypto::scheme2::{
    parse_control, seal_control, ControlOwner, ControlSealer, OpenedControl, PrivateKeyRef,
    TenantKey,
};
use crate::ports::Kek;
use crate::types::{BridgeError, Result};
use crate::TenantId;

const ERR_KEY_NOT_HELD: BridgeError = BridgeError::Crypto("tenant key version not held");
const ERR_KEY_GONE: BridgeError = BridgeError::Crypto("tenant key version is gone");
const ERR_ZERO_VERSION: BridgeError =
    BridgeError::Crypto("tenant 0 seals under the KEK, not a tenant key version");
const ERR_PRIVATE_WITHOUT_KEY: BridgeError =
    BridgeError::Crypto("private part without a tenant key");
const ERR_KEK_NOT_HELD: BridgeError =
    BridgeError::Crypto("control record names a KEK version not held");
const ERR_KEY_OTHER: BridgeError =
    BridgeError::Crypto("tenant key is not of the tenant and version it is held as");
const ERR_ENCODE: BridgeError = BridgeError::Crypto("empty private part does not encode");

/// The tenant keys a [`ChainSeal`] may use, by tenant and version, and
/// the versions known to be gone for good (retired, or destroyed by a
/// shred). One per isolate or per invocation; the composition root fills
/// it. Holds `Rc`s of the loader's keys, so a key is never copied here.
#[derive(Default)]
pub struct SealKeys {
    tenants: RefCell<BTreeMap<TenantId, Held>>,
}

#[derive(Default)]
struct Held {
    keys: BTreeMap<u32, Rc<TenantKey>>,
    gone: BTreeSet<u32>,
}

/// What [`SealKeys`] knows of one version.
enum Version {
    Held(Rc<TenantKey>),
    Gone,
    Unknown,
}

impl SealKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds `key` as its own tenant's key of its own version (the key
    /// carries both). A version marked gone is not taken back: `Err`.
    pub fn hold(&self, key: Rc<TenantKey>) -> Result<()> {
        if key.version() == 0 {
            return Err(ERR_KEY_OTHER);
        }
        let mut tenants = self.tenants.borrow_mut();
        let held = tenants.entry(key.tenant().clone()).or_default();
        if held.gone.contains(&key.version()) {
            return Err(ERR_KEY_GONE);
        }
        held.keys.insert(key.version(), key);
        Ok(())
    }

    /// Marks `version` of `tenant` gone for good: a record under it opens
    /// its door part only, and nothing is sealed under it again. Drops the
    /// key if one was held. Version 0 is no key and is ignored.
    pub fn gone(&self, tenant: &TenantId, version: u32) {
        if version == 0 {
            return;
        }
        let mut tenants = self.tenants.borrow_mut();
        let held = tenants.entry(tenant.clone()).or_default();
        held.keys.remove(&version);
        held.gone.insert(version);
    }

    /// Drops everything held for `tenant` (a shred, a refused load).
    pub fn forget(&self, tenant: &TenantId) {
        self.tenants.borrow_mut().remove(tenant);
    }

    /// Whether `version` of `tenant` is held.
    pub fn holds(&self, tenant: &TenantId, version: u32) -> bool {
        matches!(self.version(tenant, version), Version::Held(_))
    }

    fn version(&self, tenant: &TenantId, version: u32) -> Version {
        let tenants = self.tenants.borrow();
        let Some(held) = tenants.get(tenant) else {
            return Version::Unknown;
        };
        if held.gone.contains(&version) {
            return Version::Gone;
        }
        match held.keys.get(&version) {
            Some(key) => Version::Held(key.clone()),
            None => Version::Unknown,
        }
    }
}

/// The tenant chain's seal: the KEK ring, the tenant keys the root
/// loaded, and the system CSPRNG (any [`FillRandom`] in tests).
pub struct ChainSeal<'a, K, R> {
    kek: &'a K,
    keys: &'a SealKeys,
    rng: RefCell<R>,
}

impl<'a, K: Kek, R: FillRandom> ChainSeal<'a, K, R> {
    pub fn new(kek: &'a K, keys: &'a SealKeys, rng: R) -> Self {
        ChainSeal {
            kek,
            keys,
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

/// Opens the door part of a chain record: the whole record is proven.
fn open_door<'b, K: Kek>(
    kek: &K,
    name: &'b str,
    tenant: &'b Tenant,
    sealed: &'b [u8],
) -> std::result::Result<OpenedControl<'b>, SealError> {
    let env = parse_control(sealed).map_err(|_| SealError::Damaged)?;
    // A KEK version this Worker does not hold is its configuration, not
    // damage of the record: it may pass with the next deploy.
    if kek.version(env.kek_version()).is_none() {
        return Err(SealError::Failed(ERR_KEK_NOT_HELD));
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

impl<K: Kek, R: FillRandom> ControlSeal for ChainSeal<'_, K, R> {
    fn seal(
        &self,
        name: &str,
        tenant: &Tenant,
        key_version: u32,
        door: &[u8],
        private: &[u8],
    ) -> Result<Vec<u8>> {
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
            Tenant::Managed(t) => match self.keys.version(t, key_version) {
                Version::Held(tk) => {
                    if tk.tenant() != t || tk.version() != key_version {
                        return Err(ERR_KEY_OTHER);
                    }
                    seal_control(
                        self.kek,
                        name,
                        &ControlSealer::Managed(&tk),
                        door,
                        Some(private),
                        rng,
                    )
                }
                Version::Gone => Err(ERR_KEY_GONE),
                Version::Unknown => Err(ERR_KEY_NOT_HELD),
            },
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
                    return Err(SealError::Failed(ERR_KEK_NOT_HELD));
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
            (Tenant::Managed(t), PrivateKeyRef::Tenant(v)) => match self.keys.version(t, v) {
                Version::Held(tk) => {
                    // The whole record is proven by the door, and this is
                    // the key the chain committed for `v`: a private part
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
            },
            // `open_door` admits no other kind for these owners.
            _ => Err(SealError::Damaged),
        }
    }
}
