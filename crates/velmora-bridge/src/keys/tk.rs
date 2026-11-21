//! Tenant keys: creating a key version, loading a key, and the cache.
//!
//! A tenant key (TK) lives only in the key buckets, as
//! `m/tk/<t>/<n>.<v>`: version `n` of the tenant's key, wrapped under KEK
//! version `v` ([`crate::crypto::scheme2`]). The set of key buckets is
//! the head of the key-location chain ([`super::locations`]).
//!
//! # Creating version `m`
//!
//! The first key of a tenant uses the same procedure as any later one.
//!
//! 1. **Claim first, before any blob.** The claim is a record of the
//!    tenant chain ([`KeyVersionClaims`]); a claim that is already open
//!    (a run that died, or a concurrent one) is resumed, not replaced.
//! 2. **Create in the arbiter only.** If the arbiter already holds a
//!    blob of version `m`, it is adopted. Otherwise a fresh key is put
//!    there with put-if-absent, and the bytes read back are adopted,
//!    whoever wrote them. Two runs therefore end with the same key.
//! 3. **Copy** the adopted bytes to every other synchronous location,
//!    with put-if-absent, and compare the check value of every copy.
//! 4. **A version whose copies disagree is void.** It is never used and
//!    nothing is deleted: the claim moves to `m + 1` and the run starts
//!    again at step 2.
//! 5. **Commit**, with the key's check value, which the tenant chain
//!    keeps: from then on that check value is the key of version `m`. A
//!    commit that a concurrent run made already counts.
//!
//! **Two runs under different active KEK versions** (during a KEK
//! rotation) put different names, `<m>.<v>` and `<m>.<v+1>`, so the
//! arbiter's put-if-absent cannot decide between them. Each run reads
//! every copy of `m` back after its put; one that finds two keys voids
//! `m`. If the other run committed first, the void is refused and this
//! run fails, leaving a stray blob: readers then take only the copy
//! whose check value the commit pinned, and the audit reports the
//! stray.
//!
//! Before each write the writer lists the tenant's directory in the
//! location: any name that is no key blob (a shred marker among them)
//! stops it. A writer always loses to a marker, and never deletes what
//! it lost to.
//!
//! # Loading
//!
//! One list of `m/tk/<t>/` and one get, in the arbiter first, then in
//! each other active location. A name that is no key blob means the
//! tenant is refused. No copy in any location, with no such name, is a
//! loss: the loader fails and the caller alarms. With the check value the
//! commit pinned, only a copy with that value is taken; without one, the
//! copies of the version must all agree, or the load fails
//! ([`ERR_TK_SPLIT`]). An unwrapped key is kept per isolate for at most
//! [`TK_CACHE_MS`].

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use velmora::rng::FillRandom;

use super::locations::{KeyLocation, KeyLocations};
use super::record::TkRing;
use super::store::RecordStore;
use crate::crypto::scheme2::{
    tk_blob_check_value, tk_blob_name, unwrap_tenant_key, wrap_tenant_key, TenantId, TenantKey,
    KCV_LEN, TK_PREFIX,
};
use crate::ports::{Clock, Kek};
use crate::types::{BridgeError, Result, UnixMs};

/// How long an isolate keeps an unwrapped tenant key.
pub const TK_CACHE_MS: i64 = 60_000;
/// Voided versions one creation run accepts before it stops and alarms.
pub const MAX_VOIDS: u32 = 3;
/// Names per list call.
const PAGE: u32 = 1000;

/// A name below the tenant's key directory that is no key blob: a shred
/// marker, or something no writer of this code put there. Writers stop;
/// loaders refuse the tenant.
pub const ERR_TK_FOREIGN: BridgeError = BridgeError::Crypto(FOREIGN);
/// No copy of the key version in any location, and no marker: a loss.
pub const ERR_TK_MISSING: BridgeError = BridgeError::Crypto("tenant key is missing");
/// The copies of one key version hold different keys, and no pinned
/// check value says which one is committed. An alarm.
pub const ERR_TK_SPLIT: BridgeError =
    BridgeError::Crypto("tenant key copies of one version disagree");
/// The tenant state does not admit a key version (the claim or the
/// commit was refused).
pub const ERR_TK_REFUSED: BridgeError =
    BridgeError::Invalid("tenant state does not admit a key version");
/// Copies disagreed [`MAX_VOIDS`] times in one run.
pub const ERR_TK_VOIDS: BridgeError =
    BridgeError::Crypto("tenant key copies disagree again and again");
/// A location the set names has no binding.
pub const ERR_TK_UNBOUND: BridgeError = BridgeError::Invalid("key location has no binding");

const FOREIGN: &str = "tenant key directory holds a name that is no key blob";

/// Whether `e` is [`ERR_TK_FOREIGN`].
pub fn is_foreign(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Crypto(m) if *m == FOREIGN)
}

/// The directory of `tenant`'s key blobs.
pub fn tk_prefix(tenant: &TenantId) -> String {
    format!("{TK_PREFIX}{tenant}/")
}

/// `(key version, KEK version)` of a key blob name of `tenant`; `None`
/// for any other name.
pub fn parse_tk_name(tenant: &TenantId, name: &str) -> Option<(u32, u32)> {
    let rest = name.strip_prefix(&tk_prefix(tenant))?;
    let (n, v) = rest.split_once('.')?;
    let num = |s: &str| {
        (!s.is_empty()
            && s.len() <= 10
            && s.bytes().all(|b| b.is_ascii_digit())
            && !s.starts_with('0'))
        .then(|| s.parse::<u32>().ok())
        .flatten()
    };
    Some((num(n)?, num(v)?))
}

/// The key buckets by binding name.
pub struct KeyBuckets<'a, S> {
    pub by_name: Vec<(&'a str, &'a S)>,
}

impl<'a, S: RecordStore> KeyBuckets<'a, S> {
    pub fn get(&self, location: &KeyLocation) -> Result<&'a S> {
        self.by_name
            .iter()
            .find(|(n, _)| *n == location.name)
            .map(|(_, s)| *s)
            .ok_or(ERR_TK_UNBOUND)
    }
}

/// Every key blob name of `tenant` in one location, with its versions.
/// Refuses with [`ERR_TK_FOREIGN`] when any other name is there.
pub async fn list_tenant_blobs<S: RecordStore>(
    store: &S,
    tenant: &TenantId,
) -> Result<Vec<(String, u32, u32)>> {
    let prefix = tk_prefix(tenant);
    let mut after = prefix.clone();
    let mut out = Vec::new();
    loop {
        let names = store.list(&prefix, &after, PAGE).await?;
        for name in &names {
            let (n, v) = parse_tk_name(tenant, name).ok_or(ERR_TK_FOREIGN)?;
            out.push((name.clone(), n, v));
        }
        match names.last() {
            Some(last) if names.len() >= PAGE as usize => after.clone_from(last),
            _ => return Ok(out),
        }
    }
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// The answer of a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// Version `m` is claimed: by this call, or by an open claim it found.
    Claimed(u32),
    /// The tenant state does not admit it (`deleting`, `restoring`, …).
    Refused,
}

/// The answer of a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// Committed, by this call or by a concurrent run.
    Committed,
    /// The tenant moved on (`deleting` or beyond): stop. The blob stays.
    Stopped,
}

/// The claim and the commit of a key version: records of the tenant
/// chain, written by its owner.
#[allow(async_fn_in_trait)]
pub trait KeyVersionClaims {
    /// Claims the next key version, or answers the open claim.
    async fn claim(&self, tenant: &TenantId) -> Result<Claim>;
    /// Voids the open claim `version` and claims `version + 1`. Refuses
    /// (an `Err`) when `version` is not the open claim, a committed one
    /// included.
    async fn void(&self, tenant: &TenantId, version: u32) -> Result<Claim>;
    /// Commits the open claim `version`, pinning `kcv`, the check value
    /// of its key. A commit of the same version with another `kcv` is
    /// refused (an `Err`).
    async fn commit(&self, tenant: &TenantId, version: u32, kcv: [u8; KCV_LEN]) -> Result<Commit>;
}

// ---------------------------------------------------------------------------
// Creating a key version
// ---------------------------------------------------------------------------

/// What a creation run did.
#[derive(Debug)]
pub struct Created {
    /// The committed key, as the arbiter holds it.
    pub key: TenantKey,
    /// The KEK version of the blob.
    pub kek_version: u32,
    /// Versions voided on the way (an alarm each).
    pub voided: Vec<u32>,
    /// Whether this run's own key was the one adopted.
    pub generated_here: bool,
}

/// Adopts or creates version `m` in the arbiter. `Ok(None)`: the
/// arbiter's copies of `m` disagree, so `m` is void.
async fn adopt_in_arbiter<S: RecordStore, K: Kek, R: FillRandom>(
    arbiter: &S,
    kek: &K,
    tenant: &TenantId,
    m: u32,
    rng: &mut R,
) -> Result<Option<(String, Vec<u8>, bool)>> {
    let of_m = |blobs: Vec<(String, u32, u32)>| -> Vec<(String, u32)> {
        blobs
            .into_iter()
            .filter(|(_, n, _)| *n == m)
            .map(|(name, _, v)| (name, v))
            .collect()
    };
    let mut generated = false;
    let existing = of_m(list_tenant_blobs(arbiter, tenant).await?);
    if existing.is_empty() {
        let key = TenantKey::generate(tenant, m, rng)?;
        let (v, blob) = wrap_tenant_key(kek, &key, rng)?;
        let name = tk_blob_name(tenant, m, v);
        generated = match arbiter.put_if_absent(&name, blob.clone()).await {
            Ok(stored) => stored,
            // The answer was lost: the bytes read back decide.
            Err(e) => match arbiter.get(&name).await? {
                Some(b) => b == blob,
                None => return Err(e),
            },
        };
    }
    // Read every copy of `m` back, ours or another run's: they must all
    // hold the same key.
    let mut copies = Vec::new();
    for (name, v) in of_m(list_tenant_blobs(arbiter, tenant).await?) {
        let bytes = arbiter.get(&name).await?.ok_or(ERR_TK_MISSING)?;
        copies.push((tk_blob_check_value(&bytes)?, name, v, bytes));
    }
    if copies.windows(2).any(|w| w[0].0 != w[1].0) {
        return Ok(None);
    }
    // The copy under the active KEK, else the newest one this Worker
    // holds a KEK for.
    let active = kek.active().0;
    let chosen = copies
        .into_iter()
        .filter(|(_, _, v, _)| kek.version(*v).is_some())
        .max_by_key(|(_, _, v, _)| (*v == active, *v))
        .ok_or(ERR_TK_MISSING)?;
    Ok(Some((chosen.1, chosen.3, generated)))
}

/// Copies `bytes` to `store` under `name`, and checks that every copy of
/// version `m` there has the same check value. `Ok(false)`: they
/// disagree.
async fn copy_to<S: RecordStore>(
    store: &S,
    tenant: &TenantId,
    m: u32,
    name: &str,
    bytes: &[u8],
) -> Result<bool> {
    let kcv = tk_blob_check_value(bytes)?;
    let put = store.put_if_absent(name, bytes.to_vec()).await;
    if let Err(e) = put {
        // A lost answer: the copy may be there.
        if store.get(name).await?.is_none() {
            return Err(e);
        }
    }
    for (other, n, _) in list_tenant_blobs(store, tenant).await? {
        if n != m {
            continue;
        }
        let there = store.get(&other).await?.ok_or(ERR_TK_MISSING)?;
        if tk_blob_check_value(&there)? != kcv {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Creates the next key version of `tenant` (its first one included) in
/// the locations of `set`, and commits it. Resumable: a run that died is
/// finished by running it again.
pub async fn create_key_version<S, K, C, R>(
    set: &KeyLocations,
    buckets: &KeyBuckets<'_, S>,
    claims: &C,
    kek: &K,
    tenant: &TenantId,
    rng: &mut R,
) -> Result<Created>
where
    S: RecordStore,
    K: Kek,
    C: KeyVersionClaims,
    R: FillRandom,
{
    let mut voided = Vec::new();
    let mut claim = claims.claim(tenant).await?;
    loop {
        let Claim::Claimed(m) = claim else {
            return Err(ERR_TK_REFUSED);
        };
        let arbiter = buckets.get(set.arbiter())?;
        let adopted = adopt_in_arbiter(arbiter, kek, tenant, m, rng).await?;
        let mut agree = adopted.is_some();
        if let Some((name, bytes, _)) = &adopted {
            for location in set.synchronous_copies() {
                let store = buckets.get(location)?;
                if !copy_to(store, tenant, m, name, bytes).await? {
                    agree = false;
                    break;
                }
            }
        }
        if !agree {
            voided.push(m);
            if voided.len() as u32 >= MAX_VOIDS {
                return Err(ERR_TK_VOIDS);
            }
            claim = claims.void(tenant, m).await?;
            continue;
        }
        let (name, bytes, generated_here) = adopted.ok_or(ERR_TK_MISSING)?;
        // A marker that arrived during the run wins: check every active
        // location once more before the commit.
        for location in set.active() {
            list_tenant_blobs(buckets.get(location)?, tenant).await?;
        }
        let kek_version = parse_tk_name(tenant, &name).ok_or(ERR_TK_MISSING)?.1;
        let key = unwrap_tenant_key(kek, kek_version, tenant, m, &bytes)?;
        return match claims.commit(tenant, m, key.check_value()).await? {
            Commit::Committed => Ok(Created {
                key,
                kek_version,
                voided,
                generated_here,
            }),
            Commit::Stopped => Err(ERR_TK_REFUSED),
        };
    }
}

// ---------------------------------------------------------------------------
// Loading and the cache
// ---------------------------------------------------------------------------

/// Unwrapped tenant keys of one isolate, each for at most
/// [`TK_CACHE_MS`].
#[derive(Default)]
pub struct TkCache {
    keys: RefCell<BTreeMap<(TenantId, u32), Cached>>,
}

/// A key and the time it was loaded.
type Cached = (Rc<TenantKey>, UnixMs);

impl TkCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops every key of `tenant` (a shred, a refused load).
    pub fn forget(&self, tenant: &TenantId) {
        self.keys.borrow_mut().retain(|(t, _), _| t != tenant);
    }

    /// How many keys are held (tests).
    pub fn len(&self) -> usize {
        self.keys.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.borrow().is_empty()
    }

    /// Key version `version` of `tenant`: from the cache while it is
    /// fresh, else from the first active location that holds it.
    /// `pinned` is the check value the tenant chain committed for the
    /// version, when the caller has it.
    #[allow(clippy::too_many_arguments)]
    pub async fn load<S: RecordStore, K: Kek, T: Clock>(
        &self,
        set: &KeyLocations,
        buckets: &KeyBuckets<'_, S>,
        kek: &K,
        clock: &T,
        tenant: &TenantId,
        version: u32,
        pinned: Option<[u8; KCV_LEN]>,
    ) -> Result<Rc<TenantKey>> {
        let now = clock.now();
        let id = (tenant.clone(), version);
        if let Some((key, at)) = self.keys.borrow().get(&id) {
            let fresh = now.0 >= at.0 && now.0 - at.0 < TK_CACHE_MS;
            if fresh && pinned.is_none_or(|p| p == key.check_value()) {
                return Ok(key.clone());
            }
        }
        self.keys.borrow_mut().remove(&id);
        let mut last_err = ERR_TK_MISSING;
        for location in set.active() {
            let store = buckets.get(location)?;
            match load_from(store, kek, tenant, version, pinned).await {
                Ok(Some(key)) => {
                    let key = Rc::new(key);
                    self.keys.borrow_mut().insert(id, (key.clone(), now));
                    return Ok(key);
                }
                Ok(None) => {}
                // A marker or a foreign name: refused, wherever it is. Two
                // keys for one version: refused too.
                Err(e) if is_foreign(&e) || is_split(&e) => {
                    self.forget(tenant);
                    return Err(e);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

/// Whether `e` is [`ERR_TK_SPLIT`].
pub fn is_split(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Crypto(m) if *m == "tenant key copies of one version disagree")
}

/// Version `version` of `tenant`'s key from one location; `None` when the
/// location holds no copy this Worker can open.
async fn load_from<S: RecordStore, K: Kek>(
    store: &S,
    kek: &K,
    tenant: &TenantId,
    version: u32,
    pinned: Option<[u8; KCV_LEN]>,
) -> Result<Option<TenantKey>> {
    // Every copy of the version, under any KEK version: the check value
    // needs no key.
    let mut copies = Vec::new();
    for (name, n, v) in list_tenant_blobs(store, tenant).await? {
        if n != version {
            continue;
        }
        let Some(bytes) = store.get(&name).await? else {
            continue;
        };
        copies.push((tk_blob_check_value(&bytes)?, v, bytes));
    }
    match pinned {
        Some(p) => copies.retain(|(kcv, _, _)| *kcv == p),
        None => {
            if copies.windows(2).any(|w| w[0].0 != w[1].0) {
                return Err(ERR_TK_SPLIT);
            }
        }
    }
    // The copy under the active KEK first, then the newest one this
    // Worker holds a KEK for.
    let active = kek.active().0;
    let Some((_, v, bytes)) = copies
        .into_iter()
        .filter(|(_, v, _)| kek.version(*v).is_some())
        .max_by_key(|(_, v, _)| (*v == active, *v))
    else {
        return Ok(None);
    };
    unwrap_tenant_key(kek, v, tenant, version, &bytes).map(Some)
}

/// The keys of one tenant a reader holds, by version, with the one new
/// records are sealed under.
pub struct LoadedRing {
    current: Rc<TenantKey>,
    others: Vec<Rc<TenantKey>>,
}

impl LoadedRing {
    /// `current` must be the committed version; `others` older ones.
    pub fn new(current: Rc<TenantKey>, others: Vec<Rc<TenantKey>>) -> Result<LoadedRing> {
        let same_tenant = others.iter().all(|k| k.tenant() == current.tenant());
        if !same_tenant {
            return Err(BridgeError::Crypto(
                "tenant keys of another tenant in a ring",
            ));
        }
        Ok(LoadedRing { current, others })
    }
}

impl TkRing for LoadedRing {
    fn current(&self) -> Option<&TenantKey> {
        Some(&self.current)
    }

    fn key(&self, version: u32) -> Option<&TenantKey> {
        std::iter::once(&self.current)
            .chain(self.others.iter())
            .find(|k| k.version() == version)
            .map(|k| &**k)
    }
}
