//! What the recovery copy proves before it copies (AM-80, AM-80b; ADR
//! §8.10).
//!
//! **One check per record, chosen by its name, never by its bytes**
//! (ADR §3.2's reader rule). [`family`] reads the name; [`check_record`]
//! proves the bytes as the family requires:
//!
//! | Name | Must be | Proved by |
//! |---|---|---|
//! | flat data records (`m/g_…`, `m/del/g_…`, `m/art/…`, `m/seg/…`), and tenant 0's directory `m/x/<tenant 0>/` outside `b/` | a v1 manifest | `open_manifest` under the KEK |
//! | `m/x/<t>/` of a managed tenant, outside `b/` | `VMR2` naming `<t>` | `open_record_v2` under `<t>`'s ring ([`JobRings`]) |
//! | `m/t/<t>/`, `m/k/<t>/`, `m/kc/<t>/`, `m/x/<t>/b/` (tenant 0 or managed) | `VCR1` | `parse_control` and `open_door` under the KEK, the owner from the name. This proves the whole record; the private part is never opened |
//! | `m/kl/`, `m/reg/`, `m/kr/`, `m/rk/`, `m/rst/`, `m/ub/`, `m/tref/` | `VCR1`, owner `Global` | as above; under a flat `m/rk/<akid>` a v1 manifest is also accepted |
//! | `m/dg/<epoch>` | a gate anchor | parses, and its `epoch` equals its name |
//! | `m/u/<t>/`, `m/uc/<t>/` | — | no writer is built: counted `unknown_family` like any other name. The package that builds the writer adds its row |
//! | `m/tk/` | — | never read, never copied |
//! | any other name under `m/` | — | `unknown_family`, with an alarm; copied only if it opens as a v1 manifest, as before |
//!
//! A record that is not what its name requires is [`RecordCheck::CrossScheme`],
//! or [`RecordCheck::CrossTenant`] when it names another tenant: it is
//! not copied and never replaces a copy. One that fails its proof is
//! [`RecordCheck::Unreadable`].
//!
//! # A `VMR2` version the ring lacks (AM-80b)
//!
//! The ring of a tenant is read once per job ([`JobRings`]) and read again
//! **once** when a record names a version it has no key for. Then:
//!
//! - a version the reloaded ring holds opens as usual;
//! - a version a record of the chain marks destroyed is
//!   [`RecordCheck::VersionDestroyed`]: not sent, no page;
//! - a version the reloaded chain names (committed or claimed) but whose
//!   blob did not load (a partial ring) is [`RecordCheck::KeyMissing`]
//!   with `named`: `failed`, paged after
//!   [`crate::copy::KEY_MISS_PASSES`] passes;
//! - any other version, above or below the current one, is
//!   [`RecordCheck::KeyMissing`] without `named`: `failed`, paged once per
//!   pass.
//!
//! A shredded tenant's `VMR2` records are [`RecordCheck::Shredded`]; its
//! `VCR1` records, the `shredded` stub included, are proved by their door
//! like every control record, and copied.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use serde::Deserialize;
use zeroize::Zeroizing;

use super::{
    record_name, valid_key_id, valid_set_id, RecordOpener, RECORD_PREFIX, REVOKED_KEY_PREFIX,
    TENANT_DIR, TENANT_KEY_PREFIX,
};
use crate::crypto::open_manifest;
use crate::crypto::scheme2::{
    is_cross_tenant, open_record_v2, parse_control, ControlOwner, Scheme, TenantId, CONTROL_MAGIC,
    GLOBAL_CONTROL_DIRS, RECORD_V2_HEADER_LEN, RECORD_V2_MAGIC, TENANT_ID_LEN,
};
use crate::directory::gate::{anchor_epoch, GATE_ANCHOR_PREFIX};
use crate::ports::{Clock, CopyRing, Kek, TenantRingState, TenantRings};
use crate::types::{BridgeError, Result};

/// The tenant directories of a tenant's own control records besides
/// `m/x/<t>/b/` (`crypto::scheme2::MANAGED_CONTROL_DIRS`).
const CHAIN_DIRS: [&str; 3] = ["m/t/", "m/k/", "m/kc/"];
/// The bucket configuration directory below `m/x/<t>/`.
const CONFIG_DIR: &str = "b/";

const ERR_NO_KEY: BridgeError = BridgeError::Crypto("record names a key version the ring lacks");
const ERR_NOT_V2: BridgeError = BridgeError::Crypto("record is no VMR2 envelope");
const ERR_NOT_V1: BridgeError = BridgeError::Crypto("record is no v1 manifest");

/// Who a control record belongs to, from its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    Global,
    TenantZero,
    Managed(TenantId),
}

impl Owner {
    fn control(&self) -> ControlOwner<'_> {
        match self {
            Owner::Global => ControlOwner::Global,
            Owner::TenantZero => ControlOwner::TenantZero,
            Owner::Managed(t) => ControlOwner::Managed(t),
        }
    }
}

/// What a record must be, by its name (the table of the module).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Family {
    /// A v1 manifest under the KEK: tenant 0's data records, flat or in
    /// its tenant layout.
    DataV1,
    /// A `VMR2` envelope naming this managed tenant, under its ring.
    DataV2(TenantId),
    /// A `VCR1` control record of this owner.
    Control(Owner),
    /// A flat `m/rk/<akid>`: a `VCR1` record of owner `Global`, or a v1
    /// manifest (the admin API's revocation writer).
    FlatRevocation,
    /// `m/dg/<epoch>`, a gate anchor.
    Anchor,
    /// `m/tk/`: never read, never copied.
    TenantKey,
    /// Any other name, `m/u/` and `m/uc/` included (no writer is built).
    Unknown,
}

impl Family {
    /// A data record: opened with [`RecordOpen`].
    pub fn is_data(&self) -> bool {
        matches!(self, Family::DataV1 | Family::DataV2(_))
    }
}

/// The owner a tenant directory name gives: tenant 0, a managed tenant,
/// or none (not a tenant id of either).
fn owner_of(tenant: &str) -> Option<Owner> {
    match Scheme::of(tenant).ok()? {
        Scheme::One => Some(Owner::TenantZero),
        Scheme::Two(t) => Some(Owner::Managed(t)),
    }
}

/// `<dir><tenant>/<rest>`, with `rest` not empty.
fn tenant_dir<'a>(name: &'a str, dir: &str) -> Option<(&'a str, &'a str)> {
    let (tenant, rest) = name.strip_prefix(dir)?.split_once('/')?;
    (!rest.is_empty()).then_some((tenant, rest))
}

/// A flat segment name, `seg/<set id>/<index>` after `m/`.
fn flat_segment(rest: &str) -> bool {
    rest.strip_prefix("seg/")
        .and_then(|r| r.split_once('/'))
        .is_some_and(|(set, index)| {
            valid_set_id(set) && !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit())
        })
}

/// What the record at `name` must be. Only the name is read.
pub fn family(name: &str) -> Family {
    let Some(rest) = name.strip_prefix(RECORD_PREFIX) else {
        return Family::Unknown;
    };
    if name.starts_with(TENANT_KEY_PREFIX) {
        return Family::TenantKey;
    }
    if name.starts_with(TENANT_DIR) {
        let Some((tenant, below)) = tenant_dir(name, TENANT_DIR) else {
            return Family::Unknown;
        };
        let config = below.starts_with(CONFIG_DIR);
        return match (owner_of(tenant), config) {
            (Some(owner), true) => Family::Control(owner),
            (Some(Owner::TenantZero), false) => Family::DataV1,
            (Some(Owner::Managed(t)), false) => Family::DataV2(t),
            _ => Family::Unknown,
        };
    }
    for dir in CHAIN_DIRS {
        if name.starts_with(dir) {
            return match tenant_dir(name, dir).and_then(|(t, _)| owner_of(t)) {
                Some(owner) => Family::Control(owner),
                None => Family::Unknown,
            };
        }
    }
    if name
        .strip_prefix(REVOKED_KEY_PREFIX)
        .is_some_and(valid_key_id)
    {
        return Family::FlatRevocation;
    }
    if GLOBAL_CONTROL_DIRS
        .iter()
        .any(|dir| name.strip_prefix(dir).is_some_and(|r| !r.is_empty()))
    {
        return Family::Control(Owner::Global);
    }
    if name.starts_with(GATE_ANCHOR_PREFIX) {
        return Family::Anchor;
    }
    if record_name(name).is_some_and(|n| n.layout.is_flat()) || flat_segment(rest) {
        return Family::DataV1;
    }
    Family::Unknown
}

/// What [`check_record`] found.
#[derive(Debug)]
pub enum RecordCheck {
    /// It is what its name requires, and it opens: copy it. The
    /// plaintext of a data record; `None` for a control record or an
    /// anchor.
    Proved(Option<Zeroizing<Vec<u8>>>),
    /// `m/tk/`: never read, never copied.
    Never,
    /// A `VMR2` record of a shredded (or shredding) tenant: not sent, no
    /// page.
    Shredded,
    /// A `VMR2` record under a version a record of the chain marks
    /// destroyed: not sent, no page.
    VersionDestroyed,
    /// The tenant's ring could not be read now: `failed`.
    RingFailed,
    /// The reloaded ring has no key for the record's version: `failed`.
    /// `named`: the chain names the version (a partial ring).
    KeyMissing { named: bool },
    /// Not the scheme its name requires.
    CrossScheme,
    /// It names another tenant than its name does.
    CrossTenant,
    /// It does not pass its proof.
    Unreadable,
    /// A name of no known family. With its plaintext when it opens as a
    /// v1 manifest under the KEK: it is then copied, as before.
    Unknown(Option<Zeroizing<Vec<u8>>>),
}

/// One opener of a data record (AM-80 item 3): the KEK for tenant 0's
/// layouts, the ring for a managed tenant's. Generation records,
/// segmented heads, segments and article plans all open through it.
pub enum RecordOpen<'k, K> {
    Kek(&'k K),
    Ring(Rc<CopyRing>),
}

/// The tenant id and the key version a `VMR2` envelope names, raw: the
/// tenant bytes are not parsed and the version is not checked.
fn v2_header(sealed: &[u8]) -> Option<(&[u8], u32)> {
    if sealed.len() < RECORD_V2_HEADER_LEN || !sealed.starts_with(RECORD_V2_MAGIC) {
        return None;
    }
    let tenant = &sealed[4..4 + TENANT_ID_LEN];
    let mut version = [0u8; 4];
    version.copy_from_slice(&sealed[4 + TENANT_ID_LEN..RECORD_V2_HEADER_LEN]);
    Some((tenant, u32::from_be_bytes(version)))
}

/// Whether `sealed` starts like a record of scheme 2 (`VMR2` or `VCR1`),
/// which no v1 manifest does: a v1 record starts with its KEK version,
/// whose first byte is zero.
fn scheme_two(sealed: &[u8]) -> bool {
    sealed.starts_with(RECORD_V2_MAGIC) || sealed.starts_with(CONTROL_MAGIC)
}

impl<K: Kek> RecordOpener for RecordOpen<'_, K> {
    fn open_record(&self, name: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            RecordOpen::Kek(kek) => {
                if scheme_two(sealed) {
                    return Err(ERR_NOT_V1);
                }
                open_manifest(*kek, name, sealed)
            }
            RecordOpen::Ring(ring) => {
                let (_, version) = v2_header(sealed).ok_or(ERR_NOT_V2)?;
                let tk = ring.key(version).ok_or(ERR_NO_KEY)?;
                open_record_v2(tk, ring.tenant(), name, sealed)
            }
        }
    }
}

/// One ring of a tenant, as the job holds it.
struct Held {
    /// `Err(())`: it could not be read (the job does not try again).
    state: std::result::Result<TenantRingState, ()>,
    reloaded: bool,
}

/// The tenant rings of one copy job (AM-80 item 2): each read once per
/// job and tenant, and once more after a record named a version it
/// lacked. Every miss after the reload is kept for the job's pages
/// ([`JobRings::take_misses`]).
pub struct JobRings<R> {
    source: R,
    held: RefCell<BTreeMap<TenantId, Held>>,
    misses: RefCell<BTreeMap<(TenantId, u32), bool>>,
    loads: Cell<u64>,
    load_ms: Cell<u64>,
    /// Held while a ring is read: the copy checks records concurrently,
    /// and a check that finds no ring waits for one in flight instead of
    /// reading it again.
    loading: futures_util::lock::Mutex<()>,
}

impl<R: TenantRings> JobRings<R> {
    pub fn new(source: R) -> Self {
        JobRings {
            source,
            held: RefCell::new(BTreeMap::new()),
            misses: RefCell::new(BTreeMap::new()),
            loads: Cell::new(0),
            load_ms: Cell::new(0),
            loading: futures_util::lock::Mutex::new(()),
        }
    }

    /// How many rings the job read, and the milliseconds they took.
    pub fn loaded(&self) -> (u64, u64) {
        (self.loads.get(), self.load_ms.get())
    }

    /// The versions that the reloaded rings lacked in this job, each
    /// once: tenant, version, and whether the chain names it.
    pub fn take_misses(&self) -> Vec<(TenantId, u32, bool)> {
        std::mem::take(&mut *self.misses.borrow_mut())
            .into_iter()
            .map(|((t, v), named)| (t, v, named))
            .collect()
    }

    async fn load<T: Clock>(
        &self,
        clock: &T,
        tenant: &TenantId,
    ) -> std::result::Result<TenantRingState, ()> {
        let started = clock.now().0;
        let state = self.source.ring(tenant).await.map_err(|_| ());
        let spent = u64::try_from(clock.now().0.saturating_sub(started)).unwrap_or(0);
        self.loads.set(self.loads.get() + 1);
        self.load_ms.set(self.load_ms.get().saturating_add(spent));
        state
    }

    /// The ring of `tenant`: the job's, or read now; with `again`, read
    /// once more if this job has not done so yet.
    async fn ring<T: Clock>(
        &self,
        clock: &T,
        tenant: &TenantId,
        again: bool,
    ) -> std::result::Result<TenantRingState, ()> {
        let held = |rings: &Self| {
            rings
                .held
                .borrow()
                .get(tenant)
                .map(|h| (h.state.clone(), h.reloaded))
        };
        if let Some((state, reloaded)) = held(self) {
            if !again || reloaded {
                return state;
            }
        }
        // One read at a time; what a read in flight brought is looked at
        // again before reading: at most one load and one reload per
        // tenant and job, however many checks ask at once.
        let _loading = self.loading.lock().await;
        let reloaded = match held(self) {
            Some((state, reloaded)) if !again || reloaded => return state,
            Some(_) => true,
            None => false,
        };
        let state = self.load(clock, tenant).await;
        self.held.borrow_mut().insert(
            tenant.clone(),
            Held {
                state: state.clone(),
                reloaded,
            },
        );
        state
    }

    /// A ring of `tenant` that holds the key of `version`, or what the
    /// record under it counts (the rules of the module).
    pub async fn key_for<T: Clock>(
        &self,
        clock: &T,
        tenant: &TenantId,
        version: u32,
    ) -> std::result::Result<Rc<CopyRing>, RecordCheck> {
        let mut again = false;
        loop {
            match self.ring(clock, tenant, again).await {
                Err(()) => return Err(RecordCheck::RingFailed),
                Ok(TenantRingState::Shredded) => return Err(RecordCheck::Shredded),
                Ok(TenantRingState::Ring(ring)) if ring.key(version).is_some() => return Ok(ring),
                Ok(TenantRingState::Ring(ring)) if ring.destroyed(version) => {
                    return Err(RecordCheck::VersionDestroyed)
                }
                Ok(state) if again => {
                    let named = matches!(&state, TenantRingState::Ring(r) if r.named(version));
                    self.misses
                        .borrow_mut()
                        .insert((tenant.clone(), version), named);
                    return Err(RecordCheck::KeyMissing { named });
                }
                Ok(_) => again = true,
            }
        }
    }
}

/// The opener of the data record `name` whose bytes are `sealed`, after
/// the checks of its family that need no plaintext; or what it counts.
/// A name of another family than a data record is [`RecordCheck::Unreadable`].
pub async fn record_open<'k, K: Kek, R: TenantRings, T: Clock>(
    name: &str,
    sealed: &[u8],
    kek: &'k K,
    rings: &JobRings<R>,
    clock: &T,
) -> std::result::Result<RecordOpen<'k, K>, RecordCheck> {
    match family(name) {
        Family::DataV1 if scheme_two(sealed) => Err(RecordCheck::CrossScheme),
        Family::DataV1 => Ok(RecordOpen::Kek(kek)),
        Family::DataV2(tenant) => {
            let Some((named, version)) = v2_header(sealed) else {
                return Err(RecordCheck::CrossScheme);
            };
            // The raw bytes, before any parse: an envelope that names
            // tenant 0, or no tenant at all, is another tenant's too.
            if named != tenant.as_str().as_bytes() {
                return Err(RecordCheck::CrossTenant);
            }
            let ring = rings.key_for(clock, &tenant, version).await?;
            Ok(RecordOpen::Ring(ring))
        }
        _ => Err(RecordCheck::Unreadable),
    }
}

/// What a failed open of a data record counts.
pub fn open_failed(e: &BridgeError) -> RecordCheck {
    if is_cross_tenant(e) {
        RecordCheck::CrossTenant
    } else {
        RecordCheck::Unreadable
    }
}

/// Whether `bytes` is the gate anchor its name `name` promises.
fn anchor(name: &str, bytes: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Anchor {
        epoch: u64,
        #[allow(dead_code)]
        closed_at: i64,
    }
    let Some(epoch) = anchor_epoch(name) else {
        return false;
    };
    serde_json::from_slice::<Anchor>(bytes).is_ok_and(|a| a.epoch == epoch)
}

/// Proves a control record by its door part under the KEK, the owner
/// from its name. The private part is never opened.
fn control<K: Kek>(kek: &K, name: &str, owner: &Owner, bytes: &[u8]) -> RecordCheck {
    if !bytes.starts_with(CONTROL_MAGIC) {
        return RecordCheck::CrossScheme;
    }
    let opened = parse_control(bytes).and_then(|env| env.open_door(kek, name, owner.control()));
    match opened {
        Ok(_) => RecordCheck::Proved(None),
        Err(_) => RecordCheck::Unreadable,
    }
}

/// The one check of the record stored at `name` (the table of the
/// module): what the recovery copy does with it.
pub async fn check_record<K: Kek, R: TenantRings, T: Clock>(
    name: &str,
    bytes: &[u8],
    kek: &K,
    rings: &JobRings<R>,
    clock: &T,
) -> RecordCheck {
    match family(name) {
        Family::TenantKey => RecordCheck::Never,
        Family::Control(owner) => control(kek, name, &owner, bytes),
        Family::FlatRevocation if bytes.starts_with(CONTROL_MAGIC) => {
            control(kek, name, &Owner::Global, bytes)
        }
        Family::FlatRevocation if scheme_two(bytes) => RecordCheck::CrossScheme,
        Family::FlatRevocation => match open_manifest(kek, name, bytes) {
            Ok(_) => RecordCheck::Proved(None),
            Err(_) => RecordCheck::Unreadable,
        },
        Family::Anchor if anchor(name, bytes) => RecordCheck::Proved(None),
        Family::Anchor => RecordCheck::Unreadable,
        Family::Unknown => RecordCheck::Unknown(
            (!scheme_two(bytes))
                .then(|| open_manifest(kek, name, bytes).ok())
                .flatten(),
        ),
        Family::DataV1 | Family::DataV2(_) => {
            match record_open(name, bytes, kek, rings, clock).await {
                Ok(opener) => match opener.open_record(name, bytes) {
                    Ok(plain) => RecordCheck::Proved(Some(plain)),
                    Err(e) => open_failed(&e),
                },
                Err(check) => check,
            }
        }
    }
}
