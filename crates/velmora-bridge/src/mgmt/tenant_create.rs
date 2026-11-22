//! `POST /v1/tenants`: create, or adopt, the tenant of a workspace
//! (`Tenancy::create_tenant`; ADR §6.4 "From workspace to tenant", step
//! 2; AM-58).
//!
//! **The order (AM-58).** Every step is idempotent, and a retry resumes
//! at the first step that is missing:
//!
//! 1. `m/tref/<sha256(external_ref)>`, put once, names the tenant id
//!    (create-or-adopt). A put that loses reads the winner's id.
//! 2. Record 1: lifecycle `provisioning`, unit 0 listed, jurisdiction
//!    `none`, the registry's location hint ([`LOCATION_HINT`]).
//! 3. The birth token for seq 1 (tenant, unit 0, jurisdiction `""`, record
//!    seq 1, schema version, key scheme 2, kind `birth`), sealed under the
//!    control key, then `provision` on the root unit, then the born marker
//!    `m/ub/<t>/0` (put once). The sealed token **is** the marker's
//!    content: one control record that names the tenant, the unit and the
//!    record seq, with no secret (ADR §2.4 rule 6). Rule 6 allows
//!    `provision` only while the head is record 1 and the marker is
//!    absent; a unit that is born but has no marker (a crash between the
//!    two) gets its marker (the finisher's rule).
//! 4. The tenant key, version 1: the claim and the commit in the tenant
//!    chain, the key in both key buckets (`keys::tk::create_key_version`,
//!    over [`ChainClaims`]).
//! 5. The record that sets lifecycle `live` (`Activate`), with the
//!    `external_ref` in its private part, sealed under the tenant key.
//!
//! **Before the first write (AM-78, AM-70).** The body is checked
//! first: a `jurisdiction` other than `none`, any `limits` and any
//! `rate_class` answer `400` (AM-58, AM-76). Then the directory gate must
//! be open (`directory::gate::is_open`; with `DIRECTORY` unbound it counts
//! as closed) and the head of `m/kl/` must open. Either missing answers
//! `503` with nothing written, so no managed tenant chain is written
//! before its environment's first open. A head of `m/kl/` under a KEK
//! version this Worker does not hold yet is a failure that may pass: no
//! alert. Damage there alerts.
//!
//! **Intents (AM-75).** Every tenant-chain record this call writes (record
//! 1, the key claim, void and commit, `Activate`) has its intent first:
//! `apply_control(tenant, tenant chain, seq)` is sent (a failure stops the
//! call before the record, `503`) and its `pending_ops` row noted (best
//! effort), for the seq after the head read just before. If another writer
//! takes that seq, the record lands higher; the intent still finishes it,
//! because the finisher applies the head, never a row's seq (`pending`).
//! Each record names the call's `call_key_hash` (AM-79).
//!
//! **Step 3: the stores (AM-75).** Before it answers a `live` tenant (the
//! call that activated it, and every call that adopts one), the call runs
//! the tenant chain's finisher ([`TenantStores`]): the directory and the
//! listed units brought to the head, the directory first for an opening.
//! Until every store holds the head the answer is `503`, and the intent's
//! message or the next call finishes it.
//!
//! **Maintenance.** Under `MAINTENANCE=restore` every mutation answers
//! `503`, so the call stops after its body checks, before any read.
//!
//! **Answers.** `201` with the tenant for the call that wrote `m/tref/`;
//! `200` with it for a call that adopts through `m/tref/` (it may finish
//! a create still in flight), a `live` or deleting tenant included;
//! `409 external_ref_retired` when it names a shredding or shredded
//! tenant; `400 jurisdiction_not_served` for any jurisdiction but `none`
//! (absent means `none`, AM-58), `400 limits_not_served` and
//! `400 rate_class_not_served` (AM-76); `503` for every store that cannot be
//! reached, for missing key locations, and while another create holds a
//! step this one cannot take over; `500` with an alert for a record that
//! does not verify (`m/tref/`, the born marker, the tenant head), a drawn
//! id that already has a chain, and a birth token the unit refuses (no
//! retry changes these). While the head is `provisioning`, an unborn root
//! unit is expected: nothing pages (AM-58).
//!
//! Every error answer carries nothing of a store's own text.

use std::cell::RefCell;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_mgmt_types::wire::{TenantCreate, JURISDICTION_NONE};
use velmora_mgmt_types::{parse_request, Code};

use crate::crypto::scheme2::{parse_control, seal_control, ControlOwner, ControlSealer, KCV_LEN};
use crate::directory::chain::{ChainError, Written};
use crate::directory::gate::is_open;
use crate::directory::record::{Lifecycle, Tenant, TenantDoor as Door};
use crate::directory::seal::committed_check;
use crate::directory::transition::{Actor, Change};
use crate::keys::locations::{is_kek_not_held, read_locations};
use crate::keys::ports::{ControlChain, ControlIntents};
use crate::keys::tk::{create_key_version, Claim, Commit, KeyCheck, KeyVersionClaims};
use crate::mgmt::adapters::RoutedUnit;
use crate::mgmt::serve::Answer;
use crate::mgmt::tenant::{tenant_of, Read};
use crate::ports::Clock;
use crate::records::RecordStore;
use crate::root::{Root, RootPorts};
use crate::types::{BridgeError, Result, UnixMs};
use crate::unit::birth::{BirthKind, BirthToken, ProvisionRefusal};
use crate::unit::call::Refused;
use crate::unit::schema::SCHEMA_VERSION;
use crate::unit::{UnitAnswer, UnitName, UnitOp};
use crate::unit_router::UnitRouter;

/// The label of an `m/tref/` record's door part.
pub const TREF_LABEL: &str = "velmora/tref/v1";
/// The label of a born marker's door part.
pub const BORN_LABEL: &str = "velmora/ub/v1";
/// Where the registry places a tenant with no jurisdiction (AM-58: where
/// today's D1 is placed; est).
pub const LOCATION_HINT: &str = "enam";
/// The kind of a tenant create's intent rows (`pending_ops.kind`).
pub const TENANT_CREATE_KIND: &str = "tenant.create";

/// A jurisdiction the plane serves (AM-58, AM-76): milestone 1 serves one,
/// [`Jurisdiction::None`] (no data-location jurisdiction).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Jurisdiction {
    None,
}

/// The two spellings of a [`Jurisdiction`]: a tenant record names a
/// non-empty label, the unit's namespace (and so the birth token) its own
/// form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JurisdictionForms {
    pub record: &'static str,
    pub token: &'static str,
}

impl Jurisdiction {
    /// The jurisdiction a create asks for: absent or `none` is
    /// [`Jurisdiction::None`]; any other value is not served (`None`).
    pub fn of_request(asked: Option<&str>) -> Option<Jurisdiction> {
        match asked {
            None => Some(Jurisdiction::None),
            Some(j) if j == JURISDICTION_NONE => Some(Jurisdiction::None),
            Some(_) => None,
        }
    }

    /// Both spellings, from this one function: `none` in the record, `""`
    /// in the birth token. No code compares the two strings.
    pub fn forms(self) -> JurisdictionForms {
        match self {
            Jurisdiction::None => JurisdictionForms {
                record: "none",
                token: "",
            },
        }
    }
}
/// The root unit.
const ROOT: u32 = 0;
/// The bytes of a tenant id after its `t_` prefix, as hex.
const ID_BYTES: usize = 8;
/// Writes of one step that lose to another create before this one
/// answers `503` (each re-reads the head first).
const MAX_STEP_TRIES: u32 = 3;

const ERR_TREF: BridgeError = BridgeError::Crypto("tref record invalid");
const ERR_BORN: BridgeError = BridgeError::Crypto("born marker invalid");

// ---------------------------------------------------------------------------
// Names and records
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The SHA-256 of an `external_ref`, lowercase hex.
pub fn ref_hash(external_ref: &str) -> String {
    hex(&Sha256::digest(external_ref.as_bytes()))
}

/// `m/tref/<sha256(external_ref)>`.
pub fn tref_name(external_ref: &str) -> String {
    format!("m/tref/{}", ref_hash(external_ref))
}

/// `m/ub/<t>/<unit>`.
pub fn born_name(tenant: &crate::unit::TenantId, unit: u32) -> String {
    format!("m/ub/{}/{unit}", tenant.as_str())
}

/// The door part of an `m/tref/` record: the hash it is named by, and
/// the tenant id. Sealed under the control key, door part only: it
/// outlives the shred (ADR §3.3, Sec-7).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrefRecord {
    label: String,
    v: u32,
    ref_hash: String,
    tenant: String,
}

/// The door part of a born marker: the birth token itself.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BornRecord {
    label: String,
    v: u32,
    token: BirthToken,
}

/// A KEK version this Worker does not hold yet (a record of a newer
/// deploy): a failure that may pass, never damage (as the chain's seal
/// rules it, `directory::seal`).
const ERR_KEK_NOT_HELD: BridgeError = BridgeError::Invalid("control record under a newer KEK");

/// The door part of a global control record `name`.
fn open_global<'b, K: crate::ports::Kek>(
    kek: &K,
    name: &'b str,
    bytes: &'b [u8],
) -> Result<Vec<u8>> {
    let envelope = parse_control(bytes)?;
    let v = envelope.kek_version();
    match envelope.open_door(kek, name, ControlOwner::Global) {
        Ok(opened) => Ok(opened.door().to_vec()),
        Err(_)
            if kek.version(v).is_none()
                && v > kek.active().0
                && v <= crate::config::MAX_KEK_VERSION =>
        {
            Err(ERR_KEK_NOT_HELD)
        }
        Err(e) => Err(e),
    }
}

/// The tenant `m/tref/` names for `external_ref`; `None` when there is no
/// record. A record that does not open under the control key, or names
/// another hash, is damage (an `Err`).
pub async fn read_tref<S: RecordStore, K: crate::ports::Kek>(
    records: &S,
    kek: &K,
    external_ref: &str,
) -> Result<Option<crate::unit::TenantId>> {
    let name = tref_name(external_ref);
    let Some(bytes) = records.get(&name).await? else {
        return Ok(None);
    };
    let door = open_global(kek, &name, &bytes)?;
    let body: TrefRecord = serde_json::from_slice(&door).map_err(|_| ERR_TREF)?;
    if body.label != TREF_LABEL || body.v != 1 || body.ref_hash != ref_hash(external_ref) {
        return Err(ERR_TREF);
    }
    let tenant = crate::unit::TenantId::parse(&body.tenant).ok_or(ERR_TREF)?;
    // A managed tenant id, never tenant 0.
    crate::TenantId::parse(tenant.as_str()).map_err(|_| ERR_TREF)?;
    Ok(Some(tenant))
}

/// Puts the `m/tref/` record naming `tenant`, once. `false`: a record is
/// there already (read it).
pub async fn put_tref<S: RecordStore, K: crate::ports::Kek, R: FillRandom>(
    records: &S,
    kek: &K,
    external_ref: &str,
    tenant: &crate::unit::TenantId,
    rng: &mut R,
) -> Result<bool> {
    let name = tref_name(external_ref);
    let door = serde_json::to_vec(&TrefRecord {
        label: TREF_LABEL.to_string(),
        v: 1,
        ref_hash: ref_hash(external_ref),
        tenant: tenant.as_str().to_string(),
    })
    .map_err(|_| ERR_TREF)?;
    let sealed = seal_control(kek, &name, &ControlSealer::Global, &door, None, rng)?;
    records.put_if_absent(&name, sealed).await
}

/// The birth token of `tenant`'s root unit for record 1.
pub fn birth_token(tenant: &crate::unit::TenantId, jurisdiction: Jurisdiction) -> BirthToken {
    BirthToken {
        name: UnitName::new(tenant.clone(), ROOT),
        jurisdiction: jurisdiction.forms().token.to_string(),
        record_seq: 1,
        schema_version: SCHEMA_VERSION,
        key_scheme: 2,
        kind: BirthKind::Birth,
    }
}

/// The birth token sealed under the control key, as the born marker
/// `m/ub/<t>/<unit>` holds it and as `provision` carries it.
pub fn seal_born<K: crate::ports::Kek, R: FillRandom>(
    kek: &K,
    token: &BirthToken,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let name = born_name(&token.name.tenant, token.name.unit);
    let door = serde_json::to_vec(&BornRecord {
        label: BORN_LABEL.to_string(),
        v: 1,
        token: token.clone(),
    })
    .map_err(|_| ERR_BORN)?;
    seal_control(kek, &name, &ControlSealer::Global, &door, None, rng)
}

/// The token a born marker holds; `None` when there is no marker.
pub async fn read_born<S: RecordStore, K: crate::ports::Kek>(
    records: &S,
    kek: &K,
    tenant: &crate::unit::TenantId,
    unit: u32,
) -> Result<Option<BirthToken>> {
    let name = born_name(tenant, unit);
    let Some(bytes) = records.get(&name).await? else {
        return Ok(None);
    };
    let door = open_global(kek, &name, &bytes)?;
    let body: BornRecord = serde_json::from_slice(&door).map_err(|_| ERR_BORN)?;
    if body.label != BORN_LABEL
        || body.v != 1
        || body.token.name != UnitName::new(tenant.clone(), unit)
    {
        return Err(ERR_BORN);
    }
    Ok(Some(body.token))
}

// ---------------------------------------------------------------------------
// The key version claims, over the tenant chain
// ---------------------------------------------------------------------------

/// [`KeyVersionClaims`] over the tenant chain of the composition root:
/// `ClaimKeyVersion`, `VoidKeyClaim` and `CommitKeyVersion` records,
/// written by tenant creation, each after its intent ([`write_record`]).
/// A commit loads the key it commits first (the record after it is
/// sealed under it).
pub struct ChainClaims<'r, 'a, P: RootPorts, R, I> {
    pub root: &'r Root<'a, P, R>,
    pub intents: &'r I,
    pub now: UnixMs,
    /// The management call's `call_key_hash` (AM-79); `None` for a writer
    /// that is no management call.
    pub key_hash: Option<&'r str>,
}

/// Writes one tenant-chain record, its intent first (AM-75): the intent
/// names the seq after the head read here, its message is sent (a failure
/// stops the write: nothing is recorded), and its `pending_ops` row is
/// noted, best effort. A record that lands above that seq (another writer
/// took it) is still finished by the intent, since the finisher applies
/// the head. The record names `key_hash` (AM-79).
pub async fn write_record<P, R, I>(
    root: &Root<'_, P, R>,
    intents: &I,
    tenant: &crate::TenantId,
    change: &Change,
    now: UnixMs,
    key_hash: Option<&str>,
) -> std::result::Result<Written, ChainError>
where
    P: RootPorts,
    R: FillRandom,
    I: ControlIntents,
{
    let t = managed(tenant);
    let head = root.heads().head_seq(&t, 0).await?;
    let next = head.map_or(1, |h| h.saturating_add(1));
    intents
        .send(tenant, ControlChain::Tenant, next)
        .await
        .map_err(ChainError::Store)?;
    let _ = intents
        .note(tenant, ControlChain::Tenant, next, TENANT_CREATE_KIND)
        .await;
    root.chain()
        .write_keyed(
            &t,
            change,
            Actor::TenantCreation,
            now,
            head.unwrap_or(0),
            key_hash,
        )
        .await
}

fn managed(t: &crate::TenantId) -> Tenant {
    Tenant::Managed(t.clone())
}

fn chain_err(e: ChainError) -> BridgeError {
    match e {
        ChainError::Store(e) => e,
        _ => BridgeError::Invalid("tenant chain refused the key claim"),
    }
}

impl<P: RootPorts, R: FillRandom, I: ControlIntents> ChainClaims<'_, '_, P, R, I> {
    async fn door(&self, t: &crate::TenantId) -> Result<Door> {
        self.root
            .heads()
            .head(&managed(t), 0)
            .await
            .map_err(chain_err)?
            .map(|r| r.door)
            .ok_or(BridgeError::Invalid("tenant has no chain"))
    }

    fn committed(door: &Door, from: u32) -> Option<Claim> {
        (door.tk_version > from)
            .then(|| committed_check(door, door.tk_version))
            .flatten()
            .map(|kcv| Claim::Committed {
                version: door.tk_version,
                kcv,
            })
    }

    async fn write(
        &self,
        t: &crate::TenantId,
        change: Change,
    ) -> std::result::Result<(), ChainError> {
        write_record(self.root, self.intents, t, &change, self.now, self.key_hash)
            .await
            .map(|_| ())
    }
}

impl<P: RootPorts, R: FillRandom, I: ControlIntents> KeyVersionClaims
    for ChainClaims<'_, '_, P, R, I>
{
    async fn claim(&self, t: &crate::TenantId, from: u32) -> Result<Claim> {
        for _ in 0..MAX_STEP_TRIES {
            let door = self.door(t).await?;
            if let Some(c) = Self::committed(&door, from) {
                return Ok(c);
            }
            if !matches!(door.lifecycle, Lifecycle::Provisioning | Lifecycle::Live)
                || door.deletion.is_some()
            {
                return Ok(Claim::Refused);
            }
            if let Some(v) = door.rotating_to {
                return Ok(Claim::Claimed(v));
            }
            let Some(version) = door.highest_claimed.checked_add(1) else {
                return Ok(Claim::Refused);
            };
            match self.write(t, Change::ClaimKeyVersion { version }).await {
                Ok(()) => return Ok(Claim::Claimed(version)),
                // Another run claimed or committed in between: read again.
                Err(ChainError::Refused(_) | ChainError::Busy) => continue,
                Err(e) => return Err(chain_err(e)),
            }
        }
        Err(BridgeError::Invalid("key claim lost every try"))
    }

    async fn void(&self, t: &crate::TenantId, version: u32) -> Result<Claim> {
        let door = self.door(t).await?;
        if door.rotating_to != Some(version) {
            return Err(BridgeError::Invalid("not the open key claim"));
        }
        self.write(t, Change::VoidKeyClaim { version })
            .await
            .map_err(chain_err)?;
        Ok(Claim::Claimed(version + 1))
    }

    async fn commit(
        &self,
        t: &crate::TenantId,
        version: u32,
        kcv: [u8; KCV_LEN],
    ) -> Result<Commit> {
        // The records after the commit are sealed under this key.
        self.root.load_key(t, version, kcv).await?;
        match self
            .write(t, Change::CommitKeyVersion { version, kcv })
            .await
        {
            Ok(()) => Ok(Commit::Committed),
            Err(ChainError::Refused(_)) => {
                let door = self.door(t).await?;
                match (door.tk_version == version, committed_check(&door, version)) {
                    (true, Some(k)) if k == kcv => Ok(Commit::Committed),
                    _ if door.deletion.is_some()
                        || matches!(door.lifecycle, Lifecycle::Shredding | Lifecycle::Shredded) =>
                    {
                        Ok(Commit::Stopped)
                    }
                    _ => Err(BridgeError::Invalid("key commit refused")),
                }
            }
            Err(e) => Err(chain_err(e)),
        }
    }

    async fn committed_kcv(&self, t: &crate::TenantId, version: u32) -> Result<KeyCheck> {
        let door = self.door(t).await?;
        Ok(match committed_check(&door, version) {
            Some(kcv) => KeyCheck::Committed(kcv),
            None => KeyCheck::NotCommitted,
        })
    }
}

// ---------------------------------------------------------------------------
// Step 3: the stores
// ---------------------------------------------------------------------------

/// Step 3 of a tenant-chain change (ADR §2.5, AM-75): the tenant chain's
/// finisher, run by the handler before it answers.
#[allow(async_fn_in_trait)]
pub trait TenantStores {
    /// Brings the directory and every listed unit of `tenant` to its
    /// chain's head. `Ok(true)`: every store holds the head (an unbound
    /// directory counts as holding it). `Ok(false)` or `Err`: not yet; the
    /// call answers `503` and the intent's message finishes it.
    async fn finish(&self, tenant: &crate::TenantId) -> Result<bool>;
}

/// [`TenantStores`] over `directory::finish::finish_tenant`, with the
/// root's chain and directory and the units' adapter.
pub struct ChainStores<'r, 'a, P: RootPorts, R, U> {
    pub root: &'r Root<'a, P, R>,
    pub units: &'r U,
}

impl<P, R, U> TenantStores for ChainStores<'_, '_, P, R, U>
where
    P: RootPorts,
    R: FillRandom,
    U: crate::directory::finish::TenantUnits,
{
    async fn finish(&self, tenant: &crate::TenantId) -> Result<bool> {
        use crate::directory::finish::{finish_tenant, StoreStep};
        let dir = self.root.directory();
        let now = self.root.clock().now();
        let run = finish_tenant(&self.root.chain(), dir.as_ref(), self.units, tenant, now).await?;
        for page in &run.pages {
            crate::trace::alert(|| format!("mgmt: tenant create: finisher: {page}"));
        }
        let head = run.head.seq;
        let holds = |s: &StoreStep| match s {
            StoreStep::Holds(seq) => *seq >= head,
            StoreStep::Unbound => true,
            StoreStep::Waiting | StoreStep::Failed => false,
        };
        Ok(head > 0
            && run.head.complete
            && holds(&run.directory)
            && !run.units.is_empty()
            && run.units.iter().all(|(_, s)| holds(s)))
    }
}

// ---------------------------------------------------------------------------
// The call
// ---------------------------------------------------------------------------

/// The stores of a tenant create.
pub struct CreatePorts<'r, 'a, P: RootPorts, R, U, I, F> {
    pub ports: &'a P,
    pub root: &'r Root<'a, P, R>,
    /// The router's root-unit calls (`provision`, and a probe of an
    /// unborn unit).
    pub unit: &'r RoutedUnit<'r, U>,
    /// The tenant chain's intents (AM-75).
    pub intents: &'r I,
    /// Step 3: the stores brought to the head before a `live` answer.
    pub stores: &'r F,
    /// `MAINTENANCE`: under `restore` the call writes nothing.
    pub maintenance: crate::config::Maintenance,
}

/// Why a step stopped the call: its answer.
enum Stop {
    Answer(Answer),
}

fn unavailable() -> Stop {
    Stop::Answer(Answer::code(Code::ServiceUnavailable, None))
}

fn internal() -> Stop {
    Stop::Answer(Answer::code(Code::InternalError, None))
}

/// A record that does not verify, or a step no retry can finish: `500`
/// (kofra-api pages on it), with an alert line of fixed words.
fn damaged(what: &'static str) -> Stop {
    crate::trace::alert(|| format!("mgmt: tenant create stopped: {what}"));
    internal()
}

/// A store answer: `500` for a record that does not verify (a control
/// record's seal or form: `BridgeError::Crypto`), `503` for the rest.
fn store_stop(e: &BridgeError, what: &'static str) -> Stop {
    match e {
        BridgeError::Crypto(_) => damaged(what),
        _ => unavailable(),
    }
}

/// A chain answer: `500` for a head that does not verify, `503` else.
fn chain_stop(e: &ChainError) -> Stop {
    match e {
        ChainError::Damaged(_) | ChainError::PrivateUnreadable => damaged("tenant head damaged"),
        _ => unavailable(),
    }
}

/// The `call_key_hash` of a call's `Idempotency-Key` (AM-79): SHA-256,
/// lowercase hex.
pub fn call_key_hash(idempotency_key: &str) -> String {
    velmora_mgmt_types::idem::hex(&velmora_mgmt_types::idem::key_hash(idempotency_key))
}

/// Runs a tenant create. `rng` draws the tenant id and seals the
/// control records; it is taken for the call. `idempotency_key` is the
/// call's (the gate requires one on every write); its hash goes into
/// every record the call writes (AM-79).
pub async fn create_tenant<P, R, U, I, F, G>(
    ports: &CreatePorts<'_, '_, P, R, U, I, F>,
    body: &[u8],
    idempotency_key: Option<&str>,
    rng: &mut G,
) -> Answer
where
    P: RootPorts,
    R: FillRandom,
    U: UnitRouter,
    I: ControlIntents,
    F: TenantStores,
    G: FillRandom,
{
    let key_hash = idempotency_key.map(call_key_hash);
    match run(ports, body, key_hash.as_deref(), rng).await {
        Ok(answer) | Err(Stop::Answer(answer)) => answer,
    }
}

/// The body's checks, before any read (AM-58, AM-76).
fn checked_body(body: &[u8]) -> std::result::Result<(TenantCreate, Jurisdiction), Stop> {
    let body: TenantCreate =
        parse_request(body).map_err(|c| Stop::Answer(Answer::code(c, None)))?;
    let Some(jurisdiction) = Jurisdiction::of_request(body.jurisdiction.as_deref()) else {
        return Err(Stop::Answer(Answer::code(
            Code::JurisdictionNotServed,
            None,
        )));
    };
    if body.limits.is_some() {
        return Err(Stop::Answer(Answer::code(Code::LimitsNotServed, None)));
    }
    if body.rate_class.is_some() {
        return Err(Stop::Answer(Answer::code(Code::RateClassNotServed, None)));
    }
    Ok((body, jurisdiction))
}

/// The checks before the first write (AM-78, AM-70): the directory gate
/// is open, and the head of `m/kl/` opens. Answers the key locations.
async fn ready_to_write<P: RootPorts, R: FillRandom>(
    root: &Root<'_, P, R>,
) -> std::result::Result<crate::keys::locations::KeyLocations, Stop> {
    let records = root.records();
    // With `DIRECTORY` unbound the gate counts as closed (AM-78).
    let Some(dir) = root.directory() else {
        return Err(unavailable());
    };
    match is_open(records, &dir).await {
        Ok(true) => {}
        // Closed, or a read that failed: closed (`is_open`).
        Ok(false) | Err(_) => return Err(unavailable()),
    }
    match read_locations(records, root.kek(), 0).await {
        Ok(Some(l)) => Ok(l),
        // Fail closed: no tenant before its environment's first `m/kl/`
        // record (the operator call, AM-70).
        Ok(None) => Err(unavailable()),
        // A record of a newer deploy's KEK: a failure that may pass, no
        // alert (§R7-2 L5-LOW).
        Err(e) if is_kek_not_held(&e) => Err(unavailable()),
        // A store that did not answer: nothing is known to be wrong.
        Err(BridgeError::Blob(_)) => Err(unavailable()),
        Err(_) => {
            crate::trace::alert(|| "mgmt: tenant create: key locations unreadable".to_string());
            Err(unavailable())
        }
    }
}

async fn run<P, R, U, I, F, G>(
    ports: &CreatePorts<'_, '_, P, R, U, I, F>,
    body: &[u8],
    key_hash: Option<&str>,
    rng: &mut G,
) -> std::result::Result<Answer, Stop>
where
    P: RootPorts,
    R: FillRandom,
    U: UnitRouter,
    I: ControlIntents,
    F: TenantStores,
    G: FillRandom,
{
    let (body, jurisdiction) = checked_body(body)?;
    // Every mutation answers 503 under restore, before any read.
    if ports.maintenance == crate::config::Maintenance::Restore {
        return Err(unavailable());
    }
    let root = ports.root;
    let records = root.records();
    let kek = root.kek();
    let now = root.clock().now();
    // Nothing is written before both checks pass (AM-78).
    let locations = ready_to_write(root).await?;

    // 1. m/tref/: create-or-adopt.
    let (tenant, ours) = match read_tref(records, kek, &body.external_ref).await {
        Ok(Some(t)) => (t, false),
        Ok(None) => {
            let mut id = [0u8; ID_BYTES];
            rng.fill_bytes(&mut id).map_err(|_| unavailable())?;
            let text = format!("t_{}", hex(&id));
            // A managed id, checked before it is put: an all-zero draw is
            // tenant 0 and is never named (the retry draws again).
            crate::TenantId::parse(&text).map_err(|_| unavailable())?;
            let drawn = crate::unit::TenantId::parse(&text).ok_or_else(internal)?;
            // An id that already has a chain is never named for another
            // workspace (a weak or broken random source): draw again on
            // the retry.
            let drawn_chain = crate::TenantId::parse(&text).map_err(|_| internal())?;
            if head(root, &Tenant::Managed(drawn_chain)).await?.is_some() {
                return Err(damaged("drawn tenant id has a chain"));
            }
            match put_tref(records, kek, &body.external_ref, &drawn, rng).await {
                Ok(true) => (drawn, true),
                Ok(false) => match read_tref(records, kek, &body.external_ref).await {
                    Ok(Some(t)) => (t, false),
                    Ok(None) => return Err(unavailable()),
                    Err(e) => return Err(store_stop(&e, "tref record does not verify")),
                },
                // Sealing or the put: nothing was verified, so never damage.
                Err(_) => return Err(unavailable()),
            }
        }
        Err(e) => return Err(store_stop(&e, "tref record does not verify")),
    };
    let chain_tenant = crate::TenantId::parse(tenant.as_str()).map_err(|_| unavailable())?;
    let t = Tenant::Managed(chain_tenant.clone());

    // An adopted tenant that is already past provisioning is answered as
    // it is.
    let first = head(root, &t).await?;
    // A chain under the id this call named a moment ago (it read none
    // before the put) is a concurrent create of the same workspace that
    // adopted the record and went on: this call goes on with it too.
    // `201` for the call that named the tenant, `200` for one that adopts
    // it through `m/tref/` (it may finish a create still in flight).
    let status = if ours { 201 } else { 200 };
    if let Some(door) = &first {
        match door.lifecycle {
            Lifecycle::Shredding | Lifecycle::Shredded => {
                return Ok(Answer::code(Code::ExternalRefRetired, None))
            }
            Lifecycle::Live => {
                stores_hold(ports.stores, &chain_tenant).await?;
                return answer(tenant.as_str(), door, 200);
            }
            Lifecycle::Provisioning => {}
        }
    }

    // 2. Record 1. No limit and no rate class (AM-76: a create that
    // carries either was refused above).
    if first.is_none() {
        let create = Change::Create {
            jurisdiction: jurisdiction.forms().record.to_string(),
            location_hint: Some(LOCATION_HINT.to_string()),
            synthetic: false,
            limits: std::collections::BTreeMap::new(),
            rate_json: serde_json::Map::new(),
            features_json: serde_json::Map::new(),
        };
        match write_record(root, ports.intents, &chain_tenant, &create, now, key_hash).await {
            Ok(_) => {}
            // Another create wrote record 1 first: go on from its head.
            Err(ChainError::Refused(_) | ChainError::Busy) => {}
            Err(_) => return Err(unavailable()),
        }
    }

    // 3. The root unit's birth, then its marker.
    birth(ports, &tenant, &t, jurisdiction, rng).await?;

    // 4. Tenant key version 1.
    let door = head(root, &t).await?.ok_or_else(unavailable)?;
    if door.lifecycle != Lifecycle::Provisioning {
        return finish(root, ports.stores, &chain_tenant, &tenant, &t, status).await;
    }
    if door.tk_version == 0 || door.rotating_to.is_some() {
        let claims = ChainClaims {
            root,
            intents: ports.intents,
            now,
            key_hash,
        };
        let created = create_key_version(
            &locations,
            &ports.ports.key_buckets(),
            &claims,
            kek,
            &chain_tenant,
            0,
            rng,
        )
        .await;
        if created.is_err() {
            // Contention between two creates is among these: a retry
            // finishes it; the alert shows one that never does.
            crate::trace::alert(|| "mgmt: tenant create: key version not created".to_string());
            return Err(unavailable());
        }
    }

    // 5. Live.
    let door = head(root, &t).await?.ok_or_else(unavailable)?;
    if door.lifecycle == Lifecycle::Provisioning {
        let kcv = committed_check(&door, door.tk_version).ok_or_else(unavailable)?;
        root.load_key(&chain_tenant, door.tk_version, kcv)
            .await
            .map_err(|_| {
                crate::trace::alert(|| "mgmt: tenant create: committed key not loaded".to_string());
                unavailable()
            })?;
        let activate = Change::Activate {
            external_ref: Some(body.external_ref.clone()),
        };
        match write_record(root, ports.intents, &chain_tenant, &activate, now, key_hash).await {
            Ok(Written::Wrote(_) | Written::Unchanged(_)) => {}
            Err(ChainError::Refused(_) | ChainError::Busy) => {}
            Err(_) => return Err(unavailable()),
        }
    }
    finish(root, ports.stores, &chain_tenant, &tenant, &t, status).await
}

/// The tenant's head, door part only.
async fn head<P: RootPorts, R: FillRandom>(
    root: &Root<'_, P, R>,
    t: &Tenant,
) -> std::result::Result<Option<Door>, Stop> {
    root.heads()
        .head(t, 0)
        .await
        .map(|r| r.map(|r| r.door))
        .map_err(|e| chain_stop(&e))
}

/// The head after the last step: `201` with the tenant once it is
/// `live`; `503` while another create still holds a step.
/// Step 3 before a `live` answer: `503` until every store holds the head.
async fn stores_hold<F: TenantStores>(
    stores: &F,
    tenant: &crate::TenantId,
) -> std::result::Result<(), Stop> {
    match stores.finish(tenant).await {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(unavailable()),
    }
}

async fn finish<P: RootPorts, R: FillRandom, F: TenantStores>(
    root: &Root<'_, P, R>,
    stores: &F,
    chain_tenant: &crate::TenantId,
    tenant: &crate::unit::TenantId,
    t: &Tenant,
    status: u16,
) -> std::result::Result<Answer, Stop> {
    let door = head(root, t).await?.ok_or_else(unavailable)?;
    match door.lifecycle {
        Lifecycle::Live => {
            stores_hold(stores, chain_tenant).await?;
            // The head the stores hold: read again, so the answer is
            // never older than what they were brought to.
            let door = head(root, t).await?.ok_or_else(unavailable)?;
            match door.lifecycle {
                Lifecycle::Live => answer(tenant.as_str(), &door, status),
                Lifecycle::Shredding | Lifecycle::Shredded => {
                    Ok(Answer::code(Code::ExternalRefRetired, None))
                }
                Lifecycle::Provisioning => Err(unavailable()),
            }
        }
        Lifecycle::Shredding | Lifecycle::Shredded => {
            Ok(Answer::code(Code::ExternalRefRetired, None))
        }
        Lifecycle::Provisioning => Err(unavailable()),
    }
}

fn answer(id: &str, door: &Door, status: u16) -> std::result::Result<Answer, Stop> {
    match tenant_of(id, door) {
        Read::Tenant(t) => {
            let json = serde_json::to_vec(&*t).map_err(|_| internal())?;
            Ok(Answer::json(status, json))
        }
        Read::Unavailable => Ok(Answer::code(Code::ExternalRefRetired, None)),
        Read::NotYet => Err(unavailable()),
        Read::Damaged => Err(internal()),
    }
}

/// Step 3: `provision` while the head is record 1 and no marker exists,
/// then the marker. A unit that is born with no marker gets it; a unit
/// that is not born once the head moved past record 1 cannot be born
/// with a birth token any more: `500` with an alert when the unit says
/// so, `503` with an alert when the router cannot tell it from an
/// unreachable unit (an operator's case either way).
async fn birth<P, R, U, I, F, G>(
    ports: &CreatePorts<'_, '_, P, R, U, I, F>,
    tenant: &crate::unit::TenantId,
    t: &Tenant,
    jurisdiction: Jurisdiction,
    rng: &mut G,
) -> std::result::Result<(), Stop>
where
    P: RootPorts,
    R: FillRandom,
    U: UnitRouter,
    G: FillRandom,
{
    let root = ports.root;
    let records = root.records();
    let kek = root.kek();
    let name = born_name(tenant, ROOT);
    match read_born(records, kek, tenant, ROOT).await {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(e) => return Err(store_stop(&e, "born marker does not verify")),
    }
    let door = head(root, t).await?.ok_or_else(unavailable)?;
    let token = birth_token(tenant, jurisdiction);
    let sealed = seal_born(kek, &token, rng).map_err(|_| unavailable())?;
    let first_record = door.seq == token.record_seq
        && door.lifecycle == Lifecycle::Provisioning
        && door.units.contains(&ROOT);
    let born = if first_record {
        let op = UnitOp::Provision {
            token,
            sealed: sealed.clone(),
        };
        match ports.unit.call(tenant, op).await {
            Ok(a) => match a.reply.answer {
                UnitAnswer::Ok { .. } => true,
                UnitAnswer::Refused {
                    reason: Refused::Provision(ProvisionRefusal::AlreadyBorn),
                    ..
                } => true,
                // The unit refuses the token itself (a name, scheme,
                // schema or jurisdiction that does not match): no retry
                // changes that.
                UnitAnswer::Refused {
                    reason: Refused::Provision(_),
                    ..
                } => return Err(damaged("the root unit refused its birth token")),
                _ => return Err(unavailable()),
            },
            Err(_) => return Err(unavailable()),
        }
    } else {
        // The head moved past record 1: only a unit that is born already
        // gets its marker (another create provisioned it, or a crash came
        // between `provision` and the marker).
        match ports.unit.call(tenant, UnitOp::HeldKeys {}).await {
            Ok(a) => matches!(a.reply.answer, UnitAnswer::Ok { .. }),
            // The router answers an unborn listed unit of a `provisioning`
            // tenant as it answers an unreachable one: `503`, and an alert,
            // since only an operator can finish a tenant whose unit is
            // unborn once the head moved past record 1.
            Err(_) => {
                crate::trace::alert(|| {
                    "mgmt: tenant create: root unit unborn or unreachable after record 1"
                        .to_string()
                });
                return Err(unavailable());
            }
        }
    };
    if !born && !first_record {
        // Rule 6 forbids a birth token now, and nothing else makes it.
        return Err(damaged("root unit unborn after record 1"));
    }
    if !born {
        return Err(unavailable());
    }
    match records.put_if_absent(&name, sealed).await {
        // Written, or another create's marker landed first.
        Ok(_) => Ok(()),
        Err(_) => Err(unavailable()),
    }
}

// ---------------------------------------------------------------------------
// As a handler of the plane
// ---------------------------------------------------------------------------

/// The plane's tenant create over `ports`, with its random source.
pub struct TenantCreateHandler<'r, 'a, P: RootPorts, R, U, I, F, G> {
    pub ports: CreatePorts<'r, 'a, P, R, U, I, F>,
    pub rng: RefCell<Option<G>>,
}

impl<P, R, U, I, F, G> crate::mgmt::serve::Handlers
    for TenantCreateHandler<'_, '_, P, R, U, I, F, G>
where
    P: RootPorts,
    R: FillRandom,
    U: UnitRouter,
    I: ControlIntents,
    F: TenantStores,
    G: FillRandom,
{
    fn serves(&self, call: &crate::mgmt::route::Call) -> bool {
        matches!(call, crate::mgmt::route::Call::TenantCreate)
    }

    async fn handle(&self, ctx: crate::mgmt::serve::CallContext<'_>, body: &[u8]) -> Answer {
        if !matches!(ctx.admitted.call, crate::mgmt::route::Call::TenantCreate) {
            return crate::mgmt::serve::not_built();
        }
        let Some(mut rng) = self.rng.borrow_mut().take() else {
            return Answer::code(Code::ServiceUnavailable, None);
        };
        let key = ctx.checked.idempotency_key.as_deref();
        let answer = create_tenant(&self.ports, body, key, &mut rng).await;
        *self.rng.borrow_mut() = Some(rng);
        answer
    }
}
