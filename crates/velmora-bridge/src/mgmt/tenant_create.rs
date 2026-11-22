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
//! **Answers.** `201` with the tenant when this call wrote `m/tref/` or
//! took the tenant on from `provisioning`; `200` with it when the
//! reference names a tenant that is already `live` (or being deleted);
//! `409 external_ref_retired` when it names a shredding or shredded
//! tenant; `400 jurisdiction_not_served` for any jurisdiction but `none`
//! (absent means `none`, AM-58); `503` for every store that cannot be
//! reached, for missing key locations, and while another create holds a
//! step this one cannot take over. While the head is `provisioning`, an
//! unborn root unit is expected: nothing pages (AM-58).
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
use crate::directory::record::{Lifecycle, Tenant, TenantDoor as Door};
use crate::directory::seal::committed_check;
use crate::directory::transition::{Actor, Change};
use crate::keys::locations::read_locations;
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
/// The jurisdiction a tenant record names for `none` (a record's
/// jurisdiction is a non-empty label); the unit's namespace, and so the
/// birth token, says `""`.
pub const RECORD_JURISDICTION_NONE: &str = "none";
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
    let opened = parse_control(&bytes)?.open_door(kek, &name, ControlOwner::Global)?;
    let body: TrefRecord = serde_json::from_slice(opened.door()).map_err(|_| ERR_TREF)?;
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
pub fn birth_token(tenant: &crate::unit::TenantId) -> BirthToken {
    BirthToken {
        name: UnitName::new(tenant.clone(), ROOT),
        // `none`: no Durable Object jurisdiction; the unit's namespace
        // reports "" (AM-58).
        jurisdiction: String::new(),
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
    let opened = parse_control(&bytes)?.open_door(kek, &name, ControlOwner::Global)?;
    let body: BornRecord = serde_json::from_slice(opened.door()).map_err(|_| ERR_BORN)?;
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
/// written by tenant creation. A commit loads the key it commits first
/// (the record after it is sealed under it).
pub struct ChainClaims<'r, 'a, P: RootPorts, R> {
    pub root: &'r Root<'a, P, R>,
    pub now: UnixMs,
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

impl<P: RootPorts, R: FillRandom> ChainClaims<'_, '_, P, R> {
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
        self.root
            .chain()
            .write(&managed(t), &change, Actor::TenantCreation, self.now, 0)
            .await
            .map(|_| ())
    }
}

impl<P: RootPorts, R: FillRandom> KeyVersionClaims for ChainClaims<'_, '_, P, R> {
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
// The call
// ---------------------------------------------------------------------------

/// The stores of a tenant create.
pub struct CreatePorts<'r, 'a, P: RootPorts, R, U> {
    pub ports: &'a P,
    pub root: &'r Root<'a, P, R>,
    /// The router's root-unit calls (`provision`, and a probe of an
    /// unborn unit).
    pub unit: &'r RoutedUnit<'r, U>,
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

/// Runs a tenant create. `rng` draws the tenant id and seals the
/// control records; it is taken for the call.
pub async fn create_tenant<P, R, U, G>(
    ports: &CreatePorts<'_, '_, P, R, U>,
    body: &[u8],
    rng: &mut G,
) -> Answer
where
    P: RootPorts,
    R: FillRandom,
    U: UnitRouter,
    G: FillRandom,
{
    match run(ports, body, rng).await {
        Ok(answer) | Err(Stop::Answer(answer)) => answer,
    }
}

async fn run<P, R, U, G>(
    ports: &CreatePorts<'_, '_, P, R, U>,
    body: &[u8],
    rng: &mut G,
) -> std::result::Result<Answer, Stop>
where
    P: RootPorts,
    R: FillRandom,
    U: UnitRouter,
    G: FillRandom,
{
    let body: TenantCreate =
        parse_request(body).map_err(|c| Stop::Answer(Answer::code(c, None)))?;
    if body
        .jurisdiction
        .as_deref()
        .is_some_and(|j| j != JURISDICTION_NONE)
    {
        return Err(Stop::Answer(Answer::code(
            Code::JurisdictionNotServed,
            None,
        )));
    }
    let root = ports.root;
    let records = root.records();
    let kek = root.kek();
    let now = root.clock().now();

    // 1. m/tref/: create-or-adopt.
    let tenant = match read_tref(records, kek, &body.external_ref).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            let mut id = [0u8; ID_BYTES];
            rng.fill_bytes(&mut id).map_err(|_| unavailable())?;
            let text = format!("t_{}", hex(&id));
            // A managed id, checked before it is put: an all-zero draw is
            // tenant 0 and is never named (the retry draws again).
            crate::TenantId::parse(&text).map_err(|_| unavailable())?;
            let drawn = crate::unit::TenantId::parse(&text).ok_or_else(internal)?;
            match put_tref(records, kek, &body.external_ref, &drawn, rng).await {
                Ok(true) => drawn,
                Ok(false) => match read_tref(records, kek, &body.external_ref).await {
                    Ok(Some(t)) => t,
                    _ => return Err(unavailable()),
                },
                Err(_) => return Err(unavailable()),
            }
        }
        Err(_) => return Err(unavailable()),
    };
    let chain_tenant = crate::TenantId::parse(tenant.as_str()).map_err(|_| unavailable())?;
    let t = Tenant::Managed(chain_tenant.clone());

    // An adopted tenant that is already past provisioning is answered as
    // it is.
    let first = head(root, &t).await?;
    if let Some(door) = &first {
        match door.lifecycle {
            Lifecycle::Shredding | Lifecycle::Shredded => {
                return Ok(Answer::code(Code::ExternalRefRetired, None))
            }
            Lifecycle::Live => return answer(tenant.as_str(), door, 200),
            Lifecycle::Provisioning => {}
        }
    }

    // 2. Record 1.
    if first.is_none() {
        let limits = body
            .limits
            .as_ref()
            .map(|l| {
                let mut m = std::collections::BTreeMap::new();
                let mut put = |k: &str, v: Option<u64>| {
                    if let Some(v) = v {
                        m.insert(k.to_string(), v);
                    }
                };
                put(crate::mgmt::tenant::LIMIT_STORAGE, l.storage_bytes);
                put(crate::mgmt::tenant::LIMIT_UPLOAD_24H, l.upload_24h_bytes);
                put(
                    crate::mgmt::tenant::LIMIT_DOWNLOAD,
                    l.download_allowance_bytes,
                );
                put(
                    crate::mgmt::tenant::LIMIT_ACTIVE_KEYS,
                    Some(u64::from(l.active_keys)),
                );
                m
            })
            .unwrap_or_default();
        let mut rate_json = serde_json::Map::new();
        if let Some(class) = &body.rate_class {
            rate_json.insert("class".into(), serde_json::Value::String(class.clone()));
        }
        let create = Change::Create {
            jurisdiction: RECORD_JURISDICTION_NONE.to_string(),
            location_hint: Some(LOCATION_HINT.to_string()),
            synthetic: false,
            limits,
            rate_json,
            features_json: serde_json::Map::new(),
        };
        match root
            .chain()
            .write(&t, &create, Actor::TenantCreation, now, 0)
            .await
        {
            Ok(_) => {}
            // Another create wrote record 1 first: go on from its head.
            Err(ChainError::Refused(_) | ChainError::Busy) => {}
            Err(_) => return Err(unavailable()),
        }
    }

    // 3. The root unit's birth, then its marker.
    birth(ports, &tenant, &t, rng).await?;

    // 4. Tenant key version 1.
    let door = head(root, &t).await?.ok_or_else(unavailable)?;
    if door.lifecycle != Lifecycle::Provisioning {
        return finish(root, &tenant, &t).await;
    }
    if door.tk_version == 0 || door.rotating_to.is_some() {
        let locations = match read_locations(records, kek, 0).await {
            Ok(Some(l)) => l,
            // Fail closed: no key is made without its recorded locations
            // (`m/kl/`, written by the deploy step that makes the key
            // buckets).
            Ok(None) => return Err(unavailable()),
            Err(_) => return Err(unavailable()),
        };
        let claims = ChainClaims { root, now };
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
            return Err(unavailable());
        }
    }

    // 5. Live.
    let door = head(root, &t).await?.ok_or_else(unavailable)?;
    if door.lifecycle == Lifecycle::Provisioning {
        let kcv = committed_check(&door, door.tk_version).ok_or_else(unavailable)?;
        root.load_key(&chain_tenant, door.tk_version, kcv)
            .await
            .map_err(|_| unavailable())?;
        let activate = Change::Activate {
            external_ref: Some(body.external_ref.clone()),
        };
        match root
            .chain()
            .write(&t, &activate, Actor::TenantCreation, now, 0)
            .await
        {
            Ok(Written::Wrote(_) | Written::Unchanged(_)) => {}
            Err(ChainError::Refused(_) | ChainError::Busy) => {}
            Err(_) => return Err(unavailable()),
        }
    }
    finish(root, &tenant, &t).await
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
        .map_err(|_| unavailable())
}

/// The head after the last step: `201` with the tenant once it is
/// `live`; `503` while another create still holds a step.
async fn finish<P: RootPorts, R: FillRandom>(
    root: &Root<'_, P, R>,
    tenant: &crate::unit::TenantId,
    t: &Tenant,
) -> std::result::Result<Answer, Stop> {
    let door = root
        .heads()
        .head(t, 0)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?
        .door;
    match door.lifecycle {
        Lifecycle::Live => answer(tenant.as_str(), &door, 201),
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
/// with a birth token any more: `503` (an operator's case; it pages
/// through the log line).
async fn birth<P, R, U, G>(
    ports: &CreatePorts<'_, '_, P, R, U>,
    tenant: &crate::unit::TenantId,
    t: &Tenant,
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
        Err(_) => return Err(unavailable()),
    }
    let door = root
        .heads()
        .head(t, 0)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?
        .door;
    let token = birth_token(tenant);
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
            Err(_) => false,
        }
    };
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
pub struct TenantCreateHandler<'r, 'a, P: RootPorts, R, U, G> {
    pub ports: CreatePorts<'r, 'a, P, R, U>,
    pub rng: RefCell<Option<G>>,
}

impl<P, R, U, G> crate::mgmt::serve::Handlers for TenantCreateHandler<'_, '_, P, R, U, G>
where
    P: RootPorts,
    R: FillRandom,
    U: UnitRouter,
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
        let answer = create_tenant(&self.ports, body, &mut rng).await;
        *self.rng.borrow_mut() = Some(rng);
        answer
    }
}
