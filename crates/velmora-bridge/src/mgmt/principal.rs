//! `POST /v1/tenants/{t}/principals`: create, or find, the principal of
//! an `owner_ref` (`Tenancy::create_principal`; ADR §2.5, §6.2, §6.4;
//! AM-35, AM-36, AM-38).
//!
//! A principal create is a capped opening change, so it runs the opening
//! order of §2.5: the reservation in the root unit, then the intent, the
//! key-chain record and the stores, then the answer. This module holds the
//! call's own part: the body, the acting rule of AM-36, the reservation
//! ask and what its answer means, and the answer. The rest is behind
//! three ports, one per store the call reads or writes:
//!
//! - [`TenantDoor`]: the tenant as its verified head says (exists, state,
//!   the names of its placed buckets). L3's directory reader, through L6's
//!   router.
//! - [`RootUnit`]: the reservation calls of the tenant's root unit
//!   ([`UnitOp::Reserve`], [`UnitOp::Release`]). L6's `UnitRouter` and
//!   L2's unit client; [`reserve_answer`] reads the unit's answer.
//! - [`PrincipalChain`]: the key chain: the intent, the record that carries
//!   the reservation's `rid` at exactly `keys_seq + 1`, and the stores in
//!   the opening order, with the answer the root unit keeps (L4's writer).
//!
//! **The call, step by step.**
//!
//! 1. The body is `{owner_ref, grants}` ([`PrincipalCreate`]): unknown
//!    fields, a bad form or more than 64 grants answer `400`/`409`, a
//!    prefix, an expiry or an address list `400 grant_limits_not_served`.
//!    A grant list that is not empty needs `Kofra-Acting-Owner-Ref`
//!    (`400 bad_request` without it): only sign-up, with no member yet,
//!    creates without one, and then the list is empty.
//! 2. The tenant: none, `404 tenant_not_found`; `restoring`,
//!    `409 tenant_restoring`; `provisioning`, `503`.
//! 3. The ask: the key hash and the fingerprint of the request, a fresh
//!    random `rid`, the acting header, and the principal with a fresh id.
//!    What the unit answers:
//!    - `admitted`: go on with the `rid`, the subject and the `keys_seq`
//!      of the answer (a re-ask keeps the first ones). Asked again
//!      (`again`), the call first reads the record at `keys_seq + 1`: a
//!      record there that carries the `rid` is being applied, so
//!      `409 idempotency_key_in_use` with `Retry-After: 30`.
//!    - `applied`: the unit holds the record, perhaps closed (AM-9: the
//!      directory has not acknowledged it). The stores are brought to the
//!      head first ([`PrincipalChain::finish`], DUR-7), and only once every
//!      door store holds the principal open is the answer sent: the one
//!      the unit kept (cleaned of any secret), or, if the record was
//!      applied with none (by the finisher), the principal as the chain
//!      holds it, `201`. Before that, `503`.
//!    - `exists`: a principal that is not revoked holds the `owner_ref`:
//!      `200` with it when its grants equal the request's as a set (a
//!      held one only once the stores hold it open, as above),
//!      `409 principal_exists` otherwise. Nothing is kept.
//!    - `reused`: `422 idempotency_key_reused`.
//!    - a held, deleting or shredded tenant: `409 tenant_read_only` or
//!      `tenant_unavailable` from the tenant's state read again, or
//!      `409 idempotency_key_in_use` when the unit found the call's own
//!      reservation and a record of it exists.
//!    - a refusal: its contract code ([`refusal`]); `rid_taken` draws a
//!      new `rid` and asks again.
//!
//!    Once admitted, every grant must name a bucket the head places
//!    (`404 bucket_not_found` otherwise), so no grant names a bucket id
//!    that is not one yet (a derived id is predictable). The check comes
//!    after the ask, so a bucket deleted since never hides a kept answer.
//!    A refusal after the ask gives the reservation back only when this
//!    call made it and no record carries its `rid`.
//! 4. The record, through [`PrincipalChain::create`], with the answer the
//!    root unit keeps: `201` with the principal once every door store
//!    acknowledged; `503` when the record is written and a store is not
//!    (the finishers complete it; a retry answers `409` until then, and
//!    the kept answer after). A put lost to another record asks again, at
//!    most [`MAX_ASKS`] times, then `503`.
//!
//! **Answers carry nothing of a store's own text**, and every port error
//! answers `503 service_unavailable` with `Retry-After`. A principal has
//! no secret; the kept answer is still made by
//! [`crate::mgmt::idem::stored_answer`], which nulls any.

use std::cell::RefCell;
use std::collections::BTreeSet;

use velmora::rng::FillRandom;
use velmora_mgmt_types::wire::{
    Access as WireAccess, Grant, GrantIn, Principal, PrincipalCreate, PrincipalStatus,
};
use velmora_mgmt_types::{parse_request, Code};

use crate::mgmt::idem::{self, IdemRequest, Next, Reply, Reservation};
use crate::mgmt::request::Checked;
use crate::mgmt::serve::Answer;
use crate::mgmt::token::TokenClass;
use crate::types::{Result, UnixMs};
use crate::unit::call::Refused;
use crate::unit::keys::{Access, KeptAnswer, KeyGrant, SubjectStatus};
use crate::unit::reserve::{Acting, Hash32, Opening, PrincipalView, ReserveRefusal, Rid};
use crate::unit::{TenantId, UnitAnswer, UnitOp};

/// Asks one call makes before it answers `503`: a put lost to another
/// record, or a `rid` that is another reservation's, asks again (ADR §2.5
/// step 0: "after 3 lost puts (est)").
pub const MAX_ASKS: u32 = 3;

/// `Retry-After` of `429 cap_reached`, in seconds (est): the caps of
/// ADR §6.3 count per hour or per day, and a minute lets a client's
/// retry see a slot that a sweep or an hour's end freed.
pub const CAP_RETRY_AFTER_SECS: u32 = 60;

/// `Retry-After` of every other "not now" of this call: a store that
/// cannot be reached, a lost race.
pub const RETRY_AFTER_SECS: u32 = crate::mgmt::gate::RETRY_AFTER_SECS;

/// The bytes of a principal id after its `p_` prefix, as hex.
const ID_BYTES: usize = 8;

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// The tenant's state as a management write reads it from the head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoorState {
    /// `active`: every write.
    Open,
    /// `suspended` with `read_only`: no opening write.
    ReadOnly,
    /// `blocked`, `deleting`, `shredding`, `shredded`: no opening write.
    Unavailable,
    /// A `restoring` entry is set: `409 tenant_restoring`.
    Restoring,
    /// Not yet `active`: a create in flight, `503`.
    Provisioning,
}

/// The tenant as its verified head says. L3's directory reader, through
/// L6's router (§R5-4).
#[allow(async_fn_in_trait)]
pub trait TenantDoor {
    /// The tenant's state; `None` when the tenant does not exist.
    async fn state(&self, tenant: &TenantId) -> Result<Option<DoorState>>;
    /// The name of each bucket id the head places, in the order asked;
    /// `None` for an id it does not place.
    async fn bucket_names(&self, tenant: &TenantId, ids: &[String]) -> Result<Vec<Option<String>>>;
}

/// What the root unit answered a reservation ask ([`reserve_answer`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReserveAnswer {
    /// Go on: the record must be exactly `keys_seq + 1` and carry `rid`.
    /// `again`: the ask found its own `reserved` row. `scope`: the acting
    /// principal's id. `subject`: the principal the reservation holds.
    Admitted {
        rid: Rid,
        keys_seq: u64,
        again: bool,
        scope: Option<String>,
        subject: Option<String>,
    },
    /// The reservation's record was applied: the answer kept, if any,
    /// and the principal it made.
    Applied {
        status: Option<u16>,
        body: Option<String>,
        subject: Option<String>,
    },
    /// The key with another request.
    Reused,
    /// A principal that is not revoked holds the `owner_ref`.
    Exists(PrincipalView),
    /// The tenant's state refuses opening asks; the ask found its own
    /// `reserved` row (`rid`, the unit's `keys_seq`).
    NotOpen {
        rid: Rid,
        keys_seq: u64,
    },
    /// The tenant's state refuses opening asks; nothing of this call is
    /// kept.
    AccountProblem,
    Refused(ReserveRefusal),
    /// Not this call's to judge: the unit is closed, unborn, behind, or
    /// answered what a reservation never answers. `503`.
    Unavailable,
}

/// The root unit's reservation calls. L6's `UnitRouter` with L2's unit
/// client (§R5-4): the adapter runs rule 5's refresh for a unit that is
/// behind and answers what [`reserve_answer`] reads.
#[allow(async_fn_in_trait)]
pub trait RootUnit {
    /// [`UnitOp::Reserve`] at the tenant's root unit.
    async fn reserve(&self, tenant: &TenantId, op: &UnitOp) -> Result<ReserveAnswer>;
    /// [`UnitOp::Release`] of `rid`: best effort, a reservation that is
    /// not released is swept after 1 hour.
    async fn release(&self, tenant: &TenantId, rid: &Rid) -> Result<()>;
}

/// A principal as a key-chain record states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedPrincipal {
    pub id: String,
    pub owner_ref: String,
    pub status: SubjectStatus,
    pub grants: Vec<KeyGrant>,
}

/// The principal record a create writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewPrincipal {
    pub id: String,
    pub owner_ref: String,
    pub grants: Vec<KeyGrant>,
    /// The acting principal's id (`made_by`); `None` at sign-up.
    pub made_by: Option<String>,
    /// The reservation's `rid`, in the record's door part.
    pub rid: Rid,
    /// Exactly the reservation's `keys_seq + 1`.
    pub seq: u64,
    pub created_at: UnixMs,
}

/// What the key chain did with a create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainWrite {
    /// The record that carries the `rid` is at `seq` (this call's, or one
    /// of another call under the same reservation, whose bytes win), and
    /// every door store acknowledged it.
    Done(RecordedPrincipal),
    /// The record that carries the `rid` is written; a door store did not
    /// acknowledge. The finishers apply it.
    Unfinished,
    /// Another record took `seq`, and none carries the `rid`: nothing of
    /// this call is recorded. Ask again.
    Lost,
    /// Nothing recorded, and the chain cannot record now.
    Busy,
    /// Refused by the chain's own rules before any record.
    Refused(Code),
}

/// The tenant's key chain: L4's record-first writer, with the
/// reservation's `rid` in the record's door part (AM-38).
#[allow(async_fn_in_trait)]
pub trait PrincipalChain {
    /// The record at `above + 1`, if it carries `rid`, read from the
    /// chain's head now (one read, AM-55: a record of a reservation can
    /// only sit at its `keys_seq + 1`).
    async fn carrying(
        &self,
        tenant: &TenantId,
        rid: &Rid,
        above: u64,
    ) -> Result<Option<RecordedPrincipal>>;
    /// The idempotent path of a principal the head already holds (§2.5,
    /// DUR-7): brings every store to the head, the subject open only once
    /// the directory acknowledged it, and waits for each. [`ChainWrite::Done`]
    /// with the principal as the head holds it only when every door store
    /// holds it open; [`ChainWrite::Unfinished`] while any store does not
    /// (the directory down: the units hold it closed, AM-9). A subject the
    /// head does not hold is [`ChainWrite::Busy`]. Writes no record of a
    /// create.
    async fn finish(&self, tenant: &TenantId, id: &str) -> Result<ChainWrite>;
    /// The opening order of §2.5 from step 1: the intent, the record at
    /// exactly `principal.seq` (a put that loses to a record carrying the
    /// same `rid` reads that record and never writes its own bytes), then
    /// the stores. `answer` is kept by the root unit's **full** apply, the
    /// one after the directory acknowledged, never by the apply that holds
    /// the subject closed: a unit whose reservation is `applied` with an
    /// answer then holds the principal open. [`ChainWrite::Done`] only once
    /// every door store holds the principal open.
    async fn create(
        &self,
        tenant: &TenantId,
        principal: &NewPrincipal,
        answer: &KeptAnswer,
    ) -> Result<ChainWrite>;
}

/// The ports of the call, and the source of its random ids.
pub struct PrincipalPorts<'a, D, U, K, R> {
    pub door: &'a D,
    pub unit: &'a U,
    pub chain: &'a K,
    pub rng: &'a RefCell<R>,
}

/// What the call takes from the request.
#[derive(Clone, Copy, Debug)]
pub struct PrincipalCall<'a> {
    /// The tenant id of the path.
    pub tenant: &'a str,
    pub class: TokenClass,
    pub method: &'a str,
    /// The path and its query, as received (for the fingerprint).
    pub path_and_query: &'a str,
    pub checked: &'a Checked,
    pub body: &'a [u8],
    pub now: UnixMs,
}

// ---------------------------------------------------------------------------
// The unit's answer
// ---------------------------------------------------------------------------

/// Reads the root unit's answer to [`UnitOp::Reserve`]. Anything that is
/// not a reservation's answer is [`ReserveAnswer::Unavailable`].
pub fn reserve_answer(answer: &UnitAnswer) -> ReserveAnswer {
    use serde_json::Value;
    match answer {
        UnitAnswer::Ok { body, .. } => {
            let Some((name, v)) = body.as_object().and_then(|m| {
                (m.len() == 1)
                    .then(|| m.iter().next())
                    .flatten()
                    .map(|(k, v)| (k.as_str(), v))
            }) else {
                return ReserveAnswer::Unavailable;
            };
            let rid = |v: &Value| serde_json::from_value::<Rid>(v.get("rid")?.clone()).ok();
            let u64_of = |v: &Value, f: &str| v.get(f).and_then(Value::as_u64);
            let opt_str = |v: &Value, f: &str| -> Option<Option<String>> {
                match v.get(f) {
                    None | Some(Value::Null) => Some(None),
                    Some(Value::String(s)) => Some(Some(s.clone())),
                    Some(_) => None,
                }
            };
            let read = || -> Option<ReserveAnswer> {
                Some(match name {
                    "admitted" => ReserveAnswer::Admitted {
                        rid: rid(v)?,
                        keys_seq: u64_of(v, "keys_seq")?,
                        again: v.get("again")?.as_bool()?,
                        scope: opt_str(v, "scope")?,
                        subject: opt_str(v, "subject")?,
                    },
                    "applied" => ReserveAnswer::Applied {
                        status: match v.get("status") {
                            None | Some(Value::Null) => None,
                            Some(s) => Some(u16::try_from(s.as_u64()?).ok()?),
                        },
                        body: opt_str(v, "body")?,
                        subject: opt_str(v, "subject")?,
                    },
                    "reused" if v.as_bool() == Some(true) => ReserveAnswer::Reused,
                    "exists" => ReserveAnswer::Exists(serde_json::from_value(v.clone()).ok()?),
                    "not_open" => ReserveAnswer::NotOpen {
                        rid: rid(v)?,
                        keys_seq: u64_of(v, "keys_seq")?,
                    },
                    // `narrowing` is a grant change's, never a create's.
                    _ => return None,
                })
            };
            read().unwrap_or(ReserveAnswer::Unavailable)
        }
        UnitAnswer::Refused {
            reason: Refused::Reserve(r),
            ..
        } => ReserveAnswer::Refused(*r),
        UnitAnswer::Refused {
            reason: Refused::AccountProblem,
            ..
        } => ReserveAnswer::AccountProblem,
        _ => ReserveAnswer::Unavailable,
    }
}

/// The contract code of a refusal of the unit, with its `Retry-After`.
/// `None`: the refusal is not the request's (a fault of this Worker or a
/// unit rule that fails closed): `500 internal_error`.
pub fn refusal(r: ReserveRefusal) -> Option<(Code, Option<u32>)> {
    use ReserveRefusal::*;
    Some(match r {
        CapReached => (Code::CapReached, Some(CAP_RETRY_AFTER_SECS)),
        GrantNotHeld => (Code::GrantNotHeld, None),
        GrantLimitsNotServed => (Code::GrantLimitsNotServed, None),
        TooManyGrants => (Code::GrantLimitReached, None),
        ActingPrincipalUnknown => (Code::ActingPrincipalUnknown, None),
        ActingPrincipalInactive => (Code::ActingPrincipalInactive, None),
        ActingPrincipalHeld => (Code::ServiceUnavailable, Some(RETRY_AFTER_SECS)),
        // Another create holds the `owner_ref` and has no principal yet
        // (a principal that exists answers `exists`): not final, a retry
        // lands in `exists` once it is recorded, or in a reservation of
        // its own once that one is released.
        PrincipalExists => (Code::ServiceUnavailable, Some(RETRY_AFTER_SECS)),
        InternalKeyRefused => (Code::InternalKeyRefused, None),
        // A grant on a bucket id the unit holds no row for (AM-61).
        BucketNotFound => (Code::BucketNotFound, None),
        // Two principals for one `owner_ref` (the unit alarms), an id
        // that exists, a bucket's or a grant change's refusal, an ask
        // this Worker built wrong: never the request's.
        OwnerRefAmbiguous | Conflict | BucketAlreadyExists | NotFound | Malformed => return None,
        // Handled by the caller (a new `rid`).
        RidTaken => return None,
    })
}

// ---------------------------------------------------------------------------
// The call
// ---------------------------------------------------------------------------

fn code(code: Code, retry_after: Option<u32>) -> Answer {
    Answer::code(code, retry_after)
}

fn unavailable() -> Answer {
    code(Code::ServiceUnavailable, Some(RETRY_AFTER_SECS))
}

fn internal() -> Answer {
    code(Code::InternalError, None)
}

/// A read of the tenant's head that failed: `500` (pages) for a head that
/// does not verify, `503` for one that cannot be read now.
fn door_error(e: &crate::types::BridgeError) -> Answer {
    match crate::mgmt::adapters::head_damaged(e) {
        true => internal(),
        false => unavailable(),
    }
}

fn draw<const N: usize, R: FillRandom>(rng: &RefCell<R>) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    rng.borrow_mut().fill_bytes(&mut out).ok()?;
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unit_access(a: WireAccess) -> Access {
    match a {
        WireAccess::Ro => Access::Ro,
        WireAccess::Rw => Access::Rw,
    }
}

fn wire_access(a: Access) -> WireAccess {
    match a {
        Access::Ro => WireAccess::Ro,
        Access::Rw => WireAccess::Rw,
    }
}

fn wire_status(s: SubjectStatus) -> PrincipalStatus {
    match s {
        SubjectStatus::Active => PrincipalStatus::Active,
        SubjectStatus::Disabled => PrincipalStatus::Disabled,
        SubjectStatus::Revoked => PrincipalStatus::Revoked,
    }
}

fn unit_grant(g: &GrantIn) -> KeyGrant {
    KeyGrant {
        bucket_id: g.bucket_id.clone(),
        access: unit_access(g.access),
        expires_at: None,
        prefix: None,
        ip_list: Vec::new(),
    }
}

/// A grant with no limit, as a set member.
fn plain(g: &KeyGrant) -> Option<(String, Access)> {
    (g.prefix.is_none() && g.expires_at.is_none() && g.ip_list.is_empty())
        .then(|| (g.bucket_id.clone(), g.access))
}

/// Whether `held` and `asked` are the same grants as sets. A held grant
/// with a limit is never equal to an asked one (which has none).
fn same_grants(held: &[KeyGrant], asked: &[KeyGrant]) -> bool {
    let held: Option<BTreeSet<_>> = held.iter().map(plain).collect();
    let asked: Option<BTreeSet<_>> = asked.iter().map(plain).collect();
    matches!((held, asked), (Some(h), Some(a)) if h == a)
}

/// The answer's principal: grants named by the head (`null` for a bucket
/// that is gone).
async fn principal_json<D: TenantDoor>(
    door: &D,
    tenant: &TenantId,
    id: &str,
    owner_ref: &str,
    status: SubjectStatus,
    grants: &[KeyGrant],
) -> Result<Vec<u8>> {
    let ids: Vec<String> = grants.iter().map(|g| g.bucket_id.clone()).collect();
    let names = if ids.is_empty() {
        Vec::new()
    } else {
        door.bucket_names(tenant, &ids).await?
    };
    let grants = grants
        .iter()
        .enumerate()
        .map(|(i, g)| Grant {
            bucket_id: g.bucket_id.clone(),
            bucket_name: names.get(i).cloned().flatten(),
            access: wire_access(g.access),
        })
        .collect();
    let p = Principal {
        id: id.to_string(),
        owner_ref: owner_ref.to_string(),
        status: wire_status(status),
        grants,
    };
    serde_json::to_vec(&p).map_err(|_| crate::types::BridgeError::Sql("principal answer".into()))
}

fn stored(status: u16, body: Vec<u8>) -> Answer {
    Answer::json(status, body)
}

/// The answer when the unit refuses an opening ask for the tenant's state:
/// the state read again now (the unit's refusal may follow a change the
/// first read did not see). A head that still says the tenant is open
/// cannot explain the refusal: `503`.
async fn state_answer<D: TenantDoor>(door: &D, tenant: &TenantId) -> Answer {
    match door.state(tenant).await {
        Ok(Some(DoorState::ReadOnly)) => code(Code::TenantReadOnly, None),
        Ok(Some(DoorState::Unavailable)) => code(Code::TenantUnavailable, None),
        Ok(Some(DoorState::Restoring)) => code(Code::TenantRestoring, Some(RETRY_AFTER_SECS)),
        Ok(None) => code(Code::TenantNotFound, None),
        Err(e) if crate::mgmt::adapters::head_damaged(&e) => internal(),
        Ok(Some(DoorState::Open | DoorState::Provisioning)) | Err(_) => unavailable(),
    }
}

/// Whether every grant names a bucket the head places.
async fn placed<D: TenantDoor>(door: &D, tenant: &TenantId, grants: &[KeyGrant]) -> Result<bool> {
    if grants.is_empty() {
        return Ok(true);
    }
    let ids: Vec<String> = grants.iter().map(|g| g.bucket_id.clone()).collect();
    let names = door.bucket_names(tenant, &ids).await?;
    if names.len() != ids.len() {
        return Err(crate::types::BridgeError::Sql(
            "bucket names: wrong count".into(),
        ));
    }
    Ok(names.iter().all(Option::is_some))
}

/// The idempotent path (DUR-7): `answer` only once every door store holds
/// the principal `subject` open; `503` before. `kept`: the answer the
/// unit kept, sent as kept (cleaned again); without one, the principal as
/// the head holds it, with `status`.
async fn finished<D: TenantDoor, K: PrincipalChain>(
    door: &D,
    chain: &K,
    tenant: &TenantId,
    subject: &str,
    kept: Option<(u16, Vec<u8>)>,
    status: u16,
    owner_ref: Option<&str>,
) -> Answer {
    let p = match chain.finish(tenant, subject).await {
        Ok(ChainWrite::Done(p)) => p,
        _ => return unavailable(),
    };
    if let Some((kept_status, body)) = kept {
        return reply(idem::next(Reservation::Applied {
            status: kept_status,
            body,
        }));
    }
    let owner_ref = owner_ref.unwrap_or(&p.owner_ref);
    match principal_json(door, tenant, &p.id, owner_ref, p.status, &p.grants).await {
        Ok(json) => stored(status, json),
        Err(e) => door_error(&e),
    }
}

/// Gives the reservation back after a refusal that left no record, but
/// only when this call made it (`ours`: its first admit was not a re-ask)
/// and no record carries its `rid`: a reservation another call made may
/// be writing its record. Best effort: the unit's sweep releases it after
/// 1 hour anyway.
async fn give_back<U: RootUnit, K: PrincipalChain>(
    unit: &U,
    chain: &K,
    tenant: &TenantId,
    rid: &Rid,
    ours: bool,
    keys_seq: u64,
) {
    if !ours {
        return;
    }
    if let Ok(None) = chain.carrying(tenant, rid, keys_seq).await {
        let _ = unit.release(tenant, rid).await;
    }
}

/// Runs a principal create. Every answer is final for this request; the
/// caller sends it as it is.
pub async fn create_principal<D, U, K, R>(
    ports: &PrincipalPorts<'_, D, U, K, R>,
    call: PrincipalCall<'_>,
) -> Answer
where
    D: TenantDoor,
    U: RootUnit,
    K: PrincipalChain,
    R: FillRandom,
{
    // 1. The body and the acting rule (AM-36).
    let body: PrincipalCreate = match parse_request(call.body) {
        Ok(body) => body,
        Err(c) => return code(c, None),
    };
    let acting = call.checked.acting.as_deref();
    if !body.grants.is_empty() && acting.is_none() {
        return code(Code::BadRequest, None);
    }
    let Some(key) = call.checked.idempotency_key.as_deref() else {
        // The request checks refuse a write without one before here.
        return code(Code::IdempotencyKeyRequired, None);
    };
    let Some(tenant) = TenantId::parse(call.tenant) else {
        return code(Code::TenantNotFound, None);
    };

    // 2. The tenant. The buckets of the grants are checked once the unit
    //    has said this is no retry of a create it kept (a bucket deleted
    //    since never hides a kept answer).
    match ports.door.state(&tenant).await {
        Ok(Some(DoorState::Restoring)) => {
            return code(Code::TenantRestoring, Some(RETRY_AFTER_SECS))
        }
        Err(e) if crate::mgmt::adapters::head_damaged(&e) => return internal(),
        Ok(Some(DoorState::Provisioning)) | Err(_) => return unavailable(),
        Ok(None) => return code(Code::TenantNotFound, None),
        Ok(Some(DoorState::Open | DoorState::ReadOnly | DoorState::Unavailable)) => {}
    }
    let grants: Vec<KeyGrant> = body.grants.iter().map(unit_grant).collect();

    // 3. The ask.
    let idem = IdemRequest::new(
        call.class.into(),
        call.method,
        call.path_and_query,
        acting,
        call.body,
        key,
    );
    let Some(id_bytes) = draw::<ID_BYTES, R>(ports.rng) else {
        return unavailable();
    };
    let drawn_id = format!("p_{}", hex(&id_bytes));
    let mut asks = 0;
    // The reservation this call made (an admit that was no re-ask): a
    // re-ask after a lost put answers `again` for it, and it is still
    // this call's to give back.
    let mut made: Option<Rid> = None;
    while asks < MAX_ASKS {
        asks += 1;
        let Some(rid) = draw::<16, R>(ports.rng).map(Rid) else {
            return unavailable();
        };
        let op = UnitOp::Reserve {
            key_hash: Hash32(idem.key_hash),
            fingerprint: Hash32(idem.fingerprint),
            rid,
            acting: acting.map(|a| Acting::OwnerRef(a.to_string())),
            opening: Opening::Principal {
                id: drawn_id.clone(),
                owner_ref: body.owner_ref.clone(),
                grants: grants.clone(),
            },
        };
        let answer = match ports.unit.reserve(&tenant, &op).await {
            Ok(answer) => answer,
            Err(_) => return unavailable(),
        };
        let (rid, keys_seq, ours, scope, subject) = match answer {
            ReserveAnswer::Admitted {
                rid,
                keys_seq,
                again,
                scope,
                subject,
            } => {
                if again {
                    match ports.chain.carrying(&tenant, &rid, keys_seq).await {
                        Ok(Some(_)) => return reply(idem::next(Reservation::InUse)),
                        Ok(None) => {}
                        Err(_) => return unavailable(),
                    }
                }
                let subject = subject.unwrap_or_else(|| drawn_id.clone());
                if !again {
                    made = Some(rid);
                }
                (rid, keys_seq, made == Some(rid), scope, subject)
            }
            // The unit holds the record, perhaps closed (the directory
            // not yet acknowledged it): the stores are brought up first.
            ReserveAnswer::Applied {
                status,
                body: kept,
                subject: Some(subject),
            } => {
                let kept = match (status, kept) {
                    (Some(status), Some(kept)) => Some((status, kept.into_bytes())),
                    (None, None) => None,
                    _ => return internal(),
                };
                return finished(ports.door, ports.chain, &tenant, &subject, kept, 201, None).await;
            }
            ReserveAnswer::Applied { .. } => return internal(),
            ReserveAnswer::Reused => return reply(idem::next(Reservation::Reused)),
            ReserveAnswer::Exists(found) => {
                if found.status == SubjectStatus::Revoked || !same_grants(&found.grants, &grants) {
                    return code(Code::PrincipalExists, None);
                }
                if found.held {
                    // Not yet acknowledged by the directory (AM-9): answered
                    // only once every door store holds it open.
                    return finished(
                        ports.door,
                        ports.chain,
                        &tenant,
                        &found.id,
                        None,
                        200,
                        Some(&body.owner_ref),
                    )
                    .await;
                }
                return match principal_json(
                    ports.door,
                    &tenant,
                    &found.id,
                    &body.owner_ref,
                    found.status,
                    &found.grants,
                )
                .await
                {
                    Ok(json) => stored(200, json),
                    Err(e) => door_error(&e),
                };
            }
            ReserveAnswer::NotOpen { rid, keys_seq } => {
                return match ports.chain.carrying(&tenant, &rid, keys_seq).await {
                    Ok(Some(_)) => reply(idem::next(Reservation::InUse)),
                    Ok(None) => state_answer(ports.door, &tenant).await,
                    Err(_) => unavailable(),
                };
            }
            ReserveAnswer::AccountProblem => return state_answer(ports.door, &tenant).await,
            ReserveAnswer::Refused(ReserveRefusal::RidTaken) => continue,
            ReserveAnswer::Refused(r) => {
                return match refusal(r) {
                    Some((c, retry_after)) => code(c, retry_after),
                    None => internal(),
                }
            }
            ReserveAnswer::Unavailable => return unavailable(),
        };

        // Every grant names a bucket the head places, so no grant names a
        // bucket id that is not one yet (a derived id is predictable).
        match placed(ports.door, &tenant, &grants).await {
            Ok(true) => {}
            Ok(false) => {
                give_back(ports.unit, ports.chain, &tenant, &rid, ours, keys_seq).await;
                return code(Code::BucketNotFound, None);
            }
            Err(e) if crate::mgmt::adapters::head_damaged(&e) => return internal(),
            Err(_) => return unavailable(),
        }

        // 4. The record and the stores, with the answer the unit keeps.
        let json = match principal_json(
            ports.door,
            &tenant,
            &subject,
            &body.owner_ref,
            SubjectStatus::Active,
            &grants,
        )
        .await
        {
            Ok(json) => json,
            Err(e) => return door_error(&e),
        };
        let Ok(kept) = idem::stored_answer(201, &json) else {
            return internal();
        };
        let Ok(kept) = String::from_utf8(kept) else {
            return internal();
        };
        let principal = NewPrincipal {
            id: subject.clone(),
            owner_ref: body.owner_ref.clone(),
            grants: grants.clone(),
            made_by: scope,
            rid,
            seq: keys_seq + 1,
            created_at: call.now,
        };
        let kept = KeptAnswer {
            rid,
            status: 201,
            body: kept,
        };
        match ports.chain.create(&tenant, &principal, &kept).await {
            Ok(ChainWrite::Done(p)) if p == recorded(&principal) => {
                return stored(201, kept.body.into_bytes())
            }
            Ok(ChainWrite::Done(p)) => {
                // Another call under the same reservation wrote it first:
                // answer from its record.
                return match principal_json(
                    ports.door,
                    &tenant,
                    &p.id,
                    &p.owner_ref,
                    p.status,
                    &p.grants,
                )
                .await
                {
                    Ok(json) => stored(201, json),
                    Err(e) => door_error(&e),
                };
            }
            Ok(ChainWrite::Unfinished) | Ok(ChainWrite::Busy) | Err(_) => return unavailable(),
            Ok(ChainWrite::Lost) => continue,
            Ok(ChainWrite::Refused(c)) => {
                give_back(ports.unit, ports.chain, &tenant, &rid, ours, keys_seq).await;
                return code(c, c.retry_after().then_some(RETRY_AFTER_SECS));
            }
        }
    }
    unavailable()
}

fn recorded(p: &NewPrincipal) -> RecordedPrincipal {
    RecordedPrincipal {
        id: p.id.clone(),
        owner_ref: p.owner_ref.clone(),
        status: SubjectStatus::Active,
        grants: p.grants.clone(),
    }
}

fn reply(next: Next) -> Answer {
    match next {
        Next::Reply(Reply::Stored { status, body }) => Answer::json(status, body),
        Next::Reply(Reply::Code {
            code: c,
            retry_after,
        }) => code(c, retry_after),
        // `next` proceeds only on `Admitted`, which is never passed here.
        Next::Proceed { .. } => internal(),
    }
}

// ---------------------------------------------------------------------------
// As a handler of the plane
// ---------------------------------------------------------------------------

/// The plane's handlers with principal create built over `ports`; every
/// other call waits for its store ([`crate::mgmt::serve::not_built`]).
pub struct PrincipalHandlers<'a, D, U, K, R> {
    pub ports: PrincipalPorts<'a, D, U, K, R>,
}

impl<D, U, K, R> crate::mgmt::serve::Handlers for PrincipalHandlers<'_, D, U, K, R>
where
    D: TenantDoor,
    U: RootUnit,
    K: PrincipalChain,
    R: FillRandom,
{
    fn serves(&self, call: &crate::mgmt::route::Call) -> bool {
        matches!(call, crate::mgmt::route::Call::PrincipalCreate { .. })
    }

    async fn handle(&self, ctx: crate::mgmt::serve::CallContext<'_>, body: &[u8]) -> Answer {
        let crate::mgmt::route::Call::PrincipalCreate { tenant } = &ctx.admitted.call else {
            return crate::mgmt::serve::not_built();
        };
        let path_and_query = ctx.path_and_query();
        let call = PrincipalCall {
            tenant,
            class: ctx.admitted.actor.class,
            method: ctx.method,
            path_and_query: &path_and_query,
            checked: ctx.checked,
            body,
            now: ctx.now,
        };
        create_principal(&self.ports, call).await
    }
}
