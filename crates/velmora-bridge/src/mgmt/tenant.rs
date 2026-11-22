//! `GET /v1/tenants/{t}`: the tenant as its verified head says
//! (`Tenancy::tenant`; §R4-2 `Tenant`; AM-59's carried door fields).
//!
//! A read: no reservation, no record, no unit call. Every field comes from
//! the head's door part, which L3 carries for this read (AM-59):
//!
//! - `state`: `active`, `suspended` (a hold), `deleting` (a deletion is
//!   set, or the shred is running). A `provisioning` head answers `503`
//!   (the create is in flight: its retry finishes it, AM-58); a
//!   `shredded` one `404 tenant_not_found` (nothing of it is served; a
//!   create with its `external_ref` answers `409 external_ref_retired`).
//! - `access`: what the tenant's keys may do now, from the state:
//!   `full`, `read_only` (a `read_only` hold), `none` (a `locked` hold, a
//!   deletion, the shred). A `restoring` entry changes no field: it is a
//!   `503` of the moment, not a state of the tenant.
//! - `limits`: the head's named limits; a size that is absent is `null`
//!   (no limit). `active_keys` is the head's, else the plane's cap of
//!   [`DEFAULT_ACTIVE_KEYS`] (ADR §6.3).
//! - `suspension`: the hold whose mode is in force, its `since` (the
//!   earlier one when both holds have that mode, `Holds::since`), and its
//!   reason: `operator` for the operator's hold, `non_payment` for the
//!   billing hold.
//! - `deletion`: `{seq, actor, requested_at_ms, shred_due_at_ms}` of the
//!   head's deletion (`seq` is the `deletion_seq` a restore names).
//! - `created_at_ms`: the `written_at` of seq 1.
//!
//! A time before 1970 on the head (never written by a correct writer) is
//! damage: `500`, never a made-up number.

use velmora_mgmt_types::wire::{
    Deletion as WireDeletion, DeletionActor, Limits, Suspension, SuspensionMode, SuspensionReason,
    Tenant, TenantAccess, TenantState as WireState,
};
use velmora_mgmt_types::Code;

use crate::directory::record::{ActorClass, HoldMode, TenantDoor as Door, TenantState};
use crate::mgmt::serve::Answer;
use crate::types::{Result, UnixMs};
use crate::unit::TenantId;

/// The plane's cap of active S3 keys per tenant when the head names no
/// `active_keys` limit (ADR §6.3, "Key caps": 20 active S3 keys).
pub const DEFAULT_ACTIVE_KEYS: u32 = 20;

/// The limit names of the head (`TenantDoor::limits`) that the answer
/// carries.
pub const LIMIT_STORAGE: &str = "storage_bytes";
pub const LIMIT_UPLOAD_24H: &str = "upload_24h_bytes";
pub const LIMIT_DOWNLOAD: &str = "download_allowance_bytes";
pub const LIMIT_ACTIVE_KEYS: &str = "active_keys";

/// The tenant's head, door part only. `None`: the tenant has no chain.
/// `Err`: the head could not be read or did not verify.
#[allow(async_fn_in_trait)]
pub trait TenantHeadRead {
    async fn door(&self, tenant: &TenantId) -> Result<Option<Door>>;
}

/// What the head says to a read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Tenant(Box<Tenant>),
    /// No chain, or `shredded`.
    NotFound,
    /// `provisioning`: `503`.
    NotYet,
    /// The head holds what no correct writer writes.
    Damaged,
}

fn ms(t: UnixMs) -> Option<u64> {
    u64::try_from(t.0).ok()
}

/// The tenant of the answer, from its head.
pub fn tenant_of(id: &str, door: &Door) -> Read {
    let (state, access) = match door.state() {
        TenantState::Provisioning => return Read::NotYet,
        TenantState::Shredded => return Read::NotFound,
        TenantState::Active => (WireState::Active, TenantAccess::Full),
        TenantState::Suspended(HoldMode::ReadOnly) => {
            (WireState::Suspended, TenantAccess::ReadOnly)
        }
        TenantState::Suspended(HoldMode::Locked) => (WireState::Suspended, TenantAccess::None),
        TenantState::Deleting | TenantState::Shredding => (WireState::Deleting, TenantAccess::None),
    };
    let limit = |name: &str| door.limits.get(name).copied();
    let limits = Limits {
        storage_bytes: limit(LIMIT_STORAGE),
        upload_24h_bytes: limit(LIMIT_UPLOAD_24H),
        download_allowance_bytes: limit(LIMIT_DOWNLOAD),
        active_keys: limit(LIMIT_ACTIVE_KEYS).map_or(DEFAULT_ACTIVE_KEYS, |n| {
            u32::try_from(n).unwrap_or(u32::MAX)
        }),
    };
    let suspension = match (door.holds.mode(), door.holds.since()) {
        (None, _) => None,
        (Some(mode), Some(since)) => {
            // The hold whose mode is in force and whose `since` is the
            // one `Holds::since` answers (the operator's on a tie).
            let operator = door
                .holds
                .operator
                .is_some_and(|h| h.mode == mode && h.since == since);
            let Some(since_ms) = ms(since) else {
                return Read::Damaged;
            };
            Some(Suspension {
                mode: match mode {
                    HoldMode::ReadOnly => SuspensionMode::ReadOnly,
                    HoldMode::Locked => SuspensionMode::Blocked,
                },
                reason: match operator {
                    true => SuspensionReason::Operator,
                    false => SuspensionReason::NonPayment,
                },
                since_ms,
            })
        }
        (Some(_), None) => return Read::Damaged,
    };
    let deletion = match &door.deletion {
        None => None,
        Some(d) => {
            let (Some(requested_at_ms), Some(shred_due_at_ms)) =
                (ms(d.requested_at), ms(d.shred_due_at))
            else {
                return Read::Damaged;
            };
            Some(WireDeletion {
                seq: d.seq,
                actor: match d.actor {
                    ActorClass::Customer => DeletionActor::Customer,
                    ActorClass::Billing => DeletionActor::Billing,
                    ActorClass::Operator => DeletionActor::Operator,
                },
                requested_at_ms,
                shred_due_at_ms,
            })
        }
    };
    let Some(created_at_ms) = ms(door.created_at) else {
        return Read::Damaged;
    };
    Read::Tenant(Box::new(Tenant {
        id: id.to_string(),
        state,
        access,
        limits,
        suspension,
        deletion,
        created_at_ms,
    }))
}

/// Runs a tenant read. `tenant` is the path's id (the route took only
/// the contract's form, never tenant 0).
pub async fn read_tenant<H: TenantHeadRead>(heads: &H, tenant: &str) -> Answer {
    let Some(id) = TenantId::parse(tenant) else {
        return Answer::code(Code::TenantNotFound, None);
    };
    let door = match heads.door(&id).await {
        Ok(Some(door)) => door,
        Ok(None) => return Answer::code(Code::TenantNotFound, None),
        Err(_) => return Answer::code(Code::ServiceUnavailable, None),
    };
    // A head of another tenant under this name is damage (the chain's
    // reader binds the name; this holds it once more).
    let named = match &door.tenant {
        crate::directory::record::Tenant::Managed(t) => t.as_str() == id.as_str(),
        crate::directory::record::Tenant::Zero => false,
    };
    if !named {
        return Answer::code(Code::InternalError, None);
    }
    match tenant_of(id.as_str(), &door) {
        Read::Tenant(t) => match serde_json::to_vec(&*t) {
            Ok(json) => Answer::json(200, json),
            Err(_) => Answer::code(Code::InternalError, None),
        },
        Read::NotFound => Answer::code(Code::TenantNotFound, None),
        Read::NotYet => Answer::code(Code::ServiceUnavailable, None),
        Read::Damaged => Answer::code(Code::InternalError, None),
    }
}

/// The plane's tenant read over `heads`.
pub struct TenantReadHandler<'a, H> {
    pub heads: &'a H,
}

impl<H: TenantHeadRead> crate::mgmt::serve::Handlers for TenantReadHandler<'_, H> {
    fn serves(&self, call: &crate::mgmt::route::Call) -> bool {
        matches!(call, crate::mgmt::route::Call::TenantRead { .. })
    }

    async fn handle(&self, ctx: crate::mgmt::serve::CallContext<'_>, _body: &[u8]) -> Answer {
        let crate::mgmt::route::Call::TenantRead { tenant } = &ctx.admitted.call else {
            return crate::mgmt::serve::not_built();
        };
        read_tenant(self.heads, tenant).await
    }
}
