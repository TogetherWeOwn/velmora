//! The way from a managed tenant to its units (ADR-TENANCY §2.7, §8.4;
//! design round 5, AM-51).
//!
//! This module holds what the queue consumer and the request router take
//! from a tenant's verified chain head. The head is read through the unit
//! client's port, [`crate::unit_lease::client::TenantHeads`] (L3's chain
//! reader behind it); [`read_head`] turns its answer into a [`HeadView`].
//! The consumer asks it whether a unit that answered `Unborn` is listed
//! (rule 7) and whether a tenant whose unit refused a job is being
//! shredded (AM-50).
//!
//! A build without a chain reader uses [`NoHeads`], which fails every
//! read, so the consumer hands the message back and never acknowledges on
//! a head it could not read.

use crate::directory::chain::ChainError;
use crate::directory::record::{Lifecycle, TenantDoor};
use crate::types::BridgeError;
use crate::unit::{TenantId, UnitName};
use crate::unit_lease::client::TenantHeads;

/// What the consumer and the router take from a tenant's verified head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadView {
    /// The head record's seq (the tenant's `state_seq`).
    pub seq: u64,
    pub lifecycle: Lifecycle,
    /// The units the head lists, by number.
    pub units: Vec<u32>,
}

impl HeadView {
    pub fn of(door: &TenantDoor) -> HeadView {
        HeadView {
            seq: door.seq,
            lifecycle: door.lifecycle,
            units: door.units.clone(),
        }
    }

    /// The head lists `unit` (of its own tenant: the caller asked for it).
    pub fn lists(&self, unit: &UnitName) -> bool {
        self.units.contains(&unit.unit)
    }

    /// The tenant is being shredded or is shredded: its jobs stop by
    /// design (ADR §13.3).
    pub fn shredding(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Shredding | Lifecycle::Shredded)
    }
}

/// The tenant's verified head. `Ok(None)`: the tenant has no chain, so no
/// record lists any unit of it. `Err`: the read failed or did not verify,
/// never a guess. The chain is listed from its start (`known` 0): this is
/// the rare path of a refusal, and a message's numbers are not trusted as
/// a floor (a `known` above the head is an error, not the head).
pub async fn read_head<H: TenantHeads>(
    heads: &H,
    tenant: &TenantId,
) -> Result<Option<HeadView>, ChainError> {
    Ok(heads.head(tenant, 0).await?.as_ref().map(HeadView::of))
}

/// No chain reader in this build: every read fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHeads;

/// The error of [`NoHeads`].
pub const NO_HEAD_READER: &str = "no tenant head reader in this build";

impl TenantHeads for NoHeads {
    async fn head(&self, _: &TenantId, _: u64) -> Result<Option<TenantDoor>, ChainError> {
        Err(ChainError::Store(BridgeError::NotImplemented(
            NO_HEAD_READER,
        )))
    }
}

/// A tenant head for tests: `tenant` at `seq`, in `lifecycle`, listing
/// `units`; every other field at its default. Read from JSON as a record's
/// door part is, so it holds only fields a record can hold.
#[cfg(any(test, feature = "testkit"))]
pub fn test_door(tenant: &TenantId, seq: u64, lifecycle: Lifecycle, units: &[u32]) -> TenantDoor {
    serde_json::from_value(serde_json::json!({
        "v": crate::directory::record::RECORD_FORMAT,
        "tenant": tenant.as_str(),
        "seq": seq,
        "written_at": 1,
        "lifecycle": lifecycle,
        "units": units,
        "max_move_epoch": 0,
        "tk_version": 1,
        "key_checks": {"1": "00".repeat(16)},
        "highest_claimed": 1,
        "jurisdiction": "us",
    }))
    .expect("a door part")
}
