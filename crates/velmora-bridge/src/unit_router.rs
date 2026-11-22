//! The way from a managed tenant to its units (ADR-TENANCY §2.7, §8.4;
//! design round 5, AM-51).
//!
//! This module holds the ports the queue consumer and the request router
//! share. [`TenantHeads`] reads a tenant's verified chain head: the
//! consumer asks it whether a unit that answered `Unborn` is listed
//! (rule 7) and whether a tenant whose unit refused a job is being
//! shredded (AM-50).
//!
//! The adapters come from other lanes' code: the tenant chain reader
//! (`directory`, L3). A build without one uses [`NoHeads`], which fails
//! every read, so the consumer hands the message back and never
//! acknowledges on a head it could not read.

use crate::types::{BridgeError, Result};
use crate::unit::{TenantId, TenantState, UnitName};

/// What the consumer and the router take from a tenant's verified head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadView {
    pub state: TenantState,
    /// The units the head lists, by number.
    pub units: Vec<u32>,
}

impl HeadView {
    /// The head lists `unit` (of its own tenant: the caller asked for it).
    pub fn lists(&self, unit: &UnitName) -> bool {
        self.units.contains(&unit.unit)
    }

    /// The tenant is being shredded or is shredded: its jobs stop by
    /// design (ADR §13.3).
    pub fn shredding(&self) -> bool {
        matches!(self.state, TenantState::Shredding | TenantState::Shredded)
    }
}

/// A tenant's chain head, read from R2 and verified. `Err` for a read that
/// failed or a head that did not verify: never a guess.
#[allow(async_fn_in_trait)]
pub trait TenantHeads {
    async fn head(&self, tenant: &TenantId) -> Result<HeadView>;
}

/// No chain reader in this build: every read fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHeads;

/// The error of [`NoHeads`].
pub const NO_HEAD_READER: &str = "no tenant head reader in this build";

impl TenantHeads for NoHeads {
    async fn head(&self, _: &TenantId) -> Result<HeadView> {
        Err(BridgeError::NotImplemented(NO_HEAD_READER))
    }
}
