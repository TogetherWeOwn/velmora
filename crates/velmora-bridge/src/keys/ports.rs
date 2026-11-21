//! What the key writer and the finisher talk to besides the record
//! store. Each is a port so that the order of the writes can be proven
//! against fakes before the unit and the directory exist (tenant
//! side) exist.

use super::record::{Entry, KeyOp, Subject};
use crate::crypto::scheme2::TenantId;
use crate::types::Result;

/// A store that holds a copy of a tenant's key table: a unit (root or
/// other), or the directory's routes. It is a copy: everything it gets
/// was read and verified from the chain by the Worker.
#[allow(async_fn_in_trait)]
pub trait KeyTarget {
    /// A short name for logs and reports (`root`, `unit 2`, `directory`).
    fn label(&self) -> &str;
    /// The `keys_seq` this store holds.
    async fn keys_seq(&self) -> Result<u64>;
    /// Moves the store to `to_seq`. `entries` holds every subject whose
    /// newest record is above the store's `keys_seq`, and every subject
    /// revoked by `m/rk/`, each with the status in force
    /// ([`Entry::effective_status`]). One transaction; a store already
    /// at or above `to_seq` changes nothing but the revocations (setting
    /// `revoked` twice changes nothing).
    async fn apply(&self, to_seq: u64, entries: &[Entry]) -> Result<()>;
}

/// Why an opening change was refused before any record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The tenant's cap is full: `429`.
    CapFull,
    /// The grant is not a subset of the acting principal's: `403`.
    NotSubset,
    /// The change is not valid at the head, or the name is taken: `409`.
    Conflict,
    /// No such subject: `404`.
    NotFound,
}

/// The answer of the root unit's reservation call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Checked against the unit's key table as of `keys_seq`. The record
    /// must be exactly `keys_seq + 1`, so no key is recorded against a
    /// grant that an earlier record has already narrowed or revoked.
    Admitted {
        keys_seq: u64,
    },
    Refused(Refusal),
}

/// An opening change as the reservation call sees it.
#[derive(Clone, Debug)]
pub struct OpeningChange<'a> {
    pub op: KeyOp,
    /// The subject as the record will state it.
    pub subject: &'a Subject,
    /// The principal the change is made under (`made_by` of a new key,
    /// the acting principal of a widening).
    pub acting: Option<&'a str>,
}

/// The root unit's reservation call: the cap slot, under the request's
/// `Idempotency-Key`, and the check that the new grant is no wider than
/// the acting principal's.
#[allow(async_fn_in_trait)]
pub trait KeyAdmission {
    async fn admit(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        change: &OpeningChange<'_>,
    ) -> Result<Admission>;
}

/// The chain a control intent names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlChain {
    Tenant,
    Keys,
}

/// Intents: the queue message is the durable part; the
/// directory's `pending_ops` row is its visible copy.
#[allow(async_fn_in_trait)]
pub trait ControlIntents {
    /// Sends `apply_control(tenant, chain, seq)` with its delay. A failure
    /// stops the change before its record.
    async fn send(&self, tenant: &TenantId, chain: ControlChain, seq: u64) -> Result<()>;
    /// Writes the `pending_ops` row. Best effort: the directory may be
    /// down, and the message does not need it.
    async fn note(
        &self,
        tenant: &TenantId,
        chain: ControlChain,
        seq: u64,
        kind: &str,
    ) -> Result<()>;
    /// Clears the row (step 5). Best effort.
    async fn clear(&self, tenant: &TenantId, chain: ControlChain, seq: u64) -> Result<()>;
}
