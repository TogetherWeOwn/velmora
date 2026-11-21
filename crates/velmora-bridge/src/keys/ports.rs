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
    /// The subjects this store holds closed: applied while their private
    /// part could not be opened, so held `disabled`
    /// ([`Entry::effective_status`]). They are sent again once the ring
    /// opens them.
    async fn closed(&self) -> Result<Vec<String>>;
    /// In one transaction, per subject, in the order of the chain:
    /// - a subject the store does not hold is inserted;
    /// - an entry replaces the subject's row only when its `last_seq` is
    ///   above the row's; or when it is equal, the row is closed and the
    ///   entry is not (the same record, now opened); so a stale entry
    ///   never replaces a newer one, whichever way it closes or opens;
    /// - a `revoked` entry sets the row `revoked` whatever its seq, and a
    ///   row that is `revoked` stays `revoked` whatever replaces it:
    ///   revoked is final;
    /// - then the store's `keys_seq` becomes the larger of its own and
    ///   `to_seq`.
    ///
    /// The directory follows the same rule for what it holds of a key.
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
    /// The access key id is routed to another tenant already: draw a new
    /// id and ask again.
    IdTaken,
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
    /// Clears every row of `chain` of `tenant` at or below `seq` (step 5):
    /// called once every store holds the chain to `seq`. Best effort. A
    /// row above the head that is older than its intent's delay and
    /// retries names a change that was never recorded (refused after its
    /// intent, or crashed); the pending sweep drops it.
    async fn clear(&self, tenant: &TenantId, chain: ControlChain, seq: u64) -> Result<()>;
}
