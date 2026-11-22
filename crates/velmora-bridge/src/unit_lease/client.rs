//! The unit client: the Worker's side of `renew` and `sync` (ADR-TENANCY
//! §2.4 rules 5 and 12; round 5 §R5-4, AM-50, AM-51).
//!
//! A unit holds no key and does no I/O (rules 3 and 4), so the Worker
//! does the reads a unit needs and hands it the verified result:
//!
//! - **`renew`.** The unit's numbers, stamp counter and revoked count come
//!   from its own answers (a stamp read through the job path, which a unit
//!   with an expired lease still serves). The proof is
//!   [`super::renewal::prove`] over the safety bucket. Then the unit is
//!   called with `renew(proof_start, proven, revocations)`. A newer record
//!   means `sync` first; a stamp object after the counter is confirmed
//!   through the unit's own counter ([`crate::stamp::Stamp::checked`]),
//!   which records a rollback and closes the unit only if the counter has
//!   not moved.
//! - **`sync`.** The tenant chain's verified head ([`TenantHeads`]) and the
//!   key-chain records after the unit's `keys_seq` ([`KeyFeed`]): first
//!   the key apply (AM-12), then `sync` with both heads. The `sync` that
//!   would lift a `restoring` entry is the restore tool's (AM-45): it
//!   carries the lift, which no record here has, so the client reports
//!   [`Synced::LiftPending`] and changes nothing.
//! - **Rule 5 on the request path** ([`UnitClient::call`]): a
//!   `renew_needed` renews, a `sync_needed` syncs, a lower request number
//!   takes the unit's numbers; then the call runs once more. An answer
//!   with less than half of T left asks for a background renewal
//!   ([`Answered::renew_due`]; the caller runs it under `waitUntil`, at
//!   most one per unit and isolate: [`InFlight`]).
//! - **The two unit jobs** ([`UnitClient::run_job`]): `renew` and
//!   `stamp_raise`, which the queue consumer hands here (AM-51). Under
//!   `MAINTENANCE = restore` the consumer acknowledges both without a call
//!   (AM-50); that check is the consumer's, before this.
//!
//! Every port is a trait, so native tests run the real unit
//! ([`crate::unit::Unit`]) behind a fake [`UnitReplies`].
//!
//! Errors: `Err` is a store or call that failed and may pass (the queue
//! hands the message back); an outcome is an answer. No error or outcome
//! carries a key, a secret or a caller's input.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use crate::directory::chain::ChainError;
use crate::directory::record::TenantDoor;
use crate::jobmsg::UnitJob;
use crate::ports::{BlobStore, Clock};
use crate::types::Result;
use crate::unit::keys::{KeptAnswer, KeyEntry};
use crate::unit::{Seqs, TenantId, UnitCall, UnitName, UnitReply};

use super::lease::{LeaseRefusal, LeaseRules};
use super::renewal::ChainNames;
use super::stamp_id::UnitStampId;

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// The unit object as the Worker reaches it: one call, and the whole
/// reply ([`UnitReply`]: the answer, `lease_left_ms` and `revoked`). The
/// Worker's stub (`workers/s3-bridge/src/units.rs`) implements it beside
/// `tenant_catalog::UnitPort`.
#[allow(async_fn_in_trait)]
pub trait UnitReplies {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply>;
}

impl<T: UnitReplies> UnitReplies for &T {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply> {
        (**self).reply(call).await
    }
}

/// The verified head of a tenant's chain `m/t/<t>/` (L3's reader:
/// [`crate::directory::chain::TenantChain::head`], which this crate
/// implements the port for).
#[allow(async_fn_in_trait)]
pub trait TenantHeads {
    /// The newest record's door part, listing after `known`; `None` = the
    /// tenant has no chain.
    async fn head(
        &self,
        tenant: &TenantId,
        known: u64,
    ) -> std::result::Result<Option<TenantDoor>, ChainError>;
}

/// The key-chain records of a tenant after a seq, verified and in the
/// form the unit applies them (L4's reader and apply feed, AM-12).
#[allow(async_fn_in_trait)]
pub trait KeyFeed {
    /// The records of `m/k/<tenant>/` after `after`, one entry per record
    /// in chain order, up to the chain's head.
    async fn after(&self, tenant: &TenantId, after: u64) -> Result<KeyBatch>;
}

/// What [`KeyFeed::after`] read.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeyBatch {
    /// The chain's head seq (`after` when nothing follows it).
    pub head: u64,
    /// The entries after `after`, up to `head`.
    pub entries: Vec<KeyEntry>,
    /// The answers kept for the reservations whose records these are
    /// (AM-38), if the feed has them.
    pub answers: Vec<KeptAnswer>,
}

/// The key chain's finisher, told that a renewal listed revocations the
/// unit did not hold (ADR rule 12, SEC-6: "sends an `apply_control`
/// message for the key chain"). The Worker sends the `apply_control`
/// message; a failure is logged by the caller and changes nothing here.
#[allow(async_fn_in_trait)]
pub trait KeyFinisher {
    async fn revocations_unrecorded(&self, tenant: &TenantId) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Something the caller logs as an alert (it pages). Fixed words and
/// names only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Page {
    /// Names under `m/rk/<t>/` that are not an access key id: skipped.
    StrayRevocationNames(Vec<String>),
    /// The unit holds more revocations than `m/rk/<t>/` lists: not
    /// renewed (no correct history gives it).
    RevocationsShort { listed: u64, held: u64 },
    /// A stamp object after the unit's counter, confirmed: the unit is
    /// rolled back and now closed; the restore gate is needed (§8.6).
    RolledBack,
    /// The unit refused a renewal for a reason that needs an operator
    /// (no lease table, a bad list).
    RenewRefused(LeaseRefusal),
    /// The finisher could not be told of unrecorded revocations; the
    /// unit holds them all the same.
    FinisherNotTold,
}

/// What [`UnitClient::renew`] came to.
#[derive(Clone, Debug, PartialEq)]
pub enum Renewal {
    /// The unit is fresh for `lease_left_ms` more, at `seqs`.
    Renewed { seqs: Seqs, lease_left_ms: u64 },
    /// The unit takes no renewal until the gate lifts it: a `restoring`
    /// entry, or a recorded rollback (`rolled_back`).
    Closed { rolled_back: bool },
    /// The unit has no certificate (rule 7): the caller decides from the
    /// tenant's verified head whether that pages.
    Unborn,
    /// The tenant's verified head does not list this unit (it was
    /// removed): nothing to renew.
    NotListed,
    /// Not renewed, and not retryable here: see the pages.
    Refused,
}

/// What [`UnitClient::sync`] came to.
#[derive(Clone, Debug, PartialEq)]
pub enum Synced {
    /// The unit holds both chain heads: `seqs`.
    Synced { seqs: Seqs },
    /// The head clears this unit's `restoring` entry. Only the restore
    /// tool's `sync`, which carries the lift, may clear it (AM-45); the
    /// unit stays closed and nothing changed.
    LiftPending { seqs: Seqs },
    /// The unit has no certificate.
    Unborn,
    /// The tenant's verified head does not list this unit.
    NotListed,
}

/// A request-path answer after rule 5 ([`UnitClient::call`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Answered {
    /// The unit's last reply.
    pub reply: UnitReply,
    /// The call ran again with the unit's numbers, which are above the
    /// caller's: the caller's view of the tenant head is old and is read
    /// again.
    pub refreshed: Option<Seqs>,
    /// Less than half of T is left: renew in the background (rule 12).
    pub renew_due: bool,
}

/// What the queue does with a `renew` or `stamp_raise` message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Done, or nothing to do.
    Ack,
    /// Hand it back with the queue's retry delay (a failure that may pass).
    HandBack,
    /// The unit has no certificate: the consumer reads the tenant's
    /// verified head and applies AM-50's `Unborn` row.
    Unborn,
}

/// The delivery of one unit job, and its log line.
#[derive(Clone, Debug, PartialEq)]
pub struct JobResult {
    pub delivery: Delivery,
    /// A fixed word for the log line.
    pub code: &'static str,
    /// Alerts to log (each pages).
    pub pages: Vec<Page>,
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// The Worker's client of one unit. See the [module](self).
pub struct UnitClient<U, B, T, N, H, K, F> {
    /// The unit object.
    pub unit: U,
    /// The safety bucket: the proof's reads, and the stamp objects.
    pub safety: B,
    pub clock: T,
    /// The names of the tenant's records.
    pub names: N,
    /// The tenant chain's verified head.
    pub heads: H,
    /// The key chain's verified records.
    pub keys: K,
    /// The key chain's finisher.
    pub finisher: F,
    /// The unit's name.
    pub name: UnitName,
    /// Whether the caller reached the unit through a record that lists
    /// it (rule 7): the request path takes it from the head; job and
    /// Worker calls send `false` (AM-50).
    pub listed: bool,
    /// The lease dials (T): for the half-of-T rule.
    pub lease: LeaseRules,
}

impl<U, B, T, N, H, K, F> UnitClient<U, B, T, N, H, K, F>
where
    U: UnitReplies,
    B: BlobStore,
    T: Clock,
    N: ChainNames,
    H: TenantHeads,
    K: KeyFeed,
    F: KeyFinisher,
{
    /// The unit's stamp id `<tenant>.<unit>`. `Err` for tenant 0, which
    /// has no unit.
    pub fn stamp_id(&self) -> Result<UnitStampId> {
        UnitStampId::new(self.name.tenant.as_str(), self.name.unit)
    }

    /// Proves the unit fresh and renews its lease (rule 12). `seen`: the
    /// unit's numbers as its last answer gave them (the job message's for
    /// a `renew` job). Syncs first when the proof finds a newer record.
    pub async fn renew(&self, seen: Seqs) -> Result<(Renewal, Vec<Page>)> {
        let _ = seen;
        todo!("L2-1")
    }

    /// Reads and verifies both chains up to their heads, applies the
    /// key-chain records (AM-12), then calls `sync` (rule 5). `seen`: the
    /// unit's numbers as its last answer gave them.
    pub async fn sync(&self, seen: Seqs) -> Result<Synced> {
        let _ = seen;
        todo!("L2-1")
    }

    /// Rule 5 on the request path: sends `call`; on `renew_needed` renews,
    /// on `sync_needed` syncs, on a lower number (`stale`) takes the
    /// unit's numbers; then sends it once more. Each fix runs at most once
    /// per call.
    pub async fn call(&self, call: UnitCall) -> Result<Answered> {
        let _ = call;
        todo!("L2-1")
    }

    /// Whether `reply` asks for a background renewal: some lease, and
    /// less than half of T left (rule 12).
    pub fn renew_due(&self, reply: &UnitReply) -> bool {
        let half = u64::try_from(self.lease.term_ms / 2).unwrap_or(0);
        reply.lease_left_ms > 0 && reply.lease_left_ms < half
    }

    /// One `renew` or `stamp_raise` message of this unit, at the numbers
    /// it carries (AM-50, AM-51).
    pub async fn run_job(&self, job: UnitJob, seqs: Seqs) -> JobResult {
        let _ = (job, seqs);
        todo!("L2-1")
    }
}

/// The background renewals in flight in one isolate, by unit: a second
/// one for the same unit is not started while the first runs. Cheap to
/// clone; one per isolate.
#[derive(Clone, Debug, Default)]
pub struct InFlight(Rc<RefCell<BTreeSet<String>>>);

/// Held while one background renewal runs; dropping it ends it.
#[derive(Debug)]
pub struct InFlightGuard {
    set: Rc<RefCell<BTreeSet<String>>>,
    name: String,
}

impl InFlight {
    /// Starts a renewal of `name`, or `None` when one is running.
    pub fn begin(&self, name: &UnitName) -> Option<InFlightGuard> {
        let key = name.object_name();
        if !self.0.borrow_mut().insert(key.clone()) {
            return None;
        }
        Some(InFlightGuard {
            set: self.0.clone(),
            name: key,
        })
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.set.borrow_mut().remove(&self.name);
    }
}
