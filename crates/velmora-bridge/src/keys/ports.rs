//! What the key writer and the finisher talk to besides the record
//! store. Each is a port so that the order of the writes can be proven
//! against fakes before the unit and the directory exist (tenant
//! side) exist.

use super::record::{Entry, KeyOp, Marker, Rid, Subject};
use crate::crypto::scheme2::TenantId;
use crate::types::{BridgeError, BucketId, Result};

/// The most entries one apply carries (AM-12; an estimate, a page of
/// the chain).
pub const MAX_APPLY: usize = 100;

/// One entry of a key-chain apply: the record at one seq.
// Nearly every entry is a subject's; a marker is rare, so boxing the
// common case would cost an allocation per record for nothing.
#[allow(clippy::large_enum_variant)]
// `Debug` is written out: a held entry's `owner_ref` is not shown.
#[derive(Clone, PartialEq, Eq)]
pub enum ApplyEntry {
    /// A subject's record: the subject as the head holds it, at
    /// `last_seq` = the record's seq (for the subject's newest record,
    /// exactly that record's state), with the `m/rk/` revocations in force.
    /// `private` is `None` only when its private part does not open: the
    /// store holds it closed, and there is no identity to send. A subject
    /// the closing step holds (its opening not acknowledged by the
    /// directory) is [`ApplyEntry::Held`], never this.
    ///
    /// For the unit's wire (`KeyEntry`): `held = private.is_none()`; a held
    /// entry is sent without its secret, and then also without
    /// `secret_kek_version` (the unit refuses one without the other), and
    /// with no `owner_ref`.
    Subject(Entry),
    /// A subject's record the store must hold closed although its private
    /// part opened: the directory may not have its opening yet (the
    /// closing step's hold, ADR §2.5, AM-9). `entry` is the head's entry
    /// with `private: None` (no secret, no grant limits, no label), as for
    /// a subject that does not open. A held subject keeps its identity
    /// (AM-72): `owner_ref` is its private part's.
    ///
    /// For the unit's wire (`KeyEntry`): `held = true`, `owner_ref` as
    /// here, no secret, no `secret_kek_version`, grants without their
    /// limits.
    Held {
        entry: Entry,
        owner_ref: Option<String>,
    },
    /// A marker record (`KeysFrozen`, `KeysThawed`; AM-28, AM-62): it
    /// changes no subject. The store writes no row for it; it holds its
    /// seq's place in the run, so the run has no gap. `marker` is the
    /// record's kind as the chain states it.
    ///
    /// For the unit's wire (`KeyMarker`): `{"marker": "keys_frozen" |
    /// "keys_thawed", "seq": seq}` (a thaw's `ends` is not sent).
    Marker { seq: u64, marker: Marker },
}

impl std::fmt::Debug for ApplyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyEntry::Subject(e) => f.debug_tuple("Subject").field(e).finish(),
            ApplyEntry::Held { entry, owner_ref } => f
                .debug_struct("Held")
                .field("entry", entry)
                .field("owner_ref", &owner_ref.is_some())
                .finish(),
            ApplyEntry::Marker { seq, marker } => f
                .debug_struct("Marker")
                .field("seq", seq)
                .field("marker", marker)
                .finish(),
        }
    }
}

impl ApplyEntry {
    /// The seq of the record.
    pub fn seq(&self) -> u64 {
        match self {
            ApplyEntry::Subject(e) | ApplyEntry::Held { entry: e, .. } => e.last_seq,
            ApplyEntry::Marker { seq, .. } => *seq,
        }
    }

    /// The subject's entry, held or not; `None` for a marker.
    pub fn entry(&self) -> Option<&Entry> {
        match self {
            ApplyEntry::Subject(e) | ApplyEntry::Held { entry: e, .. } => Some(e),
            ApplyEntry::Marker { .. } => None,
        }
    }

    /// Whether the store must hold the subject closed: a held entry, or
    /// one whose private part did not open.
    pub fn held(&self) -> bool {
        match self {
            ApplyEntry::Subject(e) => e.private.is_none(),
            ApplyEntry::Held { .. } => true,
            ApplyEntry::Marker { .. } => false,
        }
    }
}

/// The answer a reservation keeps (AM-38): the Worker's first answer to a
/// reserved call, cleaned of every secret, which a retry under the same
/// reservation gets again. Only the root unit keeps one, and only from its
/// full apply ([`KeyTarget::apply_kept`]). `Debug` shows no body.
#[derive(Clone, PartialEq, Eq)]
pub struct KeptAnswer {
    pub rid: Rid,
    pub status: u16,
    pub body: String,
}

impl std::fmt::Debug for KeptAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeptAnswer")
            .field("rid", &self.rid)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// The answer of a store that keeps no answers to a call that has some.
pub const ERR_NO_KEPT: BridgeError = BridgeError::Invalid("this key store keeps no answers");

/// What a store answered an apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Applied; the store's `keys_seq` is now this.
    Done { keys_seq: u64 },
    /// `from_seq` is above the store's `keys_seq`: nothing was done; the
    /// caller sends again from `keys_seq`.
    Behind { keys_seq: u64 },
}

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
    /// The key-chain apply (ADR §2.4 rule 5, AM-12), in one transaction:
    /// - `from_seq` is the exclusive base: `entries` are the records
    ///   `from_seq + 1`, `from_seq + 2`, … with no gap, at most
    ///   [`MAX_APPLY`]; anything else is refused (an `Err`), and nothing
    ///   is kept;
    /// - a `from_seq` above the store's `keys_seq` answers
    ///   [`Applied::Behind`] with it, and nothing is kept;
    /// - per entry, in order: a subject the store does not hold is
    ///   inserted; an entry replaces the subject's row only when its
    ///   `last_seq` is above the row's, or equal while the row is held
    ///   closed and the entry is not; a `revoked` entry sets the row
    ///   `revoked` whatever its seq, and a `revoked` row stays `revoked`;
    ///   a marker changes nothing;
    /// - then the store's `keys_seq` becomes the larger of its own and the
    ///   last entry's seq.
    ///
    /// The directory follows the same rule for what it holds of a key.
    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied>;
    /// [`KeyTarget::apply`] that also keeps `answers` (AM-38), in the same
    /// transaction: each for the reservation of its `rid` once that is
    /// `applied` (an entry of this call or an earlier one carried the
    /// `rid`) and has no answer yet. The root unit implements it; the
    /// writer calls it only once the directory acknowledged the record and
    /// every unit holds it in full. The default refuses any answer
    /// ([`ERR_NO_KEPT`]) and applies nothing then.
    async fn apply_kept(
        &self,
        from_seq: u64,
        entries: &[ApplyEntry],
        answers: &[KeptAnswer],
    ) -> Result<Applied> {
        if !answers.is_empty() {
            return Err(ERR_NO_KEPT);
        }
        self.apply(from_seq, entries).await
    }
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
    /// A grant with a prefix, an expiry or an IP list: milestone 1 serves
    /// unlimited grants only, so a key is never made or narrowed into one
    /// that cannot work (ADR §6.2, AM-18): `400`.
    GrantLimitsNotServed,
    /// The subject holds the most grants a record may carry (64, ADR
    /// §6.2, AM-13): `409`.
    GrantCap,
    /// The acting principal of a bucket create is not an active
    /// principal: `403`.
    CreatorNotActive,
}

impl Refusal {
    /// The HTTP status of the answer.
    pub fn status(self) -> u16 {
        match self {
            Refusal::CapFull => 429,
            Refusal::NotSubset | Refusal::CreatorNotActive => 403,
            Refusal::Conflict | Refusal::IdTaken | Refusal::GrantCap => 409,
            Refusal::NotFound => 404,
            Refusal::GrantLimitsNotServed => 400,
        }
    }

    /// The code of the answer's body.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::CapFull => "cap_full",
            Refusal::NotSubset => "grant_not_subset",
            Refusal::Conflict => "conflict",
            Refusal::NotFound => "not_found",
            Refusal::IdTaken => "id_taken",
            Refusal::GrantLimitsNotServed => "grant_limits_not_served",
            Refusal::GrantCap => "too_many_grants",
            Refusal::CreatorNotActive => "creator_not_active",
        }
    }
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

/// A bucket create as the reservation call sees it.
#[derive(Clone, Copy, Debug)]
pub struct BucketReservation<'a> {
    /// The bucket's name: unique in the tenant, so the reservation holds it.
    pub name: &'a str,
    /// The acting principal. Its creator grant, `rw` on the new bucket
    /// id, is the key-chain record `keys_seq + 1` (DS1 A7, ADR §6.2).
    pub creator: &'a str,
    /// The unit the bucket is placed on.
    pub unit: u32,
}

/// The answer of the root unit's reservation call for a bucket create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BucketAdmission {
    /// The bucket-create cap slot and the name are held under the
    /// `Idempotency-Key`; the creator was an active principal at
    /// `keys_seq`. With `bound` unset, the creator grant must be exactly
    /// `keys_seq + 1`; asked again under the same key, the unit checks
    /// again at its own head and answers that head. With `bound` set, an
    /// earlier call under this key wrote the creator grant at that seq
    /// and bound it ([`KeyAdmission::bind_bucket`]): the call places that
    /// grant's bucket, and writes no new grant unless that one loses. A
    /// bound reservation is answered so whatever its creator is now: its
    /// grant was recorded first.
    Admitted {
        keys_seq: u64,
        bound: Option<u64>,
    },
    /// The reservation under this key already became the bucket
    /// `bucket`, whose creator grant is `grant_seq`: the call is a retry.
    Created {
        bucket: BucketId,
        grant_seq: u64,
    },
    Refused(Refusal),
}

/// What the root unit's reservations say of one creator-grant seq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binding {
    /// An open reservation is bound to it: the create may still finish.
    Open {
        idempotency_key: String,
        name: String,
        creator: String,
        unit: u32,
    },
    /// The reservation bound to it became the bucket.
    Created,
    /// No reservation is bound to it: none ever was (a call that died
    /// between its put and its bind), or it was released, swept, or bound
    /// again to a later seq. The seq is fenced by this answer: the grant
    /// is an orphan for good.
    None,
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
    /// Releases the reservation held under `idempotency_key`: called once
    /// a call ends with no record for it. Best effort: a reservation that
    /// is not released is swept after 1 hour (est). Releasing one that
    /// was already released, or turned into a row, changes nothing. A
    /// later call under the same key reserves again.
    async fn release(&self, tenant: &TenantId, idempotency_key: &str) -> Result<()>;
    /// The reservation of a bucket create: the bucket-create cap slot and
    /// the name, under `idempotency_key`, and the check that the creator
    /// is an active principal at the unit's `keys_seq`.
    async fn admit_bucket(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        bucket: &BucketReservation<'_>,
    ) -> Result<BucketAdmission>;
    /// Binds the bucket reservation under `idempotency_key` to the creator
    /// grant at `grant_seq`, which this call's own put wrote, only while
    /// the reservation is bound to `expected` (the `bound` this call was
    /// admitted with): a compare-and-set, so of two calls under one key
    /// only one binds, and the other places that one's bucket. `Ok(false)`:
    /// the binding was not `expected`; nothing changed. Binding the same
    /// seq again answers `Ok(true)`. From then on the unit answers it in
    /// `Admitted::bound`, and turns the reservation into the bucket row
    /// when it applies `bucket_created` for that seq.
    async fn bind_bucket(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        expected: Option<u64>,
        grant_seq: u64,
    ) -> Result<bool>;
    /// Releases the bucket reservation under `idempotency_key` only while
    /// it is bound to `bound`: a call never releases a reservation that
    /// another call under the same key has bound since. `Ok(true)`: no
    /// reservation under the key lives on (released now, or none open).
    /// `Ok(false)`: it lives on, bound to another seq or turned into the
    /// bucket; nothing changed.
    async fn release_bound(
        &self,
        tenant: &TenantId,
        idempotency_key: &str,
        bound: Option<u64>,
    ) -> Result<bool>;
    /// What the reservations say of the creator grant at `grant_seq`. An
    /// answer of [`Binding::None`] also fences the seq, in the same unit
    /// transaction: from then on [`KeyAdmission::bind_bucket`] of it
    /// answers `Ok(false)`. So the finisher's revoke of an unbound grant
    /// and a late bind of it by a stalled call never both happen.
    async fn bucket_binding(&self, tenant: &TenantId, grant_seq: u64) -> Result<Binding>;
}

/// What the tenant chain answered a `bucket_created` record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketPut {
    /// Recorded: by this call, or read back as this create after a lost
    /// answer. `in_force`: the directory and the units acknowledged it
    /// (ADR §2.5 store order); when not, the tenant chain's finisher
    /// brings them up.
    Placed { in_force: bool },
    /// Another create recorded a higher creator-grant seq first
    /// (`grant_order_lost`). This grant seq can never be placed now.
    OrderLost,
    /// Refused by the tenant's state (`restoring`, the lifecycle, a unit
    /// that is not listed): the call answers `status` with `code`.
    Refused { status: u16, code: &'static str },
}

/// The tenant chain as the creator-grant writer needs it. Its owner
/// writes the record with its own rules (`CreateBucket`: the derived id,
/// not placed, `grant_seq` above `last_grant_seq`).
#[allow(async_fn_in_trait)]
pub trait BucketRecords {
    /// Records `bucket_created{bucket, unit, creator, grant_seq}`. An
    /// `Err` says nothing about whether it was recorded.
    async fn bucket_created(
        &self,
        tenant: &TenantId,
        bucket: &BucketId,
        unit: u32,
        creator: &str,
        grant_seq: u64,
    ) -> Result<BucketPut>;
    /// Whether the verified head places `bucket`.
    async fn is_placed(&self, tenant: &TenantId, bucket: &BucketId) -> Result<bool>;
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
