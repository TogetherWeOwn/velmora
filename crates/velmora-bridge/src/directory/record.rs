//! The tenant record: one record of a tenant's chain `m/t/<tenant>/<seq>`.
//!
//! A tenant record carries **every fact the directory holds about the
//! tenant**, so that the directory is a copy of the chain heads and can be
//! rebuilt from them. It has two parts:
//!
//! - the **door part** ([`TenantDoor`]): what a gate needs to open or close
//!   a door without the tenant's key. State, holds, deletion, the
//!   `restoring` entries, flags, limits, units and placements, key
//!   versions, jurisdiction, and for tenant 0 the catalogue selector;
//! - the **private part** ([`TenantPrivate`]): what must die with the
//!   tenant's key: the `external_ref` that binds a workspace, and in the
//!   record that creates a bucket its name and its wrapped data key.
//!
//! How the two parts are sealed is the [`super::chain::ControlSeal`]
//! port's business, not this module's.
//!
//! # State is stored in part and derived in part
//!
//! The record stores a [`Lifecycle`] (`provisioning`, `live`,
//! `shredding`, `shredded`) and the two fields `holds` and `deletion`.
//! The three middle states of a live tenant follow from those two
//! ([`TenantDoor::state`]): `deleting` if a deletion is set, else
//! `suspended` if any hold is set, else `active`. A suspension therefore
//! survives a deletion and its undo, and a hold is lifted only by the
//! plane that may lift it.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::types::UnixMs;
use crate::TenantId;

/// The version of the door and private part formats. A reader refuses
/// any other: a gate that cannot apply a field must not guess it.
pub const RECORD_FORMAT: u32 = 1;

/// The number of hex digits after `t_` in a tenant id.
pub const TENANT_ID_HEX: usize = 16;

/// The owner of a tenant chain: tenant 0 (`t_0000000000000000`, scheme 1)
/// or a managed tenant, whose id is the crate's one tenant id type,
/// [`crate::TenantId`] (scheme 2). The directory names both, so it keeps
/// tenant 0 apart in its own variant, as the control seal's
/// [`crate::crypto::scheme2::ControlOwner`] does. Stored as the bare id.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Tenant {
    /// The tenant of every bucket that exists today.
    Zero,
    /// A managed tenant.
    Managed(TenantId),
}

impl Tenant {
    /// Tenant 0.
    pub fn zero() -> Tenant {
        Tenant::Zero
    }

    /// Parses a tenant id; `None` for anything but `t_` and 16 lowercase
    /// hex digits.
    pub fn parse(id: &str) -> Option<Tenant> {
        if id == crate::recovery::DEFAULT_TENANT {
            return Some(Tenant::Zero);
        }
        TenantId::parse(id).ok().map(Tenant::Managed)
    }

    /// From the 8 random bytes of a new tenant. All zero is tenant 0's id,
    /// which no new tenant may take: `None`.
    pub fn from_random(bytes: [u8; 8]) -> Option<Tenant> {
        let mut id = String::with_capacity(2 + TENANT_ID_HEX);
        id.push_str("t_");
        for b in bytes {
            id.push_str(&format!("{b:02x}"));
        }
        TenantId::parse(&id).ok().map(Tenant::Managed)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Tenant::Zero => crate::recovery::DEFAULT_TENANT,
            Tenant::Managed(t) => t.as_str(),
        }
    }

    pub fn is_zero(&self) -> bool {
        matches!(self, Tenant::Zero)
    }

    /// The managed tenant's id; `None` for tenant 0.
    pub fn managed(&self) -> Option<&TenantId> {
        match self {
            Tenant::Zero => None,
            Tenant::Managed(t) => Some(t),
        }
    }
}

impl From<TenantId> for Tenant {
    fn from(t: TenantId) -> Tenant {
        Tenant::Managed(t)
    }
}

// By the id, as the directory's rows and the chain's names sort.
impl Ord for Tenant {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for Tenant {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Tenant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Tenant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for Tenant {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Tenant::parse(&s).ok_or("not a tenant id")
    }
}

impl From<Tenant> for String {
    fn from(t: Tenant) -> String {
        t.as_str().to_owned()
    }
}

/// What the record stores of a tenant's state. The live states
/// (`active`, `suspended`, `deleting`) are derived, see
/// [`TenantDoor::state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Provisioning,
    Live,
    Shredding,
    Shredded,
}

/// What a hold allows. `locked` is stricter than `read_only`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldMode {
    ReadOnly,
    Locked,
}

/// The reason codes of an `operator` hold. Codes, never free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorReason {
    Abuse,
    Legal,
    Security,
    Other,
}

impl OperatorReason {
    /// Whether a hold with this reason preserves the data unless the
    /// operator says otherwise: on for `legal` and `abuse`.
    pub fn preserves_by_default(self) -> bool {
        matches!(self, OperatorReason::Abuse | OperatorReason::Legal)
    }
}

/// The `billing` hold. Its reason is always non-payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingHold {
    pub mode: HoldMode,
    /// The `written_at` of the record that placed the hold or changed its
    /// mode.
    pub since: UnixMs,
}

/// The `operator` hold. `preserve` means: this tenant's data must not
/// be destroyed while the hold stands. The record carries the value,
/// never the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorHold {
    pub mode: HoldMode,
    pub reason: OperatorReason,
    pub preserve: bool,
    /// The `written_at` of the record that placed the hold or changed its
    /// mode. A change of the reason or of `preserve` alone keeps it.
    pub since: UnixMs,
}

/// At most one hold per actor class. The customer plane has none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<BillingHold>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<OperatorHold>,
}

impl Holds {
    pub fn is_empty(&self) -> bool {
        self.billing.is_none() && self.operator.is_none()
    }

    /// The strictest mode in force, `None` with no hold.
    pub fn mode(&self) -> Option<HoldMode> {
        let billing = self.billing.map(|h| h.mode);
        let operator = self.operator.map(|h| h.mode);
        billing.max(operator)
    }

    /// Whether an `operator` hold with `preserve` stands.
    pub fn preserves(&self) -> bool {
        self.operator.is_some_and(|h| h.preserve)
    }

    /// Since when the mode in force holds: the `since` of the hold whose
    /// mode is the strictest, the earlier one when both hold that mode.
    /// `None` with no hold.
    pub fn since(&self) -> Option<UnixMs> {
        let mode = self.mode()?;
        let billing = self.billing.filter(|h| h.mode == mode).map(|h| h.since);
        let operator = self.operator.filter(|h| h.mode == mode).map(|h| h.since);
        match (billing, operator) {
            (Some(b), Some(o)) => Some(b.min(o)),
            (b, o) => b.or(o),
        }
    }
}

/// The class of the plane that made a change, from the token that
/// authenticated the call and never from a parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorClass {
    Customer,
    Billing,
    Operator,
}

/// Why a deletion was set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionReason {
    CustomerRequest,
    NonPayment,
    Operator(OperatorReason),
}

/// A pending deletion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deletion {
    /// The seq of the record that set this deletion. The undo names it
    /// (`deletion_seq`), so a late retry never cancels a newer deletion.
    pub seq: u64,
    /// The `written_at` of that record.
    pub requested_at: UnixMs,
    pub shred_due_at: UnixMs,
    pub reason: DeletionReason,
    pub actor: ActorClass,
    /// The SHA-256 of the call's `Idempotency-Key`, lowercase hex. Kept so
    /// that the undo can remember it.
    pub key_hash: String,
}

/// One unit that is being restored, with the seq of the record that set
/// its entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restoring {
    pub unit: u32,
    pub since_seq: u64,
}

/// Where a bucket lives, and since which move.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub bucket: String,
    pub unit: u32,
    pub epoch: u64,
}

/// Which catalogue serves tenant 0. Tenant 0 stays on today's D1 until
/// its data moves into a tenant of its own; then it serves nothing, and
/// 30 days later it is retired for good. No unit is ever born for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selector {
    /// Today's D1 catalogue.
    D1,
    /// The move's window: D1 is frozen and the other tenant's unit is
    /// being filled. Reads from D1; writes are closed.
    Moving,
    /// The flip is done: the data is the tenant that `move.to` names.
    Moved,
    /// Day 30 is done. Terminal: no record follows.
    Retired,
}

impl Selector {
    pub fn as_str(self) -> &'static str {
        match self {
            Selector::D1 => "d1",
            Selector::Moving => "moving",
            Selector::Moved => "moved",
            Selector::Retired => "retired",
        }
    }
}

/// The move of tenant 0's data into a tenant of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Move {
    /// The tenant that the data moves to.
    pub to: Tenant,
    /// The catalogue id of the frozen D1 (`main`).
    pub catalogue_id_frozen: String,
    /// The legacy stamp's counter at the flip, once it happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamp: Option<u64>,
    /// When the flip record was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flipped_at: Option<UnixMs>,
    /// The fallback undo: the stamp counter the frozen catalogue was
    /// levelled to before it served again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub levelled_to: Option<u64>,
}

/// The fields that only tenant 0's record has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantZero {
    pub selector: Selector,
    /// The move, from its window on; kept as history after an undo.
    #[serde(default, rename = "move", skip_serializing_if = "Option::is_none")]
    pub moved: Option<Move>,
    /// The stamp of an undo, higher than the move's stamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_stamp: Option<u64>,
    /// After an undo: the id of the catalogue that `d1` then means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue_id: Option<String>,
    /// Every catalogue id that a move froze, oldest first. An undo never
    /// lands on one of them but by the fallback route, onto the newest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frozen_catalogues: Vec<String>,
    /// How many moves flipped. The cutover marker that a move writes names
    /// the move by `flips + 1`: a marker at or below `flips` is one of a
    /// move that flipped, and its database was left behind.
    #[serde(default)]
    pub flips: u64,
}

impl TenantZero {
    /// The catalogue that `d1` means now: the one an undo named, or
    /// today's.
    pub fn current_catalogue(&self) -> &str {
        self.catalogue_id
            .as_deref()
            .unwrap_or(crate::config::DEFAULT_CATALOGUE_ID)
    }

    /// Whether the newest move was undone: an undo stamp above its stamp.
    pub fn undone(&self) -> bool {
        match (&self.moved, self.undo_stamp) {
            (Some(m), Some(undo)) => m.stamp.is_some_and(|stamp| undo > stamp),
            _ => false,
        }
    }
}

/// The bucket that a record creates, and the principal that asked for it.
/// History only: the creator's `rw` grant on the new bucket is a record of
/// the key chain, written before this one, and grants are built from the
/// key chain alone. Only the record that creates the bucket carries it.
/// Its name and its wrapped data key are in the record's private part
/// ([`BucketSecrets`]), sealed under the tenant key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketCreated {
    pub bucket: String,
    /// The key-chain id of the acting principal.
    pub creator: String,
    /// The key-chain seq of the creator grant: the bucket's id is derived
    /// from it ([`crate::records::bucket_id`]).
    pub grant_seq: u64,
}

/// The private facts of the bucket a record creates: its name and its data
/// key (BDK), wrapped under the tenant key (`crypto::scheme2::wrap_bdk_v2`,
/// at the record's `tk_version`). The unit makes the bucket's row from
/// them, also again after a restore, so the wrap is drawn once, before the
/// record, and never again. The shred erases both with the tenant key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketSecrets {
    pub name: String,
    #[serde(with = "b64")]
    pub bdk_wrapped: Vec<u8>,
}

impl fmt::Debug for BucketSecrets {
    // Shapes only: a name is customer data, a wrap is key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BucketSecrets")
            .field("name_len", &self.name.len())
            .field("bdk_wrapped_len", &self.bdk_wrapped.len())
            .finish()
    }
}

mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// The owner's buckets that a record places in this tenant, moved from
/// tenant 0 with their ids unchanged, and the seq of tenant 0's `moving`
/// head that admitted them. Only that record carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketsMovedIn {
    pub zero_seq: u64,
    pub unit: u32,
    pub buckets: Vec<String>,
}

/// The move that filled this tenant with tenant 0's buckets: the seq of
/// tenant 0's `moving` head that admitted the first placement. Carried
/// from the record that places them until the record that removes them
/// (AM-23): it ties `UnplaceMovedBuckets` to a tenant that a move filled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MovedIn {
    pub zero_seq: u64,
}

/// The `restoring` entry a record lifts, with the lift the unit checks
/// (ADR §8.6 step 8, AM-2, AM-15): the restore gate's, or the move's
/// `move` report. Only the record that lifts carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifted {
    pub unit: u32,
    pub since_seq: u64,
    pub proof: crate::unit::lift::LiftProof,
}

/// The door part of a tenant record. See the [module](self).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantDoor {
    pub v: u32,
    pub tenant: Tenant,
    pub seq: u64,
    pub written_at: UnixMs,
    /// The `written_at` of seq 1, carried unchanged.
    pub created_at: UnixMs,
    pub lifecycle: Lifecycle,
    #[serde(default)]
    pub holds: Holds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion: Option<Deletion>,
    /// The key hash of the last deletion that was undone. A set-deletion
    /// call that carries it again is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_deletion: Option<String>,
    /// The `deletion.seq` of the last deletion that was undone: an undo
    /// that names it again is answered without a record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_deletion_seq: Option<u64>,
    #[serde(default)]
    pub restoring: Vec<Restoring>,
    /// Per unit, the time before which no restore of it may land (plus the
    /// margin the unit adds): raised by the move's step 8(b1) to the
    /// unit's `lifted_at`, by every exit that empties the unit, and by the
    /// restore tool before a `restore`. Never lowered, never removed. A
    /// unit restore cannot take it back, since it is not in the unit.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub move_floors: BTreeMap<u32, UnixMs>,
    #[serde(default)]
    pub synthetic: bool,
    /// The tenant's key has an offline escrow copy: a shred waits and
    /// pages until an operator record clears this, naming the destruction
    /// of every escrow copy.
    #[serde(default)]
    pub escrow_offline: bool,
    /// The record that cleared `escrow_offline` names the SHA-256 of
    /// every escrow copy that was destroyed (lowercase hex).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escrow_destroyed: Vec<String>,
    /// Limits by name, in their own unit (bytes, requests). A name that
    /// is absent has no limit.
    #[serde(default)]
    pub limits: BTreeMap<String, u64>,
    /// The request rate class and cold-read weight.
    #[serde(default)]
    pub rate_json: serde_json::Map<String, serde_json::Value>,
    /// Feature flags. Unknown flags are ignored; a missing flag is off.
    #[serde(default)]
    pub features_json: serde_json::Map<String, serde_json::Value>,
    /// The unit numbers of the tenant. Unit 0 is the root unit.
    #[serde(default)]
    pub units: Vec<u32>,
    #[serde(default)]
    pub placements: Vec<Placement>,
    /// The highest move epoch any placement ever had. A bucket that is
    /// placed anew or moves takes an epoch above it, so an epoch never
    /// comes back, also for a placement that was dropped and added again.
    pub max_move_epoch: u64,
    /// The bucket this record creates, with its creator (this record
    /// only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_created: Option<BucketCreated>,
    /// The highest creator-grant seq a bucket of this tenant was created
    /// under. A new bucket needs a higher one, so a derived id never
    /// comes back, also after its bucket was dropped.
    #[serde(default)]
    pub last_grant_seq: u64,
    /// The owner's moved buckets this record places (this record only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buckets_moved_in: Option<BucketsMovedIn>,
    /// Set by the record that places moved buckets, cleared by the one
    /// that removes them; carried in between.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved_in: Option<MovedIn>,
    /// The placements an exit of the move removes, and the tenant-0 seq
    /// that admitted it (this record only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buckets_unplaced: Option<BucketsMovedIn>,
    /// The `restoring` entry this record lifts (this record only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifted: Option<Lifted>,
    /// The tenant key version in force; 0 for tenant 0, which has none.
    pub tk_version: u32,
    /// The key check value of every committed tenant key version, in
    /// lowercase hex: a load takes only the key with this value.
    #[serde(default)]
    pub key_checks: BTreeMap<u32, String>,
    /// An open rotation claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotating_to: Option<u32>,
    /// The highest tenant key version ever claimed, voided claims
    /// included: a version is never claimed twice.
    pub highest_claimed: u32,
    /// Fixed in the first record and repeated in every later one.
    pub jurisdiction: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_hint: Option<String>,
    /// Tenant 0 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_zero: Option<TenantZero>,
}

/// The private part of a tenant record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPrivate {
    pub v: u32,
    /// The workspace this tenant is bound to, opaque to storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// The name and wrapped key of the bucket that this record creates
    /// (this record only, beside the door's `bucket_created`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_created: Option<BucketSecrets>,
}

/// A tenant record: the door part and the private part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantRecord {
    pub door: TenantDoor,
    pub private: TenantPrivate,
}

/// A tenant's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantState {
    Provisioning,
    Active,
    Suspended(HoldMode),
    Deleting,
    Shredding,
    Shredded,
}

impl TenantState {
    pub fn name(self) -> &'static str {
        match self {
            TenantState::Provisioning => "provisioning",
            TenantState::Active => "active",
            TenantState::Suspended(_) => "suspended",
            TenantState::Deleting => "deleting",
            TenantState::Shredding => "shredding",
            TenantState::Shredded => "shredded",
        }
    }
}

/// What a state gives an S3 request on one unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S3Access {
    /// Everything the grant allows.
    Full,
    /// Reads only.
    ReadOnly,
    /// `403 AccountProblem`, after the signature verifies.
    AccountProblem,
    /// `503`.
    Unavailable,
}

impl TenantDoor {
    /// The state, derived from the lifecycle, the holds and the deletion.
    pub fn state(&self) -> TenantState {
        match self.lifecycle {
            Lifecycle::Provisioning => TenantState::Provisioning,
            Lifecycle::Shredding => TenantState::Shredding,
            Lifecycle::Shredded => TenantState::Shredded,
            Lifecycle::Live => match (&self.deletion, self.holds.mode()) {
                (Some(_), _) => TenantState::Deleting,
                (None, Some(mode)) => TenantState::Suspended(mode),
                (None, None) => TenantState::Active,
            },
        }
    }

    /// The `restoring` entry of `unit`, if any.
    pub fn restoring_entry(&self, unit: u32) -> Option<&Restoring> {
        self.restoring.iter().find(|r| r.unit == unit)
    }

    /// What an S3 request on `unit` gets. A unit that is being restored
    /// answers `503` whatever the state is.
    pub fn s3_access(&self, unit: u32) -> S3Access {
        if self.restoring_entry(unit).is_some() {
            return S3Access::Unavailable;
        }
        match self.state() {
            TenantState::Provisioning => S3Access::Unavailable,
            TenantState::Active => S3Access::Full,
            TenantState::Suspended(HoldMode::ReadOnly) => S3Access::ReadOnly,
            TenantState::Suspended(HoldMode::Locked)
            | TenantState::Deleting
            | TenantState::Shredding
            | TenantState::Shredded => S3Access::AccountProblem,
        }
    }

    /// The actor classes of the holds that stand, for the answer of every
    /// hold or deletion call.
    pub fn hold_classes(&self) -> Vec<ActorClass> {
        let mut out = Vec::new();
        if self.holds.billing.is_some() {
            out.push(ActorClass::Billing);
        }
        if self.holds.operator.is_some() {
            out.push(ActorClass::Operator);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn door() -> TenantDoor {
        TenantDoor {
            v: RECORD_FORMAT,
            tenant: Tenant::parse("t_00000000000000a1").unwrap(),
            seq: 1,
            written_at: UnixMs(1),
            created_at: UnixMs(1),
            lifecycle: Lifecycle::Live,
            holds: Holds::default(),
            deletion: None,
            undone_deletion: None,
            undone_deletion_seq: None,
            restoring: vec![],
            move_floors: BTreeMap::new(),
            synthetic: false,
            escrow_offline: false,
            escrow_destroyed: vec![],
            limits: BTreeMap::new(),
            rate_json: Default::default(),
            features_json: Default::default(),
            units: vec![0],
            placements: vec![],
            max_move_epoch: 0,
            last_grant_seq: 0,
            buckets_moved_in: None,
            moved_in: None,
            buckets_unplaced: None,
            lifted: None,
            bucket_created: None,
            tk_version: 1,
            key_checks: BTreeMap::from([(1, "00".repeat(16))]),
            rotating_to: None,
            highest_claimed: 1,
            jurisdiction: "us".into(),
            location_hint: None,
            tenant_zero: None,
        }
    }

    #[test]
    fn tenant_ids() {
        assert!(Tenant::zero().is_zero());
        assert_eq!(Tenant::zero().as_str(), "t_0000000000000000");
        assert!(Tenant::parse("t_0123456789abcdef").is_some());
        for bad in [
            "t_0123456789ABCDEF",
            "t_0123456789abcde",
            "t_0123456789abcdef0",
            "x_0123456789abcdef",
            "t_0123456789abcdeg",
            "",
            "t_",
        ] {
            assert!(Tenant::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(Tenant::from_random([0; 8]), None);
        let t = Tenant::from_random([0xde, 0xad, 0, 1, 2, 3, 4, 0xff]).unwrap();
        assert_eq!(t.as_str(), "t_dead0001020304ff");
        assert!(!t.is_zero());
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"t_dead0001020304ff\"");
        assert!(serde_json::from_str::<Tenant>("\"t_DEAD0001020304ff\"").is_err());
        // Tenant 0 is its own variant; every other id is the crate's
        // managed id, and both sort by the id.
        assert_eq!(Tenant::parse("t_0000000000000000"), Some(Tenant::Zero));
        assert_eq!(t.managed().map(|m| m.as_str()), Some("t_dead0001020304ff"));
        assert_eq!(Tenant::zero().managed(), None);
        assert!(Tenant::zero() < t);
        let back: Tenant = serde_json::from_str("\"t_0000000000000000\"").unwrap();
        assert!(back.is_zero());
    }

    #[test]
    fn the_state_is_derived_from_holds_and_deletion() {
        let mut d = door();
        assert_eq!(d.state(), TenantState::Active);
        assert_eq!(d.s3_access(0), S3Access::Full);

        d.holds.billing = Some(BillingHold {
            mode: HoldMode::ReadOnly,
            since: UnixMs(3),
        });
        assert_eq!(d.state(), TenantState::Suspended(HoldMode::ReadOnly));
        assert_eq!(d.s3_access(0), S3Access::ReadOnly);

        // The strictest hold is in force.
        d.holds.operator = Some(OperatorHold {
            mode: HoldMode::Locked,
            reason: OperatorReason::Security,
            preserve: false,
            since: UnixMs(5),
        });
        assert_eq!(d.state(), TenantState::Suspended(HoldMode::Locked));
        // The suspension holds since the hold whose mode is in force.
        assert_eq!(d.holds.since(), Some(UnixMs(5)));
        assert_eq!(d.s3_access(0), S3Access::AccountProblem);
        assert_eq!(
            d.hold_classes(),
            vec![ActorClass::Billing, ActorClass::Operator]
        );

        // A deletion wins over the holds, and keeps them.
        d.deletion = Some(Deletion {
            seq: 2,
            requested_at: UnixMs(2),
            shred_due_at: UnixMs(10),
            reason: DeletionReason::CustomerRequest,
            actor: ActorClass::Customer,
            key_hash: "00".into(),
        });
        assert_eq!(d.state(), TenantState::Deleting);
        assert_eq!(d.s3_access(0), S3Access::AccountProblem);
        assert!(d.holds.operator.is_some());

        d.lifecycle = Lifecycle::Provisioning;
        assert_eq!(d.state(), TenantState::Provisioning);
        assert_eq!(d.s3_access(0), S3Access::Unavailable);
    }

    #[test]
    fn a_unit_being_restored_answers_503() {
        let mut d = door();
        d.units = vec![0, 1];
        d.restoring.push(Restoring {
            unit: 1,
            since_seq: 4,
        });
        assert_eq!(d.s3_access(0), S3Access::Full);
        assert_eq!(d.s3_access(1), S3Access::Unavailable);
    }

    #[test]
    fn the_door_part_refuses_unknown_fields() {
        let mut value = serde_json::to_value(door()).unwrap();
        assert_eq!(
            serde_json::from_value::<TenantDoor>(value.clone()).unwrap(),
            door()
        );
        value
            .as_object_mut()
            .unwrap()
            .insert("shard".into(), serde_json::json!(1));
        assert!(serde_json::from_value::<TenantDoor>(value).is_err());
    }

    #[test]
    fn the_selector_has_a_fixed_form() {
        let z = TenantZero {
            selector: Selector::Moved,
            moved: Some(Move {
                to: Tenant::parse("t_00000000000000a1").unwrap(),
                catalogue_id_frozen: "main".into(),
                stamp: Some(7),
                flipped_at: Some(UnixMs(5)),
                levelled_to: None,
            }),
            undo_stamp: None,
            catalogue_id: None,
            frozen_catalogues: vec!["main".into()],
            flips: 1,
        };
        let json = serde_json::to_value(&z).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "selector": "moved",
                "move": {"to": "t_00000000000000a1", "catalogue_id_frozen": "main", "stamp": 7, "flipped_at": 5},
                "frozen_catalogues": ["main"],
                "flips": 1
            })
        );
        assert!(!z.undone());
        let undone = TenantZero {
            selector: Selector::D1,
            undo_stamp: Some(8),
            catalogue_id: Some("main2".into()),
            ..z.clone()
        };
        assert!(undone.undone());
        let not_above = TenantZero {
            undo_stamp: Some(7),
            ..undone.clone()
        };
        assert!(!not_above.undone());
        for (sel, name) in [
            (Selector::D1, "d1"),
            (Selector::Moving, "moving"),
            (Selector::Moved, "moved"),
            (Selector::Retired, "retired"),
        ] {
            assert_eq!(serde_json::to_value(sel).unwrap(), serde_json::json!(name));
            assert_eq!(sel.as_str(), name);
        }
    }
}
