//! Which tenant record may follow which.
//!
//! The tenant chain is the arbiter. A writer reads the head, validates its
//! change against **that record** with [`next`], builds the new record
//! from it, and writes exactly the next seq. On a lost put it reads the
//! head and validates again. A change that is no longer valid is refused
//! and writes nothing; the loser of a race is never written at seq + 1.
//!
//! [`next`] is a pure function of the head, the change, the actor and the
//! clock. It answers one of three things:
//!
//! - [`Outcome::Next`]: the record to write at `head.seq + 1`;
//! - [`Outcome::Unchanged`]: the head already carries the change, so no
//!   record is written (lifting a hold that is not there, setting
//!   `restoring` again for the same unit). The caller still applies the
//!   head to its stores before it answers `200`;
//! - a [`Refusal`]: `403` for a field the actor may not change, `409` for
//!   a change the head does not admit, `400` for a malformed change.
//!
//! # Who may
//!
//! The actor is the plane that made the call, from its token
//! ([`Actor`]), and the tools and jobs that have records of their own.
//! Storage decides holds and deletions from the actor class and the
//! record; Kofra's own rules are a second line.

use std::collections::BTreeMap;

use super::record::{
    ActorClass, BillingHold, BucketCreated, Deletion, DeletionReason, HoldMode, Holds, Lifecycle,
    Move, OperatorHold, OperatorReason, Placement, Restoring, Selector, TenantDoor, TenantId,
    TenantPrivate, TenantRecord, TenantZero, RECORD_FORMAT,
};
use crate::types::UnixMs;

/// The shortest hold period of a deletion by the billing token: 60 days,
/// less 1 hour of tolerance.
pub const BILLING_DELETE_MIN_MS: i64 = 60 * 24 * 3_600_000 - 3_600_000;

/// The shortest hold period of a deletion by the customer plane: 7 days.
/// A shorter one is a delete-now, which is the operator's alone, and the
/// caps count a hold below this one as a delete-now. A caller that
/// computes the due date adds its own margin for the time to this check.
pub const CUSTOMER_DELETE_MIN_MS: i64 = 7 * 24 * 3_600_000;

/// The shortest hold period of any deletion, the operator's delete-now:
/// 1 hour, less 1 minute of tolerance.
pub const OPERATOR_DELETE_MIN_MS: i64 = 3_600_000 - 60_000;

/// The length of a tenant key's check value, in bytes.
pub const KEY_CHECK_LEN: usize = 8;

/// How long tenant 0 stays `moved` before it can be retired: 30 days.
pub const RETIRE_AFTER_MS: i64 = 30 * 24 * 3_600_000;

/// Who makes a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    /// The standard or the confirmed `kofra-api` token. Which scopes each
    /// token carries (a limit change or a delete request needs the
    /// confirmed one) is checked by the management entrypoint before a
    /// change reaches the chain; the chain checks the actor class.
    Customer,
    /// The billing token.
    Billing,
    /// The operator plane.
    Operator,
    /// Tenant creation (its records up to `active`).
    TenantCreation,
    /// The key rotation job.
    RotationJob,
    /// The shred job.
    ShredJob,
    /// The restore tool, after the gate.
    RestoreTool,
    /// The tool of the move of tenant 0's data: its window, flip,
    /// give-up, undo and retirement.
    MoveTool,
}

impl Actor {
    /// The actor class a record names for this actor, if it has one.
    pub fn class(self) -> Option<ActorClass> {
        match self {
            Actor::Customer => Some(ActorClass::Customer),
            Actor::Billing => Some(ActorClass::Billing),
            Actor::Operator => Some(ActorClass::Operator),
            _ => None,
        }
    }
}

/// An `operator` hold as a call asks for it. `preserve` unset takes the
/// default of the reason; the record carries the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorHoldRequest {
    pub mode: HoldMode,
    pub reason: OperatorReason,
    pub preserve: Option<bool>,
}

/// A change to a tenant's chain.
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    /// The first record of a new tenant: `provisioning`, root unit 0.
    Create {
        jurisdiction: String,
        location_hint: Option<String>,
        synthetic: bool,
        limits: BTreeMap<String, u64>,
        rate_json: serde_json::Map<String, serde_json::Value>,
        features_json: serde_json::Map<String, serde_json::Value>,
    },
    /// The first record of tenant 0: live, on today's D1, no unit.
    CreateTenantZero { jurisdiction: String },
    /// Claim the next tenant key version.
    ClaimKeyVersion { version: u32 },
    /// Void the open claim `version` (its copies disagree) and claim
    /// `version + 1` in the same record.
    VoidKeyClaim { version: u32 },
    /// Commit the open claim, pinning the check value of its key.
    CommitKeyVersion {
        version: u32,
        kcv: [u8; KEY_CHECK_LEN],
    },
    /// `provisioning` to `active`: the last step of tenant creation. It
    /// binds the workspace: the first record whose private part is sealed
    /// under the tenant's own key.
    Activate { external_ref: Option<String> },
    /// Place, change (`Some`) or lift (`None`) the `billing` hold.
    SetBillingHold { mode: Option<HoldMode> },
    /// Place, change (`Some`) or lift (`None`) the `operator` hold.
    SetOperatorHold { hold: Option<OperatorHoldRequest> },
    /// Set a deletion. `key_hash` is the SHA-256 of the call's
    /// `Idempotency-Key`, lowercase hex.
    SetDeletion {
        shred_due_at: UnixMs,
        reason: DeletionReason,
        key_hash: String,
    },
    /// Clear the deletion and nothing else.
    UndoDeletion,
    /// Replace the limits, and the rate class when `Some`. The floor of a
    /// limit set by the billing token (the free allowance) is a registry
    /// value, checked by the management entrypoint with the registry.
    SetLimits {
        limits: BTreeMap<String, u64>,
        rate_json: Option<serde_json::Map<String, serde_json::Value>>,
    },
    /// Replace the feature flags.
    SetFeatures {
        features_json: serde_json::Map<String, serde_json::Value>,
    },
    /// Replace the unit list and the bucket placements.
    SetUnits {
        units: Vec<u32>,
        placements: Vec<Placement>,
    },
    /// Set `restoring` for one unit.
    SetRestoring { unit: u32 },
    /// Lift the `restoring` entry of `unit` whose `since_seq` is
    /// `since_seq`.
    LiftRestoring { unit: u32, since_seq: u64 },
    /// Create a bucket on a unit of the tenant. `creator` names the acting
    /// principal, as history; its grant on the bucket is a key-chain record
    /// written first.
    CreateBucket {
        bucket: String,
        unit: u32,
        creator: String,
    },
    /// Remove a bucket's placement.
    DropBucket { bucket: String },
    /// Mark the tenant's key as escrowed offline.
    SetEscrowOffline,
    /// Clear the offline escrow mark. The operator names the SHA-256 of
    /// every escrow copy it destroyed; nothing else clears it.
    ClearEscrowOffline { destroyed: Vec<String> },
    /// Tenant 0: open the move's window into tenant `to`.
    StartMove {
        to: TenantId,
        catalogue_id_frozen: String,
    },
    /// Tenant 0: the flip, at the legacy stamp's counter `stamp`.
    FlipMove { stamp: u64 },
    /// Tenant 0: give the move up before the flip.
    GiveUpMove,
    /// Tenant 0: the undo of a flipped move, onto a fresh catalogue
    /// `catalogue_id` (the reverse move).
    UndoMove {
        undo_stamp: u64,
        catalogue_id: String,
    },
    /// Tenant 0: the undo of a flipped move onto the catalogue it froze
    /// (the fallback route), after the tool levelled that catalogue's
    /// stamp again.
    UndoMoveOntoFrozen {
        undo_stamp: u64,
        /// The stamp counter the tool levelled the frozen catalogue to:
        /// at or above the flip's stamp.
        levelled_to: u64,
    },
    /// Tenant 0: retired for good, 30 days after the flip.
    RetireTenantZero,
    /// `deleting`, due, to `shredding`.
    StartShred,
    /// `shredding` to the `shredded` stub.
    FinishShred,
}

/// What [`next`] decided.
// Short-lived: made and matched in one call, never stored.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// Write this record at the next seq.
    Next(TenantRecord),
    /// The head already carries the change: write nothing.
    Unchanged,
}

/// A change that is refused. It writes nothing. `code` is fixed, never
/// free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub code: &'static str,
}

const fn refuse(status: u16, code: &'static str) -> Refusal {
    Refusal { status, code }
}

/// A field this actor may not change.
const FORBIDDEN: Refusal = refuse(403, "not_allowed_for_actor");
/// The change needs a tenant that exists.
const NO_TENANT: Refusal = refuse(409, "no_tenant");
const EXISTS: Refusal = refuse(409, "tenant_exists");
const WRONG_STATE: Refusal = refuse(409, "state_does_not_allow");
const SHREDDING: Refusal = refuse(409, "tenant_shredding");
const SHREDDED: Refusal = refuse(409, "tenant_shredded");
const RESTORING: Refusal = refuse(409, "restoring");
const DELETING: Refusal = refuse(409, "already_deleting");
const NOT_DELETING: Refusal = refuse(409, "not_deleting");
const REPLAYED: Refusal = refuse(409, "deletion_replayed");
const NOT_DUE: Refusal = refuse(409, "shred_not_due");
const PRESERVED: Refusal = refuse(409, "preserved_by_hold");
const CLAIM_OPEN: Refusal = refuse(409, "claim_open");
const NO_CLAIM: Refusal = refuse(409, "no_claim");
const VERSION: Refusal = refuse(409, "key_version");
const NOT_READY: Refusal = refuse(409, "not_ready");
const UNIT_NOT_LISTED: Refusal = refuse(409, "unit_not_listed");
const ENTRY_GONE: Refusal = refuse(409, "restoring_entry_gone");
const TENANT_ZERO: Refusal = refuse(409, "tenant_zero");
const NO_BILLING_HOLD: Refusal = refuse(403, "no_billing_hold");
const HOLD_PERIOD: Refusal = refuse(403, "hold_period_too_short");
const INVALID: Refusal = refuse(400, "invalid_change");
const KEY_CHECK: Refusal = refuse(409, "key_check_mismatch");
const ESCROWED: Refusal = refuse(409, "escrow_offline");
const RETIRED: Refusal = refuse(409, "tenant_zero_retired");
const SELECTOR: Refusal = refuse(409, "selector_does_not_allow");
const NOT_TENANT_ZERO: Refusal = refuse(409, "not_tenant_zero");
const BUCKET_EXISTS: Refusal = refuse(409, "bucket_exists");

/// Validates `change` against `head` and builds the record that follows.
/// See the [module](self).
pub fn next(
    tenant: &TenantId,
    head: Option<&TenantRecord>,
    change: &Change,
    actor: Actor,
    now: UnixMs,
) -> Result<Outcome, Refusal> {
    let Some(head) = head else {
        return first(tenant, change, actor, now);
    };
    if &head.door.tenant != tenant {
        return Err(INVALID);
    }
    match head.door.lifecycle {
        // The shred job repeats its last step after a lost answer.
        Lifecycle::Shredded if *change == Change::FinishShred && actor == Actor::ShredJob => {
            return Ok(Outcome::Unchanged)
        }
        Lifecycle::Shredded => return Err(SHREDDED),
        Lifecycle::Shredding if *change != Change::FinishShred => return Err(SHREDDING),
        _ => {}
    }
    if matches!(
        change,
        Change::Create { .. } | Change::CreateTenantZero { .. }
    ) {
        return Err(EXISTS);
    }

    let h = &head.door;
    if let Some(z) = &h.tenant_zero {
        // Retired is terminal; the tool may repeat its last step.
        if z.selector == Selector::Retired {
            return match (change, actor) {
                (Change::RetireTenantZero, Actor::MoveTool) => Ok(Outcome::Unchanged),
                _ => Err(RETIRED),
            };
        }
    }
    let mut door = h.clone();
    // Only the record that creates a bucket names it.
    door.bucket_created = None;
    let mut private = head.private.clone();

    match change {
        Change::Create { .. } | Change::CreateTenantZero { .. } => unreachable!("handled above"),

        Change::ClaimKeyVersion { version } => {
            rotation_allowed(h, actor, *version)?;
            if h.rotating_to.is_some() {
                return Err(CLAIM_OPEN);
            }
            // A claimed version is never claimed again, also one that a
            // deletion voided.
            if Some(*version) != h.highest_claimed.checked_add(1) {
                return Err(VERSION);
            }
            door.rotating_to = Some(*version);
            door.highest_claimed = *version;
        }

        Change::VoidKeyClaim { version } => {
            rotation_allowed(h, actor, *version)?;
            if h.rotating_to != Some(*version) {
                return Err(NO_CLAIM);
            }
            let next = version.checked_add(1).ok_or(VERSION)?;
            door.rotating_to = Some(next);
            door.highest_claimed = next;
        }

        Change::CommitKeyVersion { version, kcv } => {
            let kcv = hex(kcv);
            // A commit that already happened: the same key is unchanged,
            // another key is refused.
            if h.rotating_to.is_none() && h.tk_version == *version && *version > 0 {
                return match h.key_checks.get(version) == Some(&kcv) {
                    true => Ok(Outcome::Unchanged),
                    false => Err(KEY_CHECK),
                };
            }
            rotation_allowed(h, actor, *version)?;
            if h.rotating_to != Some(*version) {
                return Err(NO_CLAIM);
            }
            door.tk_version = *version;
            door.rotating_to = None;
            door.key_checks.insert(*version, kcv);
        }

        Change::Activate { external_ref } => {
            if actor != Actor::TenantCreation {
                return Err(FORBIDDEN);
            }
            if h.lifecycle != Lifecycle::Provisioning {
                return Err(WRONG_STATE);
            }
            if h.tk_version == 0
                || h.rotating_to.is_some()
                || !h.key_checks.contains_key(&h.tk_version)
            {
                return Err(NOT_READY);
            }
            door.lifecycle = Lifecycle::Live;
            private.external_ref = external_ref.clone();
        }

        Change::SetBillingHold { mode } => {
            live(h)?;
            let lifting = match (h.holds.billing, mode) {
                (_, None) => true,
                (Some(old), Some(new)) => *new < old.mode,
                (None, Some(_)) => false,
            };
            // Who may comes first: a refused actor gets its 403 also for a
            // change the head already carries.
            match actor {
                Actor::Billing => {}
                // The operator lifts or eases the billing hold; it never
                // places one.
                Actor::Operator if lifting => {}
                _ => return Err(FORBIDDEN),
            }
            if h.holds.billing.map(|b| b.mode) == *mode {
                return Ok(Outcome::Unchanged);
            }
            door.holds.billing = mode.map(|mode| BillingHold { mode });
            if mode.is_none() {
                // A record that removes the billing hold also
                // clears a deletion whose actor is billing, whoever
                // writes it.
                if let Some(d) = &h.deletion {
                    if d.actor == ActorClass::Billing {
                        door.undone_deletion = Some(d.key_hash.clone());
                        door.deletion = None;
                    }
                }
            }
        }

        Change::SetOperatorHold { hold } => {
            live(h)?;
            if actor != Actor::Operator {
                return Err(FORBIDDEN);
            }
            let new = hold.map(|r| OperatorHold {
                mode: r.mode,
                reason: r.reason,
                preserve: r.preserve.unwrap_or(r.reason.preserves_by_default()),
            });
            if new == h.holds.operator {
                return Ok(Outcome::Unchanged);
            }
            door.holds.operator = new;
        }

        Change::SetDeletion {
            shred_due_at,
            reason,
            key_hash,
        } => {
            live(h)?;
            if !valid_key_hash(key_hash) || *shred_due_at <= now {
                return Err(INVALID);
            }
            let class = match (actor, reason) {
                (Actor::Customer, DeletionReason::CustomerRequest) => ActorClass::Customer,
                (Actor::Billing, DeletionReason::NonPayment) => ActorClass::Billing,
                (Actor::Operator, DeletionReason::Operator(_)) => ActorClass::Operator,
                _ => return Err(FORBIDDEN),
            };
            // Tenant 0 is never deleted and never shredded: it has no
            // tenant key to destroy.
            if tenant.is_zero() {
                return Err(TENANT_ZERO);
            }
            if let Some(d) = &h.deletion {
                // A retry of the call whose record landed: apply the head.
                if d.key_hash == *key_hash && d.actor == class {
                    return Ok(Outcome::Unchanged);
                }
                return Err(DELETING);
            }
            if h.undone_deletion.as_deref() == Some(key_hash.as_str()) {
                return Err(REPLAYED);
            }
            let min = match class {
                ActorClass::Customer => CUSTOMER_DELETE_MIN_MS,
                ActorClass::Billing => BILLING_DELETE_MIN_MS,
                ActorClass::Operator => OPERATOR_DELETE_MIN_MS,
            };
            if class == ActorClass::Billing && h.holds.billing.is_none() {
                return Err(NO_BILLING_HOLD);
            }
            if shred_due_at.0.saturating_sub(now.0) < min {
                return Err(HOLD_PERIOD);
            }
            door.deletion = Some(Deletion {
                shred_due_at: *shred_due_at,
                reason: *reason,
                actor: class,
                key_hash: key_hash.clone(),
            });
            // A deletion voids an open rotation claim in the same record.
            door.rotating_to = None;
        }

        Change::UndoDeletion => {
            live(h)?;
            let Some(d) = &h.deletion else {
                return Err(NOT_DELETING);
            };
            let allowed = match actor {
                Actor::Customer => d.actor == ActorClass::Customer,
                Actor::Billing => d.actor == ActorClass::Billing,
                Actor::Operator => true,
                _ => false,
            };
            if !allowed {
                return Err(FORBIDDEN);
            }
            door.undone_deletion = Some(d.key_hash.clone());
            door.deletion = None;
        }

        Change::SetLimits { limits, rate_json } => {
            live(h)?;
            if actor.class().is_none() {
                return Err(FORBIDDEN);
            }
            let rate = rate_json.as_ref().unwrap_or(&h.rate_json);
            if *limits == h.limits && *rate == h.rate_json {
                return Ok(Outcome::Unchanged);
            }
            door.limits = limits.clone();
            door.rate_json = rate.clone();
        }

        Change::SetFeatures { features_json } => {
            live(h)?;
            if h.deletion.is_some() {
                return Err(WRONG_STATE);
            }
            if actor.class().is_none() {
                return Err(FORBIDDEN);
            }
            if *features_json == h.features_json {
                return Ok(Outcome::Unchanged);
            }
            // While a unit is being restored nothing widens: a flag may be
            // turned off, never on.
            if !h.restoring.is_empty() && turns_a_flag_on(&h.features_json, features_json) {
                return Err(RESTORING);
            }
            door.features_json = features_json.clone();
        }

        Change::SetUnits { units, placements } => {
            live(h)?;
            if actor != Actor::Operator {
                return Err(FORBIDDEN);
            }
            if tenant.is_zero() {
                return Err(TENANT_ZERO);
            }
            if h.deletion.is_some() {
                return Err(WRONG_STATE);
            }
            if !h.restoring.is_empty() {
                return Err(RESTORING);
            }
            if !valid_units(units, placements)
                || !epochs_advance(&h.placements, h.max_move_epoch, placements)
            {
                return Err(INVALID);
            }
            if *units == h.units && *placements == h.placements {
                return Ok(Outcome::Unchanged);
            }
            door.units = units.clone();
            door.placements = placements.clone();
            door.max_move_epoch = placements
                .iter()
                .map(|p| p.epoch)
                .fold(h.max_move_epoch, u64::max);
        }

        Change::SetRestoring { unit } => {
            live(h)?;
            if actor != Actor::Operator {
                return Err(FORBIDDEN);
            }
            if !h.units.contains(unit) {
                return Err(UNIT_NOT_LISTED);
            }
            if h.restoring_entry(*unit).is_some() {
                // Idempotent: the entry and its since_seq stand.
                return Ok(Outcome::Unchanged);
            }
            door.restoring.push(Restoring {
                unit: *unit,
                since_seq: h.seq + 1,
            });
        }

        Change::LiftRestoring { unit, since_seq } => {
            if actor != Actor::RestoreTool {
                return Err(FORBIDDEN);
            }
            let ours = Restoring {
                unit: *unit,
                since_seq: *since_seq,
            };
            if !h.restoring.contains(&ours) {
                return Err(ENTRY_GONE);
            }
            door.restoring.retain(|r| *r != ours);
        }

        Change::CreateBucket {
            bucket,
            unit,
            creator,
        } => {
            live(h)?;
            if !matches!(actor, Actor::Customer | Actor::Operator) {
                return Err(FORBIDDEN);
            }
            if h.state() != super::record::TenantState::Active {
                return Err(WRONG_STATE);
            }
            if !h.restoring.is_empty() {
                return Err(RESTORING);
            }
            if !valid_name(bucket) || !valid_name(creator) {
                return Err(INVALID);
            }
            if !h.units.contains(unit) {
                return Err(UNIT_NOT_LISTED);
            }
            if h.placements.iter().any(|p| p.bucket == *bucket) {
                return Err(BUCKET_EXISTS);
            }
            let epoch = h.max_move_epoch.checked_add(1).ok_or(INVALID)?;
            door.placements.push(Placement {
                bucket: bucket.clone(),
                unit: *unit,
                epoch,
            });
            door.max_move_epoch = epoch;
            door.bucket_created = Some(BucketCreated {
                bucket: bucket.clone(),
                creator: creator.clone(),
            });
        }

        Change::DropBucket { bucket } => {
            live(h)?;
            if !matches!(actor, Actor::Customer | Actor::Operator) {
                return Err(FORBIDDEN);
            }
            // Like a create: only an active tenant; a hold (a preserving
            // one above all) keeps every bucket where it is.
            if h.holds.preserves() {
                return Err(PRESERVED);
            }
            if h.state() != super::record::TenantState::Active {
                return Err(WRONG_STATE);
            }
            if !h.restoring.is_empty() {
                return Err(RESTORING);
            }
            if !h.placements.iter().any(|p| p.bucket == *bucket) {
                return Ok(Outcome::Unchanged);
            }
            door.placements.retain(|p| p.bucket != *bucket);
        }

        Change::SetEscrowOffline => {
            live(h)?;
            if actor != Actor::Operator {
                return Err(FORBIDDEN);
            }
            if h.escrow_offline {
                return Ok(Outcome::Unchanged);
            }
            door.escrow_offline = true;
            door.escrow_destroyed.clear();
        }

        Change::ClearEscrowOffline { destroyed } => {
            live(h)?;
            if actor != Actor::Operator {
                return Err(FORBIDDEN);
            }
            if !h.escrow_offline {
                return Ok(Outcome::Unchanged);
            }
            if destroyed.is_empty() || !destroyed.iter().all(|d| valid_sha256(d)) {
                return Err(INVALID);
            }
            door.escrow_offline = false;
            door.escrow_destroyed = destroyed.clone();
        }

        Change::StartMove {
            to,
            catalogue_id_frozen,
        } => {
            let z = move_allowed(tenant, h, actor)?;
            if to.is_zero() || !valid_name(catalogue_id_frozen) {
                return Err(INVALID);
            }
            match z.selector {
                Selector::Moving
                    if z.moved.as_ref().is_some_and(|m| {
                        m.to == *to && m.catalogue_id_frozen == *catalogue_id_frozen
                    }) =>
                {
                    return Ok(Outcome::Unchanged)
                }
                Selector::D1 if z.moved.is_none() || z.undone() => {}
                _ => return Err(SELECTOR),
            }
            // A move freezes the catalogue that `d1` means now, and no
            // other.
            if catalogue_id_frozen != z.current_catalogue() {
                return Err(INVALID);
            }
            if !h.restoring.is_empty() {
                return Err(RESTORING);
            }
            let mut z = z.clone();
            z.selector = Selector::Moving;
            z.moved = Some(Move {
                to: to.clone(),
                catalogue_id_frozen: catalogue_id_frozen.clone(),
                stamp: None,
                flipped_at: None,
                levelled_to: None,
            });
            z.undo_stamp = None;
            if !z.frozen_catalogues.contains(catalogue_id_frozen) {
                z.frozen_catalogues.push(catalogue_id_frozen.clone());
            }
            door.tenant_zero = Some(z);
        }

        Change::FlipMove { stamp } => {
            let z = move_allowed(tenant, h, actor)?;
            let m = z.moved.as_ref().ok_or(SELECTOR)?;
            match z.selector {
                Selector::Moved if m.stamp == Some(*stamp) => return Ok(Outcome::Unchanged),
                Selector::Moving => {}
                _ => return Err(SELECTOR),
            }
            if *stamp == 0 {
                return Err(INVALID);
            }
            let mut z = z.clone();
            z.selector = Selector::Moved;
            z.flips += 1;
            if let Some(m) = z.moved.as_mut() {
                m.stamp = Some(*stamp);
                m.flipped_at = Some(now);
            }
            door.tenant_zero = Some(z);
        }

        Change::GiveUpMove => {
            let z = move_allowed(tenant, h, actor)?;
            match z.selector {
                Selector::Moving => {}
                // No window open: none yet, or the last move undone.
                Selector::D1 if z.moved.is_none() || z.undone() => return Ok(Outcome::Unchanged),
                _ => return Err(SELECTOR),
            }
            let mut z = z.clone();
            z.selector = Selector::D1;
            z.moved = None;
            door.tenant_zero = Some(z);
        }

        Change::UndoMove {
            undo_stamp,
            catalogue_id,
        } => {
            let z = move_allowed(tenant, h, actor)?;
            let m = z.moved.as_ref().ok_or(SELECTOR)?;
            match z.selector {
                Selector::D1
                    if z.undo_stamp == Some(*undo_stamp)
                        && z.catalogue_id.as_deref() == Some(catalogue_id.as_str()) =>
                {
                    return Ok(Outcome::Unchanged)
                }
                Selector::Moved => {}
                _ => return Err(SELECTOR),
            }
            // A fresh catalogue: never one a move froze, whose stamps mark
            // it as rolled back. The frozen one is the fallback route's.
            if !valid_name(catalogue_id)
                || *catalogue_id == m.catalogue_id_frozen
                || z.frozen_catalogues.contains(catalogue_id)
            {
                return Err(INVALID);
            }
            if !m.stamp.is_some_and(|stamp| *undo_stamp > stamp) {
                return Err(INVALID);
            }
            let mut z = z.clone();
            z.selector = Selector::D1;
            z.undo_stamp = Some(*undo_stamp);
            z.catalogue_id = Some(catalogue_id.clone());
            door.tenant_zero = Some(z);
        }

        Change::UndoMoveOntoFrozen {
            undo_stamp,
            levelled_to,
        } => {
            let z = move_allowed(tenant, h, actor)?;
            let m = z.moved.as_ref().ok_or(SELECTOR)?;
            let frozen = m.catalogue_id_frozen.clone();
            match z.selector {
                Selector::D1
                    if z.undo_stamp == Some(*undo_stamp)
                        && z.catalogue_id.as_deref() == Some(frozen.as_str())
                        && m.levelled_to == Some(*levelled_to) =>
                {
                    return Ok(Outcome::Unchanged)
                }
                Selector::Moved => {}
                _ => return Err(SELECTOR),
            }
            let Some(stamp) = m.stamp else {
                return Err(SELECTOR);
            };
            if *undo_stamp <= stamp || *levelled_to < stamp {
                return Err(INVALID);
            }
            let mut z = z.clone();
            z.selector = Selector::D1;
            z.undo_stamp = Some(*undo_stamp);
            z.catalogue_id = Some(frozen);
            if let Some(m) = z.moved.as_mut() {
                m.levelled_to = Some(*levelled_to);
            }
            door.tenant_zero = Some(z);
        }

        Change::RetireTenantZero => {
            let z = move_allowed(tenant, h, actor)?;
            let flipped = z.moved.as_ref().and_then(|m| m.flipped_at);
            if z.selector != Selector::Moved {
                return Err(SELECTOR);
            }
            if !flipped.is_some_and(|at| now.0 >= at.0.saturating_add(RETIRE_AFTER_MS)) {
                return Err(NOT_DUE);
            }
            let mut z = z.clone();
            z.selector = Selector::Retired;
            door.tenant_zero = Some(z);
        }

        Change::StartShred => {
            if actor != Actor::ShredJob {
                return Err(FORBIDDEN);
            }
            if h.lifecycle != Lifecycle::Live {
                return Err(WRONG_STATE);
            }
            if tenant.is_zero() {
                return Err(TENANT_ZERO);
            }
            let Some(d) = &h.deletion else {
                return Err(NOT_DELETING);
            };
            if d.shred_due_at > now {
                return Err(NOT_DUE);
            }
            // Both wait and page; neither stops the clock.
            if !h.restoring.is_empty() {
                return Err(RESTORING);
            }
            if h.holds.preserves() {
                return Err(PRESERVED);
            }
            if h.escrow_offline {
                return Err(ESCROWED);
            }
            door.lifecycle = Lifecycle::Shredding;
        }

        Change::FinishShred => {
            if actor != Actor::ShredJob {
                return Err(FORBIDDEN);
            }
            if h.lifecycle != Lifecycle::Shredding {
                return Err(WRONG_STATE);
            }
            door = shredded_stub(h);
            private = TenantPrivate {
                v: RECORD_FORMAT,
                external_ref: None,
            };
        }
    }

    door.seq = h.seq + 1;
    door.written_at = now;
    Ok(Outcome::Next(TenantRecord { door, private }))
}

/// The first record of a tenant.
fn first(
    tenant: &TenantId,
    change: &Change,
    actor: Actor,
    now: UnixMs,
) -> Result<Outcome, Refusal> {
    let base = |lifecycle, jurisdiction: &str| TenantDoor {
        v: RECORD_FORMAT,
        tenant: tenant.clone(),
        seq: 1,
        written_at: now,
        lifecycle,
        holds: Holds::default(),
        deletion: None,
        undone_deletion: None,
        restoring: vec![],
        synthetic: false,
        escrow_offline: false,
        escrow_destroyed: vec![],
        limits: BTreeMap::new(),
        rate_json: Default::default(),
        features_json: Default::default(),
        units: vec![],
        placements: vec![],
        max_move_epoch: 0,
        bucket_created: None,
        tk_version: 0,
        key_checks: BTreeMap::new(),
        rotating_to: None,
        highest_claimed: 0,
        jurisdiction: jurisdiction.to_string(),
        location_hint: None,
        tenant_zero: None,
    };
    match change {
        Change::Create {
            jurisdiction,
            location_hint,
            synthetic,
            limits,
            rate_json,
            features_json,
        } => {
            if actor != Actor::TenantCreation {
                return Err(FORBIDDEN);
            }
            if tenant.is_zero() {
                return Err(TENANT_ZERO);
            }
            if !valid_jurisdiction(jurisdiction) {
                return Err(INVALID);
            }
            let mut door = base(Lifecycle::Provisioning, jurisdiction);
            door.location_hint = location_hint.clone();
            door.synthetic = *synthetic;
            door.limits = limits.clone();
            door.rate_json = rate_json.clone();
            door.features_json = features_json.clone();
            // The record that first lists the root unit is its birth record.
            door.units = vec![0];
            Ok(Outcome::Next(TenantRecord {
                door,
                // No tenant key exists yet, so the private part is empty
                // until the record that activates the tenant.
                private: TenantPrivate {
                    v: RECORD_FORMAT,
                    external_ref: None,
                },
            }))
        }
        Change::CreateTenantZero { jurisdiction } => {
            if actor != Actor::Operator {
                return Err(FORBIDDEN);
            }
            if !tenant.is_zero() {
                return Err(INVALID);
            }
            if !valid_jurisdiction(jurisdiction) {
                return Err(INVALID);
            }
            let mut door = base(Lifecycle::Live, jurisdiction);
            door.tenant_zero = Some(TenantZero {
                selector: Selector::D1,
                moved: None,
                undo_stamp: None,
                catalogue_id: None,
                frozen_catalogues: vec![],
                flips: 0,
            });
            Ok(Outcome::Next(TenantRecord {
                door,
                private: TenantPrivate {
                    v: RECORD_FORMAT,
                    external_ref: None,
                },
            }))
        }
        _ => Err(NO_TENANT),
    }
}

/// The states in which holds, deletions and limits change: a live tenant.
fn live(h: &TenantDoor) -> Result<(), Refusal> {
    match h.lifecycle {
        Lifecycle::Live => Ok(()),
        Lifecycle::Provisioning => Err(WRONG_STATE),
        Lifecycle::Shredding => Err(SHREDDING),
        Lifecycle::Shredded => Err(SHREDDED),
    }
}

/// A rotation claim or commit: `provisioning`, `active` or `suspended`,
/// never with `restoring` set, never for tenant 0. Tenant creation claims
/// and commits version 1 only.
fn rotation_allowed(h: &TenantDoor, actor: Actor, _version: u32) -> Result<(), Refusal> {
    // Tenant creation runs the claims of a provisioning tenant (its first
    // version, and the next ones if a claim is voided); the rotation job
    // those of a live one.
    match (actor, h.lifecycle) {
        (Actor::TenantCreation, Lifecycle::Provisioning)
        | (Actor::RotationJob, Lifecycle::Live) => {}
        (Actor::TenantCreation | Actor::RotationJob, _) => return Err(WRONG_STATE),
        _ => return Err(FORBIDDEN),
    }
    if h.tenant.is_zero() {
        return Err(TENANT_ZERO);
    }
    if h.deletion.is_some() {
        return Err(WRONG_STATE);
    }
    if !h.restoring.is_empty() {
        return Err(RESTORING);
    }
    Ok(())
}

/// The move tool on tenant 0's record.
fn move_allowed<'a>(
    tenant: &TenantId,
    h: &'a TenantDoor,
    actor: Actor,
) -> Result<&'a TenantZero, Refusal> {
    if actor != Actor::MoveTool {
        return Err(FORBIDDEN);
    }
    if !tenant.is_zero() {
        return Err(NOT_TENANT_ZERO);
    }
    h.tenant_zero.as_ref().ok_or(INVALID)
}

/// Whether `new` turns on a flag that `old` did not have on: a value that
/// changed to anything but `false` or `null`. A missing flag is off.
fn turns_a_flag_on(
    old: &serde_json::Map<String, serde_json::Value>,
    new: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let off = |v: Option<&serde_json::Value>| {
        matches!(
            v,
            None | Some(serde_json::Value::Null) | Some(serde_json::Value::Bool(false))
        )
    };
    new.iter()
        .any(|(k, v)| old.get(k) != Some(v) && !off(Some(v)))
}

fn valid_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A bucket id, a principal id or a catalogue id: 1 to 128 bytes of
/// ASCII letters, digits, `_` and `-`.
fn valid_name(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What stays of a shredded tenant: its id, seq and date, and the facts
/// that hold no name (jurisdiction, the last key version).
fn shredded_stub(h: &TenantDoor) -> TenantDoor {
    TenantDoor {
        v: RECORD_FORMAT,
        tenant: h.tenant.clone(),
        seq: h.seq,
        written_at: h.written_at,
        lifecycle: Lifecycle::Shredded,
        holds: Holds::default(),
        deletion: None,
        undone_deletion: None,
        restoring: vec![],
        synthetic: h.synthetic,
        escrow_offline: false,
        escrow_destroyed: vec![],
        limits: BTreeMap::new(),
        rate_json: Default::default(),
        features_json: Default::default(),
        units: vec![],
        placements: vec![],
        max_move_epoch: h.max_move_epoch,
        bucket_created: None,
        tk_version: h.tk_version,
        key_checks: BTreeMap::new(),
        rotating_to: None,
        highest_claimed: h.highest_claimed,
        jurisdiction: h.jurisdiction.clone(),
        location_hint: None,
        tenant_zero: None,
    }
}

fn valid_key_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_jurisdiction(j: &str) -> bool {
    (1..=16).contains(&j.len()) && j.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
}

/// The root unit is listed, units are strictly ascending, and every
/// placement names a listed unit, each bucket once.
fn valid_units(units: &[u32], placements: &[Placement]) -> bool {
    let ascending = units.windows(2).all(|w| w[0] < w[1]);
    let mut buckets: Vec<&str> = placements.iter().map(|p| p.bucket.as_str()).collect();
    buckets.sort_unstable();
    let unique = buckets.windows(2).all(|w| w[0] != w[1]);
    units.first() == Some(&0)
        && ascending
        && unique
        && placements
            .iter()
            .all(|p| units.contains(&p.unit) && !p.bucket.is_empty())
}

/// A bucket that stays where it is keeps its move epoch; one that is
/// placed anew or changes unit takes the epoch right above every epoch the
/// tenant ever had. The epoch is what fences a stale route, so it never
/// comes back, and no change can raise it beyond the next one.
fn epochs_advance(old: &[Placement], max_epoch: u64, new: &[Placement]) -> bool {
    new.iter()
        .all(|p| match old.iter().find(|o| o.bucket == p.bucket) {
            Some(o) if o.unit == p.unit => p.epoch == o.epoch,
            _ => Some(p.epoch) == max_epoch.checked_add(1),
        })
}

/// The order in which a change reaches the stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOrder {
    /// Record, root unit, other units, directory.
    Closing,
    /// Record, directory, root unit, other units.
    Opening,
}

/// Classifies the step from `prev` to `next`. A record that closes any
/// door is closing, even when it also opens one.
pub fn write_order(prev: Option<&TenantDoor>, next: &TenantDoor) -> WriteOrder {
    let Some(prev) = prev else {
        return WriteOrder::Opening;
    };
    let stricter_hold = |old: Option<HoldMode>, new: Option<HoldMode>| match (old, new) {
        (None, Some(_)) => true,
        (Some(o), Some(n)) => n > o,
        _ => false,
    };
    let preserve_on = !prev.holds.preserves() && next.holds.preserves();
    let operator_reason_changed = matches!(
        (prev.holds.operator, next.holds.operator),
        (Some(o), Some(n)) if o.reason != n.reason
    );
    let limit_lowered = next
        .limits
        .iter()
        .any(|(k, v)| prev.limits.get(k).is_none_or(|old| v < old));
    let restoring_added = next.restoring.iter().any(|r| !prev.restoring.contains(r));
    // A bucket that is dropped, or moves to another unit, closes the way
    // in to where it was.
    let placement_left = prev.placements.iter().any(|old| {
        !next
            .placements
            .iter()
            .any(|p| p.bucket == old.bucket && p.unit == old.unit)
    });
    let closing = stricter_hold(
        prev.holds.billing.map(|h| h.mode),
        next.holds.billing.map(|h| h.mode),
    ) || stricter_hold(
        prev.holds.operator.map(|h| h.mode),
        next.holds.operator.map(|h| h.mode),
    ) || preserve_on
        || operator_reason_changed
        || (prev.deletion.is_none() && next.deletion.is_some())
        || limit_lowered
        || restoring_added
        || placement_left
        || (prev.lifecycle != next.lifecycle
            && matches!(next.lifecycle, Lifecycle::Shredding | Lifecycle::Shredded))
        // A flag or a rate class cannot be ranked, and tenant 0's
        // selector closes its catalogue: any change of them closes.
        || prev.rate_json != next.rate_json
        || prev.features_json != next.features_json
        || prev.tenant_zero != next.tenant_zero;
    match closing {
        true => WriteOrder::Closing,
        false => WriteOrder::Opening,
    }
}

#[cfg(test)]
mod tests;
