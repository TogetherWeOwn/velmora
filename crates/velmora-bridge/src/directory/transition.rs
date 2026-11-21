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
    ActorClass, BillingHold, Deletion, DeletionReason, HoldMode, Holds, Lifecycle, OperatorHold,
    OperatorReason, Placement, Restoring, Selector, TenantDoor, TenantId, TenantPrivate,
    TenantRecord, TenantZero, RECORD_FORMAT,
};
use crate::types::UnixMs;

/// The shortest hold period of a deletion by the billing token: 60 days,
/// less 1 hour of tolerance.
pub const BILLING_DELETE_MIN_MS: i64 = 60 * 24 * 3_600_000 - 3_600_000;

/// Who makes a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    /// The standard or the confirmed `kofra-api` token.
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
        external_ref: Option<String>,
    },
    /// The first record of tenant 0: live, on today's D1, no unit.
    CreateTenantZero { jurisdiction: String },
    /// Claim the next tenant key version.
    ClaimKeyVersion { version: u32 },
    /// Commit the open claim.
    CommitKeyVersion { version: u32 },
    /// `provisioning` to `active`: the last step of tenant creation.
    Activate,
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
    /// Replace the limits, and the rate class when `Some`.
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
    let mut door = h.clone();
    let mut private = head.private.clone();

    match change {
        Change::Create { .. } | Change::CreateTenantZero { .. } => unreachable!("handled above"),

        Change::ClaimKeyVersion { version } => {
            rotation_allowed(h, actor, *version)?;
            if h.rotating_to.is_some() {
                return Err(CLAIM_OPEN);
            }
            if Some(*version) != h.tk_version.checked_add(1) {
                return Err(VERSION);
            }
            door.rotating_to = Some(*version);
        }

        Change::CommitKeyVersion { version } => {
            rotation_allowed(h, actor, *version)?;
            if h.rotating_to != Some(*version) {
                return Err(NO_CLAIM);
            }
            door.tk_version = *version;
            door.rotating_to = None;
        }

        Change::Activate => {
            if actor != Actor::TenantCreation {
                return Err(FORBIDDEN);
            }
            if h.lifecycle != Lifecycle::Provisioning {
                return Err(WRONG_STATE);
            }
            if h.tk_version == 0 || h.rotating_to.is_some() {
                return Err(NOT_READY);
            }
            door.lifecycle = Lifecycle::Live;
        }

        Change::SetBillingHold { mode } => {
            live(h)?;
            let lifting = match (h.holds.billing, mode) {
                (None, None) => return Ok(Outcome::Unchanged),
                (Some(old), Some(new)) if old.mode == *new => return Ok(Outcome::Unchanged),
                (_, None) => true,
                (Some(old), Some(new)) => *new < old.mode,
                (None, Some(_)) => false,
            };
            match actor {
                Actor::Billing => {}
                // The operator lifts or eases the billing hold; it never
                // places one.
                Actor::Operator if lifting => {}
                _ => return Err(FORBIDDEN),
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
            if h.deletion.is_some() {
                return Err(DELETING);
            }
            if h.undone_deletion.as_deref() == Some(key_hash.as_str()) {
                return Err(REPLAYED);
            }
            if class == ActorClass::Billing {
                if h.holds.billing.is_none() {
                    return Err(NO_BILLING_HOLD);
                }
                if shred_due_at.0.saturating_sub(now.0) < BILLING_DELETE_MIN_MS {
                    return Err(HOLD_PERIOD);
                }
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
            if !valid_units(units, placements) {
                return Err(INVALID);
            }
            if *units == h.units && *placements == h.placements {
                return Ok(Outcome::Unchanged);
            }
            door.units = units.clone();
            door.placements = placements.clone();
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

        Change::StartShred => {
            if actor != Actor::ShredJob {
                return Err(FORBIDDEN);
            }
            if h.lifecycle != Lifecycle::Live {
                return Err(WRONG_STATE);
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
        limits: BTreeMap::new(),
        rate_json: Default::default(),
        features_json: Default::default(),
        units: vec![],
        placements: vec![],
        tk_version: 0,
        rotating_to: None,
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
            external_ref,
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
                private: TenantPrivate {
                    v: RECORD_FORMAT,
                    external_ref: external_ref.clone(),
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
                cutover_stamp: None,
                undo_stamp: None,
                catalogue_id: None,
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
fn rotation_allowed(h: &TenantDoor, actor: Actor, version: u32) -> Result<(), Refusal> {
    match actor {
        Actor::RotationJob => {}
        Actor::TenantCreation if version == 1 => {}
        _ => return Err(FORBIDDEN),
    }
    if h.tenant.is_zero() {
        return Err(TENANT_ZERO);
    }
    match h.lifecycle {
        Lifecycle::Provisioning | Lifecycle::Live => {}
        _ => return Err(WRONG_STATE),
    }
    if h.deletion.is_some() {
        return Err(WRONG_STATE);
    }
    if !h.restoring.is_empty() {
        return Err(RESTORING);
    }
    Ok(())
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
        limits: BTreeMap::new(),
        rate_json: Default::default(),
        features_json: Default::default(),
        units: vec![],
        placements: vec![],
        tk_version: h.tk_version,
        rotating_to: None,
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
        || (prev.lifecycle != next.lifecycle
            && matches!(next.lifecycle, Lifecycle::Shredding | Lifecycle::Shredded))
        || prev.rate_json != next.rate_json;
    match closing {
        true => WriteOrder::Closing,
        false => WriteOrder::Opening,
    }
}

#[cfg(test)]
mod tests;
