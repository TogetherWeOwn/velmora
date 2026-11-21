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
//!   tenant's key. Today only the `external_ref` that binds a workspace.
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

/// The version of the door and private part formats. A reader refuses
/// any other: a gate that cannot apply a field must not guess it.
pub const RECORD_FORMAT: u32 = 1;

/// The number of hex digits after `t_` in a tenant id.
pub const TENANT_ID_HEX: usize = 16;

/// A tenant id: `t_` and 16 lowercase hex digits. Tenant 0 is
/// `t_0000000000000000`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    /// The tenant of every bucket that exists today.
    pub fn zero() -> TenantId {
        TenantId(crate::recovery::DEFAULT_TENANT.to_string())
    }

    /// Parses a tenant id; `None` for anything but `t_` and 16 lowercase
    /// hex digits.
    pub fn parse(id: &str) -> Option<TenantId> {
        let hex = id.strip_prefix("t_")?;
        let ok = hex.len() == TENANT_ID_HEX
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        ok.then(|| TenantId(id.to_string()))
    }

    /// From the 8 random bytes of a new tenant. All zero is tenant 0's id,
    /// which no new tenant may take: `None`.
    pub fn from_random(bytes: [u8; 8]) -> Option<TenantId> {
        if bytes == [0u8; 8] {
            return None;
        }
        let mut id = String::with_capacity(2 + TENANT_ID_HEX);
        id.push_str("t_");
        for b in bytes {
            id.push_str(&format!("{b:02x}"));
        }
        Some(TenantId(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == crate::recovery::DEFAULT_TENANT
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for TenantId {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        TenantId::parse(&s).ok_or("not a tenant id")
    }
}

impl From<TenantId> for String {
    fn from(t: TenantId) -> String {
        t.0
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
/// the move; then its data is another tenant's and it serves nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum Selector {
    /// Today's D1 catalogue.
    D1,
    /// The data moved to another tenant. Tenant 0 answers `503`.
    Moved { to: TenantId },
}

/// The fields that only tenant 0's record has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantZero {
    pub selector: Selector,
    /// The stamp of the move's flip, once it happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutover_stamp: Option<u64>,
    /// The stamp of an undo, higher than the cutover stamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_stamp: Option<u64>,
    /// After an undo: the id of the catalogue that `d1` then means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue_id: Option<String>,
}

/// The door part of a tenant record. See the [module](self).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantDoor {
    pub v: u32,
    pub tenant: TenantId,
    pub seq: u64,
    pub written_at: UnixMs,
    pub lifecycle: Lifecycle,
    #[serde(default)]
    pub holds: Holds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion: Option<Deletion>,
    /// The key hash of the last deletion that was undone. A set-deletion
    /// call that carries it again is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_deletion: Option<String>,
    #[serde(default)]
    pub restoring: Vec<Restoring>,
    #[serde(default)]
    pub synthetic: bool,
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
    /// The tenant key version in force; 0 for tenant 0, which has none.
    pub tk_version: u32,
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
            tenant: TenantId::parse("t_00000000000000a1").unwrap(),
            seq: 1,
            written_at: UnixMs(1),
            lifecycle: Lifecycle::Live,
            holds: Holds::default(),
            deletion: None,
            undone_deletion: None,
            restoring: vec![],
            synthetic: false,
            limits: BTreeMap::new(),
            rate_json: Default::default(),
            features_json: Default::default(),
            units: vec![0],
            placements: vec![],
            tk_version: 1,
            rotating_to: None,
            highest_claimed: 1,
            jurisdiction: "us".into(),
            location_hint: None,
            tenant_zero: None,
        }
    }

    #[test]
    fn tenant_ids() {
        assert!(TenantId::zero().is_zero());
        assert_eq!(TenantId::zero().as_str(), "t_0000000000000000");
        assert!(TenantId::parse("t_0123456789abcdef").is_some());
        for bad in [
            "t_0123456789ABCDEF",
            "t_0123456789abcde",
            "t_0123456789abcdef0",
            "x_0123456789abcdef",
            "t_0123456789abcdeg",
            "",
            "t_",
        ] {
            assert!(TenantId::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(TenantId::from_random([0; 8]), None);
        let t = TenantId::from_random([0xde, 0xad, 0, 1, 2, 3, 4, 0xff]).unwrap();
        assert_eq!(t.as_str(), "t_dead0001020304ff");
        assert!(!t.is_zero());
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"t_dead0001020304ff\"");
        assert!(serde_json::from_str::<TenantId>("\"t_DEAD0001020304ff\"").is_err());
    }

    #[test]
    fn the_state_is_derived_from_holds_and_deletion() {
        let mut d = door();
        assert_eq!(d.state(), TenantState::Active);
        assert_eq!(d.s3_access(0), S3Access::Full);

        d.holds.billing = Some(BillingHold {
            mode: HoldMode::ReadOnly,
        });
        assert_eq!(d.state(), TenantState::Suspended(HoldMode::ReadOnly));
        assert_eq!(d.s3_access(0), S3Access::ReadOnly);

        // The strictest hold is in force.
        d.holds.operator = Some(OperatorHold {
            mode: HoldMode::Locked,
            reason: OperatorReason::Security,
            preserve: false,
        });
        assert_eq!(d.state(), TenantState::Suspended(HoldMode::Locked));
        assert_eq!(d.s3_access(0), S3Access::AccountProblem);
        assert_eq!(
            d.hold_classes(),
            vec![ActorClass::Billing, ActorClass::Operator]
        );

        // A deletion wins over the holds, and keeps them.
        d.deletion = Some(Deletion {
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
            selector: Selector::Moved {
                to: TenantId::parse("t_00000000000000a1").unwrap(),
            },
            cutover_stamp: Some(7),
            undo_stamp: None,
            catalogue_id: None,
        };
        let json = serde_json::to_value(&z).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "selector": {"kind": "moved", "to": "t_00000000000000a1"},
                "cutover_stamp": 7
            })
        );
        let d1 = serde_json::to_value(Selector::D1).unwrap();
        assert_eq!(d1, serde_json::json!({"kind": "d1"}));
    }
}
