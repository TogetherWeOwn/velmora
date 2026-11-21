//! The birth certificate of a unit (tenancy ADR §2.4 rules 6, 7, 13).
//!
//! A unit is created only by `provision(token)`. The token names the
//! tenant, the unit, the jurisdiction, the record seq, the schema
//! version, the key scheme and its kind (`birth` or `restore`), and is
//! sealed under the control key. The unit holds no key (rule 3), so the
//! **Worker** verifies the seal; the unit stores the token and checks
//! that the names in it are its own.
//!
//! Two sides:
//!
//! - [`may_provision`], in the Worker: whether `provision` may be
//!   called at all, from the chain head it has just re-read and the born
//!   marker `m/ub/<t>/<unit>`.
//! - [`check_token`], in the unit: whether this token may make this
//!   object, given the caller's `state_seq`.

use serde::{Deserialize, Serialize};

use super::name::UnitName;
use super::schema::SCHEMA_VERSION;

/// `birth`: the unit is made for the first time. `restore`: it is made
/// again while the head carries `restoring` for it, and starts closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BirthKind {
    Birth,
    Restore,
}

impl BirthKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BirthKind::Birth => "birth",
            BirthKind::Restore => "restore",
        }
    }
}

/// What a token says. The seal over it is the Worker's to verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BirthToken {
    pub name: UnitName,
    /// The jurisdiction the object was made under ("" for none).
    pub jurisdiction: String,
    /// The seq of the tenant record the token was made from: for a
    /// birth, the record that first lists this unit; for a restore, the
    /// record that set its `restoring` entry.
    pub record_seq: u64,
    pub schema_version: u32,
    /// 1 for tenant 0, 2 for every other tenant (rule 13).
    pub key_scheme: u8,
    pub kind: BirthKind,
}

/// The Worker's view of the tenant chain head, re-read just before it
/// would call `provision`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadView {
    pub seq: u64,
    /// The head is the record that **first** lists this unit (the
    /// `provisioning` record, or an add-unit record).
    pub first_lists_unit: bool,
    /// The `since_seq` of the head's `restoring` entry for this unit, if
    /// it carries one.
    pub restoring_since: Option<u64>,
}

/// Why `provision` is not to be called, or was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionRefusal {
    /// The born marker exists: this unit is made only by a restore token.
    BornBefore,
    /// A birth token, but the head is not the record that first lists
    /// the unit at the token's seq (a retried job that found a newer head).
    NotTheListingRecord,
    /// A restore token, but the head carries no `restoring` entry for
    /// the unit at the token's seq (none, or one of another restore).
    NotRestoring,
    /// The token names another tenant or unit than this object.
    WrongName,
    /// The key scheme does not follow the tenant id (rule 13).
    WrongScheme,
    /// The token was made for another schema than this code's.
    WrongSchema,
    /// A birth token whose seq is below the caller's `state_seq`: a lost
    /// unit is never turned into an empty one with its first token.
    StaleBirth,
    /// The object already holds a certificate.
    AlreadyBorn,
    /// A `provision` call without the caller's numbers.
    NoNumbers,
}

/// The Worker's rule (rule 6): `provision` is called only when it may
/// make the unit.
pub fn may_provision(
    head: &HeadView,
    token: &BirthToken,
    born_marker_present: bool,
) -> Result<(), ProvisionRefusal> {
    match token.kind {
        BirthKind::Birth => {
            if born_marker_present {
                return Err(ProvisionRefusal::BornBefore);
            }
            if !head.first_lists_unit || head.seq != token.record_seq {
                return Err(ProvisionRefusal::NotTheListingRecord);
            }
            Ok(())
        }
        // The token is bound to the restore it was made for: the head
        // must still hold this unit's entry with `since_seq` = its seq
        // (ADR §8.6 step 5). A stale token of an earlier restore is
        // refused.
        BirthKind::Restore => {
            if head.restoring_since != Some(token.record_seq) {
                return Err(ProvisionRefusal::NotRestoring);
            }
            Ok(())
        }
    }
}

/// The key scheme a tenant's units hold (rule 13).
pub fn scheme_of(name: &UnitName) -> u8 {
    if name.tenant.is_zero() {
        1
    } else {
        2
    }
}

/// The unit's rule (rules 6, 13 and 14): whether `token` may make the
/// object `own`, made under `jurisdiction` ("" for none).
/// `caller_state_seq`: the `state_seq` the `provision` call carries; a
/// call without it is refused, so that a Worker that forgets it cannot
/// turn a lost unit into an empty one.
pub fn check_token(
    own: &UnitName,
    jurisdiction: &str,
    token: &BirthToken,
    caller_state_seq: Option<u64>,
) -> Result<(), ProvisionRefusal> {
    if &token.name != own || token.jurisdiction != jurisdiction {
        return Err(ProvisionRefusal::WrongName);
    }
    let Some(caller_state_seq) = caller_state_seq else {
        return Err(ProvisionRefusal::NoNumbers);
    };
    if token.key_scheme != scheme_of(own) {
        return Err(ProvisionRefusal::WrongScheme);
    }
    if token.schema_version != SCHEMA_VERSION {
        return Err(ProvisionRefusal::WrongSchema);
    }
    if token.kind == BirthKind::Birth && caller_state_seq > token.record_seq {
        return Err(ProvisionRefusal::StaleBirth);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::name::TenantId;

    fn tenant() -> TenantId {
        TenantId::parse("t_00000000000000b7").unwrap()
    }

    fn token(kind: BirthKind, record_seq: u64) -> BirthToken {
        BirthToken {
            name: UnitName::new(tenant(), 0),
            jurisdiction: String::new(),
            record_seq,
            schema_version: SCHEMA_VERSION,
            key_scheme: 2,
            kind,
        }
    }

    fn head(seq: u64, first_lists_unit: bool, restoring_since: Option<u64>) -> HeadView {
        HeadView {
            seq,
            first_lists_unit,
            restoring_since,
        }
    }

    #[test]
    fn a_birth_is_called_only_at_the_listing_record_without_a_marker() {
        let t = token(BirthKind::Birth, 3);
        assert_eq!(may_provision(&head(3, true, None), &t, false), Ok(()));
        assert_eq!(
            may_provision(&head(3, true, None), &t, true),
            Err(ProvisionRefusal::BornBefore)
        );
        // A retried job that finds a newer head does not call provision.
        assert_eq!(
            may_provision(&head(4, false, None), &t, false),
            Err(ProvisionRefusal::NotTheListingRecord)
        );
        assert_eq!(
            may_provision(&head(4, true, None), &t, false),
            Err(ProvisionRefusal::NotTheListingRecord)
        );
        assert_eq!(
            may_provision(&head(3, false, None), &t, false),
            Err(ProvisionRefusal::NotTheListingRecord)
        );
    }

    #[test]
    fn a_restore_is_called_only_while_the_head_carries_its_entry() {
        let t = token(BirthKind::Restore, 9);
        assert_eq!(may_provision(&head(12, false, Some(9)), &t, true), Ok(()));
        assert_eq!(may_provision(&head(12, false, Some(9)), &t, false), Ok(()));
        assert_eq!(
            may_provision(&head(12, false, None), &t, true),
            Err(ProvisionRefusal::NotRestoring)
        );
        // A stale token of an earlier restore, while another restore of
        // the unit is under way.
        assert_eq!(
            may_provision(&head(25, false, Some(20)), &t, true),
            Err(ProvisionRefusal::NotRestoring)
        );
    }

    #[test]
    fn the_unit_checks_names_scheme_schema_and_the_callers_seq() {
        let own = UnitName::new(tenant(), 0);
        let birth = token(BirthKind::Birth, 3);
        assert_eq!(check_token(&own, "", &birth, Some(3)), Ok(()));
        assert_eq!(
            check_token(&own, "", &birth, None),
            Err(ProvisionRefusal::NoNumbers)
        );
        assert_eq!(
            check_token(&own, "", &birth, Some(4)),
            Err(ProvisionRefusal::StaleBirth)
        );
        // A restore token is not bound to the caller's view.
        assert_eq!(
            check_token(&own, "", &token(BirthKind::Restore, 3), Some(40)),
            Ok(())
        );
        // Rule 14: a token for another jurisdiction makes no object here.
        assert_eq!(
            check_token(&own, "eu", &birth, Some(3)),
            Err(ProvisionRefusal::WrongName)
        );

        let other = UnitName::new(tenant(), 1);
        assert_eq!(
            check_token(&other, "", &birth, Some(3)),
            Err(ProvisionRefusal::WrongName)
        );
        let mut t = token(BirthKind::Birth, 3);
        t.key_scheme = 1;
        assert_eq!(
            check_token(&own, "", &t, Some(3)),
            Err(ProvisionRefusal::WrongScheme)
        );
        let mut t = token(BirthKind::Birth, 3);
        t.schema_version += 1;
        assert_eq!(
            check_token(&own, "", &t, Some(3)),
            Err(ProvisionRefusal::WrongSchema)
        );
    }

    #[test]
    fn tenant_zero_holds_scheme_one_and_every_other_tenant_scheme_two() {
        assert_eq!(scheme_of(&UnitName::new(TenantId::zero(), 0)), 1);
        assert_eq!(scheme_of(&UnitName::new(tenant(), 3)), 2);
        let mut t = token(BirthKind::Birth, 1);
        t.name = UnitName::new(TenantId::zero(), 0);
        assert_eq!(
            check_token(&t.name.clone(), "", &t, Some(1)),
            Err(ProvisionRefusal::WrongScheme)
        );
        t.key_scheme = 1;
        assert_eq!(check_token(&t.name.clone(), "", &t, Some(1)), Ok(()));
    }

    #[test]
    fn a_token_with_an_unknown_field_is_not_read() {
        let mut v = serde_json::to_value(token(BirthKind::Birth, 1)).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<BirthToken>(v).is_err());
    }
}
