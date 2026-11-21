//! The rules of the tenant state table, one test or more per rule.

use super::*;
use crate::directory::record::{S3Access, TenantState};

const DAY: i64 = 24 * 3_600_000;
const NOW: UnixMs = UnixMs(1_800_000_000_000);

fn t1() -> TenantId {
    TenantId::parse("t_00000000000000a1").unwrap()
}

fn hash(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn create() -> Change {
    Change::Create {
        jurisdiction: "us".into(),
        location_hint: Some("enam".into()),
        synthetic: false,
        limits: BTreeMap::from([("storage_bytes".to_string(), 1_000)]),
        rate_json: Default::default(),
        features_json: Default::default(),
    }
}

fn step(head: Option<&TenantRecord>, change: Change, actor: Actor) -> Result<Outcome, Refusal> {
    let tenant = head.map(|h| h.door.tenant.clone()).unwrap_or_else(t1);
    next(&tenant, head, &change, actor, NOW)
}

/// Applies a change that must produce a record.
fn apply(head: &TenantRecord, change: Change, actor: Actor) -> TenantRecord {
    match step(Some(head), change.clone(), actor) {
        Ok(Outcome::Next(r)) => r,
        other => panic!("{change:?} by {actor:?}: {other:?}"),
    }
}

fn refused(head: &TenantRecord, change: Change, actor: Actor) -> Refusal {
    match step(Some(head), change.clone(), actor) {
        Err(r) => r,
        other => panic!("{change:?} by {actor:?} was not refused: {other:?}"),
    }
}

fn unchanged(head: &TenantRecord, change: Change, actor: Actor) {
    assert_eq!(
        step(Some(head), change.clone(), actor),
        Ok(Outcome::Unchanged),
        "{change:?} by {actor:?}"
    );
}

/// A tenant through creation: provisioning, claim and commit of
/// version 1, active.
fn active() -> TenantRecord {
    let Ok(Outcome::Next(r)) = step(None, create(), Actor::TenantCreation) else {
        panic!("create");
    };
    let r = apply(
        &r,
        Change::ClaimKeyVersion { version: 1 },
        Actor::TenantCreation,
    );
    let r = apply(
        &r,
        Change::CommitKeyVersion { version: 1 },
        Actor::TenantCreation,
    );
    apply(
        &r,
        Change::Activate {
            external_ref: Some("ws_1".into()),
        },
        Actor::TenantCreation,
    )
}

fn delete_by(actor: Actor, reason: DeletionReason, due_in: i64, key: u8) -> Change {
    let _ = actor;
    Change::SetDeletion {
        shred_due_at: UnixMs(NOW.0 + due_in),
        reason,
        key_hash: hash(key),
    }
}

fn billing_hold(mode: Option<HoldMode>) -> Change {
    Change::SetBillingHold { mode }
}

fn operator_hold(mode: HoldMode, reason: OperatorReason, preserve: Option<bool>) -> Change {
    Change::SetOperatorHold {
        hold: Some(OperatorHoldRequest {
            mode,
            reason,
            preserve,
        }),
    }
}

#[test]
fn creation_runs_provisioning_claim_commit_active() {
    let Ok(Outcome::Next(p)) = step(None, create(), Actor::TenantCreation) else {
        panic!("create");
    };
    assert_eq!(p.door.seq, 1);
    assert_eq!(p.door.state(), TenantState::Provisioning);
    assert_eq!(p.door.units, vec![0]);
    assert_eq!(p.door.tk_version, 0);
    // No tenant key yet, so nothing private yet.
    assert_eq!(p.private.external_ref, None);
    assert_eq!(p.door.s3_access(0), S3Access::Unavailable);

    // Not active before version 1 is committed.
    assert_eq!(
        refused(
            &p,
            Change::Activate { external_ref: None },
            Actor::TenantCreation
        ),
        NOT_READY
    );
    let c = apply(
        &p,
        Change::ClaimKeyVersion { version: 1 },
        Actor::TenantCreation,
    );
    assert_eq!(
        refused(
            &c,
            Change::Activate { external_ref: None },
            Actor::TenantCreation
        ),
        NOT_READY
    );

    let a = active();
    assert_eq!(a.door.seq, 4);
    assert_eq!(a.door.state(), TenantState::Active);
    assert_eq!(a.door.tk_version, 1);
    // Fixed in the first record and repeated in every later one.
    assert_eq!(a.door.jurisdiction, "us");
    assert_eq!(a.door.location_hint.as_deref(), Some("enam"));
    assert_eq!(a.private.external_ref.as_deref(), Some("ws_1"));

    // Only tenant creation creates, and only once.
    assert_eq!(step(None, create(), Actor::Operator), Err(FORBIDDEN));
    assert_eq!(refused(&a, create(), Actor::TenantCreation), EXISTS);
    // Nothing but a create starts a chain.
    assert_eq!(
        step(
            None,
            Change::Activate { external_ref: None },
            Actor::TenantCreation
        ),
        Err(NO_TENANT)
    );
}

#[test]
fn tenant_zero_has_its_own_first_record() {
    let zero = TenantId::zero();
    let create_zero = Change::CreateTenantZero {
        jurisdiction: "us".into(),
    };
    // The normal create refuses tenant 0's id.
    assert_eq!(
        next(&zero, None, &create(), Actor::TenantCreation, NOW),
        Err(TENANT_ZERO)
    );
    assert_eq!(
        next(&t1(), None, &create_zero, Actor::Operator, NOW),
        Err(INVALID)
    );
    let Ok(Outcome::Next(z)) = next(&zero, None, &create_zero, Actor::Operator, NOW) else {
        panic!("tenant 0");
    };
    assert_eq!(z.door.state(), TenantState::Active);
    assert_eq!(z.door.tk_version, 0);
    assert!(z.door.units.is_empty());
    assert_eq!(
        z.door.tenant_zero.as_ref().map(|t| &t.selector),
        Some(&Selector::D1)
    );
    // Scheme 1 for good: no rotation, no unit list.
    assert_eq!(
        refused(
            &z,
            Change::ClaimKeyVersion { version: 1 },
            Actor::RotationJob
        ),
        TENANT_ZERO
    );
    assert_eq!(
        refused(
            &z,
            Change::SetUnits {
                units: vec![0],
                placements: vec![]
            },
            Actor::Operator
        ),
        TENANT_ZERO
    );
    // No unit is listed, so none can be restored.
    assert_eq!(
        refused(&z, Change::SetRestoring { unit: 0 }, Actor::Operator),
        UNIT_NOT_LISTED
    );
    // Holds work on tenant 0 as on any tenant.
    let held = apply(
        &z,
        operator_hold(HoldMode::ReadOnly, OperatorReason::Security, None),
        Actor::Operator,
    );
    assert_eq!(
        held.door.state(),
        TenantState::Suspended(HoldMode::ReadOnly)
    );
}

#[test]
fn who_places_and_lifts_holds() {
    let a = active();
    // The customer plane never touches a hold.
    assert_eq!(
        refused(&a, billing_hold(Some(HoldMode::Locked)), Actor::Customer),
        FORBIDDEN
    );
    assert_eq!(
        refused(
            &a,
            operator_hold(HoldMode::Locked, OperatorReason::Abuse, None),
            Actor::Customer
        ),
        FORBIDDEN
    );
    // Billing places only its own; the operator places only its own.
    assert_eq!(
        refused(
            &a,
            operator_hold(HoldMode::Locked, OperatorReason::Abuse, None),
            Actor::Billing
        ),
        FORBIDDEN
    );
    assert_eq!(
        refused(&a, billing_hold(Some(HoldMode::ReadOnly)), Actor::Operator),
        FORBIDDEN
    );
    let b = apply(&a, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    assert_eq!(b.door.state(), TenantState::Suspended(HoldMode::ReadOnly));
    // Making the billing hold stricter is billing's, not the operator's.
    assert_eq!(
        refused(&b, billing_hold(Some(HoldMode::Locked)), Actor::Operator),
        FORBIDDEN
    );
    let locked = apply(&b, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    // The operator may ease and lift the billing hold.
    let eased = apply(
        &locked,
        billing_hold(Some(HoldMode::ReadOnly)),
        Actor::Operator,
    );
    assert_eq!(
        eased.door.state(),
        TenantState::Suspended(HoldMode::ReadOnly)
    );
    let lifted = apply(&eased, billing_hold(None), Actor::Operator);
    assert_eq!(lifted.door.state(), TenantState::Active);

    // Only the operator plane lifts an operator hold.
    let o = apply(
        &a,
        operator_hold(HoldMode::Locked, OperatorReason::Security, None),
        Actor::Operator,
    );
    assert_eq!(
        refused(&o, Change::SetOperatorHold { hold: None }, Actor::Billing),
        FORBIDDEN
    );
    let off = apply(&o, Change::SetOperatorHold { hold: None }, Actor::Operator);
    assert_eq!(off.door.state(), TenantState::Active);
}

#[test]
fn lifting_a_hold_that_is_not_there_writes_nothing() {
    let a = active();
    unchanged(&a, billing_hold(None), Actor::Billing);
    unchanged(&a, Change::SetOperatorHold { hold: None }, Actor::Operator);
    let b = apply(&a, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    unchanged(&b, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
}

#[test]
fn preserve_is_stored_with_its_value_never_the_default() {
    let a = active();
    for (reason, default) in [
        (OperatorReason::Legal, true),
        (OperatorReason::Abuse, true),
        (OperatorReason::Security, false),
        (OperatorReason::Other, false),
    ] {
        let r = apply(
            &a,
            operator_hold(HoldMode::ReadOnly, reason, None),
            Actor::Operator,
        );
        assert_eq!(
            r.door.holds.operator.unwrap().preserve,
            default,
            "{reason:?}"
        );
        let r = apply(
            &a,
            operator_hold(HoldMode::ReadOnly, reason, Some(!default)),
            Actor::Operator,
        );
        assert_eq!(
            r.door.holds.operator.unwrap().preserve,
            !default,
            "{reason:?}"
        );
        let json = serde_json::to_value(&r.door).unwrap();
        assert!(json["holds"]["operator"]["preserve"].is_boolean());
    }
}

#[test]
fn who_sets_and_undoes_a_deletion() {
    let a = active();
    let customer = delete_by(
        Actor::Customer,
        DeletionReason::CustomerRequest,
        30 * DAY,
        1,
    );
    // The reason must match the actor.
    assert_eq!(
        refused(
            &a,
            delete_by(Actor::Customer, DeletionReason::NonPayment, 70 * DAY, 1),
            Actor::Customer
        ),
        FORBIDDEN
    );
    assert_eq!(refused(&a, customer.clone(), Actor::Billing), FORBIDDEN);
    // Jobs and tools set no deletion.
    assert_eq!(refused(&a, customer.clone(), Actor::ShredJob), FORBIDDEN);

    let d = apply(&a, customer.clone(), Actor::Customer);
    assert_eq!(d.door.state(), TenantState::Deleting);
    assert_eq!(
        d.door.deletion.as_ref().unwrap().actor,
        ActorClass::Customer
    );
    // One deletion at a time; the first due date stands.
    assert_eq!(
        refused(
            &d,
            delete_by(
                Actor::Operator,
                DeletionReason::Operator(OperatorReason::Legal),
                DAY,
                2
            ),
            Actor::Operator
        ),
        DELETING
    );
    // Billing cannot undo a customer's deletion; the customer and the
    // operator can.
    assert_eq!(refused(&d, Change::UndoDeletion, Actor::Billing), FORBIDDEN);
    let undone = apply(&d, Change::UndoDeletion, Actor::Customer);
    assert_eq!(undone.door.state(), TenantState::Active);
    apply(&d, Change::UndoDeletion, Actor::Operator);

    // An operator's deletion is the operator's to undo.
    let od = apply(
        &a,
        delete_by(
            Actor::Operator,
            DeletionReason::Operator(OperatorReason::Abuse),
            DAY,
            3,
        ),
        Actor::Operator,
    );
    assert_eq!(
        refused(&od, Change::UndoDeletion, Actor::Customer),
        FORBIDDEN
    );
    apply(&od, Change::UndoDeletion, Actor::Operator);

    // Undo without a deletion.
    assert_eq!(
        refused(&a, Change::UndoDeletion, Actor::Operator),
        NOT_DELETING
    );
    // A due date in the past and a malformed key hash are refused.
    assert_eq!(
        refused(
            &a,
            delete_by(Actor::Customer, DeletionReason::CustomerRequest, 0, 1),
            Actor::Customer
        ),
        INVALID
    );
    assert_eq!(
        refused(
            &a,
            Change::SetDeletion {
                shred_due_at: UnixMs(NOW.0 + DAY),
                reason: DeletionReason::CustomerRequest,
                key_hash: "not-a-hash".into()
            },
            Actor::Customer
        ),
        INVALID
    );
}

#[test]
fn the_undo_returns_to_the_carried_state() {
    let a = active();
    let held = apply(
        &a,
        operator_hold(HoldMode::ReadOnly, OperatorReason::Security, None),
        Actor::Operator,
    );
    let d = apply(
        &held,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    assert_eq!(d.door.state(), TenantState::Deleting);
    // A hold can be placed and lifted while deleting.
    let d = apply(&d, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    let d = apply(&d, billing_hold(None), Actor::Billing);
    let undone = apply(&d, Change::UndoDeletion, Actor::Customer);
    assert_eq!(
        undone.door.state(),
        TenantState::Suspended(HoldMode::ReadOnly)
    );
    assert!(undone.door.holds.operator.is_some());
}

#[test]
fn billing_deletes_only_under_its_hold_and_with_sixty_days() {
    let a = active();
    let dunning = |due_in| delete_by(Actor::Billing, DeletionReason::NonPayment, due_in, 9);
    assert_eq!(
        refused(&a, dunning(90 * DAY), Actor::Billing),
        NO_BILLING_HOLD
    );
    let b = apply(&a, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    assert_eq!(refused(&b, dunning(59 * DAY), Actor::Billing), HOLD_PERIOD);
    // 60 days less the hour of tolerance is the shortest.
    apply(&b, dunning(BILLING_DELETE_MIN_MS), Actor::Billing);
    assert_eq!(
        refused(&b, dunning(BILLING_DELETE_MIN_MS - 1), Actor::Billing),
        HOLD_PERIOD
    );
    let d = apply(&b, dunning(60 * DAY), Actor::Billing);
    assert_eq!(d.door.deletion.as_ref().unwrap().actor, ActorClass::Billing);
    // Billing undoes its own deletion only.
    apply(&d, Change::UndoDeletion, Actor::Billing);
    assert_eq!(
        refused(&d, Change::UndoDeletion, Actor::Customer),
        FORBIDDEN
    );
}

/// Lifting the billing hold clears a billing deletion in the same
/// record, whoever lifts it, and only a billing deletion.
#[test]
fn lifting_the_billing_hold_clears_a_billing_deletion() {
    let a = active();
    let b = apply(&a, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    let d = apply(
        &b,
        delete_by(Actor::Billing, DeletionReason::NonPayment, 61 * DAY, 9),
        Actor::Billing,
    );
    for lifter in [Actor::Billing, Actor::Operator] {
        let paid = apply(&d, billing_hold(None), lifter);
        assert_eq!(paid.door.state(), TenantState::Active, "{lifter:?}");
        assert_eq!(paid.door.deletion, None);
        assert_eq!(paid.door.undone_deletion, Some(hash(9)));
        // Easing the hold is not lifting it: the deletion stands.
        let eased = apply(&d, billing_hold(Some(HoldMode::ReadOnly)), lifter);
        assert!(eased.door.deletion.is_some());
    }
    // A customer's deletion survives the billing lift.
    let cd = apply(
        &b,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 4),
        Actor::Customer,
    );
    let lifted = apply(&cd, billing_hold(None), Actor::Billing);
    assert_eq!(lifted.door.state(), TenantState::Deleting);
    assert_eq!(lifted.door.undone_deletion, None);
}

/// A deletion that was undone is not set again by a replay of its
/// key; a newer undo replaces the remembered hash.
#[test]
fn an_undone_deletion_is_not_set_again_by_its_key() {
    let a = active();
    let d = apply(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    let undone = apply(&d, Change::UndoDeletion, Actor::Customer);
    let replay = delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1);
    assert_eq!(refused(&undone, replay.clone(), Actor::Customer), REPLAYED);
    // A new key is a new request.
    let d2 = apply(
        &undone,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 2),
        Actor::Customer,
    );
    let undone2 = apply(&d2, Change::UndoDeletion, Actor::Customer);
    // One hash is kept, not a history.
    assert_eq!(undone2.door.undone_deletion, Some(hash(2)));
    apply(&undone2, replay, Actor::Customer);
}

#[test]
fn a_deletion_voids_an_open_rotation_claim() {
    let a = active();
    let claimed = apply(
        &a,
        Change::ClaimKeyVersion { version: 2 },
        Actor::RotationJob,
    );
    assert_eq!(claimed.door.rotating_to, Some(2));
    let d = apply(
        &claimed,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    assert_eq!(d.door.rotating_to, None);
    assert_eq!(d.door.tk_version, 1);
    // No claim or commit while deleting.
    assert_eq!(
        refused(
            &d,
            Change::ClaimKeyVersion { version: 2 },
            Actor::RotationJob
        ),
        WRONG_STATE
    );
    // After the undo the rotation starts again with a new claim, of a
    // version that was never claimed.
    let undone = apply(&d, Change::UndoDeletion, Actor::Customer);
    apply(
        &undone,
        Change::ClaimKeyVersion { version: 3 },
        Actor::RotationJob,
    );
}

#[test]
fn rotation_claims_exactly_the_next_version_once() {
    let a = active();
    assert_eq!(
        refused(
            &a,
            Change::ClaimKeyVersion { version: 3 },
            Actor::RotationJob
        ),
        VERSION
    );
    // Tenant creation claims version 1 only.
    assert_eq!(
        refused(
            &a,
            Change::ClaimKeyVersion { version: 2 },
            Actor::TenantCreation
        ),
        FORBIDDEN
    );
    assert_eq!(
        refused(&a, Change::ClaimKeyVersion { version: 2 }, Actor::Operator),
        FORBIDDEN
    );
    let c = apply(
        &a,
        Change::ClaimKeyVersion { version: 2 },
        Actor::RotationJob,
    );
    assert_eq!(
        refused(
            &c,
            Change::ClaimKeyVersion { version: 2 },
            Actor::RotationJob
        ),
        CLAIM_OPEN
    );
    assert_eq!(
        refused(
            &c,
            Change::CommitKeyVersion { version: 3 },
            Actor::RotationJob
        ),
        NO_CLAIM
    );
    let done = apply(
        &c,
        Change::CommitKeyVersion { version: 2 },
        Actor::RotationJob,
    );
    assert_eq!((done.door.tk_version, done.door.rotating_to), (2, None));
    // A suspended tenant rotates too.
    let s = apply(&done, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    apply(
        &s,
        Change::ClaimKeyVersion { version: 3 },
        Actor::RotationJob,
    );
}

#[test]
fn restoring_is_idempotent_extendable_and_lifted_by_its_own_entry() {
    let a = active();
    let two = apply(
        &a,
        Change::SetUnits {
            units: vec![0, 1],
            placements: vec![Placement {
                bucket: "b_1".into(),
                unit: 1,
                epoch: 1,
            }],
        },
        Actor::Operator,
    );
    assert_eq!(
        refused(&two, Change::SetRestoring { unit: 0 }, Actor::Customer),
        FORBIDDEN
    );
    assert_eq!(
        refused(&two, Change::SetRestoring { unit: 7 }, Actor::Operator),
        UNIT_NOT_LISTED
    );
    let r0 = apply(&two, Change::SetRestoring { unit: 0 }, Actor::Operator);
    let s0 = two.door.seq + 1;
    assert_eq!(
        r0.door.restoring,
        vec![Restoring {
            unit: 0,
            since_seq: s0
        }]
    );
    // Setting it again writes nothing and keeps the since_seq.
    unchanged(&r0, Change::SetRestoring { unit: 0 }, Actor::Operator);
    // Setting and lifting never changes the state.
    assert_eq!(r0.door.state(), TenantState::Active);
    assert_eq!(r0.door.s3_access(0), S3Access::Unavailable);
    assert_eq!(r0.door.s3_access(1), S3Access::Full);

    // A second unit gets its own entry while the first is in the gate.
    let r1 = apply(&r0, Change::SetRestoring { unit: 1 }, Actor::Operator);
    assert_eq!(r1.door.restoring.len(), 2);
    // Other records move the head; the lift checks its own entry.
    let r1 = apply(&r1, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    assert_eq!(
        refused(
            &r1,
            Change::LiftRestoring {
                unit: 0,
                since_seq: s0
            },
            Actor::Operator
        ),
        FORBIDDEN
    );
    assert_eq!(
        refused(
            &r1,
            Change::LiftRestoring {
                unit: 0,
                since_seq: s0 + 5
            },
            Actor::RestoreTool
        ),
        ENTRY_GONE
    );
    let lifted = apply(
        &r1,
        Change::LiftRestoring {
            unit: 0,
            since_seq: s0,
        },
        Actor::RestoreTool,
    );
    assert_eq!(lifted.door.restoring.len(), 1);
    assert_eq!(lifted.door.restoring[0].unit, 1);
    // The hold written in between is in force at the lift.
    assert_eq!(
        lifted.door.state(),
        TenantState::Suspended(HoldMode::ReadOnly)
    );
}

#[test]
fn what_restoring_allows_and_refuses() {
    let a = active();
    let r = apply(&a, Change::SetRestoring { unit: 0 }, Actor::Operator);
    // Allowed: holds, deletion and undo, limits.
    let r = apply(&r, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    let r = apply(
        &r,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    let r = apply(&r, Change::UndoDeletion, Actor::Customer);
    let r = apply(
        &r,
        Change::SetLimits {
            limits: BTreeMap::new(),
            rate_json: None,
        },
        Actor::Operator,
    );
    // Refused: units and placements, rotation, shredding.
    assert_eq!(
        refused(
            &r,
            Change::SetUnits {
                units: vec![0, 1],
                placements: vec![]
            },
            Actor::Operator
        ),
        RESTORING
    );
    assert_eq!(
        refused(
            &r,
            Change::ClaimKeyVersion { version: 2 },
            Actor::RotationJob
        ),
        RESTORING
    );
    // Not for a provisioning tenant.
    let Ok(Outcome::Next(p)) = step(None, create(), Actor::TenantCreation) else {
        panic!()
    };
    assert_eq!(
        refused(&p, Change::SetRestoring { unit: 0 }, Actor::Operator),
        WRONG_STATE
    );
}

#[test]
fn the_shred_waits_for_its_date_the_restore_and_a_preserving_hold() {
    let a = active();
    assert_eq!(
        refused(&a, Change::StartShred, Actor::ShredJob),
        NOT_DELETING
    );
    let d = apply(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    assert_eq!(refused(&d, Change::StartShred, Actor::ShredJob), NOT_DUE);
    let due = UnixMs(NOW.0 + 7 * DAY);
    let shred_at = |head: &TenantRecord, actor| {
        next(
            &head.door.tenant,
            Some(head),
            &Change::StartShred,
            actor,
            due,
        )
    };
    assert_eq!(shred_at(&d, Actor::Operator), Err(FORBIDDEN));

    // A legal hold preserves; the deletion and its date stay as they were.
    let legal = apply(
        &d,
        operator_hold(HoldMode::Locked, OperatorReason::Legal, None),
        Actor::Operator,
    );
    assert_eq!(shred_at(&legal, Actor::ShredJob), Err(PRESERVED));
    assert_eq!(legal.door.deletion, d.door.deletion);
    // A security hold does not, unless the operator says so.
    let sec = apply(
        &d,
        operator_hold(HoldMode::Locked, OperatorReason::Security, None),
        Actor::Operator,
    );
    assert!(matches!(
        shred_at(&sec, Actor::ShredJob),
        Ok(Outcome::Next(_))
    ));
    let sec_kept = apply(
        &d,
        operator_hold(HoldMode::Locked, OperatorReason::Security, Some(true)),
        Actor::Operator,
    );
    assert_eq!(shred_at(&sec_kept, Actor::ShredJob), Err(PRESERVED));
    // Clearing preserve lets the shred run at the next pass.
    let cleared = apply(
        &legal,
        operator_hold(HoldMode::Locked, OperatorReason::Legal, Some(false)),
        Actor::Operator,
    );
    assert!(matches!(
        shred_at(&cleared, Actor::ShredJob),
        Ok(Outcome::Next(_))
    ));

    // A unit being restored holds the shred back.
    let r = apply(&d, Change::SetRestoring { unit: 0 }, Actor::Operator);
    assert_eq!(shred_at(&r, Actor::ShredJob), Err(RESTORING));
}

#[test]
fn shredding_admits_only_shredded_and_shredded_admits_nothing() {
    let a = active();
    let d = apply(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    let due = UnixMs(NOW.0 + 7 * DAY);
    let Ok(Outcome::Next(s)) = next(
        &a.door.tenant,
        Some(&d),
        &Change::StartShred,
        Actor::ShredJob,
        due,
    ) else {
        panic!("shred")
    };
    assert_eq!(s.door.state(), TenantState::Shredding);
    assert_eq!(s.door.s3_access(0), S3Access::AccountProblem);
    for (change, actor) in [
        (Change::UndoDeletion, Actor::Operator),
        (billing_hold(Some(HoldMode::Locked)), Actor::Billing),
        (Change::SetRestoring { unit: 0 }, Actor::Operator),
        (Change::ClaimKeyVersion { version: 2 }, Actor::RotationJob),
    ] {
        assert_eq!(refused(&s, change, actor), SHREDDING);
    }
    assert_eq!(refused(&s, Change::FinishShred, Actor::Operator), FORBIDDEN);
    let gone = apply(&s, Change::FinishShred, Actor::ShredJob);
    assert_eq!(gone.door.state(), TenantState::Shredded);
    // The stub holds no name and no setting.
    assert_eq!(gone.private.external_ref, None);
    assert!(gone.door.units.is_empty() && gone.door.limits.is_empty());
    assert!(gone.door.deletion.is_none() && gone.door.holds.is_empty());
    assert_eq!(gone.door.seq, s.door.seq + 1);
    for change in [Change::FinishShred, Change::UndoDeletion, create()] {
        assert_eq!(refused(&gone, change, Actor::Operator), SHREDDED);
    }
}

#[test]
fn units_and_placements_are_checked() {
    let a = active();
    let set = |units: Vec<u32>, placements: Vec<Placement>| Change::SetUnits { units, placements };
    let p = |bucket: &str, unit| Placement {
        bucket: bucket.into(),
        unit,
        epoch: 1,
    };
    for bad in [
        set(vec![1], vec![]),
        set(vec![0, 0], vec![]),
        set(vec![1, 0], vec![]),
        set(vec![0], vec![p("b", 1)]),
        set(vec![0, 1], vec![p("b", 0), p("b", 1)]),
    ] {
        assert_eq!(refused(&a, bad, Actor::Operator), INVALID);
    }
    unchanged(&a, set(vec![0], vec![]), Actor::Operator);
    assert_eq!(
        refused(&a, set(vec![0, 1], vec![]), Actor::Customer),
        FORBIDDEN
    );
    let two = apply(&a, set(vec![0, 1], vec![p("b", 1)]), Actor::Operator);
    assert_eq!(two.door.units, vec![0, 1]);
    // Not while deleting.
    let d = apply(
        &two,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    assert_eq!(
        refused(&d, set(vec![0], vec![]), Actor::Operator),
        WRONG_STATE
    );
}

#[test]
fn limits_and_features() {
    let a = active();
    let limits = BTreeMap::from([("storage_bytes".to_string(), 1_000)]);
    unchanged(
        &a,
        Change::SetLimits {
            limits: limits.clone(),
            rate_json: None,
        },
        Actor::Operator,
    );
    let mut rate = serde_json::Map::new();
    rate.insert("class".into(), serde_json::json!("standard"));
    let r = apply(
        &a,
        Change::SetLimits {
            limits: limits.clone(),
            rate_json: Some(rate.clone()),
        },
        Actor::Billing,
    );
    assert_eq!(r.door.rate_json, rate);
    assert_eq!(
        refused(
            &a,
            Change::SetLimits {
                limits: BTreeMap::new(),
                rate_json: None
            },
            Actor::ShredJob
        ),
        FORBIDDEN
    );
    // In deleting: limits change, features do not.
    let d = apply(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    apply(
        &d,
        Change::SetLimits {
            limits: BTreeMap::new(),
            rate_json: None,
        },
        Actor::Operator,
    );
    let mut f = serde_json::Map::new();
    f.insert("webdav".into(), serde_json::json!(true));
    assert_eq!(
        refused(
            &d,
            Change::SetFeatures {
                features_json: f.clone()
            },
            Actor::Operator
        ),
        WRONG_STATE
    );
    let on = apply(
        &a,
        Change::SetFeatures {
            features_json: f.clone(),
        },
        Actor::Customer,
    );
    assert_eq!(on.door.features_json, f);
}

#[test]
fn each_record_is_the_next_seq_of_its_head() {
    let a = active();
    let b = apply(&a, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    assert_eq!(b.door.seq, a.door.seq + 1);
    assert_eq!(b.door.written_at, NOW);
    // A head of another tenant is refused.
    let other = TenantId::parse("t_00000000000000b2").unwrap();
    assert_eq!(
        next(&other, Some(&a), &billing_hold(None), Actor::Billing, NOW),
        Err(INVALID)
    );
}

#[test]
fn closing_and_opening_order() {
    let a = active();
    let order =
        |prev: &TenantRecord, next: &TenantRecord| write_order(Some(&prev.door), &next.door);
    assert_eq!(write_order(None, &a.door), WriteOrder::Opening);

    let held = apply(&a, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    assert_eq!(order(&a, &held), WriteOrder::Closing);
    let stricter = apply(&held, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    assert_eq!(order(&held, &stricter), WriteOrder::Closing);
    let milder = apply(
        &stricter,
        billing_hold(Some(HoldMode::ReadOnly)),
        Actor::Billing,
    );
    assert_eq!(order(&stricter, &milder), WriteOrder::Opening);
    let lifted = apply(&milder, billing_hold(None), Actor::Billing);
    assert_eq!(order(&milder, &lifted), WriteOrder::Opening);

    let d = apply(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    assert_eq!(order(&a, &d), WriteOrder::Closing);
    let undone = apply(&d, Change::UndoDeletion, Actor::Customer);
    assert_eq!(order(&d, &undone), WriteOrder::Opening);

    let lower = apply(
        &a,
        Change::SetLimits {
            limits: BTreeMap::from([("storage_bytes".to_string(), 10)]),
            rate_json: None,
        },
        Actor::Operator,
    );
    assert_eq!(order(&a, &lower), WriteOrder::Closing);
    let raise = apply(
        &lower,
        Change::SetLimits {
            limits: BTreeMap::from([("storage_bytes".to_string(), 10_000)]),
            rate_json: None,
        },
        Actor::Operator,
    );
    assert_eq!(order(&lower, &raise), WriteOrder::Opening);
    // A new limit where there was none closes a door.
    let added = apply(
        &a,
        Change::SetLimits {
            limits: BTreeMap::from([
                ("storage_bytes".to_string(), 1_000),
                ("upload_24h_bytes".to_string(), 5),
            ]),
            rate_json: None,
        },
        Actor::Operator,
    );
    assert_eq!(order(&a, &added), WriteOrder::Closing);

    let r = apply(&a, Change::SetRestoring { unit: 0 }, Actor::Operator);
    assert_eq!(order(&a, &r), WriteOrder::Closing);
    let since = r.door.restoring[0].since_seq;
    let l = apply(
        &r,
        Change::LiftRestoring {
            unit: 0,
            since_seq: since,
        },
        Actor::RestoreTool,
    );
    assert_eq!(order(&r, &l), WriteOrder::Opening);

    let preserve = apply(
        &a,
        operator_hold(HoldMode::ReadOnly, OperatorReason::Other, Some(true)),
        Actor::Operator,
    );
    let no_preserve = apply(
        &preserve,
        operator_hold(HoldMode::ReadOnly, OperatorReason::Other, Some(false)),
        Actor::Operator,
    );
    assert_eq!(order(&preserve, &no_preserve), WriteOrder::Opening);
    let preserve_again = apply(
        &no_preserve,
        operator_hold(HoldMode::ReadOnly, OperatorReason::Other, Some(true)),
        Actor::Operator,
    );
    assert_eq!(order(&no_preserve, &preserve_again), WriteOrder::Closing);
}

fn tenant_zero() -> TenantRecord {
    let Ok(Outcome::Next(z)) = next(
        &TenantId::zero(),
        None,
        &Change::CreateTenantZero {
            jurisdiction: "us".into(),
        },
        Actor::Operator,
        NOW,
    ) else {
        panic!("tenant 0");
    };
    z
}

/// Tenant 0 has no tenant key: it is never deleted and never shredded.
#[test]
fn tenant_zero_is_never_deleted_or_shredded() {
    let z = tenant_zero();
    for (change, actor) in [
        (
            delete_by(
                Actor::Customer,
                DeletionReason::CustomerRequest,
                30 * DAY,
                1,
            ),
            Actor::Customer,
        ),
        (
            delete_by(
                Actor::Operator,
                DeletionReason::Operator(OperatorReason::Other),
                30 * DAY,
                2,
            ),
            Actor::Operator,
        ),
    ] {
        assert_eq!(refused(&z, change, actor), TENANT_ZERO);
    }
    // Not even from a head that a damaged writer left deleting.
    let mut planted = z.clone();
    planted.door.deletion = Some(Deletion {
        shred_due_at: NOW,
        reason: DeletionReason::CustomerRequest,
        actor: ActorClass::Customer,
        key_hash: hash(1),
    });
    assert_eq!(
        refused(&planted, Change::StartShred, Actor::ShredJob),
        TENANT_ZERO
    );
}

#[test]
fn every_deletion_keeps_its_minimum_hold() {
    let a = active();
    // The customer plane: 7 days, less the hour of tolerance.
    let c = |ms| delete_by(Actor::Customer, DeletionReason::CustomerRequest, ms, 1);
    assert_eq!(refused(&a, c(DAY), Actor::Customer), HOLD_PERIOD);
    assert_eq!(
        refused(&a, c(CUSTOMER_DELETE_MIN_MS - 1), Actor::Customer),
        HOLD_PERIOD
    );
    apply(&a, c(CUSTOMER_DELETE_MIN_MS), Actor::Customer);
    // The operator's delete-now: 1 hour, less a minute.
    let o = |ms| {
        delete_by(
            Actor::Operator,
            DeletionReason::Operator(OperatorReason::Abuse),
            ms,
            2,
        )
    };
    assert_eq!(refused(&a, o(60_000), Actor::Operator), HOLD_PERIOD);
    assert_eq!(
        refused(&a, o(OPERATOR_DELETE_MIN_MS - 1), Actor::Operator),
        HOLD_PERIOD
    );
    apply(&a, o(OPERATOR_DELETE_MIN_MS), Actor::Operator);
}

/// A version that a deletion voided stays claimed: it is never used again.
#[test]
fn a_voided_key_version_is_never_claimed_again() {
    let a = active();
    assert_eq!(a.door.highest_claimed, 1);
    let c = apply(
        &a,
        Change::ClaimKeyVersion { version: 2 },
        Actor::RotationJob,
    );
    assert_eq!(c.door.highest_claimed, 2);
    let d = apply(
        &c,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    assert_eq!((d.door.rotating_to, d.door.highest_claimed), (None, 2));
    let undone = apply(&d, Change::UndoDeletion, Actor::Customer);
    assert_eq!(
        refused(
            &undone,
            Change::ClaimKeyVersion { version: 2 },
            Actor::RotationJob
        ),
        VERSION
    );
    let c3 = apply(
        &undone,
        Change::ClaimKeyVersion { version: 3 },
        Actor::RotationJob,
    );
    let done = apply(
        &c3,
        Change::CommitKeyVersion { version: 3 },
        Actor::RotationJob,
    );
    assert_eq!((done.door.tk_version, done.door.highest_claimed), (3, 3));
}

#[test]
fn a_bucket_moves_only_to_a_newer_epoch() {
    let a = active();
    let p = |unit, epoch| Placement {
        bucket: "b".into(),
        unit,
        epoch,
    };
    let set = |placements| Change::SetUnits {
        units: vec![0, 1],
        placements,
    };
    let at5 = apply(&a, set(vec![p(0, 5)]), Actor::Operator);
    // To another unit at the same or an older epoch: refused.
    assert_eq!(refused(&at5, set(vec![p(1, 5)]), Actor::Operator), INVALID);
    assert_eq!(refused(&at5, set(vec![p(1, 1)]), Actor::Operator), INVALID);
    // In place, the epoch never goes back.
    assert_eq!(refused(&at5, set(vec![p(0, 4)]), Actor::Operator), INVALID);
    let moved = apply(&at5, set(vec![p(1, 6)]), Actor::Operator);
    assert_eq!(moved.door.placements, vec![p(1, 6)]);
    assert_eq!(moved.door.max_move_epoch, 6);
    // Dropped and placed again, it takes an epoch above every one before.
    let dropped = apply(&moved, set(vec![]), Actor::Operator);
    assert_eq!(dropped.door.max_move_epoch, 6);
    assert_eq!(
        refused(&dropped, set(vec![p(1, 1)]), Actor::Operator),
        INVALID
    );
    assert_eq!(
        refused(&dropped, set(vec![p(1, 6)]), Actor::Operator),
        INVALID
    );
    apply(&dropped, set(vec![p(1, 7)]), Actor::Operator);
}

/// Who may is checked before "the head carries it": a refused actor gets
/// its 403 for a no-op too.
#[test]
fn a_forbidden_no_op_is_still_forbidden() {
    let a = active();
    assert_eq!(refused(&a, billing_hold(None), Actor::Customer), FORBIDDEN);
    let b = apply(&a, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    assert_eq!(
        refused(&b, billing_hold(Some(HoldMode::Locked)), Actor::Customer),
        FORBIDDEN
    );
    // The operator places no billing hold, not even the one in force.
    assert_eq!(
        refused(&b, billing_hold(Some(HoldMode::Locked)), Actor::Operator),
        FORBIDDEN
    );
    // Lifting one that is not there is the operator's to do: no record.
    unchanged(&a, billing_hold(None), Actor::Operator);
    assert_eq!(
        refused(&a, Change::SetOperatorHold { hold: None }, Actor::Billing),
        FORBIDDEN
    );
}

/// A set-deletion retried after its record landed applies the head and
/// writes nothing; another key is another request.
#[test]
fn a_retried_deletion_is_unchanged() {
    let a = active();
    let first = delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1);
    let d = apply(&a, first.clone(), Actor::Customer);
    unchanged(&d, first, Actor::Customer);
    assert_eq!(
        refused(
            &d,
            delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 2),
            Actor::Customer
        ),
        DELETING
    );
    // The same key from another plane is not a retry.
    assert_eq!(
        refused(
            &d,
            delete_by(
                Actor::Operator,
                DeletionReason::Operator(OperatorReason::Legal),
                7 * DAY,
                1
            ),
            Actor::Operator
        ),
        DELETING
    );
}

/// Flags and tenant 0's selector cannot be ranked: any change of them is
/// closing.
#[test]
fn a_flag_or_selector_change_is_closing() {
    let a = active();
    let mut on = serde_json::Map::new();
    on.insert("webdav".into(), serde_json::json!(true));
    let with = apply(
        &a,
        Change::SetFeatures {
            features_json: on.clone(),
        },
        Actor::Operator,
    );
    let mut off = on.clone();
    off.insert("webdav".into(), serde_json::json!(false));
    let without = apply(
        &with,
        Change::SetFeatures { features_json: off },
        Actor::Operator,
    );
    assert_eq!(
        write_order(Some(&with.door), &without.door),
        WriteOrder::Closing
    );

    let z = tenant_zero();
    let mut moved = z.door.clone();
    moved.tenant_zero = Some(TenantZero {
        selector: Selector::Moved { to: t1() },
        cutover_stamp: Some(1),
        undo_stamp: None,
        catalogue_id: None,
    });
    assert_eq!(write_order(Some(&z.door), &moved), WriteOrder::Closing);
}

/// The workspace is bound at activation, the first record under the
/// tenant's own key.
#[test]
fn the_workspace_is_bound_at_activation() {
    let a = active();
    assert_eq!(a.private.external_ref.as_deref(), Some("ws_1"));
    assert_eq!(a.door.tk_version, 1);
}
