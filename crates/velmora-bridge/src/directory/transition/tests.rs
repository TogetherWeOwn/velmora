//! The rules of the tenant state table, one test or more per rule.

use super::*;
use crate::directory::record::{S3Access, TenantState};

const DAY: i64 = 24 * 3_600_000;
const NOW: UnixMs = UnixMs(1_800_000_000_000);

fn t1() -> Tenant {
    Tenant::parse("t_00000000000000a1").unwrap()
}

/// The commit of `version` with the check value of a test key.
fn commit(version: u32) -> Change {
    Change::CommitKeyVersion {
        version,
        kcv: [version as u8; KEY_CHECK_LEN],
    }
}

/// The derived id of the bucket whose creator grant is `t1`'s key-chain
/// record `k`.
fn bid(k: u64) -> String {
    crate::records::bucket_id(t1().managed().unwrap(), k)
        .as_str()
        .to_owned()
}

/// A create of the bucket under creator grant `k`, on `unit`.
fn create_bucket(k: u64, unit: u32) -> Change {
    Change::CreateBucket {
        bucket: bid(k),
        unit,
        creator: "p_owner".into(),
        grant_seq: k,
        name: format!("bucket-{k}"),
        bdk_wrapped: wrap(k as u8),
    }
}

/// A BDK wrap of the scheme-2 form (`0x02`, 73 bytes).
fn wrap(n: u8) -> Vec<u8> {
    let mut w = vec![n; crate::crypto::WRAPPED_KEY_LEN];
    w[0] = crate::crypto::scheme2::WRAP_VERSION_2;
    w
}

/// `r` with `bucket` placed on `unit` (listed if it was not) at the next
/// epoch, as a create or a move's place leaves it: the start of the
/// tests that move placed buckets.
fn placed(mut r: TenantRecord, bucket: &str, unit: u32) -> TenantRecord {
    if !r.door.units.contains(&unit) {
        r.door.units.push(unit);
        r.door.units.sort_unstable();
    }
    let epoch = r.door.max_move_epoch + 1;
    r.door.placements.push(Placement {
        bucket: bucket.into(),
        unit,
        epoch,
    });
    r.door.max_move_epoch = epoch;
    r
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

/// A `base_seq` that `step` fills with the head's seq: most tests are
/// not about a stale base.
const ANY: u64 = u64::MAX;

fn step(head: Option<&TenantRecord>, mut change: Change, actor: Actor) -> Result<Outcome, Refusal> {
    let tenant = head.map(|h| h.door.tenant.clone()).unwrap_or_else(t1);
    if let (
        Some(h),
        Change::SetLimits { base_seq, .. }
        | Change::SetFeatures { base_seq, .. }
        | Change::SetUnits { base_seq, .. },
    ) = (head, &mut change)
    {
        if *base_seq == ANY {
            *base_seq = h.door.seq;
        }
    }
    // An undo that names the deletion as the caller read it: the head's,
    // or the last one undone.
    if let (Some(h), Change::UndoDeletion { deletion_seq }) = (head, &mut change) {
        if *deletion_seq == ANY {
            *deletion_seq = match (&h.door.deletion, h.door.undone_deletion_seq) {
                (Some(d), _) => d.seq,
                (None, Some(seq)) => seq,
                (None, None) => 0,
            };
        }
    }
    next(&tenant, head, &change, actor, NOW)
}

/// Applies a change that must produce a record.
fn apply(head: &TenantRecord, change: Change, actor: Actor) -> TenantRecord {
    match step(Some(head), change, actor) {
        Ok(Outcome::Next(r)) => r,
        Ok(Outcome::Unchanged) => panic!("unchanged, by {actor:?}"),
        Err(r) => panic!("refused {}, by {actor:?}", r.code),
    }
}

fn refused(head: &TenantRecord, change: Change, actor: Actor) -> Refusal {
    match step(Some(head), change, actor) {
        Err(r) => r,
        Ok(_) => panic!("not refused, by {actor:?}"),
    }
}

fn unchanged(head: &TenantRecord, change: Change, actor: Actor) {
    assert!(
        matches!(step(Some(head), change, actor), Ok(Outcome::Unchanged)),
        "not unchanged, by {actor:?}"
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
    let r = apply(&r, commit(1), Actor::TenantCreation);
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
    let zero = Tenant::zero();
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
                base_seq: ANY,
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
    assert_eq!(
        refused(
            &d,
            Change::UndoDeletion { deletion_seq: ANY },
            Actor::Billing
        ),
        FORBIDDEN
    );
    let undone = apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
    assert_eq!(undone.door.state(), TenantState::Active);
    apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Operator,
    );

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
        refused(
            &od,
            Change::UndoDeletion { deletion_seq: ANY },
            Actor::Customer
        ),
        FORBIDDEN
    );
    apply(
        &od,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Operator,
    );

    // Undo without a deletion, and none undone before.
    assert_eq!(
        refused(
            &a,
            Change::UndoDeletion { deletion_seq: ANY },
            Actor::Operator
        ),
        NOT_REQUESTED
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
    let undone = apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
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
    apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Billing,
    );
    assert_eq!(
        refused(
            &d,
            Change::UndoDeletion { deletion_seq: ANY },
            Actor::Customer
        ),
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
        // The undo of AM-38 case 4 finds it by its seq.
        assert_eq!(paid.door.undone_deletion_seq, Some(d.door.seq));
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
    let undone = apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
    let replay = delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1);
    assert_eq!(refused(&undone, replay.clone(), Actor::Customer), REPLAYED);
    // A new key is a new request.
    let d2 = apply(
        &undone,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 2),
        Actor::Customer,
    );
    let undone2 = apply(
        &d2,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
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
    let undone = apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
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
    // Tenant creation claims for a provisioning tenant only.
    assert_eq!(
        refused(
            &a,
            Change::ClaimKeyVersion { version: 2 },
            Actor::TenantCreation
        ),
        WRONG_STATE
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
    assert_eq!(refused(&c, commit(3), Actor::RotationJob), NO_CLAIM);
    let done = apply(&c, commit(2), Actor::RotationJob);
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
    let a = placed(active(), "b_1", 0);
    let two = apply(
        &a,
        Change::SetUnits {
            base_seq: ANY,
            units: vec![0, 1],
            placements: vec![Placement {
                bucket: "b_1".into(),
                unit: 1,
                epoch: 2,
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
    let r = apply(
        &r,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
    let r = apply(
        &r,
        Change::SetLimits {
            base_seq: ANY,
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
                base_seq: ANY,
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
        (Change::UndoDeletion { deletion_seq: ANY }, Actor::Operator),
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
    for change in [
        Change::FinishShred,
        Change::UndoDeletion { deletion_seq: ANY },
        create(),
    ] {
        assert_eq!(refused(&gone, change, Actor::Operator), SHREDDED);
    }
}

#[test]
fn units_and_placements_are_checked() {
    let a = active();
    let set = |units: Vec<u32>, placements: Vec<Placement>| Change::SetUnits {
        base_seq: ANY,
        units,
        placements,
    };
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
    // A new id is never placed by a unit change.
    assert_eq!(
        refused(&a, set(vec![0, 1], vec![p("b", 1)]), Actor::Operator),
        NOT_PLACED
    );
    let a = placed(a, "b", 0);
    let two = apply(&a, set(vec![0, 1], vec![p("b", 0)]), Actor::Operator);
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
            base_seq: ANY,
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
            base_seq: ANY,
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
                base_seq: ANY,
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
            base_seq: ANY,
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
                base_seq: ANY,
                features_json: f.clone()
            },
            Actor::Operator
        ),
        WRONG_STATE
    );
    let on = apply(
        &a,
        Change::SetFeatures {
            base_seq: ANY,
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
    let other = Tenant::parse("t_00000000000000b2").unwrap();
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
    let undone = apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
    assert_eq!(order(&d, &undone), WriteOrder::Opening);

    let lower = apply(
        &a,
        Change::SetLimits {
            base_seq: ANY,
            limits: BTreeMap::from([("storage_bytes".to_string(), 10)]),
            rate_json: None,
        },
        Actor::Operator,
    );
    assert_eq!(order(&a, &lower), WriteOrder::Closing);
    let raise = apply(
        &lower,
        Change::SetLimits {
            base_seq: ANY,
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
            base_seq: ANY,
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
        &Tenant::zero(),
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
        seq: planted.door.seq,
        requested_at: NOW,
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
    let undone = apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
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
    let done = apply(&c3, commit(3), Actor::RotationJob);
    assert_eq!((done.door.tk_version, done.door.highest_claimed), (3, 3));
}

#[test]
fn a_bucket_moves_only_to_the_next_epoch() {
    let a = active();
    let p = |unit, epoch| Placement {
        bucket: "b".into(),
        unit,
        epoch,
    };
    let set = |placements| Change::SetUnits {
        base_seq: ANY,
        units: vec![0, 1],
        placements,
    };
    // It places no new id: only a create or a move's place does.
    assert_eq!(refused(&a, set(vec![p(0, 1)]), Actor::Operator), NOT_PLACED);
    let mut at1 = placed(a, "b", 0);
    at1.door.units = vec![0, 1];
    assert_eq!(at1.door.max_move_epoch, 1);
    // In place, the epoch neither goes back nor up.
    assert_eq!(refused(&at1, set(vec![p(0, 0)]), Actor::Operator), INVALID);
    assert_eq!(refused(&at1, set(vec![p(0, 9)]), Actor::Operator), INVALID);
    unchanged(&at1, set(vec![p(0, 1)]), Actor::Operator);
    // To another unit: the next epoch, never the same or a far one.
    assert_eq!(refused(&at1, set(vec![p(1, 1)]), Actor::Operator), INVALID);
    assert_eq!(
        refused(&at1, set(vec![p(1, u64::MAX)]), Actor::Operator),
        INVALID
    );
    let moved = apply(&at1, set(vec![p(1, 2)]), Actor::Operator);
    assert_eq!(moved.door.placements, vec![p(1, 2)]);
    assert_eq!(moved.door.max_move_epoch, 2);
    // Dropped, the id is not placed again by a move; the next bucket
    // takes the epoch above every one before.
    let dropped = apply(&moved, set(vec![]), Actor::Operator);
    assert_eq!(dropped.door.max_move_epoch, 2);
    assert_eq!(
        refused(&dropped, set(vec![p(1, 2)]), Actor::Operator),
        INVALID
    );
    assert_eq!(
        refused(&dropped, set(vec![p(1, 3)]), Actor::Operator),
        NOT_PLACED
    );
    let next = apply(&dropped, create_bucket(1, 1), Actor::Customer);
    assert_eq!(next.door.placements[0].epoch, 3);
}

/// A change that replaces a whole field names the head it was built from:
/// against a newer head it is refused, so it never undoes a change it did
/// not see.
#[test]
fn a_whole_field_change_on_a_stale_base_is_refused() {
    let a = active();
    let stale = a.door.seq - 1;
    let changes = [
        (
            Change::SetLimits {
                base_seq: stale,
                limits: BTreeMap::new(),
                rate_json: None,
            },
            Actor::Billing,
        ),
        (
            Change::SetFeatures {
                base_seq: stale,
                features_json: Default::default(),
            },
            Actor::Operator,
        ),
        (
            Change::SetUnits {
                base_seq: stale,
                units: a.door.units.clone(),
                placements: a.door.placements.clone(),
            },
            Actor::Operator,
        ),
    ];
    for (change, actor) in changes {
        // Refused even where the change would be a no-op on this head.
        assert_eq!(refused(&a, change, actor), STALE_BASE);
    }
    // A base newer than the head is refused too.
    assert_eq!(
        refused(
            &a,
            Change::SetFeatures {
                base_seq: a.door.seq + 1,
                features_json: Default::default(),
            },
            Actor::Operator
        ),
        STALE_BASE
    );
}

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
            base_seq: ANY,
            features_json: on.clone(),
        },
        Actor::Operator,
    );
    let mut off = on.clone();
    off.insert("webdav".into(), serde_json::json!(false));
    let without = apply(
        &with,
        Change::SetFeatures {
            base_seq: ANY,
            features_json: off,
        },
        Actor::Operator,
    );
    assert_eq!(
        write_order(Some(&with.door), &without.door),
        WriteOrder::Closing
    );

    let z = tenant_zero();
    let mut moved = z.door.clone();
    moved.tenant_zero = Some(TenantZero {
        selector: Selector::Moving,
        moved: Some(Move {
            to: t1(),
            catalogue_id_frozen: "main".into(),
            stamp: None,
            flipped_at: None,
            levelled_to: None,
        }),
        undo_stamp: None,
        catalogue_id: None,
        frozen_catalogues: vec!["main".into()],
        flips: 0,
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

#[test]
fn a_voided_claim_moves_to_the_next_version_in_one_record() {
    // During creation: version 1's copies disagree, so 2 is claimed.
    let Ok(Outcome::Next(p)) = step(None, create(), Actor::TenantCreation) else {
        panic!("create");
    };
    let c1 = apply(
        &p,
        Change::ClaimKeyVersion { version: 1 },
        Actor::TenantCreation,
    );
    assert_eq!(
        refused(
            &c1,
            Change::VoidKeyClaim { version: 2 },
            Actor::TenantCreation
        ),
        NO_CLAIM
    );
    let c2 = apply(
        &c1,
        Change::VoidKeyClaim { version: 1 },
        Actor::TenantCreation,
    );
    assert_eq!((c2.door.rotating_to, c2.door.highest_claimed), (Some(2), 2));
    assert_eq!(refused(&c2, commit(1), Actor::TenantCreation), NO_CLAIM);
    let done = apply(&c2, commit(2), Actor::TenantCreation);
    let a = apply(
        &done,
        Change::Activate { external_ref: None },
        Actor::TenantCreation,
    );
    assert_eq!(a.door.tk_version, 2);
    assert_eq!(
        a.door.key_checks.get(&2).map(String::as_str),
        Some("0202020202020202")
    );
    // The rotation job voids on a live tenant; only the open claim.
    assert_eq!(
        refused(&a, Change::VoidKeyClaim { version: 2 }, Actor::RotationJob),
        NO_CLAIM
    );
    let r = apply(
        &a,
        Change::ClaimKeyVersion { version: 3 },
        Actor::RotationJob,
    );
    let r = apply(&r, Change::VoidKeyClaim { version: 3 }, Actor::RotationJob);
    assert_eq!(r.door.rotating_to, Some(4));
    assert_eq!(
        refused(&r, Change::VoidKeyClaim { version: 4 }, Actor::Operator),
        FORBIDDEN
    );
}

#[test]
fn a_commit_pins_the_key_check_value() {
    let a = active();
    assert_eq!(a.door.key_checks.len(), 1);
    // The same commit again is unchanged; another key is refused.
    unchanged(&a, commit(1), Actor::RotationJob);
    unchanged(&a, commit(1), Actor::TenantCreation);
    assert_eq!(
        refused(
            &a,
            Change::CommitKeyVersion {
                version: 1,
                kcv: [9; KEY_CHECK_LEN]
            },
            Actor::RotationJob
        ),
        KEY_CHECK
    );
    let c = apply(
        &a,
        Change::ClaimKeyVersion { version: 2 },
        Actor::RotationJob,
    );
    let done = apply(&c, commit(2), Actor::RotationJob);
    // Every committed version keeps its value.
    assert_eq!(done.door.key_checks.len(), 2);
    assert_eq!(done.door.key_checks[&1], "0101010101010101");
}

fn moving() -> TenantRecord {
    let z = tenant_zero();
    apply(
        &z,
        Change::StartMove {
            to: t1(),
            catalogue_id_frozen: "main".into(),
        },
        Actor::MoveTool,
    )
}

#[test]
fn the_move_of_tenant_zero_runs_its_window_flip_and_retirement() {
    let z = tenant_zero();
    let start = Change::StartMove {
        to: t1(),
        catalogue_id_frozen: "main".into(),
    };
    // The move tool only, and on tenant 0 only.
    assert_eq!(refused(&z, start.clone(), Actor::Operator), FORBIDDEN);
    assert_eq!(
        refused(&active(), start.clone(), Actor::MoveTool),
        NOT_TENANT_ZERO
    );
    assert_eq!(
        refused(
            &z,
            Change::StartMove {
                to: Tenant::zero(),
                catalogue_id_frozen: "main".into()
            },
            Actor::MoveTool
        ),
        INVALID
    );
    let m = moving();
    let zm = m.door.tenant_zero.clone().unwrap();
    assert_eq!(zm.selector, Selector::Moving);
    assert_eq!(zm.moved.as_ref().unwrap().to, t1());
    // A repeated window start is unchanged; another target is refused.
    unchanged(&m, start, Actor::MoveTool);
    assert_eq!(
        refused(
            &m,
            Change::StartMove {
                to: Tenant::parse("t_00000000000000b2").unwrap(),
                catalogue_id_frozen: "main".into()
            },
            Actor::MoveTool
        ),
        SELECTOR
    );
    // No flip before the window, no flip at stamp 0.
    assert_eq!(
        refused(&z, Change::FlipMove { stamp: 9 }, Actor::MoveTool),
        SELECTOR
    );
    assert_eq!(
        refused(&m, Change::FlipMove { stamp: 0 }, Actor::MoveTool),
        INVALID
    );
    let flipped = apply(&m, Change::FlipMove { stamp: 9 }, Actor::MoveTool);
    let zf = flipped.door.tenant_zero.clone().unwrap();
    assert_eq!(zf.selector, Selector::Moved);
    assert_eq!(zf.moved.as_ref().unwrap().stamp, Some(9));
    assert_eq!(zf.moved.as_ref().unwrap().flipped_at, Some(NOW));
    // Step 8 runs again after a crash: unchanged.
    unchanged(&flipped, Change::FlipMove { stamp: 9 }, Actor::MoveTool);
    assert_eq!(
        refused(&flipped, Change::FlipMove { stamp: 10 }, Actor::MoveTool),
        SELECTOR
    );
    assert_eq!(
        refused(&flipped, Change::GiveUpMove, Actor::MoveTool),
        SELECTOR
    );
    // Retirement 30 days after the flip, and nothing after it.
    assert_eq!(
        refused(&flipped, Change::RetireTenantZero, Actor::MoveTool),
        NOT_DUE
    );
    let later = UnixMs(NOW.0 + RETIRE_AFTER_MS);
    let Ok(Outcome::Next(retired)) = next(
        &Tenant::zero(),
        Some(&flipped),
        &Change::RetireTenantZero,
        Actor::MoveTool,
        later,
    ) else {
        panic!("retire");
    };
    assert_eq!(
        retired.door.tenant_zero.as_ref().unwrap().selector,
        Selector::Retired
    );
    unchanged(&retired, Change::RetireTenantZero, Actor::MoveTool);
    for (change, actor) in [
        (
            operator_hold(HoldMode::Locked, OperatorReason::Other, None),
            Actor::Operator,
        ),
        (Change::GiveUpMove, Actor::MoveTool),
        (
            Change::UndoMove {
                undo_stamp: 99,
                catalogue_id: "main2".into(),
            },
            Actor::MoveTool,
        ),
    ] {
        assert_eq!(refused(&retired, change, actor), RETIRED);
    }
    // A d1 tenant 0 is not retired.
    assert_eq!(
        refused(&z, Change::RetireTenantZero, Actor::MoveTool),
        SELECTOR
    );
}

#[test]
fn the_move_is_given_up_before_its_flip_and_undone_after_it() {
    let m = moving();
    let back = apply(&m, Change::GiveUpMove, Actor::MoveTool);
    let zb = back.door.tenant_zero.clone().unwrap();
    assert_eq!((zb.selector, zb.moved), (Selector::D1, None));
    unchanged(&back, Change::GiveUpMove, Actor::MoveTool);
    // A second window after a give-up.
    let again = apply(
        &back,
        Change::StartMove {
            to: t1(),
            catalogue_id_frozen: "main".into(),
        },
        Actor::MoveTool,
    );
    let flipped = apply(&again, Change::FlipMove { stamp: 9 }, Actor::MoveTool);
    let undo = |undo_stamp, id: &str| Change::UndoMove {
        undo_stamp,
        catalogue_id: id.into(),
    };
    // The undo needs a stamp above the flip's and a fresh catalogue.
    assert_eq!(
        refused(&flipped, undo(9, "main2"), Actor::MoveTool),
        INVALID
    );
    assert_eq!(
        refused(&flipped, undo(10, "main"), Actor::MoveTool),
        INVALID
    );
    assert_eq!(
        refused(&flipped, undo(10, "bad id"), Actor::MoveTool),
        INVALID
    );
    assert_eq!(
        refused(&again, undo(10, "main2"), Actor::MoveTool),
        SELECTOR
    );
    let undone = apply(&flipped, undo(10, "main2"), Actor::MoveTool);
    let zu = undone.door.tenant_zero.clone().unwrap();
    assert_eq!(zu.selector, Selector::D1);
    assert_eq!(
        (zu.undo_stamp, zu.catalogue_id.as_deref()),
        (Some(10), Some("main2"))
    );
    // The move stays as history, and the undo is plain from the record.
    assert_eq!(zu.moved.as_ref().unwrap().stamp, Some(9));
    assert!(zu.undone());
    unchanged(&undone, undo(10, "main2"), Actor::MoveTool);
    // A later move again from the undone state.
    let third = apply(
        &undone,
        Change::StartMove {
            to: t1(),
            catalogue_id_frozen: "main2".into(),
        },
        Actor::MoveTool,
    );
    let z3 = third.door.tenant_zero.unwrap();
    assert_eq!(z3.selector, Selector::Moving);
    assert_eq!(z3.undo_stamp, None);
    assert_eq!(z3.catalogue_id.as_deref(), Some("main2"));
}

#[test]
fn an_escrowed_tenant_waits_for_its_escrow_to_be_destroyed_before_a_shred() {
    let a = active();
    assert_eq!(
        refused(&a, Change::SetEscrowOffline, Actor::Customer),
        FORBIDDEN
    );
    assert_eq!(
        refused(&a, Change::SetEscrowOffline, Actor::Billing),
        FORBIDDEN
    );
    let e = apply(&a, Change::SetEscrowOffline, Actor::Operator);
    assert!(e.door.escrow_offline);
    unchanged(&e, Change::SetEscrowOffline, Actor::Operator);
    let d = apply(
        &e,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    let due = UnixMs(NOW.0 + 7 * DAY);
    let shred = |h: &TenantRecord| next(&t1(), Some(h), &Change::StartShred, Actor::ShredJob, due);
    assert_eq!(shred(&d), Err(ESCROWED));
    assert_eq!(
        refused(
            &d,
            Change::ClearEscrowOffline { destroyed: vec![] },
            Actor::Operator
        ),
        INVALID
    );
    assert_eq!(
        refused(
            &d,
            Change::ClearEscrowOffline {
                destroyed: vec!["ab".repeat(32)]
            },
            Actor::Customer
        ),
        FORBIDDEN
    );
    let cleared = apply(
        &d,
        Change::ClearEscrowOffline {
            destroyed: vec!["ab".repeat(32)],
        },
        Actor::Operator,
    );
    assert!(matches!(shred(&cleared), Ok(Outcome::Next(_))));
}

#[test]
fn a_bucket_create_names_its_creator_in_its_own_record_only() {
    let a = active();
    assert_eq!(refused(&a, create_bucket(1, 0), Actor::Billing), FORBIDDEN);
    assert_eq!(
        refused(&a, create_bucket(1, 3), Actor::Customer),
        UNIT_NOT_LISTED
    );
    let mut no_creator = create_bucket(1, 0);
    if let Change::CreateBucket { creator, .. } = &mut no_creator {
        creator.clear();
    }
    assert_eq!(refused(&a, no_creator, Actor::Customer), INVALID);
    let b = apply(&a, create_bucket(1, 0), Actor::Customer);
    assert_eq!(
        b.door.bucket_created,
        Some(BucketCreated {
            bucket: bid(1),
            creator: "p_owner".into(),
            grant_seq: 1,
        })
    );
    assert_eq!(b.door.placements[0].epoch, 1);
    assert_eq!(b.door.last_grant_seq, 1);
    // The same create read back after a lost answer writes nothing.
    unchanged(&b, create_bucket(1, 0), Actor::Customer);
    // The next record of any kind carries no creator.
    let next_rec = apply(&b, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    assert_eq!(next_rec.door.bucket_created, None);
    assert_eq!(next_rec.door.last_grant_seq, 1);
    // Not while suspended, deleting or restoring.
    assert_eq!(
        refused(&next_rec, create_bucket(2, 0), Actor::Customer),
        WRONG_STATE
    );
    let r = apply(&b, Change::SetRestoring { unit: 0 }, Actor::Operator);
    assert_eq!(refused(&r, create_bucket(2, 0), Actor::Operator), RESTORING);
    // Dropping a bucket; dropping it again is unchanged.
    let dropped = apply(&b, Change::DropBucket { bucket: bid(1) }, Actor::Customer);
    assert!(dropped.door.placements.is_empty());
    unchanged(
        &dropped,
        Change::DropBucket { bucket: bid(1) },
        Actor::Customer,
    );
    // A dropped id is never made again, also not by the operator: its
    // grant seq is not above the last one. A new bucket takes a newer
    // epoch, and the record keeps no list of dropped ids.
    for actor in [Actor::Customer, Actor::Operator] {
        assert_eq!(refused(&dropped, create_bucket(1, 0), actor), GRANT_ORDER);
    }
    let again = apply(&dropped, create_bucket(2, 0), Actor::Operator);
    assert_eq!(again.door.placements[0].epoch, 2);
    assert_eq!(again.door.last_grant_seq, 2);
    // Tenant 0 makes no bucket here: it has no unit and no derived ids.
    let mut z = tenant_zero();
    z.door.units = vec![0];
    assert_eq!(
        refused(&z, create_bucket(1, 0), Actor::Operator),
        TENANT_ZERO
    );
}

/// A new bucket's id is the derivation from its creator grant's seq, and
/// that seq is above every earlier one: no list of dropped ids, no cap.
#[test]
fn bucket_ids_are_derived_from_the_creator_grant() {
    let a = active();
    // Any other id, also another grant's, is refused.
    let mut drawn = create_bucket(1, 0);
    if let Change::CreateBucket { bucket, .. } = &mut drawn {
        *bucket = "b_0123456789abcdef".into();
    }
    assert_eq!(refused(&a, drawn, Actor::Customer), NOT_DERIVED);
    let mut other_k = create_bucket(1, 0);
    if let Change::CreateBucket { bucket, .. } = &mut other_k {
        *bucket = bid(2);
    }
    assert_eq!(refused(&a, other_k, Actor::Customer), NOT_DERIVED);
    // Another tenant's derivation for the same seq is not this one's.
    let mut theirs = create_bucket(1, 0);
    if let Change::CreateBucket { bucket, .. } = &mut theirs {
        let t2 = crate::TenantId::parse("t_00000000000000a2").unwrap();
        *bucket = crate::records::bucket_id(&t2, 1).as_str().to_owned();
    }
    assert_eq!(refused(&a, theirs, Actor::Customer), NOT_DERIVED);
    // Seqs may skip (other key-chain records sit between grants), but a
    // create whose grant lost the order to a higher one is refused: the
    // caller revokes that grant and creates again under a new one.
    let at5 = apply(&a, create_bucket(5, 0), Actor::Customer);
    assert_eq!(at5.door.last_grant_seq, 5);
    for k in [1, 4] {
        assert_eq!(
            refused(&at5, create_bucket(k, 0), Actor::Customer),
            GRANT_ORDER
        );
    }
    // Its own create again is the read-back, not a lost order.
    unchanged(&at5, create_bucket(5, 0), Actor::Customer);
    let at9 = apply(&at5, create_bucket(9, 0), Actor::Customer);
    assert_eq!(at9.door.placements.len(), 2);
    // Read back under a later head (another create, a hold, the bucket
    // moved to another unit, the tenant suspended or restoring): still
    // the same create, never a lost order that would revoke its grant.
    unchanged(&at9, create_bucket(5, 0), Actor::Customer);
    unchanged(&at9, create_bucket(5, 1), Actor::Operator);
    let held = apply(&at9, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    unchanged(&held, create_bucket(5, 0), Actor::Customer);
    let restoring = apply(&at9, Change::SetRestoring { unit: 0 }, Actor::Operator);
    unchanged(&restoring, create_bucket(9, 0), Actor::Customer);
    // A placed id under a seq never recorded is not a read-back.
    let mut planted = at9.clone();
    planted.door.last_grant_seq = 3;
    assert_eq!(
        refused(&planted, create_bucket(5, 0), Actor::Customer),
        BUCKET_EXISTS
    );
    // Create and drop without end: every create passes, no record grows.
    let mut r = at9;
    for k in 10..2_100u64 {
        r = apply(&r, create_bucket(k, 0), Actor::Customer);
        r = apply(&r, Change::DropBucket { bucket: bid(k) }, Actor::Customer);
    }
    assert_eq!(r.door.placements.len(), 2);
    assert_eq!(r.door.last_grant_seq, 2_099);
    let bytes = serde_json::to_vec(&r.door).unwrap();
    assert!(bytes.len() < 2_048, "{} bytes", bytes.len());
}

/// The owner's buckets enter the tenant only through the move: tenant 0's
/// head `moving` into this tenant, and a `restoring` entry on the unit.
#[test]
fn moved_buckets_are_placed_only_by_the_move() {
    let owner = active();
    let owner = apply(&owner, Change::SetRestoring { unit: 0 }, Actor::Operator);
    let z = tenant_zero();
    let moving = moving();
    let ids = vec![
        "b_00000000000000aa".to_string(),
        "b_00000000000000bb".to_string(),
    ];
    let place = |zero: &TenantRecord, buckets: Vec<String>, unit| Change::PlaceMovedBuckets {
        buckets,
        unit,
        zero: Box::new(zero.door.clone()),
    };
    // Only the move tool.
    for actor in [Actor::Customer, Actor::Operator, Actor::RestoreTool] {
        assert_eq!(
            refused(&owner, place(&moving, ids.clone(), 0), actor),
            FORBIDDEN
        );
    }
    // Not without a window into this tenant.
    assert_eq!(
        refused(&owner, place(&z, ids.clone(), 0), Actor::MoveTool),
        NOT_MOVING_HERE
    );
    let mut elsewhere = moving.clone();
    if let Some(m) = elsewhere
        .door
        .tenant_zero
        .as_mut()
        .and_then(|z| z.moved.as_mut())
    {
        m.to = Tenant::parse("t_00000000000000a2").unwrap();
    }
    assert_eq!(
        refused(&owner, place(&elsewhere, ids.clone(), 0), Actor::MoveTool),
        NOT_MOVING_HERE
    );
    // A door that is not tenant 0's, even one shaped like it.
    let mut planted = moving.clone();
    planted.door.tenant = t1();
    assert_eq!(
        refused(&owner, place(&planted, ids.clone(), 0), Actor::MoveTool),
        NOT_MOVING_HERE
    );
    let flipped = apply(&moving, Change::FlipMove { stamp: 7 }, Actor::MoveTool);
    assert_eq!(
        refused(&owner, place(&flipped, ids.clone(), 0), Actor::MoveTool),
        NOT_MOVING_HERE
    );
    // Not without the unit's restoring entry.
    assert_eq!(
        refused(&active(), place(&moving, ids.clone(), 0), Actor::MoveTool),
        NOT_RESTORING
    );
    assert_eq!(
        refused(&owner, place(&moving, ids.clone(), 3), Actor::MoveTool),
        UNIT_NOT_LISTED
    );
    // Malformed lists.
    let too_many: Vec<String> = (0..=MAX_MOVED_BUCKETS as u64)
        .map(|i| format!("b_{i:016x}"))
        .collect();
    for bad in [
        vec![],
        vec![String::new()],
        vec![ids[0].clone(), ids[0].clone()],
        vec!["vault".to_string()],
        vec!["b_00000000000000AA".to_string()],
        vec!["b_00000000000000a".to_string()],
        too_many,
    ] {
        assert_eq!(
            refused(&owner, place(&moving, bad, 0), Actor::MoveTool),
            INVALID
        );
    }
    // Placed, at one new epoch, named with the head that admitted them.
    let r = apply(&owner, place(&moving, ids.clone(), 0), Actor::MoveTool);
    assert_eq!(
        r.door
            .placements
            .iter()
            .map(|p| (p.bucket.as_str(), p.unit, p.epoch))
            .collect::<Vec<_>>(),
        [(ids[0].as_str(), 0, 1), (ids[1].as_str(), 0, 1)]
    );
    assert_eq!(
        r.door.buckets_moved_in,
        Some(crate::directory::record::BucketsMovedIn {
            zero_seq: moving.door.seq,
            unit: 0,
            buckets: ids.clone(),
        })
    );
    assert_eq!(r.door.last_grant_seq, 0);
    // A repeat writes nothing, also after the flip; an overlap is refused.
    unchanged(&r, place(&moving, ids.clone(), 0), Actor::MoveTool);
    unchanged(&r, place(&flipped, ids.clone(), 0), Actor::MoveTool);
    assert_eq!(
        refused(
            &r,
            place(
                &moving,
                vec![ids[1].clone(), "b_00000000000000cc".into()],
                0
            ),
            Actor::MoveTool
        ),
        BUCKET_EXISTS
    );
    // The next record does not repeat the list.
    let lifted = apply(
        &r,
        Change::LiftRestoring {
            unit: 0,
            since_seq: owner.door.restoring[0].since_seq,
        },
        Actor::RestoreTool,
    );
    assert_eq!(lifted.door.buckets_moved_in, None);
    assert_eq!(lifted.door.placements.len(), 2);
    // Tenant 0 places nothing in itself.
    assert_eq!(
        refused(&moving, place(&moving, ids.clone(), 0), Actor::MoveTool),
        TENANT_ZERO
    );
}

#[test]
fn the_shred_jobs_last_step_can_be_repeated() {
    let a = active();
    let d = apply(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 7 * DAY, 1),
        Actor::Customer,
    );
    let due = UnixMs(NOW.0 + 7 * DAY);
    let Ok(Outcome::Next(s)) = next(&t1(), Some(&d), &Change::StartShred, Actor::ShredJob, due)
    else {
        panic!("shred")
    };
    let gone = apply(&s, Change::FinishShred, Actor::ShredJob);
    unchanged(&gone, Change::FinishShred, Actor::ShredJob);
    assert_eq!(
        refused(&gone, Change::FinishShred, Actor::Operator),
        SHREDDED
    );
}

#[test]
fn a_move_freezes_the_catalogue_d1_means_and_an_undo_never_lands_on_a_frozen_one() {
    let z = tenant_zero();
    // The first move freezes today's catalogue.
    assert_eq!(
        refused(
            &z,
            Change::StartMove {
                to: t1(),
                catalogue_id_frozen: "main2".into()
            },
            Actor::MoveTool
        ),
        INVALID
    );
    let m = moving();
    assert_eq!(
        m.door.tenant_zero.as_ref().unwrap().frozen_catalogues,
        vec!["main".to_string()]
    );
    // A retry with another frozen id is no retry.
    assert_eq!(
        refused(
            &m,
            Change::StartMove {
                to: t1(),
                catalogue_id_frozen: "other".into()
            },
            Actor::MoveTool
        ),
        SELECTOR
    );
    let f = apply(&m, Change::FlipMove { stamp: 9 }, Actor::MoveTool);
    let u = apply(
        &f,
        Change::UndoMove {
            undo_stamp: 10,
            catalogue_id: "main2".into(),
        },
        Actor::MoveTool,
    );
    // A second move freezes the catalogue the undo named.
    assert_eq!(
        refused(
            &u,
            Change::StartMove {
                to: t1(),
                catalogue_id_frozen: "main".into()
            },
            Actor::MoveTool
        ),
        INVALID
    );
    let m2 = apply(
        &u,
        Change::StartMove {
            to: t1(),
            catalogue_id_frozen: "main2".into(),
        },
        Actor::MoveTool,
    );
    let f2 = apply(&m2, Change::FlipMove { stamp: 3 }, Actor::MoveTool);
    // Its undo lands on neither frozen catalogue.
    for id in ["main", "main2"] {
        assert_eq!(
            refused(
                &f2,
                Change::UndoMove {
                    undo_stamp: 4,
                    catalogue_id: id.into()
                },
                Actor::MoveTool
            ),
            INVALID,
            "{id}"
        );
    }
    apply(
        &f2,
        Change::UndoMove {
            undo_stamp: 4,
            catalogue_id: "main3".into(),
        },
        Actor::MoveTool,
    );
}

#[test]
fn the_fallback_undo_lands_on_the_frozen_catalogue_after_its_stamp_is_levelled() {
    let f = apply(&moving(), Change::FlipMove { stamp: 9 }, Actor::MoveTool);
    let fallback = |undo_stamp, levelled_to| Change::UndoMoveOntoFrozen {
        undo_stamp,
        levelled_to,
    };
    // Levelled below the flip's stamp, or an undo stamp not above it.
    assert_eq!(refused(&f, fallback(10, 8), Actor::MoveTool), INVALID);
    assert_eq!(refused(&f, fallback(9, 9), Actor::MoveTool), INVALID);
    assert_eq!(refused(&f, fallback(10, 9), Actor::Operator), FORBIDDEN);
    let back = apply(&f, fallback(10, 9), Actor::MoveTool);
    assert_eq!(
        back.door
            .tenant_zero
            .as_ref()
            .unwrap()
            .moved
            .as_ref()
            .unwrap()
            .levelled_to,
        Some(9)
    );
    let z = back.door.tenant_zero.clone().unwrap();
    assert_eq!(z.selector, Selector::D1);
    assert_eq!(z.catalogue_id.as_deref(), Some("main"));
    assert!(z.undone());
    unchanged(&back, fallback(10, 9), Actor::MoveTool);
    // The same undo with another levelled counter is no repeat.
    assert_eq!(refused(&back, fallback(10, 12), Actor::MoveTool), SELECTOR);
    // Not before the flip.
    assert_eq!(
        refused(&moving(), fallback(10, 9), Actor::MoveTool),
        SELECTOR
    );
}

#[test]
fn clearing_the_escrow_names_every_destroyed_copy() {
    let e = apply(&active(), Change::SetEscrowOffline, Actor::Operator);
    for bad in [vec![], vec!["nothex".to_string()]] {
        assert_eq!(
            refused(
                &e,
                Change::ClearEscrowOffline { destroyed: bad },
                Actor::Operator
            ),
            INVALID
        );
    }
    let names = vec!["ab".repeat(32), "cd".repeat(32)];
    let c = apply(
        &e,
        Change::ClearEscrowOffline {
            destroyed: names.clone(),
        },
        Actor::Operator,
    );
    assert!(!c.door.escrow_offline);
    assert_eq!(c.door.escrow_destroyed, names);
}

#[test]
fn a_give_up_with_no_window_open_is_unchanged() {
    // No move yet.
    unchanged(&tenant_zero(), Change::GiveUpMove, Actor::MoveTool);
    // The last move undone: the next window's record was never written.
    let f = apply(&moving(), Change::FlipMove { stamp: 9 }, Actor::MoveTool);
    let u = apply(
        &f,
        Change::UndoMove {
            undo_stamp: 10,
            catalogue_id: "main2".into(),
        },
        Actor::MoveTool,
    );
    unchanged(&u, Change::GiveUpMove, Actor::MoveTool);
}

#[test]
fn marking_the_escrow_again_forgets_the_old_destroyed_names() {
    let e = apply(&active(), Change::SetEscrowOffline, Actor::Operator);
    let c = apply(
        &e,
        Change::ClearEscrowOffline {
            destroyed: vec!["ab".repeat(32)],
        },
        Actor::Operator,
    );
    let again = apply(&c, Change::SetEscrowOffline, Actor::Operator);
    assert!(again.door.escrow_destroyed.is_empty());
}

#[test]
fn a_bucket_is_dropped_only_from_an_active_tenant() {
    let a = active();
    let b = apply(&a, create_bucket(1, 0), Actor::Customer);
    let drop = || Change::DropBucket { bucket: bid(1) };
    let legal = apply(
        &b,
        operator_hold(HoldMode::Locked, OperatorReason::Legal, None),
        Actor::Operator,
    );
    assert_eq!(refused(&legal, drop(), Actor::Customer), PRESERVED);
    assert_eq!(refused(&legal, drop(), Actor::Operator), PRESERVED);
    let held = apply(&b, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    assert_eq!(refused(&held, drop(), Actor::Customer), WRONG_STATE);
    let dropped = apply(&b, drop(), Actor::Customer);
    // Dropping a bucket closes a way in.
    assert_eq!(
        write_order(Some(&b.door), &dropped.door),
        WriteOrder::Closing
    );
    assert_eq!(write_order(Some(&a.door), &b.door), WriteOrder::Opening);
}

#[test]
fn a_flip_counts_the_moves_that_flipped() {
    let f = apply(&moving(), Change::FlipMove { stamp: 9 }, Actor::MoveTool);
    assert_eq!(f.door.tenant_zero.as_ref().unwrap().flips, 1);
    let u = apply(
        &f,
        Change::UndoMove {
            undo_stamp: 10,
            catalogue_id: "main2".into(),
        },
        Actor::MoveTool,
    );
    let m2 = apply(
        &u,
        Change::StartMove {
            to: t1(),
            catalogue_id_frozen: "main2".into(),
        },
        Actor::MoveTool,
    );
    // A window that is given up does not count.
    let g = apply(&m2, Change::GiveUpMove, Actor::MoveTool);
    assert_eq!(g.door.tenant_zero.as_ref().unwrap().flips, 1);
}

/// While a unit is being restored a flag may be turned off, never on.
#[test]
fn a_flag_is_turned_off_but_never_on_while_restoring() {
    let a = active();
    let mut on = serde_json::Map::new();
    on.insert("webdav".into(), serde_json::json!(true));
    let with = apply(
        &a,
        Change::SetFeatures {
            base_seq: ANY,
            features_json: on.clone(),
        },
        Actor::Operator,
    );
    let r = apply(&with, Change::SetRestoring { unit: 0 }, Actor::Operator);
    let mut off = serde_json::Map::new();
    off.insert("webdav".into(), serde_json::json!(false));
    let turned_off = apply(
        &r,
        Change::SetFeatures {
            base_seq: ANY,
            features_json: off.clone(),
        },
        Actor::Operator,
    );
    // Removing a flag turns it off too.
    apply(
        &r,
        Change::SetFeatures {
            base_seq: ANY,
            features_json: serde_json::Map::new(),
        },
        Actor::Operator,
    );
    assert_eq!(
        refused(
            &turned_off,
            Change::SetFeatures {
                base_seq: ANY,
                features_json: on.clone()
            },
            Actor::Operator
        ),
        RESTORING
    );
    let mut other = off.clone();
    other.insert("api".into(), serde_json::json!("beta"));
    assert_eq!(
        refused(
            &turned_off,
            Change::SetFeatures {
                base_seq: ANY,
                features_json: other
            },
            Actor::Operator
        ),
        RESTORING
    );
    // After the lift it may be turned on again.
    let since = turned_off.door.restoring[0].since_seq;
    let lifted = apply(
        &turned_off,
        Change::LiftRestoring {
            unit: 0,
            since_seq: since,
        },
        Actor::RestoreTool,
    );
    apply(
        &lifted,
        Change::SetFeatures {
            base_seq: ANY,
            features_json: on,
        },
        Actor::Operator,
    );
}

/// `next` at a time of its own.
fn at(head: &TenantRecord, change: Change, actor: Actor, now: UnixMs) -> TenantRecord {
    match next(&head.door.tenant, Some(head), &change, actor, now) {
        Ok(Outcome::Next(r)) => r,
        other => panic!("{other:?}"),
    }
}

/// The tenant read's times are carried in the door (AM-59): the creation,
/// each hold's start and the deletion's record, none read back from the
/// chain.
#[test]
fn the_door_carries_the_times_of_the_tenant_read() {
    let a = active();
    assert_eq!(a.door.created_at, NOW);
    assert!(a.door.seq > 1);
    let t1 = UnixMs(NOW.0 + 1_000);
    let t2 = UnixMs(NOW.0 + 2_000);
    let t3 = UnixMs(NOW.0 + 3_000);

    // A hold starts at its record; a new mode starts again; the same mode
    // writes nothing.
    let b = at(
        &a,
        billing_hold(Some(HoldMode::ReadOnly)),
        Actor::Billing,
        t1,
    );
    assert_eq!(b.door.created_at, NOW);
    assert_eq!(b.door.holds.billing.unwrap().since, t1);
    assert_eq!(b.door.holds.since(), Some(t1));
    unchanged(&b, billing_hold(Some(HoldMode::ReadOnly)), Actor::Billing);
    let b = at(&b, billing_hold(Some(HoldMode::Locked)), Actor::Billing, t2);
    assert_eq!(b.door.holds.billing.unwrap().since, t2);

    // The operator's hold: a new reason or `preserve` alone keeps its
    // start, a new mode does not.
    let o = at(
        &b,
        operator_hold(HoldMode::ReadOnly, OperatorReason::Security, None),
        Actor::Operator,
        t2,
    );
    assert_eq!(o.door.holds.operator.unwrap().since, t2);
    let o = at(
        &o,
        operator_hold(HoldMode::ReadOnly, OperatorReason::Legal, Some(false)),
        Actor::Operator,
        t3,
    );
    assert_eq!(o.door.holds.operator.unwrap().since, t2);
    assert_eq!(o.door.holds.operator.unwrap().reason, OperatorReason::Legal);
    // The suspension's start is the start of the hold whose mode is in
    // force: billing's `locked` here.
    assert_eq!(o.door.holds.since(), Some(t2));
    let o = at(
        &o,
        operator_hold(HoldMode::Locked, OperatorReason::Legal, Some(false)),
        Actor::Operator,
        t3,
    );
    assert_eq!(o.door.holds.operator.unwrap().since, t3);
    // Both `locked`: the earlier start.
    assert_eq!(o.door.holds.since(), Some(t2));
    let lifted = at(&o, billing_hold(None), Actor::Billing, t3);
    assert_eq!(lifted.door.holds.billing, None);
    assert_eq!(lifted.door.holds.since(), Some(t3));
    let lifted = at(
        &lifted,
        Change::SetOperatorHold { hold: None },
        Actor::Operator,
        t3,
    );
    assert_eq!(lifted.door.holds.since(), None);
    assert_eq!(lifted.door.created_at, NOW);

    // The deletion names its record and its time.
    let d = at(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 8 * DAY, 1),
        Actor::Customer,
        t1,
    );
    let del = d.door.deletion.clone().unwrap();
    assert_eq!(del.seq, d.door.seq);
    assert_eq!(del.requested_at, t1);
    // Later records carry it unchanged.
    let later = at(
        &d,
        Change::SetLimits {
            base_seq: d.door.seq,
            limits: BTreeMap::new(),
            rate_json: None,
        },
        Actor::Operator,
        t2,
    );
    assert_eq!(later.door.deletion, Some(del));
    assert_eq!(later.door.created_at, NOW);
}

/// AM-38 case 4: the undo names the deletion it undoes by its seq.
#[test]
fn an_undo_names_the_deletion_it_undoes() {
    let a = active();
    let undo = |seq| Change::UndoDeletion { deletion_seq: seq };
    let d = apply(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 8 * DAY, 1),
        Actor::Customer,
    );
    let seq = d.door.deletion.as_ref().unwrap().seq;
    // Another seq than the head's deletion: refused, nothing written.
    for other in [0, seq - 1, seq + 1] {
        assert_eq!(refused(&d, undo(other), Actor::Customer), NOT_REQUESTED);
    }
    // Who may still comes first.
    assert_eq!(refused(&d, undo(seq), Actor::Billing), FORBIDDEN);
    assert_eq!(refused(&d, undo(seq), Actor::ShredJob), FORBIDDEN);
    let u = apply(&d, undo(seq), Actor::Customer);
    assert_eq!(u.door.deletion, None);
    assert_eq!(u.door.undone_deletion, Some(hash(1)));
    assert_eq!(u.door.undone_deletion_seq, Some(seq));
    // Its retry writes nothing; any other seq is refused.
    unchanged(&u, undo(seq), Actor::Customer);
    unchanged(&u, undo(seq), Actor::Operator);
    assert_eq!(refused(&u, undo(seq + 1), Actor::Customer), NOT_REQUESTED);
    assert_eq!(refused(&u, undo(seq), Actor::RestoreTool), FORBIDDEN);

    // A late retry never cancels a newer deletion.
    let d2 = apply(
        &u,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 8 * DAY, 2),
        Actor::Customer,
    );
    let seq2 = d2.door.deletion.as_ref().unwrap().seq;
    assert!(seq2 > seq);
    assert_eq!(refused(&d2, undo(seq), Actor::Customer), NOT_REQUESTED);
    let u2 = apply(&d2, undo(seq2), Actor::Operator);
    assert_eq!(u2.door.undone_deletion_seq, Some(seq2));
    assert_eq!(refused(&u2, undo(seq), Actor::Customer), NOT_REQUESTED);
}

/// AM-57: the record that creates a bucket carries its name and wrapped
/// key in the private part, never in the door, and only that record.
#[test]
fn a_bucket_create_carries_its_name_and_wrap_in_the_private_part() {
    let a = active();
    let c = apply(&a, create_bucket(1, 0), Actor::Customer);
    let secrets = c.private.bucket_created.clone().unwrap();
    assert_eq!(secrets.name, "bucket-1");
    assert_eq!(secrets.bdk_wrapped, wrap(1));
    // The door names the id, never the name.
    let door = serde_json::to_string(&c.door).unwrap();
    assert!(!door.contains("bucket-1"), "{door}");
    assert_eq!(c.door.bucket_created.as_ref().unwrap().bucket, bid(1));
    // The private part keeps the workspace beside it.
    assert_eq!(c.private.external_ref.as_deref(), Some("ws_1"));
    // The base64 form, and a Debug that shows shapes only.
    let private = serde_json::to_value(&c.private).unwrap();
    assert_eq!(private["bucket_created"]["name"], "bucket-1");
    assert_eq!(
        private["bucket_created"]["bdk_wrapped"]
            .as_str()
            .unwrap()
            .len(),
        100
    );
    let back: TenantPrivate = serde_json::from_value(private).unwrap();
    assert_eq!(back, c.private);
    let shown = format!("{secrets:?}");
    assert!(!shown.contains("bucket-1"), "{shown}");
    // The next record drops both.
    let n = apply(&c, create_bucket(2, 0), Actor::Customer);
    assert_eq!(n.private.bucket_created.as_ref().unwrap().name, "bucket-2");
    let n = apply(&n, Change::DropBucket { bucket: bid(1) }, Actor::Customer);
    assert_eq!(n.private.bucket_created, None);
    assert_eq!(n.door.bucket_created, None);
    assert_eq!(n.private.external_ref.as_deref(), Some("ws_1"));

    // A name of the plane's form, and a scheme-2 wrap.
    let with = |name: &str, w: Vec<u8>| Change::CreateBucket {
        bucket: bid(3),
        unit: 0,
        creator: "p_owner".into(),
        grant_seq: 3,
        name: name.into(),
        bdk_wrapped: w,
    };
    for bad in ["ab", "Photos", "a.b", "-ab", "ab-", &"a".repeat(64), ""] {
        assert_eq!(
            refused(&a, with(bad, wrap(3)), Actor::Customer),
            INVALID,
            "{bad}"
        );
    }
    let mut v1 = wrap(3);
    v1[0] = 0x01;
    for w in [
        v1,
        wrap(3)[..72].to_vec(),
        [wrap(3), vec![0]].concat(),
        vec![],
    ] {
        assert_eq!(refused(&a, with("photos", w), Actor::Customer), INVALID);
    }
    let ok = apply(&a, with("a-1", wrap(3)), Actor::Customer);
    assert_eq!(ok.private.bucket_created.unwrap().name, "a-1");
}

/// AM-67: the move floor of a unit only rises, and only the move and
/// restore tools raise it, on the owner tenant of tenant 0's move.
#[test]
fn the_move_floor_only_rises() {
    let owner = active();
    let moving = moving();
    let floor = |zero: &TenantRecord, unit, ms| Change::SetMoveFloor {
        unit,
        floor: UnixMs(ms),
        zero: Box::new(zero.door.clone()),
    };
    for actor in [
        Actor::Customer,
        Actor::Operator,
        Actor::Billing,
        Actor::ShredJob,
    ] {
        assert_eq!(
            refused(&owner, floor(&moving, 0, 10), actor),
            FORBIDDEN,
            "{actor:?}"
        );
    }
    let f = apply(&owner, floor(&moving, 0, 10), Actor::MoveTool);
    assert_eq!(f.door.move_floors.get(&0), Some(&UnixMs(10)));
    assert_eq!(write_order(Some(&owner.door), &f.door), WriteOrder::Closing);
    // At or below the floor: nothing written. Above it: raised.
    unchanged(&f, floor(&moving, 0, 10), Actor::RestoreTool);
    unchanged(&f, floor(&moving, 0, 9), Actor::MoveTool);
    let g = apply(&f, floor(&moving, 0, 11), Actor::RestoreTool);
    assert_eq!(g.door.move_floors.get(&0), Some(&UnixMs(11)));
    // Carried by every later record.
    let h = apply(&g, create_bucket(1, 0), Actor::Customer);
    assert_eq!(h.door.move_floors, g.door.move_floors);

    // Allowed while the unit is being restored, and while suspended.
    let r = apply(&g, Change::SetRestoring { unit: 0 }, Actor::Operator);
    let r = apply(&r, floor(&moving, 0, 12), Actor::RestoreTool);
    let s = apply(&r, billing_hold(Some(HoldMode::Locked)), Actor::Billing);
    let s = apply(&s, floor(&moving, 0, 13), Actor::MoveTool);
    assert_eq!(s.door.move_floors.get(&0), Some(&UnixMs(13)));
    // Not while deleting.
    let d = apply(
        &g,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 8 * DAY, 1),
        Actor::Customer,
    );
    assert_eq!(
        refused(&d, floor(&moving, 0, 20), Actor::MoveTool),
        WRONG_STATE
    );
    // A listed unit; a floor above 0; never tenant 0 itself.
    assert_eq!(
        refused(&owner, floor(&moving, 1, 10), Actor::MoveTool),
        UNIT_NOT_LISTED
    );
    assert_eq!(
        refused(&owner, floor(&moving, 0, 0), Actor::MoveTool),
        INVALID
    );
    assert_eq!(
        refused(&moving, floor(&moving, 0, 10), Actor::MoveTool),
        TENANT_ZERO
    );

    // Tenant 0's head: a window into this tenant, its flip or its undo
    // (`move.to` names it), or a give-up (`d1`, no move). Never a move
    // into another tenant, a forged head or a retired tenant 0.
    let flipped = apply(&moving, Change::FlipMove { stamp: 5 }, Actor::MoveTool);
    apply(&owner, floor(&flipped, 0, 10), Actor::MoveTool);
    let gave_up = apply(&moving, Change::GiveUpMove, Actor::MoveTool);
    apply(&owner, floor(&gave_up, 0, 10), Actor::MoveTool);
    let undone = apply(
        &flipped,
        Change::UndoMove {
            undo_stamp: 6,
            catalogue_id: "main2".into(),
        },
        Actor::MoveTool,
    );
    apply(&owner, floor(&undone, 0, 10), Actor::MoveTool);
    let mut elsewhere = moving.clone();
    if let Some(m) = elsewhere
        .door
        .tenant_zero
        .as_mut()
        .and_then(|z| z.moved.as_mut())
    {
        m.to = Tenant::parse("t_00000000000000b2").unwrap();
    }
    assert_eq!(
        refused(&owner, floor(&elsewhere, 0, 10), Actor::MoveTool),
        NOT_MOVING_HERE
    );
    assert_eq!(
        refused(&owner, floor(&owner, 0, 10), Actor::MoveTool),
        NOT_MOVING_HERE
    );
    let mut retired = flipped.clone();
    retired.door.tenant_zero.as_mut().unwrap().selector = Selector::Retired;
    assert_eq!(
        refused(&owner, floor(&retired, 0, 10), Actor::MoveTool),
        NOT_MOVING_HERE
    );
}

/// The shredded stub keeps the creation time, which names nothing, and
/// drops the move floors and the undo's seq with everything else.
#[test]
fn the_stub_keeps_the_creation_time_only() {
    let a = active();
    let moving = moving();
    let a = apply(
        &a,
        Change::SetMoveFloor {
            unit: 0,
            floor: UnixMs(10),
            zero: Box::new(moving.door.clone()),
        },
        Actor::MoveTool,
    );
    let d = apply(
        &a,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 8 * DAY, 1),
        Actor::Customer,
    );
    let u = apply(
        &d,
        Change::UndoDeletion { deletion_seq: ANY },
        Actor::Customer,
    );
    let d = apply(
        &u,
        delete_by(Actor::Customer, DeletionReason::CustomerRequest, 8 * DAY, 2),
        Actor::Customer,
    );
    assert!(d.door.undone_deletion_seq.is_some());
    let later = UnixMs(NOW.0 + 9 * DAY);
    let s = at(&d, Change::StartShred, Actor::ShredJob, later);
    assert_eq!(s.door.move_floors.get(&0), Some(&UnixMs(10)));
    let stub = at(&s, Change::FinishShred, Actor::ShredJob, later);
    assert_eq!(stub.door.created_at, NOW);
    assert!(stub.door.move_floors.is_empty());
    assert_eq!(stub.door.undone_deletion_seq, None);
    assert_eq!(stub.door.deletion, None);
    assert_eq!(stub.private.bucket_created, None);
}
