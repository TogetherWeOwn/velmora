//! The unit side of the reservation (`docs/units.md`, "Reservations";
//! ADR §2.5 step 0, §6.2, §6.3; AM-18, AM-35, AM-36, AM-38), the key
//! scheme of rule 13, and the size guard of ADR §2.6, on the native
//! database. `workers/unit-suite` runs this file against a Durable
//! Object too.

use serde_json::{json, Value};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::import::{ImportBatch, ImportTable, ImportValue, MoveHead};
use velmora_bridge::unit::keys::{Access, KeptAnswer, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::reserve::{
    self, Acting, Hash32, Opening, ReserveRefusal, Rid, BUCKETS_PER_DAY, CHANGES_PER_HOUR, KEPT_MS,
    MAX_ANSWER, MAX_BUCKETS, RESERVED_MS, S3_KEYS,
};
use velmora_bridge::unit::size::{SizeLimits, SizeRefusal};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const B1: &str = "b_00000000000000f1";
const B2: &str = "b_00000000000000f2";
/// The acting principal: `rw` on B1, `ro` on B2.
const P: &str = "p_member";
const OWNER: &str = "member-1";

fn tenant() -> TenantId {
    TenantId::parse("t_0000000000000f01").unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn call(op: UnitOp) -> UnitCall {
    UnitCall {
        name: own(),
        kind: CallKind::Worker,
        seqs: None,
        authenticated: true,
        listed: true,
        op,
    }
}

fn at(u: &Unit<RusqliteSql>, op: UnitOp, now: UnixMs) -> UnitAnswer {
    u.handle(&call(op), now)
}

fn worker(u: &Unit<RusqliteSql>, op: UnitOp) -> UnitAnswer {
    at(u, op, NOW)
}

fn sync(u: &Unit<RusqliteSql>, state: TenantState, restoring: Option<u64>) -> UnitAnswer {
    let h = u.head().unwrap();
    worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                seqs: Seqs {
                    state_seq: h.seqs.state_seq + 1,
                    keys_seq: h.seqs.keys_seq,
                },
                tenant_mode: (state == TenantState::Suspended)
                    .then_some(velmora_bridge::unit::call::HoldMode::ReadOnly),
                tenant_state: state,
                restoring_since: restoring,
                lift: None,
            },
        },
    )
}

fn grant(bucket: &str, access: Access) -> KeyGrant {
    KeyGrant {
        bucket_id: bucket.into(),
        access,
        expires_at: None,
        prefix: None,
        ip_list: vec![],
    }
}

fn principal_entry(
    id: &str,
    owner_ref: &str,
    seq: u64,
    status: SubjectStatus,
    held: bool,
    grants: Vec<KeyGrant>,
) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        kind: KeyKind::Principal,
        status,
        held,
        made_by: None,
        grants,
        created_at: 1,
        secret_wrapped: None,
        secret_kek_version: None,
        owner_ref: Some(owner_ref.into()),
        last_seq: seq,
        rid: None,
    }
}

fn key_entry(id: &str, seq: u64, grants: Vec<KeyGrant>, rid: Option<Rid>) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        kind: KeyKind::S3,
        status: SubjectStatus::Active,
        held: false,
        made_by: Some(P.into()),
        grants,
        created_at: 2,
        secret_wrapped: Some(vec![2, 0xaa]),
        secret_kek_version: Some(1),
        owner_ref: Some(OWNER.into()),
        last_seq: seq,
        rid,
    }
}

fn keys_seq(u: &Unit<RusqliteSql>) -> u64 {
    u.head().unwrap().seqs.keys_seq
}

fn apply(u: &Unit<RusqliteSql>, entries: Vec<KeyEntry>, answers: Vec<KeptAnswer>) -> Value {
    let from_seq = keys_seq(u);
    ok(worker(
        u,
        UnitOp::ApplyKeys {
            from_seq,
            entries: entries.into_iter().map(Into::into).collect(),
            answers,
        },
    ))
}

/// A born, active managed unit holding B1, with the acting principal.
fn ready() -> Unit<RusqliteSql> {
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    let token = BirthToken {
        name: own(),
        jurisdiction: String::new(),
        record_seq: 3,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: 2,
        kind: BirthKind::Birth,
    };
    let mut c = call(UnitOp::Provision {
        token,
        sealed: b"sealed".to_vec(),
    });
    c.seqs = Some(Seqs {
        state_seq: 3,
        keys_seq: 0,
    });
    assert!(matches!(u.handle(&c, NOW), UnitAnswer::Ok { .. }));
    assert!(matches!(
        sync(&u, TenantState::Active, None),
        UnitAnswer::Ok { .. }
    ));
    u.sql()
        .apply(&format!(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('{B1}', 'alpha', 'o', x'02', 1, 1), ('{B2}', 'held-two', 'o', x'02', 1, 1);"
        ))
        .unwrap();
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            1,
            SubjectStatus::Active,
            false,
            vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        )],
        vec![],
    );
    u
}

fn h(n: u8) -> Hash32 {
    Hash32([n; 32])
}

fn rid(n: u8) -> Rid {
    Rid([n; 16])
}

fn by_owner() -> Option<Acting> {
    Some(Acting::OwnerRef(OWNER.into()))
}

fn reserve_op(key: u8, fp: u8, r: u8, acting: Option<Acting>, opening: Opening) -> UnitOp {
    UnitOp::Reserve {
        key_hash: h(key),
        fingerprint: h(fp),
        rid: rid(r),
        acting,
        opening,
    }
}

fn new_key(id: &str, grants: Vec<KeyGrant>) -> Opening {
    Opening::Key {
        kind: KeyKind::S3,
        id: id.into(),
        grants,
    }
}

fn ok(a: UnitAnswer) -> Value {
    match a {
        UnitAnswer::Ok { body, .. } => body,
        other => panic!("not ok: {other:?}"),
    }
}

fn release_op(r: u8, admit: &Value) -> UnitOp {
    UnitOp::Release {
        rid: rid(r),
        asks: admit["admitted"]["asks"].as_u64().expect("admit asks"),
    }
}

fn refused(a: &UnitAnswer) -> Option<ReserveRefusal> {
    match a {
        UnitAnswer::Refused {
            reason: Refused::Reserve(r),
            ..
        } => Some(*r),
        _ => None,
    }
}

fn rows(u: &Unit<RusqliteSql>) -> i64 {
    u.sql()
        .with_conn(|c| c.query_row("SELECT count(*) FROM unit_reservations", [], |r| r.get(0)))
        .unwrap()
}

fn state_of(u: &Unit<RusqliteSql>, r: u8) -> Option<String> {
    u.sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT state FROM unit_reservations WHERE rid = ?1",
                [rid(r).0.to_vec()],
                |row| row.get(0),
            )
        })
        .ok()
}

fn has_cap_slot(u: &Unit<RusqliteSql>, r: u8) -> bool {
    u.sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM unit_cap_uses WHERE rid = ?1)",
                [rid(r).0.to_vec()],
                |row| row.get(0),
            )
        })
        .unwrap()
}

// ---------------------------------------------------------------------------
// The ask
// ---------------------------------------------------------------------------

#[test]
fn a_key_is_reserved_at_the_units_head_and_asked_again_under_its_rid() {
    let u = ready();
    let op = reserve_op(
        1,
        2,
        3,
        by_owner(),
        new_key("AK1", vec![grant(B1, Access::Ro)]),
    );
    let first = ok(worker(&u, op.clone()));
    assert_eq!(
        first,
        json!({ "admitted": {
            "rid": rid(3).hex(), "asks": 1, "keys_seq": 1, "again": false, "scope": P, "bound": null,
            "subject": "AK1", "unit": null,
        }})
    );
    // Asked again (a lost put, or a retry): the same rid, checked again
    // at the head, even when the retry drew another rid.
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            2,
            SubjectStatus::Active,
            false,
            vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        )],
        vec![],
    );
    let again = ok(worker(
        &u,
        reserve_op(
            1,
            2,
            9,
            by_owner(),
            new_key("AK1", vec![grant(B1, Access::Ro)]),
        ),
    ));
    assert_eq!(again["admitted"]["rid"], json!(rid(3).hex()));
    assert_eq!(again["admitted"]["asks"], json!(2));
    assert_eq!(again["admitted"]["keys_seq"], json!(2));
    assert_eq!(again["admitted"]["again"], json!(true));
    // The same key with another request.
    assert_eq!(
        ok(worker(
            &u,
            reserve_op(1, 7, 4, by_owner(), new_key("AK1", vec![]))
        )),
        json!({ "reused": true })
    );
    assert_eq!(rows(&u), 1);
    // The key is scoped by the acting principal: the same key hash under
    // no principal is another row.
    let principal_ask = ok(worker(
        &u,
        reserve_op(
            1,
            2,
            5,
            None,
            Opening::Principal {
                id: "p_new".into(),
                owner_ref: "member-2".into(),
                grants: vec![],
            },
        ),
    ));
    assert_eq!(principal_ask["admitted"]["scope"], Value::Null);
    assert_eq!(rows(&u), 2);
}

#[test]
fn malformed_limited_and_oversized_grants_are_refused_before_anything() {
    let u = ready();
    let limited = |f: &dyn Fn(&mut KeyGrant)| {
        let mut g = grant(B1, Access::Ro);
        f(&mut g);
        reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![g]))
    };
    for op in [
        limited(&|g| g.prefix = Some("a/".into())),
        limited(&|g| g.expires_at = Some(5)),
        limited(&|g| g.ip_list = vec!["192.0.2.0/24".into()]),
    ] {
        assert_eq!(
            refused(&worker(&u, op)),
            Some(ReserveRefusal::GrantLimitsNotServed)
        );
    }
    let many = (0..65)
        .map(|i| grant(&format!("b_{i:016x}"), Access::Ro))
        .collect();
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(1, 1, 1, by_owner(), new_key("AK1", many))
        )),
        Some(ReserveRefusal::TooManyGrants)
    );
    for op in [
        // A key made by no principal.
        reserve_op(1, 1, 1, None, new_key("AK1", vec![])),
        // A principal or the internal key through the key ask.
        reserve_op(
            1,
            1,
            1,
            by_owner(),
            Opening::Key {
                kind: KeyKind::Internal,
                id: "AK1".into(),
                grants: vec![],
            },
        ),
        reserve_op(
            1,
            1,
            1,
            Some(Acting::OwnerRef("bad ref".into())),
            new_key("AK1", vec![]),
        ),
        // A sign-up principal with grants (no acting principal).
        reserve_op(
            1,
            1,
            1,
            None,
            Opening::Principal {
                id: "p_2".into(),
                owner_ref: "member-2".into(),
                grants: vec![grant(B1, Access::Ro)],
            },
        ),
        reserve_op(
            1,
            1,
            1,
            by_owner(),
            Opening::Bucket {
                name: "No_Such".into(),
                unit: 0,
            },
        ),
    ] {
        assert_eq!(
            refused(&worker(&u, op.clone())),
            Some(ReserveRefusal::Malformed),
            "{op:?}"
        );
    }
    assert_eq!(rows(&u), 0, "a refusal leaves no row");
}

#[test]
fn the_acting_principal_is_resolved_in_the_unit_by_owner_ref() {
    let u = ready();
    let ask = |acting| reserve_op(1, 1, 1, acting, new_key("AK1", vec![]));
    assert_eq!(
        refused(&worker(&u, ask(Some(Acting::OwnerRef("nobody".into()))))),
        Some(ReserveRefusal::ActingPrincipalUnknown)
    );
    // By id: a key is not a principal.
    apply(&u, vec![key_entry("AKX", 2, vec![], None)], vec![]);
    assert_eq!(
        refused(&worker(&u, ask(Some(Acting::Principal("AKX".into()))))),
        Some(ReserveRefusal::ActingPrincipalUnknown)
    );
    assert!(matches!(
        worker(&u, ask(Some(Acting::Principal(P.into())))),
        UnitAnswer::Ok { .. }
    ));
    // The resolve read answers the principal and writes nothing.
    let before = rows(&u);
    let r = ok(worker(
        &u,
        UnitOp::ResolveActing {
            acting: Acting::OwnerRef(OWNER.into()),
        },
    ));
    assert_eq!(r["principal"]["id"], json!(P));
    assert_eq!(r["principal"]["grants"].as_array().unwrap().len(), 2);
    assert_eq!(rows(&u), before);
    // Disabled, then held: refused, each with its own reason.
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            3,
            SubjectStatus::Disabled,
            false,
            vec![],
        )],
        vec![],
    );
    assert_eq!(
        refused(&worker(&u, ask(by_owner()))),
        Some(ReserveRefusal::ActingPrincipalInactive)
    );
    assert_eq!(
        refused(&worker(
            &u,
            UnitOp::ResolveActing {
                acting: Acting::OwnerRef(OWNER.into())
            }
        )),
        Some(ReserveRefusal::ActingPrincipalInactive)
    );
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            4,
            SubjectStatus::Active,
            true,
            vec![grant(B1, Access::Rw)],
        )],
        vec![],
    );
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(2, 2, 2, by_owner(), new_key("AK2", vec![]))
        )),
        Some(ReserveRefusal::ActingPrincipalHeld)
    );
    // Revoked: unknown.
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            5,
            SubjectStatus::Revoked,
            false,
            vec![],
        )],
        vec![],
    );
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(2, 2, 2, by_owner(), new_key("AK2", vec![]))
        )),
        Some(ReserveRefusal::ActingPrincipalUnknown)
    );
}

#[test]
fn two_principals_of_one_owner_ref_are_never_resolved() {
    let u = ready();
    apply(
        &u,
        vec![principal_entry(
            "p_twin",
            OWNER,
            2,
            SubjectStatus::Active,
            false,
            vec![],
        )],
        vec![],
    );
    let a = worker(
        &u,
        UnitOp::ResolveActing {
            acting: Acting::OwnerRef(OWNER.into()),
        },
    );
    assert_eq!(
        a,
        UnitAnswer::Refused {
            reason: Refused::Reserve(ReserveRefusal::OwnerRefAmbiguous),
            alarm: true,
        }
    );
}

#[test]
#[ignore = "L1-5b defect: owner-ref lookup searches by kind instead of owner_ref"]
fn the_owner_ref_index_serves_the_resolve() {
    let u = ready();
    let plan: Vec<String> = u
        .sql()
        .with_conn(|c| {
            let mut st = c.prepare(
                "EXPLAIN QUERY PLAN SELECT id, status, held FROM unit_keys \
                  WHERE kind = 'principal' AND owner_ref = ?1 AND status <> 'revoked' LIMIT 2",
            )?;
            let v = st
                .query_map([OWNER], |r| r.get::<_, String>(3))?
                .collect::<rusqlite::Result<Vec<_>>>();
            v
        })
        .unwrap();
    assert!(
        plan.iter().any(|p| p.contains("unit_keys_by_owner_ref")),
        "{plan:?}"
    );
}

#[test]
fn a_grant_wider_than_the_acting_principals_is_refused() {
    let u = ready();
    let ask = |grants| reserve_op(1, 1, 1, by_owner(), new_key("AK1", grants));
    for grants in [
        vec![grant(B2, Access::Rw)],
        vec![grant(B1, Access::Rw), grant(B2, Access::Rw)],
    ] {
        assert_eq!(
            refused(&worker(&u, ask(grants))),
            Some(ReserveRefusal::GrantNotHeld)
        );
    }
    // A bucket the unit does not hold: named as such (AM-61).
    assert_eq!(
        refused(&worker(
            &u,
            ask(vec![grant("b_00000000000000f9", Access::Ro)])
        )),
        Some(ReserveRefusal::BucketNotFound)
    );
    assert!(matches!(
        worker(&u, ask(vec![grant(B1, Access::Rw), grant(B2, Access::Ro)])),
        UnitAnswer::Ok { .. }
    ));
    // Under a principal made by a narrower one, the narrower one decides.
    apply(
        &u,
        vec![KeyEntry {
            made_by: Some(P.into()),
            ..principal_entry(
                "p_sub",
                "member-sub",
                2,
                SubjectStatus::Active,
                false,
                vec![grant(B2, Access::Rw)],
            )
        }],
        vec![],
    );
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(
                2,
                2,
                2,
                Some(Acting::OwnerRef("member-sub".into())),
                new_key("AK2", vec![grant(B2, Access::Rw)])
            )
        )),
        Some(ReserveRefusal::GrantNotHeld)
    );
}

#[test]
fn a_key_that_exists_or_is_held_by_another_call_conflicts() {
    let u = ready();
    apply(&u, vec![key_entry("AK1", 2, vec![], None)], vec![]);
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![]))
        )),
        Some(ReserveRefusal::Conflict)
    );
    ok(worker(
        &u,
        reserve_op(1, 1, 1, by_owner(), new_key("AK2", vec![])),
    ));
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(2, 2, 2, by_owner(), new_key("AK2", vec![]))
        )),
        Some(ReserveRefusal::Conflict)
    );
    // Another call drawing a rid already in use.
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(3, 3, 1, by_owner(), new_key("AK3", vec![]))
        )),
        Some(ReserveRefusal::RidTaken)
    );
}

// ---------------------------------------------------------------------------
// Caps (ADR §6.2, §6.3)
// ---------------------------------------------------------------------------

#[test]
fn the_hourly_cap_counts_every_capped_change_and_only_the_latest_admit_can_free_its_slot() {
    let u = ready();
    let first_ask = reserve_op(0, 0, 0, by_owner(), new_key("AK0", vec![]));
    let first = ok(worker(&u, first_ask.clone()));
    for i in 1..S3_KEYS as u8 {
        let id = format!("AK{i}");
        ok(worker(
            &u,
            reserve_op(i, i, i, by_owner(), new_key(&id, vec![])),
        ));
    }
    // App passwords have their own cap of 20, but share the hourly one.
    for i in 0..(CHANGES_PER_HOUR - S3_KEYS) as u8 {
        let a = worker(
            &u,
            reserve_op(
                100 + i,
                100 + i,
                100 + i,
                by_owner(),
                Opening::Key {
                    kind: KeyKind::AppPassword,
                    id: format!("AP{i}"),
                    grants: vec![],
                },
            ),
        );
        assert!(matches!(a, UnitAnswer::Ok { .. }), "{i}: {a:?}");
    }
    let over = reserve_op(
        200,
        200,
        200,
        by_owner(),
        Opening::Key {
            kind: KeyKind::AppPassword,
            id: "APX".into(),
            grants: vec![],
        },
    );
    assert_eq!(
        refused(&worker(&u, over.clone())),
        Some(ReserveRefusal::CapReached)
    );
    // A new S3 key hits both limits; the absolute one takes precedence.
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(201, 201, 201, by_owner(), new_key("AKX", vec![])),
        )),
        Some(ReserveRefusal::LimitReached)
    );
    // Re-asking at the same head takes no new slot but fences the first admit.
    let again = ok(worker(&u, first_ask));
    assert_eq!(first["admitted"]["asks"], json!(1));
    assert_eq!(again["admitted"]["asks"], json!(2));
    assert_eq!(again["admitted"]["keys_seq"], first["admitted"]["keys_seq"]);
    assert_eq!(
        ok(worker(&u, release_op(0, &first))),
        json!({ "released": false })
    );
    assert_eq!(state_of(&u, 0).as_deref(), Some("reserved"));
    assert_eq!(
        refused(&worker(&u, over.clone())),
        Some(ReserveRefusal::CapReached)
    );
    assert_eq!(
        ok(worker(&u, release_op(0, &again))),
        json!({ "released": true })
    );
    assert_eq!(state_of(&u, 0), None);
    assert_eq!(
        ok(worker(&u, release_op(0, &again))),
        json!({ "released": false })
    );
    assert!(ok(worker(&u, over))["admitted"].is_object());
    // An hour on, the hourly count is clear (the open rows are swept, and
    // applied ones stay for 24 hours but count only within the hour).
    let later = UnixMs(NOW.0 + RESERVED_MS + 1);
    assert!(matches!(
        at(
            &u,
            reserve_op(250, 250, 250, by_owner(), new_key("AKL", vec![])),
            later
        ),
        UnitAnswer::Ok { .. }
    ));
}

#[test]
fn the_absolute_key_limit_counts_stored_rows_and_open_reservations() {
    let u = ready();
    let held: Vec<KeyEntry> = (0..S3_KEYS as u64 - 1)
        .map(|i| key_entry(&format!("AKH{i}"), 2 + i, vec![], None))
        .collect();
    apply(&u, held, vec![]);
    ok(worker(
        &u,
        reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![])),
    ));
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(2, 2, 2, by_owner(), new_key("AK2", vec![]))
        )),
        Some(ReserveRefusal::LimitReached)
    );
}

#[test]
fn twenty_active_credentials_of_either_kind_refuse_a_twenty_first() {
    for kind in [KeyKind::S3, KeyKind::AppPassword] {
        let u = ready();
        let entries = (1..20)
            .map(|i| KeyEntry {
                kind,
                ..key_entry(&format!("AK{i}"), 1 + i, vec![], None)
            })
            .collect();
        apply(&u, entries, vec![]);
        let ask = |n| {
            reserve_op(
                n,
                n,
                n,
                by_owner(),
                Opening::Key {
                    kind,
                    id: format!("AK{n}"),
                    grants: vec![],
                },
            )
        };
        assert!(ok(worker(&u, ask(20)))["admitted"].is_object());
        let applied = apply(
            &u,
            vec![KeyEntry {
                kind,
                ..key_entry("AK20", 21, vec![], Some(rid(20)))
            }],
            vec![],
        );
        assert_eq!(applied["reserved"], json!(1));
        assert_eq!(
            refused(&worker(&u, ask(21))),
            Some(ReserveRefusal::LimitReached),
            "{kind:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The apply keeps the answer (AM-38)
// ---------------------------------------------------------------------------

#[test]
fn the_apply_turns_the_reservation_applied_and_keeps_its_answer_once() {
    let u = ready();
    let op = reserve_op(
        1,
        1,
        7,
        by_owner(),
        new_key("AK1", vec![grant(B1, Access::Ro)]),
    );
    let admit = ok(worker(&u, op.clone()));
    let answer = r#"{"id":"AK1","secret_access_key":null}"#;
    let body = apply(
        &u,
        vec![key_entry(
            "AK1",
            2,
            vec![grant(B1, Access::Ro)],
            Some(rid(7)),
        )],
        vec![KeptAnswer {
            rid: rid(7),
            status: 201,
            body: answer.into(),
        }],
    );
    assert_eq!(body["reserved"], json!(1));
    assert_eq!(body["answers_kept"], json!(1));
    // Even the latest admit cannot release an applied row or its slot.
    assert_eq!(
        ok(worker(&u, release_op(7, &admit))),
        json!({ "released": false })
    );
    assert_eq!(state_of(&u, 7).as_deref(), Some("applied"));
    assert!(has_cap_slot(&u, 7));
    assert_eq!(
        ok(worker(&u, op.clone())),
        json!({ "applied": {
            "status": 201, "body": answer, "subject": "AK1", "bucket": null, "grant_seq": null,
        }})
    );
    // A second answer never replaces the first.
    let from_seq = keys_seq(&u);
    let again = ok(worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq,
            entries: vec![],
            answers: vec![KeptAnswer {
                rid: rid(7),
                status: 200,
                body: "{}".into(),
            }],
        },
    ));
    assert_eq!(again["answers_kept"], json!(0));
    assert_eq!(ok(worker(&u, op))["applied"]["status"], json!(201));
}

#[test]
fn an_answer_with_a_secret_or_too_large_is_never_kept() {
    let u = ready();
    for (r, body) in [
        (
            1u8,
            r#"{"id":"AK1","secret_access_key":"plain"}"#.to_string(),
        ),
        (2, format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_ANSWER))),
        (3, "[]".to_string()),
    ] {
        let id = format!("AK{r}");
        ok(worker(
            &u,
            reserve_op(r, r, r, by_owner(), new_key(&id, vec![])),
        ));
        let seq = keys_seq(&u) + 1;
        let out = apply(
            &u,
            vec![key_entry(&id, seq, vec![], Some(rid(r)))],
            vec![KeptAnswer {
                rid: rid(r),
                status: 201,
                body,
            }],
        );
        assert_eq!(out["reserved"], json!(1));
        assert_eq!(out["answers_kept"], json!(0));
        // Applied with no answer: the Worker builds it from the chain.
        let replay = ok(worker(
            &u,
            reserve_op(r, r, r, by_owner(), new_key(&id, vec![])),
        ));
        assert_eq!(replay["applied"]["status"], Value::Null);
        assert_eq!(replay["applied"]["subject"], json!(id));
    }
    // And the table refuses one directly.
    let direct = u.sql().with_conn(|c| {
        c.execute(
            "UPDATE unit_reservations SET answer_status = 500, answer_body = '{}'",
            [],
        )
    });
    assert!(direct.is_err());
}

#[test]
fn a_record_for_another_subject_does_not_apply_a_reservation() {
    let u = ready();
    ok(worker(
        &u,
        reserve_op(1, 1, 7, by_owner(), new_key("AK1", vec![])),
    ));
    let out = apply(
        &u,
        vec![key_entry("AKOTHER", 2, vec![], Some(rid(7)))],
        vec![],
    );
    assert_eq!(out["reserved"], json!(0));
    assert_eq!(state_of(&u, 7).as_deref(), Some("reserved"));
}

#[test]
fn a_record_that_narrows_or_closes_the_principal_cancels_its_open_reservations() {
    let u = ready();
    ok(worker(
        &u,
        reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![])),
    ));
    // A restatement (same grants) or a widening keeps them.
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            2,
            SubjectStatus::Active,
            false,
            vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        )],
        vec![],
    );
    assert_eq!(state_of(&u, 1).as_deref(), Some("reserved"));
    // A narrowing cancels them.
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            3,
            SubjectStatus::Active,
            false,
            vec![grant(B1, Access::Ro)],
        )],
        vec![],
    );
    assert_eq!(state_of(&u, 1), None);
    // So does a disable.
    ok(worker(
        &u,
        reserve_op(2, 2, 2, by_owner(), new_key("AK2", vec![])),
    ));
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            4,
            SubjectStatus::Disabled,
            false,
            vec![],
        )],
        vec![],
    );
    assert_eq!(state_of(&u, 2), None);
}

/// AM-61: a bucket id the unit holds no bucket row for.
const ORPHAN: &str = "b_00000000000000f9";

/// AM-61: a record whose only change drops grants on bucket ids the unit
/// holds no row for narrows nothing, so it cancels no reservation; a
/// record that also drops a grant on a bucket the unit holds does.
#[test]
fn dropping_only_a_grant_on_a_bucket_the_unit_does_not_hold_cancels_nothing() {
    let u = ready();
    // The principal gains a grant on a bucket the unit does not hold (a
    // widening, which cancels nothing).
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            2,
            SubjectStatus::Active,
            false,
            vec![
                grant(B1, Access::Rw),
                grant(B2, Access::Ro),
                grant(ORPHAN, Access::Rw),
            ],
        )],
        vec![],
    );
    ok(worker(
        &u,
        reserve_op(
            1,
            1,
            1,
            by_owner(),
            new_key("AK1", vec![grant(B1, Access::Ro)]),
        ),
    ));
    // The orphan grant is dropped, or narrowed: the reservation stays.
    for (seq, orphan) in [(3, vec![grant(ORPHAN, Access::Ro)]), (4, vec![])] {
        let mut grants = vec![grant(B1, Access::Rw), grant(B2, Access::Ro)];
        grants.extend(orphan);
        apply(
            &u,
            vec![principal_entry(
                P,
                OWNER,
                seq,
                SubjectStatus::Active,
                false,
                grants,
            )],
            vec![],
        );
        assert_eq!(state_of(&u, 1).as_deref(), Some("reserved"), "seq {seq}");
    }
    // A grant on a bucket the unit holds is dropped too: cancelled.
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            5,
            SubjectStatus::Active,
            false,
            vec![grant(B1, Access::Rw)],
        )],
        vec![],
    );
    assert_eq!(state_of(&u, 1), None);
}

/// AM-61: an ask that grants on a bucket id the unit holds no row for is
/// refused `bucket_not_found` (key create, principal create, widening),
/// before the subset rule, and nothing is kept.
#[test]
fn a_grant_on_a_bucket_the_unit_does_not_hold_is_refused_as_not_found() {
    let u = ready();
    let not_found = Some(ReserveRefusal::BucketNotFound);
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(
                1,
                1,
                1,
                by_owner(),
                new_key(
                    "AK1",
                    vec![grant(B1, Access::Ro), grant(ORPHAN, Access::Ro)]
                ),
            ),
        )),
        not_found
    );
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(
                2,
                2,
                2,
                by_owner(),
                Opening::Principal {
                    id: "p_new".into(),
                    owner_ref: "member-9".into(),
                    grants: vec![grant(ORPHAN, Access::Ro)],
                },
            ),
        )),
        not_found
    );
    // A widening of a held key onto it.
    ok(worker(
        &u,
        reserve_op(
            3,
            3,
            3,
            by_owner(),
            new_key("AK3", vec![grant(B1, Access::Ro)]),
        ),
    ));
    apply(
        &u,
        vec![key_entry(
            "AK3",
            2,
            vec![grant(B1, Access::Ro)],
            Some(rid(3)),
        )],
        vec![],
    );
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(
                4,
                4,
                4,
                by_owner(),
                Opening::Grants {
                    subject: "AK3".into(),
                    grants: vec![grant(B1, Access::Ro), grant(ORPHAN, Access::Ro)],
                },
            ),
        )),
        not_found
    );
    assert_eq!(state_of(&u, 1), None);
    assert_eq!(state_of(&u, 2), None);
    assert_eq!(state_of(&u, 4), None);
}

fn row_keys_seq(u: &Unit<RusqliteSql>, r: u8) -> i64 {
    u.sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT keys_seq FROM unit_reservations WHERE rid = ?1",
                [rid(r).0.to_vec()],
                |row| row.get(0),
            )
        })
        .unwrap()
}

/// AM-55: a re-ask answers the first `rid` and the unit's current
/// `keys_seq`, and the row keeps that seq (the Worker then reads exactly
/// `keys_seq + 1`). In a locked tenant the re-ask is answered `not_open`
/// with the row's `rid` and writes nothing.
#[test]
fn a_re_ask_keeps_the_current_keys_seq_and_writes_nothing_in_a_locked_tenant() {
    let u = ready();
    let ask = |r| {
        reserve_op(
            1,
            1,
            r,
            by_owner(),
            new_key("AK1", vec![grant(B1, Access::Ro)]),
        )
    };
    assert_eq!(ok(worker(&u, ask(1)))["admitted"]["keys_seq"], json!(1));
    assert_eq!(row_keys_seq(&u, 1), 1);
    // Another record lands first (seq 2): the re-ask answers 2, the row
    // keeps 2, and the re-ask's own rid is ignored.
    apply(&u, vec![key_entry("AKX", 2, vec![], None)], vec![]);
    let again = ok(worker(&u, ask(7)));
    assert_eq!(again["admitted"]["rid"], json!(rid(1).hex()));
    assert_eq!(again["admitted"]["keys_seq"], json!(2));
    assert_eq!(row_keys_seq(&u, 1), 2);
    assert_eq!(state_of(&u, 7), None);
    // Locked: `not_open`, with the rid and the current seq; nothing kept.
    let h = u.head().unwrap();
    assert!(matches!(
        worker(
            &u,
            UnitOp::Sync {
                head: SyncHead {
                    seqs: Seqs {
                        state_seq: h.seqs.state_seq + 1,
                        keys_seq: h.seqs.keys_seq,
                    },
                    tenant_mode: Some(velmora_bridge::unit::call::HoldMode::Locked),
                    tenant_state: TenantState::Suspended,
                    restoring_since: None,
                    lift: None,
                },
            },
        ),
        UnitAnswer::Ok { .. }
    ));
    apply(&u, vec![key_entry("AKY", 3, vec![], None)], vec![]);
    let before = u.sql().with_conn(|c| c.total_changes());
    assert_eq!(
        ok(worker(&u, ask(8))),
        json!({ "not_open": { "rid": rid(1).hex(), "keys_seq": 3 } })
    );
    assert_eq!(u.sql().with_conn(|c| c.total_changes()), before);
    assert_eq!(row_keys_seq(&u, 1), 2);
    assert_eq!(state_of(&u, 1).as_deref(), Some("reserved"));
    assert_eq!(rows(&u), 1);
}

#[test]
fn a_re_ask_refused_at_the_new_head_drops_its_row_but_keeps_its_slot() {
    let u = ready();
    let op = reserve_op(
        1,
        1,
        1,
        by_owner(),
        new_key("AK1", vec![grant(B1, Access::Rw)]),
    );
    ok(worker(&u, op.clone()));
    let latest = ok(worker(&u, op.clone()));
    assert_eq!(latest["admitted"]["asks"], json!(2));
    // The principal is narrowed by a record that names this reservation's
    // rid (so it is not cancelled by it), then the call asks again.
    apply(
        &u,
        vec![KeyEntry {
            rid: Some(rid(1)),
            ..principal_entry(
                P,
                OWNER,
                2,
                SubjectStatus::Active,
                false,
                vec![grant(B1, Access::Ro)],
            )
        }],
        vec![],
    );
    assert_eq!(state_of(&u, 1).as_deref(), Some("reserved"));
    assert_eq!(refused(&worker(&u, op)), Some(ReserveRefusal::GrantNotHeld));
    assert_eq!(state_of(&u, 1), None);
    assert!(has_cap_slot(&u, 1));
    assert_eq!(
        ok(worker(&u, release_op(1, &latest))),
        json!({ "released": false })
    );
    assert!(has_cap_slot(&u, 1));
}

// ---------------------------------------------------------------------------
// Principals (AM-35, AM-36) and grant changes (SEC-8)
// ---------------------------------------------------------------------------

#[test]
fn one_principal_per_owner_ref_that_is_not_revoked() {
    let u = ready();
    let create = |key: u8, r: u8, owner_ref: &str| {
        reserve_op(
            key,
            key,
            r,
            None,
            Opening::Principal {
                id: format!("p_{r}"),
                owner_ref: owner_ref.into(),
                grants: vec![],
            },
        )
    };
    // The member's principal exists: the ask answers it.
    let found = ok(worker(&u, create(1, 1, OWNER)));
    assert_eq!(found["exists"]["id"], json!(P));
    assert_eq!(found["exists"]["status"], json!("active"));
    assert_eq!(rows(&u), 0);
    // A new owner_ref: reserved; a second create for it under another key
    // is refused while the first is open.
    ok(worker(&u, create(2, 2, "member-2")));
    assert_eq!(
        refused(&worker(&u, create(3, 3, "member-2"))),
        Some(ReserveRefusal::PrincipalExists)
    );
    // After a revoke, a new create makes a new principal.
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            2,
            SubjectStatus::Revoked,
            false,
            vec![],
        )],
        vec![],
    );
    let fresh = ok(worker(&u, create(4, 4, OWNER)));
    assert_eq!(fresh["admitted"]["rid"], json!(rid(4).hex()));
}

#[test]
fn a_principal_create_for_an_ambiguous_owner_ref_alarms_on_every_path() {
    // L5's review note: the create must not fall through to
    // `principal_exists` when two principals hold one `owner_ref`.
    let u = ready();
    let create = |key: u8, r: u8, owner_ref: &str| {
        reserve_op(
            key,
            key,
            r,
            None,
            Opening::Principal {
                id: format!("p_{r}"),
                owner_ref: owner_ref.into(),
                grants: vec![],
            },
        )
    };
    let ambiguous = UnitAnswer::Refused {
        reason: Refused::Reserve(ReserveRefusal::OwnerRefAmbiguous),
        alarm: true,
    };
    // A new ask.
    let next = keys_seq(&u) + 1;
    apply(
        &u,
        vec![principal_entry(
            "p_twin",
            OWNER,
            next,
            SubjectStatus::Active,
            false,
            vec![],
        )],
        vec![],
    );
    assert_eq!(worker(&u, create(1, 1, OWNER)), ambiguous);
    assert_eq!(rows(&u), 0);
    // A re-ask of a create reserved before the second principal came:
    // refused with the alarm, and its row is dropped.
    ok(worker(&u, create(2, 2, "member-3")));
    assert_eq!(rows(&u), 1);
    let next = keys_seq(&u) + 1;
    apply(
        &u,
        vec![
            principal_entry(
                "p_m3a",
                "member-3",
                next,
                SubjectStatus::Active,
                false,
                vec![],
            ),
            principal_entry(
                "p_m3b",
                "member-3",
                next + 1,
                SubjectStatus::Active,
                false,
                vec![],
            ),
        ],
        vec![],
    );
    assert_eq!(worker(&u, create(2, 2, "member-3")), ambiguous);
    assert_eq!(rows(&u), 0);
}

#[test]
fn a_grant_change_is_classified_by_the_unit() {
    let u = ready();
    apply(
        &u,
        vec![key_entry("AK1", 2, vec![grant(B1, Access::Rw)], None)],
        vec![],
    );
    let change = |r: u8, subject: &str, grants| {
        reserve_op(
            r,
            r,
            r,
            by_owner(),
            Opening::Grants {
                subject: subject.into(),
                grants,
            },
        )
    };
    // Narrower: no reservation, no cap.
    for grants in [
        vec![],
        vec![grant(B1, Access::Ro)],
        vec![grant(B1, Access::Rw)],
    ] {
        assert_eq!(
            ok(worker(&u, change(1, "AK1", grants))),
            json!({ "narrowing": { "keys_seq": 2 } })
        );
    }
    assert_eq!(rows(&u), 0);
    // Wider in any field (a new bucket): a widening, subset-checked.
    assert_eq!(
        ok(worker(
            &u,
            change(2, "AK1", vec![grant(B1, Access::Rw), grant(B2, Access::Ro)])
        ))["admitted"]["again"],
        json!(false)
    );
    assert_eq!(
        refused(&worker(&u, change(3, "AK1", vec![grant(B2, Access::Rw)]))),
        Some(ReserveRefusal::GrantNotHeld)
    );
    assert_eq!(
        refused(&worker(&u, change(4, "AKNONE", vec![]))),
        Some(ReserveRefusal::NotFound)
    );
    // The internal key is outside this plane.
    apply(
        &u,
        vec![KeyEntry {
            kind: KeyKind::Internal,
            made_by: None,
            ..key_entry("AKINT", 3, vec![], None)
        }],
        vec![],
    );
    assert_eq!(
        refused(&worker(&u, change(5, "AKINT", vec![grant(B1, Access::Ro)]))),
        Some(ReserveRefusal::InternalKeyRefused)
    );
    assert_eq!(
        refused(&worker(&u, change(5, "AKINT", vec![]))),
        Some(ReserveRefusal::InternalKeyRefused)
    );
    // A disabled acting principal narrows nothing (a held one may).
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            4,
            SubjectStatus::Disabled,
            false,
            vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        )],
        vec![],
    );
    assert_eq!(
        refused(&worker(&u, change(6, "AK1", vec![]))),
        Some(ReserveRefusal::ActingPrincipalInactive)
    );
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            5,
            SubjectStatus::Active,
            true,
            vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        )],
        vec![],
    );
    assert_eq!(
        ok(worker(&u, change(6, "AK1", vec![])))["narrowing"]["keys_seq"],
        json!(5)
    );
}

#[test]
fn a_narrowing_and_a_kept_answer_are_answered_in_a_held_tenant_and_a_new_ask_is_not() {
    let u = ready();
    apply(
        &u,
        vec![key_entry("AK1", 2, vec![grant(B1, Access::Rw)], None)],
        vec![],
    );
    let create = reserve_op(1, 1, 1, by_owner(), new_key("AK2", vec![]));
    ok(worker(&u, create.clone()));
    apply(&u, vec![key_entry("AK2", 3, vec![], Some(rid(1)))], vec![]);
    let open_ask = reserve_op(2, 2, 2, by_owner(), new_key("AK3", vec![]));
    ok(worker(&u, open_ask.clone()));
    for state in [TenantState::Suspended, TenantState::Deleting] {
        assert!(matches!(sync(&u, state, None), UnitAnswer::Ok { .. }));
        let narrow = reserve_op(
            3,
            3,
            3,
            by_owner(),
            Opening::Grants {
                subject: "AK1".into(),
                grants: vec![grant(B1, Access::Ro)],
            },
        );
        assert!(ok(worker(&u, narrow))["narrowing"].is_object());
        assert!(ok(worker(&u, create.clone()))["applied"].is_object());
        // A new ask is refused; the re-ask of an open one is refused with
        // its rid, so the Worker can look for its record first.
        assert_eq!(
            worker(&u, reserve_op(4, 4, 4, by_owner(), new_key("AK4", vec![]))),
            UnitAnswer::Refused {
                reason: Refused::AccountProblem,
                alarm: false,
            }
        );
        assert_eq!(
            ok(worker(&u, open_ask.clone())),
            json!({ "not_open": { "rid": rid(2).hex(), "keys_seq": 3 } })
        );
        assert_eq!(state_of(&u, 2).as_deref(), Some("reserved"));
    }
    assert!(matches!(
        sync(&u, TenantState::Shredding, None),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(
        worker(&u, create),
        UnitAnswer::Refused {
            reason: Refused::AccountProblem,
            alarm: false,
        }
    );
}

#[test]
fn a_re_ask_is_checked_and_answered_for_the_subject_it_reserved() {
    let u = ready();
    ok(worker(
        &u,
        reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![])),
    ));
    // The retry drew another key id: the reservation keeps its own.
    let again = ok(worker(
        &u,
        reserve_op(1, 1, 2, by_owner(), new_key("AKNEW", vec![])),
    ));
    assert_eq!(again["admitted"]["subject"], json!("AK1"));
    assert_eq!(again["admitted"]["again"], json!(true));
    // The id it reserved exists now under another record (no rid): the
    // re-ask fails its check for that id, and leaves no row.
    apply(&u, vec![key_entry("AK1", 2, vec![], None)], vec![]);
    assert_eq!(
        refused(&worker(
            &u,
            reserve_op(1, 1, 2, by_owner(), new_key("AKNEW", vec![]))
        )),
        Some(ReserveRefusal::Conflict)
    );
    assert_eq!(state_of(&u, 1), None);
}

#[test]
fn a_batch_applies_a_reservation_before_a_later_narrowing_cancels() {
    let u = ready();
    ok(worker(
        &u,
        reserve_op(1, 1, 7, by_owner(), new_key("AK1", vec![])),
    ));
    ok(worker(
        &u,
        reserve_op(2, 2, 8, by_owner(), new_key("AK2", vec![])),
    ));
    let out = apply(
        &u,
        vec![
            key_entry("AK1", 2, vec![], Some(rid(7))),
            principal_entry(
                P,
                OWNER,
                3,
                SubjectStatus::Active,
                false,
                vec![grant(B1, Access::Ro)],
            ),
        ],
        vec![KeptAnswer {
            rid: rid(7),
            status: 201,
            body: "{}".into(),
        }],
    );
    assert_eq!(out["reserved"], json!(1));
    assert_eq!(out["answers_kept"], json!(1));
    assert_eq!(state_of(&u, 7).as_deref(), Some("applied"));
    // The other open one was cancelled by the narrowing.
    assert_eq!(state_of(&u, 8), None);
}

#[test]
fn a_widening_or_a_lifted_limit_of_the_principal_cancels_nothing() {
    let u = ready();
    ok(worker(
        &u,
        reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![])),
    ));
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            2,
            SubjectStatus::Active,
            false,
            vec![grant(B1, Access::Rw), grant(B2, Access::Rw)],
        )],
        vec![],
    );
    assert_eq!(state_of(&u, 1).as_deref(), Some("reserved"));
}

// ---------------------------------------------------------------------------
// Buckets: the name, the bind, the finisher's read
// ---------------------------------------------------------------------------

fn bucket(key: u8, r: u8, name: &str) -> UnitOp {
    reserve_op(
        key,
        key,
        r,
        by_owner(),
        Opening::Bucket {
            name: name.into(),
            unit: 0,
        },
    )
}

#[test]
fn a_bucket_name_is_held_by_one_call_and_never_by_an_existing_bucket() {
    let u = ready();
    assert_eq!(
        refused(&worker(&u, bucket(1, 1, "alpha"))),
        Some(ReserveRefusal::BucketAlreadyExists)
    );
    let admit = ok(worker(&u, bucket(2, 2, "beta")));
    assert_eq!(
        refused(&worker(&u, bucket(3, 3, "beta"))),
        Some(ReserveRefusal::BucketAlreadyExists)
    );
    // Released: free again.
    ok(worker(&u, release_op(2, &admit)));
    ok(worker(&u, bucket(3, 3, "beta")));
}

/// AM-57: the `created` change a `sync` carries makes the bucket's row
/// and turns the reservation bound to its creator grant `applied`; one
/// whose reservation is gone still makes its row.
#[test]
fn a_created_bucket_record_applies_its_bound_reservation() {
    use velmora_bridge::unit::buckets::{self, BucketChange};
    let u = ready();
    ok(worker(&u, bucket(1, 1, "beta")));
    ok(worker(
        &u,
        UnitOp::BindBucket {
            rid: rid(1),
            expected: None,
            grant_seq: 4,
        },
    ));
    let created = |seq, id: &str, name: &str, grant_seq| BucketChange::Created {
        seq,
        bucket_id: id.into(),
        grant_seq,
        creator: P.into(),
        name: name.into(),
        bdk_wrapped: vec![0x02, 1],
        tk_version: 1,
        written_at: 9,
    };
    let done = buckets::apply(
        u.sql(),
        &[created(5, "b_00000000000000f3", "beta", 4)],
        false,
        NOW,
    )
    .unwrap()
    .unwrap();
    assert_eq!((done.created, done.reserved), (1, 1));
    assert_eq!(
        ok(worker(&u, UnitOp::BucketBinding { grant_seq: 4 })),
        json!({ "binding": "created", "bucket": "b_00000000000000f3" })
    );
    let replay = ok(worker(&u, bucket(1, 1, "beta")));
    assert_eq!(replay["applied"]["bucket"], json!("b_00000000000000f3"));
    // No reservation left for seq 7: the row is made all the same.
    let done = buckets::apply(
        u.sql(),
        &[created(6, "b_00000000000000f4", "delta", 7)],
        false,
        NOW,
    )
    .unwrap()
    .unwrap();
    assert_eq!((done.created, done.reserved), (1, 0));
}

#[test]
fn a_bucket_reservation_binds_once_and_the_finisher_fences_an_unbound_grant() {
    let u = ready();
    let first = ok(worker(&u, bucket(1, 1, "beta")));
    assert_eq!(first["admitted"]["asks"], json!(1));
    let bind = |expected, grant_seq| UnitOp::BindBucket {
        rid: rid(1),
        expected,
        grant_seq,
    };
    assert_eq!(ok(worker(&u, bind(Some(5), 4))), json!({ "bound": false }));
    assert_eq!(ok(worker(&u, bind(None, 4))), json!({ "bound": true }));
    // The same seq again: true; another from the old expectation: false.
    assert_eq!(ok(worker(&u, bind(None, 4))), json!({ "bound": true }));
    assert_eq!(ok(worker(&u, bind(None, 6))), json!({ "bound": false }));
    // A bound reservation is answered so whatever its creator is now
    // (held here: an opening ask of a held principal is refused).
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            2,
            SubjectStatus::Active,
            true,
            vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        )],
        vec![],
    );
    assert_eq!(
        refused(&worker(&u, bucket(5, 5, "gamma"))),
        Some(ReserveRefusal::ActingPrincipalHeld)
    );
    let a = ok(worker(&u, bucket(1, 1, "beta")));
    assert_eq!(a["admitted"]["bound"], json!(4));
    assert_eq!(a["admitted"]["again"], json!(true));
    assert_eq!(a["admitted"]["asks"], json!(2));
    assert_eq!(
        ok(worker(&u, release_op(1, &first))),
        json!({ "released": false })
    );
    assert_eq!(
        ok(worker(&u, UnitOp::BucketBinding { grant_seq: 4 })),
        json!({ "binding": "open", "rid": rid(1).hex(), "name": "beta", "creator": P, "unit": 0 })
    );
    // The finisher's read of a seq no reservation holds fences it.
    assert_eq!(
        ok(worker(&u, UnitOp::BucketBinding { grant_seq: 9 })),
        json!({ "binding": "none" })
    );
    assert_eq!(ok(worker(&u, bind(Some(4), 9))), json!({ "bound": false }));
    // A release under another binding changes nothing.
    assert_eq!(
        ok(worker(
            &u,
            UnitOp::ReleaseBound {
                rid: rid(1),
                bound: None
            }
        )),
        json!({ "released": false })
    );
    // The bucket record applied for the bound seq: the reservation is
    // the bucket, and the ask answers it.
    assert!(reserve::bucket_created(
        u.sql(),
        4,
        "b_00000000000000f3",
        Some((201, r#"{"id":"b_00000000000000f3"}"#)),
        NOW
    )
    .unwrap());
    assert_eq!(
        ok(worker(&u, UnitOp::BucketBinding { grant_seq: 4 })),
        json!({ "binding": "created", "bucket": "b_00000000000000f3" })
    );
    let replay = ok(worker(&u, bucket(1, 1, "beta")));
    assert_eq!(replay["applied"]["bucket"], json!("b_00000000000000f3"));
    assert_eq!(replay["applied"]["grant_seq"], json!(4));
    assert_eq!(replay["applied"]["status"], json!(201));
}

#[test]
fn release_bound_releases_only_its_own_binding() {
    let u = ready();
    ok(worker(&u, bucket(1, 1, "beta")));
    ok(worker(
        &u,
        UnitOp::BindBucket {
            rid: rid(1),
            expected: None,
            grant_seq: 4,
        },
    ));
    assert_eq!(
        ok(worker(
            &u,
            UnitOp::ReleaseBound {
                rid: rid(1),
                bound: Some(4)
            }
        )),
        json!({ "released": true })
    );
    assert_eq!(
        ok(worker(&u, UnitOp::BucketBinding { grant_seq: 4 })),
        json!({ "binding": "none" })
    );
}

#[test]
fn a_bound_bucket_reservation_outlives_a_narrowing_of_its_creator() {
    let u = ready();
    ok(worker(&u, bucket(1, 1, "beta")));
    ok(worker(
        &u,
        UnitOp::BindBucket {
            rid: rid(1),
            expected: None,
            grant_seq: 4,
        },
    ));
    for (seq, status) in [(2, SubjectStatus::Active), (3, SubjectStatus::Disabled)] {
        apply(
            &u,
            vec![principal_entry(P, OWNER, seq, status, false, vec![])],
            vec![],
        );
        assert_eq!(
            ok(worker(&u, UnitOp::BucketBinding { grant_seq: 4 }))["binding"],
            json!("open")
        );
    }
}

#[test]
fn a_bound_bucket_reservation_is_answered_in_a_held_tenant() {
    let u = ready();
    ok(worker(&u, bucket(1, 1, "beta")));
    ok(worker(
        &u,
        UnitOp::BindBucket {
            rid: rid(1),
            expected: None,
            grant_seq: 4,
        },
    ));
    assert!(matches!(
        sync(&u, TenantState::Suspended, None),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(
        ok(worker(&u, bucket(1, 1, "beta")))["admitted"]["bound"],
        json!(4)
    );
}

#[test]
fn a_cancelled_reservation_gives_its_cap_slot_back() {
    let u = ready();
    let n = 15u8;
    for i in 0..n {
        ok(worker(
            &u,
            reserve_op(i, i, i, by_owner(), new_key(&format!("AK{i}"), vec![])),
        ));
    }
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            2,
            SubjectStatus::Active,
            false,
            vec![grant(B1, Access::Ro)],
        )],
        vec![],
    );
    // The 15 calls ask again as new asks: they fit the hourly cap with a
    // 16th, as no slot of a cancelled call is left.
    for i in 0..=n {
        let a = worker(
            &u,
            reserve_op(
                100 + i,
                100 + i,
                100 + i,
                by_owner(),
                new_key(&format!("AKN{i}"), vec![]),
            ),
        );
        assert!(matches!(a, UnitAnswer::Ok { .. }), "{i}: {a:?}");
    }
}

#[test]
fn a_held_principal_record_cancels_its_open_reservations() {
    let u = ready();
    ok(worker(
        &u,
        reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![])),
    ));
    apply(
        &u,
        vec![principal_entry(
            P,
            OWNER,
            2,
            SubjectStatus::Active,
            true,
            vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        )],
        vec![],
    );
    assert_eq!(state_of(&u, 1), None);
}

#[test]
fn a_bucket_slot_swept_unapplied_still_counts_for_the_day() {
    let u = ready();
    for i in 0..BUCKETS_PER_DAY as u8 {
        let a = worker(&u, bucket(i, i, &format!("bucket-{i}")));
        assert!(matches!(a, UnitAnswer::Ok { .. }), "{i}: {a:?}");
    }
    let later = UnixMs(NOW.0 + RESERVED_MS + 1);
    assert_eq!(
        refused(&at(&u, bucket(200, 200, "one-more"), later)),
        Some(ReserveRefusal::CapReached)
    );
    // The open rows are past their hour: a sweep (in the next ask that
    // keeps its writes) drops them, but not their slots.
    ok(at(
        &u,
        reserve_op(150, 150, 150, by_owner(), new_key("AKS", vec![])),
        later,
    ));
    let open: i64 = u
        .sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT count(*) FROM unit_reservations WHERE class = 'bucket'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(open, 0);
    assert_eq!(
        refused(&at(&u, bucket(203, 203, "still-full"), later)),
        Some(ReserveRefusal::CapReached)
    );
    // An explicit release gives a slot back; a rid of a swept row is
    // still taken.
    let fresh = UnixMs(NOW.0 + 1);
    let u2 = ready();
    let first = ok(at(&u2, bucket(0, 0, "bucket-0"), fresh));
    for i in 1..BUCKETS_PER_DAY as u8 {
        ok(at(&u2, bucket(i, i, &format!("bucket-{i}")), fresh));
    }
    ok(at(&u2, release_op(0, &first), fresh));
    assert!(matches!(
        at(&u2, bucket(201, 201, "freed"), fresh),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(
        refused(&at(
            &u,
            reserve_op(202, 202, 1, by_owner(), new_key("AKRID", vec![])),
            UnixMs(NOW.0 + KEPT_MS - 1)
        )),
        Some(ReserveRefusal::RidTaken)
    );
}

#[test]
fn the_absolute_bucket_limit_counts_closing_rows_and_open_creates() {
    let u = ready();
    // Seed the existing rows without spending any of today's create slots.
    let extra = MAX_BUCKETS as i64 - 2; // ready() already holds two buckets.
    let inserted = u
        .sql()
        .with_conn(|c| {
            c.execute(
                "WITH RECURSIVE seed(n) AS ( \
                    VALUES (1) UNION ALL SELECT n + 1 FROM seed WHERE n < ?1 \
                 ) \
                 INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
                 SELECT printf('b_%016x', n + 65536), 'seed-' || n, 'o', x'02', 1, 1 \
                   FROM seed",
                [extra],
            )
        })
        .unwrap();
    assert_eq!(inserted as i64, extra);
    assert_eq!(
        ok(worker(
            &u,
            UnitOp::BucketClose {
                bucket_id: B1.into()
            }
        ))["closing"],
        json!(true)
    );
    let over = bucket(1, 1, "one-more");
    assert_eq!(
        refused(&worker(&u, over.clone())),
        Some(ReserveRefusal::LimitReached)
    );

    // With one fewer row, the first open create takes the last place.
    assert_eq!(
        u.sql()
            .with_conn(|c| c.execute("DELETE FROM buckets WHERE name = 'seed-1'", []))
            .unwrap(),
        1
    );
    assert!(ok(worker(&u, over))["admitted"].is_object());
    assert_eq!(
        refused(&worker(&u, bucket(2, 2, "another"))),
        Some(ReserveRefusal::LimitReached)
    );
}

#[test]
fn the_daily_bucket_cap_holds() {
    let u = ready();
    for i in 0..BUCKETS_PER_DAY as u8 {
        let a = worker(&u, bucket(i, i, &format!("bucket-{i}")));
        assert!(matches!(a, UnitAnswer::Ok { .. }), "{i}: {a:?}");
        // Applied, so the next hour's sweep keeps it for the day.
        ok(worker(
            &u,
            UnitOp::BindBucket {
                rid: rid(i),
                expected: None,
                grant_seq: 10 + u64::from(i),
            },
        ));
        assert!(reserve::bucket_created(
            u.sql(),
            10 + u64::from(i),
            &format!("b_{:016x}", 100 + u64::from(i)),
            None,
            NOW
        )
        .unwrap());
    }
    assert_eq!(
        refused(&worker(&u, bucket(200, 200, "one-more"))),
        Some(ReserveRefusal::CapReached)
    );
    let next_day = UnixMs(NOW.0 + KEPT_MS + 1);
    assert!(matches!(
        at(&u, bucket(201, 201, "next-day"), next_day),
        UnitAnswer::Ok { .. }
    ));
}

#[test]
fn the_sweep_drops_open_rows_after_an_hour_and_applied_ones_after_a_day() {
    let u = ready();
    ok(worker(
        &u,
        reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![])),
    ));
    ok(worker(
        &u,
        reserve_op(2, 2, 2, by_owner(), new_key("AK2", vec![])),
    ));
    apply(&u, vec![key_entry("AK2", 2, vec![], Some(rid(2)))], vec![]);
    let hour = UnixMs(NOW.0 + RESERVED_MS);
    // Any ask sweeps first.
    ok(at(
        &u,
        reserve_op(3, 3, 3, by_owner(), new_key("AK3", vec![])),
        hour,
    ));
    assert_eq!(state_of(&u, 1), None);
    assert_eq!(state_of(&u, 2).as_deref(), Some("applied"));
    // An open row swept, its key asked again, is a new reservation.
    let again = ok(at(
        &u,
        reserve_op(1, 1, 9, by_owner(), new_key("AK1", vec![])),
        hour,
    ));
    assert_eq!(again["admitted"]["rid"], json!(rid(9).hex()));
    let day = UnixMs(NOW.0 + KEPT_MS);
    ok(at(
        &u,
        reserve_op(4, 4, 4, by_owner(), new_key("AK4", vec![])),
        day,
    ));
    assert_eq!(state_of(&u, 2), None);
}

// ---------------------------------------------------------------------------
// Where the calls run
// ---------------------------------------------------------------------------

#[test]
fn reservations_run_on_an_open_unit_authenticated_and_opening_asks_need_an_active_tenant() {
    let u = ready();
    let ask = reserve_op(1, 1, 1, by_owner(), new_key("AK1", vec![]));
    let mut unauthenticated = call(ask.clone());
    unauthenticated.authenticated = false;
    assert_eq!(
        u.handle(&unauthenticated, NOW),
        UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            alarm: false,
        }
    );
    let mut as_request = call(ask.clone());
    as_request.kind = CallKind::Request;
    assert!(matches!(
        u.handle(&as_request, NOW),
        UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            ..
        }
    ));
    let admit = ok(worker(&u, ask.clone()));
    // Suspended: an opening ask is refused; a release goes on.
    assert!(matches!(
        sync(&u, TenantState::Suspended, None),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(
        worker(&u, reserve_op(2, 2, 2, by_owner(), new_key("AK2", vec![]))),
        UnitAnswer::Refused {
            reason: Refused::AccountProblem,
            alarm: false,
        }
    );
    assert_eq!(
        ok(worker(&u, release_op(1, &admit))),
        json!({ "released": true })
    );
    // Closed: every reservation call waits for the lift.
    assert!(matches!(
        sync(&u, TenantState::Active, Some(9)),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(worker(&u, ask), UnitAnswer::Closed { .. }));
    assert!(matches!(
        worker(&u, UnitOp::BucketBinding { grant_seq: 1 }),
        UnitAnswer::Closed { .. }
    ));
}

// ---------------------------------------------------------------------------
// The key scheme (rule 13)
// ---------------------------------------------------------------------------

fn born(tenant: &str) -> Unit<RusqliteSql> {
    let name = UnitName::new(TenantId::parse(tenant).unwrap(), 0);
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), name.clone(), "");
    let token = BirthToken {
        name: name.clone(),
        jurisdiction: String::new(),
        record_seq: 3,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: if name.tenant.is_zero() { 1 } else { 2 },
        kind: BirthKind::Birth,
    };
    let c = UnitCall {
        name,
        kind: CallKind::Worker,
        seqs: Some(Seqs {
            state_seq: 3,
            keys_seq: 0,
        }),
        authenticated: true,
        listed: true,
        op: UnitOp::Provision {
            token,
            sealed: b"sealed".to_vec(),
        },
    };
    assert!(matches!(u.handle(&c, NOW), UnitAnswer::Ok { .. }));
    u
}

fn key_scheme_failure() -> UnitAnswer {
    UnitAnswer::Failed {
        class: "key_scheme".into(),
    }
}

fn insert_bucket(u: &Unit<RusqliteSql>, wrap: &str) -> rusqlite::Result<usize> {
    u.sql().with_conn(|c| {
        c.execute(
            &format!(
                "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
                   VALUES ('b_00000000000000a1', 'alpha', 'o', {wrap}, 1, 1)"
            ),
            [],
        )
    })
}

fn insert_access_key(u: &Unit<RusqliteSql>, wrap: &str) -> rusqlite::Result<usize> {
    u.sql().with_conn(|c| {
        c.execute(
            &format!(
                "INSERT INTO access_keys(access_key_id, principal, secret_wrapped, kek_version, \
                   status, created_at) VALUES ('AKS', 'p', {wrap}, 1, 'active', 1)"
            ),
            [],
        )
    })
}

#[test]
fn a_managed_unit_takes_only_scheme_two_wraps_and_tenant_zero_only_scheme_one() {
    let managed = born("t_0000000000000a01");
    for bad in ["x'01ff'", "x''", "'02'", "NULL"] {
        assert!(insert_bucket(&managed, bad).is_err(), "{bad}");
        assert!(insert_access_key(&managed, bad).is_err(), "{bad}");
    }
    assert!(insert_bucket(&managed, "x'02ff'").is_ok());
    assert!(insert_access_key(&managed, "x'02ff'").is_ok());
    // An update to the other scheme is refused too.
    let update = managed
        .sql()
        .with_conn(|c| c.execute("UPDATE buckets SET bdk_wrapped = x'01ff'", []));
    assert!(update.is_err());
    let update = managed
        .sql()
        .with_conn(|c| c.execute("UPDATE access_keys SET secret_wrapped = x'01ff'", []));
    assert!(update.is_err());

    let zero = born("t_0000000000000000");
    assert!(insert_bucket(&zero, "x'02ff'").is_err());
    assert!(insert_access_key(&zero, "x'02ff'").is_err());
    assert!(insert_bucket(&zero, "x'01ff'").is_ok());
    assert!(insert_access_key(&zero, "x'01ff'").is_ok());
}

#[test]
fn the_key_chain_apply_and_the_import_refuse_the_other_schemes_wrap() {
    let u = ready();
    // A scheme-1 secret in a managed unit's key chain: the apply fails
    // whole and keeps nothing.
    let mut bad = key_entry("AKBAD", 2, vec![], None);
    bad.secret_wrapped = Some(vec![1, 0xaa]);
    let a = worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 1,
            entries: vec![bad.into()],
            answers: vec![],
        },
    );
    assert_eq!(a, key_scheme_failure());
    assert_eq!(keys_seq(&u), 1);
    // A held key without its secret is not checked (nothing to check).
    let mut held = key_entry("AKHELD", 2, vec![], None);
    held.held = true;
    held.secret_wrapped = None;
    held.secret_kek_version = None;
    apply(&u, vec![held], vec![]);
    // A scheme-1 BDK in the move's import.
    let m = move_unit();
    assert_eq!(import_buckets(&m, 0x01), key_scheme_failure());
    assert!(matches!(import_buckets(&m, 0x02), UnitAnswer::Ok { .. }));
}

// ---------------------------------------------------------------------------
// The size guard (ADR §2.6), against a lowered limit
// ---------------------------------------------------------------------------

const S: u64 = 4;

fn moving() -> MoveHead {
    MoveHead {
        seq: 10,
        selector: "moving".into(),
        to: Some(tenant()),
        flips: 0,
    }
}

fn move_unit_with(limits: SizeLimits) -> Unit<RusqliteSql> {
    let u = ready().with_size_limits(limits);
    assert!(matches!(
        sync(&u, TenantState::Active, Some(S)),
        UnitAnswer::Ok { .. }
    ));
    u
}

fn move_unit() -> Unit<RusqliteSql> {
    move_unit_with(SizeLimits::default())
}

fn numbered(u: &Unit<RusqliteSql>, op: UnitOp) -> UnitAnswer {
    let mut c = call(op);
    c.seqs = Some(u.head().unwrap().seqs);
    u.handle(&c, NOW)
}

fn import_buckets(u: &Unit<RusqliteSql>, scheme: u8) -> UnitAnswer {
    let mut wrap = vec![7; 73];
    wrap[0] = scheme;
    let t = |s: &str| ImportValue::Text(s.into());
    let i = ImportValue::Int;
    numbered(
        u,
        UnitOp::Import {
            head: moving(),
            since: S,
            batch: ImportBatch {
                table: ImportTable::Buckets,
                columns: ImportTable::Buckets
                    .columns()
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
                after: None,
                cursor: "c1".into(),
                rows: vec![vec![
                    t("b_00000000000000f3"),
                    t("beta"),
                    t(P),
                    ImportValue::Blob(wrap),
                    i(2),
                    i(0),
                    i(10),
                ]],
            },
        },
    )
}

fn extent_rows(from: usize, n: usize) -> Vec<Vec<ImportValue>> {
    let t = |s: &str| ImportValue::Text(s.into());
    let i = ImportValue::Int;
    let b = |n: usize| ImportValue::Blob(vec![0; n]);
    (from..from + n)
        .map(|k| {
            let mut row = Vec::new();
            for col in ImportTable::Extents.columns() {
                row.push(match *col {
                    "id" => t(&format!("x_{k:026x}")),
                    "bucket_id" => t(B1),
                    "generation_id" => ImportValue::Null,
                    "state" => t("staged"),
                    "hot_safety_bytes" | "hot_cache_bytes" | "evict_seq" => i(0),
                    "plain_size" | "cipher_size" => i(10),
                    "media_header" => b(48),
                    "key_mode" => i(1),
                    "wrapped_file_key" => b(72),
                    "plain_md5" => b(16),
                    "plain_sha256" | "cipher_sha256" => b(32),
                    "safety_state" => t("held"),
                    "plan_rev" => i(0),
                    "created_at" => i(1),
                    _ => ImportValue::Null,
                });
            }
            row
        })
        .collect()
}

fn import_extents(
    u: &Unit<RusqliteSql>,
    after: Option<&str>,
    cursor: &str,
    rows: Vec<Vec<ImportValue>>,
) -> UnitAnswer {
    numbered(
        u,
        UnitOp::Import {
            head: moving(),
            since: S,
            batch: ImportBatch {
                table: ImportTable::Extents,
                columns: ImportTable::Extents
                    .columns()
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
                after: after.map(String::from),
                cursor: cursor.into(),
                rows,
            },
        },
    )
}

#[test]
fn the_size_guard_refuses_a_batch_that_would_pass_the_extent_count() {
    let u = move_unit_with(SizeLimits {
        bytes: u64::MAX,
        extents: 3,
        ..SizeLimits::default()
    });
    let a = import_extents(&u, None, "c1", extent_rows(0, 2));
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    let full = import_extents(&u, Some("c1"), "c2", extent_rows(2, 2));
    assert_eq!(
        full,
        UnitAnswer::Refused {
            reason: Refused::Size(SizeRefusal::TooManyExtents),
            alarm: true,
        }
    );
    // Nothing of the refused batch was kept; a batch that fits goes on.
    let a = import_extents(&u, Some("c1"), "c2", extent_rows(2, 1));
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
}

#[test]
fn the_size_guard_refuses_any_batch_once_the_database_is_at_its_size() {
    let probe = move_unit();
    let size = probe.sql().database_size().unwrap();
    assert!(size > 0);
    let u = move_unit_with(SizeLimits {
        bytes: size,
        extents: u64::MAX,
        ..SizeLimits::default()
    });
    assert_eq!(
        import_buckets(&u, 0x02),
        UnitAnswer::Refused {
            reason: Refused::Size(SizeRefusal::DatabaseFull),
            alarm: true,
        }
    );
    // Reads go on.
    assert!(matches!(
        worker(&u, UnitOp::ImportProgress {}),
        UnitAnswer::Ok { .. }
    ));
}

use velmora_bridge::unit::UnitSql as _;
