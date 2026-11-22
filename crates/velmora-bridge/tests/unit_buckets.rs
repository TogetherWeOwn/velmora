//! The unit side of bucket records (AM-57): `bucket_close`, the bucket
//! changes a `sync` carries and the placement check, on the native
//! database. `workers/unit-suite` runs this file against a Durable Object
//! too.

use serde_json::json;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::buckets::{
    self, BucketChange, BucketRefusal, BucketsApplied, MAX_CHANGES,
};
use velmora_bridge::unit::call::HoldMode;
use velmora_bridge::unit::keys::{KeyEntry, KeyKind, SubjectStatus};
use velmora_bridge::unit::reserve::{Acting, Hash32, Opening, Rid};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::unit_lease::lease::Proven;
use velmora_bridge::{Sql, UnixMs};

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const B1: &str = "b_00000000000000e1";
const B2: &str = "b_00000000000000e2";
const B3: &str = "b_00000000000000e3";

fn tenant() -> TenantId {
    TenantId::parse("t_0000000000000e01").unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn call(op: UnitOp, authenticated: bool) -> UnitCall {
    UnitCall {
        name: own(),
        kind: CallKind::Worker,
        seqs: None,
        authenticated,
        listed: true,
        op,
    }
}

fn worker(u: &Unit<RusqliteSql>, op: UnitOp) -> UnitAnswer {
    u.handle(&call(op, true), NOW)
}

fn sync(
    u: &Unit<RusqliteSql>,
    state: TenantState,
    mode: Option<HoldMode>,
    placed_ids: &[&str],
) -> UnitAnswer {
    let h = u.head().unwrap();
    worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                from_seq: h.seqs.state_seq,
                seqs: Seqs {
                    state_seq: h.seqs.state_seq + 1,
                    keys_seq: h.seqs.keys_seq,
                },
                tenant_mode: mode,
                tenant_state: state,
                restoring_since: None,
                lift: None,
                buckets: vec![],
                placed: placed(placed_ids),
            },
        },
    )
}

/// A managed tenant's root unit, born and active.
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
    let mut c = call(
        UnitOp::Provision {
            token,
            sealed: b"sealed".to_vec(),
        },
        true,
    );
    c.seqs = Some(Seqs {
        state_seq: 3,
        keys_seq: 0,
    });
    assert!(matches!(u.handle(&c, NOW), UnitAnswer::Ok { .. }));
    assert!(matches!(
        sync(&u, TenantState::Active, None, &[]),
        UnitAnswer::Ok { .. }
    ));
    // Rule 12 (the unit lease, u0002): the Worker's renewal at NOW, so the
    // unit serves for T; every call of these tests runs at NOW.
    let h = u.head().unwrap();
    let renewed = worker(
        &u,
        UnitOp::Renew {
            proof_start: NOW,
            proven: Proven {
                state_seq: h.seqs.state_seq,
                keys_seq: h.seqs.keys_seq,
                stamp_counter: None,
                revoked: 0,
            },
            revocations: Vec::new(),
        },
    );
    assert!(matches!(renewed, UnitAnswer::Ok { .. }), "{renewed:?}");
    u
}

fn created(seq: u64, id: &str, name: &str, grant_seq: u64) -> BucketChange {
    BucketChange::Created {
        seq,
        bucket_id: id.into(),
        grant_seq,
        creator: "p_owner".into(),
        name: name.into(),
        bdk_wrapped: vec![0x02, 9, 9],
        tk_version: 1,
        written_at: 1_700,
    }
}

fn dropped(seq: u64, id: &str) -> BucketChange {
    BucketChange::Dropped {
        seq,
        bucket_id: id.into(),
    }
}

fn apply(
    u: &Unit<RusqliteSql>,
    changes: &[BucketChange],
    restoring: bool,
) -> Result<BucketsApplied, BucketRefusal> {
    buckets::apply(u.sql(), changes, restoring, NOW).unwrap()
}

fn ids(u: &Unit<RusqliteSql>) -> Vec<String> {
    u.sql()
        .with_conn(|c| {
            let mut st = c.prepare("SELECT id FROM buckets ORDER BY id")?;
            let v = st
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>();
            v
        })
        .unwrap()
}

fn closing(u: &Unit<RusqliteSql>, id: &str) -> bool {
    buckets::is_closing(u.sql(), id).unwrap()
}

/// Something of the bucket's data: a key floor (any of the catalogue's
/// tables that name a bucket would do).
fn hold_something(u: &Unit<RusqliteSql>, id: &str) {
    velmora_bridge::unit::poll_once(u.sql().exec(
        "INSERT INTO key_floors(bucket_id, key, floor_id) VALUES (?1, 'k', 'g_1')",
        &[velmora_bridge::SqlValue::Text(id.into())],
    ))
    .unwrap()
    .unwrap();
}

fn placed(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn a_created_record_makes_the_row_once_and_a_conflict_is_refused() {
    let u = ready();
    let done = apply(&u, &[created(4, B1, "alpha", 2)], false).unwrap();
    assert_eq!((done.created, done.reserved), (1, 0));
    let row = u
        .sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT name, owner, bdk_wrapped, kek_version, created_at FROM buckets \
                 WHERE id = ?1",
                [B1],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                },
            )
        })
        .unwrap();
    assert_eq!(
        row,
        ("alpha".into(), "p_owner".into(), vec![2, 9, 9], 1, 1_700)
    );
    // The same record again changes nothing.
    let done = apply(&u, &[created(4, B1, "alpha", 2)], false).unwrap();
    assert_eq!(done.created, 0);
    // Another name for the id, the name for another id, or the creator
    // grant of another row: a broken chain.
    for c in [
        created(5, B1, "other", 3),
        created(5, B2, "alpha", 3),
        created(5, B2, "beta", 2),
    ] {
        assert_eq!(apply(&u, &[c], false), Err(BucketRefusal::CreatedConflict));
    }
    assert!(BucketRefusal::CreatedConflict.alarm());
    assert_eq!(ids(&u), vec![B1.to_string()]);
}

#[test]
fn a_scheme_one_wrap_is_never_made_in_a_managed_unit() {
    let u = ready();
    let mut c = created(4, B1, "alpha", 2);
    if let BucketChange::Created { bdk_wrapped, .. } = &mut c {
        bdk_wrapped[0] = 0x01;
    }
    assert!(buckets::apply(u.sql(), &[c], false, NOW).is_err());
}

#[test]
fn bucket_close_marks_an_empty_bucket_closing_and_refuses_one_that_holds_data() {
    let u = ready();
    apply(
        &u,
        &[created(4, B1, "alpha", 2), created(5, B2, "beta", 3)],
        false,
    )
    .unwrap();
    hold_something(&u, B2);
    let close = |id: &str| {
        worker(
            &u,
            UnitOp::BucketClose {
                bucket_id: id.into(),
            },
        )
    };
    assert!(matches!(
        close(B2),
        UnitAnswer::Refused {
            reason: Refused::Buckets(BucketRefusal::NotEmpty),
            alarm: false
        }
    ));
    assert!(!closing(&u, B2));
    assert!(matches!(
        close(B3),
        UnitAnswer::Refused {
            reason: Refused::Buckets(BucketRefusal::NotFound),
            ..
        }
    ));
    let first = close(B1);
    let UnitAnswer::Ok { body, .. } = first else {
        panic!("{first:?}")
    };
    assert_eq!(body, json!({ "closing": true, "newly": true }));
    assert!(closing(&u, B1));
    // Once more: the same answer, not newly.
    let UnitAnswer::Ok { body, .. } = close(B1) else {
        panic!()
    };
    assert_eq!(body, json!({ "closing": true, "newly": false }));
    // Only authenticated, and only in an active tenant.
    assert!(matches!(
        u.handle(
            &call(
                UnitOp::BucketClose {
                    bucket_id: B1.into()
                },
                false
            ),
            NOW
        ),
        UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            ..
        }
    ));
    assert!(matches!(
        sync(
            &u,
            TenantState::Suspended,
            Some(HoldMode::ReadOnly),
            &[B1, B2],
        ),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        close(B1),
        UnitAnswer::Refused {
            reason: Refused::AccountProblem,
            ..
        }
    ));
}

#[test]
fn a_dropped_record_drops_an_empty_row_and_keeps_one_that_holds_data_closing() {
    let u = ready();
    apply(
        &u,
        &[
            created(4, B1, "alpha", 2),
            created(5, B2, "beta", 3),
            created(6, B3, "gamma", 4),
        ],
        false,
    )
    .unwrap();
    // B1 closed by `bucket_close`; B2 not closed (a restore took the
    // close back) and empty; B3 not closed and holding data.
    worker(
        &u,
        UnitOp::BucketClose {
            bucket_id: B1.into(),
        },
    );
    hold_something(&u, B3);
    let done = apply(&u, &[dropped(7, B1), dropped(8, B2), dropped(9, B3)], false).unwrap();
    assert_eq!(done.dropped, 2);
    assert_eq!(done.drop_not_closed, vec![B3.to_string()]);
    assert_eq!(ids(&u), vec![B3.to_string()]);
    assert!(closing(&u, B3));
    // The kept row gives its name up (`~dropped/<id>`), so a later
    // `created` takes it; the head no longer places it, so the placement
    // check leaves it out.
    assert_eq!(name_of(&u, B3), format!("~dropped/{B3}"));
    assert!(buckets::placement_check(u.sql(), &[]).unwrap());
    let b4 = "b_00000000000000e4";
    let done = apply(&u, &[created(10, b4, "gamma", 5)], false).unwrap();
    assert_eq!(done.created, 1);
    assert!(buckets::placement_check(u.sql(), &placed(&[b4])).unwrap());
    // A dropped record for a row that is gone changes nothing.
    let done = apply(&u, &[dropped(11, B1)], false).unwrap();
    assert_eq!(done, BucketsApplied::default());
}

fn name_of(u: &Unit<RusqliteSql>, id: &str) -> String {
    u.sql()
        .with_conn(|c| c.query_row("SELECT name FROM buckets WHERE id = ?1", [id], |r| r.get(0)))
        .unwrap()
}

fn grant_rows(u: &Unit<RusqliteSql>, bucket: &str) -> i64 {
    u.sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT count(*) FROM grants WHERE bucket_id = ?1",
                [bucket],
                |r| r.get(0),
            )
        })
        .unwrap()
}

/// AM-57 step 2a: a closing row the head does not place is dropped once
/// it holds nothing; a placed closing row, or one that still holds data,
/// is kept.
#[test]
fn a_closing_row_the_head_does_not_place_is_swept_once_empty() {
    let u = ready();
    apply(
        &u,
        &[created(4, B1, "alpha", 2), created(5, B2, "beta", 3)],
        false,
    )
    .unwrap();
    for b in [B1, B2] {
        worker(
            &u,
            UnitOp::BucketClose {
                bucket_id: b.into(),
            },
        );
    }
    // Both closed by `bucket_close`; their records never came, and the
    // head places B1 only (B2's drop was taken back, say).
    hold_something(&u, B2);
    assert_eq!(buckets::sweep_closing(u.sql(), &placed(&[B1])).unwrap(), 0);
    assert!(buckets::placement_check(u.sql(), &placed(&[B1])).unwrap());
    // B2's data is gone: swept.
    u.sql()
        .with_conn(|c| c.execute("DELETE FROM key_floors WHERE bucket_id = ?1", [B2]))
        .unwrap();
    assert_eq!(buckets::sweep_closing(u.sql(), &placed(&[B1])).unwrap(), 1);
    assert_eq!(ids(&u), vec![B1.to_string()]);
    // The placed closing row stays (its record has not come).
    assert_eq!(buckets::sweep_closing(u.sql(), &placed(&[B1])).unwrap(), 0);
    assert!(closing(&u, B1));
}

/// The keys' grants on a bucket are applied before its row exists (`sync`
/// follows the key chain): the row's `created` serves them, and its drop
/// takes the bucket's grant rows and nothing else.
#[test]
fn a_created_row_serves_the_grants_already_applied_and_a_drop_removes_them() {
    use velmora_bridge::unit::keys::{Access, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
    let u = ready();
    apply(&u, &[created(4, B1, "alpha", 2)], false).unwrap();
    let g = |b: &str| KeyGrant {
        bucket_id: b.into(),
        access: Access::Rw,
        expires_at: None,
        prefix: None,
        ip_list: vec![],
    };
    let principal = KeyEntry {
        id: "p_owner".into(),
        kind: KeyKind::Principal,
        status: SubjectStatus::Active,
        held: false,
        made_by: None,
        grants: vec![g(B1), g(B2)],
        created_at: 1,
        secret_wrapped: None,
        secret_kek_version: None,
        owner_ref: Some("owner-1".into()),
        last_seq: 1,
        rid: None,
    };
    let key = KeyEntry {
        id: "AKBUCKETS00000000001".into(),
        kind: KeyKind::S3,
        made_by: Some("p_owner".into()),
        grants: vec![g(B1), g(B2)],
        secret_wrapped: Some(vec![0x02, 1]),
        secret_kek_version: Some(1),
        owner_ref: None,
        last_seq: 2,
        ..principal.clone()
    };
    let a = worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 0,
            entries: vec![principal.into(), key.into()],
            answers: vec![],
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!((grant_rows(&u, B1), grant_rows(&u, B2)), (1, 0));
    apply(&u, &[created(5, B2, "beta", 3)], false).unwrap();
    assert_eq!(grant_rows(&u, B2), 1);
    apply(&u, &[dropped(6, B2)], false).unwrap();
    assert_eq!((grant_rows(&u, B1), grant_rows(&u, B2)), (1, 0));
}

/// AM-56: once the reservation is gone, the finisher's binding read of K
/// answers `created` from the row made for K, and never fences it.
#[test]
fn a_bucket_row_answers_its_creator_grant_after_the_reservation_is_gone() {
    let u = ready();
    apply(&u, &[created(4, B1, "alpha", 7)], false).unwrap();
    let UnitAnswer::Ok { body, .. } = worker(&u, UnitOp::BucketBinding { grant_seq: 7 }) else {
        panic!()
    };
    assert_eq!(body, json!({ "binding": "created", "bucket": B1 }));
    let UnitAnswer::Ok { body, .. } = worker(&u, UnitOp::BucketBinding { grant_seq: 8 }) else {
        panic!()
    };
    assert_eq!(body, json!({ "binding": "none" }));
}

#[test]
fn unplaced_removes_nothing_under_a_restoring_entry() {
    let u = ready();
    apply(
        &u,
        &[created(4, B1, "alpha", 2), created(5, B2, "beta", 3)],
        false,
    )
    .unwrap();
    let unplaced = BucketChange::Unplaced {
        seq: 6,
        buckets: placed(&[B1, B2]),
    };
    let done = apply(&u, std::slice::from_ref(&unplaced), true).unwrap();
    assert_eq!(done, BucketsApplied::default());
    assert_eq!(ids(&u).len(), 2);
    let done = apply(&u, &[unplaced], false).unwrap();
    assert_eq!(done.dropped, 2);
    assert!(ids(&u).is_empty());
}

#[test]
fn the_placement_check_compares_the_rows_with_the_heads_list() {
    let u = ready();
    assert!(buckets::placement_check(u.sql(), &[]).unwrap());
    apply(&u, &[created(4, B1, "alpha", 2)], false).unwrap();
    assert!(buckets::placement_check(u.sql(), &placed(&[B1])).unwrap());
    // A row the head does not place, or a placed bucket with no row.
    assert!(!buckets::placement_check(u.sql(), &[]).unwrap());
    assert!(!buckets::placement_check(u.sql(), &placed(&[B1, B2])).unwrap());
    // A row closed by `bucket_close` whose record has not come is still
    // placed.
    worker(
        &u,
        UnitOp::BucketClose {
            bucket_id: B1.into(),
        },
    );
    assert!(buckets::placement_check(u.sql(), &placed(&[B1])).unwrap());
    assert!(BucketRefusal::PlacementsOff.alarm());
}

#[test]
fn the_bucket_part_of_a_sync_is_shape_checked_first() {
    use BucketRefusal::Malformed;
    let ok = |c: &[BucketChange], p: &[String]| buckets::check_shape(c, p, 3, 9);
    assert_eq!(
        ok(
            &[created(4, B1, "alpha", 2), dropped(9, B1)],
            &placed(&[B1])
        ),
        Ok(())
    );
    for changes in [
        // At or below the unit's state_seq, above the head's, or out of
        // order.
        vec![created(3, B1, "alpha", 2)],
        vec![created(10, B1, "alpha", 2)],
        vec![dropped(6, B1), dropped(5, B2)],
        vec![dropped(6, B1), dropped(6, B2)],
        // Not a name, not an id, no wrap, an empty unplace.
        vec![created(4, B1, "Not_A_Name", 2)],
        vec![created(4, "", "alpha", 2)],
        vec![BucketChange::Created {
            seq: 4,
            bucket_id: B1.into(),
            grant_seq: 2,
            creator: "p_owner".into(),
            name: "alpha".into(),
            bdk_wrapped: vec![],
            tk_version: 1,
            written_at: 1,
        }],
        vec![BucketChange::Unplaced {
            seq: 4,
            buckets: vec![],
        }],
    ] {
        assert_eq!(ok(&changes, &[]), Err(Malformed), "{changes:?}");
    }
    let many: Vec<BucketChange> = (0..=MAX_CHANGES as u64)
        .map(|i| dropped(4 + i, B1))
        .collect();
    assert_eq!(buckets::check_shape(&many, &[], 3, 1_000), Err(Malformed));
    // A placement list with a repeat or a bad id.
    assert_eq!(ok(&[], &placed(&[B1, B1])), Err(Malformed));
    assert_eq!(ok(&[], &placed(&[""])), Err(Malformed));
}

#[test]
fn a_bucket_change_reads_back_from_its_json_and_shows_no_name_or_wrap() {
    let c = created(4, B1, "secret-name", 2);
    let text = serde_json::to_string(&c).unwrap();
    assert_eq!(serde_json::from_str::<BucketChange>(&text).unwrap(), c);
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["admin"] = json!(true);
    assert!(serde_json::from_value::<BucketChange>(v).is_err());
    let shown = format!("{c:?}");
    assert!(!shown.contains("secret-name"), "{shown}");
}

fn owner_principal() -> KeyEntry {
    KeyEntry {
        id: "p_owner".into(),
        kind: KeyKind::Principal,
        status: SubjectStatus::Active,
        held: false,
        made_by: None,
        grants: vec![],
        created_at: 1,
        secret_wrapped: None,
        secret_kek_version: None,
        owner_ref: Some("owner-1".into()),
        last_seq: 1,
        rid: None,
    }
}

/// The unit's bucket rows with its open creates stay below
/// `MAX_PLACED`, the bound of the placement list every `sync` carries: a
/// bucket create's reservation is refused `cap_reached` at it, so a
/// tenant's `sync` is never refused for its size.
#[test]
fn a_bucket_create_is_refused_once_the_unit_holds_max_placed() {
    use velmora_bridge::unit::reserve::ReserveRefusal;
    let u = ready();
    let a = worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 0,
            entries: vec![owner_principal().into()],
            answers: vec![],
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    u.sql()
        .with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut st = tx.prepare(
                    "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
                     VALUES (?1, ?2, 'o', x'02', 1, 1)",
                )?;
                for i in 0..buckets::MAX_PLACED - 1 {
                    st.execute([format!("b_{i:016x}"), format!("bulk-{i}")])?;
                }
            }
            tx.commit()
        })
        .unwrap();
    let ask = |n: u8| UnitOp::Reserve {
        key_hash: Hash32([n; 32]),
        fingerprint: Hash32([n; 32]),
        rid: Rid([n; 16]),
        acting: Some(Acting::OwnerRef("owner-1".into())),
        opening: Opening::Bucket {
            name: format!("last-{n}"),
            unit: 0,
        },
    };
    let first = worker(&u, ask(1));
    assert!(matches!(first, UnitAnswer::Ok { .. }), "{first:?}");
    assert!(matches!(
        worker(&u, ask(2)),
        UnitAnswer::Refused {
            reason: Refused::Reserve(ReserveRefusal::CapReached),
            ..
        }
    ));
}

fn sync_buckets(
    u: &Unit<RusqliteSql>,
    state_seq: u64,
    restoring_since: Option<u64>,
    buckets: Vec<BucketChange>,
    placed_ids: &[&str],
) -> UnitAnswer {
    let current = u.head().unwrap().seqs;
    worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                from_seq: current.state_seq,
                seqs: Seqs {
                    state_seq,
                    keys_seq: current.keys_seq,
                },
                tenant_mode: None,
                tenant_state: TenantState::Active,
                restoring_since,
                lift: None,
                buckets,
                placed: placed(placed_ids),
            },
        },
    )
}

fn ok_body(answer: UnitAnswer) -> serde_json::Value {
    match answer {
        UnitAnswer::Ok { body, .. } => body,
        other => panic!("expected an OK unit answer, got {other:?}"),
    }
}

fn sync_alpha(u: &Unit<RusqliteSql>) {
    ok_body(sync_buckets(
        u,
        5,
        None,
        vec![created(5, B1, "alpha", 2)],
        &[B1],
    ));
}

/// The unit creates the placed row and makes the same reservation replay as applied.
#[test]
fn a_sync_creation_writes_the_bucket_and_applies_its_bound_reservation() {
    use velmora_bridge::unit::keys::{Access, KeyGrant};
    let u = ready();
    let owner = owner_principal();
    ok_body(worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 0,
            entries: vec![owner.clone().into()],
            answers: vec![],
        },
    ));
    let ask = || UnitOp::Reserve {
        key_hash: Hash32([1; 32]),
        fingerprint: Hash32([2; 32]),
        rid: Rid([3; 16]),
        acting: Some(Acting::OwnerRef("owner-1".into())),
        opening: Opening::Bucket {
            name: "alpha".into(),
            unit: 0,
        },
    };
    let admitted = ok_body(worker(&u, ask()));
    assert_eq!(admitted["admitted"]["keys_seq"], json!(1));
    let bound = ok_body(worker(
        &u,
        UnitOp::BindBucket {
            rid: Rid([3; 16]),
            expected: None,
            grant_seq: 2,
        },
    ));
    assert_eq!(bound, json!({ "bound": true }));
    ok_body(worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 1,
            entries: vec![KeyEntry {
                grants: vec![KeyGrant {
                    bucket_id: B1.into(),
                    access: Access::Rw,
                    expires_at: None,
                    prefix: None,
                    ip_list: vec![],
                }],
                last_seq: 2,
                ..owner
            }
            .into()],
            answers: vec![],
        },
    ));

    let body = ok_body(sync_buckets(
        &u,
        5,
        None,
        vec![created(5, B1, "alpha", 2)],
        &[B1],
    ));
    assert_eq!(body["buckets"]["created"], json!(1));
    assert_eq!(ids(&u), placed(&[B1]));
    assert_eq!(name_of(&u, B1), "alpha");
    assert_eq!(u.head().unwrap().seqs.state_seq, 5);
    let replay = ok_body(worker(&u, ask()));
    assert_eq!(replay["applied"]["bucket"], json!(B1));
    assert_eq!(replay["applied"]["grant_seq"], json!(2));
}

/// A dropped record removes the row of a bucket already closed while empty.
#[test]
fn a_sync_drop_deletes_an_empty_closing_bucket() {
    let u = ready();
    sync_alpha(&u);
    let close = ok_body(worker(
        &u,
        UnitOp::BucketClose {
            bucket_id: B1.into(),
        },
    ));
    assert_eq!(close, json!({ "closing": true, "newly": true }));

    let body = ok_body(sync_buckets(&u, 6, None, vec![dropped(6, B1)], &[]));
    assert_eq!(body["buckets"]["dropped"], json!(1));
    assert!(ids(&u).is_empty());
    assert!(!closing(&u, B1));
}

/// A late drop keeps the live object, frees the bucket name, and reports the retained row.
#[test]
fn a_sync_drop_keeps_an_occupied_bucket_under_its_dropped_name() {
    const GENERATION: &str = "g_0019a00000000c1c1c1c1c1c1c1c1";
    let u = ready();
    sync_alpha(&u);
    u.sql()
        .apply(&format!(
            "INSERT INTO generations(id, bucket_id, key, state, size, etag, content_json, \
             user_meta_json, extent_count, created_at) \
             VALUES ('{GENERATION}', '{B1}', 'k', 'live', 0, '\"e\"', '{{}}', '{{}}', 0, 1); \
             INSERT INTO objects(bucket_id, key, generation_id) VALUES ('{B1}', 'k', '{GENERATION}');"
        ))
        .unwrap();

    let body = ok_body(sync_buckets(&u, 6, None, vec![dropped(6, B1)], &[]));
    assert_eq!(body["buckets"]["dropped"], json!(0));
    assert_eq!(body["buckets"]["drop_not_closed"], json!([B1]));
    assert_eq!(ids(&u), placed(&[B1]));
    assert_eq!(name_of(&u, B1), format!("~dropped/{B1}"));
    assert!(closing(&u, B1));
    let live_generation: String = u
        .sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT generation_id FROM objects WHERE bucket_id = ?1 AND key = 'k'",
                [B1],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(live_generation, GENERATION);
}

fn sync_omitting_alpha(u: &Unit<RusqliteSql>, restoring_since: Option<u64>) -> UnitAnswer {
    sync_buckets(
        u,
        6,
        restoring_since,
        vec![created(6, B2, "beta", 3)],
        &[B2],
    )
}

/// Omitting a live bucket from placements alarms and rolls back the new row and head.
#[test]
fn a_sync_that_omits_a_bucket_alarms_without_advancing_the_head() {
    let u = ready();
    sync_alpha(&u);
    let before = u.head().unwrap();

    let answer = sync_omitting_alpha(&u, None);
    assert!(
        matches!(
            answer,
            UnitAnswer::Refused {
                reason: Refused::Buckets(BucketRefusal::PlacementsOff),
                alarm: true,
            }
        ),
        "{answer:?}"
    );
    assert_eq!(u.head().unwrap(), before);
    assert_eq!(ids(&u), placed(&[B1]));
    assert_eq!(name_of(&u, B1), "alpha");
    assert!(!closing(&u, B1));
}

/// The placement guard uses the next head's restoring entry, even on entry into restore.
#[test]
fn a_sync_entering_restore_accepts_an_omitted_bucket() {
    let u = ready();
    sync_alpha(&u);
    assert_eq!(u.head().unwrap().restoring_since, None);

    let body = ok_body(sync_omitting_alpha(&u, Some(6)));
    assert_eq!(body["buckets"]["created"], json!(1));
    let head = u.head().unwrap();
    assert_eq!(head.seqs.state_seq, 6);
    assert_eq!(head.restoring_since, Some(6));
    assert_eq!(ids(&u), placed(&[B1, B2]));
}

/// Unplacing a bucket while restoring leaves the rollback copy intact.
#[test]
fn a_sync_unplace_preserves_bucket_rows_while_restoring() {
    let u = ready();
    sync_alpha(&u);
    ok_body(sync_buckets(&u, 6, Some(6), vec![], &[B1]));

    let body = ok_body(sync_buckets(
        &u,
        7,
        Some(6),
        vec![BucketChange::Unplaced {
            seq: 7,
            buckets: placed(&[B1]),
        }],
        &[],
    ));
    assert_eq!(body["buckets"]["dropped"], json!(0));
    let head = u.head().unwrap();
    assert_eq!(head.seqs.state_seq, 7);
    assert_eq!(head.restoring_since, Some(6));
    assert_eq!(ids(&u), placed(&[B1]));
    assert_eq!(name_of(&u, B1), "alpha");
    assert!(!closing(&u, B1));
}

/// A sync based on an old sequence is refused without changing the head or rows, even with a valid bucket part.
#[test]
fn a_sync_based_on_an_old_sequence_leaves_the_head_and_rows_unchanged() {
    let u = ready();
    sync_alpha(&u);
    let before = u.head().unwrap();
    let mut head = SyncHead {
        from_seq: before.seqs.state_seq - 1,
        seqs: Seqs {
            state_seq: before.seqs.state_seq + 1,
            keys_seq: before.seqs.keys_seq,
        },
        tenant_state: TenantState::Active,
        tenant_mode: None,
        restoring_since: None,
        lift: None,
        buckets: vec![created(before.seqs.state_seq + 1, B2, "beta", 3)],
        placed: placed(&[B1, B2]),
    };
    let writes_before = u.sql().with_conn(|c| c.total_changes());

    assert_eq!(
        worker(&u, UnitOp::Sync { head: head.clone() }),
        UnitAnswer::Refused {
            reason: Refused::StaleSync,
            alarm: false,
        }
    );
    assert_eq!(u.sql().with_conn(|c| c.total_changes()), writes_before);
    assert_eq!(u.head().unwrap(), before);
    assert_eq!(ids(&u), placed(&[B1]));

    head.from_seq = before.seqs.state_seq;
    let next = head.seqs;
    let body = ok_body(worker(&u, UnitOp::Sync { head }));
    assert_eq!(body["buckets"]["created"], json!(1));
    assert_eq!(u.head().unwrap().seqs, next);
    assert_eq!(ids(&u), placed(&[B1, B2]));
}

/// Descending change sequences are malformed even if applying them would match placements.
#[test]
fn a_sync_with_out_of_order_bucket_changes_is_refused_before_changes() {
    let u = ready();
    let before = u.head().unwrap();
    let changes = || u.sql().with_conn(|c| c.total_changes());
    let writes_before = changes();

    let answer = sync_buckets(
        &u,
        6,
        None,
        vec![created(6, B1, "alpha", 2), created(5, B2, "beta", 3)],
        &[B1, B2],
    );
    assert!(
        matches!(
            answer,
            UnitAnswer::Refused {
                reason: Refused::Buckets(BucketRefusal::Malformed),
                alarm: false,
            }
        ),
        "{answer:?}"
    );
    assert_eq!(changes(), writes_before, "the malformed delta never ran");
    assert_eq!(u.head().unwrap(), before);
    assert!(ids(&u).is_empty());
}
