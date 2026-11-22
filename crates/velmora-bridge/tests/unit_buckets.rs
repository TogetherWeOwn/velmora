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
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp,
};
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

fn sync(u: &Unit<RusqliteSql>, state: TenantState, mode: Option<HoldMode>) -> UnitAnswer {
    let h = u.head().unwrap();
    worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                seqs: Seqs {
                    state_seq: h.seqs.state_seq + 1,
                    keys_seq: h.seqs.keys_seq,
                },
                tenant_mode: mode,
                tenant_state: state,
                restoring_since: None,
                lift: None,
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
        sync(&u, TenantState::Active, None),
        UnitAnswer::Ok { .. }
    ));
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
    // Another name for the id, or the name for another id: a broken chain.
    for c in [created(5, B1, "other", 3), created(5, B2, "alpha", 3)] {
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
        sync(&u, TenantState::Suspended, Some(HoldMode::ReadOnly)),
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
    // Its name stays taken, and the head no longer places it: the
    // placement check leaves it out.
    assert!(buckets::placement_check(u.sql(), &[]).unwrap());
    assert!(!buckets::placement_check(u.sql(), &placed(&[B3])).unwrap());
    // A dropped record for a row that is gone changes nothing.
    let done = apply(&u, &[dropped(10, B1)], false).unwrap();
    assert_eq!(done, BucketsApplied::default());
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
