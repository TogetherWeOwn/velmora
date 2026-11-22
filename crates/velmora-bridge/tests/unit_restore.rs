//! The restore calls and the lift checked in the unit (AM-2, AM-3), on
//! the native database. The bookmark calls are the object's; here a fake
//! stands in for them. `workers/unit-suite` runs this file against a
//! Durable Object too.

use std::cell::RefCell;

use serde_json::json;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::lift::{
    ids_hash, AckClass, ClassProof, FindingList, GateRefusal, GateSummary, LiftProof, ReplayId,
    MAX_PAGE,
};
use velmora_bridge::unit::recount::{RecountCall, RecountRefusal};
use velmora_bridge::unit::restore::{
    drive, Bookmark, PitrStep, PointInTimePort, RestoreRefusal, RestoreTarget, LEASE_TERM_MS,
    LIFT_SLACK_MS, RESTORE_MARGIN_MS,
};
use velmora_bridge::unit::{
    poll_once, BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState,
    Unit, UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::{BridgeError, Result, UnixMs};

const BORN: i64 = 1_795_000_000_000;
const S: u64 = 7;
/// The earliest time a unit closed at `t` may be restored.
const fn ready_at(t: i64) -> i64 {
    t + LEASE_TERM_MS + RESTORE_MARGIN_MS
}

fn tenant() -> TenantId {
    TenantId::parse("t_0000000000000e01").unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn token(kind: BirthKind, record_seq: u64) -> BirthToken {
    BirthToken {
        name: own(),
        jurisdiction: String::new(),
        record_seq,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: 2,
        kind,
    }
}

fn call(kind: CallKind, s: Option<Seqs>, op: UnitOp) -> UnitCall {
    UnitCall {
        name: own(),
        kind,
        seqs: s,
        authenticated: true,
        listed: true,
        op,
    }
}

fn worker(u: &Unit<RusqliteSql>, op: UnitOp, at: i64) -> UnitAnswer {
    u.handle(&call(CallKind::Worker, None, op), UnixMs(at))
}

fn sync(u: &Unit<RusqliteSql>, state_seq: u64, restoring: Option<u64>, at: i64) -> UnitAnswer {
    worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                from_seq: u.head().unwrap().seqs.state_seq,
                seqs: Seqs {
                    state_seq,
                    keys_seq: 0,
                },
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: restoring,
                lift: None,
                buckets: vec![],
                placed: vec![],
            },
        },
        at,
    )
}

fn provision(kind: BirthKind, seq: u64) -> Unit<RusqliteSql> {
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    let a = u.handle(
        &call(
            CallKind::Worker,
            Some(Seqs {
                state_seq: seq,
                keys_seq: 0,
            }),
            UnitOp::Provision {
                token: token(kind, seq),
                sealed: vec![1],
            },
        ),
        UnixMs(BORN),
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    // The lease's own table comes with the birth (`u0002`), with no
    // lease: the unit never issued one.
    u
}

/// A born, active unit, closed for a restore at `S` at time `BORN + 1000`.
fn closed() -> Unit<RusqliteSql> {
    let u = provision(BirthKind::Birth, 3);
    assert!(matches!(sync(&u, 3, None, BORN), UnitAnswer::Ok { .. }));
    assert!(matches!(
        sync(&u, S, Some(S), BORN + 1000),
        UnitAnswer::Ok { .. }
    ));
    u
}

/// The object's bookmark calls, faked: the current bookmark, the
/// bookmark of a time, and the restores asked for.
struct FakePitr {
    current: RefCell<String>,
    restored: RefCell<Vec<String>>,
}

impl FakePitr {
    fn new(current: &str) -> Self {
        FakePitr {
            current: RefCell::new(current.into()),
            restored: RefCell::new(vec![]),
        }
    }
}

impl PointInTimePort for FakePitr {
    async fn current(&self) -> Result<String> {
        Ok(self.current.borrow().clone())
    }

    async fn at(&self, unix_ms: i64) -> Result<String> {
        Ok(format!("bm-at-{unix_ms}"))
    }

    async fn restore_now(&self, bookmark: &str) -> Result<()> {
        self.restored.borrow_mut().push(bookmark.into());
        // The runtime resets the object; the request ends with an error.
        Err(BridgeError::Sql("pitr: reset".into()))
    }
}

fn step(u: &Unit<RusqliteSql>, op: UnitOp, at: i64) -> PitrStep {
    u.pitr_step(&call(CallKind::Worker, None, op), UnixMs(at))
}

fn run(u: &Unit<RusqliteSql>, op: UnitOp, at: i64, pitr: &FakePitr) -> UnitAnswer {
    poll_once(drive(step(u, op, at), pitr)).unwrap()
}

fn restore_op(kind: BirthKind, seq: u64, target: RestoreTarget, undo: &str) -> UnitOp {
    UnitOp::Restore {
        token: token(kind, seq),
        target,
        expect_undo: Bookmark(undo.into()),
        floor_ms: 0,
    }
}

fn refused_restore(r: RestoreRefusal) -> UnitAnswer {
    UnitAnswer::Refused {
        reason: Refused::Restore(r),
        alarm: false,
    }
}

fn refused_gate(r: GateRefusal) -> UnitAnswer {
    UnitAnswer::Refused {
        reason: Refused::Gate(r),
        alarm: false,
    }
}

fn closed_at(u: &Unit<RusqliteSql>) -> Option<i64> {
    u.head().unwrap().closed_at
}

// ---------------------------------------------------------------------------
// The restore calls (AM-2)
// ---------------------------------------------------------------------------

#[test]
fn the_close_time_is_the_syncs_that_set_the_entry() {
    let u = provision(BirthKind::Birth, 3);
    assert_eq!(closed_at(&u), None);
    sync(&u, 3, None, BORN);
    sync(&u, 5, Some(5), BORN + 10);
    assert_eq!(closed_at(&u), Some(BORN + 10));
    // The same entry again keeps its time.
    sync(&u, 6, Some(5), BORN + 20);
    assert_eq!(closed_at(&u), Some(BORN + 10));
    // Another entry is another close.
    sync(&u, 8, Some(8), BORN + 30);
    assert_eq!(closed_at(&u), Some(BORN + 30));
    // A restore birth is closed since its birth.
    let r = provision(BirthKind::Restore, S);
    assert_eq!(closed_at(&r), Some(BORN));
}

/// A stale restore entry cannot replace the current one even if the sync's base is current.
#[test]
fn sync_refuses_an_older_restore_entry_without_writing() {
    let u = closed();
    let before = u.head().unwrap();
    assert_eq!(before.restoring_since, Some(S));
    let total_changes = || u.sql().with_conn(|conn| conn.total_changes());
    let writes = total_changes();

    assert_eq!(
        sync(&u, S + 1, Some(S - 1), BORN + 2000),
        UnitAnswer::Refused {
            reason: Refused::StaleSync,
            alarm: false,
        }
    );
    assert_eq!(u.head().unwrap(), before);
    assert_eq!(total_changes(), writes);

    assert!(matches!(
        sync(&u, S + 1, Some(S), BORN + 3000),
        UnitAnswer::Ok { .. }
    ));
    let same = u.head().unwrap();
    assert_eq!(same.seqs.state_seq, S + 1);
    assert_eq!(same.restoring_since, Some(S));
    assert_eq!(same.closed_at, before.closed_at);

    assert!(matches!(
        sync(&u, S + 2, Some(S + 2), BORN + 4000),
        UnitAnswer::Ok { .. }
    ));
    let newer = u.head().unwrap();
    assert_eq!(newer.seqs.state_seq, S + 2);
    assert_eq!(newer.restoring_since, Some(S + 2));
    assert_eq!(newer.closed_at, Some(BORN + 4000));
}

#[test]
fn restore_prepare_is_refused_until_the_unit_is_closed_long_enough() {
    let pitr = FakePitr::new("bm-now");
    // Not closed at all.
    let open = provision(BirthKind::Birth, 3);
    sync(&open, 3, None, BORN);
    assert_eq!(
        run(
            &open,
            UnitOp::RestorePrepare { since: 3 },
            BORN + 3_600_000,
            &pitr
        ),
        refused_restore(RestoreRefusal::NotRestoring)
    );
    let u = closed();
    // Another entry than the unit's.
    assert_eq!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S + 1 },
            ready_at(BORN + 1000),
            &pitr
        ),
        refused_restore(RestoreRefusal::NotRestoring)
    );
    // Before T + 60 s after the close.
    assert_eq!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S },
            ready_at(BORN + 1000) - 1,
            &pitr
        ),
        refused_restore(RestoreRefusal::TooSoon)
    );
    // Then: the undo bookmark.
    assert_eq!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S },
            ready_at(BORN + 1000),
            &pitr
        ),
        UnitAnswer::UndoBookmark {
            seqs: Seqs {
                state_seq: S,
                keys_seq: 0
            },
            bookmark: Bookmark("bm-now".into()),
        }
    );
}

#[test]
fn a_live_lease_or_a_later_lease_holds_the_restore_back() {
    let pitr = FakePitr::new("bm-now");
    let u = closed();
    let t = ready_at(BORN + 1000);
    u.sql()
        .apply(&format!(
            "UPDATE unit_lease SET fresh_until = {}, lease_hi = {} WHERE id = 1",
            t + 5,
            t + 5
        ))
        .unwrap();
    assert_eq!(
        run(&u, UnitOp::RestorePrepare { since: S }, t, &pitr),
        refused_restore(RestoreRefusal::LeaseLive)
    );
    // Expired, but held later than closed_at + T: 60 s after it.
    u.sql()
        .apply("UPDATE unit_lease SET fresh_until = NULL")
        .unwrap();
    assert_eq!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S },
            t + 5 + RESTORE_MARGIN_MS - 1,
            &pitr
        ),
        refused_restore(RestoreRefusal::TooSoon)
    );
    // A high mark that lags its own fresh_until: the later of the two.
    u.sql()
        .apply(&format!(
            "UPDATE unit_lease SET fresh_until = {}, lease_hi = NULL",
            t + 5
        ))
        .unwrap();
    assert_eq!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S },
            t + 5 + RESTORE_MARGIN_MS - 1,
            &pitr
        ),
        refused_restore(RestoreRefusal::TooSoon)
    );
    assert!(matches!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S },
            t + 5 + RESTORE_MARGIN_MS,
            &pitr
        ),
        UnitAnswer::UndoBookmark { .. }
    ));
}

#[test]
fn a_unit_without_a_lease_table_is_not_restored() {
    let pitr = FakePitr::new("bm-now");
    let u = closed();
    u.sql().apply("DROP TABLE unit_lease").unwrap();
    assert_eq!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S },
            ready_at(BORN + 1000),
            &pitr
        ),
        refused_restore(RestoreRefusal::LeaseUnknown)
    );
}

#[test]
fn a_restore_armed_without_the_restart_says_so() {
    struct Armed(FakePitr);
    impl PointInTimePort for Armed {
        async fn current(&self) -> Result<String> {
            self.0.current().await
        }
        async fn at(&self, unix_ms: i64) -> Result<String> {
            self.0.at(unix_ms).await
        }
        async fn restore_now(&self, _: &str) -> Result<()> {
            Ok(())
        }
    }
    let u = closed();
    let pitr = Armed(FakePitr::new("bm-undo"));
    let op = restore_op(
        BirthKind::Restore,
        S,
        RestoreTarget::Time {
            at_ms: BORN + LIFT_SLACK_MS,
        },
        "bm-undo",
    );
    let a = poll_once(drive(step(&u, op, ready_at(BORN + 1000)), &pitr)).unwrap();
    assert_eq!(
        a,
        UnitAnswer::Failed {
            class: "pitr_armed".into()
        }
    );
}

#[test]
fn restore_checks_its_token_and_that_nothing_moved_since_prepare() {
    let u = closed();
    let t = ready_at(BORN + 1000);
    let pitr = FakePitr::new("bm-undo");
    let at = RestoreTarget::Time {
        at_ms: BORN + LIFT_SLACK_MS + 500,
    };
    assert_eq!(
        run(
            &u,
            restore_op(BirthKind::Birth, S, at.clone(), "bm-undo"),
            t,
            &pitr
        ),
        refused_restore(RestoreRefusal::WrongToken)
    );
    // A restore token of another entry: the unit is not closed under it.
    assert_eq!(
        run(
            &u,
            restore_op(BirthKind::Restore, S + 1, at.clone(), "bm-undo"),
            t,
            &pitr
        ),
        refused_restore(RestoreRefusal::NotRestoring)
    );
    assert_eq!(
        run(
            &u,
            restore_op(BirthKind::Restore, S, at.clone(), "bm-undo"),
            t - 1,
            &pitr
        ),
        refused_restore(RestoreRefusal::TooSoon)
    );
    // The unit wrote after prepare: its bookmark moved.
    assert_eq!(
        run(
            &u,
            restore_op(BirthKind::Restore, S, at.clone(), "bm-older"),
            t,
            &pitr
        ),
        refused_restore(RestoreRefusal::Moved)
    );
    assert!(pitr.restored.borrow().is_empty());
    // By time: the unit turns the time into a bookmark and restores.
    let a = run(
        &u,
        restore_op(BirthKind::Restore, S, at, "bm-undo"),
        t,
        &pitr,
    );
    assert_eq!(
        a,
        UnitAnswer::Failed {
            class: "pitr".into()
        }
    );
    assert_eq!(
        *pitr.restored.borrow(),
        vec![format!("bm-at-{}", BORN + LIFT_SLACK_MS + 500)]
    );
    // An undo goes back to the sealed undo bookmark, unsealed by the tool.
    let back = RestoreTarget::Bookmark {
        bookmark: Bookmark("bm-before-restore".into()),
    };
    run(
        &u,
        restore_op(BirthKind::Restore, S, back, "bm-undo"),
        t,
        &pitr,
    );
    assert_eq!(pitr.restored.borrow().last().unwrap(), "bm-before-restore");
}

#[test]
fn a_unit_born_from_a_restore_token_passes_the_wait_from_its_birth() {
    let u = provision(BirthKind::Restore, S);
    let pitr = FakePitr::new("bm-born");
    assert_eq!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S },
            ready_at(BORN) - 1,
            &pitr
        ),
        refused_restore(RestoreRefusal::TooSoon)
    );
    assert!(matches!(
        run(
            &u,
            UnitOp::RestorePrepare { since: S },
            ready_at(BORN),
            &pitr
        ),
        UnitAnswer::UndoBookmark { .. }
    ));
}

#[test]
fn restore_calls_are_worker_calls_and_need_the_objects_storage() {
    let u = closed();
    let t = ready_at(BORN + 1000);
    // Through `handle` (no point-in-time storage): refused, nothing armed.
    assert_eq!(
        worker(&u, UnitOp::RestorePrepare { since: S }, t),
        refused_restore(RestoreRefusal::NoPointInTime)
    );
    let a = u.pitr_step(
        &call(
            CallKind::Request,
            Some(Seqs {
                state_seq: S,
                keys_seq: 0,
            }),
            UnitOp::RestorePrepare { since: S },
        ),
        UnixMs(t),
    );
    assert_eq!(
        a,
        PitrStep::Answer(UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            alarm: false
        })
    );
    // An unborn unit is not restored by these calls (a gone unit is born
    // again from its restore token).
    let unborn = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    assert_eq!(
        unborn.pitr_step(
            &call(CallKind::Worker, None, UnitOp::RestorePrepare { since: S }),
            UnixMs(t)
        ),
        PitrStep::Answer(UnitAnswer::Unborn { listed: true })
    );
}

#[test]
fn a_bookmark_never_shows_in_debug_and_reads_back_from_json() {
    let b = Bookmark("0000017f-secret-bookmark".into());
    assert_eq!(format!("{b:?}"), "Bookmark(24 bytes)");
    let a = UnitAnswer::UndoBookmark {
        seqs: Seqs {
            state_seq: 1,
            keys_seq: 2,
        },
        bookmark: b.clone(),
    };
    assert!(!format!("{a:?}").contains("secret"));
    let text = serde_json::to_string(&a).unwrap();
    assert_eq!(serde_json::from_str::<UnitAnswer>(&text).unwrap(), a);
    let op = restore_op(
        BirthKind::Restore,
        S,
        RestoreTarget::Bookmark { bookmark: b },
        "u",
    );
    let c = call(CallKind::Worker, None, op);
    assert!(!format!("{c:?}").contains("secret"));
    let text = serde_json::to_string(&c).unwrap();
    assert_eq!(serde_json::from_str::<UnitCall>(&text).unwrap(), c);
}

// ---------------------------------------------------------------------------
// The lift, checked in the unit (AM-2, AM-3)
// ---------------------------------------------------------------------------

fn rid(nonce: &str) -> ReplayId {
    ReplayId {
        since: S,
        ordinal: 4,
        nonce: nonce.into(),
    }
}

/// A complete replay's summary whose only blockers are `damaged`.
fn whole(damaged: &[String]) -> GateSummary {
    let mut lists = std::collections::BTreeMap::new();
    if !damaged.is_empty() {
        lists.insert(
            FindingList::Damaged,
            ClassProof {
                count: damaged.len() as u64,
                sha256: ids_hash(damaged),
            },
        );
    }
    GateSummary {
        complete: true,
        damaged_total: damaged.len() as u64,
        lists,
        ..GateSummary::default()
    }
}

fn level_stamp(u: &Unit<RusqliteSql>, counter: u64) {
    u.sql()
        .apply(&format!(
            "INSERT INTO rollback_stamp(id, counter, catalogue_id) VALUES (1, {counter}, 't.0') \
             ON CONFLICT(id) DO UPDATE SET counter = excluded.counter"
        ))
        .unwrap();
}

fn ok(a: UnitAnswer) -> serde_json::Value {
    match a {
        UnitAnswer::Ok { body, .. } => body,
        other => panic!("not ok: {other:?}"),
    }
}

/// The lift the unit would accept now, as `gate_status` gives it.
fn proof(u: &Unit<RusqliteSql>, t: i64) -> LiftProof {
    let status = ok(worker(u, UnitOp::GateStatus {}, t));
    serde_json::from_value(status["lift"]["ok"].clone()).expect("the lift passes")
}

/// The `sync` of the record that removes the entry, naming `lift`.
fn lift(u: &Unit<RusqliteSql>, state_seq: u64, lift: Option<LiftProof>, at: i64) -> UnitAnswer {
    worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                from_seq: u.head().unwrap().seqs.state_seq,
                seqs: Seqs {
                    state_seq,
                    keys_seq: 0,
                },
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: None,
                lift,
                buckets: vec![],
                placed: vec![],
            },
        },
        at,
    )
}

fn page(list: FindingList, nonce: &str, ids: &[String]) -> UnitOp {
    UnitOp::GateBlockers {
        replay_id: rid(nonce),
        list,
        ids: ids.to_vec(),
    }
}

fn ack(nonce: &str, ids: &[String]) -> UnitOp {
    UnitOp::GateAck {
        replay_id: rid(nonce),
        class: AckClass::Damaged,
        ids: ids.to_vec(),
    }
}

fn ids(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_entry_is_not_cleared_without_a_report_of_this_replay() {
    let u = closed();
    assert_eq!(
        lift(&u, S + 1, None, BORN + 2000),
        refused_gate(GateRefusal::NoReport)
    );
    assert_eq!(u.head().unwrap().restoring_since, Some(S));
    // A report of another entry cannot be opened.
    let other = ReplayId {
        since: S + 1,
        ..rid("n1")
    };
    assert_eq!(
        worker(&u, UnitOp::GateOpen { replay_id: other }, BORN + 2000),
        refused_gate(GateRefusal::NotRestoring)
    );
}

#[test]
fn a_clean_whole_replay_lifts_with_its_proof_once_the_stamp_is_level() {
    let u = closed();
    let t = BORN + 2000;
    assert_eq!(
        ok(worker(
            &u,
            UnitOp::GateOpen {
                replay_id: rid("n1")
            },
            t
        )),
        json!({ "opened": true })
    );
    // Opening the same replay again keeps it.
    assert_eq!(
        ok(worker(
            &u,
            UnitOp::GateOpen {
                replay_id: rid("n1")
            },
            t
        )),
        json!({ "opened": false })
    );
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::StampNotLevelled)
    );
    level_stamp(&u, 4);
    // Not complete yet.
    assert_eq!(lift(&u, S + 1, None, t), refused_gate(GateRefusal::Closed));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: whole(&[]),
        },
        t,
    ));
    let status = ok(worker(&u, UnitOp::GateStatus {}, t));
    assert_eq!(status["counters_on"], json!(true));
    // The record's lift must be named, and be this one.
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::ProofMismatch)
    );
    let p = proof(&u, t);
    assert_eq!(p.replay_id, rid("n1"));
    let _ = u.take_wake();
    assert!(matches!(lift(&u, S + 1, Some(p), t), UnitAnswer::Ok { .. }));
    let h = u.head().unwrap();
    assert_eq!((h.restoring_since, h.closed_at), (None, None));
    // The lift asks for the alarm at once: what waited while the unit was
    // closed is due (AM-50's `Closed` row).
    assert_eq!(u.take_wake(), Some(UnixMs(t)));
    // The report is gone with the entry.
    assert_eq!(
        ok(worker(&u, UnitOp::GateStatus {}, t))["replay_id"],
        json!(null)
    );
}

/// An empty closing bucket unplaced on entry to restore or during it stays
/// until the proven lift, which sweeps it without another sync.
#[test]
fn the_proven_lift_sweeps_an_unplaced_closing_bucket() {
    use velmora_bridge::unit::buckets::{self, BucketChange};
    use velmora_bridge::unit_lease::lease::Proven;

    const BUCKET: &str = "b_00000000000000e1";
    let t = BORN + 2000;
    for unplace_on_entry in [true, false] {
        let u = provision(BirthKind::Birth, 3);
        let sync_buckets = |state_seq, restoring_since, buckets, placed| {
            ok(worker(
                &u,
                UnitOp::Sync {
                    head: SyncHead {
                        from_seq: u.head().unwrap().seqs.state_seq,
                        seqs: Seqs {
                            state_seq,
                            keys_seq: 0,
                        },
                        tenant_state: TenantState::Active,
                        tenant_mode: None,
                        restoring_since,
                        lift: None,
                        buckets,
                        placed,
                    },
                },
                t,
            ))
        };
        sync_buckets(
            4,
            None,
            vec![BucketChange::Created {
                seq: 4,
                bucket_id: BUCKET.into(),
                grant_seq: 1,
                creator: "p_owner".into(),
                name: "alpha".into(),
                bdk_wrapped: vec![2, 9, 9],
                tk_version: 1,
                written_at: u64::try_from(t).unwrap(),
            }],
            vec![BUCKET.into()],
        );
        ok(worker(
            &u,
            UnitOp::Renew {
                proof_start: UnixMs(t),
                proven: Proven {
                    state_seq: 4,
                    keys_seq: 0,
                    stamp_counter: None,
                    revoked: 0,
                },
                revocations: vec![],
            },
            t,
        ));
        assert_eq!(
            ok(worker(
                &u,
                UnitOp::BucketClose {
                    bucket_id: BUCKET.into()
                },
                t
            )),
            json!({ "closing": true, "newly": true })
        );
        let assert_retained = || {
            assert_eq!(buckets::count(u.sql()).unwrap(), 1);
            assert!(buckets::is_closing(u.sql(), BUCKET).unwrap());
        };
        for state_seq in [S, S + 1] {
            let unplace = if unplace_on_entry { S } else { S + 1 };
            let changes = if state_seq == unplace {
                vec![BucketChange::Unplaced {
                    seq: state_seq,
                    buckets: vec![BUCKET.into()],
                }]
            } else {
                vec![]
            };
            let placed = if state_seq < unplace {
                vec![BUCKET.into()]
            } else {
                vec![]
            };
            let body = sync_buckets(state_seq, Some(S), changes, placed);
            assert_eq!(body["buckets"]["dropped"], json!(0));
            assert_retained();
        }

        let replay_id = rid("n1");
        ok(worker(
            &u,
            UnitOp::GateOpen {
                replay_id: replay_id.clone(),
            },
            t,
        ));
        level_stamp(&u, replay_id.ordinal);
        ok(worker(
            &u,
            UnitOp::GateReport {
                replay_id,
                summary: whole(&[]),
            },
            t,
        ));
        let p = proof(&u, t);
        assert_retained();
        ok(lift(&u, S + 2, Some(p), t));
        let h = u.head().unwrap();
        assert_eq!((h.seqs.state_seq, h.restoring_since), (S + 2, None));
        assert_eq!(buckets::count(u.sql()).unwrap(), 0);
        assert!(!buckets::is_closing(u.sql(), BUCKET).unwrap());
    }
}

#[test]
fn a_lift_naming_another_replay_or_other_ids_is_refused() {
    let u = closed();
    let t = BORN + 2000;
    level_stamp(&u, 4);
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: rid("n1"),
        },
        t,
    ));
    ok(worker(
        &u,
        page(FindingList::Damaged, "n1", &ids(&["g_a"])),
        t,
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: whole(&ids(&["g_a"])),
        },
        t,
    ));
    ok(worker(&u, ack("n1", &ids(&["g_a"])), t));
    let good = proof(&u, t);
    // The record of an earlier attempt of the same restore (another
    // nonce), brought back with its counter by an undo: refused.
    let mut older = good.clone();
    older.replay_id.nonce = "n0".into();
    assert_eq!(
        lift(&u, S + 1, Some(older), t),
        refused_gate(GateRefusal::ProofMismatch)
    );
    // A record that acknowledged other ids: refused.
    let mut other = good.clone();
    other
        .acknowledged
        .get_mut(&AckClass::Damaged)
        .unwrap()
        .sha256 = ids_hash(&ids(&["g_b"]));
    assert_eq!(
        lift(&u, S + 1, Some(other), t),
        refused_gate(GateRefusal::ProofMismatch)
    );
    assert!(matches!(
        lift(&u, S + 1, Some(good), t),
        UnitAnswer::Ok { .. }
    ));
}

#[test]
fn a_restored_unit_lifts_only_with_its_counters_on() {
    let u = provision(BirthKind::Restore, S);
    let t = BORN + 2000;
    level_stamp(&u, 4);
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: rid("n1"),
        },
        t,
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: whole(&[]),
        },
        t,
    ));
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::CountersOff)
    );
    // The gate's recount turns them on (AM-3, AM-27): `Recount`, a unit
    // call, as jobs are refused while the unit is closed. No import was
    // bound to this unit, so it is the gate's and needs no seal.
    let started = ok(worker(
        &u,
        UnitOp::Recount {
            call: RecountCall::Start {},
            head: None,
        },
        t,
    ));
    assert_eq!(started["started"], json!(true));
    assert_eq!(started["counters_on"], json!(false));
    let mut on = false;
    for _ in 0..10 {
        let step = ok(worker(
            &u,
            UnitOp::Recount {
                call: RecountCall::Step { chunk: 100 },
                head: None,
            },
            t,
        ));
        if step["counters_on"] == json!(true) {
            assert!(step["finished"].is_object(), "{step}");
            on = true;
            break;
        }
    }
    assert!(on, "the recount ends and turns the counters on");
    let p = proof(&u, t);
    assert!(matches!(lift(&u, S + 1, Some(p), t), UnitAnswer::Ok { .. }));
    // An open unit's counters are the cron's: `Recount` is refused.
    assert_eq!(
        worker(
            &u,
            UnitOp::Recount {
                call: RecountCall::Start {},
                head: None,
            },
            t,
        ),
        UnitAnswer::Refused {
            reason: Refused::Recount(RecountRefusal::NotRestoring),
            alarm: false,
        }
    );
}

#[test]
fn blockers_lift_only_when_acknowledged_exactly_by_name() {
    let u = closed();
    let t = BORN + 2000;
    level_stamp(&u, 4);
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: rid("n1"),
        },
        t,
    ));
    ok(worker(
        &u,
        page(FindingList::Damaged, "n1", &ids(&["g_a", "g_b"])),
        t,
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: whole(&ids(&["g_a", "g_b"])),
        },
        t,
    ));
    ok(worker(&u, ack("n1", &ids(&["g_a"])), t));
    assert_eq!(lift(&u, S + 1, None, t), refused_gate(GateRefusal::Closed));
    // A page of more than 100 ids, or an ack for another replay: refused.
    let big: Vec<String> = (0..=MAX_PAGE).map(|i| format!("g_{i}")).collect();
    assert_eq!(
        worker(&u, ack("n1", &big), t),
        refused_gate(GateRefusal::Malformed)
    );
    assert_eq!(
        worker(&u, page(FindingList::Damaged, "n1", &big), t),
        refused_gate(GateRefusal::Malformed)
    );
    assert_eq!(
        worker(&u, ack("n2", &ids(&["g_b"])), t),
        refused_gate(GateRefusal::NoReport)
    );
    // An extra id the lift does not need: not exactly the named set.
    ok(worker(&u, ack("n1", &ids(&["g_b", "g_extra"])), t));
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::AckMismatch)
    );
    // Opening the replay again under a new nonce discards the ids and acks.
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: rid("n2"),
        },
        t,
    ));
    assert_eq!(lift(&u, S + 1, None, t), refused_gate(GateRefusal::Closed));
    ok(worker(
        &u,
        page(FindingList::Damaged, "n2", &ids(&["g_a", "g_b"])),
        t,
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n2"),
            summary: whole(&ids(&["g_a", "g_b"])),
        },
        t,
    ));
    ok(worker(&u, ack("n2", &ids(&["g_b", "g_a", "g_a"])), t));
    let p = proof(&u, t);
    let want = ids_hash(&ids(&["g_a", "g_b"]));
    assert_eq!(p.acknowledged[&AckClass::Damaged].count, 2);
    assert_eq!(p.acknowledged[&AckClass::Damaged].sha256, want);
    assert!(matches!(lift(&u, S + 1, Some(p), t), UnitAnswer::Ok { .. }));
}

#[test]
fn any_number_of_blockers_is_reported_and_acknowledged_in_pages() {
    let u = closed();
    let t = BORN + 2000;
    level_stamp(&u, 4);
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: rid("n1"),
        },
        t,
    ));
    let all: Vec<String> = (0..350).map(|i| format!("g_{i:04}")).collect();
    let report = || UnitOp::GateReport {
        replay_id: rid("n1"),
        summary: whole(&all),
    };
    let mut pages = all.chunks(MAX_PAGE);
    ok(worker(
        &u,
        page(FindingList::Damaged, "n1", pages.next().unwrap()),
        t,
    ));
    // A page missing: the stored list is not the summary's.
    ok(worker(&u, report(), t));
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::ListMismatch)
    );
    for chunk in pages {
        ok(worker(&u, page(FindingList::Damaged, "n1", chunk), t));
    }
    // A page after the summary undoes it: the summary is the last write.
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::ListMismatch)
    );
    ok(worker(&u, report(), t));
    for chunk in all.chunks(MAX_PAGE) {
        ok(worker(&u, ack("n1", chunk), t));
    }
    let p = proof(&u, t);
    assert_eq!(p.acknowledged[&AckClass::Damaged].count, 350);
    assert!(matches!(lift(&u, S + 1, Some(p), t), UnitAnswer::Ok { .. }));
}

#[test]
fn a_lost_page_of_a_list_without_a_total_keeps_the_unit_closed() {
    let u = closed();
    let t = BORN + 2000;
    level_stamp(&u, 4);
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: rid("n1"),
        },
        t,
    ));
    // 150 unreadable records; the second page never arrives.
    let unreadable: Vec<String> = (0..150).map(|i| format!("m/x/{i:04}")).collect();
    ok(worker(
        &u,
        page(FindingList::Unreadable, "n1", &unreadable[..MAX_PAGE]),
        t,
    ));
    let mut summary = whole(&[]);
    summary.lists.insert(
        FindingList::Unreadable,
        ClassProof {
            count: 150,
            sha256: ids_hash(&unreadable),
        },
    );
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: summary.clone(),
        },
        t,
    ));
    let first = UnitOp::GateAck {
        replay_id: rid("n1"),
        class: AckClass::Unreadable,
        ids: unreadable[..MAX_PAGE].to_vec(),
    };
    ok(worker(&u, first, t));
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::ListMismatch)
    );
    // A classification whose only page is lost: held rows do not turn
    // non-live by omission either.
    let mut classified = summary;
    classified.classified = true;
    classified.held_missing_total = 1;
    classified.lists.insert(
        FindingList::HeldMissingLive,
        ClassProof {
            count: 1,
            sha256: ids_hash(&ids(&["x_live"])),
        },
    );
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: classified,
        },
        t,
    ));
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::ListMismatch)
    );
}

#[test]
fn a_report_of_an_older_replay_never_lifts() {
    let u = closed();
    let t = BORN + 2000;
    level_stamp(&u, 5);
    // The report of a restore before the stamp was raised again (ordinal
    // 4): the counter is 5, so it does not lift.
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: rid("n1"),
        },
        t,
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: whole(&[]),
        },
        t,
    ));
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::StampNotLevelled)
    );
    // A report for the replay of this ordinal lifts.
    let now = ReplayId {
        ordinal: 5,
        ..rid("n3")
    };
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: now.clone(),
        },
        t,
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: now,
            summary: whole(&[]),
        },
        t,
    ));
    let p = proof(&u, t);
    assert!(matches!(lift(&u, S + 1, Some(p), t), UnitAnswer::Ok { .. }));
}

#[test]
fn the_ids_hash_is_over_sorted_unique_ids_each_with_a_newline() {
    use sha2::{Digest, Sha256};
    let ids = ["b".to_string(), "a".to_string(), "b".to_string()];
    let want: String = Sha256::digest(b"a\nb\n")
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    assert_eq!(ids_hash(&ids), want);
}
