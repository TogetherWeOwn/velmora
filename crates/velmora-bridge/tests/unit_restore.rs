//! The restore calls and the lift checked in the unit (AM-2, AM-3), on
//! the native database. The bookmark calls are the object's; here a fake
//! stands in for them. `workers/unit-suite` runs this file against a
//! Durable Object too.

use std::cell::RefCell;

use serde_json::json;
use velmora_bridge::testkit::{RusqliteSql, ARM_USAGE};
use velmora_bridge::unit::lift::{
    ids_hash, AckClass, FindingList, GateRefusal, GateSummary, LiftProof, ReplayId, MAX_PAGE,
};
use velmora_bridge::unit::restore::{
    drive, Bookmark, PitrStep, PointInTimePort, RestoreRefusal, RestoreTarget, LEASE_TERM_MS,
    RESTORE_MARGIN_MS,
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
                seqs: Seqs {
                    state_seq,
                    keys_seq: 0,
                },
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: restoring,
                lift: None,
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
    // The lease's own table (L2's migration), here by hand: no row, so
    // the unit never issued a lease.
    u.sql().apply(LEASE_TABLE).unwrap();
    u
}

const LEASE_TABLE: &str =
    "CREATE TABLE unit_lease (id INTEGER PRIMARY KEY, fresh_until INTEGER, lease_hi INTEGER)";

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
            "INSERT INTO unit_lease(id, fresh_until, lease_hi) VALUES (1, {}, {})",
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
        RestoreTarget::Time { at_ms: 1 },
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
    let at = RestoreTarget::Time { at_ms: BORN + 500 };
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
        vec![format!("bm-at-{}", BORN + 500)]
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

fn whole(damaged_total: u64) -> GateSummary {
    GateSummary {
        complete: true,
        damaged_total,
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
                seqs: Seqs {
                    state_seq,
                    keys_seq: 0,
                },
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: None,
                lift,
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
            summary: whole(0),
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
    assert!(matches!(lift(&u, S + 1, Some(p), t), UnitAnswer::Ok { .. }));
    let h = u.head().unwrap();
    assert_eq!((h.restoring_since, h.closed_at), (None, None));
    // The report is gone with the entry.
    assert_eq!(
        ok(worker(&u, UnitOp::GateStatus {}, t))["replay_id"],
        json!(null)
    );
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
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: whole(1),
        },
        t,
    ));
    ok(worker(
        &u,
        page(FindingList::Damaged, "n1", &ids(&["g_a"])),
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
            summary: whole(0),
        },
        t,
    ));
    assert_eq!(
        lift(&u, S + 1, None, t),
        refused_gate(GateRefusal::CountersOff)
    );
    // The gate's recount turns them on (AM-3).
    u.sql().apply(ARM_USAGE).unwrap();
    let p = proof(&u, t);
    assert!(matches!(lift(&u, S + 1, Some(p), t), UnitAnswer::Ok { .. }));
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
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: whole(2),
        },
        t,
    ));
    ok(worker(
        &u,
        page(FindingList::Damaged, "n1", &ids(&["g_a", "g_b"])),
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
        UnitOp::GateReport {
            replay_id: rid("n2"),
            summary: whole(2),
        },
        t,
    ));
    ok(worker(
        &u,
        page(FindingList::Damaged, "n2", &ids(&["g_a", "g_b"])),
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
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: rid("n1"),
            summary: whole(350),
        },
        t,
    ));
    let mut pages = all.chunks(MAX_PAGE);
    ok(worker(
        &u,
        page(FindingList::Damaged, "n1", pages.next().unwrap()),
        t,
    ));
    // Fewer listed than counted: closed (`Unlisted`) until every page is in.
    assert_eq!(lift(&u, S + 1, None, t), refused_gate(GateRefusal::Closed));
    for chunk in pages {
        ok(worker(&u, page(FindingList::Damaged, "n1", chunk), t));
    }
    for chunk in all.chunks(MAX_PAGE) {
        ok(worker(&u, ack("n1", chunk), t));
    }
    let p = proof(&u, t);
    assert_eq!(p.acknowledged[&AckClass::Damaged].count, 350);
    assert!(matches!(lift(&u, S + 1, Some(p), t), UnitAnswer::Ok { .. }));
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
            summary: whole(0),
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
            summary: whole(0),
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
