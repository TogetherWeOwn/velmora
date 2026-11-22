//! The lease wired into the unit (`docs/units.md`, rules 8 and 12;
//! `unit_lease`): the lease check on every call, `renew` and the `sync`
//! that closes, the numbers every answer carries, the write mark under
//! the catalogue, and the alarm. On the native database; the same unit
//! runs in the Durable Object through `DoSql`.

use serde_json::{json, Value};
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql};
use velmora_bridge::unit::jobcall::JobCall;
use velmora_bridge::unit::keys::{Access, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::restore::lease_view;
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp, UnitReply,
};
use velmora_bridge::unit_lease::alarm::{AlarmRules, MIN_ALARM_GAP_MS};
use velmora_bridge::unit_lease::job::{message, UnitJobKind};
use velmora_bridge::unit_lease::lease::{LeaseRefusal, LeaseRules, Proven};
use velmora_bridge::unit_lease::renewal::{prove, ChainNames, Proof, UnitView};
use velmora_bridge::unit_lease::store;
use velmora_bridge::unit_lease::UnitStampId;
use velmora_bridge::{BlobMeta, BlobStore, BucketId, Clock, ExtentId, UnixMs};

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const T: i64 = LeaseRules::DEFAULT.term_ms;
const PERIOD: i64 = AlarmRules::DEFAULT.stamp_period_ms;
const P: &str = "p_owner";
const K: &str = "AKWIRE00000000000001";
const GONE: &str = "AKWIRE00000000000099";
const B1: &str = "b_00000000000000e1";

fn tenant() -> TenantId {
    TenantId::parse("t_0000000000000e01").unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn stamp_id() -> String {
    format!("{}.0", tenant())
}

fn call(kind: CallKind, s: Option<Seqs>, authenticated: bool, op: UnitOp) -> UnitCall {
    UnitCall {
        name: own(),
        kind,
        seqs: s,
        authenticated,
        listed: true,
        op,
    }
}

fn at(state_seq: u64, keys_seq: u64) -> Option<Seqs> {
    Some(Seqs {
        state_seq,
        keys_seq,
    })
}

fn worker(u: &Unit<RusqliteSql>, op: UnitOp, now: UnixMs) -> UnitAnswer {
    u.handle(&call(CallKind::Worker, None, true, op), now)
}

fn sync(u: &Unit<RusqliteSql>, state_seq: u64, restoring: Option<u64>, now: UnixMs) -> UnitAnswer {
    let keys_seq = u.head().unwrap().seqs.keys_seq;
    worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                seqs: Seqs {
                    state_seq,
                    keys_seq,
                },
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: restoring,
                lift: None,
            },
        },
        now,
    )
}

fn proven(u: &Unit<RusqliteSql>, revoked: u64) -> Proven {
    let seqs = u.head().unwrap().seqs;
    Proven {
        state_seq: seqs.state_seq,
        keys_seq: seqs.keys_seq,
        stamp_counter: None,
        revoked,
    }
}

fn renew_op(proof_start: UnixMs, proven: Proven, revocations: &[&str]) -> UnitOp {
    UnitOp::Renew {
        proof_start,
        proven,
        revocations: revocations.iter().map(|s| s.to_string()).collect(),
    }
}

fn renew(u: &Unit<RusqliteSql>, now: UnixMs) -> UnitAnswer {
    worker(u, renew_op(now, proven(u, 0), &[]), now)
}

/// A born unit at seq 3, active, with no lease yet, holding bucket B1
/// with one object of two extents.
fn born() -> Unit<RusqliteSql> {
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    let token = BirthToken {
        name: own(),
        jurisdiction: String::new(),
        record_seq: 3,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: 2,
        kind: BirthKind::Birth,
    };
    let a = u.handle(
        &call(
            CallKind::Worker,
            at(3, 0),
            true,
            UnitOp::Provision {
                token,
                sealed: vec![1],
            },
        ),
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert!(matches!(sync(&u, 3, None, NOW), UnitAnswer::Ok { .. }));
    u.sql()
        .apply(&format!(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('{B1}', 'alpha', 'o', x'02', 1, 1); \
             INSERT INTO generations(id, bucket_id, key, state, size, etag, content_json, \
               user_meta_json, extent_count, created_at) \
               VALUES ('g_0019a00000000e1e1e1e1e1e1e1e1', '{B1}', 'k', 'live', 20, \
                 '\"e\"', '{{}}', '{{}}', 2, 1); \
             INSERT INTO objects(bucket_id, key, generation_id) \
               VALUES ('{B1}', 'k', 'g_0019a00000000e1e1e1e1e1e1e1e1'); \
             INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
               plain_size, cipher_size, media_header, plain_md5, plain_sha256, cipher_sha256, \
               safety_state, created_at) \
               VALUES ('x_000000000000000000000000e1', '{B1}', \
                 'g_0019a00000000e1e1e1e1e1e1e1e1', 'committed', 0, 0, 10, 10, zeroblob(48), \
                 zeroblob(16), zeroblob(32), zeroblob(32), 'held', 1), \
                      ('x_000000000000000000000000e2', '{B1}', \
                 'g_0019a00000000e1e1e1e1e1e1e1e1', 'committed', 1, 10, 10, 10, zeroblob(48), \
                 zeroblob(16), zeroblob(32), zeroblob(32), 'held', 1);"
        ))
        .unwrap();
    u
}

/// [`born`] with a lease renewed at `NOW`.
fn fresh() -> Unit<RusqliteSql> {
    let u = born();
    assert!(matches!(renew(&u, NOW), UnitAnswer::Ok { .. }));
    u
}

/// A read plan of the object: with `authenticated` it stamps the reads
/// of its extents (a write).
fn read_plan() -> UnitOp {
    UnitOp::ReadPlan {
        bucket: "alpha".into(),
        key: "k".into(),
        start: 0,
        end: 20,
        access_key_id: None,
        reader: None,
        generation: None,
    }
}

fn request(u: &Unit<RusqliteSql>, authenticated: bool, op: UnitOp, now: UnixMs) -> UnitAnswer {
    u.handle(&call(CallKind::Request, at(3, 0), authenticated, op), now)
}

fn job(u: &Unit<RusqliteSql>, c: JobCall, now: UnixMs) -> UnitAnswer {
    let seqs = u.head().unwrap().seqs;
    u.handle(
        &call(CallKind::Job, Some(seqs), true, UnitOp::Job { call: c }),
        now,
    )
}

fn changes(u: &Unit<RusqliteSql>) -> u64 {
    u.sql().with_conn(|c| c.total_changes())
}

fn lease_row(u: &Unit<RusqliteSql>) -> store::LeaseRow {
    assert!(store::present(u.sql()).unwrap(), "the lease's tables");
    store::read(u.sql()).unwrap()
}

fn renew_needed(why: Option<LeaseRefusal>) -> impl Fn(&UnitAnswer) -> bool {
    move |a| matches!(a, UnitAnswer::RenewNeeded { why: w, .. } if *w == why)
}

fn principal(seq: u64) -> KeyEntry {
    KeyEntry {
        id: P.into(),
        kind: KeyKind::Principal,
        status: SubjectStatus::Active,
        held: false,
        made_by: None,
        grants: vec![KeyGrant {
            bucket_id: B1.into(),
            access: Access::Rw,
            expires_at: None,
            prefix: None,
            ip_list: vec![],
        }],
        created_at: 1,
        secret_wrapped: None,
        secret_kek_version: None,
        owner_ref: Some("member-1".into()),
        last_seq: seq,
        rid: None,
    }
}

fn key(id: &str, seq: u64) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        kind: KeyKind::S3,
        status: SubjectStatus::Active,
        held: false,
        made_by: Some(P.into()),
        grants: vec![KeyGrant {
            bucket_id: B1.into(),
            access: Access::Ro,
            expires_at: None,
            prefix: None,
            ip_list: vec![],
        }],
        created_at: 2,
        secret_wrapped: Some(vec![2, 0xaa]),
        secret_kek_version: Some(1),
        owner_ref: Some("member-1".into()),
        last_seq: seq,
        rid: None,
    }
}

/// Whether the S3 path serves `id` (its catalogue key row is active).
fn served(u: &Unit<RusqliteSql>, id: &str) -> bool {
    u.sql().with_conn(|c| {
        c.query_row(
            "SELECT count(*) FROM access_keys WHERE access_key_id = ?1 AND status = 'active'",
            [id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            == 1
    })
}

fn status_of(u: &Unit<RusqliteSql>, id: &str) -> String {
    u.sql().with_conn(|c| {
        c.query_row("SELECT status FROM unit_keys WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap()
    })
}

// ---------------------------------------------------------------------------
// u0002
// ---------------------------------------------------------------------------

#[test]
fn a_birth_makes_the_lease_tables_with_no_lease() {
    let u = born();
    assert_eq!(lease_row(&u), store::LeaseRow::default());
    // The restore's checks see the table: a lease never issued.
    let view = lease_view(u.sql()).unwrap().expect("known");
    assert_eq!((view.fresh_until, view.lease_hi), (None, None));
    let ids: i64 = u.sql().with_conn(|c| {
        c.query_row("SELECT count(*) FROM unit_revoked_ids", [], |r| r.get(0))
            .unwrap()
    });
    assert_eq!(ids, 0);
}

// ---------------------------------------------------------------------------
// Rule 12 on every call
// ---------------------------------------------------------------------------

#[test]
fn an_expired_lease_refuses_every_call_but_the_workers_and_writes_nothing() {
    let u = born();
    let before = changes(&u);
    for (kind, authenticated, op) in [
        (CallKind::Request, true, UnitOp::Ping {}),
        (CallKind::Request, true, read_plan()),
        (CallKind::Request, false, read_plan()),
        (
            CallKind::Request,
            false,
            UnitOp::KeyRow {
                access_key_id: K.into(),
            },
        ),
    ] {
        let a = u.handle(&call(kind, at(3, 0), authenticated, op), NOW);
        assert!(renew_needed(None)(&a), "{a:?}");
    }
    let a = job(
        &u,
        JobCall::stored_plan {
            extent: ExtentId::new("x_000000000000000000000000e1"),
        },
        NOW,
    );
    assert!(renew_needed(None)(&a), "a job: {a:?}");
    assert_eq!(changes(&u), before, "nothing written");

    // The Worker's own calls still run: they copy verified records.
    assert!(matches!(sync(&u, 3, None, NOW), UnitAnswer::Ok { .. }));
    assert!(matches!(
        worker(&u, UnitOp::HeldKeys {}, NOW),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![principal(1)],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    // The stamp check of a renewal's `StampAhead` runs too.
    assert!(matches!(
        job(
            &u,
            JobCall::stamp {
                catalogue: stamp_id()
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    // A stamp raise does not: it waits for the renewal.
    let a = job(
        &u,
        JobCall::stamp_advance {
            from: None,
            catalogue: stamp_id(),
        },
        NOW,
    );
    assert!(renew_needed(None)(&a), "{a:?}");
}

#[test]
fn a_fresh_lease_serves_until_proof_start_plus_t_and_not_a_moment_longer() {
    let u = born();
    let proof_start = UnixMs(NOW.0 - 1_000);
    let a = worker(&u, renew_op(proof_start, proven(&u, 0), &[]), NOW);
    let UnitAnswer::Ok { body, .. } = a else {
        panic!("{a:?}")
    };
    assert_eq!(body["fresh_until"], json!(proof_start.0 + T));
    let last = UnixMs(proof_start.0 + T - 1);
    assert!(matches!(
        request(&u, true, UnitOp::Ping {}, last),
        UnitAnswer::Ok { .. }
    ));
    let gone = UnixMs(proof_start.0 + T);
    assert!(renew_needed(None)(&request(
        &u,
        true,
        UnitOp::Ping {},
        gone
    )));
}

#[test]
fn a_renewal_never_moves_the_lease_back_and_the_high_mark_follows_it() {
    let u = fresh();
    let first = lease_row(&u);
    assert_eq!(first.fresh_until, Some(UnixMs(NOW.0 + T)));
    assert_eq!(first.lease_hi, first.fresh_until);
    // An older proof that crossed a newer one changes nothing.
    let later = UnixMs(NOW.0 + 2_000);
    let a = worker(&u, renew_op(NOW, proven(&u, 0), &[]), later);
    assert!(matches!(a, UnitAnswer::Ok { .. }));
    assert_eq!(lease_row(&u).fresh_until, first.fresh_until);
    // A newer one moves both.
    assert!(matches!(renew(&u, later), UnitAnswer::Ok { .. }));
    let row = lease_row(&u);
    assert_eq!(row.fresh_until, Some(UnixMs(later.0 + T)));
    assert_eq!(row.lease_hi, row.fresh_until);
}

#[test]
fn a_renewal_from_a_stale_or_future_proof_or_of_a_newer_state_is_refused() {
    let u = born();
    let rules = LeaseRules::DEFAULT;
    let old = UnixMs(NOW.0 - rules.max_behind_ms - 1);
    let a = worker(&u, renew_op(old, proven(&u, 0), &[]), NOW);
    assert!(renew_needed(Some(LeaseRefusal::ProofTooOld))(&a), "{a:?}");
    let ahead = UnixMs(NOW.0 + rules.max_ahead_ms + 1);
    let a = worker(&u, renew_op(ahead, proven(&u, 0), &[]), NOW);
    assert!(renew_needed(Some(LeaseRefusal::ProofAhead))(&a), "{a:?}");
    // The proof was made for a newer state than the unit holds (it was
    // rolled back after the Worker took its view).
    let mut newer = proven(&u, 0);
    newer.state_seq += 1;
    let a = worker(&u, renew_op(NOW, newer, &[]), NOW);
    assert!(renew_needed(Some(LeaseRefusal::NotProven))(&a), "{a:?}");
    let mut stamped = proven(&u, 0);
    stamped.stamp_counter = Some(1);
    let a = worker(&u, renew_op(NOW, stamped, &[]), NOW);
    assert!(renew_needed(Some(LeaseRefusal::NotProven))(&a), "{a:?}");
    assert_eq!(lease_row(&u).fresh_until, None, "no lease from any of them");
}

#[test]
fn renew_applies_the_listed_revocations_and_counts_each_id_once() {
    let u = born();
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![principal(1), key(K, 2)],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(sync(&u, 3, None, NOW), UnitAnswer::Ok { .. }));
    assert!(served(&u, K));
    // The proof listed K and an id the unit never had a row for.
    let a = worker(&u, renew_op(NOW, proven(&u, 2), &[K, GONE]), NOW);
    let UnitAnswer::Ok { body, .. } = a else {
        panic!("{a:?}")
    };
    assert_eq!(body["applied"], json!(2));
    assert_eq!(status_of(&u, K), "revoked");
    assert!(!served(&u, K), "a revoked key is not served");
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(2));

    // The chain record that made GONE arrives later: the listing wins,
    // and the count stays one per id.
    let a = worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 2,
            entries: vec![key(GONE, 3)],
            answers: vec![],
        },
        NOW,
    );
    let UnitAnswer::Ok { body, .. } = a else {
        panic!("{a:?}")
    };
    assert_eq!(body["revoked"], json!(2));
    assert_eq!(status_of(&u, GONE), "revoked");
    assert!(!served(&u, GONE));
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(2));
    // Listing them again changes nothing.
    assert!(matches!(sync(&u, 3, None, NOW), UnitAnswer::Ok { .. }));
    let a = worker(&u, renew_op(NOW, proven(&u, 2), &[K, GONE]), NOW);
    assert!(
        matches!(&a, UnitAnswer::Ok { body, .. } if body["applied"] == json!(0)),
        "{a:?}"
    );
}

#[test]
fn a_list_that_is_not_access_key_ids_is_refused_and_keeps_nothing() {
    let u = born();
    let before = changes(&u);
    let a = worker(&u, renew_op(NOW, proven(&u, 2), &[K, "not/an-id"]), NOW);
    assert!(renew_needed(Some(LeaseRefusal::BadList))(&a), "{a:?}");
    assert_eq!(changes(&u), before);
    assert_eq!(store::revoked(u.sql()).unwrap(), None);
}

#[test]
fn a_proof_that_listed_more_than_the_unit_then_holds_is_refused() {
    let u = born();
    // The proof counted 3 revocations and handed over 2 ids: the unit
    // holds 2 and refuses (a listing that changed between count and ids).
    let a = worker(&u, renew_op(NOW, proven(&u, 3), &[K, GONE]), NOW);
    assert!(renew_needed(Some(LeaseRefusal::NotProven))(&a), "{a:?}");
    // The two it was given are kept: each is a fact of `m/rk/`.
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(2));
    assert_eq!(lease_row(&u).fresh_until, None);
}

// ---------------------------------------------------------------------------
// Closing
// ---------------------------------------------------------------------------

#[test]
fn the_sync_that_sets_a_restoring_entry_ends_the_lease_and_keeps_its_high_mark() {
    let u = fresh();
    let hi = lease_row(&u).lease_hi;
    assert!(matches!(
        sync(&u, 4, Some(4), UnixMs(NOW.0 + 1_000)),
        UnitAnswer::Ok { .. }
    ));
    let row = lease_row(&u);
    assert_eq!(row.fresh_until, None);
    assert_eq!(row.lease_hi, hi);
    let a = renew(&u, UnixMs(NOW.0 + 2_000));
    assert!(renew_needed(Some(LeaseRefusal::Restoring))(&a), "{a:?}");
    assert_eq!(lease_row(&u).fresh_until, None);
}

#[test]
fn a_recorded_rollback_closes_the_lease_at_once_and_refuses_renewal() {
    let u = fresh();
    // Raise once, then the Worker finds a stamp object after counter 1.
    assert!(matches!(
        job(
            &u,
            JobCall::stamp_advance {
                from: None,
                catalogue: stamp_id()
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    let a = job(
        &u,
        JobCall::stamp_rolled_back {
            seen: Some(1),
            now: NOW,
            catalogue: stamp_id(),
        },
        NOW,
    );
    assert!(
        matches!(&a, UnitAnswer::Ok { body, .. } if *body == Value::Bool(true)),
        "{a:?}"
    );
    assert_eq!(lease_row(&u).fresh_until, None);
    assert!(renew_needed(None)(&request(&u, true, UnitOp::Ping {}, NOW)));
    let mut p = proven(&u, 0);
    p.stamp_counter = Some(1);
    let a = worker(&u, renew_op(NOW, p, &[]), NOW);
    assert!(renew_needed(Some(LeaseRefusal::RolledBack))(&a), "{a:?}");
}

#[test]
fn a_unit_without_the_lease_table_is_never_served_or_renewed() {
    let u = born();
    u.sql().apply("DROP TABLE unit_lease").unwrap();
    assert!(renew_needed(None)(&request(&u, true, UnitOp::Ping {}, NOW)));
    let a = renew(&u, NOW);
    assert!(renew_needed(Some(LeaseRefusal::NoLeaseTable))(&a), "{a:?}");
}

// ---------------------------------------------------------------------------
// What every answer carries
// ---------------------------------------------------------------------------

#[test]
fn every_answer_carries_the_lease_left_and_the_revoked_count_once_keys_exist() {
    let u = born();
    let ping = call(CallKind::Request, at(3, 0), true, UnitOp::Ping {});
    let r = u.reply(&ping, NOW);
    assert!(renew_needed(None)(&r.answer));
    assert_eq!((r.lease_left_ms, r.revoked), (0, None));

    assert!(matches!(renew(&u, NOW), UnitAnswer::Ok { .. }));
    let r = u.reply(&ping, UnixMs(NOW.0 + 1_000));
    assert!(matches!(r.answer, UnitAnswer::Ok { .. }));
    assert_eq!(r.lease_left_ms, (T - 1_000) as u64);
    assert_eq!(r.revoked, None, "no key, no revoked");

    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![principal(1)],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    let r = u.reply(
        &call(CallKind::Request, at(3, 1), true, UnitOp::Ping {}),
        NOW,
    );
    assert_eq!(r.revoked, Some(0));
    // On the wire: the answer's object with both beside its fields.
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["answer"], json!("ok"));
    assert_eq!(v["lease_left_ms"], json!(T));
    assert_eq!(v["revoked"], json!(0));
    assert_eq!(serde_json::from_value::<UnitReply>(v).unwrap(), r);

    // An unborn unit and a call for another name carry nothing.
    let unborn = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    let r = unborn.reply(&ping, NOW);
    assert!(matches!(r.answer, UnitAnswer::Unborn { .. }));
    assert_eq!((r.lease_left_ms, r.revoked), (0, None));
    let mut other = ping.clone();
    other.name = UnitName::new(tenant(), 1);
    let r = u.reply(&other, NOW);
    assert!(matches!(
        r.answer,
        UnitAnswer::Refused {
            reason: Refused::Identity(_),
            ..
        }
    ));
    assert_eq!((r.lease_left_ms, r.revoked), (0, None));
}

// ---------------------------------------------------------------------------
// The write mark and the first write
// ---------------------------------------------------------------------------

#[test]
fn every_write_of_the_unit_moves_the_mark_and_a_read_does_not() {
    let u = fresh();
    let m0 = u.mark();
    assert!(matches!(
        request(&u, false, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(u.mark(), m0, "an unauthenticated read writes nothing");
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    let m1 = u.mark();
    assert!(m1.writes > m0.writes && !m1.writing);
    assert!(matches!(renew(&u, NOW), UnitAnswer::Ok { .. }));
    assert!(u.mark().writes > m1.writes, "the lease row is a write too");
    assert_eq!(u.mark().wake_id, m0.wake_id);
}

#[test]
fn the_first_write_since_the_raise_asks_for_the_alarm_once() {
    let u = fresh();
    let _ = u.take_wake();
    // A read stamp is a write.
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(lease_row(&u).first_write_at, Some(NOW));
    assert_eq!(u.take_wake(), Some(UnixMs(NOW.0 + PERIOD)));
    let later = UnixMs(NOW.0 + 120_000);
    assert!(matches!(
        request(&u, true, read_plan(), later),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(lease_row(&u).first_write_at, Some(NOW), "the first stays");
    assert_eq!(u.take_wake(), None);
    // The stamp's own calls never make a raise due (else each raise
    // would ask for the next).
    let u = fresh();
    let _ = u.take_wake();
    assert!(matches!(
        job(
            &u,
            JobCall::stamp_advance {
                from: None,
                catalogue: stamp_id()
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(lease_row(&u).first_write_at, None);
    assert_eq!(u.take_wake(), None);
}

// ---------------------------------------------------------------------------
// The alarm
// ---------------------------------------------------------------------------

fn job_text(kind: UnitJobKind, u: &Unit<RusqliteSql>, at: UnixMs) -> String {
    message(kind, &own(), u.head().unwrap().seqs, at).unwrap()
}

#[test]
fn the_alarm_sends_one_stamp_raise_per_period_with_writes_under_a_fresh_lease() {
    let u = fresh();
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    // Woken early: nothing is due yet; the raise's time is armed.
    let early = UnixMs(NOW.0 + 1_000);
    let step = u.alarm(early).unwrap();
    assert!(step.jobs.is_empty() && !step.raise);
    assert_eq!(
        u.alarm_done(early, &step, false).unwrap(),
        Some(UnixMs(NOW.0 + PERIOD))
    );
    let due = UnixMs(NOW.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    assert!(step.raise);
    assert_eq!(step.jobs, vec![job_text(UnitJobKind::StampRaise, &u, due)]);
    assert_eq!(u.alarm_done(due, &step, false).unwrap(), None, "idle again");
    let row = lease_row(&u);
    assert_eq!(row.first_write_at, None);
    assert_eq!((row.renew_tries, row.failed_runs), (0, 0));
}

#[test]
fn an_expired_lease_sends_one_renew_and_the_work_runs_after_the_renewal() {
    let u = fresh();
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    // The unit goes idle: its lease runs out, and the raise is due.
    let due = UnixMs(NOW.0 + T + 1);
    let step = u.alarm(due).unwrap();
    assert!(!step.raise, "no raise while expired");
    assert_eq!(step.jobs, vec![job_text(UnitJobKind::Renew, &u, due)]);
    let next = u.alarm_done(due, &step, false).unwrap().unwrap();
    assert_eq!(next.0, due.0 + AlarmRules::DEFAULT.renew_retry_ms);
    let row = lease_row(&u);
    assert_eq!(row.renew_tries, 1);
    assert_eq!(row.first_write_at, Some(NOW), "the work stays due");
    // The second try waits twice as long.
    let step = u.alarm(next).unwrap();
    assert_eq!(step.jobs, vec![job_text(UnitJobKind::Renew, &u, next)]);
    let next2 = u.alarm_done(next, &step, false).unwrap().unwrap();
    assert_eq!(next2.0, next.0 + 2 * AlarmRules::DEFAULT.renew_retry_ms);
    // The renewal comes: the tries reset, and the alarm is asked for now.
    let _ = u.take_wake();
    let back = UnixMs(next.0 + 5_000);
    assert!(matches!(renew(&u, back), UnitAnswer::Ok { .. }));
    assert_eq!(lease_row(&u).renew_tries, 0);
    assert_eq!(u.take_wake(), Some(back));
    let step = u.alarm(back).unwrap();
    assert_eq!(step.jobs, vec![job_text(UnitJobKind::StampRaise, &u, back)]);
}

#[test]
fn a_failed_send_keeps_the_work_due_and_backs_off() {
    let u = fresh();
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    let due = UnixMs(NOW.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    let next = u.alarm_done(due, &step, true).unwrap().unwrap();
    let row = lease_row(&u);
    assert_eq!(row.first_write_at, Some(NOW), "still due");
    assert_eq!(row.failed_runs, 1);
    assert!(next.0 >= due.0 + MIN_ALARM_GAP_MS);
    // A run in which everything was sent resets the count (renewed
    // first: by now less than half of T is left).
    assert!(matches!(renew(&u, next), UnitAnswer::Ok { .. }));
    let step = u.alarm(next).unwrap();
    assert!(step.raise);
    u.alarm_done(next, &step, false).unwrap();
    let row = lease_row(&u);
    assert_eq!((row.failed_runs, row.first_write_at), (0, None));
}

/// The raise is handed out only while half of T is left: its consumer
/// reaches the unit later, and a refused raise would never be asked for
/// again. With less left the alarm renews first.
#[test]
fn a_raise_waits_for_a_renewal_when_the_lease_runs_low() {
    let u = fresh();
    let write = UnixMs(NOW.0 + 60_000);
    assert!(matches!(
        request(&u, true, read_plan(), write),
        UnitAnswer::Ok { .. }
    ));
    let due = UnixMs(write.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    assert!(!step.raise);
    assert_eq!(step.jobs, vec![job_text(UnitJobKind::Renew, &u, due)]);
    let next = u.alarm_done(due, &step, false).unwrap().unwrap();
    assert_eq!(next.0, due.0 + AlarmRules::DEFAULT.renew_retry_ms);
    assert_eq!(lease_row(&u).first_write_at, Some(write), "still due");
    let _ = u.take_wake();
    assert!(matches!(renew(&u, due), UnitAnswer::Ok { .. }));
    assert_eq!(u.take_wake(), Some(due));
    let step = u.alarm(due).unwrap();
    assert_eq!(step.jobs, vec![job_text(UnitJobKind::StampRaise, &u, due)]);
}

/// A write while the raise is being sent is pending a raise of its own,
/// and a renewal during the sends does not count as a failed try.
#[test]
fn what_happens_during_the_sends_is_kept() {
    let u = fresh();
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    let due = UnixMs(NOW.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    assert!(step.raise);
    let during = UnixMs(due.0 + 10);
    assert!(matches!(
        request(&u, true, read_plan(), during),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(
        u.alarm_done(during, &step, false).unwrap(),
        Some(UnixMs(during.0 + PERIOD))
    );
    assert_eq!(lease_row(&u).first_write_at, Some(during));

    // The renew the alarm sends lands before the run is recorded.
    let late = UnixMs(during.0 + PERIOD + 1);
    assert!(late.0 > NOW.0 + T, "the lease has run out");
    let step = u.alarm(late).unwrap();
    assert!(step.run.send_renew);
    assert!(matches!(renew(&u, late), UnitAnswer::Ok { .. }));
    u.alarm_done(late, &step, false).unwrap();
    assert_eq!(lease_row(&u).renew_tries, 0);
}

/// A principal is not a key: `m/rk/` never names one, so a revoked
/// principal must not raise the count the proof compares with.
#[test]
fn a_revoked_principal_is_not_counted() {
    let u = born();
    let mut gone = principal(1);
    gone.status = SubjectStatus::Revoked;
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![gone],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(status_of(&u, P), "revoked");
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(0));
    assert!(matches!(sync(&u, 3, None, NOW), UnitAnswer::Ok { .. }));
    assert!(matches!(
        worker(&u, renew_op(NOW, proven(&u, 0), &[]), NOW),
        UnitAnswer::Ok { .. }
    ));
}

/// An alarm wake with nothing to send writes nothing, on an idle unit
/// and on a closed one (a restore's check 4 and a dump's mark need it).
#[test]
fn an_idle_or_closed_alarm_wake_writes_nothing() {
    let u = fresh();
    let m = u.mark();
    let step = u.alarm(UnixMs(NOW.0 + 1_000)).unwrap();
    assert!(step.jobs.is_empty());
    assert_eq!(
        u.alarm_done(UnixMs(NOW.0 + 1_000), &step, false).unwrap(),
        None
    );
    assert_eq!(u.mark(), m, "an idle wake");

    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    let due = UnixMs(NOW.0 + PERIOD);
    let _dead = u.alarm(due).unwrap();
    assert!(matches!(sync(&u, 4, Some(4), due), UnitAnswer::Ok { .. }));
    let m = u.mark();
    let later = UnixMs(due.0 + 1_000);
    let step = u.alarm(later).unwrap();
    assert!(step.jobs.is_empty());
    assert_eq!(u.alarm_done(later, &step, false).unwrap(), None);
    assert_eq!(u.mark(), m, "a closed wake, even with a dead run's raise");
}

/// A run that dies during its send (the object reset) leaves its raise
/// pending: the next run sends it again.
#[test]
fn a_raise_of_a_run_that_died_is_sent_again() {
    let u = fresh();
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    let due = UnixMs(NOW.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    assert!(step.raise);
    assert_eq!(lease_row(&u).raise_from, Some(NOW));
    // No `alarm_done`: the platform runs the alarm again.
    let again = UnixMs(due.0 + 1_000);
    assert!(matches!(renew(&u, again), UnitAnswer::Ok { .. }));
    let step = u.alarm(again).unwrap();
    assert!(step.raise, "the dead run's raise is due again");
    u.alarm_done(again, &step, false).unwrap();
    let row = lease_row(&u);
    assert_eq!((row.first_write_at, row.raise_from), (None, None));
}

/// A listed id that names a principal row (were one ever listed) is kept
/// on its own: the principal is left as it is, and the count and the
/// check agree with the listing.
#[test]
fn a_listed_id_of_a_principal_row_counts_without_touching_it() {
    let u = born();
    let mut p = principal(1);
    p.id = "PWIRE0000000000001".into();
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![p],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(sync(&u, 3, None, NOW), UnitAnswer::Ok { .. }));
    let a = worker(
        &u,
        renew_op(NOW, proven(&u, 1), &["PWIRE0000000000001"]),
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(status_of(&u, "PWIRE0000000000001"), "active");
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(1));
}

/// The alarm sends each job as a JavaScript object parsed from its JSON
/// text. A `serde_json::Value` given to the SDK's `MessageBuilder` goes
/// through `serde_wasm_bindgen`, which makes a map of it, and a map is
/// sent as `{}`.
#[test]
fn the_alarm_sends_raw_parsed_json() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../workers/unit/src/alarm.rs"
    ))
    .unwrap();
    assert!(src.contains("js_sys::JSON::parse(text)"));
    assert!(src.contains(".send_raw("));
    for (n, line) in src.lines().enumerate() {
        assert!(
            !line
                .replace("RawMessageBuilder", "")
                .contains("MessageBuilder"),
            "alarm.rs:{}: {line}",
            n + 1
        );
    }
}

#[test]
fn a_closed_or_unborn_unit_runs_nothing_and_arms_nothing() {
    let u = fresh();
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(sync(&u, 4, Some(4), NOW), UnitAnswer::Ok { .. }));
    let due = UnixMs(NOW.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    assert!(step.jobs.is_empty() && !step.run.send_renew);
    assert_eq!(u.alarm_done(due, &step, false).unwrap(), None);

    let unborn = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    let step = unborn.alarm(due).unwrap();
    assert!(step.jobs.is_empty());
    assert_eq!(unborn.alarm_done(due, &step, false).unwrap(), None);
    let tables: i64 = unborn.sql().with_conn(|c| {
        c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .unwrap()
    });
    assert_eq!(tables, 0, "an unborn unit writes nothing (rule 7)");
}

/// The bytes of W0b's writer (`jobmsg::UnitJob::message`, PR #190).
#[test]
fn the_alarms_jobs_are_format_2_with_the_tenant_and_the_unit() {
    let seqs = Seqs {
        state_seq: 7,
        keys_seq: 3,
    };
    assert_eq!(
        message(UnitJobKind::Renew, &own(), seqs, UnixMs(5)).unwrap(),
        r#"{"t":"renew","v":2,"at":5,"tenant":"t_0000000000000e01","unit":0,"state_seq":7,"keys_seq":3}"#
    );
    assert_eq!(
        message(
            UnitJobKind::StampRaise,
            &UnitName::new(tenant(), 4),
            seqs,
            UnixMs(6)
        )
        .unwrap(),
        r#"{"t":"stamp_raise","v":2,"at":6,"tenant":"t_0000000000000e01","unit":4,"state_seq":7,"keys_seq":3}"#
    );
    let zero = UnitName::new(TenantId::parse("t_0000000000000000").unwrap(), 0);
    assert_eq!(message(UnitJobKind::Renew, &zero, seqs, UnixMs(5)), None);
}

// ---------------------------------------------------------------------------
// From the stores to a served call
// ---------------------------------------------------------------------------

struct Names;

impl ChainNames for Names {
    fn tenant_record(&self, tenant: &str, seq: u64) -> String {
        format!("m/t/{tenant}/{seq:020}")
    }
    fn key_record(&self, tenant: &str, seq: u64) -> String {
        format!("m/k/{tenant}/{seq:020}")
    }
    fn revocation_dir(&self, tenant: &str) -> String {
        format!("m/rk/{tenant}/")
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

/// The Worker proves the unit from what its last answer said, then
/// renews it with the proof: a revocation the unit never got is applied
/// first, and the unit then serves.
#[test]
fn a_renewal_proven_from_the_stores_opens_the_unit() {
    let u = born();
    let safety = MemBlobStore::new();
    let clock = FixedClock::new(NOW);
    let (bucket, extent) = (BucketId::new("-"), ExtentId::new("planted"));
    let sha: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(b"r").into()
    };
    let meta = BlobMeta {
        bucket: &bucket,
        extent: &extent,
        cipher_sha256: &sha,
    };
    block_on(async {
        for name in [
            Names.tenant_record(tenant().as_str(), 3),
            format!("m/rk/{}/{GONE}", tenant()),
            format!("m/rk/{}/not.an-id", tenant()),
        ] {
            safety.put(&name, b"r".to_vec(), &meta).await.unwrap();
        }
    });
    let ping = call(CallKind::Request, at(3, 0), true, UnitOp::Ping {});
    let r = u.reply(&ping, NOW);
    assert!(renew_needed(None)(&r.answer));
    let UnitAnswer::RenewNeeded { seqs, .. } = r.answer else {
        unreachable!()
    };
    let id = UnitStampId::new(tenant().as_str(), 0).unwrap();
    let proof = block_on(prove(
        &safety,
        &clock,
        &Names,
        &UnitView {
            stamp_id: &id,
            state_seq: seqs.state_seq,
            keys_seq: seqs.keys_seq,
            stamp_counter: None,
            revoked: r.revoked.unwrap_or(0),
        },
    ))
    .unwrap();
    let Proof::Fresh {
        proof_start,
        proven,
        revocations,
        stray,
    } = proof
    else {
        panic!("{proof:?}")
    };
    assert_eq!(revocations, vec![GONE.to_string()]);
    assert_eq!(stray.len(), 1, "the stray name is skipped and paged");
    let renewed = u.reply(
        &call(
            CallKind::Worker,
            None,
            true,
            UnitOp::Renew {
                proof_start,
                proven,
                revocations,
            },
        ),
        clock.now(),
    );
    assert!(
        matches!(renewed.answer, UnitAnswer::Ok { .. }),
        "{renewed:?}"
    );
    assert_eq!(renewed.lease_left_ms, T as u64);
    assert_eq!(renewed.revoked, Some(1));
    assert!(matches!(u.handle(&ping, NOW), UnitAnswer::Ok { .. }));
}
