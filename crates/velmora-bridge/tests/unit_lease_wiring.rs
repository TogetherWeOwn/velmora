//! The lease wired into the unit (`docs/units.md`, rules 8 and 12;
//! `unit_lease`): the lease check on every call, `renew` and the `sync`
//! that closes, the numbers every answer carries, the write mark under
//! the catalogue, and the alarm. On the native database; the same unit
//! runs in the Durable Object through `DoSql`.

use serde_json::{json, Value};
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql};
use velmora_bridge::unit::jobcall::JobCall;
use velmora_bridge::unit::keys::{Access, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::request::RequestCall;
use velmora_bridge::unit::restore::lease_view;
use velmora_bridge::unit::{
    AlarmSent, BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState,
    Unit, UnitAnswer, UnitCall, UnitName, UnitOp, UnitReply,
};
use velmora_bridge::unit_lease::alarm::{AlarmRules, MIN_ALARM_GAP_MS};
use velmora_bridge::unit_lease::job::{message, UnitJobKind};
use velmora_bridge::unit_lease::lease::{LeaseRefusal, LeaseRules, Proven};
use velmora_bridge::unit_lease::renewal::{prove, ChainNames, Proof, UnitView};
use velmora_bridge::unit_lease::store;
use velmora_bridge::unit_lease::UnitStampId;
use velmora_bridge::{BlobMeta, BlobStore, BucketId, Clock, ExtentId, UnixMs, UploadId};

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const T: i64 = LeaseRules::DEFAULT.term_ms;
const PERIOD: i64 = AlarmRules::DEFAULT.stamp_period_ms;
const P: &str = "p_owner";
const LISTED_P: &str = "p_00000000000000a1";
const K: &str = "AKWIRE00000000000001";
const GONE: &str = "AKWIRE00000000000099";
const B1: &str = "b_00000000000000e1";
const B2: &str = "b_00000000000000e2";

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

fn sync(
    u: &Unit<RusqliteSql>,
    state_seq: u64,
    restoring: Option<u64>,
    placed: &[&str],
    now: UnixMs,
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
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: restoring,
                lift: None,
                buckets: vec![],
                placed: placed.iter().map(|id| id.to_string()).collect(),
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
    assert!(matches!(sync(&u, 3, None, &[], NOW), UnitAnswer::Ok { .. }));
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

fn listed_principal(seq: u64) -> KeyEntry {
    KeyEntry {
        id: LISTED_P.into(),
        ..principal(seq)
    }
}

fn listed_principals_key(seq: u64) -> KeyEntry {
    KeyEntry {
        made_by: Some(LISTED_P.into()),
        ..key(K, seq)
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

/// Count the catalogue's effective grants, not the grants kept in the key chain.
fn effective_grants_for(u: &Unit<RusqliteSql>, id: &str) -> i64 {
    u.sql().with_conn(|c| {
        c.query_row(
            "SELECT count(*) FROM grants WHERE access_key_id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap()
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
        // AM-63: only the unauthenticated `key_row` is answered (below).
        (
            CallKind::Request,
            true,
            UnitOp::KeyRow {
                access_key_id: K.into(),
                presigned: None,
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
    assert!(matches!(
        sync(&u, 3, None, &[B1], NOW),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        worker(&u, UnitOp::HeldKeys {}, NOW),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![principal(1).into()],
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

fn key_row(u: &Unit<RusqliteSql>, kind: CallKind, authenticated: bool, now: UnixMs) -> UnitAnswer {
    let seqs = u.head().unwrap().seqs;
    u.handle(
        &call(
            kind,
            Some(seqs),
            authenticated,
            UnitOp::KeyRow {
                access_key_id: K.into(),
                presigned: None,
            },
        ),
        now,
    )
}

/// AM-63: with an expired lease the unit still answers the S3 path's
/// first call, an unauthenticated `key_row`, read-only and marked
/// `lease_expired`, so a request whose signature verifies can renew as a
/// signed call. Nothing else is served: an authenticated `key_row` and
/// every write wait for the renewal.
#[test]
fn an_expired_lease_answers_the_unauthenticated_key_row_marked_and_serves_nothing_else() {
    let u = born();
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![principal(1).into(), key(K, 2).into()],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    let before = changes(&u);
    let a = key_row(&u, CallKind::Request, false, NOW);
    let UnitAnswer::Ok { body, .. } = &a else {
        panic!("{a:?}")
    };
    assert_eq!(body["lease_expired"], json!(true), "{body}");
    assert_eq!(body["key"]["access_key_id"], json!(K), "{body}");
    assert_eq!(body["state"]["tenant_state"], json!("active"), "{body}");
    assert_eq!(changes(&u), before, "read-only");

    // Signed, or not a request: the renewal first.
    assert!(renew_needed(None)(&key_row(
        &u,
        CallKind::Request,
        true,
        NOW
    )));
    assert!(renew_needed(None)(&key_row(&u, CallKind::Job, false, NOW)));
    // A write in the same state is refused and writes nothing.
    let seqs = u.head().unwrap().seqs;
    let write = UnitOp::Request {
        call: Box::new(RequestCall::abort_upload {
            bucket: BucketId::new(B1),
            key: "k".into(),
            upload: UploadId::new("u_00000000000000e1"),
            now: NOW,
        }),
    };
    let a = u.handle(&call(CallKind::Request, Some(seqs), true, write), NOW);
    assert!(renew_needed(None)(&a), "{a:?}");
    assert_eq!(changes(&u), before, "nothing written");

    // After a renewal the same read is served as usual, not marked.
    assert!(matches!(renew(&u, NOW), UnitAnswer::Ok { .. }));
    let a = key_row(&u, CallKind::Request, false, NOW);
    let UnitAnswer::Ok { body, .. } = &a else {
        panic!("{a:?}")
    };
    assert_eq!(body["lease_expired"], json!(false), "{body}");
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
                entries: vec![principal(1).into(), key(K, 2).into()],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        sync(&u, 3, None, &[B1], NOW),
        UnitAnswer::Ok { .. }
    ));
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
            entries: vec![key(GONE, 3).into()],
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
    assert!(matches!(
        sync(&u, 3, None, &[B1], NOW),
        UnitAnswer::Ok { .. }
    ));
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
        sync(&u, 4, Some(4), &[B1], UnixMs(NOW.0 + 1_000)),
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
    // The revocations a refused renewal listed are kept all the same.
    let mut p = proven(&u, 1);
    p.stamp_counter = Some(1);
    let a = worker(&u, renew_op(NOW, p, &[GONE]), NOW);
    assert!(renew_needed(Some(LeaseRefusal::RolledBack))(&a), "{a:?}");
    assert!(store::holds_revoked(u.sql(), GONE).unwrap());
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
                entries: vec![principal(1).into()],
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

fn request_call(call: RequestCall) -> UnitOp {
    UnitOp::Request {
        call: Box::new(call),
    }
}

/// AM-48: an S3 request call that changed a row (L1-5, `Unit::request`)
/// makes the raise due like a job's; a read and a refused write do not.
#[test]
fn a_request_write_makes_the_raise_due_and_a_read_or_a_refusal_does_not() {
    let u = fresh();
    let _ = u.take_wake();
    let read = request_call(RequestCall::live_generation {
        bucket: BucketId::new(B1),
        key: "k".into(),
    });
    assert!(matches!(
        request(&u, true, read, NOW),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(lease_row(&u).first_write_at, None);
    assert_eq!(u.take_wake(), None);
    // Out of bounds: refused before it runs.
    let refused = request_call(RequestCall::raise_floor {
        bucket: BucketId::new(B1),
        key: "k".repeat(2_000),
        id: velmora_bridge::GenerationId::new("g_0019a00000000e1e1e1e1e1e1e1e2"),
        generation: true,
    });
    assert!(matches!(
        request(&u, true, refused, NOW),
        UnitAnswer::Refused { .. }
    ));
    assert_eq!(lease_row(&u).first_write_at, None);
    assert_eq!(u.take_wake(), None);
    // A floor: a write.
    let write = request_call(RequestCall::raise_floor {
        bucket: BucketId::new(B1),
        key: "k".into(),
        id: velmora_bridge::GenerationId::new("g_0019a00000000e1e1e1e1e1e1e1e2"),
        generation: true,
    });
    let a = request(&u, true, write, NOW);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(lease_row(&u).first_write_at, Some(NOW));
    assert_eq!(u.take_wake(), Some(UnixMs(NOW.0 + PERIOD)));
}

/// AM-48: a `bucket_close` that marked the bucket makes the raise due; a
/// refused one (the bucket holds data) does not.
#[test]
fn a_bucket_close_makes_the_raise_due_and_a_refused_one_does_not() {
    let u = fresh();
    let _ = u.take_wake();
    let close = || {
        worker(
            &u,
            UnitOp::BucketClose {
                bucket_id: B1.into(),
            },
            NOW,
        )
    };
    assert!(matches!(close(), UnitAnswer::Refused { .. }), "B1 holds k");
    assert_eq!(lease_row(&u).first_write_at, None);
    assert_eq!(u.take_wake(), None);
    u.sql()
        .apply(&format!(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('{B2}', 'beta', 'o', x'02', 1, 1);"
        ))
        .unwrap();
    let a = worker(
        &u,
        UnitOp::BucketClose {
            bucket_id: B2.into(),
        },
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(lease_row(&u).first_write_at, Some(NOW));
    assert_eq!(u.take_wake(), Some(UnixMs(NOW.0 + PERIOD)));
}

/// A fresh unit holding the principal `P` (its owner ref `member-1`).
fn fresh_with_principal() -> Unit<RusqliteSql> {
    let u = fresh();
    let a = worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 0,
            entries: vec![principal(1).into()],
            answers: vec![],
        },
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    renew(&u, NOW);
    let _ = u.take_wake();
    u
}

/// The six reservation calls of #231, each asking for something new.
fn reservation_calls() -> Vec<UnitOp> {
    use velmora_bridge::unit::reserve::{Acting, Hash32, Opening, Rid};
    vec![
        UnitOp::Reserve {
            key_hash: Hash32([1; 32]),
            fingerprint: Hash32([1; 32]),
            rid: Rid([1; 16]),
            acting: Some(Acting::OwnerRef("member-1".into())),
            opening: Opening::Key {
                kind: KeyKind::S3,
                id: "AKWIRE00000000000007".into(),
                grants: vec![],
            },
        },
        UnitOp::ResolveActing {
            acting: Acting::OwnerRef("member-1".into()),
        },
        UnitOp::Release { rid: Rid([1; 16]) },
        UnitOp::BindBucket {
            rid: Rid([1; 16]),
            expected: None,
            grant_seq: 1,
        },
        UnitOp::ReleaseBound {
            rid: Rid([1; 16]),
            bound: None,
        },
        UnitOp::BucketBinding { grant_seq: 1 },
    ]
}

fn reservations(u: &Unit<RusqliteSql>) -> i64 {
    u.sql()
        .with_conn(|c| c.query_row("SELECT count(*) FROM unit_reservations", [], |r| r.get(0)))
        .unwrap()
}

/// AM-48: a reservation call that writes makes the alarm's raise due, as
/// an S3 write does; the first one asks for the alarm.
#[test]
fn a_reservation_makes_the_raise_due() {
    let u = fresh_with_principal();
    assert_eq!(lease_row(&u).first_write_at, None);
    let reserve = reservation_calls().remove(0);
    let a = worker(&u, reserve, NOW);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(reservations(&u), 1);
    assert_eq!(lease_row(&u).first_write_at, Some(NOW));
    assert_eq!(u.take_wake(), Some(UnixMs(NOW.0 + PERIOD)));
    // The release writes too, and the first write stays the first.
    let later = UnixMs(NOW.0 + 1_000);
    let a = worker(&u, reservation_calls().remove(2), later);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(lease_row(&u).first_write_at, Some(NOW));
    assert_eq!(u.take_wake(), None);
    // `resolve_acting` is a read: no raise due.
    let u = fresh_with_principal();
    let a = worker(&u, reservation_calls().remove(1), NOW);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(lease_row(&u).first_write_at, None);
    assert_eq!(u.take_wake(), None);
    // `bucket_binding` of a grant nothing is bound to writes its fence
    // (a later bind of that grant is refused): that write counts.
    let a = worker(&u, reservation_calls().remove(5), NOW);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(lease_row(&u).first_write_at, Some(NOW));
    assert_eq!(u.take_wake(), Some(UnixMs(NOW.0 + PERIOD)));
}

/// Rule 12 holds for the reservation calls: on an open unit with an
/// expired lease each one answers `renew_needed` and writes nothing
/// (they run after the lease check).
#[test]
fn an_expired_lease_refuses_every_reservation_call_and_writes_nothing() {
    let u = fresh_with_principal();
    let late = UnixMs(NOW.0 + T + 1);
    for op in reservation_calls() {
        let before = changes(&u);
        let a = worker(&u, op.clone(), late);
        assert!(renew_needed(None)(&a), "{op:?}: {a:?}");
        assert_eq!(changes(&u), before, "{op:?}");
    }
    assert_eq!(reservations(&u), 0);
    assert_eq!(lease_row(&u).first_write_at, None);
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
        u.alarm_done(early, &step, &AlarmSent::all(&step, true))
            .unwrap(),
        Some(UnixMs(NOW.0 + PERIOD))
    );
    let due = UnixMs(NOW.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    assert!(step.raise);
    assert_eq!(step.jobs, vec![job_text(UnitJobKind::StampRaise, &u, due)]);
    // Sent, the raise stays pending until its stamp lands (AM-48): the
    // alarm looks again one period on.
    assert_eq!(
        u.alarm_done(due, &step, &AlarmSent::all(&step, true))
            .unwrap(),
        Some(UnixMs(due.0 + PERIOD)),
        "the pending raise is looked at again"
    );
    let row = lease_row(&u);
    assert_eq!((row.first_write_at, row.raise_from), (None, Some(due)));
    assert_eq!((row.renew_tries, row.failed_runs), (0, 0));
    // The raise lands: nothing is pending, and the unit is idle again.
    let landed = UnixMs(due.0 + 500);
    assert!(matches!(
        job(
            &u,
            JobCall::stamp_advance {
                from: None,
                catalogue: stamp_id()
            },
            landed
        ),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(lease_row(&u).raise_from, None);
    let later = UnixMs(due.0 + PERIOD);
    let step = u.alarm(later).unwrap();
    assert!(step.jobs.is_empty() && !step.raise);
    assert_eq!(
        u.alarm_done(later, &step, &AlarmSent::all(&step, true))
            .unwrap(),
        None,
        "idle again"
    );
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
    let next = u
        .alarm_done(due, &step, &AlarmSent::all(&step, true))
        .unwrap()
        .unwrap();
    assert_eq!(next.0, due.0 + AlarmRules::DEFAULT.renew_retry_ms);
    let row = lease_row(&u);
    assert_eq!(row.renew_tries, 1);
    assert_eq!(row.first_write_at, Some(NOW), "the work stays due");
    // The second try waits twice as long.
    let step = u.alarm(next).unwrap();
    assert_eq!(step.jobs, vec![job_text(UnitJobKind::Renew, &u, next)]);
    let next2 = u
        .alarm_done(next, &step, &AlarmSent::all(&step, true))
        .unwrap()
        .unwrap();
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
    let next = u
        .alarm_done(due, &step, &AlarmSent::all(&step, false))
        .unwrap()
        .unwrap();
    let row = lease_row(&u);
    assert_eq!(row.first_write_at, Some(NOW), "still due");
    assert_eq!(row.failed_runs, 1);
    assert!(next.0 >= due.0 + MIN_ALARM_GAP_MS);
    // A run in which everything was sent resets the count (renewed
    // first: by now less than half of T is left).
    assert!(matches!(renew(&u, next), UnitAnswer::Ok { .. }));
    let step = u.alarm(next).unwrap();
    assert!(step.raise);
    u.alarm_done(next, &step, &AlarmSent::all(&step, true))
        .unwrap();
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
    let next = u
        .alarm_done(due, &step, &AlarmSent::all(&step, true))
        .unwrap()
        .unwrap();
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
    // The pending raise is looked at one period after its hand-out, the
    // write during the send one period after the write: the earlier.
    assert_eq!(
        u.alarm_done(during, &step, &AlarmSent::all(&step, true))
            .unwrap(),
        Some(UnixMs(due.0 + PERIOD))
    );
    assert_eq!(lease_row(&u).first_write_at, Some(during));
    assert_eq!(lease_row(&u).raise_from, Some(due));

    // The renew the alarm sends lands before the run is recorded.
    let late = UnixMs(during.0 + PERIOD + 1);
    assert!(late.0 > NOW.0 + T, "the lease has run out");
    let step = u.alarm(late).unwrap();
    assert!(step.run.send_renew);
    assert!(matches!(renew(&u, late), UnitAnswer::Ok { .. }));
    u.alarm_done(late, &step, &AlarmSent::all(&step, true))
        .unwrap();
    assert_eq!(lease_row(&u).renew_tries, 0);
}

/// The alarm hands out the unit's due work (AM-49): a due outbox row is
/// a job of the step, marked only once its send went through; with an
/// expired lease nothing is handed out, only `renew`.
#[test]
fn the_alarm_hands_out_due_rows_and_marks_only_what_was_sent() {
    use velmora_bridge::unit_lease::alarm::Duty;
    let u = fresh();
    let at = UnixMs(NOW.0 + 1_000);
    u.sql()
        .with_conn(|c| {
            c.execute_batch(&format!(
                "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
                   VALUES ('x_000000000000000000000000e1', 'g_0019a00000000e1e1e1e1e1e1e1e1', \
                           'post', {}, 1)",
                at.0
            ))
        })
        .unwrap();
    let sent_at = |u: &Unit<RusqliteSql>| -> Option<i64> {
        u.sql()
            .with_conn(|c| c.query_row("SELECT sent_at FROM outbox", [], |r| r.get(0)))
            .unwrap()
    };
    // Due at the row's time: the step carries its job.
    let step = u.alarm(at).unwrap();
    assert!(step.run.run.contains(&Duty::HandOut), "{:?}", step.run);
    assert_eq!(step.handout.jobs.len(), 1);
    assert_eq!(step.seqs, u.head().unwrap().seqs);
    // Its send was refused: not marked, a failed run, due again.
    let mut sent = AlarmSent::all(&step, true);
    sent.handed_out = vec![false];
    let next = u.alarm_done(at, &step, &sent).unwrap();
    assert_eq!(sent_at(&u), None);
    assert_eq!(lease_row(&u).failed_runs, 1);
    let next = next.expect("due again");
    assert!(next.0 > at.0);
    // Sent: marked, and nothing else is due before its resend window.
    let step = u.alarm(next).unwrap();
    assert_eq!(step.handout.jobs.len(), 1);
    let after = u
        .alarm_done(next, &step, &AlarmSent::all(&step, true))
        .unwrap();
    assert_eq!(sent_at(&u), Some(next.0));
    assert_eq!(lease_row(&u).failed_runs, 0);
    let resend = i64::from(velmora_bridge::jobs::RESEND_SECS) * 1000;
    assert_eq!(after, Some(UnixMs(next.0 + resend)));
    // With the lease run out the row is due, but only `renew` is sent.
    let late = UnixMs(next.0 + resend);
    assert!(late.0 > NOW.0 + T);
    let step = u.alarm(late).unwrap();
    assert!(step.handout.jobs.is_empty());
    assert!(step.run.send_renew);
}

/// A tenant that is being shredded takes no job: nothing is handed out,
/// whatever its outbox holds (review LOW 2).
#[test]
fn a_shredding_tenant_hands_out_nothing() {
    let u = fresh();
    u.sql()
        .with_conn(|c| {
            c.execute_batch(&format!(
                "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
                   VALUES ('x_000000000000000000000000e1', 'g_0019a00000000e1e1e1e1e1e1e1e1', \
                           'post', {}, 1)",
                NOW.0
            ))
        })
        .unwrap();
    let at = UnixMs(NOW.0 + 1_000);
    assert!(!u.alarm(at).unwrap().handout.jobs.is_empty());
    let u = fresh();
    u.sql()
        .with_conn(|c| {
            c.execute_batch(&format!(
                "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
                   VALUES ('x_000000000000000000000000e1', 'g_0019a00000000e1e1e1e1e1e1e1e1', \
                           'post', {}, 1); \
                 UPDATE unit_head SET tenant_state = 'shredding'",
                NOW.0
            ))
        })
        .unwrap();
    let step = u.alarm(at).unwrap();
    assert!(step.handout.jobs.is_empty());
    assert!(step.run.run.is_empty(), "{:?}", step.run);
}

/// A revoked principal counts like a revoked key (AM-72): its revoke puts
/// `m/rk/<t>/<p_id>` first, so the listing the proof compares with names
/// it too.
#[test]
fn a_revoked_principal_is_counted() {
    let u = born();
    let mut gone = principal(1);
    gone.status = SubjectStatus::Revoked;
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![gone.into()],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(status_of(&u, P), "revoked");
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(1));
    assert!(matches!(
        sync(&u, 3, None, &[B1], NOW),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        worker(&u, renew_op(NOW, proven(&u, 0), &[]), NOW),
        UnitAnswer::Ok { .. }
    ));
}

/// A principal revoked by the key chain already satisfies its listed revocation.
#[test]
fn a_recorded_principal_revocation_allows_renewal() {
    let u = born();
    let mut gone = listed_principal(1);
    gone.status = SubjectStatus::Revoked;
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![gone.into()],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(status_of(&u, LISTED_P), "revoked");
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(1));
    assert!(matches!(
        sync(&u, 3, None, &[B1], NOW),
        UnitAnswer::Ok { .. }
    ));
    let a = worker(&u, renew_op(NOW, proven(&u, 1), &[LISTED_P]), NOW);
    assert!(
        matches!(&a, UnitAnswer::Ok { body, .. } if body["applied"] == json!(0)),
        "{a:?}"
    );
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(1));
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
        u.alarm_done(UnixMs(NOW.0 + 1_000), &step, &AlarmSent::all(&step, true))
            .unwrap(),
        None
    );
    assert_eq!(u.mark(), m, "an idle wake");

    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    let due = UnixMs(NOW.0 + PERIOD);
    let _dead = u.alarm(due).unwrap();
    assert!(matches!(
        sync(&u, 4, Some(4), &[B1], due),
        UnitAnswer::Ok { .. }
    ));
    let m = u.mark();
    let later = UnixMs(due.0 + 1_000);
    let step = u.alarm(later).unwrap();
    assert!(step.jobs.is_empty());
    assert_eq!(
        u.alarm_done(later, &step, &AlarmSent::all(&step, true))
            .unwrap(),
        None
    );
    assert_eq!(u.mark(), m, "a closed wake, even with a dead run's raise");
}

/// A raise that never lands (the run died during its send, the message
/// was lost, or it was acknowledged unrun) is pending for one period
/// after its hand-out, then sent again (AM-48, AM-50).
#[test]
fn a_raise_that_does_not_land_is_sent_again_one_period_on() {
    let u = fresh();
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    let due = UnixMs(NOW.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    assert!(step.raise);
    assert_eq!(step.covered, Some(NOW));
    assert_eq!(lease_row(&u).raise_from, Some(due), "the hand-out time");
    // No `alarm_done`: the platform runs the alarm again. Within the
    // period the raise is pending, not sent again.
    let again = UnixMs(due.0 + 1_000);
    assert!(matches!(renew(&u, again), UnitAnswer::Ok { .. }));
    let step = u.alarm(again).unwrap();
    assert!(!step.raise, "still in flight");
    assert_eq!(lease_row(&u).raise_from, Some(due));
    // One period on it is dead: due again, and sent.
    let dead = UnixMs(due.0 + PERIOD);
    let step = u.alarm(dead).unwrap();
    assert!(step.raise, "the raise is due again");
    assert_eq!(lease_row(&u).raise_from, Some(dead));
    u.alarm_done(dead, &step, &AlarmSent::all(&step, true))
        .unwrap();
    // A failed send undoes the hand-out: the writes it covered are
    // pending again from their own time, not the hand-out's.
    let u = fresh();
    assert!(matches!(
        request(&u, true, read_plan(), NOW),
        UnitAnswer::Ok { .. }
    ));
    let step = u.alarm(due).unwrap();
    assert!(step.raise);
    u.alarm_done(due, &step, &AlarmSent::all(&step, false))
        .unwrap();
    let row = lease_row(&u);
    assert_eq!((row.first_write_at, row.raise_from), (Some(NOW), None));
}

/// A listed id that names a principal row (were one ever listed) is kept
/// as a revocation of that row (AM-72): the principal is revoked, and the
/// count and the check agree with the listing.
#[test]
fn a_listed_id_of_a_principal_row_revokes_it_and_counts_once() {
    let u = born();
    let mut p = principal(1);
    p.id = "PWIRE0000000000001".into();
    assert!(matches!(
        worker(
            &u,
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![p.into()],
                answers: vec![],
            },
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        sync(&u, 3, None, &[B1], NOW),
        UnitAnswer::Ok { .. }
    ));
    let a = worker(
        &u,
        renew_op(NOW, proven(&u, 1), &["PWIRE0000000000001"]),
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(status_of(&u, "PWIRE0000000000001"), "revoked");
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(1));
}

/// Renewal applies an unrecorded principal revocation, removing its key's
/// effective grant without revoking the key itself.
#[test]
fn renewal_removes_a_listed_principals_key_grants() {
    let u = born();
    let a = worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 0,
            entries: vec![listed_principal(1).into(), listed_principals_key(2).into()],
            answers: vec![],
        },
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert!(matches!(
        sync(&u, 3, None, &[B1], NOW),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(status_of(&u, LISTED_P), "active");
    assert_eq!(status_of(&u, K), "active");
    assert_eq!(effective_grants_for(&u, K), 1);
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(0));

    let grant = || {
        u.handle(
            &call(
                CallKind::Request,
                Some(u.head().unwrap().seqs),
                true,
                request_call(RequestCall::grant {
                    akid: K.into(),
                    bucket: BucketId::new(B1),
                }),
            ),
            NOW,
        )
    };
    assert!(matches!(renew(&u, NOW), UnitAnswer::Ok { .. }));
    assert_eq!(
        grant(),
        UnitAnswer::Ok {
            seqs: u.head().unwrap().seqs,
            body: json!(velmora_bridge::Perm::Ro),
        }
    );

    let a = worker(&u, renew_op(NOW, proven(&u, 1), &[LISTED_P]), NOW);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(status_of(&u, LISTED_P), "revoked");
    assert_eq!(status_of(&u, K), "active");
    assert_eq!(effective_grants_for(&u, K), 0);
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(1));
    assert_eq!(
        grant(),
        UnitAnswer::Ok {
            seqs: u.head().unwrap().seqs,
            body: json!(null),
        }
    );
}

/// A principal listed before its row exists stays revoked when the key chain
/// later supplies it as active. Its key gains no effective grants, and the
/// request for its grant on the bucket returns null.
#[test]
fn a_listed_principal_stays_revoked_when_its_records_arrive() {
    let u = born();
    assert_eq!(store::revoked(u.sql()).unwrap(), None);
    let a = worker(&u, renew_op(NOW, proven(&u, 1), &[LISTED_P]), NOW);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    let kept: bool = u.sql().with_conn(|c| {
        c.query_row(
            "SELECT EXISTS (SELECT 1 FROM unit_revoked_ids WHERE id = ?1)",
            [LISTED_P],
            |r| r.get(0),
        )
        .unwrap()
    });
    assert!(
        kept,
        "the revocation is stored before the principal arrives"
    );

    let a = worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 0,
            entries: vec![listed_principal(1).into(), listed_principals_key(2).into()],
            answers: vec![],
        },
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert_eq!(status_of(&u, LISTED_P), "revoked");
    assert_eq!(status_of(&u, K), "active");
    assert_eq!(effective_grants_for(&u, K), 0);
    assert_eq!(store::revoked(u.sql()).unwrap(), Some(1));

    let seqs = u.head().unwrap().seqs;
    assert_eq!(
        u.handle(
            &call(
                CallKind::Request,
                Some(seqs),
                true,
                request_call(RequestCall::grant {
                    akid: K.into(),
                    bucket: BucketId::new(B1),
                }),
            ),
            NOW,
        ),
        UnitAnswer::Ok {
            seqs,
            body: json!(null),
        }
    );
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
    // One raw batch per queue; never `send_batch`, which would encode
    // the messages through `serde_wasm_bindgen`.
    assert!(src.contains(".send_raw_batch(messages)"));
    assert!(!src.contains(".send_batch("));
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
    assert!(matches!(
        sync(&u, 4, Some(4), &[B1], NOW),
        UnitAnswer::Ok { .. }
    ));
    let due = UnixMs(NOW.0 + PERIOD);
    let step = u.alarm(due).unwrap();
    assert!(step.jobs.is_empty() && !step.run.send_renew);
    assert_eq!(
        u.alarm_done(due, &step, &AlarmSent::all(&step, true))
            .unwrap(),
        None
    );

    let unborn = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    let step = unborn.alarm(due).unwrap();
    assert!(step.jobs.is_empty());
    assert_eq!(
        unborn
            .alarm_done(due, &step, &AlarmSent::all(&step, true))
            .unwrap(),
        None
    );
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
