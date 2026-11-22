//! The unit's key-chain apply (AM-12, the effective grant) and the owner
//! move's import (DS1 §2.3), on the native database. `workers/unit-suite`
//! runs this file against a Durable Object too.

use serde_json::json;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::call::HoldMode;
use velmora_bridge::unit::identity::Refusal;
use velmora_bridge::unit::import::{
    ImportBatch, ImportRefusal, ImportTable, ImportValue, MoveHead, MAX_ROWS,
};
use velmora_bridge::unit::keys::{
    Access, ApplyEntry, KeyEntry, KeyGrant, KeyKind, KeyMarker, KeyRefusal, MarkerKind,
    SubjectStatus,
};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::{SqlValue, UnixMs};

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const B1: &str = "b_00000000000000d1";
const B2: &str = "b_00000000000000d2";
const P: &str = "p_owner";
const K: &str = "AKKEYS00000000000001";

fn tenant() -> TenantId {
    TenantId::parse("t_0000000000000d01").unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
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

fn seqs(state_seq: u64, keys_seq: u64) -> Option<Seqs> {
    Some(Seqs {
        state_seq,
        keys_seq,
    })
}

fn worker(u: &Unit<RusqliteSql>, op: UnitOp) -> UnitAnswer {
    u.handle(&call(CallKind::Worker, None, op), NOW)
}

fn sync(
    u: &Unit<RusqliteSql>,
    state_seq: u64,
    keys_seq: u64,
    restoring: Option<u64>,
) -> UnitAnswer {
    worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                seqs: Seqs {
                    state_seq,
                    keys_seq,
                },
                tenant_state: TenantState::Active,
                tenant_mode: None::<HoldMode>,
                restoring_since: restoring,
                lift: None,
            },
        },
    )
}

/// A born, active unit at seq 3 with bucket B1 (B2 is not this unit's).
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
            seqs(3, 0),
            UnitOp::Provision {
                token,
                sealed: b"sealed".to_vec(),
            },
        ),
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert!(matches!(sync(&u, 3, 0, None), UnitAnswer::Ok { .. }));
    u.sql()
        .apply(&format!(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('{B1}', 'alpha', 'o', x'02', 1, 1);"
        ))
        .unwrap();
    u
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

fn principal(seq: u64, status: SubjectStatus, grants: Vec<KeyGrant>) -> KeyEntry {
    KeyEntry {
        id: P.into(),
        kind: KeyKind::Principal,
        status,
        held: false,
        made_by: None,
        grants,
        created_at: 1,
        secret_wrapped: None,
        secret_kek_version: None,
        owner_ref: Some("member-1".into()),
        last_seq: seq,
        rid: None,
    }
}

fn key(seq: u64, status: SubjectStatus, grants: Vec<KeyGrant>) -> KeyEntry {
    KeyEntry {
        id: K.into(),
        kind: KeyKind::S3,
        status,
        held: false,
        made_by: Some(P.into()),
        grants,
        created_at: 2,
        secret_wrapped: Some(vec![2, 0xaa, 0xbb]),
        secret_kek_version: Some(1),
        owner_ref: Some("member-1".into()),
        last_seq: seq,
        rid: None,
    }
}

fn apply(u: &Unit<RusqliteSql>, from_seq: u64, entries: Vec<KeyEntry>) -> UnitAnswer {
    worker(
        u,
        UnitOp::ApplyKeys {
            from_seq,
            entries: entries.into_iter().map(Into::into).collect(),
            answers: vec![],
        },
    )
}

fn keys_seq(u: &Unit<RusqliteSql>) -> u64 {
    u.head().unwrap().seqs.keys_seq
}

/// The key's served grants: (bucket, perm), and whether its row is served.
fn served(u: &Unit<RusqliteSql>, id: &str) -> (bool, Vec<(String, String)>) {
    u.sql()
        .with_conn(|c| {
            let row: i64 = c.query_row(
                "SELECT count(*) FROM access_keys WHERE access_key_id = ?1 AND status = 'active'",
                [id],
                |r| r.get(0),
            )?;
            let mut st = c.prepare(
                "SELECT bucket_id, perm FROM grants WHERE access_key_id = ?1 ORDER BY bucket_id",
            )?;
            let grants = st
                .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, rusqlite::Error>((row == 1, grants))
        })
        .unwrap()
}

fn status_of(u: &Unit<RusqliteSql>, id: &str) -> String {
    u.sql()
        .with_conn(|c| {
            c.query_row("SELECT status FROM unit_keys WHERE id = ?1", [id], |r| {
                r.get(0)
            })
        })
        .unwrap()
}

fn ok_body(a: UnitAnswer) -> serde_json::Value {
    match a {
        UnitAnswer::Ok { body, .. } => body,
        other => panic!("not ok: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The key-chain apply (AM-12)
// ---------------------------------------------------------------------------

#[test]
fn an_apply_writes_the_keys_moves_keys_seq_and_lets_sync_pass() {
    let u = born();
    // Before the apply a sync with a higher keys_seq is refused.
    assert!(matches!(
        sync(&u, 3, 2, None),
        UnitAnswer::Refused {
            reason: Refused::KeysNotApplied,
            ..
        }
    ));
    let body = ok_body(apply(
        &u,
        0,
        vec![
            principal(1, SubjectStatus::Active, vec![grant(B1, Access::Rw)]),
            key(2, SubjectStatus::Active, vec![grant(B1, Access::Ro)]),
        ],
    ));
    assert_eq!(body["applied"], json!(2));
    assert_eq!(body["revoked"], json!(0));
    assert_eq!(keys_seq(&u), 2);
    assert_eq!(served(&u, K), (true, vec![(B1.into(), "ro".into())]));
    // The principal has no secret: never a served key row.
    assert_eq!(served(&u, P), (false, vec![]));
    assert!(matches!(sync(&u, 3, 2, None), UnitAnswer::Ok { .. }));
    // The key row reaches the S3 path through the catalogue's own code.
    let a = u.handle(
        &call(
            CallKind::Request,
            seqs(3, 2),
            UnitOp::KeyRow {
                access_key_id: K.into(),
            },
        ),
        NOW,
    );
    let body = ok_body(a);
    assert_eq!(body["key"]["access_key_id"], json!(K));
    assert_eq!(body["key"]["principal"], json!(P));
}

#[test]
fn a_base_above_the_units_keys_seq_is_behind_and_writes_nothing() {
    let u = born();
    let a = apply(&u, 4, vec![key(5, SubjectStatus::Active, vec![])]);
    assert_eq!(
        a,
        UnitAnswer::KeysBehind {
            seqs: Seqs {
                state_seq: 3,
                keys_seq: 0
            }
        }
    );
    assert_eq!(keys_seq(&u), 0);
    assert_eq!(served(&u, K), (false, vec![]));
}

#[test]
fn a_gap_or_a_malformed_entry_is_refused_and_nothing_is_kept() {
    let u = born();
    let gap = apply(
        &u,
        0,
        vec![
            principal(1, SubjectStatus::Active, vec![grant(B1, Access::Rw)]),
            key(3, SubjectStatus::Active, vec![grant(B1, Access::Ro)]),
        ],
    );
    assert!(matches!(
        gap,
        UnitAnswer::Refused {
            reason: Refused::Keys(KeyRefusal::Gap),
            ..
        }
    ));
    let mut bad = principal(1, SubjectStatus::Active, vec![]);
    bad.secret_wrapped = Some(vec![1]);
    bad.secret_kek_version = Some(1);
    let mut open_without_secret = key(2, SubjectStatus::Active, vec![]);
    open_without_secret.secret_wrapped = None;
    open_without_secret.secret_kek_version = None;
    for entries in [
        vec![bad],
        vec![
            principal(1, SubjectStatus::Active, vec![]),
            open_without_secret,
        ],
    ] {
        assert!(matches!(
            apply(&u, 0, entries),
            UnitAnswer::Refused {
                reason: Refused::Keys(KeyRefusal::Malformed),
                ..
            }
        ));
    }
    assert_eq!(keys_seq(&u), 0);
    let rows: i64 = u
        .sql()
        .with_conn(|c| c.query_row("SELECT count(*) FROM unit_keys", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(rows, 0);
}

fn marker(kind: MarkerKind, seq: u64) -> ApplyEntry {
    ApplyEntry::Marker(KeyMarker { marker: kind, seq })
}

fn apply_items(u: &Unit<RusqliteSql>, from_seq: u64, entries: Vec<ApplyEntry>) -> UnitAnswer {
    worker(
        u,
        UnitOp::ApplyKeys {
            from_seq,
            entries,
            answers: vec![],
        },
    )
}

fn key_rows(u: &Unit<RusqliteSql>) -> i64 {
    u.sql()
        .with_conn(|c| c.query_row("SELECT count(*) FROM unit_keys", [], |r| r.get(0)))
        .unwrap()
}

/// AM-62: a record that changes no subject (`KeysFrozen`, `KeysThawed`)
/// comes as a marker item. It counts in the gap rule, writes no row, is
/// counted as skipped, and `keys_seq` moves past it.
#[test]
fn a_marker_counts_in_the_gap_rule_writes_no_row_and_moves_keys_seq() {
    let u = born();
    let body = ok_body(apply_items(
        &u,
        0,
        vec![
            principal(1, SubjectStatus::Active, vec![grant(B1, Access::Rw)]).into(),
            marker(MarkerKind::KeysFrozen, 2),
            key(3, SubjectStatus::Active, vec![grant(B1, Access::Ro)]).into(),
            marker(MarkerKind::KeysThawed, 4),
        ],
    ));
    assert_eq!(body["applied"], json!(2));
    assert_eq!(body["skipped"], json!(2));
    assert_eq!(keys_seq(&u), 4);
    assert_eq!(key_rows(&u), 2);
    assert_eq!(served(&u, K), (true, vec![(B1.into(), "ro".into())]));
    // A page of a marker alone moves keys_seq and writes no key row, so
    // the next page's base (the marker's seq) is not above the unit's:
    // a frozen chain is never answered `Behind` for ever (L4 #234 r1 M3).
    let body = ok_body(apply_items(&u, 4, vec![marker(MarkerKind::KeysFrozen, 5)]));
    assert_eq!(
        (body["applied"].clone(), body["skipped"].clone()),
        (json!(0), json!(1))
    );
    assert_eq!(keys_seq(&u), 5);
    assert_eq!(key_rows(&u), 2);
    let body = ok_body(apply_items(
        &u,
        5,
        vec![key(6, SubjectStatus::Revoked, vec![]).into()],
    ));
    assert_eq!(body["applied"], json!(1));
    assert_eq!(keys_seq(&u), 6);
    assert_eq!(status_of(&u, K), "revoked");
    // A marker sent again at or below keys_seq changes nothing.
    let body = ok_body(apply_items(&u, 4, vec![marker(MarkerKind::KeysFrozen, 5)]));
    assert_eq!(body["skipped"], json!(1));
    assert_eq!(keys_seq(&u), 6);
}

#[test]
fn a_marker_out_of_its_seq_is_a_gap_and_nothing_is_kept() {
    let u = born();
    for entries in [
        // The marker skips seq 2.
        vec![
            principal(1, SubjectStatus::Active, vec![]).into(),
            marker(MarkerKind::KeysFrozen, 3),
        ],
        // The marker repeats seq 1.
        vec![
            principal(1, SubjectStatus::Active, vec![]).into(),
            marker(MarkerKind::KeysThawed, 1),
        ],
        // An entry after a marker skips a seq.
        vec![
            marker(MarkerKind::KeysFrozen, 1),
            key(3, SubjectStatus::Active, vec![]).into(),
        ],
    ] {
        assert!(matches!(
            apply_items(&u, 0, entries),
            UnitAnswer::Refused {
                reason: Refused::Keys(KeyRefusal::Gap),
                ..
            }
        ));
    }
    assert_eq!(keys_seq(&u), 0);
    assert_eq!(key_rows(&u), 0);
    // Above MAX_ENTRIES items, markers included: malformed.
    let many: Vec<ApplyEntry> = (1..=101)
        .map(|n| marker(MarkerKind::KeysFrozen, n))
        .collect();
    assert!(matches!(
        apply_items(&u, 0, many),
        UnitAnswer::Refused {
            reason: Refused::Keys(KeyRefusal::Malformed),
            ..
        }
    ));
    assert_eq!(keys_seq(&u), 0);
}

#[test]
fn a_marker_reads_back_from_its_json_and_takes_nothing_else() {
    let c = call(
        CallKind::Worker,
        None,
        UnitOp::ApplyKeys {
            from_seq: 1,
            entries: vec![
                marker(MarkerKind::KeysFrozen, 2),
                marker(MarkerKind::KeysThawed, 3),
            ],
            answers: vec![],
        },
    );
    let text = serde_json::to_string(&c).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["op"]["entries"],
        json!([
            {"marker": "keys_frozen", "seq": 2},
            {"marker": "keys_thawed", "seq": 3},
        ])
    );
    assert_eq!(serde_json::from_str::<UnitCall>(&text).unwrap(), c);
    // A marker is exactly `marker` and `seq`; anything else is refused,
    // and so is an entry that carries `marker`.
    for bad in [
        json!({"marker": "keys_frozen", "seq": 2, "id": "AK"}),
        json!({"marker": "keys_opened", "seq": 2}),
        json!({"marker": "keys_frozen"}),
        json!({"seq": 2}),
    ] {
        let mut w = v.clone();
        w["op"]["entries"][0] = bad.clone();
        assert!(
            serde_json::from_value::<UnitCall>(w).is_err(),
            "{bad} was taken"
        );
    }
    let mut entry = serde_json::to_value(key(2, SubjectStatus::Active, vec![])).unwrap();
    entry["marker"] = json!("keys_frozen");
    let mut w = v.clone();
    w["op"]["entries"][0] = entry;
    assert!(serde_json::from_value::<UnitCall>(w).is_err());
}

#[test]
fn an_entry_at_or_below_its_rows_seq_is_skipped() {
    let u = born();
    ok_body(apply(
        &u,
        0,
        vec![
            principal(1, SubjectStatus::Active, vec![grant(B1, Access::Rw)]),
            key(2, SubjectStatus::Active, vec![grant(B1, Access::Rw)]),
        ],
    ));
    // The key is narrowed at 3.
    ok_body(apply(
        &u,
        2,
        vec![key(3, SubjectStatus::Active, vec![grant(B1, Access::Ro)])],
    ));
    // A caller that read from an older base sends seq 2 and 3 again: the
    // old seq-2 entry must not widen the key back.
    let body = ok_body(apply(
        &u,
        1,
        vec![
            key(2, SubjectStatus::Active, vec![grant(B1, Access::Rw)]),
            key(3, SubjectStatus::Active, vec![grant(B1, Access::Ro)]),
        ],
    ));
    assert_eq!(body["skipped"], json!(2));
    assert_eq!(keys_seq(&u), 3);
    assert_eq!(served(&u, K), (true, vec![(B1.into(), "ro".into())]));
}

#[test]
fn a_revocation_applies_whatever_its_seq_and_is_final() {
    let u = born();
    ok_body(apply(
        &u,
        0,
        vec![
            principal(1, SubjectStatus::Active, vec![grant(B1, Access::Rw)]),
            key(2, SubjectStatus::Active, vec![grant(B1, Access::Rw)]),
            key(3, SubjectStatus::Active, vec![grant(B1, Access::Ro)]),
        ],
    ));
    // A revoke of seq 3 sent again under an older base still revokes.
    let mut revoke = key(3, SubjectStatus::Revoked, vec![]);
    revoke.secret_wrapped = None;
    revoke.secret_kek_version = None;
    let body = ok_body(apply(&u, 2, vec![revoke]));
    assert_eq!(body["revoked"], json!(1));
    assert_eq!(status_of(&u, K), "revoked");
    assert_eq!(served(&u, K), (false, vec![]));
    // A later record that would make it active leaves it revoked.
    ok_body(apply(
        &u,
        3,
        vec![key(4, SubjectStatus::Active, vec![grant(B1, Access::Rw)])],
    ));
    assert_eq!(status_of(&u, K), "revoked");
    assert_eq!(served(&u, K), (false, vec![]));
    // A revocation of a subject the unit never held is kept as a row.
    let mut other = key(5, SubjectStatus::Revoked, vec![]);
    other.id = "AKKEYS00000000000009".into();
    other.secret_wrapped = None;
    other.secret_kek_version = None;
    ok_body(apply(&u, 4, vec![other]));
    assert_eq!(status_of(&u, "AKKEYS00000000000009"), "revoked");
}

#[test]
fn a_held_subject_is_not_served_until_the_same_seq_opens_it() {
    let u = born();
    ok_body(apply(
        &u,
        0,
        vec![principal(
            1,
            SubjectStatus::Active,
            vec![grant(B1, Access::Rw)],
        )],
    ));
    let mut closed = key(2, SubjectStatus::Active, vec![grant(B1, Access::Rw)]);
    closed.held = true;
    closed.secret_wrapped = None;
    closed.secret_kek_version = None;
    ok_body(apply(&u, 1, vec![closed.clone()]));
    assert_eq!(served(&u, K), (false, vec![]));
    let held = ok_body(worker(&u, UnitOp::HeldKeys {}));
    assert_eq!(held["held"], json!([K]));
    // The bring-up's second send: the same record, now opened.
    ok_body(apply(
        &u,
        1,
        vec![key(2, SubjectStatus::Active, vec![grant(B1, Access::Rw)])],
    ));
    assert_eq!(served(&u, K), (true, vec![(B1.into(), "rw".into())]));
    assert_eq!(ok_body(worker(&u, UnitOp::HeldKeys {}))["held"], json!([]));
    // The closed copy of the same seq does not close it again.
    let body = ok_body(apply(&u, 1, vec![closed]));
    assert_eq!(body["skipped"], json!(1));
    assert_eq!(served(&u, K), (true, vec![(B1.into(), "rw".into())]));
}

#[test]
fn the_served_grant_is_the_keys_own_inside_its_principals() {
    let u = born();
    u.sql()
        .apply(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('b_00000000000000d3', 'gamma', 'o', x'02', 1, 1);",
        )
        .unwrap();
    let b3 = "b_00000000000000d3";
    let mut narrow = grant(b3, Access::Ro);
    narrow.prefix = Some("photos/".into());
    ok_body(apply(
        &u,
        0,
        vec![
            principal(
                1,
                SubjectStatus::Active,
                vec![grant(B1, Access::Ro), grant(b3, Access::Rw)],
            ),
            // rw on B1 is wider than the principal's ro: lowered to ro;
            // B2 is not this unit's; the prefix grant on b3 cannot be
            // stated here.
            key(
                2,
                SubjectStatus::Active,
                vec![grant(B1, Access::Rw), grant(B2, Access::Ro), narrow],
            ),
        ],
    ));
    assert_eq!(served(&u, K), (true, vec![(B1.into(), "ro".into())]));
    ok_body(apply(
        &u,
        2,
        vec![key(
            3,
            SubjectStatus::Active,
            vec![grant(B1, Access::Ro), grant(b3, Access::Rw)],
        )],
    ));
    assert_eq!(
        served(&u, K),
        (
            true,
            vec![(B1.into(), "ro".into()), (b3.into(), "rw".into())]
        )
    );
    // The principal is disabled: its key is not served, though its own
    // record did not change.
    ok_body(apply(
        &u,
        3,
        vec![principal(
            4,
            SubjectStatus::Disabled,
            vec![grant(B1, Access::Ro)],
        )],
    ));
    assert_eq!(served(&u, K), (false, vec![]));
    // Enabled again, narrower: the key follows.
    ok_body(apply(
        &u,
        4,
        vec![principal(
            5,
            SubjectStatus::Active,
            vec![grant(B1, Access::Ro)],
        )],
    ));
    assert_eq!(served(&u, K), (true, vec![(B1.into(), "ro".into())]));
    // A key whose principal the unit does not hold is not served.
    let mut orphan = key(6, SubjectStatus::Active, vec![grant(B1, Access::Ro)]);
    orphan.id = "AKKEYS00000000000002".into();
    orphan.made_by = Some("p_missing".into());
    ok_body(apply(&u, 5, vec![orphan]));
    assert_eq!(served(&u, "AKKEYS00000000000002"), (false, vec![]));
}

#[test]
fn a_key_needs_its_principal_and_the_internal_key_is_not_served_here() {
    let u = born();
    let mut lone = key(1, SubjectStatus::Active, vec![grant(B1, Access::Rw)]);
    lone.made_by = None;
    assert!(matches!(
        apply(&u, 0, vec![lone]),
        UnitAnswer::Refused {
            reason: Refused::Keys(KeyRefusal::Malformed),
            ..
        }
    ));
    let mut internal = key(1, SubjectStatus::Active, vec![grant(B1, Access::Rw)]);
    internal.kind = KeyKind::Internal;
    assert!(matches!(
        apply(&u, 0, vec![internal.clone()]),
        UnitAnswer::Refused {
            reason: Refused::Keys(KeyRefusal::Malformed),
            ..
        }
    ));
    internal.made_by = None;
    ok_body(apply(&u, 0, vec![internal]));
    assert_eq!(served(&u, K), (false, vec![]));
}

#[test]
fn a_key_entry_reads_back_from_its_json_and_hides_its_secret_in_debug() {
    let e = key(2, SubjectStatus::Active, vec![grant(B1, Access::Ro)]);
    let c = call(
        CallKind::Worker,
        None,
        UnitOp::ApplyKeys {
            from_seq: 1,
            entries: vec![e.clone().into()],
            answers: vec![],
        },
    );
    let text = serde_json::to_string(&c).unwrap();
    assert_eq!(serde_json::from_str::<UnitCall>(&text).unwrap(), c);
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["op"]["entries"][0]["admin"] = json!(true);
    assert!(serde_json::from_value::<UnitCall>(v).is_err());
    let shown = format!("{c:?}");
    assert!(!shown.contains("member-1"), "{shown}");
    assert!(!shown.contains("170") && !shown.contains("aa"), "{shown}");
}

#[test]
fn apply_is_a_worker_call_only() {
    let u = born();
    let a = u.handle(
        &call(
            CallKind::Request,
            seqs(3, 0),
            UnitOp::ApplyKeys {
                from_seq: 0,
                entries: vec![principal(1, SubjectStatus::Active, vec![]).into()],
                answers: vec![],
            },
        ),
        NOW,
    );
    assert!(matches!(
        a,
        UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            ..
        }
    ));
    assert_eq!(keys_seq(&u), 0);
}

// ---------------------------------------------------------------------------
// The import (DS1 §2.3)
// ---------------------------------------------------------------------------

const SINCE: u64 = 4;

/// The owner's unit in the window: born, then its `restoring` entry set
/// at seq 4.
fn closed_for_the_move() -> Unit<RusqliteSql> {
    let u = born();
    assert!(matches!(
        sync(&u, SINCE, 0, Some(SINCE)),
        UnitAnswer::Ok { .. }
    ));
    u
}

fn moving(seq: u64) -> MoveHead {
    MoveHead {
        seq,
        selector: "moving".into(),
        to: Some(tenant()),
        flips: 0,
    }
}

fn t(s: &str) -> ImportValue {
    ImportValue::Text(s.into())
}

fn i(n: i64) -> ImportValue {
    ImportValue::Int(n)
}

fn b(n: usize) -> ImportValue {
    ImportValue::Blob(vec![0; n])
}

const N: ImportValue = ImportValue::Null;

fn batch(
    table: ImportTable,
    after: Option<&str>,
    cursor: &str,
    rows: Vec<Vec<ImportValue>>,
) -> ImportBatch {
    ImportBatch {
        table,
        columns: table.columns().iter().map(|c| c.to_string()).collect(),
        after: after.map(String::from),
        cursor: cursor.into(),
        rows,
    }
}

fn import(
    u: &Unit<RusqliteSql>,
    s: Option<Seqs>,
    head: MoveHead,
    since: u64,
    b: ImportBatch,
) -> UnitAnswer {
    u.handle(
        &call(
            CallKind::Worker,
            s,
            UnitOp::Import {
                head,
                since,
                batch: b,
            },
        ),
        NOW,
    )
}

/// A scheme-2 BDK wrap's shape: 73 bytes after the version byte 0x02.
fn bdk() -> ImportValue {
    let mut w = vec![0; 73];
    w[0] = 0x02;
    ImportValue::Blob(w)
}

fn bucket_row(id: &str, name: &str) -> Vec<ImportValue> {
    vec![t(id), t(name), t(P), bdk(), i(1), i(0), i(10)]
}

const G: &str = "g_0019a00000000d1d1d1d1d1d1d1d1";
const X: &str = "x_000000000000000000000000d1";

fn generation_row() -> Vec<ImportValue> {
    vec![
        t(G),
        t(B2),
        t("k"),
        t("live"),
        i(10),
        t("\"e\""),
        N,
        t("{}"),
        t("{}"),
        i(1),
        i(10),
        N,
    ]
}

fn extent_row(plan_rev: i64) -> Vec<ImportValue> {
    vec![
        t(X),
        t(B2),
        t(G),
        t("committed"),
        i(0),
        i(0),
        i(10),
        i(10),
        b(48),
        i(1),
        b(40),
        b(16),
        b(32),
        b(32),
        t("held"),
        i(1),
        i(plan_rev),
        N,
        N,
        N,
        i(10),
        i(0),
        i(0),
        N,
        i(0),
        N,
        N,
        N,
        N,
        N,
    ]
}

fn imported(u: &Unit<RusqliteSql>, table: &str) -> i64 {
    u.sql()
        .with_conn(|c| c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)))
        .unwrap()
}

fn refusal(a: &UnitAnswer) -> Option<(Refused, bool)> {
    match a {
        UnitAnswer::Refused { reason, alarm } => Some((*reason, *alarm)),
        _ => None,
    }
}

#[test]
fn the_import_column_lists_are_the_units_schema() {
    let u = born();
    for table in ImportTable::ALL {
        let cols: Vec<String> = u
            .sql()
            .with_conn(|c| {
                let mut st = c.prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?;
                let names = st
                    .query_map([table.name()], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()?;
                Ok::<_, rusqlite::Error>(names)
            })
            .unwrap();
        assert_eq!(cols, table.columns(), "{}", table.name());
        assert_eq!(ImportTable::parse(table.name()), Some(table));
    }
}

#[test]
fn an_import_runs_only_inside_the_move_window_of_this_unit() {
    // Not restoring: refused, with an alarm.
    let u = born();
    let a = import(
        &u,
        seqs(3, 0),
        moving(10),
        SINCE,
        batch(
            ImportTable::Buckets,
            None,
            "c1",
            vec![bucket_row(B2, "beta")],
        ),
    );
    assert_eq!(
        refusal(&a),
        Some((Refused::Import(ImportRefusal::NotBound), true))
    );
    let u = closed_for_the_move();
    let s = seqs(SINCE, 0);
    let one = || {
        batch(
            ImportTable::Buckets,
            None,
            "c1",
            vec![bucket_row(B2, "beta")],
        )
    };
    for (head, since) in [
        // Another restore entry than the unit's.
        (moving(10), SINCE + 1),
        // Tenant 0 is not moving.
        (
            MoveHead {
                seq: 10,
                selector: "d1".into(),
                to: None,
                flips: 0,
            },
            SINCE,
        ),
        (
            MoveHead {
                seq: 10,
                selector: "moved".into(),
                to: Some(tenant()),
                flips: 0,
            },
            SINCE,
        ),
        // Moving to another tenant.
        (
            MoveHead {
                seq: 10,
                selector: "moving".into(),
                to: Some(TenantId::parse("t_0000000000000d02").unwrap()),
                flips: 0,
            },
            SINCE,
        ),
    ] {
        let a = import(&u, s, head, since, one());
        assert_eq!(
            refusal(&a),
            Some((Refused::Import(ImportRefusal::NotBound), true))
        );
    }
    // The numbers are a job's: none or lower is refused, higher needs a sync.
    let a = import(&u, None, moving(10), SINCE, one());
    assert_eq!(
        refusal(&a),
        Some((Refused::Identity(Refusal::StaleJob), false))
    );
    let a = import(&u, seqs(SINCE - 1, 0), moving(10), SINCE, one());
    assert_eq!(
        refusal(&a),
        Some((Refused::Identity(Refusal::StaleJob), false))
    );
    assert!(matches!(
        import(&u, seqs(SINCE + 1, 0), moving(10), SINCE, one()),
        UnitAnswer::SyncNeeded { .. }
    ));
    assert_eq!(imported(&u, "buckets"), 1);
    // In the window, bound to this move: applied.
    let body = ok_body(import(&u, s, moving(10), SINCE, one()));
    assert_eq!(
        body,
        json!({ "table": "buckets", "cursor": "c1", "rows": 1, "applied": true })
    );
    assert_eq!(imported(&u, "buckets"), 2);
    // A tenant-0 head older than one already bound to is refused.
    let a = import(
        &u,
        s,
        moving(9),
        SINCE,
        batch(
            ImportTable::Buckets,
            Some("c1"),
            "c2",
            vec![bucket_row("b_00000000000000d4", "delta")],
        ),
    );
    assert_eq!(
        refusal(&a),
        Some((Refused::Import(ImportRefusal::NotBound), true))
    );
    // While closed, the unit serves nothing else.
    let a = u.handle(&call(CallKind::Request, s, UnitOp::Ping {}), NOW);
    assert!(matches!(a, UnitAnswer::Closed { .. }), "{a:?}");
}

#[test]
fn tenant_zero_and_a_non_root_unit_take_no_import() {
    for name in [
        UnitName::new(TenantId::zero(), 0),
        UnitName::new(tenant(), 1),
    ] {
        let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), name.clone(), "");
        let token = BirthToken {
            name: name.clone(),
            jurisdiction: String::new(),
            record_seq: 3,
            schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
            key_scheme: if name.tenant.is_zero() { 1 } else { 2 },
            kind: BirthKind::Restore,
        };
        let mut c = call(
            CallKind::Worker,
            seqs(3, 0),
            UnitOp::Provision {
                token,
                sealed: vec![1],
            },
        );
        c.name = name.clone();
        assert!(matches!(u.handle(&c, NOW), UnitAnswer::Ok { .. }));
        let mut head = moving(10);
        head.to = Some(name.tenant.clone());
        let mut c = call(
            CallKind::Worker,
            seqs(3, 0),
            UnitOp::Import {
                head,
                since: 3,
                batch: batch(
                    ImportTable::Buckets,
                    None,
                    "c1",
                    vec![bucket_row(B2, "beta")],
                ),
            },
        );
        c.name = name;
        let a = u.handle(&c, NOW);
        assert_eq!(
            refusal(&a),
            Some((Refused::Import(ImportRefusal::NotBound), true))
        );
    }
}

#[test]
fn batches_apply_once_and_in_order_and_the_import_resumes_by_cursor() {
    let u = closed_for_the_move();
    let s = seqs(SINCE, 0);
    let first = batch(
        ImportTable::Buckets,
        None,
        "b1",
        vec![bucket_row(B2, "beta")],
    );
    let second = batch(
        ImportTable::Buckets,
        Some("b1"),
        "b2",
        vec![
            bucket_row("b_00000000000000d4", "delta"),
            bucket_row("b_00000000000000d5", "eps"),
        ],
    );
    ok_body(import(&u, s, moving(10), SINCE, first.clone()));
    // A batch that skips one is refused.
    let skip = batch(
        ImportTable::Buckets,
        Some("b2"),
        "b3",
        vec![bucket_row("b_00000000000000d6", "zeta")],
    );
    let a = import(&u, s, moving(10), SINCE, skip);
    assert_eq!(
        refusal(&a),
        Some((Refused::Import(ImportRefusal::OutOfOrder), false))
    );
    ok_body(import(&u, s, moving(10), SINCE, second.clone()));
    // The answer of the last batch was lost: it is sent again and changes
    // nothing.
    let body = ok_body(import(&u, s, moving(10), SINCE, second));
    assert_eq!(
        body,
        json!({ "table": "buckets", "cursor": "b2", "rows": 3, "applied": false })
    );
    // An older batch sent again is out of order, not applied twice.
    let a = import(&u, s, moving(10), SINCE, first);
    assert_eq!(
        refusal(&a),
        Some((Refused::Import(ImportRefusal::OutOfOrder), false))
    );
    assert_eq!(imported(&u, "buckets"), 4);
    let mut progress = ok_body(worker(&u, UnitOp::ImportProgress {}));
    assert!(progress["schema_tables"].is_array());
    progress.as_object_mut().unwrap().remove("schema_tables");
    assert_eq!(
        progress,
        json!({
            "tables": [{ "table": "buckets", "cursor": "b2", "rows": 3 }],
            "sealed": null,
            "t0_seq": 10,
            "since_seq": SINCE,
            "move_lifted": false,
            "lifted_at": null,
        })
    );
}

#[test]
fn a_batch_of_another_shape_is_refused_and_nothing_of_it_is_kept() {
    let u = closed_for_the_move();
    let s = seqs(SINCE, 0);
    let mut wrong_cols = batch(
        ImportTable::Buckets,
        None,
        "c1",
        vec![bucket_row(B2, "beta")],
    );
    wrong_cols.columns.swap(0, 1);
    let mut short_row = batch(
        ImportTable::Buckets,
        None,
        "c1",
        vec![bucket_row(B2, "beta")],
    );
    short_row.rows[0].pop();
    let empty = batch(ImportTable::Buckets, None, "c1", vec![]);
    let too_many = batch(
        ImportTable::UsageHours,
        None,
        "c1",
        (0..=MAX_ROWS as i64)
            .map(|h| vec![i(h), i(0), i(0), i(0), i(0), i(0)])
            .collect(),
    );
    let no_cursor = batch(ImportTable::Buckets, None, "", vec![bucket_row(B2, "beta")]);
    for bad in [wrong_cols, short_row, empty, too_many, no_cursor] {
        let a = import(&u, s, moving(10), SINCE, bad);
        assert_eq!(
            refusal(&a),
            Some((Refused::Import(ImportRefusal::Shape), false))
        );
    }
    assert_eq!(imported(&u, "buckets"), 1);
    assert_eq!(imported(&u, "usage_hours"), 0);
}

#[test]
fn a_leased_outbox_row_or_an_extent_above_plan_rev_1_is_refused() {
    let u = closed_for_the_move();
    let s = seqs(SINCE, 0);
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(
            ImportTable::Buckets,
            None,
            "c1",
            vec![bucket_row(B2, "beta")],
        ),
    ));
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(ImportTable::Generations, None, "c1", vec![generation_row()]),
    ));
    let a = import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(ImportTable::Extents, None, "c1", vec![extent_row(2)]),
    );
    assert_eq!(
        refusal(&a),
        Some((Refused::Import(ImportRefusal::Shape), false))
    );
    assert_eq!(imported(&u, "extents"), 0);
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(ImportTable::Extents, None, "c1", vec![extent_row(1)]),
    ));
    let outbox = |owner: ImportValue| {
        vec![
            t(X),
            t(G),
            t("verify"),
            i(1),
            i(10),
            i(3),
            owner,
            N,
            i(0),
            N,
            i(10),
            N,
        ]
    };
    let a = import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(ImportTable::Outbox, None, "c1", vec![outbox(t("job-7"))]),
    );
    assert_eq!(
        refusal(&a),
        Some((Refused::Import(ImportRefusal::Shape), false))
    );
    assert_eq!(imported(&u, "outbox"), 0);
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(ImportTable::Outbox, None, "c1", vec![outbox(N)]),
    ));
    assert_eq!(imported(&u, "outbox"), 1);
}

#[test]
fn imported_rows_are_kept_with_their_values_and_counted_by_a_born_units_counters() {
    let u = closed_for_the_move();
    let s = seqs(SINCE, 0);
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(
            ImportTable::Buckets,
            None,
            "c1",
            vec![bucket_row(B2, "beta")],
        ),
    ));
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(ImportTable::Generations, None, "c1", vec![generation_row()]),
    ));
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(
            ImportTable::Objects,
            None,
            "c1",
            vec![vec![t(B2), t("k"), t(G)]],
        ),
    ));
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(ImportTable::Extents, None, "c1", vec![extent_row(1)]),
    ));
    // The extent's insert trigger made its generation_extents row; the
    // same row imported is accepted, another one is refused.
    let other = batch(
        ImportTable::GenerationExtents,
        None,
        "c1",
        vec![vec![t(G), i(0), t(X), i(5)]],
    );
    let a = import(&u, s, moving(10), SINCE, other);
    assert_eq!(
        refusal(&a),
        Some((Refused::Import(ImportRefusal::Shape), false))
    );
    ok_body(import(
        &u,
        s,
        moving(10),
        SINCE,
        batch(
            ImportTable::GenerationExtents,
            None,
            "c1",
            vec![vec![t(G), i(0), t(X), i(0)]],
        ),
    ));
    assert_eq!(imported(&u, "generation_extents"), 1);
    // Every value with its type class.
    let (typ, len): (String, i64) = u
        .sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT typeof(bdk_wrapped), length(bdk_wrapped) FROM buckets WHERE id = ?1",
                [B2],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!((typ.as_str(), len), ("blob", 73));
    // The born unit's counters are on, and counted the imported extent.
    let held: i64 = u
        .sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT x_unreleased FROM usage_global WHERE id = 1",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(held, 1);
}

#[test]
fn a_bucket_imported_after_the_keys_gets_their_grants() {
    let u = closed_for_the_move();
    // The owner's key chain is applied while the unit is closed.
    ok_body(apply(
        &u,
        0,
        vec![
            principal(1, SubjectStatus::Active, vec![grant(B2, Access::Rw)]),
            key(2, SubjectStatus::Active, vec![grant(B2, Access::Rw)]),
        ],
    ));
    assert_eq!(served(&u, K), (true, vec![]));
    assert!(matches!(
        sync(&u, SINCE, 2, Some(SINCE)),
        UnitAnswer::Ok { .. }
    ));
    ok_body(import(
        &u,
        seqs(SINCE, 2),
        moving(10),
        SINCE,
        batch(
            ImportTable::Buckets,
            None,
            "c1",
            vec![bucket_row(B2, "beta")],
        ),
    ));
    assert_eq!(served(&u, K), (true, vec![(B2.into(), "rw".into())]));
}

#[test]
fn an_import_call_reads_back_from_its_json() {
    let c = call(
        CallKind::Worker,
        seqs(SINCE, 0),
        UnitOp::Import {
            head: moving(10),
            since: SINCE,
            batch: batch(
                ImportTable::Buckets,
                None,
                "c1",
                vec![bucket_row(B2, "beta")],
            ),
        },
    );
    let text = serde_json::to_string(&c).unwrap();
    assert_eq!(serde_json::from_str::<UnitCall>(&text).unwrap(), c);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["op"]["batch"]["rows"][0][0], json!({ "t": B2 }));
    assert_eq!(v["op"]["batch"]["rows"][0][4], json!({ "i": 1 }));
    let mut v2 = v.clone();
    v2["op"]["batch"]["table"] = json!("access_keys");
    assert!(serde_json::from_value::<UnitCall>(v2).is_err());
    let mut v3 = v;
    v3["op"]["head"]["extra"] = json!(1);
    assert!(serde_json::from_value::<UnitCall>(v3).is_err());
    // Rows hold names and wrapped keys: `Debug` shows the shape only.
    let shown = format!("{c:?}");
    assert!(
        !shown.contains("beta") && shown.contains("rows: 1"),
        "{shown}"
    );
    let _ = SqlValue::Null;
}
