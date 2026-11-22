//! The owner move's end in the unit (`docs/units.md`, "Import", "Export"
//! and "Restore gate"): the import's seal (AM-29), the `move` lift report
//! and its binding (AM-15), and `export` (AM-26), on the native database.
//! `workers/unit-suite` runs this file against a Durable Object too.

use serde_json::{json, Value};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::export::{
    self, chain_key_rows, hash_rows, ExportMode, ExportRefusal, ExportTable, KeyTable, MAX_BYTES,
};
use velmora_bridge::unit::identity::Refusal;
use velmora_bridge::unit::import::{
    ImportBatch, ImportCount, ImportRefusal, ImportTable, ImportValue, MoveHead, MAX_CURSOR,
};
use velmora_bridge::unit::keys::{Access, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::lift::{
    ids_hash, ClassProof, FindingList, GateRefusal, GateSummary, LiftProof, ReplayId,
};
use velmora_bridge::unit::recount::{RecountCall, RecountRefusal};
use velmora_bridge::unit::restore::{
    Bookmark, PitrStep, RestoreRefusal, RestoreTarget, LIFT_SLACK_MS,
};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_795_000_000_000);
/// The `since_seq` of the move's `restoring` entry (S_move).
const S: u64 = 4;
/// Tenant 0's `flips` in the window: the move ordinal is `F + 1`.
const F: u64 = 2;
const B1: &str = "b_00000000000000e1";
const B2: &str = "b_00000000000000e2";
const G: &str = "g_0019a00000000e1e1e1e1e1e1e1e1";
const P: &str = "p_owner";
const K: &str = "AKMOVE0000000000001";

fn tenant() -> TenantId {
    TenantId::parse("t_0000000000000e01").unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn seqs(state_seq: u64, keys_seq: u64) -> Option<Seqs> {
    Some(Seqs {
        state_seq,
        keys_seq,
    })
}

fn call_on(name: &UnitName, kind: CallKind, s: Option<Seqs>, op: UnitOp) -> UnitCall {
    UnitCall {
        name: name.clone(),
        kind,
        seqs: s,
        authenticated: true,
        listed: true,
        op,
    }
}

fn worker(u: &Unit<RusqliteSql>, op: UnitOp) -> UnitAnswer {
    u.handle(&call_on(u.name(), CallKind::Worker, None, op), NOW)
}

/// A Worker call that carries the unit's own numbers (a move call).
fn numbered(u: &Unit<RusqliteSql>, op: UnitOp) -> UnitAnswer {
    let s = u.head().unwrap().seqs;
    u.handle(&call_on(u.name(), CallKind::Worker, Some(s), op), NOW)
}

fn sync_to(
    u: &Unit<RusqliteSql>,
    state_seq: u64,
    restoring: Option<u64>,
    lift: Option<LiftProof>,
) -> UnitAnswer {
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
                lift,
            },
        },
    )
}

/// A unit `name` born at seq 3 from a token of `kind`; a birth is then
/// synced active and closed for the move at S.
fn born_as(name: UnitName, kind: BirthKind) -> Unit<RusqliteSql> {
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), name.clone(), "");
    let token = BirthToken {
        name: name.clone(),
        jurisdiction: String::new(),
        record_seq: 3,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: if name.tenant.is_zero() { 1 } else { 2 },
        kind,
    };
    let a = u.handle(
        &call_on(
            &name,
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
    if kind == BirthKind::Birth {
        assert!(matches!(sync_to(&u, 3, None, None), UnitAnswer::Ok { .. }));
    }
    let a = sync_to(&u, S, Some(S), None);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    u
}

/// The owner's root unit in the window: born, empty, closed at S.
fn closed_for_the_move() -> Unit<RusqliteSql> {
    born_as(own(), BirthKind::Birth)
}

fn moving(seq: u64) -> MoveHead {
    MoveHead {
        seq,
        selector: "moving".into(),
        to: Some(tenant()),
        flips: F,
    }
}

fn t(s: &str) -> ImportValue {
    ImportValue::Text(s.into())
}

fn i(n: i64) -> ImportValue {
    ImportValue::Int(n)
}

fn b(n: usize) -> ImportValue {
    ImportValue::Blob(vec![7; n])
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

fn import(u: &Unit<RusqliteSql>, b: ImportBatch) -> UnitAnswer {
    numbered(
        u,
        UnitOp::Import {
            head: moving(10),
            since: S,
            batch: b,
        },
    )
}

fn ok(a: UnitAnswer) -> Value {
    match a {
        UnitAnswer::Ok { body, .. } => body,
        other => panic!("not ok: {other:?}"),
    }
}

fn refusal(a: &UnitAnswer) -> Option<(Refused, bool)> {
    match a {
        UnitAnswer::Refused { reason, alarm } => Some((*reason, *alarm)),
        _ => None,
    }
}

/// A scheme-2 BDK wrap's shape: 73 bytes after the version byte 0x02.
fn bdk() -> ImportValue {
    let mut w = vec![7; 73];
    w[0] = 0x02;
    ImportValue::Blob(w)
}

fn bucket_row(id: &str, name: &str, owner: &str) -> Vec<ImportValue> {
    vec![t(id), t(name), t(owner), bdk(), i(2), i(0), i(10)]
}

fn generation_row(meta: &str) -> Vec<ImportValue> {
    vec![
        t(G),
        t(B1),
        t("k"),
        t("live"),
        i(10),
        t("\"e\""),
        N,
        t("{}"),
        t(meta),
        i(0),
        i(10),
        N,
    ]
}

fn object_row(key: &str) -> Vec<ImportValue> {
    vec![t(B1), t(key), t(G)]
}

/// Two buckets, one generation and the objects named, imported.
fn fill(u: &Unit<RusqliteSql>, keys: &[&str]) {
    ok(import(
        u,
        batch(
            ImportTable::Buckets,
            None,
            "c1",
            vec![bucket_row(B1, "alpha", P), bucket_row(B2, "beta", P)],
        ),
    ));
    ok(import(
        u,
        batch(
            ImportTable::Generations,
            None,
            "c1",
            vec![generation_row("{}")],
        ),
    ));
    if !keys.is_empty() {
        ok(import(
            u,
            batch(
                ImportTable::Objects,
                None,
                "c1",
                keys.iter().map(|k| object_row(k)).collect(),
            ),
        ));
    }
}

/// Every import table's row count as the unit holds it.
fn counts(u: &Unit<RusqliteSql>) -> Vec<ImportCount> {
    ImportTable::ALL
        .into_iter()
        .map(|table| {
            let rows: i64 = u
                .sql()
                .with_conn(|c| {
                    c.query_row(
                        "SELECT coalesce((SELECT rows FROM unit_import WHERE tbl = ?1), 0)",
                        [table.name()],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            ImportCount {
                table,
                rows: rows as u64,
            }
        })
        .collect()
}

fn seal(u: &Unit<RusqliteSql>, head: MoveHead, tables: Vec<ImportCount>) -> UnitAnswer {
    numbered(
        u,
        UnitOp::ImportSeal {
            head,
            since: S,
            tables,
        },
    )
}

fn rid(since: u64, ordinal: u64, nonce: &str) -> ReplayId {
    ReplayId {
        since,
        ordinal,
        nonce: nonce.into(),
    }
}

fn open_move(u: &Unit<RusqliteSql>, id: ReplayId, head: MoveHead) -> UnitAnswer {
    numbered(
        u,
        UnitOp::GateOpenMove {
            replay_id: id,
            head,
        },
    )
}

/// The move report's summary: complete, every count 0, every hash the
/// hash of no id.
fn empty_summary() -> GateSummary {
    let none = ids_hash(std::iter::empty::<&String>());
    GateSummary {
        complete: true,
        classified: true,
        lists: FindingList::ALL
            .into_iter()
            .map(|l| {
                (
                    l,
                    ClassProof {
                        count: 0,
                        sha256: none.clone(),
                    },
                )
            })
            .collect(),
        ..GateSummary::default()
    }
}

fn status(u: &Unit<RusqliteSql>) -> Value {
    ok(worker(u, UnitOp::GateStatus {}))
}

fn proof(u: &Unit<RusqliteSql>) -> LiftProof {
    let s = status(u);
    serde_json::from_value(s["lift"]["ok"].clone()).unwrap_or_else(|_| panic!("no lift: {s}"))
}

fn raise_stamp(u: &Unit<RusqliteSql>, counter: u64) {
    u.sql()
        .apply(&format!(
            "INSERT INTO rollback_stamp(id, counter, catalogue_id) VALUES (1, {counter}, '{}.0') \
             ON CONFLICT(id) DO UPDATE SET counter = excluded.counter",
            tenant()
        ))
        .unwrap();
}

fn gate_refused(r: GateRefusal) -> Option<(Refused, bool)> {
    Some((Refused::Gate(r), false))
}

// ---------------------------------------------------------------------------
// The import's seal (AM-29)
// ---------------------------------------------------------------------------

#[test]
fn the_seal_needs_every_tables_count_and_then_takes_no_batch() {
    let u = closed_for_the_move();
    fill(&u, &["a", "b"]);
    let right = counts(&u);
    assert_eq!(
        right
            .iter()
            .find(|c| c.table == ImportTable::Objects)
            .map(|c| c.rows),
        Some(2)
    );
    // A count that is not the unit's, a table missing, or a table twice.
    let mut wrong = right.clone();
    wrong[2].rows += 1;
    let short = right[1..].to_vec();
    let mut twice = right.clone();
    twice.push(right[0].clone());
    for tables in [wrong, short, twice, Vec::new()] {
        let a = seal(&u, moving(10), tables);
        assert_eq!(
            refusal(&a),
            Some((Refused::Import(ImportRefusal::CountMismatch), false))
        );
    }
    assert_eq!(
        ok(worker(&u, UnitOp::ImportProgress {}))["sealed"],
        json!(null)
    );
    // The seal records this window's ordinal, flips + 1.
    assert_eq!(
        ok(seal(&u, moving(10), right.clone())),
        json!({ "sealed": F + 1, "newly": true })
    );
    assert_eq!(
        ok(seal(&u, moving(10), right.clone())),
        json!({ "sealed": F + 1, "newly": false })
    );
    assert_eq!(
        ok(worker(&u, UnitOp::ImportProgress {}))["sealed"],
        json!(F + 1)
    );
    // Another window's seal is refused.
    let mut other = moving(11);
    other.flips = F + 1;
    assert_eq!(
        refusal(&seal(&u, other, right)),
        Some((Refused::Import(ImportRefusal::NotBound), true))
    );
    // No batch after the seal, not even the last one sent again.
    for b in [
        batch(
            ImportTable::Objects,
            Some("c1"),
            "c2",
            vec![object_row("c")],
        ),
        batch(ImportTable::Objects, None, "c1", vec![object_row("a")]),
    ] {
        assert_eq!(
            refusal(&import(&u, b)),
            Some((Refused::Import(ImportRefusal::Sealed), false))
        );
    }
    let objects: i64 = u
        .sql()
        .with_conn(|c| c.query_row("SELECT count(*) FROM objects", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(objects, 2);
}

#[test]
fn the_seal_is_bound_and_numbered_as_a_batch() {
    let u = closed_for_the_move();
    fill(&u, &["a"]);
    let tables = counts(&u);
    // Another entry, or tenant 0 not moving to this tenant: refused, and
    // the Worker alarms.
    let wrong_since = numbered(
        &u,
        UnitOp::ImportSeal {
            head: moving(10),
            since: S + 1,
            tables: tables.clone(),
        },
    );
    let mut d1 = moving(10);
    d1.selector = "d1".into();
    let older = moving(9);
    for a in [
        wrong_since,
        seal(&u, d1, tables.clone()),
        seal(&u, older, tables.clone()),
    ] {
        assert_eq!(
            refusal(&a),
            Some((Refused::Import(ImportRefusal::NotBound), true)),
            "{a:?}"
        );
    }
    // Numbers below the unit's, or none, are refused as a stale job.
    let stale = u.handle(
        &call_on(
            &own(),
            CallKind::Worker,
            seqs(S - 1, 0),
            UnitOp::ImportSeal {
                head: moving(10),
                since: S,
                tables: tables.clone(),
            },
        ),
        NOW,
    );
    assert_eq!(
        refusal(&stale),
        Some((Refused::Identity(Refusal::StaleJob), false))
    );
    assert_eq!(
        ok(worker(&u, UnitOp::ImportProgress {}))["sealed"],
        json!(null)
    );
}

// ---------------------------------------------------------------------------
// The move's lift report (AM-15)
// ---------------------------------------------------------------------------

#[test]
fn a_move_report_lifts_only_under_the_imports_binding() {
    let u = closed_for_the_move();
    fill(&u, &["a"]);
    let id = rid(S, 0, "m1");
    // Before the seal.
    assert_eq!(
        refusal(&open_move(&u, id.clone(), moving(10))),
        gate_refused(GateRefusal::ImportNotSealed)
    );
    ok(seal(&u, moving(10), counts(&u)));
    // Another window (flips), tenant 0 not moving here, or older than a
    // head the unit has seen.
    let mut other_window = moving(10);
    other_window.flips = F + 1;
    assert_eq!(
        refusal(&open_move(&u, id.clone(), other_window)),
        gate_refused(GateRefusal::ImportNotSealed)
    );
    let mut d1 = moving(10);
    d1.selector = "d1".into();
    let mut elsewhere = moving(10);
    elsewhere.to = Some(TenantId::parse("t_0000000000000e02").unwrap());
    for head in [d1, elsewhere, moving(9)] {
        assert_eq!(
            refusal(&open_move(&u, id.clone(), head)),
            gate_refused(GateRefusal::MoveNotBound)
        );
    }
    // Not the unit's entry; an ordinal that is not the stamp counter (no
    // stamp row: never raised, 0).
    assert_eq!(
        refusal(&open_move(&u, rid(S + 1, 0, "m1"), moving(10))),
        gate_refused(GateRefusal::NotRestoring)
    );
    assert_eq!(
        refusal(&open_move(&u, rid(S, 1, "m1"), moving(10))),
        gate_refused(GateRefusal::StampNotLevelled)
    );
    assert_eq!(
        ok(open_move(&u, id.clone(), moving(11))),
        json!({ "opened": true })
    );
    assert_eq!(
        ok(open_move(&u, id.clone(), moving(11))),
        json!({ "opened": false })
    );
    // The unit has now seen tenant 0 at 11.
    assert_eq!(
        refusal(&open_move(&u, id.clone(), moving(10))),
        gate_refused(GateRefusal::MoveNotBound)
    );
    // Not complete yet.
    assert_eq!(status(&u)["kind"], json!("move"));
    assert_eq!(
        status(&u)["lift"]["refused"],
        json!("closed"),
        "an open move report is not complete"
    );
    // A move report takes no blocker, no acknowledgement, and no summary
    // but a complete, empty one.
    let blockers = worker(
        &u,
        UnitOp::GateBlockers {
            replay_id: id.clone(),
            list: FindingList::Damaged,
            ids: vec!["g_1".into()],
        },
    );
    assert_eq!(refusal(&blockers), gate_refused(GateRefusal::MoveNotEmpty));
    let acked = worker(
        &u,
        UnitOp::GateAck {
            replay_id: id.clone(),
            class: velmora_bridge::unit::lift::AckClass::Damaged,
            ids: vec!["g_1".into()],
        },
    );
    assert_eq!(refusal(&acked), gate_refused(GateRefusal::MoveNotEmpty));
    let mut not_empty = empty_summary();
    not_empty.damaged_total = 1;
    let mut incomplete = empty_summary();
    incomplete.complete = false;
    for summary in [not_empty, incomplete] {
        let a = worker(
            &u,
            UnitOp::GateReport {
                replay_id: id.clone(),
                summary,
            },
        );
        assert_eq!(refusal(&a), gate_refused(GateRefusal::MoveNotEmpty));
    }
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: id.clone(),
            summary: empty_summary(),
        },
    ));
    // `gate_status` names the lift; the `sync` of the lift record lifts.
    let p = proof(&u);
    assert_eq!(p.replay_id, id);
    assert!(p.acknowledged.is_empty());
    assert_eq!(
        refusal(&sync_to(&u, S + 1, None, None)),
        gate_refused(GateRefusal::ProofMismatch)
    );
    assert!(matches!(
        sync_to(&u, S + 1, None, Some(p)),
        UnitAnswer::Ok { .. }
    ));
    let h = u.head().unwrap();
    assert_eq!((h.restoring_since, h.closed_at), (None, None));
    // Open now: a move report cannot be opened again.
    assert_eq!(
        refusal(&open_move(&u, rid(S, 0, "m2"), moving(11))),
        gate_refused(GateRefusal::NotRestoring)
    );
    // The lift used the seal up: under a later entry (a restore of the
    // owner's unit), the window's head opens no move report, and only the
    // restore gate can lift.
    let later = S + 5;
    ok(sync_to(&u, later, Some(later), None));
    assert_eq!(
        refusal(&open_move(&u, rid(later, 0, "m3"), moving(11))),
        gate_refused(GateRefusal::MoveNotBound)
    );
    let r = rid(later, 2, "r1");
    raise_stamp(&u, 2);
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: r.clone(),
        },
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: r.clone(),
            summary: empty_summary(),
        },
    ));
    assert_eq!(proof(&u).replay_id, r);
}

#[test]
fn a_raise_between_the_report_and_the_lift_re_enters_under_a_new_entry() {
    let u = closed_for_the_move();
    fill(&u, &["a"]);
    ok(seal(&u, moving(10), counts(&u)));
    let first = rid(S, 0, "m1");
    ok(open_move(&u, first.clone(), moving(10)));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: first.clone(),
            summary: empty_summary(),
        },
    ));
    let stale = proof(&u);
    // A stamp raise lands after the tool read `gate_status`: the lift
    // record's `sync` is refused, and the unit stays closed.
    raise_stamp(&u, 1);
    assert_eq!(
        refusal(&sync_to(&u, S + 1, None, Some(stale))),
        gate_refused(GateRefusal::StampNotLevelled)
    );
    assert_eq!(u.head().unwrap().restoring_since, Some(S));
    // The tool writes a new `restoring` entry and syncs the unit to it.
    let s2 = S + 2;
    ok(sync_to(&u, s2, Some(s2), None));
    // The old report names the old entry.
    assert_eq!(status(&u)["lift"]["refused"], json!("no_report"));
    // The seal survives: a resumed copy is told the import is done, under
    // either entry.
    for since in [S, s2] {
        let b = numbered(
            &u,
            UnitOp::Import {
                head: moving(12),
                since,
                batch: batch(
                    ImportTable::Objects,
                    Some("c1"),
                    "c2",
                    vec![object_row("z")],
                ),
            },
        );
        assert_eq!(
            refusal(&b),
            Some((Refused::Import(ImportRefusal::Sealed), false))
        );
    }
    assert_eq!(
        ok(worker(&u, UnitOp::ImportProgress {}))["sealed"],
        json!(F + 1)
    );
    let second = rid(s2, 1, "m2");
    assert_eq!(
        ok(open_move(&u, second.clone(), moving(12))),
        json!({ "opened": true })
    );
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: second.clone(),
            summary: empty_summary(),
        },
    ));
    let p = proof(&u);
    assert_eq!(p.replay_id, second);
    assert!(matches!(
        sync_to(&u, s2 + 1, None, Some(p)),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(u.head().unwrap().restoring_since, None);
}

#[test]
fn a_move_import_that_is_not_sealed_never_lifts() {
    let u = closed_for_the_move();
    fill(&u, &["a"]);
    // A restore report, complete and clean, for the move's entry.
    raise_stamp(&u, 3);
    let id = rid(S, 3, "r1");
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: id.clone(),
        },
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: id,
            summary: empty_summary(),
        },
    ));
    assert_eq!(status(&u)["lift"]["refused"], json!("import_not_sealed"));
    assert_eq!(
        refusal(&sync_to(&u, S + 1, None, None)),
        gate_refused(GateRefusal::ImportNotSealed)
    );
    assert_eq!(u.head().unwrap().restoring_since, Some(S));
    // Under a later entry too (a rollback to a point inside the window,
    // then a restore): the partial import is never lifted.
    let later = S + 3;
    ok(sync_to(&u, later, Some(later), None));
    let r = rid(later, 3, "r2");
    ok(worker(
        &u,
        UnitOp::GateOpen {
            replay_id: r.clone(),
        },
    ));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: r.clone(),
            summary: empty_summary(),
        },
    ));
    assert_eq!(status(&u)["lift"]["refused"], json!("import_not_sealed"));
    assert_eq!(
        refusal(&sync_to(&u, later + 1, None, None)),
        gate_refused(GateRefusal::ImportNotSealed)
    );
}

#[test]
fn an_imported_key_must_be_of_its_columns_class() {
    let u = closed_for_the_move();
    fill(&u, &[]);
    let mut null_id = bucket_row(B1, "x", P);
    null_id[0] = N;
    let mut blob_id = bucket_row(B1, "x", P);
    blob_id[0] = b(4);
    let text_seq = vec![t(G), t("1"), N, i(0)];
    for (table, row) in [
        (ImportTable::Buckets, null_id),
        (ImportTable::Buckets, blob_id),
        (ImportTable::GenerationExtents, text_seq),
        (ImportTable::Objects, vec![t(B1), i(7), t(G)]),
    ] {
        let after = match table {
            ImportTable::Buckets => Some("c1"),
            _ => None,
        };
        let a = import(&u, batch(table, after, "c9", vec![row]));
        assert_eq!(
            refusal(&a),
            Some((Refused::Import(ImportRefusal::Shape), false)),
            "{table:?}"
        );
    }
}

#[test]
fn only_the_root_unit_of_a_managed_tenant_takes_a_move_report() {
    for name in [
        UnitName::new(TenantId::zero(), 0),
        UnitName::new(tenant(), 1),
    ] {
        let u = born_as(name.clone(), BirthKind::Restore);
        let mut head = moving(10);
        head.to = Some(name.tenant.clone());
        let a = numbered(
            &u,
            UnitOp::GateOpenMove {
                replay_id: rid(S, 0, "m1"),
                head,
            },
        );
        assert_eq!(
            refusal(&a),
            gate_refused(GateRefusal::MoveNotBound),
            "{name}"
        );
    }
}

#[test]
fn a_move_report_carries_the_units_numbers() {
    let u = closed_for_the_move();
    fill(&u, &[]);
    ok(seal(&u, moving(10), counts(&u)));
    let op = UnitOp::GateOpenMove {
        replay_id: rid(S, 0, "m1"),
        head: moving(10),
    };
    let none = u.handle(&call_on(&own(), CallKind::Worker, None, op.clone()), NOW);
    assert_eq!(
        refusal(&none),
        Some((Refused::Identity(Refusal::StaleJob), false))
    );
    let ahead = u.handle(&call_on(&own(), CallKind::Worker, seqs(S + 1, 0), op), NOW);
    assert!(matches!(ahead, UnitAnswer::SyncNeeded { .. }), "{ahead:?}");
}

fn recount(call: RecountCall, head: Option<MoveHead>) -> UnitOp {
    UnitOp::Recount { call, head }
}

fn recount_refused(r: RecountRefusal) -> Option<(Refused, bool)> {
    Some((Refused::Recount(r), false))
}

#[test]
fn a_restore_born_unit_lifts_a_move_only_with_its_counters_on() {
    let u = born_as(own(), BirthKind::Restore);
    fill(&u, &["a"]);
    let start = |head| recount(RecountCall::Start {}, head);
    // The import filled this entry: the recount is the move's, and needs
    // the seal (AM-27, AM-29).
    assert_eq!(
        refusal(&numbered(&u, start(Some(moving(10))))),
        recount_refused(RecountRefusal::ImportNotSealed)
    );
    ok(seal(&u, moving(10), counts(&u)));
    let id = rid(S, 0, "m1");
    ok(open_move(&u, id.clone(), moving(10)));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: id,
            summary: empty_summary(),
        },
    ));
    // Until `Recount` turns them on, the lift is refused.
    assert_eq!(status(&u)["lift"]["refused"], json!("counters_off"));
    // Bound as the move report is: tenant 0's head, this window, moving
    // here, not older than seen; numbered as an import batch.
    assert_eq!(
        refusal(&numbered(&u, start(None))),
        recount_refused(RecountRefusal::MoveNotBound)
    );
    let mut other_window = moving(10);
    other_window.flips = F + 1;
    assert_eq!(
        refusal(&numbered(&u, start(Some(other_window)))),
        recount_refused(RecountRefusal::ImportNotSealed)
    );
    let mut d1 = moving(10);
    d1.selector = "d1".into();
    let mut elsewhere = moving(10);
    elsewhere.to = Some(TenantId::parse("t_0000000000000e02").unwrap());
    for head in [d1, elsewhere, moving(9)] {
        assert_eq!(
            refusal(&numbered(&u, start(Some(head)))),
            recount_refused(RecountRefusal::MoveNotBound)
        );
    }
    assert_eq!(
        refusal(&worker(&u, start(Some(moving(10))))),
        Some((Refused::Identity(Refusal::StaleJob), false))
    );
    // It writes: an unauthenticated call is refused (rule 11).
    let mut unauthenticated = call_on(
        &own(),
        CallKind::Worker,
        Some(u.head().unwrap().seqs),
        start(Some(moving(10))),
    );
    unauthenticated.authenticated = false;
    assert_eq!(
        refusal(&u.handle(&unauthenticated, NOW)),
        Some((Refused::Unauthenticated, false))
    );
    let started = ok(numbered(&u, start(Some(moving(10)))));
    assert_eq!(started["started"], json!(true));
    let mut on = false;
    for _ in 0..10 {
        let step = ok(numbered(
            &u,
            recount(RecountCall::Step { chunk: 1 }, Some(moving(10))),
        ));
        if step["counters_on"] == json!(true) {
            on = true;
            break;
        }
    }
    assert!(on, "the recount ends and turns the counters on");
    // The pass counted what the import brought.
    let live: i64 = u
        .sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT live_objects FROM usage_buckets WHERE kind = 1 AND bucket_id = ?1",
                [B1],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(live, 1);
    let p = proof(&u);
    assert!(matches!(
        sync_to(&u, S + 1, None, Some(p)),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(
        refusal(&numbered(&u, start(Some(moving(10))))),
        recount_refused(RecountRefusal::NotRestoring)
    );
    // A later restore of this unit never goes back into the move's
    // window: a time before the lift is refused; a time after it goes on
    // to the lease checks.
    let s2 = S + 2;
    assert!(matches!(
        sync_to(&u, s2, Some(s2), None),
        UnitAnswer::Ok { .. }
    ));
    let restore = |at_ms| {
        let c = call_on(
            &own(),
            CallKind::Worker,
            None,
            UnitOp::Restore {
                token: BirthToken {
                    name: own(),
                    jurisdiction: String::new(),
                    record_seq: s2,
                    schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
                    key_scheme: 2,
                    kind: BirthKind::Restore,
                },
                target: RestoreTarget::Time { at_ms },
                expect_undo: Bookmark("undo".into()),
            },
        );
        match u.pitr_step(&c, NOW) {
            PitrStep::Answer(a) => refusal(&a),
            other => panic!("armed: {other:?}"),
        }
    };
    // The lift's time is its call's clock: a margin after it is refused too.
    for at_ms in [NOW.0 - 1, NOW.0, NOW.0 + LIFT_SLACK_MS - 1] {
        assert_eq!(
            restore(at_ms),
            Some((Refused::Restore(RestoreRefusal::BeforeMoveLift), false)),
            "{at_ms}"
        );
    }
    assert_eq!(
        restore(NOW.0 + LIFT_SLACK_MS),
        Some((Refused::Restore(RestoreRefusal::LeaseUnknown), false))
    );
}

// ---------------------------------------------------------------------------
// The import cursor: the longest key the S3 path takes
// ---------------------------------------------------------------------------

/// The cursor the move's copy sends: the typed JSON of the row's key.
fn cursor_of(key: &[ImportValue]) -> String {
    serde_json::to_string(key).unwrap()
}

#[test]
fn a_cursor_naming_a_long_object_key_is_taken() {
    let u = closed_for_the_move();
    fill(&u, &[]);
    // A 1024-byte key of quotes and backslashes (JSON doubles each), and
    // an 8 KiB key of control characters (JSON writes each in 6 bytes):
    // the S3 path bounds a key only by its 8 KiB request target.
    let k1024: String = "\"\\".repeat(512);
    let k8k: String = "\u{1}".repeat(8 * 1024);
    let mut after: Option<String> = None;
    for (n, key) in [k1024, k8k].into_iter().enumerate() {
        let cursor = cursor_of(&[t(B1), t(&key)]);
        assert!(
            cursor.len() > 2 * key.len() && cursor.len() <= MAX_CURSOR,
            "{}",
            cursor.len()
        );
        let a = import(
            &u,
            batch(
                ImportTable::Objects,
                after.as_deref(),
                &cursor,
                vec![object_row(&key)],
            ),
        );
        assert_eq!(ok(a)["rows"], json!(n + 1));
        after = Some(cursor);
    }
    // One byte over the bound is refused, not truncated.
    let too_long = "x".repeat(MAX_CURSOR + 1);
    let a = import(
        &u,
        batch(
            ImportTable::Objects,
            after.as_deref(),
            &too_long,
            vec![object_row("y")],
        ),
    );
    assert_eq!(
        refusal(&a),
        Some((Refused::Import(ImportRefusal::Shape), false))
    );
}

// ---------------------------------------------------------------------------
// Export (AM-26)
// ---------------------------------------------------------------------------

fn every_export_table() -> Vec<ExportTable> {
    let mut all: Vec<ExportTable> = ImportTable::ALL
        .into_iter()
        .map(ExportTable::Data)
        .collect();
    all.push(ExportTable::Keys(KeyTable::UnitKeys));
    all.push(ExportTable::Keys(KeyTable::UnitKeyGrants));
    all
}

fn export_op(
    table: ExportTable,
    after: Option<Vec<ImportValue>>,
    limit: u32,
    mode: ExportMode,
) -> UnitOp {
    UnitOp::Export {
        table,
        after,
        limit,
        mode,
    }
}

fn rows_of(body: &Value) -> Vec<Vec<ImportValue>> {
    serde_json::from_value(body["rows"].clone()).unwrap()
}

#[test]
fn the_export_lists_are_the_units_schema() {
    let u = closed_for_the_move();
    for table in every_export_table() {
        let (cols, pk): (Vec<String>, Vec<String>) = u.sql().with_conn(|c| {
            let mut st = c
                .prepare(&format!("PRAGMA table_info(\"{}\")", table.name()))
                .unwrap();
            let rows: Vec<(String, i64)> = st
                .query_map([], |r| Ok((r.get(1)?, r.get(5)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            let cols = rows.iter().map(|(n, _)| n.clone()).collect();
            let mut pk: Vec<(i64, String)> = rows
                .iter()
                .filter(|(_, k)| *k > 0)
                .map(|(n, k)| (*k, n.clone()))
                .collect();
            pk.sort();
            (cols, pk.into_iter().map(|(_, n)| n).collect())
        });
        let ints: Vec<String> = u.sql().with_conn(|c| {
            let mut st = c
                .prepare(&format!("PRAGMA table_info(\"{}\")", table.name()))
                .unwrap();
            st.query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(5)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .filter(|(_, ty, pk)| *pk > 0 && ty.eq_ignore_ascii_case("INTEGER"))
            .map(|(n, _, _)| n)
            .collect()
        });
        assert_eq!(ints, table.integer_keys(), "{}", table.name());
        assert_eq!(cols, table.columns(), "{}", table.name());
        assert_eq!(pk, table.key_columns(), "{}", table.name());
        for c in table.hash_excluded() {
            assert!(cols.contains(&c.to_string()), "{}.{c}", table.name());
            assert!(
                !table.key_columns().contains(c),
                "{}.{c} is a key",
                table.name()
            );
        }
    }
}

#[test]
fn every_page_walks_its_primary_key_in_order() {
    let u = closed_for_the_move();
    for table in every_export_table() {
        for after in [false, true] {
            let sql = export::page_sql(table, after);
            let n = table.key_columns().len() + 1;
            let plan: Vec<String> = u.sql().with_conn(|c| {
                let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
                let params: Vec<rusqlite::types::Value> = (0..if after { n } else { 1 })
                    .map(|_| rusqlite::types::Value::Integer(1))
                    .collect();
                st.query_map(rusqlite::params_from_iter(params), |r| {
                    r.get::<_, String>(3)
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
            });
            let text = plan.join(" | ");
            assert!(!text.contains("TEMP B-TREE"), "{}: {text}", table.name());
            if after {
                assert!(text.contains("SEARCH"), "{}: {text}", table.name());
            }
        }
    }
}

#[test]
fn export_is_refused_unless_the_unit_is_closed() {
    let u = closed_for_the_move();
    fill(&u, &["a"]);
    ok(seal(&u, moving(10), counts(&u)));
    let id = rid(S, 0, "m1");
    ok(open_move(&u, id.clone(), moving(10)));
    ok(worker(
        &u,
        UnitOp::GateReport {
            replay_id: id,
            summary: empty_summary(),
        },
    ));
    let p = proof(&u);
    ok(sync_to(&u, S + 1, None, Some(p)));
    for mode in [ExportMode::Hash, ExportMode::Rows] {
        let a = worker(
            &u,
            export_op(ExportTable::Data(ImportTable::Objects), None, 10, mode),
        );
        assert_eq!(
            refusal(&a),
            Some((Refused::Export(ExportRefusal::NotRestoring), false))
        );
    }
}

#[test]
fn export_pages_in_key_order_and_its_hash_is_the_rows_without_excluded_columns() {
    let u = closed_for_the_move();
    // Keys whose byte order is not their insert order.
    let keys = ["b", "a/2", "a", "\u{e9}", "a/10", "B"];
    fill(&u, &keys);
    let table = ExportTable::Data(ImportTable::Objects);
    let mut sorted: Vec<&str> = keys.to_vec();
    sorted.sort();
    let want: Vec<Vec<ImportValue>> = sorted.iter().map(|k| object_row(k)).collect();
    // Rows in pages of 4: the second page starts after the first's last
    // key, and `more` is false only on the last.
    let p1 = ok(worker(&u, export_op(table, None, 4, ExportMode::Rows)));
    assert_eq!(
        (p1["count"].clone(), p1["more"].clone()),
        (json!(4), json!(true))
    );
    assert_eq!(rows_of(&p1), want[..4]);
    let last: Vec<ImportValue> = serde_json::from_value(p1["last"].clone()).unwrap();
    assert_eq!(last, vec![t(B1), t(sorted[3])]);
    let p2 = ok(worker(
        &u,
        export_op(table, Some(last.clone()), 4, ExportMode::Rows),
    ));
    assert_eq!(
        (p2["count"].clone(), p2["more"].clone()),
        (json!(2), json!(false))
    );
    assert_eq!(rows_of(&p2), want[4..]);
    // Hash mode answers the same page without its rows, and the digest is
    // `hash_rows` over the same rows: what the tool computes on D1.
    let h1 = ok(worker(&u, export_op(table, None, 4, ExportMode::Hash)));
    assert_eq!(h1["rows"], Value::Null);
    assert_eq!(h1["last"], p1["last"]);
    assert_eq!(h1["sha256"], json!(hash_rows(table, &want[..4]).unwrap()));
    let h2 = ok(worker(
        &u,
        export_op(table, Some(last), 4, ExportMode::Hash),
    ));
    assert_eq!(h2["sha256"], json!(hash_rows(table, &want[4..]).unwrap()));
    assert_ne!(h1["sha256"], h2["sha256"]);
    // Buckets: the transformed columns are not hashed (V1), every other
    // column is, with its type class.
    let buckets = ExportTable::Data(ImportTable::Buckets);
    let h = ok(worker(&u, export_op(buckets, None, 10, ExportMode::Hash)));
    let d1_side = vec![
        vec![t(B1), t("alpha"), t("d1-owner"), b(60), i(1), i(0), i(10)],
        vec![t(B2), t("beta"), t("d1-owner"), b(60), i(1), i(0), i(10)],
    ];
    assert_eq!(h["sha256"], json!(hash_rows(buckets, &d1_side).unwrap()));
    let mut renamed = d1_side.clone();
    renamed[1][1] = t("gamma");
    let mut retyped = d1_side.clone();
    retyped[0][6] = t("10");
    for other in [renamed, retyped] {
        assert_ne!(h["sha256"], json!(hash_rows(buckets, &other).unwrap()));
    }
    // The wraps leave as stored, still wrapped, in rows mode.
    let r = ok(worker(&u, export_op(buckets, None, 10, ExportMode::Rows)));
    assert_eq!(rows_of(&r)[0][3], bdk());
    // An empty table: no rows, no last key, the digest of nothing.
    let gc = ExportTable::Data(ImportTable::Gc);
    let e = ok(worker(&u, export_op(gc, None, 10, ExportMode::Hash)));
    assert_eq!(
        e,
        json!({
            "table": "gc", "mode": "hash", "count": 0, "last": null, "more": false,
            "sha256": hash_rows(gc, &[]).unwrap(),
        })
    );
}

#[test]
fn a_rows_answer_stops_at_one_mib_and_a_larger_row_comes_alone() {
    let u = closed_for_the_move();
    fill(&u, &[]);
    // Three generations: 600 KiB, 1.2 MiB and 10 bytes of metadata.
    let big = |id: &str, n: usize| {
        let mut r = generation_row(&"m".repeat(n));
        r[0] = t(id);
        r
    };
    let g2 = "g_0019a00000000e1e1e1e1e1e1e1e2";
    let g3 = "g_0019a00000000e1e1e1e1e1e1e1e3";
    let g4 = "g_0019a00000000e1e1e1e1e1e1e1e4";
    ok(import(
        &u,
        batch(
            ImportTable::Generations,
            Some("c1"),
            "c2",
            vec![big(g2, 600 * 1024), big(g3, 1200 * 1024), big(g4, 10)],
        ),
    ));
    let table = ExportTable::Data(ImportTable::Generations);
    // G (small) and g2 fit under 1 MiB; g3 would pass it.
    let p1 = ok(worker(&u, export_op(table, None, 500, ExportMode::Rows)));
    assert_eq!(
        (p1["count"].clone(), p1["more"].clone()),
        (json!(2), json!(true))
    );
    let size: usize = rows_of(&p1)
        .iter()
        .map(|r| serde_json::to_vec(r).unwrap().len())
        .sum();
    assert!(size <= MAX_BYTES);
    // g3 alone, larger than the bound.
    let p2 = ok(worker(
        &u,
        export_op(table, Some(vec![t(g2)]), 500, ExportMode::Rows),
    ));
    assert_eq!(
        (p2["count"].clone(), p2["more"].clone()),
        (json!(1), json!(true))
    );
    assert_eq!(p2["last"], json!([{ "t": g3 }]));
    let p3 = ok(worker(
        &u,
        export_op(table, Some(vec![t(g3)]), 500, ExportMode::Rows),
    ));
    assert_eq!(
        (p3["count"].clone(), p3["more"].clone()),
        (json!(1), json!(false))
    );
    // Hash mode is not cut by size: one page of all four.
    let h = ok(worker(&u, export_op(table, None, 500, ExportMode::Hash)));
    assert_eq!(
        (h["count"].clone(), h["more"].clone()),
        (json!(4), json!(false))
    );
}

fn principal(seq: u64, grants: Vec<KeyGrant>) -> KeyEntry {
    KeyEntry {
        id: P.into(),
        kind: KeyKind::Principal,
        status: SubjectStatus::Active,
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

fn key(id: &str, seq: u64, status: SubjectStatus, grants: Vec<KeyGrant>) -> KeyEntry {
    KeyEntry {
        id: id.into(),
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

fn grant(bucket: &str, access: Access) -> KeyGrant {
    KeyGrant {
        bucket_id: bucket.into(),
        access,
        expires_at: None,
        prefix: None,
        ip_list: Vec::new(),
    }
}

#[test]
fn the_key_tables_are_hashed_only_and_equal_the_chains_projection() {
    let u = closed_for_the_move();
    fill(&u, &[]);
    let k2 = "AKMOVE0000000000002";
    // The move's direct apply (step 5(e)): a principal, two keys, one of
    // them revoked and then sent again with another status.
    let entries = vec![
        principal(1, vec![grant(B1, Access::Rw), grant(B2, Access::Ro)]),
        key(K, 2, SubjectStatus::Active, vec![grant(B1, Access::Rw)]),
        key(k2, 3, SubjectStatus::Revoked, vec![grant(B2, Access::Ro)]),
        key(k2, 4, SubjectStatus::Active, vec![grant(B1, Access::Ro)]),
    ];
    let a = worker(
        &u,
        UnitOp::ApplyKeys {
            from_seq: 0,
            entries: entries.clone(),
            answers: vec![],
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    let (keys_rows, grant_rows) = chain_key_rows(&entries).unwrap();
    assert_eq!(keys_rows.len(), 3);
    assert_eq!(
        keys_rows[1][2],
        t("revoked"),
        "a revoked subject stays revoked"
    );
    let kt = ExportTable::Keys(KeyTable::UnitKeys);
    let gt = ExportTable::Keys(KeyTable::UnitKeyGrants);
    let hk = ok(worker(&u, export_op(kt, None, 500, ExportMode::Hash)));
    assert_eq!(hk["count"], json!(3));
    assert_eq!(hk["sha256"], json!(hash_rows(kt, &keys_rows).unwrap()));
    let hg = ok(worker(&u, export_op(gt, None, 500, ExportMode::Hash)));
    assert_eq!(hg["count"], json!(grant_rows.len()));
    assert_eq!(hg["sha256"], json!(hash_rows(gt, &grant_rows).unwrap()));
    // In pages too: the second page of the grants after the first's key.
    let first = ok(worker(&u, export_op(gt, None, 2, ExportMode::Hash)));
    assert_eq!(
        first["sha256"],
        json!(hash_rows(gt, &grant_rows[..2]).unwrap())
    );
    let after: Vec<ImportValue> = serde_json::from_value(first["last"].clone()).unwrap();
    let rest = ok(worker(&u, export_op(gt, Some(after), 2, ExportMode::Hash)));
    assert_eq!(
        rest["sha256"],
        json!(hash_rows(gt, &grant_rows[2..]).unwrap())
    );
    // The digest covers the wrap: another secret is another digest.
    let mut other = keys_rows.clone();
    other[0][6] = ImportValue::Blob(vec![2, 0xaa, 0xbc]);
    assert_ne!(hk["sha256"], json!(hash_rows(kt, &other).unwrap()));
    // No key row leaves the unit.
    for table in [kt, gt] {
        let a = worker(&u, export_op(table, None, 10, ExportMode::Rows));
        assert_eq!(
            refusal(&a),
            Some((Refused::Export(ExportRefusal::HashOnly), false))
        );
    }
}

#[test]
fn a_malformed_export_is_refused_and_export_writes_nothing() {
    let u = closed_for_the_move();
    fill(&u, &["a"]);
    let objects = ExportTable::Data(ImportTable::Objects);
    for op in [
        export_op(objects, None, 0, ExportMode::Hash),
        export_op(objects, None, 501, ExportMode::Rows),
        export_op(objects, Some(vec![t(B1)]), 10, ExportMode::Rows),
        export_op(objects, Some(vec![t(B1), N]), 10, ExportMode::Rows),
        export_op(
            objects,
            Some(vec![t(B1), t("a"), t("b")]),
            10,
            ExportMode::Hash,
        ),
        export_op(objects, Some(vec![t(B1), i(1)]), 10, ExportMode::Hash),
        export_op(
            ExportTable::Data(ImportTable::Gc),
            Some(vec![t("5")]),
            10,
            ExportMode::Rows,
        ),
        export_op(
            ExportTable::Data(ImportTable::Articles),
            Some(vec![t("x_1"), b(1)]),
            10,
            ExportMode::Rows,
        ),
    ] {
        assert_eq!(
            refusal(&worker(&u, op)),
            Some((Refused::Export(ExportRefusal::Malformed), false))
        );
    }
    let changes = |u: &Unit<RusqliteSql>| -> i64 {
        u.sql()
            .with_conn(|c| c.query_row("SELECT total_changes()", [], |r| r.get(0)))
            .unwrap()
    };
    let before = changes(&u);
    for table in every_export_table() {
        ok(worker(&u, export_op(table, None, 500, ExportMode::Hash)));
    }
    assert_eq!(changes(&u), before);
    // An export is a Worker call: a request call is refused.
    let a = u.handle(
        &call_on(
            &own(),
            CallKind::Request,
            seqs(S, 0),
            export_op(objects, None, 10, ExportMode::Rows),
        ),
        NOW,
    );
    assert_eq!(refusal(&a), Some((Refused::Unauthenticated, false)));
}

#[test]
fn the_export_and_seal_calls_read_back_from_their_json() {
    let c = call_on(
        &own(),
        CallKind::Worker,
        seqs(S, 0),
        export_op(
            ExportTable::Data(ImportTable::UploadPartExtents),
            Some(vec![t("u_1"), i(2), i(0)]),
            500,
            ExportMode::Rows,
        ),
    );
    let v = serde_json::to_value(&c).unwrap();
    assert_eq!(v["op"]["table"], json!("upload_part_extents"));
    assert_eq!(serde_json::from_value::<UnitCall>(v).unwrap(), c);
    let k = serde_json::json!({
        "name": own(), "kind": "worker", "authenticated": true,
        "op": { "op": "export", "table": "unit_keys", "limit": 5, "mode": "hash" }
    });
    let back: UnitCall = serde_json::from_value(k).unwrap();
    assert!(matches!(
        back.op,
        UnitOp::Export {
            table: ExportTable::Keys(KeyTable::UnitKeys),
            after: None,
            ..
        }
    ));
    // An unknown table, or a unit's own table, does not parse.
    for table in [
        "unit_head",
        "unit_birth",
        "unit_import",
        "unit_gate_report",
        "access_keys",
    ] {
        let bad = serde_json::json!({
            "name": own(), "kind": "worker",
            "op": { "op": "export", "table": table, "limit": 5, "mode": "hash" }
        });
        assert!(serde_json::from_value::<UnitCall>(bad).is_err(), "{table}");
    }
    // A head without `flips` does not parse (AM-29).
    let bad = serde_json::json!({
        "name": own(), "kind": "worker",
        "op": { "op": "import_seal", "since": 4, "tables": [],
                "head": { "seq": 1, "selector": "moving", "to": tenant() } }
    });
    assert!(serde_json::from_value::<UnitCall>(bad).is_err());
}
