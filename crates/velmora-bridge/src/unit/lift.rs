//! The lift, checked inside the unit (`docs/units.md`, "Restore gate";
//! ADR §8.6 step 8, amendments AM-2 and AM-3).
//!
//! The gate's final replay of a restore has a **replay id**: the restore
//! entry's `since_seq` S, the stamp ordinal raised before the restore,
//! and a nonce from the tool. The unit keeps one gate report, for one
//! replay id:
//!
//! - `gate_open(replay_id)` starts the report for that replay. A stored
//!   report of another replay id is discarded with its blocker ids and its
//!   acknowledgements: an old report that a point-in-time restore brought
//!   back never counts.
//! - `gate_blockers(replay_id, list, ids)` adds the ids a list of the
//!   replay holds, in pages of at most [`MAX_PAGE`] ids, so a replay with
//!   any number of blockers can be reported (no total cap).
//! - `gate_report(replay_id, summary)` stores the counts that are not
//!   lists: whether the replay is complete, the totals, and whether its
//!   held rows were classified.
//! - `gate_ack(replay_id, class, ids)` acknowledges blocker ids by name,
//!   in pages of at most [`MAX_PAGE`] ids.
//!
//! **The `sync` that clears `restoring_since` is refused unless
//! [`check`] passes for the stored report and names the same lift:**
//!
//! - the report names the entry being cleared (S);
//! - its ordinal equals the unit's stamp counter, as the gate levelled it;
//! - the lift decision of [`super::gate::lift`] on its findings opens, and
//!   per class the acknowledged ids are exactly the ones that decision
//!   needs: the same count, and the same SHA-256 over the sorted ids with
//!   duplicates removed (UTF-8, each id followed by `\n`);
//! - every usage counter is on (AM-3: a unit born from a `restore` token
//!   starts with them off, and the gate's recount turns them on);
//! - and the `sync` carries the lift record's [`LiftProof`] (its replay
//!   id and those counts and hashes), equal to the one the unit computes.
//!
//! Totals count distinct ids: a list holds each id once, and a total
//! above its list keeps the unit closed (`Unlisted`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::gate::{self, Acknowledged, GateFindings, Lift};
use super::object::poll_once;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result};

/// The most ids one page carries (blockers or acknowledgements).
pub const MAX_PAGE: usize = 100;
/// The longest nonce (est).
pub const MAX_NONCE: usize = 64;
/// The longest id (est).
pub const MAX_ID: usize = 512;

/// The replay a gate report belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayId {
    /// The `since_seq` of the unit's `restoring` entry.
    pub since: u64,
    /// The stamp ordinal raised before the restore.
    pub ordinal: u64,
    pub nonce: String,
}

/// The classes a lift may acknowledge (`gate::Acknowledged`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckClass {
    Damaged,
    HeldMissing,
    Unreadable,
    Unpublishable,
    DamagedUnpublished,
    Twins,
    OtherBucket,
}

impl AckClass {
    pub const ALL: [AckClass; 7] = [
        AckClass::Damaged,
        AckClass::HeldMissing,
        AckClass::Unreadable,
        AckClass::Unpublishable,
        AckClass::DamagedUnpublished,
        AckClass::Twins,
        AckClass::OtherBucket,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AckClass::Damaged => "damaged",
            AckClass::HeldMissing => "held_missing",
            AckClass::Unreadable => "unreadable",
            AckClass::Unpublishable => "unpublishable",
            AckClass::DamagedUnpublished => "damaged_unpublished",
            AckClass::Twins => "twins",
            AckClass::OtherBucket => "other_bucket",
        }
    }

    fn of(self, a: &Acknowledged) -> &BTreeSet<String> {
        match self {
            AckClass::Damaged => &a.damaged,
            AckClass::HeldMissing => &a.held_missing,
            AckClass::Unreadable => &a.unreadable,
            AckClass::Unpublishable => &a.unpublishable,
            AckClass::DamagedUnpublished => &a.damaged_unpublished,
            AckClass::Twins => &a.twins,
            AckClass::OtherBucket => &a.other_bucket,
        }
    }

    fn of_mut(self, a: &mut Acknowledged) -> &mut BTreeSet<String> {
        match self {
            AckClass::Damaged => &mut a.damaged,
            AckClass::HeldMissing => &mut a.held_missing,
            AckClass::Unreadable => &mut a.unreadable,
            AckClass::Unpublishable => &mut a.unpublishable,
            AckClass::DamagedUnpublished => &mut a.damaged_unpublished,
            AckClass::Twins => &mut a.twins,
            AckClass::OtherBucket => &mut a.other_bucket,
        }
    }

    fn parse(s: &str) -> Option<AckClass> {
        AckClass::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// The id lists of a replay's findings (`gate::GateFindings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingList {
    Damaged,
    Unreadable,
    Unpublishable,
    DamagedUnpublished,
    Twins,
    OtherBucket,
    HeldMissing,
    /// Of `held_missing`, the ids a servable generation names, when the
    /// gate classified them.
    HeldMissingLive,
}

impl FindingList {
    pub const ALL: [FindingList; 8] = [
        FindingList::Damaged,
        FindingList::Unreadable,
        FindingList::Unpublishable,
        FindingList::DamagedUnpublished,
        FindingList::Twins,
        FindingList::OtherBucket,
        FindingList::HeldMissing,
        FindingList::HeldMissingLive,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            FindingList::Damaged => "damaged",
            FindingList::Unreadable => "unreadable",
            FindingList::Unpublishable => "unpublishable",
            FindingList::DamagedUnpublished => "damaged_unpublished",
            FindingList::Twins => "twins",
            FindingList::OtherBucket => "other_bucket",
            FindingList::HeldMissing => "held_missing",
            FindingList::HeldMissingLive => "held_missing_live",
        }
    }

    fn parse(s: &str) -> Option<FindingList> {
        FindingList::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// What a replay found besides its id lists.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateSummary {
    /// The replay reached its end.
    pub complete: bool,
    pub damaged_total: u64,
    pub other_bucket_total: u32,
    pub held_missing_total: u32,
    /// The held rows were classified: `held_missing_live` is their live
    /// class. Otherwise every held row counts as live.
    pub classified: bool,
}

/// One class of a lift: how many ids it names and their hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassProof {
    pub count: u64,
    pub sha256: String,
}

/// What a lift record carries, and the `sync` that lifts names: the
/// replay id and, per class it acknowledges, the count and hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiftProof {
    pub replay_id: ReplayId,
    #[serde(default)]
    pub acknowledged: BTreeMap<AckClass, ClassProof>,
}

/// Why a gate call or a lift was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateRefusal {
    /// The unit is not closed under the replay id's entry.
    NotRestoring,
    /// No report, or the report is of another replay.
    NoReport,
    /// The report's ordinal is not the unit's stamp counter.
    StampNotLevelled,
    /// The findings keep the unit closed.
    Closed,
    /// The acknowledged ids are not exactly the ones the lift needs.
    AckMismatch,
    /// A usage counter is off (AM-3).
    CountersOff,
    /// The `sync` names no lift, or another one than the unit computes.
    ProofMismatch,
    /// A page above [`MAX_PAGE`] ids, an empty or long id, or a bad nonce.
    Malformed,
}

/// SHA-256 over the sorted ids with duplicates removed, each followed
/// by `\n`, as lowercase hex.
pub fn ids_hash<'a>(ids: impl IntoIterator<Item = &'a String>) -> String {
    let set: BTreeSet<&String> = ids.into_iter().collect();
    let mut h = Sha256::new();
    for id in set {
        h.update(id.as_bytes());
        h.update(b"\n");
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn valid(id: &ReplayId) -> bool {
    !id.nonce.is_empty() && id.nonce.len() <= MAX_NONCE
}

fn page_ok(ids: &[String]) -> bool {
    ids.len() <= MAX_PAGE && ids.iter().all(|i| !i.is_empty() && i.len() <= MAX_ID)
}

/// The stored report: its replay id and summary.
fn stored<S: Sql>(sql: &S) -> Result<Option<(ReplayId, GateSummary)>> {
    let rows = poll_once(sql.query(
        "SELECT since_seq, ordinal, nonce, summary FROM unit_gate_report WHERE id = 1",
        &[],
    ))??;
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    let (SqlValue::Int(since), SqlValue::Int(ordinal), SqlValue::Text(nonce), SqlValue::Text(f)) =
        (&r[0], &r[1], &r[2], &r[3])
    else {
        return Err(decode("unit_gate_report"));
    };
    let summary: GateSummary =
        serde_json::from_str(f).map_err(|_| decode("unit_gate_report summary"))?;
    Ok(Some((
        ReplayId {
            since: u64::try_from(*since).map_err(|_| decode("since"))?,
            ordinal: u64::try_from(*ordinal).map_err(|_| decode("ordinal"))?,
            nonce: nonce.clone(),
        },
        summary,
    )))
}

/// The findings of the stored report: its summary and its id lists.
fn findings<S: Sql>(sql: &S, summary: &GateSummary) -> Result<GateFindings> {
    let rows = poll_once(sql.query(
        "SELECT list, id FROM unit_gate_blockers ORDER BY list, id",
        &[],
    ))??;
    let mut lists: BTreeMap<FindingList, Vec<String>> = BTreeMap::new();
    for r in rows {
        let (SqlValue::Text(l), SqlValue::Text(id)) = (&r[0], &r[1]) else {
            return Err(decode("unit_gate_blockers"));
        };
        let list = FindingList::parse(l).ok_or_else(|| decode("unit_gate_blockers list"))?;
        lists.entry(list).or_default().push(id.clone());
    }
    let mut take = |l: FindingList| lists.remove(&l).unwrap_or_default();
    Ok(GateFindings {
        complete: summary.complete,
        damaged_total: summary.damaged_total,
        damaged: take(FindingList::Damaged),
        unreadable: take(FindingList::Unreadable),
        unpublishable: take(FindingList::Unpublishable),
        damaged_unpublished: take(FindingList::DamagedUnpublished),
        twins: take(FindingList::Twins),
        other_bucket_total: summary.other_bucket_total,
        other_bucket: take(FindingList::OtherBucket),
        held_missing_total: summary.held_missing_total,
        held_missing: take(FindingList::HeldMissing),
        held_missing_live: summary
            .classified
            .then(|| take(FindingList::HeldMissingLive)),
    })
}

fn acks<S: Sql>(sql: &S) -> Result<Acknowledged> {
    let rows = poll_once(sql.query("SELECT class, id FROM unit_gate_acks", &[]))??;
    let mut a = Acknowledged::default();
    for r in rows {
        let (SqlValue::Text(c), SqlValue::Text(id)) = (&r[0], &r[1]) else {
            return Err(decode("unit_gate_acks"));
        };
        let class = AckClass::parse(c).ok_or_else(|| decode("unit_gate_acks class"))?;
        class.of_mut(&mut a).insert(id.clone());
    }
    Ok(a)
}

/// The report is of `id`, and the unit is closed under its entry.
fn bound<S: Sql>(
    sql: &S,
    restoring_since: Option<u64>,
    id: &ReplayId,
) -> Result<std::result::Result<(), GateRefusal>> {
    if restoring_since != Some(id.since) {
        return Ok(Err(GateRefusal::NotRestoring));
    }
    if !stored(sql)?.is_some_and(|(have, _)| have == *id) {
        return Ok(Err(GateRefusal::NoReport));
    }
    Ok(Ok(()))
}

/// Starts the report of `id`, discarding any other. Inside the caller's
/// transaction; `restoring_since` is the unit's.
pub fn open<S: Sql>(
    sql: &S,
    restoring_since: Option<u64>,
    id: &ReplayId,
) -> Result<std::result::Result<bool, GateRefusal>> {
    if !valid(id) {
        return Ok(Err(GateRefusal::Malformed));
    }
    if restoring_since != Some(id.since) {
        return Ok(Err(GateRefusal::NotRestoring));
    }
    if stored(sql)?.is_some_and(|(have, _)| have == *id) {
        return Ok(Ok(false));
    }
    clear(sql)?;
    poll_once(sql.exec(
        "INSERT INTO unit_gate_report(id, since_seq, ordinal, nonce, summary) \
         VALUES (1, ?1, ?2, ?3, ?4)",
        &[
            int(id.since)?,
            int(id.ordinal)?,
            SqlValue::Text(id.nonce.clone()),
            SqlValue::Text(json_text(&GateSummary::default())?),
        ],
    ))??;
    Ok(Ok(true))
}

/// Stores the summary of the replay `id`.
pub fn report<S: Sql>(
    sql: &S,
    restoring_since: Option<u64>,
    id: &ReplayId,
    summary: &GateSummary,
) -> Result<std::result::Result<(), GateRefusal>> {
    if let Err(r) = bound(sql, restoring_since, id)? {
        return Ok(Err(r));
    }
    poll_once(sql.exec(
        "UPDATE unit_gate_report SET summary = ?1 WHERE id = 1",
        &[SqlValue::Text(json_text(summary)?)],
    ))??;
    Ok(Ok(()))
}

/// Adds one page of ids of one list of the replay `id`.
pub fn blockers<S: Sql>(
    sql: &S,
    restoring_since: Option<u64>,
    id: &ReplayId,
    list: FindingList,
    ids: &[String],
) -> Result<std::result::Result<(), GateRefusal>> {
    if !page_ok(ids) {
        return Ok(Err(GateRefusal::Malformed));
    }
    if let Err(r) = bound(sql, restoring_since, id)? {
        return Ok(Err(r));
    }
    for i in ids {
        poll_once(sql.exec(
            "INSERT INTO unit_gate_blockers(list, id) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            &[
                SqlValue::Text(list.as_str().into()),
                SqlValue::Text(i.clone()),
            ],
        ))??;
    }
    Ok(Ok(()))
}

/// Acknowledges one page of ids of one class for the replay `id`.
pub fn ack<S: Sql>(
    sql: &S,
    restoring_since: Option<u64>,
    id: &ReplayId,
    class: AckClass,
    ids: &[String],
) -> Result<std::result::Result<(), GateRefusal>> {
    if !page_ok(ids) {
        return Ok(Err(GateRefusal::Malformed));
    }
    if let Err(r) = bound(sql, restoring_since, id)? {
        return Ok(Err(r));
    }
    for i in ids {
        poll_once(sql.exec(
            "INSERT INTO unit_gate_acks(class, id) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            &[
                SqlValue::Text(class.as_str().into()),
                SqlValue::Text(i.clone()),
            ],
        ))??;
    }
    Ok(Ok(()))
}

/// Forgets the report, its blocker ids and its acknowledgements.
pub fn clear<S: Sql>(sql: &S) -> Result<()> {
    poll_once(sql.exec("DELETE FROM unit_gate_acks", &[]))??;
    poll_once(sql.exec("DELETE FROM unit_gate_blockers", &[]))??;
    poll_once(sql.exec("DELETE FROM unit_gate_report", &[]))??;
    Ok(())
}

/// The lift check (module doc), but for the proof the `sync` names.
/// `Ok(proof)`: what the lift record must carry.
pub fn check<S: Sql>(
    sql: &S,
    restoring_since: Option<u64>,
) -> Result<std::result::Result<LiftProof, GateRefusal>> {
    let Some(since) = restoring_since else {
        return Ok(Err(GateRefusal::NotRestoring));
    };
    let Some((id, summary)) = stored(sql)? else {
        return Ok(Err(GateRefusal::NoReport));
    };
    if id.since != since {
        return Ok(Err(GateRefusal::NoReport));
    }
    if stamp_counter(sql)? != Some(id.ordinal) {
        return Ok(Err(GateRefusal::StampNotLevelled));
    }
    let found = findings(sql, &summary)?;
    let acked = acks(sql)?;
    let needed = match gate::lift(&found, &acked) {
        Lift::Clean => Acknowledged::default(),
        Lift::Acknowledged { named } => named,
        Lift::Closed { .. } => return Ok(Err(GateRefusal::Closed)),
    };
    let mut acknowledged = BTreeMap::new();
    for c in AckClass::ALL {
        let (need, have) = (c.of(&needed), c.of(&acked));
        if need.len() != have.len() || ids_hash(need) != ids_hash(have) {
            return Ok(Err(GateRefusal::AckMismatch));
        }
        if !have.is_empty() {
            acknowledged.insert(
                c,
                ClassProof {
                    count: have.len() as u64,
                    sha256: ids_hash(have),
                },
            );
        }
    }
    if !counters_on(sql)? {
        return Ok(Err(GateRefusal::CountersOff));
    }
    Ok(Ok(LiftProof {
        replay_id: id,
        acknowledged,
    }))
}

/// The check, and that `named` (the lift the `sync` carries) is its
/// proof.
pub fn check_named<S: Sql>(
    sql: &S,
    restoring_since: Option<u64>,
    named: Option<&LiftProof>,
) -> Result<std::result::Result<(), GateRefusal>> {
    let proof = match check(sql, restoring_since)? {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    if named != Some(&proof) {
        return Ok(Err(GateRefusal::ProofMismatch));
    }
    Ok(Ok(()))
}

/// The stored report and what a lift needs, for `gate_status`.
pub fn status<S: Sql>(sql: &S, restoring_since: Option<u64>) -> Result<Value> {
    let report = stored(sql)?;
    let decision = match &report {
        Some((_, summary)) => {
            serde_json::to_value(gate::lift(&findings(sql, summary)?, &acks(sql)?))
                .map_err(|_| BridgeError::Invalid("unit: lift decision"))?
        }
        None => Value::Null,
    };
    let lift = match check(sql, restoring_since)? {
        Ok(proof) => json!({ "ok": proof }),
        Err(why) => json!({ "refused": why }),
    };
    Ok(json!({
        "replay_id": report.as_ref().map(|(id, _)| id),
        "decision": decision,
        "stamp_counter": stamp_counter(sql)?,
        "counters_on": counters_on(sql)?,
        "lift": lift,
    }))
}

fn stamp_counter<S: Sql>(sql: &S) -> Result<Option<u64>> {
    let rows = poll_once(sql.query("SELECT counter FROM rollback_stamp WHERE id = 1", &[]))??;
    match rows.first().and_then(|r| r.first()) {
        None => Ok(None),
        Some(SqlValue::Int(n)) => Ok(u64::try_from(*n).ok()),
        Some(_) => Err(decode("rollback_stamp")),
    }
}

fn counters_on<S: Sql>(sql: &S) -> Result<bool> {
    let rows = poll_once(sql.query(
        "SELECT all_x = 1 AND all_o = 1 AND all_g = 1 FROM usage_global WHERE id = 1",
        &[],
    ))??;
    Ok(matches!(
        rows.first().and_then(|r| r.first()),
        Some(SqlValue::Int(1))
    ))
}

fn json_text<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|_| BridgeError::Invalid("unit: gate summary"))
}

fn int(n: u64) -> Result<SqlValue> {
    i64::try_from(n)
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("number out of range"))
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}
