//! The unit side of bucket records (`docs/units.md`, "Buckets"; ADR §2.4
//! rule 5, §6.2; amendment AM-57).
//!
//! A managed tenant's bucket rows come only from its tenant chain. The
//! Worker's `sync` to a unit carries, besides the head's numbers and
//! state, the bucket changes of the tenant records it moves past, for the
//! buckets placed on this unit, in seq order ([`BucketChange`]), and the
//! list of bucket ids the head places on this unit. In the `sync`'s
//! transaction the unit calls [`apply`] and then [`placement_check`]:
//!
//! 1. `created`: makes the bucket's row from the record (id, name,
//!    creator, the wrapped BDK and its key version, `created_at` = the
//!    record's `written_at`) and calls [`reserve::bucket_created`], which
//!    turns the reservation bound to `grant_seq`, if one is left,
//!    `applied`. A row that exists with the same id and name changes
//!    nothing; one with the same id and another name, or another id with
//!    the name, is a broken chain: refused (`created_conflict`, alarm).
//!    The row keeps `grant_seq` (`unit_bucket_grant`), so the finisher's
//!    `bucket_binding(K)` answers `created` from it once the reservation
//!    is gone (AM-56), and every key's grant on the bucket, applied before
//!    the row existed, is served from now on.
//! 2. `dropped`: drops the row if it is `closing` and holds nothing of
//!    the bucket. A row that is not closing (a restore or a rollback took
//!    the close back) is marked closing first. A row kept because it
//!    still holds something is renamed `~dropped/<bucket_id>`, so that a
//!    later `created` can take the name; the rest of the `sync` applies,
//!    and the unit pages `drop_not_closed` for the operator. No object is
//!    deleted for it.
//!
//!    Step 2a: [`sweep_closing`], on every `sync` (after `apply`, before
//!    the check) and on the gate's last call after §8.6 step 7.4, drops
//!    each closing row the head does not place once it holds nothing.
//! 3. `unplaced` (`UnplaceMovedBuckets`, AM-23): nothing while the unit's
//!    `restoring` entry is set (the 30-day copy keeps its rows until the
//!    day-30 `deleteAll()`); otherwise each bucket as in 2.
//! 4. [`placement_check`]: the unit's bucket rows, less every closing row
//!    the head does not place, equal the head's list. Run only while the
//!    `restoring` entry is not set, and by the `sync` that clears it. A
//!    difference refuses the whole `sync` (`placements_off`, alarm).
//!
//! "Holds nothing of the bucket" is the catalogue's own rule for a
//! bucket delete (`sql::auth::delete_bucket`): no generation, object,
//! key floor, upload or extent names it. It is stricter than "no object
//! and no open upload": a bucket whose deleted objects still have
//! generations or extents waiting for the collector stays closing until
//! they are gone, so no row that names data on the backbone is left
//! without its bucket (and its BDK).
//!
//! Bucket delete is close, then record, then drop: [`close`] (the
//! handler's `bucket_close` call) answers `bucket_not_empty` if the
//! bucket holds anything, and otherwise marks it closing, so every write
//! into it answers `NoSuchBucket` from then on ([`is_closing`]); then the
//! `DropBucket` record; then `sync`. A closing bucket whose record never
//! came stays closed and empty, and its name taken, until a delete retry
//! completes it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::keys;
use super::object::poll_once;
use super::reserve;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result, UnixMs};

/// The most bucket rows a unit holds (est): a bucket create's
/// reservation is refused `cap_reached` at it, so the head's placement
/// list for the unit, which every `sync` carries whole, never outgrows
/// [`check_shape`]'s bound.
pub const MAX_PLACED: usize = 10_000;
/// The most bucket changes one `sync` may carry (est), and the most ids
/// all its `unplaced` changes name together: a restore to an older
/// bookmark at the create cap (50 a day for 30 days, with their drops)
/// stays inside it.
pub const MAX_CHANGES: usize = 10_000;

/// One bucket change of a tenant record, as the Worker read and verified
/// it (`name` and `bdk_wrapped` come from the record's private part).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub enum BucketChange {
    Created {
        seq: u64,
        bucket_id: String,
        grant_seq: u64,
        creator: String,
        name: String,
        #[serde(with = "b64")]
        bdk_wrapped: Vec<u8>,
        tk_version: u32,
        /// The record's `written_at`: the row's `created_at`.
        written_at: u64,
    },
    Dropped {
        seq: u64,
        bucket_id: String,
    },
    Unplaced {
        seq: u64,
        buckets: Vec<String>,
    },
    /// Several placements on this unit that one record removed outside a
    /// `restoring` entry (an operator's `SetUnits`): each is dropped as a
    /// `dropped` is, whatever entry the unit holds when it applies them
    /// (an `unplaced` keeps its rows under an entry). Built by the
    /// Worker (L2, `unit_lease::placements`).
    Removed {
        seq: u64,
        buckets: Vec<String>,
    },
}

impl BucketChange {
    pub fn seq(&self) -> u64 {
        match self {
            BucketChange::Created { seq, .. }
            | BucketChange::Dropped { seq, .. }
            | BucketChange::Unplaced { seq, .. }
            | BucketChange::Removed { seq, .. } => *seq,
        }
    }
}

/// Shows no name and no wrap.
impl std::fmt::Debug for BucketChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BucketChange::Created {
                seq,
                bucket_id,
                grant_seq,
                ..
            } => f
                .debug_struct("Created")
                .field("seq", seq)
                .field("bucket_id", bucket_id)
                .field("grant_seq", grant_seq)
                .finish_non_exhaustive(),
            BucketChange::Dropped { seq, bucket_id } => f
                .debug_struct("Dropped")
                .field("seq", seq)
                .field("bucket_id", bucket_id)
                .finish(),
            BucketChange::Unplaced { seq, buckets } => f
                .debug_struct("Unplaced")
                .field("seq", seq)
                .field("buckets", &buckets.len())
                .finish(),
            BucketChange::Removed { seq, buckets } => f
                .debug_struct("Removed")
                .field("seq", seq)
                .field("buckets", &buckets.len())
                .finish(),
        }
    }
}

/// Why a bucket call or a `sync`'s bucket part was refused. Nothing of
/// the call is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketRefusal {
    /// `bucket_close` on a bucket that holds something:
    /// `409 bucket_not_empty`.
    NotEmpty,
    /// `bucket_close` on a bucket id the unit holds no row for:
    /// `404 bucket_not_found`.
    NotFound,
    /// The unit's bucket rows differ from the head's placement list after
    /// the changes (AM-57): the whole `sync` is refused, with an alarm.
    /// The Worker reads the chain again and sends it once more; the same
    /// refusal again stops and pages.
    PlacementsOff,
    /// A `created` names an id the unit holds under another name, or a
    /// name another id holds: a broken chain (alarm).
    CreatedConflict,
    /// Out of seq order, too many, or a value that cannot be one.
    Malformed,
}

impl BucketRefusal {
    /// Whether the refusal pages.
    pub fn alarm(self) -> bool {
        matches!(
            self,
            BucketRefusal::PlacementsOff | BucketRefusal::CreatedConflict
        )
    }
}

/// What [`apply`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BucketsApplied {
    /// Rows made by a `created`.
    pub created: u64,
    /// Reservations a `created` turned `applied`.
    pub reserved: u64,
    /// Rows dropped.
    pub dropped: u64,
    /// Rows a `dropped` or `unplaced` reached that still hold something:
    /// kept closing under `~dropped/<bucket_id>`, and paged
    /// `drop_not_closed` (the `sync` answer carries them for the Worker's
    /// page).
    pub drop_not_closed: Vec<String>,
}

/// `bucket_close(bucket_id)` (ADR §6.2): in the caller's transaction,
/// `not_empty` if the bucket holds anything, otherwise the row is marked
/// closing (once; a closing row answers the same). `true`: newly closed.
pub fn close<S: Sql>(
    sql: &S,
    bucket_id: &str,
    now: UnixMs,
) -> Result<std::result::Result<bool, BucketRefusal>> {
    if !reserve::valid_id(bucket_id) {
        return Ok(Err(BucketRefusal::Malformed));
    }
    if !bucket_exists(sql, bucket_id)? {
        return Ok(Err(BucketRefusal::NotFound));
    }
    if holds_anything(sql, bucket_id)? {
        return Ok(Err(BucketRefusal::NotEmpty));
    }
    let n = poll_once(sql.exec(
        "INSERT OR IGNORE INTO unit_bucket_closing(bucket_id, closed_at) VALUES (?1, ?2)",
        &[SqlValue::Text(bucket_id.into()), SqlValue::Int(now.0)],
    ))??;
    Ok(Ok(n == 1))
}

/// Whether the bucket is closing: every write into it answers
/// `NoSuchBucket` (the request path asks this before a write).
pub fn is_closing<S: Sql>(sql: &S, bucket_id: &str) -> Result<bool> {
    Ok(!poll_once(sql.query(
        "SELECT 1 FROM unit_bucket_closing WHERE bucket_id = ?1",
        &[SqlValue::Text(bucket_id.into())],
    ))??
    .is_empty())
}

/// The shape of a `sync`'s bucket part, before anything is read: changes
/// in seq order (strictly rising), above the unit's `state_seq`, at or
/// below the head's; ids and names well formed; at most [`MAX_CHANGES`]
/// changes and [`MAX_PLACED`] ids in a list.
pub fn check_shape(
    changes: &[BucketChange],
    placed: &[String],
    from_seq: u64,
    to_seq: u64,
) -> std::result::Result<(), BucketRefusal> {
    use BucketRefusal::Malformed;
    if changes.len() > MAX_CHANGES || placed.len() > MAX_PLACED {
        return Err(Malformed);
    }
    let mut last = from_seq;
    let mut unplaced = 0usize;
    for c in changes {
        if c.seq() <= last || c.seq() > to_seq || i64::try_from(c.seq()).is_err() {
            return Err(Malformed);
        }
        if let BucketChange::Unplaced { buckets, .. } | BucketChange::Removed { buckets, .. } = c {
            unplaced = unplaced.saturating_add(buckets.len());
            if unplaced > MAX_CHANGES {
                return Err(Malformed);
            }
        }
        last = c.seq();
        match c {
            BucketChange::Created {
                bucket_id,
                grant_seq,
                creator,
                name,
                bdk_wrapped,
                written_at,
                ..
            } => {
                if !reserve::valid_id(bucket_id)
                    || !reserve::valid_id(creator)
                    || !reserve::valid_bucket_name(name)
                    || bdk_wrapped.is_empty()
                    || bdk_wrapped.len() > 256
                    || i64::try_from(*grant_seq).is_err()
                    || i64::try_from(*written_at).is_err()
                {
                    return Err(Malformed);
                }
            }
            BucketChange::Dropped { bucket_id, .. } => {
                if !reserve::valid_id(bucket_id) {
                    return Err(Malformed);
                }
            }
            BucketChange::Unplaced { buckets, .. } | BucketChange::Removed { buckets, .. } => {
                if buckets.is_empty()
                    || buckets.len() > MAX_PLACED
                    || !buckets.iter().all(|b| reserve::valid_id(b))
                {
                    return Err(Malformed);
                }
            }
        }
    }
    let unique: BTreeSet<&str> = placed.iter().map(String::as_str).collect();
    if unique.len() != placed.len() || !placed.iter().all(|b| reserve::valid_id(b)) {
        return Err(Malformed);
    }
    Ok(())
}

/// Applies `changes` (already shape-checked, [`check_shape`]) in the
/// caller's transaction. `restoring`: the unit's `restoring` entry is
/// set, so an `unplaced` removes nothing. A refusal leaves the caller to
/// roll the whole `sync` back.
pub fn apply<S: Sql>(
    sql: &S,
    changes: &[BucketChange],
    restoring: bool,
    now: UnixMs,
) -> Result<std::result::Result<BucketsApplied, BucketRefusal>> {
    let mut done = BucketsApplied::default();
    for c in changes {
        match c {
            BucketChange::Created {
                bucket_id,
                grant_seq,
                creator,
                name,
                bdk_wrapped,
                tk_version,
                written_at,
                ..
            } => {
                match existing(sql, bucket_id, name, *grant_seq)? {
                    Existing::Same => {}
                    Existing::Conflict => return Ok(Err(BucketRefusal::CreatedConflict)),
                    Existing::None => {
                        poll_once(sql.exec(
                            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, \
                               created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            &[
                                SqlValue::Text(bucket_id.clone()),
                                SqlValue::Text(name.clone()),
                                SqlValue::Text(creator.clone()),
                                SqlValue::Blob(bdk_wrapped.clone()),
                                SqlValue::Int(i64::from(*tk_version)),
                                SqlValue::Int(int(*written_at)?),
                            ],
                        ))??;
                        poll_once(sql.exec(
                            "INSERT INTO unit_bucket_grant(bucket_id, grant_seq) VALUES (?1, ?2)",
                            &[
                                SqlValue::Text(bucket_id.clone()),
                                SqlValue::Int(int(*grant_seq)?),
                            ],
                        ))??;
                        // The keys' grants on it were applied before the
                        // row existed (`sync` follows the key chain): they
                        // are served from now on.
                        keys::project_buckets(sql, std::slice::from_ref(bucket_id))?;
                        done.created += 1;
                    }
                }
                // A reservation gone (swept, or taken back by a restore)
                // still has its row made from the record.
                if reserve::bucket_created(sql, *grant_seq, bucket_id, None, now)? {
                    done.reserved += 1;
                }
            }
            BucketChange::Dropped { bucket_id, .. } => {
                drop_row(sql, bucket_id, now, &mut done)?;
            }
            BucketChange::Unplaced { buckets, .. } => {
                if restoring {
                    continue;
                }
                for b in buckets {
                    drop_row(sql, b, now, &mut done)?;
                }
            }
            BucketChange::Removed { buckets, .. } => {
                for b in buckets {
                    drop_row(sql, b, now, &mut done)?;
                }
            }
        }
    }
    Ok(Ok(done))
}

/// AM-57 step 4: whether the unit's bucket rows, less every closing row
/// whose id `placed` does not hold, equal `placed`. The caller runs it
/// only while the unit's `restoring` entry is not set, and in the `sync`
/// that clears it.
pub fn placement_check<S: Sql>(sql: &S, placed: &[String]) -> Result<bool> {
    let want: BTreeSet<&str> = placed.iter().map(String::as_str).collect();
    let mut held = BTreeSet::new();
    for (id, is_closing) in rows(sql)? {
        if !is_closing || want.contains(id.as_str()) {
            held.insert(id);
        }
    }
    Ok(held.len() == want.len() && held.iter().all(|id| want.contains(id.as_str())))
}

/// AM-57 step 2a: drops each closing row whose id `placed` does not hold
/// once it holds nothing. Run on every `sync` after [`apply`] and before
/// [`placement_check`], and on the gate's last call after §8.6 step 7.4.
/// Answers the rows dropped.
pub fn sweep_closing<S: Sql>(sql: &S, placed: &[String]) -> Result<u64> {
    let want: BTreeSet<&str> = placed.iter().map(String::as_str).collect();
    let mut dropped = 0;
    for (id, is_closing) in rows(sql)? {
        if is_closing && !want.contains(id.as_str()) && !holds_anything(sql, &id)? {
            delete_row(sql, &id)?;
            dropped += 1;
        }
    }
    Ok(dropped)
}

/// Every bucket row's id, and whether it is closing.
fn rows<S: Sql>(sql: &S) -> Result<Vec<(String, bool)>> {
    let rows = poll_once(sql.query(
        "SELECT b.id, c.bucket_id IS NOT NULL FROM buckets b \
           LEFT JOIN unit_bucket_closing c ON c.bucket_id = b.id ORDER BY b.id",
        &[],
    ))??;
    rows.into_iter()
        .map(|r| match (r.first(), r.get(1)) {
            (Some(SqlValue::Text(id)), Some(SqlValue::Int(c))) => Ok((id.clone(), *c != 0)),
            _ => Err(decode("buckets id")),
        })
        .collect()
}

/// The number of bucket rows the unit holds.
pub fn count<S: Sql>(sql: &S) -> Result<u64> {
    let rows = poll_once(sql.query("SELECT count(*) FROM buckets", &[]))??;
    match rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Int(n)) => u64::try_from(*n).map_err(|_| decode("bucket count")),
        _ => Err(decode("bucket count")),
    }
}

/// The bucket row made from the `bucket_created` record whose creator
/// grant is at `grant_seq`, if the unit holds it (AM-56).
pub fn by_grant_seq<S: Sql>(sql: &S, grant_seq: u64) -> Result<Option<String>> {
    let rows = poll_once(sql.query(
        "SELECT bucket_id FROM unit_bucket_grant WHERE grant_seq = ?1",
        &[SqlValue::Int(int(grant_seq)?)],
    ))??;
    match rows.into_iter().next().and_then(|r| r.into_iter().next()) {
        None => Ok(None),
        Some(SqlValue::Text(id)) => Ok(Some(id)),
        Some(_) => Err(decode("unit_bucket_grant")),
    }
}

enum Existing {
    None,
    Same,
    Conflict,
}

/// Whether a `created`'s row exists: the same (id and name, and its
/// `grant_seq` if kept), none, or a conflict (another name for the id,
/// the name for another id, or the `grant_seq` another row holds).
fn existing<S: Sql>(sql: &S, bucket_id: &str, name: &str, grant_seq: u64) -> Result<Existing> {
    if by_grant_seq(sql, grant_seq)?.is_some_and(|other| other != bucket_id) {
        return Ok(Existing::Conflict);
    }
    let rows = poll_once(sql.query(
        "SELECT id, name FROM buckets WHERE id = ?1 OR name = ?2",
        &[
            SqlValue::Text(bucket_id.into()),
            SqlValue::Text(name.into()),
        ],
    ))??;
    let mut found = Existing::None;
    for r in rows {
        match (r.first(), r.get(1)) {
            (Some(SqlValue::Text(id)), Some(SqlValue::Text(n))) if id == bucket_id && n == name => {
                found = Existing::Same;
            }
            (Some(SqlValue::Text(_)), Some(SqlValue::Text(_))) => return Ok(Existing::Conflict),
            _ => return Err(decode("buckets row")),
        }
    }
    Ok(found)
}

/// AM-57 step 2 for one bucket id: absent, nothing; otherwise closing
/// (marked now if it was not), then dropped if it holds nothing, or kept,
/// renamed `~dropped/<bucket_id>`, and paged.
fn drop_row<S: Sql>(
    sql: &S,
    bucket_id: &str,
    now: UnixMs,
    done: &mut BucketsApplied,
) -> Result<()> {
    if !bucket_exists(sql, bucket_id)? {
        return Ok(());
    }
    poll_once(sql.exec(
        "INSERT OR IGNORE INTO unit_bucket_closing(bucket_id, closed_at) VALUES (?1, ?2)",
        &[SqlValue::Text(bucket_id.into()), SqlValue::Int(now.0)],
    ))??;
    if holds_anything(sql, bucket_id)? {
        // The head freed the name: a later `created` may take it. No
        // bucket name starts with `~`, so the renamed row meets none.
        poll_once(sql.exec(
            "UPDATE buckets SET name = '~dropped/' || id WHERE id = ?1",
            &[SqlValue::Text(bucket_id.into())],
        ))??;
        done.drop_not_closed.push(bucket_id.to_string());
        return Ok(());
    }
    delete_row(sql, bucket_id)?;
    done.dropped += 1;
    Ok(())
}

/// As the catalogue's bucket delete: its grants, then the row (its
/// closing and grant rows go with it).
fn delete_row<S: Sql>(sql: &S, bucket_id: &str) -> Result<()> {
    for text in [
        "DELETE FROM grants WHERE bucket_id = ?1",
        "DELETE FROM unit_bucket_closing WHERE bucket_id = ?1",
        "DELETE FROM unit_bucket_grant WHERE bucket_id = ?1",
        "DELETE FROM buckets WHERE id = ?1",
    ] {
        poll_once(sql.exec(text, &[SqlValue::Text(bucket_id.into())]))??;
    }
    Ok(())
}

fn bucket_exists<S: Sql>(sql: &S, bucket_id: &str) -> Result<bool> {
    super::keys::bucket_exists(sql, bucket_id)
}

/// The catalogue's rule for a bucket delete: a generation, an object, a
/// key floor, an upload or an extent names the bucket.
fn holds_anything<S: Sql>(sql: &S, bucket_id: &str) -> Result<bool> {
    let rows = poll_once(sql.query(
        "SELECT EXISTS (SELECT 1 FROM generations WHERE bucket_id = ?1) \
             OR EXISTS (SELECT 1 FROM objects WHERE bucket_id = ?1) \
             OR EXISTS (SELECT 1 FROM key_floors WHERE bucket_id = ?1) \
             OR EXISTS (SELECT 1 FROM uploads WHERE bucket_id = ?1) \
             OR EXISTS (SELECT 1 FROM extents WHERE bucket_id = ?1)",
        &[SqlValue::Text(bucket_id.into())],
    ))??;
    match rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Int(n)) => Ok(*n != 0),
        _ => Err(decode("bucket in use")),
    }
}

fn int(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| BridgeError::Invalid("number out of range"))
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}

mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}
