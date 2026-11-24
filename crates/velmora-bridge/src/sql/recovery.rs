//! Catalogue statements of the recovery write path (DESIGN §A.8): the
//! delete that a tombstone can replay, and the extent rows a multipart
//! Complete records before it publishes.

use super::objects::{
    extent_cols, extent_row, guard_precondition, retire_live_in, text, Cols, Stmt,
};
use super::replay::guard_no_replay;
use super::SqlCatalog;
use crate::ports::{Dialect, Sql, SqlValue, UploadTarget};
use crate::types::{
    BridgeError, BucketId, GenerationId, GenerationState, PartExtent, Precondition, Result, UnixMs,
};

/// Retires the live generation of `(bucket, key)` if its id sorts before
/// `before`. One batch: the guard and the delete see the same pointer.
/// `client` = the delete of a client, which changes nothing while a
/// replay is under way; the replay itself applies its tombstones without
/// that guard.
pub(super) async fn delete_object_before<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
    before: &GenerationId,
    condition: Option<&Precondition>,
    now: UnixMs,
    client: bool,
) -> Result<bool> {
    let mut stmts = Vec::new();
    if client {
        stmts.push(guard_no_replay());
    }
    delete_before(
        c.sql.dialect(),
        &mut stmts,
        (bucket, key),
        before,
        condition,
        now,
        client,
    );
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(true),
        Err(BridgeError::GuardFailed) => Ok(false),
        Err(e) => Err(e),
    }
}

/// [`delete_object_before`] of a client for every `(key, before, now)`,
/// each key once, as one batch: the statements of that call for each
/// key, in the order given, under one guard against a replay. A guard
/// that fails for one key leaves every key as it was.
pub(super) async fn delete_objects_before<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    deletes: &[(&str, &GenerationId, UnixMs)],
) -> Result<bool> {
    if deletes.is_empty() {
        return Ok(true);
    }
    let mut stmts = vec![guard_no_replay()];
    for (key, before, now) in deletes {
        delete_before(
            c.sql.dialect(),
            &mut stmts,
            (bucket, key),
            before,
            None,
            *now,
            true,
        );
    }
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(true),
        Err(BridgeError::GuardFailed) => Ok(false),
        Err(e) => Err(e),
    }
}

/// The statements that retire the live generation of `(bucket, key)` if
/// its id sorts before `before`, without the guard against a replay.
fn delete_before(
    dialect: Dialect,
    stmts: &mut Vec<Stmt>,
    (bucket, key): (&BucketId, &str),
    before: &GenerationId,
    condition: Option<&Precondition>,
    now: UnixMs,
    client: bool,
) {
    if client {
        // A floor above the tombstone is a write that began after the
        // tombstone was chosen. Its record sorts after the tombstone, so
        // a replay would publish it over this delete; and where it is
        // held to the object this delete removes, it must find the
        // delete in its way (the floor this batch leaves below). The
        // caller comes back with a tombstone above that id.
        stmts.push((
            GUARD_DELETE_FLOOR,
            vec![text(bucket.as_str()), text(key), text(before.as_str())],
        ));
    }
    stmts.extend(condition.map(|c| guard_precondition(bucket, key, c)));
    stmts.push((
        GUARD_DELETE_POINTER,
        vec![text(bucket.as_str()), text(key), text(before.as_str())],
    ));
    // The service raised the floor to the tombstone before it stored
    // the record. Here again for a caller that applies a tombstone it
    // did not write; rolled back with the batch when nothing is deleted.
    stmts.push((
        dialect.pick(RAISE_TOMBSTONE, RAISE_TOMBSTONE_PG),
        vec![text(bucket.as_str()), text(key), text(before.as_str())],
    ));
    stmts.extend(retire_live_in(
        dialect,
        bucket,
        key,
        GenerationState::Deleted,
        now,
    ));
    stmts.push((DELETE_POINTER, vec![text(bucket.as_str()), text(key)]));
}

/// Extent rows of the parts the upload holds now, by part number and,
/// within a part, in body order.
pub(super) async fn upload_extents<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
    limit: u32,
) -> Result<Vec<PartExtent>> {
    let sql = UPLOAD_EXTENTS;
    let rows = c
        .sql
        .query(
            sql,
            &[
                text(t.id.as_str()),
                text(t.bucket.as_str()),
                text(t.key),
                SqlValue::Int(i64::from(limit)),
            ],
        )
        .await?;
    rows.into_iter()
        .map(|mut row| {
            if row.len() < 2 {
                return Err(BridgeError::Sql("row decode: missing column".into()));
            }
            let rest = row.split_off(2);
            let mut at = Cols::new(row);
            Ok(PartExtent {
                part_number: at.num()?,
                piece: at.num()?,
                extent: extent_row(rest)?,
            })
        })
        .collect()
}

const GUARD_DELETE_FLOOR: &str =
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS (SELECT 1 FROM key_floors \
             WHERE bucket_id = ?1 AND key = ?2 AND floor_id > ?3)";

const GUARD_DELETE_POINTER: &str =
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM objects \
         WHERE bucket_id = ?1 AND key = ?2 AND generation_id < ?3)";

const RAISE_TOMBSTONE_PG: &str =
    "INSERT INTO key_floors(bucket_id, key, floor_id) VALUES (?1, ?2, ?3) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET \
           floor_id = GREATEST(key_floors.floor_id, excluded.floor_id)";

const RAISE_TOMBSTONE: &str =
    "INSERT INTO key_floors(bucket_id, key, floor_id) VALUES (?1, ?2, ?3) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET \
           floor_id = max(floor_id, excluded.floor_id)";

const DELETE_POINTER: &str = "DELETE FROM objects WHERE bucket_id = ?1 AND key = ?2";

const UPLOAD_EXTENTS: &str = concat!(
    "SELECT p.part_number, p.piece, ",
    extent_cols!(),
    " FROM \
           (SELECT part_number, 0 AS piece, extent_id FROM upload_parts WHERE upload_id = ?1 \
            UNION ALL \
            SELECT part_number, piece, extent_id FROM upload_part_extents \
             WHERE upload_id = ?1) p \
         JOIN extents ON extents.id = p.extent_id \
         WHERE extents.bucket_id = ?2 AND EXISTS \
           (SELECT 1 FROM uploads u WHERE u.id = ?1 AND u.bucket_id = ?2 AND u.key = ?3) \
         ORDER BY p.part_number, p.piece LIMIT ?4"
);

#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<Stmt> {
    super::pg_manifest(&[
        (GUARD_DELETE_FLOOR, "TTT"),
        (GUARD_DELETE_POINTER, "TTT"),
        (RAISE_TOMBSTONE_PG, "TTT"),
        (DELETE_POINTER, "TT"),
        (UPLOAD_EXTENTS, "TTTI"),
    ])
}
