//! Catalogue statements of the recovery write path (DESIGN §A.8): the
//! delete that a tombstone can replay, and the extent rows a multipart
//! Complete records before it publishes.

use super::objects::{extent_row, retire_live, text, EXTENT_COLS};
use super::replay::guard_no_replay;
use super::SqlCatalog;
use crate::ports::{Sql, UploadTarget};
use crate::types::{
    BridgeError, BucketId, ExtentRow, GenerationId, GenerationState, Result, UnixMs,
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
    now: UnixMs,
    client: bool,
) -> Result<bool> {
    let mut stmts = Vec::new();
    if client {
        stmts.push(guard_no_replay());
    }
    stmts.push((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM objects \
         WHERE bucket_id = ?1 AND key = ?2 AND generation_id < ?3)",
        vec![text(bucket.as_str()), text(key), text(before.as_str())],
    ));
    // The service raised the floor to the tombstone before it stored
    // the record. Here again for a caller that applies a tombstone it
    // did not write; rolled back with the batch when nothing is deleted.
    stmts.push((
        "INSERT INTO key_floors(bucket_id, key, floor_id) VALUES (?1, ?2, ?3) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET \
           floor_id = max(floor_id, excluded.floor_id)",
        vec![text(bucket.as_str()), text(key), text(before.as_str())],
    ));
    stmts.extend(retire_live(bucket, key, GenerationState::Deleted, now));
    stmts.push((
        "DELETE FROM objects WHERE bucket_id = ?1 AND key = ?2",
        vec![text(bucket.as_str()), text(key)],
    ));
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(true),
        Err(BridgeError::GuardFailed) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Extent rows of the parts the upload holds now.
pub(super) async fn upload_extents<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
) -> Result<Vec<ExtentRow>> {
    let sql = format!(
        "SELECT {EXTENT_COLS} FROM extents WHERE bucket_id = ?2 AND id IN \
           (SELECT p.extent_id FROM upload_parts p JOIN uploads u ON u.id = p.upload_id \
            WHERE u.id = ?1 AND u.bucket_id = ?2 AND u.key = ?3)"
    );
    let rows = c
        .sql
        .query(
            &sql,
            &[text(t.id.as_str()), text(t.bucket.as_str()), text(t.key)],
        )
        .await?;
    rows.into_iter().map(extent_row).collect()
}
