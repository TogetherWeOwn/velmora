//! Buckets, access keys and grants (catalogue lane A).
//!
//! Lookups fail closed: a disabled access key is indistinguishable from
//! one that does not exist. It has no row, no grant and no buckets.

use super::objects::{ms, text, Cols};
use super::replay::guard_no_replay;
use super::uploads::guarded;
use super::SqlCatalog;
use crate::ports::{GrantPut, Guard, Row, Sql, SqlValue};
use crate::types::{
    AccessKeyRow, AccessKeySummary, BridgeError, Bucket, BucketId, KeyStatus, Perm, Result,
};

pub(super) fn bucket_row(row: Row) -> Result<Bucket> {
    let mut c = Cols::new(row);
    Ok(Bucket {
        id: BucketId::new(c.text()?),
        name: c.text()?,
        owner: c.text()?,
        bdk_wrapped: c.blob()?,
        kek_version: c.num()?,
        disposable: c.num::<i64>()? != 0,
        created_at: c.ms()?,
    })
}

/// `Lost` = the name is taken (the row is left untouched).
pub(super) async fn create_bucket<S: Sql>(c: &SqlCatalog<S>, b: &Bucket) -> Result<Guard<()>> {
    let changed = c
        .sql
        .exec(
            CREATE_BUCKET,
            &[
                text(b.id.as_str()),
                text(&b.name),
                text(&b.owner),
                SqlValue::Blob(b.bdk_wrapped.clone()),
                SqlValue::Int(i64::from(b.kek_version)),
                SqlValue::Int(i64::from(b.disposable)),
                ms(b.created_at),
            ],
        )
        .await?;
    Ok(if changed == 1 {
        Guard::Applied(())
    } else {
        Guard::Lost
    })
}

pub(super) async fn create_access_key<S: Sql>(c: &SqlCatalog<S>, k: &AccessKeyRow) -> Result<()> {
    c.sql
        .exec(
            CREATE_KEY,
            &[
                text(&k.access_key_id),
                text(&k.principal),
                SqlValue::Blob(k.secret_wrapped.clone()),
                SqlValue::Int(i64::from(k.kek_version)),
                text(k.status.as_str()),
                ms(k.created_at),
            ],
        )
        .await
        .map(|_| ())
}

/// Sets the key's permission on the bucket, replacing an earlier grant.
pub(super) async fn put_grant<S: Sql>(
    c: &SqlCatalog<S>,
    akid: &str,
    bucket: &BucketId,
    perm: Perm,
) -> Result<()> {
    c.sql
        .exec(
            UPSERT_GRANT,
            &[text(akid), text(bucket.as_str()), text(perm.as_str())],
        )
        .await
        .map(|_| ())
}

/// See [`crate::ports::Catalog::put_grant_if_present`]. One statement:
/// the existence checks, the no-narrowing check and the write commit
/// together. The `WHERE` of the `SELECT` also keeps SQLite from reading
/// `ON CONFLICT` as a join constraint. When the `WHERE` of `DO UPDATE`
/// fails, SQLite (and D1) count no change.
///
/// After no change, the grant row tells the two cases apart: it exists
/// only while the key and the bucket do (their deletes take it along),
/// so a row there means the write was a narrowing.
pub(super) async fn put_grant_if_present<S: Sql>(
    c: &SqlCatalog<S>,
    akid: &str,
    bucket: &BucketId,
    perm: Perm,
) -> Result<GrantPut> {
    let changed = c
        .sql
        .exec(
            UPSERT_PRESENT_GRANT,
            &[text(akid), text(bucket.as_str()), text(perm.as_str())],
        )
        .await?;
    if changed == 1 {
        return Ok(GrantPut::Applied);
    }
    let rows = c
        .sql
        .query(GRANT_EXISTS, &[text(akid), text(bucket.as_str())])
        .await?;
    match rows.first().map(Vec::as_slice) {
        Some([SqlValue::Int(0)]) => Ok(GrantPut::Lost),
        Some([SqlValue::Int(_)]) => Ok(GrantPut::Narrowing),
        _ => Err(BridgeError::Sql(
            "put_grant_if_present: unexpected row".into(),
        )),
    }
}

pub(super) async fn bucket_by_name<S: Sql>(
    c: &SqlCatalog<S>,
    name: &str,
) -> Result<Option<Bucket>> {
    let rows = c.sql.query(BUCKET_BY_NAME, &[text(name)]).await?;
    rows.into_iter().next().map(bucket_row).transpose()
}

/// `true` while a row of any table names the bucket, other than a grant.
/// `extents` and `uploads` have no index on the bucket: this reads them
/// through, which a rare call can afford.
pub(super) async fn bucket_in_use<S: Sql>(c: &SqlCatalog<S>, bucket: &BucketId) -> Result<bool> {
    let rows = c.sql.query(BUCKET_IN_USE, &[text(bucket.as_str())]).await?;
    match rows.first().map(Vec::as_slice) {
        Some([SqlValue::Int(n)]) => Ok(*n != 0),
        _ => Err(crate::types::BridgeError::Sql(
            "bucket_in_use: unexpected row".into(),
        )),
    }
}

/// See [`crate::ports::Catalog::delete_bucket`]. The guards and deletes
/// are one batch: a write commits before it (and this batch either cleans
/// up CORS or refuses a nonempty bucket) or after it (and finds no bucket).
pub(super) async fn delete_bucket<S: Sql>(c: &SqlCatalog<S>, b: &Bucket) -> Result<Guard<()>> {
    let id = || vec![text(b.id.as_str())];
    let mut stmts = vec![
        guard_bucket_id(b),
        guard_no_replay(),
        (GUARD_EMPTY_BUCKET, id()),
        (DELETE_BUCKET_GRANTS, id()),
    ];
    if c.cors_enabled {
        stmts.push((super::cors::DELETE_BUCKET_CORS, id()));
    }
    stmts.push((DELETE_BUCKET, id()));
    guarded(c, stmts).await
}

pub(super) fn guard_bucket_id(b: &Bucket) -> (&'static str, Vec<SqlValue>) {
    (GUARD_BUCKET_ID, vec![text(b.id.as_str()), text(&b.name)])
}

/// Buckets the key holds a grant on, by name. Empty for a disabled key.
pub(super) async fn buckets_for<S: Sql>(c: &SqlCatalog<S>, akid: &str) -> Result<Vec<Bucket>> {
    let rows = c.sql.query(BUCKETS_FOR, &[text(akid)]).await?;
    rows.into_iter().map(bucket_row).collect()
}

/// The key's row, only while it is active.
pub(super) async fn access_key<S: Sql>(
    c: &SqlCatalog<S>,
    akid: &str,
) -> Result<Option<AccessKeyRow>> {
    let rows = c.sql.query(ACTIVE_KEY, &[text(akid)]).await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let mut r = Cols::new(row);
    Ok(Some(AccessKeyRow {
        access_key_id: r.text()?,
        principal: r.text()?,
        secret_wrapped: r.blob()?,
        kek_version: r.num()?,
        status: r.parsed(KeyStatus::parse)?,
        created_at: r.ms()?,
    }))
}

/// The key's permission on exactly this bucket. `None` without a grant,
/// and for a disabled key.
pub(super) async fn grant<S: Sql>(
    c: &SqlCatalog<S>,
    akid: &str,
    bucket: &BucketId,
) -> Result<Option<Perm>> {
    let rows = c
        .sql
        .query(ACTIVE_GRANT, &[text(akid), text(bucket.as_str())])
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    Cols::new(row).parsed(Perm::parse).map(Some)
}

/// See [`crate::ports::Catalog::access_key_exists`].
pub(super) async fn access_key_exists<S: Sql>(c: &SqlCatalog<S>, akid: &str) -> Result<bool> {
    let rows = c.sql.query(KEY_EXISTS, &[text(akid)]).await?;
    match rows.first().map(Vec::as_slice) {
        Some([SqlValue::Int(n)]) => Ok(*n != 0),
        _ => Err(BridgeError::Sql("access_key_exists: unexpected row".into())),
    }
}

/// See [`crate::ports::Catalog::list_access_keys`]. One query: the page
/// of keys, each joined to its grants. `secret_wrapped` is not selected.
pub(super) async fn list_access_keys<S: Sql>(
    c: &SqlCatalog<S>,
    after: &str,
    limit: u32,
) -> Result<Vec<AccessKeySummary>> {
    let rows = c
        .sql
        .query(LIST_KEYS, &[text(after), SqlValue::Int(i64::from(limit))])
        .await?;
    let mut keys: Vec<AccessKeySummary> = Vec::new();
    for row in rows {
        let mut r = Cols::new(row);
        let akid = r.text()?;
        let status = r.parsed(KeyStatus::parse)?;
        let created_at = r.ms()?;
        let bucket = r.opt_text()?;
        let perm = r.opt_text()?;
        if keys.last().is_none_or(|k| k.access_key_id != akid) {
            keys.push(AccessKeySummary {
                access_key_id: akid,
                status,
                created_at,
                grants: Vec::new(),
            });
        }
        if let (Some(bucket), Some(perm), Some(key)) = (bucket, perm, keys.last_mut()) {
            let perm = Perm::parse(&perm)
                .ok_or_else(|| BridgeError::Sql("list_access_keys: unknown perm".into()))?;
            key.grants.push((bucket, perm));
        }
    }
    Ok(keys)
}

/// See [`crate::ports::Catalog::delete_access_keys`]. The ids travel as
/// one JSON array, so a page of any size is two statements.
pub(super) async fn delete_access_keys<S: Sql>(c: &SqlCatalog<S>, akids: &[String]) -> Result<u64> {
    if akids.is_empty() {
        return Ok(0);
    }
    let ids = serde_json::to_string(akids)
        .map_err(|_| BridgeError::Sql("delete_access_keys: encode".into()))?;
    let changed = c
        .sql
        .batch(vec![
            (
                c.sql
                    .dialect()
                    .pick(DELETE_KEY_GRANTS, DELETE_KEY_GRANTS_PG),
                vec![text(&ids)],
            ),
            (
                c.sql.dialect().pick(DELETE_KEYS, DELETE_KEYS_PG),
                vec![text(&ids)],
            ),
        ])
        .await?;
    Ok(changed.get(1).copied().unwrap_or(0))
}

const CREATE_BUCKET: &str =
    "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(name) DO NOTHING";

const CREATE_KEY: &str =
    "INSERT INTO access_keys(access_key_id, principal, secret_wrapped, kek_version, \
               status, created_at) VALUES (?1,?2,?3,?4,?5,?6)";

const UPSERT_GRANT: &str = "INSERT INTO grants(access_key_id, bucket_id, perm) VALUES (?1,?2,?3) \
             ON CONFLICT(access_key_id, bucket_id) DO UPDATE SET perm = excluded.perm";

const UPSERT_PRESENT_GRANT: &str =
    "INSERT INTO grants(access_key_id, bucket_id, perm) SELECT ?1, ?2, ?3 \
             WHERE EXISTS (SELECT 1 FROM access_keys WHERE access_key_id = ?1) \
               AND EXISTS (SELECT 1 FROM buckets WHERE id = ?2) \
             ON CONFLICT(access_key_id, bucket_id) DO UPDATE SET perm = excluded.perm \
             WHERE excluded.perm = 'rw' OR grants.perm = excluded.perm";

const GRANT_EXISTS: &str =
    "SELECT EXISTS (SELECT 1 FROM grants WHERE access_key_id = ?1 AND bucket_id = ?2)";

const BUCKET_BY_NAME: &str =
    "SELECT id, name, owner, bdk_wrapped, kek_version, disposable, created_at \
             FROM buckets WHERE name = ?1";

const BUCKET_IN_USE: &str = "SELECT EXISTS (SELECT 1 FROM generations WHERE bucket_id = ?1) \
                 OR EXISTS (SELECT 1 FROM objects WHERE bucket_id = ?1) \
                 OR EXISTS (SELECT 1 FROM key_floors WHERE bucket_id = ?1) \
                 OR EXISTS (SELECT 1 FROM uploads WHERE bucket_id = ?1) \
                 OR EXISTS (SELECT 1 FROM extents WHERE bucket_id = ?1)";

const GUARD_BUCKET_ID: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS \
                   (SELECT 1 FROM buckets WHERE id = ?1 AND name = ?2)";

const GUARD_EMPTY_BUCKET: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
                   EXISTS (SELECT 1 FROM generations WHERE bucket_id = ?1) \
                   OR EXISTS (SELECT 1 FROM objects WHERE bucket_id = ?1) \
                   OR EXISTS (SELECT 1 FROM key_floors WHERE bucket_id = ?1) \
                   OR EXISTS (SELECT 1 FROM uploads WHERE bucket_id = ?1) \
                   OR EXISTS (SELECT 1 FROM extents WHERE bucket_id = ?1)";

const DELETE_BUCKET_GRANTS: &str = "DELETE FROM grants WHERE bucket_id = ?1";

const DELETE_BUCKET: &str = "DELETE FROM buckets WHERE id = ?1";

const BUCKETS_FOR: &str =
    "SELECT b.id, b.name, b.owner, b.bdk_wrapped, b.kek_version, b.disposable, \
               b.created_at \
             FROM grants g JOIN buckets b ON b.id = g.bucket_id \
             JOIN access_keys k ON k.access_key_id = g.access_key_id \
             WHERE g.access_key_id = ?1 AND k.status = 'active' ORDER BY b.name";

const ACTIVE_KEY: &str =
    "SELECT access_key_id, principal, secret_wrapped, kek_version, status, created_at \
             FROM access_keys WHERE access_key_id = ?1 AND status = 'active'";

const ACTIVE_GRANT: &str = "SELECT g.perm FROM grants g \
             JOIN access_keys k ON k.access_key_id = g.access_key_id \
             WHERE g.access_key_id = ?1 AND g.bucket_id = ?2 AND k.status = 'active'";

const KEY_EXISTS: &str = "SELECT EXISTS (SELECT 1 FROM access_keys WHERE access_key_id = ?1)";

const LIST_KEYS: &str = "SELECT k.access_key_id, k.status, k.created_at, b.name, g.perm \
             FROM (SELECT access_key_id, status, created_at FROM access_keys \
                   WHERE access_key_id > ?1 ORDER BY access_key_id LIMIT ?2) k \
             LEFT JOIN grants g ON g.access_key_id = k.access_key_id \
             LEFT JOIN buckets b ON b.id = g.bucket_id \
             ORDER BY k.access_key_id, b.name";

const DELETE_KEY_GRANTS_PG: &str = "DELETE FROM grants WHERE access_key_id IN (SELECT value FROM jsonb_array_elements_text(?1::jsonb) AS k(value))";

const DELETE_KEY_GRANTS: &str =
    "DELETE FROM grants WHERE access_key_id IN (SELECT value FROM json_each(?1))";

const DELETE_KEYS_PG: &str = "DELETE FROM access_keys WHERE access_key_id IN (SELECT value FROM jsonb_array_elements_text(?1::jsonb) AS k(value))";

const DELETE_KEYS: &str =
    "DELETE FROM access_keys WHERE access_key_id IN (SELECT value FROM json_each(?1))";

#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(&'static str, Vec<SqlValue>)> {
    super::pg_manifest(&[
        (CREATE_BUCKET, "TTTBIII"),
        (CREATE_KEY, "TTBITI"),
        (UPSERT_GRANT, "TTT"),
        (UPSERT_PRESENT_GRANT, "TTT"),
        (GRANT_EXISTS, "TT"),
        (BUCKET_BY_NAME, "T"),
        (BUCKET_IN_USE, "T"),
        (GUARD_BUCKET_ID, "TT"),
        (GUARD_EMPTY_BUCKET, "T"),
        (DELETE_BUCKET_GRANTS, "T"),
        (DELETE_BUCKET, "T"),
        (BUCKETS_FOR, "T"),
        (ACTIVE_KEY, "T"),
        (ACTIVE_GRANT, "TT"),
        (KEY_EXISTS, "T"),
        (LIST_KEYS, "TI"),
        (DELETE_KEY_GRANTS_PG, "T"),
        (DELETE_KEYS_PG, "T"),
    ])
}
