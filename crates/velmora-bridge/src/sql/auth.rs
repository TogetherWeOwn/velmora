//! Buckets, access keys and grants (catalogue lane A).
//!
//! Lookups fail closed: a disabled access key is indistinguishable from
//! one that does not exist. It has no row, no grant and no buckets.

use super::objects::{ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Guard, Row, Sql, SqlValue};
use crate::types::{AccessKeyRow, Bucket, BucketId, KeyStatus, Perm, Result};

fn bucket_row(row: Row) -> Result<Bucket> {
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
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(name) DO NOTHING",
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
            "INSERT INTO access_keys(access_key_id, principal, secret_wrapped, kek_version, \
               status, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
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
            "INSERT INTO grants(access_key_id, bucket_id, perm) VALUES (?1,?2,?3) \
             ON CONFLICT(access_key_id, bucket_id) DO UPDATE SET perm = excluded.perm",
            &[text(akid), text(bucket.as_str()), text(perm.as_str())],
        )
        .await
        .map(|_| ())
}

pub(super) async fn bucket_by_name<S: Sql>(
    c: &SqlCatalog<S>,
    name: &str,
) -> Result<Option<Bucket>> {
    let rows = c
        .sql
        .query(
            "SELECT id, name, owner, bdk_wrapped, kek_version, disposable, created_at \
             FROM buckets WHERE name = ?1",
            &[text(name)],
        )
        .await?;
    rows.into_iter().next().map(bucket_row).transpose()
}

/// Buckets the key holds a grant on, by name. Empty for a disabled key.
pub(super) async fn buckets_for<S: Sql>(c: &SqlCatalog<S>, akid: &str) -> Result<Vec<Bucket>> {
    let rows = c
        .sql
        .query(
            "SELECT b.id, b.name, b.owner, b.bdk_wrapped, b.kek_version, b.disposable, \
               b.created_at \
             FROM grants g JOIN buckets b ON b.id = g.bucket_id \
             JOIN access_keys k ON k.access_key_id = g.access_key_id \
             WHERE g.access_key_id = ?1 AND k.status = 'active' ORDER BY b.name",
            &[text(akid)],
        )
        .await?;
    rows.into_iter().map(bucket_row).collect()
}

/// The key's row, only while it is active.
pub(super) async fn access_key<S: Sql>(
    c: &SqlCatalog<S>,
    akid: &str,
) -> Result<Option<AccessKeyRow>> {
    let rows = c
        .sql
        .query(
            "SELECT access_key_id, principal, secret_wrapped, kek_version, status, created_at \
             FROM access_keys WHERE access_key_id = ?1 AND status = 'active'",
            &[text(akid)],
        )
        .await?;
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
        .query(
            "SELECT g.perm FROM grants g \
             JOIN access_keys k ON k.access_key_id = g.access_key_id \
             WHERE g.access_key_id = ?1 AND g.bucket_id = ?2 AND k.status = 'active'",
            &[text(akid), text(bucket.as_str())],
        )
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    Cols::new(row).parsed(Perm::parse).map(Some)
}
