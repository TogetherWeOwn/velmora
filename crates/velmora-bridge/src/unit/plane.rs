//! The management plane's reads of a tenant's root unit (`docs/units.md`,
//! "Management reads"; L1-Q16, L5-C1; package L1-5b).
//!
//! The plane (`mgmt`) reads a managed tenant's root unit through the
//! router as [`super::request::RequestCall`]s of kind `request`,
//! `authenticated` and `listed`, like the S3 path. Each is a read
//! (served while `suspended` with `read_only` too), bounded, and answered
//! from indexed rows or counters:
//!
//! - `bucket_names` (at most [`MAX_LOOKUP`] ids): each id's bucket name,
//!   in the order asked; none for an id with no row or a `closing` row
//!   (a closing bucket is gone to the plane).
//! - `buckets_page` (name order, UTF-8 bytes; `after` a name),
//!   `buckets_named` (at most [`MAX_LOOKUP`] names, in the order asked)
//!   and `bucket_by_id`: open rows only, as [`BucketItem`].
//! - `keys_page` (S3 keys or app passwords, in creation order then id;
//!   `after` the last item's `created_at` and `id`) and `key_by_id`:
//!   never the internal key, a principal or a revoked row, and never a
//!   secret, as [`KeyItem`].
//! - `reach`: the open buckets, their live objects and bytes, and the
//!   keys `keys_page` lists, as [`Reach`].
//!
//! A bucket's `stored_bytes` and `object_count` are the unit's usage
//! counters (`usage_buckets`, one primary-key read each). Until a recount
//! has switched the counters on (`seeded`), they are not known, and the
//! answer says `null` rather than a partial count.
//!
//! The unit holds no key label (a private part of the key record, which
//! the plane reads from the verified chain) and no last-used time (no
//! request writes one), so a [`KeyItem`] has neither.

use serde::{Deserialize, Serialize};

use super::keys::{self, KeyGrant, KeyKind, SubjectStatus};
use super::object::poll_once;
use crate::ports::{Row, Sql, SqlValue};
use crate::types::{BridgeError, Result};

/// The most ids or names one lookup names.
pub const MAX_LOOKUP: usize = 64;
/// The most items one page asks for.
pub const MAX_ITEMS: u32 = 1_000;

/// One open bucket as the plane shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketItem {
    pub id: String,
    pub name: String,
    pub created_at: u64,
    /// Live plaintext bytes; `None` until the counters are on.
    pub stored_bytes: Option<u64>,
    /// Live objects; `None` until the counters are on.
    pub object_count: Option<u64>,
}

/// A page of a list: the items, and whether more follow the last.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub more: bool,
}

/// The kinds `keys_page` lists. Any other kind does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListedKind {
    S3,
    AppPassword,
}

impl ListedKind {
    fn kind(self) -> KeyKind {
        match self {
            ListedKind::S3 => KeyKind::S3,
            ListedKind::AppPassword => KeyKind::AppPassword,
        }
    }
}

/// Where a key page starts: after the item with this `created_at` and
/// `id` (the last item of the page before). It needs no row of its own,
/// so a cursor stays good whatever happened to that key since.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysAfter {
    pub created_at: u64,
    pub id: String,
}

/// One S3 key or app password as the plane shows it: never its secret.
/// `held`: the unit holds it closed (AM-9); it is not served.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyItem {
    pub id: String,
    pub kind: KeyKind,
    pub status: SubjectStatus,
    pub held: bool,
    /// The principal that made it (none for tenant 0's older keys).
    pub made_by: Option<String>,
    pub grants: Vec<KeyGrant>,
    pub created_at: u64,
    pub last_seq: u64,
}

/// What a tenant reaches on its root unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reach {
    /// Open bucket rows.
    pub buckets: u64,
    /// Live objects in them; `None` until the counters are on.
    pub objects: Option<u64>,
    /// Their live plaintext bytes; `None` until the counters are on.
    pub stored_bytes: Option<u64>,
    /// S3 keys and app passwords that are not revoked.
    pub keys: u64,
}

const OPEN: &str = "NOT EXISTS (SELECT 1 FROM unit_bucket_closing c WHERE c.bucket_id = b.id)";

/// Each id's open bucket name, in the order asked.
pub fn bucket_names<S: Sql>(sql: &S, ids: &[String]) -> Result<Vec<Option<String>>> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let rows = poll_once(sql.query(
            &format!("SELECT b.name FROM buckets b WHERE b.id = ?1 AND {OPEN}"),
            &[SqlValue::Text(id.clone())],
        ))??;
        out.push(
            match rows.into_iter().next().and_then(|r| r.into_iter().next()) {
                Some(SqlValue::Text(name)) => Some(name),
                None => None,
                Some(_) => return Err(decode("buckets name")),
            },
        );
    }
    Ok(out)
}

/// Whether the usage counters are on (`UsageCounters::seeded`).
fn seeded<S: Sql>(sql: &S) -> Result<bool> {
    let rows = poll_once(sql.query(
        "SELECT all_x AND all_o AND all_g FROM usage_global WHERE id = 1",
        &[],
    ))??;
    Ok(matches!(
        rows.first().and_then(|r| r.first()),
        Some(SqlValue::Int(1))
    ))
}

/// A bucket row (`id`, `name`, `created_at`) with its usage counters.
fn bucket_item<S: Sql>(sql: &S, r: Row, seeded: bool) -> Result<BucketItem> {
    let (Some(SqlValue::Text(id)), Some(SqlValue::Text(name)), Some(SqlValue::Int(created))) =
        (r.first(), r.get(1), r.get(2))
    else {
        return Err(decode("buckets row"));
    };
    let (stored_bytes, object_count) = if seeded {
        let rows = poll_once(sql.query(
            "SELECT live_bytes, live_objects FROM usage_buckets WHERE kind = 1 AND bucket_id = ?1",
            &[SqlValue::Text(id.clone())],
        ))??;
        match rows.first().map(|r| (r.first(), r.get(1))) {
            None => (Some(0), Some(0)),
            Some((Some(SqlValue::Int(b)), Some(SqlValue::Int(o)))) => (
                Some(nonneg(*b, "live_bytes")?),
                Some(nonneg(*o, "live_objects")?),
            ),
            Some(_) => return Err(decode("usage_buckets row")),
        }
    } else {
        (None, None)
    };
    Ok(BucketItem {
        id: id.clone(),
        name: name.clone(),
        created_at: nonneg(*created, "buckets created_at")?,
        stored_bytes,
        object_count,
    })
}

/// Open buckets after the name `after`, in name order (bytes).
pub fn buckets_page<S: Sql>(sql: &S, after: Option<&str>, limit: u32) -> Result<Page<BucketItem>> {
    let seeded = seeded(sql)?;
    let take = i64::from(limit) + 1;
    let rows = match after {
        Some(a) => poll_once(sql.query(
            &format!(
                "SELECT b.id, b.name, b.created_at FROM buckets b \
                  WHERE b.name > ?1 AND {OPEN} ORDER BY b.name LIMIT ?2"
            ),
            &[SqlValue::Text(a.to_string()), SqlValue::Int(take)],
        ))??,
        None => poll_once(sql.query(
            &format!(
                "SELECT b.id, b.name, b.created_at FROM buckets b \
                  WHERE {OPEN} ORDER BY b.name LIMIT ?1"
            ),
            &[SqlValue::Int(take)],
        ))??,
    };
    page(rows, limit, |r| bucket_item(sql, r, seeded))
}

/// Each name's open bucket, in the order asked.
pub fn buckets_named<S: Sql>(sql: &S, names: &[String]) -> Result<Vec<Option<BucketItem>>> {
    let seeded = seeded(sql)?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let rows = poll_once(sql.query(
            &format!(
                "SELECT b.id, b.name, b.created_at FROM buckets b WHERE b.name = ?1 AND {OPEN}"
            ),
            &[SqlValue::Text(name.clone())],
        ))??;
        out.push(match rows.into_iter().next() {
            Some(r) => Some(bucket_item(sql, r, seeded)?),
            None => None,
        });
    }
    Ok(out)
}

/// The open bucket `id`.
pub fn bucket_by_id<S: Sql>(sql: &S, id: &str) -> Result<Option<BucketItem>> {
    let rows = poll_once(sql.query(
        &format!("SELECT b.id, b.name, b.created_at FROM buckets b WHERE b.id = ?1 AND {OPEN}"),
        &[SqlValue::Text(id.to_string())],
    ))??;
    match rows.into_iter().next() {
        Some(r) => Ok(Some(bucket_item(sql, r, seeded(sql)?)?)),
        None => Ok(None),
    }
}

const KEY_COLUMNS: &str = "id, kind, status, held, made_by, created_at, last_seq";

/// A `unit_keys` row of [`KEY_COLUMNS`] with its grants.
fn key_item<S: Sql>(sql: &S, r: Row) -> Result<KeyItem> {
    let text = |v: Option<&SqlValue>, what| match v {
        Some(SqlValue::Text(s)) => Ok(s.clone()),
        _ => Err(decode(what)),
    };
    let id = text(r.first(), "unit_keys id")?;
    let kind = KeyKind::parse(&text(r.get(1), "unit_keys kind")?)
        .ok_or_else(|| decode("unit_keys kind"))?;
    let status = SubjectStatus::parse(&text(r.get(2), "unit_keys status")?)
        .ok_or_else(|| decode("unit_keys status"))?;
    let held = match r.get(3) {
        Some(SqlValue::Int(h)) => *h == 1,
        _ => return Err(decode("unit_keys held")),
    };
    let made_by = match r.get(4) {
        Some(SqlValue::Text(p)) => Some(p.clone()),
        Some(SqlValue::Null) => None,
        _ => return Err(decode("unit_keys made_by")),
    };
    let (Some(SqlValue::Int(created)), Some(SqlValue::Int(last))) = (r.get(5), r.get(6)) else {
        return Err(decode("unit_keys numbers"));
    };
    Ok(KeyItem {
        grants: keys::grants_of(sql, &id)?,
        id,
        kind,
        status,
        held,
        made_by,
        created_at: nonneg(*created, "unit_keys created_at")?,
        last_seq: nonneg(*last, "unit_keys last_seq")?,
    })
}

/// Keys of `kind` that are not revoked, after `after`, in creation order
/// then id.
pub fn keys_page<S: Sql>(
    sql: &S,
    kind: ListedKind,
    after: Option<&KeysAfter>,
    limit: u32,
) -> Result<Page<KeyItem>> {
    let kind = SqlValue::Text(kind.kind().as_str().into());
    let take = SqlValue::Int(i64::from(limit) + 1);
    let rows = match after {
        Some(a) => poll_once(sql.query(
            &format!(
                "SELECT {KEY_COLUMNS} FROM unit_keys \
                  WHERE kind IN ('s3', 'app_password') AND kind = ?1 AND status <> 'revoked' AND (created_at, id) > (?2, ?3) \
                  ORDER BY created_at, id LIMIT ?4"
            ),
            &[kind, int(a.created_at)?, SqlValue::Text(a.id.clone()), take],
        ))??,
        None => poll_once(sql.query(
            &format!(
                "SELECT {KEY_COLUMNS} FROM unit_keys \
                  WHERE kind IN ('s3', 'app_password') AND kind = ?1 AND status <> 'revoked' ORDER BY created_at, id LIMIT ?2"
            ),
            &[kind, take],
        ))??,
    };
    page(rows, limit, |r| key_item(sql, r))
}

/// The S3 key or app password `id`, if it is not revoked.
pub fn key_by_id<S: Sql>(sql: &S, id: &str) -> Result<Option<KeyItem>> {
    let rows = poll_once(sql.query(
        &format!(
            "SELECT {KEY_COLUMNS} FROM unit_keys \
              WHERE id = ?1 AND kind IN ('s3', 'app_password') AND status <> 'revoked'"
        ),
        &[SqlValue::Text(id.to_string())],
    ))??;
    match rows.into_iter().next() {
        Some(r) => Ok(Some(key_item(sql, r)?)),
        None => Ok(None),
    }
}

/// What the tenant reaches on this unit. Each count is bounded by a
/// cap: the bucket rows by the `sync` shape bound
/// ([`super::buckets::MAX_PLACED`]), the keys by the rows of two kinds.
pub fn reach<S: Sql>(sql: &S) -> Result<Reach> {
    let count = |text: String| -> Result<u64> {
        let rows = poll_once(sql.query(&text, &[]))??;
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Int(n)) => nonneg(*n, "count"),
            _ => Err(decode("count")),
        }
    };
    let buckets = count(format!("SELECT count(*) FROM buckets b WHERE {OPEN}"))?;
    let keys = count(
        "SELECT count(*) FROM unit_keys \
          WHERE kind IN ('s3', 'app_password') AND status <> 'revoked'"
            .into(),
    )?;
    let (objects, stored_bytes) = if seeded(sql)? {
        let rows = poll_once(sql.query(
            &format!(
                "SELECT coalesce(sum(u.live_objects), 0), coalesce(sum(u.live_bytes), 0) \
                   FROM usage_buckets u JOIN buckets b ON b.id = u.bucket_id \
                  WHERE u.kind = 1 AND {OPEN}"
            ),
            &[],
        ))??;
        match rows.first().map(|r| (r.first(), r.get(1))) {
            Some((Some(SqlValue::Int(o)), Some(SqlValue::Int(b)))) => {
                (Some(nonneg(*o, "objects")?), Some(nonneg(*b, "bytes")?))
            }
            _ => return Err(decode("usage sum")),
        }
    } else {
        (None, None)
    };
    Ok(Reach {
        buckets,
        objects,
        stored_bytes,
        keys,
    })
}

/// The first `limit` rows as items, and whether a row followed them (the
/// query asked for one more).
fn page<T>(rows: Vec<Row>, limit: u32, mut item: impl FnMut(Row) -> Result<T>) -> Result<Page<T>> {
    let more = rows.len() > limit as usize;
    let items = rows
        .into_iter()
        .take(limit as usize)
        .map(&mut item)
        .collect::<Result<Vec<_>>>()?;
    Ok(Page { items, more })
}

fn nonneg(n: i64, what: &'static str) -> Result<u64> {
    u64::try_from(n).map_err(|_| decode(what))
}

fn int(n: u64) -> Result<SqlValue> {
    i64::try_from(n)
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("number out of range"))
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}
