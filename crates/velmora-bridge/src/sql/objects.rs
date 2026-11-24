//! Objects, generations, listing and admin status (catalogue lane A).
//!
//! Publication and deletion are each one atomic [`Sql::batch`]. The
//! generation being replaced or deleted is resolved *inside* the batch
//! (sub-selects on the live `objects` pointer), never read beforehand, so
//! two racing writers cannot both retire the same generation or leave one
//! live without a pointer. Statements are fixed-shape, one row each, and
//! stay far below the 100-bound-parameter limit.

use super::intents::publish_intents;
use super::replay::guard_no_replay;
use super::uploads::published;
use super::SqlCatalog;
use crate::ports::{Dialect, KeyHead, PublishOutcome, Row, Sql, SqlValue};
use crate::recovery::Recorded;
use crate::types::{
    BackboneStatus, BridgeError, BucketId, CommitGeneration, CopyGeneration, ExtentId, ExtentRow,
    ExtentState, ExtentStatus, GenerationId, GenerationRow, GenerationState, ListCursor, ListEntry,
    ListPage, ListQuery, ObjectStatus, OutboxStage, Precondition, Result, SafetyState, UnixMs,
    VerifyKind, VerifyResult, WriteId,
};

/// A retired generation's key is shredded this long after retirement;
/// its cached and pinned ciphertext is due for deletion immediately.
const SHRED_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

/// Catalogue queries one LIST page may spend. D1 allows 1,000 per
/// invocation and the request also pays for auth; a page that runs out
/// is returned truncated with a valid cursor.
const LIST_QUERY_BUDGET: u32 = 200;

/// Rows fetched per LIST query (plus one look-ahead row).
const LIST_BATCH_MAX: u32 = 1000;

// ---------------------------------------------------------------------------
// Row encoding helpers (shared with `auth`)
// ---------------------------------------------------------------------------

pub(super) fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

pub(super) fn ms(t: UnixMs) -> SqlValue {
    SqlValue::Int(t.0)
}

pub(super) fn uint(v: u64) -> Result<SqlValue> {
    i64::try_from(v)
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("integer exceeds the catalogue range"))
}

pub(super) fn opt<T>(v: Option<T>, f: impl FnOnce(T) -> SqlValue) -> SqlValue {
    v.map_or(SqlValue::Null, f)
}

fn bad(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("row decode: {what}"))
}

/// Reads one result row column by column, in statement order.
pub(super) struct Cols(std::vec::IntoIter<SqlValue>);

impl Cols {
    pub(super) fn new(row: Row) -> Self {
        Cols(row.into_iter())
    }

    fn next(&mut self) -> Result<SqlValue> {
        self.0.next().ok_or_else(|| bad("missing column"))
    }

    pub(super) fn opt_text(&mut self) -> Result<Option<String>> {
        match self.next()? {
            SqlValue::Null => Ok(None),
            SqlValue::Text(s) => Ok(Some(s)),
            _ => Err(bad("expected text")),
        }
    }

    pub(super) fn text(&mut self) -> Result<String> {
        self.opt_text()?.ok_or_else(|| bad("unexpected NULL"))
    }

    pub(super) fn opt_num<T: TryFrom<i64>>(&mut self) -> Result<Option<T>> {
        match self.next()? {
            SqlValue::Null => Ok(None),
            SqlValue::Int(i) => T::try_from(i)
                .map(Some)
                .map_err(|_| bad("integer out of range")),
            _ => Err(bad("expected integer")),
        }
    }

    pub(super) fn num<T: TryFrom<i64>>(&mut self) -> Result<T> {
        self.opt_num()?.ok_or_else(|| bad("unexpected NULL"))
    }

    pub(super) fn opt_ms(&mut self) -> Result<Option<UnixMs>> {
        Ok(self.opt_num::<i64>()?.map(UnixMs))
    }

    pub(super) fn ms(&mut self) -> Result<UnixMs> {
        self.num::<i64>().map(UnixMs)
    }

    pub(super) fn opt_blob(&mut self) -> Result<Option<Vec<u8>>> {
        match self.next()? {
            SqlValue::Null => Ok(None),
            SqlValue::Blob(b) => Ok(Some(b)),
            _ => Err(bad("expected blob")),
        }
    }

    pub(super) fn blob(&mut self) -> Result<Vec<u8>> {
        self.opt_blob()?.ok_or_else(|| bad("unexpected NULL"))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        <[u8; N]>::try_from(self.blob()?).map_err(|_| bad("digest length"))
    }

    /// A `CHECK (… IN (…))` column through the enum's `parse`.
    pub(super) fn parsed<T>(&mut self, parse: fn(&str) -> Option<T>) -> Result<T> {
        parse(&self.text()?).ok_or_else(|| bad("unknown enum value"))
    }
}

/// How many columns the generation projection selects.
const GENERATION_WIDTH: usize = 12;
macro_rules! generation_cols {
    () => {
        "g.id, g.bucket_id, g.key, g.state, g.size, g.etag, \
     g.checksum_json, g.content_json, g.user_meta_json, g.extent_count, g.created_at, g.retired_at"
    };
}

fn generation_row(row: Row) -> Result<GenerationRow> {
    let mut c = Cols::new(row);
    Ok(GenerationRow {
        id: GenerationId::new(c.text()?),
        bucket_id: BucketId::new(c.text()?),
        key: c.text()?,
        state: c.parsed(GenerationState::parse)?,
        size: c.num()?,
        etag: c.text()?,
        checksum_json: c.opt_text()?,
        content_json: c.text()?,
        user_meta_json: c.text()?,
        extent_count: c.num()?,
        created_at: c.ms()?,
        retired_at: c.opt_ms()?,
    })
}

/// The `extents` columns in schema order, with the place the extent has
/// in the generation it was first written for.
macro_rules! extent_cols {
    () => {
        "id, bucket_id, generation_id, state, seq, plain_offset, plain_size, cipher_size, \
     media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, cipher_sha256, \
     safety_state, article_count, plan_rev, last_verified_at, release_evidence, released_at, \
     created_at"
    };
}
pub(super) use extent_cols;

/// One extent row: the `extents` columns in schema order.
pub(super) fn extent_row(row: Row) -> Result<ExtentRow> {
    let mut c = Cols::new(row);
    Ok(ExtentRow {
        id: ExtentId::new(c.text()?),
        bucket_id: BucketId::new(c.text()?),
        generation_id: c.opt_text()?.map(GenerationId::new),
        state: c.parsed(ExtentState::parse)?,
        seq: c.opt_num()?,
        plain_offset: c.opt_num()?,
        plain_size: c.num()?,
        cipher_size: c.num()?,
        media_header: c.blob()?,
        key_mode: c.num()?,
        wrapped_file_key: c.opt_blob()?,
        plain_md5: c.array()?,
        plain_sha256: c.array()?,
        cipher_sha256: c.array()?,
        safety_state: c.parsed(SafetyState::parse)?,
        article_count: c.opt_num()?,
        plan_rev: c.num()?,
        last_verified_at: c.opt_ms()?,
        release_evidence: c.opt_text()?,
        released_at: c.opt_ms()?,
        created_at: c.ms()?,
    })
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

pub(super) async fn live_generation<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
) -> Result<Option<GenerationRow>> {
    live_generation_asked(c, bucket, key, false).await
}

/// [`live_generation`], asked through [`Sql::query_after_refusal`] when
/// `after_refusal` is set: the caller follows a batch that was refused.
pub(super) async fn live_generation_asked<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
    after_refusal: bool,
) -> Result<Option<GenerationRow>> {
    let sql = LIVE_GENERATION;
    let params = [text(bucket.as_str()), text(key)];
    let rows = if after_refusal {
        c.sql.query_after_refusal(sql, &params).await?
    } else {
        c.sql.query(sql, &params).await?
    };
    rows.into_iter().next().map(generation_row).transpose()
}

pub(super) async fn generation_by_id<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    generation: &GenerationId,
) -> Result<Option<(crate::types::Bucket, GenerationRow)>> {
    let sql = GENERATION_BY_ID;
    let rows = c
        .sql
        .query(sql, &[text(generation.as_str()), text(bucket.as_str())])
        .await?;
    let Some(mut row) = rows.into_iter().next() else {
        return Ok(None);
    };
    if row.len() != GENERATION_WIDTH + 7 {
        return Err(bad("generation and bucket width"));
    }
    let bucket = row.split_off(GENERATION_WIDTH);
    Ok(Some((
        super::auth::bucket_row(bucket)?,
        generation_row(row)?,
    )))
}

/// The select list of an extent as a generation references it: `seq` and
/// `plain_offset` come from the reference, not from the generation the
/// extent was first written for.
macro_rules! placed_extent_cols {
    () => {
        "e.id, e.bucket_id, e.generation_id, e.state, ge.seq, ge.plain_offset, \
     e.plain_size, e.cipher_size, e.media_header, e.key_mode, e.wrapped_file_key, \
     e.plain_md5, e.plain_sha256, e.cipher_sha256, e.safety_state, e.article_count, \
     e.plan_rev, e.last_verified_at, e.release_evidence, e.released_at, e.created_at"
    };
}

/// The last `seq` of generation `?1` whose reference begins at or
/// before (`$cmp` is `<=`) or before (`<`) the offset `$at`, as a
/// recursive common table expression named `$name`; -1 when there is
/// none. Its answer is the row with `hi - lo <= 1`.
///
/// Offsets rise with `seq`, so the condition holds for a run of
/// references from the first on, and the end of that run is found by
/// halving `(lo, hi)`: `lo` is -1 or a `seq` the condition holds for,
/// `hi` is one past the last `seq` or a `seq` it does not hold for. Each
/// step seeks the primary key twice, once for each bound it sets: about
/// 17 steps and 34 seeks for 131,072 references, where walking the key
/// backwards read every reference behind the range.
///
/// Writers number references from 0 without a gap, but nothing in the
/// schema says so. A step therefore reads the first reference at or
/// after the middle rather than the one exactly there: the condition
/// still holds for a run from the first `seq` on, and a `seq` that has
/// no reference stands for the next one that has.
macro_rules! bisect {
    ($name:literal, $cmp:literal, $at:literal, $seed:literal) => {
        concat!(
            $name,
            "(lo, hi) AS (SELECT ",
            $seed,
            ", COALESCE((SELECT MAX(seq) + 1 FROM generation_extents \
                WHERE generation_id = ?1), 0) \
              UNION ALL \
              SELECT CASE WHEN (SELECT plain_offset FROM generation_extents \
                                 WHERE generation_id = ?1 AND seq >= (b.lo + b.hi) / 2 \
                                 ORDER BY seq LIMIT 1) ",
            $cmp,
            " ",
            $at,
            " THEN (b.lo + b.hi) / 2 ELSE b.lo END, \
                     CASE WHEN (SELECT plain_offset FROM generation_extents \
                                 WHERE generation_id = ?1 AND seq >= (b.lo + b.hi) / 2 \
                                 ORDER BY seq LIMIT 1) ",
            $cmp,
            " ",
            $at,
            " THEN b.hi ELSE (b.lo + b.hi) / 2 END \
                FROM ",
            $name,
            " b WHERE b.hi - b.lo > 1)"
        )
    };
}

/// The extents of `generation` that hold plaintext `[start, end)`.
///
/// Offsets rise with `seq`, so the range is one run of the primary key:
/// from the last reference that begins at or before `start` to the last
/// that begins before `end`. Both ends are found by bisecting `seq`
/// (`bisect!`), which reads a few references whatever the size of the
/// object and no extent row; only the extents of the range itself are
/// joined.
///
/// Which rows a range selects is not covered by the authentication of
/// an extent. The reader checks that what it is given tiles the range
/// (`service/get.rs`, `pieces`), and `tests/sql_objects.rs` holds this
/// statement to the one it replaced.
pub(super) async fn extents_in<S: Sql>(
    c: &SqlCatalog<S>,
    generation: &GenerationId,
    start: u64,
    end: u64,
) -> Result<Vec<ExtentRow>> {
    let (Ok(start), Ok(end)) = (i64::try_from(start), i64::try_from(end)) else {
        return Err(bad("range offset"));
    };
    let sql = c.sql.dialect().pick(EXTENTS_IN, EXTENTS_IN_PG);
    let rows = c
        .sql
        .query(
            sql,
            &[
                text(generation.as_str()),
                SqlValue::Int(start),
                SqlValue::Int(end),
            ],
        )
        .await?;
    rows.into_iter().map(extent_row).collect()
}

pub(super) async fn live_object<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
    let Some(generation) = live_generation(c, bucket, key).await? else {
        return Ok(None);
    };
    // The extents this generation references, placed where it has them:
    // `seq` and `plain_offset` come from the reference, not from the
    // generation the extent was first written for.
    let rows = c
        .sql
        .query(LIVE_EXTENTS, &[text(generation.id.as_str())])
        .await?;
    let extents = rows.into_iter().map(extent_row).collect::<Result<_>>()?;
    Ok(Some((generation, extents)))
}

// ---------------------------------------------------------------------------
// Publication and deletion
// ---------------------------------------------------------------------------

pub(super) type Stmt = (&'static str, Vec<SqlValue>);

/// The extents that leave service when the generation `objects` points
/// at for `(?1, ?2)` is retired: those it references that no other live
/// generation and no open upload references.
macro_rules! retiring {
    () => {
        concat!(
            "SELECT DISTINCT ge.extent_id FROM objects o \
               JOIN generation_extents ge ON ge.generation_id = o.generation_id \
              WHERE o.bucket_id = ?1 AND o.key = ?2 AND NOT ",
            live_ref!("ge.extent_id", except "o.generation_id"),
            " AND NOT ",
            part_ref!("ge.extent_id")
        )
    };
}

/// Statements that retire whatever generation `objects` points at for
/// `(bucket, key)`: its state flipped and, for each extent that leaves
/// service with it (see `retiring!`), GC rows queued and the posting
/// obligation cancelled. An extent another live generation still
/// references (a copy) is left alone. They must run before the pointer is
/// moved or removed and after the replacing generation, if any, has its
/// extent references; all are no-ops when the key has no live object.
pub(super) fn retire_live(
    bucket: &BucketId,
    key: &str,
    to: GenerationState,
    now: UnixMs,
) -> Vec<Stmt> {
    retire_live_in(Dialect::Sqlite, bucket, key, to, now)
}

pub(super) fn retire_live_in(
    dialect: Dialect,
    bucket: &BucketId,
    key: &str,
    to: GenerationState,
    now: UnixMs,
) -> Vec<Stmt> {
    let b = || text(bucket.as_str());
    vec![
        (
            dialect.pick(RETIRE_GC, RETIRE_GC_PG),
            vec![b(), text(key), ms(now), ms(now.plus_ms(SHRED_GRACE_MS))],
        ),
        (RETIRE_OUTBOX, vec![b(), text(key), ms(now)]),
        (
            RETIRE_GENERATION,
            vec![b(), text(key), text(to.as_str()), ms(now)],
        ),
    ]
}

/// The row of a new live generation.
fn generation_insert(g: &GenerationRow) -> Result<Stmt> {
    Ok((
        INSERT_GENERATION,
        vec![
            text(g.id.as_str()),
            text(g.bucket_id.as_str()),
            text(&g.key),
            text(g.state.as_str()),
            uint(g.size)?,
            text(&g.etag),
            opt(g.checksum_json.as_deref(), text),
            text(&g.content_json),
            text(&g.user_meta_json),
            SqlValue::Int(i64::from(g.extent_count)),
            ms(g.created_at),
        ],
    ))
}

/// Points `(bucket, key)` of `g` at it.
fn pointer_upsert(g: &GenerationRow) -> Stmt {
    (
        UPSERT_POINTER,
        vec![
            text(g.bucket_id.as_str()),
            text(&g.key),
            text(g.id.as_str()),
        ],
    )
}

/// Inserts a freshly sealed extent as `committed` in `generation`.
fn extent_insert(e: &ExtentRow, generation: &GenerationId) -> Result<Stmt> {
    Ok((
        INSERT_EXTENT,
        vec![
            text(e.id.as_str()),
            text(e.bucket_id.as_str()),
            text(generation.as_str()),
            text(ExtentState::Committed.as_str()),
            opt(e.seq, |v| SqlValue::Int(i64::from(v))),
            e.plain_offset.map_or(Ok(SqlValue::Null), uint)?,
            uint(e.plain_size)?,
            uint(e.cipher_size)?,
            SqlValue::Blob(e.media_header.clone()),
            SqlValue::Int(i64::from(e.key_mode)),
            opt(e.wrapped_file_key.clone(), SqlValue::Blob),
            SqlValue::Blob(e.plain_md5.to_vec()),
            SqlValue::Blob(e.plain_sha256.to_vec()),
            SqlValue::Blob(e.cipher_sha256.to_vec()),
            text(e.safety_state.as_str()),
            opt(e.article_count, |v| SqlValue::Int(i64::from(v))),
            SqlValue::Int(i64::from(e.plan_rev)),
            opt(e.last_verified_at, ms),
            opt(e.release_evidence.as_deref(), text),
            opt(e.released_at, ms),
            ms(e.created_at),
        ],
    ))
}

/// Raises the floor of `(bucket, key)` to `id` if it is lower. Called
/// before a recovery record with that id is stored, in a statement of
/// its own: whatever happens to the record's own batch afterwards, every
/// later id on the key is minted above it ([`newest_id`]) and held to
/// that ([`guard_newest`]). A floor raised for a write that then fails
/// costs nothing. `generation` = the record is a generation manifest:
/// the floor then also says that a record may exist that was never
/// published ([`unpublished_floor`]).
///
/// Returns the rows changed: 1 when the key now has a floor at or above
/// `id`, 0 when the catalogue has no such bucket.
pub(super) async fn raise_floor<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
    id: &GenerationId,
    generation: bool,
) -> Result<u64> {
    let (sql, params) = raise_floor_stmt(c.sql.dialect(), bucket, key, id, generation);
    c.sql.exec(sql, &params).await
}

fn raise_floor_stmt(
    dialect: Dialect,
    bucket: &BucketId,
    key: &str,
    id: &GenerationId,
    generation: bool,
) -> Stmt {
    (
        // Nothing for a bucket the catalogue does not have (a replay
        // can read a tombstone of one): nothing is published there.
        dialect.pick(RAISE_FLOOR, RAISE_FLOOR_PG),
        vec![
            text(bucket.as_str()),
            text(key),
            text(id.as_str()),
            SqlValue::Int(i64::from(generation)),
        ],
    )
}

/// [`raise_floor`] for the tombstone of every `(key, id)`, as one batch.
/// `false` = the catalogue has no such bucket, and no floor was raised.
pub(super) async fn raise_floors<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    ids: &[(&str, &GenerationId)],
) -> Result<bool> {
    let stmts: Vec<Stmt> = ids
        .iter()
        .map(|(key, id)| raise_floor_stmt(c.sql.dialect(), bucket, key, id, false))
        .collect();
    // One transaction: the bucket is there for every statement or for
    // none, so either every key has its floor or no row was changed.
    let changed = c.sql.batch(stmts).await?;
    Ok(changed.iter().all(|n| *n == 1))
}

/// The tombstone `id` of `(bucket, key)` is stored: it covers every
/// record the floor was raised for so far, if the floor is not above it.
/// A record whose floor is raised after this sets the mark again.
pub(super) async fn settle_floor<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
    id: &GenerationId,
) -> Result<()> {
    let (sql, params) = settle_floor_stmt(bucket, key, id);
    c.sql.exec(sql, &params).await.map(|_| ())
}

fn settle_floor_stmt(bucket: &BucketId, key: &str, id: &GenerationId) -> Stmt {
    (
        SETTLE_FLOOR,
        vec![text(bucket.as_str()), text(key), text(id.as_str())],
    )
}

/// [`settle_floor`] for every `(key, id)`, as one batch.
pub(super) async fn settle_floors<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    ids: &[(&str, &GenerationId)],
) -> Result<()> {
    let stmts = ids
        .iter()
        .map(|(key, id)| settle_floor_stmt(bucket, key, id))
        .collect();
    c.sql.batch(stmts).await.map(|_| ())
}

/// The live id and the floor of every key of `keys`, in its order. One
/// statement, so the answer is the catalogue of one moment. The keys go
/// as one JSON array; each row names the place and the text of its key,
/// and an answer that is not exactly the keys asked for is an error.
pub(super) async fn key_heads<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    keys: &[&str],
) -> Result<Vec<KeyHead>> {
    let bad = || BridgeError::Sql("key_heads: unexpected row".into());
    let list = serde_json::to_string(keys).map_err(|_| bad())?;
    let rows = c
        .sql
        .query(
            c.sql.dialect().pick(KEY_HEADS, KEY_HEADS_PG),
            &[text(bucket.as_str()), text(&list)],
        )
        .await?;
    if rows.len() != keys.len() {
        return Err(bad());
    }
    let id = |v: SqlValue| match v {
        SqlValue::Text(id) => Ok(Some(GenerationId::new(id))),
        SqlValue::Null => Ok(None),
        _ => Err(bad()),
    };
    rows.into_iter()
        .zip(keys.iter().enumerate())
        .map(|(row, (i, key))| {
            let [at, value, live, floor, unpublished] =
                <[SqlValue; 5]>::try_from(row).map_err(|_| bad())?;
            if at != SqlValue::Int(i as i64) || value != SqlValue::Text((*key).to_owned()) {
                return Err(bad());
            }
            Ok(KeyHead {
                live: id(live)?,
                floor: id(floor)?,
                unpublished: match unpublished {
                    SqlValue::Int(n) => n != 0,
                    SqlValue::Null => false,
                    _ => return Err(bad()),
                },
            })
        })
        .collect()
}

/// The floor of `(bucket, key)` if a generation record may exist under
/// it that no tombstone covers: the record of a write that was not
/// published and was not removed. While the key has a live generation,
/// that one is on top of such a record; without one, a replay would
/// publish the record, so a delete of the key must leave a tombstone.
pub(super) async fn unpublished_floor<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
) -> Result<Option<GenerationId>> {
    let rows = c
        .sql
        .query(UNPUBLISHED_FLOOR, &[text(bucket.as_str()), text(key)])
        .await?;
    match rows.first().map(Vec::as_slice) {
        Some([SqlValue::Text(id)]) => Ok(Some(GenerationId::new(id.clone()))),
        None => Ok(None),
        Some(_) => Err(BridgeError::Sql("unpublished_floor: unexpected row".into())),
    }
}

/// Guard of every publication: `id` sorts after the live generation of
/// `(bucket, key)` and is not below the key's floor, the highest id a
/// recovery record of the key was ever stored under (the publication
/// raised it to its own id before it stored its record). Ids on one key
/// are then in commit order, the order a replay of the recovery records
/// rebuilds; a clock that runs behind cannot publish "into the past",
/// and neither can a write that sorts before the record of a delete or
/// of a write that failed. The floor itself passes: it is this
/// publication's own id, or an id only 64 equal random bits could repeat.
pub(super) fn guard_newest(bucket: &BucketId, key: &str, id: &GenerationId) -> Stmt {
    (
        GUARD_NEWEST,
        vec![text(bucket.as_str()), text(key), text(id.as_str())],
    )
}

/// Guard of a conditional write: the live object of `(bucket, key)`
/// meets `condition` ([`Precondition::check`] decides the same way). It
/// is a statement of the batch that publishes or deletes, placed before
/// the statements that retire the live generation and move the pointer:
/// it reads the object that batch replaces. Of two conditional writes
/// that race for one key, the batch that runs second sees what the
/// first published and writes nothing.
pub(super) fn guard_precondition(bucket: &BucketId, key: &str, condition: &Precondition) -> Stmt {
    let at = || vec![text(bucket.as_str()), text(key)];
    match condition {
        Precondition::Absent => (GUARD_ABSENT, at()),
        Precondition::Exists => (GUARD_PRESENT, at()),
        Precondition::Etag(etag) => {
            let mut params = at();
            params.push(text(etag));
            (GUARD_ETAG, params)
        }
    }
}

/// The key lives under `id`: a floor at or below it has nothing left to
/// hold back, the live pointer does it from here.
pub(super) fn clear_floor(bucket: &BucketId, key: &str, id: &GenerationId) -> Stmt {
    (
        CLEAR_FLOOR,
        vec![text(bucket.as_str()), text(key), text(id.as_str())],
    )
}

/// The newest id in the history of `(bucket, key)`: the live generation
/// or the floor, whichever sorts later.
pub(super) async fn newest_id<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
) -> Result<Option<GenerationId>> {
    let rows = c
        .sql
        .query(NEWEST_ID, &[text(bucket.as_str()), text(key)])
        .await?;
    match rows.first().map(Vec::as_slice) {
        Some([SqlValue::Text(id)]) => Ok(Some(GenerationId::new(id.clone()))),
        Some([SqlValue::Null]) | None => Ok(None),
        Some(_) => Err(BridgeError::Sql("newest_id: unexpected row".into())),
    }
}

/// Publishes one new generation of a single PUT. One batch: the new
/// generation with its extents and posting obligations, the previous
/// generation retired with GC rows, and the live pointer moved. Any
/// failing statement leaves the catalogue exactly as it was. `Lost` =
/// the key already has a newer id ([`guard_newest`]).
///
/// With `write`, the body was stored as slices under that write: the
/// batch also commits only while every intent of the write is still
/// `open` under this generation id, and deletes the intents.
pub(super) async fn commit_generation<S: Sql>(
    c: &SqlCatalog<S>,
    commit: &CommitGeneration,
    write: Option<&WriteId>,
    condition: Option<&Precondition>,
    record: Recorded,
) -> Result<PublishOutcome> {
    let g = &commit.generation;
    // The extents must tile the object exactly, in order: a gap or an
    // overlap here would be served as wrong bytes later. Each must still
    // have its key and its pinned copy, or the object could not be read.
    let mut offset = 0u64;
    let mut tiled = usize::try_from(g.extent_count).ok() == Some(commit.extents.len());
    for (i, e) in commit.extents.iter().enumerate() {
        tiled &= e.bucket_id == g.bucket_id
            && e.generation_id.as_ref().is_none_or(|id| id == &g.id)
            && e.seq.map(u64::from) == u64::try_from(i).ok()
            && e.plain_offset == Some(offset)
            && e.wrapped_file_key.is_some()
            && e.safety_state == SafetyState::Held;
        offset = offset.saturating_add(e.plain_size);
    }
    if !tiled || offset != g.size || g.state != GenerationState::Live || g.retired_at.is_some() {
        return Err(BridgeError::Invalid(
            "commit does not describe one live generation",
        ));
    }

    let mut stmts: Vec<Stmt> = Vec::with_capacity(10 + 3 * commit.extents.len());
    stmts.push(guard_no_replay());
    stmts.extend(condition.map(|c| guard_precondition(&g.bucket_id, &g.key, c)));
    stmts.push(guard_newest(&g.bucket_id, &g.key, &g.id));
    stmts.push(clear_floor(&g.bucket_id, &g.key, &g.id));
    stmts.push(generation_insert(g)?);
    for e in &commit.extents {
        stmts.push(extent_insert(e, &g.id)?);
        // The reference reads go through. `OR IGNORE`: the migration's
        // trigger records the same row for the insert above.
        stmts.push((
            c.sql
                .dialect()
                .pick(INSERT_EXTENT_REFERENCE, INSERT_EXTENT_REFERENCE_PG),
            vec![text(e.id.as_str())],
        ));
        stmts.push((
            // Marked as sent from the start (`sent_at`): the caller
            // sends the post job itself (`Catalog::commit_generation`).
            ENQUEUE_POST,
            vec![text(e.id.as_str()), text(g.id.as_str()), ms(commit.now)],
        ));
    }
    if let Some(write) = write {
        stmts.extend(publish_intents(
            c.sql.dialect(),
            write,
            &g.id,
            commit.extents.len(),
        )?);
    }
    stmts.extend(retire_live_in(
        c.sql.dialect(),
        &g.bucket_id,
        &g.key,
        GenerationState::Superseded,
        commit.now,
    ));
    stmts.push(pointer_upsert(g));
    published(c, stmts, &g.id, record).await
}

/// Publishes a copy: a new generation that references the extents of the
/// source generation, in the same order and at the same offsets. One
/// batch:
/// - guard: the source is still the live object of its key, so its
///   extents are in service and the row the caller read is the one copied;
/// - the new generation and its references, and a guard that there are
///   as many as the generation claims. No extent, key or posting
///   obligation is written: the extents keep the ones they have;
/// - the destination's previous generation retired. When the destination
///   is the source key, that is the source itself, and its extents stay in
///   service through the new references;
/// - the live pointer moved.
pub(super) async fn copy_generation<S: Sql>(
    c: &SqlCatalog<S>,
    copy: &CopyGeneration,
    condition: Option<&Precondition>,
    record: Recorded,
) -> Result<PublishOutcome> {
    let g = &copy.generation;
    if g.state != GenerationState::Live || g.retired_at.is_some() || g.id == copy.source {
        return Err(BridgeError::Invalid(
            "copy does not describe one new live generation",
        ));
    }
    let source = || text(copy.source.as_str());
    let mut stmts: Vec<Stmt> = vec![
        (
            GUARD_COPY_SOURCE,
            vec![
                text(g.bucket_id.as_str()),
                text(&copy.source_key),
                source(),
                uint(g.size)?,
                text(&g.etag),
                SqlValue::Int(i64::from(g.extent_count)),
            ],
        ),
        guard_no_replay(),
    ];
    // On the destination key. The source has its own guard above.
    stmts.extend(condition.map(|c| guard_precondition(&g.bucket_id, &g.key, c)));
    stmts.extend([
        // The copy is the newest id of its key as well, as for a PUT.
        guard_newest(&g.bucket_id, &g.key, &g.id),
        clear_floor(&g.bucket_id, &g.key, &g.id),
        generation_insert(g)?,
        (COPY_REFERENCES, vec![text(g.id.as_str()), source()]),
        // The copy has every reference its row claims, as a completed
        // upload is held to: a source with fewer than it claims is never
        // copied into an object that reads short.
        (
            GUARD_REFERENCE_COUNT,
            vec![
                text(g.id.as_str()),
                SqlValue::Int(i64::from(g.extent_count)),
            ],
        ),
    ]);
    stmts.extend(retire_live_in(
        c.sql.dialect(),
        &g.bucket_id,
        &g.key,
        GenerationState::Superseded,
        copy.now,
    ));
    stmts.push(pointer_upsert(g));
    published(c, stmts, &g.id, record).await
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

/// For NUL-free stored text, being strictly after `abc\0...` is
/// equivalent to being strictly after `abc` in byte order.
pub(super) fn before_nul(s: &str) -> &str {
    s.split_once('\0').map_or(s, |(prefix, _)| prefix)
}

/// The least string greater than every string that starts with `s`, or
/// `None` when no such string exists (`s` is empty or all U+10FFFF).
/// UTF-8 byte order equals code-point order, so this is also the bound in
/// SQLite's binary text collation.
pub(super) fn successor(s: &str) -> Option<String> {
    let mut chars: Vec<char> = s.chars().collect();
    while let Some(c) = chars.pop() {
        let next = match u32::from(c) {
            0xD7FF => Some('\u{E000}'), // step over the surrogate gap
            n => char::from_u32(n + 1),
        };
        if let Some(n) = next {
            chars.push(n);
            return Some(chars.into_iter().collect());
        }
    }
    None
}

/// The inclusive lower bound after a skipped prefix. No stored key can
/// contain NUL, so the first valid extension of its NUL-free head is U+0001.
pub(super) fn skip_prefix_bound(done: &str) -> Option<String> {
    if let Some((head, _)) = done.split_once('\0') {
        Some(format!("{head}\u{1}"))
    } else {
        successor(done)
    }
}

/// One ListObjectsV2 page. The prefix is a key range (no `LIKE`). With a
/// delimiter, keys are folded into common prefixes here and the scan
/// seeks past each emitted prefix. The returned cursor carries the last
/// key consumed and the prefix being skipped, so the next page never
/// repeats a common prefix.
pub(super) async fn list<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    q: &ListQuery,
) -> Result<ListPage> {
    let mut page = ListPage::default();
    if q.max_keys == 0 || q.prefix.contains('\0') {
        return Ok(page);
    }
    let delimiter = q
        .delimiter
        .as_deref()
        .filter(|d| !d.is_empty() && !d.contains('\0'));
    let upper = successor(&q.prefix);
    let sql = if upper.is_some() {
        LIST_OBJECTS_BELOW
    } else {
        LIST_OBJECTS
    };

    let mut from = q.prefix.clone(); // inclusive lower bound
    let mut after = before_nul(q.after.as_deref().unwrap_or_default()).to_owned(); // exclusive lower bound
    let mut skip: Option<String> = None; // common prefix being folded
    if let Some(done) = &q.skip_prefix {
        match skip_prefix_bound(done) {
            Some(s) => from = from.max(s),
            None => return Ok(page),
        }
    }

    let mut emitted = 0u32;
    for _ in 0..LIST_QUERY_BUDGET {
        // One look-ahead row decides truncation.
        let limit = (q.max_keys - emitted).min(LIST_BATCH_MAX) + 1;
        let mut params = vec![
            text(bucket.as_str()),
            text(&from),
            text(&after),
            SqlValue::Int(i64::from(limit)),
        ];
        params.extend(upper.as_deref().map(text));
        let rows = c.sql.query(sql, &params).await?;
        let full = u32::try_from(rows.len()).ok() == Some(limit);

        for row in rows {
            let mut cols = Cols::new(row);
            let key = cols.text()?;
            if skip.as_deref().is_some_and(|p| key.starts_with(p)) {
                after = key;
                continue;
            }
            let folded = delimiter.and_then(|d| {
                let rest = key.get(q.prefix.len()..)?;
                let end = q.prefix.len() + rest.find(d)? + d.len();
                Some(key[..end].to_string())
            });
            // A common prefix that the lower bound lies inside sorts at or
            // before that bound: it is not reported, and its keys are skipped.
            if let Some(prefix) = &folded {
                if q.after.as_deref().is_some_and(|a| a.starts_with(prefix)) {
                    skip = folded;
                    after = key;
                    continue;
                }
            }
            if emitted == q.max_keys {
                page.next = Some(ListCursor {
                    after,
                    skip_prefix: skip,
                });
                return Ok(page);
            }
            match folded {
                Some(prefix) => {
                    page.common_prefixes.push(prefix.clone());
                    skip = Some(prefix);
                }
                None => {
                    page.entries.push(ListEntry {
                        key: key.clone(),
                        size: cols.num()?,
                        etag: cols.text()?,
                        last_modified: cols.ms()?,
                    });
                    skip = None;
                }
            }
            emitted += 1;
            after = key;
        }

        if !full {
            return Ok(page);
        }
        if let Some(prefix) = &skip {
            // Seek past the rest of the folded prefix in one step.
            match successor(prefix) {
                Some(s) => from = s,
                None => return Ok(page),
            }
        }
    }
    // Query budget spent: a valid partial page; the next one resumes here.
    page.next = Some(ListCursor {
        after,
        skip_prefix: skip,
    });
    Ok(page)
}

/// See [`crate::ports::Catalog::list_heads`]. With a delimiter this is
/// one statement, a skip-scan: each step of the recursion seeks the next
/// key on the primary key of `objects` (one row), and after a key that
/// holds the delimiter past the prefix it seeks to the successor of that
/// key's group. `q.max_keys` heads cost about three rows each (the seek,
/// the object, its generation), however many keys the groups hold.
pub(super) async fn list_heads<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    q: &ListQuery,
) -> Result<Vec<ListEntry>> {
    if q.max_keys == 0 || q.prefix.contains('\0') {
        return Ok(Vec::new());
    }
    // "Fewer rows than asked for" must mean the range is exhausted, so
    // a request for more than one statement returns is refused, not cut.
    if q.max_keys > LIST_BATCH_MAX + 1 {
        return Err(BridgeError::Invalid("list_heads: more than one batch"));
    }
    let limit = q.max_keys;
    let upper = successor(&q.prefix);
    // One lower bound: inclusive at `from`, or exclusive at `after`.
    let mut from = q.prefix.clone();
    if let Some(done) = &q.skip_prefix {
        match skip_prefix_bound(done) {
            Some(s) => from = from.max(s),
            None => return Ok(Vec::new()),
        }
    }
    let after = before_nul(q.after.as_deref().unwrap_or_default()).to_owned();
    let (bound, exclusive) = if after >= from {
        (after, true)
    } else {
        (from, false)
    };
    // The successor of a group is its head up to the delimiter, then the
    // successor of the delimiter. A delimiter that has none (all
    // U+10FFFF) is listed row by row: the caller folds either way.
    let group = q
        .delimiter
        .as_deref()
        .filter(|d| !d.is_empty() && !d.contains('\0'))
        .and_then(|d| Some((d, successor(d)?)));

    let mut params = vec![
        text(bucket.as_str()),
        text(&bound),
        SqlValue::Int(i64::from(limit)),
    ];
    let sql = match &group {
        None => {
            params.extend(upper.as_deref().map(text));
            match (exclusive, upper.is_some()) {
                (true, true) => HEADS_EXCLUSIVE_BELOW,
                (true, false) => HEADS_EXCLUSIVE,
                (false, true) => HEADS_INCLUSIVE_BELOW,
                (false, false) => HEADS_INCLUSIVE,
            }
        }
        Some((delimiter, next)) => {
            // SQLite uses CROSS JOIN to seek the object by each head instead
            // of scanning the bucket. PG uses the C-collated keys and strpos
            // with character offsets (the bound prefix length is INT8).
            let prefix_chars = i64::try_from(q.prefix.chars().count())
                .map_err(|_| BridgeError::Invalid("list prefix length"))?;
            params.extend([SqlValue::Int(prefix_chars), text(delimiter), text(next)]);
            params.extend(upper.as_deref().map(text));
            let dialect = c.sql.dialect();
            match (exclusive, upper.is_some()) {
                (true, true) => dialect.pick(GROUPED_EXCLUSIVE_BELOW, GROUPED_EXCLUSIVE_BELOW_PG),
                (true, false) => dialect.pick(GROUPED_EXCLUSIVE, GROUPED_EXCLUSIVE_PG),
                (false, true) => dialect.pick(GROUPED_INCLUSIVE_BELOW, GROUPED_INCLUSIVE_BELOW_PG),
                (false, false) => dialect.pick(GROUPED_INCLUSIVE, GROUPED_INCLUSIVE_PG),
            }
        }
    };
    let rows = c.sql.query(sql, &params).await?;
    let mut heads = Vec::with_capacity(rows.len());
    for row in rows {
        let mut cols = Cols::new(row);
        heads.push(ListEntry {
            key: cols.text()?,
            size: cols.num()?,
            etag: cols.text()?,
            last_modified: cols.ms()?,
        });
    }
    Ok(heads)
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

pub(super) async fn object_status<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
) -> Result<Option<ObjectStatus>> {
    let sql = LIVE_GENERATION;
    let rows = c
        .sql
        .query(sql, &[text(bucket.as_str()), text(key)])
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let generation = generation_row(row)?;
    let gid = [text(generation.id.as_str())];

    let rows = c.sql.query(STATUS_EXTENTS, &gid).await?;
    let mut extents = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        extents.push(ExtentStatus {
            extent_id: ExtentId::new(r.text()?),
            seq: r.opt_num()?,
            safety_state: r.parsed(SafetyState::parse)?,
            stage: r
                .opt_text()?
                .map(|s| OutboxStage::parse(&s).ok_or_else(|| bad("unknown enum value")))
                .transpose()?,
            attempts: r.opt_num()?.unwrap_or(0),
            last_error: r.opt_text()?,
            backbones: Vec::new(),
        });
    }

    // Latest verification per backbone at the extent's current plan_rev.
    let rows = c.sql.query(STATUS_VERIFICATIONS, &gid).await?;
    for row in rows {
        let mut r = Cols::new(row);
        let extent_id = r.text()?;
        let mut status = BackboneStatus {
            backbone: r.text()?,
            provider_id: r.text()?,
            verified_at: r.ms()?,
            plan_rev: r.num()?,
            articles_ok: r.num()?,
            articles_total: r.num()?,
            result: r.parsed(VerifyResult::parse)?,
            kind: {
                let (kind, mode) = (r.text()?, r.opt_text()?);
                VerifyKind::from_columns(&kind, mode.as_deref())
                    .ok_or_else(|| BridgeError::Sql("unknown verification kind".into()))?
            },
            counts: false,
        };
        let article_count: Option<u32> = r.opt_num()?;
        status.counts = status.result == VerifyResult::Ok
            && status.articles_ok == status.articles_total
            && article_count == Some(status.articles_total);
        if let Some(e) = extents
            .iter_mut()
            .find(|e| e.extent_id.as_str() == extent_id)
        {
            e.backbones.push(status);
        }
    }
    Ok(Some(ObjectStatus {
        generation,
        extents,
    }))
}

/// Compare-and-set: `true` only if the extent was in `from`.
pub(super) async fn set_safety_state<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    from: SafetyState,
    to: SafetyState,
) -> Result<bool> {
    let changed = c
        .sql
        .exec(
            // Every change of state bumps the eviction fence, so an eviction
            // listed before it is refused.
            SAFETY_CAS,
            &[
                text(extent.as_str()),
                text(from.as_str()),
                text(to.as_str()),
            ],
        )
        .await?;
    // At least one: a usage-counter trigger adds its own row to the
    // count, and only when the extent's row was changed.
    Ok(changed >= 1)
}

const LIVE_EXTENTS: &str =
    "SELECT e.id, e.bucket_id, e.generation_id, e.state, ge.seq, ge.plain_offset, \
               e.plain_size, e.cipher_size, e.media_header, e.key_mode, e.wrapped_file_key, \
               e.plain_md5, e.plain_sha256, e.cipher_sha256, e.safety_state, e.article_count, \
               e.plan_rev, e.last_verified_at, e.release_evidence, e.released_at, e.created_at \
             FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
             WHERE ge.generation_id = ?1 ORDER BY ge.seq";

const RETIRE_GENERATION: &str = "UPDATE generations SET state = ?3, retired_at = ?4 WHERE id = \
               (SELECT generation_id FROM objects WHERE bucket_id = ?1 AND key = ?2)";

const INSERT_GENERATION: &str =
    "INSERT INTO generations(id, bucket_id, key, state, size, etag, checksum_json, \
           content_json, user_meta_json, extent_count, created_at, retired_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL)";

const UPSERT_POINTER: &str =
    "INSERT INTO objects(bucket_id, key, generation_id) VALUES (?1, ?2, ?3) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET generation_id = excluded.generation_id";

const INSERT_EXTENT: &str =
    "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, plain_size, \
           cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, \
           cipher_sha256, safety_state, article_count, plan_rev, last_verified_at, \
           release_evidence, released_at, created_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)";

const RAISE_FLOOR_PG: &str = "INSERT INTO key_floors(bucket_id, key, floor_id, unpublished) \
         SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM buckets WHERE id = ?1) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET \
           floor_id = GREATEST(key_floors.floor_id, excluded.floor_id), \
           unpublished = GREATEST(key_floors.unpublished, excluded.unpublished)";

const RAISE_FLOOR: &str = "INSERT INTO key_floors(bucket_id, key, floor_id, unpublished) \
         SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM buckets WHERE id = ?1) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET \
           floor_id = max(floor_id, excluded.floor_id), \
           unpublished = max(unpublished, excluded.unpublished)";

const SETTLE_FLOOR: &str = "UPDATE key_floors SET unpublished = 0 \
         WHERE bucket_id = ?1 AND key = ?2 AND floor_id <= ?3 AND unpublished <> 0";

const KEY_HEADS_PG: &str = "SELECT k.ord - 1, k.value, o.generation_id, f.floor_id, f.unpublished \
             FROM jsonb_array_elements_text(?2::jsonb) WITH ORDINALITY k(value, ord) \
             LEFT JOIN objects o ON o.bucket_id = ?1 AND o.key = k.value \
             LEFT JOIN key_floors f ON f.bucket_id = ?1 AND f.key = k.value \
             ORDER BY k.ord";

const KEY_HEADS: &str = "SELECT k.key, k.value, o.generation_id, f.floor_id, f.unpublished \
             FROM json_each(?2) k \
             LEFT JOIN objects o ON o.bucket_id = ?1 AND o.key = k.value \
             LEFT JOIN key_floors f ON f.bucket_id = ?1 AND f.key = k.value \
             ORDER BY k.key";

const UNPUBLISHED_FLOOR: &str = "SELECT floor_id FROM key_floors \
             WHERE bucket_id = ?1 AND key = ?2 AND unpublished <> 0";

const GUARD_NEWEST: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS (SELECT 1 FROM objects \
           WHERE bucket_id = ?1 AND key = ?2 AND generation_id >= ?3) \
         OR EXISTS (SELECT 1 FROM key_floors \
           WHERE bucket_id = ?1 AND key = ?2 AND floor_id > ?3)";

const GUARD_ABSENT: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS (SELECT 1 FROM objects \
               WHERE bucket_id = ?1 AND key = ?2)";

const GUARD_PRESENT: &str =
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM objects \
               WHERE bucket_id = ?1 AND key = ?2)";

const GUARD_ETAG: &str =
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM objects o \
                   JOIN generations g ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
                  WHERE o.bucket_id = ?1 AND o.key = ?2 AND g.etag = ?3)";

const CLEAR_FLOOR: &str =
    "DELETE FROM key_floors WHERE bucket_id = ?1 AND key = ?2 AND floor_id <= ?3";

const NEWEST_ID: &str = "SELECT max(id) FROM (SELECT generation_id AS id FROM objects \
               WHERE bucket_id = ?1 AND key = ?2 \
             UNION ALL SELECT floor_id FROM key_floors \
               WHERE bucket_id = ?1 AND key = ?2)";

const INSERT_EXTENT_REFERENCE_PG: &str =
    "INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
             SELECT generation_id, seq, id, plain_offset FROM extents WHERE id = ?1 \
          ON CONFLICT (generation_id, seq) DO NOTHING";

const INSERT_EXTENT_REFERENCE: &str =
    "INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
             SELECT generation_id, seq, id, plain_offset FROM extents WHERE id = ?1";

const ENQUEUE_POST: &str =
    "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at, sent_at) \
             VALUES (?1, ?2, 'post', ?3, ?3, ?3)";

const GUARD_COPY_SOURCE: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS ( \
               SELECT 1 FROM objects o JOIN generations s ON s.id = o.generation_id \
                WHERE o.bucket_id = ?1 AND o.key = ?2 AND o.generation_id = ?3 \
                  AND s.bucket_id = ?1 AND s.state = 'live' \
                  AND s.size = ?4 AND s.etag = ?5 AND s.extent_count = ?6)";

const COPY_REFERENCES: &str =
    "INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
             SELECT ?1, seq, extent_id, plain_offset FROM generation_extents \
              WHERE generation_id = ?2";

const GUARD_REFERENCE_COUNT: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
               (SELECT COUNT(*) FROM generation_extents WHERE generation_id = ?1) <> ?2";

const STATUS_EXTENTS: &str =
    "SELECT e.id, ge.seq, e.safety_state, o.stage, o.attempts, o.last_error \
             FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
             LEFT JOIN outbox o ON o.extent_id = e.id \
             WHERE ge.generation_id = ?1 ORDER BY ge.seq";

const STATUS_VERIFICATIONS: &str =
    "SELECT v.extent_id, v.backbone, v.provider_id, v.verified_at, v.plan_rev, \
               CASE v.kind WHEN 'stat' THEN v.articles_present ELSE v.articles_ok END, \
               v.articles_total, v.result, v.kind, v.mode, \
               e.article_count + COALESCE(e.parity_count, 0) \
             FROM verifications v JOIN extents e ON e.id = v.extent_id \
             WHERE e.id IN (SELECT extent_id FROM generation_extents WHERE generation_id = ?1) \
               AND v.plan_rev = e.plan_rev AND v.verified_at = \
               (SELECT MAX(n.verified_at) FROM verifications n WHERE n.extent_id = v.extent_id \
                  AND n.backbone = v.backbone AND n.plan_rev = v.plan_rev) \
             ORDER BY v.extent_id, v.backbone";

const SAFETY_CAS: &str = "UPDATE extents SET safety_state = ?3, evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND safety_state = ?2";

const LIVE_GENERATION: &str = concat!(
    "SELECT ",
    generation_cols!(),
    " FROM objects o JOIN generations g \
         ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
         WHERE o.bucket_id = ?1 AND o.key = ?2"
);

const GENERATION_BY_ID: &str = concat!(
    "SELECT ",
    generation_cols!(),
    ", b.id, b.name, b.owner, b.bdk_wrapped, b.kek_version, \
           b.disposable, b.created_at \
         FROM generations g JOIN buckets b ON b.id = g.bucket_id \
         WHERE g.id = ?1 AND g.bucket_id = ?2"
);

const EXTENTS_IN: &str = concat!(
    "WITH RECURSIVE ",
    bisect!("first_ref", "<=", "?2", "-1"),
    ", ",
    bisect!("last_ref", "<", "?3", "-1"),
    " \
         SELECT ",
    placed_extent_cols!(),
    " \
         FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
         WHERE ge.generation_id = ?1 \
           AND ge.seq >= (SELECT MAX(lo, 0) FROM first_ref WHERE hi - lo <= 1) \
           AND ge.seq <= (SELECT lo FROM last_ref WHERE hi - lo <= 1) \
         ORDER BY ge.seq"
);

const EXTENTS_IN_PG: &str = concat!(
    "WITH RECURSIVE ",
    bisect!("first_ref", "<=", "?2", "-1::bigint"),
    ", ",
    bisect!("last_ref", "<", "?3", "-1::bigint"),
    " \
         SELECT ",
    placed_extent_cols!(),
    " \
         FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
         WHERE ge.generation_id = ?1 \
           AND ge.seq >= (SELECT GREATEST(lo, 0) FROM first_ref WHERE hi - lo <= 1) \
           AND ge.seq <= (SELECT lo FROM last_ref WHERE hi - lo <= 1) \
         ORDER BY ge.seq"
);

const RETIRE_OUTBOX: &str = concat!(
    "UPDATE outbox SET stage = 'cancelled', sent_at = NULL, updated_at = ?3 \
                 WHERE stage NOT IN ('done', 'cancelled') AND extent_id IN (",
    retiring!(),
    ")"
);

const RETIRE_GC: &str = concat!(
    "INSERT INTO gc(extent_id, action, due_at) \
                 SELECT x.extent_id, a.action, a.due_at FROM (",
    retiring!(),
    ") x JOIN (SELECT 'delete_cache' AS action, ?3 AS due_at \
                       UNION ALL SELECT 'delete_safety', ?3 \
                       UNION ALL SELECT 'shred_key', ?4) a"
);

const RETIRE_GC_PG: &str = concat!(
    "INSERT INTO gc(extent_id, action, due_at) \
                 SELECT x.extent_id, a.action, a.due_at FROM (",
    retiring!(),
    ") x CROSS JOIN (SELECT 'delete_cache' AS action, ?3 AS due_at \
                       UNION ALL SELECT 'delete_safety', ?3 \
                       UNION ALL SELECT 'shred_key', ?4) a"
);

const LIST_OBJECTS: &str = "SELECT o.key, g.size, g.etag, g.created_at FROM objects o \
         JOIN generations g \
         ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
         WHERE o.bucket_id = ?1 AND o.key >= ?2 AND o.key > ?3  ORDER BY o.key LIMIT ?4";

const LIST_OBJECTS_BELOW: &str = "SELECT o.key, g.size, g.etag, g.created_at FROM objects o \
         JOIN generations g \
         ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
         WHERE o.bucket_id = ?1 AND o.key >= ?2 AND o.key > ?3 AND o.key < ?5 ORDER BY o.key LIMIT ?4";

macro_rules! heads_plain {
    ($op:literal, $below:literal) => {
        concat!(
            "SELECT o.key, g.size, g.etag, g.created_at FROM objects o \
                 JOIN generations g \
                 ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
                 WHERE o.bucket_id = ?1 AND o.key ",
            $op,
            " ?2 ",
            $below,
            " ORDER BY o.key LIMIT ?3"
        )
    };
}

macro_rules! heads_grouped {
    ($op:literal, $below:literal) => {
        concat!(
            "WITH RECURSIVE scan(n, key) AS ( \
                   SELECT 1, (SELECT o.key FROM objects o WHERE o.bucket_id = ?1 \
                              AND o.key ",
            $op,
            " ?2 ",
            $below,
            " ORDER BY o.key LIMIT 1) \
                   UNION ALL \
                   SELECT n + 1, CASE WHEN instr(substr(key, ?4 + 1), ?5) > 0 \
                     THEN (SELECT o.key FROM objects o WHERE o.bucket_id = ?1 \
                           AND o.key >= substr(scan.key, 1, \
                                 ?4 + instr(substr(scan.key, ?4 + 1), ?5) - 1) || ?6 \
                           ",
            $below,
            " ORDER BY o.key LIMIT 1) \
                     ELSE (SELECT o.key FROM objects o WHERE o.bucket_id = ?1 \
                           AND o.key > scan.key ",
            $below,
            " ORDER BY o.key LIMIT 1) END \
                   FROM scan WHERE key IS NOT NULL AND n < ?3 \
                 ) \
                 SELECT s.key, g.size, g.etag, g.created_at FROM scan s \
                 CROSS JOIN objects o ON o.bucket_id = ?1 AND o.key = s.key \
                 LEFT JOIN generations g \
                 ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
                 ORDER BY s.n"
        )
    };
}

macro_rules! heads_grouped_pg {
    ($op:literal, $below:literal) => {
        concat!(
    "WITH RECURSIVE scan(n, key) AS ( \
                   SELECT 1, (SELECT o.key FROM objects o WHERE o.bucket_id = ?1 \
                              AND o.key ",
    $op,
    " ?2 ",
    $below,
    " ORDER BY o.key LIMIT 1) \
                   UNION ALL \
                   SELECT n + 1, CASE WHEN strpos(substr(key, ?4::int + 1), ?5) > 0 \
                     THEN (SELECT o.key FROM objects o WHERE o.bucket_id = ?1 \
                           AND o.key >= substr(scan.key, 1, \
                                 ?4::int + strpos(substr(scan.key, ?4::int + 1), ?5) - 1) || ?6 \
                           ",
    $below,
    " ORDER BY o.key LIMIT 1) \
                     ELSE (SELECT o.key FROM objects o WHERE o.bucket_id = ?1 \
                           AND o.key > scan.key ",
    $below,
    " ORDER BY o.key LIMIT 1) END \
                   FROM scan WHERE key IS NOT NULL AND n < ?3 \
                 ) \
                 SELECT s.key, g.size, g.etag, g.created_at FROM scan s \
                 JOIN objects o ON o.bucket_id = ?1 AND o.key = s.key \
                 LEFT JOIN generations g \
                 ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
                 ORDER BY s.n"
)
    };
}

const HEADS_EXCLUSIVE: &str = heads_plain!(">", "");

const GROUPED_EXCLUSIVE: &str = heads_grouped!(">", "");

const GROUPED_EXCLUSIVE_PG: &str = heads_grouped_pg!(">", "");

const HEADS_EXCLUSIVE_BELOW: &str = heads_plain!(">", "AND o.key < ?4");

const GROUPED_EXCLUSIVE_BELOW: &str = heads_grouped!(">", "AND o.key < ?7");

const GROUPED_EXCLUSIVE_BELOW_PG: &str = heads_grouped_pg!(">", "AND o.key < ?7");

const HEADS_INCLUSIVE: &str = heads_plain!(">=", "");

const GROUPED_INCLUSIVE: &str = heads_grouped!(">=", "");

const GROUPED_INCLUSIVE_PG: &str = heads_grouped_pg!(">=", "");

const HEADS_INCLUSIVE_BELOW: &str = heads_plain!(">=", "AND o.key < ?4");

const GROUPED_INCLUSIVE_BELOW: &str = heads_grouped!(">=", "AND o.key < ?7");

const GROUPED_INCLUSIVE_BELOW_PG: &str = heads_grouped_pg!(">=", "AND o.key < ?7");

#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<Stmt> {
    super::pg_manifest(&[
        (LIVE_EXTENTS, "T"),
        (RETIRE_GENERATION, "TTTI"),
        (INSERT_GENERATION, "TTTTITTTTII"),
        (INSERT_GENERATION, "TTTTITNTTII"),
        (UPSERT_POINTER, "TTT"),
        (INSERT_EXTENT, "TTTTIIIIBIBBBBTIIITII"),
        (INSERT_EXTENT, "TTTTNNIIBINBBBTNINNNI"),
        (RAISE_FLOOR_PG, "TTTI"),
        (SETTLE_FLOOR, "TTT"),
        (KEY_HEADS_PG, "TT"),
        (UNPUBLISHED_FLOOR, "TT"),
        (GUARD_NEWEST, "TTT"),
        (GUARD_ABSENT, "TT"),
        (GUARD_PRESENT, "TT"),
        (GUARD_ETAG, "TTT"),
        (CLEAR_FLOOR, "TTT"),
        (NEWEST_ID, "TT"),
        (INSERT_EXTENT_REFERENCE_PG, "T"),
        (ENQUEUE_POST, "TTI"),
        (GUARD_COPY_SOURCE, "TTTITI"),
        (COPY_REFERENCES, "TT"),
        (GUARD_REFERENCE_COUNT, "TI"),
        (STATUS_EXTENTS, "T"),
        (STATUS_VERIFICATIONS, "T"),
        (SAFETY_CAS, "TTT"),
        (LIVE_GENERATION, "TT"),
        (GENERATION_BY_ID, "TT"),
        (EXTENTS_IN_PG, "TII"),
        (RETIRE_OUTBOX, "TTI"),
        (RETIRE_GC_PG, "TTII"),
        (LIST_OBJECTS, "TTTI"),
        (LIST_OBJECTS_BELOW, "TTTIT"),
        (HEADS_EXCLUSIVE, "TTI"),
        (GROUPED_EXCLUSIVE_PG, "TTIITT"),
        (HEADS_EXCLUSIVE_BELOW, "TTIT"),
        (GROUPED_EXCLUSIVE_BELOW_PG, "TTIITTT"),
        (HEADS_INCLUSIVE, "TTI"),
        (GROUPED_INCLUSIVE_PG, "TTIITT"),
        (HEADS_INCLUSIVE_BELOW, "TTIT"),
        (GROUPED_INCLUSIVE_BELOW_PG, "TTIITTT"),
    ])
}
