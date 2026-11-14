//! Objects, generations, listing and admin status (catalogue lane A).
//!
//! Publication and deletion are each one atomic [`Sql::batch`]. The
//! generation being replaced or deleted is resolved *inside* the batch
//! (sub-selects on the live `objects` pointer), never read beforehand, so
//! two racing writers cannot both retire the same generation or leave one
//! live without a pointer. Statements are fixed-shape, one row each, and
//! stay far below the 100-bound-parameter limit.

use super::SqlCatalog;
use crate::ports::{Row, Sql, SqlValue};
use crate::types::{
    BackboneStatus, BridgeError, BucketId, CommitGeneration, ExtentId, ExtentRow, ExtentState,
    ExtentStatus, GenerationId, GenerationRow, GenerationState, ListCursor, ListEntry, ListPage,
    ListQuery, ObjectStatus, OutboxStage, Result, SafetyState, UnixMs, VerifyResult,
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

const GENERATION_COLS: &str = "g.id, g.bucket_id, g.key, g.state, g.size, g.etag, \
     g.checksum_json, g.content_json, g.user_meta_json, g.extent_count, g.created_at, g.retired_at";

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

/// Column list of [`extent_row`], for any `SELECT … FROM extents`.
pub(super) const EXTENT_COLS: &str =
    "id, bucket_id, generation_id, state, seq, plain_offset, plain_size, cipher_size, \
     media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, cipher_sha256, \
     safety_state, article_count, plan_rev, last_verified_at, release_evidence, released_at, \
     created_at";

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

pub(super) async fn live_object<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
    let sql = format!(
        "SELECT {GENERATION_COLS} FROM objects o JOIN generations g \
         ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
         WHERE o.bucket_id = ?1 AND o.key = ?2"
    );
    let rows = c
        .sql
        .query(&sql, &[text(bucket.as_str()), text(key)])
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let generation = generation_row(row)?;
    let sql = format!("SELECT {EXTENT_COLS} FROM extents WHERE generation_id = ?1 ORDER BY seq");
    let rows = c.sql.query(&sql, &[text(generation.id.as_str())]).await?;
    let extents = rows.into_iter().map(extent_row).collect::<Result<_>>()?;
    Ok(Some((generation, extents)))
}

// ---------------------------------------------------------------------------
// Publication and deletion
// ---------------------------------------------------------------------------

type Stmt = (&'static str, Vec<SqlValue>);

/// Statements that retire whatever generation `objects` points at for
/// `(bucket, key)`: GC rows for its extents, its posting obligations
/// cancelled, and its state flipped. They must run before the pointer is
/// moved or removed, and all are no-ops when the key has no live object.
pub(super) fn retire_live(
    bucket: &BucketId,
    key: &str,
    to: GenerationState,
    now: UnixMs,
) -> Vec<Stmt> {
    let b = || text(bucket.as_str());
    vec![
        (
            "INSERT INTO gc(extent_id, action, due_at) \
             SELECT e.id, a.action, a.due_at FROM objects o \
             JOIN extents e ON e.generation_id = o.generation_id \
             JOIN (SELECT 'delete_cache' AS action, ?3 AS due_at \
                   UNION ALL SELECT 'delete_safety', ?3 \
                   UNION ALL SELECT 'shred_key', ?4) a \
             WHERE o.bucket_id = ?1 AND o.key = ?2",
            vec![b(), text(key), ms(now), ms(now.plus_ms(SHRED_GRACE_MS))],
        ),
        (
            "UPDATE outbox SET stage = 'cancelled', updated_at = ?3 \
             WHERE stage NOT IN ('done', 'cancelled') AND extent_id IN \
               (SELECT e.id FROM objects o JOIN extents e ON e.generation_id = o.generation_id \
                WHERE o.bucket_id = ?1 AND o.key = ?2)",
            vec![b(), text(key), ms(now)],
        ),
        (
            "UPDATE generations SET state = ?3, retired_at = ?4 WHERE id = \
               (SELECT generation_id FROM objects WHERE bucket_id = ?1 AND key = ?2)",
            vec![b(), text(key), text(to.as_str()), ms(now)],
        ),
    ]
}

/// Inserts a freshly sealed extent as `committed` in `generation`.
fn extent_insert(e: &ExtentRow, generation: &GenerationId) -> Result<Stmt> {
    Ok((
        "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, plain_size, \
           cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, \
           cipher_sha256, safety_state, article_count, plan_rev, last_verified_at, \
           release_evidence, released_at, created_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
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

/// Publishes one new generation of a single PUT. One batch: the new
/// generation with its extents and posting obligations, the previous
/// generation retired with GC rows, and the live pointer moved. Any
/// failing statement leaves the catalogue exactly as it was.
pub(super) async fn commit_generation<S: Sql>(
    c: &SqlCatalog<S>,
    commit: &CommitGeneration,
) -> Result<()> {
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

    let mut stmts: Vec<Stmt> = Vec::with_capacity(5 + 2 * commit.extents.len());
    stmts.push((
        "INSERT INTO generations(id, bucket_id, key, state, size, etag, checksum_json, \
           content_json, user_meta_json, extent_count, created_at, retired_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL)",
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
    ));
    for e in &commit.extents {
        stmts.push(extent_insert(e, &g.id)?);
        stmts.push((
            "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
             VALUES (?1, ?2, 'post', ?3, ?3)",
            vec![text(e.id.as_str()), text(g.id.as_str()), ms(commit.now)],
        ));
    }
    stmts.extend(retire_live(
        &g.bucket_id,
        &g.key,
        GenerationState::Superseded,
        commit.now,
    ));
    stmts.push((
        "INSERT INTO objects(bucket_id, key, generation_id) VALUES (?1, ?2, ?3) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET generation_id = excluded.generation_id",
        vec![
            text(g.bucket_id.as_str()),
            text(&g.key),
            text(g.id.as_str()),
        ],
    ));
    c.sql.batch(stmts).await.map(|_| ())
}

/// Idempotent: deleting a key with no live object changes nothing.
pub(super) async fn delete_object<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
    now: UnixMs,
) -> Result<()> {
    let mut stmts = retire_live(bucket, key, GenerationState::Deleted, now);
    stmts.push((
        "DELETE FROM objects WHERE bucket_id = ?1 AND key = ?2",
        vec![text(bucket.as_str()), text(key)],
    ));
    c.sql.batch(stmts).await.map(|_| ())
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

/// The least string greater than every string that starts with `s`, or
/// `None` when no such string exists (`s` is empty or all U+10FFFF).
/// UTF-8 byte order equals code-point order, so this is also the bound in
/// SQLite's binary text collation.
fn successor(s: &str) -> Option<String> {
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
    if q.max_keys == 0 {
        return Ok(page);
    }
    let delimiter = q.delimiter.as_deref().filter(|d| !d.is_empty());
    let upper = successor(&q.prefix);
    let sql = format!(
        "SELECT o.key, g.size, g.etag, g.created_at FROM objects o \
         JOIN generations g \
         ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
         WHERE o.bucket_id = ?1 AND o.key >= ?2 AND o.key > ?3 {} ORDER BY o.key LIMIT ?4",
        if upper.is_some() {
            "AND o.key < ?5"
        } else {
            ""
        }
    );

    let mut from = q.prefix.clone(); // inclusive lower bound
    let mut after = q.after.clone().unwrap_or_default(); // exclusive lower bound
    let mut skip: Option<String> = None; // common prefix being folded
    if let Some(done) = &q.skip_prefix {
        match successor(done) {
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
        let rows = c.sql.query(&sql, &params).await?;
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

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

pub(super) async fn object_status<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    key: &str,
) -> Result<Option<ObjectStatus>> {
    let sql = format!(
        "SELECT {GENERATION_COLS} FROM objects o JOIN generations g \
         ON g.id = o.generation_id AND g.bucket_id = o.bucket_id \
         WHERE o.bucket_id = ?1 AND o.key = ?2"
    );
    let rows = c
        .sql
        .query(&sql, &[text(bucket.as_str()), text(key)])
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let generation = generation_row(row)?;
    let gid = [text(generation.id.as_str())];

    let rows = c
        .sql
        .query(
            "SELECT e.id, e.seq, e.safety_state, o.stage, o.attempts, o.last_error \
             FROM extents e LEFT JOIN outbox o ON o.extent_id = e.id \
             WHERE e.generation_id = ?1 ORDER BY e.seq",
            &gid,
        )
        .await?;
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
    let rows = c
        .sql
        .query(
            "SELECT v.extent_id, v.backbone, v.provider_id, v.verified_at, v.plan_rev, \
               v.articles_ok, v.articles_total, v.result, e.article_count \
             FROM verifications v JOIN extents e ON e.id = v.extent_id \
             WHERE e.generation_id = ?1 AND v.plan_rev = e.plan_rev AND v.verified_at = \
               (SELECT MAX(n.verified_at) FROM verifications n WHERE n.extent_id = v.extent_id \
                  AND n.backbone = v.backbone AND n.plan_rev = v.plan_rev) \
             ORDER BY v.extent_id, v.backbone",
            &gid,
        )
        .await?;
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
            "UPDATE extents SET safety_state = ?3, evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND safety_state = ?2",
            &[
                text(extent.as_str()),
                text(from.as_str()),
                text(to.as_str()),
            ],
        )
        .await?;
    Ok(changed == 1)
}
