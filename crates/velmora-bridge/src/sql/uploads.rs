//! Multipart uploads: guarded batches and the completion receipt (catalogue lane B).
//!
//! Every mutation is one atomic [`Sql::batch`] whose first statement is a
//! `tx_guard` insert naming the full authorized target `(id, bucket, key)`
//! and the expected state. A failed guard rolls the whole batch back and is
//! reported as [`Guard::Lost`]. UploadPart, Abort and Complete each bump
//! `uploads.revision`, so `revision = R` pins the exact part set a Complete
//! validated. Statements are fixed-shape and bind at most 21 parameters.

use super::objects::{clear_tombstone, guard_newest};
use super::SqlCatalog;
use crate::ports::{Guard, PublishOutcome, Row, Sql, SqlValue, UploadTarget};
use crate::recovery::Recorded;
use crate::types::{
    BridgeError, BucketId, CompleteUpload, ExtentId, ExtentRow, ExtentState, GenerationId,
    GenerationState, Result, UnixMs, UploadId, UploadPartRow, UploadRow, UploadState,
};

/// A retired extent's key is shredded this long after retirement; its
/// pinned ciphertext is due for deletion immediately.
const SHRED_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Statement and row helpers (shared with `outbox`, `gc` and `permits`)
// ---------------------------------------------------------------------------

pub(super) type Stmt = (&'static str, Vec<SqlValue>);

pub(super) fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

pub(super) fn ms(t: UnixMs) -> SqlValue {
    SqlValue::Int(t.0)
}

pub(super) fn int(v: impl TryInto<i64>) -> Result<SqlValue> {
    v.try_into()
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("integer exceeds the catalogue range"))
}

fn opt<T>(v: Option<T>, f: impl FnOnce(T) -> SqlValue) -> SqlValue {
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

    /// A fixed-length digest column.
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        <[u8; N]>::try_from(self.blob()?).map_err(|_| bad("digest length"))
    }

    /// A `CHECK (… IN (…))` column through the enum's `parse`.
    pub(super) fn parsed<T>(&mut self, parse: fn(&str) -> Option<T>) -> Result<T> {
        parse(&self.text()?).ok_or_else(|| bad("unknown enum value"))
    }
}

/// Runs a batch whose first statement is a `tx_guard` insert.
pub(super) async fn guarded<S: Sql>(c: &SqlCatalog<S>, stmts: Vec<Stmt>) -> Result<Guard<()>> {
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(Guard::Applied(())),
        Err(BridgeError::GuardFailed) => Ok(Guard::Lost),
        Err(e) => Err(e),
    }
}

/// Runs the batch that publishes the generation `id`. It runs only
/// against the proof of that generation's recovery record, and turns the
/// proof into the one that deletes only when the guard failed and
/// nothing was written.
pub(super) async fn published<S: Sql>(
    c: &SqlCatalog<S>,
    stmts: Vec<Stmt>,
    id: &GenerationId,
    record: Recorded,
) -> Result<PublishOutcome> {
    if record.generation() != id {
        return Err(BridgeError::Invalid(
            "the recovery record is of another generation",
        ));
    }
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(PublishOutcome::Applied),
        Err(BridgeError::GuardFailed) => Ok(PublishOutcome::Refused(record.refused())),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Shared statements
// ---------------------------------------------------------------------------

fn target(t: &UploadTarget<'_>) -> Vec<SqlValue> {
    vec![text(t.id.as_str()), text(t.bucket.as_str()), text(t.key)]
}

/// First statement of every upload mutation: the upload exists for this
/// exact target and is still `open`.
fn guard_open(t: &UploadTarget<'_>) -> Stmt {
    (
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM uploads \
         WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open')",
        target(t),
    )
}

/// GC rows for this upload's part extents that are still `staged`: all of
/// them, or only the one currently stored under `part_number`.
fn gc_staged_parts(id: &UploadId, part_number: Option<u16>, now: UnixMs) -> Stmt {
    (
        "INSERT INTO gc(extent_id, action, due_at) \
         SELECT p.extent_id, a.action, a.due_at FROM upload_parts p \
         JOIN extents e ON e.id = p.extent_id \
         JOIN (SELECT 'delete_safety' AS action, ?2 AS due_at \
               UNION ALL SELECT 'shred_key', ?3) a \
         WHERE p.upload_id = ?1 AND e.state = 'staged' \
           AND (?4 IS NULL OR p.part_number = ?4)",
        vec![
            text(id.as_str()),
            ms(now),
            ms(now.plus_ms(SHRED_GRACE_MS)),
            opt(part_number, |n| SqlValue::Int(i64::from(n))),
        ],
    )
}

// ---------------------------------------------------------------------------
// Create and read
// ---------------------------------------------------------------------------

pub(super) async fn create_upload<S: Sql>(c: &SqlCatalog<S>, u: &UploadRow) -> Result<()> {
    if u.state != UploadState::Open || u.revision != 0 || u.completed_generation_id.is_some() {
        return Err(BridgeError::Invalid("a new upload is open at revision 0"));
    }
    c.sql
        .exec(
            "INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, \
               revision, initiated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'open', 0, ?6)",
            &[
                text(u.id.as_str()),
                text(u.bucket_id.as_str()),
                text(&u.key),
                text(&u.content_json),
                text(&u.user_meta_json),
                ms(u.initiated_at),
            ],
        )
        .await?;
    Ok(())
}

/// The upload row is read before its parts: a part written in between
/// makes the parts newer than `revision`, never older, and the revision
/// guard of Complete then refuses that view.
pub(super) async fn upload<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
) -> Result<Option<(UploadRow, Vec<UploadPartRow>)>> {
    let rows = c
        .sql
        .query(
            "SELECT id, bucket_id, key, content_json, user_meta_json, state, revision, \
               completed_generation_id, complete_digest, result_etag, initiated_at \
             FROM uploads WHERE id = ?1 AND bucket_id = ?2 AND key = ?3",
            &target(t),
        )
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let mut r = Cols::new(row);
    let upload = UploadRow {
        id: UploadId::new(r.text()?),
        bucket_id: BucketId::new(r.text()?),
        key: r.text()?,
        content_json: r.text()?,
        user_meta_json: r.text()?,
        state: r.parsed(UploadState::parse)?,
        revision: r.num()?,
        completed_generation_id: r.opt_text()?.map(GenerationId::new),
        complete_digest: match r.opt_blob()? {
            Some(d) => Some(<[u8; 32]>::try_from(d).map_err(|_| bad("digest length"))?),
            None => None,
        },
        result_etag: r.opt_text()?,
        initiated_at: UnixMs(r.num()?),
    };
    let rows = c
        .sql
        .query(
            "SELECT upload_id, part_number, extent_id, size, etag, uploaded_at \
             FROM upload_parts WHERE upload_id = ?1 ORDER BY part_number",
            &[text(t.id.as_str())],
        )
        .await?;
    let mut parts = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        parts.push(UploadPartRow {
            upload_id: UploadId::new(r.text()?),
            part_number: r.num()?,
            extent_id: ExtentId::new(r.text()?),
            size: r.num()?,
            etag: r.text()?,
            uploaded_at: UnixMs(r.num()?),
        });
    }
    Ok(Some((upload, parts)))
}

// ---------------------------------------------------------------------------
// UploadPart and Abort
// ---------------------------------------------------------------------------

/// Stores one part: the staged extent, the part row (replacing an earlier
/// upload of the same number, whose extent goes to GC) and `revision + 1`.
pub(super) async fn put_upload_part<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
    part: &UploadPartRow,
    e: &ExtentRow,
    now: UnixMs,
) -> Result<Guard<()>> {
    if &part.upload_id != t.id
        || part.extent_id != e.id
        || part.size != e.plain_size
        || &e.bucket_id != t.bucket
        || e.state != ExtentState::Staged
        || e.generation_id.is_some()
    {
        return Err(BridgeError::Invalid(
            "part does not describe one staged extent of this upload",
        ));
    }
    let part_number = SqlValue::Int(i64::from(part.part_number));
    let stmts = vec![
        guard_open(t),
        // Before the upsert: this still names the part being replaced.
        gc_staged_parts(t.id, Some(part.part_number), now),
        (
            "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
               plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, \
               plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, created_at) \
             VALUES (?1,?2,NULL,'staged',NULL,NULL,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13)",
            vec![
                text(e.id.as_str()),
                text(e.bucket_id.as_str()),
                int(e.plain_size)?,
                int(e.cipher_size)?,
                SqlValue::Blob(e.media_header.clone()),
                SqlValue::Int(i64::from(e.key_mode)),
                opt(e.wrapped_file_key.clone(), SqlValue::Blob),
                SqlValue::Blob(e.plain_md5.to_vec()),
                SqlValue::Blob(e.plain_sha256.to_vec()),
                SqlValue::Blob(e.cipher_sha256.to_vec()),
                text(e.safety_state.as_str()),
                SqlValue::Int(i64::from(e.plan_rev)),
                ms(e.created_at),
            ],
        ),
        (
            "INSERT INTO upload_parts(upload_id, part_number, extent_id, size, etag, uploaded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(upload_id, part_number) DO UPDATE SET extent_id = excluded.extent_id, \
               size = excluded.size, etag = excluded.etag, uploaded_at = excluded.uploaded_at",
            vec![
                text(t.id.as_str()),
                part_number,
                text(e.id.as_str()),
                int(part.size)?,
                text(&part.etag),
                ms(part.uploaded_at),
            ],
        ),
        (
            "UPDATE uploads SET revision = revision + 1 \
             WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open'",
            target(t),
        ),
    ];
    guarded(c, stmts).await
}

/// Closes the upload and sends every part extent to GC.
pub(super) async fn abort_upload<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
    now: UnixMs,
) -> Result<Guard<()>> {
    let stmts = vec![
        guard_open(t),
        gc_staged_parts(t.id, None, now),
        (
            "UPDATE uploads SET state = 'aborted', revision = revision + 1 \
             WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open'",
            target(t),
        ),
    ];
    guarded(c, stmts).await
}

// ---------------------------------------------------------------------------
// Complete
// ---------------------------------------------------------------------------

/// Publishes the upload as one generation, in one batch.
///
/// - Guard: the target is `open` at exactly `revision`, so the parts are
///   the ones the caller validated. A completed or aborted upload is
///   `Lost` and nothing is published again; the caller answers a retry
///   from the stored receipt.
/// - A placement adopts an extent only if it is a still-staged part of
///   **this** upload in this bucket. A second guard then requires that
///   exactly `extent_count` extents were adopted and that they tile
///   `size` bytes in `seq` order; a foreign, repeated or misplaced extent
///   id therefore rolls everything back (`Lost`).
/// - Parts the request did not list go to GC; the key's previous
///   generation is retired; the receipt is stored with `revision + 1`.
pub(super) async fn complete_upload<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
    revision: u64,
    digest: &[u8; 32],
    commit: &CompleteUpload,
    record: Recorded,
) -> Result<PublishOutcome> {
    let g = &commit.generation;
    let now = commit.now;
    let in_order = commit
        .placements
        .iter()
        .enumerate()
        .all(|(i, p)| u32::try_from(i).ok() == Some(p.seq));
    if &g.bucket_id != t.bucket
        || g.key != t.key
        || g.state != GenerationState::Live
        || g.retired_at.is_some()
        || commit.placements.is_empty()
        || usize::try_from(g.extent_count).ok() != Some(commit.placements.len())
        || !in_order
    {
        return Err(BridgeError::Invalid(
            "completion does not describe one live generation of this target",
        ));
    }
    let gen_id = || text(g.id.as_str());
    let key = || vec![text(t.bucket.as_str()), text(t.key)];

    let mut stmts: Vec<Stmt> = Vec::with_capacity(11 + commit.placements.len());
    let mut guard = target(t);
    guard.push(int(revision)?);
    stmts.push((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM uploads \
         WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open' AND revision = ?4)",
        guard,
    ));
    stmts.push(guard_newest(t.bucket, t.key, &g.id));
    stmts.push(clear_tombstone(t.bucket, t.key, &g.id));
    stmts.push((
        "INSERT INTO generations(id, bucket_id, key, state, size, etag, checksum_json, \
           content_json, user_meta_json, extent_count, created_at, retired_at) \
         VALUES (?1,?2,?3,'live',?4,?5,?6,?7,?8,?9,?10,NULL)",
        vec![
            gen_id(),
            text(g.bucket_id.as_str()),
            text(&g.key),
            int(g.size)?,
            text(&g.etag),
            opt(g.checksum_json.as_deref(), text),
            text(&g.content_json),
            text(&g.user_meta_json),
            SqlValue::Int(i64::from(g.extent_count)),
            ms(g.created_at),
        ],
    ));
    for p in &commit.placements {
        stmts.push((
            "UPDATE extents SET generation_id = ?1, seq = ?2, plain_offset = ?3, \
               state = 'committed' \
             WHERE id = ?4 AND bucket_id = ?5 AND state = 'staged' AND generation_id IS NULL \
               AND id IN (SELECT extent_id FROM upload_parts WHERE upload_id = ?6)",
            vec![
                gen_id(),
                SqlValue::Int(i64::from(p.seq)),
                int(p.plain_offset)?,
                text(p.extent_id.as_str()),
                text(t.bucket.as_str()),
                text(t.id.as_str()),
            ],
        ));
    }
    stmts.push((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
           (SELECT COUNT(*) FROM extents WHERE generation_id = ?1) <> ?2 \
           OR (SELECT COALESCE(SUM(plain_size), 0) FROM extents WHERE generation_id = ?1) <> ?3 \
           OR EXISTS (SELECT 1 FROM (SELECT plain_offset, SUM(plain_size) OVER (ORDER BY seq \
                ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS expected \
                FROM extents WHERE generation_id = ?1) \
              WHERE plain_offset <> COALESCE(expected, 0))",
        vec![
            gen_id(),
            SqlValue::Int(i64::from(g.extent_count)),
            int(g.size)?,
        ],
    ));
    stmts.push((
        "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
         SELECT id, generation_id, 'post', ?2, ?2 FROM extents WHERE generation_id = ?1",
        vec![gen_id(), ms(now)],
    ));
    // After adoption: whatever is still staged was not listed.
    stmts.push(gc_staged_parts(t.id, None, now));
    // Retire the generation the live pointer names, before moving it.
    let mut retire_gc = key();
    retire_gc.extend([ms(now), ms(now.plus_ms(SHRED_GRACE_MS))]);
    stmts.push((
        "INSERT INTO gc(extent_id, action, due_at) \
         SELECT e.id, a.action, a.due_at FROM objects o \
         JOIN extents e ON e.generation_id = o.generation_id \
         JOIN (SELECT 'delete_cache' AS action, ?3 AS due_at \
               UNION ALL SELECT 'delete_safety', ?3 \
               UNION ALL SELECT 'shred_key', ?4) a \
         WHERE o.bucket_id = ?1 AND o.key = ?2",
        retire_gc,
    ));
    let mut retire = key();
    retire.push(ms(now));
    stmts.push((
        "UPDATE outbox SET stage = 'cancelled', updated_at = ?3 \
         WHERE stage NOT IN ('done', 'cancelled') AND generation_id = \
           (SELECT generation_id FROM objects WHERE bucket_id = ?1 AND key = ?2)",
        retire.clone(),
    ));
    stmts.push((
        "UPDATE generations SET state = 'superseded', retired_at = ?3 WHERE id = \
           (SELECT generation_id FROM objects WHERE bucket_id = ?1 AND key = ?2)",
        retire,
    ));
    let mut pointer = key();
    pointer.push(gen_id());
    stmts.push((
        "INSERT INTO objects(bucket_id, key, generation_id) VALUES (?1, ?2, ?3) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET generation_id = excluded.generation_id",
        pointer,
    ));
    let mut receipt = target(t);
    receipt.extend([
        int(revision)?,
        gen_id(),
        SqlValue::Blob(digest.to_vec()),
        text(&g.etag),
    ]);
    stmts.push((
        "UPDATE uploads SET state = 'completed', revision = revision + 1, \
           completed_generation_id = ?5, complete_digest = ?6, result_etag = ?7 \
         WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open' AND revision = ?4",
        receipt,
    ));
    published(c, stmts, &g.id, record).await
}
