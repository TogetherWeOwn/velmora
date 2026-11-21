//! Multipart uploads: guarded batches and the completion receipt (catalogue lane B).
//!
//! Every mutation is one atomic [`Sql::batch`] whose first statement is a
//! `tx_guard` insert naming the full authorized target `(id, bucket, key)`
//! and the expected state. A failed guard rolls the whole batch back and is
//! reported as [`Guard::Lost`]. UploadPart, Abort and Complete each bump
//! `uploads.revision`, so `revision = R` pins the exact part set a Complete
//! validated. Statements are fixed-shape and bind at most 21 parameters.

use super::intents::{part_intents_close, part_intents_open};
use super::objects::{clear_floor, guard_newest, guard_precondition, successor};
use super::replay::guard_no_replay;
use super::SqlCatalog;
use crate::ports::{Guard, PublishOutcome, Row, Sql, SqlValue, UploadTarget};
use crate::recovery::Recorded;
use crate::types::{
    BridgeError, BucketId, CompleteUpload, ExtentId, ExtentRow, ExtentState, GenerationId,
    GenerationState, OpenUpload, Precondition, Result, UnixMs, UploadId, UploadListQuery,
    UploadPartRow, UploadRow, UploadState, WriteId,
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
        Err(BridgeError::GuardFailed) => Ok(PublishOutcome::Refused(
            record.refused(super::GuardRefused(())),
        )),
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
/// them, or only those currently stored under `part_number`. A part of
/// several extents has its first in `upload_parts` and the others in
/// `upload_part_extents`.
fn gc_staged_parts(id: &UploadId, part_number: Option<u16>, now: UnixMs) -> Stmt {
    (
        "INSERT INTO gc(extent_id, action, due_at) \
         SELECT p.extent_id, a.action, a.due_at FROM \
           (SELECT extent_id FROM upload_parts \
             WHERE upload_id = ?1 AND (?4 IS NULL OR part_number = ?4) \
            UNION ALL SELECT extent_id FROM upload_part_extents \
             WHERE upload_id = ?1 AND (?4 IS NULL OR part_number = ?4)) p \
         JOIN extents e ON e.id = p.extent_id \
         JOIN (SELECT 'delete_safety' AS action, ?2 AS due_at \
               UNION ALL SELECT 'shred_key', ?3) a \
         WHERE e.state = 'staged'",
        vec![
            text(id.as_str()),
            ms(now),
            ms(now.plus_ms(SHRED_GRACE_MS)),
            opt(part_number, |n| SqlValue::Int(i64::from(n))),
        ],
    )
}

/// Removes the rows naming the extents after the first of every part.
/// For a batch that closes the upload, after the extents were adopted or
/// sent to GC.
fn drop_pieces(id: &UploadId) -> Stmt {
    (
        "DELETE FROM upload_part_extents WHERE upload_id = ?1",
        vec![text(id.as_str())],
    )
}

// ---------------------------------------------------------------------------
// Create and read
// ---------------------------------------------------------------------------

pub(super) async fn create_upload<S: Sql>(c: &SqlCatalog<S>, u: &UploadRow) -> Result<()> {
    if u.state != UploadState::Open || u.revision != 0 || u.completed_generation_id.is_some() {
        return Err(BridgeError::Invalid("a new upload is open at revision 0"));
    }
    // Nothing for a bucket the catalogue does not have (it was deleted
    // after the request was authorized): the upload is not opened.
    let opened = c
        .sql
        .exec(
            "INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, \
               revision, initiated_at) SELECT ?1, ?2, ?3, ?4, ?5, 'open', 0, ?6 \
             WHERE EXISTS (SELECT 1 FROM buckets WHERE id = ?2)",
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
    if opened != 1 {
        return Err(BridgeError::Invalid(
            "the bucket of the upload does not exist",
        ));
    }
    Ok(())
}

/// An upload id is lowercase hex: this sorts after every one of them.
const AFTER_EVERY_UPLOAD_ID: &str = "~";

/// The open uploads of a bucket in `(key, upload id)` order. The prefix
/// is a key range (no `LIKE`); a skipped common prefix moves the lower
/// bound to its successor.
pub(super) async fn list_uploads<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    q: &UploadListQuery,
) -> Result<Vec<OpenUpload>> {
    if q.limit == 0 {
        return Ok(Vec::new());
    }
    let mut from = q.prefix.clone(); // inclusive lower bound
    if let Some(done) = &q.skip_prefix {
        match successor(done) {
            Some(s) => from = from.max(s),
            None => return Ok(Vec::new()),
        }
    }
    let (after_key, after_id) = match &q.after {
        Some((key, id)) => (key.as_str(), id.as_deref().unwrap_or(AFTER_EVERY_UPLOAD_ID)),
        None => ("", ""),
    };
    let upper = successor(&q.prefix);
    let sql = format!(
        "SELECT key, id, initiated_at FROM uploads \
         WHERE bucket_id = ?1 AND state = 'open' AND key >= ?2 \
           AND (key > ?3 OR (key = ?3 AND id > ?4)) {} \
         ORDER BY key, id LIMIT ?5",
        if upper.is_some() { "AND key < ?6" } else { "" }
    );
    let mut params = vec![
        text(bucket.as_str()),
        text(&from),
        text(after_key),
        text(after_id),
        SqlValue::Int(i64::from(q.limit)),
    ];
    params.extend(upper.as_deref().map(text));
    let rows = c.sql.query(&sql, &params).await?;
    rows.into_iter()
        .map(|row| {
            let mut r = Cols::new(row);
            Ok(OpenUpload {
                key: r.text()?,
                id: UploadId::new(r.text()?),
                initiated_at: UnixMs(r.num()?),
            })
        })
        .collect()
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

/// The insert of one staged part extent.
fn staged_extent(e: &ExtentRow) -> Result<Stmt> {
    Ok((
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
    ))
}

/// The statements that make `extents`, in body order, the part: the
/// staged extents, the part row (replacing an earlier upload of the same
/// number, whose extents go to GC) and the rows of the extents after the
/// first. They follow the guards of the batch.
fn part_statements(
    t: &UploadTarget<'_>,
    part: &UploadPartRow,
    extents: &[ExtentRow],
    now: UnixMs,
) -> Result<Vec<Stmt>> {
    let whole = extents
        .iter()
        .try_fold(0u64, |sum, e| sum.checked_add(e.plain_size));
    let staged = extents.iter().all(|e| {
        &e.bucket_id == t.bucket && e.state == ExtentState::Staged && e.generation_id.is_none()
    });
    let first = extents.first();
    if &part.upload_id != t.id
        || first.map(|e| &e.id) != Some(&part.extent_id)
        || whole != Some(part.size)
        || !staged
    {
        return Err(BridgeError::Invalid(
            "part does not describe staged extents of this upload",
        ));
    }
    let number = || SqlValue::Int(i64::from(part.part_number));
    let mut stmts = Vec::with_capacity(2 * extents.len() + 2);
    // Before the upsert: this still names the part being replaced.
    stmts.push(gc_staged_parts(t.id, Some(part.part_number), now));
    for e in extents {
        stmts.push(staged_extent(e)?);
    }
    stmts.push((
        "INSERT INTO upload_parts(upload_id, part_number, extent_id, size, etag, uploaded_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(upload_id, part_number) DO UPDATE SET extent_id = excluded.extent_id, \
           size = excluded.size, etag = excluded.etag, uploaded_at = excluded.uploaded_at",
        vec![
            text(t.id.as_str()),
            number(),
            text(part.extent_id.as_str()),
            int(part.size)?,
            text(&part.etag),
            ms(part.uploaded_at),
        ],
    ));
    // The extents after the first of the part that was replaced.
    stmts.push((
        "DELETE FROM upload_part_extents WHERE upload_id = ?1 AND part_number = ?2",
        vec![text(t.id.as_str()), number()],
    ));
    for (piece, e) in extents.iter().enumerate().skip(1) {
        stmts.push((
            "INSERT INTO upload_part_extents(upload_id, part_number, piece, extent_id) \
             VALUES (?1, ?2, ?3, ?4)",
            vec![
                text(t.id.as_str()),
                number(),
                int(piece)?,
                text(e.id.as_str()),
            ],
        ));
    }
    Ok(stmts)
}

fn bump_revision(t: &UploadTarget<'_>) -> Stmt {
    (
        "UPDATE uploads SET revision = revision + 1 \
         WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open'",
        target(t),
    )
}

/// Stores one part of one extent: the staged extent, the part row
/// (replacing an earlier upload of the same number, whose extents go to
/// GC) and `revision + 1`.
pub(super) async fn put_upload_part<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
    part: &UploadPartRow,
    e: &ExtentRow,
    now: UnixMs,
) -> Result<Guard<()>> {
    let mut stmts = vec![guard_open(t)];
    stmts.extend(part_statements(t, part, std::slice::from_ref(e), now)?);
    stmts.push(bump_revision(t));
    guarded(c, stmts).await
}

/// Stores one part whose body was stored as slices, the write `write`:
/// one staged extent per slice, in body order. Like [`put_upload_part`],
/// and in the same batch the intents of the write go: every one of them
/// is still `open` and names an extent this batch inserted. A write the
/// sweep took, or one a replay removed, is `Lost` and nothing is written.
pub(super) async fn put_upload_part_sliced<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
    part: &UploadPartRow,
    extents: &[ExtentRow],
    write: &WriteId,
    now: UnixMs,
) -> Result<Guard<()>> {
    let mut stmts = vec![guard_open(t), guard_no_replay()];
    let part_stmts = part_statements(t, part, extents, now)?;
    stmts.extend(part_intents_open(write, extents.len())?);
    stmts.extend(part_stmts);
    stmts.extend(part_intents_close(write, extents.len())?);
    stmts.push(bump_revision(t));
    guarded(c, stmts).await
}

/// Extents held under the other part numbers of the upload.
pub(super) async fn extents_held<S: Sql>(
    c: &SqlCatalog<S>,
    upload: &UploadId,
    except: u16,
) -> Result<u64> {
    let rows = c
        .sql
        .query(
            "SELECT (SELECT COUNT(*) FROM upload_parts WHERE upload_id = ?1 AND part_number <> ?2) \
                  + (SELECT COUNT(*) FROM upload_part_extents \
                      WHERE upload_id = ?1 AND part_number <> ?2)",
            &[text(upload.as_str()), SqlValue::Int(i64::from(except))],
        )
        .await?;
    match rows.into_iter().next() {
        Some(row) => Cols::new(row).num(),
        None => Ok(0),
    }
}

/// Closes the upload and sends every part extent to GC. The rows that
/// name the extents after the first of a part go with it.
pub(super) async fn abort_upload<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
    now: UnixMs,
) -> Result<Guard<()>> {
    let stmts = vec![
        guard_open(t),
        gc_staged_parts(t.id, None, now),
        drop_pieces(t.id),
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

/// The extents generation `?1` adopted, as `e`: its references, kept to
/// the extents first published in it. Every adopted extent has its
/// reference by the time this is read, so these are the rows of
/// `extents WHERE generation_id = ?1`, each found by its primary key.
/// `CROSS JOIN` and the unary `+` fix that order. The trigger copies
/// `seq` into the reference; `+e.seq = ge.seq` holds that, so the walk
/// in `ge.seq` order is the extents' order, read from the primary key of
/// `generation_extents` with no sort.
macro_rules! adopted {
    () => {
        "generation_extents ge CROSS JOIN extents e ON e.id = ge.extent_id \
          WHERE ge.generation_id = ?1 AND +e.generation_id = ?1 AND +e.seq = ge.seq"
    };
}

/// Publishes the upload as one generation, in one batch.
///
/// - Guard: the target is `open` at exactly `revision`, so the parts are
///   the ones the caller validated. A completed or aborted upload is
///   `Lost` and nothing is published again; the caller answers a retry
///   from the stored receipt.
/// - A placement adopts an extent only if it is a still-staged extent of
///   a part of **this** upload in this bucket. The placements are bound
///   as a few JSON values ([`super::publish`]), so the batch does not
///   grow with the extents. A second guard then requires that
///   exactly `extent_count` extents were adopted and that they tile
///   `size` bytes in `seq` order; a foreign, repeated or misplaced extent
///   id therefore rolls everything back (`Lost`). So does a part of
///   several extents that is not adopted whole and in body order.
/// - Parts the request did not list go to GC; the key's previous
///   generation is retired; the receipt is stored with `revision + 1`.
pub(super) async fn complete_upload<S: Sql>(
    c: &SqlCatalog<S>,
    t: &UploadTarget<'_>,
    revision: u64,
    digest: &[u8; 32],
    commit: &CompleteUpload,
    condition: Option<&Precondition>,
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

    // Built before any statement runs: placements that do not fit the
    // database's statements are refused here, with nothing written.
    let values = super::publish::placement_values(&commit.placements, c.sql.limits())?;

    let mut stmts: Vec<Stmt> = Vec::with_capacity(17 + values.len());
    let mut guard = target(t);
    guard.push(int(revision)?);
    stmts.push((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM uploads \
         WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open' AND revision = ?4)",
        guard,
    ));
    stmts.push(guard_no_replay());
    stmts.extend(condition.map(|c| guard_precondition(t.bucket, t.key, c)));
    stmts.push(guard_newest(t.bucket, t.key, &g.id));
    stmts.push(clear_floor(t.bucket, t.key, &g.id));
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
    // One statement per value of placements, not one per extent. Only a
    // staged extent of a part of this upload is taken.
    stmts.extend(super::publish::adopt(
        &g.id,
        t.bucket,
        super::publish::Source::Upload(t.id),
        &values,
    ));
    // The references reads go through. `OR IGNORE`: the migration's
    // trigger records the same rows for the adoptions above.
    //
    // No statement of this batch filters `extents` by generation: no
    // index serves that. The extents this generation adopted are found
    // by primary key instead. Here from the parts of the upload, which
    // an adopted extent always is one of ([`super::publish`]); below
    // from the references this statement leaves, one per adopted extent.
    stmts.push((
        "INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
         SELECT e.generation_id, e.seq, e.id, e.plain_offset \
           FROM (SELECT extent_id FROM upload_parts WHERE upload_id = ?2 \
                 UNION SELECT extent_id FROM upload_part_extents WHERE upload_id = ?2) p \
          CROSS JOIN extents e ON e.id = p.extent_id \
          WHERE +e.generation_id = ?1",
        vec![gen_id(), text(t.id.as_str())],
    ));
    stmts.push((
        concat!(
            "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
               (SELECT COUNT(*) FROM generation_extents WHERE generation_id = ?1) <> ?2 \
               OR (SELECT COUNT(*) FROM ",
            adopted!(),
            ") <> ?2 \
               OR (SELECT COALESCE(SUM(e.plain_size), 0) FROM ",
            adopted!(),
            ") <> ?3 \
               OR EXISTS (SELECT 1 FROM (SELECT e.plain_offset AS plain_offset, \
                    SUM(e.plain_size) OVER (ORDER BY ge.seq \
                    ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS expected FROM ",
            adopted!(),
            ") WHERE plain_offset <> COALESCE(expected, 0))"
        ),
        vec![
            gen_id(),
            SqlValue::Int(i64::from(g.extent_count)),
            int(g.size)?,
        ],
    ));
    // A part of several extents is adopted whole and in body order.
    stmts.push((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS \
           (SELECT 1 FROM upload_part_extents x \
              JOIN upload_parts p ON p.upload_id = x.upload_id \
               AND p.part_number = x.part_number \
              JOIN extents e0 ON e0.id = p.extent_id \
              JOIN extents e ON e.id = x.extent_id \
             WHERE x.upload_id = ?1 \
               AND ((e.generation_id IS ?2) <> (e0.generation_id IS ?2) \
                    OR (e0.generation_id IS ?2 AND e.seq <> e0.seq + x.piece)))",
        vec![text(t.id.as_str()), gen_id()],
    ));
    stmts.push((
        concat!(
            // Marked as sent from the start (`sent_at`): the caller
            // sends the post jobs itself (`Catalog::complete_upload`).
            "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at, sent_at) \
             SELECT e.id, e.generation_id, 'post', ?2, ?2, ?2 FROM ",
            adopted!()
        ),
        vec![gen_id(), ms(now)],
    ));
    // After adoption: whatever is still staged was not listed.
    stmts.push(gc_staged_parts(t.id, None, now));
    // Nothing reads the order within a part once the upload is closed.
    stmts.push(drop_pieces(t.id));
    // Retire the generation the live pointer names, before moving it.
    stmts.extend(super::objects::retire_live(
        t.bucket,
        t.key,
        GenerationState::Superseded,
        now,
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
    if record.generation() != &g.id {
        return Err(BridgeError::Invalid(
            "the recovery record is of another generation",
        ));
    }
    let failed = match c.sql.batch(stmts).await {
        Ok(_) => return Ok(PublishOutcome::Applied),
        Err(BridgeError::GuardFailed) => {
            return Ok(PublishOutcome::Refused(
                record.refused(super::GuardRefused(())),
            ))
        }
        Err(e) => e,
    };
    // The outcome is unknown: the batch may have applied, or may still.
    // Moving the upload to its next revision settles it. If that applies,
    // the upload was still open at `revision`, so the batch had not
    // applied, and its own guard on `revision` fails from here on. Then
    // nothing is published under this id, and its record may go, so
    // that a replay cannot publish an upload the client aborts later.
    let mut open_at = target(t);
    open_at.push(int(revision)?);
    let fence = vec![
        (
            "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM uploads \
             WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open' AND revision = ?4)",
            open_at.clone(),
        ),
        (
            "UPDATE uploads SET revision = revision + 1 \
             WHERE id = ?1 AND bucket_id = ?2 AND key = ?3 AND state = 'open' AND revision = ?4",
            open_at,
        ),
    ];
    match c.sql.batch(fence).await {
        Ok(_) => Ok(PublishOutcome::Fenced(
            record.refused(super::GuardRefused(())),
        )),
        // Still unknown, or it had applied: the record stays.
        Err(_) => Err(failed),
    }
}
