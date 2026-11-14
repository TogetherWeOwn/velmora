//! Catalogue statements of a recovery replay (DESIGN §A.8).
//!
//! A generation manifest is applied in two idempotent steps:
//!
//! 1. [`replay_extents`], any number of times, in chunks: the bucket and
//!    the extents exist (new ones as `staged` rows without a generation,
//!    like the parts of an open upload), their article plans exist, and
//!    an extent whose pinned copy is gone says so.
//! 2. [`replay_publish`], once: one guarded batch that publishes the
//!    generation. An extent no generation holds yet is adopted, exactly
//!    like a multipart Complete adopts its parts. An extent another
//!    generation already holds (the two share it through a copy) gets a
//!    second reference in `generation_extents` and is otherwise left as
//!    it is. Which of the two manifests comes first does not matter.
//!
//! A generation row therefore exists only when the whole generation was
//! published, which is what makes "already present" a safe reason to
//! skip a manifest.

use super::objects::{clear_tombstone, ms, opt, retire_live, text, uint};
use super::SqlCatalog;
use crate::ports::{Guard, Sql, SqlValue};
use crate::replay::{ReplayExtent, ReplayProbe};
use crate::types::{
    ArticleRow, BridgeError, Bucket, ExtentPlacement, GenerationId, GenerationRow, GenerationState,
    Result, SafetyState, UnixMs,
};

type Stmt = (&'static str, Vec<SqlValue>);

/// Statements per batch before it is sent.
const BATCH_STATEMENTS: usize = 300;

pub(super) async fn replay_probe<S: Sql>(
    c: &SqlCatalog<S>,
    g: &GenerationRow,
) -> Result<ReplayProbe> {
    let rows = c
        .sql
        .query(
            "SELECT (SELECT COUNT(*) FROM generations WHERE id = ?1), \
                    (SELECT COUNT(*) FROM objects WHERE bucket_id = ?2 AND key = ?3 \
                       AND generation_id > ?1)",
            &[
                text(g.id.as_str()),
                text(g.bucket_id.as_str()),
                text(&g.key),
            ],
        )
        .await?;
    Ok(match rows.first().map(Vec::as_slice) {
        Some([SqlValue::Int(0), SqlValue::Int(0)]) => ReplayProbe::Absent,
        Some([SqlValue::Int(0), SqlValue::Int(_)]) => ReplayProbe::Superseded,
        Some([SqlValue::Int(_), _]) => ReplayProbe::Present,
        _ => return Err(BridgeError::Sql("row decode: replay probe".into())),
    })
}

fn bucket_insert(b: &Bucket) -> Stmt {
    (
        "INSERT OR IGNORE INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, \
           created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        vec![
            text(b.id.as_str()),
            text(&b.name),
            text(&b.owner),
            SqlValue::Blob(b.bdk_wrapped.clone()),
            SqlValue::Int(i64::from(b.kek_version)),
            SqlValue::Int(i64::from(b.disposable)),
            ms(b.created_at),
        ],
    )
}

fn article_insert(a: &ArticleRow) -> Result<Stmt> {
    Ok((
        "INSERT OR IGNORE INTO articles(extent_id, idx, message_id, newsgroup, headers, \
           cipher_offset, cipher_len, payload_sha256, state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        vec![
            text(a.extent_id.as_str()),
            SqlValue::Int(i64::from(a.idx)),
            text(&a.message_id),
            text(&a.newsgroup),
            SqlValue::Blob(a.headers.clone()),
            uint(a.cipher_offset)?,
            uint(a.cipher_len)?,
            SqlValue::Blob(a.payload_sha256.to_vec()),
            text(a.state.as_str()),
        ],
    ))
}

/// The statements for one extent. Every one is a no-op on a catalogue
/// that already has what it would write.
fn extent_stmts(x: &ReplayExtent, now: UnixMs, out: &mut Vec<Stmt>) -> Result<()> {
    let e = &x.row;
    let id = || text(e.id.as_str());
    let safety = if x.safety_present {
        SafetyState::Held
    } else {
        SafetyState::Deleted
    };
    out.push((
        "INSERT OR IGNORE INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
           plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, \
           plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, created_at) \
         VALUES (?1,?2,NULL,'staged',NULL,NULL,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13)",
        vec![
            id(),
            text(e.bucket_id.as_str()),
            uint(e.plain_size)?,
            uint(e.cipher_size)?,
            SqlValue::Blob(e.media_header.clone()),
            SqlValue::Int(i64::from(e.key_mode)),
            opt(e.wrapped_file_key.clone(), SqlValue::Blob),
            SqlValue::Blob(e.plain_md5.to_vec()),
            SqlValue::Blob(e.plain_sha256.to_vec()),
            SqlValue::Blob(e.cipher_sha256.to_vec()),
            text(safety.as_str()),
            SqlValue::Int(i64::from(e.plan_rev)),
            ms(e.created_at),
        ],
    ));
    if let Some(plan) = &x.plan {
        for a in plan {
            out.push(article_insert(a)?);
        }
        out.push((
            "UPDATE extents SET article_count = ?2, plan_rev = ?3 \
             WHERE id = ?1 AND article_count IS NULL",
            vec![
                id(),
                SqlValue::Int(i64::try_from(plan.len()).unwrap_or(i64::MAX)),
                SqlValue::Int(i64::from(e.plan_rev)),
            ],
        ));
    }
    if !x.safety_present {
        // The pinned copy is given up only after the articles were read
        // back, so what is left of the pipeline has nothing to do. Reads
        // verify every byte against the digests either way.
        out.push((
            "UPDATE extents SET safety_state = 'deleted', evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND safety_state IN ('held', 'releasing')",
            vec![id()],
        ));
        out.push((
            "UPDATE outbox SET stage = 'done', lease_owner = NULL, lease_until = NULL, \
               updated_at = ?2 WHERE extent_id = ?1 AND stage IN ('post', 'verify', 'release')",
            vec![id(), ms(now)],
        ));
        out.push((
            "UPDATE articles SET state = 'posted' WHERE extent_id = ?1 AND state = 'planned'",
            vec![id()],
        ));
    }
    Ok(())
}

/// Step 1.
pub(super) async fn replay_extents<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &Bucket,
    extents: &[ReplayExtent],
    now: UnixMs,
) -> Result<()> {
    let mut stmts: Vec<Stmt> = Vec::new();
    for x in extents {
        if stmts.is_empty() {
            stmts.push(bucket_insert(bucket));
        }
        extent_stmts(x, now, &mut stmts)?;
        if stmts.len() >= BATCH_STATEMENTS {
            c.sql.batch(core::mem::take(&mut stmts)).await?;
        }
    }
    if !stmts.is_empty() {
        c.sql.batch(stmts).await?;
    }
    Ok(())
}

/// Live generations with an extent that has no copy anywhere: its pinned
/// copy is gone and it has no article plan. Returns their number and the
/// ids of the first `limit`.
pub(super) async fn replay_damaged<S: Sql>(
    c: &SqlCatalog<S>,
    limit: u32,
) -> Result<(u64, Vec<GenerationId>)> {
    const DAMAGED: &str = "FROM objects o WHERE EXISTS (SELECT 1 FROM generation_extents ge \
         JOIN extents e ON e.id = ge.extent_id \
         WHERE ge.generation_id = o.generation_id AND e.safety_state = 'deleted' \
           AND NOT EXISTS (SELECT 1 FROM articles a WHERE a.extent_id = e.id))";
    let count = c
        .sql
        .query(&format!("SELECT COUNT(*) {DAMAGED}"), &[])
        .await?;
    let count = match count.first().map(Vec::as_slice) {
        Some([SqlValue::Int(n)]) => u64::try_from(*n).unwrap_or(0),
        _ => return Err(BridgeError::Sql("row decode: damaged count".into())),
    };
    let rows = c
        .sql
        .query(
            &format!("SELECT o.generation_id {DAMAGED} ORDER BY o.generation_id LIMIT ?1"),
            &[SqlValue::Int(i64::from(limit))],
        )
        .await?;
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        match row.as_slice() {
            [SqlValue::Text(id)] => ids.push(GenerationId::new(id.clone())),
            _ => return Err(BridgeError::Sql("row decode: damaged id".into())),
        }
    }
    Ok((count, ids))
}

/// Step 2. `Lost` = the generation is already there, a newer generation
/// of the key is live, or the extents do not tile it (one of them is
/// missing, in another bucket, still a part of an upload under another
/// generation's name, or its key was shredded).
pub(super) async fn replay_publish<S: Sql>(
    c: &SqlCatalog<S>,
    g: &GenerationRow,
    placements: &[ExtentPlacement],
    now: UnixMs,
) -> Result<Guard<()>> {
    if g.state != GenerationState::Live
        || g.retired_at.is_some()
        || usize::try_from(g.extent_count).ok() != Some(placements.len())
    {
        return Err(BridgeError::Invalid(
            "replay does not describe one live generation",
        ));
    }
    let gen_id = || text(g.id.as_str());
    let bucket = || text(g.bucket_id.as_str());
    let mut stmts: Vec<Stmt> = Vec::with_capacity(10 + 2 * placements.len());
    stmts.push((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS (SELECT 1 FROM generations WHERE id = ?1) \
         OR EXISTS (SELECT 1 FROM objects WHERE bucket_id = ?2 AND key = ?3 \
                    AND generation_id > ?1)",
        vec![gen_id(), bucket(), text(&g.key)],
    ));
    stmts.push(clear_tombstone(&g.bucket_id, &g.key, &g.id));
    stmts.push(insert_live(g)?);
    for p in placements {
        stmts.push((
            "UPDATE extents SET generation_id = ?1, seq = ?2, plain_offset = ?3, \
               state = 'committed' \
             WHERE id = ?4 AND bucket_id = ?5 AND state = 'staged' AND generation_id IS NULL",
            vec![
                gen_id(),
                SqlValue::Int(i64::from(p.seq)),
                uint(p.plain_offset)?,
                text(p.extent_id.as_str()),
                bucket(),
            ],
        ));
        // An extent another generation holds is shared with it: this
        // generation is a copy of that one, or that one of this. The
        // adoption above already wrote the reference for an extent it
        // took (trigger `generation_extents_on_adopt`), and such an
        // extent no longer matches here.
        stmts.push((
            "INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
             SELECT ?1, ?2, e.id, ?3 FROM extents e \
              WHERE e.id = ?4 AND e.bucket_id = ?5 AND e.state = 'committed' \
                AND e.generation_id <> ?1",
            vec![
                gen_id(),
                SqlValue::Int(i64::from(p.seq)),
                uint(p.plain_offset)?,
                text(p.extent_id.as_str()),
                bucket(),
            ],
        ));
    }
    // The referenced extents tile the object exactly, each with its key.
    stmts.push((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
           (SELECT COUNT(*) FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
             WHERE ge.generation_id = ?1 AND e.wrapped_file_key IS NOT NULL) <> ?2 \
           OR (SELECT COALESCE(SUM(e.plain_size), 0) FROM generation_extents ge \
                 JOIN extents e ON e.id = ge.extent_id WHERE ge.generation_id = ?1) <> ?3 \
           OR EXISTS (SELECT 1 FROM (SELECT ge.plain_offset AS plain_offset, \
                SUM(e.plain_size) OVER (ORDER BY ge.seq \
                ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS expected \
                FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
               WHERE ge.generation_id = ?1) \
              WHERE plain_offset <> COALESCE(expected, 0))",
        vec![
            gen_id(),
            SqlValue::Int(i64::from(g.extent_count)),
            uint(g.size)?,
        ],
    ));
    // An extent whose pinned copy is held goes through post and verify
    // again: posting a planned article twice is harmless, and the read
    // back is the evidence a release needs. The obligation stays under
    // the generation the extent was first written for.
    stmts.push((
        "INSERT OR IGNORE INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
         SELECT e.id, e.generation_id, \
                CASE e.safety_state WHEN 'held' THEN 'post' ELSE 'done' END, ?2, ?2 \
           FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
          WHERE ge.generation_id = ?1",
        vec![gen_id(), ms(now)],
    ));
    // A shared extent can have left service earlier in this replay: the
    // generation it was written for was retired by a manifest that sorts
    // before this one. It is back in service now, so its obligation runs
    // again, and the collection queued for it is called off below.
    // Nothing collects while a restore runs, so no delete is under way.
    stmts.push((
        "UPDATE outbox SET stage = CASE (SELECT e.safety_state FROM extents e \
                                          WHERE e.id = outbox.extent_id) \
                                   WHEN 'held' THEN 'post' WHEN 'releasing' THEN 'release' \
                                   ELSE 'done' END, \
                attempts = 0, cursor = 0, last_error = NULL, next_at = ?2, updated_at = ?2, \
                lease_token = lease_token + 1, lease_owner = NULL, lease_until = NULL \
          WHERE stage = 'cancelled' AND extent_id IN \
                (SELECT extent_id FROM generation_extents WHERE generation_id = ?1)",
        vec![gen_id(), ms(now)],
    ));
    // Its open GC rows are closed: they were queued for a retirement
    // that this reference undoes. When the extent really leaves service,
    // the retirement that takes its last reference queues fresh rows.
    stmts.push((
        "UPDATE gc SET done_at = ?2 WHERE done_at IS NULL AND extent_id IN \
                (SELECT extent_id FROM generation_extents WHERE generation_id = ?1)",
        vec![gen_id(), ms(now)],
    ));
    stmts.extend(retire_live(
        &g.bucket_id,
        &g.key,
        GenerationState::Superseded,
        now,
    ));
    stmts.push((
        "INSERT INTO objects(bucket_id, key, generation_id) VALUES (?1, ?2, ?3) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET generation_id = excluded.generation_id",
        vec![bucket(), text(&g.key), gen_id()],
    ));
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(Guard::Applied(())),
        Err(BridgeError::GuardFailed) => Ok(Guard::Lost),
        Err(e) => Err(e),
    }
}

/// The row of `g` as the live generation it describes.
fn insert_live(g: &GenerationRow) -> Result<Stmt> {
    Ok((
        "INSERT INTO generations(id, bucket_id, key, state, size, etag, checksum_json, \
           content_json, user_meta_json, extent_count, created_at, retired_at) \
         VALUES (?1,?2,?3,'live',?4,?5,?6,?7,?8,?9,?10,NULL)",
        vec![
            text(g.id.as_str()),
            text(g.bucket_id.as_str()),
            text(&g.key),
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
