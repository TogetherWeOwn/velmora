//! Write intents: the slices of a multi-extent write, recorded before
//! they are stored (migration 0011).
//!
//! All rows of one `write_id` change state together, in one statement:
//!
//! ```text
//! open ──publish──▶ (deleted with the batch that publishes)
//! open ──request gave up──▶ abandoned
//! open (old) / abandoned ──fence──▶ sweeping ──▶ (deleted) | kept
//! ```
//!
//! The publish batch commits only while every row is still `open`, and
//! the fence commits only while the write has no generation and no
//! extent row. So exactly one of the two wins: a fenced write is never
//! published, and a published write is never fenced.

use super::objects::{ms, text, Cols};
use super::replay::guard_no_replay;
use super::SqlCatalog;
use crate::ports::{Guard, Sql, SqlValue};
use crate::types::{
    BridgeError, ExtentId, GenerationId, IntentFence, IntentStats, Result, UnixMs, WriteId,
};

type Stmt = (&'static str, Vec<SqlValue>);

fn count(n: usize) -> Result<SqlValue> {
    i64::try_from(n)
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("slice count exceeds the catalogue range"))
}

/// Fails the batch unless the write has exactly `slices` rows, all of
/// them `open`, and (with `generation`) all under that generation id.
fn guard_open(write: &WriteId, generation: Option<&GenerationId>, slices: usize) -> Result<Stmt> {
    Ok((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
           (SELECT COUNT(*) FROM write_intents WHERE write_id = ?1) <> ?3 \
           OR (SELECT COUNT(*) FROM write_intents WHERE write_id = ?1 AND state = 'open' \
                AND (?2 IS NULL OR generation_id = ?2)) <> ?3",
        vec![
            text(write.as_str()),
            generation.map_or(SqlValue::Null, |g| text(g.as_str())),
            count(slices)?,
        ],
    ))
}

/// Fails the batch when the write has a generation row or an extent row:
/// it was published.
fn guard_unpublished(write: &WriteId) -> Stmt {
    (
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
           EXISTS (SELECT 1 FROM write_intents w JOIN generations g ON g.id = w.generation_id \
                    WHERE w.write_id = ?1) \
           OR EXISTS (SELECT 1 FROM write_intents w JOIN extents e ON e.id = w.extent_id \
                       WHERE w.write_id = ?1)",
        vec![text(write.as_str())],
    )
}

/// Fails the batch when the stamp counter is below `seen`, the value
/// the caller found level with the stamp objects in `SAFETY`: the
/// catalogue was restored to an earlier point since that check. `None`
/// = the check found no stamp object at all, and there is nothing to
/// be behind.
fn guard_stamp(seen: Option<u64>) -> Result<Stmt> {
    let seen = match seen {
        None => SqlValue::Null,
        Some(n) => SqlValue::Int(
            i64::try_from(n)
                .map_err(|_| BridgeError::Invalid("stamp counter exceeds the catalogue range"))?,
        ),
    };
    Ok((
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE ?1 IS NOT NULL AND NOT EXISTS \
           (SELECT 1 FROM rollback_stamp WHERE id = 1 AND counter >= ?1)",
        vec![seen],
    ))
}

pub(super) async fn open_intents<S: Sql>(
    c: &SqlCatalog<S>,
    write: &WriteId,
    extents: &[ExtentId],
    now: UnixMs,
) -> Result<Guard<()>> {
    if extents.is_empty() {
        return Err(BridgeError::Invalid("a write has at least one slice"));
    }
    // No intent is created under a replay: the replay removed the rows
    // when it started (all but `kept` rows of records it does not read)
    // and must find no other row when it ends.
    let mut stmts: Vec<Stmt> = Vec::with_capacity(1 + extents.len());
    stmts.push(guard_no_replay());
    for e in extents {
        stmts.push((
            "INSERT INTO write_intents(extent_id, write_id, state, created_at) \
             VALUES (?1, ?2, 'open', ?3)",
            vec![text(e.as_str()), text(write.as_str()), ms(now)],
        ));
    }
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(Guard::Applied(())),
        Err(BridgeError::GuardFailed) => Ok(Guard::Lost),
        Err(e) => Err(e),
    }
}

pub(super) async fn intents_generation<S: Sql>(
    c: &SqlCatalog<S>,
    write: &WriteId,
    generation: &GenerationId,
    slices: usize,
) -> Result<Guard<()>> {
    let stmts = vec![
        guard_no_replay(),
        guard_open(write, None, slices)?,
        (
            "UPDATE write_intents SET generation_id = ?2 WHERE write_id = ?1 AND state = 'open'",
            vec![text(write.as_str()), text(generation.as_str())],
        ),
    ];
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(Guard::Applied(())),
        Err(BridgeError::GuardFailed) => Ok(Guard::Lost),
        Err(e) => Err(e),
    }
}

/// The statements a publish batch of the write carries, after its
/// extent inserts: every intent is still `open` under the generation
/// being published and names an extent this batch inserted; then the
/// intents go. An extent row and its intent never exist together.
pub(super) fn publish_intents(
    write: &WriteId,
    generation: &GenerationId,
    slices: usize,
) -> Result<[Stmt; 3]> {
    Ok([
        guard_open(write, Some(generation), slices)?,
        (
            "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
               (SELECT COUNT(*) FROM write_intents w JOIN extents e ON e.id = w.extent_id \
                 WHERE w.write_id = ?1 AND e.generation_id = ?2) <> ?3",
            vec![
                text(write.as_str()),
                text(generation.as_str()),
                count(slices)?,
            ],
        ),
        (
            "DELETE FROM write_intents WHERE write_id = ?1",
            vec![text(write.as_str())],
        ),
    ])
}

pub(super) async fn abandon_intents<S: Sql>(c: &SqlCatalog<S>, write: &WriteId) -> Result<()> {
    c.sql
        .exec(
            "UPDATE write_intents SET state = 'abandoned' WHERE write_id = ?1 AND state = 'open'",
            &[text(write.as_str())],
        )
        .await?;
    Ok(())
}

pub(super) async fn due_intents<S: Sql>(
    c: &SqlCatalog<S>,
    open_before: UnixMs,
    limit: u32,
) -> Result<Vec<WriteId>> {
    let rows = c
        .sql
        .query(
            "SELECT write_id, MIN(created_at) AS first FROM write_intents \
              WHERE state IN ('abandoned', 'sweeping') OR (state = 'open' AND created_at < ?1) \
              GROUP BY write_id ORDER BY first, write_id LIMIT ?2",
            &[ms(open_before), SqlValue::Int(i64::from(limit))],
        )
        .await?;
    rows.into_iter()
        .map(|row| Ok(WriteId::new(Cols::new(row).text()?)))
        .collect()
}

/// The rows of a fenced write.
async fn fenced<S: Sql>(
    c: &SqlCatalog<S>,
    write: &WriteId,
) -> Result<(Option<GenerationId>, Vec<ExtentId>)> {
    let rows = c
        .sql
        .query(
            "SELECT extent_id, generation_id FROM write_intents \
              WHERE write_id = ?1 AND state = 'sweeping' ORDER BY extent_id",
            &[text(write.as_str())],
        )
        .await?;
    let mut generation = None;
    let mut extents = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        extents.push(ExtentId::new(r.text()?));
        if let Some(g) = r.opt_text()? {
            generation = Some(GenerationId::new(g));
        }
    }
    Ok((generation, extents))
}

pub(super) async fn fence_intents<S: Sql>(
    c: &SqlCatalog<S>,
    write: &WriteId,
    open_before: UnixMs,
    stamp: Option<u64>,
) -> Result<IntentFence> {
    let stmts = vec![
        guard_no_replay(),
        guard_stamp(stamp)?,
        guard_unpublished(write),
        (
            "UPDATE write_intents SET state = 'sweeping' WHERE write_id = ?1 \
               AND (state IN ('abandoned', 'sweeping') OR (state = 'open' AND created_at < ?2))",
            vec![text(write.as_str()), ms(open_before)],
        ),
    ];
    match c.sql.batch(stmts).await {
        Ok(changed) if changed.last().copied().unwrap_or(0) == 0 => Ok(IntentFence::Gone),
        Ok(_) => {
            let (generation, extents) = fenced(c, write).await?;
            Ok(IntentFence::Fenced {
                generation,
                extents,
            })
        }
        Err(BridgeError::GuardFailed) => published_intents(c, write).await,
        Err(e) => Err(e),
    }
}

/// After a refused fence: when the write has catalogue rows it was
/// published, and only its intents are in the way. They are deleted and
/// counted in a batch that decides the condition again and fails when
/// it does not hold.
async fn published_intents<S: Sql>(c: &SqlCatalog<S>, write: &WriteId) -> Result<IntentFence> {
    let stmts = vec![
        guard_no_replay(),
        (
            "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ( \
               EXISTS (SELECT 1 FROM write_intents w \
                 JOIN generations g ON g.id = w.generation_id WHERE w.write_id = ?1) \
               OR EXISTS (SELECT 1 FROM write_intents w \
                 JOIN extents e ON e.id = w.extent_id WHERE w.write_id = ?1))",
            vec![text(write.as_str())],
        ),
        (
            "INSERT INTO meta(k, v) VALUES ('intent_anomalies', 1) \
             ON CONFLICT(k) DO UPDATE SET v = v + 1",
            Vec::new(),
        ),
        (
            "DELETE FROM write_intents WHERE write_id = ?1",
            vec![text(write.as_str())],
        ),
    ];
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(IntentFence::Published),
        Err(BridgeError::GuardFailed) => Ok(IntentFence::Refused),
        Err(e) => Err(e),
    }
}

pub(super) async fn hold_intent_fence<S: Sql>(
    c: &SqlCatalog<S>,
    write: &WriteId,
    slices: usize,
    stamp: Option<u64>,
) -> Result<bool> {
    let stmts = vec![
        guard_no_replay(),
        guard_stamp(stamp)?,
        guard_unpublished(write),
        (
            "UPDATE write_intents SET state = 'sweeping' \
              WHERE write_id = ?1 AND state = 'sweeping'",
            vec![text(write.as_str())],
        ),
    ];
    match c.sql.batch(stmts).await {
        Ok(changed) => Ok(slices > 0 && changed.last().copied() == u64::try_from(slices).ok()),
        Err(BridgeError::GuardFailed) => Ok(false),
        Err(e) => Err(e),
    }
}

pub(super) async fn keep_intents<S: Sql>(c: &SqlCatalog<S>, write: &WriteId) -> Result<()> {
    // Counted once: a second call finds no `sweeping` row.
    let stmts = vec![
        (
            "INSERT INTO meta(k, v) SELECT 'intent_anomalies', 1 WHERE EXISTS \
               (SELECT 1 FROM write_intents WHERE write_id = ?1 AND state = 'sweeping') \
             ON CONFLICT(k) DO UPDATE SET v = v + 1",
            vec![text(write.as_str())],
        ),
        (
            "UPDATE write_intents SET state = 'kept' WHERE write_id = ?1 AND state = 'sweeping'",
            vec![text(write.as_str())],
        ),
    ];
    c.sql.batch(stmts).await?;
    Ok(())
}

pub(super) async fn drop_intents<S: Sql>(c: &SqlCatalog<S>, write: &WriteId) -> Result<()> {
    c.sql
        .exec(
            "DELETE FROM write_intents WHERE write_id = ?1 AND state = 'sweeping'",
            &[text(write.as_str())],
        )
        .await?;
    Ok(())
}

pub(super) async fn intent_stats<S: Sql>(
    c: &SqlCatalog<S>,
    open_before: UnixMs,
) -> Result<IntentStats> {
    let rows = c
        .sql
        .query(
            "SELECT \
               COUNT(DISTINCT CASE WHEN state = 'kept' THEN write_id END), \
               COUNT(CASE WHEN state = 'kept' THEN 1 END), \
               MIN(CASE WHEN state = 'kept' THEN created_at END), \
               COUNT(DISTINCT CASE WHEN state IN ('abandoned', 'sweeping') \
                 OR (state = 'open' AND created_at < ?1) THEN write_id END), \
               MIN(CASE WHEN state IN ('abandoned', 'sweeping') \
                 OR (state = 'open' AND created_at < ?1) THEN created_at END), \
               COUNT(DISTINCT CASE WHEN state = 'open' AND created_at >= ?1 THEN write_id END), \
               COALESCE((SELECT v FROM meta WHERE k = 'intent_anomalies'), 0) \
             FROM write_intents",
            &[ms(open_before)],
        )
        .await?;
    let row = rows
        .into_iter()
        .next()
        .ok_or_else(|| BridgeError::Sql("row decode: intent stats".into()))?;
    let mut r = Cols::new(row);
    Ok(IntentStats {
        kept_writes: r.num()?,
        kept_slices: r.num()?,
        oldest_kept_at: r.opt_ms()?,
        waiting_writes: r.num()?,
        oldest_waiting_at: r.opt_ms()?,
        open_writes: r.num()?,
        anomalies: r.num()?,
    })
}
