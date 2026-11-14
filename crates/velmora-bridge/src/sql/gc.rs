//! Garbage-collection rows (catalogue lane B).
//!
//! GC rows are only ever queued for extents that left service: a replaced,
//! unlisted or aborted upload part, or an extent of a retired generation.
//! `gc_begin` still re-checks that at execution time and refuses to act on
//! an extent a live generation or an open upload references.

use super::uploads::{guarded, ms, text, Cols, Stmt};
use super::SqlCatalog;
use crate::ports::{Guard, Sql, SqlValue};
use crate::types::{BlobStoreKind, ExtentId, GcAction, GcRow, GcStep, Result, UnixMs};

/// A refused row is looked at again after this long, so it cannot keep
/// newer work out of the bounded `gc_due` window.
const SKIP_RETRY_MS: i64 = 60 * 60 * 1000;

/// True while the extent `?1` must not be touched.
macro_rules! in_use {
    () => {
        "(EXISTS (SELECT 1 FROM extents e JOIN generations g ON g.id = e.generation_id \
                  WHERE e.id = ?1 AND g.state = 'live') \
          OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id \
                     WHERE p.extent_id = ?1 AND u.state = 'open'))"
    };
}

/// True while `?2` is an open row for exactly this extent (`?1`) and
/// action (`?3`): the caller's copy of the row is not trusted.
macro_rules! open_row {
    () => {
        "EXISTS (SELECT 1 FROM gc WHERE id = ?2 AND extent_id = ?1 AND action = ?3 \
                 AND done_at IS NULL)"
    };
}

/// Open rows that are due, oldest first. With `disposable_only`, only rows
/// whose extent belongs to a bucket flagged `disposable`.
pub(super) async fn gc_due<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    limit: u32,
    disposable_only: bool,
) -> Result<Vec<GcRow>> {
    let rows = c
        .sql
        .query(
            "SELECT gc.id, gc.extent_id, gc.action, gc.due_at FROM gc \
             WHERE gc.done_at IS NULL AND gc.due_at <= ?1 \
               AND (?2 = 0 OR EXISTS (SELECT 1 FROM extents e JOIN buckets b ON b.id = e.bucket_id \
                    WHERE e.id = gc.extent_id AND b.disposable = 1)) \
             ORDER BY gc.due_at, gc.id LIMIT ?3",
            &[
                ms(now),
                SqlValue::Int(i64::from(disposable_only)),
                SqlValue::Int(i64::from(limit)),
            ],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(GcRow {
            id: r.num()?,
            extent_id: ExtentId::new(r.text()?),
            action: r.parsed(GcAction::parse)?,
            due_at: UnixMs(r.num()?),
            done_at: None,
        });
    }
    Ok(out)
}

/// Decides one row. Blob actions are returned to the caller, who deletes
/// the blob and then calls `gc_done`. Catalogue-only actions are applied
/// and closed here, in one batch guarded by the in-use check.
pub(super) async fn gc_begin<S: Sql>(
    c: &SqlCatalog<S>,
    row: &GcRow,
    now: UnixMs,
) -> Result<GcStep> {
    let ident = || {
        vec![
            text(row.extent_id.as_str()),
            SqlValue::Int(row.id),
            text(row.action.as_str()),
        ]
    };
    let close: Stmt = (
        "UPDATE gc SET done_at = ?2 WHERE id = ?1 AND done_at IS NULL",
        vec![SqlValue::Int(row.id), ms(now)],
    );
    let free = match row.action {
        GcAction::DeleteCache | GcAction::DeleteSafety => {
            let rows = c
                .sql
                .query(
                    concat!("SELECT ", open_row!(), " AND NOT ", in_use!()),
                    &ident(),
                )
                .await?;
            let free = match rows.into_iter().next() {
                Some(r) => Cols::new(r).num::<i64>()? != 0,
                None => false,
            };
            if free && row.action == GcAction::DeleteCache {
                // The cache fill stops being counted before its blob is
                // deleted, never after: a cold read that fills the cache
                // while this delete runs records its copy after this
                // statement, so the copy stays counted. (A count left for
                // a blob that the delete then removed is corrected by the
                // next eviction.)
                c.sql
                    .exec(
                        "UPDATE extents SET hot_cache_bytes = 0, evict_seq = evict_seq + 1 \
                         WHERE id = ?1 AND hot_cache_bytes > 0",
                        &[text(row.extent_id.as_str())],
                    )
                    .await?;
            }
            free
        }
        GcAction::ShredKey | GcAction::DropArticlesMeta => {
            let apply = if row.action == GcAction::ShredKey {
                "UPDATE extents SET wrapped_file_key = NULL WHERE id = ?1"
            } else {
                "DELETE FROM articles WHERE extent_id = ?1"
            };
            let stmts = vec![
                (
                    concat!(
                        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT ",
                        open_row!(),
                        " OR ",
                        in_use!()
                    ),
                    ident(),
                ),
                (apply, vec![text(row.extent_id.as_str())]),
                close,
            ];
            if guarded(c, stmts).await? == Guard::Applied(()) {
                return Ok(GcStep::Done);
            }
            false
        }
    };
    if !free {
        c.sql
            .exec(
                "UPDATE gc SET due_at = ?4 WHERE id = ?2 AND extent_id = ?1 AND action = ?3 \
                   AND done_at IS NULL",
                &[ident(), vec![ms(now.plus_ms(SKIP_RETRY_MS))]].concat(),
            )
            .await?;
        return Ok(GcStep::Skipped);
    }
    Ok(match row.action {
        GcAction::DeleteCache => GcStep::DeleteBlob {
            store: BlobStoreKind::Cache,
            key: row.extent_id.cache_key(),
        },
        _ => GcStep::DeleteBlob {
            store: BlobStoreKind::Safety,
            key: row.extent_id.safety_key(),
        },
    })
}

/// Closes a blob row after its delete; a safety delete also records that
/// the extent no longer has a safety copy and ends the hot-tier count of
/// it. (The count of a cache fill ended in `gc_begin`, before the delete.)
pub(super) async fn gc_done<S: Sql>(c: &SqlCatalog<S>, id: i64, now: UnixMs) -> Result<()> {
    c.sql
        .batch(vec![
            (
                "UPDATE extents SET safety_state = 'deleted', hot_safety_bytes = 0, \
                   evict_seq = evict_seq + 1 \
                 WHERE id = (SELECT extent_id FROM gc \
                 WHERE id = ?1 AND action = 'delete_safety' AND done_at IS NULL)",
                vec![SqlValue::Int(id)],
            ),
            (
                "UPDATE gc SET done_at = ?2 WHERE id = ?1 AND done_at IS NULL",
                vec![SqlValue::Int(id), ms(now)],
            ),
        ])
        .await?;
    Ok(())
}
