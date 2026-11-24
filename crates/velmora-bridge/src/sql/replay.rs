//! Catalogue statements of a recovery replay (DESIGN §A.8).
//!
//! A generation manifest is applied in two idempotent steps:
//!
//! 1. [`replay_extents`], any number of times, in chunks: the bucket and
//!    the extents exist (new ones as `staged` rows without a generation,
//!    like the parts of an open upload), their article plans exist (a
//!    packed plan that cannot be read is replaced by its record's), and
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

use super::objects::{clear_floor, ms, opt, retire_live_in, text, uint};
use super::uploads::int;
use super::SqlCatalog;
use crate::ports::{Sql, SqlLimits, SqlValue};
use crate::recovery::{start_after, GENERATION_PREFIX, RECORD_PREFIX};
use crate::replay::{ReplayExtent, ReplayMark, ReplayProbe, ReplayPublish, RestoreProgress};
use crate::stamp::StampRow;
use crate::types::{
    ArticleRow, BridgeError, Bucket, ExtentId, ExtentPlacement, GenerationId, GenerationRow,
    GenerationState, Result, SafetyState, UnixMs,
};

type Stmt = (&'static str, Vec<SqlValue>);

/// Ends every claim on extent `?1` while its row still holds the plan
/// `?2`, the addendum `?3` and the count whose literal is `?4`: the
/// lease token moves on, as when a lease is given up, so every write of
/// a job that holds the row is refused (`held!` in `sql/outbox.rs`).
/// A verify that had got past a backbone starts at the first again: the
/// passes it would skip are the ones deleted here.
/// Run before the statement that changes those values, in its batch.
const FENCE_CLAIMS: &str =
    "UPDATE outbox SET lease_token = lease_token + 1, lease_owner = NULL, lease_until = NULL, \
       cursor = CASE stage WHEN 'verify' THEN 0 ELSE cursor END \
     WHERE extent_id = ?1 \
       AND EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND plan = ?2 \
         AND parity IS ?3 AND quote(parity_count) = ?4)";

/// Statements per batch before it is sent.
const BATCH_STATEMENTS: usize = 300;

pub(super) async fn replay_probe<S: Sql>(
    c: &SqlCatalog<S>,
    g: &GenerationRow,
) -> Result<ReplayProbe> {
    let rows = c
        .sql
        .query(
            REPLAY_PROBE,
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

fn bucket_insert(dialect: crate::ports::Dialect, b: &Bucket) -> Stmt {
    (
        dialect.pick(INSERT_BUCKET, INSERT_BUCKET_PG),
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

fn article_insert(dialect: crate::ports::Dialect, a: &ArticleRow) -> Result<Stmt> {
    Ok((
        // Beside a packed plan a row is never read: none is written.
        dialect.pick(INSERT_ARTICLE, INSERT_ARTICLE_PG),
        vec![
            text(a.extent_id.as_str()),
            SqlValue::Int(i64::from(a.idx)),
            text(&a.message_id),
            text(&a.newsgroup),
            SqlValue::Blob(a.headers.clone()),
            uint(a.cipher_offset)?,
            uint(a.cipher_len)?,
            SqlValue::Blob(a.payload_sha256.to_vec()),
            opt(a.yenc_name.as_deref(), text),
            text(a.state.as_str()),
        ],
    ))
}

/// The statements for one extent. Every one is a no-op on a catalogue
/// that already has what it would write.
fn extent_stmts(
    dialect: crate::ports::Dialect,
    x: &ReplayExtent,
    now: UnixMs,
    out: &mut Vec<Stmt>,
) -> Result<()> {
    let e = &x.row;
    let id = || text(e.id.as_str());
    let safety = if x.safety_present {
        SafetyState::Held
    } else {
        SafetyState::Deleted
    };
    out.push((
        dialect.pick(INSERT_EXTENT, INSERT_EXTENT_PG),
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
    match (&x.plan, &x.packed) {
        // The packed plan goes on the extent's row, and no article row
        // is written. An extent that has a plan keeps it, as with rows;
        // one that lost its plan (the count is all that is left of it)
        // gets it back. Its parity addendum goes with it, by the same
        // statement, and never without it.
        (Some(plan), Some(packed)) => {
            let (parity, parity_count) = parity_of(x, packed);
            out.push((
                RESTORE_PACKED_PLAN,
                vec![
                    id(),
                    SqlValue::Int(i64::try_from(plan.len()).unwrap_or(i64::MAX)),
                    SqlValue::Int(i64::from(e.plan_rev)),
                    SqlValue::Blob(packed.clone()),
                    parity,
                    parity_count,
                ],
            ))
        }
        (Some(plan), None) => {
            for a in plan {
                out.push(article_insert(dialect, a)?);
            }
            out.push((
                RESTORE_UNPACKED_COUNT,
                vec![
                    id(),
                    SqlValue::Int(i64::try_from(plan.len()).unwrap_or(i64::MAX)),
                    SqlValue::Int(i64::from(e.plan_rev)),
                ],
            ));
        }
        (None, _) => {}
    }
    if !x.safety_present {
        // The pinned copy is given up only after the articles were read
        // back, so what is left of the pipeline has nothing to do. Reads
        // verify every byte against the digests either way.
        out.push((SET_ABSENT_SAFETY, vec![id()]));
        out.push((TERMINATE_ABSENT_OUTBOX, vec![id(), ms(now)]));
        out.push((RESTORE_ARTICLES_POSTED, vec![id()]));
        // The same for a packed plan: posted, at a time nobody knows.
        out.push((
            RESTORE_EXTENT_POSTED,
            vec![id(), SqlValue::Int(crate::plan::POSTED_AT_UNKNOWN)],
        ));
    }
    Ok(())
}

/// The parity addendum of the record of `x` and the number of its
/// articles, as the values of `extents.parity` and `parity_count`
/// beside the packed plan `packed`. Both are NULL when the record has
/// none, and when the one it has is not an addendum of that plan: such
/// an extent is restored without parity, and the replay goes on.
fn parity_of(x: &ReplayExtent, packed: &[u8]) -> (SqlValue, SqlValue) {
    addendum_of(x, packed, x.parity.as_deref())
}

/// `addendum` and the number of its articles as the values of
/// `extents.parity` and `parity_count` beside the packed plan `packed`
/// of the extent of `x`; NULL both for none and for one that is not an
/// addendum of that plan.
fn addendum_of(x: &ReplayExtent, packed: &[u8], addendum: Option<&[u8]>) -> (SqlValue, SqlValue) {
    let read = addendum.and_then(|addendum| {
        let parity = crate::parity::expand(&x.row.id, x.row.cipher_size, packed, addendum).ok()?;
        Some((addendum, i64::try_from(parity.articles.len()).ok()?))
    });
    match read {
        Some((addendum, count)) => (SqlValue::Blob(addendum.to_vec()), SqlValue::Int(count)),
        None => (SqlValue::Null, SqlValue::Null),
    }
}

/// A packed plan in the catalogue that cannot be read.
struct Unreadable {
    extent: ExtentId,
    /// The stored value.
    stored: Vec<u8>,
    /// The parity addendum on the row, beside the plan that does not
    /// read.
    parity: Option<Vec<u8>>,
    /// The plan of the extent's record, to put in its place. `None` =
    /// the record has no plan that this row can hold.
    plan: Option<Vec<u8>>,
}

/// A parity addendum in the catalogue that cannot be read beside its
/// packed plan, which can, and the addendum of the extent's record to
/// put in its place.
struct LostAddendum {
    extent: ExtentId,
    /// The stored plan and `extents.parity` as they were read, and the
    /// SQL literal (`quote`) of `extents.parity_count`.
    plan: Vec<u8>,
    stored: SqlValue,
    stored_count: SqlValue,
    /// The record's addendum and the number of its articles.
    parity: SqlValue,
    parity_count: SqlValue,
}

/// The extents of `extents` whose packed plan in the catalogue cannot be
/// read (a damaged value, the plan of another extent), and those whose
/// plan can be read but whose parity addendum cannot, or is not the one
/// the row counts, where the record has the addendum of that plan.
///
/// An addendum that cannot be read fails every job that verifies or
/// releases the extent, so the record is the only way back for it too.
/// Where the record has none that is an addendum of the stored plan,
/// the row is left as it is: its jobs keep failing, and the extent is
/// never taken for one without parity.
///
/// A plan the catalogue has is kept, in whatever form, as long as it
/// can be read. One that cannot is no plan: every reader of the extent
/// fails on it, and the schema keeps it from being dropped while the
/// extent is in service, so the record is the only way back.
async fn unreadable_plans<S: Sql>(
    c: &SqlCatalog<S>,
    extents: &[ReplayExtent],
) -> Result<(Vec<Unreadable>, Vec<LostAddendum>)> {
    let mut out = Vec::new();
    let mut addenda = Vec::new();
    for chunk in extents.chunks(LOST_CHUNK) {
        let rows = c
            .sql
            .query(
                &unreadable_plan_sql(c.sql.dialect(), chunk.len()),
                &chunk
                    .iter()
                    .map(|x| text(x.row.id.as_str()))
                    .collect::<Vec<_>>(),
            )
            .await?;
        for row in rows {
            let mut r = super::uploads::Cols::new(row);
            let id = ExtentId::new(r.text()?);
            let cipher_size: u64 = r.num()?;
            let stored = r.blob()?;
            let parity = r.opt_blob()?;
            // On D1, an invalid numeric value is projected as text so
            // damage to one row does not stop replay of the others.
            // The CAS binds the SQLite storage literal, or the exact
            // nullable BIGINT on Postgres (with null-safe equality).
            let count = r.value()?;
            let count_cas = r.value()?;
            let Some(x) = chunk.iter().find(|x| x.row.id == id) else {
                continue;
            };
            if crate::plan::expand(&id, cipher_size, &stored, None, None).is_ok() {
                // The plan reads. Its addendum has to read beside it,
                // and be the one the row counts.
                let on_row = match &parity {
                    Some(parity) => SqlValue::Blob(parity.clone()),
                    None => SqlValue::Null,
                };
                let reads = addendum_of(x, &stored, parity.as_deref());
                let sound = match (&on_row, &count) {
                    (SqlValue::Null, SqlValue::Null) => true,
                    _ => reads == (on_row.clone(), count.clone()),
                };
                if sound {
                    continue;
                }
                let (from_record, record_count) = addendum_of(x, &stored, x.parity.as_deref());
                if from_record != SqlValue::Null {
                    addenda.push(LostAddendum {
                        extent: id,
                        plan: stored,
                        stored: on_row,
                        stored_count: count_cas,
                        parity: from_record,
                        parity_count: record_count,
                    });
                }
                continue;
            }
            // The record's plan in the form the replay stores it in,
            // and the explicit form when it stores rows: beside a plan
            // value, rows are not read.
            let plan = match (&x.packed, &x.plan) {
                (Some(packed), _) => Some(packed.clone()),
                (None, Some(rows)) => crate::plan::repack(&id, cipher_size, rows, None),
                (None, None) => None,
            };
            // Only a value that reads on this very row is worth
            // writing.
            let plan =
                plan.filter(|p| crate::plan::expand(&id, cipher_size, p, None, None).is_ok());
            out.push(Unreadable {
                extent: id,
                stored,
                parity,
                plan,
            });
        }
    }
    Ok((out, addenda))
}

/// Step 1. Returns the extents whose packed plan cannot be read and
/// stays so: their record has no plan to put in its place.
pub(super) async fn replay_extents<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &Bucket,
    extents: &[ReplayExtent],
    now: UnixMs,
) -> Result<Vec<ExtentId>> {
    let (unreadable, addenda) = unreadable_plans(c, extents).await?;
    let mut stmts: Vec<Stmt> = Vec::new();
    for x in extents {
        if stmts.is_empty() {
            stmts.push(bucket_insert(c.sql.dialect(), bucket));
        }
        extent_stmts(c.sql.dialect(), x, now, &mut stmts)?;
        for u in unreadable.iter().filter(|u| u.extent == x.row.id) {
            let Some(plan) = &u.plan else { continue };
            // Keyed on the very value that was read: a plan that
            // changed since is another plan, and is left alone. The
            // record's addendum, when it is one of this plan, goes in
            // with it; failing that the row keeps the addendum it has,
            // when that is one of this plan. Any other addendum is of
            // another plan and goes: the extent has no parity.
            let from_record = addendum_of(x, plan, x.parity.as_deref());
            let (parity, parity_count) = match from_record {
                (SqlValue::Null, _) => addendum_of(x, plan, u.parity.as_deref()),
                found => found,
            };
            // Where that writes another addendum than the row has, the
            // passes on record and the claims in flight are of the old
            // one: both go first, in this batch, as below.
            let swapped = || {
                vec![
                    text(x.row.id.as_str()),
                    SqlValue::Blob(u.stored.clone()),
                    parity.clone(),
                ]
            };
            stmts.push((
                c.sql
                    .dialect()
                    .pick(DROP_PASSES_FOR_SWAP, DROP_PASSES_FOR_SWAP_PG),
                swapped(),
            ));
            stmts.push((
                c.sql
                    .dialect()
                    .pick(FENCE_CLAIMS_FOR_SWAP, FENCE_CLAIMS_FOR_SWAP_PG),
                swapped(),
            ));
            stmts.push((
                REPLACE_UNREADABLE_PLAN,
                vec![
                    text(x.row.id.as_str()),
                    SqlValue::Int(i64::try_from(x.plan.as_ref().map_or(0, Vec::len)).unwrap_or(0)),
                    SqlValue::Int(i64::from(x.row.plan_rev)),
                    SqlValue::Blob(plan.clone()),
                    SqlValue::Blob(u.stored.clone()),
                    parity,
                    parity_count,
                ],
            ));
        }
        for a in addenda.iter().filter(|a| a.extent == x.row.id) {
            // Keyed on the very values that were read. A pass on record
            // is bound to the plan revision and the number of articles,
            // not to the addendum: whoever writes another addendum on
            // an extent drops its passes in the same batch, so that
            // none of them speaks for parity articles it never saw.
            let read = || {
                vec![
                    text(a.extent.as_str()),
                    SqlValue::Blob(a.plan.clone()),
                    a.stored.clone(),
                    a.stored_count.clone(),
                ]
            };
            stmts.push((
                c.sql
                    .dialect()
                    .pick(DROP_PASSES_FOR_ADDENDUM, DROP_PASSES_FOR_ADDENDUM_PG),
                read(),
            ));
            // And ends every claim on the extent: a job in flight read
            // the plan before this batch and asks the backbones for the
            // articles of the old addendum. Its lease is dead from here
            // on, so what it finds is not recorded and it releases
            // nothing; the row is free for a job that reads the plan as
            // it is now.
            stmts.push((c.sql.dialect().pick(FENCE_CLAIMS, FENCE_CLAIMS_PG), read()));
            let mut params = read();
            params.extend([a.parity.clone(), a.parity_count.clone()]);
            stmts.push((
                c.sql.dialect().pick(REPLACE_ADDENDUM, REPLACE_ADDENDUM_PG),
                params,
            ));
        }
        if stmts.len() >= BATCH_STATEMENTS {
            c.sql.batch(core::mem::take(&mut stmts)).await?;
        }
    }
    if !stmts.is_empty() {
        c.sql.batch(stmts).await?;
    }
    Ok(unreadable
        .into_iter()
        .filter(|u| u.plan.is_none())
        .map(|u| u.extent)
        .collect())
}

/// Live generations with an extent that has no copy anywhere: its pinned
/// copy is gone and it has no article plan. Returns their number and the
/// ids of the first `limit`.
pub(super) async fn replay_damaged<S: Sql>(
    c: &SqlCatalog<S>,
    limit: u32,
) -> Result<(u64, Vec<GenerationId>)> {
    let count = c.sql.query(COUNT_DAMAGED, &[]).await?;
    let count = match count.first().map(Vec::as_slice) {
        Some([SqlValue::Int(n)]) => u64::try_from(*n).unwrap_or(0),
        _ => return Err(BridgeError::Sql("row decode: damaged count".into())),
    };
    let rows = c
        .sql
        .query(LIST_DAMAGED, &[SqlValue::Int(i64::from(limit))])
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

/// Ids of extents whose row says a pinned copy exists.
pub(super) async fn held_extents<S: Sql>(
    c: &SqlCatalog<S>,
    after: &str,
    limit: u32,
) -> Result<Vec<ExtentId>> {
    let rows = c
        .sql
        .query(
            REPLAY_HELD_PAGE,
            &[text(after), SqlValue::Int(i64::from(limit))],
        )
        .await?;
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        match row.as_slice() {
            [SqlValue::Text(id)] => ids.push(ExtentId::new(id.clone())),
            _ => return Err(BridgeError::Sql("row decode: held extent".into())),
        }
    }
    Ok(ids)
}

/// How often [`restore_begin`] reads the mark again when another begin
/// moved it in between.
const BEGIN_ATTEMPTS: u32 = 4;

pub(super) async fn restore_begin<S: Sql>(
    c: &SqlCatalog<S>,
    since: UnixMs,
    now: UnixMs,
) -> Result<std::result::Result<UnixMs, UnixMs>> {
    for _ in 0..BEGIN_ATTEMPTS {
        // The mark is the start time, moved past the mark of the replay
        // before it when the two fall into one millisecond. It is read
        // first and the batch commits only if it is still the same, so
        // that the batch needs no result row: the mark it wrote is known.
        let rows = c.sql.query(REPLAY_STATE, &[]).await?;
        let before = match rows.first().map(Vec::as_slice) {
            None => None,
            Some([SqlValue::Int(mark), SqlValue::Int(ended), SqlValue::Int(point)]) => {
                // A replay that has not ended is replaced only by one
                // that starts no later than it: the catalogue holds no
                // more than the records up to that point, whatever was
                // restored since. A row that the runbook's arming
                // statement wrote over no unfinished replay has no such
                // point (`since_ms` -1).
                if *ended == 0 && *point >= 0 && since.0 > *point {
                    return Ok(Err(UnixMs(*point)));
                }
                Some(*mark)
            }
            Some(_) => return Err(BridgeError::Sql("row decode: restore mark".into())),
        };
        let run = before.map_or(now.0, |mark| now.0.max(mark.saturating_add(1)));
        // Every generation id the replay reads sorts after this one.
        let first_key = start_after(GENERATION_PREFIX, since);
        let first_read = first_key
            .strip_prefix(RECORD_PREFIX)
            .ok_or(BridgeError::Invalid("a record key without its prefix"))?;
        let stmts: Vec<Stmt> = vec![
            (
                c.sql.dialect().pick(GUARD_REPLAY_RUN, GUARD_REPLAY_RUN_PG),
                vec![opt(before, SqlValue::Int)],
            ),
            // The rule above, held by the batch itself: it does not
            // rest on the row that was read.
            (GUARD_REPLAY_WINDOW, vec![ms(since)]),
            // The intents of a restored catalogue can name the blobs of
            // objects that were acknowledged after its backup; their
            // rows only come back with the replay. No sweep may read
            // these intents: they go in the batch that starts the
            // replay. Losing them leaves at most the blobs of writes
            // that were under way.
            //
            // A `kept` row stays when this replay does not read its
            // record (one minted before `since`): the row is then still
            // the only sign of a record without an object, and no sweep
            // deletes anything of a `kept` write.
            (PRUNE_WRITE_INTENTS, vec![text(first_read)]),
            (ARM_REPLAY, vec![ms(since), SqlValue::Int(run)]),
        ];
        match c.sql.batch(stmts).await {
            Ok(_) => return Ok(Ok(UnixMs(run))),
            // Another begin moved the mark: read again.
            Err(BridgeError::GuardFailed) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(BridgeError::Sql("restore mark kept moving".into()))
}

pub(super) async fn restore_finish<S: Sql>(
    c: &SqlCatalog<S>,
    run: UnixMs,
    now: UnixMs,
    stamp: u64,
    seen: Option<u64>,
    catalogue: &str,
) -> Result<bool> {
    // Ending the same replay twice is the same as ending it once.
    // The stamp is made level in the same batch, before the state is
    // changed and only while it says `replaying`: this call is then the
    // one that ends the replay, and the catalogue holds every record.
    // A second call for a replay that has ended changes no stamp. Its
    // cursor may be an old one, sent again after the catalogue was
    // rolled back to a point after that replay: the rollback that was
    // found then stays on record. The counter never moves down.
    // `stamp` was chosen from the counter `seen`. If the database was
    // brought back to an earlier point since that read, the counter is
    // another one: the stamp is left alone, and so is the state, which
    // is changed only over a stamp that is level and not marked.
    let seen = match seen {
        Some(counter) => int(counter)?,
        None => SqlValue::Null,
    };
    let changed = c
        .sql
        .batch(vec![
            (
                c.sql.dialect().pick(LEVEL_STAMP, LEVEL_STAMP_PG),
                vec![int(stamp)?, ms(run), text(catalogue), seen],
            ),
            (FINISH_REPLAY_STATE, vec![ms(now), ms(run), int(stamp)?]),
        ])
        .await?;
    Ok(changed.get(1) == Some(&1))
}

pub(super) async fn stamp<S: Sql>(c: &SqlCatalog<S>, catalogue: &str) -> Result<StampRow> {
    let rows = c.sql.query(READ_STAMP, &[text(catalogue)]).await?;
    match rows.first().map(Vec::as_slice) {
        None => Ok(StampRow {
            counter: None,
            rolled_back: false,
        }),
        // The stamp objects of this database are under another id: the
        // ones under `catalogue` say nothing about it.
        Some([_, _, SqlValue::Int(0)]) => Err(crate::stamp::ERR_CATALOGUE_ID),
        Some([SqlValue::Int(counter), SqlValue::Int(rolled), SqlValue::Int(_)]) => Ok(StampRow {
            counter: Some(
                u64::try_from(*counter)
                    .map_err(|_| BridgeError::Sql("row decode: stamp counter".into()))?,
            ),
            rolled_back: *rolled != 0,
        }),
        _ => Err(BridgeError::Sql("row decode: rollback stamp".into())),
    }
}

pub(super) async fn stamp_advance<S: Sql>(
    c: &SqlCatalog<S>,
    from: Option<u64>,
    catalogue: &str,
) -> Result<bool> {
    let changed = match from {
        None => c.sql.exec(SEED_STAMP, &[text(catalogue)]).await?,
        Some(from) => c.sql.exec(ADVANCE_STAMP, &[int(from)?]).await?,
    };
    Ok(changed == 1)
}

pub(super) async fn stamp_rolled_back<S: Sql>(
    c: &SqlCatalog<S>,
    seen: Option<u64>,
    now: UnixMs,
    catalogue: &str,
) -> Result<bool> {
    // Only while the counter is what the caller compared the stamp
    // objects with. A raise that ran in between moved it and put an
    // object of its own: that object is no sign of a rollback.
    let changed = match seen {
        // Without a row the counter is 0: behind every stamp object.
        None => {
            c.sql
                .exec(SEED_ROLLBACK_MARK, &[ms(now), text(catalogue)])
                .await?
        }
        Some(seen) => c.sql.exec(MARK_ROLLBACK, &[ms(now), int(seen)?]).await?,
    };
    Ok(changed == 1)
}

pub(super) async fn restore_pending<S: Sql>(c: &SqlCatalog<S>) -> Result<bool> {
    let rows = c.sql.query(REPLAY_ACTIVE, &[]).await?;
    match rows.first().map(Vec::as_slice) {
        Some([SqlValue::Int(n)]) => Ok(*n != 0),
        _ => Err(BridgeError::Sql("row decode: restore state".into())),
    }
}

/// Fails the batch it is in while a replay is under way, or while a
/// rollback of the catalogue was found and not yet replayed. Every batch
/// that publishes or deletes for a client carries it: the gate at the
/// start of a request is read before the batch runs, and a replay that
/// started in between must not find a write committed under it.
pub(super) fn guard_no_replay() -> Stmt {
    (GUARD_NO_REPLAY, Vec::new())
}

pub(super) async fn restore_progress<S: Sql>(
    c: &SqlCatalog<S>,
    run: UnixMs,
) -> Result<Option<RestoreProgress>> {
    let rows = c.sql.query(REPLAY_PROGRESS, &[ms(run)]).await?;
    let bad = || BridgeError::Sql("row decode: restore progress".into());
    match rows.first().map(Vec::as_slice) {
        None => Ok(None),
        Some([SqlValue::Int(since), SqlValue::Null, _, _, SqlValue::Int(ended)]) => {
            Ok(Some(RestoreProgress {
                since: UnixMs(*since),
                reached: None,
                ended: *ended != 0,
            }))
        }
        Some(
            [SqlValue::Int(since), SqlValue::Int(phase), SqlValue::Text(after), SqlValue::Int(extent), SqlValue::Int(ended)],
        ) => Ok(Some(RestoreProgress {
            since: UnixMs(*since),
            reached: Some(ReplayMark {
                phase: u8::try_from(*phase).map_err(|_| bad())?,
                after: after.clone(),
                extent: u32::try_from(*extent).map_err(|_| bad())?,
            }),
            ended: *ended != 0,
        })),
        Some(_) => Err(bad()),
    }
}

pub(super) async fn restore_advance<S: Sql>(
    c: &SqlCatalog<S>,
    run: UnixMs,
    next: &ReplayMark,
) -> Result<()> {
    c.sql
        .exec(
            ADVANCE_REPLAY_PROGRESS,
            &[
                ms(run),
                SqlValue::Int(i64::from(next.phase)),
                text(&next.after),
                SqlValue::Int(i64::from(next.extent)),
            ],
        )
        .await?;
    Ok(())
}

/// Extent ids per statement of [`unreadable_plans`].
const LOST_CHUNK: usize = 50;

/// Extents per query of [`has_unread_extent`] that asks for the sizes
/// of their packed plans. The plans themselves are asked for in runs
/// bounded by their bytes ([`SqlLimits::result_bytes`]): a plan grows
/// with the articles of its extent, so a number of rows does not bound
/// an answer that carries plans.
const UNREAD_ROWS: usize = 500;

/// Whether one of the extents has no copy anywhere. One query per value
/// of placements ([`super::publish::placement_values`]).
///
/// Asked after the batch of a replay was refused, so through
/// [`Sql::query_after_refusal`].
async fn has_lost_extent<S: Sql>(c: &SqlCatalog<S>, values: &[String]) -> Result<bool> {
    for value in values {
        let rows = c
            .sql
            .query_after_refusal(
                c.sql
                    .dialect()
                    .pick(EXTENT_HAS_NO_COPY, EXTENT_HAS_NO_COPY_PG),
                &[SqlValue::Text(value.clone())],
            )
            .await?;
        if !rows.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether one of the extents has no pinned copy and a packed plan that
/// cannot be read. Such a value is no plan ([`unreadable_plans`]), so
/// the extent has no copy anywhere, though its row holds a value and
/// [`NO_COPY`] does not see it.
async fn has_unread_extent<S: Sql>(
    c: &SqlCatalog<S>,
    placements: &[ExtentPlacement],
    limits: SqlLimits,
) -> Result<bool> {
    let window = SqlLimits {
        set_rows: limits.set_rows.min(UNREAD_ROWS),
        ..limits
    };
    for value in super::publish::placement_values(placements, window)? {
        // Which of them have a plan to judge, and how large it is.
        let sizes = c
            .sql
            .query(
                c.sql
                    .dialect()
                    .pick(UNREAD_PLAN_SIZES, UNREAD_PLAN_SIZES_PG),
                &[SqlValue::Text(value)],
            )
            .await?;
        let mut sized = Vec::with_capacity(sizes.len());
        for row in sizes {
            let mut r = super::uploads::Cols::new(row);
            let id = r.text()?;
            let bytes: u64 = r.num()?;
            sized.push((id, bytes));
        }
        for ids in plan_runs(&sized, limits)? {
            let rows = c
                .sql
                .query(
                    c.sql
                        .dialect()
                        .pick(UNREAD_PLAN_VALUES, UNREAD_PLAN_VALUES_PG),
                    &[SqlValue::Text(ids)],
                )
                .await?;
            for row in rows {
                let mut r = super::uploads::Cols::new(row);
                let id = ExtentId::new(r.text()?);
                let cipher_size: u64 = r.num()?;
                let stored = r.blob()?;
                if crate::plan::expand(&id, cipher_size, &stored, None, None).is_err() {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// The ids of `sized` (an extent id and the bytes of its plan) as JSON
/// arrays, in order, each naming plans of at most
/// `limits.result_bytes` together, or one plan that is larger than that
/// on its own.
fn plan_runs(sized: &[(String, u64)], limits: SqlLimits) -> Result<Vec<String>> {
    let budget = u64::try_from(limits.result_bytes).unwrap_or(u64::MAX);
    let mut runs = Vec::new();
    let mut run = String::new();
    let mut held = 0u64;
    for (id, bytes) in sized {
        let id = serde_json::to_string(id)
            .map_err(|_| BridgeError::Invalid("an extent id that is not JSON text"))?;
        let full = held.saturating_add(*bytes) > budget
            || run.len().saturating_add(id.len()).saturating_add(2) > limits.value_bytes;
        if !run.is_empty() && full {
            run.push(']');
            runs.push(core::mem::take(&mut run));
            held = 0;
        }
        run.push(if run.is_empty() { '[' } else { ',' });
        run.push_str(&id);
        held = held.saturating_add(*bytes);
    }
    if !run.is_empty() {
        run.push(']');
        runs.push(run);
    }
    Ok(runs)
}

/// The id of the live generation of the key of `g`, if it is the same
/// object: the same size and ETag, and exactly the extents of
/// `placements` at their places. The placements are compared in SQL, a
/// value at a time; no extent row is loaded.
///
/// A replay asks this of a record whose batch was just refused, so
/// every read goes through [`Sql::query_after_refusal`].
pub(super) async fn replay_twin<S: Sql>(
    c: &SqlCatalog<S>,
    g: &GenerationRow,
    placements: &[ExtentPlacement],
) -> Result<Option<GenerationId>> {
    let Some(live) = super::objects::live_generation_asked(c, &g.bucket_id, &g.key, true).await?
    else {
        return Ok(None);
    };
    // Each `seq` once: together with the counts below, every reference
    // of the live generation is then matched by exactly one placement.
    let distinct = placements.windows(2).all(|w| w[0].seq < w[1].seq);
    if live.size != g.size
        || live.etag != g.etag
        || usize::try_from(live.extent_count).ok() != Some(placements.len())
        || !distinct
    {
        return Ok(None);
    }
    let count = |rows: Vec<crate::ports::Row>| match rows.first().map(Vec::as_slice) {
        Some([SqlValue::Int(n)]) => {
            u64::try_from(*n).map_err(|_| BridgeError::Sql("row decode: twin count".into()))
        }
        _ => Err(BridgeError::Sql("row decode: twin count".into())),
    };
    let wanted = placements.len() as u64;
    let held = count(
        c.sql
            .query_after_refusal(COUNT_REPLAY_EXTENTS, &[text(live.id.as_str())])
            .await?,
    )?;
    if held != wanted {
        return Ok(None);
    }
    let mut same = 0u64;
    for value in super::publish::placement_values(placements, c.sql.limits())? {
        same += count(
            c.sql
                .query_after_refusal(
                    c.sql
                        .dialect()
                        .pick(COUNT_MATCHED_PLACEMENTS, COUNT_MATCHED_PLACEMENTS_PG),
                    &[text(live.id.as_str()), SqlValue::Text(value)],
                )
                .await?,
        )?;
    }
    Ok((same == wanted).then_some(live.id))
}

/// Whether the catalogue knows an older generation of the key of `g`,
/// live or not. `after_refusal`: the batch of the replay was just
/// refused, and the read goes through [`Sql::query_after_refusal`].
async fn has_older<S: Sql>(
    c: &SqlCatalog<S>,
    g: &GenerationRow,
    after_refusal: bool,
) -> Result<bool> {
    let sql = HAS_OLDER_GENERATION;
    let params = [
        text(g.bucket_id.as_str()),
        text(&g.key),
        text(g.id.as_str()),
    ];
    let older = if after_refusal {
        c.sql.query_after_refusal(sql, &params).await?
    } else {
        c.sql.query(sql, &params).await?
    };
    Ok(!older.is_empty())
}

/// Step 2. `Refused` = the generation is already there, a newer
/// generation of the key is live, or the extents do not tile it (one of
/// them is missing, in another bucket, still a part of an upload under
/// another generation's name, or its key was shredded). `Damaged` = the
/// catalogue knows an older generation of the key, live or not, and
/// this one cannot be read in full: a record that lingers from a write
/// that failed must not take the place of a good object, nor that of a
/// delete. The rule looks at rows that stay, not at what is live at the
/// moment, so a second replay over the same records decides the same:
/// tombstones are applied after the manifests, and the object that was
/// live when this generation was refused may be deleted by then.
pub(super) async fn replay_publish<S: Sql>(
    c: &SqlCatalog<S>,
    g: &GenerationRow,
    placements: &[ExtentPlacement],
    now: UnixMs,
) -> Result<ReplayPublish> {
    if g.state != GenerationState::Live
        || g.retired_at.is_some()
        || usize::try_from(g.extent_count).ok() != Some(placements.len())
    {
        return Err(BridgeError::Invalid(
            "replay does not describe one live generation",
        ));
    }
    // A packed plan that cannot be read is no plan, and the guard of
    // the batch below cannot tell: it sees a value. So it is asked
    // here, of the rows the batch will find (nothing else writes during
    // a replay), and only for a key that has an older generation: the
    // one case in which it decides.
    let limits = c.sql.limits();
    if has_older(c, g, false).await? && has_unread_extent(c, placements, limits).await? {
        return Ok(ReplayPublish::Damaged);
    }
    let values = super::publish::placement_values(placements, limits)?;
    let gen_id = || text(g.id.as_str());
    let bucket = || text(g.bucket_id.as_str());
    let mut stmts: Vec<Stmt> = Vec::with_capacity(12 + 2 * values.len());
    stmts.push((
        GUARD_REPLAY_NEW_GENERATION,
        vec![gen_id(), bucket(), text(&g.key)],
    ));
    stmts.push(clear_floor(&g.bucket_id, &g.key, &g.id));
    stmts.push(insert_live(g)?);
    // An extent no generation holds is adopted; one another generation
    // holds is shared with it (this generation is a copy of that one, or
    // that one of this) and gets a second reference. Two statements per
    // value of placements, not two per extent.
    stmts.extend(super::publish::adopt_in(
        c.sql.dialect(),
        &g.id,
        &g.bucket_id,
        super::publish::Source::Record,
        &values,
    ));
    // The referenced extents tile the object exactly, each with its key.
    stmts.push((
        GUARD_REPLAY_TILING,
        vec![
            gen_id(),
            SqlValue::Int(i64::from(g.extent_count)),
            uint(g.size)?,
        ],
    ));
    // A generation that cannot be read in full replaces nothing. On a
    // key without an older generation it is published, so that the key
    // answers with an error and not with "no such key".
    stmts.push((GUARD_DAMAGED_REPLAY, vec![gen_id(), bucket(), text(&g.key)]));
    // An extent whose pinned copy is held goes through post and verify
    // again: posting a planned article twice is harmless, and the read
    // back is the evidence a release needs. The obligation stays under
    // the generation the extent was first written for.
    stmts.push((
        c.sql
            .dialect()
            .pick(INSERT_REPLAY_OUTBOX, INSERT_REPLAY_OUTBOX_PG),
        vec![gen_id(), ms(now)],
    ));
    // A shared extent can have left service earlier in this replay: the
    // generation it was written for was retired by a manifest that sorts
    // before this one. It is back in service now, so its obligation runs
    // again, and the collection queued for it is called off below.
    // Nothing collects while a restore runs, so no delete is under way.
    stmts.push((REARM_REPLAY_OUTBOX, vec![gen_id(), ms(now)]));
    // Its open GC rows are closed: they were queued for a retirement
    // that this reference undoes. When the extent really leaves service,
    // the retirement that takes its last reference queues fresh rows.
    stmts.push((CLOSE_REPLAY_GC, vec![gen_id(), ms(now)]));
    stmts.extend(retire_live_in(
        c.sql.dialect(),
        &g.bucket_id,
        &g.key,
        GenerationState::Superseded,
        now,
    ));
    stmts.push((
        SET_REPLAY_LIVE_POINTER,
        vec![bucket(), text(&g.key), gen_id()],
    ));
    match c.sql.batch(stmts).await {
        Ok(_) => Ok(ReplayPublish::Published),
        Err(BridgeError::GuardFailed) => {
            // Which guard refused it. Nothing else writes during a
            // replay, so the catalogue is as the batch found it.
            if has_older(c, g, true).await? && has_lost_extent(c, &values).await? {
                Ok(ReplayPublish::Damaged)
            } else {
                Ok(ReplayPublish::Refused)
            }
        }
        Err(e) => Err(e),
    }
}

/// The row of `g` as the live generation it describes.
fn insert_live(g: &GenerationRow) -> Result<Stmt> {
    Ok((
        INSERT_REPLAY_GENERATION,
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

const FENCE_CLAIMS_PG: &str =
    "UPDATE outbox SET lease_token = lease_token + 1, lease_owner = NULL, lease_until = NULL, \
       cursor = CASE stage WHEN 'verify' THEN 0 ELSE cursor END \
     WHERE extent_id = ?1 \
       AND EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND plan = ?2 \
         AND parity IS NOT DISTINCT FROM ?3 AND parity_count IS NOT DISTINCT FROM ?4::bigint)";

const INSERT_BUCKET: &str =
    "INSERT OR IGNORE INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, \
           created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)";

const INSERT_BUCKET_PG: &str =
    "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, \
           created_at) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT DO NOTHING";

const INSERT_ARTICLE: &str =
    "INSERT OR IGNORE INTO articles(extent_id, idx, message_id, newsgroup, headers, \
           cipher_offset, cipher_len, payload_sha256, yenc_name, state) \
           SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 \
           WHERE (SELECT plan FROM extents WHERE id = ?1) IS NULL";

const INSERT_ARTICLE_PG: &str =
    "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, \
           cipher_offset, cipher_len, payload_sha256, yenc_name, state) \
           SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 \
           WHERE (SELECT plan FROM extents WHERE id = ?1) IS NULL ON CONFLICT DO NOTHING";

const INSERT_EXTENT: &str =
    "INSERT OR IGNORE INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
           plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, \
           plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, created_at) \
         VALUES (?1,?2,NULL,'staged',NULL,NULL,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13)";

const INSERT_EXTENT_PG: &str = "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
           plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, \
           plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, created_at) \
         VALUES (?1,?2,NULL,'staged',NULL,NULL,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13) ON CONFLICT DO NOTHING";

const DROP_PASSES_FOR_SWAP: &str = "DELETE FROM verifications WHERE extent_id = ?1 \
                   AND EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND plan = ?2 \
                     AND parity IS NOT ?3)";

const DROP_PASSES_FOR_SWAP_PG: &str = "DELETE FROM verifications WHERE extent_id = ?1 \
                   AND EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND plan = ?2 \
                     AND parity IS DISTINCT FROM ?3)";

const FENCE_CLAIMS_FOR_SWAP: &str =
    "UPDATE outbox SET lease_token = lease_token + 1, lease_owner = NULL, \
                   lease_until = NULL, \
                   cursor = CASE stage WHEN 'verify' THEN 0 ELSE cursor END \
                 WHERE extent_id = ?1 \
                   AND EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND plan = ?2 \
                     AND parity IS NOT ?3)";

const FENCE_CLAIMS_FOR_SWAP_PG: &str =
    "UPDATE outbox SET lease_token = lease_token + 1, lease_owner = NULL, \
                   lease_until = NULL, \
                   cursor = CASE stage WHEN 'verify' THEN 0 ELSE cursor END \
                 WHERE extent_id = ?1 \
                   AND EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND plan = ?2 \
                     AND parity IS DISTINCT FROM ?3)";

const DROP_PASSES_FOR_ADDENDUM: &str = "DELETE FROM verifications WHERE extent_id = ?1 \
                   AND EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND plan = ?2 \
                     AND parity IS ?3 AND quote(parity_count) = ?4)";

const DROP_PASSES_FOR_ADDENDUM_PG: &str = "DELETE FROM verifications WHERE extent_id = ?1 \
                   AND EXISTS (SELECT 1 FROM extents WHERE id = ?1 AND plan = ?2 \
                     AND parity IS NOT DISTINCT FROM ?3 AND parity_count IS NOT DISTINCT FROM ?4::bigint)";

const REPLACE_ADDENDUM: &str = "UPDATE extents SET parity = ?5, parity_count = ?6 \
                 WHERE id = ?1 AND plan = ?2 AND parity IS ?3 AND quote(parity_count) = ?4";

const REPLACE_ADDENDUM_PG: &str = "UPDATE extents SET parity = ?5, parity_count = ?6 \
                 WHERE id = ?1 AND plan = ?2 AND parity IS NOT DISTINCT FROM ?3 AND parity_count IS NOT DISTINCT FROM ?4::bigint";

fn unreadable_plan_sql(dialect: crate::ports::Dialect, arity: usize) -> String {
    let marks = vec!["?"; arity].join(",");
    match dialect {
        crate::ports::Dialect::Sqlite => format!(
            "SELECT id, cipher_size, plan, parity, \
                       CASE WHEN typeof(parity_count) = 'real' \
                           OR (typeof(parity_count) = 'integer' \
                             AND parity_count NOT BETWEEN 0 AND 4294967295) \
                         THEN quote(parity_count) ELSE parity_count END, \
                       quote(parity_count) \
                     FROM extents WHERE id IN ({marks}) AND plan IS NOT NULL"
        ),
        crate::ports::Dialect::Postgres => format!(
            "SELECT id, cipher_size, plan, parity, \
            parity_count, parity_count FROM extents WHERE id IN ({marks}) AND plan IS NOT NULL"
        ),
    }
}

const GUARD_REPLAY_RUN: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
                   (SELECT started_at FROM restore_state WHERE id = 1) IS NOT ?1";

const GUARD_REPLAY_RUN_PG: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
                   (SELECT started_at FROM restore_state WHERE id = 1) IS DISTINCT FROM ?1";

const LEVEL_STAMP: &str = "INSERT INTO rollback_stamp(id, counter, catalogue_id, rolled_back_at) \
                 SELECT 1, ?1, ?3, NULL WHERE EXISTS (SELECT 1 FROM restore_state \
                   WHERE id = 1 AND started_at = ?2 AND state = 'replaying') \
                   AND (SELECT counter FROM rollback_stamp WHERE id = 1) IS ?4 \
                 ON CONFLICT(id) DO UPDATE SET \
                   counter = max(counter, excluded.counter), rolled_back_at = NULL";

const LEVEL_STAMP_PG: &str = "INSERT INTO rollback_stamp(id, counter, catalogue_id, rolled_back_at) \
                 SELECT 1, ?1, ?3, NULL WHERE EXISTS (SELECT 1 FROM restore_state \
                   WHERE id = 1 AND started_at = ?2 AND state = 'replaying') \
                   AND (SELECT counter FROM rollback_stamp WHERE id = 1) IS NOT DISTINCT FROM ?4 \
                 ON CONFLICT(id) DO UPDATE SET \
                   counter = GREATEST(rollback_stamp.counter, excluded.counter), rolled_back_at = NULL";

macro_rules! damaged {
    () => {
        "FROM objects o WHERE EXISTS (SELECT 1 FROM generation_extents ge \
         JOIN extents e ON e.id = ge.extent_id \
         WHERE ge.generation_id = o.generation_id AND e.safety_state = 'deleted' \
           AND e.plan IS NULL \
           AND NOT EXISTS (SELECT 1 FROM articles a WHERE a.extent_id = e.id))"
    };
}

const COUNT_DAMAGED: &str = concat!("SELECT COUNT(*) ", damaged!());
const LIST_DAMAGED: &str = concat!(
    "SELECT o.generation_id ",
    damaged!(),
    " ORDER BY o.generation_id LIMIT ?1"
);

const UNREAD_PLAN_SIZES: &str = "SELECT e.id, length(e.plan) FROM json_each(?1) j \
                   CROSS JOIN extents e ON e.id = json_extract(j.value,'$[0]') \
                  WHERE +e.safety_state = 'deleted' AND e.plan IS NOT NULL";

const UNREAD_PLAN_SIZES_PG: &str =
    "SELECT e.id, octet_length(e.plan) FROM jsonb_array_elements(?1::jsonb) AS j(value) \
                   JOIN extents e ON e.id = (j.value->>0) \
                  WHERE e.safety_state = 'deleted' AND e.plan IS NOT NULL";

const UNREAD_PLAN_VALUES: &str = "SELECT e.id, e.cipher_size, e.plan FROM json_each(?1) j \
                       CROSS JOIN extents e ON e.id = j.value \
                      WHERE +e.safety_state = 'deleted' AND e.plan IS NOT NULL";

const UNREAD_PLAN_VALUES_PG: &str =
    "SELECT e.id, e.cipher_size, e.plan FROM jsonb_array_elements_text(?1::jsonb) AS j(value) \
                       JOIN extents e ON e.id = j.value \
                      WHERE e.safety_state = 'deleted' AND e.plan IS NOT NULL";

const COUNT_MATCHED_PLACEMENTS: &str =
    "SELECT COUNT(*) FROM json_each(?2) j CROSS JOIN generation_extents ge \
                         ON ge.generation_id = ?1 AND ge.seq = json_extract(j.value,'$[1]') \
                      WHERE ge.extent_id = json_extract(j.value,'$[0]') \
                        AND ge.plain_offset = json_extract(j.value,'$[2]')";

const COUNT_MATCHED_PLACEMENTS_PG: &str =
    "SELECT COUNT(*) FROM jsonb_array_elements(?2::jsonb) AS j(value) JOIN generation_extents ge \
                         ON ge.generation_id = ?1 AND ge.seq = (j.value->>1)::bigint \
                      WHERE ge.extent_id = (j.value->>0) \
                        AND ge.plain_offset = (j.value->>2)::bigint";

macro_rules! no_copy {
    () => {
        "e.safety_state = 'deleted' AND e.plan IS NULL \
     AND NOT EXISTS (SELECT 1 FROM articles a WHERE a.extent_id = e.id)"
    };
}

const EXTENT_HAS_NO_COPY: &str = concat!(
    "SELECT 1 FROM json_each(?1) j \
                       CROSS JOIN extents e ON e.id = json_extract(j.value,'$[0]') \
                      WHERE ",
    no_copy!(),
    " LIMIT 1"
);
const EXTENT_HAS_NO_COPY_PG: &str = concat!(
    "SELECT 1 FROM jsonb_array_elements(?1::jsonb) AS j(value) \
                       JOIN extents e ON e.id = (j.value->>0) \
                      WHERE ",
    no_copy!(),
    " LIMIT 1"
);

const INSERT_REPLAY_OUTBOX: &str =
    "INSERT OR IGNORE INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
         SELECT e.id, e.generation_id, \
                CASE e.safety_state WHEN 'held' THEN 'post' ELSE 'done' END, ?2, ?2 \
           FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
          WHERE ge.generation_id = ?1";

const INSERT_REPLAY_OUTBOX_PG: &str =
    "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
         SELECT e.id, e.generation_id, \
                CASE e.safety_state WHEN 'held' THEN 'post' ELSE 'done' END, ?2, ?2 \
           FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
          WHERE ge.generation_id = ?1 ON CONFLICT DO NOTHING";

const REPLAY_PROBE: &str = "SELECT (SELECT COUNT(*) FROM generations WHERE id = ?1), \
                    (SELECT COUNT(*) FROM objects WHERE bucket_id = ?2 AND key = ?3 \
                       AND generation_id > ?1)";

const RESTORE_PACKED_PLAN: &str =
    "UPDATE extents SET article_count = ?2, plan_rev = ?3, plan = ?4, \
                   parity = ?5, parity_count = ?6 \
                 WHERE id = ?1 AND plan IS NULL \
                   AND NOT EXISTS (SELECT 1 FROM articles WHERE extent_id = ?1)";

const RESTORE_UNPACKED_COUNT: &str = "UPDATE extents SET article_count = ?2, plan_rev = ?3 \
                 WHERE id = ?1 AND article_count IS NULL";

const SET_ABSENT_SAFETY: &str =
    "UPDATE extents SET safety_state = 'deleted', evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND safety_state IN ('held', 'releasing')";

const TERMINATE_ABSENT_OUTBOX: &str = "UPDATE outbox SET stage = 'done', lease_owner = NULL, lease_until = NULL, \
               sent_at = NULL, updated_at = ?2 WHERE extent_id = ?1 AND stage IN ('post', 'verify', 'release')";

const RESTORE_ARTICLES_POSTED: &str =
    "UPDATE articles SET state = 'posted' WHERE extent_id = ?1 AND state = 'planned'";

const RESTORE_EXTENT_POSTED: &str = "UPDATE extents SET posted_at = ?2 \
             WHERE id = ?1 AND plan IS NOT NULL AND posted_at IS NULL";

const REPLACE_UNREADABLE_PLAN: &str =
    "UPDATE extents SET article_count = ?2, plan_rev = ?3, plan = ?4, \
                   parity = ?6, parity_count = ?7 \
                 WHERE id = ?1 AND plan = ?5";

const REPLAY_HELD_PAGE: &str =
    "SELECT id FROM extents WHERE id > ?1 AND safety_state IN ('held', 'releasing') \
             ORDER BY id LIMIT ?2";

const REPLAY_STATE: &str =
    "SELECT started_at, state = 'complete', since_ms FROM restore_state WHERE id = 1";

const GUARD_REPLAY_WINDOW: &str =
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS (SELECT 1 FROM restore_state \
                   WHERE id = 1 AND state <> 'complete' AND since_ms >= 0 AND ?1 > since_ms)";

const PRUNE_WRITE_INTENTS: &str = "DELETE FROM write_intents WHERE NOT \
                   (state = 'kept' AND generation_id IS NOT NULL AND generation_id <= ?1)";

const ARM_REPLAY: &str = "INSERT INTO restore_state(id, state, since_ms, started_at, finished_at) \
                 VALUES (1, 'replaying', ?1, ?2, NULL) \
                 ON CONFLICT(id) DO UPDATE SET state = 'replaying', since_ms = excluded.since_ms, \
                   started_at = excluded.started_at, \
                   finished_at = NULL, reached_phase = NULL, reached_after = NULL, \
                   reached_extent = NULL";

const FINISH_REPLAY_STATE: &str = "UPDATE restore_state SET state = 'complete', \
                   finished_at = COALESCE(finished_at, ?1) \
                 WHERE id = 1 AND started_at = ?2 AND (state = 'complete' OR EXISTS \
                   (SELECT 1 FROM rollback_stamp WHERE id = 1 AND counter >= ?3 \
                    AND rolled_back_at IS NULL))";

const READ_STAMP: &str = "SELECT counter, rolled_back_at IS NOT NULL, catalogue_id = ?1 \
             FROM rollback_stamp WHERE id = 1";

const SEED_STAMP: &str = "INSERT INTO rollback_stamp(id, counter, catalogue_id) VALUES (1, 1, ?1) \
                     ON CONFLICT(id) DO NOTHING";

const ADVANCE_STAMP: &str = "UPDATE rollback_stamp SET counter = counter + 1 \
                     WHERE id = 1 AND counter = ?1 AND rolled_back_at IS NULL";

const SEED_ROLLBACK_MARK: &str =
    "INSERT INTO rollback_stamp(id, counter, catalogue_id, rolled_back_at) \
                     VALUES (1, 0, ?2, ?1) ON CONFLICT(id) DO NOTHING";

const MARK_ROLLBACK: &str = "UPDATE rollback_stamp SET rolled_back_at = ?1 \
                     WHERE id = 1 AND counter = ?2 AND rolled_back_at IS NULL";

const REPLAY_ACTIVE: &str =
    "SELECT (SELECT COUNT(*) FROM restore_state WHERE state <> 'complete') \
                  + (SELECT COUNT(*) FROM rollback_stamp \
                     WHERE id = 1 AND rolled_back_at IS NOT NULL)";

const GUARD_NO_REPLAY: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS \
           (SELECT 1 FROM restore_state WHERE id = 1 AND state <> 'complete') \
           OR EXISTS (SELECT 1 FROM rollback_stamp WHERE id = 1 AND rolled_back_at IS NOT NULL)";

const REPLAY_PROGRESS: &str =
    "SELECT since_ms, reached_phase, reached_after, reached_extent, state = 'complete' \
             FROM restore_state WHERE id = 1 AND started_at = ?1";

const ADVANCE_REPLAY_PROGRESS: &str =
    "UPDATE restore_state SET reached_phase = ?2, reached_after = ?3, reached_extent = ?4 \
             WHERE id = 1 AND started_at = ?1 AND (reached_phase IS NULL \
               OR (reached_phase, reached_after, reached_extent) < (?2, ?3, ?4))";

const COUNT_REPLAY_EXTENTS: &str =
    "SELECT COUNT(*) FROM generation_extents WHERE generation_id = ?1";

const HAS_OLDER_GENERATION: &str = "SELECT 1 FROM generations WHERE bucket_id = ?1 AND key = ?2 \
               AND id < ?3 LIMIT 1";

const GUARD_REPLAY_NEW_GENERATION: &str =
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS (SELECT 1 FROM generations WHERE id = ?1) \
         OR EXISTS (SELECT 1 FROM objects WHERE bucket_id = ?2 AND key = ?3 \
                    AND generation_id > ?1)";

const GUARD_REPLAY_TILING: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
           (SELECT COUNT(*) FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
             WHERE ge.generation_id = ?1 AND e.wrapped_file_key IS NOT NULL) <> ?2 \
           OR (SELECT COALESCE(SUM(e.plain_size), 0) FROM generation_extents ge \
                 JOIN extents e ON e.id = ge.extent_id WHERE ge.generation_id = ?1) <> ?3 \
           OR EXISTS (SELECT 1 FROM (SELECT ge.plain_offset AS plain_offset, \
                SUM(e.plain_size) OVER (ORDER BY ge.seq \
                ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS expected \
                FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
               WHERE ge.generation_id = ?1) \
              WHERE plain_offset <> COALESCE(expected, 0))";

const GUARD_DAMAGED_REPLAY: &str =
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS (SELECT 1 FROM generations \
           WHERE bucket_id = ?2 AND key = ?3 AND id < ?1) \
         AND EXISTS (SELECT 1 FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
          WHERE ge.generation_id = ?1 AND e.safety_state = 'deleted' AND e.plan IS NULL \
            AND NOT EXISTS (SELECT 1 FROM articles a WHERE a.extent_id = e.id))";

const REARM_REPLAY_OUTBOX: &str = "UPDATE outbox SET stage = CASE (SELECT e.safety_state FROM extents e \
                                          WHERE e.id = outbox.extent_id) \
                                   WHEN 'held' THEN 'post' WHEN 'releasing' THEN 'release' \
                                   ELSE 'done' END, \
                attempts = 0, cursor = 0, last_error = NULL, next_at = ?2, updated_at = ?2, \
                sent_at = NULL, lease_token = lease_token + 1, lease_owner = NULL, lease_until = NULL \
          WHERE stage = 'cancelled' AND extent_id IN \
                (SELECT extent_id FROM generation_extents WHERE generation_id = ?1)";

const CLOSE_REPLAY_GC: &str = "UPDATE gc SET done_at = ?2 WHERE done_at IS NULL AND extent_id IN \
                (SELECT extent_id FROM generation_extents WHERE generation_id = ?1)";

const SET_REPLAY_LIVE_POINTER: &str =
    "INSERT INTO objects(bucket_id, key, generation_id) VALUES (?1, ?2, ?3) \
         ON CONFLICT(bucket_id, key) DO UPDATE SET generation_id = excluded.generation_id";

const INSERT_REPLAY_GENERATION: &str =
    "INSERT INTO generations(id, bucket_id, key, state, size, etag, checksum_json, \
           content_json, user_meta_json, extent_count, created_at, retired_at) \
         VALUES (?1,?2,?3,'live',?4,?5,?6,?7,?8,?9,?10,NULL)";

/// Actual Postgres texts and representative wire types for typed PREPARE.
#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(String, Vec<SqlValue>)> {
    const I: SqlValue = SqlValue::Int(0);
    const T: SqlValue = SqlValue::Text(String::new());
    const B: SqlValue = SqlValue::Blob(Vec::new());
    let mut statements = vec![
        (FENCE_CLAIMS_PG.to_owned(), vec![T, B, B, I]),
        (INSERT_BUCKET_PG.to_owned(), vec![T, T, T, B, I, I, I]),
        (
            INSERT_ARTICLE_PG.to_owned(),
            vec![T, I, T, T, B, I, I, B, T, T],
        ),
        (
            INSERT_EXTENT_PG.to_owned(),
            vec![T, T, I, I, B, I, B, B, B, B, T, I, I],
        ),
        (DROP_PASSES_FOR_SWAP_PG.to_owned(), vec![T, B, B]),
        (FENCE_CLAIMS_FOR_SWAP_PG.to_owned(), vec![T, B, B]),
        (DROP_PASSES_FOR_ADDENDUM_PG.to_owned(), vec![T, B, B, I]),
        (REPLACE_ADDENDUM_PG.to_owned(), vec![T, B, B, I, B, I]),
        (GUARD_REPLAY_RUN_PG.to_owned(), vec![I]),
        (LEVEL_STAMP_PG.to_owned(), vec![I, I, T, I]),
        (COUNT_DAMAGED.to_owned(), vec![]),
        (LIST_DAMAGED.to_owned(), vec![I]),
        (UNREAD_PLAN_SIZES_PG.to_owned(), vec![T]),
        (UNREAD_PLAN_VALUES_PG.to_owned(), vec![T]),
        (COUNT_MATCHED_PLACEMENTS_PG.to_owned(), vec![T, T]),
        (EXTENT_HAS_NO_COPY_PG.to_owned(), vec![T]),
        (INSERT_REPLAY_OUTBOX_PG.to_owned(), vec![T, I]),
        (REPLAY_PROBE.to_owned(), vec![T, T, T]),
        (RESTORE_PACKED_PLAN.to_owned(), vec![T, I, I, B, B, I]),
        (RESTORE_UNPACKED_COUNT.to_owned(), vec![T, I, I]),
        (SET_ABSENT_SAFETY.to_owned(), vec![T]),
        (TERMINATE_ABSENT_OUTBOX.to_owned(), vec![T, I]),
        (RESTORE_ARTICLES_POSTED.to_owned(), vec![T]),
        (RESTORE_EXTENT_POSTED.to_owned(), vec![T, I]),
        (
            REPLACE_UNREADABLE_PLAN.to_owned(),
            vec![T, I, I, B, B, B, I],
        ),
        (REPLAY_HELD_PAGE.to_owned(), vec![T, I]),
        (REPLAY_STATE.to_owned(), vec![]),
        (GUARD_REPLAY_WINDOW.to_owned(), vec![I]),
        (PRUNE_WRITE_INTENTS.to_owned(), vec![T]),
        (ARM_REPLAY.to_owned(), vec![I, I]),
        (FINISH_REPLAY_STATE.to_owned(), vec![I, I, I]),
        (READ_STAMP.to_owned(), vec![T]),
        (SEED_STAMP.to_owned(), vec![T]),
        (ADVANCE_STAMP.to_owned(), vec![I]),
        (SEED_ROLLBACK_MARK.to_owned(), vec![I, T]),
        (MARK_ROLLBACK.to_owned(), vec![I, I]),
        (REPLAY_ACTIVE.to_owned(), vec![]),
        (GUARD_NO_REPLAY.to_owned(), vec![]),
        (REPLAY_PROGRESS.to_owned(), vec![I]),
        (ADVANCE_REPLAY_PROGRESS.to_owned(), vec![I, I, T, I]),
        (COUNT_REPLAY_EXTENTS.to_owned(), vec![T]),
        (HAS_OLDER_GENERATION.to_owned(), vec![T, T, T]),
        (GUARD_REPLAY_NEW_GENERATION.to_owned(), vec![T, T, T]),
        (GUARD_REPLAY_TILING.to_owned(), vec![T, I, I]),
        (GUARD_DAMAGED_REPLAY.to_owned(), vec![T, T, T]),
        (REARM_REPLAY_OUTBOX.to_owned(), vec![T, I]),
        (CLOSE_REPLAY_GC.to_owned(), vec![T, I]),
        (SET_REPLAY_LIVE_POINTER.to_owned(), vec![T, T, T]),
        (
            INSERT_REPLAY_GENERATION.to_owned(),
            vec![T, T, T, I, T, T, T, T, I, I],
        ),
    ];
    statements.extend((1..=LOST_CHUNK).map(|arity| {
        (
            unreadable_plan_sql(crate::ports::Dialect::Postgres, arity),
            vec![T; arity],
        )
    }));
    statements
}
