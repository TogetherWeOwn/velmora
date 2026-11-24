//! Outbox leases with fencing tokens, article plans, verification and release (catalogue lane B).
//!
//! `claim` bumps `outbox.lease_token` and hands it out in a [`Lease`].
//! Every later write names the row by extent, generation, stage **and**
//! token, so it changes nothing once the row was cancelled, advanced or
//! claimed by someone else. Giving a lease up (`advance`, `fail`, `defer`,
//! `finish_release`) bumps the token as well: a released lease is dead.
//! Writes that touch more than one table are batches with that predicate
//! as their `tx_guard`.

use core::fmt::Write as _;

use super::uploads::{int, ms, text, Cols, Stmt};
use super::SqlCatalog;
use crate::plan::{PackReport, StoredPlan};
use crate::ports::{Guard, Lease, Permit, Sql, SqlValue, VerifyRecord, LEASE_SECS};
use crate::types::{
    ArticleRow, ArticleState, BackboneStatus, BridgeError, Bucket, BucketId, DueRow, ExtentId,
    ExtentRow, ExtentState, FailClass, GenerationId, GenerationState, JobExtent, OutboxStage,
    OutboxStats, Resend, Result, SafetyState, UnixMs, VerificationRow, VerifyEscalation,
    VerifyKind, VerifyResult,
};

/// Lease length. Jobs renew on a timer and before each read article.
const LEASE_MS: i64 = LEASE_SECS as i64 * 1000;

// `outbox.updated_at` is the time of the row's last lease transition
// (claim, advance, fail, defer, done, cancel). `renew` and `set_cursor`
// leave it alone, so under a held lease it is the claim time. The release
// guard does not tell this job's verifications from older ones by it: two
// claims can fall in one millisecond. Each row carries the token of the
// lease it was recorded under (`verifications.lease_token`), and the
// guard counts those of the token that releases.

/// The row a lease names; parameters `?1..?4` are [`lease_params`].
macro_rules! held {
    () => {
        "extent_id = ?1 AND generation_id = ?2 AND stage = ?3 AND lease_token = ?4"
    };
}

/// `tx_guard` that fires unless the lease still holds its row.
macro_rules! held_guard {
    () => {
        concat!(
            "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE ",
            held!(),
            ")"
        )
    };
}

/// Gives the lease up: the token moves on, so the old lease is dead.
macro_rules! unlease {
    () => {
        "lease_token = lease_token + 1, lease_owner = NULL, lease_until = NULL"
    };
}

/// The one verification row that speaks for its backbone: the latest for
/// the extent's current plan (`v` = verifications, `e` = its extent).
macro_rules! latest {
    () => {
        "v.plan_rev = e.plan_rev AND v.verified_at = (SELECT MAX(w.verified_at) \
           FROM verifications w WHERE w.extent_id = v.extent_id AND w.backbone = v.backbone \
             AND w.plan_rev = e.plan_rev)"
    };
}

/// The articles a row found: read back and matching for a `body` row,
/// present for a `stat` row. A `stat` row keeps `articles_ok` at 0, so a
/// reader from before `kind` never takes it for a read-back.
macro_rules! tally {
    () => {
        "(CASE v.kind WHEN 'stat' THEN v.articles_present ELSE v.articles_ok END)"
    };
}

/// How many articles the plan of extent `e` has: its data articles and
/// the parity articles of its addendum. NULL = no plan.
macro_rules! total {
    () => {
        "(e.article_count + COALESCE(e.parity_count, 0))"
    };
}

/// Whether that row is a complete pass of its kind for the current plan:
/// of every article of it, the parity articles included ([`total`]). A
/// pass that left them out is not one.
///
/// A pass is bound to the plan revision and to this number, not to the
/// addendum itself. That holds because the addendum of a plan never
/// changes once it is stored. Code that writes another addendum on an
/// extent that has one must delete the extent's `verifications` in the
/// same batch (or bind the passes to the revision of the addendum):
/// otherwise a pass over other parity articles would count for these.
macro_rules! counts {
    () => {
        concat!(
            "(v.result = 'ok' AND ",
            tally!(),
            " = v.articles_total AND v.articles_total = COALESCE(",
            total!(),
            ", -1))"
        )
    };
}

/// Whether the last check of the bytes on the backbone of row `v`
/// failed, for the current plan of extent `e`: a full read (`body` row)
/// that is not a complete pass, or a size check that found an article of
/// the wrong size (`mode = 'size'`, `corrupt`), with no full read after
/// it. A `STAT` answer, or a later size that fits, says nothing about
/// bytes that were found missing or wrong, so such a backbone holds no
/// copy until it is read in full again.
///
/// A full read of fewer articles than the plan has ([`total`]) is not a
/// complete pass either, whatever it found: a version from before
/// parity reads the data articles alone, and such a read says nothing
/// of a parity article that an earlier read found missing or wrong.
macro_rules! body_failed {
    () => {
        concat!(
            "EXISTS (SELECT 1 FROM verifications f \
               WHERE f.extent_id = v.extent_id AND f.backbone = v.backbone \
                 AND f.plan_rev = e.plan_rev \
                 AND ((f.kind = 'body' \
                       AND (f.result <> 'ok' OR f.articles_ok <> f.articles_total \
                         OR f.articles_total <> COALESCE(",
            total!(),
            ", -1))) \
                   OR (f.mode = 'size' AND f.result = 'corrupt')) \
                 AND NOT EXISTS (SELECT 1 FROM verifications g \
                   WHERE g.extent_id = f.extent_id AND g.backbone = f.backbone \
                     AND g.plan_rev = f.plan_rev AND g.kind = 'body' \
                     AND g.verified_at > f.verified_at))"
        )
    };
}

/// A row that is evidence for the release of extent `?1` at `?6`: the one
/// that speaks for a backbone in the list `?7`, a complete pass, recorded
/// under the claim of lease token `?4` (the guard checks that the lease
/// holds the outbox row), on a backbone whose last full read did not fail
/// ([`body_failed`]). The token, not the time, names the claim: a claim
/// made in the millisecond an earlier one recorded a pass and gave the
/// row up would count that pass by its time. The claim time only bounds
/// the range of the key that is read: the job that holds the claim stamps
/// its rows after it.
macro_rules! fresh_pass {
    ($backbones:literal) => {
        concat!(
            "v.extent_id = ?1 AND v.verified_at <= ?6 AND v.lease_token = ?4 \
               AND v.verified_at >= (SELECT updated_at FROM outbox WHERE extent_id = ?1) \
               AND v.backbone IN (",
            $backbones,
            ") AND ",
            counts!(),
            " AND ",
            latest!(),
            " AND NOT ",
            body_failed!()
        )
    };
}

/// The full check on record for a backbone: row `b` is a complete `body`
/// pass of the current plan of its extent `e`, and no later check of that
/// backbone for that plan was another `body` or failed. So there is at
/// most one per backbone, a later `stat` pass leaves it standing, and a
/// plan that changed has none until it is read in full again.
macro_rules! body_on_record {
    () => {
        concat!(
            "b.plan_rev = e.plan_rev AND b.kind = 'body' AND b.result = 'ok' \
               AND b.articles_ok = b.articles_total \
               AND b.articles_total = COALESCE(",
            total!(),
            ", -1) \
               AND NOT EXISTS (SELECT 1 FROM verifications x \
                 WHERE x.extent_id = b.extent_id AND x.backbone = b.backbone \
                   AND x.plan_rev = b.plan_rev AND x.verified_at > b.verified_at \
                   AND (x.kind = 'body' OR x.result <> 'ok'))"
        )
    };
}

fn lease_params(l: &Lease, extra: impl IntoIterator<Item = SqlValue>) -> Result<Vec<SqlValue>> {
    let mut p = vec![
        text(l.extent.as_str()),
        text(l.generation.as_str()),
        text(l.stage.as_str()),
        int(l.token)?,
    ];
    p.extend(extra);
    Ok(p)
}

/// One fenced statement: `false` when the lease no longer holds the row.
async fn fenced<S: Sql>(
    c: &SqlCatalog<S>,
    sql: &str,
    l: &Lease,
    extra: impl IntoIterator<Item = SqlValue>,
) -> Result<bool> {
    Ok(c.sql.exec(sql, &lease_params(l, extra)?).await? > 0)
}

/// A batch led by a `tx_guard`: `false` when the guard fired.
async fn fenced_batch<S: Sql>(c: &SqlCatalog<S>, stmts: Vec<Stmt>) -> Result<bool> {
    Ok(super::uploads::guarded(c, stmts).await? == Guard::Applied(()))
}

// ---------------------------------------------------------------------------
// Lease lifecycle
// ---------------------------------------------------------------------------

/// Claims a due, unleased row in exactly this stage. `None`: duplicate
/// delivery, backoff not yet due, leased, cancelled or already advanced.
pub(super) async fn claim<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    generation: &GenerationId,
    stage: OutboxStage,
    owner: &str,
    now: UnixMs,
) -> Result<Option<Lease>> {
    if !matches!(
        stage,
        OutboxStage::Post | OutboxStage::Verify | OutboxStage::Release
    ) {
        return Ok(None);
    }
    let rows = c
        .sql
        .query(
            CLAIM,
            &[
                text(extent.as_str()),
                text(generation.as_str()),
                text(stage.as_str()),
                text(owner),
                ms(now.plus_ms(LEASE_MS)),
                ms(now),
            ],
        )
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let mut r = Cols::new(row);
    Ok(Some(Lease {
        extent: extent.clone(),
        generation: generation.clone(),
        stage,
        token: r.num()?,
        attempts: r.num()?,
        cursor: r.num()?,
        claimed_at: now,
    }))
}

const RENEW: &str = concat!("UPDATE outbox SET lease_until = ?5 WHERE ", held!());

pub(super) async fn renew<S: Sql>(c: &SqlCatalog<S>, l: &Lease, now: UnixMs) -> Result<bool> {
    fenced(c, RENEW, l, [ms(now.plus_ms(LEASE_MS))]).await
}

/// [`renew`] and one permit renewal per permit, as one batch. No guard:
/// every statement is fenced by its own token, so each result stands
/// alone.
pub(super) async fn renew_all<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    permits: &[Permit],
    now: UnixMs,
) -> Result<(bool, Vec<bool>)> {
    let mut stmts: Vec<Stmt> = Vec::with_capacity(permits.len() + 1);
    stmts.push((RENEW, lease_params(l, [ms(now.plus_ms(LEASE_MS))])?));
    for p in permits {
        stmts.push(super::permits::renew_stmt(p, now)?);
    }
    let changed = c.sql.batch(stmts).await?;
    if changed.len() != permits.len() + 1 {
        return Err(BridgeError::Sql("renewal batch result count".into()));
    }
    Ok((
        changed[0] > 0,
        changed[1..].iter().map(|n| *n > 0).collect(),
    ))
}

/// Moves the row to `to` and gives the lease up. Attempts and cursor
/// restart: they are per stage.
///
/// The caller sends the job of a stage that has work (`post`, `verify`,
/// `release`) itself, so the same write marks the row as sent for its
/// new due time (`sent_at = next_at`, see [`due`]); the caller takes the
/// mark back if that send fails ([`unmark_sent`]). The mark is the due
/// time and not the time of the send, because a mark older than the due
/// time is outdated. A row that moves to an end stage keeps no mark.
pub(super) async fn advance<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    to: OutboxStage,
    next_at: UnixMs,
    now: UnixMs,
) -> Result<bool> {
    let sql = ADVANCE;
    fenced(c, sql, l, [text(to.as_str()), ms(next_at), ms(now)]).await
}

pub(super) async fn fail<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    class: FailClass,
    next_at: UnixMs,
    now: UnixMs,
) -> Result<bool> {
    let sql = FAIL;
    fenced(c, sql, l, [ms(next_at), text(class.as_str()), ms(now)]).await
}

/// Like `fail`, but hands back the attempt the claim counted.
pub(super) async fn defer<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    next_at: UnixMs,
    now: UnixMs,
) -> Result<bool> {
    let sql = c.sql.dialect().pick(DEFER, DEFER_PG);
    fenced(c, sql, l, [ms(next_at), ms(now)]).await
}

pub(super) async fn defer_at<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    cursor: u32,
    next_at: UnixMs,
    now: UnixMs,
) -> Result<bool> {
    let sql = c
        .sql
        .dialect()
        .pick(DEFER_WITH_CURSOR, DEFER_WITH_CURSOR_PG);
    let cursor = SqlValue::Int(i64::from(cursor));
    fenced(c, sql, l, [ms(next_at), ms(now), cursor]).await
}

pub(super) async fn set_cursor<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    cursor: u32,
    _now: UnixMs,
) -> Result<bool> {
    let sql = SET_CURSOR;
    fenced(c, sql, l, [SqlValue::Int(i64::from(cursor))]).await
}

// ---------------------------------------------------------------------------
// Job reads
// ---------------------------------------------------------------------------

pub(super) async fn job_extent<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    generation: &GenerationId,
) -> Result<Option<JobExtent>> {
    // The extent is in service while any live generation references it,
    // not only the one it was written for (which the outbox row names).
    let sql = JOB_EXTENT;
    let rows = c
        .sql
        .query(sql, &[text(extent.as_str()), text(generation.as_str())])
        .await?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let mut r = Cols::new(row);
    let extent = ExtentRow {
        id: ExtentId::new(r.text()?),
        bucket_id: BucketId::new(r.text()?),
        generation_id: r.opt_text()?.map(GenerationId::new),
        state: r.parsed(ExtentState::parse)?,
        seq: r.opt_num()?,
        plain_offset: r.opt_num()?,
        plain_size: r.num()?,
        cipher_size: r.num()?,
        media_header: r.blob()?,
        key_mode: r.num()?,
        wrapped_file_key: r.opt_blob()?,
        plain_md5: r.array()?,
        plain_sha256: r.array()?,
        cipher_sha256: r.array()?,
        safety_state: r.parsed(SafetyState::parse)?,
        article_count: r.opt_num()?,
        plan_rev: r.num()?,
        last_verified_at: r.opt_num()?.map(UnixMs),
        release_evidence: r.opt_text()?,
        released_at: r.opt_num()?.map(UnixMs),
        created_at: UnixMs(r.num()?),
    };
    let bucket = Bucket {
        id: BucketId::new(r.text()?),
        name: r.text()?,
        owner: r.text()?,
        bdk_wrapped: r.blob()?,
        kek_version: r.num()?,
        disposable: r.num::<i64>()? != 0,
        created_at: UnixMs(r.num()?),
    };
    Ok(Some(JobExtent {
        extent,
        bucket,
        generation_state: r.parsed(GenerationState::parse)?,
        parity_count: r.opt_num()?,
    }))
}

/// The plan of `extent`: its packed plan when it has one
/// (`extents.plan`), else its rows in `articles`. One statement reads
/// both, the packed plan first, and the parity addendum with it
/// (`extents.parity`). The addendum is handed out as it is stored: one
/// that cannot be read does not fail the read of the plan.
pub(super) async fn stored_plan<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
) -> Result<StoredPlan> {
    let rows = c.sql.query(READ_ARTICLES, &[text(extent.as_str())]).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        if r.num::<i64>()? == 0 {
            // The packed plan is the plan: rows that are still there are
            // a copy of it that was not dropped yet.
            let id = ExtentId::new(r.text()?);
            r.num::<i64>()?;
            r.opt_text()?;
            r.opt_text()?;
            let packed = r.blob()?;
            let cipher_size: u64 = r.num()?;
            r.num::<i64>()?;
            let parity = r.opt_blob()?;
            r.opt_text()?;
            r.opt_text()?;
            r.opt_text()?;
            let posted_at: Option<i64> = r.opt_num()?;
            let reposted_at: Option<i64> = r.opt_num()?;
            let rows = crate::plan::expand(&id, cipher_size, &packed, posted_at, reposted_at)?;
            return Ok(StoredPlan {
                rows,
                packed: Some(packed),
                parity,
            });
        }
        out.push(ArticleRow {
            extent_id: ExtentId::new(r.text()?),
            idx: r.num()?,
            message_id: r.text()?,
            newsgroup: r.text()?,
            headers: r.blob()?,
            cipher_offset: r.num()?,
            cipher_len: r.num()?,
            payload_sha256: r.array()?,
            yenc_name: r.opt_text()?,
            state: r.parsed(ArticleState::parse)?,
            provider_id: r.opt_text()?,
            posted_at: r.opt_num()?.map(UnixMs),
            reposted_at: r.opt_num()?.map(UnixMs),
        });
    }
    Ok(StoredPlan {
        rows: out,
        packed: None,
        parity: None,
    })
}

// ---------------------------------------------------------------------------
// Article plan and posting
// ---------------------------------------------------------------------------

/// Stores the plan unless the extent already has one, then returns what
/// is stored. The whole plan is one batch keyed on `extents.article_count`
/// being unset, so a plan is never partial and the first one wins; the
/// caller posts only the returned rows. `None` = fenced.
pub(super) async fn plan_articles<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    rows: &[ArticleRow],
) -> Result<Option<Vec<ArticleRow>>> {
    let contiguous = rows
        .iter()
        .enumerate()
        .all(|(i, a)| a.extent_id == l.extent && u32::try_from(i).ok() == Some(a.idx));
    if rows.is_empty() || !contiguous {
        return Err(BridgeError::Invalid(
            "article plan is not idx 0..n of the leased extent",
        ));
    }
    let mut stmts: Vec<Stmt> = Vec::with_capacity(rows.len() + 2);
    stmts.push((held_guard!(), lease_params(l, [])?));
    for a in rows {
        stmts.push((
            INSERT_UNPACKED_ARTICLE,
            vec![
                text(a.extent_id.as_str()),
                SqlValue::Int(i64::from(a.idx)),
                text(&a.message_id),
                text(&a.newsgroup),
                SqlValue::Blob(a.headers.clone()),
                int(a.cipher_offset)?,
                int(a.cipher_len)?,
                SqlValue::Blob(a.payload_sha256.to_vec()),
                a.yenc_name.as_deref().map_or(SqlValue::Null, text),
            ],
        ));
    }
    // Last: the inserts above key on the count still being unset.
    stmts.push((
        FINISH_UNPACKED_PLAN,
        vec![text(l.extent.as_str()), int(rows.len())?],
    ));
    if !fenced_batch(c, stmts).await? {
        return Ok(None);
    }
    Ok(Some(stored_plan(c, &l.extent).await?.rows))
}

/// [`plan_articles`] for a packed plan: the plan is one value on the
/// extent's row, stored unless the extent already has a plan (packed or
/// in rows). Returns what is stored; `None` = fenced.
///
/// `plan` must expand to a plan of the leased extent, whose ciphertext
/// has `cipher_size` bytes: a value that does not is refused before
/// anything is written.
///
/// `parity` is the plan's parity addendum, stored by the same statement
/// as the plan: an extent never has one without the other being the plan
/// it was made for, and a plan that lost to an earlier one leaves its
/// addendum unwritten with it. It must expand beside `plan`, or nothing
/// is written.
pub(super) async fn plan_packed<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    cipher_size: u64,
    plan: &[u8],
    parity: Option<&[u8]>,
) -> Result<Option<StoredPlan>> {
    let count = crate::plan::expand(&l.extent, cipher_size, plan, None, None)?.len();
    let parity_count = match parity {
        Some(addendum) => {
            let parity = crate::parity::expand(&l.extent, cipher_size, plan, addendum)?;
            int(parity.articles.len())?
        }
        None => SqlValue::Null,
    };
    let stmts: Vec<Stmt> = vec![
        (held_guard!(), lease_params(l, [])?),
        (
            // The addendum is written once, with the plan, on an extent
            // that has neither (`article_count IS NULL`), so no pass on
            // record can be of another addendum. A statement that
            // rewrites the addendum of an extent must delete that
            // extent's `verifications` in the same batch: a pass is
            // bound to `plan_rev` and the article total only
            // (`counts!`).
            STORE_PACKED_PLAN,
            vec![
                text(l.extent.as_str()),
                int(count)?,
                SqlValue::Blob(plan.to_vec()),
                int(cipher_size)?,
                parity.map_or(SqlValue::Null, |p| SqlValue::Blob(p.to_vec())),
                parity_count,
            ],
        ),
    ];
    if !fenced_batch(c, stmts).await? {
        return Ok(None);
    }
    stored_plan(c, &l.extent).await.map(Some)
}

pub(super) async fn mark_posted<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    idx: u32,
    provider: &str,
    now: UnixMs,
) -> Result<bool> {
    let sql = MARK_ONE_POSTED;
    let extra = [SqlValue::Int(i64::from(idx)), text(provider), ms(now)];
    fenced(c, sql, l, extra).await
}

/// Marks every listed article posted, or none: the batch is led by the
/// lease guard, so a stale lease writes nothing.
///
/// A packed plan is posted as a whole: its extent is stamped when the
/// call lists every article of the plan, the parity articles of its
/// addendum included (`extents.parity_count` of them, `idx` from
/// `article_count` on). A call that lists fewer writes
/// nothing at all and is an error ([`ERR_PARTIAL_PLAN`]): a plan is
/// never taken for posted when its stamp was not written, and a caller
/// that holds its lease never hears that it lost it.
pub(super) async fn mark_posted_many<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    posted: &[(u32, &str)],
    now: UnixMs,
) -> Result<bool> {
    if posted.is_empty() {
        return renew_check(c, l).await;
    }
    let mut stmts: Vec<Stmt> = Vec::with_capacity(4);
    stmts.push((held_guard!(), lease_params(l, [])?));
    // One statement per provider, not per article.
    let mut providers: Vec<&str> = Vec::new();
    for (_, provider) in posted {
        if !providers.contains(provider) {
            providers.push(provider);
        }
    }
    for provider in providers {
        let idxs: Vec<u32> = posted
            .iter()
            .filter(|(_, p)| *p == provider)
            .map(|(idx, _)| *idx)
            .collect();
        stmts.push((
            c.sql
                .dialect()
                .pick(MARK_ARTICLES_POSTED, MARK_ARTICLES_POSTED_PG),
            vec![
                text(l.extent.as_str()),
                text(&idx_list(&idxs)),
                text(provider),
                ms(now),
            ],
        ));
    }
    let listed: Vec<u32> = posted.iter().map(|(idx, _)| *idx).collect();
    // Every article of the plan is `0..article_count`, and then its
    // parity articles when it has an addendum: as many distinct ones
    // below the count of both are all of them.
    stmts.push((
        c.sql
            .dialect()
            .pick(MARK_PACKED_POSTED, MARK_PACKED_POSTED_PG),
        vec![text(l.extent.as_str()), ms(now), text(&idx_list(&listed))],
    ));
    // A packed plan that the call did not mark is not posted: nothing
    // is written.
    stmts.push((GUARD_POSTED_PLAN, vec![text(l.extent.as_str())]));
    if fenced_batch(c, stmts).await? {
        return Ok(true);
    }
    // Either guard refuses the batch. A lease that is still held was
    // not the one: the call did not list the whole plan. That is a
    // fault of the caller, which must not take it for a lost lease and
    // leave the job without a failed attempt on its row.
    if renew_check(c, l).await? {
        return Err(ERR_PARTIAL_PLAN);
    }
    Ok(false)
}

/// A packed plan was marked posted by a call that did not list every
/// one of its articles.
const ERR_PARTIAL_PLAN: BridgeError =
    BridgeError::Invalid("a packed plan is marked posted only as a whole");

/// `idxs` as a JSON array, for `json_each`.
fn idx_list(idxs: &[u32]) -> String {
    let mut out = String::from("[");
    for (at, idx) in idxs.iter().enumerate() {
        if at > 0 {
            out.push(',');
        }
        let _ = write!(out, "{idx}");
    }
    out.push(']');
    out
}

/// Stamps every listed article as posted again at `now`, or none: the
/// batch is led by the lease guard. A stamp never moves back. A packed
/// plan has one stamp for all its articles, on its extent.
pub(super) async fn mark_reposted_many<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    idxs: &[u32],
    now: UnixMs,
) -> Result<bool> {
    if idxs.is_empty() {
        return renew_check(c, l).await;
    }
    let stmts: Vec<Stmt> = vec![
        (held_guard!(), lease_params(l, [])?),
        (
            c.sql
                .dialect()
                .pick(MARK_ARTICLES_REPOSTED, MARK_ARTICLES_REPOSTED_PG),
            vec![text(l.extent.as_str()), text(&idx_list(idxs)), ms(now)],
        ),
        (
            c.sql
                .dialect()
                .pick(MARK_PACKED_REPOSTED, MARK_PACKED_REPOSTED_PG),
            vec![text(l.extent.as_str()), ms(now)],
        ),
    ];
    fenced_batch(c, stmts).await
}

/// Whether the lease still holds its row (a read; nothing is extended).
async fn renew_check<S: Sql>(c: &SqlCatalog<S>, l: &Lease) -> Result<bool> {
    let sql = CHECK_LEASE;
    Ok(!c.sql.query(sql, &lease_params(l, [])?).await?.is_empty())
}

// ---------------------------------------------------------------------------
// Verification and release
// ---------------------------------------------------------------------------

/// Appends one verification result under the lease, with its token; a
/// full `body` pass of the current plan also moves
/// `extents.last_verified_at` forward. A `stat` pass does not: nothing
/// was read.
///
/// [`VerifyRecord::Kept`]: the lease holds, but a row of the backbone at
/// the same millisecond stays, as the rule below has it. Its count of
/// changed rows says so (0); no time is compared to find it out.
pub(super) async fn record_verification<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    v: &VerificationRow,
) -> Result<VerifyRecord> {
    if v.extent_id != l.extent {
        return Err(BridgeError::Invalid(
            "verification is not for the leased extent",
        ));
    }
    let row = vec![
        text(v.extent_id.as_str()),
        text(&v.backbone),
        text(&v.provider_id),
        ms(v.verified_at),
        SqlValue::Int(i64::from(v.plan_rev)),
        SqlValue::Int(i64::from(v.articles_ok)),
        SqlValue::Int(i64::from(v.articles_total)),
        text(v.result.as_str()),
        text(v.kind.column()),
        v.kind.mode_column().map_or(SqlValue::Null, text),
        int(l.token)?,
    ];
    let stmts = vec![
        (held_guard!(), lease_params(l, [])?),
        (
            // Two results for one backbone in the same millisecond: a
            // failure is never replaced, so the pair cannot count as a
            // pass, and the kind is that of the result that stays. A
            // `stat` pass never replaces a `body` pass: the row is the
            // full check on record, which a release needs, and the
            // `body` pass says all the `stat` pass would. The tally of a
            // `STAT` goes to `articles_present` (see `tally!`). A row
            // that is replaced takes the claim of the result that
            // replaces it; one that stays keeps its own.
            WRITE_VERIFICATION,
            row,
        ),
        (
            STAMP_LAST_BODY_VERIFY,
            vec![
                text(v.extent_id.as_str()),
                ms(v.verified_at),
                text(v.result.as_str()),
                SqlValue::Int(i64::from(v.articles_ok)),
                SqlValue::Int(i64::from(v.articles_total)),
                SqlValue::Int(i64::from(v.plan_rev)),
                text(v.kind.column()),
            ],
        ),
    ];
    match c.sql.batch(stmts).await {
        // One row changed: inserted, or put in the place of the row at
        // that instant. None: that row stays.
        Ok(changed) => Ok(match changed.get(1) {
            Some(n) if *n > 0 => VerifyRecord::Stored,
            _ => VerifyRecord::Kept,
        }),
        Err(BridgeError::GuardFailed) => Ok(VerifyRecord::Fenced),
        Err(e) => Err(e),
    }
}

/// Reads the columns `kind`, `mode` of a verification row.
pub(super) fn kind_of(r: &mut Cols) -> Result<VerifyKind> {
    let (kind, mode) = (r.text()?, r.opt_text()?);
    VerifyKind::from_columns(&kind, mode.as_deref())
        .ok_or_else(|| BridgeError::Sql("unknown verification kind".into()))
}

/// Latest row per backbone for the extent's current plan. `counts` is true
/// only for a complete pass of the row's `kind` (`ok`, `articles_ok =
/// articles_total` = every article of the plan, parity included): a
/// newer failure hides an older pass, a newer `stat` pass hides an older
/// `body` pass, and two providers on one backbone are one row.
pub(super) async fn backbone_status<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
) -> Result<Vec<BackboneStatus>> {
    let sql = BACKBONE_STATUS;
    let rows = c.sql.query(sql, &[text(extent.as_str())]).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(BackboneStatus {
            backbone: r.text()?,
            provider_id: r.text()?,
            verified_at: UnixMs(r.num()?),
            plan_rev: r.num()?,
            articles_ok: r.num()?,
            articles_total: r.num()?,
            result: r.parsed(VerifyResult::parse)?,
            kind: kind_of(&mut r)?,
            counts: r.num::<i64>()? != 0,
        });
    }
    Ok(out)
}

/// The last check of the bytes per backbone, for the current plan:
/// - its latest `body` row, pass or failure. `counts` is true where that
///   row is the full check on record ([`body_on_record`]);
/// - its latest size check that found an article of the wrong size, if
///   no full read came after it (kind `Size`, never `counts`).
///
/// A row here that is not a complete pass means the backbone holds no
/// copy until it is read in full again ([`body_failed`]).
pub(super) async fn body_checks<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
) -> Result<Vec<BackboneStatus>> {
    let sql = BODY_CHECKS;
    let rows = c.sql.query(sql, &[text(extent.as_str())]).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(BackboneStatus {
            backbone: r.text()?,
            provider_id: r.text()?,
            verified_at: UnixMs(r.num()?),
            plan_rev: r.num()?,
            articles_ok: r.num()?,
            articles_total: r.num()?,
            result: r.parsed(VerifyResult::parse)?,
            kind: kind_of(&mut r)?,
            counts: r.num::<i64>()? != 0,
        });
    }
    Ok(out)
}

/// Authorizes unpinning the safety copy (it becomes evictable). One batch whose guard requires:
/// the release lease still holds, a live generation references the extent, the copy is
/// `held` (or `releasing`, when re-driven), and the release rule holds:
/// - at least `required` of the `counting` backbones have a complete pass
///   recorded under this claim (between the claim time and `now`); a
///   `stat` pass is enough here, except on a backbone whose last full
///   read failed ([`body_failed`]), which holds no copy;
/// - at least one of those backbones also has the full check on record
///   ([`body_on_record`]): a complete `body` pass of the current plan,
///   from verify or from this claim, that no later check has cancelled.
///
/// So `stat` passes release nothing for a plan that was never read in
/// full, nor when the backbone that was read in full no longer answers
/// for every article. A pass on a backbone outside `counting` is not
/// looked at. The lease must also be unexpired: an expired lease may
/// be taken over at any moment. Anything else is `Lost`.
///
/// `light` is `None` for the guard above, and `Some(need_full)` for the
/// light check. With `Some(false)` (an extent outside the sample) the
/// second point is left out: the first one, the lease and the rest of
/// the guard are the same.
///
/// Under the light check the escalations count too (`verify_escalations`,
/// those that had not ended when the extent was stored): a pass on a
/// backbone under full reads counts only with the full check on record
/// for that backbone, and with any backbone of `counting` under full
/// reads the second point holds whatever `need_full` says. They are
/// read in the guard, so one raised after the job read them is not
/// missed.
///
/// `whole` is false for a release job: the copy becomes `releasing`,
/// and [`finish_release`] is the last step. With `whole` the lease is
/// that of the verify job that releases what it has just checked
/// ([`crate::ports::Catalog::release_at_verify`]): the same guard over
/// the claim of that lease, then the last step in the same batch. The
/// copy goes from `held` to `released` and the row from `verify` to
/// `done` together or not at all, so no copy is left `releasing` under
/// a row in `verify`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn begin_release<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    required: u32,
    counting: &[String],
    evidence_json: &str,
    now: UnixMs,
    light: Option<bool>,
    whole: bool,
) -> Result<Guard<()>> {
    let need_full = light.unwrap_or(true);
    let light = light.is_some();
    let stage = match whole {
        false => OutboxStage::Release,
        true => OutboxStage::Verify,
    };
    if l.stage != stage || required == 0 {
        return Err(BridgeError::Invalid(match whole {
            false => "release needs a release lease and at least one required backbone",
            true => "release at verify needs a verify lease and at least one required backbone",
        }));
    }
    let labels =
        serde_json::to_string(counting).map_err(|_| BridgeError::Invalid("backbone labels"))?;
    // The release-stage guard still accepts `releasing`; the job
    // reopens an interrupted decision before it checks again. The
    // verify-stage batch never takes a copy unless it is `held`.
    let guard = match whole {
        false => c
            .sql
            .dialect()
            .pick(GUARD_RELEASE_JOB, GUARD_RELEASE_JOB_PG),
        true => c
            .sql
            .dialect()
            .pick(GUARD_RELEASE_AT_VERIFY, GUARD_RELEASE_AT_VERIFY_PG),
    };
    let mark = match whole {
        false => (
            START_SAFETY_RELEASE,
            vec![text(l.extent.as_str()), text(evidence_json)],
        ),
        // The mark and the write of [`finish_release`] as one: the row
        // ends as the two steps of a release job leave it, but for the
        // fence, which moves once for the one change of state.
        true => (
            COMPLETE_SAFETY_RELEASE,
            vec![text(l.extent.as_str()), text(evidence_json), ms(now)],
        ),
    };
    let mut stmts = vec![
        (
            guard,
            lease_params(
                l,
                [
                    SqlValue::Int(i64::from(required)),
                    ms(now),
                    text(&labels),
                    SqlValue::Int(i64::from(need_full)),
                    SqlValue::Int(i64::from(light)),
                ],
            )?,
        ),
        mark,
    ];
    if whole {
        // The row as the move to the release stage and then
        // [`finish_release`] leave it: nothing of the verify rounds (the
        // resume point, the last error) stays on a row that is done.
        // Last: after this the lease no longer holds.
        let done = ADVANCE_RELEASE_AT_VERIFY;
        stmts.push((done, lease_params(l, [ms(now)])?));
    }
    super::uploads::guarded(c, stmts).await
}

/// See [`crate::ports::Catalog::escalate_verify`].
pub(super) async fn escalate_verify<S: Sql>(
    c: &SqlCatalog<S>,
    e: &VerifyEscalation,
    plan_rev: u32,
) -> Result<()> {
    // One batch: the escalation only where this extent has not raised
    // the backbone for this plan, then the note that it has.
    let raise = (
        RAISE_ESCALATION,
        vec![
            text(&e.backbone),
            ms(e.until),
            ms(e.raised_at),
            text(e.extent_id.as_str()),
            text(e.result.as_str()),
            int(plan_rev)?,
        ],
    );
    let note = (
        c.sql.dialect().pick(RAISE_ONCE, RAISE_ONCE_PG),
        vec![
            text(e.extent_id.as_str()),
            text(&e.backbone),
            int(plan_rev)?,
            ms(e.raised_at),
        ],
    );
    c.sql.batch(vec![raise, note]).await?;
    Ok(())
}

/// See [`crate::ports::Catalog::verify_raised`].
pub(super) async fn verify_raised<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    backbone: &str,
    plan_rev: u32,
) -> Result<bool> {
    let rows = c
        .sql
        .query(
            ALREADY_RAISED,
            &[text(extent.as_str()), text(backbone), int(plan_rev)?],
        )
        .await?;
    Ok(!rows.is_empty())
}

/// See [`crate::ports::Catalog::verify_escalations`].
pub(super) async fn verify_escalations<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
) -> Result<Vec<VerifyEscalation>> {
    let rows = c.sql.query(LIST_ESCALATIONS, &[ms(now)]).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(VerifyEscalation {
            backbone: r.text()?,
            until: UnixMs(r.num()?),
            raised_at: UnixMs(r.num()?),
            extent_id: ExtentId::new(r.text()?),
            result: r.parsed(VerifyResult::parse)?,
        });
    }
    Ok(out)
}

/// `releasing` → `released`, row done. The safety copy stays in R2: from
/// here on it is evictable, and counted as such. A never-read extent
/// starts its eviction order at its upload time.
///
/// The guard does not look at the decision again: this is the last step
/// of the job whose `begin_release` was applied, under the same lease.
/// Whatever takes that decision's ground away (a replay that writes
/// another addendum) ends the lease in its own batch, and a job that
/// finds the extent `releasing` withdraws the decision first
/// ([`reopen_release`]).
pub(super) async fn finish_release<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    now: UnixMs,
) -> Result<bool> {
    let guard = GUARD_FINISH_RELEASE;
    let done = ADVANCE_RELEASE;
    let stmts = vec![
        (guard, lease_params(l, [ms(now)])?),
        (
            FINISH_SAFETY_RELEASE,
            vec![text(l.extent.as_str()), ms(now)],
        ),
        // Last: after this the lease no longer holds.
        (done, lease_params(l, [ms(now)])?),
    ];
    fenced_batch(c, stmts).await
}

/// See [`crate::ports::Catalog::reopen_release`]. `releasing` → `held`
/// under the release lease, which is kept. Both states pin the safety
/// copy, so nothing becomes evictable and no counter moves.
pub(super) async fn reopen_release<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    now: UnixMs,
) -> Result<bool> {
    let guard = GUARD_REOPEN_RELEASE;
    let stmts = vec![
        (guard, lease_params(l, [ms(now)])?),
        (REOPEN_RELEASE, vec![text(l.extent.as_str())]),
    ];
    fenced_batch(c, stmts).await
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// The stages the dispatcher sends jobs for.
const DUE_STAGES: [&str; 3] = ["post", "verify", "release"];

/// Due rows no job holds, oldest first, without the ones the dispatcher
/// has sent a job for and that job may still be on its way: a row with a
/// mark (`sent_at`) is left out until the seconds `resend` has for its
/// stage after the mark. A claim clears the mark, and a due time later
/// than the mark outdates it, so a row that a job gave back or moved on
/// is listed at once.
///
/// At most `limit` rows. Each stage has a third of them to itself, its
/// oldest rows; what a stage does not use goes to the oldest rows left
/// of the others. Without the shares, a backlog of one stage longer
/// than `limit` (post rows, when posting is behind) took every run, and
/// rows of the other stages that were due were not sent at all.
///
/// One statement per stage, each along `outbox_due` in its order (the
/// rowid breaks a tie), with no sort: a statement stops at `limit` rows
/// it lists. The marks and the leases are not in the index, so it also
/// reads the due rows it passes over on the way, which are at most the
/// rows marked within that time and the ones a job holds.
pub(super) async fn due<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    resend: Resend,
    limit: u32,
) -> Result<Vec<DueRow>> {
    let limit_rows = limit as usize;
    let share = limit_rows / DUE_STAGES.len();
    // (next_at, order within its stage, row)
    let mut kept: Vec<(i64, usize, DueRow)> = Vec::new();
    let mut spare: Vec<(i64, usize, DueRow)> = Vec::new();
    for stage in DUE_STAGES {
        let resend_secs = match stage {
            "post" => resend.post_secs,
            _ => resend.verify_secs,
        };
        let rows = c
            .sql
            .query(
                c.sql.dialect().pick(DUE_PAGE, DUE_PAGE_PG),
                &[
                    ms(now),
                    SqlValue::Int(i64::from(limit)),
                    ms(now.plus_ms(-i64::from(resend_secs) * 1000)),
                    text(stage),
                ],
            )
            .await?;
        for (at, row) in rows.into_iter().enumerate() {
            let mut r = Cols::new(row);
            let due = DueRow {
                extent_id: ExtentId::new(r.text()?),
                generation_id: GenerationId::new(r.text()?),
                stage: r.parsed(OutboxStage::parse)?,
            };
            let next_at: i64 = r.num()?;
            if at < share {
                kept.push((next_at, at, due));
            } else {
                spare.push((next_at, at, due));
            }
        }
    }
    // Stable sorts: rows due at the same time keep the order of the
    // stages, and of their stage.
    spare.sort_by_key(|(next_at, at, _)| (*next_at, *at));
    let room = limit_rows.saturating_sub(kept.len());
    kept.extend(spare.into_iter().take(room));
    kept.sort_by_key(|(next_at, at, _)| (*next_at, *at));
    Ok(kept.into_iter().map(|(_, _, due)| due).collect())
}

/// Marks rows the dispatcher has just sent a job for (`sent_at = now`).
/// Only a row that is still due and held by no job is marked: one that
/// a job claimed since it was listed keeps no mark, so it is listed
/// again as soon as that job lets go of it. The ids travel as one JSON
/// array. One row written per marked row; `sent_at` is in no index.
/// The unary `+` keeps the planner off the due index, which would walk
/// every due row: each row is found by its id.
pub(super) async fn mark_sent<S: Sql>(
    c: &SqlCatalog<S>,
    extents: &[ExtentId],
    now: UnixMs,
) -> Result<u64> {
    let ids = ids_json(extents.iter().map(ExtentId::as_str).collect());
    let sql = c.sql.dialect().pick(MARK_SENT, MARK_SENT_PG);
    set_mark(c, sql, ids, now).await
}

/// `ids` as one JSON array; `None` if there are none.
fn ids_json(ids: Vec<&str>) -> Option<String> {
    match ids.is_empty() {
        true => None,
        false => serde_json::to_string(&ids).ok(),
    }
}

/// Runs `sql` with `?1 = at` and `?2 = ids`; nothing without ids.
async fn set_mark<S: Sql>(
    c: &SqlCatalog<S>,
    sql: &str,
    ids: Option<String>,
    at: UnixMs,
) -> Result<u64> {
    match ids {
        Some(ids) => c.sql.exec(sql, &[ms(at), text(&ids)]).await,
        None => Ok(0),
    }
}

/// Takes back the mark `mark` of the rows of `jobs`: the job that was
/// to be sent for each of them was not ([`advance`], or a
/// publication, whose rows are marked as they are inserted). Only a row
/// that still carries this very mark is changed: one that a job claimed
/// since has none, and one that was marked again keeps its newer mark.
/// One row written per row changed; each row is found by its id.
pub(super) async fn unmark_sent<S: Sql>(
    c: &SqlCatalog<S>,
    jobs: &[crate::types::Job],
    mark: UnixMs,
) -> Result<u64> {
    let ids = jobs.iter().filter_map(|j| j.extent().map(ExtentId::as_str));
    let ids = ids_json(ids.collect());
    let sql = c.sql.dialect().pick(UNMARK_SENT, UNMARK_SENT_PG);
    set_mark(c, sql, ids, mark).await
}

/// The attempts above which a row is in the `outbox_exhausted` index.
/// The index says `attempts > 50` in its `WHERE`, and a statement is
/// answered from it only when it spells the same condition, so the
/// figure is part of the statement text below and not a bound value.
pub const EXHAUSTED_INDEX_ATTEMPTS: u32 = 50;

// The jobs' limit is never below the index's: every row the dispatcher
// buries is in the index.
const _: () = assert!(crate::jobs::MAX_ATTEMPTS >= EXHAUSTED_INDEX_ATTEMPTS);

/// The bury for a limit at or above the index's: it reads the entries
/// of `outbox_exhausted` (the rows out of attempts at a working stage)
/// and nothing else, however many rows wait. `?1` narrows a higher
/// limit further.
pub const BURY_EXHAUSTED: &str = "UPDATE outbox INDEXED BY outbox_exhausted \
       SET stage = 'dead', updated_at = ?2 \
     WHERE attempts > 50 AND stage IN ('post', 'verify', 'release') AND attempts > ?1 \
       AND (lease_until IS NULL OR lease_until < ?2)";

/// Moves unleased rows with more than `max_attempts` claims to `dead`.
pub(super) async fn bury_exhausted<S: Sql>(
    c: &SqlCatalog<S>,
    max_attempts: u32,
    now: UnixMs,
) -> Result<u64> {
    // A limit below the index's would miss the rows between the two:
    // those are read the long way. `jobs::MAX_ATTEMPTS` never is.
    // Counted by the rows returned, not by the rows changed: a
    // usage-counter trigger adds to the latter.
    let buried = c
        .sql
        .query(
            &bury_sql(c.sql.dialect(), max_attempts >= EXHAUSTED_INDEX_ATTEMPTS),
            &[SqlValue::Int(i64::from(max_attempts)), ms(now)],
        )
        .await?;
    Ok(buried.len() as u64)
}

/// Sends `done` extents that a release could not be decided for back to
/// verify: a live generation references the extent, the safety copy is still `held`, and
/// fewer than `required` of the configured `backbones` count. The row
/// restarts as a fresh obligation (cursor and attempts at zero) and the
/// lease token moves on. One statement, so a row is moved once.
pub(super) async fn redrive_underverified<S: Sql>(
    c: &SqlCatalog<S>,
    backbones: &[String],
    required: u32,
    limit: u32,
    now: UnixMs,
) -> Result<u64> {
    let labels =
        serde_json::to_string(backbones).map_err(|_| BridgeError::Invalid("backbone labels"))?;
    // One run looks at a window of `limit` pinned extents (held or
    // releasing), read from the partial index alone, and the next run
    // starts after it: the cost of a run does not grow with the number
    // of pinned extents. The window counts releasing ones too, so a
    // backlog of them is stepped over a window at a time rather than
    // read whole in search of `limit` held ones; the update below takes
    // the held ones of the window.
    let after = c
        .sql
        .query(REDRIVE_CURSOR, &[])
        .await?
        .into_iter()
        .next()
        .map(|row| Cols::new(row).text())
        .transpose()?
        .unwrap_or_default();
    let dialect = c.sql.dialect();
    let mut window = c
        .sql
        .query(
            // The condition is the index's own `WHERE`, word for word:
            // the planner takes a partial index only then.
            dialect.pick(REDRIVE_WINDOW, REDRIVE_WINDOW_PG),
            &[text(&after), SqlValue::Int(i64::from(limit))],
        )
        .await?;
    let full = window.len() >= limit as usize;
    let Some(last) = window.pop() else {
        set_redrive_cursor(c, "").await?;
        return Ok(0);
    };
    let last = Cols::new(last).text()?;
    let mut params = vec![ms(now), text(&labels), SqlValue::Int(i64::from(required))];
    let sql = match dialect {
        crate::ports::Dialect::Sqlite => {
            params.extend([text(&after), text(&last)]);
            REDRIVE
        }
        crate::ports::Dialect::Postgres => {
            let mut ids = window
                .into_iter()
                .map(|row| Cols::new(row).text())
                .collect::<Result<Vec<_>>>()?;
            ids.push(last.clone());
            let ids = serde_json::to_string(&ids)
                .map_err(|_| BridgeError::Sql("redrive: encode window".into()))?;
            params.push(SqlValue::Text(ids));
            REDRIVE_PG
        }
    };
    // Counted by the rows returned: see `bury_exhausted`.
    let moved = c.sql.query(sql, &params).await?;
    // A short window was the end of the index: start over next time.
    set_redrive_cursor(c, if full { &last } else { "" }).await?;
    Ok(moved.len() as u64)
}

/// Re-arms cancelled obligations of extents that a live generation
/// references. Current code never leaves one: it cancels a posting only
/// with the extent's last reference. A Worker from before extent
/// references can, after a rollback: it knows an extent by the generation
/// it was first written for alone, and the schema stops it only while
/// that generation is live. The row restarts at the stage its safety copy
/// is at: `post` while held, `release` when a release was begun and not
/// finished, `done` otherwise. One call looks at the next `limit` outbox
/// rows, in a rotation over all of them, so its cost does not grow with
/// the table.
pub(super) async fn revive_referenced<S: Sql>(
    c: &SqlCatalog<S>,
    limit: u32,
    now: UnixMs,
) -> Result<u64> {
    let after = c
        .sql
        .query(REVIVE_CURSOR, &[])
        .await?
        .into_iter()
        .next()
        .map(|row| Cols::new(row).text())
        .transpose()?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let window = c
        .sql
        .query(
            c.sql.dialect().pick(REVIVE_WINDOW, REVIVE_WINDOW_PG),
            &[SqlValue::Int(after), SqlValue::Int(i64::from(limit))],
        )
        .await?;
    let full = window.len() >= limit as usize;
    let last = match window.into_iter().next_back() {
        Some(row) => Cols::new(row).num::<i64>()?,
        None => {
            set_scan_cursor(c, "revive", "0").await?;
            return Ok(0);
        }
    };
    let sql = c.sql.dialect().pick(REVIVE, REVIVE_PG);
    // Counted by the rows returned: see `bury_exhausted`.
    let revived = c
        .sql
        .query(sql, &[ms(now), SqlValue::Int(after), SqlValue::Int(last)])
        .await?;
    // A short window was the end of the table: start over next time.
    let next = if full { last } else { 0 };
    set_scan_cursor(c, "revive", &next.to_string()).await?;
    Ok(revived.len() as u64)
}

/// Extents per write of [`pack_plans`] (two statements each).
const PACK_CHUNK: usize = 25;

/// See [`crate::ports::Catalog::pack_plans`].
///
/// The packed plan is made here from the rows as they were read, and the
/// write that stores it checks that they still are what was read: an
/// article plan never changes, so that is the extent having no packed
/// plan yet, the same size and article count, and every article posted.
/// The stamps are taken from the rows inside the write, so one that a
/// repost sets meanwhile is not lost. A plan whose articles were posted
/// at a time nobody knows (rows of a replay) is packed as posted at 0.
pub(super) async fn pack_plans<S: Sql>(c: &SqlCatalog<S>, limit: u32) -> Result<PackReport> {
    let after = c
        .sql
        .query(PACK_CURSOR, &[])
        .await?
        .into_iter()
        .next()
        .map(|row| Cols::new(row).text())
        .transpose()?
        .unwrap_or_default();
    // One row per extent that has article rows, by the primary key.
    let window = c
        .sql
        .query(
            PACK_WINDOW,
            &[text(&after), SqlValue::Int(i64::from(limit))],
        )
        .await?;
    let mut ids = Vec::with_capacity(window.len());
    for row in window {
        ids.push(ExtentId::new(Cols::new(row).text()?));
    }
    let mut report = PackReport {
        looked: u32::try_from(ids.len()).unwrap_or(u32::MAX),
        packed: 0,
        end: ids.len() < limit as usize,
    };
    let mut stmts: Vec<Stmt> = Vec::with_capacity(2 * PACK_CHUNK);
    // Per statement of the batch: it packs a plan.
    let mut packs: Vec<bool> = Vec::with_capacity(2 * PACK_CHUNK);
    for (at, id) in ids.iter().enumerate() {
        // A plan that cannot be read stays as it is: the step goes on
        // with the next extent, and the readers of this one report it.
        if let Ok(plan) = stored_plan(c, id).await {
            let posted = plan.rows.iter().all(|a| a.state == ArticleState::Posted);
            // The plan covers the whole ciphertext: its end is the size.
            let cipher_size = plan.rows.last().map(|a| a.cipher_offset + a.cipher_len);
            // Rows beside a packed plan are a copy that was not dropped.
            let mut copy = plan.packed.is_some();
            let packed = match (&plan.packed, cipher_size) {
                (None, Some(size)) if posted => crate::plan::pack_explicit(id, size, &plan.rows)
                    .ok()
                    .map(|blob| (blob, size)),
                _ => None,
            };
            if let Some((blob, size)) = packed {
                stmts.push((
                    STORE_PACKED_FROM_ROWS,
                    vec![
                        text(id.as_str()),
                        SqlValue::Blob(blob),
                        int(size)?,
                        int(plan.rows.len())?,
                        SqlValue::Int(crate::plan::POSTED_AT_UNKNOWN),
                    ],
                ));
                packs.push(true);
                copy = true;
            }
            if copy {
                // Only the rows of a plan that is packed: they are a
                // copy of it from here on.
                stmts.push((DROP_PACKED_ARTICLES, vec![text(id.as_str())]));
                packs.push(false);
            }
        }
        if stmts.len() >= 2 * PACK_CHUNK || (at + 1 == ids.len() && !stmts.is_empty()) {
            let changed = c.sql.batch(core::mem::take(&mut stmts)).await?;
            let packed: u64 = changed
                .iter()
                .zip(packs.drain(..))
                .filter_map(|(n, packs)| packs.then_some(*n))
                .sum();
            report.packed += u32::try_from(packed).unwrap_or(u32::MAX);
        }
    }
    // A short window was the end of the table: start over next time.
    let next = match (report.end, ids.last()) {
        (false, Some(last)) => last.as_str(),
        _ => "",
    };
    if next != after {
        set_scan_cursor(c, "pack", next).await?;
    }
    Ok(report)
}

async fn set_redrive_cursor<S: Sql>(c: &SqlCatalog<S>, at: &str) -> Result<()> {
    set_scan_cursor(c, "redrive", at).await
}

async fn set_scan_cursor<S: Sql>(c: &SqlCatalog<S>, k: &str, at: &str) -> Result<()> {
    c.sql
        .exec(
            c.sql.dialect().pick(SET_SCAN_CURSOR, SET_SCAN_CURSOR_PG),
            &[text(k), text(at)],
        )
        .await?;
    Ok(())
}

pub(super) async fn record_dispatch<S: Sql>(c: &SqlCatalog<S>, now: UnixMs) -> Result<()> {
    c.sql
        .exec(
            c.sql.dialect().pick(RECORD_DISPATCH, RECORD_DISPATCH_PG),
            &[ms(now)],
        )
        .await?;
    Ok(())
}

pub(super) async fn outbox_stats<S: Sql>(c: &SqlCatalog<S>) -> Result<OutboxStats> {
    // From the usage counters once they are switched on: one row read.
    // Until then the table is counted, as it was before the counters.
    let usage = super::usage::counters(c).await?;
    let mut counted = Vec::with_capacity(OutboxStage::ALL.len());
    if usage.seeded {
        for &stage in OutboxStage::ALL {
            // A stage without rows is left out, as a count of the
            // table leaves it out.
            if let Ok(n @ 1..) = u64::try_from(usage.outbox(stage)) {
                counted.push((stage, n));
            }
        }
    } else {
        let rows = c.sql.query(OUTBOX_STATS, &[]).await?;
        for row in rows {
            let mut r = Cols::new(row);
            counted.push((r.parsed(OutboxStage::parse)?, r.num::<u64>()?));
        }
    }
    let by_stage: Vec<_> = OutboxStage::ALL
        .iter()
        .filter_map(|s| counted.iter().find(|(stage, _)| stage == s).copied())
        .collect();
    let dead = by_stage
        .iter()
        .find(|(s, _)| *s == OutboxStage::Dead)
        .map_or(0, |(_, n)| *n);
    let rows = c.sql.query(LAST_DISPATCH_AT, &[]).await?;
    let last_dispatch_at = match rows.into_iter().next() {
        Some(row) => Some(UnixMs(Cols::new(row).num()?)),
        None => None,
    };
    Ok(OutboxStats {
        by_stage,
        dead,
        last_dispatch_at,
    })
}

const CLAIM: &str = "UPDATE outbox SET lease_token = lease_token + 1, lease_owner = ?4, \
               lease_until = ?5, attempts = attempts + 1, updated_at = ?6, sent_at = NULL \
             WHERE extent_id = ?1 AND generation_id = ?2 AND stage = ?3 AND next_at <= ?6 \
               AND (lease_until IS NULL OR lease_until < ?6) \
             RETURNING lease_token, attempts, cursor";

const ADVANCE: &str = concat!(
    "UPDATE outbox SET stage = ?5, next_at = ?6, updated_at = ?7, attempts = 0, cursor = 0, \
           last_error = NULL, \
           sent_at = CASE WHEN ?5 IN ('post', 'verify', 'release') THEN ?6 END, ",
    unlease!(),
    " WHERE ",
    held!()
);

const FAIL: &str = concat!(
    "UPDATE outbox SET next_at = ?5, last_error = ?6, updated_at = ?7, ",
    unlease!(),
    " WHERE ",
    held!()
);

const SET_CURSOR: &str = concat!("UPDATE outbox SET cursor = ?5 WHERE ", held!());

const JOB_EXTENT: &str = concat!(
    "SELECT e.id, e.bucket_id, e.generation_id, e.state, e.seq, e.plain_offset, \
           e.plain_size, e.cipher_size, e.media_header, e.key_mode, e.wrapped_file_key, \
           e.plain_md5, e.plain_sha256, e.cipher_sha256, e.safety_state, e.article_count, \
           e.plan_rev, e.last_verified_at, e.release_evidence, e.released_at, e.created_at, \
           b.id, b.name, b.owner, b.bdk_wrapped, b.kek_version, b.disposable, b.created_at, \
           CASE WHEN ",
    live_ref!("e.id"),
    " THEN 'live' ELSE g.state END, e.parity_count \
         FROM extents e JOIN buckets b ON b.id = e.bucket_id \
         JOIN generations g ON g.id = e.generation_id \
         WHERE e.id = ?1 AND e.generation_id = ?2"
);

const READ_ARTICLES: &str = "SELECT 0 AS packed, id AS extent_id, -1 AS idx, NULL AS message_id, \
               NULL AS newsgroup, plan AS headers, cipher_size AS cipher_offset, \
               0 AS cipher_len, parity AS payload_sha256, NULL AS yenc_name, NULL AS state, \
               NULL AS provider_id, posted_at, reposted_at \
             FROM extents WHERE id = ?1 AND plan IS NOT NULL \
             UNION ALL \
             SELECT 1, extent_id, idx, message_id, newsgroup, headers, cipher_offset, \
               cipher_len, payload_sha256, yenc_name, state, provider_id, posted_at, \
               reposted_at \
             FROM articles WHERE extent_id = ?1 ORDER BY packed, idx";

const INSERT_UNPACKED_ARTICLE: &str =
    "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, cipher_offset, \
               cipher_len, payload_sha256, yenc_name, state) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'planned' \
             WHERE (SELECT article_count FROM extents WHERE id = ?1) IS NULL";

const FINISH_UNPACKED_PLAN: &str = "UPDATE extents SET article_count = ?2, plan_rev = 1 \
         WHERE id = ?1 AND article_count IS NULL";

const STORE_PACKED_PLAN: &str = "UPDATE extents SET article_count = ?2, plan_rev = 1, plan = ?3, \
               parity = ?5, parity_count = ?6 \
             WHERE id = ?1 AND article_count IS NULL AND cipher_size = ?4";

const MARK_ONE_POSTED: &str = concat!(
    "UPDATE articles SET state = 'posted', provider_id = ?6, posted_at = ?7 \
         WHERE extent_id = ?1 AND idx = ?5 \
           AND (SELECT plan FROM extents WHERE id = ?1) IS NULL \
           AND EXISTS (SELECT 1 FROM outbox WHERE ",
    held!(),
    ")"
);

const GUARD_POSTED_PLAN: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE EXISTS \
           (SELECT 1 FROM extents WHERE id = ?1 AND plan IS NOT NULL AND posted_at IS NULL)";

const CHECK_LEASE: &str = concat!("SELECT 1 FROM outbox WHERE ", held!());

const WRITE_VERIFICATION: &str =
    "INSERT INTO verifications(extent_id, backbone, provider_id, verified_at, \
               plan_rev, articles_ok, articles_present, articles_total, result, kind, mode, \
               lease_token) \
             VALUES (?1, ?2, ?3, ?4, ?5, CASE ?9 WHEN 'stat' THEN 0 ELSE ?6 END, \
               CASE ?9 WHEN 'stat' THEN ?6 ELSE 0 END, ?7, ?8, ?9, ?10, ?11) \
             ON CONFLICT(extent_id, backbone, verified_at) DO UPDATE SET \
               provider_id = excluded.provider_id, plan_rev = excluded.plan_rev, \
               articles_ok = excluded.articles_ok, \
               articles_present = excluded.articles_present, \
               articles_total = excluded.articles_total, \
               result = excluded.result, kind = excluded.kind, mode = excluded.mode, \
               lease_token = excluded.lease_token \
             WHERE verifications.result = 'ok' \
               AND NOT (verifications.kind = 'body' AND excluded.kind = 'stat' \
                 AND excluded.result = 'ok')";

const STAMP_LAST_BODY_VERIFY: &str = "UPDATE extents SET last_verified_at = ?2 \
             WHERE id = ?1 AND ?3 = 'ok' AND ?4 = ?5 \
               AND ?5 = article_count + COALESCE(parity_count, 0) AND ?6 = plan_rev \
               AND ?7 = 'body' \
               AND (last_verified_at IS NULL OR last_verified_at < ?2)";

const BACKBONE_STATUS: &str = concat!(
    "SELECT v.backbone, v.provider_id, v.verified_at, v.plan_rev, ",
    tally!(),
    ", v.articles_total, v.result, v.kind, v.mode, ",
    counts!(),
    " FROM verifications v JOIN extents e ON e.id = v.extent_id \
         WHERE v.extent_id = ?1 AND ",
    latest!(),
    " ORDER BY v.backbone"
);

const BODY_CHECKS: &str = concat!(
    "SELECT b.backbone, b.provider_id, b.verified_at, b.plan_rev, b.articles_ok, \
           b.articles_total, b.result, b.kind, b.mode, (b.kind = 'body' AND ",
    body_on_record!(),
    ") FROM verifications b JOIN extents e ON e.id = b.extent_id \
         WHERE b.extent_id = ?1 AND b.plan_rev = e.plan_rev \
           AND (b.kind = 'body' OR (b.mode = 'size' AND b.result = 'corrupt')) \
           AND NOT EXISTS (SELECT 1 FROM verifications g \
             WHERE g.extent_id = b.extent_id AND g.backbone = b.backbone \
               AND g.plan_rev = b.plan_rev AND g.verified_at > b.verified_at \
               AND (g.kind = 'body' OR (b.kind <> 'body' AND g.mode = 'size' \
                 AND g.result = 'corrupt'))) \
         ORDER BY b.backbone, b.verified_at"
);

const START_SAFETY_RELEASE: &str =
    "UPDATE extents SET safety_state = 'releasing', release_evidence = ?2, \
               evict_seq = evict_seq + 1 WHERE id = ?1";

const COMPLETE_SAFETY_RELEASE: &str =
    "UPDATE extents SET safety_state = 'released', release_evidence = ?2, \
               released_at = ?3, hot_safety_bytes = cipher_size, \
               last_read_at = COALESCE(last_read_at, created_at), \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1";

const ADVANCE_RELEASE_AT_VERIFY: &str = concat!(
    "UPDATE outbox SET stage = 'done', updated_at = ?5, cursor = 0, last_error = NULL, ",
    unlease!(),
    " WHERE ",
    held!()
);

const RAISE_ESCALATION: &str =
    "INSERT INTO verify_escalations(backbone, until, raised_at, extent_id, result) \
         SELECT ?1, ?2, ?3, ?4, ?5 WHERE NOT EXISTS (SELECT 1 FROM verify_raises \
           WHERE extent_id = ?4 AND backbone = ?1 AND plan_rev = ?6) \
         ON CONFLICT(backbone) DO UPDATE SET until = excluded.until, \
           raised_at = excluded.raised_at, extent_id = excluded.extent_id, \
           result = excluded.result \
         WHERE excluded.until > verify_escalations.until";

const ALREADY_RAISED: &str =
    "SELECT 1 FROM verify_raises WHERE extent_id = ?1 AND backbone = ?2 AND plan_rev = ?3";

const LIST_ESCALATIONS: &str =
    "SELECT backbone, until, raised_at, extent_id, result FROM verify_escalations \
             WHERE until > ?1 ORDER BY backbone";

const GUARD_FINISH_RELEASE: &str = concat!(
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE ",
    held!(),
    " AND stage = 'release' AND lease_until >= ?5) \
         OR NOT EXISTS (SELECT 1 FROM extents WHERE id = ?1 \
           AND safety_state = 'releasing')"
);

const ADVANCE_RELEASE: &str = concat!(
    "UPDATE outbox SET stage = 'done', updated_at = ?5, ",
    unlease!(),
    " WHERE ",
    held!()
);

const FINISH_SAFETY_RELEASE: &str =
    "UPDATE extents SET safety_state = 'released', released_at = ?2, \
               hot_safety_bytes = cipher_size, \
               last_read_at = COALESCE(last_read_at, created_at), \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1";

const GUARD_REOPEN_RELEASE: &str = concat!(
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE ",
    held!(),
    " AND stage = 'release' AND lease_until >= ?5)"
);

const REOPEN_RELEASE: &str = "UPDATE extents SET safety_state = 'held', release_evidence = NULL, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND safety_state = 'releasing'";

const REDRIVE_CURSOR: &str = "SELECT v FROM scan_cursors WHERE k = 'redrive'";

const REVIVE_CURSOR: &str = "SELECT v FROM scan_cursors WHERE k = 'revive'";

const PACK_CURSOR: &str = "SELECT v FROM scan_cursors WHERE k = 'pack'";

const PACK_WINDOW: &str = "SELECT extent_id FROM articles WHERE extent_id > ?1 AND idx = 0 \
             ORDER BY extent_id LIMIT ?2";

const STORE_PACKED_FROM_ROWS: &str = "UPDATE extents SET plan = ?2, \
                       posted_at = COALESCE((SELECT MAX(posted_at) FROM articles \
                                              WHERE extent_id = ?1), ?5), \
                       reposted_at = (SELECT MAX(reposted_at) FROM articles \
                                       WHERE extent_id = ?1) \
                     WHERE id = ?1 AND plan IS NULL AND cipher_size = ?3 \
                       AND article_count = ?4 \
                       AND (SELECT COUNT(*) FROM articles \
                             WHERE extent_id = ?1 AND state = 'posted') = ?4";

const DROP_PACKED_ARTICLES: &str = "DELETE FROM articles WHERE extent_id = ?1 \
                       AND (SELECT plan FROM extents WHERE id = ?1) IS NOT NULL";

const OUTBOX_STATS: &str = "SELECT stage, COUNT(*) FROM outbox GROUP BY stage";

const LAST_DISPATCH_AT: &str = "SELECT v FROM meta WHERE k = 'last_dispatch_at'";

const DEFER: &str = concat!(
    "UPDATE outbox SET next_at = ?5, updated_at = ?6, attempts = MAX(attempts - 1, 0), ",
    unlease!(),
    " WHERE ",
    held!()
);

const DEFER_PG: &str = concat!(
    "UPDATE outbox SET next_at = ?5, updated_at = ?6, attempts = GREATEST(attempts - 1, 0), ",
    unlease!(),
    " WHERE ",
    held!()
);

const DEFER_WITH_CURSOR: &str = concat!(
    "UPDATE outbox SET next_at = ?5, updated_at = ?6, cursor = ?7, \
         attempts = MAX(attempts - 1, 0), ",
    unlease!(),
    " WHERE ",
    held!()
);

const DEFER_WITH_CURSOR_PG: &str = concat!(
    "UPDATE outbox SET next_at = ?5, updated_at = ?6, cursor = ?7, \
         attempts = GREATEST(attempts - 1, 0), ",
    unlease!(),
    " WHERE ",
    held!()
);

const MARK_ARTICLES_POSTED: &str =
    "UPDATE articles SET state = 'posted', provider_id = ?3, posted_at = ?4 \
             WHERE extent_id = ?1 AND idx IN (SELECT value FROM json_each(?2)) \
               AND (SELECT plan FROM extents WHERE id = ?1) IS NULL";

const MARK_ARTICLES_POSTED_PG: &str = "UPDATE articles SET state = 'posted', provider_id = ?3, posted_at = ?4 \
             WHERE extent_id = ?1 AND idx IN (SELECT value::bigint FROM jsonb_array_elements_text(?2::jsonb) AS j(value)) \
               AND (SELECT plan FROM extents WHERE id = ?1) IS NULL";

const MARK_PACKED_POSTED: &str = "UPDATE extents SET posted_at = ?2 \
         WHERE id = ?1 AND plan IS NOT NULL AND posted_at IS NULL \
           AND article_count + COALESCE(parity_count, 0) = \
               (SELECT COUNT(DISTINCT value) FROM json_each(?3) \
                 WHERE value < article_count + COALESCE(parity_count, 0))";

const MARK_PACKED_POSTED_PG: &str = "UPDATE extents SET posted_at = ?2 \
         WHERE id = ?1 AND plan IS NOT NULL AND posted_at IS NULL \
           AND article_count + COALESCE(parity_count, 0) = \
               (SELECT COUNT(DISTINCT value::bigint) FROM jsonb_array_elements_text(?3::jsonb) AS j(value) \
                 WHERE value::bigint < article_count + COALESCE(parity_count, 0))";

const MARK_ARTICLES_REPOSTED: &str =
    "UPDATE articles SET reposted_at = MAX(COALESCE(reposted_at, ?3), ?3) \
             WHERE extent_id = ?1 AND idx IN (SELECT value FROM json_each(?2)) \
               AND (SELECT plan FROM extents WHERE id = ?1) IS NULL";

const MARK_ARTICLES_REPOSTED_PG: &str = "UPDATE articles SET reposted_at = GREATEST(COALESCE(reposted_at, ?3), ?3) \
             WHERE extent_id = ?1 AND idx IN (SELECT value::bigint FROM jsonb_array_elements_text(?2::jsonb) AS j(value)) \
               AND (SELECT plan FROM extents WHERE id = ?1) IS NULL";

const MARK_PACKED_REPOSTED: &str =
    "UPDATE extents SET reposted_at = MAX(COALESCE(reposted_at, ?2), ?2) \
             WHERE id = ?1 AND plan IS NOT NULL";

const MARK_PACKED_REPOSTED_PG: &str =
    "UPDATE extents SET reposted_at = GREATEST(COALESCE(reposted_at, ?2), ?2) \
             WHERE id = ?1 AND plan IS NOT NULL";

const RAISE_ONCE: &str =
    "INSERT OR IGNORE INTO verify_raises(extent_id, backbone, plan_rev, raised_at) \
         VALUES (?1, ?2, ?3, ?4)";

const RAISE_ONCE_PG: &str = "INSERT INTO verify_raises(extent_id, backbone, plan_rev, raised_at) \
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING";

const DUE_PAGE: &str = "SELECT extent_id, generation_id, stage, next_at FROM outbox \
                 WHERE stage = ?4 AND next_at <= ?1 \
                   AND (lease_until IS NULL OR lease_until < ?1) \
                   AND (sent_at IS NULL OR sent_at < next_at OR sent_at <= ?3) \
                 ORDER BY next_at, rowid LIMIT ?2";

const DUE_PAGE_PG: &str = "SELECT extent_id, generation_id, stage, next_at FROM outbox \
                 WHERE stage = ?4 AND next_at <= ?1 \
                   AND (lease_until IS NULL OR lease_until < ?1) \
                   AND (sent_at IS NULL OR sent_at < next_at OR sent_at <= ?3) \
                 ORDER BY next_at, seq LIMIT ?2";

const MARK_SENT: &str = "UPDATE outbox SET sent_at = ?1 \
               WHERE extent_id IN (SELECT value FROM json_each(?2)) \
                 AND +stage IN ('post', 'verify', 'release') AND +next_at <= ?1 \
                 AND (lease_until IS NULL OR lease_until < ?1)";

// Keep eligibility a residual filter so a short ID list cannot turn
// into a scan of every due row through outbox_due.
const MARK_SENT_PG: &str = "UPDATE outbox SET sent_at = ?1 \
               WHERE extent_id = ANY (ARRAY(SELECT jsonb_array_elements_text(?2::jsonb))) \
                 AND CASE WHEN stage IN ('post', 'verify', 'release') AND next_at <= ?1 \
                   THEN lease_until IS NULL OR lease_until < ?1 ELSE FALSE END";

const UNMARK_SENT: &str = "UPDATE outbox SET sent_at = NULL \
               WHERE extent_id IN (SELECT value FROM json_each(?2)) AND sent_at = ?1";

const UNMARK_SENT_PG: &str = "UPDATE outbox SET sent_at = NULL \
               WHERE extent_id IN (SELECT value FROM jsonb_array_elements_text(?2::jsonb) AS j(value)) AND sent_at = ?1";

const BURY_EXHAUSTED_PG: &str = "UPDATE outbox \
       SET stage = 'dead', updated_at = ?2 \
     WHERE attempts > 50 AND stage IN ('post', 'verify', 'release') AND attempts > ?1 \
       AND (lease_until IS NULL OR lease_until < ?2)";

const BURY_ANY: &str = "UPDATE outbox SET stage = 'dead', updated_at = ?2 \
         WHERE stage IN ('post', 'verify', 'release') AND attempts > ?1 \
           AND (lease_until IS NULL OR lease_until < ?2)";

const REDRIVE_WINDOW: &str = "SELECT id FROM extents INDEXED BY extents_safety \
              WHERE safety_state IN ('held', 'releasing') \
                AND id > ?1 ORDER BY id LIMIT ?2";

const REDRIVE_WINDOW_PG: &str = "SELECT id FROM extents \
              WHERE safety_state IN ('held', 'releasing') \
                AND id > ?1 ORDER BY id LIMIT ?2";

const REDRIVE: &str = concat!(
    "UPDATE outbox SET stage = 'verify', next_at = ?1, cursor = 0, attempts = 0, \
           last_error = NULL, updated_at = ?1, sent_at = NULL, ",
    unlease!(),
    // Driven from the window of the index, each outbox row found by
    // its key: `CROSS JOIN` fixes the order and the unary `+` keeps
    // the planner off `outbox_due`, which would walk every `done`
    // row (every extent ever posted) once per run.
    " WHERE +stage = 'done' AND extent_id IN ( \
           SELECT e.id FROM extents e INDEXED BY extents_safety \
             CROSS JOIN outbox o ON o.extent_id = e.id \
            WHERE e.safety_state IN ('held', 'releasing') AND e.safety_state = 'held' \
              AND e.id > ?4 AND e.id <= ?5 AND +o.stage = 'done' AND ",
    live_ref!("e.id"),
    " AND (SELECT COUNT(*) FROM verifications v \
                    WHERE v.extent_id = e.id \
                      AND v.backbone IN (SELECT value FROM json_each(?2)) AND ",
    latest!(),
    " AND ",
    counts!(),
    ") < ?3) RETURNING 1"
);

const REDRIVE_PG: &str = concat!(
        "UPDATE outbox SET stage = 'verify', next_at = ?1, cursor = 0, attempts = 0, \
           last_error = NULL, updated_at = ?1, sent_at = NULL, ",
        unlease!(),
        // A sparse ID range can span much of the outbox. Probe only
        // the selected IDs and keep the live-reference check correlated
        // so it cannot become a join over the whole key span.
        " WHERE extent_id = ANY (ARRAY(SELECT jsonb_array_elements_text(?4::jsonb))) \
            AND CASE WHEN stage = 'done' THEN 1 = (SELECT 1 FROM extents e \
              WHERE e.id = outbox.extent_id AND e.safety_state = 'held' \
                AND 1 = (SELECT 1 FROM generation_extents lr \
                  JOIN generations lg ON lg.id = lr.generation_id \
                 WHERE lr.extent_id = e.id AND lg.state = 'live' LIMIT 1) \
                AND (SELECT COUNT(*) FROM verifications v \
                    WHERE v.extent_id = e.id \
                      AND v.backbone IN (SELECT value FROM jsonb_array_elements_text(?2::jsonb) AS j(value)) AND ",
        latest!(),
        " AND ",
        counts!(),
        ") < ?3) ELSE FALSE END RETURNING 1"
    );

const REVIVE_WINDOW: &str = "SELECT rowid FROM outbox WHERE rowid > ?1 ORDER BY rowid LIMIT ?2";

const REVIVE_WINDOW_PG: &str = "SELECT seq FROM outbox WHERE seq > ?1 ORDER BY seq LIMIT ?2";

const REVIVE: &str = concat!(
    "UPDATE outbox SET stage = CASE (SELECT e.safety_state FROM extents e \
                                          WHERE e.id = outbox.extent_id) \
                                   WHEN 'held' THEN 'post' WHEN 'releasing' THEN 'release' \
                                   ELSE 'done' END, \
                attempts = 0, cursor = 0, last_error = NULL, next_at = ?1, updated_at = ?1, \
                sent_at = NULL, ",
    unlease!(),
    // `+stage`: the window is found by rowid. Through the stage
    // index the statement would visit every cancelled row there is.
    " WHERE rowid > ?2 AND rowid <= ?3 AND +stage = 'cancelled' AND ",
    live_ref!("outbox.extent_id"),
    " RETURNING 1"
);

const REVIVE_PG: &str = concat!(
    "UPDATE outbox SET stage = CASE (SELECT e.safety_state FROM extents e \
                                          WHERE e.id = outbox.extent_id) \
                                   WHEN 'held' THEN 'post' WHEN 'releasing' THEN 'release' \
                                   ELSE 'done' END, \
                attempts = 0, cursor = 0, last_error = NULL, next_at = ?1, updated_at = ?1, \
                sent_at = NULL, ",
    unlease!(),
    // `+stage`: the window is found by rowid. Through the stage
    // index the statement would visit every cancelled row there is.
    " WHERE seq > ?2 AND seq <= ?3 AND stage = 'cancelled' AND ",
    live_ref!("outbox.extent_id"),
    " RETURNING 1"
);

const SET_SCAN_CURSOR: &str = "INSERT OR REPLACE INTO scan_cursors(k, v) VALUES (?1, ?2)";

const SET_SCAN_CURSOR_PG: &str =
    "INSERT INTO scan_cursors(k, v) VALUES (?1, ?2) ON CONFLICT (k) DO UPDATE SET v = excluded.v";

const RECORD_DISPATCH: &str = "INSERT OR REPLACE INTO meta(k, v) VALUES ('last_dispatch_at', ?1)";

const RECORD_DISPATCH_PG: &str = "INSERT INTO meta(k, v) VALUES ('last_dispatch_at', ?1) ON CONFLICT (k) DO UPDATE SET v = excluded.v";

macro_rules! release_guard {
    ($states:literal, $backbones:literal) => {
        concat!(
            "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE ",
            held!(),
            " AND lease_until >= ?6) \
     OR NOT ",
            live_ref!("?1"),
            " OR NOT EXISTS (SELECT 1 FROM extents WHERE id = ?1 \
          AND safety_state ",
            $states,
            ") \
     OR (SELECT COUNT(*) FROM verifications v JOIN extents e ON e.id = v.extent_id \
          WHERE ",
            fresh_pass!($backbones),
            " AND NOT (?9 = 1 \
            AND EXISTS (SELECT 1 FROM verify_escalations z \
              WHERE z.backbone = v.backbone AND z.until > e.created_at) \
            AND NOT EXISTS (SELECT 1 FROM verifications b \
              WHERE b.extent_id = v.extent_id AND b.backbone = v.backbone AND ",
            body_on_record!(),
            "))) < ?5 \
     OR ((?8 = 1 OR (?9 = 1 AND EXISTS (SELECT 1 FROM verify_escalations z \
            JOIN extents o ON o.id = ?1 \
            WHERE z.until > o.created_at \
              AND z.backbone IN (",
            $backbones,
            ")))) \
         AND NOT EXISTS (SELECT 1 FROM verifications v \
          JOIN extents e ON e.id = v.extent_id WHERE ",
            fresh_pass!($backbones),
            " AND EXISTS (SELECT 1 FROM verifications b \
            WHERE b.extent_id = v.extent_id AND b.backbone = v.backbone AND ",
            body_on_record!(),
            ")))"
        )
    };
}

const GUARD_RELEASE_JOB: &str = release_guard!(
    "IN ('held', 'releasing')",
    "SELECT value FROM json_each(?7)"
);
const GUARD_RELEASE_JOB_PG: &str = release_guard!(
    "IN ('held', 'releasing')",
    "SELECT value FROM jsonb_array_elements_text(?7::jsonb) AS j(value)"
);

const GUARD_RELEASE_AT_VERIFY: &str = release_guard!("= 'held'", "SELECT value FROM json_each(?7)");
const GUARD_RELEASE_AT_VERIFY_PG: &str = release_guard!(
    "= 'held'",
    "SELECT value FROM jsonb_array_elements_text(?7::jsonb) AS j(value)"
);

fn bury_sql(dialect: crate::ports::Dialect, indexed: bool) -> String {
    let sql = if indexed {
        dialect.pick(BURY_EXHAUSTED, BURY_EXHAUSTED_PG)
    } else {
        BURY_ANY
    };
    format!("{sql} RETURNING 1")
}

/// Actual Postgres texts and representative wire types for typed PREPARE.
#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(String, Vec<SqlValue>)> {
    const I: SqlValue = SqlValue::Int(0);
    const T: SqlValue = SqlValue::Text(String::new());
    const B: SqlValue = SqlValue::Blob(Vec::new());
    vec![
        (held_guard!().to_owned(), vec![T, T, T, I]),
        (RENEW.to_owned(), vec![T, T, T, I, I]),
        (CLAIM.to_owned(), vec![T, T, T, T, I, I]),
        (ADVANCE.to_owned(), vec![T, T, T, I, T, I, I]),
        (FAIL.to_owned(), vec![T, T, T, I, I, T, I]),
        (SET_CURSOR.to_owned(), vec![T, T, T, I, I]),
        (JOB_EXTENT.to_owned(), vec![T, T]),
        (READ_ARTICLES.to_owned(), vec![T]),
        (
            INSERT_UNPACKED_ARTICLE.to_owned(),
            vec![T, I, T, T, B, I, I, B, T],
        ),
        (FINISH_UNPACKED_PLAN.to_owned(), vec![T, I]),
        (STORE_PACKED_PLAN.to_owned(), vec![T, I, B, I, B, I]),
        (MARK_ONE_POSTED.to_owned(), vec![T, T, T, I, I, T, I]),
        (GUARD_POSTED_PLAN.to_owned(), vec![T]),
        (CHECK_LEASE.to_owned(), vec![T, T, T, I]),
        (
            WRITE_VERIFICATION.to_owned(),
            vec![T, T, T, I, I, I, I, T, T, T, I],
        ),
        (STAMP_LAST_BODY_VERIFY.to_owned(), vec![T, I, T, I, I, I, T]),
        (BACKBONE_STATUS.to_owned(), vec![T]),
        (BODY_CHECKS.to_owned(), vec![T]),
        (START_SAFETY_RELEASE.to_owned(), vec![T, T]),
        (COMPLETE_SAFETY_RELEASE.to_owned(), vec![T, T, I]),
        (ADVANCE_RELEASE_AT_VERIFY.to_owned(), vec![T, T, T, I, I]),
        (RAISE_ESCALATION.to_owned(), vec![T, I, I, T, T, I]),
        (ALREADY_RAISED.to_owned(), vec![T, T, I]),
        (LIST_ESCALATIONS.to_owned(), vec![I]),
        (GUARD_FINISH_RELEASE.to_owned(), vec![T, T, T, I, I]),
        (ADVANCE_RELEASE.to_owned(), vec![T, T, T, I, I]),
        (FINISH_SAFETY_RELEASE.to_owned(), vec![T, I]),
        (GUARD_REOPEN_RELEASE.to_owned(), vec![T, T, T, I, I]),
        (REOPEN_RELEASE.to_owned(), vec![T]),
        (REDRIVE_CURSOR.to_owned(), vec![]),
        (REVIVE_CURSOR.to_owned(), vec![]),
        (PACK_CURSOR.to_owned(), vec![]),
        (PACK_WINDOW.to_owned(), vec![T, I]),
        (STORE_PACKED_FROM_ROWS.to_owned(), vec![T, B, I, I, I]),
        (DROP_PACKED_ARTICLES.to_owned(), vec![T]),
        (OUTBOX_STATS.to_owned(), vec![]),
        (LAST_DISPATCH_AT.to_owned(), vec![]),
        (DEFER_PG.to_owned(), vec![T, T, T, I, I, I]),
        (DEFER_WITH_CURSOR_PG.to_owned(), vec![T, T, T, I, I, I, I]),
        (MARK_ARTICLES_POSTED_PG.to_owned(), vec![T, T, T, I]),
        (MARK_PACKED_POSTED_PG.to_owned(), vec![T, I, T]),
        (MARK_ARTICLES_REPOSTED_PG.to_owned(), vec![T, T, I]),
        (MARK_PACKED_REPOSTED_PG.to_owned(), vec![T, I]),
        (RAISE_ONCE_PG.to_owned(), vec![T, T, I, I]),
        (DUE_PAGE_PG.to_owned(), vec![I, I, I, T]),
        (MARK_SENT_PG.to_owned(), vec![I, T]),
        (UNMARK_SENT_PG.to_owned(), vec![I, T]),
        (REDRIVE_WINDOW_PG.to_owned(), vec![T, I]),
        (REDRIVE_PG.to_owned(), vec![I, T, I, T]),
        (REVIVE_WINDOW_PG.to_owned(), vec![I, I]),
        (REVIVE_PG.to_owned(), vec![I, I, I]),
        (SET_SCAN_CURSOR_PG.to_owned(), vec![T, T]),
        (RECORD_DISPATCH_PG.to_owned(), vec![I]),
        (
            GUARD_RELEASE_JOB_PG.to_owned(),
            vec![T, T, T, I, I, I, T, I, I],
        ),
        (
            GUARD_RELEASE_AT_VERIFY_PG.to_owned(),
            vec![T, T, T, I, I, I, T, I, I],
        ),
        (bury_sql(crate::ports::Dialect::Postgres, false), vec![I, I]),
        (bury_sql(crate::ports::Dialect::Postgres, true), vec![I, I]),
    ]
}

#[cfg(all(test, feature = "pg-test-record", not(target_arch = "wasm32")))]
mod pg_plan_tests {
    use super::super::gc::GC_ORPHAN_WINDOW_PG;
    use super::{MARK_SENT_PG, REDRIVE_PG, REDRIVE_WINDOW_PG};
    use serde_json::Value;
    use std::path::{Path, PathBuf};
    use tokio_postgres::{NoTls, SimpleQueryMessage, Transaction};

    fn pg(sql: &str) -> String {
        sql.replace('?', "$")
    }

    async fn explain(tx: &Transaction<'_>, statement: &str) -> Value {
        let sql = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE {statement}");
        let results = tx.simple_query(&sql).await.unwrap();
        let plan = results.iter().find_map(|message| match message {
            SimpleQueryMessage::Row(row) => row.get(0),
            _ => None,
        });
        let json: Value =
            serde_json::from_str(plan.expect("EXPLAIN did not return a plan")).unwrap();
        json[0]["Plan"].clone()
    }

    fn bounded_plan(plan: &Value, name: &str, window: usize) {
        let get = |key: &str| plan[key].as_f64().unwrap_or_default();
        if let Some(table) = plan["Relation Name"].as_str() {
            // Include rejected tuples, not just those emitted by the scan.
            let visited = (get("Actual Rows")
                + get("Rows Removed by Filter")
                + get("Rows Removed by Index Recheck"))
                * get("Actual Loops");
            let cap = (window * 4) as f64;
            assert!(
                visited <= cap && get("Index Searches") <= cap,
                "{name}: {table} visited {visited} tuples, {} index searches for {window} ids",
                get("Index Searches")
            );
        }
        if let Some(children) = plan["Plans"].as_array() {
            for child in children {
                bounded_plan(child, name, window);
            }
        }
    }

    #[tokio::test]
    async fn postgres_background_windows_keep_bounded_scans() {
        let Ok(url) = std::env::var("VELMORA_TEST_PG_URL") else {
            return;
        };
        let migrations = std::env::var_os("VELMORA_TEST_PG_BASELINE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workers/s3-bridge/pg")
            });
        let (mut db, conn) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        let driver = tokio::spawn(conn);
        let tx = db.transaction().await.unwrap();
        let pid: i32 = tx
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        let schema = format!("outbox_plan_{pid}");
        tx.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema}, pg_temp"
        ))
        .await
        .unwrap();
        let migration = |name: &str| std::fs::read_to_string(migrations.join(name)).unwrap();
        tx.batch_execute(&migration("0001_baseline_pre.sql"))
            .await
            .unwrap();
        tx.batch_execute(
            "INSERT INTO usage_global(id) VALUES (1), (2);
             INSERT INTO buckets (id,name,owner,bdk_wrapped,kek_version,created_at)
                 VALUES ('b','bucket','owner',''::bytea,1,0);
             INSERT INTO generations (id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at)
                 SELECT 'g'||lpad(i::text,6,'0'),'b','key','live',1,'etag','{}','{}',1,0
                   FROM generate_series(1,100000) i;
             INSERT INTO extents (id,bucket_id,generation_id,state,seq,plain_offset,plain_size,cipher_size,
                                  media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at)
                 SELECT 'x'||lpad(i::text,6,'0'),'b','g'||lpad(i::text,6,'0'),'committed',i,i-1,1,1,
                        ''::bytea,''::bytea,''::bytea,''::bytea,
                        CASE WHEN i < 10000 OR i > 79000 OR i % 137 = 0 THEN 'held' ELSE 'released' END,0
                   FROM generate_series(1,100000) i;
             INSERT INTO generation_extents (generation_id,seq,extent_id,plain_offset)
                 SELECT generation_id,seq,id,plain_offset FROM extents;
             INSERT INTO outbox (extent_id,generation_id,stage,next_at,updated_at)
                 SELECT id,generation_id,'done',0,0 FROM extents ORDER BY seq;
             INSERT INTO extents (id,bucket_id,state,plain_size,cipher_size,media_header,
                                  plain_md5,plain_sha256,cipher_sha256,safety_state,created_at)
                 SELECT 'orphan'||i,'b','staged',1,1,''::bytea,''::bytea,''::bytea,''::bytea,'held',0
                   FROM generate_series(1,500) i;
             INSERT INTO gc(extent_id,action,due_at)
                 SELECT id,'delete_safety',10 FROM extents WHERE id LIKE 'orphan%';
             INSERT INTO uploads (id,bucket_id,key,content_json,user_meta_json,state,initiated_at)
                 SELECT 'upload'||seq,'b','key','{}','{}','open',0 FROM extents WHERE seq IS NOT NULL;
             INSERT INTO upload_parts (upload_id,part_number,extent_id,size,etag,uploaded_at)
                 SELECT 'upload'||seq,1,id,1,'etag',0 FROM extents WHERE seq IS NOT NULL;",
        ).await.unwrap();
        tx.batch_execute(&migration("0002_baseline_post.sql"))
            .await
            .unwrap();
        tx.batch_execute(
            "ANALYZE extents; ANALYZE outbox; ANALYZE generation_extents; ANALYZE generations; \
                          ANALYZE gc; ANALYZE uploads; ANALYZE upload_parts",
        )
        .await
        .unwrap();

        let ids = tx
            .query(&pg(REDRIVE_WINDOW_PG), &[&"x010000", &500_i64])
            .await
            .unwrap();
        assert_eq!(ids.len(), 500);
        let selected: Vec<&str> = ids.iter().map(|row| row.get(0)).collect();
        let first = serde_json::to_string(&selected[..1]).unwrap();
        let selected = serde_json::to_string(&selected).unwrap();
        tx.batch_execute(&format!(
            "PREPARE redrive(bigint,text,bigint,text) AS {}",
            pg(REDRIVE_PG)
        ))
        .await
        .unwrap();
        let plan = explain(&tx, &format!("redrive(1,'[]',1,'{selected}')")).await;
        assert_eq!(plan["Actual Rows"].as_f64(), Some(ids.len() as f64));
        bounded_plan(&plan, "redrive", ids.len());

        tx.batch_execute(&format!(
            "PREPARE mark_sent(bigint,text) AS {}",
            pg(MARK_SENT_PG)
        ))
        .await
        .unwrap();
        let plan = explain(&tx, &format!("mark_sent(2,'{first}')")).await;
        bounded_plan(&plan, "mark sent", 1);
        let marked: i64 = tx
            .query_one("SELECT count(*) FROM outbox WHERE sent_at = 2", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(marked, 1);

        tx.batch_execute(&format!(
            "PREPARE orphans(bigint,bigint,bigint,bigint) AS {}",
            pg(GC_ORPHAN_WINDOW_PG)
        ))
        .await
        .unwrap();
        let plan = explain(&tx, "orphans(10,0,0,500)").await;
        assert_eq!(plan["Actual Rows"].as_f64(), Some(500.));
        bounded_plan(&plan, "orphan window", 500);
        let candidates = tx
            .query(
                &pg(GC_ORPHAN_WINDOW_PG),
                &[&10_i64, &0_i64, &0_i64, &500_i64],
            )
            .await
            .unwrap();
        assert!(candidates.iter().all(|row| row.get::<_, bool>(3)));
        tx.rollback().await.unwrap();
        drop(db);
        driver.await.unwrap().unwrap();
    }
}
