//! Outbox leases with fencing tokens, article plans, verification and release (catalogue lane B).
//!
//! `claim` bumps `outbox.lease_token` and hands it out in a [`Lease`].
//! Every later write names the row by extent, generation, stage **and**
//! token, so it changes nothing once the row was cancelled, advanced or
//! claimed by someone else. Giving a lease up (`advance`, `fail`, `defer`,
//! `finish_release`) bumps the token as well: a released lease is dead.
//! Writes that touch more than one table are batches with that predicate
//! as their `tx_guard`.

use super::uploads::{int, ms, text, Cols, Stmt};
use super::SqlCatalog;
use crate::ports::{Guard, Lease, Sql, SqlValue};
use crate::types::{
    ArticleRow, ArticleState, BackboneStatus, BridgeError, Bucket, BucketId, DueRow, ExtentId,
    ExtentRow, ExtentState, FailClass, GenerationId, GenerationState, JobExtent, OutboxStage,
    OutboxStats, Result, SafetyState, UnixMs, VerificationRow, VerifyResult,
};

/// Lease length. Jobs renew before each article.
const LEASE_MS: i64 = 600_000;

// `outbox.updated_at` is the time of the row's last lease transition
// (claim, advance, fail, defer, done, cancel). `renew` and `set_cursor`
// leave it alone, so under a held lease it is the claim time; the release
// guard uses it to tell this job's verifications from older ones.

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

/// Whether that row is a full pass of the current plan.
macro_rules! counts {
    () => {
        "(v.result = 'ok' AND v.articles_ok = v.articles_total \
           AND v.articles_total = COALESCE(e.article_count, -1))"
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
            "UPDATE outbox SET lease_token = lease_token + 1, lease_owner = ?4, \
               lease_until = ?5, attempts = attempts + 1, updated_at = ?6 \
             WHERE extent_id = ?1 AND generation_id = ?2 AND stage = ?3 AND next_at <= ?6 \
               AND (lease_until IS NULL OR lease_until < ?6) \
             RETURNING lease_token, attempts, cursor",
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
    }))
}

pub(super) async fn renew<S: Sql>(c: &SqlCatalog<S>, l: &Lease, now: UnixMs) -> Result<bool> {
    let sql = concat!("UPDATE outbox SET lease_until = ?5 WHERE ", held!());
    fenced(c, sql, l, [ms(now.plus_ms(LEASE_MS))]).await
}

/// Moves the row to `to` and gives the lease up. Attempts and cursor
/// restart: they are per stage.
pub(super) async fn advance<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    to: OutboxStage,
    next_at: UnixMs,
    now: UnixMs,
) -> Result<bool> {
    let sql = concat!(
        "UPDATE outbox SET stage = ?5, next_at = ?6, updated_at = ?7, attempts = 0, cursor = 0, \
           last_error = NULL, ",
        unlease!(),
        " WHERE ",
        held!()
    );
    fenced(c, sql, l, [text(to.as_str()), ms(next_at), ms(now)]).await
}

pub(super) async fn fail<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    class: FailClass,
    next_at: UnixMs,
    now: UnixMs,
) -> Result<bool> {
    let sql = concat!(
        "UPDATE outbox SET next_at = ?5, last_error = ?6, updated_at = ?7, ",
        unlease!(),
        " WHERE ",
        held!()
    );
    fenced(c, sql, l, [ms(next_at), text(class.as_str()), ms(now)]).await
}

/// Like `fail`, but hands back the attempt the claim counted.
pub(super) async fn defer<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    next_at: UnixMs,
    now: UnixMs,
) -> Result<bool> {
    let sql = concat!(
        "UPDATE outbox SET next_at = ?5, updated_at = ?6, attempts = MAX(attempts - 1, 0), ",
        unlease!(),
        " WHERE ",
        held!()
    );
    fenced(c, sql, l, [ms(next_at), ms(now)]).await
}

pub(super) async fn set_cursor<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    cursor: u32,
    _now: UnixMs,
) -> Result<bool> {
    let sql = concat!("UPDATE outbox SET cursor = ?5 WHERE ", held!());
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
    let rows = c
        .sql
        .query(
            "SELECT e.id, e.bucket_id, e.generation_id, e.state, e.seq, e.plain_offset, \
               e.plain_size, e.cipher_size, e.media_header, e.key_mode, e.wrapped_file_key, \
               e.plain_md5, e.plain_sha256, e.cipher_sha256, e.safety_state, e.article_count, \
               e.plan_rev, e.last_verified_at, e.release_evidence, e.released_at, e.created_at, \
               b.id, b.name, b.owner, b.bdk_wrapped, b.kek_version, b.disposable, b.created_at, \
               g.state \
             FROM extents e JOIN buckets b ON b.id = e.bucket_id \
             JOIN generations g ON g.id = e.generation_id \
             WHERE e.id = ?1 AND e.generation_id = ?2",
            &[text(extent.as_str()), text(generation.as_str())],
        )
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
    }))
}

pub(super) async fn articles<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
) -> Result<Vec<ArticleRow>> {
    let rows = c
        .sql
        .query(
            "SELECT extent_id, idx, message_id, newsgroup, headers, cipher_offset, cipher_len, \
               payload_sha256, state, provider_id, posted_at \
             FROM articles WHERE extent_id = ?1 ORDER BY idx",
            &[text(extent.as_str())],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(ArticleRow {
            extent_id: ExtentId::new(r.text()?),
            idx: r.num()?,
            message_id: r.text()?,
            newsgroup: r.text()?,
            headers: r.blob()?,
            cipher_offset: r.num()?,
            cipher_len: r.num()?,
            payload_sha256: r.array()?,
            state: r.parsed(ArticleState::parse)?,
            provider_id: r.opt_text()?,
            posted_at: r.opt_num()?.map(UnixMs),
        });
    }
    Ok(out)
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
            "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, cipher_offset, \
               cipher_len, payload_sha256, state) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'planned' \
             WHERE (SELECT article_count FROM extents WHERE id = ?1) IS NULL",
            vec![
                text(a.extent_id.as_str()),
                SqlValue::Int(i64::from(a.idx)),
                text(&a.message_id),
                text(&a.newsgroup),
                SqlValue::Blob(a.headers.clone()),
                int(a.cipher_offset)?,
                int(a.cipher_len)?,
                SqlValue::Blob(a.payload_sha256.to_vec()),
            ],
        ));
    }
    // Last: the inserts above key on the count still being unset.
    stmts.push((
        "UPDATE extents SET article_count = ?2, plan_rev = 1 \
         WHERE id = ?1 AND article_count IS NULL",
        vec![text(l.extent.as_str()), int(rows.len())?],
    ));
    if !fenced_batch(c, stmts).await? {
        return Ok(None);
    }
    articles(c, &l.extent).await.map(Some)
}

pub(super) async fn mark_posted<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    idx: u32,
    provider: &str,
    now: UnixMs,
) -> Result<bool> {
    let sql = concat!(
        "UPDATE articles SET state = 'posted', provider_id = ?6, posted_at = ?7 \
         WHERE extent_id = ?1 AND idx = ?5 AND EXISTS (SELECT 1 FROM outbox WHERE ",
        held!(),
        ")"
    );
    let extra = [SqlValue::Int(i64::from(idx)), text(provider), ms(now)];
    fenced(c, sql, l, extra).await
}

// ---------------------------------------------------------------------------
// Verification and release
// ---------------------------------------------------------------------------

/// Appends one verification result under the lease; a full pass of the
/// current plan also moves `extents.last_verified_at` forward.
pub(super) async fn record_verification<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    v: &VerificationRow,
) -> Result<bool> {
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
    ];
    let stmts = vec![
        (held_guard!(), lease_params(l, [])?),
        (
            // Two results for one backbone in the same millisecond: a
            // failure is never replaced, so the pair cannot count as a pass.
            "INSERT INTO verifications(extent_id, backbone, provider_id, verified_at, \
               plan_rev, articles_ok, articles_total, result) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT(extent_id, backbone, verified_at) DO UPDATE SET \
               provider_id = excluded.provider_id, plan_rev = excluded.plan_rev, \
               articles_ok = excluded.articles_ok, articles_total = excluded.articles_total, \
               result = excluded.result \
             WHERE verifications.result = 'ok'",
            row,
        ),
        (
            "UPDATE extents SET last_verified_at = ?2 \
             WHERE id = ?1 AND ?3 = 'ok' AND ?4 = ?5 AND ?5 = article_count AND ?6 = plan_rev \
               AND (last_verified_at IS NULL OR last_verified_at < ?2)",
            vec![
                text(v.extent_id.as_str()),
                ms(v.verified_at),
                text(v.result.as_str()),
                SqlValue::Int(i64::from(v.articles_ok)),
                SqlValue::Int(i64::from(v.articles_total)),
                SqlValue::Int(i64::from(v.plan_rev)),
            ],
        ),
    ];
    fenced_batch(c, stmts).await
}

/// Latest row per backbone for the extent's current plan. `counts` is true
/// only for a full pass (`ok`, `articles_ok = articles_total =
/// article_count`): a newer failure hides an older pass, and two providers
/// on one backbone are one row.
pub(super) async fn backbone_status<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
) -> Result<Vec<BackboneStatus>> {
    let sql = concat!(
        "SELECT v.backbone, v.provider_id, v.verified_at, v.plan_rev, v.articles_ok, \
           v.articles_total, v.result, ",
        counts!(),
        " FROM verifications v JOIN extents e ON e.id = v.extent_id \
         WHERE v.extent_id = ?1 AND ",
        latest!(),
        " ORDER BY v.backbone"
    );
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
            counts: r.num::<i64>()? != 0,
        });
    }
    Ok(out)
}

/// Authorizes deleting the safety copy. One batch whose guard requires:
/// the release lease still holds, the generation is live, the copy is
/// `held` (or `releasing`, when re-driven), and at least `required`
/// backbones count with a row recorded under this claim (between the claim
/// time and `now`). The lease must also be unexpired: an expired lease may
/// be taken over at any moment. Anything else is `Lost`.
pub(super) async fn begin_release<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    required: u32,
    evidence_json: &str,
    now: UnixMs,
) -> Result<Guard<()>> {
    if l.stage != OutboxStage::Release || required == 0 {
        return Err(BridgeError::Invalid(
            "release needs a release lease and at least one required backbone",
        ));
    }
    let guard = concat!(
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE ",
        held!(),
        " AND lease_until >= ?6) \
         OR NOT EXISTS (SELECT 1 FROM generations WHERE id = ?2 AND state = 'live') \
         OR NOT EXISTS (SELECT 1 FROM extents WHERE id = ?1 \
              AND safety_state IN ('held', 'releasing')) \
         OR (SELECT COUNT(*) FROM verifications v JOIN extents e ON e.id = v.extent_id \
              WHERE v.extent_id = ?1 AND v.verified_at <= ?6 \
                AND v.verified_at >= (SELECT updated_at FROM outbox WHERE extent_id = ?1) AND ",
        counts!(),
        " AND ",
        latest!(),
        ") < ?5"
    );
    let stmts = vec![
        (
            guard,
            lease_params(l, [SqlValue::Int(i64::from(required)), ms(now)])?,
        ),
        (
            "UPDATE extents SET safety_state = 'releasing', release_evidence = ?2 WHERE id = ?1",
            vec![text(l.extent.as_str()), text(evidence_json)],
        ),
    ];
    super::uploads::guarded(c, stmts).await
}

/// After the safety copy was deleted: `releasing` → `released`, row done.
pub(super) async fn finish_release<S: Sql>(
    c: &SqlCatalog<S>,
    l: &Lease,
    now: UnixMs,
) -> Result<bool> {
    let guard = concat!(
        "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE ",
        held!(),
        " AND stage = 'release' AND lease_until >= ?5) \
         OR NOT EXISTS (SELECT 1 FROM extents WHERE id = ?1 \
           AND safety_state = 'releasing')"
    );
    let done = concat!(
        "UPDATE outbox SET stage = 'done', updated_at = ?5, ",
        unlease!(),
        " WHERE ",
        held!()
    );
    let stmts = vec![
        (guard, lease_params(l, [ms(now)])?),
        (
            "UPDATE extents SET safety_state = 'released', released_at = ?2 WHERE id = ?1",
            vec![text(l.extent.as_str()), ms(now)],
        ),
        // Last: after this the lease no longer holds.
        (done, lease_params(l, [ms(now)])?),
    ];
    fenced_batch(c, stmts).await
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Rows a job could claim right now: live stage, due, not leased.
pub(super) async fn due<S: Sql>(c: &SqlCatalog<S>, now: UnixMs, limit: u32) -> Result<Vec<DueRow>> {
    let rows = c
        .sql
        .query(
            "SELECT extent_id, generation_id, stage FROM outbox \
             WHERE stage IN ('post', 'verify', 'release') AND next_at <= ?1 \
               AND (lease_until IS NULL OR lease_until < ?1) \
             ORDER BY next_at, extent_id LIMIT ?2",
            &[ms(now), SqlValue::Int(i64::from(limit))],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(DueRow {
            extent_id: ExtentId::new(r.text()?),
            generation_id: GenerationId::new(r.text()?),
            stage: r.parsed(OutboxStage::parse)?,
        });
    }
    Ok(out)
}

/// Moves unleased rows with more than `max_attempts` claims to `dead`.
pub(super) async fn bury_exhausted<S: Sql>(
    c: &SqlCatalog<S>,
    max_attempts: u32,
    now: UnixMs,
) -> Result<u64> {
    c.sql
        .exec(
            "UPDATE outbox SET stage = 'dead', updated_at = ?2 \
             WHERE stage IN ('post', 'verify', 'release') AND attempts > ?1 \
               AND (lease_until IS NULL OR lease_until < ?2)",
            &[SqlValue::Int(i64::from(max_attempts)), ms(now)],
        )
        .await
}

pub(super) async fn record_dispatch<S: Sql>(c: &SqlCatalog<S>, now: UnixMs) -> Result<()> {
    c.sql
        .exec(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('last_dispatch_at', ?1)",
            &[ms(now)],
        )
        .await?;
    Ok(())
}

pub(super) async fn outbox_stats<S: Sql>(c: &SqlCatalog<S>) -> Result<OutboxStats> {
    let rows = c
        .sql
        .query("SELECT stage, COUNT(*) FROM outbox GROUP BY stage", &[])
        .await?;
    let mut counted = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        counted.push((r.parsed(OutboxStage::parse)?, r.num::<u64>()?));
    }
    let by_stage: Vec<_> = OutboxStage::ALL
        .iter()
        .filter_map(|s| counted.iter().find(|(stage, _)| stage == s).copied())
        .collect();
    let dead = by_stage
        .iter()
        .find(|(s, _)| *s == OutboxStage::Dead)
        .map_or(0, |(_, n)| *n);
    let rows = c
        .sql
        .query("SELECT v FROM meta WHERE k = 'last_dispatch_at'", &[])
        .await?;
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
