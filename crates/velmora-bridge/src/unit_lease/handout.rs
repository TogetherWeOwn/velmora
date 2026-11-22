//! The alarm's hand-out on a unit ([`super::alarm::Duty::HandOut`];
//! ADR-TENANCY §2.4 rules 4, 8 and 12; round 5 §R5-4 row 5, AM-49).
//!
//! Tenant 0's cron dispatcher sends due outbox rows as jobs, and starts
//! garbage collection and eviction. On a unit only the alarm may send
//! (rule 4), so the same work is the alarm's: this module decides it from
//! the unit's own tables, and the object class sends it.
//!
//! - **When it is due** ([`due_at`]): the earliest time an outbox row is
//!   due (the same condition as `Catalog::due`, with tenant 0's resend
//!   window for a queue whose backlog is not known), a GC row is due, or
//!   the eviction check is due while the unit holds evictable bytes; and
//!   never sooner than [`HANDOUT_PERIOD_MS`] after the last hand-out, the
//!   cadence of tenant 0's cron. An idle unit has nothing due and costs
//!   nothing.
//! - **What it sends** ([`plan`]): exhausted rows are buried first, then
//!   up to [`crate::jobs::DISPATCH_LIMIT`] due rows as `extent` jobs, one
//!   `gc` job while a GC row is due, and one `evict` job per
//!   [`crate::jobs::EVICT_CHECK_SECS`] while the unit holds evictable
//!   bytes. The consumer holds the configuration: a `gc` job does nothing
//!   with `GC_MODE` off, and an `evict` job takes the cap's excess itself.
//! - **Where it goes** ([`route`]): every message through
//!   [`crate::routing`], as tenant 0's: an extent's job to its shard, the
//!   rest and the unit's own `renew` and `stamp_raise` to `AUX_Q`, or to
//!   the first verify queue where `AUX_Q` is not bound (AM-49). The jobs
//!   are format 2, naming the tenant, the unit and its numbers.
//! - **After the sends** ([`done`]): the rows of the batches that were
//!   sent are marked; the eviction check is recorded; the run is recorded
//!   only when every send went through, so a failed one is due again.
//!
//! Not handed out here yet: the write-intent sweep (tenant 0's is gated
//! by `INTENT_SWEEP`, which only the Worker's configuration holds and its
//! consumer does not check), the re-drive of under-verified extents, plan
//! packing and the usage recount. Each is an extra of tenant 0's
//! dispatcher; the day close (W7) and the directory report are not built.

use crate::jobmsg::{JobFormat, JobTenant};
use crate::jobs::{DISPATCH_LIMIT, EVICT_CHECK_SECS, MAX_ATTEMPTS, RESEND_SECS};
use crate::ports::{Catalog, Sql, SqlValue};
use crate::routing::{binding_name, lane, Lane, Shards, AUX_Q};
use crate::sql::SqlCatalog;
use crate::types::{BridgeError, ExtentId, Job, Resend, Result, UnixMs, JOB_VERSION};
use crate::unit::object::poll_once;

/// The least time between two hand-outs: tenant 0's cron runs once a
/// minute. 60 s (est).
pub const HANDOUT_PERIOD_MS: i64 = 60 * 1000;

/// Messages per `sendBatch` (Queues' limit).
pub const SEND_BATCH: usize = 100;

const POST_QUEUES: &str = "POST_Q";
const VERIFY_QUEUES: &str = "VERIFY_Q";

const EVICT_EVERY_MS: i64 = EVICT_CHECK_SECS as i64 * 1000;
const RESEND_MS: i64 = RESEND_SECS as i64 * 1000;

/// The resend window of a unit's rows: tenant 0's for queues whose
/// backlog is not known (a unit cannot ask).
const RESEND: Resend = Resend {
    post_secs: RESEND_SECS,
    verify_secs: RESEND_SECS,
};

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}

fn one_time<S: Sql>(sql: &S, stmt: &str, params: &[SqlValue]) -> Result<Option<UnixMs>> {
    let rows = poll_once(sql.query(stmt, params))??;
    match rows.first().and_then(|r| r.first()) {
        None | Some(SqlValue::Null) => Ok(None),
        Some(SqlValue::Int(n)) => Ok(Some(UnixMs(*n))),
        Some(SqlValue::Text(t)) => t
            .parse()
            .map(|n| Some(UnixMs(n)))
            .map_err(|_| decode("hand-out time")),
        _ => Err(decode("hand-out time")),
    }
}

/// When the hand-out is next due; `None` = nothing waits. See the
/// [module](self).
pub fn due_at<S: Sql>(cat: &SqlCatalog<S>) -> Result<Option<UnixMs>> {
    let sql = &cat.sql;
    // The earliest time `Catalog::due` would take a row: its `next_at`,
    // after its lease, and after its mark's resend window when the mark
    // is at or after `next_at`.
    let outbox = one_time(
        sql,
        "SELECT min(max(next_at, \
             CASE WHEN lease_until IS NULL THEN next_at ELSE lease_until + 1 END, \
             CASE WHEN sent_at IS NULL OR sent_at < next_at THEN next_at \
                  ELSE sent_at + ?1 END)) \
           FROM outbox WHERE stage IN ('post', 'verify', 'release')",
        &[SqlValue::Int(RESEND_MS)],
    )?;
    // As `gc_due(.., disposable_only = true)`: the only mode that runs.
    let gc = one_time(
        sql,
        "SELECT min(gc.due_at) FROM gc WHERE gc.done_at IS NULL \
           AND EXISTS (SELECT 1 FROM extents e JOIN buckets b ON b.id = e.bucket_id \
                       WHERE e.id = gc.extent_id AND b.disposable = 1)",
        &[],
    )?;
    let evict = if poll_once(cat.evictable_bytes())?? > 0 {
        let checked = one_time(sql, "SELECT v FROM meta WHERE k = 'hot_checked_at'", &[])?;
        Some(checked.map_or(UnixMs(0), |at| UnixMs(at.0.saturating_add(EVICT_EVERY_MS))))
    } else {
        None
    };
    let Some(work) = [outbox, gc, evict].into_iter().flatten().min() else {
        return Ok(None);
    };
    let last = one_time(sql, "SELECT v FROM meta WHERE k = 'last_dispatch_at'", &[])?;
    Ok(Some(match last {
        Some(at) => work.max(UnixMs(at.0.saturating_add(HANDOUT_PERIOD_MS))),
        None => work,
    }))
}

/// What one hand-out sends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Handout {
    /// The jobs, in order: the due rows' `extent` jobs, then `gc`, then
    /// `evict`.
    pub jobs: Vec<Job>,
    /// The eviction check was due: it is recorded after the sends.
    pub evict_check: bool,
}

/// The work of a hand-out at `now` (it buries exhausted rows first, one
/// write). See the [module](self).
pub fn plan<S: Sql>(cat: &SqlCatalog<S>, now: UnixMs) -> Result<Handout> {
    // Buried first, so an exhausted row is not sent once more.
    poll_once(cat.bury_exhausted(MAX_ATTEMPTS, now))??;
    let due = poll_once(cat.due(now, RESEND, DISPATCH_LIMIT))??;
    let mut jobs: Vec<Job> = due
        .into_iter()
        .map(|row| Job::Extent {
            v: JOB_VERSION,
            extent: row.extent_id,
            generation: row.generation_id,
            stage: row.stage,
        })
        .collect();
    if !poll_once(cat.gc_due(now, 1, true))??.is_empty() {
        jobs.push(Job::Gc { v: JOB_VERSION });
    }
    let evict_check = poll_once(cat.hot_check_due(now, EVICT_EVERY_MS))??;
    if evict_check && poll_once(cat.evictable_bytes())?? > 0 {
        jobs.push(Job::Evict {
            v: JOB_VERSION,
            remaining: 0,
        });
    }
    Ok(Handout { jobs, evict_check })
}

/// After the sends of `handout`: `sent[i]` = job `i` went to its queue.
pub fn done<S: Sql>(
    cat: &SqlCatalog<S>,
    now: UnixMs,
    handout: &Handout,
    sent: &[bool],
) -> Result<()> {
    let extents: Vec<ExtentId> = handout
        .jobs
        .iter()
        .zip(sent)
        .filter_map(|(job, sent)| match (job, sent) {
            (Job::Extent { extent, .. }, true) => Some(extent.clone()),
            _ => None,
        })
        .collect();
    if !extents.is_empty() {
        poll_once(cat.mark_sent(&extents, now))??;
    }
    let all = sent.len() == handout.jobs.len() && sent.iter().all(|s| *s);
    let evict_sent = handout
        .jobs
        .iter()
        .zip(sent)
        .all(|(job, sent)| !matches!(job, Job::Evict { .. }) || *sent);
    if handout.evict_check && evict_sent {
        poll_once(cat.hot_checked(now))??;
    }
    if all {
        poll_once(cat.record_dispatch(now))??;
    }
    Ok(())
}

/// The binding name of `lane`'s queue.
pub fn binding(lane: Lane) -> String {
    match lane {
        Lane::Post(i) => binding_name(POST_QUEUES, i),
        Lane::Verify(i) => binding_name(VERIFY_QUEUES, i),
        Lane::Aux => AUX_Q.to_string(),
    }
}

/// The lane of a unit's own `renew` and `stamp_raise`: the lane of a job
/// that names no extent (AM-49).
pub fn unit_job_lane(shards: Shards) -> Lane {
    lane(&Job::Gc { v: JOB_VERSION }, shards)
}

/// One `sendBatch` of an alarm run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// The binding of the queue.
    pub binding: String,
    /// The messages' JSON texts.
    pub texts: Vec<String>,
    /// For each text, the index of its hand-out job; `None` for the
    /// unit's own jobs.
    pub handout: Vec<Option<usize>>,
}

/// The sends of one alarm run: the unit's own job texts (`renew`,
/// `stamp_raise`) and the hand-out's jobs, in format 2 for `tenant`, by
/// queue in lane order, at most [`SEND_BATCH`] per send.
pub fn route(
    unit_jobs: &[String],
    handout: &[Job],
    tenant: &JobTenant,
    shards: Shards,
) -> Result<Vec<Outgoing>> {
    let mut by_lane: Vec<(Lane, String, Option<usize>)> = Vec::new();
    let own = unit_job_lane(shards);
    for text in unit_jobs {
        by_lane.push((own, text.clone(), None));
    }
    for (i, job) in handout.iter().enumerate() {
        let text = serde_json::to_string(&JobFormat::Tenant.message(job, tenant))
            .map_err(|_| BridgeError::Invalid("unit: job message encode"))?;
        by_lane.push((lane(job, shards), text, Some(i)));
    }
    let mut out = Vec::new();
    for target in shards.lanes() {
        let mine: Vec<&(Lane, String, Option<usize>)> =
            by_lane.iter().filter(|(l, ..)| *l == target).collect();
        for chunk in mine.chunks(SEND_BATCH) {
            out.push(Outgoing {
                binding: binding(target),
                texts: chunk.iter().map(|(_, t, _)| t.clone()).collect(),
                handout: chunk.iter().map(|(.., i)| *i).collect(),
            });
        }
    }
    Ok(out)
}
