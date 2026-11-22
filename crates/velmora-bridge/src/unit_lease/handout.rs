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
//!   window for a queue whose backlog is not known; from a bounded window
//!   of each stage, never late), a GC row is due while `GC_MODE` runs, or
//!   the eviction check is due while the cap is set and the unit holds
//!   evictable bytes; and never sooner than [`HANDOUT_PERIOD_MS`] after
//!   the last hand-out, the cadence of tenant 0's cron. A unit with
//!   nothing in its outbox and no cache has nothing due; one that holds
//!   cache wakes once per eviction-check period to take its total.
//! - **What it sends** ([`plan`]): exhausted rows are buried first, then
//!   up to [`crate::jobs::DISPATCH_LIMIT`] due rows as `extent` jobs, one
//!   `gc` job while a GC row is due and `GC_MODE` runs, and one `evict`
//!   job per [`crate::jobs::EVICT_CHECK_SECS`] while the unit's evictable
//!   bytes are above `HOT_CAP_BYTES`, as tenant 0's dispatcher. The
//!   object class reads both from the Worker's environment
//!   ([`HandoutRules`]).
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

/// What the Worker's configuration says about the hand-out. The unit's
/// object class runs in the Worker and reads them from its environment
/// ([`HandoutRules::from_vars`]); a unit never reads a configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandoutRules {
    /// `GC_MODE = disposable`: `gc` jobs run. Off, a GC row is never
    /// handed out (tenant 0's dispatcher sends none either).
    pub gc: bool,
    /// `HOT_CAP_BYTES`: an `evict` job is sent only above it. `None` = no
    /// eviction is handed out.
    pub hot_cap_bytes: Option<u64>,
}

impl HandoutRules {
    /// Hands out outbox rows only: no GC, no eviction.
    pub const ROWS_ONLY: HandoutRules = HandoutRules {
        gc: false,
        hot_cap_bytes: None,
    };

    /// The rules of the Worker's variables, with `BridgeConfig`'s
    /// meanings. A value that does not parse turns its part off (fail
    /// toward doing less: GC deletes, and eviction only frees cache).
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> HandoutRules {
        let gc = get("GC_MODE").is_some_and(|v| v == "disposable");
        let hot_cap_bytes = match get("HOT_CAP_BYTES") {
            Some(v) if !v.trim().is_empty() => v
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|cap| i64::try_from(*cap).is_ok()),
            _ => Some(crate::config::DEFAULT_HOT_CAP_BYTES),
        };
        HandoutRules { gc, hot_cap_bytes }
    }
}

/// Outbox rows of one stage that [`due_at`] reads, at most: the earliest
/// by `next_at`, along the `outbox_due` index.
pub const DUE_WINDOW: u32 = 500;

/// GC rows [`due_at`] looks at, at most, by `due_at`.
const GC_WINDOW: u32 = 500;

/// When the hand-out is next due; `None` = nothing waits. See the
/// [module](self). Bounded: at most [`DUE_WINDOW`] rows per outbox stage
/// and a bounded GC look. Never late: a row past a full window has a
/// `next_at` at or after the window's last one, which then stands for it
/// (an early wake finds nothing and records its run).
pub fn due_at<S: Sql>(cat: &SqlCatalog<S>, rules: &HandoutRules) -> Result<Option<UnixMs>> {
    let sql = &cat.sql;
    let mut outbox: Option<UnixMs> = None;
    for stage in ["post", "verify", "release"] {
        let rows = poll_once(sql.query(
            "SELECT next_at, lease_until, sent_at FROM outbox \
              WHERE stage = ?1 ORDER BY next_at, rowid LIMIT ?2",
            &[
                SqlValue::Text(stage.into()),
                SqlValue::Int(i64::from(DUE_WINDOW)),
            ],
        ))??;
        let mut last = None;
        for r in &rows {
            let int = |v: &SqlValue| match v {
                SqlValue::Int(n) => Ok(Some(*n)),
                SqlValue::Null => Ok(None),
                _ => Err(decode("outbox")),
            };
            let next_at = int(&r[0])?.ok_or(decode("outbox next_at"))?;
            // The earliest time `Catalog::due` would take it: its
            // `next_at`, after its lease, and after its mark's resend
            // window when the mark is at or after `next_at`.
            let mut at = next_at;
            if let Some(until) = int(&r[1])? {
                at = at.max(until.saturating_add(1));
            }
            if let Some(sent) = int(&r[2])?.filter(|sent| *sent >= next_at) {
                at = at.max(sent.saturating_add(RESEND_MS));
            }
            outbox = Some(outbox.map_or(UnixMs(at), |o| UnixMs(o.0.min(at))));
            last = Some(next_at);
        }
        if rows.len() >= DUE_WINDOW as usize {
            if let Some(last) = last {
                outbox = Some(outbox.map_or(UnixMs(last), |o| UnixMs(o.0.min(last))));
            }
        }
    }
    // As `gc_due(.., disposable_only = true)`, the only mode that runs,
    // and only while it runs: the earliest disposable row of a bounded
    // window. A window full of rows that are not disposable (they stay
    // open for good: `gc_due` skips them) stands for the rest by its last
    // `due_at`, held to one look per eviction-check period so that it does
    // not wake the unit every minute.
    let gc = if rules.gc {
        let window = poll_once(sql.query(
            "SELECT g.due_at, EXISTS (SELECT 1 FROM extents e JOIN buckets b ON b.id = e.bucket_id \
                                      WHERE e.id = g.extent_id AND b.disposable = 1) \
               FROM (SELECT due_at, extent_id FROM gc WHERE done_at IS NULL \
                      ORDER BY due_at LIMIT ?1) g",
            &[SqlValue::Int(i64::from(GC_WINDOW))],
        ))??;
        let mut first = None;
        let mut last = None;
        for r in &window {
            let (Some(SqlValue::Int(at)), Some(SqlValue::Int(disposable))) = (r.first(), r.get(1))
            else {
                return Err(decode("gc"));
            };
            if *disposable != 0 && first.is_none() {
                first = Some(UnixMs(*at));
            }
            last = Some(UnixMs(*at));
        }
        match (first, last) {
            (Some(at), _) => Some(at),
            (None, Some(last)) if window.len() >= GC_WINDOW as usize => {
                let looked = one_time(sql, "SELECT v FROM meta WHERE k = 'gc_looked_at'", &[])?;
                Some(match looked {
                    Some(at) => last.max(UnixMs(at.0.saturating_add(EVICT_EVERY_MS))),
                    None => last,
                })
            }
            _ => None,
        }
    } else {
        None
    };
    // The eviction check, while the cap is set and any byte is evictable
    // (one row read): once per period, as tenant 0's.
    let evict = if rules.hot_cap_bytes.is_some() && any_evictable(sql)? {
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

/// Whether any extent has evictable bytes (the `extents_evictable`
/// predicate, one row).
fn any_evictable<S: Sql>(sql: &S) -> Result<bool> {
    let rows = poll_once(sql.query(
        "SELECT 1 FROM extents WHERE hot_cache_bytes > 0 \
           OR (hot_safety_bytes > 0 AND safety_state NOT IN ('held', 'releasing')) LIMIT 1",
        &[],
    ))??;
    Ok(!rows.is_empty())
}

/// What one hand-out sends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Handout {
    /// The jobs, in order: the due rows' `extent` jobs, then `gc`, then
    /// `evict`.
    pub jobs: Vec<Job>,
    /// The eviction check was due: it is recorded after the sends.
    pub evict_check: bool,
    /// GC was looked at (`GC_MODE` runs): recorded after the sends.
    pub gc_looked: bool,
}

/// The work of a hand-out at `now` (it buries exhausted rows first, one
/// write). See the [module](self).
pub fn plan<S: Sql>(cat: &SqlCatalog<S>, now: UnixMs, rules: &HandoutRules) -> Result<Handout> {
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
    if rules.gc && !poll_once(cat.gc_due(now, 1, true))??.is_empty() {
        jobs.push(Job::Gc { v: JOB_VERSION });
    }
    // As tenant 0's: one total per period, and a job only above the cap.
    let evict_check = match rules.hot_cap_bytes {
        Some(_) => poll_once(cat.hot_check_due(now, EVICT_EVERY_MS))??,
        None => false,
    };
    if evict_check {
        let over = poll_once(cat.evictable_bytes())?? > rules.hot_cap_bytes.unwrap_or(u64::MAX);
        if over {
            jobs.push(Job::Evict {
                v: JOB_VERSION,
                remaining: 0,
            });
        }
    }
    Ok(Handout {
        jobs,
        evict_check,
        gc_looked: rules.gc,
    })
}

/// After the sends of `handout`: `sent[i]` = job `i` went to its queue.
pub fn done<S: Sql>(
    cat: &SqlCatalog<S>,
    now: UnixMs,
    handout: &Handout,
    sent: &[bool],
) -> Result<()> {
    // The GC look of this run (`due_at`'s floor for a window of rows that
    // never close).
    if handout.gc_looked {
        poll_once(cat.sql.exec(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('gc_looked_at', ?1)",
            &[SqlValue::Int(now.0)],
        ))??;
    }
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
