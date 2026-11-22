//! The isolate's table of running queue jobs, and what it logs about
//! the byte budget.
//!
//! An invocation that the runtime cancels is not dropped: the job it ran
//! keeps its bytes of the budget and its extent in memory. Every job
//! therefore runs in the isolate's [`JobTable`], and each invocation
//! first drops the jobs there that are older than any invocation can be
//! ([`reap`]). A live invocation marks its job every few seconds, on a
//! timer of its own; the timers of a cancelled one never fire, so a job
//! that has not been marked for a minute is dropped as well. A budget
//! that stays full is said in the log, at most once a minute per isolate
//! ([`Watch`]): sizes, counts and times only. What waiting for room cost
//! the requests and the jobs is said the same way ([`PressureWatch`]).
//!
//! Dev only: `DEV_ABANDON_JOB_N=<n>` abandons every n-th post job of an
//! isolate two seconds after it began, as a cancelled invocation does:
//! the job is neither polled again nor dropped, and the invocation ends
//! with its message put back.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::time::Duration;

use futures_util::future::{select, Either};
use velmora_bridge::ingress::{ByteBudget, Pressure};
use velmora_bridge::jobtable::{JobTable, Ran, JOB_BEAT_MS, JOB_MAX_AGE_MS, JOB_QUIET_MS};
use velmora_bridge::{JobOutcome, UnixMs};

/// Name of the dev-only variable that abandons post jobs.
pub const DEV_ABANDON_JOB_N: &str = "DEV_ABANDON_JOB_N";

/// How long a job runs before the dev knob abandons it: it then holds
/// its bytes and is in the middle of its posts.
const ABANDON_AFTER: Duration = Duration::from_secs(2);

/// The least time between two lines about a full budget, per isolate.
const WATCH_EVERY_MS: i64 = 60_000;

thread_local! {
    static TABLE: JobTable<'static, JobOutcome> = JobTable::new();
    static WATCH: RefCell<Watch> = const { RefCell::new(Watch::new()) };
    static PRESSURE: RefCell<PressureWatch> = const { RefCell::new(PressureWatch::new()) };
    static ABANDON: Cell<Abandon> = const { Cell::new(Abandon { every: 0, seen: 0 }) };
}

/// `dev` is the validated environment. Outside dev the value is never
/// read (always off). In dev, absent, empty or `0` is off, a count from
/// 1 to 1000 is every n-th post job and anything else is refused.
pub fn abandon_from_var(dev: bool, raw: Option<&str>) -> Result<u32, String> {
    if !dev {
        return Ok(0);
    }
    match raw.map(str::trim) {
        None | Some("") => Ok(0),
        Some(n) => match n.parse::<u32>() {
            Ok(n) if n <= 1000 => Ok(n),
            _ => Err(format!("invalid {DEV_ABANDON_JOB_N}")),
        },
    }
}

/// Counts post jobs and picks every n-th.
#[derive(Clone, Copy)]
struct Abandon {
    every: u32,
    seen: u32,
}

impl Abandon {
    fn pick(&mut self) -> bool {
        if self.every == 0 {
            return false;
        }
        self.seen += 1;
        if self.seen >= self.every {
            self.seen = 0;
            return true;
        }
        false
    }
}

/// Sets the dev knob of this isolate, when its bridge is built.
pub fn set_abandon(every: u32) {
    ABANDON.with(|c| c.set(Abandon { every, seen: 0 }));
}

fn abandon_this_one() -> bool {
    ABANDON.with(|c| {
        let mut a = c.get();
        let pick = a.pick();
        c.set(a);
        pick
    })
}

/// Runs `job` in the isolate's table and marks it every `JOB_BEAT_MS`
/// on this invocation's own timer. A cancelled invocation is never
/// polled again, so its mark goes stale and another invocation drops
/// the job after `JOB_QUIET_MS`.
///
/// A job that has not ended after `JOB_WAIT_MS` is dropped here and the
/// message is tried again: with the beat pending, the runtime no longer
/// ends an invocation whose job waits on something that cannot come.
///
/// `None`: the job was dropped while this invocation still ran. That
/// takes an invocation whose timer did not fire for `JOB_QUIET_MS`, or a
/// job older than the platform lets an invocation be. This invocation
/// is not woken by the drop: it sees `None` at its next beat. The
/// caller retries the message; the row stays leased until the lease
/// runs out.
pub async fn run(
    now: UnixMs,
    post: bool,
    job: impl Future<Output = JobOutcome> + 'static,
) -> Option<JobOutcome> {
    let running = TABLE.with(|t| t.run(now, job));
    if !(post && abandon_this_one()) {
        // The job is marked for as long as this invocation runs: were
        // it cancelled, the timer would not fire again and the mark
        // would go stale.
        let clock = || UnixMs(worker::Date::now().as_millis() as i64);
        let beat = || worker::Delay::from(Duration::from_millis(JOB_BEAT_MS as u64));
        return match running.marked(now, clock, beat).await {
            Ran::Done(outcome) => Some(outcome),
            Ran::Dropped { unmarked_ms } => {
                // How late this invocation's timer was: what
                // `JOB_QUIET_MS` has to exceed.
                worker::console_error!(
                    "job table: a running job was dropped: unmarked_ms={unmarked_ms}"
                );
                None
            }
            Ran::Overdue { waited_ms } => {
                worker::console_error!(
                    "job table: a job did not end and was given up: waited_ms={waited_ms}"
                );
                Some(JobOutcome::Retry {
                    delay_secs: velmora_bridge::jobs::INFRA_RETRY_SECS,
                })
            }
        };
    }
    let pause = Box::pin(worker::Delay::from(ABANDON_AFTER));
    match select(running, pause).await {
        Either::Left((outcome, _)) => outcome,
        Either::Right(((), running)) => {
            worker::console_log!("dev: a post job is abandoned");
            // As a cancelled invocation leaves it: never polled again
            // and never dropped. The invocation ends, so nothing the
            // job began goes on either.
            std::mem::forget(running);
            Some(JobOutcome::Retry {
                delay_secs: velmora_bridge::jobs::INFRA_RETRY_SECS,
            })
        }
    }
}

/// Drops the jobs of invocations that are gone. `Some(line)` when there
/// were any.
///
/// The drop runs in another invocation than the one that made the job,
/// so every destructor on a job's path runs outside its request. One
/// that lets a JavaScript exception out ends the whole Wasm instance,
/// and with it every job running in the isolate. That happened with
/// wasm-streams 0.7.0: dropping the reader of an R2 body called
/// `releaseLock()`, which throws outside the reader's request. 0.7.1
/// ignores that throw and leaves the stream locked;
/// `the_stream_reader_drop_does_not_throw` holds the lockfile to it.
///
/// The other destructors a queue job can hold, as read in worker 0.8.7:
/// the transports close their socket through `Socket.close`, whose
/// binding catches; `worker::Socket` has no destructor of its own;
/// `worker::Delay` calls `clearTimeout`, which does not catch and was
/// not seen to throw; futures, closures and the D1, R2 and queue
/// handles make no call on drop. A new one that calls the runtime
/// without catching brings the failure back.
pub fn reap(budget: &ByteBudget, isolate: i64, now: UnixMs) -> Option<String> {
    let before = budget.in_use();
    let (quiet, old, left, total) = TABLE.with(|t| {
        let quiet = t.reap_quiet(now, JOB_QUIET_MS);
        (quiet, t.reap(now, JOB_MAX_AGE_MS), t.len(), t.reaped())
    });
    let n = quiet + old;
    (n > 0).then(|| {
        format!(
            "job table: abandoned jobs dropped: isolate={isolate} dropped={n} quiet={quiet} \
             budget_in_use_before={before} budget_in_use={} running_jobs={left} dropped_total={total} \
             spare_bytes={}",
            budget.in_use(),
            budget.spare_bytes(),
        )
    })
}

/// What [`Watch`] reads of an isolate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub now: UnixMs,
    /// `ByteBudget::refused`.
    pub refused: u64,
    pub in_use: u64,
    pub jobs_in_use: u64,
    /// `ByteBudget::spare_bytes`: idle extent buffers, in both counts
    /// above.
    pub spare_bytes: u64,
    pub capacity: u64,
    pub job_capacity: u64,
    pub waiting: usize,
    pub running_jobs: usize,
    pub oldest_job: Option<UnixMs>,
    pub dropped_total: u64,
}

/// Says when the budget of an isolate stays full: a line when charges
/// were refused after their full wait since the last line, at most one
/// per [`WATCH_EVERY_MS`]. Held in memory, nothing is stored.
pub struct Watch {
    last_at: Option<i64>,
    last_refused: u64,
}

impl Watch {
    pub const fn new() -> Self {
        Watch {
            last_at: None,
            last_refused: 0,
        }
    }

    pub fn line(&mut self, isolate: i64, r: &Reading) -> Option<String> {
        if r.refused <= self.last_refused {
            return None;
        }
        if self
            .last_at
            .is_some_and(|at| r.now.0.saturating_sub(at) < WATCH_EVERY_MS)
        {
            return None;
        }
        let refused_since = r.refused - self.last_refused;
        self.last_at = Some(r.now.0);
        self.last_refused = r.refused;
        let oldest = match r.oldest_job {
            Some(began) => (r.now.0.saturating_sub(began.0) / 1000).to_string(),
            None => "-".to_string(),
        };
        Some(format!(
            "budget saturated: isolate={isolate} refused={refused_since} refused_total={} \
             budget_in_use={} jobs_in_use={} capacity={} job_capacity={} waiting={} \
             running_jobs={} oldest_job_age_s={oldest} dropped_total={} spare_bytes={}",
            r.refused,
            r.in_use,
            r.jobs_in_use,
            r.capacity,
            r.job_capacity,
            r.waiting,
            r.running_jobs,
            r.dropped_total,
            r.spare_bytes,
        ))
    }
}

/// The line about a full budget, when one is due.
pub fn watch_line(budget: &ByteBudget, isolate: i64, now: UnixMs) -> Option<String> {
    let (running_jobs, oldest_job, dropped_total) =
        TABLE.with(|t| (t.len(), t.oldest(), t.reaped()));
    let reading = Reading {
        now,
        refused: budget.refused(),
        in_use: budget.in_use(),
        jobs_in_use: budget.jobs_in_use(),
        spare_bytes: budget.spare_bytes(),
        capacity: budget.capacity(),
        job_capacity: budget.job_capacity(),
        waiting: budget.waiting(),
        running_jobs,
        oldest_job,
        dropped_total,
    };
    WATCH.with(|w| w.borrow_mut().line(isolate, &reading))
}

/// Says what the shared budget cost the requests and the jobs of an
/// isolate since the last line: how many charges waited for room, for
/// how long, and how many were refused, each kind apart. A line when a
/// count moved, at most one per [`WATCH_EVERY_MS`]; every figure is
/// what was added since the line before, so the lines of an isolate
/// sum to its totals. Held in memory, nothing is stored.
pub struct PressureWatch {
    last_at: Option<i64>,
    last: Pressure,
}

impl PressureWatch {
    pub const fn new() -> Self {
        PressureWatch {
            last_at: None,
            last: Pressure {
                request_waits: 0,
                request_wait_ms: 0,
                request_refused: 0,
                job_waits: 0,
                job_wait_ms: 0,
                job_refused: 0,
                too_large: 0,
            },
        }
    }

    pub fn line(&mut self, isolate: i64, now: UnixMs, p: Pressure) -> Option<String> {
        if p == self.last {
            return None;
        }
        if self
            .last_at
            .is_some_and(|at| now.0.saturating_sub(at) < WATCH_EVERY_MS)
        {
            return None;
        }
        let was = std::mem::replace(&mut self.last, p);
        self.last_at = Some(now.0);
        Some(format!(
            "budget pressure: isolate={isolate} request_waits={} request_wait_ms={} \
             request_refused={} job_waits={} job_wait_ms={} job_refused={} too_large={}",
            p.request_waits.saturating_sub(was.request_waits),
            p.request_wait_ms.saturating_sub(was.request_wait_ms),
            p.request_refused.saturating_sub(was.request_refused),
            p.job_waits.saturating_sub(was.job_waits),
            p.job_wait_ms.saturating_sub(was.job_wait_ms),
            p.job_refused.saturating_sub(was.job_refused),
            p.too_large.saturating_sub(was.too_large),
        ))
    }
}

/// The line about what waiting for the budget cost, when one is due.
pub fn pressure_line(budget: &ByteBudget, isolate: i64, now: UnixMs) -> Option<String> {
    PRESSURE.with(|w| w.borrow_mut().line(isolate, now, budget.pressure()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A job dropped for its age is dropped outside its request. Before
    /// 0.7.1, wasm-streams' reader called `releaseLock()` in its
    /// destructor without catching what it throws there, which ended
    /// the Wasm instance (see [`reap`]).
    #[test]
    fn the_stream_reader_drop_does_not_throw() {
        let lock = include_str!("../../../Cargo.lock");
        let version = lock
            .split("[[package]]")
            .filter_map(|p| p.trim_start().strip_prefix("name = \"wasm-streams\"\n"))
            .filter_map(|p| p.lines().next()?.strip_prefix("version = \""))
            .filter_map(|v| v.strip_suffix('"'))
            .map(|v| {
                v.split('.')
                    .map(|n| n.parse::<u32>().expect("a numeric version part"))
                    .collect::<Vec<_>>()
            })
            .min()
            .expect("wasm-streams is in the lockfile");
        assert!(
            version >= vec![0, 7, 1],
            "wasm-streams {version:?} lets releaseLock() throw out of a destructor"
        );
    }

    #[test]
    fn abandon_is_dev_only_and_refuses_garbage() {
        for raw in [None, Some(""), Some(" "), Some("0")] {
            assert_eq!(abandon_from_var(true, raw), Ok(0));
        }
        assert_eq!(abandon_from_var(true, Some("5")), Ok(5));
        assert_eq!(abandon_from_var(true, Some("1000")), Ok(1000));
        for raw in ["1001", "-1", "1.5", "on"] {
            let err = abandon_from_var(true, Some(raw)).unwrap_err();
            assert_eq!(err, "invalid DEV_ABANDON_JOB_N");
        }
        // Outside dev the value is never read.
        for raw in [None, Some("5"), Some("garbage")] {
            assert_eq!(abandon_from_var(false, raw), Ok(0));
        }
    }

    #[test]
    fn every_nth_post_job_is_picked() {
        let mut off = Abandon { every: 0, seen: 0 };
        assert!((0..10).all(|_| !off.pick()));
        let mut third = Abandon { every: 3, seen: 0 };
        let picks: Vec<bool> = (0..7).map(|_| third.pick()).collect();
        assert_eq!(picks, [false, false, true, false, false, true, false]);
    }

    fn reading(now: i64, refused: u64) -> Reading {
        Reading {
            now: UnixMs(now),
            refused,
            in_use: 66,
            jobs_in_use: 66,
            spare_bytes: 16,
            capacity: 48,
            job_capacity: 72,
            waiting: 2,
            running_jobs: 3,
            oldest_job: Some(UnixMs(now - 90_000)),
            dropped_total: 1,
        }
    }

    #[test]
    fn a_full_budget_is_said_once_a_minute_and_only_while_charges_are_refused() {
        let mut watch = Watch::new();
        // Nothing was refused: nothing is said.
        assert_eq!(watch.line(7, &reading(1_000, 0)), None);
        assert_eq!(
            watch.line(7, &reading(2_000, 3)).as_deref(),
            Some(
                "budget saturated: isolate=7 refused=3 refused_total=3 budget_in_use=66 \
                 jobs_in_use=66 capacity=48 job_capacity=72 waiting=2 running_jobs=3 \
                 oldest_job_age_s=90 dropped_total=1 spare_bytes=16"
            )
        );
        // More are refused within the minute: said when it is over, with
        // all of them.
        assert_eq!(watch.line(7, &reading(30_000, 5)), None);
        assert_eq!(watch.line(7, &reading(61_999, 9)), None);
        let line = watch.line(7, &reading(62_000, 9)).expect("a minute on");
        assert!(line.contains(" refused=6 refused_total=9 "), "{line}");
        // The budget has room again: silence.
        assert_eq!(watch.line(7, &reading(500_000, 9)), None);
    }

    #[test]
    fn a_reading_without_jobs_has_no_age() {
        let mut watch = Watch::new();
        let mut r = reading(1_000, 1);
        r.oldest_job = None;
        let line = watch.line(1, &r).expect("refused");
        assert!(line.contains(" oldest_job_age_s=- "), "{line}");
    }

    #[test]
    fn what_waiting_cost_is_said_once_a_minute_as_what_was_added() {
        let mut watch = PressureWatch::new();
        let mut p = Pressure::default();
        // Nothing waited: nothing is said.
        assert_eq!(watch.line(7, UnixMs(1_000), p), None);
        p.request_waits = 2;
        p.request_wait_ms = 700;
        p.job_refused = 1;
        assert_eq!(
            watch.line(7, UnixMs(2_000), p).as_deref(),
            Some(
                "budget pressure: isolate=7 request_waits=2 request_wait_ms=700 \
                 request_refused=0 job_waits=0 job_wait_ms=0 job_refused=1 too_large=0"
            )
        );
        // More within the minute: said when it is over, all of it, once.
        p.request_waits = 5;
        p.too_large = 1;
        assert_eq!(watch.line(7, UnixMs(61_999), p), None);
        let line = watch.line(7, UnixMs(62_000), p).expect("a minute on");
        assert!(
            line.contains(" request_waits=3 request_wait_ms=0 "),
            "{line}"
        );
        assert!(line.ends_with(" job_refused=0 too_large=1"), "{line}");
        // Nothing moved since: silence.
        assert_eq!(watch.line(7, UnixMs(500_000), p), None);
    }
}
