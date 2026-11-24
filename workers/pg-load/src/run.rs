use crate::fixture::{self, OpError, Read};
use crate::{percentile, probe, Config, DrillConnect, Family, Job, MIN_READ_SAMPLES};
use futures_util::{
    future::{join3, select, Either},
    pin_mut,
    stream::FuturesUnordered,
    StreamExt,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};
use tokio_postgres::{types::Type, Client};
use velmora_bridge::{
    pg::{PgConfig, PgConnect, PgSql},
    sql::SqlCatalog,
    types::UnixMs,
};

const WRITE_POOL_SLOTS: usize = 5;
const MAX_LOGICAL_WRITES: usize = 64;
const SAMPLE_MS: u64 = 250;
// At most one missed nominal tick between reported samples.
const MAX_SAMPLE_GAP_MS: u64 = 2 * SAMPLE_MS;
const READ_SLOTS: usize = 3;
const READ_TIMEOUT_MS: f64 = 20_000.0;
const ARM_KEY: &str = "pg_load_fixture_v1";

#[allow(async_fn_in_trait)]
pub trait Runtime {
    fn monotonic_ms(&self) -> f64;
    fn wall_ms(&self) -> i64;
    fn lock_key(&self) -> i64 {
        PgConfig::default().lock_key
    }
    async fn sleep(&self, duration: Duration);
}

async fn until(r: &impl Runtime, target: f64) {
    let remaining = target - r.monotonic_ms();
    if remaining > 0.0 {
        r.sleep(Duration::from_millis(remaining.ceil() as u64))
            .await;
    }
}

#[derive(Default, Serialize)]
struct Failures {
    overloaded: u64,
    refused: u64,
    other: u64,
}
impl Failures {
    fn add(&mut self, error: OpError) {
        match error {
            OpError::Overloaded => self.overloaded += 1,
            OpError::Refused => self.refused += 1,
            OpError::Failed => self.other += 1,
        }
    }
}

#[derive(Default, Serialize)]
struct FamilyResult {
    planned_batches: u32,
    completed_batches: u32,
    late_batches: u32,
    queue_full_batches: u32,
    unstarted_at_deadline_batches: u32,
    failures: Failures,
}

#[derive(Serialize)]
struct Latency {
    scheduled: usize,
    samples: usize,
    late_completions: usize,
    timed_out: usize,
    statement_p95_ms: Option<f64>,
    end_to_end_p95_ms: Option<f64>,
}

#[derive(Serialize)]
struct Coverage {
    status: &'static str,
    minimum_samples_per_read_and_phase: usize,
    at_least_ninety_percent_advisory_ticks: bool,
    advisory_gap_within_tolerance: bool,
    unloaded_read_coverage: bool,
    loaded_read_coverage: bool,
}

#[derive(Serialize)]
struct Reads {
    get: Latency,
    head: Latency,
    list: Latency,
    failures: Failures,
}

#[derive(Serialize)]
pub struct Report {
    requested_batches_per_minute: u32,
    batches_per_minute: f64,
    completed_batches_each_minute: Vec<u32>,
    in_five_percent_each_minute: bool,
    family: BTreeMap<Family, FamilyResult>,
    write_pool: PoolStats,
    // All six WP1 overload SQLSTATEs are mapped to the same public error.
    overloaded_upper_bound_on_55p03: u64,
    advisory_sampling_period_ms: u64,
    advisory_sampling_ticks: u64,
    advisory_expected_ticks: u64,
    advisory_missed_ticks: u64,
    advisory_sample_offsets_ms: Vec<f64>,
    advisory_max_gap_ms: f64,
    advisory_gap_tolerance_ms: u64,
    advisory_wait_samples: usize,
    sampled_lock_wait_p99_ms: Option<f64>,
    advisory_error: Option<String>,
    r3a_coverage: Coverage,
    unloaded_reads: Reads,
    loaded_reads: Reads,
}

impl Report {
    pub fn usable(&self) -> bool {
        self.r3a_coverage.status == "SUFFICIENT"
            && self
                .family
                .values()
                .all(|f| f.failures.refused + f.failures.other == 0)
    }

    pub fn meets_local_rate(&self) -> bool {
        self.usable()
            && self.in_five_percent_each_minute
            && self.overloaded_upper_bound_on_55p03 == 0
    }
}

type Cat<C> = SqlCatalog<PgSql<C>>;

#[derive(Default)]
struct ReadSamples {
    statement: Vec<f64>,
    end_to_end: Vec<f64>,
    late: usize,
    timed_out: usize,
    scheduled: usize,
}

impl ReadSamples {
    fn success(&mut self, statement_ms: f64, end_to_end_ms: f64, late: bool) {
        self.statement.push(statement_ms);
        self.end_to_end.push(end_to_end_ms);
        self.late += usize::from(late);
    }

    fn timeout(&mut self, elapsed_ms: f64) {
        self.timed_out += 1;
        self.end_to_end.push(elapsed_ms);
    }

    fn finish(mut self) -> Latency {
        Latency {
            scheduled: self.scheduled,
            samples: self.statement.len(),
            late_completions: self.late,
            timed_out: self.timed_out,
            statement_p95_ms: percentile(&mut self.statement, 95),
            end_to_end_p95_ms: percentile(&mut self.end_to_end, 95),
        }
    }
}

impl Reads {
    fn covered(&self) -> bool {
        self.failures.overloaded + self.failures.refused + self.failures.other == 0
            && [&self.get, &self.head, &self.list].into_iter().all(|r| {
                r.samples >= MIN_READ_SAMPLES && r.samples == r.scheduled && r.timed_out == 0
            })
    }
}

async fn reads<C: DrillConnect, R: Runtime>(
    reader: &C,
    statements: &[Vec<probe::Statement>; 3],
    runtime: &R,
    start: f64,
    ms: u64,
    rate: u32,
) -> Reads {
    let mut samples: [ReadSamples; 3] = Default::default();
    let mut failures = Failures::default();
    let deadline = start + ms as f64;
    let total = ms * u64::from(rate) / 60_000;
    let at = |i: u64| start + (i * 60_000 / u64::from(rate)) as f64;
    let mut next = 0;
    let mut active = FuturesUnordered::new();
    // The timetable is fixed. When slots fill the next due probe waits in
    // the timetable (bounded by the phase's request count) instead of shed.
    while next < total || !active.is_empty() {
        let now = runtime.monotonic_ms();
        if now >= deadline {
            for i in next..total {
                let stat = &mut samples[(i % 3) as usize];
                stat.scheduled += 1;
                stat.timeout((deadline - at(i)).clamp(0.0, READ_TIMEOUT_MS));
            }
            next = total;
        } else if next < total && active.len() < READ_SLOTS && at(next) <= now {
            let scheduled = at(next);
            let op = (next % 3) as usize;
            let choices = &statements[op];
            let selected = &choices[(next as usize / 3) % choices.len()];
            samples[op].scheduled += 1;
            next += 1;
            active.push(async move {
                let cutoff = scheduled + READ_TIMEOUT_MS;
                if runtime.monotonic_ms() >= cutoff {
                    return (op, scheduled, None);
                }
                let query = probe::execute(reader, runtime, selected);
                let timeout = until(runtime, cutoff);
                pin_mut!(query, timeout);
                let outcome = match select(timeout, query).await {
                    Either::Right((r, _)) => Some(r),
                    Either::Left(_) => None,
                };
                (op, scheduled, outcome)
            });
            continue;
        }
        let wake = if next < total && active.len() < READ_SLOTS {
            at(next)
        } else {
            deadline
        };
        let result = if active.is_empty() {
            if next >= total {
                break;
            }
            until(runtime, wake).await;
            None
        } else if now >= deadline {
            active.next().await // retain late in-flight results (or explicit timeout)
        } else {
            let timer = until(runtime, wake);
            pin_mut!(timer);
            match select(active.next(), timer).await {
                Either::Left((r, _)) => r,
                Either::Right(_) => None,
            }
        };
        if let Some((op, scheduled, result)) = result {
            let stat = &mut samples[op];
            match result {
                Some(Ok(latency)) => {
                    let completed = runtime.monotonic_ms();
                    stat.success(
                        latency,
                        (completed - scheduled).max(0.0),
                        completed > deadline,
                    );
                }
                Some(Err(error)) => failures.add(error),
                None => stat.timeout(READ_TIMEOUT_MS),
            }
        }
    }
    until(runtime, deadline).await;
    let [get, head, list] = samples.map(ReadSamples::finish);
    Reads {
        get,
        head,
        list,
        failures,
    }
}

struct Writes<'a, C: PgConnect, R> {
    cat: &'a Cat<C>,
    rt: &'a R,
    start: f64,
    minutes: usize,
    jobs: &'a [Job],
}

#[derive(Serialize)]
struct PoolStats {
    admission_slots: usize,
    max_logical_writes: usize,
    peak_logical_writes: usize,
    peak_admitted_writes: usize,
    queue_admissions: usize,
    queue_wait_p50_ms: Option<f64>,
    queue_wait_p99_ms: Option<f64>,
    arrival_schedule_lag_p99_ms: Option<f64>,
}

struct WritesResult {
    family: BTreeMap<Family, FamilyResult>,
    minutes: Vec<u32>,
    pool: PoolStats,
}

struct Completed {
    family: Family,
    minutes: [Option<usize>; 3],
    error: Option<OpError>,
}

async fn writes<C: PgConnect, R: Runtime>(w: Writes<'_, C, R>) -> WritesResult {
    let provider = fixture::provider();
    let mut active = FuturesUnordered::new();
    let mut pending = VecDeque::with_capacity(MAX_LOGICAL_WRITES);
    let mut queue_wait = Vec::new();
    let mut lag = Vec::new();
    let mut peak_logical = 0;
    let mut peak_admitted = 0;
    let mut family = BTreeMap::<Family, FamilyResult>::new();
    let mut minutes = vec![0; w.minutes];
    let deadline = w.start + (w.minutes * 60_000) as f64;
    let mut arrivals = w.jobs.iter().enumerate().peekable();
    for job in w.jobs {
        family.entry(job.family).or_default().planned_batches += job.family.batches();
    }
    loop {
        let now = w.rt.monotonic_ms();
        // Arrivals advance even when all writer admission slots are busy.
        if now < deadline {
            while arrivals
                .peek()
                .is_some_and(|(_, job)| w.start + job.at_ms as f64 <= now)
            {
                let (i, job) = arrivals.next().expect("due arrival");
                lag.push(now - (w.start + job.at_ms as f64));
                if active.len() + pending.len() == MAX_LOGICAL_WRITES {
                    family
                        .get_mut(&job.family)
                        .expect("planned family")
                        .queue_full_batches += job.family.batches();
                } else {
                    pending.push_back((i, job, now));
                    peak_logical = peak_logical.max(active.len() + pending.len());
                }
            }
            while active.len() < WRITE_POOL_SLOTS {
                let Some((i, job, queued)) = pending.pop_front() else {
                    break;
                };
                queue_wait.push((w.rt.monotonic_ms() - queued).max(0.0));
                let w = &w;
                let provider = &provider;
                active.push(async move {
                    let mut minutes = [None; 3];
                    let mut n = 0;
                    let error = fixture::write(
                        w.cat,
                        provider,
                        job.family,
                        i,
                        UnixMs(w.rt.wall_ms()),
                        || {
                            minutes[n] =
                                Some(((w.rt.monotonic_ms() - w.start).max(0.0) as usize) / 60_000);
                            n += 1;
                        },
                    )
                    .await
                    .err();
                    Completed {
                        family: job.family,
                        minutes,
                        error,
                    }
                });
                peak_admitted = peak_admitted.max(active.len());
            }
        } else {
            for job in pending
                .drain(..)
                .map(|(_, job, _)| job)
                .chain(arrivals.by_ref().map(|(_, job)| job))
            {
                family
                    .get_mut(&job.family)
                    .expect("planned family")
                    .unstarted_at_deadline_batches += job.family.batches();
            }
        }
        if active.is_empty() && arrivals.peek().is_none() {
            break;
        }
        let at = arrivals
            .peek()
            .map_or(deadline, |(_, job)| w.start + job.at_ms as f64);
        let done = if now >= deadline {
            active.next().await // drain; count late acknowledgements separately
        } else if active.is_empty() {
            until(w.rt, at).await;
            None
        } else {
            let timer = until(w.rt, at);
            pin_mut!(timer);
            match select(active.next(), timer).await {
                Either::Left((done, _)) => done,
                Either::Right(_) => None,
            }
        };
        if let Some(done) = done {
            let stats = family.get_mut(&done.family).expect("planned family");
            for minute in done.minutes.into_iter().flatten() {
                if let Some(total) = minutes.get_mut(minute) {
                    *total += 1;
                    stats.completed_batches += 1;
                } else {
                    stats.late_batches += 1;
                }
            }
            if let Some(error) = done.error {
                stats.failures.add(error);
            }
        }
    }
    WritesResult {
        family,
        minutes,
        pool: PoolStats {
            admission_slots: WRITE_POOL_SLOTS,
            max_logical_writes: MAX_LOGICAL_WRITES,
            peak_logical_writes: peak_logical,
            peak_admitted_writes: peak_admitted,
            queue_admissions: queue_wait.len(),
            queue_wait_p50_ms: percentile(&mut queue_wait, 50),
            queue_wait_p99_ms: percentile(&mut queue_wait, 99),
            arrival_schedule_lag_p99_ms: percentile(&mut lag, 99),
        },
    }
}

async fn advisory(
    client: &Client,
    runtime: &impl Runtime,
    start: f64,
    duration: u64,
    lock: i64,
) -> (Vec<f64>, Vec<f64>, Option<String>) {
    let mut waits = Vec::new();
    let mut error = None;
    let mut samples = Vec::new();
    let mut next_tick = 0;
    while next_tick < duration / SAMPLE_MS {
        let elapsed = (runtime.monotonic_ms() - start).max(0.0) as u64;
        let tick = (elapsed / SAMPLE_MS).max(next_tick);
        if tick >= duration / SAMPLE_MS {
            break;
        }
        until(runtime, start + (tick * SAMPLE_MS) as f64).await;
        let result = client.query_typed("SELECT EXTRACT(EPOCH FROM (clock_timestamp()-l.waitstart))::float8 * 1000 \
             FROM pg_catalog.pg_stat_activity a JOIN pg_catalog.pg_locks l USING(pid) \
             WHERE a.datname=current_database() AND a.wait_event='advisory' \
             AND l.locktype='advisory' AND NOT l.granted AND l.waitstart IS NOT NULL AND l.objsubid=1 \
             AND l.classid::bigint=($1::bigint >> 32) AND l.objid::bigint=($1::bigint & 4294967295)", &[(&lock, Type::INT8)])
            .await;
        match result {
            Ok(rows) => {
                let receipt = (runtime.monotonic_ms() - start).max(0.0);
                if receipt <= duration as f64 {
                    samples.push(receipt);
                    waits.extend(rows.into_iter().map(|row| row.get::<_, f64>(0).max(0.0)));
                }
            }
            Err(e) => {
                error = Some(fixture::sql_error("sample advisory waits", e));
                break;
            }
        }
        next_tick = tick + 1;
    }
    (samples, waits, error)
}

fn sampler_coverage(samples: &[f64], duration: u64) -> (bool, f64) {
    let mut previous = 0.0_f64;
    let mut max_gap = 0.0_f64;
    for sample in samples.iter().copied().chain([duration as f64]) {
        max_gap = max_gap.max(sample - previous);
        previous = previous.max(sample);
    }
    (
        samples.len() as u64 * 10 >= (duration / SAMPLE_MS) * 9,
        max_gap,
    )
}

async fn target(client: &Client) -> Result<(String, String, String), String> {
    let row = client.query_typed_one("SELECT current_database()::text,current_schema()::text,current_user::text, \
        EXISTS (SELECT FROM meta WHERE k=$1 AND v=1) AND NOT EXISTS (SELECT FROM rollback_stamp LIMIT 1)", &[(&ARM_KEY, Type::TEXT)])
        .await.map_err(|e| fixture::sql_error("check drill target", e))?;
    if !row.get::<_, bool>(3) {
        return Err("target is not armed or has rollback stamps".into());
    }
    Ok((row.get(0), row.get(1), row.get(2)))
}

/// Admits at most five writer calls, separate from the read probe and sampler.
/// The two connectors must point at the same explicitly armed drill copy.
pub async fn run<C: DrillConnect + Clone, R: Runtime>(
    writer: C,
    reader: C,
    runtime: &R,
    config: &Config,
) -> Result<Report, String> {
    let jobs = config.plan();
    let pg = PgConfig {
        lock_key: runtime.lock_key(),
        ..PgConfig::default()
    };
    let rd = reader
        .connect()
        .await
        .map_err(|_| "could not connect read sampler")?;
    let wr = writer
        .connect()
        .await
        .map_err(|_| "could not connect setup writer")?;
    let (wd, ws, wu) = target(wr.client()).await?;
    let (rd_db, rs, ru) = target(rd.client()).await?;
    if (wd, ws) != (rd_db, rs) {
        return Err("drill pools disagree on database or schema".into());
    }
    if wu != ru {
        let can_sample: bool = rd
            .client()
            .query_typed_one(
                "SELECT pg_has_role(current_user,'pg_read_all_stats','USAGE')",
                &[],
            )
            .await
            .map_err(|e| fixture::sql_error("verify sampler permissions", e))?
            .get(0);
        if !can_sample {
            return Err("read role cannot see writer wait events".into());
        }
    }
    wr.client()
        .batch_execute("BEGIN READ WRITE")
        .await
        .map_err(|e| fixture::sql_error("begin marker claim", e))?;
    let claimed = wr
        .client()
        .execute_typed(
            "UPDATE meta SET v=2 WHERE k=$1 AND v=1",
            &[(&ARM_KEY, Type::TEXT)],
        )
        .await
        .map_err(|e| fixture::sql_error("claim drill marker", e))?;
    if claimed != 1 {
        return Err("drill was already claimed".into());
    }
    wr.client()
        .batch_execute("COMMIT")
        .await
        .map_err(|e| fixture::sql_error("commit marker claim", e))?;
    // The read origin must see the same one-shot claim, not a separately armed DB.
    let sees_claim: bool = rd
        .client()
        .query_typed_one(
            "SELECT EXISTS(SELECT FROM meta WHERE k=$1 AND v=2)",
            &[(&ARM_KEY, Type::TEXT)],
        )
        .await
        .map_err(|e| fixture::sql_error("verify drill claim on read pool", e))?
        .get(0);
    if !sees_claim {
        return Err("read pool does not see drill claim".into());
    }
    fixture::seed(wr.client(), &jobs).await?;
    drop(wr);
    let cat = SqlCatalog::new(PgSql::new(writer, reader.clone(), pg));
    fixture::read(&cat, Read::Head, 0)
        .await
        .map_err(|_| "read pool cannot see seeded fixture")?;
    let probes = probe::statements().await?;
    let start = runtime.monotonic_ms();
    let unloaded = reads(
        &reader,
        &probes,
        runtime,
        start,
        u64::from(config.unloaded_seconds) * 1000,
        config.reads_per_minute,
    )
    .await;
    let start = runtime.monotonic_ms();
    let duration = u64::from(config.minutes) * 60_000;
    let (write_result, loaded, sampled) = join3(
        writes(Writes {
            cat: &cat,
            rt: runtime,
            start,
            minutes: config.minutes as usize,
            jobs: &jobs,
        }),
        reads(
            &reader,
            &probes,
            runtime,
            start,
            duration,
            config.reads_per_minute,
        ),
        advisory(rd.client(), runtime, start, duration, pg.lock_key),
    )
    .await;
    drop(rd);
    let (sample_offsets, mut waits, advisory_error) = sampled;
    let ticks = sample_offsets.len() as u64;
    let WritesResult {
        family,
        minutes: completed,
        pool: write_pool,
    } = write_result;
    let target = config.batches_per_minute;
    let expected_ticks = duration / SAMPLE_MS;
    let (enough_ticks, max_gap) = sampler_coverage(&sample_offsets, duration);
    let gap_covered = max_gap <= MAX_SAMPLE_GAP_MS as f64;
    let (unloaded_covered, loaded_covered) = (unloaded.covered(), loaded.covered());
    let r3a_coverage = Coverage {
        status: if enough_ticks
            && gap_covered
            && advisory_error.is_none()
            && unloaded_covered
            && loaded_covered
        {
            "SUFFICIENT"
        } else {
            "INCONCLUSIVE"
        },
        minimum_samples_per_read_and_phase: MIN_READ_SAMPLES,
        at_least_ninety_percent_advisory_ticks: enough_ticks,
        advisory_gap_within_tolerance: gap_covered,
        unloaded_read_coverage: unloaded_covered,
        loaded_read_coverage: loaded_covered,
    };
    let overloaded = family.values().map(|f| f.failures.overloaded).sum::<u64>()
        + unloaded.failures.overloaded
        + loaded.failures.overloaded;
    Ok(Report {
        requested_batches_per_minute: target,
        batches_per_minute: f64::from(completed.iter().sum::<u32>()) / f64::from(config.minutes),
        in_five_percent_each_minute: completed.iter().all(|&n| n.abs_diff(target) * 20 <= target),
        completed_batches_each_minute: completed,
        family,
        write_pool,
        overloaded_upper_bound_on_55p03: overloaded,
        advisory_sampling_period_ms: SAMPLE_MS,
        advisory_sampling_ticks: ticks,
        advisory_expected_ticks: expected_ticks,
        advisory_missed_ticks: expected_ticks.saturating_sub(ticks),
        advisory_sample_offsets_ms: sample_offsets,
        advisory_max_gap_ms: max_gap,
        advisory_gap_tolerance_ms: MAX_SAMPLE_GAP_MS,
        advisory_wait_samples: waits.len(),
        sampled_lock_wait_p99_ms: percentile(&mut waits, 99),
        advisory_error,
        r3a_coverage,
        unloaded_reads: unloaded,
        loaded_reads: loaded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acceptable_tick_count_cannot_hide_a_contiguous_gap() {
        let timestamps: Vec<_> = (0..40)
            .filter(|i| !(10..=12).contains(i))
            .map(|i| f64::from(i * 250))
            .collect();
        let (enough_ticks, gap) = sampler_coverage(&timestamps, 10_000);
        assert!(enough_ticks);
        assert_eq!(gap, 1_000.0);
        assert!(gap > MAX_SAMPLE_GAP_MS as f64);
        assert_eq!(sampler_coverage(&[800.0, 950.0], 1_000).1, 800.0);
        assert_eq!(sampler_coverage(&[0.0, 150.0], 1_000).1, 850.0);
    }

    #[test]
    fn late_results_contribute_to_both_percentiles() {
        let mut stats = ReadSamples::default();
        for _ in 0..199 {
            stats.success(1.0, 2.0, false);
        }
        for _ in 0..11 {
            stats.success(5.0, 23.0, true);
        }
        let measured = stats.finish();
        assert_eq!(measured.late_completions, 11);
        assert_eq!(measured.statement_p95_ms, Some(5.0));
        assert_eq!(measured.end_to_end_p95_ms, Some(23.0));
    }

    #[test]
    fn missing_reads_or_timeouts_fail_coverage() {
        let reads = |n, timeout| {
            let stat = || {
                let mut s = ReadSamples {
                    scheduled: n + usize::from(timeout),
                    ..ReadSamples::default()
                };
                for _ in 0..n {
                    s.success(1.0, 2.0, false);
                }
                if timeout {
                    s.timeout(READ_TIMEOUT_MS);
                }
                s.finish()
            };
            Reads {
                get: stat(),
                head: stat(),
                list: stat(),
                failures: Failures::default(),
            }
        };
        assert!(reads(200, false).covered());
        assert!(!reads(199, false).covered());
        assert!(!reads(200, true).covered());
    }
}
