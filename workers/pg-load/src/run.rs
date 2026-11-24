use crate::fixture::{self, OpError, Read};
use crate::{percentile, Config, Family, Job};
use futures_util::{future::join3, stream::FuturesUnordered, StreamExt};
use serde::Serialize;
use std::{collections::BTreeMap, time::Duration};
use tokio_postgres::Client;
use velmora_bridge::{
    pg::{PgConfig, PgConnect, PgSql},
    sql::SqlCatalog,
    types::UnixMs,
};

const WRITE_LANES: usize = 3;
const SAMPLE_MS: u64 = 250;
const ARM_KEY: &str = "pg_load_fixture_v1";

#[allow(async_fn_in_trait)]
pub trait Runtime {
    fn monotonic_ms(&self) -> f64;
    fn wall_ms(&self) -> i64;
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
    failures: Failures,
}

#[derive(Serialize)]
struct Latency {
    samples: usize,
    p95_ms: Option<f64>,
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
    // All six WP1 overload SQLSTATEs are mapped to the same public error.
    overloaded_upper_bound_on_55p03: u64,
    advisory_sampling_period_ms: u64,
    advisory_sampling_ticks: u64,
    advisory_expected_ticks: u64,
    advisory_wait_samples: usize,
    sampled_lock_wait_p99_ms: Option<f64>,
    unloaded_reads: Reads,
    loaded_reads: Reads,
}

impl Report {
    pub fn usable(&self) -> bool {
        self.family
            .values()
            .all(|f| f.failures.refused + f.failures.other == 0)
            && [&self.unloaded_reads, &self.loaded_reads]
                .into_iter()
                .all(|r| {
                    r.failures.overloaded + r.failures.refused + r.failures.other == 0
                        && r.get.samples > 0
                        && r.head.samples > 0
                        && r.list.samples > 0
                })
            && self.advisory_sampling_ticks > 0
    }

    pub fn meets_local_rate(&self) -> bool {
        self.usable()
            && self.in_five_percent_each_minute
            && self.overloaded_upper_bound_on_55p03 == 0
    }
}

type Cat<C> = SqlCatalog<PgSql<C>>;

async fn reads<C: PgConnect>(
    cat: &Cat<C>,
    runtime: &impl Runtime,
    start: f64,
    ms: u64,
    rate: u32,
) -> Reads {
    let mut samples: [Vec<f64>; 3] = Default::default();
    let mut failures = Failures::default();
    let deadline = start + ms as f64;
    for i in 0..(ms * u64::from(rate) / 60_000) {
        until(runtime, start + (i * 60_000 / u64::from(rate)) as f64).await;
        let t = runtime.monotonic_ms();
        if t >= deadline {
            break;
        }
        let operation = (i % 3) as usize;
        match fixture::read(
            cat,
            [Read::Get, Read::Head, Read::List][operation],
            i as usize / 3,
        )
        .await
        {
            Ok(()) => {
                let done = runtime.monotonic_ms();
                if done <= deadline {
                    samples[operation].push((done - t).max(0.0));
                }
            }
            Err(error) => failures.add(error),
        }
    }
    // Do not begin the loaded phase early, even if all unloaded probes finished early.
    until(runtime, deadline).await;
    let [get, head, list] = samples.map(|mut values| Latency {
        samples: values.len(),
        p95_ms: percentile(&mut values, 95),
    });
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

async fn writes<C: PgConnect, R: Runtime>(
    w: Writes<'_, C, R>,
) -> (BTreeMap<Family, FamilyResult>, Vec<u32>) {
    let provider = fixture::provider();
    let mut lanes = FuturesUnordered::new();
    for lane in 0..WRITE_LANES {
        let w = &w;
        let provider = &provider;
        lanes.push(async move {
            let mut counts: BTreeMap<_, FamilyResult> = BTreeMap::new();
            let mut minutes = vec![0; w.minutes];
            for (i, job) in w.jobs.iter().enumerate().skip(lane).step_by(WRITE_LANES) {
                let stats = counts.entry(job.family).or_default();
                stats.planned_batches += job.family.batches();
                until(w.rt, w.start + job.at_ms as f64).await;
                if w.rt.monotonic_ms() >= w.start + (w.minutes * 60_000) as f64 {
                    continue;
                }
                let result = fixture::write(
                    w.cat,
                    provider,
                    job.family,
                    i,
                    UnixMs(w.rt.wall_ms()),
                    || {
                        let minute = ((w.rt.monotonic_ms() - w.start).max(0.0) as usize) / 60_000;
                        if let Some(count) = minutes.get_mut(minute) {
                            *count += 1;
                            stats.completed_batches += 1;
                        } else {
                            stats.late_batches += 1;
                        }
                    },
                )
                .await;
                if let Err(error) = result {
                    stats.failures.add(error);
                }
            }
            (counts, minutes)
        });
    }
    let mut result: BTreeMap<Family, FamilyResult> = BTreeMap::new();
    let mut minutes = vec![0; w.minutes];
    while let Some((counts, buckets)) = lanes.next().await {
        for (family, counts) in counts {
            let stat = result.entry(family).or_default();
            stat.planned_batches += counts.planned_batches;
            stat.completed_batches += counts.completed_batches;
            stat.late_batches += counts.late_batches;
            stat.failures.overloaded += counts.failures.overloaded;
            stat.failures.refused += counts.failures.refused;
            stat.failures.other += counts.failures.other;
        }
        for (total, done) in minutes.iter_mut().zip(buckets) {
            *total += done;
        }
    }
    (result, minutes)
}

async fn advisory(
    client: &Client,
    runtime: &impl Runtime,
    start: f64,
    duration: u64,
    lock: i64,
) -> Result<(u64, Vec<f64>), String> {
    let mut waits = Vec::new();
    let mut ticks = 0;
    let mut next_tick = 0;
    while next_tick < duration / SAMPLE_MS {
        let elapsed = (runtime.monotonic_ms() - start).max(0.0) as u64;
        let tick = (elapsed / SAMPLE_MS).max(next_tick);
        if tick >= duration / SAMPLE_MS {
            break;
        }
        until(runtime, start + (tick * SAMPLE_MS) as f64).await;
        let rows = client.query("SELECT EXTRACT(EPOCH FROM (clock_timestamp()-l.waitstart))::float8 * 1000 \
             FROM pg_catalog.pg_stat_activity a JOIN pg_catalog.pg_locks l USING(pid) \
             WHERE a.datname=current_database() AND a.wait_event='advisory' \
             AND l.locktype='advisory' AND NOT l.granted AND l.waitstart IS NOT NULL AND l.objsubid=1 \
             AND l.classid::bigint=($1::bigint >> 32) AND l.objid::bigint=($1::bigint & 4294967295)", &[&lock])
            .await.map_err(|e| fixture::sql_error("sample advisory waits", e))?;
        for row in rows {
            waits.push(row.get::<_, f64>(0).max(0.0));
        }
        ticks += 1;
        next_tick = tick + 1;
    }
    Ok((ticks, waits))
}

async fn target(client: &Client) -> Result<(String, String, String), String> {
    let row = client.query_one("SELECT current_database()::text,current_schema()::text,current_user::text, \
        EXISTS (SELECT FROM meta WHERE k=$1 AND v=1) AND NOT EXISTS (SELECT FROM rollback_stamp LIMIT 1)", &[&ARM_KEY])
        .await.map_err(|e| fixture::sql_error("check drill target", e))?;
    if !row.get::<_, bool>(3) {
        return Err("target is not armed or has rollback stamps".into());
    }
    Ok((row.get(0), row.get(1), row.get(2)))
}

/// Uses at most three writers, one read probe, and one advisory sampler.
/// The two connectors must point at the same explicitly armed drill copy.
pub async fn run<C: PgConnect + Clone, R: Runtime>(
    writer: C,
    reader: C,
    runtime: &R,
    config: &Config,
) -> Result<Report, String> {
    let jobs = config.plan();
    let pg = PgConfig::default();
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
            .query_one(
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
    let claimed = wr
        .client()
        .execute("UPDATE meta SET v=2 WHERE k=$1 AND v=1", &[&ARM_KEY])
        .await
        .map_err(|e| fixture::sql_error("claim drill marker", e))?;
    if claimed != 1 {
        return Err("drill was already claimed".into());
    }
    // The read origin must see the same one-shot claim, not a separately armed DB.
    let sees_claim: bool = rd
        .client()
        .query_one(
            "SELECT EXISTS(SELECT FROM meta WHERE k=$1 AND v=2)",
            &[&ARM_KEY],
        )
        .await
        .map_err(|e| fixture::sql_error("verify drill claim on read pool", e))?
        .get(0);
    if !sees_claim {
        return Err("read pool does not see drill claim".into());
    }
    fixture::seed(wr.client(), &jobs).await?;
    drop(wr);
    let cat = SqlCatalog::new(PgSql::new(writer, reader, pg));
    fixture::read(&cat, Read::Head, 0)
        .await
        .map_err(|_| "read pool cannot see seeded fixture")?;
    let start = runtime.monotonic_ms();
    let unloaded = reads(
        &cat,
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
        reads(&cat, runtime, start, duration, config.reads_per_minute),
        advisory(rd.client(), runtime, start, duration, pg.lock_key),
    )
    .await;
    drop(rd);
    let (ticks, mut waits) = sampled?;
    let (family, completed) = write_result;
    let target = config.batches_per_minute;
    let overloaded = family.values().map(|f| f.failures.overloaded).sum::<u64>()
        + unloaded.failures.overloaded
        + loaded.failures.overloaded;
    Ok(Report {
        requested_batches_per_minute: target,
        batches_per_minute: f64::from(completed.iter().sum::<u32>()) / f64::from(config.minutes),
        in_five_percent_each_minute: completed.iter().all(|&n| n.abs_diff(target) * 20 <= target),
        completed_batches_each_minute: completed,
        family,
        overloaded_upper_bound_on_55p03: overloaded,
        advisory_sampling_period_ms: SAMPLE_MS,
        advisory_sampling_ticks: ticks,
        advisory_expected_ticks: duration / SAMPLE_MS,
        advisory_wait_samples: waits.len(),
        sampled_lock_wait_p99_ms: percentile(&mut waits, 99),
        unloaded_reads: unloaded,
        loaded_reads: loaded,
    })
}
