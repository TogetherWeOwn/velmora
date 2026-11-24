//! Catalogue load driver. No production Worker imports this crate.

mod fixture;
mod probe;
mod run;
#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
mod worker_socket;

pub use probe::{DrillConnect, DrillSession};
pub use run::{run, Runtime};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    PutPublish,
    MultipartCreate,
    MultipartPart,
    MultipartComplete,
    MultipartAbort,
    Delete,
    OutboxPostClaim,
    OutboxPostPlan,
    OutboxPostMark,
    OutboxPostAdvance,
    OutboxVerifyClaim,
    OutboxVerifyRecord,
    OutboxVerifyAdvance,
    OutboxReleaseClaim,
    OutboxReleaseAdvance,
    PermitsAcquire,
    PermitsRelease,
    Gc,
    Usage,
    Dispatch,
}

impl Family {
    pub fn batches(self) -> u32 {
        match self {
            Self::PutPublish | Self::MultipartComplete => 2, // floor, then publish
            Self::Delete | Self::Dispatch => 3,
            Self::Usage => 2, // start, then a bounded recount step
            _ => 1,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    batches_per_minute: u32,
    minutes: u32,
    #[serde(default = "read_rate")]
    reads_per_minute: u32,
    #[serde(default = "unloaded_seconds")]
    unloaded_seconds: u32,
    mix: BTreeMap<Family, u32>,
}

fn read_rate() -> u32 {
    1500
}
fn unloaded_seconds() -> u32 {
    30
}

pub fn parse_config(json: &str) -> Result<Config, &'static str> {
    let cfg: Config = serde_json::from_str(json).map_err(|_| "invalid load configuration")?;
    if !(1..=16_000).contains(&cfg.batches_per_minute)
        || !(1..=20).contains(&cfg.minutes)
        || !(60..=2400).contains(&cfg.reads_per_minute)
        || !(3..=60).contains(&cfg.unloaded_seconds)
        || cfg.mix.is_empty()
        || cfg.mix.values().any(|w| !(1..=1_000_000).contains(w))
        || !cfg
            .mix
            .keys()
            .any(|f| f.batches() <= cfg.batches_per_minute * cfg.minutes)
    {
        return Err("load configuration outside supported bounds");
    }
    Ok(cfg)
}

#[derive(Clone, Copy, Debug)]
pub struct Job {
    pub family: Family,
    pub at_ms: u64,
}

impl Config {
    pub fn plan(&self) -> Vec<Job> {
        // Weighted fair scheduling in *batch* units. Greedily choose the
        // smallest virtual finish time, comparing fractions as integers.
        let total = self.batches_per_minute * self.minutes;
        let mut cursor = 0;
        let mut counts: BTreeMap<_, _> = self.mix.keys().map(|&f| (f, 0)).collect();
        let mut jobs = Vec::new();
        while let Some((&family, _)) = self
            .mix
            .iter()
            .filter(|(f, _)| f.batches() <= total - cursor)
            .min_by(|(f, w), (g, v)| {
                (u64::from(counts[f] + f.batches()) * u64::from(**v))
                    .cmp(&(u64::from(counts[g] + g.batches()) * u64::from(**w)))
            })
        {
            jobs.push(Job {
                family,
                at_ms: u64::from(cursor) * 60_000 / u64::from(self.batches_per_minute),
            });
            *counts.get_mut(&family).expect("planned family") += family.batches();
            cursor += family.batches();
        }
        jobs
    }
}

pub fn percentile(values: &mut [f64], pct: usize) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable_by(f64::total_cmp);
    Some(values[(values.len() * pct).div_ceil(100) - 1])
}
