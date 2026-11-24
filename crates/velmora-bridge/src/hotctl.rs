//! Pure hot-cache sizing. No scheduler, persistence or eviction policy.

use crate::config::{HotCtlConfig, HotCtlMode, MISS_USD_PER_GIB};
use crate::types::{HotShape, UnixMs};

const GIB: f64 = (1u64 << 30) as f64;
const HOUR_MS: i64 = 3_600_000;
const HOURS_PER_DAY: f64 = 24.;
const DAYS_PER_MONTH: f64 = 30.;
const STORAGE_USD_PER_GIB_MONTH: f64 = 0.0161;
/// Index-scan signal budget until the catalogue has constant-cost totals.
pub const MEASURABLE_MAX_BYTES: u64 = 1 << 40;
pub const EXTENT_BYTES: u64 = 16 << 20;
pub const REUSE_HOURS: [u32; 10] = [1, 3, 6, 12, 24, 48, 72, 168, 336, 720];
pub const OLDER: usize = REUSE_HOURS.len();
pub const FIRST: usize = OLDER + 1;
pub const MISS_BUCKETS: usize = FIRST + 1;

/// Cumulative ciphertext bytes. The SQL port uses these keys in bucket order.
pub const HIT_KEY: &str = "hotc_hit";
pub const MISS_KEYS: [&str; MISS_BUCKETS] = [
    "hotg_1h",
    "hotg_3h",
    "hotg_6h",
    "hotg_12h",
    "hotg_24h",
    "hotg_48h",
    "hotg_72h",
    "hotg_7d",
    "hotg_14d",
    "hotg_30d",
    "hotg_older",
    "hotg_first",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub hit: u64,
    pub miss: [u64; MISS_BUCKETS],
}

#[derive(Clone, Copy, Debug)]
pub struct Signals {
    pub shape: HotShape,
    pub counters: Counters,
}

#[derive(Clone, Copy, Debug)]
pub struct Inputs {
    pub now: UnixMs,
    /// None if either the shape or the counters could not be read.
    pub signals: Option<Signals>,
}

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub fixed_cap: u64,
    pub config: HotCtlConfig,
}

/// Smoothed bytes/day. Using rates (rather than deltas) lets the next sample
/// cover a missed cron tick without counting its traffic as a one-hour burst.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rates {
    pub hit: f64,
    pub miss: [f64; MISS_BUCKETS],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    pub observed_at: UnixMs,
    pub counters: Counters,
    /// None until there has been an elapsed interval between snapshots.
    pub rates: Option<Rates>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct State {
    pub cap: Option<u64>,
    pub last_grow_at: Option<UnixMs>,
    pub last_shrink_at: Option<UnixMs>,
    pub sample: Option<Sample>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Fixed,
    HoldErr,
    Idle,
    FirstRead,
    GrowCx,
    GrowCost,
    Shrink,
    Hold,
    CappedAtMax,
    MaxLowered,
    UnlimitedNeedsCounters,
    NeedsCounters,
}

impl Reason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::HoldErr => "hold_err",
            Self::Idle => "idle",
            Self::FirstRead => "first_read",
            Self::GrowCx => "grow_cx",
            Self::GrowCost => "grow_cost",
            Self::Shrink => "shrink",
            Self::Hold => "hold",
            Self::CappedAtMax => "capped_at_max",
            Self::MaxLowered => "max_lowered",
            Self::UnlimitedNeedsCounters => "unlimited_needs_counters",
            Self::NeedsCounters => "needs_counters",
        }
    }
}

/// The actual rate-limited change, distinct from why the controller asked for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Hold,
    Grow,
    Shrink,
}

impl Step {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Grow => "grow",
            Self::Shrink => "shrink",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Decision {
    pub target: u64,
    /// Configured spending bound; None reports "none", even when signal
    /// coverage temporarily limits the computed target.
    pub max_bytes: Option<u64>,
    /// Whether to replace the persisted target; the sample may advance even
    /// when the target is held or the deadband suppresses a change.
    pub target_changed: bool,
    pub step: Step,
    pub reason: Reason,
    pub tau_h: Option<f64>,
    pub rho_gib_h: Option<f64>,
    pub hit_ratio: Option<f64>,
    pub hit_floor_breached: bool,
    pub reads_day: Option<f64>,
    pub save_usd_mo: Option<f64>,
    pub next: State,
}

impl Sample {
    fn baseline(now: UnixMs, counters: Counters) -> Self {
        Self {
            observed_at: now,
            counters,
            rates: None,
        }
    }

    fn update(self, now: UnixMs, counters: Counters) -> Option<(Self, Rates)> {
        let elapsed_h = now.0.checked_sub(self.observed_at.0)? as f64 / HOUR_MS as f64;
        if elapsed_h <= 0. {
            return None;
        }
        let weight = if self.rates.is_some() {
            -(-elapsed_h / HOURS_PER_DAY).exp_m1()
        } else {
            1.
        };
        let previous = self.rates.unwrap_or_default();
        let update = |old: f64, start: u64, end: u64| {
            if !old.is_finite() || old < 0. {
                return None;
            }
            let daily = end.checked_sub(start)? as f64 * HOURS_PER_DAY / elapsed_h;
            Some(old * (1. - weight) + daily * weight)
        };
        let mut rates = Rates {
            hit: update(previous.hit, self.counters.hit, counters.hit)?,
            ..Rates::default()
        };
        for i in 0..MISS_BUCKETS {
            rates.miss[i] = update(previous.miss[i], self.counters.miss[i], counters.miss[i])?;
        }
        Some((
            Self {
                observed_at: now,
                counters,
                rates: Some(rates),
            },
            rates,
        ))
    }
}

fn sum_between(rates: &Rates, lower_h: f64, upper_h: f64) -> f64 {
    REUSE_HOURS
        .into_iter()
        .zip(rates.miss)
        .filter_map(|(edge, bytes)| {
            let edge = f64::from(edge);
            (lower_h < edge && edge <= upper_h).then_some(bytes)
        })
        .sum()
}

fn save_usd_mo(rates: &Rates, rho: f64, fixed: u64, target: u64) -> f64 {
    let storage = (fixed as f64 - target as f64) / GIB * STORAGE_USD_PER_GIB_MONTH;
    // Report the churn penalty only for newly cold reuse ages. When the
    // target grows that interval is empty; this is a conservative estimate.
    if rho == 0. || target >= fixed {
        return storage;
    }
    let miss_cost = sum_between(rates, target as f64 / rho, fixed as f64 / rho) / GIB
        * DAYS_PER_MONTH
        * MISS_USD_PER_GIB;
    storage - miss_cost
}

/// Evaluate a single hourly sample. `Params` comes from validated config.
/// Eviction continues to use the fixed cap until separately wired.
pub fn decide(input: Inputs, state: &State, p: &Params) -> Decision {
    let cfg = p.config;
    let mut d = Decision {
        target: p.fixed_cap,
        max_bytes: cfg.max_bytes,
        target_changed: false,
        step: Step::Hold,
        reason: Reason::Fixed,
        tau_h: None,
        rho_gib_h: None,
        hit_ratio: None,
        hit_floor_breached: false,
        reads_day: None,
        save_usd_mo: None,
        next: *state,
    };
    if cfg.mode == HotCtlMode::Fixed {
        return d;
    }

    let max = cfg.max_bytes.unwrap_or(u64::MAX).min(MEASURABLE_MAX_BYTES);
    let prev_cap = state.cap.unwrap_or(p.fixed_cap);
    // An existing target above a newly lowered maximum must walk down,
    // not jump. The fixed cap supplies a bounded seed for a new controller.
    let cap = state.cap.map_or_else(
        || prev_cap.clamp(cfg.min_bytes, max),
        |cap| cap.max(cfg.min_bytes),
    );
    d.target = cap;
    d.reason = Reason::HoldErr;
    let Some(Signals { shape, counters }) = input.signals else {
        return d;
    };
    let Some(stamped) = shape.evictable_bytes.checked_sub(shape.never_read_bytes) else {
        return d;
    };
    let tau = match (stamped, shape.oldest_read_at) {
        (0, None) => 1.,
        (1.., Some(oldest)) => {
            ((input.now.0.saturating_sub(oldest.0)) as f64 / HOUR_MS as f64).max(1.)
        }
        _ => return d,
    };
    let (sample, rates) = match state.sample {
        None => {
            // No rate yet: a baseline is not evidence of idle traffic.
            d.next.sample = Some(Sample::baseline(input.now, counters));
            return d;
        }
        Some(old) if old.observed_at >= input.now => return d,
        Some(old) => match old.update(input.now, counters) {
            Some(sample) => sample,
            None => {
                // A reset is a sampling gap, not zero traffic. Rebase
                // the snapshot but keep the last good smoothed rates.
                let mut baseline = Sample::baseline(input.now, counters);
                baseline.rates = old.rates.filter(|rates| {
                    rates.hit.is_finite()
                        && rates.hit >= 0.
                        && rates.miss.iter().all(|v| v.is_finite() && *v >= 0.)
                });
                d.next.sample = Some(baseline);
                return d;
            }
        },
    };
    d.next.sample = Some(sample);

    let rho = stamped as f64 / tau;
    let rates = &rates;
    let reads = (rates.hit + rates.miss.iter().sum::<f64>()) / EXTENT_BYTES as f64;
    let horizon = f64::from(cfg.horizon_h);
    let active = rates.hit + sum_between(rates, 0., horizon) + rates.miss[FIRST];
    let hit = (active > 0.).then(|| rates.hit / active);
    d.tau_h = Some(tau);
    d.rho_gib_h = Some(rho / GIB);
    d.reads_day = Some(reads);
    d.hit_ratio = hit;
    let under_floor = hit.is_some_and(|h| h < cfg.hit_floor);
    d.hit_floor_breached = under_floor;

    let (want, reason) = if reads < cfg.min_reads as f64 {
        (cfg.min_bytes as f64, Reason::Idle)
    } else {
        let cx = under_floor
            .then(|| {
                REUSE_HOURS
                    .into_iter()
                    .map(f64::from)
                    .take_while(|&edge| edge <= horizon)
                    .find(|&edge| {
                        (rates.hit + sum_between(rates, 0., edge)) / active >= cfg.hit_floor
                    })
            })
            .flatten();
        let cost = REUSE_HOURS.into_iter().rev().map(f64::from).find(|&edge| {
            edge <= horizon
                && edge > tau
                && sum_between(rates, tau, edge) * DAYS_PER_MONTH * MISS_USD_PER_GIB
                    > rho * (edge - tau) * STORAGE_USD_PER_GIB_MONTH
        });
        match (cx, cost) {
            (Some(a), Some(b)) if rho > 0. && b > a => (rho * b, Reason::GrowCost),
            (Some(a), _) if rho > 0. => (rho * a, Reason::GrowCx),
            (_, Some(b)) if rho > 0. => (rho * b, Reason::GrowCost),
            _ if under_floor && cx.is_none() && rates.miss[FIRST] > 0. => {
                (cap as f64, Reason::FirstRead)
            }
            _ if hit.is_some_and(|h| h >= cfg.hit_floor + cfg.hit_margin) => {
                ((cap - cap / 10) as f64, Reason::Shrink)
            }
            _ => (cap as f64, Reason::Hold),
        }
    };

    // Don't let the reuse model recommend a smaller cache when measured
    // active traffic is missing the floor. The spending limit still wins.
    let (want, reason) = if under_floor && reason != Reason::Idle && want < cap as f64 {
        (cap as f64, Reason::Hold)
    } else {
        (want, reason)
    };
    let wanted = (want.ceil() as u64).clamp(cfg.min_bytes, max);
    d.reason = if want > max as f64 || cap > max {
        match cfg.max_bytes {
            None => Reason::UnlimitedNeedsCounters,
            Some(limit) if limit > max => Reason::NeedsCounters,
            Some(_) => Reason::CappedAtMax,
        }
    } else {
        reason
    };
    let due = |last: Option<UnixMs>, hours| {
        last.is_none_or(|last| input.now.0.saturating_sub(last.0) >= hours * HOUR_MS)
    };
    let mut target = if wanted > cap {
        wanted.min(cap.saturating_mul(2))
    } else if wanted < cap && due(state.last_grow_at, 24) && due(state.last_shrink_at, 6) {
        wanted.max(cap - cap / 10)
    } else {
        cap
    };
    // Idle must reach the exact minimum even if the last step is <5%.
    let reaches_bound =
        (reason == Reason::Idle && target == cfg.min_bytes) || (cap > max && target == max);
    if !reaches_bound && u128::from(target.abs_diff(cap)) * 20 < u128::from(cap) {
        target = cap;
    }
    if target > cap {
        d.step = Step::Grow;
        d.next.last_grow_at = Some(input.now);
    } else if target < cap {
        d.step = Step::Shrink;
        d.next.last_shrink_at = Some(input.now);
        if cfg.max_bytes.is_some_and(|limit| limit < cap) {
            d.reason = Reason::MaxLowered;
        } else if d.reason != Reason::Idle {
            d.reason = Reason::Shrink;
        }
    } else if matches!(d.reason, Reason::GrowCx | Reason::GrowCost | Reason::Shrink) {
        d.reason = Reason::Hold;
    }
    d.target = target;
    d.target_changed = target != prev_cap;
    d.next.cap = Some(target);
    d.save_usd_mo = Some(save_usd_mo(rates, rho, p.fixed_cap, target));
    d
}
