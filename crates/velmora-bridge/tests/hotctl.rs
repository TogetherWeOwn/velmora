use velmora_bridge::config::{HotCtlConfig, HotCtlMode};
use velmora_bridge::hotctl::{
    decide, Counters, Inputs, Params, Rates, Reason, Sample, Signals, State, EXTENT_BYTES,
    MEASURABLE_MAX_BYTES,
};
use velmora_bridge::{HotShape, UnixMs};

const GIB: u64 = 1 << 30;
const HOUR: i64 = 3_600_000;

fn params() -> Params {
    Params {
        fixed_cap: 100 * GIB,
        config: HotCtlConfig {
            mode: HotCtlMode::Shadow,
            ..HotCtlConfig::default()
        },
    }
}

fn inputs(hour: i64, stamped_gib: u64, tail_age_h: i64, counters: Counters) -> Inputs {
    Inputs {
        now: UnixMs(hour * HOUR),
        signals: Some(Signals {
            shape: HotShape {
                evictable_bytes: stamped_gib * GIB,
                never_read_bytes: 0,
                oldest_read_at: (stamped_gib > 0).then_some(UnixMs((hour - tail_age_h) * HOUR)),
            },
            counters,
        }),
    }
}

#[test]
fn fixed_and_unreadable_hold_without_updating_samples() {
    let mut p = params();
    let state = State {
        cap: Some(200 * GIB),
        ..State::default()
    };
    let unreadable = Inputs {
        now: UnixMs(HOUR),
        signals: None,
    };
    let d = decide(unreadable, &state, &p);
    assert_eq!(d.reason, Reason::HoldErr);
    assert_eq!(d.next, state);
    p.config.mode = HotCtlMode::Fixed;
    let d = decide(unreadable, &state, &p);
    assert_eq!(d.reason, Reason::Fixed);
    assert_eq!(d.target, p.fixed_cap);
    assert_eq!(d.next, state);
}

#[test]
fn reset_counters_hold_and_rebaseline() {
    let p = params();
    let prior = Counters {
        hit: 50 * GIB,
        ..Counters::default()
    };
    let d = decide(inputs(0, 0, 0, prior), &State::default(), &p);
    let reset = decide(inputs(1, 0, 0, Counters::default()), &d.next, &p);
    assert_eq!(reset.reason, Reason::HoldErr);
    assert_eq!(reset.target, d.target);
    assert_ne!(
        decide(inputs(2, 0, 0, Counters::default()), &reset.next, &p).reason,
        Reason::HoldErr
    );
}

#[test]
fn first_reads_do_not_grow_and_archive_misses_do_not_drive_growth() {
    for (miss_idx, reason) in [(11, Reason::FirstRead), (8, Reason::Shrink)] {
        let p = params();
        let base = State {
            last_grow_at: Some(UnixMs(0)),
            ..State::default()
        };
        let d = decide(inputs(0, 100, 1, Counters::default()), &base, &p);
        let mut c = Counters {
            hit: GIB,
            ..Counters::default()
        };
        c.miss[miss_idx] = 1_000 * GIB;
        let after = decide(inputs(1, 100, 1, c), &d.next, &p);
        assert_eq!(after.reason, reason);
        assert_eq!(after.target, d.target);
    }
}

#[test]
fn sub_five_percent_target_is_held_except_to_reach_the_idle_minimum() {
    let mut p = params();
    p.config.max_bytes = Some(103 * GIB);
    let base = State {
        last_grow_at: Some(UnixMs(0)),
        ..State::default()
    };
    let d = decide(inputs(0, 100, 4, Counters::default()), &base, &p);
    let mut c = Counters::default();
    c.miss[4] = 10 * GIB;
    let d = decide(inputs(1, 100, 4, c), &d.next, &p);
    assert_eq!(d.target, 100 * GIB);
    assert_eq!(d.reason, Reason::CappedAtMax);

    let base = State {
        cap: Some(p.config.min_bytes + 1),
        ..State::default()
    };
    let d = decide(inputs(0, 0, 0, Counters::default()), &base, &p);
    assert_eq!(d.target, p.config.min_bytes);
}

#[test]
fn idle_walks_down_in_bounded_steps_and_honors_both_cooldowns() {
    let p = params();
    for (start, steps) in [(p.fixed_cap, 22), (p.config.max_bytes.unwrap(), 44)] {
        let mut state = State {
            cap: Some(start),
            last_grow_at: Some(UnixMs(0)),
            ..State::default()
        };
        let mut c = Counters::default();
        let mut changes = Vec::new();
        for h in 0..14 * 24 {
            // 192 extent reads/day, below the gate even after convergence.
            c.hit += 8 * EXTENT_BYTES;
            let d = decide(inputs(h, 0, 0, c), &state, &p);
            let cap = state.cap.unwrap();
            assert_eq!(d.reason, Reason::Idle);
            assert!((p.config.min_bytes..=cap).contains(&d.target));
            assert!(d.target >= cap - cap / 10);
            if d.target != cap {
                changes.push(h);
            }
            state = d.next;
        }
        assert_eq!(changes[0], 24);
        assert!(changes.windows(2).all(|pair| pair[1] - pair[0] >= 6));
        assert!(changes.len() <= steps);
        assert_eq!(state.cap, Some(p.config.min_bytes));
    }
}

#[test]
fn unlimited_is_guarded_and_lowering_the_bound_walks_down() {
    let mut p = params();
    p.config.max_bytes = None;
    let mut state = State::default();
    let mut c = Counters::default();
    for h in 0..8 {
        if h > 0 {
            c.miss[4] += 100 * GIB;
        }
        let cap = state.cap.unwrap_or(p.fixed_cap);
        let d = decide(inputs(h, cap / GIB, 1, c), &state, &p);
        assert!(d.target <= 2 * cap);
        assert!(d.target <= MEASURABLE_MAX_BYTES);
        assert_eq!(d.max_bytes, None);
        state = d.next;
    }
    assert_eq!(state.cap, Some(MEASURABLE_MAX_BYTES));
    let d = decide(inputs(8, 1024, 1, c), &state, &p);
    assert_eq!(d.reason.as_str(), "unlimited_needs_counters");
    p.config.max_bytes = Some(1000 * GIB);
    let d = decide(inputs(9, 1024, 1, c), &d.next, &p);
    assert_eq!(
        d.target, MEASURABLE_MAX_BYTES,
        "grow cooldown still applies"
    );
    assert_eq!(d.max_bytes, Some(1000 * GIB));
    let d = decide(inputs(30, 1024, 1, c), &d.next, &p);
    assert_eq!(
        d.target,
        1000 * GIB,
        "bound change can close within the deadband"
    );
    p.config.max_bytes = Some(500 * GIB);
    let d = decide(inputs(36, 1000, 1, c), &d.next, &p);
    assert_eq!(
        d.target,
        900 * GIB,
        "a large bound change still steps down at 10%"
    );
    p.config.max_bytes = None;
    c.miss[4] += 100 * GIB;
    let d = decide(inputs(37, 900, 1, c), &d.next, &p);
    assert_eq!(d.target, MEASURABLE_MAX_BYTES);
    assert_eq!(d.reason, Reason::UnlimitedNeedsCounters);
}

#[test]
fn repeated_18_hour_cohort_recovers_the_hit_floor_within_six_runs() {
    let p = params();
    let mut c = Counters::default();
    const DAY_BYTES: u64 = 2_000_000_000_000;
    const HOURLY_BYTES: u64 = DAY_BYTES / 24;
    const COHORT_GIB: u64 = 115;
    // The 18 h cohort is revisited, and repeated reads of its same extents
    // make traffic larger than unique cache occupancy. The baseline is the
    // measured warm workload before this step, at a smaller request rate.
    let mut state = State {
        cap: Some(p.fixed_cap),
        sample: Some(Sample {
            observed_at: UnixMs(0),
            counters: c,
            rates: {
                let mut rates = Rates {
                    hit: 0.90 * DAY_BYTES as f64,
                    ..Rates::default()
                };
                rates.miss[11] = 0.046 * DAY_BYTES as f64;
                rates
            },
        }),
        ..State::default()
    };
    let mut breached = false;
    let mut grew = false;
    for h in 1..=14 * 24 {
        let cap = state.cap.unwrap();
        let unique = COHORT_GIB * GIB;
        let misses = unique.saturating_sub(cap).min(HOURLY_BYTES);
        c.hit += HOURLY_BYTES - misses;
        c.miss[4] += misses;
        let d = decide(inputs(h, cap.min(unique) / GIB, 18, c), &state, &p);
        if h <= 6 {
            breached |= d.hit_ratio.unwrap() < p.config.hit_floor;
            grew |= d.target > cap;
        }
        if h == 6 {
            assert!(breached && grew);
            assert!(d.hit_ratio.unwrap() >= p.config.hit_floor, "{d:?}");
        }
        state = d.next;
    }
}

#[test]
fn stationary_workload_changes_direction_at_most_twice_and_idle_recovers() {
    let p = params();
    let mut state = State::default();
    let mut c = Counters::default();
    let mut direction = 0;
    let mut changes = 0;
    for h in 0..14 * 24 {
        if h > 0 && h <= 7 * 24 {
            c.hit += 23 * EXTENT_BYTES;
            c.miss[11] += EXTENT_BYTES; // Stable ~96% hit ratio, above floor, below shrink margin.
        }
        let d = decide(inputs(h, 100, 18, c), &state, &p);
        let step = d.target.cmp(&state.cap.unwrap_or(p.fixed_cap));
        if !step.is_eq() {
            let sign = if step.is_gt() { 1 } else { -1 };
            changes += usize::from(direction != 0 && direction != sign);
            direction = sign;
        }
        if h == 7 * 24 {
            assert!(changes <= 2);
        }
        state = d.next;
    }
    assert_eq!(state.cap, Some(p.config.min_bytes));
}

#[test]
fn growth_doubles_at_most_and_reports_unmet_hit_floor_at_max() {
    let p = params();
    let mut state = State::default();
    let mut c = Counters::default();
    for h in 0..14 * 24 {
        // Uniform 2 TB/day with 18 h reuse needs 1.5 TB of occupancy.
        // A byte-reuse model with that deterministic age never hits at 1 TiB.
        let cap = state.cap.unwrap_or(p.fixed_cap);
        if h > 0 {
            c.miss[4] += 2_000_000_000_000 / 24;
        }
        let tail_h = (cap / (2_000_000_000_000 / 24)).max(1) as i64;
        let decision = decide(inputs(h, cap / GIB, tail_h, c), &state, &p);
        assert!((p.config.min_bytes..=p.config.max_bytes.unwrap()).contains(&decision.target));
        assert!(decision.target <= cap * 2);
        assert!(decision.target >= cap - cap / 10);
        state = decision.next;
        if h >= 8 {
            assert_eq!(decision.target, p.config.max_bytes.unwrap());
            assert_eq!(decision.reason, Reason::CappedAtMax);
            assert!(decision.hit_ratio.unwrap() < p.config.hit_floor);
        }
    }
}
