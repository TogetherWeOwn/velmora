//! The pure rules of the unit lease module: the freshness lease (ADR-TENANCY
//! §2.4 rule 12, RD-12), the alarm dispatcher (rules 4, 8, 12; RD-9), the
//! unit stamp id (§8.5, RL-5) and the write-mark helpers (§8.6).

use velmora_bridge::unit_lease::{
    alarm::*,
    lease::*,
    mark::{exact, statement_may_write, Mark},
    stamp_id::*,
};
use velmora_bridge::UnixMs;

const T0: UnixMs = UnixMs(1_800_000_000_000);
const LEASE_RULES: LeaseRules = LeaseRules::DEFAULT;
const ALARM_RULES: AlarmRules = AlarmRules::DEFAULT;
/// The state every proof in these tests was made for, and the unit holds.
const HEAD: Proven = Proven {
    state_seq: 4,
    keys_seq: 9,
    stamp_counter: Some(2),
    revoked: 3,
};

/// The alarm's view of an open unit with no failed renewals.
fn open(lease: &FreshLease) -> UnitAt<'_> {
    UnitAt {
        lease,
        closed: false,
        renew_tries: 0,
        failed_runs: 0,
    }
}

fn at(offset_ms: i64) -> UnixMs {
    UnixMs(T0.0 + offset_ms)
}

fn renew(lease: &mut FreshLease, proof_start: UnixMs, now: UnixMs) -> UnixMs {
    let previous = lease.fresh_until();
    let proof_end = UnixMs(proof_start.0 + LEASE_RULES.term_ms);
    let upper_bound = previous.map_or(proof_end, |until| until.max(proof_end));
    let until = lease
        .renew(proof_start, &HEAD, &HEAD, 0, now, &LEASE_RULES)
        .unwrap();
    assert_eq!(lease.fresh_until(), Some(until));
    assert!(until <= upper_bound);
    until
}

/// Both forms of an ungranted lease always require renewal.
#[test]
fn ungranted_leases_require_renewal() {
    for now in [UnixMs(i64::MIN), T0, UnixMs(i64::MAX)] {
        assert_eq!(
            FreshLease::expired().admit(now, &LEASE_RULES),
            Admit::RenewNeeded
        );
        assert_eq!(
            FreshLease::default().admit(now, &LEASE_RULES),
            Admit::RenewNeeded
        );
    }
}

/// A renewed lease is fresh until expiry and asks for renewal below half its term.
#[test]
fn freshness_and_renew_soon_boundaries() {
    let mut lease = FreshLease::expired();
    renew(&mut lease, T0, T0);
    assert_eq!(lease.fresh_until(), Some(at(600_000)));

    for (offset, left_ms, renew_soon) in [
        (0, 600_000, false),
        (300_000, 300_000, false),
        (300_001, 299_999, true),
        (599_999, 1, true),
    ] {
        assert_eq!(
            lease.admit(at(offset), &LEASE_RULES),
            Admit::Fresh {
                left_ms,
                renew_soon
            },
            "at offset {offset}",
        );
    }
    assert_eq!(lease.admit(at(600_000), &LEASE_RULES), Admit::RenewNeeded);
}

/// A stalled proof grants freshness from the start of the proof.
#[test]
fn stalled_proof_uses_proof_start() {
    let mut lease = FreshLease::expired();
    let now = at(20_000);
    let until = renew(&mut lease, T0, now);
    assert_eq!(lease.fresh_until(), Some(at(600_000)));
    assert!(until < UnixMs(now.0 + LEASE_RULES.term_ms));
}

/// A proof older than the allowed limit leaves the lease unchanged.
#[test]
fn proof_age_boundary() {
    let mut lease = FreshLease::expired();
    assert_eq!(
        lease.renew(T0, &HEAD, &HEAD, 0, at(30_001), &LEASE_RULES),
        Err(RenewRefused::ProofTooOld { behind_ms: 30_001 }),
    );
    assert_eq!(lease, FreshLease::expired());
    assert_eq!(renew(&mut lease, T0, at(30_000)), at(600_000));
}

/// A proof too far ahead leaves the lease unchanged and the exact limit is accepted.
#[test]
fn proof_ahead_boundary() {
    let mut lease = FreshLease::expired();
    assert_eq!(
        lease.renew(at(5_001), &HEAD, &HEAD, 0, T0, &LEASE_RULES),
        Err(RenewRefused::ProofAhead { ahead_ms: 5_001 }),
    );
    assert_eq!(lease, FreshLease::expired());
    assert_eq!(renew(&mut lease, at(5_000), T0), at(605_000));
}

/// An accepted renewal from an older proof preserves a later expiry.
#[test]
fn renewal_never_moves_expiry_backwards() {
    let mut lease = FreshLease::expired();
    let now = at(10_000);
    assert_eq!(renew(&mut lease, now, now), at(610_000));
    assert_eq!(renew(&mut lease, T0, now), at(610_000));
    assert_eq!(lease.fresh_until(), Some(at(610_000)));
}

/// Closing a fresh lease requires renewal, and a valid proof opens it again.
#[test]
fn close_and_reopen_lease() {
    let mut lease = FreshLease::expired();
    renew(&mut lease, T0, T0);
    assert!(lease.is_fresh(T0, &LEASE_RULES));
    lease.close();
    assert_eq!(lease.admit(T0, &LEASE_RULES), Admit::RenewNeeded);

    let later = at(1_000);
    renew(&mut lease, later, later);
    assert!(lease.is_fresh(later, &LEASE_RULES));
}

/// Stored expiry round-trips and valid rules require nonnegative bounds and a longer term.
#[test]
fn stored_expiry_and_rule_validation() {
    assert_eq!(FreshLease::from_stored(Some(T0)).fresh_until(), Some(T0));
    assert!(LEASE_RULES.valid());
    assert!(!LeaseRules {
        term_ms: 30_000,
        ..LEASE_RULES
    }
    .valid());
    assert!(!LeaseRules {
        term_ms: 29_999,
        ..LEASE_RULES
    }
    .valid());
    assert!(!LeaseRules {
        max_behind_ms: -1,
        ..LEASE_RULES
    }
    .valid());
    assert!(!LeaseRules {
        max_ahead_ms: -1,
        ..LEASE_RULES
    }
    .valid());
}

/// Due times choose the earliest wake, and ready duties run in duty order.
#[test]
fn due_times_and_duty_order() {
    let dues = Dues::none();
    assert_eq!(dues.earliest(), None);
    let dues = dues
        .with(Duty::Sweep, Some(at(5)))
        .with(Duty::Report, Some(at(2)));
    assert_eq!(dues.earliest(), Some(at(2)));

    let dues = dues
        .with(Duty::DayClose, Some(at(6)))
        .with(Duty::HandOut, Some(at(4)))
        .with(Duty::StampRaise, Some(at(3)));
    assert_eq!(
        dues.due_at(at(5)),
        [Duty::Sweep, Duty::HandOut, Duty::StampRaise, Duty::Report],
    );
    let order = [
        Duty::DayClose,
        Duty::Sweep,
        Duty::HandOut,
        Duty::StampRaise,
        Duty::Report,
    ];
    assert_eq!(Duty::ALL, order);
    assert_eq!(dues.due_at(at(6)), order);
}

/// A fresh lease lets the alarm run due duties with day close first.
#[test]
fn fresh_alarm_runs_due_work() {
    let lease = FreshLease::from_stored(Some(at(600_000)));
    let dues = Dues::none()
        .with(Duty::HandOut, Some(at(-1)))
        .with(Duty::DayClose, Some(T0))
        .with(Duty::Sweep, Some(T0))
        .with(Duty::Report, Some(at(1)));
    assert_eq!(
        on_alarm(T0, &open(&lease), &dues, &LEASE_RULES, &ALARM_RULES),
        AlarmRun {
            run: vec![Duty::DayClose, Duty::Sweep, Duty::HandOut],
            send_renew: false,
            retry_at: None,
        },
    );
}

/// An expired lease with due work sends only a renewal and schedules a retry.
#[test]
fn expired_alarm_defers_due_work() {
    let lease = FreshLease::expired();
    let dues = Dues::none()
        .with(Duty::DayClose, Some(T0))
        .with(Duty::HandOut, Some(T0));
    assert_eq!(
        on_alarm(T0, &open(&lease), &dues, &LEASE_RULES, &ALARM_RULES),
        AlarmRun {
            run: vec![],
            send_renew: true,
            retry_at: Some(at(60_000)),
        },
    );
}

/// An expired lease with no due work can stay idle.
#[test]
fn expired_idle_alarm_skips_renewal() {
    let lease = FreshLease::expired();
    let dues = Dues::none();
    assert_eq!(
        on_alarm(T0, &open(&lease), &dues, &LEASE_RULES, &ALARM_RULES),
        AlarmRun {
            run: vec![],
            send_renew: false,
            retry_at: None,
        },
    );
}

/// Renewal brings the retry forward so the next alarm can run all deferred duties.
#[test]
fn renewal_rearms_deferred_work() {
    let mut lease = FreshLease::expired();
    let dues = Dues::none()
        .with(Duty::DayClose, Some(T0))
        .with(Duty::Sweep, Some(T0));
    let first = on_alarm(T0, &open(&lease), &dues, &LEASE_RULES, &ALARM_RULES);
    assert!(first.send_renew);
    assert!(first.run.is_empty());
    assert_eq!(first.retry_at, Some(at(60_000)));

    let now = at(1_000);
    renew(&mut lease, at(900), now);
    let wanted = after_renew(now, &dues);
    assert_eq!(wanted, Some(now));
    assert_eq!(rearm(first.retry_at, wanted), Rearm::Set(now));
    assert_eq!(
        on_alarm(now, &open(&lease), &dues, &LEASE_RULES, &ALARM_RULES),
        AlarmRun {
            run: vec![Duty::DayClose, Duty::Sweep],
            send_renew: false,
            retry_at: None,
        },
    );
}

/// Renewal requests an immediate alarm only when work is already due.
#[test]
fn renewal_without_due_work_needs_no_alarm() {
    assert_eq!(after_renew(T0, &Dues::none()), None);
    // Work due later: its own time, so a far retry alarm is moved earlier.
    let future = Dues::none().with(Duty::Sweep, Some(at(300_000)));
    assert_eq!(after_renew(T0, &future), Some(at(300_000)));
    assert_eq!(
        rearm(Some(at(1_800_000)), after_renew(T0, &future)),
        Rearm::Set(at(300_000))
    );
    // Work overdue: now.
    let overdue = Dues::none().with(Duty::Sweep, Some(at(-5)));
    assert_eq!(after_renew(T0, &overdue), Some(T0));
}

/// The next alarm: the earliest due time, never at or before now; with
/// an expired lease never before the renewal retry; none for a closed unit.
#[test]
fn next_alarm_is_never_in_the_past() {
    let fresh = FreshLease::from_stored(Some(at(600_000)));
    let expired = FreshLease::expired();
    let empty = Dues::none();
    let later = empty.with(Duty::Sweep, Some(at(5_000)));
    let overdue = empty.with(Duty::Sweep, Some(at(-5_000)));

    // Fresh lease.
    let unit = open(&fresh);
    let n = |d: &Dues, r| next_alarm(T0, &unit, d, r, &LEASE_RULES, &ALARM_RULES);
    assert_eq!(n(&empty, None), None);
    assert_eq!(n(&later, None), Some(at(5_000)));
    assert_eq!(n(&overdue, None), Some(at(MIN_ALARM_GAP_MS)));

    // Expired lease: the retry decides when work is due before it.
    let unit = open(&expired);
    let n = |d: &Dues, r| next_alarm(T0, &unit, d, r, &LEASE_RULES, &ALARM_RULES);
    assert_eq!(n(&empty, Some(at(60_000))), None);
    assert_eq!(n(&overdue, Some(at(60_000))), Some(at(60_000)));
    assert_eq!(n(&later, Some(at(60_000))), Some(at(60_000)));
    let far = empty.with(Duty::Report, Some(at(90_000)));
    assert_eq!(n(&far, Some(at(60_000))), Some(at(90_000)));
    // Without a retry from the run: the backoff of the tries so far.
    let tried = UnitAt {
        lease: &expired,
        closed: false,
        renew_tries: 2,
        failed_runs: 0,
    };
    assert_eq!(
        next_alarm(T0, &tried, &overdue, None, &LEASE_RULES, &ALARM_RULES),
        Some(at(240_000))
    );

    // Closed: nothing, whatever is due.
    for lease in [&fresh, &expired] {
        let unit = UnitAt {
            lease,
            closed: true,
            renew_tries: 0,
            failed_runs: 0,
        };
        assert_eq!(
            next_alarm(
                T0,
                &unit,
                &overdue,
                Some(at(60_000)),
                &LEASE_RULES,
                &ALARM_RULES
            ),
            None
        );
    }
}

/// The run, the next alarm and the re-arm composed: with an expired lease
/// and work due, the alarm is armed once at the retry, never at or before
/// now, so it sends one renew job per retry period (rule 12); a closed
/// unit arms nothing.
#[test]
fn an_expired_or_closed_unit_does_not_loop_its_alarm() {
    let dues = Dues::none()
        .with(Duty::DayClose, Some(at(-1)))
        .with(Duty::HandOut, Some(T0));
    let expired = FreshLease::expired();
    let mut now = T0;
    let mut renew_jobs = Vec::new();
    for tries in 0..8 {
        let unit = UnitAt {
            lease: &expired,
            closed: false,
            renew_tries: tries,
            failed_runs: 0,
        };
        let run = on_alarm(now, &unit, &dues, &LEASE_RULES, &ALARM_RULES);
        assert!(run.run.is_empty());
        assert!(run.send_renew);
        renew_jobs.push(now);
        let wanted = next_alarm(now, &unit, &dues, run.retry_at, &LEASE_RULES, &ALARM_RULES);
        // The alarm fired, so none is armed.
        let Rearm::Set(next) = rearm(None, wanted) else {
            panic!("work is due: an alarm must be armed");
        };
        assert!(next > now, "armed in the past at {now:?}");
        now = next;
    }
    let gaps: Vec<i64> = renew_jobs.windows(2).map(|w| w[1].0 - w[0].0).collect();
    assert_eq!(
        gaps,
        [60_000, 120_000, 240_000, 480_000, 960_000, 1_800_000, 1_800_000]
    );

    let fresh = FreshLease::from_stored(Some(at(600_000)));
    for lease in [&expired, &fresh] {
        let unit = UnitAt {
            lease,
            closed: true,
            renew_tries: 0,
            failed_runs: 0,
        };
        let run = on_alarm(T0, &unit, &dues, &LEASE_RULES, &ALARM_RULES);
        assert!(!run.send_renew && run.run.is_empty());
        let wanted = next_alarm(T0, &unit, &dues, run.retry_at, &LEASE_RULES, &ALARM_RULES);
        assert_eq!(rearm(None, wanted), Rearm::Keep);
    }
}

/// A renewal is refused when the unit holds less than the proof covered:
/// a lower seq or stamp counter (rolled back below the Worker's view), or
/// fewer revocations (an apply that failed half-way, SEC-6). It changes
/// nothing then. A unit that holds more (a raise or a sync after the
/// proof began) is renewed: a busy unit's stamp moves during every proof.
#[test]
fn a_renewal_is_refused_only_below_what_it_proved() {
    let mut lease = FreshLease::expired();
    for own in [
        Proven {
            stamp_counter: Some(1),
            ..HEAD
        },
        Proven {
            stamp_counter: None,
            ..HEAD
        },
        Proven {
            state_seq: 3,
            ..HEAD
        },
        Proven {
            keys_seq: 8,
            ..HEAD
        },
        Proven { revoked: 2, ..HEAD },
    ] {
        assert_eq!(
            lease.renew(T0, &HEAD, &own, 0, T0, &LEASE_RULES),
            Err(RenewRefused::NotProven { proven: HEAD, own })
        );
        assert_eq!(lease, FreshLease::expired());
    }
    for own in [
        HEAD,
        Proven {
            stamp_counter: Some(4),
            ..HEAD
        },
        Proven {
            keys_seq: 10,
            ..HEAD
        },
        Proven {
            state_seq: 5,
            ..HEAD
        },
        Proven { revoked: 4, ..HEAD },
    ] {
        let mut lease = FreshLease::expired();
        assert!(
            lease.renew(T0, &HEAD, &own, 0, T0, &LEASE_RULES).is_ok(),
            "{own:?}"
        );
    }
    // A unit never raised is below one that was; two never raised agree.
    let never = Proven {
        stamp_counter: None,
        ..HEAD
    };
    assert!(never.covers(&never));
    assert!(!never.covers(&HEAD));
}

/// Pass 3 of the review: the revocations are bound by id. The proof
/// listed {A, Y}; the apply of Y failed and a concurrent revoke of Z
/// reached the unit, so the unit holds {A, Z}: the count is level, and
/// the renewal is still refused because Y is not revoked there.
#[test]
fn a_renewal_with_a_listed_id_unapplied_is_refused() {
    let listed = ["AKIAA", "AKIAY"];
    let held = ["AKIAA", "AKIAZ"];
    let missing = unapplied(listed, |id| held.contains(&id));
    assert_eq!(missing, 1);
    let proven = Proven { revoked: 2, ..HEAD };
    let own = Proven {
        revoked: 2,
        keys_seq: HEAD.keys_seq + 1,
        ..HEAD
    };
    let mut lease = FreshLease::expired();
    assert_eq!(
        lease.renew(T0, &proven, &own, missing, T0, &LEASE_RULES),
        Err(RenewRefused::RevocationsUnapplied { count: 1 })
    );
    assert_eq!(lease, FreshLease::expired());

    // With Y applied (or tombstoned) the renewal goes through.
    let held = ["AKIAA", "AKIAY", "AKIAZ"];
    let missing = unapplied(listed, |id| held.contains(&id));
    assert_eq!(missing, 0);
    assert!(lease
        .renew(T0, &proven, &own, missing, T0, &LEASE_RULES)
        .is_ok());
}

/// An alarm is set only when no alarm is armed or the wanted time is earlier.
#[test]
fn rearm_sets_only_new_or_earlier_alarms() {
    assert_eq!(rearm(None, None), Rearm::Keep);
    assert_eq!(rearm(None, Some(T0)), Rearm::Set(T0));
    assert_eq!(rearm(Some(T0), Some(T0)), Rearm::Keep);
    assert_eq!(rearm(Some(T0), Some(at(1))), Rearm::Keep);
    assert_eq!(rearm(Some(T0), Some(at(-1))), Rearm::Set(at(-1)));
    assert_eq!(rearm(Some(T0), None), Rearm::Keep);
}

/// The first write schedules a stamp raise half a lease term later.
#[test]
fn stamp_raise_follows_first_write_by_half_a_term() {
    assert_eq!(stamp_raise_due(None, &ALARM_RULES), None);
    assert_eq!(stamp_raise_due(Some(T0), &ALARM_RULES), Some(at(300_000)));
    assert_eq!(ALARM_RULES.stamp_period_ms, LEASE_RULES.term_ms / 2);
    // A raise due inside a lease that a write's renewal opened.
    let mut lease = FreshLease::expired();
    renew(&mut lease, T0, T0);
    let due = stamp_raise_due(Some(T0), &ALARM_RULES).unwrap();
    assert!(lease.is_fresh(due, &LEASE_RULES));
    assert!(!AlarmRules {
        stamp_period_ms: LEASE_RULES.term_ms,
        ..ALARM_RULES
    }
    .valid());
}

/// A unit stamp ID carries its tenant and unit number in its displayed form.
#[test]
fn stamp_id_parts_and_display() {
    let tenant = "t_0123456789abcdef";
    let id = UnitStampId::new(tenant, 0).unwrap();
    assert_eq!(id.as_str(), "t_0123456789abcdef.0");
    assert_eq!(id.tenant(), tenant);
    assert_eq!(id.unit(), 0);
    assert_eq!(id.to_string(), id.as_str());
}

/// Unit stamp IDs require a valid managed tenant other than tenant zero.
#[test]
fn stamp_id_refuses_invalid_tenants() {
    let too_long = format!("t_{}", "a".repeat(65));
    for tenant in [
        "t_0000000000000000",
        "",
        "t_",
        "T_abc",
        "t_ABC",
        "t_a-b",
        "x_abc",
        "t_a.b",
        &too_long,
    ] {
        assert!(UnitStampId::new(tenant, 0).is_err(), "{tenant:?}");
    }
}

/// The longest valid stamp ID is 77 bytes and parses back unchanged.
#[test]
fn longest_stamp_id_round_trips() {
    let tenant = format!("t_{}", "z".repeat(64));
    let id = UnitStampId::new(&tenant, u32::MAX).unwrap();
    assert_eq!(MAX_UNIT_STAMP_ID_LEN, 77);
    assert_eq!(id.as_str().len(), MAX_UNIT_STAMP_ID_LEN);
    assert_eq!(UnitStampId::parse(id.as_str()), Some(id));
}

/// Parsing accepts canonical decimal units and rejects malformed stamp IDs.
#[test]
fn parse_requires_canonical_stamp_id() {
    let id = UnitStampId::new("t_abc", 0).unwrap();
    assert_eq!(UnitStampId::parse(id.as_str()), Some(id));
    assert_eq!(UnitStampId::parse("t_abc.0").unwrap().unit(), 0);
    assert_eq!(UnitStampId::parse("t_abc.10").unwrap().unit(), 10);

    for invalid in [
        "t_abc.",
        "t_abc.01",
        "t_abc.-1",
        "t_abc.4294967296",
        "t_abc",
        "main",
        "t_abc.1.2",
    ] {
        assert_eq!(UnitStampId::parse(invalid), None, "{invalid:?}");
    }
}

/// The unit separator keeps unit stamp IDs and directories distinct from the catalogue.
#[test]
fn unit_stamp_ids_and_catalogue_are_distinct() {
    for catalogue in ["main", "t_0123456789abcdef"] {
        assert_eq!(UnitStampId::parse(catalogue), None);
    }

    let catalogue_directory = format!("rs/{}/", "main");
    for (tenant, number) in [("t_abc", 0), ("t_0123456789abcdef", 10), ("t_z", u32::MAX)] {
        let unit = UnitStampId::new(tenant, number).unwrap();
        assert!(unit.as_str().contains(UNIT_SEPARATOR));
        let unit_directory = format!("rs/{}/", unit.as_str());
        assert!(!unit_directory.starts_with(&catalogue_directory));
        assert!(!catalogue_directory.starts_with(&unit_directory));
    }
}

/// SQL write words are matched case-insensitively as whole words.
#[test]
fn statement_write_words_are_matched_whole() {
    for sql in [
        "INSERT INTO a VALUES (1)",
        "update a set b=1",
        "DELETE FROM a",
        "REPLACE INTO a VALUES(1)",
        "UPDATE outbox SET x=1 WHERE y RETURNING slot",
        "SELECT 1 RETURNING x",
        "CREATE TABLE z(a)",
        "PRAGMA foreign_keys = OFF",
        "END",
        "  release sp1",
        "SELECT 1; END TRANSACTION",
        "WITH t AS (SELECT 1) INSERT INTO a SELECT * FROM t",
    ] {
        assert!(statement_may_write(sql), "{sql}");
    }

    for sql in [
        "SELECT updated_at, deleted_flag FROM objects WHERE inserted_by = ?1",
        "SELECT count(*) FROM extents",
        "  select a from b",
        "SELECT CASE WHEN a THEN 1 ELSE 0 END FROM b",
        "SELECT x FROM t WHERE label = 'release' ORDER BY y",
    ] {
        assert!(!statement_may_write(sql), "{sql}");
    }
}

/// Exactness requires at least one mark and agreement on both wake and write count.
#[test]
fn exact_requires_matching_wakes_and_write_counts() {
    let mark = Mark {
        wake_id: [1; 16],
        writes: 5,
        writing: false,
    };
    assert!(!exact(&[]));
    assert!(exact(&[mark]));
    assert!(exact(&[mark, mark, mark]));
    assert!(!exact(&[mark, Mark { writes: 6, ..mark }]));
    // Pages read inside one write carry one mark and are still not exact.
    let inside = Mark {
        writing: true,
        ..mark
    };
    assert!(!exact(&[inside]));
    assert!(!exact(&[inside, inside]));
    assert!(!exact(&[
        mark,
        Mark {
            wake_id: [2; 16],
            ..mark
        }
    ]));
}

/// A closed unit (restoring, behind its stamp, or unborn) runs nothing and
/// sends no renew job, whatever is due; the gate's lift arms it again.
#[test]
fn closed_unit_alarm_does_nothing() {
    let dues = Dues::none()
        .with(Duty::DayClose, Some(T0))
        .with(Duty::HandOut, Some(T0));
    let idle = AlarmRun {
        run: vec![],
        send_renew: false,
        retry_at: None,
    };
    for lease in [
        FreshLease::expired(),
        FreshLease::from_stored(Some(at(600_000))),
    ] {
        let unit = UnitAt {
            lease: &lease,
            closed: true,
            renew_tries: 0,
            failed_runs: 0,
        };
        assert_eq!(on_alarm(T0, &unit, &dues, &LEASE_RULES, &ALARM_RULES), idle);
    }
}

/// Renew jobs that keep failing back off: 1, 2, 4 ... minutes, at most 30.
#[test]
fn failing_renewals_back_off_to_a_cap() {
    assert_eq!(renew_retry_ms(0, &ALARM_RULES), 60_000);
    assert_eq!(renew_retry_ms(1, &ALARM_RULES), 120_000);
    assert_eq!(renew_retry_ms(4, &ALARM_RULES), 960_000);
    assert_eq!(renew_retry_ms(5, &ALARM_RULES), 1_800_000);
    assert_eq!(renew_retry_ms(u32::MAX, &ALARM_RULES), 1_800_000);

    let lease = FreshLease::expired();
    let dues = Dues::none().with(Duty::Sweep, Some(T0));
    let unit = UnitAt {
        lease: &lease,
        closed: false,
        renew_tries: 3,
        failed_runs: 0,
    };
    let run = on_alarm(T0, &unit, &dues, &LEASE_RULES, &ALARM_RULES);
    assert!(run.send_renew);
    assert_eq!(run.retry_at, Some(at(480_000)));
}

/// A stale renewal retry, or a retry already in the past, never arms the
/// alarm at or before now.
#[test]
fn a_stale_retry_never_arms_in_the_past() {
    let expired = FreshLease::expired();
    let unit = open(&expired);
    let overdue = Dues::none().with(Duty::HandOut, Some(at(-10_000)));
    assert_eq!(
        next_alarm(
            T0,
            &unit,
            &overdue,
            Some(at(-5_000)),
            &LEASE_RULES,
            &ALARM_RULES
        ),
        Some(at(MIN_ALARM_GAP_MS))
    );
    assert!(AlarmRules::DEFAULT.valid());
    assert!(!AlarmRules {
        renew_retry_ms: 0,
        ..AlarmRules::DEFAULT
    }
    .valid());
    assert!(!AlarmRules {
        renew_retry_max_ms: 1,
        ..AlarmRules::DEFAULT
    }
    .valid());
}

/// A duty that keeps failing on a fresh lease backs off like a renewal:
/// 1 s after a clean run, then 1, 2, 4 ... minutes, at most 30.
#[test]
fn failing_duties_back_off() {
    let fresh = FreshLease::from_stored(Some(at(600_000)));
    let overdue = Dues::none().with(Duty::HandOut, Some(at(-1)));
    let gap = |failed_runs| {
        let unit = UnitAt {
            lease: &fresh,
            closed: false,
            renew_tries: 0,
            failed_runs,
        };
        next_alarm(T0, &unit, &overdue, None, &LEASE_RULES, &ALARM_RULES)
            .unwrap()
            .0
            - T0.0
    };
    assert_eq!(gap(0), MIN_ALARM_GAP_MS);
    assert_eq!(gap(1), 60_000);
    assert_eq!(gap(2), 120_000);
    assert_eq!(gap(10), 1_800_000);
}
