//! The alarm dispatcher of a unit: what one alarm run does, and when the
//! next one is armed (ADR-TENANCY §2.4 rules 4, 8 and 12; RD-9).
//!
//! - **Only the alarm sends to a queue** (rule 4). A call never does.
//! - **One alarm, re-armed only when the earliest due time moves
//!   earlier** (rule 8): each `setAlarm` is a billed row write. An alarm
//!   that is armed earlier than needed is left as it is; it wakes, finds
//!   nothing due, and arms the next time.
//! - **The alarm obeys the lease** (rule 12). With an expired lease it
//!   sends one `renew` job and nothing else: no sweep, no day close, no
//!   job hand-out. The work that was due is not dropped (RD-9): it stays
//!   due, the alarm is armed again for a later try of the renewal, and
//!   when a `renew` succeeds while work is due the unit sets its alarm to
//!   now ([`after_renew`]). The next run does the due work, **the day
//!   close first**.
//!
//! - **A closed unit runs nothing and asks for nothing.** A unit that is
//!   `restoring`, behind its stamp, or `UNBORN` refuses `renew` (§8.6
//!   step 2), so a renew job would only be refused; the restore gate's
//!   lift arms the alarm again.
//! - **Renewals that keep failing back off**: the retry doubles from
//!   [`AlarmRules::renew_retry_ms`] up to [`AlarmRules::renew_retry_max_ms`],
//!   so a unit whose renewal cannot succeed costs a bounded number of
//!   queue messages and alarm writes. The unit counts the tries since its
//!   last successful renewal and resets the count at one.
//!
//! This module decides and does nothing: the unit object computes the
//! due time of each [`Duty`] from its own tables, asks [`on_alarm`] what
//! to run, runs it, computes the due times again, asks [`next_alarm`]
//! when to wake, and arms what [`rearm`] answers. After a successful
//! `renew` it arms what [`rearm`] answers for [`after_renew`]. It is pure, so every rule above is a native test.

use crate::types::UnixMs;

use super::lease::{FreshLease, LeaseRules};

/// The work an alarm run hands out, in the order it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Duty {
    /// Close the usage day and put its seal message in the outbox
    /// (§4.4). First, always (RD-9).
    DayClose,
    /// The unit's sweeps: reservations older than their hour (§2.5 step
    /// 0), expired write intents.
    Sweep,
    /// Send the due outbox rows as jobs, and the GC, evict, scrub and
    /// repair jobs of this unit: today's cron work, per unit.
    HandOut,
    /// Ask the Worker for one more stamp raise: once per period in which
    /// the unit had writes (§8.5). An addition to the raises of the
    /// request path, never their replacement.
    StampRaise,
    /// Report changed numbers to the directory through the outbox, at
    /// most once per 5 minutes (est, §7.3).
    Report,
}

impl Duty {
    /// Every duty, in run order.
    pub const ALL: [Duty; 5] = [
        Duty::DayClose,
        Duty::Sweep,
        Duty::HandOut,
        Duty::StampRaise,
        Duty::Report,
    ];

    const fn index(self) -> usize {
        match self {
            Duty::DayClose => 0,
            Duty::Sweep => 1,
            Duty::HandOut => 2,
            Duty::StampRaise => 3,
            Duty::Report => 4,
        }
    }
}

/// When each duty is next due. `None` = nothing of that kind is waiting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dues([Option<UnixMs>; 5]);

impl Dues {
    /// Nothing due.
    pub const fn none() -> Dues {
        Dues([None; 5])
    }

    /// With `duty` due at `at` (or not due, for `None`).
    pub fn with(mut self, duty: Duty, at: Option<UnixMs>) -> Dues {
        self.0[duty.index()] = at;
        self
    }

    /// When `duty` is due.
    pub fn get(&self, duty: Duty) -> Option<UnixMs> {
        self.0[duty.index()]
    }

    /// The earliest due time of any duty.
    pub fn earliest(&self) -> Option<UnixMs> {
        self.0.iter().flatten().min().copied()
    }

    /// The duties due at `now`, in run order.
    pub fn due_at(&self, now: UnixMs) -> Vec<Duty> {
        Duty::ALL
            .into_iter()
            .filter(|d| self.get(*d).is_some_and(|at| at.0 <= now.0))
            .collect()
    }
}

/// The dials of the dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlarmRules {
    /// After a run with an expired lease: when to send the next `renew`
    /// job if no renewal has succeeded by then, for the first try. 60 s
    /// (est). Doubled for every further try without a successful renewal.
    pub renew_retry_ms: i64,
    /// The longest wait between two renew jobs of the alarm. 30 minutes
    /// (est).
    pub renew_retry_max_ms: i64,
    /// The period of the alarm's stamp raise. 5 minutes (est), half the
    /// lease term. A write was made under a fresh lease, and a request
    /// renews in the background once less than half of T is left, so the
    /// raise usually falls while the lease still holds. If it does not
    /// (the unit went idle and its lease ran out), the alarm renews first
    /// and asks for the raise right after the renewal (rule 12, RD-9): the
    /// alarm's raise then comes up to one renewal later than the period.
    pub stamp_period_ms: i64,
}

impl AlarmRules {
    pub const DEFAULT: AlarmRules = AlarmRules {
        renew_retry_ms: 60 * 1000,
        renew_retry_max_ms: 30 * 60 * 1000,
        stamp_period_ms: LeaseRules::DEFAULT.term_ms / 2,
    };

    /// Positive waits, a cap not below the first wait, and a stamp period
    /// of at most half the lease term.
    pub const fn valid(&self) -> bool {
        self.renew_retry_ms > 0
            && self.renew_retry_max_ms >= self.renew_retry_ms
            && self.stamp_period_ms > 0
            && self.stamp_period_ms <= LeaseRules::DEFAULT.term_ms / 2
    }
}

const _: () = assert!(AlarmRules::DEFAULT.valid());

/// What one alarm run does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlarmRun {
    /// The duties to run now, in order. Empty when the lease has expired.
    pub run: Vec<Duty>,
    /// Send one `renew` job (the lease has expired and work is due). The
    /// unit adds one to its count of renew tries.
    pub send_renew: bool,
    /// Arm at least this early after the run, whatever the duties say
    /// then: the retry of the renewal. `None` = only the due times
    /// decide.
    pub retry_at: Option<UnixMs>,
}

/// The state of the unit an alarm finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitAt<'a> {
    pub lease: &'a FreshLease,
    /// `restoring`, behind its stamp, or `UNBORN`: the unit refuses
    /// `renew` and every job.
    pub closed: bool,
    /// Renew jobs the alarm sent since the last successful renewal.
    pub renew_tries: u32,
    /// Runs in a row in which a duty failed (a queue send refused, say).
    /// Reset by a run in which every duty succeeded.
    pub failed_runs: u32,
}

/// The wait before renew try `tries + 1`: [`AlarmRules::renew_retry_ms`]
/// doubled `tries` times, at most [`AlarmRules::renew_retry_max_ms`].
pub fn renew_retry_ms(tries: u32, rules: &AlarmRules) -> i64 {
    let factor = 1i64.checked_shl(tries.min(62)).unwrap_or(i64::MAX);
    rules
        .renew_retry_ms
        .saturating_mul(factor)
        .min(rules.renew_retry_max_ms)
}

/// What an alarm that fires at `now` does, for `unit` with `dues`.
pub fn on_alarm(
    now: UnixMs,
    unit: &UnitAt<'_>,
    dues: &Dues,
    lease_rules: &LeaseRules,
    rules: &AlarmRules,
) -> AlarmRun {
    let due = dues.due_at(now);
    if due.is_empty() || unit.closed {
        // Woken early or for work a request already did: nothing to do,
        // and nothing to renew for. Or closed: nothing may run, and a
        // renewal would be refused.
        return AlarmRun {
            run: Vec::new(),
            send_renew: false,
            retry_at: None,
        };
    }
    if unit.lease.is_fresh(now, lease_rules) {
        return AlarmRun {
            run: due,
            send_renew: false,
            retry_at: None,
        };
    }
    AlarmRun {
        run: Vec::new(),
        send_renew: true,
        retry_at: Some(UnixMs(
            now.0
                .saturating_add(renew_retry_ms(unit.renew_tries, rules)),
        )),
    }
}

/// After a `renew` succeeded at `now`: the time to pass to [`rearm`].
/// Work that is due now gives `now`, so the next run does it at once,
/// the day close first (RD-9). Work that is due later gives its time, so
/// a retry alarm that the backoff armed further out is moved earlier.
/// `None` = nothing waits.
pub fn after_renew(now: UnixMs, dues: &Dues) -> Option<UnixMs> {
    dues.earliest().map(|at| at.max(now))
}

/// The least time from a run to the alarm it arms. A duty still due
/// after its run (it took a bounded number of rows) is taken up again
/// after this gap rather than at once. 1 s (est).
pub const MIN_ALARM_GAP_MS: i64 = 1000;

/// When the alarm should next fire after a run at `now`, given the due
/// times as the unit computes them after the run and the run's
/// [`AlarmRun::retry_at`]. Never at or before `now`:
///
/// - a closed unit: `None`; the restore gate's lift arms it again;
/// - a fresh lease: the earliest due time, at least
///   [`MIN_ALARM_GAP_MS`] after `now`; after runs in which a duty
///   failed, at least the renewal backoff for that many failures;
/// - an expired lease: the earliest due time, but not before the renewal
///   retry (`retry_at`, or without one `now` plus the backoff for
///   `renew_tries`). Work that is due never wakes the alarm before the
///   renewal it waits for, so the expired case sends one renew job per
///   retry period and no more (rule 12).
pub fn next_alarm(
    now: UnixMs,
    unit: &UnitAt<'_>,
    dues: &Dues,
    retry_at: Option<UnixMs>,
    lease_rules: &LeaseRules,
    rules: &AlarmRules,
) -> Option<UnixMs> {
    if unit.closed {
        return None;
    }
    let earliest = dues.earliest()?;
    let gap = if unit.lease.is_fresh(now, lease_rules) {
        // Work that keeps failing backs off like a renewal does.
        match unit.failed_runs {
            0 => MIN_ALARM_GAP_MS,
            n => renew_retry_ms(n - 1, rules),
        }
    } else {
        retry_at.map_or_else(
            || renew_retry_ms(unit.renew_tries, rules),
            |at| at.0.saturating_sub(now.0),
        )
    };
    // Never at or before now, whatever the dials or a stale retry say.
    let floor = now.0.saturating_add(gap.max(MIN_ALARM_GAP_MS));
    Some(UnixMs(earliest.0.max(floor)))
}

/// What to do with the alarm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rearm {
    /// Leave it: no `setAlarm`, no row write.
    Keep,
    /// `setAlarm(at)`.
    Set(UnixMs),
}

/// `armed` is the alarm in force (`None` after it fired, or never set);
/// `wanted` is [`next_alarm`] or [`after_renew`]. Sets only when nothing is armed or the
/// wanted time is earlier than the armed one.
pub fn rearm(armed: Option<UnixMs>, wanted: Option<UnixMs>) -> Rearm {
    match (armed, wanted) {
        (_, None) => Rearm::Keep,
        (None, Some(at)) => Rearm::Set(at),
        (Some(cur), Some(at)) if at.0 < cur.0 => Rearm::Set(at),
        (Some(_), Some(_)) => Rearm::Keep,
    }
}

/// The due time of the alarm's stamp raise: one period after the first
/// write since the last raise the alarm asked for. `None` = no write
/// since, so no raise is due (an idle unit costs nothing).
pub fn stamp_raise_due(
    first_write_since_raise: Option<UnixMs>,
    rules: &AlarmRules,
) -> Option<UnixMs> {
    first_write_since_raise.map(|at| UnixMs(at.0.saturating_add(rules.stamp_period_ms)))
}
