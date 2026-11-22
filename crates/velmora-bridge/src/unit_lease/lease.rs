//! The freshness lease of a unit (ADR-TENANCY §2.4 rule 12).
//!
//! A unit stores `fresh_until`, a wall-clock time. While it is in the
//! future the unit serves; once it has passed, the unit refuses every
//! call but `renew` and `sync` and answers `renew_needed`. The Worker
//! renews by proving that the unit is at the head of its two chains and
//! not behind its rollback stamp ([`super::renewal`]), then calls
//! `renew(proof_start)`, where `proof_start` is the Worker's clock just
//! before the first read of that proof.
//!
//! **The lease runs from the start of the proof, never from the call**
//! (RD-12): `fresh_until = proof_start + T`. A renewal that stalled
//! between its reads and its call therefore cannot stretch the bound by
//! the length of the stall. A `proof_start` too far behind the unit's
//! clock (the proof is stale) or ahead of it (the Worker's clock is
//! wrong) is refused, and the Worker proves again.
//!
//! **A renewal is bound to what it proved.** The proof was made for the
//! unit's `state_seq`, `keys_seq` and stamp counter as the Worker knew
//! them, and it listed a number of revocations ([`Proven`]). `renew`
//! carries them, and the unit refuses, in the same transaction that sets
//! the lease, when any of its own is **below** the proven one:
//!
//! - a unit rolled back to a lower counter or seq after the Worker took
//!   its view gets no lease from a proof of the newer state;
//! - a unit that holds fewer revocations than the proof listed was not
//!   given every listed id (an apply that failed half-way). The unit
//!   counts a listed id it holds no key for as revoked too (a
//!   tombstone), or the two counts would never meet.
//!
//! **The listed ids are bound one by one, not only by count** (SEC-6).
//! When the proof handed ids to apply, `renew` carries them, and the unit
//! counts, in the same transaction, those it does not hold as revoked or
//! tombstoned ([`unapplied`]); `renew` refuses unless that is 0. A count
//! alone is not enough: an apply that failed for one id while a
//! concurrent revoke of another key reached the unit leaves the count
//! level and the first key alive.
//!
//! A value **above** the proven one is accepted. The proof's stamp counter
//! is the newest stamp object it listed (or the unit's counter when it
//! listed none), and it saw no record after its seqs, so a higher value in
//! the unit came from a raise or a `sync` after `proof_start`. A value
//! below it is a unit behind its stamp: refused `not_proven`, and the
//! Worker confirms the rollback through the unit's counter. Refusing it would fail the renewals of every busy
//! unit, whose stamp moves twice per commit during the 300 ms of a proof.
//!
//! A renewal never moves the lease back: of two renewals that cross,
//! the one with the later proof decides. Each of them was a whole proof,
//! so the later bound is the one the proofs support.
//!
//! This is the unit's side and it is pure: no I/O, no clock of its own.
//! The unit object passes its clock in and stores [`FreshLease::fresh_until`]
//! in its `unit_lease` row (one row write per renewal, [`super::store`]).

use crate::types::UnixMs;

/// The dials of the lease. All in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseRules {
    /// T: how long a proof keeps a unit fresh. 10 minutes (est, owner
    /// dial).
    pub term_ms: i64,
    /// How far a `proof_start` may lie behind the unit's clock. 30 s
    /// (est): the proof is two HEADs and two lists, about 300 ms.
    pub max_behind_ms: i64,
    /// How far a `proof_start` may lie ahead of the unit's clock. 5 s
    /// (est): the Worker and the unit read the same platform clock.
    pub max_ahead_ms: i64,
}

impl LeaseRules {
    /// The values of the ADR.
    pub const DEFAULT: LeaseRules = LeaseRules {
        term_ms: 10 * 60 * 1000,
        max_behind_ms: 30 * 1000,
        max_ahead_ms: 5 * 1000,
    };

    /// Whether the dials make a lease that a fresh proof can open: a
    /// positive term longer than the oldest proof accepted, and bounds
    /// that are not negative.
    pub const fn valid(&self) -> bool {
        self.term_ms > 0
            && self.max_behind_ms >= 0
            && self.max_ahead_ms >= 0
            && self.term_ms > self.max_behind_ms
    }
}

const _: () = assert!(LeaseRules::DEFAULT.valid());

/// What the lease says about a call that arrives at `now`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// The lease holds. `left_ms` is carried in every answer of the
    /// unit; with `renew_soon` the Worker renews in the background
    /// (`waitUntil`), so that a request waits for a renewal only on a
    /// unit that was idle for longer than T.
    Fresh { left_ms: i64, renew_soon: bool },
    /// The lease has run out (or was never granted, or was closed). Every
    /// call but `renew` and `sync` answers `renew_needed`.
    RenewNeeded,
}

/// The unit state a renewal proof was made for: the two chain seqs and
/// the stamp counter (`None` = never raised). On the wire in `renew`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proven {
    pub state_seq: u64,
    pub keys_seq: u64,
    #[serde(default)]
    pub stamp_counter: Option<u64>,
    /// Revoked keys: what the proof listed under `m/rk/<t>/`, and for the
    /// unit what it holds, tombstones included.
    pub revoked: u64,
}

impl Proven {
    /// Whether `self` (the unit's own) is at least `proven` in every part.
    /// A stamp counter of `None` (never raised) is below every `Some`.
    pub fn covers(&self, proven: &Proven) -> bool {
        self.state_seq >= proven.state_seq
            && self.keys_seq >= proven.keys_seq
            && self.stamp_counter >= proven.stamp_counter
            && self.revoked >= proven.revoked
    }
}

/// Why a `renew` was refused. The unit answers `renew_needed` with the
/// reason ([`LeaseRefusal`]); the Worker proves again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenewRefused {
    /// `proof_start` is more than [`LeaseRules::max_behind_ms`] behind
    /// the unit's clock.
    ProofTooOld { behind_ms: i64 },
    /// `proof_start` is more than [`LeaseRules::max_ahead_ms`] ahead of
    /// the unit's clock.
    ProofAhead { ahead_ms: i64 },
    /// The unit holds less than the proof covered in some part: a lower
    /// seq or stamp counter, or fewer revocations.
    NotProven { proven: Proven, own: Proven },
    /// This many ids that the proof listed for the unit to apply are not
    /// revoked (or tombstoned) in the unit.
    RevocationsUnapplied { count: usize },
}

/// Why the unit answered `renew_needed` to a `renew`, as it crosses the
/// wire. Nothing of the lease moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRefusal {
    /// The unit has a `restoring` entry: it refuses `renew` until the
    /// restore gate lifts it (§8.6 step 2).
    Restoring,
    /// The unit's stamp row records a rollback: the restore gate is
    /// needed (§8.6). The Worker pages.
    RolledBack,
    /// The unit has no lease table (born before `u0002`). The Worker
    /// pages.
    NoLeaseTable,
    /// [`RenewRefused::ProofTooOld`].
    ProofTooOld,
    /// [`RenewRefused::ProofAhead`].
    ProofAhead,
    /// [`RenewRefused::NotProven`].
    NotProven,
    /// [`RenewRefused::RevocationsUnapplied`].
    RevocationsUnapplied,
    /// The listed ids were too many or not access key ids; nothing was
    /// applied.
    BadList,
}

impl From<RenewRefused> for LeaseRefusal {
    fn from(r: RenewRefused) -> LeaseRefusal {
        match r {
            RenewRefused::ProofTooOld { .. } => LeaseRefusal::ProofTooOld,
            RenewRefused::ProofAhead { .. } => LeaseRefusal::ProofAhead,
            RenewRefused::NotProven { .. } => LeaseRefusal::NotProven,
            RenewRefused::RevocationsUnapplied { .. } => LeaseRefusal::RevocationsUnapplied,
        }
    }
}

/// How many of `listed` (the ids of [`super::renewal::Proof::Fresh`] that
/// the Worker applied) the unit does not hold as revoked or tombstoned.
/// `holds_revoked` answers from the unit's own key table, in the
/// transaction of the `renew`.
pub fn unapplied<'a>(
    listed: impl IntoIterator<Item = &'a str>,
    mut holds_revoked: impl FnMut(&str) -> bool,
) -> usize {
    listed.into_iter().filter(|id| !holds_revoked(id)).count()
}

/// The lease of one unit.
///
/// `None` means no lease: a unit that was born from a `restore` token
/// starts so (§2.4 rule 6), and so does one that was closed
/// ([`FreshLease::close`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FreshLease {
    fresh_until: Option<UnixMs>,
}

impl FreshLease {
    /// No lease: every call but `renew` and `sync` is refused.
    pub const fn expired() -> FreshLease {
        FreshLease { fresh_until: None }
    }

    /// The lease as the unit stored it.
    pub const fn from_stored(fresh_until: Option<UnixMs>) -> FreshLease {
        FreshLease { fresh_until }
    }

    /// What the unit stores.
    pub const fn fresh_until(&self) -> Option<UnixMs> {
        self.fresh_until
    }

    /// The lease at `now`. Fresh while `now < fresh_until`.
    pub fn admit(&self, now: UnixMs, rules: &LeaseRules) -> Admit {
        match self.fresh_until {
            Some(until) if now.0 < until.0 => {
                let left_ms = until.0 - now.0;
                Admit::Fresh {
                    left_ms,
                    // Below half of T.
                    renew_soon: left_ms.saturating_mul(2) < rules.term_ms,
                }
            }
            _ => Admit::RenewNeeded,
        }
    }

    /// Whether the lease holds at `now`.
    pub fn is_fresh(&self, now: UnixMs, rules: &LeaseRules) -> bool {
        matches!(self.admit(now, rules), Admit::Fresh { .. })
    }

    /// `renew(proof_start, proven)`, called by the unit at its own `now`,
    /// after the Worker proved the unit fresh (and after any `sync` and
    /// the revocations that the proof asked for). `own` is what the unit
    /// holds, read in the same transaction; it must cover `proven`
    /// ([`Proven::covers`]). `unapplied` is [`unapplied`] over the ids the
    /// proof listed, counted in that transaction; it must be 0.
    ///
    /// Sets `fresh_until` to `proof_start + T` unless it is already
    /// later, and answers the lease in force afterwards. It is never set
    /// to anything later than `proof_start + T` by this call.
    ///
    /// The caller checks the unit's own closing conditions first: a unit
    /// that is `restoring`, `UNBORN`, or behind its stamp refuses `renew`
    /// whatever its lease (§8.6 step 2).
    pub fn renew(
        &mut self,
        proof_start: UnixMs,
        proven: &Proven,
        own: &Proven,
        unapplied: usize,
        now: UnixMs,
        rules: &LeaseRules,
    ) -> Result<UnixMs, RenewRefused> {
        if !own.covers(proven) {
            return Err(RenewRefused::NotProven {
                proven: *proven,
                own: *own,
            });
        }
        if unapplied > 0 {
            return Err(RenewRefused::RevocationsUnapplied { count: unapplied });
        }
        let behind_ms = now.0.saturating_sub(proof_start.0);
        if behind_ms > rules.max_behind_ms {
            return Err(RenewRefused::ProofTooOld { behind_ms });
        }
        let ahead_ms = proof_start.0.saturating_sub(now.0);
        if ahead_ms > rules.max_ahead_ms {
            return Err(RenewRefused::ProofAhead { ahead_ms });
        }
        let proposed = UnixMs(proof_start.0.saturating_add(rules.term_ms));
        let until = match self.fresh_until {
            Some(current) if current.0 >= proposed.0 => current,
            _ => proposed,
        };
        self.fresh_until = Some(until);
        Ok(until)
    }

    /// Ends the lease at once: the restore procedure's close (§8.6 step
    /// 2), and a renewal that found a newer stamp (the unit was rolled
    /// back, §2.4 rule 12).
    pub fn close(&mut self) {
        self.fresh_until = None;
    }
}
