//! The restore gate's lift decision (`docs/units.md`, "Restore gate").
//!
//! A restored unit is closed (`restoring`), and only the gate opens it.
//! The gate lifts only when the last replay is **whole and clean**:
//!
//! - `damaged_total = 0`;
//! - `held_missing_live = 0`;
//! - the lists `unreadable`, `unpublishable`, `damaged_unpublished` and
//!   `twins` are empty, and `other_bucket_total = 0`.
//!
//! These are the conditions on which today's replay script exits 2
//! (`workers/s3-bridge/ops/catalog-replay.sh`).
//!
//! **While the replay is not whole** (any of the five blockers above
//! other than `damaged_total` is not empty), every held row whose safety
//! copy is gone counts as live, and nothing is set aside: the record
//! that was not applied may be the one that makes a generation servable
//! again. Until the gate classifies held rows into their
//! three classes (live, orphan, deleted), every `held_missing` row counts
//! as live as well: that is the stricter rule, and it never opens a unit
//! that a classification would keep closed.
//!
//! **An acknowledged lift** names each blocker it accepts, by id, in the
//! lift record. A lift that acknowledges any of the five sets nothing
//! aside, so the same record must also name every `held_missing` id.
//! Anything not named keeps the unit closed.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::replay::ReplayReport;

/// What the gate's last replay found, as the lift decision reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateFindings {
    /// The replay reached its end (`next` was `None`).
    pub complete: bool,
    pub damaged_total: u64,
    pub damaged: Vec<String>,
    pub unreadable: Vec<String>,
    pub unpublishable: Vec<String>,
    /// Generation ids of `damaged_unpublished` records.
    pub damaged_unpublished: Vec<String>,
    pub twins: Vec<String>,
    pub other_bucket_total: u32,
    pub other_bucket: Vec<String>,
    /// Held rows whose safety copy is gone, all classes.
    pub held_missing_total: u32,
    pub held_missing: Vec<String>,
    /// Of those, the ids of the rows a servable generation names, when
    /// the gate has classified the whole list; `None` = not classified,
    /// all count as live. A step that adds held rows clears it.
    pub held_missing_live: Option<Vec<String>>,
}

impl GateFindings {
    /// Adds one step of a replay, as the replay script does: every report
    /// covers its own call, so the counts are summed and the lists joined,
    /// except `damaged_total` and `damaged`, which the last call sets for
    /// the whole replay. The replay is complete when the step added is its
    /// last (`next` is `None`). Start from `GateFindings::default()` and
    /// add every step in order.
    pub fn add(&mut self, step: &ReplayReport) {
        fn join(into: &mut Vec<String>, more: impl IntoIterator<Item = String>, dedup: bool) {
            for id in more {
                if !dedup || !into.contains(&id) {
                    into.push(id);
                }
            }
        }
        self.complete = step.next.is_none();
        self.damaged_total = step.damaged_total;
        self.damaged = step.damaged.clone();
        join(&mut self.unreadable, step.unreadable.iter().cloned(), true);
        join(
            &mut self.unpublishable,
            step.unpublishable.iter().cloned(),
            false,
        );
        join(
            &mut self.damaged_unpublished,
            step.damaged_unpublished.iter().map(|d| d.id.clone()),
            false,
        );
        join(&mut self.twins, step.twins.iter().cloned(), true);
        self.other_bucket_total = self
            .other_bucket_total
            .saturating_add(step.other_bucket_total);
        join(
            &mut self.other_bucket,
            step.other_bucket.iter().cloned(),
            false,
        );
        // Rows added after a classification are not classified.
        if step.held_missing_total > 0 || !step.held_missing.is_empty() {
            self.held_missing_live = None;
        }
        self.held_missing_total = self
            .held_missing_total
            .saturating_add(step.held_missing_total);
        join(
            &mut self.held_missing,
            step.held_missing.iter().cloned(),
            false,
        );
    }

    /// The findings of a whole replay, its steps in order.
    pub fn of_replay<'a>(steps: impl IntoIterator<Item = &'a ReplayReport>) -> GateFindings {
        let mut found = GateFindings::default();
        for step in steps {
            found.add(step);
        }
        found
    }

    /// Rows other than those of a bucket of this name, counted by the
    /// larger of the total and the ids listed: neither is trusted alone.
    fn other_bucket_rows(&self) -> u64 {
        u64::from(self.other_bucket_total).max(self.other_bucket.len() as u64)
    }

    fn held_missing_rows(&self) -> u64 {
        u64::from(self.held_missing_total).max(self.held_missing.len() as u64)
    }

    /// The replay is whole: nothing it found was left unapplied.
    pub fn whole(&self) -> bool {
        self.unreadable.is_empty()
            && self.unpublishable.is_empty()
            && self.damaged_unpublished.is_empty()
            && self.twins.is_empty()
            && self.other_bucket_rows() == 0
    }

    /// The held rows without a copy that count as live, and their ids:
    /// all of them while the replay is not whole or the rows are not
    /// classified; then the classified live ids.
    fn live_held(&self) -> (&[String], u64) {
        // A classification covers the listed rows only: with rows beyond
        // the list, all of them count.
        let listed = self.held_missing.len() as u64 == self.held_missing_rows();
        match (self.whole() && listed, &self.held_missing_live) {
            (true, Some(live)) => (live, live.len() as u64),
            _ => (&self.held_missing, self.held_missing_rows()),
        }
    }

    /// How many held rows without a copy count as live.
    pub fn held_missing_live(&self) -> u64 {
        self.live_held().1
    }
}

/// What the operator accepts by name in a lift record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledged {
    #[serde(default)]
    pub damaged: BTreeSet<String>,
    #[serde(default)]
    pub held_missing: BTreeSet<String>,
    #[serde(default)]
    pub unreadable: BTreeSet<String>,
    #[serde(default)]
    pub unpublishable: BTreeSet<String>,
    #[serde(default)]
    pub damaged_unpublished: BTreeSet<String>,
    #[serde(default)]
    pub twins: BTreeSet<String>,
    #[serde(default)]
    pub other_bucket: BTreeSet<String>,
}

/// Why the unit stays closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "blocker", rename_all = "snake_case")]
pub enum Blocker {
    /// The replay has not reached its end.
    Incomplete,
    /// More rows than the report lists ids for: the lift cannot name
    /// them all, so it cannot be acknowledged until a replay lists them.
    Unlisted {
        what: String,
        total: u64,
        listed: usize,
    },
    /// Ids the lift record does not name.
    NotAcknowledged { what: String, ids: Vec<String> },
}

/// The lift decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lift", rename_all = "snake_case")]
pub enum Lift {
    /// Clean: lift, nothing to name.
    Clean,
    /// Lift with these named acknowledgements (all of them were needed).
    Acknowledged { named: Acknowledged },
    /// Stay closed and page.
    Closed { blockers: Vec<Blocker> },
}

/// Step 8: whether the unit may open on these findings.
pub fn lift(found: &GateFindings, ack: &Acknowledged) -> Lift {
    let mut blockers = Vec::new();
    if !found.complete {
        blockers.push(Blocker::Incomplete);
    }
    let mut needed = Acknowledged::default();
    let mut need = |what: &'static str,
                    ids: &[String],
                    total: u64,
                    acked: &BTreeSet<String>,
                    into: &mut BTreeSet<String>| {
        if total == 0 && ids.is_empty() {
            return;
        }
        if (ids.len() as u64) < total {
            blockers.push(Blocker::Unlisted {
                what: what.into(),
                total,
                listed: ids.len(),
            });
            return;
        }
        let missing: Vec<String> = ids
            .iter()
            .filter(|id| !acked.contains(*id))
            .cloned()
            .collect();
        if missing.is_empty() {
            into.extend(ids.iter().cloned());
        } else {
            blockers.push(Blocker::NotAcknowledged {
                what: what.into(),
                ids: missing,
            });
        }
    };
    let n = |v: &Vec<String>| v.len() as u64;
    need(
        "damaged",
        &found.damaged,
        found.damaged_total,
        &ack.damaged,
        &mut needed.damaged,
    );
    need(
        "unreadable",
        &found.unreadable,
        n(&found.unreadable),
        &ack.unreadable,
        &mut needed.unreadable,
    );
    need(
        "unpublishable",
        &found.unpublishable,
        n(&found.unpublishable),
        &ack.unpublishable,
        &mut needed.unpublishable,
    );
    need(
        "damaged_unpublished",
        &found.damaged_unpublished,
        n(&found.damaged_unpublished),
        &ack.damaged_unpublished,
        &mut needed.damaged_unpublished,
    );
    need(
        "twins",
        &found.twins,
        n(&found.twins),
        &ack.twins,
        &mut needed.twins,
    );
    need(
        "other_bucket",
        &found.other_bucket,
        found.other_bucket_rows(),
        &ack.other_bucket,
        &mut needed.other_bucket,
    );
    // Held rows without a copy: all of them count while the replay is
    // not whole or not classified, and must all be named; once classified,
    // the live ones.
    let (live_ids, live) = found.live_held();
    if live > 0 {
        need(
            "held_missing",
            live_ids,
            live,
            &ack.held_missing,
            &mut needed.held_missing,
        );
    }
    if !blockers.is_empty() {
        return Lift::Closed { blockers };
    }
    if needed == Acknowledged::default() {
        Lift::Clean
    } else {
        Lift::Acknowledged { named: needed }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean() -> GateFindings {
        GateFindings {
            complete: true,
            ..GateFindings::default()
        }
    }

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn v(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_clean_whole_replay_lifts() {
        assert_eq!(lift(&clean(), &Acknowledged::default()), Lift::Clean);
    }

    #[test]
    fn an_unfinished_replay_never_lifts_even_acknowledged() {
        let mut f = clean();
        f.complete = false;
        assert_eq!(
            lift(&f, &Acknowledged::default()),
            Lift::Closed {
                blockers: vec![Blocker::Incomplete]
            }
        );
    }

    #[test]
    fn each_blocker_keeps_the_unit_closed_until_named() {
        let cases: Vec<(GateFindings, Acknowledged)> = vec![
            (
                GateFindings {
                    damaged_total: 1,
                    damaged: v(&["g1"]),
                    ..clean()
                },
                Acknowledged {
                    damaged: set(&["g1"]),
                    ..Default::default()
                },
            ),
            (
                GateFindings {
                    unreadable: v(&["m/x/a"]),
                    ..clean()
                },
                Acknowledged {
                    unreadable: set(&["m/x/a"]),
                    ..Default::default()
                },
            ),
            (
                GateFindings {
                    unpublishable: v(&["g2"]),
                    ..clean()
                },
                Acknowledged {
                    unpublishable: set(&["g2"]),
                    ..Default::default()
                },
            ),
            (
                GateFindings {
                    damaged_unpublished: v(&["g3"]),
                    ..clean()
                },
                Acknowledged {
                    damaged_unpublished: set(&["g3"]),
                    ..Default::default()
                },
            ),
            (
                GateFindings {
                    twins: v(&["m/x/t/b"]),
                    ..clean()
                },
                Acknowledged {
                    twins: set(&["m/x/t/b"]),
                    ..Default::default()
                },
            ),
            (
                GateFindings {
                    other_bucket_total: 1,
                    other_bucket: v(&["g4"]),
                    ..clean()
                },
                Acknowledged {
                    other_bucket: set(&["g4"]),
                    ..Default::default()
                },
            ),
            (
                GateFindings {
                    held_missing_total: 1,
                    held_missing: v(&["x1"]),
                    ..clean()
                },
                Acknowledged {
                    held_missing: set(&["x1"]),
                    ..Default::default()
                },
            ),
        ];
        for (found, ack) in cases {
            assert!(
                matches!(lift(&found, &Acknowledged::default()), Lift::Closed { .. }),
                "{found:?}"
            );
            assert_eq!(
                lift(&found, &ack),
                Lift::Acknowledged { named: ack.clone() },
                "{found:?}"
            );
        }
    }

    #[test]
    fn a_partial_acknowledgement_names_what_is_missing() {
        let f = GateFindings {
            unreadable: v(&["a", "b"]),
            ..clean()
        };
        let ack = Acknowledged {
            unreadable: set(&["a"]),
            ..Default::default()
        };
        assert_eq!(
            lift(&f, &ack),
            Lift::Closed {
                blockers: vec![Blocker::NotAcknowledged {
                    what: "unreadable".into(),
                    ids: v(&["b"])
                }]
            }
        );
    }

    #[test]
    fn a_blocker_with_more_rows_than_ids_cannot_be_acknowledged() {
        let f = GateFindings {
            damaged_total: 3,
            damaged: v(&["g1"]),
            ..clean()
        };
        let ack = Acknowledged {
            damaged: set(&["g1"]),
            ..Default::default()
        };
        assert_eq!(
            lift(&f, &ack),
            Lift::Closed {
                blockers: vec![Blocker::Unlisted {
                    what: "damaged".into(),
                    total: 3,
                    listed: 1
                }]
            }
        );
    }

    #[test]
    fn held_rows_count_as_live_until_classified_on_a_whole_replay() {
        let mut f = GateFindings {
            held_missing_total: 2,
            held_missing: v(&["x1", "x2"]),
            ..clean()
        };
        assert_eq!(f.held_missing_live(), 2);
        // Classified on a whole replay: orphans and deleted rows are set
        // aside and do not count.
        f.held_missing_live = Some(Vec::new());
        assert_eq!(f.held_missing_live(), 0);
        assert_eq!(lift(&f, &Acknowledged::default()), Lift::Clean);
        // One live row: the lift names that one, not the orphan.
        f.held_missing_live = Some(v(&["x1"]));
        let live_only = Acknowledged {
            held_missing: set(&["x1"]),
            ..Default::default()
        };
        assert_eq!(
            lift(&f, &live_only),
            Lift::Acknowledged {
                named: live_only.clone()
            }
        );
        // A later step that adds held rows clears the classification.
        let mut more = step(true);
        more.held_missing_total = 1;
        more.held_missing = v(&["x3"]);
        let mut g = f.clone();
        g.add(&more);
        assert_eq!(g.held_missing_live, None);
        assert_eq!(g.held_missing_live(), 3);
        assert!(matches!(lift(&g, &live_only), Lift::Closed { .. }));
        // Rows beyond the list are not covered by a classification.
        let mut h = f.clone();
        h.held_missing_total = 3;
        assert_eq!(h.held_missing_live(), 3);
        assert!(matches!(lift(&h, &live_only), Lift::Closed { .. }));
        f.held_missing_live = Some(Vec::new());
        // The same classification on a replay that is not whole counts
        // nothing aside.
        f.unreadable = v(&["m/x/u"]);
        assert_eq!(f.held_missing_live(), 2);
        let only_unreadable = Acknowledged {
            unreadable: set(&["m/x/u"]),
            ..Default::default()
        };
        assert!(matches!(lift(&f, &only_unreadable), Lift::Closed { .. }));
        let both = Acknowledged {
            unreadable: set(&["m/x/u"]),
            held_missing: set(&["x1", "x2"]),
            ..Default::default()
        };
        assert_eq!(
            lift(&f, &both),
            Lift::Acknowledged {
                named: both.clone()
            }
        );
    }

    fn step(last: bool) -> ReplayReport {
        ReplayReport {
            next: (!last).then(|| crate::replay::ReplayCursor {
                since_ms: 0,
                phase: crate::replay::ReplayPhase::Held,
                after: String::new(),
                extent: 0,
                name: String::new(),
                run_ms: 0,
            }),
            ..ReplayReport::default()
        }
    }

    #[test]
    fn a_blocker_of_an_earlier_step_keeps_the_unit_closed() {
        let mut first = step(false);
        first.unreadable = v(&["m/x/a"]);
        first.held_missing_total = 3;
        first.held_missing = v(&["x1", "x2", "x3"]);
        let last = step(true);
        let found = GateFindings::of_replay([&first, &last]);
        assert!(found.complete);
        assert!(!found.whole());
        assert_eq!(found.held_missing_live(), 3);
        assert!(matches!(
            lift(&found, &Acknowledged::default()),
            Lift::Closed { .. }
        ));
        // The last step alone would have lifted: the gate never reads it alone.
        assert_eq!(
            lift(&GateFindings::of_replay([&last]), &Acknowledged::default()),
            Lift::Clean
        );
    }

    #[test]
    fn steps_add_up_as_the_replay_script_adds_them() {
        let mut a = step(false);
        a.other_bucket_total = 1;
        a.other_bucket = v(&["g1"]);
        a.twins = v(&["t1"]);
        a.unreadable = v(&["u1"]);
        a.damaged_total = 9;
        a.damaged = v(&["old"]);
        let mut b = step(true);
        b.other_bucket_total = 2;
        b.other_bucket = v(&["g2", "g3"]);
        b.twins = v(&["t1"]);
        b.unreadable = v(&["u1", "u2"]);
        b.damaged_total = 1;
        b.damaged = v(&["g9"]);
        let found = GateFindings::of_replay([&a, &b]);
        assert_eq!(found.other_bucket_total, 3);
        assert_eq!(found.other_bucket, v(&["g1", "g2", "g3"]));
        assert_eq!(found.twins, v(&["t1"]));
        assert_eq!(found.unreadable, v(&["u1", "u2"]));
        // The last call sets the damage for the whole replay.
        assert_eq!(found.damaged_total, 1);
        assert_eq!(found.damaged, v(&["g9"]));
        let mut unfinished = GateFindings::of_replay([&a]);
        assert!(!unfinished.complete);
        unfinished.add(&b);
        assert!(unfinished.complete);
    }

    #[test]
    fn ids_without_a_total_still_count() {
        let found = GateFindings {
            held_missing: v(&["x1"]),
            other_bucket: v(&["g1"]),
            ..clean()
        };
        assert!(!found.whole());
        assert_eq!(found.held_missing_live(), 1);
        assert!(matches!(
            lift(&found, &Acknowledged::default()),
            Lift::Closed { .. }
        ));
    }
}
