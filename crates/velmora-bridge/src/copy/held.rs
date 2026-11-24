//! Opt-in retry of generations held by the fresh publication gate.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    generation, minted_ms, put_mark, BlobEntry, BlobStore, Budget, Clock, Copied, Copier,
    CopyCounts, HttpSend, Item, Kek, Known, Named, Phase, Place, Read, ReadChunk, Span, UnixMs,
    Walked, What, JOB_COPIES, MAX_KEY_BYTES, SWEEP_RECORDS, WANT_KEY,
};

const PREFIX: &str = "h:";
const AFTER_KEY: &str = "rc/held-after";
const QUOTA: usize = JOB_COPIES / 4;
const MAX_AGE_MS: i64 = 6 * 60 * 60 * 1000;

/// A pass uses at most one held slice. Retrying the first queue job
/// after a send failure must not rotate through a second slice.
#[derive(Default, Deserialize, Serialize)]
struct Rotation {
    pass: i64,
    key: String,
}

fn stamped(key: &str) -> Option<(i64, u32)> {
    let at = minted_ms(key).filter(|_| generation(key))?;
    Some((at, u32::try_from(at / 1000).ok()?))
}

pub(super) fn retain(
    saved: BTreeMap<String, u32>,
    since: i64,
    parallel: bool,
) -> BTreeMap<String, u32> {
    let holds: BTreeSet<String> = if parallel {
        saved
            .iter()
            .filter_map(|(entry, &stamp)| {
                let key = entry.strip_prefix(PREFIX)?;
                (stamped(key)?.1 == stamp).then(|| key.to_owned())
            })
            .take(SWEEP_RECORDS)
            .collect()
    } else {
        BTreeSet::new()
    };
    // Take the holds first: stale/ordinary prefixes must never evict a hold.
    let mut result: BTreeMap<_, _> = holds
        .iter()
        .map(|key| {
            let entry = format!("{PREFIX}{key}");
            let stamp = saved[&entry];
            (entry, stamp)
        })
        .collect();
    let room = SWEEP_RECORDS - result.len();
    result.extend(
        saved
            .into_iter()
            .filter(|(key, _)| minted_ms(key).is_some_and(|ms| ms >= since) || holds.contains(key))
            .take(room),
    );
    result
}

impl Known {
    pub(super) fn forget_hold(&mut self, key: &str) {
        self.forget(&format!("{PREFIX}{key}"));
    }
}

impl<B: BlobStore, K: Kek, T: Clock, H: HttpSend> Copier<'_, B, K, T, H> {
    /// Save a request before forgetting why it was needed. One write
    /// suffices for every hold relinquished by this job.
    async fn ask_for_held_walk(&self, known: &mut Known) -> bool {
        if !known.walk_requested {
            known.walk_requested = self.save_time(WANT_KEY, self.clock.now()).await.is_ok();
            known.mark_failed |= !known.walk_requested;
        }
        known.walk_requested
    }

    pub(super) async fn remember_hold(&self, known: &mut Known, key: &str) {
        let Some((_, stamp)) = stamped(key) else {
            self.ask_for_held_walk(known).await;
            return;
        };
        let entry = format!("{PREFIX}{key}");
        if known.plans.contains_key(&entry) {
            return;
        }
        if known.plans.len() >= SWEEP_RECORDS {
            self.ask_for_held_walk(known).await;
            return;
        }
        known.plans.insert(entry, stamp);
        known.changed = true;
    }

    pub(super) async fn retry_held(
        &self,
        pass: UnixMs,
        span: &Span,
        budget: &mut Budget<'_>,
        counts: &mut CopyCounts,
        known: &mut Known,
    ) -> Walked {
        self.load_known(known, span).await;
        let keys: Vec<(String, i64)> = known
            .plans
            .keys()
            .filter_map(|entry| {
                let key = entry.strip_prefix(PREFIX)?;
                let at = minted_ms(key)?;
                (at < span.since).then(|| (key.to_owned(), at))
            })
            .collect();
        if keys.is_empty() {
            return Walked::End;
        }
        let after: Rotation = self
            .read_mark(AFTER_KEY, MAX_KEY_BYTES + 64)
            .await
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(|rotation: &Rotation| generation(&rotation.key))
            .unwrap_or_default();
        if after.pass >= pass.0 && !after.key.is_empty() {
            return Walked::End;
        }
        let start = keys.partition_point(|(key, _)| *key <= after.key);
        let mut last = None;
        let mut outage = false;
        for (key, written) in keys[start..].iter().chain(&keys[..start]) {
            if budget.copies >= QUOTA || self.spent(budget.started) {
                break;
            }
            let first = budget.copies == 0;
            let remaining = QUOTA - budget.copies;
            budget.copies += 1;
            if pass.0.saturating_sub(*written) >= MAX_AGE_MS {
                if !self.ask_for_held_walk(known).await {
                    // Leave the pointer before this handoff so the next pass
                    // can retry it without waiting through a full rotation.
                    break;
                }
                known.forget(key);
                known.forget_hold(key);
                last = Some(key);
                continue;
            }

            // Point read from the bounded hold list: never list the old
            // generation range. Use the same fresh publication gate below.
            let started = self.clock.now();
            let read = self.read_generation(key, None, true).await;
            budget.timing.generation_reads += 1;
            budget.timing.generation_ms += self.elapsed_ms(started);
            if matches!(read, Read::Is(Copied::Gone)) {
                known.forget(key);
                known.forget_hold(key);
                last = Some(key);
                continue;
            }
            let mut place = Place::first(Phase::Held, pass);
            let (size, of, cost) = match &read {
                Read::Generation { bytes, named } => {
                    let of = named.extents();
                    let segments = match named {
                        Named::Plans(_) => 0,
                        Named::Segments(head) => head.segments.len(),
                    };
                    (
                        bytes.len() as u64,
                        of,
                        1 + of - known.confirmed(&place, key, named) + segments,
                    )
                }
                _ => (0, 0, 1),
            };
            let oversized = cost > remaining;
            if oversized && !first {
                // This is the first candidate next pass. Only its sizing
                // read was charged here; it cannot exceed this pass's slice.
                break;
            }
            budget.copy_limit = if oversized { JOB_COPIES } else { QUOTA };
            let entry = BlobEntry {
                key: key.clone(),
                size,
                md5: String::new(),
            };
            let input = ReadChunk {
                items: &[Item {
                    entry: &entry,
                    what: What::Copy(None),
                }],
                records: vec![(0, read)],
            };
            let chunk = self
                .copy_read_chunk(input, span, &mut place, budget, counts, known)
                .await;
            budget.copy_limit = JOB_COPIES;
            if chunk.finished == 0 {
                // Keep a bounded prefix when the 250-op or time limit was
                // hit, even when only the segmented head/segments remain.
                known.keep_for_retry(key, place.plans as usize, of);
            }
            last = Some(key);
            outage = chunk.outage;
            if oversized || outage {
                break;
            }
        }
        if let Some(key) = last {
            let mark = Rotation {
                pass: pass.0,
                key: key.clone(),
            };
            // The small safe-key record always serializes.
            let bytes = serde_json::to_vec(&mark).unwrap_or_default();
            known.mark_failed |= put_mark(self.safety, AFTER_KEY, bytes).await.is_err();
        }
        // The successor resumes the normal fresh sweep, not another held slice.
        if outage {
            Walked::Outage
        } else {
            Walked::End
        }
    }
}
