//! The recovery copy: every recovery record of the safety bucket, copied
//! to a store outside this account ([`crate::remote`]).
//!
//! A **pass** walks all of `m/` in key order and compares both listings
//! by key, size and MD5. A record that is missing or different over
//! there is copied; nothing else is sent.
//!
//! - **Nothing is ever deleted over there.** "Absent in the safety
//!   bucket" cannot be told from "the safety bucket was lost", which is
//!   the event the copy exists for. A copy without a source is counted
//!   (`extra`) and left alone.
//! - **A record is copied only if it opens** under the KEK and its own
//!   name. One that does not is counted (`source_unreadable`) and never
//!   replaces a copy.
//! - **A generation record is copied once its id is two minutes old.**
//!   The record of a refused publication is removed in the request that
//!   wrote it ([`crate::recovery::discard_generation`]); the wait keeps
//!   it from being copied first.
//! - **Tenant keys (`m/tk/`) never leave.**
//! - **No catalogue.** The pass reads the two stores and the clock, so
//!   it runs while the catalogue is closed (rolled back, or a replay
//!   unfinished) and trusts no cursor: a lost or repeated job only makes
//!   the next pass do the work. It does not run in `MAINTENANCE=restore`,
//!   when the safety bucket may be half filled.

use std::collections::{BTreeMap, BTreeSet};

use futures_util::stream::{self, StreamExt};
use serde::Serialize;
use velmora_s3_proto::sign::Listed;

use crate::config::Maintenance;
use crate::crypto::open_manifest;
use crate::ports::{BlobEntry, BlobStore, Clock, JobSink, Kek};
use crate::recovery::{GENERATION_PREFIX, RECORD_PREFIX, TENANT_KEY_PREFIX};
use crate::remote::{md5_hex, HttpSend, RemoteError, S3Remote};
use crate::types::{Job, JobOutcome, Result, UnixMs, JOB_VERSION};

/// A pass starts on the cron run that falls in the first
/// [`START_WINDOW_MS`] of each interval of this length.
pub const PASS_INTERVAL_MS: i64 = 15 * 60 * 1000;
/// The cron period: exactly one run falls in the window.
pub const START_WINDOW_MS: i64 = 5 * 60 * 1000;
/// A generation record younger than this (by its id) is not copied yet.
pub const MIN_AGE_MS: i64 = 2 * 60 * 1000;
/// Bounds of one job; the next job goes on from the cursor.
pub const JOB_COPIES: usize = 250;
pub const JOB_PAGES: u32 = 40;
pub const JOB_MS: i64 = 20_000;
/// Copies under way at once.
pub const CONCURRENCY: usize = 6;
/// Source keys read per page.
pub const PAGE: u32 = 1000;
/// A job that failed is retried while its pass is younger than this.
/// A pass ends when it is [`PASS_INTERVAL_MS`] old: the next one has
/// started.
pub const RETRY_WINDOW_MS: i64 = 10 * 60 * 1000;
pub const RETRY_SECS: u32 = 60;
/// List requests to the store for one page of the source, and for
/// counting the copies past the last source key.
pub const LIST_PAGES: u32 = 10;
/// A group of at least this many copies that got no answer at all means
/// the store is down. Fewer are taken as a fault of those records.
pub const OUTAGE_MIN: usize = 3;

/// What one job did. Counts only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CopyCounts {
    /// Source records seen (tenant keys excluded) and their bytes.
    pub records: u64,
    pub bytes: u64,
    /// Already equal over there.
    pub same: u64,
    pub copied: u64,
    /// Not copied, and worth another try (the next pass makes it).
    pub failed: u64,
    /// Refused by the store with a 4xx: needs the operator.
    pub refused: u64,
    /// Does not open here; not copied.
    pub source_unreadable: u64,
    /// Generation records too young to copy.
    pub young: u64,
    /// Copies without a source (at least this many). Never deleted.
    pub extra: u64,
}

impl CopyCounts {
    /// Nothing is left for a later pass to mend.
    pub fn clean(&self) -> bool {
        self.failed == 0 && self.refused == 0
    }
}

/// Result of one job: what it did, and where the next one goes on
/// (`None` = the pass has ended).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyStep {
    pub counts: CopyCounts,
    pub next: Option<String>,
    /// The step stopped because the store did not answer.
    pub outage: bool,
}

enum Copied {
    Done,
    Same,
    Gone,
    Unreadable,
    /// Not copied; the store answered.
    Failed,
    /// Not copied; the store gave no answer.
    Down,
    Refused,
}

/// True on the cron run that starts a pass.
pub fn pass_due(now: UnixMs) -> bool {
    now.0.rem_euclid(PASS_INTERVAL_MS) < START_WINDOW_MS
}

/// Milliseconds in the id of a generation record's key.
fn minted_ms(key: &str) -> Option<i64> {
    let hex = key.strip_prefix(GENERATION_PREFIX)?.get(..13)?;
    i64::from_str_radix(hex, 16).ok()
}

fn young(key: &str, now: UnixMs) -> bool {
    minted_ms(key).is_some_and(|ms| ms > now.0 - MIN_AGE_MS)
}

/// Everything a pass touches.
pub struct Copier<'a, B: BlobStore, K: Kek, T: Clock, H: HttpSend> {
    pub safety: &'a B,
    pub kek: &'a K,
    pub clock: &'a T,
    pub remote: &'a S3Remote<H>,
    pub maintenance: Maintenance,
}

impl<B: BlobStore, K: Kek, T: Clock, H: HttpSend> Copier<'_, B, K, T, H> {
    /// The cron hook: sends the first job of a pass when one is due at
    /// `scheduled`, the time the cron run was set for. A run that
    /// starts late still starts its pass.
    pub async fn start_pass<J: JobSink>(&self, jobs: &J, scheduled: UnixMs) -> Result<bool> {
        if self.maintenance == Maintenance::Restore || !pass_due(scheduled) {
            return Ok(false);
        }
        let first = Job::RecoveryCopy {
            v: JOB_VERSION,
            pass: scheduled,
            cursor: String::new(),
        };
        jobs.send(&first, 0).await?;
        Ok(true)
    }

    /// One queue job of a pass: a step from `cursor`, then the message
    /// for the next step. `None` = nothing was done (maintenance, or a
    /// newer pass has started).
    pub async fn run_job<J: JobSink>(
        &self,
        jobs: &J,
        pass: UnixMs,
        cursor: &str,
    ) -> (JobOutcome, Option<CopyCounts>) {
        if self.maintenance == Maintenance::Restore {
            return (JobOutcome::Ack, None);
        }
        // A pass ends when the next one starts: the newer pass passes
        // quickly over what is done, so two never run for long.
        let age = self.clock.now().0 - pass.0;
        if age >= PASS_INTERVAL_MS {
            return (JobOutcome::Ack, None);
        }
        // Every step is idempotent, so a failed job simply runs again,
        // but not for ever: a later pass takes over.
        let again = if age < RETRY_WINDOW_MS {
            JobOutcome::Retry {
                delay_secs: RETRY_SECS,
            }
        } else {
            JobOutcome::Ack
        };
        let Ok(step) = self.step(cursor).await else {
            return (again, None);
        };
        // The store is down: the cursor does not move while the job may
        // be retried. After that the pass goes on past the records that
        // failed, so that no record can hold back those behind it.
        if step.outage && age < RETRY_WINDOW_MS {
            return (again, Some(step.counts));
        }
        if let Some(cursor) = step.next {
            let next = Job::RecoveryCopy {
                v: JOB_VERSION,
                pass,
                cursor,
            };
            if jobs.send(&next, 0).await.is_err() {
                return (again, Some(step.counts));
            }
        }
        (JobOutcome::Ack, Some(step.counts))
    }

    fn spent(&self, started: UnixMs) -> bool {
        self.clock.now().0 - started.0 >= JOB_MS
    }

    /// Walks the source from `cursor` until a bound of the job is
    /// reached, the store is found down, or the source ends.
    pub async fn step(&self, cursor: &str) -> Result<CopyStep> {
        let started = self.clock.now();
        let mut counts = CopyCounts::default();
        let mut cursor = cursor.to_string();
        let mut copies = 0;
        let mut outage = false;
        for _ in 0..JOB_PAGES {
            if outage || copies >= JOB_COPIES || self.spent(started) {
                break;
            }
            let mut source = self
                .safety
                .list_entries(RECORD_PREFIX, &cursor, PAGE)
                .await?;
            let Some(last) = source.last().map(|e| e.key.clone()) else {
                // The source has ended; what the store still lists is extra.
                counts.extra += self.listed(&cursor, None).await?.0.len() as u64;
                return Ok(CopyStep {
                    counts,
                    next: None,
                    outage: false,
                });
            };
            // The store may hold far more keys in this range than the
            // source: its listing is cut after LIST_PAGES requests, and
            // the page then ends at the last key listed.
            let (there, cut) = self.listed(&cursor, Some(&last)).await?;
            let end = match cut {
                Some(cut) => {
                    source.retain(|e| e.key <= cut);
                    cut
                }
                None => last,
            };
            let there: BTreeMap<&str, &Listed> =
                there.iter().map(|o| (o.key.as_str(), o)).collect();
            let names: BTreeSet<&str> = source.iter().map(|e| e.key.as_str()).collect();

            // In key order, CONCURRENCY copies at a time; the bounds are
            // looked at after each group, and the page ends at the key
            // where one is reached.
            let now = self.clock.now();
            let mut group: Vec<(&BlobEntry, Option<&Listed>)> = Vec::new();
            let mut stopped: Option<&str> = None;
            for entry in &source {
                if entry.key.starts_with(TENANT_KEY_PREFIX) {
                    continue;
                }
                counts.records += 1;
                counts.bytes += entry.size;
                let copy = there.get(entry.key.as_str()).copied();
                if young(&entry.key, now) {
                    counts.young += 1;
                    continue;
                }
                if copy.is_some_and(|c| {
                    c.size == entry.size && c.etag.eq_ignore_ascii_case(&entry.md5)
                }) {
                    counts.same += 1;
                    continue;
                }
                group.push((entry, copy));
                if group.len() == CONCURRENCY || copies + group.len() >= JOB_COPIES {
                    copies += group.len();
                    outage = self.copy_group(&mut group, &mut counts).await;
                    if outage || copies >= JOB_COPIES || self.spent(started) {
                        stopped = Some(&entry.key);
                        break;
                    }
                }
            }
            if !group.is_empty() {
                copies += group.len();
                outage = self.copy_group(&mut group, &mut counts).await;
            }
            let upto = stopped.map_or(end, str::to_string);
            counts.extra += there
                .keys()
                .filter(|k| **k <= upto.as_str() && !names.contains(*k))
                .count() as u64;
            cursor = upto;
        }
        Ok(CopyStep {
            counts,
            next: Some(cursor),
            outage,
        })
    }

    /// Copies the records of `group` at once and empties it. True = the
    /// store answered none of them: it is down.
    async fn copy_group(
        &self,
        group: &mut Vec<(&BlobEntry, Option<&Listed>)>,
        counts: &mut CopyCounts,
    ) -> bool {
        let size = group.len();
        let results: Vec<Copied> = stream::iter(group.drain(..))
            .map(|(entry, copy)| self.copy_one(&entry.key, copy))
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        let mut down = 0;
        for result in results {
            match result {
                Copied::Done => counts.copied += 1,
                Copied::Same => counts.same += 1,
                Copied::Unreadable => counts.source_unreadable += 1,
                Copied::Failed => counts.failed += 1,
                Copied::Down => {
                    counts.failed += 1;
                    down += 1;
                }
                Copied::Refused => counts.refused += 1,
                // Removed since it was listed: not a record any more.
                Copied::Gone => counts.records -= 1,
            }
        }
        size >= OUTAGE_MIN && down == size
    }

    /// Copies of the store after `after`, up to and including `upto`
    /// (`None` = to the end), from at most [`LIST_PAGES`] requests. The
    /// second value is the last key listed when the requests ran out
    /// before `upto` was reached.
    async fn listed(
        &self,
        after: &str,
        upto: Option<&String>,
    ) -> Result<(Vec<Listed>, Option<String>)> {
        let mut out: Vec<Listed> = Vec::new();
        let mut after = after.to_string();
        for pages in 1..=LIST_PAGES {
            let page = self
                .remote
                .list(self.clock, RECORD_PREFIX, &after)
                .await
                .map_err(remote_err)?;
            let Some(last) = page.objects.last().map(|o| o.key.clone()) else {
                break;
            };
            out.extend(page.objects);
            if !page.truncated || upto.is_some_and(|u| last.as_str() >= u.as_str()) {
                break;
            }
            if pages == LIST_PAGES {
                return Ok((out, upto.map(|_| last)));
            }
            after = last;
        }
        if let Some(upto) = upto {
            out.retain(|o| o.key.as_str() <= upto.as_str());
        }
        Ok((out, None))
    }

    async fn copy_one(&self, key: &str, copy: Option<&Listed>) -> Copied {
        let bytes = match self.safety.get(key, None).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Copied::Gone,
            Err(_) => return Copied::Failed,
        };
        if open_manifest(self.kek, key, &bytes).is_err() {
            return Copied::Unreadable;
        }
        // The listing may name another digest than the MD5 of the bytes;
        // an equal copy is not sent again.
        let md5 = md5_hex(&bytes);
        if copy.is_some_and(|c| c.size == bytes.len() as u64 && c.etag.eq_ignore_ascii_case(&md5)) {
            return Copied::Same;
        }
        match self.remote.put(self.clock, key, &bytes).await {
            Ok(()) => Copied::Done,
            Err(RemoteError::Refused(_) | RemoteError::Unsignable) => Copied::Refused,
            Err(RemoteError::Unavailable) => Copied::Down,
            Err(_) => Copied::Failed,
        }
    }
}

fn remote_err(e: RemoteError) -> crate::types::BridgeError {
    crate::types::BridgeError::Blob(
        match e {
            RemoteError::Refused(_) => "recovery store refused the request",
            RemoteError::Unavailable => "recovery store did not answer",
            RemoteError::Mismatch => "recovery store answered out of contract",
            RemoteError::Unsignable => "recovery store request cannot be signed",
        }
        .to_string(),
    )
}
