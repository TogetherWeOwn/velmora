//! The recovery copy: every recovery record of the safety bucket, copied
//! to a store outside this account ([`crate::remote`]).
//!
//! A **pass** starts every [`PASS_INTERVAL_MS`] and does two things, in
//! this order:
//!
//! 1. **The fresh sweep.** The generation records and the tombstones
//!    minted in the last [`FRESH_MS`]. Their keys start with the time,
//!    so this is a short range of the listing however many records the
//!    bucket holds. A new write or delete is over there one pass later.
//! 2. **The walk.** Everything else under `m/`, in key order, from
//!    where the last pass stopped ([`WALK_KEY`]). A pass ends when the
//!    next one starts; the walk goes on from the saved place and starts
//!    over at its end, so every key is reached whatever their number.
//!
//! Both compare the two listings by key, size and MD5. A record that is
//! missing or different over there is copied; nothing else is sent.
//!
//! - **A fresh generation record is sent after its article plans.** The
//!   key of an article plan is random, so a new one cannot be found in
//!   a listing without reading all of it. The sweep reads which extents
//!   a generation names and copies their plans first. A record with a
//!   plan that is not written yet (the extent is not posted) is held
//!   back (`pending`) and looked at again by the next pass. Once it is
//!   older than [`FRESH_MS`] the walk copies it as it is, and its plans
//!   when it comes to them.
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
//! - **Tenant keys (`m/tk/`) never leave**, and neither do their names.
//! - **What something else wrote over there is counted (`foreign`) and
//!   passed.** It is never a copy, and it does not stop the pass. (One
//!   exception: a key with a control character is refused by the
//!   parser of the listing, so the step fails and says so.)
//! - **No catalogue.** The pass reads the two stores and the clock, so
//!   it runs while the catalogue is closed (rolled back, or a replay
//!   unfinished). The saved place of the walk is a hint: any value,
//!   or none, only changes where the walk starts, never what it
//!   reaches. A lost or repeated job only makes a later pass do the
//!   work. It does not run in `MAINTENANCE=restore`, when the safety
//!   bucket may be half filled.
//! - **A record of the walk that could not be copied waits for the walk
//!   to come round.** One of the fresh sweep is tried again by the next
//!   pass.

use std::collections::{BTreeMap, BTreeSet};

use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use velmora_s3_proto::sign::Listed;

use crate::config::Maintenance;
use crate::crypto::open_manifest;
use crate::ports::{BlobEntry, BlobMeta, BlobStore, Clock, JobSink, Kek};
use crate::recovery::{
    plan_keys, start_after, GENERATION_PREFIX, RECORD_PREFIX, TENANT_KEY_PREFIX, TOMBSTONE_PREFIX,
};
use crate::remote::{md5_hex, HttpSend, RemoteError, S3Remote, MAX_KEY_BYTES};
use crate::types::{BucketId, ExtentId, Job, JobOutcome, Result, UnixMs, JOB_VERSION};

/// A pass starts on the cron run that falls in the first
/// [`START_WINDOW_MS`] of each interval of this length.
pub const PASS_INTERVAL_MS: i64 = 15 * 60 * 1000;
/// The cron period: exactly one run falls in the window.
pub const START_WINDOW_MS: i64 = 5 * 60 * 1000;
/// A generation record younger than this (by its id) is not copied yet.
pub const MIN_AGE_MS: i64 = 2 * 60 * 1000;
/// The fresh sweep of a pass covers the generation records and the
/// tombstones minted in this long before the pass started. Older ones
/// belong to the walk.
pub const FRESH_MS: i64 = 60 * 60 * 1000;
/// Where the walk stopped: a key of the safety bucket, outside the
/// records. Its body is the key the walk goes on after.
pub const WALK_KEY: &str = "rc/walk";
/// Bounds of one job; the next job goes on from the cursor. A copy and
/// a check of an article plan count alike, so a job makes about 1,100
/// requests at most.
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

/// The key after the last tombstone.
const TOMBSTONES_END: &str = "m/del0";

/// What one job did. Counts only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CopyCounts {
    /// Source records seen (tenant keys excluded) and their bytes.
    pub records: u64,
    pub bytes: u64,
    /// Already equal over there.
    pub same: u64,
    /// Records sent. An article plan sent ahead of the walk, for a
    /// fresh generation record, is counted here and not in `records`.
    pub copied: u64,
    /// Not copied, and worth another try (a later pass makes it).
    pub failed: u64,
    /// Refused by the store with a 4xx: needs the operator.
    pub refused: u64,
    /// Does not open here; not copied.
    pub source_unreadable: u64,
    /// Generation records too young to copy.
    pub young: u64,
    /// Fresh generation records held back: an article plan they name is
    /// not over there yet.
    pub pending: u64,
    /// Copies without a source (at least this many). Never deleted.
    pub extra: u64,
    /// Keys over there that this service would not write: something
    /// else did. Never a copy, never deleted.
    pub foreign: u64,
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
    /// The key the walk goes on after, when the step came to the walk
    /// (empty = from the start: the walk has ended).
    pub walk: Option<String>,
}

/// Why a job did not do its step: a class, and a status at most. Never
/// text from a store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepError {
    /// The safety bucket could not be read.
    Source,
    /// The recovery store could not be listed.
    Store(RemoteError),
    /// The job for the next step could not be sent.
    Queue,
    /// The fresh sweep was not at its end when the next pass started:
    /// what was left of it was not looked at.
    Expired,
    /// The place of the walk could not be saved. The pass goes on; a
    /// pass that starts before a later save walks this part again.
    Mark,
}

/// The parts of a pass, in the order they are done.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    /// Fresh generation records, and whatever sorts after them.
    #[serde(rename = "g")]
    Generations,
    /// Fresh tombstones.
    #[serde(rename = "d")]
    Tombstones,
    /// The walk below the fresh tombstones.
    #[serde(rename = "a")]
    Low,
    /// The walk between the tombstones and the fresh generation records.
    #[serde(rename = "b")]
    High,
}

/// Where a pass stands: the cursor of a job, as JSON. An empty cursor,
/// or one that does not parse, is the start of a pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Place {
    #[serde(rename = "p")]
    phase: Phase,
    /// The key the phase goes on after.
    #[serde(rename = "k")]
    key: String,
    /// A generation record after `key` that an earlier job began, and
    /// how many of its article plans, in order, are over there. They
    /// stay in the cursor until the phase ends; only that record reads
    /// them.
    #[serde(rename = "g", default, skip_serializing_if = "String::is_empty")]
    generation: String,
    #[serde(rename = "n", default, skip_serializing_if = "is_zero")]
    plans: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl Place {
    fn at(phase: Phase, key: String) -> Place {
        Place {
            phase,
            key,
            generation: String::new(),
            plans: 0,
        }
    }

    fn parse(cursor: &str) -> Option<Place> {
        serde_json::from_str(cursor).ok()
    }

    fn cursor(&self) -> String {
        // Serializing plain strings and integers cannot fail.
        serde_json::to_string(self).unwrap_or_default()
    }

    fn walking(&self) -> bool {
        matches!(self.phase, Phase::Low | Phase::High)
    }
}

/// The keys of one phase: after the place of the pass, up to and
/// including `until` (`None` = to the end).
struct Span {
    until: Option<String>,
    /// Generation records are sent after their article plans.
    plans: bool,
}

/// The first key of the fresh generation records (or tombstones) of the
/// pass that started at `pass`: every fresh one sorts after it.
fn fresh(prefix: &str, pass: UnixMs) -> String {
    start_after(prefix, UnixMs(pass.0 - FRESH_MS))
}

fn span(phase: Phase, pass: UnixMs) -> Span {
    let until = match phase {
        Phase::Generations => None,
        Phase::Tombstones => Some(TOMBSTONES_END.to_string()),
        Phase::Low => Some(fresh(TOMBSTONE_PREFIX, pass)),
        Phase::High => Some(fresh(GENERATION_PREFIX, pass)),
    };
    Span {
        until,
        plans: phase == Phase::Generations,
    }
}

/// Where the walk of a pass starts, from the place that was saved. A
/// place outside the two parts of the walk is read as the start.
fn walk_from(saved: String, pass: UnixMs) -> Place {
    if saved < fresh(TOMBSTONE_PREFIX, pass) {
        Place::at(Phase::Low, saved)
    } else if saved.as_str() >= TOMBSTONES_END && saved < fresh(GENERATION_PREFIX, pass) {
        Place::at(Phase::High, saved)
    } else {
        Place::at(Phase::Low, String::new())
    }
}

/// What a job has used of its bounds.
struct Budget {
    started: UnixMs,
    copies: usize,
    pages: u32,
}

/// How a phase stopped.
#[derive(PartialEq, Eq)]
enum Walked {
    /// It reached the end of its keys.
    End,
    /// A bound of the job was reached.
    More,
    /// The store was found down.
    Outage,
}

/// What the store holds in a range.
#[derive(Default)]
struct Range {
    copies: Vec<Listed>,
    foreign: Vec<String>,
    /// The last key listed, when the requests ran out before the end of
    /// the range.
    cut: Option<String>,
}

/// Where a source page ends for the store. Tenant keys are passed as a
/// whole, by a key that sorts after all of them and names none.
fn page_end(last: &str) -> String {
    if last.starts_with(TENANT_KEY_PREFIX) {
        format!("{}0", TENANT_KEY_PREFIX.trim_end_matches('/'))
    } else {
        last.to_string()
    }
}

/// What the listings say of a source record.
enum What<'a> {
    Young,
    Same,
    /// To copy; the copy over there, when one is listed.
    Copy(Option<&'a Listed>),
}

struct Item<'a> {
    entry: &'a BlobEntry,
    what: What<'a>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
    /// A generation record held back for an article plan.
    Held,
}

/// A record to copy, after the first look at it.
enum Read {
    Is(Copied),
    /// A fresh generation record: its bytes, and the keys of the
    /// article plans it names.
    Generation {
        bytes: Vec<u8>,
        plans: Vec<String>,
    },
}

/// What became of the article plan of a fresh generation record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Plan {
    /// Equal over there already.
    There,
    Sent,
    /// Not written yet: the extent is not posted.
    Absent,
    Unreadable,
    Failed,
    Down,
    Refused,
}

/// What became of the records of a chunk.
struct Chunk {
    /// How many of them, from the first, are finished. The cursor does
    /// not pass the others.
    finished: usize,
    outage: bool,
}

/// At least [`OUTAGE_MIN`] requests, and no answer to any of them.
fn all_down(asked: usize, down: usize) -> bool {
    asked >= OUTAGE_MIN && down == asked
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

fn equal(copy: Option<&Listed>, size: u64, md5: &str) -> bool {
    copy.is_some_and(|c| c.size == size && c.etag.eq_ignore_ascii_case(md5))
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
    /// for the next step. No counts = no step was done (maintenance, a
    /// newer pass has started, or the step failed). The third value is
    /// why the job did not do all of its work, when it did not; the
    /// job may be acknowledged all the same, so it has to be reported.
    pub async fn run_job<J: JobSink>(
        &self,
        jobs: &J,
        pass: UnixMs,
        cursor: &str,
    ) -> (JobOutcome, Option<CopyCounts>, Option<StepError>) {
        if self.maintenance == Maintenance::Restore {
            return (JobOutcome::Ack, None, None);
        }
        // A pass ends when the next one starts. The walk loses nothing
        // by it: the newer pass goes on from the place that was saved.
        // A fresh sweep that is cut short is late, and says so.
        let age = self.clock.now().0 - pass.0;
        if age >= PASS_INTERVAL_MS {
            let walking = Place::parse(cursor).is_some_and(|p| p.walking());
            let why = (!walking).then_some(StepError::Expired);
            return (JobOutcome::Ack, None, why);
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
        let step = match self.step(pass, cursor).await {
            Ok(step) => step,
            Err(e) => return (again, None, Some(e)),
        };
        // The store is down: the cursor does not move while the job may
        // be retried. After that the pass goes on past the records that
        // failed, so that no record can hold back those behind it.
        if step.outage && age < RETRY_WINDOW_MS {
            let down = StepError::Store(RemoteError::Unavailable);
            return (again, Some(step.counts), Some(down));
        }
        let mut why = None;
        if let Some(at) = &step.walk {
            if self.save_walk(at).await.is_err() {
                why = Some(StepError::Mark);
            }
        }
        if let Some(cursor) = step.next {
            let next = Job::RecoveryCopy {
                v: JOB_VERSION,
                pass,
                cursor,
            };
            if jobs.send(&next, 0).await.is_err() {
                return (again, Some(step.counts), Some(StepError::Queue));
            }
        }
        (JobOutcome::Ack, Some(step.counts), why)
    }

    fn spent(&self, started: UnixMs) -> bool {
        self.clock.now().0 - started.0 >= JOB_MS
    }

    /// Does the pass that started at `pass` from `cursor` on, phase
    /// after phase, until a bound of the job is reached, the store is
    /// found down, or the pass ends.
    pub async fn step(
        &self,
        pass: UnixMs,
        cursor: &str,
    ) -> std::result::Result<CopyStep, StepError> {
        let mut budget = Budget {
            started: self.clock.now(),
            copies: 0,
            pages: 0,
        };
        let mut counts = CopyCounts::default();
        let mut place = Place::parse(cursor)
            .unwrap_or_else(|| Place::at(Phase::Generations, fresh(GENERATION_PREFIX, pass)));
        loop {
            let phase = span(place.phase, pass);
            let walked = self
                .walk(&phase, &mut place, &mut budget, &mut counts)
                .await?;
            if walked == Walked::End {
                place = match place.phase {
                    Phase::Generations => {
                        Place::at(Phase::Tombstones, fresh(TOMBSTONE_PREFIX, pass))
                    }
                    Phase::Tombstones => walk_from(self.saved_walk().await?, pass),
                    Phase::Low => Place::at(Phase::High, TOMBSTONES_END.to_string()),
                    Phase::High => {
                        return Ok(CopyStep {
                            counts,
                            next: None,
                            outage: false,
                            walk: Some(String::new()),
                        })
                    }
                };
                continue;
            }
            return Ok(CopyStep {
                counts,
                walk: place.walking().then(|| place.key.clone()),
                next: Some(place.cursor()),
                outage: walked == Walked::Outage,
            });
        }
    }

    /// The place the walk was saved at; empty when none is, or when it
    /// is not a key.
    async fn saved_walk(&self) -> std::result::Result<String, StepError> {
        let saved = self
            .safety
            .get(WALK_KEY, None)
            .await
            .map_err(|_| StepError::Source)?;
        Ok(saved
            .filter(|bytes| bytes.len() <= MAX_KEY_BYTES)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default())
    }

    async fn save_walk(&self, at: &str) -> Result<()> {
        let body = at.as_bytes().to_vec();
        let sha: [u8; 32] = Sha256::digest(&body).into();
        let meta = BlobMeta {
            bucket: &BucketId::new("-"),
            extent: &ExtentId::new("recovery-copy"),
            cipher_sha256: &sha,
        };
        self.safety.put(WALK_KEY, body, &meta).await
    }

    /// Walks the keys of `span` after `place.key`, and moves the place,
    /// until a bound of the job is reached, the store is found down, or
    /// the keys end.
    async fn walk(
        &self,
        span: &Span,
        place: &mut Place,
        budget: &mut Budget,
        counts: &mut CopyCounts,
    ) -> std::result::Result<Walked, StepError> {
        let inside = |key: &str| span.until.iter().all(|until| key <= until.as_str());
        loop {
            if budget.pages >= JOB_PAGES
                || budget.copies >= JOB_COPIES
                || self.spent(budget.started)
            {
                return Ok(Walked::More);
            }
            budget.pages += 1;
            let mut source = self
                .safety
                .list_entries(RECORD_PREFIX, &place.key, PAGE)
                .await
                .map_err(|_| StepError::Source)?;
            source.retain(|e| inside(&e.key));
            let Some(last) = source.last().map(|e| page_end(&e.key)) else {
                // The keys have ended; what the store still lists in the
                // span is extra.
                let rest = self.listed(&place.key, span.until.as_ref()).await?;
                counts.extra += rest.copies.iter().filter(|o| inside(&o.key)).count() as u64;
                counts.foreign += rest.foreign.iter().filter(|k| inside(k)).count() as u64;
                return Ok(Walked::End);
            };
            // The store may hold far more keys in this range than the
            // source: its listing is cut after LIST_PAGES requests, and
            // the page then ends at the last key listed.
            let range = self.listed(&place.key, Some(&last)).await?;
            let end = match range.cut {
                Some(cut) => {
                    source.retain(|e| e.key <= cut);
                    cut
                }
                None => last,
            };
            let there: BTreeMap<&str, &Listed> =
                range.copies.iter().map(|o| (o.key.as_str(), o)).collect();
            let names: BTreeSet<&str> = source.iter().map(|e| e.key.as_str()).collect();
            let now = self.clock.now();
            let items: Vec<Item> = source
                .iter()
                .filter(|e| !e.key.starts_with(TENANT_KEY_PREFIX))
                .map(|entry| {
                    let copy = there.get(entry.key.as_str()).copied();
                    let what = if young(&entry.key, now) {
                        What::Young
                    } else if equal(copy, entry.size, &entry.md5) {
                        What::Same
                    } else {
                        What::Copy(copy)
                    };
                    Item { entry, what }
                })
                .collect();

            // In key order, a chunk of CONCURRENCY copies at a time; the
            // bounds are looked at after each chunk, and the page ends
            // at the last record that is finished.
            let mut done = 0;
            let mut outage = false;
            while done < items.len() {
                let room = CONCURRENCY.min(JOB_COPIES.saturating_sub(budget.copies));
                let mut to = done;
                let mut copies = 0;
                while to < items.len() {
                    if matches!(items[to].what, What::Copy(_)) {
                        if copies == room {
                            break;
                        }
                        copies += 1;
                    }
                    to += 1;
                }
                budget.copies += copies;
                let chunk = self
                    .copy_chunk(&items[done..to], span.plans, place, budget, counts)
                    .await;
                done += chunk.finished;
                outage = chunk.outage;
                if done < to || outage || budget.copies >= JOB_COPIES || self.spent(budget.started)
                {
                    break;
                }
            }
            let upto = if done == items.len() {
                end
            } else if done == 0 {
                place.key.clone()
            } else {
                items[done - 1].entry.key.clone()
            };
            counts.extra += there
                .keys()
                .filter(|k| **k <= upto.as_str() && !names.contains(*k))
                .count() as u64;
            counts.foreign += range.foreign.iter().filter(|k| **k <= upto).count() as u64;
            place.key = upto;
            if outage {
                return Ok(Walked::Outage);
            }
            if done < items.len() {
                return Ok(Walked::More);
            }
        }
    }

    /// Does the records of `chunk` and counts those that are finished.
    ///
    /// With `plans`, a generation record is sent after the article plans
    /// it names: all the records are read, then the plans are looked at,
    /// in key order as far as the bounds of the job allow, then the
    /// records whose plans are all over there are sent. A record whose
    /// plans did not fit is not finished: `place` keeps how far it came,
    /// and the next job goes on there. Nothing after it is counted. (A
    /// record after it that is not a generation record was sent all the
    /// same; the next job finds it equal.)
    async fn copy_chunk(
        &self,
        chunk: &[Item<'_>],
        plans: bool,
        place: &mut Place,
        budget: &mut Budget,
        counts: &mut CopyCounts,
    ) -> Chunk {
        let work = chunk
            .iter()
            .enumerate()
            .filter_map(|(i, item)| match item.what {
                What::Copy(copy) => Some((i, item.entry, copy)),
                _ => None,
            });
        let read: Vec<(usize, Read)> = stream::iter(work)
            .map(|(i, entry, copy)| async move {
                if plans && entry.key.starts_with(GENERATION_PREFIX) {
                    (i, self.read_generation(&entry.key, copy).await)
                } else {
                    (i, Read::Is(self.copy_one(&entry.key, copy).await))
                }
            })
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        let mut result: Vec<Option<Copied>> = vec![None; chunk.len()];
        let mut generations: BTreeMap<usize, (Vec<u8>, Vec<String>)> = BTreeMap::new();
        let (mut asked, mut down) = (0, 0);
        for (i, read) in read {
            match read {
                Read::Is(copied) => {
                    asked += 1;
                    down += usize::from(copied == Copied::Down);
                    result[i] = Some(copied);
                }
                Read::Generation { bytes, plans } => {
                    generations.insert(i, (bytes, plans));
                }
            }
        }
        let mut outage = all_down(asked, down);

        // The plans to look at: those of each record, in key order,
        // while the job has room.
        let mut finished = chunk.len();
        let mut part: Option<(usize, usize)> = None;
        let mut tasks: Vec<(usize, &str)> = Vec::new();
        let mut room = JOB_COPIES.saturating_sub(budget.copies);
        for (i, (_, keys)) in &generations {
            // A count for another record, or one larger than this record
            // has plans, is not believed.
            let begun = place.generation == chunk[*i].entry.key;
            let from = match place.plans as usize {
                n if begun && n <= keys.len() => n,
                _ => 0,
            };
            let take = (keys.len() - from).min(room);
            tasks.extend(keys[from..from + take].iter().map(|k| (*i, k.as_str())));
            room -= take;
            if from + take < keys.len() {
                part = Some((*i, from + take));
                finished = *i;
                break;
            }
        }
        budget.copies += tasks.len();
        let looked: Vec<(usize, Plan)> = stream::iter(tasks)
            .map(|(i, key)| async move { (i, self.plan(key).await) })
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        let mut held: BTreeSet<usize> = BTreeSet::new();
        let (asked, mut down) = (looked.len(), 0);
        for (i, plan) in looked {
            match plan {
                Plan::There => continue,
                Plan::Sent => {
                    counts.copied += 1;
                    continue;
                }
                Plan::Absent => {}
                Plan::Unreadable => counts.source_unreadable += 1,
                Plan::Failed => counts.failed += 1,
                Plan::Down => {
                    counts.failed += 1;
                    down += 1;
                }
                Plan::Refused => counts.refused += 1,
            }
            held.insert(i);
        }
        outage |= all_down(asked, down);
        if let Some((i, plans)) = part {
            if held.contains(&i) {
                // Held back already: finished for this pass.
                finished = i + 1;
            } else {
                place.generation = chunk[i].entry.key.clone();
                place.plans = plans as u32;
            }
        }

        // The records whose plans are all over there.
        for i in &held {
            result[*i] = Some(Copied::Held);
        }
        let ready = generations
            .iter()
            .filter(|(i, _)| **i < finished && !held.contains(*i))
            .map(|(i, (bytes, _))| (*i, bytes));
        let sent: Vec<(usize, Copied)> = stream::iter(ready)
            .map(|(i, bytes)| async move { (i, self.send(&chunk[i].entry.key, bytes).await) })
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        let (asked, mut down) = (sent.len(), 0);
        for (i, copied) in sent {
            down += usize::from(copied == Copied::Down);
            result[i] = Some(copied);
        }
        outage |= all_down(asked, down);

        for (item, copied) in chunk.iter().zip(result).take(finished) {
            let copied = match item.what {
                What::Young => {
                    counts.young += 1;
                    None
                }
                What::Same => Some(Copied::Same),
                What::Copy(_) => copied,
            };
            match copied {
                // Removed since it was listed: not a record any more.
                Some(Copied::Gone) => continue,
                Some(Copied::Done) => counts.copied += 1,
                Some(Copied::Same) => counts.same += 1,
                Some(Copied::Unreadable) => counts.source_unreadable += 1,
                Some(Copied::Failed | Copied::Down) => counts.failed += 1,
                Some(Copied::Refused) => counts.refused += 1,
                Some(Copied::Held) => counts.pending += 1,
                None => {}
            }
            counts.records += 1;
            counts.bytes += item.entry.size;
        }
        Chunk { finished, outage }
    }

    /// What the store holds after `after`, at least up to and including
    /// `upto` (`None` = to the end), from at most [`LIST_PAGES`]
    /// requests. The last answer may reach past `upto`; the caller
    /// counts only what lies before its cursor.
    async fn listed(
        &self,
        after: &str,
        upto: Option<&String>,
    ) -> std::result::Result<Range, StepError> {
        let mut range = Range::default();
        let mut after = after.to_string();
        for pages in 1..=LIST_PAGES {
            let page = self
                .remote
                .list(self.clock, RECORD_PREFIX, &after)
                .await
                .map_err(StepError::Store)?;
            let Some(last) = page.last else {
                break;
            };
            range.copies.extend(page.objects);
            range.foreign.extend(page.foreign);
            if !page.truncated || upto.is_some_and(|u| last.as_str() >= u.as_str()) {
                break;
            }
            if pages == LIST_PAGES {
                range.cut = upto.map(|_| last);
                return Ok(range);
            }
            after = last;
        }
        Ok(range)
    }

    /// Reads a fresh generation record that is to be copied.
    async fn read_generation(&self, key: &str, copy: Option<&Listed>) -> Read {
        let bytes = match self.safety.get(key, None).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Read::Is(Copied::Gone),
            Err(_) => return Read::Is(Copied::Failed),
        };
        let Ok(plain) = open_manifest(self.kek, key, &bytes) else {
            return Read::Is(Copied::Unreadable);
        };
        if equal(copy, bytes.len() as u64, &md5_hex(&bytes)) {
            return Read::Is(Copied::Same);
        }
        // Without the extents it names, its plans cannot be sent first.
        match plan_keys(&plain) {
            Some(plans) => Read::Generation { bytes, plans },
            None => Read::Is(Copied::Unreadable),
        }
    }

    /// Makes the article plan at `key` equal over there.
    async fn plan(&self, key: &str) -> Plan {
        let bytes = match self.safety.get(key, None).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Plan::Absent,
            Err(_) => return Plan::Failed,
        };
        if open_manifest(self.kek, key, &bytes).is_err() {
            return Plan::Unreadable;
        }
        match self.remote.head(self.clock, key).await {
            Ok(copy) if equal(copy.as_ref(), bytes.len() as u64, &md5_hex(&bytes)) => {
                return Plan::There
            }
            Ok(_) => {}
            Err(RemoteError::Refused(_) | RemoteError::Unsignable) => return Plan::Refused,
            Err(RemoteError::Unavailable) => return Plan::Down,
            Err(_) => return Plan::Failed,
        }
        match self.send(key, &bytes).await {
            Copied::Done => Plan::Sent,
            Copied::Refused => Plan::Refused,
            Copied::Down => Plan::Down,
            _ => Plan::Failed,
        }
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
        if equal(copy, bytes.len() as u64, &md5_hex(&bytes)) {
            return Copied::Same;
        }
        self.send(key, &bytes).await
    }

    async fn send(&self, key: &str, bytes: &[u8]) -> Copied {
        match self.remote.put(self.clock, key, bytes).await {
            Ok(()) => Copied::Done,
            Err(RemoteError::Refused(_) | RemoteError::Unsignable) => Copied::Refused,
            Err(RemoteError::Unavailable) => Copied::Down,
            Err(_) => Copied::Failed,
        }
    }
}
