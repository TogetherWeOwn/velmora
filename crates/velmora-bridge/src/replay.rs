//! Catalogue restore: replays the recovery records in `SAFETY` into the
//! catalogue (DESIGN §A.8). It runs only while `MAINTENANCE=restore`,
//! when no request and no job changes the catalogue.
//!
//! The catalogue after a replay is the fold of the records in id order:
//! the live generation of a key is its newest manifest, unless a newer
//! tombstone exists. Manifests go first, oldest first, then tombstones.
//! The records of both layouts ([`Layout`]) are read, as one list in id
//! order: where a record is stored says nothing about its place in it.
//! Every step is idempotent, so a replay can be repeated, resumed from
//! its cursor, or run over a catalogue that already holds some or all of
//! the records.
//!
//! One call does a bounded amount of work and returns a cursor, because a
//! Worker invocation has a subrequest limit. A generation with many
//! extents spans several calls; it is published by the call that
//! finishes its last extent.
//!
//! The time of a replay is the time of its reads of the store, so a
//! call asks the store ahead of its step and for several things at
//! once: the records it listed and what the store has of their
//! extents. Only the reads are moved. The step itself is unchanged: it
//! takes one record after the other in id order, writes the catalogue
//! in that order, and decides on an answer the store gave in the same
//! call. A read that failed ahead is made again by the step.
//!
//! A segmented record ([`GenerationHead`]) is replayed the same way,
//! with its extents read from its segments: a call reads the head and
//! the segment its cursor is in. Before the first extent of such a
//! record is restored, and again in the call that publishes it, every
//! segment is read, one at a time, and held to the head. A record with
//! a segment that is missing, does not open or is not the one its head
//! names is unreadable as a whole: its names are reported, and nothing
//! of it is published.
//!
//! What a replay cannot bring back: access keys and grants (re-issue them
//! through the admin API), uploads that were in progress, and an extent
//! with neither a pinned copy nor an article plan record. A generation
//! with such an extent is published all the same, so that a read of it
//! fails loudly instead of answering "no such key"; the last call of a
//! replay reports the live ones as `damaged`. The one exception: such a
//! generation is not published on a key that has an older generation,
//! live or deleted. It is the record of a write that was never
//! acknowledged far more often than the loss of an acknowledged one, so
//! the key stays as the older records leave it and the record is
//! reported as `damaged_unpublished`. Those entries carry the name of
//! the bucket and the object key beside the id; no other list does.

use std::collections::{HashMap, HashSet};
use std::pin::pin;
use std::sync::Mutex;

use futures_util::future::{self, Either};
use futures_util::stream::{self, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};

use crate::ports::{
    BlobEntry, BlobMeta, BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector,
    ReadAheadBlob,
};
use crate::recovery::{
    read_article_plan, read_segment, read_stored_generation, read_tombstone, record_name,
    start_after, ExtentRecord, GenerationHead, Layout, PlanRead, StoredGeneration, Unpublished,
    GENERATION_PREFIX, MAX_SEGMENTS, TOMBSTONE_PREFIX,
};
use crate::types::{
    ArticleRow, ArticleState, BridgeError, BucketId, ByteSpan, ExtentId, ExtentPlacement,
    ExtentRow, GenerationId, Result, UnixMs,
};

/// How much one call does. A record costs two blob reads (the record,
/// and, with read-ahead on, whether it is still there when the step
/// comes to it) and up to seven catalogue calls, an extent two blob reads (three when its
/// plan is looked for in a second layout) and a share of a catalogue
/// batch. With the default that is about 3,500 blob reads and 2,000
/// catalogue calls, a little over half of a Worker invocation's
/// subrequest limit (10,000). The most a call can come to is higher:
/// the extents asked ahead are no more than `extents`, but those of a
/// record the step then leaves out (it belongs to a bucket made again
/// under the same name) were asked for nothing, and the step asks for
/// as many again: up to 3,000 blob reads more with the default, which
/// is still below the limit.
#[derive(Clone, Copy, Debug)]
pub struct ReplayLimits {
    /// Records listed and finished at most.
    pub records: u32,
    /// Extents checked at most.
    pub extents: usize,
}

/// Extents a call asks the blob store about ahead at the same time.
/// An extent is two reads at once (its pinned copy and its article
/// plan), so that is twelve reads, beside the ones of the step itself.
/// A Worker invocation holds six connections open at most and queues
/// the rest, so more than that is not faster there.
pub const STORE_READS: usize = 6;

/// Where the pinned copies are stored: [`ExtentId::safety_key`].
const PINNED_PREFIX: &str = "x/";
/// Keys asked of one listing of the pinned copies, and listings a call
/// makes at most.
const HELD_PAGE: u32 = 1000;
const HELD_PAGES: u32 = 4;

/// Damaged generations the last call lists by id.
const DAMAGED_LISTED: u32 = 100;
const OTHER_BUCKET_LISTED: usize = 100;
const HELD_MISSING_LISTED: usize = 100;

impl Default for ReplayLimits {
    fn default() -> Self {
        ReplayLimits {
            records: 50,
            extents: 100,
        }
    }
}

/// Where a manifest's generation stands in the catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayProbe {
    Absent,
    /// The generation row exists: it was published in full.
    Present,
    /// Absent, and a newer generation of the key is live.
    Superseded,
}

/// What the catalogue did with a manifest's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayPublish {
    Published,
    /// Already present, a newer generation of the key is live, or the
    /// extents do not tile it. Nothing was written.
    Refused,
    /// The catalogue knows an older generation of the key, and this one
    /// has an extent with neither a pinned copy nor an article plan.
    /// Nothing was written.
    Damaged,
}

/// One extent of a manifest with what the blob store says about it.
#[derive(Clone, Debug)]
pub struct ReplayExtent {
    pub row: ExtentRow,
    /// The article plan record, if there is one.
    pub plan: Option<Vec<ArticleRow>>,
    /// `plan` in its packed form ([`crate::plan`]), when the catalogue
    /// is to hold it that way: it is then stored on the extent's row,
    /// and no article row is written.
    pub packed: Option<Vec<u8>>,
    /// The parity addendum of the plan record, as the record holds it.
    /// It goes on the extent's row only with `packed`, and only when it
    /// is an addendum of that plan ([`crate::parity::expand`]): any
    /// other is left out, and the extent has no parity.
    pub parity: Option<Vec<u8>>,
    /// Whether the pinned copy exists.
    pub safety_present: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplayPhase {
    Manifests,
    Tombstones,
    /// Extents the catalogue says are pinned, checked against the store.
    Held,
}

/// Resume point of a replay. Opaque to the caller: send back what the
/// last call returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCursor {
    /// Records minted at or after this time are replayed.
    pub since_ms: i64,
    pub phase: ReplayPhase,
    /// The last finished record: its blob key in the flat layout,
    /// whichever layout it is stored in. The place is one id, and the
    /// records of every layout after that id are still to come.
    pub after: String,
    /// Extents already handled of the record after `after`.
    pub extent: u32,
    /// The name the record `extent` counts in is stored under: a record
    /// of one id may be stored under a name of each layout, and the
    /// count is of the one that was read. Empty between two records,
    /// and in a cursor of a build from before segmented records, whose
    /// count is of a record in one part under the first name of its id.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The replay this cursor belongs to, as the restore route recorded
    /// it when the replay started. Only that replay is ended by it.
    #[serde(default)]
    pub run_ms: i64,
}

/// A place in a replay, in the order the replay goes through the
/// records: the phase, then the blob key, then the extent.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReplayMark {
    /// 0 = manifests, 1 = tombstones, 2 = held extents.
    pub phase: u8,
    pub after: String,
    pub extent: u32,
}

/// What the catalogue holds of a replay that was started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreProgress {
    /// Records minted at or after this time are replayed.
    pub since: UnixMs,
    /// Where the next step starts. `None` = no step has finished.
    pub reached: Option<ReplayMark>,
    /// The replay has ended: the catalogue no longer refuses writes or
    /// orphan claims for it.
    pub ended: bool,
}

impl ReplayCursor {
    /// The place this cursor starts a step from.
    pub fn mark(&self) -> ReplayMark {
        ReplayMark {
            phase: match self.phase {
                ReplayPhase::Manifests => 0,
                ReplayPhase::Tombstones => 1,
                ReplayPhase::Held => 2,
            },
            after: self.after.clone(),
            extent: self.extent,
        }
    }

    /// Whether a replay that has come as far as `progress` may take a
    /// step from this cursor: it is of the same restore point and not
    /// ahead of it. A cursor that is behind repeats what was done, which
    /// changes nothing; one that is ahead would leave records out.
    pub fn follows(&self, progress: &RestoreProgress) -> bool {
        let reached = match &progress.reached {
            Some(mark) => mark.clone(),
            None => ReplayCursor::start(progress.since).mark(),
        };
        self.since_ms == progress.since.0 && self.mark() <= reached
    }

    /// A replay of every record minted at or after `since`.
    pub fn start(since: UnixMs) -> Self {
        ReplayCursor {
            since_ms: since.0,
            phase: ReplayPhase::Manifests,
            after: start_after(GENERATION_PREFIX, since),
            extent: 0,
            name: String::new(),
            run_ms: 0,
        }
    }
}

/// A record that was not published, with where it belongs: the id alone
/// does not tell the operator which object to look at.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RecordRef {
    pub id: String,
    /// The name of the record's bucket.
    pub bucket: String,
    pub key: String,
}

/// What one call did. Lists hold generation ids or blob keys, never
/// object keys; `damaged_unpublished` is the exception.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ReplayReport {
    /// Generation manifests finished.
    pub manifests: u32,
    /// Published by this call.
    pub published: u32,
    /// Already in the catalogue.
    pub present: u32,
    /// Not published: a newer generation of the key is live.
    pub superseded: u32,
    /// Extents checked.
    pub extents: u32,
    /// Extents that have an article plan record.
    pub article_plans: u32,
    /// Extents whose pinned copy is gone.
    pub safety_missing: u32,
    pub tombstones: u32,
    /// Tombstones that removed a live object.
    pub deleted: u32,
    /// Refused, and nothing is missing: a newer live generation of the
    /// key holds the same extents in the same order. A Complete that
    /// was sent again after an unanswered one leaves two records of one
    /// object. Replayed together they are published one over the other,
    /// and the object stands under the id of the later one.
    pub duplicate: u32,
    /// Not published: the catalogue refused the generation (an extent
    /// is missing, its key was shredded or it belongs to another
    /// generation, or it lost a race).
    pub unpublishable: Vec<String>,
    /// Not published: an extent of the generation has no copy anywhere,
    /// and the key has an older generation. The key stays as the older
    /// records leave it. Listed with bucket and key: the operator has
    /// to decide about that one object.
    pub damaged_unpublished: Vec<RecordRef>,
    /// Not replayed: the catalogue has another bucket under the name of
    /// the record's bucket. The first ids of `other_bucket_total`.
    pub other_bucket_total: u32,
    pub other_bucket: Vec<String>,
    /// Extents whose row says the pinned copy is held, checked.
    pub held_checked: u32,
    /// Of those, the ones whose pinned copy is gone: the catalogue is
    /// older than their release, and this replay did not reach their
    /// records. A replay from 0 repairs them. `held_missing` holds the
    /// first extent ids of each call.
    pub held_missing_total: u32,
    pub held_missing: Vec<String>,
    /// Set by the last call: live generations with an extent that has no
    /// copy anywhere. `damaged` holds the first ids of `damaged_total`.
    pub damaged_total: u64,
    pub damaged: Vec<String>,
    /// The same id is stored under the names of both layouts: the blob
    /// keys of the tenant layout of such ids. The flat name is replayed,
    /// and the other one only when the flat name gives no record (it
    /// does not open, or is gone). A write stores its record once, so
    /// this is the trace of a record that was put there by hand.
    pub twins: Vec<String>,
    /// Records that did not open or parse (blob keys). Also the name
    /// of the plan record of an extent whose packed plan in the
    /// catalogue cannot be read and stays so, because the record has no
    /// plan to put in its place (whether or not the record exists).
    /// Such an extent is not counted in `damaged`; a generation it
    /// keeps from its key is listed in `damaged_unpublished`.
    pub unreadable: Vec<String>,
    /// `None` = the replay is complete.
    pub next: Option<ReplayCursor>,
}

impl<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>
    Bridge<C, B, N, J, K, T>
{
    /// One bounded step of a replay. A blob store or catalogue failure
    /// is an error and changes nothing that the same cursor would not
    /// redo.
    pub async fn replay_step(&self, cursor: ReplayCursor) -> Result<ReplayReport> {
        let limits = if self.cfg.replay_read_ahead {
            ReplayLimits {
                records: 250,
                extents: 1_000,
            }
        } else {
            ReplayLimits::default()
        };
        self.replay_step_within(cursor, limits).await
    }

    /// [`Self::replay_step`] with explicit limits (both at least 1).
    pub async fn replay_step_within(
        &self,
        cursor: ReplayCursor,
        limits: ReplayLimits,
    ) -> Result<ReplayReport> {
        let limits = ReplayLimits {
            records: limits.records.max(1),
            extents: limits.extents.max(1),
        };
        let mut report = ReplayReport::default();
        let next = match cursor.phase {
            ReplayPhase::Manifests => self.replay_manifests(cursor, limits, &mut report).await?,
            ReplayPhase::Tombstones => self.replay_tombstones(cursor, limits, &mut report).await?,
            ReplayPhase::Held => self.replay_held(cursor, limits, &mut report).await?,
        };
        report.next = next;
        Ok(report)
    }

    async fn replay_manifests(
        &self,
        mut cursor: ReplayCursor,
        limits: ReplayLimits,
        report: &mut ReplayReport,
    ) -> Result<Option<ReplayCursor>> {
        let names = self
            .listed(GENERATION_PREFIX, &cursor.after, limits.records, report)
            .await?;
        // From here on the store is asked through `store`: what the
        // records below need of it is asked ahead, several at a time,
        // one run of records while the run before it is written to the
        // catalogue. The catalogue is written by one record after the
        // other, in the order of their ids, as before: only the store
        // is asked ahead, and it is only read.
        let store = &Ahead::new(&self.safety);
        let mut call = Call {
            budget: limits.extents,
            reads: 0,
            buckets: HashMap::new(),
        };
        let more = if self.cfg.replay_read_ahead {
            self.replay_runs_ahead(store, &names, &mut cursor, &mut call, report)
                .await?
        } else {
            self.replay_run(store, &names, &mut cursor, &mut call, report)
                .await?
        };
        if more || names.len() as u64 == u64::from(limits.records) {
            return Ok(Some(cursor));
        }
        Ok(Some(ReplayCursor {
            phase: ReplayPhase::Tombstones,
            after: start_after(TOMBSTONE_PREFIX, UnixMs(cursor.since_ms)),
            // A count in a record that is not listed any more is of nothing.
            extent: 0,
            name: String::new(),
            ..cursor
        }))
    }

    async fn replay_runs_ahead(
        &self,
        store: &Ahead<'_, B>,
        names: &[Listed],
        cursor: &mut ReplayCursor,
        call: &mut Call,
        report: &mut ReplayReport,
    ) -> Result<bool> {
        // Extents asked ahead so far: no more than the call can handle.
        let extents = call.budget;
        let mut asked = self
            .ahead_manifests(
                store,
                names.get(..AHEAD_RECORDS.min(names.len())).unwrap_or(&[]),
                Some(cursor),
                extents,
            )
            .await;
        for (run, next) in names
            .chunks(AHEAD_RECORDS)
            .zip(names.chunks(AHEAD_RECORDS).skip(1).map(Some).chain([None]))
        {
            let left = extents.saturating_sub(asked);
            let (more, ahead) = {
                let step = pin!(self.replay_run(store, run, cursor, call, report));
                let ahead = pin!(async move {
                    match next {
                        Some(next) if left > 0 => {
                            self.ahead_manifests(store, next, None, left).await
                        }
                        _ => 0,
                    }
                });
                // The run that is asked ahead is waited for when this
                // one is done and the call goes on; a call that ends
                // here does not wait for it.
                match future::select(step, ahead).await {
                    Either::Left((more, ahead)) => {
                        let more = more?;
                        (more, if more { 0 } else { ahead.await })
                    }
                    Either::Right((ahead, step)) => (step.await?, ahead),
                }
            };
            asked += ahead;
            if more {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The step for the records of `run`, one after the other. `true` =
    /// the call is out of extents or of segment reads inside a record;
    /// the cursor says where the next one goes on.
    async fn replay_run(
        &self,
        store: &Ahead<'_, B>,
        run: &[Listed],
        cursor: &mut ReplayCursor,
        call: &mut Call,
        report: &mut ReplayReport,
    ) -> Result<bool> {
        for listed in run {
            let flat = &listed.flat;
            // The name the cursor counts extents in: the one it holds,
            // or, when it holds none (a cursor of an older build, which
            // counted in records in one part only), the first name of
            // the id. A count made in one name is never used in
            // another, and the names before it were given up and are
            // not read again. A count without a name cannot be told
            // from one made in a record that is gone since; every
            // cursor this build makes inside a record names it.
            let named = std::mem::take(&mut cursor.name);
            let mut skip = listed.names().any(|(name, _)| *name == named);
            let owner = if named.is_empty() {
                listed.name.clone()
            } else {
                named.clone()
            };
            // The first name of the id that can be read: a name that
            // cannot must not hide a record of the same id that can.
            for (name, layout) in listed.names() {
                if skip && *name != owner {
                    continue;
                }
                skip = false;
                // Another name than the one the count was made in, be
                // it that the record of that name is gone, or that it
                // does not open any more: this one starts at its first
                // extent.
                if *name != owner {
                    cursor.extent = 0;
                }
                let record = match read_stored_generation(store, &self.kek, name).await {
                    Ok(Some(record)) => record,
                    // Removed by an operator since the listing.
                    Ok(None) => continue,
                    Err(BridgeError::Blob(e)) => return Err(BridgeError::Blob(e)),
                    Err(_) => {
                        report.unreadable.push(name.clone());
                        continue;
                    }
                };
                let segmented = matches!(record, StoredGeneration::Segmented(_));
                // A count the cursor did not name was made in a record
                // in one part.
                if segmented && named.is_empty() {
                    cursor.extent = 0;
                }
                // The cursor names the record it is in, so that the
                // count is not used in another when this one is gone
                // by the next call.
                cursor.name.clone_from(name);
                match self
                    .replay_manifest(store, &record, layout, cursor, call, report)
                    .await?
                {
                    Replayed::Done => {
                        report.manifests += 1;
                        break;
                    }
                    // Out of budget inside this record.
                    Replayed::More => return Ok(true),
                    // As a record that was removed before it was read.
                    Replayed::Gone => {
                        cursor.extent = 0;
                        cursor.name.clear();
                    }
                    Replayed::Unreadable(segment) => {
                        for unread in [segment, name.clone()] {
                            if !report.unreadable.contains(&unread) {
                                report.unreadable.push(unread);
                            }
                        }
                        // The record under the other name starts at its
                        // first extent, whatever was read of this one.
                        cursor.extent = 0;
                        cursor.name.clear();
                    }
                }
            }
            *cursor = finished(cursor.clone(), flat);
        }
        Ok(false)
    }

    /// Asks the store ahead for what the step needs of `names`: the
    /// record under the first name of each id, and, of the records in
    /// one part, the pinned copy and the article plan of the extents
    /// this call can come to, several at a time. Nothing is decided
    /// here and nothing is reported. The step then reads the same
    /// names through `store`, in the order of the records, with the
    /// code that reads them from the store itself; whatever was not
    /// asked ahead, or could not be, is asked then. `cursor` = the
    /// cursor of the call, when `names` are its first records. Returns
    /// the number of extents asked about.
    async fn ahead_manifests(
        &self,
        store: &Ahead<'_, B>,
        names: &[Listed],
        cursor: Option<&ReplayCursor>,
        extents: usize,
    ) -> usize {
        let keep = &store.keeping();
        // The extents of each record in one part, in the order of the
        // records, until no more is kept. A record that does not open
        // here does not open in the step either, which reports it.
        let records: Vec<Vec<ExtentId>> = stream::iter(names.iter().map(|listed| async move {
            let record = read_stored_generation(keep, &self.kek, &listed.name).await;
            let Ok(Some(StoredGeneration::Single(m))) = record else {
                return Vec::new();
            };
            // The step asks nothing about the extents of a record that
            // a newer one of the object is over. The catalogue is only
            // read here; the step asks it again and decides.
            let superseded = match m.generation() {
                Ok(generation) => matches!(
                    self.catalog.replay_probe(&generation).await,
                    Ok(ReplayProbe::Superseded)
                ),
                Err(_) => true,
            };
            if superseded {
                return Vec::new();
            }
            m.extents
                .iter()
                .map(|e| ExtentId::new(e.id.clone()))
                .collect()
        }))
        .buffered(STORE_READS)
        .take_while(|_| std::future::ready(!store.full()))
        .collect()
        .await;
        // The step takes up the first record at the extent of its
        // cursor, when the count is of that name.
        let skip = match (cursor, names.first()) {
            (Some(cursor), Some(first)) if cursor.name.is_empty() || cursor.name == first.name => {
                cursor.extent as usize
            }
            _ => 0,
        };
        let wanted = names
            .iter()
            .zip(&records)
            .enumerate()
            .flat_map(|(at, (listed, ids))| {
                let skip = if at == 0 { skip } else { 0 };
                ids.iter().skip(skip).map(move |id| (id, &listed.layout))
            })
            .take(extents);
        stream::iter(wanted.map(|(id, layout)| self.probe_replay_extent(keep, id, layout)))
            .buffered(STORE_READS)
            .take_while(|_| std::future::ready(!store.full()))
            .count()
            .await
    }

    /// Reads every segment of `head`, one at a time, and holds each to
    /// the head. `Ok(Err(name))` = the segment stored at `name` is
    /// missing or is not the one the head names: the record is
    /// unreadable. `Ok(Ok(placements))` = where the generation has each
    /// of its extents, when `placed`; empty otherwise.
    async fn read_segments(
        &self,
        store: &Ahead<'_, B>,
        head: &GenerationHead,
        layout: &Layout,
        placed: bool,
    ) -> Result<std::result::Result<Vec<ExtentPlacement>, String>> {
        let mut placements = Vec::new();
        for index in 0..head.segments.len() {
            match read_segment(store, &self.kek, layout, head, index).await {
                Ok(extents) if placed => {
                    // Room for what the head counts, once a segment of
                    // it is what the head says.
                    if index == 0 {
                        placements.reserve_exact(head.extent_count() as usize);
                    }
                    placements.extend(extents.iter().map(placement));
                }
                Ok(_) => {}
                Err(BridgeError::Blob(e)) => return Err(BridgeError::Blob(e)),
                Err(_) => return Ok(Err(head.segment_key(layout, index))),
            }
        }
        Ok(Ok(placements))
    }

    /// What the store has of one extent: whether its pinned copy is
    /// there, and its article plan record. When read-ahead is enabled,
    /// the two are asked at once.
    async fn probe_replay_extent<S: BlobStore>(
        &self,
        store: &S,
        extent: &ExtentId,
        layout: &Layout,
    ) -> Result<(bool, PlanRead)> {
        let key = extent.safety_key();
        if !self.cfg.replay_read_ahead {
            let pinned = store.head(&key).await?.is_some();
            let plan = read_article_plan(store, &self.kek, extent, layout).await?;
            return Ok((pinned, plan));
        }
        let (pinned, plan) = future::try_join(
            store.head(&key),
            read_article_plan(store, &self.kek, extent, layout),
        )
        .await?;
        Ok((pinned.is_some(), plan))
    }

    async fn replay_manifest(
        &self,
        store: &Ahead<'_, B>,
        record: &StoredGeneration,
        // The layout the record is stored in: where its segments are,
        // and where the article plans of its extents are looked for
        // first.
        layout: &Layout,
        cursor: &mut ReplayCursor,
        call: &mut Call,
        report: &mut ReplayReport,
    ) -> Result<Replayed> {
        let Call {
            budget,
            reads,
            buckets,
        } = call;
        let (generation, bucket) = match record {
            StoredGeneration::Single(m) => (m.generation()?, m.bucket()),
            StoredGeneration::Segmented(head) => (head.generation(), head.bucket()),
        };
        // With read-ahead on, the record was read at the start of its
        // run, some time before the step comes to it, and a write that
        // was under way when the restore began removes its record when
        // the catalogue refuses it. So at the record's turn the store
        // itself, never what was read ahead, is asked whether it still
        // has the record, at the same time as the catalogue is asked
        // about it. Off, the record was read just now, as on main.
        let (probe, there) = if self.cfg.replay_read_ahead {
            let (probe, there) = future::try_join(
                self.catalog.replay_probe(&generation),
                self.safety.head(&cursor.name),
            )
            .await?;
            (probe, Some(there.is_some()))
        } else {
            (self.catalog.replay_probe(&generation).await?, None)
        };
        if probe == ReplayProbe::Superseded {
            report.superseded += 1;
            return Ok(Replayed::Done);
        }
        // A bucket made again under the same name since the export has
        // another id and another data key. Nothing of the record can go
        // into it, and its rows cannot go in beside it: the name is
        // unique. The operator decides which of the two stays.
        // The id a name was found under is the one it has for the rest
        // of the call: nothing but this replay writes, and it adds no
        // bucket under a name that has one. A name that was not found
        // is asked for again: the record's own bucket goes in with its
        // first extent.
        let named = match buckets.get(&bucket.name) {
            Some(id) => Some(id.clone()),
            None => {
                let named = self.catalog.bucket_by_name(&bucket.name).await?;
                let id = named.map(|b| b.id);
                if self.cfg.replay_read_ahead {
                    if let Some(id) = &id {
                        buckets.insert(bucket.name.clone(), id.clone());
                    }
                }
                id
            }
        };
        if let Some(named) = named {
            if named != bucket.id {
                report.other_bucket_total += 1;
                if report.other_bucket.len() < OTHER_BUCKET_LISTED {
                    report.other_bucket.push(generation.id.as_str().to_owned());
                }
                return Ok(Replayed::Done);
            }
        }
        // A record the store no longer had at its turn leaves nothing
        // behind: no row of it is written. This does not fence the
        // removal of a refused record after that answer; main has the
        // same window after its record GET.
        if probe != ReplayProbe::Present && there == Some(false) {
            return Ok(Replayed::Gone);
        }
        let now = self.clock.now();
        let total = generation.extent_count as usize;
        let mut at = cursor.extent as usize;
        if let StoredGeneration::Segmented(head) = record {
            // Before the first row of the record is written: a record
            // that cannot be read when the replay comes to it leaves
            // nothing behind. (One that loses a segment after that
            // leaves extent rows of no generation. Nothing reads them
            // and no sweep removes them; a replay of the record, once
            // it reads again, writes the same rows.)
            if at == 0 {
                if *budget == 0 || !fits(reads, head.segments.len()) {
                    return Ok(Replayed::More);
                }
                if let Err(segment) = self.read_segments(store, head, layout, false).await? {
                    return Ok(Replayed::Unreadable(segment));
                }
            }
        }
        // The segment the cursor is in: its index and its extents.
        let mut held: Option<(usize, Vec<ExtentRecord>)> = None;
        while at < total {
            if *budget == 0 {
                return Ok(Replayed::More);
            }
            // The run of extents the cursor is in, and the `seq` of its
            // first: the whole record, or one segment of it.
            let (first, run): (usize, &[ExtentRecord]) = match record {
                StoredGeneration::Single(m) => (0, &m.extents),
                StoredGeneration::Segmented(head) => {
                    let seq = u32::try_from(at).unwrap_or(u32::MAX);
                    let Some(index) = head.segment_of(seq) else {
                        return Err(BridgeError::Invalid("recovery record is malformed"));
                    };
                    if held.as_ref().is_none_or(|(i, _)| *i != index) {
                        drop(held.take());
                        // The cursor is at the first extent of a
                        // segment: the next call reads it.
                        if !fits(reads, 1) {
                            return Ok(Replayed::More);
                        }
                        match read_segment(store, &self.kek, layout, head, index).await {
                            Ok(extents) => held = Some((index, extents)),
                            Err(BridgeError::Blob(e)) => return Err(BridgeError::Blob(e)),
                            Err(_) => {
                                return Ok(Replayed::Unreadable(head.segment_key(layout, index)))
                            }
                        }
                    }
                    let extents = held.as_ref().map_or(&[][..], |(_, e)| e);
                    (head.segments[index].seq as usize, extents)
                }
            };
            let end = total.min(at + *budget).min(first + run.len());
            // Take results in record order and stage the chunk only
            // after every answer. With read-ahead off, validate and
            // read each extent before starting the next one.
            let reads_at_once = if self.cfg.replay_read_ahead {
                STORE_READS
            } else {
                1
            };
            let mut probes = pin!(stream::iter((at..end).map(|index| async move {
                let row = match record {
                    StoredGeneration::Single(m) => m.extent(index),
                    StoredGeneration::Segmented(head) => head.extent(&run[index - first]),
                }?;
                let found = self.probe_replay_extent(store, &row.id, layout).await?;
                Ok::<_, BridgeError>((row, found))
            }))
            .buffered(reads_at_once));
            let mut chunk = Vec::with_capacity(end - at);
            while let Some((mut row, (safety_present, read))) = probes.try_next().await? {
                // A plan in an existing catalogue row is kept; this one
                // fills the gap when the row or its plan is missing.
                let state = if safety_present {
                    ArticleState::Planned
                } else {
                    ArticleState::Posted
                };
                // A plan record that does not open must not stop the
                // replay: it is reported and the extent is restored
                // without a plan. A store that cannot be reached still
                // fails the call, so that the caller retries.
                // The plan may be in the other layout than the record:
                // an extent is posted after its object is published,
                // and a copy names the extents of an older object.
                let mut unopened = read.unreadable;
                let record = read.record;
                let mut packed = None;
                let mut parity = None;
                let plan = match record {
                    Some(record) => match record.rows(state) {
                        Ok(rows) => {
                            row.plan_rev = record.plan_rev;
                            if self.cfg.packed_plans {
                                packed = crate::plan::repack(
                                    &row.id,
                                    row.cipher_size,
                                    &rows,
                                    record.packed.as_deref(),
                                );
                                parity = record.parity.filter(|_| packed.is_some());
                            }
                            Some(rows)
                        }
                        Err(_) => {
                            unopened.extend(read.name);
                            None
                        }
                    },
                    None => None,
                };
                for name in unopened {
                    if !report.unreadable.contains(&name) {
                        report.unreadable.push(name);
                    }
                }
                report.extents += 1;
                report.article_plans += u32::from(plan.is_some());
                report.safety_missing += u32::from(!safety_present);
                chunk.push(crate::replay::ReplayExtent {
                    row,
                    plan,
                    packed,
                    parity,
                    safety_present,
                });
            }
            // A plan in the catalogue that cannot be read and that no
            // record replaces is named like a record that does not
            // open: the extent cannot be read from Usenet.
            for extent in self.catalog.replay_extents(&bucket, &chunk, now).await? {
                let named = Layout::all().iter().any(|l| {
                    let name = l.article_key(&extent);
                    report.unreadable.contains(&name)
                });
                if !named {
                    report.unreadable.push(layout.article_key(&extent));
                }
            }
            *budget -= end - at;
            at = end;
            cursor.extent = u32::try_from(at).unwrap_or(u32::MAX);
        }
        let id = generation.id.as_str().to_owned();
        match probe {
            ReplayProbe::Present => report.present += 1,
            _ => {
                // The segment of the last extents is not held twice.
                drop(held);
                let placements: Vec<ExtentPlacement> = match record {
                    StoredGeneration::Single(m) => m.extents.iter().map(placement).collect(),
                    // Every segment again, whatever the calls before
                    // this one read: what is published is what the head
                    // names, all of it, as it is stored now.
                    StoredGeneration::Segmented(head) => {
                        if !fits(reads, head.segments.len()) {
                            return Ok(Replayed::More);
                        }
                        match self.read_segments(store, head, layout, true).await? {
                            Ok(placements) => placements,
                            Err(segment) => return Ok(Replayed::Unreadable(segment)),
                        }
                    }
                };
                match self
                    .catalog
                    .replay_publish(&generation, &placements, now)
                    .await?
                {
                    ReplayPublish::Published => report.published += 1,
                    ReplayPublish::Damaged => {
                        // Its id stays the floor of the key, as after a
                        // write that failed: whatever is acknowledged
                        // on the key from now on sorts after the record,
                        // also if its data is found again.
                        self.catalog
                            .raise_floor(
                                &generation.bucket_id,
                                &generation.key,
                                &generation.id,
                                true,
                            )
                            .await?;
                        report.damaged_unpublished.push(RecordRef {
                            id,
                            bucket: bucket.name.clone(),
                            key: generation.key.clone(),
                        });
                    }
                    // The extents of an object can be shared, so a second
                    // record of one object is published like any other
                    // manifest, over the first. What is refused and has a
                    // live twin was published before: by an earlier run,
                    // or because a newer record of the object is live.
                    ReplayPublish::Refused => {
                        match self.catalog.replay_twin(&generation, &placements).await? {
                            Some(_) => report.duplicate += 1,
                            None => report.unpublishable.push(id),
                        }
                    }
                }
            }
        }
        Ok(Replayed::Done)
    }

    async fn replay_tombstones(
        &self,
        mut cursor: ReplayCursor,
        limits: ReplayLimits,
        report: &mut ReplayReport,
    ) -> Result<Option<ReplayCursor>> {
        let names = self
            .listed(TOMBSTONE_PREFIX, &cursor.after, limits.records, report)
            .await?;
        let now = self.clock.now();
        let store = &Ahead::new(&self.safety);
        if self.cfg.replay_read_ahead {
            // The record under the first name of every id, asked ahead.
            let keep = &store.keeping();
            stream::iter(names.iter().map(|listed| keep.get(&listed.name, None)))
                .buffered(STORE_READS)
                .take_while(|_| std::future::ready(!store.full()))
                .for_each(|_| std::future::ready(()))
                .await;
        }
        for listed in &names {
            let flat = &listed.flat;
            // As for a generation: the first name of the id that opens.
            let mut opened = None;
            for (name, _) in listed.names() {
                match read_tombstone(store, &self.kek, name).await {
                    Ok(Some(t)) => {
                        opened = Some(t);
                        break;
                    }
                    Ok(None) => {}
                    Err(crate::types::BridgeError::Blob(e)) => {
                        return Err(crate::types::BridgeError::Blob(e))
                    }
                    Err(_) => report.unreadable.push(name.clone()),
                }
            }
            if let Some(t) = opened {
                let (bucket, id) = (BucketId::new(t.bucket_id), GenerationId::new(t.id));
                // The floor is raised also when nothing is deleted
                // here: a write after the replay sorts after every
                // tombstone on record.
                let deleted = self
                    .catalog
                    .replay_tombstone(&bucket, &t.key, &id, now)
                    .await?;
                report.tombstones += 1;
                report.deleted += u32::from(deleted);
            }
            cursor = finished(cursor, flat);
        }
        if names.len() as u64 == u64::from(limits.records) {
            return Ok(Some(cursor));
        }
        Ok(Some(ReplayCursor {
            phase: ReplayPhase::Held,
            after: String::new(),
            extent: 0,
            ..cursor
        }))
    }

    /// The next records of one kind after `after`, at most `limit`, from
    /// every layout, in the order of their ids. `prefix` and `after` are
    /// keys of the flat layout ([`GENERATION_PREFIX`] or
    /// [`TOMBSTONE_PREFIX`], and the place of the cursor).
    ///
    /// Each layout is listed from the same place, `limit` keys at most.
    /// The first `limit` of them all together are then the next ones:
    /// none of them sorts after the last key of a listing that was cut,
    /// so no record that was not listed lies before one that is
    /// answered. Fewer than `limit` = the records have ended.
    async fn listed(
        &self,
        prefix: &str,
        after: &str,
        limit: u32,
        report: &mut ReplayReport,
    ) -> Result<Vec<Listed>> {
        let mut all: Vec<Listed> = Vec::new();
        for layout in Layout::all() {
            let names = self
                .safety
                .list(&layout.of_flat(prefix), &layout.of_flat(after), limit)
                .await?;
            for name in names {
                // A key under the prefix that is no record name (it
                // has a `/` after the id) is read where it is, and
                // reported as what does not open.
                let flat = match record_name(&name) {
                    Some(parsed) => parsed.flat(),
                    None => format!(
                        "{}{}",
                        crate::recovery::RECORD_PREFIX,
                        &name[layout.root().len().min(name.len())..]
                    ),
                };
                all.push(Listed {
                    name,
                    flat,
                    layout: layout.clone(),
                    twin: None,
                });
            }
        }
        // Stable: of two names of one id, the flat one stays first.
        all.sort_by(|a, b| a.flat.cmp(&b.flat));
        let mut next: Vec<Listed> = Vec::new();
        for record in all {
            let full = next.len() as u64 == u64::from(limit);
            match next.last_mut() {
                Some(last) if last.flat == record.flat => {
                    report.twins.push(record.name.clone());
                    last.twin = Some((record.name, record.layout));
                }
                _ if full => break,
                _ => next.push(record),
            }
        }
        Ok(next)
    }

    /// A replay from a restore point does not read the records of older
    /// extents. If the catalogue is older than the release of one of
    /// them, its row still says `held` while the pinned copy is gone,
    /// and the pipeline would wait for a copy that never comes. This
    /// finds them; it changes nothing.
    async fn replay_held(
        &self,
        mut cursor: ReplayCursor,
        limits: ReplayLimits,
        report: &mut ReplayReport,
    ) -> Result<Option<ReplayCursor>> {
        let limit = u32::try_from(limits.extents).unwrap_or(u32::MAX);
        let ids = self.catalog.held_extents(&cursor.after, limit).await?;
        // The pinned copies are listed over the span of the ids, in the
        // order of both: one call of the store for a thousand of them.
        // A copy the listing names is there. One it does not name is
        // asked for by its own key: only that answer says it is
        // missing, as before. So a listing that ends early, because
        // copies of extents the catalogue does not hold lie in between,
        // costs time and changes nothing.
        let mut listed: HashSet<String> = HashSet::new();
        if let Some(last) = ids
            .last()
            .filter(|_| self.cfg.replay_read_ahead)
            .map(ExtentId::safety_key)
        {
            let mut at = ExtentId::new(cursor.after.clone()).safety_key();
            for _ in 0..HELD_PAGES {
                // Listing is only an optimization. If it fails, keep
                // prior pages and ask the uncovered keys individually.
                let Ok(keys) = self.safety.list(PINNED_PREFIX, &at, HELD_PAGE).await else {
                    break;
                };
                let end = (keys.len() as u64) < u64::from(HELD_PAGE);
                if let Some(key) = keys.last() {
                    at.clone_from(key);
                }
                listed.extend(keys);
                if end || at >= last {
                    break;
                }
            }
        }
        let listed = &listed;
        // Several at a time when enabled, taken in the order of the ids.
        let reads_at_once = if self.cfg.replay_read_ahead {
            STORE_READS
        } else {
            1
        };
        let present: Vec<bool> = stream::iter(ids.iter().map(|id| async move {
            let key = id.safety_key();
            Ok::<_, BridgeError>(listed.contains(&key) || self.safety.head(&key).await?.is_some())
        }))
        .buffered(reads_at_once)
        .try_collect()
        .await?;
        for (id, present) in ids.iter().zip(present) {
            report.held_checked += 1;
            if !present {
                report.held_missing_total += 1;
                if report.held_missing.len() < HELD_MISSING_LISTED {
                    report.held_missing.push(id.as_str().to_owned());
                }
            }
            cursor.after = id.as_str().to_owned();
        }
        if ids.len() as u64 == u64::from(limit) {
            return Ok(Some(cursor));
        }
        let (total, ids) = self.catalog.replay_damaged(DAMAGED_LISTED).await?;
        report.damaged_total = total;
        report.damaged = ids.iter().map(|id| id.as_str().to_owned()).collect();
        Ok(None)
    }
}

/// The most segments one call of a replay reads: twice the most a head
/// names. Each is one read of the blob store, and a call has a bounded
/// number of those.
///
/// This bounds a call, not a restore. Over the calls of a restore a
/// segment of an unpublished record is read three times (before the
/// first row, for its extents, and to publish), and once more for each
/// call that stops inside it, which the next call reads again.
pub const SEGMENT_READS: usize = 2 * MAX_SEGMENTS;

/// Whether a call that has read `reads` segments may read every segment
/// of a head that has `all` as well, and counts them if so. A call that
/// has read none may: no head has more than [`MAX_SEGMENTS`].
fn fits(reads: &mut usize, all: usize) -> bool {
    if *reads > 0 && *reads + all > SEGMENT_READS {
        return false;
    }
    *reads += all;
    true
}

/// Records in a run: what the store has for a run is asked while the
/// run before it is written to the catalogue.
const AHEAD_RECORDS: usize = 16;

/// What a call has left and what it has learned.
struct Call {
    /// Extents the call may still handle.
    budget: usize,
    /// Segments it has read.
    reads: usize,
    /// The id of each bucket name the catalogue was found to have.
    buckets: HashMap<String, BucketId>,
}

/// Aggregate budget for retained and in-flight speculative bodies.
/// Reserve against response metadata before reading bytes. A response
/// that will not fit is left for the ordered replay step.
const AHEAD_BYTES: usize = 8 * 1024 * 1024;

/// The blob store of one replay call, with the answers the call asked
/// for ahead of their use. What is read through [`Ahead::keeping`] is
/// kept: the answer to a `get` of a whole blob or to a `head`. What
/// the step reads through the store itself is answered from what is
/// kept, once, when the answer is there, and by the store otherwise.
/// So an answer the step works with is one the store gave earlier in
/// the same call. A call that failed is not kept: the step asks again
/// and fails as it would have. A replay only reads this store, and
/// nothing else writes to it while a restore runs; a write through
/// this one drops what is kept, and what was asked before it is not
/// kept after it.
struct Ahead<'a, B> {
    store: &'a B,
    kept: Mutex<Kept>,
}

/// The side of an [`Ahead`] that reads ahead: its answers are kept.
struct Keeping<'s, 'a, B>(&'s Ahead<'a, B>);

#[derive(Default)]
struct Kept {
    gets: HashMap<String, Option<Vec<u8>>>,
    heads: HashMap<String, Option<u64>>,
    /// The bytes of `gets`.
    bytes: usize,
    /// Bytes reserved for in-flight reads and their cache copies.
    reserved: usize,
    /// Counts the writes: an answer asked for before a write is not
    /// kept after it.
    writes: u64,
}

impl Kept {
    fn drop_get(&mut self, key: &str) -> Option<Option<Vec<u8>>> {
        let answer = self.gets.remove(key)?;
        self.bytes -= answer.as_ref().map_or(0, Vec::len);
        Some(answer)
    }

    fn written(&mut self) {
        *self = Kept {
            writes: self.writes + 1,
            reserved: self.reserved,
            ..Kept::default()
        };
    }
}

/// Release a reservation on error, completion, or cancellation of the
/// speculative future. No lock is held across the adapter's await.
struct Reservation<'a> {
    kept: &'a Mutex<Kept>,
    bytes: usize,
}

impl Reservation<'_> {
    fn claim(&mut self, size: u64) -> bool {
        // Reserve the body, its cached copy, and a byte for the R2 EOF
        // check. The caller uses the returned body before yielding again.
        let Some(bytes) = usize::try_from(size)
            .ok()
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(1))
        else {
            return false;
        };
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        if bytes > AHEAD_BYTES - (kept.bytes + kept.reserved) {
            return false;
        }
        kept.reserved += bytes;
        self.bytes = bytes;
        true
    }

    fn release(&mut self, kept: &mut Kept) {
        kept.reserved -= std::mem::take(&mut self.bytes);
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.bytes != 0 {
            let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
            self.release(&mut kept);
        }
    }
}

impl<'a, B: BlobStore> Ahead<'a, B> {
    fn new(store: &'a B) -> Self {
        Ahead {
            store,
            kept: Mutex::new(Kept::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Kept> {
        self.kept.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether as much is kept as a call may hold.
    fn full(&self) -> bool {
        let kept = self.lock();
        kept.bytes + kept.reserved >= AHEAD_BYTES
    }

    /// The store for what is read ahead.
    fn keeping(&self) -> Keeping<'_, 'a, B> {
        Keeping(self)
    }
}

impl<B: BlobStore> BlobStore for Ahead<'_, B> {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.lock().written();
        self.store.put(key, bytes, meta).await
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        if span.is_none() {
            if let Some(answer) = self.lock().drop_get(key) {
                return Ok(answer);
            }
        }
        self.store.get(key, span).await
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        let kept = self.lock().heads.remove(key);
        match kept {
            Some(answer) => Ok(answer),
            None => self.store.head(key).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.lock().written();
        self.store.delete(key).await
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.lock().written();
        self.store.delete_record(refused).await
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.store.list(prefix, start_after, limit).await
    }

    async fn list_entries(
        &self,
        prefix: &str,
        start_after: &str,
        limit: u32,
    ) -> Result<Vec<BlobEntry>> {
        self.store.list_entries(prefix, start_after, limit).await
    }
}

impl<B: BlobStore> BlobStore for Keeping<'_, '_, B> {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.0.put(key, bytes, meta).await
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        // Only whole objects are useful to the speculative reader.
        if span.is_some() {
            return Ok(None);
        }
        let writes = {
            let kept = self.0.lock();
            if let Some(answer) = kept.gets.get(key) {
                let size = answer.as_ref().map_or(0, Vec::len);
                return if size <= AHEAD_BYTES - (kept.bytes + kept.reserved) {
                    Ok(answer.clone())
                } else {
                    Ok(None)
                };
            }
            kept.writes
        };
        let mut reservation = Reservation {
            kept: &self.0.kept,
            bytes: 0,
        };
        let answer = match self
            .0
            .store
            .get_for_read_ahead(key, |size| reservation.claim(size))
            .await?
        {
            ReadAheadBlob::Missing => None,
            // Only a genuine miss belongs in the cache.
            ReadAheadBlob::Skipped => return Ok(None),
            ReadAheadBlob::Body(bytes) => Some(bytes),
        };
        let mut kept = self.0.lock();
        if kept.writes == writes && !kept.gets.contains_key(key) {
            kept.bytes += answer.as_ref().map_or(0, Vec::len);
            kept.gets.insert(key.to_owned(), answer.clone());
        }
        reservation.release(&mut kept);
        Ok(answer)
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        let writes = {
            let kept = self.0.lock();
            if let Some(answer) = kept.heads.get(key) {
                return Ok(*answer);
            }
            kept.writes
        };
        let answer = self.0.store.head(key).await?;
        let mut kept = self.0.lock();
        if kept.writes == writes {
            kept.heads.insert(key.to_owned(), answer);
        }
        Ok(answer)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.0.delete(key).await
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.0.store.list(prefix, start_after, limit).await
    }

    async fn list_entries(
        &self,
        prefix: &str,
        start_after: &str,
        limit: u32,
    ) -> Result<Vec<BlobEntry>> {
        self.0.store.list_entries(prefix, start_after, limit).await
    }
}

/// What a call made of one generation record.
enum Replayed {
    /// Nothing is left to do for it.
    Done,
    /// The call is out of extents or of segment reads; the cursor says
    /// where the next one goes on.
    More,
    /// It is segmented, and the segment stored at this name is missing
    /// or is not the one its head names. Nothing of it was published.
    Unreadable(String),
    /// The record was removed since it was read. No row of it was
    /// written in this call, and it was not published.
    Gone,
}

/// Where a generation has the extent of a record.
fn placement(e: &ExtentRecord) -> ExtentPlacement {
    ExtentPlacement {
        extent_id: crate::types::ExtentId::new(e.id.clone()),
        seq: e.seq,
        plain_offset: e.plain_offset,
    }
}

/// A record a replay step is to read.
struct Listed {
    /// Its blob key.
    name: String,
    /// The blob key of the same id in the flat layout: its place in
    /// the order, and what the cursor holds.
    flat: String,
    /// The layout it is stored in.
    layout: Layout,
    /// The name and layout of the same id in the other layout, when
    /// both are stored: read when the first name gives no record.
    twin: Option<(String, Layout)>,
}

impl Listed {
    /// The names the record is stored under, the one to read first.
    fn names(&self) -> impl Iterator<Item = (&String, &Layout)> {
        std::iter::once((&self.name, &self.layout))
            .chain(self.twin.as_ref().map(|(name, layout)| (name, layout)))
    }
}

/// The cursor after the record whose flat name is `flat` is done.
fn finished(cursor: ReplayCursor, flat: &str) -> ReplayCursor {
    ReplayCursor {
        after: flat.to_owned(),
        extent: 0,
        name: String::new(),
        ..cursor
    }
}

#[cfg(test)]
mod segment_reads {
    use super::*;

    /// A call reads no more than [`SEGMENT_READS`] segments, however
    /// they fall over the passes of a record or over several records;
    /// a call that has read none takes any head.
    #[test]
    fn a_call_reads_a_bounded_number_of_segments() {
        let mut reads = 0;
        assert!(fits(&mut reads, MAX_SEGMENTS));
        assert!(fits(&mut reads, MAX_SEGMENTS));
        assert_eq!(reads, SEGMENT_READS);
        assert!(!fits(&mut reads, 1));
        assert_eq!(reads, SEGMENT_READS);

        let mut reads = 1;
        assert!(!fits(&mut reads, SEGMENT_READS));
        assert!(fits(&mut reads, SEGMENT_READS - 1));

        // Whatever a head says, the first of a call is read.
        let mut reads = 0;
        assert!(fits(&mut reads, SEGMENT_READS + 1));
    }
}

#[cfg(test)]
mod ahead {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    /// A store that answers one turn of the executor later, and notes
    /// what it was asked and how many calls were under way at once.
    #[derive(Default)]
    struct Slow {
        blobs: RefCell<BTreeMap<String, Vec<u8>>>,
        asked: RefCell<Vec<String>>,
        flying: Cell<usize>,
        most: Cell<usize>,
        fail: Cell<bool>,
    }

    impl Slow {
        fn with(blobs: &[(&str, usize)]) -> Self {
            let slow = Slow::default();
            for (key, size) in blobs {
                slow.blobs
                    .borrow_mut()
                    .insert((*key).to_owned(), vec![7; *size]);
            }
            slow
        }

        async fn turn(&self, what: &str, key: &str) -> Result<()> {
            self.asked.borrow_mut().push(format!("{what} {key}"));
            self.flying.set(self.flying.get() + 1);
            self.most.set(self.most.get().max(self.flying.get()));
            tokio::task::yield_now().await;
            self.flying.set(self.flying.get() - 1);
            if self.fail.get() {
                return Err(BridgeError::Blob("down".into()));
            }
            Ok(())
        }

        fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }
    }

    impl BlobStore for Slow {
        async fn put(&self, key: &str, bytes: Vec<u8>, _: &BlobMeta<'_>) -> Result<()> {
            self.turn("put", key).await?;
            self.blobs.borrow_mut().insert(key.to_owned(), bytes);
            Ok(())
        }

        async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
            self.turn(if span.is_some() { "range" } else { "get" }, key)
                .await?;
            Ok(self.blobs.borrow().get(key).cloned())
        }

        async fn get_for_read_ahead(
            &self,
            key: &str,
            reserve: impl FnOnce(u64) -> bool,
        ) -> Result<ReadAheadBlob> {
            let size = self.blobs.borrow().get(key).map(Vec::len);
            let accepted = size.map(|n| reserve(n as u64));
            // Model a response whose metadata arrives before its body.
            self.turn("get", key).await?;
            Ok(match accepted {
                Some(true) => ReadAheadBlob::Body(self.blobs.borrow()[key].clone()),
                Some(false) => ReadAheadBlob::Skipped,
                None => ReadAheadBlob::Missing,
            })
        }

        async fn head(&self, key: &str) -> Result<Option<u64>> {
            self.turn("head", key).await?;
            Ok(self.blobs.borrow().get(key).map(|b| b.len() as u64))
        }

        async fn delete(&self, key: &str) -> Result<()> {
            self.turn("delete", key).await?;
            self.blobs.borrow_mut().remove(key);
            Ok(())
        }

        async fn delete_record(&self, _: &Unpublished) -> Result<()> {
            Ok(())
        }

        async fn list(&self, _: &str, _: &str, _: u32) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    /// An answer asked for ahead is the store's, is given to the step
    /// once, and the store is asked again after that.
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_kept_is_given_once() {
        let slow = Slow::with(&[("a", 3)]);
        let ahead = Ahead::new(&slow);
        let keep = ahead.keeping();
        assert_eq!(keep.get("a", None).await.unwrap(), Some(vec![7; 3]));
        assert_eq!(keep.get("none", None).await.unwrap(), None);
        assert_eq!(keep.head("a").await.unwrap(), Some(3));
        assert_eq!(keep.head("none").await.unwrap(), None);
        // Asked again ahead: not of the store.
        assert_eq!(keep.get("a", None).await.unwrap(), Some(vec![7; 3]));
        assert_eq!(keep.head("a").await.unwrap(), Some(3));
        let once = ["get a", "get none", "head a", "head none"];
        assert_eq!(slow.asked(), once);

        assert_eq!(ahead.get("a", None).await.unwrap(), Some(vec![7; 3]));
        assert_eq!(ahead.get("none", None).await.unwrap(), None);
        assert_eq!(ahead.head("a").await.unwrap(), Some(3));
        assert_eq!(ahead.head("none").await.unwrap(), None);
        assert_eq!(slow.asked(), once, "the step is answered from what is kept");
        assert_eq!(ahead.lock().bytes, 0);

        // Each answer was given once: the store is asked from here on,
        // and what it says to the step is not kept.
        slow.blobs.borrow_mut().remove("a");
        assert_eq!(ahead.get("a", None).await.unwrap(), None);
        assert_eq!(ahead.head("a").await.unwrap(), None);
        assert_eq!(ahead.get("a", None).await.unwrap(), None);
        assert_eq!(slow.asked().len(), once.len() + 3);
        assert!(ahead.lock().gets.is_empty() && ahead.lock().heads.is_empty());
    }

    /// A call the store failed is not an answer: the step asks again,
    /// and fails if the store still does.
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_call_is_not_kept() {
        let slow = Slow::with(&[("a", 3)]);
        let ahead = Ahead::new(&slow);
        let keep = ahead.keeping();
        slow.fail.set(true);
        assert!(matches!(
            keep.get("a", None).await,
            Err(BridgeError::Blob(_))
        ));
        assert!(matches!(keep.head("a").await, Err(BridgeError::Blob(_))));
        assert!(matches!(
            ahead.get("a", None).await,
            Err(BridgeError::Blob(_))
        ));
        assert!(matches!(ahead.head("a").await, Err(BridgeError::Blob(_))));
        slow.fail.set(false);
        assert_eq!(ahead.get("a", None).await.unwrap(), Some(vec![7; 3]));
        assert_eq!(ahead.head("a").await.unwrap(), Some(3));
        assert_eq!(slow.asked().len(), 6);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_damaged_48_mib_record_is_not_buffered_ahead() {
        let key = "m/g_0000018bcfe5680000000000000000ff";
        let size = 48 * 1024 * 1024;
        let slow = Slow::with(&[(key, size)]);
        let ahead = Ahead::new(&slow);
        let answer = ahead.keeping().get(key, None).await.unwrap();
        assert_eq!(
            answer.as_ref().map(Vec::len),
            None,
            "oversized speculative answer"
        );
        assert_eq!(ahead.lock().bytes, 0);
        // The authoritative step still sees the full damaged record.
        let read = read_stored_generation(&ahead, &crate::testkit::TestKek::new(), key).await;
        assert!(matches!(
            read,
            Err(BridgeError::Crypto(_)) | Err(BridgeError::Invalid(_))
        ));
    }

    /// No more is kept than a call may hold; a part of a blob is never
    /// kept; and a write through the wrapper voids what is kept, also
    /// what was asked for before it and answered after it.
    #[tokio::test(flavor = "current_thread")]
    async fn what_is_kept_is_bounded() {
        let slow = Slow::with(&[("big", AHEAD_BYTES), ("b", 5), ("c", 5)]);
        let ahead = Ahead::new(&slow);
        let keep = ahead.keeping();
        keep.get("b", None).await.unwrap();
        assert!(!ahead.full());
        assert!(keep.get("big", None).await.unwrap().is_none());
        assert!(!ahead.lock().gets.contains_key("big"));
        keep.get("c", None).await.unwrap();
        assert_eq!(ahead.lock().bytes, 10);
        let span = ByteSpan { start: 0, len: 2 };
        assert!(keep.get("b", Some(span)).await.unwrap().is_none());
        ahead.get("b", Some(span)).await.unwrap();
        assert_eq!(slow.asked().last().unwrap(), "range b");

        let (bucket, extent) = (BucketId::new("b".to_owned()), ExtentId::new("x".to_owned()));
        let meta = BlobMeta {
            bucket: &bucket,
            extent: &extent,
            cipher_sha256: &[0; 32],
        };
        // A read ahead of `b` and of the head of `c` that the store
        // answers only after the write.
        let (old, old_head, put) = future::join3(
            keep.get("b", None),
            keep.head("c"),
            ahead.put("b", vec![1], &meta),
        )
        .await;
        put.unwrap();
        assert_eq!(old.unwrap(), Some(vec![7; 5]));
        assert_eq!(old_head.unwrap(), Some(5));
        assert_eq!(ahead.lock().bytes, 0);
        assert!(ahead.lock().gets.is_empty() && ahead.lock().heads.is_empty());
        assert_eq!(ahead.get("b", None).await.unwrap(), Some(vec![1]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn in_flight_reads_share_the_byte_budget_and_release_on_cancel() {
        let part = AHEAD_BYTES / 3;
        let slow = Slow::with(&[("a", part), ("b", part)]);
        let ahead = Ahead::new(&slow);
        let keep = ahead.keeping();
        {
            let mut pending = pin!(keep.get("a", None));
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert_eq!(ahead.lock().reserved, 2 * part + 1);
            assert!(keep.get("b", None).await.unwrap().is_none());
        }
        assert_eq!(ahead.lock().reserved, 0);
        let answer = keep.get("b", None).await.unwrap();
        assert_eq!(answer.as_ref().map(Vec::len), Some(part));
        assert_eq!(ahead.lock().reserved, 0);
        assert_eq!(ahead.lock().bytes, part);
    }

    /// The store is asked for several things at once, and never for
    /// more than [`STORE_READS`].
    #[tokio::test(flavor = "current_thread")]
    async fn reads_ahead_run_several_at_a_time() {
        let keys: Vec<String> = (0..40).map(|i| format!("k{i:02}")).collect();
        let slow = Slow::default();
        let ahead = Ahead::new(&slow);
        let keep = ahead.keeping();
        stream::iter(keys.iter().map(|key| keep.get(key, None)))
            .buffered(STORE_READS)
            .for_each(|_| std::future::ready(()))
            .await;
        assert_eq!(slow.most.get(), STORE_READS);
        assert_eq!(slow.asked().len(), 40);
        assert_eq!(ahead.lock().gets.len(), 40);
    }
}
