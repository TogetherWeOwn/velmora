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

use serde::{Deserialize, Serialize};

use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::recovery::{
    read_article_plan, read_generation, read_tombstone, record_name, start_after,
    GenerationManifest, Layout, GENERATION_PREFIX, TOMBSTONE_PREFIX,
};
use crate::types::{
    ArticleRow, ArticleState, BucketId, ExtentPlacement, ExtentRow, GenerationId, Result, UnixMs,
};

/// How much one call does. The default keeps a call far below a Worker
/// invocation's subrequest limit.
#[derive(Clone, Copy, Debug)]
pub struct ReplayLimits {
    /// Records listed and finished at most.
    pub records: u32,
    /// Extents checked at most (two blob reads each).
    pub extents: usize,
}

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
        self.replay_step_within(cursor, ReplayLimits::default())
            .await
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
        let mut budget = limits.extents;
        for listed in &names {
            let flat = &listed.flat;
            // The first name of the id that opens: a name that does not
            // must not hide a record of the same id that does.
            let mut opened = None;
            for (name, layout) in listed.names() {
                match read_generation(&self.safety, &self.kek, name).await {
                    Ok(Some(m)) => {
                        opened = Some((m, layout));
                        break;
                    }
                    // Removed by an operator since the listing.
                    Ok(None) => {}
                    Err(crate::types::BridgeError::Blob(e)) => {
                        return Err(crate::types::BridgeError::Blob(e))
                    }
                    Err(_) => report.unreadable.push(name.clone()),
                }
            }
            let Some((manifest, layout)) = opened else {
                cursor = finished(cursor, flat);
                continue;
            };
            if !self
                .replay_manifest(&manifest, layout, &mut cursor, &mut budget, report)
                .await?
            {
                // Out of budget inside this record.
                return Ok(Some(cursor));
            }
            report.manifests += 1;
            cursor = finished(cursor, flat);
        }
        if names.len() as u64 == u64::from(limits.records) {
            return Ok(Some(cursor));
        }
        Ok(Some(ReplayCursor {
            phase: ReplayPhase::Tombstones,
            after: start_after(TOMBSTONE_PREFIX, UnixMs(cursor.since_ms)),
            ..cursor
        }))
    }

    /// `false` = the extent budget ran out; `cursor` says where.
    async fn replay_manifest(
        &self,
        m: &GenerationManifest,
        // The layout the record is stored in: where the article plans
        // of its extents are looked for first.
        layout: &Layout,
        cursor: &mut ReplayCursor,
        budget: &mut usize,
        report: &mut ReplayReport,
    ) -> Result<bool> {
        let generation = m.generation()?;
        let probe = self.catalog.replay_probe(&generation).await?;
        if probe == ReplayProbe::Superseded {
            report.superseded += 1;
            return Ok(true);
        }
        let bucket = m.bucket();
        // A bucket made again under the same name since the export has
        // another id and another data key. Nothing of the record can go
        // into it, and its rows cannot go in beside it: the name is
        // unique. The operator decides which of the two stays.
        if let Some(named) = self.catalog.bucket_by_name(&bucket.name).await? {
            if named.id != bucket.id {
                report.other_bucket_total += 1;
                if report.other_bucket.len() < OTHER_BUCKET_LISTED {
                    report.other_bucket.push(generation.id.as_str().to_owned());
                }
                return Ok(true);
            }
        }
        let now = self.clock.now();
        let mut at = cursor.extent as usize;
        while at < m.extents.len() {
            if *budget == 0 {
                return Ok(false);
            }
            let end = m.extents.len().min(at + *budget);
            let mut chunk = Vec::with_capacity(end - at);
            for index in at..end {
                let mut row = m.extent(index)?;
                let safety_present = self.safety.head(&row.id.safety_key()).await?.is_some();
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
                let read = read_article_plan(&self.safety, &self.kek, &row.id, layout).await?;
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
                let placements: Vec<ExtentPlacement> = m
                    .extents
                    .iter()
                    .map(|e| ExtentPlacement {
                        extent_id: crate::types::ExtentId::new(e.id.clone()),
                        seq: e.seq,
                        plain_offset: e.plain_offset,
                    })
                    .collect();
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
        Ok(true)
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
        for listed in &names {
            let flat = &listed.flat;
            // As for a generation: the first name of the id that opens.
            let mut opened = None;
            for (name, _) in listed.names() {
                match read_tombstone(&self.safety, &self.kek, name).await {
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
        for id in &ids {
            report.held_checked += 1;
            if self.safety.head(&id.safety_key()).await?.is_none() {
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
        ..cursor
    }
}
