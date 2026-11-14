//! Catalogue restore: replays the recovery records in `SAFETY` into the
//! catalogue (DESIGN §A.8). It runs only while `MAINTENANCE=restore`,
//! when no request and no job changes the catalogue.
//!
//! The catalogue after a replay is the fold of the records in id order:
//! the live generation of a key is its newest manifest, unless a newer
//! tombstone exists. Manifests go first, oldest first, then tombstones.
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
//! replay reports the live ones as `damaged`.

use serde::{Deserialize, Serialize};

use crate::ports::{BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, NntpConnector};
use crate::recovery::{
    read_article_plan, read_generation, read_tombstone, start_after, GenerationManifest,
    GENERATION_PREFIX, TOMBSTONE_PREFIX,
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

/// One extent of a manifest with what the blob store says about it.
#[derive(Clone, Debug)]
pub struct ReplayExtent {
    pub row: ExtentRow,
    /// The article plan record, if there is one.
    pub plan: Option<Vec<ArticleRow>>,
    /// Whether the pinned copy exists.
    pub safety_present: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplayPhase {
    Manifests,
    Tombstones,
}

/// Resume point of a replay. Opaque to the caller: send back what the
/// last call returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayCursor {
    /// Records minted at or after this time are replayed.
    pub since_ms: i64,
    pub phase: ReplayPhase,
    /// Blob key of the last finished record.
    pub after: String,
    /// Extents already handled of the record after `after`.
    pub extent: u32,
}

impl ReplayCursor {
    /// A replay of every record minted at or after `since`.
    pub fn start(since: UnixMs) -> Self {
        ReplayCursor {
            since_ms: since.0,
            phase: ReplayPhase::Manifests,
            after: start_after(GENERATION_PREFIX, since),
            extent: 0,
        }
    }
}

/// What one call did. Lists hold generation ids or blob keys, never
/// object keys.
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
    /// Not published: the catalogue refused the generation (its extents
    /// belong to another generation, or it lost a race).
    pub unpublishable: Vec<String>,
    /// Set by the last call: live generations with an extent that has no
    /// copy anywhere. `damaged` holds the first ids of `damaged_total`.
    pub damaged_total: u64,
    pub damaged: Vec<String>,
    /// Records that did not open or parse (blob keys).
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
            .safety
            .list(GENERATION_PREFIX, &cursor.after, limits.records)
            .await?;
        let mut budget = limits.extents;
        for name in &names {
            let manifest = match read_generation(&self.safety, &self.kek, name).await {
                Ok(Some(m)) => m,
                // Removed by an operator since the listing.
                Ok(None) => {
                    cursor = finished(cursor, name);
                    continue;
                }
                Err(crate::types::BridgeError::Blob(e)) => {
                    return Err(crate::types::BridgeError::Blob(e))
                }
                Err(_) => {
                    report.unreadable.push(name.clone());
                    cursor = finished(cursor, name);
                    continue;
                }
            };
            if !self
                .replay_manifest(&manifest, &mut cursor, &mut budget, report)
                .await?
            {
                // Out of budget inside this record.
                return Ok(Some(cursor));
            }
            report.manifests += 1;
            cursor = finished(cursor, name);
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
        let now = self.clock.now();
        let mut at = cursor.extent as usize;
        while at < m.extents.len() {
            if *budget == 0 {
                return Ok(false);
            }
            let end = m.extents.len().min(at + *budget);
            let mut chunk = Vec::with_capacity(end - at);
            for index in at..end {
                let row = m.extent(index)?;
                let safety_present = self.safety.head(&row.id.safety_key()).await?.is_some();
                // A plan in an existing catalogue row is kept; this one
                // fills the gap when the row or its plan is missing.
                let state = if safety_present {
                    ArticleState::Planned
                } else {
                    ArticleState::Posted
                };
                let plan = match read_article_plan(&self.safety, &self.kek, &row.id).await? {
                    Some(record) => Some(record.rows(state)?),
                    None => None,
                };
                report.extents += 1;
                report.article_plans += u32::from(plan.is_some());
                report.safety_missing += u32::from(!safety_present);
                chunk.push(crate::replay::ReplayExtent {
                    row,
                    plan,
                    safety_present,
                });
            }
            self.catalog.replay_extents(&bucket, &chunk, now).await?;
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
                    Guard::Applied(()) => report.published += 1,
                    Guard::Lost => report.unpublishable.push(id),
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
            .safety
            .list(TOMBSTONE_PREFIX, &cursor.after, limits.records)
            .await?;
        let now = self.clock.now();
        for name in &names {
            match read_tombstone(&self.safety, &self.kek, name).await {
                Ok(Some(t)) => {
                    let deleted = self
                        .catalog
                        .delete_object_before(
                            &BucketId::new(t.bucket_id),
                            &t.key,
                            &GenerationId::new(t.id),
                            now,
                        )
                        .await?;
                    report.tombstones += 1;
                    report.deleted += u32::from(deleted);
                }
                Ok(None) => {}
                Err(crate::types::BridgeError::Blob(e)) => {
                    return Err(crate::types::BridgeError::Blob(e))
                }
                Err(_) => report.unreadable.push(name.clone()),
            }
            cursor = finished(cursor, name);
        }
        if names.len() as u64 == u64::from(limits.records) {
            return Ok(Some(cursor));
        }
        let (total, ids) = self.catalog.replay_damaged(DAMAGED_LISTED).await?;
        report.damaged_total = total;
        report.damaged = ids.iter().map(|id| id.as_str().to_owned()).collect();
        Ok(None)
    }
}

/// The cursor after the record at `name` is done.
fn finished(cursor: ReplayCursor, name: &str) -> ReplayCursor {
    ReplayCursor {
        after: name.to_owned(),
        extent: 0,
        ..cursor
    }
}
