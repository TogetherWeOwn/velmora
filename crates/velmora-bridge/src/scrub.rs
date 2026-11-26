//! Scrub and repair (H5/H6): released extents are read back from Usenet
//! alone, on a schedule, and what has been lost is put back.
//!
//! # A run
//!
//! The cron dispatcher sends one [`Job::Scrub`](crate::types::Job) while
//! `SCRUB=on` and no run holds the scrub's lease. A run takes the lease
//! (one run at a time; every write it makes names the lease's token),
//! checks the extents that are due, the one due longest first, a page at
//! a time, and ends after `SCRUB_EXTENTS_PER_RUN` extents, after
//! `SCRUB_RUN_SECS`, when repair reconstruction has no slot, or when
//! the breaker trips. An unavailable copy check defers only that copy.
//! The lease lasts as long as a queue invocation can
//! ([`JOB_MAX_AGE_MS`]), so a run that died frees it by itself.
//!
//! # A check
//!
//! - Each counting backbone has separate STAT and full read-back clocks.
//!   STAT checks every article without downloading its body. A full check
//!   verifies every article and the assembled ciphertext on that backbone
//!   alone, including the hashes of any parity articles.
//! - Only a confirmed loss uses the multi-backbone cold reader to source
//!   repair bytes. That reconstruction never advances another copy's clock.
//!
//! # A loss
//!
//! - Seen once, it is recorded `suspect` and checked again after
//!   `SCRUB_CONFIRM_SECS`: a provider that answered `430` for a moment
//!   costs one more read, not a repair.
//! - Seen again, the extent is re-pinned ([`Catalog::scrub_repin`]): the
//!   verified ciphertext goes back to the safety store, the extent back
//!   to `held` and its outbox row back to `verify`. The verify stage
//!   posts what a backbone lacks under the stored message-ids and reads
//!   it back, and the release needs `REQUIRED_BACKBONES` and the minimum
//!   age again, as for any upload. The bytes come from Usenet (another
//!   backbone, or the extent's parity, which the reader rebuilds lost
//!   articles from), else from the cache copy, else from the safety copy
//!   if it is still in R2; each is checked against the extent's digest
//!   first.
//! - A loss is re-pinned only once its first sighting is at least
//!   [`REPIN_MIN_LOSS_AGE_MS`] old. Eviction keeps the safety copy of an
//!   extent with a loss on record, so an eviction that passed its check
//!   before the loss was recorded has ended (a queue invocation lasts at
//!   most [`JOB_MAX_AGE_MS`]) before the re-pin, and its delete cannot
//!   take the copy the re-pin keeps.
//! - Every safety copy the scrub writes after its last catalogue check
//!   (after the re-pin, or in the repair watch) is followed by a guarded
//!   GC row: garbage collection that ended before the PUT landed, or a
//!   PUT whose reply was lost, cannot leave the copy behind.
//! - No intact copy anywhere: `unrecoverable`, an alert line, and a
//!   check again after `SCRUB_CONFIRM_SECS` (a backbone that was down
//!   may come back).
//! - A re-pinned extent is looked at again when its repair should have
//!   ended ([`repair_bound_secs`]). Still pinned, it is `stalled`, with an
//!   alert line; a safety copy that is gone meanwhile is written again.
//!
//! # Valves
//!
//! - The breaker: if 8 or more extents and more than 12% of the checks
//!   of one kind on a backbone find loss, the run stops
//!   and repairs nothing more there. That is a backbone event (an outage,
//!   a purge, a provider answering `430` while throttled), not lost
//!   articles: re-pinning would copy the store back into R2. From then on
//!   at most one loss a run on that backbone is re-pinned
//!   ([`BLOCKED_REPINS_PER_RUN`]); the others stay `suspect`, until 8
//!   checks in a row, across runs, find nothing lacking there. A BODY
//!   incident requires clean BODY checks.
//! - At most `SCRUB_REPAIRS_PER_RUN` re-pins per run.

use futures_util::future::{select, Either};
use sha2::{Digest, Sha256};

use crate::fetch::ProviderSession;
use crate::fetch::{
    ask_articles_together, cold_step_bytes, read_articles, ColdFetch, ColdReader, ColdStats,
};
use crate::jobtable::JOB_MAX_AGE_MS;
use crate::plan::StoredPlan;
use crate::pool::Pool;
use crate::ports::PermitClass;
use crate::ports::{BlobMeta, BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::post::Stop;
use crate::types::{
    ArticleRow, ArticleState, BridgeError, ExtentRow, JobOutcome, ProviderConfig, Result,
    SafetyState, ScrubCandidate, ScrubEnd, ScrubResult, ScrubRun, UnixMs,
};
use crate::verify::{release_backbones, MISSING_BACKOFF_SECS, REVERIFY_SECS};

/// Extents read from the due list per catalogue call.
pub const SCRUB_PAGE: u32 = 8;

/// The breaker trips when at least this many extents of a run lack
/// articles on one backbone...
pub const INCIDENT_MIN_EXTENTS: u32 = 8;
/// ...and they are more than this share, in percent, of the extents the
/// run checked. 1 % of articles lost everywhere hits 11.4 % of extents
/// of 12 articles (the repair-data design, section 5.4); beyond that the
/// cause is the backbone, not the articles.
pub const INCIDENT_PERCENT: u32 = 12;

/// How old the first sighting of a loss must be before it is re-pinned:
/// two queue invocations. Eviction keeps the safety copy of an extent
/// with a loss on record (`EVICT_SAFETY_STILL_OK`), and an eviction
/// that passed its check before the loss was recorded deletes within
/// one invocation of that check. The second invocation covers the scrub
/// run that wrote the record after it saw the loss. Production confirm
/// intervals (at least an hour) are longer; this binds in dev only.
pub const REPIN_MIN_LOSS_AGE_MS: i64 = 2 * JOB_MAX_AGE_MS;

/// Re-pins a run makes at most for losses on a backbone under an
/// incident: one, the least that is not none. A loss that lasts on one
/// backbone (a takedown of one large object) trips the breaker again on
/// every run and would otherwise never be repaired; during a backbone
/// outage this costs at most one extent pinned and verified per run.
pub const BLOCKED_REPINS_PER_RUN: u32 = 1;

/// How long a re-pinned extent is given before the scrub looks at it
/// again: the minimum age of the safety copy, every wait verify makes
/// for a missing article and its wait after a failed backbone, and one
/// confirm interval. All from the settings and constants they are.
pub fn repair_bound_secs(safety_min_age_secs: u32, confirm_secs: u32) -> u64 {
    let waits: u64 = MISSING_BACKOFF_SECS.iter().map(|s| u64::from(*s)).sum();
    u64::from(safety_min_age_secs) + waits + u64::from(REVERIFY_SECS) + u64::from(confirm_secs)
}

/// Where the bytes of a repair came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairSource {
    /// Read from Usenet: articles a backbone lacks came from another.
    Usenet,
    /// Read from Usenet with lost articles rebuilt from the extent's
    /// parity ([`rebuilt`]).
    Parity,
    /// The cache copy (`c/<extent>`).
    Cache,
    /// The safety copy (`x/<extent>`), still in R2 after the release.
    Safety,
}

impl RepairSource {
    pub fn as_str(self) -> &'static str {
        match self {
            RepairSource::Usenet => "usenet",
            RepairSource::Parity => "parity",
            RepairSource::Cache => "cache",
            RepairSource::Safety => "safety",
        }
    }
}

/// Articles the reader rebuilt from parity between two of its stats.
fn rebuilt(before: &ColdStats, after: &ColdStats) -> u32 {
    after.rebuilt.saturating_sub(before.rebuilt)
}

/// What one backbone's own check found.
enum Presence {
    Complete {
        intact: bool,
        bytes: u64,
    },
    /// No slot, or it could not be asked: nothing is known.
    Unknown,
}

const DAY_MS: i64 = 86_400_000;

/// Keep the healthy phases aligned even if workers begin late or the
/// checks of one extent finish at different times.
fn next_cadence(due: UnixMs, now: UnixMs, interval: i64) -> UnixMs {
    let elapsed = now.0.saturating_sub(due.0).rem_euclid(interval);
    now.plus_ms(interval - elapsed)
}

fn intervals(cfg: &crate::config::ScrubConfig) -> [i64; 2] {
    [
        i64::from(cfg.interval_days) * DAY_MS,
        i64::from(cfg.full_interval_days) * DAY_MS,
    ]
}

/// What a check of a released extent found.
struct Found {
    /// The backbones that lack articles, by label.
    lacking: Vec<String>,
    /// The ciphertext, if the read got all of it intact.
    cipher: Option<Vec<u8>>,
    /// Articles rebuilt from parity by the read.
    rebuilt: u32,
    /// The read broke off: `cipher` is `None` for that, not because no
    /// provider has the bytes.
    interrupted: bool,
    /// The bytes the read holds, charged until the check is done with.
    _charge: Option<crate::ingress::Charge>,
}

#[derive(Default)]
struct CopyChecks {
    lacking: Vec<String>,
    observed: Vec<Observation>,
    busy: bool,
    deferred: bool,
    prior_loss: Option<UnixMs>,
    confirmed: Vec<String>,
}

/// Why a check did not finish.
enum Halt {
    /// A provider had no slot: the run stops, the extent waits.
    Busy,
    /// The read broke off: the extent is looked at again later, and the
    /// run goes on.
    Deferred,
    /// The catalogue failed, or the lease is gone.
    Stopped,
}

impl From<crate::types::BridgeError> for Halt {
    fn from(_: crate::types::BridgeError) -> Halt {
        Halt::Stopped
    }
}

/// What a run carries from one extent to the next.
struct Walk<'w, 's, C: Catalog, N: NntpConnector, T: Clock> {
    /// The lease's token: every write of the run names it.
    token: u64,
    run: &'w mut ScrubRun,
    breaker: &'w mut Breaker,
    /// The backbones of the breaker trips that stand.
    blocked: Vec<String>,
    body_blocked: Vec<String>,
    deferred_checks: bool,
    completed_checks: bool,
    /// The copy-check sessions, kept from one extent to the next.
    stats: &'w mut Vec<ProviderSession<'s, C, N, T>>,
    /// Providers that refused this run's login: not asked again in it.
    refused: Vec<String>,
    /// Backbones whose scheduled check could not finish in this run.
    unavailable: Vec<String>,
    /// Re-pins of this run for a loss on a backbone under an incident.
    blocked_repins: u32,
    /// Separate recovery streaks; a check of A never clears B's block.
    clean: Vec<(String, u64)>,
}

struct Observation {
    backbone: String,
    full: bool,
    intact: bool,
}

/// The breaker's counts for one run, by backbone and kind of check.
#[derive(Default)]
struct Breaker {
    samples: Vec<(String, bool, u32, u32)>,
}

impl Breaker {
    fn note(&mut self, observed: &[Observation]) {
        for check in observed {
            let bad = u32::from(!check.intact);
            match self
                .samples
                .iter_mut()
                .find(|(b, full, _, _)| *b == check.backbone && *full == check.full)
            {
                Some((_, _, checked, lost)) => {
                    *checked += 1;
                    *lost += bad;
                }
                None => self
                    .samples
                    .push((check.backbone.clone(), check.full, 1, bad)),
            }
        }
    }

    fn tripped(&self) -> Vec<(String, bool, u32, u32)> {
        self.samples
            .iter()
            .filter(|(_, _, checked, lost)| breaker_trips(*lost, *checked))
            .cloned()
            .collect()
    }
}

/// Whether `lacking` and `checked` trip the breaker (for tests and the
/// operator's arithmetic).
pub fn breaker_trips(lacking: u32, checked: u32) -> bool {
    lacking >= INCIDENT_MIN_EXTENTS
        && u64::from(lacking) * 100 > u64::from(checked) * u64::from(INCIDENT_PERCENT)
}

/// The counting backbones the extent's release evidence names for its
/// current plan.
fn evidence_backbones(extent: &ExtentRow) -> Vec<String> {
    let Some(raw) = extent.release_evidence.as_deref() else {
        return Vec::new();
    };
    let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(raw) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for row in &rows {
        let rev = row.get("plan_rev").and_then(serde_json::Value::as_u64);
        let name = row.get("backbone").and_then(serde_json::Value::as_str);
        if let (Some(rev), Some(name)) = (rev, name) {
            if rev == u64::from(extent.plan_rev) && !out.iter().any(|b| b == name) {
                out.push(name.to_owned());
            }
        }
    }
    out
}

fn evidence_names(extent: &ExtentRow, backbone: &str) -> bool {
    evidence_backbones(extent).iter().any(|b| b == backbone)
}

/// Whether the extent is releasable under `counting` (the backbones that
/// count now): its release evidence names `required` of them for its
/// current plan. The rule eviction applies before it deletes an extent's
/// last R2 copy (`sql::hot` `releasable_now!`).
pub fn releasable_now(extent: &ExtentRow, counting: &[String], required: u32) -> bool {
    let named = evidence_backbones(extent)
        .iter()
        .filter(|b| counting.contains(b))
        .count();
    u32::try_from(named).unwrap_or(u32::MAX) >= required
}

fn digest_ok(extent: &ExtentRow, bytes: &[u8]) -> bool {
    bytes.len() as u64 == extent.cipher_size
        && <[u8; 32]>::from(Sha256::digest(bytes)) == extent.cipher_sha256
}

impl<C, B, N, J, K, T> Bridge<C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    /// The queue job of a scrub run. Always acked: the next cron run
    /// sends another when the lease is free, and an extent that was not
    /// recorded is due as it was.
    pub async fn run_scrub(&self) -> JobOutcome {
        if self.cfg.scrub.on {
            let _ = self.scrub_run().await;
        }
        JobOutcome::Ack
    }

    /// One scrub run. `Ok(None)`: another run holds the lease.
    pub async fn scrub_run(&self) -> Result<Option<ScrubRun>> {
        let started = self.clock.now();
        let until = started.plus_ms(JOB_MAX_AGE_MS);
        let Some(token) = self.catalog.scrub_take(started, until).await? else {
            return Ok(None);
        };
        // A failure before the run begins gives the lease back at once.
        let begun = async {
            self.reconcile_put_intents(started).await?;
            let state = self.catalog.scrub_state().await?;
            let reader = self.scrub_reader(self.cfg.scrub.sockets)?;
            Ok::<_, crate::types::BridgeError>((state, reader))
        };
        let (state, mut reader) = match begun.await {
            Ok(begun) => begun,
            Err(e) => {
                let now = self.clock.now();
                // The lease only: the incidents and totals stay as they are.
                let _ = self.catalog.scrub_free(token, now).await;
                crate::trace::scrub_run(|| "ended=stopped before the first extent".to_owned());
                return Err(e);
            }
        };
        // An incident clears only on fresh observations of that backbone.
        let blocked = state.blocked();
        let mut clean = state.incident_clean_by;
        let body_blocked = state.incident_body_by;
        if clean.is_empty()
            && blocked.len() == 1
            && body_blocked.is_empty()
            && state.incident_clean != 0
        {
            clean.push((blocked[0].clone(), state.incident_clean));
        }
        let mut run = ScrubRun::default();
        let mut breaker = Breaker::default();
        let mut stats = Vec::new();
        let mut walk = Walk {
            token,
            run: &mut run,
            breaker: &mut breaker,
            blocked,
            body_blocked,
            deferred_checks: false,
            completed_checks: false,
            stats: &mut stats,
            refused: Vec::new(),
            unavailable: Vec::new(),
            blocked_repins: 0,
            clean,
        };
        let ended = self.scrub_pages(started, &mut reader, &mut walk).await;
        let mut blocked = core::mem::take(&mut walk.blocked);
        let mut body_blocked = core::mem::take(&mut walk.body_blocked);
        let mut clean = core::mem::take(&mut walk.clean);
        let no_copy_progress = !walk.completed_checks && walk.deferred_checks;
        ProviderSession::close_all(stats).await;
        reader.close().await;
        run.ended = ended;
        if no_copy_progress || (run.checked == 0 && ended == ScrubEnd::Busy) {
            crate::trace::alert(|| format!("scrub-no-progress ended={} checked=0", ended.as_str()));
        }
        if run.incident.is_some() {
            // Keep the original conservative rule: a run that tripped
            // the breaker cannot also clear existing blocks.
            clean.clear();
        } else {
            blocked.retain(|name| {
                !clean
                    .iter()
                    .any(|(b, n)| b == name && *n >= u64::from(INCIDENT_MIN_EXTENTS))
            });
            clean.retain(|(name, _)| blocked.contains(name));
        }
        run.incident_clean = if blocked.len() == 1 {
            clean.first().map_or(0, |(_, n)| *n)
        } else {
            0
        };
        body_blocked.retain(|name| blocked.contains(name));
        run.blocked = blocked;
        run.incident_clean_by = clean;
        run.incident_body_by = body_blocked;
        let now = self.clock.now();
        // A run that lost its lease adds nothing: the totals are another
        // run's to add.
        let _ = self.catalog.scrub_end(token, &run, now).await;
        crate::trace::scrub_run(|| {
            format!(
                "checked={} ok={} suspect={} repaired={} unrecoverable={} stalled={} \
                 bytes={} refetched={} ended={} ms={}",
                run.checked,
                run.ok,
                run.suspect,
                run.repaired,
                run.unrecoverable,
                run.stalled,
                run.bytes_read,
                run.refetched,
                run.ended.as_str(),
                now.0 - started.0
            )
        });
        Ok(Some(run))
    }

    /// Runs `f`, which is not a provider call, while the run's sessions
    /// sit unused: once the first of their slots has only the goodbye and
    /// the slack left ([`ColdReader::idle_ms`], [`ProviderSession::idle_ms`])
    /// they are all ended, and `f` goes on. No socket outlives its slot.
    async fn idle<'s, F: core::future::Future>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        stats: &mut Vec<ProviderSession<'s, C, N, T>>,
        f: F,
    ) -> F::Output {
        let limit = stats
            .iter()
            .map(ProviderSession::idle_ms)
            .chain(reader.idle_ms())
            .min();
        let mut f = core::pin::pin!(f);
        if let (Some(ms), Some(sleep)) = (limit, self.budget.sleeper()) {
            match select(f.as_mut(), sleep(ms)).await {
                Either::Left((out, _)) => return out,
                Either::Right(_) => {
                    ProviderSession::close_all(core::mem::take(stats)).await;
                    reader.hang_up().await;
                }
            }
        }
        f.await
    }

    /// Ends every session of the run: before a step that holds none of
    /// them for long (a repair's blob reads and writes).
    async fn hang_up_all<'s>(
        reader: &mut ColdReader<'s, C, N, T>,
        stats: &mut Vec<ProviderSession<'s, C, N, T>>,
    ) {
        ProviderSession::close_all(core::mem::take(stats)).await;
        reader.hang_up().await;
    }

    async fn scrub_pages<'s>(
        &'s self,
        started: UnixMs,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
    ) -> ScrubEnd {
        let cfg = &self.cfg.scrub;
        let deadline = started.plus_secs(cfg.run_secs);
        let backbones = crate::verify::release_labels(&self.cfg.providers);
        // Up to 1,024 pending admissions per run, always in bounded
        // indexed pages. Normal incremental runs stop after the first page.
        for _ in 0..8 {
            if self.clock.now() >= deadline {
                return ScrubEnd::Time;
            }
            match self
                .catalog
                .scrub_enroll(walk.token, &backbones, started, intervals(cfg))
                .await
            {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => return ScrubEnd::Stopped,
            }
        }
        let mut taken = 0u32;
        // An extent this run has looked at is not looked at again in it,
        // whatever it left on the row (a write that did not land, say).
        let mut seen: Vec<crate::types::ExtentId> = Vec::new();
        'pages: loop {
            let left = cfg.extents_per_run - taken;
            if left == 0 {
                return ScrubEnd::Quota;
            }
            let now = self.clock.now();
            if now >= deadline {
                return ScrubEnd::Time;
            }
            let available: Vec<_> = backbones
                .iter()
                .filter(|name| !walk.unavailable.contains(name))
                .cloned()
                .collect();
            let due = self
                .catalog
                .scrub_due(&available, now, left.min(SCRUB_PAGE));
            let page = match self.idle(reader, walk.stats, due).await {
                Ok(page) => page,
                Err(_) => return ScrubEnd::Stopped,
            };
            // Every extent looked at is recorded with a due time ahead,
            // so it leaves the list; one that is back at its head (its
            // write did not land) ends the run rather than read a page
            // that grows with the run.
            let fresh: Vec<&ScrubCandidate> = page
                .iter()
                .filter(|c| !seen.contains(&c.extent.id))
                .collect();
            if fresh.is_empty() {
                return ScrubEnd::Idle;
            }
            for candidate in fresh {
                seen.push(candidate.extent.id.clone());
                if self.clock.now() >= deadline {
                    return ScrubEnd::Time;
                }
                let unavailable = walk.unavailable.len();
                match self.scrub_one(reader, candidate, &backbones, walk).await {
                    Ok(observed) => taken += u32::from(observed),
                    Err(Halt::Busy) => return ScrubEnd::Busy,
                    Err(Halt::Stopped) => return ScrubEnd::Stopped,
                    // Handled where it arises; never reaches here.
                    Err(Halt::Deferred) => {}
                }
                if walk.run.incident.is_some() {
                    return ScrubEnd::Incident;
                }
                if walk.unavailable.len() != unavailable {
                    // The rest of this page may be an unavailable copy's
                    // backlog. Fetch again without that backbone.
                    continue 'pages;
                }
            }
        }
    }

    async fn scrub_record_one<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        extent: &ExtentRow,
        (result, next): (ScrubResult, Option<UnixMs>),
    ) -> core::result::Result<(), Halt> {
        let token = walk.token;
        let now = self.clock.now();
        // Released-copy deadlines live in scrub_copies. Only the repair
        // watch puts an extent-wide deadline on the extent row.
        let write = self
            .catalog
            .scrub_record(token, &extent.id, result, now, next);
        match self.idle(reader, walk.stats, write).await? {
            true => Ok(()),
            // The lease is gone, or the extent left the states the scrub
            // looks at under the check: either way, nothing more here.
            false => match self.catalog.scrub_state().await {
                Ok(state) if state.lease_token == token => Ok(()),
                _ => Err(Halt::Stopped),
            },
        }
    }

    async fn scrub_one<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        candidate: &ScrubCandidate,
        backbones: &[String],
        walk: &mut Walk<'_, 's, C, N, T>,
    ) -> core::result::Result<bool, Halt> {
        let cfg = &self.cfg.scrub;
        let token = walk.token;
        let extent = &candidate.extent;
        let confirm = i64::from(cfg.confirm_secs) * 1000;
        let now = self.clock.now();
        let watch_due = candidate.watch_at.is_some_and(|at| at <= now);
        if extent.safety_state == SafetyState::Deleted {
            let retire = self.catalog.scrub_retire(token, &extent.id);
            self.idle(reader, walk.stats, retire).await?;
            return Ok(false);
        }
        if extent.safety_state != SafetyState::Released {
            // A held repair is watched separately. Postpone due copy
            // checks to its current (or newly scheduled) repair watch
            // without advancing their phases or clearing their losses.
            let (next_watch, watched) = if !watch_due {
                (candidate.watch_at, false)
            } else if matches!(
                extent.safety_state,
                SafetyState::Held | SafetyState::Releasing
            ) && matches!(
                candidate.last,
                Some(ScrubResult::Repairing | ScrubResult::Stalled | ScrubResult::Unrecoverable)
            ) {
                // The stored plan with its parity addendum: the watch may
                // rebuild a lost copy from parity, as the repair read does.
                let plan = self.catalog.stored_plan(&extent.id);
                match self.idle(reader, walk.stats, plan).await {
                    Ok(plan) => {
                        let next = self.watch_repair(reader, walk, candidate, plan).await?;
                        (next, next.is_some())
                    }
                    // A plan that cannot be decoded: said, and the watch
                    // looks again later with the repair on record as it is.
                    Err(BridgeError::Invalid(what)) => {
                        Self::alert_bad_plan(extent, what);
                        let next = self.clock.now().plus_ms(confirm);
                        self.catalog.scrub_defer(token, &extent.id, next).await?;
                        (Some(next), false)
                    }
                    Err(e) => return Err(e.into()),
                }
            } else {
                self.catalog.scrub_drop(token, &extent.id).await?;
                (None, false)
            };
            let next = next_watch.unwrap_or_else(|| self.clock.now().plus_ms(confirm));
            let updates: Vec<_> = candidate
                .checks
                .iter()
                .map(|check| (check.clone(), next, check.loss_at))
                .collect();
            self.advance_checks(reader, walk, extent, &updates, None)
                .await?;
            return Ok(watched);
        }
        if watch_due {
            // A completed repair (or an old extent-wide deadline) is not
            // evidence that any copy's scheduled read-back has passed.
            self.catalog.scrub_drop(token, &extent.id).await?;
        }
        // Released, but not releasable under the backbones that count now
        // (one that held it stopped counting): eviction keeps its last R2
        // copy until a re-verify on the counting backbones releases it
        // again. Looked at on its own deadline too, not only with checks.
        let reverify = watch_due && !releasable_now(extent, backbones, self.cfg.required_backbones);
        if candidate.checks.is_empty() && !reverify {
            return Ok(false);
        }
        let live = self.catalog.scrub_live(&extent.id);
        let live = self.idle(reader, walk.stats, live).await?;
        let stored = if live {
            let load = self.catalog.stored_plan(&extent.id);
            match self.idle(reader, walk.stats, load).await {
                Ok(stored) => Some(stored),
                // A packed plan that cannot be decoded is the same every
                // time: deferred like an addendum that cannot be read.
                // A catalogue that did not answer still stops the run.
                Err(BridgeError::Invalid(what)) => {
                    return self.defer_bad_plan(reader, walk, candidate, what).await;
                }
                Err(e) => return Err(e.into()),
            }
        } else {
            None
        };
        let Some(stored) = stored.filter(|plan| {
            !plan.rows.is_empty()
                && u32::try_from(plan.rows.len()).ok() == extent.article_count
                && plan.rows.iter().all(|a| a.state == ArticleState::Posted)
        }) else {
            let now = self.clock.now();
            let intervals = intervals(cfg);
            let updates: Vec<_> = candidate
                .checks
                .iter()
                .map(|check| {
                    // An orphan can still be referenced by a staged copy. Do
                    // not keep it at the head of the confirmation queue while
                    // waiting for GC or for that reference to become live.
                    let delay = if live {
                        confirm
                    } else {
                        intervals[usize::from(check.full)]
                    };
                    (check.clone(), now.plus_ms(delay), check.loss_at)
                })
                .collect();
            self.advance_checks(reader, walk, extent, &updates, None)
                .await?;
            self.scrub_record_one(reader, walk, extent, (ScrubResult::Skipped, None))
                .await?;
            return Ok(false);
        };
        let parity = match stored.parity_plan(&extent.id, extent.cipher_size) {
            Ok(parity) => parity,
            Err(_) => {
                return self
                    .defer_bad_plan(reader, walk, candidate, "parity addendum")
                    .await;
            }
        };
        if candidate.checks.is_empty() {
            self.reverify(reader, walk, candidate, backbones, stored)
                .await?;
            return Ok(true);
        }
        let mut plan = stored.rows.clone();
        if let Some(parity) = parity {
            plan.extend(parity.articles);
        }
        let CopyChecks {
            lacking,
            observed,
            busy,
            deferred,
            prior_loss,
            confirmed,
        } = self.check_copies(reader, walk, candidate, &plan).await?;
        let observed_any = !observed.is_empty();
        walk.deferred_checks |= busy || deferred;
        walk.completed_checks |= observed_any;
        walk.breaker.note(&observed);
        for backbone in &walk.blocked {
            let checks = || observed.iter().filter(|check| &check.backbone == backbone);
            if lacking.contains(backbone) {
                walk.clean.retain(|(name, _)| name != backbone);
            } else if checks().any(|check| check.full || !walk.body_blocked.contains(backbone)) {
                if let Some((_, n)) = walk.clean.iter_mut().find(|(name, _)| name == backbone) {
                    *n += 1;
                } else {
                    walk.clean.push((backbone.clone(), 1));
                }
            }
        }
        if lacking.is_empty() && (!observed_any || busy || deferred) {
            if let Some(at) = prior_loss {
                self.alert_deferred(extent, at);
            } else if deferred {
                if candidate.last == Some(ScrubResult::Deferred) {
                    crate::trace::alert(|| {
                        format!(
                            "scrub-deferred {} the read broke off twice in a row",
                            extent.id.as_str()
                        )
                    });
                }
                self.scrub_record_one(reader, walk, extent, (ScrubResult::Deferred, None))
                    .await?;
            }
            return Ok(observed_any);
        }
        walk.run.checked += 1;
        if lacking.is_empty() {
            let unresolved = self.catalog.scrub_has_loss(&extent.id, backbones);
            if prior_loss.is_none() && self.idle(reader, walk.stats, unresolved).await?.is_empty() {
                if releasable_now(extent, backbones, self.cfg.required_backbones) {
                    walk.run.ok += 1;
                    self.scrub_record_one(reader, walk, extent, (ScrubResult::Ok, None))
                        .await?;
                } else {
                    self.reverify(reader, walk, candidate, backbones, stored)
                        .await?;
                }
            }
            return Ok(true);
        }
        let tripped = walk.breaker.tripped();
        if !tripped.is_empty() {
            for (backbone, full, checked, lacking) in &tripped {
                crate::trace::alert(|| format!("scrub-incident {backbone} {lacking}/{checked}"));
                if !walk.blocked.contains(backbone) {
                    walk.blocked.push(backbone.clone());
                }
                if *full && !walk.body_blocked.contains(backbone) {
                    walk.body_blocked.push(backbone.clone());
                }
            }
            walk.run.incident = tripped.first().map(|(b, _, _, _)| b.clone());
            // Stored now, under the lease: a run that dies before its end
            // still leaves the next one blocked.
            let _ = self
                .catalog
                .scrub_block(token, &walk.blocked, &walk.body_blocked)
                .await;
        }

        if confirmed.is_empty() {
            walk.run.suspect += 1;
            self.scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, None))
                .await?;
            return Ok(true);
        }
        // Held back from a re-pin, not from the finding: an extent with
        // no intact copy anywhere is still said to be unrecoverable.
        let under_incident = confirmed.iter().any(|l| walk.blocked.contains(l));
        let may_repin = tripped.is_empty()
            && (!under_incident || walk.blocked_repins < BLOCKED_REPINS_PER_RUN)
            && walk.run.repaired < cfg.repairs_per_run;
        // Confirmation gates repair, not what verify must read in full.
        // Include losses from this visit and any still on record, even
        // when their checks were not due on this visit.
        let unresolved = self.catalog.scrub_has_loss(&extent.id, backbones);
        let mut unread = lacking;
        unread.extend(self.idle(reader, walk.stats, unresolved).await?);
        unread.sort_unstable();
        unread.dedup();
        let repaired = walk.run.repaired;
        // The stored plan, parity addendum included: the reader rebuilds
        // what every backbone lost if the parity covers it.
        let found = self
            .repair_read(reader, walk, extent, stored, unread)
            .await?;
        let mut loss = candidate.clone();
        loss.last_scrubbed_at = prior_loss;
        self.repair(reader, walk, &loss, found, may_repin).await?;
        if under_incident && walk.run.repaired > repaired {
            walk.blocked_repins += 1;
        }
        Ok(true)
    }

    /// Re-verifies a released extent that is not releasable under the
    /// backbones that count now: it is re-pinned from verified bytes, and
    /// verify reads the counting backbones its release evidence does not
    /// name in full (posting what one lacks) before it releases it again,
    /// with evidence on the counting backbones. Within the run's re-pins;
    /// past them, looked at again after the confirm interval.
    async fn reverify<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        candidate: &ScrubCandidate,
        backbones: &[String],
        stored: StoredPlan,
    ) -> core::result::Result<(), Halt> {
        let extent = &candidate.extent;
        let cfg = &self.cfg.scrub;
        let unproven: Vec<String> = backbones
            .iter()
            .filter(|b| !evidence_names(extent, b))
            .cloned()
            .collect();
        let may = walk.run.repaired < cfg.repairs_per_run
            && walk.run.incident.is_none()
            && walk.breaker.tripped().is_empty();
        if !may {
            let next = self.clock.now().plus_ms(i64::from(cfg.confirm_secs) * 1000);
            self.catalog
                .scrub_defer(walk.token, &extent.id, next)
                .await?;
            return Ok(());
        }
        crate::trace::alert(|| {
            format!(
                "scrub-reverify {} unproven=[{}]: not releasable under the backbones that \
                 count now",
                extent.id.as_str(),
                unproven.join(",")
            )
        });
        let found = self
            .repair_read(reader, walk, extent, stored, unproven)
            .await?;
        self.repair(reader, walk, candidate, found, true).await
    }

    fn alert_bad_plan(extent: &ExtentRow, what: &str) {
        crate::trace::alert(|| {
            format!(
                "scrub-bad-plan {} its {what} cannot be read; looked at again after \
                 SCRUB_CONFIRM_SECS",
                extent.id.as_str()
            )
        });
    }

    /// A plan this version cannot decode is no evidence about the copies:
    /// the due checks wait a confirm interval with their phases and losses
    /// as they are, nothing is recorded, and the run goes on.
    async fn defer_bad_plan<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        candidate: &ScrubCandidate,
        what: &str,
    ) -> core::result::Result<bool, Halt> {
        let extent = &candidate.extent;
        Self::alert_bad_plan(extent, what);
        let confirm = i64::from(self.cfg.scrub.confirm_secs) * 1000;
        let next = self.clock.now().plus_ms(confirm);
        let updates: Vec<_> = candidate
            .checks
            .iter()
            .map(|check| (check.clone(), next, check.loss_at))
            .collect();
        self.advance_checks(reader, walk, extent, &updates, None)
            .await?;
        Ok(false)
    }

    async fn advance_checks<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        extent: &ExtentRow,
        updates: &[(crate::types::ScrubCheck, UnixMs, Option<UnixMs>)],
        verified: Option<UnixMs>,
    ) -> core::result::Result<(), Halt> {
        if !updates.is_empty() {
            let verified = verified.map(|at| (at, extent.plan_rev));
            let write = self
                .catalog
                .scrub_advance(walk.token, &extent.id, updates, verified);
            if !self.idle(reader, walk.stats, write).await? {
                return Err(Halt::Stopped);
            }
        }
        Ok(())
    }

    async fn check_copies<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        candidate: &ScrubCandidate,
        plan: &[ArticleRow],
    ) -> core::result::Result<CopyChecks, Halt> {
        let extent = &candidate.extent;
        let holder = reader.holder().to_owned();
        let groups = release_backbones(&self.cfg.providers);
        let intervals = intervals(&self.cfg.scrub);
        let confirm = i64::from(self.cfg.scrub.confirm_secs) * 1000;
        let mut out = CopyChecks::default();
        let mut updates = Vec::with_capacity(candidate.checks.len());
        // The last scheduled BODY check that passed (H6 `last_verified_at`).
        let mut verified = None;
        for check in &candidate.checks {
            if walk.unavailable.contains(&check.backbone) {
                continue;
            }
            let Some((_, providers)) = groups.iter().find(|(name, _)| *name == check.backbone)
            else {
                continue;
            };
            let _charge = if check.full {
                let bytes = cold_step_bytes(extent.cipher_size, 1);
                let charged = self.budget.charge_job(bytes);
                match self.idle(reader, walk.stats, charged).await {
                    Ok(charge) => Some(charge),
                    Err(_) => {
                        out.busy = true;
                        out.prior_loss = out.prior_loss.into_iter().chain(check.loss_at).min();
                        walk.unavailable.push(check.backbone.clone());
                        continue;
                    }
                }
            } else {
                None
            };
            let answer = self
                .presence(
                    &holder,
                    walk.stats,
                    &mut walk.refused,
                    plan,
                    providers,
                    check.full.then_some(extent),
                )
                .await;
            let now = self.clock.now();
            match answer {
                Ok(Presence::Complete { intact, bytes }) => {
                    walk.run.bytes_read += bytes;
                    out.observed.push(Observation {
                        backbone: check.backbone.clone(),
                        full: check.full,
                        intact,
                    });
                    if intact {
                        if check.full {
                            verified = Some(now);
                        }
                        let interval = intervals[usize::from(check.full)];
                        let next = next_cadence(check.phase_at, now, interval);
                        let mut check = check.clone();
                        // The nominal deadline moves only after a pass.
                        // A retry changes due_at, not the cadence anchor.
                        check.phase_at = next;
                        updates.push((check, next, None));
                    } else {
                        if !out.lacking.contains(&check.backbone) {
                            out.lacking.push(check.backbone.clone());
                        }
                        // Confirmed: seen at an earlier visit, and long
                        // enough ago that no eviction from before that
                        // sighting can still delete ([`REPIN_MIN_LOSS_AGE_MS`]).
                        let settled = check
                            .loss_at
                            .is_some_and(|at| at.plus_ms(REPIN_MIN_LOSS_AGE_MS) <= now);
                        if settled && !out.confirmed.contains(&check.backbone) {
                            out.confirmed.push(check.backbone.clone());
                        }
                        out.prior_loss = out.prior_loss.into_iter().chain(check.loss_at).min();
                        updates.push((
                            check.clone(),
                            now.plus_ms(confirm),
                            Some(check.loss_at.unwrap_or(now)),
                        ));
                    }
                }
                Ok(Presence::Unknown) => {
                    out.busy = true;
                    out.prior_loss = out.prior_loss.into_iter().chain(check.loss_at).min();
                    walk.unavailable.push(check.backbone.clone());
                }
                Err(Halt::Deferred) => {
                    out.deferred = true;
                    out.prior_loss = out.prior_loss.into_iter().chain(check.loss_at).min();
                    walk.unavailable.push(check.backbone.clone());
                }
                Err(halt) => return Err(halt),
            }
        }
        self.advance_checks(reader, walk, extent, &updates, verified)
            .await?;
        Ok(out)
    }

    /// A repair can reconstruct from any provider. It is never used as
    /// evidence for a periodic STAT or BODY check.
    async fn repair_read<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        extent: &ExtentRow,
        plan: StoredPlan,
        lacking: Vec<String>,
    ) -> core::result::Result<Found, Halt> {
        Self::hang_up_all(reader, walk.stats).await;
        let bytes = cold_step_bytes(extent.cipher_size, reader.sockets());
        let charge = self
            .budget
            .charge_job(bytes)
            .await
            .map_err(|_| Halt::Busy)?;
        let before = reader.stats();
        let read = reader.fetch_planned(extent, plan, self.clock.now()).await?;
        let after = reader.stats();
        let interrupted = matches!(read, ColdFetch::Interrupted);
        let cipher = match read {
            ColdFetch::Filled(cipher) => {
                walk.run.bytes_read += extent.cipher_size;
                Some(cipher)
            }
            ColdFetch::Unavailable | ColdFetch::Unrecoverable | ColdFetch::Interrupted => None,
            ColdFetch::Busy => return Err(Halt::Busy),
        };
        walk.run.refetched += after.refetched.saturating_sub(before.refetched);
        Ok(Found {
            lacking,
            cipher,
            rebuilt: rebuilt(&before, &after),
            interrupted,
            _charge: Some(charge),
        })
    }

    /// Ask one provider of this backbone for every planned article. For
    /// BODY, never mix accounts' answers or reuse a reconstruction from
    /// another backbone. Keep the session for subsequent copy checks.
    async fn presence<'s>(
        &'s self,
        holder: &str,
        stats: &mut Vec<ProviderSession<'s, C, N, T>>,
        refused: &mut Vec<String>,
        plan: &[ArticleRow],
        providers: &[&'s ProviderConfig],
        full: Option<&ExtentRow>,
    ) -> core::result::Result<Presence, Halt> {
        let now = self.clock.now();
        // The run's sessions sit unused while the pool is read: they are
        // ended if the first of their slots would run out first, as in
        // `idle`. No socket outlives its slot.
        let pool = {
            let limit = stats.iter().map(ProviderSession::idle_ms).min();
            let mut load = core::pin::pin!(Pool::load(&self.catalog, &self.cfg.providers, now));
            match (limit, self.budget.sleeper()) {
                (Some(ms), Some(sleep)) => match select(load.as_mut(), sleep(ms)).await {
                    Either::Left((out, _)) => out,
                    Either::Right(_) => {
                        ProviderSession::close_all(core::mem::take(stats)).await;
                        load.await
                    }
                },
                _ => load.await,
            }
        }?;
        let rows: Vec<&ArticleRow> = plan.iter().collect();
        // As verify asks: the providers that still retain the oldest
        // article first; the others only when none does. A provider past
        // its retention answers 430 for what it no longer keeps, which
        // is no loss of the backbone. One that refused this run's login
        // is not asked again in it.
        let oldest = plan.iter().filter_map(|a| a.posted_at).min();
        let askable: Vec<&ProviderConfig> = providers
            .iter()
            .copied()
            .filter(|p| !refused.contains(&p.id))
            .collect();
        let (mut fresh, expired): (Vec<_>, Vec<_>) =
            askable.into_iter().partition(|p| p.retains(oldest, now));
        if fresh.is_empty() {
            fresh = expired;
        }
        // The sessions kept for other backbones sit unused while this one
        // is asked (a pass that can take several calls): they are set
        // aside, and ended if their slots would run out first.
        let (mine, parked): (Vec<_>, Vec<_>) = core::mem::take(stats)
            .into_iter()
            .partition(|s| providers.iter().any(|p| p.id == s.provider.id));
        *stats = mine;
        let mut order = pool.order(fresh, PermitClass::Background);
        // A provider this run keeps a session on comes first: the session
        // itself counts as load there, and moving to the next one would
        // log in again for every extent.
        if let Some(at) = order
            .iter()
            .position(|p| stats.iter().any(|s| s.provider.id == p.id))
        {
            let kept = order.remove(at);
            order.insert(0, kept);
        }
        // Sessions of this backbone on a provider other than the one to
        // ask first are ended: one session per backbone at most.
        let first = order.first().map(|p| p.id.clone());
        let (stale, keep): (Vec<_>, Vec<_>) = core::mem::take(stats).into_iter().partition(|s| {
            providers.iter().any(|p| p.id == s.provider.id)
                && first.as_deref() != Some(s.provider.id.as_str())
        });
        *stats = keep;
        ProviderSession::close_all(stale).await;
        let limit = parked.iter().map(ProviderSession::idle_ms).min();
        let parked = core::cell::RefCell::new(parked);
        // Ends the sessions set aside (borrowed only to take them out).
        let end_parked = || async {
            let gone: Vec<_> = parked.borrow_mut().drain(..).collect();
            ProviderSession::close_all(gone).await;
        };
        let answer = {
            let ask = async {
                for provider in order {
                    let kept = stats.iter().position(|s| s.provider.id == provider.id);
                    let mut tries = 0;
                    loop {
                        tries += 1;
                        let reused = kept.is_some() && tries == 1;
                        // Whether this run held other sessions when the slot
                        // was asked for (the timer may end the set-aside
                        // ones meanwhile, which frees a slot too).
                        let held = !stats.is_empty() || !parked.borrow().is_empty();
                        let mut session = match kept.filter(|_| reused) {
                            Some(at) => Some(stats.swap_remove(at)),
                            None => self.check_session(provider, holder, full.is_some()).await?,
                        };
                        if session.is_none() && held {
                            let blocks = |s: &ProviderSession<'s, C, N, T>| {
                                s.provider.id == provider.id
                                    || provider
                                        .pool
                                        .as_ref()
                                        .is_some_and(|pool| s.provider.pool.as_ref() == Some(pool))
                            };
                            // Free only slots that could block this provider.
                            // An unrelated busy backbone must not evict healthy sessions.
                            let (mut released, keep): (Vec<_>, Vec<_>) =
                                core::mem::take(stats).into_iter().partition(blocks);
                            *stats = keep;
                            {
                                let mut sessions = parked.borrow_mut();
                                let (mine, keep): (Vec<_>, Vec<_>) =
                                    core::mem::take(&mut *sessions)
                                        .into_iter()
                                        .partition(blocks);
                                *sessions = keep;
                                released.extend(mine);
                            }
                            if !released.is_empty() {
                                ProviderSession::close_all(released).await;
                                session =
                                    self.check_session(provider, holder, full.is_some()).await?;
                            }
                        }
                        let Some(mut session) = session else {
                            break;
                        };
                        let checked = match full {
                            None => ask_articles_together(&mut session, None, &rows, None)
                                .await
                                .map(|tally| (tally.ok as usize == rows.len(), 0)),
                            Some(extent) => Self::body_copy(&mut session, extent, &rows).await,
                        };
                        match checked {
                            Ok((intact, bytes)) => {
                                stats.push(session);
                                return Ok(Presence::Complete { intact, bytes });
                            }
                            // A kept session whose slot expired: a new one.
                            Err(Stop::NoPermit) if reused => {
                                session.close().await;
                                continue;
                            }
                            // The account was refused: not asked again in this
                            // run; the next provider of the backbone is asked.
                            Err(Stop::Refused) => {
                                session.close().await;
                                refused.push(provider.id.clone());
                                break;
                            }
                            Err(Stop::Catalog) => {
                                session.close().await;
                                return Err(Halt::Stopped);
                            }
                            Err(Stop::NoPermit) => {
                                session.close().await;
                                break;
                            }
                            Err(_) => {
                                session.close().await;
                                return if full.is_some() {
                                    Err(Halt::Deferred)
                                } else {
                                    Ok(Presence::Unknown)
                                };
                            }
                        }
                    }
                }
                Ok(Presence::Unknown)
            };
            let mut ask = core::pin::pin!(ask);
            match (limit, self.budget.sleeper()) {
                (Some(ms), Some(sleep)) => match select(ask.as_mut(), sleep(ms)).await {
                    Either::Left((out, _)) => out,
                    Either::Right(_) => {
                        end_parked().await;
                        ask.await
                    }
                },
                _ => ask.await,
            }
        };
        stats.extend(parked.into_inner());
        answer
    }

    async fn body_copy<'s>(
        session: &mut ProviderSession<'s, C, N, T>,
        extent: &ExtentRow,
        rows: &[&ArticleRow],
    ) -> core::result::Result<(bool, u64), Stop> {
        let size = usize::try_from(extent.cipher_size).map_err(|_| Stop::Catalog)?;
        let mut cipher = vec![0; size];
        let mut bytes = 0u64;
        let count = extent.article_count.unwrap_or(0);
        let mut valid_spans = true;
        let tally = read_articles(session, None, rows, |row, payload| {
            bytes += payload.len() as u64;
            if row.idx < count {
                let start = usize::try_from(row.cipher_offset).ok();
                let target = start
                    .and_then(|start| cipher.get_mut(start..start.saturating_add(payload.len())));
                match target {
                    Some(target) => target.copy_from_slice(&payload),
                    None => valid_spans = false,
                }
            }
        })
        .await?;
        Ok((
            tally.ok as usize == rows.len() && valid_spans && digest_ok(extent, &cipher),
            bytes,
        ))
    }

    /// Prefer drill capacity for BODY; STAT can also use spare drill
    /// capacity. Background slots leave a reserve for customer reads.
    async fn check_session<'s>(
        &'s self,
        provider: &'s ProviderConfig,
        holder: &str,
        full: bool,
    ) -> Result<Option<ProviderSession<'s, C, N, T>>> {
        let spare =
            (full && provider.drill_conns != 0) || provider.drill_conns > self.cfg.scrub.sockets;
        let classes: &[PermitClass] = match spare {
            false => &[PermitClass::Background],
            true => &[PermitClass::Drill, PermitClass::Background],
        };
        for class in classes {
            let opened = ProviderSession::open(
                &self.catalog,
                &self.nntp,
                &self.clock,
                provider,
                *class,
                holder,
            )
            .await?;
            if let Some(session) = opened {
                return Ok(Some(session.with_timer(self.budget.sleeper())));
            }
        }
        Ok(None)
    }

    /// The affected copy remains confirmed and is already scheduled to retry.
    fn alert_deferred(&self, extent: &ExtentRow, since: UnixMs) {
        if since.plus_secs(self.cfg.scrub.confirm_secs.saturating_mul(2)) < self.clock.now() {
            crate::trace::alert(|| {
                format!(
                    "scrub-deferred {} a loss seen before: its looks keep breaking off",
                    extent.id.as_str()
                )
            });
        }
    }

    /// Whether some enabled provider posts to the backbone `name`: only
    /// such a provider can be sent an article that backbone lacks.
    fn posts_to(&self, name: &str) -> bool {
        self.cfg
            .providers
            .iter()
            .any(|p| p.post && p.enabled && crate::verify::label(&p.backbone) == name)
    }

    /// A confirmed loss: the bytes from the first source that has them
    /// intact, back in the safety store, and the extent re-pinned.
    async fn repair<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        candidate: &ScrubCandidate,
        found: Found,
        may_repin: bool,
    ) -> core::result::Result<(), Halt> {
        let extent = &candidate.extent;
        let cfg = &self.cfg.scrub;
        let token = walk.token;
        let confirm = u64::from(cfg.confirm_secs);
        let lacking = found.lacking.join(",");
        // Blob reads and writes and catalogue writes follow: no session
        // is to sit open through them.
        Self::hang_up_all(reader, walk.stats).await;
        let read = found.cipher.is_some();
        let (source, cipher) = match found.cipher {
            Some(cipher) if found.rebuilt > 0 => (RepairSource::Parity, Some(cipher)),
            Some(cipher) => (RepairSource::Usenet, Some(cipher)),
            None => match self.stored_copy(extent).await {
                Ok(stored) => stored,
                // A blob store did not answer: not "no copy". Looked at
                // again later, the loss still on record (confirmed).
                Err(()) => {
                    if let Some(since) = candidate.last_scrubbed_at {
                        self.alert_deferred(extent, since);
                    }
                    return Ok(());
                }
            },
        };
        let Some(cipher) = cipher else {
            if found.interrupted {
                // The read broke off: Usenet may well hold it. Not
                // unrecoverable on that, and still confirmed: the next
                // look that finds the loss again repairs it.
                if let Some(since) = candidate.last_scrubbed_at {
                    self.alert_deferred(extent, since);
                }
                return Ok(());
            }
            walk.run.unrecoverable += 1;
            crate::trace::alert(|| {
                format!(
                    "scrub-unrecoverable {} lacking=[{lacking}] no intact copy on Usenet, \
                     in the cache or in the safety store",
                    extent.id.as_str()
                )
            });
            return self
                .scrub_record_one(reader, walk, extent, (ScrubResult::Unrecoverable, None))
                .await;
        };
        // A backbone that lacks articles and that no provider posts to:
        // verify cannot put them back there. The extent is re-pinned all
        // the same: `STAT` and a read assembled across providers do not
        // prove that the backbones left hold it whole, and the pinned
        // copy keeps it at two copies until a release, by its own rule
        // (a full read on record, `REQUIRED_BACKBONES` holding it), says
        // otherwise. The operator is told.
        let counting = crate::verify::release_labels(&self.cfg.providers);
        let unpostable: Vec<&String> = found.lacking.iter().filter(|l| !self.posts_to(l)).collect();
        if !unpostable.is_empty() {
            let names = unpostable
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(",");
            crate::trace::alert(|| {
                format!(
                    "scrub-unpostable {} lacking=[{names}]: no provider posts to it; \
                     a fresh article plan is the repair",
                    extent.id.as_str()
                )
            });
        }
        if !may_repin {
            // Under an incident on a backbone it lacks, or past the run's
            // re-pins: looked at again later.
            walk.run.suspect += 1;
            return self
                .scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, None))
                .await;
        }
        let now = self.clock.now();
        let bound = repair_bound_secs(self.cfg.safety_min_age_secs, cfg.confirm_secs);
        let next = now.plus_ms(i64::try_from(bound * 1000).unwrap_or(i64::MAX));
        // No provider served the bytes: every backbone that counts gets a
        // failed full read, so
        // verify reads each in full and none counts toward the release
        // before it has passed one, whatever `STAT` says (it says
        // "present" for a body no provider serves).
        // Read from Usenet: the backbones that lack articles, or did not
        // serve one whole, get the failed full read, so verify reads them
        // in full (a second loss there that `STAT` does not show is found
        // then, not after the release).
        let unread: Vec<String> = match read {
            true => found.lacking.clone(),
            false => counting,
        };
        // The cache may hold the last good copy. Write it to the safety
        // store before re-pinning, while eviction may still take the
        // cache fill. From Usenet the copy is written after the re-pin:
        // Usenet still holds the bytes meanwhile.
        let key = extent.id.safety_key();
        if source == RepairSource::Cache && !self.put_safety(extent, cipher.clone()).await {
            // A lost reply may hide a write.
            self.collect_if_unreferenced(extent).await?;
            walk.run.suspect += 1;
            return self
                .scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, None))
                .await;
        }
        let repinned = match self
            .catalog
            .scrub_repin(token, &extent.id, (now, next), &unread)
            .await
        {
            Ok(repinned) => repinned,
            Err(e) => {
                // The batch may have committed with its reply lost. One
                // point read tells: re-pinned by this very batch, it goes
                // on as after any re-pin (the copy written and checked,
                // the watch moved up if it is not there). Not known either
                // way, the copy is written all the same. A copy written
                // here or above is not to outlive an extent GC collects.
                match self.catalog.scrub_repin_landed(&extent.id, now).await {
                    Ok(true) => true,
                    Ok(false) => {
                        let _ = self.collect_if_unreferenced(extent).await;
                        return Err(e.into());
                    }
                    Err(_) => {
                        let _ = self.put_safety(extent, cipher.clone()).await;
                        let _ = self.collect_if_unreferenced(extent).await;
                        return Err(e.into());
                    }
                }
            }
        };
        if repinned {
            // Read from Usenet: the copy is written (one in R2 may be
            // there with other bytes). Already in R2 (the safety copy just
            // read, or the cache copy written before the re-pin): it is
            // looked for, since an eviction that began before the re-pin
            // may have deleted it, and written if it is not there.
            let in_r2 = matches!(source, RepairSource::Safety | RepairSource::Cache);
            let mut there = in_r2 && matches!(self.safety.head(&key).await, Ok(Some(_)));
            let mut wrote = false;
            for _ in 0..2 {
                if there {
                    break;
                }
                wrote = true;
                there = self.put_safety(extent, cipher.clone()).await
                    && matches!(self.safety.head(&key).await, Ok(Some(_)));
            }
            // Right after the PUTs, before any other write can fail.
            let collected = match wrote {
                true => self.collect_if_unreferenced(extent).await,
                false => Ok(()),
            };
            walk.run.repaired += 1;
            crate::trace::alert(|| {
                format!(
                    "scrub-repair {} source={} lacking=[{lacking}]",
                    extent.id.as_str(),
                    source.as_str()
                )
            });
            if !there {
                // Pinned without its copy: verify cannot post from it. The
                // watch looks again after the confirm interval, not at the
                // bound.
                crate::trace::alert(|| {
                    format!(
                        "scrub-repair-copy-missing {} the safety copy could not be written",
                        extent.id.as_str()
                    )
                });
                let next = self
                    .clock
                    .now()
                    .plus_ms(i64::try_from(confirm * 1000).unwrap_or(i64::MAX));
                self.catalog.scrub_defer(token, &extent.id, next).await?;
            }
            collected?;
            return Ok(());
        }
        // A refusal or a failed safety GET is not permission to delete:
        // another run may need this copy. Only GC may remove the write,
        // and only if the catalogue proves the extent is unreferenced.
        if source == RepairSource::Cache {
            self.catalog
                .gc_enqueue_scrub_safety(&extent.id, self.clock.now())
                .await?;
        }
        walk.run.suspect += 1;
        self.scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, None))
            .await
    }

    /// Read the intact safety copy, or fall back to an intact cache copy.
    /// `Err(())` means no intact copy was found and at least one read failed.
    async fn stored_copy(
        &self,
        extent: &ExtentRow,
    ) -> core::result::Result<(RepairSource, Option<Vec<u8>>), ()> {
        let safety_answered = match self.safety.get(&extent.id.safety_key(), None).await {
            Ok(Some(bytes)) if digest_ok(extent, &bytes) => {
                return Ok((RepairSource::Safety, Some(bytes)));
            }
            Ok(_) => true,
            Err(_) => false,
        };
        match self.cache.get(&extent.id.cache_key(), None).await {
            Ok(Some(bytes)) if digest_ok(extent, &bytes) => Ok((RepairSource::Cache, Some(bytes))),
            Ok(_) if safety_answered => Ok((RepairSource::Usenet, None)),
            _ => Err(()),
        }
    }

    /// The PUT intents whose PUT can no longer land (the invocation that
    /// sent it has ended, [`JOB_MAX_AGE_MS`]): each gets the guarded GC
    /// enqueue, a no-op while the extent is referenced, then goes. At most
    /// [`SCRUB_PAGE`] a run; an intent that fails stays for the next.
    async fn reconcile_put_intents(&self, now: UnixMs) -> Result<()> {
        for extent in self.catalog.scrub_put_intents_due(now, SCRUB_PAGE).await? {
            self.catalog.gc_enqueue_scrub_safety(&extent, now).await?;
            self.catalog.scrub_drop_put_intent(&extent).await?;
        }
        Ok(())
    }

    /// After a safety PUT made past the last catalogue check, whatever its
    /// answer (a lost reply may hide a write): a guarded `delete_safety`
    /// row, inserted only if the extent is unreferenced now. Garbage
    /// collection that ended before the PUT landed then runs again; while
    /// the extent is referenced nothing is inserted, and a collection
    /// that begins later finds the copy already there.
    async fn collect_if_unreferenced(&self, extent: &ExtentRow) -> Result<()> {
        self.catalog
            .gc_enqueue_scrub_safety(&extent.id, self.clock.now())
            .await
    }

    /// Writes verified ciphertext as the extent's safety copy, behind a
    /// write-ahead intent: the intent is on record before the PUT is sent,
    /// so a run that stops between the PUT and its catalogue update (or
    /// the guarded GC enqueue after it) leaves it for a later run to
    /// reconcile ([`Self::reconcile_put_intents`]). No intent, no PUT.
    async fn put_safety(&self, extent: &ExtentRow, cipher: Vec<u8>) -> bool {
        if !digest_ok(extent, &cipher) {
            return false;
        }
        let until = self.clock.now().plus_ms(JOB_MAX_AGE_MS);
        if self
            .catalog
            .scrub_put_intent(&extent.id, until)
            .await
            .is_err()
        {
            return false;
        }
        let meta = BlobMeta {
            bucket: &extent.bucket_id,
            extent: &extent.id,
            cipher_sha256: &extent.cipher_sha256,
        };
        self.safety
            .put(&extent.id.safety_key(), cipher, &meta)
            .await
            .is_ok()
    }

    /// A re-pinned extent at its repair bound, still pinned: the repair
    /// has stalled. Its safety copy is made sure of, from Usenet or the
    /// cache if it is gone.
    async fn watch_repair<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        candidate: &ScrubCandidate,
        plan: StoredPlan,
    ) -> core::result::Result<Option<UnixMs>, Halt> {
        let extent = &candidate.extent;
        let cfg = &self.cfg.scrub;
        let bound = repair_bound_secs(self.cfg.safety_min_age_secs, cfg.confirm_secs);
        let after = |secs: u64| {
            self.clock
                .now()
                .plus_ms(i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX))
        };
        // An early look: the re-pin could not write the copy and asked to
        // be looked at again after the confirm interval. Before the bound
        // the repair has not stalled; it only needs its copy.
        let deadline = candidate
            .last_scrubbed_at
            .map(|at| at.plus_ms(i64::try_from(bound * 1000).unwrap_or(i64::MAX)));
        let early = candidate.last == Some(ScrubResult::Repairing)
            && deadline.is_some_and(|d| self.clock.now() < d);
        // Blob reads come first: no session sits open through them.
        Self::hang_up_all(reader, walk.stats).await;
        // No live object holds it any more (deleted or overwritten while
        // it was pinned): garbage collection's, not the scrub's. Nothing
        // is read or written for it again.
        if !self.catalog.scrub_live(&extent.id).await? {
            self.catalog.scrub_drop(walk.token, &extent.id).await?;
            return Ok(None);
        }
        // One charge for all this holds at once: the safety copy read
        // back, or a read from Usenet and the copy written from it.
        let bytes = cold_step_bytes(extent.cipher_size, reader.sockets());
        let Ok(_charge) = self.budget.charge_job(bytes).await else {
            return Err(Halt::Busy);
        };
        // A store that did not answer is not a missing copy: no
        // `unrecoverable` on it (`unknown`).
        let (kept, mut unknown) = match self.safety.get(&extent.id.safety_key(), None).await {
            Ok(Some(bytes)) => (digest_ok(extent, &bytes), false),
            Ok(None) => (false, false),
            Err(_) => (false, true),
        };
        let mut rewrote = false;
        if !kept {
            let read = reader.fetch_planned(extent, plan, self.clock.now()).await;
            let (cipher, interrupted) = match read? {
                ColdFetch::Filled(cipher) => {
                    walk.run.bytes_read += extent.cipher_size;
                    (Some(cipher), false)
                }
                ColdFetch::Unavailable | ColdFetch::Unrecoverable => (None, false),
                ColdFetch::Busy => return Err(Halt::Busy),
                // The read broke off: Usenet may well hold it, and the
                // cache is still asked.
                ColdFetch::Interrupted => (None, true),
            };
            reader.hang_up().await;
            let cipher = match cipher {
                Some(cipher) => Some(cipher),
                None => match self.cache.get(&extent.id.cache_key(), None).await {
                    Ok(Some(bytes)) if digest_ok(extent, &bytes) => Some(bytes),
                    Ok(_) => None,
                    Err(_) => {
                        unknown = true;
                        None
                    }
                },
            };
            if cipher.is_none() && (interrupted || unknown) {
                // Nothing is known to be lost: looked at again after the
                // confirm interval.
                let next = after(u64::from(cfg.confirm_secs));
                self.catalog
                    .scrub_defer(walk.token, &extent.id, next)
                    .await?;
                return Ok(Some(next));
            }
            match cipher {
                Some(cipher) => {
                    rewrote = self.put_safety(extent, cipher).await;
                    // Written after the liveness check above.
                    self.collect_if_unreferenced(extent).await?;
                }
                None => {
                    walk.run.unrecoverable += 1;
                    crate::trace::alert(|| {
                        format!(
                            "scrub-unrecoverable {} re-pinned, its safety copy is gone and no \
                             intact copy is on Usenet or in the cache",
                            extent.id.as_str()
                        )
                    });
                    let next = Some(after(u64::from(cfg.confirm_secs)));
                    self.scrub_record_one(reader, walk, extent, (ScrubResult::Unrecoverable, next))
                        .await?;
                    return Ok(next);
                }
            }
        }
        if early {
            let next = match (kept || rewrote, deadline) {
                (true, Some(deadline)) => deadline,
                _ => {
                    crate::trace::alert(|| {
                        format!(
                            "scrub-repair-copy-missing {} the safety copy could not be written",
                            extent.id.as_str()
                        )
                    });
                    after(u64::from(cfg.confirm_secs))
                }
            };
            self.catalog
                .scrub_defer(walk.token, &extent.id, next)
                .await?;
            return Ok(Some(next));
        }
        walk.run.stalled += 1;
        crate::trace::alert(|| {
            format!(
                "scrub-stalled {} still pinned at its repair bound; safety copy {}",
                extent.id.as_str(),
                match (kept, rewrote) {
                    (true, _) => "intact",
                    (false, true) => "written again",
                    (false, false) => "missing, not written",
                }
            )
        });
        // A copy that could not be written is tried again soon, not at
        // the next bound.
        let next = Some(after(if kept || rewrote {
            bound
        } else {
            u64::from(cfg.confirm_secs)
        }));
        self.scrub_record_one(reader, walk, extent, (ScrubResult::Stalled, next))
            .await?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_breaker_needs_both_a_count_and_a_share() {
        // Fewer than 8 never trips, however large the share.
        assert!(!breaker_trips(7, 7));
        // 8 of 96 is 8.3 %: scattered loss, repaired.
        assert!(!breaker_trips(8, 96));
        // 12 of 100 is not more than 12 %.
        assert!(!breaker_trips(12, 100));
        assert!(breaker_trips(13, 100));
        assert!(breaker_trips(8, 8));
        assert!(breaker_trips(8, 66));
        assert!(!breaker_trips(8, 67));
    }

    #[test]
    fn the_repair_bound_is_the_sum_of_what_it_waits_for() {
        // Production: SAFETY_MIN_AGE_SECS 86,400 and the default confirm.
        assert_eq!(
            repair_bound_secs(86_400, 3600),
            86_400 + 25_920 + 21_600 + 3600
        );
        assert_eq!(repair_bound_secs(0, 1), 25_920 + 21_600 + 1);
    }

    #[test]
    fn the_breaker_counts_each_backbone_and_kind_apart() {
        let mut b = Breaker::default();
        let observation = |name: &str, full, intact| Observation {
            backbone: name.into(),
            full,
            intact,
        };
        for _ in 0..60 {
            b.note(&[observation("b", true, true), observation("a", false, true)]);
        }
        for _ in 0..7 {
            b.note(&[observation("a", true, false)]);
        }
        assert!(b.tripped().is_empty());
        b.note(&[observation("a", true, false)]);
        assert_eq!(b.tripped(), [("a".into(), true, 8, 8)]);
    }
}
