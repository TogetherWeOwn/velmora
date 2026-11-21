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
//! `SCRUB_RUN_SECS`, at the first provider without a free slot, or when
//! the breaker trips. The lease lasts as long as a queue invocation can
//! ([`JOB_MAX_AGE_MS`]), so a run that died frees it by itself.
//!
//! # A check
//!
//! - Every backbone that counts toward a release is asked with `STAT`
//!   for every article, all at once (one provider each, on one of its
//!   drill connections if one is free, else on a background slot of its
//!   `max_conns`, which leaves a slot for reads).
//! - The extent is read whole with the drill reader of
//!   `POST /_admin/drill`: every article from the first provider that
//!   has it intact, checked against its SHA-256, and the ciphertext
//!   against the extent's digest. Nothing unverified is ever kept.
//! - Ok: every article read and every backbone holds every article.
//!   Otherwise a loss: a backbone lacks articles, or no provider served
//!   one intact.
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
//!   backbone, or parity once the reader rebuilds from it), else from
//!   the cache copy, else from the safety copy if it is still in R2; each
//!   is checked against the extent's digest first.
//! - No intact copy anywhere: `unrecoverable`, an alert line, and a
//!   check again after `SCRUB_CONFIRM_SECS` (a backbone that was down
//!   may come back).
//! - A re-pinned extent is looked at again when its repair should have
//!   ended ([`repair_bound_secs`]). Still pinned, it is `stalled`, with an
//!   alert line; a safety copy that is gone meanwhile is written again.
//!
//! # Valves
//!
//! - The breaker: a run that finds 8 or more of the extents it checked,
//!   and more than 12 % of them, lacking articles on one backbone stops
//!   and repairs nothing more there. That is a backbone event (an outage,
//!   a purge, a provider answering `430` while throttled), not lost
//!   articles: re-pinning would copy the store back into R2. From then on
//!   at most one loss a run on that backbone is re-pinned
//!   ([`BLOCKED_REPINS_PER_RUN`]); the others stay `suspect`, until 8
//!   checks in a row, across runs, find nothing lacking there.
//! - At most `SCRUB_REPAIRS_PER_RUN` re-pins per run.

use futures_util::future::{select, Either};
use sha2::{Digest, Sha256};

use crate::fetch::ProviderSession;
use crate::fetch::{ask_articles_together, cold_step_bytes, ColdFetch, ColdReader, ColdStats};
use crate::jobtable::JOB_MAX_AGE_MS;
use crate::pool::Pool;
use crate::ports::PermitClass;
use crate::ports::{BlobMeta, BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::post::Stop;
use crate::types::{
    ArticleRow, ArticleState, ExtentRow, JobOutcome, ProviderConfig, Result, SafetyState,
    ScrubCandidate, ScrubEnd, ScrubResult, ScrubRun, UnixMs,
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
    /// parity. The reader reports rebuilt articles once it rebuilds
    /// ([`rebuilt`]); until then no read is this.
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

/// Articles the reader rebuilt from parity between two of its stats:
/// the hook of the parity read. The reader on this version does not
/// rebuild, so it is 0; the reader that does counts them in its stats,
/// and this is where they are read.
fn rebuilt(_before: &ColdStats, _after: &ColdStats) -> u32 {
    0
}

/// What one backbone said to `STAT` for every article.
enum Presence {
    /// The indexes of the articles it lacks (empty: it holds them all),
    /// and the provider that said so.
    Lacks(Vec<u32>, String),
    /// No slot, or it could not be asked: nothing is known.
    Unknown,
}

/// What the backbones that count said to `STAT`.
#[derive(Default)]
struct Asked {
    /// The labels of those that lack articles.
    lacking: Vec<String>,
    /// Each backbone, and the provider that answered for it.
    by: Vec<(String, String)>,
}

/// What a check of a released extent found.
struct Found {
    /// The backbones that lack articles, by label.
    lacking: Vec<String>,
    /// The ciphertext, if the read got all of it intact.
    cipher: Option<Vec<u8>>,
    /// Articles rebuilt from parity by the read.
    rebuilt: u32,
    /// Articles one provider did not serve intact that another did.
    refetched: u32,
    /// The read broke off: `cipher` is `None` for that, not because no
    /// provider has the bytes.
    interrupted: bool,
    /// The bytes the read holds, charged until the check is done with.
    _charge: Option<crate::ingress::Charge>,
}

impl Found {
    fn loss(&self) -> bool {
        !self.lacking.is_empty() || self.cipher.is_none()
    }
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
    /// The `STAT` sessions, kept from one extent to the next.
    stats: &'w mut Vec<ProviderSession<'s, C, N, T>>,
    /// Providers that refused this run's login: not asked again in it.
    refused: Vec<String>,
    /// Re-pins of this run for a loss on a backbone under an incident.
    blocked_repins: u32,
    /// Checks in a row, since the last trip and across runs, that found
    /// nothing lacking on a backbone under an incident. A check that does
    /// sets it back to 0.
    clean: u64,
}

/// The breaker's tally for one run.
#[derive(Default)]
struct Breaker {
    checked: u32,
    /// Per backbone label: the extents that lacked articles there.
    lacking: Vec<(String, u32)>,
}

impl Breaker {
    fn note(&mut self, found: &Found) {
        self.checked += 1;
        for name in &found.lacking {
            match self.lacking.iter_mut().find(|(b, _)| b == name) {
                Some((_, n)) => *n += 1,
                None => self.lacking.push((name.clone(), 1)),
            }
        }
    }

    /// The backbones it trips for, with their counts.
    fn tripped(&self) -> Vec<(&str, u32)> {
        self.lacking
            .iter()
            .filter(|(_, n)| breaker_trips(*n, self.checked))
            .map(|(b, n)| (b.as_str(), *n))
            .collect()
    }
}

/// Whether `lacking` and `checked` trip the breaker (for tests and the
/// operator's arithmetic).
pub fn breaker_trips(lacking: u32, checked: u32) -> bool {
    lacking >= INCIDENT_MIN_EXTENTS
        && u64::from(lacking) * 100 > u64::from(checked) * u64::from(INCIDENT_PERCENT)
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
        // No repair on a backbone that tripped the breaker, until a run
        // that could have tripped it again did not.
        let blocked = state.blocked();
        let mut run = ScrubRun::default();
        let mut breaker = Breaker::default();
        let mut stats = Vec::new();
        let mut walk = Walk {
            token,
            run: &mut run,
            breaker: &mut breaker,
            blocked,
            stats: &mut stats,
            refused: Vec::new(),
            blocked_repins: 0,
            clean: state.incident_clean,
        };
        let ended = self.scrub_pages(started, &mut reader, &mut walk).await;
        let blocked = core::mem::take(&mut walk.blocked);
        let clean = walk.clean;
        ProviderSession::close_all(stats).await;
        reader.close().await;
        run.ended = ended;
        if ended == ScrubEnd::Busy && run.checked == 0 {
            // A provider had no slot, or a backbone that counts could not
            // be asked at all (all its providers cooling or refused): the
            // run could check nothing.
            crate::trace::alert(|| "scrub-no-progress ended=busy checked=0".to_owned());
        }
        // The backbones under an incident after this run: its own trip
        // adds one; a run that checked enough extents to trip the
        // breaker and did not clears them all.
        // (A trip starts the count of clean checks again; once runs
        // without a trip have checked as many extents as a trip needs,
        // the incidents clear.)
        (run.blocked, run.incident_clean) = match &run.incident {
            // Every backbone that tripped is in `blocked` already.
            Some(_) => (blocked, 0),
            None if blocked.is_empty() => (blocked, 0),
            None => match clean >= u64::from(INCIDENT_MIN_EXTENTS) {
                true => (Vec::new(), 0),
                false => (blocked, clean),
            },
        };
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
        let mut taken = 0u32;
        // An extent this run has looked at is not looked at again in it,
        // whatever it left on the row (a write that did not land, say).
        let mut seen: Vec<crate::types::ExtentId> = Vec::new();
        loop {
            let left = cfg.extents_per_run - taken;
            if left == 0 {
                return ScrubEnd::Quota;
            }
            let now = self.clock.now();
            if now >= deadline {
                return ScrubEnd::Time;
            }
            let due = self.catalog.scrub_due(now, left.min(SCRUB_PAGE));
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
                taken += 1;
                match self.scrub_one(reader, candidate, walk).await {
                    Ok(()) => {}
                    Err(Halt::Busy) => return ScrubEnd::Busy,
                    Err(Halt::Stopped) => return ScrubEnd::Stopped,
                    // Handled where it arises; never reaches here.
                    Err(Halt::Deferred) => {}
                }
                if walk.run.incident.is_some() {
                    return ScrubEnd::Incident;
                }
            }
        }
    }

    async fn scrub_record_one<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        extent: &ExtentRow,
        (result, next_in_secs): (ScrubResult, u64),
    ) -> core::result::Result<(), Halt> {
        let token = walk.token;
        let now = self.clock.now();
        let next =
            now.plus_ms(i64::try_from(next_in_secs.saturating_mul(1000)).unwrap_or(i64::MAX));
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
        walk: &mut Walk<'_, 's, C, N, T>,
    ) -> core::result::Result<(), Halt> {
        let cfg = &self.cfg.scrub;
        let token = walk.token;
        let extent = &candidate.extent;
        // Only the scrub gives a held extent a due time: it re-pinned it.
        let repinned = matches!(
            candidate.last,
            Some(ScrubResult::Repairing | ScrubResult::Stalled | ScrubResult::Unrecoverable)
        );
        let interval = u64::from(cfg.interval_days) * 86_400;
        let confirm = u64::from(cfg.confirm_secs);
        let plan = match extent.safety_state {
            SafetyState::Released => {
                // An extent no live object holds (deleted or overwritten,
                // before garbage collection) is not read, and never
                // brought back.
                let live = self.catalog.scrub_live(&extent.id);
                if !self.idle(reader, walk.stats, live).await? {
                    return self
                        .scrub_record_one(reader, walk, extent, (ScrubResult::Skipped, interval))
                        .await;
                }
                let plan = self.catalog.articles(&extent.id);
                self.idle(reader, walk.stats, plan).await?
            }
            SafetyState::Held | SafetyState::Releasing if repinned => {
                let plan = self.catalog.articles(&extent.id).await?;
                return self.watch_repair(reader, walk, candidate, plan).await;
            }
            // Deleted, or pinned by something else than the scrub: off
            // the due list (it leaves the index with its due time).
            _ => {
                self.catalog.scrub_drop(token, &extent.id).await?;
                return Ok(());
            }
        };
        if plan.is_empty() || plan.iter().any(|a| a.state != ArticleState::Posted) {
            // Not on Usenet in full: nothing to read back.
            return self
                .scrub_record_one(reader, walk, extent, (ScrubResult::Skipped, interval))
                .await;
        }

        let found = match self.check(reader, walk, extent, plan).await {
            Ok(found) => found,
            // The read broke off (a provider went away under it, or one
            // that may still hold an article is cooling): nothing is
            // known. Looked at again after the confirm interval; the run
            // goes on, so one such extent does not hold up the rest.
            Err(Halt::Deferred) => {
                // A loss seen before stays on record: the next look that
                // finds it again confirms it, whatever broke off between.
                if matches!(
                    candidate.last,
                    Some(ScrubResult::Suspect | ScrubResult::Unrecoverable)
                ) {
                    return self.defer_seen(token, candidate, confirm).await;
                }
                if candidate.last == Some(ScrubResult::Deferred) {
                    crate::trace::alert(|| {
                        format!(
                            "scrub-deferred {} the read broke off twice in a row",
                            extent.id.as_str()
                        )
                    });
                }
                return self
                    .scrub_record_one(reader, walk, extent, (ScrubResult::Deferred, confirm))
                    .await;
            }
            Err(halt) => return Err(halt),
        };
        match found.lacking.iter().any(|l| walk.blocked.contains(l)) {
            true => walk.clean = 0,
            false => walk.clean += 1,
        }
        {
            let run = &mut *walk.run;
            run.checked += 1;
            walk.breaker.note(&found);
            if found.cipher.is_some() {
                run.bytes_read += extent.cipher_size;
            }
        }
        if !found.loss() {
            walk.run.ok += 1;
            // Articles a provider did not serve and another did: counted
            // for the run's line. Not an alert: a `430` from a provider of
            // a backbone that does not count is one of them.
            walk.run.refetched += found.refetched;
            return self
                .scrub_record_one(reader, walk, extent, (ScrubResult::Ok, interval))
                .await;
        }

        let confirmed = matches!(
            candidate.last,
            Some(ScrubResult::Suspect | ScrubResult::Unrecoverable)
        );
        let tripped: Vec<(String, u32)> = walk
            .breaker
            .tripped()
            .into_iter()
            .map(|(b, n)| (b.to_owned(), n))
            .collect();
        if !tripped.is_empty() {
            let checked = walk.breaker.checked;
            for (backbone, lacking) in &tripped {
                crate::trace::alert(|| format!("scrub-incident {backbone} {lacking}/{checked}"));
                if !walk.blocked.contains(backbone) {
                    walk.blocked.push(backbone.clone());
                }
            }
            walk.run.incident = tripped.first().map(|(b, _)| b.clone());
            walk.clean = 0;
            // Stored now, under the lease: a run that dies before its end
            // still leaves the next one blocked.
            let _ = self.catalog.scrub_block(token, &walk.blocked).await;
            if confirmed {
                // Classified as any confirmed loss (unrecoverable when no
                // copy is left), but not re-pinned.
                return self.repair(reader, walk, candidate, found, false).await;
            }
            walk.run.suspect += 1;
            return self
                .scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, confirm))
                .await;
        }

        if !confirmed {
            walk.run.suspect += 1;
            return self
                .scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, confirm))
                .await;
        }
        // Held back from a re-pin, not from the finding: an extent with
        // no intact copy anywhere is still said to be unrecoverable.
        let under_incident = found.lacking.iter().any(|l| walk.blocked.contains(l));
        let may_repin = (!under_incident || walk.blocked_repins < BLOCKED_REPINS_PER_RUN)
            && walk.run.repaired < cfg.repairs_per_run;
        let repaired = walk.run.repaired;
        let done = self.repair(reader, walk, candidate, found, may_repin).await;
        if under_incident && walk.run.repaired > repaired {
            walk.blocked_repins += 1;
        }
        done
    }

    /// `STAT` on every backbone that counts, then the whole extent read
    /// with the scrub's reader.
    async fn check<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        walk: &mut Walk<'_, 's, C, N, T>,
        extent: &ExtentRow,
        plan: Vec<ArticleRow>,
    ) -> core::result::Result<Found, Halt> {
        // The reader's sessions wait while the backbones are asked.
        let holder = reader.holder().to_owned();
        // Taken before the race: the reader's timer may end its sessions
        // while a backbone waits for a slot one of them held.
        let reader_held = reader.idle_ms().is_some();
        let lacking = {
            let asked = self.presence_all(&holder, walk.stats, &mut walk.refused, &plan);
            let mut asked = core::pin::pin!(asked);
            let limit = reader.idle_ms();
            match (limit, self.budget.sleeper()) {
                (Some(ms), Some(sleep)) => match select(asked.as_mut(), sleep(ms)).await {
                    Either::Left((out, _)) => out,
                    Either::Right(_) => {
                        reader.hang_up().await;
                        asked.await
                    }
                },
                _ => asked.await,
            }
        };
        // No slot to ask a backbone with while the reader keeps sessions
        // from the extent before: the slot may be one of them (a provider
        // with one background slot). They are ended and it is asked once
        // more.
        let asked = match lacking {
            Err(Halt::Busy) if reader_held => {
                reader.hang_up().await;
                self.presence_all(&holder, walk.stats, &mut walk.refused, &plan)
                    .await
            }
            other => other,
        }?;
        let lacking = asked.lacking;

        let bytes = cold_step_bytes(extent.cipher_size, reader.sockets());
        // The wait for room in the byte budget is no provider call: the
        // run's sessions are ended if their slots would run out first.
        let charged = self.budget.charge_job(bytes);
        let Ok(charge) = self.idle(reader, walk.stats, charged).await else {
            return Err(Halt::Busy);
        };
        let before = reader.stats();
        // The `STAT` sessions wait while the extent is read.
        let plan_again = plan.clone();
        // Taken before the race, as above: the `STAT` sessions' timer may
        // end them while the read waits for a slot one of them held.
        let stats_held = !walk.stats.is_empty();
        let read = {
            let limit = walk.stats.iter().map(ProviderSession::idle_ms).min();
            let fetch = reader.fetch_planned(extent, plan);
            let mut fetch = core::pin::pin!(fetch);
            match (limit, self.budget.sleeper()) {
                (Some(ms), Some(sleep)) => match select(fetch.as_mut(), sleep(ms)).await {
                    Either::Left((out, _)) => out,
                    Either::Right(_) => {
                        ProviderSession::close_all(core::mem::take(walk.stats)).await;
                        fetch.await
                    }
                },
                _ => fetch.await,
            }
        };
        // No slot for the read while the run keeps `STAT` sessions: the
        // slot may be one of them (a provider without drill connections
        // and one background slot). They are ended and the read asked
        // once more.
        let read = match read {
            Ok(ColdFetch::Busy) if stats_held => {
                ProviderSession::close_all(core::mem::take(walk.stats)).await;
                reader.fetch_planned(extent, plan_again).await
            }
            other => other,
        };
        let after = reader.stats();
        let interrupted = matches!(read, Ok(ColdFetch::Interrupted));
        // The provider that answered `STAT` for a backbone that counts
        // did not serve an article whole: that backbone does not hold the
        // extent whole (another of its accounts says nothing of it).
        let mut lacking = lacking;
        for (name, by) in asked.by {
            let count = |s: &ColdStats| s.failed.iter().find(|f| f.0 == by).map_or(0, |f| f.1);
            if count(&after) > count(&before) && !lacking.contains(&name) {
                lacking.push(name);
            }
        }
        let cipher = match read? {
            ColdFetch::Filled(cipher) => Some(cipher),
            ColdFetch::Unavailable => None,
            // No provider that may hold a missing article has a free
            // slot: the run waits for the next one.
            ColdFetch::Busy => return Err(Halt::Busy),
            // A backbone already said it lacks articles: that is the
            // finding, whatever became of the read.
            ColdFetch::Interrupted if !lacking.is_empty() => None,
            ColdFetch::Interrupted => return Err(Halt::Deferred),
        };
        Ok(Found {
            lacking,
            cipher,
            rebuilt: rebuilt(&before, &after),
            refetched: after.refetched.saturating_sub(before.refetched),
            interrupted,
            _charge: Some(charge),
        })
    }

    /// The labels of the backbones that count and lack articles of
    /// `plan`. `Busy`: a backbone could not be asked.
    async fn presence_all<'s>(
        &'s self,
        holder: &str,
        stats: &mut Vec<ProviderSession<'s, C, N, T>>,
        refused: &mut Vec<String>,
        plan: &[ArticleRow],
    ) -> core::result::Result<Asked, Halt> {
        let mut asked = Asked::default();
        for (name, providers) in release_backbones(&self.cfg.providers) {
            match self
                .presence(holder, stats, refused, plan, &providers)
                .await?
            {
                Presence::Lacks(missing, by) => {
                    if !missing.is_empty() {
                        asked.lacking.push(name.clone());
                    }
                    asked.by.push((name, by));
                }
                Presence::Unknown => return Err(Halt::Busy),
            }
        }
        Ok(asked)
    }

    /// What one backbone holds of `plan`, asked with `STAT` of one of its
    /// `providers`, all articles at once. The session is kept in
    /// `stats` for the next extent of the run: one login per backbone
    /// and run, not per extent. A kept session whose slot was lost is
    /// ended and one is opened anew; a kept session on a provider the
    /// backbone no longer asks first is ended.
    async fn presence<'s>(
        &'s self,
        holder: &str,
        stats: &mut Vec<ProviderSession<'s, C, N, T>>,
        refused: &mut Vec<String>,
        plan: &[ArticleRow],
        providers: &[&'s ProviderConfig],
    ) -> core::result::Result<Presence, Halt> {
        let now = self.clock.now();
        let pool = Pool::load(&self.catalog, &self.cfg.providers, now).await?;
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
                            None => self.stat_session(provider, holder).await?,
                        };
                        if session.is_none() && held {
                            // The slot may be one this run keeps for another
                            // backbone (providers that share a pool): those are
                            // ended, and the slot asked for once more.
                            ProviderSession::close_all(core::mem::take(stats)).await;
                            end_parked().await;
                            session = self.stat_session(provider, holder).await?;
                        }
                        let Some(mut session) = session else {
                            break;
                        };
                        let tally = ask_articles_together(&mut session, None, &rows, None).await;
                        match tally {
                            Ok(tally) => {
                                stats.push(session);
                                let mut lacks = tally.missing;
                                // Never a size pass here, so `corrupt` stays
                                // empty; a provider that says so lacks it.
                                lacks.extend(tally.corrupt);
                                return Ok(Presence::Lacks(lacks, provider.id.clone()));
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
                            Err(_) => {
                                session.close().await;
                                return Ok(Presence::Unknown);
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

    /// A slot to ask `provider` with: one of its drill connections when
    /// it has more of them than the reader can hold (`SCRUB_SOCKETS`),
    /// so the session never takes one the reader needs; else a
    /// background slot of its `max_conns`, which keeps one for reads.
    /// `None`: none is free.
    async fn stat_session<'s>(
        &'s self,
        provider: &'s ProviderConfig,
        holder: &str,
    ) -> Result<Option<ProviderSession<'s, C, N, T>>> {
        let spare = provider.drill_conns > self.cfg.scrub.sockets;
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

    /// A loss seen before (`suspect` or `unrecoverable`) whose look broke
    /// off: looked at again after the confirm interval with its result
    /// kept, so the next look that finds the loss confirms it. The time
    /// of the last look that ended stays as it is: once it is more than
    /// two confirm intervals old, the looks keep breaking off and that is
    /// said (`scrub-deferred`) on each of them.
    async fn defer_seen(
        &self,
        token: u64,
        candidate: &ScrubCandidate,
        confirm: u64,
    ) -> core::result::Result<(), Halt> {
        let now = self.clock.now();
        let confirm_ms = i64::try_from(confirm * 1000).unwrap_or(i64::MAX);
        let stale = candidate
            .last_scrubbed_at
            .is_some_and(|at| at.plus_ms(confirm_ms.saturating_mul(2)) < now);
        if stale {
            crate::trace::alert(|| {
                format!(
                    "scrub-deferred {} a loss seen before: its looks keep breaking off",
                    candidate.extent.id.as_str()
                )
            });
        }
        self.catalog
            .scrub_defer(token, &candidate.extent.id, now.plus_ms(confirm_ms))
            .await?;
        Ok(())
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
                Err(()) => return self.defer_seen(token, candidate, confirm).await,
            },
        };
        let Some(cipher) = cipher else {
            if found.interrupted {
                // The read broke off: Usenet may well hold it. Not
                // unrecoverable on that, and still confirmed: the next
                // look that finds the loss again repairs it.
                return self.defer_seen(token, candidate, confirm).await;
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
                .scrub_record_one(reader, walk, extent, (ScrubResult::Unrecoverable, confirm))
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
                .scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, confirm))
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
        // The cache copy is the last copy when it is the source (Usenet
        // lacks it everywhere and the safety copy is gone): it is written
        // to the safety store before the re-pin, while the eviction may
        // still take the cache fill, and taken back if the guard refuses
        // (it did not exist before). From Usenet the copy is written
        // after the re-pin: Usenet still holds the bytes meanwhile.
        let key = extent.id.safety_key();
        if source == RepairSource::Cache && !self.put_safety(extent, cipher.clone()).await {
            walk.run.suspect += 1;
            return self
                .scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, confirm))
                .await;
        }
        let repinned = self
            .catalog
            .scrub_repin(token, &extent.id, (now, next), &unread)
            .await;
        if source == RepairSource::Cache && matches!(repinned, Ok(false)) {
            // Written for this re-pin alone, and the guard refused it (an
            // answer, not an error: after an error the re-pin may have
            // gone through, and the copy stays).
            let _ = crate::recovery::delete_blob(&self.safety, &key).await;
        }
        if repinned? {
            // Read from Usenet: the copy is written (one in R2 may be
            // there with other bytes). Already in R2 (the safety copy just
            // read, or the cache copy written before the re-pin): it is
            // looked for, since an eviction that began before the re-pin
            // may have deleted it, and written if it is not there.
            let in_r2 = matches!(source, RepairSource::Safety | RepairSource::Cache);
            let mut there = in_r2 && matches!(self.safety.head(&key).await, Ok(Some(_)));
            for _ in 0..2 {
                if there {
                    break;
                }
                there = self.put_safety(extent, cipher.clone()).await
                    && matches!(self.safety.head(&key).await, Ok(Some(_)));
            }
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
            return Ok(());
        }
        // Refused: the extent is no longer released and done, or no live
        // object holds it, or the lease is gone. Looked at again later.
        walk.run.suspect += 1;
        self.scrub_record_one(reader, walk, extent, (ScrubResult::Suspect, confirm))
            .await
    }

    /// The cache copy if it is intact, else the safety copy if it is.
    /// `Err(())`: a store could not be read, so whether it holds a copy
    /// is not known.
    async fn stored_copy(
        &self,
        extent: &ExtentRow,
    ) -> core::result::Result<(RepairSource, Option<Vec<u8>>), ()> {
        let mut unknown = false;
        // The safety copy first: when it is intact nothing is written.
        for (source, store, key) in [
            (RepairSource::Safety, &self.safety, extent.id.safety_key()),
            (RepairSource::Cache, &self.cache, extent.id.cache_key()),
        ] {
            match store.get(&key, None).await {
                Ok(Some(bytes)) if digest_ok(extent, &bytes) => return Ok((source, Some(bytes))),
                Ok(_) => {}
                Err(_) => unknown = true,
            }
        }
        match unknown {
            true => Err(()),
            false => Ok((RepairSource::Usenet, None)),
        }
    }

    /// Writes verified ciphertext as the extent's safety copy.
    async fn put_safety(&self, extent: &ExtentRow, cipher: Vec<u8>) -> bool {
        if !digest_ok(extent, &cipher) {
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
        plan: Vec<ArticleRow>,
    ) -> core::result::Result<(), Halt> {
        let extent = &candidate.extent;
        let cfg = &self.cfg.scrub;
        let bound = repair_bound_secs(self.cfg.safety_min_age_secs, cfg.confirm_secs);
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
            return Ok(());
        }
        // One charge for all this holds at once: the safety copy read
        // back, or a read from Usenet and the copy written from it.
        let bytes = cold_step_bytes(extent.cipher_size, reader.sockets());
        let Ok(_charge) = self.budget.charge_job(bytes).await else {
            return Err(Halt::Busy);
        };
        let kept = match self.safety.get(&extent.id.safety_key(), None).await {
            Ok(Some(bytes)) => digest_ok(extent, &bytes),
            _ => false,
        };
        let mut rewrote = false;
        if !kept {
            let read = reader.fetch_planned(extent, plan).await;
            let cipher = match read? {
                ColdFetch::Filled(cipher) => {
                    walk.run.bytes_read += extent.cipher_size;
                    Some(cipher)
                }
                ColdFetch::Unavailable => {
                    reader.hang_up().await;
                    match self.cache.get(&extent.id.cache_key(), None).await {
                        Ok(Some(bytes)) if digest_ok(extent, &bytes) => Some(bytes),
                        _ => None,
                    }
                }
                ColdFetch::Busy => return Err(Halt::Busy),
                ColdFetch::Interrupted => {
                    let next = self.clock.now().plus_ms(i64::from(cfg.confirm_secs) * 1000);
                    self.catalog
                        .scrub_defer(walk.token, &extent.id, next)
                        .await?;
                    return Ok(());
                }
            };
            reader.hang_up().await;
            match cipher {
                Some(cipher) => rewrote = self.put_safety(extent, cipher).await,
                None => {
                    walk.run.unrecoverable += 1;
                    crate::trace::alert(|| {
                        format!(
                            "scrub-unrecoverable {} re-pinned, its safety copy is gone and no \
                             intact copy is on Usenet or in the cache",
                            extent.id.as_str()
                        )
                    });
                    let confirm = u64::from(cfg.confirm_secs);
                    return self
                        .scrub_record_one(
                            reader,
                            walk,
                            extent,
                            (ScrubResult::Unrecoverable, confirm),
                        )
                        .await;
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
                    self.clock.now().plus_ms(i64::from(cfg.confirm_secs) * 1000)
                }
            };
            self.catalog
                .scrub_defer(walk.token, &extent.id, next)
                .await?;
            return Ok(());
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
        let next = match kept || rewrote {
            true => bound,
            false => u64::from(cfg.confirm_secs),
        };
        self.scrub_record_one(reader, walk, extent, (ScrubResult::Stalled, next))
            .await
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
    fn the_breaker_counts_each_backbone_apart() {
        let mut b = Breaker::default();
        let found = |lacking: &[&str]| Found {
            lacking: lacking.iter().map(|s| s.to_string()).collect(),
            cipher: Some(Vec::new()),
            rebuilt: 0,
            refetched: 0,
            interrupted: false,
            _charge: None,
        };
        for _ in 0..7 {
            b.note(&found(&["a"]));
            b.note(&found(&["b"]));
        }
        assert!(b.tripped().is_empty());
        b.note(&found(&["a"]));
        assert_eq!(b.tripped(), [("a", 8)]);
    }
}
