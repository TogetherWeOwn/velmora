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
//!   no loss on that backbone is repaired, and the extents stay
//!   `suspect`, until a run that checked enough extents to trip the
//!   breaker ends without tripping it.
//! - At most `SCRUB_REPAIRS_PER_RUN` re-pins per run.

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
    /// The indexes of the articles it lacks (empty: it holds them all).
    Lacks(Vec<u32>),
    /// No slot, or it could not be asked: nothing is known.
    Unknown,
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
    /// The bytes the read holds, charged until the check is done with.
    _charge: Option<crate::ingress::Charge>,
}

impl Found {
    fn loss(&self) -> bool {
        !self.lacking.is_empty() || self.cipher.is_none()
    }
}

/// Why a check stopped the run.
enum Halt {
    /// A provider had no slot, or a read broke off: the extent waits.
    Busy,
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
    /// The backbone of the last breaker trip, while it stands.
    blocked: Option<String>,
    /// The `STAT` sessions, kept from one extent to the next.
    stats: &'w mut Vec<ProviderSession<'s, C, N, T>>,
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

    /// The backbone it trips for, if any, with its count.
    fn tripped(&self) -> Option<(&str, u32)> {
        self.lacking
            .iter()
            .find(|(_, n)| {
                *n >= INCIDENT_MIN_EXTENTS
                    && u64::from(*n) * 100 > u64::from(self.checked) * u64::from(INCIDENT_PERCENT)
            })
            .map(|(b, n)| (b.as_str(), *n))
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
        let state = self.catalog.scrub_state().await?;
        let cfg = &self.cfg.scrub;
        // No repair on a backbone that tripped the breaker, until a run
        // that could have tripped it again did not.
        let blocked = state.last_incident.clone();
        let mut run = ScrubRun::default();
        let mut breaker = Breaker::default();
        let mut reader = self.drill_reader(cfg.sockets)?;
        let mut stats = Vec::new();
        let mut walk = Walk {
            token,
            run: &mut run,
            breaker: &mut breaker,
            blocked,
            stats: &mut stats,
        };
        let ended = self.scrub_pages(started, &mut reader, &mut walk).await;
        ProviderSession::close_all(stats).await;
        reader.close().await;
        run.ended = ended;
        let now = self.clock.now();
        // A run that lost its lease adds nothing: the totals are another
        // run's to add.
        let _ = self.catalog.scrub_end(token, &run, now).await;
        crate::trace::cold_read(|| {
            format!(
                "scrub: checked={} ok={} suspect={} repaired={} unrecoverable={} stalled={} \
                 bytes={} refetched={} ended={:?} ms={}",
                run.checked,
                run.ok,
                run.suspect,
                run.repaired,
                run.unrecoverable,
                run.stalled,
                run.bytes_read,
                run.refetched,
                run.ended,
                now.0 - started.0
            )
        });
        Ok(Some(run))
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
            let ask = left.min(SCRUB_PAGE).saturating_add(seen.len() as u32);
            let page = match self.catalog.scrub_due(now, ask).await {
                Ok(page) => page,
                Err(_) => return ScrubEnd::Stopped,
            };
            let fresh: Vec<&ScrubCandidate> = page
                .iter()
                .filter(|c| !seen.contains(&c.extent.id))
                .take(left.min(SCRUB_PAGE) as usize)
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
                }
                if walk.run.incident.is_some() {
                    return ScrubEnd::Incident;
                }
            }
        }
    }

    async fn scrub_record_one(
        &self,
        token: u64,
        extent: &ExtentRow,
        result: ScrubResult,
        next_in_secs: u64,
    ) -> core::result::Result<(), Halt> {
        let now = self.clock.now();
        let next =
            now.plus_ms(i64::try_from(next_in_secs.saturating_mul(1000)).unwrap_or(i64::MAX));
        match self
            .catalog
            .scrub_record(token, &extent.id, result, now, next)
            .await?
        {
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
        let plan = self.catalog.articles(&extent.id).await?;
        let posted = !plan.is_empty() && plan.iter().all(|a| a.state == ArticleState::Posted);
        let repinned = matches!(
            candidate.last,
            Some(ScrubResult::Repairing | ScrubResult::Stalled)
        );
        match extent.safety_state {
            SafetyState::Released if posted => {}
            SafetyState::Held | SafetyState::Releasing if repinned && posted => {
                return self
                    .watch_repair(token, reader, extent, plan, walk.run)
                    .await;
            }
            // Not on Usenet in full, deleted, or pinned by something
            // else than the scrub: off the due list.
            _ => {
                self.catalog.scrub_drop(token, &extent.id).await?;
                return Ok(());
            }
        }

        let found = self.check(reader, walk.stats, extent, plan).await?;
        let (run, breaker) = (&mut *walk.run, &mut *walk.breaker);
        run.checked += 1;
        breaker.note(&found);
        if found.cipher.is_some() {
            run.bytes_read += extent.cipher_size;
        }
        if !found.loss() {
            run.ok += 1;
            if found.refetched > 0 {
                run.refetched += found.refetched;
            }
            let interval = u64::from(cfg.interval_days) * 86_400;
            return self
                .scrub_record_one(token, extent, ScrubResult::Ok, interval)
                .await;
        }

        if let Some((backbone, lacking)) = breaker.tripped() {
            let line = format!("{backbone} {lacking}/{}", breaker.checked);
            crate::trace::alert(|| format!("scrub-incident {line}"));
            run.incident = Some(backbone.to_owned());
            run.suspect += 1;
            let confirm = u64::from(cfg.confirm_secs);
            return self
                .scrub_record_one(token, extent, ScrubResult::Suspect, confirm)
                .await;
        }

        let confirmed = matches!(
            candidate.last,
            Some(ScrubResult::Suspect | ScrubResult::Unrecoverable)
        );
        let held_back = walk
            .blocked
            .as_deref()
            .is_some_and(|b| found.lacking.iter().any(|l| l == b))
            || run.repaired >= cfg.repairs_per_run;
        if !confirmed || held_back {
            run.suspect += 1;
            let confirm = u64::from(cfg.confirm_secs);
            return self
                .scrub_record_one(token, extent, ScrubResult::Suspect, confirm)
                .await;
        }
        self.repair(token, extent, found, run).await
    }

    /// `STAT` on every backbone that counts, then the whole extent read
    /// with the drill reader.
    async fn check<'s>(
        &'s self,
        reader: &mut ColdReader<'s, C, N, T>,
        stats: &mut Vec<ProviderSession<'s, C, N, T>>,
        extent: &ExtentRow,
        plan: Vec<ArticleRow>,
    ) -> core::result::Result<Found, Halt> {
        let mut lacking = Vec::new();
        for (name, providers) in release_backbones(&self.cfg.providers) {
            match self
                .presence(reader.holder(), stats, &plan, &providers)
                .await?
            {
                Presence::Lacks(missing) if missing.is_empty() => {}
                Presence::Lacks(_) => lacking.push(name),
                Presence::Unknown => return Err(Halt::Busy),
            }
        }

        let bytes = cold_step_bytes(extent.cipher_size, reader.sockets());
        let Ok(charge) = self.budget.charge_job(bytes).await else {
            return Err(Halt::Busy);
        };
        let before = reader.stats();
        let read = reader.fetch_planned(extent, plan).await;
        let after = reader.stats();
        let cipher = match read? {
            ColdFetch::Filled(cipher) => Some(cipher),
            ColdFetch::Unavailable => None,
            ColdFetch::Busy | ColdFetch::Interrupted => return Err(Halt::Busy),
        };
        Ok(Found {
            lacking,
            cipher,
            rebuilt: rebuilt(&before, &after),
            refetched: after.refetched.saturating_sub(before.refetched),
            _charge: Some(charge),
        })
    }

    /// What one backbone holds of `plan`, asked with `STAT` of one of its
    /// `providers`, all articles at once. The session is kept in
    /// `stats` for the next extent of the run: one login per backbone
    /// and run, not per extent. A kept session whose slot was lost is
    /// ended and one is opened anew.
    async fn presence<'s>(
        &'s self,
        holder: &str,
        stats: &mut Vec<ProviderSession<'s, C, N, T>>,
        plan: &[ArticleRow],
        providers: &[&'s ProviderConfig],
    ) -> core::result::Result<Presence, Halt> {
        let now = self.clock.now();
        let pool = Pool::load(&self.catalog, &self.cfg.providers, now).await?;
        let rows: Vec<&ArticleRow> = plan.iter().collect();
        for provider in pool.order(providers.to_vec(), PermitClass::Background) {
            let kept = stats.iter().position(|s| s.provider.id == provider.id);
            let mut tries = 0;
            loop {
                tries += 1;
                let reused = kept.is_some() && tries == 1;
                let session = match kept.filter(|_| reused) {
                    Some(at) => Some(stats.swap_remove(at)),
                    None => self.stat_session(provider, holder).await?,
                };
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
                        return Ok(Presence::Lacks(lacks));
                    }
                    // A kept session whose slot expired: a new one.
                    Err(Stop::NoPermit) if reused => {
                        session.close().await;
                        continue;
                    }
                    // The account was refused: the next provider of the
                    // backbone is asked.
                    Err(Stop::Refused) => {
                        session.close().await;
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
    }

    /// A slot to ask `provider` with: one of its drill connections if it
    /// has any free (the reader holds at most `SCRUB_SOCKETS` of them),
    /// else a background slot of its `max_conns`, which keeps one for
    /// reads. `None`: neither is free.
    async fn stat_session<'s>(
        &'s self,
        provider: &'s ProviderConfig,
        holder: &str,
    ) -> Result<Option<ProviderSession<'s, C, N, T>>> {
        let classes: &[PermitClass] = match provider.drill_conns {
            0 => &[PermitClass::Background],
            _ => &[PermitClass::Drill, PermitClass::Background],
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

    /// A confirmed loss: the bytes from the first source that has them
    /// intact, back in the safety store, and the extent re-pinned.
    async fn repair(
        &self,
        token: u64,
        extent: &ExtentRow,
        found: Found,
        run: &mut ScrubRun,
    ) -> core::result::Result<(), Halt> {
        let cfg = &self.cfg.scrub;
        let confirm = u64::from(cfg.confirm_secs);
        let lacking = found.lacking.join(",");
        let (source, cipher) = match found.cipher {
            Some(cipher) if found.rebuilt > 0 => (RepairSource::Parity, Some(cipher)),
            Some(cipher) => (RepairSource::Usenet, Some(cipher)),
            None => self.stored_copy(extent).await,
        };
        let Some(cipher) = cipher else {
            run.unrecoverable += 1;
            crate::trace::alert(|| {
                format!(
                    "scrub-unrecoverable {} lacking=[{lacking}] no intact copy on Usenet, \
                     in the cache or in the safety store",
                    extent.id.as_str()
                )
            });
            return self
                .scrub_record_one(token, extent, ScrubResult::Unrecoverable, confirm)
                .await;
        };
        if source != RepairSource::Safety && !self.put_safety(extent, cipher).await {
            // The store did not take it: try again at the next look.
            run.suspect += 1;
            return self
                .scrub_record_one(token, extent, ScrubResult::Suspect, confirm)
                .await;
        }
        let now = self.clock.now();
        let bound = repair_bound_secs(self.cfg.safety_min_age_secs, cfg.confirm_secs);
        let next = now.plus_ms(i64::try_from(bound * 1000).unwrap_or(i64::MAX));
        if self
            .catalog
            .scrub_repin(token, &extent.id, now, next)
            .await?
        {
            run.repaired += 1;
            crate::trace::alert(|| {
                format!(
                    "scrub-repair {} source={} lacking=[{lacking}]",
                    extent.id.as_str(),
                    source.as_str()
                )
            });
            return Ok(());
        }
        // Refused: the extent is no longer released and done, or no live
        // object holds it, or the lease is gone. Looked at again later;
        // the safety copy written stays an evictable copy.
        run.suspect += 1;
        self.scrub_record_one(token, extent, ScrubResult::Suspect, confirm)
            .await
    }

    /// The cache copy if it is intact, else the safety copy if it is.
    async fn stored_copy(&self, extent: &ExtentRow) -> (RepairSource, Option<Vec<u8>>) {
        if let Ok(Some(bytes)) = self.cache.get(&extent.id.cache_key(), None).await {
            if digest_ok(extent, &bytes) {
                return (RepairSource::Cache, Some(bytes));
            }
        }
        if let Ok(Some(bytes)) = self.safety.get(&extent.id.safety_key(), None).await {
            if digest_ok(extent, &bytes) {
                return (RepairSource::Safety, Some(bytes));
            }
        }
        (RepairSource::Usenet, None)
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
    async fn watch_repair(
        &self,
        token: u64,
        reader: &mut ColdReader<'_, C, N, T>,
        extent: &ExtentRow,
        plan: Vec<ArticleRow>,
        run: &mut ScrubRun,
    ) -> core::result::Result<(), Halt> {
        let cfg = &self.cfg.scrub;
        let bound = repair_bound_secs(self.cfg.safety_min_age_secs, cfg.confirm_secs);
        let kept = match self.safety.get(&extent.id.safety_key(), None).await {
            Ok(Some(bytes)) => digest_ok(extent, &bytes),
            _ => false,
        };
        let mut rewrote = false;
        if !kept {
            let bytes = cold_step_bytes(extent.cipher_size, reader.sockets());
            let Ok(charge) = self.budget.charge_job(bytes).await else {
                return Err(Halt::Busy);
            };
            let read = reader.fetch_planned(extent, plan).await;
            drop(charge);
            let cipher = match read? {
                ColdFetch::Filled(cipher) => {
                    run.bytes_read += extent.cipher_size;
                    Some(cipher)
                }
                ColdFetch::Unavailable => {
                    match self.cache.get(&extent.id.cache_key(), None).await {
                        Ok(Some(bytes)) if digest_ok(extent, &bytes) => Some(bytes),
                        _ => None,
                    }
                }
                ColdFetch::Busy | ColdFetch::Interrupted => return Err(Halt::Busy),
            };
            match cipher {
                Some(cipher) => rewrote = self.put_safety(extent, cipher).await,
                None => {
                    run.unrecoverable += 1;
                    crate::trace::alert(|| {
                        format!(
                            "scrub-unrecoverable {} re-pinned, its safety copy is gone and no \
                             intact copy is on Usenet or in the cache",
                            extent.id.as_str()
                        )
                    });
                    let confirm = u64::from(cfg.confirm_secs);
                    return self
                        .scrub_record_one(token, extent, ScrubResult::Unrecoverable, confirm)
                        .await;
                }
            }
        }
        run.stalled += 1;
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
        self.scrub_record_one(token, extent, ScrubResult::Stalled, bound)
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
            _charge: None,
        };
        for _ in 0..7 {
            b.note(&found(&["a"]));
            b.note(&found(&["b"]));
        }
        assert!(b.tripped().is_none());
        b.note(&found(&["a"]));
        assert_eq!(b.tripped(), Some(("a", 8)));
    }
}
