//! Probes of providers whose strikes nothing else would clear.
//!
//! Only a good session clears a provider's strikes (`provider_health`).
//! A provider that no caller picks keeps the strikes of an outage that
//! ended long ago, and reads as unhealthy for good: the last read tier
//! while the tiers above it serve every read, or a provider whose
//! strikes keep it behind the others. A strike below the cooldown
//! threshold never expires, and neither does the count of cooldowns in
//! a row once the last one is over.
//!
//! The cron run asks such a provider itself, once in a while: one
//! session, its login and, on a reader, one `STAT` of an id that does
//! not exist (a `430` is an answer in order). The session's outcome is
//! reported as any session's is ([`crate::fetch::report_health`]): a
//! good one clears the strikes, a failed one is one more strike on the
//! usual ladder of cooldowns.
//!
//! Which providers: enabled, a strike or a cooldown on record, not
//! cooling now, and quiet for [`PROBE_QUIET_MS`]: no strike and no
//! cooldown end in that time, so a provider whose cooldowns grew is
//! asked by real work first once its cooldown is over. After a refused
//! login the quiet time is [`LOGIN_REFUSED_QUIET_MS`], counted from the
//! strike: every probe of a refused account is one more refused login on
//! its record. That time is never shorter than the cooldown the strike
//! started, and real work does not try a refused account before its
//! cooldown ends either, so a probe may follow at once a cooldown that
//! reached its cap of six hours. A probe
//! takes a read slot as any read does (no slot, no probe), so the
//! provider's connection and address limits hold.
//!
//! Load: the cron run looks once every [`PROBE_EVERY_MS`]
//! ([`probe_tick`]), with one read of `provider_health` (one row per
//! provider that ever failed) and one of the replay state. While every provider is healthy nothing
//! is written. A probe writes its slot (taken and given back) and at
//! most one health row; a provider that keeps failing is probed at most
//! once per tick, and less often once its cooldowns grow past the
//! interval.

use futures_util::future::join_all;

use crate::config::Maintenance;
use crate::fetch::{report_health, request_holder, ProviderSession};
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector, NntpSession, PermitClass,
};
use crate::post::Stop;
use crate::types::{BridgeError, ProviderConfig, ProviderFault, Result, UnixMs};

/// How often the cron run looks for providers to probe.
pub const PROBE_EVERY_MS: i64 = 15 * 60_000;

/// How long a provider has had no strike before it is probed. Shorter
/// than [`PROBE_EVERY_MS`], so a provider whose last strike was just
/// before one tick is probed at the next.
pub const PROBE_QUIET_MS: i64 = 10 * 60_000;
const _: () = assert!(PROBE_QUIET_MS < PROBE_EVERY_MS);

/// The quiet time after a refused login: as long as the longest
/// cooldown such a strike starts.
pub const LOGIN_REFUSED_QUIET_MS: i64 = crate::sql::LOGIN_REFUSED_COOLDOWN_MAX_MS;

/// The article a reader is asked about: an id no server has (the
/// `invalid` top-level domain), so the answer is a `430`.
pub const PROBE_MESSAGE_ID: &str = "velmora-health-probe@probe.invalid";

/// Whether the cron run scheduled at `scheduled` looks for providers to
/// probe: the run in the first minute of every [`PROBE_EVERY_MS`]. A
/// cron that fires every few minutes hits it once per interval; one that
/// fires less often probes at the multiples it hits.
pub fn probe_tick(scheduled: UnixMs) -> bool {
    scheduled.0.rem_euclid(PROBE_EVERY_MS) < 60_000
}

/// How a probe of one provider went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probed {
    /// The session went well: the strikes are cleared.
    Recovered,
    /// The session failed: one more strike, and why.
    Failed(ProviderFault),
    /// No slot, or the provider stated a connection limit: nothing was
    /// learnt and nothing is recorded.
    NoSlot,
    /// The session ended without an answer that says anything about the
    /// provider (its slot was lost, or a reply that is not its fault).
    Inconclusive,
}

impl core::fmt::Display for Probed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Probed::Recovered => f.write_str("recovered"),
            Probed::Failed(fault) => write!(f, "failed {}", fault.as_str()),
            Probed::NoSlot => f.write_str("no_slot"),
            Probed::Inconclusive => f.write_str("inconclusive"),
        }
    }
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
    /// Probes every provider that is due ([`crate::probe`]), all at
    /// once, and says how each probe went. Nothing in maintenance
    /// `restore` or while a replay is not finished, as the dispatcher
    /// sends nothing then either.
    pub async fn probe_providers(&self) -> Result<Vec<(String, Probed)>> {
        if self.cfg.maintenance == Maintenance::Restore || self.catalog.restore_pending().await? {
            return Ok(Vec::new());
        }
        let now = self.clock.now();
        let due = self
            .catalog
            .providers_to_probe(
                now,
                now.plus_ms(-PROBE_QUIET_MS),
                now.plus_ms(-LOGIN_REFUSED_QUIET_MS),
            )
            .await?;
        let providers: Vec<&ProviderConfig> = self
            .cfg
            .providers
            .iter()
            .filter(|p| p.enabled && due.contains(&p.id))
            .collect();
        let probed = join_all(providers.iter().map(|p| self.probe(p))).await;
        providers
            .into_iter()
            .zip(probed)
            .map(|(p, probed)| probed.map(|o| (p.id.clone(), o)))
            .collect()
    }

    async fn probe(&self, provider: &ProviderConfig) -> Result<Probed> {
        let holder = request_holder("probe")?;
        let opened = ProviderSession::open(
            &self.catalog,
            &self.nntp,
            &self.clock,
            provider,
            PermitClass::Read,
            &holder,
        )
        .await?;
        let Some(session) = opened else {
            return Ok(Probed::NoSlot);
        };
        let mut session = session.with_timer(self.budget.sleeper());
        let asked = ask(&mut session).await;
        let health = session.finish().await;
        report_health(&self.catalog, &self.clock, &provider.id, health).await;
        match (health, asked) {
            (Some(Ok(())), _) => Ok(Probed::Recovered),
            (Some(Err(fault)), _) => Ok(Probed::Failed(fault)),
            (None, Err(Stop::NoPermit)) => Ok(Probed::NoSlot),
            (None, Err(Stop::Fenced | Stop::Catalog)) => Err(BridgeError::Sql(
                "catalogue failed during a provider probe".into(),
            )),
            (None, _) => Ok(Probed::Inconclusive),
        }
    }
}

/// Connects (greeting and login), renews the slot as a read does after
/// a connect, and asks a reader about [`PROBE_MESSAGE_ID`]. The session
/// keeps how it went; a provider that only posts is in order once its
/// login is.
async fn ask<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
) -> core::result::Result<(), Stop> {
    session.session().await?;
    session.keep(None).await?;
    if !session.provider.read {
        session.note_ok();
        return Ok(());
    }
    let asked = session.session().await?.stat(PROBE_MESSAGE_ID).await;
    match asked {
        Ok(_) => session.note_ok(),
        Err(e) => {
            session.note_err(&e);
            session.discard();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tick_in_the_first_minute_of_each_interval_probes() {
        let base = UnixMs(1_800_000_000_000 / PROBE_EVERY_MS * PROBE_EVERY_MS);
        assert!(probe_tick(base));
        assert!(probe_tick(base.plus_ms(59_999)));
        assert!(!probe_tick(base.plus_ms(60_000)));
        assert!(!probe_tick(base.plus_ms(5 * 60_000)));
        assert!(!probe_tick(base.plus_ms(10 * 60_000)));
        assert!(probe_tick(base.plus_ms(PROBE_EVERY_MS)));
        // A cron every five minutes hits one tick in three.
        let hits = (0..12)
            .filter(|i| probe_tick(base.plus_ms(i * 5 * 60_000)))
            .count();
        assert_eq!(hits, 4);
    }
}
