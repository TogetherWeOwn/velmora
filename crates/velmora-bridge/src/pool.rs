//! The provider pool: which provider a job asks first.
//!
//! One catalogue read ([`Catalog::provider_load`]) gives every provider's
//! held connection slots and health. From that snapshot:
//! - a disabled provider and one in a cooldown are left out;
//! - the rest are tried by `priority` (`0` first);
//! - inside a priority tier the provider with the most free slots goes
//!   first (one whose `max_ips` addresses are all in use has none), and a tie goes to the one that was handed the fewest slots so
//!   far, which rotates idle providers of a tier.
//!
//! The order is a preference only. The permit gate still decides whether
//! a connection may be opened.

use crate::ports::{Catalog, PermitClass};
use crate::types::{ProviderConfig, ProviderFault, ProviderLoad, Result, UnixMs};

/// A snapshot of the pool at `now`.
pub(crate) struct Pool<'a> {
    providers: &'a [ProviderConfig],
    load: Vec<ProviderLoad>,
    now: UnixMs,
}

impl<'a> Pool<'a> {
    pub(crate) async fn load<C: Catalog>(
        catalog: &C,
        providers: &'a [ProviderConfig],
        now: UnixMs,
    ) -> Result<Pool<'a>> {
        let load = catalog.provider_load(now).await?;
        Ok(Pool::new(providers, load, now))
    }

    pub(crate) fn new(
        providers: &'a [ProviderConfig],
        load: Vec<ProviderLoad>,
        now: UnixMs,
    ) -> Pool<'a> {
        Pool {
            providers,
            load,
            now,
        }
    }

    fn state(&self, id: &str) -> Option<&ProviderLoad> {
        self.load.iter().find(|l| l.provider_id == id)
    }

    fn held(&self, id: &str) -> u32 {
        self.state(id).map_or(0, |l| l.held)
    }

    fn cooling(&self, p: &ProviderConfig) -> bool {
        self.state(&p.id)
            .is_some_and(|l| l.cooldown_until > self.now)
    }

    /// Slots the provider could still hand out to a caller of `class`
    /// that holds none there: under its own limit and, in a pool, under
    /// what the pool's accounts hold together; none while the account is
    /// in use from as many addresses as it allows, or as it allows to
    /// background jobs.
    fn free(&self, p: &ProviderConfig, class: PermitClass) -> u32 {
        let (holders, jobs) = self
            .state(&p.id)
            .map_or((0, 0), |l| (l.holders, l.background_holders));
        let no_address = p.max_ips.is_some_and(|max| holders >= max)
            || (class == PermitClass::Background
                && p.background_ips().is_some_and(|max| jobs >= max));
        if no_address {
            return 0;
        }
        // Drill slots are not in the snapshot: a drill is ordered by
        // what a read would find.
        let own = p.max_conns.saturating_sub(self.held(&p.id));
        match (&p.pool, p.pool_max_conns) {
            (Some(pool), Some(max)) => {
                let held: u32 = self
                    .providers
                    .iter()
                    .filter(|q| q.pool.as_ref() == Some(pool))
                    .map(|q| self.held(&q.id))
                    .sum();
                own.min(max.saturating_sub(held))
            }
            _ => own,
        }
    }

    /// The enabled providers among `candidates` that are not cooling, in
    /// the order a caller of `class` should try them.
    pub(crate) fn order<'c>(
        &self,
        candidates: Vec<&'c ProviderConfig>,
        class: PermitClass,
    ) -> Vec<&'c ProviderConfig> {
        let mut usable: Vec<&ProviderConfig> = candidates
            .into_iter()
            .filter(|p| p.enabled && !self.cooling(p))
            .collect();
        // Stable: equal providers keep their configuration order.
        usable.sort_by_key(|p| {
            let uses = self.state(&p.id).map_or(0, |l| l.uses);
            (p.priority, core::cmp::Reverse(self.free(p, class)), uses)
        });
        usable
    }

    /// When the first cooling provider among the enabled `candidates`
    /// comes back; `None` = none of them is cooling.
    pub(crate) fn cooling_until(&self, candidates: &[&ProviderConfig]) -> Option<UnixMs> {
        candidates
            .iter()
            .filter(|p| p.enabled && self.cooling(p))
            .filter_map(|p| self.state(&p.id).map(|l| l.cooldown_until))
            .min()
    }

    /// The enabled cooling provider among `candidates` whose cooldown
    /// ends first, for one attempt before its time. A provider that
    /// cools because it refused the login is not among them: it is asked
    /// again only when its cooldown ends.
    pub(crate) fn soonest_cooling<'c>(
        &self,
        candidates: &[&'c ProviderConfig],
    ) -> Option<&'c ProviderConfig> {
        candidates
            .iter()
            .copied()
            .filter(|p| p.enabled && self.cooling(p))
            .filter(|p| self.fault(p) != Some(ProviderFault::LoginRefused))
            .min_by_key(|p| self.state(&p.id).map(|l| l.cooldown_until))
    }

    /// The ids of the `candidates` whose last strike was a refusal of
    /// the connection or the login, and no good session since. The next
    /// connect is a probe of whether they still refuse.
    pub(crate) fn refusing<'c>(&self, candidates: &[&'c ProviderConfig]) -> Vec<&'c str> {
        candidates
            .iter()
            .filter(|p| self.fault(p).is_some_and(ProviderFault::is_refusal))
            .map(|p| p.id.as_str())
            .collect()
    }

    fn fault(&self, p: &ProviderConfig) -> Option<ProviderFault> {
        self.state(&p.id).and_then(|l| l.fault)
    }
}
