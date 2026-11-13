//! The provider pool: which provider a job asks first.
//!
//! One catalogue read ([`Catalog::provider_load`]) gives every provider's
//! held connection slots and health. From that snapshot:
//! - a disabled provider and one in a cooldown are left out;
//! - the rest are tried by `priority` (`0` first);
//! - inside a priority tier the provider with the most free slots goes
//!   first, and a tie goes to the one that was handed the fewest slots so
//!   far, which rotates idle providers of a tier.
//!
//! The order is a preference only. The permit gate still decides whether
//! a connection may be opened.

use crate::ports::Catalog;
use crate::types::{ProviderConfig, ProviderLoad, Result, UnixMs};

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

    /// Slots the provider could still hand out: under its own limit and,
    /// in a pool, under what the pool's accounts hold together.
    fn free(&self, p: &ProviderConfig) -> u32 {
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
    /// the order they should be tried.
    pub(crate) fn order<'c>(&self, candidates: Vec<&'c ProviderConfig>) -> Vec<&'c ProviderConfig> {
        let mut usable: Vec<&ProviderConfig> = candidates
            .into_iter()
            .filter(|p| p.enabled && !self.cooling(p))
            .collect();
        // Stable: equal providers keep their configuration order.
        usable.sort_by_key(|p| {
            let uses = self.state(&p.id).map_or(0, |l| l.uses);
            (p.priority, core::cmp::Reverse(self.free(p)), uses)
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
    /// ends first.
    pub(crate) fn soonest_cooling<'c>(
        &self,
        candidates: &[&'c ProviderConfig],
    ) -> Option<&'c ProviderConfig> {
        candidates
            .iter()
            .copied()
            .filter(|p| p.enabled && self.cooling(p))
            .min_by_key(|p| self.state(&p.id).map(|l| l.cooldown_until))
    }
}
