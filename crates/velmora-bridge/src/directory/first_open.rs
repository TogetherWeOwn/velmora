//! The directory gate's first open (ADR §8.6, AM-78).
//!
//! A directory made empty by its migration is closed until its first gate
//! run. Milestone 1 runs that run with [`FirstOpen`] steps:
//!
//! - each per-tenant step (revocations, key versions, key routes, root
//!   units, finisher, sealed days) is done only while the tenant chains
//!   list no managed tenant ([`managed_tenant_exists`]);
//! - key locations are done when the head of `m/kl/` opens and its
//!   locations are copied into `key_locations` (ADR §8.6 step 3); a head
//!   that is absent or does not open leaves the step not done;
//! - the registry is done while `m/reg/` is absent (AM-58's fixed location
//!   hint);
//! - counters start the feed epoch at the run's epoch.
//!
//! The run's tenant step and its closing comparison run as for every gate
//! run ([`run_gate`]).
//!
//! [`first_open`] is the operator call's body (AM-70b), with its guard:
//! `run_gate` closes the gate and empties `pending_ops` before its first
//! step, so it checks first. An open gate answers [`FirstOpenAnswer::
//! AlreadyOpen`] and runs nothing; a managed tenant chain answers
//! [`FirstOpenAnswer::HasTenants`] (`409 gate_has_tenants`, it pages) and
//! runs nothing. Only a closed gate with no managed tenant chain gets a
//! run, and a run that left the gate closed may be started again. The run
//! reads the gate row again right before its closing
//! ([`super::gate::run_gate_if_closed`]): a call whose guard passed while
//! another run was under way answers [`FirstOpenAnswer::Moved`] instead
//! of closing the gate that run opened. The read and the closing are
//! still two calls apart, so the operator route runs one call at a time.

use super::chain::{chain_prefix, ControlSeal, TenantChain, TENANT_CHAIN_PREFIX};
use super::gate::{is_open, run_gate_if_closed, GateRun, GateSteps, StepReport};
use super::record::Tenant;
use super::store::{location_status, SqlDirectory};
use crate::keys::locations::read_locations;
use crate::ports::{Kek, Sql};
use crate::records::RecordStore;
use crate::types::{Result, UnixMs};

/// The reason a first open names in its closing.
pub const FIRST_OPEN_REASON: &str = "first_open";

/// The prefix of the registry chain.
pub const REGISTRY_PREFIX: &str = "m/reg/";

/// What the first-open call did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstOpenAnswer {
    /// The gate is open: nothing ran (`200`).
    AlreadyOpen,
    /// A managed tenant chain exists: nothing ran (`409 gate_has_tenants`,
    /// it pages).
    HasTenants,
    /// A gate run ran; [`GateRun::opened`] says whether it opened.
    Ran(GateRun),
    /// The gate opened between the guard and the closing, or another
    /// closing took the epoch: nothing ran (`503`; a call again answers
    /// `AlreadyOpen` or runs).
    Moved,
}

/// Whether any tenant chain but tenant 0's exists: at most two listings
/// of one name each. A stray name under `m/t/` counts as one.
pub async fn managed_tenant_exists<S: RecordStore>(store: &S) -> Result<bool> {
    let first = store.list(TENANT_CHAIN_PREFIX, "", 1).await?;
    let Some(key) = first.first() else {
        return Ok(false);
    };
    let zero = chain_prefix(&Tenant::Zero);
    if !key.starts_with(&zero) {
        return Ok(true);
    }
    // Past every name under tenant 0's chain: `0` is the byte after `/`.
    let after = format!("{}0", zero.trim_end_matches('/'));
    Ok(!store.list(TENANT_CHAIN_PREFIX, &after, 1).await?.is_empty())
}

/// The gate steps of the first open. See the [module](self).
pub struct FirstOpen<'a, S, K, Q> {
    pub store: &'a S,
    pub kek: &'a K,
    pub dir: SqlDirectory<'a, Q>,
}

impl<S: RecordStore, K: Kek, Q: Sql> FirstOpen<'_, S, K, Q> {
    /// A per-tenant step: done only while no managed tenant chain exists.
    async fn no_tenant(&self) -> Result<StepReport> {
        Ok(match managed_tenant_exists(self.store).await? {
            false => StepReport::done(),
            true => StepReport::not_done("managed_tenant_exists"),
        })
    }
}

impl<S: RecordStore, K: Kek, Q: Sql> GateSteps for FirstOpen<'_, S, K, Q> {
    async fn revocations(&self) -> Result<StepReport> {
        self.no_tenant().await
    }

    async fn key_locations_and_registry(&self) -> Result<StepReport> {
        let mut problems = Vec::new();
        // A head that is absent or does not open leaves the step not done.
        match read_locations(self.store, self.kek, 0).await {
            Ok(Some(set)) => {
                self.dir.put_key_locations(&set).await?;
                let want: Vec<(String, String, u64)> = set
                    .locations
                    .iter()
                    .map(|l| {
                        (
                            l.name.clone(),
                            location_status(l.status).to_string(),
                            set.seq,
                        )
                    })
                    .collect();
                let mut want = want;
                want.sort();
                if self.dir.key_locations().await? != want {
                    problems.push("key_locations_differ".to_string());
                }
            }
            Ok(None) => problems.push("key_locations_absent".to_string()),
            Err(_) => problems.push("key_locations_unreadable".to_string()),
        }
        if !self.store.list(REGISTRY_PREFIX, "", 1).await?.is_empty() {
            problems.push("registry_present".to_string());
        }
        Ok(StepReport {
            done: problems.is_empty(),
            problems,
        })
    }

    async fn key_versions(&self) -> Result<StepReport> {
        self.no_tenant().await
    }

    async fn key_routes_and_labels(&self) -> Result<StepReport> {
        self.no_tenant().await
    }

    async fn root_units(&self) -> Result<StepReport> {
        self.no_tenant().await
    }

    async fn finisher(&self) -> Result<StepReport> {
        self.no_tenant().await
    }

    async fn counters(&self, epoch: u64) -> Result<StepReport> {
        if self.dir.start_feed_epoch(epoch).await? || self.dir.feed_epoch().await? == epoch {
            return Ok(StepReport::done());
        }
        Ok(StepReport::not_done("feed_epoch_newer"))
    }

    async fn sealed_days(&self) -> Result<StepReport> {
        self.no_tenant().await
    }
}

/// The first-open call (AM-78): the guard, then one gate run with
/// [`FirstOpen`] steps. `kek` opens the head of `m/kl/`.
pub async fn first_open<S, C, Q, K>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    kek: &K,
    now: UnixMs,
) -> Result<FirstOpenAnswer>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    K: Kek,
{
    if is_open(chain.store, dir).await? {
        return Ok(FirstOpenAnswer::AlreadyOpen);
    }
    if managed_tenant_exists(chain.store).await? {
        return Ok(FirstOpenAnswer::HasTenants);
    }
    let steps = FirstOpen {
        store: chain.store,
        kek,
        dir: SqlDirectory { sql: dir.sql },
    };
    match run_gate_if_closed(chain, dir, &steps, FIRST_OPEN_REASON, now).await? {
        Some(run) => Ok(FirstOpenAnswer::Ran(run)),
        None => Ok(FirstOpenAnswer::Moved),
    }
}
