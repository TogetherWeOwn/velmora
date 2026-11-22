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
//! run, and a run that left the gate closed may be started again.

use super::chain::{ControlSeal, TenantChain};
use super::gate::{run_gate, GateRun, GateSteps, StepReport};
use super::store::SqlDirectory;
use crate::ports::{Kek, Sql};
use crate::records::RecordStore;
use crate::types::{BridgeError, Result, UnixMs};

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
}

/// Whether any tenant chain but tenant 0's exists: at most two listings
/// of one name each. A stray name under `m/t/` counts as one.
pub async fn managed_tenant_exists<S: RecordStore>(store: &S) -> Result<bool> {
    let _ = store;
    Err(BridgeError::NotImplemented("managed_tenant_exists"))
}

/// The gate steps of the first open. See the [module](self).
pub struct FirstOpen<'a, S, K, Q> {
    pub store: &'a S,
    pub kek: &'a K,
    pub dir: SqlDirectory<'a, Q>,
}

impl<S: RecordStore, K: Kek, Q: Sql> GateSteps for FirstOpen<'_, S, K, Q> {
    async fn revocations(&self) -> Result<StepReport> {
        Err(BridgeError::NotImplemented("FirstOpen"))
    }
    async fn key_locations_and_registry(&self) -> Result<StepReport> {
        Err(BridgeError::NotImplemented("FirstOpen"))
    }
    async fn key_versions(&self) -> Result<StepReport> {
        Err(BridgeError::NotImplemented("FirstOpen"))
    }
    async fn key_routes_and_labels(&self) -> Result<StepReport> {
        Err(BridgeError::NotImplemented("FirstOpen"))
    }
    async fn root_units(&self) -> Result<StepReport> {
        Err(BridgeError::NotImplemented("FirstOpen"))
    }
    async fn finisher(&self) -> Result<StepReport> {
        Err(BridgeError::NotImplemented("FirstOpen"))
    }
    async fn counters(&self, _epoch: u64) -> Result<StepReport> {
        Err(BridgeError::NotImplemented("FirstOpen"))
    }
    async fn sealed_days(&self) -> Result<StepReport> {
        Err(BridgeError::NotImplemented("FirstOpen"))
    }
}

/// Placeholder for the signature commit.
struct NoSteps;
impl GateSteps for NoSteps {
    async fn revocations(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("x"))
    }
    async fn key_locations_and_registry(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("x"))
    }
    async fn key_versions(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("x"))
    }
    async fn key_routes_and_labels(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("x"))
    }
    async fn root_units(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("x"))
    }
    async fn finisher(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("x"))
    }
    async fn counters(&self, _epoch: u64) -> Result<StepReport> {
        Ok(StepReport::not_done("x"))
    }
    async fn sealed_days(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("x"))
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
    let _ = (chain, dir, kek, now, run_gate::<S, C, Q, NoSteps>);
    Err(BridgeError::NotImplemented("first_open"))
}
