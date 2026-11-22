//! The finisher of a tenant chain (ADR §2.5, AM-75): the consumer of
//! `apply_control(tenant, t, _)`, the pending sweep and every handler's
//! step 3 run it.
//!
//! It reads the head of the chain (never a message's seq) and brings every
//! store to it, in the table's order:
//!
//! - **closing** (the records the directory does not hold close any door,
//!   [`super::transition::write_order`]): every listed unit, the root unit
//!   first, then the directory;
//! - **opening**: the directory first, and the units only once the
//!   directory holds the head.
//!
//! The directory step copies the head's door into the `tenants` and
//! `units` rows ([`SqlDirectory::apply_tenant`], idempotent by seq). Before
//! it raises a row from `s` to the head `h`, it reads the verified records
//! `s + 1` to `h` and appends each record's events in seq order
//! ([`super::events::tenant_events`]): events first, so after a crash the
//! next run repeats the appends, and `UNIQUE (tenant, source)` keeps one
//! row each. No handler writes a chain event itself.
//!
//! For each unit that answers born, it writes the unit's born marker if
//! it is missing ([`TenantUnits::mark_born`], ADR §2.4 rule 6). Last, it
//! clears the `pending_ops` rows of the chain at or below what every store
//! holds.
//!
//! With no directory bound (AM-75), the directory step and the clear are
//! skipped, and an opening reaches the units at once.

use super::chain::{ControlSeal, TenantChain};
use super::store::SqlDirectory;
use super::transition::WriteOrder;
use crate::crypto::scheme2::TenantId;
use crate::keys::ports::ControlChain;
use crate::pending::{ChainFinisher, ChainHead, ChainKey};
use crate::ports::Sql;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result, UnixMs};

/// The most records of the chain one run reads for the directory step:
/// the events of a row that is further behind are appended over the next
/// runs, and the row is raised to the last record read. Such a run brings
/// the units up first (the closing order), whatever the records say.
pub const MAX_FINISH_RECORDS: u64 = 100;

/// The chain a [`TenantFinisher`] was asked to finish is a key chain.
pub const ERR_NOT_TENANT_CHAIN: BridgeError =
    BridgeError::Invalid("tenant finisher: not a tenant chain");

/// What a unit holds of the tenant chain after its bring-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitHolds {
    /// The unit holds the chain up to `state_seq`.
    Seq { state_seq: u64 },
    /// The unit is not born yet. Under a `provisioning` head this is
    /// expected (AM-58), and the unit counts as holding the head: its
    /// birth token carries the state, and nothing it would serve is open.
    Unborn,
}

/// The tenant's units, as the finisher needs them. The adapter is the
/// request path's unit client (`UnitClient::sync`, ADR §2.4 rule 5) and the
/// born marker of tenant create.
#[allow(async_fn_in_trait)]
pub trait TenantUnits {
    /// Brings `unit` of `tenant` to the tenant chain's head and answers
    /// what it holds then. A unit that holds less than the head (a lift
    /// that waits for the restore tool's proof, AM-45) answers its own
    /// seq. An `Err`: the unit could not be reached.
    async fn bring_up(&self, tenant: &TenantId, unit: u32) -> Result<UnitHolds>;
    /// Writes `unit`'s born marker if it is missing (ADR §2.4 rule 6),
    /// once the unit answered born. Idempotent; the finisher calls it for
    /// every born unit it brings up.
    async fn mark_born(&self, tenant: &TenantId, unit: u32) -> Result<()>;
}

/// What one store did in a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreStep {
    /// The store holds this seq now.
    Holds(u64),
    /// Not run: an opening whose directory step did not reach the head.
    Waiting,
    /// No directory is bound.
    Unbound,
    /// The store failed; the next run tries again.
    Failed,
}

/// What a run of the tenant finisher did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantFinish {
    /// The head it read. A tenant chain is complete when read to its end.
    pub head: ChainHead,
    /// The order it brought the stores up in; `None` with no head.
    pub order: Option<WriteOrder>,
    pub directory: StoreStep,
    /// Per listed unit, the root unit first.
    pub units: Vec<(u32, StoreStep)>,
    /// Events appended (repeats not counted).
    pub events: u32,
    /// The seq up to which the `pending_ops` rows were cleared.
    pub cleared_to: Option<u64>,
    /// Fixed codes of what pages: damage, never an outage.
    pub pages: Vec<&'static str>,
}

/// Runs the finisher of `tenant`'s chain at `now`. See the
/// [module](self). An `Err` only when the head could not be read.
pub async fn finish_tenant<S, C, Q, U>(
    chain: &TenantChain<'_, S, C>,
    dir: Option<&SqlDirectory<'_, Q>>,
    units: &U,
    tenant: &TenantId,
    now: UnixMs,
) -> Result<TenantFinish>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    U: TenantUnits,
{
    let _ = (chain, dir, units, tenant, now);
    Err(BridgeError::NotImplemented("finish_tenant"))
}

/// [`finish_tenant`] as the pending sweep's [`ChainFinisher`]: it answers
/// [`ERR_NOT_TENANT_CHAIN`] for a key chain, which the caller sends to
/// the key-chain finisher.
pub struct TenantFinisher<'a, S, C, Q, U> {
    pub chain: TenantChain<'a, S, C>,
    /// `None`: no directory is bound.
    pub dir: Option<SqlDirectory<'a, Q>>,
    pub units: &'a U,
    pub now: UnixMs,
}

impl<S, C, Q, U> ChainFinisher for TenantFinisher<'_, S, C, Q, U>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    U: TenantUnits,
{
    async fn finish(&self, chain: &ChainKey) -> Result<ChainHead> {
        if chain.chain != ControlChain::Tenant {
            return Err(ERR_NOT_TENANT_CHAIN);
        }
        let run = finish_tenant(
            &self.chain,
            self.dir.as_ref(),
            self.units,
            &chain.tenant,
            self.now,
        )
        .await?;
        Ok(run.head)
    }
}
