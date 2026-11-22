//! The directory gate's first open (ADR §8.6, AM-78, AM-83b).
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
//! # The first open takes epoch 1, and only epoch 1 (AM-83b)
//!
//! [`first_open`] is the operator call's body (AM-70b). No call of it puts
//! any anchor but `m/dg/…01`, and it never calls
//! [`SqlDirectory::mark_closed`] (which closes an open row at the same
//! epoch). The gate row moves only forward, each move a compare-and-set:
//! no row or closed at epoch 0, then closed at epoch 1 with `pending_ops`
//! emptied once ([`SqlDirectory::first_close`]), then open at epoch 1
//! ([`SqlDirectory::first_open_gate`]). In order:
//!
//! 1. One read of the gate row, then one listing of `m/dg/`. The row
//!    first: a first open puts anchor 1 before it writes the row, so a row
//!    at epoch 1 read here has its anchor in the listing.
//! 2. Anchor 1 only, row open at epoch 1: [`FirstOpenAnswer::AlreadyOpen`]
//!    (`200`), nothing runs. This comes before the tenant check, so a retry
//!    after a lost `200` and a tenant create still answers `200` (C6).
//! 3. Any name under `m/dg/` but anchor 1; no anchor with a row that is
//!    neither absent nor closed at epoch 0; any row but absent, closed at 0
//!    or closed at 1: [`FirstOpenAnswer::EpochUnexpected`] (`409
//!    gate_epoch_unexpected`, it pages), nothing written. No first open
//!    makes these states: a drill teardown, a restore tool or damage does.
//! 4. A managed tenant chain: [`FirstOpenAnswer::HasTenants`] (`409
//!    gate_has_tenants`, it pages), nothing written; unless the gate is
//!    open at epoch 1 by then (another call opened it after this call's
//!    read), which answers `200`.
//! 5. No anchor: anchor 1 is put once. Losing the put to another call is
//!    not a failure (the anchor exists), and a lost answer is read back.
//! 6. The batch of [`SqlDirectory::first_close`]. Any call may make this
//!    move once anchor 1 exists, so a lost answer after the anchor put
//!    sticks nothing.
//! 7. The [`FirstOpen`] steps by [`super::gate::run_first_open`], which
//!    re-reads the row before every step and conditions every write.
//! 8. The open. A compare-and-set that changed no row (in 6 or 8) reads
//!    the gate again: open at epoch 1 answers `200`, anything else
//!    [`FirstOpenAnswer::Moved`] (`503` with `Retry-After`).
//!
//! So no first-open call closes a gate that another call opened, and none
//! empties `pending_ops` after an open.

use super::chain::{chain_prefix, ControlSeal, TenantChain, TENANT_CHAIN_PREFIX};
use super::gate::{
    anchor_key, open_at_one, run_first_open, GateRun, GateSteps, StepReport, GATE_ANCHOR_PREFIX,
};
use super::record::Tenant;
use super::store::{location_status, GateRow, SqlDirectory};
use crate::keys::locations::read_locations;
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
    /// The gate is open at epoch 1: nothing ran (`200`).
    AlreadyOpen,
    /// A managed tenant chain exists and the gate is not open: nothing
    /// ran (`409 gate_has_tenants`, it pages).
    HasTenants,
    /// The anchors or the gate row are in a state that no first open
    /// makes (a name under `m/dg/` other than anchor 1, a row at an epoch
    /// above 1, a row at epoch 1 without its anchor): nothing ran (`409
    /// gate_epoch_unexpected`, it pages).
    EpochUnexpected,
    /// A gate run ran; [`GateRun::opened`] says whether it opened.
    Ran(GateRun),
    /// A compare-and-set found another state: another call moved the gate
    /// meanwhile, and it is not open at epoch 1 (`503` with `Retry-After`;
    /// a call again answers `200`, runs, or answers `409`).
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

/// The first-open call (AM-78, AM-83b): see the [module](self). `kek`
/// opens the head of `m/kl/`.
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
    // 1. The row, then the anchors.
    let row = dir.gate_row().await?;
    let names = chain.store.list(GATE_ANCHOR_PREFIX, "", 2).await?;
    let anchored = match names.as_slice() {
        [] => false,
        [only] if *only == anchor_key(1) => true,
        _ => return Ok(FirstOpenAnswer::EpochUnexpected),
    };
    let state = RowState::of(row);
    // 2.
    if anchored && state == RowState::OpenAtOne {
        return Ok(FirstOpenAnswer::AlreadyOpen);
    }
    // 3.
    match (anchored, state) {
        (_, RowState::Fresh) | (true, RowState::ClosedAtOne) => {}
        _ => return Ok(FirstOpenAnswer::EpochUnexpected),
    }
    // 4.
    if managed_tenant_exists(chain.store).await? {
        // Read before another call's open, and a tenant create since.
        if open_at_one(chain.store, dir).await? {
            return Ok(FirstOpenAnswer::AlreadyOpen);
        }
        return Ok(FirstOpenAnswer::HasTenants);
    }
    // 5.
    if !anchored {
        put_first_anchor(chain.store, now).await?;
    }
    // 6.
    dir.first_close(FIRST_OPEN_REASON, now).await?;
    let moved = GateRow {
        closed: true,
        epoch: 1,
        pending_cleared: true,
    };
    if dir.gate_row().await? != Some(moved) {
        return settled(chain.store, dir).await;
    }
    // 7 and 8.
    let steps = FirstOpen {
        store: chain.store,
        kek,
        dir: SqlDirectory { sql: dir.sql },
    };
    let run = run_first_open(chain, dir, &steps, now).await?;
    if run.closed_over && !run.opened {
        return settled(chain.store, dir).await;
    }
    Ok(FirstOpenAnswer::Ran(run))
}

/// The gate row as the first open sorts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowState {
    /// No row, or closed at epoch 0: the gate never opened.
    Fresh,
    ClosedAtOne,
    OpenAtOne,
    /// Any other row.
    Other,
}

impl RowState {
    fn of(row: Option<GateRow>) -> RowState {
        match row {
            None => RowState::Fresh,
            Some(GateRow {
                closed: true,
                epoch: 0,
                ..
            }) => RowState::Fresh,
            Some(GateRow {
                closed: true,
                epoch: 1,
                ..
            }) => RowState::ClosedAtOne,
            Some(GateRow {
                closed: false,
                epoch: 1,
                ..
            }) => RowState::OpenAtOne,
            Some(_) => RowState::Other,
        }
    }
}

/// The answer after a compare-and-set that found another state.
async fn settled<S: RecordStore, Q: Sql>(
    store: &S,
    dir: &SqlDirectory<'_, Q>,
) -> Result<FirstOpenAnswer> {
    Ok(match open_at_one(store, dir).await? {
        true => FirstOpenAnswer::AlreadyOpen,
        false => FirstOpenAnswer::Moved,
    })
}

/// Puts anchor 1 once (AM-83b item 5). Another call's put of it is no
/// failure: the anchor exists. An `Err` says nothing about whether it
/// landed, so the name is read back.
async fn put_first_anchor<S: RecordStore>(store: &S, now: UnixMs) -> Result<()> {
    let body = serde_json::to_vec(&serde_json::json!({
        "epoch": 1,
        "closed_at": now.0,
    }))
    .map_err(|_| BridgeError::Invalid("gate anchor"))?;
    match store.put_if_absent(&anchor_key(1), body).await {
        Ok(_) => Ok(()),
        Err(e) => match store.exists(&anchor_key(1)).await {
            Ok(true) => Ok(()),
            _ => Err(e),
        },
    }
}
