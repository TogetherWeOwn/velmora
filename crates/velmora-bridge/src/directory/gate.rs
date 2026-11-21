//! The directory gate: after a restore of the directory database (Time
//! Travel) or a rebuild from nothing, the management plane answers `503`
//! until every row is a copy of a record again.
//!
//! The gate runs in a fixed order. This module runs the steps that the
//! tenant chain answers, and asks a [`GateSteps`] for the others (key
//! routes, key locations and versions, bucket labels, the root units, the
//! finisher, the counters, the sealed days), each of which another part of
//! the build owns. The gate opens only when every step reports done and
//! no tenant chain was damaged, and only for the epoch it closed.
//!
//! The same tenant step, read-only, is the nightly comparison of the
//! directory against the chain heads ([`compare_tenants`]): it reports a
//! difference and never writes.
//!
//! # What passes a closed gate
//!
//! Five closing calls need no directory row and are let through at once
//! ([`ClosingCall`]): revoke, disable and narrow a key, clear a public
//! flag, and an operator hold. Every other management call answers `503`
//! while the gate is closed.

#![allow(async_fn_in_trait)]

use super::chain::{
    chain_prefix, ChainError, ControlSeal, RecordStore, TenantChain, TENANT_CHAIN_PREFIX,
};
use super::record::{TenantDoor, TenantId};
use super::store::SqlDirectory;
use crate::ports::Sql;
use crate::types::{BridgeError, Result, UnixMs};

/// A management call that passes a closed gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosingCall {
    RevokeKey,
    DisableKey,
    NarrowKey,
    ClearPublicFlag,
    OperatorHold,
}

/// A management call as the gate sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementCall {
    Closing(ClosingCall),
    /// Every other call.
    Other,
}

/// Whether `call` may run while the gate is `closed`.
pub fn admitted(closed: bool, call: ManagementCall) -> bool {
    !closed || matches!(call, ManagementCall::Closing(_))
}

/// One difference between a tenant row and its chain head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Difference {
    /// A chain with no row.
    Missing(TenantId),
    /// A row behind its head.
    Behind {
        tenant: TenantId,
        row_seq: u64,
        head_seq: u64,
    },
    /// A row ahead of its head: the row names a record that is not in R2.
    Ahead {
        tenant: TenantId,
        row_seq: u64,
        head_seq: u64,
    },
    /// A row at the head's seq that does not say what the head says.
    Changed(TenantId),
    /// A row that no chain backs.
    Orphan(TenantId),
    /// A chain that does not read: missing record, stray name, a record
    /// that names another tenant or seq.
    Damaged {
        tenant: TenantId,
        what: &'static str,
    },
}

/// What the tenant step did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantStep {
    /// Tenants with a chain.
    pub chains: u64,
    /// Rows written from a head.
    pub written: u64,
    /// Rows removed: no chain backs them.
    pub removed: u64,
    pub differences: Vec<Difference>,
}

impl TenantStep {
    /// Whether a chain was damaged: the gate cannot open on it.
    pub fn damaged(&self) -> bool {
        self.differences
            .iter()
            .any(|d| matches!(d, Difference::Damaged { .. }))
    }
}

/// The result of a step that another part of the build owns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepReport {
    pub done: bool,
    /// Fixed codes of what kept it from done, or what it found.
    pub problems: Vec<String>,
}

impl StepReport {
    pub fn done() -> StepReport {
        StepReport {
            done: true,
            problems: vec![],
        }
    }

    pub fn not_done(problem: &str) -> StepReport {
        StepReport {
            done: false,
            problems: vec![problem.to_string()],
        }
    }
}

/// The gate steps that the tenant chain does not answer, in the gate's
/// order. Each must be idempotent: a gate that is killed runs again from
/// its first step.
pub trait GateSteps {
    /// Step 1, keys: apply valid shred markers and every revocation.
    async fn revocations(&self) -> Result<StepReport>;
    /// Step 3: key locations from the head of `m/kl/`; the registry from
    /// the head of `m/reg/`.
    async fn key_locations_and_registry(&self) -> Result<StepReport>;
    /// Step 4: the highest key version ever claimed, from the key buckets
    /// as well as the records; a mismatch alarms.
    async fn key_versions(&self) -> Result<StepReport>;
    /// Step 5: key routes from every key chain, with every revocation on
    /// top and no route for a shredded tenant; bucket labels from the
    /// newest bucket configuration record of every bucket.
    async fn key_routes_and_labels(&self) -> Result<StepReport>;
    /// Step 6: cross-check every root unit (seqs, unit list, key list,
    /// jurisdiction) and take its counters and attention conditions again.
    async fn root_units(&self) -> Result<StepReport>;
    /// Step 7, after the pending table was emptied: run the finisher for
    /// every tenant whose chain head is above its root unit's seq.
    async fn finisher(&self) -> Result<StepReport>;
    /// Step 8: a new epoch of the event feed; the shred brake and the
    /// delete caps restart as used up for the current window, the other
    /// counters at zero.
    async fn counters(&self, epoch: u64) -> Result<StepReport>;
    /// Step 9: the sealed-usage-day index from `m/u/`; the pressure flag
    /// treated as set until its job has run.
    async fn sealed_days(&self) -> Result<StepReport>;
}

/// The steps of a gate run whose code does not exist yet. Every one is
/// "not done", so a gate run with them never opens.
pub struct NotBuilt;

impl GateSteps for NotBuilt {
    async fn revocations(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("revocations_not_built"))
    }
    async fn key_locations_and_registry(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("key_locations_not_built"))
    }
    async fn key_versions(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("key_versions_not_built"))
    }
    async fn key_routes_and_labels(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("key_routes_not_built"))
    }
    async fn root_units(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("root_units_not_built"))
    }
    async fn finisher(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("finisher_not_built"))
    }
    async fn counters(&self, _epoch: u64) -> Result<StepReport> {
        Ok(StepReport::not_done("counters_not_built"))
    }
    async fn sealed_days(&self) -> Result<StepReport> {
        Ok(StepReport::not_done("sealed_days_not_built"))
    }
}

/// What a gate run did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateRun {
    /// The epoch this run closed the gate at.
    pub epoch: u64,
    pub tenants: TenantStep,
    /// The other steps, by name, in the gate's order.
    pub steps: Vec<(&'static str, StepReport)>,
    /// Whether this run opened the gate.
    pub opened: bool,
}

/// Every tenant id that has a chain, in id order: one listing call per
/// tenant, each starting after the last tenant's whole chain.
pub async fn chain_tenants<S: RecordStore>(store: &S) -> Result<Vec<TenantId>> {
    let mut out = Vec::new();
    let mut after = String::new();
    loop {
        let keys = store.list(TENANT_CHAIN_PREFIX, &after, 1).await?;
        let Some(key) = keys.into_iter().next() else {
            return Ok(out);
        };
        let tenant = key
            .strip_prefix(TENANT_CHAIN_PREFIX)
            .and_then(|rest| rest.split('/').next())
            .and_then(TenantId::parse)
            .ok_or(BridgeError::Invalid("stray name under the tenant chains"))?;
        // Past every seq of this tenant: digits sort before `~`.
        after = format!("{}~", chain_prefix(&tenant));
        out.push(tenant);
    }
}

/// Every tenant id that has a row, in id order.
async fn row_tenants<S: Sql>(dir: &SqlDirectory<'_, S>) -> Result<Vec<TenantId>> {
    let mut out = Vec::new();
    let mut after = String::new();
    loop {
        let page = dir.tenant_ids(&after, 500).await?;
        let Some(last) = page.last() else {
            return Ok(out);
        };
        after = last.as_str().to_string();
        let done = page.len() < 500;
        out.extend(page);
        if done {
            return Ok(out);
        }
    }
}

/// The head door of every chain, or the damage that kept it from reading.
async fn heads<S: RecordStore, C: ControlSeal>(chain: &TenantChain<'_, S, C>) -> Result<Heads> {
    let mut out = Vec::new();
    for tenant in chain_tenants(chain.store).await? {
        let head = match chain.head(&tenant, 0).await {
            Ok(Some(read)) => Ok(read.door),
            Ok(None) => Err("chain_empty"),
            Err(ChainError::Damaged(what)) => Err(what),
            Err(ChainError::Store(e)) => return Err(e),
            Err(_) => Err("chain_unreadable"),
        };
        out.push((tenant, head));
    }
    Ok(out)
}

/// Compares every tenant row with its chain head. Read-only: the nightly
/// comparison.
pub async fn compare_tenants<S: RecordStore, C: ControlSeal, Q: Sql>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
) -> Result<Vec<Difference>> {
    compare(&heads(chain).await?, dir).await
}

type Heads = Vec<(TenantId, std::result::Result<TenantDoor, &'static str>)>;

async fn compare<Q: Sql>(heads: &Heads, dir: &SqlDirectory<'_, Q>) -> Result<Vec<Difference>> {
    let mut out = Vec::new();
    for (tenant, head) in heads {
        let head = match head {
            Ok(door) => door,
            Err(what) => {
                out.push(Difference::Damaged {
                    tenant: tenant.clone(),
                    what,
                });
                continue;
            }
        };
        match dir.tenant(tenant).await? {
            None => out.push(Difference::Missing(tenant.clone())),
            Some(row) if row.record_seq < head.seq => out.push(Difference::Behind {
                tenant: tenant.clone(),
                row_seq: row.record_seq,
                head_seq: head.seq,
            }),
            Some(row) if row.record_seq > head.seq => out.push(Difference::Ahead {
                tenant: tenant.clone(),
                row_seq: row.record_seq,
                head_seq: head.seq,
            }),
            Some(row) if row.door != *head || !units_match(dir, head).await? => {
                out.push(Difference::Changed(tenant.clone()))
            }
            Some(_) => {}
        }
    }
    for tenant in row_tenants(dir).await? {
        if !heads.iter().any(|(t, _)| *t == tenant) {
            out.push(Difference::Orphan(tenant));
        }
    }
    Ok(out)
}

/// Whether the unit rows say what the head says.
async fn units_match<Q: Sql>(dir: &SqlDirectory<'_, Q>, head: &TenantDoor) -> Result<bool> {
    let rows = dir.units(&head.tenant).await?;
    let listed: Vec<(u32, Option<u64>)> = head
        .units
        .iter()
        .map(|u| (*u, head.restoring_entry(*u).map(|r| r.since_seq)))
        .collect();
    let stored: Vec<(u32, Option<u64>)> =
        rows.iter().map(|r| (r.unit, r.restoring_since)).collect();
    Ok(listed == stored)
}

/// Gate step 2 (and the tenant part of step 1): every row takes its
/// chain head, every field; a row that no chain backs is removed; a
/// shredded tenant keeps its row and loses its routes and labels.
pub async fn rebuild_tenants<S: RecordStore, C: ControlSeal, Q: Sql>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    now: UnixMs,
) -> Result<TenantStep> {
    let heads = heads(chain).await?;
    let mut step = TenantStep {
        differences: compare(&heads, dir).await?,
        ..TenantStep::default()
    };
    for (_, head) in &heads {
        if let Ok(door) = head {
            step.chains += 1;
            dir.replace_tenant(door, now).await?;
            step.written += 1;
        }
    }
    for d in &step.differences {
        if let Difference::Orphan(tenant) = d {
            dir.remove_tenant(tenant).await?;
            step.removed += 1;
        }
    }
    Ok(step)
}

/// Runs the gate from its first step: closes it in a new epoch, runs every
/// step in order, and opens it only if every step is done, no chain was
/// damaged, and no other run closed it since.
pub async fn run_gate<S: RecordStore, C: ControlSeal, Q: Sql, G: GateSteps>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    steps: &G,
    reason: &str,
    now: UnixMs,
) -> Result<GateRun> {
    let epoch = dir.close_gate(reason, now).await?;
    let mut reports: Vec<(&'static str, StepReport)> = Vec::new();
    reports.push(("revocations", steps.revocations().await?));
    let tenants = rebuild_tenants(chain, dir, now).await?;
    reports.push((
        "key_locations_and_registry",
        steps.key_locations_and_registry().await?,
    ));
    reports.push(("key_versions", steps.key_versions().await?));
    reports.push((
        "key_routes_and_labels",
        steps.key_routes_and_labels().await?,
    ));
    reports.push(("root_units", steps.root_units().await?));
    dir.clear_all_pending().await?;
    reports.push(("finisher", steps.finisher().await?));
    reports.push(("counters", steps.counters(epoch).await?));
    reports.push(("sealed_days", steps.sealed_days().await?));
    let ready = !tenants.damaged() && reports.iter().all(|(_, r)| r.done);
    let opened = ready && dir.open_gate(epoch, now).await?;
    Ok(GateRun {
        epoch,
        tenants,
        steps: reports,
        opened,
    })
}
