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
//! # Where the gate is held
//!
//! In two places, so that a restore of the directory database cannot
//! open it. Each closing puts a put-once anchor `m/dg/<epoch>` in R2 and
//! then marks the gate row closed at that epoch; the next epoch is taken
//! from the anchors, never from the database alone. The gate is open only
//! while the row says open **and** its epoch is the newest anchor
//! ([`is_open`]). A restored row that says open at an older epoch is
//! therefore closed. An anchor says only "closed at this epoch", so a
//! forged one can close the gate and never open it.
//!
//! This holds for a restore that follows a closing. A Time Travel restore
//! made with no closing before it brings back a row that is open at the
//! newest epoch, and it is open until a gate run closes it: the restore
//! of the directory database is therefore run only by a tool that closes
//! the gate first.
//!
//! # What passes a closed gate
//!
//! Five closing calls need no directory row and are let through at once
//! ([`ClosingCall`]): revoke, disable and narrow a key, clear a public
//! flag, and an operator hold. Every other management call answers `503`
//! while the gate is closed.

#![allow(async_fn_in_trait)]

use std::collections::BTreeMap;

use super::chain::{ChainError, ControlSeal, TenantChain, TENANT_CHAIN_PREFIX};
use super::record::{Tenant, TenantDoor};
use super::store::SqlDirectory;
use crate::ports::Sql;
use crate::records::RecordStore;
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
    Missing(Tenant),
    /// A row behind its head.
    Behind {
        tenant: Tenant,
        row_seq: u64,
        head_seq: u64,
    },
    /// A row ahead of its head: the row names a record that is not in R2.
    Ahead {
        tenant: Tenant,
        row_seq: u64,
        head_seq: u64,
    },
    /// A row at the head's seq that does not say what the head says, or
    /// whose columns disagree with its own door.
    Changed(Tenant),
    /// A row that does not parse or names another tenant or seq.
    Unreadable(Tenant),
    /// A row that no chain backs.
    Orphan(Tenant),
    /// A chain that does not read: missing record, stray name, a record
    /// that names another tenant or seq.
    Damaged { tenant: Tenant, what: &'static str },
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
    /// Writes skipped because the row changed since the comparison.
    pub raced: u64,
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
    /// counters at zero. It refuses an epoch below the newest it has
    /// started: a run that was closed over may reach it late.
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
    /// A newer run closed the gate over this one, which stopped.
    pub closed_over: bool,
    /// Names under the anchor prefix that are no anchor. Each alarms: one
    /// after the open epoch keeps the gate closed until it is removed.
    pub anchor_strays: u64,
}

/// The prefix of the gate anchors in R2: `m/dg/<epoch>`, put once each.
pub const GATE_ANCHOR_PREFIX: &str = "m/dg/";

/// How many lost anchor puts a closing takes before it fails.
const MAX_ANCHOR_TRIES: u32 = 3;

/// How many rounds of the tenant step a gate run takes before it gives up
/// on rows that keep changing under it.
const MAX_TENANT_ROUNDS: u32 = 3;

fn anchor_key(epoch: u64) -> String {
    format!("{GATE_ANCHOR_PREFIX}{epoch:020}")
}

/// The highest epoch an anchor may name: well inside the integers that
/// every store and every JSON reader keeps exactly.
pub const MAX_EPOCH: u64 = (1 << 53) - 1;

/// The newest anchored epoch, 0 = none, and the number of names under
/// the prefix that are no anchor (a stray name, or an epoch above
/// [`MAX_EPOCH`]). A stray name alarms; it never stops a closing.
pub async fn anchored_epoch<S: RecordStore>(store: &S) -> Result<(u64, u64)> {
    let mut newest = 0;
    let mut strays = 0;
    let mut after = String::new();
    loop {
        let keys = store.list(GATE_ANCHOR_PREFIX, &after, 1000).await?;
        for key in &keys {
            match anchor_epoch(key) {
                Some(epoch) => newest = newest.max(epoch),
                None => strays += 1,
            }
        }
        match keys.last() {
            Some(last) if keys.len() == 1000 => after = last.clone(),
            _ => return Ok((newest, strays)),
        }
    }
}

fn anchor_epoch(key: &str) -> Option<u64> {
    key.strip_prefix(GATE_ANCHOR_PREFIX)
        .filter(|d| d.len() == 20 && d.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|d| d.parse::<u64>().ok())
        .filter(|&e| (1..=MAX_EPOCH).contains(&e))
}

/// Closes the gate at a new epoch: the anchor first, then the row, which
/// is read back. The epoch is above every anchor and above the row's.
pub async fn close<S: RecordStore, Q: Sql>(
    store: &S,
    dir: &SqlDirectory<'_, Q>,
    reason: &str,
    now: UnixMs,
) -> Result<u64> {
    for _ in 0..MAX_ANCHOR_TRIES {
        let (anchored, _strays) = anchored_epoch(store).await?;
        let epoch = anchored
            .max(dir.gate().await?.epoch)
            .checked_add(1)
            .filter(|&e| e <= MAX_EPOCH)
            .ok_or(BridgeError::Invalid("gate epoch out of range"))?;
        let body = serde_json::to_vec(&serde_json::json!({
            "epoch": epoch,
            "closed_at": now.0,
        }))
        .map_err(|_| BridgeError::Invalid("gate anchor"))?;
        if store.put_if_absent(&anchor_key(epoch), body).await? {
            dir.mark_closed(epoch, reason, now).await?;
            let row = dir.gate().await?;
            if !row.closed || row.epoch < epoch {
                return Err(BridgeError::Invalid("gate row did not take the closing"));
            }
            return Ok(epoch);
        }
    }
    Err(BridgeError::Invalid("gate anchor: lost every put"))
}

/// Whether the gate is open: the row says open at epoch E, and the names
/// under the anchor prefix after E - 1 are exactly E's anchor. One short
/// listing; any other name there (a newer anchor, a stray) keeps it
/// closed. An `Err` is closed too: the caller answers `503`.
pub async fn is_open<S: RecordStore, Q: Sql>(store: &S, dir: &SqlDirectory<'_, Q>) -> Result<bool> {
    let row = dir.gate().await?;
    if row.closed || row.epoch == 0 || row.epoch > MAX_EPOCH {
        return Ok(false);
    }
    let after = match row.epoch - 1 {
        0 => String::new(),
        e => anchor_key(e),
    };
    let names = store.list(GATE_ANCHOR_PREFIX, &after, 2).await?;
    Ok(names == [anchor_key(row.epoch)])
}

/// Every tenant id that has a chain, in id order: one listing call per
/// tenant, each starting after the last tenant's whole chain.
pub async fn chain_tenants<S: RecordStore>(store: &S) -> Result<Vec<Tenant>> {
    let mut out: Vec<Tenant> = Vec::new();
    let mut after = String::new();
    loop {
        let keys = store.list(TENANT_CHAIN_PREFIX, &after, 1).await?;
        let Some(key) = keys.into_iter().next() else {
            return Ok(out);
        };
        let tenant = key
            .strip_prefix(TENANT_CHAIN_PREFIX)
            // A record name has a `/` after the tenant id; a bare
            // `m/t/<tenant>` is a stray name.
            .and_then(|rest| rest.split_once('/').map(|(tenant, _)| tenant))
            .and_then(Tenant::parse)
            .ok_or(BridgeError::Invalid("stray name under the tenant chains"))?;
        if out.last().is_some_and(|last| *last >= tenant) {
            return Err(BridgeError::Invalid("tenant chains out of order"));
        }
        // Past every name under `m/t/<tenant>/`: `0` is the byte after `/`.
        after = format!("{TENANT_CHAIN_PREFIX}{}0", tenant.as_str());
        out.push(tenant);
    }
}

/// Every tenant id that has a row, in id order.
async fn row_tenants<S: Sql>(dir: &SqlDirectory<'_, S>) -> Result<Vec<Tenant>> {
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

type Heads = Vec<(Tenant, std::result::Result<TenantDoor, &'static str>)>;

/// The head door of every chain, or the damage that kept it from reading.
async fn heads<S: RecordStore, C: ControlSeal>(chain: &TenantChain<'_, S, C>) -> Result<Heads> {
    let mut out = Vec::new();
    for tenant in chain_tenants(chain.store).await? {
        let head = match chain.head(&tenant, 0).await {
            Ok(Some(read)) => Ok(read.door),
            Ok(None) => Err("chain_empty"),
            Err(ChainError::Damaged(what)) => Err(what),
            Err(ChainError::Store(e)) => return Err(e),
            // A key version this isolate does not hold yet: the run fails
            // and is run again, it is not damage.
            Err(ChainError::KeyNotHeld { .. }) => {
                return Err(BridgeError::Invalid("tenant key version not held yet"))
            }
            Err(_) => Err("chain_unreadable"),
        };
        out.push((tenant, head));
    }
    Ok(out)
}

/// What the comparison found, with the row seqs it saw.
struct Compared {
    differences: Vec<Difference>,
    /// The seq of each row as read, `None` for no row.
    observed: BTreeMap<Tenant, Option<u64>>,
}

/// Compares every tenant row with its chain head. Read-only: the nightly
/// comparison.
pub async fn compare_tenants<S: RecordStore, C: ControlSeal, Q: Sql>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
) -> Result<Vec<Difference>> {
    Ok(compare(&heads(chain).await?, dir).await?.differences)
}

async fn compare<Q: Sql>(heads: &Heads, dir: &SqlDirectory<'_, Q>) -> Result<Compared> {
    let mut out = Compared {
        differences: Vec::new(),
        observed: BTreeMap::new(),
    };
    for (tenant, head) in heads {
        let raw = dir.raw_tenant(tenant).await?;
        out.observed
            .insert(tenant.clone(), raw.as_ref().and_then(|r| r.record_seq));
        let head = match head {
            Ok(door) => door,
            Err(what) => {
                out.differences.push(Difference::Damaged {
                    tenant: tenant.clone(),
                    what,
                });
                continue;
            }
        };
        let difference = match raw {
            None => Some(Difference::Missing(tenant.clone())),
            Some(row) => match (row.door, row.record_seq) {
                (None, _) | (_, None) => Some(Difference::Unreadable(tenant.clone())),
                (Some(_), Some(seq)) if seq < head.seq => Some(Difference::Behind {
                    tenant: tenant.clone(),
                    row_seq: seq,
                    head_seq: head.seq,
                }),
                (Some(_), Some(seq)) if seq > head.seq => Some(Difference::Ahead {
                    tenant: tenant.clone(),
                    row_seq: seq,
                    head_seq: head.seq,
                }),
                (Some(door), _) if door != *head || !units_match(dir, head).await => {
                    Some(Difference::Changed(tenant.clone()))
                }
                (Some(_), _) => None,
            },
        };
        out.differences.extend(difference);
    }
    for tenant in row_tenants(dir).await? {
        if !heads.iter().any(|(t, _)| *t == tenant) {
            let seq = dir.raw_tenant(&tenant).await?.and_then(|r| r.record_seq);
            out.observed.insert(tenant.clone(), seq);
            out.differences.push(Difference::Orphan(tenant));
        }
    }
    Ok(out)
}

/// Whether the unit rows say what the head says. Rows that do not read
/// do not say it, and the rebuild writes them again.
async fn units_match<Q: Sql>(dir: &SqlDirectory<'_, Q>, head: &TenantDoor) -> bool {
    let Ok(rows) = dir.units(&head.tenant).await else {
        return false;
    };
    let listed: Vec<(u32, Option<u64>)> = head
        .units
        .iter()
        .map(|u| (*u, head.restoring_entry(*u).map(|r| r.since_seq)))
        .collect();
    let stored: Vec<(u32, Option<u64>)> =
        rows.iter().map(|r| (r.unit, r.restoring_since)).collect();
    listed == stored
}

/// Gate step 2 (and the tenant part of step 1): every row takes its
/// chain head, every field; a row that no chain backs is removed; a
/// shredded tenant keeps its row and loses its routes and labels.
///
/// Each write is conditional on the row seq that the comparison saw, so a
/// head that a closing call applied meanwhile is not overwritten with an
/// older one, and a tenant created meanwhile is not removed. A skipped
/// write is counted in `raced`; the gate compares again before it opens.
pub async fn rebuild_tenants<S: RecordStore, C: ControlSeal, Q: Sql>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    now: UnixMs,
) -> Result<TenantStep> {
    let heads = heads(chain).await?;
    let compared = compare(&heads, dir).await?;
    let mut step = TenantStep {
        differences: compared.differences.clone(),
        ..TenantStep::default()
    };
    for (tenant, head) in &heads {
        if head.is_err() {
            continue;
        }
        step.chains += 1;
        // The row first, then the head: a closing call that lands between
        // the two either is in the head read here, or changed the row and
        // makes the write below a no-op. Never an older head over a newer
        // row.
        let observed = dir.row_seq(tenant).await?;
        let fresh = match chain.head(tenant, 0).await {
            Ok(Some(read)) => read.door,
            Ok(None) | Err(ChainError::Damaged(_)) | Err(ChainError::PrivateUnreadable) => {
                step.raced += 1;
                continue;
            }
            Err(ChainError::Store(e)) => return Err(e),
            Err(_) => return Err(BridgeError::Invalid("tenant chain not readable now")),
        };
        match dir.replace_tenant(&fresh, &observed, now).await? {
            true => step.written += 1,
            false => step.raced += 1,
        }
    }
    for d in &compared.differences {
        if let Difference::Orphan(tenant) = d {
            let observed = dir.row_seq(tenant).await?;
            // Removed only when the chain is surely still absent; an
            // error is not "absent".
            match chain.head_seq(tenant, 0).await {
                Ok(None) => {}
                _ => {
                    step.raced += 1;
                    continue;
                }
            }
            match dir.remove_tenant(tenant, &observed).await? {
                true => step.removed += 1,
                false => step.raced += 1,
            }
        }
    }
    Ok(step)
}

/// Runs the gate from its first step: closes it at a new epoch, runs every
/// step in order, and opens it only if every step is done, no chain was
/// damaged, the rows equal the heads when it is about to open, and no
/// other run closed it since.
pub async fn run_gate<S: RecordStore, C: ControlSeal, Q: Sql, G: GateSteps>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    steps: &G,
    reason: &str,
    now: UnixMs,
) -> Result<GateRun> {
    let epoch = close(chain.store, dir, reason, now).await?;
    let mut run = GateRun {
        epoch,
        tenants: TenantStep::default(),
        steps: Vec::new(),
        opened: false,
        closed_over: false,
        anchor_strays: 0,
    };
    // Before every step: a newer run that closed the gate over this one
    // does the rest, and this one writes nothing more.
    macro_rules! step {
        ($name:expr, $call:expr) => {{
            if !ours(chain.store, epoch).await? {
                run.closed_over = true;
                return Ok(run);
            }
            run.steps.push(($name, $call.await?));
        }};
    }
    step!("revocations", steps.revocations());
    if !ours(chain.store, epoch).await? {
        run.closed_over = true;
        return Ok(run);
    }
    run.tenants = rebuild_tenants(chain, dir, now).await?;
    step!(
        "key_locations_and_registry",
        steps.key_locations_and_registry()
    );
    step!("key_versions", steps.key_versions());
    step!("key_routes_and_labels", steps.key_routes_and_labels());
    step!("root_units", steps.root_units());
    // Only while the gate is closed at this run's epoch.
    dir.clear_pending_in_gate(epoch).await?;
    step!("finisher", steps.finisher());
    step!("counters", steps.counters(epoch));
    step!("sealed_days", steps.sealed_days());

    // The rows must equal the heads now, not only at step 2: a closing
    // call may have written meanwhile. Rows that differ get another
    // round of the tenant step.
    let mut clean = false;
    if !run.tenants.damaged() {
        for _ in 0..MAX_TENANT_ROUNDS {
            let left = compare_tenants(chain, dir).await?;
            if left.is_empty() {
                clean = true;
                break;
            }
            if left.iter().any(|d| matches!(d, Difference::Damaged { .. })) {
                break;
            }
            rebuild_tenants(chain, dir, now).await?;
        }
    }
    let (anchored, strays) = anchored_epoch(chain.store).await?;
    run.anchor_strays = strays;
    run.closed_over = anchored != epoch;
    let ready = clean && !run.closed_over && run.steps.iter().all(|(_, r)| r.done);
    // Open, and say so only if the open check agrees: a stray anchor
    // name keeps the gate closed, and the run reports it.
    run.opened = ready && dir.open_gate(epoch, now).await? && is_open(chain.store, dir).await?;
    Ok(run)
}

/// Whether the newest anchor is still this run's.
async fn ours<S: RecordStore>(store: &S, epoch: u64) -> Result<bool> {
    Ok(anchored_epoch(store).await?.0 == epoch)
}

/// How old the oldest pending operation may get (est): an alarm at 10
/// minutes and a page at 30.
pub const PENDING_ALARM_MS: i64 = 10 * 60_000;
pub const PENDING_PAGE_MS: i64 = 30 * 60_000;

/// The level of the pending-operations age alarm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingLevel {
    Ok,
    Alarm,
    Page,
}

/// The alarm level for the oldest pending operation.
pub fn pending_level(oldest: Option<UnixMs>, now: UnixMs) -> PendingLevel {
    match oldest.map(|t| now.0.saturating_sub(t.0)) {
        Some(age) if age >= PENDING_PAGE_MS => PendingLevel::Page,
        Some(age) if age >= PENDING_ALARM_MS => PendingLevel::Alarm,
        _ => PendingLevel::Ok,
    }
}
