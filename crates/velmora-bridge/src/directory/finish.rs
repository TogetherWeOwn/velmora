//! The finisher of a tenant chain (ADR §2.5, AM-75): the consumer of
//! `apply_control(tenant, t, _)`, the pending sweep and every handler's
//! step 3 run it.
//!
//! It reads the head of the chain (never a message's seq) and brings every
//! store to it, in the table's order:
//!
//! - **closing** (the records the directory does not hold close any door,
//!   [`super::transition::write_order`]): every listed unit, the root unit
//!   first, then the directory, and the directory only once every unit
//!   holds the head (so a closing a unit missed stays above the row and
//!   the next run takes the closing order again);
//! - **opening**: the directory first, and the units only once the
//!   directory holds the head. Where the row or the records are not known,
//!   the head's own record decides, and an opening head waits. An opening
//!   head over closings the directory does not hold takes the opening
//!   order when every unit already holds those closings
//!   ([`TenantUnits::held`]), and the closing order otherwise: a unit takes
//!   only the head, and a closing does not wait on the directory.
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

use super::chain::{ChainError, ControlSeal, ReadRecord, TenantChain};
use super::events::tenant_events;
use super::feed::Appended;
use super::record::{Lifecycle, Tenant};
use super::store::{ChainKind, RawTenant, SqlDirectory};
use super::transition::{write_order, WriteOrder};
use crate::crypto::scheme2::TenantId;
use crate::keys::ports::ControlChain;
use crate::pending::{ChainFinisher, ChainHead, ChainKey};
use crate::ports::Sql;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result, UnixMs};

/// The most records of the chain one run reads for the directory step:
/// the events of a row that is further behind are appended over the next
/// runs, and the row is raised to the last record read. Such a run takes
/// its order from the records it read and the head's own record.
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
    /// What `unit` of `tenant` holds of the tenant chain, read without
    /// bringing it up (the unit's own numbers, rule 5). The finisher asks
    /// it only for an opening head over closings the directory does not
    /// hold: if every unit holds them, the opening goes to the directory
    /// first. An `Err`: the unit could not be read (the closing order).
    async fn held(&self, tenant: &TenantId, unit: u32) -> Result<UnitHolds>;
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
    /// Not run: the order holds it back. An opening's units wait for the
    /// directory to hold the head; a closing's directory waits for every
    /// listed unit to hold it.
    Waiting,
    /// No directory is bound.
    Unbound,
    /// The unit is not born. Under a `provisioning` head this is expected
    /// and counts as holding the head; past it, it pages (`unit_unborn`)
    /// and holds nothing.
    Unborn,
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
    /// Units whose born marker could not be written (the next run tries
    /// again).
    pub born_failed: Vec<u32>,
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
    let managed = Tenant::Managed(tenant.clone());
    let mut run = TenantFinish {
        head: ChainHead {
            seq: 0,
            complete: true,
        },
        order: None,
        directory: match dir {
            Some(_) => StoreStep::Failed,
            None => StoreStep::Unbound,
        },
        units: Vec::new(),
        events: 0,
        cleared_to: None,
        born_failed: Vec::new(),
        pages: Vec::new(),
    };
    // The row before the head: a head read after it is at least as new.
    let row = match dir {
        None => Row::Unbound,
        Some(d) => match d.raw_tenant(&managed).await {
            Ok(None) => Row::Seq(0),
            Ok(Some(RawTenant {
                record_seq: Some(seq),
                door: Some(_),
            })) => Row::Seq(seq),
            Ok(Some(_)) => {
                run.pages.push("directory_row_unreadable");
                Row::Unknown
            }
            Err(_) => Row::Unknown,
        },
    };
    let head = match chain.head(&managed, 0).await {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(run),
        Err(e) => return Err(chain_error(e)),
    };
    let h = head.door.seq;
    run.head.seq = h;

    // The records the directory does not hold, oldest first, each with
    // the one before it.
    let mut steps: Vec<(Option<ReadRecord>, ReadRecord)> = Vec::new();
    let mut readable = false;
    let mut far = false;
    if let Row::Seq(s) = row {
        if s > h {
            run.pages.push("directory_row_ahead");
        } else if s == h {
            readable = true;
        } else if head.door.lifecycle == Lifecycle::Shredded {
            // The shred's purge removes the records below the stub, and
            // its events with them: the stub alone, with no event.
            readable = true;
            steps.push((None, head.clone()));
        } else {
            let to = h.min(s.saturating_add(MAX_FINISH_RECORDS));
            far = to < h;
            match read_steps(chain, &managed, s, to, &head).await {
                Ok(read) => {
                    readable = true;
                    steps = read;
                }
                Err(Some(what)) => run.pages.push(what),
                Err(None) => {}
            }
        }
    }

    // The order: closing when a record the directory does not hold
    // closes a door that the units may not have closed yet. Where those
    // records are not all known (no row was read, it is ahead, a record
    // did not read, or the row is further behind than one run reads), the
    // head's own record decides too (AM-75: "when the head's record
    // opens"). So an opening never reaches a unit before the directory
    // holds it, unless a closing below it is still outstanding at a unit:
    // a unit takes only the head, and a closing does not wait on the
    // directory (ADR §2.5). A closing below an opening head that is not
    // known reaches the units by the lease renewal (ADR §2.4 rule 12,
    // within T) or a later run.
    let known = matches!(row, Row::Seq(_)) && readable && !far;
    let provisioning = head.door.lifecycle == Lifecycle::Provisioning;
    // A head in a shred closes, also where its records below are purged
    // and only the stub is read.
    let mut last_closing = steps
        .iter()
        .filter(|(prev, r)| {
            write_order(prev.as_ref().map(|p| &p.door), &r.door) == WriteOrder::Closing
        })
        .map(|(_, r)| r.door.seq)
        .max();
    if matches!(
        head.door.lifecycle,
        Lifecycle::Shredding | Lifecycle::Shredded
    ) || (!known
        && last_closing.is_none()
        && head_closes(chain, &managed, &head, &mut run.pages).await)
    {
        last_closing = Some(h);
    }
    let order = match last_closing {
        None => WriteOrder::Opening,
        Some(c) if c == h => WriteOrder::Closing,
        // An opening head over closings: if every unit holds them already,
        // only openings are left, and the directory goes first.
        Some(c) => match units_hold_at_least(units, tenant, &head, c, provisioning).await {
            true => WriteOrder::Opening,
            false => WriteOrder::Closing,
        },
    };
    run.order = Some(order);

    if order == WriteOrder::Closing {
        bring_units(units, tenant, &head, &mut run).await;
    }
    // A closing reaches the directory only once every listed unit holds
    // the head, so a run whose unit step failed leaves the closing record
    // above the row, and the next run takes the closing order again.
    let units_hold = run.units.iter().all(|(_, step)| match step {
        StoreStep::Holds(seq) => *seq >= h,
        StoreStep::Unborn => provisioning,
        _ => false,
    });
    if let (Some(d), Row::Seq(s), true) = (dir, &row, readable) {
        run.directory = match order == WriteOrder::Opening || units_hold {
            true => directory_step(d, *s, h, &steps, now, &mut run.events).await,
            false => StoreStep::Waiting,
        };
    }
    if order == WriteOrder::Opening {
        match (dir, run.directory) {
            (None, _) => bring_units(units, tenant, &head, &mut run).await,
            (Some(_), StoreStep::Holds(seq)) if seq == h => {
                bring_units(units, tenant, &head, &mut run).await
            }
            _ => {
                run.units = head
                    .door
                    .units
                    .iter()
                    .map(|u| (*u, StoreStep::Waiting))
                    .collect()
            }
        }
    }

    // Clear what every store holds.
    // A unit whose born marker is not written holds back the clear: the
    // rows keep the finisher running until it is.
    if let (Some(d), StoreStep::Holds(held)) = (dir, run.directory) {
        let mut floor = Some(held);
        for (unit, step) in &run.units {
            floor = match (floor, step) {
                _ if run.born_failed.contains(unit) => None,
                (Some(f), StoreStep::Holds(seq)) => Some(f.min(*seq)),
                (Some(f), StoreStep::Unborn) if provisioning => Some(f),
                _ => None,
            };
        }
        if let Some(to) = floor.filter(|&to| to > 0) {
            if d.clear_pending(&managed, ChainKind::Tenant, to)
                .await
                .is_ok()
            {
                run.cleared_to = Some(to);
            }
        }
    }
    Ok(run)
}

/// What the finisher read of the directory's row.
enum Row {
    /// No directory is bound.
    Unbound,
    /// The row's seq; 0 for no row.
    Seq(u64),
    /// The row could not be read, or does not say a seq it can be trusted
    /// with.
    Unknown,
}

/// The tenant chain did not read: damage pages, anything else may pass.
pub const ERR_CHAIN_DAMAGED: BridgeError =
    BridgeError::Invalid("tenant finisher: the tenant chain is damaged");

/// The tenant key version a record names is not held here yet.
pub const ERR_KEY_NOT_HELD: BridgeError =
    BridgeError::Invalid("tenant finisher: tenant key version not held yet");

fn chain_error(e: ChainError) -> BridgeError {
    match e {
        ChainError::Store(e) => e,
        ChainError::KeyNotHeld { .. } => ERR_KEY_NOT_HELD,
        _ => ERR_CHAIN_DAMAGED,
    }
}

/// Whether every unit the head lists holds the tenant chain at `seq` or
/// above, as read without bringing it up ([`TenantUnits::held`]). An unborn
/// unit counts under a `provisioning` head; a unit that cannot be read
/// does not.
async fn units_hold_at_least<U: TenantUnits>(
    units: &U,
    tenant: &TenantId,
    head: &ReadRecord,
    seq: u64,
    provisioning: bool,
) -> bool {
    for &unit in &head.door.units {
        let holds = match units.held(tenant, unit).await {
            Ok(UnitHolds::Seq { state_seq }) => state_seq >= seq,
            Ok(UnitHolds::Unborn) => provisioning,
            Err(_) => false,
        };
        if !holds {
            return false;
        }
    }
    true
}

/// Whether the head's own record closes a door against the record before
/// it (one read). A head in a shred closes. A record before it that does
/// not read counts as not closing: the units then wait for the directory,
/// and damage pages.
async fn head_closes<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    tenant: &Tenant,
    head: &ReadRecord,
    pages: &mut Vec<&'static str>,
) -> bool {
    if matches!(
        head.door.lifecycle,
        Lifecycle::Shredding | Lifecycle::Shredded
    ) {
        return true;
    }
    let prev = match head.door.seq {
        1 => None,
        seq => match chain.read(tenant, seq - 1).await {
            Ok(Some(r)) => Some(r),
            Ok(None) => {
                pages.push("tenant_record_missing");
                return false;
            }
            Err(ChainError::Store(_)) | Err(ChainError::KeyNotHeld { .. }) => return false,
            Err(_) => {
                pages.push("tenant_record_damaged");
                return false;
            }
        },
    };
    write_order(prev.as_ref().map(|p| &p.door), &head.door) == WriteOrder::Closing
}

/// The records `s + 1` to `to`, each with the record before it (`None`
/// for seq 1). `Err(Some(code))`: damage, which pages; `Err(None)`: the
/// store failed.
async fn read_steps<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    tenant: &Tenant,
    s: u64,
    to: u64,
    head: &ReadRecord,
) -> std::result::Result<Vec<(Option<ReadRecord>, ReadRecord)>, Option<&'static str>> {
    let read = |seq: u64| async move {
        if seq == head.door.seq {
            return Ok(head.clone());
        }
        match chain.read(tenant, seq).await {
            Ok(Some(r)) => Ok(r),
            Ok(None) => Err(Some("tenant_record_missing")),
            Err(ChainError::Store(_)) | Err(ChainError::KeyNotHeld { .. }) => Err(None),
            Err(_) => Err(Some("tenant_record_damaged")),
        }
    };
    let mut prev = match s {
        0 => None,
        s => Some(read(s).await?),
    };
    let mut out = Vec::new();
    for seq in s + 1..=to {
        let r = read(seq).await?;
        out.push((prev.take(), r.clone()));
        prev = Some(r);
    }
    Ok(out)
}

/// The directory step: the events of `steps` in seq order, then the row
/// raised to the last of them.
async fn directory_step<Q: Sql>(
    dir: &SqlDirectory<'_, Q>,
    s: u64,
    h: u64,
    steps: &[(Option<ReadRecord>, ReadRecord)],
    now: UnixMs,
    events: &mut u32,
) -> StoreStep {
    let Some((_, last)) = steps.last() else {
        return match s == h {
            true => StoreStep::Holds(h),
            false => StoreStep::Failed,
        };
    };
    for (prev, r) in steps {
        for event in tenant_events(prev.as_ref(), r) {
            match dir.append_event(&event).await {
                Ok(Appended::Appended) => *events += 1,
                Ok(Appended::Repeated) => {}
                Err(_) => return StoreStep::Failed,
            }
        }
    }
    match dir.apply_tenant(&last.door, now).await {
        Ok(_) => StoreStep::Holds(last.door.seq),
        Err(_) => StoreStep::Failed,
    }
}

/// Every listed unit, the root unit first, brought to the head; a born
/// unit's marker written if it is missing.
async fn bring_units<U: TenantUnits>(
    units: &U,
    tenant: &TenantId,
    head: &ReadRecord,
    run: &mut TenantFinish,
) {
    let provisioning = head.door.lifecycle == Lifecycle::Provisioning;
    // The list is ascending, so the root unit (0) comes first.
    for &unit in &head.door.units {
        let step = match units.bring_up(tenant, unit).await {
            Ok(UnitHolds::Seq { state_seq }) => {
                if units.mark_born(tenant, unit).await.is_err() {
                    run.born_failed.push(unit);
                }
                StoreStep::Holds(state_seq)
            }
            Ok(UnitHolds::Unborn) => {
                // Past provisioning a listed unit that is not born has lost
                // its catalogue (or was never made): it pages.
                if !provisioning {
                    run.pages.push("unit_unborn");
                }
                StoreStep::Unborn
            }
            Err(_) => StoreStep::Failed,
        };
        run.units.push((unit, step));
    }
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
