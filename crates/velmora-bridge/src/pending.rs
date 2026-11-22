//! The pending sweep (tenancy ADR §2.5, "Three things finish a crashed
//! change"): a cron job that takes the `pending_ops` rows older than
//! [`SWEEP_AGE_MS`], runs the finisher of each named chain, and drops a
//! row that names a change above the chain's head.
//!
//! A `pending_ops` row is the visible copy of a control intent; the
//! queue message `apply_control(tenant, chain, seq)` is its durable part
//! (`keys::ports::ControlIntents`). The finisher reads the head of the
//! chain, never a row's seq, applies every record above what each store
//! holds, and clears the rows at or below what every store holds. So
//! after it has run:
//!
//! - a row at or below the head is a recorded change: the finisher has
//!   cleared it if every store holds it, and otherwise it stays and the
//!   next pass runs the finisher again (the attention list reads the age
//!   of what stays from the directory; ADR: alarm at 10 minutes, page at
//!   30);
//! - a row above the head names a change that was never recorded: its
//!   intent was refused before its record, or the Worker stopped between
//!   the two. Nothing will ever clear it, so the sweep drops it.
//!
//! Dropping a row is safe whatever happens next: a row is only a copy.
//! Should the record of a dropped row be written after all (a request
//! still running), its queue message and the freshness lease still
//! finish it, and the finisher reads the head, not the row. The finisher
//! runs before the head is compared, so a revocation whose `m/rk/` record
//! was written and whose chain record was not is appended by the
//! finisher first, and its row is then at or below the head.
//!
//! The sweep runs each chain at most once per pass, and a chain whose
//! finisher fails keeps its rows (nothing is dropped on a head that was
//! not read) and does not stop the others.

use crate::crypto::scheme2::TenantId;
use crate::keys::ports::ControlChain;
use crate::types::{Result, UnixMs};

/// Rows younger than this are left to their message: its delay (30 s,
/// est) and its first deliveries come first (ADR §2.5, "older than 2
/// minutes").
pub const SWEEP_AGE_MS: i64 = 2 * 60 * 1000;

/// Rows one pass takes at most.
pub const SWEEP_ROWS: u32 = 500;

/// One `pending_ops` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRow {
    pub tenant: TenantId,
    pub chain: ControlChain,
    pub seq: u64,
    /// When the intent was noted.
    pub noted_at: UnixMs,
}

/// The directory's `pending_ops` rows.
#[allow(async_fn_in_trait)]
pub trait PendingRows {
    /// Up to `limit` rows noted at or before `cutoff`, oldest first.
    async fn noted_by(&self, cutoff: UnixMs, limit: u32) -> Result<Vec<PendingRow>>;
    /// Removes this one row (tenant, chain and seq). A row that is gone
    /// already is no error.
    async fn drop_row(&self, row: &PendingRow) -> Result<()>;
}

/// The finisher of a chain.
#[allow(async_fn_in_trait)]
pub trait ChainFinisher {
    /// Runs the finisher of `chain` of `tenant`, and answers the head
    /// seq it read (0 for a chain with no record). An `Err`: the head
    /// could not be read.
    async fn finish(&self, tenant: &TenantId, chain: ControlChain) -> Result<u64>;
}

/// What one pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Rows taken.
    pub rows: u32,
    /// Chains whose finisher ran and answered a head.
    pub finished: u32,
    /// Chains whose finisher failed: their rows were kept.
    pub failed: u32,
    /// Rows of those chains.
    pub unread: u32,
    /// Rows at or below the head: recorded changes, which the finisher
    /// cleared if every store holds them, and left otherwise.
    pub recorded: u32,
    /// Rows dropped: above the head after the finisher.
    pub dropped: u32,
    /// Rows above the head whose drop failed: kept for the next pass.
    pub drop_failed: u32,
}

/// One pass of the sweep at `now`. An `Err` only when the rows could not
/// be read.
pub async fn sweep<P: PendingRows, F: ChainFinisher>(
    rows: &P,
    finisher: &F,
    now: UnixMs,
) -> Result<SweepReport> {
    let taken = rows
        .noted_by(UnixMs(now.0 - SWEEP_AGE_MS), SWEEP_ROWS)
        .await?;
    let mut report = SweepReport {
        rows: taken.len() as u32,
        ..SweepReport::default()
    };
    // Each chain once, in the order of its oldest row.
    let mut chains: Vec<(&TenantId, ControlChain)> = Vec::new();
    for row in &taken {
        if !chains
            .iter()
            .any(|(t, c)| *t == &row.tenant && *c == row.chain)
        {
            chains.push((&row.tenant, row.chain));
        }
    }
    for (tenant, chain) in chains {
        let of_chain = taken
            .iter()
            .filter(|r| &r.tenant == tenant && r.chain == chain);
        let head = match finisher.finish(tenant, chain).await {
            Ok(head) => {
                report.finished += 1;
                head
            }
            Err(_) => {
                report.failed += 1;
                report.unread += of_chain.count() as u32;
                continue;
            }
        };
        for row in of_chain {
            if row.seq <= head {
                report.recorded += 1;
            } else if rows.drop_row(row).await.is_ok() {
                report.dropped += 1;
            } else {
                report.drop_failed += 1;
            }
        }
    }
    Ok(report)
}
