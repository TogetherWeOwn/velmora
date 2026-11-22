//! The pending sweep (tenancy ADR §2.5, "Three things finish a crashed
//! change"): a cron job that runs the finisher of every chain with a
//! `pending_ops` row older than [`SWEEP_AGE_MS`], and drops the rows of
//! that chain above the head the finisher read.
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
//! - a row above a **complete** head names a change that was never
//!   recorded: its intent was refused before its record, or its request
//!   stopped between the two. Nothing would ever clear it, so the sweep
//!   drops it.
//!
//! A head is complete ([`ChainHead::complete`]) when the finisher read
//! the chain to its end and recorded every revocation it found in
//! `m/rk/` without a chain record. A revocation whose chain record could
//! not be appended (a lost put, a store error, a key that would not
//! load) leaves the head below a change that is in force: the head is
//! then not complete, and no row of the chain is dropped.
//!
//! Only rows noted at or before the pass's cutoff are dropped
//! ([`PendingRows::drop_above`]). A retry of a change notes its row again
//! (noting refreshes the row's time), so a retry that records the seq
//! after the head was read keeps its row.
//!
//! A dropped row is only a copy. Should its record be written after all,
//! the freshness lease and the finisher of the chain's next change, both
//! of which read the head, finish it.
//!
//! The sweep goes chain by chain, in the order of the chains' keys, at
//! most [`SWEEP_CHAINS`] chains examined a pass, and the next pass starts
//! after the last one ([`SweepReport::next_after`]). A chain whose rows stay (a store
//! that is down, a subject that is closed) therefore holds no other
//! chain back. A chain whose finisher fails keeps its rows and stops no
//! other.

use crate::crypto::scheme2::TenantId;
use crate::keys::ports::ControlChain;
use crate::types::{Result, UnixMs};

/// Rows younger than this are left to their message: its delay (30 s,
/// est) and its first deliveries come first (ADR §2.5, "older than 2
/// minutes").
pub const SWEEP_AGE_MS: i64 = 2 * 60 * 1000;

/// Chains one pass finishes at most.
pub const SWEEP_CHAINS: u32 = 100;

/// A chain of a tenant: the key the sweep goes in order of: the tenant,
/// then its key chain before its tenant chain, the order of the
/// directory's `pending_ops` key (`tenant`, `chain` as `k` or `t`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainKey {
    pub tenant: TenantId,
    pub chain: ControlChain,
}

impl ChainKey {
    fn order(&self) -> (&TenantId, u8) {
        let chain = match self.chain {
            ControlChain::Keys => 0,
            ControlChain::Tenant => 1,
        };
        (&self.tenant, chain)
    }
}

impl Ord for ChainKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.order().cmp(&other.order())
    }
}

impl PartialOrd for ChainKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The directory's `pending_ops` rows, by chain.
#[allow(async_fn_in_trait)]
pub trait PendingRows {
    /// The next `limit` chains that have rows, in key order and after
    /// `after`, each with the time of its oldest row. It examines exactly
    /// the chains it answers, so a pass costs O(`limit`) index reads
    /// whatever the rows' ages or how many rows a chain holds: in SQL,
    /// step from chain to chain on the key `(tenant, chain, seq)`, and
    /// take each chain's oldest row from an index on `(tenant, chain,
    /// created_at)` (the column of `pending_ops` in
    /// `migrations-directory/0001_directory.sql`).
    async fn chains_after(
        &self,
        after: Option<&ChainKey>,
        limit: u32,
    ) -> Result<Vec<(ChainKey, UnixMs)>>;
    /// Deletes the rows of `chain` whose seq is above `head` and that
    /// were noted at or before `cutoff`, in one statement; answers how
    /// many. A row noted again after `cutoff` stays.
    async fn drop_above(&self, chain: &ChainKey, head: u64, cutoff: UnixMs) -> Result<u32>;
}

/// The head a finisher read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    /// The seq of the newest record (0 for a chain with no record).
    pub seq: u64,
    /// The chain was read to its end and every revocation of `m/rk/` has
    /// its chain record: no change in force is above `seq`.
    pub complete: bool,
}

/// The finisher of a chain.
#[allow(async_fn_in_trait)]
pub trait ChainFinisher {
    /// Runs the finisher of the chain, and answers the head it read. An
    /// `Err`: the head could not be read.
    async fn finish(&self, chain: &ChainKey) -> Result<ChainHead>;
}

/// What one pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Chains whose finisher ran and answered a complete head.
    pub finished: u32,
    /// Chains whose finisher answered a head that was not complete:
    /// their rows were kept.
    pub incomplete: u32,
    /// Chains whose finisher failed: their rows were kept.
    pub failed: u32,
    /// Chains whose drop failed: their rows were kept for the next pass.
    pub drop_failed: u32,
    /// Rows dropped: above a complete head.
    pub dropped: u32,
    /// Where the next pass starts: the last chain of this pass, or
    /// `None` when this pass reached the last chain (the next one starts
    /// from the first).
    pub next_after: Option<ChainKey>,
}

impl crate::keys::writer::FinishReport {
    /// The head this run of the key-chain finisher read, as the sweep
    /// takes it: complete only when the chain was read to its head and
    /// every revocation of `m/rk/` has its chain record.
    pub fn chain_head(&self) -> ChainHead {
        ChainHead {
            seq: self.head,
            complete: self.append_failed.is_empty() && !self.failed.iter().any(|l| l == "chain"),
        }
    }
}

/// One pass of the sweep at `now`, after the chain `after` (the
/// `next_after` of the pass before). The caller stores `next_after`
/// durably between passes (an isolate's memory does not outlive a cron
/// run; a directory row will do): a caller that passes `None` every time
/// only ever reaches the first [`SWEEP_CHAINS`] chains. An `Err` only when the chains could
/// not be read.
pub async fn sweep<P: PendingRows, F: ChainFinisher>(
    rows: &P,
    finisher: &F,
    now: UnixMs,
    after: Option<&ChainKey>,
) -> Result<SweepReport> {
    let cutoff = UnixMs(now.0 - SWEEP_AGE_MS);
    let chains = rows.chains_after(after, SWEEP_CHAINS).await?;
    let mut report = SweepReport {
        next_after: if chains.len() as u32 == SWEEP_CHAINS {
            chains.last().map(|(chain, _)| chain.clone())
        } else {
            None
        },
        ..SweepReport::default()
    };
    // A chain whose rows are all younger than the cutoff is left to its
    // messages.
    for (chain, _) in chains.iter().filter(|(_, oldest)| oldest.0 <= cutoff.0) {
        let head = match finisher.finish(chain).await {
            Ok(head) if head.complete => {
                report.finished += 1;
                head
            }
            Ok(_) => {
                report.incomplete += 1;
                continue;
            }
            Err(_) => {
                report.failed += 1;
                continue;
            }
        };
        match rows.drop_above(chain, head.seq, cutoff).await {
            Ok(n) => report.dropped += n,
            Err(_) => report.drop_failed += 1,
        }
    }
    Ok(report)
}
