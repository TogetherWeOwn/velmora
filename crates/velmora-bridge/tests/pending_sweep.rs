//! The pending sweep (`velmora_bridge::pending`): chains with a row
//! older than two minutes; the finisher of each chain once, before any
//! row is compared with its head; rows above a complete head are
//! dropped, nothing is dropped on a head that is not complete; a chain
//! that cannot be read keeps its rows; the sweep goes on from where the
//! last pass stopped, so rows that stay hold no other chain back.

use std::cell::RefCell;

use velmora_bridge::keys::ports::ControlChain;
use velmora_bridge::pending::{
    sweep, ChainFinisher, ChainHead, ChainKey, PendingRows, SweepReport, SWEEP_AGE_MS, SWEEP_CHAINS,
};
use velmora_bridge::{BridgeError, Result, TenantId, UnixMs};

const NOW: UnixMs = UnixMs(1_794_000_000_000);
const OLD: i64 = SWEEP_AGE_MS + 1_000;

fn tenant(n: u32) -> TenantId {
    TenantId::parse(&format!("t_{:016x}", u64::from(n) + 0x100)).unwrap()
}

fn key(t: u32, chain: ControlChain) -> ChainKey {
    ChainKey {
        tenant: tenant(t),
        chain,
    }
}

/// (chain, seq, noted_at) rows.
#[derive(Default)]
struct Rows {
    rows: RefCell<Vec<(ChainKey, u64, UnixMs)>>,
    asked: RefCell<Vec<(UnixMs, Option<ChainKey>, u32)>>,
    refuse_reads: bool,
    refuse_drops: bool,
}

impl Rows {
    fn with(rows: &[(u32, ControlChain, u64, i64)]) -> Rows {
        let r = Rows::default();
        for (t, c, seq, age) in rows {
            r.rows
                .borrow_mut()
                .push((key(*t, *c), *seq, UnixMs(NOW.0 - age)));
        }
        r
    }

    fn seqs_of(&self, chain: &ChainKey) -> Vec<u64> {
        let mut seqs: Vec<u64> = self
            .rows
            .borrow()
            .iter()
            .filter(|(k, _, _)| k == chain)
            .map(|(_, s, _)| *s)
            .collect();
        seqs.sort_unstable();
        seqs
    }
}

impl PendingRows for Rows {
    async fn chains_noted_by(
        &self,
        cutoff: UnixMs,
        after: Option<&ChainKey>,
        limit: u32,
    ) -> Result<Vec<ChainKey>> {
        self.asked
            .borrow_mut()
            .push((cutoff, after.cloned(), limit));
        if self.refuse_reads {
            return Err(BridgeError::Sql("directory down".into()));
        }
        let mut chains: Vec<ChainKey> = self
            .rows
            .borrow()
            .iter()
            .filter(|(k, _, at)| at.0 <= cutoff.0 && after.is_none_or(|a| k > a))
            .map(|(k, _, _)| k.clone())
            .collect();
        chains.sort();
        chains.dedup();
        chains.truncate(limit as usize);
        Ok(chains)
    }

    async fn drop_above(&self, chain: &ChainKey, head: u64, cutoff: UnixMs) -> Result<u32> {
        if self.refuse_drops {
            return Err(BridgeError::Sql("directory down".into()));
        }
        let mut rows = self.rows.borrow_mut();
        let before = rows.len();
        rows.retain(|(k, seq, at)| !(k == chain && *seq > head && at.0 <= cutoff.0));
        Ok((before - rows.len()) as u32)
    }
}

/// Heads by chain; a run may raise one first (a revocation it appends),
/// answer it incomplete, or fail.
#[derive(Default)]
struct Finisher {
    heads: RefCell<Vec<(ChainKey, ChainHead)>>,
    raise_to: Vec<(ChainKey, u64)>,
    fail: Vec<ChainKey>,
    calls: RefCell<Vec<ChainKey>>,
}

impl Finisher {
    fn with(heads: &[(u32, ControlChain, u64)]) -> Finisher {
        let f = Finisher::default();
        for (t, c, seq) in heads {
            f.set(key(*t, *c), *seq, true);
        }
        f
    }

    fn set(&self, chain: ChainKey, seq: u64, complete: bool) {
        let mut heads = self.heads.borrow_mut();
        heads.retain(|(k, _)| *k != chain);
        heads.push((chain, ChainHead { seq, complete }));
    }
}

impl ChainFinisher for Finisher {
    async fn finish(&self, chain: &ChainKey) -> Result<ChainHead> {
        self.calls.borrow_mut().push(chain.clone());
        if self.fail.contains(chain) {
            return Err(BridgeError::Blob("chain unreadable".into()));
        }
        if let Some((_, to)) = self.raise_to.iter().find(|(k, _)| k == chain) {
            self.set(chain.clone(), *to, true);
        }
        Ok(self.heads.borrow().iter().find(|(k, _)| k == chain).map_or(
            ChainHead {
                seq: 0,
                complete: true,
            },
            |(_, h)| *h,
        ))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rows_above_a_complete_head_are_dropped_and_the_others_left() {
    let keys = key(1, ControlChain::Keys);
    let state = key(1, ControlChain::Tenant);
    let rows = Rows::with(&[
        (1, ControlChain::Keys, 4, OLD),
        (1, ControlChain::Keys, 5, OLD),
        (1, ControlChain::Keys, 6, OLD + 4_000),
        // Above the head, but younger than the cutoff: left to its message.
        (1, ControlChain::Keys, 7, SWEEP_AGE_MS - 1),
        (1, ControlChain::Tenant, 2, OLD),
    ]);
    let f = Finisher::with(&[(1, ControlChain::Keys, 5), (1, ControlChain::Tenant, 2)]);
    let report = sweep(&rows, &f, NOW, None).await.unwrap();
    assert_eq!(
        report,
        SweepReport {
            finished: 2,
            dropped: 1,
            ..SweepReport::default()
        }
    );
    assert_eq!(rows.seqs_of(&keys), [4, 5, 7]);
    assert_eq!(rows.seqs_of(&state), [2]);
    // Each chain once, in key order (`k` before `t`, as the directory's
    // key sorts them).
    assert_eq!(*f.calls.borrow(), [keys, state]);
    assert_eq!(
        *rows.asked.borrow(),
        [(UnixMs(NOW.0 - SWEEP_AGE_MS), None, SWEEP_CHAINS)]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_is_dropped_on_a_head_that_is_not_complete() {
    // A revocation's m/rk/ record is written, its chain record could not
    // be appended: the head is below a change in force.
    let rows = Rows::with(&[(2, ControlChain::Keys, 8, OLD)]);
    let f = Finisher::default();
    f.set(key(2, ControlChain::Keys), 7, false);
    let report = sweep(&rows, &f, NOW, None).await.unwrap();
    assert_eq!((report.incomplete, report.dropped), (1, 0));
    assert_eq!(rows.seqs_of(&key(2, ControlChain::Keys)), [8]);
}

#[tokio::test(flavor = "current_thread")]
async fn the_head_is_read_after_the_finisher_has_run() {
    // The finisher appends the missing revocation, so its row is at the
    // head.
    let rows = Rows::with(&[(2, ControlChain::Keys, 8, OLD)]);
    let mut f = Finisher::with(&[(2, ControlChain::Keys, 7)]);
    f.raise_to.push((key(2, ControlChain::Keys), 8));
    let report = sweep(&rows, &f, NOW, None).await.unwrap();
    assert_eq!((report.finished, report.dropped), (1, 0));
    assert_eq!(rows.seqs_of(&key(2, ControlChain::Keys)), [8]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_chain_that_cannot_be_read_keeps_its_rows_and_stops_no_other() {
    let rows = Rows::with(&[
        (1, ControlChain::Keys, 9, OLD),
        (1, ControlChain::Keys, 10, OLD),
        (3, ControlChain::Tenant, 4, OLD),
    ]);
    let mut f = Finisher::with(&[(3, ControlChain::Tenant, 3)]);
    f.fail.push(key(1, ControlChain::Keys));
    let report = sweep(&rows, &f, NOW, None).await.unwrap();
    assert_eq!(
        report,
        SweepReport {
            finished: 1,
            failed: 1,
            dropped: 1,
            ..SweepReport::default()
        }
    );
    assert_eq!(rows.seqs_of(&key(1, ControlChain::Keys)), [9, 10]);
    assert!(rows.seqs_of(&key(3, ControlChain::Tenant)).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_drop_is_counted_and_the_rows_stay() {
    let rows = Rows {
        refuse_drops: true,
        ..Rows::with(&[(1, ControlChain::Keys, 3, OLD)])
    };
    let f = Finisher::with(&[(1, ControlChain::Keys, 2)]);
    let report = sweep(&rows, &f, NOW, None).await.unwrap();
    assert_eq!((report.dropped, report.drop_failed), (0, 1));
    assert_eq!(rows.seqs_of(&key(1, ControlChain::Keys)), [3]);
}

#[tokio::test(flavor = "current_thread")]
async fn chains_that_cannot_be_read_are_an_error() {
    let rows = Rows {
        refuse_reads: true,
        ..Rows::default()
    };
    let f = Finisher::default();
    assert!(sweep(&rows, &f, NOW, None).await.is_err());
    assert!(f.calls.borrow().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn tenants_are_swept_apart() {
    // The same chain and seq in two tenants: each against its own head.
    let rows = Rows::with(&[
        (1, ControlChain::Keys, 5, OLD),
        (2, ControlChain::Keys, 5, OLD),
    ]);
    let f = Finisher::with(&[(1, ControlChain::Keys, 5), (2, ControlChain::Keys, 4)]);
    let report = sweep(&rows, &f, NOW, None).await.unwrap();
    assert_eq!(report.dropped, 1);
    assert_eq!(rows.seqs_of(&key(1, ControlChain::Keys)), [5]);
    assert!(rows.seqs_of(&key(2, ControlChain::Keys)).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn rows_that_stay_hold_no_later_chain_back() {
    // More chains whose rows stay (a closed subject: never a complete
    // head) than one pass takes, ahead of one droppable row.
    let stuck = SWEEP_CHAINS + 50;
    let mut fixture: Vec<(u32, ControlChain, u64, i64)> = (0..stuck)
        .map(|t| (t, ControlChain::Keys, 1, OLD + 60_000))
        .collect();
    fixture.push((stuck, ControlChain::Keys, 9, OLD));
    let rows = Rows::with(&fixture);
    let f = Finisher::default();
    for t in 0..stuck {
        f.set(key(t, ControlChain::Keys), 0, false);
    }
    f.set(key(stuck, ControlChain::Keys), 8, true);

    let first = sweep(&rows, &f, NOW, None).await.unwrap();
    assert_eq!((first.incomplete, first.dropped), (SWEEP_CHAINS, 0));
    assert_eq!(
        first.next_after,
        Some(key(SWEEP_CHAINS - 1, ControlChain::Keys))
    );
    let second = sweep(&rows, &f, NOW, first.next_after.as_ref())
        .await
        .unwrap();
    assert_eq!(
        (second.incomplete, second.finished, second.dropped),
        (50, 1, 1)
    );
    // The last chain was reached: the next pass starts from the first.
    assert_eq!(second.next_after, None);
    assert!(rows.seqs_of(&key(stuck, ControlChain::Keys)).is_empty());
    assert_eq!(rows.rows.borrow().len(), stuck as usize);
}

#[tokio::test(flavor = "current_thread")]
async fn a_row_noted_again_after_the_cutoff_stays() {
    // A retry noted seq 6 again just now, after its first try's row was
    // old: the sweep only drops what was noted by the cutoff.
    let rows = Rows::with(&[
        (4, ControlChain::Keys, 5, OLD),
        (4, ControlChain::Keys, 6, 1_000),
    ]);
    let f = Finisher::with(&[(4, ControlChain::Keys, 4)]);
    let report = sweep(&rows, &f, NOW, None).await.unwrap();
    assert_eq!(report.dropped, 1);
    assert_eq!(rows.seqs_of(&key(4, ControlChain::Keys)), [6]);
}

#[test]
fn a_finisher_run_is_complete_only_without_a_failed_append_or_chain_read() {
    use velmora_bridge::keys::writer::FinishReport;
    let clean = FinishReport {
        head: 9,
        failed: vec!["unit 2".into()],
        closed: vec!["k1".into()],
        ..FinishReport::default()
    };
    // A store that did not acknowledge, or a closed subject, leaves the
    // head complete: the rows above it are still unrecorded changes.
    assert_eq!(
        clean.chain_head(),
        ChainHead {
            seq: 9,
            complete: true
        }
    );
    let append = FinishReport {
        head: 9,
        append_failed: vec!["AKID".into()],
        ..FinishReport::default()
    };
    assert_eq!(
        append.chain_head(),
        ChainHead {
            seq: 9,
            complete: false
        }
    );
    let unread = FinishReport {
        head: 4,
        failed: vec!["chain".into()],
        ..FinishReport::default()
    };
    assert_eq!(
        unread.chain_head(),
        ChainHead {
            seq: 4,
            complete: false
        }
    );
}
