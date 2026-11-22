//! The pending sweep (`velmora_bridge::pending`): rows older than two
//! minutes; the finisher of each chain once, before any row is compared
//! with its head; a row above the head is dropped, a row at or below it
//! is left to the finisher; a chain that cannot be read keeps its rows.

use std::cell::RefCell;
use std::collections::BTreeMap;

use velmora_bridge::keys::ports::ControlChain;
use velmora_bridge::pending::{
    sweep, ChainFinisher, PendingRow, PendingRows, SweepReport, SWEEP_AGE_MS, SWEEP_ROWS,
};
use velmora_bridge::{BridgeError, Result, TenantId, UnixMs};

const NOW: UnixMs = UnixMs(1_794_000_000_000);

fn tenant(n: u8) -> TenantId {
    TenantId::parse(&format!("t_00000000000000{n:02x}")).unwrap()
}

fn row(t: u8, chain: ControlChain, seq: u64, age_ms: i64) -> PendingRow {
    PendingRow {
        tenant: tenant(t),
        chain,
        seq,
        noted_at: UnixMs(NOW.0 - age_ms),
    }
}

#[derive(Default)]
struct Rows {
    rows: RefCell<Vec<PendingRow>>,
    cutoffs: RefCell<Vec<(UnixMs, u32)>>,
    refuse_reads: bool,
    refuse_drops: bool,
}

impl PendingRows for Rows {
    async fn noted_by(&self, cutoff: UnixMs, limit: u32) -> Result<Vec<PendingRow>> {
        self.cutoffs.borrow_mut().push((cutoff, limit));
        if self.refuse_reads {
            return Err(BridgeError::Sql("directory down".into()));
        }
        let mut rows: Vec<_> = self
            .rows
            .borrow()
            .iter()
            .filter(|r| r.noted_at.0 <= cutoff.0)
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.noted_at.0);
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn drop_row(&self, row: &PendingRow) -> Result<()> {
        if self.refuse_drops {
            return Err(BridgeError::Sql("directory down".into()));
        }
        self.rows.borrow_mut().retain(|r| r != row);
        Ok(())
    }
}

/// Heads by chain; a finisher run may raise one first (a revocation it
/// appends), and may fail.
#[derive(Default)]
struct Finisher {
    heads: RefCell<BTreeMap<(String, bool), u64>>,
    raise_to: BTreeMap<(String, bool), u64>,
    fail: Vec<(String, bool)>,
    /// (tenant, keys chain?, rows of the store when called)
    calls: RefCell<Vec<(String, bool)>>,
}

fn key(t: &TenantId, chain: ControlChain) -> (String, bool) {
    (t.as_str().to_owned(), chain == ControlChain::Keys)
}

impl ChainFinisher for Finisher {
    async fn finish(&self, tenant: &TenantId, chain: ControlChain) -> Result<u64> {
        let k = key(tenant, chain);
        self.calls.borrow_mut().push(k.clone());
        if self.fail.contains(&k) {
            return Err(BridgeError::Blob("chain unreadable".into()));
        }
        if let Some(to) = self.raise_to.get(&k) {
            self.heads.borrow_mut().insert(k.clone(), *to);
        }
        Ok(self.heads.borrow().get(&k).copied().unwrap_or(0))
    }
}

fn finisher(heads: &[(u8, ControlChain, u64)]) -> Finisher {
    let f = Finisher::default();
    for (t, c, h) in heads {
        f.heads.borrow_mut().insert(key(&tenant(*t), *c), *h);
    }
    f
}

#[tokio::test(flavor = "current_thread")]
async fn a_row_above_the_head_is_dropped_and_one_at_or_below_it_is_left() {
    let rows = Rows::default();
    *rows.rows.borrow_mut() = vec![
        row(1, ControlChain::Keys, 4, SWEEP_AGE_MS + 1_000),
        row(1, ControlChain::Keys, 5, SWEEP_AGE_MS + 1_000),
        row(1, ControlChain::Keys, 6, SWEEP_AGE_MS + 5_000),
        row(1, ControlChain::Tenant, 2, SWEEP_AGE_MS + 1_000),
    ];
    let f = finisher(&[(1, ControlChain::Keys, 5), (1, ControlChain::Tenant, 2)]);
    let report = sweep(&rows, &f, NOW).await.unwrap();
    assert_eq!(
        report,
        SweepReport {
            rows: 4,
            finished: 2,
            recorded: 3,
            dropped: 1,
            ..SweepReport::default()
        }
    );
    let left: Vec<_> = rows.rows.borrow().iter().map(|r| r.seq).collect();
    assert_eq!(left, [4, 5, 2]);
    // One run per chain, the chain of the oldest row first.
    assert_eq!(
        *f.calls.borrow(),
        [
            key(&tenant(1), ControlChain::Keys),
            key(&tenant(1), ControlChain::Tenant)
        ]
    );
    assert_eq!(
        *rows.cutoffs.borrow(),
        [(UnixMs(NOW.0 - SWEEP_AGE_MS), SWEEP_ROWS)]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_row_younger_than_two_minutes_is_left_to_its_message() {
    let rows = Rows::default();
    *rows.rows.borrow_mut() = vec![row(1, ControlChain::Keys, 9, SWEEP_AGE_MS - 1)];
    let f = finisher(&[(1, ControlChain::Keys, 0)]);
    let report = sweep(&rows, &f, NOW).await.unwrap();
    assert_eq!(report, SweepReport::default());
    assert!(f.calls.borrow().is_empty());
    assert_eq!(rows.rows.borrow().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn the_head_is_read_after_the_finisher_has_run() {
    // A revocation whose m/rk/ record is written and whose chain record
    // is not: the finisher appends it, so its row is at the head.
    let rows = Rows::default();
    *rows.rows.borrow_mut() = vec![row(2, ControlChain::Keys, 8, SWEEP_AGE_MS)];
    let mut f = finisher(&[(2, ControlChain::Keys, 7)]);
    f.raise_to.insert(key(&tenant(2), ControlChain::Keys), 8);
    let report = sweep(&rows, &f, NOW).await.unwrap();
    assert_eq!((report.recorded, report.dropped), (1, 0));
    assert_eq!(rows.rows.borrow().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_chain_that_cannot_be_read_keeps_its_rows_and_stops_no_other() {
    let rows = Rows::default();
    *rows.rows.borrow_mut() = vec![
        row(1, ControlChain::Keys, 9, SWEEP_AGE_MS + 3_000),
        row(1, ControlChain::Keys, 10, SWEEP_AGE_MS + 2_000),
        row(3, ControlChain::Tenant, 4, SWEEP_AGE_MS + 1_000),
    ];
    let mut f = finisher(&[(3, ControlChain::Tenant, 3)]);
    f.fail.push(key(&tenant(1), ControlChain::Keys));
    let report = sweep(&rows, &f, NOW).await.unwrap();
    assert_eq!(
        report,
        SweepReport {
            rows: 3,
            finished: 1,
            failed: 1,
            unread: 2,
            dropped: 1,
            ..SweepReport::default()
        }
    );
    let left: Vec<_> = rows.rows.borrow().iter().map(|r| r.seq).collect();
    assert_eq!(left, [9, 10]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_drop_is_counted_and_the_row_stays() {
    let rows = Rows {
        refuse_drops: true,
        ..Rows::default()
    };
    *rows.rows.borrow_mut() = vec![row(1, ControlChain::Keys, 3, SWEEP_AGE_MS)];
    let f = finisher(&[(1, ControlChain::Keys, 2)]);
    let report = sweep(&rows, &f, NOW).await.unwrap();
    assert_eq!((report.dropped, report.drop_failed), (0, 1));
    assert_eq!(rows.rows.borrow().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn rows_that_cannot_be_read_are_an_error() {
    let rows = Rows {
        refuse_reads: true,
        ..Rows::default()
    };
    let f = finisher(&[]);
    assert!(sweep(&rows, &f, NOW).await.is_err());
    assert!(f.calls.borrow().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn tenants_are_swept_apart() {
    // The same chain and seq in two tenants: each against its own head.
    let rows = Rows::default();
    *rows.rows.borrow_mut() = vec![
        row(1, ControlChain::Keys, 5, SWEEP_AGE_MS + 2_000),
        row(2, ControlChain::Keys, 5, SWEEP_AGE_MS + 1_000),
    ];
    let f = finisher(&[(1, ControlChain::Keys, 5), (2, ControlChain::Keys, 4)]);
    let report = sweep(&rows, &f, NOW).await.unwrap();
    assert_eq!((report.recorded, report.dropped), (1, 1));
    let left: Vec<_> = rows
        .rows
        .borrow()
        .iter()
        .map(|r| r.tenant.as_str().to_owned())
        .collect();
    assert_eq!(left, [tenant(1).as_str()]);
}
