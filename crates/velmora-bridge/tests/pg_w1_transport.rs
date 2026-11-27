//! The W1 hold through a proxy that forwards one request at a time, as
//! Hyperdrive did in the E0 probe: the one-Sync-per-statement transport
//! holds the writer lock across every request's wait, and the single-Sync
//! transport does not. 16 writers for 10 s per case, a 1-statement write and an
//! 11-statement batch shaped like `commit_generation`, with a 2 ms
//! sampler of the W1 holder's wait state. Needs `VELMORA_TEST_PG_URL`.

#![cfg(feature = "testkit-pg")]

mod pg_support;

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pg_support::{connect, Delay, Direct, Fault, Proxy, Schema};
use velmora_bridge::pg::WriteTx;
use velmora_bridge::{Sql, SqlValue};

const D: Duration = Duration::from_millis(5);
const WRITERS: usize = 16;
const RUN: Duration = Duration::from_secs(10);
/// Rows of the batch transaction (plus its guard and a read).
const BATCH_ROWS: i64 = 9;

const SETUP: &str = "CREATE TABLE w (tx bigint NOT NULL, i bigint NOT NULL, PRIMARY KEY (tx, i));
    CREATE TABLE tx_guard (ok BIGINT NOT NULL CONSTRAINT tx_guard_ok CHECK (ok = 1));";

#[derive(Debug, Default)]
struct Outcome {
    singles: u64,
    batches: u64,
    held_samples: u64,
    client_read: u64,
    acked: Vec<(i64, i64)>,
    /// Frontend Sync and Query messages the proxy saw.
    syncs: usize,
    queries: usize,
}

impl Outcome {
    fn per_second(n: u64) -> f64 {
        n as f64 / RUN.as_secs_f64()
    }
    fn total(&self) -> f64 {
        Self::per_second(self.singles + self.batches)
    }
    fn share(&self) -> f64 {
        self.client_read as f64 / self.held_samples.max(1) as f64
    }
}

async fn sample_w1(s: &Schema, stop: Arc<AtomicBool>) -> (u64, u64) {
    let client = connect(&s.base).await;
    let key = s.lock_key;
    let (classid, objid) = ((key >> 32) as u32, key as u32);
    let statement = client
        .prepare(
            "SELECT coalesce(a.wait_event, '') FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid \
             WHERE l.locktype = 'advisory' AND l.granted AND l.classid = $1::oid \
             AND l.objid = $2::oid AND l.objsubid = 1",
        )
        .await
        .unwrap();
    let (mut held, mut client_read) = (0, 0);
    while !stop.load(Ordering::Relaxed) {
        let rows = client.query(&statement, &[&classid, &objid]).await.unwrap();
        if let Some(row) = rows.first() {
            held += 1;
            if row.get::<_, String>(0) == "ClientRead" {
                client_read += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    (held, client_read)
}

async fn run(s: &Schema, write_tx: WriteTx, delay: Delay, next: Arc<AtomicI64>) -> Outcome {
    let proxy = Proxy::start(&s.base, delay, Fault::None).await;
    let config = proxy.config(&s.config());
    let stop = Arc::new(AtomicBool::new(false));
    let singles = Arc::new(AtomicU64::new(0));
    let batches = Arc::new(AtomicU64::new(0));
    let sampler = {
        let stop = stop.clone();
        async move { sample_w1(s, stop).await }
    };
    let writers = (0..WRITERS).map(|w| {
        let pg = s.pg(Direct(config.clone()), write_tx);
        let (stop, next) = (stop.clone(), next.clone());
        let (singles, batches) = (singles.clone(), batches.clone());
        async move {
            let mut acked = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let tx = next.fetch_add(1, Ordering::Relaxed);
                if w % 2 == 0 {
                    let n = pg
                        .exec("INSERT INTO w VALUES (?1, 0)", &[SqlValue::Int(tx)])
                        .await
                        .expect("single write");
                    assert_eq!(n, 1);
                    singles.fetch_add(1, Ordering::Relaxed);
                    acked.push((tx, 1));
                } else {
                    let mut stmts = vec![
                        ("INSERT INTO tx_guard(ok) SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM w WHERE tx = ?1) THEN 1 ELSE 0 END", vec![SqlValue::Int(tx)]),
                        ("SELECT count(*) FROM w WHERE tx = ?1", vec![SqlValue::Int(tx)]),
                    ];
                    for i in 0..BATCH_ROWS {
                        stmts.push(("INSERT INTO w VALUES (?1, ?2)", vec![SqlValue::Int(tx), SqlValue::Int(i)]));
                    }
                    assert_eq!(stmts.len(), 11);
                    let counts = pg.batch(stmts).await.expect("batch write");
                    assert_eq!(counts.len(), 11);
                    batches.fetch_add(1, Ordering::Relaxed);
                    acked.push((tx, BATCH_ROWS));
                }
            }
            acked
        }
    });
    let timer = async {
        tokio::time::sleep(RUN).await;
        stop.store(true, Ordering::Relaxed);
    };
    let started = Instant::now();
    let ((held, client_read), acked, ()) =
        tokio::join!(sampler, futures_util::future::join_all(writers), timer);
    let _ = started;
    let (syncs, queries) = {
        let trace = proxy.trace.lock().unwrap();
        (trace.syncs, trace.queries)
    };
    drop(proxy);
    Outcome {
        syncs,
        queries,
        singles: singles.load(Ordering::Relaxed),
        batches: batches.load(Ordering::Relaxed),
        held_samples: held,
        client_read,
        acked: acked.into_iter().flatten().collect(),
    }
}

async fn assert_all_or_nothing(s: &Schema, acked: &[(i64, i64)]) {
    // Every acknowledged transaction is there in full, and no transaction
    // is there in part.
    let rows = s
        .admin
        .query(
            &format!("SELECT tx, count(*) FROM {}.w GROUP BY tx", s.name),
            &[],
        )
        .await
        .unwrap();
    let stored: std::collections::BTreeMap<i64, i64> =
        rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    for (tx, n) in acked {
        assert_eq!(stored.get(tx), Some(n), "acknowledged transaction {tx}");
    }
    for (tx, n) in &stored {
        assert!(*n == 1 || *n == BATCH_ROWS, "transaction {tx} has {n} rows");
    }
}

fn report(name: &str, o: &Outcome) {
    println!(
        "{name}: {:.1} txn/s ({:.1} single, {:.1} batch), W1 held in {} samples, ClientRead share {:.3}",
        o.total(),
        Outcome::per_second(o.singles),
        Outcome::per_second(o.batches),
        o.held_samples,
        o.share()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_sync_writes_do_not_hold_w1_across_proxy_waits() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let next = Arc::new(AtomicI64::new(1));
    let typed_per_request = run(&s, WriteTx::Pipeline, Delay::PerRequest(D), next.clone()).await;
    report("pipelined, per-request proxy", &typed_per_request);
    let typed_faithful = run(&s, WriteTx::Pipeline, Delay::Faithful(D), next.clone()).await;
    report("pipelined, faithful latency", &typed_faithful);
    let single_sync_per_request =
        run(&s, WriteTx::SingleSync, Delay::PerRequest(D), next.clone()).await;
    report("single Sync, per-request proxy", &single_sync_per_request);

    // 1. The reproduction: W1 waits on the client, at most 1/(2d).
    assert!(typed_per_request.share() >= 0.5, "{typed_per_request:?}");
    let ceiling = 1.0 / (2.0 * D.as_secs_f64());
    assert!(typed_per_request.total() <= ceiling);
    assert!(Outcome::per_second(typed_per_request.singles) <= ceiling);
    // 2. Latency alone, with requests in one flight, does not cause it.
    assert!(typed_faithful.total() >= 3.0 * typed_per_request.total());
    // 3. One Sync per transaction removes it: exactly one Sync for each
    // write transaction, and no simple query on the success path.
    assert!(
        single_sync_per_request.share() <= 0.05,
        "{:.3}",
        single_sync_per_request.share()
    );
    assert!(single_sync_per_request.total() >= 3.0 * typed_per_request.total());
    let transactions = (single_sync_per_request.singles + single_sync_per_request.batches) as usize;
    assert_eq!(single_sync_per_request.syncs, transactions);
    assert_eq!(single_sync_per_request.queries, 0);
    // The typed transport sends a Sync per statement and two simple queries.
    assert!(
        typed_per_request.syncs > (typed_per_request.singles + typed_per_request.batches) as usize
    );
    // 4. Nothing acknowledged is missing and nothing is half applied.
    let acked: Vec<_> = [
        &typed_per_request,
        &typed_faithful,
        &single_sync_per_request,
    ]
    .iter()
    .flat_map(|o| o.acked.iter().copied())
    .collect();
    assert_all_or_nothing(&s, &acked).await;
}
