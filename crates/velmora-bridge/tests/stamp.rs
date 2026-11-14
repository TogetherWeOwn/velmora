//! The rollback stamp: a catalogue that was restored to an earlier
//! point is found from the safety bucket, closes for writes and stops
//! its background jobs until a replay has ended.
//!
//! "Snapshot" here is a copy of every catalogue table inside the same
//! SQLite database; "rollback" puts every table back to it.

mod service_support;

use std::rc::Rc;

use serde_json::{json, Value};
use service_support::*;
use velmora_bridge::config::Maintenance;
use velmora_bridge::recovery::{delete_blob, TENANT_KEY_PREFIX};
use velmora_bridge::stamp::{stamp_key, StampRow, ERR_ROLLED_BACK, STAMP_PREFIX};
use velmora_bridge::*;

const BUCKET: &str = "vault";

/// Parents first.
const TABLES: [&str; 16] = [
    "buckets",
    "access_keys",
    "grants",
    "generations",
    "extents",
    "objects",
    "gc",
    "uploads",
    "upload_parts",
    "articles",
    "verifications",
    "key_floors",
    "outbox",
    "generation_extents",
    "restore_state",
    "rollback_stamp",
];

fn sql(rig: &Rig, script: &str) {
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(script).unwrap());
}

fn snapshot(rig: &Rig) {
    for t in TABLES {
        sql(
            rig,
            &format!("DROP TABLE IF EXISTS snap_{t}; CREATE TABLE snap_{t} AS SELECT * FROM {t};"),
        );
    }
}

/// Every table is as it was at the snapshot: what a Time Travel restore
/// or an import of an older export does.
fn rollback(rig: &Rig) {
    sql(rig, "PRAGMA foreign_keys = OFF;");
    for t in TABLES {
        sql(
            rig,
            &format!("DELETE FROM {t}; INSERT INTO {t} SELECT * FROM snap_{t};"),
        );
    }
    sql(rig, "PRAGMA foreign_keys = ON;");
}

fn stamps(rig: &Rig) -> Vec<String> {
    let mut keys: Vec<String> = rig
        .bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| k.starts_with(STAMP_PREFIX))
        .collect();
    keys.sort();
    keys
}

async fn row(rig: &Rig) -> StampRow {
    rig.bridge.catalog.stamp().await.unwrap()
}

/// The raise found the catalogue behind its stamp.
fn refused(raised: Result<()>) -> bool {
    matches!(raised, Err(BridgeError::Invalid(why)) if ERR_ROLLED_BACK.to_string().contains(why))
}

fn level(counter: u64) -> StampRow {
    StampRow {
        counter: Some(counter),
        rolled_back: false,
    }
}

async fn get(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
        .await
}

async fn delete(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Delete, &path(BUCKET, key), &[], &[], b"")
        .await
}

async fn admin(rig: &Rig, method: Method, path: &str, body: &[u8]) -> Resp {
    let mut req = Req {
        method,
        target: format!("/_admin{path}"),
        headers: Vec::new(),
        body: body.to_vec(),
    };
    req.set_header("host", HOST);
    req.set_header("content-length", &req.body.len().to_string());
    req.set_header(
        "authorization",
        &format!("Bearer {}", rig.bridge.cfg.admin_token.expose()),
    );
    rig.send(req).await
}

async fn status(rig: &Rig) -> Value {
    let r = admin(rig, Method::Get, "/status", b"").await;
    r.expect(200);
    serde_json::from_slice(&r.body).unwrap()
}

fn maintenance(rig: &mut Rig, mode: Maintenance) {
    Rc::get_mut(&mut rig.bridge).unwrap().cfg.maintenance = mode;
}

/// Runs the restore route to its end.
async fn restore(rig: &Rig) {
    let mut body = json!({ "since_ms": 0 });
    loop {
        let r = admin(rig, Method::Post, "/restore", body.to_string().as_bytes()).await;
        r.expect(200);
        let report: Value = serde_json::from_slice(&r.body).unwrap();
        if report["next"].is_null() {
            return;
        }
        body = json!({ "cursor": report["next"] });
    }
}

// ---------------------------------------------------------------------------
// No false alarm
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_fresh_catalogue_is_not_locked_out() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    // No row and no stamp object: nothing to be behind.
    assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());
    assert_eq!(row(&rig).await.counter, None);
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);

    let report = rig.bridge.dispatch().await.unwrap();
    assert!(!report.rolled_back && !report.stamp_failed && report.permits_seeded);
    assert_eq!(row(&rig).await, level(1));
    assert_eq!(stamps(&rig), [stamp_key("main", 1)]);
    assert_eq!(stamp_key("main", 1), "rs/main/00000000000000000001");

    // Each raise is one new object for a value the catalogue holds.
    rig.bridge.raise_stamp().await.unwrap();
    rig.bridge.dispatch().await.unwrap();
    assert_eq!(row(&rig).await, level(3));
    assert_eq!(
        stamps(&rig),
        [1, 2, 3].map(|n| stamp_key("main", n)).to_vec()
    );
    assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());
    rig.put(&signer, BUCKET, "b", b"b").await.expect(200);
    assert_eq!(status(&rig).await["catalogue_rolled_back"], false);
}

#[tokio::test(flavor = "current_thread")]
async fn the_bucket_is_never_ahead_of_the_catalogue() {
    let rig = rig();
    rig.bridge.raise_stamp().await.unwrap();

    // The object cannot be put: the counter has moved, the bucket has
    // not. That is the safe side, and the next raise covers it.
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = Some(STAMP_PREFIX.to_string());
    assert!(rig.bridge.raise_stamp().await.is_err());
    assert_eq!(row(&rig).await, level(2));
    assert_eq!(stamps(&rig), [stamp_key("main", 1)]);
    // The tick goes on without its stamp.
    let report = rig.bridge.dispatch().await.unwrap();
    assert!(report.stamp_failed && !report.rolled_back && report.permits_seeded);
    assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());

    *rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    rig.bridge.raise_stamp().await.unwrap();
    assert_eq!(row(&rig).await, level(4));
    assert_eq!(stamps(&rig), [stamp_key("main", 1), stamp_key("main", 4)]);
    assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());

    // A counter that cannot be moved puts no object at all.
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = Some(("UPDATE rollback_stamp", 0));
    assert!(rig.bridge.raise_stamp().await.is_err());
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = None;
    assert_eq!(row(&rig).await, level(4));
    assert_eq!(stamps(&rig).len(), 2);

    // A move from a value the counter has left changes nothing.
    assert!(!rig.bridge.catalog.stamp_advance(Some(3)).await.unwrap());
    assert!(!rig.bridge.catalog.stamp_advance(None).await.unwrap());
    assert_eq!(row(&rig).await, level(4));

    // The stamps of another catalogue over the same bucket do not count.
    let other = BucketId::new("-");
    let meta = BlobMeta {
        bucket: &other,
        extent: &ExtentId::new("rollback-stamp"),
        cipher_sha256: &sha256(b""),
    };
    let key = stamp_key("other", 99);
    rig.bridge
        .safety
        .put(&key, Vec::new(), &meta)
        .await
        .unwrap();
    assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());
}

// ---------------------------------------------------------------------------
// A rollback is found, closes the gate, and a replay opens it
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_rollback_closes_writes_and_stops_jobs_until_a_replay_ends() {
    let mut rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
    rig.bridge.dispatch().await.unwrap();
    rig.bridge.clock.advance_ms(1000);
    snapshot(&rig);

    // After the restore point: a write, and the raise that covers it.
    rig.put(&signer, BUCKET, "b", b"b").await.expect(200);
    rig.bridge.raise_stamp().await.unwrap();
    assert_eq!(row(&rig).await, level(2));

    rollback(&rig);
    rig.bridge.jobs.inner.take();
    assert_eq!(row(&rig).await, level(1));
    get(&rig, &signer, "b").await.expect(404);

    // The tick finds it before it does anything else, and does not move
    // the counter: one more raise would have made the two level.
    let report = rig.bridge.dispatch().await.unwrap();
    assert!(report.rolled_back && !report.permits_seeded);
    assert_eq!(report.enqueued, 0);
    assert!(rig.bridge.jobs.inner.sent().is_empty());
    assert_eq!(
        row(&rig).await,
        StampRow {
            counter: Some(1),
            rolled_back: true
        }
    );
    assert_eq!(stamps(&rig).len(), 2);

    // Writes are refused, reads are served, jobs do nothing.
    assert!(rig.bridge.catalogue_rolled_back().await.unwrap());
    rig.put(&signer, BUCKET, "c", b"c").await.expect(503);
    delete(&rig, &signer, "a").await.expect(503);
    get(&rig, &signer, "a").await.expect(200);
    assert_eq!(
        rig.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(refused(rig.bridge.raise_stamp().await));
    assert_eq!(stamps(&rig).len(), 2);
    let s = status(&rig).await;
    assert_eq!(s["catalogue_rolled_back"], true);
    assert_eq!(s["replay_unfinished"], true);
    // It stays so over any number of ticks.
    assert!(rig.bridge.dispatch().await.unwrap().rolled_back);
    assert_eq!(row(&rig).await.counter, Some(1));

    // The replay brings the write back and makes the two level.
    maintenance(&mut rig, Maintenance::Restore);
    restore(&rig).await;
    maintenance(&mut rig, Maintenance::Off);
    assert_eq!(row(&rig).await, level(2));
    assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());
    assert_eq!(get(&rig, &signer, "b").await.expect(200).body, b"b");
    rig.put(&signer, BUCKET, "c", b"c").await.expect(200);
    let report = rig.bridge.dispatch().await.unwrap();
    assert!(!report.rolled_back && report.permits_seeded);
    assert_eq!(row(&rig).await, level(3));
    assert_eq!(status(&rig).await["catalogue_rolled_back"], false);
}

#[tokio::test(flavor = "current_thread")]
async fn a_raise_on_a_rolled_back_catalogue_does_not_hide_it() {
    let rig = rig();
    rig.bridge.raise_stamp().await.unwrap();
    snapshot(&rig);
    // Exactly one raise is lost with the rollback: a raise that moved
    // the counter first would find its own value already taken, put it
    // again, and leave the two level.
    rig.bridge.raise_stamp().await.unwrap();
    rollback(&rig);

    assert!(refused(rig.bridge.raise_stamp().await));
    assert_eq!(
        row(&rig).await,
        StampRow {
            counter: Some(1),
            rolled_back: true
        }
    );
    assert_eq!(stamps(&rig), [stamp_key("main", 1), stamp_key("main", 2)]);
    assert!(rig.bridge.dispatch().await.unwrap().rolled_back);
    assert!(rig.bridge.catalogue_rolled_back().await.unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn a_catalogue_without_its_counter_is_behind_any_stamp() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bridge.raise_stamp().await.unwrap();
    // A restore from an export that has no counter row.
    sql(&rig, "DELETE FROM rollback_stamp;");

    assert!(rig.bridge.catalogue_rolled_back().await.unwrap());
    assert_eq!(
        row(&rig).await,
        StampRow {
            counter: Some(0),
            rolled_back: true
        }
    );
    rig.put(&signer, BUCKET, "a", b"a").await.expect(503);
    assert!(refused(rig.bridge.raise_stamp().await));
    assert_eq!(stamps(&rig).len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_check_that_cannot_be_made_ends_the_tick() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
    rig.bridge.jobs.inner.take();

    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = Some(("FROM rollback_stamp", 0));
    assert!(rig.bridge.dispatch().await.is_err());
    assert!(rig.bridge.catalogue_rolled_back().await.is_err());
    assert!(rig.bridge.jobs.inner.sent().is_empty());
    assert!(stamps(&rig).is_empty());
}

// ---------------------------------------------------------------------------
// The replay and the stamp
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_replay_that_did_not_end_leaves_the_catalogue_closed() {
    let mut rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
    rig.bridge.raise_stamp().await.unwrap();
    snapshot(&rig);
    rig.bridge.raise_stamp().await.unwrap();
    rollback(&rig);
    assert!(rig.bridge.catalogue_rolled_back().await.unwrap());

    // The end of an older replay does not make the stamp level.
    let catalog = &rig.bridge.catalog;
    let old = catalog.restore_begin(UnixMs(0), rig.now()).await.unwrap();
    let run = catalog.restore_begin(UnixMs(0), rig.now()).await.unwrap();
    assert!(!catalog.restore_finish(old, rig.now(), 2).await.unwrap());
    assert!(row(&rig).await.rolled_back);
    assert_eq!(row(&rig).await.counter, Some(1));
    rig.put(&signer, BUCKET, "b", b"b").await.expect(503);

    // The end of the one under way does, and never moves the counter down.
    assert!(catalog.restore_finish(run, rig.now(), 2).await.unwrap());
    assert_eq!(row(&rig).await, level(2));
    assert!(catalog.restore_finish(run, rig.now(), 1).await.unwrap());
    assert_eq!(row(&rig).await, level(2));
    rig.put(&signer, BUCKET, "b", b"b").await.expect(200);

    // The route reads the newest stamp itself, also when the catalogue
    // has no counter at all.
    rig.bridge.raise_stamp().await.unwrap();
    rig.bridge.raise_stamp().await.unwrap();
    sql(&rig, "DELETE FROM rollback_stamp;");
    maintenance(&mut rig, Maintenance::Restore);
    restore(&rig).await;
    assert_eq!(row(&rig).await, level(4));
}

// ---------------------------------------------------------------------------
// No delete removes a stamp or a reserved key
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn no_delete_removes_a_stamp_or_a_tenant_key() {
    let rig = rig();
    rig.bridge.raise_stamp().await.unwrap();
    let stamp = stamp_key("main", 1);
    let tenant_key = format!("{TENANT_KEY_PREFIX}t_0000000000000000/1");
    let bucket = BucketId::new("-");
    let meta = BlobMeta {
        bucket: &bucket,
        extent: &ExtentId::new("tenant-key"),
        cipher_sha256: &sha256(b"k"),
    };
    rig.bridge
        .safety
        .put(&tenant_key, b"k".to_vec(), &meta)
        .await
        .unwrap();

    for key in [&stamp, &tenant_key] {
        assert!(rig.bridge.safety.delete(key).await.is_err(), "{key}");
        assert!(delete_blob(&rig.bridge.safety, key).await.is_err(), "{key}");
        assert!(rig.bridge.safety.contains(key), "{key}");
    }
}
