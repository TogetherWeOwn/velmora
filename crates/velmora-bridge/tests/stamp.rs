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
    rig.bridge.catalog.stamp("main").await.unwrap()
}

/// The raise found the catalogue behind its stamp.
fn refused(raised: Result<()>) -> bool {
    matches!(raised, Err(BridgeError::Invalid(why)) if ERR_ROLLED_BACK.to_string().contains(why))
}

fn behind(counter: u64) -> StampRow {
    StampRow {
        counter: Some(counter),
        rolled_back: true,
    }
}

/// Puts a stamp object as a raise would.
async fn put_stamp(rig: &Rig, counter: u64) {
    let bucket = BucketId::new("-");
    let body = rig.now().0.to_string().into_bytes();
    let meta = BlobMeta {
        bucket: &bucket,
        extent: &ExtentId::new("rollback-stamp"),
        cipher_sha256: &sha256(&body),
    };
    let key = stamp_key("main", counter);
    rig.bridge.safety.put(&key, body, &meta).await.unwrap();
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

/// Runs the restore route to its end. Returns the body of its last call.
async fn restore(rig: &Rig) -> Value {
    restore_with(rig, || ()).await
}

/// The same; `before_step` runs before every call that carries a cursor.
async fn restore_with(rig: &Rig, before_step: impl Fn()) -> Value {
    let mut body = json!({ "since_ms": 0 });
    loop {
        if body.get("cursor").is_some() {
            before_step();
        }
        let r = admin(rig, Method::Post, "/restore", body.to_string().as_bytes()).await;
        r.expect(200);
        let report: Value = serde_json::from_slice(&r.body).unwrap();
        if report["next"].is_null() {
            return body;
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
    assert!(!rig
        .bridge
        .catalog
        .stamp_advance(Some(3), "main")
        .await
        .unwrap());
    assert!(!rig
        .bridge
        .catalog
        .stamp_advance(None, "main")
        .await
        .unwrap());
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
    rig.put(&signer, BUCKET, "c", b"c")
        .await
        .expect_writes_refused();
    delete(&rig, &signer, "a").await.expect_writes_refused();
    get(&rig, &signer, "a").await.expect(200);
    assert_eq!(
        rig.bridge
            .run_job(&TENANT_ZERO, &Job::Gc { v: JOB_VERSION })
            .await,
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

/// Runs `checked` up to its list call, lets `between` run to its end,
/// then lets the list call go on: `checked` compares a counter it read
/// before `between` with the objects that are there after it.
async fn interleave<A, B>(rig: &Rig, checked: A, between: B) -> A::Output
where
    A: std::future::Future,
    B: std::future::Future,
{
    let safety = &rig.bridge.safety;
    safety.hold_list.set(true);
    let between = async {
        // Bounded: a `checked` that makes no list call fails the test.
        let mut turns = 0;
        while !safety.list_held.get() {
            turns += 1;
            assert!(turns < HOLD_TURNS, "no list call was made");
            tokio::task::yield_now().await;
        }
        between.await;
        safety.list_held.set(false);
    };
    tokio::join!(checked, between).0
}

/// Two raises at once: one reads the counter, the other moves it and
/// puts its object, then the first one lists. The object it sees is no
/// sign of a rollback.
#[tokio::test(flavor = "current_thread")]
async fn a_raise_beside_another_raise_is_not_a_rollback() {
    let rig = rig();
    let bridge = &rig.bridge;
    bridge.raise_stamp().await.unwrap();

    let other = async { bridge.raise_stamp().await.unwrap() };
    interleave(&rig, bridge.raise_stamp(), other).await.unwrap();
    assert_eq!(row(&rig).await, level(3));
    assert_eq!(stamps(&rig).len(), 3);

    let other = async { bridge.raise_stamp().await.unwrap() };
    assert!(!interleave(&rig, bridge.catalogue_rolled_back(), other)
        .await
        .unwrap());
    assert_eq!(row(&rig).await, level(4));

    let other = async { bridge.raise_stamp().await.unwrap() };
    let report = interleave(&rig, bridge.dispatch(), other).await.unwrap();
    assert!(!report.rolled_back && !report.stamp_failed && report.permits_seeded);
    assert_eq!(row(&rig).await, level(6));
    assert_eq!(stamps(&rig).len(), 6);
}

/// The same on a catalogue that has no counter yet.
#[tokio::test(flavor = "current_thread")]
async fn the_first_raise_beside_a_check_is_not_a_rollback() {
    let rig = rig();
    let bridge = &rig.bridge;
    let other = async { bridge.raise_stamp().await.unwrap() };
    assert!(!interleave(&rig, bridge.catalogue_rolled_back(), other)
        .await
        .unwrap());
    assert_eq!(row(&rig).await, level(1));

    let rig = self::rig();
    let bridge = &rig.bridge;
    let other = async { bridge.raise_stamp().await.unwrap() };
    interleave(&rig, bridge.raise_stamp(), other).await.unwrap();
    assert_eq!(row(&rig).await, level(2));
}

/// A rollback that happens between the read and the list call is still
/// found: the counter is what was read, and an object is after it.
#[tokio::test(flavor = "current_thread")]
async fn a_rollback_beside_a_check_is_found() {
    let rig = rig();
    let bridge = &rig.bridge;
    bridge.raise_stamp().await.unwrap();
    snapshot(&rig);
    let lost = async {
        // Moves the counter and comes back to the same value.
        bridge.raise_stamp().await.unwrap();
        rollback(&rig);
    };
    assert!(interleave(&rig, bridge.catalogue_rolled_back(), lost)
        .await
        .unwrap());
    assert!(row(&rig).await.rolled_back);
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
    let old = catalog
        .restore_begin(UnixMs(0), rig.now())
        .await
        .unwrap()
        .unwrap();
    let run = catalog
        .restore_begin(UnixMs(0), rig.now())
        .await
        .unwrap()
        .unwrap();
    assert!(!catalog
        .restore_finish(old, rig.now(), 2, row(&rig).await.counter, "main")
        .await
        .unwrap());
    assert!(row(&rig).await.rolled_back);
    assert_eq!(row(&rig).await.counter, Some(1));
    rig.put(&signer, BUCKET, "b", b"b").await.expect(503);

    // The end of the one under way does, and never moves the counter down.
    assert!(catalog
        .restore_finish(run, rig.now(), 2, row(&rig).await.counter, "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await, level(2));
    assert!(catalog
        .restore_finish(run, rig.now(), 1, row(&rig).await.counter, "main")
        .await
        .unwrap());
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

/// A replay ended, and the catalogue was later rolled back to a point
/// after it. The last call of that replay, sent again, is a cursor the
/// catalogue knows; it reads no record. It must not open the catalogue.
#[tokio::test(flavor = "current_thread")]
async fn the_last_call_of_an_ended_replay_does_not_clear_a_later_rollback() {
    let mut rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
    maintenance(&mut rig, Maintenance::Restore);
    let last = restore(&rig).await;
    assert!(last.get("cursor").is_some(), "{last}");
    // Sent again while nothing happened: the same answer, as before.
    admin(&rig, Method::Post, "/restore", last.to_string().as_bytes())
        .await
        .expect(200);
    maintenance(&mut rig, Maintenance::Off);
    rig.bridge.dispatch().await.unwrap();
    let before = row(&rig).await;

    snapshot(&rig);
    rig.put(&signer, BUCKET, "b", b"b").await.expect(200);
    rig.bridge.dispatch().await.unwrap();
    rollback(&rig);
    assert!(rig.bridge.dispatch().await.unwrap().rolled_back);

    maintenance(&mut rig, Maintenance::Restore);
    let refused = admin(&rig, Method::Post, "/restore", last.to_string().as_bytes()).await;
    refused.expect(409);
    assert!(refused.text().contains("rolled back"), "{}", refused.text());
    assert_eq!(
        row(&rig).await,
        StampRow {
            rolled_back: true,
            ..before
        }
    );
    assert_eq!(status(&rig).await["catalogue_rolled_back"], true);
    get(&rig, &signer, "b").await.expect(404);

    // A new replay reads the records and opens it.
    restore(&rig).await;
    assert!(!row(&rig).await.rolled_back);
    assert_eq!(get(&rig, &signer, "b").await.expect(200).body, b"b");
}

/// A replay ran, and the catalogue was later rolled back to a point
/// where that replay had not ended yet. The rest of that replay reads
/// none of the records written after it: its last call must not open
/// the catalogue, and the tick says what happened.
#[tokio::test(flavor = "current_thread")]
async fn a_rollback_into_a_replay_is_not_cleared_by_that_replay() {
    let mut rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
    rig.bridge.dispatch().await.unwrap();
    rig.bridge.clock.advance_ms(1000);

    // The snapshot that stays is the one before the last call.
    maintenance(&mut rig, Maintenance::Restore);
    let last = restore_with(&rig, || snapshot(&rig)).await;
    assert!(last.get("cursor").is_some(), "{last}");
    maintenance(&mut rig, Maintenance::Off);

    rig.bridge.clock.advance_ms(1000);
    rig.put(&signer, BUCKET, "b", b"b").await.expect(200);
    rig.bridge.dispatch().await.unwrap();
    rig.bridge.dispatch().await.unwrap();
    assert_eq!(row(&rig).await, level(3));

    let last = last.to_string();
    for tick_first in [true, false] {
        rollback(&rig);
        rig.bridge.jobs.inner.take();
        assert_eq!(row(&rig).await, level(1));
        get(&rig, &signer, "b").await.expect(404);
        if tick_first {
            // The replay is on record as not ended, so the tick sends
            // nothing. It still looks at the bucket.
            let report = rig.bridge.dispatch().await.unwrap();
            assert!(report.rolled_back && !report.permits_seeded);
            assert!(rig.bridge.jobs.inner.sent().is_empty());
            assert_eq!(row(&rig).await, behind(1));
        }
        maintenance(&mut rig, Maintenance::Restore);
        let refused = admin(&rig, Method::Post, "/restore", last.as_bytes()).await;
        refused.expect(409);
        assert!(refused.text().contains("rolled back"), "{}", refused.text());
        assert_eq!(row(&rig).await, behind(1), "tick first: {tick_first}");
        maintenance(&mut rig, Maintenance::Off);
        rig.put(&signer, BUCKET, "c", b"c").await.expect(503);
        get(&rig, &signer, "b").await.expect(404);
    }
    maintenance(&mut rig, Maintenance::Restore);

    // A new replay must not start later than the one that did not end.
    let later = json!({ "since_ms": 5000, "margin_ms": 0 }).to_string();
    let refused = admin(&rig, Method::Post, "/restore", later.as_bytes()).await;
    refused.expect(409);
    let said: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(said["unfinished_since_ms"], 0, "{said}");
    admin(&rig, Method::Post, "/restore", last.as_bytes())
        .await
        .expect(409);

    restore(&rig).await;
    maintenance(&mut rig, Maintenance::Off);
    assert_eq!(row(&rig).await, level(3));
    assert_eq!(get(&rig, &signer, "b").await.expect(200).body, b"b");
    rig.put(&signer, BUCKET, "c", b"c").await.expect(200);
    assert!(!rig.bridge.dispatch().await.unwrap().rolled_back);
    // Once a replay has ended, the next one starts where it is told to.
    maintenance(&mut rig, Maintenance::Restore);
    admin(&rig, Method::Post, "/restore", later.as_bytes())
        .await
        .expect(200);
}

/// The runbook closes a restored database with one statement file, then
/// starts the replay from the restore point. That file must not look
/// like a replay from the beginning that did not end; a replay that
/// really did not end keeps its restore point through it.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_starts_at_its_restore_point_after_the_runbook_statement() {
    const ARM: &str = include_str!("../../../workers/s3-bridge/ops/restore-arm.sql");
    let mut rig = rig();
    maintenance(&mut rig, Maintenance::Restore);
    let rig = &rig;
    let begin = |since_ms: i64| async move {
        let body = json!({ "since_ms": since_ms, "margin_ms": 0 }).to_string();
        admin(rig, Method::Post, "/restore", body.as_bytes()).await
    };

    // No replay ever ran on this database.
    sql(rig, ARM);
    sql(rig, ARM);
    begin(5000).await.expect(200);
    // A replay ran to its end.
    restore(rig).await;
    sql(rig, ARM);
    sql(rig, ARM);
    begin(5000).await.expect(200);
    // That one did not end.
    sql(rig, ARM);
    let refused = begin(5001).await;
    refused.expect(409);
    let said: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(said["unfinished_since_ms"], 5000, "{said}");
    begin(5000).await.expect(200);
    begin(4000).await.expect(200);
    begin(4001).await.expect(409);
}

/// The last step reads the stamp, then ends the replay. A database that
/// is brought back in between, to a point where that replay had not
/// ended, must not be opened with what was read before.
#[tokio::test(flavor = "current_thread")]
async fn the_end_of_a_replay_holds_the_catalogue_to_the_counter_it_read() {
    let rig = rig();
    rig.bridge.raise_stamp().await.unwrap();
    let catalog = &rig.bridge.catalog;
    let run = catalog
        .restore_begin(UnixMs(0), rig.now())
        .await
        .unwrap()
        .unwrap();
    snapshot(&rig);
    assert!(catalog
        .restore_finish(run, rig.now(), 2, Some(1), "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await, level(2));
    assert!(!catalog.restore_pending().await.unwrap());

    // The last step is sent again and reads the counter; then the
    // database goes back.
    let seen = row(&rig).await.counter;
    rollback(&rig);
    assert!(!catalog
        .restore_finish(run, rig.now(), 2, seen, "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await, level(1));
    assert!(catalog.restore_pending().await.unwrap());
    // No row where one was read is the same.
    sql(&rig, "DELETE FROM rollback_stamp;");
    assert!(!catalog
        .restore_finish(run, rig.now(), 2, seen, "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await.counter, None);
    assert!(catalog.restore_pending().await.unwrap());
    // And a row where none was read.
    rollback(&rig);
    assert!(!catalog
        .restore_finish(run, rig.now(), 2, None, "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await, level(1));
    assert!(catalog.restore_pending().await.unwrap());
    // A level counter with a rollback on record does not open it either.
    sql(
        &rig,
        "UPDATE rollback_stamp SET counter = 2, rolled_back_at = 1;",
    );
    assert!(!catalog
        .restore_finish(run, rig.now(), 2, Some(1), "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await, behind(2));
    assert!(catalog.restore_pending().await.unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn the_end_of_a_replay_never_moves_the_counter_down() {
    let mut rig = rig();
    rig.bridge.raise_stamp().await.unwrap();
    rig.bridge.raise_stamp().await.unwrap();
    // Two values whose objects could not be put: the newest object is
    // behind the counter.
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = Some(STAMP_PREFIX.to_string());
    assert!(rig.bridge.raise_stamp().await.is_err());
    assert!(rig.bridge.raise_stamp().await.is_err());
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    assert_eq!(row(&rig).await, level(4));
    assert_eq!(stamps(&rig).len(), 2);

    maintenance(&mut rig, Maintenance::Restore);
    restore(&rig).await;
    assert_eq!(row(&rig).await, level(4));

    // The same in the catalogue alone, for a replay that is under way.
    let catalog = &rig.bridge.catalog;
    let run = catalog
        .restore_begin(UnixMs(0), rig.now())
        .await
        .unwrap()
        .unwrap();
    assert!(catalog
        .restore_finish(run, rig.now(), 1, row(&rig).await.counter, "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await, level(4));

    // And a replay that has ended changes no stamp when it is ended
    // again: a rollback found since stays on record.
    sql(&rig, "UPDATE rollback_stamp SET rolled_back_at = 1;");
    assert!(catalog
        .restore_finish(run, rig.now(), 9, row(&rig).await.counter, "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await, behind(4));
}

#[tokio::test(flavor = "current_thread")]
async fn the_newest_stamp_is_found_over_many_list_pages() {
    let mut rig = rig();
    rig.bridge.raise_stamp().await.unwrap();
    snapshot(&rig);
    for counter in 2..=1101 {
        put_stamp(&rig, counter).await;
    }
    rollback(&rig);
    assert!(rig.bridge.catalogue_rolled_back().await.unwrap());

    maintenance(&mut rig, Maintenance::Restore);
    restore(&rig).await;
    assert_eq!(row(&rig).await, level(1101));
    assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());
}

// ---------------------------------------------------------------------------
// Checks that fail, and checks beside something else
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_tick_whose_check_fails_sends_no_job() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
    rig.bridge.raise_stamp().await.unwrap();
    rig.bridge.jobs.inner.take();
    // The tick has something to send.
    sql(&rig, "UPDATE outbox SET next_at = 0;");

    // The bucket cannot be listed.
    rig.bridge.safety.fail_list.set(true);
    assert!(rig.bridge.dispatch().await.is_err());
    rig.bridge.safety.fail_list.set(false);
    assert!(rig.bridge.jobs.inner.sent().is_empty());

    // The stamp row cannot be read; every other statement works.
    let only_the_row = Some(("SELECT counter, rolled_back_at", 0));
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = only_the_row;
    assert!(!rig.bridge.catalog.restore_pending().await.unwrap());
    assert!(rig.bridge.dispatch().await.is_err());
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = None;
    assert!(rig.bridge.jobs.inner.sent().is_empty());
    assert_eq!(row(&rig).await, level(1));

    let report = rig.bridge.dispatch().await.unwrap();
    assert!(report.enqueued > 0, "the tick had nothing to send");
    assert!(!rig.bridge.jobs.inner.sent().is_empty());
}

/// The gate at the start of a request is read before its batch runs. A
/// rollback that is recorded in between refuses the batch.
#[tokio::test(flavor = "current_thread")]
async fn a_rollback_recorded_after_the_gate_refuses_the_commit() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bridge.raise_stamp().await.unwrap();

    let bridge = rig.bridge.clone();
    let hook = move |_: &str| {
        bridge.catalog.sql.with_conn(|c| {
            c.execute("UPDATE rollback_stamp SET rolled_back_at = 1", [])
                .unwrap()
        });
    };
    rig.bridge.safety.before_put.replace(Some(Box::new(hook)));
    rig.put(&signer, BUCKET, "a", b"a").await.expect(503);
    assert_eq!(row(&rig).await, behind(1), "the hook ran");

    sql(&rig, "UPDATE rollback_stamp SET rolled_back_at = NULL;");
    get(&rig, &signer, "a").await.expect(404);
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
}

#[tokio::test(flavor = "current_thread")]
async fn a_recorded_rollback_stops_the_counter() {
    let rig = rig();
    rig.bridge.raise_stamp().await.unwrap();
    sql(&rig, "UPDATE rollback_stamp SET rolled_back_at = 1;");
    assert!(!rig
        .bridge
        .catalog
        .stamp_advance(Some(1), "main")
        .await
        .unwrap());
    assert_eq!(row(&rig).await, behind(1));
}

/// A write raises the stamp between the tick's check and the tick's own
/// raise. The check was made: the tick goes on, without a raise.
#[tokio::test(flavor = "current_thread")]
async fn a_tick_that_loses_its_raise_to_a_write_goes_on() {
    let rig = rig();
    let bridge = &rig.bridge;
    bridge.raise_stamp().await.unwrap();

    bridge.safety.list_first.set(true);
    let other = async { bridge.raise_stamp().await.unwrap() };
    let report = interleave(&rig, bridge.dispatch(), other).await.unwrap();
    assert!(!report.rolled_back && !report.stamp_failed && report.permits_seeded);
    assert_eq!(row(&rig).await, level(2));
    assert_eq!(stamps(&rig).len(), 2);

    // A raise that must put its own object tries again.
    bridge.safety.list_first.set(true);
    let other = async { bridge.raise_stamp().await.unwrap() };
    interleave(&rig, bridge.raise_stamp(), other).await.unwrap();
    assert_eq!(row(&rig).await, level(4));
    assert_eq!(stamps(&rig).len(), 4);

    // Lost to a restore of the database, which took the counter back:
    // the check is made again and finds it.
    bridge.jobs.inner.take();
    snapshot(&rig);
    bridge.raise_stamp().await.unwrap();
    bridge.safety.list_first.set(true);
    let restored = async { rollback(&rig) };
    let report = interleave(&rig, bridge.dispatch(), restored).await.unwrap();
    assert!(report.rolled_back && !report.permits_seeded);
    assert!(bridge.jobs.inner.sent().is_empty());
    assert_eq!(row(&rig).await, behind(4));
    assert_eq!(stamps(&rig).len(), 5);

    // Lost to a raise, after which a check recorded a rollback: the
    // counter moved up, and the tick ends all the same.
    sql(
        &rig,
        "UPDATE rollback_stamp SET counter = 5, rolled_back_at = NULL;",
    );
    bridge.safety.list_first.set(true);
    let found = async {
        let both = "UPDATE rollback_stamp SET counter = 6, rolled_back_at = 1;";
        sql(&rig, both)
    };
    let report = interleave(&rig, bridge.dispatch(), found).await.unwrap();
    assert!(report.rolled_back && !report.permits_seeded);
    assert!(bridge.jobs.inner.sent().is_empty());
    assert_eq!(row(&rig).await, behind(6));
}

/// Garbage collection and eviction delete. Each looks at the bucket
/// itself first, whatever the last tick saw.
#[tokio::test(flavor = "current_thread")]
async fn gc_and_eviction_check_the_stamp_before_they_delete() {
    let rig = rig();
    let bridge = &rig.bridge;
    bridge.raise_stamp().await.unwrap();
    snapshot(&rig);
    bridge.raise_stamp().await.unwrap();
    let gc = Job::Gc { v: JOB_VERSION };

    rollback(&rig);
    assert_eq!(bridge.run_job(&TENANT_ZERO, &gc).await, JobOutcome::Ack);
    assert_eq!(row(&rig).await, behind(1));
    rollback(&rig);
    assert_eq!(bridge.evict_batch(&TENANT_ZERO, 0).await.unwrap(), 0);
    assert_eq!(row(&rig).await, behind(1));

    // A check that cannot be made: the job comes back later.
    rollback(&rig);
    bridge.safety.fail_list.set(true);
    assert_ne!(bridge.run_job(&TENANT_ZERO, &gc).await, JobOutcome::Ack);
    assert!(bridge.evict_batch(&TENANT_ZERO, 0).await.is_err());
    assert_eq!(row(&rig).await, level(1));
}

/// The row keeps the id its objects are keyed by. Under another id the
/// bucket would look empty and no rollback would ever be found.
#[tokio::test(flavor = "current_thread")]
async fn a_stamp_of_another_catalogue_id_is_not_used() {
    let mut rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
    rig.bridge.raise_stamp().await.unwrap();
    rig.bridge.jobs.inner.take();
    sql(&rig, "UPDATE outbox SET next_at = 0;");

    let set_id = |rig: &mut Rig, id: &str| {
        Rc::get_mut(&mut rig.bridge).unwrap().cfg.catalogue_id = id.to_string();
    };
    set_id(&mut rig, "other");
    let wrong_id = |e: BridgeError| velmora_bridge::stamp::is_catalogue_id_error(&e);
    assert!(wrong_id(rig.bridge.raise_stamp().await.unwrap_err()));
    assert!(wrong_id(
        rig.bridge.catalogue_rolled_back().await.unwrap_err()
    ));
    assert!(wrong_id(rig.bridge.dispatch().await.unwrap_err()));
    assert!(rig.bridge.jobs.inner.sent().is_empty());
    assert_ne!(
        rig.bridge
            .run_job(&TENANT_ZERO, &Job::Gc { v: JOB_VERSION })
            .await,
        JobOutcome::Ack
    );
    assert!(rig.bridge.evict_batch(&TENANT_ZERO, 0).await.is_err());
    assert_eq!(stamps(&rig), [stamp_key("main", 1)]);
    let s = status(&rig).await;
    assert_eq!(s["catalogue_id_mismatch"], true);
    assert!(s["catalogue_rolled_back"].is_null(), "{s}");
    maintenance(&mut rig, Maintenance::Restore);
    let mut body = json!({ "since_ms": 0 }).to_string();
    loop {
        let r = admin(&rig, Method::Post, "/restore", body.as_bytes()).await;
        if r.status != 200 {
            r.expect(500);
            break;
        }
        let report: Value = serde_json::from_slice(&r.body).unwrap();
        assert!(
            !report["next"].is_null(),
            "the replay ended under another id"
        );
        body = json!({ "cursor": report["next"] }).to_string();
    }
    sql(&rig, "DELETE FROM restore_state;");
    maintenance(&mut rig, Maintenance::Off);

    set_id(&mut rig, "main");
    rig.bridge.raise_stamp().await.unwrap();
    assert_eq!(row(&rig).await, level(2));
    let s = status(&rig).await;
    assert_eq!(s["catalogue_id_mismatch"], false);
    assert_eq!(s["catalogue_rolled_back"], false);
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

/// The one tenant there is.
static TENANT_ZERO: velmora_bridge::TenantScope = velmora_bridge::TenantScope::tenant_zero();
