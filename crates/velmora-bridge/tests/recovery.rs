//! Catalogue recovery (DESIGN §A.8): the recovery records are written
//! before a commit, are never deleted, and rebuild the catalogue.
//!
//! "Export" here is a copy of every catalogue table inside the same
//! SQLite database; "loss" deletes every row.

mod service_support;

use serde_json::{json, Value};
use service_support::*;
use velmora_bridge::config::Maintenance;
use velmora_bridge::recovery::{delete_blob, GENERATION_PREFIX, TOMBSTONE_PREFIX};
use velmora_bridge::replay::{ReplayCursor, ReplayLimits, ReplayReport};
use velmora_bridge::*;

const BUCKET: &str = "vault";
const TABLES: [&str; 13] = [
    "generation_extents",
    "outbox",
    "verifications",
    "articles",
    "upload_parts",
    "uploads",
    "gc",
    "objects",
    "extents",
    "generations",
    "grants",
    "access_keys",
    "buckets",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sql(rig: &Rig, script: &str) {
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(script).unwrap());
}

/// Copies every table aside (the export).
fn export(rig: &Rig) {
    for t in TABLES {
        sql(
            rig,
            &format!("DROP TABLE IF EXISTS bak_{t}; CREATE TABLE bak_{t} AS SELECT * FROM {t};"),
        );
    }
}

/// Deletes every catalogue row (the loss).
fn wipe(rig: &Rig) {
    for t in TABLES {
        sql(rig, &format!("DELETE FROM {t};"));
    }
    for t in TABLES {
        assert_eq!(rig.count(t), 0, "{t} is empty after the wipe");
    }
}

/// Loads the export back. Tables go in parent-first order.
fn import(rig: &Rig) {
    for t in TABLES.iter().rev() {
        // The `extents` rows have already written their own references.
        sql(
            rig,
            &format!("INSERT OR IGNORE INTO {t} SELECT * FROM bak_{t};"),
        );
    }
}

/// Everything the catalogue says, for "nothing changed" checks.
fn dump(rig: &Rig) -> String {
    let mut out = String::new();
    for t in TABLES {
        rig.bridge.catalog.sql.with_conn(|c| {
            let mut stmt = c
                .prepare(&format!("SELECT * FROM {t} ORDER BY 1, 2"))
                .unwrap();
            let n = stmt.column_count();
            let mut rows = stmt.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                out.push_str(t);
                for i in 0..n {
                    out.push_str(&format!("|{:?}", row.get_ref(i).unwrap()));
                }
                out.push('\n');
            }
        });
    }
    out
}

fn add(total: &mut ReplayReport, step: ReplayReport) {
    total.manifests += step.manifests;
    total.published += step.published;
    total.present += step.present;
    total.superseded += step.superseded;
    total.extents += step.extents;
    total.article_plans += step.article_plans;
    total.safety_missing += step.safety_missing;
    total.tombstones += step.tombstones;
    total.deleted += step.deleted;
    total.unpublishable.extend(step.unpublishable);
    total.unreadable.extend(step.unreadable);
    total.damaged_total = step.damaged_total;
    total.damaged = step.damaged;
}

/// Replays to the end. Returns the summed report and the number of calls.
async fn replay(rig: &Rig, since: UnixMs, limits: ReplayLimits) -> (ReplayReport, u32) {
    let mut total = ReplayReport::default();
    let mut cursor = Some(ReplayCursor::start(since));
    let mut calls = 0;
    while let Some(at) = cursor {
        calls += 1;
        assert!(calls < 10_000, "the replay does not end");
        let mut step = rig.bridge.replay_step_within(at, limits).await.unwrap();
        cursor = step.next.take();
        add(&mut total, step);
    }
    (total, calls)
}

async fn get(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
        .await
}

async fn delete(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Delete, &path(BUCKET, key), &[], &[], b"")
        .await
}

async fn create_upload(rig: &Rig, signer: &Signer, key: &str) -> String {
    let r = rig
        .call(
            signer,
            Method::Post,
            &path(BUCKET, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    r.expect(200);
    r.values("UploadId").remove(0)
}

async fn upload_part(
    rig: &Rig,
    signer: &Signer,
    key: &str,
    id: &str,
    n: u16,
    body: &[u8],
) -> String {
    let r = rig
        .call(
            signer,
            Method::Put,
            &path(BUCKET, key),
            &[("partNumber", &n.to_string()), ("uploadId", id)],
            &[],
            body,
        )
        .await;
    r.expect(200);
    r.header("etag").unwrap().to_string()
}

async fn complete(rig: &Rig, signer: &Signer, key: &str, id: &str, etags: &[String]) -> Resp {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in etags.iter().enumerate() {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
            i + 1,
            etag.replace('"', "&quot;")
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        signer,
        Method::Post,
        &path(BUCKET, key),
        &[("uploadId", id)],
        &[],
        xml.as_bytes(),
    )
    .await
}

/// A two-extent object: parts of 5 MiB and 1 KiB.
async fn multipart(rig: &Rig, signer: &Signer, key: &str, seed: u8) -> Vec<u8> {
    let first = pattern(seed, 5 * MIB);
    let last = pattern(seed.wrapping_add(1), 1024);
    let id = create_upload(rig, signer, key).await;
    let etags = vec![
        upload_part(rig, signer, key, &id, 1, &first).await,
        upload_part(rig, signer, key, &id, 2, &last).await,
    ];
    complete(rig, signer, key, &id, &etags).await.expect(200);
    [first, last].concat()
}

fn records(rig: &Rig) -> Vec<String> {
    rig.bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| k.starts_with("m/"))
        .collect()
}

/// The access key and its grant are not in the recovery records: an
/// operator issues them again.
async fn reissue_key(rig: &Rig) -> Signer {
    let bucket = rig
        .bridge
        .catalog
        .bucket_by_name(BUCKET)
        .await
        .unwrap()
        .expect("the replay restored the bucket");
    let signer = rig.key(AKID, secret(), KeyStatus::Active).await;
    rig.grant(AKID, &bucket, Perm::Rw).await;
    signer
}

fn tick(rig: &Rig) {
    rig.bridge.clock.advance_ms(1000);
}

// ---------------------------------------------------------------------------
// A record that cannot be written stops the request before the commit
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn manifest_write_failure_commits_nothing() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "kept", b"kept").await.expect(200);
    tick(&rig);
    let upload = create_upload(&rig, &signer, "mp").await;
    let etag = upload_part(&rig, &signer, "mp", &upload, 1, b"part one").await;
    let before = dump(&rig);
    let records_before = records(&rig);

    *rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("m/".to_string());

    // PUT: the extent blob is stored, the catalogue never hears of it.
    let put = rig.put(&signer, BUCKET, "k", b"payload").await;
    put.expect_error(500, "InternalError");
    assert_eq!(put.header("etag"), None);
    assert!(rig.live(&bucket, "k").await.is_none());
    rig.head(&signer, BUCKET, "k").await.expect(404);

    // An overwrite leaves the old object in place.
    rig.put(&signer, BUCKET, "kept", b"newer")
        .await
        .expect_error(500, "InternalError");
    assert_eq!(get(&rig, &signer, "kept").await.expect(200).body, b"kept");

    // Complete: the upload stays open and nothing is published.
    complete(&rig, &signer, "mp", &upload, std::slice::from_ref(&etag))
        .await
        .expect_error(500, "InternalError");
    assert!(rig.live(&bucket, "mp").await.is_none());

    // DELETE: the object stays.
    delete(&rig, &signer, "kept")
        .await
        .expect_error(500, "InternalError");
    assert_eq!(get(&rig, &signer, "kept").await.expect(200).body, b"kept");

    assert_eq!(dump(&rig), before, "no catalogue row changed");
    assert_eq!(records(&rig), records_before, "no record was written");
    assert_eq!(rig.bridge.budget.in_use(), 0);

    // The store recovers and the same requests go through.
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    tick(&rig);
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    complete(&rig, &signer, "mp", &upload, std::slice::from_ref(&etag))
        .await
        .expect(200);
    delete(&rig, &signer, "kept").await.expect(204);
    get(&rig, &signer, "kept").await.expect(404);
    assert_eq!(records(&rig).len(), records_before.len() + 3);
}

/// A delete of nothing writes no tombstone.
#[tokio::test(flavor = "current_thread")]
async fn delete_of_a_missing_key_writes_no_record() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    delete(&rig, &signer, "never").await.expect(204);
    assert!(records(&rig).is_empty());
}

// ---------------------------------------------------------------------------
// Records are never deleted
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn recovery_records_survive_gc_and_eviction() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"one").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "k", b"two").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "gone", b"gone").await.expect(200);
    tick(&rig);
    delete(&rig, &signer, "gone").await.expect(204);
    let kept = records(&rig);
    assert_eq!(
        kept.iter()
            .filter(|k| k.starts_with(GENERATION_PREFIX))
            .count(),
        3
    );
    assert_eq!(
        kept.iter()
            .filter(|k| k.starts_with(TOMBSTONE_PREFIX))
            .count(),
        1
    );
    let extents_before = rig
        .bridge
        .safety
        .keys()
        .iter()
        .filter(|k| k.starts_with("x/"))
        .count();
    assert_eq!(extents_before, 3);

    // GC runs every row of the two retired generations, key shredding
    // included.
    rig.bridge.clock.advance_secs(3 * 24 * 60 * 60);
    for _ in 0..4 {
        assert_eq!(
            rig.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
            JobOutcome::Ack
        );
    }
    let extents_after = rig
        .bridge
        .safety
        .keys()
        .iter()
        .filter(|k| k.starts_with("x/"))
        .count();
    assert_eq!(extents_after, 1, "GC deleted the retired extents");
    assert_eq!(records(&rig), kept, "GC deleted no record");

    // Eviction with the pinned copy included.
    let mut evict = Req {
        method: Method::Post,
        target: format!("/_admin/evict/{BUCKET}/k?include_safety=1"),
        headers: Vec::new(),
        body: Vec::new(),
    };
    evict.set_header("host", HOST);
    evict.set_header(
        "authorization",
        &format!("Bearer {}", rig.bridge.cfg.admin_token.expose()),
    );
    rig.send(evict).await.expect(200);
    assert_eq!(records(&rig), kept, "eviction deleted no record");

    // The one function every blob delete goes through refuses a record,
    // whatever asks.
    for key in kept.iter().map(String::as_str).chain(["m/", "m/art/x"]) {
        for store in [&rig.bridge.safety, &rig.bridge.cache] {
            assert!(matches!(
                delete_blob(store, key).await,
                Err(BridgeError::Invalid(_))
            ));
        }
    }
    assert_eq!(records(&rig), kept);
}

// ---------------------------------------------------------------------------
// Export, later writes, loss, restore
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn export_plus_replay_restores_later_writes() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a-old").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "b", b"b").await.expect(200);
    tick(&rig);
    let big = multipart(&rig, &signer, "big", 1).await;
    tick(&rig);

    export(&rig);
    let exported_at = rig.now();
    tick(&rig);

    rig.put(&signer, BUCKET, "a", b"a-new").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "c", b"c").await.expect(200);
    tick(&rig);
    delete(&rig, &signer, "b").await.expect(204);
    tick(&rig);
    let late = multipart(&rig, &signer, "late", 7).await;
    tick(&rig);
    let truth = dump(&rig);

    wipe(&rig);
    import(&rig);
    // The export alone is the old state.
    assert_eq!(get(&rig, &signer, "a").await.expect(200).body, b"a-old");
    get(&rig, &signer, "b").await.expect(200);
    get(&rig, &signer, "c").await.expect(404);

    let (report, _) = replay(&rig, exported_at, ReplayLimits::default()).await;
    assert_eq!(report.published, 3, "a-new, c and late: {report:?}");
    assert_eq!((report.tombstones, report.deleted), (1, 1), "{report:?}");
    assert_eq!(report.damaged_total, 0);
    assert!(report.unpublishable.is_empty() && report.unreadable.is_empty());

    assert_eq!(get(&rig, &signer, "a").await.expect(200).body, b"a-new");
    get(&rig, &signer, "b").await.expect(404);
    assert_eq!(get(&rig, &signer, "c").await.expect(200).body, b"c");
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, big);
    assert_eq!(get(&rig, &signer, "late").await.expect(200).body, late);
    // Every table equals the catalogue before the loss, but for clock
    // columns the replay stamps and the upload that was open.
    for t in ["buckets", "objects", "access_keys", "grants", "articles"] {
        let rows = |d: &str| -> Vec<String> {
            d.lines()
                .filter(|l| l.starts_with(&format!("{t}|")))
                .map(str::to_string)
                .collect()
        };
        assert_eq!(rows(&dump(&rig)), rows(&truth), "{t}");
    }
    for t in ["generations", "extents", "outbox"] {
        let was = truth.lines().filter(|l| l.starts_with(&format!("{t}|")));
        assert_eq!(rig.count(t), was.count() as i64, "{t}");
    }

    // A second replay changes nothing.
    let settled = dump(&rig);
    let (again, _) = replay(&rig, exported_at, ReplayLimits::default()).await;
    assert_eq!((again.published, again.deleted), (0, 0), "{again:?}");
    assert_eq!(again.present, 3);
    assert_eq!(dump(&rig), settled);
}

// ---------------------------------------------------------------------------
// Total loss: the records alone rebuild the catalogue
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn records_alone_rebuild_the_catalogue() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a-old").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "a", b"a-new").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "gone", b"gone").await.expect(200);
    tick(&rig);
    delete(&rig, &signer, "gone").await.expect(204);
    tick(&rig);
    // Deleted and written again: the tombstone is older than the object.
    rig.put(&signer, BUCKET, "back", b"first").await.expect(200);
    tick(&rig);
    delete(&rig, &signer, "back").await.expect(204);
    tick(&rig);
    rig.put(&signer, BUCKET, "back", b"second")
        .await
        .expect(200);
    tick(&rig);
    let big = multipart(&rig, &signer, "dir/big", 3).await;
    let head = rig.head(&signer, BUCKET, "dir/big").await;
    let live_before = rig.live(&bucket, "dir/big").await.unwrap();

    wipe(&rig);
    // One record and one extent per call: every resume point is used.
    let limits = ReplayLimits {
        records: 1,
        extents: 1,
    };
    let (report, calls) = replay(&rig, UnixMs(0), limits).await;
    assert!(calls > 8, "{calls} calls");
    assert_eq!(report.manifests, 6, "{report:?}");
    assert_eq!(report.published, 6, "{report:?}");
    assert_eq!(report.extents, 7);
    assert_eq!((report.tombstones, report.deleted), (2, 1), "{report:?}");
    assert_eq!(report.damaged_total, 0);
    assert!(report.unpublishable.is_empty() && report.unreadable.is_empty());

    let signer = reissue_key(&rig).await;
    assert_eq!(get(&rig, &signer, "a").await.expect(200).body, b"a-new");
    get(&rig, &signer, "gone").await.expect(404);
    assert_eq!(get(&rig, &signer, "back").await.expect(200).body, b"second");
    assert_eq!(get(&rig, &signer, "dir/big").await.expect(200).body, big);
    let head_after = rig.head(&signer, BUCKET, "dir/big").await;
    assert_eq!(head_after.header("etag"), head.header("etag"));
    assert_eq!(
        head_after.header("content-length"),
        head.header("content-length")
    );
    assert_eq!(rig.live(&bucket, "dir/big").await.unwrap(), live_before);
    let listed = rig
        .call(
            &signer,
            Method::Get,
            &format!("/{BUCKET}"),
            &[("list-type", "2")],
            &[],
            b"",
        )
        .await;
    assert_eq!(listed.expect(200).values("Key"), ["a", "back", "dir/big"]);

    // History is back too: the overwritten and the deleted generations
    // are retired, and their extents wait for garbage collection.
    assert_eq!(rig.count("generations"), 6);
    assert_eq!(rig.count("objects"), 3);
    assert!(rig.count("gc") > 0);
    // Every live extent is back in the pipeline, at its first stage.
    let posting: i64 = rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row(
            "SELECT COUNT(*) FROM outbox o JOIN objects l ON l.generation_id = o.generation_id \
             WHERE o.stage = 'post'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    });
    assert_eq!(posting, 4);

    // The same replay again, in one call per phase.
    let settled = dump(&rig);
    let (again, calls) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(calls, 2);
    assert_eq!(
        (again.published, again.present, again.deleted),
        (0, 6, 0),
        "{again:?}"
    );
    assert_eq!(dump(&rig), settled);
}

// ---------------------------------------------------------------------------
// Copies: two generations share extents
// ---------------------------------------------------------------------------

async fn copy(rig: &Rig, signer: &Signer, from: &str, to: &str) -> Resp {
    let source = format!("/{BUCKET}/{from}");
    rig.call(
        signer,
        Method::Put,
        &path(BUCKET, to),
        &[],
        &[("x-amz-copy-source", source.as_str())],
        b"",
    )
    .await
}

fn count(rig: &Rig, query: &str) -> i64 {
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.query_row(query, [], |r| r.get(0)).unwrap())
}

/// Open GC rows for an extent a live object references.
const LIVE_IN_GC: &str = "SELECT COUNT(*) FROM gc WHERE done_at IS NULL AND extent_id IN \
     (SELECT ge.extent_id FROM generation_extents ge \
        JOIN objects o ON o.generation_id = ge.generation_id)";
/// Extents of live objects whose posting obligation is at its first stage.
const LIVE_POSTING: &str = "SELECT COUNT(DISTINCT ge.extent_id) FROM generation_extents ge \
     JOIN objects o ON o.generation_id = ge.generation_id \
     JOIN outbox x ON x.extent_id = ge.extent_id WHERE x.stage = 'post'";

/// A copy is rebuilt with its shared extents, and it stays when the
/// source it was made from is deleted or overwritten.
#[tokio::test(flavor = "current_thread")]
async fn a_copy_outlives_its_source_through_a_replay() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "src", b"payload")
        .await
        .expect(200);
    tick(&rig);
    let big = multipart(&rig, &signer, "big", 5).await;
    tick(&rig);
    copy(&rig, &signer, "src", "dst").await.expect(200);
    tick(&rig);
    copy(&rig, &signer, "big", "big-copy").await.expect(200);
    tick(&rig);
    // A copy of a copy, and a copy that is itself removed again.
    copy(&rig, &signer, "dst", "dst-2").await.expect(200);
    tick(&rig);
    copy(&rig, &signer, "src", "short-lived").await.expect(200);
    tick(&rig);
    delete(&rig, &signer, "short-lived").await.expect(204);
    tick(&rig);
    delete(&rig, &signer, "src").await.expect(204);
    tick(&rig);
    rig.put(&signer, BUCKET, "big", b"replaced")
        .await
        .expect(200);
    tick(&rig);
    let live_before = rig.live(&bucket, "big-copy").await.unwrap();
    let head = rig.head(&signer, BUCKET, "big-copy").await;
    assert_eq!(rig.count("extents"), 4);

    wipe(&rig);
    let limits = ReplayLimits {
        records: 1,
        extents: 1,
    };
    let (report, _) = replay(&rig, UnixMs(0), limits).await;
    assert_eq!(report.manifests, 7, "{report:?}");
    assert_eq!(report.published, 7, "{report:?}");
    assert_eq!((report.tombstones, report.deleted), (2, 2), "{report:?}");
    assert_eq!(report.damaged_total, 0);
    assert!(report.unpublishable.is_empty() && report.unreadable.is_empty());

    let signer = reissue_key(&rig).await;
    get(&rig, &signer, "src").await.expect(404);
    get(&rig, &signer, "short-lived").await.expect(404);
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, b"payload");
    assert_eq!(
        get(&rig, &signer, "dst-2").await.expect(200).body,
        b"payload"
    );
    assert_eq!(
        get(&rig, &signer, "big").await.expect(200).body,
        b"replaced"
    );
    assert_eq!(get(&rig, &signer, "big-copy").await.expect(200).body, big);
    assert_eq!(rig.live(&bucket, "big-copy").await.unwrap(), live_before);
    let head_after = rig.head(&signer, BUCKET, "big-copy").await;
    assert_eq!(head_after.header("etag"), head.header("etag"));

    // No extent was duplicated, every live one is in service and back in
    // the pipeline, and none waits for garbage collection.
    assert_eq!(rig.count("extents"), 4);
    assert_eq!(rig.count("generations"), 7);
    assert_eq!(rig.count("objects"), 4);
    assert_eq!(count(&rig, LIVE_IN_GC), 0);
    assert_eq!(count(&rig, LIVE_POSTING), 4);
    assert_eq!(rig.count("gc"), 0);

    // The same replay again changes nothing.
    let settled = dump(&rig);
    let (again, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(
        (again.published, again.present, again.deleted),
        (0, 7, 0),
        "{again:?}"
    );
    assert_eq!(dump(&rig), settled);

    // The reference count is intact: the extent goes when its last
    // reference does, not before.
    delete(&rig, &signer, "dst").await.expect(204);
    assert_eq!(rig.count("gc"), 0);
    assert_eq!(
        get(&rig, &signer, "dst-2").await.expect(200).body,
        b"payload"
    );
    delete(&rig, &signer, "dst-2").await.expect(204);
    assert_eq!(rig.count("gc"), 3);
}

/// A copy's record describes its extents in full: it rebuilds the copy
/// when the source's record is gone.
#[tokio::test(flavor = "current_thread")]
async fn a_copy_is_rebuilt_without_the_record_of_its_source() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "src", b"payload")
        .await
        .expect(200);
    let (source, _) = rig.live(&bucket, "src").await.unwrap();
    tick(&rig);
    copy(&rig, &signer, "src", "dst").await.expect(200);
    let live_before = rig.live(&bucket, "dst").await.unwrap();
    rig.bridge
        .safety
        .delete(&recovery::generation_key(&source.id))
        .await
        .unwrap();

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!((report.manifests, report.published), (1, 1), "{report:?}");
    assert!(report.unpublishable.is_empty() && report.unreadable.is_empty());

    let signer = reissue_key(&rig).await;
    get(&rig, &signer, "src").await.expect(404);
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, b"payload");
    let (generation, extents) = rig.live(&bucket, "dst").await.unwrap();
    assert_eq!(generation, live_before.0);
    assert_eq!(extents[0].id, live_before.1[0].id);
    assert_eq!(count(&rig, LIVE_POSTING), 1);
}

/// A replay over an export taken before the copy adds the copy to the
/// extents the catalogue already holds.
#[tokio::test(flavor = "current_thread")]
async fn a_copy_made_after_the_export_is_replayed_onto_it() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "src", b"payload")
        .await
        .expect(200);
    tick(&rig);
    export(&rig);
    let since = rig.now();
    tick(&rig);
    copy(&rig, &signer, "src", "dst").await.expect(200);
    tick(&rig);
    delete(&rig, &signer, "src").await.expect(204);

    wipe(&rig);
    import(&rig);
    let (report, _) = replay(&rig, since, ReplayLimits::default()).await;
    assert_eq!((report.manifests, report.published), (1, 1), "{report:?}");
    assert_eq!((report.tombstones, report.deleted), (1, 1), "{report:?}");
    assert!(report.unpublishable.is_empty() && report.unreadable.is_empty());

    get(&rig, &signer, "src").await.expect(404);
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, b"payload");
    assert_eq!(rig.count("extents"), 1);
    assert_eq!(rig.count("gc"), 0);
    assert_eq!(count(&rig, LIVE_POSTING), 1);
}

/// The record that retires the source can sort before the copy's: the
/// writer of the newer source had a clock that was behind. The replay
/// retires the source first and still publishes the copy over its
/// extent, back in service and back in the pipeline.
#[tokio::test(flavor = "current_thread")]
async fn a_copy_is_replayed_after_the_record_that_retired_its_source() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let start = rig.now();
    rig.put(&signer, BUCKET, "src", b"payload")
        .await
        .expect(200);
    rig.bridge.clock.advance_secs(60);
    copy(&rig, &signer, "src", "dst").await.expect(200);
    // Overwritten later, by an isolate whose clock says it is earlier.
    rig.bridge.clock.set(UnixMs(start.0 + 1000));
    rig.put(&signer, BUCKET, "src", b"newer").await.expect(200);
    rig.bridge.clock.advance_secs(120);
    assert_eq!(rig.count("gc"), 0);

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!((report.manifests, report.published), (3, 3), "{report:?}");
    assert!(report.unpublishable.is_empty() && report.unreadable.is_empty());
    assert_eq!(report.damaged_total, 0);

    let signer = reissue_key(&rig).await;
    assert_eq!(get(&rig, &signer, "src").await.expect(200).body, b"newer");
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, b"payload");
    assert_eq!(count(&rig, LIVE_POSTING), 2);

    // The rows queued when the source was retired are still open. The
    // collector refuses each of them while the copy is live.
    assert_eq!(count(&rig, LIVE_IN_GC), 3);
    rig.bridge.clock.advance_secs(8 * 86_400);
    let due = rig
        .bridge
        .catalog
        .gc_due(rig.now(), 100, false)
        .await
        .unwrap();
    assert_eq!(due.len(), 3);
    for row in &due {
        assert_eq!(
            rig.bridge.catalog.gc_begin(row, rig.now()).await.unwrap(),
            GcStep::Skipped
        );
    }
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, b"payload");
}

/// A copy onto an existing key is the newest generation of that key by
/// id, also when the copying isolate's clock is behind the one that wrote
/// the destination. A replay therefore ends with the copy, not with the
/// object it replaced.
#[tokio::test(flavor = "current_thread")]
async fn a_copy_stays_over_the_object_it_replaced() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let start = rig.now();
    rig.put(&signer, BUCKET, "src", b"payload")
        .await
        .expect(200);
    rig.bridge.clock.advance_secs(60);
    rig.put(&signer, BUCKET, "dst", b"replaced")
        .await
        .expect(200);
    let (replaced, _) = rig.live(&bucket, "dst").await.unwrap();
    rig.bridge.clock.set(UnixMs(start.0 + 1000));
    copy(&rig, &signer, "src", "dst").await.expect(200);
    let (copied, _) = rig.live(&bucket, "dst").await.unwrap();
    assert!(copied.id > replaced.id, "{copied:?} {replaced:?}");
    rig.bridge.clock.advance_secs(120);

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!((report.manifests, report.published), (3, 3), "{report:?}");
    assert!(report.unpublishable.is_empty() && report.unreadable.is_empty());
    let signer = reissue_key(&rig).await;
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, b"payload");
    assert_eq!(rig.live(&bucket, "dst").await.unwrap().0, copied);
}

/// A record older than a live generation of its key is not published
/// over it when the older generation is unknown to the catalogue.
#[tokio::test(flavor = "current_thread")]
async fn an_older_record_never_replaces_a_newer_object() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"old").await.expect(200);
    tick(&rig);
    wipe(&rig);
    // The catalogue restarts empty and only the newer write reaches it.
    let (first, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(first.published, 1);
    let signer2 = reissue_key(&rig).await;
    rig.put(&signer2, BUCKET, "k", b"new").await.expect(200);
    sql(
        &rig,
        "DELETE FROM outbox; DELETE FROM gc; DELETE FROM generation_extents WHERE generation_id IN \
               (SELECT id FROM generations WHERE state <> 'live'); \
               DELETE FROM extents WHERE generation_id IN \
               (SELECT id FROM generations WHERE state <> 'live'); \
               DELETE FROM generations WHERE state <> 'live';",
    );
    assert_eq!(rig.count("generations"), 1);

    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(
        (report.published, report.present, report.superseded),
        (0, 1, 1),
        "{report:?}"
    );
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, b"new");
    assert_eq!(rig.count("generations"), 1);
}

// ---------------------------------------------------------------------------
// Damage is reported, never hidden
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_lost_extent_and_a_broken_record_are_reported() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "fine", b"fine").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "lost", b"lost").await.expect(200);
    let (lost_generation, lost_extents) = rig.live(&bucket, "lost").await.unwrap();
    tick(&rig);
    rig.put(&signer, BUCKET, "torn", b"torn").await.expect(200);
    let (torn_generation, _) = rig.live(&bucket, "torn").await.unwrap();

    // The extent of `lost` has no copy anywhere, and the record of
    // `torn` does not open.
    for x in &lost_extents {
        rig.bridge
            .safety
            .inner
            .delete(&x.id.safety_key())
            .await
            .unwrap();
        rig.bridge
            .cache
            .inner
            .delete(&x.id.cache_key())
            .await
            .unwrap();
    }
    let torn_record = format!("m/{}", torn_generation.id.as_str());
    assert!(rig.bridge.safety.corrupt(&torn_record, |b| {
        let last = b.len() - 1;
        b[last] ^= 1;
    }));

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(report.published, 2, "{report:?}");
    assert_eq!(report.unreadable, [torn_record]);
    assert_eq!(report.safety_missing, 1);
    assert_eq!(report.damaged_total, 1);
    assert_eq!(report.damaged, [lost_generation.id.as_str()]);

    let signer = reissue_key(&rig).await;
    assert_eq!(get(&rig, &signer, "fine").await.expect(200).body, b"fine");
    // Known to exist, and unreadable: an error, not "no such key".
    let lost = get(&rig, &signer, "lost").await;
    assert!(
        lost.status >= 500 || lost.stream_error.is_some(),
        "{}",
        lost.status
    );
    rig.head(&signer, BUCKET, "lost").await.expect(200);
    get(&rig, &signer, "torn").await.expect(404);
}

/// An article plan record that does not open is reported and does not
/// stop the replay: the extent comes back without a plan, from its
/// pinned copy.
#[tokio::test(flavor = "current_thread")]
async fn an_unreadable_article_plan_does_not_stop_the_replay() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "one", b"one").await.expect(200);
    let (_, extents) = rig.live(&bucket, "one").await.unwrap();
    tick(&rig);
    rig.put(&signer, BUCKET, "two", b"two").await.expect(200);

    let torn = format!("m/art/{}", extents[0].id.as_str());
    let garbage = b"not a sealed record".to_vec();
    let digest = sha256(&garbage);
    let meta = BlobMeta {
        bucket: &bucket.id,
        extent: &extents[0].id,
        cipher_sha256: &digest,
    };
    rig.bridge
        .safety
        .inner
        .put(&torn, garbage, &meta)
        .await
        .unwrap();

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(report.published, 2, "{report:?}");
    assert_eq!(report.unreadable, [torn]);
    assert_eq!(report.article_plans, 0);
    assert_eq!(report.damaged_total, 0);

    let signer = reissue_key(&rig).await;
    assert_eq!(get(&rig, &signer, "one").await.expect(200).body, b"one");
    assert_eq!(get(&rig, &signer, "two").await.expect(200).body, b"two");
}

/// A record sealed under another key or stored under another name does
/// not open.
#[tokio::test(flavor = "current_thread")]
async fn a_record_is_bound_to_its_name() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "one", b"one").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "two", b"two").await.expect(200);
    let (one, _) = rig.live(&bucket, "one").await.unwrap();
    let (two, _) = rig.live(&bucket, "two").await.unwrap();
    let (name_one, name_two) = (
        format!("m/{}", one.id.as_str()),
        format!("m/{}", two.id.as_str()),
    );
    // Swap the two records.
    let a = rig.bridge.safety.stored(&name_one).unwrap().bytes;
    let b = rig.bridge.safety.stored(&name_two).unwrap().bytes;
    assert!(rig.bridge.safety.corrupt(&name_one, |x| *x = b));
    assert!(rig.bridge.safety.corrupt(&name_two, |x| *x = a));
    // No plaintext of the object's name or bucket in a record.
    let sealed = rig.bridge.safety.stored(&name_one).unwrap().bytes;
    for word in [&b"vault"[..], b"one", b"two", b"bdk_wrapped"] {
        assert!(!sealed.windows(word.len()).any(|w| w == word));
    }

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(report.published, 0);
    assert_eq!(report.unreadable, [name_one, name_two]);
    assert_eq!(rig.count("generations"), 0);
}

// ---------------------------------------------------------------------------
// The admin route
// ---------------------------------------------------------------------------

async fn admin(rig: &Rig, path: &str, body: Value) -> Resp {
    let mut req = Req {
        method: Method::Post,
        target: format!("/_admin{path}"),
        headers: Vec::new(),
        body: body.to_string().into_bytes(),
    };
    req.set_header("host", HOST);
    req.set_header("content-length", &req.body.len().to_string());
    req.set_header(
        "authorization",
        &format!("Bearer {}", rig.bridge.cfg.admin_token.expose()),
    );
    rig.send(req).await
}

#[tokio::test(flavor = "current_thread")]
async fn restore_route_runs_only_in_maintenance() {
    // A serving bridge writes two objects and deletes one.
    let serving = rig();
    let (_, signer) = serving.standard(BUCKET).await;
    serving.put(&signer, BUCKET, "a", b"a").await.expect(200);
    tick(&serving);
    serving.put(&signer, BUCKET, "b", b"b").await.expect(200);
    tick(&serving);
    delete(&serving, &signer, "b").await.expect(204);

    let refused = admin(&serving, "/restore", json!({ "since_ms": 0 })).await;
    refused.expect(409);
    assert!(refused.text().contains("NotInMaintenance"));

    // A bridge in maintenance over the same blobs and an empty catalogue.
    let mut cfg = config(Vec::new());
    cfg.maintenance = Maintenance::Restore;
    let restoring = rig_with(NoNntp, cfg);
    for key in serving.bridge.safety.keys() {
        let blob = serving.bridge.safety.stored(&key).unwrap();
        let meta = BlobMeta {
            bucket: &blob.bucket,
            extent: &blob.extent,
            cipher_sha256: &blob.cipher_sha256,
        };
        restoring
            .bridge
            .safety
            .put(&key, blob.bytes.clone(), &meta)
            .await
            .unwrap();
    }

    let mut req = Req {
        method: Method::Post,
        target: "/_admin/restore".to_string(),
        headers: Vec::new(),
        body: b"{\"since_ms\":0}".to_vec(),
    };
    req.set_header("host", HOST);
    req.set_header("content-length", "14");
    restoring.send(req).await.expect(401);
    for bad in [
        json!({}),
        json!({ "since_ms": -1 }),
        json!({ "since_ms": 0, "margin_ms": -1 }),
        json!({ "since_ms": 0, "cursor": { "since_ms": 0, "phase": "manifests", "after": "", "extent": 0 } }),
        json!({ "since_ms": 0, "other": 1 }),
    ] {
        let r = admin(&restoring, "/restore", bad.clone()).await;
        assert_eq!(r.status, 400, "{bad}: {}", r.text());
    }

    let mut body = json!({ "since_ms": 0 });
    let (mut published, mut deleted, mut calls) = (0, 0, 0);
    loop {
        calls += 1;
        let r = admin(&restoring, "/restore", body).await;
        r.expect(200);
        let report: Value = serde_json::from_slice(&r.body).unwrap();
        published += report["published"].as_u64().unwrap();
        deleted += report["deleted"].as_u64().unwrap();
        // Counts and ids only: never an object key.
        assert!(!r.text().contains("\"key\""));
        if report["next"].is_null() {
            assert_eq!(report["damaged_total"], 0);
            break;
        }
        body = json!({ "cursor": report["next"] });
    }
    assert_eq!((published, deleted, calls), (2, 1, 2));
    assert_eq!(restoring.count("objects"), 1);
    assert_eq!(restoring.count("generations"), 2);

    // Maintenance still refuses everything else.
    let signer = reissue_key(&restoring).await;
    let put = restoring.put(&signer, BUCKET, "c", b"c").await;
    assert_eq!(put.status, 503, "{}", put.text());
}
