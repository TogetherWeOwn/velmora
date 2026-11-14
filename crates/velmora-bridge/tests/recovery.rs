//! Catalogue recovery (DESIGN §A.8): the recovery records are written
//! before a commit, are never deleted, and rebuild the catalogue.
//!
//! "Export" here is a copy of every catalogue table inside the same
//! SQLite database; "loss" deletes every row.

mod service_support;

use serde_json::{json, Value};
use service_support::*;
use velmora_bridge::config::Maintenance;
use velmora_bridge::recovery::{
    delete_blob, tombstone_id, write_tombstone, GENERATION_PREFIX, TOMBSTONE_PREFIX,
};
use velmora_bridge::replay::{ReplayCursor, ReplayLimits, ReplayReport};
use velmora_bridge::*;

const BUCKET: &str = "vault";
const TABLES: [&str; 14] = [
    "generation_extents",
    "outbox",
    "key_floors",
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
    total.duplicate += step.duplicate;
    total.other_bucket_total += step.other_bucket_total;
    total.other_bucket.extend(step.other_bucket);
    total.held_checked += step.held_checked;
    total.held_missing_total += step.held_missing_total;
    total.held_missing.extend(step.held_missing);
    total.unpublishable.extend(step.unpublishable);
    total.damaged_unpublished.extend(step.damaged_unpublished);
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
    // A first read stamps the extent's last read time; the reads below
    // fall within the same hour and write nothing.
    assert_eq!(get(&rig, &signer, "kept").await.expect(200).body, b"kept");
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

    // Each of them raised the floor of its key before the store refused
    // the record, and that is all: the next id on the key sorts after
    // the one that failed.
    let rows = |dump: String| -> Vec<String> {
        let rows = dump.lines().filter(|l| !l.starts_with("key_floors|"));
        rows.map(str::to_owned).collect()
    };
    assert_eq!(rows(dump(&rig)), rows(before), "no catalogue row changed");
    assert_eq!(rig.count("key_floors"), 3, "k, kept and mp");
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

    // A delete of a record is refused whatever asks: by the function
    // that release, collection and evict delete through, and by the
    // store itself for a caller that goes around it.
    for key in kept.iter().map(String::as_str).chain(["m/", "m/art/x"]) {
        for store in [&rig.bridge.safety, &rig.bridge.cache] {
            assert!(matches!(
                delete_blob(store, key).await,
                Err(BridgeError::Invalid(_))
            ));
            assert!(matches!(
                store.delete(key).await,
                Err(BridgeError::Invalid(_))
            ));
        }
    }
    assert_eq!(records(&rig), kept);
}

#[tokio::test(flavor = "current_thread")]
async fn only_a_refused_publication_gives_its_record_up() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"v1").await.expect(200);
    let (live, extents) = rig
        .bridge
        .catalog
        .live_object(&bucket.id, "k")
        .await
        .unwrap()
        .unwrap();
    let kept = records(&rig);

    // A generation that sorts before the live one, recorded and offered.
    let mut older = live.clone();
    older.id = GenerationId::mint(UnixMs(rig.now().0 - 1000), [1; 8]);
    let mut rows = extents.clone();
    for (i, row) in rows.iter_mut().enumerate() {
        row.id = ExtentId::mint([i as u8; 13]);
        row.generation_id = Some(older.id.clone());
    }
    let commit = CommitGeneration {
        generation: older,
        extents: rows,
        now: rig.now(),
    };
    let write = || {
        velmora_bridge::recovery::write_generation(
            &rig.bridge.catalog,
            &rig.bridge.safety,
            &rig.bridge.kek,
            &bucket,
            &commit.generation,
            &commit.extents,
        )
    };

    // The proof of one generation publishes no other.
    let mut other = commit.clone();
    other.generation.id = GenerationId::mint(UnixMs(rig.now().0 + 1000), [2; 8]);
    for row in &mut other.extents {
        row.generation_id = Some(other.generation.id.clone());
    }
    let proof = write().await.unwrap();
    assert!(matches!(
        rig.bridge.catalog.commit_generation(&other, proof).await,
        Err(BridgeError::Invalid(_))
    ));
    assert_eq!(rig.count("generations"), 1);

    // Refused: the proof comes back, and it is what removes the record.
    let proof = write().await.unwrap();
    assert_eq!(records(&rig).len(), kept.len() + 1);
    let PublishOutcome::Refused(refused) = rig
        .bridge
        .catalog
        .commit_generation(&commit, proof)
        .await
        .unwrap()
    else {
        panic!("an id older than the live one was published");
    };
    assert_eq!(refused.generation(), &commit.generation.id);
    velmora_bridge::recovery::discard_generation(&rig.bridge.safety, &refused)
        .await
        .unwrap();
    assert_eq!(records(&rig), kept);
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, b"v1");
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
    assert_eq!(calls, 3);
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
    assert!(rig
        .bridge
        .safety
        .lose(&recovery::generation_key(&source.id)));

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

    // The collection queued when the source was retired is called off:
    // the copy brought the extent back into service.
    assert_eq!(count(&rig, LIVE_IN_GC), 0);
    assert_eq!(rig.count("gc WHERE done_at IS NULL"), 0);
    assert_eq!(rig.count("gc"), 3);
    rig.bridge.clock.advance_secs(8 * 86_400);
    let due = rig.bridge.catalog.gc_due(rig.now(), 100, false);
    assert!(due.await.unwrap().is_empty());
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, b"payload");

    // With its last reference the extent leaves service again, and that
    // retirement queues its own rows.
    delete(&rig, &signer, "dst").await.expect(204);
    assert_eq!(rig.count("gc WHERE done_at IS NULL"), 3);
    assert_eq!(rig.count("gc"), 6);
}

/// The extent a copy brings back into service can be one whose release
/// was begun and not finished. Its obligation restarts at the release
/// stage, the only one that finishes it, with a fresh lease token.
#[tokio::test(flavor = "current_thread")]
async fn a_copy_takes_up_the_unfinished_release_of_its_extent() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let start = rig.now();
    rig.put(&signer, BUCKET, "src", b"payload")
        .await
        .expect(200);
    sql(
        &rig,
        "UPDATE extents SET safety_state = 'releasing', evict_seq = evict_seq + 1; \
         UPDATE outbox SET stage = 'release', cursor = 2, attempts = 3, last_error = 'x', \
           lease_owner = 'gone', lease_until = 1;",
    );
    export(&rig);
    rig.bridge.clock.advance_secs(60);
    copy(&rig, &signer, "src", "dst").await.expect(200);
    // Overwritten later, by an isolate whose clock says it is earlier.
    rig.bridge.clock.set(UnixMs(start.0 + 1000));
    rig.put(&signer, BUCKET, "src", b"newer").await.expect(200);
    rig.bridge.clock.advance_secs(120);

    wipe(&rig);
    import(&rig);
    let token = count(&rig, "SELECT lease_token FROM outbox");
    let (report, _) = replay(&rig, start, ReplayLimits::default()).await;
    assert!(report.unpublishable.is_empty() && report.unreadable.is_empty());
    assert_eq!(get(&rig, &signer, "src").await.expect(200).body, b"newer");
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, b"payload");

    const SHARED: &str = "FROM outbox o JOIN extents e ON e.id = o.extent_id \
         WHERE e.safety_state = 'releasing'";
    assert_eq!(
        count(
            &rig,
            &format!(
                "SELECT COUNT(*) {SHARED} AND o.stage = 'release' AND o.cursor = 0 \
                   AND o.attempts = 0 AND o.last_error IS NULL AND o.lease_owner IS NULL \
                   AND o.lease_until IS NULL"
            )
        ),
        1
    );
    assert!(count(&rig, &format!("SELECT o.lease_token {SHARED}")) > token);
    assert_eq!(count(&rig, LIVE_IN_GC), 0);
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

/// The record of a Complete that failed can linger after its parts are
/// gone. A replay does not put it over the object the key holds: a
/// generation that cannot be read replaces nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_record_without_its_extents_does_not_replace_a_good_object() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "big", b"good").await.expect(200);
    let (good, _) = rig.live(&bucket, "big").await.unwrap();
    tick(&rig);
    let (id, etags, _) = two_parts(&rig, &signer, "big").await;
    tick(&rig);

    // The Complete is refused and the store keeps its record.
    rig.bridge.safety.fail_record_deletes.set(3);
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::NotApplied));
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(500);
    let lingering = records(&rig).into_iter().max().unwrap()["m/".len()..].to_owned();
    assert!(lingering.as_str() > good.id.as_str());

    // The parts are collected before they were posted: no pinned copy,
    // no article plan.
    let parts: Vec<String> = rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c
            .prepare("SELECT id FROM extents WHERE generation_id IS NULL")
            .unwrap();
        let ids = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        ids.map(|id| id.unwrap()).collect()
    });
    assert_eq!(parts.len(), 2);
    for part in &parts {
        let id = velmora_bridge::ExtentId::new(part.clone());
        assert!(rig.bridge.safety.lose(&id.safety_key()));
        // Not posted yet, so no article plan record was written.
        assert!(!rig
            .bridge
            .safety
            .contains(&velmora_bridge::recovery::article_key(&id)));
    }

    // The second replay runs over what the first one left.
    wipe(&rig);
    for _ in 0..2 {
        let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
        assert_eq!(
            report.damaged_unpublished,
            [lingering.as_str()],
            "{report:?}"
        );
        assert!(report.unpublishable.is_empty(), "{report:?}");
        assert_eq!(report.damaged_total, 0, "{report:?}");
        assert_eq!(live_ids(&rig), [good.id.as_str()]);
    }
    let signer = reissue_key(&rig).await;
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, b"good");

    // With nothing older live it is published, and reads fail loudly.
    wipe(&rig);
    assert!(rig.bridge.safety.lose(&format!("m/{}", good.id.as_str())));
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert!(report.damaged_unpublished.is_empty(), "{report:?}");
    assert_eq!(report.damaged, [lingering.as_str()], "{report:?}");
}

/// A good object, a delete, then a record whose extents are gone. The
/// tombstone removes the object after the record was refused; a second
/// replay must not take the empty key for one without a history and
/// publish the record. And what is acknowledged after the replay sorts
/// after the refused record, also from a clock that runs behind.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_record_stays_refused_after_the_tombstone_before_it() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"good").await.expect(200);
    rig.put(&signer, BUCKET, "j", b"good").await.expect(200);
    tick(&rig);
    delete(&rig, &signer, "k").await.expect(204);
    tick(&rig);
    let mut lost = Vec::new();
    for key in ["j", "k"] {
        rig.put(&signer, BUCKET, key, b"lost").await.expect(200);
        let (generation, extents) = rig.live(&bucket, key).await.unwrap();
        for x in &extents {
            assert!(rig.bridge.safety.lose(&x.id.safety_key()));
            let plan = velmora_bridge::recovery::article_key(&x.id);
            rig.bridge.safety.lose(&plan);
        }
        lost.push(generation.id.as_str().to_owned());
    }
    lost.sort();

    wipe(&rig);
    for _ in 0..3 {
        let (mut report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
        report.damaged_unpublished.sort();
        assert_eq!(report.damaged_unpublished, lost, "{report:?}");
        assert_eq!(report.damaged_total, 0, "{report:?}");
        assert_eq!(live_ids(&rig).len(), 1, "only `j` is live");
    }
    let signer = reissue_key(&rig).await;
    get(&rig, &signer, "k").await.expect(404);
    assert_eq!(get(&rig, &signer, "j").await.expect(200).body, b"good");

    // The floor of a key is its refused record: a write and a delete
    // from a clock that runs behind sort after it.
    rig.bridge.clock.advance_ms(-1500);
    for key in ["j", "k"] {
        rig.put(&signer, BUCKET, key, b"new").await.expect(200);
        let (new, _) = rig.live(&bucket, key).await.unwrap();
        assert!(new.id.as_str() > lost[1].as_str(), "{new:?} after {lost:?}");
        delete(&rig, &signer, key).await.expect(204);
        let newest = tombstones(&rig).into_iter().max().unwrap();
        assert!(&newest["m/del/".len()..] > new.id.as_str(), "{newest}");
    }
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
        // Started and not ended: the catalogue says so.
        assert_eq!(restore_state(&restoring), ["replaying"]);
        body = json!({ "cursor": report["next"] });
    }
    assert_eq!(restore_state(&restoring), ["complete"]);
    assert_eq!((published, deleted, calls), (2, 1, 3));

    // A cursor of this replay that arrives after another replay was
    // started does not end the other one.
    let first = admin(&restoring, "/restore", json!({ "since_ms": 0 })).await;
    first.expect(200);
    let first: Value = serde_json::from_slice(&first.body).unwrap();
    let second = admin(&restoring, "/restore", json!({ "since_ms": 0 })).await;
    second.expect(200);
    let second: Value = serde_json::from_slice(&second.body).unwrap();
    assert_ne!(first["next"]["run_ms"], second["next"]["run_ms"]);
    let finish = |mut body: Value| {
        let restoring = &restoring;
        async move {
            loop {
                let r = admin(restoring, "/restore", body).await;
                if r.status != 200 {
                    return r.status;
                }
                let report: Value = serde_json::from_slice(&r.body).unwrap();
                if report["next"].is_null() {
                    return 200;
                }
                body = json!({ "cursor": report["next"] });
            }
        }
    };
    assert_eq!(finish(json!({ "cursor": first["next"] })).await, 409);
    assert_eq!(restore_state(&restoring), ["replaying"]);
    assert_eq!(finish(json!({ "cursor": second["next"] })).await, 200);
    assert_eq!(restore_state(&restoring), ["complete"]);
    assert_eq!(restoring.count("objects"), 1);
    assert_eq!(restoring.count("generations"), 2);

    // Maintenance still refuses everything else.
    let signer = reissue_key(&restoring).await;
    let put = restoring.put(&signer, BUCKET, "c", b"c").await;
    assert_eq!(put.status, 503, "{}", put.text());
}

// ---------------------------------------------------------------------------
// The order of ids on a key is the order of its commits
// ---------------------------------------------------------------------------

/// What every key answers now; then the catalogue is lost and rebuilt
/// from the records alone, and every key must answer the same.
async fn replay_answers_the_same(rig: &Rig, signer: &Signer, keys: &[&str]) {
    let mut before = Vec::new();
    for key in keys {
        let got = get(rig, signer, key).await;
        before.push((got.status, got.body.clone()));
    }
    wipe(rig);
    let (report, _) = replay(rig, UnixMs(0), ReplayLimits::default()).await;
    assert!(
        report.unpublishable.is_empty() && report.unreadable.is_empty(),
        "{report:?}"
    );
    let signer = reissue_key(rig).await;
    for (key, (status, body)) in keys.iter().zip(before) {
        let got = get(rig, &signer, key).await;
        assert_eq!(got.status, status, "{key} after the replay");
        if status == 200 {
            assert_eq!(got.body, body, "{key} after the replay");
        }
    }
}

fn live_ids(rig: &Rig) -> Vec<String> {
    rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c
            .prepare("SELECT generation_id FROM objects ORDER BY key")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    })
}

#[tokio::test(flavor = "current_thread")]
async fn an_overwrite_from_a_slow_clock_stays_on_top_in_a_replay() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"v1").await.expect(200);
    let v1 = live_ids(&rig).remove(0);
    // The isolate that takes the overwrite runs half a second behind.
    rig.bridge.clock.advance_ms(-500);
    rig.put(&signer, BUCKET, "k", b"v2").await.expect(200);
    let v2 = live_ids(&rig).remove(0);
    assert!(v2 > v1, "{v2} sorts after {v1}");
    // The record of the first try is gone: one record per generation.
    assert_eq!(
        records(&rig)
            .iter()
            .filter(|r| r.starts_with(GENERATION_PREFIX))
            .count(),
        2
    );
    rig.bridge.clock.advance_ms(2000);
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, b"v2");
    replay_answers_the_same(&rig, &signer, &["k"]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_put_after_a_delete_sorts_after_the_tombstone() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"v1").await.expect(200);
    rig.bridge.clock.advance_ms(-500);
    delete(&rig, &signer, "k").await.expect(204);
    let tombstone = records(&rig)
        .into_iter()
        .find_map(|r| r.strip_prefix(TOMBSTONE_PREFIX).map(str::to_owned))
        .unwrap();
    rig.bridge.clock.advance_ms(100);
    rig.put(&signer, BUCKET, "k", b"v2").await.expect(200);
    let v2 = live_ids(&rig).remove(0);
    assert!(v2 > tombstone, "{v2} sorts after {tombstone}");
    // The key lives again: the catalogue keeps no tombstone for it.
    assert_eq!(rig.count("key_floors"), 0);
    rig.bridge.clock.advance_ms(2000);
    replay_answers_the_same(&rig, &signer, &["k"]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn writes_in_one_millisecond_replay_in_commit_order() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    // The clock does not move: every id below is minted in the same
    // millisecond, where only random bytes would order them.
    let keys: Vec<String> = (0..12).map(|i| format!("k{i}")).collect();
    for key in &keys {
        rig.put(&signer, BUCKET, key, b"v1").await.expect(200);
        rig.put(&signer, BUCKET, key, b"v2").await.expect(200);
        rig.put(&signer, BUCKET, key, b"v3").await.expect(200);
    }
    rig.put(&signer, BUCKET, "gone", b"v1").await.expect(200);
    delete(&rig, &signer, "gone").await.expect(204);
    rig.put(&signer, BUCKET, "back", b"v1").await.expect(200);
    delete(&rig, &signer, "back").await.expect(204);
    rig.put(&signer, BUCKET, "back", b"v2").await.expect(200);
    delete(&rig, &signer, "back").await.expect(204);
    rig.put(&signer, BUCKET, "back", b"v3").await.expect(200);
    assert_eq!(get(&rig, &signer, "gone").await.status, 404);
    assert_eq!(get(&rig, &signer, "back").await.expect(200).body, b"v3");
    assert_eq!(rig.count("key_floors"), 1, "only the deleted key has one");

    let mut all: Vec<&str> = keys.iter().map(String::as_str).collect();
    all.extend(["gone", "back"]);
    for key in &keys {
        assert_eq!(get(&rig, &signer, key).await.expect(200).body, b"v3");
    }
    tick(&rig);
    replay_answers_the_same(&rig, &signer, &all).await;
    // The replay raises a floor for every tombstone it reads: "gone", and
    // "back", whose floor sits under its live generation and holds
    // nothing back.
    assert_eq!(rig.count("key_floors"), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn a_complete_from_a_slow_clock_stays_on_top_in_a_replay() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create_upload(&rig, &signer, "big").await;
    let first = pattern(3, 5 * MIB);
    let last = pattern(4, 1024);
    let etags = vec![
        upload_part(&rig, &signer, "big", &id, 1, &first).await,
        upload_part(&rig, &signer, "big", &id, 2, &last).await,
    ];
    tick(&rig);
    rig.put(&signer, BUCKET, "big", b"small").await.expect(200);
    let put = live_ids(&rig).remove(0);
    rig.bridge.clock.advance_ms(-500);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(200);
    let completed = live_ids(&rig).remove(0);
    assert!(completed > put, "{completed} sorts after {put}");
    rig.bridge.clock.advance_ms(2000);
    assert_eq!(
        get(&rig, &signer, "big").await.expect(200).body,
        [first, last].concat()
    );
    replay_answers_the_same(&rig, &signer, &["big"]).await;
}

// ---------------------------------------------------------------------------
// An upload that the export saw open, completed after it
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn an_abort_after_the_replay_of_its_complete_harms_nothing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create_upload(&rig, &signer, "big").await;
    let first = pattern(3, 5 * MIB);
    let last = pattern(4, 1024);
    let etags = vec![
        upload_part(&rig, &signer, "big", &id, 1, &first).await,
        upload_part(&rig, &signer, "big", &id, 2, &last).await,
    ];
    tick(&rig);
    export(&rig);
    let exported_at = rig.now();
    tick(&rig);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(200);
    tick(&rig);
    wipe(&rig);
    import(&rig);
    let (report, _) = replay(&rig, exported_at, ReplayLimits::default()).await;
    assert_eq!(report.published, 1, "{report:?}");
    assert!(report.unpublishable.is_empty(), "{report:?}");
    let whole = [first, last].concat();
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, whole);

    // The export still says the upload is open. The client's Abort of
    // it must not queue the published extents for collection.
    rig.call(
        &signer,
        Method::Delete,
        &path(BUCKET, "big"),
        &[("uploadId", id.as_str())],
        &[],
        b"",
    )
    .await;
    let collected: i64 = rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row(
            "SELECT COUNT(*) FROM gc WHERE extent_id IN (SELECT e.id FROM extents e \
               JOIN objects o ON o.generation_id = e.generation_id)",
            [],
            |r| r.get(0),
        )
        .unwrap()
    });
    assert_eq!(collected, 0);
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, whole);
}

// ---------------------------------------------------------------------------
// A Complete whose publication the catalogue did not answer
// ---------------------------------------------------------------------------

async fn abort(rig: &Rig, signer: &Signer, key: &str, id: &str) -> Resp {
    rig.call(
        signer,
        Method::Delete,
        &path(BUCKET, key),
        &[("uploadId", id)],
        &[],
        b"",
    )
    .await
}

async fn two_parts(rig: &Rig, signer: &Signer, key: &str) -> (String, Vec<String>, Vec<u8>) {
    let id = create_upload(rig, signer, key).await;
    let first = pattern(5, 5 * MIB);
    let last = pattern(6, 1024);
    let etags = vec![
        upload_part(rig, signer, key, &id, 1, &first).await,
        upload_part(rig, signer, key, &id, 2, &last).await,
    ];
    (id, etags, [first, last].concat())
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_complete_that_is_then_aborted_does_not_come_back() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let (id, etags, _) = two_parts(&rig, &signer, "big").await;
    let before = records(&rig);
    tick(&rig);

    // The catalogue fails before it wrote anything. Complete shows that
    // nothing was published, and takes its record back.
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::NotApplied));
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(500);
    assert_eq!(records(&rig), before);
    get(&rig, &signer, "big").await.expect(404);

    tick(&rig);
    abort(&rig, &signer, "big", &id).await.expect(204);
    tick(&rig);
    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(report.published, 0, "{report:?}");
    let generations: i64 = rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row("SELECT COUNT(*) FROM generations", [], |r| r.get(0))
            .unwrap()
    });
    assert_eq!(generations, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn the_record_of_a_failed_complete_is_deleted_again_when_the_store_fails() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let (id, etags, _) = two_parts(&rig, &signer, "big").await;
    let before = records(&rig);
    tick(&rig);

    let fail = |deletes: u32| {
        rig.bridge.safety.fail_record_deletes.set(deletes);
        rig.bridge
            .catalog
            .sql
            .fail_publish
            .set(Some(PublishFault::NotApplied));
    };
    // Two failures of the store: the third delete removes the record.
    fail(2);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(500);
    assert_eq!(records(&rig), before);
    assert_eq!(rig.bridge.safety.fail_record_deletes.get(), 0);

    // A store that stays down leaves the record: the known remainder.
    tick(&rig);
    fail(3);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(500);
    assert_eq!(records(&rig).len(), before.len() + 1);
    assert_eq!(rig.bridge.safety.fail_record_deletes.get(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_complete_can_be_sent_again() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let (id, etags, whole) = two_parts(&rig, &signer, "big").await;
    tick(&rig);
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::NotApplied));
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(500);
    tick(&rig);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(200);
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, whole);
    tick(&rig);
    replay_answers_the_same(&rig, &signer, &["big"]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_complete_that_applied_without_an_answer_keeps_its_record() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let (id, etags, whole) = two_parts(&rig, &signer, "big").await;
    let before = records(&rig).len();
    tick(&rig);

    // The catalogue committed, and the answer was lost. The upload is
    // no longer open, so nothing shows that the batch did not apply.
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::Applied));
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(500);
    assert_eq!(records(&rig).len(), before + 1);
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, whole);
    tick(&rig);
    replay_answers_the_same(&rig, &signer, &["big"]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn two_records_of_one_object_are_not_reported_as_a_loss() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let (id, etags, whole) = two_parts(&rig, &signer, "big").await;
    let before = records(&rig).len();
    tick(&rig);

    // The catalogue answers neither the publication nor the question
    // whether it applied, so the record of this attempt stays.
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::Down));
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(500);
    tick(&rig);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(200);
    assert_eq!(records(&rig).len(), before + 2);
    tick(&rig);

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    // Both records are published, the later over the earlier: they
    // share the extents.
    assert_eq!((report.published, report.duplicate), (2, 0), "{report:?}");
    assert!(report.unpublishable.is_empty(), "{report:?}");
    let signer = reissue_key(&rig).await;
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, whole);
}

/// A Complete that got no answer leaves its record; a delete of the key
/// lands; the Complete is sent again and succeeds. The object must
/// stand under the id of the second record, or the tombstone, which
/// sorts between the two, removes it in a replay.
#[tokio::test(flavor = "current_thread")]
async fn a_delete_between_two_records_of_one_object_does_not_remove_it() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "big", b"first").await.expect(200);
    tick(&rig);
    let (id, etags, whole) = two_parts(&rig, &signer, "big").await;
    tick(&rig);
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::Down));
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(500);
    tick(&rig);
    delete(&rig, &signer, "big").await.expect(204);
    tick(&rig);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(200);
    tick(&rig);
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, whole);
    let live: String = rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row("SELECT generation_id FROM objects", [], |r| r.get(0))
            .unwrap()
    });

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!((report.published, report.duplicate), (3, 0), "{report:?}");
    assert_eq!((report.tombstones, report.deleted), (1, 0), "{report:?}");
    assert!(report.unpublishable.is_empty(), "{report:?}");
    let signer = reissue_key(&rig).await;
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, whole);
    let (restored, generations): (String, i64) = rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row(
            "SELECT (SELECT generation_id FROM objects), \
                    (SELECT COUNT(*) FROM generations WHERE state = 'live')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    });
    assert_eq!((restored, generations), (live, 1));

    // A second replay over the result changes nothing.
    let (again, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!((again.published, again.deleted), (0, 0), "{again:?}");
    assert_eq!(get(&rig, &signer, "big").await.expect(200).body, whole);
}

// ---------------------------------------------------------------------------
// A bucket that was made again under the same name
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn records_of_a_bucket_whose_name_is_taken_are_reported_and_skipped() {
    let rig = rig();
    let (old, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"one").await.expect(200);
    tick(&rig);
    rig.put(&signer, BUCKET, "b", b"two").await.expect(200);
    tick(&rig);
    delete(&rig, &signer, "b").await.expect(204);
    tick(&rig);
    wipe(&rig);

    // Before the replay, somebody makes the bucket again.
    let mut new = rig.bucket("vault-again", true).await;
    assert_ne!(new.id, old.id);
    sql(
        &rig,
        "UPDATE buckets SET name = 'vault' WHERE name = 'vault-again'",
    );
    new.name = BUCKET.to_string();
    let signer = rig.key(AKID, secret(), KeyStatus::Active).await;
    rig.grant(AKID, &new, Perm::Rw).await;
    rig.put(&signer, BUCKET, "c", b"three").await.expect(200);
    tick(&rig);

    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(report.other_bucket_total, 2, "{report:?}");
    assert_eq!(report.other_bucket.len(), 2, "{report:?}");
    assert_eq!((report.published, report.present), (0, 1), "{report:?}");
    assert!(report.unpublishable.is_empty(), "{report:?}");
    get(&rig, &signer, "a").await.expect(404);
    assert_eq!(get(&rig, &signer, "c").await.expect(200).body, b"three");
}

// ---------------------------------------------------------------------------
// A replay that was started and did not end
// ---------------------------------------------------------------------------

fn restore_state(rig: &Rig) -> Vec<String> {
    rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c.prepare("SELECT state FROM restore_state").unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    })
}

#[tokio::test(flavor = "current_thread")]
async fn an_unfinished_replay_refuses_writes_without_maintenance() {
    // Maintenance is off in this rig, as after a deploy that came too
    // early.
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"one").await.expect(200);
    let (id, etags, _) = two_parts(&rig, &signer, "big").await;
    let before = records(&rig);

    let run = rig
        .bridge
        .catalog
        .restore_begin(UnixMs(0), rig.now())
        .await
        .unwrap()
        .unwrap();
    rig.put(&signer, BUCKET, "a", b"two").await.expect(503);
    rig.put(&signer, BUCKET, "new", b"new").await.expect(503);
    delete(&rig, &signer, "a").await.expect(503);
    copy(&rig, &signer, "a", "copy").await.expect(503);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(503);
    let r = rig
        .call(
            &signer,
            Method::Post,
            &path(BUCKET, "other"),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    assert_eq!(r.status, 503, "{}", r.text());
    // Nothing was recorded, and reads go on.
    assert_eq!(records(&rig), before);
    assert_eq!(get(&rig, &signer, "a").await.expect(200).body, b"one");

    // Neither do the admin routes that change something, the queue
    // jobs, or the dispatcher.
    admin(&rig, "/buckets", json!({ "name": "second" }))
        .await
        .expect(503);
    admin(&rig, "/evict/vault/a?include_safety=1", json!({}))
        .await
        .expect(503);
    let outbox = || -> (String, String, String, i64) {
        rig.bridge.catalog.sql.with_conn(|c| {
            c.query_row(
                "SELECT extent_id, generation_id, stage, attempts FROM outbox \
                 ORDER BY extent_id LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
        })
    };
    let row = outbox();
    assert_eq!(row.2, "post");
    let job = Job::Extent {
        v: JOB_VERSION,
        extent: ExtentId::new(row.0.clone()),
        generation: GenerationId::new(row.1.clone()),
        stage: OutboxStage::Post,
    };
    assert_eq!(rig.bridge.run_job(&job).await, JobOutcome::Ack);
    assert_eq!(outbox(), row);
    assert_eq!(
        rig.bridge.dispatch().await.unwrap(),
        DispatchReport::default()
    );
    assert_eq!(rig.count("buckets"), 1);

    // The end of another replay does not end this one.
    assert!(!rig
        .bridge
        .catalog
        .restore_finish(UnixMs(run.0 - 1), rig.now(), 0, "main")
        .await
        .unwrap());
    assert_eq!(restore_state(&rig), ["replaying"]);
    assert!(rig
        .bridge
        .catalog
        .restore_finish(run, rig.now(), 0, "main")
        .await
        .unwrap());
    assert_eq!(restore_state(&rig), ["complete"]);
    assert!(rig.bridge.dispatch().await.unwrap().permits_seeded);
    rig.put(&signer, BUCKET, "a", b"two").await.expect(200);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(200);

    // A second restore arms the gate again, under a later mark, also
    // within the same millisecond.
    let second = rig
        .bridge
        .catalog
        .restore_begin(UnixMs(5), rig.now())
        .await
        .unwrap()
        .unwrap();
    assert!(second > run);
    assert_eq!(restore_state(&rig), ["replaying"]);
    rig.put(&signer, BUCKET, "a", b"three").await.expect(503);
}

/// The runbook closes a database that was just brought back with one
/// statement file, before any replay has run. It must hold with
/// maintenance off, over an empty table and over the row of a finished
/// replay, and make the cursors of that replay void.
#[tokio::test(flavor = "current_thread")]
async fn the_runbook_statement_closes_a_restored_catalogue() {
    const ARM: &str = include_str!("../../../workers/s3-bridge/ops/restore-arm.sql");
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"one").await.expect(200);
    let arm = || {
        rig.bridge
            .catalog
            .sql
            .with_conn(|c| c.execute_batch(ARM).unwrap())
    };
    let catalog = &rig.bridge.catalog;

    arm();
    assert_eq!(restore_state(&rig), ["replaying"]);
    rig.put(&signer, BUCKET, "a", b"two").await.expect(503);
    delete(&rig, &signer, "a").await.expect(503);
    assert_eq!(get(&rig, &signer, "a").await.expect(200).body, b"one");
    // Twice is as good as once.
    arm();
    rig.put(&signer, BUCKET, "a", b"two").await.expect(503);

    // A replay that runs to its end opens it.
    let run = catalog
        .restore_begin(UnixMs(0), rig.now())
        .await
        .unwrap()
        .unwrap();
    replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert!(catalog
        .restore_finish(run, rig.now(), 0, "main")
        .await
        .unwrap());
    rig.put(&signer, BUCKET, "a", b"two").await.expect(200);

    // Brought back once more (the row of the finished replay came with
    // the copy): closed again, and the old replay cannot end the new
    // state.
    arm();
    assert_eq!(restore_state(&rig), ["replaying"]);
    rig.put(&signer, BUCKET, "a", b"three").await.expect(503);
    assert_eq!(catalog.restore_progress(run).await.unwrap(), None);
    assert!(!catalog
        .restore_finish(run, rig.now(), 0, "main")
        .await
        .unwrap());
    assert_eq!(restore_state(&rig), ["replaying"]);
}

/// A request that passed the gate before a replay started must not
/// commit under it: the batch itself is refused, and the client is told
/// to come back.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_that_starts_after_the_gate_refuses_the_commit() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"one").await.expect(200);
    let (id, etags, _) = two_parts(&rig, &signer, "big").await;
    let before = records(&rig);
    let live = live_ids(&rig);

    // The replay starts when the request stores its first blob: after
    // its gate, before its batch.
    let arm = || {
        let bridge = rig.bridge.clone();
        let hook = move |_: &str| {
            bridge.catalog.sql.with_conn(|c| {
                let q = "INSERT INTO restore_state(id, state, since_ms, started_at) \
                         VALUES (1, 'replaying', 0, 1)";
                c.execute(q, []).unwrap()
            });
        };
        rig.bridge.safety.before_put.replace(Some(Box::new(hook)));
    };
    let disarm = || {
        assert_eq!(restore_state(&rig), ["replaying"], "the hook ran");
        rig.bridge
            .catalog
            .sql
            .with_conn(|c| c.execute("DELETE FROM restore_state", []).unwrap());
    };

    arm();
    rig.put(&signer, BUCKET, "a", b"two").await.expect(503);
    disarm();
    arm();
    rig.put(&signer, BUCKET, "new", b"new").await.expect(503);
    disarm();
    arm();
    copy(&rig, &signer, "a", "copy").await.expect(503);
    disarm();
    arm();
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(503);
    disarm();
    // Nothing was published, and no record of these writes is left.
    assert_eq!(live_ids(&rig), live);
    assert_eq!(records(&rig), before);

    // A delete answers 503 as well, and the object stays. Its tombstone
    // is on record, as that of any delete that failed.
    arm();
    delete(&rig, &signer, "a").await.expect(503);
    disarm();
    assert_eq!(live_ids(&rig), live);
    assert_eq!(get(&rig, &signer, "a").await.expect(200).body, b"one");

    // With no replay under way, each of them goes through.
    rig.put(&signer, BUCKET, "a", b"two").await.expect(200);
    copy(&rig, &signer, "a", "copy").await.expect(200);
    complete(&rig, &signer, "big", &id, &etags)
        .await
        .expect(200);
    delete(&rig, &signer, "a").await.expect(204);
    get(&rig, &signer, "a").await.expect(404);
}

/// The restore route takes a cursor only up to the place the replay has
/// come to. A cursor that is ahead (a later phase, a later record,
/// another restore point) would end the replay with records left out,
/// and open the catalogue for writes.
#[tokio::test(flavor = "current_thread")]
async fn a_cursor_ahead_of_the_replay_is_refused() {
    let serving = rig();
    let (_, signer) = serving.standard(BUCKET).await;
    serving.put(&signer, BUCKET, "a", b"a").await.expect(200);
    tick(&serving);
    serving.put(&signer, BUCKET, "b", b"b").await.expect(200);
    tick(&serving);
    delete(&serving, &signer, "b").await.expect(204);

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
    let step = |body: Value| {
        let restoring = &restoring;
        async move {
            let r = admin(restoring, "/restore", body).await;
            let report: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            (r.status, report)
        }
    };

    let (status, first) = step(json!({ "since_ms": 0, "margin_ms": 0 })).await;
    assert_eq!(status, 200);
    let next = first["next"].clone();
    assert_eq!(next["phase"], "tombstones");
    let with = |field: &str, value: Value| {
        let mut cursor = next.clone();
        cursor[field] = value;
        json!({ "cursor": cursor })
    };
    for ahead in [
        // A phase the replay has not come to.
        with("phase", json!("held")),
        // A record further on in this phase.
        with("after", json!("m/del/zzzz")),
        with("extent", json!(1)),
        // A later restore point: fewer records.
        with("since_ms", json!(1)),
    ] {
        let (status, _) = step(ahead.clone()).await;
        assert_eq!(status, 400, "{ahead}");
        assert_eq!(restore_state(&restoring), ["replaying"]);
    }
    // Nothing of the tombstone phase has run.
    assert_eq!(restoring.count("objects"), 2);
    // Another replay's mark.
    let (status, _) = step(with("run_ms", json!(1))).await;
    assert_eq!(status, 409);

    // A cursor that is behind repeats a step and changes nothing: the
    // place on record stays where it was.
    let behind = json!({ "cursor": {
        "since_ms": 0, "phase": "manifests", "after": "", "extent": 0,
        "run_ms": next["run_ms"],
    }});
    let (status, again) = step(behind).await;
    assert_eq!(status, 200);
    assert_eq!(again["next"], next);
    assert_eq!(again["published"], 0);
    assert_eq!(again["present"], 2);

    // Neither does the place on record move backwards.
    let run = UnixMs(next["run_ms"].as_i64().unwrap());
    let catalog = &restoring.bridge.catalog;
    let reached = catalog.restore_progress(run).await.unwrap().unwrap();
    assert_eq!(reached.reached.as_ref().map(|m| m.phase), Some(1));
    let back = velmora_bridge::replay::ReplayMark {
        phase: 0,
        after: "m/gen/zzzz".into(),
        extent: 9,
    };
    catalog.restore_advance(run, &back).await.unwrap();
    assert_eq!(catalog.restore_progress(run).await.unwrap(), Some(reached));

    // From the place on record, the replay runs to its end.
    let mut body = json!({ "cursor": next });
    loop {
        let (status, report) = step(body).await;
        assert_eq!(status, 200);
        if report["next"].is_null() {
            break;
        }
        // A cursor the route handed out is taken once more, also after
        // the replay went past it.
        body = json!({ "cursor": report["next"] });
    }
    assert_eq!(restore_state(&restoring), ["complete"]);
    assert_eq!(restoring.count("objects"), 1);
}

// ---------------------------------------------------------------------------
// A catalogue that is older than the release of a pinned copy
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_pinned_copy_released_after_the_export_is_found() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "old", b"old").await.expect(200);
    let (_, extents) = rig.live(&bucket, "old").await.unwrap();
    tick(&rig);
    rig.put(&signer, BUCKET, "kept", b"kept").await.expect(200);
    tick(&rig);
    export(&rig);
    let exported_at = rig.now();
    tick(&rig);

    // After the export the pipeline released the pinned copy of `old`.
    // The export still says it is held.
    for x in &extents {
        rig.bridge
            .safety
            .inner
            .delete(&x.id.safety_key())
            .await
            .unwrap();
    }
    wipe(&rig);
    import(&rig);

    // A replay from the restore point does not read the record of
    // `old`, and reports the extent.
    let (report, _) = replay(&rig, exported_at, ReplayLimits::default()).await;
    assert_eq!(report.held_checked, 2, "{report:?}");
    assert_eq!(report.held_missing_total, 1, "{report:?}");
    assert_eq!(report.held_missing, [extents[0].id.as_str()]);

    // A replay from 0 reads it and sets the row right.
    let (report, _) = replay(
        &rig,
        UnixMs(0),
        ReplayLimits {
            records: 1,
            extents: 1,
        },
    )
    .await;
    assert_eq!(report.held_checked, 1, "{report:?}");
    assert_eq!(report.held_missing_total, 0, "{report:?}");
    assert_eq!(report.safety_missing, 1, "{report:?}");
}

// ---------------------------------------------------------------------------
// Random histories inside one millisecond replay to the same answers
// ---------------------------------------------------------------------------

/// splitmix64: the histories below are the same on every run.
struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) % sides
    }
}

const DICE_KEYS: [&str; 4] = ["k0", "k1", "k2", "k3"];

/// One random write: a PUT, a copy (onto another key, or onto itself
/// with new metadata), a delete or a one-part multipart upload. The
/// clock mostly stands still, so ids are minted in one millisecond;
/// now and then it moves a little, also backwards (an isolate whose
/// clock is behind).
async fn random_write(
    rig: &Rig,
    signer: &Signer,
    dice: &mut Dice,
    n: usize,
    log: &mut Vec<String>,
) {
    match dice.roll(8) {
        0 => rig.bridge.clock.advance_ms(1),
        1 => rig.bridge.clock.advance_ms(-2),
        _ => {}
    }
    let key = DICE_KEYS[dice.roll(4) as usize];
    let body = format!("body {n}");
    let status = match dice.roll(6) {
        0 | 1 => {
            log.push(format!("put {key}"));
            rig.put(signer, BUCKET, key, body.as_bytes()).await.status
        }
        2 => {
            let from = DICE_KEYS[dice.roll(4) as usize];
            log.push(format!("copy {from} -> {key}"));
            let source = format!("/{BUCKET}/{from}");
            let tag = n.to_string();
            let mut headers = vec![("x-amz-copy-source", source.as_str())];
            if from == key || dice.roll(2) == 0 {
                headers.push(("x-amz-metadata-directive", "REPLACE"));
                headers.push(("x-amz-meta-n", tag.as_str()));
            }
            rig.call(signer, Method::Put, &path(BUCKET, key), &[], &headers, b"")
                .await
                .status
        }
        3 | 4 => {
            log.push(format!("delete {key}"));
            delete(rig, signer, key).await.status
        }
        _ => {
            log.push(format!("complete {key}"));
            let id = create_upload(rig, signer, key).await;
            let etag = upload_part(rig, signer, key, &id, 1, body.as_bytes()).await;
            complete(rig, signer, key, &id, &[etag]).await.status
        }
    };
    // A copy of a key that is not there answers 404; nothing else fails.
    assert!(matches!(status, 200 | 204 | 404), "{status}: {log:?}");
}

/// What a client sees of every key.
async fn answers(
    rig: &Rig,
    signer: &Signer,
) -> Vec<(u16, Vec<u8>, Option<String>, Option<String>)> {
    let mut all = Vec::new();
    for key in DICE_KEYS {
        let got = get(rig, signer, key).await;
        let live = got.status == 200;
        all.push((
            got.status,
            if live { got.body.clone() } else { Vec::new() },
            got.header("x-amz-meta-n")
                .filter(|_| live)
                .map(str::to_owned),
            got.header("etag").filter(|_| live).map(str::to_owned),
        ));
    }
    all
}

#[tokio::test(flavor = "current_thread")]
async fn random_histories_in_one_millisecond_replay_to_the_same_answers() {
    for seed in 0..150u64 {
        let rig = rig();
        let (_, signer) = rig.standard(BUCKET).await;
        let mut dice = Dice(seed);
        let mut log = Vec::new();
        for n in 0..40 {
            random_write(&rig, &signer, &mut dice, n, &mut log).await;
        }
        let before = answers(&rig, &signer).await;
        wipe(&rig);
        let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
        assert!(
            report.unpublishable.is_empty() && report.unreadable.is_empty(),
            "seed {seed}: {report:?}"
        );
        let signer = reissue_key(&rig).await;
        assert_eq!(answers(&rig, &signer).await, before, "seed {seed}: {log:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn random_histories_across_an_export_replay_to_the_same_answers() {
    for seed in 1000..1300u64 {
        let rig = rig();
        let (_, signer) = rig.standard(BUCKET).await;
        let mut dice = Dice(seed);
        let mut log = Vec::new();
        let cut = 5 + dice.roll(30) as usize;
        for n in 0..cut {
            random_write(&rig, &signer, &mut dice, n, &mut log).await;
        }
        export(&rig);
        // The restore point lies before the export by more than any
        // clock in the history runs behind.
        let since = rig.now().plus_ms(-1000);
        log.push("export".into());
        for n in cut..40 {
            random_write(&rig, &signer, &mut dice, n, &mut log).await;
        }
        let before = answers(&rig, &signer).await;
        wipe(&rig);
        import(&rig);
        let (report, _) = replay(&rig, since, ReplayLimits::default()).await;
        assert!(
            report.unpublishable.is_empty() && report.unreadable.is_empty(),
            "seed {seed}: {report:?}"
        );
        assert_eq!(answers(&rig, &signer).await, before, "seed {seed}: {log:?}");
    }
}

/// Clears what a fault left armed, so the next request starts clean.
async fn disarm(rig: &Rig) {
    let sql = &rig.bridge.catalog.sql;
    sql.fail_publish.set(None);
    sql.fail_batches.set(0);
    rig.bridge.safety.fail_record_deletes.set(0);
    // `Down` fails the batch after the publication too: this is it.
    let _ = sql.batch(Vec::new()).await;
}

/// The first half of a DeleteObject, as the service does it: the
/// tombstone is on record and the batch has not run. `None` = nothing
/// to delete.
async fn begin_delete(
    rig: &Rig,
    bucket: &BucketId,
    key: &str,
    dice: &mut Dice,
) -> Option<GenerationId> {
    let catalog = &rig.bridge.catalog;
    let seen = match catalog.live_object(bucket, key).await.unwrap() {
        Some((live, _)) => live.id,
        None => catalog.unpublished_floor(bucket, key).await.unwrap()?,
    };
    let newest = catalog.newest_id(bucket, key).await.unwrap();
    let newest = newest.map_or(seen.clone(), |n| n.max(seen));
    let now = rig.now();
    let id = tombstone_id(now, &newest, dice.roll(u64::MAX).to_be_bytes());
    let (safety, kek) = (&rig.bridge.safety, &rig.bridge.kek);
    write_tombstone(catalog, safety, kek, bucket, key, &id, now)
        .await
        .unwrap();
    Some(id)
}

/// One random request with a random fault: a publication batch that
/// fails before or after it applied, or with the batch after it; a
/// batch that fails; a store that does not delete a refused record; a
/// clock that runs well behind. A delete can stop after its tombstone
/// and finish later, or never.
async fn random_faulty_write(
    rig: &Rig,
    signer: &Signer,
    bucket: &BucketId,
    dice: &mut Dice,
    n: usize,
    begun: &mut Vec<(&'static str, GenerationId)>,
    log: &mut Vec<String>,
) {
    disarm(rig).await;
    match dice.roll(8) {
        0 => rig.bridge.clock.advance_ms(1),
        1 => rig.bridge.clock.advance_ms(-2),
        2 => rig.bridge.clock.advance_ms(-40),
        _ => {}
    }
    let key = DICE_KEYS[dice.roll(4) as usize];
    let body = format!("body {n}");
    let op = dice.roll(8);
    // A Complete arms its fault after the upload exists.
    let upload = match op {
        7 => {
            let id = create_upload(rig, signer, key).await;
            let etag = upload_part(rig, signer, key, &id, 1, body.as_bytes()).await;
            Some((id, etag))
        }
        _ => None,
    };
    let sql = &rig.bridge.catalog.sql;
    let fault = match dice.roll(10) {
        0 => {
            sql.fail_publish.set(Some(PublishFault::NotApplied));
            "not applied"
        }
        1 => {
            sql.fail_publish.set(Some(PublishFault::Applied));
            "applied"
        }
        2 => {
            sql.fail_publish.set(Some(PublishFault::Down));
            "down"
        }
        3 => {
            sql.fail_publish.set(Some(PublishFault::NotApplied));
            rig.bridge.safety.fail_record_deletes.set(3);
            "not applied, record stays"
        }
        4 => {
            rig.bridge.safety.fail_record_deletes.set(3);
            "record stays"
        }
        5 => {
            sql.fail_batches.set(1 + dice.roll(2) as u32);
            "batch fails"
        }
        _ => "",
    };
    match (op, upload) {
        (0..=2, _) => {
            log.push(format!("put {key} [{fault}]"));
            rig.put(signer, BUCKET, key, body.as_bytes()).await;
        }
        (3, _) => {
            let from = DICE_KEYS[dice.roll(4) as usize];
            log.push(format!("copy {from} -> {key} [{fault}]"));
            let source = format!("/{BUCKET}/{from}");
            let tag = n.to_string();
            let mut headers = vec![("x-amz-copy-source", source.as_str())];
            if from == key || dice.roll(2) == 0 {
                headers.push(("x-amz-metadata-directive", "REPLACE"));
                headers.push(("x-amz-meta-n", tag.as_str()));
            }
            rig.call(signer, Method::Put, &path(BUCKET, key), &[], &headers, b"")
                .await;
        }
        (4, _) => {
            log.push(format!("delete {key} [{fault}]"));
            delete(rig, signer, key).await;
        }
        (5, _) => {
            disarm(rig).await;
            if let Some(id) = begin_delete(rig, bucket, key, dice).await {
                log.push(format!("delete {key} begins"));
                begun.push((key, id));
            }
        }
        (6, _) if !begun.is_empty() => {
            let (key, id) = begun.swap_remove(dice.roll(begun.len() as u64) as usize);
            log.push(format!("delete {key} finishes [{fault}]"));
            let _ = rig
                .bridge
                .catalog
                .delete_object_before(bucket, key, &id, rig.now())
                .await;
        }
        (_, Some((id, etag))) => {
            log.push(format!("complete {key} [{fault}]"));
            complete(rig, signer, key, &id, &[etag]).await;
        }
        _ => {}
    }
}

/// Whatever failed on a key and whatever was left half done, the next
/// acknowledged write or delete of the key decides what a replay
/// restores: it sorts after every record stored before it.
#[tokio::test(flavor = "current_thread")]
async fn random_histories_with_faults_replay_to_the_same_answers() {
    for seed in 2000..2200u64 {
        let rig = rig();
        let (bucket, signer) = rig.standard(BUCKET).await;
        let mut dice = Dice(seed);
        let mut log = Vec::new();
        let mut begun = Vec::new();
        for n in 0..40 {
            random_faulty_write(
                &rig, &signer, &bucket.id, &mut dice, n, &mut begun, &mut log,
            )
            .await;
        }
        disarm(&rig).await;
        for key in DICE_KEYS {
            let status = if dice.roll(2) == 0 {
                log.push(format!("last: put {key}"));
                rig.put(&signer, BUCKET, key, b"last").await.status
            } else {
                log.push(format!("last: delete {key}"));
                delete(&rig, &signer, key).await.status
            };
            assert!(matches!(status, 200 | 204), "seed {seed}: {status} {log:?}");
        }
        let before = answers(&rig, &signer).await;
        wipe(&rig);
        let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
        assert!(
            report.unpublishable.is_empty() && report.unreadable.is_empty(),
            "seed {seed}: {report:?} {log:?}"
        );
        let signer = reissue_key(&rig).await;
        assert_eq!(answers(&rig, &signer).await, before, "seed {seed}: {log:?}");
    }
}

/// Two deletes that both saw the same live generation: the first one
/// commits, the second one stores its tombstone and then finds nothing
/// left to delete. Both are acknowledged. A PUT after them must sort
/// after both tombstones, or a replay applies the second tombstone to it.
#[tokio::test(flavor = "current_thread")]
async fn a_put_sorts_after_a_tombstone_whose_delete_found_nothing() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let bucket = bucket.id;
    rig.put(&signer, BUCKET, "k", b"v1").await.expect(200);
    let v1 = GenerationId::new(live_ids(&rig).remove(0));
    rig.bridge.clock.advance_ms(10);
    let now_b = UnixMs(rig.bridge.clock.now().0 + 1);
    let t_b = recovery::tombstone_id(now_b, &v1, [0xff; 8]);
    recovery::write_tombstone(
        &rig.bridge.catalog,
        &rig.bridge.safety,
        &rig.bridge.kek,
        &bucket,
        "k",
        &t_b,
        now_b,
    )
    .await
    .unwrap();
    delete(&rig, &signer, "k").await.expect(204);
    let cat = &rig.bridge.catalog;
    assert!(!cat
        .delete_object_before(&bucket, "k", &t_b, now_b)
        .await
        .unwrap());
    rig.bridge.clock.advance_ms(1);
    rig.put(&signer, BUCKET, "k", b"v2").await.expect(200);
    replay_answers_the_same(&rig, &signer, &["k"]).await;
}

/// The newest generation record there is, and how many there are.
fn newest_record(rig: &Rig) -> (String, usize) {
    let all = records(rig);
    let ids = all
        .iter()
        .filter(|r| !r[GENERATION_PREFIX.len()..].contains('/'));
    let ids: Vec<&String> = ids.collect();
    let newest = ids.iter().max().unwrap();
    (newest[GENERATION_PREFIX.len()..].to_owned(), ids.len())
}

/// A PUT whose record is stored and whose batch then fails for the
/// database answers 500, and its record stays: nobody knows whether the
/// batch went through. An acknowledged PUT after it, from an isolate
/// whose clock is behind, must still sort after that record, or a replay
/// publishes the failed write over it.
#[tokio::test(flavor = "current_thread")]
async fn a_put_sorts_after_the_record_of_a_put_whose_commit_failed() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "over", b"v1").await.expect(200);
    rig.bridge.clock.advance_ms(10);
    for key in ["new", "over"] {
        let (_, before) = newest_record(&rig);
        rig.bridge.catalog.sql.fail_batches.set(1);
        rig.put(&signer, BUCKET, key, b"failed")
            .await
            .expect_error(500, "InternalError");
        let (failed, after) = newest_record(&rig);
        assert_eq!(after, before + 1, "the record of the failed PUT stays");

        // The next writer's clock is half a second behind.
        rig.bridge.clock.advance_ms(-500);
        rig.put(&signer, BUCKET, key, b"v2").await.expect(200);
        let live = rig.bridge.catalog.sql.with_conn(|c| {
            let q = "SELECT generation_id FROM objects WHERE key = ?1";
            c.query_row(q, [key], |r| r.get::<_, String>(0)).unwrap()
        });
        assert!(live > failed, "{key}: {live} sorts after {failed}");
        rig.bridge.clock.advance_ms(1000);
    }
    replay_answers_the_same(&rig, &signer, &["new", "over"]).await;
}

/// The same for a copy whose batch failed for the database.
#[tokio::test(flavor = "current_thread")]
async fn a_put_sorts_after_the_record_of_a_copy_whose_commit_failed() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "src", b"source").await.expect(200);
    rig.bridge.clock.advance_ms(10);
    rig.bridge.catalog.sql.fail_batches.set(1);
    copy(&rig, &signer, "src", "dst")
        .await
        .expect_error(500, "InternalError");
    let (failed, _) = newest_record(&rig);
    rig.bridge.clock.advance_ms(-500);
    rig.put(&signer, BUCKET, "dst", b"put").await.expect(200);
    let ids = live_ids(&rig);
    assert!(ids[0] > failed, "{} sorts after {failed}", ids[0]);
    rig.bridge.clock.advance_ms(1000);
    replay_answers_the_same(&rig, &signer, &["src", "dst"]).await;
}

/// A copy whose batch was refused because its source changed removes
/// its record, and here the store refuses that. The copy fails; its
/// record stays. A PUT on the destination from a slower clock sorts
/// after it all the same.
#[tokio::test(flavor = "current_thread")]
async fn a_put_sorts_after_the_record_a_refused_copy_could_not_remove() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "src", b"source").await.expect(200);
    rig.bridge.clock.advance_ms(10);
    let (_, before) = newest_record(&rig);

    let etag = |rig: &Rig, etag: &str| {
        rig.bridge.catalog.sql.with_conn(|c| {
            let q = "UPDATE generations SET etag = ?1 WHERE key = 'src'";
            c.execute(q, [etag]).unwrap()
        });
    };
    let source = rig.live(&bucket, "src").await.unwrap().0.etag;
    let bridge = rig.bridge.clone();
    let hook = move |key: &str| {
        // The source changes between the read and the batch, and the
        // record written here cannot be removed afterwards.
        bridge.catalog.sql.with_conn(|c| {
            let q = "UPDATE generations SET etag = '\"changed\"' WHERE key = 'src'";
            c.execute(q, []).unwrap()
        });
        *bridge.safety.fail_delete.borrow_mut() = Some(key.to_owned());
    };
    rig.bridge.safety.before_put.replace(Some(Box::new(hook)));
    copy(&rig, &signer, "src", "dst")
        .await
        .expect_error(500, "InternalError");
    let (orphan, after) = newest_record(&rig);
    assert_eq!(after, before + 1, "the record of the refused copy stays");
    *rig.bridge.safety.fail_delete.borrow_mut() = None;
    etag(&rig, &source);

    rig.bridge.clock.advance_ms(-500);
    rig.put(&signer, BUCKET, "dst", b"put").await.expect(200);
    let ids = live_ids(&rig);
    assert!(ids[0] > orphan, "{} sorts after {orphan}", ids[0]);
    rig.bridge.clock.advance_ms(1000);
    replay_answers_the_same(&rig, &signer, &["src", "dst"]).await;
}

/// A Complete whose batch was refused because the upload changed removes
/// its record as a best effort. When that fails and the request then
/// ends in an error, the record stays, and a PUT on the key from a
/// slower clock sorts after it all the same.
#[tokio::test(flavor = "current_thread")]
async fn a_put_sorts_after_the_record_a_refused_complete_could_not_remove() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create_upload(&rig, &signer, "big").await;
    let etag = upload_part(&rig, &signer, "big", &id, 1, b"part one").await;
    rig.bridge.clock.advance_ms(10);

    let bridge = rig.bridge.clone();
    let hook = move |key: &str| {
        // The upload changes between the read and the batch; the record
        // cannot be removed; and the next read of the upload fails.
        bridge.catalog.sql.with_conn(|c| {
            c.execute("UPDATE uploads SET revision = revision + 1", [])
                .unwrap()
        });
        *bridge.safety.fail_delete.borrow_mut() = Some(key.to_owned());
        let sql = &bridge.catalog.sql;
        sql.fail_matching.replace(Some(("FROM uploads", 0)));
    };
    rig.bridge.safety.before_put.replace(Some(Box::new(hook)));
    complete(&rig, &signer, "big", &id, std::slice::from_ref(&etag))
        .await
        .expect_error(500, "InternalError");
    rig.bridge.catalog.sql.fail_matching.replace(None);
    *rig.bridge.safety.fail_delete.borrow_mut() = None;
    let (orphan, records) = newest_record(&rig);
    assert_eq!(records, 1, "the record of the refused Complete stays");
    get(&rig, &signer, "big").await.expect(404);

    rig.bridge.clock.advance_ms(-500);
    rig.put(&signer, BUCKET, "big", b"put").await.expect(200);
    let ids = live_ids(&rig);
    assert!(ids[0] > orphan, "{} sorts after {orphan}", ids[0]);
    rig.bridge.clock.advance_ms(1000);
    replay_answers_the_same(&rig, &signer, &["big"]).await;
}

/// A delete after a write that failed with its record stored: the
/// tombstone sorts after that record, so a replay cannot publish the
/// failed write over the acknowledged delete.
#[tokio::test(flavor = "current_thread")]
async fn a_delete_sorts_after_the_record_of_a_put_whose_commit_failed() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"v1").await.expect(200);
    rig.bridge.clock.advance_ms(10);
    rig.bridge.catalog.sql.fail_batches.set(1);
    rig.put(&signer, BUCKET, "k", b"failed")
        .await
        .expect_error(500, "InternalError");
    let (failed, _) = newest_record(&rig);
    rig.bridge.clock.advance_ms(-500);
    delete(&rig, &signer, "k").await.expect(204);
    let tombstone = records(&rig)
        .into_iter()
        .find_map(|r| r.strip_prefix(TOMBSTONE_PREFIX).map(str::to_owned))
        .unwrap();
    assert!(tombstone > failed, "{tombstone} sorts after {failed}");
    rig.bridge.clock.advance_ms(1000);
    replay_answers_the_same(&rig, &signer, &["k"]).await;
}

fn tombstones(rig: &Rig) -> Vec<String> {
    records(rig)
        .into_iter()
        .filter(|r| r.starts_with(TOMBSTONE_PREFIX))
        .collect()
}

/// A delete of a key with nothing live, after a write that failed with
/// its record stored: the delete is acknowledged, so a replay must not
/// publish the failed write. The delete leaves a tombstone above that
/// record, once: a repeated delete of the key records nothing more.
#[tokio::test(flavor = "current_thread")]
async fn a_delete_of_nothing_live_covers_the_record_of_a_failed_put() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    // A key that was never written and one that is: no tombstone.
    delete(&rig, &signer, "k").await.expect(204);
    assert!(tombstones(&rig).is_empty());

    rig.bridge.catalog.sql.fail_batches.set(1);
    rig.put(&signer, BUCKET, "k", b"failed")
        .await
        .expect_error(500, "InternalError");
    let (failed, _) = newest_record(&rig);
    // From a clock that runs behind, all the same.
    rig.bridge.clock.advance_ms(-500);
    delete(&rig, &signer, "k").await.expect(204);
    let written = tombstones(&rig);
    assert_eq!(written.len(), 1);
    let tombstone = written[0].strip_prefix(TOMBSTONE_PREFIX).unwrap();
    assert!(
        tombstone > failed.as_str(),
        "{tombstone} sorts after {failed}"
    );
    delete(&rig, &signer, "k").await.expect(204);
    delete(&rig, &signer, "k").await.expect(204);
    assert_eq!(tombstones(&rig), written, "nothing more to cover");
    rig.bridge.clock.advance_ms(1000);
    replay_answers_the_same(&rig, &signer, &["k"]).await;

    // After the replay the same holds: nothing live, nothing to cover.
    delete(&rig, &signer, "k").await.expect(204);
    assert_eq!(tombstones(&rig), written);
}

/// The same for a copy and for a write that failed after a delete: each
/// failed write is covered by the next acknowledged delete.
#[tokio::test(flavor = "current_thread")]
async fn each_failed_write_on_a_deleted_key_is_covered_by_the_next_delete() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "src", b"source").await.expect(200);
    rig.put(&signer, BUCKET, "k", b"v1").await.expect(200);
    delete(&rig, &signer, "k").await.expect(204);
    assert_eq!(tombstones(&rig).len(), 1);

    rig.bridge.catalog.sql.fail_batches.set(1);
    copy(&rig, &signer, "src", "k")
        .await
        .expect_error(500, "InternalError");
    delete(&rig, &signer, "k").await.expect(204);
    assert_eq!(tombstones(&rig).len(), 2);

    rig.bridge.catalog.sql.fail_batches.set(1);
    rig.put(&signer, BUCKET, "k", b"failed")
        .await
        .expect_error(500, "InternalError");
    delete(&rig, &signer, "k").await.expect(204);
    assert_eq!(tombstones(&rig).len(), 3);
    delete(&rig, &signer, "k").await.expect(204);
    assert_eq!(tombstones(&rig).len(), 3);
    replay_answers_the_same(&rig, &signer, &["src", "k"]).await;
}

/// The delete of a key with nothing live runs the catalogue batch as
/// well: a PUT that is published under an id below the tombstone, after
/// the delete looked and before its batch, is deleted here as it is in
/// a replay.
#[tokio::test(flavor = "current_thread")]
async fn a_put_published_under_the_tombstone_of_such_a_delete_is_deleted() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bridge.catalog.sql.fail_batches.set(1);
    rig.put(&signer, BUCKET, "k", b"failed")
        .await
        .expect_error(500, "InternalError");
    // The PUT lands when the delete stores its tombstone: its id is
    // above the record of the failed write and below the tombstone,
    // which is minted one millisecond after the floor at the least.
    let (failed, _) = newest_record(&rig);
    let between = format!("{}ffffffffffffffff", &failed[..15]);
    let bridge = rig.bridge.clone();
    let hook = move |_: &str| {
        bridge.catalog.sql.with_conn(|c| {
            c.execute(
                "INSERT INTO generations(id, bucket_id, key, state, size, etag, checksum_json, \
                   content_json, user_meta_json, extent_count, created_at) \
                 SELECT ?1, bucket_id, key, 'live', 0, 'x', '{}', '{}', '{}', 0, 0 \
                   FROM key_floors WHERE key = 'k'",
                [&between],
            )
            .unwrap();
            c.execute(
                "INSERT INTO objects(bucket_id, key, generation_id) \
                 SELECT bucket_id, key, id FROM generations WHERE key = 'k'",
                [],
            )
            .unwrap()
        });
    };
    rig.bridge.safety.before_put.replace(Some(Box::new(hook)));
    delete(&rig, &signer, "k").await.expect(204);
    assert_eq!(rig.count("generations"), 1, "the hook ran");
    assert!(live_ids(&rig).is_empty(), "deleted with the batch");
    get(&rig, &signer, "k").await.expect(404);
}

/// A replay leaves the floors as the records say, also for a tombstone
/// that deletes nothing in it: a PUT after the replay sorts after every
/// tombstone on record, and a second replay keeps it.
#[tokio::test(flavor = "current_thread")]
async fn a_put_after_a_replay_sorts_after_every_tombstone_on_record() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let bucket = bucket.id;
    rig.put(&signer, BUCKET, "k", b"v1").await.expect(200);
    let v1 = GenerationId::new(live_ids(&rig).remove(0));
    rig.bridge.clock.advance_ms(10);
    // The second delete of two, as above: its tombstone is the later one.
    let now_b = UnixMs(rig.bridge.clock.now().0 + 1);
    let t_b = recovery::tombstone_id(now_b, &v1, [0xff; 8]);
    let (cat, safety) = (&rig.bridge.catalog, &rig.bridge.safety);
    recovery::write_tombstone(cat, safety, &rig.bridge.kek, &bucket, "k", &t_b, now_b)
        .await
        .unwrap();
    delete(&rig, &signer, "k").await.expect(204);
    assert!(!cat
        .delete_object_before(&bucket, "k", &t_b, now_b)
        .await
        .unwrap());

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!((report.tombstones, report.deleted), (2, 1), "{report:?}");
    let signer = reissue_key(&rig).await;
    rig.bridge.clock.set(now_b);
    rig.put(&signer, BUCKET, "k", b"v2").await.expect(200);
    let v2 = live_ids(&rig).remove(0);
    assert!(v2.as_str() > t_b.as_str(), "{v2} sorts after {t_b:?}");
    replay_answers_the_same(&rig, &signer, &["k"]).await;
}

/// A Complete that the catalogue refuses while nothing changed the
/// upload and nothing outran its id is not tried again: the parts are
/// not adoptable. The floor the request raised for its own record does
/// not count as a newer id on the key.
#[tokio::test(flavor = "current_thread")]
async fn a_complete_refused_for_its_parts_is_not_taken_for_an_id_race() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create_upload(&rig, &signer, "big").await;
    let etag = upload_part(&rig, &signer, "big", &id, 1, b"part one").await;
    let bridge = rig.bridge.clone();
    let hook = move |_: &str| {
        // The part is no longer what was listed when the batch runs,
        // and the upload itself says nothing of it.
        bridge.catalog.sql.with_conn(|c| {
            c.execute("UPDATE extents SET plain_size = plain_size + 1", [])
                .unwrap()
        });
    };
    rig.bridge.safety.before_put.replace(Some(Box::new(hook)));
    complete(&rig, &signer, "big", &id, std::slice::from_ref(&etag))
        .await
        .expect_error(400, "InvalidPart");
    assert!(records(&rig).is_empty(), "the refused record is removed");
}

// ---------------------------------------------------------------------------
// Article plans: each row's yEnc form
// ---------------------------------------------------------------------------

/// Stores a plan record for the only extent of `key`, one row per
/// article, row `i` under `names[i]`. Returns the extent and the plan.
async fn plan_record(
    rig: &Rig,
    bucket: &Bucket,
    key: &str,
    names: &[Option<&str>],
) -> (ExtentRow, Vec<ArticleRow>) {
    let (_, extents) = rig.live(bucket, key).await.unwrap();
    let extent = extents[0].clone();
    let spans = velmora_bridge::articles::article_spans(extent.cipher_size);
    assert_eq!(spans.len(), names.len());
    let plan: Vec<ArticleRow> = (0u32..)
        .zip(spans.iter().zip(names))
        .map(|(idx, (span, name))| ArticleRow {
            extent_id: extent.id.clone(),
            idx,
            message_id: format!("{idx}k7q2m9x4v1z8c3b6n5j0h2g4f6d8s1a3@example.invalid"),
            newsgroup: "alt.binaries.test".into(),
            headers: format!("Subject: s{idx}\r\n").into_bytes(),
            cipher_offset: span.start,
            cipher_len: span.len,
            payload_sha256: [idx as u8; 32],
            yenc_name: name.map(str::to_owned),
            state: ArticleState::Planned,
            provider_id: None,
            posted_at: None,
        })
        .collect();
    velmora_bridge::recovery::write_article_plan(
        &rig.bridge.safety,
        &rig.bridge.kek,
        &extent,
        &plan,
    )
    .await
    .unwrap();
    (extent, plan)
}

/// A replay through the SQL catalogue restores each row's yEnc name: a
/// standalone row keeps its own, an older multi-part row stays NULL, so
/// each reposts in the form it was posted in.
#[tokio::test(flavor = "current_thread")]
async fn a_replayed_plan_keeps_each_rows_yenc_form() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = vec![7u8; 1_000_000];
    rig.put(&signer, BUCKET, "two-articles", &body)
        .await
        .expect(200);
    let (extent, plan) =
        plan_record(&rig, &bucket, "two-articles", &[Some("k3v9q0zx7m2a"), None]).await;

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(report.article_plans, 1, "{report:?}");
    assert!(report.unreadable.is_empty(), "{report:?}");

    let rows = rig.bridge.catalog.articles(&extent.id).await.unwrap();
    let names: Vec<_> = rows.iter().map(|a| a.yenc_name.clone()).collect();
    assert_eq!(names, [Some("k3v9q0zx7m2a".to_string()), None]);
    let ids: Vec<_> = rows.iter().map(|a| a.message_id.clone()).collect();
    let want: Vec<_> = plan.iter().map(|a| a.message_id.clone()).collect();
    assert_eq!(ids, want);
}

/// A plan record whose yEnc name the catalogue would refuse is reported
/// unreadable, not skipped without a word by the replay's insert.
#[tokio::test(flavor = "current_thread")]
async fn a_plan_record_with_a_bad_yenc_name_is_unreadable() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = vec![7u8; 1_000_000];
    rig.put(&signer, BUCKET, "two-articles", &body)
        .await
        .expect(200);
    let (extent, _) = plan_record(&rig, &bucket, "two-articles", &[None, Some("Not Valid")]).await;

    wipe(&rig);
    let (report, _) = replay(&rig, UnixMs(0), ReplayLimits::default()).await;
    assert_eq!(report.published, 1, "{report:?}");
    assert_eq!(report.article_plans, 0, "{report:?}");
    assert_eq!(report.unreadable, [format!("m/art/{}", extent.id.as_str())]);
    assert!(rig
        .bridge
        .catalog
        .articles(&extent.id)
        .await
        .unwrap()
        .is_empty());
}
