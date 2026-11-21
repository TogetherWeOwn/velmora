//! `GC_ORPHANS`: the collector of upload parts that nothing refers to.
//!
//! The rule is in `src/sql/gc.rs`. These tests hold it against a model
//! that never reads the catalogue's own idea of a reference: it learns
//! the blobs of a part from what the safety store gained while the part
//! was uploaded, and from then on follows the S3 calls. A part becomes
//! an orphan when it is uploaded again under its number, when its
//! upload is aborted, and when a completion leaves it out; the collector
//! must delete the blobs of orphans older than the grace period, and
//! nothing else, whatever ran in between. One thing holds an orphan
//! back: a recovery record a replay could still publish over its key.
//! The model knows those from the writes it made fail, and at the end
//! of every history the catalogue is lost and rebuilt from the records.
//! For a part whose upload the catalogue no longer knows, the collector
//! asks about the whole bucket once a day and keeps the answer. The
//! model reads the kept answer back, holds it against the writes it had
//! made fail when the answer was given, and expects the claims of that
//! day to go by it, also under a record stored since.
//!
//! Everything runs as production does: `GC_MODE=off`, a bucket that is
//! not disposable. One test turns both collectors on in a disposable
//! bucket.

mod service_support;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use futures_util::FutureExt;
use serde_json::{json, Value};
use service_support::*;
use velmora_bridge::config::{BridgeConfig, GcMode, Maintenance, ORPHAN_GRACE_MS};
use velmora_bridge::jobs::{ORPHAN_BATCH, ORPHAN_SCAN};
use velmora_bridge::replay::{ReplayCursor, ReplayLimits, ReplayReport};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::NEXT_DROP_SUPERSEDED_INDEXES;
use velmora_bridge::*;

const BUCKET: &str = "vault";
const HOUR: i64 = 60 * 60 * 1000;
const DAY: i64 = 24 * HOUR;
/// Past the rest between two passes of the scan, and past the time the
/// answer about the marks of a bucket is kept.
const REST: i64 = DAY + 1;
/// One extent up to 8 KiB and slices of 4 KiB: a part above 8 KiB is
/// several extents, the ones after the first in `upload_part_extents`.
const EXTENT: usize = 8 * 1024;
/// Keys that may carry a record that was never published.
const MARKS: &str = "SELECT COUNT(*) FROM key_floors WHERE unpublished <> 0";
/// What a lost catalogue loses, children first.
const TABLES: [&str; 15] = [
    "upload_part_extents",
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

struct T {
    rig: Rig,
    signer: Signer,
    /// The bucket the calls below go to.
    bucket: Cell<&'static str>,
}

async fn setup_with(tune: impl FnOnce(&mut BridgeConfig)) -> T {
    let mut cfg = config(Vec::new());
    cfg.gc_mode = GcMode::Off;
    cfg.gc_orphans = true;
    cfg.max_extent_bytes = EXTENT as u64;
    cfg.slice_bytes = EXTENT as u64 / 2;
    cfg.max_put_bytes = 64 * 1024;
    tune(&mut cfg);
    let rig = rig_with(NoNntp, cfg);
    let bucket = rig.bucket(BUCKET, false).await;
    let signer = rig.key(AKID, secret(), KeyStatus::Active).await;
    rig.grant(AKID, &bucket, Perm::Rw).await;
    T {
        rig,
        signer,
        bucket: Cell::new(BUCKET),
    }
}

async fn setup() -> T {
    setup_with(|_| ()).await
}

/// An open `gc` row, as the catalogue has it.
#[derive(Clone, Debug)]
struct Queued {
    id: i64,
    extent: String,
    action: String,
    done: bool,
}

impl T {
    fn catalog(&self) -> &TestCatalog {
        &self.rig.bridge.catalog
    }

    fn now(&self) -> UnixMs {
        self.rig.now()
    }

    fn cutoff(&self) -> UnixMs {
        self.now().plus_ms(-ORPHAN_GRACE_MS)
    }

    fn advance(&self, ms: i64) {
        self.rig.bridge.clock.advance_ms(ms);
    }

    /// The ciphertext blobs in the safety store.
    fn blobs(&self) -> BTreeSet<String> {
        self.rig
            .bridge
            .safety
            .keys()
            .into_iter()
            .filter(|k| k.starts_with("x/"))
            .collect()
    }

    fn sql(&self, sql: &str) {
        self.catalog()
            .sql
            .with_conn(|c| c.execute_batch(sql).unwrap());
    }

    fn count(&self, sql: &str) -> i64 {
        self.catalog()
            .sql
            .with_conn(|c| c.query_row(sql, [], |r| r.get(0)).unwrap())
    }

    fn queued(&self) -> Vec<Queued> {
        self.catalog().sql.with_conn(|c| {
            let mut stmt = c
                .prepare("SELECT id, extent_id, action, done_at IS NOT NULL FROM gc ORDER BY id")
                .unwrap();
            let rows = stmt
                .query_map([], |r| {
                    Ok(Queued {
                        id: r.get(0)?,
                        extent: r.get(1)?,
                        action: r.get(2)?,
                        done: r.get(3)?,
                    })
                })
                .unwrap();
            rows.map(|r| r.unwrap()).collect()
        })
    }

    async fn call(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Resp {
        self.rig
            .call(
                &self.signer,
                method,
                &path(self.bucket.get(), key),
                query,
                headers,
                body,
            )
            .await
    }

    async fn create(&self, key: &str) -> String {
        let r = self
            .call(Method::Post, key, &[("uploads", "")], &[], b"")
            .await;
        r.expect(200);
        r.values("UploadId").remove(0)
    }

    async fn part(&self, key: &str, id: &str, n: u16, body: &[u8]) -> String {
        let r = self
            .call(
                Method::Put,
                key,
                &[("partNumber", &n.to_string()), ("uploadId", id)],
                &[],
                body,
            )
            .await;
        r.expect(200);
        r.header("etag").unwrap().to_string()
    }

    async fn part_copy(&self, key: &str, id: &str, n: u16, from: &str) -> String {
        let source = format!("/{}/{from}", self.bucket.get());
        let r = self
            .call(
                Method::Put,
                key,
                &[("partNumber", &n.to_string()), ("uploadId", id)],
                &[("x-amz-copy-source", &source)],
                b"",
            )
            .await;
        r.expect(200);
        r.values("ETag").remove(0).replace("&quot;", "\"")
    }

    fn complete_req(&self, key: &str, id: &str, parts: &[(u16, &str)]) -> Req {
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (n, etag) in parts {
            xml.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        self.signer.sign(
            self.now(),
            Method::Post,
            &path(self.bucket.get(), key),
            &[("uploadId", id)],
            &[],
            xml.into_bytes(),
        )
    }

    async fn complete(&self, key: &str, id: &str, parts: &[(u16, &str)]) {
        let r = self.rig.send(self.complete_req(key, id, parts)).await;
        r.expect(200);
        assert!(r.values("Code").is_empty(), "{}", r.text());
    }

    async fn abort(&self, key: &str, id: &str) {
        self.call(Method::Delete, key, &[("uploadId", id)], &[], b"")
            .await
            .expect(204);
    }

    async fn put(&self, key: &str, body: &[u8]) {
        self.call(Method::Put, key, &[], &[], body)
            .await
            .expect(200);
    }

    async fn copy(&self, from: &str, to: &str) {
        let source = format!("/{}/{from}", self.bucket.get());
        self.call(Method::Put, to, &[], &[("x-amz-copy-source", &source)], b"")
            .await
            .expect(200);
    }

    async fn delete(&self, key: &str) {
        self.call(Method::Delete, key, &[], &[], b"")
            .await
            .expect(204);
    }

    async fn get(&self, key: &str) -> Vec<u8> {
        let r = self.call(Method::Get, key, &[], &[], b"").await;
        r.expect(200);
        assert!(r.stream_error.is_none(), "{:?}", r.stream_error);
        r.body
    }

    /// One cron run and the GC job it sent, if it sent one.
    async fn tick(&self) -> bool {
        self.rig.bridge.jobs.inner.take();
        let report = self.rig.bridge.dispatch().await.unwrap();
        let jobs: Vec<Job> = self
            .rig
            .bridge
            .jobs
            .inner
            .take()
            .into_iter()
            .map(|s| s.job)
            .filter(|j| matches!(j, Job::Gc { .. }))
            .collect();
        assert_eq!(report.gc_enqueued, !jobs.is_empty());
        assert!(jobs.len() <= 1);
        for job in &jobs {
            assert_eq!(self.rig.bridge.run_job(job).await, JobOutcome::Ack);
        }
        !jobs.is_empty()
    }

    /// Cron runs until the scan rests: the rest of a pass. Returns the
    /// number of GC jobs.
    async fn pass(&self) -> u32 {
        let mut jobs = 0;
        while self.tick().await {
            jobs += 1;
            assert!(jobs < 10_000, "the scan never rests");
        }
        jobs
    }

    /// The scan starts a pass at the next cron run, whatever rest it
    /// was in.
    fn wake(&self) {
        self.sql("DELETE FROM scan_cursors WHERE k = 'orphans'");
    }

    /// What the catalogue last found about the marks of the buckets:
    /// the rows it keeps for a day (`clean:<ms>` or `marked:<ms>`).
    fn verdicts(&self) -> Vec<String> {
        self.catalog().sql.with_conn(|c| {
            let mut stmt = c
                .prepare("SELECT v FROM scan_cursors WHERE k LIKE 'orphans:bucket:%' ORDER BY k")
                .unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
            rows.map(|r| r.unwrap()).collect()
        })
    }

    /// The tables of the catalogue, in the order they were made.
    fn tables(&self) -> Vec<String> {
        self.catalog().sql.with_conn(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name <> 'tx_guard' \
                       AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'at_%' ORDER BY rowid",
                )
                .unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
            rows.map(|r| r.unwrap()).collect()
        })
    }

    /// Keeps the catalogue as it is now under a name: a state that Time
    /// Travel can return to.
    fn bookmark(&self, name: &str) {
        for table in self.tables() {
            self.sql(&format!(
                "DROP TABLE IF EXISTS at_{name}_{table}; \
                 CREATE TABLE at_{name}_{table} AS SELECT * FROM {table};"
            ));
        }
    }

    /// Every table is as it was at the bookmark: what a Time Travel
    /// restore does. The tables that triggers keep come after the ones
    /// they follow, so they end as they were too.
    fn time_travel(&self, name: &str) {
        self.sql("PRAGMA foreign_keys = OFF;");
        for table in self.tables() {
            self.sql(&format!(
                "DELETE FROM {table}; INSERT INTO {table} SELECT * FROM at_{name}_{table};"
            ));
        }
        self.sql("PRAGMA foreign_keys = ON;");
    }

    /// The restore route, from the first record to the last, with the
    /// service in maintenance for it: the replay that follows a
    /// restore, on the catalogue as it is.
    async fn replay_in_place(&mut self) {
        self.replay_taking(0).await;
    }

    /// The same, with `took` milliseconds between its first request and
    /// the ones that follow.
    async fn replay_taking(&mut self, took: i64) {
        self.maintenance(Maintenance::Restore);
        let started = self.now();
        let mut body = json!({ "since_ms": 0 });
        loop {
            let mut req = Req {
                method: Method::Post,
                target: "/_admin/restore".to_string(),
                headers: Vec::new(),
                body: body.to_string().into_bytes(),
            };
            req.set_header("host", HOST);
            req.set_header("content-length", &req.body.len().to_string());
            let token = self.rig.bridge.cfg.admin_token.expose().to_string();
            req.set_header("authorization", &format!("Bearer {token}"));
            let r = self.rig.send(req).await;
            assert_eq!(r.status, 200, "{}", r.text());
            let report: Value = serde_json::from_slice(&r.body).unwrap();
            if report["next"].is_null() {
                break;
            }
            if self.now() == started {
                self.advance(took);
            }
            body = json!({ "cursor": report["next"] });
        }
        assert_eq!(self.now().0 - started.0, took);
        assert_eq!(
            self.count("SELECT finished_at - started_at FROM restore_state WHERE id = 1"),
            took
        );
        self.maintenance(Maintenance::Off);
    }

    fn maintenance(&mut self, mode: Maintenance) {
        Rc::get_mut(&mut self.rig.bridge).unwrap().cfg.maintenance = mode;
    }

    /// What the GC job does with one row, through the catalogue.
    async fn collect(&self, row: &GcRow, cutoff: UnixMs) -> bool {
        self.collect_all(std::slice::from_ref(row), cutoff).await[0]
    }

    /// What the GC job does with the rows of a window, through the
    /// catalogue: one claim for all of them, then the blobs it granted.
    async fn collect_all(&self, rows: &[GcRow], cutoff: UnixMs) -> Vec<bool> {
        let granted = claim_rows(self.catalog(), rows, self.now(), cutoff).await;
        assert_eq!(granted.len(), rows.len());
        for (row, _) in rows.iter().zip(&granted).filter(|(_, granted)| **granted) {
            self.rig
                .bridge
                .safety
                .delete(&row.extent_id.safety_key())
                .await
                .unwrap();
            self.catalog()
                .gc_orphan_done(row.id, self.now())
                .await
                .unwrap();
        }
        granted
    }

    /// The generation records in the safety store.
    fn records(&self) -> BTreeSet<String> {
        let keys = self.rig.bridge.safety.keys().into_iter();
        keys.filter(|k| k.starts_with("m/g_")).collect()
    }

    /// Runs one write whose record is stored, whose batch does not run
    /// and whose record cannot be removed afterwards: the request fails
    /// and the record stays.
    async fn lost(&self, req: Req) {
        let before = self.records();
        self.rig.bridge.safety.fail_record_deletes.set(1000);
        let sql = &self.catalog().sql;
        sql.fail_publish.set(Some(PublishFault::NotApplied));
        let r = self.rig.send(req).await;
        assert!(r.status >= 500, "{}: {}", r.status, r.text());
        assert!(sql.fail_publish.take().is_none(), "no publication ran");
        self.rig.bridge.safety.fail_record_deletes.set(0);
        assert_eq!(self.records().difference(&before).count(), 1);
    }

    async fn complete_lost(&self, key: &str, id: &str, parts: &[(u16, &str)]) {
        self.lost(self.complete_req(key, id, parts)).await;
    }

    async fn put_lost(&self, key: &str, body: &[u8]) {
        let target = path(self.bucket.get(), key);
        let req = self
            .signer
            .sign(self.now(), Method::Put, &target, &[], &[], body.to_vec());
        self.lost(req).await;
    }

    async fn status(&self, key: &str) -> u16 {
        self.call(Method::Get, key, &[], &[], b"").await.status
    }

    /// The catalogue is lost and rebuilt from the recovery records, to
    /// the end. Returns the report of the last call, which counts the
    /// live objects that cannot be read.
    async fn restore(&self) -> ReplayReport {
        for table in TABLES {
            self.sql(&format!("DELETE FROM {table};"));
        }
        let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
        let mut last = ReplayReport::default();
        let mut calls = 0;
        while let Some(at) = cursor {
            calls += 1;
            assert!(calls < 100_000, "the replay does not end");
            let limits = ReplayLimits::default();
            let mut step = self
                .rig
                .bridge
                .replay_step_within(at, limits)
                .await
                .unwrap();
            cursor = step.next.take();
            assert!(step.unpublishable.is_empty(), "{step:?}");
            assert!(step.unreadable.is_empty(), "{step:?}");
            last = step;
        }
        // Keys and grants are not in the records, and neither is a
        // bucket nothing was ever published in.
        let bucket = match self.catalog().bucket_by_name(BUCKET).await.unwrap() {
            Some(bucket) => bucket,
            None => self.rig.bucket(BUCKET, false).await,
        };
        self.rig.key(AKID, secret(), KeyStatus::Active).await;
        self.rig.grant(AKID, &bucket, Perm::Rw).await;
        last
    }
}

/// A claim that no error cuts short.
async fn claim_rows<C: Catalog>(
    catalog: &C,
    rows: &[GcRow],
    now: UnixMs,
    cutoff: UnixMs,
) -> Vec<bool> {
    let (granted, claimed) = catalog.gc_orphan_claim(rows, now, cutoff).await;
    claimed.unwrap();
    granted
}

fn gc_row(id: i64, extent: &str) -> GcRow {
    GcRow {
        id,
        extent_id: ExtentId::new(extent.to_string()),
        action: GcAction::DeleteSafety,
        due_at: UnixMs(0),
        done_at: None,
    }
}

fn blob_of(extent: &str) -> String {
    format!("x/{extent}")
}

/// Runs `then` in the middle of the next put to the safety store of a
/// key under `prefix`, before the blob is stored.
fn at_put_of(bridge: &Rc<TestBridge<NoNntp>>, prefix: &'static str, then: Rc<dyn Fn()>) {
    let again = Rc::clone(bridge);
    *bridge.safety.before_put.borrow_mut() = Some(Box::new(move |key: &str| {
        if key.starts_with(prefix) {
            then();
        } else {
            at_put_of(&again, prefix, then);
        }
    }));
}

// ---------------------------------------------------------------------------
// The switch
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn off_by_default_and_nothing_is_deleted_while_off() {
    assert!(!config(Vec::new()).gc_orphans);
    let t = setup_with(|cfg| cfg.gc_orphans = false).await;
    let id = t.create("k").await;
    t.part("k", &id, 1, &pattern(1, 900)).await;
    t.part("k", &id, 1, &pattern(2, 900)).await;
    t.abort("k", &id).await;
    let blobs = t.blobs();
    assert_eq!(blobs.len(), 2);
    t.advance(400 * DAY);
    // The cron run sends no job, and a job that arrives all the same
    // (sent before the switch went off) does nothing.
    assert!(!t.tick().await);
    let job = Job::Gc { v: 1 };
    assert_eq!(t.rig.bridge.run_job(&job).await, JobOutcome::Ack);
    assert_eq!(t.blobs(), blobs);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL"),
        0
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM scan_cursors WHERE k = 'orphans'"),
        0
    );
}

// ---------------------------------------------------------------------------
// The three ways a part is dropped, and the grace period
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_dropped_part_goes_at_the_grace_period_and_not_a_millisecond_before() {
    let t = setup().await;
    // Replaced: part 1 uploaded twice. Unlisted: part 2 is left out of
    // the completion. Aborted: the second upload.
    let a = t.create("a").await;
    t.part("a", &a, 1, &pattern(1, 3000)).await;
    let replaced = t.blobs();
    let kept = pattern(2, 20_000);
    let etag = t.part("a", &a, 1, &kept).await;
    let before = t.blobs();
    t.part("a", &a, 2, &pattern(3, 700)).await;
    let unlisted: BTreeSet<String> = t.blobs().difference(&before).cloned().collect();
    let before = t.blobs();
    let b = t.create("b").await;
    t.part("b", &b, 1, &pattern(4, 20_000)).await;
    t.part("b", &b, 2, &pattern(5, 10)).await;
    let aborted: BTreeSet<String> = t.blobs().difference(&before).cloned().collect();
    assert_eq!((replaced.len(), unlisted.len(), aborted.len()), (1, 1, 6));

    // The three drops, a day apart.
    let t0 = t.now();
    t.advance(DAY);
    t.complete("a", &a, &[(1, &etag)]).await;
    t.advance(DAY);
    t.abort("b", &b).await;
    let all = t.blobs();
    let gone = |sets: &[&BTreeSet<String>]| -> BTreeSet<String> {
        let mut left = all.clone();
        for set in sets {
            left = left.difference(set).cloned().collect();
        }
        left
    };

    // One millisecond short of the grace period of the first drop.
    t.rig.bridge.clock.set(t0.plus_ms(ORPHAN_GRACE_MS - 1));
    t.pass().await;
    assert_eq!(t.blobs(), all);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL"),
        0
    );

    // At it: the replaced part and nothing else. (A pass rests for a
    // day; the scan is woken here, to show the millisecond.)
    t.advance(1);
    t.wake();
    t.pass().await;
    assert_eq!(t.blobs(), gone(&[&replaced]));
    // A day later the unlisted part, another day later the aborted ones.
    t.rig
        .bridge
        .clock
        .set(t0.plus_ms(DAY + ORPHAN_GRACE_MS - 1));
    t.wake();
    t.pass().await;
    assert_eq!(t.blobs(), gone(&[&replaced]));
    t.advance(1);
    t.wake();
    t.pass().await;
    assert_eq!(t.blobs(), gone(&[&replaced, &unlisted]));
    t.rig
        .bridge
        .clock
        .set(t0.plus_ms(2 * DAY + ORPHAN_GRACE_MS));
    t.wake();
    t.pass().await;
    assert_eq!(t.blobs(), gone(&[&replaced, &unlisted, &aborted]));

    // The catalogue says exactly that, and the object reads back.
    assert_eq!(
        t.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'"),
        8
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL AND action = 'delete_safety'"),
        8
    );
    // The key of a collected part is not this collector's to shred.
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL AND action <> 'delete_safety'"),
        0
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM extents WHERE wrapped_file_key IS NULL"),
        0
    );
    assert!(t.get("a").await == kept);
}

/// The scan binds its place as integers, and the database takes only
/// those a JS number holds exactly (the fixture refuses the others as
/// D1 does). A first pass, a pass after a rest, and a cursor this code
/// did not write all start before every row, with a number it takes.
#[tokio::test(flavor = "current_thread")]
async fn a_pass_starts_at_a_number_the_database_takes() {
    let t = setup().await;
    let cursors = [
        None,
        Some(""),
        Some("at"),
        Some("at:1:2:3"),
        Some("at:x:1"),
        Some("rest:soon"),
        Some("at:-9223372036854775808:0"),
        Some("at:-9007199254740992:0"),
        Some("at:9007199254740992:0"),
        Some("at:0:9223372036854775807"),
        Some("rest:9223372036854775807"),
        Some("rest:-9007199254740992"),
        // A rest that is over.
        Some("rest:1"),
    ];
    for (i, cursor) in cursors.into_iter().enumerate() {
        let before = t.blobs();
        let upload = t.create("a").await;
        t.part("a", &upload, 1, &pattern(i as u8, 700)).await;
        let part: BTreeSet<String> = t.blobs().difference(&before).cloned().collect();
        assert_eq!(part.len(), 1);
        t.abort("a", &upload).await;
        t.advance(ORPHAN_GRACE_MS);
        t.sql("DELETE FROM scan_cursors WHERE k = 'orphans'");
        if let Some(v) = cursor {
            t.sql(&format!(
                "INSERT INTO scan_cursors(k, v) VALUES ('orphans', '{v}')"
            ));
        }
        t.pass().await;
        assert!(t.blobs().is_disjoint(&part), "cursor {cursor:?}");
        assert_eq!(
            t.count("SELECT COUNT(*) FROM gc WHERE action = 'delete_safety' AND done_at IS NULL"),
            0,
            "cursor {cursor:?}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_upload_in_progress_keeps_every_part_however_old() {
    // Production limits: three parts of 5 MiB and a tail.
    let t = setup_with(|cfg| {
        cfg.max_extent_bytes = 16 * MIB as u64;
        cfg.slice_bytes = 8 * MIB as u64;
        cfg.max_put_bytes = 16 * MIB as u64;
    })
    .await;
    let id = t.create("big").await;
    let bodies = [
        pattern(1, 5 * MIB),
        pattern(2, 5 * MIB + 9),
        pattern(3, 5 * MIB),
        pattern(4, 1234),
    ];
    let mut etags = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        etags.push(t.part("big", &id, i as u16 + 1, body).await);
    }
    // Part 2 is sent again with the same bytes (a client that retried):
    // the same ETag, another extent. The first copy is an orphan.
    let before = t.blobs();
    assert_eq!(t.part("big", &id, 2, &bodies[1]).await, etags[1]);
    let live: BTreeSet<String> = t.blobs().difference(&before).cloned().collect();
    assert_eq!(live.len(), 1);

    // A year passes with the upload open, and the collector runs.
    t.advance(365 * DAY);
    assert!(t.pass().await >= 1);
    let left = t.blobs();
    assert_eq!(left.len(), 4, "only the first copy of part 2 went");
    assert!(live.is_subset(&left));

    // The upload completes and reads back byte for byte.
    let listed: Vec<(u16, &str)> = etags
        .iter()
        .enumerate()
        .map(|(i, e)| (i as u16 + 1, e.as_str()))
        .collect();
    t.complete("big", &id, &listed).await;
    assert!(t.get("big").await == bodies.concat());
}

#[tokio::test(flavor = "current_thread")]
async fn deleted_and_replaced_objects_are_not_this_collectors() {
    let t = setup().await;
    // An object of two extents, a copy of it, an object made of one
    // upload part, and an overwrite: every extent was part of an object.
    t.put("one", &pattern(1, 12_000)).await;
    t.copy("one", "two").await;
    let id = t.create("three").await;
    let etag = t.part("three", &id, 1, &pattern(2, 5000)).await;
    t.complete("three", &id, &[(1, &etag)]).await;
    t.put("four", &pattern(3, 100)).await;
    t.put("four", &pattern(4, 100)).await;
    t.delete("one").await;
    t.delete("three").await;
    let blobs = t.blobs();
    // Rows are queued for the extents no object reads any more: those
    // of `three` and of the first `four`. (`one` is still read by its
    // copy.)
    assert!(t.count("SELECT COUNT(*) FROM gc WHERE action = 'delete_safety'") >= 2);

    t.advance(400 * DAY);
    t.pass().await;
    assert_eq!(t.blobs(), blobs);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL"),
        0
    );
    // Nor by a claim made for each of their rows.
    for q in t.queued() {
        assert!(!t.collect(&gc_row(q.id, &q.extent), t.cutoff()).await);
    }
    assert_eq!(t.blobs(), blobs);
    assert!(t.get("two").await == pattern(1, 12_000));
}

// ---------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------

/// A completion is under way (its parts were read and checked, its
/// recovery record is being written) when the collector runs a whole
/// pass, and claims are made for every extent of the upload against
/// the row of a real orphan. The completion then commits.
#[tokio::test(flavor = "current_thread")]
async fn a_completion_racing_the_collector_loses_nothing() {
    let t = setup().await;
    let id = t.create("k").await;
    t.part("k", &id, 1, &pattern(1, 2000)).await;
    let orphan = t.blobs();
    let body = pattern(2, 20_000);
    let etag = t.part("k", &id, 1, &body).await;
    let listed: Vec<String> = t
        .blobs()
        .difference(&orphan)
        .map(|k| k.trim_start_matches("x/").to_string())
        .collect();
    assert_eq!(listed.len(), 5);
    let orphan_row = t.queued().remove(0);
    assert_eq!(orphan_row.action, "delete_safety");
    // An aborted upload of another key, as old.
    let z = t.create("z").await;
    t.part("z", &z, 1, &pattern(3, 100)).await;
    t.abort("z", &z).await;
    assert_eq!(t.blobs().len(), 7);
    t.advance(40 * DAY);

    let fired = Rc::new(std::cell::Cell::new(false));
    let (bridge, seen, cutoff) = (Rc::clone(&t.rig.bridge), Rc::clone(&fired), t.cutoff());
    at_put_of(
        &t.rig.bridge,
        "m/",
        Rc::new(move || {
            for extent in &listed {
                let row = [gc_row(orphan_row.id, extent)];
                let claimed = claim_rows(&bridge.catalog, &row, bridge.clock.now(), cutoff)
                    .now_or_never()
                    .expect("the catalogue answers at once");
                assert_eq!(claimed, [false], "a listed part was claimed");
            }
            let job = Job::Gc { v: 1 };
            let outcome = bridge.run_job(&job).now_or_never();
            assert_eq!(outcome, Some(JobOutcome::Ack));
            seen.set(true);
        }),
    );
    t.complete("k", &id, &[(1, &etag)]).await;
    assert!(fired.get());
    // The pass inside the completion took the part of the other key and
    // nothing of this one: the completion's record was being stored,
    // and until it is published or gone it may be all that names the
    // part that was uploaded twice.
    assert_eq!(t.blobs().len(), 6);
    assert!(t.blobs().is_superset(&orphan));
    // Published: the next pass takes that part, and only it.
    t.advance(REST);
    t.pass().await;
    assert!(t.blobs().is_disjoint(&orphan));
    assert_eq!(t.blobs().len(), 5);
    assert!(t.get("k").await == body);
}

/// Point 5 on its own: nothing queues a row for a part of an open
/// upload, and a row that names one all the same is refused, for the
/// extent `upload_parts` names and for the further extents of a sliced
/// part alike.
#[tokio::test(flavor = "current_thread")]
async fn a_row_that_names_a_part_of_an_open_upload_is_refused() {
    let t = setup().await;
    let id = t.create("k").await;
    let body = pattern(1, 10_000);
    let etag = t.part("k", &id, 1, &body).await;
    let blobs = t.blobs();
    assert_eq!(blobs.len(), 3);
    assert_eq!(t.count("SELECT COUNT(*) FROM upload_part_extents"), 2);
    t.sql("INSERT INTO gc(extent_id, action, due_at) SELECT id, 'delete_safety', 0 FROM extents");
    t.advance(400 * DAY);
    for published in [false, true] {
        t.advance(REST);
        t.pass().await;
        for q in t.queued() {
            assert!(!t.collect(&gc_row(q.id, &q.extent), t.cutoff()).await);
        }
        assert_eq!(t.blobs(), blobs);
        assert_eq!(
            t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL"),
            0
        );
        assert_eq!(
            t.count("SELECT COUNT(*) FROM extents WHERE safety_state <> 'held'"),
            0
        );
        // And once they are an object's, for that reason (3 and 4).
        if !published {
            t.complete("k", &id, &[(1, &etag)]).await;
        }
    }
    assert!(t.get("k").await == body);
}

// ---------------------------------------------------------------------------
// Records that were never published (point 7)
// ---------------------------------------------------------------------------

/// A completion stored its record, its batch never ran and the record
/// could not be removed. The parts it names are then dropped, one by a
/// second upload of its number and the other by the abort.
#[tokio::test(flavor = "current_thread")]
async fn a_part_named_by_a_record_that_was_never_published_stays() {
    let t = setup().await;
    let second = t.rig.bucket("second", false).await;
    t.rig.grant(AKID, &second, Perm::Rw).await;
    let since = |before: &BTreeSet<String>| -> BTreeSet<String> {
        t.blobs().difference(before).cloned().collect()
    };

    let id = t.create("k").await;
    let one = t.part("k", &id, 1, &pattern(1, 10_000)).await;
    t.part("k", &id, 2, &pattern(2, 3000)).await;
    assert_eq!(t.blobs().len(), 4);
    t.complete_lost("k", &id, &[(1, &one)]).await;
    assert_eq!(t.count(MARKS), 1);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM uploads WHERE state = 'open'"),
        1
    );
    t.part("k", &id, 1, &pattern(3, 100)).await;
    t.abort("k", &id).await;
    let of_k = t.blobs();
    assert_eq!(of_k.len(), 5);

    // Dropped parts of another key: one uploaded twice, one aborted.
    let other = t.create("other").await;
    t.part("other", &other, 1, &pattern(4, 100)).await;
    let twice = since(&of_k);
    t.part("other", &other, 1, &pattern(5, 100)).await;
    t.abort("other", &other).await;
    // And the same under the key of that name in another bucket.
    t.bucket.set("second");
    let far = t.create("k").await;
    t.part("k", &far, 1, &pattern(6, 100)).await;
    t.part("k", &far, 1, &pattern(7, 10_000)).await;
    t.abort("k", &far).await;
    t.bucket.set(BUCKET);
    assert_eq!(t.blobs().len(), 5 + 2 + 4);

    // What stays: every part of `k`, and the part of `other` that was
    // uploaded twice. No row says which upload that one was of, and an
    // upload of its bucket was made on a key that carries the mark.
    let stays: BTreeSet<String> = of_k.union(&twice).cloned().collect();
    for days in [40, 400] {
        t.advance(days * DAY);
        t.pass().await;
        assert_eq!(t.blobs(), stays);
        for q in t.queued().iter().filter(|q| !q.done) {
            assert!(!t.collect(&gc_row(q.id, &q.extent), t.cutoff()).await);
        }
        assert_eq!(t.blobs(), stays);
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'"),
        5
    );

    // An acknowledged write of the key puts its record above the one
    // that lingers: a replay ends with this object, whatever became of
    // the parts.
    t.put("k", b"new").await;
    assert_eq!(t.count(MARKS), 0);
    t.advance(REST);
    t.pass().await;
    assert_eq!(t.blobs().len(), 1);
    let report = t.restore().await;
    assert_eq!(report.damaged_total, 0, "{report:?}");
    assert!(t.get("k").await == b"new");
}

/// What the rule is for. The catalogue is lost, and the replay
/// publishes the record of the completion that was never acknowledged:
/// its object reads, because its parts stayed.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_publishes_the_lingering_record_and_its_object_reads() {
    let t = setup().await;
    let body = pattern(1, 10_000);
    let id = t.create("k").await;
    let one = t.part("k", &id, 1, &body).await;
    t.part("k", &id, 2, &pattern(2, 3000)).await;
    t.complete_lost("k", &id, &[(1, &one)]).await;
    t.abort("k", &id).await;
    let blobs = t.blobs();
    t.advance(400 * DAY);
    t.pass().await;
    assert_eq!(t.blobs(), blobs);
    assert_eq!(t.status("k").await, 404);

    let report = t.restore().await;
    assert_eq!(report.damaged_total, 0, "{report:?}");
    assert!(t.get("k").await == body);
    // The part is an object's now, and stays; the one the completion
    // left out is no upload's any more, and stays too.
    t.advance(400 * DAY);
    t.pass().await;
    assert_eq!(t.blobs(), blobs);
    assert!(t.get("k").await == body);
}

/// A delete of the key covers the record as well: it writes a
/// tombstone though it finds nothing to delete.
#[tokio::test(flavor = "current_thread")]
async fn a_delete_of_the_key_covers_the_lingering_record() {
    let t = setup().await;
    let id = t.create("k").await;
    let one = t.part("k", &id, 1, &pattern(1, 3000)).await;
    t.complete_lost("k", &id, &[(1, &one)]).await;
    t.abort("k", &id).await;
    t.advance(40 * DAY);
    t.pass().await;
    assert_eq!(t.blobs().len(), 1);

    t.delete("k").await;
    assert_eq!(t.count(MARKS), 0);
    t.advance(REST);
    t.pass().await;
    assert!(t.blobs().is_empty());
    let report = t.restore().await;
    assert_eq!(report.damaged_total, 0, "{report:?}");
    assert_eq!(t.status("k").await, 404);
}

#[tokio::test(flavor = "current_thread")]
async fn a_claim_proves_its_row_again() {
    let t = setup().await;
    let id = t.create("k").await;
    t.part("k", &id, 1, &pattern(1, 100)).await;
    let first = t.blobs();
    t.part("k", &id, 1, &pattern(2, 100)).await;
    let live: Vec<String> = t.blobs().difference(&first).cloned().collect();
    let live = live[0].trim_start_matches("x/").to_string();
    let orphan = first
        .iter()
        .next()
        .unwrap()
        .trim_start_matches("x/")
        .to_string();
    let rows = t.queued();
    let (safety, shred) = (&rows[0], &rows[1]);
    assert_eq!(
        (safety.action.as_str(), shred.action.as_str()),
        ("delete_safety", "shred_key")
    );
    t.advance(ORPHAN_GRACE_MS);
    let cutoff = t.cutoff();
    let catalog = t.catalog();
    let claim = |id: i64, extent: &str, cutoff: UnixMs| {
        let (row, now) = (gc_row(id, extent), t.now());
        async move { claim_rows(catalog, &[row], now, cutoff).await[0] }
    };

    // Too young by a millisecond; the row of another action; a row that
    // does not exist; the live part under the orphan's row.
    assert!(!claim(safety.id, &orphan, cutoff.plus_ms(-1)).await);
    assert!(!claim(shred.id, &orphan, t.now()).await);
    assert!(!claim(9999, &orphan, cutoff).await);
    assert!(!claim(safety.id, &live, cutoff).await);
    // A part that was dropped a moment ago, under the row of the old one.
    let before = t.blobs();
    let other = t.create("y").await;
    t.part("y", &other, 1, &pattern(3, 100)).await;
    t.abort("y", &other).await;
    let young: Vec<String> = t.blobs().difference(&before).cloned().collect();
    let young = young[0].trim_start_matches("x/").to_string();
    assert!(!claim(safety.id, &young, cutoff).await);
    // While a replay is under way, and while a rollback waits for one.
    t.sql(
        "INSERT INTO restore_state(id, state, since_ms, started_at) VALUES (1, 'replaying', 0, 1)",
    );
    assert!(!claim(safety.id, &orphan, cutoff).await);
    t.sql("UPDATE restore_state SET state = 'complete', finished_at = 2");
    t.sql(
        "INSERT OR REPLACE INTO rollback_stamp(id, counter, catalogue_id, rolled_back_at) \
           VALUES (1, 0, 'main', 5)",
    );
    assert!(!claim(safety.id, &orphan, cutoff).await);
    t.sql("UPDATE rollback_stamp SET rolled_back_at = NULL");
    // An extent a replay inserted and has not published yet looks like
    // a part: staged, no generation. It has no open row.
    t.sql(&format!(
        "UPDATE gc SET done_at = 1 WHERE id = {}",
        safety.id
    ));
    assert!(!claim(safety.id, &orphan, cutoff).await);
    t.sql(&format!(
        "UPDATE gc SET done_at = NULL WHERE id = {}",
        safety.id
    ));
    // A reference of any generation, live or not.
    t.put("other", b"x").await;
    t.sql(&format!(
        "INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
         SELECT id, 7, '{orphan}', 0 FROM generations LIMIT 1"
    ));
    assert!(!claim(safety.id, &orphan, cutoff).await);
    t.sql("UPDATE generations SET state = 'deleted'");
    assert!(!claim(safety.id, &orphan, cutoff).await);
    t.sql(&format!(
        "DELETE FROM generation_extents WHERE extent_id = '{orphan}'"
    ));
    // An extent of a generation, also one that no reference row names
    // (the write path never leaves such a one).
    t.sql(&format!(
        "UPDATE extents SET state = 'committed', \
           generation_id = (SELECT id FROM generations LIMIT 1) WHERE id = '{orphan}'"
    ));
    t.sql(&format!(
        "DELETE FROM generation_extents WHERE extent_id = '{orphan}'"
    ));
    assert!(!claim(safety.id, &orphan, cutoff).await);
    t.sql(&format!(
        "UPDATE extents SET state = 'staged' WHERE id = '{orphan}'"
    ));
    assert!(!claim(safety.id, &orphan, cutoff).await);
    t.sql(&format!(
        "UPDATE extents SET state = 'committed', generation_id = NULL WHERE id = '{orphan}'"
    ));
    assert!(!claim(safety.id, &orphan, cutoff).await);
    t.sql(&format!(
        "UPDATE extents SET state = 'staged' WHERE id = '{orphan}'"
    ));
    // Nothing above wrote anything.
    assert_eq!(
        t.count("SELECT COUNT(*) FROM extents WHERE safety_state <> 'held'"),
        0
    );
    assert_eq!(t.blobs().len(), 4);

    // The claim itself, and again: the second one is granted too and
    // leaves the copy `deleted`. It bumps the eviction fence once more,
    // as every statement that sets `safety_state` must, and a bump only
    // refuses an eviction listing taken before it.
    assert!(claim(safety.id, &orphan, cutoff).await);
    let seq = t.count(&format!(
        "SELECT evict_seq FROM extents WHERE id = '{orphan}'"
    ));
    assert!(claim(safety.id, &orphan, cutoff).await);
    assert_eq!(
        t.count(&format!(
            "SELECT evict_seq FROM extents WHERE id = '{orphan}' AND safety_state = 'deleted' \
               AND hot_safety_bytes = 0"
        )),
        seq + 1
    );
}

/// The catalogue of a test, with a change that is committed right after
/// the first read through it: between the read that sorts the rows of
/// a claim and the batch that decides them.
struct ChangedAfterRead<'a> {
    inner: &'a FailSql,
    change: Cell<Option<String>>,
}

impl Sql for ChangedAfterRead<'_> {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let rows = self.inner.query(sql, params).await;
        if let Some(change) = self.change.take() {
            self.inner.with_conn(|c| c.execute_batch(&change).unwrap());
        }
        rows
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.inner.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        self.inner.batch(stmts).await
    }
}

/// The read that sorts the rows of a claim proves nothing: a claim
/// whose extent is not what that read said is refused by its batch.
/// Neither change happens in the service (an extent keeps its bucket,
/// and the part row of a dropped part stays), so both are made by hand:
/// what is shown is that the batch does not lean on the read.
#[tokio::test(flavor = "current_thread")]
async fn the_read_that_sorts_the_rows_of_a_claim_proves_nothing() {
    let t = setup().await;
    let other = t.rig.bucket("other", false).await;
    // A part of an aborted upload: its upload is known.
    let a = t.create("a").await;
    t.part("a", &a, 1, &pattern(1, 100)).await;
    t.abort("a", &a).await;
    // The older bytes of a part of an upload that goes on: not known.
    let b = t.create("b").await;
    t.part("b", &b, 1, &pattern(2, 100)).await;
    t.part("b", &b, 1, &pattern(3, 100)).await;
    t.advance(ORPHAN_GRACE_MS);
    let (now, cutoff) = (t.now(), t.cutoff());
    let rows = t
        .catalog()
        .gc_orphans(now, cutoff, ORPHAN_SCAN, ORPHAN_BATCH)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let known = |row: &GcRow| {
        t.count(&format!(
            "SELECT COUNT(*) FROM upload_parts WHERE extent_id = '{}'",
            row.extent_id.as_str()
        )) == 1
    };
    let (of_upload, in_bucket) = match (known(&rows[0]), known(&rows[1])) {
        (true, false) => (&rows[0], &rows[1]),
        (false, true) => (&rows[1], &rows[0]),
        both => panic!("{both:?}"),
    };
    let (sql, all, now) = (&t.catalog().sql, &rows, t.now());
    let claim = |change: String| async move {
        let catalog = SqlCatalog::new(ChangedAfterRead {
            inner: sql,
            change: Cell::new(Some(change)),
        });
        let granted = claim_rows(&catalog, all, now, cutoff).await;
        assert!(catalog.sql.change.take().is_none());
        granted
    };
    let held = || t.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'held'");
    assert_eq!(held(), 3);

    // The part row is gone after the read, and the key of the upload it
    // led to carries a mark: the claim that was sorted as one of a
    // known upload is refused. So is the other one, by the mark itself.
    t.sql("CREATE TABLE put_back AS SELECT * FROM upload_parts");
    let granted = claim(format!(
        "DELETE FROM upload_parts WHERE extent_id = '{of_upload}'; \
         INSERT INTO key_floors(bucket_id, key, floor_id, unpublished) \
         SELECT bucket_id, 'a', 'g_0', 1 FROM extents WHERE id = '{of_upload}'",
        of_upload = of_upload.extent_id.as_str()
    ))
    .await;
    assert_eq!(granted, vec![false, false]);
    assert_eq!(held(), 3);
    t.sql(
        "DELETE FROM key_floors; \
         INSERT INTO upload_parts SELECT * FROM put_back WHERE extent_id NOT IN \
           (SELECT extent_id FROM upload_parts); \
         DROP TABLE put_back",
    );

    // The extent is in another bucket after the read, one with a marked
    // key that an upload was begun on: the claim that was sorted into
    // the first bucket is refused, behind a guard that passed (the
    // first bucket is asked about again, and found clean).
    assert_eq!(t.verdicts().len(), 1);
    assert!(t.verdicts()[0].starts_with("marked:"));
    t.sql("DELETE FROM scan_cursors WHERE k LIKE 'orphans:bucket:%'");
    let granted = claim(format!(
        "UPDATE extents SET bucket_id = '{other}' WHERE id = '{in_bucket}'; \
         INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, \
                             initiated_at) \
         VALUES ('u_elsewhere', '{other}', 'c', '{{}}', '{{}}', 'aborted', 1); \
         INSERT INTO key_floors(bucket_id, key, floor_id, unpublished) \
         VALUES ('{other}', 'c', 'g_0', 1)",
        other = other.id.as_str(),
        in_bucket = in_bucket.extent_id.as_str()
    ))
    .await;
    let expect: Vec<bool> = rows.iter().map(|r| r.id == of_upload.id).collect();
    assert_eq!(granted, expect);
    assert_eq!(t.verdicts(), [format!("clean:{}", now.0)]);
    assert_eq!(held(), 2);
    assert_eq!(t.blobs().len(), 3);
}

/// The parts whose upload is not known wait while a key of their bucket
/// carries the mark. Those of another bucket, claimed in the same
/// call, do not wait with them, whichever bucket comes first.
#[tokio::test(flavor = "current_thread")]
async fn a_marked_key_holds_back_the_parts_of_its_own_bucket_only() {
    for marked in [BUCKET, "other"] {
        let t = setup().await;
        let other = t.rig.bucket("other", false).await;
        t.rig.grant(AKID, &other, Perm::Rw).await;
        // In each bucket, the older bytes of a part that was uploaded again.
        for bucket in [BUCKET, "other"] {
            t.bucket.set(bucket);
            let id = t.create("k").await;
            t.part("k", &id, 1, &pattern(1, 100)).await;
            t.part("k", &id, 1, &pattern(2, 100)).await;
        }
        t.sql(&format!(
            "INSERT INTO key_floors(bucket_id, key, floor_id, unpublished) \
             SELECT id, 'k', 'g_0', 1 FROM buckets WHERE name = '{marked}'"
        ));
        t.advance(ORPHAN_GRACE_MS);
        let (now, cutoff) = (t.now(), t.cutoff());
        let rows = t
            .catalog()
            .gc_orphans(now, cutoff, ORPHAN_SCAN, ORPHAN_BATCH)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        let granted = t.collect_all(&rows, cutoff).await;
        let expect: Vec<bool> = rows
            .iter()
            .map(|row| {
                t.count(&format!(
                    "SELECT COUNT(*) FROM extents e JOIN buckets b ON b.id = e.bucket_id \
                     WHERE e.id = '{}' AND b.name <> '{marked}'",
                    row.extent_id.as_str()
                )) == 1
            })
            .collect();
        assert_eq!(granted, expect, "{marked}");
        assert_eq!(granted.iter().filter(|g| **g).count(), 1);
    }
}
// ---------------------------------------------------------------------------
// The answer about the marks of a bucket, kept for a day
// ---------------------------------------------------------------------------

/// An upload on `key` with one part that was uploaded again: the older
/// bytes are a part whose upload the catalogue no longer knows. Returns
/// their blob.
async fn replaced_part(t: &T, key: &str, seed: u8) -> String {
    let before = t.blobs();
    let id = t.create(key).await;
    t.part(key, &id, 1, &pattern(seed, 100)).await;
    let old: Vec<String> = t.blobs().difference(&before).cloned().collect();
    t.part(key, &id, 1, &pattern(seed + 1, 100)).await;
    assert_eq!(old.len(), 1);
    old.into_iter().next().unwrap()
}

/// The open `delete_safety` row of a blob.
fn row_of(t: &T, blob: &str) -> GcRow {
    let queued = t.queued();
    let q = queued
        .iter()
        .find(|q| blob_of(&q.extent) == blob && q.action == "delete_safety")
        .unwrap();
    gc_row(q.id, &q.extent)
}

/// A bucket with a marked key is asked once, and for the rest of the
/// day its parts of unknown uploads are refused without a statement
/// that writes or reads the uploads. Settling the key frees them with
/// the next answer, a day after the last.
#[tokio::test(flavor = "current_thread")]
async fn a_bucket_with_a_marked_key_is_asked_once_a_day() {
    let t = setup().await;
    let old = replaced_part(&t, "k", 1).await;
    // A completion on another key of the bucket fails after it stored
    // its record.
    let other = t.create("other").await;
    let etag = t.part("other", &other, 1, &pattern(9, 100)).await;
    t.complete_lost("other", &other, &[(1, &etag)]).await;
    assert_eq!(t.count(MARKS), 1);
    t.advance(ORPHAN_GRACE_MS);
    let (asked, cutoff) = (t.now(), t.cutoff());
    let row = row_of(&t, &old);

    assert!(t.verdicts().is_empty());
    assert!(!t.collect(&row, cutoff).await);
    assert_eq!(t.verdicts(), [format!("marked:{}", asked.0)]);
    // Asked again the same day: no batch at all.
    let sql = &t.catalog().sql;
    sql.reset_write_steps();
    t.advance(DAY - 1);
    assert!(!t.collect(&row, t.cutoff()).await);
    assert_eq!(sql.write_steps(), 0);
    // The key is settled. The answer of the day stands.
    t.delete("other").await;
    assert_eq!(t.count(MARKS), 0);
    assert!(!t.collect(&row, t.cutoff()).await);
    assert_eq!(t.verdicts(), [format!("marked:{}", asked.0)]);
    // A day after it the bucket is asked again, and the part goes.
    t.advance(1);
    assert!(t.collect(&row, t.cutoff()).await);
    assert_eq!(t.verdicts(), [format!("clean:{}", t.now().0)]);
    assert!(!t.blobs().contains(&old));
}

/// A mark that is raised after the bucket was found clean holds back
/// nothing that day, and need not: its record was stored now, from a
/// part list that the part dropped 31 days ago is not in. The replay
/// makes an object of that record, and it reads.
#[tokio::test(flavor = "current_thread")]
async fn a_mark_raised_after_the_answer_names_no_part_dropped_before_it() {
    let t = setup().await;
    let first = replaced_part(&t, "k", 1).await;
    let second = replaced_part(&t, "k", 3).await;
    t.advance(ORPHAN_GRACE_MS);
    let cutoff = t.cutoff();
    assert!(t.collect(&row_of(&t, &first), cutoff).await);
    assert_eq!(t.verdicts(), [format!("clean:{}", t.now().0)]);

    // An hour later a completion on the same key fails after it stored
    // its record: the key is marked, and the record names the parts
    // that upload lists now.
    t.advance(HOUR);
    let id = t.create("k").await;
    let body = pattern(7, 300);
    let etag = t.part("k", &id, 1, &body).await;
    t.complete_lost("k", &id, &[(1, &etag)]).await;
    assert_eq!(t.count(MARKS), 1);
    // The other old part goes by the answer of an hour ago.
    assert!(t.collect(&row_of(&t, &second), cutoff).await);
    assert!(!t.blobs().contains(&second));
    // A part of the marked upload itself does not: its upload is known,
    // and that check is made by the claim.
    t.abort("k", &id).await;
    t.advance(ORPHAN_GRACE_MS - HOUR);
    for q in t.queued().iter().filter(|q| !q.done) {
        assert!(!t.collect(&gc_row(q.id, &q.extent), t.cutoff()).await);
    }

    let report = t.restore().await;
    assert_eq!(report.damaged_total, 0, "{report:?}");
    assert!(t.get("k").await == body);
}

/// The claim does not lean on what it read about the answer: the batch
/// proves that the row says clean, and young enough.
#[tokio::test(flavor = "current_thread")]
async fn the_answer_about_a_bucket_is_proved_by_the_batch_of_the_claim() {
    let t = setup().await;
    let blobs = [
        replaced_part(&t, "a", 1).await,
        replaced_part(&t, "b", 3).await,
        replaced_part(&t, "c", 5).await,
        replaced_part(&t, "d", 7).await,
    ];
    t.advance(ORPHAN_GRACE_MS);
    let (now, cutoff) = (t.now(), t.cutoff());
    // The bucket is found clean.
    assert!(t.collect(&row_of(&t, &blobs[0]), cutoff).await);
    let clean = format!("clean:{}", now.0);
    assert_eq!(t.verdicts(), std::slice::from_ref(&clean));

    // An answer from a time that is still to come is not used: the
    // bucket is asked about again.
    t.sql(&format!(
        "UPDATE scan_cursors SET v = 'marked:{}' WHERE k LIKE 'orphans:bucket:%'",
        now.0 + 1
    ));
    assert!(t.collect(&row_of(&t, &blobs[3]), cutoff).await);
    assert_eq!(t.verdicts(), std::slice::from_ref(&clean));

    // Between the read of a claim and its batch the row comes to say
    // something else: marked, clean a day ago, nothing a number can be
    // read from, a word that is not "clean" before a time, or it is
    // gone.
    let stale = now.0 - DAY;
    let changes = [
        format!(
            "UPDATE scan_cursors SET v = 'marked:{}' WHERE k LIKE 'orphans:bucket:%'",
            now.0
        ),
        format!("UPDATE scan_cursors SET v = 'clean:{stale}' WHERE k LIKE 'orphans:bucket:%'"),
        "UPDATE scan_cursors SET v = 'clean:' WHERE k LIKE 'orphans:bucket:%'".to_string(),
        format!(
            "UPDATE scan_cursors SET v = 'dirty:{}' WHERE k LIKE 'orphans:bucket:%'",
            now.0
        ),
        "UPDATE scan_cursors SET v = 'cleaner:9007199254740991' WHERE k LIKE 'orphans:bucket:%'"
            .to_string(),
        "DELETE FROM scan_cursors WHERE k LIKE 'orphans:bucket:%'".to_string(),
    ];
    let row = row_of(&t, &blobs[1]);
    for change in changes {
        t.sql(&format!(
            "UPDATE scan_cursors SET v = '{clean}' WHERE k LIKE 'orphans:bucket:%'"
        ));
        let catalog = SqlCatalog::new(ChangedAfterRead {
            inner: &t.catalog().sql,
            change: Cell::new(Some(change.clone())),
        });
        let granted = claim_rows(&catalog, std::slice::from_ref(&row), now, cutoff).await;
        assert!(catalog.sql.change.take().is_none());
        assert_eq!(granted, [false], "{change}");
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'"),
        2
    );
    // One millisecond younger than a day is young enough.
    t.sql(&format!(
        "INSERT INTO scan_cursors(k, v) SELECT 'orphans:bucket:' || id, 'clean:{}' FROM buckets \
         WHERE true ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        stale + 1
    ));
    assert!(t.collect(&row, cutoff).await);
    assert_eq!(t.verdicts(), [format!("clean:{}", stale + 1)]);
}

// ---------------------------------------------------------------------------
// After a replay
// ---------------------------------------------------------------------------

/// What `undone_restore` leaves.
struct Undone {
    /// The older bytes of part 1, dropped on the history that was kept.
    old: String,
    dropped: UnixMs,
    /// When the replay after the undoing ended.
    ended: UnixMs,
    /// The upload as the history that was left has it: its id, the
    /// ETag of its part 1, and that part's bytes (the older ones).
    id: String,
    etag: String,
    body: Vec<u8>,
}

/// The history that one history of the database cannot have:
///
/// - day 9: an upload is open, with two parts;
/// - day 10: part 1 is uploaded again, and its older bytes are dropped;
/// - day 10.5: the database is taken back to day 9, where the upload
///   lists the older bytes, and replayed. The service runs on;
/// - day 11.9: the state `left`;
/// - day 12: the restore is undone (the database is taken back to day
///   10.5 less a moment) and replayed, which takes the hour before day
///   12. The drop of day 10 is back.
///
/// Time Travel reaches `left` until day 41.9.
async fn undone_restore(t: &mut T) -> Undone {
    let before = t.blobs();
    let id = t.create("k").await;
    let (body, b) = (pattern(1, 700), pattern(2, 900));
    let etag = t.part("k", &id, 1, &body).await;
    let old: Vec<String> = t.blobs().difference(&before).cloned().collect();
    assert_eq!(old.len(), 1);
    t.part("k", &id, 2, &b).await;
    t.pass().await;
    t.bookmark("day9");

    t.advance(DAY);
    let dropped = t.now();
    t.part("k", &id, 1, &pattern(3, 700)).await;
    t.pass().await;
    t.advance(DAY / 2 - 1);
    t.bookmark("day10");
    t.advance(1);

    // Taken back to day 9. The cron run finds the catalogue behind its
    // stamp, and the replay opens it again.
    let behind = |t: &T| {
        t.rig.bridge.jobs.inner.take();
        let report = t.rig.bridge.dispatch().now_or_never().unwrap().unwrap();
        report.rolled_back
    };
    t.time_travel("day9");
    assert!(behind(t));
    t.replay_in_place().await;
    assert!(!behind(t));
    t.advance(DAY + 4 * DAY / 10);
    t.pass().await;
    t.bookmark("left");
    t.advance(DAY / 10 - HOUR);

    // The restore is undone. The replay takes an hour, and it is from
    // its end that the collector waits.
    t.time_travel("day10");
    assert!(behind(t));
    t.replay_taking(HOUR).await;
    assert!(!behind(t));
    let ended = UnixMs(t.count("SELECT finished_at FROM restore_state WHERE state = 'complete'"));
    assert_eq!(ended, t.now());
    assert_eq!(ended.0 - dropped.0, 2 * DAY);
    Undone {
        old: old.into_iter().next().unwrap(),
        dropped,
        ended,
        id,
        etag,
        body,
    }
}

/// After a replay the collector waits the grace period once more, to
/// the millisecond: a part dropped 31 days ago stays until the replay
/// ended 31 days ago as well.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_holds_the_collector_for_the_grace_period() {
    let mut t = setup().await;
    let u = undone_restore(&mut t).await;
    let row = row_of(&t, &u.old);
    let all = t.blobs();

    // The part was dropped 31 days ago, and more.
    for at in [
        u.dropped.plus_ms(ORPHAN_GRACE_MS),
        u.dropped.plus_ms(ORPHAN_GRACE_MS + DAY),
        u.ended.plus_ms(ORPHAN_GRACE_MS - 1),
    ] {
        t.rig.bridge.clock.set(at);
        t.wake();
        t.pass().await;
        assert_eq!(t.blobs(), all, "{at:?}");
        assert!(!t.collect(&row, t.cutoff()).await);
        // No answer about the bucket is asked for or kept meanwhile.
        assert!(t.verdicts().is_empty());
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'"),
        0
    );
    t.advance(1);
    t.wake();
    t.pass().await;
    let mut left = all.clone();
    assert!(left.remove(&u.old));
    assert_eq!(t.blobs(), left);
}

/// Why it waits. On the day the part has been dropped for 31 days, the
/// history that the undone restore left is 29 days old: the database is
/// taken back to it, the upload there lists the older bytes of part 1,
/// and it completes with them and reads back.
#[tokio::test(flavor = "current_thread")]
async fn a_history_left_by_an_undone_restore_still_reads_its_parts() {
    let mut t = setup().await;
    let u = undone_restore(&mut t).await;
    t.rig.bridge.clock.set(u.dropped.plus_ms(ORPHAN_GRACE_MS));
    t.wake();
    t.pass().await;
    assert!(t.blobs().contains(&u.old));

    t.time_travel("left");
    t.rig.bridge.jobs.inner.take();
    assert!(t.rig.bridge.dispatch().await.unwrap().rolled_back);
    t.replay_in_place().await;
    t.complete("k", &u.id, &[(1, &u.etag)]).await;
    assert!(t.get("k").await == u.body);
}

// ---------------------------------------------------------------------------
// A claim that an error cuts short
// ---------------------------------------------------------------------------

/// The catalogue of a test, with one batch that fails: the one after
/// `pass` batches that went through.
struct FailsABatch<'a> {
    inner: &'a FailSql,
    pass: Cell<Option<u32>>,
}

impl Sql for FailsABatch<'_> {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.inner.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.inner.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        match self.pass.get() {
            Some(0) => {
                self.pass.set(None);
                Err(BridgeError::Sql("database down".into()))
            }
            pass => {
                self.pass.set(pass.map(|n| n - 1));
                self.inner.batch(stmts).await
            }
        }
    }
}

/// The rows of a window are claimed in more than one batch. When one
/// fails, the claims of the others, before it and after it, are still
/// decided and answered as granted, with the error: the catalogue says
/// those copies are gone, so they must go now and not wait for a pass
/// that finds them again; and a group whose batch fails does not hold
/// up the groups after it.
#[tokio::test(flavor = "current_thread")]
async fn a_claim_that_an_error_cuts_short_keeps_what_it_granted() {
    // The batch that fails: the one of the known uploads (the first),
    // the one that asks about the bucket, then the one that claims
    // behind the answer. The rows: of an unknown upload, of a known.
    for (pass, expect) in [(0, [true, false]), (1, [false, true]), (2, [false, true])] {
        let t = setup().await;
        // A part of a known upload, and one of an unknown.
        let before = t.blobs();
        let id = t.create("a").await;
        t.part("a", &id, 1, &pattern(1, 100)).await;
        t.abort("a", &id).await;
        let known: Vec<String> = t.blobs().difference(&before).cloned().collect();
        let unknown = replaced_part(&t, "b", 3).await;
        t.advance(ORPHAN_GRACE_MS);
        let (now, cutoff) = (t.now(), t.cutoff());
        let rows = [row_of(&t, &unknown), row_of(&t, &known[0])];

        let catalog = SqlCatalog::new(FailsABatch {
            inner: &t.catalog().sql,
            pass: Cell::new(Some(pass)),
        });
        let (granted, claimed) = catalog.gc_orphan_claim(&rows, now, cutoff).await;
        assert!(matches!(claimed, Err(BridgeError::Sql(_))), "{claimed:?}");
        assert!(catalog.sql.pass.get().is_none());
        assert_eq!(granted, expect, "batch {pass}");
        assert_eq!(
            t.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'"),
            1
        );
        // The row that was not decided goes with a later claim.
        assert_eq!(t.collect_all(&rows, cutoff).await, [true, true]);
    }
}

/// A bucket that cannot be asked about does not hold up the next one:
/// whichever of two comes first, the parts of the other are decided.
#[tokio::test(flavor = "current_thread")]
async fn a_bucket_whose_batch_fails_does_not_hold_up_the_next() {
    for down in [BUCKET, "other"] {
        let t = setup().await;
        let other = t.rig.bucket("other", false).await;
        t.rig.grant(AKID, &other, Perm::Rw).await;
        let mut blobs = Vec::new();
        for bucket in [BUCKET, "other"] {
            t.bucket.set(bucket);
            blobs.push(replaced_part(&t, "k", 1).await);
        }
        t.advance(ORPHAN_GRACE_MS);
        let (now, cutoff) = (t.now(), t.cutoff());
        let rows = [row_of(&t, &blobs[0]), row_of(&t, &blobs[1])];
        t.sql(&format!(
            "CREATE TRIGGER down BEFORE INSERT ON scan_cursors \
             WHEN NEW.k = 'orphans:bucket:' || (SELECT id FROM buckets WHERE name = '{down}') \
             BEGIN SELECT RAISE(ABORT, 'database down'); END;"
        ));
        let (granted, claimed) = t.catalog().gc_orphan_claim(&rows, now, cutoff).await;
        assert!(matches!(claimed, Err(BridgeError::Sql(_))), "{claimed:?}");
        assert_eq!(granted, [down != BUCKET, down == BUCKET], "{down}");
        assert_eq!(t.verdicts(), [format!("clean:{}", now.0)]);
    }
}

/// The same through the job. It deletes the copies that its claim was
/// granted, closes their rows, and asks to run again.
#[tokio::test(flavor = "current_thread")]
async fn a_job_whose_claim_an_error_cuts_short_deletes_what_was_granted() {
    let t = setup().await;
    let before = t.blobs();
    let id = t.create("a").await;
    t.part("a", &id, 1, &pattern(1, 100)).await;
    t.abort("a", &id).await;
    let known: BTreeSet<String> = t.blobs().difference(&before).cloned().collect();
    let unknown = replaced_part(&t, "b", 3).await;
    // The upload on `b` is open, and keeps the bytes of now.
    let kept: BTreeSet<String> = t
        .blobs()
        .into_iter()
        .filter(|blob| !known.contains(blob))
        .collect();
    t.advance(ORPHAN_GRACE_MS);
    // The database fails the batch that keeps the answer about a bucket.
    t.sql(
        "CREATE TRIGGER down BEFORE INSERT ON scan_cursors WHEN NEW.k LIKE 'orphans:bucket:%' \
         BEGIN SELECT RAISE(ABORT, 'database down'); END;",
    );

    t.rig.bridge.jobs.inner.take();
    assert!(t.rig.bridge.dispatch().await.unwrap().gc_enqueued);
    let job = t.rig.bridge.jobs.inner.take().remove(0).job;
    assert!(matches!(
        t.rig.bridge.run_job(&job).await,
        JobOutcome::Retry { .. }
    ));
    // The part of the aborted upload went, and its row is closed.
    assert_eq!(t.blobs(), kept);
    assert!(kept.contains(&unknown));
    assert_eq!(
        t.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'"),
        1
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL AND action = 'delete_safety'"),
        1
    );

    // The other goes with the next pass.
    t.sql("DROP TRIGGER down;");
    t.advance(REST);
    t.pass().await;
    let mut left = kept.clone();
    assert!(left.remove(&unknown));
    assert_eq!(t.blobs(), left);
}

/// A row is closed only where the catalogue says the copy is gone. A
/// database taken back, between the claim of a job and its last step,
/// to before that claim says `held`: the row stays open there, and the
/// next claim sets the state and the usage right and closes it.
#[tokio::test(flavor = "current_thread")]
async fn a_row_is_closed_only_where_the_catalogue_says_the_copy_is_gone() {
    let t = setup().await;
    let blob = replaced_part(&t, "a", 1).await;
    t.advance(ORPHAN_GRACE_MS);
    let row = row_of(&t, &blob);
    let (now, cutoff) = (t.now(), t.cutoff());
    let state = || {
        t.catalog().sql.with_conn(|c| {
            c.query_row(
                "SELECT e.safety_state, g.done_at IS NULL FROM gc g \
                   JOIN extents e ON e.id = g.extent_id WHERE g.id = ?1",
                [row.id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
            )
            .unwrap()
        })
    };
    let usage = || t.count("SELECT unreleased_bytes FROM usage_global WHERE id = 1");
    let pinned = usage();
    t.bookmark("before");

    let rows = std::slice::from_ref(&row);
    assert_eq!(claim_rows(t.catalog(), rows, now, cutoff).await, [true]);
    assert_eq!(state(), ("deleted".to_string(), true));
    let after = usage();
    assert!(after < pinned, "{after} {pinned}");
    t.time_travel("before");
    let safety = &t.rig.bridge.safety;
    safety.delete(&row.extent_id.safety_key()).await.unwrap();
    t.catalog().gc_orphan_done(row.id, now).await.unwrap();
    assert!(!t.blobs().contains(&blob));
    assert_eq!(state(), ("held".to_string(), true));
    assert_eq!(usage(), pinned);

    assert!(t.collect(&row, cutoff).await);
    assert_eq!(state(), ("deleted".to_string(), false));
    assert_eq!(usage(), after);
}

#[tokio::test(flavor = "current_thread")]
async fn a_blob_delete_that_fails_is_repeated_by_the_next_pass() {
    let t = setup().await;
    let id = t.create("k").await;
    t.part("k", &id, 1, &pattern(1, 100)).await;
    t.part("k", &id, 2, &pattern(2, 100)).await;
    t.abort("k", &id).await;
    let blobs = t.blobs();
    let stuck = blobs.iter().next().unwrap().clone();
    t.advance(ORPHAN_GRACE_MS);
    *t.rig.bridge.safety.fail_delete.borrow_mut() = Some(stuck.clone());

    // The job fails and asks to run again; the other part went.
    t.rig.bridge.jobs.inner.take();
    assert!(t.rig.bridge.dispatch().await.unwrap().gc_enqueued);
    let job = t.rig.bridge.jobs.inner.take().remove(0).job;
    assert!(matches!(
        t.rig.bridge.run_job(&job).await,
        JobOutcome::Retry { .. }
    ));
    assert_eq!(t.blobs(), BTreeSet::from([stuck.clone()]));
    // The catalogue already says the copy is gone; its row is open.
    assert_eq!(
        t.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'"),
        2
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NULL AND action = 'delete_safety'"),
        1
    );
    // The job that runs again reads the rest of the pass: nothing.
    assert_eq!(t.rig.bridge.run_job(&job).await, JobOutcome::Ack);
    assert_eq!(t.blobs().len(), 1);

    *t.rig.bridge.safety.fail_delete.borrow_mut() = None;
    t.advance(REST);
    assert_eq!(t.pass().await, 1);
    assert!(t.blobs().is_empty());
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NULL AND action = 'delete_safety'"),
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_is_deleted_on_a_catalogue_behind_its_stamp() {
    let t = setup().await;
    let id = t.create("k").await;
    t.part("k", &id, 1, &pattern(1, 100)).await;
    t.abort("k", &id).await;
    // The stamp was raised (a cron run does), and the catalogue is then
    // taken back to before that.
    t.rig.bridge.dispatch().await.unwrap();
    assert!(t.count("SELECT counter FROM rollback_stamp") >= 1);
    t.sql("UPDATE rollback_stamp SET counter = counter - 1");
    let blobs = t.blobs();
    t.advance(ORPHAN_GRACE_MS + DAY);

    // The job on its own: it compares the stamp before it reads a row.
    let job = Job::Gc { v: 1 };
    assert_eq!(t.rig.bridge.run_job(&job).await, JobOutcome::Ack);
    assert_eq!(t.blobs(), blobs);
    assert_eq!(
        t.count("SELECT COUNT(*) FROM scan_cursors WHERE k = 'orphans'"),
        0
    );
    // The cron run finds the rollback and records it; from then on the
    // claim refuses as well.
    t.rig.bridge.jobs.inner.take();
    assert!(t.rig.bridge.dispatch().await.unwrap().rolled_back);
    for q in t.queued() {
        assert!(!t.collect(&gc_row(q.id, &q.extent), t.cutoff()).await);
    }
    assert_eq!(t.blobs(), blobs);
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

/// Many open rows that are not parts (the rows of deleted objects, all
/// due at the same millisecond) in front of, between and behind the
/// orphans: every window reads its share and no more, and a pass finds
/// every orphan.
#[tokio::test(flavor = "current_thread")]
async fn a_pass_steps_over_the_rows_of_deleted_objects_a_window_at_a_time() {
    let t = setup().await;
    t.put("object", &pattern(9, 10)).await;
    let committed: String = t.catalog().sql.with_conn(|c| {
        c.query_row(
            "SELECT id FROM extents WHERE state = 'committed'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    });
    let filler = |n: usize, due: i64| {
        let mut sql = String::from("INSERT INTO gc(extent_id, action, due_at) VALUES ");
        for i in 0..n {
            let action = [
                "delete_cache",
                "delete_safety",
                "shred_key",
                "drop_articles_meta",
            ][i % 4];
            sql.push_str(&format!(
                "{}('{committed}', '{action}', {due})",
                if i == 0 { "" } else { "," }
            ));
        }
        sql
    };
    let t = &t;
    let orphan = |key: &'static str, seed: u8| async move {
        let id = t.create(key).await;
        t.part(key, &id, 1, &pattern(seed, 50)).await;
        t.abort(key, &id).await;
    };
    let t0 = t.now().0;
    let scan = ORPHAN_SCAN as usize;
    t.sql(&filler(2 * scan + 30, t0));
    orphan("a", 1).await;
    t.sql(&filler(scan - 3, t0));
    t.advance(5);
    orphan("b", 2).await;
    orphan("c", 3).await;
    t.sql(&filler(scan, t0 + 5));
    t.advance(ORPHAN_GRACE_MS);
    assert_eq!(t.blobs().len(), 4);
    let open = t.count("SELECT COUNT(*) FROM gc") as usize;

    // One window a cron run, each at most ORPHAN_SCAN rows further.
    let mut jobs = 0;
    let mut at = (i64::MIN, 0);
    while t.tick().await {
        jobs += 1;
        let cursor: String = t.catalog().sql.with_conn(|c| {
            c.query_row("SELECT v FROM scan_cursors WHERE k = 'orphans'", [], |r| {
                r.get(0)
            })
            .unwrap()
        });
        let fields: Vec<&str> = cursor.split(':').collect();
        if fields[0] == "rest" {
            continue;
        }
        let next = (
            fields[1].parse::<i64>().unwrap(),
            fields[2].parse::<i64>().unwrap(),
        );
        assert!(next > at, "{cursor}");
        let stepped = t.count(&format!(
            "SELECT COUNT(*) FROM gc WHERE (due_at, id) > ({}, {}) AND (due_at, id) <= ({}, {})",
            at.0, at.1, next.0, next.1
        )) as usize;
        assert!(stepped <= scan, "{stepped}");
        at = next;
    }
    // Rows closed by the pass leave the count of open ones behind it,
    // so the windows are as many as the open rows need, or one more.
    let windows = open.div_ceil(scan) as u32;
    assert!(
        jobs == windows || jobs == windows + 1,
        "{jobs} jobs for {open} rows"
    );
    assert_eq!(
        t.blobs().len(),
        1,
        "the three orphans went, the object stayed"
    );
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL"),
        3
    );
    // The scan rests: no job until the day is over.
    assert!(!t.tick().await);
    t.advance(DAY - 1);
    assert!(!t.tick().await);
    t.advance(1);
    assert!(t.tick().await);
}

/// A job takes at most `ORPHAN_BATCH` parts, and the next one goes on
/// behind the last it took.
#[tokio::test(flavor = "current_thread")]
async fn a_job_takes_a_bounded_number_of_parts() {
    let t = setup().await;
    let batch = ORPHAN_BATCH as usize;
    let parts = 2 * batch + 20;
    let mut ids = Vec::new();
    for u in 0..parts.div_ceil(50) {
        let key = format!("k{u}");
        let id = t.create(&key).await;
        for n in 0..50.min(parts - u * 50) {
            t.part(&key, &id, n as u16 + 1, &[u as u8, n as u8]).await;
        }
        ids.push((key, id));
    }
    for (key, id) in &ids {
        t.abort(key, id).await;
    }
    assert_eq!(t.blobs().len(), parts);
    t.advance(ORPHAN_GRACE_MS);
    for left in [parts - batch, parts - 2 * batch, 0] {
        assert!(t.tick().await);
        assert_eq!(t.blobs().len(), left);
    }
    t.pass().await;
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NULL AND action = 'delete_safety'"),
        0
    );
}

/// `GC_MODE=disposable` and `GC_ORPHANS=on` together, in a disposable
/// bucket, where a dropped part has a row that both collectors take.
/// Whichever gets to a row first, and wherever the other one comes in,
/// the copy goes once, the row is closed once, and a row that is closed
/// is not claimed again.
#[tokio::test(flavor = "current_thread")]
async fn both_collectors_on_one_row() {
    let t = setup_with(|cfg| cfg.gc_mode = GcMode::Disposable).await;
    let scratch = t.rig.bucket("scratch", true).await;
    t.rig.grant(AKID, &scratch, Perm::Rw).await;
    t.bucket.set("scratch");
    let id = t.create("k").await;
    for n in 1..=4 {
        t.part("k", &id, n, &[n as u8]).await;
    }
    t.abort("k", &id).await;
    assert_eq!(t.blobs().len(), 4);
    t.advance(ORPHAN_GRACE_MS);
    let (now, cutoff) = (t.now(), t.cutoff());
    let rows: Vec<GcRow> = t
        .queued()
        .iter()
        .filter(|q| q.action == "delete_safety")
        .map(|q| gc_row(q.id, &q.extent))
        .collect();
    assert_eq!(rows.len(), 4);
    let catalog = t.catalog();
    let claim = |row: &GcRow| {
        let (row, now) = (row.clone(), t.now());
        async move { claim_rows(catalog, &[row], now, cutoff).await[0] }
    };
    let begins = |row: &GcRow| {
        let row = row.clone();
        async move {
            let step = catalog.gc_begin(&row, now).await.unwrap();
            let blob = row.extent_id.safety_key();
            matches!(step, GcStep::DeleteBlob { store: BlobStoreKind::Safety, key } if key == blob)
        }
    };
    let state = |row: &GcRow| -> (String, i64) {
        catalog.sql.with_conn(|c| {
            c.query_row(
                "SELECT e.safety_state, (SELECT done_at IS NOT NULL FROM gc WHERE id = ?2) \
                   FROM extents e WHERE e.id = ?1",
                rusqlite::params![row.extent_id.as_str(), row.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        })
    };

    // 0: this collector claimed, and its job ended before the delete.
    // The other one takes the row from there.
    assert!(claim(&rows[0]).await);
    assert_eq!(state(&rows[0]), ("deleted".to_string(), 0));
    assert!(begins(&rows[0]).await);
    // 1: the other one was told to delete, and this one claims before
    // it did; then both finish, this one first.
    assert!(begins(&rows[1]).await);
    assert!(claim(&rows[1]).await);
    catalog.gc_orphan_done(rows[1].id, now).await.unwrap();
    catalog.gc_done(rows[1].id, now).await.unwrap();
    assert_eq!(state(&rows[1]), ("deleted".to_string(), 1));
    assert!(!claim(&rows[1]).await);
    assert!(!begins(&rows[1]).await);
    // 2: the same, and the other one finishes first.
    assert!(begins(&rows[2]).await);
    assert!(claim(&rows[2]).await);
    catalog.gc_done(rows[2].id, now).await.unwrap();
    catalog.gc_orphan_done(rows[2].id, now).await.unwrap();
    assert_eq!(state(&rows[2]), ("deleted".to_string(), 1));
    assert!(!claim(&rows[2]).await);
    // No blob was deleted yet. The jobs delete those of 0 and 3; the
    // rows of 1 and 2 were closed above by hand, without a delete, and
    // a closed row is nobody's any more.
    assert_eq!(t.blobs().len(), 4);
    t.pass().await;
    t.advance(REST);
    t.pass().await;
    assert_eq!(
        t.blobs(),
        [&rows[1], &rows[2]]
            .map(|r| r.extent_id.safety_key())
            .into_iter()
            .collect()
    );
    for row in &rows {
        assert_eq!(state(row), ("deleted".to_string(), 1));
        assert!(!claim(row).await);
    }
    assert_eq!(
        t.count("SELECT COUNT(*) FROM gc WHERE done_at IS NULL AND action = 'delete_safety'"),
        0
    );
}

// ---------------------------------------------------------------------------
// Rows read and written
// ---------------------------------------------------------------------------

/// The parts whose upload is not known (here: each uploaded twice) need
/// the one statement that reads every upload of the catalogue. It runs
/// once a day for a bucket, however many such parts and windows there
/// are: with a thousand more uploads in the catalogue, the first claim
/// of a day costs a few steps per upload more, and the claims of the
/// rest of that day cost what they cost without them.
#[tokio::test(flavor = "current_thread")]
async fn the_uploads_of_a_bucket_are_read_once_a_day() {
    const PARTS: u16 = 40;
    const UPLOADS: u64 = 1000;
    // When the windows are claimed, from the first: the same
    // millisecond, the last one of that day, the first of the next.
    const AT: [i64; 4] = [0, 0, DAY - 1, DAY];
    let mut cost = Vec::new();
    for uploads in [0, UPLOADS] {
        let t = setup().await;
        let id = t.create("k").await;
        for n in 1..=PARTS {
            t.part("k", &id, n, &[1, n as u8]).await;
            t.part("k", &id, n, &[2, n as u8]).await;
        }
        // Uploads of other keys, long over.
        t.sql(&format!(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < {uploads}) \
             INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, \
                                 initiated_at) \
             SELECT printf('u_%032x', i), (SELECT id FROM buckets WHERE name = '{BUCKET}'), \
                    printf('old/%d', i), '{{}}', '{{}}', 'aborted', 1 FROM n WHERE {uploads} > 0"
        ));
        t.advance(ORPHAN_GRACE_MS);
        let start = t.now();
        let rows = t
            .catalog()
            .gc_orphans(start, t.cutoff(), ORPHAN_SCAN, ORPHAN_BATCH)
            .await
            .unwrap();
        assert_eq!(rows.len(), usize::from(PARTS));
        let sql = &t.catalog().sql;
        let mut steps = Vec::new();
        for (window, at) in rows.chunks(rows.len() / AT.len()).zip(AT) {
            t.rig.bridge.clock.set(start.plus_ms(at));
            sql.reset_read_stats();
            sql.reset_write_steps();
            let granted = claim_rows(t.catalog(), window, t.now(), t.cutoff()).await;
            assert_eq!(granted, vec![true; window.len()]);
            // One read sorts the rows.
            assert_eq!(sql.read_stats().queries, 1);
            steps.push(sql.write_steps());
        }
        assert_eq!(steps.len(), AT.len());
        // The answer of the first day, then the one of the second.
        assert_eq!(t.verdicts(), [format!("clean:{}", start.0 + DAY)]);
        cost.push(steps);
    }
    let (few, many) = (&cost[0], &cost[1]);
    println!(
        "steps of four claims of {} parts each, the last a day after the first: {few:?} with 1 \
         upload, {many:?} with {UPLOADS} more",
        usize::from(PARTS) / AT.len()
    );
    let more: Vec<u64> = many.iter().zip(few).map(|(many, few)| many - few).collect();
    for asked in [more[0], more[3]] {
        assert!((1..=30).contains(&(asked / UPLOADS)), "{few:?} {many:?}");
    }
    // What it must not cost: a read of the uploads for every window.
    assert_eq!(more[1..3], [0, 0], "{few:?} {many:?}");
}

/// What D1 bills for one collected part, on the schema of today and on
/// the one after the superseded indexes are dropped: three rows. The
/// extent row, the usage counter its trigger moves, and the `gc` row.
/// The partial indexes the two rows leave cost nothing (an index entry
/// removed is not billed).
#[tokio::test(flavor = "current_thread")]
async fn rows_written_per_collected_part() {
    for next_schema in [false, true] {
        let t = setup().await;
        if next_schema {
            t.sql(NEXT_DROP_SUPERSEDED_INDEXES);
        }
        let parts = 40;
        let id = t.create("k").await;
        for n in 0..parts {
            t.part("k", &id, n + 1, &[n as u8]).await;
        }
        t.abort("k", &id).await;
        t.advance(ORPHAN_GRACE_MS);
        // The job on its own, without the cron run that sent it.
        t.rig.bridge.jobs.inner.take();
        assert!(t.rig.bridge.dispatch().await.unwrap().gc_enqueued);
        t.rig.bridge.jobs.inner.take();
        let sql = &t.catalog().sql;
        sql.meter_writes().unwrap();
        let job = Job::Gc { v: 1 };
        assert_eq!(t.rig.bridge.run_job(&job).await, JobOutcome::Ack);
        assert!(t.blobs().is_empty());
        let writes = sql.writes();
        let by = |needle: &str| -> u64 {
            let found: Vec<u64> = writes
                .by_statement
                .iter()
                .filter(|(text, _)| text.contains(needle))
                .map(|(_, tally)| tally.billed())
                .collect();
            assert_eq!(found.len(), 1, "{needle}: {:#?}", writes.by_statement);
            found[0]
        };
        let parts = u64::from(parts);
        assert_eq!(by("UPDATE extents SET safety_state = 'deleted'"), 2 * parts);
        assert_eq!(by("UPDATE gc SET done_at"), parts);
        // And one for the job: where the scan is.
        assert_eq!(by("INSERT INTO scan_cursors"), 1);
        assert_eq!(
            writes.billed(),
            3 * parts + 1,
            "next schema {next_schema}: {:#?}",
            writes.by_statement
        );
        println!(
            "rows written (next schema: {next_schema}): {} for {parts} parts and one job",
            writes.billed()
        );
    }
}

// ---------------------------------------------------------------------------
// Random histories
// ---------------------------------------------------------------------------

/// splitmix64: the histories are the same on every run.
struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) % sides
    }

    fn pick<'a, V>(&mut self, of: &'a [V]) -> &'a V {
        &of[self.roll(of.len() as u64) as usize]
    }

    /// A body of one extent, or (one time in four) of several.
    fn body(&mut self) -> Vec<u8> {
        let len = if self.roll(4) == 0 {
            EXTENT + 1 + self.roll(12_000) as usize
        } else {
            1 + self.roll(2000) as usize
        };
        pattern(self.roll(250) as u8, len)
    }
}

struct Part {
    etag: String,
    body: Vec<u8>,
    blobs: BTreeSet<String>,
    /// The blob of its first extent.
    first: String,
}

struct Upload {
    key: &'static str,
    id: String,
    parts: BTreeMap<u16, Part>,
}

/// The blob of a dropped part.
#[derive(Clone, Copy)]
struct Orphan {
    dropped: i64,
    /// The key of its upload.
    key: &'static str,
    /// The first extent of a part that an abort or a completion
    /// dropped: the one the catalogue can still tell the upload of.
    known: bool,
}

/// What the S3 calls of a history add up to.
#[derive(Default)]
struct Model {
    open: Vec<Upload>,
    objects: BTreeMap<&'static str, Vec<u8>>,
    /// Keys an upload was ever begun on.
    uploaded: BTreeSet<&'static str>,
    /// Keys a write failed on after it stored its record, with no
    /// write or delete acknowledged since: the keys the catalogue marks.
    marked: BTreeSet<&'static str>,
    /// Of those, the ones whose newest record is such a one, and the
    /// object a replay makes of it. A PutObject mints its first id by
    /// its own clock: its record can sort under one the key already has.
    lingering: BTreeMap<&'static str, Vec<u8>>,
    /// The newest id a record of the key was stored under.
    top: BTreeMap<&'static str, String>,
    /// The names of the records seen so far.
    records: BTreeSet<String>,
    /// Every ciphertext blob that was ever stored.
    stored: BTreeSet<String>,
    /// The blobs of dropped parts.
    orphans: BTreeMap<String, Orphan>,
    /// The blobs the collector was right to delete.
    collected: BTreeSet<String>,
    /// Blobs taken by a claim made after later S3 calls.
    raced: usize,
    /// Claims that had to be refused, and were.
    refused: usize,
    /// Of those, the ones for an orphan old enough that a lingering
    /// record held back.
    held: usize,
    /// What the collector was last told about the marks of the bucket,
    /// and when: (the time, no key of an upload was marked).
    answer: Option<(i64, bool)>,
    /// Old enough parts of unknown uploads that an answer of the day
    /// let go under a mark raised since, and ones that it held back
    /// after the last mark was gone.
    let_go_by_answer: usize,
    held_by_answer: usize,
}

/// Keys of uploads, and one that only ever sees whole objects.
const KEYS: [&str; 4] = ["k0", "k1", "k2", "k3"];
const EVERY_KEY: [&str; 5] = ["k0", "k1", "k2", "k3", "plain"];

impl Model {
    /// The blobs the store gained since the last call, and the first of
    /// them that was sent to it.
    fn gained(&mut self, t: &T) -> (BTreeSet<String>, Option<String>) {
        let new: BTreeSet<String> = t.blobs().difference(&self.stored).cloned().collect();
        self.stored.extend(new.iter().cloned());
        let puts = t.rig.bridge.safety.puts.borrow();
        let first = puts
            .iter()
            .map(|(key, _)| key)
            .find(|key| new.contains(*key));
        (new.clone(), first.cloned())
    }

    /// `again` = dropped by a second upload of its number.
    fn drop_part(&mut self, part: Part, key: &'static str, again: bool, now: UnixMs) {
        for blob in part.blobs {
            let orphan = Orphan {
                dropped: now.0,
                key,
                known: !again && blob == part.first,
            };
            assert!(self.orphans.insert(blob, orphan).is_none());
        }
    }

    /// The id of the record the last call stored, a generation's or a
    /// tombstone: one at most.
    fn stored_record(&mut self, t: &T) -> Option<String> {
        let mut new = Vec::new();
        for name in t.rig.bridge.safety.keys() {
            let id = name.strip_prefix("m/del/").or(name.strip_prefix("m/"));
            let Some(id) = id.filter(|id| id.starts_with("g_")) else {
                continue;
            };
            if self.records.insert(name.clone()) {
                new.push(id.to_string());
            }
        }
        assert!(new.len() <= 1, "{new:?}");
        new.pop()
    }

    /// A write or a delete of the key was acknowledged: its record is
    /// above every record of the key. Only a delete that found nothing,
    /// on a key that is not marked, stores none.
    fn acknowledged(&mut self, t: &T, key: &'static str) {
        match self.stored_record(t) {
            Some(id) => {
                let under = self.top.insert(key, id.clone());
                assert!(under.is_none_or(|under| under < id), "{key}: {id}");
            }
            None => assert!(!self.marked.contains(key), "{key}"),
        }
        self.marked.remove(key);
        self.lingering.remove(key);
    }

    /// A write of the key failed and left its record.
    fn lost(&mut self, t: &T, key: &'static str, body: Vec<u8>) {
        let id = self.stored_record(t).unwrap();
        self.marked.insert(key);
        if self.top.get(key).is_none_or(|top| *top < id) {
            self.top.insert(key, id);
            self.lingering.insert(key, body);
        }
    }

    /// No key that an upload was ever begun on is marked.
    fn clean(&self) -> bool {
        !self.marked.iter().any(|key| self.uploaded.contains(key))
    }

    /// Point 7 of the rule by the marks of now, in the model's words.
    fn free_now(&self, orphan: &Orphan) -> bool {
        if orphan.known {
            !self.marked.contains(orphan.key)
        } else {
            self.clean()
        }
    }

    /// The answer about the bucket that the catalogue keeps, after a
    /// claim at the time of now. It changes only when the last one is a
    /// day old, and then it is what the marks of now say.
    #[track_caller]
    fn asked(&mut self, t: &T) {
        let now = t.now().0;
        let have = match &t.verdicts()[..] {
            [] => None,
            [one] => {
                let (word, at) = one.split_once(':').unwrap();
                assert!(matches!(word, "clean" | "marked"), "{one}");
                Some((at.parse::<i64>().unwrap(), word == "clean"))
            }
            more => panic!("{more:?}"),
        };
        if have != self.answer {
            let last = self.answer.map(|(at, _)| at);
            assert!(last.is_none_or(|at| at <= now - DAY), "{last:?} {have:?}");
            assert_eq!(have, Some((now, self.clean())));
            self.answer = have;
        }
    }

    /// Point 7 of the rule for an old enough part that a claim at the
    /// time of now named, after that claim. A part of a known upload
    /// goes by the mark of its key. One of an unknown upload goes by
    /// the answer about the bucket, which by then is a day old at most.
    #[track_caller]
    fn free(&mut self, orphan: &Orphan, now: UnixMs) -> bool {
        if orphan.known {
            return !self.marked.contains(orphan.key);
        }
        let (at, clean) = self.answer.expect("nothing asked about the bucket");
        assert!(
            now.0 - DAY < at && at <= now.0,
            "an answer of {at} at {now:?}"
        );
        match (clean, self.clean()) {
            (true, false) => self.let_go_by_answer += 1,
            (false, true) => self.held_by_answer += 1,
            _ => {}
        }
        clean
    }

    /// The orphans old enough at `cutoff` that are still there.
    fn ripe(&self, cutoff: UnixMs) -> BTreeSet<String> {
        self.orphans
            .iter()
            .filter(|(blob, o)| o.dropped <= cutoff.0 && !self.collected.contains(*blob))
            .map(|(blob, _)| blob.clone())
            .collect()
    }

    /// The ones of them that no mark of now holds back.
    fn due_now(&self, cutoff: UnixMs) -> BTreeSet<String> {
        let mut ripe = self.ripe(cutoff);
        ripe.retain(|blob| self.free_now(&self.orphans[blob]));
        ripe
    }

    /// The store holds every blob ever stored but the collected ones.
    #[track_caller]
    fn check_blobs(&self, t: &T, what: &str) {
        let expected: BTreeSet<String> = self.stored.difference(&self.collected).cloned().collect();
        let have = t.blobs();
        let lost: Vec<_> = expected.difference(&have).collect();
        let kept: Vec<_> = have.difference(&expected).collect();
        assert!(
            lost.is_empty() && kept.is_empty(),
            "{what}: lost {lost:?}, extra {kept:?}"
        );
    }

    fn new_part(&mut self, t: &T, etag: String, body: Vec<u8>) -> Part {
        let (blobs, first) = self.gained(t);
        let extents = if body.len() <= EXTENT {
            1
        } else {
            body.len().div_ceil(EXTENT / 2)
        };
        assert_eq!(blobs.len(), extents);
        Part {
            etag,
            body,
            blobs,
            first: first.unwrap(),
        }
    }

    /// One S3 call.
    async fn write(&mut self, t: &T, dice: &mut Dice) -> &'static str {
        let now = t.now();
        match dice.roll(82) {
            0..=9 if self.open.len() < 6 => {
                let key = *dice.pick(&KEYS);
                let id = t.create(key).await;
                self.uploaded.insert(key);
                self.open.push(Upload {
                    key,
                    id,
                    parts: BTreeMap::new(),
                });
                "create"
            }
            10..=39 if !self.open.is_empty() => {
                let u = dice.roll(self.open.len() as u64) as usize;
                let n = 1 + dice.roll(3) as u16;
                // One time in five the bytes it already has: a retry.
                let body = match self.open[u].parts.get(&n) {
                    Some(have) if dice.roll(5) == 0 => have.body.clone(),
                    _ => dice.body(),
                };
                let key = self.open[u].key;
                let etag = t.part(key, &self.open[u].id, n, &body).await;
                let part = self.new_part(t, etag, body);
                if let Some(old) = self.open[u].parts.insert(n, part) {
                    self.drop_part(old, key, true, now);
                }
                "part"
            }
            40..=44 if !self.open.is_empty() && !self.objects.is_empty() => {
                let u = dice.roll(self.open.len() as u64) as usize;
                let n = 1 + dice.roll(3) as u16;
                let sources: Vec<&'static str> = self.objects.keys().copied().collect();
                let from = *dice.pick(&sources);
                let body = self.objects[from].clone();
                if body.len() > EXTENT {
                    return "skip";
                }
                let key = self.open[u].key;
                let etag = t.part_copy(key, &self.open[u].id, n, from).await;
                // A part made by a copy is stored again, never shared.
                let part = self.new_part(t, etag, body);
                if let Some(old) = self.open[u].parts.insert(n, part) {
                    self.drop_part(old, key, true, now);
                }
                "part copy"
            }
            45..=50 if !self.open.is_empty() => {
                let u = dice.roll(self.open.len() as u64) as usize;
                let up = self.open.remove(u);
                t.abort(up.key, &up.id).await;
                for (_, part) in up.parts {
                    self.drop_part(part, up.key, false, now);
                }
                "abort"
            }
            51..=58 => {
                let Some(u) = self.with_parts(dice) else {
                    return "skip";
                };
                self.complete(t, u, dice).await;
                "complete"
            }
            59..=63 => {
                let key = *dice.pick(&EVERY_KEY);
                let body = dice.body();
                t.put(key, &body).await;
                self.gained(t);
                self.objects.insert(key, body);
                self.acknowledged(t, key);
                "put"
            }
            64..=67 if !self.objects.is_empty() => {
                let sources: Vec<&'static str> = self.objects.keys().copied().collect();
                let (from, to) = (*dice.pick(&sources), *dice.pick(&EVERY_KEY));
                if from == to {
                    return "skip";
                }
                t.copy(from, to).await;
                // A server-side copy stores nothing: it reads the
                // extents of its source.
                assert!(self.gained(t).0.is_empty());
                let body = self.objects[from].clone();
                self.objects.insert(to, body);
                self.acknowledged(t, to);
                "copy"
            }
            // A delete, also of a key that has no object.
            68..=73 => {
                let key = *dice.pick(&EVERY_KEY);
                t.delete(key).await;
                self.objects.remove(key);
                self.acknowledged(t, key);
                "delete"
            }
            // A completion whose record is stored and stays, and whose
            // batch never runs. The upload is as it was.
            74..=78 => {
                let Some(u) = self.with_parts(dice) else {
                    return "skip";
                };
                let up = &self.open[u];
                let numbers: Vec<u16> = up.parts.keys().copied().collect();
                let listed = &up.parts[dice.pick(&numbers)];
                let n = *up
                    .parts
                    .iter()
                    .find(|(_, p)| p.etag == listed.etag)
                    .unwrap()
                    .0;
                t.complete_lost(up.key, &up.id, &[(n, &listed.etag)]).await;
                let (key, body) = (up.key, listed.body.clone());
                assert!(self.gained(t).0.is_empty());
                self.lost(t, key, body);
                "lost complete"
            }
            // The same of a PutObject.
            79..=81 => {
                let key = *dice.pick(&EVERY_KEY);
                let body = pattern(dice.roll(250) as u8, 1 + dice.roll(2000) as usize);
                t.put_lost(key, &body).await;
                // Its blob stays: the record names it.
                assert_eq!(self.gained(t).0.len(), 1);
                self.lost(t, key, body);
                "lost put"
            }
            _ => "skip",
        }
    }

    /// An open upload that has a part.
    fn with_parts(&self, dice: &mut Dice) -> Option<usize> {
        let with_parts: Vec<usize> = (0..self.open.len())
            .filter(|u| !self.open[*u].parts.is_empty())
            .collect();
        (!with_parts.is_empty()).then(|| *dice.pick(&with_parts))
    }

    /// Completes the upload `u` with one of its parts; the others are
    /// left out of the list.
    async fn complete(&mut self, t: &T, u: usize, dice: &mut Dice) {
        let now = t.now();
        let mut up = self.open.remove(u);
        let numbers: Vec<u16> = up.parts.keys().copied().collect();
        let n = *dice.pick(&numbers);
        let listed = up.parts.remove(&n).unwrap();
        t.complete(up.key, &up.id, &[(n, &listed.etag)]).await;
        assert!(self.gained(t).0.is_empty());
        self.objects.insert(up.key, listed.body);
        self.acknowledged(t, up.key);
        for (_, part) in up.parts {
            self.drop_part(part, up.key, false, now);
        }
    }

    /// The collector, one of four ways.
    async fn collector(&mut self, t: &T, dice: &mut Dice) -> &'static str {
        match dice.roll(4) {
            // Whole passes of the job, as the cron runs them.
            0 => {
                self.passes(t, "pass").await;
                "pass"
            }
            // Whole passes through the catalogue, in small windows.
            1 => {
                let (scan, limit) = (1 + dice.roll(9) as u32, 1 + dice.roll(4) as u32);
                for whole in [false, true] {
                    t.advance(REST);
                    let (now, cutoff) = (t.now(), t.cutoff());
                    let mut windows = 0;
                    while t.catalog().gc_orphans_due(now).await.unwrap() {
                        let rows = t
                            .catalog()
                            .gc_orphans(now, cutoff, scan, limit)
                            .await
                            .unwrap();
                        assert!(rows.len() <= limit as usize);
                        for row in &rows {
                            self.take(t, row, cutoff, "window").await;
                        }
                        windows += 1;
                        assert!(windows < 100_000);
                    }
                    self.passed(t, whole, "windows");
                }
                "windows"
            }
            // A window is read, S3 calls run, and only then are its
            // rows claimed: what a job does that was slow. Half of the
            // time its first row is claimed before the calls, so the
            // bucket may be asked about before them and the answer
            // used after.
            2 => {
                let (now, cutoff) = (t.now(), t.cutoff());
                let mut rows = t
                    .catalog()
                    .gc_orphans(now, cutoff, ORPHAN_SCAN, 5)
                    .await
                    .unwrap();
                if dice.roll(2) == 0 && !rows.is_empty() {
                    let first = rows.remove(0);
                    self.take(t, &first, cutoff, "window").await;
                }
                for _ in 0..1 + dice.roll(4) {
                    self.write(t, dice).await;
                }
                for row in &rows {
                    self.raced += usize::from(self.take(t, row, cutoff, "stale window").await);
                }
                "stale window"
            }
            // A claim for every row there is, and for extents under
            // rows that are not theirs.
            _ => {
                let (now, cutoff) = (t.now(), t.cutoff());
                let (ripe, due) = (self.ripe(cutoff), self.due_now(cutoff));
                let queued = t.queued();
                // First the extents under rows that are not theirs,
                // while those rows are open.
                let left: Vec<String> = t.blobs().into_iter().collect();
                let open_due = queued.iter().filter(|q| {
                    !q.done && q.action == "delete_safety" && due.contains(&blob_of(&q.extent))
                });
                // (the row, the row it was made of, whether it is crossed)
                let mut asked: Vec<(GcRow, &Queued, bool)> = Vec::new();
                for row in open_due.take(3) {
                    for _ in 0..6 {
                        let extent = dice.pick(&left).trim_start_matches("x/");
                        if extent != row.extent {
                            asked.push((gc_row(row.id, extent), row, true));
                        }
                    }
                }
                asked.extend(queued.iter().map(|q| (gc_row(q.id, &q.extent), q, false)));
                // One call for each row, or one for all of them as the
                // job makes it: the answers must be the same.
                let answers = if dice.roll(2) == 0 {
                    let rows: Vec<GcRow> = asked.iter().map(|(row, ..)| row.clone()).collect();
                    t.collect_all(&rows, cutoff).await
                } else {
                    let mut answers = Vec::new();
                    for (row, ..) in &asked {
                        answers.push(t.collect(row, cutoff).await);
                    }
                    answers
                };
                self.asked(t);
                for ((_, q, crossed), did) in asked.iter().zip(answers) {
                    if *crossed {
                        assert!(!did, "an extent went under the row of another: {q:?}");
                        self.refused += 1;
                        continue;
                    }
                    let blob = blob_of(&q.extent);
                    let open = !q.done && q.action == "delete_safety";
                    let old_enough = open && ripe.contains(&blob);
                    let free = old_enough && {
                        let orphan = self.orphans[&blob];
                        self.free(&orphan, now)
                    };
                    assert_eq!(did, free, "{q:?}");
                    if did {
                        self.collected.insert(blob);
                    } else {
                        self.refused += 1;
                        self.held += usize::from(open && ripe.contains(&blob));
                    }
                }
                "claims"
            }
        }
    }

    /// A row the scan returned: it is a ripe orphan. Its claim goes
    /// through whatever ran since, unless a record lingers over it by
    /// now, or did when the bucket was last asked about. Returns
    /// whether it went through.
    async fn take(&mut self, t: &T, row: &GcRow, cutoff: UnixMs, what: &str) -> bool {
        let blob = row.extent_id.safety_key();
        let orphan = self.orphans.get(&blob).copied();
        let dropped = orphan.map(|o| o.dropped);
        assert!(
            dropped.is_some_and(|at| at <= cutoff.0),
            "{what}: the scan returned {blob}, dropped at {dropped:?}, cutoff {cutoff:?}"
        );
        assert_eq!(row.due_at.0, dropped.unwrap());
        let did = t.collect(row, cutoff).await;
        self.asked(t);
        let free = self.free(&orphan.unwrap(), t.now());
        assert_eq!(did, free, "{what}: {blob}");
        if free {
            self.collected.insert(blob);
        } else {
            self.refused += 1;
            self.held += 1;
        }
        free
    }

    /// Two passes of the job, as the cron runs them, a rest apart. The
    /// first is the rest of the pass that the windows read before it
    /// left off; the second is a whole one.
    async fn passes(&mut self, t: &T, what: &str) {
        for whole in [false, true] {
            t.advance(REST);
            t.pass().await;
            self.passed(t, whole, what);
        }
    }

    /// After a pass at the time of now. Whatever went was an orphan
    /// that was due; after a whole pass every orphan that was due went.
    fn passed(&mut self, t: &T, whole: bool, what: &str) {
        let (now, cutoff) = (t.now(), t.cutoff());
        self.asked(t);
        let have = t.blobs();
        for blob in self.ripe(cutoff) {
            if !whole && have.contains(&blob) {
                continue;
            }
            let orphan = self.orphans[&blob];
            if self.free(&orphan, now) {
                self.collected.insert(blob);
            }
        }
        self.check_blobs(t, what);
    }

    /// The catalogue's own account matches: the extents it calls
    /// deleted are the collected ones, and their rows are closed.
    fn check_catalogue(&self, t: &T) {
        let deleted: BTreeSet<String> = t.catalog().sql.with_conn(|c| {
            let mut stmt = c
                .prepare("SELECT id FROM extents WHERE safety_state = 'deleted'")
                .unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
            rows.map(|r| blob_of(&r.unwrap())).collect()
        });
        assert_eq!(deleted, self.collected);
        let closed: BTreeSet<String> = t
            .queued()
            .into_iter()
            .filter(|q| q.done)
            .map(|q| {
                assert_eq!(q.action, "delete_safety");
                blob_of(&q.extent)
            })
            .collect();
        assert_eq!(closed, self.collected);
    }

    /// Every key reads as the model has it.
    async fn check_objects(&self, t: &T, what: &str) {
        for key in EVERY_KEY {
            match self.objects.get(key) {
                Some(body) => assert!(&t.get(key).await == body, "{what}: {key}"),
                None => assert_eq!(t.status(key).await, 404, "{what}: {key}"),
            }
        }
    }
}

/// What a history came to.
#[derive(Default)]
struct Tally {
    /// Blobs stored, and the ones of dropped parts among them.
    stored: usize,
    orphans: usize,
    /// Collected before the end of the history.
    early: usize,
    raced: usize,
    refused: usize,
    held: usize,
    /// Blobs of dropped parts that a lingering record kept to the end,
    /// and the objects the replay made of lingering records.
    kept: usize,
    revived: usize,
    let_go_by_answer: usize,
    held_by_answer: usize,
}

/// One history.
async fn history(seed: u64, steps: u32) -> Tally {
    let t = setup().await;
    let mut dice = Dice(seed);
    let mut m = Model::default();
    for step in 0..steps {
        let what = match dice.roll(100) {
            0..=71 => m.write(&t, &mut dice).await,
            72..=83 => {
                let ms = *dice.pick(&[1, 1000, HOUR, DAY, 9 * DAY, 16 * DAY, ORPHAN_GRACE_MS]);
                t.advance(ms);
                "time"
            }
            _ => m.collector(&t, &mut dice).await,
        };
        m.check_blobs(&t, &format!("seed {seed} step {step} ({what})"));
    }
    m.check_catalogue(&t);
    let early = m.collected.len();

    // Every object reads back, and every upload still open completes
    // and reads back, whatever was collected around them.
    m.check_objects(&t, &format!("seed {seed}")).await;
    while let Some(u) = (0..m.open.len()).find(|u| !m.open[*u].parts.is_empty()) {
        let key = m.open[u].key;
        m.complete(&t, u, &mut dice).await;
        assert!(
            t.get(key).await == m.objects[key],
            "seed {seed}: {key} completed"
        );
    }
    for up in std::mem::take(&mut m.open) {
        t.abort(up.key, &up.id).await;
    }
    // In the end every dropped part goes but the ones a lingering
    // record holds back, and nothing else ever does.
    let end = |m: &mut Model, what: &str| {
        t.advance(ORPHAN_GRACE_MS);
        let what = format!("seed {seed} {what}");
        let passes = m.passes(&t, &what);
        passes.now_or_never().expect("nothing waits in a pass");
        m.check_catalogue(&t);
    };
    end(&mut m, "end");
    let kept = m.orphans.len() - m.collected.len();
    let left = m
        .orphans
        .iter()
        .filter(|(blob, _)| !m.collected.contains(*blob));
    assert_eq!(left.filter(|(_, o)| !m.free_now(o)).count(), kept);
    // Half of the histories go on: the keys are written or deleted,
    // and then every dropped part goes.
    if seed.is_multiple_of(2) {
        for key in m.marked.iter().copied().collect::<Vec<_>>() {
            if dice.roll(2) == 0 {
                t.delete(key).await;
                m.objects.remove(key);
            } else {
                let body = dice.body();
                t.put(key, &body).await;
                m.gained(&t);
                m.objects.insert(key, body);
            }
            m.acknowledged(&t, key);
        }
        end(&mut m, "covered");
        assert_eq!(m.collected, m.orphans.keys().cloned().collect());
    }
    m.check_objects(&t, &format!("seed {seed} at the end"))
        .await;
    for q in t.queued() {
        assert!(!t.collect(&gc_row(q.id, &q.extent), t.now()).await);
    }

    // The catalogue is lost. The replay publishes every record: the
    // lingering ones become objects, and every object reads, the
    // collector having taken nothing a record on top of its key names.
    let revived = m.lingering.len();
    let report = t.restore().await;
    assert_eq!(report.damaged_total, 0, "seed {seed}: {report:?}");
    m.objects.append(&mut m.lingering);
    m.check_objects(&t, &format!("seed {seed} after the replay"))
        .await;
    // And nothing goes after it.
    t.advance(ORPHAN_GRACE_MS);
    for _ in 0..2 {
        t.advance(REST);
        t.pass().await;
    }
    m.check_blobs(&t, &format!("seed {seed} after the replay"));
    m.check_objects(&t, &format!("seed {seed} long after the replay"))
        .await;
    Tally {
        stored: m.stored.len(),
        orphans: m.orphans.len(),
        early,
        raced: m.raced,
        refused: m.refused,
        held: m.held,
        kept,
        revived,
        let_go_by_answer: m.let_go_by_answer,
        held_by_answer: m.held_by_answer,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn random_histories_delete_exactly_the_dropped_parts() {
    let mut sum = Tally::default();
    for seed in 0..60 {
        let one = history(seed, 150).await;
        sum.stored += one.stored;
        sum.orphans += one.orphans;
        sum.early += one.early;
        sum.raced += one.raced;
        sum.refused += one.refused;
        sum.held += one.held;
        sum.kept += one.kept;
        sum.revived += one.revived;
        sum.let_go_by_answer += one.let_go_by_answer;
        sum.held_by_answer += one.held_by_answer;
    }
    let Tally {
        stored,
        orphans,
        early,
        raced,
        refused,
        held,
        kept,
        revived,
        let_go_by_answer,
        held_by_answer,
    } = sum;
    println!(
        "random histories: {stored} blobs stored, {orphans} of dropped parts, {early} of them \
         collected during the history ({raced} by a claim made after later calls), \
         {refused} claims refused ({held} for a lingering record), {kept} blobs kept to the \
         end by one, {revived} lingering records made objects by the replay; by the answer \
         of the day about the bucket {let_go_by_answer} went under a mark raised since and \
         {held_by_answer} stayed after the last mark was gone"
    );
    // The histories are worth their name.
    assert!(
        orphans > 1500 && stored > orphans + 1000,
        "{orphans} of {stored}"
    );
    assert!(
        early > 500 && raced > 50 && refused > 5000,
        "{early} {raced} {refused}"
    );
    assert!(
        held > 1000 && kept > 100 && revived > 10,
        "{held} {kept} {revived}"
    );
    assert!(
        let_go_by_answer > 5 && held_by_answer > 20,
        "{let_go_by_answer} {held_by_answer}"
    );
}
