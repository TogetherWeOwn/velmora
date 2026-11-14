//! `SqlCatalog` for buckets, access keys, grants, objects and listing,
//! over SQLite with the D1 schema.
//!
//! Every statement goes through [`Probe`], which refuses more than 100
//! bound parameters (the D1 limit), counts queries, and can make a batch
//! lose its guard after all of its statements ran.

use std::cell::{Cell, RefCell};

use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{PublishUnrecorded, RusqliteSql};
use velmora_bridge::*;

/// 2025-11-13T00:00:00.123Z.
const T0: UnixMs = UnixMs(1_762_992_000_123);
const DAY_MS: i64 = 86_400_000;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Probe {
    db: RusqliteSql,
    /// When set, every batch ends with a failing `tx_guard` insert.
    lose_guard: Cell<bool>,
    queries: Cell<u32>,
    execs: Cell<u32>,
    batches: Cell<u32>,
    /// Statements of the most recent batch, in order.
    last_batch: RefCell<Vec<&'static str>>,
}

fn check_params(params: &[SqlValue]) {
    assert!(
        params.len() <= 100,
        "statement binds {} params",
        params.len()
    );
}

impl Sql for Probe {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        check_params(params);
        self.queries.set(self.queries.get() + 1);
        self.db.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        check_params(params);
        self.execs.set(self.execs.get() + 1);
        self.db.exec(sql, params).await
    }
    async fn batch(&self, mut stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        stmts.iter().for_each(|(_, p)| check_params(p));
        self.batches.set(self.batches.get() + 1);
        *self.last_batch.borrow_mut() = stmts.iter().map(|(sql, _)| *sql).collect();
        if self.lose_guard.get() {
            stmts.push(("INSERT INTO tx_guard(ok) VALUES (0)", vec![]));
        }
        self.db.batch(stmts).await
    }
}

struct Fx {
    cat: SqlCatalog<Probe>,
    next_id: Cell<u8>,
}

impl Fx {
    fn new() -> Fx {
        Fx {
            cat: SqlCatalog::new(Probe {
                db: RusqliteSql::with_schema().unwrap(),
                lose_guard: Cell::new(false),
                queries: Cell::new(0),
                execs: Cell::new(0),
                batches: Cell::new(0),
                last_batch: RefCell::new(vec![]),
            }),
            next_id: Cell::new(1),
        }
    }

    fn seed(&self) -> u8 {
        let n = self.next_id.get();
        self.next_id.set(n + 1);
        n
    }

    async fn bucket(&self, name: &str) -> Bucket {
        let b = Bucket {
            id: BucketId::mint([self.seed(); 8]),
            name: name.into(),
            owner: "owner".into(),
            bdk_wrapped: vec![7; 73],
            kek_version: 1,
            disposable: true,
            created_at: T0,
        };
        assert_eq!(
            self.cat.create_bucket(&b).await.unwrap(),
            Guard::Applied(())
        );
        b
    }

    /// A well-formed single-PUT commit of `extents` extents.
    fn commit(&self, bucket: &BucketId, key: &str, extents: u32, now: UnixMs) -> CommitGeneration {
        let seed = self.seed();
        let id = GenerationId::mint(now, [seed; 8]);
        let rows = (0..extents)
            .map(|seq| {
                let mut raw = [seed; 13];
                raw[0] = seq as u8;
                ExtentRow {
                    id: ExtentId::mint(raw),
                    bucket_id: bucket.clone(),
                    generation_id: Some(id.clone()),
                    state: ExtentState::Committed,
                    seq: Some(seq),
                    plain_offset: Some(u64::from(seq) * 5),
                    plain_size: 5,
                    cipher_size: 69,
                    media_header: vec![seed; 48],
                    key_mode: 1,
                    wrapped_file_key: Some(vec![seed; 73]),
                    plain_md5: [seed; 16],
                    plain_sha256: [seed; 32],
                    cipher_sha256: [seq as u8; 32],
                    safety_state: SafetyState::Held,
                    article_count: None,
                    plan_rev: 0,
                    last_verified_at: None,
                    release_evidence: None,
                    released_at: None,
                    created_at: now,
                }
            })
            .collect();
        CommitGeneration {
            generation: GenerationRow {
                id,
                bucket_id: bucket.clone(),
                key: key.into(),
                state: GenerationState::Live,
                size: u64::from(extents) * 5,
                etag: format!("\"{seed:032x}\""),
                checksum_json: Some("{\"crc32\":\"AAAAAA==\"}".into()),
                content_json: "{\"content-type\":\"text/plain\"}".into(),
                user_meta_json: "{}".into(),
                extent_count: extents,
                created_at: now,
                retired_at: None,
            },
            extents: rows,
            now,
        }
    }

    async fn put(&self, bucket: &BucketId, key: &str, now: UnixMs) -> CommitGeneration {
        let c = self.commit(bucket, key, 1, now);
        self.cat.publish(&c).await.unwrap();
        c
    }

    fn int(&self, sql: &str) -> i64 {
        self.cat
            .sql
            .db
            .with_conn(|c| c.query_row(sql, [], |r| r.get(0)).unwrap())
    }

    fn strings(&self, sql: &str) -> Vec<String> {
        self.cat.sql.db.with_conn(|c| {
            let mut stmt = c.prepare(sql).unwrap();
            let rows = stmt.query_map([], |r| r.get(0)).unwrap();
            rows.map(|r| r.unwrap()).collect()
        })
    }

    /// `(batch, exec)` calls since the last reading.
    fn writes(&self) -> (u32, u32) {
        (self.cat.sql.batches.take(), self.cat.sql.execs.take())
    }

    fn run(&self, sql: &str) {
        self.cat.sql.db.apply(sql).unwrap();
    }

    /// Row counts of every table a publication or deletion writes.
    fn footprint(&self) -> [i64; 5] {
        ["generations", "extents", "outbox", "objects", "gc"]
            .map(|t| self.int(&format!("SELECT COUNT(*) FROM {t}")))
    }
}

fn query(prefix: &str, delimiter: Option<&str>, max_keys: u32) -> ListQuery {
    ListQuery {
        prefix: prefix.into(),
        delimiter: delimiter.map(String::from),
        after: None,
        skip_prefix: None,
        max_keys,
    }
}

/// Pages a listing to the end. Returns the keys, the common prefixes and
/// the size of each page, checking the page invariants on the way.
async fn page_all(
    fx: &Fx,
    bucket: &BucketId,
    mut q: ListQuery,
) -> (Vec<String>, Vec<String>, Vec<usize>) {
    let (mut keys, mut prefixes, mut sizes) = (vec![], vec![], vec![]);
    for _ in 0..10_000 {
        let page = fx.cat.list(bucket, &q).await.unwrap();
        let n = page.entries.len() + page.common_prefixes.len();
        assert!(n <= q.max_keys as usize, "page holds {n} items");
        sizes.push(n);
        keys.extend(page.entries.into_iter().map(|e| e.key));
        prefixes.extend(page.common_prefixes);
        match page.next {
            Some(cursor) => {
                assert!(n > 0, "a truncated page must make progress");
                q.after = Some(cursor.after);
                q.skip_prefix = cursor.skip_prefix;
            }
            None => return (keys, prefixes, sizes),
        }
    }
    panic!("listing did not terminate");
}

/// What S3 says a complete listing holds: keys under the prefix in byte
/// order, folded at the first delimiter after the prefix.
fn model(all: &[&str], prefix: &str, delimiter: Option<&str>) -> (Vec<String>, Vec<String>) {
    let mut sorted: Vec<&str> = all
        .iter()
        .copied()
        .filter(|k| k.starts_with(prefix))
        .collect();
    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let (mut keys, mut prefixes) = (vec![], Vec::<String>::new());
    for k in sorted {
        let rest = &k[prefix.len()..];
        match delimiter.and_then(|d| rest.find(d).map(|i| i + d.len())) {
            Some(end) => {
                let p = format!("{prefix}{}", &rest[..end]);
                if prefixes.last() != Some(&p) {
                    prefixes.push(p);
                }
            }
            None => keys.push(k.to_string()),
        }
    }
    (keys, prefixes)
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn commit_publishes_generation_extents_and_outbox() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let c = fx.commit(&b.id, "dir/file.bin", 3, T0);
    fx.cat.publish(&c).await.unwrap();

    let (generation, extents) = fx
        .cat
        .live_object(&b.id, "dir/file.bin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generation, c.generation);
    assert_eq!(extents, c.extents, "extents come back in seq order");
    assert_eq!(fx.footprint(), [1, 3, 3, 1, 0]);
    assert_eq!(
        fx.int(&format!(
            "SELECT COUNT(*) FROM outbox WHERE stage = 'post' AND attempts = 0 \
             AND lease_token = 0 AND next_at = {0} AND generation_id = '{1}'",
            T0.0, c.generation.id
        )),
        3
    );
    assert!(fx
        .cat
        .live_object(&b.id, "dir/file")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn commit_guard_failure_makes_nothing_visible() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let c = fx.commit(&b.id, "k", 2, T0);

    fx.cat.sql.lose_guard.set(true);
    let lost = fx.cat.publish(&c).await.unwrap();
    assert_eq!(lost, Guard::Lost);
    fx.cat.sql.lose_guard.set(false);

    assert_eq!(fx.footprint(), [0, 0, 0, 0, 0]);
    assert!(fx.cat.live_object(&b.id, "k").await.unwrap().is_none());
    assert!(fx.cat.object_status(&b.id, "k").await.unwrap().is_none());
    let page = fx.cat.list(&b.id, &query("", None, 1000)).await.unwrap();
    assert_eq!(page, ListPage::default());

    // The same commit succeeds afterwards: the failure left no residue.
    fx.cat.publish(&c).await.unwrap();
    assert_eq!(fx.footprint(), [1, 2, 2, 1, 0]);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_overwrite_keeps_the_old_generation_live() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let v1 = fx.put(&b.id, "k", T0).await;
    let before = fx.footprint();

    // Guard lost after every statement ran.
    let v2 = fx.commit(&b.id, "k", 1, T0.plus_ms(10));
    fx.cat.sql.lose_guard.set(true);
    assert_eq!(fx.cat.publish(&v2).await.unwrap(), Guard::Lost);
    fx.cat.sql.lose_guard.set(false);

    // A statement in the middle fails (extent id already taken).
    let mut v3 = fx.commit(&b.id, "k", 2, T0.plus_ms(20));
    v3.extents[1].id = v1.extents[0].id.clone();
    assert!(matches!(
        fx.cat.publish(&v3).await,
        Err(BridgeError::Sql(_))
    ));

    // A failed delete is all-or-nothing too.
    fx.cat.sql.lose_guard.set(true);
    assert!(fx
        .cat
        .delete_object(&b.id, "k", T0.plus_ms(30))
        .await
        .is_err());
    fx.cat.sql.lose_guard.set(false);

    assert_eq!(fx.footprint(), before);
    let (generation, extents) = fx.cat.live_object(&b.id, "k").await.unwrap().unwrap();
    assert_eq!(generation, v1.generation);
    assert_eq!(extents, v1.extents);
    assert_eq!(fx.strings("SELECT stage FROM outbox"), ["post"]);
}

/// The pointer move is the last statement of a publication and the
/// pointer removal the last of a deletion. Failing exactly there proves
/// everything before it was in the same transaction.
#[tokio::test(flavor = "current_thread")]
async fn failure_on_the_last_statement_rolls_back_the_whole_batch() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;

    // One batch and nothing else per successful write.
    fx.writes();
    let v1 = fx.commit(&b.id, "k", 2, T0);
    fx.cat.publish(&v1).await.unwrap();
    assert_eq!(fx.writes(), (1, 0), "first commit");
    assert!(fx
        .cat
        .sql
        .last_batch
        .borrow()
        .last()
        .is_some_and(|s| s.starts_with("INSERT INTO objects")));
    fx.cat
        .publish(&fx.commit(&b.id, "k", 1, T0.plus_ms(1)))
        .await
        .unwrap();
    assert_eq!(fx.writes(), (1, 0), "overwrite");
    fx.cat
        .delete_object(&b.id, "k", T0.plus_ms(2))
        .await
        .unwrap();
    assert_eq!(fx.writes(), (1, 0), "delete");
    assert!(fx
        .cat
        .sql
        .last_batch
        .borrow()
        .last()
        .is_some_and(|s| s.starts_with("DELETE FROM objects")));

    let live = fx.put(&b.id, "live", T0.plus_ms(3)).await;
    let before = fx.footprint();
    let rows = |fx: &Fx| {
        fx.strings(
            "SELECT 'g:' || id || ':' || state || ':' || COALESCE(retired_at, '') FROM generations \
             UNION ALL SELECT 'x:' || id || ':' || generation_id FROM extents \
             UNION ALL SELECT 'o:' || extent_id || ':' || stage || ':' || updated_at FROM outbox \
             UNION ALL SELECT 'p:' || key || ':' || generation_id FROM objects \
             UNION ALL SELECT 'c:' || extent_id || ':' || action FROM gc ORDER BY 1",
        )
    };
    let snapshot = rows(&fx);

    fx.run(
        "CREATE TRIGGER fail_ins BEFORE INSERT ON objects BEGIN SELECT RAISE(ABORT, 'x'); END;
         CREATE TRIGGER fail_upd BEFORE UPDATE ON objects BEGIN SELECT RAISE(ABORT, 'x'); END;
         CREATE TRIGGER fail_del BEFORE DELETE ON objects BEGIN SELECT RAISE(ABORT, 'x'); END;",
    );
    fx.writes();
    // New key: the pointer insert fails.
    let fresh = fx.commit(&b.id, "fresh", 2, T0.plus_ms(10));
    let err = fx.cat.publish(&fresh).await.unwrap_err();
    assert!(matches!(err, BridgeError::Sql(_)), "{err:?}");
    assert_eq!(fx.writes(), (1, 0));
    assert_eq!(
        (fx.footprint(), rows(&fx)),
        (before, snapshot.clone()),
        "insert"
    );
    // Overwrite: the pointer update fails after the old generation was
    // retired, its outbox cancelled and its GC rows written.
    let over = fx.commit(&b.id, "live", 1, T0.plus_ms(11));
    let err = fx.cat.publish(&over).await.unwrap_err();
    assert!(matches!(err, BridgeError::Sql(_)), "{err:?}");
    assert_eq!(fx.writes(), (1, 0));
    assert_eq!(
        (fx.footprint(), rows(&fx)),
        (before, snapshot.clone()),
        "update"
    );
    // Delete: the pointer removal fails.
    let err = fx
        .cat
        .delete_object(&b.id, "live", T0.plus_ms(12))
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Sql(_)), "{err:?}");
    assert_eq!(fx.writes(), (1, 0));
    assert_eq!((fx.footprint(), rows(&fx)), (before, snapshot), "delete");

    let (generation, extents) = fx.cat.live_object(&b.id, "live").await.unwrap().unwrap();
    assert_eq!((generation, extents), (live.generation, live.extents));
    assert!(fx.cat.live_object(&b.id, "fresh").await.unwrap().is_none());

    // With the triggers gone the same writes go through.
    fx.run("DROP TRIGGER fail_ins; DROP TRIGGER fail_upd; DROP TRIGGER fail_del;");
    fx.cat.publish(&fresh).await.unwrap();
    fx.cat.publish(&over).await.unwrap();
    fx.cat
        .delete_object(&b.id, "live", T0.plus_ms(12))
        .await
        .unwrap();
}

/// Retiring a generation must not read the whole outbox: the cancel is
/// driven from the live pointer through indexed lookups.
#[tokio::test(flavor = "current_thread")]
async fn outbox_cancel_does_not_scan_the_outbox() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    fx.put(&b.id, "k", T0).await;
    fx.cat.delete_object(&b.id, "k", T0).await.unwrap();
    let delete = fx.cat.sql.last_batch.borrow().clone();
    fx.put(&b.id, "k2", T0).await;
    fx.put(&b.id, "k2", T0.plus_ms(1)).await;
    let overwrite = fx.cat.sql.last_batch.borrow().clone();

    // Unbound parameters plan the same way as bound ones.
    let explain = |sql: &str| {
        fx.cat.sql.db.with_conn(|c| {
            let mut stmt = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let mut rows = stmt.raw_query();
            let mut lines = vec![];
            while let Some(row) = rows.next().unwrap() {
                lines.push(row.get::<_, String>(3).unwrap());
            }
            lines.join("\n")
        })
    };
    for batch in [&delete, &overwrite] {
        let cancel: Vec<_> = batch
            .iter()
            .filter(|s| s.starts_with("UPDATE outbox"))
            .collect();
        assert_eq!(cancel.len(), 1);
        let plan = explain(cancel[0]);
        assert!(plan.contains("SEARCH outbox USING"), "{plan}");
        assert!(plan.contains("SEARCH o USING PRIMARY KEY"), "{plan}");
        assert!(plan.contains("SEARCH e USING"), "{plan}");
        // No statement of a retirement reads a whole table.
        for sql in batch.iter() {
            let plan = explain(sql);
            let scans: Vec<_> = plan
                .lines()
                .filter(|l| l.starts_with("SCAN") && *l != "SCAN CONSTANT ROW" && *l != "SCAN a")
                .collect();
            assert!(scans.is_empty(), "{sql}\n{plan}");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn overwrite_supersedes_old_generation_and_adds_gc_rows() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let v1 = fx.commit(&b.id, "k", 2, T0);
    fx.cat.publish(&v1).await.unwrap();
    let other = fx.put(&b.id, "other", T0).await;

    let t1 = T0.plus_ms(5_000);
    let v2 = fx.put(&b.id, "k", t1).await;

    let (generation, extents) = fx.cat.live_object(&b.id, "k").await.unwrap().unwrap();
    assert_eq!(generation, v2.generation);
    assert_eq!(extents, v2.extents);
    assert_eq!(
        fx.strings(&format!(
            "SELECT state || ':' || retired_at FROM generations WHERE id = '{}'",
            v1.generation.id
        )),
        [format!("superseded:{}", t1.0)]
    );
    // Three GC rows per old extent: blobs now, key shred a day later.
    let mut expected = vec![];
    for e in &v1.extents {
        expected.push(format!("{}:delete_cache:{}", e.id, t1.0));
        expected.push(format!("{}:delete_safety:{}", e.id, t1.0));
        expected.push(format!("{}:shred_key:{}", e.id, t1.0 + DAY_MS));
    }
    expected.sort();
    assert_eq!(
        fx.strings(
            "SELECT extent_id || ':' || action || ':' || due_at FROM gc \
             WHERE done_at IS NULL ORDER BY 1"
        ),
        expected
    );
    // The old posting obligations are cancelled; nothing else is touched.
    assert_eq!(
        fx.strings(&format!(
            "SELECT DISTINCT stage || ':' || updated_at FROM outbox WHERE generation_id = '{}'",
            v1.generation.id
        )),
        [format!("cancelled:{}", t1.0)]
    );
    assert_eq!(
        fx.int("SELECT COUNT(*) FROM outbox WHERE stage = 'post'"),
        2
    );
    assert_eq!(
        fx.int("SELECT COUNT(*) FROM generations WHERE state = 'live'"),
        2
    );
    assert_eq!(
        fx.cat.live_object(&b.id, "other").await.unwrap().unwrap().0,
        other.generation
    );
    let page = fx.cat.list(&b.id, &query("", None, 1000)).await.unwrap();
    let listed: Vec<_> = page.entries.iter().map(|e| (&*e.key, &*e.etag)).collect();
    assert_eq!(
        listed,
        [
            ("k", &*v2.generation.etag),
            ("other", &*other.generation.etag)
        ]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn finished_outbox_rows_stay_done_when_retired() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    fx.put(&b.id, "k", T0).await;
    fx.run("UPDATE outbox SET stage = 'done'");
    fx.put(&b.id, "k", T0.plus_ms(1)).await;
    assert_eq!(
        fx.strings("SELECT stage FROM outbox ORDER BY generation_id"),
        ["done", "post"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn commit_rejects_input_that_is_not_one_live_generation() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let other = fx.bucket("beta").await;
    let good = fx.commit(&b.id, "k", 2, T0);

    let mut cases = vec![];
    let mut c = good.clone();
    c.generation.state = GenerationState::Superseded;
    cases.push(c);
    let mut c = good.clone();
    c.generation.retired_at = Some(T0);
    cases.push(c);
    let mut c = good.clone();
    c.generation.extent_count = 3;
    cases.push(c);
    let mut c = good.clone();
    c.extents[1].bucket_id = other.id.clone();
    cases.push(c);
    let mut c = good.clone();
    c.extents[1].generation_id = Some(GenerationId::new("g_other"));
    cases.push(c);
    let mut c = good.clone();
    c.extents.swap(0, 1);
    cases.push(c);
    let mut c = good.clone();
    c.extents[1].plain_offset = Some(4);
    cases.push(c);
    let mut c = good.clone();
    c.generation.size += 1;
    cases.push(c);
    let mut c = good.clone();
    c.extents[0].seq = None;
    cases.push(c);
    let mut c = good.clone();
    c.extents[1].wrapped_file_key = None;
    cases.push(c);
    for state in [
        SafetyState::Releasing,
        SafetyState::Released,
        SafetyState::Deleted,
    ] {
        let mut c = good.clone();
        c.extents[0].safety_state = state;
        cases.push(c);
    }
    let mut c = good.clone();
    c.extents[0].plain_offset = None;
    cases.push(c);

    for (i, c) in cases.iter().enumerate() {
        let err = fx.cat.publish(c).await.unwrap_err();
        assert!(matches!(err, BridgeError::Invalid(_)), "case {i}: {err:?}");
    }
    assert_eq!(fx.footprint(), [0, 0, 0, 0, 0]);

    // A commit into a bucket that does not exist writes nothing either.
    let ghost = fx.commit(&BucketId::new("b_missing"), "k", 1, T0);
    assert!(fx.cat.publish(&ghost).await.is_err());
    assert_eq!(fx.footprint(), [0, 0, 0, 0, 0]);
}

#[tokio::test(flavor = "current_thread")]
async fn commit_binds_fresh_extents_to_the_generation_as_committed() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let want = fx.commit(&b.id, "k", 2, T0);
    // Extents straight from sealing: not yet bound to a generation.
    let mut fresh = want.clone();
    for e in &mut fresh.extents {
        e.generation_id = None;
        e.state = ExtentState::Staged;
    }
    fx.cat.publish(&fresh).await.unwrap();
    let (_, extents) = fx.cat.live_object(&b.id, "k").await.unwrap().unwrap();
    assert_eq!(extents, want.extents);
}

// ---------------------------------------------------------------------------
// Deletion
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn delete_retires_generation_cancels_outbox_and_adds_gc_rows() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let v1 = fx.put(&b.id, "k", T0).await;
    let keep = fx.put(&b.id, "keep", T0).await;

    // Deleting a key that does not exist changes nothing.
    let before = fx.footprint();
    fx.cat.delete_object(&b.id, "nope", T0).await.unwrap();
    assert_eq!(fx.footprint(), before);

    let t1 = T0.plus_ms(7_000);
    fx.cat.delete_object(&b.id, "k", t1).await.unwrap();

    assert!(fx.cat.live_object(&b.id, "k").await.unwrap().is_none());
    assert!(fx.cat.object_status(&b.id, "k").await.unwrap().is_none());
    assert_eq!(
        fx.strings(&format!(
            "SELECT state || ':' || retired_at FROM generations WHERE id = '{}'",
            v1.generation.id
        )),
        [format!("deleted:{}", t1.0)]
    );
    let x = &v1.extents[0].id;
    assert_eq!(
        fx.strings("SELECT extent_id || ':' || action || ':' || due_at FROM gc ORDER BY 1"),
        [
            format!("{x}:delete_cache:{}", t1.0),
            format!("{x}:delete_safety:{}", t1.0),
            format!("{x}:shred_key:{}", t1.0 + DAY_MS),
        ]
    );
    assert_eq!(
        fx.strings(&format!("SELECT stage FROM outbox WHERE extent_id = '{x}'")),
        ["cancelled"]
    );
    // The extent row and its wrapped key survive until the shred is due.
    assert_eq!(
        fx.int(&format!(
            "SELECT COUNT(*) FROM extents WHERE id = '{x}' AND wrapped_file_key IS NOT NULL"
        )),
        1
    );

    // A second delete is a no-op: no second set of GC rows.
    fx.cat
        .delete_object(&b.id, "k", t1.plus_ms(1))
        .await
        .unwrap();
    assert_eq!(fx.int("SELECT COUNT(*) FROM gc"), 3);

    let (generation, _) = fx.cat.live_object(&b.id, "keep").await.unwrap().unwrap();
    assert_eq!(generation, keep.generation);
    assert_eq!(
        fx.strings("SELECT key FROM objects"),
        ["keep"],
        "only the deleted key lost its pointer"
    );

    // The key can be written again.
    let v2 = fx.put(&b.id, "k", t1.plus_ms(2)).await;
    assert_eq!(
        fx.cat.live_object(&b.id, "k").await.unwrap().unwrap().0,
        v2.generation
    );
    assert_eq!(
        fx.int("SELECT COUNT(*) FROM gc"),
        3,
        "nothing live was replaced"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn same_key_in_two_buckets_is_independent() {
    let fx = Fx::new();
    let a = fx.bucket("alpha").await;
    let b = fx.bucket("beta").await;
    let in_a = fx.put(&a.id, "k", T0).await;
    let in_b = fx.put(&b.id, "k", T0).await;

    fx.put(&a.id, "k", T0.plus_ms(1)).await;
    fx.cat
        .delete_object(&a.id, "k", T0.plus_ms(2))
        .await
        .unwrap();

    assert!(fx.cat.live_object(&a.id, "k").await.unwrap().is_none());
    let (generation, _) = fx.cat.live_object(&b.id, "k").await.unwrap().unwrap();
    assert_eq!(generation, in_b.generation);
    assert_eq!(
        fx.int(&format!(
            "SELECT COUNT(*) FROM gc WHERE extent_id = '{}'",
            in_b.extents[0].id
        )),
        0
    );
    assert_eq!(
        fx.int(&format!(
            "SELECT COUNT(*) FROM gc WHERE extent_id = '{}'",
            in_a.extents[0].id
        )),
        3
    );
    let (keys, _, _) = page_all(&fx, &a.id, query("", None, 10)).await;
    assert!(keys.is_empty());
    let (keys, _, _) = page_all(&fx, &b.id, query("", None, 10)).await;
    assert_eq!(keys, ["k"]);
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn list_prefix_max_keys_and_continuation() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let all = [
        "a", "a/1", "a/2", "a/3", "a0", "ab", "b/1", "docs/x", "docs/y", "dot",
    ];
    for k in all {
        fx.put(&b.id, k, T0).await;
    }

    let page = fx.cat.list(&b.id, &query("", None, 3)).await.unwrap();
    let keys: Vec<_> = page.entries.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(keys, ["a", "a/1", "a/2"]);
    assert_eq!(
        page.next,
        Some(ListCursor {
            after: "a/2".into(),
            skip_prefix: None
        })
    );
    let first = &page.entries[0];
    assert_eq!(
        (first.size, first.last_modified, first.etag.len()),
        (5, T0, 34)
    );

    for max_keys in [1, 2, 3, 4, 9, 10, 11, 1000] {
        for prefix in ["", "a", "a/", "a/2", "do", "docs/", "zzz"] {
            let (keys, prefixes, sizes) = page_all(&fx, &b.id, query(prefix, None, max_keys)).await;
            let (want, _) = model(&all, prefix, None);
            assert_eq!(keys, want, "prefix {prefix:?} max_keys {max_keys}");
            assert!(prefixes.is_empty());
            let pages = want.len().div_ceil(max_keys as usize).max(1);
            assert_eq!(
                sizes.len(),
                pages,
                "an exact fit is not reported as truncated"
            );
        }
    }

    // Exactly max-keys remaining: complete, not truncated.
    let page = fx.cat.list(&b.id, &query("a/", None, 3)).await.unwrap();
    assert_eq!(page.entries.len(), 3);
    assert_eq!(page.next, None);

    // start-after is exclusive, and may name a key that does not exist.
    let mut q = query("a", None, 1000);
    q.after = Some("a/2".into());
    let (keys, _, _) = page_all(&fx, &b.id, q).await;
    assert_eq!(keys, ["a/3", "a0", "ab"]);
    let mut q = query("", None, 1000);
    q.after = Some("c".into());
    let (keys, _, _) = page_all(&fx, &b.id, q).await;
    assert_eq!(keys, ["docs/x", "docs/y", "dot"]);

    assert_eq!(
        fx.cat.list(&b.id, &query("", None, 0)).await.unwrap(),
        ListPage::default()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn list_delimiter_pages_each_common_prefix_once() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    for k in ["a/1", "a/2", "b/1"] {
        fx.put(&b.id, k, T0).await;
    }

    let mut q = query("", Some("/"), 1);
    let one = fx.cat.list(&b.id, &q).await.unwrap();
    assert!(one.entries.is_empty());
    assert_eq!(one.common_prefixes, ["a/"]);
    let cursor = one.next.expect("b/ is still to come");
    assert_eq!(cursor.skip_prefix.as_deref(), Some("a/"));

    q.after = Some(cursor.after);
    q.skip_prefix = cursor.skip_prefix;
    let two = fx.cat.list(&b.id, &q).await.unwrap();
    assert!(two.entries.is_empty());
    assert_eq!(two.common_prefixes, ["b/"]);
    assert_eq!(two.next, None);

    // A last-key-only token (no skip state) is what repeats `a/`; the
    // cursor this catalogue returns never does.
    let (keys, prefixes, sizes) = page_all(&fx, &b.id, query("", Some("/"), 1)).await;
    assert!(keys.is_empty());
    assert_eq!(prefixes, ["a/", "b/"]);
    assert_eq!(sizes, [1, 1]);
}

/// A caller that folds delimiters itself asks for plain rows and passes
/// the common prefix it already emitted: the scan seeks past that prefix
/// in the query instead of returning its rows.
#[tokio::test(flavor = "current_thread")]
async fn list_skip_prefix_seeks_past_the_prefix_without_scanning_it() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    for k in ["a/1", "a/2", "a/3", "a0", "b/1"] {
        fx.put(&b.id, k, T0).await;
    }
    let rows = |after: Option<&str>, skip: &str, prefix: &str, max_keys: u32| {
        let mut q = query(prefix, None, max_keys);
        q.after = after.map(String::from);
        q.skip_prefix = Some(skip.into());
        q
    };
    let keys =
        |page: ListPage| -> Vec<String> { page.entries.into_iter().map(|e| e.key).collect() };

    fx.cat.sql.queries.set(0);
    let page = fx
        .cat
        .list(&b.id, &rows(Some("a/1"), "a/", "", 1))
        .await
        .unwrap();
    assert_eq!(fx.cat.sql.queries.get(), 1);
    assert_eq!(
        page.next,
        Some(ListCursor {
            after: "a0".into(),
            skip_prefix: None
        })
    );
    assert_eq!(keys(page), ["a0"], "a/2 and a/3 were never fetched");

    let page = fx
        .cat
        .list(&b.id, &rows(None, "a/", "", 1000))
        .await
        .unwrap();
    assert_eq!(keys(page), ["a0", "b/1"]);
    // Both bounds hold: `after` beyond the skipped prefix still applies,
    // and so does the listing prefix.
    let page = fx
        .cat
        .list(&b.id, &rows(Some("a0"), "a/", "", 1000))
        .await
        .unwrap();
    assert_eq!(keys(page), ["b/1"]);
    let page = fx
        .cat
        .list(&b.id, &rows(None, "a/", "a", 1000))
        .await
        .unwrap();
    assert_eq!(keys(page), ["a0"]);
    let page = fx
        .cat
        .list(&b.id, &rows(None, "a/", "b", 1000))
        .await
        .unwrap();
    assert_eq!(keys(page), ["b/1"]);
    // Nothing sorts after a prefix with no successor.
    let page = fx
        .cat
        .list(&b.id, &rows(None, "\u{10FFFF}", "", 1000))
        .await
        .unwrap();
    assert_eq!(page, ListPage::default());
}

#[tokio::test(flavor = "current_thread")]
async fn list_delimiter_matches_model_at_every_page_size() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let all = [
        "a",
        "a/",
        "a/1",
        "a/2",
        "a/b/1",
        "a/b/2",
        "a//x",
        "a0",
        "b/1",
        "c",
        "d/e/f/g",
        "d/e/h",
        "d/z",
        "photos/2024/jan/1.jpg",
        "photos/2024/jan/2.jpg",
        "photos/2024/feb/1.jpg",
        "photos/2025/x.jpg",
        "photos/readme",
        "z",
        "z/",
    ];
    for k in all {
        fx.put(&b.id, k, T0).await;
    }
    for (prefix, delimiter) in [
        ("", "/"),
        ("a", "/"),
        ("a/", "/"),
        ("a/b", "/"),
        ("d/", "/"),
        ("d/e/", "/"),
        ("photos/", "/"),
        ("photos/2024/", "/"),
        ("photos/", "/jan/"),
        ("", "o"),
        ("nope/", "/"),
    ] {
        let want = model(&all, prefix, Some(delimiter));
        for max_keys in [1, 2, 3, 5, 1000] {
            let q = query(prefix, Some(delimiter), max_keys);
            let (keys, prefixes, sizes) = page_all(&fx, &b.id, q).await;
            let at = format!("prefix {prefix:?} delimiter {delimiter:?} max_keys {max_keys}");
            assert_eq!((keys, prefixes), want.clone(), "{at}");
            let total = want.0.len() + want.1.len();
            let full_pages = sizes.iter().filter(|n| **n == max_keys as usize).count();
            assert_eq!(full_pages, total / max_keys as usize, "{at}: {sizes:?}");
        }
    }

    // An empty delimiter means no delimiter.
    let (keys, prefixes, _) = page_all(&fx, &b.id, query("a/", Some(""), 2)).await;
    assert_eq!((keys, prefixes), model(&all, "a/", None));

    // A common prefix at or before start-after is not reported, at any
    // page size, and the keys under it are not listed either.
    for after in ["a/", "a/1", "a/b/1", "a/zzz"] {
        for max_keys in [1, 2, 1000] {
            let mut q = query("", Some("/"), max_keys);
            q.after = Some(after.into());
            let (keys, prefixes, _) = page_all(&fx, &b.id, q).await;
            let at = format!("after {after:?} max_keys {max_keys}");
            assert_eq!(prefixes, ["b/", "d/", "photos/", "z/"], "{at}");
            assert_eq!(keys, ["a0", "c", "z"], "{at}");
        }
    }
    // start-after before the prefix string itself leaves it in.
    let mut q = query("", Some("/"), 1000);
    q.after = Some("a".into());
    let page = fx.cat.list(&b.id, &q).await.unwrap();
    assert_eq!(page.common_prefixes, ["a/", "b/", "d/", "photos/", "z/"]);
    // Nested: only the prefix that contains start-after is dropped.
    let mut q = query("a/", Some("/"), 1000);
    q.after = Some("a/b/1".into());
    let page = fx.cat.list(&b.id, &q).await.unwrap();
    assert_eq!(page.common_prefixes, [] as [&str; 0]);
    assert!(page.entries.is_empty() && page.next.is_none());
    let mut q = query("a/", Some("/"), 1000);
    q.after = Some("a/1".into());
    let page = fx.cat.list(&b.id, &q).await.unwrap();
    assert_eq!(page.common_prefixes, ["a/b/"]);
}

#[tokio::test(flavor = "current_thread")]
async fn keys_with_reserved_characters_round_trip() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let all = [
        "100%/done",
        "100%25/literal",
        "100a/like-wildcard",
        "a b/c d.txt",
        "a+b/c+d.txt",
        "a_b/x",
        "axb/x",
        "dir//double",
        "dir//double//deeper",
        "dir/single",
        "//leading",
        " lead and trail ",
        "tab\there",
        "quote'\"\\;--",
        "ünï/çødé.txt",
        "日本語/ファイル",
        "emoji/\u{1F600}.png",
        "k\u{D7FF}x",
        "k\u{E000}",
        "m\u{10FFFF}",
        "m\u{10FFFF}a",
        "n",
    ];
    let mut committed = vec![];
    for k in all {
        committed.push(fx.put(&b.id, k, T0).await);
    }
    for (k, c) in all.iter().zip(&committed) {
        let (generation, _) = fx.cat.live_object(&b.id, k).await.unwrap().unwrap();
        assert_eq!(generation, c.generation, "key {k:?}");
    }

    // Byte order, exactly as stored.
    let (keys, _, _) = page_all(&fx, &b.id, query("", None, 4)).await;
    assert_eq!(keys, model(&all, "", None).0);

    // The prefix is a range, not a pattern, and stops at the right key.
    for prefix in [
        "100%",
        "100%2",
        "a_b",
        "a b/",
        "a+b",
        "dir/",
        "dir//",
        "/",
        "//",
        " ",
        "quote'",
        "ü",
        "日本",
        "emoji/\u{1F600}",
        "k\u{D7FF}",
        "k",
        "m\u{10FFFF}",
        "\u{10FFFF}",
    ] {
        for delimiter in [None, Some("/"), Some("//"), Some("%"), Some("ø")] {
            for max_keys in [1, 3, 1000] {
                let q = query(prefix, delimiter, max_keys);
                let got = page_all(&fx, &b.id, q).await;
                let want = model(&all, prefix, delimiter);
                assert_eq!(
                    (got.0, got.1),
                    want,
                    "prefix {prefix:?} delimiter {delimiter:?} max_keys {max_keys}"
                );
            }
        }
    }

    // `dir//double` folds at the first delimiter after the prefix.
    let page = fx
        .cat
        .list(&b.id, &query("dir/", Some("/"), 1000))
        .await
        .unwrap();
    assert_eq!(page.common_prefixes, ["dir//"]);
    let keys: Vec<_> = page.entries.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(keys, ["dir/single"]);

    // Delete addresses the exact key only.
    fx.cat
        .delete_object(&b.id, "a b/c d.txt", T0)
        .await
        .unwrap();
    fx.cat.delete_object(&b.id, "dir/", T0).await.unwrap();
    let (keys, _, _) = page_all(&fx, &b.id, query("", None, 1000)).await;
    assert_eq!(keys.len(), all.len() - 1);
    assert!(fx
        .cat
        .live_object(&b.id, "a+b/c+d.txt")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn list_query_budget_returns_valid_partial_page() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let seed = fx.put(&b.id, "zz-last", T0).await;
    // 260 directories of 262 keys: more keys per directory than one
    // query fetches at max-keys 250, so every common prefix costs a query.
    fx.run(&format!(
        "WITH RECURSIVE d(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM d WHERE i < 259), \
                        f(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM f WHERE j < 261) \
         INSERT INTO objects(bucket_id, key, generation_id) \
         SELECT '{}', printf('d%03d/f%03d', i, j), '{}' FROM d, f",
        b.id, seed.generation.id
    ));

    let q = query("", Some("/"), 250);
    fx.cat.sql.queries.set(0);
    let page = fx.cat.list(&b.id, &q).await.unwrap();
    let spent = fx.cat.sql.queries.get();
    assert_eq!(spent, 200, "the page stops at its query budget");
    assert!(page.entries.is_empty());
    assert_eq!(page.common_prefixes.len(), 200);
    assert_eq!(page.common_prefixes[199], "d199/");
    let cursor = page.next.clone().expect("a partial page is truncated");
    assert_eq!(cursor.skip_prefix.as_deref(), Some("d199/"));

    // Resuming loses nothing and repeats nothing.
    let (keys, prefixes, sizes) = page_all(&fx, &b.id, q).await;
    assert_eq!(keys, ["zz-last"]);
    let want: Vec<String> = (0..260).map(|i| format!("d{i:03}/")).collect();
    assert_eq!(prefixes, want);
    assert_eq!(sizes, [200, 61]);
}

// ---------------------------------------------------------------------------
// Buckets, access keys and grants
// ---------------------------------------------------------------------------

fn access_key(akid: &str, status: KeyStatus) -> AccessKeyRow {
    AccessKeyRow {
        access_key_id: akid.into(),
        principal: "owner".into(),
        secret_wrapped: vec![9; 73],
        kek_version: 2,
        status,
        created_at: T0,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn create_bucket_loses_when_the_name_is_taken() {
    let fx = Fx::new();
    let first = fx.bucket("alpha").await;
    assert_eq!(
        fx.cat.bucket_by_name("alpha").await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(fx.cat.bucket_by_name("alph").await.unwrap(), None);
    assert_eq!(fx.cat.bucket_by_name("ALPHA").await.unwrap(), None);

    let mut second = first.clone();
    second.id = BucketId::mint([0xEE; 8]);
    second.owner = "intruder".into();
    second.bdk_wrapped = vec![1; 73];
    second.disposable = false;
    assert_eq!(fx.cat.create_bucket(&second).await.unwrap(), Guard::Lost);
    assert_eq!(fx.cat.bucket_by_name("alpha").await.unwrap(), Some(first));
    assert_eq!(fx.int("SELECT COUNT(*) FROM buckets"), 1);

    second.name = "beta".into();
    assert_eq!(
        fx.cat.create_bucket(&second).await.unwrap(),
        Guard::Applied(())
    );
    assert_eq!(fx.cat.bucket_by_name("beta").await.unwrap(), Some(second));
}

#[tokio::test(flavor = "current_thread")]
async fn grant_for_one_bucket_does_not_reach_another() {
    let fx = Fx::new();
    let a = fx.bucket("alpha").await;
    let b = fx.bucket("beta").await;
    let c = fx.bucket("gamma").await;
    let (key_a, key_b) = ("AKVL000000000000000A", "AKVL000000000000000B");
    for k in [key_a, key_b] {
        fx.cat
            .create_access_key(&access_key(k, KeyStatus::Active))
            .await
            .unwrap();
    }
    fx.cat.put_grant(key_a, &a.id, Perm::Rw).await.unwrap();
    fx.cat.put_grant(key_b, &b.id, Perm::Ro).await.unwrap();

    assert_eq!(
        fx.cat.access_key(key_a).await.unwrap(),
        Some(access_key(key_a, KeyStatus::Active))
    );
    assert_eq!(fx.cat.grant(key_a, &a.id).await.unwrap(), Some(Perm::Rw));
    assert_eq!(fx.cat.grant(key_a, &b.id).await.unwrap(), None);
    assert_eq!(fx.cat.grant(key_a, &c.id).await.unwrap(), None);
    assert_eq!(fx.cat.grant(key_b, &a.id).await.unwrap(), None);
    assert_eq!(fx.cat.grant(key_b, &b.id).await.unwrap(), Some(Perm::Ro));
    assert_eq!(
        fx.cat.buckets_for(key_a).await.unwrap(),
        std::slice::from_ref(&a)
    );
    assert_eq!(
        fx.cat.buckets_for(key_b).await.unwrap(),
        std::slice::from_ref(&b)
    );

    // A second grant widens exactly that key; replacing a grant changes
    // the permission without adding a row.
    fx.cat.put_grant(key_a, &c.id, Perm::Ro).await.unwrap();
    fx.cat.put_grant(key_a, &a.id, Perm::Ro).await.unwrap();
    assert_eq!(fx.cat.grant(key_a, &a.id).await.unwrap(), Some(Perm::Ro));
    assert_eq!(fx.cat.buckets_for(key_a).await.unwrap(), [a, c.clone()]);
    assert_eq!(fx.cat.buckets_for(key_b).await.unwrap(), [b]);
    assert_eq!(fx.int("SELECT COUNT(*) FROM grants"), 3);

    // Grants need an existing key and bucket; a key id is unique.
    assert!(fx
        .cat
        .put_grant("AKVL00000000000000ZZ", &c.id, Perm::Rw)
        .await
        .is_err());
    assert!(fx
        .cat
        .put_grant(key_a, &BucketId::new("b_missing"), Perm::Rw)
        .await
        .is_err());
    assert!(fx
        .cat
        .create_access_key(&access_key(key_a, KeyStatus::Active))
        .await
        .is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn disabled_key_behaves_like_an_unknown_key() {
    let fx = Fx::new();
    let a = fx.bucket("alpha").await;
    let (live, off, unknown) = (
        "AKVL000000000000000A",
        "AKVL000000000000000D",
        "AKVL000000000000000U",
    );
    fx.cat
        .create_access_key(&access_key(live, KeyStatus::Active))
        .await
        .unwrap();
    fx.cat
        .create_access_key(&access_key(off, KeyStatus::Disabled))
        .await
        .unwrap();
    fx.cat.put_grant(live, &a.id, Perm::Rw).await.unwrap();
    fx.cat.put_grant(off, &a.id, Perm::Rw).await.unwrap();

    for akid in [off, unknown] {
        assert_eq!(fx.cat.access_key(akid).await.unwrap(), None, "{akid}");
        assert_eq!(fx.cat.grant(akid, &a.id).await.unwrap(), None, "{akid}");
        assert_eq!(fx.cat.buckets_for(akid).await.unwrap(), [], "{akid}");
    }
    assert!(fx.cat.access_key(live).await.unwrap().is_some());

    // Disabling a key that was working takes effect on the next lookup.
    fx.run(&format!(
        "UPDATE access_keys SET status = 'disabled' WHERE access_key_id = '{live}'"
    ));
    assert_eq!(fx.cat.access_key(live).await.unwrap(), None);
    assert_eq!(fx.cat.grant(live, &a.id).await.unwrap(), None);
    assert_eq!(fx.cat.buckets_for(live).await.unwrap(), []);
}

// ---------------------------------------------------------------------------
// Admin status and the safety compare-and-set
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn object_status_reports_stage_and_latest_verification_per_backbone() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let c = fx.commit(&b.id, "k", 2, T0);
    fx.cat.publish(&c).await.unwrap();
    let (x0, x1) = (&c.extents[0].id, &c.extents[1].id);

    let fresh = fx.cat.object_status(&b.id, "k").await.unwrap().unwrap();
    assert_eq!(fresh.generation, c.generation);
    assert_eq!(fresh.extents.len(), 2);
    for (i, e) in fresh.extents.iter().enumerate() {
        assert_eq!(e.extent_id, c.extents[i].id);
        assert_eq!(e.seq, Some(i as u32));
        assert_eq!(
            (e.stage, e.attempts, e.safety_state),
            (Some(OutboxStage::Post), 0, SafetyState::Held)
        );
        assert_eq!((e.last_error.as_deref(), e.backbones.len()), (None, 0));
    }

    fx.run(&format!(
        "UPDATE extents SET article_count = 4, plan_rev = 2 WHERE id = '{x0}';
         UPDATE outbox SET stage = 'verify', attempts = 3, last_error = 'timeout'
           WHERE extent_id = '{x0}';
         DELETE FROM outbox WHERE extent_id = '{x1}';
         INSERT INTO verifications(extent_id, backbone, provider_id, verified_at, plan_rev,
                                   articles_ok, articles_total, result) VALUES
           ('{x0}', 'bb-a', 'p1', 100, 2, 4, 4, 'ok'),
           ('{x0}', 'bb-a', 'p1', 200, 2, 3, 4, 'missing'),
           ('{x0}', 'bb-b', 'p2', 100, 2, 3, 4, 'missing'),
           ('{x0}', 'bb-b', 'p2', 300, 2, 4, 4, 'ok'),
           ('{x0}', 'bb-c', 'p3', 900, 1, 4, 4, 'ok'),
           ('{x0}', 'bb-d', 'p4', 400, 2, 3, 3, 'ok');"
    ));
    let status = fx.cat.object_status(&b.id, "k").await.unwrap().unwrap();
    let e0 = &status.extents[0];
    assert_eq!(
        (e0.stage, e0.attempts, e0.last_error.as_deref()),
        (Some(OutboxStage::Verify), 3, Some("timeout"))
    );
    let seen: Vec<_> = e0
        .backbones
        .iter()
        .map(|s| (s.backbone.as_str(), s.verified_at.0, s.result, s.counts))
        .collect();
    assert_eq!(
        seen,
        [
            // A newer failure cancels the older pass.
            ("bb-a", 200, VerifyResult::Missing, false),
            ("bb-b", 300, VerifyResult::Ok, true),
            // bb-c only has a row for an old plan: not reported.
            // bb-d verified fewer articles than the plan holds.
            ("bb-d", 400, VerifyResult::Ok, false),
        ]
    );
    let e1 = &status.extents[1];
    assert_eq!((e1.stage, e1.attempts, e1.backbones.len()), (None, 0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn set_safety_state_is_a_compare_and_set() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let c = fx.commit(&b.id, "k", 2, T0);
    fx.cat.publish(&c).await.unwrap();
    let (x0, x1) = (&c.extents[0].id, &c.extents[1].id);
    use SafetyState::{Deleted, Held, Released};

    assert!(fx.cat.set_safety_state(x0, Held, Deleted).await.unwrap());
    // The loser of a race, a wrong `from`, and an unknown extent write nothing.
    assert!(!fx.cat.set_safety_state(x0, Held, Deleted).await.unwrap());
    assert!(!fx
        .cat
        .set_safety_state(x1, Released, Deleted)
        .await
        .unwrap());
    assert!(!fx
        .cat
        .set_safety_state(&ExtentId::new("x_missing"), Held, Deleted)
        .await
        .unwrap());

    let (_, extents) = fx.cat.live_object(&b.id, "k").await.unwrap().unwrap();
    assert_eq!(
        [extents[0].safety_state, extents[1].safety_state],
        [Deleted, Held]
    );
    let status = fx.cat.object_status(&b.id, "k").await.unwrap().unwrap();
    assert_eq!(status.extents[0].safety_state, Deleted);
}

// ---------------------------------------------------------------------------
// Ids on one key are in commit order
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_commit_under_an_older_or_equal_id_is_refused() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let v1 = fx.put(&b.id, "k", T0.plus_ms(10)).await;
    let before = fx.footprint();
    assert_eq!(
        fx.cat.newest_id(&b.id, "k").await.unwrap(),
        Some(v1.generation.id.clone())
    );

    // Older by the clock; and in the same millisecond with random bytes
    // that sort first (the fixture counts its seeds up, so a later one
    // sorts after: build the smaller one by hand).
    let older = fx.commit(&b.id, "k", 1, T0);
    assert_eq!(fx.cat.publish(&older).await.unwrap(), Guard::Lost);
    let mut same_ms = fx.commit(&b.id, "k", 1, T0.plus_ms(10));
    let id = GenerationId::mint(T0.plus_ms(10), [0; 8]);
    assert!(id < v1.generation.id);
    same_ms.extents[0].generation_id = Some(id.clone());
    same_ms.generation.id = id;
    assert_eq!(fx.cat.publish(&same_ms).await.unwrap(), Guard::Lost);
    // The id of the live generation itself: refused, not a key clash.
    let mut again = fx.commit(&b.id, "k", 1, T0.plus_ms(10));
    again.extents[0].generation_id = Some(v1.generation.id.clone());
    again.generation.id = v1.generation.id.clone();
    assert_eq!(fx.cat.publish(&again).await.unwrap(), Guard::Lost);
    assert_eq!(fx.footprint(), before);

    // Another key and another bucket are not held back by this one.
    let other = fx.bucket("beta").await;
    fx.put(&b.id, "k2", T0).await;
    fx.put(&other.id, "k", T0).await;
    // A later one in the same millisecond is in order.
    let later = fx.commit(&b.id, "k", 1, T0.plus_ms(10));
    assert!(later.generation.id > v1.generation.id);
    assert_eq!(fx.cat.publish(&later).await.unwrap(), Guard::Applied(()));
}

#[tokio::test(flavor = "current_thread")]
async fn a_commit_must_sort_after_the_last_tombstone_of_the_key() {
    let fx = Fx::new();
    let b = fx.bucket("alpha").await;
    let v1 = fx.put(&b.id, "k", T0).await;
    assert_eq!(fx.cat.newest_id(&b.id, "nope").await.unwrap(), None);

    // A tombstone that does not sort after the live generation deletes
    // nothing and is not remembered.
    assert!(!fx
        .cat
        .delete_object_before(&b.id, "k", &v1.generation.id, T0.plus_ms(1))
        .await
        .unwrap());
    assert_eq!(fx.int("SELECT COUNT(*) FROM key_tombstones"), 0);

    let tombstone = GenerationId::mint(T0.plus_ms(50), [9; 8]);
    assert!(fx
        .cat
        .delete_object_before(&b.id, "k", &tombstone, T0.plus_ms(50))
        .await
        .unwrap());
    assert!(fx.cat.live_object(&b.id, "k").await.unwrap().is_none());
    assert_eq!(
        fx.cat.newest_id(&b.id, "k").await.unwrap(),
        Some(tombstone.clone())
    );

    // Older than the tombstone, and the tombstone's own id: refused.
    let older = fx.commit(&b.id, "k", 1, T0.plus_ms(20));
    assert_eq!(fx.cat.publish(&older).await.unwrap(), Guard::Lost);
    let mut equal = fx.commit(&b.id, "k", 1, T0.plus_ms(50));
    equal.extents[0].generation_id = Some(tombstone.clone());
    equal.generation.id = tombstone.clone();
    assert_eq!(fx.cat.publish(&equal).await.unwrap(), Guard::Lost);
    assert!(fx.cat.live_object(&b.id, "k").await.unwrap().is_none());
    assert_eq!(fx.int("SELECT COUNT(*) FROM key_tombstones"), 1);

    // After it: published, and the tombstone row has done its work.
    let newer = fx.commit(&b.id, "k", 1, T0.plus_ms(51));
    assert_eq!(fx.cat.publish(&newer).await.unwrap(), Guard::Applied(()));
    assert_eq!(fx.int("SELECT COUNT(*) FROM key_tombstones"), 0);
    assert_eq!(
        fx.cat.newest_id(&b.id, "k").await.unwrap(),
        Some(newer.generation.id.clone())
    );
}
