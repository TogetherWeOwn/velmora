//! The set-based publish (`sql::publish`) over the selected catalogue
//! backend: CompleteMultipartUpload and a recovery replay give a
//! generation its extents with one or two statements per value of
//! placements instead of one or two per extent.
//!
//! Every batch goes through [`Rec`]. It records what was sent, sets the
//! row limit of a value to 100 so that an object of a few hundred
//! extents spans three values, and can run a batch the way it was built
//! before: the set statements swapped for the per-extent statements
//! they replace ([`per_extent`]), everything else as it is. The two
//! must leave the same catalogue.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use velmora_bridge::recovery::Recorded;
use velmora_bridge::replay::{ReplayExtent, ReplayPublish};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{PublishUnrecorded, TestSql};
use velmora_bridge::*;

const T0: UnixMs = UnixMs(1_762_992_000_123);
const KEY: &str = "dir/big file.bin";
const DIGEST: [u8; 32] = [0xd1; 32];
/// Rows per value in these tests.
const ROWS: usize = 100;

/// What D1 answered to the first query after a large refused batch.
const OVERLOADED: &str =
    "D1_ERROR: D1 DB is overloaded. Too many resources consumed within a 10 second window.";

type Stmt = (&'static str, Vec<SqlValue>);

// ---------------------------------------------------------------------------
// The statements the set-based ones replace, as they were
// ---------------------------------------------------------------------------

const OLD_ADOPT_UPLOAD: &str =
    "UPDATE extents SET generation_id = ?1, seq = ?2, plain_offset = ?3, \
       state = 'committed' \
     WHERE id = ?4 AND bucket_id = ?5 AND state = 'staged' AND generation_id IS NULL \
       AND (EXISTS (SELECT 1 FROM upload_parts \
                     WHERE extent_id = ?4 AND upload_id = ?6) \
            OR EXISTS (SELECT 1 FROM upload_part_extents \
                        WHERE extent_id = ?4 AND upload_id = ?6))";

const OLD_ADOPT_RECORD: &str =
    "UPDATE extents SET generation_id = ?1, seq = ?2, plain_offset = ?3, \
       state = 'committed' \
     WHERE id = ?4 AND bucket_id = ?5 AND state = 'staged' AND generation_id IS NULL";

const OLD_REFERENCE: &str =
    "INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
     SELECT ?1, ?2, e.id, ?3 FROM extents e \
      WHERE e.id = ?4 AND e.bucket_id = ?5 AND e.state = 'committed' \
        AND e.generation_id <> ?1";

fn is_set(sql: &str) -> bool {
    sql.starts_with("WITH m(extent_id")
}

fn is_adopt(sql: &str) -> bool {
    is_set(sql) && sql.contains("UPDATE extents SET")
}

fn is_reference(sql: &str) -> bool {
    is_set(sql) && sql.contains("INTO generation_extents")
}

/// The placements of a bound value.
fn placements_of(value: &SqlValue) -> Vec<(String, u32, u64)> {
    let SqlValue::Text(json) = value else {
        panic!("placements are bound as text: {value:?}");
    };
    serde_json::from_str(json).unwrap()
}

/// The batch as it was built before: per extent, one adopt statement for
/// an upload, and an adopt and a reference statement for a record.
fn per_extent(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut stmts = stmts.into_iter().peekable();
    while let Some((sql, params)) = stmts.next() {
        if !is_set(sql) {
            out.push((sql, params));
            continue;
        }
        assert!(is_adopt(sql), "a reference follows its adopt: {sql}");
        let row = |(id, seq, off): &(String, u32, u64)| {
            vec![
                params[0].clone(),
                SqlValue::Int(i64::from(*seq)),
                SqlValue::Int(i64::try_from(*off).unwrap()),
                SqlValue::Text(id.clone()),
                params[2].clone(),
            ]
        };
        let placed = placements_of(&params[1]);
        if let Some(upload) = params.get(3) {
            for p in &placed {
                let mut bound = row(p);
                bound.push(upload.clone());
                out.push((OLD_ADOPT_UPLOAD, bound));
            }
            continue;
        }
        let (next, reference) = stmts.next().expect("a record references what it adopts");
        assert!(is_reference(next));
        assert_eq!(reference, params, "both statements bind the same value");
        for p in &placed {
            out.push((OLD_ADOPT_RECORD, row(p)));
            out.push((OLD_REFERENCE, row(p)));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The recording adapter
// ---------------------------------------------------------------------------

enum Fault {
    /// The batch ends with a failing `tx_guard` insert.
    Guard,
    /// The batch does not run and reports this.
    NotRun(&'static str),
    /// The batch commits and reports this.
    Unreported(&'static str),
}

struct Rec {
    db: TestSql,
    /// Run batches the way they were built before ([`per_extent`]).
    old: Cell<bool>,
    /// One per batch to come, taken from the front.
    faults: RefCell<VecDeque<Fault>>,
    /// Every batch as the catalogue sent it.
    batches: RefCell<Vec<Vec<Stmt>>>,
    /// Every query as the catalogue sent it.
    queries: RefCell<Vec<(String, Vec<SqlValue>)>>,
    /// Limits other than the ones of the tests above.
    limits: Cell<Option<SqlLimits>>,
    /// Answer reads as overloaded once a batch was refused by a guard,
    /// until something waits: what D1 does after a large refused batch.
    throttles: Cell<bool>,
    throttled: Cell<bool>,
    /// Whether [`Sql::query_after_refusal`] waits the way the D1
    /// adapter does. Without it the method is the one of the trait.
    patient: Cell<bool>,
    /// Reads that waited.
    waited: Cell<u32>,
}

impl Sql for Rec {
    fn dialect(&self) -> Dialect {
        self.db.dialect()
    }
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.queries
            .borrow_mut()
            .push((sql.to_owned(), params.to_vec()));
        if self.throttled.get() {
            return Err(BridgeError::Sql(OVERLOADED.into()));
        }
        self.db.query(sql, params).await
    }
    async fn query_after_refusal(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        if self.patient.get() && self.throttled.replace(false) {
            self.waited.set(self.waited.get() + 1);
        }
        self.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.db.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<Stmt>) -> Result<Vec<u64>> {
        self.batches.borrow_mut().push(stmts.clone());
        let mut stmts = if self.old.get() {
            per_extent(stmts)
        } else {
            stmts
        };
        let fault = self.faults.borrow_mut().pop_front();
        let ran = match fault {
            None if self.old.get() => self.db.fixture_batch(stmts).await,
            None => self.db.batch(stmts).await,
            Some(Fault::Guard) => {
                stmts.push(("INSERT INTO tx_guard(ok) VALUES (0)", vec![]));
                self.db.fixture_batch(stmts).await
            }
            Some(Fault::NotRun(message)) => Err(BridgeError::Sql(message.into())),
            Some(Fault::Unreported(message)) => {
                self.db.batch(stmts).await?;
                Err(BridgeError::Sql(message.into()))
            }
        };
        if self.throttles.get() && matches!(ran, Err(BridgeError::GuardFailed)) {
            self.throttled.set(true);
        }
        ran
    }
    fn limits(&self) -> SqlLimits {
        self.limits.get().unwrap_or(SqlLimits {
            set_rows: ROWS,
            ..SqlLimits::D1
        })
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fx {
    cat: SqlCatalog<Rec>,
    seed: Cell<u32>,
    bucket: BucketId,
    other_bucket: BucketId,
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}

fn target<'a>(bucket: &'a BucketId, key: &'a str, id: &'a UploadId) -> UploadTarget<'a> {
    UploadTarget { bucket, key, id }
}

/// An upload ready to be completed.
struct Staged {
    id: UploadId,
    commit: CompleteUpload,
    revision: u64,
    /// The extents the commit lists, in order.
    extents: Vec<ExtentId>,
}

/// Generations of a recovery record: their rows and placements.
struct Recorded3 {
    first: (GenerationRow, Vec<ExtentPlacement>),
    copy: (GenerationRow, Vec<ExtentPlacement>),
    newer: (GenerationRow, Vec<ExtentPlacement>),
}

impl Fx {
    /// `old`: batches run the way they were built before.
    async fn new(old: bool) -> Fx {
        let fx = Fx {
            cat: SqlCatalog::new(Rec {
                db: if old {
                    TestSql::with_schema_unrecorded()
                } else {
                    TestSql::with_schema()
                }
                .unwrap(),
                old: Cell::new(old),
                faults: RefCell::new(VecDeque::new()),
                batches: RefCell::new(Vec::new()),
                queries: RefCell::new(Vec::new()),
                limits: Cell::new(None),
                throttles: Cell::new(false),
                throttled: Cell::new(false),
                patient: Cell::new(false),
                waited: Cell::new(0),
            }),
            seed: Cell::new(1),
            bucket: BucketId::mint([0xb1; 8]),
            other_bucket: BucketId::mint([0xb2; 8]),
        };
        for (id, name) in [(&fx.bucket, "one"), (&fx.other_bucket, "two")] {
            fx.run(
                "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, \
                 created_at) VALUES (?1, ?2, 'owner', ?3, 1, 1, 0)",
                &[text(id.as_str()), text(name), SqlValue::Blob(vec![7])],
            )
            .await;
        }
        fx
    }

    fn sql(&self) -> &Rec {
        &self.cat.sql
    }

    fn next(&self) -> u32 {
        let n = self.seed.get();
        self.seed.set(n + 1);
        n
    }

    /// `N` bytes that differ for every `n`.
    fn bytes<const N: usize>(n: u32) -> [u8; N] {
        let mut out = [0xe0; N];
        out[N - 4..].copy_from_slice(&n.to_be_bytes());
        out
    }

    async fn run(&self, sql: &str, params: &[SqlValue]) -> u64 {
        self.sql().db.fixture_exec(sql, params).await.unwrap()
    }

    async fn count(&self, sql: &str) -> i64 {
        match self.sql().db.fixture_query(sql, &[]).await.unwrap()[0][0] {
            SqlValue::Int(n) => n,
            ref other => panic!("not an integer: {other:?}"),
        }
    }

    /// Every row of every table, by table and then sorted.
    async fn dump(&self) -> Vec<String> {
        let db = &self.sql().db;
        let names = db.fixture(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
            "SELECT table_name::text FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' ORDER BY table_name",
        );
        let tables = db.fixture_query(names, &[]).await.unwrap();
        let mut out = Vec::new();
        for table in tables {
            let SqlValue::Text(name) = &table[0] else {
                panic!("a table name is text");
            };
            let rows = db
                .fixture_query(&format!("SELECT * FROM {name}"), &[])
                .await;
            let mut rows: Vec<String> = rows
                .unwrap()
                .iter()
                .map(|r| format!("{name}: {r:?}"))
                .collect();
            rows.sort();
            out.extend(rows);
        }
        out
    }

    /// The plan SQLite makes for a statement, a line per step.
    async fn plan(&self, sql: &str, params: &[SqlValue]) -> Vec<String> {
        let rows = self
            .sql()
            .db
            .fixture_query(&format!("EXPLAIN QUERY PLAN {sql}"), params)
            .await
            .unwrap();
        rows.into_iter()
            .map(|r| match r.into_iter().nth(3) {
                Some(SqlValue::Text(detail)) => detail,
                other => panic!("no plan detail: {other:?}"),
            })
            .collect()
    }

    fn extent(&self, bucket: &BucketId, size: u64) -> ExtentRow {
        let n = self.next();
        ExtentRow {
            id: ExtentId::mint(Self::bytes(n)),
            bucket_id: bucket.clone(),
            generation_id: None,
            state: ExtentState::Staged,
            seq: None,
            plain_offset: None,
            plain_size: size,
            cipher_size: size + 64,
            media_header: Self::bytes::<48>(n).to_vec(),
            key_mode: 1,
            wrapped_file_key: Some(Self::bytes::<73>(n).to_vec()),
            plain_md5: Self::bytes(n),
            plain_sha256: Self::bytes(n),
            cipher_sha256: Self::bytes(n),
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: T0,
        }
    }

    async fn create(&self, bucket: &BucketId, key: &str) -> UploadId {
        let id = UploadId::mint(Self::bytes(self.next()));
        self.cat
            .create_upload(&UploadRow {
                id: id.clone(),
                bucket_id: bucket.clone(),
                key: key.into(),
                content_json: "{}".into(),
                user_meta_json: "{}".into(),
                state: UploadState::Open,
                revision: 0,
                completed_generation_id: None,
                complete_digest: None,
                result_etag: None,
                initiated_at: T0,
            })
            .await
            .unwrap();
        id
    }

    /// Stores part `number` as one extent of `size` bytes.
    async fn part(&self, t: &UploadTarget<'_>, number: u16, size: u64) -> ExtentId {
        let e = self.extent(t.bucket, size);
        let part = UploadPartRow {
            upload_id: t.id.clone(),
            part_number: number,
            extent_id: e.id.clone(),
            size,
            etag: format!("\"etag-{number}\""),
            uploaded_at: T0,
        };
        let stored = self.cat.put_upload_part(t, &part, &e, T0).await.unwrap();
        assert_eq!(stored, Guard::Applied(()));
        e.id
    }

    /// Stores part `number` as one extent per size.
    async fn sliced(&self, t: &UploadTarget<'_>, number: u16, sizes: &[u64]) -> Vec<ExtentId> {
        let extents: Vec<ExtentRow> = sizes.iter().map(|s| self.extent(t.bucket, *s)).collect();
        let ids: Vec<ExtentId> = extents.iter().map(|e| e.id.clone()).collect();
        let write = WriteId::mint(Self::bytes(self.next()));
        let opened = self.cat.open_intents(&write, &ids, T0).await.unwrap();
        assert_eq!(opened, Guard::Applied(()));
        let part = UploadPartRow {
            upload_id: t.id.clone(),
            part_number: number,
            extent_id: ids[0].clone(),
            size: sizes.iter().sum(),
            etag: format!("\"etag-{number}\""),
            uploaded_at: T0,
        };
        let stored = self
            .cat
            .put_upload_part_sliced(t, &part, &extents, &write, T0)
            .await
            .unwrap();
        assert_eq!(stored, Guard::Applied(()));
        ids
    }

    fn generation(&self, bucket: &BucketId, key: &str, at: UnixMs, sizes: &[u64]) -> GenerationRow {
        GenerationRow {
            id: GenerationId::mint(at, Self::bytes(self.next())),
            bucket_id: bucket.clone(),
            key: key.into(),
            state: GenerationState::Live,
            size: sizes.iter().sum(),
            etag: format!("\"abc-{}\"", sizes.len()),
            checksum_json: None,
            content_json: "{}".into(),
            user_meta_json: "{}".into(),
            extent_count: sizes.len() as u32,
            created_at: at,
            retired_at: None,
        }
    }

    /// The commit of `extents`, placed end to end.
    fn commit(&self, bucket: &BucketId, key: &str, extents: &[(ExtentId, u64)]) -> CompleteUpload {
        let sizes: Vec<u64> = extents.iter().map(|(_, size)| *size).collect();
        let ids: Vec<ExtentId> = extents.iter().map(|(id, _)| id.clone()).collect();
        CompleteUpload {
            generation: self.generation(bucket, key, T0, &sizes),
            placements: placed(&ids, &sizes),
            now: T0.plus_ms(5),
        }
    }

    async fn revision(&self, t: &UploadTarget<'_>) -> u64 {
        self.cat
            .upload(t)
            .await
            .unwrap()
            .expect("upload")
            .0
            .revision
    }

    /// An open upload on `key` of `bucket` with `parts` one-extent parts
    /// of `size(i)` bytes, and the commit that lists them all.
    async fn staged(
        &self,
        bucket: &BucketId,
        key: &str,
        parts: u16,
        size: impl Fn(u16) -> u64,
    ) -> Staged {
        let id = self.create(bucket, key).await;
        let t = target(bucket, key, &id);
        let mut listed = Vec::new();
        for number in 1..=parts {
            listed.push((self.part(&t, number, size(number)).await, size(number)));
        }
        Staged {
            commit: self.commit(bucket, key, &listed),
            revision: self.revision(&t).await,
            extents: listed.into_iter().map(|(id, _)| id).collect(),
            id,
        }
    }

    /// A key that has a live object, and an upload on it: 230 parts of
    /// one extent, a part of three, and a part the commit does not list.
    /// 233 extents, so three values of placements.
    async fn staged_large(&self) -> Staged {
        let small = self.staged(&self.bucket, KEY, 2, |_| 64).await;
        assert_eq!(self.complete(&small, None).await, Guard::Applied(()));

        let id = self.create(&self.bucket, KEY).await;
        let t = target(&self.bucket, KEY, &id);
        let size = |number: u16| 100 + u64::from(number % 7);
        let mut listed = Vec::new();
        for number in 1..=230 {
            listed.push((self.part(&t, number, size(number)).await, size(number)));
        }
        for (x, size) in self
            .sliced(&t, 231, &[90, 80, 70])
            .await
            .into_iter()
            .zip([90, 80, 70])
        {
            listed.push((x, size));
        }
        self.part(&t, 232, 50).await;
        Staged {
            commit: self.commit(&self.bucket, KEY, &listed),
            revision: self.revision(&t).await,
            extents: listed.into_iter().map(|(id, _)| id).collect(),
            id,
        }
    }

    async fn complete(&self, s: &Staged, condition: Option<&Precondition>) -> Guard<()> {
        let g = &s.commit.generation;
        let t = target(&g.bucket_id, &g.key, &s.id);
        self.cat
            .publish_upload_if(&t, s.revision, &DIGEST, &s.commit, condition)
            .await
            .unwrap()
    }

    /// Stores staged extents the way a replay does (step 1).
    async fn replayed(&self, sizes: &[u64]) -> Vec<ExtentId> {
        let bucket = Bucket {
            id: self.bucket.clone(),
            name: "one".into(),
            owner: "owner".into(),
            bdk_wrapped: vec![7],
            kek_version: 1,
            disposable: true,
            created_at: UnixMs(0),
        };
        let extents: Vec<ReplayExtent> = sizes
            .iter()
            .map(|size| ReplayExtent {
                row: self.extent(&self.bucket, *size),
                plan: None,
                packed: None,
                parity: None,
                safety_present: true,
            })
            .collect();
        for chunk in extents.chunks(50) {
            let stranded = self.cat.replay_extents(&bucket, chunk, T0).await.unwrap();
            assert!(stranded.is_empty());
        }
        extents.into_iter().map(|x| x.row.id).collect()
    }

    /// Three generations as a recovery record names them, their extents
    /// stored: `first` on key `a` (150 extents); `copy` on key `b`, of
    /// 100 extents of its own and then 120 of `first` (three values,
    /// shared and own extents in one); and `newer`, which replaces
    /// `first` on key `a` while `copy` still reads its extents.
    async fn recorded(&self) -> Recorded3 {
        let size = |i: usize| 100 + (i % 5) as u64;
        let sizes: Vec<u64> = (0..150).map(size).collect();
        let ids = self.replayed(&sizes).await;
        let first = (
            self.generation(&self.bucket, "a", T0, &sizes),
            placed(&ids, &sizes),
        );

        let own: Vec<u64> = (0..100).map(|i| 200 + (i % 3) as u64).collect();
        let mut copy_ids = self.replayed(&own).await;
        let mut copy_sizes = own;
        copy_ids.extend(ids[10..130].iter().cloned());
        copy_sizes.extend(&sizes[10..130]);
        let copy = (
            self.generation(&self.bucket, "b", T0.plus_ms(1), &copy_sizes),
            placed(&copy_ids, &copy_sizes),
        );

        let sizes = [300, 301, 302, 303, 304];
        let ids = self.replayed(&sizes).await;
        let newer = (
            self.generation(&self.bucket, "a", T0.plus_ms(2), &sizes),
            placed(&ids, &sizes),
        );
        Recorded3 { first, copy, newer }
    }

    async fn replay(&self, g: &(GenerationRow, Vec<ExtentPlacement>)) -> ReplayPublish {
        self.cat
            .replay_publish(&g.0, &g.1, T0.plus_secs(9))
            .await
            .unwrap()
    }

    /// The set statements of the last batch.
    fn last_set_statements(&self) -> Vec<Stmt> {
        let batches = self.sql().batches.borrow();
        let last = batches.last().expect("a batch was sent");
        last.iter()
            .filter(|(sql, _)| is_set(sql))
            .cloned()
            .collect()
    }

    fn last_batch_len(&self) -> usize {
        self.sql().batches.borrow().last().expect("a batch").len()
    }
}

#[cfg(feature = "testkit-pg")]
#[tokio::test]
async fn replay_executes_every_legal_unreadable_plan_window() {
    if !TestSql::postgres_selected() {
        return;
    }
    let fx = Fx::new(false).await;
    for size in 1..=50 {
        assert_eq!(fx.replayed(&vec![5; size]).await.len(), size);
    }
}

/// `ids` end to end, in order.
fn placed(ids: &[ExtentId], sizes: &[u64]) -> Vec<ExtentPlacement> {
    let mut offset = 0;
    ids.iter()
        .zip(sizes)
        .enumerate()
        .map(|(i, (id, size))| {
            let p = ExtentPlacement {
                extent_id: id.clone(),
                seq: i as u32,
                plain_offset: offset,
            };
            offset += size;
            p
        })
        .collect()
}

// ---------------------------------------------------------------------------
// One builder, a statement or two per value
// ---------------------------------------------------------------------------

#[tokio::test]
async fn complete_sends_one_adopt_statement_per_value_of_placements() {
    let fx = Fx::new(false).await;
    let s = fx.staged_large().await;
    assert_eq!(s.commit.placements.len(), 233);
    assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));
    // 16 statements and one per value: 100, 100 and 33 placements.
    assert_eq!(fx.last_batch_len(), 16 + 3);
    let set = fx.last_set_statements();
    assert_eq!(set.len(), 3);
    assert!(set.iter().all(|(sql, p)| is_adopt(sql) && p.len() == 4));
    let rows: Vec<usize> = set
        .iter()
        .map(|(_, p)| placements_of(&p[1]).len())
        .collect();
    assert_eq!(rows, [100, 100, 33]);

    // A conditional Complete has its condition as one statement more.
    let fx = Fx::new(false).await;
    let s = fx.staged(&fx.bucket, KEY, 233, |_| 100).await;
    assert_eq!(
        fx.complete(&s, Some(&Precondition::Absent)).await,
        Guard::Applied(())
    );
    assert_eq!(fx.last_batch_len(), 17 + 3);

    // The batch does not grow with the extents: one value, one statement.
    let fx = Fx::new(false).await;
    let s = fx.staged(&fx.bucket, KEY, 100, |_| 100).await;
    assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));
    assert_eq!(fx.last_batch_len(), 16 + 1);
}

#[tokio::test]
async fn a_replay_sends_two_statements_per_value_of_placements() {
    let fx = Fx::new(false).await;
    let r = fx.recorded().await;
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
    assert_eq!(fx.last_batch_len(), 12 + 2 * 2);
    assert_eq!(r.copy.1.len(), 220);
    assert_eq!(fx.replay(&r.copy).await, ReplayPublish::Published);
    assert_eq!(fx.last_batch_len(), 12 + 2 * 3);
    let set = fx.last_set_statements();
    assert_eq!(set.len(), 6);
    for pair in set.chunks(2) {
        assert!(is_adopt(pair[0].0) && is_reference(pair[1].0));
        assert_eq!(pair[0].1, pair[1].1);
        assert_eq!(pair[0].1.len(), 3);
    }
    // Both paths adopt with the same statement: a Complete adds only
    // the condition that the extent is a part of its upload.
    let record = set[0].0;
    let live = Fx::new(false).await;
    let s = live.staged(&live.bucket, KEY, 3, |_| 100).await;
    assert_eq!(live.complete(&s, None).await, Guard::Applied(()));
    let upload = live.last_set_statements()[0].0;
    assert!(upload.starts_with(record) && upload.len() > record.len());
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// The values are the outer loop, and every extent is found by its
/// primary key. Any other plan reads the whole value once per row.
fn assert_driven_by_the_values(plan: &[String], table: &str, index: &str) {
    let at = |what: &str| plan.iter().position(|step| step.contains(what));
    let scan = at("SCAN json_each")
        .or(at("SCAN j VIRTUAL TABLE"))
        .unwrap_or_else(|| panic!("no scan of the value: {plan:#?}"));
    let search = format!("SEARCH {table} USING ");
    let found = at(&search).unwrap_or_else(|| panic!("no search of {table}: {plan:#?}"));
    assert!(scan < found, "{plan:#?}");
    assert!(plan[found].contains(index), "{plan:#?}");
    let scans_a_table = plan.iter().any(|step| {
        step.starts_with("SCAN")
            && !step.contains("json_each")
            && !step.starts_with("SCAN j VIRTUAL TABLE")
            && step != "SCAN m"
    });
    assert!(!scans_a_table, "{plan:#?}");
    assert!(
        !plan.iter().any(|s| s.contains("extents_by_generation")),
        "{plan:#?}"
    );
}

const EXTENTS_BY_ID: &str = "INDEX sqlite_autoindex_extents_1 (id=?)";

#[tokio::test]
async fn the_set_statements_find_each_extent_by_its_primary_key() {
    if TestSql::postgres_selected() {
        return; // sqlite_only: asserts SQLite EXPLAIN QUERY PLAN output.
    }
    // Complete.
    let fx = Fx::new(false).await;
    let s = fx.staged_large().await;
    assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));
    for (sql, params) in fx.last_set_statements() {
        let plan = fx.plan(sql, &params).await;
        assert_driven_by_the_values(&plan, "extents", EXTENTS_BY_ID);
    }

    // Replay: adopt and reference, and the two checks that read the
    // extents of the placements.
    let fx = Fx::new(false).await;
    let r = fx.recorded().await;
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
    assert_eq!(fx.replay(&r.copy).await, ReplayPublish::Published);
    for (sql, params) in fx.last_set_statements() {
        let plan = fx.plan(sql, &params).await;
        let table = if is_adopt(sql) { "extents" } else { "e" };
        assert_driven_by_the_values(&plan, table, EXTENTS_BY_ID);
    }
    // A generation that does not tile, on a key with an older one: the
    // "unread" check runs before the batch and the "lost" check after.
    fx.sql().queries.borrow_mut().clear();
    let mut bad = (r.newer.0.clone(), r.newer.1.clone());
    bad.0.size += 1;
    assert_eq!(fx.replay(&bad).await, ReplayPublish::Refused);
    let checks: Vec<(String, Vec<SqlValue>)> = fx
        .sql()
        .queries
        .borrow()
        .iter()
        .filter(|(sql, _)| sql.contains("json_each"))
        .cloned()
        .collect();
    assert_eq!(checks.len(), 2, "{checks:#?}");
    for (sql, params) in &checks {
        let plan = fx.plan(sql, params).await;
        assert_driven_by_the_values(&plan, "e", EXTENTS_BY_ID);
    }

    // The comparison with the live generation: its references, by key.
    fx.sql().queries.borrow_mut().clear();
    let twin = fx.cat.replay_twin(&r.copy.0, &r.copy.1).await.unwrap();
    assert_eq!(twin.as_ref(), Some(&r.copy.0.id));
    let compared: Vec<(String, Vec<SqlValue>)> = fx
        .sql()
        .queries
        .borrow()
        .iter()
        .filter(|(sql, _)| sql.contains("json_each"))
        .cloned()
        .collect();
    assert_eq!(compared.len(), 3);
    for (sql, params) in &compared {
        let plan = fx.plan(sql, params).await;
        assert_driven_by_the_values(&plan, "ge", "(generation_id=? AND seq=?)");
    }
}

// ---------------------------------------------------------------------------
// The same catalogue as the per-extent statements leave
// ---------------------------------------------------------------------------

#[tokio::test]
async fn complete_leaves_the_rows_the_per_extent_statements_left() {
    let (new, old) = (Fx::new(false).await, Fx::new(true).await);
    let mut dumps = Vec::new();
    for fx in [&new, &old] {
        let s = fx.staged_large().await;
        assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));
        // The object is what the commit says, in both.
        let g = s.commit.generation.id.as_str();
        let placed = fx
            .sql()
            .db
            .fixture_query(
                "SELECT e.id, ge.seq, ge.plain_offset, e.seq, e.plain_offset \
                   FROM generation_extents ge JOIN extents e ON e.id = ge.extent_id \
                  WHERE ge.generation_id = ?1 AND e.generation_id = ?1 \
                    AND e.state = 'committed' ORDER BY ge.seq",
                &[text(g)],
            )
            .await
            .unwrap();
        let want: Vec<Row> = s
            .commit
            .placements
            .iter()
            .map(|p| {
                let (seq, off) = (i64::from(p.seq), p.plain_offset as i64);
                vec![
                    text(p.extent_id.as_str()),
                    SqlValue::Int(seq),
                    SqlValue::Int(off),
                    SqlValue::Int(seq),
                    SqlValue::Int(off),
                ]
            })
            .collect();
        assert_eq!(placed, want);
        assert_eq!(fx.count("SELECT COUNT(*) FROM outbox").await, 233 + 2);
        dumps.push(fx.dump().await);
    }
    // The old run really was per extent.
    assert_eq!(new.last_set_statements().len(), 3);
    assert!(old.sql().old.get());
    assert_eq!(dumps[0], dumps[1]);
    assert!(dumps[0].len() > 900);
}

#[tokio::test]
async fn a_replay_leaves_the_rows_the_per_extent_statements_left() {
    let (new, old) = (Fx::new(false).await, Fx::new(true).await);
    let mut dumps = Vec::new();
    for fx in [&new, &old] {
        let r = fx.recorded().await;
        for g in [&r.first, &r.copy, &r.newer] {
            assert_eq!(fx.replay(g).await, ReplayPublish::Published);
        }
        // `copy` holds 100 extents of its own and shares 120.
        let own = format!(
            "SELECT COUNT(*) FROM extents WHERE generation_id = '{}'",
            r.copy.0.id
        );
        assert_eq!(fx.count(&own).await, 100);
        let held = format!(
            "SELECT COUNT(*) FROM generation_extents WHERE generation_id = '{}'",
            r.copy.0.id
        );
        assert_eq!(fx.count(&held).await, 220);
        assert_eq!(
            fx.cat.replay_twin(&r.copy.0, &r.copy.1).await.unwrap(),
            Some(r.copy.0.id.clone())
        );
        dumps.push(fx.dump().await);
    }
    assert_eq!(dumps[0], dumps[1]);
    assert!(dumps[0].len() > 900);
}

// ---------------------------------------------------------------------------
// Again, and not at all
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publishing_again_changes_nothing() {
    // Complete: the call again is refused, and its statements again, on
    // their own, take nothing.
    let fx = Fx::new(false).await;
    let s = fx.staged_large().await;
    assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));
    let set = fx.last_set_statements();
    let before = fx.dump().await;
    assert_eq!(fx.complete(&s, None).await, Guard::Lost);
    assert_eq!(fx.dump().await, before);
    let changed = fx.sql().db.fixture_batch(set).await.unwrap();
    assert_eq!(changed, [0, 0, 0]);
    assert_eq!(fx.dump().await, before);

    // Replay.
    let fx = Fx::new(false).await;
    let r = fx.recorded().await;
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
    assert_eq!(fx.replay(&r.copy).await, ReplayPublish::Published);
    let set = fx.last_set_statements();
    let before = fx.dump().await;
    assert_eq!(fx.replay(&r.copy).await, ReplayPublish::Refused);
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Refused);
    assert_eq!(fx.dump().await, before);
    let changed = fx.sql().db.fixture_batch(set).await.unwrap();
    assert_eq!(changed, [0; 6]);
    assert_eq!(fx.dump().await, before);
}

#[tokio::test]
async fn a_failure_of_the_last_statement_takes_every_value_back() {
    let fx = Fx::new(false).await;
    let s = fx.staged_large().await;
    let before = fx.dump().await;
    fx.sql().faults.borrow_mut().push_back(Fault::Guard);
    assert_eq!(fx.complete(&s, None).await, Guard::Lost);
    // All three values ran before it, and none of them is left.
    assert_eq!(fx.last_batch_len(), 16 + 3);
    assert_eq!(fx.dump().await, before);
    // The same commit then publishes.
    assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));

    let fx = Fx::new(false).await;
    let r = fx.recorded().await;
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
    let before = fx.dump().await;
    fx.sql().faults.borrow_mut().push_back(Fault::Guard);
    assert_eq!(fx.replay(&r.copy).await, ReplayPublish::Refused);
    assert_eq!(fx.last_batch_len(), 12 + 2 * 3);
    assert_eq!(fx.dump().await, before);
    assert_eq!(fx.replay(&r.copy).await, ReplayPublish::Published);
}

// ---------------------------------------------------------------------------
// Only the extents of this upload
// ---------------------------------------------------------------------------

/// A commit of 205 extents of 100 bytes whose 204th placement (in the
/// third value) names `foreign` instead: every guard on count, size and
/// tiling would pass if the extent were adopted.
async fn refuses_foreign(fx: &Fx, s: &Staged, foreign: &ExtentId, what: &str) {
    let mut commit = CompleteUpload {
        generation: s.commit.generation.clone(),
        placements: s.commit.placements.clone(),
        now: s.commit.now,
    };
    commit.placements[203].extent_id = foreign.clone();
    let before = fx.dump().await;
    let t = target(&fx.bucket, KEY, &s.id);
    let outcome = fx
        .cat
        .publish_upload(&t, s.revision, &DIGEST, &commit)
        .await
        .unwrap();
    assert_eq!(outcome, Guard::Lost, "{what}");
    assert_eq!(fx.last_set_statements().len(), 3, "{what}");
    assert_eq!(fx.dump().await, before, "{what}");

    // And named beside all of its own, as one extent more.
    let mut more = CompleteUpload {
        generation: s.commit.generation.clone(),
        placements: s.commit.placements.clone(),
        now: s.commit.now,
    };
    more.placements.push(ExtentPlacement {
        extent_id: foreign.clone(),
        seq: 205,
        plain_offset: 20_500,
    });
    more.generation.extent_count = 206;
    more.generation.size = 20_600;
    let outcome = fx
        .cat
        .publish_upload(&t, s.revision, &DIGEST, &more)
        .await
        .unwrap();
    assert_eq!(outcome, Guard::Lost, "{what}");
    assert_eq!(fx.dump().await, before, "{what}");
}

#[tokio::test]
async fn an_extent_of_another_upload_bucket_or_tenant_is_not_adopted() {
    let fx = Fx::new(false).await;
    let s = fx.staged(&fx.bucket, KEY, 205, |_| 100).await;

    // A part of another upload on the same key.
    let other = fx.create(&fx.bucket, KEY).await;
    let of_other_upload = fx.part(&target(&fx.bucket, KEY, &other), 1, 100).await;
    refuses_foreign(&fx, &s, &of_other_upload, "another upload").await;

    // A slice of a part of another upload.
    let sliced = fx.create(&fx.bucket, "elsewhere").await;
    let slices = fx
        .sliced(&target(&fx.bucket, "elsewhere", &sliced), 1, &[100, 100])
        .await;
    refuses_foreign(&fx, &s, &slices[1], "a slice of another upload").await;

    // A part of an upload in another bucket.
    let far = fx.create(&fx.other_bucket, KEY).await;
    let of_other_bucket = fx.part(&target(&fx.other_bucket, KEY, &far), 1, 100).await;
    refuses_foreign(&fx, &s, &of_other_bucket, "another bucket").await;

    // A slice another tenant's upload holds.
    let theirs = fx.create(&fx.bucket, "theirs").await;
    let of_other_tenant = fx
        .sliced(&target(&fx.bucket, "theirs", &theirs), 1, &[100, 100])
        .await;
    let moved = fx
        .run(
            "UPDATE upload_part_extents SET tenant_id = 't_00000000000000ff' \
             WHERE upload_id = ?1",
            &[text(theirs.as_str())],
        )
        .await;
    // The first slice is the part's own row; the second is named here.
    assert_eq!(moved, 1);
    refuses_foreign(&fx, &s, &of_other_tenant[1], "another tenant").await;

    // A staged extent of the bucket that no upload names (a replay
    // stores such rows).
    let loose = fx.replayed(&[100]).await;
    refuses_foreign(&fx, &s, &loose[0], "no upload").await;

    // None of them was touched, and the upload still completes.
    let untouched = fx
        .count(
            "SELECT COUNT(*) FROM extents WHERE state = 'staged' AND generation_id IS NULL \
             AND seq IS NULL AND plain_offset IS NULL",
        )
        .await;
    assert_eq!(untouched, 205 + 1 + 2 + 1 + 2 + 1);
    assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));
    let g = format!(
        "SELECT COUNT(*) FROM extents WHERE generation_id = '{}'",
        s.commit.generation.id
    );
    assert_eq!(fx.count(&g).await, 205);
    for x in [&of_other_upload, &slices[1], &of_other_bucket, &loose[0]] {
        assert!(!s.extents.contains(x));
    }
}

#[tokio::test]
async fn a_replay_takes_no_extent_of_another_bucket() {
    let fx = Fx::new(false).await;
    let r = fx.recorded().await;
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
    let size_of = |p: &ExtentPlacement| {
        let id = text(p.extent_id.as_str());
        let fx = &fx;
        async move {
            let sql = "SELECT plain_size FROM extents WHERE id = ?1";
            match fx.sql().db.fixture_query(sql, &[id]).await.unwrap()[0][0] {
                SqlValue::Int(n) => n as u64,
                ref other => panic!("not a size: {other:?}"),
            }
        }
    };
    // Of the same size as the extent each one displaces, so that the
    // bucket is all that tells them apart. `[50]` is an extent the
    // generation adopts, `[215]` (third value) one it shares.
    let staged = fx.staged(&fx.other_bucket, "x", 1, |_| 0).await.id;
    let adopted = size_of(&r.copy.1[50]).await;
    let foreign_staged = fx
        .part(&target(&fx.other_bucket, "x", &staged), 2, adopted)
        .await;
    let shared = size_of(&r.copy.1[215]).await;
    let far = fx.staged(&fx.other_bucket, KEY, 1, |_| shared).await;
    assert_eq!(fx.complete(&far, None).await, Guard::Applied(()));
    let foreign_committed = far.extents[0].clone();

    let before = fx.dump().await;
    for (at, foreign) in [(50, foreign_staged), (215, foreign_committed)] {
        let mut bad = (r.copy.0.clone(), r.copy.1.clone());
        bad.1[at].extent_id = foreign;
        assert_eq!(fx.replay(&bad).await, ReplayPublish::Refused, "{at}");
        assert_eq!(fx.dump().await, before, "{at}");
    }
    assert_eq!(fx.replay(&r.copy).await, ReplayPublish::Published);
}

/// An extent the generation adopted has its one reference from the
/// adoption. Named a second time, it gets no second one: the count of
/// references then falls short and the generation is refused, as it was
/// with a statement per extent.
#[tokio::test]
async fn a_replay_references_no_extent_of_its_own_twice() {
    let mut dumps = Vec::new();
    for old in [false, true] {
        let fx = Fx::new(old).await;
        let ids = fx.replayed(&[100, 100]).await;
        let twice = [ids[0].clone(), ids[1].clone(), ids[0].clone()];
        let sizes = [100, 100, 100];
        let g = (
            fx.generation(&fx.bucket, "a", T0, &sizes),
            placed(&twice, &sizes),
        );
        let before = fx.dump().await;
        assert_eq!(fx.replay(&g).await, ReplayPublish::Refused, "{old}");
        assert_eq!(fx.dump().await, before);
        dumps.push(before);
    }
    assert_eq!(dumps[0], dumps[1]);
}

/// A record that places two extents at one `seq`, the second of them
/// an extent another generation holds: the reference is not written a
/// second time at that `seq`, so the count guard refuses the record and
/// nothing is written. The replay goes on and lists it as one it could
/// not publish. The statements before these failed the batch with a
/// constraint error instead, which stopped the replay.
#[tokio::test]
async fn a_replay_refuses_two_extents_at_one_seq() {
    // Extents of its own, then extents of the other generation; the
    // last placement takes the `seq` of the first.
    let cases = [
        ("two shared", 0, 2, 1),
        ("its own, then a shared one", 1, 1, 1),
        (
            "its own in the first value, a shared one in the second",
            ROWS,
            1,
            2,
        ),
    ];
    for (what, own, shared, values) in cases {
        for old in [false, true] {
            let fx = Fx::new(old).await;
            let held = fx.replayed(&[100, 100]).await;
            let first = (
                fx.generation(&fx.bucket, "a", T0, &[100, 100]),
                placed(&held, &[100, 100]),
            );
            assert_eq!(fx.replay(&first).await, ReplayPublish::Published);

            let sizes = vec![100; own + shared];
            let mut ids = fx.replayed(&sizes[..own]).await;
            ids.extend(held[..shared].iter().cloned());
            let g = fx.generation(&fx.bucket, "b", T0.plus_ms(1), &sizes);
            let good = placed(&ids, &sizes);
            let mut twice = good.clone();
            twice.last_mut().unwrap().seq = 0;

            let before = fx.dump().await;
            let outcome = fx.cat.replay_publish(&g, &twice, T0.plus_secs(9)).await;
            assert_eq!(fx.dump().await, before, "{what}, {old}");
            if old {
                assert!(
                    matches!(&outcome, Err(BridgeError::Sql(_))),
                    "{what}: {outcome:?}"
                );
                continue;
            }
            assert_eq!(outcome.unwrap(), ReplayPublish::Refused, "{what}");
            assert_eq!(fx.last_set_statements().len(), 2 * values, "{what}");
            assert_eq!(
                fx.cat.replay_twin(&g, &twice).await.unwrap(),
                None,
                "{what}"
            );

            // With the object live as the record should have named it,
            // these placements are still not that object.
            assert_eq!(
                fx.replay(&(g.clone(), good.clone())).await,
                ReplayPublish::Published,
                "{what}"
            );
            let mut again = g.clone();
            again.id = GenerationId::mint(T0.plus_secs(60), [9; 8]);
            assert_eq!(
                fx.cat.replay_twin(&again, &good).await.unwrap(),
                Some(g.id.clone()),
                "{what}"
            );
            assert_eq!(
                fx.cat.replay_twin(&again, &twice).await.unwrap(),
                None,
                "{what}"
            );
            // Every extent is a shared one now.
            let before = fx.dump().await;
            assert_eq!(
                fx.replay(&(again, twice)).await,
                ReplayPublish::Refused,
                "{what}"
            );
            assert_eq!(fx.dump().await, before, "{what}");
        }
    }
}

/// The checks that read the extents of the placements go through every
/// value, not the first: the extent that cannot be read is the last of
/// 120, on a key that has an older generation.
#[tokio::test]
async fn a_replay_finds_an_extent_without_a_copy_in_any_value() {
    for (what, damage) in [
        (
            "lost",
            "UPDATE extents SET safety_state = 'deleted' WHERE id = ?1",
        ),
        (
            "unread",
            "UPDATE extents SET safety_state = 'deleted', plan = x'00' WHERE id = ?1",
        ),
    ] {
        let fx = Fx::new(false).await;
        let r = fx.recorded().await;
        assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
        let sizes = [100; 120];
        let ids = fx.replayed(&sizes).await;
        let g = (
            fx.generation(&fx.bucket, "a", T0.plus_ms(3), &sizes),
            placed(&ids, &sizes),
        );
        // In the first value it is found as well.
        for at in [119, 0] {
            let id = [text(ids[at].as_str())];
            let whole = fx
                .sql()
                .db
                .fixture_query("SELECT safety_state, plan FROM extents WHERE id = ?1", &id);
            let whole = whole.await.unwrap().remove(0);
            // At least one: a usage-counter trigger adds its own row.
            let damage = fx.sql().db.fixture(
                damage,
                if what == "unread" {
                    "UPDATE extents SET safety_state = 'deleted', plan = decode('00', 'hex') WHERE id = ?1"
                } else {
                    damage
                },
            );
            assert!(fx.run(damage, &id).await >= 1, "{what}");
            let before = fx.dump().await;
            assert_eq!(fx.replay(&g).await, ReplayPublish::Damaged, "{what} {at}");
            assert_eq!(fx.dump().await, before, "{what} {at}");
            let mut back = whole;
            back.push(id[0].clone());
            let restored = fx
                .run(
                    "UPDATE extents SET safety_state = ?1, plan = ?2 WHERE id = ?3",
                    &back,
                )
                .await;
            assert!(restored >= 1);
        }
        assert_eq!(fx.replay(&g).await, ReplayPublish::Published, "{what}");
    }
}

// ---------------------------------------------------------------------------
// The live generation, compared a value at a time
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_twin_is_the_same_extents_at_the_same_places() {
    let fx = Fx::new(false).await;
    let r = fx.recorded().await;
    let (g, placements) = &r.copy;
    assert_eq!(fx.cat.replay_twin(g, placements).await.unwrap(), None);
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
    assert_eq!(fx.replay(&r.copy).await, ReplayPublish::Published);

    // Whatever id the other generation has: the object is compared.
    let mut again = g.clone();
    again.id = GenerationId::mint(T0.plus_secs(60), [9; 8]);
    let twin = fx.cat.replay_twin(&again, placements).await.unwrap();
    assert_eq!(twin.as_ref(), Some(&g.id));

    let differs = |change: &dyn Fn(&mut GenerationRow, &mut Vec<ExtentPlacement>)| {
        let (mut g, mut p) = (again.clone(), placements.clone());
        change(&mut g, &mut p);
        (g, p)
    };
    let spare = fx.replayed(&[100]).await.remove(0);
    let cases: Vec<(&str, (GenerationRow, Vec<ExtentPlacement>))> = vec![
        ("size", differs(&|g, _| g.size += 1)),
        ("etag", differs(&|g, _| g.etag = "\"other\"".into())),
        (
            "an offset in the last value",
            differs(&|_, p| p[219].plain_offset += 1),
        ),
        (
            "an offset in the first value",
            differs(&|_, p| p[0].plain_offset = 1),
        ),
        (
            "an extent",
            differs(&|_, p| p[150].extent_id = spare.clone()),
        ),
        (
            "two extents swapped",
            differs(&|_, p| {
                let id = p[101].extent_id.clone();
                p[101].extent_id = core::mem::replace(&mut p[102].extent_id, id);
            }),
        ),
        ("a seq twice", differs(&|_, p| p[7].seq = 6)),
        // Every row of it matches a reference, and the count is right:
        // only the order of the `seq` tells.
        ("a placement twice", differs(&|_, p| p[7] = p[6].clone())),
        (
            "an extent short",
            differs(&|_, p| {
                p.pop();
            }),
        ),
        (
            "an extent more",
            differs(&|_, p| {
                p.push(ExtentPlacement {
                    extent_id: spare.clone(),
                    seq: 220,
                    plain_offset: 0,
                })
            }),
        ),
    ];
    for (what, (g, p)) in &cases {
        assert_eq!(fx.cat.replay_twin(g, p).await.unwrap(), None, "{what}");
    }
    // Another key, another bucket: there is no live generation to match.
    let mut elsewhere = again.clone();
    elsewhere.key = "c".into();
    assert_eq!(
        fx.cat.replay_twin(&elsewhere, placements).await.unwrap(),
        None
    );
    // And `first`, retired by `newer`, is no twin of anything live.
    assert_eq!(fx.replay(&r.newer).await, ReplayPublish::Published);
    assert_eq!(
        fx.cat.replay_twin(&r.first.0, &r.first.1).await.unwrap(),
        None
    );
    assert_eq!(
        fx.cat.replay_twin(&r.newer.0, &r.newer.1).await.unwrap(),
        Some(r.newer.0.id.clone())
    );
}

// ---------------------------------------------------------------------------
// The fence after a batch of unknown outcome
// ---------------------------------------------------------------------------

async fn complete_outcome(fx: &Fx, s: &Staged) -> Result<PublishOutcome> {
    let t = target(&fx.bucket, KEY, &s.id);
    let record = Recorded::for_test(&s.commit.generation.id);
    fx.cat
        .complete_upload(&t, s.revision, &DIGEST, &s.commit, None, record)
        .await
}

/// D1 can answer the first statement after a large batch that did not
/// commit with "D1 DB is overloaded". The fence of Complete is that
/// statement when the batch failed with anything but a guard: it must
/// then say that the outcome is unknown, never that nothing was
/// published.
#[tokio::test]
async fn an_overloaded_fence_leaves_the_outcome_unknown() {
    // The batch did not run, and the fence is refused as overloaded.
    let fx = Fx::new(false).await;
    let s = fx.staged_large().await;
    let before = fx.dump().await;
    fx.sql().faults.borrow_mut().extend([
        Fault::NotRun("D1_ERROR: Network connection lost."),
        Fault::NotRun(OVERLOADED),
    ]);
    let outcome = complete_outcome(&fx, &s).await;
    // The error of the batch, not a proof that nothing is published:
    // only `Refused` and `Fenced` carry one, and the record goes only
    // with one.
    assert!(
        matches!(&outcome, Err(BridgeError::Sql(m)) if m.contains("Network connection lost")),
        "{outcome:?}"
    );
    assert_eq!(fx.sql().batches.borrow().last().unwrap().len(), 2);
    assert_eq!(fx.dump().await, before);
    // Still open at its revision: the same Complete then publishes.
    assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));

    // The batch committed without saying so, and the fence is refused
    // as overloaded: the object is there, and the answer is still an
    // error and not "nothing published".
    let fx = Fx::new(false).await;
    let s = fx.staged_large().await;
    fx.sql().faults.borrow_mut().extend([
        Fault::Unreported("D1_ERROR: Network connection lost."),
        Fault::NotRun(OVERLOADED),
    ]);
    assert!(matches!(
        complete_outcome(&fx, &s).await,
        Err(BridgeError::Sql(_))
    ));
    let live = format!(
        "SELECT COUNT(*) FROM objects WHERE generation_id = '{}'",
        s.commit.generation.id
    );
    assert_eq!(fx.count(&live).await, 1);

    // The overloaded answer to the batch itself is an unknown outcome
    // like any other; a fence that then runs settles it.
    let fx = Fx::new(false).await;
    let s = fx.staged_large().await;
    fx.sql()
        .faults
        .borrow_mut()
        .push_back(Fault::NotRun(OVERLOADED));
    assert!(matches!(
        complete_outcome(&fx, &s).await,
        Ok(PublishOutcome::Fenced(_))
    ));
    let t = target(&fx.bucket, KEY, &s.id);
    assert_eq!(fx.revision(&t).await, s.revision + 1);
    // Nothing stands under the id of the attempt, live or not.
    for table in ["objects WHERE generation_id", "generations WHERE id"] {
        let rows = format!(
            "SELECT COUNT(*) FROM {table} = '{}'",
            s.commit.generation.id
        );
        assert_eq!(fx.count(&rows).await, 0, "{table}");
    }
    assert_eq!(fx.complete(&s, None).await, Guard::Lost);
}

/// The batch committed and its answer was lost; the fence then runs.
/// It finds the upload completed and changes nothing, so the outcome
/// is the error of the batch and never `Fenced`: `Fenced` would say
/// that nothing is published under this id, and the caller would drop
/// the record of a live object.
#[tokio::test]
async fn a_fence_after_a_batch_that_committed_is_not_fenced() {
    let fx = Fx::new(false).await;
    let s = fx.staged_large().await;
    fx.sql()
        .faults
        .borrow_mut()
        .push_back(Fault::Unreported("D1_ERROR: Network connection lost."));
    let outcome = complete_outcome(&fx, &s).await;
    assert!(
        matches!(&outcome, Err(BridgeError::Sql(m)) if m.contains("Network connection lost")),
        "{outcome:?}"
    );
    // The fence ran, and no fault was left to answer it.
    assert_eq!(fx.sql().batches.borrow().last().unwrap().len(), 2);
    assert!(fx.sql().faults.borrow().is_empty());
    let g = &s.commit.generation.id;
    let live = format!("SELECT COUNT(*) FROM objects WHERE generation_id = '{g}'");
    assert_eq!(fx.count(&live).await, 1);
    let adopted = format!("SELECT COUNT(*) FROM generation_extents WHERE generation_id = '{g}'");
    assert_eq!(fx.count(&adopted).await, s.extents.len() as i64);
    // Completed at the revision the batch left: the fence moved nothing.
    let t = target(&fx.bucket, KEY, &s.id);
    assert_eq!(fx.revision(&t).await, s.revision + 1);
    let completed = format!(
        "SELECT COUNT(*) FROM uploads WHERE id = '{}' AND state = 'completed' \
         AND completed_generation_id = '{g}'",
        s.id.as_str()
    );
    assert_eq!(fx.count(&completed).await, 1);
}

// ---------------------------------------------------------------------------
// Rows written
// ---------------------------------------------------------------------------

/// Rows written by one Complete of `parts` one-extent parts, as D1
/// bills them: with the set statements, and with the per-extent ones.
async fn rows_written(parts: u16) -> (u64, u64) {
    let mut billed = Vec::new();
    for old in [false, true] {
        let fx = Fx::new(old).await;
        let s = fx.staged(&fx.bucket, KEY, parts, |_| 100).await;
        fx.sql().db.sqlite().meter_writes().unwrap();
        assert_eq!(fx.complete(&s, None).await, Guard::Applied(()));
        billed.push(fx.sql().db.sqlite().writes().billed());
    }
    (billed[0], billed[1])
}

#[tokio::test]
async fn the_set_statements_write_no_row_more_than_the_per_extent_ones() {
    if TestSql::postgres_selected() {
        return; // sqlite_only: asserts SQLite preupdate-hook billing counts.
    }
    let (set, per_extent) = rows_written(233).await;
    assert_eq!(set, per_extent);
    assert!(set > 233);
}

/// The figure at the largest object of today (`MAX_OBJECT_EXTENTS`).
/// Run with `--ignored --nocapture` to read it.
#[tokio::test]
#[ignore = "a measurement: 10,000 parts take a while"]
async fn rows_written_at_ten_thousand_extents() {
    if TestSql::postgres_selected() {
        return; // sqlite_only: measures SQLite preupdate-hook billing counts.
    }
    let (set, per_extent) = rows_written(10_000).await;
    println!("rows written per publish at 10,000 extents: set {set}, per extent {per_extent}");
    assert_eq!(set, per_extent);
}

// ---------------------------------------------------------------------------
// Reads around a refused batch
// ---------------------------------------------------------------------------

/// A refused batch is charged in full, and D1 then answers "overloaded"
/// for some seconds. The reads that tell why a replay was refused go
/// through `query_after_refusal`, which the D1 adapter makes wait: with
/// it the replay gets its answer, and without it the replay fails with
/// nothing published, to be run again.
#[tokio::test]
async fn the_reads_after_a_refused_replay_wait_out_an_overloaded_database() {
    for lost in [false, true] {
        let fx = Fx::new(false).await;
        let r = fx.recorded().await;
        // An older record under a newer live generation is refused; a
        // newer one that lost an extent is damage.
        let (live, again, expected) = if lost {
            let id = [text(r.newer.1[3].extent_id.as_str())];
            let gone = "UPDATE extents SET safety_state = 'deleted' WHERE id = ?1";
            assert!(fx.run(gone, &id).await >= 1); // the row, and the usage triggers' writes
            (&r.first, &r.newer, ReplayPublish::Damaged)
        } else {
            (&r.newer, &r.first, ReplayPublish::Refused)
        };
        assert_eq!(fx.replay(live).await, ReplayPublish::Published);
        let before = fx.dump().await;
        let replay = || fx.cat.replay_publish(&again.0, &again.1, T0.plus_secs(9));

        // An adapter that does not wait: the read is refused as well.
        fx.sql().throttles.set(true);
        let failed = replay().await;
        assert!(
            matches!(&failed, Err(BridgeError::Sql(m)) if m.contains("overloaded")),
            "{failed:?}"
        );
        assert_eq!(fx.sql().waited.get(), 0);
        fx.sql().throttled.set(false);
        assert_eq!(fx.dump().await, before, "lost: {lost}");

        // One that waits: the answer of a database that was never busy.
        fx.sql().patient.set(true);
        assert_eq!(replay().await.unwrap(), expected, "lost: {lost}");
        assert_eq!(fx.sql().waited.get(), 1);
        assert!(!fx.sql().throttled.get());
        assert_eq!(fx.dump().await, before, "lost: {lost}");

        // The comparison with the live generation is asked right after
        // a refusal too, and waits the same way.
        fx.sql().throttled.set(true);
        let twin = fx.cat.replay_twin(&live.0, &live.1).await.unwrap();
        assert_eq!(twin, Some(live.0.id.clone()));
        assert_eq!(fx.sql().waited.get(), 2);
        fx.sql().throttled.set(true);
        fx.sql().patient.set(false);
        assert!(fx.cat.replay_twin(&live.0, &live.1).await.is_err());
    }
}

/// The check for a plan that cannot be read asks for plans by their
/// bytes, not by a number of rows: first which extents have one and how
/// large, then the plans in runs that fit one answer. A plan that is
/// damaged is found wherever it sits, and a plan larger than an answer
/// is asked for alone.
#[tokio::test]
async fn unread_plans_are_read_in_runs_bounded_by_their_bytes() {
    let fx = Fx::new(false).await;
    let r = fx.recorded().await;
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
    let sizes = [100; 520];
    let ids = fx.replayed(&sizes).await;
    let g = (
        fx.generation(&fx.bucket, "a", T0.plus_ms(3), &sizes),
        placed(&ids, &sizes),
    );
    // One article each, and one extent of many: its plan alone is more
    // than an answer may carry.
    const MANY: usize = 5;
    const MANY_BYTES: u64 = 40_000_000;
    let mut plan_bytes = 0;
    let mut many_bytes = 0;
    for (i, id) in ids.iter().enumerate() {
        let cipher_size = if i == MANY { MANY_BYTES } else { 164 };
        let (plan, _) = velmora_bridge::plan::plan_seeded(
            &mut velmora::rng::SystemRng,
            T0.0 / 1000,
            &["alt.binaries.test"],
            id,
            cipher_size,
            |span| Some([span.start as u8; 32]),
        )
        .unwrap();
        if i == MANY {
            many_bytes = plan.len();
        } else {
            plan_bytes = plan.len();
        }
        let set = "UPDATE extents SET safety_state = 'deleted', plan = ?2, cipher_size = ?3 \
                   WHERE id = ?1";
        let bound = [
            text(id.as_str()),
            SqlValue::Blob(plan),
            SqlValue::Int(cipher_size as i64),
        ];
        assert!(fx.run(set, &bound).await >= 1); // the row, and the usage triggers' writes
    }
    assert!(many_bytes > plan_bytes * 10, "{many_bytes} {plan_bytes}");
    // Ten plans to an answer, and more than 500 extents to a value of
    // placements.
    fx.sql().limits.set(Some(SqlLimits {
        set_rows: 600,
        result_bytes: plan_bytes * 10,
        ..SqlLimits::D1
    }));

    let asked = |fx: &Fx, text: &str| -> Vec<usize> {
        let queries = fx.sql().queries.borrow();
        queries
            .iter()
            .filter(|(sql, _)| sql.contains(text))
            .map(|(_, params)| match &params[0] {
                SqlValue::Text(json) => {
                    let ids: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
                    ids.len()
                }
                other => panic!("{other:?}"),
            })
            .collect()
    };
    const SIZES: &str = "length(e.plan)";
    const PLANS: &str = "e.cipher_size, e.plan";

    // Every plan reads: all of them are asked for, ten at a time, the
    // extents 500 at a time.
    fx.sql().queries.borrow_mut().clear();
    let before = fx.dump().await;
    let published = fx.replay(&g).await;
    assert_eq!(asked(&fx, SIZES), [500, 20]);
    // The five before the large plan, the large plan alone, the other
    // 494 of the first value, and the 20 of the second.
    let mut expected = vec![5, 1];
    expected.extend([10; 49]);
    expected.extend([4, 10, 10]);
    assert_eq!(asked(&fx, PLANS), expected);

    // The same record with the plan of its last extent damaged, in a
    // catalogue as it was before: found in the last run.
    assert_eq!(published, ReplayPublish::Published);
    assert_ne!(fx.dump().await, before);
    let fx = Fx::new(false).await;
    let r = fx.recorded().await;
    assert_eq!(fx.replay(&r.first).await, ReplayPublish::Published);
    let ids = fx.replayed(&sizes).await;
    let g = (
        fx.generation(&fx.bucket, "a", T0.plus_ms(3), &sizes),
        placed(&ids, &sizes),
    );
    let set = fx.sql().db.fixture(
        "UPDATE extents SET safety_state = 'deleted', plan = x'00' WHERE id = ?1",
        "UPDATE extents SET safety_state = 'deleted', plan = decode('00', 'hex') WHERE id = ?1",
    );
    assert!(fx.run(set, &[text(ids[519].as_str())]).await >= 1);
    fx.sql().limits.set(Some(SqlLimits {
        set_rows: 600,
        result_bytes: plan_bytes * 10,
        ..SqlLimits::D1
    }));
    let before = fx.dump().await;
    assert_eq!(fx.replay(&g).await, ReplayPublish::Damaged);
    assert_eq!(fx.dump().await, before);
    assert_eq!(asked(&fx, SIZES), [500, 20]);
    assert_eq!(asked(&fx, PLANS), [1]);
}
