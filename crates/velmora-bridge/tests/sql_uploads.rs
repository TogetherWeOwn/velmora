//! `SqlCatalog` multipart uploads over SQLite with the D1 schema.
//!
//! The catalogue is single-writer per statement batch, so a race is two
//! batches in either order: each test runs the competing call between the
//! read (`upload`) and the write of the other, both ways round.
//!
//! Every statement goes through [`Probe`], which refuses more than 100
//! bound parameters (the D1 limit) and can make a batch fail after all of
//! its statements ran.

use std::cell::{Cell, RefCell};

use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{PublishUnrecorded, RusqliteSql};
use velmora_bridge::*;

const T0: UnixMs = UnixMs(1_762_992_000_123);
const DAY_MS: i64 = 86_400_000;
const KEY: &str = "dir/big file.bin";

struct Probe {
    db: RusqliteSql,
    /// When set, every batch ends with a failing `tx_guard` insert.
    lose_guard: Cell<bool>,
    /// The statements of every batch, as they were sent.
    batched: RefCell<Vec<(&'static str, Vec<SqlValue>)>>,
}

fn check_params(params: &[SqlValue]) {
    assert!(params.len() <= 100, "statement binds {}", params.len());
}

impl Sql for Probe {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        check_params(params);
        self.db.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        check_params(params);
        self.db.exec(sql, params).await
    }
    async fn batch(&self, mut stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        stmts.iter().for_each(|(_, p)| check_params(p));
        self.batched.borrow_mut().extend(stmts.iter().cloned());
        if self.lose_guard.get() {
            stmts.push(("INSERT INTO tx_guard(ok) VALUES (0)", vec![]));
        }
        self.db.batch(stmts).await
    }
}

struct Fx {
    cat: SqlCatalog<Probe>,
    seed: Cell<u8>,
    bucket: BucketId,
    other_bucket: BucketId,
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}

impl Fx {
    async fn new() -> Fx {
        let fx = Fx {
            cat: SqlCatalog::new(Probe {
                db: RusqliteSql::with_schema().unwrap(),
                lose_guard: Cell::new(false),
                batched: RefCell::new(Vec::new()),
            }),
            seed: Cell::new(1),
            bucket: BucketId::mint([0xb1; 8]),
            other_bucket: BucketId::mint([0xb2; 8]),
        };
        for (id, name) in [(&fx.bucket, "one"), (&fx.other_bucket, "two")] {
            fx.run(
                "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, \
                 created_at) VALUES (?1, ?2, 'owner', x'07', 1, 1, 0)",
                &[text(id.as_str()), text(name)],
            )
            .await;
        }
        fx
    }

    fn next(&self) -> u8 {
        let n = self.seed.get();
        self.seed.set(n + 1);
        n
    }

    async fn run(&self, sql: &str, params: &[SqlValue]) -> u64 {
        self.cat.sql.db.exec(sql, params).await.unwrap()
    }

    /// One integer from a query without parameters.
    async fn count(&self, sql: &str) -> i64 {
        match self.cat.sql.db.query(sql, &[]).await.unwrap()[0][0] {
            SqlValue::Int(n) => n,
            ref other => panic!("not an integer: {other:?}"),
        }
    }

    /// The first column of every row, as text.
    async fn texts(&self, sql: &str, params: &[SqlValue]) -> Vec<String> {
        let rows = self.cat.sql.db.query(sql, params).await.unwrap();
        rows.into_iter()
            .map(|r| match r.into_iter().next() {
                Some(SqlValue::Text(s)) => s,
                other => panic!("not text: {other:?}"),
            })
            .collect()
    }

    async fn create(&self, bucket: &BucketId, key: &str) -> UploadId {
        let id = UploadId::mint([self.next(); 16]);
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

    fn extent(&self, bucket: &BucketId, size: u64) -> ExtentRow {
        let n = self.next();
        ExtentRow {
            id: ExtentId::mint([n; 13]),
            bucket_id: bucket.clone(),
            generation_id: None,
            state: ExtentState::Staged,
            seq: None,
            plain_offset: None,
            plain_size: size,
            cipher_size: size + 64,
            media_header: vec![n; 48],
            key_mode: 1,
            wrapped_file_key: Some(vec![n; 73]),
            plain_md5: [n; 16],
            plain_sha256: [n; 32],
            plain_crc64: None,
            cipher_sha256: [n; 32],
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: T0,
        }
    }

    /// Uploads part `number` of `size` bytes; returns its extent id.
    async fn part(&self, t: &UploadTarget<'_>, number: u16, size: u64) -> (ExtentId, Guard<()>) {
        let e = self.extent(t.bucket, size);
        let part = UploadPartRow {
            upload_id: t.id.clone(),
            part_number: number,
            extent_id: e.id.clone(),
            size,
            etag: format!("\"etag-{number}-{}\"", e.id),
            uploaded_at: T0,
        };
        let g = self.cat.put_upload_part(t, &part, &e, T0).await.unwrap();
        (e.id, g)
    }

    fn commit(&self, bucket: &BucketId, key: &str, extents: &[(&ExtentId, u64)]) -> CompleteUpload {
        let mut offset = 0;
        let placements = extents
            .iter()
            .enumerate()
            .map(|(i, (id, size))| {
                let p = ExtentPlacement {
                    extent_id: (*id).clone(),
                    seq: i as u32,
                    plain_offset: offset,
                };
                offset += size;
                p
            })
            .collect::<Vec<_>>();
        CompleteUpload {
            generation: GenerationRow {
                id: GenerationId::mint(T0, [self.next(); 8]),
                bucket_id: bucket.clone(),
                key: key.into(),
                state: GenerationState::Live,
                size: offset,
                etag: "\"abc-2\"".into(),
                checksum_json: None,
                content_json: "{}".into(),
                user_meta_json: "{}".into(),
                extent_count: placements.len() as u32,
                created_at: T0,
                retired_at: None,
            },
            placements,
            now: T0.plus_ms(5),
        }
    }

    async fn read(&self, t: &UploadTarget<'_>) -> (UploadRow, Vec<UploadPartRow>) {
        self.cat.upload(t).await.unwrap().expect("upload exists")
    }

    async fn live_generation(&self, bucket: &BucketId, key: &str) -> Option<String> {
        self.texts(
            "SELECT generation_id FROM objects WHERE bucket_id = ?1 AND key = ?2",
            &[text(bucket.as_str()), text(key)],
        )
        .await
        .pop()
    }

    /// The safety invariant: no extent of a live generation has a GC row.
    async fn assert_no_live_extent_is_gc_bound(&self) {
        let n = self
            .count(
                "SELECT COUNT(*) FROM gc JOIN extents e ON e.id = gc.extent_id \
                 JOIN generations g ON g.id = e.generation_id WHERE g.state = 'live'",
            )
            .await;
        assert_eq!(n, 0, "a live generation references a GC-bound extent");
    }

    async fn gc_extents(&self) -> Vec<String> {
        self.texts("SELECT DISTINCT extent_id FROM gc ORDER BY extent_id", &[])
            .await
    }
}

fn target<'a>(bucket: &'a BucketId, key: &'a str, id: &'a UploadId) -> UploadTarget<'a> {
    UploadTarget { bucket, key, id }
}

const DIGEST: [u8; 32] = [0xd1; 32];

// ---------------------------------------------------------------------------
// Create, UploadPart, read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_then_parts_bump_revision_and_list_in_order() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (upload, parts) = fx.read(&t).await;
    assert_eq!((upload.state, upload.revision), (UploadState::Open, 0));
    assert!(parts.is_empty());

    let (x2, g) = fx.part(&t, 2, 700).await;
    assert_eq!(g, Guard::Applied(()));
    let (x1, _) = fx.part(&t, 1, 500).await;
    let (upload, parts) = fx.read(&t).await;
    assert_eq!(upload.revision, 2);
    assert_eq!(
        parts
            .iter()
            .map(|p| (p.part_number, p.extent_id.clone(), p.size))
            .collect::<Vec<_>>(),
        vec![(1, x1, 500), (2, x2, 700)]
    );
    // Nothing is posted before Complete, and the parts are staged.
    assert_eq!(fx.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM extents WHERE state = 'staged' AND generation_id IS NULL")
            .await,
        2
    );
}

#[tokio::test]
async fn create_refuses_a_row_that_is_not_a_fresh_open_upload() {
    let fx = Fx::new().await;
    let row = UploadRow {
        id: UploadId::mint([9; 16]),
        bucket_id: fx.bucket.clone(),
        key: KEY.into(),
        content_json: "{}".into(),
        user_meta_json: "{}".into(),
        state: UploadState::Completed,
        revision: 0,
        completed_generation_id: None,
        complete_digest: None,
        result_etag: None,
        initiated_at: T0,
    };
    assert!(matches!(
        fx.cat.create_upload(&row).await,
        Err(BridgeError::Invalid(_))
    ));
    assert_eq!(fx.count("SELECT COUNT(*) FROM uploads").await, 0);
}

#[tokio::test]
async fn upload_part_replace_sends_old_extent_to_gc() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (old, _) = fx.part(&t, 1, 500).await;
    let (keep, _) = fx.part(&t, 2, 500).await;
    assert!(fx.gc_extents().await.is_empty());

    let (new, g) = fx.part(&t, 1, 900).await;
    assert_eq!(g, Guard::Applied(()));
    let (upload, parts) = fx.read(&t).await;
    assert_eq!(upload.revision, 3);
    assert_eq!(parts.len(), 2);
    assert_eq!((parts[0].extent_id.clone(), parts[0].size), (new, 900));
    assert_eq!(parts[1].extent_id, keep);
    assert_eq!(fx.gc_extents().await, vec![old.to_string()]);
    let actions = fx
        .texts(
            "SELECT action || ':' || due_at FROM gc ORDER BY action",
            &[],
        )
        .await;
    assert_eq!(
        actions,
        vec![
            format!("delete_safety:{}", T0.0),
            format!("shred_key:{}", T0.0 + DAY_MS)
        ]
    );
}

#[tokio::test]
async fn upload_part_refuses_a_mismatched_extent() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    // The extent belongs to another bucket.
    let e = fx.extent(&fx.other_bucket, 10);
    let part = UploadPartRow {
        upload_id: id.clone(),
        part_number: 1,
        extent_id: e.id.clone(),
        size: 10,
        etag: "\"e\"".into(),
        uploaded_at: T0,
    };
    assert!(matches!(
        fx.cat.put_upload_part(&t, &part, &e, T0).await,
        Err(BridgeError::Invalid(_))
    ));
    // Part number outside 1..=10000 is refused by the schema, atomically.
    let e = fx.extent(&fx.bucket, 10);
    let part = UploadPartRow {
        part_number: 10_001,
        extent_id: e.id.clone(),
        ..part
    };
    assert!(matches!(
        fx.cat.put_upload_part(&t, &part, &e, T0).await,
        Err(BridgeError::Sql(_))
    ));
    assert_eq!(fx.count("SELECT COUNT(*) FROM extents").await, 0);
    assert_eq!(fx.read(&t).await.0.revision, 0);
}

// ---------------------------------------------------------------------------
// Target binding
// ---------------------------------------------------------------------------

/// Every call with the right upload id but the wrong bucket or key behaves
/// exactly as if the id did not exist, and writes nothing.
async fn wrong_target_is_unknown(
    fx: &Fx,
    id: &UploadId,
    wrong: UploadTarget<'_>,
    good_part: &ExtentId,
) {
    assert!(fx.cat.upload(&wrong).await.unwrap().is_none());

    let e = fx.extent(wrong.bucket, 10);
    let part = UploadPartRow {
        upload_id: id.clone(),
        part_number: 2,
        extent_id: e.id.clone(),
        size: 10,
        etag: "\"e\"".into(),
        uploaded_at: T0,
    };
    assert_eq!(
        fx.cat.put_upload_part(&wrong, &part, &e, T0).await.unwrap(),
        Guard::Lost
    );
    let c = fx.commit(wrong.bucket, wrong.key, &[(good_part, 500)]);
    assert_eq!(
        fx.cat.publish_upload(&wrong, 1, &DIGEST, &c).await.unwrap(),
        Guard::Lost
    );
    assert_eq!(fx.cat.abort_upload(&wrong, T0).await.unwrap(), Guard::Lost);

    assert_eq!(fx.count("SELECT COUNT(*) FROM extents").await, 1);
    assert_eq!(fx.count("SELECT COUNT(*) FROM generations").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM objects").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM gc").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM outbox").await, 0);
    let (upload, parts) = fx.read(&target(&fx.bucket, KEY, id)).await;
    assert_eq!((upload.state, upload.revision), (UploadState::Open, 1));
    assert_eq!(parts.len(), 1);
}

#[tokio::test]
async fn upload_id_cross_bucket_is_nosuchupload() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let (x1, _) = fx.part(&target(&fx.bucket, KEY, &id), 1, 500).await;
    wrong_target_is_unknown(&fx, &id, target(&fx.other_bucket, KEY, &id), &x1).await;
}

#[tokio::test]
async fn upload_id_cross_key_is_nosuchupload() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let (x1, _) = fx.part(&target(&fx.bucket, KEY, &id), 1, 500).await;
    wrong_target_is_unknown(&fx, &id, target(&fx.bucket, "other-key", &id), &x1).await;
}

// ---------------------------------------------------------------------------
// Complete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn complete_publishes_listed_parts_and_retires_the_rest() {
    let fx = Fx::new().await;
    // A previous object under the key, published by an earlier upload.
    let old_id = fx.create(&fx.bucket, KEY).await;
    let old_t = target(&fx.bucket, KEY, &old_id);
    let (old_x, _) = fx.part(&old_t, 1, 100).await;
    let old_c = fx.commit(&fx.bucket, KEY, &[(&old_x, 100)]);
    assert_eq!(
        fx.cat
            .publish_upload(&old_t, 1, &DIGEST, &old_c)
            .await
            .unwrap(),
        Guard::Applied(())
    );

    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (x1, _) = fx.part(&t, 1, 500).await;
    let (x2, _) = fx.part(&t, 2, 700).await;
    let (unlisted, _) = fx.part(&t, 7, 50).await;
    let (upload, _) = fx.read(&t).await;
    let c = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);
    assert_eq!(
        fx.cat
            .publish_upload(&t, upload.revision, &DIGEST, &c)
            .await
            .unwrap(),
        Guard::Applied(())
    );

    // Pointer, generation and extents in part order.
    let gen = c.generation.id.to_string();
    assert_eq!(fx.live_generation(&fx.bucket, KEY).await, Some(gen.clone()));
    let placed = fx
        .texts(
            "SELECT id || ':' || seq || ':' || plain_offset || ':' || state FROM extents \
             WHERE generation_id = ?1 ORDER BY seq",
            &[text(&gen)],
        )
        .await;
    assert_eq!(
        placed,
        vec![
            format!("{x1}:0:0:committed"),
            format!("{x2}:1:500:committed")
        ]
    );
    // One posting obligation per published extent, due now.
    let outbox = fx
        .texts(
            "SELECT extent_id || ':' || stage || ':' || next_at FROM outbox \
             WHERE generation_id = ?1 ORDER BY extent_id",
            &[text(&gen)],
        )
        .await;
    assert_eq!(
        outbox,
        vec![
            format!("{x1}:post:{}", c.now.0),
            format!("{x2}:post:{}", c.now.0)
        ]
    );
    // The unlisted part and the previous generation's extent go to GC.
    let mut expected = vec![unlisted.to_string(), old_x.to_string()];
    expected.sort();
    assert_eq!(fx.gc_extents().await, expected);
    fx.assert_no_live_extent_is_gc_bound().await;
    let old_gen = old_c.generation.id.to_string();
    assert_eq!(
        fx.texts(
            "SELECT state || ':' || retired_at FROM generations WHERE id = ?1",
            &[text(&old_gen)]
        )
        .await,
        vec![format!("superseded:{}", c.now.0)]
    );
    assert_eq!(
        fx.texts(
            "SELECT stage FROM outbox WHERE generation_id = ?1",
            &[text(&old_gen)]
        )
        .await,
        vec!["cancelled"]
    );
    // Receipt.
    let (upload, _) = fx.read(&t).await;
    assert_eq!(upload.state, UploadState::Completed);
    assert_eq!(upload.revision, 4);
    assert_eq!(
        upload.completed_generation_id,
        Some(c.generation.id.clone())
    );
    assert_eq!(upload.complete_digest, Some(DIGEST));
    assert_eq!(upload.result_etag.as_deref(), Some("\"abc-2\""));
}

/// A placement naming an extent that is not a part of this upload must
/// not adopt it: not another upload's staged part, not a published
/// extent, not an unknown id. The whole completion rolls back.
#[tokio::test]
async fn complete_refuses_extent_of_another_upload() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (mine, _) = fx.part(&t, 1, 500).await;

    // Same bucket, same size: only the upload differs.
    let victim_id = fx.create(&fx.bucket, "victim").await;
    let victim_t = target(&fx.bucket, "victim", &victim_id);
    let (theirs, _) = fx.part(&victim_t, 1, 500).await;
    let unknown = ExtentId::mint([0xee; 13]);

    for foreign in [&theirs, &unknown] {
        for extents in [
            vec![(foreign, 500)],
            vec![(&mine, 500), (foreign, 500)],
            vec![(&mine, 500), (&mine, 500)],
        ] {
            let c = fx.commit(&fx.bucket, KEY, &extents);
            assert_eq!(
                fx.cat.publish_upload(&t, 1, &DIGEST, &c).await.unwrap(),
                Guard::Lost
            );
        }
    }
    assert_eq!(fx.count("SELECT COUNT(*) FROM generations").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM objects").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM extents WHERE state = 'staged' AND generation_id IS NULL")
            .await,
        2
    );
    assert_eq!(fx.read(&t).await.0.state, UploadState::Open);

    // The victim still completes with its own extent, and an extent that
    // is now published cannot be adopted by the first upload either.
    let c = fx.commit(&fx.bucket, "victim", &[(&theirs, 500)]);
    assert_eq!(
        fx.cat
            .publish_upload(&victim_t, 1, &DIGEST, &c)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    let steal = fx.commit(&fx.bucket, KEY, &[(&theirs, 500)]);
    assert_eq!(
        fx.cat.publish_upload(&t, 1, &DIGEST, &steal).await.unwrap(),
        Guard::Lost
    );
    assert_eq!(
        fx.texts(
            "SELECT generation_id FROM extents WHERE id = ?1",
            &[text(theirs.as_str())]
        )
        .await,
        vec![c.generation.id.to_string()]
    );
    assert_eq!(fx.live_generation(&fx.bucket, KEY).await, None);
}

#[tokio::test]
async fn complete_refuses_offsets_that_do_not_tile() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (x1, _) = fx.part(&t, 1, 500).await;
    let (x2, _) = fx.part(&t, 2, 700).await;

    // A gap, an overlap, and a wrong total.
    let mut gap = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);
    gap.placements[1].plain_offset = 501;
    let mut overlap = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);
    overlap.placements[1].plain_offset = 499;
    let mut total = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);
    total.generation.size = 1199;
    for c in [gap, overlap, total] {
        assert_eq!(
            fx.cat.publish_upload(&t, 2, &DIGEST, &c).await.unwrap(),
            Guard::Lost
        );
    }
    assert_eq!(fx.count("SELECT COUNT(*) FROM generations").await, 0);

    // Shape errors never reach the database.
    let mut count = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);
    count.generation.extent_count = 3;
    let mut seq = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);
    seq.placements[1].seq = 5;
    let wrong_key = fx.commit(&fx.bucket, "elsewhere", &[(&x1, 500), (&x2, 700)]);
    let empty = fx.commit(&fx.bucket, KEY, &[]);
    for c in [count, seq, wrong_key, empty] {
        assert!(matches!(
            fx.cat.publish_upload(&t, 2, &DIGEST, &c).await,
            Err(BridgeError::Invalid(_))
        ));
    }

    let ok = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);
    assert_eq!(
        fx.cat.publish_upload(&t, 2, &DIGEST, &ok).await.unwrap(),
        Guard::Applied(())
    );
}

/// A second Complete of a completed upload publishes nothing: it is
/// `Lost`, and the receipt answers the retry. It must not move the key
/// back over an object written after the first Complete.
#[tokio::test]
async fn complete_retry_returns_receipt() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (x1, _) = fx.part(&t, 1, 500).await;
    let c = fx.commit(&fx.bucket, KEY, &[(&x1, 500)]);
    assert_eq!(
        fx.cat.publish_upload(&t, 1, &DIGEST, &c).await.unwrap(),
        Guard::Applied(())
    );

    // A later overwrite of the same key by another upload.
    let later_id = fx.create(&fx.bucket, KEY).await;
    let later_t = target(&fx.bucket, KEY, &later_id);
    let (y1, _) = fx.part(&later_t, 1, 900).await;
    let later = fx.commit(&fx.bucket, KEY, &[(&y1, 900)]);
    assert_eq!(
        fx.cat
            .publish_upload(&later_t, 1, &DIGEST, &later)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    let snapshot = |fx: &Fx| {
        let conn = &fx.cat.sql.db;
        conn.with_conn(|c| {
            let mut dump = Vec::new();
            for table in [
                "uploads",
                "generations",
                "objects",
                "extents",
                "outbox",
                "gc",
            ] {
                let n: i64 = c
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                dump.push((table, n));
            }
            dump
        })
    };
    let before = snapshot(&fx);

    // The retry: same request, at the revision the client first saw and
    // at the receipt's revision, with the same and with a fresh generation.
    for revision in [1, 2] {
        for retry in [c.clone(), fx.commit(&fx.bucket, KEY, &[(&x1, 500)])] {
            assert_eq!(
                fx.cat
                    .publish_upload(&t, revision, &DIGEST, &retry)
                    .await
                    .unwrap(),
                Guard::Lost
            );
        }
    }
    assert_eq!(snapshot(&fx), before);
    assert_eq!(
        fx.live_generation(&fx.bucket, KEY).await,
        Some(later.generation.id.to_string()),
        "the retry rolled the key back over a later overwrite"
    );
    let (upload, _) = fx.read(&t).await;
    assert_eq!(upload.state, UploadState::Completed);
    assert_eq!(upload.complete_digest, Some(DIGEST));
    assert_eq!(
        upload.completed_generation_id,
        Some(c.generation.id.clone())
    );
    assert_eq!(upload.result_etag, Some(c.generation.etag.clone()));
    fx.assert_no_live_extent_is_gc_bound().await;
}

// ---------------------------------------------------------------------------
// Races: exactly one wins
// ---------------------------------------------------------------------------

#[tokio::test]
async fn complete_vs_upload_part_race() {
    // UploadPart replace lands between Complete's read and its batch.
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (x1, _) = fx.part(&t, 1, 500).await;
    let (x2, _) = fx.part(&t, 2, 700).await;
    let (seen, _) = fx.read(&t).await;
    let stale = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);

    let (x1b, g) = fx.part(&t, 1, 600).await;
    assert_eq!(g, Guard::Applied(()));
    assert_eq!(
        fx.cat
            .publish_upload(&t, seen.revision, &DIGEST, &stale)
            .await
            .unwrap(),
        Guard::Lost,
        "Complete published a part set that was replaced under it"
    );
    assert_eq!(fx.count("SELECT COUNT(*) FROM generations").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(fx.gc_extents().await, vec![x1.to_string()]);

    // Re-read and re-validate: the new part set completes.
    let (seen, parts) = fx.read(&t).await;
    assert_eq!(parts[0].extent_id, x1b);
    let fresh = fx.commit(&fx.bucket, KEY, &[(&x1b, 600), (&x2, 700)]);
    assert_eq!(
        fx.cat
            .publish_upload(&t, seen.revision, &DIGEST, &fresh)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    fx.assert_no_live_extent_is_gc_bound().await;

    // The other order: Complete won, so the late UploadPart is refused and
    // leaves no extent behind.
    let extents = fx.count("SELECT COUNT(*) FROM extents").await;
    let (_, g) = fx.part(&t, 1, 650).await;
    assert_eq!(g, Guard::Lost);
    assert_eq!(fx.count("SELECT COUNT(*) FROM extents").await, extents);
    assert_eq!(fx.gc_extents().await, vec![x1.to_string()]);
    assert_eq!(
        fx.live_generation(&fx.bucket, KEY).await,
        Some(fresh.generation.id.to_string())
    );
    fx.assert_no_live_extent_is_gc_bound().await;
}

#[tokio::test]
async fn complete_vs_abort_race() {
    // Abort lands between Complete's read and its batch: Abort wins.
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (x1, _) = fx.part(&t, 1, 500).await;
    let (seen, _) = fx.read(&t).await;
    let c = fx.commit(&fx.bucket, KEY, &[(&x1, 500)]);

    assert_eq!(
        fx.cat.abort_upload(&t, T0).await.unwrap(),
        Guard::Applied(())
    );
    assert_eq!(
        fx.cat
            .publish_upload(&t, seen.revision, &DIGEST, &c)
            .await
            .unwrap(),
        Guard::Lost
    );
    // Not even at the post-abort revision.
    assert_eq!(
        fx.cat
            .publish_upload(&t, seen.revision + 1, &DIGEST, &c)
            .await
            .unwrap(),
        Guard::Lost
    );
    assert_eq!(fx.count("SELECT COUNT(*) FROM generations").await, 0);
    assert_eq!(fx.live_generation(&fx.bucket, KEY).await, None);
    assert_eq!(fx.gc_extents().await, vec![x1.to_string()]);
    let (upload, _) = fx.read(&t).await;
    assert_eq!((upload.state, upload.revision), (UploadState::Aborted, 2));
    // A second Abort and a late UploadPart change nothing.
    assert_eq!(fx.cat.abort_upload(&t, T0).await.unwrap(), Guard::Lost);
    assert_eq!(fx.part(&t, 2, 10).await.1, Guard::Lost);
    assert_eq!(fx.count("SELECT COUNT(*) FROM gc").await, 2);
    fx.assert_no_live_extent_is_gc_bound().await;

    // The other order: Complete wins, Abort is refused and queues no GC.
    let id = fx.create(&fx.bucket, "second").await;
    let t = target(&fx.bucket, "second", &id);
    let (y1, _) = fx.part(&t, 1, 500).await;
    let c = fx.commit(&fx.bucket, "second", &[(&y1, 500)]);
    assert_eq!(
        fx.cat.publish_upload(&t, 1, &DIGEST, &c).await.unwrap(),
        Guard::Applied(())
    );
    assert_eq!(fx.cat.abort_upload(&t, T0).await.unwrap(), Guard::Lost);
    assert_eq!(fx.gc_extents().await, vec![x1.to_string()]);
    assert_eq!(fx.read(&t).await.0.state, UploadState::Completed);
    fx.assert_no_live_extent_is_gc_bound().await;
}

/// A batch that fails after its last statement leaves no trace: the
/// guarded batches rely on all-or-nothing execution.
#[tokio::test]
async fn failed_batch_writes_nothing() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (x1, _) = fx.part(&t, 1, 500).await;

    fx.cat.sql.lose_guard.set(true);
    assert_eq!(fx.part(&t, 1, 600).await.1, Guard::Lost);
    let c = fx.commit(&fx.bucket, KEY, &[(&x1, 500)]);
    assert_eq!(
        fx.cat.publish_upload(&t, 1, &DIGEST, &c).await.unwrap(),
        Guard::Lost
    );
    assert_eq!(fx.cat.abort_upload(&t, T0).await.unwrap(), Guard::Lost);
    fx.cat.sql.lose_guard.set(false);

    assert_eq!(fx.count("SELECT COUNT(*) FROM extents").await, 1);
    assert_eq!(fx.count("SELECT COUNT(*) FROM generations").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM objects").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM outbox").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM gc").await, 0);
    let (upload, parts) = fx.read(&t).await;
    assert_eq!((upload.state, upload.revision), (UploadState::Open, 1));
    assert_eq!(parts[0].extent_id, x1);
}

// ---------------------------------------------------------------------------
// Scope of side effects
// ---------------------------------------------------------------------------

/// Publishes a one-part object and returns its extent and generation ids.
async fn publish(fx: &Fx, bucket: &BucketId, key: &str) -> (ExtentId, String) {
    let id = fx.create(bucket, key).await;
    let t = target(bucket, key, &id);
    let (x, _) = fx.part(&t, 1, 400).await;
    let c = fx.commit(bucket, key, &[(&x, 400)]);
    let done = fx.cat.publish_upload(&t, 1, &DIGEST, &c).await.unwrap();
    assert_eq!(done, Guard::Applied(()));
    (x, c.generation.id.to_string())
}

/// A part added after Complete's read is not in the list Complete
/// validated. The revision catches it even though every listed extent is
/// still adoptable.
#[tokio::test]
async fn complete_loses_to_a_part_added_after_its_read() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (x1, _) = fx.part(&t, 1, 500).await;
    let (x2, _) = fx.part(&t, 2, 700).await;
    let (seen, _) = fx.read(&t).await;
    let stale = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);

    let (_, g) = fx.part(&t, 3, 300).await;
    assert_eq!(g, Guard::Applied(()));
    assert_eq!(
        fx.cat
            .publish_upload(&t, seen.revision, &DIGEST, &stale)
            .await
            .unwrap(),
        Guard::Lost
    );
    assert_eq!(fx.count("SELECT COUNT(*) FROM generations").await, 0);
    assert!(fx.gc_extents().await.is_empty());
    assert_eq!(fx.read(&t).await.0.state, UploadState::Open);
}

/// An overwrite retires the previous generation of that key in that
/// bucket and nothing else.
#[tokio::test]
async fn overwrite_retires_only_the_same_key_in_the_same_bucket() {
    let fx = Fx::new().await;
    let (old_x, old_gen) = publish(&fx, &fx.bucket, KEY).await;
    let (posted_x, posted_gen) = publish(&fx, &fx.bucket, "posted").await;
    let (neighbour_x, neighbour_gen) = publish(&fx, &fx.bucket, "neighbour").await;
    let (twin_x, twin_gen) = publish(&fx, &fx.other_bucket, KEY).await;
    // One object already finished posting; overwrite it too, below.
    fx.run(
        "UPDATE outbox SET stage = 'done' WHERE extent_id = ?1",
        &[text(posted_x.as_str())],
    )
    .await;

    let (new_x, new_gen) = publish(&fx, &fx.bucket, KEY).await;
    publish(&fx, &fx.bucket, "posted").await;

    let fx = &fx;
    let state = |generation: String| async move {
        fx.texts(
            "SELECT state FROM generations WHERE id = ?1",
            &[text(&generation)],
        )
        .await
        .pop()
        .unwrap()
    };
    let stage = |extent: ExtentId| async move {
        fx.texts(
            "SELECT stage FROM outbox WHERE extent_id = ?1",
            &[text(extent.as_str())],
        )
        .await
        .pop()
        .unwrap()
    };
    assert_eq!(state(old_gen).await, "superseded");
    assert_eq!(state(posted_gen).await, "superseded");
    assert_eq!(stage(old_x.clone()).await, "cancelled");
    // A finished job stays finished: its history is not rewritten.
    assert_eq!(stage(posted_x.clone()).await, "done");
    for (extent, generation) in [
        (neighbour_x, neighbour_gen),
        (twin_x, twin_gen),
        (new_x, new_gen),
    ] {
        assert_eq!(state(generation).await, "live");
        assert_eq!(stage(extent).await, "post");
    }
    assert_eq!(
        fx.gc_extents().await,
        {
            let mut want = vec![old_x.to_string(), posted_x.to_string()];
            want.sort();
            want
        },
        "GC rows only for the two retired extents"
    );
    assert_eq!(
        fx.live_generation(&fx.bucket, "neighbour").await.is_some(),
        fx.live_generation(&fx.other_bucket, KEY).await.is_some()
    );
    fx.assert_no_live_extent_is_gc_bound().await;
}

/// Abort and part replacement queue GC for this upload's extents only.
#[tokio::test]
async fn abort_touches_only_its_own_parts() {
    let fx = Fx::new().await;
    let mine = fx.create(&fx.bucket, KEY).await;
    let theirs = fx.create(&fx.bucket, KEY).await;
    let t_mine = target(&fx.bucket, KEY, &mine);
    let t_theirs = target(&fx.bucket, KEY, &theirs);
    let (x_mine, _) = fx.part(&t_mine, 1, 100).await;
    let (x_theirs, _) = fx.part(&t_theirs, 1, 100).await;

    // Replacing my part 1 leaves their part 1 alone.
    let (x_mine2, _) = fx.part(&t_mine, 1, 120).await;
    assert_eq!(fx.gc_extents().await, vec![x_mine.to_string()]);
    assert_eq!(
        fx.cat.abort_upload(&t_mine, T0).await.unwrap(),
        Guard::Applied(())
    );
    let mut want = vec![x_mine.to_string(), x_mine2.to_string()];
    want.sort();
    assert_eq!(fx.gc_extents().await, want);

    // Their upload is intact and still completes.
    let (seen, parts) = fx.read(&t_theirs).await;
    assert_eq!((seen.state, parts.len()), (UploadState::Open, 1));
    let c = fx.commit(&fx.bucket, KEY, &[(&x_theirs, 100)]);
    assert_eq!(
        fx.cat
            .publish_upload(&t_theirs, seen.revision, &DIGEST, &c)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    fx.assert_no_live_extent_is_gc_bound().await;
}

// ---------------------------------------------------------------------------
// Listing open uploads, and deleting a bucket
// ---------------------------------------------------------------------------

fn listing(prefix: &str, limit: u32) -> UploadListQuery {
    UploadListQuery {
        prefix: prefix.into(),
        after: None,
        skip_prefix: None,
        limit,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn open_uploads_list_by_key_then_id_within_one_bucket() {
    let fx = Fx::new().await;
    // Created out of key order; ids ascend with creation.
    let mut made = Vec::new();
    for key in ["dir/b", "a", "dir/a", "a", "dir0", "di", "100%_x", "100%"] {
        made.push((key.to_string(), fx.create(&fx.bucket, key).await));
    }
    let elsewhere = fx.create(&fx.other_bucket, "a").await;
    made.sort();
    let keys = |rows: &[OpenUpload]| rows.iter().map(|r| r.key.clone()).collect::<Vec<_>>();
    let pairs = |rows: Vec<OpenUpload>| rows.into_iter().map(|r| (r.key, r.id)).collect::<Vec<_>>();

    let all = fx
        .cat
        .list_uploads(&fx.bucket, &listing("", 100))
        .await
        .unwrap();
    assert!(all
        .iter()
        .all(|r| r.initiated_at == T0 && r.id != elsewhere));
    assert_eq!(pairs(all), made);
    let other = fx
        .cat
        .list_uploads(&fx.other_bucket, &listing("", 100))
        .await
        .unwrap();
    assert_eq!(pairs(other), [("a".to_string(), elsewhere)]);

    // The limit, and the prefix as a key range: `%` and `_` are bytes
    // like any other.
    let rows = fx
        .cat
        .list_uploads(&fx.bucket, &listing("", 3))
        .await
        .unwrap();
    assert_eq!(pairs(rows), made[..3]);
    assert!(fx
        .cat
        .list_uploads(&fx.bucket, &listing("", 0))
        .await
        .unwrap()
        .is_empty());
    let rows = fx
        .cat
        .list_uploads(&fx.bucket, &listing("dir/", 100))
        .await
        .unwrap();
    assert_eq!(keys(&rows), ["dir/a", "dir/b"]);
    let rows = fx
        .cat
        .list_uploads(&fx.bucket, &listing("di", 100))
        .await
        .unwrap();
    assert_eq!(keys(&rows), ["di", "dir/a", "dir/b", "dir0"]);
    let rows = fx
        .cat
        .list_uploads(&fx.bucket, &listing("100%_", 100))
        .await
        .unwrap();
    assert_eq!(keys(&rows), ["100%_x"]);
    let rows = fx
        .cat
        .list_uploads(&fx.bucket, &listing("1__", 100))
        .await
        .unwrap();
    assert!(rows.is_empty());

    // After a key and an id: the later uploads of that key, then the
    // keys after it. After a key alone: only the keys after it.
    let first_a = made.iter().find(|(k, _)| k == "a").unwrap().1.clone();
    let mut q = listing("", 100);
    q.after = Some(("a".into(), Some(first_a.as_str().to_owned())));
    let rows = fx.cat.list_uploads(&fx.bucket, &q).await.unwrap();
    assert_eq!(keys(&rows), ["a", "di", "dir/a", "dir/b", "dir0"]);
    assert_ne!(rows[0].id, first_a);
    q.after = Some(("a".into(), None));
    let rows = fx.cat.list_uploads(&fx.bucket, &q).await.unwrap();
    assert_eq!(keys(&rows), ["di", "dir/a", "dir/b", "dir0"]);
    // Past a common prefix: none of its members, whatever the position.
    q.after = Some(("dir/a".into(), None));
    q.skip_prefix = Some("dir/".into());
    let rows = fx.cat.list_uploads(&fx.bucket, &q).await.unwrap();
    assert_eq!(keys(&rows), ["dir0"]);
    q.prefix = "dir/".into();
    assert!(fx
        .cat
        .list_uploads(&fx.bucket, &q)
        .await
        .unwrap()
        .is_empty());

    // Only open uploads are listed.
    let (key, id) = made.last().unwrap().clone();
    assert_eq!(
        fx.cat
            .abort_upload(&target(&fx.bucket, &key, &id), T0)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    let rows = fx
        .cat
        .list_uploads(&fx.bucket, &listing("", 100))
        .await
        .unwrap();
    assert_eq!(rows.len(), made.len() - 1);
    assert!(rows.iter().all(|r| r.id != id));
}

fn bucket_row(id: &BucketId, name: &str) -> Bucket {
    Bucket {
        id: id.clone(),
        name: name.into(),
        owner: "owner".into(),
        bdk_wrapped: vec![7],
        kek_version: 1,
        disposable: true,
        created_at: UnixMs(0),
    }
}

/// A bucket goes only while no row names it but its grants, and it
/// takes exactly its grants with it.
#[tokio::test(flavor = "current_thread")]
async fn a_bucket_is_deleted_only_while_nothing_names_it() {
    // Every way a bucket can be named by a row that is not a grant.
    let traces: [(&str, &str); 5] = [
        (
            "generations",
            "INSERT INTO generations(id, bucket_id, key, state, size, etag, content_json, \
             user_meta_json, extent_count, created_at) \
             VALUES ('g_1', ?1, 'k', 'deleted', 0, '\"e\"', '{}', '{}', 0, 0)",
        ),
        (
            "key_floors",
            "INSERT INTO key_floors(bucket_id, key, floor_id) VALUES (?1, 'k', 'g_1')",
        ),
        (
            "uploads",
            "INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, \
             initiated_at) VALUES ('u1', ?1, 'k', '{}', '{}', 'aborted', 0)",
        ),
        ("objects", ""),
        ("extents", ""),
    ];
    for (table, insert) in traces {
        let fx = Fx::new().await;
        let one = bucket_row(&fx.bucket, "one");
        match table {
            "objects" => {
                // The live pointer has no foreign key on the bucket.
                fx.run(
                    "INSERT INTO generations(id, bucket_id, key, state, size, etag, \
                     content_json, user_meta_json, extent_count, created_at) \
                     VALUES ('g_1', ?1, 'k', 'live', 0, '\"e\"', '{}', '{}', 0, 0)",
                    &[text(fx.other_bucket.as_str())],
                )
                .await;
                fx.run(
                    "INSERT INTO objects(bucket_id, key, generation_id) VALUES (?1, 'k', 'g_1')",
                    &[text(fx.bucket.as_str())],
                )
                .await;
            }
            "extents" => {
                let id = fx.create(&fx.other_bucket, "k").await;
                let (_, staged) = fx.part(&target(&fx.other_bucket, "k", &id), 1, 10).await;
                assert_eq!(staged, Guard::Applied(()));
                fx.run(
                    "UPDATE extents SET bucket_id = ?1",
                    &[text(fx.bucket.as_str())],
                )
                .await;
            }
            _ => {
                fx.run(insert, &[text(fx.bucket.as_str())]).await;
            }
        }
        assert!(fx.cat.bucket_in_use(&fx.bucket).await.unwrap(), "{table}");
        assert_eq!(
            fx.cat.delete_bucket(&one).await.unwrap(),
            Guard::Lost,
            "{table}"
        );
        assert_eq!(fx.count("SELECT COUNT(*) FROM buckets").await, 2, "{table}");
    }

    let fx = Fx::new().await;
    let one = bucket_row(&fx.bucket, "one");
    fx.run(
        "INSERT INTO access_keys(access_key_id, principal, secret_wrapped, kek_version, status, \
         created_at) VALUES ('AK', 'p', x'00', 1, 'active', 0)",
        &[],
    )
    .await;
    for bucket in [&fx.bucket, &fx.other_bucket] {
        fx.cat.put_grant("AK", bucket, Perm::Rw).await.unwrap();
    }
    // What the other bucket holds does not keep this one.
    fx.create(&fx.other_bucket, "k").await;
    assert!(!fx.cat.bucket_in_use(&fx.bucket).await.unwrap());
    assert!(fx.cat.bucket_in_use(&fx.other_bucket).await.unwrap());

    // The row must be the bucket the caller read: same id, same name.
    assert_eq!(
        fx.cat
            .delete_bucket(&bucket_row(&fx.bucket, "renamed"))
            .await
            .unwrap(),
        Guard::Lost
    );
    assert_eq!(
        fx.cat.delete_bucket(&one).await.unwrap(),
        Guard::Applied(())
    );
    assert_eq!(
        fx.texts("SELECT name FROM buckets", &[]).await,
        ["two".to_string()]
    );
    assert_eq!(
        fx.texts("SELECT bucket_id FROM grants", &[]).await,
        [fx.other_bucket.as_str().to_string()]
    );
    // Gone: a second delete changes nothing, and nothing can be opened
    // or recorded under the id any more.
    assert_eq!(fx.cat.delete_bucket(&one).await.unwrap(), Guard::Lost);
    let id = UploadId::mint([0xee; 16]);
    assert!(fx
        .cat
        .create_upload(&UploadRow {
            id,
            bucket_id: fx.bucket.clone(),
            key: "k".into(),
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
        .is_err());
    let floor = GenerationId::mint(T0, [1; 8]);
    assert!(fx
        .cat
        .raise_floor(&fx.bucket, "k", &floor, false)
        .await
        .is_err());
    assert_eq!(fx.count("SELECT COUNT(*) FROM uploads").await, 1);
    assert_eq!(fx.count("SELECT COUNT(*) FROM key_floors").await, 0);
}

#[tokio::test]
async fn a_conditional_complete_is_judged_by_its_own_batch_and_leaves_the_upload_open() {
    let fx = Fx::new().await;
    // An object under the key, published by an earlier upload.
    let old_id = fx.create(&fx.bucket, KEY).await;
    let old_t = target(&fx.bucket, KEY, &old_id);
    let (old_x, _) = fx.part(&old_t, 1, 100).await;
    let mut old_c = fx.commit(&fx.bucket, KEY, &[(&old_x, 100)]);
    old_c.generation.etag = "\"old-1\"".into();

    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (x1, _) = fx.part(&t, 1, 500).await;
    let (upload, _) = fx.read(&t).await;

    // No object yet: nothing to match.
    for condition in [Precondition::Exists, Precondition::Etag("\"old-1\"".into())] {
        let c = fx.commit(&fx.bucket, KEY, &[(&x1, 500)]);
        assert_eq!(
            fx.cat
                .publish_upload_if(&t, upload.revision, &DIGEST, &c, Some(&condition))
                .await
                .unwrap(),
            Guard::Lost,
            "{condition:?}"
        );
    }
    assert_eq!(
        fx.cat
            .publish_upload_if(&old_t, 1, &DIGEST, &old_c, Some(&Precondition::Absent))
            .await
            .unwrap(),
        Guard::Applied(())
    );

    // An object under the key: not absent, and another ETag.
    for condition in [Precondition::Absent, Precondition::Etag("\"abc-2\"".into())] {
        let c = fx.commit(&fx.bucket, KEY, &[(&x1, 500)]);
        assert_eq!(
            fx.cat
                .publish_upload_if(&t, upload.revision, &DIGEST, &c, Some(&condition))
                .await
                .unwrap(),
            Guard::Lost,
            "{condition:?}"
        );
    }
    // Refused, the upload is what it was: open, at the same revision,
    // with its part, and the object under the key is the old one.
    let (after, parts) = fx.read(&t).await;
    assert_eq!(
        (after.state, after.revision),
        (UploadState::Open, upload.revision)
    );
    assert_eq!(parts.len(), 1);
    assert_eq!(
        fx.live_generation(&fx.bucket, KEY).await,
        Some(old_c.generation.id.to_string())
    );

    // So it can still be completed, here against the ETag that is live.
    let c = fx.commit(&fx.bucket, KEY, &[(&x1, 500)]);
    let matching = Precondition::Etag("\"old-1\"".into());
    assert_eq!(
        fx.cat
            .publish_upload_if(&t, upload.revision, &DIGEST, &c, Some(&matching))
            .await
            .unwrap(),
        Guard::Applied(())
    );
    assert_eq!(
        fx.live_generation(&fx.bucket, KEY).await,
        Some(c.generation.id.to_string())
    );
    assert_eq!(fx.read(&t).await.0.state, UploadState::Completed);
}

// ---------------------------------------------------------------------------
// A part in several extents
// ---------------------------------------------------------------------------

impl Fx {
    /// Stores part `number` as `sizes.len()` extents under intents of
    /// their own; returns the extents in body order.
    async fn sliced(
        &self,
        t: &UploadTarget<'_>,
        number: u16,
        sizes: &[u64],
    ) -> (Vec<ExtentId>, Guard<()>) {
        let extents: Vec<ExtentRow> = sizes.iter().map(|s| self.extent(t.bucket, *s)).collect();
        let ids: Vec<ExtentId> = extents.iter().map(|e| e.id.clone()).collect();
        let write = WriteId::mint([self.next(); 16]);
        let opened = self.cat.open_intents(&write, &ids, T0).await.unwrap();
        assert_eq!(opened, Guard::Applied(()));
        let part = sliced_row(t, number, &extents);
        let g = self
            .cat
            .put_upload_part_sliced(t, &part, &extents, &write, T0)
            .await
            .unwrap();
        (ids, g)
    }

    /// The extents of the open parts, as `part:piece:extent`.
    async fn staged(&self, t: &UploadTarget<'_>) -> Vec<String> {
        let all = self.cat.upload_extents(t, 1000).await.unwrap();
        all.iter()
            .map(|p| format!("{}:{}:{}", p.part_number, p.piece, p.extent.id))
            .collect()
    }
}

fn sliced_row(t: &UploadTarget<'_>, number: u16, extents: &[ExtentRow]) -> UploadPartRow {
    UploadPartRow {
        upload_id: t.id.clone(),
        part_number: number,
        extent_id: extents[0].id.clone(),
        size: extents.iter().map(|e| e.plain_size).sum(),
        etag: format!("\"etag-{number}\""),
        uploaded_at: T0,
    }
}

#[tokio::test]
async fn a_sliced_part_is_stored_only_under_its_own_open_intents() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let extents: Vec<ExtentRow> = (0..3).map(|_| fx.extent(&fx.bucket, 100)).collect();
    let ids: Vec<ExtentId> = extents.iter().map(|e| e.id.clone()).collect();
    let write = WriteId::mint([0xa1; 16]);
    let other = WriteId::mint([0xa2; 16]);
    let put = |extents: Vec<ExtentRow>, write: WriteId| {
        let (fx, t) = (&fx, &t);
        async move {
            let part = sliced_row(t, 1, &extents);
            fx.cat
                .put_upload_part_sliced(t, &part, &extents, &write, T0)
                .await
                .unwrap()
        }
    };

    // No rows at all, the rows of another write, fewer extents than
    // rows, and other extents than the rows name.
    assert_eq!(put(extents.clone(), write.clone()).await, Guard::Lost);
    assert_eq!(
        fx.cat.open_intents(&write, &ids, T0).await.unwrap(),
        Guard::Applied(())
    );
    assert_eq!(put(extents.clone(), other).await, Guard::Lost);
    assert_eq!(put(extents[..2].to_vec(), write.clone()).await, Guard::Lost);
    let mut swapped = extents.clone();
    swapped[2] = fx.extent(&fx.bucket, 100);
    assert_eq!(put(swapped, write.clone()).await, Guard::Lost);
    assert_eq!(fx.count("SELECT COUNT(*) FROM extents").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM upload_parts").await, 0);
    assert_eq!(fx.count("SELECT COUNT(*) FROM write_intents").await, 3);
    assert_eq!(fx.read(&t).await.0.revision, 0);

    // Rows that were given up store nothing either.
    fx.cat.abandon_intents(&write).await.unwrap();
    assert_eq!(put(extents.clone(), write.clone()).await, Guard::Lost);
    assert_eq!(fx.count("SELECT COUNT(*) FROM extents").await, 0);

    // Under its own open rows the part is stored, and the rows go.
    let (stored, g) = fx.sliced(&t, 1, &[100, 100, 40]).await;
    assert_eq!(g, Guard::Applied(()));
    assert_eq!(
        fx.staged(&t).await,
        [
            format!("1:0:{}", stored[0]),
            format!("1:1:{}", stored[1]),
            format!("1:2:{}", stored[2])
        ]
    );
    assert_eq!(fx.count("SELECT COUNT(*) FROM write_intents").await, 3);
    let (upload, parts) = fx.read(&t).await;
    assert_eq!((upload.revision, parts.len()), (1, 1));
    assert_eq!((parts[0].size, &parts[0].extent_id), (240, &stored[0]));

    // One extent in its place: all three go to garbage collection.
    let (single, _) = fx.part(&t, 1, 100).await;
    let mut want: Vec<String> = stored.iter().map(|x| x.to_string()).collect();
    want.sort();
    assert_eq!(fx.gc_extents().await, want);
    assert_eq!(fx.staged(&t).await, [format!("1:0:{single}")]);
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM upload_part_extents").await,
        0
    );

    // And slices in the place of the one extent. Abort takes them all.
    let (again, _) = fx.sliced(&t, 1, &[100, 100]).await;
    want.push(single.to_string());
    want.sort();
    assert_eq!(fx.gc_extents().await, want);
    assert_eq!(
        fx.cat.abort_upload(&t, T0).await.unwrap(),
        Guard::Applied(())
    );
    want.extend(again.iter().map(|x| x.to_string()));
    want.sort();
    assert_eq!(fx.gc_extents().await, want);
    assert_eq!(put(extents, write).await, Guard::Lost);
}

#[tokio::test]
async fn complete_adopts_a_sliced_part_whole_and_in_order() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (s, _) = fx.sliced(&t, 1, &[100, 100, 100]).await;
    let (d, _) = fx.part(&t, 2, 100).await;
    let (unlisted, _) = fx.sliced(&t, 3, &[100, 100]).await;
    let (a, b, c) = (&s[0], &s[1], &s[2]);

    // Not a part of its slices, not in another order, and not with
    // another part between them.
    for extents in [
        vec![a, b, &d],
        vec![a, c, &d],
        vec![b, c, &d],
        vec![a, &d],
        vec![a, c, b, &d],
        vec![b, a, c, &d],
        vec![a, &d, b, c],
        vec![a, b, c, &d, &unlisted[1]],
    ] {
        let sized: Vec<(&ExtentId, u64)> = extents.iter().map(|x| (*x, 100)).collect();
        let commit = fx.commit(&fx.bucket, KEY, &sized);
        assert_eq!(
            fx.cat
                .publish_upload(&t, 3, &DIGEST, &commit)
                .await
                .unwrap(),
            Guard::Lost,
            "{} extents",
            extents.len()
        );
    }
    assert_eq!(fx.count("SELECT COUNT(*) FROM generations").await, 0);
    assert_eq!(fx.read(&t).await.0.state, UploadState::Open);

    let sized: Vec<(&ExtentId, u64)> = [a, b, c, &d].into_iter().map(|x| (x, 100)).collect();
    let commit = fx.commit(&fx.bucket, KEY, &sized);
    assert_eq!(
        fx.cat
            .publish_upload(&t, 3, &DIGEST, &commit)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    let placed = fx
        .texts(
            "SELECT id FROM extents WHERE generation_id = ?1 AND state = 'committed' ORDER BY seq",
            &[text(commit.generation.id.as_str())],
        )
        .await;
    assert_eq!(placed, [a, b, c, &d].map(|x| x.to_string()));
    assert_eq!(fx.count("SELECT COUNT(*) FROM outbox").await, 4);
    // Both slices of the part that was not listed are collected.
    let mut want: Vec<String> = unlisted.iter().map(|x| x.to_string()).collect();
    want.sort();
    assert_eq!(fx.gc_extents().await, want);
    fx.assert_no_live_extent_is_gc_bound().await;
}

// ---------------------------------------------------------------------------
// Complete without the index on the generation of an extent
// ---------------------------------------------------------------------------

/// Complete finds the extents of its upload through the parts and the
/// generation's own rows, each by its primary key: on the schema the
/// next release leaves (no index on `extents.generation_id`) it adopts
/// plain and sliced parts as before, and no statement of it reads the
/// extents table through.
#[tokio::test]
async fn complete_reads_no_extent_but_its_own_once_the_generation_index_is_gone() {
    let fx = Fx::new().await;
    fx.cat
        .sql
        .db
        .apply(velmora_bridge::testkit::NEXT_DROP_SUPERSEDED_INDEXES)
        .unwrap();
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    let (s, _) = fx.sliced(&t, 1, &[100, 100, 100]).await;
    let (d, _) = fx.part(&t, 2, 100).await;
    let (_unlisted, _) = fx.part(&t, 3, 50).await;
    let (upload, _) = fx.read(&t).await;
    let listed = [(&s[0], 100), (&s[1], 100), (&s[2], 100), (&d, 100)];
    let c = fx.commit(&fx.bucket, KEY, &listed);
    fx.cat.sql.batched.borrow_mut().clear();
    assert_eq!(
        fx.cat
            .publish_upload(&t, upload.revision, &DIGEST, &c)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    let adopted = fx
        .texts(
            "SELECT extent_id FROM generation_extents WHERE generation_id = ?1 ORDER BY seq",
            &[text(c.generation.id.as_str())],
        )
        .await;
    let want: Vec<String> = listed.iter().map(|(x, _)| x.as_str().to_string()).collect();
    assert_eq!(adopted, want);
    let queued = fx
        .texts(
            "SELECT extent_id FROM outbox WHERE generation_id = ?1 ORDER BY extent_id",
            &[text(c.generation.id.as_str())],
        )
        .await;
    assert_eq!(queued.len(), 4);

    let ran = std::mem::take(&mut *fx.cat.sql.batched.borrow_mut());
    assert!(ran.len() > 5, "the batch of a Complete");
    for (sql, params) in ran {
        let plan = fx
            .cat
            .sql
            .db
            .query(&format!("EXPLAIN QUERY PLAN {sql}"), &params)
            .await
            .unwrap();
        for row in plan {
            let SqlValue::Text(step) = &row[3] else {
                panic!("unexpected {row:?}")
            };
            if step.starts_with("SCAN extents") && sql.starts_with("INSERT INTO generations") {
                // With triggers on `generations` (the usage counters),
                // SQLite compiles the parent side of each foreign key into
                // the INSERT: a walk of the child rows that runs only when
                // the statement itself broke a key, which fails it anyway.
                // `FkIfZero` jumps over it otherwise, so it reads nothing.
                assert!(
                    only_fk_guarded(&fx, sql, &params, "extents").await,
                    "{sql}\n{step}"
                );
                continue;
            }
            assert!(
                !step.starts_with("SCAN extents") && !step.starts_with("SCAN e"),
                "{sql}\n{step}"
            );
            // The offsets check walks the references in `seq` order
            // from their primary key: no sort.
            if sql.contains(" OVER (") {
                assert!(!step.contains("TEMP B-TREE"), "{sql}\n{step}");
            }
        }
    }
}

/// Every open of `table` in the program of `sql` comes right after an
/// `FkIfZero`: it runs only when a foreign key of the statement is broken.
async fn only_fk_guarded(fx: &Fx, sql: &str, params: &[SqlValue], table: &str) -> bool {
    let db = &fx.cat.sql.db;
    let root = db
        .query(
            "SELECT rootpage FROM sqlite_master WHERE type = 'table' AND name = ?1",
            &[text(table)],
        )
        .await
        .unwrap();
    let root = root[0][0].clone();
    let code = db.query(&format!("EXPLAIN {sql}"), params).await.unwrap();
    let op = |row: &Row| match &row[1] {
        SqlValue::Text(op) => op.clone(),
        other => panic!("unexpected {other:?}"),
    };
    let opens: Vec<usize> = (0..code.len())
        .filter(|&i| op(&code[i]) == "OpenRead" && code[i][3] == root)
        .collect();
    !opens.is_empty()
        && opens
            .iter()
            .all(|&i| i > 0 && op(&code[i - 1]) == "FkIfZero")
}

// ---------------------------------------------------------------------------
// UploadPart reads its own part only
// ---------------------------------------------------------------------------

/// Every `gc` row as `extent:action:due_at`, sorted.
async fn gc_rows(fx: &Fx) -> Vec<String> {
    fx.texts(
        "SELECT extent_id || ':' || action || ':' || due_at FROM gc \
         ORDER BY extent_id, action",
        &[],
    )
    .await
}

fn gc_want(extents: &[&ExtentId], now: UnixMs) -> Vec<String> {
    let mut want: Vec<String> = extents
        .iter()
        .flat_map(|x| {
            [
                format!("{x}:delete_safety:{}", now.0),
                format!("{x}:shred_key:{}", now.0 + DAY_MS),
            ]
        })
        .collect();
    want.sort();
    want
}

/// Every step of the query plan of `sql`.
async fn plan_steps(fx: &Fx, sql: &str, params: &[SqlValue]) -> Vec<String> {
    let plan = fx
        .cat
        .sql
        .db
        .query(&format!("EXPLAIN QUERY PLAN {sql}"), params)
        .await
        .unwrap();
    plan.into_iter()
        .map(|row| match &row[3] {
            SqlValue::Text(step) => step.clone(),
            other => panic!("unexpected {other:?}"),
        })
        .collect()
}

#[tokio::test]
async fn upload_part_seeks_its_own_part_and_gc_rows_are_unchanged() {
    let fx = Fx::new().await;
    let id = fx.create(&fx.bucket, KEY).await;
    let t = target(&fx.bucket, KEY, &id);
    // Other parts, one of them sliced: none of them may be read or sent
    // to GC by a replacement of part 2.
    let (one, _) = fx.part(&t, 1, 100).await;
    let (sliced3, _) = fx.sliced(&t, 3, &[100, 100, 40]).await;
    for n in 4..=40 {
        fx.part(&t, n, 10).await;
    }
    let (two, _) = fx.sliced(&t, 2, &[100, 60]).await;
    assert!(fx.gc_extents().await.is_empty());

    // The state alone, from the upload row.
    assert_eq!(
        fx.cat.upload_state(&t).await.unwrap(),
        Some(UploadState::Open)
    );
    let other = fx.create(&fx.other_bucket, KEY).await;
    assert_eq!(
        fx.cat
            .upload_state(&target(&fx.bucket, KEY, &other))
            .await
            .unwrap(),
        None,
        "an upload id of another bucket is unknown here"
    );

    // Replace part 2 (two extents) by one extent: exactly its two
    // extents go to GC, each with both actions, as before.
    fx.cat.sql.batched.borrow_mut().clear();
    let (two_new, g) = fx.part(&t, 2, 70).await;
    assert_eq!(g, Guard::Applied(()));
    assert_eq!(gc_rows(&fx).await, gc_want(&[&two[0], &two[1]], T0));

    // No statement of that batch walks the parts of the upload, whatever
    // the alias: only the part tables have an `upload_id` column, so
    // `(upload_id=?)` alone is such a walk; and nothing is scanned but
    // constant rows and the one-row `restore_state`.
    let ran = std::mem::take(&mut *fx.cat.sql.batched.borrow_mut());
    let mut by_part = 0;
    for (sql, params) in &ran {
        for step in plan_steps(&fx, sql, params).await {
            by_part += usize::from(step.contains("(upload_id=? AND part_number=?)"));
            let scan_ok =
                ["SCAN CONSTANT ROW", "SCAN a", "SCAN restore_state"].contains(&step.as_str());
            assert!(
                !step.contains("(upload_id=?)") && (!step.starts_with("SCAN ") || scan_ok),
                "{sql}\n{step}"
            );
        }
    }
    assert!(
        by_part >= 3,
        "the GC select (both tables) and the piece delete"
    );

    // Abort sends every remaining part extent to GC, as before.
    assert_eq!(
        fx.cat.abort_upload(&t, T0).await.unwrap(),
        Guard::Applied(())
    );
    let parts = fx.read(&t).await.1;
    assert_eq!(parts.len(), 40);
    let mut all: Vec<ExtentId> = vec![two[0].clone(), two[1].clone()];
    all.extend(parts.iter().map(|p| p.extent_id.clone()));
    all.extend(sliced3[1..].iter().cloned());
    assert!(all.contains(&one) && all.contains(&two_new));
    let refs: Vec<&ExtentId> = all.iter().collect();
    assert_eq!(gc_rows(&fx).await, gc_want(&refs, T0));
    assert_eq!(
        fx.cat.upload_state(&t).await.unwrap(),
        Some(UploadState::Aborted)
    );
}
