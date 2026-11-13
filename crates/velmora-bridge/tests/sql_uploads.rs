//! `SqlCatalog` multipart uploads over SQLite with the D1 schema.
//!
//! The catalogue is single-writer per statement batch, so a race is two
//! batches in either order: each test runs the competing call between the
//! read (`upload`) and the write of the other, both ways round.
//!
//! Every statement goes through [`Probe`], which refuses more than 100
//! bound parameters (the D1 limit) and can make a batch fail after all of
//! its statements ran.

use std::cell::Cell;

use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::*;

const T0: UnixMs = UnixMs(1_762_992_000_123);
const DAY_MS: i64 = 86_400_000;
const KEY: &str = "dir/big file.bin";

struct Probe {
    db: RusqliteSql,
    /// When set, every batch ends with a failing `tx_guard` insert.
    lose_guard: Cell<bool>,
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
        fx.cat
            .complete_upload(&wrong, 1, &DIGEST, &c)
            .await
            .unwrap(),
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
            .complete_upload(&old_t, 1, &DIGEST, &old_c)
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
            .complete_upload(&t, upload.revision, &DIGEST, &c)
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
                fx.cat.complete_upload(&t, 1, &DIGEST, &c).await.unwrap(),
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
            .complete_upload(&victim_t, 1, &DIGEST, &c)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    let steal = fx.commit(&fx.bucket, KEY, &[(&theirs, 500)]);
    assert_eq!(
        fx.cat
            .complete_upload(&t, 1, &DIGEST, &steal)
            .await
            .unwrap(),
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
            fx.cat.complete_upload(&t, 2, &DIGEST, &c).await.unwrap(),
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
            fx.cat.complete_upload(&t, 2, &DIGEST, &c).await,
            Err(BridgeError::Invalid(_))
        ));
    }

    let ok = fx.commit(&fx.bucket, KEY, &[(&x1, 500), (&x2, 700)]);
    assert_eq!(
        fx.cat.complete_upload(&t, 2, &DIGEST, &ok).await.unwrap(),
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
        fx.cat.complete_upload(&t, 1, &DIGEST, &c).await.unwrap(),
        Guard::Applied(())
    );

    // A later overwrite of the same key by another upload.
    let later_id = fx.create(&fx.bucket, KEY).await;
    let later_t = target(&fx.bucket, KEY, &later_id);
    let (y1, _) = fx.part(&later_t, 1, 900).await;
    let later = fx.commit(&fx.bucket, KEY, &[(&y1, 900)]);
    assert_eq!(
        fx.cat
            .complete_upload(&later_t, 1, &DIGEST, &later)
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
                    .complete_upload(&t, revision, &DIGEST, &retry)
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
            .complete_upload(&t, seen.revision, &DIGEST, &stale)
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
            .complete_upload(&t, seen.revision, &DIGEST, &fresh)
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
            .complete_upload(&t, seen.revision, &DIGEST, &c)
            .await
            .unwrap(),
        Guard::Lost
    );
    // Not even at the post-abort revision.
    assert_eq!(
        fx.cat
            .complete_upload(&t, seen.revision + 1, &DIGEST, &c)
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
        fx.cat.complete_upload(&t, 1, &DIGEST, &c).await.unwrap(),
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
        fx.cat.complete_upload(&t, 1, &DIGEST, &c).await.unwrap(),
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
