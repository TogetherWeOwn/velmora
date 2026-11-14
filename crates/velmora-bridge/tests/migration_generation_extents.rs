//! Migration 0005 on a catalogue that already holds data.
//!
//! The catalogue is filled through the service, then taken back to the
//! schema of migration 0004 (the reference table, its indexes and its
//! triggers removed), which leaves exactly the rows a Worker from before
//! the migration writes. Applying 0005 to that must give every object the
//! reads it had.

mod service_support;

use service_support::*;
use velmora_bridge::testkit::{
    RusqliteSql, MIGRATION_0001, MIGRATION_0002, MIGRATION_0003, MIGRATION_0004, MIGRATION_0005,
};
use velmora_bridge::*;

const BUCKET: &str = "bkt-migrate";
const KEYS: [&str; 3] = ["one", "big", "over"];

/// Takes a catalogue back to the schema of migration 0004, data kept.
const UNDO_0005: &str = "DROP TRIGGER generation_extents_on_insert; \
     DROP TRIGGER generation_extents_on_adopt; \
     DROP TRIGGER gc_keep_shared_extents; \
     DROP TRIGGER outbox_keep_shared_extents; \
     DROP TRIGGER extents_keep_key_in_service; \
     DROP TRIGGER articles_keep_in_service; \
     DROP INDEX upload_parts_by_extent; \
     DROP TABLE generation_extents;";

fn schema(db: &RusqliteSql) -> Vec<(String, String, Option<String>)> {
    db.with_conn(|c| {
        let mut stmt = c
            .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        rows
    })
}

/// Every reference row, as text.
fn references(rig: &Rig) -> Vec<String> {
    rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c
            .prepare(
                "SELECT generation_id || '/' || seq || '/' || extent_id || '/' || plain_offset \
                 FROM generation_extents ORDER BY 1",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<String>, _>>()
            .unwrap();
        rows
    })
}

async fn multipart(rig: &Rig, signer: &Signer, key: &str, parts: &[&[u8]], complete: bool) {
    let object = path(BUCKET, key);
    let created = rig
        .call(signer, Method::Post, &object, &[("uploads", "")], &[], b"")
        .await;
    created.expect(200);
    let id = created.values("UploadId").remove(0);
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, part) in parts.iter().enumerate() {
        let n = (i + 1).to_string();
        let sent = rig
            .call(
                signer,
                Method::Put,
                &object,
                &[("partNumber", &n), ("uploadId", &id)],
                &[],
                part,
            )
            .await;
        sent.expect(200);
        xml.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
            sent.header("etag").unwrap()
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    if complete {
        rig.call(
            signer,
            Method::Post,
            &object,
            &[("uploadId", &id)],
            &[("content-type", "application/xml")],
            xml.as_bytes(),
        )
        .await
        .expect(200);
    }
}

/// What a reader sees of every key: the catalogue rows and the bytes.
async fn reads(
    rig: &Rig,
    bucket: &Bucket,
    signer: &Signer,
) -> Vec<(
    Option<(GenerationRow, Vec<ExtentRow>)>,
    Option<ObjectStatus>,
    Vec<u8>,
)> {
    let mut out = Vec::new();
    for key in KEYS.into_iter().chain(["gone"]) {
        let status = rig
            .bridge
            .catalog
            .object_status(&bucket.id, key)
            .await
            .unwrap();
        let got = rig
            .call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
            .await;
        out.push((rig.live(bucket, key).await, status, got.body));
    }
    out
}

#[tokio::test(flavor = "current_thread")]
async fn backfill_gives_existing_objects_the_reads_they_had() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let one = pattern(1, 123_456);
    let part_a = pattern(2, 5 * MIB);
    let part_b = pattern(3, 70_000);
    let over = pattern(4, 9_000);
    rig.put(&signer, BUCKET, "one", &one).await.expect(200);
    multipart(&rig, &signer, "big", &[&part_a, &part_b], true).await;
    rig.put(&signer, BUCKET, "over", &pattern(5, 500))
        .await
        .expect(200);
    rig.put(&signer, BUCKET, "over", &over).await.expect(200);
    rig.put(&signer, BUCKET, "gone", &pattern(6, 500))
        .await
        .expect(200);
    rig.call(
        &signer,
        Method::Delete,
        &path(BUCKET, "gone"),
        &[],
        &[],
        b"",
    )
    .await
    .expect(204);
    // An upload that is still open: its part is in no generation.
    multipart(&rig, &signer, "open", &[&pattern(7, 4_000)], false).await;

    let before = reads(&rig, &bucket, &signer).await;
    assert_eq!(before[0].2, one);
    assert_eq!(before[1].2, [part_a.as_slice(), part_b.as_slice()].concat());
    assert_eq!(before[2].2, over);
    assert!(before[3].0.is_none());
    let written = references(&rig);
    // one + big (2) + over (2 generations) + gone.
    assert_eq!(written.len(), 6);
    assert_eq!(rig.count("extents"), 7);

    // Back to the schema of migration 0004, data kept.
    let db: &RusqliteSql = &rig.bridge.catalog.sql;
    db.apply(UNDO_0005).unwrap();
    let old = RusqliteSql::open_in_memory().unwrap();
    for migration in [
        MIGRATION_0001,
        MIGRATION_0002,
        MIGRATION_0003,
        MIGRATION_0004,
    ] {
        old.apply(migration).unwrap();
    }
    assert_eq!(schema(db), schema(&old));

    db.apply(MIGRATION_0005).unwrap();
    assert_eq!(schema(db), schema(&RusqliteSql::with_schema().unwrap()));
    assert_eq!(references(&rig), written);
    assert_eq!(reads(&rig, &bucket, &signer).await, before);

    // The backfill statement is safe to run again.
    let again = db.with_conn(|c| {
        c.execute(
            "INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
             SELECT generation_id, seq, id, plain_offset FROM extents \
              WHERE generation_id IS NOT NULL AND seq IS NOT NULL AND plain_offset IS NOT NULL",
            [],
        )
        .unwrap()
    });
    assert_eq!(again, 0);
}

/// A Worker from before the migration publishes through the `extents`
/// columns alone. The triggers record the reference for it.
#[tokio::test(flavor = "current_thread")]
async fn old_writers_still_publish_readable_objects() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "one", &pattern(1, 1000))
        .await
        .expect(200);
    multipart(&rig, &signer, "open", &[&pattern(7, 4_000)], false).await;
    let (generation, extents) = rig.live(&bucket, "one").await.unwrap();
    assert_eq!(rig.count("generation_extents"), 1);

    // Multipart Complete, the old way: the staged part is adopted in place.
    let adopted = rig.bridge.catalog.sql.with_conn(|c| {
        c.execute(
            "UPDATE extents SET generation_id = ?1, state = 'committed', seq = 1, \
               plain_offset = 1000 WHERE state = 'staged'",
            [generation.id.as_str()],
        )
        .unwrap()
    });
    assert_eq!(adopted, 1);
    let (_, now) = rig.live(&bucket, "one").await.unwrap();
    assert_eq!(now.len(), 2);
    assert_eq!(now[0], extents[0]);
    assert_eq!((now[1].seq, now[1].plain_offset), (Some(1), Some(1000)));
}

/// What a Worker from before the migration runs to retire the live
/// generation of `(?1, ?2)`: garbage-collection rows and cancelled
/// postings for the extents first written for it, then the state.
const OLD_RETIRE: [&str; 3] = [
    "INSERT INTO gc(extent_id, action, due_at) \
     SELECT e.id, a.action, a.due_at FROM objects o \
     JOIN extents e ON e.generation_id = o.generation_id \
     JOIN (SELECT 'delete_cache' AS action, ?3 AS due_at \
           UNION ALL SELECT 'delete_safety', ?3 \
           UNION ALL SELECT 'shred_key', ?3) a \
     WHERE o.bucket_id = ?1 AND o.key = ?2",
    "UPDATE outbox SET stage = 'cancelled', updated_at = ?3 \
     WHERE stage NOT IN ('done', 'cancelled') AND extent_id IN \
       (SELECT e.id FROM objects o JOIN extents e ON e.generation_id = o.generation_id \
        WHERE o.bucket_id = ?1 AND o.key = ?2)",
    "UPDATE generations SET state = 'deleted', retired_at = ?3 WHERE id = \
       (SELECT generation_id FROM objects WHERE bucket_id = ?1 AND key = ?2)",
];

/// Runs [`OLD_RETIRE`] as that Worker does: one batch.
async fn old_retire(rig: &Rig, bucket: &Bucket, key: &str) -> Result<Vec<u64>> {
    let args = || {
        vec![
            SqlValue::Text(bucket.id.as_str().to_owned()),
            SqlValue::Text(key.to_owned()),
            SqlValue::Int(rig.now().0),
        ]
    };
    let stmts = OLD_RETIRE.iter().map(|sql| (*sql, args())).collect();
    rig.bridge.catalog.sql.batch(stmts).await
}

/// After a rollback, a Worker from before the migration does not know
/// that a copy shares the extents of its source. The statements with
/// which it would take them out of service fail; the ones that touch
/// nothing shared still work.
#[tokio::test(flavor = "current_thread")]
async fn old_workers_cannot_take_a_shared_extent_out_of_service() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(1, 200_000);
    rig.put(&signer, BUCKET, "src", &body).await.expect(200);
    rig.put(&signer, BUCKET, "solo", &pattern(2, 1000))
        .await
        .expect(200);
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "dst"),
        &[],
        &[("x-amz-copy-source", &format!("/{BUCKET}/src"))],
        b"",
    )
    .await
    .expect(200);
    let (_, shared) = rig.live(&bucket, "src").await.unwrap();
    let shared = SqlValue::Text(shared[0].id.as_str().to_owned());
    let (_, solo) = rig.live(&bucket, "solo").await.unwrap();
    let solo = SqlValue::Text(solo[0].id.as_str().to_owned());
    let db = &rig.bridge.catalog.sql;
    db.with_conn(|c| {
        c.execute(
            "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, \
               cipher_offset, cipher_len, payload_sha256, state) \
             SELECT id, 0, id, 'g', x'', 0, 1, x'', 'planned' FROM extents",
            [],
        )
        .unwrap()
    });
    let pending = rig.count("outbox WHERE stage NOT IN ('done', 'cancelled')");
    assert!(pending >= 2);

    // Retiring the source: refused, and the batch leaves nothing behind.
    let refused = old_retire(&rig, &bucket, "src").await.unwrap_err();
    assert!(
        format!("{refused:?}").contains("referenced by another live generation"),
        "{refused:?}"
    );
    assert_eq!(rig.count("gc"), 0);
    assert_eq!(rig.count("outbox WHERE stage = 'cancelled'"), 0);
    assert!(rig.live(&bucket, "src").await.is_some());
    // Each of the two statements is refused on its own, too.
    for sql in &OLD_RETIRE[..2] {
        let args = vec![
            SqlValue::Text(bucket.id.as_str().to_owned()),
            SqlValue::Text("src".to_owned()),
            SqlValue::Int(rig.now().0),
        ];
        let refused = db.batch(vec![(*sql, args)]).await.unwrap_err();
        assert!(
            format!("{refused:?}").contains("referenced by another live generation"),
            "{refused:?}"
        );
    }

    // The collector's writes, for an extent in service: refused.
    const SHRED: &str = "UPDATE extents SET wrapped_file_key = NULL WHERE id = ?1";
    const DROP_ARTICLES: &str = "DELETE FROM articles WHERE extent_id = ?1";
    for sql in [SHRED, DROP_ARTICLES] {
        for extent in [&shared, &solo] {
            let refused = db.batch(vec![(sql, vec![extent.clone()])]).await;
            let refused = refused.unwrap_err();
            assert!(format!("{refused:?}").contains("in service"), "{refused:?}");
        }
    }
    assert_eq!(rig.count("extents WHERE wrapped_file_key IS NULL"), 0);
    assert_eq!(rig.count("articles"), 2);

    // An object nothing else references retires as it always did.
    old_retire(&rig, &bucket, "solo").await.unwrap();
    assert_eq!(rig.count("gc"), 3);
    assert_eq!(rig.count("outbox WHERE stage = 'cancelled'"), 1);
    for sql in [SHRED, DROP_ARTICLES] {
        db.batch(vec![(sql, vec![solo.clone()])]).await.unwrap();
    }

    // So does the copy: no extent was first written for it, so nothing
    // is queued. After it, the source is the only reference and goes too.
    old_retire(&rig, &bucket, "dst").await.unwrap();
    assert_eq!(rig.count("gc"), 3);
    let read = rig
        .call(&signer, Method::Get, &path(BUCKET, "src"), &[], &[], b"")
        .await;
    read.expect(200);
    assert!(read.body == body);
    old_retire(&rig, &bucket, "src").await.unwrap();
    assert_eq!(rig.count("gc"), 6);
    db.batch(vec![(SHRED, vec![shared.clone()])]).await.unwrap();
}

/// The schema stops an older Worker only while the generation an extent
/// was first written for is live. Once the current Worker has retired
/// that generation and a copy keeps the extent in service, the older
/// Worker can cancel its posting. The periodic re-drive arms it again.
#[tokio::test(flavor = "current_thread")]
async fn a_posting_cancelled_after_its_first_generation_retired_is_revived() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(1, 200_000);
    rig.put(&signer, BUCKET, "src", &body).await.expect(200);
    rig.put(&signer, BUCKET, "solo", &pattern(2, 1000))
        .await
        .expect(200);
    let copy = [("x-amz-copy-source", &*format!("/{BUCKET}/src"))];
    rig.call(&signer, Method::Put, &path(BUCKET, "dst"), &[], &copy, b"")
        .await
        .expect(200);
    // The current Worker retires the source; the copy keeps its extent.
    rig.call(&signer, Method::Delete, &path(BUCKET, "src"), &[], &[], b"")
        .await
        .expect(204);
    // And an object of its own, whose posting is rightly cancelled.
    rig.call(
        &signer,
        Method::Delete,
        &path(BUCKET, "solo"),
        &[],
        &[],
        b"",
    )
    .await
    .expect(204);
    let (_, shared) = rig.live(&bucket, "dst").await.unwrap();
    let shared = SqlValue::Text(shared[0].id.as_str().to_owned());
    assert_eq!(rig.count("outbox WHERE stage = 'cancelled'"), 1);
    assert_eq!(rig.count("outbox WHERE stage = 'post'"), 1);

    // The older Worker's cancel, for the shared extent: not refused.
    let db = &rig.bridge.catalog.sql;
    db.batch(vec![(
        "UPDATE outbox SET stage = 'cancelled', attempts = 4, updated_at = 1 \
          WHERE stage NOT IN ('done', 'cancelled') AND extent_id = ?1",
        vec![shared.clone()],
    )])
    .await
    .unwrap();
    assert_eq!(rig.count("outbox WHERE stage = 'cancelled'"), 2);

    // One pass of the re-drive: the referenced extent is posted again,
    // the unreferenced one stays cancelled.
    let now = rig.now();
    assert_eq!(
        rig.bridge
            .catalog
            .revive_referenced(500, now)
            .await
            .unwrap(),
        1
    );
    let revived = db
        .query(
            "SELECT stage, attempts, next_at FROM outbox WHERE extent_id = ?1",
            std::slice::from_ref(&shared),
        )
        .await
        .unwrap();
    assert_eq!(
        revived,
        vec![vec![
            SqlValue::Text("post".to_owned()),
            SqlValue::Int(0),
            SqlValue::Int(now.0)
        ]]
    );
    assert_eq!(rig.count("outbox WHERE stage = 'cancelled'"), 1);
    assert_eq!(
        rig.bridge
            .catalog
            .revive_referenced(500, now)
            .await
            .unwrap(),
        0
    );

    // The scan is a rotation: with a window of one row it still reaches
    // every row, and starts over at the end.
    db.batch(vec![(
        "UPDATE outbox SET stage = 'cancelled' WHERE extent_id = ?1",
        vec![shared.clone()],
    )])
    .await
    .unwrap();
    // A release that was begun and not finished is taken up where it
    // stopped: only the release stage unpins the safety copy.
    db.batch(vec![(
        "UPDATE extents SET safety_state = 'releasing', evict_seq = evict_seq + 1 WHERE id = ?1",
        vec![shared.clone()],
    )])
    .await
    .unwrap();
    let mut total = 0;
    for _ in 0..rig.count("outbox") + 1 {
        total += rig.bridge.catalog.revive_referenced(1, now).await.unwrap();
    }
    assert_eq!(total, 1);
    assert_eq!(rig.count("outbox WHERE stage = 'release'"), 1);
    let read = rig
        .call(&signer, Method::Get, &path(BUCKET, "dst"), &[], &[], b"")
        .await;
    read.expect(200);
    assert!(read.body == body);
}

/// A live generation that does not have the extents it claims stops the
/// migration before it creates anything.
#[tokio::test(flavor = "current_thread")]
async fn migration_stops_when_a_live_object_would_come_out_short() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "one", &pattern(1, 1000))
        .await
        .expect(200);
    multipart(
        &rig,
        &signer,
        "big",
        &[&pattern(2, 5 * MIB), &pattern(3, 70_000)],
        true,
    )
    .await;
    let (big, _) = rig.live(&bucket, "big").await.unwrap();
    let db: &RusqliteSql = &rig.bridge.catalog.sql;
    db.apply(UNDO_0005).unwrap();
    let old = schema(db);

    // The second extent of "big" has lost its place.
    let damage = |seq: &str| {
        db.with_conn(|c| {
            c.execute(
                &format!("UPDATE extents SET seq = {seq} WHERE generation_id = ?1 AND seq = 1"),
                [big.id.as_str()],
            )
            .unwrap()
        })
    };
    assert_eq!(damage("NULL"), 1);
    assert!(db.apply(MIGRATION_0005).is_err());
    assert_eq!(schema(db), old);

    // A retired generation in that state holds nothing a reader needs.
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| {
            c.execute(
                "UPDATE generations SET state = 'superseded' WHERE id = ?1",
                [big.id.as_str()],
            )
        })
        .unwrap();
    db.apply(MIGRATION_0005).unwrap();
    assert_eq!(rig.count("generation_extents"), 2);
}
