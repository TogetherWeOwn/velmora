//! Migration 0004 on a catalogue that already holds data.
//!
//! The catalogue is filled through the service, then taken back to the
//! schema of migration 0003 (the reference table, its indexes and its
//! triggers removed), which leaves exactly the rows a Worker from before
//! the migration writes. Applying 0004 to that must give every object the
//! reads it had.

mod service_support;

use service_support::*;
use velmora_bridge::testkit::{
    RusqliteSql, MIGRATION_0001, MIGRATION_0002, MIGRATION_0003, MIGRATION_0004,
};
use velmora_bridge::*;

const BUCKET: &str = "bkt-migrate";
const KEYS: [&str; 3] = ["one", "big", "over"];

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

    // Back to the schema of migration 0003, data kept.
    let db: &RusqliteSql = &rig.bridge.catalog.sql;
    db.apply(
        "DROP TRIGGER generation_extents_on_insert; \
         DROP TRIGGER generation_extents_on_adopt; \
         DROP INDEX upload_parts_by_extent; \
         DROP TABLE generation_extents;",
    )
    .unwrap();
    let old = RusqliteSql::open_in_memory().unwrap();
    for migration in [MIGRATION_0001, MIGRATION_0002, MIGRATION_0003] {
        old.apply(migration).unwrap();
    }
    assert_eq!(schema(db), schema(&old));

    db.apply(MIGRATION_0004).unwrap();
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
