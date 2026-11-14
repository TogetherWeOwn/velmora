//! Catalogue recovery (DESIGN §A.8): the recovery records are written
//! before a commit, are never deleted, and rebuild the catalogue.
//!
//! "Export" here is a copy of every catalogue table inside the same
//! SQLite database; "loss" deletes every row.

mod service_support;

use service_support::*;
use velmora_bridge::recovery::{delete_blob, GENERATION_PREFIX, TOMBSTONE_PREFIX};
use velmora_bridge::*;

const BUCKET: &str = "vault";
const TABLES: [&str; 12] = [
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

fn records(rig: &Rig) -> Vec<String> {
    rig.bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| k.starts_with("m/"))
        .collect()
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
