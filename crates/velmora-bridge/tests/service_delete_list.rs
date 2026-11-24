//! DeleteObjects, ListMultipartUploads, ListParts and DeleteBucket through
//! `Bridge::handle`, over the SQL catalogue and in-memory blob stores.

mod intent_support;
mod service_support;

use std::rc::Rc;

use base64::Engine as _;
use intent_support::{admin, column, number, restore, rollback, snapshot};
use service_support::*;
use velmora_bridge::config::Maintenance;
use velmora_bridge::crypto::open_manifest;
use velmora_bridge::recovery::Tombstone;
use velmora_bridge::*;

const BUCKET: &str = "bkt-batch";
const OTHER: &str = "bkt-other";
const RO_KEY: &str = "AKIDBATCHREADONLY001";
const RO_SECRET: &str = "batch-read-only-signing-secret-012345678";
const OTHER_KEY: &str = "AKIDBATCHOTHER000001";
const OTHER_SECRET: &str = "batch-other-bucket-signing-secret-012345";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn escape(key: &str) -> String {
    key.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn delete_xml(keys: &[&str], quiet: bool) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for key in keys {
        xml.push_str(&format!("<Object><Key>{}</Key></Object>", escape(key)));
    }
    if quiet {
        xml.push_str("<Quiet>true</Quiet>");
    }
    xml.push_str("</Delete>");
    xml
}

/// `POST /bucket?delete` of `xml` with its `Content-MD5`.
async fn delete_objects(rig: &Rig, signer: &Signer, bucket: &str, xml: &str) -> Resp {
    let md5 = b64(&md5::compute(xml.as_bytes()).0);
    rig.call(
        signer,
        Method::Post,
        &format!("/{bucket}"),
        &[("delete", "")],
        &[("content-md5", &md5)],
        xml.as_bytes(),
    )
    .await
}

async fn delete_object(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Delete, &path(BUCKET, key), &[], &[], b"")
        .await
}

async fn get(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
        .await
}

/// The keys with a live object, straight from the catalogue.
fn live_keys(rig: &Rig) -> Vec<String> {
    column(rig, "SELECT key FROM objects ORDER BY key")
}

/// Every tombstone record of the safety store, opened: `(key, deleted_at)`.
async fn tombstones(rig: &Rig) -> Vec<(String, String, i64)> {
    let mut out = Vec::new();
    for name in rig.bridge.safety.keys() {
        if !name.starts_with("m/del/") {
            continue;
        }
        let sealed = rig.bridge.safety.inner.get(&name, None).await.unwrap();
        let plain = open_manifest(&rig.bridge.kek, &name, &sealed.unwrap()).unwrap();
        let record: Tombstone = serde_json::from_slice(&plain).unwrap();
        assert_eq!(format!("m/del/{}", record.id), name);
        out.push((record.bucket_id, record.key, record.deleted_at));
    }
    out.sort();
    out
}

/// A read-only key on `bucket`.
async fn reader(rig: &Rig, bucket: &Bucket) -> Signer {
    let signer = rig.key(RO_KEY, RO_SECRET, KeyStatus::Active).await;
    rig.grant(RO_KEY, bucket, Perm::Ro).await;
    signer
}

fn set_maintenance(rig: &mut Rig, mode: Maintenance) {
    Rc::get_mut(&mut rig.bridge)
        .expect("no request is running")
        .cfg
        .maintenance = mode;
}

// ---------------------------------------------------------------------------
// DeleteObjects
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn delete_objects_deletes_every_named_key_and_no_other() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    for key in ["a", "dir/b & <c>", "c", "keep"] {
        rig.put(&signer, BUCKET, key, key.as_bytes())
            .await
            .expect(200);
    }

    // A key that never existed is deleted too, as with DeleteObject.
    let xml = delete_xml(&["a", "dir/b & <c>", "never"], false);
    let resp = delete_objects(&rig, &signer, BUCKET, &xml).await;
    resp.expect(200);
    assert_eq!(resp.header("content-type"), Some("application/xml"));
    assert!(resp
        .text()
        .starts_with("<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"));
    assert_eq!(resp.values("Key"), ["a", "dir/b &amp; &lt;c&gt;", "never"]);
    assert_eq!(resp.text().matches("<Deleted>").count(), 3);
    assert!(!resp.text().contains("<Error>"));
    assert_eq!(live_keys(&rig), ["c", "keep"]);
    get(&rig, &signer, "a").await.expect_error(404, "NoSuchKey");
    assert_eq!(get(&rig, &signer, "keep").await.expect(200).body, b"keep");
    // One tombstone per object that was live, none for the key that was not.
    assert_eq!(
        tombstones(&rig)
            .await
            .into_iter()
            .map(|t| t.1)
            .collect::<Vec<_>>(),
        ["a", "dir/b & <c>"]
    );

    // Quiet: nothing to report when every key was deleted. A key named
    // twice is deleted once and answered twice.
    let resp = delete_objects(&rig, &signer, BUCKET, &delete_xml(&["c", "c"], true)).await;
    resp.expect(200);
    assert_eq!(
        resp.text(),
        "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></DeleteResult>"
    );
    assert_eq!(live_keys(&rig), ["keep"]);
    assert_eq!(tombstones(&rig).await.len(), 3);
    let resp = delete_objects(&rig, &signer, BUCKET, &delete_xml(&["x", "x"], false)).await;
    assert_eq!(resp.expect(200).values("Key"), ["x", "x"]);
}

#[tokio::test(flavor = "current_thread")]
async fn delete_objects_needs_an_integrity_check_that_holds() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let xml = delete_xml(&["k"], false);
    let post = |headers: &[(&str, &str)], body: &str| {
        signer.sign(
            rig.now(),
            Method::Post,
            &format!("/{BUCKET}"),
            &[("delete", "")],
            headers,
            body.as_bytes().to_vec(),
        )
    };

    // No Content-MD5 and no checksum: refused, although the signature
    // covers the body. The body is not read.
    let (resp, polled) = rig.send_watched(post(&[], &xml)).await;
    resp.expect_error(400, "InvalidRequest");
    assert_eq!(
        resp.message(),
        "Missing required header for this request: Content-MD5."
    );
    assert!(!polled);

    // A digest of another body.
    let wrong = b64(&md5::compute(b"another body").0);
    rig.send(post(&[("content-md5", &wrong)], &xml))
        .await
        .expect_error(400, "BadDigest");
    rig.send(post(&[("content-md5", "not base64!")], &xml))
        .await
        .expect_error(400, "InvalidDigest");
    let wrong = crc32c_b64(b"another body");
    rig.send(post(&[("x-amz-checksum-crc32c", &wrong)], &xml))
        .await
        .expect_error(400, "BadDigest");
    assert_eq!(live_keys(&rig), ["k"]);
    assert!(tombstones(&rig).await.is_empty());

    // A checksum header instead of Content-MD5.
    let sum = crc32c_b64(xml.as_bytes());
    let resp = rig
        .send(post(&[("x-amz-checksum-crc32c", &sum)], &xml))
        .await;
    assert_eq!(resp.expect(200).values("Key"), ["k"]);
    assert!(live_keys(&rig).is_empty());

    // The checksum in the trailer of an aws-chunked body, as SDKs send it.
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let chunked = |trailer_sum: &str| {
        let decoded = xml.len().to_string();
        let (mut req, _) = signer.sign_as(
            rig.now(),
            Method::Post,
            &format!("/{BUCKET}"),
            &[("delete", "")],
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", decoded.as_str()),
                ("x-amz-trailer", "x-amz-checksum-crc32c"),
            ],
            Vec::new(),
            Some("STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
        );
        req.set_header("transfer-encoding", "chunked");
        req.body = unsigned_chunks(
            xml.as_bytes(),
            64 * 1024,
            &format!("x-amz-checksum-crc32c:{trailer_sum}"),
        );
        req
    };
    rig.send(chunked(&wrong))
        .await
        .expect_error(400, "BadDigest");
    assert_eq!(live_keys(&rig), ["k"]);
    let resp = rig.send(chunked(&sum)).await;
    assert_eq!(resp.expect(200).values("Key"), ["k"]);
    assert!(live_keys(&rig).is_empty());
}

/// The document has a limit of its own. A deployment whose extents and
/// objects are capped below it still takes a full-size delete.
#[tokio::test(flavor = "current_thread")]
async fn delete_objects_takes_a_document_larger_than_an_extent() {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = 64 * 1024;
    cfg.max_put_bytes = 64 * 1024;
    cfg.slice_bytes = 64 * 1024;
    let rig = rig_with_selected(NoNntp, cfg);
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k0", b"payload").await.expect(200);

    // 200 keys of 1000 bytes: about 200 KiB of XML.
    let mut keys: Vec<String> = (0..199).map(|i| format!("{i:0>1000}")).collect();
    keys.push("k0".to_string());
    let xml = delete_xml(&keys.iter().map(String::as_str).collect::<Vec<_>>(), false);
    assert!(xml.len() > 3 * 64 * 1024);
    let resp = delete_objects(&rig, &signer, BUCKET, &xml).await;
    assert_eq!(resp.expect(200).values("Key").len(), 200);
    assert!(live_keys(&rig).is_empty());

    // The same document with a checksum header instead of `Content-MD5`
    // is validated against the same limit.
    let crc = crc32c_b64(xml.as_bytes());
    let resp = rig
        .call(
            &signer,
            Method::Post,
            &format!("/{BUCKET}"),
            &[("delete", "")],
            &[("x-amz-checksum-crc32c", &crc)],
            xml.as_bytes(),
        )
        .await;
    assert_eq!(resp.expect(200).values("Key").len(), 200);
}

#[tokio::test(flavor = "current_thread")]
async fn delete_objects_refuses_a_document_it_cannot_take() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k0", b"payload").await.expect(200);

    let many = |n: usize| {
        let keys: Vec<String> = (0..n).map(|i| format!("k{i}")).collect();
        delete_xml(&keys.iter().map(String::as_str).collect::<Vec<_>>(), true)
    };
    for (xml, code) in [
        // One key more than a request may name.
        (many(1001), "MalformedXML"),
        ("<Delete></Delete>".to_string(), "MalformedXML"),
        ("not xml at all".to_string(), "MalformedXML"),
        (
            "<Delete><Object><Key>k0</Key></Object>".to_string(),
            "MalformedXML",
        ),
        (
            "<Other><Object><Key>k0</Key></Object></Other>".to_string(),
            "MalformedXML",
        ),
        // A version cannot be deleted here: refused, not ignored.
        (
            "<Delete><Object><Key>k0</Key><VersionId>1</VersionId></Object></Delete>".to_string(),
            "InvalidRequest",
        ),
    ] {
        let resp = delete_objects(&rig, &signer, BUCKET, &xml).await;
        assert_eq!(
            (resp.status, resp.code().as_str()),
            (400, code),
            "{}",
            &xml[..xml.len().min(80)]
        );
        if code == "MalformedXML" {
            assert_eq!(resp.message(), "The XML you provided was not well-formed.");
        }
    }
    assert_eq!(live_keys(&rig), ["k0"]);
    assert!(tombstones(&rig).await.is_empty());

    // Exactly the limit is taken.
    let resp = delete_objects(&rig, &signer, BUCKET, &many(1000)).await;
    assert_eq!(
        resp.expect(200).text(),
        "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></DeleteResult>"
    );
    assert!(live_keys(&rig).is_empty());
    assert_eq!(tombstones(&rig).await.len(), 1);

    // A body over the size limit is refused before it is read.
    let huge = vec![b' '; 2 * 1024 * 1024 + 1];
    let md5 = b64(&md5::compute(&huge).0);
    let req = signer.sign(
        rig.now(),
        Method::Post,
        &format!("/{BUCKET}"),
        &[("delete", "")],
        &[("content-md5", &md5)],
        huge,
    );
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(400, "EntityTooLarge");
    assert!(!polled);
}

#[tokio::test(flavor = "current_thread")]
async fn delete_objects_answers_for_each_key_on_its_own() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"payload").await.expect(200);
    rig.put(&signer, BUCKET, "b", b"payload").await.expect(200);

    // A key no request can store is an error of that key only.
    let long = "k".repeat(1025);
    let resp = delete_objects(&rig, &signer, BUCKET, &delete_xml(&["a", &long], false)).await;
    resp.expect(200);
    assert_eq!(resp.values("Key"), ["a".to_string(), long.clone()]);
    assert_eq!(resp.values("Code"), ["InvalidArgument"]);
    assert_eq!(live_keys(&rig), ["b"]);
    // Quiet still reports it.
    let resp = delete_objects(&rig, &signer, BUCKET, &delete_xml(&["a", &long], true)).await;
    assert_eq!(resp.expect(200).values("Key"), [long]);

    // The tombstone of a key cannot be stored: the key is not deleted and
    // the answer says so, with status 200 and an entry per key.
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("m/del/".into());
    let resp = delete_objects(&rig, &signer, BUCKET, &delete_xml(&["b", "never"], false)).await;
    resp.expect(200);
    assert_eq!(resp.values("Key"), ["b", "never"]);
    assert_eq!(resp.values("Code"), ["InternalError"]);
    assert_eq!(resp.text().matches("<Deleted>").count(), 1);
    assert_eq!(live_keys(&rig), ["b"]);
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = None;

    // The catalogue fails after the tombstone was stored: not deleted
    // either, and a retry deletes.
    rig.bridge.catalog.sql.fail_writes.set(true);
    let resp = delete_objects(&rig, &signer, BUCKET, &delete_xml(&["b"], false)).await;
    assert_eq!(resp.expect(200).values("Code"), ["InternalError"]);
    rig.bridge.catalog.sql.fail_writes.set(false);
    assert_eq!(live_keys(&rig), ["b"]);
    let resp = delete_objects(&rig, &signer, BUCKET, &delete_xml(&["b"], false)).await;
    assert!(!resp.expect(200).text().contains("<Error>"));
    assert!(live_keys(&rig).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn delete_objects_is_held_to_the_grants_and_gates_of_a_delete() {
    let mut rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let other = rig.bucket(OTHER, true).await;
    let ro = reader(&rig, &bucket).await;
    let stranger = rig.key(OTHER_KEY, OTHER_SECRET, KeyStatus::Active).await;
    rig.grant(OTHER_KEY, &other, Perm::Rw).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let xml = delete_xml(&["k"], false);

    // A read-only key, a key of another bucket, no bucket, no signature.
    delete_objects(&rig, &ro, BUCKET, &xml)
        .await
        .expect_error(403, "AccessDenied");
    delete_objects(&rig, &stranger, BUCKET, &xml)
        .await
        .expect_error(404, "NoSuchBucket");
    delete_objects(&rig, &signer, "bkt-nowhere", &xml)
        .await
        .expect_error(404, "NoSuchBucket");
    let mut req = signer.sign(
        rig.now(),
        Method::Post,
        &format!("/{BUCKET}"),
        &[("delete", "")],
        &[],
        xml.as_bytes().to_vec(),
    );
    req.headers.retain(|(n, _)| n != "authorization");
    assert_eq!(rig.send(req).await.status, 403);
    // The key of another bucket deletes there, not here.
    let resp = delete_objects(&rig, &stranger, OTHER, &xml).await;
    assert_eq!(resp.expect(200).values("Key"), ["k"]);
    assert_eq!(live_keys(&rig), ["k"]);
    assert!(tombstones(&rig).await.is_empty());

    // While the catalogue is being restored nothing is deleted, and the
    // body is not read.
    set_maintenance(&mut rig, Maintenance::Restore);
    let md5 = b64(&md5::compute(xml.as_bytes()).0);
    let req = signer.sign(
        rig.now(),
        Method::Post,
        &format!("/{BUCKET}"),
        &[("delete", "")],
        &[("content-md5", &md5)],
        xml.as_bytes().to_vec(),
    );
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_writes_refused();
    assert!(!polled);
    set_maintenance(&mut rig, Maintenance::Off);
    assert_eq!(live_keys(&rig), ["k"]);
    assert!(tombstones(&rig).await.is_empty());
}

/// What a catalogue says about the keys of the bucket, without the ids
/// (they carry random bits).
fn catalogue_state(rig: &Rig) -> Vec<String> {
    let mut out = column(
        rig,
        "SELECT 'generation ' || key || ' ' || state FROM generations ORDER BY key, id",
    );
    out.extend(column(
        rig,
        "SELECT 'live ' || o.key || ' ' || g.etag FROM objects o \
         JOIN generations g ON g.id = o.generation_id ORDER BY o.key",
    ));
    out.extend(column(
        rig,
        "SELECT 'floor ' || key FROM key_floors ORDER BY key",
    ));
    out
}

const DELETED: [&str; 5] = ["a", "b", "never", "gone", "c"];

/// A rig with a snapshot of its empty catalogue, then the objects `a`,
/// `b`, `c` (`c` overwritten once), `keep`, and `gone`, which was
/// deleted before.
async fn seeded() -> (Rig, Signer) {
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    snapshot(&rig);
    for key in ["a", "b", "c", "c", "keep", "gone"] {
        rig.bridge.clock.advance_ms(10);
        rig.put(&signer, BUCKET, key, format!("body of {key}").as_bytes())
            .await
            .expect(200);
    }
    rig.bridge.clock.advance_ms(10);
    delete_object(&rig, &signer, "gone").await.expect(204);
    rig.bridge.clock.advance_ms(1000);
    (rig, signer)
}

/// One DeleteObjects request leaves the recovery records and the
/// catalogue that a DeleteObject request per key leaves, so a replay of
/// the records gives the same catalogue either way.
#[tokio::test(flavor = "current_thread")]
async fn delete_objects_records_what_a_delete_per_key_records() {
    let (mut batch, batch_signer) = seeded().await;
    let (mut single, single_signer) = seeded().await;
    let before = tombstones(&batch).await;
    assert_eq!(before.len(), 1);
    assert_eq!(before, tombstones(&single).await);
    assert_eq!(catalogue_state(&batch), catalogue_state(&single));

    let resp = delete_objects(&batch, &batch_signer, BUCKET, &delete_xml(&DELETED, false)).await;
    assert_eq!(resp.expect(200).values("Key"), DELETED);
    assert!(!resp.text().contains("<Error>"));
    for key in DELETED {
        delete_object(&single, &single_signer, key)
            .await
            .expect(204);
    }

    // The same tombstones: bucket, key and time, one per object that was
    // live, on top of the one both had.
    let records = tombstones(&batch).await;
    assert_eq!(records, tombstones(&single).await);
    assert_eq!(
        records.iter().map(|t| t.1.as_str()).collect::<Vec<_>>(),
        ["a", "b", "c", "gone"]
    );
    // The same number of records of every kind, and nothing else stored.
    let kinds = |rig: &Rig| {
        let mut kinds: Vec<String> = rig
            .bridge
            .safety
            .keys()
            .into_iter()
            .map(|k| k[..k.rfind('/').map_or(0, |i| i + 1)].to_string())
            .collect();
        kinds.sort();
        kinds
    };
    assert_eq!(kinds(&batch), kinds(&single));
    // The same catalogue.
    let state = catalogue_state(&batch);
    assert_eq!(state, catalogue_state(&single));
    assert_eq!(live_keys(&batch), ["keep"]);
    assert_eq!(
        number(&batch, "SELECT COUNT(*) FROM gc"),
        number(&single, "SELECT COUNT(*) FROM gc")
    );

    // The catalogue is lost and replayed from the records: the same
    // catalogue again, on both sides, with only `keep` alive.
    for (rig, signer) in [(&mut batch, &batch_signer), (&mut single, &single_signer)] {
        rollback(rig);
        assert!(live_keys(rig).is_empty());
        restore(rig).await;
        assert_eq!(live_keys(rig), ["keep"]);
        assert_eq!(
            get(rig, signer, "keep").await.expect(200).body,
            b"body of keep"
        );
        for key in DELETED {
            get(rig, signer, key).await.expect_error(404, "NoSuchKey");
        }
    }
    let replayed = catalogue_state(&batch);
    assert_eq!(replayed, catalogue_state(&single));
    assert!(
        replayed.contains(&"generation a deleted".to_string()),
        "{replayed:?}"
    );
}

// ---------------------------------------------------------------------------
// ListMultipartUploads and ListParts
// ---------------------------------------------------------------------------

async fn create(rig: &Rig, signer: &Signer, bucket: &str, key: &str) -> String {
    let created = rig
        .call(
            signer,
            Method::Post,
            &path(bucket, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    created.expect(200);
    created.values("UploadId").remove(0)
}

async fn part(rig: &Rig, signer: &Signer, key: &str, id: &str, n: u16, bytes: &[u8]) -> String {
    let n = n.to_string();
    let sent = rig
        .call(
            signer,
            Method::Put,
            &path(BUCKET, key),
            &[("partNumber", &n), ("uploadId", id)],
            &[],
            bytes,
        )
        .await;
    sent.expect(200);
    sent.header("etag").unwrap().to_owned()
}

async fn abort(rig: &Rig, signer: &Signer, key: &str, id: &str) {
    rig.call(
        signer,
        Method::Delete,
        &path(BUCKET, key),
        &[("uploadId", id)],
        &[],
        b"",
    )
    .await
    .expect(204);
}

async fn complete(rig: &Rig, signer: &Signer, key: &str, id: &str, etags: &[String]) {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in etags.iter().enumerate() {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
            i + 1
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        signer,
        Method::Post,
        &path(BUCKET, key),
        &[("uploadId", id)],
        &[("content-type", "application/xml")],
        xml.as_bytes(),
    )
    .await
    .expect(200);
}

async fn list_uploads(rig: &Rig, signer: &Signer, bucket: &str, query: &[(&str, &str)]) -> Resp {
    let mut q = vec![("uploads", "")];
    q.extend_from_slice(query);
    rig.call(signer, Method::Get, &format!("/{bucket}"), &q, &[], b"")
        .await
}

async fn list_parts(
    rig: &Rig,
    signer: &Signer,
    bucket: &str,
    key: &str,
    id: &str,
    query: &[(&str, &str)],
) -> Resp {
    let mut q = vec![("uploadId", id)];
    q.extend_from_slice(query);
    rig.call(signer, Method::Get, &path(bucket, key), &q, &[], b"")
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn list_multipart_uploads_lists_the_open_uploads_of_the_bucket() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let other = rig.bucket(OTHER, true).await;
    rig.grant(AKID, &other, Perm::Rw).await;

    // Nothing open yet.
    let resp = list_uploads(&rig, &signer, BUCKET, &[]).await;
    resp.expect(200);
    assert_eq!(resp.header("content-type"), Some("application/xml"));
    assert_eq!(resp.values("Bucket"), [BUCKET]);
    assert_eq!(resp.values("IsTruncated"), ["false"]);
    assert!(resp.values("UploadId").is_empty());

    rig.bridge.clock.advance_ms(1500);
    let mut ids = std::collections::BTreeMap::new();
    for key in ["a.txt", "dir/one", "dir/two & <three>", "z"] {
        ids.insert(key, create(&rig, &signer, BUCKET, key).await);
    }
    let second = create(&rig, &signer, BUCKET, "a.txt").await;
    let elsewhere = create(&rig, &signer, OTHER, "a.txt").await;
    let mut both = [ids["a.txt"].clone(), second.clone()];
    both.sort();

    let resp = list_uploads(&rig, &signer, BUCKET, &[]).await;
    resp.expect(200);
    assert_eq!(
        resp.values("Key"),
        [
            "a.txt",
            "a.txt",
            "dir/one",
            "dir/two &amp; &lt;three&gt;",
            "z"
        ]
    );
    assert_eq!(
        resp.values("UploadId"),
        [
            both[0].clone(),
            both[1].clone(),
            ids["dir/one"].clone(),
            ids["dir/two & <three>"].clone(),
            ids["z"].clone()
        ]
    );
    assert_eq!(resp.values("Initiated")[0], "2027-01-15T08:00:01.500Z");
    assert!(!resp.text().contains(&elsewhere));
    // The other bucket lists its own.
    let resp = list_uploads(&rig, &signer, OTHER, &[]).await;
    assert_eq!(resp.expect(200).values("UploadId"), [elsewhere]);

    // Prefix and delimiter.
    let resp = list_uploads(&rig, &signer, BUCKET, &[("prefix", "dir/")]).await;
    assert_eq!(resp.expect(200).values("UploadId").len(), 2);
    let resp = list_uploads(&rig, &signer, BUCKET, &[("delimiter", "/")]).await;
    resp.expect(200);
    assert_eq!(resp.values("Key"), ["a.txt", "a.txt", "z"]);
    assert!(resp
        .text()
        .contains("<CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes>"));
    let resp = list_uploads(&rig, &signer, BUCKET, &[("encoding-type", "url")]).await;
    assert_eq!(
        resp.expect(200).values("Key")[3],
        "dir%2Ftwo%20%26%20%3Cthree%3E"
    );

    // Pages of one: the markers of each page give the next.
    let mut seen = Vec::new();
    let mut marker: Option<(String, String)> = None;
    for _ in 0..10 {
        let mut q = vec![("max-uploads", "1")];
        if let Some((key, id)) = &marker {
            q.push(("key-marker", key));
            q.push(("upload-id-marker", id));
        }
        let resp = list_uploads(&rig, &signer, BUCKET, &q).await;
        resp.expect(200);
        seen.extend(resp.values("UploadId"));
        if resp.values("IsTruncated") == ["false"] {
            marker = None;
            break;
        }
        marker = Some((
            resp.values("NextKeyMarker")
                .remove(0)
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">"),
            resp.values("NextUploadIdMarker").remove(0),
        ));
    }
    assert!(marker.is_none(), "the listing did not end");
    assert_eq!(seen.len(), 5);
    assert_eq!(seen[..2], both);

    // An upload that was aborted or completed is no longer listed.
    abort(&rig, &signer, "z", &ids["z"]).await;
    let etag = part(&rig, &signer, "dir/one", &ids["dir/one"], 1, b"part").await;
    complete(&rig, &signer, "dir/one", &ids["dir/one"], &[etag]).await;
    let resp = list_uploads(&rig, &signer, BUCKET, &[]).await;
    assert_eq!(
        resp.expect(200).values("Key"),
        ["a.txt", "a.txt", "dir/two &amp; &lt;three&gt;"]
    );

    // A read-only key may list; a key without a grant may not.
    let ro = reader(&rig, &bucket).await;
    let resp = list_uploads(&rig, &ro, BUCKET, &[]).await;
    assert_eq!(resp.expect(200).values("UploadId").len(), 3);
    list_uploads(&rig, &ro, OTHER, &[])
        .await
        .expect_error(404, "NoSuchBucket");
    for (name, value) in [("max-uploads", "many"), ("encoding-type", "base64")] {
        list_uploads(&rig, &signer, BUCKET, &[(name, value)])
            .await
            .expect_error(400, "InvalidArgument");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn list_parts_lists_the_parts_of_one_open_upload() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let other = rig.bucket(OTHER, true).await;
    rig.grant(AKID, &other, Perm::Rw).await;
    let key = "dir/big file & <co>.bin";
    let id = create(&rig, &signer, BUCKET, key).await;

    // No part yet.
    let resp = list_parts(&rig, &signer, BUCKET, key, &id, &[]).await;
    resp.expect(200);
    assert_eq!(resp.values("Bucket"), [BUCKET]);
    assert_eq!(resp.values("Key"), ["dir/big file &amp; &lt;co&gt;.bin"]);
    assert_eq!(resp.values("UploadId"), std::slice::from_ref(&id));
    assert!(resp.values("PartNumber").is_empty());
    assert_eq!(resp.values("IsTruncated"), ["false"]);

    rig.bridge.clock.advance_ms(2000);
    let mut etags = std::collections::BTreeMap::new();
    for (n, len) in [(3u16, 300usize), (1, 100), (7, 700)] {
        etags.insert(
            n,
            part(&rig, &signer, key, &id, n, &pattern(n as u8, len)).await,
        );
    }
    // A part sent again replaces the first.
    etags.insert(1, part(&rig, &signer, key, &id, 1, &pattern(9, 111)).await);

    let resp = list_parts(&rig, &signer, BUCKET, key, &id, &[]).await;
    resp.expect(200);
    assert_eq!(resp.values("PartNumber"), ["1", "3", "7"]);
    assert_eq!(resp.values("Size"), ["111", "300", "700"]);
    assert_eq!(
        resp.values("ETag"),
        [1, 3, 7].map(|n| etags[&n].replace('"', "&quot;"))
    );
    assert_eq!(resp.values("LastModified")[0], "2027-01-15T08:00:02.000Z");

    // Pages.
    let resp = list_parts(&rig, &signer, BUCKET, key, &id, &[("max-parts", "2")]).await;
    resp.expect(200);
    assert_eq!(resp.values("PartNumber"), ["1", "3"]);
    assert_eq!(resp.values("IsTruncated"), ["true"]);
    assert_eq!(resp.values("NextPartNumberMarker"), ["3"]);
    let resp = list_parts(
        &rig,
        &signer,
        BUCKET,
        key,
        &id,
        &[("max-parts", "2"), ("part-number-marker", "3")],
    )
    .await;
    resp.expect(200);
    assert_eq!(resp.values("PartNumber"), ["7"]);
    assert_eq!(resp.values("IsTruncated"), ["false"]);
    list_parts(&rig, &signer, BUCKET, key, &id, &[("max-parts", "x")])
        .await
        .expect_error(400, "InvalidArgument");

    // A read-only key may list the parts.
    let ro = reader(&rig, &bucket).await;
    let resp = list_parts(&rig, &ro, BUCKET, key, &id, &[]).await;
    assert_eq!(resp.expect(200).values("PartNumber").len(), 3);

    // The id under another key, under another bucket, an id of another
    // bucket here, an id that never was, and one that is no id.
    let foreign = create(&rig, &signer, OTHER, key).await;
    let unknown = "0123456789abcdef0123456789abcdef";
    let upper = unknown.to_uppercase();
    for (b, k, i) in [
        (BUCKET, "another key", id.as_str()),
        (OTHER, key, id.as_str()),
        (BUCKET, key, foreign.as_str()),
        (BUCKET, key, unknown),
        (BUCKET, key, "nonsense"),
        (BUCKET, key, upper.as_str()),
        (BUCKET, key, ""),
    ] {
        let resp = list_parts(&rig, &signer, b, k, i, &[]).await;
        resp.expect_error(404, "NoSuchUpload");
        assert_eq!(
            resp.message(),
            "The specified upload does not exist. The upload ID may be invalid, or the upload \
             may have been aborted or completed.",
            "{b}/{k} {i}"
        );
        assert!(!resp.text().contains("<Part>"));
    }
    // It is found where it belongs.
    list_parts(&rig, &signer, OTHER, key, &foreign, &[])
        .await
        .expect(200);
    list_parts(&rig, &ro, OTHER, key, &foreign, &[])
        .await
        .expect_error(404, "NoSuchBucket");

    // Aborted or completed: no such upload any more.
    abort(&rig, &signer, key, &id).await;
    list_parts(&rig, &signer, BUCKET, key, &id, &[])
        .await
        .expect_error(404, "NoSuchUpload");
    let done = create(&rig, &signer, BUCKET, "done").await;
    let etag = part(&rig, &signer, "done", &done, 1, b"part").await;
    complete(&rig, &signer, "done", &done, &[etag]).await;
    list_parts(&rig, &signer, BUCKET, "done", &done, &[])
        .await
        .expect_error(404, "NoSuchUpload");
}

// ---------------------------------------------------------------------------
// DeleteBucket
// ---------------------------------------------------------------------------

/// `DELETE /bucket` with an `Authorization` header as given.
async fn delete_bucket_as(rig: &Rig, bucket: &str, authorization: Option<&str>) -> Resp {
    let mut req = Req {
        method: Method::Delete,
        target: format!("/{bucket}"),
        headers: Vec::new(),
        body: Vec::new(),
    };
    req.set_header("host", HOST);
    if let Some(value) = authorization {
        req.set_header("authorization", value);
    }
    rig.send(req).await
}

/// `DELETE /bucket` with the admin token.
async fn delete_bucket(rig: &Rig, bucket: &str) -> Resp {
    let token = format!("Bearer {}", rig.bridge.cfg.admin_token.expose());
    delete_bucket_as(rig, bucket, Some(&token)).await
}

fn bucket_names(rig: &Rig) -> Vec<String> {
    column(rig, "SELECT name FROM buckets ORDER BY name")
}

#[tokio::test(flavor = "current_thread")]
async fn delete_bucket_removes_a_bucket_that_never_held_anything() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let other = rig.bucket(OTHER, true).await;
    rig.grant(AKID, &other, Perm::Rw).await;
    let ro = reader(&rig, &bucket).await;
    rig.put(&signer, OTHER, "k", b"payload").await.expect(200);
    // Reading and listing leave no trace.
    rig.head(&signer, BUCKET, "k").await.expect(404);
    list_uploads(&rig, &ro, BUCKET, &[]).await.expect(200);
    let stored = rig.bridge.safety.keys();
    let rows_of_other = (rig.count("generations"), rig.count("extents"));

    // Only the administrator deletes a bucket.
    for auth in [None, Some("Bearer wrong"), Some("Basic abc")] {
        let resp = delete_bucket_as(&rig, BUCKET, auth).await;
        resp.expect_error(403, "AccessDenied");
    }
    let resp = rig
        .call(
            &signer,
            Method::Delete,
            &format!("/{BUCKET}"),
            &[],
            &[],
            b"",
        )
        .await;
    resp.expect_error(403, "AccessDenied");
    assert_eq!(
        resp.message(),
        "Only the administrator can delete a bucket."
    );
    rig.call(&ro, Method::Delete, &format!("/{BUCKET}"), &[], &[], b"")
        .await
        .expect_error(403, "AccessDenied");
    assert_eq!(bucket_names(&rig), [BUCKET, OTHER]);
    assert_eq!(rig.count("grants"), 3);

    let resp = delete_bucket(&rig, BUCKET).await;
    resp.expect(204);
    assert!(resp.body.is_empty());
    // The bucket and its grants are gone; the other bucket, its grant,
    // its rows and every stored blob are as they were.
    assert_eq!(bucket_names(&rig), [OTHER]);
    assert_eq!(
        column(&rig, "SELECT bucket_id FROM grants"),
        [other.id.as_str()]
    );
    assert_eq!(
        (rig.count("generations"), rig.count("extents")),
        rows_of_other
    );
    assert_eq!(rig.bridge.safety.keys(), stored);
    for table in ["generations", "objects", "key_floors", "uploads", "extents"] {
        assert_eq!(
            number(
                &rig,
                &format!(
                    "SELECT COUNT(*) FROM {table} WHERE bucket_id = '{}'",
                    bucket.id.as_str()
                )
            ),
            0,
            "{table}"
        );
    }
    assert_eq!(rig.head(&signer, OTHER, "k").await.status, 200);

    // Gone for every request, and deleting it again says so.
    assert_eq!(rig.head(&signer, BUCKET, "k").await.status, 404);
    assert_eq!(rig.put(&signer, BUCKET, "k", b"payload").await.status, 404);
    delete_bucket(&rig, BUCKET)
        .await
        .expect_error(404, "NoSuchBucket");
    delete_bucket(&rig, "bkt-never-was")
        .await
        .expect_error(404, "NoSuchBucket");
    assert_eq!(rig.bridge.safety.keys(), stored);

    // The name is free again, and the new bucket works.
    let again = rig.bucket(BUCKET, true).await;
    rig.grant(AKID, &again, Perm::Rw).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
}

#[tokio::test(flavor = "current_thread")]
async fn delete_bucket_keeps_a_bucket_that_holds_or_held_anything() {
    let not_empty = |resp: &Resp| {
        resp.expect_error(409, "BucketNotEmpty");
        assert!(resp
            .message()
            .starts_with("The bucket you tried to delete is not empty"));
    };

    // A live object.
    let rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let before = (rig.bridge.safety.keys(), catalogue_state(&rig));
    not_empty(&delete_bucket(&rig, BUCKET).await);
    // A key that may write the bucket is told the same.
    not_empty(
        &rig.call(
            &signer,
            Method::Delete,
            &format!("/{BUCKET}"),
            &[],
            &[],
            b"",
        )
        .await,
    );
    assert_eq!(bucket_names(&rig), [BUCKET]);
    assert_eq!(rig.count("grants"), 1);
    assert_eq!((rig.bridge.safety.keys(), catalogue_state(&rig)), before);
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, b"payload");

    // The object is deleted: its data is not released yet, and its
    // recovery records stay for good. A replay would bring the bucket
    // back from them, so the bucket is kept.
    delete_object(&rig, &signer, "k").await.expect(204);
    assert!(live_keys(&rig).is_empty());
    not_empty(&delete_bucket(&rig, BUCKET).await);
    not_empty(
        &rig.call(
            &signer,
            Method::Delete,
            &format!("/{BUCKET}"),
            &[],
            &[],
            b"",
        )
        .await,
    );
    assert_eq!(bucket_names(&rig), [BUCKET]);

    // An upload in progress, with and without a part, and after its abort.
    let rig = self::rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer, BUCKET, "big").await;
    not_empty(&delete_bucket(&rig, BUCKET).await);
    part(&rig, &signer, "big", &id, 1, b"part").await;
    not_empty(&delete_bucket(&rig, BUCKET).await);
    abort(&rig, &signer, "big", &id).await;
    not_empty(&delete_bucket(&rig, BUCKET).await);
    assert_eq!(bucket_names(&rig), [BUCKET]);
    assert_eq!(rig.count("uploads"), 1);

    // A write that stored its record and was never published: only the
    // floor of the key says so.
    let rig = self::rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::NotApplied));
    let resp = rig.put(&signer, BUCKET, "k", b"payload").await;
    rig.bridge.catalog.sql.fail_publish.set(None);
    assert_ne!(resp.status, 200);
    assert_eq!((rig.count("generations"), rig.count("key_floors")), (0, 1));
    assert!(rig.bridge.catalog.bucket_in_use(&bucket.id).await.unwrap());
    not_empty(&delete_bucket(&rig, BUCKET).await);
    assert_eq!(bucket_names(&rig), [BUCKET]);
}

#[tokio::test(flavor = "current_thread")]
async fn delete_bucket_is_refused_during_a_replay_and_allowed_under_maintenance() {
    let mut rig = rig_selected();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bucket(OTHER, true).await;

    // Under maintenance no client can write, and no replay is under way:
    // an empty bucket can go, and an S3 key still deletes nothing.
    set_maintenance(&mut rig, Maintenance::Restore);
    let signed = rig
        .call(
            &signer,
            Method::Delete,
            &format!("/{BUCKET}"),
            &[],
            &[],
            b"",
        )
        .await;
    assert_ne!(signed.status, 204);
    assert_eq!(bucket_names(&rig).len(), 2);
    delete_bucket(&rig, OTHER).await.expect(204);
    assert_eq!(bucket_names(&rig), [BUCKET]);

    // A replay is under way (its cursor is on record): the records it
    // has yet to read may name the bucket. Refused in either mode.
    let now = rig.now();
    let begun = rig.bridge.catalog.restore_begin(UnixMs(0), now).await;
    assert!(begun.unwrap().is_ok());
    for mode in [Maintenance::Restore, Maintenance::Off] {
        set_maintenance(&mut rig, mode);
        delete_bucket(&rig, BUCKET)
            .await
            .expect_error(503, "ServiceUnavailable");
        assert_eq!(bucket_names(&rig), [BUCKET]);
        assert_eq!(rig.count("grants"), 1);
    }
    // The catalogue refuses on its own, whatever the handler checked.
    let bucket = rig.bridge.catalog.bucket_by_name(BUCKET).await.unwrap();
    assert_eq!(
        rig.bridge
            .catalog
            .delete_bucket(&bucket.unwrap())
            .await
            .unwrap(),
        Guard::Lost
    );
    assert_eq!(bucket_names(&rig), [BUCKET]);
}

/// A request that was authorized before the bucket was deleted stores
/// nothing afterwards: no record, no upload, no blob.
#[tokio::test(flavor = "current_thread")]
async fn a_write_that_lost_its_bucket_stores_no_record() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    // The PUT stops at its first write to the safety store or the
    // catalogue; the bucket goes while it waits.
    let stored = rig.bridge.safety.keys();
    assert_eq!(
        rig.bridge.catalog.delete_bucket(&bucket).await.unwrap(),
        Guard::Applied(())
    );
    // What the stopped request does next, with the bucket it was given.
    let id = GenerationId::mint(rig.now(), [7; 8]);
    assert!(rig
        .bridge
        .catalog
        .raise_floor(&bucket.id, "k", &id, true)
        .await
        .is_err());
    assert!(velmora_bridge::recovery::write_tombstone(
        &rig.bridge.catalog,
        &rig.bridge.safety,
        &rig.bridge.kek,
        &rig.bridge.cfg.records,
        &bucket.id,
        "k",
        &id,
        rig.now(),
    )
    .await
    .is_err());
    assert_eq!(rig.bridge.safety.keys(), stored);
    assert_eq!(rig.count("key_floors"), 0);
    assert_eq!(rig.count("uploads"), 0);
    // And a new request finds no bucket.
    assert_eq!(rig.put(&signer, BUCKET, "k", b"payload").await.status, 404);
    assert_eq!(
        rig.call(
            &signer,
            Method::Post,
            &path(BUCKET, "k"),
            &[("uploads", "")],
            &[],
            b""
        )
        .await
        .status,
        404
    );
    assert_eq!(rig.bridge.safety.keys(), stored);
}

/// One replay of every record, under the maintenance the caller set.
/// Returns how many records it left out because another bucket holds
/// their bucket's name.
async fn replay_all(rig: &Rig) -> u64 {
    let mut body = serde_json::json!({ "since_ms": 0, "margin_ms": 0 });
    let mut other_bucket = 0;
    loop {
        let r = admin(rig, Method::Post, "/restore", body.to_string().as_bytes()).await;
        r.expect(200);
        let report: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        other_bucket += report["other_bucket_total"].as_u64().unwrap();
        if report["next"].is_null() {
            break;
        }
        body = serde_json::json!({ "cursor": report["next"] });
    }
    other_bucket
}

/// A bucket is deleted, its name is given to a new bucket that takes
/// data, and the catalogue is then set back to before the deletion. The
/// catalogue names the deleted bucket again, and a replay leaves the
/// records of the new one out and says so. Deleting the stale bucket,
/// which is still empty, and replaying again brings the objects back.
/// All of it runs under maintenance: the stale bucket still has its
/// grants, and a client write into it would keep it for good.
#[tokio::test(flavor = "current_thread")]
async fn a_rollback_to_before_a_bucket_deletion_is_repaired_by_deleting_it_again() {
    let mut rig = rig_selected();
    let (stale, signer) = rig.standard(BUCKET).await;
    snapshot(&rig);

    delete_bucket(&rig, BUCKET).await.expect(204);
    let body = format!(r#"{{"name":"{BUCKET}","disposable":true}}"#);
    admin(&rig, Method::Post, "/buckets", body.as_bytes())
        .await
        .expect(200);
    let fresh = rig
        .bridge
        .catalog
        .bucket_by_name(BUCKET)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(fresh.id, stale.id);
    rig.grant(AKID, &fresh, Perm::Rw).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);

    let bucket_ids = |rig: &Rig| column(rig, "SELECT id FROM buckets");
    rollback(&rig);
    assert_eq!(bucket_ids(&rig), [stale.id.as_str()]);

    // The replay ends, and reports the record it could not place.
    set_maintenance(&mut rig, Maintenance::Restore);
    assert_eq!(replay_all(&rig).await, 1);
    assert_eq!(bucket_ids(&rig), [stale.id.as_str()]);
    assert!(live_keys(&rig).is_empty());

    // The key is granted the stale bucket again. Maintenance is what
    // keeps its writes out until that bucket is gone.
    assert_eq!(rig.count("grants"), 1);
    let refused = rig.put(&signer, BUCKET, "window", b"payload").await;
    refused.expect_error(503, "ServiceUnavailable");
    assert_eq!(rig.count("generations"), 0);

    // The stale bucket never held anything, so it can go; the next replay
    // makes the bucket of the records and publishes them.
    delete_bucket(&rig, BUCKET).await.expect(204);
    assert_eq!(replay_all(&rig).await, 0);
    assert_eq!(bucket_ids(&rig), [fresh.id.as_str()]);
    assert_eq!(live_keys(&rig), ["k"]);
    set_maintenance(&mut rig, Maintenance::Off);

    // Grants are not in the records: the key is granted the bucket again.
    assert_eq!(rig.count("grants"), 0);
    assert_eq!(get(&rig, &signer, "k").await.status, 404);
    let restored = rig
        .bridge
        .catalog
        .bucket_by_name(BUCKET)
        .await
        .unwrap()
        .unwrap();
    rig.grant(AKID, &restored, Perm::Rw).await;
    let resp = get(&rig, &signer, "k").await;
    assert_eq!((resp.status, resp.body.as_slice()), (200, &b"payload"[..]));
}
