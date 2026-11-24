//! Requests that must not read every extent row of an object: a delete
//! and a conditional write need the generation alone, a part copied by
//! range needs the extents of its range, and a whole-object copy of a
//! source above the single-record limit is refused before it reads any.

mod service_support;

use service_support::*;
use velmora_bridge::config::SINGLE_RECORD_EXTENTS;
use velmora_bridge::*;

const BUCKET: &str = "bkt-large-readers";
const MIB: usize = 1024 * 1024;

/// Text of every statement that joins extent rows to a generation: the
/// whole-object read and the read of a range.
const EXTENT_ROWS: &str = "generation_extents ge JOIN extents e";
/// Text only the whole-object read has.
const EVERY_EXTENT: &str = "WHERE ge.generation_id = ?1 ORDER BY ge.seq";

fn source(key: &str) -> String {
    format!("/{BUCKET}/{}", uri_encode(key, true))
}

/// Makes single statements that contain `text` fail from now on.
fn refuse(rig: &Rig, text: &'static str) {
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = Some((text, 0));
}

fn allow(rig: &Rig) {
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = None;
}

async fn call(rig: &Rig, signer: &Signer, method: Method, key: &str, h: &[(&str, &str)]) -> Resp {
    rig.call(signer, method, &path(BUCKET, key), &[], h, b"")
        .await
}

async fn multipart(rig: &Rig, signer: &Signer, key: &str, parts: &[&[u8]]) {
    let created = rig
        .call(
            signer,
            Method::Post,
            &path(BUCKET, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    created.expect(200);
    let id = created.values("UploadId").remove(0);
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, bytes) in parts.iter().enumerate() {
        let n = (i + 1).to_string();
        let sent = rig
            .call(
                signer,
                Method::Put,
                &path(BUCKET, key),
                &[("partNumber", &n), ("uploadId", &id)],
                &[],
                bytes,
            )
            .await;
        sent.expect(200);
        let etag = sent.header("etag").unwrap();
        xml.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        signer,
        Method::Post,
        &path(BUCKET, key),
        &[("uploadId", &id)],
        &[("content-type", "application/xml")],
        xml.as_bytes(),
    )
    .await
    .expect(200);
}

/// Appends empty extents to a live generation until it has `to` of
/// them, the way a publication would have left them: one row and one
/// reference each, and the count on the generation. (The schema still
/// has the trigger that writes the reference for a worker older than
/// the table; the second statement is for when it is gone.)
fn grow(rig: &Rig, generation: &GenerationRow, to: u32) {
    let db = &rig.bridge.catalog.sql.inner;
    let fill = db.fixture(
        "WITH RECURSIVE n(i) AS (SELECT ?2 UNION ALL SELECT i + 1 FROM n WHERE i + 1 < ?3) \
             INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
               plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, \
               plain_sha256, cipher_sha256, safety_state, created_at) \
             SELECT printf('x_%026x', n.i), e.bucket_id, e.generation_id, e.state, n.i, ?4, \
               0, e.cipher_size, e.media_header, e.key_mode, e.wrapped_file_key, e.plain_md5, \
               e.plain_sha256, e.cipher_sha256, e.safety_state, e.created_at \
             FROM n, extents e WHERE e.generation_id = ?1 AND e.seq = 0",
        "WITH RECURSIVE n(i) AS (SELECT ?2 UNION ALL SELECT i + 1 FROM n WHERE i + 1 < ?3) \
             INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
               plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, \
               plain_sha256, cipher_sha256, safety_state, created_at) \
             SELECT 'x_' || lpad(to_hex(n.i), 26, '0'), e.bucket_id, e.generation_id, e.state, n.i, ?4, \
               0, e.cipher_size, e.media_header, e.key_mode, e.wrapped_file_key, e.plain_md5, \
               e.plain_sha256, e.cipher_sha256, e.safety_state, e.created_at \
             FROM n, extents e WHERE e.generation_id = ?1 AND e.seq = 0",
    );
    let id = SqlValue::Text(generation.id.as_str().into());
    let start = SqlValue::Int(i64::from(generation.extent_count));
    let stop = SqlValue::Int(i64::from(to));
    db.fixture_query_now(
        fill,
        &[
            id.clone(),
            start.clone(),
            stop.clone(),
            SqlValue::Int(generation.size as i64),
        ],
    )
    .unwrap();
    let reference = db.fixture(
        "INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
         SELECT ?1, seq, id, plain_offset FROM extents WHERE generation_id = ?1 AND seq >= ?2",
        "INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
         SELECT ?1, seq, id, plain_offset FROM extents WHERE generation_id = ?1 AND seq >= ?2 ON CONFLICT DO NOTHING",
    );
    db.fixture_query_now(reference, &[id.clone(), start])
        .unwrap();
    db.fixture_query_now(
        "UPDATE generations SET extent_count = ?2 WHERE id = ?1",
        &[id, stop],
    )
    .unwrap();
}

/// DeleteObject and the conditions of a write are decided on the
/// generation row. With every read of extent rows failing they still
/// answer, and answer the same.
#[tokio::test(flavor = "current_thread")]
async fn delete_and_write_conditions_load_no_extent_row() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let (a, b) = (pattern(1, 5 * MIB), pattern(2, 70_000));
    multipart(&rig, &signer, "big", &[&a, &b]).await;
    rig.put(&signer, BUCKET, "one", b"one").await.expect(200);
    let (big, extents) = rig.live(&bucket, "big").await.unwrap();
    assert_eq!(extents.len(), 2);

    refuse(&rig, EXTENT_ROWS);
    // The tripwire is live: a GET needs the rows and fails.
    call(&rig, &signer, Method::Get, "big", &[])
        .await
        .expect(500);

    let put = |headers: Vec<(&'static str, String)>| {
        let (rig, signer) = (&rig, &signer);
        async move {
            let headers: Vec<(&str, &str)> =
                headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
            rig.call(
                signer,
                Method::Put,
                &path(BUCKET, "big"),
                &[],
                &headers,
                b"next",
            )
            .await
        }
    };
    put(vec![("if-none-match", "*".into())])
        .await
        .expect_error(412, "PreconditionFailed");
    put(vec![(
        "if-match",
        "\"00000000000000000000000000000000\"".into(),
    )])
    .await
    .expect_error(412, "PreconditionFailed");
    assert_eq!(rig.count("generations"), 2);
    put(vec![("if-match", big.etag.clone())]).await.expect(200);
    put(vec![("if-none-match", "*".into())])
        .await
        .expect_error(412, "PreconditionFailed");

    call(&rig, &signer, Method::Delete, "big", &[])
        .await
        .expect(204);
    call(&rig, &signer, Method::Delete, "big", &[])
        .await
        .expect(204);
    call(&rig, &signer, Method::Delete, "never", &[])
        .await
        .expect(204);
    // Gone, so the condition now holds.
    put(vec![("if-none-match", "*".into())]).await.expect(200);

    allow(&rig);
    let back = call(&rig, &signer, Method::Get, "big", &[]).await;
    back.expect(200);
    assert_eq!(back.body, b"next");
    assert_eq!(
        call(&rig, &signer, Method::Get, "one", &[]).await.body,
        b"one"
    );
}

/// A source of exactly the single-record limit is copied as before; one
/// extent more and the copy is refused with an error that names the way
/// out, before any extent row is read and with nothing stored.
#[tokio::test(flavor = "current_thread")]
async fn copy_of_a_source_above_the_single_record_limit_is_refused() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(3, 50_000);
    rig.put(&signer, BUCKET, "src", &body).await.expect(200);
    let (src, _) = rig.live(&bucket, "src").await.unwrap();
    grow(&rig, &src, SINGLE_RECORD_EXTENTS);

    let from = source("src");
    let copy = |to: &'static str| {
        let (rig, signer, from) = (&rig, &signer, from.as_str());
        async move { call(rig, signer, Method::Put, to, &[("x-amz-copy-source", from)]).await }
    };
    copy("at-limit").await.expect(200);
    let (copied, extents) = rig.live(&bucket, "at-limit").await.unwrap();
    assert_eq!(copied.extent_count, SINGLE_RECORD_EXTENTS);
    assert_eq!(extents.len(), SINGLE_RECORD_EXTENTS as usize);
    assert_eq!((copied.size, &copied.etag), (src.size, &src.etag));

    let (src, _) = rig.live(&bucket, "src").await.unwrap();
    grow(&rig, &src, SINGLE_RECORD_EXTENTS + 1);
    let generations = rig.count("generations");
    let references = rig.count("generation_extents");
    let records = rig.bridge.safety.keys().len();
    refuse(&rig, EXTENT_ROWS);
    let refused = copy("above").await;
    refused.expect_error(400, "InvalidRequest");
    assert!(
        refused.message().contains("UploadPartCopy"),
        "{}",
        refused.message()
    );
    // Onto itself with new metadata is the same read of the source.
    call(
        &rig,
        &signer,
        Method::Put,
        "src",
        &[
            ("x-amz-copy-source", &from),
            ("x-amz-metadata-directive", "REPLACE"),
        ],
    )
    .await
    .expect_error(400, "InvalidRequest");
    allow(&rig);
    assert_eq!(rig.count("generations"), generations);
    assert_eq!(rig.count("generation_extents"), references);
    assert_eq!(rig.bridge.safety.keys().len(), records);
    assert!(rig.live(&bucket, "above").await.is_none());

    // A condition on the source that fails is still answered as one.
    call(
        &rig,
        &signer,
        Method::Put,
        "above",
        &[
            ("x-amz-copy-source", &from),
            ("x-amz-copy-source-if-none-match", &src.etag),
        ],
    )
    .await
    .expect_error(412, "PreconditionFailed");
}

/// The source of a copy is read twice, its generation and then its
/// rows, and the key can be overwritten in between. The conditions on
/// the source are then judged on what was loaded, not on what was seen
/// first.
#[tokio::test(flavor = "current_thread")]
async fn copy_judges_its_conditions_on_the_source_it_loaded() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "src", &pattern(4, 9_000))
        .await
        .expect(200);
    rig.put(&signer, BUCKET, "other", &pattern(5, 7_000))
        .await
        .expect(200);
    let (first, _) = rig.live(&bucket, "src").await.unwrap();
    let (other, _) = rig.live(&bucket, "other").await.unwrap();
    assert_ne!(first.etag, other.etag);

    let from = source("src");
    let copy = |to: &'static str| {
        let (rig, signer, from, etag) = (&rig, &signer, from.as_str(), first.etag.as_str());
        async move {
            let h = [
                ("x-amz-copy-source", from),
                ("x-amz-copy-source-if-match", etag),
            ];
            call(rig, signer, Method::Put, to, &h).await
        }
    };
    copy("before").await.expect(200);

    // Between the two reads the key gets the generation of `other`.
    *rig.bridge.catalog.sql.before_matching.borrow_mut() = Some((
        "FROM objects o JOIN generations g",
        1,
        "UPDATE objects SET generation_id = \
           (SELECT generation_id FROM objects WHERE key = 'other') WHERE key = 'src'"
            .into(),
    ));
    copy("during").await.expect_error(412, "PreconditionFailed");
    assert!(rig.bridge.catalog.sql.before_matching.borrow().is_none());
    assert!(rig.live(&bucket, "during").await.is_none());
    let (now, _) = rig.live(&bucket, "src").await.unwrap();
    assert_eq!(now.id, other.id);

    // And when it is deleted in between, there is no source.
    *rig.bridge.catalog.sql.before_matching.borrow_mut() = Some((
        "FROM objects o JOIN generations g",
        1,
        "DELETE FROM objects WHERE key = 'src'".into(),
    ));
    let h = [("x-amz-copy-source", from.as_str())];
    call(&rig, &signer, Method::Put, "gone", &h)
        .await
        .expect_error(404, "NoSuchKey");
    assert!(rig.bridge.catalog.sql.before_matching.borrow().is_none());
}

/// UploadPartCopy reads the extents of its range and no others, so it
/// is the way to copy a source too large for CopyObject.
#[tokio::test(flavor = "current_thread")]
async fn part_copy_reads_the_extents_of_its_range_from_a_source_of_any_size() {
    let rig = rig_selected();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let (a, b) = (pattern(4, 5 * MIB), pattern(5, 70_000));
    multipart(&rig, &signer, "big", &[&a, &b]).await;
    let (big, _) = rig.live(&bucket, "big").await.unwrap();
    grow(&rig, &big, SINGLE_RECORD_EXTENTS + 1);
    let whole = [a, b].concat();

    let created = rig
        .call(
            &signer,
            Method::Post,
            &path(BUCKET, "dst"),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    let id = created.values("UploadId").remove(0);
    let from = source("big");
    let (start, end) = (5 * MIB - 10, 5 * MIB + 60_000);
    refuse(&rig, EVERY_EXTENT);
    for (n, range) in [
        (1, format!("bytes={start}-{}", end - 1)),
        (2, "bytes=100-199".to_owned()),
    ] {
        let n = n.to_string();
        rig.call(
            &signer,
            Method::Put,
            &path(BUCKET, "dst"),
            &[("partNumber", &n), ("uploadId", &id)],
            &[
                ("x-amz-copy-source", &from),
                ("x-amz-copy-source-range", &range),
            ],
            b"",
        )
        .await
        .expect(200);
    }
    allow(&rig);

    let parts = rig
        .bridge
        .catalog
        .sql
        .inner
        .fixture_query_now(
            "SELECT e.plain_size, e.plain_md5 FROM upload_parts p \
          JOIN extents e ON e.id = p.extent_id WHERE p.upload_id = ?1 ORDER BY p.part_number",
            &[SqlValue::Text(id.as_str().into())],
        )
        .unwrap()
        .into_iter()
        .map(|row| {
            let [SqlValue::Int(size), SqlValue::Blob(md5)] = row.as_slice() else {
                panic!("unexpected fixture part")
            };
            (*size, md5.clone())
        })
        .collect::<Vec<_>>();
    let expected = [&whole[start..end], &whole[100..200]];
    assert_eq!(parts.len(), 2);
    for ((size, md5), bytes) in parts.iter().zip(expected) {
        assert_eq!(*size as usize, bytes.len());
        assert_eq!(md5[..], md5::compute(bytes).0);
    }
}
