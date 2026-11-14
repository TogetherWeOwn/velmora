//! CopyObject over the SQL catalogue and in-memory blob stores: the copy
//! is a new generation over the source's extents, and those extents stay
//! in service for as long as any live generation references them.

mod service_support;

use service_support::*;
use velmora_bridge::*;

const BUCKET: &str = "bkt-copy";
const DAY_SECS: u32 = 86_400;

fn source(key: &str) -> String {
    format!("/{BUCKET}/{}", uri_encode(key, true))
}

async fn copy<N: NntpConnector + 'static>(
    rig: &Rig<N>,
    signer: &Signer,
    from: &str,
    to: &str,
    extra: &[(&str, &str)],
) -> Resp {
    let mut headers = vec![("x-amz-copy-source", from)];
    headers.extend_from_slice(extra);
    rig.call(signer, Method::Put, &path(BUCKET, to), &[], &headers, b"")
        .await
}

async fn get<N: NntpConnector + 'static>(rig: &Rig<N>, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
        .await
}

async fn delete<N: NntpConnector + 'static>(rig: &Rig<N>, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Delete, &path(BUCKET, key), &[], &[], b"")
        .await
}

/// Runs every garbage-collection row that is due a week from now.
async fn collect_garbage<N: NntpConnector + 'static>(rig: &Rig<N>) {
    rig.bridge.clock.advance_secs(7 * DAY_SECS);
    assert_eq!(
        rig.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
}

fn open_gc<N: NntpConnector + 'static>(rig: &Rig<N>, extent: &ExtentId) -> i64 {
    rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row(
            "SELECT COUNT(*) FROM gc WHERE extent_id = ?1",
            [extent.as_str()],
            |r| r.get(0),
        )
        .unwrap()
    })
}

fn generation_state<N: NntpConnector + 'static>(rig: &Rig<N>, id: &GenerationId) -> String {
    rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row(
            "SELECT state FROM generations WHERE id = ?1",
            [id.as_str()],
            |r| r.get(0),
        )
        .unwrap()
    })
}

#[tokio::test(flavor = "current_thread")]
async fn copy_is_a_new_generation_over_the_same_extent() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(5, 300_000);
    let put = rig
        .call(
            &signer,
            Method::Put,
            &path(BUCKET, "src dir/ü.bin"),
            &[],
            &[
                ("content-type", "application/x-test"),
                ("x-amz-meta-origin", "unit test"),
            ],
            &body,
        )
        .await;
    put.expect(200);
    let etag = put.header("etag").unwrap().to_owned();
    let (from, from_extents) = rig.live(&bucket, "src dir/ü.bin").await.unwrap();
    let blobs = rig.bridge.safety.keys();
    rig.bridge.jobs.inner.take();
    rig.bridge.clock.advance_secs(90);

    let done = copy(&rig, &signer, &source("src dir/ü.bin"), "dst/copy.bin", &[]).await;
    done.expect(200);
    assert_eq!(done.header("content-type"), Some("application/xml"));
    assert!(
        done.text().contains("<CopyObjectResult>"),
        "{}",
        done.text()
    );
    assert_eq!(
        done.values("ETag"),
        vec![etag.replace('"', "&quot;")],
        "{}",
        done.text()
    );
    assert_eq!(done.values("LastModified").len(), 1);

    // Nothing was stored, sealed or queued for posting.
    assert_eq!(rig.bridge.safety.keys(), blobs);
    assert_eq!(rig.count("extents"), 1);
    assert_eq!(rig.count("outbox"), 1);
    assert_eq!(rig.count("generations"), 2);
    assert_eq!(rig.count("generation_extents"), 2);
    assert!(rig.bridge.jobs.inner.sent().is_empty());

    let (to, to_extents) = rig.live(&bucket, "dst/copy.bin").await.unwrap();
    assert_ne!(to.id, from.id);
    assert_eq!(to_extents, from_extents);
    assert_eq!((to.size, &to.etag), (from.size, &from.etag));
    assert_eq!(to.created_at, rig.now());

    let read = get(&rig, &signer, "dst/copy.bin").await;
    read.expect(200);
    assert_eq!(read.body, body);
    assert_eq!(read.header("etag"), Some(etag.as_str()));
    assert_eq!(read.header("content-type"), Some("application/x-test"));
    assert_eq!(read.header("x-amz-meta-origin"), Some("unit test"));
    // The source is untouched.
    let read = get(&rig, &signer, "src dir/ü.bin").await;
    read.expect(200);
    assert_eq!(read.body, body);

    // The source may be named without the leading slash.
    let bare = format!("{BUCKET}/dst/copy.bin");
    copy(&rig, &signer, &bare, "dst/again.bin", &[])
        .await
        .expect(200);
    assert_eq!(get(&rig, &signer, "dst/again.bin").await.body, body);
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_directive_copies_or_replaces() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(6, 10_000);
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "a"),
        &[],
        &[("content-type", "text/a"), ("x-amz-meta-one", "1")],
        &body,
    )
    .await
    .expect(200);

    // COPY ignores the metadata the request carries.
    copy(
        &rig,
        &signer,
        &source("a"),
        "kept",
        &[
            ("x-amz-metadata-directive", "COPY"),
            ("content-type", "text/ignored"),
            ("x-amz-meta-two", "2"),
        ],
    )
    .await
    .expect(200);
    let read = get(&rig, &signer, "kept").await;
    assert_eq!(read.header("content-type"), Some("text/a"));
    assert_eq!(read.header("x-amz-meta-one"), Some("1"));
    assert_eq!(read.header("x-amz-meta-two"), None);

    copy(
        &rig,
        &signer,
        &source("a"),
        "replaced",
        &[
            ("x-amz-metadata-directive", "REPLACE"),
            ("content-type", "text/b"),
            ("x-amz-meta-two", "2"),
        ],
    )
    .await
    .expect(200);
    let read = get(&rig, &signer, "replaced").await;
    read.expect(200);
    assert_eq!(read.body, body);
    assert_eq!(read.header("content-type"), Some("text/b"));
    assert_eq!(read.header("x-amz-meta-one"), None);
    assert_eq!(read.header("x-amz-meta-two"), Some("2"));

    copy(
        &rig,
        &signer,
        &source("a"),
        "bad",
        &[("x-amz-metadata-directive", "MERGE")],
    )
    .await
    .expect_error(400, "InvalidArgument");
    assert_eq!(get(&rig, &signer, "bad").await.status, 404);
}

#[tokio::test(flavor = "current_thread")]
async fn source_conditions_that_do_not_hold_are_412() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let put = rig.put(&signer, BUCKET, "a", &pattern(7, 1000)).await;
    let etag = put.header("etag").unwrap().to_owned();
    // The object was written in 2027.
    let before = "Sat, 01 Jan 2000 00:00:00 GMT";
    let after = "Tue, 01 Jan 2030 00:00:00 GMT";

    let refused: [(&str, &str); 4] = [
        ("x-amz-copy-source-if-match", "\"0000\""),
        ("x-amz-copy-source-if-none-match", &etag),
        ("x-amz-copy-source-if-unmodified-since", before),
        ("x-amz-copy-source-if-modified-since", after),
    ];
    for header in refused {
        let r = copy(&rig, &signer, &source("a"), "b", &[header]).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (412, "PreconditionFailed"),
            "{header:?}"
        );
    }
    assert_eq!(get(&rig, &signer, "b").await.status, 404);
    assert_eq!(rig.count("generations"), 1);

    let held: [(&str, &str); 4] = [
        ("x-amz-copy-source-if-match", &etag),
        ("x-amz-copy-source-if-none-match", "\"0000\""),
        ("x-amz-copy-source-if-unmodified-since", after),
        ("x-amz-copy-source-if-modified-since", before),
    ];
    for (i, header) in held.into_iter().enumerate() {
        let r = copy(&rig, &signer, &source("a"), &format!("ok-{i}"), &[header]).await;
        assert_eq!(r.status, 200, "{header:?}: {}", r.text());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn read_only_grant_on_the_destination_is_refused() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", &pattern(8, 1000))
        .await
        .expect(200);
    let reader = rig
        .key("AKIDTESTKEY000000002", secret(), KeyStatus::Active)
        .await;
    rig.grant("AKIDTESTKEY000000002", &bucket, Perm::Ro).await;

    get(&rig, &reader, "a").await.expect(200);
    copy(&rig, &reader, &source("a"), "b", &[])
        .await
        .expect_error(403, "AccessDenied");
    assert_eq!(rig.count("generations"), 1);
    assert_eq!(get(&rig, &signer, "b").await.status, 404);
}

#[tokio::test(flavor = "current_thread")]
async fn copy_onto_itself_needs_replace() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(9, 70_000);
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "a"),
        &[],
        &[("content-type", "text/old")],
        &body,
    )
    .await
    .expect(200);
    let (old, extents) = rig.live(&bucket, "a").await.unwrap();

    copy(&rig, &signer, &source("a"), "a", &[])
        .await
        .expect_error(400, "InvalidRequest");
    copy(
        &rig,
        &signer,
        &source("a"),
        "a",
        &[("x-amz-metadata-directive", "COPY")],
    )
    .await
    .expect_error(400, "InvalidRequest");
    assert_eq!(rig.live(&bucket, "a").await.unwrap().0.id, old.id);

    copy(
        &rig,
        &signer,
        &source("a"),
        "a",
        &[
            ("x-amz-metadata-directive", "REPLACE"),
            ("content-type", "text/new"),
        ],
    )
    .await
    .expect(200);
    let (new, new_extents) = rig.live(&bucket, "a").await.unwrap();
    assert_ne!(new.id, old.id);
    assert_eq!(new_extents, extents);
    assert_eq!(generation_state(&rig, &old.id), "superseded");
    // The replaced generation took nothing out of service with it.
    assert_eq!(open_gc(&rig, &extents[0].id), 0);
    assert_eq!(rig.count("outbox WHERE stage = 'cancelled'"), 0);

    collect_garbage(&rig).await;
    let read = get(&rig, &signer, "a").await;
    read.expect(200);
    assert_eq!(read.body, body);
    assert_eq!(read.header("content-type"), Some("text/new"));
}

#[tokio::test(flavor = "current_thread")]
async fn requests_the_copy_cannot_honour_store_nothing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bucket("bkt-other", true).await;
    rig.put(&signer, BUCKET, "a", &pattern(1, 1000))
        .await
        .expect(200);

    // Another bucket, whether or not it exists or is granted.
    for other in ["/bkt-other/a", "/bkt-missing/a"] {
        let r = copy(&rig, &signer, other, "b", &[]).await;
        r.expect_error(501, "NotImplemented");
        assert!(r.text().contains("another bucket"), "{}", r.text());
    }
    copy(&rig, &signer, &format!("/{BUCKET}/a?versionId=3"), "b", &[])
        .await
        .expect_error(501, "NotImplemented");
    copy(&rig, &signer, &format!("/{BUCKET}/a?x=1"), "b", &[])
        .await
        .expect_error(400, "InvalidArgument");
    copy(&rig, &signer, &format!("/{BUCKET}"), "b", &[])
        .await
        .expect_error(400, "InvalidArgument");
    copy(&rig, &signer, &source("missing"), "b", &[])
        .await
        .expect_error(404, "NoSuchKey");
    // A copy has no body and no range.
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "b"),
        &[],
        &[("x-amz-copy-source", &source("a"))],
        b"body",
    )
    .await
    .expect_error(400, "InvalidRequest");
    copy(
        &rig,
        &signer,
        &source("a"),
        "b",
        &[("x-amz-copy-source-range", "bytes=0-9")],
    )
    .await
    .expect_error(400, "InvalidRequest");
    // A conditional on the destination is refused like on any write.
    copy(&rig, &signer, &source("a"), "b", &[("if-none-match", "*")])
        .await
        .expect_error(501, "NotImplemented");

    assert_eq!(get(&rig, &signer, "b").await.status, 404);
    assert_eq!(rig.count("generations"), 1);
    assert_eq!(rig.count("generation_extents"), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn extent_stays_until_the_last_generation_that_references_it_is_gone() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(2, 400_000);
    rig.put(&signer, BUCKET, "src", &body).await.expect(200);
    let (_, extents) = rig.live(&bucket, "src").await.unwrap();
    let extent = extents[0].id.clone();
    copy(&rig, &signer, &source("src"), "kept-1", &[])
        .await
        .expect(200);
    copy(&rig, &signer, &source("src"), "kept-2", &[])
        .await
        .expect(200);

    // Delete the source: the copies keep the extent in service.
    assert_eq!(delete(&rig, &signer, "src").await.status, 204);
    assert_eq!(open_gc(&rig, &extent), 0);
    assert_eq!(rig.count("outbox WHERE stage = 'cancelled'"), 0);
    collect_garbage(&rig).await;
    assert!(rig.bridge.safety.contains(&extent.safety_key()));
    for key in ["kept-1", "kept-2"] {
        let read = get(&rig, &signer, key).await;
        read.expect(200);
        assert_eq!(read.body, body, "{key}");
    }
    assert_eq!(get(&rig, &signer, "src").await.status, 404);

    // Overwrite one copy: the other still references the extent.
    let other = pattern(3, 5_000);
    rig.put(&signer, BUCKET, "kept-1", &other).await.expect(200);
    assert_eq!(open_gc(&rig, &extent), 0);
    collect_garbage(&rig).await;
    assert!(rig.bridge.safety.contains(&extent.safety_key()));
    assert_eq!(get(&rig, &signer, "kept-1").await.body, other);
    let read = get(&rig, &signer, "kept-2").await;
    read.expect(200);
    assert_eq!(read.body, body);
    let (_, last) = rig.live(&bucket, "kept-2").await.unwrap();
    assert!(last[0].wrapped_file_key.is_some());

    // The last reference goes: now, and only now, the extent is collected.
    assert_eq!(delete(&rig, &signer, "kept-2").await.status, 204);
    assert_eq!(open_gc(&rig, &extent), 3);
    assert_eq!(rig.count("outbox WHERE stage = 'cancelled'"), 1);
    collect_garbage(&rig).await;
    assert!(!rig.bridge.safety.contains(&extent.safety_key()));
    assert_eq!(rig.count("gc WHERE done_at IS NULL"), 0);
    assert_eq!(
        rig.count("extents WHERE wrapped_file_key IS NOT NULL"),
        1,
        "only the overwrite's extent keeps its key"
    );
}

/// A garbage-collection row for an extent a copy still references is
/// refused when it runs, however it came to be queued.
#[tokio::test(flavor = "current_thread")]
async fn collector_refuses_an_extent_a_copy_references() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(4, 50_000);
    rig.put(&signer, BUCKET, "src", &body).await.expect(200);
    let (_, extents) = rig.live(&bucket, "src").await.unwrap();
    let extent = extents[0].id.clone();
    copy(&rig, &signer, &source("src"), "kept", &[])
        .await
        .expect(200);
    assert_eq!(delete(&rig, &signer, "src").await.status, 204);

    rig.bridge.catalog.sql.with_conn(|c| {
        for action in ["delete_cache", "delete_safety", "shred_key"] {
            c.execute(
                "INSERT INTO gc(extent_id, action, due_at) VALUES (?1, ?2, 0)",
                [extent.as_str(), action],
            )
            .unwrap();
        }
    });
    collect_garbage(&rig).await;

    assert!(rig.bridge.safety.contains(&extent.safety_key()));
    assert_eq!(rig.count("gc WHERE done_at IS NULL"), 3);
    let read = get(&rig, &signer, "kept").await;
    read.expect(200);
    assert_eq!(read.body, body);
}

/// Without `SERVER_SIDE_COPY` no copy is created: a Worker that is rolled
/// back to must be able to read every object that exists.
#[tokio::test(flavor = "current_thread")]
async fn copy_is_refused_while_it_is_switched_off() {
    let mut cfg = config(Vec::new());
    cfg.server_side_copy = false;
    let rig = rig_with(NoNntp, cfg);
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", &pattern(1, 1000))
        .await
        .expect(200);
    let r = copy(&rig, &signer, &source("a"), "b", &[]).await;
    r.expect_error(501, "NotImplemented");
    assert!(r.text().contains("not enabled"), "{}", r.text());
    assert_eq!(get(&rig, &signer, "b").await.status, 404);
    assert_eq!(rig.count("generations"), 1);
    assert_eq!(rig.count("generation_extents"), 1);
}

/// A copy keeps the checksum stored with its source and computes none.
#[tokio::test(flavor = "current_thread")]
async fn copy_cannot_compute_another_checksum() {
    use base64::Engine as _;
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(1, 1000);
    let sum = base64::engine::general_purpose::STANDARD.encode(sha256(&body));
    rig.put(&signer, BUCKET, "bare", &body).await.expect(200);
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "summed"),
        &[],
        &[("x-amz-checksum-sha256", &sum)],
        &body,
    )
    .await
    .expect(200);

    let sha = [("x-amz-checksum-algorithm", "SHA256")];
    // The source has that checksum: it is the copy's as well.
    let r = copy(&rig, &signer, &source("summed"), "b", &sha).await;
    r.expect(200);
    assert_eq!(r.values("ChecksumSHA256"), std::slice::from_ref(&sum));
    // The source has none, or another one.
    copy(&rig, &signer, &source("bare"), "c", &sha)
        .await
        .expect_error(501, "NotImplemented");
    copy(
        &rig,
        &signer,
        &source("summed"),
        "c",
        &[("x-amz-checksum-algorithm", "CRC32")],
    )
    .await
    .expect_error(501, "NotImplemented");
    // A checksum value has no bytes to be checked against.
    copy(
        &rig,
        &signer,
        &source("summed"),
        "c",
        &[("x-amz-checksum-sha256", &sum)],
    )
    .await
    .expect_error(400, "InvalidRequest");
    assert_eq!(get(&rig, &signer, "c").await.status, 404);
    assert_eq!(rig.count("generations"), 3);
}
