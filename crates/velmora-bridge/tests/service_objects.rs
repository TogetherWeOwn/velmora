//! PutObject, HeadObject, DeleteObject, authentication and the mutation
//! gates, over the SQL catalogue and in-memory blob stores.

mod service_support;

use base64::Engine as _;
use service_support::*;
use velmora_bridge::config::Maintenance;
use velmora_bridge::*;

const BUCKET: &str = "bkt-objects";

fn md5_etag(body: &[u8]) -> String {
    format!("\"{}\"", hex(&md5::compute(body).0))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Nothing a PUT would leave behind exists.
fn assert_nothing_stored<N: NntpConnector + 'static>(rig: &Rig<N>) {
    assert_eq!(rig.bridge.safety.keys(), Vec::<String>::new());
    assert_eq!(rig.bridge.cache.keys(), Vec::<String>::new());
    assert_eq!(rig.count("generations"), 0);
    assert_eq!(rig.count("objects"), 0);
    assert_eq!(rig.count("extents"), 0);
    assert_eq!(rig.count("outbox"), 0);
    assert!(rig.bridge.jobs.inner.sent().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn put_then_head_reports_the_stored_object() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    // Whole seconds are reported; the catalogue keeps milliseconds.
    rig.bridge.clock.advance_ms(999);
    let body = pattern(3, 200_000);

    let put = rig
        .call(
            &signer,
            Method::Put,
            &path(BUCKET, "dir/file.bin"),
            &[],
            &[
                ("content-type", "application/x-test"),
                ("cache-control", "max-age=60"),
                ("x-amz-meta-origin", "unit test"),
            ],
            &body,
        )
        .await;
    put.expect(200);
    assert_eq!(put.header("etag"), Some(md5_etag(&body).as_str()));
    assert!(put.body.is_empty());

    // The catalogue names one committed extent whose safety copy exists
    // and is not the plaintext.
    let (generation, extents) = rig.live(&bucket, "dir/file.bin").await.unwrap();
    assert_eq!(generation.size, body.len() as u64);
    assert_eq!(generation.created_at, UnixMs(T0.0 + 999));
    assert_eq!(extents.len(), 1);
    let extent = &extents[0];
    assert_eq!(extent.safety_state, SafetyState::Held);
    assert_eq!(extent.plain_sha256, sha256(&body));
    let blob = rig.bridge.safety.stored(&extent.id.safety_key()).unwrap();
    assert_eq!(blob.bytes.len() as u64, extent.cipher_size);
    assert_eq!(sha256(&blob.bytes), extent.cipher_sha256);
    assert!(!blob.bytes.windows(64).any(|w| w == &body[..64]));
    assert!(rig.bridge.cache.keys().is_empty());

    // One wake-up for the posting stage of that extent.
    let sent = rig.bridge.jobs.inner.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].job,
        Job::Extent {
            v: JOB_VERSION,
            extent: extent.id.clone(),
            generation: generation.id.clone(),
            stage: OutboxStage::Post,
        }
    );
    assert_eq!(rig.count("outbox"), 1);

    let head = rig.head(&signer, BUCKET, "dir/file.bin").await;
    head.expect(200);
    assert!(head.body.is_empty());
    assert_eq!(head.header("content-length"), Some("200000"));
    assert_eq!(head.header("etag"), Some(md5_etag(&body).as_str()));
    assert_eq!(
        head.header("last-modified"),
        Some("Fri, 15 Jan 2027 08:00:00 GMT")
    );
    assert_eq!(head.header("content-type"), Some("application/x-test"));
    assert_eq!(head.header("cache-control"), Some("max-age=60"));
    assert_eq!(head.header("x-amz-meta-origin"), Some("unit test"));
    assert_eq!(head.header("accept-ranges"), Some("bytes"));
}

#[tokio::test(flavor = "current_thread")]
async fn head_uses_the_catalogue_only() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"hello").await.expect(200);
    // With every copy of the bytes gone, HEAD still answers.
    let (_, extents) = rig.live(&bucket, "k").await.unwrap();
    rig.bridge
        .safety
        .delete(&extents[0].id.safety_key())
        .await
        .unwrap();
    let head = rig.head(&signer, BUCKET, "k").await;
    head.expect(200);
    assert_eq!(head.header("content-length"), Some("5"));

    let range = rig
        .call(
            &signer,
            Method::Head,
            &path(BUCKET, "k"),
            &[],
            &[("range", "bytes=1-3")],
            b"",
        )
        .await;
    range.expect(200);
    assert_eq!(range.header("content-length"), Some("3"));

    let not_modified = rig
        .call(
            &signer,
            Method::Head,
            &path(BUCKET, "k"),
            &[],
            &[("if-none-match", md5_etag(b"hello").as_str())],
            b"",
        )
        .await;
    not_modified.expect(304);

    let missing = rig.head(&signer, BUCKET, "nope").await;
    missing.expect(404);
    assert!(missing.body.is_empty(), "a HEAD error has no body");
}

#[tokio::test(flavor = "current_thread")]
async fn empty_object_and_overwrite() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let put = rig.put(&signer, BUCKET, "k", b"").await;
    put.expect(200);
    assert_eq!(put.header("etag"), Some(md5_etag(b"").as_str()));
    let head = rig.head(&signer, BUCKET, "k").await;
    assert_eq!(head.expect(200).header("content-length"), Some("0"));

    rig.put(&signer, BUCKET, "k", b"second").await.expect(200);
    let head = rig.head(&signer, BUCKET, "k").await;
    assert_eq!(head.header("etag"), Some(md5_etag(b"second").as_str()));
    let (generation, _) = rig.live(&bucket, "k").await.unwrap();
    assert_eq!(generation.size, 6);
    assert_eq!(rig.count("objects"), 1);
    assert_eq!(rig.count("generations"), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn put_is_not_acked_when_the_commit_fails() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.bridge.catalog.sql.with_conn(|c| {
        c.execute_batch(
            "CREATE TRIGGER refuse BEFORE INSERT ON objects \
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap()
    });
    let put = rig.put(&signer, BUCKET, "k", b"payload").await;
    put.expect_error(500, "InternalError");
    assert_eq!(put.header("etag"), None);
    // The batch rolled back as a whole; only the orphan safety blob is left.
    assert!(rig.live(&bucket, "k").await.is_none());
    assert_eq!(rig.count("generations"), 0);
    assert_eq!(rig.count("extents"), 0);
    assert_eq!(rig.count("outbox"), 0);
    assert!(rig.bridge.jobs.inner.sent().is_empty());
    rig.head(&signer, BUCKET, "k").await.expect(404);
}

#[tokio::test(flavor = "current_thread")]
async fn safety_copy_is_written_before_the_commit() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    // Exhaust the store: an in-memory store cannot fail, so make the
    // catalogue refuse instead and check the order through what is left.
    rig.bridge.catalog.sql.with_conn(|c| {
        c.execute_batch(
            "CREATE TRIGGER refuse BEFORE INSERT ON generations \
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap()
    });
    rig.put(&signer, BUCKET, "k", b"payload")
        .await
        .expect_error(500, "InternalError");
    // The safety copy was written before the catalogue was asked.
    assert_eq!(rig.bridge.safety.keys().len(), 1);
    assert_eq!(rig.count("objects"), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn put_succeeds_when_the_wake_up_is_lost() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.bridge.jobs.fail.set(true);
    let put = rig.put(&signer, BUCKET, "k", b"payload").await;
    put.expect(200);
    assert_eq!(put.header("etag"), Some(md5_etag(b"payload").as_str()));
    // The posting obligation is in the catalogue for the dispatcher.
    assert!(rig.live(&bucket, "k").await.is_some());
    assert_eq!(rig.count("outbox"), 1);
    assert!(rig.bridge.jobs.inner.sent().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn conditional_write_is_501_and_stores_nothing() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    for (name, value) in [
        ("if-match", "\"0123456789abcdef0123456789abcdef\""),
        ("if-none-match", "*"),
        ("if-modified-since", "Fri, 15 Jan 2027 08:00:00 GMT"),
        ("if-unmodified-since", "Fri, 15 Jan 2027 08:00:00 GMT"),
    ] {
        let req = signer.sign(
            rig.now(),
            Method::Put,
            &path(BUCKET, "k"),
            &[],
            &[(name, value)],
            b"payload".to_vec(),
        );
        let (resp, polled) = rig.send_watched(req).await;
        resp.expect_error(501, "NotImplemented");
        assert!(!polled, "{name}: the body was read");
        assert_nothing_stored(&rig);
    }

    // A conditional DELETE leaves the object in place.
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let resp = rig
        .call(
            &signer,
            Method::Delete,
            &path(BUCKET, "k"),
            &[],
            &[("if-match", md5_etag(b"payload").as_str())],
            b"",
        )
        .await;
    resp.expect_error(501, "NotImplemented");
    assert!(rig.live(&bucket, "k").await.is_some());
    rig.head(&signer, BUCKET, "k").await.expect(200);
}

#[tokio::test(flavor = "current_thread")]
async fn unauthenticated_body_never_read() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let good = || {
        signer.sign(
            rig.now(),
            Method::Put,
            &path(BUCKET, "k"),
            &[],
            &[],
            b"payload".to_vec(),
        )
    };

    // No credentials at all.
    let mut req = good();
    req.headers.retain(|(n, _)| n != "authorization");
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(403, "AccessDenied");
    assert!(!polled);

    // A signature made with another secret.
    let forged = Signer::new(AKID, &format!("{}-other", secret()));
    let req = forged.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(403, "SignatureDoesNotMatch");
    assert!(!polled);

    // A signed header changed after signing.
    let mut req = good();
    req.set_header("x-amz-date", "20270115T080001Z");
    let (resp, polled) = rig.send_watched(req).await;
    assert_eq!(resp.status, 403);
    assert!(!polled);

    // A request signed outside the allowed clock skew.
    let req = signer.sign(
        UnixMs(T0.0 - 3_600_000),
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(403, "RequestTimeTooSkewed");
    assert!(!polled);

    // A request for another host.
    let mut req = good();
    req.set_header("host", "other.test");
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(403, "AccessDenied");
    assert!(!polled);

    assert_nothing_stored(&rig);
}

#[tokio::test(flavor = "current_thread")]
async fn edge_added_headers_are_ignored() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let edge = [
        ("cf-connecting-ip", "203.0.113.7"),
        ("cf-ipcity", "S\u{e3}o Paulo"),
        ("cf-ray", "8f0000000000abcd-GRU"),
        ("x-forwarded-for", "203.0.113.7, 198.51.100.2"),
        ("x-forwarded-proto", "https"),
        ("x-real-ip", "203.0.113.7"),
        ("true-client-ip", "203.0.113.7"),
        ("cdn-loop", "edge; loops=1"),
    ];
    let with_edge = |mut req: Req| {
        for (name, value) in edge {
            req.headers.push((name.to_string(), value.to_string()));
        }
        req
    };
    let put = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    rig.send(with_edge(put)).await.expect(200);
    let head = signer.sign(
        rig.now(),
        Method::Head,
        &path(BUCKET, "k"),
        &[],
        &[],
        Vec::new(),
    );
    rig.send(with_edge(head)).await.expect(200);

    // They cannot stand in for a signature.
    let mut unsigned = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "k2"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    unsigned.headers.retain(|(n, _)| n != "authorization");
    let (resp, polled) = rig.send_watched(with_edge(unsigned)).await;
    resp.expect_error(403, "AccessDenied");
    assert!(!polled);
}

#[tokio::test(flavor = "current_thread")]
async fn denials_do_not_reveal_what_exists() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let other = rig.bucket("bkt-other", true).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);

    let unknown = Signer::new("AKIDUNKNOWN000000000", secret());
    let disabled = rig
        .key("AKIDDISABLED00000000", secret(), KeyStatus::Disabled)
        .await;
    rig.grant("AKIDDISABLED00000000", &other, Perm::Rw).await;
    let ungranted = rig
        .key("AKIDUNGRANTED0000000", secret(), KeyStatus::Active)
        .await;

    let mut denials = Vec::new();
    for (who, bucket) in [
        (&unknown, BUCKET),       // unknown key
        (&disabled, "bkt-other"), // disabled key that holds a grant
        (&ungranted, BUCKET),     // valid key, no grant on this bucket
        (&signer, "bkt-other"),   // valid key, granted elsewhere only
        (&signer, "bkt-absent"),  // valid key, bucket does not exist
    ] {
        for method in [Method::Get, Method::Head, Method::Put, Method::Delete] {
            let head = method == Method::Head;
            let resp = rig
                .call(who, method, &path(bucket, "k"), &[], &[], b"")
                .await;
            assert_eq!(resp.status, 403, "{} on {bucket}", who.akid);
            if !head {
                assert_eq!(resp.code(), "AccessDenied");
                denials.push(resp.body);
            }
        }
        let list = rig
            .call(
                who,
                Method::Get,
                &format!("/{bucket}"),
                &[("list-type", "2")],
                &[],
                b"",
            )
            .await;
        list.expect_error(403, "AccessDenied");
        denials.push(list.body);
    }
    denials.dedup();
    assert_eq!(denials.len(), 1, "every denial has the same body");
    assert_eq!(rig.count("objects"), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn read_only_grant_cannot_mutate() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let reader = rig
        .key("AKIDREADONLY00000000", secret(), KeyStatus::Active)
        .await;
    rig.grant("AKIDREADONLY00000000", &bucket, Perm::Ro).await;

    rig.head(&reader, BUCKET, "k").await.expect(200);
    let req = reader.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "k2"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(403, "AccessDenied");
    assert!(!polled);
    rig.call(&reader, Method::Delete, &path(BUCKET, "k"), &[], &[], b"")
        .await
        .expect_error(403, "AccessDenied");
    assert!(rig.live(&bucket, "k").await.is_some());
    assert_eq!(rig.count("objects"), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_declared_length_rejected_unread() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let sign = |body: &[u8]| {
        signer.sign(
            rig.now(),
            Method::Put,
            &path(BUCKET, "k"),
            &[],
            &[],
            body.to_vec(),
        )
    };

    // One byte over the extent limit, by declaration alone.
    let mut req = sign(b"x");
    req.set_header("content-length", &(16 * MIB + 1).to_string());
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(400, "EntityTooLarge");
    assert!(!polled);

    // No declared length.
    let mut req = sign(b"x");
    req.headers.retain(|(n, _)| n != "content-length");
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(411, "MissingContentLength");
    assert!(!polled);

    // A length that is not a number.
    let mut req = sign(b"x");
    req.set_header("content-length", "1e3");
    let (resp, polled) = rig.send_watched(req).await;
    assert_eq!(resp.status, 400);
    assert!(!polled);

    // A body longer than declared is cut off and refused.
    let mut req = sign(b"0123456789");
    req.set_header("content-length", "4");
    rig.send(req).await.expect_error(400, "EntityTooLarge");

    // A body shorter than declared.
    let mut req = sign(b"0123");
    req.set_header("content-length", "10");
    rig.send(req).await.expect_error(400, "IncompleteBody");

    assert_nothing_stored(&rig);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn full_budget_is_slow_down_and_reads_nothing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let _held = rig
        .bridge
        .budget
        .try_charge(rig.bridge.cfg.inflight_budget_bytes)
        .unwrap();
    let req = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(503, "SlowDown");
    assert!(resp.header("retry-after").is_some());
    assert!(!polled);
    assert_nothing_stored(&rig);
}

#[tokio::test(flavor = "current_thread")]
async fn digest_mismatch_stores_nothing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = b"payload";

    // Content-MD5 of other bytes.
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[("content-md5", &b64(&md5::compute(b"other").0))],
        body,
    )
    .await
    .expect_error(400, "BadDigest");

    // A body that is not the one whose hash was signed.
    let mut req = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[],
        body.to_vec(),
    );
    req.body = b"PAYLOAD".to_vec();
    let resp = rig.send(req).await;
    assert_eq!(resp.status, 400, "{}", resp.text());

    // A checksum header of other bytes.
    let resp = rig
        .call(
            &signer,
            Method::Put,
            &path(BUCKET, "k"),
            &[],
            &[("x-amz-checksum-sha256", &b64(&sha256(b"other")))],
            body,
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_nothing_stored(&rig);

    // The matching checksum is stored and reported back on request.
    let sum = b64(&sha256(body));
    let put = rig
        .call(
            &signer,
            Method::Put,
            &path(BUCKET, "k"),
            &[],
            &[
                ("content-md5", &b64(&md5::compute(body).0)),
                ("x-amz-checksum-sha256", &sum),
            ],
            body,
        )
        .await;
    put.expect(200);
    assert_eq!(put.header("x-amz-checksum-sha256"), Some(sum.as_str()));
    let head = rig
        .call(
            &signer,
            Method::Head,
            &path(BUCKET, "k"),
            &[],
            &[("x-amz-checksum-mode", "ENABLED")],
            b"",
        )
        .await;
    assert_eq!(
        head.expect(200).header("x-amz-checksum-sha256"),
        Some(sum.as_str())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn real_bucket_refused_before_h9() {
    // This test describes the closed gate; opening it must revisit it.
    const { assert!(!REAL_DATA_READY) }
    let rig = rig();
    let real = rig.bucket("bkt-real", false).await;
    let signer = rig.key(AKID, secret(), KeyStatus::Active).await;
    rig.grant(AKID, &real, Perm::Rw).await;

    let req = signer.sign(
        rig.now(),
        Method::Put,
        &path("bkt-real", "k"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    let (resp, polled) = rig.send_watched(req).await;
    resp.expect_error(403, "AccessDenied");
    assert!(!polled);
    rig.call(
        &signer,
        Method::Delete,
        &path("bkt-real", "k"),
        &[],
        &[],
        b"",
    )
    .await
    .expect_error(403, "AccessDenied");
    assert_nothing_stored(&rig);

    // Reads are not gated: there is simply nothing there.
    rig.head(&signer, "bkt-real", "k").await.expect(404);

    // A disposable bucket next to it takes the same write.
    let scratch = rig.bucket(BUCKET, true).await;
    rig.grant(AKID, &scratch, Perm::Rw).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
}

#[tokio::test(flavor = "current_thread")]
async fn restore_mode_refuses_mutations() {
    let mut cfg = config(Vec::new());
    cfg.maintenance = Maintenance::Restore;
    let frozen = rig_with(NoNntp, cfg);
    let (_, signer) = frozen.standard(BUCKET).await;
    let req = signer.sign(
        frozen.now(),
        Method::Put,
        &path(BUCKET, "k"),
        &[],
        &[],
        b"payload".to_vec(),
    );
    let (resp, polled) = frozen.send_watched(req).await;
    assert_eq!(resp.status, 503);
    assert!(!polled);
    let resp = frozen
        .call(&signer, Method::Delete, &path(BUCKET, "k"), &[], &[], b"")
        .await;
    assert_eq!(resp.status, 503);
    assert_nothing_stored(&frozen);
    frozen.head(&signer, BUCKET, "k").await.expect(404);
}

#[tokio::test(flavor = "current_thread")]
async fn copy_is_not_a_put() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "src", b"payload")
        .await
        .expect(200);
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "dst"),
        &[],
        &[("x-amz-copy-source", "/bkt-objects/src")],
        b"",
    )
    .await
    .expect_error(501, "NotImplemented");
    rig.head(&signer, BUCKET, "dst").await.expect(404);
}

#[tokio::test(flavor = "current_thread")]
async fn delete_is_always_204() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "k", b"payload").await.expect(200);
    let target = path(BUCKET, "k");
    let delete = || rig.call(&signer, Method::Delete, &target, &[], &[], b"");

    let first = delete().await;
    first.expect(204);
    assert!(first.body.is_empty());
    assert!(rig.live(&bucket, "k").await.is_none());
    rig.head(&signer, BUCKET, "k").await.expect(404);

    // Again, and for a key that never existed.
    delete().await.expect(204);
    rig.call(
        &signer,
        Method::Delete,
        &path(BUCKET, "never"),
        &[],
        &[],
        b"",
    )
    .await
    .expect(204);

    // The key can be written again.
    rig.put(&signer, BUCKET, "k", b"again").await.expect(200);
    let head = rig.head(&signer, BUCKET, "k").await;
    assert_eq!(head.expect(200).header("content-length"), Some("5"));
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_keys_are_stored_verbatim() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let keys = [
        "with space/and more.txt",
        "plus+sign+key",
        "percent%25literal%zz",
        "ünïcödé/日本語/🙂.bin",
        "double//slash///key",
        "/leading-slash",
        "trailing/",
        "dots/../up/./here",
        "query?looking&key=1#frag",
    ];
    for (i, key) in keys.iter().enumerate() {
        let body = format!("body {i}");
        rig.put(&signer, BUCKET, key, body.as_bytes())
            .await
            .expect(200);
        let (generation, _) = rig.live(&bucket, key).await.unwrap();
        assert_eq!(generation.key, *key);
        let head = rig.head(&signer, BUCKET, key).await;
        assert_eq!(
            head.expect(200).header("etag"),
            Some(md5_etag(body.as_bytes()).as_str()),
            "{key}"
        );
    }
    assert_eq!(rig.count("objects"), keys.len() as i64);

    // A raw `+` in the path is a plus, never a space.
    let head = rig
        .call(
            &signer,
            Method::Head,
            "/bkt-objects/plus+sign+key",
            &[],
            &[],
            b"",
        )
        .await;
    head.expect(200);
    rig.head(&signer, BUCKET, "plus sign key").await.expect(404);

    // Each key deletes by its own name only.
    for key in keys {
        rig.call(&signer, Method::Delete, &path(BUCKET, key), &[], &[], b"")
            .await
            .expect(204);
    }
    assert_eq!(rig.count("objects"), 0);
}
