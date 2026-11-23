//! Request metrics for Worker-answered HEAD and upload errors.

mod service_support;

use std::rc::Rc;

use service_support::*;
use velmora_bridge::metrics::{request_point, GetObservation, Request};
use velmora_bridge::*;

const BUCKET: &str = "bkt-write-metrics";
const KEY: &str = "key-not-for-metrics";

async fn observed(rig: &Rig, req: Req, method: &str, status: u16, tail: &[&str]) -> Resp {
    let mut get = GetObservation::default();
    let response = Rc::clone(&rig.bridge)
        .handle_observed(req.into_request(), &mut get)
        .await;
    let response = Resp::collect(response).await;
    response.expect(status);
    let point = request_point(
        &Request {
            method,
            admin: false,
            sub: false,
            status: response.status,
            latency_ms: 0,
            bytes_in: 0,
            bytes_out: 0,
            colo: "iad",
            get,
        },
        1,
    );
    // Assert the entire serialized blob allowlist, not just the stage. The
    // signed URL, bucket, key, upload ID, and injected SQL text are not blobs.
    let class = match status {
        200 => "2xx",
        404 => "4xx",
        _ => "5xx",
    };
    let mut expected = vec!["req", method, class, "s3", "IAD"];
    expected.extend_from_slice(tail);
    assert_eq!(point.analytics_blobs().collect::<Vec<_>>(), expected);
    response
}

#[tokio::test(flavor = "current_thread")]
async fn put_failures_report_auth_lookup_r2_budget_and_commit() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let request = || {
        signer.sign(
            rig.now(),
            Method::Put,
            &path(BUCKET, KEY),
            &[],
            &[],
            b"payload".to_vec(),
        )
    };
    let sql = &rig.bridge.catalog.sql;
    *sql.fail_matching.borrow_mut() = Some(("FROM access_keys WHERE access_key_id", 0));
    observed(&rig, request(), "PUT", 500, &["auth", "unknown"])
        .await
        .expect_error(500, "InternalError");
    *sql.fail_matching.borrow_mut() = Some(("FROM restore_state", 0));
    observed(&rig, request(), "PUT", 500, &["lookup", "unknown"])
        .await
        .expect_error(500, "InternalError");
    sql.fail_matching.borrow_mut().take();

    rig.bridge.safety.fail_put.set(true);
    observed(&rig, request(), "PUT", 500, &["r2", "le_1gib"])
        .await
        .expect_error(500, "InternalError");
    rig.bridge.safety.fail_put.set(false);

    let held = rig
        .bridge
        .budget
        .try_charge(rig.bridge.budget.capacity())
        .unwrap();
    observed(&rig, request(), "PUT", 503, &["budget", "le_1gib"])
        .await
        .expect_error(503, "SlowDown");
    drop(held);

    rig.bridge.jobs.fail.set(true);
    assert!(observed(&rig, request(), "PUT", 200, &[])
        .await
        .body
        .is_empty());
    assert_eq!(rig.count("outbox WHERE sent_at IS NULL"), 1);
    rig.bridge.jobs.fail.set(false);

    sql.fail_publish.set(Some(PublishFault::Down));
    observed(&rig, request(), "PUT", 500, &["commit", "le_1gib"])
        .await
        .expect_error(500, "InternalError");
}

#[tokio::test(flavor = "current_thread")]
async fn head_failures_stay_bodyless_and_report_stage_and_size() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, KEY, b"payload").await.expect(200);
    let request = || {
        signer.sign(
            rig.now(),
            Method::Head,
            &path(BUCKET, KEY),
            &[],
            &[],
            vec![],
        )
    };
    let sql = &rig.bridge.catalog.sql;
    *sql.fail_matching.borrow_mut() = Some(("FROM access_keys WHERE access_key_id", 0));
    assert!(observed(&rig, request(), "HEAD", 500, &["auth", "unknown"])
        .await
        .body
        .is_empty());
    *sql.fail_matching.borrow_mut() = Some(("FROM objects o JOIN generations g", 0));
    assert!(
        observed(&rig, request(), "HEAD", 500, &["lookup", "unknown"])
            .await
            .body
            .is_empty()
    );
    sql.fail_matching.borrow_mut().take();
    sql.with_conn(|conn| {
        conn.execute(
            "UPDATE generations SET size = ?1, content_json = 'null'",
            [1_i64 << 31],
        )
    })
    .unwrap();
    let failed = observed(&rig, request(), "HEAD", 500, &["other", "gt_1gib"]).await;
    assert!(failed.body.is_empty());
    assert!(failed.header("content-type").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn multipart_failures_are_redacted_and_successes_are_unchanged() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let target = path(BUCKET, KEY);
    let created = rig
        .call(&signer, Method::Post, &target, &[("uploads", "")], &[], b"")
        .await;
    created.expect(200);
    let id = created.values("UploadId").remove(0);
    let part = || {
        signer.sign(
            rig.now(),
            Method::Put,
            &target,
            &[("partNumber", "1"), ("uploadId", &id)],
            &[],
            b"payload".to_vec(),
        )
    };
    let sql = &rig.bridge.catalog.sql;
    *sql.fail_matching.borrow_mut() = Some(("FROM uploads", 0));
    observed(&rig, part(), "PUT", 500, &["lookup", "unknown"])
        .await
        .expect_error(500, "InternalError");
    sql.fail_matching.borrow_mut().take();
    rig.bridge.safety.fail_put.set(true);
    observed(&rig, part(), "PUT", 500, &["r2", "unknown"])
        .await
        .expect_error(500, "InternalError");
    rig.bridge.safety.fail_put.set(false);
    sql.fail_batches.set(1);
    observed(&rig, part(), "PUT", 500, &["commit", "unknown"])
        .await
        .expect_error(500, "InternalError");
    let uploaded = observed(&rig, part(), "PUT", 200, &[]).await;
    let etag = uploaded.header("etag").unwrap();
    let xml = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
    let complete = || {
        signer.sign(
            rig.now(),
            Method::Post,
            &target,
            &[("uploadId", &id)],
            &[],
            xml.as_bytes().to_vec(),
        )
    };
    *sql.fail_matching.borrow_mut() = Some(("FROM uploads", 0));
    observed(&rig, complete(), "POST", 500, &["lookup", "unknown"])
        .await
        .expect_error(500, "InternalError");
    sql.fail_matching.borrow_mut().take();
    rig.bridge.safety.fail_put.set(true);
    observed(&rig, complete(), "POST", 500, &["r2", "le_1gib"])
        .await
        .expect_error(500, "InternalError");
    rig.bridge.safety.fail_put.set(false);
    sql.fail_publish.set(Some(PublishFault::Down));
    observed(&rig, complete(), "POST", 500, &["commit", "le_1gib"])
        .await
        .expect_error(500, "InternalError");

    rig.bridge.jobs.fail.set(true);
    let completed = observed(&rig, complete(), "POST", 200, &[]).await;
    assert!(!completed.values("ETag").is_empty());
    assert_eq!(rig.count("outbox WHERE sent_at IS NULL"), 1);
}
