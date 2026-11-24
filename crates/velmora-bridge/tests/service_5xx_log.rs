//! The request log line of a 5xx names what failed: the stage, the error
//! variant and the provider's class or code. Never the key, the query or
//! a message text.

mod service_support;

use std::rc::Rc;

use service_support::*;
use velmora_bridge::ingress::log_line_with;
use velmora_bridge::metrics::GetObservation;
use velmora_bridge::*;

const BUCKET: &str = "bkt-5xx-log";
const KEY: &str = "private-key-not-for-logs";

/// Sends `req` and returns the answer and the request's log line.
async fn logged(rig: &Rig, req: Req) -> (Resp, String) {
    let target = format!("/{BUCKET}/{KEY}?X-Amz-Signature=secret");
    let method = req_method(&req);
    let mut observed = GetObservation::default();
    let resp = Rc::clone(&rig.bridge)
        .handle_observed(req.into_request(), &mut observed)
        .await;
    let resp = Resp::collect(resp).await;
    let line = log_line_with(&method, &target, resp.status, "ray-1", Some(&observed));
    assert!(!line.contains(KEY) && !line.contains("secret"), "{line}");
    (resp, line)
}

fn req_method(req: &Req) -> String {
    format!("{:?}", req.method).to_uppercase()
}

/// The fields after the request part of a log line.
fn fields(line: &str) -> &str {
    line.split_once(" id=ray-1")
        .map(|(_, rest)| rest.trim_start())
        .unwrap_or_else(|| panic!("{line}"))
}

#[tokio::test(flavor = "current_thread")]
async fn a_put_that_fails_logs_its_stage_variant_and_code() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let put = || {
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

    // The key lookup. (The D1 adapter's classes, `d1_overloaded` and
    // the like, are named in `metrics`; this catalogue has none.)
    *sql.fail_matching.borrow_mut() = Some(("FROM access_keys", 0));
    let (resp, line) = logged(&rig, put()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=auth err=Sql code=sql_other");
    sql.fail_matching.borrow_mut().take();

    // The restore gate.
    *sql.fail_matching.borrow_mut() = Some(("FROM restore_state", 0));
    let (resp, line) = logged(&rig, put()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=lookup err=Sql code=sql_other");
    sql.fail_matching.borrow_mut().take();

    // The safety copy: the store failed, ...
    rig.bridge.safety.fail_put.set(true);
    let (resp, line) = logged(&rig, put()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=r2 err=Blob code=-");
    rig.bridge.safety.fail_put.set(false);

    // ... or holds other bytes than were sealed.
    rig.bridge.safety.false_receipt.set(Some(|mut r| {
        r.size += 1;
        r
    }));
    let (resp, line) = logged(&rig, put()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=r2 err=StoredSizeMismatch code=-");
    rig.bridge.safety.false_receipt.set(Some(|mut r| {
        r.md5[0] ^= 1;
        r
    }));
    let (resp, line) = logged(&rig, put()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=r2 err=StoredMd5Mismatch code=-");
    rig.bridge.safety.false_receipt.set(None);

    // The byte budget.
    let held = rig
        .bridge
        .budget
        .try_charge(rig.bridge.budget.capacity())
        .unwrap();
    let (resp, line) = logged(&rig, put()).await;
    resp.expect_error(503, "SlowDown");
    assert_eq!(fields(&line), "stage=budget err=SlowDown code=-");
    drop(held);

    // The live-object read of a conditional PUT.
    *sql.fail_matching.borrow_mut() = Some(("FROM objects o JOIN generations", 0));
    let conditional = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, KEY),
        &[],
        &[("if-none-match", "*")],
        b"payload".to_vec(),
    );
    let (resp, line) = logged(&rig, conditional).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=lookup err=Sql code=sql_other");
    sql.fail_matching.borrow_mut().take();

    // A PUT that went through logs no fields.
    let (resp, line) = logged(&rig, put()).await;
    resp.expect(200);
    assert!(line.ends_with("status=200 id=ray-1"), "{line}");

    // The batch that publishes.
    sql.fail_publish.set(Some(PublishFault::Down));
    let (resp, line) = logged(&rig, put()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=commit err=Sql code=sql_other");
}

#[tokio::test(flavor = "current_thread")]
async fn an_upload_part_that_fails_logs_its_stage_variant_and_code() {
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

    *sql.fail_matching.borrow_mut() = Some(("FROM access_keys", 0));
    let (resp, line) = logged(&rig, part()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=auth err=Sql code=sql_other");
    sql.fail_matching.borrow_mut().take();

    rig.bridge.safety.fail_put.set(true);
    let (resp, line) = logged(&rig, part()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=r2 err=Blob code=-");
    rig.bridge.safety.fail_put.set(false);

    // The batch that records the part.
    sql.fail_batches.set(1);
    let (resp, line) = logged(&rig, part()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=commit err=Sql code=sql_other");
}

#[tokio::test(flavor = "current_thread")]
async fn a_get_that_fails_logs_its_stage_variant_and_code() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, KEY, b"payload").await.expect(200);
    let get = || signer.sign(rig.now(), Method::Get, &path(BUCKET, KEY), &[], &[], vec![]);
    let sql = &rig.bridge.catalog.sql;

    *sql.fail_matching.borrow_mut() = Some(("FROM objects o JOIN generations", 0));
    let (resp, line) = logged(&rig, get()).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=lookup err=Sql code=sql_other");
    sql.fail_matching.borrow_mut().take();

    let (resp, line) = logged(&rig, get()).await;
    resp.expect(200);
    assert!(line.ends_with("status=200 id=ray-1"), "{line}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_sliced_put_logs_the_fault_of_its_failed_slice() {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = 4 * 1024;
    cfg.slice_bytes = 2 * 1024;
    let rig = rig_with(NoNntp, cfg);
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bridge.safety.fail_put.set(true);
    let req = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, KEY),
        &[],
        &[],
        vec![7; 5 * 1024],
    );
    let (resp, line) = logged(&rig, req).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=r2 err=Blob code=-");
}

#[tokio::test(flavor = "current_thread")]
async fn a_copy_whose_source_lookup_fails_logs_the_catalogue_error() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "source", b"payload")
        .await
        .expect(200);
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() =
        Some(("FROM objects o JOIN generations", 0));
    let req = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, KEY),
        &[],
        &[("x-amz-copy-source", &format!("/{BUCKET}/source"))],
        vec![],
    );
    let (resp, line) = logged(&rig, req).await;
    rig.bridge.catalog.sql.fail_matching.borrow_mut().take();
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=lookup err=Sql code=sql_other");
}

#[tokio::test(flavor = "current_thread")]
async fn a_head_bucket_and_an_unsupported_route_log_their_reason() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = Some(("FROM access_keys", 0));
    let head = signer.sign(
        rig.now(),
        Method::Head,
        &format!("/{BUCKET}"),
        &[],
        &[],
        vec![],
    );
    let (resp, line) = logged(&rig, head).await;
    rig.bridge.catalog.sql.fail_matching.borrow_mut().take();
    resp.expect(500);
    assert_eq!(fields(&line), "stage=auth err=Sql code=sql_other");

    let versions = signer.sign(
        rig.now(),
        Method::Get,
        &format!("/{BUCKET}"),
        &[("versions", "")],
        &[],
        vec![],
    );
    let (resp, line) = logged(&rig, versions).await;
    resp.expect(501);
    assert_eq!(fields(&line), "stage=other err=UnsupportedRoute code=-");
}

/// An upload of one part, ready to complete: the Complete request.
async fn ready_upload(rig: &Rig, signer: &Signer, key: &str) -> Req {
    let target = path(BUCKET, key);
    let created = rig
        .call(signer, Method::Post, &target, &[("uploads", "")], &[], b"")
        .await;
    created.expect(200);
    let id = created.values("UploadId").remove(0);
    let uploaded = rig
        .call(
            signer,
            Method::Put,
            &target,
            &[("partNumber", "1"), ("uploadId", &id)],
            &[],
            b"payload",
        )
        .await;
    uploaded.expect(200);
    let etag = uploaded.header("etag").unwrap().to_owned();
    let xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
    );
    signer.sign(
        rig.now(),
        Method::Post,
        &target,
        &[("uploadId", &id)],
        &[],
        xml.into_bytes(),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn fenced_exhausted_and_restore_refusals_log_why() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let sql = &rig.bridge.catalog.sql;

    // The batch failed and the fence showed that nothing was published.
    let complete = ready_upload(&rig, &signer, KEY).await;
    sql.fail_publish.set(Some(PublishFault::NotApplied));
    let (resp, line) = logged(&rig, complete).await;
    resp.expect_error(500, "InternalError");
    assert_eq!(fields(&line), "stage=commit err=Fenced code=-");

    // The same, with the catalogue overloaded.
    let complete = ready_upload(&rig, &signer, KEY).await;
    sql.fail_publish.set(Some(PublishFault::PgOverloaded));
    let (resp, line) = logged(&rig, complete).await;
    resp.expect_error(503, "SlowDown");
    assert_eq!(fields(&line), "stage=commit err=FencedOverloaded code=-");

    // A PUT whose every attempt is refused by its guard. (Complete runs
    // out of attempts only when the key outruns each attempt's id; a
    // guard that refuses with nothing changed is `InvalidPart` there.)
    sql.refuse_publishes.set(u32::MAX);
    let put = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, KEY),
        &[],
        &[],
        b"x".to_vec(),
    );
    let (resp, line) = logged(&rig, put).await;
    sql.refuse_publishes.set(0);
    resp.expect_error(503, "SlowDown");
    assert_eq!(fields(&line), "stage=commit err=AttemptsExhausted code=-");

    // A replay under way refuses a PUT before its body is read.
    sql.apply(
        "INSERT INTO restore_state (id, state, since_ms, started_at) \
         VALUES (1, 'replaying', 0, 1);",
    )
    .unwrap();
    let put = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, KEY),
        &[],
        &[],
        b"x".to_vec(),
    );
    let (resp, line) = logged(&rig, put).await;
    resp.expect(503);
    assert_eq!(fields(&line), "stage=other err=RestorePending code=-");
}

#[tokio::test(flavor = "current_thread")]
async fn a_copy_that_is_switched_off_logs_copy_disabled() {
    let mut cfg = config(Vec::new());
    cfg.server_side_copy = false;
    let rig = rig_with(NoNntp, cfg);
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "source", b"payload")
        .await
        .expect(200);
    let req = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, KEY),
        &[],
        &[("x-amz-copy-source", &format!("/{BUCKET}/source"))],
        vec![],
    );
    let (resp, line) = logged(&rig, req).await;
    resp.expect_error(501, "NotImplemented");
    assert_eq!(fields(&line), "stage=other err=CopyDisabled code=-");
}
