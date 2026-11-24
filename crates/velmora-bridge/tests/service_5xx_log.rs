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
