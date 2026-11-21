//! Path-style S3 requests across the configured endpoint hosts.

mod service_support;

use service_support::*;
use velmora_bridge::config::{HostClass, S3Host};
use velmora_bridge::{Catalog, Method, Secret};

const BUCKET: &str = "bkt-hosts";
const TOKEN: &str = "admin-token-fixture-admin-token-fixture";
const CUSTOMER: &str = "s3.customer.test";

fn two_hosts() -> Rig {
    let mut cfg = config(Vec::new());
    cfg.admin_token = Secret::new(TOKEN.to_string());
    cfg.s3_hosts = vec![S3Host {
        name: CUSTOMER.into(),
        class: HostClass::Customer,
    }];
    rig_with(NoNntp, cfg)
}

async fn bearer_call(rig: &Rig, method: Method, target: &str, host: &str) -> Resp {
    rig.send(Req {
        method,
        target: target.to_string(),
        headers: vec![
            ("host".to_string(), host.to_string()),
            ("authorization".to_string(), format!("Bearer {TOKEN}")),
        ],
        body: Vec::new(),
    })
    .await
}

fn assert_host_refused(resp: &Resp, message: &str) {
    resp.expect(400);
    assert_eq!(resp.code(), "InvalidRequest");
    assert!(resp.message().contains(message), "{}", resp.text());
}

#[tokio::test(flavor = "current_thread")]
async fn both_hosts_can_write_and_read_the_same_objects() {
    let rig = two_hosts();
    let (_, signer) = rig.standard(BUCKET).await;
    for (write_host, key, payload) in [
        (CUSTOMER, "customer", b"written on customer".as_slice()),
        (HOST, "legacy", b"written on legacy".as_slice()),
    ] {
        let object = path(BUCKET, key);
        rig.call(
            &signer,
            Method::Put,
            &object,
            &[],
            &[("host", write_host)],
            payload,
        )
        .await
        .expect(200);
        for read_host in [CUSTOMER, HOST] {
            let resp = rig
                .call(
                    &signer,
                    Method::Get,
                    &object,
                    &[],
                    &[("host", read_host)],
                    b"",
                )
                .await;
            resp.expect(200);
            assert_eq!(
                resp.body, payload,
                "wrote via {write_host}, read via {read_host}"
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_signed_mixed_case_host_is_accepted() {
    let rig = two_hosts();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "mixed-case"),
        &[],
        &[("host", "S3.Customer.Test")],
        b"payload",
    )
    .await
    .expect(200);
}

#[tokio::test(flavor = "current_thread")]
async fn changing_the_host_after_signing_invalidates_the_signature() {
    let rig = two_hosts();
    let (_, signer) = rig.standard(BUCKET).await;
    let mut req = signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "changed-host"),
        &[],
        &[("host", HOST)],
        b"payload".to_vec(),
    );
    req.set_header("host", CUSTOMER);
    let resp = rig.send(req).await;
    resp.expect(403);
    assert_eq!(resp.code(), "SignatureDoesNotMatch");
}

#[tokio::test(flavor = "current_thread")]
async fn presigned_get_requires_the_host_it_was_signed_for() {
    let rig = two_hosts();
    let (_, signer) = rig.standard(BUCKET).await;
    let payload = b"presigned payload";
    rig.put(&signer, BUCKET, "presigned", payload)
        .await
        .expect(200);

    let req = presign(&signer, rig.now(), &path(BUCKET, "presigned"));
    let customer_req = Req {
        method: Method::Get,
        target: req.target.clone(),
        headers: vec![("host".to_string(), CUSTOMER.to_string())],
        body: Vec::new(),
    };
    rig.send(customer_req)
        .await
        .expect_error(403, "SignatureDoesNotMatch");

    let resp = rig.send(req).await;
    resp.expect(200);
    assert_eq!(resp.body, payload);

    // Signed for the customer host: good there, refused on the other.
    let req = presign_for(&signer, rig.now(), &path(BUCKET, "presigned"), CUSTOMER);
    let mut legacy_req = presign_for(&signer, rig.now(), &path(BUCKET, "presigned"), CUSTOMER);
    legacy_req.set_header("host", HOST);
    let resp = rig.send(req).await;
    resp.expect(200);
    assert_eq!(resp.body, payload);
    rig.send(legacy_req)
        .await
        .expect_error(403, "SignatureDoesNotMatch");
}

#[tokio::test(flavor = "current_thread")]
async fn admin_routes_are_hidden_on_the_customer_host() {
    let rig = two_hosts();
    let target = "/_admin/status";
    bearer_call(&rig, Method::Get, target, CUSTOMER)
        .await
        .expect_error(404, "NotFound");

    bearer_call(&rig, Method::Get, target, HOST)
        .await
        .expect(200);
}

#[tokio::test(flavor = "current_thread")]
async fn bearer_create_bucket_requires_a_legacy_host() {
    let rig = two_hosts();
    bearer_call(&rig, Method::Put, "/newbucket", CUSTOMER)
        .await
        .expect_error(403, "AccessDenied");
    assert!(rig
        .bridge
        .catalog
        .bucket_by_name("newbucket")
        .await
        .unwrap()
        .is_none());

    bearer_call(&rig, Method::Put, "/newbucket", HOST)
        .await
        .expect(200);
}

#[tokio::test(flavor = "current_thread")]
async fn bearer_delete_bucket_is_refused_on_the_customer_host() {
    let rig = two_hosts();
    rig.bucket(BUCKET, true).await;

    bearer_call(&rig, Method::Delete, "/bkt-hosts", CUSTOMER)
        .await
        .expect_error(403, "AccessDenied");
    assert!(rig
        .bridge
        .catalog
        .bucket_by_name(BUCKET)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_host_is_refused() {
    let rig = two_hosts();
    let (_, signer) = rig.standard(BUCKET).await;
    let resp = rig
        .call(
            &signer,
            Method::Get,
            &path(BUCKET, "key"),
            &[],
            &[("host", "unknown.test")],
            b"",
        )
        .await;
    assert_host_refused(&resp, "does not name this endpoint");
}

#[tokio::test(flavor = "current_thread")]
async fn virtual_hosted_style_is_refused_for_both_endpoints() {
    let rig = two_hosts();
    let (_, signer) = rig.standard(BUCKET).await;
    for host in ["bucket.s3.customer.test", "bucket.s3.test"] {
        let resp = rig
            .call(
                &signer,
                Method::Get,
                &path(BUCKET, "key"),
                &[],
                &[("host", host)],
                b"",
            )
            .await;
        assert_host_refused(&resp, "Virtual-hosted-style");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn multipart_completion_names_the_customer_host() {
    let rig = two_hosts();
    let (_, signer) = rig.standard(BUCKET).await;
    let object = path(BUCKET, "multipart");
    let host = [("host", CUSTOMER)];
    let created = rig
        .call(
            &signer,
            Method::Post,
            &object,
            &[("uploads", "")],
            &host,
            b"",
        )
        .await;
    created.expect(200);
    let id = created.values("UploadId").pop().unwrap();

    let part = rig
        .call(
            &signer,
            Method::Put,
            &object,
            &[("partNumber", "1"), ("uploadId", &id)],
            &host,
            b"payload",
        )
        .await;
    part.expect(200);
    let etag = part.header("etag").unwrap().replace('"', "&quot;");
    let xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let completed = rig
        .call(
            &signer,
            Method::Post,
            &object,
            &[("uploadId", &id)],
            &host,
            xml.as_bytes(),
        )
        .await;
    completed.expect(200);
    let location = completed.values("Location").pop().unwrap();
    assert!(
        location.starts_with("https://s3.customer.test/"),
        "{location}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn customer_host_is_refused_when_no_extras_are_configured() {
    let rig = rig_with(NoNntp, config(Vec::new()));
    let (_, signer) = rig.standard(BUCKET).await;
    let resp = rig
        .call(
            &signer,
            Method::Get,
            &path(BUCKET, "key"),
            &[],
            &[("host", CUSTOMER)],
            b"",
        )
        .await;
    assert_host_refused(&resp, "does not name this endpoint");
}
