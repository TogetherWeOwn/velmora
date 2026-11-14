//! Client compatibility: the SDK `x-id` query hint and a signed
//! `Accept-Encoding` that the edge rewrote, through `Bridge::handle`.

mod service_support;

use service_support::*;
use velmora_bridge::ingress::restore_accept_encoding;
use velmora_bridge::*;

const BUCKET: &str = "bkt-compat";

fn code(resp: &Resp) -> String {
    let text = resp.text();
    text.split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(c, _)| c.to_owned())
        .unwrap_or_default()
}

fn xml_field(text: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    text.split_once(&open)
        .and_then(|(_, rest)| rest.split_once(&close))
        .map(|(v, _)| v.to_owned())
        .unwrap_or_else(|| panic!("no <{tag}> in {text}"))
}

// ---------------------------------------------------------------------------
// x-id
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn x_id_is_accepted_on_every_object_operation() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let p = path(BUCKET, "dir/obj.bin");
    let body = pattern(7, 4096);

    let put = rig
        .call(
            &signer,
            Method::Put,
            &p,
            &[("x-id", "PutObject")],
            &[],
            &body,
        )
        .await;
    assert_eq!(put.status, 200, "PutObject: {}", put.text());

    let head = rig
        .call(
            &signer,
            Method::Head,
            &p,
            &[("x-id", "HeadObject")],
            &[],
            b"",
        )
        .await;
    assert_eq!(head.status, 200);

    let get = rig
        .call(&signer, Method::Get, &p, &[("x-id", "GetObject")], &[], b"")
        .await;
    assert_eq!(get.status, 200, "GetObject: {}", get.text());
    assert_eq!(get.body, body);

    let ranged = rig
        .call(
            &signer,
            Method::Get,
            &p,
            &[("x-id", "GetObject")],
            &[("range", "bytes=10-19")],
            b"",
        )
        .await;
    assert_eq!(ranged.status, 206);
    assert_eq!(ranged.body, body[10..20]);

    let list = rig
        .call(
            &signer,
            Method::Get,
            &format!("/{BUCKET}"),
            &[("list-type", "2"), ("x-id", "ListObjectsV2")],
            &[],
            b"",
        )
        .await;
    assert_eq!(list.status, 200, "ListObjectsV2: {}", list.text());
    assert!(list.text().contains("<Key>dir/obj.bin</Key>"));

    let del = rig
        .call(
            &signer,
            Method::Delete,
            &p,
            &[("x-id", "DeleteObject")],
            &[],
            b"",
        )
        .await;
    assert_eq!(del.status, 204, "DeleteObject: {}", del.text());
    assert_eq!(rig.head(&signer, BUCKET, "dir/obj.bin").await.status, 404);
}

#[tokio::test(flavor = "current_thread")]
async fn x_id_is_accepted_on_every_multipart_operation() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let p = path(BUCKET, "mp.bin");
    let body = pattern(3, 1024);

    let create = rig
        .call(
            &signer,
            Method::Post,
            &p,
            &[("uploads", ""), ("x-id", "CreateMultipartUpload")],
            &[],
            b"",
        )
        .await;
    assert_eq!(create.status, 200, "Create: {}", create.text());
    let upload_id = xml_field(&create.text(), "UploadId");

    let part = rig
        .call(
            &signer,
            Method::Put,
            &p,
            &[
                ("partNumber", "1"),
                ("uploadId", &upload_id),
                ("x-id", "UploadPart"),
            ],
            &[],
            &body,
        )
        .await;
    assert_eq!(part.status, 200, "UploadPart: {}", part.text());
    let etag = part.header("etag").expect("part etag").to_owned();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
    );
    let complete = rig
        .call(
            &signer,
            Method::Post,
            &p,
            &[
                ("uploadId", &upload_id),
                ("x-id", "CompleteMultipartUpload"),
            ],
            &[],
            complete_xml.as_bytes(),
        )
        .await;
    assert_eq!(complete.status, 200, "Complete: {}", complete.text());
    assert!(!complete.text().contains("<Error>"), "{}", complete.text());

    let get = rig
        .call(&signer, Method::Get, &p, &[("x-id", "GetObject")], &[], b"")
        .await;
    assert_eq!(get.status, 200);
    assert_eq!(get.body, body);

    // A second upload, aborted.
    let create = rig
        .call(
            &signer,
            Method::Post,
            &path(BUCKET, "aborted.bin"),
            &[("uploads", ""), ("x-id", "CreateMultipartUpload")],
            &[],
            b"",
        )
        .await;
    let upload_id = xml_field(&create.text(), "UploadId");
    let abort = rig
        .call(
            &signer,
            Method::Delete,
            &path(BUCKET, "aborted.bin"),
            &[("uploadId", &upload_id), ("x-id", "AbortMultipartUpload")],
            &[],
            b"",
        )
        .await;
    assert_eq!(abort.status, 204, "Abort: {}", abort.text());
}

/// `x-id` is part of the canonical query: adding, removing or changing it
/// after signing breaks the signature.
#[tokio::test(flavor = "current_thread")]
async fn x_id_is_covered_by_the_signature() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    assert_eq!(rig.put(&signer, BUCKET, "k", b"hello").await.status, 200);
    let p = path(BUCKET, "k");

    let mut added = signer.sign(rig.now(), Method::Get, &p, &[], &[], vec![]);
    added.target = format!("{p}?x-id=GetObject");
    let resp = rig.send(added).await;
    assert_eq!(
        (resp.status, code(&resp).as_str()),
        (403, "SignatureDoesNotMatch")
    );

    let mut changed = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[("x-id", "GetObject")],
        &[],
        vec![],
    );
    changed.target = format!("{p}?x-id=HeadObject");
    let resp = rig.send(changed).await;
    assert_eq!(
        (resp.status, code(&resp).as_str()),
        (403, "SignatureDoesNotMatch")
    );

    let mut removed = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[("x-id", "GetObject")],
        &[],
        vec![],
    );
    removed.target = p.clone();
    let resp = rig.send(removed).await;
    assert_eq!(
        (resp.status, code(&resp).as_str()),
        (403, "SignatureDoesNotMatch")
    );
}

/// The value is a hint only: the method and sub-resources route, as at S3.
#[tokio::test(flavor = "current_thread")]
async fn x_id_never_changes_routing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let p = path(BUCKET, "k");
    assert_eq!(rig.put(&signer, BUCKET, "k", b"hello").await.status, 200);

    // A GET naming another operation is still a GetObject.
    let get = rig
        .call(
            &signer,
            Method::Get,
            &p,
            &[("x-id", "DeleteObject")],
            &[],
            b"",
        )
        .await;
    assert_eq!(get.status, 200);
    assert_eq!(get.body, b"hello");
    assert_eq!(rig.head(&signer, BUCKET, "k").await.status, 200);

    // An unsupported sub-resource stays NotImplemented whatever x-id says.
    let acl = rig
        .call(
            &signer,
            Method::Get,
            &p,
            &[("acl", ""), ("x-id", "GetObject")],
            &[],
            b"",
        )
        .await;
    assert_eq!(acl.status, 501);

    // A repeated x-id is ambiguous and refused.
    let mut twice = signer.sign(rig.now(), Method::Get, &p, &[], &[], vec![]);
    twice.target = format!("{p}?x-id=GetObject&x-id=GetObject");
    let resp = rig.send(twice).await;
    assert_eq!(resp.status, 400);
}

// ---------------------------------------------------------------------------
// Accept-Encoding
// ---------------------------------------------------------------------------

/// What the Worker sees from the edge: the client's header replaced by the
/// edge's own value.
fn edge_rewrite(req: &mut Req) {
    req.set_header("accept-encoding", "gzip, br");
}

fn restored(mut req: Req, client: Option<&str>) -> Req {
    restore_accept_encoding(&mut req.headers, client);
    req
}

#[test]
fn restore_replaces_only_accept_encoding_and_only_with_a_value() {
    let base = vec![
        ("host".to_owned(), "s3.test".to_owned()),
        ("Accept-Encoding".to_owned(), "gzip, br".to_owned()),
        ("accept-encoding".to_owned(), "br".to_owned()),
        ("x-amz-date".to_owned(), "20260101T000000Z".to_owned()),
    ];

    let mut h = base.clone();
    restore_accept_encoding(&mut h, Some("gzip"));
    assert_eq!(
        h,
        vec![
            ("host".to_owned(), "s3.test".to_owned()),
            ("x-amz-date".to_owned(), "20260101T000000Z".to_owned()),
            ("accept-encoding".to_owned(), "gzip".to_owned()),
        ]
    );

    for client in [None, Some("")] {
        let mut h = base.clone();
        restore_accept_encoding(&mut h, client);
        assert_eq!(h, base, "{client:?} must leave the headers as received");
    }

    // Never adds a header the request did not carry, beyond the one value.
    let mut h = vec![("host".to_owned(), "s3.test".to_owned())];
    restore_accept_encoding(&mut h, Some("identity"));
    assert_eq!(h.len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn signed_accept_encoding_verifies_against_the_client_value() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    assert_eq!(rig.put(&signer, BUCKET, "k", b"hello").await.status, 200);
    let p = path(BUCKET, "k");

    // rclone's default: Accept-Encoding: gzip, signed.
    let mut req = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[],
        &[("accept-encoding", "gzip")],
        vec![],
    );
    edge_rewrite(&mut req);
    let resp = rig.send(restored(req, Some("gzip"))).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.body, b"hello");

    // Without the restore the edge value cannot verify (the regression).
    let mut req = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[],
        &[("accept-encoding", "gzip")],
        vec![],
    );
    edge_rewrite(&mut req);
    let resp = rig.send(restored(req, None)).await;
    assert_ne!(resp.status, 200);
}

#[tokio::test(flavor = "current_thread")]
async fn accept_encoding_tolerance_never_admits_a_bad_or_missing_signature() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    assert_eq!(rig.put(&signer, BUCKET, "k", b"hello").await.status, 200);
    let p = path(BUCKET, "k");

    // The client signed one value and the edge reports another.
    let mut req = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[],
        &[("accept-encoding", "gzip")],
        vec![],
    );
    edge_rewrite(&mut req);
    let resp = rig.send(restored(req, Some("identity"))).await;
    assert_eq!(
        (resp.status, code(&resp).as_str()),
        (403, "SignatureDoesNotMatch")
    );

    // No Authorization at all: still refused.
    let mut req = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[],
        &[("accept-encoding", "gzip")],
        vec![],
    );
    req.headers.retain(|(n, _)| n != "authorization");
    edge_rewrite(&mut req);
    let resp = rig.send(restored(req, Some("gzip"))).await;
    assert_eq!(resp.status, 403);
    assert_eq!(code(&resp), "AccessDenied");

    // A wrong signature with the restored value: refused.
    let mut req = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[],
        &[("accept-encoding", "gzip")],
        vec![],
    );
    let auth = req
        .headers
        .iter_mut()
        .find(|(n, _)| n == "authorization")
        .unwrap();
    let last = auth.1.pop().unwrap();
    auth.1.push(if last == '0' { '1' } else { '0' });
    edge_rewrite(&mut req);
    let resp = rig.send(restored(req, Some("gzip"))).await;
    assert_eq!(
        (resp.status, code(&resp).as_str()),
        (403, "SignatureDoesNotMatch")
    );

    // Another header changed after signing still fails: only
    // Accept-Encoding is restored.
    let mut req = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[],
        &[("accept-encoding", "gzip"), ("range", "bytes=0-1")],
        vec![],
    );
    req.set_header("range", "bytes=0-4");
    edge_rewrite(&mut req);
    let resp = rig.send(restored(req, Some("gzip"))).await;
    assert_eq!(
        (resp.status, code(&resp).as_str()),
        (403, "SignatureDoesNotMatch")
    );

    // A multi-coding value is still refused as possibly merged.
    let mut req = signer.sign(
        rig.now(),
        Method::Get,
        &p,
        &[],
        &[("accept-encoding", "gzip, br")],
        vec![],
    );
    edge_rewrite(&mut req);
    let resp = rig.send(restored(req, Some("gzip, br"))).await;
    assert_eq!((resp.status, code(&resp).as_str()), (400, "InvalidRequest"));
}

/// Unsigned Accept-Encoding (aws-cli, boto3, restic) is unaffected.
#[tokio::test(flavor = "current_thread")]
async fn unsigned_accept_encoding_is_unaffected() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    assert_eq!(rig.put(&signer, BUCKET, "k", b"hello").await.status, 200);
    for client in [None, Some(""), Some("identity"), Some("gzip")] {
        let mut req = signer.sign(rig.now(), Method::Get, &path(BUCKET, "k"), &[], &[], vec![]);
        edge_rewrite(&mut req);
        let resp = rig.send(restored(req, client)).await;
        assert_eq!(resp.status, 200, "{client:?}");
    }
}
