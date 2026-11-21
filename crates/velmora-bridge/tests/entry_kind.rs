//! Each entry point admits one kind of credential:
//! an app password works through the WebDAV entry point only, an S3 key
//! through the S3 entry point only. A key of the wrong kind is answered
//! as an unknown key, on the plain path and on the multipart path.

mod service_support;

use service_support::*;
use velmora_bridge::entry::{ENTRY_HEADER, WEBDAV};
use velmora_bridge::*;

const APP: &str = "APVLTESTAPPPASSWORD1";
const S3K: &str = "AKVLTESTS3KEY0000001";

/// A rig with one bucket, an S3 key and an app password, both `rw` on it.
async fn two_kinds() -> (Rig, Signer, Signer) {
    let rig = rig();
    let b = rig.bucket("dav", true).await;
    let s3 = rig.key(S3K, secret(), KeyStatus::Active).await;
    rig.grant(S3K, &b, Perm::Rw).await;
    let app = rig
        .key(APP, "app-password-secret-0123456789", KeyStatus::Active)
        .await;
    rig.grant(APP, &b, Perm::Rw).await;
    (rig, s3, app)
}

/// Signs a request and adds unsigned headers to it, as the WebDAV
/// entrypoint (the marker) or the edge (`cf-*`) would.
async fn send(
    rig: &Rig,
    signer: &Signer,
    method: Method,
    target: &str,
    query: &[(&str, &str)],
    body: &[u8],
    unsigned: &[(&str, &str)],
) -> Resp {
    let mut req = signer.sign(rig.now(), method, target, query, &[], body.to_vec());
    for (name, value) in unsigned {
        req.headers.push((name.to_string(), value.to_string()));
    }
    rig.send(req).await
}

fn code(resp: &Resp) -> String {
    let body = String::from_utf8_lossy(&resp.body);
    body.split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| code.to_string())
        .unwrap_or_default()
}

const MARK: (&str, &str) = (ENTRY_HEADER, WEBDAV);

#[tokio::test]
async fn s3_entry_admits_s3_keys_only() {
    let (rig, s3, app) = two_kinds().await;
    let put = send(&rig, &s3, Method::Put, "/dav/a", &[], b"one", &[]).await;
    assert_eq!(put.status, 200);
    let got = send(&rig, &app, Method::Get, "/dav/a", &[], b"", &[]).await;
    assert_eq!(
        (got.status, code(&got).as_str()),
        (403, "InvalidAccessKeyId")
    );
    let put = send(&rig, &app, Method::Put, "/dav/b", &[], b"two", &[]).await;
    assert_eq!(
        (put.status, code(&put).as_str()),
        (403, "InvalidAccessKeyId")
    );
    let list = send(&rig, &app, Method::Get, "/", &[], b"", &[]).await;
    assert_eq!(
        (list.status, code(&list).as_str()),
        (403, "InvalidAccessKeyId")
    );
}

#[tokio::test]
async fn webdav_entry_admits_app_passwords_only() {
    let (rig, s3, app) = two_kinds().await;
    let put = send(&rig, &app, Method::Put, "/dav/a", &[], b"one", &[MARK]).await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    let got = send(&rig, &app, Method::Get, "/dav/a", &[], b"", &[MARK]).await;
    assert_eq!((got.status, got.body.as_slice()), (200, &b"one"[..]));
    let list = send(&rig, &app, Method::Get, "/", &[], b"", &[MARK]).await;
    assert_eq!(list.status, 200);

    let got = send(&rig, &s3, Method::Get, "/dav/a", &[], b"", &[MARK]).await;
    assert_eq!(
        (got.status, code(&got).as_str()),
        (403, "InvalidAccessKeyId")
    );
    let del = send(&rig, &s3, Method::Delete, "/dav/a", &[], b"", &[MARK]).await;
    assert_eq!(
        (del.status, code(&del).as_str()),
        (403, "InvalidAccessKeyId")
    );
}

#[tokio::test]
async fn a_marker_from_the_edge_counts_for_nothing() {
    let (rig, s3, app) = two_kinds().await;
    for edge in [
        ("cf-connecting-ip", "192.0.2.1"),
        ("x-forwarded-for", "192.0.2.1"),
    ] {
        // An app password with a forged marker is still on the S3 entry.
        let got = send(&rig, &app, Method::Put, "/dav/a", &[], b"x", &[MARK, edge]).await;
        assert_eq!(
            (got.status, code(&got).as_str()),
            (403, "InvalidAccessKeyId")
        );
        // And an S3 key keeps working on it: the marker is ignored.
        let got = send(&rig, &s3, Method::Put, "/dav/a", &[], b"x", &[MARK, edge]).await;
        assert_eq!(got.status, 200);
    }
    // Two markers, or one with another value, is no marker.
    let two = send(&rig, &app, Method::Get, "/dav/a", &[], b"", &[MARK, MARK]).await;
    assert_eq!(
        (two.status, code(&two).as_str()),
        (403, "InvalidAccessKeyId")
    );
    let other = send(
        &rig,
        &app,
        Method::Get,
        "/dav/a",
        &[],
        b"",
        &[(ENTRY_HEADER, "s3")],
    )
    .await;
    assert_eq!(
        (other.status, code(&other).as_str()),
        (403, "InvalidAccessKeyId")
    );
}

#[tokio::test]
async fn multipart_holds_the_same_binding() {
    let (rig, s3, app) = two_kinds().await;
    // Through the WebDAV entry point an app password uploads in parts.
    let created = send(
        &rig,
        &app,
        Method::Post,
        "/dav/big",
        &[("uploads", "")],
        b"",
        &[MARK],
    )
    .await;
    assert_eq!(
        created.status,
        200,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    let body = String::from_utf8_lossy(&created.body).to_string();
    let upload_id = body
        .split_once("<UploadId>")
        .and_then(|(_, r)| r.split_once("</UploadId>"))
        .map(|(id, _)| id.to_string())
        .unwrap();
    let q = [("partNumber", "1"), ("uploadId", upload_id.as_str())];
    let part = send(&rig, &app, Method::Put, "/dav/big", &q, b"part", &[]).await;
    assert_eq!(
        (part.status, code(&part).as_str()),
        (403, "InvalidAccessKeyId")
    );
    let part = send(&rig, &s3, Method::Put, "/dav/big", &q, b"part", &[MARK]).await;
    assert_eq!(
        (part.status, code(&part).as_str()),
        (403, "InvalidAccessKeyId")
    );
    let part = send(&rig, &app, Method::Put, "/dav/big", &q, b"part", &[MARK]).await;
    assert_eq!(part.status, 200, "{}", String::from_utf8_lossy(&part.body));

    // The S3 entry point refuses the app password on create too.
    let created = send(
        &rig,
        &app,
        Method::Post,
        "/dav/big2",
        &[("uploads", "")],
        b"",
        &[],
    )
    .await;
    assert_eq!(
        (created.status, code(&created).as_str()),
        (403, "InvalidAccessKeyId")
    );
    let created = send(
        &rig,
        &s3,
        Method::Post,
        "/dav/big2",
        &[("uploads", "")],
        b"",
        &[MARK],
    )
    .await;
    assert_eq!(
        (created.status, code(&created).as_str()),
        (403, "InvalidAccessKeyId")
    );
}
