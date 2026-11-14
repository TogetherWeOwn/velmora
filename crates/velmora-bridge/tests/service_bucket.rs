//! HeadBucket, GetBucketLocation and a SigV4-signed CreateBucket through
//! `Bridge::handle`.

mod service_support;

use service_support::*;
use velmora_bridge::*;

const BUCKET: &str = "bkt-probe";

fn code(resp: &Resp) -> String {
    let text = resp.text();
    text.split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(c, _)| c.to_owned())
        .unwrap_or_default()
}

#[tokio::test(flavor = "current_thread")]
async fn head_bucket_answers_for_a_granted_bucket_only() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let other = rig.bucket("bkt-not-granted", true).await;

    let ok = rig
        .call(&signer, Method::Head, &format!("/{BUCKET}"), &[], &[], b"")
        .await;
    assert_eq!(ok.status, 200);
    assert_eq!(ok.header("x-amz-bucket-region"), Some(REGION));
    assert!(ok.body.is_empty());

    // Not granted and missing look the same, with no body.
    for name in [other.name.as_str(), "bkt-missing"] {
        let resp = rig
            .call(&signer, Method::Head, &format!("/{name}"), &[], &[], b"")
            .await;
        assert_eq!(resp.status, 403, "{name}");
        assert!(resp.body.is_empty());
    }

    // A read-only grant may probe too.
    let ro = rig
        .key(
            "AKIDREADONLY00000001",
            "ro-secret-0123456789abcdef",
            KeyStatus::Active,
        )
        .await;
    rig.grant("AKIDREADONLY00000001", &other, Perm::Ro).await;
    let resp = rig
        .call(
            &ro,
            Method::Head,
            &format!("/{}", other.name),
            &[],
            &[],
            b"",
        )
        .await;
    assert_eq!(resp.status, 200);
}

#[tokio::test(flavor = "current_thread")]
async fn head_bucket_requires_a_valid_signature() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let mut req = signer.sign(
        rig.now(),
        Method::Head,
        &format!("/{BUCKET}"),
        &[],
        &[],
        vec![],
    );
    let auth = req
        .headers
        .iter_mut()
        .find(|(n, _)| n == "authorization")
        .unwrap();
    let last = auth.1.pop().unwrap();
    auth.1.push(if last == '0' { '1' } else { '0' });
    assert_eq!(rig.send(req).await.status, 403);

    let mut req = signer.sign(
        rig.now(),
        Method::Head,
        &format!("/{BUCKET}"),
        &[],
        &[],
        vec![],
    );
    req.headers.retain(|(n, _)| n != "authorization");
    assert_eq!(rig.send(req).await.status, 403);

    let wrong = Signer::new(AKID, "not-the-secret-0123456789abcdef");
    let resp = rig
        .call(&wrong, Method::Head, &format!("/{BUCKET}"), &[], &[], b"")
        .await;
    assert_eq!(resp.status, 403);
}

#[tokio::test(flavor = "current_thread")]
async fn get_bucket_location_reports_the_region() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let resp = rig
        .call(
            &signer,
            Method::Get,
            &format!("/{BUCKET}"),
            &[("location", "")],
            &[],
            b"",
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        resp.text()
            .contains(&format!(">{REGION}</LocationConstraint>")),
        "{}",
        resp.text()
    );

    let resp = rig
        .call(
            &signer,
            Method::Get,
            "/bkt-missing",
            &[("location", "")],
            &[],
            b"",
        )
        .await;
    assert_eq!((resp.status, code(&resp).as_str()), (403, "AccessDenied"));
}

#[tokio::test(flavor = "current_thread")]
async fn signed_create_bucket_only_confirms_an_owned_bucket() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = format!(
        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{REGION}</LocationConstraint></CreateBucketConfiguration>"
    );

    // rclone's pre-upload CreateBucket on a bucket it may write.
    let resp = rig
        .call(
            &signer,
            Method::Put,
            &format!("/{BUCKET}"),
            &[],
            &[],
            body.as_bytes(),
        )
        .await;
    assert_eq!(
        (resp.status, code(&resp).as_str()),
        (409, "BucketAlreadyOwnedByYou")
    );

    // A new name is not created by a key, and is not told apart from a
    // bucket that exists without a grant.
    let other = rig.bucket("bkt-not-granted", true).await;
    for name in ["bkt-brand-new", other.name.as_str()] {
        let resp = rig
            .call(&signer, Method::Put, &format!("/{name}"), &[], &[], b"")
            .await;
        assert_eq!(
            (resp.status, code(&resp).as_str()),
            (403, "AccessDenied"),
            "{name}"
        );
    }
    assert!(rig
        .bridge
        .catalog
        .bucket_by_name("bkt-brand-new")
        .await
        .unwrap()
        .is_none());

    // Read-only is not write.
    let ro = rig
        .key(
            "AKIDREADONLY00000001",
            "ro-secret-0123456789abcdef",
            KeyStatus::Active,
        )
        .await;
    rig.grant("AKIDREADONLY00000001", &other, Perm::Ro).await;
    let resp = rig
        .call(&ro, Method::Put, &format!("/{}", other.name), &[], &[], b"")
        .await;
    assert_eq!((resp.status, code(&resp).as_str()), (403, "AccessDenied"));

    // A bad signature is refused before any answer about the bucket.
    let mut req = signer.sign(
        rig.now(),
        Method::Put,
        &format!("/{BUCKET}"),
        &[],
        &[],
        vec![],
    );
    let auth = req
        .headers
        .iter_mut()
        .find(|(n, _)| n == "authorization")
        .unwrap();
    let last = auth.1.pop().unwrap();
    auth.1.push(if last == '0' { '1' } else { '0' });
    let resp = rig.send(req).await;
    assert_eq!(
        (resp.status, code(&resp).as_str()),
        (403, "SignatureDoesNotMatch")
    );
}
