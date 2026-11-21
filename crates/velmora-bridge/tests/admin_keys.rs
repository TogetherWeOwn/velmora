//! `GET /_admin/keys` and `DELETE /_admin/keys/<id>`: revocation takes
//! effect on the next request (header-signed and presigned), leaves other
//! keys alone, never shows a secret, and outlives a catalogue restore.
//!
//! `POST /_admin/keys/<id>/grants`: grants a key on one more bucket, as
//! an upsert that never narrows, only while the key and the bucket both
//! exist.

mod service_support;

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use service_support::*;
use sha2::Sha256;
use velmora_bridge::config::Maintenance;
use velmora_bridge::recovery::{read_key_revocation, REVOKED_KEY_PREFIX};
use velmora_bridge::*;

const BUCKET: &str = "bkt-keys";
const TOKEN: &str = "admin-token-fixture-admin-token-fixture";

fn admin_req(method: Method, target: &str, auth: Option<&str>, body: Option<&Value>) -> Req {
    let mut headers = Vec::new();
    if let Some(auth) = auth {
        headers.push(("authorization".to_string(), auth.to_string()));
    }
    let body = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    if !body.is_empty() {
        headers.push(("content-type".to_string(), "application/json".to_string()));
        headers.push(("content-length".to_string(), body.len().to_string()));
    }
    Req {
        method,
        target: target.to_string(),
        headers,
        body,
    }
}

async fn admin<N: NntpConnector + 'static>(
    rig: &Rig<N>,
    method: Method,
    target: &str,
    body: Option<Value>,
) -> Resp {
    let auth = format!("Bearer {TOKEN}");
    rig.send(admin_req(method, target, Some(&auth), body.as_ref()))
        .await
}

/// Mints a key through the API; returns its signer.
async fn mint<N: NntpConnector + 'static>(rig: &Rig<N>, buckets: &[&str], perm: &str) -> Signer {
    let r = admin(
        rig,
        Method::Post,
        "/_admin/keys",
        Some(json!({ "buckets": buckets, "perm": perm })),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    Signer::new(
        v["access_key_id"].as_str().unwrap(),
        v["secret"].as_str().unwrap(),
    )
}

async fn revoke<N: NntpConnector + 'static>(rig: &Rig<N>, akid: &str) -> Resp {
    admin(rig, Method::Delete, &format!("/_admin/keys/{akid}"), None).await
}

async fn list<N: NntpConnector + 'static>(rig: &Rig<N>, query: &str) -> Resp {
    admin(rig, Method::Get, &format!("/_admin/keys{query}"), None).await
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// A presigned GET of `raw_path`, signed at `now` and valid for an hour.
fn presign(signer: &Signer, now: UnixMs, raw_path: &str) -> Req {
    let (stamp, scope, key) = signer.scope(now);
    let credential = format!("{}/{scope}", signer.akid);
    let mut q: Vec<(String, String)> = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        ("X-Amz-Credential", credential.as_str()),
        ("X-Amz-Date", stamp.as_str()),
        ("X-Amz-Expires", "3600"),
        ("X-Amz-SignedHeaders", "host"),
    ]
    .iter()
    .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
    .collect();
    q.sort();
    let query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical = format!("GET\n{raw_path}\n{query}\nhost:{HOST}\n\nhost\nUNSIGNED-PAYLOAD");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&sha256(canonical.as_bytes()))
    );
    let signature = hex(&hmac(&key, to_sign.as_bytes()));
    Req {
        method: Method::Get,
        target: format!("{raw_path}?{query}&X-Amz-Signature={signature}"),
        headers: vec![("host".to_string(), HOST.to_string())],
        body: Vec::new(),
    }
}

/// No response may carry a secret or the name of a secret column.
fn assert_no_secret(resp: &Resp, secrets: &[&str]) {
    let text = resp.text();
    for s in secrets {
        assert!(!text.contains(s), "a secret leaked: {}", resp.status);
        assert!(
            resp.headers.iter().all(|(_, v)| !v.contains(s)),
            "a secret leaked into a header"
        );
    }
    assert!(!text.contains("secret_wrapped"));
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_key_is_refused_on_the_next_request_signed_or_presigned() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let doomed = mint(&rig, &[BUCKET], "rw").await;
    let kept = mint(&rig, &[BUCKET], "ro").await;
    let secrets = [doomed.secret.as_str(), kept.secret.as_str()];
    let obj = path(BUCKET, "a.bin");

    let put = rig.put(&doomed, BUCKET, "a.bin", b"payload").await;
    assert_eq!(put.status, 200, "{}", put.text());
    // Both credentials work before the revocation.
    let get = rig.call(&doomed, Method::Get, &obj, &[], &[], b"").await;
    assert_eq!(get.status, 200);
    let url = presign(&doomed, rig.now(), &obj);
    let target = url.target.clone();
    let pre = rig.send(url).await;
    assert_eq!(pre.status, 200, "{}", pre.text());
    assert_eq!(pre.body, b"payload");
    assert_eq!(rig.count("access_keys"), 2);
    assert_eq!(rig.count("grants"), 2);

    let r = revoke(&rig, &doomed.akid).await;
    assert_eq!(r.status, 204, "{}", r.text());
    assert!(r.body.is_empty());
    assert_no_secret(&r, &secrets);

    // The row (with its wrapped secret) and its grant are gone.
    assert_eq!(rig.count("access_keys"), 1);
    assert_eq!(rig.count("grants"), 1);

    // Header-signed: every kind of request, the bucket listing included.
    for (method, target) in [
        (Method::Get, obj.as_str()),
        (Method::Head, obj.as_str()),
        (Method::Get, "/"),
        (Method::Get, &format!("/{BUCKET}")),
    ] {
        let r = rig
            .call(&doomed, method.clone(), target, &[], &[], b"")
            .await;
        assert_eq!(r.status, 403, "{method:?} {target}");
        if method != Method::Head {
            assert_eq!(r.code(), "InvalidAccessKeyId", "{method:?} {target}");
        }
        assert_no_secret(&r, &secrets);
    }
    let r = rig.put(&doomed, BUCKET, "b.bin", b"late").await;
    assert_eq!((r.status, r.code().as_str()), (403, "InvalidAccessKeyId"));
    // The multipart routes look the key up on their own path.
    let r = rig
        .call(
            &doomed,
            Method::Post,
            &path(BUCKET, "c.bin"),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "InvalidAccessKeyId"));
    assert_eq!(rig.count("uploads"), 0);

    // The presigned URL made before the revocation, sent again.
    let r = rig
        .send(Req {
            method: Method::Get,
            target,
            headers: vec![("host".to_string(), HOST.to_string())],
            body: Vec::new(),
        })
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "InvalidAccessKeyId"));
    assert_no_secret(&r, &secrets);
    // And one presigned after it.
    let r = rig.send(presign(&doomed, rig.now(), &obj)).await;
    assert_eq!((r.status, r.code().as_str()), (403, "InvalidAccessKeyId"));

    // The other key is untouched.
    let r = rig.call(&kept, Method::Get, &obj, &[], &[], b"").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"payload");
    let r = rig.send(presign(&kept, rig.now(), &obj)).await;
    assert_eq!(r.status, 200);

    // Idempotent: the second call finds no key.
    let r = revoke(&rig, &doomed.akid).await;
    assert_eq!(r.status, 404);
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["error"], "NoSuchAccessKey");
    assert_no_secret(&r, &secrets);

    // The recovery record exists, opens, and holds no secret.
    let rec = read_key_revocation(&rig.bridge.safety, &rig.bridge.kek, &doomed.akid)
        .await
        .unwrap()
        .expect("revocation record");
    assert_eq!(rec.access_key_id, doomed.akid);
    assert_eq!(rec.revoked_at, rig.now().0);
    let names = rig
        .bridge
        .safety
        .list(REVOKED_KEY_PREFIX, "", 100)
        .await
        .unwrap();
    assert_eq!(names, vec![format!("{REVOKED_KEY_PREFIX}{}", doomed.akid)]);
    let raw = rig
        .bridge
        .safety
        .get(&names[0], None)
        .await
        .unwrap()
        .unwrap();
    assert!(!raw
        .windows(doomed.secret.len())
        .any(|w| w == doomed.secret.as_bytes()));
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_or_malformed_ids_are_404_and_change_nothing() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    for id in [
        "AKVLNOSUCHKEY0000000",
        "akvl-not-an-id",
        "AKVL%2F..%2Fx",
        "..",
        "AKVL/extra",
        &"A".repeat(129),
    ] {
        let r = revoke(&rig, id).await;
        assert_eq!(r.status, 404, "{id}");
        assert_no_secret(&r, &[&key.secret]);
    }
    let r = admin(&rig, Method::Delete, "/_admin/keys/", None).await;
    assert_eq!(r.status, 404);
    // Nothing was written and the key still works.
    assert!(rig
        .bridge
        .safety
        .list(REVOKED_KEY_PREFIX, "", 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(rig.count("access_keys"), 1);
    let r = rig.put(&key, BUCKET, "k", b"x").await;
    assert_eq!(r.status, 200);
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_record_write_leaves_the_key_and_a_retry_revokes_it() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = Some(REVOKED_KEY_PREFIX.to_string());
    let r = revoke(&rig, &key.akid).await;
    assert_eq!(r.status, 500);
    assert_no_secret(&r, &[&key.secret]);
    // No record, so the key was not deleted either.
    assert_eq!(rig.count("access_keys"), 1);
    assert_eq!(rig.put(&key, BUCKET, "k", b"x").await.status, 200);

    *rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    assert_eq!(revoke(&rig, &key.akid).await.status, 204);
    assert_eq!(rig.put(&key, BUCKET, "k", b"x").await.status, 403);
}

#[tokio::test(flavor = "current_thread")]
async fn list_shows_ids_grants_and_times_never_secrets() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    rig.bucket("bkt-other", true).await;
    let a = mint(&rig, &[BUCKET, "bkt-other"], "rw").await;
    let b = mint(&rig, &["bkt-other"], "ro").await;

    let r = list(&rig, "").await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_no_secret(&r, &[&a.secret, &b.secret]);
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert!(v["next"].is_null());
    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let find = |id: &str| keys.iter().find(|k| k["access_key_id"] == id).unwrap();
    assert_eq!(
        find(&a.akid),
        &json!({
            "access_key_id": a.akid,
            "kind": "s3",
            "status": "active",
            "created_at": rig.now().0,
            "grants": [
                { "bucket": BUCKET, "perm": "rw" },
                { "bucket": "bkt-other", "perm": "rw" },
            ],
        })
    );
    assert_eq!(
        find(&b.akid)["grants"],
        json!([{ "bucket": "bkt-other", "perm": "ro" }])
    );
    // Only the documented fields.
    for k in keys {
        let mut fields: Vec<&String> = k.as_object().unwrap().keys().collect();
        fields.sort();
        assert_eq!(
            fields,
            ["access_key_id", "created_at", "grants", "kind", "status"]
        );
    }

    // `after` pages by id.
    let first = keys[0]["access_key_id"].as_str().unwrap().to_string();
    let r = list(&rig, &format!("?after={first}")).await;
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    assert_ne!(v["keys"][0]["access_key_id"], first.as_str());
    for bad in ["?after=a-b", "?after=", "?other=1", "?after"] {
        assert_eq!(list(&rig, bad).await.status, 400, "{bad}");
    }

    // A revoked key is no longer listed.
    assert_eq!(revoke(&rig, &a.akid).await.status, 204);
    let v: Value = serde_json::from_slice(&list(&rig, "").await.body).unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    assert_eq!(v["keys"][0]["access_key_id"], b.akid.as_str());
}

#[tokio::test(flavor = "current_thread")]
async fn list_pages_past_five_hundred_keys() {
    let rig = rig();
    let bucket = rig.bucket(BUCKET, true).await;
    for i in 0..501 {
        let akid = format!("AKVLPAGE{i:012}");
        rig.key(&akid, "secret-secret-secret-secret-0000", KeyStatus::Active)
            .await;
        rig.grant(&akid, &bucket, Perm::Ro).await;
    }
    let v: Value = serde_json::from_slice(&list(&rig, "").await.body).unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 500);
    assert_eq!(v["next"], "AKVLPAGE000000000499");
    let v: Value =
        serde_json::from_slice(&list(&rig, "?after=AKVLPAGE000000000499").await.body).unwrap();
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    assert!(v["next"].is_null());
}

#[tokio::test(flavor = "current_thread")]
async fn only_the_admin_bearer_reaches_the_key_routes() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    let target = format!("/_admin/keys/{}", key.akid);
    for (method, target) in [
        (Method::Delete, target.as_str()),
        (Method::Get, "/_admin/keys"),
    ] {
        for auth in [None, Some("Bearer ")] {
            let r = rig
                .send(admin_req(method.clone(), target, auth, None))
                .await;
            assert_eq!(r.status, 401, "{method:?} {target} {auth:?}");
            assert_no_secret(&r, &[&key.secret]);
        }
        for auth in ["Bearer wrong", &format!("Bearer {TOKEN}x")] {
            let r = rig
                .send(admin_req(method.clone(), target, Some(auth), None))
                .await;
            assert_eq!(r.status, 403, "{method:?} {target}");
            assert_no_secret(&r, &[&key.secret]);
        }
        // An S3 signature, even of a valid key, is not the admin bearer.
        let r = rig.call(&key, method.clone(), target, &[], &[], b"").await;
        assert!(
            matches!(r.status, 401 | 403),
            "{method:?} {target}: {}",
            r.status
        );
        assert_no_secret(&r, &[&key.secret]);
    }
    // Nothing was revoked.
    assert_eq!(rig.count("access_keys"), 1);
    assert_eq!(rig.put(&key, BUCKET, "k", b"x").await.status, 200);
}

#[tokio::test(flavor = "current_thread")]
async fn a_restore_forgets_keys_revoked_after_the_export() {
    let mut cfg = config(Vec::new());
    cfg.maintenance = Maintenance::Restore;
    let rig = rig_with(NoNntp, cfg);
    let bucket = rig.bucket(BUCKET, true).await;
    let doomed = rig
        .key(
            "AKVLDOOMED0000000001",
            "secret-doomed-secret-doomed-0001",
            KeyStatus::Active,
        )
        .await;
    rig.grant(&doomed.akid, &bucket, Perm::Rw).await;
    let kept = rig
        .key(
            "AKVLKEPT000000000001",
            "secret-kept-secret-kept-000000001",
            KeyStatus::Active,
        )
        .await;
    rig.grant(&kept.akid, &bucket, Perm::Ro).await;
    let probe = format!("/{BUCKET}");

    // Revocation is accepted under maintenance.
    assert_eq!(revoke(&rig, &doomed.akid).await.status, 204);
    let r = rig.call(&doomed, Method::Get, &probe, &[], &[], b"").await;
    assert_eq!((r.status, r.code().as_str()), (403, "InvalidAccessKeyId"));

    // A catalogue export made before the revocation is loaded: the row
    // and its grant are back.
    rig.key(&doomed.akid, &doomed.secret, KeyStatus::Active)
        .await;
    rig.grant(&doomed.akid, &bucket, Perm::Rw).await;
    assert_eq!(rig.count("access_keys"), 2);
    // Under maintenance its revocation record refuses it all the same,
    // signed or presigned, before any replay step ran.
    let r = rig.call(&doomed, Method::Get, &probe, &[], &[], b"").await;
    assert_eq!((r.status, r.code().as_str()), (403, "InvalidAccessKeyId"));
    let r = rig.send(presign(&doomed, rig.now(), &probe)).await;
    assert_eq!((r.status, r.code().as_str()), (403, "InvalidAccessKeyId"));
    let r = rig.call(&kept, Method::Get, &probe, &[], &[], b"").await;
    assert_eq!(r.status, 200, "a key without a record still reads");

    // The first replay step deletes it before it replays anything.
    let r = admin(
        &rig,
        Method::Post,
        "/_admin/restore",
        Some(json!({ "since_ms": 0 })),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let r = rig.call(&doomed, Method::Get, &probe, &[], &[], b"").await;
    assert_eq!((r.status, r.code().as_str()), (403, "InvalidAccessKeyId"));
    assert_eq!(rig.count("access_keys"), 1);
    assert_eq!(rig.count("grants"), 1);
    let r = rig.call(&kept, Method::Get, &probe, &[], &[], b"").await;
    assert_eq!(r.status, 200);
}

// ---------------------------------------------------------------------------
// POST /_admin/keys/<id>/grants
// ---------------------------------------------------------------------------

async fn grant_req<N: NntpConnector + 'static>(rig: &Rig<N>, akid: &str, body: Value) -> Resp {
    admin(
        rig,
        Method::Post,
        &format!("/_admin/keys/{akid}/grants"),
        Some(body),
    )
    .await
}

/// The grants `GET /_admin/keys` lists for `akid`; `None` if the key is
/// not listed.
async fn listed_grants<N: NntpConnector + 'static>(rig: &Rig<N>, akid: &str) -> Option<Value> {
    let v: Value = serde_json::from_slice(&list(rig, "").await.body).unwrap();
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["access_key_id"] == akid)
        .map(|k| k["grants"].clone())
}

#[tokio::test(flavor = "current_thread")]
async fn a_grant_opens_another_bucket_to_the_key() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    rig.bucket("bkt-second", true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    // Before the grant the key cannot write there.
    assert_eq!(rig.put(&key, "bkt-second", "k", b"x").await.status, 404);

    let r = grant_req(
        &rig,
        &key.akid,
        json!({ "bucket": "bkt-second", "perm": "rw" }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_no_secret(&r, &[&key.secret]);
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(
        v,
        json!({ "access_key_id": key.akid, "bucket": "bkt-second", "perm": "rw" })
    );

    let put = rig.put(&key, "bkt-second", "k", b"payload").await;
    assert_eq!(put.status, 200, "{}", put.text());
    let get = rig
        .call(&key, Method::Get, &path("bkt-second", "k"), &[], &[], b"")
        .await;
    assert_eq!(get.status, 200);
    assert_eq!(get.body, b"payload");
    let buckets = rig.call(&key, Method::Get, "/", &[], &[], b"").await;
    assert_eq!(buckets.status, 200);
    let text = buckets.text();
    assert!(text.contains(&format!("<Name>{BUCKET}</Name>")), "{text}");
    assert!(text.contains("<Name>bkt-second</Name>"), "{text}");

    assert_eq!(
        listed_grants(&rig, &key.akid).await.unwrap(),
        json!([
            { "bucket": BUCKET, "perm": "rw" },
            { "bucket": "bkt-second", "perm": "rw" },
        ])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_second_grant_widens_the_first() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    rig.bucket("bkt-second", true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;

    let r = grant_req(
        &rig,
        &key.akid,
        json!({ "bucket": "bkt-second", "perm": "ro" }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(rig.put(&key, "bkt-second", "k", b"x").await.status, 403);
    let r = rig
        .call(&key, Method::Get, "/bkt-second", &[], &[], b"")
        .await;
    assert_eq!(r.status, 200, "ro still lists: {}", r.text());

    let r = grant_req(
        &rig,
        &key.akid,
        json!({ "bucket": "bkt-second", "perm": "rw" }),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(rig.put(&key, "bkt-second", "k", b"x").await.status, 200);
    assert_eq!(rig.count("grants"), 2);
    assert_eq!(
        listed_grants(&rig, &key.akid).await.unwrap(),
        json!([
            { "bucket": BUCKET, "perm": "rw" },
            { "bucket": "bkt-second", "perm": "rw" },
        ])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn grant_requests_that_name_nothing_or_are_malformed_change_nothing() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let key = mint(&rig, &[BUCKET], "ro").await;
    let ok_body = json!({ "bucket": BUCKET, "perm": "rw" });
    let code = |r: &Resp| {
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        v["error"].as_str().unwrap().to_string()
    };

    // A well-formed id that names no key.
    let r = grant_req(&rig, "AKVLNOSUCHKEY0000000", ok_body.clone()).await;
    assert_eq!((r.status, code(&r).as_str()), (404, "NoSuchAccessKey"));
    // Ids that could not have been minted.
    for id in ["akvl-not-an-id", "AKVL%2F..%2Fx", "..", "AKVL/extra", ""] {
        let r = grant_req(&rig, id, ok_body.clone()).await;
        assert_eq!(r.status, 404, "{id:?}: {}", r.text());
    }
    let long = "A".repeat(129);
    let r = grant_req(&rig, &long, ok_body.clone()).await;
    assert_eq!(r.status, 404);

    // No such bucket.
    let r = grant_req(
        &rig,
        &key.akid,
        json!({ "bucket": "bkt-none", "perm": "rw" }),
    )
    .await;
    assert_eq!((r.status, code(&r).as_str()), (404, "NoSuchBucket"));
    // Bad perm, unknown field, missing field, not JSON.
    for body in [
        json!({ "bucket": BUCKET, "perm": "admin" }),
        json!({ "bucket": BUCKET, "perm": "RW" }),
    ] {
        let r = grant_req(&rig, &key.akid, body).await;
        assert_eq!((r.status, code(&r).as_str()), (400, "InvalidArgument"));
    }
    for body in [
        json!({ "bucket": BUCKET, "perm": "rw", "wildcard": true }),
        json!({ "bucket": BUCKET }),
        json!("bkt-keys rw"),
    ] {
        let r = grant_req(&rig, &key.akid, body.clone()).await;
        assert_eq!(r.status, 400, "{body}");
    }

    assert_eq!(rig.count("grants"), 1);
    assert_eq!(rig.put(&key, BUCKET, "k", b"x").await.status, 403);
    assert_eq!(
        listed_grants(&rig, &key.akid).await.unwrap(),
        json!([{ "bucket": BUCKET, "perm": "ro" }])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn only_the_admin_bearer_grants() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    rig.bucket("bkt-second", true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    let target = format!("/_admin/keys/{}/grants", key.akid);
    let body = json!({ "bucket": "bkt-second", "perm": "rw" });
    for auth in [None, Some("Bearer ")] {
        let r = rig
            .send(admin_req(Method::Post, &target, auth, Some(&body)))
            .await;
        assert_eq!(r.status, 401, "{auth:?}");
    }
    for auth in ["Bearer wrong", &format!("Bearer {TOKEN}x")] {
        let r = rig
            .send(admin_req(Method::Post, &target, Some(auth), Some(&body)))
            .await;
        assert_eq!(r.status, 403);
    }
    // The key's own S3 signature is not the admin bearer either.
    let bytes = body.to_string().into_bytes();
    let r = rig
        .call(&key, Method::Post, &target, &[], &[], &bytes)
        .await;
    assert!(matches!(r.status, 401 | 403), "{}", r.status);
    assert_eq!(rig.count("grants"), 1);
    assert_eq!(rig.put(&key, "bkt-second", "k", b"x").await.status, 404);
}

#[tokio::test(flavor = "current_thread")]
async fn other_methods_on_grants_are_405_and_revoke_nothing() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    let target = format!("/_admin/keys/{}/grants", key.akid);
    for method in [Method::Get, Method::Put, Method::Delete, Method::Head] {
        let r = admin(&rig, method.clone(), &target, None).await;
        assert_eq!(r.status, 405, "{method:?}");
    }
    assert_eq!(rig.count("access_keys"), 1);
    assert_eq!(rig.count("grants"), 1);
    assert!(rig
        .bridge
        .safety
        .list(REVOKED_KEY_PREFIX, "", 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(rig.put(&key, BUCKET, "k", b"x").await.status, 200);
    // Revocation itself is unchanged.
    assert_eq!(revoke(&rig, &key.akid).await.status, 204);
}

#[tokio::test(flavor = "current_thread")]
async fn a_revoked_key_cannot_be_granted() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    rig.bucket("bkt-second", true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    let other = mint(&rig, &[BUCKET], "ro").await;
    assert_eq!(revoke(&rig, &key.akid).await.status, 204);

    let r = grant_req(
        &rig,
        &key.akid,
        json!({ "bucket": "bkt-second", "perm": "rw" }),
    )
    .await;
    assert_eq!(r.status, 404, "{}", r.text());
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["error"], "NoSuchAccessKey");
    assert!(listed_grants(&rig, &key.akid).await.is_none());
    // Only the other key's grant is left.
    assert_eq!(rig.count("grants"), 1);
    assert_eq!(
        listed_grants(&rig, &other.akid).await.unwrap(),
        json!([{ "bucket": BUCKET, "perm": "ro" }])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn no_grant_is_accepted_under_maintenance() {
    let mut cfg = config(Vec::new());
    cfg.maintenance = Maintenance::Restore;
    let rig = rig_with(NoNntp, cfg);
    let bucket = rig.bucket(BUCKET, true).await;
    let second = rig.bucket("bkt-second", true).await;
    let key = rig
        .key(
            "AKVLGRANT00000000001",
            "secret-grant-secret-grant-000001",
            KeyStatus::Active,
        )
        .await;
    rig.grant(&key.akid, &bucket, Perm::Rw).await;

    let r = grant_req(
        &rig,
        &key.akid,
        json!({ "bucket": second.name, "perm": "rw" }),
    )
    .await;
    assert_eq!(r.status, 503, "{}", r.text());
    // Checked before the id: a malformed one is refused the same way.
    let r = grant_req(&rig, "..", json!({ "bucket": second.name, "perm": "rw" })).await;
    assert_eq!(r.status, 503);
    assert_eq!(rig.count("grants"), 1);
}

/// The catalogue write is guarded by the key and the bucket rows: a
/// grant that lands after a revocation or a bucket deletion writes
/// nothing, so it cannot outlive either.
#[tokio::test(flavor = "current_thread")]
async fn a_guarded_grant_after_revocation_or_bucket_deletion_writes_nothing() {
    let rig = rig();
    let bucket = rig.bucket(BUCKET, true).await;
    let second = rig.bucket("bkt-second", true).await;
    let key = rig
        .key(
            "AKVLRACE000000000001",
            "secret-race-secret-race-00000001",
            KeyStatus::Active,
        )
        .await;
    rig.grant(&key.akid, &bucket, Perm::Rw).await;
    let catalog = &rig.bridge.catalog;

    // Applied while both rows exist, and an upsert on repeat.
    assert_eq!(
        catalog
            .put_grant_if_present(&key.akid, &second.id, Perm::Ro)
            .await
            .unwrap(),
        GrantPut::Applied
    );
    assert_eq!(
        catalog
            .put_grant_if_present(&key.akid, &second.id, Perm::Rw)
            .await
            .unwrap(),
        GrantPut::Applied
    );
    assert_eq!(
        catalog.grant(&key.akid, &second.id).await.unwrap(),
        Some(Perm::Rw)
    );
    // Never narrowed: rw stays rw, and the outcome says why.
    assert_eq!(
        catalog
            .put_grant_if_present(&key.akid, &second.id, Perm::Ro)
            .await
            .unwrap(),
        GrantPut::Narrowing
    );
    assert_eq!(
        catalog.grant(&key.akid, &second.id).await.unwrap(),
        Some(Perm::Rw)
    );
    assert_eq!(rig.count("grants"), 2);

    // The bucket goes (with its grants): a late grant on it is refused.
    assert_eq!(
        catalog.delete_bucket(&second).await.unwrap(),
        Guard::Applied(())
    );
    assert_eq!(rig.count("grants"), 1);
    assert_eq!(
        catalog
            .put_grant_if_present(&key.akid, &second.id, Perm::Rw)
            .await
            .unwrap(),
        GrantPut::Lost
    );
    assert_eq!(rig.count("grants"), 1);
    // Through the route: the bucket name is unknown now.
    let r = grant_req(
        &rig,
        &key.akid,
        json!({ "bucket": "bkt-second", "perm": "rw" }),
    )
    .await;
    assert_eq!(r.status, 404);

    // The key goes (with its grants): a late grant for it is refused.
    assert_eq!(
        catalog
            .delete_access_keys(std::slice::from_ref(&key.akid))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        catalog
            .put_grant_if_present(&key.akid, &bucket.id, Perm::Rw)
            .await
            .unwrap(),
        GrantPut::Lost
    );
    assert_eq!(rig.count("grants"), 0);
    assert_eq!(rig.count("access_keys"), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_grant_is_never_narrowed() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    // Repeating rw is fine.
    let r = grant_req(&rig, &key.akid, json!({ "bucket": BUCKET, "perm": "rw" })).await;
    assert_eq!(r.status, 200, "{}", r.text());

    let r = grant_req(&rig, &key.akid, json!({ "bucket": BUCKET, "perm": "ro" })).await;
    assert_eq!(r.status, 409, "{}", r.text());
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_no_secret(&r, &[&key.secret]);
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["error"], "GrantNarrowingRefused");

    // Nothing changed: the key still writes.
    assert_eq!(rig.put(&key, BUCKET, "k", b"x").await.status, 200);
    assert_eq!(
        listed_grants(&rig, &key.akid).await.unwrap(),
        json!([{ "bucket": BUCKET, "perm": "rw" }])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn no_grant_is_accepted_while_a_replay_is_unfinished() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    rig.bucket("bkt-second", true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    rig.bridge.catalog.sql.with_conn(|c| {
        c.execute(
            "INSERT INTO restore_state (id, state, since_ms, started_at) \
             VALUES (1, 'replaying', 0, 1)",
            [],
        )
        .unwrap();
    });
    assert!(rig.bridge.catalog.restore_pending().await.unwrap());

    let r = grant_req(
        &rig,
        &key.akid,
        json!({ "bucket": "bkt-second", "perm": "rw" }),
    )
    .await;
    assert_eq!(r.status, 503, "{}", r.text());
    assert_eq!(rig.count("grants"), 1);
    assert_eq!(rig.put(&key, "bkt-second", "k", b"x").await.status, 404);
}

#[tokio::test(flavor = "current_thread")]
async fn every_admin_answer_is_no_store() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let auth = format!("Bearer {TOKEN}");
    for (method, target, auth) in [
        (Method::Get, "/_admin/status", Some(auth.as_str())),
        (Method::Get, "/_admin/nothing-here", Some(auth.as_str())),
        (Method::Put, "/_admin/status", Some(auth.as_str())),
        (Method::Get, "/_admin/status", None),
        (Method::Get, "/_admin/status", Some("Bearer wrong")),
    ] {
        let r = rig
            .send(admin_req(method.clone(), target, auth, None))
            .await;
        assert_eq!(
            r.header("cache-control"),
            Some("no-store"),
            "{method:?} {target} {}",
            r.status
        );
        let n = r
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("cache-control"))
            .count();
        assert_eq!(n, 1, "one cache-control header");
    }
}

/// The Worker's own path: `ingress::front` runs the precheck (which
/// refuses a missing or wrong bearer itself) and then the bridge. Every
/// admin answer of either carries `no-store`; an S3 refusal does not
/// get one added.
#[tokio::test(flavor = "current_thread")]
async fn admin_refusals_of_the_precheck_are_no_store() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let key = mint(&rig, &[BUCKET], "rw").await;
    let grants = format!("/_admin/keys/{}/grants", key.akid);
    let body = json!({ "bucket": BUCKET, "perm": "rw" });
    let good = format!("Bearer {TOKEN}");
    let through_front = |req: Req, https: bool| {
        let bridge = std::rc::Rc::clone(&rig.bridge);
        async move {
            let resp = ingress::front(req.into_request(), &bridge.cfg, https, |r| {
                std::rc::Rc::clone(&bridge).handle(r)
            })
            .await;
            Resp::collect(resp).await
        }
    };
    for (method, target, auth, https, status) in [
        (Method::Get, "/_admin/status", None, true, 401),
        (
            Method::Get,
            "/_admin/status",
            Some("Bearer wrong"),
            true,
            403,
        ),
        (Method::Post, grants.as_str(), None, true, 401),
        (
            Method::Post,
            grants.as_str(),
            Some("Bearer wrong"),
            true,
            403,
        ),
        (Method::Get, "/_admin", None, true, 401),
        // Plain http is refused before the bearer is looked at.
        (
            Method::Get,
            "/_admin/status",
            Some(good.as_str()),
            false,
            403,
        ),
        // And the bridge's own answers keep theirs.
        (
            Method::Get,
            "/_admin/status",
            Some(good.as_str()),
            true,
            200,
        ),
        (
            Method::Post,
            grants.as_str(),
            Some(good.as_str()),
            true,
            200,
        ),
    ] {
        let with_body = (method == Method::Post).then_some(&body);
        let r = through_front(admin_req(method.clone(), target, auth, with_body), https).await;
        assert_eq!(
            r.status,
            status,
            "{method:?} {target} {auth:?}: {}",
            r.text()
        );
        assert_eq!(
            r.header("cache-control"),
            Some("no-store"),
            "{method:?} {target} {auth:?}"
        );
        let n = r
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("cache-control"))
            .count();
        assert_eq!(n, 1, "one cache-control header");
    }
    // An S3 request refused by the precheck is not an admin answer.
    let r = through_front(
        admin_req(Method::Get, &format!("/{BUCKET}"), None, None),
        true,
    )
    .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.header("cache-control"), None);

    // The URL form the Worker sees before it parses the request.
    for (url, admin) in [
        ("https://h/_admin", true),
        ("https://h/_admin/keys?after=x", true),
        ("https://h/_admin?x=1", true),
        ("https://h/_adminx", false),
        ("https://h/bkt/_admin/k", false),
        ("https://h/", false),
        // Unreadable: treated as admin, so the refusal is not cached.
        ("not a url", true),
    ] {
        assert_eq!(ingress::is_admin_url(url), admin, "{url}");
    }
    // The host a URL was sent to, as a Host header has it.
    for (url, host) in [
        ("https://h/_admin", Some("h")),
        (
            "https://Admin.example:8443/x?y=1",
            Some("Admin.example:8443"),
        ),
        ("https://user@h?x", Some("h")),
        ("https:///x", None),
        ("not a url", None),
    ] {
        assert_eq!(ingress::url_authority(url), host, "{url}");
    }
}

/// `kind: app_password` mints an `APVL` key pair that the S3 entry point
/// refuses; a bad kind is refused before anything is written.
#[tokio::test]
async fn app_passwords_are_minted_with_their_own_prefix() {
    let rig = rig();
    rig.bucket(BUCKET, true).await;
    let r = admin(
        &rig,
        Method::Post,
        "/_admin/keys",
        Some(json!({ "buckets": [BUCKET], "perm": "rw", "kind": "app_password" })),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let v: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["kind"], "app_password");
    let app = Signer::new(
        v["access_key_id"].as_str().unwrap(),
        v["secret"].as_str().unwrap(),
    );
    assert!(
        app.akid.starts_with("APVL") && app.akid.len() == 20,
        "{}",
        app.akid
    );
    let s3 = mint(&rig, &[BUCKET], "rw").await;
    assert!(s3.akid.starts_with("AKVL"), "{}", s3.akid);

    let r = rig.put(&app, BUCKET, "k", b"x").await;
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.text().contains("InvalidAccessKeyId"));
    assert_eq!(rig.put(&s3, BUCKET, "k", b"x").await.status, 200);

    let v: Value = serde_json::from_slice(&list(&rig, "").await.body).unwrap();
    let kinds: Vec<(String, String)> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            (
                k["access_key_id"].as_str().unwrap().to_string(),
                k["kind"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(kinds.contains(&(app.akid.clone(), "app_password".into())));
    assert!(kinds.contains(&(s3.akid.clone(), "s3".into())));

    let keys_before = rig.count("access_keys");
    for bad in ["internal", "S3", ""] {
        let r = admin(
            &rig,
            Method::Post,
            "/_admin/keys",
            Some(json!({ "buckets": [BUCKET], "perm": "ro", "kind": bad })),
        )
        .await;
        assert_eq!(r.status, 400, "{bad}: {}", r.text());
    }
    assert_eq!(rig.count("access_keys"), keys_before);
}
