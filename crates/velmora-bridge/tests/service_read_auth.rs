//! A GET or HEAD of an object reads who asks together with the object,
//! in one statement. It is judged as every other request is: the same
//! callers are let in, and a caller that is refused gets the answer a
//! request authenticated on the single reads gets (GetBucketLocation
//! here), by a signed header, by a presigned URL and after a chunked
//! upload alike.

mod service_support;

use hmac::{Hmac, KeyInit, Mac};
use service_support::*;
use sha2::Sha256;
use velmora_bridge::config::Maintenance;
use velmora_bridge::recovery::write_key_revocation;
use velmora_bridge::*;

const BUCKET: &str = "bkt-read-auth";
const STREAMING: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// The smallest a signed chunk that is not the last may be.
const CHUNK: usize = 8192;

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// A secret that is not the one of any key of the rig.
fn another_secret() -> String {
    hex(&sha256(secret().as_bytes()))
}

/// A presigned request: the signature in the query, `host` the only
/// signed header, the payload unsigned.
fn presign(
    signer: &Signer,
    now: UnixMs,
    method: Method,
    raw_path: &str,
    query: &[(&str, &str)],
) -> Req {
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
    .chain(query)
    .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
    .collect();
    q.sort();
    let query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical = format!(
        "{}\n{raw_path}\n{query}\nhost:{HOST}\n\nhost\nUNSIGNED-PAYLOAD",
        method.as_str()
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&sha256(canonical.as_bytes()))
    );
    let signature = hex(&hmac(&key, to_sign.as_bytes()));
    Req {
        method,
        target: format!("{raw_path}?{query}&X-Amz-Signature={signature}"),
        headers: vec![("host".to_string(), HOST.to_string())],
        body: Vec::new(),
    }
}

/// What is done to a request after it was signed.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Twist {
    None,
    /// The signature replaced.
    Tampered,
    /// No credential at all.
    Anonymous,
    /// `Host` in the virtual-hosted form.
    VirtualHost,
    /// `Host` naming something else.
    OtherHost,
    /// A signed header that is not served.
    RefusedHeader,
}

/// One kind of caller: who signs, for which bucket, how the request is
/// bent, and the answer expected of a request for an object that
/// exists (`None`: it is served).
struct Caller<'a> {
    name: &'static str,
    signer: &'a Signer,
    bucket: &'a str,
    twist: Twist,
    refused: Option<(u16, &'static str)>,
}

fn request(
    rig: &Rig<NoNntp>,
    caller: &Caller<'_>,
    presigned: bool,
    method: Method,
    target: &str,
    query: &[(&str, &str)],
    signed: &[(&'static str, &'static str)],
) -> Req {
    let mut headers = signed.to_vec();
    if caller.twist == Twist::RefusedHeader {
        headers.push(("x-amz-tagging", "a=b"));
    }
    let mut req = match presigned {
        true => presign(caller.signer, rig.now(), method, target, query),
        false => caller
            .signer
            .sign(rig.now(), method, target, query, &headers, Vec::new()),
    };
    match caller.twist {
        Twist::Tampered if presigned => {
            let (head, _) = req.target.rsplit_once("X-Amz-Signature=").unwrap();
            req.target = format!("{head}X-Amz-Signature={}", "0".repeat(64));
        }
        Twist::Tampered => {
            let signed = req
                .headers
                .iter()
                .find(|(n, _)| n == "authorization")
                .map(|(_, v)| v.clone())
                .unwrap();
            let (head, _) = signed.rsplit_once("Signature=").unwrap();
            req.set_header(
                "authorization",
                &format!("{head}Signature={}", "0".repeat(64)),
            );
        }
        Twist::Anonymous if presigned => {
            req.target = target.to_owned();
        }
        Twist::Anonymous => req.headers.retain(|(n, _)| n != "authorization"),
        Twist::VirtualHost => req.set_header("host", &format!("{BUCKET}.{HOST}")),
        Twist::OtherHost => req.set_header("host", "elsewhere.test"),
        Twist::None | Twist::RefusedHeader => {}
    }
    req
}

/// Runs every kind of caller against an object that exists, by a signed
/// header and by a presigned URL, and holds GET and HEAD of the object
/// to the answer of GetBucketLocation for the same caller.
async fn judged_alike(maintenance: Maintenance) {
    let body = b"the stored body";
    // The object is stored before the service goes into maintenance:
    // nothing is written then.
    let mut rig = rig();
    let (bucket, rw) = rig.standard(BUCKET).await;
    rig.put(&rw, BUCKET, "k", body).await.expect(200);
    std::rc::Rc::get_mut(&mut rig.bridge)
        .expect("no request is in flight")
        .cfg
        .maintenance = maintenance;

    let other = rig.bucket("bkt-read-other", true).await;
    let ro = rig
        .key("AKIDTESTKEY0000000RO", secret(), KeyStatus::Active)
        .await;
    rig.grant(&ro.akid, &bucket, Perm::Ro).await;
    let disabled = rig
        .key("AKIDTESTKEY000000OFF", secret(), KeyStatus::Disabled)
        .await;
    rig.grant(&disabled.akid, &bucket, Perm::Rw).await;
    let ungranted = rig
        .key("AKIDTESTKEY00000ELSE", secret(), KeyStatus::Active)
        .await;
    rig.grant(&ungranted.akid, &other, Perm::Rw).await;
    let revoked = rig
        .key("AKIDTESTKEY00REVOKED", secret(), KeyStatus::Active)
        .await;
    rig.grant(&revoked.akid, &bucket, Perm::Rw).await;
    let unknown = Signer::new("AKIDTESTKEY000000NONE", secret());
    let wrong = Signer::new(&rw.akid, &another_secret());
    let west = Signer {
        region: "us-west-2".to_owned(),
        ..rw.clone()
    };
    if maintenance == Maintenance::Restore {
        // The row and the grant are still in the catalogue; the record
        // of the revocation is the authority.
        write_key_revocation(
            &rig.bridge.safety,
            &rig.bridge.kek,
            &revoked.akid,
            rig.now(),
        )
        .await
        .unwrap();
    }

    let caller = |name, signer, bucket, twist, refused| Caller {
        name,
        signer,
        bucket,
        twist,
        refused,
    };
    let revoked_answer = match maintenance {
        Maintenance::Restore => Some((403, "InvalidAccessKeyId")),
        _ => None,
    };
    let callers = [
        caller("rw", &rw, BUCKET, Twist::None, None),
        caller("ro", &ro, BUCKET, Twist::None, None),
        caller("revoked", &revoked, BUCKET, Twist::None, revoked_answer),
        caller(
            "unknown key",
            &unknown,
            BUCKET,
            Twist::None,
            Some((403, "InvalidAccessKeyId")),
        ),
        caller(
            "disabled key",
            &disabled,
            BUCKET,
            Twist::None,
            Some((403, "InvalidAccessKeyId")),
        ),
        // To a key, a bucket it has no grant on does not exist.
        caller(
            "no grant",
            &ungranted,
            BUCKET,
            Twist::None,
            Some((404, "NoSuchBucket")),
        ),
        caller(
            "absent bucket",
            &rw,
            "bkt-read-absent",
            Twist::None,
            Some((404, "NoSuchBucket")),
        ),
        // A caller that did not authenticate learns nothing of the bucket.
        caller(
            "unknown key, absent bucket",
            &unknown,
            "bkt-read-absent",
            Twist::None,
            Some((403, "InvalidAccessKeyId")),
        ),
        caller(
            "wrong secret",
            &wrong,
            BUCKET,
            Twist::None,
            Some((403, "SignatureDoesNotMatch")),
        ),
        caller(
            "wrong secret, absent bucket",
            &wrong,
            "bkt-read-absent",
            Twist::None,
            Some((403, "SignatureDoesNotMatch")),
        ),
        caller(
            "tampered",
            &rw,
            BUCKET,
            Twist::Tampered,
            Some((403, "SignatureDoesNotMatch")),
        ),
        caller(
            "anonymous",
            &rw,
            BUCKET,
            Twist::Anonymous,
            Some((403, "AccessDenied")),
        ),
        caller("wrong region", &west, BUCKET, Twist::None, Some((400, ""))),
        caller(
            "virtual host",
            &rw,
            BUCKET,
            Twist::VirtualHost,
            Some((400, "InvalidRequest")),
        ),
        caller(
            "other host",
            &rw,
            BUCKET,
            Twist::OtherHost,
            Some((400, "InvalidRequest")),
        ),
        caller(
            "unknown key, other host",
            &unknown,
            BUCKET,
            Twist::OtherHost,
            Some((400, "InvalidRequest")),
        ),
        caller(
            "refused header",
            &rw,
            BUCKET,
            Twist::RefusedHeader,
            Some((501, "NotImplemented")),
        ),
    ];

    let mut ran = 0;
    for c in &callers {
        for presigned in [false, true] {
            // A presigned URL signs no header beside `host`.
            if presigned && c.twist == Twist::RefusedHeader {
                continue;
            }
            let how = format!(
                "{} ({}, {maintenance:?})",
                c.name,
                if presigned { "presigned" } else { "header" }
            );
            let object = path(c.bucket, "k");
            let get = rig
                .send(request(&rig, c, presigned, Method::Get, &object, &[], &[]))
                .await;
            let head = rig
                .send(request(&rig, c, presigned, Method::Head, &object, &[], &[]))
                .await;
            // A range is signed; a presigned URL signs `host` alone.
            let range: &[(&str, &str)] = match presigned {
                true => &[],
                false => &[("range", "bytes=4-9")],
            };
            let ranged = rig
                .send(request(
                    &rig,
                    c,
                    presigned,
                    Method::Get,
                    &object,
                    &[],
                    range,
                ))
                .await;
            // The same caller on the single reads.
            let reference = rig
                .send(request(
                    &rig,
                    c,
                    presigned,
                    Method::Get,
                    &format!("/{}", c.bucket),
                    &[("location", "")],
                    &[],
                ))
                .await;
            match c.refused {
                None => {
                    assert_eq!(get.status, 200, "{how}");
                    assert_eq!(get.body, body, "{how}");
                    assert_eq!(head.status, 200, "{how}");
                    match presigned {
                        true => assert_eq!(ranged.body, body, "{how}"),
                        false => {
                            assert_eq!(ranged.status, 206, "{how}");
                            assert_eq!(ranged.body, &body[4..10], "{how}");
                        }
                    }
                    assert_eq!(reference.status, 200, "{how}");
                }
                Some((status, code)) => {
                    assert_eq!(get.status, status, "{how}");
                    if !code.is_empty() {
                        assert_eq!(get.code(), code, "{how}");
                    }
                    assert_ne!(get.body, body, "{how}");
                    // The answer of the single reads, to the letter.
                    assert_eq!(
                        (get.status, get.code(), get.message()),
                        (reference.status, reference.code(), reference.message()),
                        "{how}"
                    );
                    assert_eq!(
                        (ranged.status, ranged.code(), ranged.message()),
                        (reference.status, reference.code(), reference.message()),
                        "{how}: range"
                    );
                    assert_eq!(head.status, status, "{how}: HEAD");
                    assert!(head.body.is_empty(), "{how}: HEAD");
                    assert!(head.header("etag").is_none(), "{how}: HEAD");
                    assert!(get.header("etag").is_none(), "{how}");
                }
            }
            ran += 1;
        }
    }
    assert_eq!(ran, callers.len() * 2 - 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_read_is_judged_as_every_other_request() {
    judged_alike(Maintenance::Off).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_read_under_maintenance_is_judged_as_every_other_request() {
    judged_alike(Maintenance::Restore).await;
}

/// Under maintenance the record of a revocation is the authority on a
/// key. A read that cannot ask the catalogue, or cannot ask for that
/// record, is answered 500 and nothing of the object: it is not judged
/// without it.
#[tokio::test(flavor = "current_thread")]
async fn a_read_that_cannot_ask_fails_closed() {
    let mut rig = rig();
    let (_, rw) = rig.standard(BUCKET).await;
    rig.put(&rw, BUCKET, "k", b"the stored body")
        .await
        .expect(200);
    std::rc::Rc::get_mut(&mut rig.bridge)
        .expect("no request is in flight")
        .cfg
        .maintenance = Maintenance::Restore;
    let object = path(BUCKET, "k");
    // What a served read asks before it is admitted: the catalogue
    // (the first call), then the safety store for the record.
    for skip in 0..2 {
        for presigned in [false, true] {
            for head in [false, true] {
                let how = format!("call {skip}, presigned {presigned}, head {head}");
                let method = if head { Method::Head } else { Method::Get };
                let req = match presigned {
                    true => presign(&rw, rig.now(), method, &object, &[]),
                    false => rw.sign(rig.now(), method, &object, &[], &[], Vec::new()),
                };
                rig.trip().arm(skip, Trip::Fail);
                let resp = rig.send(req).await;
                assert!(rig.trip().tripped(), "{how}");
                assert_eq!(resp.status, 500, "{how}");
                assert!(resp.header("etag").is_none(), "{how}");
                assert!(resp.header("content-range").is_none(), "{how}");
                match head {
                    true => assert!(resp.body.is_empty(), "{how}"),
                    false => assert_eq!(resp.code(), "InternalError", "{how}"),
                }
            }
        }
    }
    // The same read with nothing in its way is served.
    rig.trip().disarm();
    let resp = rig.call(&rw, Method::Get, &object, &[], &[], b"").await;
    assert_eq!(resp.expect(200).body, b"the stored body");
}

/// The refusals that name their cause say the same on a read: the
/// region to use, and the style of addressing.
#[tokio::test(flavor = "current_thread")]
async fn a_read_is_told_what_it_is_refused_for() {
    let rig = rig();
    let (_, rw) = rig.standard(BUCKET).await;
    rig.put(&rw, BUCKET, "k", b"payload").await.expect(200);
    let object = path(BUCKET, "k");
    let west = Signer {
        region: "us-west-2".to_owned(),
        ..rw.clone()
    };

    let resp = rig.call(&west, Method::Get, &object, &[], &[], b"").await;
    resp.expect_error(400, "AuthorizationHeaderMalformed");
    assert_eq!(resp.values("Region"), [REGION]);
    assert!(resp.message().contains("us-west-2"));
    let resp = rig
        .send(presign(&west, rig.now(), Method::Get, &object, &[]))
        .await;
    resp.expect_error(400, "AuthorizationQueryParametersError");
    assert_eq!(resp.values("Region"), [REGION]);

    // The aliases of the region sign a read as well.
    for region in ["us-east-1", "auto"] {
        let alias = Signer {
            region: region.to_owned(),
            ..rw.clone()
        };
        rig.call(&alias, Method::Get, &object, &[], &[], b"")
            .await
            .expect(200);
        rig.send(presign(&alias, rig.now(), Method::Get, &object, &[]))
            .await
            .expect(200);
    }

    let mut req = rw.sign(rig.now(), Method::Get, &object, &[], &[], Vec::new());
    req.set_header("host", &format!("{BUCKET}.{HOST}"));
    let resp = rig.send(req).await;
    resp.expect_error(400, "InvalidRequest");
    assert!(resp.message().starts_with("Virtual-hosted-style requests"));
    // The host is judged before the path: on a virtual-hosted request
    // the first segment is a key, not a bucket name.
    let mut req = rw.sign(
        rig.now(),
        Method::Get,
        "/Photos/image.jpg",
        &[],
        &[],
        Vec::new(),
    );
    req.set_header("host", &format!("{BUCKET}.{HOST}"));
    let resp = rig.send(req).await;
    resp.expect_error(400, "InvalidRequest");
    assert!(resp.message().starts_with("Virtual-hosted-style requests"));

    // A range the signature does not cover is not acted on.
    let mut req = rw.sign(rig.now(), Method::Get, &object, &[], &[], Vec::new());
    req.headers.push(("range".into(), "bytes=0-2".into()));
    rig.send(req).await.expect_error(403, "AccessDenied");
    let mut req = presign(&rw, rig.now(), Method::Get, &object, &[]);
    req.headers.push(("range".into(), "bytes=0-2".into()));
    rig.send(req).await.expect_error(403, "AccessDenied");

    let resp = rig
        .call(
            &rw,
            Method::Get,
            &object,
            &[],
            &[("x-amz-tagging", "a=b")],
            b"",
        )
        .await;
    resp.expect_error(501, "NotImplemented");
    assert_eq!(resp.values("Header"), ["x-amz-tagging"]);
}

/// A chunked upload is admitted by its request signature, the seed of
/// the chunk signatures; what it stored is read back by a signed header
/// and by a presigned URL. Signed with another secret it stores nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_chunked_upload_is_signed_and_read_back() {
    let rig = rig();
    let (_, rw) = rig.standard(BUCKET).await;
    let wrong = Signer::new(&rw.akid, &another_secret());
    let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let decoded = data.len().to_string();
    let chunked = |signer: &Signer, key: &str| {
        let (mut req, seed) = signer.sign_as(
            rig.now(),
            Method::Put,
            &path(BUCKET, key),
            &[],
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", decoded.as_str()),
            ],
            Vec::new(),
            Some(STREAMING),
        );
        let wire = signer.signed_chunks(rig.now(), &seed, &data, CHUNK, None);
        req.set_header("content-length", &wire.len().to_string());
        req.body = wire;
        req
    };

    let get = |signer: &Signer, key: &str| {
        let req = signer.sign(
            rig.now(),
            Method::Get,
            &path(BUCKET, key),
            &[],
            &[],
            Vec::new(),
        );
        rig.send(req)
    };

    rig.send(chunked(&wrong, "refused"))
        .await
        .expect_error(403, "SignatureDoesNotMatch");
    get(&rw, "refused").await.expect_error(404, "NoSuchKey");

    rig.send(chunked(&rw, "stored")).await.expect(200);
    let object = path(BUCKET, "stored");
    let by_header = get(&rw, "stored").await;
    assert_eq!(by_header.expect(200).body, data);
    let by_url = rig
        .send(presign(&rw, rig.now(), Method::Get, &object, &[]))
        .await;
    assert_eq!(by_url.expect(200).body, data);
    // The same reads with another secret.
    get(&wrong, "stored")
        .await
        .expect_error(403, "SignatureDoesNotMatch");
    rig.send(presign(&wrong, rig.now(), Method::Get, &object, &[]))
        .await
        .expect_error(403, "SignatureDoesNotMatch");
}
