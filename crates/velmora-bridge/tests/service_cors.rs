//! Bucket CORS through the real S3 router and SQL catalogue.
#[path = "service_support/cors_clients.rs"]
mod cors_clients;
mod service_support;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use service_support::*;
use std::cell::Cell;
use std::rc::Rc;
use velmora_bridge::*;

fn cors_rig() -> Rig {
    let mut rig = rig_selected();
    Rc::get_mut(&mut rig.bridge)
        .unwrap()
        .catalog
        .enable_bucket_cors()
        .unwrap();
    rig
}

const BUCKET: &str = "/cors-test";
const OBJECT: &str = "/cors-test/missing";
const ORIGIN: &str = "https://app.example.test";
const DOC: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <CORSRule><ID>browser</ID><AllowedOrigin>https://*.example.test</AllowedOrigin>
    <AllowedMethod>PUT</AllowedMethod><AllowedMethod>GET</AllowedMethod>
    <AllowedHeader>x-amz-*</AllowedHeader><AllowedHeader>content-type</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>600</MaxAgeSeconds></CORSRule>
  <CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule>
</CORSConfiguration>"#;

async fn put_doc(rig: &Rig, signer: &Signer) -> Resp {
    let md5 = STANDARD.encode(md5::compute(DOC).0);
    rig.call(
        signer,
        Method::Put,
        BUCKET,
        &[("cors", "")],
        &[("content-md5", &md5)],
        DOC,
    )
    .await
}

fn preflight(path: &str, origin: &str, method: &str, headers: &str) -> Req {
    Req {
        method: Method::Other("OPTIONS".into()),
        target: path.into(),
        headers: vec![
            ("host".into(), HOST.into()),
            ("origin".into(), origin.into()),
            ("access-control-request-method".into(), method.into()),
            ("access-control-request-headers".into(), headers.into()),
        ],
        body: vec![],
    }
}

#[tokio::test(flavor = "current_thread")]
async fn bucket_cors_requires_signature_and_bucket_permission() {
    let rig = cors_rig();
    let (bucket, signer) = rig.standard(&BUCKET[1..]).await;
    let ungranted = rig
        .key("AKIDCORSUNGRANTED01", secret(), KeyStatus::Active)
        .await;
    let read_only = rig
        .key("AKIDCORSREADONLY001", secret(), KeyStatus::Active)
        .await;
    rig.grant("AKIDCORSREADONLY001", &bucket, Perm::Ro).await;
    for method in [Method::Get, Method::Put, Method::Delete] {
        let body = if method == Method::Put { DOC } else { b"" };
        let mut req = signer.sign(
            rig.now(),
            method.clone(),
            BUCKET,
            &[("cors", "")],
            &[],
            body.to_vec(),
        );
        req.headers.retain(|(name, _)| name != "authorization");
        let resp = rig.send(req).await;
        assert_eq!(resp.status, 403, "unsigned {method:?}: {}", resp.text());
        let resp = rig
            .call(
                &ungranted,
                method.clone(),
                BUCKET,
                &[("cors", "")],
                &[],
                body,
            )
            .await;
        assert_eq!(resp.status, 404, "ungranted {method:?}: {}", resp.text());
        assert!(resp.text().contains("<Code>NoSuchBucket</Code>"));
        if method != Method::Get {
            let resp = rig
                .call(
                    &read_only,
                    method.clone(),
                    BUCKET,
                    &[("cors", "")],
                    &[],
                    body,
                )
                .await;
            assert_eq!(resp.status, 403, "read-only {method:?}: {}", resp.text());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn put_cors_requires_and_verifies_a_body_checksum() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    for (headers, code) in [
        (&[][..], "InvalidRequest"),
        (
            &[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")][..],
            "BadDigest",
        ),
    ] {
        let refused = rig
            .call(&signer, Method::Put, BUCKET, &[("cors", "")], headers, DOC)
            .await;
        assert_eq!(refused.status, 400, "{}", refused.text());
        assert!(refused.text().contains(&format!("<Code>{code}</Code>")));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn preflight_missing_config_and_unknown_bucket_are_indistinguishable() {
    let rig = cors_rig();
    rig.standard(&BUCKET[1..]).await;
    let no_config = rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await;
    assert_eq!(no_config.status, 403, "{}", no_config.text());
    let unknown = rig
        .send(preflight("/unknown-bucket/missing", ORIGIN, "PUT", ""))
        .await;
    assert_eq!(unknown.status, no_config.status);
    assert_eq!(unknown.headers, no_config.headers);
    assert_eq!(unknown.body, no_config.body);
}

#[tokio::test(flavor = "current_thread")]
async fn bucket_cors_roundtrips_and_applies_to_preflight_and_actual_responses() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    let cors = &[("cors", "")];
    let absent = rig.call(&signer, Method::Get, BUCKET, cors, &[], b"").await;
    assert_eq!(absent.status, 404, "{}", absent.text());
    assert!(absent
        .text()
        .contains("<Code>NoSuchCORSConfiguration</Code>"));
    let put = put_doc(&rig, &signer).await;
    assert_eq!(put.status, 200, "{}", put.text());
    let get = rig.call(&signer, Method::Get, BUCKET, cors, &[], b"").await;
    assert_eq!(get.status, 200, "{}", get.text());
    assert!(get.text().contains("<ID>browser</ID>"));

    for path in [BUCKET, OBJECT] {
        let ok = rig
            .send(preflight(path, ORIGIN, "PUT", "X-Amz-Date, Content-Type"))
            .await;
        assert_eq!(ok.status, 200, "{}", ok.text());
        assert_eq!(ok.header("access-control-allow-origin"), Some(ORIGIN));
        assert_eq!(ok.header("access-control-allow-credentials"), Some("true"));
        assert_eq!(ok.header("access-control-allow-methods"), Some("PUT, GET"));
        assert_eq!(
            ok.header("access-control-allow-headers"),
            Some("X-Amz-Date, Content-Type")
        );
        assert_eq!(ok.header("access-control-max-age"), Some("600"));
        assert_eq!(
            ok.header("vary"),
            Some("Origin, Access-Control-Request-Headers, Access-Control-Request-Method")
        );
        assert!(ok.body.is_empty());
    }
    for (origin, method, headers) in [
        ("https://wrong.test", "PUT", ""),
        (ORIGIN, "put", ""),
        (ORIGIN, "PUT", "age"),
    ] {
        let refused = rig.send(preflight(OBJECT, origin, method, headers)).await;
        assert_eq!(refused.status, 403, "{}", refused.text());
        assert!(refused.header("access-control-allow-origin").is_none());
    }
    let plain = rig.call(&signer, Method::Get, OBJECT, &[], &[], b"").await;
    let actual = rig
        .call(
            &signer,
            Method::Get,
            OBJECT,
            &[],
            &[("origin", ORIGIN)],
            b"",
        )
        .await;
    assert_eq!(
        (actual.status, actual.body.as_slice()),
        (plain.status, plain.body.as_slice())
    );
    assert_eq!(actual.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(actual.header("access-control-expose-headers"), Some("ETag"));
    assert_eq!(
        actual.header("access-control-allow-credentials"),
        Some("true")
    );
    assert_eq!(actual.header("vary"), Some("Origin"));
    assert!(plain.header("access-control-allow-origin").is_none());
    let public = rig
        .send(preflight(OBJECT, "https://wrong.test", "GET", ""))
        .await;
    assert_eq!(public.header("access-control-allow-origin"), Some("*"));
    assert!(public.header("access-control-allow-credentials").is_none());
    let public_actual = rig
        .call(
            &signer,
            Method::Get,
            OBJECT,
            &[],
            &[("origin", "https://wrong.test")],
            b"",
        )
        .await;
    assert_eq!(
        public_actual.header("access-control-allow-origin"),
        Some("*")
    );
    assert!(public_actual
        .header("access-control-allow-credentials")
        .is_none());
    let mut unsigned = signer.sign(
        rig.now(),
        Method::Get,
        OBJECT,
        &[],
        &[("origin", ORIGIN)],
        vec![],
    );
    unsigned.headers.retain(|(name, _)| name != "authorization");
    assert_eq!(rig.send(unsigned).await.status, 403);

    let deleted = rig
        .call(&signer, Method::Delete, BUCKET, cors, &[], b"")
        .await;
    assert_eq!(deleted.status, 204, "{}", deleted.text());
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        403
    );
}

#[tokio::test(flavor = "current_thread")]
async fn preflight_ignores_object_existence_and_presigned_reads_still_verify() {
    const PRESENT: &str = "/cors-test/present";
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    let written = rig
        .call(&signer, Method::Put, PRESENT, &[], &[], b"object body")
        .await;
    assert_eq!(written.status, 200, "{}", written.text());
    let present = rig.send(preflight(PRESENT, ORIGIN, "GET", "")).await;
    let absent = rig.send(preflight(OBJECT, ORIGIN, "GET", "")).await;
    assert_eq!(present.status, 200);
    assert_eq!(
        (present.status, present.headers, present.body),
        (absent.status, absent.headers, absent.body)
    );
    let mut request = presign(&signer, rig.now(), PRESENT);
    request.set_header("origin", ORIGIN);
    let valid = rig.send(request).await;
    assert_eq!(valid.status, 200, "{}", valid.text());
    assert_eq!(valid.body, b"object body");
    assert_eq!(valid.header("access-control-allow-origin"), Some(ORIGIN));
    let mut request = presign(&signer, rig.now(), PRESENT);
    request.set_header("origin", ORIGIN);
    let last = request.target.pop().unwrap();
    request.target.push(if last == '0' { '1' } else { '0' });
    let refused = rig.send(request).await;
    assert_eq!(refused.status, 403, "{}", refused.text());
    assert_eq!(refused.header("access-control-allow-origin"), Some(ORIGIN));
    assert!(!refused.text().contains("object body"));
}

#[tokio::test(flavor = "current_thread")]
async fn no_origin_makes_zero_cors_reads_and_preserves_options_refusal() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    let plain = rig.call(&signer, Method::Get, OBJECT, &[], &[], b"").await;
    assert_eq!(plain.status, 404);
    assert!(plain.header("vary").is_none());
    let mut options = preflight(OBJECT, ORIGIN, "PUT", "");
    options.headers.retain(|(h, _)| h != "origin");
    assert_eq!(rig.send(options).await.status, 501);
    assert_eq!(rig.bridge.catalog.sql.cors_queries.get(), 0);
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        200
    );
    assert_eq!(rig.bridge.catalog.sql.cors_queries.get(), 1);
    let actual = rig
        .call(
            &signer,
            Method::Get,
            OBJECT,
            &[],
            &[("origin", ORIGIN)],
            b"",
        )
        .await;
    assert_eq!(actual.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(
        rig.bridge.catalog.sql.cors_queries.get(),
        1,
        "cache is shared with actual requests"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn negative_preflights_cache_unknown_buckets_and_missing_configs() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    let calls = || rig.bridge.catalog.sql.cors_queries.get();
    for (path, expected) in [("/unknown-bucket/key", 1), (OBJECT, 2)] {
        assert_eq!(
            rig.send(preflight(path, ORIGIN, "PUT", "")).await.status,
            403
        );
        assert_eq!(calls(), expected);
        assert_eq!(
            rig.send(preflight(path, ORIGIN, "PUT", "")).await.status,
            403
        );
        assert_eq!(calls(), expected);
    }
    rig.bridge.clock.advance_ms(59_999);
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        403
    );
    assert_eq!(calls(), 2);
    rig.bridge.clock.advance_ms(1);
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        403
    );
    assert_eq!(calls(), 3);
    // A fresh negative entry must not mask a Put in the same isolate.
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        200
    );
    assert_eq!(calls(), 4);
}

async fn through_front(rig: &Rig, req: S3Request, https: bool) -> (Resp, bool) {
    let entered = Cell::new(false);
    let resp = ingress::front_with_bucket_cors(req, &rig.bridge, https, |req| {
        entered.set(true);
        Rc::clone(&rig.bridge).handle(req)
    })
    .await;
    (Resp::collect(resp).await, entered.get())
}

#[tokio::test(flavor = "current_thread")]
async fn ingress_put_refusals_carry_cors_for_a_matching_origin() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    let too_large = (rig.bridge.cfg.max_put_bytes + 1).to_string();
    for (length, status, code) in [
        (Some(too_large.as_str()), 400, "EntityTooLarge"),
        (None, 411, "MissingContentLength"),
    ] {
        let make_request = |origin| {
            let mut req = signer.sign(rig.now(), Method::Put, OBJECT, &[], &[], vec![]);
            req.headers.retain(|(name, _)| name != "content-length");
            if let Some(length) = length {
                req.set_header("content-length", length);
            }
            if let Some(origin) = origin {
                req.set_header("origin", origin);
            }
            req.into_request()
        };
        let before = rig.bridge.catalog.sql.cors_queries.get();
        let (plain, entered) = through_front(&rig, make_request(None), true).await;
        assert_eq!(rig.bridge.catalog.sql.cors_queries.get(), before);
        assert!(!entered);
        assert_eq!(plain.status, status, "{}", plain.text());
        assert!(plain.text().contains(&format!("<Code>{code}</Code>")));
        assert!(plain.header("access-control-allow-origin").is_none());
        let (matched, entered) = through_front(&rig, make_request(Some(ORIGIN)), true).await;
        assert!(!entered);
        assert_eq!(
            (matched.status, matched.body.as_slice()),
            (plain.status, plain.body.as_slice())
        );
        assert_eq!(matched.header("access-control-allow-origin"), Some(ORIGIN));
        assert_eq!(
            matched.header("access-control-expose-headers"),
            Some("ETag")
        );
        assert_eq!(matched.header("vary"), Some("Origin"));
        let (unmatched, entered) =
            through_front(&rig, make_request(Some("https://wrong.test")), true).await;
        assert!(!entered);
        assert_eq!(unmatched.status, status);
        assert!(unmatched.header("access-control-allow-origin").is_none());
        let (insecure, entered) = through_front(&rig, make_request(Some(ORIGIN)), false).await;
        assert!(!entered);
        assert_eq!(insecure.status, 403);
        assert!(insecure.header("access-control-allow-origin").is_none());
    }
    let mut unsigned = signer.sign(
        rig.now(),
        Method::Put,
        OBJECT,
        &[],
        &[("origin", ORIGIN)],
        vec![],
    );
    unsigned.headers.retain(|(name, _)| name != "authorization");
    let (refused, entered) = through_front(&rig, unsigned.into_request(), true).await;
    assert!(!entered);
    assert_eq!(refused.status, 403);
    assert!(refused.text().contains("<Code>AccessDenied</Code>"));
    assert_eq!(refused.header("access-control-allow-origin"), Some(ORIGIN));
}

#[tokio::test(flavor = "current_thread")]
async fn only_valid_enabled_preflight_passes_unsigned_ingress() {
    const EXTRA: &str = "cors-extra.test";
    let mut rig = cors_rig();
    Rc::get_mut(&mut rig.bridge)
        .unwrap()
        .cfg
        .s3_hosts
        .push(config::S3Host {
            name: EXTRA.into(),
            class: config::HostClass::Customer,
        });
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    let options = || preflight(OBJECT, ORIGIN, "PUT", "").into_request();
    for host in [HOST, EXTRA] {
        let mut req = preflight(OBJECT, ORIGIN, "PUT", "");
        req.set_header("host", host);
        let (ok, entered) = through_front(&rig, req.into_request(), true).await;
        assert_eq!(ok.status, 200, "{host}: {}", ok.text());
        assert!(entered);
        assert_eq!(ok.header("access-control-allow-origin"), Some(ORIGIN));
    }

    let mut missing_method = options();
    missing_method
        .headers
        .retain(|(name, _)| name != "access-control-request-method");
    let mut missing_origin = options();
    missing_origin.headers.retain(|(name, _)| name != "origin");
    let mut body = options();
    body.body = Body::Stream {
        declared_len: None,
        stream: Box::pin(futures_util::stream::iter([Ok(vec![1])])),
    };
    let mut length = options();
    length.headers.push(("content-length".into(), "1".into()));
    let mut other_host = preflight(OBJECT, ORIGIN, "PUT", "");
    other_host.set_header("host", "not-s3.test");
    let mut refused = vec![
        missing_method,
        missing_origin,
        body,
        length,
        other_host.into_request(),
    ];
    for path in ["/", "/ab/key", "//key"] {
        refused.push(preflight(path, ORIGIN, "PUT", "").into_request());
    }
    for method in [
        Method::Get,
        Method::Put,
        Method::Post,
        Method::Delete,
        Method::Head,
        Method::Other("PATCH".into()),
    ] {
        let mut req = options();
        req.method = method;
        refused.push(req);
    }
    for req in refused {
        let (resp, entered) = through_front(&rig, req, true).await;
        assert_eq!(resp.status, 403, "{}", resp.text());
        assert!(!entered, "an unsigned non-preflight reached the router");
    }
    let admin = preflight("/_admin/status", ORIGIN, "PUT", "").into_request();
    let (resp, entered) = through_front(&rig, admin, true).await;
    assert_eq!(resp.status, 401, "{}", resp.text());
    assert!(!entered);
    let (_, entered) = through_front(&rig, options(), false).await;
    assert!(!entered, "transport still must be HTTPS");
    let (off, entered) = through_front(&rig_selected(), options(), true).await;
    assert_eq!(off.status, 403);
    assert!(!entered);
}

const MALFORMED_ORIGINS: [&str; 2] = [
    "https://evil.test, https://x.example.test",
    "https://bad origin.example.test",
];

#[tokio::test(flavor = "current_thread")]
async fn preflight_wildcard_never_echoes_malformed_origins() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    for origin in MALFORMED_ORIGINS {
        let refused = rig.send(preflight(OBJECT, origin, "PUT", "")).await;
        assert_eq!(refused.status, 403, "{}", refused.text());
        assert!(refused.header("access-control-allow-origin").is_none());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn actual_wildcard_never_echoes_malformed_origins() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    for origin in MALFORMED_ORIGINS {
        let actual = rig
            .call(
                &signer,
                Method::Get,
                OBJECT,
                &[],
                &[("origin", origin)],
                b"",
            )
            .await;
        assert!(actual.header("access-control-allow-origin").is_none());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn wildcard_request_headers_still_require_http_tokens() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    let refused = rig
        .send(preflight(OBJECT, ORIGIN, "PUT", "x-amz-bad header"))
        .await;
    assert_eq!(refused.status, 403, "{}", refused.text());
    assert!(refused.header("access-control-allow-headers").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn put_cors_obeys_mutation_gates() {
    let mut rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    let md5 = STANDARD.encode(md5::compute(DOC).0);
    let conditional = rig
        .call(
            &signer,
            Method::Put,
            BUCKET,
            &[("cors", "")],
            &[("content-md5", &md5), ("if-match", "*")],
            DOC,
        )
        .await;
    assert_eq!(conditional.status, 501, "{}", conditional.text());
    Rc::get_mut(&mut rig.bridge).unwrap().cfg.maintenance = config::Maintenance::Restore;
    let maintenance = put_doc(&rig, &signer).await;
    assert_eq!(maintenance.status, 503, "{}", maintenance.text());
}

#[tokio::test(flavor = "current_thread")]
async fn put_cors_refuses_pending_replay_before_reading_body() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    rig.bridge
        .catalog
        .sql
        .inner
        .fixture_script(
            "INSERT INTO restore_state(id,state,since_ms,started_at) VALUES (1,'replaying',0,1)",
        )
        .unwrap();
    let md5 = STANDARD.encode(md5::compute(DOC).0);
    let mut req = signer
        .sign(
            rig.now(),
            Method::Put,
            BUCKET,
            &[("cors", "")],
            &[("content-md5", &md5)],
            DOC.to_vec(),
        )
        .into_request();
    req.body = Body::Stream {
        declared_len: Some(DOC.len() as u64),
        stream: Box::pin(futures_util::stream::poll_fn(|_| {
            panic!("read body while replay is pending")
        })),
    };
    let resp = Resp::collect(Rc::clone(&rig.bridge).handle(req).await).await;
    assert_eq!(resp.status, 503, "{}", resp.text());
}

#[tokio::test(flavor = "current_thread")]
async fn put_cors_cannot_leave_a_row_if_bucket_deletion_wins_after_auth() {
    let rig = cors_rig();
    let (bucket, signer) = rig.standard(&BUCKET[1..]).await;
    let id = bucket.id.as_str();
    let delete = format!(
        "DELETE FROM grants WHERE bucket_id = '{id}'; DELETE FROM buckets WHERE id = '{id}';"
    );
    let md5 = STANDARD.encode(md5::compute(DOC).0);
    let mut req = signer
        .sign(
            rig.now(),
            Method::Put,
            BUCKET,
            &[("cors", "")],
            &[("content-md5", &md5)],
            DOC.to_vec(),
        )
        .into_request();
    let bridge = Rc::clone(&rig.bridge);
    req.body = Body::Stream {
        declared_len: Some(DOC.len() as u64),
        stream: Box::pin(futures_util::stream::once(async move {
            bridge.catalog.sql.inner.fixture_script(&delete).unwrap();
            Ok(DOC.to_vec())
        })),
    };
    let resp = Resp::collect(Rc::clone(&rig.bridge).handle(req).await).await;
    assert_eq!(resp.status, 404, "{}", resp.text());
    assert!(resp.text().contains("<Code>NoSuchBucket</Code>"));
    assert!(rig
        .bridge
        .catalog
        .bucket_cors(&bucket.id)
        .await
        .unwrap()
        .is_none());
}

fn admin_request(rig: &Rig, method: Method) -> Req {
    Req {
        method,
        target: BUCKET.into(),
        headers: vec![
            ("host".into(), HOST.into()),
            (
                "authorization".into(),
                format!("Bearer {}", rig.bridge.cfg.admin_token.expose()),
            ),
        ],
        body: vec![],
    }
}

#[tokio::test(flavor = "current_thread")]
async fn admin_delete_with_cors_off_does_not_need_the_new_table() {
    let rig = rig_selected();
    rig.bucket(&BUCKET[1..], true).await;
    rig.bridge
        .catalog
        .sql
        .inner
        .fixture_script("DROP TABLE bucket_cors")
        .unwrap();
    let resp = rig.send(admin_request(&rig, Method::Delete)).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
}

#[tokio::test(flavor = "current_thread")]
async fn deleting_and_recreating_a_bucket_drops_its_cors_row_and_cached_rule() {
    let rig = cors_rig();
    let (old, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 200);
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        200
    );
    let deleted = rig.send(admin_request(&rig, Method::Delete)).await;
    assert_eq!(deleted.status, 204, "{}", deleted.text());
    assert!(rig
        .bridge
        .catalog
        .bucket_cors(&old.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        403
    );
    let created = rig.send(admin_request(&rig, Method::Put)).await;
    assert_eq!(created.status, 200, "{}", created.text());
    let new = rig
        .bridge
        .catalog
        .bucket_by_name(&BUCKET[1..])
        .await
        .unwrap()
        .unwrap();
    assert_ne!(new.id, old.id);
    rig.grant(AKID, &new, Perm::Rw).await;
    let cfg = rig
        .call(&signer, Method::Get, BUCKET, &[("cors", "")], &[], b"")
        .await;
    assert_eq!(cfg.status, 404, "{}", cfg.text());
    assert!(cfg.text().contains("<Code>NoSuchCORSConfiguration</Code>"));
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        403
    );
}

#[tokio::test(flavor = "current_thread")]
async fn bucket_cors_is_off_by_default() {
    let rig = rig_selected();
    let (_, signer) = rig.standard(&BUCKET[1..]).await;
    assert_eq!(put_doc(&rig, &signer).await.status, 501);
    assert_eq!(
        rig.send(preflight(OBJECT, ORIGIN, "PUT", "")).await.status,
        501
    );
    assert_eq!(rig.bridge.catalog.sql.cors_queries.get(), 0);
}
