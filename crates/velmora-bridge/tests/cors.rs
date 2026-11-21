mod service_support;

use std::rc::Rc;

use service_support::*;
use velmora_bridge::{fanout::INTERNAL_TARGET, ingress, Method};

const ORIGIN: &str = "https://console.example.app";
const OTHER: &str = "https://other.example.app";
const EXPOSE: &str = "ETag, x-amz-request-id, Content-Range, Accept-Ranges";
const BUCKET: &str = "browser-media";
const TARGET: &str = "/browser-media/video";

fn cors_rig() -> Rig {
    let mut cfg = config(vec![]);
    cfg.cors_origins = vec![ORIGIN.into()];
    rig_with(NoNntp, cfg)
}

fn req(method: &str, target: &str, headers: &[(&str, &str)]) -> Req {
    let mut req = Req {
        method: Method::parse(method),
        target: target.into(),
        headers: vec![("host".into(), HOST.into())],
        body: Vec::new(),
    };
    for (name, value) in headers {
        req.set_header(name, value);
    }
    req
}

async fn fetch(rig: &Rig, req: Req) -> Resp {
    Resp::collect(
        ingress::front(req.into_request(), &rig.bridge.cfg, true, |req| {
            Rc::clone(&rig.bridge).handle(req)
        })
        .await
        .with_request_id("test-ray"),
    )
    .await
}

fn assert_no_cors(resp: &Resp) {
    assert!(!resp
        .headers
        .iter()
        .any(|(name, _)| name.starts_with("access-control-")));
    assert_eq!(resp.header("vary"), None);
}

fn assert_actual_cors(resp: &Resp) {
    assert_eq!(resp.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(resp.header("access-control-expose-headers"), Some(EXPOSE));
    assert_eq!(resp.header("vary"), Some("Origin"));
    assert_eq!(resp.header("access-control-allow-credentials"), None);
    assert_eq!(resp.header("access-control-allow-methods"), None);
    assert_eq!(resp.header("x-amz-request-id"), Some("test-ray"));
}

#[tokio::test(flavor = "current_thread")]
async fn preflight_bypasses_auth_and_storage() {
    let rig = cors_rig();
    let calls = rig.trip().calls();
    rig.trip().arm(0, Trip::Fail);
    let resp = fetch(
        &rig,
        req(
            "OPTIONS",
            TARGET,
            &[
                ("origin", ORIGIN),
                ("access-control-request-method", "GET"),
                ("access-control-request-headers", "Range, X-Amz-Date"),
            ],
        ),
    )
    .await;
    resp.expect(200);
    assert!(resp.body.is_empty());
    assert_eq!(resp.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(resp.header("access-control-expose-headers"), Some(EXPOSE));
    assert_eq!(
        resp.header("access-control-allow-methods"),
        Some("GET, HEAD, PUT, POST, DELETE")
    );
    assert_eq!(
        resp.header("access-control-allow-headers"),
        Some("range, x-amz-date")
    );
    assert_eq!(resp.header("access-control-max-age"), Some("600"));
    assert_eq!(
        resp.header("vary"),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );
    assert_eq!(resp.header("access-control-allow-credentials"), None);
    assert_eq!(rig.trip().calls(), calls);
    assert!(!rig.trip().tripped());
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_preflights_are_refused_without_cors_headers() {
    let rig = cors_rig();
    let too_many = ["Range"; 33].join(", ");
    for (origin, method, headers) in [
        (Some(OTHER), Some("GET"), None),
        (None, Some("GET"), None),
        (Some(ORIGIN), Some("PATCH"), None),
        (Some(ORIGIN), None, None),
        (Some(ORIGIN), Some("GET"), Some("Range, bad_header")),
        (Some(ORIGIN), Some("GET"), Some(too_many.as_str())),
    ] {
        let mut req = req("OPTIONS", TARGET, &[]);
        for (name, value) in [
            ("origin", origin),
            ("access-control-request-method", method),
            ("access-control-request-headers", headers),
        ] {
            if let Some(value) = value {
                req.set_header(name, value);
            }
        }
        let resp = fetch(&rig, req).await;
        resp.expect_error(403, "AccessForbidden");
        assert_eq!(
            resp.message(),
            "CORSResponse: This CORS request is not allowed."
        );
        assert_no_cors(&resp);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn admin_and_internal_targets_keep_their_own_responses() {
    let rig = cors_rig();
    for target in ["/_admin", "/_admin/status", INTERNAL_TARGET] {
        for method in ["OPTIONS", "GET"] {
            let resp = fetch(
                &rig,
                req(
                    method,
                    target,
                    &[("origin", ORIGIN), ("access-control-request-method", "GET")],
                ),
            )
            .await;
            assert_ne!(resp.status, 200);
            assert_ne!(resp.code(), "AccessForbidden");
            assert_no_cors(&resp);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn actual_s3_responses_include_cors_only_for_listed_origins() {
    let rig = cors_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "video", b"media")
        .await
        .expect(200);

    for origin in [Some(ORIGIN), Some(OTHER), None] {
        let mut req = signer.sign(rig.now(), Method::Get, TARGET, &[], &[], Vec::new());
        if let Some(origin) = origin {
            req.set_header("origin", origin);
        }
        let resp = fetch(&rig, req).await;
        resp.expect(200);
        assert_eq!(resp.body, b"media");
        if origin == Some(ORIGIN) {
            assert_actual_cors(&resp);
        } else {
            assert_no_cors(&resp);
        }
    }

    let resp = fetch(&rig, req("GET", TARGET, &[("origin", ORIGIN)])).await;
    resp.expect_error(403, "AccessDenied");
    assert_actual_cors(&resp);

    let mut invalid = signer.sign(rig.now(), Method::Get, TARGET, &[], &[], Vec::new());
    invalid.set_header("origin", ORIGIN);
    invalid.set_header("range", "bytes=0-1");
    let resp = fetch(&rig, invalid).await;
    resp.expect_error(403, "AccessDenied");
    assert_actual_cors(&resp);
}

#[tokio::test(flavor = "current_thread")]
async fn empty_list_keeps_existing_options_and_get_behavior() {
    let rig = rig();
    let resp = fetch(
        &rig,
        req(
            "OPTIONS",
            TARGET,
            &[("origin", ORIGIN), ("access-control-request-method", "GET")],
        ),
    )
    .await;
    resp.expect_error(403, "AccessDenied");
    assert_no_cors(&resp);

    let (_, signer) = rig.standard(BUCKET).await;
    let mut options = signer.sign(
        rig.now(),
        Method::parse("OPTIONS"),
        TARGET,
        &[],
        &[],
        Vec::new(),
    );
    options.set_header("origin", ORIGIN);
    let resp = fetch(&rig, options).await;
    resp.expect_error(501, "NotImplemented");
    assert_no_cors(&resp);

    rig.put(&signer, BUCKET, "video", b"media")
        .await
        .expect(200);
    let mut get = signer.sign(rig.now(), Method::Get, TARGET, &[], &[], Vec::new());
    get.set_header("origin", ORIGIN);
    let resp = fetch(&rig, get).await;
    resp.expect(200);
    assert_no_cors(&resp);
}
