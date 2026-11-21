use crate::config::BridgeConfig;
use crate::ingress::{header, is_admin_target};
use crate::{RespBody, S3Request, S3Response};

const EXPOSE: &str = "ETag, x-amz-request-id, Content-Range, Accept-Ranges";
const METHODS: &str = "GET, HEAD, PUT, POST, DELETE";
const PREFLIGHT_VARY: &str =
    "Origin, Access-Control-Request-Method, Access-Control-Request-Headers";

fn applies(req: &S3Request, cfg: &BridgeConfig) -> bool {
    !cfg.cors_origins.is_empty()
        && req.raw_target.starts_with('/')
        && !crate::fanout::is_internal_target(&req.raw_target)
        && !is_admin_target(&req.raw_target)
}

pub(crate) fn allowed_origin<'a>(req: &S3Request, cfg: &'a BridgeConfig) -> Option<&'a str> {
    if !applies(req, cfg) {
        return None;
    }
    let origin = header(req, "origin")?;
    cfg.cors_origins
        .iter()
        .find(|s| *s == origin)
        .map(String::as_str)
}

pub(crate) fn preflight(req: &S3Request, cfg: &BridgeConfig) -> Option<S3Response> {
    if req.method.as_str() != "OPTIONS" || !applies(req, cfg) {
        return None;
    }
    let allowed = allowed_origin(req, cfg).and_then(|origin| allow_preflight(req, origin));
    Some(allowed.unwrap_or_else(|| {
        S3Response::error(
            403,
            "AccessForbidden",
            "CORSResponse: This CORS request is not allowed.",
        )
    }))
}

fn allow_preflight(req: &S3Request, origin: &str) -> Option<S3Response> {
    let method = header(req, "access-control-request-method")?;
    if !matches!(method, "GET" | "HEAD" | "PUT" | "POST" | "DELETE") {
        return None;
    }

    let mut resp = S3Response {
        status: 200,
        body: RespBody::Empty,
        headers: vec![
            ("access-control-allow-methods".into(), METHODS.into()),
            ("access-control-max-age".into(), "600".into()),
            ("vary".into(), PREFLIGHT_VARY.into()),
        ],
    };
    // Validate all fields, including repeated header lines if the adapter
    // has kept them separate.
    let mut names = Vec::new();
    for (_, value) in req
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("access-control-request-headers"))
    {
        for name in value.split(',').map(|name| name.trim_matches([' ', '\t'])) {
            if names.len() == 32
                || !(1..=64).contains(&name.len())
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return None;
            }
            names.push(name.to_ascii_lowercase());
        }
    }
    if !names.is_empty() {
        resp.headers
            .push(("access-control-allow-headers".into(), names.join(", ")));
    }
    decorate_origin(origin, &mut resp);
    Some(resp)
}

pub(crate) fn decorate(req: &S3Request, cfg: &BridgeConfig, resp: &mut S3Response) {
    if let Some(origin) = allowed_origin(req, cfg) {
        decorate_origin(origin, resp);
    }
}

pub(crate) fn decorate_origin(origin: &str, resp: &mut S3Response) {
    resp.headers
        .push(("access-control-allow-origin".into(), origin.into()));
    resp.headers
        .push(("access-control-expose-headers".into(), EXPOSE.into()));
    let mut vary = resp
        .headers
        .iter_mut()
        .filter(|(name, _)| name.eq_ignore_ascii_case("vary"));
    if let Some((_, first)) = vary.next() {
        let includes_origin = |value: &str| {
            value
                .split(',')
                .any(|field| field.trim().eq_ignore_ascii_case("origin"))
        };
        if !includes_origin(first) && !vary.any(|(_, value)| includes_origin(value)) {
            if !first.trim().is_empty() {
                first.push_str(", ");
            }
            first.push_str("Origin");
        }
    } else {
        resp.headers.push(("vary".into(), "Origin".into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, Method};

    const ORIGIN: &str = "https://console.example.app";

    fn request(method: &str, requested_headers: Option<&str>) -> S3Request {
        let mut headers = vec![("access-control-request-method".into(), method.into())];
        if let Some(value) = requested_headers {
            headers.push(("access-control-request-headers".into(), value.into()));
        }
        S3Request {
            method: Method::parse("OPTIONS"),
            raw_target: "/bucket/key".into(),
            headers,
            body: Body::Empty,
        }
    }

    fn value<'a>(resp: &'a S3Response, name: &str) -> Option<&'a str> {
        resp.headers
            .iter()
            .find_map(|(key, val)| key.eq_ignore_ascii_case(name).then_some(val.as_str()))
    }

    #[test]
    fn preflight_accepts_supported_methods_without_requested_headers() {
        for method in ["GET", "HEAD", "PUT", "POST", "DELETE"] {
            let resp = allow_preflight(&request(method, None), ORIGIN).unwrap();
            assert_eq!(resp.status, 200);
            assert!(matches!(resp.body, RespBody::Empty));
            assert_eq!(value(&resp, "access-control-allow-headers"), None);
            assert_eq!(value(&resp, "vary"), Some(PREFLIGHT_VARY));
        }
        assert!(allow_preflight(&request("get", None), ORIGIN).is_none());
    }

    #[test]
    fn requested_header_names_are_normalized_and_bounded() {
        let longest = "X".repeat(64);
        let headers = [longest.as_str(); 32].join(", ");
        let resp = allow_preflight(&request("GET", Some(&headers)), ORIGIN).unwrap();
        assert_eq!(
            value(&resp, "access-control-allow-headers"),
            Some(headers.to_ascii_lowercase().as_str())
        );

        let too_long = "a".repeat(65);
        for invalid in ["", "Range,", "Range,,Host", "a_b", "x y", "x-é", &too_long] {
            assert!(allow_preflight(&request("GET", Some(invalid)), ORIGIN).is_none());
        }
    }

    #[test]
    fn vary_keeps_existing_fields_and_avoids_duplicate_origin() {
        for (existing, expected) in [
            ("Accept-Encoding", "Accept-Encoding, Origin"),
            ("Accept-Encoding, ORIGIN", "Accept-Encoding, ORIGIN"),
        ] {
            let mut resp = S3Response::error(403, "AccessDenied", "Denied");
            resp.headers.push(("Vary".into(), existing.into()));
            decorate_origin(ORIGIN, &mut resp);
            assert_eq!(value(&resp, "vary"), Some(expected));
            assert_eq!(value(&resp, "access-control-allow-origin"), Some(ORIGIN));
            assert_eq!(value(&resp, "access-control-expose-headers"), Some(EXPOSE));
        }
    }
}
