//! `worker::Request` -> `S3Request`, `S3Response` -> `worker::Response`.
//!
//! The raw target comes from `req.inner().url()` only, cut by
//! `ingress::origin_form`. `Request::url()` parses through `url::Url`, which
//! resolves dot segments and rewrites backslashes, so it would verify a
//! different key than the client signed; clippy bans it in this crate.
//! Header values pass through untouched, with one exception: an
//! `Accept-Encoding` the edge rewrote is replaced by the client's own value
//! from `request.cf.clientAcceptEncoding` (`ingress::restore_accept_encoding`),
//! so a client that signed it verifies. The body stays an unread stream:
//! only `ingress::read_capped` or `ingress::read_upload` reads it, after auth
//! and the budget charge.

use futures_util::StreamExt;
use velmora_bridge::ingress::{self, IngressError};
use velmora_bridge::{Body, BridgeError, Method, RespBody, S3Request, S3Response};
use worker::{FixedLengthStream, Headers, Request, Response, ResponseBody};

/// One request as the bridge sees it, plus what the edge knows about it.
pub struct Incoming {
    pub req: S3Request,
    /// From the runtime's own URL scheme, never a forwarded header.
    pub https: bool,
}

/// Builds the `S3Request` without touching the body.
pub fn to_s3_request(mut req: Request) -> Result<Incoming, IngressError> {
    let url = req.inner().url();
    let raw_target = ingress::origin_form(&url)?.to_string();
    let https = ingress::is_https(&url);
    let method = Method::parse(&req.inner().method());
    let mut headers: Vec<(String, String)> = req.headers().entries().collect();
    ingress::restore_accept_encoding(&mut headers, client_accept_encoding(&req).as_deref());
    let declared_len = ingress::declared_length(&headers).unwrap_or(None);
    let body = if req.inner().body().is_some() {
        let stream = req
            .stream()
            .map_err(|_| IngressError::Internal)?
            .map(|chunk| chunk.map_err(|_| BridgeError::Invalid("request body stream")));
        Body::Stream {
            declared_len,
            stream: Box::pin(stream),
        }
    } else {
        Body::Empty
    };
    Ok(Incoming {
        req: S3Request {
            method,
            raw_target,
            headers,
            body,
        },
        https,
    })
}

/// `request.cf.clientAcceptEncoding`, the client's own `Accept-Encoding`
/// before the edge rewrote it (see `ingress::restore_accept_encoding`).
/// `None` when the runtime gives no `cf` object or no string there.
fn client_accept_encoding(req: &Request) -> Option<String> {
    use worker::js_sys::Reflect;
    use worker::wasm_bindgen::JsValue;
    let cf = Reflect::get(req.inner(), &JsValue::from_str("cf")).ok()?;
    if !cf.is_object() {
        return None;
    }
    Reflect::get(&cf, &JsValue::from_str("clientAcceptEncoding"))
        .ok()?
        .as_string()
}

fn content_length(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<u64>().ok())
}

/// `S3Response` -> `worker::Response`. A streamed body with a declared
/// `content-length` goes through a `FixedLengthStream`, so the client sees
/// the length and a short stream fails the response instead of truncating
/// it silently. Stream errors never carry their text to the client.
pub fn to_response(resp: S3Response) -> Response {
    try_response(resp).unwrap_or_else(|_| internal_error())
}

fn try_response(resp: S3Response) -> worker::Result<Response> {
    let headers = Headers::new();
    for (name, value) in &resp.headers {
        headers.append(name, value)?;
    }
    let out = match resp.body {
        RespBody::Empty => Response::empty()?,
        RespBody::Bytes(bytes) => Response::from_bytes(bytes)?,
        RespBody::Stream(stream) => {
            let stream = stream
                .map(|chunk| chunk.map_err(|_| worker::Error::RustError("body stream".into())));
            match content_length(&resp.headers) {
                Some(len) => {
                    let fixed: worker::worker_sys::FixedLengthStream =
                        FixedLengthStream::wrap(stream, len).into();
                    Response::from_body(ResponseBody::Stream(fixed.readable()))?
                }
                None => Response::from_stream(stream)?,
            }
        }
    };
    Ok(out.with_status(resp.status).with_headers(headers))
}

/// A class-only `500` (fail closed). Never names a variable or value.
pub fn internal_error() -> Response {
    try_response(IngressError::Internal.response())
        .or_else(|_| Response::error("Internal Error", 500))
        .unwrap_or_else(|_| Response::empty().expect("empty response").with_status(500))
}
