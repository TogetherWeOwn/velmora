//! `worker::Request` <-> `S3Request`, `S3Response` -> `worker::Response`
//! (integration lane).
//!
//! The raw target comes from `req.inner().url()` only. `Request::url()`
//! parses through `url::Url`, which resolves dot segments and rewrites
//! backslashes, so it would verify a different key than the client signed;
//! clippy bans it in this crate. The body stays an unread stream.

use futures_util::StreamExt;
use velmora_bridge::{Body, BridgeError, Method, RespBody, S3Request, S3Response};
use worker::{Headers, Request, Response, Result};

/// Cuts scheme and authority off an absolute URL by byte scanning; path
/// and query are returned unchanged. Skeleton helper: the integration lane
/// replaces it with `ingress::origin_form`, which also rejects control bytes.
fn origin_form(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    match url[after_scheme..].find('/') {
        Some(i) => &url[after_scheme + i..],
        None => "/",
    }
}

pub fn to_s3_request(mut req: Request) -> Result<S3Request> {
    let raw_target = origin_form(&req.inner().url()).to_string();
    let method = Method::parse(&req.inner().method());
    let headers: Vec<(String, String)> = req.headers().entries().collect();
    let declared_len = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.trim().parse::<u64>().ok());
    let body = if req.inner().body().is_some() {
        let stream = req
            .stream()?
            .map(|chunk| chunk.map_err(|_| BridgeError::Invalid("request body stream")));
        Body::Stream {
            declared_len,
            stream: Box::pin(stream),
        }
    } else {
        Body::Empty
    };
    Ok(S3Request {
        method,
        raw_target,
        headers,
        body,
    })
}

pub fn to_response(resp: S3Response) -> Result<Response> {
    let headers = Headers::new();
    for (name, value) in &resp.headers {
        headers.append(name, value)?;
    }
    let out = match resp.body {
        RespBody::Empty => Response::empty()?,
        RespBody::Bytes(bytes) => Response::from_bytes(bytes)?,
        RespBody::Stream(stream) => Response::from_stream(
            stream.map(|chunk| chunk.map_err(|e| worker::Error::RustError(e.to_string()))),
        )?,
    };
    Ok(out.with_status(resp.status).with_headers(headers))
}
