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

use std::cell::RefCell;
use std::future::poll_fn;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use futures_util::{Stream, StreamExt};
use velmora_bridge::ingress::{self, IngressError};
use velmora_bridge::{Body, BridgeError, ByteStream, Method, RespBody, S3Request, S3Response};
use worker::wasm_bindgen::{closure::Closure, JsCast};
use worker::web_sys::AbortSignal;
use worker::{EncodeBody, FixedLengthStream, Headers, Request, Response, ResponseBody};

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
    // A request through a service binding may have no `Host` header:
    // the host of its URL is the one it was sent to.
    if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
        if let Some(host) = ingress::url_authority(&url) {
            headers.push(("host".to_string(), host.to_string()));
        }
    }
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

/// A one-shot signal from a Rust response stream to its invocation's
/// detached-open cleanup. There is only one waiter per stream.
#[derive(Clone, Default)]
pub struct BodyDone(Rc<RefCell<BodyState>>);

#[derive(Default)]
struct BodyState {
    stream: Option<ByteStream>,
    done: bool,
    done_waker: Option<Waker>,
    pull_waker: Option<Waker>,
}

impl BodyDone {
    pub(crate) fn track(&self, stream: ByteStream) -> TrackedBody {
        self.0.borrow_mut().stream = Some(stream);
        TrackedBody {
            done: self.clone(),
            listener: None,
        }
    }

    pub(crate) fn abort(&self) -> bool {
        self.finish(true)
    }

    fn finish(&self, disconnected: bool) -> bool {
        let Some(stream) = self.0.borrow_mut().stream.take() else {
            return false;
        };
        // Drop the stream before any waiter checks for detached work: a
        // GET body stops reading for it here, and the Usenet read and
        // cache write it had under way are counted as detached
        // (`velmora_bridge::service::detached_bodies`) until they end.
        drop(stream);
        let (done_waker, pull_waker) = {
            let mut state = self.0.borrow_mut();
            state.done = true;
            (state.done_waker.take(), state.pull_waker.take())
        };
        if let Some(waker) = done_waker {
            waker.wake();
        }
        if disconnected {
            // A JS pull can still be pending even though its Rust future
            // is gone. Wake it so the adapter returns EOF to the pipe.
            if let Some(waker) = pull_waker {
                waker.wake();
            }
        }
        true
    }

    pub async fn wait(self) {
        poll_fn(|cx| {
            let mut state = self.0.borrow_mut();
            if state.done {
                Poll::Ready(())
            } else {
                state.done_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await;
    }
}

pub(crate) struct TrackedBody {
    done: BodyDone,
    listener: Option<DisconnectListener>,
}

// A fixed-length pipe waiting for a chunk may not see the closed socket
// until its next write. Listen on the request independently of the pipe.
struct DisconnectListener {
    signal: AbortSignal,
    callback: Closure<dyn FnMut()>,
}

impl DisconnectListener {
    fn new(signal: &AbortSignal, done: BodyDone) -> worker::Result<Self> {
        let on_abort = move || {
            if done.abort() {
                worker::console_log!("stream: client went away, body dropped");
            }
        };
        if signal.aborted() {
            on_abort();
        }
        let callback = Closure::new(on_abort);
        signal.add_event_listener_with_callback("abort", callback.as_ref().unchecked_ref())?;
        Ok(Self {
            signal: signal.clone(),
            callback,
        })
    }
}

impl Drop for DisconnectListener {
    fn drop(&mut self) {
        let _ = self
            .signal
            .remove_event_listener_with_callback("abort", self.callback.as_ref().unchecked_ref());
    }
}

impl Stream for TrackedBody {
    type Item = Result<Vec<u8>, BridgeError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = {
            let mut state = self.done.0.borrow_mut();
            let Some(stream) = &mut state.stream else {
                return Poll::Ready(None);
            };
            let next = stream.as_mut().poll_next(cx);
            state.pull_waker = next.is_pending().then(|| cx.waker().clone());
            next
        };
        if matches!(next, Poll::Ready(None | Some(Err(_)))) {
            self.done.finish(false);
            self.listener = None;
        }
        next
    }
}

impl Drop for TrackedBody {
    fn drop(&mut self) {
        self.done.finish(false);
    }
}

/// `S3Response` -> `worker::Response`. A streamed body with a declared
/// `content-length` goes through a `FixedLengthStream`, so the client sees
/// the length and a short stream fails the response instead of truncating
/// it silently. Stream errors never carry their text to the client.
pub fn to_response(resp: S3Response, signal: Option<&AbortSignal>) -> (Response, Option<BodyDone>) {
    try_response(resp, signal).unwrap_or_else(|_| (internal_error(), None))
}

fn try_response(
    resp: S3Response,
    signal: Option<&AbortSignal>,
) -> worker::Result<(Response, Option<BodyDone>)> {
    let headers = Headers::new();
    for (name, value) in &resp.headers {
        headers.append(name, value)?;
    }
    let mut body_done = None;
    let mut track = |stream| {
        let done = BodyDone::default();
        let mut tracked = done.track(stream);
        if let Some(signal) = signal {
            tracked.listener = Some(DisconnectListener::new(signal, done.clone())?);
        }
        body_done = Some(done);
        Ok::<_, worker::Error>(
            tracked.map(|chunk| chunk.map_err(|_| worker::Error::RustError("body stream".into()))),
        )
    };
    let out = match resp.body {
        RespBody::Empty => Response::empty()?,
        RespBody::Bytes(bytes) => Response::from_bytes(bytes)?,
        // `fetch` settles a deferred body first; one that is left is
        // streamed with its keepalive.
        RespBody::Deferred(d) => Response::from_stream(track(d.into_stream(
            crate::env::sleeper(),
            velmora_bridge::keepalive::KEEPALIVE_INTERVAL_MS,
        ))?)?,
        // `fetch` serves a body in sub-ranges itself (`crate::fanout`);
        // one that reaches this point has no stream to go to.
        RespBody::Fanout(_) => return Err(worker::Error::RustError("fanout body".into())),
        RespBody::Stream(stream) => {
            let stream = track(stream)?;
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
    // `manual`: the body is sent as it is. Every body is final; a
    // `content-encoding` header can only be an object's stored metadata,
    // which describes the stored bytes. The default (`automatic`) would
    // compress such an object again and drop its length.
    Ok((
        out.with_status(resp.status)
            .with_headers(headers)
            .with_encode_body(EncodeBody::Manual),
        body_done,
    ))
}

/// A class-only `500` (fail closed). Never names a variable or value.
pub fn internal_error() -> Response {
    try_response(IngressError::Internal.response(), None)
        .map(|(resp, _)| resp)
        .or_else(|_| Response::error("Internal Error", 500))
        .unwrap_or_else(|_| Response::empty().expect("empty response").with_status(500))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{stream, Stream};
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};

    #[derive(Default)]
    struct Wakes(std::sync::atomic::AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn body_done_wakes_the_waiter_at_eof_not_at_a_chunk() {
        let done = BodyDone::default();
        let mut body = std::pin::pin!(done.track(Box::pin(stream::iter([Ok(vec![1])]))));
        let mut wait = std::pin::pin!(done.clone().wait());
        let wakes = std::sync::Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);

        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert!(matches!(
            body.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(bytes))) if bytes == [1]
        ));
        assert_eq!(wakes.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(matches!(
            body.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        assert_eq!(wakes.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(wait.as_mut().poll(&mut cx).is_ready());
        assert!(!done.abort(), "a completed body cannot be aborted");
    }

    #[test]
    fn body_done_is_set_on_stream_error_before_drop() {
        let done = BodyDone::default();
        let failing = stream::iter([Err(BridgeError::Invalid("test body")), Ok(vec![1])]);
        let mut body = std::pin::pin!(done.track(Box::pin(failing)));
        let mut wait = std::pin::pin!(done.wait());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());

        assert!(matches!(
            body.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Err(_)))
        ));
        assert!(wait.as_mut().poll(&mut cx).is_ready());
        assert!(matches!(
            body.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn body_done_is_set_on_drop_during_a_pending_pull() {
        let done = BodyDone::default();
        let mut body = Box::pin(done.track(Box::pin(stream::pending())));
        let mut wait = std::pin::pin!(done.wait());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());

        assert!(body.as_mut().poll_next(&mut cx).is_pending());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        drop(body);
        assert!(wait.as_mut().poll(&mut cx).is_ready());
    }
}
