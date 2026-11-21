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
    let body = if let Some(raw) = req.inner().body() {
        let stream: velmora_bridge::ByteStream = match ByobReads::new(&raw) {
            Some(reads) => Box::pin(pieces(reads)),
            // Not a byte stream: the runtime's default reader.
            None => Box::pin(
                req.stream()
                    .map_err(|_| IngressError::Internal)?
                    .map(|chunk| chunk.map_err(|_| BridgeError::Invalid("request body stream"))),
            ),
        };
        Body::Stream {
            declared_len,
            stream,
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

/// The most one body read asks for, and so the size of the one runtime
/// buffer every read reuses. The default reader hands a deployed request
/// body out in 4 KiB items, each a new array crossing into wasm on its
/// own task; a BYOB read fills up to this much at once. It is one plain
/// chunk, inside the item allowance of a streamed upload's charge
/// (`ingress::STREAM_ITEM_ALLOWANCE`).
const BODY_READ: u32 = velmora::media::PLAIN_CHUNK_SIZE as u32;

/// Reads of a body: `Ok(None)` is its end. After an error or the end
/// nothing more is asked.
trait PieceReads {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, BridgeError>;
}

/// The body as a stream of pieces, in order. It ends at the end of the
/// body or after the first failed read.
fn pieces<R: PieceReads + 'static>(
    reads: R,
) -> impl futures_util::Stream<Item = Result<Vec<u8>, BridgeError>> {
    futures_util::stream::unfold(Some(reads), |state| async move {
        let mut reads = state?;
        match reads.next_piece().await {
            Ok(Some(piece)) => Some((Ok(piece), Some(reads))),
            Ok(None) => None,
            Err(e) => Some((Err(e), None)),
        }
    })
}

#[worker::wasm_bindgen::prelude::wasm_bindgen(wasm_bindgen = worker::wasm_bindgen)]
extern "C" {
    /// A `ReadableStream` of bytes.
    type ByteBody;
    /// A `ReadableStreamBYOBReader`.
    type ByobReader;
    #[wasm_bindgen(method, catch, js_name = getReader)]
    fn byob_reader(
        this: &ByteBody,
        options: &worker::js_sys::Object,
    ) -> Result<ByobReader, worker::wasm_bindgen::JsValue>;
    #[wasm_bindgen(method, catch)]
    fn cancel(this: &ByobReader) -> Result<worker::js_sys::Promise, worker::wasm_bindgen::JsValue>;
    #[wasm_bindgen(method, catch)]
    fn read(
        this: &ByobReader,
        view: &worker::js_sys::Uint8Array,
    ) -> Result<worker::js_sys::Promise, worker::wasm_bindgen::JsValue>;
    /// What a read resolves to.
    type ReadResult;
    #[wasm_bindgen(method, getter)]
    fn done(this: &ReadResult) -> bool;
    #[wasm_bindgen(method, getter)]
    fn value(this: &ReadResult) -> Option<worker::js_sys::Uint8Array>;
}

/// What one BYOB read gave, from its `done` flag and the length of the
/// view it handed back (`None`: no view).
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum ReadGave {
    /// The end of the body.
    End,
    /// A piece of this many bytes.
    Piece,
    /// A failed or canceled body, or a read that gave nothing.
    Failed,
}

/// At the end a read says done and hands the (empty) view back (workerd
/// from compatibility date 2024-05-13, `internal_stream_byob_return_view`;
/// ours is later). A canceled body says done with no view: that is not
/// an end. A read that is not the end fills at least one byte.
fn read_gave(done: bool, view_len: Option<u32>) -> ReadGave {
    match (done, view_len) {
        (_, None) => ReadGave::Failed,
        (true, Some(_)) => ReadGave::End,
        (false, Some(0)) => ReadGave::Failed,
        (false, Some(_)) => ReadGave::Piece,
    }
}

/// A request body read with a BYOB reader into one runtime buffer; each
/// read is copied once, into a piece of its own length.
struct ByobReads {
    reader: ByobReader,
    /// The runtime buffer; a read transfers it and hands it back. `None`
    /// after the end or a failure, and while a read is under way.
    buffer: Option<worker::js_sys::ArrayBuffer>,
    /// The body ended or failed: there is nothing left to cancel.
    settled: bool,
}

impl ByobReads {
    /// `None` when the body has no BYOB reader (it is not a byte stream).
    fn new(stream: &worker::web_sys::ReadableStream) -> Option<Self> {
        use worker::wasm_bindgen::JsCast;
        let options = worker::js_sys::Object::new();
        worker::js_sys::Reflect::set(&options, &"mode".into(), &"byob".into()).ok()?;
        Some(ByobReads {
            reader: stream
                .unchecked_ref::<ByteBody>()
                .byob_reader(&options)
                .ok()?,
            buffer: Some(worker::js_sys::ArrayBuffer::new(BODY_READ)),
            settled: false,
        })
    }
}

/// A body left unread (a refused upload) is canceled, as the default
/// reader's stream did when it was dropped.
impl Drop for ByobReads {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self.reader.cancel();
        }
    }
}

impl PieceReads for ByobReads {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, BridgeError> {
        use worker::wasm_bindgen::JsCast;
        let failed = || BridgeError::Invalid("request body stream");
        let buffer = self.buffer.take().ok_or_else(failed)?;
        // A read that fails or ends leaves nothing to cancel; a piece
        // sets this back.
        self.settled = true;
        let view = worker::js_sys::Uint8Array::new(&buffer);
        let promise = self.reader.read(&view).map_err(|_| failed())?;
        let result: ReadResult = worker::wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|_| failed())?
            .unchecked_into();
        let filled = result.value();
        match read_gave(result.done(), filled.as_ref().map(|v| v.length())) {
            ReadGave::End => Ok(None),
            ReadGave::Failed => Err(failed()),
            ReadGave::Piece => {
                let filled = filled.ok_or_else(failed)?;
                let piece = filled.to_vec();
                // The runtime hands the whole buffer back; one that came
                // back smaller would cap every later read, so it is
                // replaced.
                let back = filled.buffer();
                self.buffer = Some(if back.byte_length() < BODY_READ {
                    worker::js_sys::ArrayBuffer::new(BODY_READ)
                } else {
                    back
                });
                self.settled = false;
                Ok(Some(piece))
            }
        }
    }
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
        // `fetch` settles a deferred body first; one that is left is
        // streamed with its keepalive.
        RespBody::Deferred(d) => Response::from_stream(
            d.into_stream(
                crate::env::sleeper(),
                velmora_bridge::keepalive::KEEPALIVE_INTERVAL_MS,
            )
            .map(|chunk| chunk.map_err(|_| worker::Error::RustError("body stream".into()))),
        )?,
        // `fetch` serves a body in sub-ranges itself (`crate::fanout`);
        // one that reaches this point has no stream to go to.
        RespBody::Fanout(_) => return Err(worker::Error::RustError("fanout body".into())),
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
    // `manual`: the body is sent as it is. Every body is final; a
    // `content-encoding` header can only be an object's stored metadata,
    // which describes the stored bytes. The default (`automatic`) would
    // compress such an object again and drop its length.
    Ok(out
        .with_status(resp.status)
        .with_headers(headers)
        .with_encode_body(EncodeBody::Manual))
}

/// A class-only `500` (fail closed). Never names a variable or value.
pub fn internal_error() -> Response {
    try_response(IngressError::Internal.response())
        .or_else(|_| Response::error("Internal Error", 500))
        .unwrap_or_else(|_| Response::empty().expect("empty response").with_status(500))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pieces from a script: `Some(Ok(n))` is a piece of `n` bytes,
    /// `Some(Err(()))` a failed read, `None` the end.
    struct Scripted {
        steps: Vec<Option<Result<usize, ()>>>,
        asked: std::rc::Rc<std::cell::Cell<usize>>,
        next_byte: u8,
    }

    impl PieceReads for Scripted {
        async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, BridgeError> {
            self.asked.set(self.asked.get() + 1);
            assert!(!self.steps.is_empty(), "read after the end or a failure");
            match self.steps.remove(0) {
                None => Ok(None),
                Some(Err(())) => Err(BridgeError::Invalid("request body stream")),
                Some(Ok(n)) => Ok(Some(
                    (0..n)
                        .map(|_| {
                            self.next_byte = self.next_byte.wrapping_add(1);
                            self.next_byte
                        })
                        .collect(),
                )),
            }
        }
    }

    use std::future::Future;

    fn collect(steps: Vec<Option<Result<usize, ()>>>) -> (Vec<Result<Vec<u8>, ()>>, usize) {
        use std::task::{Context, Poll, Waker};
        let asked = std::rc::Rc::new(std::cell::Cell::new(0));
        let reads = Scripted {
            steps,
            asked: asked.clone(),
            next_byte: 0,
        };
        let fut = pieces(reads).map(|p| p.map_err(|_| ())).collect::<Vec<_>>();
        let out = match std::pin::pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("scripted reads never wait"),
        };
        (out, asked.get())
    }

    #[test]
    fn pieces_come_in_order_and_end_with_the_body() {
        let (out, asked) = collect(vec![Some(Ok(3)), Some(Ok(65_536)), Some(Ok(1)), None]);
        let bytes: Vec<u8> = out.into_iter().flat_map(|p| p.unwrap()).collect();
        assert_eq!(bytes.len(), 65_540);
        assert!(bytes
            .iter()
            .enumerate()
            .all(|(i, b)| *b == ((i + 1) % 256) as u8));
        assert_eq!(asked, 4, "no read after the end");
    }

    #[test]
    fn an_empty_body_is_no_piece() {
        let (out, asked) = collect(vec![None]);
        assert!(out.is_empty());
        assert_eq!(asked, 1);
    }

    #[test]
    fn a_failed_read_is_the_last_item() {
        let (out, asked) = collect(vec![Some(Ok(10)), Some(Err(())), Some(Ok(10))]);
        assert_eq!(out.len(), 2);
        assert!(out[0].is_ok());
        assert!(out[1].is_err());
        assert_eq!(asked, 2, "nothing is read after a failure");
    }

    #[test]
    fn a_read_ends_gives_a_piece_or_fails() {
        assert_eq!(read_gave(true, Some(0)), ReadGave::End);
        assert_eq!(read_gave(true, None), ReadGave::Failed, "canceled");
        assert_eq!(read_gave(false, None), ReadGave::Failed);
        assert_eq!(read_gave(false, Some(0)), ReadGave::Failed, "empty read");
        assert_eq!(read_gave(false, Some(1)), ReadGave::Piece);
        assert_eq!(read_gave(false, Some(BODY_READ)), ReadGave::Piece);
    }

    #[test]
    fn one_read_fits_the_item_allowance() {
        assert!(u64::from(BODY_READ) <= velmora_bridge::ingress::STREAM_ITEM_ALLOWANCE);
    }
}
