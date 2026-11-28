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
    let body = if let Some(raw) = req.inner().body() {
        let (declared_len, read_len) = body_lengths(&method, &headers);
        let stream: velmora_bridge::ByteStream = match ByobReads::new(&raw, read_len) {
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

/// The most one body fill gathers, and so the maximum size of its reused
/// runtime buffer. The default reader hands a deployed request body out
/// in 4 KiB items, each a new array crossing into wasm on its
/// own task; a BYOB read fills up to this much at once. It is one plain
/// chunk, inside the item allowance of a streamed upload's charge
/// (`ingress::STREAM_ITEM_ALLOWANCE`).
const BODY_READ: u32 = velmora::media::PLAIN_CHUNK_SIZE as u32;
const BODY_PROBE: u32 = 4096;

/// Wire length for the consumer and length to size the BYOB reader.
/// A reader length of `None` is a single-read body-presence probe.
fn body_lengths(method: &Method, headers: &[(String, String)]) -> (Option<u64>, Option<u64>) {
    let wire_len = || ingress::declared_length(headers).unwrap_or(None);
    // The two object PUT handlers dispatch to CopyObject or UploadPartCopy
    // on presence of this header. Those operations only probe for a body
    // and take no body charge; upload framing must not select their reader.
    if matches!(method, Method::Put)
        && headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-amz-copy-source"))
    {
        return (wire_len(), None);
    }
    match ingress::upload_lengths(headers, u64::MAX) {
        // The admission budget uses the decoded length for aws-chunked,
        // including when the wire length was omitted.
        Ok(ingress::UploadLengths { encoded, decoded }) => {
            (encoded, Some(decoded.min(encoded.unwrap_or(decoded))))
        }
        // Invalid headers are still rejected by existing consumer checks.
        Err(_) => {
            let wire = wire_len();
            (wire, wire)
        }
    }
}

fn body_read_cap(declared_len: Option<u64>) -> u32 {
    match declared_len {
        // Even an empty body needs a non-empty view to read its end.
        Some(n) => n.clamp(1, u64::from(BODY_READ)) as u32,
        // An undeclared body can be an uncharged CopyObject body probe.
        None => BODY_PROBE,
    }
}

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
}

#[worker::wasm_bindgen::prelude::wasm_bindgen(
    wasm_bindgen = worker::wasm_bindgen,
    inline_js = "export async function fillBody(reader, buf, singleRead) {
  const cap = buf.byteLength;
  const target = singleRead ? 1 : cap;
  let off = 0;
  for (;;) {
    const r = await reader.read(new Uint8Array(buf, off, cap - off));
    if (r.value === undefined) throw new Error('body canceled');
    buf = r.value.buffer;
    off += r.value.byteLength;
    if (r.done) return { buf, n: off, done: true };
    if (r.value.byteLength === 0) throw new Error('empty read');
    if (off >= target) return { buf, n: off, done: false };
  }
}
export function cancelBody(reader) {
  reader.cancel().catch(() => {});
}"
)]
extern "C" {
    /// Cancels the body; a stream that already failed is not an error.
    #[wasm_bindgen(js_name = cancelBody)]
    fn cancel_body(reader: &ByobReader);
    /// Reads the body in JS until `buf` is full or the body ends; an
    /// undeclared body probe returns as soon as any bytes arrive. A
    /// deployed body gives at most 8 KiB per read (measured), and every
    /// read that came back into wasm cost a task and a wake. Rejects if
    /// the body failed or was canceled (a done read without a view).
    #[wasm_bindgen(catch, js_name = fillBody)]
    fn fill_body(
        reader: &ByobReader,
        buf: worker::js_sys::ArrayBuffer,
        single_read: bool,
    ) -> Result<worker::js_sys::Promise, worker::wasm_bindgen::JsValue>;
    /// What `fill_body` resolves to.
    type Filled;
    #[wasm_bindgen(method, getter)]
    fn buf(this: &Filled) -> worker::js_sys::ArrayBuffer;
    #[wasm_bindgen(method, getter)]
    fn n(this: &Filled) -> u32;
    #[wasm_bindgen(method, getter)]
    fn done(this: &Filled) -> bool;
}

/// What one fill gave, from the bytes it filled and whether the body
/// ended.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum FillGave {
    /// The end of the body, nothing more.
    End,
    /// A piece, and more may follow.
    Piece,
    /// The last piece of the body.
    LastPiece,
    /// A fill that neither ended nor filled anything.
    Failed,
}

/// At the end a read says done and hands the (empty) view back (workerd
/// from compatibility date 2024-05-13, `internal_stream_byob_return_view`;
/// ours is later); a fill that is not the end provides at least one byte.
fn fill_gave(filled: u32, done: bool) -> FillGave {
    match (filled, done) {
        (0, true) => FillGave::End,
        (0, false) => FillGave::Failed,
        (_, true) => FillGave::LastPiece,
        (_, false) => FillGave::Piece,
    }
}

/// A request body read with a BYOB reader into one runtime buffer; each
/// fill is copied once into a piece.
struct ByobReads {
    reader: ByobReader,
    cap: u32,
    /// A probe must not wait for more bytes once it knows the body exists.
    single_read: bool,
    /// The runtime buffer, allocated on the first poll. A fill transfers
    /// it and hands it back.
    buffer: Option<worker::js_sys::ArrayBuffer>,
    /// The body ended: there is nothing left to cancel.
    settled: bool,
    /// A fill failed or was interrupted: further reads return the error.
    failed: bool,
}

impl ByobReads {
    /// `None` when the body has no BYOB reader (it is not a byte stream).
    fn new(stream: &worker::web_sys::ReadableStream, declared_len: Option<u64>) -> Option<Self> {
        use worker::wasm_bindgen::JsCast;
        let options = worker::js_sys::Object::new();
        worker::js_sys::Reflect::set(&options, &"mode".into(), &"byob".into()).ok()?;
        Some(ByobReads {
            reader: stream
                .unchecked_ref::<ByteBody>()
                .byob_reader(&options)
                .ok()?,
            cap: body_read_cap(declared_len),
            single_read: declared_len.is_none(),
            buffer: None,
            settled: false,
            failed: false,
        })
    }
}

/// A body left unread (a refused upload) is canceled, as the default
/// reader's stream did when it was dropped.
impl Drop for ByobReads {
    fn drop(&mut self) {
        if !self.settled {
            cancel_body(&self.reader);
        }
    }
}

impl PieceReads for ByobReads {
    async fn next_piece(&mut self) -> Result<Option<Vec<u8>>, BridgeError> {
        use worker::wasm_bindgen::JsCast;
        let failed = || BridgeError::Invalid("request body stream");
        if self.failed {
            return Err(failed());
        }
        if self.settled {
            return Ok(None);
        }
        // The upload holds its stream charge before polling. Opening the
        // reader earlier must not allocate a buffer outside that charge.
        let buffer = self
            .buffer
            .take()
            .unwrap_or_else(|| worker::js_sys::ArrayBuffer::new(self.cap));
        // Do not retry a rejected or interrupted fill. Drop still cancels
        // it; an already errored reader rejects cancel and JS handles that.
        self.failed = true;
        let promise = fill_body(&self.reader, buffer, self.single_read).map_err(|_| failed())?;
        let filled: Filled = worker::wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|_| failed())?
            .unchecked_into();
        let n = filled.n();
        let back = filled.buf();
        let done = filled.done();
        let gave = fill_gave(n, done);
        if matches!(gave, FillGave::Failed) || n > back.byte_length() {
            return Err(failed());
        }
        self.failed = false;
        self.settled = done;
        if matches!(gave, FillGave::End) {
            return Ok(None);
        }
        let piece =
            worker::js_sys::Uint8Array::new_with_byte_offset_and_length(&back, 0, n).to_vec();
        if matches!(gave, FillGave::Piece) {
            // The runtime hands the whole buffer back; one that came back
            // smaller would cap every later fill, so it is replaced.
            self.buffer = Some(if back.byte_length() < self.cap {
                worker::js_sys::ArrayBuffer::new(self.cap)
            } else {
                back
            });
        }
        Ok(Some(piece))
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
    fn a_fill_ends_gives_a_piece_or_fails() {
        assert_eq!(fill_gave(0, true), FillGave::End);
        assert_eq!(fill_gave(0, false), FillGave::Failed, "nothing filled");
        assert_eq!(fill_gave(1, true), FillGave::LastPiece);
        assert_eq!(fill_gave(BODY_READ, true), FillGave::LastPiece);
        assert_eq!(fill_gave(BODY_READ, false), FillGave::Piece);
    }

    #[test]
    fn one_read_fits_the_item_allowance() {
        assert!(u64::from(BODY_READ) <= velmora_bridge::ingress::STREAM_ITEM_ALLOWANCE);
    }

    #[test]
    fn copy_uses_a_body_presence_probe_regardless_of_upload_framing() {
        let mut headers = vec![
            ("content-encoding".into(), "aws-chunked".into()),
            ("x-amz-decoded-content-length".into(), "65536".into()),
        ];
        assert_eq!(body_lengths(&Method::Put, &headers), (None, Some(65_536)));
        headers.push(("X-Amz-Copy-Source".into(), "/bucket/key".into()));
        assert_eq!(body_lengths(&Method::Put, &headers), (None, None));
        headers.push(("Content-Length".into(), "0".into()));
        assert_eq!(body_lengths(&Method::Put, &headers), (Some(0), None));
    }

    #[test]
    fn the_body_buffer_fits_the_declared_length_or_the_probe_cap() {
        for (declared, cap) in [
            (0, 1),
            (1, 1),
            (32_768, 32_768),
            (65_536, 65_536),
            (65_537, 65_536),
            (u64::MAX, 65_536),
        ] {
            let actual = body_read_cap(Some(declared));
            assert!(u64::from(actual) <= declared.max(1));
            assert_eq!(actual, cap);
        }
        assert_eq!(body_read_cap(None), 4096);
    }
}
