//! `impl BlobStore` over an R2 bucket.
//!
//! `put` stores the custom metadata (`bucket`, `extent`, `cipher-sha256`
//! in hex) and asks R2 to check the body against `cipher_sha256`, so a
//! corrupted upload is refused rather than stored. A ranged `get` returns
//! exactly the span or fails. Errors carry the operation class only.
//!
//! `put_stream` hands R2 a stream of a fixed length, so the blob is not
//! held in memory. R2 stores nothing when the stream fails or ends at
//! another length. It cannot be given a digest before the bytes exist,
//! so the answer carries the size and the MD5 R2 reports (the etag of an
//! object written by one put) and the caller compares them with what it
//! sent. The custom metadata of such a blob has no `cipher-sha256`.
//!
//! Dev only: `DEV_TOMBSTONE_PUT_DELAY_MS` makes every put of a tombstone
//! record to the safety store wait that long first (a slow store), so the
//! local acceptance run can make a DeleteObjects outlast a client's read
//! timeout. Outside `ENVIRONMENT=dev` the variable is ignored.

use std::collections::HashMap;

use futures_util::StreamExt;

use velmora_bridge::recovery::{
    is_protected_key, record_name, RecordKind, Unpublished, ERR_RECORD_DELETE,
};
use velmora_bridge::{
    BlobEntry, BlobMeta, BlobStore, BridgeError, ByteSpan, ByteStream, PutReceipt, Result,
    StreamMeta,
};
use worker::js_sys::{ArrayBuffer, Object, Promise, Reflect, Uint8Array};
use worker::wasm_bindgen::prelude::wasm_bindgen;
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::web_sys::ReadableStream;
use worker::{Bucket, FixedLengthStream, Range};

/// R2 range offsets travel as JS numbers (workers-rs panics above this).
const MAX_SAFE_OFFSET: u64 = (1 << 53) - 1;

/// The most a `get` reserves up front; a larger body grows as it arrives.
const MAX_PRESIZE: u64 = 32 * 1024 * 1024;

pub struct R2Blobs {
    bucket: Bucket,
    /// Dev only: the wait before a tombstone put, in milliseconds.
    tombstone_delay_ms: u32,
}

/// Name of the dev-only tombstone put delay variable.
pub const DEV_TOMBSTONE_PUT_DELAY_MS: &str = "DEV_TOMBSTONE_PUT_DELAY_MS";

/// Most a tombstone put may be held back.
const MAX_TOMBSTONE_DELAY_MS: u32 = 60_000;

/// `dev` is the validated environment. Outside dev the value is never
/// read (0). In dev, absent or empty is 0, and anything other than an
/// integer up to [`MAX_TOMBSTONE_DELAY_MS`] is refused.
pub fn tombstone_delay_from_var(dev: bool, raw: Option<&str>) -> std::result::Result<u32, String> {
    if !dev {
        return Ok(0);
    }
    match raw.map(str::trim) {
        None | Some("") => Ok(0),
        Some(v) => v
            .parse::<u32>()
            .ok()
            .filter(|ms| *ms <= MAX_TOMBSTONE_DELAY_MS)
            .ok_or_else(|| format!("invalid {DEV_TOMBSTONE_PUT_DELAY_MS}")),
    }
}

impl R2Blobs {
    pub fn new(bucket: Bucket) -> Self {
        R2Blobs {
            bucket,
            tombstone_delay_ms: 0,
        }
    }

    /// Dev only (see the module docs).
    pub fn with_tombstone_delay(mut self, ms: u32) -> Self {
        self.tombstone_delay_ms = ms;
        self
    }
}

/// `r2: <op> failed[: <class>][ (<code>)]`. Of R2's message only a class
/// from a fixed list and the code it ends with are kept (R2 ends its
/// errors with one, e.g. `(10001)`), for the request log
/// (`velmora_bridge::metrics::Fault`); never the text itself.
fn blob_err(op: &'static str) -> impl Fn(worker::Error) -> BridgeError {
    move |e| BridgeError::Blob(format!("r2: {op} failed{}", r2_detail(&e.to_string())))
}

fn r2_detail(text: &str) -> String {
    let class = if text.contains("Network connection lost") {
        ": network lost"
    } else if text.contains("timed out") || text.contains("timeout") {
        ": timeout"
    } else if text.contains("internal error") {
        ": internal"
    } else if text.contains("stream") {
        ": stream"
    } else {
        ""
    };
    match r2_code(text) {
        Some(code) => format!("{class} ({code})"),
        None => class.to_string(),
    }
}

/// The number in parentheses that an R2 error ends with.
fn r2_code(text: &str) -> Option<u32> {
    let digits = text.trim_end().strip_suffix(')')?.rsplit_once('(')?.1;
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn custom_metadata(meta: &BlobMeta<'_>) -> HashMap<String, String> {
    HashMap::from([
        ("bucket".to_string(), meta.bucket.as_str().to_string()),
        ("extent".to_string(), meta.extent.as_str().to_string()),
        ("cipher-sha256".to_string(), hex(meta.cipher_sha256)),
    ])
}

fn stream_metadata(meta: &StreamMeta<'_>) -> HashMap<String, String> {
    HashMap::from([
        ("bucket".to_string(), meta.bucket.as_str().to_string()),
        ("extent".to_string(), meta.extent.as_str().to_string()),
    ])
}

/// The MD5 an etag names: exactly 32 hex digits, or nothing.
fn etag_md5(etag: &str) -> Option<[u8; 16]> {
    let raw = etag.as_bytes();
    if raw.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = char::from(raw[2 * i]).to_digit(16)?;
        let lo = char::from(raw[2 * i + 1]).to_digit(16)?;
        *byte = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

/// The R2 range for a non-empty span; refuses offsets R2 cannot address.
fn r2_range(span: ByteSpan) -> Result<Range> {
    if span
        .start
        .checked_add(span.len)
        .is_none_or(|end| end > MAX_SAFE_OFFSET)
    {
        return Err(BridgeError::Blob("r2: range out of bounds".into()));
    }
    Ok(Range::OffsetWithLength {
        offset: span.start,
        length: span.len,
    })
}

/// An empty span is valid up to and including the end of the object.
fn empty_span(span: ByteSpan, size: u64) -> Result<Vec<u8>> {
    if span.start > size {
        return Err(BridgeError::Blob("r2: range past end".into()));
    }
    Ok(Vec::new())
}

/// Why a body read failed.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum BodyError {
    /// The body ended before the expected length.
    Short,
    /// The body went on past the expected length.
    Long,
    /// The runtime failed the read.
    Read,
}

/// Plain reads of a body: `Ok(0)` is its end. A read never returns more
/// than `dst.len()` bytes, and is never asked for 0.
trait BodyReads {
    async fn read(&mut self, dst: &mut [u8]) -> std::result::Result<usize, BodyError>;
}

/// Reads a body of exactly `expected` bytes into one buffer of that size.
///
/// The buffer is reserved up to [`MAX_PRESIZE`] ahead of what has arrived,
/// so a larger body grows as it arrives. Each read lands in place: no chunk
/// is held twice. The buffer has room for one byte past `expected`, so a
/// longer body shows itself without being read further.
async fn fill_body<R: BodyReads>(
    reads: &mut R,
    expected: u64,
) -> std::result::Result<Vec<u8>, BodyError> {
    // Only a 32-bit target refuses here, and no extent comes near 4 GiB.
    let room = usize::try_from(expected)
        .ok()
        .and_then(|e| e.checked_add(1))
        .ok_or(BodyError::Read)?;
    let mut bytes = Vec::new();
    let mut filled = 0;
    loop {
        if filled == bytes.len() {
            bytes.resize(room.min(filled + MAX_PRESIZE as usize), 0);
        }
        match reads.read(&mut bytes[filled..]).await? {
            0 => break,
            n => filled += n,
        }
        if filled == room {
            return Err(BodyError::Long);
        }
    }
    if filled + 1 < room {
        return Err(BodyError::Short);
    }
    bytes.truncate(filled);
    Ok(bytes)
}

/// Largest single read asked of R2, and so the most the runtime buffer
/// holds. R2 fills about 64 KiB per read whatever the size (up to about
/// 400 KiB measured), so 256 KiB loses nothing.
const MAX_READ: u64 = 256 * 1024;

/// A body read with a BYOB reader into one runtime buffer that every read
/// reuses. The default reader hands R2 bodies out in 4 KiB chunks, each a
/// new array that is copied twice on its way into the body; a BYOB read is
/// about 64 KiB, copied once, into its place in the body.
struct ByobReads {
    reader: ByobReader,
    /// The runtime buffer; a read transfers it and hands it back.
    buffer: Option<ArrayBuffer>,
}

#[wasm_bindgen(wasm_bindgen = worker::wasm_bindgen)]
extern "C" {
    /// A `ReadableStream` of bytes.
    type ByteBody;
    /// A `ReadableStreamBYOBReader`.
    type ByobReader;
    #[wasm_bindgen(method, catch, js_name = getReader)]
    fn byob_reader(this: &ByteBody, options: &Object) -> std::result::Result<ByobReader, JsValue>;
    #[wasm_bindgen(method, catch)]
    fn read(this: &ByobReader, view: &Uint8Array) -> std::result::Result<Promise, JsValue>;
    /// What a read resolves to.
    type ReadResult;
    #[wasm_bindgen(method, getter)]
    fn done(this: &ReadResult) -> bool;
    #[wasm_bindgen(method, getter)]
    fn value(this: &ReadResult) -> Option<Uint8Array>;
}

impl ByobReads {
    /// `None` when the stream has no BYOB reader (it is not a byte
    /// stream). R2 bodies are byte streams, so `get` then fails closed.
    /// The buffer is no larger than the body needs (`expected` plus the
    /// spare byte), so a small range holds a small buffer.
    fn new(stream: &ReadableStream, expected: u64) -> Option<Self> {
        let options = Object::new();
        Reflect::set(&options, &"mode".into(), &"byob".into()).ok()?;
        Some(ByobReads {
            reader: stream
                .unchecked_ref::<ByteBody>()
                .byob_reader(&options)
                .ok()?,
            buffer: Some(ArrayBuffer::new(
                expected.saturating_add(1).min(MAX_READ) as u32
            )),
        })
    }
}

impl BodyReads for ByobReads {
    async fn read(&mut self, dst: &mut [u8]) -> std::result::Result<usize, BodyError> {
        // The buffer is gone only after a read that failed or ended.
        let buffer = self.buffer.take().ok_or(BodyError::Read)?;
        let want = buffer.byte_length().min(dst.len() as u32);
        let view = Uint8Array::new_with_byte_offset_and_length(&buffer, 0, want);
        let promise = self.reader.read(&view).map_err(|_| BodyError::Read)?;
        let result: ReadResult = JsFuture::from(promise)
            .await
            .map_err(|_| BodyError::Read)?
            .unchecked_into();
        // At the end a read says done and hands the (empty) view back, as
        // workerd does from compatibility date 2024-05-13
        // (`internal_stream_byob_return_view`; ours is later). A canceled
        // stream says done with no view: that is not an end.
        let filled = result.value().ok_or(BodyError::Read)?;
        if result.done() {
            return Ok(0);
        }
        let n = filled.length() as usize;
        if n > dst.len() {
            return Err(BodyError::Read);
        }
        filled.copy_to(&mut dst[..n]);
        self.buffer = Some(filled.buffer());
        Ok(n)
    }
}

async fn read_body(object: worker::Object, span: Option<ByteSpan>) -> Result<Vec<u8>> {
    let body = object
        .body()
        .ok_or_else(|| BridgeError::Blob("r2: get returned no body".into()))?;
    let expected = span.map_or_else(|| object.size(), |s| s.len);
    let stream = match body.response_body().map_err(blob_err("get body"))? {
        worker::ResponseBody::Stream(stream) => stream,
        _ => return Err(BridgeError::Blob("r2: get returned no body".into())),
    };
    let Some(mut reads) = ByobReads::new(&stream, expected) else {
        return Err(BridgeError::Blob("r2: get body failed".into()));
    };
    fill_body(&mut reads, expected).await.map_err(|e| {
        BridgeError::Blob(
            match (e, span) {
                (BodyError::Short, Some(_)) => "r2: short range",
                (BodyError::Short, None) => "r2: short body",
                (BodyError::Long, _) => "r2: long body",
                (BodyError::Read, _) => "r2: get body failed",
            }
            .into(),
        )
    })
}

impl velmora_bridge::audit::AuditSource for R2Blobs {
    async fn page(&self, prefix: &str, after: &str) -> Result<velmora_bridge::audit::AuditPage> {
        use velmora_bridge::audit::{AuditEntry, AuditPage, PAGE_SIZE};
        let page = self
            .bucket
            .list()
            .prefix(prefix)
            .start_after(after)
            .limit(PAGE_SIZE)
            .execute()
            .await
            .map_err(blob_err("audit list"))?;
        Ok(AuditPage {
            objects: page
                .objects()
                .iter()
                .map(|o| AuditEntry {
                    key: o.key(),
                    size: o.size(),
                    uploaded: velmora_bridge::UnixMs(o.uploaded().as_millis() as i64),
                })
                .collect(),
            truncated: page.truncated(),
        })
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(object) = self
            .bucket
            .get(key)
            .execute()
            .await
            .map_err(blob_err("audit get"))?
        else {
            return Ok(None);
        };
        if object.size() > velmora_bridge::remote::MAX_AUDIT_BYTES as u64 {
            return Ok(None);
        }
        read_body(object, None).await.map(Some)
    }
}

impl BlobStore for R2Blobs {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        if self.tombstone_delay_ms > 0
            && record_name(key).is_some_and(|n| n.kind == RecordKind::Tombstone)
        {
            let wait = std::time::Duration::from_millis(u64::from(self.tombstone_delay_ms));
            worker::Delay::from(wait).await;
        }
        self.bucket
            .put(key, bytes)
            .custom_metadata(custom_metadata(meta))
            .sha256(meta.cipher_sha256.to_vec())
            .execute()
            .await
            .map_err(blob_err("put"))?;
        Ok(())
    }

    async fn put_stream(
        &self,
        key: &str,
        len: u64,
        body: ByteStream,
        meta: &StreamMeta<'_>,
    ) -> Result<PutReceipt> {
        // The cause of a failed piece stays with the caller; R2 only has
        // to see that the stream failed.
        let pieces = body.map(|piece| piece.map_err(|_| worker::Error::from("stream failed")));
        let object = self
            .bucket
            .put(key, FixedLengthStream::wrap(pieces, len))
            .custom_metadata(stream_metadata(meta))
            .execute()
            .await
            .map_err(blob_err("put"))?
            // Absent only for a conditional put, which this is not.
            .ok_or_else(|| BridgeError::Blob("r2: put returned no object".into()))?;
        let md5 = etag_md5(&object.etag())
            .ok_or_else(|| BridgeError::Blob("r2: put returned no md5".into()))?;
        Ok(PutReceipt {
            size: object.size(),
            md5,
        })
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        let mut req = self.bucket.get(key);
        match span {
            // R2 has no empty range: answer from a head.
            Some(s) if s.len == 0 => {
                return match self.head(key).await? {
                    None => Ok(None),
                    Some(size) => empty_span(s, size).map(Some),
                };
            }
            Some(s) => req = req.range(r2_range(s)?),
            None => {}
        }
        let Some(object) = req.execute().await.map_err(blob_err("get"))? else {
            return Ok(None);
        };
        read_body(object, span).await.map(Some)
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        let object = self.bucket.head(key).await.map_err(blob_err("head"))?;
        Ok(object.map(|o| o.size()))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        if is_protected_key(key) {
            return Err(ERR_RECORD_DELETE);
        }
        self.bucket.delete(key).await.map_err(blob_err("delete"))
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.bucket
            .delete(refused.key())
            .await
            .map_err(blob_err("delete"))
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut cursor: Option<String> = None;
        // R2 may return a short page that is not the last one.
        while (keys.len() as u64) < u64::from(limit) {
            let want = limit - keys.len() as u32;
            let mut req = self.bucket.list().prefix(prefix).limit(want);
            req = match &cursor {
                Some(c) => req.cursor(c.clone()),
                None => req.start_after(start_after),
            };
            let page = req.execute().await.map_err(blob_err("list"))?;
            keys.extend(page.objects().iter().map(worker::Object::key));
            cursor = match (page.truncated(), page.cursor()) {
                (true, Some(c)) => Some(c),
                _ => break,
            };
        }
        Ok(keys)
    }

    /// Sizes and MD5s from the listing itself, with no read per key:
    /// R2's etag of an object written by one put is the MD5 of its
    /// bytes. As in the default, only an empty answer is the end: a
    /// limit of 0 is read as 1, and a page that says "more" and gives
    /// no cursor is an error.
    async fn list_entries(
        &self,
        prefix: &str,
        start_after: &str,
        limit: u32,
    ) -> Result<Vec<BlobEntry>> {
        let limit = limit.max(1);
        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;
        while (entries.len() as u64) < u64::from(limit) {
            let want = limit - entries.len() as u32;
            let mut req = self.bucket.list().prefix(prefix).limit(want);
            req = match &cursor {
                Some(c) => req.cursor(c.clone()),
                None => req.start_after(start_after),
            };
            let page = req.execute().await.map_err(blob_err("list"))?;
            entries.extend(page.objects().iter().map(|o| BlobEntry {
                key: o.key(),
                size: o.size(),
                md5: o.etag(),
            }));
            cursor = match (page.truncated(), page.cursor()) {
                (true, Some(c)) => Some(c),
                (true, None) => {
                    return Err(BridgeError::Blob("list: more to come and no cursor".into()))
                }
                (false, _) => break,
            };
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora_bridge::{BucketId, ExtentId};

    #[test]
    fn an_r2_error_keeps_its_class_and_code_only() {
        let err = |text: &str| match blob_err("put")(worker::Error::RustError(text.into())) {
            BridgeError::Blob(m) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            err("put: We encountered an internal error. Please try again. (10001)"),
            "r2: put failed: internal (10001)"
        );
        assert_eq!(
            err("Network connection lost."),
            "r2: put failed: network lost"
        );
        assert_eq!(
            err("put: The specified object name is not valid. (10020)"),
            "r2: put failed (10020)"
        );
        // Text that is not R2's code is dropped, whatever it holds.
        assert_eq!(err("put: photos/2024 (secret)"), "r2: put failed");
        assert_eq!(err("put: (1234567)"), "r2: put failed");
        for text in [
            "put: We encountered an internal error. Please try again. (10001)",
            "Network connection lost.",
            "put: (10058)",
        ] {
            let fault = velmora_bridge::metrics::Fault::of(&BridgeError::Blob(err(text)));
            assert_eq!(fault.variant(), "Blob");
            assert!(fault.code().starts_with("r2_put"), "{}", fault.code());
        }
    }

    #[test]
    fn metadata_names_bucket_extent_and_digest() {
        let bucket = BucketId::new("b_0123456789abcdef");
        let extent = ExtentId::new("e_00112233445566778899aabbccddeeff");
        let digest = [0xab; 32];
        let m = custom_metadata(&BlobMeta {
            bucket: &bucket,
            extent: &extent,
            cipher_sha256: &digest,
        });
        assert_eq!(m.len(), 3);
        assert_eq!(m["bucket"], "b_0123456789abcdef");
        assert_eq!(m["extent"], extent.as_str());
        assert_eq!(m["cipher-sha256"], "ab".repeat(32));
    }

    #[test]
    fn a_streamed_blob_names_bucket_and_extent_only() {
        let bucket = BucketId::new("b_0123456789abcdef");
        let extent = ExtentId::new("e_00112233445566778899aabbccddeeff");
        let m = stream_metadata(&StreamMeta {
            bucket: &bucket,
            extent: &extent,
        });
        assert_eq!(m.len(), 2);
        assert_eq!(m["bucket"], "b_0123456789abcdef");
        assert_eq!(m["extent"], extent.as_str());
    }

    #[test]
    fn an_etag_is_an_md5_only_when_it_is_32_hex_digits() {
        let md5 = etag_md5("d41d8cd98f00b204e9800998ecf8427e").unwrap();
        assert_eq!(hex(&md5), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(etag_md5("D41D8CD98F00B204E9800998ECF8427E"), Some(md5));
        for bad in [
            "",
            "d41d8cd98f00b204e9800998ecf8427",
            "d41d8cd98f00b204e9800998ecf8427e0",
            "d41d8cd98f00b204e9800998ecf8427g",
            "\"d41d8cd98f00b204e9800998ecf842\"",
            "d41d8cd98f00b204e9800998ecf842-2",
            "+41d8cd98f00b204e9800998ecf8427e",
        ] {
            assert_eq!(etag_md5(bad), None, "{bad}");
        }
    }

    #[test]
    fn range_is_exact_and_bounded() {
        match r2_range(ByteSpan { start: 10, len: 5 }).unwrap() {
            Range::OffsetWithLength { offset, length } => assert_eq!((offset, length), (10, 5)),
            _ => panic!("wrong range kind"),
        }
        let empty = |start| empty_span(ByteSpan { start, len: 0 }, 10);
        assert!(empty(0).is_ok() && empty(10).is_ok() && empty(11).is_err());
        assert!(r2_range(ByteSpan {
            start: MAX_SAFE_OFFSET,
            len: 1
        })
        .is_err());
        assert!(r2_range(ByteSpan {
            start: u64::MAX,
            len: 1
        })
        .is_err());
    }

    /// Reads from a script: each step is how many bytes the next read
    /// gives at most (or a failure), out of `body`.
    struct Scripted {
        body: Vec<u8>,
        at: usize,
        steps: Vec<Option<usize>>,
        asked: Vec<usize>,
    }

    impl BodyReads for Scripted {
        async fn read(&mut self, dst: &mut [u8]) -> std::result::Result<usize, BodyError> {
            assert!(!dst.is_empty(), "a read of 0 bytes");
            self.asked.push(dst.len());
            let step = if self.steps.is_empty() {
                Some(usize::MAX)
            } else {
                self.steps.remove(0)
            };
            let max = step.ok_or(BodyError::Read)?;
            let n = max.min(dst.len()).min(self.body.len() - self.at);
            dst[..n].copy_from_slice(&self.body[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    fn scripted(len: usize, steps: Vec<Option<usize>>) -> Scripted {
        Scripted {
            body: (0..len).map(|i| (i * 7 + i / 251) as u8).collect(),
            at: 0,
            steps,
            asked: Vec::new(),
        }
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        match std::pin::pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("scripted reads never wait"),
        }
    }

    #[test]
    fn body_lands_in_order_whatever_the_read_sizes() {
        for steps in [
            vec![],
            vec![Some(1); 40],
            vec![Some(4096); 9],
            vec![Some(3), Some(65536), Some(5)],
        ] {
            let mut r = scripted(70_001, steps);
            let got = run(fill_body(&mut r, 70_001)).unwrap();
            assert_eq!(got, r.body);
        }
    }

    #[test]
    fn exact_body_ends_with_one_spare_byte() {
        let mut r = scripted(1000, vec![]);
        assert_eq!(run(fill_body(&mut r, 1000)).unwrap().len(), 1000);
        assert_eq!(
            r.asked,
            vec![1001, 1],
            "one read for the body, one for its end"
        );
    }

    #[test]
    fn short_long_and_failed_bodies_are_refused() {
        assert_eq!(
            run(fill_body(&mut scripted(99, vec![]), 100)),
            Err(BodyError::Short)
        );
        assert_eq!(
            run(fill_body(&mut scripted(101, vec![]), 100)),
            Err(BodyError::Long)
        );
        let failing = vec![Some(10), None];
        assert_eq!(
            run(fill_body(&mut scripted(100, failing), 100)),
            Err(BodyError::Read)
        );
        // A body that fails at its end is not taken as complete.
        let failing_end = vec![Some(100), None];
        assert_eq!(
            run(fill_body(&mut scripted(100, failing_end), 100)),
            Err(BodyError::Read)
        );
    }

    #[test]
    fn empty_body_reads_only_its_end() {
        let mut r = scripted(0, vec![]);
        assert_eq!(run(fill_body(&mut r, 0)).unwrap(), Vec::<u8>::new());
        assert_eq!(r.asked, vec![1]);
        assert_eq!(
            run(fill_body(&mut scripted(1, vec![]), 0)),
            Err(BodyError::Long)
        );
    }

    #[test]
    fn buffer_grows_by_the_presize_step() {
        let len = MAX_PRESIZE as usize + 5;
        let mut r = scripted(len, vec![]);
        assert_eq!(run(fill_body(&mut r, len as u64)).unwrap(), r.body);
        assert_eq!(r.asked, vec![MAX_PRESIZE as usize, 6, 1]);
    }
}
