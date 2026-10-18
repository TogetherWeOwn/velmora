//! Offline framing-unit edges for [`BufferedTransport`].
//!
//! Covers the five arms `review_article_direct.rs` does not: `write_line`
//! CR/LF rejection, bare-LF tolerance, the two EOF arms (empty buffer vs
//! partial bytes without CRLF), the two `MAX_LINE_BYTES` arms
//! (newline-found vs buffer-full), and the `is_article_limit_error`
//! classifier. In-memory script transport only; no network, no fixture
//! server. Touches no transport implementation.

use std::io;
use std::sync::{Arc, Mutex};

use nntune_core::transport::{
    is_article_limit_error, BufferedTransport, Transport, ARTICLE_LIMIT_ERROR, MAX_LINE_BYTES,
};

#[derive(Default)]
struct Trace {
    written: Vec<u8>,
    writes: usize,
}

struct Script {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    trace: Arc<Mutex<Trace>>,
}

impl Transport for Script {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out
            .len()
            .min(self.chunk)
            .min(self.data.len().saturating_sub(self.pos));
        if n == 0 {
            // EOF: the outer transport classifies it into the two
            // UnexpectedEof arms under test.
            return Ok(0);
        }
        out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut trace = self.trace.lock().unwrap();
        trace.written.extend_from_slice(bytes);
        trace.writes += 1;
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn transport(data: &[u8], chunk: usize) -> (BufferedTransport<Script>, Arc<Mutex<Trace>>) {
    limited_transport(data, chunk, MAX_LINE_BYTES)
}

fn limited_transport(
    data: &[u8],
    chunk: usize,
    limit: usize,
) -> (BufferedTransport<Script>, Arc<Mutex<Trace>>) {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let inner = Script {
        data: data.to_vec(),
        pos: 0,
        chunk,
        trace: trace.clone(),
    };
    (BufferedTransport::with_article_limit(inner, limit), trace)
}

#[test]
fn max_line_bytes_is_16_kib() {
    assert_eq!(MAX_LINE_BYTES, 16 * 1024);
}

#[tokio::test]
async fn write_line_rejects_embedded_line_breaks() {
    for bad in [
        b"AB\rCD".as_slice(),
        b"AB\nCD".as_slice(),
        b"AB\r\nCD".as_slice(),
        b"\r".as_slice(),
        b"\n".as_slice(),
    ] {
        let (mut t, trace) = transport(b"", 4096);
        let err = t.write_line(bad).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "NNTP command contains a line break");
        // Nothing reaches the wire.
        assert!(trace.lock().unwrap().written.is_empty());
        // Rejection does not poison the connection: a clean line still sends.
        t.write_line(b"NOOP").await.unwrap();
        assert_eq!(trace.lock().unwrap().written, b"NOOP\r\n");
    }
}

#[tokio::test]
async fn write_line_clean_sends_single_crlf_packet() {
    let (mut t, trace) = transport(b"", 4096);
    t.write_line(b"MODE READER").await.unwrap();
    let trace = trace.lock().unwrap();
    assert_eq!(trace.writes, 1);
    assert_eq!(trace.written, b"MODE READER\r\n");
}

#[tokio::test]
async fn read_line_tolerates_bare_lf() {
    for chunk in [1, 4096] {
        let (mut t, _) = transport(b"hello\nNEXT\r\n", chunk);
        assert_eq!(t.read_line().await.unwrap(), b"hello", "chunk {chunk}");
        assert_eq!(t.read_line().await.unwrap(), b"NEXT", "chunk {chunk}");
    }
}

#[tokio::test]
async fn read_line_eof_arms_have_distinct_messages() {
    for chunk in [1, 4096] {
        // Empty buffer: connection closed mid-line.
        let (mut t, _) = transport(b"", chunk);
        let err = t.read_line().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "chunk {chunk}");
        assert_eq!(err.to_string(), "NNTP connection closed mid-line");

        // Partial bytes without CRLF: a different message on the same kind.
        let (mut t, _) = transport(b"PARTIAL", chunk);
        let err = t.read_line().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "chunk {chunk}");
        assert_eq!(
            err.to_string(),
            "NNTP connection closed without CRLF",
            "chunk {chunk}"
        );
    }
}

#[tokio::test]
async fn max_line_bytes_newline_found_arm() {
    // The LF sits at index MAX_LINE_BYTES + 1 (16 KiB of `A` + CRLF), and
    // each `read` delivers at most 4096 bytes (`transport.rs` fixed chunk
    // array), so the script chunk only shrinks reads, never grows them. A
    // chunk below 4096 that does not divide the 16 KiB boundary makes one
    // read straddle it: e.g. with chunk 1000 the read starting at
    // buffered-len 16000 (< MAX, no LF yet) delivers bytes [16000, 16386),
    // so the next loop-top finds the LF at pos 16385 >= MAX -- the
    // newline-found arm. (A 4096-multiple chunk lands the buffer exactly on
    // MAX with no LF and takes the buffer-full arm instead.)
    let mut data = vec![b'A'; MAX_LINE_BYTES];
    data.extend_from_slice(b"\r\n");
    for chunk in [1000, 3000] {
        let (mut t, _) = transport(&data, chunk);
        let err = t.read_line().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "chunk {chunk}");
        assert_eq!(err.to_string(), "NNTP line exceeds 16 KiB", "chunk {chunk}");
    }
}

#[tokio::test]
async fn max_line_bytes_buffer_full_arm() {
    // No LF at all: only the buffer-full arm can reject this with InvalidData.
    // Without that guard the transport would read to EOF and return
    // UnexpectedEof ("closed without CRLF"), so the assertions below fail.
    let data = vec![b'A'; MAX_LINE_BYTES]; // no LF: only the buffer-full arm can reject this
    for chunk in [1, 1024] {
        let (mut t, _) = transport(&data, chunk);
        let err = t.read_line().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "chunk {chunk}");
        assert_eq!(err.to_string(), "NNTP line exceeds 16 KiB", "chunk {chunk}");
    }
}

#[test]
fn article_limit_error_constant_value() {
    assert_eq!(ARTICLE_LIMIT_ERROR, "NNTP article exceeds byte limit");
}

#[test]
fn article_limit_classifier_requires_kind_and_message() {
    // Exact (InvalidData + message): true.
    let limit = io::Error::new(io::ErrorKind::InvalidData, ARTICLE_LIMIT_ERROR);
    assert!(is_article_limit_error(&limit));

    // Same kind, other message: false.
    let other_message = io::Error::new(io::ErrorKind::InvalidData, "NNTP line exceeds 16 KiB");
    assert!(!is_article_limit_error(&other_message));

    // Other kind, same message: false.
    let other_kind = io::Error::new(io::ErrorKind::UnexpectedEof, ARTICLE_LIMIT_ERROR);
    assert!(!is_article_limit_error(&other_kind));

    // Neither: false.
    let neither = io::Error::new(io::ErrorKind::TimedOut, "timed out");
    assert!(!is_article_limit_error(&neither));
}

#[tokio::test]
async fn dot_block_limit_refusal_classifies_as_article_limit() {
    // A live refusal off the same code path must satisfy the classifier,
    // tying the truth table above to a real dot-block error.
    // "aaa\r\n" appends 5 bytes over a 4-byte cap: refused.
    let (mut t, _) = limited_transport(b"aaa\r\n.\r\n", 1, 4);
    let mut out = Vec::new();
    let err = t.read_dot_block(&mut out).await.unwrap_err();
    assert!(is_article_limit_error(&err));
}
