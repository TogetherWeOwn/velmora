//! Pins the NNTP transport line-bytes limit fail-closed.
//!
//! Boundary convention: a "line" is measured in wire bytes INCLUDING the
//! CRLF terminator, because [`BufferedTransport::read_line`] rejects on the
//! position of the LF (`pos >= MAX_LINE_BYTES`), not on the content length.
//! So a wire line of exactly `MAX_LINE_BYTES` bytes (content `MAX - 2` +
//! CRLF, LF at index `MAX - 1`) still parses, while a wire line of
//! `MAX_LINE_BYTES + 1` bytes (content `MAX - 1` + CRLF, LF at index `MAX`)
//! fails with exactly "NNTP line exceeds 16 KiB" and poisons the connection:
//! every later `read_line`, `write_line` and `read_dot_block` fails with the
//! "unusable; reconnect" `BrokenPipe` instead of touching the wire.
//!
//! Sibling coverage: `transport_framing.rs` pins the two rejection arms
//! (newline-found vs buffer-full) and the literal value; this file pins the
//! exact off-by-one boundary, the fail-closed poisoning, and the same
//! behavior through [`NntpClient`]. In-memory script transports only; no
//! network. Touches no transport implementation.
//!
//! Sensitivity: widening the `pos >= MAX_LINE_BYTES` guard to `>` (or
//! raising the constant) turns the `max_plus_one` tests red while the
//! `exactly_max` tests stay green (verified by mutation, restored).

#[path = "review_support/nntp.rs"]
mod support;

use std::io;

use nntune_core::error::Error;
use nntune_core::nntp::NntpConfig;
use nntune_core::transport::{BufferedTransport, Transport, MAX_LINE_BYTES};

/// Exact refusal message in `transport.rs` (`read_line_inner`, both arms).
const LINE_LIMIT_MESSAGE: &str = "NNTP line exceeds 16 KiB";
/// Message every operation returns once the connection is poisoned.
const UNUSABLE_MESSAGE: &str = "NNTP connection is unusable; reconnect before retrying";

struct Script {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl Transport for Script {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out
            .len()
            .min(self.chunk)
            .min(self.data.len().saturating_sub(self.pos));
        if n == 0 {
            return Ok(0);
        }
        out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    async fn write_all(&mut self, _bytes: &[u8]) -> io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn transport(data: &[u8], chunk: usize) -> BufferedTransport<Script> {
    BufferedTransport::new(Script {
        data: data.to_vec(),
        pos: 0,
        chunk,
    })
}

/// Wire line of exactly `len` content bytes + CRLF (`len + 2` wire bytes).
fn wire_line(content_len: usize) -> Vec<u8> {
    let mut line = vec![b'A'; content_len];
    line.extend_from_slice(b"\r\n");
    line
}

fn assert_unusable(err: &io::Error) {
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(err.to_string(), UNUSABLE_MESSAGE);
}

#[test]
fn max_line_bytes_is_16_kib() {
    assert_eq!(MAX_LINE_BYTES, 16 * 1024);
}

#[tokio::test]
async fn wire_line_of_exactly_max_bytes_parses() {
    // Content MAX - 2 + CRLF = exactly MAX wire bytes; the LF sits at
    // index MAX - 1, just under the `pos >= MAX_LINE_BYTES` guard.
    // A trailing reply proves framing stays aligned afterwards.
    for chunk in [1, 1000, 4096] {
        let mut data = wire_line(MAX_LINE_BYTES - 2);
        data.extend_from_slice(b"220 ok\r\n");
        let mut t = transport(&data, chunk);
        let line = t.read_line().await.expect("MAX wire bytes must parse");
        assert_eq!(line.len(), MAX_LINE_BYTES - 2, "chunk {chunk}");
        assert!(line.iter().all(|&b| b == b'A'), "chunk {chunk}");
        assert_eq!(t.read_line().await.unwrap(), b"220 ok", "chunk {chunk}");
    }
}

#[tokio::test]
async fn wire_line_of_max_plus_one_fails_closed_with_exact_message() {
    // Content MAX - 1 + CRLF = MAX + 1 wire bytes; the LF sits at index
    // MAX, tripping the guard. The arm (newline-found vs buffer-full)
    // depends on chunking; the message and the poisoning must not.
    for chunk in [1, 1000, 4096] {
        let mut t = transport(&wire_line(MAX_LINE_BYTES - 1), chunk);
        let err = t.read_line().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "chunk {chunk}");
        assert_eq!(err.to_string(), LINE_LIMIT_MESSAGE, "chunk {chunk}");

        // Fail-closed: the connection is unusable afterwards.
        assert_unusable(&t.read_line().await.unwrap_err());
        assert_unusable(&t.write_line(b"NOOP").await.unwrap_err());
        let mut out = Vec::new();
        assert_unusable(&t.read_dot_block(&mut out).await.unwrap_err());
        assert!(out.is_empty());
    }
}

#[tokio::test]
async fn nntp_reply_of_exactly_max_wire_bytes_parses() {
    // "111 " + text + CRLF = exactly MAX wire bytes through NntpClient.
    let text = "X".repeat(MAX_LINE_BYTES - 6);
    let wire = format!("111 {text}\r\n");
    assert_eq!(wire.len(), MAX_LINE_BYTES);
    let config = NntpConfig::default();
    let (mut client, _) = support::connect(wire.as_bytes(), 1000, &config).await;
    let reply = client.raw_command("DATE").await.expect("MAX wire bytes");
    assert_eq!(reply.code, 111);
    assert_eq!(reply.text, text);
}

#[tokio::test]
async fn nntp_reply_of_max_plus_one_wire_bytes_fails_and_poisons_client() {
    // "111 " + text + CRLF = MAX + 1 wire bytes: the reply read fails with
    // the exact transport message, and the client stays unusable.
    let text = "X".repeat(MAX_LINE_BYTES - 5);
    let wire = format!("111 {text}\r\n");
    assert_eq!(wire.len(), MAX_LINE_BYTES + 1);
    let config = NntpConfig::default();
    let (mut client, trace) = support::connect(wire.as_bytes(), 1000, &config).await;
    let writes_before = trace.lock().unwrap().written.len();

    let Err(Error::Io(io_err)) = client.raw_command("DATE").await else {
        panic!("MAX + 1 wire bytes must fail the reply read");
    };
    assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(io_err.to_string(), LINE_LIMIT_MESSAGE);

    // Fail-closed: no further command reaches the wire.
    let mut out = Vec::new();
    for result in [
        client.stat("a@x").await.map(|_| ()),
        client.raw_command("DATE").await.map(|_| ()),
        client.raw_dot_block(&mut out).await,
    ] {
        let Err(Error::Io(io_err)) = result else {
            panic!("poisoned client must stay unusable");
        };
        assert_eq!(io_err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(io_err.to_string(), UNUSABLE_MESSAGE);
    }
    assert!(out.is_empty());
    // Only the failed "DATE\r\n" reached the wire; the poisoned follow-ups
    // wrote nothing.
    assert_eq!(
        trace.lock().unwrap().written.len(),
        writes_before + b"DATE\r\n".len()
    );
}
