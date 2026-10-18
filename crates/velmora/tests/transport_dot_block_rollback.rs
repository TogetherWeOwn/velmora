//! Pins dot-block failure rollback and connection poisoning.
//!
//! `BufferedTransport::read_dot_block` (`transport.rs`) rolls back partial
//! output (`out.truncate(start)`) and poisons the connection (`invalidate()`)
//! when a dot-block fails mid-stream. The article-limit arm already has
//! rollback/poisoning coverage in `review_article_direct.rs`; this file pins
//! the non-limit arms: a truncated block (EOF before the lone `.`) and an
//! injected transport error after a complete line. Both start from a
//! pre-filled `out`, assert byte-exact rollback to the prefix, and assert
//! every subsequent entrypoint fails with the unusable-connection error
//! without touching the wire. In-memory script transport only; no network,
//! no fixture server. Touches no transport implementation.

use std::io;
use std::sync::{Arc, Mutex};

use nntune_core::transport::{BufferedTransport, Transport};

const UNUSABLE_MESSAGE: &str = "NNTP connection is unusable; reconnect before retrying";

#[derive(Default)]
struct Trace {
    written: Vec<u8>,
    writes: usize,
}

struct Script {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    /// Byte position at which reads start failing with `fail_kind`; `None`
    /// means reads fail only at EOF (`Ok(0)`).
    fail_at: Option<usize>,
    fail_kind: io::ErrorKind,
    trace: Arc<Mutex<Trace>>,
}

impl Transport for Script {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(fail_at) = self.fail_at {
            if self.pos >= fail_at {
                return Err(io::Error::new(self.fail_kind, "injected mid-block failure"));
            }
        }
        let mut n = out
            .len()
            .min(self.chunk)
            .min(self.data.len().saturating_sub(self.pos));
        if let Some(fail_at) = self.fail_at {
            n = n.min(fail_at.saturating_sub(self.pos));
            if n == 0 {
                return Err(io::Error::new(self.fail_kind, "injected mid-block failure"));
            }
        }
        if n == 0 {
            // EOF: the outer transport reports the truncated dot-block as
            // UnexpectedEof, which triggers the rollback/poison arm.
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

fn transport(
    data: &[u8],
    chunk: usize,
    fail_at: Option<usize>,
) -> (BufferedTransport<Script>, Arc<Mutex<Trace>>) {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let inner = Script {
        data: data.to_vec(),
        pos: 0,
        chunk,
        fail_at,
        fail_kind: io::ErrorKind::ConnectionReset,
        trace: trace.clone(),
    };
    (BufferedTransport::new(inner), trace)
}

fn assert_unusable(err: &io::Error, entrypoint: &str) {
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{entrypoint}");
    assert_eq!(err.to_string(), UNUSABLE_MESSAGE, "{entrypoint}");
}

async fn assert_every_entrypoint_unusable<T: Transport>(
    t: &mut BufferedTransport<T>,
    trace: &Arc<Mutex<Trace>>,
) {
    let writes = trace.lock().unwrap().written.len();
    let err = t.read_line().await.unwrap_err();
    assert_unusable(&err, "read_line after dot-block failure");
    // A second dot-block attempt fails closed without touching its own `out`.
    let mut next = b"sentinel".to_vec();
    let err = t.read_dot_block(&mut next).await.unwrap_err();
    assert_unusable(&err, "read_dot_block after dot-block failure");
    assert_eq!(next, b"sentinel");
    let err = t.write_line(b"NOOP").await.unwrap_err();
    assert_unusable(&err, "write_line after dot-block failure");
    assert_eq!(trace.lock().unwrap().written.len(), writes);
}

#[tokio::test]
async fn truncated_dot_block_rolls_back_prefill_and_poisons_connection() {
    // "..a\r\nbb\r\n" would append ".a\r\nbb\r\n" (8 bytes) before EOF
    // cuts the block short of its lone-`.` terminator: the failure lands
    // after partial output exists, so exact rollback is observable.
    for chunk in [1, 4096] {
        let (mut t, trace) = transport(b"..a\r\nbb\r\n", chunk, None);
        let prefix = b"PINNED-PREFIX:";
        let mut out = prefix.to_vec();
        let err = t.read_dot_block(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "chunk {chunk}");
        // Byte-exact rollback: exactly the N prefilled bytes remain.
        assert_eq!(out, prefix, "chunk {chunk}");
        assert_eq!(out.len(), prefix.len(), "chunk {chunk}");
        assert_every_entrypoint_unusable(&mut t, &trace).await;
    }
}

#[tokio::test]
async fn transport_error_mid_block_rolls_back_prefill_and_poisons_connection() {
    // First line ("aa\r\n") is delivered whole; reads then fail with
    // ConnectionReset mid-block. Partial output must still roll back.
    let wire = b"aa\r\nbbb\r\n.\r\n";
    for chunk in [1, 4096] {
        let (mut t, trace) = transport(wire, chunk, Some(5));
        let prefix = b"PINNED-PREFIX:";
        let mut out = prefix.to_vec();
        let err = t.read_dot_block(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset, "chunk {chunk}");
        assert_eq!(out, prefix, "chunk {chunk}");
        assert_eq!(out.len(), prefix.len(), "chunk {chunk}");
        assert_every_entrypoint_unusable(&mut t, &trace).await;
    }
}
