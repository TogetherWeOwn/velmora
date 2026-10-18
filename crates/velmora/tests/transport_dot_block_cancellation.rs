//! Pins dot-block cancellation rollback and connection poisoning.
//!
//! Returned EOF/transport errors already roll back partial output and poison
//! the connection (`transport_dot_block_rollback.rs`). This file pins the
//! distinct cancellation path: a real `read_dot_block` future that has
//! appended at least one line and then returns `Poll::Pending` is dropped.
//! Dropping that pending future must restore the caller's original output
//! prefix and make every subsequent read/write fail before touching the
//! underlying transport.
//!
//! Positive controls pin the boundaries that must not change: dropping the
//! future before its first poll neither consumes input nor poisons the
//! connection, a completed dot-block retains its output and stays usable,
//! and a returned EOF still rolls back and poisons exactly as before.
//!
//! In-memory scripted transport only; no network, no fixture server.
//! Touches no transport implementation.

use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use nntune_core::transport::{BufferedTransport, Transport};

const UNUSABLE_MESSAGE: &str = "NNTP connection is unusable; reconnect before retrying";
const PREFIX: &[u8] = b"PINNED-PREFIX:";

#[derive(Default)]
struct Trace {
    reads: usize,
    written: Vec<u8>,
    writes: usize,
}

/// Scripted transport: delivers `data` in `chunk`-byte reads. Once `pos`
/// reaches `pend_after`, reads never resolve, so a caller awaiting the next
/// line observes `Poll::Pending` with work already done.
struct Script {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    pend_after: Option<usize>,
    trace: Arc<Mutex<Trace>>,
}

impl Transport for Script {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.trace.lock().unwrap().reads += 1;
        if let Some(pend_after) = self.pend_after {
            if self.pos >= pend_after {
                std::future::pending::<()>().await;
            }
        }
        let mut n = out
            .len()
            .min(self.chunk)
            .min(self.data.len().saturating_sub(self.pos));
        if let Some(pend_after) = self.pend_after {
            n = n.min(pend_after.saturating_sub(self.pos));
        }
        if n == 0 {
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
    pend_after: Option<usize>,
) -> (BufferedTransport<Script>, Arc<Mutex<Trace>>) {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let inner = Script {
        data: data.to_vec(),
        pos: 0,
        chunk,
        pend_after,
        trace: trace.clone(),
    };
    (BufferedTransport::new(inner), trace)
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

/// Polls a future exactly once. The scripted transport only pends where it
/// is scripted to, so one poll runs the dot-block read up to that point.
fn poll_once<F: Future>(future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    future.poll(&mut cx)
}

fn assert_unusable(err: &io::Error, entrypoint: &str) {
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{entrypoint}");
    assert_eq!(err.to_string(), UNUSABLE_MESSAGE, "{entrypoint}");
}

async fn assert_every_entrypoint_unusable_without_touching_transport(
    t: &mut BufferedTransport<Script>,
    trace: &Arc<Mutex<Trace>>,
) {
    let (reads, writes, written) = {
        let trace = trace.lock().unwrap();
        (trace.reads, trace.writes, trace.written.len())
    };
    let err = t.read_line().await.unwrap_err();
    assert_unusable(&err, "read_line after cancelled dot-block");
    // A second dot-block attempt fails closed without touching its own `out`.
    let mut next = b"sentinel".to_vec();
    let err = t.read_dot_block(&mut next).await.unwrap_err();
    assert_unusable(&err, "read_dot_block after cancelled dot-block");
    assert_eq!(next, b"sentinel");
    let err = t.write_line(b"NOOP").await.unwrap_err();
    assert_unusable(&err, "write_line after cancelled dot-block");
    let trace = trace.lock().unwrap();
    assert_eq!(trace.reads, reads, "underlying reads after poisoning");
    assert_eq!(trace.writes, writes, "underlying writes after poisoning");
    assert_eq!(trace.written.len(), written);
}

#[tokio::test]
async fn dropping_pending_dot_block_after_one_line_rolls_back_and_poisons() {
    // The first line ("aa\r\n", 4 wire bytes) is delivered whole; the next
    // read then pends forever. One poll therefore appends that line to the
    // caller's buffer and returns Pending inside the following line read.
    for chunk in [1, 4096] {
        let (mut t, trace) = transport(b"aa\r\n", chunk, Some(4));
        let mut out = PREFIX.to_vec();
        let reads_after_poll = {
            let mut future = pin!(t.read_dot_block(&mut out));
            assert!(
                poll_once(future.as_mut()).is_pending(),
                "chunk {chunk}: dot-block must pend after the first line"
            );
            let reads = trace.lock().unwrap().reads;
            assert!(
                reads >= 2,
                "chunk {chunk}: first line consumed, next read pending (reads={reads})"
            );
            reads
            // `future` is dropped here, cancelling the pending dot-block
            // after one line was appended to `out`.
        };
        assert_eq!(
            trace.lock().unwrap().reads,
            reads_after_poll,
            "chunk {chunk}: dropping must not read further"
        );
        // Byte-exact rollback: exactly the prefilled prefix remains, the
        // appended "aa\r\n" from the cancelled block is gone.
        assert_eq!(out, PREFIX, "chunk {chunk}");
        assert_eq!(out.len(), PREFIX.len(), "chunk {chunk}");
        assert_every_entrypoint_unusable_without_touching_transport(&mut t, &trace).await;
    }
}

#[tokio::test]
async fn dropping_pending_dot_block_after_two_lines_rolls_back_all_of_them() {
    // Both lines are delivered, then the read for the terminator pends:
    // rollback must remove every line the cancelled block appended, not
    // just the most recent one.
    let wire = b"aa\r\n..b\r\n";
    let (mut t, trace) = transport(wire, 4096, Some(wire.len()));
    let mut out = PREFIX.to_vec();
    {
        let mut future = pin!(t.read_dot_block(&mut out));
        assert!(poll_once(future.as_mut()).is_pending());
    }
    assert_eq!(out, PREFIX);
    assert_every_entrypoint_unusable_without_touching_transport(&mut t, &trace).await;
}

#[tokio::test]
async fn dropping_dot_block_before_first_poll_neither_consumes_nor_poisons() {
    let wire = b"aa\r\n.\r\n";
    let (mut t, trace) = transport(wire, 4096, None);
    let mut out = PREFIX.to_vec();
    {
        // Created and dropped at the end of this block without a single poll.
        let _future = pin!(t.read_dot_block(&mut out));
    }
    assert_eq!(out, PREFIX);
    assert_eq!(trace.lock().unwrap().reads, 0, "unpolled future read input");
    assert_eq!(trace.lock().unwrap().writes, 0);

    // The same connection then completes the same dot-block normally.
    t.read_dot_block(&mut out).await.unwrap();
    let mut expected = PREFIX.to_vec();
    expected.extend_from_slice(b"aa\r\n");
    assert_eq!(out, expected);
    t.write_line(b"NOOP").await.unwrap();
    assert_eq!(trace.lock().unwrap().written, b"NOOP\r\n");
}

#[tokio::test]
async fn completed_dot_block_retains_output_and_connection_stays_usable() {
    let wire = b"..a\r\nbb\r\n.\r\n221 next\r\n";
    let (mut t, trace) = transport(wire, 4096, None);
    let mut out = PREFIX.to_vec();
    t.read_dot_block(&mut out).await.unwrap();
    let mut expected = PREFIX.to_vec();
    expected.extend_from_slice(b".a\r\nbb\r\n");
    assert_eq!(out, expected);

    assert_eq!(t.read_line().await.unwrap(), b"221 next");
    t.write_line(b"NOOP").await.unwrap();
    assert_eq!(trace.lock().unwrap().written, b"NOOP\r\n");
}

#[tokio::test]
async fn returned_eof_error_still_rolls_back_and_poisons() {
    // Positive control for the pre-existing returned-error contract: a
    // truncated block (EOF before the lone `.`) keeps its current behavior
    // alongside whatever cancellation cleanup is added.
    let (mut t, trace) = transport(b"aa\r\n", 4096, None);
    let mut out = PREFIX.to_vec();
    let err = t.read_dot_block(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(out, PREFIX);
    assert_every_entrypoint_unusable_without_touching_transport(&mut t, &trace).await;
}
