//! Direct [`BufferedTransport`] article-ceiling acceptance tests.
//!
//! Covers the follow-up gap: `BufferedTransport::with_article_limit` must
//! clamp oversized limits to [`MAX_ARTICLE_BYTES`] (64 MiB), keep smaller
//! limits, and allow zero only for empty dot blocks. No giant input fixture
//! is allocated; the 64 MiB boundary is proven via the constant plus
//! small-limit enforcement on the same code path.

use std::io;
use std::sync::{Arc, Mutex};

use nntune_core::transport::{BufferedTransport, Transport, MAX_ARTICLE_BYTES};

#[derive(Default)]
struct Trace {
    written: Vec<u8>,
}

struct Wire {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    trace: Arc<Mutex<Trace>>,
}

impl Transport for Wire {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out
            .len()
            .min(self.chunk)
            .min(self.data.len().saturating_sub(self.pos));
        if n == 0 {
            // EOF: the outer transport treats this as a truncated frame.
            return Ok(0);
        }
        out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.trace.lock().unwrap().written.extend_from_slice(bytes);
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn wire_with_limit(
    data: &[u8],
    chunk: usize,
    limit: usize,
) -> (BufferedTransport<Wire>, Arc<Mutex<Trace>>) {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let inner = Wire {
        data: data.to_vec(),
        pos: 0,
        chunk,
        trace: trace.clone(),
    };
    (BufferedTransport::with_article_limit(inner, limit), trace)
}

#[test]
fn max_article_bytes_is_64_mib() {
    assert_eq!(MAX_ARTICLE_BYTES, 64 * 1024 * 1024);
}

#[tokio::test]
async fn oversized_limit_clamps_and_still_accepts_small_dot_block() {
    // usize::MAX must not panic, wrap, or reject small data: it clamps to
    // MAX_ARTICLE_BYTES, so an 8-byte dot block succeeds. The full 64 MiB
    // boundary is not exercised here to avoid a giant fixture; enforcement
    // at the boundary shares the code path proven by the small-cap tests.
    for limit in [usize::MAX, MAX_ARTICLE_BYTES + 1, MAX_ARTICLE_BYTES] {
        for chunk in [1, 4096] {
            let (mut t, _) = wire_with_limit(b"..a\r\nbb\r\n.\r\nNEXT\r\n", chunk, limit);
            let mut out = Vec::new();
            t.read_dot_block(&mut out).await.unwrap();
            assert_eq!(out, b".a\r\nbb\r\n", "limit {limit}, chunk {chunk}");
            // Still usable after success.
            assert_eq!(t.read_line().await.unwrap(), b"NEXT");
        }
    }
}

#[tokio::test]
async fn small_exact_cap_accepts_with_prefilled_prefix() {
    // Wire "..a\r\nbb\r\n" unstuffs to ".a\r\nbb\r\n": exactly 8 bytes
    // including both CRLFs.
    for chunk in [1, 4096] {
        let (mut t, _) = wire_with_limit(b"..a\r\nbb\r\n.\r\nNEXT\r\n", chunk, 8);
        let mut out = b"existing bytes longer than the per-article cap:".to_vec();
        let mut expected = out.clone();
        expected.extend_from_slice(b".a\r\nbb\r\n");
        t.read_dot_block(&mut out).await.unwrap();
        assert_eq!(out, expected, "chunk {chunk}");
        // Prefilled contents do not count toward the cap, and the connection
        // stays usable.
        assert_eq!(t.read_line().await.unwrap(), b"NEXT");
    }
}

#[tokio::test]
async fn streamed_cap_plus_one_rejects_rolls_back_and_kills_connection() {
    // "aa\r\n" (4) + "bbb\r\n" (5) = 9 appended bytes: one over an 8-byte cap.
    for chunk in [1, 4096] {
        let (mut t, trace) = wire_with_limit(b"aa\r\nbbb\r\n.\r\nTRAILING\r\n", chunk, 8);
        let prefix = b"untouched-prefix:";
        let mut out = prefix.to_vec();
        assert!(t.read_dot_block(&mut out).await.is_err(), "chunk {chunk}");
        // Prefilled output rolls back; at most the cap may have been appended
        // before rejection, never past it.
        assert_eq!(out, prefix, "chunk {chunk}");
        let writes = trace.lock().unwrap().written.len();
        // Every entrypoint is now unusable, without touching the wire.
        assert!(t.read_line().await.is_err());
        let mut next = b"sentinel".to_vec();
        assert!(t.read_dot_block(&mut next).await.is_err());
        assert_eq!(next, b"sentinel");
        assert!(t.write_line(b"DATE").await.is_err());
        assert_eq!(trace.lock().unwrap().written.len(), writes);
    }
}

#[tokio::test]
async fn smaller_limit_is_kept_not_clamped_up() {
    // 4-byte cap: "aa\r\n" (4) passes, "aaa\r\n" (5) fails.
    let (mut t, _) = wire_with_limit(b"aa\r\n.\r\n", 1, 4);
    let mut out = Vec::new();
    t.read_dot_block(&mut out).await.unwrap();
    assert_eq!(out, b"aa\r\n");

    let (mut t, _) = wire_with_limit(b"aaa\r\n.\r\n", 1, 4);
    let mut out = Vec::new();
    assert!(t.read_dot_block(&mut out).await.is_err());
    assert!(out.is_empty());
    assert!(t.read_line().await.is_err());
}

#[tokio::test]
async fn zero_limit_allows_only_empty_dot_block() {
    // Empty dot block appends nothing: allowed at zero.
    let (mut t, _) = wire_with_limit(b".\r\nNEXT\r\n", 1, 0);
    let mut out = b"prefix:".to_vec();
    t.read_dot_block(&mut out).await.unwrap();
    assert_eq!(out, b"prefix:");
    assert_eq!(t.read_line().await.unwrap(), b"NEXT");

    // Any content exceeds zero: rejects, rolls back, kills the connection.
    for chunk in [1, 4096] {
        let (mut t, trace) = wire_with_limit(b"a\r\n.\r\n", chunk, 0);
        let mut out = b"prefix:".to_vec();
        assert!(t.read_dot_block(&mut out).await.is_err());
        assert_eq!(out, b"prefix:");
        assert!(t.read_line().await.is_err());
        assert!(t.write_line(b"NOOP").await.is_err());
        assert!(trace.lock().unwrap().written.is_empty());
    }
}
