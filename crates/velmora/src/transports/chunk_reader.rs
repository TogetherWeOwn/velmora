//! Hands the chunks of a stream out as plain reads.
//!
//! A runtime stream delivers whole chunks. [`ChunkReader`] keeps the one
//! chunk it is reading from and copies out of it, so a caller with a small
//! buffer gets the rest on its next read without another call into the
//! runtime, and a chunk is copied exactly once, into the caller's buffer.
//!
//! The source of the chunks is a [`ChunkPort`]. On Workers it is a held
//! stream reader (`worker_stream`); the tests script one. Nothing here
//! depends on the runtime, so the order and completeness of the bytes is
//! tested natively.

use std::io;
use std::task::{Context, Poll};

/// Where chunks come from.
pub(crate) trait ChunkPort {
    /// One received chunk.
    type Chunk;

    /// Polls the read in flight; starts one when there is none. `Ok(None)`
    /// is the end of the stream.
    ///
    /// A started read belongs to the port, not to the caller's future: it
    /// stays in flight when the caller stops polling and the next call
    /// picks it up, so no byte the stream handed over is ever dropped.
    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Self::Chunk>>>;

    /// Bytes in `chunk`.
    fn chunk_len(chunk: &Self::Chunk) -> usize;

    /// Copies `dst.len()` bytes of `chunk`, from offset `at`, into `dst`.
    /// The caller keeps `at + dst.len() <= chunk_len(chunk)`.
    fn copy_out(chunk: &Self::Chunk, at: usize, dst: &mut [u8]);

    /// Takes back a chunk that has been read to its end (its buffer may be
    /// used for the next read).
    fn recycle(&mut self, chunk: Self::Chunk);
}

/// Reads bytes out of the chunks of a [`ChunkPort`], in order.
pub(crate) struct ChunkReader<P: ChunkPort> {
    port: P,
    /// The chunk being read and how much of it is already handed out.
    held: Option<(P::Chunk, usize)>,
}

impl<P: ChunkPort> ChunkReader<P> {
    pub(crate) fn new(port: P) -> Self {
        ChunkReader { port, held: None }
    }

    /// Reads up to `dst.len()` bytes. `Ok(0)` is the end of the stream
    /// (or an empty `dst`). An empty chunk that is not the end is skipped,
    /// never reported as the end.
    pub(crate) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if dst.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if let Some((chunk, at)) = self.held.take() {
                let len = P::chunk_len(&chunk);
                let n = dst.len().min(len - at);
                P::copy_out(&chunk, at, &mut dst[..n]);
                if at + n < len {
                    self.held = Some((chunk, at + n));
                } else {
                    self.port.recycle(chunk);
                }
                return Poll::Ready(Ok(n));
            }
            match self.port.poll_chunk(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(Some(chunk))) => {
                    if P::chunk_len(&chunk) == 0 {
                        self.port.recycle(chunk);
                    } else {
                        self.held = Some((chunk, 0));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::task::Waker;

    /// What the scripted stream does next.
    #[derive(Clone, Debug)]
    enum Step {
        Chunk(Vec<u8>),
        /// The read in flight is not ready on this poll.
        Wait,
        Fail(&'static str),
        End,
    }

    #[derive(Default)]
    struct Script {
        steps: VecDeque<Step>,
        /// Reads started, and whether one is in flight.
        started: usize,
        in_flight: bool,
        recycled: usize,
        handed_out: usize,
    }

    impl ChunkPort for Script {
        type Chunk = Vec<u8>;

        fn poll_chunk(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
            if !self.in_flight {
                self.in_flight = true;
                self.started += 1;
            }
            match self.steps.pop_front().unwrap_or(Step::End) {
                Step::Wait => Poll::Pending,
                Step::Chunk(bytes) => {
                    self.in_flight = false;
                    self.handed_out += 1;
                    Poll::Ready(Ok(Some(bytes)))
                }
                Step::Fail(msg) => {
                    self.in_flight = false;
                    Poll::Ready(Err(io::Error::other(msg)))
                }
                Step::End => {
                    self.in_flight = false;
                    Poll::Ready(Ok(None))
                }
            }
        }

        fn chunk_len(chunk: &Vec<u8>) -> usize {
            chunk.len()
        }

        fn copy_out(chunk: &Vec<u8>, at: usize, dst: &mut [u8]) {
            dst.copy_from_slice(&chunk[at..at + dst.len()]);
        }

        fn recycle(&mut self, _chunk: Vec<u8>) {
            self.recycled += 1;
        }
    }

    fn reader(steps: Vec<Step>) -> ChunkReader<Script> {
        ChunkReader::new(Script {
            steps: steps.into(),
            ..Script::default()
        })
    }

    /// Reads to the end with buffers of the sizes `sizes` (cycled); a
    /// pending poll is simply polled again, as a woken task would.
    fn drain(r: &mut ChunkReader<Script>, sizes: &[usize]) -> io::Result<Vec<u8>> {
        let mut cx = Context::from_waker(Waker::noop());
        let mut out = Vec::new();
        let mut turn = 0usize;
        loop {
            let mut buf = vec![0xEEu8; sizes[turn % sizes.len()]];
            turn += 1;
            match r.poll_read(&mut cx, &mut buf) {
                Poll::Pending => continue,
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Ready(Ok(0)) => return Ok(out),
                Poll::Ready(Ok(n)) => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// A small deterministic generator (the tests need no randomness crate).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self, below: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((self.0 >> 33) as usize) % below
        }
    }

    #[test]
    fn every_byte_once_and_in_order_for_any_chunking() {
        let mut rng = Lcg(7);
        for round in 0..400 {
            let total = rng.next(5000);
            let bytes: Vec<u8> = (0..total).map(|i| (i * 31 + round) as u8).collect();
            let mut steps = Vec::new();
            let mut at = 0;
            let mut chunks = 0;
            while at < total {
                match rng.next(6) {
                    0 => steps.push(Step::Wait),
                    1 => steps.push(Step::Chunk(Vec::new())),
                    _ => {
                        let n = (1 + rng.next(700)).min(total - at);
                        steps.push(Step::Chunk(bytes[at..at + n].to_vec()));
                        at += n;
                        chunks += 1;
                    }
                }
            }
            let empties = steps
                .iter()
                .filter(|s| matches!(s, Step::Chunk(c) if c.is_empty()))
                .count();
            let sizes = [1 + rng.next(900), 1 + rng.next(64), 1 + rng.next(4096)];
            let mut r = reader(steps);
            let got = drain(&mut r, &sizes).expect("no failure scripted");
            assert_eq!(got, bytes, "round {round}");
            // Every chunk came back to the port once it was read out.
            assert_eq!(r.port.recycled, chunks + empties, "round {round}");
            assert!(r.held.is_none());
        }
    }

    #[test]
    fn a_small_buffer_reads_one_chunk_without_another_read() {
        let mut r = reader(vec![Step::Chunk((0u8..100).collect())]);
        let mut cx = Context::from_waker(Waker::noop());
        let mut seen = Vec::new();
        for _ in 0..10 {
            let mut buf = [0u8; 10];
            assert!(matches!(
                r.poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(10))
            ));
            seen.extend_from_slice(&buf);
        }
        assert_eq!(seen, (0u8..100).collect::<Vec<_>>());
        assert_eq!(r.port.started, 1, "one chunk is one read of the stream");
        assert_eq!(r.port.recycled, 1);
    }

    #[test]
    fn an_empty_chunk_is_not_the_end() {
        let mut r = reader(vec![
            Step::Chunk(Vec::new()),
            Step::Wait,
            Step::Chunk(Vec::new()),
            Step::Chunk(b"late".to_vec()),
        ]);
        assert_eq!(drain(&mut r, &[64]).unwrap(), b"late");
    }

    #[test]
    fn the_end_is_zero_bytes_and_stays_the_end() {
        let mut r = reader(vec![Step::Chunk(b"ab".to_vec()), Step::End, Step::End]);
        let mut cx = Context::from_waker(Waker::noop());
        let mut buf = [0u8; 8];
        assert!(matches!(r.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(2))));
        assert!(matches!(r.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(0))));
        assert!(matches!(r.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(0))));
    }

    #[test]
    fn a_failure_is_reported_after_the_bytes_before_it() {
        let mut r = reader(vec![Step::Chunk(b"abc".to_vec()), Step::Fail("reset")]);
        let mut cx = Context::from_waker(Waker::noop());
        let mut buf = [0u8; 2];
        assert!(matches!(r.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(2))));
        assert!(matches!(r.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(1))));
        match r.poll_read(&mut cx, &mut buf) {
            Poll::Ready(Err(e)) => assert_eq!(e.to_string(), "reset"),
            other => panic!("expected the failure, got {other:?}"),
        }
    }

    #[test]
    fn a_read_given_up_while_pending_loses_nothing() {
        // The caller's future is dropped after a pending poll (a timeout);
        // the read stays in flight in the port and the next read gets its
        // bytes, into whatever buffer that read brings.
        let mut r = reader(vec![
            Step::Wait,
            Step::Wait,
            Step::Chunk(b"first".to_vec()),
            Step::Chunk(b"second".to_vec()),
        ]);
        let mut cx = Context::from_waker(Waker::noop());
        let mut abandoned = [0u8; 3];
        assert!(r.poll_read(&mut cx, &mut abandoned).is_pending());
        assert_eq!(abandoned, [0u8; 3], "a pending read writes nothing");
        assert_eq!(drain(&mut r, &[4]).unwrap(), b"firstsecond");
        assert_eq!(r.port.started, 3, "two chunks and the end; none restarted");
    }

    #[test]
    fn an_empty_buffer_reads_nothing_and_starts_nothing() {
        let mut r = reader(vec![Step::Chunk(b"x".to_vec())]);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(r.poll_read(&mut cx, &mut []), Poll::Ready(Ok(0))));
        assert_eq!(r.port.started, 0);
        assert_eq!(drain(&mut r, &[1]).unwrap(), b"x");
    }
}
