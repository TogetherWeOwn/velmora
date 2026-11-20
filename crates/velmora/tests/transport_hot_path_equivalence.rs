//! The line reader and the dot-block writer against plain models.
//!
//! `BufferedTransport` scans with vector searches and reads in large
//! chunks. These tests hold it to byte-at-a-time models of the wire rules:
//! same bytes out, same refusals, whatever way the bytes arrive.

use std::future::Future;
use std::io;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use velmora::transport::{BufferedTransport, Transport, ARTICLE_LIMIT_ERROR, MAX_LINE_BYTES};

fn now<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("in-memory transport never waits"),
    }
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> usize {
        (self.next() % n) as usize
    }
}

/// Hands `input` out in pieces of the given sizes (cycled) and records
/// every write.
struct Script {
    input: Vec<u8>,
    at: usize,
    pieces: Vec<usize>,
    turn: usize,
    written: Vec<u8>,
}

impl Script {
    fn new(input: Vec<u8>, pieces: Vec<usize>) -> Self {
        Script {
            input,
            at: 0,
            pieces,
            turn: 0,
            written: Vec::new(),
        }
    }
}

impl Transport for Script {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let piece = self.pieces[self.turn % self.pieces.len()];
        self.turn += 1;
        let n = piece.min(buf.len()).min(self.input.len() - self.at);
        buf[..n].copy_from_slice(&self.input[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.written.extend_from_slice(buf);
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Writing: framing check and dot-stuffing
// ---------------------------------------------------------------------------

/// The dot-block writer one byte at a time: the stuffed bytes, or the
/// refusal text.
fn model_stuff(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut stuffed = Vec::new();
    let mut at_line_start = true;
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\r' => {
                if data.get(i + 1) != Some(&b'\n') {
                    return Err("NNTP dot-block holds a bare CR outside CRLF");
                }
                stuffed.extend_from_slice(b"\r\n");
                i += 2;
                at_line_start = true;
            }
            b'\n' => return Err("NNTP dot-block holds a bare LF outside CRLF"),
            b'.' if at_line_start => {
                stuffed.extend_from_slice(b"..");
                i += 1;
                at_line_start = false;
            }
            b => {
                stuffed.push(b);
                i += 1;
                at_line_start = false;
            }
        }
    }
    if !stuffed.ends_with(b"\r\n") {
        stuffed.extend_from_slice(b"\r\n");
    }
    stuffed.extend_from_slice(b".\r\n");
    Ok(stuffed)
}

fn assert_write_matches(data: &[u8]) {
    let mut transport = BufferedTransport::new(Script::new(Vec::new(), vec![1]));
    let got = now(transport.write_dot_block(data));
    let wire = transport.into_inner().written;
    match model_stuff(data) {
        Ok(want) => {
            got.unwrap_or_else(|err| panic!("{data:?} refused: {err}"));
            assert!(wire == want, "{data:?}: wire bytes differ");
        }
        Err(reason) => {
            let err = got.expect_err("the model refuses this block");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{data:?}");
            assert_eq!(err.to_string(), reason, "{data:?}");
            assert!(wire.is_empty(), "{data:?}: bytes written on a refusal");
        }
    }
}

#[test]
fn dot_block_writer_matches_the_model_on_every_short_block() {
    // Every block of up to 8 bytes over the four bytes that matter.
    let alphabet = *b"\r\n.a";
    for len in 0..=8u32 {
        for code in 0..4u32.pow(len) {
            let data: Vec<u8> = (0..len)
                .map(|k| alphabet[(code >> (2 * k)) as usize & 3])
                .collect();
            assert_write_matches(&data);
        }
    }
}

#[test]
fn dot_block_writer_matches_the_model_on_article_sized_blocks() {
    let mut rng = XorShift(0x5151_5151_abab_abab);
    for round in 0..300 {
        let mut data = Vec::new();
        let lines = rng.below(400);
        for _ in 0..lines {
            let len = rng.below(140);
            for _ in 0..len {
                let roll = rng.next();
                data.push(match roll % 11 {
                    0..=2 => b'.',
                    _ => match (roll >> 16) as u8 {
                        b'\r' | b'\n' => b'x',
                        other => other,
                    },
                });
            }
            data.extend_from_slice(b"\r\n");
        }
        // A few rounds without the final CRLF, and a few with a stray
        // CR or LF somewhere.
        if round % 5 == 0 && !data.is_empty() {
            data.truncate(data.len() - 2);
        }
        if round % 7 == 0 && !data.is_empty() {
            let at = rng.below(data.len() as u64);
            data[at] = if round % 2 == 0 { b'\r' } else { b'\n' };
        }
        assert_write_matches(&data);
    }
}

// ---------------------------------------------------------------------------
// Reading: lines and dot-blocks
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum ReadEnd {
    /// The block, and the line that follows it on the wire.
    Block(Vec<u8>, Result<Vec<u8>, (io::ErrorKind, String)>),
    Refused(io::ErrorKind, String),
}

/// One line off the front of `rest`, by the reader's rules.
fn model_line<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], (io::ErrorKind, String)> {
    let too_long = || {
        (
            io::ErrorKind::InvalidData,
            "NNTP line exceeds 16 KiB".to_string(),
        )
    };
    match rest.iter().position(|&b| b == b'\n') {
        Some(pos) if pos >= MAX_LINE_BYTES => Err(too_long()),
        Some(pos) => {
            let mut line = &rest[..pos];
            *rest = &rest[pos + 1..];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
            Ok(line)
        }
        None if rest.len() >= MAX_LINE_BYTES => Err(too_long()),
        None if rest.is_empty() => Err((
            io::ErrorKind::UnexpectedEof,
            "NNTP connection closed mid-line".to_string(),
        )),
        None => Err((
            io::ErrorKind::UnexpectedEof,
            "NNTP connection closed without CRLF".to_string(),
        )),
    }
}

fn model_read(stream: &[u8], limit: usize) -> ReadEnd {
    let mut rest = stream;
    let mut out = Vec::new();
    loop {
        let line = match model_line(&mut rest) {
            Ok(line) => line,
            Err((kind, text)) => return ReadEnd::Refused(kind, text),
        };
        if line == b"." {
            let after = model_line(&mut rest).map(<[u8]>::to_vec);
            return ReadEnd::Block(out, after);
        }
        let content = if line.starts_with(b"..") {
            &line[1..]
        } else {
            line
        };
        if content.len() + 2 > limit.saturating_sub(out.len()) {
            return ReadEnd::Refused(io::ErrorKind::InvalidData, ARTICLE_LIMIT_ERROR.to_string());
        }
        out.extend_from_slice(content);
        out.extend_from_slice(b"\r\n");
    }
}

fn real_read(stream: &[u8], limit: usize, pieces: Vec<usize>) -> ReadEnd {
    let mut transport =
        BufferedTransport::with_article_limit(Script::new(stream.to_vec(), pieces), limit);
    let mut out = b"kept".to_vec();
    match now(transport.read_dot_block(&mut out)) {
        Ok(()) => {
            assert_eq!(&out[..4], b"kept");
            let after = now(transport.read_line()).map_err(|err| (err.kind(), err.to_string()));
            ReadEnd::Block(out[4..].to_vec(), after)
        }
        Err(err) => {
            assert_eq!(out, b"kept", "a refused block must roll back");
            // And the connection is unusable from here on.
            let again = now(transport.read_line()).unwrap_err();
            assert_eq!(again.kind(), io::ErrorKind::BrokenPipe);
            ReadEnd::Refused(err.kind(), err.to_string())
        }
    }
}

fn random_stream(rng: &mut XorShift) -> Vec<u8> {
    let mut stream = Vec::new();
    let lines = rng.below(60);
    for _ in 0..lines {
        let len = match rng.below(40) {
            0 => MAX_LINE_BYTES - 3 + rng.below(6),
            1 => 0,
            2 => 4090 + rng.below(12),
            _ => rng.below(200),
        };
        for k in 0..len {
            let roll = rng.next();
            stream.push(match roll % 13 {
                0 | 1 => b'.',
                2 if k + 1 == len => b'\r',
                3 if roll % 97 == 3 => b'\r',
                _ => match (roll >> 16) as u8 {
                    b'\n' => b'y',
                    other => other,
                },
            });
        }
        stream.extend_from_slice(if rng.below(9) == 0 { b"\n" } else { b"\r\n" });
        if rng.below(50) == 0 {
            stream.extend_from_slice(b".\r\n");
        }
    }
    match rng.below(8) {
        0 => {}
        1 => stream.extend_from_slice(b".\r\n"),
        2 => stream.extend_from_slice(b".\n222 next\r\n"),
        3 => stream.extend_from_slice(b".\r\n222 cut"),
        _ => stream.extend_from_slice(b".\r\n222 next line\r\nmore\r\n"),
    }
    stream
}

#[test]
fn dot_block_reader_matches_the_model_however_the_bytes_arrive() {
    let mut rng = XorShift(0x7777_1234_4321_7777);
    let (mut blocks, mut refusals) = (0, 0);
    for _ in 0..1500 {
        let stream = random_stream(&mut rng);
        let limit = match rng.below(4) {
            0 => rng.below(4000),
            1 => stream.len().saturating_sub(rng.below(40)),
            _ => usize::MAX,
        };
        let want = model_read(&stream, limit.min(velmora::transport::MAX_ARTICLE_BYTES));
        for pieces in [
            vec![1],
            vec![4096],
            vec![1 << 20],
            vec![1 + rng.below(9), 1 + rng.below(700), 1 + rng.below(70_000)],
        ] {
            let got = real_read(&stream, limit, pieces.clone());
            assert!(
                got == want,
                "pieces {pieces:?}, limit {limit}, stream of {} bytes: reader and model disagree",
                stream.len()
            );
        }
        match want {
            ReadEnd::Block(..) => blocks += 1,
            ReadEnd::Refused(..) => refusals += 1,
        }
    }
    assert!(blocks > 200, "blocks {blocks}");
    assert!(refusals > 200, "refusals {refusals}");
}

#[test]
fn line_reader_matches_the_model_line_by_line() {
    let mut rng = XorShift(0x0f0f_f0f0_1357_2468);
    for _ in 0..400 {
        let stream = random_stream(&mut rng);
        for pieces in [vec![1], vec![3, 5000], vec![1 << 20]] {
            let mut transport = BufferedTransport::new(Script::new(stream.clone(), pieces));
            let mut rest = &stream[..];
            loop {
                let want = model_line(&mut rest).map(<[u8]>::to_vec);
                let got = now(transport.read_line()).map_err(|err| (err.kind(), err.to_string()));
                assert_eq!(got, want);
                if want.is_err() {
                    break;
                }
            }
        }
    }
}
