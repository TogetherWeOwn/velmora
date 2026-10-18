//! Tests-only pin: ciphertext-range overflow fails closed as `InvalidInput`.
//!
//! Contract under test (unchanged implementation in `src/decrypt.rs`):
//!
//! - Whenever a ciphertext extent `off..off + len` is not representable in
//!   `u64`, the shared exact-read helper rejects it up front with
//!   `io::ErrorKind::InvalidInput` and the exact message
//!   `"ciphertext range exceeds addressable offsets"` — before issuing any
//!   source request for the overflowing extent. It never wraps to a small
//!   offset, and it never degrades to `UnexpectedEof` when the source would
//!   otherwise report end-of-source.
//! - On the AES-CBC seam the `io` error surfaces unchanged as `Error::Io`,
//!   so both the kind and the message are directly observable. On the
//!   rclone seam a block-extent overflow is wrapped once as
//!   `Error::Decrypt("rclone block {n}: {io}")`; the embedded message is
//!   pinned by containment there.
//!
//! Note on read counts (`Ruling`): `aes_cbc::read_at` serves the preceding
//! 16-byte IV *before* the ciphertext extent, so an `off = u64::MAX`
//! rejection observably follows the IV reads — total reads are 3 with the
//! 7-byte chunk below, not zero. "Zero source reads" holds for the
//! overflowing extent itself: no request is ever issued at or above the
//! ciphertext offset, and no request wraps below the high window. Each
//! test pins the exact read offsets to prove it.
//!
//! Note on mid-stream coverage: with the up-front extent check in place,
//! the loop's per-advance `checked_add` is defense-in-depth that honest
//! short reads cannot reach (every advance stays inside the validated
//! extent). The byte-at-a-time test below pins the observable half of
//! that: a failure that lands mid-operation, after 16 one-byte IV reads,
//! still reports `InvalidInput`, never a wrapped offset.
//!
//! Sensitivity (mutants run 2026-10-18, restored afterwards):
//! - message text changed -> all `InvalidInput` tests fail on the exact
//!   message assertion;
//! - `range_overflow` kind changed to `UnexpectedEof` -> kind assertions
//!   fail;
//! - up-front `checked_add` removed -> the endless-source tests issue
//!   reads at/above the ciphertext offset (offset assertions fail) and the
//!   EOF-source test degrades to `UnexpectedEof` (kind assertion fails).
//!
//! All fixtures are synthetic and offline: tiny destinations, no large
//! allocations, no real keys.

use std::cell::RefCell;
use std::io;

use nntune_core::decrypt::rclone::{
    CIPHER_BLOCK_SIZE, CIPHER_OVERHEAD, HEADER_SIZE, PLAIN_BLOCK_SIZE,
};
use nntune_core::decrypt::{aes_cbc, rclone, ReadAt};
use nntune_core::Error;

const RANGE_OVERFLOW_MSG: &str = "ciphertext range exceeds addressable offsets";

/// Fails the test unless `result` is exactly the shared-helper overflow:
/// `Error::Io` with kind `InvalidInput` and the exact message.
fn expect_range_overflow(result: Result<usize, Error>, what: &str) {
    match result {
        Err(Error::Io(e)) => {
            assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidInput,
                "{what}: overflow must be InvalidInput, got {:?}: {e}",
                e.kind(),
            );
            assert_eq!(
                e.to_string(),
                RANGE_OVERFLOW_MSG,
                "{what}: overflow message pin mismatch: {e}"
            );
        }
        Err(other) => panic!("{what}: expected Error::Io overflow, got {other:?}"),
        Ok(n) => panic!("{what}: expected overflow rejection, got Ok({n})"),
    }
}

/// Endless source in fixed short reads; records every requested offset.
struct EndlessChunk {
    chunk: usize,
    fill: u8,
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for EndlessChunk {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        let n = buf.len().min(self.chunk);
        buf[..n].fill(self.fill);
        Ok(n)
    }
}

/// Serves a 16-byte IV window at `base` in short reads, end-of-source
/// everywhere else. Proves the overflow wins over EOF: without the
/// up-front extent check the ciphertext reads would hit EOF and report
/// `UnexpectedEof` instead of `InvalidInput`.
struct IvWindowThenEof {
    base: u64,
    window: [u8; 16],
    chunk: usize,
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for IvWindowThenEof {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        let Some(rel) = off.checked_sub(self.base) else {
            return Ok(0);
        };
        if rel >= self.window.len() as u64 {
            return Ok(0);
        }
        let rel = rel as usize;
        let n = buf.len().min(self.chunk).min(self.window.len() - rel);
        buf[..n].copy_from_slice(&self.window[rel..rel + n]);
        Ok(n)
    }
}

fn rclone_header(nonce: &[u8; 24]) -> [u8; HEADER_SIZE as usize] {
    let mut header = [0u8; HEADER_SIZE as usize];
    header[..8].copy_from_slice(b"RCLONE\x00\x00");
    header[8..].copy_from_slice(nonce);
    header
}

/// Valid rclone header at 0, endless short reads everywhere else.
struct HeaderPlusEndless {
    header: [u8; HEADER_SIZE as usize],
    chunk: usize,
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for HeaderPlusEndless {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        if off < HEADER_SIZE {
            let off = off as usize;
            let n = buf.len().min(self.header.len() - off);
            buf[..n].copy_from_slice(&self.header[off..off + n]);
            return Ok(n);
        }
        let n = buf.len().min(self.chunk);
        buf[..n].fill(0x5a);
        Ok(n)
    }
}

/// Records requests and always reports end-of-source.
struct CountingEof {
    recorded: RefCell<Vec<u64>>,
}

impl ReadAt for CountingEof {
    fn read_at(&self, _buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.recorded.borrow_mut().push(off);
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// AES-CBC: off = u64::MAX on a non-empty destination
// ---------------------------------------------------------------------------

/// `off = u64::MAX` with a 64-byte destination: the ciphertext extent
/// `cipher_off..cipher_off + 80` crosses `u64::MAX` and must fail closed
/// with `InvalidInput` before any ciphertext byte is requested. The three
/// recorded reads are the 16-byte IV served first (7-byte chunks); no read
/// is issued at or above the ciphertext offset and none wraps below the
/// high window.
#[test]
fn aes_off_max_ciphertext_extent_is_invalid_input_with_no_wrapped_read() {
    let src = EndlessChunk {
        chunk: 7,
        fill: 0x42,
        recorded: RefCell::new(Vec::new()),
    };
    let key = [0x2bu8; 32];
    let iv = [0x11u8; 16];
    let mut dst = [0u8; 64];

    let result = aes_cbc::read_at(&src, &key, &iv, &mut dst, u64::MAX);

    expect_range_overflow(result, "aes off=MAX");
    // Ciphertext offset for off=MAX: first_block * 16 = u64::MAX - 15.
    let cipher_off = u64::MAX - 15;
    let recorded = src.recorded.borrow();
    assert_eq!(
        recorded.len(),
        3,
        "aes off=MAX: only the 16-byte IV (3 short reads) may be served; \
         the 80-byte ciphertext extent must issue zero reads: {recorded:?}"
    );
    assert!(
        recorded.iter().all(|&off| off < cipher_off),
        "aes off=MAX: ciphertext extent was requested despite overflow: {recorded:?}"
    );
    assert!(
        recorded.iter().all(|&off| off >= u64::MAX - 31),
        "aes off=MAX: source was asked for a wrapped offset: {recorded:?}"
    );
}

/// Last byte unrepresentable (`off = MAX - 3`, 8 bytes: last plaintext
/// byte would be `MAX + 4`) with a source that serves the IV and then
/// reports EOF. The rejection must still be `InvalidInput`, not the
/// `UnexpectedEof` an unchecked cursor would hit at the ciphertext offset.
#[test]
fn aes_last_byte_unrepresentable_is_invalid_input_not_unexpected_eof() {
    // IV offset for this off: cipher_off - 16 = u64::MAX - 31.
    let iv_base = u64::MAX - 31;
    let src = IvWindowThenEof {
        base: iv_base,
        window: [0x77u8; 16],
        chunk: 7,
        recorded: RefCell::new(Vec::new()),
    };
    let key = [0x2bu8; 32];
    let iv = [0x11u8; 16];
    let mut dst = [0u8; 8];

    let result = aes_cbc::read_at(&src, &key, &iv, &mut dst, u64::MAX - 3);

    expect_range_overflow(result, "aes last-byte-unrepresentable");
    let cipher_off = u64::MAX - 15;
    let recorded = src.recorded.borrow();
    assert!(
        !recorded.is_empty(),
        "aes last-byte: IV window must have been served (proves the EOF \
         source was reached, not bypassed)"
    );
    assert!(
        recorded.iter().all(|&off| off < cipher_off),
        "aes last-byte: ciphertext extent was requested despite overflow: {recorded:?}"
    );
    assert!(
        recorded
            .iter()
            .all(|&off| (iv_base..iv_base + 16).contains(&off)),
        "aes last-byte: reads outside the IV window (wrapped or ciphertext): {recorded:?}"
    );
}

/// Byte-at-a-time streaming (`off = MAX - 15`, 17 bytes) fails mid-operation
/// — after all 16 one-byte IV reads — with `InvalidInput` and zero
/// ciphertext reads. Pins the finest cursor granularity against wrap.
#[test]
fn aes_single_byte_stream_mid_operation_extent_is_invalid_input() {
    let src = EndlessChunk {
        chunk: 1,
        fill: 0x42,
        recorded: RefCell::new(Vec::new()),
    };
    let key = [0x2bu8; 32];
    let iv = [0x11u8; 16];
    let mut dst = [0u8; 17];

    let result = aes_cbc::read_at(&src, &key, &iv, &mut dst, u64::MAX - 15);

    expect_range_overflow(result, "aes single-byte stream");
    // Block-aligned off: cipher_off = off = u64::MAX - 15.
    let cipher_off = u64::MAX - 15;
    let recorded = src.recorded.borrow();
    assert_eq!(
        recorded.len(),
        16,
        "aes stream: only the 16 one-byte IV reads may be served: {recorded:?}"
    );
    assert!(
        recorded.iter().all(|&off| off < cipher_off),
        "aes stream: ciphertext extent was requested despite overflow: {recorded:?}"
    );
    assert!(
        recorded.iter().all(|&off| off >= cipher_off - 16),
        "aes stream: source was asked for a wrapped offset: {recorded:?}"
    );
}

// ---------------------------------------------------------------------------
// rclone: block extent crossing u64::MAX keeps the overflow message
// ---------------------------------------------------------------------------

/// The largest block whose sealed extent crosses `u64::MAX`. The rclone seam
/// wraps the helper's `io` error once (`"rclone block {n}: {io}"`), so the
/// pin is containment of the exact overflow message — and the absence of
/// any EOF text — with zero block-byte reads (only the header at 0).
#[test]
fn rclone_block_extent_crossing_max_preserves_overflow_message() {
    let block_number = (u64::MAX - HEADER_SIZE) / CIPHER_BLOCK_SIZE;
    let cipher_off = HEADER_SIZE + block_number * CIPHER_BLOCK_SIZE;
    assert!(
        cipher_off as u128 + (PLAIN_BLOCK_SIZE + CIPHER_OVERHEAD) as u128 > u64::MAX as u128,
        "fixture block extent must cross u64::MAX (cipher_off={cipher_off})"
    );
    let plain_start = block_number * PLAIN_BLOCK_SIZE;
    let plaintext_size = plain_start
        .checked_add(PLAIN_BLOCK_SIZE)
        .expect("fixture plaintext extent must stay representable");

    let nonce = [0xb1u8; 24];
    let src = HeaderPlusEndless {
        header: rclone_header(&nonce),
        chunk: 1024,
        recorded: RefCell::new(Vec::new()),
    };
    let derived = vec![0x3cu8; 80];
    let mut dst = [0u8; 8];

    let err = rclone::read_at(&src, &derived, plaintext_size, &mut dst, plain_start)
        .expect_err("rclone block extent crossing u64::MAX must be rejected");
    match err {
        Error::Decrypt(msg) => {
            assert!(
                msg.contains(RANGE_OVERFLOW_MSG),
                "rclone extent: Decrypt must preserve the overflow message, got: {msg}"
            );
            assert!(
                !msg.contains("ended mid-range"),
                "rclone extent: overflow must not degrade to EOF text, got: {msg}"
            );
        }
        other => panic!("rclone extent: expected Error::Decrypt, got {other:?}"),
    }
    let recorded = src.recorded.borrow();
    assert!(
        recorded.iter().all(|&off| off < HEADER_SIZE),
        "rclone extent: block bytes were requested despite overflow: {recorded:?}"
    );
}

// ---------------------------------------------------------------------------
// Boundary control: empty destinations stay Ok(0) with zero reads
// ---------------------------------------------------------------------------

/// Empty destinations never perform coordinate arithmetic at all — even at
/// `u64::MAX` — and return `Ok(0)` without touching the source. Sharpens
/// the non-empty qualifier on every pin above.
#[test]
fn empty_dst_at_max_stays_ok_with_zero_reads() {
    let src = CountingEof {
        recorded: RefCell::new(Vec::new()),
    };
    let key = [0x2bu8; 32];
    let iv = [0x11u8; 16];
    let mut empty: [u8; 0] = [];
    assert_eq!(
        aes_cbc::read_at(&src, &key, &iv, &mut empty, u64::MAX).unwrap(),
        0
    );
    assert!(
        src.recorded.borrow().is_empty(),
        "empty aes read must not touch the source: {:?}",
        src.recorded.borrow()
    );
}
