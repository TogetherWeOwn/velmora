//! yEnc encode/decode, ported from the v1 Go worker (`worker/internal/yenc`).
//!
//! Wire behaviour is byte-identical to v1: same headers, same 128-column
//! lines, same escape rules, same size/crc checks. The decoder additionally
//! has an explicit SIMD fast path — 16 bytes at a time on lanes that contain
//! no `=` escape byte — with a scalar fallback for dirty lanes and for targets
//! without SIMD:
//!
//! - `x86_64`: SSE2 (always available on x86_64).
//! - `wasm32` with `target-feature=+simd128`: wasm simd128. Pass
//!   `RUSTFLAGS="-C target-feature=+simd128"` when building for Workers.
//! - everything else: scalar.
//!
//! Escapes are rare in practice (4 of 256 byte values), so the common case
//! runs fully vectorised while odd lanes cost one scalar pass.

use std::io;

use crate::error::{Error, Result};

/// Standard yEnc encoded line width in output columns. An escape `=` counts
/// as one column, matching the v1 encoder.
pub const LINE_LENGTH: usize = 128;

// ---------------------------------------------------------------------------
// SIMD lane helpers
// ---------------------------------------------------------------------------

/// 16-byte lane primitives. Every platform provides the same items; SIMD
/// targets implement them with vector intrinsics. Targets without SIMD set
/// `LANES` to false and the callers run their scalar loops only.
///
/// The `*_bits` functions return one bit per lane byte (bit `n` for byte
/// `n`), so the caller knows where the first special byte sits and can copy
/// everything before it in one vector store.
#[cfg(target_arch = "x86_64")]
mod simd {
    use core::arch::x86_64::*;

    /// Whether this target has vector lanes at all.
    pub(super) const LANES: bool = true;

    /// Bits of the lane bytes that are the `=` escape marker (decode side).
    /// (SSE2 is part of the x86_64 baseline, so no runtime detection.)
    ///
    /// # Safety
    /// Every pointer must have 16 bytes behind it: readable at `input`,
    /// writable at `output`. No alignment is needed.
    #[inline(always)]
    pub(super) unsafe fn escape_bits(input: *const u8) -> u32 {
        // SAFETY: caller guarantees 16 readable bytes at `input`; unaligned
        // loads are used throughout so no alignment requirement.
        unsafe {
            let v = _mm_loadu_si128(input as *const __m128i);
            let eq = _mm_cmpeq_epi8(v, _mm_set1_epi8(b'=' as i8));
            _mm_movemask_epi8(eq) as u32
        }
    }

    /// Copy 16 bytes applying the yEnc `-42` transform. Only valid for
    /// lanes where [`escape_bits`] returned zero.
    ///
    /// # Safety
    /// Every pointer must have 16 bytes behind it: readable at `input`,
    /// writable at `output`. No alignment is needed.
    #[inline(always)]
    pub(super) unsafe fn sub42_copy16(input: *const u8, output: *mut u8) {
        // SAFETY: same contract as `escape_bits`, plus 16 writable bytes.
        unsafe {
            let v = _mm_loadu_si128(input as *const __m128i);
            let r = _mm_sub_epi8(v, _mm_set1_epi8(42));
            _mm_storeu_si128(output as *mut __m128i, r);
        }
    }

    /// Bits of the lane bytes whose `+42` value must be escaped when
    /// encoding: NUL, LF, CR and `=`.
    ///
    /// # Safety
    /// Every pointer must have 16 bytes behind it: readable at `input`,
    /// writable at `output`. No alignment is needed.
    #[inline(always)]
    pub(super) unsafe fn critical_bits(input: *const u8) -> u32 {
        // SAFETY: caller guarantees 16 readable bytes at `input`.
        unsafe {
            let v = _mm_add_epi8(_mm_loadu_si128(input as *const __m128i), _mm_set1_epi8(42));
            let hit = _mm_or_si128(
                _mm_or_si128(
                    _mm_cmpeq_epi8(v, _mm_setzero_si128()),
                    _mm_cmpeq_epi8(v, _mm_set1_epi8(b'\n' as i8)),
                ),
                _mm_or_si128(
                    _mm_cmpeq_epi8(v, _mm_set1_epi8(b'\r' as i8)),
                    _mm_cmpeq_epi8(v, _mm_set1_epi8(b'=' as i8)),
                ),
            );
            _mm_movemask_epi8(hit) as u32
        }
    }

    /// Copy 16 bytes applying the yEnc `+42` transform. The caller uses
    /// only the output bytes that come before the first critical byte.
    ///
    /// # Safety
    /// Every pointer must have 16 bytes behind it: readable at `input`,
    /// writable at `output`. No alignment is needed.
    #[inline(always)]
    pub(super) unsafe fn add42_copy16(input: *const u8, output: *mut u8) {
        // SAFETY: 16 readable bytes at `input`, 16 writable at `output`.
        unsafe {
            let v = _mm_loadu_si128(input as *const __m128i);
            let r = _mm_add_epi8(v, _mm_set1_epi8(42));
            _mm_storeu_si128(output as *mut __m128i, r);
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod simd {
    use core::arch::wasm32::*;

    /// Whether this target has vector lanes at all.
    pub(super) const LANES: bool = true;

    /// Bits of the lane bytes that are the `=` escape marker (decode side).
    ///
    /// # Safety
    /// Every pointer must have 16 bytes behind it: readable at `input`,
    /// writable at `output`. No alignment is needed.
    #[inline(always)]
    pub(super) unsafe fn escape_bits(input: *const u8) -> u32 {
        // SAFETY: caller guarantees 16 readable bytes at `input`.
        unsafe {
            let v = v128_load(input as *const v128);
            i8x16_bitmask(i8x16_eq(v, i8x16_splat(b'=' as i8))) as u32
        }
    }

    /// Copy 16 bytes applying the yEnc `-42` transform. Only valid for
    /// lanes where [`escape_bits`] returned zero.
    ///
    /// # Safety
    /// Every pointer must have 16 bytes behind it: readable at `input`,
    /// writable at `output`. No alignment is needed.
    #[inline(always)]
    pub(super) unsafe fn sub42_copy16(input: *const u8, output: *mut u8) {
        // SAFETY: same contract as `escape_bits`, plus 16 writable bytes.
        unsafe {
            let v = v128_load(input as *const v128);
            v128_store(output as *mut v128, i8x16_sub(v, i8x16_splat(42)));
        }
    }

    /// Bits of the lane bytes whose `+42` value must be escaped when
    /// encoding: NUL, LF, CR and `=`.
    ///
    /// # Safety
    /// Every pointer must have 16 bytes behind it: readable at `input`,
    /// writable at `output`. No alignment is needed.
    #[inline(always)]
    pub(super) unsafe fn critical_bits(input: *const u8) -> u32 {
        // SAFETY: caller guarantees 16 readable bytes at `input`.
        unsafe {
            let v = i8x16_add(v128_load(input as *const v128), i8x16_splat(42));
            let hit = v128_or(
                v128_or(
                    i8x16_eq(v, i8x16_splat(0)),
                    i8x16_eq(v, i8x16_splat(b'\n' as i8)),
                ),
                v128_or(
                    i8x16_eq(v, i8x16_splat(b'\r' as i8)),
                    i8x16_eq(v, i8x16_splat(b'=' as i8)),
                ),
            );
            i8x16_bitmask(hit) as u32
        }
    }

    /// Copy 16 bytes applying the yEnc `+42` transform. The caller uses
    /// only the output bytes that come before the first critical byte.
    ///
    /// # Safety
    /// Every pointer must have 16 bytes behind it: readable at `input`,
    /// writable at `output`. No alignment is needed.
    #[inline(always)]
    pub(super) unsafe fn add42_copy16(input: *const u8, output: *mut u8) {
        // SAFETY: 16 readable bytes at `input`, 16 writable at `output`.
        unsafe {
            let v = v128_load(input as *const v128);
            v128_store(output as *mut v128, i8x16_add(v, i8x16_splat(42)));
        }
    }
}

/// Scalar fallback: no vector lanes, so the callers never reach these and
/// run their byte loops only. (LLVM still autovectorises parts of them.)
#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
mod simd {
    pub(super) const LANES: bool = false;

    pub(super) unsafe fn escape_bits(_input: *const u8) -> u32 {
        unreachable!("no vector lanes on this target")
    }

    pub(super) unsafe fn sub42_copy16(_input: *const u8, _output: *mut u8) {
        unreachable!("no vector lanes on this target")
    }

    pub(super) unsafe fn critical_bits(_input: *const u8) -> u32 {
        unreachable!("no vector lanes on this target")
    }

    pub(super) unsafe fn add42_copy16(_input: *const u8, _output: *mut u8) {
        unreachable!("no vector lanes on this target")
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Describes one yEnc article segment. All framing values are caller-supplied
/// and deterministic: this module never mints Message-IDs or subjects.
///
/// A zero `total` (or `total <= 1`) encodes a single-part segment with no
/// `=ypart` line. A `total > 1` encodes a multi-part segment with `=ybegin
/// part/total` labels, a `=ypart` range line, and a `pcrc32` trailer.
///
/// Per yEnc 1.3 the multi-part `=ybegin size=` is the size of the ENTIRE file
/// (not this part); only `=yend size=` is the part size. `file_size` carries
/// that file size and is required for multi-part segments.
#[derive(Debug, Clone)]
pub struct SegmentParams {
    /// File name for the `=ybegin name=` label. Must not contain line breaks.
    pub name: String,
    /// 1-based part number for multi-part segments.
    pub part: u32,
    /// Total part count for multi-part segments.
    pub total: u32,
    /// 1-based inclusive first byte of this segment within the file.
    pub begin: u64,
    /// 1-based inclusive last byte of this segment within the file.
    pub end: u64,
    /// Total decoded file size, emitted as `=ybegin size=`. Required for
    /// multi-part segments and must be `>= end`. Ignored for single-part.
    pub file_size: u64,
}

impl SegmentParams {
    /// Single-part parameters for a whole in-memory buffer.
    pub fn single(name: impl Into<String>) -> Self {
        SegmentParams {
            name: name.into(),
            part: 0,
            total: 0,
            begin: 0,
            end: 0,
            file_size: 0,
        }
    }

    fn multipart(&self) -> bool {
        self.total > 1
    }

    fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::Malformed("yenc segment name is required".into()));
        }
        if self.name.contains(['\r', '\n']) {
            return Err(Error::Malformed(format!(
                "yenc segment name {:?} must not contain line breaks",
                self.name
            )));
        }
        if self.multipart() {
            if self.part < 1 || self.part > self.total {
                return Err(Error::Malformed(format!(
                    "yenc segment part {} out of range for total {}",
                    self.part, self.total
                )));
            }
            if self.begin < 1 || self.end < self.begin {
                return Err(Error::Malformed(format!(
                    "yenc segment range [{},{}] is invalid (1-based, inclusive)",
                    self.begin, self.end
                )));
            }
            if self.file_size == 0 {
                return Err(Error::Malformed(
                    "yenc segment file size is required for multi-part segments".into(),
                ));
            }
            if self.file_size < self.end {
                return Err(Error::Malformed(format!(
                    "yenc segment file size {} is smaller than part end {}",
                    self.file_size, self.end
                )));
            }
        }
        Ok(())
    }
}

/// Streams the yEnc encoding of `data` to `w` and returns the CRC32-IEEE of
/// the raw segment bytes for the `=yend` trailer.
///
/// The encoded article is never held in a second article-sized buffer:
/// encoding accumulates in one stack line buffer (`LINE_LENGTH` columns plus
/// CRLF) flushed as it fills. Bytes whose `+42` value is NUL, LF, CR, or `=`
/// are escaped (`=` followed by value `+64`).
/// One stack line buffer (`LINE_LENGTH` columns plus CRLF), flushed as it
/// fills, so the encoded article streams without a second article-sized
/// allocation.
struct LineBuf {
    line: [u8; LINE_LENGTH + 2],
    used: usize,
    column: usize,
}

impl LineBuf {
    fn new() -> Self {
        LineBuf {
            line: [0u8; LINE_LENGTH + 2],
            used: 0,
            column: 0,
        }
    }

    fn flush(&mut self, w: &mut impl io::Write) -> io::Result<()> {
        if self.used == 0 {
            return Ok(());
        }
        self.line[self.used] = b'\r';
        self.line[self.used + 1] = b'\n';
        self.used += 2;
        w.write_all(&self.line[..self.used])?;
        self.used = 0;
        self.column = 0;
        Ok(())
    }

    fn emit(&mut self, w: &mut impl io::Write, b: u8) -> io::Result<()> {
        self.line[self.used] = b;
        self.used += 1;
        self.column += 1;
        if self.column >= LINE_LENGTH {
            self.flush(w)?;
        }
        Ok(())
    }
}

pub fn encode_body(w: &mut impl io::Write, data: &[u8]) -> Result<u32> {
    let mut hash = crc32fast::Hasher::new();
    hash.update(data);

    let mut buf = LineBuf::new();
    for &b in data {
        let mut value = b.wrapping_add(42);
        if value == 0 || value == b'\n' || value == b'\r' || value == b'=' {
            if buf.column >= LINE_LENGTH - 1 {
                // Never strand `=` at end of line: the escape pair must stay
                // on one line or `decode_to` rejects it as malformed.
                buf.flush(w)?;
            }
            buf.emit(w, b'=')?;
            value = value.wrapping_add(64);
        }
        buf.emit(w, value)?;
    }
    buf.flush(w)?;
    Ok(hash.finalize())
}

/// Input bytes handled per output reservation in [`encode_body_vec`].
const ENCODE_BLOCK: usize = 4096;

/// Most output bytes `len` input bytes can encode to, whatever column the
/// block starts at: two columns per byte, a CRLF per line of at least
/// `LINE_LENGTH - 1` columns, and one vector store of slack.
const fn encoded_bound(len: usize) -> usize {
    2 * len + 2 * (2 * len / (LINE_LENGTH - 1) + 3) + 32
}

/// [`encode_body`] straight into a `Vec`, appending to `out`. The output is
/// byte-identical to [`encode_body`] (which stays as the reference and the
/// streaming form); this one runs 16 bytes at a time on SIMD targets and
/// writes without a per-line `write_all`.
///
/// Returns the CRC32 of `data`.
pub fn encode_body_vec(out: &mut Vec<u8>, data: &[u8]) -> u32 {
    let mut hash = crc32fast::Hasher::new();
    hash.update(data);

    let mut column = 0usize;
    for block in data.chunks(ENCODE_BLOCK) {
        let start = out.len();
        out.resize(start + encoded_bound(block.len()), 0);
        let written = encode_block(block, &mut out[start..], &mut column);
        out.truncate(start + written);
    }
    if column > 0 {
        out.extend_from_slice(b"\r\n");
    }
    hash.finalize()
}

/// Encodes `data` into `dst` continuing a line at `*column`, and returns the
/// bytes written. `dst` must hold at least `encoded_bound(data.len())`
/// bytes; every write outside the vector store is bounds-checked, and the
/// vector store is taken only with 16 writable bytes left.
fn encode_block(data: &[u8], dst: &mut [u8], column: &mut usize) -> usize {
    let mut col = *column;
    let mut i = 0usize;
    let mut o = 0usize;
    if simd::LANES {
        // Each round takes the clean bytes at the head of a 16-byte lane,
        // capped at the room left on the line, then the one critical byte
        // that stopped it (if any). `col < LINE_LENGTH` holds on entry.
        while i + 16 <= data.len() && o + 24 <= dst.len() {
            let take = (LINE_LENGTH - col).min(16);
            let input = data.as_ptr().wrapping_add(i);
            // SAFETY: the loop bounds guarantee 16 readable bytes at `i`
            // and 16 writable bytes at `o`; both functions need exactly
            // that and use unaligned access.
            let bits = unsafe {
                simd::add42_copy16(input, dst.as_mut_ptr().wrapping_add(o));
                simd::critical_bits(input)
            } & ((1u32 << take) - 1);
            let clean = if bits == 0 {
                take
            } else {
                bits.trailing_zeros() as usize
            };
            i += clean;
            o += clean;
            col += clean;
            if bits != 0 {
                // `clean < take`, so the line still has room for a column.
                if col >= LINE_LENGTH - 1 {
                    // Never strand `=` at end of line.
                    dst[o] = b'\r';
                    dst[o + 1] = b'\n';
                    o += 2;
                    col = 0;
                }
                dst[o] = b'=';
                dst[o + 1] = data[i].wrapping_add(42).wrapping_add(64);
                i += 1;
                o += 2;
                col += 2;
            }
            if col >= LINE_LENGTH {
                dst[o] = b'\r';
                dst[o + 1] = b'\n';
                o += 2;
                col = 0;
            }
        }
    }
    for &b in &data[i..] {
        let mut value = b.wrapping_add(42);
        if value == 0 || value == b'\n' || value == b'\r' || value == b'=' {
            if col >= LINE_LENGTH - 1 {
                dst[o] = b'\r';
                dst[o + 1] = b'\n';
                o += 2;
                col = 0;
            }
            dst[o] = b'=';
            o += 1;
            col += 1;
            value = value.wrapping_add(64);
        }
        dst[o] = value;
        o += 1;
        col += 1;
        if col >= LINE_LENGTH {
            dst[o] = b'\r';
            dst[o + 1] = b'\n';
            o += 2;
            col = 0;
        }
    }
    *column = col;
    o
}

fn check_segment(p: &SegmentParams, data: &[u8]) -> Result<()> {
    p.validate()?;
    if p.multipart() && data.len() as u64 != p.end - p.begin + 1 {
        return Err(Error::Malformed(format!(
            "yenc segment {}/{} holds {} bytes, range [{},{}] needs {}",
            p.part,
            p.total,
            data.len(),
            p.begin,
            p.end,
            p.end - p.begin + 1
        )));
    }
    Ok(())
}

fn write_segment_head(w: &mut impl io::Write, p: &SegmentParams, len: usize) -> io::Result<()> {
    if p.multipart() {
        write!(
            w,
            "=ybegin part={} total={} line={} size={} name={}\r\n",
            p.part, p.total, LINE_LENGTH, p.file_size, p.name
        )?;
        write!(w, "=ypart begin={} end={}\r\n", p.begin, p.end)
    } else {
        write!(
            w,
            "=ybegin line={} size={} name={}\r\n",
            LINE_LENGTH, len, p.name
        )
    }
}

fn write_segment_tail(
    w: &mut impl io::Write,
    p: &SegmentParams,
    len: usize,
    crc: u32,
) -> io::Result<()> {
    if p.multipart() {
        write!(w, "=yend size={} part={} pcrc32={crc:08x}\r\n", len, p.part)
    } else {
        write!(w, "=yend size={len} crc32={crc:08x}\r\n")
    }
}

/// Writes one complete yEnc article segment: the `=ybegin` header (plus
/// `=ypart` for multi-part), the streamed encoded body, and the `=yend`
/// footer carrying the segment CRC32 (`crc32=` single-part, `pcrc32=`
/// multi-part). For multi-part segments `data.len()` must equal the
/// `[begin,end]` range length.
pub fn encode_segment(w: &mut impl io::Write, p: &SegmentParams, data: &[u8]) -> Result<()> {
    check_segment(p, data)?;
    write_segment_head(w, p, data.len())?;
    let crc = encode_body(w, data)?;
    write_segment_tail(w, p, data.len(), crc)?;
    Ok(())
}

/// [`encode_segment`] appending to a `Vec`, with the body encoded by
/// [`encode_body_vec`]. The appended bytes are identical to what
/// [`encode_segment`] writes; nothing is appended when the parameters are
/// refused.
pub fn encode_segment_vec(out: &mut Vec<u8>, p: &SegmentParams, data: &[u8]) -> Result<()> {
    check_segment(p, data)?;
    write_segment_head(out, p, data.len())?;
    let crc = encode_body_vec(out, data);
    write_segment_tail(out, p, data.len(), crc)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decodes one yEnc article into `dst`: a single-part article, or one part of
/// a multi-part article sized by its `=ypart` range.
///
/// `article` is the raw article bytes (NNTP headers before `=ybegin` are
/// skipped, mirroring v1). Decoded bytes are written directly into the
/// caller-owned destination and validated before the returned length is
/// exposed — no second article-sized buffer is allocated.
///
/// Returns the number of decoded bytes. Errors are [`Error::Malformed`] or
/// [`Error::CrcMismatch`].
///
/// Trailer validation in this entry point (both the single-part and
/// multi-part paths) distinguishes an *absent* `=yend size=` — which stays
/// optional, as before — from a *present* one: a present value must be a
/// valid non-negative decimal equal to the decoded payload length, and an
/// empty, non-numeric, negative, or out-of-range value is rejected as
/// [`Error::Malformed`] rather than treated as an omission. The `=yend`
/// line carries only ASCII `key=value` tokens, so a trailer that is not
/// valid UTF-8 is likewise rejected instead of letting the size and CRC
/// lookups silently miss every key.
///
/// The `=ybegin` line is the one place a poster-supplied filename appears,
/// and legacy postings carry it in Latin-1/CP1252 or other non-UTF-8 bytes.
/// Its ASCII control fields are therefore read from raw bytes, and only
/// from the tokens before the trailing `name=` field: filename bytes are
/// never decoded, transcoded, or reinterpreted as control tags. The
/// `=ypart` and `=yend` lines carry no filename and keep the strict UTF-8
/// parsing above.
///
/// Checksum validation follows the same scoping: a multipart article is
/// validated against its part checksum (`pcrc32=`) only — a whole-file
/// `crc32=` covers bytes this article does not contain and is never
/// compared against the decoded part alone, so a multipart article with
/// only the whole-file checksum still decodes. Checksums stay optional,
/// and a present but malformed applicable checksum is rejected.
pub fn decode_to(message_id: &str, article: &[u8], dst: &mut [u8]) -> Result<usize> {
    decode_part_to(message_id, article, dst).map(|part| part.written)
}

/// Verified placement from the same bounded decoder used by ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedPart {
    pub written: usize,
    pub file_size: u64,
    pub offset: u64,
    pub multipart: bool,
    pub part_number: Option<u64>,
}

/// Decode into caller-bounded storage and retain the actual yEnc geometry.
/// Neither checksums nor geometry authenticate original media cryptographically.
pub fn decode_part_to(message_id: &str, article: &[u8], dst: &mut [u8]) -> Result<DecodedPart> {
    let mut lines = split_lines(article);

    let begin_line = loop {
        match lines.next() {
            Some((line, _)) if line.starts_with(b"=ybegin ") => break line,
            Some(_) => continue,
            None => {
                return Err(malformed(message_id, "missing =ybegin line"));
            }
        }
    };

    let declared_size = begin_header_int(begin_line, "size=")
        .filter(|&v| v >= 0)
        .ok_or_else(|| malformed(message_id, "=ybegin missing or invalid size="))?;
    // A part= label in second position marks a multi-part article, where
    // =ybegin size= is the whole-file size (yEnc 1.3): the part length comes
    // from the =ypart range instead. Position 2 (right after =ybegin) is
    // checked rather than the whole line so a filename containing "part="
    // cannot flip the interpretation.
    let multipart = begin_line
        .split(|&b| b == b' ' || b == b'\t')
        .nth(1)
        .is_some_and(|field| field.starts_with(b"part="));
    let part_number = if multipart {
        Some(
            begin_header_int(begin_line, "part=")
                .filter(|&n| n > 0)
                .ok_or_else(|| malformed(message_id, "invalid part number"))? as u64,
        )
    } else {
        None
    };
    if !multipart && declared_size as u64 > dst.len() as u64 {
        return Err(malformed(
            message_id,
            &format!(
                "declared size {declared_size} exceeds destination of {} bytes",
                dst.len()
            ),
        ));
    }

    let mut written = 0usize;
    let trailer: &[u8];
    let (mut ypart_begin, mut ypart_end) = (0i64, 0i64);
    let mut ypart_seen = false;
    let mut body_started = false;
    loop {
        let Some((content, terminated)) = lines.next() else {
            return Err(malformed(message_id, "missing =yend line"));
        };
        // Match the `=yend` keyword as a whole token. A bare prefix match
        // would take a malformed line such as `=yending` as the trailer; it
        // declares no size= or crc32=, so a corrupted body whose length
        // matches the header would decode with no checksum at all.
        if content == b"=yend" || content.starts_with(b"=yend ") || content.starts_with(b"=yend\t")
        {
            trailer = content;
            break;
        }
        // Multi-part range line. It carries no encoded bytes; its begin=/end=
        // range declares this segment's decoded length. A bare `=` never
        // appears in valid encoded output (escapable bytes are always
        // `=`-prefixed), so this prefix cannot collide with a body line.
        if content.starts_with(b"=ypart ") {
            if body_started {
                return Err(malformed(message_id, "=ypart after body data"));
            }
            if ypart_seen {
                return Err(malformed(message_id, "duplicate =ypart line"));
            }
            let (begin, end) = match (header_int(content, "begin="), header_int(content, "end=")) {
                (Some(b), Some(e)) if b >= 1 && e >= b => (b, e),
                _ => {
                    return Err(malformed(
                        message_id,
                        "=ypart missing or invalid begin=/end=",
                    ))
                }
            };
            (ypart_begin, ypart_end) = (begin, end);
            ypart_seen = true;
            continue;
        }
        body_started = true;
        match decode_line_into(content, &mut dst[written..]) {
            Ok(n) => written += n,
            Err(reason) => return Err(malformed(message_id, reason)),
        }
        if !terminated {
            return Err(malformed(message_id, "missing =yend line"));
        }
    }

    if multipart != ypart_seen {
        if multipart {
            return Err(malformed(
                message_id,
                "multipart =ybegin without =ypart line",
            ));
        }
        return Err(malformed(message_id, "=ypart without multipart =ybegin"));
    }
    if ypart_seen {
        let part_len = ypart_end - ypart_begin + 1;
        if part_len as u64 > dst.len() as u64 {
            return Err(malformed(
                message_id,
                &format!(
                    "part range [{ypart_begin},{ypart_end}] exceeds destination of {} bytes",
                    dst.len()
                ),
            ));
        }
        if declared_size < ypart_end {
            return Err(malformed(
                message_id,
                &format!("file size {declared_size} smaller than part end {ypart_end}"),
            ));
        }
        if written as i64 != part_len {
            return Err(malformed(
                message_id,
                &format!(
                    "decoded {written} bytes, =ypart range [{ypart_begin},{ypart_end}] needs {part_len}"
                ),
            ));
        }
    } else if written as i64 != declared_size {
        return Err(malformed(
            message_id,
            &format!("decoded {written} bytes, header declared size={declared_size}"),
        ));
    }
    // `header_value` yields `None` for a non-UTF-8 line just as it does for
    // an absent key, so one stray non-UTF-8 byte in the trailer would
    // silently skip both the size and CRC checks below. The trailer holds
    // only ASCII `key=value` tokens (no filename), so reject it outright.
    if std::str::from_utf8(trailer).is_err() {
        return Err(malformed(message_id, "=yend line is not valid UTF-8"));
    }
    if let Some(trailer_size_text) = header_value(trailer, "size=") {
        // A present trailer size is not optional metadata: only its
        // *absence* may skip this check. `header_int` would collapse a
        // parse failure (empty, non-numeric, or overflowing value) to
        // `None` and silently skip validation, so parse the raw token
        // here and reject anything that is not a non-negative decimal.
        let Some(trailer_size) = trailer_size_text.parse::<i64>().ok().filter(|&v| v >= 0) else {
            return Err(malformed(
                message_id,
                "=yend declared size= is not a valid non-negative integer",
            ));
        };
        if trailer_size != written as i64 {
            return Err(malformed(
                message_id,
                &format!("decoded {written} bytes, trailer declared size={trailer_size}"),
            ));
        }
    }
    // Checksum scope: `pcrc32=` covers this decoded part, while `crc32=`
    // covers the whole file. For a multipart article only the part checksum
    // can be compared against the bytes decoded here; a whole-file `crc32=`
    // must never be used as if it were the part checksum (and stays
    // unverified until reassembly, which is out of scope for this decoder).
    // For a single-part article part == whole file, so either field applies,
    // with `crc32=` precedence (matching the stream decoder): `crc32=` is
    // selected when present, `pcrc32=` only when `crc32=` is absent.
    let crc_text = if multipart {
        header_value(trailer, "pcrc32=")
    } else {
        header_value(trailer, "crc32=").or_else(|| header_value(trailer, "pcrc32="))
    };
    if let Some(crc_text) = crc_text {
        match u32::from_str_radix(crc_text, 16) {
            Ok(want) => {
                // One pass over the decoded bytes (the same CRC32 a
                // per-line update gives, without a call per line).
                let got = crc32fast::hash(&dst[..written]);
                if want != got {
                    return Err(Error::CrcMismatch {
                        message_id: message_id.to_string(),
                        want,
                        got,
                    });
                }
            }
            Err(_) => return Err(malformed(message_id, "=yend crc32 is not valid hex")),
        }
    }

    Ok(DecodedPart {
        written,
        file_size: declared_size as u64,
        offset: if multipart {
            (ypart_begin - 1) as u64
        } else {
            0
        },
        multipart,
        part_number,
    })
}

fn malformed(message_id: &str, reason: &str) -> Error {
    Error::Malformed(format!("malformed yenc article {message_id}: {reason}"))
}

/// Decodes one raw body line (no line terminator) into `dst`, returning the
/// decoded length. On SIMD targets each round takes the bytes at the head
/// of a 16-byte lane that come before an `=`, then that one escape pair,
/// and goes back to lanes; the scalar loop finishes the last partial lane
/// (and is the whole decoder on targets without SIMD).
fn decode_line_into(line: &[u8], dst: &mut [u8]) -> std::result::Result<usize, &'static str> {
    let mut i = 0usize;
    let mut o = 0usize;
    if simd::LANES {
        while i + 16 <= line.len() && o + 16 <= dst.len() {
            let input = line.as_ptr().wrapping_add(i);
            // SAFETY: the loop bounds guarantee 16 readable bytes at `i`.
            let bits = unsafe { simd::escape_bits(input) };
            if bits == 0 {
                // SAFETY: as above, and 16 writable bytes at `o`.
                unsafe { simd::sub42_copy16(input, dst.as_mut_ptr().wrapping_add(o)) };
                i += 16;
                o += 16;
                continue;
            }
            // Copy the bytes before the first `=` one by one (a vector
            // store here would write past the decoded bytes, and `dst` may
            // be a window of a buffer other articles fill), then take the
            // escape pair with the same checks as the scalar loop below.
            let clean = bits.trailing_zeros() as usize;
            for (to, from) in dst[o..o + clean].iter_mut().zip(&line[i..i + clean]) {
                *to = from.wrapping_sub(42);
            }
            i += clean + 1;
            o += clean;
            if i >= line.len() {
                return Err("yenc escape at end of line");
            }
            if o >= dst.len() {
                return Err("decoded article exceeds destination");
            }
            dst[o] = line[i].wrapping_sub(64).wrapping_sub(42);
            i += 1;
            o += 1;
        }
    }
    while i < line.len() {
        let mut b = line[i];
        i += 1;
        if b == b'=' {
            if i >= line.len() {
                return Err("yenc escape at end of line");
            }
            b = line[i].wrapping_sub(64);
            i += 1;
        }
        if o >= dst.len() {
            return Err("decoded article exceeds destination");
        }
        dst[o] = b.wrapping_sub(42);
        o += 1;
    }
    Ok(o)
}

/// Yields `(content, newline_terminated)` lines; a trailing `\r` is stripped
/// from each content slice. The final chunk without `\n` is still yielded.
fn split_lines(mut rest: &[u8]) -> impl Iterator<Item = (&[u8], bool)> + '_ {
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match memchr::memchr(b'\n', rest) {
            Some(pos) => {
                let mut line = &rest[..pos];
                rest = &rest[pos + 1..];
                if line.last() == Some(&b'\r') {
                    line = &line[..line.len() - 1];
                }
                Some((line, true))
            }
            None => {
                let mut line = rest;
                rest = b"";
                if line.last() == Some(&b'\r') {
                    line = &line[..line.len() - 1];
                }
                Some((line, false))
            }
        }
    })
}

fn header_int(line: &[u8], key: &str) -> Option<i64> {
    header_value(line, key)?.parse().ok()
}

/// Byte-oriented counterpart of [`header_int`] for the `=ybegin` line only.
///
/// The filename after `name=` is the last field on that line and may carry
/// legacy Latin-1/CP1252 (or otherwise non-UTF-8) bytes, so UTF-8 decoding
/// the whole line would lose the valid ASCII control fields before it.
/// Tokens are scanned as raw bytes and the scan stops at the `name=` token:
/// everything from there on is filename bytes, never control fields, even
/// when it contains tag-looking ASCII. The matched value itself must still
/// be a plain UTF-8 decimal, so numeric validation is exactly as strict as
/// [`header_int`].
fn begin_header_int(line: &[u8], key: &str) -> Option<i64> {
    for token in line.split(|&b| b == b' ' || b == b'\t') {
        if token.starts_with(b"name=") {
            return None;
        }
        if let Some(value) = token.strip_prefix(key.as_bytes()) {
            return std::str::from_utf8(value).ok()?.parse().ok();
        }
    }
    None
}

fn header_value<'a>(line: &'a [u8], key: &str) -> Option<&'a str> {
    let line = std::str::from_utf8(line).ok()?;
    for token in line.split([' ', '\t']) {
        if let Some(value) = token.strip_prefix(key) {
            return Some(value);
        }
    }
    None
}
