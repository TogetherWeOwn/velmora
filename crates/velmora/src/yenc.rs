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

/// 16-byte lane primitives. Every platform provides the same two functions;
/// SIMD targets implement them with vector intrinsics, the rest fall through
/// to scalar code (which the caller would have run anyway).
#[cfg(target_arch = "x86_64")]
mod simd {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    /// True when the 16 bytes at `input` contain no `=` escape byte.
    /// (SSE2 is part of the x86_64 baseline, so no runtime detection.)
    pub(super) fn lane_is_clean(input: *const u8) -> bool {
        // SAFETY: caller guarantees 16 readable bytes at `input`; unaligned
        // loads are used throughout so no alignment requirement.
        unsafe {
            let v = _mm_loadu_si128(input as *const __m128i);
            let eq = _mm_cmpeq_epi8(v, _mm_set1_epi8(b'=' as i8));
            _mm_movemask_epi8(eq) == 0
        }
    }

    /// Copy 16 bytes applying the yEnc `-42` transform. Only valid for lanes
    /// where [`lane_is_clean`] returned true.
    pub(super) fn sub42_copy16(input: *const u8, output: *mut u8) {
        // SAFETY: same contract as `lane_is_clean`, plus 16 writable bytes.
        unsafe {
            let v = _mm_loadu_si128(input as *const __m128i);
            let r = _mm_sub_epi8(v, _mm_set1_epi8(42));
            _mm_storeu_si128(output as *mut __m128i, r);
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod simd {
    use core::arch::wasm32::*;

    /// True when the 16 bytes at `input` contain no `=` escape byte.
    pub(super) fn lane_is_clean(input: *const u8) -> bool {
        // SAFETY: caller guarantees 16 readable bytes at `input`.
        unsafe {
            let v = v128_load(input as *const v128);
            i8x16_bitmask(i8x16_eq(v, i8x16_splat(b'=' as i8))) == 0
        }
    }

    /// Copy 16 bytes applying the yEnc `-42` transform. Only valid for lanes
    /// where [`lane_is_clean`] returned true.
    pub(super) fn sub42_copy16(input: *const u8, output: *mut u8) {
        // SAFETY: same contract as `lane_is_clean`, plus 16 writable bytes.
        unsafe {
            let v = v128_load(input as *const v128);
            v128_store(output as *mut v128, i8x16_sub(v, i8x16_splat(42)));
        }
    }
}

/// Scalar fallback: never claims a clean lane, so decoding always takes the
/// byte loop below. (LLVM still autovectorises parts of it.)
#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
mod simd {
    pub(super) fn lane_is_clean(_input: *const u8) -> bool {
        false
    }

    pub(super) fn sub42_copy16(_input: *const u8, _output: *mut u8) {
        unreachable!("lane_is_clean is always false on this target")
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

/// Writes one complete yEnc article segment: the `=ybegin` header (plus
/// `=ypart` for multi-part), the streamed encoded body, and the `=yend`
/// footer carrying the segment CRC32 (`crc32=` single-part, `pcrc32=`
/// multi-part). For multi-part segments `data.len()` must equal the
/// `[begin,end]` range length.
pub fn encode_segment(w: &mut impl io::Write, p: &SegmentParams, data: &[u8]) -> Result<()> {
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

    if p.multipart() {
        write!(
            w,
            "=ybegin part={} total={} line={} size={} name={}\r\n",
            p.part, p.total, LINE_LENGTH, p.file_size, p.name
        )?;
        write!(w, "=ypart begin={} end={}\r\n", p.begin, p.end)?;
    } else {
        write!(
            w,
            "=ybegin line={} size={} name={}\r\n",
            LINE_LENGTH,
            data.len(),
            p.name
        )?;
    }

    let crc = encode_body(w, data)?;

    if p.multipart() {
        write!(
            w,
            "=yend size={} part={} pcrc32={crc:08x}\r\n",
            data.len(),
            p.part
        )?;
    } else {
        write!(w, "=yend size={} crc32={crc:08x}\r\n", data.len())?;
    }
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
    let fields: Vec<&[u8]> = begin_line.split(|&b| b == b' ' || b == b'\t').collect();
    let multipart = fields.len() > 1 && fields[1].starts_with(b"part=");
    if !multipart && declared_size as u64 > dst.len() as u64 {
        return Err(malformed(
            message_id,
            &format!(
                "declared size {declared_size} exceeds destination of {} bytes",
                dst.len()
            ),
        ));
    }

    let mut hash = crc32fast::Hasher::new();
    let mut written = 0usize;
    let trailer: &[u8];
    let (mut ypart_begin, mut ypart_end) = (0i64, 0i64);
    let mut ypart_seen = false;
    let mut body_started = false;
    loop {
        let Some((content, terminated)) = lines.next() else {
            return Err(malformed(message_id, "missing =yend line"));
        };
        if content.starts_with(b"=yend") {
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
        let before = written;
        match decode_line_into(content, &mut dst[written..]) {
            Ok(n) => {
                hash.update(&dst[written..written + n]);
                written += n;
            }
            Err(reason) => return Err(malformed(message_id, reason)),
        }
        let _ = before;
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
    // preserving the existing pcrc32-then-crc32 precedence.
    let crc_text = if multipart {
        header_value(trailer, "pcrc32=")
    } else {
        header_value(trailer, "pcrc32=").or_else(|| header_value(trailer, "crc32="))
    };
    if let Some(crc_text) = crc_text {
        match u32::from_str_radix(crc_text, 16) {
            Ok(want) => {
                let got = hash.finalize();
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

    Ok(written)
}

fn malformed(message_id: &str, reason: &str) -> Error {
    Error::Malformed(format!("malformed yenc article {message_id}: {reason}"))
}

/// Decodes one raw body line (no line terminator) into `dst`, returning the
/// decoded length. Clean 16-byte lanes go through SIMD; the first lane
/// containing `=` — and everything after it — takes the scalar escape loop.
fn decode_line_into(line: &[u8], dst: &mut [u8]) -> std::result::Result<usize, &'static str> {
    let mut i = 0usize;
    let mut o = 0usize;
    while i + 16 <= line.len() && o + 16 <= dst.len() {
        // SAFETY: loop bounds guarantee 16 readable bytes at `i` and 16
        // writable bytes at `o`; `lane_is_clean`/`sub42_copy16` require exactly
        // that (unaligned access is used inside).
        let input = line.as_ptr().wrapping_add(i);
        if simd::lane_is_clean(input) {
            simd::sub42_copy16(input, dst.as_mut_ptr().wrapping_add(o));
            i += 16;
            o += 16;
        } else {
            break;
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
        match rest.iter().position(|&b| b == b'\n') {
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
