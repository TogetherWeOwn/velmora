//! PAR2 set creator: one recovery set per file at 10% redundancy over the
//! ciphertext, generated before posting.
//!
//! This is the write side [`super`] lacks: [`Par2Creator`] streams file bytes
//! in arbitrary chunks and emits `Main` + `FileDesc` + `IFSC` +
//! one `RecvSlic` packet per recovery slice, framed exactly as
//! [`super::RecoverySet::parse`] (and the reference repair binary) expect.
//!
//! Wire contract (PAR 2.0; packet field order verified against the parser and
//! the reference tool's observable behaviour — all code below is written
//! fresh):
//!
//! - Slice size is the article payload rounded down to a multiple of 128
//!   ([`slice_size_for_article_payload`]); it must also be a non-zero multiple
//!   of 4 and fit [`super::MAX_BLOCK_SIZE`].
//! - Recovery count is 10% of the data-slice count, rounded up, minimum one
//!   ([`recovery_slice_count`]); exponents are `0..recovery_count`, so the
//!   first recovery slice is plain XOR parity.
//! - Recovery math is GF(2^16) Reed-Solomon over little-endian `u16` words
//!   (see [`super::gf16`]); the short last slice is zero-padded before it
//!   enters the matrix, the IFSC hashes, and the CRCs.
//! - File ID = MD5(`first-16k MD5 ‖ length LE ‖ name bytes`); set ID = MD5 of
//!   the Main packet body. Per-slice IFSC entries carry the MD5 and CRC32 of
//!   the zero-padded slice.
//!
//! Streaming and memory: the creator holds one input slice plus
//! `recovery_count × slice_size` accumulator bytes (the ≈3.5 MB class at the
//! design's example sizes: 5 × ~721 KB for a ~32 MB file), the 20-byte IFSC
//! entries, and hash states — never the whole file, never the whole album.
//! The total ciphertext length is required up front ([`Par2Creator::new`])
//! so the accumulator budget is fixed before the first byte streams.
//!
//! Production repair stays on the Container path (`par2` binary via
//! [`super::repair`]); [`recover_slices`] is a validation-grade decoder for
//! create→damage→repair round-trip tests and for environments without the
//! binary. PAR2 bytes are posted obfuscated like data articles by the
//! manifest/post stage, which also owns the article payload constant and the
//! per-packet article split (see [`CreatedSet::packets`]).

use crate::error::{Error, Result};

use super::gf16;
use super::{MAX_BLOCK_SIZE, MAX_PAR2_RECOVERY_SLICES};

/// Redundancy: recovery slices per data slice, in percent. Owner-settled at
/// 10% (design §3/§4: postie's example config; the default 5% is not used).
pub const REDUNDANCY_PERCENT: u32 = 10;

/// First-16k hash span, in bytes (matches the FileDesc `hash16k` field).
pub const FIRST_16K_SPAN: usize = 16 * 1024;

/// PAR2 slice alignment unit: slice sizes are article payloads rounded down
/// to a multiple of this (design §3). A multiple of 128 is always a multiple
/// of 4 (packet framing) and even (`u16` words).
pub const SLICE_ALIGNMENT: u64 = 128;

/// Upper bound on data slices per file. The Vandermonde scheme needs distinct
/// full-order bases (about 26k exist below the group order); music files at
/// hundred-kilobyte slices stay two orders of magnitude under this. Anything
/// past it fails closed instead of emitting an unrepairable set.
pub const MAX_DATA_SLICES: u64 = 20_000;

/// Upper bound on recovery accumulator bytes per file (32 MiB). `new`
/// allocates the accumulators in full and `finish` holds them alive while
/// retaining every recovery packet, so the finish peak is ≈2× the
/// accumulators plus O(slice) scratch; sizing the cap here keeps even the
/// accepted worst case (≈64 MiB peak) inside the 128 MB Worker-isolate
/// budget this card streams within. Accumulators sit near 10% of the file,
/// so 32 MiB still admits ~320 MB per file — far above the FLAC-track class
/// this serves (≈3.5 MB accumulators); no honest caller is rejected.
pub const MAX_ACCUMULATOR_BYTES: u64 = 32 << 20;

/// Scratch budget for the [`recover_slices`] dense solve (64 MiB). The
/// Gauss-Jordan inversion holds three `m × m` `u16` matrices for `m` missing
/// slices (6`m`² bytes), so this caps `m` near 3 300 — far above honest
/// geometry (10% redundancy over at most [`MAX_DATA_SLICES`] slices caps `m`
/// at ~2 000) while failing closed on absurd geometry (20 000 missing would
/// otherwise commit ~2.4 GB and OOM the isolate).
pub const MAX_RECOVERY_SCRATCH_BYTES: u64 = 64 << 20;

/// Streaming zero-run chunk for slice-tail padding (same shape as the read
/// side's hasher chunks).
const ZERO_CHUNK_SIZE: usize = 8192;

/// Round an article payload down to a usable PAR2 slice size (a multiple of
/// [`SLICE_ALIGNMENT`]). Errors on payloads below one alignment unit (which
/// would round to zero) and on sizes past [`MAX_BLOCK_SIZE`].
pub fn slice_size_for_article_payload(payload_bytes: u64) -> Result<u64> {
    let slice = payload_bytes & !(SLICE_ALIGNMENT - 1);
    if slice == 0 {
        return Err(Error::Malformed(format!(
            "par2 creator: article payload {payload_bytes} is below one slice alignment unit ({SLICE_ALIGNMENT})"
        )));
    }
    if slice > MAX_BLOCK_SIZE {
        return Err(Error::Malformed(format!(
            "par2 creator: slice size {slice} exceeds the supported bound of {MAX_BLOCK_SIZE}"
        )));
    }
    Ok(slice)
}

/// Number of data slices for `total_len` bytes at `slice_size`.
///
/// # Panics
///
/// Panics if `slice_size` is zero (integer division by zero). Callers must
/// validate first — [`Par2Creator::new`] rejects a zero slice size before
/// reaching this.
pub fn data_slice_count(total_len: u64, slice_size: u64) -> u64 {
    total_len.div_ceil(slice_size)
}

/// Recovery slices for `data_slices` data slices: 10% rounded up, minimum
/// one. Fails closed on empty or absurd inputs.
pub fn recovery_slice_count(data_slices: u64) -> Result<u64> {
    if data_slices == 0 {
        return Err(Error::Malformed(
            "par2 creator: cannot build a recovery set for an empty file".into(),
        ));
    }
    if data_slices > MAX_DATA_SLICES {
        return Err(Error::Malformed(format!(
            "par2 creator: {data_slices} data slices exceed the per-file bound of {MAX_DATA_SLICES}"
        )));
    }
    let recovery = data_slices
        .saturating_mul(u64::from(REDUNDANCY_PERCENT))
        .div_ceil(100)
        .max(1);
    if recovery > MAX_PAR2_RECOVERY_SLICES as u64 {
        return Err(Error::Malformed(format!(
            "par2 creator: {recovery} recovery slices exceed the packet bound of {MAX_PAR2_RECOVERY_SLICES}"
        )));
    }
    Ok(recovery)
}

fn malformed(detail: impl Into<String>) -> Error {
    Error::Malformed(format!("par2 creator: {}", detail.into()))
}

/// Rejects FileDesc names the parser would refuse, so every set this creator
/// emits parses back: empty or all-NUL names, leading-NUL names, and names
/// with trailing NULs (which the parser's padding trim would desync from the
/// File ID derivation).
fn check_filename(name: &[u8]) -> Result<()> {
    let end = name.iter().rposition(|&b| b != 0).map_or(0, |n| n + 1);
    let trimmed = &name[..end];
    if trimmed.is_empty() {
        return Err(malformed("filename is empty after NUL trimming"));
    }
    if trimmed[0] == 0 {
        return Err(malformed("filename starts with a NUL byte"));
    }
    if end != name.len() {
        return Err(malformed(
            "filename has trailing NUL bytes, which the packet padding would desync",
        ));
    }
    Ok(())
}

/// One finished recovery set: packet bytes plus the metadata the manifest/post
/// stage needs to split them into obfuscated articles.
#[derive(Debug, Clone)]
pub struct CreatedSet {
    /// MD5 of the Main packet body; carried by every packet.
    pub set_id: [u8; 16],
    /// MD5(`first16k ‖ length ‖ name`): the file's identity in the set.
    pub file_id: [u8; 16],
    /// Slice size in bytes.
    pub block_size: u64,
    /// Number of data slices (ceil of length over slice size).
    pub data_slices: u64,
    /// Number of recovery slices (10%, see [`recovery_slice_count`]).
    pub recovery_slices: u64,
    /// Packets in emission order: Main, FileDesc, IFSC, then one RecvSlic per
    /// recovery slice (exponents `0..recovery_slices`). Kept separate so the
    /// posting stage can place each packet into its own article(s).
    pub packets: Vec<Vec<u8>>,
}

impl CreatedSet {
    /// The whole set as one concatenated packet stream (one `.par2` object).
    pub fn bytes(&self) -> Vec<u8> {
        self.packets.concat()
    }

    /// `(exponent, data)` pairs for the recovery slices, in exponent order.
    /// Each data slice is exactly [`Self::block_size`] bytes.
    pub fn recovery_pairs(&self) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::with_capacity(self.recovery_slices as usize);
        for packet in self.packets.iter().skip(3) {
            let body = &packet[64..];
            let exponent = u32::from_le_bytes(body[..4].try_into().unwrap()) as u16;
            out.push((exponent, body[4..].to_vec()));
        }
        out
    }
}

/// Streaming PAR2 set builder. Feed the ciphertext with [`push`](Self::push)
/// in any chunking; [`finish`](Self::finish) emits the packets. Byte counts
/// are enforced against the declared total: overruns fail at `push` time,
/// shortfalls at `finish` time.
pub struct Par2Creator {
    filename_bytes: Vec<u8>,
    total_len: u64,
    slice_size: usize,
    slice_words: usize,
    data_slices: u64,
    recovery_slices: usize,
    bases: Vec<u16>,
    /// Recovery accumulators as `u16` words (`recovery_slices × slice_words`).
    acc: Vec<u16>,
    /// Current input slice assembly buffer (bytes; always full `slice_size`).
    slice_buf: Vec<u8>,
    /// Transcode scratch (`slice_words` words).
    slice_scratch: Vec<u16>,
    slice_fill: usize,
    slice_index: u64,
    pushed: u64,
    whole_md5: md5::Context,
    first16k_md5: md5::Context,
    first16k_remaining: usize,
    slice_md5: md5::Context,
    slice_crc: crc32fast::Hasher,
    ifsc: Vec<([u8; 16], u32)>,
}

impl Par2Creator {
    /// Starts a set for `total_len` ciphertext bytes stored under `filename`
    /// (the obfuscated name the posting stage assigns; treated as opaque
    /// identity bytes, never logged). `slice_size` must already be aligned
    /// (see [`slice_size_for_article_payload`]).
    pub fn new(filename: &[u8], total_len: u64, slice_size: u64) -> Result<Self> {
        check_filename(filename)?;
        if slice_size == 0 || !slice_size.is_multiple_of(4) {
            return Err(malformed(format!(
                "slice size {slice_size} is not a non-zero multiple of 4"
            )));
        }
        if slice_size > MAX_BLOCK_SIZE {
            return Err(malformed(format!(
                "slice size {slice_size} exceeds the supported bound of {MAX_BLOCK_SIZE}"
            )));
        }
        if total_len == 0 {
            return Err(malformed("cannot build a recovery set for an empty file"));
        }
        let slice_size_usize = usize::try_from(slice_size)
            .map_err(|_| malformed(format!("slice size {slice_size} overflows usize")))?;
        let data_slices = data_slice_count(total_len, slice_size);
        let recovery_slices = recovery_slice_count(data_slices)?;
        let recovery_usize = usize::try_from(recovery_slices)
            .map_err(|_| malformed("recovery slice count overflows usize"))?;
        let acc_bytes = recovery_slices
            .checked_mul(slice_size)
            .ok_or_else(|| malformed("recovery accumulator size overflows u64"))?;
        if acc_bytes > MAX_ACCUMULATOR_BYTES {
            return Err(malformed(format!(
                "recovery accumulators need {acc_bytes} bytes, past the per-file bound of {MAX_ACCUMULATOR_BYTES}"
            )));
        }
        let data_usize = usize::try_from(data_slices)
            .map_err(|_| malformed("data slice count overflows usize"))?;
        let bases =
            gf16::input_bases(data_usize).ok_or_else(|| malformed("no Vandermonde bases left"))?;
        let slice_words = slice_size_usize / 2;
        Ok(Self {
            filename_bytes: filename.to_vec(),
            total_len,
            slice_size: slice_size_usize,
            slice_words,
            data_slices,
            recovery_slices: recovery_usize,
            bases,
            acc: vec![0u16; recovery_usize.saturating_mul(slice_words)],
            slice_buf: vec![0u8; slice_size_usize],
            slice_scratch: vec![0u16; slice_words],
            slice_fill: 0,
            slice_index: 0,
            pushed: 0,
            whole_md5: md5::Context::new(),
            first16k_md5: md5::Context::new(),
            first16k_remaining: FIRST_16K_SPAN
                .min(usize::try_from(total_len).unwrap_or(usize::MAX)),
            slice_md5: md5::Context::new(),
            slice_crc: crc32fast::Hasher::new(),
            ifsc: Vec::with_capacity(data_usize),
        })
    }

    /// Expected total length, for progress/checkpoint callers.
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Bytes accepted so far.
    pub fn pushed(&self) -> u64 {
        self.pushed
    }

    /// Feeds the next ciphertext chunk. Chunk boundaries are arbitrary —
    /// single bytes and multi-slice writes behave identically.
    pub fn push(&mut self, mut chunk: &[u8]) -> Result<()> {
        if (chunk.len() as u64) > self.total_len - self.pushed {
            return Err(malformed(format!(
                "push of {} bytes overruns the declared length {} ({} already pushed)",
                chunk.len(),
                self.total_len,
                self.pushed
            )));
        }
        self.whole_md5.consume(chunk);
        if self.first16k_remaining > 0 {
            let take = self.first16k_remaining.min(chunk.len());
            self.first16k_md5.consume(&chunk[..take]);
            self.first16k_remaining -= take;
        }
        while !chunk.is_empty() {
            let take = (self.slice_size - self.slice_fill).min(chunk.len());
            self.slice_buf[self.slice_fill..self.slice_fill + take].copy_from_slice(&chunk[..take]);
            self.slice_md5.consume(&chunk[..take]);
            self.slice_crc.update(&chunk[..take]);
            self.slice_fill += take;
            self.pushed += take as u64;
            chunk = &chunk[take..];
            if self.slice_fill == self.slice_size {
                self.commit_slice()?;
            }
        }
        Ok(())
    }

    /// Commits the assembled slice: IFSC entry plus one Reed-Solomon pass
    /// over every recovery accumulator.
    fn commit_slice(&mut self) -> Result<()> {
        let index = usize::try_from(self.slice_index)
            .map_err(|_| malformed("slice index overflows usize"))?;
        if index >= self.bases.len() {
            return Err(malformed("more slices than the declared length admits"));
        }
        // Zero-pad the tail: the assembly buffer may hold bytes from a
        // previous full slice, and every digest plus the RS matrix must see
        // the slice padded to full size.
        let pad = self.slice_size - self.slice_fill;
        if pad > 0 {
            self.slice_buf[self.slice_fill..].fill(0);
            let zeros = [0u8; ZERO_CHUNK_SIZE];
            let mut left = pad as u64;
            while left > 0 {
                let take = left.min(zeros.len() as u64) as usize;
                self.slice_md5.consume(&zeros[..take]);
                self.slice_crc.update(&zeros[..take]);
                left -= take as u64;
            }
        }
        let slice_ctx = std::mem::replace(&mut self.slice_md5, md5::Context::new());
        self.ifsc
            .push((slice_ctx.finalize().0, self.slice_crc.clone().finalize()));
        self.slice_crc = crc32fast::Hasher::new();

        // Transcode to words (slices are multiples of 4, hence even) and run
        // one multiply-accumulate per recovery row: acc[e] ^= slice *
        // base[index]^e.
        for (word, pair) in self
            .slice_scratch
            .iter_mut()
            .zip(self.slice_buf.as_chunks::<2>().0)
        {
            *word = u16::from_le_bytes([pair[0], pair[1]]);
        }
        let base = self.bases[index];
        for e in 0..self.recovery_slices {
            let factor = gf16::pow(base, e as u32);
            if factor == 0 {
                continue;
            }
            let acc_e = &mut self.acc[e * self.slice_words..(e + 1) * self.slice_words];
            gf16::madd(acc_e, &self.slice_scratch, factor);
        }

        self.slice_fill = 0;
        self.slice_index += 1;
        Ok(())
    }

    /// Finishes the set. Errors when fewer than `total_len` bytes were pushed.
    pub fn finish(mut self) -> Result<CreatedSet> {
        if self.pushed != self.total_len {
            return Err(malformed(format!(
                "short file: pushed {} of {} declared bytes",
                self.pushed, self.total_len
            )));
        }
        if self.slice_fill > 0 {
            self.commit_slice()?;
        }
        if self.slice_index != self.data_slices {
            return Err(malformed(format!(
                "internal error: committed {} slices for {} expected",
                self.slice_index, self.data_slices
            )));
        }
        let whole_md5 = self.whole_md5.finalize().0;
        let first16k_md5 = self.first16k_md5.finalize().0;

        let mut seed = Vec::with_capacity(24 + self.filename_bytes.len());
        seed.extend_from_slice(&first16k_md5);
        seed.extend_from_slice(&self.total_len.to_le_bytes());
        seed.extend_from_slice(&self.filename_bytes);
        let file_id = md5::compute(&seed).0;

        let block_size = self.slice_size as u64;
        let mut main_body = Vec::new();
        main_body.extend_from_slice(&block_size.to_le_bytes());
        main_body.extend_from_slice(&1u32.to_le_bytes());
        main_body.extend_from_slice(&file_id);
        let set_id = md5::compute(&main_body).0;

        let mut fd_body = Vec::new();
        fd_body.extend_from_slice(&file_id);
        fd_body.extend_from_slice(&whole_md5);
        fd_body.extend_from_slice(&first16k_md5);
        fd_body.extend_from_slice(&self.total_len.to_le_bytes());
        fd_body.extend_from_slice(&self.filename_bytes);

        // IFSC: file ID followed by one (slice MD5 ‖ CRC32) entry per block.
        let mut ifsc_body = Vec::new();
        ifsc_body.extend_from_slice(&file_id);
        for (hash, crc) in &self.ifsc {
            ifsc_body.extend_from_slice(hash);
            ifsc_body.extend_from_slice(&crc.to_le_bytes());
        }

        let mut packets = Vec::with_capacity(3 + self.recovery_slices);
        packets.push(packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body));
        packets.push(packet(&set_id, &ptype(b"FileDesc"), &fd_body));
        packets.push(packet(&set_id, &ptype(b"IFSC\0\0\0\0"), &ifsc_body));
        let mut row_bytes = vec![0u8; self.slice_size];
        for (e, acc_row) in self.acc.chunks_exact(self.slice_words).enumerate() {
            for (dst, word) in row_bytes
                .as_chunks_mut::<2>()
                .0
                .iter_mut()
                .zip(acc_row.iter())
            {
                dst.copy_from_slice(&word.to_le_bytes());
            }
            let mut body = Vec::with_capacity(4 + self.slice_size);
            body.extend_from_slice(&(e as u32).to_le_bytes());
            body.extend_from_slice(&row_bytes);
            packets.push(packet(&set_id, &ptype(b"RecvSlic"), &body));
        }

        Ok(CreatedSet {
            set_id,
            file_id,
            block_size,
            data_slices: self.data_slices,
            recovery_slices: self.recovery_slices as u64,
            packets,
        })
    }
}

/// Builds a whole set in one call (streaming equivalent: one `push`).
pub fn create_single_file(filename: &[u8], data: &[u8], slice_size: u64) -> Result<CreatedSet> {
    let mut creator = Par2Creator::new(filename, data.len() as u64, slice_size)?;
    creator.push(data)?;
    creator.finish()
}

/// Validation-grade Reed-Solomon decoder: reconstructs missing data slices
/// from surviving data slices plus recovery slices.
///
/// - `block_size` / `data_count` identify the set geometry (every slice is
///   exactly `block_size` bytes; slice `i` carries base `i` as in
///   [`gf16::input_bases`]);
/// - `present` maps data-slice index → surviving bytes;
/// - `recovery` maps recovery exponent → recovery-slice bytes (see
///   [`CreatedSet::recovery_pairs`]), in exponent-ascending order: the first
///   `m` pairs cover the `m` missing slices, and exponents `0..m` keep the
///   coefficient matrix a classical Vandermonde (always invertible for
///   distinct non-zero bases);
///
/// Returns the reconstructed `(index, bytes)` pairs in index order. Errors
/// when more slices are missing than recovery slices cover, on size or index
/// violations, when the dense-solve scratch would pass
/// [`MAX_RECOVERY_SCRATCH_BYTES`], or on a singular matrix (which honest
/// sets never produce).
pub fn recover_slices(
    block_size: usize,
    data_count: usize,
    present: &[(u32, Vec<u8>)],
    recovery: &[(u16, Vec<u8>)],
) -> Result<Vec<(u32, Vec<u8>)>> {
    if block_size == 0 || !block_size.is_multiple_of(2) {
        return Err(malformed("recovery needs a non-zero even block size"));
    }
    if data_count == 0 || data_count > MAX_DATA_SLICES as usize {
        return Err(malformed("recovery needs a sane data slice count"));
    }
    let mut is_present = vec![false; data_count];
    for (index, bytes) in present {
        let i = *index as usize;
        if i >= data_count {
            return Err(malformed("present slice index out of range"));
        }
        if bytes.len() != block_size {
            return Err(malformed("present slice has the wrong length"));
        }
        if is_present[i] {
            return Err(malformed("duplicate present slice index"));
        }
        is_present[i] = true;
    }
    for (_, bytes) in recovery {
        if bytes.len() != block_size {
            return Err(malformed("recovery slice has the wrong length"));
        }
    }
    let missing: Vec<usize> = (0..data_count).filter(|&i| !is_present[i]).collect();
    if missing.len() > recovery.len() {
        return Err(malformed(format!(
            "need {} recovery slices for {} missing data slices, have {}",
            missing.len(),
            missing.len(),
            recovery.len()
        )));
    }
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    // Fail closed before the dense `m × m` solve below: three `u16`
    // matrices (6 bytes per cell) must fit the scratch budget, checked
    // without overflow.
    {
        let m = missing.len() as u64;
        let bytes = m.checked_mul(m).and_then(|cells| cells.checked_mul(6));
        if bytes.is_none_or(|b| b > MAX_RECOVERY_SCRATCH_BYTES) {
            return Err(malformed(format!(
                "recovery of {} slices needs past the {MAX_RECOVERY_SCRATCH_BYTES}-byte scratch budget",
                missing.len()
            )));
        }
    }

    let bases = gf16::input_bases(data_count).ok_or_else(|| malformed("no bases"))?;
    let words = block_size / 2;
    let m = missing.len();
    let used = &recovery[..m];

    // Coefficient matrix A[r][c] = base[missing[c]]^exponent[r].
    let mut a = vec![vec![0u16; m]; m];
    for (r, (exp, _)) in used.iter().enumerate() {
        for (c, &j) in missing.iter().enumerate() {
            a[r][c] = gf16::pow(bases[j], u32::from(*exp));
        }
    }
    let inv = invert_matrix(&a).ok_or_else(|| malformed("singular recovery matrix"))?;

    let present_words: Vec<Vec<u16>> = present.iter().map(|(_, b)| bytes_to_words(b)).collect();
    let rec_words: Vec<Vec<u16>> = used.iter().map(|(_, b)| bytes_to_words(b)).collect();
    let present_order: Vec<usize> = present.iter().map(|(i, _)| *i as usize).collect();

    // The coefficient matrix is shared by all words: solve once per word as
    // x = inv * rhs with rhs[r] = rec[r] - sum_present(present * base^exp).
    let mut out: Vec<Vec<u16>> = vec![vec![0u16; words]; m];
    let mut rhs = vec![0u16; m];
    for w in 0..words {
        for (r, (exp, _)) in used.iter().enumerate() {
            rhs[r] = rec_words[r][w];
            for (p, &i) in present_order.iter().enumerate() {
                let f = gf16::pow(bases[i], u32::from(*exp));
                rhs[r] ^= gf16::mul(present_words[p][w], f);
            }
        }
        for (c, row) in out.iter_mut().enumerate().take(m) {
            let mut v = 0u16;
            for (r, &value) in rhs.iter().enumerate() {
                v ^= gf16::mul(inv[c][r], value);
            }
            row[w] = v;
        }
    }

    Ok(missing
        .into_iter()
        .zip(out)
        .map(|(i, w)| (i as u32, words_to_bytes(&w)))
        .collect())
}

/// Gauss-Jordan inversion over GF(2^16). Returns `None` for singular input.
fn invert_matrix(a: &[Vec<u16>]) -> Option<Vec<Vec<u16>>> {
    let n = a.len();
    if n == 0 || a.iter().any(|row| row.len() != n) {
        return None;
    }
    let mut left: Vec<Vec<u16>> = a.to_vec();
    let mut right: Vec<Vec<u16>> = (0..n)
        .map(|r| {
            let mut row = vec![0u16; n];
            row[r] = 1;
            row
        })
        .collect();
    for col in 0..n {
        let mut pivot = col;
        while pivot < n && left[pivot][col] == 0 {
            pivot += 1;
        }
        if pivot == n {
            return None;
        }
        left.swap(col, pivot);
        right.swap(col, pivot);
        let piv = left[col][col];
        if piv != 1 {
            for c in 0..n {
                left[col][c] = gf16::div(left[col][c], piv)?;
                right[col][c] = gf16::div(right[col][c], piv)?;
            }
        }
        for r in 0..n {
            if r != col && left[r][col] != 0 {
                let scale = left[r][col];
                for c in 0..n {
                    left[r][c] ^= gf16::mul(left[col][c], scale);
                    right[r][c] ^= gf16::mul(right[col][c], scale);
                }
            }
        }
    }
    Some(right)
}

fn bytes_to_words(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn words_to_bytes(words: &[u16]) -> Vec<u8> {
    let mut out = vec![0u8; words.len() * 2];
    for (dst, word) in out.as_chunks_mut::<2>().0.iter_mut().zip(words.iter()) {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Packet framing (same rules as the parser and the in-tree test builders)
// ---------------------------------------------------------------------------

fn ptype(suffix: &[u8]) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(b"PAR 2.0\0");
    t[8..8 + suffix.len().min(8)].copy_from_slice(&suffix[..suffix.len().min(8)]);
    t
}

fn packet(set_id: &[u8; 16], kind: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut aligned = body.to_vec();
    while !aligned.len().is_multiple_of(4) {
        aligned.push(0);
    }
    let mut p = Vec::with_capacity(64 + aligned.len());
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&((64 + aligned.len()) as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(set_id);
    p.extend_from_slice(kind);
    p.extend_from_slice(&aligned);
    let digest = md5::compute(&p[32..]).0;
    p[16..32].copy_from_slice(&digest);
    p
}
