//! Reed-Solomon erasure code over article-sized shards: the repair-parity
//! codec. Pure computation: no format, no I/O, no storage.
//!
//! One stripe is one extent. Data shard `i` is the payload of the extent's
//! article `i`; each parity shard is one more article. Any `t` lost data
//! shards can be rebuilt from the surviving data shards and any `t` parity
//! shards.
//!
//! Nothing here depends on that reading. The shard count, the parity rows
//! and the shard lengths are arguments, so a stripe can as well be a group
//! of extents with one extent per shard.
//!
//! # The code
//!
//! - **Field:** GF(2^16) with the polynomial `0x1100B`, through the kernel
//!   in [`crate::par2::gf16`] (scalar everywhere, simd128 on `wasm32` built
//!   with `target-feature=+simd128`). This module adds no `unsafe`.
//! - **Shards:** every shard is read as little-endian `u16` words and
//!   zero-padded to the shard length `L`: the longest data shard, rounded up
//!   to an even number of bytes ([`shard_len`]). Parity shards are exactly
//!   `L` bytes.
//! - **Generator:** a Cauchy matrix. The coefficient of data shard `i` in
//!   parity row `j` is `1 / (x_j ^ y_i)` with `y_i = i` and
//!   `x_j = 0x8000 | j` ([`coefficient`]). `i` and `j` are both below
//!   `0x8000`, so the `x` and `y` sets are disjoint and the denominator is
//!   never zero. Every square sub-matrix of a Cauchy matrix is invertible,
//!   so every loss pattern of up to `t` data shards is recoverable from any
//!   `t` parity rows. (PAR2's Vandermonde matrix does not have this property
//!   without restricting its constants, and row 0 here is deliberately not
//!   plain XOR.)
//! - **Rows:** a parity shard is identified by its row number `j`
//!   (`0..=0x7FFF`). The row numbers of a stripe need not be contiguous: a
//!   later repair can add a row that was never used before.
//!
//! # What the codec checks, and what it cannot
//!
//! [`reconstruct`] is an erasure decoder: it is told which shards are lost.
//! It refuses, with a named error and no bytes:
//!
//! - more lost data shards than parity shards ([`RsError::TooManyLosses`]);
//! - shard lengths that cannot belong to one stripe;
//! - a rebuilt shard whose bytes past its stated length are not zero
//!   ([`RsError::PaddingNotZero`]): the stripe it was given is inconsistent.
//!
//! It cannot tell that a shard it was handed as *present* holds wrong
//! bytes when the rebuilt shards are as long as the stripe: with exactly as
//! many parity shards as losses there is no redundancy left to check
//! against. The caller must check every rebuilt shard against the digest it
//! holds for that article before using a byte of it, and should check every
//! shard it passes in the same way. Parity shards beyond the number of
//! losses are not used as a cross-check. If a rebuilt shard fails its
//! digest, one of the shards passed in is wrong: the caller finds it by
//! its own digests, or tries again with other parity shards.
//!
//! # Cost
//!
//! Encoding `m` rows over `k` data shards is `k * m` multiply-accumulate
//! passes over `L / 2` words. Rebuilding `t` shards is `t * (k - t)` passes
//! for the syndromes plus `t * t` for the solve. All data shards of the
//! stripe are passed in at once. On top of them and of the shards returned,
//! working memory peaks at one shard of scratch plus `m + 1` shards
//! (encode: the `m` rows as words, and one row being copied out as bytes)
//! or `t + 2` shards (decode: `t` syndromes, the scratch, and one shard
//! being copied out), plus two `t * t` matrices of 2-byte entries for the
//! solve (16 KiB at the limit). One call takes at most
//! [`MAX_PARITY_SHARDS`] parity shards.

use std::fmt;

use crate::par2::gf16;

/// Most data shards in one stripe: data shard indexes are the Cauchy `y`
/// values `0..0x8000`.
pub const MAX_DATA_SHARDS: usize = 0x8000;

/// Highest parity row number: parity rows are the Cauchy `x` values
/// `0x8000 | row`.
pub const MAX_PARITY_ROW: u16 = 0x7FFF;

/// Most parity shards in one call: rows asked of [`encode`], or parity
/// shards handed to [`reconstruct`] (so also the most lost data shards one
/// call rebuilds). Far above any configured stripe; it bounds the decode
/// matrix (`t * t` entries, solved in `t^3` steps) and the working memory.
pub const MAX_PARITY_SHARDS: usize = 64;

/// Why an encode or a reconstruction was refused. No variant carries shard
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsError {
    /// The stripe has no data shards.
    NoDataShards,
    /// The stripe has more than [`MAX_DATA_SHARDS`] data shards.
    TooManyDataShards { count: usize },
    /// More than [`MAX_PARITY_SHARDS`] parity rows or parity shards in one
    /// call.
    TooManyParityShards { count: usize },
    /// A parity row number is above [`MAX_PARITY_ROW`].
    RowOutOfRange { row: u16 },
    /// The same parity row number was given twice.
    DuplicateRow { row: u16 },
    /// Data shard `index` has no bytes (present) or a stated length of zero
    /// (lost).
    EmptyDataShard { index: usize },
    /// A parity shard's length is zero or odd, or differs from the other
    /// parity shards' length.
    ParityLength { row: u16, len: usize },
    /// The data shard lengths do not give the stripe's shard length: the
    /// longest of them, rounded up to even, must equal the parity shards'
    /// length.
    ShardLengthMismatch { expected: usize, parity: usize },
    /// More data shards are lost than parity shards were supplied. Nothing
    /// was rebuilt.
    TooManyLosses { lost: usize, parity: usize },
    /// The rebuilt data shard `index` has a non-zero byte past its stated
    /// length: the shards supplied do not belong to one consistent stripe.
    /// Nothing is returned.
    PaddingNotZero { index: usize },
    /// The decode matrix was singular. A Cauchy matrix never is; this is a
    /// defect, reported instead of returning bytes.
    SingularMatrix,
}

impl fmt::Display for RsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RsError::NoDataShards => write!(f, "parity: the stripe has no data shards"),
            RsError::TooManyDataShards { count } => write!(
                f,
                "parity: {count} data shards, the limit is {MAX_DATA_SHARDS}"
            ),
            RsError::TooManyParityShards { count } => write!(
                f,
                "parity: {count} parity shards in one call, the limit is {MAX_PARITY_SHARDS}"
            ),
            RsError::RowOutOfRange { row } => write!(
                f,
                "parity: row {row} is above the highest row {MAX_PARITY_ROW}"
            ),
            RsError::DuplicateRow { row } => write!(f, "parity: row {row} given twice"),
            RsError::EmptyDataShard { index } => {
                write!(f, "parity: data shard {index} is empty")
            }
            RsError::ParityLength { row, len } => write!(
                f,
                "parity: row {row} has {len} bytes; parity shards are non-empty, even and of one length"
            ),
            RsError::ShardLengthMismatch { expected, parity } => write!(
                f,
                "parity: the data shards give a shard length of {expected} bytes, the parity shards have {parity}"
            ),
            RsError::TooManyLosses { lost, parity } => write!(
                f,
                "parity: {lost} data shards lost, {parity} parity shards supplied: not recoverable"
            ),
            RsError::PaddingNotZero { index } => write!(
                f,
                "parity: rebuilt data shard {index} has non-zero padding: the stripe is inconsistent"
            ),
            RsError::SingularMatrix => write!(f, "parity: singular decode matrix"),
        }
    }
}

impl std::error::Error for RsError {}

/// One data shard handed to [`reconstruct`].
#[derive(Debug, Clone, Copy)]
pub enum DataShard<'a> {
    /// The shard's bytes (the article payload, unpadded).
    Present(&'a [u8]),
    /// The shard is lost. `len` is its byte length (the article's payload
    /// length on record); the rebuilt shard is cut to it.
    Lost { len: usize },
}

/// One parity shard handed to [`reconstruct`]: its row number and its
/// bytes (exactly the stripe's shard length).
#[derive(Debug, Clone, Copy)]
pub struct ParityShard<'a> {
    /// Parity row number, as given to [`encode`].
    pub row: u16,
    /// The parity shard, as returned by [`encode`].
    pub bytes: &'a [u8],
}

/// The shard length of a stripe whose data shards have these byte lengths:
/// the longest, rounded up to an even number. `None` for no shards or when
/// every length is zero.
pub fn shard_len<I: IntoIterator<Item = usize>>(data_lens: I) -> Option<usize> {
    let longest = data_lens.into_iter().max()?;
    if longest == 0 {
        return None;
    }
    // A slice is at most `isize::MAX` bytes, so this cannot overflow for
    // real shards; fail closed for any other input.
    longest.checked_add(longest & 1)
}

/// Cauchy coefficient of data shard `data_index` in parity row `row`:
/// `1 / ((0x8000 | row) ^ data_index)`. Never zero.
pub fn coefficient(row: u16, data_index: usize) -> Result<u16, RsError> {
    if row > MAX_PARITY_ROW {
        return Err(RsError::RowOutOfRange { row });
    }
    if data_index >= MAX_DATA_SHARDS {
        return Err(RsError::TooManyDataShards {
            count: data_index.saturating_add(1),
        });
    }
    // `data_index < 0x8000` and bit 15 is set by the row term, so the
    // denominator has bit 15 set and is not zero.
    let denominator = (0x8000 | row) ^ (data_index as u16);
    gf16::inv(denominator).ok_or(RsError::SingularMatrix)
}

fn check_data_count(count: usize) -> Result<(), RsError> {
    if count == 0 {
        return Err(RsError::NoDataShards);
    }
    if count > MAX_DATA_SHARDS {
        return Err(RsError::TooManyDataShards { count });
    }
    Ok(())
}

fn check_parity_count(count: usize) -> Result<(), RsError> {
    if count > MAX_PARITY_SHARDS {
        return Err(RsError::TooManyParityShards { count });
    }
    Ok(())
}

fn check_rows<I: IntoIterator<Item = u16>>(rows: I) -> Result<(), RsError> {
    let mut seen: Vec<u16> = Vec::new();
    for row in rows {
        if row > MAX_PARITY_ROW {
            return Err(RsError::RowOutOfRange { row });
        }
        seen.push(row);
    }
    seen.sort_unstable();
    for pair in seen.windows(2) {
        if pair[0] == pair[1] {
            return Err(RsError::DuplicateRow { row: pair[0] });
        }
    }
    Ok(())
}

/// Reads `bytes` into `words` as little-endian `u16`s, zero-padding the
/// rest. `bytes` must fit: `bytes.len() <= 2 * words.len()` (checked by
/// every caller before the call; a longer input panics here instead of
/// being cut silently).
fn load_words(words: &mut [u16], bytes: &[u8]) {
    assert!(bytes.len() <= words.len() * 2);
    let whole = bytes.len() / 2;
    let (pairs, _) = bytes.as_chunks::<2>();
    for (word, pair) in words[..whole].iter_mut().zip(pairs) {
        *word = u16::from_le_bytes(*pair);
    }
    let mut next = whole;
    if !bytes.len().is_multiple_of(2) {
        words[next] = u16::from(bytes[bytes.len() - 1]);
        next += 1;
    }
    words[next..].fill(0);
}

fn words_to_bytes(words: &[u16]) -> Vec<u8> {
    let mut bytes = vec![0u8; words.len() * 2];
    let (pairs, _) = bytes.as_chunks_mut::<2>();
    for (pair, word) in pairs.iter_mut().zip(words.iter()) {
        *pair = word.to_le_bytes();
    }
    bytes
}

/// Computes the parity shards `rows` of the stripe `data`.
///
/// `data[i]` is data shard `i` (unpadded; lengths may differ, none may be
/// empty). Returns one parity shard per entry of `rows`, in the same order,
/// each [`shard_len`] bytes long. At most [`MAX_PARITY_SHARDS`] rows per
/// call. The result is a pure function of the data
/// bytes and the row numbers: a repeat gives the same bytes, and a row
/// computed alone equals the same row computed with others.
pub fn encode(data: &[&[u8]], rows: &[u16]) -> Result<Vec<Vec<u8>>, RsError> {
    check_data_count(data.len())?;
    check_parity_count(rows.len())?;
    check_rows(rows.iter().copied())?;
    if let Some(index) = data.iter().position(|shard| shard.is_empty()) {
        return Err(RsError::EmptyDataShard { index });
    }
    let len = shard_len(data.iter().map(|shard| shard.len())).ok_or(RsError::NoDataShards)?;
    let words = len / 2;

    let mut parity: Vec<Vec<u16>> = rows.iter().map(|_| vec![0u16; words]).collect();
    let mut scratch = vec![0u16; words];
    for (index, shard) in data.iter().enumerate() {
        load_words(&mut scratch, shard);
        for (row, acc) in rows.iter().zip(parity.iter_mut()) {
            gf16::madd(acc, &scratch, coefficient(*row, index)?);
        }
    }
    // Each row's words are freed as soon as its bytes exist.
    Ok(parity
        .into_iter()
        .map(|words| words_to_bytes(&words))
        .collect())
}

/// Inverts the square matrix `a` (row-major, `n * n` entries) over
/// GF(2^16) by Gauss-Jordan elimination. `None` if it is singular.
fn invert(mut a: Vec<u16>, n: usize) -> Option<Vec<u16>> {
    debug_assert_eq!(a.len(), n * n);
    let mut inverse = vec![0u16; n * n];
    for d in 0..n {
        inverse[d * n + d] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r * n + col] != 0)?;
        if pivot != col {
            for c in 0..n {
                a.swap(pivot * n + c, col * n + c);
                inverse.swap(pivot * n + c, col * n + c);
            }
        }
        let scale = gf16::inv(a[col * n + col])?;
        for c in 0..n {
            a[col * n + c] = gf16::mul(a[col * n + c], scale);
            inverse[col * n + c] = gf16::mul(inverse[col * n + c], scale);
        }
        for r in 0..n {
            let factor = a[r * n + col];
            if r == col || factor == 0 {
                continue;
            }
            for c in 0..n {
                let x = gf16::mul(a[col * n + c], factor);
                a[r * n + c] ^= x;
                let y = gf16::mul(inverse[col * n + c], factor);
                inverse[r * n + c] ^= y;
            }
        }
    }
    Some(inverse)
}

/// Rebuilds the lost data shards of a stripe.
///
/// `data` lists every data shard of the stripe in order, present or lost.
/// `parity` holds surviving parity shards, each with the row number it was
/// encoded under. With `t` shards lost, the first `t` entries of `parity`
/// are used; further entries are validated (row, length) and otherwise
/// ignored. At most [`MAX_PARITY_SHARDS`] entries.
///
/// Returns the rebuilt shards in the order of their index in `data`, each
/// cut to its stated length. With nothing lost the result is empty and
/// only the number of `parity` entries is checked, not their content.
///
/// Errors, always without bytes: see [`RsError`]. In particular more losses
/// than parity shards is [`RsError::TooManyLosses`].
///
/// The caller must check each rebuilt shard against the digest on record
/// for it before use (module docs: the codec cannot detect a wrong
/// *present* shard in general).
pub fn reconstruct(
    data: &[DataShard<'_>],
    parity: &[ParityShard<'_>],
) -> Result<Vec<Vec<u8>>, RsError> {
    check_data_count(data.len())?;
    let mut lost: Vec<(usize, usize)> = Vec::new();
    for (index, shard) in data.iter().enumerate() {
        match *shard {
            DataShard::Present(bytes) => {
                if bytes.is_empty() {
                    return Err(RsError::EmptyDataShard { index });
                }
            }
            DataShard::Lost { len } => {
                if len == 0 {
                    return Err(RsError::EmptyDataShard { index });
                }
                lost.push((index, len));
            }
        }
    }
    check_parity_count(parity.len())?;
    if lost.is_empty() {
        return Ok(Vec::new());
    }
    let t = lost.len();
    if parity.len() < t {
        return Err(RsError::TooManyLosses {
            lost: t,
            parity: parity.len(),
        });
    }

    // Every parity shard supplied must be well formed, used or not.
    check_rows(parity.iter().map(|p| p.row))?;
    let len = parity[0].bytes.len();
    for p in parity {
        if p.bytes.len() != len || len == 0 || !len.is_multiple_of(2) {
            return Err(RsError::ParityLength {
                row: p.row,
                len: p.bytes.len(),
            });
        }
    }
    // Every data length is known (lost shards state theirs), so the
    // stripe's shard length is known exactly and must be the parity length.
    let expected = shard_len(data.iter().map(|shard| match *shard {
        DataShard::Present(bytes) => bytes.len(),
        DataShard::Lost { len } => len,
    }))
    // `None` only for a stated length that cannot be rounded up: no real
    // shard is that long.
    .ok_or(RsError::ShardLengthMismatch {
        expected: usize::MAX,
        parity: len,
    })?;
    if expected != len {
        return Err(RsError::ShardLengthMismatch {
            expected,
            parity: len,
        });
    }
    let words = len / 2;
    let used = &parity[..t];

    // Syndromes: parity row minus the surviving data's share of it. What
    // is left is the lost shards' share: S = A * X, with
    // A[a][b] = coefficient(row_a, lost_b).
    let mut syndromes: Vec<Vec<u16>> = Vec::with_capacity(t);
    for p in used {
        let mut s = vec![0u16; words];
        load_words(&mut s, p.bytes);
        syndromes.push(s);
    }
    let mut scratch = vec![0u16; words];
    for (index, shard) in data.iter().enumerate() {
        let DataShard::Present(bytes) = *shard else {
            continue;
        };
        load_words(&mut scratch, bytes);
        for (p, s) in used.iter().zip(syndromes.iter_mut()) {
            gf16::madd(s, &scratch, coefficient(p.row, index)?);
        }
    }

    let mut matrix = Vec::with_capacity(t * t);
    for p in used {
        for &(index, _) in &lost {
            matrix.push(coefficient(p.row, index)?);
        }
    }
    let inverse = invert(matrix, t).ok_or(RsError::SingularMatrix)?;

    // X = A^-1 * S. All shards are rebuilt and checked before any is
    // returned.
    let mut rebuilt: Vec<Vec<u8>> = Vec::with_capacity(t);
    for (b, &(index, shard_bytes)) in lost.iter().enumerate() {
        let mut x = vec![0u16; words];
        for (a, s) in syndromes.iter().enumerate() {
            gf16::madd(&mut x, s, inverse[b * t + a]);
        }
        let mut bytes = words_to_bytes(&x);
        if bytes[shard_bytes..].iter().any(|&byte| byte != 0) {
            return Err(RsError::PaddingNotZero { index });
        }
        bytes.truncate(shard_bytes);
        rebuilt.push(bytes);
    }
    Ok(rebuilt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Field inverse without the log tables: a^(2^16 - 2) by repeated
    /// multiplication with the double-and-add [`gf16::mul`].
    fn slow_inv(a: u16) -> u16 {
        let mut result = 1u16;
        let mut base = a;
        let mut exp = 65_534u32;
        while exp != 0 {
            if exp & 1 != 0 {
                result = gf16::mul(result, base);
            }
            base = gf16::mul(base, base);
            exp >>= 1;
        }
        result
    }

    /// Parity by the definition, a word at a time, without `madd`.
    fn slow_encode(data: &[&[u8]], rows: &[u16]) -> Vec<Vec<u8>> {
        let len = shard_len(data.iter().map(|d| d.len())).unwrap();
        let word = |shard: &[u8], w: usize| {
            let lo = shard.get(2 * w).copied().unwrap_or(0);
            let hi = shard.get(2 * w + 1).copied().unwrap_or(0);
            u16::from_le_bytes([lo, hi])
        };
        rows.iter()
            .map(|&row| {
                let mut out = Vec::with_capacity(len);
                for w in 0..len / 2 {
                    let mut acc = 0u16;
                    for (i, shard) in data.iter().enumerate() {
                        let c = slow_inv((0x8000 | row) ^ i as u16);
                        acc ^= gf16::mul(word(shard, w), c);
                    }
                    out.extend_from_slice(&acc.to_le_bytes());
                }
                out
            })
            .collect()
    }

    fn bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 56) as u8
            })
            .collect()
    }

    #[test]
    fn coefficient_is_the_cauchy_inverse_and_never_zero() {
        for row in [0u16, 1, 2, 7, 0x7FFF] {
            for index in [0usize, 1, 11, 23, 0x7FFF] {
                let c = coefficient(row, index).unwrap();
                assert_ne!(c, 0);
                assert_eq!(gf16::mul(c, (0x8000 | row) ^ index as u16), 1);
                assert_eq!(c, slow_inv((0x8000 | row) ^ index as u16));
            }
        }
        assert_eq!(
            coefficient(0x8000, 0),
            Err(RsError::RowOutOfRange { row: 0x8000 })
        );
        assert_eq!(
            coefficient(0, 0x8000),
            Err(RsError::TooManyDataShards { count: 0x8001 })
        );
    }

    #[test]
    fn shard_len_is_the_longest_rounded_up_to_even() {
        assert_eq!(shard_len([721_120, 721_072, 5]), Some(721_120));
        assert_eq!(shard_len([69]), Some(70));
        assert_eq!(shard_len([1, 2, 3]), Some(4));
        assert_eq!(shard_len([0, 0]), None);
        assert_eq!(shard_len(std::iter::empty()), None);
        assert_eq!(shard_len([usize::MAX]), None);
    }

    #[test]
    fn encode_matches_the_definition() {
        // Lengths cross the 8-word vector chunk and include odd ones.
        for lens in [
            vec![1usize],
            vec![2, 1],
            vec![15, 16, 17],
            vec![33, 32, 31, 7],
            vec![64, 63, 1, 40, 39],
        ] {
            let data: Vec<Vec<u8>> = lens
                .iter()
                .enumerate()
                .map(|(i, &len)| bytes(0xA5 + i as u64, len))
                .collect();
            let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
            let rows = [0u16, 1, 2, 9, 0x7FFF];
            assert_eq!(encode(&refs, &rows).unwrap(), slow_encode(&refs, &rows));
        }
    }

    #[test]
    fn a_row_alone_equals_the_row_among_others() {
        let data: Vec<Vec<u8>> = (0..5).map(|i| bytes(i, 40 + i as usize)).collect();
        let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let all = encode(&refs, &[0, 1, 2, 3]).unwrap();
        for (at, row) in [0u16, 1, 2, 3].iter().enumerate() {
            assert_eq!(encode(&refs, &[*row]).unwrap()[0], all[at]);
        }
        // Order of the request is the order of the answer.
        let swapped = encode(&refs, &[3, 0]).unwrap();
        assert_eq!(swapped[0], all[3]);
        assert_eq!(swapped[1], all[0]);
        assert!(encode(&refs, &[]).unwrap().is_empty());
    }

    #[test]
    fn a_one_shard_stripe_is_not_a_copy_of_the_data() {
        let data = bytes(7, 4096);
        let parity = encode(&[&data], &[0]).unwrap();
        assert_eq!(parity[0].len(), data.len());
        assert_ne!(parity[0], data);
    }

    #[test]
    fn invert_gives_the_inverse_of_every_small_cauchy_block() {
        for n in 1..=6usize {
            let rows: Vec<u16> = (0..n as u16).map(|j| j * 3 + 1).collect();
            let cols: Vec<usize> = (0..n).map(|i| i * 5 + 2).collect();
            let mut a = Vec::new();
            for &r in &rows {
                for &c in &cols {
                    a.push(coefficient(r, c).unwrap());
                }
            }
            let inverse = invert(a.clone(), n).unwrap();
            for r in 0..n {
                for c in 0..n {
                    let mut acc = 0u16;
                    for m in 0..n {
                        acc ^= gf16::mul(a[r * n + m], inverse[m * n + c]);
                    }
                    assert_eq!(acc, u16::from(r == c), "n {n} at ({r},{c})");
                }
            }
        }
        // A singular matrix is refused.
        assert_eq!(invert(vec![1, 2, 1, 2], 2), None);
        assert_eq!(invert(vec![0], 1), None);
        // A zero on the diagonal needs the row swap.
        assert_eq!(invert(vec![0, 1, 1, 0], 2), Some(vec![0, 1, 1, 0]));
    }

    #[test]
    fn encode_refuses_bad_stripes() {
        let a = [1u8, 2, 3];
        assert_eq!(encode(&[], &[0]), Err(RsError::NoDataShards));
        assert_eq!(
            encode(&[&a, &[]], &[0]),
            Err(RsError::EmptyDataShard { index: 1 })
        );
        assert_eq!(
            encode(&[&a], &[0x8000]),
            Err(RsError::RowOutOfRange { row: 0x8000 })
        );
        assert_eq!(
            encode(&[&a], &[4, 1, 4]),
            Err(RsError::DuplicateRow { row: 4 })
        );
        let rows: Vec<u16> = (0..=MAX_PARITY_SHARDS as u16).collect();
        assert_eq!(
            encode(&[&a], &rows),
            Err(RsError::TooManyParityShards {
                count: MAX_PARITY_SHARDS + 1
            })
        );
        assert_eq!(encode(&[&a], &rows[1..]).unwrap().len(), MAX_PARITY_SHARDS);
        let many: Vec<&[u8]> = vec![&a; MAX_DATA_SHARDS + 1];
        assert_eq!(
            encode(&many, &[0]),
            Err(RsError::TooManyDataShards {
                count: MAX_DATA_SHARDS + 1
            })
        );
    }

    #[test]
    fn the_last_data_index_and_row_work() {
        // Index 0x7FFF with row 0x7FFF: denominator 0x8000 ^ 0x7FFF ^ 0x7FFF.
        let a = [9u8, 8, 7, 6];
        let many: Vec<&[u8]> = vec![&a; MAX_DATA_SHARDS];
        let parity = encode(&many, &[MAX_PARITY_ROW]).unwrap();
        let mut shards: Vec<DataShard<'_>> = many.iter().map(|s| DataShard::Present(s)).collect();
        shards[MAX_DATA_SHARDS - 1] = DataShard::Lost { len: 4 };
        let rebuilt = reconstruct(
            &shards,
            &[ParityShard {
                row: MAX_PARITY_ROW,
                bytes: &parity[0],
            }],
        )
        .unwrap();
        assert_eq!(rebuilt, vec![a.to_vec()]);
    }
}
