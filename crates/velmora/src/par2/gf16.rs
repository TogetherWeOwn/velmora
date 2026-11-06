//! GF(2^16) arithmetic and the Reed-Solomon multiply-accumulate kernel used by
//! the PAR2 creator ([`super::creator`]).
//!
//! Interop contract (PAR 2.0 as implemented by the reference tool the repair
//! path shells out to; behaviour re-stated here so the math below is reviewable
//! without it — no reference code is used, everything is written fresh):
//!
//! - The field is GF(2^16) defined by x^16 + x^12 + x^3 + x + 1. Doubling
//!   (`xtime`) reduces an overflowing bit 16 with `0x100B` (the polynomial
//!   without the x^16 term).
//! - Data slices are read as little-endian `u16` words (all supported targets
//!   are little-endian); a short last slice is zero-padded to the full slice
//!   size before it enters the matrix.
//! - Input slice `i` (0-based) carries the Vandermonde base `antilog[logbase]`,
//!   where `logbase` starts at 0 and skips every value with
//!   `gcd(65535, logbase) != 1` (full-order bases only, so distinct recovery
//!   exponents always give distinct factors).
//! - Recovery slice with exponent `e` is `sum_i data[i] * base[i]^e`. Exponent
//!   0 is therefore plain XOR parity.
//!
//! The hot loop is `madd`: `dst[w] ^= src[w] * factor` over whole slices. The
//! factor is fixed per call, so it is expanded once into nibble tables (four
//! 16-entry tables for the low result byte, four for the high byte; 128 bytes
//! total) and then applied word by word. Two backends share the tables:
//!
//! - scalar ([`madd_scalar`]): portable fallback, also the differential-test
//!   oracle for the vector backend;
//! - simd128 ([`madd_simd128`]): `wasm32` with `target-feature=+simd128`,
//!   eight words per iteration via `i8x16_swizzle` nibble lookups, following
//!   the same `#[cfg]` shape as the yEnc decoder in [`crate::yenc`].
//!
//! [`madd`] picks the backend for the target. Everything else in this module
//! (log/antilog tables, [`mul`], [`pow`], [`inv`], [`input_bases`]) is shared.

use std::sync::OnceLock;

/// Low 16 bits of the field polynomial x^16 + x^12 + x^3 + x + 1: the value
/// XORed into a doubling word when bit 15 carries out.
pub const FIELD_POLY_LOW: u16 = 0x100B;

/// Full 17-bit generator, for documentation: `0x1100B`.
pub const FIELD_GENERATOR: u32 = 0x1100B;

/// Multiplicative group order (2^16 - 1).
pub const FIELD_ORDER: u32 = 65_535;

fn log_table() -> &'static [u16; 65_536] {
    static LOG: OnceLock<[u16; 65_536]> = OnceLock::new();
    LOG.get_or_init(|| {
        let mut log = [0u16; 65_536];
        let mut b: u32 = 1;
        for l in 0..FIELD_ORDER {
            log[b as usize] = l as u16;
            b <<= 1;
            if b & 0x1_0000 != 0 {
                b ^= FIELD_GENERATOR;
            }
        }
        log[0] = (FIELD_ORDER) as u16;
        log
    })
}

fn alog_table() -> &'static [u16; 65_536] {
    static ALOG: OnceLock<[u16; 65_536]> = OnceLock::new();
    ALOG.get_or_init(|| {
        let mut alog = [0u16; 65_536];
        let mut b: u32 = 1;
        for l in 0..FIELD_ORDER {
            alog[l as usize] = b as u16;
            b <<= 1;
            if b & 0x1_0000 != 0 {
                b ^= FIELD_GENERATOR;
            }
        }
        alog[FIELD_ORDER as usize] = 0;
        alog
    })
}

/// Field multiplication by double-and-add. Used for table construction and as
/// the independent scalar oracle in tests; the slice loop uses nibble tables.
pub fn mul(mut a: u16, mut b: u16) -> u16 {
    let mut acc = 0u16;
    while b != 0 {
        if b & 1 != 0 {
            acc ^= a;
        }
        let carry = (a & 0x8000) != 0;
        a <<= 1;
        if carry {
            a ^= FIELD_POLY_LOW;
        }
        b >>= 1;
    }
    acc
}

/// `base^exp` in the field. `exp == 0` gives 1 for any base (including 0),
/// which is what makes exponent-0 recovery slices plain XOR parity.
pub fn pow(base: u16, exp: u32) -> u16 {
    if exp == 0 {
        return 1;
    }
    if base == 0 {
        return 0;
    }
    let log = log_table();
    let alog = alog_table();
    let e = (u64::from(log[base as usize]) * u64::from(exp)) % u64::from(FIELD_ORDER);
    alog[e as usize]
}

/// Multiplicative inverse. Returns `None` for 0 (which has none).
pub fn inv(a: u16) -> Option<u16> {
    if a == 0 {
        return None;
    }
    let log = log_table();
    let alog = alog_table();
    let e = (u64::from(FIELD_ORDER) - u64::from(log[a as usize])) % u64::from(FIELD_ORDER);
    Some(alog[e as usize])
}

/// Field division. Returns `None` on division by zero.
pub fn div(a: u16, b: u16) -> Option<u16> {
    if b == 0 {
        return None;
    }
    if a == 0 {
        return Some(0);
    }
    let log = log_table();
    let alog = alog_table();
    let e = (u64::from(log[a as usize]) + u64::from(FIELD_ORDER) - u64::from(log[b as usize]))
        % u64::from(FIELD_ORDER);
    Some(alog[e as usize])
}

fn gcd(mut a: u32, mut b: u32) -> u32 {
    // Same shape as the reference `gcd` (Euclid, `gcd(a, 0) == 0`): only the
    // `== 1` outcome matters to callers.
    while a != 0 && b != 0 {
        if a > b {
            a %= b;
        } else {
            b %= a;
        }
    }
    a + b
}

/// Number of full-order bases in GF(2^16): φ(65535) = 32 768. No larger
/// [`input_bases`] count can succeed, so larger counts are rejected before
/// any allocation.
pub const MAX_INPUT_BASES: usize = 32_768;

/// Vandermonde bases for `count` input slices: the first `count` full-order
/// powers of the primitive element, i.e. `antilog[logbase]` skipping every
/// `logbase` with `gcd(65535, logbase) != 1`. Fails closed past the group
/// order (the scheme has no more full-order bases beyond it), and rejects
/// counts past [`MAX_INPUT_BASES`] before allocating.
pub fn input_bases(count: usize) -> Option<Vec<u16>> {
    if count > MAX_INPUT_BASES {
        return None;
    }
    let alog = alog_table();
    let mut bases = Vec::with_capacity(count);
    let mut logbase: u32 = 0;
    for _ in 0..count {
        while gcd(FIELD_ORDER, logbase) != 1 {
            logbase += 1;
            if logbase >= FIELD_ORDER {
                return None;
            }
        }
        bases.push(alog[logbase as usize]);
        logbase += 1;
    }
    Some(bases)
}

/// Per-factor nibble multiply tables: `mul(word, factor)` splits `word` into
/// four nibbles, looks each nibble up in its position table, and XORs the four
/// 16-bit contributions (stored as low/high byte halves for the swizzle
/// backend). 128 bytes total; rebuilt per (recovery row, input slice) factor,
/// which costs 64 scalar [`mul`]s against hundreds of thousands of word ops.
#[repr(align(16))]
#[derive(Debug, Clone)]
pub struct NibbleMul {
    /// `lo[k][n]` / `hi[k][n]`: low/high byte of `mul(n << (4*k), factor)`.
    pub lo: [[u8; 16]; 4],
    /// High bytes, same indexing.
    pub hi: [[u8; 16]; 4],
}

/// Builds the nibble tables for one factor. Factor 0 yields all-zero tables
/// (and [`madd`] skips the loop entirely for it).
pub fn nibble_tables(factor: u16) -> NibbleMul {
    let mut t = NibbleMul {
        lo: [[0; 16]; 4],
        hi: [[0; 16]; 4],
    };
    for k in 0..4 {
        for n in 0..16u16 {
            let p = mul(n << (4 * k), factor);
            t.lo[k as usize][n as usize] = p as u8;
            t.hi[k as usize][n as usize] = (p >> 8) as u8;
        }
    }
    t
}

/// Scalar multiply-accumulate: `dst[i] ^= mul(src[i], factor)` via `t`.
/// Panics on length mismatch; empty slices are a no-op.
pub fn madd_scalar(dst: &mut [u16], src: &[u16], t: &NibbleMul) {
    assert_eq!(dst.len(), src.len());
    for (d, &w) in dst.iter_mut().zip(src.iter()) {
        let n0 = (w & 0xF) as usize;
        let n1 = ((w >> 4) & 0xF) as usize;
        let n2 = ((w >> 8) & 0xF) as usize;
        let n3 = (w >> 12) as usize;
        let lo = t.lo[0][n0] ^ t.lo[1][n1] ^ t.lo[2][n2] ^ t.lo[3][n3];
        let hi = t.hi[0][n0] ^ t.hi[1][n1] ^ t.hi[2][n2] ^ t.hi[3][n3];
        *d ^= (u16::from(hi) << 8) | u16::from(lo);
    }
}

/// wasm simd128 multiply-accumulate over `words` little-endian `u16` words.
///
/// Layout per 8-word (16-byte) chunk, with `v` the source bytes
/// `[L0,H0,L1,H1,..,L7,H7]` (`word i == H_i<<8 | L_i`):
///
/// - `lo_idx = v & 0x0F` is `[n0_0,n2_0,n0_1,n2_1,..]`; `hi_idx` (after a
///   16-bit shift right by 4 and the same mask) is `[n1_0,n3_0,..]`;
/// - one shuffle regroups each into `[nA_0..nA_7, nC_0..nC_7]`;
/// - eight `i8x16_swizzle` lookups resolve the low (and, separately, high)
///   result bytes for both nibble positions; half-masks keep the valid lanes;
/// - the two halves are folded and interleaved back to `[lo,hi]` word order,
///   then XORed into the destination.
///
/// # Safety
///
/// `src` must be readable and `dst` readable/writable for `words` `u16`s;
/// `t` must be valid. Only whole 8-word chunks take the vector path; the
/// caller handles the tail with [`madd_scalar`].
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
pub unsafe fn madd_simd128(dst: *mut u16, src: *const u16, words: usize, t: &NibbleMul) {
    use core::arch::wasm32::*;

    // Regroups alternating nibble lanes into [first-8 | second-8].
    static REGROUP: [u8; 16] = [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15];
    // Keeps the low / high 8 lanes of a lookup result.
    static KEEP_LO: [u8; 16] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    static KEEP_HI: [u8; 16] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    // Folds [A0..A7, B0..B7] to (A^B) in the low 8 lanes.
    static FOLD_HI_DOWN: [u8; 16] = [8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7];
    // Spreads 8 lane values to even (or, masked, odd) byte lanes.
    static SPREAD: [u8; 16] = [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7];
    static KEEP_EVEN: [u8; 16] = [
        0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0,
    ];
    static KEEP_ODD: [u8; 16] = [
        0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF,
    ];

    let regroup = v128_load(REGROUP.as_ptr() as *const v128);
    let keep_lo = v128_load(KEEP_LO.as_ptr() as *const v128);
    let keep_hi = v128_load(KEEP_HI.as_ptr() as *const v128);
    let fold_hi_down = v128_load(FOLD_HI_DOWN.as_ptr() as *const v128);
    let spread = v128_load(SPREAD.as_ptr() as *const v128);
    let keep_even = v128_load(KEEP_EVEN.as_ptr() as *const v128);
    let keep_odd = v128_load(KEEP_ODD.as_ptr() as *const v128);
    let nibble_mask = i8x16_splat(0x0F);

    let t0lo = v128_load(t.lo[0].as_ptr() as *const v128);
    let t1lo = v128_load(t.lo[1].as_ptr() as *const v128);
    let t2lo = v128_load(t.lo[2].as_ptr() as *const v128);
    let t3lo = v128_load(t.lo[3].as_ptr() as *const v128);
    let t0hi = v128_load(t.hi[0].as_ptr() as *const v128);
    let t1hi = v128_load(t.hi[1].as_ptr() as *const v128);
    let t2hi = v128_load(t.hi[2].as_ptr() as *const v128);
    let t3hi = v128_load(t.hi[3].as_ptr() as *const v128);

    let chunks = words / 8;
    for c in 0..chunks {
        // SAFETY: `c` addresses a whole 8-word chunk inside the caller's
        // range; loads/stores are unaligned-safe.
        let s = v128_load((src as *const u8).add(c * 16) as *const v128);
        let lo_idx = v128_and(s, nibble_mask);
        let shifted = u16x8_shr(s, 4);
        let hi_idx = v128_and(shifted, nibble_mask);
        let idx_lo = i8x16_swizzle(lo_idx, regroup);
        let idx_hi = i8x16_swizzle(hi_idx, regroup);

        let lo_res = v128_xor(
            v128_xor(
                v128_and(i8x16_swizzle(t0lo, idx_lo), keep_lo),
                v128_and(i8x16_swizzle(t1lo, idx_hi), keep_lo),
            ),
            v128_xor(
                v128_and(i8x16_swizzle(t2lo, idx_lo), keep_hi),
                v128_and(i8x16_swizzle(t3lo, idx_hi), keep_hi),
            ),
        );
        let hi_res = v128_xor(
            v128_xor(
                v128_and(i8x16_swizzle(t0hi, idx_lo), keep_lo),
                v128_and(i8x16_swizzle(t1hi, idx_hi), keep_lo),
            ),
            v128_xor(
                v128_and(i8x16_swizzle(t2hi, idx_lo), keep_hi),
                v128_and(i8x16_swizzle(t3hi, idx_hi), keep_hi),
            ),
        );

        // Fold [A | B] halves to A^B in the low 8 lanes.
        let lo_folded = v128_and(
            v128_xor(lo_res, i8x16_swizzle(lo_res, fold_hi_down)),
            keep_lo,
        );
        let hi_folded = v128_and(
            v128_xor(hi_res, i8x16_swizzle(hi_res, fold_hi_down)),
            keep_lo,
        );
        // Interleave to [lo0,hi0,lo1,hi1,..] word order.
        let emit = v128_xor(
            v128_and(i8x16_swizzle(lo_folded, spread), keep_even),
            v128_and(i8x16_swizzle(hi_folded, spread), keep_odd),
        );

        let d = v128_load((dst as *const u8).add(c * 16) as *const v128);
        v128_store((dst as *mut u8).add(c * 16) as *mut v128, v128_xor(d, emit));
    }
}

/// Multiply-accumulate: `dst[i] ^= mul(src[i], factor)` for whole slices.
/// Dispatches to the simd128 kernel where available, otherwise the scalar
/// nibble loop. A zero factor is a no-op (matches the reference early-out).
pub fn madd(dst: &mut [u16], src: &[u16], factor: u16) {
    // Unconditional: this safe fn guards unsafe backend reads sized by
    // `dst.len()`, so a shorter `src` must panic here, never read OOB in a
    // release simd128 build.
    assert_eq!(dst.len(), src.len());
    if factor == 0 || dst.is_empty() {
        return;
    }
    let t = nibble_tables(factor);
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        let words = dst.len();
        let chunks = words / 8 * 8;
        if chunks > 0 {
            // SAFETY: both slices cover `words` words; the vector path only
            // touches the whole-chunk prefix, the scalar path the tail.
            unsafe {
                madd_simd128(dst.as_mut_ptr(), src.as_ptr(), chunks, &t);
            }
        }
        madd_scalar(&mut dst[chunks..], &src[chunks..], &t);
    }
    #[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
    {
        madd_scalar(dst, src, &t);
    }
}
