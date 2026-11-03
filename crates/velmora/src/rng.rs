//! CSPRNG bytes for posting obfuscation, portable across native and wasm.
//!
//! All posting randomness (message-IDs, subjects, yEnc names, From lines,
//! date jitter, newsgroup picks) flows through [`FillRandom`]. Production
//! code uses [`SystemRng`], which is `getrandom` with the `js` feature so it
//! builds on `wasm32-unknown-unknown` (Workers) as well as native targets.
//! Tests use deterministic byte sources instead and assert shape properties
//! (length, charset, contract validity, uniqueness) against the real RNG.

use std::io;

use crate::error::{Error, Result};

/// A fill-with-random-bytes source. Generic over the source so obfuscation
/// stays deterministic under test without a test-only production path.
pub trait FillRandom {
    /// Appends exactly `dest.len()` random bytes to `dest`.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()>;
}

/// System CSPRNG via `getrandom` (with the `js` backend on wasm32, so this
/// builds for the Workers posting path). There is deliberately no `Default`
/// seedable constructor: every byte comes from the OS/browser entropy pool.
pub struct SystemRng;

impl FillRandom for SystemRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::getrandom(dest).map_err(|_| {
            // `io::Error::other` is stable since 1.74; MSRV is 1.75.
            Error::Io(io::Error::other(
                "CSPRNG failure: no random bytes available",
            ))
        })
    }
}

/// Uniform integer in `[0, bound)` via rejection sampling on `u64` — no
/// modulo bias, so newsgroup picks and jitter offsets are uniform over the
/// operator allow-list and the jitter window. `bound == 0` is a caller bug
/// and fails closed.
pub fn uniform_below<R: FillRandom>(rng: &mut R, bound: u64) -> Result<u64> {
    if bound == 0 {
        return Err(Error::Malformed(
            "RNG uniform bound must be non-zero".into(),
        ));
    }
    // Largest multiple of `bound` that fits in u64: values at or above it
    // are redrawn so the accepted range maps evenly onto [0, bound).
    let limit = u64::MAX - (u64::MAX % bound) - 1;
    loop {
        let mut raw = [0u8; 8];
        rng.fill_bytes(&mut raw)?;
        let value = u64::from_le_bytes(raw);
        if value <= limit {
            return Ok(value % bound);
        }
    }
}

/// Fills `dest` with characters drawn uniformly from `alphabet` (1..=256
/// bytes long; shorter alphabets redraw via rejection so every character is
/// equally likely). An empty or over-long alphabet is a caller bug and fails
/// closed.
pub fn fill_alphabet<R: FillRandom>(rng: &mut R, dest: &mut [u8], alphabet: &[u8]) -> Result<()> {
    if alphabet.is_empty() || alphabet.len() > 256 {
        return Err(Error::Malformed(
            "RNG alphabet must hold 1 to 256 characters".into(),
        ));
    }
    let width = alphabet.len();
    // Accept bytes below the largest multiple of `width` fitting in a byte.
    let accept = 256 - (256 % width);
    let mut one = [0u8; 1];
    for slot in dest.iter_mut() {
        loop {
            rng.fill_bytes(&mut one)?;
            if (one[0] as usize) < accept {
                *slot = alphabet[(one[0] as usize) % width];
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic byte source for unit tests: a xorshift64* stream.
    /// Test-only; production randomness always comes from [`SystemRng`].
    struct Deterministic(u64);

    impl FillRandom for Deterministic {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            for chunk in dest.chunks_mut(8) {
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                let v = self.0.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    #[test]
    fn uniform_below_covers_full_range_without_bias_shape() {
        let mut rng = Deterministic(0x12345678);
        // Bound 1 always yields 0; small bounds hit every value quickly.
        assert_eq!(uniform_below(&mut rng, 1).unwrap(), 0);
        let mut seen = [false; 6];
        for _ in 0..600 {
            seen[uniform_below(&mut rng, 6).unwrap() as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "every value 0..6 must appear");
        assert!(uniform_below(&mut rng, 0).is_err());
    }

    #[test]
    fn fill_alphabet_uses_only_alphabet_bytes() {
        let mut rng = Deterministic(0xdeadbeef);
        let mut out = [0u8; 64];
        fill_alphabet(&mut rng, &mut out, b"ab").unwrap();
        assert!(out.iter().all(|&b| b == b'a' || b == b'b'));
        assert!(out.contains(&b'a') && out.contains(&b'b'));
        assert!(fill_alphabet(&mut rng, &mut out, b"").is_err());
    }
}
