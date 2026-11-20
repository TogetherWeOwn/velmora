//! Self-check and CPU benchmark of the repair-parity codec
//! ([`velmora::rs`]).
//!
//! Built as a plain `wasm32-unknown-unknown` module and run under node
//! (`run.mjs`), once without and once with `target-feature=+simd128`. The
//! codec's multiply-accumulate kernel has a scalar and a simd128 back end;
//! [`selfcheck`] proves that the build at hand produces the bytes the
//! native build pins ([`FINGERPRINT`]), so the two back ends are checked
//! against each other and against the native scalar code on every change.
//!
//! The functions are exported by name in the wasm build only. They take and return plain integers; there is no
//! JavaScript glue.

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use velmora::article::{ARTICLE_PAYLOAD_BYTES, ARTICLE_ZERO_PAYLOAD_BYTES};
use velmora::media::ciphertext_size;
use velmora::par2::gf16;
use velmora::rs::{encode, reconstruct, DataShard, ParityShard};

/// SHA-256 over every byte [`fingerprint`] produces. Pinned by the native
/// test; every wasm build must reproduce it.
pub const FINGERPRINT: &str = "b848b32868cb22045e77a67eadbc50c396e4421a0592d789d69bb75e9cedf5b0";

/// The configured geometries: (plain bytes of the extent, parity count).
const GEOMETRIES: [(u64, usize); 4] = [(5, 1), (8 << 20, 2), (16 << 20, 3), (16 << 20, 4)];

struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn stream(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = SplitMix(seed);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Article payload lengths of an extent with `plain` plaintext bytes (the
/// engine's fixed cuts). Empty if the size does not fit.
fn article_lens(plain: u64) -> Vec<usize> {
    let Some(cipher) = ciphertext_size(plain) else {
        return Vec::new();
    };
    let mut lens = Vec::new();
    let mut start = 0u64;
    while start < cipher {
        let full = if start == 0 {
            ARTICLE_ZERO_PAYLOAD_BYTES
        } else {
            ARTICLE_PAYLOAD_BYTES
        };
        let len = full.min(cipher - start);
        lens.push(len as usize);
        start += len;
    }
    lens
}

fn stripe(seed: u64, lens: &[usize]) -> Vec<Vec<u8>> {
    lens.iter()
        .enumerate()
        .map(|(i, &len)| stream(seed + i as u64, len))
        .collect()
}

fn refs(data: &[Vec<u8>]) -> Vec<&[u8]> {
    data.iter().map(|d| d.as_slice()).collect()
}

/// Loses the data shards `lost`, rebuilds them from the parity shards not
/// listed in `lost_parity`, and returns them. `None` on any error or on a
/// rebuilt shard that differs from the original.
fn round_trip(
    data: &[Vec<u8>],
    parity: &[Vec<u8>],
    lost: &[usize],
    lost_parity: &[usize],
) -> Option<Vec<Vec<u8>>> {
    let shards: Vec<DataShard<'_>> = data
        .iter()
        .enumerate()
        .map(|(i, d)| {
            if lost.contains(&i) {
                DataShard::Lost { len: d.len() }
            } else {
                DataShard::Present(d)
            }
        })
        .collect();
    let live: Vec<ParityShard<'_>> = parity
        .iter()
        .enumerate()
        .filter(|(j, _)| !lost_parity.contains(j))
        .map(|(j, bytes)| ParityShard {
            row: j as u16,
            bytes,
        })
        .collect();
    let rebuilt = reconstruct(&shards, &live).ok()?;
    if rebuilt.len() != lost.len() {
        return None;
    }
    for (index, bytes) in lost.iter().zip(&rebuilt) {
        if bytes != &data[*index] {
            return None;
        }
    }
    Some(rebuilt)
}

/// Every subset of `0..n` with up to `max` members.
fn subsets_up_to(n: usize, max: usize) -> Vec<Vec<usize>> {
    let mut out = vec![Vec::new()];
    let mut at = 0;
    while at < out.len() {
        let current = out[at].clone();
        at += 1;
        if current.len() == max {
            continue;
        }
        let start = current.last().map_or(0, |&last| last + 1);
        for i in start..n {
            let mut next = current.clone();
            next.push(i);
            out.push(next);
        }
    }
    out
}

/// The kernel's dispatching `madd` against its scalar loop, on word counts
/// around the 8-word vector chunk and on a long buffer.
fn kernel_agrees() -> bool {
    let mut rng = SplitMix(0xC0FFEE);
    let mut lengths: Vec<usize> = (0..=40).collect();
    lengths.extend([255, 256, 257, 4_099, 360_560]);
    for words in lengths {
        let src: Vec<u16> = (0..words).map(|_| rng.next() as u16).collect();
        let start: Vec<u16> = (0..words).map(|_| rng.next() as u16).collect();
        for factor in [1u16, 2, 0x8000, 0xFFFF, rng.next() as u16 | 1] {
            let mut fast = start.clone();
            gf16::madd(&mut fast, &src, factor);
            let mut slow = start.clone();
            gf16::madd_scalar(&mut slow, &src, &gf16::nibble_tables(factor));
            if fast != slow {
                return false;
            }
            // And against the field multiplication itself.
            let direct = src
                .iter()
                .zip(&start)
                .zip(&fast)
                .take(64)
                .all(|((&s, &d), &f)| f == d ^ gf16::mul(s, factor));
            if !direct {
                return false;
            }
        }
    }
    true
}

/// Runs the codec over fixed stripes and hashes every byte it produces:
///
/// 1. for each configured shard count, a stripe of small shards shaped
///    like the real cuts: the parity shards, then the rebuilt shards of
///    every loss pattern up to the parity count;
/// 2. for each configured geometry at the real article sizes: the parity
///    shards, then the rebuilt shards for the first `t` and the last `t`
///    data shards lost, `t` from 1 to the parity count.
///
/// `None` if any step fails or any rebuilt shard differs from the original.
pub fn fingerprint() -> Option<String> {
    let mut hash = Sha256::new();
    for (at, (plain, m)) in GEOMETRIES.into_iter().enumerate() {
        let k = article_lens(plain).len();
        let rows: Vec<u16> = (0..m as u16).collect();

        let small: Vec<usize> = (0..k)
            .map(|i| match i {
                _ if k == 1 => 69,
                0 => 1_456,
                _ if i == k - 1 => 897,
                _ => 1_408,
            })
            .collect();
        let data = stripe(1_000 + at as u64, &small);
        let parity = encode(&refs(&data), &rows).ok()?;
        for p in &parity {
            hash.update(p);
        }
        for pattern in subsets_up_to(k + m, m) {
            let lost: Vec<usize> = pattern.iter().copied().filter(|&i| i < k).collect();
            let lost_parity: Vec<usize> = pattern
                .iter()
                .filter(|&&i| i >= k)
                .map(|&i| i - k)
                .collect();
            for shard in round_trip(&data, &parity, &lost, &lost_parity)? {
                hash.update(&shard);
            }
        }

        let lens = article_lens(plain);
        let data = stripe(2_000 + at as u64, &lens);
        let parity = encode(&refs(&data), &rows).ok()?;
        for p in &parity {
            hash.update(p);
        }
        for t in 1..=m.min(k) {
            let first: Vec<usize> = (0..t).collect();
            let last: Vec<usize> = (k - t..k).collect();
            for lost in [first, last] {
                for shard in round_trip(&data, &parity, &lost, &[])? {
                    hash.update(&shard);
                }
            }
        }
    }
    Some(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

struct Bench {
    data: Vec<Vec<u8>>,
    rows: Vec<u16>,
    parity: Vec<Vec<u8>>,
}

static BENCH: Mutex<Option<Bench>> = Mutex::new(None);

/// 1 if this build's kernel and codec produce the pinned bytes, else 0.
#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C" fn selfcheck() -> u32 {
    u32::from(kernel_agrees() && fingerprint().as_deref() == Some(FINGERPRINT))
}

/// 1 if this module was built with the simd128 kernel.
#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C" fn simd128() -> u32 {
    u32::from(cfg!(all(
        target_arch = "wasm32",
        target_feature = "simd128"
    )))
}

/// Prepares one extent of `plain_bytes` plaintext bytes with `parity`
/// parity shards. Returns the number of data shards (articles), 0 on
/// failure.
#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C" fn setup(plain_bytes: u32, parity: u32) -> u32 {
    let lens = article_lens(u64::from(plain_bytes));
    let data = stripe(42, &lens);
    let rows: Vec<u16> = (0..parity as u16).collect();
    let Ok(shards) = encode(&refs(&data), &rows) else {
        return 0;
    };
    let articles = data.len() as u32;
    let Ok(mut bench) = BENCH.lock() else {
        return 0;
    };
    *bench = Some(Bench {
        data,
        rows,
        parity: shards,
    });
    articles
}

/// Encodes every parity shard of the prepared extent. Returns the bytes
/// produced, 0 on failure.
#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C" fn bench_encode() -> u32 {
    let Ok(bench) = BENCH.lock() else {
        return 0;
    };
    let Some(b) = bench.as_ref() else {
        return 0;
    };
    match encode(&refs(&b.data), &b.rows) {
        Ok(parity) => parity.iter().map(|p| p.len() as u32).sum(),
        Err(_) => 0,
    }
}

/// Rebuilds the first `lost` data shards of the prepared extent from the
/// rest. Returns the bytes rebuilt, 0 on failure.
#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C" fn bench_decode(lost: u32) -> u32 {
    let Ok(bench) = BENCH.lock() else {
        return 0;
    };
    let Some(b) = bench.as_ref() else {
        return 0;
    };
    let lost = lost as usize;
    let shards: Vec<DataShard<'_>> = b
        .data
        .iter()
        .enumerate()
        .map(|(i, d)| {
            if i < lost {
                DataShard::Lost { len: d.len() }
            } else {
                DataShard::Present(d)
            }
        })
        .collect();
    let parity: Vec<ParityShard<'_>> = b
        .rows
        .iter()
        .zip(&b.parity)
        .map(|(&row, bytes)| ParityShard { row, bytes })
        .collect();
    match reconstruct(&shards, &parity) {
        Ok(rebuilt) => rebuilt.iter().map(|r| r.len() as u32).sum(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_pinned() {
        assert_eq!(fingerprint().as_deref(), Some(FINGERPRINT));
    }

    #[test]
    fn selfcheck_passes_natively() {
        assert_eq!(selfcheck(), 1);
        assert_eq!(simd128(), 0);
    }

    #[test]
    fn bench_entry_points_work() {
        assert_eq!(setup(8 << 20, 2), 12);
        assert_eq!(bench_encode(), 2 * 721_120);
        assert_eq!(bench_decode(1), 721_120);
        assert_eq!(bench_decode(2), 721_120 + 721_072);
        assert_eq!(bench_decode(3), 0);
    }
}
