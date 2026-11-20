//! Repair-parity codec (`velmora::rs`): fixed vectors, every loss pattern at
//! the configured geometries, refusals, and randomized round trips.
//!
//! The fixed vectors come from an independent model
//! (`testdata/rs-parity/vectors.py`, standard-library Python, no code shared
//! with the engine). They pin the bytes: a change to the field, the
//! generator matrix, the word order or the padding rule fails here.

use sha2::{Digest, Sha256};
use velmora::article::{ARTICLE_PAYLOAD_BYTES, ARTICLE_ZERO_PAYLOAD_BYTES};
use velmora::media::ciphertext_size;
use velmora::rs::{
    encode, reconstruct, shard_len, DataShard, ParityShard, RsError, MAX_PARITY_SHARDS,
};

const MIB: u64 = 1024 * 1024;

// ---- helpers ----------------------------------------------------------

struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// splitmix64 from `seed`, each output as 8 little-endian bytes, cut to
/// `len` (the same stream as `vectors.py`).
fn stream(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = SplitMix(seed);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Article payload lengths of an extent with `plain` plaintext bytes: the
/// engine's fixed cuts (article 0 carries the header, the last article the
/// remainder).
fn article_lens(plain: u64) -> Vec<usize> {
    let cipher = ciphertext_size(plain).expect("fits");
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// Every subset of `0..n` with exactly `size` members, in order.
fn subsets(n: usize, size: usize) -> Vec<Vec<usize>> {
    fn walk(
        start: usize,
        n: usize,
        size: usize,
        current: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if current.len() == size {
            out.push(current.clone());
            return;
        }
        for i in start..n {
            current.push(i);
            walk(i + 1, n, size, current, out);
            current.pop();
        }
    }
    let mut out = Vec::new();
    walk(0, n, size, &mut Vec::new(), &mut out);
    out
}

/// One stripe: data shards, the parity rows and their shards.
struct Stripe {
    data: Vec<Vec<u8>>,
    rows: Vec<u16>,
    parity: Vec<Vec<u8>>,
}

impl Stripe {
    fn new(data: Vec<Vec<u8>>, rows: Vec<u16>) -> Self {
        let parity = encode(&refs(&data), &rows).expect("encode");
        Self { data, rows, parity }
    }

    fn k(&self) -> usize {
        self.data.len()
    }

    /// The reconstruct call for a loss pattern over the `k + m` shards
    /// (indexes `k..` are parity shards): lost data is marked lost, lost
    /// parity is withheld.
    fn attempt(&self, lost: &[usize]) -> Result<Vec<Vec<u8>>, RsError> {
        let shards: Vec<DataShard<'_>> = self
            .data
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
        let parity: Vec<ParityShard<'_>> = self
            .rows
            .iter()
            .zip(&self.parity)
            .enumerate()
            .filter(|(j, _)| !lost.contains(&(self.k() + j)))
            .map(|(_, (&row, bytes))| ParityShard { row, bytes })
            .collect();
        reconstruct(&shards, &parity)
    }

    /// Loses `lost`, rebuilds the data, re-encodes the lost parity rows from
    /// the rebuilt stripe, and requires every byte to be the original.
    fn assert_recovers(&self, lost: &[usize]) {
        let rebuilt = self
            .attempt(lost)
            .unwrap_or_else(|e| panic!("pattern {lost:?}: {e}"));
        let lost_data: Vec<usize> = lost.iter().copied().filter(|&i| i < self.k()).collect();
        assert_eq!(rebuilt.len(), lost_data.len(), "pattern {lost:?}");
        let mut restored = self.data.clone();
        for (index, bytes) in lost_data.iter().zip(rebuilt) {
            assert!(
                bytes == self.data[*index],
                "pattern {lost:?}: data shard {index} differs"
            );
            restored[*index] = bytes;
        }
        let lost_rows: Vec<u16> = lost
            .iter()
            .filter(|&&i| i >= self.k())
            .map(|&i| self.rows[i - self.k()])
            .collect();
        let again = encode(&refs(&restored), &lost_rows).expect("re-encode");
        for (row, bytes) in lost_rows.iter().zip(again) {
            let at = self.rows.iter().position(|r| r == row).unwrap();
            assert!(
                bytes == self.parity[at],
                "pattern {lost:?}: parity row {row} differs"
            );
        }
    }
}

/// The configured geometries: (plain bytes of the extent, parity count).
const GEOMETRIES: [(u64, usize); 4] = [(5, 1), (8 * MIB, 2), (16 * MIB, 3), (16 * MIB, 4)];

/// A stripe with the geometry's shard count but small shards, keeping the
/// shape of the real cuts: a longer first shard, equal middle shards, and a
/// short, odd last shard.
fn small_stripe(seed: u64, k: usize, m: usize) -> Stripe {
    let lens: Vec<usize> = (0..k)
        .map(|i| {
            if k == 1 {
                69
            } else if i == 0 {
                1_456
            } else if i == k - 1 {
                897
            } else {
                1_408
            }
        })
        .collect();
    Stripe::new(stripe(seed, &lens), (0..m as u16).collect())
}

// ---- fixed vectors ----------------------------------------------------

#[test]
fn tiny_vectors_match_the_independent_model() {
    let cases: [(&[&str], &[u16], &[&str]); 3] = [
        (&["010203"], &[0], &["9f6de75c"]),
        (
            &["68656c6c6f", "ffee00dd", "8001"],
            &[0, 1],
            &["a60142f0d513", "ca116dd6ed83"],
        ),
        (
            &["0001", "0100ffff"],
            &[0x7FFF, 5],
            &["f712ae06", "2215043c"],
        ),
    ];
    for (data, rows, want) in cases {
        let data: Vec<Vec<u8>> = data.iter().map(|d| unhex(d)).collect();
        let parity = encode(&refs(&data), rows).unwrap();
        let got: Vec<String> = parity.iter().map(|p| hex(p)).collect();
        assert_eq!(got, want, "data {data:?} rows {rows:?}");

        // And back: each stored parity shard alone rebuilds each data shard.
        for (row, bytes) in rows.iter().zip(want) {
            let bytes = unhex(bytes);
            for lost in 0..data.len() {
                let shards: Vec<DataShard<'_>> = data
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        if i == lost {
                            DataShard::Lost { len: d.len() }
                        } else {
                            DataShard::Present(d)
                        }
                    })
                    .collect();
                let rebuilt = reconstruct(
                    &shards,
                    &[ParityShard {
                        row: *row,
                        bytes: &bytes,
                    }],
                )
                .unwrap();
                assert_eq!(rebuilt, vec![data[lost].clone()]);
            }
        }
    }
}

/// (stream seed, plain bytes, parity row, SHA-256 of the parity shard).
const PARITY_DIGESTS: [(u64, u64, u16, &str); 14] = [
    // one article of 69 B, (1,1), shard 70 B
    (
        1,
        5,
        0,
        "8b3044f69b0aad50bdc70be12538d25491dff27ff13f6f0086de0a057b9e5c99",
    ),
    // two articles, the last 17 B, (2,2)
    (
        2,
        720_897,
        0,
        "e60a007cf0716c7f90aa30dec53b0bcb26c7302d00b302dc800f6ea691481c95",
    ),
    (
        2,
        720_897,
        1,
        "37f112e83ccde6c91fa8d9c66261904775fc3f09c80476d46be06b7b2d401e2c",
    ),
    // 8 articles, the last 196,689 B, (8,2)
    (
        3,
        5_242_897,
        0,
        "4c11ca6446fc7d6250bb880c7c58f5cafca22f3dda1015f42314b156307cf1ab",
    ),
    (
        3,
        5_242_897,
        1,
        "8341fb5d0fd9ad707842b0ff3c37e3dfd75687f58e91c2317f1f4dca41c40535",
    ),
    // 8 MiB: 12 articles, the last 458,864 B, (12,2)
    (
        4,
        8_388_608,
        0,
        "1b9263524ee50fe0b726cdbe77286c067535555026f1c216c90876c05a8fe942",
    ),
    (
        4,
        8_388_608,
        1,
        "9f74612171a71f95210cb87a24627beb6236ac3ab0456b3c1587892fb30003ec",
    ),
    // 16 MiB: 24 articles, the last 196,656 B: rows 0 to 2 are (24,3),
    // rows 0 to 3 are (24,4)
    (
        5,
        16_777_216,
        0,
        "ad04e2f6758f6be6c35624f61af7a8015c0077c7c7842a551393ad2102365850",
    ),
    (
        5,
        16_777_216,
        1,
        "0e44d6fb7f1178bfa302a71dcebf57e7f306b07f00056828b8533353766f0658",
    ),
    (
        5,
        16_777_216,
        2,
        "7ec919640d7a0388aace64a1df7c9cabd135d90833a38e38cb541ccaee2fef5b",
    ),
    (
        5,
        16_777_216,
        3,
        "1900987439b7c20ce00d4db5fa31740b234ebaa1ff440b9798f3dcfc27315abd",
    ),
    // 8 MiB again, rows a later top-up would use
    (
        4,
        8_388_608,
        2,
        "403fcd6a6402a0b7feb4917b4b3511baf9013c42f734387959a116f030ca9c8e",
    ),
    (
        4,
        8_388_608,
        0x7FFF,
        "de32c5972fc623f560a4b445c72a9c0fba406f38305614b9789714dedfc7f027",
    ),
    // 8 MiB, row 1 asked for alone: the same shard as above
    (
        4,
        8_388_608,
        1,
        "9f74612171a71f95210cb87a24627beb6236ac3ab0456b3c1587892fb30003ec",
    ),
];

#[test]
fn full_size_parity_matches_the_independent_model() {
    for (seed, plain, row, want) in PARITY_DIGESTS {
        let lens = article_lens(plain);
        let data = stripe(seed, &lens);
        let parity = encode(&refs(&data), &[row]).unwrap();
        assert_eq!(parity[0].len(), shard_len(lens.iter().copied()).unwrap());
        assert_eq!(
            hex(&Sha256::digest(&parity[0])),
            want,
            "seed {seed} plain {plain} row {row}"
        );
    }
}

#[test]
fn the_geometries_are_the_ones_the_vectors_name() {
    assert_eq!(article_lens(5), vec![69]);
    let eight = article_lens(8 * MIB);
    assert_eq!(eight.len(), 12);
    assert_eq!((eight[0], eight[1], eight[11]), (721_120, 721_072, 458_864));
    let sixteen = article_lens(16 * MIB);
    assert_eq!(sixteen.len(), 24);
    assert_eq!(sixteen[23], 196_656);
    assert_eq!(shard_len(sixteen.iter().copied()), Some(721_120));
    assert_eq!(shard_len(article_lens(5)), Some(70));
}

// ---- every loss pattern ----------------------------------------------

/// Every pattern of up to `m` lost shards among the `k + m`, at each
/// configured shard count, with the shape of the real cuts (unequal
/// shards, short odd last shard). 3 + 106 + 3,304 + 24,158 patterns at
/// (1,1), (12,2), (24,3) and (24,4).
#[test]
fn every_loss_pattern_up_to_the_parity_count_recovers() {
    let mut patterns = 0usize;
    for (at, (plain, m)) in GEOMETRIES.into_iter().enumerate() {
        let k = article_lens(plain).len();
        let s = small_stripe(100 + at as u64, k, m);
        for size in 0..=m {
            for lost in subsets(k + m, size) {
                s.assert_recovers(&lost);
                patterns += 1;
            }
        }
    }
    assert_eq!(patterns, 3 + 106 + 3_304 + 24_158);
}

/// One loss more than the parity count is refused for every pattern: an
/// error, never bytes.
#[test]
fn every_pattern_one_past_the_parity_count_is_refused() {
    let mut patterns = 0usize;
    for (at, (plain, m)) in GEOMETRIES.into_iter().enumerate() {
        let k = article_lens(plain).len();
        let s = small_stripe(200 + at as u64, k, m);
        for lost in subsets(k + m, m + 1) {
            let lost_data = lost.iter().filter(|&&i| i < k).count();
            let live_parity = m - (lost.len() - lost_data);
            assert_eq!(
                s.attempt(&lost),
                Err(RsError::TooManyLosses {
                    lost: lost_data,
                    parity: live_parity
                }),
                "pattern {lost:?}"
            );
            patterns += 1;
        }
    }
    // C(2,2) + C(14,3) + C(27,4) + C(28,5)
    assert_eq!(patterns, 1 + 364 + 17_550 + 98_280);
}

/// The real article sizes. (1,1) and (12,2): every pattern (3 and 106).
/// (24,3) and (24,4): every single loss, and every pattern that loses as
/// many shards as there is parity among the first article, its neighbour,
/// the last full article, the short last article and the parity shards
/// (the patterns differ from the small-shard run above only in shard
/// length, which these cover).
#[test]
fn full_size_extents_recover() {
    for (at, (plain, m)) in GEOMETRIES.into_iter().enumerate() {
        let lens = article_lens(plain);
        let k = lens.len();
        let s = Stripe::new(stripe(300 + at as u64, &lens), (0..m as u16).collect());
        if k <= 12 {
            for size in 0..=m {
                for lost in subsets(k + m, size) {
                    s.assert_recovers(&lost);
                }
            }
            continue;
        }
        for i in 0..k + m {
            s.assert_recovers(&[i]);
        }
        let mut corners = vec![0, 1, k - 2, k - 1];
        corners.extend(k..k + m);
        for pick in subsets(corners.len(), m) {
            let lost: Vec<usize> = pick.iter().map(|&p| corners[p]).collect();
            s.assert_recovers(&lost);
        }
    }
}

// ---- refusals and limits ---------------------------------------------

fn present(data: &[Vec<u8>]) -> Vec<DataShard<'_>> {
    data.iter().map(|d| DataShard::Present(d)).collect()
}

#[test]
fn nothing_lost_rebuilds_nothing() {
    let s = small_stripe(1, 12, 2);
    assert_eq!(s.attempt(&[]), Ok(Vec::new()));
    // No parity is needed for that.
    assert_eq!(reconstruct(&present(&s.data), &[]), Ok(Vec::new()));
    // The limit on parity shards per call holds all the same.
    let too_many = vec![
        ParityShard {
            row: 0,
            bytes: &s.parity[0]
        };
        MAX_PARITY_SHARDS + 1
    ];
    assert_eq!(
        reconstruct(&present(&s.data), &too_many),
        Err(RsError::TooManyParityShards {
            count: MAX_PARITY_SHARDS + 1
        })
    );
}

#[test]
fn malformed_stripes_are_refused() {
    let s = small_stripe(2, 12, 2);
    let p = |j: usize| ParityShard {
        row: s.rows[j],
        bytes: &s.parity[j],
    };
    let mut shards = present(&s.data);
    shards[3] = DataShard::Lost {
        len: s.data[3].len(),
    };

    assert_eq!(reconstruct(&[], &[p(0)]), Err(RsError::NoDataShards));
    assert_eq!(
        reconstruct(&shards, &[]),
        Err(RsError::TooManyLosses { lost: 1, parity: 0 })
    );
    // A parity shard cut short, alone or next to a good one.
    let short = &s.parity[1][..s.parity[1].len() - 2];
    assert_eq!(
        reconstruct(
            &shards,
            &[
                p(0),
                ParityShard {
                    row: 1,
                    bytes: short
                }
            ]
        ),
        Err(RsError::ParityLength {
            row: 1,
            len: short.len()
        })
    );
    assert_eq!(
        reconstruct(
            &shards,
            &[ParityShard {
                row: 1,
                bytes: short
            }]
        ),
        Err(RsError::ShardLengthMismatch {
            expected: 1_456,
            parity: 1_454
        })
    );
    let odd = &s.parity[0][..s.parity[0].len() - 1];
    assert_eq!(
        reconstruct(&shards, &[ParityShard { row: 0, bytes: odd }]),
        Err(RsError::ParityLength {
            row: 0,
            len: odd.len()
        })
    );
    assert_eq!(
        reconstruct(&shards, &[ParityShard { row: 0, bytes: &[] }]),
        Err(RsError::ParityLength { row: 0, len: 0 })
    );
    // Rows: out of range, or the same row twice.
    assert_eq!(
        reconstruct(
            &shards,
            &[ParityShard {
                row: 0x8000,
                bytes: &s.parity[0]
            }]
        ),
        Err(RsError::RowOutOfRange { row: 0x8000 })
    );
    assert_eq!(
        reconstruct(&shards, &[p(0), p(0)]),
        Err(RsError::DuplicateRow { row: 0 })
    );
    // Lengths: an empty shard, a lost shard said to be longer than the
    // stripe, a present shard longer than the stripe.
    let mut empty_lost = present(&s.data);
    empty_lost[3] = DataShard::Lost { len: 0 };
    assert_eq!(
        reconstruct(&empty_lost, &[p(0)]),
        Err(RsError::EmptyDataShard { index: 3 })
    );
    let mut empty_present = shards.clone();
    empty_present[5] = DataShard::Present(&[]);
    assert_eq!(
        reconstruct(&empty_present, &[p(0)]),
        Err(RsError::EmptyDataShard { index: 5 })
    );
    let mut too_long = present(&s.data);
    too_long[3] = DataShard::Lost { len: 1_457 };
    assert_eq!(
        reconstruct(&too_long, &[p(0)]),
        Err(RsError::ShardLengthMismatch {
            expected: 1_458,
            parity: 1_456
        })
    );
    let long = vec![7u8; 2_000];
    let mut long_present = shards.clone();
    long_present[5] = DataShard::Present(&long);
    assert_eq!(
        reconstruct(&long_present, &[p(0)]),
        Err(RsError::ShardLengthMismatch {
            expected: 2_000,
            parity: 1_456
        })
    );
    // A stated length that cannot be rounded up to even.
    let mut huge = present(&s.data);
    huge[3] = DataShard::Lost { len: usize::MAX };
    assert_eq!(
        reconstruct(&huge, &[p(0)]),
        Err(RsError::ShardLengthMismatch {
            expected: usize::MAX,
            parity: 1_456
        })
    );
    // More parity shards than one call takes: refused before any work,
    // also when as many shards are lost.
    let rows: Vec<u16> = (0..65).collect();
    let too_many: Vec<ParityShard<'_>> = rows
        .iter()
        .map(|&row| ParityShard {
            row,
            bytes: &s.parity[0],
        })
        .collect();
    assert_eq!(
        reconstruct(&shards, &too_many),
        Err(RsError::TooManyParityShards { count: 65 })
    );
    // The longest shard lost and said to be shorter: the stripe would be
    // shorter than its parity.
    let mut first_short = present(&s.data);
    first_short[0] = DataShard::Lost { len: 1_000 };
    assert_eq!(
        reconstruct(&first_short, &[p(0)]),
        Err(RsError::ShardLengthMismatch {
            expected: 1_408,
            parity: 1_456
        })
    );
}

/// A lost shard said to be shorter than it is would be cut: refused,
/// because the bytes past the stated length are not zero.
#[test]
fn a_rebuilt_shard_with_non_zero_padding_is_refused() {
    let s = small_stripe(3, 12, 2);
    let p0 = ParityShard {
        row: 0,
        bytes: &s.parity[0],
    };
    let mut shards = present(&s.data);
    shards[4] = DataShard::Lost {
        len: s.data[4].len() - 1,
    };
    assert_eq!(
        reconstruct(&shards, &[p0]),
        Err(RsError::PaddingNotZero { index: 4 })
    );

    // Damage in a present shard, at a position past the end of the short
    // lost shard: the rebuilt padding is not zero.
    let mut damaged = s.data.clone();
    damaged[2][1_000] ^= 0x40;
    let mut shards = present(&damaged);
    shards[11] = DataShard::Lost { len: 897 };
    assert_eq!(
        reconstruct(&shards, &[p0]),
        Err(RsError::PaddingNotZero { index: 11 })
    );
    // With two lost, the first inconsistent one is named and nothing is
    // returned.
    shards[4] = DataShard::Lost { len: 1_408 };
    let p1 = ParityShard {
        row: 1,
        bytes: &s.parity[1],
    };
    assert_eq!(
        reconstruct(&shards, &[p0, p1]),
        Err(RsError::PaddingNotZero { index: 11 })
    );
}

/// The stated limit of an erasure code: with as many parity shards as
/// losses, a wrong *present* shard (or a wrong parity shard, or a wrong
/// row number) gives a wrong rebuilt shard, not an error. It never gives
/// the right one, so the caller's digest check on the rebuilt shard
/// always catches it.
#[test]
fn wrong_inputs_never_rebuild_the_original() {
    let s = small_stripe(4, 12, 2);
    let lost = 5usize;
    let original = &s.data[lost];
    let mut rng = SplitMix(99);

    for _ in 0..300 {
        // One flipped bit in one present data shard.
        let mut damaged = s.data.clone();
        let mut victim = rng.below(s.k() - 1);
        if victim >= lost {
            victim += 1;
        }
        let at = rng.below(damaged[victim].len());
        damaged[victim][at] ^= 1 << rng.below(8);
        let mut shards = present(&damaged);
        shards[lost] = DataShard::Lost {
            len: original.len(),
        };
        let out = reconstruct(
            &shards,
            &[ParityShard {
                row: 0,
                bytes: &s.parity[0],
            }],
        );
        assert!(!matches!(&out, Ok(r) if &r[0] == original));

        // One flipped bit in the parity shard.
        let mut parity = s.parity[1].clone();
        let at = rng.below(parity.len());
        parity[at] ^= 1 << rng.below(8);
        let mut shards = present(&s.data);
        shards[lost] = DataShard::Lost {
            len: original.len(),
        };
        let out = reconstruct(
            &shards,
            &[ParityShard {
                row: 1,
                bytes: &parity,
            }],
        );
        assert!(!matches!(&out, Ok(r) if &r[0] == original));
    }

    // Parity row 1 handed over as row 0.
    let mut shards = present(&s.data);
    shards[lost] = DataShard::Lost {
        len: original.len(),
    };
    let out = reconstruct(
        &shards,
        &[ParityShard {
            row: 0,
            bytes: &s.parity[1],
        }],
    );
    assert!(!matches!(&out, Ok(r) if &r[0] == original));
}

// ---- randomized round trips -------------------------------------------

/// Random stripes: 1 to 40 data shards of 1 to 300 bytes, 1 to 6 parity
/// rows drawn from the whole row range, any number of losses up to the
/// parity count, parity shards handed over in a random order with spares.
#[test]
fn random_stripes_round_trip() {
    let mut rng = SplitMix(0x5EED);
    for round in 0..3_000u64 {
        let k = 1 + rng.below(40);
        let m = 1 + rng.below(6);
        let lens: Vec<usize> = (0..k).map(|_| 1 + rng.below(300)).collect();
        let data = stripe(round * 1_000, &lens);
        let mut rows: Vec<u16> = Vec::new();
        while rows.len() < m {
            let row = if rng.below(2) == 0 {
                rng.below(8) as u16
            } else {
                rng.below(0x8000) as u16
            };
            if !rows.contains(&row) {
                rows.push(row);
            }
        }
        let parity = encode(&refs(&data), &rows).unwrap();
        let len = shard_len(lens.iter().copied()).unwrap();
        assert!(parity.iter().all(|p| p.len() == len));
        // Encoding again gives the same bytes.
        assert_eq!(encode(&refs(&data), &rows).unwrap(), parity);

        // Lose up to min(k, m) data shards.
        let t = rng.below(k.min(m) + 1);
        let mut lost: Vec<usize> = Vec::new();
        while lost.len() < t {
            let i = rng.below(k);
            if !lost.contains(&i) {
                lost.push(i);
            }
        }
        lost.sort_unstable();
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

        // Parity in a random order; keep a random count from t to m.
        let mut order: Vec<usize> = (0..m).collect();
        for i in (1..m).rev() {
            order.swap(i, rng.below(i + 1));
        }
        let keep = t + rng.below(m - t + 1);
        let supplied: Vec<ParityShard<'_>> = order[..keep]
            .iter()
            .map(|&j| ParityShard {
                row: rows[j],
                bytes: &parity[j],
            })
            .collect();

        let rebuilt = reconstruct(&shards, &supplied)
            .unwrap_or_else(|e| panic!("round {round}: k {k} m {m} lost {lost:?}: {e}"));
        let want: Vec<Vec<u8>> = lost.iter().map(|&i| data[i].clone()).collect();
        assert_eq!(rebuilt, want, "round {round}: k {k} m {m} lost {lost:?}");

        // One parity shard fewer than losses is refused.
        if t > 0 {
            assert_eq!(
                reconstruct(&shards, &supplied[..t - 1]),
                Err(RsError::TooManyLosses {
                    lost: t,
                    parity: t - 1
                })
            );
        }
    }
}

/// A row added later (top-up) works with rows from the first encode, and
/// the stripe then survives one more loss.
#[test]
fn a_row_added_later_joins_the_stripe() {
    let lens = article_lens(8 * MIB);
    let data = stripe(77, &lens);
    let first = encode(&refs(&data), &[0, 1]).unwrap();
    let extra = encode(&refs(&data), &[2]).unwrap();

    let mut shards = present(&data);
    for i in [0usize, 6, 11] {
        shards[i] = DataShard::Lost { len: lens[i] };
    }
    let rebuilt = reconstruct(
        &shards,
        &[
            ParityShard {
                row: 2,
                bytes: &extra[0],
            },
            ParityShard {
                row: 0,
                bytes: &first[0],
            },
            ParityShard {
                row: 1,
                bytes: &first[1],
            },
        ],
    )
    .unwrap();
    assert!(rebuilt[0] == data[0] && rebuilt[1] == data[6] && rebuilt[2] == data[11]);
}

#[test]
fn errors_render_without_shard_bytes() {
    let text = RsError::TooManyLosses { lost: 3, parity: 2 }.to_string();
    assert_eq!(
        text,
        "parity: 3 data shards lost, 2 parity shards supplied: not recoverable"
    );
    let _: &dyn std::error::Error = &RsError::SingularMatrix;
}

/// The most parity shards one call takes: 64 rows over 70 data shards,
/// 64 of them lost.
#[test]
fn the_largest_call_round_trips() {
    let lens: Vec<usize> = (0..70).map(|i| 40 + i).collect();
    let data = stripe(9, &lens);
    let rows: Vec<u16> = (0..MAX_PARITY_SHARDS as u16).map(|j| j * 500).collect();
    let parity = encode(&refs(&data), &rows).unwrap();
    let shards: Vec<DataShard<'_>> = data
        .iter()
        .enumerate()
        .map(|(i, d)| {
            if i >= 6 {
                DataShard::Lost { len: d.len() }
            } else {
                DataShard::Present(d)
            }
        })
        .collect();
    let supplied: Vec<ParityShard<'_>> = rows
        .iter()
        .zip(&parity)
        .map(|(&row, bytes)| ParityShard { row, bytes })
        .collect();
    assert_eq!(reconstruct(&shards, &supplied).unwrap(), data[6..].to_vec());
}
