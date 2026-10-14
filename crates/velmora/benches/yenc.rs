//! yEnc throughput benches. Report as ms/MB for the bench gate (baseline:
//! the TS/V8 implementation at 1.2 ms/MB on Workers).
//!
//! Native runs: `cargo bench -p nntune-core`.
//! Workers runs: deploy `workers/bench` (sibling card) which calls the same
//! `decode_to`/`encode_body` over 1 MiB and reports `Date.now()` deltas.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use nntune_core::yenc::{decode_to, encode_body, encode_segment, SegmentParams};
use std::hint::black_box;

/// Deterministic PRNG (xorshift64*) so benches are stable across runs.
fn pseudorandom(len: usize) -> Vec<u8> {
    let mut x = 0x1234_5678_9abc_def1u64;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn bench_decode_clean(c: &mut Criterion) {
    let raw = pseudorandom(1 << 20);
    // Scrub escapable outputs so the SIMD fast path stays fully engaged.
    let raw: Vec<u8> = raw
        .into_iter()
        .map(|b| {
            let v = b.wrapping_add(42);
            if v == 0 || v == b'\n' || v == b'\r' || v == b'=' {
                b.wrapping_add(1)
            } else {
                b
            }
        })
        .collect();
    let mut article = Vec::new();
    encode_segment(&mut article, &SegmentParams::single("bench.bin"), &raw).unwrap();
    let mut dst = vec![0u8; raw.len() + 64];
    let mut group = c.benchmark_group("yenc-decode-clean-1MiB");
    group.throughput(Throughput::Bytes(raw.len() as u64));
    group.bench_function("decode_to", |b| {
        b.iter(|| {
            let n = decode_to(black_box("bench"), black_box(&article), &mut dst).unwrap();
            black_box(n)
        })
    });
    group.finish();
}

fn bench_decode_escapes(c: &mut Criterion) {
    // Escape-heavy input: every byte forces an `=` escape.
    let raw = vec![0xd6u8; 1 << 20]; // 0xd6 + 42 = 0x00 -> escaped
    let mut article = Vec::new();
    encode_segment(&mut article, &SegmentParams::single("bench.bin"), &raw).unwrap();
    let mut dst = vec![0u8; raw.len() + 64];
    let mut group = c.benchmark_group("yenc-decode-escapes-1MiB");
    group.throughput(Throughput::Bytes(raw.len() as u64));
    group.bench_function("decode_to", |b| {
        b.iter(|| {
            let n = decode_to(black_box("bench"), black_box(&article), &mut dst).unwrap();
            black_box(n)
        })
    });
    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let raw = pseudorandom(1 << 20);
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 64 + 256);
    let mut group = c.benchmark_group("yenc-encode-1MiB");
    group.throughput(Throughput::Bytes(raw.len() as u64));
    group.bench_function("encode_body", |b| {
        b.iter(|| {
            out.clear();
            let crc = encode_body(&mut out, black_box(&raw)).unwrap();
            black_box(crc)
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_decode_clean,
    bench_decode_escapes,
    bench_encode
);
criterion_main!(benches);
