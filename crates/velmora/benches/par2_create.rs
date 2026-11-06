//! PAR2 creation benches at track-scale FLAC sizes. Report as ms/MB for the
//! canary card; these numbers feed the card, not the `review_bench_guard`
//! gate (that gate pins the verify/precheck benches only).
//!
//! Native runs: `cargo bench -p velmora --bench par2_create`.
//!
//! Geometry mirrors the posting pipeline: the slice is the design §4 example
//! (11 cipher blocks = 721,072 article bytes, rounded down to 721,024), and
//! bytes stream in article-sized pushes so slice assembly crosses chunk
//! boundaries exactly as it will in production.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;
use std::time::Duration;
use velmora::par2::creator::{create_single_file, Par2Creator};

// Design §4 example: 11 cipher blocks of article payload, aligned to 128.
const ARTICLE_PUSH: usize = 721_072;
const SLICE: u64 = 721_024;
const FILENAME: &[u8] = b"par2-create-bench.bin";

/// Deterministic PRNG (xorshift64*) so benches are stable across runs.
fn pseudorandom(len: usize) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
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

fn bench_create_group(c: &mut Criterion, label: &str, len: usize) {
    let data = pseudorandom(len);
    // Sanity: the streaming path and the one-shot helper agree before timing.
    let mut streamed = Par2Creator::new(FILENAME, data.len() as u64, SLICE).unwrap();
    for chunk in data.chunks(ARTICLE_PUSH) {
        streamed.push(chunk).unwrap();
    }
    let expected = streamed.finish().unwrap().bytes();
    assert_eq!(
        create_single_file(FILENAME, &data, SLICE).unwrap().bytes(),
        expected
    );

    let mut group = c.benchmark_group(label);
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    group.bench_function("stream-article-pushes", |b| {
        b.iter(|| {
            let mut creator =
                Par2Creator::new(black_box(FILENAME), data.len() as u64, black_box(SLICE)).unwrap();
            for chunk in black_box(&data).chunks(ARTICLE_PUSH) {
                creator.push(chunk).unwrap();
            }
            black_box(creator.finish().unwrap());
        })
    });
    group.finish();
}

fn bench_create_8mib(c: &mut Criterion) {
    bench_create_group(c, "par2-create-8MiB", 8 << 20);
}

fn bench_create_32mib(c: &mut Criterion) {
    bench_create_group(c, "par2-create-32MiB", 32 << 20);
}

criterion_group!(benches, bench_create_8mib, bench_create_32mib);
criterion_main!(benches);
