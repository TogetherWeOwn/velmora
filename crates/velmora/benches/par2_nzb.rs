//! par2 verification and NZB parsing benches. Report as ms/MB for the bench
//! gate: the `review_bench_guard` test fails on a >20% regression past its
//! pinned baseline.
//!
//! Native runs: `cargo bench -p nntune-core --bench par2_nzb`.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use nntune_core::nzb::Parser;
use nntune_core::par2::RecoverySet;
use std::hint::black_box;

const BLOCK_SIZE: u64 = 32 << 10;
const FILE_LEN: usize = 1 << 20;
const FILENAME: &str = "bench.bin";

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

fn packet(set_id: &[u8; 16], kind: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut aligned = body.to_vec();
    while aligned.len() % 4 != 0 {
        aligned.push(0);
    }
    let mut p = Vec::new();
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

fn ptype(suffix: &[u8]) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(b"PAR 2.0\0");
    t[8..8 + suffix.len().min(8)].copy_from_slice(&suffix[..suffix.len().min(8)]);
    t
}

fn recovery_set_bytes(data: &[u8]) -> Vec<u8> {
    let whole_md5 = md5::compute(data).0;
    let first16k = md5::compute(&data[..data.len().min(16 * 1024)]).0;
    let mut seed = Vec::new();
    seed.extend_from_slice(&first16k);
    seed.extend_from_slice(&(data.len() as u64).to_le_bytes());
    seed.extend_from_slice(FILENAME.as_bytes());
    let file_id = md5::compute(&seed).0;

    let mut main_body = Vec::new();
    main_body.extend_from_slice(&BLOCK_SIZE.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes());
    main_body.extend_from_slice(&file_id);
    let set_id = md5::compute(&main_body).0;

    let mut fd_body = Vec::new();
    fd_body.extend_from_slice(&file_id);
    fd_body.extend_from_slice(&whole_md5);
    fd_body.extend_from_slice(&first16k);
    fd_body.extend_from_slice(&(data.len() as u64).to_le_bytes());
    fd_body.extend_from_slice(FILENAME.as_bytes());
    while fd_body.len() % 4 != 0 {
        fd_body.push(0);
    }

    let mut ifsc_body = Vec::new();
    ifsc_body.extend_from_slice(&file_id);
    for block in data.chunks(BLOCK_SIZE as usize) {
        let mut h = crc32fast::Hasher::new();
        h.update(block);
        if block.len() < BLOCK_SIZE as usize {
            h.update(&vec![0u8; BLOCK_SIZE as usize - block.len()]);
        }
        ifsc_body.extend_from_slice(&[0u8; 16]);
        ifsc_body.extend_from_slice(&h.finalize().to_le_bytes());
    }

    [
        packet(&set_id, &ptype(b"FileDesc"), &fd_body),
        packet(&set_id, &ptype(b"IFSC\0\0\0\0"), &ifsc_body),
        packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body),
    ]
    .concat()
}

fn bench_verify(c: &mut Criterion) {
    let data = pseudorandom(FILE_LEN);
    let set = RecoverySet::parse(&recovery_set_bytes(&data)).unwrap();
    let mut group = c.benchmark_group("par2-verify-1MiB");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("verify", |b| {
        b.iter(|| {
            set.verify(black_box(FILENAME), black_box(&data)).unwrap();
            black_box(())
        })
    });
    group.finish();
}

fn bench_precheck(c: &mut Criterion) {
    let data = pseudorandom(FILE_LEN);
    let set = RecoverySet::parse(&recovery_set_bytes(&data)).unwrap();
    // Uneven "segments" as fetch_release would record them.
    let cuts = [0usize, 300_000, 700_000, FILE_LEN];
    let segments: Vec<(u32, u64)> = cuts
        .windows(2)
        .map(|w| (crc32fast::hash(&data[w[0]..w[1]]), (w[1] - w[0]) as u64))
        .collect();
    let mut group = c.benchmark_group("par2-precheck-1MiB");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("precheck", |b| {
        b.iter(|| {
            assert!(set
                .precheck(black_box(FILENAME), black_box(&segments))
                .unwrap());
        })
    });
    group.finish();
}

fn bench_nzb_parse(c: &mut Criterion) {
    // Small-document, large-declared stress shape: 64 files x 16 segments x
    // 1 MiB declared, so the bench measures parser throughput per document
    // byte while accounting gigabytes of declared payload.
    let mut xml = String::from("<nzb>");
    for f in 0..64 {
        xml.push_str("<file poster=\"p\" date=\"1700000000\" subject=\"s\"><segments>");
        for s in 0..16 {
            let number = s + 1;
            xml.push_str(&format!(
                "<segment bytes=\"1048576\" number=\"{number}\">msg-{f}-{s}@bench.example.com</segment>"
            ));
        }
        xml.push_str("</segments></file>");
    }
    xml.push_str("</nzb>");
    let xml = xml.into_bytes();
    let parser = Parser::with_default_limits().unwrap();
    let mut group = c.benchmark_group("nzb-parse-stress");
    group.throughput(Throughput::Bytes(xml.len() as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            let doc = parser.parse(black_box(xml.as_slice())).unwrap();
            black_box(doc.encoded_bytes)
        })
    });
    group.finish();
}

criterion_group!(benches, bench_verify, bench_precheck, bench_nzb_parse);
criterion_main!(benches);
