//! Bench guard: par2 verification must not regress more than 20%.
//!
//! Criterion benches live in `benches/par2_nzb.rs` (same style as
//! `benches/yenc.rs`); this test is the CI gate. Absolute wall-time guards
//! flake across machines, so the guard is machine-normalised: it times
//! [`RecoverySet::verify`] against a naive reference doing the same
//! unavoidable work (whole-file MD5 plus per-block CRC32 with zero-padded
//! last slice) in the same run, and fails when the verify/reference time
//! ratio regresses more than 20% past the pinned baseline below.
//!
//! Re-pinning: run `cargo test -p velmora bench_guard -- --nocapture`,
//! read the printed ratio on the reference machine, and set
//! `BASELINE_RATIO` to it. Only re-pin after an intentional algorithmic
//! change, never to make a red run green.

use std::time::{Duration, Instant};

use velmora::par2::RecoverySet;

const BLOCK_SIZE: u64 = 32 << 10;
const FILE_LEN: usize = 2 << 20;
const FILENAME: &str = "guard.bin";

/// Pinned verify/reference time ratio. `verify` does the same hashing work
/// as the reference, so parity is 1.0 (measured 0.95-1.07 across runs on the
/// reference machine). Re-pin per the instructions above.
const BASELINE_RATIO: f64 = 1.0;

/// Fails when the ratio regresses more than 20% past [`BASELINE_RATIO`].
const REGRESSION_FACTOR: f64 = 1.2;

const ROUNDS: usize = 11;

fn fixture_bytes() -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut out = vec![0u8; FILE_LEN];
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
    out
}

fn packet(set_id: &[u8; 16], kind: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut aligned = body.to_vec();
    while !aligned.len().is_multiple_of(4) {
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
    while !fd_body.len().is_multiple_of(4) {
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

/// The unavoidable floor: whole-file MD5 plus per-block CRC32 with the
/// zero-padded last slice, timed standalone.
fn reference_work(data: &[u8]) -> Duration {
    let started = Instant::now();
    let _ = md5::compute(data);
    for block in data.chunks(BLOCK_SIZE as usize) {
        let mut h = crc32fast::Hasher::new();
        h.update(block);
        if block.len() < BLOCK_SIZE as usize {
            h.update(&vec![0u8; BLOCK_SIZE as usize - block.len()]);
        }
        std::hint::black_box(h.finalize());
    }
    started.elapsed()
}

fn best_of_alternating(
    rounds: usize,
    mut verify: impl FnMut() -> Duration,
    mut reference: impl FnMut() -> Duration,
) -> (Duration, Duration) {
    let mut best_verify = Duration::MAX;
    let mut best_reference = Duration::MAX;
    for round in 0..rounds {
        if round % 2 == 0 {
            best_verify = best_verify.min(verify());
            best_reference = best_reference.min(reference());
        } else {
            best_reference = best_reference.min(reference());
            best_verify = best_verify.min(verify());
        }
    }
    (best_verify, best_reference)
}

#[test]
fn measurement_rounds_alternate_order_and_keep_independent_minima() {
    use std::cell::RefCell;

    let calls = RefCell::new(Vec::new());
    let mut verify_times = [9, 2, 5].into_iter();
    let mut reference_times = [3, 8, 1].into_iter();
    let measured = best_of_alternating(
        3,
        || {
            calls.borrow_mut().push("verify");
            Duration::from_nanos(verify_times.next().unwrap())
        },
        || {
            calls.borrow_mut().push("reference");
            Duration::from_nanos(reference_times.next().unwrap())
        },
    );
    assert_eq!(
        calls.into_inner(),
        [
            "verify",
            "reference",
            "reference",
            "verify",
            "verify",
            "reference"
        ]
    );
    assert_eq!(measured, (Duration::from_nanos(2), Duration::from_nanos(1)));
}

#[test]
fn par2_verify_has_no_regression_beyond_twenty_percent() {
    let data = fixture_bytes();
    let set = RecoverySet::parse(&recovery_set_bytes(&data)).expect("set parses");

    // Warm up allocators and the instruction cache before measuring.
    set.verify(FILENAME, &data).expect("healthy verifies");
    reference_work(&data);

    let (verify, reference) = best_of_alternating(
        ROUNDS,
        || {
            let started = Instant::now();
            set.verify(FILENAME, &data).expect("healthy verifies");
            started.elapsed()
        },
        || reference_work(&data),
    );
    let ratio = verify.as_secs_f64() / reference.as_secs_f64().max(f64::EPSILON);
    eprintln!("bench guard: verify={verify:?} reference={reference:?} ratio={ratio:.3}");

    assert!(
        ratio <= BASELINE_RATIO * REGRESSION_FACTOR,
        "par2 verify regressed more than 20%: ratio {ratio:.3} exceeds baseline {BASELINE_RATIO} x {REGRESSION_FACTOR}"
    );
}
