//! PAR2 creator tests: packet layout, redundancy math, streaming equivalence,
//! GF(2^16) kernel cross-checks, and create→damage→repair round-trips.
//!
//! Fixture names are synthetic (`*.test.bin`); no real catalogue names appear.
//! Damage is modelled as erased slices (lost articles) plus one
//! corrupt-then-erase case mirroring production (verify rejects → slice
//! erased → recovery → verify accepts). The reference-binary interop test at
//! the bottom runs only when a `par2` binary is available (CI installs one;
//! local runs without it skip with a note).

use velmora::par2::creator::{
    create_single_file, data_slice_count, recover_slices, recovery_slice_count,
    slice_size_for_article_payload, CreatedSet, Par2Creator,
};
use velmora::par2::gf16;
use velmora::par2::RecoverySet;

const FILENAME: &[u8] = b"par2-create-test.bin";
const SLICE: u64 = 1024;

/// Deterministic PRNG (xorshift64*) so fixtures are stable across runs.
fn pseudorandom(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    let mut out = vec![0u8; len];
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
    out
}

fn data_slices_padded(data: &[u8], slice: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for chunk in data.chunks(slice) {
        let mut s = vec![0u8; slice];
        s[..chunk.len()].copy_from_slice(chunk);
        out.push(s);
    }
    out
}

/// Splits `data` into slices and drops `erase` (by index), returning
/// `(present, original_padded_slices)`.
type ErasedSlices = (Vec<(u32, Vec<u8>)>, Vec<Vec<u8>>);

fn erase_slices(data: &[u8], slice: usize, erase: &[u32]) -> ErasedSlices {
    let all = data_slices_padded(data, slice);
    let present = all
        .iter()
        .enumerate()
        .filter(|(i, _)| !erase.contains(&(*i as u32)))
        .map(|(i, s)| (i as u32, s.clone()))
        .collect();
    (present, all)
}

fn reassemble(recovered: &[(u32, Vec<u8>)], present: &[(u32, Vec<u8>)], len: usize) -> Vec<u8> {
    let mut slices: Vec<(u32, Vec<u8>)> = present.to_vec();
    slices.extend(recovered.iter().cloned());
    slices.sort_by_key(|(i, _)| *i);
    let mut out: Vec<u8> = slices.into_iter().flat_map(|(_, s)| s).collect();
    out.truncate(len);
    out
}

// --- Sizing helpers ----------------------------------------------------------

#[test]
fn slice_size_rounds_article_payload_down_to_128() {
    // Design §4 example: k = 11 cipher blocks = 721,072 bytes.
    assert_eq!(slice_size_for_article_payload(721_072).unwrap(), 721_024);
    assert_eq!(slice_size_for_article_payload(128).unwrap(), 128);
    assert_eq!(slice_size_for_article_payload(129).unwrap(), 128);
    assert_eq!(slice_size_for_article_payload(256).unwrap(), 256);
    assert!(slice_size_for_article_payload(127).is_err());
    assert!(slice_size_for_article_payload(0).is_err());
}

#[test]
fn redundancy_is_ten_percent_rounded_up_minimum_one() {
    assert_eq!(recovery_slice_count(1).unwrap(), 1);
    assert_eq!(recovery_slice_count(9).unwrap(), 1);
    assert_eq!(recovery_slice_count(10).unwrap(), 1);
    assert_eq!(recovery_slice_count(11).unwrap(), 2);
    assert_eq!(recovery_slice_count(25).unwrap(), 3);
    assert_eq!(recovery_slice_count(46).unwrap(), 5);
    assert_eq!(recovery_slice_count(140).unwrap(), 14);
    assert!(recovery_slice_count(0).is_err());
    assert_eq!(data_slice_count(10_000, 1024), 10);
    assert_eq!(data_slice_count(1024, 1024), 1);
    assert_eq!(data_slice_count(1025, 1024), 2);
}

// --- Packet layout -----------------------------------------------------------

#[test]
fn created_set_parses_verifies_and_pins_layout() {
    let data = pseudorandom(10_000, 0x51ab_3c7d_29e1_04f5);
    let set = create_single_file(FILENAME, &data, SLICE).unwrap();
    assert_eq!(set.block_size, SLICE);
    assert_eq!(set.data_slices, 10);
    assert_eq!(set.recovery_slices, 1);
    // Main + FileDesc + IFSC + one RecvSlic.
    assert_eq!(set.packets.len(), 4);

    // Recovery exponents are 0..R, each slice exactly one block.
    let pairs = set.recovery_pairs();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, 0);
    assert_eq!(pairs[0].1.len(), SLICE as usize);

    // The set parses through the existing read path and the bytes verify.
    let parsed = RecoverySet::parse(&set.bytes()).expect("created set parses");
    assert_eq!(parsed.set_id, set.set_id);
    assert_eq!(parsed.block_size, SLICE);
    assert_eq!(parsed.recovery_blocks, 1);
    let name = std::str::from_utf8(FILENAME).unwrap();
    parsed.verify(name, &data).expect("created bytes verify");

    // Set ID is the MD5 of the Main packet body (first packet, body at 64..).
    let main_body = &set.packets[0][64..];
    assert_eq!(md5::compute(main_body).0, set.set_id);
    // File ID derives from 16k hash, length and name.
    let first16k = md5::compute(&data[..data.len().min(16 * 1024)]).0;
    let mut seed = Vec::new();
    seed.extend_from_slice(&first16k);
    seed.extend_from_slice(&(data.len() as u64).to_le_bytes());
    seed.extend_from_slice(FILENAME);
    assert_eq!(md5::compute(&seed).0, set.file_id);
}

#[test]
fn exponent_zero_slice_is_xor_parity() {
    // Interop-critical property: exponent 0 uses factor 1 for every input,
    // so the slice must equal the XOR of all (padded) data slices whatever
    // the field tables do.
    let data = pseudorandom(5_000, 0x1234_5678_9abc_def1);
    let set = create_single_file(FILENAME, &data, SLICE).unwrap();
    let slices = data_slices_padded(&data, SLICE as usize);
    let mut parity = vec![0u8; SLICE as usize];
    for s in &slices {
        for (p, b) in parity.iter_mut().zip(s.iter()) {
            *p ^= *b;
        }
    }
    assert_eq!(set.recovery_pairs()[0].1, parity);
}

// --- Streaming -----------------------------------------------------------------

#[test]
fn chunked_push_matches_one_shot() {
    let data = pseudorandom(100_000, 0xdead_beef_cafe_1234);
    let reference = create_single_file(FILENAME, &data, 4096).unwrap();
    for chunk_size in [1usize, 7, 1000, 4096, 65536] {
        let total = data.len() as u64;
        let mut creator = Par2Creator::new(FILENAME, total, 4096).unwrap();
        for chunk in data.chunks(chunk_size) {
            creator.push(chunk).unwrap();
        }
        let set = creator.finish().unwrap();
        assert_eq!(
            set.bytes(),
            reference.bytes(),
            "chunk size {chunk_size} diverged from one-shot"
        );
    }
}

#[test]
fn creator_rejects_bad_inputs() {
    let data = pseudorandom(3000, 99);
    // Empty file.
    assert!(create_single_file(FILENAME, &[], SLICE).is_err());
    // Bad slice sizes (the 128-alignment itself is the caller's job via
    // `slice_size_for_article_payload`; the constructor only needs a non-zero
    // multiple of 4, so 1000 is accepted and 1002 is rejected).
    assert!(Par2Creator::new(FILENAME, 3000, 0).is_err());
    assert!(Par2Creator::new(FILENAME, 3000, 1002).is_err());
    assert!(Par2Creator::new(FILENAME, 3000, 1000).is_ok());
    assert!(Par2Creator::new(FILENAME, 3000, 1 << 29).is_err());
    // Accumulator budget (32 MiB, checked before allocation): 1 MiB slices
    // over 321 data slices need 33 recovery slices = 33 MiB of accumulators,
    // rejected even though the pre-round-2 256 MiB cap would have admitted
    // it — and `finish` would then peak near 2x that against the 128 MB
    // isolate cap. Just under the cap stays accepted (300 slices → 30 MiB).
    assert!(Par2Creator::new(FILENAME, 321 * (1 << 20), 1 << 20).is_err());
    assert!(Par2Creator::new(FILENAME, 300 * (1 << 20), 1 << 20).is_ok());
    // Bad names (mirrors the parser's rejections).
    assert!(Par2Creator::new(b"", 3000, SLICE).is_err());
    assert!(Par2Creator::new(b"\0\0\0\0", 3000, SLICE).is_err());
    assert!(Par2Creator::new(b"\0lead.bin", 3000, SLICE).is_err());
    assert!(Par2Creator::new(b"trail.bin\0\0", 3000, SLICE).is_err());
    // Overrun and shortfall.
    let mut c = Par2Creator::new(FILENAME, 100, SLICE).unwrap();
    assert!(c.push(&data[..101]).is_err());
    let mut c = Par2Creator::new(FILENAME, 3000, SLICE).unwrap();
    c.push(&data[..1000]).unwrap();
    assert!(c.finish().is_err());
    // Exact total in odd chunks still finishes.
    let mut c = Par2Creator::new(FILENAME, 3000, SLICE).unwrap();
    c.push(&data[..2999]).unwrap();
    c.push(&data[2999..3000]).unwrap();
    assert!(c.finish().is_ok());
}

// --- Field spot-checks (pin the extracted interop facts) -----------------------

#[test]
fn field_basics_match_gf2_16_with_poly_0x1100b() {
    // xtime carries out through the low 16 bits of the polynomial.
    assert_eq!(gf16::mul(2, 0x8000), 0x100B);
    assert_eq!(gf16::mul(0, 0xbeef), 0);
    assert_eq!(gf16::mul(0xbeef, 0), 0);
    assert_eq!(gf16::mul(1, 0xbeef), 0xbeef);
    assert_eq!(gf16::mul(0xbeef, 1), 0xbeef);
    // Commutativity spot-check.
    assert_eq!(gf16::mul(0x1234, 0xabcd), gf16::mul(0xabcd, 0x1234));
    // 2 is primitive: order exactly 65535.
    assert_eq!(gf16::pow(2, 65_535), 1);
    assert_ne!(gf16::pow(2, 32_767), 1);
    assert_eq!(gf16::pow(0xbeef, 0), 1);
    // Inverse and division.
    for a in [1u16, 2, 3, 0x100B, 0x8000, 0xFFFF, 0xbeef] {
        assert_eq!(gf16::mul(a, gf16::inv(a).unwrap()), 1);
        assert_eq!(gf16::div(gf16::mul(a, 0x1234), 0x1234).unwrap(), a);
    }
    assert!(gf16::inv(0).is_none());
    assert!(gf16::div(1, 0).is_none());
    // Input bases skip non-coprime logs: antilog[1]=2, antilog[2]=4,
    // antilog[4]=16 (log 3 has gcd(65535,3)=3).
    assert_eq!(gf16::input_bases(3).unwrap(), vec![2, 4, 16]);
}

#[test]
fn kernel_matches_independent_russian_peasant_model() {
    // Independent oracle written straight from the polynomial: any divergence
    // from madd (scalar or simd128 dispatch) is a kernel bug.
    fn model_mul(a: u16, b: u16) -> u16 {
        let mut acc = 0u16;
        let (mut x, mut y) = (a, b);
        while y != 0 {
            if y & 1 != 0 {
                acc ^= x;
            }
            let carry = x & 0x8000 != 0;
            x <<= 1;
            if carry {
                x ^= 0x100B;
            }
            y >>= 1;
        }
        acc
    }
    let mut rng = 0x8bad_f00d_cafe_1234u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for round in 0..30 {
        let words = 1 + (next() % 300) as usize;
        let factor = next() as u16;
        let src: Vec<u16> = (0..words).map(|_| next() as u16).collect();
        let mut want = vec![0x5a5au16; words];
        for (d, s) in want.iter_mut().zip(src.iter()) {
            *d ^= model_mul(*s, factor);
        }
        // Scalar backend directly.
        let t = gf16::nibble_tables(factor);
        let mut got_scalar = vec![0x5a5au16; words];
        gf16::madd_scalar(&mut got_scalar, &src, &t);
        assert_eq!(got_scalar, want, "scalar backend, round {round}");
        // Dispatched path (simd128 where the target enables it).
        let mut got = vec![0x5a5au16; words];
        gf16::madd(&mut got, &src, factor);
        assert_eq!(got, want, "dispatched backend, round {round}");
    }
    // Zero factor is a no-op and empty slices are safe.
    let mut dst = vec![1u16, 2, 3];
    gf16::madd(&mut dst, &[4u16, 5, 6], 0);
    assert_eq!(dst, vec![1u16, 2, 3]);
    let mut empty: Vec<u16> = Vec::new();
    gf16::madd(&mut empty, &[], 7);
}

#[test]
#[should_panic(expected = "assertion")]
fn madd_panics_on_length_mismatch() {
    // Release simd128 sizes its unsafe reads by `dst.len()`; a shorter `src`
    // must panic here, never read out of bounds.
    let mut dst = vec![0u16; 8];
    gf16::madd(&mut dst, &[], 1);
}

#[test]
#[should_panic(expected = "assertion")]
fn madd_scalar_panics_on_length_mismatch() {
    let mut dst = vec![0u16; 8];
    let t = gf16::nibble_tables(1);
    gf16::madd_scalar(&mut dst, &[1u16, 2], &t);
}

#[test]
fn input_bases_rejects_impossible_counts() {
    // φ(65535) = 32 768 full-order bases exist; anything larger is
    // impossible and must fail closed instead of panicking on capacity.
    assert!(gf16::input_bases(usize::MAX).is_none());
    assert!(gf16::input_bases(32_769).is_none());
    assert_eq!(gf16::input_bases(32_768).unwrap().len(), 32_768);
    assert!(gf16::input_bases(0).unwrap().is_empty());
}

// --- Round-trips -----------------------------------------------------------------

fn roundtrip(data_len: usize, slice: u64, erase: &[u32], seed: u64) {
    let data = pseudorandom(data_len, seed);
    let set: CreatedSet = create_single_file(FILENAME, &data, slice).unwrap();
    let (present, _) = erase_slices(&data, slice as usize, erase);
    let recovered = recover_slices(
        slice as usize,
        set.data_slices as usize,
        &present,
        &set.recovery_pairs(),
    )
    .expect("recovery within redundancy must succeed");
    assert_eq!(recovered.len(), erase.len());
    let rebuilt = reassemble(&recovered, &present, data.len());
    assert_eq!(rebuilt, data, "rebuilt bytes differ from the original");
    let name = std::str::from_utf8(FILENAME).unwrap();
    RecoverySet::parse(&set.bytes())
        .unwrap()
        .verify(name, &rebuilt)
        .expect("rebuilt bytes verify through the existing read path");
}

#[test]
fn roundtrip_single_slice_loss() {
    // 10 data slices, 1 recovery slice: lose slice 3 (middle, full).
    roundtrip(10_000, 1024, &[3], 0x51ab_3c7d_29e1_04f5);
    // Lose the short last slice (zero-padding path).
    roundtrip(10_000, 1024, &[9], 0x51ab_3c7d_29e1_04f5);
    // Lose the first slice (16k-hash coverage path).
    roundtrip(10_000, 1024, &[0], 0x7777_7777_7777_7777);
}

#[test]
fn roundtrip_multi_slice_loss_up_to_redundancy() {
    // 25 data slices -> 3 recovery slices: lose all 3 at once.
    roundtrip(100_000, 4096, &[2, 11, 24], 0x1234_5678_9abc_def1);
    // 46 data slices -> 5 recovery slices: lose 5 scattered incl. edges.
    roundtrip(
        46 * 4096 - 500,
        4096,
        &[0, 7, 23, 31, 45],
        0xabcd_abcd_abcd_abcd,
    );
}

#[test]
fn multi_slice_recovery_reuses_rhs_with_nonzero_exponents_and_reordered_present() {
    let slice = 128;
    let data = pseudorandom(40 * slice - 7, 0x1234_5678_9abc_def1);
    let set = create_single_file(FILENAME, &data, slice as u64).unwrap();
    let (mut present, original) = erase_slices(&data, slice, &[0, 12, 39]);
    present.reverse();
    // Exponents 1, 2, 3 exercise nontrivial factors in every recovery row.
    let recovery = set.recovery_pairs();
    let recovered = recover_slices(slice, 40, &present, &recovery[1..]).unwrap();
    assert_eq!(
        recovered.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        vec![0, 12, 39]
    );
    for (index, bytes) in &recovered {
        assert_eq!(bytes, &original[*index as usize]);
    }
    assert_eq!(reassemble(&recovered, &present, data.len()), data);
}

#[test]
fn roundtrip_corrupt_then_erase_mirrors_production_flow() {
    // Corrupt bytes in place: verify (existing path) rejects, the slice is
    // declared lost, recovery restores it, verify accepts.
    let data = pseudorandom(20_000, 0x00fe_e1de_adbe_ef42);
    let slice = 2048u64;
    let set = create_single_file(FILENAME, &data, slice).unwrap();
    let name = std::str::from_utf8(FILENAME).unwrap();
    let parsed = RecoverySet::parse(&set.bytes()).unwrap();

    let mut damaged = data.clone();
    damaged[5000] ^= 0xFF;
    damaged[5001] ^= 0x01;
    assert!(parsed.verify(name, &damaged).is_err());

    let corrupt_slice = 5000 / slice as usize;
    let (present, _) = erase_slices(&data, slice as usize, &[corrupt_slice as u32]);
    let recovered = recover_slices(
        slice as usize,
        set.data_slices as usize,
        &present,
        &set.recovery_pairs(),
    )
    .unwrap();
    let rebuilt = reassemble(&recovered, &present, data.len());
    assert_eq!(rebuilt, data);
    parsed.verify(name, &rebuilt).unwrap();
}

#[test]
fn loss_beyond_redundancy_fails() {
    let data = pseudorandom(100_000, 0x1111_2222_3333_4444);
    let set = create_single_file(FILENAME, &data, 4096).unwrap();
    assert_eq!(set.recovery_slices, 3);
    let (present, _) = erase_slices(&data, 4096, &[0, 1, 2, 3]);
    assert!(recover_slices(
        4096,
        set.data_slices as usize,
        &present,
        &set.recovery_pairs(),
    )
    .is_err());
}

#[test]
fn recover_slices_rejects_absurd_matrix_geometry() {
    // 20 000 missing slices of 2 bytes each is ~80 KB of input but a
    // 20 000 × 20 000 dense solve (~2.4 GB): fail closed on the scratch
    // budget instead of OOMing the isolate.
    let recovery: Vec<(u16, Vec<u8>)> = (0..20_000).map(|i| (i as u16, vec![0u8; 2])).collect();
    assert!(recover_slices(2, 20_000, &[], &recovery).is_err());
}

// --- Reference-binary interop (gated) --------------------------------------------

/// Runs the created set through the *existing* repair path
/// (`repair_with_binary`, the same subprocess the Container batch job uses)
/// with a real reference binary. Skips with a note when no binary is
/// available; CI installs one so this runs there.
#[cfg(target_os = "linux")]
#[test]
fn interop_repair_with_reference_binary_when_available() {
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};

    fn find_par2() -> Option<PathBuf> {
        if let Some(loc) = std::env::var_os("PAR2_BIN") {
            let p = PathBuf::from(&loc);
            if p.is_file() {
                return Some(p);
            }
            let in_dir = p.join("par2");
            if in_dir.is_file() {
                return Some(in_dir);
            }
        }
        for dir in ["/usr/bin", "/usr/local/bin"] {
            for name in ["par2", "par2cmdline"] {
                let p = Path::new(dir).join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|d| d.join("par2"))
                .find(|p| p.is_file())
        })
    }

    let Some(par2_bin) = find_par2() else {
        eprintln!("interop note: no `par2` reference binary in PATH; skipping");
        return;
    };

    let data = pseudorandom(100_000, 0x5555_6666_7777_8888);
    let slice = 4096u64;
    let set = create_single_file(FILENAME, &data, slice).unwrap();
    let name = std::str::from_utf8(FILENAME).unwrap();

    let base: PathBuf = std::env::var_os("PAPERCLIP_RUN_SCRATCH_DIR")
        .or_else(|| std::env::var_os("PAPERCLIP_SCRATCH_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("nntune-create-interop-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    let scratch = base.join("scratch");
    fs::create_dir(&scratch).unwrap();
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _guard = Guard(base);

    // Stage the created set plus a damaged target (three erased slices: the
    // full 3-slice redundancy, so the reference binary must use every
    // recovery row including the exponent-2 row), then repair through the
    // existing path.
    // Write the damaged file with the erased slices zeroed (simulating lost
    // articles replaced by nothing): repair must reconstruct them.
    fs::write(scratch.join("set.par2"), set.bytes()).unwrap();
    let mut staged = data.clone();
    for i in [4usize, 17, 20] {
        let start = i * slice as usize;
        let end = (start + slice as usize).min(staged.len());
        staged[start..end].fill(0);
    }
    fs::write(scratch.join("par2-create-test.bin"), &staged).unwrap();
    let parsed = RecoverySet::parse(&set.bytes()).unwrap();
    assert!(parsed.verify(name, &staged).is_err());

    let report =
        velmora::par2::repair::repair_with_binary(&par2_bin, &scratch, &[Path::new("set.par2")])
            .expect("repair path runs");
    assert!(report.success, "reference repair failed: {report:?}");
    let repaired = fs::read(scratch.join("par2-create-test.bin")).unwrap();
    assert_eq!(repaired, data, "reference binary did not restore our bytes");
    parsed.verify(name, &repaired).unwrap();
}
