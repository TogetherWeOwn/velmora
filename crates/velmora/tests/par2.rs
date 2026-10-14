//! PAR2 tests: a minimal recovery set built from scratch in-test (Main +
//! FileDesc + IFSC + one recovery slice), verified byte-for-byte against the
//! format rules ported from v1, plus `crc32_combine` against the Go reference
//! values and a concatenation property test.

use nntune_core::error::Error;
use nntune_core::par2::{crc32_combine, RecoverySet};

const BLOCK_SIZE: u64 = 256;
const FILENAME: &str = "track.flac";

fn file_bytes() -> Vec<u8> {
    let mut x = 0x51ab_3c7d_29e1_04f5u64;
    let mut out = vec![0u8; 1000];
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
    out
}

fn block_crcs(data: &[u8]) -> Vec<u32> {
    data.chunks(BLOCK_SIZE as usize)
        .map(|block| {
            let mut h = crc32fast::Hasher::new();
            h.update(block);
            if block.len() < BLOCK_SIZE as usize {
                // PAR2 checksums the last slice zero-padded to full size.
                h.update(&vec![0u8; BLOCK_SIZE as usize - block.len()]);
            }
            h.finalize()
        })
        .collect()
}

// --- PAR2 packet construction ---------------------------------------------

fn packet(set_id: &[u8; 16], kind: &[u8; 16], body: &[u8]) -> Vec<u8> {
    // Packet lengths are multiples of 4; pad the body like par2cmdline does.
    let mut aligned = body.to_vec();
    while aligned.len() % 4 != 0 {
        aligned.push(0);
    }
    let mut p = Vec::new();
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&((64 + aligned.len()) as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5 placeholder
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

struct Fixture {
    data: Vec<u8>,
    set_bytes: Vec<u8>,
    file_id: [u8; 16],
}

fn fixture() -> Fixture {
    fixture_with_crcs(block_crcs(&file_bytes()), BLOCK_SIZE)
}

/// Builds the fixture around caller-supplied block CRCs and slice size, so
/// tests can forge IFSC/packet values the honest builder never emits.
fn fixture_with_crcs(crcs: Vec<u32>, block_size: u64) -> Fixture {
    let data = file_bytes();
    let whole_md5 = md5::compute(&data).0;
    let first16k = md5::compute(&data[..data.len().min(16 * 1024)]).0;
    let mut seed = Vec::new();
    seed.extend_from_slice(&first16k);
    seed.extend_from_slice(&(data.len() as u64).to_le_bytes());
    seed.extend_from_slice(FILENAME.as_bytes());
    let file_id = md5::compute(&seed).0;

    let mut main_body = Vec::new();
    main_body.extend_from_slice(&block_size.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes()); // 1 recoverable file
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
    for crc in crcs {
        ifsc_body.extend_from_slice(&[0u8; 16]); // per-slice MD5 (unused by verify)
        ifsc_body.extend_from_slice(&crc.to_le_bytes());
    }

    let mut rs_body = Vec::new();
    rs_body.extend_from_slice(&7u32.to_le_bytes()); // exponent 7

    let mut set_bytes = Vec::new();
    // Deliberately scramble packet order: the format fixes no order.
    set_bytes.extend(packet(&set_id, &ptype(b"FileDesc"), &fd_body));
    set_bytes.extend(packet(&set_id, &ptype(b"RecvSlic"), &rs_body));
    set_bytes.extend(packet(&set_id, &ptype(b"IFSC\0\0\0\0"), &ifsc_body));
    set_bytes.extend(packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body));
    Fixture {
        data,
        set_bytes,
        file_id,
    }
}

// --- Parser ---------------------------------------------------------------

#[test]
fn parses_minimal_set_and_marks_file_protected() {
    let f = fixture();
    let set = RecoverySet::parse(&f.set_bytes).expect("valid set parses");
    assert_eq!(set.block_size, BLOCK_SIZE);
    assert_eq!(set.recovery_blocks, 1);
    assert_eq!(set.files.len(), 1);
    let file = set.protected_file_by_name(FILENAME).expect("protected");
    assert_eq!(file.file_id, f.file_id);
    assert_eq!(file.length, 1000);
    assert_eq!(file.block_crc32s, block_crcs(&f.data));
    assert!(file.has_file_desc);
}

#[test]
fn unknown_packet_types_are_ignored_but_still_checksummed() {
    let f = fixture();
    let set_id = {
        let set = RecoverySet::parse(&f.set_bytes).unwrap();
        set.set_id
    };
    let mut with_unknown = f.set_bytes.clone();
    with_unknown.extend(packet(&set_id, &ptype(b"NewMagic"), b"future data!!"));
    let set = RecoverySet::parse(&with_unknown).expect("unknown packets ignored");
    assert_eq!(set.files.len(), 1);

    // ...but a bad checksum on an unknown packet still fails the set.
    let last = with_unknown.len() - 1;
    with_unknown[last] ^= 0x01;
    assert!(RecoverySet::parse(&with_unknown).is_err());
}

#[test]
fn rejects_structural_forgeries() {
    let f = fixture();
    // Sanity: the fixture itself parses before we start forging it.
    RecoverySet::parse(&f.set_bytes).unwrap();

    // Bad magic.
    let mut bad = f.set_bytes.clone();
    bad[0] = b'X';
    assert!(RecoverySet::parse(&bad).is_err());

    // Truncated.
    assert!(RecoverySet::parse(&f.set_bytes[..100]).is_err());
    assert!(RecoverySet::parse(b"").is_err());

    // Mixed set IDs across packets.
    let mut mixed = f.set_bytes.clone();
    // Flip a set-ID byte in the second packet (past its header).
    mixed[64 + 40] ^= 0x01;
    // Repair that packet's checksum so only the set-ID check fires... it
    // can't: the checksum covers the set ID, so this is a checksum failure.
    // Either way it must not parse.
    assert!(RecoverySet::parse(&mixed).is_err());

    // Set ID that is not the MD5 of the Main body: rebuild Main with a forged
    // ID but a valid packet checksum.
    let forged: [u8; 16] = [0xabu8; 16];
    let mut main_body = Vec::new();
    main_body.extend_from_slice(&BLOCK_SIZE.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes());
    main_body.extend_from_slice(&f.file_id);
    let set_bytes = [packet(&forged, &ptype(b"Main\0\0\0\0"), &main_body)].concat();
    let err = RecoverySet::parse(&set_bytes).unwrap_err();
    assert!(
        err.to_string().contains("MD5 of the Main packet"),
        "got: {err}"
    );

    // FileDesc whose file ID does not derive from its own content.
    let mut fd = Vec::new();
    fd.extend_from_slice(&[9u8; 16]);
    fd.extend_from_slice(&[0u8; 16]);
    fd.extend_from_slice(&[0u8; 16]);
    fd.extend_from_slice(&1000u64.to_le_bytes());
    fd.extend_from_slice(b"evil.flac\0\0\0");
    // Forge a fresh set around the bad FileDesc: Main lists the evil ID and
    // the set ID derives from that Main, so only the FileDesc derivation
    // check can fire.
    let mut main2 = Vec::new();
    main2.extend_from_slice(&BLOCK_SIZE.to_le_bytes());
    main2.extend_from_slice(&1u32.to_le_bytes());
    main2.extend_from_slice(&[9u8; 16]);
    let sid2 = md5::compute(&main2).0;
    let set_bytes = [
        packet(&sid2, &ptype(b"FileDesc"), &fd),
        packet(&sid2, &ptype(b"Main\0\0\0\0"), &main2),
    ]
    .concat();
    let err = RecoverySet::parse(&set_bytes).unwrap_err();
    assert!(err.to_string().contains("not derived"), "got: {err}");
}

// --- Verify ---------------------------------------------------------------

/// A forged IFSC carrying MORE block checksums than the file admits must
/// return an error, never panic with an out-of-bounds index (remote panic
/// from a ~200-byte packet). A 1000-byte file at 256-byte slices needs
/// exactly 4; this set carries 5 correct-looking CRCs.
#[test]
fn verify_and_precheck_reject_extra_block_crcs_without_panicking() {
    let mut crcs = block_crcs(&file_bytes());
    crcs.push(0xdead_beef);
    let f = fixture_with_crcs(crcs, BLOCK_SIZE);
    // The set itself still parses (IFSC order/count is only meaningful
    // against the file length at verify time).
    let set = RecoverySet::parse(&f.set_bytes).expect("over-long IFSC parses");
    let err = set.verify(FILENAME, &f.data).unwrap_err();
    assert!(
        matches!(err, Error::Par2Unhealthy { .. }),
        "want Par2Unhealthy, got: {err}"
    );
    let cuts = [0usize, 500, 1000];
    let segments: Vec<(u32, u64)> = cuts
        .windows(2)
        .map(|w| (crc32fast::hash(&f.data[w[0]..w[1]]), (w[1] - w[0]) as u64))
        .collect();
    assert!(set.precheck(FILENAME, &segments).is_err());
}

/// Same for FEWER checksums than required: 3 instead of 4.
#[test]
fn verify_rejects_missing_block_crcs() {
    let mut crcs = block_crcs(&file_bytes());
    crcs.pop();
    let f = fixture_with_crcs(crcs, BLOCK_SIZE);
    let set = RecoverySet::parse(&f.set_bytes).expect("short IFSC parses");
    assert!(set.verify(FILENAME, &f.data).is_err());
}

/// An absurd Main slice size is rejected at parse with a bounded error —
/// crucially WITHOUT allocating or hashing gigabytes of zeroes. A 1 GiB
/// slice over a 1000-byte file would otherwise burn ~1 GiB of zero-hash CPU
/// per verify call from one small packet.
#[test]
fn parse_rejects_absurd_block_size() {
    let f = fixture();
    let huge = 1u64 << 32;
    let mut main_body = Vec::new();
    main_body.extend_from_slice(&huge.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes());
    main_body.extend_from_slice(&f.file_id);
    let set_id = md5::compute(&main_body).0;
    let set_bytes = packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body);
    let err = RecoverySet::parse(&set_bytes).unwrap_err();
    assert!(
        err.to_string().contains("exceeds the supported bound"),
        "got: {err}"
    );
}

#[test]
fn verify_accepts_healthy_and_rejects_damaged() {
    let f = fixture();
    let set = RecoverySet::parse(&f.set_bytes).unwrap();
    set.verify(FILENAME, &f.data).expect("healthy verifies");

    let mut damaged = f.data.clone();
    damaged[500] ^= 0x01;
    let err = set.verify(FILENAME, &damaged).unwrap_err();
    assert!(matches!(err, Error::Par2Unhealthy { .. }), "got: {err}");

    let err = set.verify(FILENAME, &f.data[..999]).unwrap_err();
    assert!(err.to_string().contains("length"), "got: {err}");

    let err = set.verify("nope.flac", &f.data).unwrap_err();
    assert!(matches!(err, Error::Par2Unhealthy { .. }), "got: {err}");
}

// --- Precheck + crc32_combine ------------------------------------------------

fn crc_of(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

#[test]
fn crc32_combine_matches_go_reference() {
    // Produced by v1 `Combine` over "hello " + 65-byte second half.
    assert_eq!(crc32_combine(0xed81f9f6, 0xf8eb7a84, 65), 0x3fcabd71);
    assert_eq!(crc32_combine(0x12345678, 0x9abcdef0, 0), 0x12345678);
}

#[test]
fn crc32_combine_matches_concatenation() {
    let mut x = 0x8bad_f00d_cafe_1234u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..50 {
        let total = 1 + (next() % 2000) as usize;
        let cut = (next() as usize) % (total + 1);
        let mut data = vec![0u8; total];
        for b in data.iter_mut() {
            *b = next() as u8;
        }
        let (a, b) = data.split_at(cut);
        assert_eq!(
            crc32_combine(crc_of(a), crc_of(b), b.len() as u64),
            crc_of(&data)
        );
    }
}

#[test]
fn precheck_proves_healthy_file_without_rehashing() {
    let f = fixture();
    let set = RecoverySet::parse(&f.set_bytes).unwrap();
    // Split the file into uneven "segments" as fetch_release would record.
    let cuts = [0usize, 300, 700, 1000];
    let segments: Vec<(u32, u64)> = cuts
        .windows(2)
        .map(|w| (crc_of(&f.data[w[0]..w[1]]), (w[1] - w[0]) as u64))
        .collect();
    assert!(set.precheck(FILENAME, &segments).unwrap());

    // A corrupted segment CRC fails the precheck (no repair binary involved).
    let mut bad = segments.clone();
    bad[1].0 ^= 0x01;
    assert!(!set.precheck(FILENAME, &bad).unwrap());

    // Lengths that don't sum to the file length are an error, not a pass.
    assert!(set.precheck(FILENAME, &segments[..2]).is_err());
    assert!(set.precheck("unknown.flac", &segments).is_err());
}
