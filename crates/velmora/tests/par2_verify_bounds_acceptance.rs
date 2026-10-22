//! Synthetic acceptance contract for PAR2 verification and bounded parsing.
//!
//! Invalid set metadata is Malformed (dead-letter); corrupt candidate bytes
//! remain Par2Unhealthy / Ok(false) (repair). These tests use public entry
//! points only; zero block size also exercises publicly mutable set metadata.
//! The growth vectors impose a generous finite safety ceiling, not an exact
//! implementation constant: smaller documented caps are permitted. Replaying
//! an identical packet must not consume another unique-entry allowance.

use nntune_core::error::Error;
use nntune_core::par2::{RecoverySet, RecoverySetBuilder};

const NAME: &str = "track.flac";
const DATA: &[u8] = b"0123456789abcdef0123456789";
const BLOCK_SIZE: u64 = 16;
// At most a few MiB of synthetic metadata per vector. No giant allocation is
// needed to detect unbounded per-packet retention. This is an upper acceptance
// ceiling, not a demand that every set of this size be accepted.
const GROWTH_CEILING: u32 = 65_536;

fn packet(set_id: [u8; 16], kind: &[u8], body: &[u8]) -> Vec<u8> {
    let aligned = (body.len() + 3) & !3;
    let mut bytes = b"PAR2\0PKT".to_vec();
    bytes.extend_from_slice(&((64 + aligned) as u64).to_le_bytes());
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&set_id);
    let mut tag = [0; 16];
    tag[..8].copy_from_slice(b"PAR 2.0\0");
    tag[8..8 + kind.len()].copy_from_slice(kind);
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(body);
    bytes.resize(64 + aligned, 0);
    let digest = md5::compute(&bytes[32..]).0;
    bytes[16..32].copy_from_slice(&digest);
    bytes
}

fn file_id(name: &[u8]) -> [u8; 16] {
    let mut seed = md5::compute(DATA).0.to_vec();
    seed.extend_from_slice(&(DATA.len() as u64).to_le_bytes());
    seed.extend_from_slice(name);
    md5::compute(seed).0
}

fn description(name: &[u8], identity_name: &[u8]) -> Vec<u8> {
    let mut body = file_id(identity_name).to_vec();
    body.extend_from_slice(&md5::compute(DATA).0);
    body.extend_from_slice(&md5::compute(DATA).0);
    body.extend_from_slice(&(DATA.len() as u64).to_le_bytes());
    body.extend_from_slice(name);
    body
}

fn checksums(id: [u8; 16], count: usize) -> Vec<u8> {
    let mut body = id.to_vec();
    for i in 0..count {
        let mut block = [0; BLOCK_SIZE as usize];
        if let Some(chunk) = DATA.chunks(BLOCK_SIZE as usize).nth(i) {
            block[..chunk.len()].copy_from_slice(chunk);
        }
        body.extend_from_slice(&md5::compute(block).0);
        body.extend_from_slice(&crc32fast::hash(&block).to_le_bytes());
    }
    body
}

struct Fixture {
    set_id: [u8; 16],
    packets: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(name: &[u8], identity_name: &[u8], count: usize) -> Self {
        let id = file_id(identity_name);
        let mut main = BLOCK_SIZE.to_le_bytes().to_vec();
        main.extend_from_slice(&1u32.to_le_bytes());
        main.extend_from_slice(&id);
        let set_id = md5::compute(&main).0;
        Self {
            set_id,
            packets: vec![
                packet(set_id, b"FileDesc", &description(name, identity_name)),
                packet(set_id, b"IFSC", &checksums(id, count)),
                packet(set_id, b"Main", &main),
                packet(set_id, b"RecvSlic", &7u32.to_le_bytes()),
            ],
        }
    }

    fn healthy() -> Self {
        Self::new(NAME.as_bytes(), NAME.as_bytes(), 2)
    }

    fn parse(&self) -> RecoverySet {
        RecoverySet::parse(&self.packets.concat()).expect("synthetic set must parse")
    }
}

fn segments(data: &[u8]) -> Vec<(u32, u64)> {
    // Cuts do not coincide with the 16-byte PAR2 block boundary.
    data.chunks(7)
        .map(|chunk| (crc32fast::hash(chunk), chunk.len() as u64))
        .collect()
}

fn assert_malformed<T: std::fmt::Debug>(result: Result<T, Error>, context: &str) {
    assert!(
        matches!(result, Err(Error::Malformed(_))),
        "{context}: expected dead-letter Error::Malformed, got {result:?}"
    );
}

fn invalid_metadata(case: &str) -> (RecoverySet, &str) {
    match case {
        "unknown" => (Fixture::healthy().parse(), "unknown.flac"),
        "zero" => {
            // Public fields allow callers to construct this invalid state even
            // if parsing itself refuses a zero-size Main packet.
            let mut set = Fixture::healthy().parse();
            set.block_size = 0;
            (set, NAME)
        }
        "empty" => (
            Fixture::new(NAME.as_bytes(), NAME.as_bytes(), 0).parse(),
            NAME,
        ),
        "short" => (
            Fixture::new(NAME.as_bytes(), NAME.as_bytes(), 1).parse(),
            NAME,
        ),
        "extra" => (
            Fixture::new(NAME.as_bytes(), NAME.as_bytes(), 3).parse(),
            NAME,
        ),
        _ => unreachable!(),
    }
}

macro_rules! taxonomy_case {
    ($verify:ident, $precheck:ident, $case:literal) => {
        #[test]
        fn $verify() {
            let (set, name) = invalid_metadata($case);
            assert_malformed(set.verify(name, DATA), concat!($case, " verify"));
            assert_malformed(set.verify_bytes(name.as_bytes(), DATA), "raw verify");
        }

        #[test]
        fn $precheck() {
            let (set, name) = invalid_metadata($case);
            let segments = segments(DATA);
            assert_malformed(set.precheck(name, &segments), concat!($case, " precheck"));
            assert_malformed(
                set.precheck_bytes(name.as_bytes(), &segments),
                "raw precheck",
            );
        }
    };
}

taxonomy_case!(
    unknown_file_verify_is_malformed,
    unknown_file_precheck_is_malformed,
    "unknown"
);
taxonomy_case!(
    zero_block_verify_is_malformed,
    zero_block_precheck_is_malformed,
    "zero"
);
taxonomy_case!(
    empty_checksums_verify_is_malformed,
    empty_checksums_precheck_is_malformed,
    "empty"
);
taxonomy_case!(
    short_checksums_verify_is_malformed,
    short_checksums_precheck_is_malformed,
    "short"
);
taxonomy_case!(
    extra_checksums_verify_is_malformed,
    extra_checksums_precheck_is_malformed,
    "extra"
);

#[test]
fn damaged_candidate_is_repairable_not_malformed() {
    let set = Fixture::healthy().parse();
    let mut damaged = DATA.to_vec();
    damaged[3] ^= 1;
    for result in [
        set.verify(NAME, &damaged),
        set.verify_bytes(NAME.as_bytes(), &damaged),
    ] {
        assert!(
            matches!(result, Err(Error::Par2Unhealthy { .. })),
            "{result:?}"
        );
    }
    assert!(!set.precheck(NAME, &segments(&damaged)).unwrap());
    assert!(!set
        .precheck_bytes(NAME.as_bytes(), &segments(&damaged))
        .unwrap());
}

#[test]
fn wrong_candidate_length_remains_repairable() {
    let set = Fixture::healthy().parse();
    assert!(matches!(
        set.verify(NAME, &DATA[..23]),
        Err(Error::Par2Unhealthy { .. })
    ));
}

fn reject_name(raw_name: &[u8]) {
    // The identity authenticates the post-NUL bytes (empty), so rejection must
    // concern the empty name, not an unrelated File ID derivation mismatch.
    let fixture = Fixture::new(raw_name, b"", 2);
    assert_malformed(
        RecoverySet::parse(&fixture.packets.concat()),
        "empty filename parse",
    );
    let mut builder = RecoverySetBuilder::new();
    assert_malformed(
        builder.add_stream(&fixture.packets[0]),
        "empty filename stream",
    );
}

#[test]
fn empty_filename_is_malformed() {
    reject_name(b"");
}

#[test]
fn all_nul_filename_is_malformed() {
    reject_name(b"\0\0\0\0");
}

#[test]
fn leading_nul_with_nonempty_suffix_is_malformed() {
    reject_name(b"\0track.flac");
}

#[test]
fn ordinary_utf8_and_ansi_names_still_verify() {
    for name in [NAME.as_bytes(), "Björk.flac".as_bytes(), b"Bj\xf6rk.flac"] {
        let set = Fixture::new(name, name, 2).parse();
        let file = set
            .protected_file_by_name_bytes(name)
            .expect("raw name retained");
        assert_eq!(file.filename_bytes, name);
        let display = String::from_utf8_lossy(name);
        set.verify(&display, DATA).unwrap();
        set.verify_bytes(name, DATA).unwrap();
        assert!(set.precheck(&display, &segments(DATA)).unwrap());
        assert!(set.precheck_bytes(name, &segments(DATA)).unwrap());
    }
}

#[test]
fn whole_md5_is_checked_even_when_block_crcs_match() {
    let f = Fixture::healthy();
    let mut packets = f.packets.clone();
    let mut desc = description(NAME.as_bytes(), NAME.as_bytes());
    desc[16] ^= 1; // File ID authenticates first16k MD5, not whole-file MD5.
    packets[0] = packet(f.set_id, b"FileDesc", &desc);
    let set = RecoverySet::parse(&packets.concat()).unwrap();
    assert!(matches!(
        set.verify(NAME, DATA),
        Err(Error::Par2Unhealthy { .. })
    ));
}

#[test]
fn block_crc_is_checked_even_when_whole_md5_matches() {
    let f = Fixture::healthy();
    let mut packets = f.packets.clone();
    let mut ifsc = checksums(file_id(NAME.as_bytes()), 2);
    ifsc[32] ^= 1;
    packets[1] = packet(f.set_id, b"IFSC", &ifsc);
    let set = RecoverySet::parse(&packets.concat()).unwrap();
    assert!(matches!(
        set.verify(NAME, DATA),
        Err(Error::Par2Unhealthy { .. })
    ));
    assert!(!set.precheck(NAME, &segments(DATA)).unwrap());
}

fn reject_declared_length(length: u64, with_prefix: bool) {
    let f = Fixture::healthy();
    let mut oversized = packet(f.set_id, b"Future", b"abcd");
    oversized[8..16].copy_from_slice(&length.to_le_bytes());
    let mut builder = RecoverySetBuilder::new();
    let mut stream = Vec::new();
    if with_prefix {
        builder.add_stream(&f.packets.concat()).unwrap();
        stream.extend_from_slice(&f.packets.concat());
    }
    stream.extend_from_slice(&oversized);
    assert_malformed(RecoverySet::parse(&stream), "declared u64 length parse");
    assert_malformed(
        builder.add_stream(&oversized),
        "declared u64 length streaming",
    );
}

#[test]
fn four_gib_length_cannot_wrap_to_valid_unknown_packet() {
    // Low 32 bits are the *valid* physical packet length, so an `as usize`
    // truncation on wasm32 would silently accept this packet and skip it.
    reject_declared_length((1u64 << 32) + 68, false);
}

#[test]
fn four_gib_length_cannot_wrap_after_valid_packet_prefix() {
    reject_declared_length((1u64 << 32) + 68, true);
}

#[test]
fn maximum_aligned_u64_length_is_malformed_without_panicking() {
    reject_declared_length(u64::MAX - 3, true);
}

#[test]
fn huge_length_with_sixty_four_bit_high_word_is_malformed() {
    reject_declared_length((1u64 << 63) + 68, true);
}

#[derive(Clone, Copy, Debug)]
enum Growth {
    Recovery,
    Description,
    Checksums,
}

fn growth_packet(kind: Growth, index: u32) -> Vec<u8> {
    let set_id = [0x42; 16];
    match kind {
        Growth::Recovery => packet(set_id, b"RecvSlic", &index.to_le_bytes()),
        Growth::Description => {
            let name = format!("track-{index}.flac");
            packet(
                set_id,
                b"FileDesc",
                &description(name.as_bytes(), name.as_bytes()),
            )
        }
        Growth::Checksums => {
            let mut id = [0; 16];
            id[..4].copy_from_slice(&index.to_le_bytes());
            packet(set_id, b"IFSC", &checksums(id, 2))
        }
    }
}

fn assert_growth_bounded(kind: Growth) {
    let mut builder = RecoverySetBuilder::new();
    // No finish(): that would conflate a missing Main packet with a bound.
    // Packet-order independence permits metadata before Main. The cap must
    // fire during accumulation, not after all attacker metadata is retained.
    for i in 0..=GROWTH_CEILING {
        let result = builder.add_stream(&growth_packet(kind, i));
        if result.is_err() {
            assert!(i >= 16, "ordinary small {kind:?} set rejected at {i}");
            assert_malformed(result, "unique metadata cap");
            return;
        }
    }
    panic!(
        "unbounded {kind:?} metadata: accepted {} unique packets",
        GROWTH_CEILING + 1
    );
}

#[test]
fn unique_recovery_exponents_are_count_bounded_while_streaming() {
    assert_growth_bounded(Growth::Recovery);
}

#[test]
fn unique_file_descriptions_and_filenames_are_count_bounded_while_streaming() {
    assert_growth_bounded(Growth::Description);
}

#[test]
fn unique_ifsc_file_ids_are_count_bounded_while_streaming() {
    assert_growth_bounded(Growth::Checksums);
}

#[test]
fn main_membership_growth_is_bounded() {
    let mut main = BLOCK_SIZE.to_le_bytes().to_vec();
    main.extend_from_slice(&(GROWTH_CEILING + 1).to_le_bytes());
    for index in 0..=GROWTH_CEILING {
        let mut id = [0; 16];
        id[..4].copy_from_slice(&index.to_le_bytes());
        main.extend_from_slice(&id);
    }
    let bytes = packet(md5::compute(&main).0, b"Main", &main);
    assert_malformed(RecoverySet::parse(&bytes), "Main membership cap");
    assert_malformed(
        RecoverySetBuilder::new().add_stream(&bytes),
        "streamed Main membership cap",
    );
}

#[test]
fn identical_packets_deduplicate_without_spending_unique_capacity() {
    let f = Fixture::healthy();
    let mut builder = RecoverySetBuilder::new();
    builder.add_stream(&f.packets.concat()).unwrap();
    for _ in 0..=GROWTH_CEILING {
        for bytes in &f.packets {
            builder
                .add_stream(bytes)
                .expect("duplicate must not exhaust unique-entry caps");
        }
    }
    let set = builder.finish().unwrap();
    assert_eq!(set.files.len(), 1);
    assert_eq!(set.recovery_blocks, 1);
    set.verify(NAME, DATA).unwrap();
}

#[test]
fn unknown_packets_skip_without_spending_retained_metadata_capacity() {
    let f = Fixture::healthy();
    let mut builder = RecoverySetBuilder::new();
    builder.add_stream(&f.packets.concat()).unwrap();
    for i in 0..=GROWTH_CEILING {
        builder
            .add_stream(&packet(f.set_id, b"Future", &i.to_le_bytes()))
            .unwrap();
    }
    let set = builder.finish().unwrap();
    assert_eq!(set.files.len(), 1);
    assert_eq!(set.recovery_blocks, 1);
    set.verify(NAME, DATA).unwrap();
}

#[test]
fn skipped_unknown_packet_still_requires_a_valid_md5() {
    let f = Fixture::healthy();
    let mut stream = f.packets.concat();
    let mut unknown = packet(f.set_id, b"Future", b"abcd");
    unknown[64] ^= 1;
    stream.extend_from_slice(&unknown);
    assert_malformed(RecoverySet::parse(&stream), "unknown packet checksum");
}
