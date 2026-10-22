//! Pin for the two PAR2 framing literals (`crates/nntune-core/src/par2.rs`):
//! `IFSC_ENTRY_SIZE` (`:54`, length validation at `:709`, chunked walk at
//! `:728`) and `ZERO_CHUNK_SIZE` (`:84`, streaming zero-run hasher at
//! `:822-824`, so verification never holds a slice-sized zero allocation).
//!
//! Both literals are private to `par2.rs`, and this card forbids
//! production-code changes (so no `pub` re-export to import here). The value
//! pins therefore read the declaration text via `include_str!`: any change to
//! either literal — value, type, or name — flips the pin. The behavior pins
//! prove the values are load-bearing rather than decorative:
//!
//! - IFSC entries are 16-byte MD5 + 4-byte LE CRC (20 bytes). A payload whose
//!   parser-visible length is not a multiple of 20 is rejected with the exact
//!   message; two well-formed entries parse, walk in stride (`e[16..20]` feeds
//!   each block's checksum), and verify.
//! - `verify` over a file whose last-slice padding exceeds one 8 KiB chunk
//!   succeeds, exercising the multi-iteration zero-run path (the chunk size
//!   itself is output-invisible by construction, so its value is pinned by
//!   the source-text test above).
//!
//! Sensitivity: changing `IFSC_ENTRY_SIZE` flips both the source-text pin and
//! the valid-fixture tests (a 20-byte entry no longer divides the new stride);
//! changing `ZERO_CHUNK_SIZE` flips its source-text pin (verified by mutation,
//! restored). An empty IFSC (zero entries, `0 % 20 == 0`) still parses — the
//! control that separates the modulo arm from the short-body arm.
//!
//! Boundary: the precheck segment-sum overflow pin covers a different check;
//! #397 pins packet-shape framing (different aspect); `MAX_BLOCK_SIZE` is
//! pinned in `par2_block_size_cap.rs`. All packets are
//! constructed byte-for-byte in this file (magic, lengths, checksums, set-ID
//! derivation) with the `packet()` builder copied from
//! `par2_precheck_overflow.rs`, never via the parser under test. The only
//! imports from the crate are the parser entry point (`RecoverySet`) and the
//! error type; hashes come from the format's own crates (`md5`,
//! `crc32fast`).

use nntune_core::error::Error;
use nntune_core::par2::RecoverySet;

/// The crate source under test. Both framing literals are private, so the
/// value pins match their declaration lines here instead of importing them.
const PAR2_RS: &str = include_str!("../src/par2.rs");

/// Local mirror of the crate's IFSC stride, used to build fixtures below (not
/// imported: the constant is private). Must stay 20: 16-byte MD5 + 4-byte LE
/// CRC32 per slice checksum.
const IFSC_ENTRY_SIZE: usize = 20;
/// Local mirror of the crate's zero-run chunk, used by the chunked CRC mirror
/// below. Must stay 8192.
const ZERO_CHUNK_SIZE: usize = 8192;

const FILENAME: &str = "track.flac";
const IFSC_REMAINDER_MSG: &str =
    "par2: malformed recovery set: IFSC packet body is not a whole number of slice checksums";

fn file_bytes() -> Vec<u8> {
    let mut x = 0x51ab_3c7d_29e1_04f5u64;
    let mut out = vec![0u8; 100];
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
    out
}

/// Per-block CRC32s with the last block zero-padded to `block_size`, hashed
/// in `ZERO_CHUNK_SIZE` pieces — the same chunked shape as the crate's
/// `update_zero_run`, so the expected values only match if chunked hashing is
/// correct.
fn block_crcs(data: &[u8], block_size: u64) -> Vec<u32> {
    let bs = block_size as usize;
    data.chunks(bs)
        .map(|block| {
            let mut h = crc32fast::Hasher::new();
            h.update(block);
            let zeros = [0u8; ZERO_CHUNK_SIZE];
            let mut n = (bs - block.len()) as u64;
            while n > 0 {
                let take = n.min(ZERO_CHUNK_SIZE as u64) as usize;
                h.update(&zeros[..take]);
                n -= take as u64;
            }
            h.finalize()
        })
        .collect()
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

fn derive_file_id(first16k: &[u8; 16], len: u64, name: &[u8]) -> [u8; 16] {
    let mut seed = Vec::with_capacity(24 + name.len());
    seed.extend_from_slice(first16k);
    seed.extend_from_slice(&len.to_le_bytes());
    seed.extend_from_slice(name);
    md5::compute(&seed).0
}

/// A complete set (FileDesc + IFSC + Main) around `block_size` whose IFSC
/// payload is exactly `file_id ++ entries`. Callers build `entries` from the
/// local `IFSC_ENTRY_SIZE` stride, so a crate-stride change breaks the valid
/// fixtures, not just the source-text pins.
fn set_bytes(block_size: u64, entries: &[u8]) -> Vec<u8> {
    let data = file_bytes();
    let whole_md5 = md5::compute(&data).0;
    let first16k = md5::compute(&data[..data.len().min(16 * 1024)]).0;
    let file_id = derive_file_id(&first16k, data.len() as u64, FILENAME.as_bytes());

    let mut main_body = Vec::new();
    main_body.extend_from_slice(&block_size.to_le_bytes());
    main_body.extend_from_slice(&1u32.to_le_bytes());
    main_body.extend_from_slice(&file_id);
    let set_id = md5::compute(&main_body).0;

    let mut fd_body = Vec::new();
    fd_body.extend_from_slice(&file_id);
    fd_body.extend_from_slice(&whole_md5);
    fd_body.extend_from_slice(&first16k);
    fd_body.extend_from_slice(&(data.len() as u64).to_le_bytes());
    fd_body.extend_from_slice(FILENAME.as_bytes());

    let mut ifsc_body = Vec::new();
    ifsc_body.extend_from_slice(&file_id);
    ifsc_body.extend_from_slice(entries);

    let mut set_bytes = Vec::new();
    set_bytes.extend(packet(&set_id, &ptype(b"FileDesc"), &fd_body));
    set_bytes.extend(packet(&set_id, &ptype(b"IFSC\0\0\0\0"), &ifsc_body));
    set_bytes.extend(packet(&set_id, &ptype(b"Main\0\0\0\0"), &main_body));
    set_bytes
}

/// One IFSC entry: 16-byte MD5 slot (zeroed; the parser only reads the CRC
/// tail) followed by the LE CRC32.
fn entry(crc: u32) -> [u8; 20] {
    let mut e = [0u8; 20];
    e[16..20].copy_from_slice(&crc.to_le_bytes());
    e
}

fn malformed_message(err: &Error) -> &str {
    match err {
        Error::Malformed(msg) => msg.as_str(),
        other => panic!("expected Error::Malformed, got {other:?}"),
    }
}

fn declaration_lines(name: &str) -> Vec<&str> {
    PAR2_RS
        .lines()
        .filter(|l| l.trim().starts_with(&format!("const {name}")))
        .collect()
}

#[test]
fn ifsc_entry_size_is_20() {
    assert_eq!(
        IFSC_ENTRY_SIZE, 20,
        "local stride must be 16-byte MD5 + 4-byte CRC"
    );
    let found = declaration_lines("IFSC_ENTRY_SIZE");
    assert_eq!(
        found.len(),
        1,
        "want exactly one IFSC_ENTRY_SIZE declaration, got: {found:?}"
    );
    assert_eq!(
        found[0].trim(),
        "const IFSC_ENTRY_SIZE: usize = 20;",
        "IFSC stride moved; this pin exists to catch exactly that"
    );
}

#[test]
fn zero_chunk_size_is_8192() {
    assert_eq!(ZERO_CHUNK_SIZE, 8192, "local chunk must be 8 KiB");
    let found = declaration_lines("ZERO_CHUNK_SIZE");
    assert_eq!(
        found.len(),
        1,
        "want exactly one ZERO_CHUNK_SIZE declaration, got: {found:?}"
    );
    assert_eq!(
        found[0].trim(),
        "const ZERO_CHUNK_SIZE: usize = 8192;",
        "zero-run chunk moved; this pin exists to catch exactly that"
    );
}

#[test]
fn twenty_byte_entries_parse_walk_in_stride_and_verify() {
    // 100 bytes at 64-byte slices: 2 blocks, so 2 entries of 20 bytes.
    let data = file_bytes();
    let crcs = block_crcs(&data, 64);
    assert_eq!(crcs.len(), 2);
    let mut entries = Vec::new();
    for &crc in &crcs {
        entries.extend_from_slice(&entry(crc));
    }
    assert_eq!(entries.len(), 2 * IFSC_ENTRY_SIZE);

    let set =
        RecoverySet::parse(&set_bytes(64, &entries)).expect("whole 20-byte entries must parse");
    let file_id = derive_file_id(
        &md5::compute(&data[..data.len().min(16 * 1024)]).0,
        data.len() as u64,
        FILENAME.as_bytes(),
    );
    assert_eq!(
        set.files
            .get(&file_id)
            .expect("IFSC file present")
            .block_crc32s,
        crcs,
        "each 20-byte entry must feed its own block checksum in order"
    );
    set.verify(FILENAME, &data)
        .expect("correct 20-byte entries must verify");
}

#[test]
fn corrupt_second_entry_crc_fails_verify_on_block_1() {
    // Parse accepts any 20-byte entry (values are unchecked until verify),
    // but the flipped CRC must surface as exactly block 1's mismatch — proof
    // the walk reads `e[16..20]` of each entry, not a shifted window.
    let data = file_bytes();
    let mut entries = Vec::new();
    for &crc in &block_crcs(&data, 64) {
        entries.extend_from_slice(&entry(crc));
    }
    entries[16 + IFSC_ENTRY_SIZE + 3] ^= 0x01;

    let set = RecoverySet::parse(&set_bytes(64, &entries)).expect("wrong values still parse");
    let err = set.verify(FILENAME, &data).unwrap_err();
    match err {
        Error::Par2Unhealthy { detail, .. } => assert!(
            detail.contains("block 1 CRC32 mismatch"),
            "want block-1 mismatch, got: {detail}"
        ),
        other => panic!("expected Par2Unhealthy, got {other:?}"),
    }
}

#[test]
fn ifsc_tail_not_a_multiple_of_20_is_rejected() {
    // One whole entry plus `tail` stray bytes. The parser sees the packet
    // padded to a multiple of 4, so the parser-visible remainder is
    // (20 + tail + pad) % 20; tails 17..=19 would pad up to a whole second
    // entry and parse (packet-padding interaction, #397 territory), so the
    // rejection pin uses tails that stay fractional after padding.
    for tail in [1usize, 7, 11, 15] {
        let pad = (4 - (16 + IFSC_ENTRY_SIZE + tail) % 4) % 4;
        let visible = IFSC_ENTRY_SIZE + tail + pad;
        assert_ne!(
            visible % IFSC_ENTRY_SIZE,
            0,
            "tail {tail} must stay fractional after {pad} pad bytes"
        );
        let mut entries = entry(0x1234_5678).to_vec();
        entries.extend(std::iter::repeat(0xABu8).take(tail));
        let err = RecoverySet::parse(&set_bytes(64, &entries)).unwrap_err();
        assert_eq!(
            malformed_message(&err),
            IFSC_REMAINDER_MSG,
            "tail {tail} (parser-visible {visible} bytes) must pin the remainder message, got: {err}"
        );
    }
}

#[test]
fn empty_ifsc_entries_parse_with_no_checksums() {
    // Zero entries: 0 % 20 == 0 takes the Ok path. Control separating the
    // modulo arm (above) from the short-body arm (body < 16 bytes).
    let set = RecoverySet::parse(&set_bytes(64, &[])).expect("empty IFSC must parse");
    let data = file_bytes();
    let file_id = derive_file_id(
        &md5::compute(&data[..data.len().min(16 * 1024)]).0,
        data.len() as u64,
        FILENAME.as_bytes(),
    );
    assert!(set
        .files
        .get(&file_id)
        .expect("IFSC file present")
        .block_crc32s
        .is_empty());
    let err = set.verify(FILENAME, &data).unwrap_err();
    let msg = malformed_message(&err);
    assert!(
        msg.contains("carries no block checksums"),
        "empty IFSC must fail verify for lack of checksums, got: {msg}"
    );
}

#[test]
fn verify_hashes_multi_chunk_zero_padding() {
    // 100 bytes at 16 KiB slices: one block, 16_284 zero-pad bytes — more
    // than one 8 KiB chunk, so the crate's zero-run loop must iterate.
    // Success proves the chunked path hashes exactly the zero-run CRC.
    const BLOCK: u64 = 16 * 1024;
    let data = file_bytes();
    let padding = BLOCK - data.len() as u64;
    assert_eq!(padding, 16_284);
    assert!(
        padding > ZERO_CHUNK_SIZE as u64,
        "padding must exceed one chunk to exercise the loop"
    );
    let crcs = block_crcs(&data, BLOCK);
    assert_eq!(crcs.len(), 1);
    let mut entries = Vec::new();
    entries.extend_from_slice(&entry(crcs[0]));

    let set = RecoverySet::parse(&set_bytes(BLOCK, &entries)).expect("single-entry set must parse");
    set.verify(FILENAME, &data)
        .expect("multi-chunk zero padding must verify");
}
