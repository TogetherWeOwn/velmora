//! Raw-byte filename acceptance tests for [`RecoverySet`].
//!
//! The display APIs (`*_by_name`, `verify`, `precheck`) key on lossy
//! `String`s, so colliding invalid-byte names stay fail-closed there. The
//! raw APIs (`protected_file_by_name_bytes`, `verify_bytes`,
//! `precheck_bytes`) must select the original NUL-trimmed bytes without
//! lossy conversion while keeping every length/MD5/CRC/protected-membership
//! check identical.

use nntune_core::par2::RecoverySet;

const BLOCK_SIZE: u64 = 16;
const LATIN1_NAME: &[u8] = b"Bj\xf6rk - J\xf3ga.flac";

struct File<'a> {
    raw_name: &'a [u8],
    id_name: &'a [u8],
    data: &'a [u8],
}

fn packet(set_id: [u8; 16], kind: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(b"PAR2\0PKT".as_slice());
    let aligned_len = (body.len() + 3) & !3;
    out.extend_from_slice(&((64 + aligned_len) as u64).to_le_bytes());
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&set_id);
    let mut packet_type = [0; 16];
    packet_type[..8].copy_from_slice(b"PAR 2.0\0");
    packet_type[8..8 + kind.len()].copy_from_slice(kind);
    out.extend_from_slice(&packet_type);
    out.extend_from_slice(body);
    out.resize(64 + aligned_len, 0);
    let checksum = md5::compute(&out[32..]).0;
    out[16..32].copy_from_slice(&checksum);
    out
}

fn file_id(file: &File<'_>) -> [u8; 16] {
    let mut seed = md5::compute(&file.data[..file.data.len().min(16 * 1024)])
        .0
        .to_vec();
    seed.extend_from_slice(&(file.data.len() as u64).to_le_bytes());
    seed.extend_from_slice(file.id_name);
    md5::compute(seed).0
}

fn recovery_set(files: &[File<'_>]) -> Vec<u8> {
    recovery_set_with_recoverable(files, files.len() as u32)
}

fn recovery_set_with_recoverable(files: &[File<'_>], recoverable: u32) -> Vec<u8> {
    let mut main = BLOCK_SIZE.to_le_bytes().to_vec();
    main.extend_from_slice(&recoverable.to_le_bytes());
    for file in files {
        main.extend_from_slice(&file_id(file));
    }
    let set_id = md5::compute(&main).0;
    let mut bytes = packet(set_id, b"Main", &main);
    for file in files {
        let id = file_id(file);
        let mut desc = id.to_vec();
        desc.extend_from_slice(&md5::compute(file.data).0);
        desc.extend_from_slice(&md5::compute(&file.data[..file.data.len().min(16 * 1024)]).0);
        desc.extend_from_slice(&(file.data.len() as u64).to_le_bytes());
        desc.extend_from_slice(file.raw_name);
        bytes.extend(packet(set_id, b"FileDesc", &desc));
        let mut ifsc = id.to_vec();
        for chunk in file.data.chunks(BLOCK_SIZE as usize) {
            let mut padded = [0; BLOCK_SIZE as usize];
            padded[..chunk.len()].copy_from_slice(chunk);
            ifsc.extend_from_slice(&md5::compute(padded).0);
            ifsc.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
        }
        bytes.extend(packet(set_id, b"IFSC", &ifsc));
    }
    bytes
}

fn segments_for(data: &[u8]) -> Vec<(u32, u64)> {
    // Uneven cuts like a real fetch would record.
    let mut cuts = vec![0usize, data.len() / 3, 2 * data.len() / 3, data.len()];
    cuts.dedup();
    if cuts.len() < 2 {
        cuts = vec![0, data.len()];
    }
    cuts.windows(2)
        .map(|w| (crc32fast::hash(&data[w[0]..w[1]]), (w[1] - w[0]) as u64))
        .collect()
}

#[test]
fn raw_latin1_name_selects_nul_trimmed_bytes_without_lossy_conversion() {
    let file = File {
        raw_name: LATIN1_NAME,
        id_name: LATIN1_NAME,
        data: b"sample audio",
    };
    assert_ne!(
        file.raw_name.len() % 4,
        0,
        "fixture must exercise NUL padding"
    );
    let id = file_id(&file);
    let set = RecoverySet::parse(&recovery_set(&[file])).expect("valid set parses");
    let found = set
        .protected_file_by_name_bytes(LATIN1_NAME)
        .expect("raw lookup misses NUL-trimmed name");
    assert_eq!(found.file_id, id);
    assert!(found.protected);
    assert!(found.has_file_desc);
    assert_eq!(found.length, 12);
    // Display form is lossy and NUL-free, but the raw path never converts.
    assert!(!found.filename.ends_with('\0'));
    assert_eq!(found.filename, String::from_utf8_lossy(LATIN1_NAME));

    // Healthy candidate passes; wrong candidate fails (same length, new bytes).
    set.verify_bytes(LATIN1_NAME, b"sample audio").unwrap();
    assert!(set.verify_bytes(LATIN1_NAME, b"sample audix").is_err());

    // Precheck parity: healthy CRCs pass, a one-bit corruption fails closed.
    let segments = segments_for(b"sample audio");
    assert!(set.precheck_bytes(LATIN1_NAME, &segments).unwrap());
    let mut bad = segments.clone();
    bad[0].0 ^= 0x01;
    assert!(!set.precheck_bytes(LATIN1_NAME, &bad).unwrap());
}

#[test]
fn colliding_invalid_byte_names_select_correct_file() {
    let first_raw = b"track-\x80.flac";
    let second_raw = b"track-\x81.flac";
    let display = String::from_utf8_lossy(first_raw);
    assert_eq!(display, String::from_utf8_lossy(second_raw));

    let a = File {
        raw_name: first_raw,
        id_name: first_raw,
        data: b"first-file-bytes",
    };
    let b = File {
        raw_name: second_raw,
        id_name: second_raw,
        data: b"other-file-bytes",
    };
    let ids = [file_id(&a), file_id(&b)];
    assert_ne!(ids[0], ids[1]);

    let set = RecoverySet::parse(&recovery_set(&[a, b])).expect("raw names differ, must parse");
    assert_eq!(set.files.len(), 2);

    // Each raw name selects its own file, never the colliding sibling.
    let fa = set
        .protected_file_by_name_bytes(first_raw.as_slice())
        .expect("first raw name missing");
    assert_eq!(fa.file_id, ids[0]);
    assert_eq!(fa.length, 16);
    let fb = set
        .protected_file_by_name_bytes(second_raw.as_slice())
        .expect("second raw name missing");
    assert_eq!(fb.file_id, ids[1]);

    // Healthy candidates pass; cross-wired candidates fail.
    set.verify_bytes(first_raw, b"first-file-bytes").unwrap();
    set.verify_bytes(second_raw, b"other-file-bytes").unwrap();
    assert!(set.verify_bytes(first_raw, b"other-file-bytes").is_err());
    assert!(set.verify_bytes(second_raw, b"first-file-bytes").is_err());

    // Precheck parity per file.
    let seg_a = segments_for(b"first-file-bytes");
    let seg_b = segments_for(b"other-file-bytes");
    assert!(set.precheck_bytes(first_raw, &seg_a).unwrap());
    assert!(set.precheck_bytes(second_raw, &seg_b).unwrap());
    let mut bad_a = seg_a.clone();
    bad_a[0].0 ^= 0x01;
    assert!(!set.precheck_bytes(first_raw, &bad_a).unwrap());

    // Display-name ambiguity stays fail-closed: no selection, never a pass.
    assert!(set.protected_file_by_name(&display).is_none());
    assert!(set.verify(&display, b"first-file-bytes").is_err());
    assert!(set.verify(&display, b"other-file-bytes").is_err());
    assert!(set.precheck(&display, &seg_a).is_err());
}

#[test]
fn raw_verify_keeps_length_md5_crc_validation_identical_to_display() {
    let name = "Björk - Jóga.flac";
    let file = File {
        raw_name: name.as_bytes(),
        id_name: name.as_bytes(),
        data: b"sample audio",
    };
    let set = RecoverySet::parse(&recovery_set(&[file])).unwrap();

    // Byte and display APIs agree on UTF-8 names.
    set.verify(name, b"sample audio").unwrap();
    set.verify_bytes(name.as_bytes(), b"sample audio").unwrap();

    // Wrong length never passes on either path.
    assert!(set.verify_bytes(name.as_bytes(), b"short").is_err());
    assert!(set.verify(name, b"short").is_err());

    // Same-length damage (MD5 and CRC) never passes on either path.
    let mut damaged = b"sample audio".to_vec();
    damaged[3] ^= 0x01;
    assert!(set.verify_bytes(name.as_bytes(), &damaged).is_err());
    assert!(set.verify(name, &damaged).is_err());

    // Missing entries never pass.
    assert!(set.protected_file_by_name_bytes(b"missing.flac").is_none());
    assert!(set.verify_bytes(b"missing.flac", b"sample audio").is_err());
    assert!(set
        .precheck_bytes(b"missing.flac", &segments_for(b"sample audio"))
        .is_err());
}

#[test]
fn raw_precheck_wrong_lengths_are_errors_not_passes() {
    let name = "track.flac";
    let data = b"0123456789abcdef0123456789";
    let file = File {
        raw_name: name.as_bytes(),
        id_name: name.as_bytes(),
        data,
    };
    let set = RecoverySet::parse(&recovery_set(&[file])).unwrap();
    let segments = segments_for(data);
    assert!(set.precheck_bytes(name.as_bytes(), &segments).unwrap());

    // Truncated segment lists disagree on length: error, never Ok(true).
    assert!(set.precheck_bytes(name.as_bytes(), &segments[..1]).is_err());
    assert!(set.precheck(name, &segments[..1]).is_err());
}

#[test]
fn raw_unprotected_or_missing_entries_never_pass() {
    let prot = File {
        raw_name: b"protected.flac",
        id_name: b"protected.flac",
        data: b"protected-bytes!",
    };
    let unprot = File {
        raw_name: b"unprotected.flac",
        id_name: b"unprotected.flac",
        data: b"unprotected-data",
    };
    // Only the first file is recoverable: the second carries real metadata
    // but no recovery blocks, so it must never vouch for bytes.
    let bytes = recovery_set_with_recoverable(
        &[
            File {
                raw_name: prot.raw_name,
                id_name: prot.id_name,
                data: prot.data,
            },
            File {
                raw_name: unprot.raw_name,
                id_name: unprot.id_name,
                data: unprot.data,
            },
        ],
        1,
    );
    let set = RecoverySet::parse(&bytes).unwrap();
    assert!(set.protected_file_by_name_bytes(prot.raw_name).is_some());
    assert!(set.protected_file_by_name_bytes(unprot.raw_name).is_none());

    set.verify_bytes(prot.raw_name, prot.data).unwrap();
    assert!(set.verify_bytes(unprot.raw_name, unprot.data).is_err());
    assert!(set
        .precheck_bytes(prot.raw_name, &segments_for(prot.data))
        .unwrap());
    assert!(set
        .precheck_bytes(unprot.raw_name, &segments_for(unprot.data))
        .is_err());
}

#[test]
fn raw_precheck_u64_max_lengths_error_without_overflow() {
    let name = "track.flac";
    let data = b"0123456789abcdef";
    let file = File {
        raw_name: name.as_bytes(),
        id_name: name.as_bytes(),
        data,
    };
    let set = RecoverySet::parse(&recovery_set(&[file])).unwrap();

    // A single u64::MAX segment cannot sum to a 16-byte file: error, not panic.
    assert!(set
        .precheck_bytes(name.as_bytes(), &[(0, u64::MAX)])
        .is_err());
    // Two huge lengths must not wrap around to a passing sum either.
    assert!(set
        .precheck_bytes(name.as_bytes(), &[(0, u64::MAX), (0, 1)])
        .is_err());
    assert!(set.precheck(name, &[(0, u64::MAX)]).is_err());
}
