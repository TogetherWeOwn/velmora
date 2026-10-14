//! File IDs authenticate raw FileDesc filename bytes, not display strings.

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
    let mut main = BLOCK_SIZE.to_le_bytes().to_vec();
    main.extend_from_slice(&(files.len() as u32).to_le_bytes());
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

#[test]
fn valid_raw_latin1_name_and_nul_padding_authenticate() {
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
    let bytes = recovery_set(&[file]);
    let set = RecoverySet::parse(&bytes).expect("valid raw-byte FileDesc ID rejected");
    assert_eq!(set.files.len(), 1);
    let parsed = &set.files[&id];
    assert_eq!(parsed.file_id, id);
    assert_eq!(parsed.filename, String::from_utf8_lossy(LATIN1_NAME));
    assert!(!parsed.filename.ends_with('\0'));
    assert!(parsed.protected);
    set.verify(&parsed.filename, b"sample audio").unwrap();
}

#[test]
fn replacement_text_file_id_is_not_a_valid_raw_filename_id() {
    let lossy = String::from_utf8_lossy(LATIN1_NAME);
    let file = File {
        raw_name: LATIN1_NAME,
        id_name: lossy.as_bytes(),
        data: b"sample audio",
    };
    assert!(
        RecoverySet::parse(&recovery_set(&[file])).is_err(),
        "forged lossy-name ID accepted"
    );
}

#[test]
fn distinct_raw_names_with_identical_lossy_display_never_select_one_arbitrarily() {
    let first = b"track-\x80.flac";
    let second = b"track-\x81.flac";
    let display = String::from_utf8_lossy(first);
    assert_eq!(display, String::from_utf8_lossy(second));
    let a = File {
        raw_name: first,
        id_name: first,
        data: b"first",
    };
    let b = File {
        raw_name: second,
        id_name: second,
        data: b"other",
    };
    let ids = [file_id(&a), file_id(&b)];
    assert_ne!(ids[0], ids[1]);
    // A collision rejection is only meaningful if each name is valid alone.
    RecoverySet::parse(&recovery_set(&[File {
        raw_name: first,
        id_name: first,
        data: b"first",
    }]))
    .unwrap();
    RecoverySet::parse(&recovery_set(&[File {
        raw_name: second,
        id_name: second,
        data: b"other",
    }]))
    .unwrap();
    match RecoverySet::parse(&recovery_set(&[a, b])) {
        Err(err) => {
            let text = err.to_string().to_lowercase();
            assert!(
                text.contains("duplicate")
                    || text.contains("ambiguous")
                    || text.contains("collision"),
                "not a name-collision rejection: {err}"
            );
        }
        Ok(set) => {
            assert_eq!(set.files.len(), 2);
            assert!(ids.iter().all(|id| set.files.contains_key(id)));
            assert!(
                set.file_by_name(&display).is_none(),
                "lossy name resolved ambiguously"
            );
            assert!(set.protected_file_by_name(&display).is_none());
            assert!(set.verify(&display, b"first").is_err());
            assert!(set.verify(&display, b"other").is_err());
            assert!(set.precheck(&display, &[]).is_err());
        }
    }
}

#[test]
fn utf8_name_control_verifies_valid_checksum_packets() {
    let name = "Björk - Jóga.flac";
    let file = File {
        raw_name: name.as_bytes(),
        id_name: name.as_bytes(),
        data: b"sample audio",
    };
    let set = RecoverySet::parse(&recovery_set(&[file])).unwrap();
    set.verify(name, b"sample audio").unwrap();
}
