use sha2::{Digest, Sha256};
use std::io::Cursor;
use velmora_kit::{verify_packs, Entry, RecordRef};

fn pack(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, data) in members {
        let mut h = tar::Header::new_ustar();
        h.set_path(name).unwrap();
        h.set_size(data.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        tar.append(&h, *data).unwrap();
    }
    zstd::bulk::compress(&tar.into_inner().unwrap(), 1).unwrap()
}

#[test]
fn verifies_exact_authenticated_pack_inventory() {
    let name = "m/x/tenant/g_test";
    let ciphertext = b"sealed record";
    let entries = [Entry::RecordRef(RecordRef {
        name: name.into(),
        sha256: Sha256::digest(ciphertext).to_vec(),
    })];
    assert!(verify_packs([Cursor::new(pack(&[(name, ciphertext)]))], &entries).is_ok());
    for bad in [
        pack(&[]),
        pack(&[("m/g_test", ciphertext)]),
        pack(&[(name, b"changed")]),
        pack(&[(name, ciphertext), (name, ciphertext)]),
        pack(&[(name, ciphertext), ("m/g_extra", b"extra")]),
    ] {
        assert!(verify_packs([Cursor::new(bad)], &entries).is_err());
    }
}

#[test]
fn rejects_extension_records_even_if_regular_member_matches() {
    let name = "m/exact";
    let mut tar = tar::Builder::new(Vec::new());
    tar.append_pax_extensions([("mtime", &b"0"[..])]).unwrap();
    let mut h = tar::Header::new_ustar();
    h.set_path(name).unwrap();
    h.set_size(1);
    h.set_mode(0o600);
    h.set_cksum();
    tar.append(&h, &b"x"[..]).unwrap();
    let packed = zstd::bulk::compress(&tar.into_inner().unwrap(), 1).unwrap();
    let entries = [Entry::RecordRef(RecordRef {
        name: name.into(),
        sha256: Sha256::digest(b"x").to_vec(),
    })];
    assert_eq!(
        verify_packs([Cursor::new(packed)], &entries).unwrap_err(),
        velmora_kit::Error::Format
    );
}

#[test]
fn bounded_window_pack_can_hold_more_than_eight_mib_of_tar() {
    use std::io::Write;
    let name = "m/exact";
    let data = vec![9; 9 * 1024 * 1024];
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
    encoder.window_log(23).unwrap();
    {
        let mut tar = tar::Builder::new(&mut encoder);
        let mut h = tar::Header::new_ustar();
        h.set_path(name).unwrap();
        h.set_size(data.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        tar.append(&h, data.as_slice()).unwrap();
        tar.finish().unwrap();
    }
    encoder.flush().unwrap();
    let entries = [Entry::RecordRef(RecordRef {
        name: name.into(),
        sha256: Sha256::digest(&data).to_vec(),
    })];
    verify_packs([Cursor::new(encoder.finish().unwrap())], &entries).unwrap();
}
