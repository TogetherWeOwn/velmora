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
