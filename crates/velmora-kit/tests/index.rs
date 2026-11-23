use std::io::Cursor;
use velmora_bridge::{ports::Kek, types::KekBytes};
use velmora_kit::{read_index, write_index, Entry, RecordRef};

struct Key(KekBytes);
impl Kek for Key {
    fn active(&self) -> (u32, &KekBytes) {
        (5, &self.0)
    }
    fn version(&self, v: u32) -> Option<&KekBytes> {
        (v == 5).then_some(&self.0)
    }
}

fn fixture() -> (Vec<Entry>, Vec<u8>, Key) {
    let key = Key(KekBytes::new([1; 32]));
    let entries = vec![Entry::RecordRef(RecordRef {
        name: "m/example".to_owned(),
        sha256: vec![8; 32],
    })];
    let mut sealed = vec![];
    write_index(&mut sealed, "test-1", &key, entries.iter()).unwrap();
    (entries, sealed, key)
}

#[test]
fn round_trips_index_and_empty_index() {
    let (entries, sealed, key) = fixture();
    assert_eq!(&sealed[..4], b"VKI1");
    assert_eq!(sealed[4], 1);
    assert_eq!(
        read_index(Cursor::new(sealed), "test-1", &key).unwrap(),
        entries
    );
    let mut empty = vec![];
    write_index(&mut empty, "test-2", &key, [].iter()).unwrap();
    assert!(read_index(Cursor::new(empty), "test-2", &key)
        .unwrap()
        .is_empty());
}

#[test]
fn rejects_wrong_identity_key_and_changed_bytes() {
    let (_, sealed, key) = fixture();
    let wrong_key = Key(KekBytes::new([2; 32]));
    assert!(read_index(Cursor::new(&sealed), "test-2", &key).is_err());
    assert!(read_index(Cursor::new(&sealed), "test-1", &wrong_key).is_err());
    for i in [4, 8, 12, 13, 15, sealed.len() - 1] {
        let mut broken = sealed.clone();
        broken[i] ^= 1;
        assert!(read_index(Cursor::new(broken), "test-1", &key).is_err());
    }
}

#[test]
fn rejects_truncation_and_extra_bytes() {
    let (_, mut sealed, key) = fixture();
    for i in 0..sealed.len() {
        assert!(read_index(Cursor::new(&sealed[..i]), "test-1", &key).is_err());
    }
    sealed.push(0);
    assert!(read_index(Cursor::new(sealed), "test-1", &key).is_err());
}

#[test]
fn cbor_item_crosses_frames_and_reordering_is_refused() {
    let key = Key(KekBytes::new([1; 32]));
    let entries = vec![Entry::RecordRef(RecordRef {
        name: "a".repeat(4 * 1024 * 1024 + 3),
        sha256: vec![8; 32],
    })];
    let mut sealed = vec![];
    write_index(&mut sealed, "test-3", &key, entries.iter()).unwrap();
    assert_eq!(sealed[4], 0);
    let frame_two = 9 + u32::from_be_bytes(sealed[5..9].try_into().unwrap()) as usize;
    assert_eq!(sealed[frame_two], 1);
    assert!(read_index(Cursor::new(&sealed[..frame_two]), "test-3", &key).is_err());
    let reordered = [&sealed[..4], &sealed[frame_two..], &sealed[4..frame_two]].concat();
    assert!(read_index(Cursor::new(reordered), "test-3", &key).is_err());
    assert_eq!(
        read_index(Cursor::new(sealed), "test-3", &key).unwrap(),
        entries
    );
}
