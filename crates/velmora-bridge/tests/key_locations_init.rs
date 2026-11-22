//! The first key-location record (AM-70, AM-70b): `init_locations` writes
//! `m/kl/` seq 1 only into an empty chain, answers a head that names the
//! two locations as `Same` and any other head as `Differ`, and fails
//! (writing nothing) on a head that does not open, telling a KEK version
//! not held yet from damage.

use std::cell::Cell;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::keys::locations::{
    init_locations, is_kek_not_held, is_locations_damage, locations_chain, read_locations,
    two_in_account, write_locations, InitLocations, KeyLocation, LocationStatus,
};
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::testkit::TestKek;
use velmora_bridge::Result;

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(b"key locations init");
            h.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn kek_bytes(v: u32) -> [u8; 32] {
    Sha256::digest(format!("kl kek {v}").as_bytes()).into()
}

/// This Worker's KEK: version 1 active and held.
fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, kek_bytes(1))])
}

#[tokio::test(flavor = "current_thread")]
async fn an_empty_chain_gets_seq_one_and_a_re_run_writes_nothing() {
    let store = MemRecords::new();
    let kek = kek();
    assert_eq!(
        init_locations(&store, &kek, &mut TestRng(1)).await.unwrap(),
        InitLocations::Written
    );
    let head = read_locations(&store, &kek, 0).await.unwrap().unwrap();
    assert_eq!(head, two_in_account());
    assert_eq!(store.names(), vec![locations_chain().name(1)]);
    let puts = store.puts();
    assert_eq!(
        init_locations(&store, &kek, &mut TestRng(2)).await.unwrap(),
        InitLocations::Same
    );
    assert_eq!(store.puts(), puts);
}

/// `Same` whatever the head's seq and its other locations, as long as it
/// lists `KEYS_A` as the active synchronous arbiter and `KEYS_B` as active
/// and synchronous; anything else is `Differ`. Neither writes.
#[tokio::test(flavor = "current_thread")]
async fn a_head_answers_same_or_differ_and_nothing_is_written() {
    let kek = kek();
    // A later set: seq 2 adds a proposed escrow location.
    let store = MemRecords::new();
    init_locations(&store, &kek, &mut TestRng(1)).await.unwrap();
    let mut later = two_in_account();
    later.seq = 2;
    later.locations.push(KeyLocation {
        name: "KEYS_E".into(),
        status: LocationStatus::Proposed,
        arbiter: false,
        synchronous: false,
    });
    assert!(write_locations(&store, &kek, &later, &mut TestRng(2))
        .await
        .unwrap());
    let puts = store.puts();
    assert_eq!(
        init_locations(&store, &kek, &mut TestRng(3)).await.unwrap(),
        InitLocations::Same
    );
    assert_eq!(store.puts(), puts);

    // KEYS_B only proposed, or KEYS_B asynchronous: `Differ`.
    for differ in [
        {
            let mut s = two_in_account();
            s.locations[1].status = LocationStatus::Proposed;
            s
        },
        {
            let mut s = two_in_account();
            s.locations[1].synchronous = false;
            s
        },
    ] {
        let store = MemRecords::new();
        assert!(write_locations(&store, &kek, &differ, &mut TestRng(4))
            .await
            .unwrap());
        let puts = store.puts();
        assert_eq!(
            init_locations(&store, &kek, &mut TestRng(5)).await.unwrap(),
            InitLocations::Differ
        );
        assert_eq!(store.puts(), puts);
        assert_eq!(
            read_locations(&store, &kek, 0).await.unwrap().unwrap(),
            differ
        );
    }
}

/// A head that appears between the read and the put: the put loses, and
/// the answer is the head's.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_first_put_answers_from_the_head() {
    struct Racing<'a> {
        inner: &'a MemRecords,
        kek: &'a TestKek,
        theirs: Cell<bool>,
        other: bool,
    }
    impl RecordStore for Racing<'_> {
        async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
            if self.theirs.replace(false) {
                let mut set = two_in_account();
                if self.other {
                    set.locations[1].status = LocationStatus::Proposed;
                }
                assert!(
                    write_locations(self.inner, self.kek, &set, &mut TestRng(50))
                        .await
                        .unwrap()
                );
            }
            self.inner.put_if_absent(name, bytes).await
        }
        async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get(name).await
        }
        async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
            self.inner.list(prefix, start_after, limit).await
        }
    }
    let kek = kek();
    for (other, expected) in [(false, InitLocations::Same), (true, InitLocations::Differ)] {
        let inner = MemRecords::new();
        let store = Racing {
            inner: &inner,
            kek: &kek,
            theirs: Cell::new(true),
            other,
        };
        assert_eq!(
            init_locations(&store, &kek, &mut TestRng(1)).await.unwrap(),
            expected
        );
        assert_eq!(inner.names().len(), 1);
    }
}

/// A head that does not open fails the call and writes nothing: a record
/// under a newer KEK version this Worker does not hold yet is the
/// not-held error (no page); a damaged record, or a version this Worker
/// should hold, is not.
#[tokio::test(flavor = "current_thread")]
async fn a_head_that_does_not_open_fails_and_tells_not_held_from_damage() {
    // A newer deploy wrote seq 1 under KEK version 2.
    let newer = TestKek::with_versions(2, &[(1, kek_bytes(1)), (2, kek_bytes(2))]);
    let store = MemRecords::new();
    assert_eq!(
        init_locations(&store, &newer, &mut TestRng(1))
            .await
            .unwrap(),
        InitLocations::Written
    );
    let kek = kek();
    let puts = store.puts();
    let err = init_locations(&store, &kek, &mut TestRng(2))
        .await
        .unwrap_err();
    assert!(is_kek_not_held(&err), "{err:?}");
    assert!(!is_locations_damage(&err));
    let err = read_locations(&store, &kek, 0).await.unwrap_err();
    assert!(is_kek_not_held(&err));
    assert_eq!(store.puts(), puts);
    // The newer Worker reads it.
    assert!(read_locations(&store, &newer, 0).await.unwrap().is_some());

    // A version not newer than this Worker's active one, which it does
    // not hold: damage.
    let ahead = TestKek::with_versions(3, &[(3, kek_bytes(3))]);
    let err = read_locations(&store, &ahead, 0).await.unwrap_err();
    assert!(!is_kek_not_held(&err), "{err:?}");
    assert!(is_locations_damage(&err), "{err:?}");

    // Damage: a flipped byte in the record.
    let name = locations_chain().name(1);
    let store = MemRecords::new();
    init_locations(&store, &kek, &mut TestRng(3)).await.unwrap();
    let mut bytes = store.raw(&name).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    store.plant(&name, bytes);
    let puts = store.puts();
    let err = init_locations(&store, &kek, &mut TestRng(4))
        .await
        .unwrap_err();
    assert!(!is_kek_not_held(&err), "{err:?}");
    assert!(is_locations_damage(&err), "{err:?}");
    assert_eq!(store.puts(), puts);

    // A store outage is neither: `503` with no page.
    let store = MemRecords::new();
    store.refuse_lists(true);
    let err = init_locations(&store, &kek, &mut TestRng(5))
        .await
        .unwrap_err();
    assert!(
        !is_kek_not_held(&err) && !is_locations_damage(&err),
        "{err:?}"
    );
    assert!(store.names().is_empty());
}
