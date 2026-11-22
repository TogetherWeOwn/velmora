//! The first key-location record (AM-70): `init_locations` probes the two
//! key buckets before it writes `m/kl/` seq 1, answers a head that names
//! the set as `Same` and any other head as `Differ`, and writes nothing
//! when the two bindings are one bucket.

use std::cell::{Cell, RefCell};

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::keys::locations::{
    init_locations, read_locations, two_in_account, write_locations, InitLocations, LocationStatus,
    ProbeDelete, ERR_PROBE_READBACK, PROBE_PREFIX,
};
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::testkit::TestKek;
use velmora_bridge::{BridgeError, Result};

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

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, Sha256::digest(b"kl kek").into())])
}

/// A key bucket binding over a fake bucket, with a delete, and switches
/// to fail one step.
struct Binding<'a> {
    bucket: &'a MemRecords,
    deletes: RefCell<Vec<String>>,
    /// `get` answers other bytes than were put.
    garbles: Cell<bool>,
    /// `delete` fails.
    delete_down: Cell<bool>,
}

impl<'a> Binding<'a> {
    fn new(bucket: &'a MemRecords) -> Self {
        Binding {
            bucket,
            deletes: RefCell::new(Vec::new()),
            garbles: Cell::new(false),
            delete_down: Cell::new(false),
        }
    }
}

impl RecordStore for Binding<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        self.bucket.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let got = self.bucket.get(name).await?;
        Ok(match self.garbles.get() {
            true => got.map(|mut b| {
                b[0] ^= 1;
                b
            }),
            false => got,
        })
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.bucket.list(prefix, start_after, limit).await
    }
}

impl ProbeDelete for Binding<'_> {
    async fn delete(&self, name: &str) -> Result<()> {
        if self.delete_down.get() {
            return Err(BridgeError::Blob("fake: delete down".into()));
        }
        self.deletes.borrow_mut().push(name.to_owned());
        self.bucket.lose(name);
        Ok(())
    }
}

/// Two buckets, two bindings, the control store and the KEK.
struct World {
    store: MemRecords,
    a: MemRecords,
    b: MemRecords,
    kek: TestKek,
}

impl World {
    fn new() -> Self {
        World {
            store: MemRecords::new(),
            a: MemRecords::new(),
            b: MemRecords::new(),
            kek: kek(),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn two_distinct_buckets_get_seq_one_and_no_probe_is_left() {
    let w = World::new();
    let (a, b) = (Binding::new(&w.a), Binding::new(&w.b));
    assert_eq!(
        init_locations(&w.store, &w.kek, &a, &b, &mut TestRng(1))
            .await
            .unwrap(),
        InitLocations::Written
    );
    let head = read_locations(&w.store, &w.kek, 0).await.unwrap().unwrap();
    assert_eq!(head, two_in_account());
    assert_eq!(head.arbiter().name, "KEYS_A");
    // One probe per bucket, each deleted through its own binding, and
    // nothing left in either bucket.
    for (binding, bucket) in [(&a, &w.a), (&b, &w.b)] {
        let deletes = binding.deletes.borrow();
        assert_eq!(deletes.len(), 1);
        assert!(deletes[0].starts_with(PROBE_PREFIX));
        assert_eq!(deletes[0].len(), PROBE_PREFIX.len() + 32);
        assert!(bucket.names().is_empty());
    }
    assert_ne!(a.deletes.borrow()[0], b.deletes.borrow()[0]);
    // The key buckets got no record; the control store got one.
    assert_eq!(w.store.names().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_head_that_names_the_set_is_same_and_another_is_differ_without_a_probe() {
    let w = World::new();
    let (a, b) = (Binding::new(&w.a), Binding::new(&w.b));
    init_locations(&w.store, &w.kek, &a, &b, &mut TestRng(1))
        .await
        .unwrap();
    let puts = w.store.puts();
    let (a2, b2) = (Binding::new(&w.a), Binding::new(&w.b));
    assert_eq!(
        init_locations(&w.store, &w.kek, &a2, &b2, &mut TestRng(2))
            .await
            .unwrap(),
        InitLocations::Same
    );
    assert_eq!(w.store.puts(), puts);
    assert!(a2.deletes.borrow().is_empty() && b2.deletes.borrow().is_empty());
    assert_eq!(w.a.puts() + w.b.puts(), 2, "no probe on a re-run");

    // Another head: seq 1 with KEYS_B only proposed.
    let w = World::new();
    let mut other = two_in_account();
    other.locations[1].status = LocationStatus::Proposed;
    assert!(write_locations(&w.store, &w.kek, &other, &mut TestRng(3))
        .await
        .unwrap());
    let (a, b) = (Binding::new(&w.a), Binding::new(&w.b));
    let puts = w.store.puts();
    assert_eq!(
        init_locations(&w.store, &w.kek, &a, &b, &mut TestRng(4))
            .await
            .unwrap(),
        InitLocations::Differ
    );
    assert_eq!(w.store.puts(), puts);
    assert_eq!(w.a.puts() + w.b.puts(), 0);
    assert_eq!(
        read_locations(&w.store, &w.kek, 0).await.unwrap().unwrap(),
        other
    );
}

/// Both bindings name one bucket: each probe is visible through the
/// other binding, so nothing is written, and both probes are deleted.
#[tokio::test(flavor = "current_thread")]
async fn two_bindings_of_one_bucket_write_nothing() {
    let w = World::new();
    let (a, b) = (Binding::new(&w.a), Binding::new(&w.a));
    assert_eq!(
        init_locations(&w.store, &w.kek, &a, &b, &mut TestRng(1))
            .await
            .unwrap(),
        InitLocations::NotDistinct
    );
    assert!(read_locations(&w.store, &w.kek, 0).await.unwrap().is_none());
    assert!(w.store.names().is_empty());
    assert!(w.a.names().is_empty(), "both probes deleted");
    assert_eq!(a.deletes.borrow().len(), 1);
    assert_eq!(b.deletes.borrow().len(), 1);
}

/// A probe that does not read back, or a delete that fails, is an error
/// with nothing written; a re-run with the stores well writes seq 1.
#[tokio::test(flavor = "current_thread")]
async fn a_probe_that_fails_writes_nothing_and_a_re_run_succeeds() {
    let w = World::new();
    let (a, b) = (Binding::new(&w.a), Binding::new(&w.b));
    b.garbles.set(true);
    let err = init_locations(&w.store, &w.kek, &a, &b, &mut TestRng(1))
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), ERR_PROBE_READBACK.to_string());
    assert!(w.store.names().is_empty());
    // Both probes went even so.
    assert!(w.a.names().is_empty() && w.b.names().is_empty());

    let (a, b) = (Binding::new(&w.a), Binding::new(&w.b));
    a.delete_down.set(true);
    assert!(init_locations(&w.store, &w.kek, &a, &b, &mut TestRng(2))
        .await
        .is_err());
    assert!(w.store.names().is_empty());
    assert_eq!(w.a.names().len(), 1, "the probe whose delete failed");
    assert!(w.b.names().is_empty());

    let (a, b) = (Binding::new(&w.a), Binding::new(&w.b));
    assert_eq!(
        init_locations(&w.store, &w.kek, &a, &b, &mut TestRng(3))
            .await
            .unwrap(),
        InitLocations::Written
    );
    // The earlier probe stays (outside every tenant's key directory); the
    // new ones are gone.
    assert_eq!(w.a.names().len(), 1);
    assert!(w.a.names()[0].starts_with(PROBE_PREFIX));
}

/// A put of seq 1 lost to another run's: the head is read again and
/// answered from.
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
    for (other, expected) in [(false, InitLocations::Same), (true, InitLocations::Differ)] {
        let w = World::new();
        let store = Racing {
            inner: &w.store,
            kek: &w.kek,
            theirs: Cell::new(true),
            other,
        };
        let (a, b) = (Binding::new(&w.a), Binding::new(&w.b));
        assert_eq!(
            init_locations(&store, &w.kek, &a, &b, &mut TestRng(1))
                .await
                .unwrap(),
            expected
        );
        assert_eq!(w.store.names().len(), 1);
    }
}
