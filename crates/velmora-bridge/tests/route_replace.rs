//! The route record's conditional replace (`replace_route`), as the owner
//! move and its undo call it, and the `RecordStore` ETag methods under it.

use std::cell::{Cell, RefCell};

use futures_util::future::join_all;
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::TenantId;
use velmora_bridge::keys::record::SubjectKind;
use velmora_bridge::keys::routes::{
    put_route, read_route, replace_route, route_name, Route, RoutePut, REPLACE_TRIES,
};
use velmora_bridge::records::{MemRecords, RecordStore, Tagged};
use velmora_bridge::testkit::TestKek;
use velmora_bridge::Result;

const KEY: &str = "AKVL0001";

struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

impl TestRng {
    fn new(label: &str) -> Self {
        Self {
            seed: Sha256::digest(label.as_bytes()).into(),
            counter: 0,
        }
    }
}

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update(self.seed);
            hash.update(self.counter.to_be_bytes());
            self.counter += 1;
            block.copy_from_slice(&hash.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, Sha256::digest(b"route replace kek").into())])
}

fn tenant(n: u8) -> String {
    let t = format!("t_00000000000000{n:02x}");
    TenantId::parse(&t).unwrap();
    t
}

/// Tenant 0, as a route record names it.
const ZERO: &str = "t_0000000000000000";

fn route(t: &str, kind: SubjectKind, at: u64) -> Option<Route> {
    Some(Route {
        access_key_id: KEY.into(),
        tenant: t.to_string(),
        kind,
        created_at: at,
    })
}

/// A sealed route record of `akid` naming `t`. A key is never created
/// with a route to tenant 0, so its record is made as the undo makes it:
/// put to a managed tenant, then replaced.
async fn sealed(kek: &TestKek, t: &str, akid: &str, kind: SubjectKind, label: &str) -> Vec<u8> {
    let scratch = MemRecords::new();
    let mut rng = TestRng::new(label);
    let first = TenantId::parse(if t == ZERO { "t_00000000000000fe" } else { t }).unwrap();
    assert_eq!(
        put_route(&scratch, kek, &first, akid, kind, 100, &mut rng)
            .await
            .unwrap(),
        RoutePut::Ours
    );
    if t == ZERO {
        assert!(
            replace_route(&scratch, kek, akid, first.as_str(), ZERO, kind, &mut rng)
                .await
                .unwrap()
        );
    }
    scratch.raw(&route_name(akid)).unwrap()
}

async fn put(store: &MemRecords, kek: &TestKek, t: &str, akid: &str, kind: SubjectKind) {
    let bytes = sealed(kek, t, akid, kind, &format!("put {t} {akid}")).await;
    store.plant(&route_name(akid), bytes);
}

async fn replace<S: RecordStore>(
    store: &S,
    kek: &TestKek,
    from: &str,
    to: &str,
    kind: SubjectKind,
) -> Result<bool> {
    let mut rng = TestRng::new(&format!("replace {from} {to}"));
    replace_route(store, kek, KEY, from, to, kind, &mut rng).await
}

#[tokio::test(flavor = "current_thread")]
async fn the_move_and_its_undo_replace_the_route_and_keep_created_at() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    let puts = store.puts();

    assert!(replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .unwrap());
    assert_eq!(
        read_route(&store, &kek, KEY).await.unwrap(),
        route(&owner, SubjectKind::S3, 100)
    );
    assert_eq!(store.replaces(), 1);

    // A rerun of the same step finds it done and writes nothing.
    let before = store.raw(&route_name(KEY));
    assert!(replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .unwrap());
    assert_eq!(store.replaces(), 1);
    assert_eq!(store.raw(&route_name(KEY)), before);

    // The undo puts it back.
    assert!(replace(&store, &kek, &owner, ZERO, SubjectKind::S3)
        .await
        .unwrap());
    assert_eq!(
        read_route(&store, &kek, KEY).await.unwrap(),
        route(ZERO, SubjectKind::S3, 100)
    );
    assert_eq!(store.replaces(), 2);
    assert_eq!(store.puts(), puts, "a replace never puts");
}

#[tokio::test(flavor = "current_thread")]
async fn a_route_of_a_third_tenant_or_no_route_is_left_alone() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    assert!(!replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .unwrap());
    assert!(store.names().is_empty(), "a replace never creates a route");
    assert_eq!(store.replaces(), 0);

    put(&store, &kek, &tenant(2), KEY, SubjectKind::S3).await;
    let before = store.raw(&route_name(KEY));
    assert!(!replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .unwrap());
    assert_eq!(store.raw(&route_name(KEY)), before);
    assert_eq!(store.replaces(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_route_that_names_the_target_with_another_kind_takes_the_new_kind() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, &owner, KEY, SubjectKind::S3).await;
    assert!(
        replace(&store, &kek, ZERO, &owner, SubjectKind::AppPassword)
            .await
            .unwrap()
    );
    assert_eq!(
        read_route(&store, &kek, KEY).await.unwrap(),
        route(&owner, SubjectKind::AppPassword, 100)
    );
    assert_eq!(store.replaces(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_lost_answer_is_read_back() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    store.lose_replace_answers(1);
    assert!(replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .unwrap());
    assert_eq!(
        read_route(&store, &kek, KEY).await.unwrap(),
        route(&owner, SubjectKind::S3, 100)
    );
    assert_eq!(store.replaces(), 1, "the read-back found it stored");
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_replace_is_an_error_and_changes_nothing() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    let before = store.raw(&route_name(KEY));
    store.refuse("m/kr/");
    assert!(replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .is_err());
    assert_eq!(store.raw(&route_name(KEY)), before);
    assert_eq!(store.replaces(), u64::from(REPLACE_TRIES));
    store.allow("m/kr/");
    assert!(replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn a_record_that_does_not_open_is_an_error_and_is_not_overwritten() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    // Another key id's record under this name.
    put(&store, &kek, ZERO, "AKVL0002", SubjectKind::S3).await;
    let other = store.raw(&route_name("AKVL0002")).unwrap();
    store.plant(&route_name(KEY), other.clone());
    assert!(replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .is_err());
    assert_eq!(store.raw(&route_name(KEY)), Some(other));

    let mut torn = store.raw(&route_name("AKVL0002")).unwrap();
    let last = torn.len() - 1;
    torn[last] ^= 1;
    store.plant(&route_name(KEY), torn.clone());
    assert!(replace(&store, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .is_err());
    assert_eq!(store.raw(&route_name(KEY)), Some(torn));
    assert_eq!(store.replaces(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn bad_input_is_refused_before_any_read() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    let mut rng = TestRng::new("bad");
    for (akid, kind) in [
        (KEY, SubjectKind::Principal),
        ("", SubjectKind::S3),
        ("AK/../x", SubjectKind::S3),
    ] {
        assert!(
            replace_route(&store, &kek, akid, ZERO, &owner, kind, &mut rng)
                .await
                .is_err()
        );
    }
    // Only the move and its undo replace a route: tenant 0 on exactly one
    // side, and no tenant id that a route cannot name.
    put(&store, &kek, &owner, "AKVL0002", SubjectKind::S3).await;
    let before = store.raw(&route_name("AKVL0002"));
    for (from, to) in [
        (owner.as_str(), tenant(2).as_str()),
        (ZERO, ZERO),
        (owner.as_str(), owner.as_str()),
        ("t_zz", ZERO),
        (ZERO, "t_0000000000000001x"),
    ] {
        assert!(replace_route(
            &store,
            &kek,
            "AKVL0002",
            from,
            to,
            SubjectKind::S3,
            &mut rng
        )
        .await
        .is_err());
    }
    assert_eq!(store.raw(&route_name("AKVL0002")), before);
    assert_eq!(store.replaces(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_key_create_never_takes_a_tenant_zero_route() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    let before = store.raw(&route_name(KEY));
    let mut rng = TestRng::new("create");
    assert_eq!(
        put_route(
            &store,
            &kek,
            &TenantId::parse(&owner).unwrap(),
            KEY,
            SubjectKind::S3,
            500,
            &mut rng
        )
        .await
        .unwrap(),
        RoutePut::Taken
    );
    assert_eq!(store.raw(&route_name(KEY)), before);
    assert!(
        TenantId::parse(ZERO).is_err(),
        "no key is created on tenant 0's route"
    );
}

/// A store where every replace but the last loses to a fresh tenant-0
/// record written just before it, and the last one stores and loses its
/// answer.
struct LoseLast<'a> {
    inner: &'a MemRecords,
    flips: RefCell<Vec<Vec<u8>>>,
    calls: Cell<u32>,
}

impl RecordStore for LoseLast<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
    async fn get_tagged(&self, name: &str) -> Result<Option<Tagged>> {
        self.inner.get_tagged(name).await
    }
    async fn replace_if_match(&self, name: &str, etag: &str, bytes: Vec<u8>) -> Result<bool> {
        self.calls.set(self.calls.get() + 1);
        let next = self.flips.borrow_mut().pop();
        if let Some(flip) = next {
            self.inner.plant(name, flip);
            return self.inner.replace_if_match(name, etag, bytes).await;
        }
        assert!(self.inner.replace_if_match(name, etag, bytes).await?);
        Err(velmora_bridge::BridgeError::Blob("answer lost".into()))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_lost_answer_on_the_last_try_is_read_back() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    let mut flips = Vec::new();
    for i in 1..REPLACE_TRIES {
        flips.push(sealed_route(&kek, ZERO, SubjectKind::S3, &format!("last {i}")).await);
    }
    let lose = LoseLast {
        inner: &store,
        flips: RefCell::new(flips),
        calls: Cell::new(0),
    };
    assert!(replace(&lose, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .unwrap());
    assert_eq!(lose.calls.get(), REPLACE_TRIES);
    assert_eq!(
        read_route(&store, &kek, KEY).await.unwrap(),
        route(&owner, SubjectKind::S3, 100)
    );
}

/// A store whose replace lets another writer in first: before the first
/// `writes` replaces it runs `other` (a replace of its own) and then
/// forwards the call with the caller's (now stale) ETag.
struct Racing<'a> {
    inner: &'a MemRecords,
    other: RefCell<Vec<Vec<u8>>>,
}

impl RecordStore for Racing<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
    async fn get_tagged(&self, name: &str) -> Result<Option<Tagged>> {
        self.inner.get_tagged(name).await
    }
    async fn replace_if_match(&self, name: &str, etag: &str, bytes: Vec<u8>) -> Result<bool> {
        let next = self.other.borrow_mut().pop();
        if let Some(theirs) = next {
            let now = self.inner.get_tagged(name).await?.unwrap();
            assert!(self.inner.replace_if_match(name, &now.etag, theirs).await?);
        }
        self.inner.replace_if_match(name, etag, bytes).await
    }
}

async fn sealed_route(kek: &TestKek, t: &str, kind: SubjectKind, label: &str) -> Vec<u8> {
    sealed(kek, t, KEY, kind, label).await
}

#[tokio::test(flavor = "current_thread")]
async fn a_newer_route_written_in_between_is_never_overwritten() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, &owner, KEY, SubjectKind::S3).await;
    // The give-up reads the owner's route; a later window puts it to a
    // third tenant before the give-up's replace lands.
    let newer = sealed_route(&kek, &tenant(3), SubjectKind::S3, "newer").await;
    let racing = Racing {
        inner: &store,
        other: RefCell::new(vec![newer.clone()]),
    };
    assert!(!replace(&racing, &kek, &owner, ZERO, SubjectKind::S3)
        .await
        .unwrap());
    assert_eq!(store.raw(&route_name(KEY)), Some(newer));
}

#[tokio::test(flavor = "current_thread")]
async fn a_concurrent_rerun_that_wins_counts_as_done() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    let theirs = sealed_route(&kek, &owner, SubjectKind::S3, "theirs").await;
    let racing = Racing {
        inner: &store,
        other: RefCell::new(vec![theirs.clone()]),
    };
    assert!(replace(&racing, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .unwrap());
    assert_eq!(
        store.raw(&route_name(KEY)),
        Some(theirs),
        "the winner's record stays"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_route_that_keeps_changing_is_an_error_after_the_tries() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    // Every try loses to a fresh tenant-0 record (new bytes, new ETag).
    let mut flips = Vec::new();
    for i in 0..REPLACE_TRIES {
        flips.push(sealed_route(&kek, ZERO, SubjectKind::S3, &format!("flip {i}")).await);
    }
    let racing = Racing {
        inner: &store,
        other: RefCell::new(flips),
    };
    assert!(replace(&racing, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .is_err());
    assert_eq!(
        read_route(&store, &kek, KEY).await.unwrap(),
        route(ZERO, SubjectKind::S3, 100)
    );
}

/// A store that yields between every call, so concurrent replaces all
/// read the same ETag before any of them writes.
struct Yielding<'a> {
    inner: &'a MemRecords,
}

impl RecordStore for Yielding<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
    async fn get_tagged(&self, name: &str) -> Result<Option<Tagged>> {
        let got = self.inner.get_tagged(name).await;
        tokio::task::yield_now().await;
        got
    }
    async fn replace_if_match(&self, name: &str, etag: &str, bytes: Vec<u8>) -> Result<bool> {
        tokio::task::yield_now().await;
        self.inner.replace_if_match(name, etag, bytes).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn of_sixteen_concurrent_replaces_one_wins() {
    let (store, kek) = (MemRecords::new(), kek());
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    let yielding = Yielding { inner: &store };
    let targets: Vec<String> = (1..=16).map(tenant).collect();
    let answers = join_all(
        targets
            .iter()
            .map(|t| replace(&yielding, &kek, ZERO, t, SubjectKind::S3)),
    )
    .await;
    let won: Vec<&String> = answers
        .iter()
        .zip(&targets)
        .filter(|(a, _)| *a.as_ref().unwrap())
        .map(|(_, t)| t)
        .collect();
    assert_eq!(won.len(), 1, "answers: {answers:?}");
    assert_eq!(
        read_route(&store, &kek, KEY).await.unwrap(),
        route(won[0], SubjectKind::S3, 100)
    );
    assert_eq!(store.replaces(), 16);
}

/// A store with only the required methods.
struct PutOnly<'a> {
    inner: &'a MemRecords,
    calls: Cell<u32>,
}

impl RecordStore for PutOnly<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.calls.set(self.calls.get() + 1);
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_store_without_the_etag_methods_refuses_the_replace() {
    let (store, kek, owner) = (MemRecords::new(), kek(), tenant(1));
    put(&store, &kek, ZERO, KEY, SubjectKind::S3).await;
    let before = store.raw(&route_name(KEY));
    let bare = PutOnly {
        inner: &store,
        calls: Cell::new(0),
    };
    assert!(replace(&bare, &kek, ZERO, &owner, SubjectKind::S3)
        .await
        .is_err());
    assert!(bare
        .replace_if_match(&route_name(KEY), "x", vec![1])
        .await
        .is_err());
    assert_eq!(store.raw(&route_name(KEY)), before);
    assert_eq!(store.replaces(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn mem_records_replace_only_on_the_etag_it_holds() {
    let store = MemRecords::new();
    assert_eq!(store.get_tagged("a").await.unwrap(), None);
    assert!(!store.replace_if_match("a", "x", vec![1]).await.unwrap());
    assert!(store.raw("a").is_none());

    assert!(store.put_if_absent("a", vec![1]).await.unwrap());
    let one = store.get_tagged("a").await.unwrap().unwrap();
    assert_eq!(one.bytes, vec![1]);
    assert!(!store.replace_if_match("a", "x", vec![2]).await.unwrap());
    assert_eq!(store.raw("a"), Some(vec![1]));

    // Forwarded through a reference, not the refusing defaults.
    let by_ref = &store;
    assert!(
        <&MemRecords as RecordStore>::replace_if_match(&by_ref, "a", &one.etag, vec![2])
            .await
            .unwrap()
    );
    let two = <&MemRecords as RecordStore>::get_tagged(&by_ref, "a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(two.bytes, vec![2]);
    assert_ne!(two.etag, one.etag);
    assert!(!store
        .replace_if_match("a", &one.etag, vec![3])
        .await
        .unwrap());
    assert_eq!(store.raw("a"), Some(vec![2]));
}
