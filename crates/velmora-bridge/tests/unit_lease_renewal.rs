//! The renewal proof of a unit's freshness lease and the stamp of a unit
//! (ADR-TENANCY §2.4 rule 12, §8.5; SEC-6, RD-12).
//!
//! The proof runs against an in-memory safety bucket whose every call
//! takes 100 ms of the test clock, so the time the proof starts from can
//! be told from the times of its reads.

#![allow(async_fn_in_trait)]

use std::cell::{Cell, RefCell};

use velmora_bridge::recovery::Unpublished;
use velmora_bridge::stamp::{stamp_key, Stamp, StampLedger, StampRow, ERR_ROLLED_BACK};
use velmora_bridge::testkit::{FixedClock, MemBlobStore};
use velmora_bridge::unit_lease::lease::{FreshLease, LeaseRules};
use velmora_bridge::unit_lease::renewal::{prove, revocations, ChainNames, Proof, UnitView};
use velmora_bridge::unit_lease::UnitStampId;
use velmora_bridge::*;

const T0: UnixMs = UnixMs(1_800_000_000_000);
const TENANT: &str = "t_0123456789abcdef";
const OTHER: &str = "t_fedcba9876543210";
/// What one call of the bucket takes.
const CALL_MS: i64 = 100;

/// The layout the tests assume for the chains; the real one belongs to
/// the lanes that write them.
struct Names;

impl ChainNames for Names {
    fn tenant_record(&self, tenant: &str, seq: u64) -> String {
        format!("m/t/{tenant}/{seq:020}")
    }
    fn key_record(&self, tenant: &str, seq: u64) -> String {
        format!("m/k/{tenant}/{seq:020}")
    }
    fn revocation_dir(&self, tenant: &str) -> String {
        format!("m/rk/{tenant}/")
    }
}

/// A bucket over which every call takes [`CALL_MS`] of `clock`, and
/// which records when each call began.
struct SlowBucket<'a> {
    inner: MemBlobStore,
    clock: &'a FixedClock,
    calls: RefCell<Vec<(&'static str, UnixMs)>>,
}

impl<'a> SlowBucket<'a> {
    fn new(clock: &'a FixedClock) -> Self {
        SlowBucket {
            inner: MemBlobStore::new(),
            clock,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn enter(&self, what: &'static str) {
        self.calls.borrow_mut().push((what, self.clock.now()));
        self.clock.advance_ms(CALL_MS);
    }

    async fn plant(&self, key: &str) {
        use sha2::{Digest, Sha256};
        let sha: [u8; 32] = Sha256::digest(b"x").into();
        let bucket = BucketId::new("-");
        let extent = ExtentId::new("planted");
        let meta = BlobMeta {
            bucket: &bucket,
            extent: &extent,
            cipher_sha256: &sha,
        };
        self.inner.put(key, b"x".to_vec(), &meta).await.unwrap();
    }

    fn count(&self, what: &str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|(w, _)| *w == what)
            .count()
    }

    fn reset(&self) {
        self.calls.borrow_mut().clear();
    }
}

impl BlobStore for SlowBucket<'_> {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.enter("put");
        self.inner.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.enter("get");
        self.inner.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.enter("head");
        self.inner.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.enter("delete");
        self.inner.delete(key).await
    }
    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.inner.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.enter("list");
        self.inner.list(prefix, start_after, limit).await
    }
}

/// A unit's stamp counter, with the rules of the `rollback_stamp` row:
/// compare-and-set moves, a recorded rollback, and the id check.
struct UnitLedger {
    id: String,
    counter: Cell<Option<u64>>,
    rolled_back: Cell<bool>,
}

impl UnitLedger {
    fn new(id: &UnitStampId) -> Self {
        UnitLedger {
            id: id.as_str().to_string(),
            counter: Cell::new(None),
            rolled_back: Cell::new(false),
        }
    }

    fn check(&self, id: &str) -> Result<()> {
        if id == self.id {
            Ok(())
        } else {
            Err(velmora_bridge::stamp::ERR_CATALOGUE_ID)
        }
    }
}

impl StampLedger for &UnitLedger {
    async fn stamp(&self, id: &str) -> Result<StampRow> {
        self.check(id)?;
        Ok(StampRow {
            counter: self.counter.get(),
            rolled_back: self.rolled_back.get(),
        })
    }
    async fn stamp_advance(&self, from: Option<u64>, id: &str) -> Result<bool> {
        self.check(id)?;
        if self.rolled_back.get() || self.counter.get() != from {
            return Ok(false);
        }
        self.counter.set(Some(from.map_or(1, |c| c + 1)));
        Ok(true)
    }
    async fn stamp_rolled_back(&self, seen: Option<u64>, _now: UnixMs, id: &str) -> Result<bool> {
        self.check(id)?;
        if self.rolled_back.get() || self.counter.get() != seen {
            return Ok(false);
        }
        self.rolled_back.set(true);
        Ok(true)
    }
}

fn unit_id(unit: u32) -> UnitStampId {
    UnitStampId::new(TENANT, unit).unwrap()
}

fn view(id: &UnitStampId, state_seq: u64, keys_seq: u64, revoked: u64) -> UnitView<'_> {
    UnitView {
        stamp_id: id,
        state_seq,
        keys_seq,
        stamp_counter: None,
        revoked,
    }
}

/// Plants chain records 1..=n of both chains of `tenant`.
async fn chains(bucket: &SlowBucket<'_>, tenant: &str, state: u64, keys: u64) {
    for seq in 1..=state {
        bucket.plant(&Names.tenant_record(tenant, seq)).await;
    }
    for seq in 1..=keys {
        bucket.plant(&Names.key_record(tenant, seq)).await;
    }
}

/// A unit at the head of both chains, with no stamp object and every
/// revocation, is proven fresh with two HEADs and two lists.
#[tokio::test(flavor = "current_thread")]
async fn a_unit_at_the_head_is_proven_with_two_heads_and_two_lists() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 3, 5).await;
    bucket.plant(&format!("m/rk/{TENANT}/AKIAREVOKED1")).await;
    let id = unit_id(0);

    let proof = prove(&bucket, &clock, &Names, &view(&id, 3, 5, 1))
        .await
        .unwrap();

    assert_eq!(
        proof,
        Proof::Fresh {
            proof_start: T0,
            revocations: Vec::new(),
        }
    );
    assert_eq!(bucket.count("head"), 2);
    assert_eq!(bucket.count("list"), 2);
    assert_eq!(bucket.calls.borrow().len(), 4, "no other call");
}

/// RD-12: the proof starts before its first read, and a renewal from it
/// holds the unit fresh until `proof_start + T`, not until the call's
/// arrival plus T, however long the proof took.
#[tokio::test(flavor = "current_thread")]
async fn the_lease_runs_from_the_start_of_the_proof() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 1, 1).await;
    let id = unit_id(0);

    let Proof::Fresh { proof_start, .. } = prove(&bucket, &clock, &Names, &view(&id, 1, 1, 0))
        .await
        .unwrap()
    else {
        panic!("not proven");
    };
    let first_read = bucket.calls.borrow()[0].1;
    assert!(proof_start <= first_read, "taken before the first read");
    assert_eq!(proof_start, T0);

    // The call to the unit stalls for 20 s after the proof.
    clock.advance_ms(20_000);
    let mut lease = FreshLease::expired();
    let rules = LeaseRules::DEFAULT;
    let until = lease.renew(proof_start, clock.now(), &rules).unwrap();
    assert_eq!(until, UnixMs(T0.0 + rules.term_ms));
    assert!(until.0 < clock.now().0 + rules.term_ms);

    // A stall past the bound: the unit refuses, the Worker proves again.
    let mut lease = FreshLease::expired();
    clock.advance_ms(rules.max_behind_ms);
    assert!(lease.renew(proof_start, clock.now(), &rules).is_err());
    assert_eq!(lease.fresh_until(), None);
}

/// A newer record in either chain asks for `sync` first; the revocations
/// are not listed then.
#[tokio::test(flavor = "current_thread")]
async fn a_newer_record_asks_for_sync_first() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 4, 2).await;
    let id = unit_id(0);

    let proof = prove(&bucket, &clock, &Names, &view(&id, 3, 2, 0))
        .await
        .unwrap();
    assert_eq!(
        proof,
        Proof::SyncNeeded {
            tenant_chain: true,
            key_chain: false,
        }
    );

    bucket.reset();
    let proof = prove(&bucket, &clock, &Names, &view(&id, 4, 1, 0))
        .await
        .unwrap();
    assert_eq!(
        proof,
        Proof::SyncNeeded {
            tenant_chain: false,
            key_chain: true,
        }
    );
    assert_eq!(bucket.count("list"), 1, "only the stamp list");
}

/// Another tenant's records do not move this tenant's heads.
#[tokio::test(flavor = "current_thread")]
async fn another_tenants_chains_are_not_read() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 1, 1).await;
    chains(&bucket, OTHER, 9, 9).await;
    bucket.plant(&format!("m/rk/{OTHER}/AKIAOTHER")).await;
    let id = unit_id(0);

    let proof = prove(&bucket, &clock, &Names, &view(&id, 1, 1, 0))
        .await
        .unwrap();
    assert!(matches!(proof, Proof::Fresh { ref revocations, .. } if revocations.is_empty()));
}

/// SEC-6: a revocation that is in `m/rk/` only, in a tenant with two
/// units where the second unit never saw the closing call, is handed to
/// the renewal of that second unit; the root unit, which saw it, gets
/// nothing to apply.
#[tokio::test(flavor = "current_thread")]
async fn a_revocation_only_in_the_bucket_is_applied_at_renewal_of_every_unit() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 2, 7).await;
    bucket.plant(&format!("m/rk/{TENANT}/AKIAFIRST")).await;
    // The revoke crashed after its `m/rk/` put: no chain record, and the
    // second unit never got the call.
    bucket.plant(&format!("m/rk/{TENANT}/AKIASECOND")).await;
    let root = unit_id(0);
    let second = unit_id(1);

    let root_proof = prove(&bucket, &clock, &Names, &view(&root, 2, 7, 2))
        .await
        .unwrap();
    assert!(matches!(root_proof, Proof::Fresh { ref revocations, .. } if revocations.is_empty()));

    let second_proof = prove(&bucket, &clock, &Names, &view(&second, 2, 7, 1))
        .await
        .unwrap();
    assert_eq!(
        second_proof,
        Proof::Fresh {
            proof_start: clock.now().0.checked_sub(4 * CALL_MS).map(UnixMs).unwrap(),
            revocations: vec!["AKIAFIRST".to_string(), "AKIASECOND".to_string()],
        }
    );
}

/// A unit that holds more revocations than the put-only directory lists
/// is not renewed.
#[tokio::test(flavor = "current_thread")]
async fn a_unit_with_more_revocations_than_the_bucket_is_not_renewed() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 1, 1).await;
    bucket.plant(&format!("m/rk/{TENANT}/AKIAONE")).await;
    let id = unit_id(0);

    let proof = prove(&bucket, &clock, &Names, &view(&id, 1, 1, 2))
        .await
        .unwrap();
    assert_eq!(proof, Proof::RevocationsShort { listed: 1, held: 2 });
}

/// The revocation list is read in pages of 1,000 and counts all of them.
#[tokio::test(flavor = "current_thread")]
async fn revocations_are_listed_in_pages_of_a_thousand() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    for n in 0..2_500 {
        bucket.plant(&format!("m/rk/{TENANT}/AKIA{n:08}")).await;
    }
    let ids = revocations(&bucket, &Names, TENANT).await.unwrap();
    assert_eq!(ids.len(), 2_500);
    assert_eq!(bucket.count("list"), 3);
    assert!(ids.windows(2).all(|w| w[0] < w[1]));

    // Exactly one page: one more list call finds the end.
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    for n in 0..1_000 {
        bucket.plant(&format!("m/rk/{TENANT}/AKIA{n:08}")).await;
    }
    assert_eq!(
        revocations(&bucket, &Names, TENANT).await.unwrap().len(),
        1_000
    );
    assert_eq!(bucket.count("list"), 2);
}

/// A key below the revocation directory that is not one access key id
/// fails the proof; a directory that does not name the tenant is
/// refused before any list.
#[tokio::test(flavor = "current_thread")]
async fn malformed_revocation_names_fail_closed() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    bucket.plant(&format!("m/rk/{TENANT}/nested/AKIA")).await;
    assert!(revocations(&bucket, &Names, TENANT).await.is_err());

    struct Flat;
    impl ChainNames for Flat {
        fn tenant_record(&self, t: &str, s: u64) -> String {
            Names.tenant_record(t, s)
        }
        fn key_record(&self, t: &str, s: u64) -> String {
            Names.key_record(t, s)
        }
        fn revocation_dir(&self, _: &str) -> String {
            // Tenant 0's flat directory: every tenant's ids are under it.
            "m/rk/".to_string()
        }
    }
    let bucket = SlowBucket::new(&clock);
    assert!(revocations(&bucket, &Flat, TENANT).await.is_err());
    assert_eq!(bucket.count("list"), 0);
}

/// The stamp of a unit runs the same algorithm as tenant 0's, keyed by
/// the unit's id; a unit restored to an earlier counter is found by its
/// next renewal and by its next raise, and the finding is recorded.
#[tokio::test(flavor = "current_thread")]
async fn a_unit_behind_its_stamp_is_found_by_the_renewal_and_the_raise() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 1, 1).await;
    let id = unit_id(3);
    let ledger = UnitLedger::new(&id);
    let stamp = Stamp {
        ledger: &ledger,
        safety: &bucket,
        clock: &clock,
        id: id.as_str(),
    };
    for _ in 0..3 {
        stamp.raise().await.unwrap();
    }
    assert_eq!(ledger.counter.get(), Some(3));
    for n in 1..=3 {
        assert!(bucket.inner.contains(&stamp_key(id.as_str(), n)));
    }
    assert_eq!(
        stamp_key(id.as_str(), 3),
        format!("rs/{TENANT}.3/00000000000000000003")
    );

    // At its counter: proven.
    let mut v = view(&id, 1, 1, 0);
    v.stamp_counter = Some(3);
    assert!(matches!(
        prove(&bucket, &clock, &Names, &v).await.unwrap(),
        Proof::Fresh { .. }
    ));

    // The platform takes the unit back to counter 1.
    ledger.counter.set(Some(1));
    v.stamp_counter = Some(1);
    assert_eq!(
        prove(&bucket, &clock, &Names, &v).await.unwrap(),
        Proof::StampAhead { seen: Some(1) }
    );
    // Confirmed through the unit's counter, and recorded.
    assert_eq!(stamp.checked().await.unwrap(), None);
    assert!(ledger.rolled_back.get(), "recorded");
    let err = stamp.raise().await.unwrap_err();
    assert_eq!(err.to_string(), ERR_ROLLED_BACK.to_string());
    assert!(stamp.rolled_back().await.unwrap());
}

/// A raise that runs after the unit answered puts a stamp object after
/// the counter the proof was given. The proof reports the stamp ahead;
/// the confirmation finds the counter moved, records nothing, and the
/// next proof from the unit's new counter passes.
#[tokio::test(flavor = "current_thread")]
async fn a_raise_after_the_unit_answered_is_not_a_rollback() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 1, 1).await;
    let id = unit_id(0);
    let ledger = UnitLedger::new(&id);
    let stamp = Stamp {
        ledger: &ledger,
        safety: &bucket,
        clock: &clock,
        id: id.as_str(),
    };
    stamp.raise().await.unwrap();
    let mut v = view(&id, 1, 1, 0);
    v.stamp_counter = Some(1);

    // A request raises between the unit's answer and the proof.
    stamp.raise().await.unwrap();
    assert_eq!(
        prove(&bucket, &clock, &Names, &v).await.unwrap(),
        Proof::StampAhead { seen: Some(1) }
    );
    assert_eq!(stamp.checked().await.unwrap(), Some(Some(2)));
    assert!(!ledger.rolled_back.get(), "nothing recorded");

    v.stamp_counter = Some(2);
    assert!(matches!(
        prove(&bucket, &clock, &Names, &v).await.unwrap(),
        Proof::Fresh { .. }
    ));
}

/// Two units of one tenant, and tenant 0's `main`, never read each
/// other's stamp objects.
#[tokio::test(flavor = "current_thread")]
async fn stamps_of_units_do_not_share_a_prefix() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    chains(&bucket, TENANT, 1, 1).await;
    let one = unit_id(1);
    let ten = unit_id(10);
    // Unit 10 and tenant 0 have stamps; unit 1 has none.
    bucket.plant(&stamp_key(ten.as_str(), 1)).await;
    bucket.plant(&stamp_key("main", 7)).await;

    let proof = prove(&bucket, &clock, &Names, &view(&one, 1, 1, 0))
        .await
        .unwrap();
    assert!(
        matches!(proof, Proof::Fresh { .. }),
        "unit 1 is not unit 10"
    );

    let ledger = UnitLedger::new(&one);
    let stamp = Stamp {
        ledger: &ledger,
        safety: &bucket,
        clock: &clock,
        id: one.as_str(),
    };
    assert!(!stamp.rolled_back().await.unwrap());
}

/// A ledger whose row was made under another id refuses every call, so
/// a unit addressed with a wrong id never raises and never checks an
/// empty prefix.
#[tokio::test(flavor = "current_thread")]
async fn a_stamp_under_another_id_is_refused() {
    let clock = FixedClock::new(T0);
    let bucket = SlowBucket::new(&clock);
    let ledger = UnitLedger::new(&unit_id(0));
    let other = unit_id(1);
    let stamp = Stamp {
        ledger: &ledger,
        safety: &bucket,
        clock: &clock,
        id: other.as_str(),
    };
    let err = stamp.raise().await.unwrap_err();
    assert!(velmora_bridge::stamp::is_catalogue_id_error(&err));
    assert_eq!(bucket.count("put"), 0);
}
