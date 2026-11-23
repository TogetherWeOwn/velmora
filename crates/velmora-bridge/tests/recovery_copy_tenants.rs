//! AM-80 / AM-80b against an in-memory SAFETY bucket, real copier and S3 adapter.

mod record_registry_support;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;
use velmora_bridge::config::Maintenance;
use velmora_bridge::copy::{
    plan_hint, Copier, CopyCounts, BEGAN_KEY, FRESH_MS, JOB_COPIES, JOB_MS, JOB_PAGES,
    KEY_MISS_KEY, KEY_PAGE_PREFIX, PAGE, PASS_INTERVAL_MS, RECHECK_TENANTS, STORE_KEY, SWEPT_KEY,
    WALKED_KEY, WANT_KEY,
};
use velmora_bridge::crypto::scheme2::{seal_record_v2, CONTROL_HEADER_LEN, RECORD_V2_HEADER_LEN};
use velmora_bridge::crypto::{seal_manifest, WRAP_OVERHEAD};
use velmora_bridge::directory::chain::record_key;
use velmora_bridge::directory::record::Tenant;
use velmora_bridge::records::MemRecords;
use velmora_bridge::recovery::check::{check_record, JobRings, RecordCheck};
use velmora_bridge::remote::{
    md5_hex, HttpRequest, HttpResponse, HttpSend, NoAnswer, RemoteConfig, S3Remote,
};
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, TestKek};
use velmora_bridge::*;

use record_registry_support::{key, scope, A, B, SHREDDED, ZERO};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const FRESH: i64 = 10 * 60_000;
const WALK: &str = r#"{"p":"a","k":"m/"}"#;

thread_local! {
    static ALERTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn capture_alerts() {
    ALERTS.with(|lines| lines.borrow_mut().clear());
    trace::log_alerts(|line| ALERTS.with(|lines| lines.borrow_mut().push(line.to_owned())));
}

fn alerts() -> Vec<String> {
    ALERTS.with(|lines| std::mem::take(&mut *lines.borrow_mut()))
}

#[derive(Clone, Default)]
struct RemoteStore {
    objects: Rc<RefCell<BTreeMap<String, Vec<u8>>>>,
    puts: Rc<RefCell<Vec<String>>>,
}

fn decode_query(value: &str) -> String {
    let mut bytes = value.bytes();
    let mut decoded = Vec::new();
    while let Some(byte) = bytes.next() {
        decoded.push(if byte == b'%' {
            let high = (bytes.next().unwrap() as char).to_digit(16).unwrap();
            let low = (bytes.next().unwrap() as char).to_digit(16).unwrap();
            (high * 16 + low) as u8
        } else {
            byte
        });
    }
    String::from_utf8(decoded).unwrap()
}

impl HttpSend for RemoteStore {
    async fn send(&self, req: &HttpRequest) -> std::result::Result<HttpResponse, NoAnswer> {
        let target = req.url.strip_prefix("https://copy.test/records").unwrap();
        let mut response = HttpResponse {
            status: 200,
            ..HttpResponse::default()
        };
        match req.method {
            "GET" => {
                let query: BTreeMap<_, _> = target
                    .strip_prefix('?')
                    .unwrap()
                    .split('&')
                    .map(|pair| pair.split_once('=').unwrap())
                    .map(|(k, v)| (k, decode_query(v)))
                    .collect();
                assert_eq!(query["list-type"], "2");
                let after = query
                    .get("start-after")
                    .map(String::as_str)
                    .unwrap_or_default();
                let limit: usize = query["max-keys"].parse().unwrap();
                let objects = self.objects.borrow();
                let mut found = objects.iter().filter(|(name, _)| {
                    name.starts_with(&query["prefix"]) && name.as_str() > after
                });
                let mut xml = String::from("<ListBucketResult>");
                for (name, bytes) in found.by_ref().take(limit) {
                    use std::fmt::Write as _;
                    write!(xml, "<Contents><Key>{name}</Key><ETag>&quot;{}&quot;</ETag><Size>{}</Size></Contents>", md5_hex(bytes), bytes.len()).unwrap();
                }
                let truncated = found.next().is_some();
                response.body =
                    format!("{xml}<IsTruncated>{truncated}</IsTruncated></ListBucketResult>")
                        .into_bytes();
            }
            "HEAD" => match self.objects.borrow().get(target.strip_prefix('/').unwrap()) {
                Some(bytes) => {
                    response.headers = vec![
                        ("content-length".into(), bytes.len().to_string()),
                        ("etag".into(), format!("\"{}\"", md5_hex(bytes))),
                    ]
                }
                None => response.status = 404,
            },
            "PUT" => {
                let name = target.strip_prefix('/').unwrap();
                self.puts.borrow_mut().push(name.into());
                self.objects
                    .borrow_mut()
                    .insert(name.into(), req.body.clone());
            }
            method => panic!("unexpected remote method: {method}"),
        }
        Ok(response)
    }

    async fn pause(&self, _: u64) {
        panic!("the in-memory remote should not need a retry");
    }
}

type RingResult = Result<TenantRingState>;

#[derive(Default)]
struct Rings {
    answers: RefCell<BTreeMap<TenantId, VecDeque<RingResult>>>,
    loads: RefCell<Vec<TenantId>>,
    yield_before_load: Cell<bool>,
    load_cost: RefCell<Option<(FixedClock, i64)>>,
}

#[derive(Clone, Default)]
struct RingSource(Rc<Rings>);

impl RingSource {
    fn answer(&self, tenant: &str, answers: impl IntoIterator<Item = RingResult>) {
        self.0.answers.borrow_mut().insert(
            TenantId::parse(tenant).unwrap(),
            answers.into_iter().collect(),
        );
    }

    fn calls(&self, tenant: &str) -> usize {
        self.0
            .loads
            .borrow()
            .iter()
            .filter(|t| t.as_str() == tenant)
            .count()
    }
}

impl TenantRings for RingSource {
    async fn ring(&self, tenant: &TenantId) -> RingResult {
        self.0.loads.borrow_mut().push(tenant.clone());
        if self.0.yield_before_load.get() {
            // A real ring depends on I/O. Let other record checks reach the
            // same tenant while this job's ring load is in flight.
            tokio::task::yield_now().await;
        }
        if let Some((clock, ms)) = self.0.load_cost.borrow().as_ref() {
            clock.advance_ms(*ms);
        }
        let mut answers = self.0.answers.borrow_mut();
        let q = answers
            .get_mut(tenant)
            .unwrap_or_else(|| panic!("unexpected ring load: {tenant}"));
        if q.len() == 1 {
            match q.front().unwrap() {
                Ok(state) => Ok(state.clone()),
                Err(_) => Err(BridgeError::Invalid("test ring load unavailable")),
            }
        } else {
            q.pop_front().unwrap()
        }
    }
}

fn ring(tenant: &str, loaded: &[u32], named: &[u32], destroyed: &[u32]) -> RingResult {
    Ok(TenantRingState::Ring(Rc::new(
        CopyRing::new(
            TenantId::parse(tenant).unwrap(),
            loaded.iter().map(|&v| Rc::new(key(tenant, v))).collect(),
            named.iter().copied().collect(),
            destroyed.iter().copied().collect(),
        )
        .unwrap(),
    )))
}

#[derive(Default)]
struct CountingSafety {
    inner: MemBlobStore,
    entry_pages: Cell<u32>,
    dir_pages: RefCell<Vec<Vec<String>>>,
    miss_writes: Cell<usize>,
    claim_attempts: Cell<usize>,
    yield_before_claim: Cell<bool>,
}

impl BlobStore for CountingSafety {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        if key == KEY_MISS_KEY {
            self.miss_writes.set(self.miss_writes.get() + 1);
        }
        self.inner.put(key, bytes, meta).await
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.inner.get(key, span).await
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.inner.head(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }

    async fn delete_record(&self, refused: &recovery::Unpublished) -> Result<()> {
        self.inner.delete_record(refused).await
    }

    async fn list(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<String>> {
        let keys = self.inner.list(prefix, after, limit).await?;
        if prefix == "m/x/" {
            self.dir_pages.borrow_mut().push(keys.clone());
        }
        Ok(keys)
    }

    async fn list_entries(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<BlobEntry>> {
        self.entry_pages.set(self.entry_pages.get() + 1);
        self.inner.list_entries(prefix, after, limit).await
    }

    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>) -> Result<bool> {
        if key.starts_with(KEY_PAGE_PREFIX) {
            self.claim_attempts.set(self.claim_attempts.get() + 1);
            if self.yield_before_claim.get() {
                tokio::task::yield_now().await;
            }
        }
        // The inner store's head and put do not suspend. Once the claimed
        // operation starts, another job cannot interleave with it.
        self.inner.put_if_absent(key, bytes).await
    }
}

struct World {
    safety: CountingSafety,
    kek: TestKek,
    clock: FixedClock,
    jobs: FakeJobs,
    e2: RemoteStore,
    remote: S3Remote<RemoteStore>,
    source: RingSource,
}

impl World {
    fn new() -> Self {
        let e2 = RemoteStore::default();
        let config = RemoteConfig::from_vars(|var| {
            Some(
                match var {
                    "RECOVERY_COPY" => "on",
                    "E2_ENDPOINT" => "https://copy.test",
                    "E2_REGION" => "us-west-1",
                    "E2_BUCKET" => "records",
                    "RECOVERY_PREFIX" => "fixture/",
                    "E2_ACCESS_KEY" => "AKTESTTESTTESTTEST00",
                    "E2_SECRET_KEY" => "synthetic-fixture-credential",
                    _ => return None,
                }
                .into(),
            )
        })
        .unwrap()
        .unwrap();
        let source = RingSource::default();
        for t in [A, B] {
            source.answer(t, [ring(t, &[1], &[1], &[])]);
        }
        source.answer(SHREDDED, [Ok(TenantRingState::Shredded)]);
        Self {
            safety: CountingSafety::default(),
            kek: TestKek::new(),
            clock: FixedClock::new(NOW),
            jobs: FakeJobs::new(),
            remote: S3Remote::new(config, e2.clone()),
            e2,
            source,
        }
    }

    fn copier<'a>(
        &'a self,
        rings: &'a JobRings<RingSource>,
    ) -> Copier<'a, CountingSafety, TestKek, FixedClock, RemoteStore, RingSource> {
        Copier {
            safety: &self.safety,
            kek: &self.kek,
            clock: &self.clock,
            remote: &self.remote,
            maintenance: Maintenance::Off,
            rings,
        }
    }

    async fn raw(&self, name: &str, bytes: &[u8]) {
        let sha: [u8; 32] = Sha256::digest(bytes).into();
        self.safety
            .put(
                name,
                bytes.to_vec(),
                &BlobMeta {
                    bucket: &BucketId::new("b_fixture"),
                    extent: &ExtentId::new("x_fixture"),
                    cipher_sha256: &sha,
                },
            )
            .await
            .unwrap();
    }

    async fn data(&self, t: &str, version: u32, name: &str, plain: &[u8]) -> Vec<u8> {
        let bytes = if t == ZERO {
            seal_manifest(&self.kek, name, plain, &mut SystemRng).unwrap()
        } else {
            seal_record_v2(&key(t, version), name, plain, &mut SystemRng).unwrap()
        };
        self.raw(name, &bytes).await;
        bytes
    }

    fn there(&self, name: &str) -> Option<Vec<u8>> {
        self.e2
            .objects
            .borrow()
            .get(&format!("fixture/{name}"))
            .cloned()
    }

    fn seed_copy(&self, name: &str, bytes: Vec<u8>) {
        self.e2
            .objects
            .borrow_mut()
            .insert(format!("fixture/{name}"), bytes);
    }

    fn put_at(&self, name: &str) -> usize {
        self.e2
            .puts
            .borrow()
            .iter()
            .position(|key| *key == format!("fixture/{name}"))
            .unwrap_or_else(|| panic!("not sent: {name}"))
    }

    async fn step(&self, cursor: &str) -> CopyCounts {
        let rings = JobRings::new(self.source.clone());
        let step = self
            .copier(&rings)
            .step(self.clock.now(), cursor)
            .await
            .unwrap();
        assert!(
            step.next.is_none(),
            "fixture should fit one job: {:?}",
            step.next
        );
        step.counts
    }

    async fn job(&self, pass: UnixMs, cursor: &str) -> (JobOutcome, CopyCounts) {
        let rings = JobRings::new(self.source.clone());
        let (outcome, counts, _) = self.copier(&rings).run_job(&self.jobs, pass, cursor).await;
        (outcome, counts.expect("job ran"))
    }

    async fn pass(&self) -> CopyCounts {
        let mut counts = CopyCounts::default();
        let mut cursor = String::new();
        for _ in 0..16 {
            let rings = JobRings::new(self.source.clone());
            let step = self
                .copier(&rings)
                .step(self.clock.now(), &cursor)
                .await
                .unwrap();
            counts.add(&step.counts);
            match step.next {
                Some(next) => cursor = next,
                None => return counts,
            }
        }
        panic!("fixture did not finish in 16 jobs");
    }

    async fn first_job(&self) -> CopyCounts {
        let (outcome, counts) = self.job(self.clock.now(), "").await;
        assert_eq!(outcome, JobOutcome::Ack);
        assert!(self.jobs.take().is_empty(), "fixture should fit one job");
        counts
    }

    async fn finish_pass(&self, pass: UnixMs) -> CopyCounts {
        let mut counts = CopyCounts::default();
        for _ in 0..16 {
            let sent = self.jobs.take();
            if sent.is_empty() {
                return counts;
            }
            assert_eq!(sent.len(), 1);
            let Job::RecoveryCopy {
                pass: next_pass,
                cursor,
                ..
            } = &sent[0].job
            else {
                panic!("expected recovery copy continuation");
            };
            assert_eq!(*next_pass, pass);
            let (outcome, next) = self.job(pass, cursor).await;
            assert_eq!(outcome, JobOutcome::Ack);
            counts.add(&next);
        }
        panic!("pass did not finish within 16 continuations");
    }

    async fn miss_marks(&self) -> BTreeMap<String, [i64; 3]> {
        let bytes = self.safety.get(KEY_MISS_KEY, None).await.unwrap().unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn rest_walk(&self) {
        let ended = self.clock.now().0 - PASS_INTERVAL_MS;
        let mark = ended.to_string();
        for name in [BEGAN_KEY, WALKED_KEY, SWEPT_KEY] {
            self.raw(name, mark.as_bytes()).await;
        }
        self.raw(STORE_KEY, self.remote.place().as_bytes()).await;
    }

    fn hint(&self, t: &str, extent: &str) -> (UnixMs, String) {
        let post = Job::Extent {
            v: JOB_VERSION,
            extent: ExtentId::new(extent),
            generation: GenerationId::new("g_0000000000001_a"),
            stage: OutboxStage::Post,
        };
        match plan_hint(&post, &JobOutcome::Ack, &scope(t), self.clock.now()) {
            Some(Job::RecoveryCopy { pass, cursor, .. }) => (pass, cursor),
            other => panic!("expected recovery copy hint: {other:?}"),
        }
    }
}

fn article(t: &str, extent: &str) -> String {
    format!("m/x/{t}/art/{extent}")
}

fn generation(t: &str, age: i64, tail: &str) -> String {
    format!("m/x/{t}/g_{:013x}_{tail}", NOW.0 - age)
}

fn flip(mut bytes: Vec<u8>, index: usize) -> Vec<u8> {
    bytes[index] ^= 1;
    bytes
}

#[tokio::test(flavor = "current_thread")]
async fn t1_sweep_and_walk_copy_real_writer_families_byte_for_byte() {
    capture_alerts();
    let w = World::new();
    let mut expected = record_registry_support::control_records(&w.kek).await;
    expected.extend(record_registry_support::data_records(&w.kek).await);
    let parts = record_registry_support::segmented_records(&w.kek, B).await;
    expected.extend(parts.plans);
    expected.extend(parts.segments);
    expected.push(parts.head);
    let key_blob =
        velmora_bridge::crypto::scheme2::tk_blob_name(&TenantId::parse(A).unwrap(), 1, 1);
    let (_, wrapped) =
        velmora_bridge::crypto::scheme2::wrap_tenant_key(&w.kek, &key(A, 1), &mut SystemRng)
            .unwrap();
    w.raw(&key_blob, &wrapped).await;
    for (name, bytes) in &expected {
        w.raw(name, bytes).await;
    }
    let c = w.pass().await;
    assert_eq!(
        (c.source_unreadable, c.damaged(), c.pending, c.failed),
        (0, 0, 0, 0),
        "{c:?}"
    );
    for (name, bytes) in &expected {
        assert_eq!(w.there(name).as_ref(), Some(bytes), "{name}");
    }
    assert_eq!(c.copied, expected.len() as u64);
    assert!(w.there(&key_blob).is_none());
    assert!(alerts().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn t2_wrong_envelopes_and_corruption_never_replace_good_copies() {
    capture_alerts();
    let w = World::new();
    let src = article(A, "x_other");
    let v2 = seal_record_v2(&key(A, 1), &src, b"plan", &mut SystemRng).unwrap();
    use RecordCheck::{CrossScheme, CrossTenant, Unreadable};

    let mut cases = Vec::new();
    for name in ["m/art/x_flat".to_string(), article(ZERO, "x_zero")] {
        let good = seal_manifest(&w.kek, &name, b"good", &mut SystemRng).unwrap();
        cases.push((name, good, v2.clone(), CrossScheme));
    }
    for (leaf, wrong_tenant) in [("x_v1", false), ("x_cross", true)] {
        let name = article(A, leaf);
        let good = seal_record_v2(&key(A, 1), &name, b"good", &mut SystemRng).unwrap();
        let bad = if wrong_tenant {
            seal_record_v2(
                &key(B, 1),
                &article(B, leaf),
                b"other tenant",
                &mut SystemRng,
            )
            .unwrap()
        } else {
            seal_manifest(&w.kek, &name, b"wrong scheme", &mut SystemRng).unwrap()
        };
        let expected = if wrong_tenant {
            CrossTenant
        } else {
            CrossScheme
        };
        cases.push((name, good, bad, expected));
    }
    for (t, door) in [(A, true), (B, false)] {
        let records = MemRecords::new();
        record_registry_support::tenant_control(&w.kek, &records, t, false).await;
        let name = record_key(&Tenant::Managed(TenantId::parse(t).unwrap()), 4);
        let good = records.raw(&name).unwrap();
        let index = if door {
            CONTROL_HEADER_LEN
        } else {
            good.len() - 1
        };
        let bad = flip(good.clone(), index);
        cases.push((name, good, bad, Unreadable));
    }
    let name = article(A, "x_corrupt");
    let good = seal_record_v2(&key(A, 1), &name, b"good", &mut SystemRng).unwrap();
    let bad = flip(good.clone(), good.len() - 1);
    cases.push((name, good, bad, Unreadable));

    for (name, good, bad, expected) in &cases {
        let rings = JobRings::new(w.source.clone());
        let found = check_record(name, bad, &w.kek, &rings, &w.clock).await;
        assert!(
            matches!(
                (expected, found),
                (CrossScheme, CrossScheme) | (CrossTenant, CrossTenant) | (Unreadable, Unreadable)
            ),
            "wrong refusal class: {name}"
        );
        w.raw(name, bad).await;
        w.seed_copy(name, good.clone());
    }
    let c = w.pass().await;
    assert_eq!(
        (c.cross_scheme, c.cross_tenant, c.source_unreadable),
        (3, 1, 3),
        "{c:?}"
    );
    assert_eq!(c.damaged(), 7);
    assert_eq!((c.copied, c.same, c.failed), (0, 0, 0));
    assert_eq!(
        alerts(),
        ["recovery copy (cross_record) cross_scheme=3 cross_tenant=1"]
    );
    assert!(w.e2.puts.borrow().is_empty());
    for (name, good, _, _) in cases {
        assert_eq!(w.there(&name), Some(good), "{name}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_family_alarms_even_when_its_v1_record_can_be_copied() {
    capture_alerts();
    let w = World::new();
    let name = "m/zz-unregistered/fixture";
    let bytes = w.data(ZERO, 1, name, b"legacy fallback").await;
    let c = w.pass().await;
    assert_eq!((c.unknown_family, c.damaged(), c.copied), (1, 1, 1));
    assert_eq!(w.there(name), Some(bytes));
    assert_eq!(alerts(), ["recovery copy (unknown_family) records=1"]);
}

#[tokio::test(flavor = "current_thread")]
async fn t3_shredded_vmr2_is_untouched_while_its_control_records_copy() {
    capture_alerts();
    let w = World::new();
    let name = article(SHREDDED, "x_shredded");
    let old = seal_record_v2(&key(SHREDDED, 1), &name, b"already copied", &mut SystemRng).unwrap();
    w.seed_copy(&name, old.clone());
    w.data(SHREDDED, 1, &name, b"not to be copied").await;
    let controls = record_registry_support::shredded_controls(&w.kek, SHREDDED).await;
    for (name, bytes) in &controls {
        w.raw(name, bytes).await;
    }
    let c = w.pass().await;
    assert_eq!(
        (c.shredded, c.copied, c.failed, c.damaged()),
        (1, controls.len() as u64, 0, 0)
    );
    assert_eq!(w.there(&name), Some(old));
    for (name, bytes) in controls {
        assert_eq!(w.there(&name), Some(bytes), "{name}");
    }
    assert!(alerts().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn t3_ring_error_wants_a_walk_and_next_pass_copies() {
    capture_alerts();
    let w = World::new();
    let name = generation(A, FRESH, "recover");
    let bytes = w.data(A, 1, &name, br#"{"v":1,"extents":[]}"#).await;
    w.rest_walk().await;
    w.source
        .answer(A, [Err(BridgeError::Invalid("test ring load unavailable"))]);
    assert!(w.safety.get(WANT_KEY, None).await.unwrap().is_none());
    let (outcome, c) = w.job(w.clock.now(), "").await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(
        (c.failed, c.source_unreadable, c.copied),
        (1, 0, 0),
        "{c:?}"
    );
    assert!(w.safety.get(WANT_KEY, None).await.unwrap().is_some());
    assert!(w.there(&name).is_none());
    assert!(alerts().is_empty());

    w.clock.advance_ms(PASS_INTERVAL_MS);
    w.source.answer(A, [ring(A, &[1], &[1], &[])]);
    let (outcome, c) = w.job(w.clock.now(), "").await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(
        (c.failed, c.source_unreadable, c.copied),
        (0, 0, 1),
        "{c:?}"
    );
    assert_eq!(w.there(&name), Some(bytes));
}

#[tokio::test(flavor = "current_thread")]
async fn t3_partial_ring_serves_the_key_that_loaded() {
    let w = World::new();
    w.source.answer(A, [ring(A, &[1], &[1, 2], &[])]);
    let name = article(A, "x_loaded");
    let bytes = w.data(A, 1, &name, b"plan").await;
    let c = w.step(WALK).await;
    assert_eq!(
        (c.copied, c.failed, c.damaged(), c.ring_loads),
        (1, 0, 0, 1)
    );
    assert_eq!(w.there(&name), Some(bytes));
}

#[tokio::test(flavor = "current_thread")]
async fn t3_mid_rotation_reloads_once_and_copies_the_committed_version() {
    let w = World::new();
    w.source.answer(
        A,
        [ring(A, &[1], &[1, 2], &[]), ring(A, &[1, 2], &[1, 2], &[])],
    );
    let name = article(A, "x_rotation");
    let bytes = w.data(A, 2, &name, b"plan").await;
    let c = w.step(WALK).await;
    assert_eq!(
        (c.copied, c.failed, c.damaged(), c.ring_loads),
        (1, 0, 0, 2)
    );
    assert_eq!(w.source.calls(A), 2);
    assert_eq!(w.there(&name), Some(bytes));
}

async fn seed_missing_version_jobs(w: &World, version: u32) {
    for i in 0..=JOB_COPIES {
        let name = article(A, &format!("x_missing_{i:04}"));
        w.data(A, version, &name, b"plan").await;
    }
}

async fn missing_version_jobs(w: &World) {
    let pass = w.clock.now();
    let mut cursor = WALK.to_owned();
    for failed in [JOB_COPIES as u64, 1] {
        let (outcome, c) = w.job(pass, &cursor).await;
        assert_eq!(outcome, JobOutcome::Ack);
        assert_eq!(
            (c.failed, c.damaged(), c.copied, c.ring_loads),
            (failed, 0, 0, 2),
            "{c:?}"
        );
        let sent = w.jobs.take();
        if failed == 1 {
            assert!(sent.is_empty(), "fixture should finish in two jobs");
        } else {
            assert_eq!(sent.len(), 1);
            let Job::RecoveryCopy {
                pass: next_pass,
                cursor: next,
                ..
            } = &sent[0].job
            else {
                panic!("expected recovery copy continuation");
            };
            assert_eq!(*next_pass, pass);
            cursor = next.clone();
        }
    }
    assert!(w.e2.puts.borrow().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_unknown_future_version_pages_once_each_pass_across_jobs() {
    capture_alerts();
    let w = World::new();
    w.source.answer(A, [ring(A, &[1], &[1, 2], &[])]);
    seed_missing_version_jobs(&w, 3).await;
    for _ in 0..2 {
        missing_version_jobs(&w).await;
        assert_eq!(
            alerts(),
            [format!(
                "recovery copy (copy_key_version_missing) tenant={A} version=3 ring=unknown"
            )]
        );
        assert!(w.safety.get(KEY_MISS_KEY, None).await.unwrap().is_some());
        w.clock.advance_ms(PASS_INTERVAL_MS);
    }
    assert_eq!(w.source.calls(A), 8);
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_destroyed_version_counts_without_paging() {
    capture_alerts();
    let w = World::new();
    // Even a first read that says destroyed must be confirmed by the reload.
    w.source.answer(A, [ring(A, &[2], &[2], &[1])]);
    let name = article(A, "x_destroyed");
    w.data(A, 1, &name, b"plan").await;
    let c = w.step(WALK).await;
    assert_eq!(
        (
            c.version_destroyed,
            c.failed,
            c.damaged(),
            c.copied,
            c.ring_loads
        ),
        (1, 0, 0, 0, 2)
    );
    assert_eq!(w.source.calls(A), 2);
    assert!(w.there(&name).is_none());
    assert!(alerts().is_empty());
    assert_eq!(w.safety.miss_writes.get(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_named_missing_key_pages_on_pass_five_then_once_per_pass() {
    capture_alerts();
    let w = World::new();
    w.source.answer(A, [ring(A, &[1], &[1, 2], &[])]);
    seed_missing_version_jobs(&w, 2).await;
    for pass in 1..=6 {
        missing_version_jobs(&w).await;
        let expected = if pass <= 4 {
            vec![]
        } else {
            vec![format!(
                "recovery copy (copy_key_version_missing) tenant={A} version=2 ring=partial"
            )]
        };
        assert_eq!(alerts(), expected, "pass {pass}");
        w.clock.advance_ms(PASS_INTERVAL_MS);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t3_many_records_and_versions_cannot_reload_more_than_once_per_tenant() {
    capture_alerts();
    let w = World::new();
    w.source.0.yield_before_load.set(true);
    for v in 1..=8 {
        for t in [A, B] {
            let name = article(t, &format!("x_key_{v}"));
            w.data(t, v, &name, b"plan").await;
        }
    }
    let c = w.step(WALK).await;
    assert_eq!(
        (c.copied, c.failed, c.damaged(), c.ring_loads),
        (2, 14, 0, 4),
        "{c:?}"
    );
    assert_eq!((w.source.calls(A), w.source.calls(B)), (2, 2));
    assert_eq!(
        alerts().len(),
        14,
        "one page for each unknown tenant/version pair"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t4_fresh_managed_generation_waits_for_its_plan() {
    let w = World::new();
    let name = generation(A, FRESH, "pending");
    let bytes = w
        .data(A, 1, &name, br#"{"v":1,"extents":[{"id":"x_pending"}]}"#)
        .await;
    w.rest_walk().await;
    let c = w.pass().await;
    assert_eq!((c.pending, c.copied, c.damaged()), (1, 0, 0), "{c:?}");
    assert!(w.there(&name).is_none());

    let plan = article(A, "x_pending");
    let plan_bytes = w.data(A, 1, &plan, b"plan").await;
    w.clock.advance_ms(PASS_INTERVAL_MS);
    let c = w.pass().await;
    assert_eq!((c.pending, c.copied, c.damaged()), (0, 2, 0), "{c:?}");
    assert_eq!(w.there(&name), Some(bytes));
    assert_eq!(w.there(&plan), Some(plan_bytes));
    assert!(w.put_at(&plan) < w.put_at(&name));
}

#[tokio::test(flavor = "current_thread")]
async fn t4_managed_segmented_head_is_sent_after_its_plans_and_segments() {
    let w = World::new();
    let parts = record_registry_support::segmented_records(&w.kek, A).await;
    assert_eq!(parts.segments.len(), 2);
    for (name, bytes) in parts
        .plans
        .iter()
        .chain(&parts.segments)
        .chain(std::iter::once(&parts.head))
    {
        w.raw(name, bytes).await;
    }
    w.rest_walk().await;
    let c = w.pass().await;
    assert_eq!((c.copied, c.pending, c.damaged()), (5, 0, 0), "{c:?}");
    let head_at = w.put_at(&parts.head.0);
    for (name, bytes) in parts.plans.iter().chain(&parts.segments) {
        assert_eq!(w.there(name).as_ref(), Some(bytes), "{name}");
        assert!(w.put_at(name) < head_at, "{name} must precede the head");
    }
    assert_eq!(w.there(&parts.head.0), Some(parts.head.1));
}

#[tokio::test(flavor = "current_thread")]
async fn t4_managed_post_hint_copies_the_scoped_plan() {
    let w = World::new();
    let name = article(A, "x_hinted");
    let bytes = w.data(A, 1, &name, b"plan").await;
    let (pass, cursor) = w.hint(A, "x_hinted");
    assert_eq!(pass, UnixMs(0));
    let fields: serde_json::Value = serde_json::from_str(&cursor).unwrap();
    assert_eq!(fields["k"], name);
    let (outcome, c) = w.job(pass, &cursor).await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!((c.copied, c.failed, c.damaged()), (1, 0, 0));
    assert_eq!(w.there(&name), Some(bytes));
    assert!(w.there("m/art/x_hinted").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_hint_does_not_page_or_write_the_key_miss_mark() {
    capture_alerts();
    let w = World::new();
    let extent = "x_hint_missing";
    let name = article(A, extent);
    // An unknown version would page immediately in a pass job.
    w.data(A, 2, &name, b"plan").await;
    let (pass, cursor) = w.hint(A, extent);
    let (_, c) = w.job(pass, &cursor).await;
    assert_eq!((c.failed, c.ring_loads, c.copied), (1, 2, 0), "{c:?}");
    assert!(alerts().is_empty());
    assert_eq!(w.safety.miss_writes.get(), 0);
    assert!(w.safety.get(KEY_MISS_KEY, None).await.unwrap().is_none());
    assert!(w.there(&name).is_none());

    let c = w.step(WALK).await;
    assert_eq!(c.failed, 1);
    assert_eq!(alerts(), [missing_key_page(2, "unknown")]);
    let writes = w.safety.miss_writes.get();
    assert!(writes > 0);
    let (_, c) = w.job(pass, &cursor).await;
    assert_eq!(c.failed, 1);
    assert!(alerts().is_empty());
    assert_eq!(w.safety.miss_writes.get(), writes, "hint rewrote the mark");
}

fn missing_key_page(version: u32, kind: &str) -> String {
    tenant_key_page(A, version, kind)
}

fn tenant_key_page(tenant: &str, version: u32, kind: &str) -> String {
    format!(
        "recovery copy (copy_key_version_missing) tenant={tenant} version={version} ring={kind}"
    )
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_overlapping_jobs_claim_one_page_and_next_pass_prunes_it() {
    capture_alerts();
    let w = World::new();
    w.source.answer(A, [ring(A, &[1], &[1, 2], &[])]);
    let name = generation(A, FRESH_MS + PASS_INTERVAL_MS, "overlapping_miss");
    w.data(A, 2, &name, br#"{"v":1,"extents":[]}"#).await;
    assert_eq!(w.first_job().await.failed, 1);
    for _ in 2..5 {
        w.clock.advance_ms(PASS_INTERVAL_MS);
        assert_eq!(w.first_job().await.failed, 0);
    }
    assert!(alerts().is_empty());

    w.clock.advance_ms(PASS_INTERVAL_MS);
    let pass = w.clock.now();
    w.safety.yield_before_claim.set(true);
    let (first, redelivery, walk) =
        tokio::join!(w.job(pass, ""), w.job(pass, ""), w.job(pass, WALK));
    for (outcome, counts) in [first, redelivery] {
        assert_eq!(
            (outcome, counts.failed, counts.ring_loads),
            (JobOutcome::Ack, 0, 2)
        );
    }
    assert_eq!((walk.0, walk.1.failed), (JobOutcome::Ack, 1));
    assert!(w.jobs.take().is_empty());
    assert_eq!(
        w.safety.claim_attempts.get(),
        3,
        "all three jobs found the due miss"
    );
    assert_eq!(alerts(), [missing_key_page(2, "partial")]);
    let claim = |at: UnixMs| format!("{KEY_PAGE_PREFIX}{:016}/{A}/2", at.0);
    assert_eq!(
        w.safety.list(KEY_PAGE_PREFIX, "", PAGE).await.unwrap(),
        [claim(pass)]
    );

    w.safety.yield_before_claim.set(false);
    w.clock.advance_ms(PASS_INTERVAL_MS);
    assert_eq!(w.first_job().await.failed, 0);
    assert_eq!(alerts(), [missing_key_page(2, "partial")]);
    assert_eq!(
        w.safety.list(KEY_PAGE_PREFIX, "", PAGE).await.unwrap(),
        [claim(w.clock.now())],
        "earlier claims must be removed by the first job"
    );
    assert_eq!(w.step(WALK).await.failed, 1);
    assert!(alerts().is_empty(), "the next pass also claims only once");
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_walk_only_misses_all_page_while_tenant_rechecks_rotate() {
    capture_alerts();
    let w = World::new();
    let tenants: Vec<_> = (1..=RECHECK_TENANTS + 5)
        .map(|i| format!("t_{i:016x}"))
        .collect();
    for t in &tenants {
        w.source.answer(t, [ring(t, &[1], &[1, 2], &[])]);
        let name = generation(t, FRESH_MS + PASS_INTERVAL_MS, "rotation_miss");
        w.data(t, 2, &name, br#"{"v":1,"extents":[]}"#).await;
    }
    let start = w.clock.now();
    let (outcome, first) = w.job(start, "").await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(
        first.failed + w.finish_pass(start).await.failed,
        tenants.len() as u64
    );
    let ended = w.safety.get(WALKED_KEY, None).await.unwrap().unwrap();
    assert!(alerts().is_empty());

    let full_rotation = tenants.len().div_ceil(RECHECK_TENANTS);
    let mut history = VecDeque::new();
    let mut recovered = false;
    let target = &tenants[0];
    let recovery_pass = 9;
    for pass in 2..recovery_pass + full_rotation {
        if pass == recovery_pass {
            w.source
                .answer(target, [ring(target, &[1, 2], &[1, 2], &[])]);
        }
        let before: Vec<_> = tenants.iter().map(|t| w.source.calls(t)).collect();
        w.clock.advance_ms(PASS_INTERVAL_MS);
        let at = w.clock.now();
        let (outcome, first) = w.job(at, "").await;
        assert_eq!((outcome, first.failed), (JobOutcome::Ack, 0), "pass {pass}");
        let mut checked = BTreeSet::new();
        for (t, old) in tenants.iter().zip(before) {
            let loads = w.source.calls(t) - old;
            if loads != 0 {
                let resolved = t == target && pass >= recovery_pass;
                assert_eq!(loads, if resolved { 1 } else { 2 }, "{t} in pass {pass}");
                checked.insert(t);
                recovered |= resolved;
            }
        }
        if pass < recovery_pass {
            assert_eq!(checked.len(), RECHECK_TENANTS, "pass {pass}");
            history.push_back(checked);
            if history.len() == full_rotation {
                let seen: BTreeSet<_> = history.iter().flatten().copied().collect();
                let skipped: Vec<_> = tenants.iter().filter(|t| !seen.contains(t)).collect();
                assert!(
                    skipped.is_empty(),
                    "tenants not rechecked by pass {pass}: {skipped:?}"
                );
                history.pop_front();
            }
        }
        let expected: Vec<_> = tenants
            .iter()
            .filter(|t| pass >= 5 && !(recovered && *t == target))
            .map(|t| tenant_key_page(t, 2, "partial"))
            .collect();
        assert_eq!(alerts(), expected, "first job of pass {pass}");
        assert_eq!(
            w.miss_marks().await.contains_key(&format!("{target}/2")),
            !recovered,
            "pass {pass}"
        );
        let continuation = w.finish_pass(at).await;
        assert_eq!(
            (continuation.failed, continuation.ring_loads),
            (0, 0),
            "pass {pass}"
        );
        assert!(alerts().is_empty(), "continuation paged in pass {pass}");
        assert_eq!(
            w.safety.get(WALKED_KEY, None).await.unwrap().as_ref(),
            Some(&ended),
            "pass {pass}"
        );
    }
    assert!(recovered, "loaded key was not rechecked in one rotation");
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_partial_miss_keeps_paging_when_the_ring_becomes_unreadable() {
    capture_alerts();
    let w = World::new();
    let miss = format!("{A}/2");
    w.source.answer(A, [ring(A, &[1], &[1, 2], &[])]);
    let name = generation(A, FRESH_MS + PASS_INTERVAL_MS, "partial_then_unreadable");
    w.data(A, 2, &name, br#"{"v":1,"extents":[]}"#).await;
    assert_eq!(w.first_job().await.failed, 1);
    assert!(alerts().is_empty());
    let ended = w.safety.get(WALKED_KEY, None).await.unwrap().unwrap();
    let mark = w.miss_marks().await[&miss];
    assert_eq!(mark[2], 1);
    for pass in 2..=8 {
        if pass == 6 {
            w.source
                .answer(A, [Err(BridgeError::Invalid("test ring load unavailable"))]);
        }
        w.clock.advance_ms(PASS_INTERVAL_MS);
        let c = w.first_job().await;
        assert_eq!(
            (c.failed, c.ring_loads),
            (0, if pass < 6 { 2 } else { 1 }),
            "pass {pass}: {c:?}"
        );
        if pass < 5 {
            assert!(alerts().is_empty(), "pass {pass}");
        } else {
            assert_eq!(alerts(), [missing_key_page(2, "partial")], "pass {pass}");
        }
        assert_eq!(w.miss_marks().await, BTreeMap::from([(miss.clone(), mark)]));
        assert_eq!(
            w.safety.get(WALKED_KEY, None).await.unwrap().as_ref(),
            Some(&ended)
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_vmr2_version_zero_and_unreadable_ring_are_distinct_misses() {
    capture_alerts();
    let w = World::new();
    let name = generation(A, FRESH_MS + PASS_INTERVAL_MS, "version_zero");
    let mut bytes = seal_record_v2(
        &key(A, 1),
        &name,
        br#"{"v":1,"extents":[]}"#,
        &mut SystemRng,
    )
    .unwrap();
    bytes[RECORD_V2_HEADER_LEN - 4..RECORD_V2_HEADER_LEN].copy_from_slice(&0u32.to_be_bytes());
    w.raw(&name, &bytes).await;
    let version = format!("{A}/0");
    let unreadable = format!("{A}/ring");
    assert_eq!(w.first_job().await.failed, 1);
    assert_eq!(alerts(), [missing_key_page(0, "unknown")]);
    let unknown_mark = [NOW.0, NOW.0, 0];
    assert_eq!(
        w.miss_marks().await,
        BTreeMap::from([(version.clone(), unknown_mark)])
    );

    w.source
        .answer(A, [Err(BridgeError::Invalid("test ring load unavailable"))]);
    // A separate walk job observes the outage before its recheck is due.
    assert_eq!(w.step(WALK).await.failed, 1);
    assert!(alerts().is_empty());
    let both = BTreeMap::from([
        (version.clone(), unknown_mark),
        (unreadable, [NOW.0, NOW.0, 2]),
    ]);
    assert_eq!(w.miss_marks().await, both);
    for pass in 2..=6 {
        if pass == 6 {
            w.source.answer(A, [ring(A, &[1], &[1], &[])]);
        }
        w.clock.advance_ms(PASS_INTERVAL_MS);
        assert_eq!(w.first_job().await.failed, 0, "pass {pass} should not walk");
        let mut expected = vec![missing_key_page(0, "unknown")];
        if pass == 5 {
            expected.push(missing_key_page(0, "unreadable"));
        }
        assert_eq!(alerts(), expected, "pass {pass}");
        let marks = w.miss_marks().await;
        if pass == 6 {
            assert_eq!(marks, BTreeMap::from([(version.clone(), unknown_mark)]));
        } else {
            assert_eq!(marks, both, "pass {pass}");
        }
    }
    assert!(w.there(&name).is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_walk_only_partial_miss_pages_for_thirty_hours_without_gaps() {
    capture_alerts();
    let w = World::new();
    w.source.answer(A, [ring(A, &[1], &[1, 2], &[])]);
    let name = generation(A, FRESH_MS + PASS_INTERVAL_MS, "persistent_partial");
    w.data(A, 2, &name, br#"{"v":1,"extents":[]}"#).await;
    assert_eq!(w.first_job().await.failed, 1);
    assert!(alerts().is_empty());
    let miss = format!("{A}/2");
    let mut last_seen = NOW.0;
    let mut walks = 1;
    let mut rests = 0;
    let duration = 30 * 60 * 60 * 1000;
    for pass in 2..=5 + duration / PASS_INTERVAL_MS {
        w.clock.advance_ms(PASS_INTERVAL_MS);
        let c = w.first_job().await;
        // Leave the walk's persisted schedule alone. Only its visits,
        // not the first-job recheck, should refresh last_seen.
        match c.failed {
            0 => rests += 1,
            1 => {
                walks += 1;
                last_seen = w.clock.now().0;
            }
            _ => panic!("pass {pass}: expected at most one failed record, got {c:?}"),
        }
        let pages = alerts();
        if pass < 5 {
            assert!(pages.is_empty(), "pass {pass}: {pages:?}");
        } else {
            assert_eq!(pages, [missing_key_page(2, "partial")], "pass {pass}");
        }
        assert_eq!(
            w.miss_marks().await[&miss],
            [NOW.0, last_seen, 1],
            "pass {pass}"
        );
    }
    assert!(walks > 1 && rests > 0, "walks={walks}, rests={rests}");
    assert!(w.there(&name).is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_recheck_stops_when_ring_loads_spend_the_job_time() {
    capture_alerts();
    let w = World::new();
    w.rest_walk().await;
    let tenants: Vec<_> = (1..=RECHECK_TENANTS)
        .map(|i| format!("t_{i:016x}"))
        .collect();
    let marks: BTreeMap<_, _> = tenants
        .iter()
        .map(|t| {
            w.source.answer(t, [ring(t, &[1], &[1, 2], &[])]);
            (format!("{t}/2"), [NOW.0 - 4 * PASS_INTERVAL_MS, NOW.0, 1])
        })
        .collect();
    w.raw(KEY_MISS_KEY, &serde_json::to_vec(&marks).unwrap())
        .await;
    // A partial ring needs one load and one reload; two tenants use the
    // full budget, with no operation already in flight at the deadline.
    w.source
        .0
        .load_cost
        .replace(Some((w.clock.clone(), JOB_MS / 4)));
    let (outcome, c) = w.job(NOW, "").await;
    assert_eq!(outcome, JobOutcome::Ack);
    let checked: Vec<_> = tenants
        .iter()
        .map(|t| w.source.calls(t))
        .filter(|&n| n != 0)
        .collect();
    assert_eq!(
        checked,
        [2, 2],
        "time budget should stop the recheck before the tenant cap"
    );
    assert_eq!((c.ring_loads, c.ring_ms), (4, JOB_MS as u64));
    assert_eq!(w.clock.now().0 - NOW.0, JOB_MS);
    assert_eq!(
        w.safety.entry_pages.get(),
        0,
        "started the sweep after spending the job time"
    );
    assert_eq!(
        alerts(),
        tenants
            .iter()
            .map(|t| tenant_key_page(t, 2, "partial"))
            .collect::<Vec<_>>()
    );
    assert_eq!(w.miss_marks().await, marks);
    let continuation = w.finish_pass(NOW).await;
    assert_eq!(continuation.ring_loads, 0);
    assert!(alerts().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_first_job_rechecks_partial_ring_while_walk_rests() {
    capture_alerts();
    let w = World::new();
    w.source.answer(A, [ring(A, &[1], &[1, 2], &[])]);
    let name = generation(A, FRESH_MS + PASS_INTERVAL_MS, "old_missing");
    w.data(A, 2, &name, br#"{"v":1,"extents":[]}"#).await;
    assert_eq!(w.first_job().await.failed, 1);
    assert!(alerts().is_empty());
    let ended = w.safety.get(WALKED_KEY, None).await.unwrap().unwrap();
    let miss = format!("{A}/2");
    let first_seen = w.miss_marks().await[&miss][1];

    for pass in 2..=7 {
        w.clock.advance_ms(PASS_INTERVAL_MS);
        let c = w.first_job().await;
        assert_eq!((c.failed, c.ring_loads), (0, 2), "pass {pass}: {c:?}");
        if pass < 5 {
            assert!(alerts().is_empty(), "page before pass 5 (pass {pass})");
        } else {
            assert_eq!(alerts(), [missing_key_page(2, "partial")], "pass {pass}");
            // A redelivered first job must not page again in the same slot.
            assert_eq!(w.first_job().await.failed, 0);
            assert!(alerts().is_empty(), "duplicate page in pass {pass}");
        }
        assert_eq!(w.miss_marks().await[&miss][1], first_seen);
        assert_eq!(
            w.safety.get(WALKED_KEY, None).await.unwrap(),
            Some(ended.clone())
        );
    }

    w.clock.advance_ms(PASS_INTERVAL_MS);
    w.source.answer(A, [ring(A, &[1, 2], &[1, 2], &[])]);
    let c = w.first_job().await;
    assert_eq!((c.failed, c.ring_loads), (0, 1));
    assert!(!w.miss_marks().await.contains_key(&miss));
    assert!(alerts().is_empty());
    assert!(w.there(&name).is_none(), "the old record was not rewalked");
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_first_job_bounds_rechecks_by_tenant_not_version() {
    capture_alerts();
    let w = World::new();
    w.rest_walk().await;
    let tenants: Vec<_> = (1..=RECHECK_TENANTS + 3)
        .map(|i| format!("t_{i:016x}"))
        .collect();
    let mut marks = BTreeMap::new();
    for tenant in &tenants {
        w.source
            .answer(tenant, [ring(tenant, &[1], &[1, 2, 3], &[])]);
        for version in [2, 3] {
            // `[first, last, kind]`, kind 1: a partial ring.
            marks.insert(format!("{tenant}/{version}"), [NOW.0, NOW.0, 1]);
        }
    }
    w.raw(KEY_MISS_KEY, &serde_json::to_vec(&marks).unwrap())
        .await;
    for _ in 0..2 {
        let before: Vec<_> = tenants.iter().map(|t| w.source.calls(t)).collect();
        let c = w.first_job().await;
        let loads: Vec<_> = tenants
            .iter()
            .zip(before)
            .map(|(t, old)| w.source.calls(t) - old)
            .filter(|&loads| loads != 0)
            .collect();
        assert_eq!(loads, vec![2; RECHECK_TENANTS]);
        assert_eq!(c.ring_loads as usize, loads.iter().sum::<usize>());

        // A continuation on an empty range must not recheck the mark.
        let (outcome, continuation) = w.job(w.clock.now(), WALK).await;
        assert_eq!((outcome, continuation.ring_loads), (JobOutcome::Ack, 0));
        assert_eq!(w.miss_marks().await, marks);
        assert!(alerts().is_empty());
        w.clock.advance_ms(PASS_INTERVAL_MS);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_truncated_vmr2_is_unreadable_without_a_ring_load_or_page() {
    capture_alerts();
    let w = World::new();
    for version in [1, 2] {
        for body in [0, WRAP_OVERHEAD - 1] {
            let name = article(A, &format!("x_truncated_{version}_{body}"));
            let mut bytes =
                seal_record_v2(&key(A, version), &name, b"plan", &mut SystemRng).unwrap();
            bytes.truncate(RECORD_V2_HEADER_LEN + body);
            w.raw(&name, &bytes).await;
        }
    }
    let c = w.step(WALK).await;
    assert_eq!(
        (c.source_unreadable, c.failed, c.ring_loads, c.copied),
        (4, 0, 0, 0),
        "{c:?}"
    );
    assert_eq!(w.source.calls(A), 0);
    assert_eq!(w.safety.miss_writes.get(), 0);
    assert!(alerts().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_vmr2_cut_inside_its_header_is_unreadable_not_cross_scheme() {
    capture_alerts();
    let w = World::new();
    for len in [4, RECORD_V2_HEADER_LEN - 1] {
        let name = article(A, &format!("x_short_header_{len}"));
        let mut bytes = seal_record_v2(&key(A, 1), &name, b"plan", &mut SystemRng).unwrap();
        bytes.truncate(len);
        w.raw(&name, &bytes).await;
    }
    let c = w.step(WALK).await;
    assert_eq!(
        (c.source_unreadable, c.cross_scheme, c.failed, c.copied),
        (2, 0, 0, 0),
        "{c:?}"
    );
    assert_eq!((c.ring_loads, w.source.calls(A)), (0, 0));
    assert!(w.safety.get(KEY_MISS_KEY, None).await.unwrap().is_none());
    assert!(alerts().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_garbled_key_miss_marks_do_not_suppress_partial_ring_pages() {
    capture_alerts();
    let miss = format!("{A}/2");
    let future = NOW.0 + 10 * PASS_INTERVAL_MS;
    let mut oversized =
        serde_json::to_vec(&BTreeMap::from([(&miss, [future, NOW.0, future])])).unwrap();
    oversized.resize(256 * 1024, b' ');
    let marks = [
        (
            "minimum first",
            serde_json::json!([i64::MIN, NOW.0, i64::MIN]),
        ),
        (
            "maximum first",
            serde_json::json!([i64::MAX, NOW.0, i64::MIN]),
        ),
        (
            "minimum last",
            serde_json::json!([NOW.0, i64::MIN, i64::MIN]),
        ),
        (
            "maximum last",
            serde_json::json!([NOW.0, i64::MAX, i64::MIN]),
        ),
        ("future first", serde_json::json!([future, NOW.0, i64::MIN])),
        ("future paged", serde_json::json!([NOW.0, NOW.0, future])),
        ("maximum paged", serde_json::json!([NOW.0, NOW.0, i64::MAX])),
        ("non-numeric", serde_json::json!(["bad", NOW.0, i64::MIN])),
    ];
    let cases = marks.into_iter().map(|(label, mark)| {
        let bytes = serde_json::to_vec(&BTreeMap::from([(&miss, mark)])).unwrap();
        (label, bytes)
    });
    for (label, bytes) in cases.chain([("oversized", oversized)]) {
        let w = World::new();
        w.source.answer(A, [ring(A, &[1], &[1, 2], &[])]);
        w.data(A, 2, &article(A, "x_garbled_miss"), b"plan").await;
        w.raw(KEY_MISS_KEY, &bytes).await;
        for pass in 1..=5 {
            let c = w.step(WALK).await;
            assert_eq!((c.failed, c.ring_loads), (1, 2), "{label}, pass {pass}");
            let pages = alerts();
            if !pages.is_empty() || pass == 5 {
                assert_eq!(
                    pages,
                    [missing_key_page(2, "partial")],
                    "{label}, pass {pass}"
                );
            }
            w.clock.advance_ms(PASS_INTERVAL_MS);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn am80b_unreadable_ring_pages_on_pass_five_and_clears_when_readable() {
    capture_alerts();
    let w = World::new();
    let name = article(A, "x_unreadable_ring");
    w.data(A, 1, &name, b"plan").await;
    w.source
        .answer(A, [Err(BridgeError::Invalid("test ring load unavailable"))]);
    assert_eq!(w.first_job().await.failed, 1);
    assert!(alerts().is_empty());
    let miss = format!("{A}/ring");
    assert!(w.miss_marks().await.contains_key(&miss));
    for pass in 2..=6 {
        w.clock.advance_ms(PASS_INTERVAL_MS);
        let c = w.first_job().await;
        assert_eq!((c.failed, c.ring_loads), (0, 1), "pass {pass}");
        if pass < 5 {
            assert!(alerts().is_empty(), "page before pass 5 (pass {pass})");
        } else {
            assert_eq!(alerts(), [missing_key_page(0, "unreadable")], "pass {pass}");
            // A second job finds the same unavailable ring in this slot.
            assert_eq!(w.step(WALK).await.failed, 1);
            assert!(alerts().is_empty(), "duplicate page in pass {pass}");
        }
    }
    w.source.answer(A, [ring(A, &[1], &[1], &[])]);
    for pass in 7..=8 {
        w.clock.advance_ms(PASS_INTERVAL_MS);
        let c = w.first_job().await;
        assert_eq!((c.failed, c.ring_loads), (0, u64::from(pass == 7)));
        assert!(!w.miss_marks().await.contains_key(&miss));
        assert!(alerts().is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t5_default_directory_page_uses_one_list_and_advances_past_strays() {
    let w = World::new();
    for key in ["01", "02", "b01", "b02", "z01"] {
        w.raw(&format!("m/x/{key}"), b"stray").await;
    }
    for dir in ["a", "c"] {
        for i in 0..32 {
            w.raw(&format!("m/x/{dir}/k{i:02}"), b"record").await;
        }
    }
    let mut after = String::new();
    for (dirs, next) in [
        (None, Some("m/x/02")),
        (Some("m/x/a/"), Some("m/x/a0")),
        (None, Some("m/x/b02")),
        (Some("m/x/c/"), Some("m/x/c0")),
        (None, None),
    ] {
        let page = w.safety.list_dirs("m/x/", &after, 2).await.unwrap();
        assert_eq!(w.safety.dir_pages.take().len(), 1, "start_after={after:?}");
        assert_eq!(
            page.dirs,
            dirs.into_iter().collect::<Vec<_>>(),
            "start_after={after:?}"
        );
        assert_eq!(page.next.as_deref(), next, "start_after={after:?}");
        after = page.next.unwrap_or_default();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t5_sweep_finds_thirty_tenants_across_raw_directory_pages_in_one_pass() {
    let w = World::new();
    w.rest_walk().await;
    let ended = w.safety.get(WALKED_KEY, None).await.unwrap().unwrap();
    for name in ["m/x/00_stray", "m/x/t_000000000000000a", "m/x/z_stray"] {
        w.raw(name, b"stray").await;
    }
    let mut expected = Vec::new();
    for i in 1..=30 {
        let t = format!("t_{i:016x}");
        w.source.answer(&t, [ring(&t, &[1], &[1], &[])]);
        // More than PAGE raw keys overall, but only these three fresh
        // generations per tenant are in the sweep's time range.
        for extra in 0..35 {
            w.raw(
                &article(&t, &format!("x_walk_only_{extra:02}")),
                b"not swept",
            )
            .await;
        }
        for fresh in 0..3 {
            let name = generation(&t, FRESH, &format!("paged_{fresh}"));
            let bytes = w.data(&t, 1, &name, br#"{"v":1,"extents":[]}"#).await;
            expected.push((name, bytes));
        }
    }
    let pass = w.clock.now();
    let (outcome, mut counts) = w.job(pass, "").await;
    assert_eq!(outcome, JobOutcome::Ack);
    counts.add(&w.finish_pass(pass).await);
    assert_eq!(
        (counts.copied, counts.failed, counts.damaged()),
        (90, 0, 0),
        "{counts:?}"
    );
    assert!(w
        .safety
        .dir_pages
        .borrow()
        .iter()
        .any(|keys| keys.len() == PAGE as usize));
    assert_eq!(w.safety.get(WALKED_KEY, None).await.unwrap(), Some(ended));
    for (name, bytes) in expected {
        assert_eq!(w.there(&name), Some(bytes), "{name}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t5_managed_directory_requests_share_the_job_page_budget() {
    check_managed_directory_budget(30).await;
}

#[tokio::test(flavor = "current_thread")]
async fn t5_managed_directory_listing_defers_when_the_last_page_is_spent() {
    // End the last tenant's generation phase at the budget boundary,
    // before the final list_dirs call to find the end of the tenant list.
    check_managed_directory_budget(16).await;
}

async fn check_managed_directory_budget(fresh_dirs: usize) {
    let w = World::new();
    w.rest_walk().await;
    let mut records = Vec::new();
    let mut dir_visits = BTreeMap::new();
    for i in 1..=30 {
        let tenant = format!("t_{i:016x}");
        w.source.answer(&tenant, [ring(&tenant, &[1], &[1], &[])]);
        dir_visits.insert(format!("m/x/{tenant}/"), 0);
        let fresh = i <= fresh_dirs;
        let age = if fresh {
            FRESH
        } else {
            FRESH_MS + PASS_INTERVAL_MS
        };
        let name = generation(&tenant, age, "many_dirs");
        let bytes = w.data(&tenant, 1, &name, br#"{"v":1,"extents":[]}"#).await;
        records.push((name, fresh.then_some(bytes)));
    }
    let pass = w.clock.now();
    let mut cursor = String::new();
    let mut finished = false;
    let mut dir_requests = 0;
    for job in 1..=4 {
        let (outcome, c) = w.job(pass, &cursor).await;
        assert_eq!(outcome, JobOutcome::Ack);
        assert_eq!((c.failed, c.damaged()), (0, 0));
        let pages = w.safety.entry_pages.replace(0);
        let dirs = w.safety.dir_pages.take();
        let requests = pages as usize + dirs.len();
        assert!(
            requests <= JOB_PAGES as usize,
            "job {job}: {pages} entry pages + {} directory pages exceeds budget {JOB_PAGES}",
            dirs.len()
        );
        dir_requests += dirs.len();
        for key in dirs.into_iter().flatten() {
            // This fixture has exactly one record per directory.
            let (dir, _) = key.rsplit_once('/').unwrap();
            *dir_visits
                .get_mut(&format!("{dir}/"))
                .expect("unknown tenant directory") += 1;
        }
        let sent = w.jobs.take();
        if sent.is_empty() {
            assert!(job >= 3, "fixture should span several jobs");
            assert!(
                dir_requests <= job + 1,
                "too many directory listings: {dir_requests}"
            );
            finished = true;
            break;
        }
        assert_eq!(sent.len(), 1);
        let Job::RecoveryCopy {
            pass: next_pass,
            cursor: next,
            ..
        } = &sent[0].job
        else {
            panic!("expected recovery copy continuation");
        };
        assert_eq!(*next_pass, pass);
        cursor.clone_from(next);
    }
    assert!(finished, "sweep did not finish within four jobs");
    for (dir, visits) in dir_visits {
        assert!((1..=3).contains(&visits), "{dir} was listed {visits} times");
    }
    for (name, bytes) in records {
        assert_eq!(w.there(&name), bytes, "{name}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t5_sweep_copies_all_three_tenants_in_one_pass_with_walk_at_rest() {
    let w = World::new();
    w.rest_walk().await;
    let ended = w.safety.get(WALKED_KEY, None).await.unwrap().unwrap();
    let old = article(A, "x_not_swept");
    w.data(A, 1, &old, b"not part of the sweep").await;
    let mut expected = Vec::new();
    for t in [ZERO, A, B] {
        let name = generation(t, FRESH, "swept");
        let id = name.rsplit('/').next().unwrap();
        let tombstone = format!("m/x/{t}/del/{id}");
        let gone = w.data(t, 1, &tombstone, b"tombstone").await;
        expected.push((tombstone, gone));
        let bytes = w.data(t, 1, &name, br#"{"v":1,"extents":[]}"#).await;
        expected.push((name, bytes));
    }
    let (outcome, c) = w.job(w.clock.now(), "").await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!((c.copied, c.pending, c.damaged()), (6, 0, 0), "{c:?}");
    assert!(w.jobs.take().is_empty());
    assert_eq!(w.safety.get(WALKED_KEY, None).await.unwrap(), Some(ended));
    assert!(w.there(&old).is_none(), "the walk should still be resting");
    for (name, bytes) in expected {
        assert_eq!(w.there(&name), Some(bytes), "{name}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t5_walk_leaves_a_fresh_managed_generation_pending_for_the_sweep() {
    let w = World::new();
    let name = generation(A, FRESH, "missing");
    let unrelated = article(B, "x_walked");
    w.data(A, 1, &name, br#"{"v":1,"extents":[{"id":"x_missing"}]}"#)
        .await;
    let found = w.data(B, 1, &unrelated, b"walk sees this").await;
    let c = w.step(WALK).await;
    assert_eq!((c.copied, c.pending, c.damaged()), (1, 0, 0), "{c:?}");
    assert_eq!(w.there(&unrelated), Some(found));
    assert!(w.there(&name).is_none());
    let c = w.pass().await;
    assert_eq!((c.copied, c.pending, c.damaged()), (0, 1, 0), "{c:?}");
    assert!(w.there(&name).is_none());
}
