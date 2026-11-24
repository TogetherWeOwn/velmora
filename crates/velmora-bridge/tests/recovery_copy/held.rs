use super::*;

const SIX_HOURS: i64 = 6 * 60 * 60 * 1000;
const QUOTA: usize = JOB_COPIES / 4;

fn held(key: &str) -> (String, u32) {
    let minted_ms = i64::from_str_radix(&key["m/g_".len()..][..13], 16).unwrap();
    (format!("h:{key}"), (minted_ms / 1000).try_into().unwrap())
}

async fn save_held(w: &World, entries: impl IntoIterator<Item = (String, u32)>) {
    let map: BTreeMap<_, _> = entries.into_iter().collect();
    w.raw(SWEEP_KEY, serde_json::to_vec(&map).unwrap()).await;
}

async fn held_map(w: &World) -> BTreeMap<String, u32> {
    let text = known(w).await;
    if text.is_empty() {
        BTreeMap::new()
    } else {
        serde_json::from_str(&text).unwrap()
    }
}

async fn rest(w: &World, at: UnixMs) {
    w.clock.set(at);
    w.raw(STORE_KEY, w.remote.place().into_bytes()).await;
    w.raw(WALKED_KEY, at.0.to_string().into_bytes()).await;
    w.raw(
        SWEPT_KEY,
        (at.0 - PASS_INTERVAL_MS).to_string().into_bytes(),
    )
    .await;
}

async fn pass(w: &World, at: UnixMs) {
    pass_with(w, at, &w.copier()).await;
}

async fn pass_with<B: BlobStore>(
    w: &World,
    at: UnixMs,
    copier: &Copier<'_, B, TestKek, FixedClock, &'static FakeE2>,
) {
    let mut cursor = String::new();
    for _ in 0..10 {
        let (outcome, report) = copier.run_job_report(&w.jobs, at, &cursor).await;
        assert_eq!((outcome, report.error), (JobOutcome::Ack, None));
        let jobs = w.jobs.take();
        if jobs.is_empty() {
            return;
        }
        assert_eq!(jobs.len(), 1);
        let Job::RecoveryCopy { cursor: next, .. } = &jobs[0].job else {
            panic!("unexpected successor");
        };
        cursor.clone_from(next);
    }
    panic!("pass did not end");
}

#[tokio::test(flavor = "current_thread")]
async fn held_generation_is_retried_next_pass_after_leaving_the_fresh_window() {
    let w = World::with_parallel_fresh(true);
    let key = generation(FRESH_MS - PASS_INTERVAL_MS + 1, "_held");
    w.generation(&key, &["x_held"]).await;
    let now = UnixMs(NOW);
    rest(&w, now).await;
    pass(&w, now).await;
    assert!(w.e2.get(&key).is_none());
    let (held_key, stamped) = held(&key);
    assert_eq!(held_map(&w).await.get(&held_key), Some(&stamped));
    assert_eq!(time_at(&w, WANT_KEY).await, None);

    let plan = "m/art/x_held";
    w.record(plan, b"new plan").await;
    let next = UnixMs(NOW + PASS_INTERVAL_MS);
    w.clock.set(next);
    pass(&w, next).await;
    assert!(put_at(w.e2, plan).unwrap() < put_at(w.e2, &key).unwrap());
    assert!(!held_map(&w).await.contains_key(&held_key));
}

#[tokio::test(flavor = "current_thread")]
async fn held_expiry_drops_a_key_only_after_requesting_the_walk() {
    for fail in [true, false] {
        let w = World::with_parallel_fresh(true);
        let key = generation(SIX_HOURS, "_expired");
        w.generation(&key, &["x_missing"]).await;
        let (held_key, stamped) = held(&key);
        save_held(&w, [(held_key.clone(), stamped)]).await;
        let now = UnixMs(NOW);
        rest(&w, now).await;
        let source = NoMark(&w.safety, if fail { WANT_KEY } else { "unused" });
        let copier = Copier {
            safety: &source,
            kek: &w.kek,
            clock: &w.clock,
            remote: &w.remote,
            maintenance: Maintenance::Off,
        };
        assert_eq!(
            copier.run_job_report(&w.jobs, now, "").await.0,
            JobOutcome::Ack
        );
        assert_eq!(time_at(&w, WANT_KEY).await.is_none(), fail);
        assert_eq!(held_map(&w).await.contains_key(&held_key), fail);
        assert!(w.e2.get(&key).is_none());
        if fail {
            let next = UnixMs(NOW + PASS_INTERVAL_MS);
            rest(&w, next).await;
            pass(&w, next).await;
            assert_eq!(time_at(&w, WANT_KEY).await, Some(next.0.to_string()));
            assert!(!held_map(&w).await.contains_key(&held_key));
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn held_entries_take_cap_slots_and_overflow_requests_the_walk() {
    let w = World::with_parallel_fresh(true);
    let key = generation(FRESH_MS - PASS_INTERVAL_MS + 1, "_overflow");
    w.generation(&key, &["x_missing"]).await;
    let entries = (0..SWEEP_RECORDS).map(|i| held(&generation(600_000, &format!("_{i:04}"))));
    save_held(&w, entries).await;
    let now = UnixMs(NOW);
    rest(&w, now).await;
    pass(&w, now).await;
    let saved = held_map(&w).await;
    assert_eq!(saved.len(), SWEEP_RECORDS);
    assert!(!saved.contains_key(&held(&key).0));
    assert_eq!(time_at(&w, WANT_KEY).await, Some(NOW.to_string()));
    assert!(w.e2.get(&key).is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_sweep_ignores_held_markers() {
    let w = World::new();
    let key = generation(FRESH_MS - PASS_INTERVAL_MS + 1, "_legacy");
    w.generation(&key, &["x_missing"]).await;
    let entry = held(&key);
    save_held(&w, [entry.clone()]).await;
    let now = UnixMs(NOW);
    rest(&w, now).await;
    pass(&w, now).await;
    assert!(
        w.e2.get(&key).is_some(),
        "legacy publication rule is unchanged"
    );
    assert!(!held_map(&w).await.contains_key(&entry.0));
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_held_head_resumes_without_repeating_its_slice_on_redelivery() {
    let w = World::with_parallel_fresh(true);
    let key = generation(FRESH_MS + 1, "_resume");
    let sealed = w.segmented(&key, JOB_COPIES + 40, 64, true).await;
    for (name, bytes) in &sealed.segments {
        w.e2.set(name, bytes);
    }
    let first_plan = format!("m/art/{}", sealed.plain[0].extents[0].id);
    let (marker, stamp) = held(&key);
    save_held(&w, [(marker.clone(), stamp)]).await;
    let now = UnixMs(NOW);
    rest(&w, now).await;
    pass(&w, now).await;
    assert!(w.e2.get(&key).is_none());
    assert_eq!(held_map(&w).await.get(&key), Some(&(JOB_COPIES as u32 - 1)));
    pass(&w, now).await;
    assert!(
        w.e2.get(&key).is_none(),
        "redelivery must not consume a second held slice"
    );

    let next = UnixMs(NOW + PASS_INTERVAL_MS);
    rest(&w, next).await;
    pass(&w, next).await;
    assert!(w.e2.get(&key).is_some());
    assert!(!held_map(&w).await.contains_key(&marker));
    assert_eq!(
        asked_for(w.e2, "HEAD", &first_plan),
        2,
        "one missing HEAD, one PUT verification"
    );
}

/// A listing includes metadata without issuing a GET for each object, as R2 does.
struct ListedSource<'a>(&'a MemBlobStore);

impl BlobStore for ListedSource<'_> {
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.0.get(key, span).await
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.0.put(key, bytes, meta).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.0.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.0.delete(key).await
    }
    async fn delete_record(&self, refused: &recovery::Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<String>> {
        self.0.list(prefix, after, limit).await
    }
    async fn list_entries(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<BlobEntry>> {
        Ok(self
            .list(prefix, after, limit)
            .await?
            .into_iter()
            .map(|key| {
                let bytes = self.0.stored(&key).unwrap().bytes;
                BlobEntry {
                    key,
                    size: bytes.len() as u64,
                    md5: md5_hex(&bytes),
                }
            })
            .collect())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn held_slice_rotates_with_an_oversized_head_and_leaves_room_for_fresh_work() {
    let w = World::with_parallel_fresh(true);
    let age = FRESH_MS + 1;
    let keys: Vec<_> = (0..SWEEP_RECORDS)
        .map(|i| generation(age, &format!("_{i:04}")))
        .collect();
    let oversized = &keys[10];
    const SEGMENTS: usize = 64;
    let sealed = w.segmented(oversized, SEGMENTS, 1, true).await;
    for (key, bytes) in sealed.segments {
        w.e2.set(&key, &bytes);
    }
    for key in keys.iter().filter(|key| *key != oversized) {
        // Cost one generation read each, but remain on the ring for retry.
        w.record(key, b"not a generation manifest").await;
    }
    save_held(&w, keys.iter().map(|key| held(key))).await;
    let ops = keys.len() - 1 + 1 + 2 * SEGMENTS;
    let passes = ops.div_ceil(QUOTA) + 1;
    let aged_prefix = &keys[0][.."m/g_".len() + 13];
    let copier = Copier {
        safety: &ListedSource(&w.safety),
        kek: &w.kek,
        clock: &w.clock,
        remote: &w.remote,
        maintenance: Maintenance::Off,
    };
    for i in 0..passes {
        let at = UnixMs(NOW + i as i64 * PASS_INTERVAL_MS);
        rest(&w, at).await;
        let fresh = generation(2 * MIN_AGE_MS - i as i64 * PASS_INTERVAL_MS, "_fresh");
        w.generation(&fresh, &[]).await;
        let before = w.safety.gets_under(aged_prefix);
        let was_published = w.e2.get(oversized).is_some();
        pass_with(&w, at, &copier).await;
        let reads = w.safety.gets_under(aged_prefix) - before;
        if !was_published && w.e2.get(oversized).is_some() {
            assert_eq!(reads, 1, "oversized head must own the entire slice");
        } else {
            assert!(reads <= QUOTA as u64, "held reads: {reads}");
        }
        assert!(
            w.e2.get(&fresh).is_some(),
            "fresh sweep made no progress in pass {i}"
        );
    }
    assert!(w.e2.get(oversized).is_some());
    assert!(keys.iter().all(|key| w.safety.gets_under(key) > 0));
}
