//! Catalogue contract tests run on SQLite and on PostgreSQL via TestSql.

use velmora_bridge::hotctl::{FIRST, HIT_KEY, MISS_KEYS, OLDER, REUSE_HOURS};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::TestSql;
use velmora_bridge::{Catalog, ExtentId, HotShape, HotStats, SqlValue, UnixMs, MAX_SQL_PARAMS};

const CAP: &str = "hot_cap_target";
const AT: &str = "hot_ctl_at";
const BYTES: i64 = 1 << 34;
const HOUR: i64 = 3_600_000;

async fn setup() -> SqlCatalog<TestSql> {
    let db = TestSql::with_schema_unarmed().unwrap();
    db.fixture_exec(
        "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
         VALUES ('b', 'b', 'o', ?1, 1, 0)",
        &[SqlValue::Blob(vec![0])],
    )
    .await
    .unwrap();
    SqlCatalog::new(db)
}

async fn extent(
    db: &TestSql,
    id: &str,
    state: &str,
    cache: i64,
    last_read: Option<i64>,
) -> ExtentId {
    db.fixture_exec(
        "INSERT INTO extents(id, bucket_id, state, plain_size, cipher_size, media_header, \
         plain_md5, plain_sha256, cipher_sha256, safety_state, created_at, \
         hot_safety_bytes, hot_cache_bytes, last_read_at) \
         VALUES (?1, 'b', 'committed', 1, ?2, ?3, ?3, ?3, ?3, ?4, 0, ?2, ?5, ?6)",
        &[
            SqlValue::Text(id.into()),
            SqlValue::Int(BYTES),
            SqlValue::Blob(vec![0]),
            SqlValue::Text(state.into()),
            SqlValue::Int(cache),
            last_read.map_or(SqlValue::Null, SqlValue::Int),
        ],
    )
    .await
    .unwrap();
    ExtentId::new(id)
}

#[tokio::test]
async fn hot_ctl_store_refuses_missing_expected_version_after_first_write() {
    let c = SqlCatalog::new(TestSql::with_schema().unwrap());
    assert_eq!(c.hot_ctl_load(&[AT, CAP]).await.unwrap(), [None, None]);
    let at = UnixMs(1_800_000_000_000);
    let next = UnixMs(at.0 + 1);
    assert!(c
        .hot_ctl_store(None, &[(CAP, BYTES), (AT, at.0)])
        .await
        .unwrap());
    for expected in [None, Some(next), Some(UnixMs(at.0 - 1))] {
        assert!(
            !c.hot_ctl_store(expected, &[(CAP, 9), (AT, next.0)])
                .await
                .unwrap(),
            "a missing or stale expected version must not overwrite controller state: {expected:?}"
        );
        assert_eq!(
            c.hot_ctl_load(&[AT, CAP]).await.unwrap(),
            [Some(at.0), Some(BYTES)]
        );
    }
    assert!(c
        .hot_ctl_store(Some(at), &[(CAP, -BYTES), (AT, next.0)])
        .await
        .unwrap());
    assert_eq!(
        c.hot_ctl_load(&[AT, CAP]).await.unwrap(),
        [Some(next.0), Some(-BYTES)]
    );
}

#[tokio::test]
async fn hot_ctl_load_preserves_order_missing_keys_and_duplicates_at_every_arity() {
    let c = SqlCatalog::new(TestSql::with_schema().unwrap());
    assert!(c.hot_ctl_load(&[]).await.unwrap().is_empty());
    c.hot_counters_add(0).await.unwrap();
    assert_eq!(c.hot_ctl_load(&[HIT_KEY]).await.unwrap(), [None]);
    const LAST: &str = "hot_ctl_last";
    assert!(c
        .hot_ctl_store(None, &[(CAP, BYTES), (LAST, 9)])
        .await
        .unwrap());
    c.hot_counters_add(BYTES as u64).await.unwrap();
    c.hot_counters_add(7).await.unwrap();
    let keys = [HIT_KEY, AT, CAP, HIT_KEY];
    let values = [Some(BYTES + 7), None, Some(BYTES), Some(BYTES + 7)];
    for arity in 1..=MAX_SQL_PARAMS {
        // The last parameter must be used even at the largest arity.
        let requested: Vec<_> = keys
            .into_iter()
            .cycle()
            .take(arity - 1)
            .chain([LAST])
            .collect();
        let expected: Vec<_> = values
            .into_iter()
            .cycle()
            .take(arity - 1)
            .chain([Some(9)])
            .collect();
        assert_eq!(
            c.hot_ctl_load(&requested).await.unwrap(),
            expected,
            "arity {arity}"
        );
    }
    assert!(c.hot_ctl_load(&[CAP; MAX_SQL_PARAMS + 1]).await.is_err());
}

#[tokio::test]
async fn hot_ghost_adds_bytes_to_the_pre_fill_reuse_bucket() {
    let c = setup().await;
    let now = UnixMs(1_800_000_000_000);
    c.hot_ghost(&ExtentId::new("missing"), now).await.unwrap();
    assert_eq!(
        c.hot_ctl_load(&MISS_KEYS).await.unwrap(),
        [None; MISS_KEYS.len()]
    );
    let cases = REUSE_HOURS
        .map(|hours| Some(now.0 - i64::from(hours) * HOUR))
        .into_iter()
        .enumerate()
        .chain([(OLDER, Some(now.0 - 721 * HOUR)), (FIRST, None)]);
    for (bucket, last_read) in cases {
        let x = extent(&c.sql, &format!("ghost-{bucket}"), "released", 0, last_read).await;
        c.hot_ghost(&x, now).await.unwrap();
        c.hot_ghost(&x, now).await.unwrap();
        assert_eq!(
            c.hot_ctl_load(&[MISS_KEYS[bucket]]).await.unwrap(),
            [Some(2 * BYTES)]
        );
    }
    assert_eq!(
        c.hot_ctl_load(&MISS_KEYS).await.unwrap(),
        [Some(2 * BYTES); MISS_KEYS.len()]
    );
}

#[tokio::test]
async fn hot_eviction_keeps_pinned_safety_and_fences_stale_claims() {
    let c = setup().await;
    assert_eq!(c.hot_shape().await.unwrap(), HotShape::default());
    let pinned = extent(&c.sql, "z-pinned", "held", BYTES, None).await;
    let released = extent(&c.sql, "a-released", "released", 0, Some(100)).await;
    assert_eq!(
        c.hot_stats().await.unwrap(),
        HotStats {
            pinned_bytes: BYTES as u64,
            pinned_extents: 1,
            evictable_bytes: 2 * BYTES as u64,
            evictable_extents: 2,
        }
    );
    assert_eq!(
        c.hot_shape().await.unwrap(),
        HotShape {
            evictable_bytes: 2 * BYTES as u64,
            never_read_bytes: BYTES as u64,
            oldest_read_at: Some(UnixMs(100)),
        }
    );
    let limited = c.evict_candidates(1).await.unwrap();
    let [only] = limited.as_slice() else {
        panic!(
            "expected exactly one eviction candidate, got {}",
            limited.len()
        );
    };
    assert_eq!((&only.extent, only.pinned), (&pinned, true));
    let candidates = c.evict_candidates(2).await.unwrap();
    let (p, r) = (&candidates[0], &candidates[1]);
    assert_eq!(
        (&p.extent, p.pinned, &r.extent, r.pinned),
        (&pinned, true, &released, false)
    );
    for x in [p, r] {
        assert!(c.begin_evict(x).await.unwrap());
        assert!(!c.begin_evict(x).await.unwrap());
    }
    assert!(c.finish_evict(p).await.unwrap());
    assert_eq!(
        c.sql
            .fixture_query(
                "SELECT hot_safety_bytes, hot_cache_bytes FROM extents WHERE id = ?1",
                &[SqlValue::Text(pinned.to_string())],
            )
            .await
            .unwrap(),
        [vec![SqlValue::Int(BYTES), SqlValue::Int(0)]]
    );
    c.record_cache_fill(&released, UnixMs(200)).await.unwrap();
    assert!(
        !c.finish_evict(r).await.unwrap(),
        "a fresh fill invalidates the claim"
    );
    assert_eq!(
        c.touch_read(&released, UnixMs(205), 10, true)
            .await
            .unwrap(),
        UnixMs(200)
    );
    let old_seq = c.hot_seq(&released).await.unwrap();
    c.record_cache_fill(&released, UnixMs(210)).await.unwrap();
    assert!(!c.hot_forget(&released, old_seq, true, true).await.unwrap());
    let seq = c.hot_seq(&released).await.unwrap();
    assert!(c.hot_forget(&released, seq, true, false).await.unwrap());
    assert_eq!(c.evictable_bytes().await.unwrap(), BYTES as u64);
    let refreshed = c.evict_candidates(1).await.unwrap().pop().unwrap();
    assert!(c.begin_evict(&refreshed).await.unwrap());
    assert!(c.finish_evict(&refreshed).await.unwrap());
    assert_eq!(c.evictable_bytes().await.unwrap(), 0);
}

#[tokio::test]
async fn hot_drain_claims_the_current_nonzero_value_once_and_hot_sweep_keeps_a_window() {
    let c = SqlCatalog::new(TestSql::with_schema().unwrap());
    let bytes = BYTES as u64;
    assert!(!c.hot_drain_claim(bytes).await.unwrap());
    c.hot_drain_set(bytes - 1).await.unwrap();
    c.hot_drain_set(bytes).await.unwrap();
    assert!(!c.hot_drain_claim(bytes - 1).await.unwrap());
    assert!(c.hot_drain_claim(bytes).await.unwrap());
    assert!(!c.hot_drain_claim(bytes).await.unwrap());
    assert!(!c.hot_drain_claim(0).await.unwrap());

    let now = UnixMs(1_800_000_000_000);
    assert!(c.hot_check_due(now, 10).await.unwrap());
    c.hot_checked(UnixMs(now.0 - 10)).await.unwrap();
    assert!(c.hot_check_due(now, 10).await.unwrap());
    c.hot_checked(now).await.unwrap();
    assert!(!c.hot_check_due(now, 10).await.unwrap());
    assert!(c.hot_check_due(UnixMs(now.0 - 1), 10).await.unwrap());
}
