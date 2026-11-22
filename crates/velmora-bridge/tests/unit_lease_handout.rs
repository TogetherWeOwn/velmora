//! The alarm's hand-out on a unit (`unit_lease::handout`; round 5 §R5-4
//! row 5, AM-49): when it is due, what it sends, where each message goes,
//! and what is recorded after the sends.

use velmora_bridge::jobmsg::{admit_for, Admission, JobTenant, Units};
use velmora_bridge::jobs::{DISPATCH_LIMIT, EVICT_CHECK_SECS, MAX_ATTEMPTS, RESEND_SECS};
use velmora_bridge::routing::{Lane, Shards};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit_lease::handout::{
    binding, done, due_at, plan, route, unit_job_lane, Handout, HANDOUT_PERIOD_MS, SEND_BATCH,
};
use velmora_bridge::{
    Catalog, ExtentId, GenerationId, Job, OutboxStage, Resend, UnixMs, JOB_VERSION,
};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const B1: &str = "b_00000000000000e1";
const G1: &str = "g_0019a00000000e1e1e1e1e1e1e1e1";
const RESEND_MS: i64 = RESEND_SECS as i64 * 1000;
const EVICT_MS: i64 = EVICT_CHECK_SECS as i64 * 1000;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn ext(n: u32) -> String {
    format!("x_{n:026x}")
}

/// A catalogue with one bucket (`disposable` as given), one generation
/// and `n` committed extents, none in the outbox.
fn catalogue(n: u32, disposable: bool) -> SqlCatalog<RusqliteSql> {
    let sql = RusqliteSql::with_schema().unwrap();
    let mut script = format!(
        "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at, disposable) \
           VALUES ('{B1}', 'alpha', 'o', x'00', 1, 1, {}); \
         INSERT INTO generations(id, bucket_id, key, state, size, etag, content_json, \
           user_meta_json, extent_count, created_at) \
           VALUES ('{G1}', '{B1}', 'k', 'live', {n}, '\"e\"', '{{}}', '{{}}', {n}, 1);",
        i32::from(disposable)
    );
    for i in 0..n {
        script.push_str(&format!(
            "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
               plain_size, cipher_size, media_header, plain_md5, plain_sha256, cipher_sha256, \
               safety_state, created_at) \
               VALUES ('{}', '{B1}', '{G1}', 'committed', {i}, {i}, 1, 1, zeroblob(48), \
                 zeroblob(16), zeroblob(32), zeroblob(32), 'held', 1);",
            ext(i)
        ));
    }
    sql.with_conn(|c| c.execute_batch(&script)).unwrap();
    SqlCatalog::new(sql)
}

fn exec(cat: &SqlCatalog<RusqliteSql>, stmt: &str) {
    cat.sql.with_conn(|c| c.execute_batch(stmt)).unwrap();
}

fn outbox(cat: &SqlCatalog<RusqliteSql>, n: u32, stage: &str, next_at: i64) {
    exec(
        cat,
        &format!(
            "INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at) \
               VALUES ('{}', '{G1}', '{stage}', {next_at}, 1)",
            ext(n)
        ),
    );
}

fn due_rows(cat: &SqlCatalog<RusqliteSql>, at: i64) -> usize {
    let resend = Resend {
        post_secs: RESEND_SECS,
        verify_secs: RESEND_SECS,
    };
    block_on(cat.due(UnixMs(at), resend, DISPATCH_LIMIT))
        .unwrap()
        .len()
}

/// The hand-out is due exactly when `Catalog::due` would take its first
/// row, and not a millisecond before.
fn due_exactly(cat: &SqlCatalog<RusqliteSql>, want: i64) {
    assert_eq!(due_at(cat).unwrap(), Some(UnixMs(want)));
    assert_eq!(due_rows(cat, want - 1), 0, "before {want}");
    assert!(due_rows(cat, want) > 0, "at {want}");
}

// ---------------------------------------------------------------------------
// When it is due
// ---------------------------------------------------------------------------

#[test]
fn an_idle_unit_has_no_hand_out_due() {
    let cat = catalogue(2, false);
    assert_eq!(due_at(&cat).unwrap(), None);
    // Rows that no dispatcher sends (done, cancelled, dead) wait for
    // nothing.
    for (n, stage) in [(0, "done"), (1, "dead")] {
        outbox(&cat, n, stage, NOW.0);
    }
    assert_eq!(due_at(&cat).unwrap(), None);
}

/// A row's due time is its `next_at`, after its lease, and after its
/// mark's resend window when it was marked at or after `next_at`: the
/// same condition as `Catalog::due`.
#[test]
fn the_due_time_is_when_due_takes_the_row() {
    let cat = catalogue(1, false);
    outbox(&cat, 0, "post", NOW.0 + 5_000);
    due_exactly(&cat, NOW.0 + 5_000);
    // Marked after its `next_at`: once its resend window has passed.
    let mark = NOW.0 + 6_000;
    exec(&cat, &format!("UPDATE outbox SET sent_at = {mark}"));
    due_exactly(&cat, mark + RESEND_MS);
    // A mark before `next_at` (a later advance) does not hold it back.
    exec(&cat, &format!("UPDATE outbox SET sent_at = {}", NOW.0));
    due_exactly(&cat, NOW.0 + 5_000);
    // A lease holds it until after `lease_until`.
    let until = NOW.0 + 9_000;
    exec(&cat, &format!("UPDATE outbox SET lease_until = {until}"));
    due_exactly(&cat, until + 1);
    // Every stage the dispatcher sends.
    for stage in ["verify", "release"] {
        exec(
            &cat,
            &format!("UPDATE outbox SET stage = '{stage}', lease_until = NULL, sent_at = NULL"),
        );
        due_exactly(&cat, NOW.0 + 5_000);
    }
}

/// The earliest row decides, and never sooner than one period after the
/// last hand-out.
#[test]
fn the_earliest_work_decides_after_one_period_since_the_last_run() {
    let cat = catalogue(3, false);
    outbox(&cat, 0, "post", NOW.0 + 9_000);
    outbox(&cat, 1, "verify", NOW.0 + 3_000);
    outbox(&cat, 2, "release", NOW.0 + 7_000);
    assert_eq!(due_at(&cat).unwrap(), Some(UnixMs(NOW.0 + 3_000)));
    block_on(cat.record_dispatch(NOW)).unwrap();
    assert_eq!(
        due_at(&cat).unwrap(),
        Some(UnixMs(NOW.0 + HANDOUT_PERIOD_MS))
    );
}

/// A GC row of a disposable bucket is due at its `due_at`; one of a bucket
/// that is not disposable never runs (`GC_MODE` has no other mode), so it
/// is not due.
#[test]
fn a_gc_row_is_due_only_where_gc_can_run() {
    let cat = catalogue(1, false);
    let gc = format!(
        "INSERT INTO gc(extent_id, action, due_at) VALUES ('{}', 'delete_cache', {})",
        ext(0),
        NOW.0 + 4_000
    );
    exec(&cat, &gc);
    assert_eq!(due_at(&cat).unwrap(), None);
    let cat = catalogue(1, true);
    exec(&cat, &gc);
    assert_eq!(due_at(&cat).unwrap(), Some(UnixMs(NOW.0 + 4_000)));
    exec(&cat, "UPDATE gc SET done_at = 1");
    assert_eq!(due_at(&cat).unwrap(), None);
}

/// With evictable bytes the eviction check is due every
/// `EVICT_CHECK_SECS` after the last one.
#[test]
fn the_eviction_check_is_due_while_bytes_are_evictable() {
    let cat = catalogue(1, false);
    assert_eq!(due_at(&cat).unwrap(), None, "nothing evictable");
    exec(&cat, "UPDATE extents SET hot_cache_bytes = 10");
    assert!(block_on(cat.evictable_bytes()).unwrap() > 0);
    assert_eq!(due_at(&cat).unwrap(), Some(UnixMs(0)), "never checked");
    block_on(cat.hot_checked(NOW)).unwrap();
    assert_eq!(due_at(&cat).unwrap(), Some(UnixMs(NOW.0 + EVICT_MS)));
}

// ---------------------------------------------------------------------------
// What it sends, and what is recorded
// ---------------------------------------------------------------------------

#[test]
fn a_hand_out_sends_the_due_rows_and_buries_the_exhausted() {
    let cat = catalogue(3, true);
    outbox(&cat, 0, "post", NOW.0);
    outbox(&cat, 1, "verify", NOW.0 + 60_000);
    outbox(&cat, 2, "release", NOW.0);
    exec(
        &cat,
        &format!(
            "UPDATE outbox SET attempts = {} WHERE extent_id = '{}'",
            MAX_ATTEMPTS + 1,
            ext(2)
        ),
    );
    exec(
        &cat,
        &format!(
            "INSERT INTO gc(extent_id, action, due_at) VALUES ('{}', 'delete_cache', {})",
            ext(0),
            NOW.0
        ),
    );
    let h = plan(&cat, NOW).unwrap();
    let extents: Vec<&Job> = h
        .jobs
        .iter()
        .filter(|j| matches!(j, Job::Extent { .. }))
        .collect();
    assert_eq!(
        extents,
        [&Job::Extent {
            v: JOB_VERSION,
            extent: ExtentId::new(ext(0)),
            generation: GenerationId::new(G1),
            stage: OutboxStage::Post,
        }],
        "the due row, not the later one, not the exhausted one"
    );
    assert!(h.jobs.contains(&Job::Gc { v: JOB_VERSION }));
    let stage: String = cat
        .sql
        .with_conn(|c| {
            c.query_row(
                &format!("SELECT stage FROM outbox WHERE extent_id = '{}'", ext(2)),
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(stage, "dead");
}

/// Only the rows whose send went through are marked; the run is recorded
/// only when every send went through.
#[test]
fn only_what_was_sent_is_marked_and_a_failed_run_is_not_recorded() {
    let cat = catalogue(2, false);
    outbox(&cat, 0, "post", NOW.0);
    outbox(&cat, 1, "post", NOW.0);
    let h = plan(&cat, NOW).unwrap();
    assert_eq!(h.jobs.len(), 2);
    let first = match &h.jobs[0] {
        Job::Extent { extent, .. } => extent.as_str().to_string(),
        other => panic!("{other:?}"),
    };
    done(&cat, NOW, &h, &[true, false]).unwrap();
    let marked: Vec<String> = cat
        .sql
        .with_conn(|c| {
            let mut s = c
                .prepare("SELECT extent_id FROM outbox WHERE sent_at IS NOT NULL")
                .unwrap();
            s.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<std::result::Result<Vec<String>, _>>()
        })
        .unwrap();
    assert_eq!(marked, [first]);
    assert_eq!(block_on(cat.outbox_stats()).unwrap().last_dispatch_at, None);
    // The row that was not sent is due again at once.
    assert_eq!(due_rows(&cat, NOW.0 + 1), 1);
    // Every send through: the run is recorded.
    let h = plan(&cat, UnixMs(NOW.0 + 1)).unwrap();
    done(&cat, UnixMs(NOW.0 + 1), &h, &vec![true; h.jobs.len()]).unwrap();
    assert_eq!(
        block_on(cat.outbox_stats()).unwrap().last_dispatch_at,
        Some(UnixMs(NOW.0 + 1))
    );
    assert_eq!(due_rows(&cat, NOW.0 + 2), 0);
}

// ---------------------------------------------------------------------------
// Where each message goes
// ---------------------------------------------------------------------------

fn unit() -> JobTenant {
    JobTenant::of_unit("t_00000000000000a7", 2, 9, 4).unwrap()
}

/// Every hand-out job goes where tenant 0's job of the same kind and
/// extent would (`routing::lane`), in format 2 naming the unit; the
/// unit's own jobs go to `AUX_Q`, or to the first verify queue without it.
#[test]
fn every_message_is_routed_as_tenant_zeros() {
    let mut jobs: Vec<Job> = (0..300)
        .map(|n| Job::Extent {
            v: JOB_VERSION,
            extent: ExtentId::new(ext(n)),
            generation: GenerationId::new(G1),
            stage: match n % 3 {
                0 => OutboxStage::Post,
                1 => OutboxStage::Verify,
                _ => OutboxStage::Release,
            },
        })
        .collect();
    jobs.push(Job::Gc { v: JOB_VERSION });
    jobs.push(Job::Evict {
        v: JOB_VERSION,
        remaining: 0,
    });
    let own = vec![
        r#"{"t":"stamp_raise","v":2,"at":1,"tenant":"t_00000000000000a7","unit":2,"state_seq":9,"keys_seq":4}"#.to_string(),
    ];
    for shards in [
        Shards {
            post: 1,
            verify: 1,
            aux: false,
        },
        Shards {
            post: 4,
            verify: 3,
            aux: true,
        },
    ] {
        let out = route(&own, &jobs, &unit(), shards).unwrap();
        let mut seen = vec![false; jobs.len()];
        let mut own_seen = 0;
        for batch in &out {
            assert!(!batch.texts.is_empty() && batch.texts.len() <= SEND_BATCH);
            assert_eq!(batch.texts.len(), batch.handout.len());
            for (text, i) in batch.texts.iter().zip(&batch.handout) {
                let Some(i) = i else {
                    own_seen += 1;
                    assert_eq!(text, &own[0]);
                    assert_eq!(batch.binding, binding(unit_job_lane(shards)));
                    continue;
                };
                assert!(!seen[*i], "sent twice");
                seen[*i] = true;
                let job = &jobs[*i];
                assert_eq!(
                    batch.binding,
                    binding(velmora_bridge::routing::lane(job, shards))
                );
                let value: serde_json::Value = serde_json::from_str(text).unwrap();
                assert_eq!(value["tenant"], "t_00000000000000a7");
                assert_eq!(value["unit"], 2);
                assert_eq!(
                    (value["state_seq"].clone(), value["keys_seq"].clone()),
                    (9.into(), 4.into())
                );
                let Admission::Run { job: read, .. } = admit_for(&value, Units::Bound) else {
                    panic!("{text}");
                };
                assert_eq!(&read, job);
            }
        }
        assert!(seen.iter().all(|s| *s), "every job is sent once");
        assert_eq!(own_seen, 1);
    }
    let lone = Shards {
        post: 1,
        verify: 2,
        aux: false,
    };
    assert_eq!(unit_job_lane(lone), Lane::Verify(0));
    assert_eq!(binding(Lane::Verify(0)), "VERIFY_Q");
    assert_eq!(binding(Lane::Verify(1)), "VERIFY_Q2");
    assert_eq!(binding(Lane::Post(3)), "POST_Q4");
    assert_eq!(binding(Lane::Aux), "AUX_Q");
    assert_eq!(unit_job_lane(Shards { aux: true, ..lone }), Lane::Aux);
}

#[test]
fn an_empty_run_sends_nothing() {
    let out = route(
        &[],
        &Handout::default().jobs,
        &unit(),
        Shards {
            post: 2,
            verify: 2,
            aux: true,
        },
    )
    .unwrap();
    assert!(out.is_empty());
}
