//! The usage counters (migration 0020) against the tables they count.
//!
//! - Random sequences of row changes, failed batches, rolled-back
//!   transactions and recount steps: whenever the counters are switched
//!   on, they equal what the tables say.
//! - The recount: bounded chunks, resumable, reports a difference and
//!   replaces the counters only when asked to.
//! - The migration: additive, reads no table, and leaves a Worker from
//!   before it with the row counts it had.
//! - Migration 0025: a release by the verify job is counted as a verify
//!   and a release, and nothing else is counted differently.

use velmora_bridge::sql::usage::{
    BUCKET_TOTALS, COUNTERS, OLDEST, RECOUNT_CHUNK_MAX, STEP_EXTENTS, STEP_GENERATIONS_BUCKETS,
    STEP_GENERATIONS_CURSOR, STEP_OUTBOX,
};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::*;
use velmora_bridge::*;

const T0: i64 = 1_762_992_000_123;

/// xorshift64*: the sequences are the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<'a>(&mut self, of: &[&'a str]) -> &'a str {
        of[self.below(of.len() as u64) as usize]
    }
}

const SAFETY: [&str; 4] = ["held", "releasing", "released", "deleted"];
const STAGES: [&str; 6] = ["post", "verify", "release", "done", "cancelled", "dead"];
const GEN_STATES: [&str; 3] = ["live", "superseded", "deleted"];
const BUCKETS: [&str; 3] = ["b_1", "b_2", "b_3"];

fn row(db: &RusqliteSql, sql: &str, n: usize) -> Vec<i64> {
    db.with_conn(|c| {
        c.query_row(sql, (), |r| (0..n).map(|i| r.get::<_, i64>(i)).collect())
            .unwrap()
    })
}

/// The level counters of row `id`, in the order of [`TRUTH`].
fn levels(db: &RusqliteSql, id: i64) -> Vec<i64> {
    row(
        db,
        &format!(
            "SELECT x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted, \
                    ob_post, ob_verify, ob_release, ob_done, ob_cancelled, ob_dead \
               FROM usage_global WHERE id = {id}"
        ),
        11,
    )
}

/// The same figures, counted from the tables.
const TRUTH: &str = "SELECT \
  (SELECT COUNT(*) FROM extents WHERE safety_state IN ('held', 'releasing')), \
  (SELECT COALESCE(SUM(cipher_size), 0) FROM extents \
    WHERE safety_state IN ('held', 'releasing')), \
  (SELECT COUNT(*) FROM extents WHERE safety_state = 'released'), \
  (SELECT COALESCE(SUM(cipher_size), 0) FROM extents WHERE safety_state = 'released'), \
  (SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'), \
  (SELECT COUNT(*) FROM outbox WHERE stage = 'post'), \
  (SELECT COUNT(*) FROM outbox WHERE stage = 'verify'), \
  (SELECT COUNT(*) FROM outbox WHERE stage = 'release'), \
  (SELECT COUNT(*) FROM outbox WHERE stage = 'done'), \
  (SELECT COUNT(*) FROM outbox WHERE stage = 'cancelled'), \
  (SELECT COUNT(*) FROM outbox WHERE stage = 'dead')";

fn pairs(db: &RusqliteSql, sql: &str) -> Vec<(String, i64, i64)> {
    db.with_conn(|c| {
        let mut stmt = c.prepare(sql).unwrap();
        let rows = stmt.query_map((), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)));
        rows.unwrap().map(|r| r.unwrap()).collect()
    })
}

/// Live objects per bucket as the counters have them. A row of zeros
/// is a bucket without live objects.
fn bucket_counters(db: &RusqliteSql) -> Vec<(String, i64, i64)> {
    pairs(
        db,
        "SELECT bucket_id, live_objects, live_bytes FROM usage_buckets \
          WHERE kind = 1 AND (live_objects <> 0 OR live_bytes <> 0) ORDER BY 1",
    )
}

fn bucket_truth(db: &RusqliteSql) -> Vec<(String, i64, i64)> {
    pairs(
        db,
        "SELECT bucket_id, COUNT(*), SUM(size) FROM generations WHERE state = 'live' \
          GROUP BY bucket_id HAVING COUNT(*) <> 0 OR SUM(size) <> 0 ORDER BY 1",
    )
}

fn armed(db: &RusqliteSql) -> bool {
    row(
        db,
        "SELECT all_x AND all_o AND all_g FROM usage_global WHERE id = 1",
        1,
    )[0] == 1
}

/// The counters equal the tables. `at` names the place in a failure.
fn assert_exact(db: &RusqliteSql, at: &str) {
    assert_eq!(levels(db, 1), row(db, TRUTH, 11), "levels, {at}");
    assert_eq!(bucket_counters(db), bucket_truth(db), "buckets, {at}");
}

fn add_buckets(db: &RusqliteSql) {
    db.with_conn(|c| {
        for b in BUCKETS {
            c.execute(
                "INSERT INTO buckets (id, name, owner, bdk_wrapped, kek_version, created_at) \
                 VALUES (?1, ?1 || '-name', 'o', x'00', 1, 0)",
                (b,),
            )
            .unwrap();
        }
    });
}

const ADD_EXTENT: &str = "INSERT INTO extents (id, bucket_id, state, plain_size, cipher_size, \
     media_header, plain_md5, plain_sha256, cipher_sha256, safety_state, created_at) \
   VALUES (?1, ?2, 'committed', ?3, ?3, x'00', x'00', x'00', x'00', ?4, 0)";
const ADD_OUTBOX: &str =
    "INSERT INTO outbox (extent_id, generation_id, stage, next_at, updated_at) \
   VALUES (?1, 'g', ?2, ?3, ?3)";
const ADD_GENERATION: &str = "INSERT INTO generations (id, bucket_id, key, state, size, etag, \
     content_json, user_meta_json, extent_count, created_at) \
   VALUES (?1, ?2, ?1, ?3, ?4, 'e', '{}', '{}', 0, 0)";

/// What the event counters must say: kept beside the database, moved
/// only for a change that happened while the counters were on.
#[derive(Default, Debug, PartialEq, Eq)]
struct Totals {
    posts: i64,
    verifies: i64,
    releases: i64,
    dead: i64,
    failures: i64,
}

fn totals(db: &RusqliteSql) -> Totals {
    let t = row(
        db,
        "SELECT posts_total, verifies_total, releases_total, dead_total, failures_total \
           FROM usage_global WHERE id = 1",
        5,
    );
    Totals {
        posts: t[0],
        verifies: t[1],
        releases: t[2],
        dead: t[3],
        failures: t[4],
    }
}

/// The filed hours and the hour under way add up to every event
/// counted, an `off` in between or not.
fn hourly_sum(db: &RusqliteSql) -> Totals {
    let t = row(
        db,
        "SELECT h_posts + (SELECT COALESCE(SUM(posts), 0) FROM usage_hours), \
                h_verifies + (SELECT COALESCE(SUM(verifies), 0) FROM usage_hours), \
                h_releases + (SELECT COALESCE(SUM(releases), 0) FROM usage_hours), \
                h_dead + (SELECT COALESCE(SUM(dead), 0) FROM usage_hours), \
                h_failures + (SELECT COALESCE(SUM(failures), 0) FROM usage_hours) \
           FROM usage_global WHERE id = 1",
        5,
    );
    Totals {
        posts: t[0],
        verifies: t[1],
        releases: t[2],
        dead: t[3],
        failures: t[4],
    }
}

/// One random sequence. Returns how many recounts ended.
async fn run_sequence(seed: u64, start_armed: bool, steps: u32) -> u32 {
    let db = if start_armed {
        RusqliteSql::with_schema().unwrap()
    } else {
        RusqliteSql::with_schema_unarmed().unwrap()
    };
    add_buckets(&db);
    let catalog = SqlCatalog::new(db);
    let db = &catalog.sql;
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut now = T0;
    let mut model = Totals::default();
    // The same since the counters were last switched off.
    let mut since = Totals::default();
    let mut ended = 0;
    // Ids are drawn from a small space, so that a new row lands before
    // the recount's cursor as often as after it.
    let xid = |rng: &mut Rng| format!("x_{:03}", rng.below(160));
    let gid = |rng: &mut Rng| format!("g_{:03}", rng.below(160));

    for step in 0..steps {
        let at = format!("seed {seed}, step {step}");
        if rng.below(4) == 0 {
            now += (rng.below(50) * 60_000) as i64;
        }
        let on = armed(db);
        match rng.below(100) {
            0..=17 => {
                let (id, b, s) = (xid(&mut rng), rng.pick(&BUCKETS), rng.pick(&SAFETY));
                let size = rng.below(5_000) as i64;
                let _ = db.with_conn(|c| c.execute(ADD_EXTENT, (id, b, size, s)));
            }
            18..=27 => {
                let (id, s) = (xid(&mut rng), rng.pick(&SAFETY));
                let _ = db.with_conn(|c| {
                    c.execute(
                        "UPDATE extents SET safety_state = ?2 WHERE id = ?1",
                        (id, s),
                    )
                });
            }
            28..=30 => {
                let (id, size) = (xid(&mut rng), rng.below(5_000) as i64);
                let _ = db.with_conn(|c| {
                    c.execute(
                        "UPDATE extents SET cipher_size = ?2 WHERE id = ?1",
                        (id, size),
                    )
                });
            }
            // Refused by the foreign key while the extent has an outbox row.
            31..=35 => {
                let id = xid(&mut rng);
                let _ = db.with_conn(|c| c.execute("DELETE FROM extents WHERE id = ?1", (id,)));
            }
            36..=47 => {
                let (id, s) = (xid(&mut rng), rng.pick(&STAGES));
                let _ = db.with_conn(|c| c.execute(ADD_OUTBOX, (id, s, now)));
            }
            48..=62 => {
                let (id, new) = (xid(&mut rng), rng.pick(&STAGES));
                let old: Option<String> = db.with_conn(|c| {
                    c.query_row(
                        "SELECT stage FROM outbox WHERE extent_id = ?1",
                        (&id,),
                        |r| r.get(0),
                    )
                    .ok()
                });
                let n = db
                    .with_conn(|c| {
                        c.execute(
                            "UPDATE outbox SET stage = ?2, updated_at = ?3 WHERE extent_id = ?1",
                            (&id, new, now),
                        )
                    })
                    .unwrap();
                if let (true, 1, Some(old)) = (on, n, old.as_deref()) {
                    if old != new {
                        model.posts += i64::from(old == "post" && new == "verify");
                        since.posts += i64::from(old == "post" && new == "verify");
                        model.verifies +=
                            i64::from(old == "verify" && matches!(new, "release" | "done"));
                        since.verifies +=
                            i64::from(old == "verify" && matches!(new, "release" | "done"));
                        model.releases += i64::from(old == "release" && new == "done");
                        since.releases += i64::from(old == "release" && new == "done");
                        model.dead += i64::from(new == "dead");
                        since.dead += i64::from(new == "dead");
                    }
                }
            }
            63..=66 => {
                let id = xid(&mut rng);
                let n = db
                    .with_conn(|c| {
                        c.execute(
                            "UPDATE outbox SET last_error = 'e', attempts = attempts + 1, \
                               updated_at = ?2 WHERE extent_id = ?1",
                            (&id, now),
                        )
                    })
                    .unwrap();
                if on && n == 1 {
                    model.failures += 1;
                    since.failures += 1;
                }
            }
            67..=69 => {
                let id = xid(&mut rng);
                let _ =
                    db.with_conn(|c| c.execute("DELETE FROM outbox WHERE extent_id = ?1", (id,)));
            }
            70..=79 => {
                let (id, b, s) = (gid(&mut rng), rng.pick(&BUCKETS), rng.pick(&GEN_STATES));
                let size = rng.below(9_000) as i64;
                let _ = db.with_conn(|c| c.execute(ADD_GENERATION, (id, b, s, size)));
            }
            80..=85 => {
                let (id, s) = (gid(&mut rng), rng.pick(&GEN_STATES));
                let _ = db.with_conn(|c| {
                    c.execute("UPDATE generations SET state = ?2 WHERE id = ?1", (id, s))
                });
            }
            86..=87 => {
                let (id, size) = (gid(&mut rng), rng.below(9_000) as i64);
                let _ = db.with_conn(|c| {
                    c.execute("UPDATE generations SET size = ?2 WHERE id = ?1", (id, size))
                });
            }
            88..=89 => {
                let id = gid(&mut rng);
                let _ = db.with_conn(|c| c.execute("DELETE FROM generations WHERE id = ?1", (id,)));
            }
            // A batch whose last statement fails: all of it is undone,
            // the counter changes of its first statements too.
            90..=91 => {
                let before = (levels(db, 1), levels(db, 2), bucket_counters(db));
                let failed = db
                    .batch(vec![
                        (
                            "UPDATE extents SET safety_state = 'released'",
                            Vec::<SqlValue>::new(),
                        ),
                        ("UPDATE outbox SET stage = 'done'", vec![]),
                        ("UPDATE generations SET state = 'deleted'", vec![]),
                        ("INSERT INTO tx_guard (ok) VALUES (0)", vec![]),
                    ])
                    .await;
                assert!(
                    matches!(failed, Err(velmora_bridge::types::BridgeError::GuardFailed)),
                    "{at}: {failed:?}"
                );
                assert_eq!(
                    before,
                    (levels(db, 1), levels(db, 2), bucket_counters(db)),
                    "a failed batch moved a counter, {at}"
                );
            }
            // A transaction that is rolled back.
            92 => {
                let before = (levels(db, 1), levels(db, 2), totals(db));
                db.with_conn(|c| {
                    c.execute_batch(
                        "BEGIN; DELETE FROM outbox; UPDATE extents SET safety_state = 'deleted'; \
                         DELETE FROM generations WHERE state = 'live'; ROLLBACK;",
                    )
                })
                .unwrap();
                assert_eq!(before, (levels(db, 1), levels(db, 2), totals(db)), "{at}");
            }
            93..=94 => {
                let (adopt, restart) = (rng.below(3) == 0, rng.below(4) == 0);
                catalog
                    .usage_recount_start(UnixMs(now), adopt, restart, false)
                    .await
                    .unwrap();
            }
            95..=98 => {
                let chunk = 1 + rng.below(60) as u32;
                let out = catalog
                    .usage_recount_step(chunk, UnixMs(now))
                    .await
                    .unwrap();
                assert!(out.rows <= u64::from(chunk), "{at}");
                if let Some(done) = out.finished {
                    ended += 1;
                    // Counters that were on were right all along: the
                    // recount finds nothing.
                    if on {
                        assert_eq!(done.drift, 0, "{at}: {:?}", done.detail);
                    } else {
                        assert!(done.adopted, "{at}");
                    }
                    assert!(armed(db), "{at}");
                }
            }
            _ => {
                if rng.below(4) == 0 {
                    catalog.usage_off().await.unwrap();
                    since = Totals::default();
                }
            }
        }
        if armed(db) {
            assert_exact(db, &at);
        }
        assert_eq!(totals(db), since, "totals, {at}");
        assert_eq!(hourly_sum(db), model, "hours, {at}");
    }

    // Whatever state the sequence ended in: a recount from the start
    // ends with the counters on and exact.
    let was_on = armed(db);
    assert!(catalog
        .usage_recount_start(UnixMs(now), false, true, false)
        .await
        .unwrap());
    let done = loop {
        let out = catalog.usage_recount_step(7, UnixMs(now)).await.unwrap();
        assert!(!out.idle);
        if let Some(done) = out.finished {
            break done;
        }
    };
    assert_eq!((done.drift, done.adopted), (0, !was_on), "seed {seed}");
    assert!(armed(db));
    assert_exact(db, &format!("seed {seed}, end"));
    ended + 1
}

#[tokio::test]
async fn counters_equal_the_tables_after_any_sequence() {
    let mut ended = 0;
    for seed in 0..60 {
        ended += run_sequence(seed, seed % 2 == 0, 500).await;
    }
    // The sequences did end recounts in the middle of the changes.
    assert!(ended > 100, "{ended}");
}

// ---------------------------------------------------------------------------
// The recount
// ---------------------------------------------------------------------------

/// `n` extents with an outbox row each and `n` live generations.
fn fill(db: &RusqliteSql, n: u32) {
    add_buckets(db);
    db.with_conn(|c| {
        for i in 0..n {
            let (x, g) = (format!("x_{i:05}"), format!("g_{i:05}"));
            let b = BUCKETS[(i % 3) as usize];
            c.execute(
                ADD_EXTENT,
                (&x, b, 100 + i64::from(i), SAFETY[(i % 4) as usize]),
            )
            .unwrap();
            c.execute(ADD_OUTBOX, (&x, STAGES[(i % 6) as usize], T0))
                .unwrap();
            c.execute(ADD_GENERATION, (&g, b, "live", 10 + i64::from(i)))
                .unwrap();
        }
    });
}

#[tokio::test]
async fn the_first_recount_switches_the_counters_on_in_bounded_steps() {
    let db = RusqliteSql::with_schema_unarmed().unwrap();
    fill(&db, 25);
    let catalog = SqlCatalog::new(db);
    let db = &catalog.sql;

    // As the migration leaves it: nothing counted, nothing running.
    let before = catalog.usage_counters().await.unwrap();
    assert!(!before.seeded);
    assert_eq!(levels(db, 1), vec![0; 11]);
    let idle = catalog.usage_recount_step(10, UnixMs(T0)).await.unwrap();
    assert!(idle.idle && idle.rows == 0 && idle.finished.is_none());

    assert!(catalog
        .usage_recount_start(UnixMs(T0), false, false, false)
        .await
        .unwrap());
    // A second start does not begin again.
    assert!(!catalog
        .usage_recount_start(UnixMs(T0 + 1), false, false, false)
        .await
        .unwrap());

    // 25 rows a table, 10 a step: 10, 10, 5 for each, then the end.
    let mut seen = Vec::new();
    let done = loop {
        let (state, _) = catalog.usage_recounts().await.unwrap();
        // Rows written meanwhile are counted, on either side of the cursor.
        if seen.len() == 4 {
            db.with_conn(|c| {
                c.execute(ADD_EXTENT, ("x_00000a", "b_1", 7_i64, "held"))
                    .unwrap();
                c.execute(ADD_EXTENT, ("x_99999", "b_1", 9_i64, "held"))
                    .unwrap();
                c.execute(
                    "UPDATE outbox SET stage = 'dead' WHERE extent_id = 'x_00001'",
                    (),
                )
                .unwrap();
                c.execute(
                    "UPDATE outbox SET stage = 'dead' WHERE extent_id = 'x_00024'",
                    (),
                )
                .unwrap();
                c.execute("DELETE FROM generations WHERE id = 'g_00003'", ())
                    .unwrap();
            });
        }
        // The counters stay off until the recount has ended.
        assert!(!catalog.usage_counters().await.unwrap().seeded);
        let out = catalog
            .usage_recount_step(10, UnixMs(T0 + 5))
            .await
            .unwrap();
        seen.push((state.table, out.rows));
        if let Some(done) = out.finished {
            break done;
        }
    };
    assert_eq!(
        seen,
        [
            ("extents", 10),
            ("extents", 10),
            ("extents", 5),
            ("outbox", 10),
            ("outbox", 10),
            ("outbox", 5),
            ("generations", 10),
            ("generations", 10),
            ("generations", 4),
            ("finish", 0),
        ]
    );
    assert!(done.adopted);
    assert_eq!((done.drift, done.rows, done.detail.clone()), (0, 74, None));
    assert_eq!(
        (done.started_at, done.finished_at),
        (UnixMs(T0), UnixMs(T0 + 5))
    );
    assert!(catalog.usage_counters().await.unwrap().seeded);
    assert_exact(db, "after the first recount");
    // The recount's own rows are cleared.
    assert_eq!(
        row(db, "SELECT COUNT(*) FROM usage_buckets WHERE kind = 2", 1),
        [0]
    );
    let (state, last) = catalog.usage_recounts().await.unwrap();
    assert!(!state.running);
    assert_eq!(last, Some(done));
}

#[tokio::test]
async fn a_recount_reports_a_difference_and_replaces_only_when_asked() {
    let db = RusqliteSql::with_schema().unwrap();
    fill(&db, 12);
    let catalog = SqlCatalog::new(db);
    let db = &catalog.sql;
    assert_exact(db, "filled");

    // A counter that went wrong, however it did.
    db.apply(
        "UPDATE usage_global SET ob_post = ob_post + 3, unreleased_bytes = 1 WHERE id = 1; \
         UPDATE usage_buckets SET live_objects = live_objects + 1 \
          WHERE kind = 1 AND bucket_id = 'b_2';",
    )
    .unwrap();
    let wrong = levels(db, 1);

    let finish = |adopt: bool| {
        let catalog = &catalog;
        async move {
            assert!(catalog
                .usage_recount_start(UnixMs(T0), adopt, false, false)
                .await
                .unwrap());
            loop {
                let out = catalog.usage_recount_step(5, UnixMs(T0)).await.unwrap();
                if let Some(done) = out.finished {
                    break done;
                }
            }
        }
    };

    // Reported, and left as it is: a difference is looked at first.
    let done = finish(false).await;
    assert_eq!((done.drift, done.adopted), (3, false));
    let detail = done.detail.expect("detail");
    assert!(detail.contains("\"buckets_differing\":1"), "{detail}");
    assert!(detail.contains("\"unreleased_bytes\":1,"), "{detail}");
    assert_eq!(levels(db, 1), wrong);

    // Asked to: replaced.
    let done = finish(true).await;
    assert_eq!((done.drift, done.adopted), (3, true));
    assert_exact(db, "adopted");
    let done = finish(false).await;
    assert_eq!((done.drift, done.adopted), (0, false));
}

#[tokio::test]
async fn a_restart_drops_the_recount_under_way_and_off_stops_the_counters() {
    let db = RusqliteSql::with_schema().unwrap();
    fill(&db, 9);
    let catalog = SqlCatalog::new(db);
    let db = &catalog.sql;
    assert!(catalog
        .usage_recount_start(UnixMs(T0), false, false, false)
        .await
        .unwrap());
    for _ in 0..8 {
        catalog.usage_recount_step(4, UnixMs(T0)).await.unwrap();
    }
    let (state, _) = catalog.usage_recounts().await.unwrap();
    assert_eq!((state.table, state.rows_seen), ("generations", 26));

    assert!(catalog
        .usage_recount_start(UnixMs(T0 + 9), true, true, false)
        .await
        .unwrap());
    let (state, _) = catalog.usage_recounts().await.unwrap();
    assert_eq!(
        (state.table, state.rows_seen, state.started_at, state.adopt),
        ("extents", 0, UnixMs(T0 + 9), true)
    );
    assert_eq!(levels(db, 2), vec![0; 11]);
    assert_eq!(
        row(db, "SELECT COUNT(*) FROM usage_buckets WHERE kind = 2", 1),
        [0]
    );

    // Off: no trigger writes again, and the recount is gone. The event
    // totals and the hour under way start again from zero.
    let events = "SELECT posts_total + verifies_total + releases_total + dead_total \
                  + failures_total + hour + h_posts + h_verifies + h_releases + h_dead \
                  + h_failures FROM usage_global WHERE id = 1";
    db.apply("UPDATE outbox SET stage = 'verify', updated_at = 7200000 WHERE stage = 'post'")
        .unwrap();
    assert!(row(db, events, 1)[0] > 0);
    let counted = hourly_sum(db);
    catalog.usage_off().await.unwrap();
    assert_eq!(row(db, events, 1), [0]);
    // The hour that was under way is filed, not lost.
    assert_eq!(hourly_sum(db), counted);
    assert!(counted.posts > 0);
    // Counting that goes on within that same hour adds to the filed
    // hour when it is filed again.
    db.apply(ARM_USAGE).unwrap();
    db.apply("UPDATE outbox SET stage = 'release', updated_at = 7200001 WHERE stage = 'verify'")
        .unwrap();
    // The snapshot shows that hour whole while it is under way: what
    // the off filed and what came after, once.
    let snap = catalog.usage_snapshot(48).await.unwrap();
    assert_eq!(
        (snap.counters.current.hour, snap.counters.current.posts),
        (2, counted.posts)
    );
    assert!(snap.counters.current.verifies > 0);
    assert!(snap.hours.iter().all(|h| h.hour != 2));
    db.apply("UPDATE outbox SET stage = 'done', updated_at = 10800000 WHERE stage = 'release'")
        .unwrap();
    let again = hourly_sum(db);
    assert_eq!(again.posts, counted.posts);
    assert!(again.verifies > 0 && again.releases > 0);
    assert_eq!(
        row(
            db,
            "SELECT posts, verifies FROM usage_hours WHERE hour = 2",
            2
        ),
        [again.posts, again.verifies]
    );
    // The same through the other two places that file an hour: a
    // second off (hour 3, with its releases), then a recorded failure
    // of a later hour that files hour 3 again, with a failure in it.
    catalog.usage_off().await.unwrap();
    assert_eq!(hourly_sum(db), again);
    db.apply(ARM_USAGE).unwrap();
    let fail = |at: i64| {
        let sql = format!(
            "UPDATE outbox SET last_error = 'e', attempts = attempts + 1, updated_at = {at} \
              WHERE extent_id = (SELECT MIN(extent_id) FROM outbox)"
        );
        db.apply(&sql).unwrap();
    };
    fail(10_800_001);
    fail(14_400_000);
    assert_eq!(
        row(
            db,
            "SELECT releases, failures FROM usage_hours WHERE hour = 3",
            2
        ),
        [again.releases, 1]
    );
    catalog.usage_off().await.unwrap();
    assert!(!catalog.usage_counters().await.unwrap().seeded);
    assert!(!catalog.usage_recounts().await.unwrap().0.running);
    // The weekly recount starts only while the counters are on: one
    // that read "on" before the off does not start, and cannot switch
    // them back on.
    assert!(!catalog
        .usage_recount_start(UnixMs(T0 + 10), false, false, true)
        .await
        .unwrap());
    assert!(!catalog
        .usage_recount_start(UnixMs(T0 + 10), false, true, true)
        .await
        .unwrap());
    assert!(!catalog.usage_recounts().await.unwrap().0.running);
    let frozen = (levels(db, 1), bucket_counters(db));
    db.meter_writes().unwrap();
    db.reset_writes();
    db.with_conn(|c| {
        c.execute(ADD_EXTENT, ("x_new", "b_1", 5_i64, "held"))
            .unwrap();
        c.execute(ADD_OUTBOX, ("x_new", "post", T0)).unwrap();
        c.execute(
            "UPDATE outbox SET stage = 'verify' WHERE extent_id = 'x_new'",
            (),
        )
        .unwrap();
        c.execute(ADD_GENERATION, ("g_new", "b_1", "live", 5_i64))
            .unwrap();
    });
    assert_eq!(frozen, (levels(db, 1), bucket_counters(db)));
    let written = db.writes();
    assert!(
        written
            .by_table
            .keys()
            .all(|(table, _)| !table.starts_with("usage_")),
        "{:?}",
        written.by_table.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_step_counts_no_more_than_the_largest_chunk() {
    let db = RusqliteSql::with_schema_unarmed().unwrap();
    add_buckets(&db);
    db.with_conn(|c| {
        for i in 0..(RECOUNT_CHUNK_MAX + 50) {
            c.execute(ADD_EXTENT, (format!("x_{i:05}"), "b_1", 1_i64, "held"))
                .unwrap();
        }
    });
    let catalog = SqlCatalog::new(db);
    catalog
        .usage_recount_start(UnixMs(T0), false, false, false)
        .await
        .unwrap();
    let out = catalog
        .usage_recount_step(u32::MAX, UnixMs(T0))
        .await
        .unwrap();
    assert_eq!(out.rows, u64::from(RECOUNT_CHUNK_MAX));
    let out = catalog
        .usage_recount_step(u32::MAX, UnixMs(T0))
        .await
        .unwrap();
    assert_eq!(out.rows, 50);
}

fn plan(db: &RusqliteSql, sql: &str, params: usize) -> Vec<String> {
    db.with_conn(|c| {
        let mut stmt = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        for i in 1..=params {
            stmt.raw_bind_parameter(i, 10_i64).unwrap();
        }
        let mut rows = stmt.raw_query();
        let mut out = Vec::new();
        while let Some(r) = rows.next().unwrap() {
            out.push(r.get::<_, String>(3).unwrap());
        }
        out
    })
}

/// No statement of the recount or of a dashboard read walks a table:
/// each goes into `extents`, `outbox` or `generations` through an index,
/// at the cursor, and stops at its `LIMIT`.
#[test]
fn every_statement_reads_through_an_index() {
    let db = RusqliteSql::with_schema().unwrap();
    for (sql, params, table) in [
        (STEP_EXTENTS, 1, "extents"),
        (STEP_OUTBOX, 1, "outbox"),
        (STEP_GENERATIONS_BUCKETS, 1, "generations"),
        (STEP_GENERATIONS_CURSOR, 1, "generations"),
        (OLDEST, 0, "outbox"),
    ] {
        let plan = plan(&db, sql, params);
        let on_table: Vec<&String> = plan
            .iter()
            .filter(|l| l.split_whitespace().nth(1) == Some(table))
            .collect();
        assert!(!on_table.is_empty(), "{table}: {plan:?}");
        for line in on_table {
            assert!(
                line.starts_with("SEARCH") && line.contains("INDEX"),
                "{table} is not read through an index: {plan:?}"
            );
        }
    }
    // The counters themselves: two rows, and one row per bucket.
    for sql in [COUNTERS, BUCKET_TOTALS] {
        let plan = plan(&db, sql, 0);
        for big in ["extents", "outbox", "generations", "objects", "articles"] {
            assert!(
                plan.iter()
                    .all(|l| l.split_whitespace().nth(1) != Some(big)),
                "{plan:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The migration and a Worker from before it
// ---------------------------------------------------------------------------

/// The statements of the migration outside its triggers.
fn top_level(script: &str) -> Vec<String> {
    let text: String = script
        .lines()
        .map(|l| l.split_once("--").map_or(l, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find("CREATE TRIGGER") {
        out.extend(rest[..at].split(';').map(str::to_string));
        let end = rest[at..].find("\nEND;").expect("trigger end") + at + 5;
        rest = &rest[end..];
    }
    out.extend(rest.split(';').map(str::to_string));
    out.into_iter()
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Additive, and no work at migration time: new tables, new triggers
/// and two constant rows. Nothing is altered, dropped, indexed or read,
/// so the migration takes the same time on any catalogue; the backfill
/// is the recount, run afterwards in bounded steps.
#[test]
fn the_migration_adds_tables_and_triggers_and_reads_nothing() {
    let statements = top_level(MIGRATION_0020);
    assert_eq!(statements.len(), 5, "{statements:?}");
    for s in &statements {
        assert!(
            s.starts_with("CREATE TABLE usage_")
                || s == "INSERT INTO usage_global (id) VALUES (1), (2)",
            "{s}"
        );
    }
    for word in ["ALTER ", "DROP ", "CREATE INDEX", "CREATE UNIQUE", "PRAGMA"] {
        assert!(!MIGRATION_0020.to_uppercase().contains(word), "{word}");
    }

    // On a catalogue with rows it adds its two rows and counts nothing.
    let db = RusqliteSql::open_in_memory().unwrap();
    for script in before_0020() {
        db.apply(script).unwrap();
    }
    fill(&db, 30);
    db.apply(MIGRATION_0020).unwrap();
    assert_eq!(
        row(
            &db,
            "SELECT (SELECT COUNT(*) FROM usage_global), (SELECT COUNT(*) FROM usage_hours), \
                    (SELECT COUNT(*) FROM usage_buckets), (SELECT COUNT(*) FROM usage_recounts), \
                    (SELECT COUNT(*) FROM extents), (SELECT COUNT(*) FROM outbox), \
                    (SELECT COUNT(*) FROM generations)",
            7
        ),
        [2, 0, 0, 0, 30, 30, 30]
    );
    assert_eq!(levels(&db, 1), vec![0; 11]);
    assert!(!armed(&db));
}

/// The catalogue as it is before migration 0025, counters on.
fn before_0025() -> RusqliteSql {
    let db = RusqliteSql::open_in_memory().unwrap();
    for script in before_0020() {
        db.apply(script).unwrap();
    }
    for script in [MIGRATION_0020, MIGRATION_0021, MIGRATION_0022, ARM_USAGE] {
        db.apply(script).unwrap();
    }
    db
}

/// Row changes as the Worker makes them, one batch each: the extent
/// first where it changes, then its outbox row.
fn stage_changes(db: &RusqliteSql) {
    add_buckets(db);
    let rows = [
        ("x_a", "held", "verify"),
        ("x_b", "held", "verify"),
        ("x_c", "released", "verify"),
        ("x_d", "releasing", "release"),
        ("x_e", "held", "verify"),
        ("x_f", "held", "verify"),
    ];
    db.with_conn(|c| {
        for (id, safety, stage) in rows {
            c.execute(ADD_EXTENT, (id, "b_1", 100, safety)).unwrap();
            c.execute(ADD_OUTBOX, (id, stage, T0)).unwrap();
        }
        c.execute(
            "UPDATE extents SET released_at = ?1 WHERE id = 'x_c'",
            (T0 - 1,),
        )
        .unwrap();
    });
    let released = "UPDATE extents SET safety_state = 'released', released_at = ?2 WHERE id = ?1";
    let to = "UPDATE outbox SET stage = ?3, updated_at = ?2 WHERE extent_id = ?1";
    let batch = |id: &str, at: i64, release: bool, stage: &str| {
        db.with_conn(|c| {
            c.execute_batch("BEGIN").unwrap();
            if release {
                assert_eq!(c.execute(released, (id, at)).unwrap(), 1);
            }
            assert!(c.execute(to, (id, at, stage)).unwrap() >= 1);
            c.execute_batch("COMMIT").unwrap();
        })
    };
    // Released by the verify job that checked it.
    batch("x_a", T0 + 5, true, "done");
    // Parked with the copy held: too few backbones count.
    batch("x_b", T0 + 6, false, "done");
    // Its copy was released at another time.
    batch("x_c", T0 + 7, false, "done");
    // The last step of a release job.
    batch("x_d", T0 + 8, true, "done");
    // A verify that passed before the minimum age was over.
    batch("x_e", T0 + 9, false, "release");
    // Released by a verify job two hours later.
    batch("x_f", T0 + 2 * 3_600_000, true, "done");
}

/// Migration 0025. A row that goes from `verify` to `done` in the batch
/// that releases its copy is a verify and a release, in the totals and
/// in the hours. Every other change counts as it did.
#[test]
fn a_release_by_the_verify_job_counts_as_a_verify_and_a_release() {
    let db = RusqliteSql::with_schema().unwrap();
    stage_changes(&db);
    let want = Totals {
        verifies: 5,
        releases: 3,
        ..Totals::default()
    };
    assert_eq!(totals(&db), want);
    assert_eq!(hourly_sum(&db), want);
    assert_exact(&db, "after the releases");
    // The hour of the first five was filed when the sixth came.
    let filed = "SELECT COUNT(*), SUM(verifies), SUM(releases) FROM usage_hours";
    assert_eq!(row(&db, filed, 3), [1, 4, 2]);

    // Before the migration the two releases by a verify job were
    // verifies only: that is all it changes.
    let old = before_0025();
    stage_changes(&old);
    let before = Totals {
        releases: 1,
        ..want
    };
    assert_eq!(totals(&old), before);
    assert_eq!(levels(&old, 1), levels(&db, 1));
}

/// Migration 0025 replaces one trigger: the text of 0020 but for the
/// two places that count a release. It reads and writes no row, so it
/// takes the same time on any catalogue, and the counters stay as they
/// are and switched on.
#[test]
fn migration_0025_replaces_the_stage_trigger_and_nothing_else() {
    assert_eq!(
        top_level(MIGRATION_0025),
        ["DROP TRIGGER usage_outbox_stage"]
    );
    let trigger = |script: &str| {
        let at = script.find("CREATE TRIGGER usage_outbox_stage").unwrap();
        let end = script[at..].find("\nEND;").unwrap() + at + 5;
        script[at..end]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert_eq!(MIGRATION_0025.matches("CREATE TRIGGER").count(), 1);
    let was = "(OLD.stage = 'release' AND NEW.stage = 'done')";
    let is = "((OLD.stage = 'release' AND NEW.stage = 'done') \
               OR (OLD.stage = 'verify' AND NEW.stage = 'done' \
               AND EXISTS (SELECT 1 FROM extents e WHERE e.id = NEW.extent_id \
               AND e.safety_state = 'released' AND e.released_at = NEW.updated_at)))";
    let old = trigger(MIGRATION_0020);
    assert_eq!(old.matches(was).count(), 2);
    assert_eq!(trigger(MIGRATION_0025), old.replace(was, is));

    let db = before_0025();
    fill(&db, 30);
    let other = "SELECT type, name, sql FROM sqlite_master \
                  WHERE name <> 'usage_outbox_stage' ORDER BY 1, 2";
    let schema = |db: &RusqliteSql| pairs_of(db, other);
    let counters = "SELECT * FROM usage_global ORDER BY id";
    let state = |db: &RusqliteSql| (schema(db), levels(db, 1), totals(db), armed(db));
    let (before, global) = (state(&db), pairs_of(&db, counters));
    db.meter_writes().unwrap();
    db.apply(MIGRATION_0025).unwrap();
    assert_eq!(db.writes().billed(), 0);
    assert_eq!(state(&db), before);
    assert_eq!(pairs_of(&db, counters), global);
    assert!(armed(&db));
}

/// Every column of every row of a query, as text.
fn pairs_of(db: &RusqliteSql, sql: &str) -> Vec<Vec<String>> {
    db.with_conn(|c| {
        let mut q = c.prepare(sql).unwrap();
        let n = q.column_count();
        let mut rows = q.query(()).unwrap();
        let mut out = Vec::new();
        while let Some(r) = rows.next().unwrap() {
            let columns = (0..n).map(|i| format!("{:?}", r.get_ref(i).unwrap()));
            out.push(columns.collect());
        }
        out
    })
}

fn before_0020() -> Vec<&'static str> {
    vec![
        MIGRATION_0001,
        MIGRATION_0002,
        MIGRATION_0003,
        MIGRATION_0004,
        MIGRATION_0005,
        MIGRATION_0006,
        MIGRATION_0007,
        MIGRATION_0008,
        MIGRATION_0009,
        MIGRATION_0010,
        MIGRATION_0011,
        MIGRATION_0012,
        MIGRATION_0013,
        MIGRATION_0014,
        MIGRATION_0015,
        MIGRATION_0016,
        MIGRATION_0017,
        MIGRATION_0018,
        MIGRATION_0019,
    ]
}

/// The statements a Worker from before the migration runs, and the row
/// count (`meta.changes`) each reports. Such a Worker compares some of
/// them with exactly 1.
async fn old_worker_changes(db: &RusqliteSql) -> Vec<u64> {
    let mut out = Vec::new();
    for sql in [
        "INSERT INTO extents (id, bucket_id, state, plain_size, cipher_size, media_header, \
           plain_md5, plain_sha256, cipher_sha256, safety_state, created_at) \
         VALUES ('x_old', 'b_1', 'committed', 5, 5, x'00', x'00', x'00', x'00', 'held', 0)",
        "INSERT INTO outbox (extent_id, generation_id, stage, next_at, updated_at) \
         VALUES ('x_old', 'g', 'post', 0, 0)",
        "UPDATE outbox SET stage = 'verify', updated_at = 9 WHERE extent_id = 'x_old'",
        "UPDATE outbox SET last_error = 'e', updated_at = 9 WHERE extent_id = 'x_old'",
        "UPDATE extents SET safety_state = 'releasing' WHERE id = 'x_old'",
        "UPDATE extents SET safety_state = 'released' WHERE id = 'x_old'",
        "INSERT INTO generations (id, bucket_id, key, state, size, etag, content_json, \
           user_meta_json, extent_count, created_at) \
         VALUES ('g_old', 'b_1', 'k', 'live', 5, 'e', '{}', '{}', 0, 0)",
        "UPDATE generations SET state = 'superseded' WHERE id = 'g_old'",
        "DELETE FROM generations WHERE id = 'g_old'",
        "DELETE FROM outbox WHERE extent_id = 'x_old'",
        "DELETE FROM extents WHERE id = 'x_old'",
    ] {
        out.push(db.exec(sql, &[]).await.unwrap());
    }
    out
}

/// Rollback safety. Until a recount has switched the counters on, a
/// Worker from before the migration sees the catalogue it knows: every
/// statement reports the row count it did, and writes the rows it did.
/// After `usage_off` it is so again.
#[tokio::test]
async fn an_old_worker_is_not_disturbed_until_the_counters_are_on() {
    let old = RusqliteSql::open_in_memory().unwrap();
    for script in before_0020() {
        old.apply(script).unwrap();
    }
    // And the migrations after it: the usage counters are the only
    // difference between the two.
    old.apply(MIGRATION_0021).unwrap();
    old.apply(MIGRATION_0022).unwrap();
    add_buckets(&old);
    old.meter_writes().unwrap();
    let expected = old_worker_changes(&old).await;
    assert_eq!(expected, [1; 11]);
    let expected_rows = old.writes().billed();

    let new = RusqliteSql::with_schema_unarmed().unwrap();
    add_buckets(&new);
    new.meter_writes().unwrap();
    assert_eq!(old_worker_changes(&new).await, expected);
    assert_eq!(new.writes().billed(), expected_rows);

    // Switched on, a statement reports the counter row with its own:
    // what a Worker from before the migration would take for a conflict.
    new.apply(ARM_USAGE).unwrap();
    let on = old_worker_changes(&new).await;
    assert_ne!(on, expected);
    assert!(on.iter().all(|n| *n >= 1));

    // Switched off before such a Worker is put back: as before.
    let catalog = SqlCatalog::new(new);
    catalog.usage_off().await.unwrap();
    catalog.sql.reset_writes();
    assert_eq!(old_worker_changes(&catalog.sql).await, expected);
    assert_eq!(catalog.sql.writes().billed(), expected_rows);
}
