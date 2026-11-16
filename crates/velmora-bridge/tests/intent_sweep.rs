//! The sweep of sliced writes that were never published: what a request
//! leaves at each point it can stop, what the sweep does with it, and
//! what a restore of the catalogue does to both.

mod intent_support;
mod service_support;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use intent_support::*;
use service_support::*;
use velmora_bridge::ports::Catalog;
use velmora_bridge::*;

const KEY: &str = "k";
const SLICES: usize = 5;
/// Past the grace period of the sweep.
const DAY_MS: i64 = 25 * HOUR_MS;

/// A rig with an object under [`KEY`], and the body a sliced PUT is
/// about to replace it with.
struct Setup {
    rig: Rig,
    bucket: Bucket,
    signer: Signer,
    old: Vec<u8>,
    new: Vec<u8>,
}

async fn setup_with(cfg: config::BridgeConfig) -> Setup {
    let rig = rig_with(NoNntp, cfg);
    let (bucket, signer) = rig.standard(BUCKET).await;
    let old = pattern(9, 100);
    rig.put(&signer, BUCKET, KEY, &old).await.expect(200);
    rig.bridge.clock.advance_ms(1000);
    Setup {
        rig,
        bucket,
        signer,
        old,
        new: pattern(1, SLICES * SLICE),
    }
}

async fn setup() -> Setup {
    setup_with(small_config()).await
}

impl Setup {
    /// The sliced PUT of the new body, not yet started.
    fn put(&self) -> Running<'static, Resp> {
        self.put_to(KEY, &self.new)
    }

    fn put_to(&self, key: &str, body: &[u8]) -> Running<'static, Resp> {
        let req = mode_req(&self.rig, &self.signer, key, body, Mode::Literal);
        start(&self.rig, req)
    }

    /// The sliced PUT, stopped before the first call at which `at` holds.
    async fn put_stopped(&self, at: impl Fn(&Point) -> bool) -> Running<'static, Resp> {
        step_to(&self.rig, self.put(), |rig| at(&point(rig)))
            .await
            .stalled()
    }

    async fn body(&self) -> Vec<u8> {
        get(&self.rig, &self.signer, KEY)
            .await
            .expect(200)
            .body
            .clone()
    }

    fn write(&self) -> String {
        let rows = intents(&self.rig);
        assert!(rows.iter().all(|i| i.write == rows[0].write));
        rows[0].write.clone()
    }

    async fn sweep(&self, write: &str) -> JobOutcome {
        self.rig.bridge.run_job(&sweep_job(write)).await
    }
}

/// How far the sliced PUT of a [`Setup`] has come.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Point {
    /// Intent rows.
    rows: usize,
    /// The rows hold the id of a recovery record.
    named: bool,
    /// Slices in the safety bucket.
    blobs: usize,
    /// The stamp counter of the catalogue.
    counter: i64,
    /// Stamp objects in the safety bucket.
    stamps: usize,
    /// The recovery record of the write exists.
    record: bool,
    /// The catalogue holds the generation.
    published: bool,
}

fn point(rig: &Rig) -> Point {
    let rows = intents(rig);
    Point {
        rows: rows.len(),
        named: rows.iter().any(|i| i.generation.is_some()),
        blobs: blobs(rig).len() - 1,
        counter: number(
            rig,
            "SELECT COALESCE((SELECT counter FROM rollback_stamp), 0)",
        ),
        stamps: stamps(rig).len(),
        record: records(rig).len() == 2,
        published: rig.count("generations") == 2,
    }
}

/// Generation ids with a recovery record and no catalogue row.
fn unpublished(rig: &Rig) -> Vec<String> {
    let have = column(rig, "SELECT id FROM generations");
    records(rig)
        .into_iter()
        .filter(|id| !have.contains(id))
        .collect()
}

/// Runs the sweep until a tick finds nothing to do.
async fn sweep_out(rig: &Rig) {
    for _ in 0..4 {
        if sweep_tick(rig).await == 0 {
            return;
        }
    }
    panic!("the sweep does not come to an end: {:?}", intents(rig));
}

fn kept(rig: &Rig) -> bool {
    states(rig) == [("kept".to_string(), SLICES)]
}

// ---------------------------------------------------------------------------
// The order of a sliced write
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_sliced_write_goes_through_its_steps_in_one_order() {
    let mut seen: Vec<Point> = Vec::new();
    let mut n = 0;
    let answer = loop {
        let s = setup().await;
        let ran = run_until(&s.rig, s.put(), n, Trip::Stall).await;
        let at = point(&s.rig);
        if seen.last() != Some(&at) {
            seen.push(at);
        }
        if let Ran::Done(r) = ran {
            break r;
        }
        n += 1;
    };
    answer.expect(200);

    let mut at = Point {
        rows: 0,
        named: false,
        blobs: 0,
        counter: 0,
        stamps: 0,
        record: false,
        published: false,
    };
    let mut expected = vec![at.clone()];
    let mut then = |change: &dyn Fn(&mut Point)| {
        change(&mut at);
        expected.push(at.clone());
    };
    // Every slice has its row before the first one is stored.
    then(&|p| p.rows = SLICES);
    for _ in 0..SLICES {
        then(&|p| p.blobs += 1);
    }
    // The id of the record is on the rows, and the stamp is raised,
    // before the record exists.
    then(&|p| p.named = true);
    then(&|p| p.counter = 1);
    then(&|p| p.stamps = 1);
    then(&|p| p.record = true);
    // The publish takes the rows with it.
    then(&|p| {
        p.published = true;
        p.rows = 0;
        p.named = false;
    });
    // The stamp once more, before the answer.
    then(&|p| p.counter = 2);
    then(&|p| p.stamps = 2);
    assert_eq!(seen, expected);
}

// ---------------------------------------------------------------------------
// A request that stops anywhere
// ---------------------------------------------------------------------------

/// After a request ended in any way: the sweep leaves the key readable
/// and every published slice in place, removes what nobody can publish,
/// keeps what a recovery record names, and a replay then agrees.
async fn settles(mut s: Setup, answered: Option<u16>, what: &str) {
    let rig = &s.rig;
    assert!(broken(rig).is_empty(), "{what}");
    let all = records(rig);

    // At once: only what the request gave up is taken.
    sweep_tick(rig).await;
    assert_eq!(records(rig), all, "{what}");
    assert!(broken(rig).is_empty(), "{what}");
    if answered == Some(200) {
        assert!(s.body().await == s.new, "{what}");
    }

    rig.bridge.clock.advance_ms(DAY_MS);
    sweep_out(rig).await;
    assert_eq!(records(rig), all, "{what}: the sweep deletes no record");
    assert!(broken(rig).is_empty(), "{what}");
    let pending = unpublished(rig);
    let rows = intents(rig);
    let stats = intent_status(rig).await;
    if pending.is_empty() {
        assert!(rows.is_empty(), "{what}: {rows:?}");
        assert!(orphans(rig).is_empty(), "{what}");
        assert_eq!(stats["anomalies"], 0, "{what}");
    } else {
        // A record without a catalogue row: its slices stay, listed.
        assert_eq!(pending.len(), 1, "{what}");
        assert!(kept(rig), "{what}: {rows:?}");
        assert!(
            rows.iter()
                .all(|i| i.generation.as_deref() == Some(pending[0].as_str())),
            "{what}"
        );
        let named: Vec<String> = rows.iter().map(|i| i.extent.clone()).collect();
        assert_eq!(orphans(rig), named, "{what}");
        assert_eq!(stats["anomalies"], 1, "{what}");
        assert_eq!(stats["kept_writes"], 1, "{what}");
        assert_eq!(stats["kept_slices"], SLICES, "{what}");
    }
    assert_eq!(stats["waiting_writes"], 0, "{what}");
    let now = s.body().await;
    assert!(now == s.old || now == s.new, "{what}");
    if answered == Some(200) {
        assert!(now == s.new, "{what}");
    }

    // The replay publishes what has a record, and nothing else.
    let expect_new = now == s.new || !pending.is_empty();
    restore(&mut s.rig).await;
    let after = s.body().await;
    assert!(
        after
            == if expect_new {
                s.new.clone()
            } else {
                s.old.clone()
            },
        "{what}"
    );
    assert!(broken(&s.rig).is_empty(), "{what}");
    assert!(unpublished(&s.rig).is_empty(), "{what}");
    assert!(intents(&s.rig).is_empty(), "{what}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_request_that_stops_at_any_call_leaves_nothing_broken() {
    for trip in [Trip::Stall, Trip::Fail, Trip::Lost] {
        let mut n = 0;
        loop {
            let s = setup().await;
            let ran = run_until(&s.rig, s.put(), n, trip).await;
            let reached = s.rig.trip().tripped();
            s.rig.trip().disarm();
            // A stalled request is dropped here: its handler was killed.
            let answered = ran.done().map(|r| r.status);
            if !reached {
                assert_eq!(answered, Some(200));
                assert!(n > 20, "the request made {n} calls");
                break;
            }
            settles(s, answered, &format!("{trip:?} at call {n}")).await;
            n += 1;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_request_killed_after_slice_k_is_swept_after_the_grace_period() {
    for k in 0..=SLICES {
        let s = setup().await;
        drop(s.put_stopped(|p| p.rows == SLICES && p.blobs == k).await);
        s.rig.trip().disarm();
        assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
        assert_eq!(orphans(&s.rig).len(), k);

        // Not before the grace period is over.
        s.rig.bridge.clock.advance_ms(24 * HOUR_MS);
        assert_eq!(sweep_tick(&s.rig).await, 0);
        assert_eq!(s.sweep(&s.write()).await, JobOutcome::Ack);
        assert_eq!(orphans(&s.rig).len(), k, "a job sent early deletes nothing");
        assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
        let stats = intent_status(&s.rig).await;
        assert_eq!(
            (&stats["open_writes"], &stats["waiting_writes"]),
            (&1.into(), &0.into())
        );

        s.rig.bridge.clock.advance_ms(1);
        let stats = intent_status(&s.rig).await;
        assert_eq!(
            (&stats["open_writes"], &stats["waiting_writes"]),
            (&0.into(), &1.into())
        );
        assert_eq!(stats["oldest_waiting_at"], intents(&s.rig)[0].created_at);
        assert_eq!(sweep_tick(&s.rig).await, 1);
        assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
        assert_eq!(blobs(&s.rig).len(), 1);
        assert!(s.body().await == s.old);
        assert_eq!(intent_status(&s.rig).await["anomalies"], 0);
    }
}

// ---------------------------------------------------------------------------
// Between the record and the publish
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn killed_between_record_and_publish_everything_is_kept_and_a_replay_publishes_it() {
    let mut s = setup().await;
    drop(s.put_stopped(|p| p.record).await);
    s.rig.trip().disarm();
    assert!(!point(&s.rig).published);
    let record = unpublished(&s.rig);
    assert_eq!(record.len(), 1);
    assert_eq!(sweep_tick(&s.rig).await, 0, "the rows are open");

    s.rig.bridge.clock.advance_ms(DAY_MS);
    // The job is delivered twice. The late one has seen the record and
    // is about to keep the write when the other one does.
    let late = start_job(&s.rig, sweep_job(&s.write()));
    let late = step_to(&s.rig, late, |rig| {
        states(rig) == [("sweeping".to_string(), SLICES)]
    })
    .await
    .stalled();
    let late = resume_until(&s.rig, late, 1, Trip::Stall).await.stalled();
    assert_eq!(states(&s.rig), [("sweeping".to_string(), SLICES)]);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(kept(&s.rig));
    assert_eq!(intent_status(&s.rig).await["anomalies"], 1);
    assert_eq!(resume(&s.rig, late).await, JobOutcome::Ack);
    assert_eq!(unpublished(&s.rig), record);
    assert_eq!(orphans(&s.rig).len(), SLICES);
    let first = intent_status(&s.rig).await;
    assert_eq!(first["kept_writes"], 1);
    assert_eq!(first["kept_slices"], SLICES);
    assert_eq!(first["anomalies"], 1);
    assert_eq!(first["waiting_writes"], 0);

    // Counted once, however often the tick runs or the job is sent.
    assert_eq!(sweep_tick(&s.rig).await, 0);
    assert_eq!(s.sweep(&s.write()).await, JobOutcome::Ack);
    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 0);
    assert_eq!(intent_status(&s.rig).await, first);
    assert_eq!(orphans(&s.rig).len(), SLICES);
    assert!(s.body().await == s.old);

    restore(&mut s.rig).await;
    assert!(s.body().await == s.new);
    assert!(orphans(&s.rig).is_empty() && broken(&s.rig).is_empty());
    assert!(intents(&s.rig).is_empty());
    assert_eq!(intent_status(&s.rig).await["kept_writes"], 0);
}

// ---------------------------------------------------------------------------
// A refused publish
// ---------------------------------------------------------------------------

/// Makes the next `times` publications of [`KEY`] lose: when a recovery
/// record is put, the floor of the key moves above its id.
fn refuse_publishes(s: &Setup, times: u32) -> Rc<Cell<u32>> {
    fn install(bridge: Rc<TestBridge<NoNntp>>, bucket: String, left: Rc<Cell<u32>>) {
        let again = Rc::clone(&bridge);
        let hook = move |key: &str| {
            match key.strip_prefix("m/g_") {
                Some(rest) if left.get() > 0 => {
                    left.set(left.get() - 1);
                    let ms = i64::from_str_radix(&rest[..13], 16).unwrap();
                    let floor = format!("g_{:013x}{}", ms + 1, &rest[13..]);
                    again.catalog.sql.with_conn(|c| {
                        c.execute(
                            "INSERT INTO key_floors(bucket_id, key, floor_id) VALUES (?1, ?2, ?3) \
                             ON CONFLICT(bucket_id, key) DO UPDATE SET floor_id = excluded.floor_id",
                            [bucket.as_str(), KEY, floor.as_str()],
                        )
                        .unwrap()
                    });
                }
                _ => {}
            }
            if left.get() > 0 {
                install(Rc::clone(&again), bucket, left);
            }
        };
        bridge.safety.before_put.replace(Some(Box::new(hook)));
    }
    let left = Rc::new(Cell::new(times));
    install(
        Rc::clone(&s.rig.bridge),
        s.bucket.id.as_str().to_string(),
        Rc::clone(&left),
    );
    left
}

#[tokio::test(flavor = "current_thread")]
async fn a_publish_refused_once_is_tried_again_under_a_later_id() {
    let s = setup().await;
    let left = refuse_publishes(&s, 1);
    s.put().await.expect(200);
    assert_eq!(left.get(), 0);
    assert!(s.body().await == s.new);
    assert!(unpublished(&s.rig).is_empty(), "the refused record went");
    assert!(intents(&s.rig).is_empty() && orphans(&s.rig).is_empty());
    // A raise before each record and one after the commit.
    assert_eq!(stamps(&s.rig).len(), 3);
    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 0);
    assert!(s.body().await == s.new);
}

#[tokio::test(flavor = "current_thread")]
async fn a_publish_refused_to_the_end_removes_its_record_and_gives_the_slices_up() {
    let s = setup().await;
    let left = refuse_publishes(&s, 100);
    s.put().await.expect_error(503, "SlowDown");
    assert_eq!(left.get(), 96, "four tries");
    s.rig.bridge.safety.before_put.replace(None);
    assert!(unpublished(&s.rig).is_empty());
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
    assert_eq!(orphans(&s.rig).len(), SLICES);

    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
    assert!(s.body().await == s.old);
    assert_eq!(intent_status(&s.rig).await["anomalies"], 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_publish_whose_record_cannot_be_removed_keeps_everything() {
    let s = setup().await;
    refuse_publishes(&s, 1);
    // Every try of the delete fails.
    s.rig.bridge.safety.fail_record_deletes.set(3);
    s.put().await.expect_error(500, "InternalError");
    // The record may be read by a replay: the rows are not given up.
    assert_eq!(unpublished(&s.rig).len(), 1);
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
    assert_eq!(sweep_tick(&s.rig).await, 0);

    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(kept(&s.rig));
    assert_eq!(unpublished(&s.rig).len(), 1);
    assert_eq!(orphans(&s.rig).len(), SLICES);
    assert_eq!(intent_status(&s.rig).await["anomalies"], 1);
    assert!(s.body().await == s.old);
}

// ---------------------------------------------------------------------------
// A publish without an answer
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn an_unanswered_publish_that_committed_stays_readable() {
    let s = setup().await;
    s.rig
        .bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::Applied));
    s.put().await.expect_error(500, "InternalError");
    // The commit took the rows; nothing was marked.
    assert!(intents(&s.rig).is_empty());
    assert!(s.body().await == s.new);
    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 0);
    assert!(s.body().await == s.new);
    assert!(broken(&s.rig).is_empty() && orphans(&s.rig).is_empty());
    assert_eq!(intent_status(&s.rig).await["anomalies"], 0);
}

#[tokio::test(flavor = "current_thread")]
async fn an_unanswered_publish_that_did_not_commit_is_kept() {
    let mut s = setup().await;
    s.rig
        .bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::NotApplied));
    s.put().await.expect_error(500, "InternalError");
    // The handler cannot know: the rows stay open.
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
    assert_eq!(unpublished(&s.rig).len(), 1);
    assert_eq!(sweep_tick(&s.rig).await, 0);

    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(kept(&s.rig));
    assert_eq!(unpublished(&s.rig).len(), 1);
    assert_eq!(orphans(&s.rig).len(), SLICES);
    assert_eq!(intent_status(&s.rig).await["anomalies"], 1);
    assert!(s.body().await == s.old);
    restore(&mut s.rig).await;
    assert!(s.body().await == s.new);
}

// ---------------------------------------------------------------------------
// The publish and the sweep, in both orders
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_writer_older_than_twelve_hours_gives_up_before_its_record() {
    let s = setup().await;
    // Stopped at the put of its last slice: its age is looked at after
    // that put.
    let fut = s.put_stopped(|p| p.blobs == SLICES - 1).await;
    s.rig
        .bridge
        .clock
        .advance_ms(intents::WRITER_MAX_AGE_MS + 1);
    resume(&s.rig, fut).await.expect_error(503, "SlowDown");
    assert!(unpublished(&s.rig).is_empty());
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
    assert!(stamps(&s.rig).is_empty());
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());

    // At the age itself it still publishes.
    let s = setup().await;
    let fut = s.put_stopped(|p| p.blobs == SLICES - 1).await;
    s.rig.bridge.clock.advance_ms(intents::WRITER_MAX_AGE_MS);
    resume(&s.rig, fut).await.expect(200);
    assert!(s.body().await == s.new);
}

/// A writer that outlives the grace period is outside what the ages
/// allow for. The fence still decides: nothing is published without its
/// slices.
#[tokio::test(flavor = "current_thread")]
async fn the_sweep_first_then_the_publish_publishes_nothing() {
    // The sweep takes the rows before the record is written.
    let s = setup().await;
    let fut = s.put_stopped(|p| p.stamps == 1).await;
    assert!(!point(&s.rig).record);
    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
    let r = resume(&s.rig, fut).await;
    assert!(r.status >= 500, "{}", r.text());
    assert_eq!(s.rig.count("generations"), 1);
    assert!(
        unpublished(&s.rig).is_empty(),
        "the writer removed its record"
    );
    assert!(broken(&s.rig).is_empty());
    assert!(s.body().await == s.old);

    // The sweep takes them with the record written: it keeps the slices,
    // and the publish is refused all the same.
    let s = setup().await;
    let fut = s.put_stopped(|p| p.record).await;
    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(kept(&s.rig));
    let r = resume(&s.rig, fut).await;
    assert!(r.status >= 500, "{}", r.text());
    assert_eq!(s.rig.count("generations"), 1);
    assert!(broken(&s.rig).is_empty());
    assert_eq!(orphans(&s.rig).len(), SLICES);
    assert!(s.body().await == s.old);

    // The sweep job stops between its fence and its deletes, and the
    // writer comes to its publish meanwhile.
    let s = setup().await;
    let fut = s.put_stopped(|p| p.record).await;
    let write = s.write();
    s.rig.bridge.clock.advance_ms(DAY_MS);
    let job = step_to(&s.rig, start_job(&s.rig, sweep_job(&write)), |rig| {
        states(rig) == [("sweeping".to_string(), SLICES)]
    })
    .await
    .stalled();
    let r = resume(&s.rig, fut).await;
    assert!(r.status >= 500, "{}", r.text());
    assert_eq!(resume(&s.rig, job).await, JobOutcome::Ack);
    assert_eq!(s.rig.count("generations"), 1);
    assert!(broken(&s.rig).is_empty());
    assert!(s.body().await == s.old);
}

#[tokio::test(flavor = "current_thread")]
async fn the_publish_first_then_the_sweep_deletes_nothing() {
    // A job that was sent for the write arrives after its publish.
    let s = setup().await;
    let fut = s.put_stopped(|p| p.record).await;
    let write = s.write();
    resume(&s.rig, fut).await.expect(200);
    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(s.sweep(&write).await, JobOutcome::Ack);
    assert!(s.body().await == s.new);
    assert!(broken(&s.rig).is_empty());
    assert_eq!(intent_status(&s.rig).await["anomalies"], 0);

    // The job has passed its first check when the publish commits.
    let s = setup().await;
    let fut = s.put_stopped(|p| p.record).await;
    let write = s.write();
    s.rig.bridge.clock.advance_ms(DAY_MS);
    let calls = s.rig.trip().calls();
    let job = run_until(&s.rig, start_job(&s.rig, sweep_job(&write)), 2, Trip::Stall)
        .await
        .stalled();
    assert_eq!(s.rig.trip().calls(), calls + 3);
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
    // Twelve hours are long gone, but this writer is past that check.
    resume(&s.rig, fut).await.expect(200);
    assert_eq!(resume(&s.rig, job).await, JobOutcome::Ack);
    assert!(s.body().await == s.new);
    assert!(broken(&s.rig).is_empty() && orphans(&s.rig).is_empty());

    // Intent rows next to the rows of the published write (a catalogue
    // put together from two points in time): the rows go, counted, and
    // no slice is touched.
    let s = setup().await;
    let fut = s.put_stopped(|p| p.record).await;
    snapshot(&s.rig);
    resume(&s.rig, fut).await.expect(200);
    sql(
        &s.rig,
        "INSERT INTO write_intents SELECT * FROM snap_write_intents; \
         UPDATE write_intents SET state = 'abandoned';",
    );
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(intents(&s.rig).is_empty());
    assert_eq!(intent_status(&s.rig).await["anomalies"], 1);
    assert!(broken(&s.rig).is_empty());
    assert!(s.body().await == s.new);
}

// ---------------------------------------------------------------------------
// A slice put that fails
// ---------------------------------------------------------------------------

/// Every put of a slice that was sent: its key and the SHA-256 of its
/// bytes.
fn slice_puts(rig: &Rig) -> Vec<(String, [u8; 32])> {
    let puts = rig.bridge.safety.puts.borrow();
    puts.iter()
        .filter(|(key, _)| key.starts_with("x/"))
        .cloned()
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn a_slice_put_that_fails_is_sent_again_with_the_same_bytes() {
    // The put fails, or it is carried out and its answer is lost.
    for trip in [Trip::Fail, Trip::Lost] {
        for k in [1, 2, SLICES - 1] {
            let s = setup().await;
            let before = slice_puts(&s.rig).len();
            // Stopped at the put of slice k - 1: the call after it trips.
            let fut = s
                .put_stopped(|p| p.rows == SLICES && p.blobs == k - 1)
                .await;
            let what = format!("{trip:?} at slice {k}");
            let answer = resume_until(&s.rig, fut, 0, trip).await.done();
            answer.expect(&what).expect(200);

            let puts = slice_puts(&s.rig).split_off(before);
            assert_eq!(puts.len(), SLICES + 1, "{what}");
            assert_eq!(puts[k], puts[k + 1], "{what}: the same key and bytes");
            let keys: BTreeSet<&String> = puts.iter().map(|(key, _)| key).collect();
            assert_eq!(keys.len(), SLICES, "{what}");
            assert!(s.body().await == s.new, "{what}");
            assert!(broken(&s.rig).is_empty() && orphans(&s.rig).is_empty());
            assert!(intents(&s.rig).is_empty(), "{what}");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_slice_put_that_keeps_failing_ends_the_write_after_three_attempts() {
    let s = setup().await;
    let before = slice_puts(&s.rig).len();
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("x/".into());
    s.put().await.expect_error(500, "InternalError");
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = None;

    let puts = slice_puts(&s.rig).split_off(before);
    assert_eq!(puts.len(), 3);
    assert!(puts.iter().all(|put| put == &puts[0]));
    // No record can exist: the request gave its rows up.
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
    assert!(stamps(&s.rig).is_empty() && unpublished(&s.rig).is_empty());
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
    assert!(s.body().await == s.old);
}

// ---------------------------------------------------------------------------
// The guards of the write path, one at a time
// ---------------------------------------------------------------------------

/// The publish batch inserts the extents of its commit and removes the
/// intent rows of its write. It commits only when the two are the same
/// slices.
#[tokio::test(flavor = "current_thread")]
async fn a_publish_whose_intents_name_other_extents_is_refused() {
    let s = setup().await;
    let fut = s.put_stopped(|p| p.record).await;
    // The rows are open, under the id of the record and as many as the
    // slices: they name other extents than the commit holds.
    sql(
        &s.rig,
        "UPDATE write_intents SET extent_id = extent_id || 'z'",
    );
    let r = resume(&s.rig, fut).await;
    assert!(r.status >= 500, "{}", r.text());
    assert_eq!(s.rig.count("generations"), 1);
    assert_eq!(s.rig.count("extents"), 1);
    assert!(unpublished(&s.rig).is_empty(), "the record was removed");
    assert_eq!(s.rig.count("write_intents"), SLICES as i64);
    assert!(s.body().await == s.old);
}

/// A writer that no longer has all its rows `open` stops before it
/// raises the stamp or writes a record, and leaves the rows as the
/// sweep made them.
#[tokio::test(flavor = "current_thread")]
async fn a_writer_whose_rows_are_not_open_writes_no_record() {
    for tamper in [
        "UPDATE write_intents SET state = 'sweeping'",
        "UPDATE write_intents SET state = 'kept'",
        "UPDATE write_intents SET state = 'sweeping' \
          WHERE extent_id = (SELECT MIN(extent_id) FROM write_intents)",
        "DELETE FROM write_intents WHERE extent_id = (SELECT MIN(extent_id) FROM write_intents)",
        "DELETE FROM write_intents",
    ] {
        let s = setup().await;
        let fut = s.put_stopped(|p| p.blobs == SLICES).await;
        sql(&s.rig, tamper);
        let rows = intents(&s.rig);
        let r = resume(&s.rig, fut).await;
        assert!(r.status >= 500, "{tamper}: {}", r.text());
        // Neither the stamp nor a record: it stopped at its rows.
        let at = point(&s.rig);
        assert_eq!((at.counter, at.stamps), (0, 0), "{tamper}");
        assert!(!at.named && !at.record && !at.published, "{tamper}");
        // Giving up takes `open` rows only.
        let after = intents(&s.rig);
        assert_eq!(after.len(), rows.len(), "{tamper}");
        for (was, is) in rows.iter().zip(&after) {
            let expected = match was.state.as_str() {
                "open" => "abandoned",
                other => other,
            };
            assert_eq!(is.state, expected, "{tamper}");
        }
        assert!(s.body().await == s.old, "{tamper}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn giving_up_changes_open_rows_only() {
    let s = setup().await;
    drop(s.put_stopped(|p| p.blobs == SLICES).await);
    s.rig.trip().disarm();
    let write = WriteId::new(s.write());
    let catalog = &s.rig.bridge.catalog;
    for state in ["sweeping", "kept", "abandoned"] {
        sql(
            &s.rig,
            &format!("UPDATE write_intents SET state = '{state}'"),
        );
        catalog.abandon_intents(&write).await.unwrap();
        assert_eq!(states(&s.rig), [(state.to_string(), SLICES)]);
    }
    sql(&s.rig, "UPDATE write_intents SET state = 'open'");
    catalog.abandon_intents(&write).await.unwrap();
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
}

/// The put of the recovery record fails, or is carried out without an
/// answer. The request cannot tell the two apart: its rows stay `open`,
/// and the sweep decides after the grace period by what `SAFETY` holds.
#[tokio::test(flavor = "current_thread")]
async fn a_record_write_without_an_answer_leaves_the_rows_open() {
    // Which call of the request puts the record.
    let s = setup().await;
    let calls = s.rig.trip().calls();
    drop(s.put_stopped(|p| p.record).await);
    // The last call counted is the one the request stopped at; the put
    // of the record is the one before it.
    let skip = s.rig.trip().calls() - calls - 2;

    for trip in [Trip::Fail, Trip::Lost] {
        let mut s = setup().await;
        let ran = run_until(&s.rig, s.put(), skip, trip).await;
        assert!(s.rig.trip().tripped());
        ran.done()
            .expect("an answer")
            .expect_error(500, "InternalError");
        let at = point(&s.rig);
        assert_eq!(at.stamps, 1, "{trip:?}: the call was the put of the record");
        assert_eq!(at.record, trip == Trip::Lost, "{trip:?}");
        assert!(at.named && !at.published, "{trip:?}");
        assert_eq!(states(&s.rig), [("open".to_string(), SLICES)], "{trip:?}");
        assert_eq!(sweep_tick(&s.rig).await, 0, "{trip:?}");

        s.rig.bridge.clock.advance_ms(DAY_MS);
        assert_eq!(sweep_tick(&s.rig).await, 1, "{trip:?}");
        if trip == Trip::Lost {
            // The record exists: everything stays, and a replay
            // publishes the write.
            assert!(kept(&s.rig));
            assert_eq!(orphans(&s.rig).len(), SLICES);
            restore(&mut s.rig).await;
            assert!(s.body().await == s.new);
        } else {
            assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
            assert!(s.body().await == s.old);
        }
        assert!(broken(&s.rig).is_empty(), "{trip:?}");
    }
}

// ---------------------------------------------------------------------------
// The guards of the sweep batches, one at a time
// ---------------------------------------------------------------------------

/// Intent rows of the write `w_guard` put next to the object of a
/// [`Setup`], which is published.
fn guard_rows(s: &Setup, state: &str, names: &str) -> WriteId {
    let rows = match names {
        // They name the extent of the object.
        "extent" => format!(
            "INSERT INTO write_intents(extent_id, write_id, state, created_at) \
             SELECT id, 'w_guard', '{state}', 0 FROM extents"
        ),
        // They hold the id of its generation.
        "generation" => format!(
            "INSERT INTO write_intents(extent_id, write_id, state, created_at, generation_id) \
             SELECT 'x_none', 'w_guard', '{state}', 0, id FROM generations"
        ),
        // Neither: the write was not published.
        _ => format!(
            "INSERT INTO write_intents(extent_id, write_id, state, created_at) \
             VALUES ('x_none', 'w_guard', '{state}', 0)"
        ),
    };
    sql(&s.rig, "DELETE FROM write_intents");
    sql(&s.rig, &rows);
    WriteId::new("w_guard")
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_with_a_catalogue_row_is_neither_fenced_nor_held() {
    let s = setup().await;
    let catalog = &s.rig.bridge.catalog;
    let all = blobs(&s.rig);
    let now = s.rig.now();
    for names in ["extent", "generation"] {
        // The fence finds the write published: its rows go, counted.
        let before = intent_status(&s.rig).await["anomalies"].as_u64().unwrap();
        let write = guard_rows(&s, "abandoned", names);
        assert_eq!(
            catalog.fence_intents(&write, now, None).await.unwrap(),
            IntentFence::Published,
            "{names}"
        );
        assert_eq!(s.rig.count("write_intents"), 0, "{names}");
        assert_eq!(
            intent_status(&s.rig).await["anomalies"],
            before + 1,
            "{names}"
        );

        // Rows that are fenced already are not held either.
        let write = guard_rows(&s, "sweeping", names);
        assert!(
            !catalog.hold_intent_fence(&write, 1, None).await.unwrap(),
            "{names}"
        );
        // The same rows of a write that was not published are.
        let write = guard_rows(&s, "sweeping", "nothing");
        assert!(catalog.hold_intent_fence(&write, 1, None).await.unwrap());
        // And the job deletes nothing of the published one.
        let write = guard_rows(&s, "sweeping", names);
        assert_eq!(s.sweep(write.as_str()).await, JobOutcome::Ack, "{names}");
        assert_eq!(blobs(&s.rig), all, "{names}");
        assert!(s.body().await == s.old, "{names}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn under_a_replay_no_intent_batch_goes_through() {
    let s = setup().await;
    let catalog = &s.rig.bridge.catalog;
    let now = s.rig.now();
    catalog
        .restore_begin(UnixMs(0), now)
        .await
        .unwrap()
        .unwrap();

    // Fenced rows are not held.
    let write = guard_rows(&s, "sweeping", "nothing");
    assert!(!catalog.hold_intent_fence(&write, 1, None).await.unwrap());
    // The rows of a published write stay, uncounted: under a replay
    // the catalogue rows are no proof of anything.
    for names in ["extent", "generation"] {
        let write = guard_rows(&s, "abandoned", names);
        assert_eq!(
            catalog.fence_intents(&write, now, None).await.unwrap(),
            IntentFence::Refused,
            "{names}"
        );
        assert_eq!(states(&s.rig), [("abandoned".to_string(), 1)], "{names}");
    }
    assert_eq!(
        number(
            &s.rig,
            "SELECT COUNT(*) FROM meta WHERE k = 'intent_anomalies'"
        ),
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn only_fenced_rows_are_dropped_and_they_count_as_waiting() {
    let s = setup().await;
    let catalog = &s.rig.bridge.catalog;
    for state in ["open", "abandoned", "kept"] {
        let write = guard_rows(&s, state, "nothing");
        catalog.drop_intents(&write).await.unwrap();
        assert_eq!(states(&s.rig), [(state.to_string(), 1)]);
    }
    // A write a job left fenced is still to be swept, and is shown so.
    let write = guard_rows(&s, "sweeping", "nothing");
    let stats = intent_status(&s.rig).await;
    assert_eq!(stats["waiting_writes"], 1);
    assert_eq!(stats["oldest_waiting_at"], 0);
    assert_eq!(stats["open_writes"], 0);
    catalog.drop_intents(&write).await.unwrap();
    assert_eq!(s.rig.count("write_intents"), 0);
    assert_eq!(intent_status(&s.rig).await["waiting_writes"], 0);
}

/// `oldest_kept_at` is where a restore must start from to read the
/// record of every kept write: the earliest kept row, and no row in
/// another state.
#[tokio::test(flavor = "current_thread")]
async fn the_oldest_kept_write_is_the_earliest_kept_row_only() {
    let s = setup().await;
    sql(&s.rig, "DELETE FROM write_intents");
    // The later kept write sorts first, and a write that is still to
    // be swept is older than both.
    sql(
        &s.rig,
        "INSERT INTO write_intents(extent_id, write_id, state, created_at) VALUES \
           ('x_a', 'w_a_late', 'kept', 500), \
           ('x_b', 'w_b_early', 'kept', 300), \
           ('x_c', 'w_b_early', 'kept', 300), \
           ('x_d', 'w_c_older', 'abandoned', 100)",
    );
    let stats = intent_status(&s.rig).await;
    assert_eq!(stats["kept_writes"], 2);
    assert_eq!(stats["kept_slices"], 3);
    assert_eq!(stats["oldest_kept_at"], 300);
    assert_eq!(stats["waiting_writes"], 1);
    assert_eq!(stats["oldest_waiting_at"], 100);

    // Without the older of the two, the later one is the oldest.
    sql(
        &s.rig,
        "DELETE FROM write_intents WHERE write_id = 'w_b_early'",
    );
    assert_eq!(intent_status(&s.rig).await["oldest_kept_at"], 500);
    // Without any, there is none, whatever else waits.
    sql(&s.rig, "DELETE FROM write_intents WHERE state = 'kept'");
    let stats = intent_status(&s.rig).await;
    assert!(stats["oldest_kept_at"].is_null());
    assert_eq!(stats["oldest_waiting_at"], 100);
}

// ---------------------------------------------------------------------------
// The stamp counter inside the fence and the hold
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn the_fence_and_the_hold_fail_below_the_counter_that_was_compared() {
    let s = setup().await;
    // A sliced write raised the stamp twice.
    s.put_to("other", &s.new).await.expect(200);
    let counter = u64::try_from(point(&s.rig).counter).unwrap();
    assert_eq!(counter, 2);
    let catalog = &s.rig.bridge.catalog;
    let now = s.rig.now();

    // The check saw a stamp object this catalogue does not know.
    let write = guard_rows(&s, "abandoned", "nothing");
    let ahead = Some(counter + 1);
    assert_eq!(
        catalog.fence_intents(&write, now, ahead).await.unwrap(),
        IntentFence::Refused
    );
    assert_eq!(states(&s.rig), [("abandoned".to_string(), 1)]);
    // Level with it, or above it, the fence goes through.
    for seen in [Some(counter), Some(counter - 1), None] {
        let write = guard_rows(&s, "abandoned", "nothing");
        let fence = catalog.fence_intents(&write, now, seen).await.unwrap();
        assert!(matches!(fence, IntentFence::Fenced { .. }), "{seen:?}");
        assert!(!catalog.hold_intent_fence(&write, 1, ahead).await.unwrap());
        assert_eq!(states(&s.rig), [("sweeping".to_string(), 1)]);
        assert!(catalog.hold_intent_fence(&write, 1, seen).await.unwrap());
    }
    // A catalogue without a stamp row is behind every counter.
    sql(&s.rig, "DELETE FROM rollback_stamp");
    let write = guard_rows(&s, "abandoned", "nothing");
    assert_eq!(
        catalog.fence_intents(&write, now, Some(1)).await.unwrap(),
        IntentFence::Refused
    );
    let write = guard_rows(&s, "sweeping", "nothing");
    assert!(!catalog.hold_intent_fence(&write, 1, Some(1)).await.unwrap());
}

/// The database is restored between the rollback check of a sweep job
/// and the batch that acts on it. The check was made on the catalogue
/// as it was; the batch runs on the restored one and refuses.
#[tokio::test(flavor = "current_thread")]
async fn a_restore_between_the_rollback_check_and_its_batch_stops_the_job() {
    let recorded = |s: &Setup| {
        number(
            &s.rig,
            "SELECT COUNT(*) FROM rollback_stamp WHERE rolled_back_at IS NOT NULL",
        )
    };

    // Before the fence.
    let s = setup().await;
    drop(s.put_stopped(|p| p.blobs == SLICES).await);
    s.rig.trip().disarm();
    let write = s.write();
    s.rig.bridge.clock.advance_ms(DAY_MS);
    snapshot(&s.rig);
    s.put_to("other", &s.new).await.expect(200);
    // The check is two calls; the job stops at the fence.
    let job = run_until(&s.rig, start_job(&s.rig, sweep_job(&write)), 2, Trip::Stall)
        .await
        .stalled();
    rollback(&s.rig);
    assert_eq!(resume(&s.rig, job).await, JobOutcome::Ack);
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
    assert_eq!(orphans(&s.rig).len(), 2 * SLICES, "nothing was deleted");
    assert_eq!(recorded(&s), 0, "the batch refused, not a second check");

    // Before the hold: the rows of the restored catalogue are fenced,
    // as the job left them.
    let s = setup().await;
    drop(s.put_stopped(|p| p.blobs == SLICES).await);
    s.rig.trip().disarm();
    let write = s.write();
    s.rig.bridge.clock.advance_ms(DAY_MS);
    let job = step_to(&s.rig, start_job(&s.rig, sweep_job(&write)), |rig| {
        states(rig) == [("sweeping".to_string(), SLICES)]
    })
    .await
    .stalled();
    snapshot(&s.rig);
    resume(&s.rig, s.put_to("other", &s.new)).await.expect(200);
    // The read of the fenced rows, the two calls of the second check,
    // and the job stops at the hold.
    let calls = s.rig.trip().calls();
    let job = resume_until(&s.rig, job, 2, Trip::Stall).await.stalled();
    assert_eq!(s.rig.trip().calls(), calls + 3);
    rollback(&s.rig);
    assert_eq!(resume(&s.rig, job).await, JobOutcome::Ack);
    assert_eq!(states(&s.rig), [("sweeping".to_string(), SLICES)]);
    assert_eq!(orphans(&s.rig).len(), 2 * SLICES, "nothing was deleted");
    assert_eq!(recorded(&s), 0, "the batch refused, not a second check");
}

// ---------------------------------------------------------------------------
// The start of a replay
// ---------------------------------------------------------------------------

/// A write that died between its record and its publish, marked `kept`
/// by the sweep. Returns the id of its record and the time in it.
async fn kept_write(s: &Setup) -> (String, i64) {
    drop(s.put_stopped(|p| p.record).await);
    s.rig.trip().disarm();
    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(kept(&s.rig));
    let record = unpublished(&s.rig);
    assert_eq!(record.len(), 1);
    let minted = i64::from_str_radix(&record[0][2..15], 16).unwrap();
    (record[0].clone(), minted)
}

/// A kept row is the only sign of a record without an object. A replay
/// that does not read the record must leave the row.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_that_starts_after_a_kept_record_leaves_its_rows() {
    let mut s = setup().await;
    let (record, minted) = kept_write(&s).await;
    let oldest = intents(&s.rig)[0].created_at;
    assert!(oldest <= minted);
    let first = intent_status(&s.rig).await;
    assert_eq!(first["kept_writes"], 1);
    assert_eq!(first["oldest_kept_at"], oldest);

    // A second write died at the same place a day later: its rows are
    // open and hold the id of its record.
    let fut = step_to(&s.rig, s.put_to("other", &s.new), |rig| {
        records(rig).len() == 3
    })
    .await
    .stalled();
    drop(fut);
    s.rig.trip().disarm();
    assert_eq!(
        states(&s.rig),
        [("kept".to_string(), SLICES), ("open".to_string(), SLICES)]
    );

    // From after both records, and from one millisecond after the kept
    // one: neither replay reads the kept record. The open rows go
    // whether or not their record is read; only the kept rows stay.
    for (since, unread) in [(s.rig.now().0 + 1, 2), (minted + 1, 1)] {
        restore_from(&mut s.rig, since).await;
        assert!(kept(&s.rig), "since {since}: only the kept rows stay");
        assert_eq!(intent_status(&s.rig).await["kept_writes"], 1);
        assert_eq!(intent_status(&s.rig).await["oldest_kept_at"], oldest);
        let left = unpublished(&s.rig);
        assert_eq!(left.len(), unread, "since {since}");
        assert!(left.contains(&record), "since {since}");
        assert_eq!(orphans(&s.rig).len(), unread * SLICES, "since {since}");
        assert!(s.body().await == s.old, "since {since}");
    }

    // From the time of the record, or from `oldest_kept_at`: the replay
    // publishes it, and its rows go with the first step.
    restore_from(&mut s.rig, minted).await;
    assert!(s.body().await == s.new);
    assert!(intents(&s.rig).is_empty());
    let last = intent_status(&s.rig).await;
    assert_eq!(last["kept_writes"], 0);
    assert!(last["oldest_kept_at"].is_null());
    assert!(unpublished(&s.rig).is_empty() && orphans(&s.rig).is_empty());
    assert!(broken(&s.rig).is_empty());

    let mut s = setup().await;
    kept_write(&s).await;
    let oldest = intents(&s.rig)[0].created_at;
    restore_from(&mut s.rig, oldest).await;
    assert!(s.body().await == s.new);
    assert!(intents(&s.rig).is_empty() && broken(&s.rig).is_empty());
}

/// Two begins read the mark of the replay before them and then write
/// their own. The second one to write must not get the mark of the
/// first: a cursor belongs to one replay.
#[tokio::test(flavor = "current_thread")]
async fn two_begins_at_once_get_two_marks() {
    let s = setup().await;
    let catalog = &s.rig.bridge.catalog;
    let now = s.rig.now();
    let mark = || number(&s.rig, "SELECT started_at FROM restore_state");
    for round in 0..2 {
        // The first begin has read the mark and stops at its batch.
        let first = run_until(
            &s.rig,
            catalog.restore_begin(UnixMs(500), now),
            1,
            Trip::Stall,
        )
        .await
        .stalled();
        let second = catalog.restore_begin(UnixMs(500), now).await.unwrap();
        let second = second.unwrap();
        assert_eq!(mark(), second.0, "round {round}");
        let first = resume(&s.rig, first).await.unwrap().unwrap();
        assert!(first > second, "round {round}: {first:?} after {second:?}");
        assert_eq!(mark(), first.0, "round {round}");
    }
}

/// A begin read that the last replay had ended. Before its batch runs,
/// the database is restored to a point at which that replay had not
/// ended. The batch must hold the rule itself: a later restore point
/// than the one of an unfinished replay is refused.
#[tokio::test(flavor = "current_thread")]
async fn a_begin_does_not_move_an_unfinished_replay_to_a_later_point() {
    let s = setup().await;
    let catalog = &s.rig.bridge.catalog;
    let now = s.rig.now();
    let run = catalog.restore_begin(UnixMs(100), now).await.unwrap();
    let run = run.unwrap();
    snapshot(&s.rig);
    sql(
        &s.rig,
        &format!(
            "UPDATE restore_state SET state = 'complete', finished_at = {}",
            now.0
        ),
    );

    let later = run_until(
        &s.rig,
        catalog.restore_begin(UnixMs(500), now),
        1,
        Trip::Stall,
    )
    .await
    .stalled();
    rollback(&s.rig);
    assert_eq!(resume(&s.rig, later).await.unwrap(), Err(UnixMs(100)));
    assert_eq!(
        column(
            &s.rig,
            "SELECT state || ' ' || since_ms || ' ' || started_at FROM restore_state"
        ),
        [format!("replaying 100 {}", run.0)]
    );

    // Another begin from a later point started and has not ended.
    let s = setup().await;
    let catalog = &s.rig.bridge.catalog;
    let later = run_until(
        &s.rig,
        catalog.restore_begin(UnixMs(500), now),
        1,
        Trip::Stall,
    )
    .await
    .stalled();
    catalog
        .restore_begin(UnixMs(100), now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resume(&s.rig, later).await.unwrap(), Err(UnixMs(100)));
    assert_eq!(number(&s.rig, "SELECT since_ms FROM restore_state"), 100);
}

// ---------------------------------------------------------------------------
// A sweep job that dies
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_sweep_job_that_stops_at_any_call_is_finished_by_the_next_tick() {
    for keeps in [false, true] {
        for trip in [Trip::Stall, Trip::Fail, Trip::Lost] {
            let mut n = 0;
            loop {
                let s = setup().await;
                // Killed with every slice stored: before the record, or
                // after it.
                drop(
                    s.put_stopped(|p| if keeps { p.record } else { p.blobs == SLICES })
                        .await,
                );
                s.rig.trip().disarm();
                s.rig.bridge.clock.advance_ms(DAY_MS);
                let all = records(&s.rig);
                let jobs = sweep_jobs(&s.rig).await;
                assert_eq!(jobs.len(), 1);

                let job = start_job(&s.rig, jobs[0].clone());
                let ran = run_until(&s.rig, job, n, trip).await;
                let reached = s.rig.trip().tripped();
                s.rig.trip().disarm();
                let what = format!("keeps={keeps} {trip:?} at call {n}");
                match ran.done() {
                    Some(outcome) if !reached => assert_eq!(outcome, JobOutcome::Ack, "{what}"),
                    Some(JobOutcome::Ack) => assert_eq!(trip, Trip::Fail, "{what}"),
                    _ => {}
                }
                assert!(broken(&s.rig).is_empty(), "{what}");

                sweep_out(&s.rig).await;
                assert_eq!(records(&s.rig), all, "{what}");
                assert!(s.body().await == s.old, "{what}");
                let stats = intent_status(&s.rig).await;
                if keeps {
                    assert!(kept(&s.rig), "{what}: {:?}", states(&s.rig));
                    assert_eq!(orphans(&s.rig).len(), SLICES, "{what}");
                    assert_eq!(stats["anomalies"], 1, "{what}");
                    assert_eq!(stats["kept_writes"], 1, "{what}");
                } else {
                    assert!(intents(&s.rig).is_empty(), "{what}");
                    assert!(orphans(&s.rig).is_empty(), "{what}");
                    assert_eq!(stats["anomalies"], 0, "{what}");
                }
                assert_eq!(stats["waiting_writes"], 0, "{what}");
                if !reached {
                    assert!(n >= 4, "the job made {n} calls");
                    break;
                }
                n += 1;
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_tick_hands_over_twenty_writes_oldest_first_and_the_switch_stops_it() {
    let mut cfg = small_config();
    cfg.intent_sweep = false;
    let mut s = setup_with(cfg).await;
    drop(s.put_stopped(|p| p.blobs == SLICES).await);
    s.rig.trip().disarm();
    let killed = s.write();
    for i in 0..24 {
        sql(
            &s.rig,
            &format!(
                "INSERT INTO write_intents(extent_id, write_id, state, created_at) \
                 VALUES ('x_gone{i:02}', 'w_gone{i:02}', 'abandoned', {})",
                T0.0 - 1000 + i
            ),
        );
    }
    s.rig.bridge.clock.advance_ms(DAY_MS);

    // Switched off: no job is sent, a job that arrives does nothing, and
    // the rows wait.
    assert_eq!(sweep_jobs(&s.rig).await.len(), 0);
    assert_eq!(s.sweep(&killed).await, JobOutcome::Ack);
    assert_eq!(s.rig.count("write_intents"), 24 + SLICES as i64);
    assert_eq!(orphans(&s.rig).len(), SLICES);
    let stats = intent_status(&s.rig).await;
    assert_eq!(stats["sweep"], "off");
    assert_eq!(stats["waiting_writes"], 25);
    assert_eq!(stats["oldest_waiting_at"], T0.0 - 1000);

    std::rc::Rc::get_mut(&mut s.rig.bridge)
        .unwrap()
        .cfg
        .intent_sweep = true;
    assert_eq!(intent_status(&s.rig).await["sweep"], "on");
    let jobs = sweep_jobs(&s.rig).await;
    let sent: Vec<String> = jobs
        .iter()
        .map(|j| match j {
            Job::Sweep { write, .. } => write.as_str().to_string(),
            other => panic!("{other:?}"),
        })
        .collect();
    let expected: Vec<String> = (0..20).map(|i| format!("w_gone{i:02}")).collect();
    assert_eq!(sent, expected);
    for job in &jobs {
        // A slice that was never stored is no obstacle.
        assert_eq!(s.rig.bridge.run_job(job).await, JobOutcome::Ack);
    }
    assert_eq!(s.rig.count("write_intents"), 4 + SLICES as i64);
    assert_eq!(sweep_tick(&s.rig).await, 5);
    assert!(intents(&s.rig).is_empty() && orphans(&s.rig).is_empty());
    assert!(s.body().await == s.old);
}

// ---------------------------------------------------------------------------
// The sweep against a restore of the catalogue
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_catalogue_restored_into_an_upload_without_maintenance_loses_nothing() {
    for last_raise_fails in [false, true] {
        restored_into_an_upload(last_raise_fails).await;
    }
}

/// With `last_raise_fails` the raise that follows the commit stores
/// nothing: the one before the record is then the only stamp of the
/// write.
async fn restored_into_an_upload(last_raise_fails: bool) {
    let mut s = setup().await;
    // The point the catalogue is taken back to: two slices stored.
    let fut = s.put_stopped(|p| p.blobs == 2).await;
    snapshot(&s.rig);
    if last_raise_fails {
        let fut = step_to(&s.rig, fut, |rig| point(rig).published)
            .await
            .stalled();
        *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("rs/".into());
        resume(&s.rig, fut).await.expect(200);
        *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
        assert_eq!(point(&s.rig).stamps, 1);
    } else {
        resume(&s.rig, fut).await.expect(200);
        assert_eq!(point(&s.rig).stamps, 2);
    }
    assert!(s.body().await == s.new);
    let all = (blobs(&s.rig), records(&s.rig));

    // More than a day later the database is restored to that point.
    // Nobody switched maintenance on.
    s.rig.bridge.clock.advance_ms(DAY_MS);
    rollback(&s.rig);
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
    assert!(intents(&s.rig).iter().all(|i| i.generation.is_none()));
    let write = s.write();

    // A sweep job that runs before any tick has looked: it refuses.
    assert_eq!(s.sweep(&write).await, JobOutcome::Ack);
    assert_eq!((blobs(&s.rig), records(&s.rig)), all);
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
    // The tick sends no job, and the write gate is closed.
    let report = s.rig.bridge.dispatch().await.unwrap();
    assert!(report.rolled_back);
    assert_eq!(report.sweeps_enqueued, 0);
    assert_eq!(status(&s.rig).await["catalogue_rolled_back"], true);
    s.rig
        .put(&s.signer, BUCKET, "other", b"x")
        .await
        .expect_writes_refused();
    s.put().await.expect_writes_refused();
    assert_eq!(s.sweep(&write).await, JobOutcome::Ack);
    assert_eq!((blobs(&s.rig), records(&s.rig)), all);

    // The replay brings the object back, and the rows of the restored
    // table are gone with its start.
    restore(&mut s.rig).await;
    assert!(s.body().await == s.new);
    assert!(intents(&s.rig).is_empty());
    assert!(broken(&s.rig).is_empty() && orphans(&s.rig).is_empty());
    assert_eq!(sweep_tick(&s.rig).await, 0);
    assert_eq!(blobs(&s.rig), all.0);
}

#[tokio::test(flavor = "current_thread")]
async fn the_raise_before_the_record_has_to_succeed() {
    let s = setup().await;
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("rs/".into());
    s.put().await.expect_error(503, "SlowDown");
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    assert!(
        unpublished(&s.rig).is_empty(),
        "no record without its stamp"
    );
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
    assert!(s.body().await == s.old);
}

/// The two cases the stamp of a commit does not see: the handler is
/// killed between its commit and the raise that follows, or that raise
/// fails. The catalogue is then restored to a point before the commit.
#[tokio::test(flavor = "current_thread")]
async fn a_commit_without_its_stamp_is_kept_after_a_restore_and_replayed() {
    for killed in [true, false] {
        let mut s = setup().await;
        // The restore point: the latest one the first raise does not
        // cover.
        let fut = s.put_stopped(|p| p.stamps == 1).await;
        snapshot(&s.rig);
        if killed {
            let fut = step_to(&s.rig, fut, |rig| point(rig).published)
                .await
                .stalled();
            assert_eq!(point(&s.rig).stamps, 1);
            drop(fut);
            s.rig.trip().disarm();
        } else {
            *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("rs/".into());
            // The commit stands and is answered.
            resume(&s.rig, fut).await.expect(200);
            *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
            assert_eq!(point(&s.rig).stamps, 1);
        }
        assert!(s.body().await == s.new);
        let all = (blobs(&s.rig), records(&s.rig));

        rollback(&s.rig);
        // Nothing tells this catalogue from one that was never restored.
        assert!(!s.rig.bridge.catalogue_rolled_back().await.unwrap());
        assert!(s.body().await == s.old);
        assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
        assert!(intents(&s.rig).iter().all(|i| i.generation.is_some()));

        s.rig.bridge.clock.advance_ms(DAY_MS);
        assert_eq!(sweep_tick(&s.rig).await, 1, "killed={killed}");
        // The rows name the record, and the record is there.
        assert!(kept(&s.rig), "killed={killed}");
        assert_eq!((blobs(&s.rig), records(&s.rig)), all, "killed={killed}");
        assert_eq!(intent_status(&s.rig).await["anomalies"], 1);

        restore(&mut s.rig).await;
        assert!(s.body().await == s.new, "killed={killed}");
        assert!(broken(&s.rig).is_empty() && orphans(&s.rig).is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_counter_behind_the_newest_stamp_or_missing_refuses_the_sweep() {
    for tamper in [
        "UPDATE rollback_stamp SET counter = counter - 1",
        "DELETE FROM rollback_stamp",
    ] {
        let s = setup().await;
        // A sliced write raised the stamp; another one died.
        s.put_to("other", &s.new).await.expect(200);
        drop(s.put_stopped(|p| p.blobs == SLICES + 5).await);
        s.rig.trip().disarm();
        let write = s.write();
        s.rig.bridge.clock.advance_ms(DAY_MS);
        let all = blobs(&s.rig);

        sql(&s.rig, tamper);
        assert_eq!(s.sweep(&write).await, JobOutcome::Ack, "{tamper}");
        assert_eq!(blobs(&s.rig), all, "{tamper}");
        assert_eq!(states(&s.rig), [("open".to_string(), SLICES)], "{tamper}");
        assert!(s.rig.bridge.catalogue_rolled_back().await.unwrap());
        assert_eq!(sweep_jobs(&s.rig).await.len(), 0, "{tamper}");
        assert_eq!(blobs(&s.rig), all, "{tamper}");
    }

    // The same rows on a catalogue that is level with its stamp go.
    let s = setup().await;
    s.put_to("other", &s.new).await.expect(200);
    drop(s.put_stopped(|p| p.blobs == SLICES + 5).await);
    s.rig.trip().disarm();
    s.rig.bridge.clock.advance_ms(DAY_MS);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_started_replay_empties_the_intents_and_refuses_every_step() {
    let mut s = setup().await;
    drop(s.put_stopped(|p| p.blobs == SLICES).await);
    s.rig.trip().disarm();
    s.rig.bridge.clock.advance_ms(DAY_MS);
    snapshot(&s.rig);
    let write = WriteId::new(s.write());
    let all = blobs(&s.rig);
    let again = "INSERT INTO write_intents SELECT * FROM snap_write_intents; \
                 UPDATE write_intents SET state = 'abandoned';";
    let catalog = &s.rig.bridge.catalog;

    // A first begin, a second one, and one with an earlier restore point.
    let point = UnixMs(1_000);
    for (i, since) in [point, point, UnixMs(0)].into_iter().enumerate() {
        if i > 0 {
            sql(&s.rig, again);
            assert_eq!(s.rig.count("write_intents"), SLICES as i64);
        }
        s.rig.bridge.clock.advance_ms(1);
        let begun = catalog.restore_begin(since, s.rig.now()).await.unwrap();
        assert!(begun.is_ok(), "begin {i}");
        assert_eq!(s.rig.count("write_intents"), 0, "begin {i}");
    }
    // A begin that is refused (a later restore point than the one of the
    // replay that has not ended) starts nothing and empties nothing.
    sql(&s.rig, again);
    let refused = catalog.restore_begin(point, s.rig.now()).await.unwrap();
    assert_eq!(refused, Err(UnixMs(0)));
    assert_eq!(s.rig.count("write_intents"), SLICES as i64);
    sql(&s.rig, "DELETE FROM write_intents");

    // Under the replay nothing about intents goes through, also when a
    // caller skipped its own check.
    sql(&s.rig, again);
    let open_before = s.rig.now();
    assert_eq!(
        catalog
            .fence_intents(&write, open_before, None)
            .await
            .unwrap(),
        IntentFence::Refused
    );
    assert!(!catalog
        .hold_intent_fence(&write, SLICES, None)
        .await
        .unwrap());
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
    sql(&s.rig, "UPDATE write_intents SET state = 'open'");
    let id = GenerationId::new("g_0000000000001aaaaaaaaaaaaaaaa");
    assert_eq!(
        catalog
            .intents_generation(&write, &id, SLICES)
            .await
            .unwrap(),
        Guard::Lost
    );
    let fresh = [ExtentId::new("x_fresh")];
    assert_eq!(
        catalog
            .open_intents(&WriteId::new("w_fresh"), &fresh, s.rig.now())
            .await
            .unwrap(),
        Guard::Lost
    );
    assert_eq!(s.rig.count("write_intents"), SLICES as i64);
    sql(&s.rig, "UPDATE write_intents SET state = 'abandoned'");
    // The job and the tick refuse as well, and a sliced PUT stores
    // nothing.
    assert_eq!(s.sweep(write.as_str()).await, JobOutcome::Ack);
    assert_eq!(sweep_jobs(&s.rig).await.len(), 0);
    s.put().await.expect_error(503, "ServiceUnavailable");
    assert_eq!(blobs(&s.rig), all);
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);

    // The replay to its end: the table is empty and the gate open.
    restore(&mut s.rig).await;
    assert_eq!(s.rig.count("write_intents"), 0);
    s.put().await.expect(200);
    assert!(s.body().await == s.new);
}

#[tokio::test(flavor = "current_thread")]
async fn a_replay_that_starts_under_a_writer_publishes_nothing_of_it() {
    for at in [2, SLICES] {
        let s = setup().await;
        let fut = s.put_stopped(|p| p.blobs == at).await;
        s.rig
            .bridge
            .catalog
            .restore_begin(UnixMs(0), s.rig.now())
            .await
            .unwrap()
            .unwrap();
        resume(&s.rig, fut).await.expect_writes_refused();
        assert_eq!(s.rig.count("generations"), 1);
        assert_eq!(s.rig.count("write_intents"), 0);
        assert!(unpublished(&s.rig).is_empty());
        assert!(broken(&s.rig).is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_restore_between_the_fence_and_the_delete_stops_the_job() {
    /// A dead write past its grace period and its sweep job, stopped
    /// with the rows fenced and no slice deleted.
    async fn fenced(s: &Setup, before: impl FnOnce(&Setup)) -> Running<'static, JobOutcome> {
        drop(s.put_stopped(|p| p.blobs == SLICES).await);
        s.rig.trip().disarm();
        s.rig.bridge.clock.advance_ms(DAY_MS);
        before(s);
        let job = start_job(&s.rig, sweep_job(&s.write()));
        step_to(&s.rig, job, |rig| {
            states(rig) == [("sweeping".to_string(), SLICES)]
        })
        .await
        .stalled()
    }

    // A replay starts.
    let s = setup().await;
    let job = fenced(&s, |_| {}).await;
    s.rig
        .bridge
        .catalog
        .restore_begin(UnixMs(0), s.rig.now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resume(&s.rig, job).await, JobOutcome::Ack);
    assert_eq!(orphans(&s.rig).len(), SLICES);

    // The database is restored to a point before the fence, and a write
    // raised the stamp in between.
    let s = setup().await;
    let job = fenced(&s, |s| snapshot(&s.rig)).await;
    resume(&s.rig, s.put_to("other", &s.new)).await.expect(200);
    let job = step_to(&s.rig, job, |_| true).await.stalled();
    rollback(&s.rig);
    assert_eq!(resume(&s.rig, job).await, JobOutcome::Ack);
    assert_eq!(orphans(&s.rig).len(), 2 * SLICES, "nothing was deleted");
    assert!(s.rig.bridge.catalogue_rolled_back().await.unwrap());
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);

    // The same without a raise in between, and the job has read its
    // rows: they are not fenced any more, so it deletes nothing. The
    // next tick starts over.
    let s = setup().await;
    let job = fenced(&s, |s| snapshot(&s.rig)).await;
    let job = resume_until(&s.rig, job, 0, Trip::Stall).await.stalled();
    rollback(&s.rig);
    assert_eq!(resume(&s.rig, job).await, JobOutcome::Ack);
    assert_eq!(orphans(&s.rig).len(), SLICES);
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());

    // The database is restored to a point after the fence, and a write
    // raised the stamp in between. The rows are fenced as the job left
    // them, and a catalogue behind its stamp still stops the delete.
    let s = setup().await;
    let job = fenced(&s, |_| {}).await;
    let job = resume_until(&s.rig, job, 0, Trip::Stall).await.stalled();
    snapshot(&s.rig);
    resume(&s.rig, s.put_to("other", &s.new)).await.expect(200);
    rollback(&s.rig);
    assert_eq!(states(&s.rig), [("sweeping".to_string(), SLICES)]);
    assert_eq!(resume(&s.rig, job).await, JobOutcome::Ack);
    assert_eq!(orphans(&s.rig).len(), 2 * SLICES, "nothing was deleted");
    assert_eq!(states(&s.rig), [("sweeping".to_string(), SLICES)]);
    assert_eq!(sweep_tick(&s.rig).await, 0, "and no tick sends a job");
}

// ---------------------------------------------------------------------------
// Random interleavings
// ---------------------------------------------------------------------------

/// SplitMix64.
struct Rand(u64);

impl Rand {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Copy>(&mut self, of: &[T]) -> T {
        of[self.below(of.len() as u64) as usize]
    }
}

/// A PutObject that has not ended.
struct Paused {
    fut: Running<'static, Resp>,
    key: &'static str,
    body: Vec<u8>,
    /// How far the clock moved under it.
    waited_ms: i64,
}

/// What the test knows about the keys while requests, sweeps and
/// restores of the catalogue follow each other in a random order.
struct World {
    rig: Rig,
    signer: Signer,
    rand: Rand,
    /// Every body sent to a key.
    sent: BTreeMap<&'static str, Vec<Vec<u8>>>,
    /// What a key may read once every record is replayed: the body of
    /// the last `200`, and of every request that ended without one
    /// since.
    allowed: BTreeMap<&'static str, Vec<Vec<u8>>>,
    acknowledged: BTreeSet<&'static str>,
    paused: Option<Paused>,
    snapshot: bool,
    /// Every write id seen.
    writes: BTreeSet<String>,
    bodies: u8,
    checked: u64,
    swept: u64,
}

const KEYS: [&str; 3] = ["a", "b", "c"];

impl World {
    async fn new(seed: u64) -> World {
        let rig = small_rig();
        let (_, signer) = rig.standard(BUCKET).await;
        World {
            rig,
            signer,
            rand: Rand(seed),
            sent: BTreeMap::new(),
            allowed: BTreeMap::new(),
            acknowledged: BTreeSet::new(),
            paused: None,
            snapshot: false,
            writes: BTreeSet::new(),
            bodies: 0,
            checked: 0,
            swept: 0,
        }
    }

    fn request(&mut self) -> (&'static str, Vec<u8>, Running<'static, Resp>) {
        let key = self.rand.pick(&KEYS);
        let len = self
            .rand
            .pick(&[100, EXTENT, EXTENT + 1, 3 * SLICE, 5 * SLICE + 7]);
        self.bodies = self.bodies.wrapping_add(1);
        let body = pattern(self.bodies, len);
        let mode = self.rand.pick(&MODES);
        let req = mode_req(&self.rig, &self.signer, key, &body, mode);
        self.sent.entry(key).or_default().push(body.clone());
        (key, body.clone(), start(&self.rig, req))
    }

    /// A request ended: with an answer, or killed.
    fn ended(&mut self, key: &'static str, body: Vec<u8>, answer: Option<&Resp>) {
        match answer.map(|r| r.status) {
            Some(200) => {
                self.allowed.insert(key, vec![body]);
                self.acknowledged.insert(key);
            }
            // Refused before anything was stored.
            Some(503) if !self.acknowledged.contains(key) && !self.allowed.contains_key(key) => {
                self.allowed.entry(key).or_default().push(body);
            }
            _ => self.allowed.entry(key).or_default().push(body),
        }
    }

    fn trip(&mut self) -> (u64, Trip) {
        (
            self.rand.below(45),
            self.rand.pick(&[Trip::Stall, Trip::Fail, Trip::Lost]),
        )
    }

    async fn step(&mut self) {
        match self.rand.below(12) {
            // A request from start to end.
            0 | 1 => {
                let (key, body, fut) = self.request();
                let r = fut.await;
                self.ended(key, body, Some(&r));
            }
            // A request that is killed, or one of whose calls fails.
            2 | 3 => {
                let (key, body, fut) = self.request();
                let (skip, trip) = self.trip();
                let ran = run_until(&self.rig, fut, skip, trip).await;
                self.rig.trip().disarm();
                self.ended(key, body, ran.done().as_ref());
            }
            // A request that stops for a while.
            4 if self.paused.is_none() => {
                let (key, body, fut) = self.request();
                let skip = self.rand.below(45);
                match run_until(&self.rig, fut, skip, Trip::Stall).await {
                    Ran::Stalled(fut) => {
                        self.paused = Some(Paused {
                            fut,
                            key,
                            body,
                            waited_ms: 0,
                        })
                    }
                    Ran::Done(r) => self.ended(key, body, Some(&r)),
                }
                self.rig.trip().disarm();
            }
            // It goes on: some calls, to its end, or not at all.
            4 | 5 => {
                let Some(p) = self.paused.take() else { return };
                let (skip, trip) = match self.rand.below(4) {
                    0 => (u64::MAX, Trip::Stall),
                    1 => {
                        // Killed.
                        self.ended(p.key, p.body, None);
                        return;
                    }
                    _ => self.trip(),
                };
                match resume_until(&self.rig, p.fut, skip, trip).await {
                    Ran::Stalled(fut) => self.paused = Some(Paused { fut, ..p }),
                    Ran::Done(r) => self.ended(p.key, p.body, Some(&r)),
                }
                self.rig.trip().disarm();
            }
            // Time passes. A request lives less than the twelve hours
            // after which it gives up by itself.
            6 | 7 => {
                let mut ms = self
                    .rand
                    .pick(&[1000, HOUR_MS, 5 * HOUR_MS, 13 * HOUR_MS, DAY_MS]);
                if let Some(p) = &mut self.paused {
                    ms = ms.min(11 * HOUR_MS - p.waited_ms);
                    p.waited_ms += ms;
                }
                self.rig.bridge.clock.advance_ms(ms);
            }
            // A tick and its sweep jobs, some of which die.
            8 | 9 => {
                let mut jobs = sweep_jobs(&self.rig).await;
                // And a job of some earlier tick, delivered late.
                if !self.writes.is_empty() && self.rand.below(2) == 0 {
                    let all: Vec<&str> = self.writes.iter().map(String::as_str).collect();
                    jobs.push(sweep_job(self.rand.pick(&all)));
                }
                for job in jobs {
                    let records = records(&self.rig);
                    let fut = start_job(&self.rig, job);
                    if self.rand.below(3) == 0 {
                        let (skip, trip) = self.trip();
                        drop(run_until(&self.rig, fut, skip % 14, trip).await);
                        self.rig.trip().disarm();
                    } else {
                        fut.await;
                    }
                    self.swept += 1;
                    assert_eq!(
                        records,
                        self::records(&self.rig),
                        "the sweep deleted a record"
                    );
                    self.check().await;
                }
            }
            10 => {
                if !self.snapshot || self.rand.below(3) == 0 {
                    snapshot(&self.rig);
                    self.snapshot = true;
                } else {
                    // The database goes back, with whatever runs.
                    rollback(&self.rig);
                }
            }
            // The runbook's restore. Nothing else runs under it.
            _ => {
                if let Some(p) = self.paused.take() {
                    self.ended(p.key, p.body, None);
                }
                restore(&mut self.rig).await;
            }
        }
    }

    /// What holds after every step.
    async fn check(&mut self) {
        let rig = &self.rig;
        for i in intents(rig) {
            self.writes.insert(i.write);
        }
        // No extent row without its slice.
        assert_eq!(broken(rig), Vec::<String>::new());
        // No recovery record without every slice it names.
        let have: BTreeSet<String> = blobs(rig).into_iter().collect();
        for id in records(rig) {
            let name = recovery::generation_key(&GenerationId::new(id.clone()));
            let record = recovery::read_generation(&rig.bridge.safety, &rig.bridge.kek, &name)
                .await
                .unwrap()
                .unwrap();
            assert!(!record.extents.is_empty());
            for extent in &record.extents {
                assert!(
                    have.contains(&extent.id),
                    "record {id} lost its slice {}",
                    extent.id
                );
            }
            self.checked += 1;
        }
    }

    /// Whatever the catalogue says at this moment, a key reads a body
    /// that was sent to it, whole.
    async fn read(&self) {
        for key in KEYS {
            let r = get(&self.rig, &self.signer, key).await;
            match r.status {
                200 => assert!(
                    self.sent[key].contains(&r.body),
                    "{key} reads something that was never sent"
                ),
                404 | 503 => {}
                other => panic!("{key}: {other} {}", r.text()),
            }
        }
    }

    /// The end: every record is replayed, and each key reads what its
    /// last answers allow.
    async fn finish(mut self) -> (u64, u64) {
        if let Some(p) = self.paused.take() {
            self.ended(p.key, p.body, None);
        }
        self.rig.bridge.clock.advance_ms(DAY_MS);
        restore(&mut self.rig).await;
        self.check().await;
        self.rig.bridge.clock.advance_ms(DAY_MS);
        sweep_out(&self.rig).await;
        self.check().await;
        for key in KEYS {
            let r = get(&self.rig, &self.signer, key).await;
            let allowed = self.allowed.get(key).cloned().unwrap_or_default();
            match r.status {
                200 => assert!(allowed.contains(&r.body), "{key}"),
                404 => assert!(!self.acknowledged.contains(key), "{key} is gone"),
                other => panic!("{key}: {other} {}", r.text()),
            }
        }
        // The replay emptied the intents, and nothing was written since.
        assert!(intents(&self.rig).is_empty());
        (self.checked, self.swept)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn random_writers_sweeps_rollbacks_and_replays_lose_nothing() {
    let (mut checked, mut swept) = (0, 0);
    for seed in 0..60 {
        let mut world = World::new(seed).await;
        for step in 0..80 {
            world.rig.bridge.clock.advance_ms(1000);
            let what = format!("seed {seed} step {step}");
            let guard = PanicNote(what);
            world.step().await;
            world.check().await;
            world.read().await;
            std::mem::forget(guard);
        }
        let guard = PanicNote(format!("seed {seed} at the end"));
        let (c, s) = world.finish().await;
        std::mem::forget(guard);
        checked += c;
        swept += s;
    }
    // The run looked at something.
    assert!(checked > 1000, "{checked} records checked");
    assert!(swept > 100, "{swept} sweep jobs");
}

/// Says where a failed run was.
struct PanicNote(String);

impl Drop for PanicNote {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("failed at {}", self.0);
        }
    }
}
