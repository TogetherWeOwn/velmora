//! `impl JobSink` over Queues. A `Job` is sent as a JSON message. Post jobs
//! go to a post queue (`POST_Q`, and `POST_Q2`, `POST_Q3`, ... where they
//! are bound); verify, release, gc and recovery-copy jobs go to a verify
//! queue (`VERIFY_Q`, `VERIFY_Q2`, ...). An extent's job always goes to
//! the same queue of its kind ([`shard`]).
//!
//! Dev only: `DEV_DROP_NOTIFY_N` makes the first `n` `send` calls of the
//! isolate fail without sending (a queue that refuses the notification),
//! so the local acceptance run can prove that the handler leaves the
//! outbox row unmarked and the next run of the cron dispatcher sends its
//! job. (A notification lost after the queue took it is made up for only
//! when its mark has aged, an hour or more: the native tests cover that
//! with their own clock.) `send_many` is never dropped; the dispatcher
//! must keep re-enqueueing extents through it so the re-drive itself is
//! never lost.
//! A restarted isolate re-arms the counter. Outside `ENVIRONMENT=dev` the
//! variable is ignored.

use std::sync::atomic::{AtomicU32, Ordering};

use std::time::Duration;

use futures_util::future::{join_all, select, Either};
use velmora_bridge::{
    Backlog, BridgeError, Job, JobSink, Oldest, OutboxStage, Result, UnixMs, MAX_QUEUE_DELAY_SECS,
};
use worker::js_sys::{Function, Promise, Reflect};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::{console_error, MessageBuilder, Queue, QueueContentType};

/// Queues' `sendBatch` limit.
const MAX_BATCH: usize = 100;

/// Name of the dev-only drop counter variable.
pub const DEV_DROP_NOTIFY_N: &str = "DEV_DROP_NOTIFY_N";

/// Sends still to be dropped. Read once when the isolate builds its bridge,
/// so it counts down across the isolate's requests.
#[derive(Debug, Default)]
pub struct DropNotify(AtomicU32);

impl DropNotify {
    /// `dev` is the validated environment. Outside dev the value is never
    /// read (always 0). In dev, absent or empty is 0 and anything other than
    /// a non-negative integer is refused.
    pub fn from_var(dev: bool, raw: Option<&str>) -> std::result::Result<Self, String> {
        if !dev {
            return Ok(DropNotify::default());
        }
        let n = match raw.map(str::trim) {
            None | Some("") => 0,
            Some(v) => v
                .parse::<u32>()
                .map_err(|_| format!("invalid {DEV_DROP_NOTIFY_N}"))?,
        };
        Ok(DropNotify(AtomicU32::new(n)))
    }

    /// `true` = drop this send (and count it).
    fn take(&self) -> bool {
        // A compare-exchange loop rather than `fetch_update`, which newer
        // toolchains deprecate while its replacement is above the MSRV.
        let mut n = self.0.load(Ordering::Relaxed);
        while n > 0 {
            match self
                .0
                .compare_exchange_weak(n, n - 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(current) => n = current,
            }
        }
        false
    }

    #[cfg(test)]
    fn remaining(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Most queues of one kind a deployment may bind (`POST_Q`, `POST_Q2`,
/// ... and `VERIFY_Q`, `VERIFY_Q2`, ...).
pub const MAX_QUEUES: usize = 8;

/// The binding name of queue `index` (from 0) of the kind `first` names:
/// `POST_Q`, then `POST_Q2`, `POST_Q3`, ...
pub fn binding_name(first: &str, index: usize) -> String {
    match index {
        0 => first.into(),
        n => format!("{first}{}", n + 1),
    }
}

/// How many queues of the kind `first` names are bound, given which
/// binding names exist: `first`, `first2`, ... counted up to the first
/// name that is not bound. A name bound after a gap is refused with that
/// name: the queues after a gap would silently get no jobs.
pub fn bound_queues(
    first: &str,
    is_bound: impl Fn(&str) -> bool,
) -> std::result::Result<usize, String> {
    let bound: Vec<bool> = (0..MAX_QUEUES)
        .map(|index| is_bound(&binding_name(first, index)))
        .collect();
    let count = bound.iter().take_while(|b| **b).count();
    match bound.iter().skip(count).position(|b| *b) {
        Some(after) => {
            let (stray, gap) = (
                binding_name(first, count + after),
                binding_name(first, count),
            );
            Err(format!("binding {stray} without {gap}"))
        }
        None if count == 0 => Err(format!("missing binding {first}")),
        None => Ok(count),
    }
}

pub struct QueueSink {
    /// Never empty.
    post: Vec<Queue>,
    /// Never empty.
    verify: Vec<Queue>,
    /// The queue of the jobs that name no extent ([`AUX_Q`]), when
    /// bound.
    aux: Option<Queue>,
    drop_notify: DropNotify,
}

/// The binding of the queue for jobs that name no extent: gc, sweep,
/// eviction and recovery copy. Optional: without it they go to the first
/// verify queue, as before. There they wait in front of that queue's
/// verify and release jobs, which then fall hours behind the other
/// verify queues' whenever many recovery-copy jobs are sent.
pub const AUX_Q: &str = "AUX_Q";

impl QueueSink {
    /// `post` and `verify` hold the queues of each kind in binding order,
    /// at least one each: an empty list is refused, with the name of the
    /// first binding of the kind. `aux` is the queue bound as [`AUX_Q`].
    pub fn new(
        post: Vec<Queue>,
        verify: Vec<Queue>,
        aux: Option<Queue>,
        drop_notify: DropNotify,
    ) -> std::result::Result<Self, &'static str> {
        if post.is_empty() {
            return Err("POST_Q");
        }
        if verify.is_empty() {
            return Err("VERIFY_Q");
        }
        Ok(QueueSink {
            post,
            verify,
            aux,
            drop_notify,
        })
    }

    fn shards(&self) -> Shards {
        Shards {
            post: self.post.len(),
            verify: self.verify.len(),
            aux: self.aux.is_some(),
        }
    }

    fn queue(&self, lane: Lane) -> &Queue {
        match lane {
            Lane::Post(shard) => &self.post[shard],
            Lane::Verify(shard) => &self.verify[shard],
            // `lane` names it only when it is bound.
            Lane::Aux => self.aux.as_ref().unwrap_or(&self.verify[0]),
        }
    }
}

/// The queue a job is sent to: the kind and the queue's index in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Post(usize),
    Verify(usize),
    /// The queue of the jobs that name no extent.
    Aux,
}

/// How many queues of each kind are bound, at least one each.
#[derive(Clone, Copy, Debug)]
struct Shards {
    post: usize,
    verify: usize,
    /// The queue for jobs that name no extent is bound.
    aux: bool,
}

impl Shards {
    /// Every lane, post queues first.
    fn lanes(self) -> impl Iterator<Item = Lane> {
        (0..self.post)
            .map(Lane::Post)
            .chain((0..self.verify).map(Lane::Verify))
            .chain(self.aux.then_some(Lane::Aux))
    }
}

/// The queue of an extent among `queues` of one kind: the same one every
/// time, and the extents spread evenly (FNV-1a over the id, then mixed).
///
/// Each queue has its own consumer, whose invocations share an isolate:
/// one byte budget and one thread. More queues are more isolates at
/// work. Which queue a job is in changes nothing else: a job only names
/// an outbox row, and the lease on that row decides who works on it.
fn shard(extent: &str, queues: usize) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in extent.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Mixed once more (the finalizer of MurmurHash3): a change in the
    // last byte of the id alone reaches only some bits of FNV-1a.
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    (h % queues.max(1) as u64) as usize
}

/// Post jobs go to a post queue. Every other job goes to a verify queue:
/// an extent's by its id (a wake-up goes where its job would). The rest
/// (gc, sweep, eviction, recovery copy) go to their own queue when it is
/// bound, and to the first verify queue when it is not.
fn lane(job: &Job, shards: Shards) -> Lane {
    match job {
        Job::Extent {
            stage: OutboxStage::Post,
            extent,
            ..
        } => Lane::Post(shard(extent.as_str(), shards.post)),
        Job::Wake {
            stage: OutboxStage::Post,
            extent,
            ..
        } => Lane::Post(shard(extent.as_str(), shards.post)),
        Job::Extent { extent, .. } | Job::Wake { extent, .. } => {
            Lane::Verify(shard(extent.as_str(), shards.verify))
        }
        _ if shards.aux => Lane::Aux,
        _ => Lane::Verify(0),
    }
}

fn check_delay(delay_secs: u32) -> Result<()> {
    if delay_secs > MAX_QUEUE_DELAY_SECS {
        return Err(BridgeError::Queue(format!(
            "delay {delay_secs} s above {MAX_QUEUE_DELAY_SECS} s"
        )));
    }
    Ok(())
}

/// The jobs of each lane that has any, in lane order.
fn batches(jobs: &[Job], shards: Shards) -> Vec<(Lane, Vec<&Job>)> {
    shards
        .lanes()
        .map(|target| {
            let batch: Vec<&Job> = jobs.iter().filter(|j| lane(j, shards) == target).collect();
            (target, batch)
        })
        .filter(|(_, batch)| !batch.is_empty())
        .collect()
}

/// The outcome of sends that were all made: a queue that refused its
/// batch did not keep the others from getting theirs.
fn first_error<E>(sends: Vec<std::result::Result<(), E>>) -> Result<()> {
    match sends.into_iter().find_map(|sent| sent.err()) {
        Some(_) => Err(BridgeError::Queue("send failed".into())),
        None => Ok(()),
    }
}

fn send_err(_: worker::Error) -> BridgeError {
    BridgeError::Queue("send failed".into())
}

/// Longest wait for one queue to say what it holds. A queue that takes
/// longer is not known, and the dispatcher goes on.
const METRICS_TIMEOUT_MS: u64 = 5_000;

/// What one queue says it holds, from two values of its metrics: the
/// number of messages it can deliver now and the time the oldest was
/// sent, in ms.
///
/// The queues were seen to leave a message that waits out a delay out
/// of the count while they name its time. A job the dispatcher sends
/// has no delay, and the queues that take them always hold delayed
/// messages of other kinds (a wake-up waits up to twelve hours). So a
/// count of zero is an empty queue for the dispatcher, whatever time is
/// named: nothing it sent can be waiting there. With messages to
/// deliver, the time is that of the oldest message, delayed or not;
/// without a time that can be one, the queue is not known.
fn oldest_of(count: Option<f64>, oldest_ms: Option<f64>) -> Oldest {
    match (count, oldest_ms) {
        (Some(0.0), _) => Oldest::Empty,
        // Under 2^53: an exact integer.
        (Some(n), Some(ms))
            if n.is_finite() && n > 0.0 && (1.0..9_007_199_254_740_992.0).contains(&ms) =>
        {
            Oldest::At(UnixMs(ms as i64))
        }
        _ => Oldest::Unknown,
    }
}

/// The oldest message in the queues of one kind. One queue that is not
/// known makes the kind unknown: the message of a row may be in it.
fn oldest_in(queues: impl IntoIterator<Item = Oldest>) -> Oldest {
    let mut oldest = Oldest::Empty;
    for queue in queues {
        oldest = match (oldest, queue) {
            (_, Oldest::Unknown) => return Oldest::Unknown,
            (kept, Oldest::Empty) => kept,
            (Oldest::At(a), Oldest::At(b)) => Oldest::At(a.min(b)),
            (_, at) => at,
        };
    }
    oldest
}

/// The realtime metrics of one queue (`metrics()` of the binding).
/// `None` for a runtime without them, a call that failed and an answer
/// in another shape.
async fn metrics(queue: &Queue) -> Option<(Option<f64>, Option<f64>)> {
    let binding: &JsValue = queue.as_ref();
    let call = Reflect::get(binding, &JsValue::from_str("metrics")).ok()?;
    let call: Function = call.dyn_into().ok()?;
    let promise: Promise = call.call0(binding).ok()?.dyn_into().ok()?;
    let answer = JsFuture::from(promise).await.ok()?;
    let field = |name: &str| Reflect::get(&answer, &JsValue::from_str(name)).ok();
    let count = field("backlogCount").and_then(|v| v.as_f64());
    // A `Date`, whose value is the time in ms; absent for a queue that
    // holds nothing. Anything else is a time that cannot be one.
    let oldest_ms = field("oldestMessageTimestamp")
        .filter(|v| !v.is_undefined() && !v.is_null())
        .map(|v| {
            let date = || v.dyn_ref::<worker::js_sys::Date>().map(|d| d.get_time());
            v.as_f64().or_else(date).unwrap_or(f64::NAN)
        });
    Some((count, oldest_ms))
}

/// What one queue holds, or unknown after [`METRICS_TIMEOUT_MS`].
async fn oldest_of_queue(queue: &Queue) -> Oldest {
    let asked = Box::pin(metrics(queue));
    let limit = Box::pin(worker::Delay::from(Duration::from_millis(
        METRICS_TIMEOUT_MS,
    )));
    match select(asked, limit).await {
        Either::Left((Some((count, oldest_ms)), _)) => oldest_of(count, oldest_ms),
        _ => Oldest::Unknown,
    }
}

impl JobSink for QueueSink {
    /// One metrics call per post and verify queue, all at once. A kind
    /// that is not known is said in the log, by its name alone.
    async fn backlog(&self) -> Backlog {
        let (post, verify) = futures_util::future::join(
            join_all(self.post.iter().map(oldest_of_queue)),
            join_all(self.verify.iter().map(oldest_of_queue)),
        )
        .await;
        let backlog = Backlog {
            post: oldest_in(post),
            verify: oldest_in(verify),
        };
        for (kind, oldest) in [("post", backlog.post), ("verify", backlog.verify)] {
            if oldest == Oldest::Unknown {
                console_error!("dispatch: what the {kind} queues hold is not known");
            }
        }
        backlog
    }

    async fn send(&self, job: &Job, delay_secs: u32) -> Result<()> {
        check_delay(delay_secs)?;
        if self.drop_notify.take() {
            return Err(BridgeError::Queue("dev: send refused".to_string()));
        }
        let msg = MessageBuilder::new(job)
            .content_type(QueueContentType::Json)
            .delay_seconds(delay_secs)
            .build();
        self.queue(lane(job, self.shards()))
            .send(msg)
            .await
            .map_err(send_err)
    }

    /// One batch per queue, every queue tried. An `Err` may come with
    /// sent batches; the
    /// dispatcher re-drives from the outbox and a duplicate job only finds
    /// its lease taken.
    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        if jobs.len() > MAX_BATCH {
            return Err(BridgeError::Queue(format!("batch above {MAX_BATCH} jobs")));
        }
        let shards = self.shards();
        let mut sends = Vec::new();
        for (target, batch) in batches(jobs, shards) {
            sends.push(self.queue(target).send_batch(batch).await);
        }
        first_error(sends)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora_bridge::{ExtentId, GenerationId, WriteId, JOB_VERSION};

    fn extent_job(stage: OutboxStage) -> Job {
        Job::Extent {
            v: JOB_VERSION,
            extent: ExtentId::new("e_1"),
            generation: GenerationId::new("g_1"),
            stage,
        }
    }

    fn wake_job(stage: OutboxStage) -> Job {
        Job::Wake {
            v: JOB_VERSION,
            extent: ExtentId::new("e_1"),
            generation: GenerationId::new("g_1"),
            stage,
            at: velmora_bridge::UnixMs(1),
        }
    }

    const ONE: Shards = Shards {
        post: 1,
        verify: 1,
        aux: false,
    };

    /// A wake-up waits in the queue its job would be sent to.
    #[test]
    fn a_wake_up_uses_the_queue_of_its_job() {
        let many = Shards {
            post: 4,
            verify: 4,
            aux: false,
        };
        for stage in [OutboxStage::Post, OutboxStage::Verify, OutboxStage::Release] {
            assert_eq!(lane(&wake_job(stage), many), lane(&extent_job(stage), many));
        }
        assert!(matches!(
            lane(&wake_job(OutboxStage::Release), many),
            Lane::Verify(_)
        ));
    }

    /// A queue is empty, holds messages from a known time on, or is not
    /// known; a count without a time, and garbage, are not known.
    #[test]
    fn a_queue_says_what_it_holds_or_is_not_known() {
        const SENT: f64 = 1_762_992_000_123.0;
        let at = Oldest::At(UnixMs(1_762_992_000_123));
        assert_eq!(oldest_of(Some(3.0), Some(SENT)), at);
        // Nothing to deliver: empty, also when messages that wait out
        // a delay are named by their time, or the time is none.
        for oldest_ms in [None, Some(SENT), Some(0.0), Some(f64::NAN)] {
            assert_eq!(oldest_of(Some(0.0), oldest_ms), Oldest::Empty);
        }
        for (count, oldest_ms) in [
            (None, None),
            (None, Some(SENT)),
            (Some(3.0), None),
            (Some(-1.0), None),
            (Some(-1.0), Some(SENT)),
            (Some(f64::NAN), None),
            (Some(f64::NAN), Some(SENT)),
            (Some(f64::INFINITY), Some(SENT)),
            // A queue that names the epoch for its oldest message, or
            // a time that is none.
            (Some(3.0), Some(0.0)),
            (Some(3.0), Some(-1.0)),
            (Some(3.0), Some(f64::NAN)),
            (Some(3.0), Some(f64::INFINITY)),
            (Some(3.0), Some(1e300)),
        ] {
            assert_eq!(
                oldest_of(count, oldest_ms),
                Oldest::Unknown,
                "{count:?} {oldest_ms:?}"
            );
        }
    }

    /// The oldest message of a kind is the oldest of its queues, and
    /// one queue that is not known makes the kind unknown.
    #[test]
    fn a_kind_is_as_old_as_its_oldest_queue() {
        let at = |ms| Oldest::At(UnixMs(ms));
        assert_eq!(oldest_in([]), Oldest::Empty);
        assert_eq!(oldest_in([Oldest::Empty, Oldest::Empty]), Oldest::Empty);
        assert_eq!(oldest_in([Oldest::Empty, at(7), Oldest::Empty]), at(7));
        assert_eq!(oldest_in([at(9), at(7), at(8)]), at(7));
        for unknown in [
            vec![Oldest::Unknown],
            vec![at(7), Oldest::Unknown],
            vec![Oldest::Unknown, at(7)],
            vec![Oldest::Empty, Oldest::Unknown, Oldest::Empty],
        ] {
            assert_eq!(oldest_in(unknown.clone()), Oldest::Unknown, "{unknown:?}");
        }
    }

    #[test]
    fn only_post_jobs_use_the_post_queue() {
        assert_eq!(lane(&extent_job(OutboxStage::Post), ONE), Lane::Post(0));
        for stage in [OutboxStage::Verify, OutboxStage::Release] {
            assert_eq!(lane(&extent_job(stage), ONE), Lane::Verify(0));
        }
        for job in other_jobs() {
            assert_eq!(lane(&job, ONE), Lane::Verify(0));
        }
    }

    /// The jobs that name no extent.
    fn other_jobs() -> Vec<Job> {
        let mut jobs = vec![
            Job::Gc { v: JOB_VERSION },
            // The sweep of a write deletes blobs and posts nothing.
            Job::Sweep {
                v: JOB_VERSION,
                write: WriteId::new("w_0000000000000000"),
            },
            // The recovery copy shares the verify lane; a job is bounded.
            Job::RecoveryCopy {
                v: JOB_VERSION,
                pass: velmora_bridge::UnixMs(1),
                cursor: String::new(),
            },
        ];
        for remaining in [0, 4096] {
            jobs.push(Job::Evict {
                v: JOB_VERSION,
                remaining,
            });
        }
        jobs
    }

    fn job_of(extent: &str, stage: OutboxStage) -> Job {
        Job::Extent {
            v: JOB_VERSION,
            extent: ExtentId::new(extent),
            generation: GenerationId::new("g_1"),
            stage,
        }
    }

    #[test]
    fn an_extent_keeps_its_queue_and_extents_spread_over_all() {
        let shards = Shards {
            post: 4,
            verify: 2,
            aux: false,
        };
        let mut post = [0u32; 4];
        let mut verify = [0u32; 2];
        for n in 0..4000u32 {
            // The shape of a real id: a prefix and hex digits.
            let id = format!("x_{:026x}", u128::from(n) * 0x9e37_79b9_7f4a_7c15_f39c);
            let Lane::Post(p) = lane(&job_of(&id, OutboxStage::Post), shards) else {
                panic!("a post job left the post queues");
            };
            assert_eq!(lane(&job_of(&id, OutboxStage::Post), shards), Lane::Post(p));
            post[p] += 1;
            for stage in [OutboxStage::Verify, OutboxStage::Release] {
                let Lane::Verify(v) = lane(&job_of(&id, stage), shards) else {
                    panic!("a verify job left the verify queues");
                };
                assert_eq!(v, shard(&id, 2));
                if stage == OutboxStage::Verify {
                    verify[v] += 1;
                }
            }
        }
        // Even within a fifth of the mean.
        assert!(post.iter().all(|n| (800..=1200).contains(n)), "{post:?}");
        assert!(
            verify.iter().all(|n| (1600..=2400).contains(n)),
            "{verify:?}"
        );
        // Ids that differ in the last character only still spread.
        let mut tail = [0u32; 4];
        for c in "0123456789abcdef".chars() {
            tail[shard(&format!("x_00000000000000000000000{c}"), 4)] += 1;
        }
        assert!(tail.iter().filter(|n| **n > 0).count() >= 3, "{tail:?}");
    }

    #[test]
    fn jobs_without_an_extent_use_their_own_queue_when_it_is_bound() {
        let shards = Shards {
            post: 4,
            verify: 3,
            aux: true,
        };
        for job in other_jobs() {
            assert_eq!(lane(&job, shards), Lane::Aux);
        }
        // An extent's jobs stay where they were.
        assert_eq!(
            lane(&extent_job(OutboxStage::Post), shards),
            lane(
                &extent_job(OutboxStage::Post),
                Shards {
                    aux: false,
                    ..shards
                }
            )
        );
        assert!(matches!(
            lane(&extent_job(OutboxStage::Verify), shards),
            Lane::Verify(_)
        ));
        // Their batch is sent apart from the verify queues' batches.
        let mut jobs = other_jobs();
        jobs.push(extent_job(OutboxStage::Verify));
        let sent = batches(&jobs, shards);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].0, Lane::Aux);
        assert_eq!(sent[1].1.len(), jobs.len() - 1);
        assert_eq!(shards.lanes().count(), 8);
    }

    #[test]
    fn jobs_without_an_extent_use_the_first_verify_queue() {
        let shards = Shards {
            post: 4,
            verify: 3,
            aux: false,
        };
        for job in other_jobs() {
            assert_eq!(lane(&job, shards), Lane::Verify(0));
        }
    }

    #[test]
    fn every_lane_is_listed_once_and_one_queue_takes_everything() {
        let shards = Shards {
            post: 3,
            verify: 2,
            aux: false,
        };
        let lanes: Vec<Lane> = shards.lanes().collect();
        assert_eq!(
            lanes,
            [
                Lane::Post(0),
                Lane::Post(1),
                Lane::Post(2),
                Lane::Verify(0),
                Lane::Verify(1)
            ]
        );
        for n in 0..64 {
            assert_eq!(shard(&format!("x_{n:x}"), 1), 0);
            // Never out of range, and no division by zero.
            assert_eq!(shard(&format!("x_{n:x}"), 0), 0);
            assert!(shard(&format!("x_{n:x}"), MAX_QUEUES) < MAX_QUEUES);
        }
    }

    #[test]
    fn bound_queues_are_counted_and_a_gap_is_refused() {
        let with = |names: &'static [&'static str]| {
            bound_queues("POST_Q", move |name| names.contains(&name))
        };
        assert_eq!(with(&["POST_Q"]), Ok(1));
        assert_eq!(with(&["POST_Q", "POST_Q2", "POST_Q3", "VERIFY_Q"]), Ok(3));
        assert_eq!(with(&["VERIFY_Q"]), Err("missing binding POST_Q".into()));
        assert_eq!(
            with(&["POST_Q", "POST_Q3", "POST_Q4"]),
            Err("binding POST_Q3 without POST_Q2".into())
        );
        assert_eq!(
            with(&["POST_Q2"]),
            Err("binding POST_Q2 without POST_Q".into())
        );
        // Names above the most this build reads are not looked at.
        assert_eq!(with(&["POST_Q", "POST_Q10"]), Ok(1));
    }

    #[test]
    fn post_jobs_and_wakeups_reach_all_eight_bound_shards() {
        let names = [
            "POST_Q", "POST_Q2", "POST_Q3", "POST_Q4", "POST_Q5", "POST_Q6", "POST_Q7", "POST_Q8",
        ];
        let post = bound_queues("POST_Q", |name| names.contains(&name)).unwrap();
        assert_eq!(post, 8);
        let shards = Shards {
            post,
            verify: 4,
            aux: true,
        };
        let mut visited = [false; 8];
        for n in 0..128 {
            let extent = ExtentId::new(format!("e_{n:x}"));
            let generation = GenerationId::new("g_1");
            let job = Job::Extent {
                v: JOB_VERSION,
                extent: extent.clone(),
                generation: generation.clone(),
                stage: OutboxStage::Post,
            };
            let wake = Job::Wake {
                v: JOB_VERSION,
                extent,
                generation,
                stage: OutboxStage::Post,
                at: velmora_bridge::UnixMs(1),
            };
            let target = lane(&job, shards);
            assert_eq!(lane(&wake, shards), target);
            let Lane::Post(shard) = target else {
                panic!("post job routed to {target:?}");
            };
            visited[shard] = true;
        }
        assert_eq!(visited, [true; 8]);
    }

    #[test]
    fn a_batch_is_split_by_queue_and_no_job_is_left_out() {
        let shards = Shards {
            post: 3,
            verify: 2,
            aux: false,
        };
        let mut jobs: Vec<Job> = (0..40u8)
            .map(|n| Job::Extent {
                v: JOB_VERSION,
                extent: ExtentId::new(format!("e_{n}")),
                generation: GenerationId::new("g_1"),
                stage: if n % 2 == 0 {
                    OutboxStage::Post
                } else {
                    OutboxStage::Verify
                },
            })
            .collect();
        jobs.push(Job::Gc { v: JOB_VERSION });
        let split = batches(&jobs, shards);
        assert_eq!(
            split.iter().map(|(_, b)| b.len()).sum::<usize>(),
            jobs.len()
        );
        for (target, batch) in &split {
            assert!(!batch.is_empty());
            assert!(batch.iter().all(|j| lane(j, shards) == *target));
        }
        let lanes: Vec<Lane> = split.iter().map(|(l, _)| *l).collect();
        let mut sorted = lanes.clone();
        sorted.dedup();
        assert_eq!(lanes, sorted, "one batch per queue");
        assert!(batches(&[], shards).is_empty());
    }

    #[test]
    fn sends_report_the_first_failure_after_all_were_made() {
        assert!(first_error::<&str>(vec![]).is_ok());
        assert!(first_error::<&str>(vec![Ok(()), Ok(())]).is_ok());
        let failed = first_error(vec![Ok(()), Err("second queue"), Ok(())]);
        assert!(matches!(failed, Err(BridgeError::Queue(_))));
    }

    #[test]
    fn binding_names_count_from_two() {
        assert_eq!(binding_name("POST_Q", 0), "POST_Q");
        assert_eq!(binding_name("POST_Q", 1), "POST_Q2");
        assert_eq!(binding_name("VERIFY_Q", 0), "VERIFY_Q");
        assert_eq!(binding_name("VERIFY_Q", 7), "VERIFY_Q8");
    }

    #[test]
    fn drop_counter_drops_exactly_n_then_passes() {
        let d = DropNotify::from_var(true, Some("2")).unwrap();
        assert_eq!(d.remaining(), 2);
        assert!(d.take());
        assert!(d.take());
        assert!(!d.take(), "after n drops, sends go through");
        assert!(!d.take());
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn drop_counter_in_dev_defaults_to_zero_and_refuses_garbage() {
        for raw in [None, Some(""), Some(" "), Some("0")] {
            let d = DropNotify::from_var(true, raw).unwrap();
            assert!(!d.take(), "{raw:?}");
        }
        assert!(DropNotify::from_var(true, Some(" 1 ")).unwrap().take());
        for raw in ["-1", "x", "1.5", "4294967296"] {
            // The refusal names the variable, never the value.
            let err = DropNotify::from_var(true, Some(raw)).unwrap_err();
            assert_eq!(err, "invalid DEV_DROP_NOTIFY_N");
        }
    }

    #[test]
    fn drop_counter_is_ignored_outside_dev() {
        // Prod never drops, whatever the variable says, and never refuses.
        for raw in [None, Some("1"), Some("1000"), Some("garbage")] {
            let d = DropNotify::from_var(false, raw).unwrap();
            assert_eq!(d.remaining(), 0, "{raw:?}");
            assert!(!d.take(), "{raw:?}");
        }
    }

    #[test]
    fn delay_is_capped_at_twelve_hours() {
        assert!(check_delay(0).is_ok());
        assert!(check_delay(MAX_QUEUE_DELAY_SECS).is_ok());
        assert!(matches!(
            check_delay(MAX_QUEUE_DELAY_SECS + 1),
            Err(BridgeError::Queue(_))
        ));
    }
}
