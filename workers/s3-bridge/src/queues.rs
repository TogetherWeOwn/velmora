//! `impl JobSink` over Queues. A `Job` is sent as a JSON message. Post jobs
//! go to a post queue (`POST_Q`, and `POST_Q2`, `POST_Q3`, ... where they
//! are bound); verify, release, gc and recovery-copy jobs go to a verify
//! queue (`VERIFY_Q`, `VERIFY_Q2`, ...). An extent's job always goes to
//! the same queue of its kind ([`shard`]).
//!
//! Dev only: `DEV_DROP_NOTIFY_N` makes the first `n` `send` calls of the
//! isolate vanish while reporting success (a lost queue notification), so
//! the local acceptance run can prove that the cron dispatcher re-drives
//! the outbox. `send_many` is never dropped; the dispatcher must keep
//! re-enqueueing extents through it so the re-drive itself is never lost.
//! A restarted isolate re-arms the counter. Outside `ENVIRONMENT=dev` the
//! variable is ignored.

use std::sync::atomic::{AtomicU32, Ordering};

use velmora_bridge::{BridgeError, Job, JobSink, OutboxStage, Result, MAX_QUEUE_DELAY_SECS};
use worker::{MessageBuilder, Queue, QueueContentType};

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

pub struct QueueSink {
    /// Never empty.
    post: Vec<Queue>,
    /// Never empty.
    verify: Vec<Queue>,
    drop_notify: DropNotify,
}

impl QueueSink {
    /// `post` and `verify` hold the queues of each kind in binding order,
    /// at least one each: an empty list is refused, with the name of the
    /// first binding of the kind.
    pub fn new(
        post: Vec<Queue>,
        verify: Vec<Queue>,
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
            drop_notify,
        })
    }

    fn shards(&self) -> Shards {
        Shards {
            post: self.post.len(),
            verify: self.verify.len(),
        }
    }

    fn queue(&self, lane: Lane) -> &Queue {
        match lane {
            Lane::Post(shard) => &self.post[shard],
            Lane::Verify(shard) => &self.verify[shard],
        }
    }
}

/// The queue a job is sent to: the kind and the queue's index in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Post(usize),
    Verify(usize),
}

/// How many queues of each kind are bound, at least one each.
#[derive(Clone, Copy, Debug)]
struct Shards {
    post: usize,
    verify: usize,
}

impl Shards {
    /// Every lane, post queues first.
    fn lanes(self) -> impl Iterator<Item = Lane> {
        (0..self.post)
            .map(Lane::Post)
            .chain((0..self.verify).map(Lane::Verify))
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
/// an extent's by its id, the rest (gc, sweep, eviction, recovery copy)
/// to the first.
fn lane(job: &Job, shards: Shards) -> Lane {
    match job {
        Job::Extent {
            stage: OutboxStage::Post,
            extent,
            ..
        } => Lane::Post(shard(extent.as_str(), shards.post)),
        Job::Extent { extent, .. } => Lane::Verify(shard(extent.as_str(), shards.verify)),
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

fn send_err(_: worker::Error) -> BridgeError {
    BridgeError::Queue("send failed".into())
}

impl JobSink for QueueSink {
    async fn send(&self, job: &Job, delay_secs: u32) -> Result<()> {
        check_delay(delay_secs)?;
        if self.drop_notify.take() {
            return Ok(());
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

    /// One batch per queue. An `Err` may follow a sent batch; the
    /// dispatcher re-drives from the outbox and a duplicate job only finds
    /// its lease taken.
    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        if jobs.len() > MAX_BATCH {
            return Err(BridgeError::Queue(format!("batch above {MAX_BATCH} jobs")));
        }
        let shards = self.shards();
        for target in shards.lanes() {
            let batch: Vec<&Job> = jobs.iter().filter(|j| lane(j, shards) == target).collect();
            if !batch.is_empty() {
                self.queue(target)
                    .send_batch(batch)
                    .await
                    .map_err(send_err)?;
            }
        }
        Ok(())
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

    const ONE: Shards = Shards { post: 1, verify: 1 };

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
        let shards = Shards { post: 4, verify: 2 };
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
    fn jobs_without_an_extent_use_the_first_verify_queue() {
        let shards = Shards { post: 4, verify: 3 };
        for job in other_jobs() {
            assert_eq!(lane(&job, shards), Lane::Verify(0));
        }
    }

    #[test]
    fn every_lane_is_listed_once_and_one_queue_takes_everything() {
        let shards = Shards { post: 3, verify: 2 };
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
