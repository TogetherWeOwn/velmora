//! Which queue a job is sent to (ADR-TENANCY §2.4 rule 4, AM-49).
//!
//! Tenant 0's dispatcher (the Worker's `QueueSink`) and a unit's alarm
//! route every message through this one function, fallback included: a
//! job that names no extent goes to the queue bound as [`AUX_Q`], or to
//! the first verify queue where `AUX_Q` is not bound. Moved unchanged
//! from `workers/s3-bridge/src/queues.rs`, so that the unit's crate,
//! which the Worker depends on, reaches it without a copy.

use crate::types::{Job, OutboxStage};

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

/// The binding of the queue for jobs that name no extent: gc, sweep,
/// eviction and recovery copy. Optional: without it they go to the first
/// verify queue, as before. There they wait in front of that queue's
/// verify and release jobs, which then fall hours behind the other
/// verify queues' whenever many recovery-copy jobs are sent.
pub const AUX_Q: &str = "AUX_Q";

/// The queue a job is sent to: the kind and the queue's index in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Post(usize),
    Verify(usize),
    /// The queue of the jobs that name no extent.
    Aux,
}

/// How many queues of each kind are bound, at least one each.
#[derive(Clone, Copy, Debug)]
pub struct Shards {
    pub post: usize,
    pub verify: usize,
    /// The queue for jobs that name no extent is bound.
    pub aux: bool,
}

impl Shards {
    /// Every lane, post queues first.
    pub fn lanes(self) -> impl Iterator<Item = Lane> {
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
pub fn shard(extent: &str, queues: usize) -> usize {
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
pub fn lane(job: &Job, shards: Shards) -> Lane {
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

/// The jobs of each lane that has any, in lane order.
pub fn batches(jobs: &[Job], shards: Shards) -> Vec<(Lane, Vec<&Job>)> {
    shards
        .lanes()
        .map(|target| {
            let batch: Vec<&Job> = jobs.iter().filter(|j| lane(j, shards) == target).collect();
            (target, batch)
        })
        .filter(|(_, batch)| !batch.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExtentId, GenerationId, WriteId, JOB_VERSION};

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
            at: crate::UnixMs(1),
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
                pass: crate::UnixMs(1),
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
    fn binding_names_count_from_two() {
        assert_eq!(binding_name("POST_Q", 0), "POST_Q");
        assert_eq!(binding_name("POST_Q", 1), "POST_Q2");
        assert_eq!(binding_name("VERIFY_Q", 0), "VERIFY_Q");
        assert_eq!(binding_name("VERIFY_Q", 7), "VERIFY_Q8");
    }
    /// A unit's outbox row and tenant 0's of the same extent go to the
    /// same queue (AM-49): the unit's message, in format 2 with its
    /// tenant and unit, is read back to the job tenant 0's dispatcher
    /// would send, and that job's lane is the lane of the message.
    #[test]
    fn a_units_job_goes_to_the_queue_of_the_flat_job_of_its_extent() {
        use crate::jobmsg::{admit_for, Admission, JobFormat, JobTenant, Units};
        let unit = JobTenant::of_unit("t_00000000000000a7", 3, 9, 4).unwrap();
        for shards in [
            ONE,
            Shards {
                post: 4,
                verify: 3,
                aux: true,
            },
            Shards {
                post: 8,
                verify: 8,
                aux: false,
            },
        ] {
            let mut jobs = other_jobs();
            for n in 0..64u32 {
                let id = format!("x_{:026x}", u128::from(n) * 0x9e37_79b9_7f4a_7c15_f39c);
                for stage in [OutboxStage::Post, OutboxStage::Verify, OutboxStage::Release] {
                    jobs.push(job_of(&id, stage));
                }
            }
            for job in &jobs {
                let text = serde_json::to_value(JobFormat::Tenant.message(job, &unit)).unwrap();
                let Admission::Run { job: read, .. } = admit_for(&text, Units::Bound) else {
                    panic!("{text}");
                };
                assert_eq!(&read, job);
                assert_eq!(lane(&read, shards), lane(job, shards), "{text}");
            }
        }
    }
}
