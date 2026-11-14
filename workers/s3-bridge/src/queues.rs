//! `impl JobSink` over Queues. A `Job` is sent as a JSON message. Post jobs
//! go to `POST_Q`; verify, release and gc jobs go to `VERIFY_Q`.
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

pub struct QueueSink {
    post: Queue,
    verify: Queue,
    drop_notify: DropNotify,
}

impl QueueSink {
    pub fn new(post: Queue, verify: Queue, drop_notify: DropNotify) -> Self {
        QueueSink {
            post,
            verify,
            drop_notify,
        }
    }

    fn queue(&self, lane: Lane) -> &Queue {
        match lane {
            Lane::Post => &self.post,
            Lane::Verify => &self.verify,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Post,
    Verify,
}

fn lane(job: &Job) -> Lane {
    match job {
        Job::Extent {
            stage: OutboxStage::Post,
            ..
        } => Lane::Post,
        _ => Lane::Verify,
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
        self.queue(lane(job)).send(msg).await.map_err(send_err)
    }

    /// One batch per queue. An `Err` may follow a sent `POST_Q` batch; the
    /// dispatcher re-drives from the outbox and a duplicate job only finds
    /// its lease taken.
    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        if jobs.len() > MAX_BATCH {
            return Err(BridgeError::Queue(format!("batch above {MAX_BATCH} jobs")));
        }
        for target in [Lane::Post, Lane::Verify] {
            let batch: Vec<&Job> = jobs.iter().filter(|j| lane(j) == target).collect();
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
    use velmora_bridge::{ExtentId, GenerationId, JOB_VERSION};

    fn extent_job(stage: OutboxStage) -> Job {
        Job::Extent {
            v: JOB_VERSION,
            extent: ExtentId::new("e_1"),
            generation: GenerationId::new("g_1"),
            stage,
        }
    }

    #[test]
    fn only_post_jobs_use_the_post_queue() {
        assert_eq!(lane(&extent_job(OutboxStage::Post)), Lane::Post);
        for stage in [OutboxStage::Verify, OutboxStage::Release] {
            assert_eq!(lane(&extent_job(stage)), Lane::Verify);
        }
        assert_eq!(lane(&Job::Gc { v: JOB_VERSION }), Lane::Verify);
        for remaining in [0, 4096] {
            let evict = Job::Evict {
                v: JOB_VERSION,
                remaining,
            };
            assert_eq!(lane(&evict), Lane::Verify);
        }
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
