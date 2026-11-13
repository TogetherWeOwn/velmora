//! `impl JobSink` over Queues. A `Job` is sent as a JSON message. Post jobs
//! go to `POST_Q`; verify, release and gc jobs go to `VERIFY_Q`.

use velmora_bridge::{BridgeError, Job, JobSink, OutboxStage, Result, MAX_QUEUE_DELAY_SECS};
use worker::{MessageBuilder, Queue, QueueContentType};

/// Queues' `sendBatch` limit.
const MAX_BATCH: usize = 100;

pub struct QueueSink {
    post: Queue,
    verify: Queue,
}

impl QueueSink {
    pub fn new(post: Queue, verify: Queue) -> Self {
        QueueSink { post, verify }
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
