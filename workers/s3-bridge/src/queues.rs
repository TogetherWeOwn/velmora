//! `impl JobSink` over Queues (adapter lane). Post jobs go to `POST_Q`;
//! verify, release and gc jobs to `VERIFY_Q`.
//!
//! Walking-skeleton stub: every call answers `NotImplemented`.

use velmora_bridge::{BridgeError, Job, JobSink, Result};
use worker::Queue;

pub struct QueueSink {
    #[allow(dead_code)] // read once the adapter lands
    post: Queue,
    #[allow(dead_code)] // read once the adapter lands
    verify: Queue,
}

impl QueueSink {
    pub fn new(post: Queue, verify: Queue) -> Self {
        QueueSink { post, verify }
    }
}

impl JobSink for QueueSink {
    async fn send(&self, _job: &Job, _delay_secs: u32) -> Result<()> {
        Err(BridgeError::NotImplemented("queues::send"))
    }

    async fn send_many(&self, _jobs: &[Job]) -> Result<()> {
        Err(BridgeError::NotImplemented("queues::send_many"))
    }
}
