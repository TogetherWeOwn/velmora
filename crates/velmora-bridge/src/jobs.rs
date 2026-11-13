//! Queue jobs (`run_job`: post, verify, release, gc) and the cron
//! dispatcher (jobs/admin lane, DESIGN §A.7).
//!
//! Walking-skeleton stub. `run_job` asks for a retry so no message is
//! lost before the real stages land; `dispatch` reports `NotImplemented`.

use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{BridgeError, DispatchReport, Job, JobOutcome, Result};

/// Retry delay the stub asks for.
const STUB_RETRY_SECS: u32 = 300;

impl<C, B, N, J, K, T> Bridge<C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    /// Runs one queue job to an outcome. Never panics on a stale job.
    pub async fn run_job(&self, _job: &Job) -> JobOutcome {
        JobOutcome::Retry {
            delay_secs: STUB_RETRY_SECS,
        }
    }

    /// The whole cron handler: bounded D1 reads and queue sends only.
    pub async fn dispatch(&self) -> Result<DispatchReport> {
        Err(BridgeError::NotImplemented("jobs::dispatch"))
    }
}
