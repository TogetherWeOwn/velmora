//! Runs a queue attempt in the job table and writes its optional observation.

use std::future::Future;

use velmora_bridge::{metrics::job_point, trace::observe_job, Clock, JobOutcome};

use crate::{jobs, metrics};

/// The observation lives in the same future as the job. A duplicate or
/// abandoned attempt cannot write another job's point.
pub(crate) async fn run_in_table(
    clock: impl Clock + 'static,
    post: bool,
    observation: Option<(String, u32)>,
    run: impl Future<Output = JobOutcome> + 'static,
) -> JobOutcome {
    let now = clock.now();
    let attempt = async move {
        let Some((queue, weight)) = observation else {
            return run.await;
        };
        let (outcome, trace) = observe_job(&clock, run).await;
        if let Some(point) = job_point(&trace, &queue, weight) {
            metrics::write(&point);
        }
        outcome
    };
    jobs::run(now, post, attempt)
        .await
        .unwrap_or(JobOutcome::Retry {
            delay_secs: velmora_bridge::jobs::INFRA_RETRY_SECS,
        })
}
