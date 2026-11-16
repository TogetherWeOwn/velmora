//! Worker entry: `fetch` -> headers-only precheck -> `Bridge::handle` (S3
//! and `/_admin`), `queue` -> `Bridge::run_job`, `scheduled` ->
//! the start of a pass of the recovery copy when one is due, then
//! `Bridge::dispatch` (the bounded dispatcher). A recovery-copy job is run
//! here, with the recovery store, not by `Bridge::run_job`.
//!
//! The `Bridge` is built once per isolate from validated configuration.
//! A refused configuration is a `500` with a class-only log line (fail
//! closed). Logs carry method, bucket, key hash, status and request ID;
//! never credentials, presigned queries, bodies or provider text.

mod d1;
mod e2;
mod env;
mod http;
mod nntp;
mod queues;
mod r2;

use std::cell::RefCell;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};

use velmora_bridge::copy::Copier;
use velmora_bridge::ingress;
use velmora_bridge::keepalive;
use velmora_bridge::service::classify;
use velmora_bridge::{
    BridgeError, Job, JobOutcome, OutboxStage, RespBody, S3Response, UnixMs, JOB_VERSION,
};
use worker::{
    console_error, console_log, event, Context, Env, MessageBatch, MessageExt,
    QueueRetryOptionsBuilder, Request, Response, Result, ScheduleContext, ScheduledEvent,
};

/// Error class for logs: the variant only, never its text.
fn error_class(e: &BridgeError) -> &'static str {
    match e {
        BridgeError::GuardFailed => "guard",
        BridgeError::NotImplemented(_) => "not-implemented",
        BridgeError::Sql(_) => "sql",
        BridgeError::Blob(_) => "blob",
        BridgeError::Nntp(_) => "nntp",
        BridgeError::Queue(_) => "queue",
        BridgeError::Crypto(_) => "crypto",
        BridgeError::Config(_) => "config",
        BridgeError::Invalid(_) => "invalid",
        _ => "other",
    }
}

/// One-shot hand-off of the handler's response to the fetch future.
#[derive(Default)]
struct Slot {
    resp: Option<S3Response>,
    waker: Option<Waker>,
}

/// Runs `Bridge::handle` under `waitUntil`, so a client disconnect does not
/// strand it mid-await: the runtime keeps driving it, a withheld body then
/// fails its read, and every budget `Charge` it holds is dropped. The work
/// of a deferred body (DeleteObjects) runs there too, after the response
/// is handed over, so dropping the body does not stop it. Once the client
/// is gone the runtime gives `waitUntil` at most 30 s more: keys not done
/// by then stay as they are, and a re-send of the request finishes them.
async fn handle_detached(
    ctx: &Context,
    bridge: Rc<env::WorkerBridge>,
    req: velmora_bridge::S3Request,
) -> S3Response {
    let slot = Rc::new(RefCell::new(Slot::default()));
    let tx = Rc::clone(&slot);
    ctx.wait_until(async move {
        let mut resp = bridge.handle(req).await;
        let work = match &mut resp.body {
            RespBody::Deferred(d) => d.take_work(),
            _ => None,
        };
        {
            let mut s = tx.borrow_mut();
            s.resp = Some(resp);
            if let Some(w) = s.waker.take() {
                w.wake();
            }
        }
        if let Some(work) = work {
            work.await;
        }
    });
    poll_fn(|cx| {
        let mut s = slot.borrow_mut();
        match s.resp.take() {
            Some(resp) => Poll::Ready(resp),
            None => {
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    })
    .await
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let method = req.inner().method();
    let request_id = req
        .headers()
        .get("cf-ray")
        .ok()
        .flatten()
        .unwrap_or_default();
    let bridge = match env::bridge(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            return Ok(http::internal_error());
        }
    };
    let incoming = match http::to_s3_request(req) {
        Ok(incoming) => incoming,
        Err(e) => {
            console_log!(
                "{}",
                ingress::log_line(&method, "-", e.status(), &request_id)
            );
            return Ok(http::to_response(e.response()));
        }
    };
    let target = incoming.req.raw_target.clone();
    let route = classify(&incoming.req.method, &target);
    let resp = match ingress::precheck(&route, &incoming.req, &bridge.cfg, incoming.https) {
        Err(e) => e.response(),
        Ok(()) => {
            let resp = handle_detached(&ctx, Rc::clone(&bridge), incoming.req).await;
            // A deferred document: buffered when it is done soon, else
            // streamed with keepalive whitespace.
            keepalive::settle_response(resp, env::sleeper()).await
        }
    };
    console_log!(
        "{}",
        ingress::log_line(&method, &target, resp.status, &request_id)
    );
    if let Some(line) = env::memory_line(&bridge) {
        console_log!("{line}");
    }
    Ok(http::to_response(resp))
}

#[event(queue)]
async fn queue(batch: MessageBatch<serde_json::Value>, env: Env, _ctx: Context) -> Result<()> {
    let bridge = match env::bridge(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            // Every message is retried by the platform.
            return Err(worker::Error::RustError("config refused".into()));
        }
    };
    for msg in batch.messages()? {
        let Ok(job) = serde_json::from_value::<Job>(msg.body().clone()) else {
            // A job only names an outbox row; the dispatcher re-drives it.
            console_error!("malformed job message dropped");
            msg.ack();
            continue;
        };
        let outcome = match &job {
            // Never through `run_job`, which reads the catalogue. A job
            // of another version is dropped: the next pass does the work.
            Job::RecoveryCopy { v, pass, cursor } => {
                if *v == JOB_VERSION {
                    recovery_copy(&env, &bridge, *pass, cursor).await
                } else {
                    console_error!("recovery copy: a job of another version was dropped");
                    JobOutcome::Ack
                }
            }
            _ => bridge.run_job(&job).await,
        };
        log_post_trace(&job, &outcome);
        match outcome {
            JobOutcome::Ack => msg.ack(),
            JobOutcome::Retry { delay_secs } => msg.retry_with_options(
                &QueueRetryOptionsBuilder::new()
                    .with_delay_seconds(delay_secs)
                    .build(),
            ),
        }
    }
    if let Some(line) = env::memory_line(&bridge) {
        console_log!("{line}");
    }
    Ok(())
}

fn copier<'a>(
    bridge: &'a env::WorkerBridge,
    remote: &'a velmora_bridge::remote::S3Remote<e2::FetchHttp>,
) -> Copier<'a, r2::R2Blobs, velmora_bridge::KekRing, env::WorkerClock, e2::FetchHttp> {
    Copier {
        safety: &bridge.safety,
        kek: &bridge.kek,
        clock: &bridge.clock,
        remote,
        maintenance: bridge.cfg.maintenance,
    }
}

/// One job of a pass of the recovery copy. Logs counts only. A job
/// that is retried does its work again and logs it again with
/// `retry=true`: a sum over a pass takes the other lines only.
async fn recovery_copy(
    env: &Env,
    bridge: &env::WorkerBridge,
    pass: UnixMs,
    cursor: &str,
) -> JobOutcome {
    let remote = match env::recovery_store(env) {
        Ok(Some(remote)) => remote,
        // Switched off since the job was sent.
        Ok(None) => return JobOutcome::Ack,
        Err(class) => {
            console_error!("recovery copy: config refused: {class}");
            return JobOutcome::Ack;
        }
    };
    let (outcome, counts, why) = copier(bridge, &remote)
        .run_job(&bridge.jobs, pass, cursor)
        .await;
    let retry = matches!(outcome, JobOutcome::Retry { .. });
    // The reason is a class and a status at most. It is logged whether
    // the job is retried or not: past the retry window a job that did
    // nothing is acknowledged, and must not end without a line.
    if let Some(why) = why {
        console_error!(
            "recovery copy: pass={} retry={retry} stopped: {why:?}",
            pass.0
        );
    }
    match counts {
        Some(c) if c.clean() && c.source_unreadable == 0 && !retry => console_log!(
            "recovery copy: pass={} records={} bytes={} same={} copied={} young={} pending={} extra={} foreign={}",
            pass.0,
            c.records,
            c.bytes,
            c.same,
            c.copied,
            c.young,
            c.pending,
            c.extra,
            c.foreign
        ),
        Some(c) => console_error!(
            "recovery copy: pass={} retry={retry} records={} copied={} failed={} refused={} source_unreadable={} pending={} extra={} foreign={}",
            pass.0,
            c.records,
            c.copied,
            c.failed,
            c.refused,
            c.source_unreadable,
            c.pending,
            c.extra,
            c.foreign
        ),
        None => {}
    }
    outcome
}

/// One line per post job: its outcome and phase timings, milliseconds
/// and counts only (see `velmora_bridge::trace`).
fn log_post_trace(job: &Job, outcome: &JobOutcome) {
    let Job::Extent {
        extent,
        stage: OutboxStage::Post,
        ..
    } = job
    else {
        return;
    };
    if let Some(trace) = velmora_bridge::trace::take(extent) {
        let outcome = match outcome {
            JobOutcome::Ack => "ack".to_string(),
            JobOutcome::Retry { delay_secs } => format!("retry {delay_secs}s"),
        };
        console_log!("post job: outcome={outcome} {trace}");
    }
}

#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let bridge = match env::bridge(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            return;
        }
    };
    // Before the dispatcher and apart from it: the copy reads no
    // catalogue, so a dispatcher that fails or does not return cannot
    // keep a pass from starting.
    match env::recovery_store(&env) {
        Ok(None) => {}
        Ok(Some(remote)) => {
            if copier(&bridge, &remote)
                .start_pass(&bridge.jobs, UnixMs(event.schedule() as i64))
                .await
                .is_err()
            {
                console_error!("recovery copy: the pass was not started");
            }
        }
        Err(class) => console_error!("recovery copy: config refused: {class}"),
    }
    match bridge.dispatch().await {
        Ok(report) => {
            if report.rolled_back {
                console_error!(
                    "dispatch: the catalogue is behind its rollback stamp; writes are refused until a replay has ended"
                );
            }
            if report.stamp_failed {
                console_error!("dispatch: the rollback stamp was not raised");
            }
            if report.redrive_failed {
                console_error!("dispatch: re-drive failed");
            }
            if report.evict_failed {
                console_error!("dispatch: hot-tier check failed");
            }
            if report.release_paused {
                if let Some(warning) = bridge.cfg.release_paused() {
                    console_error!("dispatch: {warning}");
                }
            }
            if report.sweep_failed {
                console_error!("dispatch: the sweep of unpublished writes was not sent");
            }
            if report.pack_failed {
                console_error!("dispatch: packing article plans failed");
            }
        }
        Err(e) => console_error!("dispatch failed: {}", error_class(&e)),
    }
}
