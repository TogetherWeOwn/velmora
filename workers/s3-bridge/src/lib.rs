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
mod fanout;
mod http;
mod jobs;
mod metrics;
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
    // What a GET read from Usenet, one line per run of cold extents.
    velmora_bridge::trace::log_cold_reads(|line| {
        console_log!("cold read: {line}");
        // A cache miss, counted as it happens: see `velmora_bridge::metrics`.
        metrics::write(&velmora_bridge::metrics::cold_read_point());
    });
    metrics::bind(&env);
    if let Ok(bridge) = env::bridge(&env) {
        log_budget(&bridge);
    }
    let started = worker::Date::now().as_millis();
    let method = req.inner().method();
    let colo = req.cf().map(|cf| cf.colo()).unwrap_or_default();
    let length = |headers: &worker::Headers| {
        headers
            .get("content-length")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let bytes_in = length(req.headers());
    // A sub-request of a large GET is this Worker calling itself: the
    // GET it belongs to is the request that is counted.
    let internal = req
        .headers()
        .has(velmora_bridge::fanout::TOKEN_HEADER)
        .unwrap_or(false);
    // Every answer for an admin route carries `no-store`, the early
    // refusals below too.
    let admin = ingress::is_admin_url(&req.inner().url());
    // The ray ID: what the request is logged under, and what every
    // answer carries as `x-amz-request-id` (`S3Response::with_request_id`).
    // A request that did not come through the edge (a service binding)
    // has no ray ID and is given an ID of its own.
    let request_id = req
        .headers()
        .get("cf-ray")
        .ok()
        .flatten()
        .filter(|ray| !ray.is_empty())
        .unwrap_or_else(|| {
            use worker::js_sys::{Date, Math};
            velmora_bridge::local_request_id(
                Date::now() as u64,
                (Math::random() * 4_294_967_296.0) as u32,
            )
        });
    let early = |resp: S3Response| {
        let mut resp = resp;
        if admin {
            ingress::no_store(&mut resp);
        }
        http::to_response(resp.with_request_id(&request_id))
    };
    // The point of this request, if it gets one. A sub-request of a
    // large GET gets none unless it failed: a 5xx is never left out,
    // whatever headers the request carried.
    let count = |status: u16, sample: u32, bytes_out: u64| {
        if internal && status < 500 {
            return;
        }
        // A request without a ray id (one through a service binding)
        // is drawn by its place in this isolate's count instead.
        let drawn = if request_id.is_empty() {
            // The start time too: every isolate counts from one.
            format!("{started}n{}", metrics::next())
        } else {
            request_id.clone()
        };
        if let Some(weight) = velmora_bridge::metrics::weight(status, sample, &drawn) {
            let seen = velmora_bridge::metrics::Request {
                method: &method,
                admin,
                sub: internal,
                status,
                latency_ms: worker::Date::now().as_millis().saturating_sub(started),
                bytes_in,
                bytes_out,
                colo: &colo,
            };
            metrics::write(&velmora_bridge::metrics::request_point(&seen, weight));
        }
    };
    let bridge = match env::bridge(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            let resp = ingress::IngressError::Internal.response();
            count(resp.status, 1, 0);
            return Ok(early(resp));
        }
    };
    let incoming = match http::to_s3_request(req) {
        Ok(incoming) => incoming,
        Err(e) => {
            console_log!(
                "{}",
                ingress::log_line(&method, "-", e.status(), &request_id)
            );
            count(e.status(), bridge.cfg.metrics_sample, 0);
            return Ok(early(e.response()));
        }
    };
    let target = incoming.req.raw_target.clone();
    let resp = ingress::front(incoming.req, &bridge.cfg, incoming.https, |req| async {
        let resp = handle_detached(&ctx, Rc::clone(&bridge), req).await;
        // A deferred document: buffered when it is done soon, else
        // streamed with keepalive whitespace.
        keepalive::settle_response(resp, env::sleeper()).await
    })
    .await
    .with_request_id(&request_id);
    // A body in sub-ranges: the first one is opened before the status is
    // known to the client.
    let (status, out) = fanout::respond(&env, &ctx, resp, &request_id).await;
    console_log!(
        "{}",
        ingress::log_line(&method, &target, status, &request_id)
    );
    if let Some(line) = env::memory_line(&bridge) {
        console_log!("{line}");
    }
    count(status, bridge.cfg.metrics_sample, length(out.headers()));
    Ok(out)
}

#[event(queue)]
async fn queue(batch: MessageBatch<serde_json::Value>, env: Env, _ctx: Context) -> Result<()> {
    // What an operator has to see of a job: a failed full read of a
    // sampled extent, for one.
    velmora_bridge::trace::log_alerts(|line| console_error!("alert: {line}"));
    let bridge = match env::bridge(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            // Every message is retried by the platform.
            return Err(worker::Error::RustError("config refused".into()));
        }
    };
    log_budget(&bridge);
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
            _ => run_in_table(&bridge, &job).await,
        };
        log_post_trace(&job, &outcome);
        plan_hint(&env, &bridge, &job, &outcome).await;
        match outcome {
            JobOutcome::Ack => msg.ack(),
            JobOutcome::Retry { delay_secs } => msg.retry_with_options(
                &QueueRetryOptionsBuilder::new()
                    .with_delay_seconds(delay_secs)
                    .build(),
            ),
        }
    }
    log_budget(&bridge);
    if let Some(line) = env::memory_line(&bridge) {
        console_log!("{line}");
    }
    Ok(())
}

/// Runs a job in the isolate's job table, where a later invocation can
/// drop it should this one be cancelled: a cancelled invocation is not
/// dropped, and the job would keep its bytes of the budget (`jobs`).
async fn run_in_table(bridge: &Rc<env::WorkerBridge>, job: &Job) -> JobOutcome {
    let now = velmora_bridge::ports::Clock::now(&bridge.clock);
    // A wake that is due runs its stage too.
    let post = matches!(
        job,
        Job::Extent {
            stage: OutboxStage::Post,
            ..
        } | Job::Wake {
            stage: OutboxStage::Post,
            ..
        }
    );
    let (b, j) = (Rc::clone(bridge), job.clone());
    match jobs::run(now, post, async move { b.run_job(&j).await }).await {
        Some(outcome) => outcome,
        // `jobs::run` has logged it.
        None => JobOutcome::Retry {
            delay_secs: velmora_bridge::jobs::INFRA_RETRY_SECS,
        },
    }
}

/// Drops the jobs of invocations that are gone, and says when the byte
/// budget of this isolate stays full. Counts, sizes and times only.
fn log_budget(bridge: &env::WorkerBridge) {
    let now = velmora_bridge::ports::Clock::now(&bridge.clock);
    if let Some(line) = jobs::reap(&bridge.budget, env::isolate(), now) {
        console_error!("{line}");
    }
    if let Some(line) = jobs::watch_line(&bridge.budget, env::isolate(), now) {
        console_error!("{line}");
    }
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

/// After a post job that is done: the hint that brings the article
/// plan of its extent over to the recovery store now. Without it the
/// plan waits for the walk (`velmora_bridge::copy`).
async fn plan_hint(env: &Env, bridge: &env::WorkerBridge, job: &Job, outcome: &JobOutcome) {
    use velmora_bridge::copy::{posted, send_hint};
    // Nothing to hint at, or no copy. A configuration that is refused
    // is found by the job of the hint, which says nothing: the cron
    // run says it.
    if posted(job, outcome).is_none()
        || bridge.cfg.maintenance == velmora_bridge::config::Maintenance::Restore
        || !env::recovery_copy_on(env)
    {
        return;
    }
    let now = velmora_bridge::ports::Clock::now(&bridge.clock);
    if !send_hint(&bridge.safety, &bridge.jobs, job, outcome, now).await {
        console_error!("recovery copy: a hint was not sent");
    }
}

/// One job of a pass of the recovery copy, or of a hint (pass 0). Logs counts only. A job
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
        // A hint (pass 0) says nothing: there is one for every extent,
        // and the cron run says it.
        Err(_) if pass.0 == 0 => return JobOutcome::Ack,
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
    // A hint that is held back while the store is down asked nothing,
    // and comes again: no line for each of them.
    let held = pass.0 == 0 && retry && counts.is_none();
    if let Some(why) = why.filter(|_| !held) {
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
            if report.mark_failed {
                console_error!(
                    "dispatch: the sent mark was not written; due rows are sent again next run"
                );
            }
            if report.evict_failed {
                console_error!("dispatch: hot-tier check failed");
            }
            if report.release_paused {
                if let Some(warning) = bridge.cfg.release_paused() {
                    console_error!("dispatch: {warning}");
                }
            }
            if !report.verify_escalated.is_empty() {
                console_error!(
                    "dispatch: a full read of a sampled extent failed; every extent is read in \
                     full on: {}",
                    report.verify_escalated.join(", ")
                );
            }
            if report.sweep_failed {
                console_error!("dispatch: the sweep of unpublished writes was not sent");
            }
            if report.pack_failed {
                console_error!("dispatch: packing article plans failed");
            }
            if report.recount_failed {
                console_error!("dispatch: the usage recount step failed");
            }
            match report.recount_drift {
                Some(0) => console_log!("dispatch: usage recount ended, no drift"),
                Some(n) => console_error!(
                    "alert: usage counters differ from the tables in {n} figures; see /_admin/ops-snapshot"
                ),
                None => {}
            }
            let resend_secs = velmora_bridge::jobs::RESEND_SECS;
            if report.resend_post_secs > resend_secs || report.resend_verify_secs > resend_secs {
                console_log!(
                    "dispatch: queues behind; a sent row is left alone for {} s (post), {} s (verify)",
                    report.resend_post_secs,
                    report.resend_verify_secs
                );
            }
        }
        Err(e) => console_error!("dispatch failed: {}", error_class(&e)),
    }
}
