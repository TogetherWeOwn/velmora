//! Worker entry: `fetch` -> headers-only precheck -> `Bridge::handle` (S3
//! and `/_admin`), `queue` -> `Bridge::run_job`, `scheduled` ->
//! the start of a pass of the recovery copy when one is due, then
//! `Bridge::dispatch` (the bounded dispatcher), then, once every 15
//! minutes, `Bridge::probe_providers` (a provider whose strikes no session
//! clears). A recovery-copy job is run here, with the recovery store, not
//! by `Bridge::run_job`.
//!
//! The `Bridge` is built once per isolate from validated configuration.
//! A refused configuration is a `500` with a class-only log line (fail
//! closed). Logs carry method, bucket, key hash, status and request ID;
//! never credentials, presigned queries, bodies or provider text.

mod catalog_sql;
mod d1;
mod e2;
mod env;
mod fanout;
mod gate;
mod http;
mod jobs;
mod metrics;
mod nntp;
mod pgsql;
mod queue_attempt;
mod queues;
mod r2;
mod recovery_audit;
mod recovery_log;
mod request_log;

use std::cell::RefCell;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};

use velmora_bridge::copy::Copier;
use velmora_bridge::ingress;
use velmora_bridge::keepalive;
use velmora_bridge::metrics::{FailureStage as Stage, Fault, RequestObservation};
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
    resp: Option<(S3Response, RequestObservation)>,
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
    ctx: Rc<Context>,
    bridge: Rc<env::WorkerBridge>,
    req: velmora_bridge::S3Request,
) -> (S3Response, RequestObservation) {
    let slot = Rc::new(RefCell::new(Slot::default()));
    let tx = Rc::clone(&slot);
    let spawn: ingress::Spawner = Rc::new(move |work| ctx.wait_until(work));
    let flush = (bridge.cfg.hot_ctl.mode != velmora_bridge::config::HotCtlMode::Fixed)
        .then(|| Rc::clone(&spawn));
    spawn(Box::pin(async move {
        let mut get = RequestObservation::default();
        let mut resp = bridge
            .handle_observed_with_hit_flush(req, &mut get, flush)
            .await;
        let work = match &mut resp.body {
            RespBody::Deferred(d) => d.take_work(),
            _ => None,
        };
        {
            let mut s = tx.borrow_mut();
            s.resp = Some((resp, get));
            if let Some(w) = s.waker.take() {
                w.wake();
            }
        }
        if let Some(work) = work {
            work.await;
        }
    }));
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
    // GET it belongs to is the request that is counted. Set below, and
    // only for a request whose token verifies: the header alone, which
    // any client can send, changes nothing.
    let internal = std::cell::Cell::new(false);
    // Every answer for an admin route carries `no-store`, the early
    // refusals below too.
    let url = req.inner().url();
    let admin = ingress::is_admin_url(&url);
    // Only identify CompleteMultipartUpload here if the router did not run.
    let initial = || {
        if method == "POST" && !admin {
            velmora_bridge::service::initial_observation(
                &method,
                ingress::origin_form(&url).unwrap_or(""),
            )
        } else {
            RequestObservation::default()
        }
    };
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
    let count = |status: u16, sample: u32, bytes_out: u64, get: RequestObservation| {
        if internal.get() && status < 500 {
            return;
        }
        // Every request has an ID now (a ray ID, or one of its own for a
        // request through a service binding), so the draw is by that ID.
        // The count of this isolate stays as a guard for an empty one.
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
                sub: internal.get(),
                status,
                latency_ms: worker::Date::now().as_millis().saturating_sub(started),
                bytes_in,
                bytes_out,
                colo: &colo,
                get,
            };
            metrics::write(&velmora_bridge::metrics::request_point(&seen, weight));
        }
    };
    let bridge = match env::bridge(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            let resp = ingress::IngressError::Internal.response();
            let intended = resp.status;
            let out = early(resp);
            let mut observed = initial();
            observed.mark_fault(Stage::Other, Fault::named("Config"));
            let status = request_log::Answered {
                method: &method,
                target: "-",
                request_id: &request_id,
                admin,
            }
            .finish(intended, out.status_code(), &mut observed);
            count(status, 1, 0, observed);
            return Ok(out);
        }
    };
    let incoming = match http::to_s3_request(req) {
        Ok(incoming) => incoming,
        Err(e) => {
            // The answer first: the line has the status the client got.
            let out = early(e.response());
            let mut observed = initial();
            observed.mark_fault(Stage::Other, Fault::named("RequestConversion"));
            let status = request_log::Answered {
                method: &method,
                target: "-",
                request_id: &request_id,
                admin,
            }
            .finish(e.status(), out.status_code(), &mut observed);
            count(status, bridge.cfg.metrics_sample, 0, observed);
            return Ok(out);
        }
    };
    let target = incoming.req.raw_target.clone();
    internal.set(
        velmora_bridge::fanout::admit(
            &bridge.kek,
            &incoming.req,
            velmora_bridge::ports::Clock::now(&bridge.clock),
        )
        .is_ok(),
    );
    let got = std::cell::Cell::new(None);
    let ctx = Rc::new(ctx);
    let resp = ingress::front(incoming.req, &bridge.cfg, incoming.https, |req| async {
        let (resp, get) = handle_detached(Rc::clone(&ctx), Rc::clone(&bridge), req).await;
        got.set(Some(get));
        // A deferred document: buffered when it is done soon, else
        // streamed with keepalive whitespace.
        keepalive::settle_response(resp, env::sleeper()).await
    })
    .await
    .with_request_id(&request_id);
    // A body in sub-ranges: the first one is opened before the status is
    // known to the client.
    let mut get = got.into_inner().unwrap_or_else(initial);
    let (status, out) = fanout::respond(&env, &ctx, resp, &request_id, &mut get).await;
    // HTTP conversion can itself turn a response into a 500: the line has
    // the status the client got and, for a 5xx, what the handler observed
    // of it (stage, error variant, provider code; names and numbers only).
    let metrics_status = request_log::Answered {
        method: &method,
        target: &target,
        request_id: &request_id,
        admin,
    }
    .finish(status, out.status_code(), &mut get);
    if let Some(line) = env::memory_line(&bridge) {
        console_log!("{line}");
    }
    count(
        metrics_status,
        bridge.cfg.metrics_sample,
        length(out.headers()),
        get,
    );
    Ok(out)
}

// Match the SDK queue export, but keep the raw batch long enough to read
// optional telemetry metadata without the typed SDK getter's unwrap.
mod queue_export {
    use worker::wasm_bindgen::{prelude::wasm_bindgen, JsValue};
    use worker::{worker_sys, Env};

    #[wasm_bindgen(wasm_bindgen = ::worker::wasm_bindgen, wasm_bindgen_futures = ::worker::wasm_bindgen_futures, js_sys = ::worker::js_sys)]
    pub async fn queue(
        event: worker_sys::MessageBatch,
        env: Env,
        ctx: worker_sys::Context,
    ) -> std::result::Result<JsValue, JsValue> {
        std::panic::AssertUnwindSafe(async move {
            if let Err(e) = super::handle_queue(event, env, worker::Context::new(ctx)).await {
                worker::console_log!("{}", &e);
                panic!("{e}");
            }
            Ok(JsValue::UNDEFINED)
        })
        .await
    }
}

async fn handle_queue(
    event: worker::worker_sys::MessageBatch,
    env: Env,
    ctx: Context,
) -> Result<()> {
    // What an operator has to see of a job: a failed full read of a
    // sampled extent, for one.
    velmora_bridge::trace::log_alerts(|line| console_error!("alert: {line}"));
    // One line per scrub run.
    velmora_bridge::trace::log_scrub_runs(|line| console_log!("scrub: {line}"));
    let bridge = match env::bridge(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            // Every message is retried by the platform.
            return Err(worker::Error::RustError("config refused".into()));
        }
    };
    use velmora_bridge::metrics::job_weight;
    let sample = if metrics::bind(&env) {
        metrics::sample_binding(&env)
    } else {
        0
    };
    let queue = if sample > 0 {
        metrics::queue_name(|| event.queue().map(|name| name.as_string()))
    } else {
        String::new()
    };
    let batch = MessageBatch::<serde_json::Value>::from(event);
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
                    recovery_copy(&env, &ctx, &bridge, *pass, cursor).await
                } else {
                    console_error!("recovery copy: a job of another version was dropped");
                    JobOutcome::Ack
                }
            }
            _ => {
                let observation = job
                    .extent()
                    .and_then(|_| job_weight(sample))
                    .map(|weight| (queue.clone(), weight));
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
                let (b, j) = (Rc::clone(&bridge), job.clone());
                queue_attempt::run_in_table(env::WorkerClock, post, observation, async move {
                    b.run_job(&j).await
                })
                .await
            }
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
    // What the requests and the jobs waited for each other's bytes: a
    // measurement, so a plain log line and not an error.
    if let Some(line) = jobs::pressure_line(&bridge.budget, env::isolate(), now) {
        console_log!("{line}");
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
    ctx: &Context,
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
            let log = recovery_log::Log::config_refused(
                pass,
                velmora_bridge::ports::Clock::now(&bridge.clock),
            );
            return record_copy_job(ctx, env, log, Default::default(), 1, JobOutcome::Ack);
        }
    };
    let (outcome, report) = copier(bridge, &remote)
        .run_job_report(&bridge.jobs, pass, cursor)
        .await;
    let at = velmora_bridge::ports::Clock::now(&bridge.clock);
    let (counts, why) = (report.counts.as_ref(), report.error);
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
    if pass.0 == 0 {
        return outcome;
    }
    let log = recovery_log::Log {
        at,
        pass,
        destination: Some(remote.place()),
        first: remote
            .transport()
            .first_problem
            .get()
            .or_else(|| recovery_log::source_problem(&report)),
    };
    let problems = report.problems();
    record_copy_job(ctx, env, log, report, problems, outcome)
}

fn record_copy_job(
    ctx: &Context,
    env: &Env,
    log: recovery_log::Log,
    report: velmora_bridge::copy::JobReport,
    problems: u64,
    outcome: JobOutcome,
) -> JobOutcome {
    recovery_log::complete_job(outcome, || {
        ctx.wait_until(persist_copy_job(env.clone(), log, report, problems));
    })
}

async fn persist_copy_job(
    env: Env,
    log: recovery_log::Log,
    report: velmora_bridge::copy::JobReport,
    problems: u64,
) {
    let wrote = match catalog_sql::CatalogSql::recovery_log_from_env(&env) {
        Ok(db) => log.job(&db, &report, problems).await.is_ok(),
        Err(_) => false,
    };
    if !wrote {
        console_error!("recovery copy: job telemetry write failed");
    }
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
async fn scheduled(event: ScheduledEvent, env: Env, ctx: ScheduleContext) {
    let scheduled = UnixMs(event.schedule() as i64);
    if velmora_bridge::copy::pass_due(scheduled) {
        let env = env.clone();
        ctx.wait_until(async move {
            let ok = match catalog_sql::CatalogSql::recovery_log_from_env(&env) {
                Ok(db) => recovery_log::prune_tick(
                    &db,
                    scheduled,
                    velmora_bridge::ports::Clock::now(&env::WorkerClock),
                )
                .await
                .is_ok(),
                Err(_) => false,
            };
            if !ok {
                console_error!("recovery copy: telemetry prune failed");
            }
        });
    }
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
    let copy_allowed = bridge.cfg.maintenance != velmora_bridge::config::Maintenance::Restore;
    match env::recovery_store(&env) {
        Ok(None) => {}
        Ok(Some(remote)) => {
            if copier(&bridge, &remote)
                .start_pass(&bridge.jobs, scheduled)
                .await
                .is_err()
            {
                console_error!("recovery copy: the pass was not started");
            }
            if copy_allowed {
                if let Some(pass) = recovery_audit::pass_at(scheduled) {
                    ctx.wait_until(recovery_audit::run(env.clone(), pass, remote));
                }
            }
        }
        Err(class) => {
            console_error!("recovery copy: config refused: {class}");
            if copy_allowed && velmora_bridge::copy::pass_due(scheduled) {
                // Configuration was refused before a job could be sent.
                let log = recovery_log::Log::config_refused(
                    scheduled,
                    velmora_bridge::ports::Clock::now(&bridge.clock),
                );
                ctx.wait_until(persist_copy_job(env.clone(), log, Default::default(), 1));
            }
        }
    }
    match bridge.dispatch().await {
        Ok(report) => {
            if let Some(line) = report.hot_ctl.as_ref().and_then(|ctl| ctl.log_line().ok()) {
                console_log!("{line}");
            }
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
    // After the dispatcher and apart from it: a provider whose strikes
    // no session clears gets one probe session now and then.
    if velmora_bridge::probe::probe_tick(UnixMs(event.schedule() as i64)) {
        match bridge.probe_providers().await {
            Ok(probed) => {
                for (id, outcome) in probed {
                    console_log!("provider probe: {id} {outcome}");
                }
            }
            Err(e) => console_error!("provider probe failed: {}", error_class(&e)),
        }
    }
}

#[cfg(test)]
mod request_log_wiring {
    /// The fetch handler, as compiled.
    const SOURCE: &str = include_str!("lib.rs");

    /// The lines themselves are tested in `request_log`; this checks that
    /// the handler writes none of its own and settles each of its three
    /// answers there, the handled one with the handler's own observation.
    #[test]
    fn every_answer_is_finished_by_the_request_log() {
        let code = SOURCE
            .split("#[cfg(test)]\nmod request_log_wiring")
            .next()
            .unwrap();
        for direct in ["ingress::log_line", "settled_log_line("] {
            assert!(!code.contains(direct), "{direct} bypasses request_log");
        }
        let calls: Vec<&str> = code
            .split("request_log::Answered {")
            .skip(1)
            .map(|call| call.split(";").next().unwrap())
            .collect();
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert!(calls
            .iter()
            .all(|call| call.contains(".finish(") && call.contains("out.status_code()")));
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains("&mut get"))
                .count(),
            1,
            "the handled request logs its own observation"
        );
        assert!(code.contains("let mut get = got.into_inner().unwrap_or_else(initial);"));
    }
}
