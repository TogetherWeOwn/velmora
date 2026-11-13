//! Worker entry: `fetch` -> headers-only precheck -> `Bridge::handle` (S3
//! and `/_admin`), `queue` -> `Bridge::run_job`, `scheduled` ->
//! `Bridge::dispatch` only (the bounded dispatcher).
//!
//! The `Bridge` is built once per isolate from validated configuration.
//! A refused configuration is a `500` with a class-only log line (fail
//! closed). Logs carry method, bucket, key hash, status and request ID;
//! never credentials, presigned queries, bodies or provider text.

mod d1;
mod env;
mod http;
mod nntp;
mod queues;
mod r2;

use std::rc::Rc;

use velmora_bridge::ingress;
use velmora_bridge::service::classify;
use velmora_bridge::{BridgeError, Job, JobOutcome};
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

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
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
        Ok(()) => Rc::clone(&bridge).handle(incoming.req).await,
    };
    console_log!(
        "{}",
        ingress::log_line(&method, &target, resp.status, &request_id)
    );
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
        match bridge.run_job(&job).await {
            JobOutcome::Ack => msg.ack(),
            JobOutcome::Retry { delay_secs } => msg.retry_with_options(
                &QueueRetryOptionsBuilder::new()
                    .with_delay_seconds(delay_secs)
                    .build(),
            ),
        }
    }
    Ok(())
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let bridge = match env::bridge(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            return;
        }
    };
    if let Err(e) = bridge.dispatch().await {
        console_error!("dispatch failed: {}", error_class(&e));
    }
}
