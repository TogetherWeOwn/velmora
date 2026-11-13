//! Worker entry (integration lane): `fetch` -> `Bridge::handle`, `queue`
//! -> `Bridge::run_job`, `scheduled` -> `Bridge::dispatch` only.
//!
//! Walking skeleton: the `Bridge` is built per invocation from validated
//! configuration (fail closed: a refused config is a `500` with a
//! class-only log line), and every route answers `501`.

mod d1;
mod env;
mod http;
mod nntp;
mod queues;
mod r2;

use std::rc::Rc;

use velmora_bridge::{Job, JobOutcome};
use worker::{
    console_error, event, Context, Env, MessageBatch, MessageExt, QueueRetryOptionsBuilder,
    Request, Response, Result, ScheduleContext, ScheduledEvent,
};

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let bridge = match env::build(&env) {
        Ok(bridge) => Rc::new(bridge),
        Err(class) => {
            console_error!("config refused: {class}");
            return Response::error("Internal Error", 500);
        }
    };
    let req = http::to_s3_request(req)?;
    http::to_response(bridge.handle(req).await)
}

#[event(queue)]
async fn queue(batch: MessageBatch<serde_json::Value>, env: Env, _ctx: Context) -> Result<()> {
    let bridge = match env::build(&env) {
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
    let bridge = match env::build(&env) {
        Ok(bridge) => bridge,
        Err(class) => {
            console_error!("config refused: {class}");
            return;
        }
    };
    if let Err(e) = bridge.dispatch().await {
        console_error!("dispatch failed: {e}");
    }
}
