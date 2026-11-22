//! The unit's alarm (`docs/units.md`, rules 4, 8 and 12): the one place
//! of the object class that sends to a queue or arms an alarm.
//!
//! - [`run`]: the alarm handler. The unit decides what to send
//!   (`Unit::alarm`): one `stamp_raise` per period with writes under a
//!   fresh lease with at least half of T left, one `renew` instead of
//!   the raise with less, and with an expired lease one `renew` and
//!   nothing else; and, under a fresh lease, the hand-out of its due work
//!   (`unit_lease::handout`: due outbox rows, `gc`, `evict`). Every message
//!   goes through `velmora_bridge::routing`, as tenant 0's: an extent's
//!   job to its shard of the post or verify queues, the rest to `AUX_Q`,
//!   or to the first verify queue where `AUX_Q` is not bound (AM-49). Then
//!   the unit records what was sent (`Unit::alarm_done`) and answers when
//!   to fire next, which is armed here.
//! - [`arm`]: after a call, the time the call asked for, armed only when
//!   nothing is armed or it is earlier than the armed one (rule 8: each
//!   `setAlarm` is a billed row write).
//!
//! A send that fails leaves its work due (a row stays unmarked, a raise
//! pending) and counts a failed run; the unit backs off. An alarm handler
//! that fails is retried by the platform.

use std::cell::Cell;

use velmora_bridge::jobmsg::JobTenant;
use velmora_bridge::routing::{bound_queues, Shards, AUX_Q};
use velmora_bridge::unit::{AlarmSent, AlarmStep, Unit};
use velmora_bridge::unit_lease::alarm::{rearm, Rearm};
use velmora_bridge::unit_lease::handout::{route, Outgoing};
use velmora_bridge::UnixMs;
use worker::js_sys;
use worker::wasm_bindgen::JsValue;
use worker::{Date, Env, QueueContentType, RawMessageBuilder, ScheduledTime, SendMessage, State};

use crate::DoSql;

/// The alarm as one wake knows it: `None` = not read yet; then the armed
/// time (`Some(None)` = none armed).
pub type Armed = Option<Option<i64>>;

fn now() -> UnixMs {
    UnixMs(Date::now().as_millis() as i64)
}

/// The queues bound in this Worker, as `routing` counts them.
fn shards(env: &Env) -> Option<Shards> {
    let bound = |name: &str| env.queue(name).is_ok();
    Some(Shards {
        post: bound_queues("POST_Q", bound).ok()?,
        verify: bound_queues("VERIFY_Q", bound).ok()?,
        aux: bound(AUX_Q),
    })
}

/// The sends of `step`, by queue; `None` = they cannot be made (no queue
/// bound, or the unit names no tenant with a job form).
fn sends(unit: &Unit<DoSql>, env: &Env, step: &AlarmStep) -> Option<Vec<Outgoing>> {
    let name = unit.name();
    let tenant = JobTenant::of_unit(
        name.tenant.as_str(),
        name.unit,
        step.seqs.state_seq,
        step.seqs.keys_seq,
    )?;
    route(&step.jobs, &step.handout.jobs, &tenant, shards(env)?).ok()
}

/// One `sendBatch`. The message's JSON text is parsed by JavaScript into
/// a plain object: a `serde_json::Value` would go through
/// `serde_wasm_bindgen`, which makes a map of an object, and a map is
/// sent as `{}`.
async fn send(env: &Env, out: &Outgoing) -> bool {
    let Ok(queue) = env.queue(&out.binding) else {
        return false;
    };
    let mut messages: Vec<SendMessage<JsValue>> = Vec::with_capacity(out.texts.len());
    for text in &out.texts {
        let Ok(body) = js_sys::JSON::parse(text) else {
            return false;
        };
        messages.push(RawMessageBuilder::new(body).build_with_content_type(QueueContentType::Json));
    }
    queue.send_raw_batch(messages).await.is_ok()
}

/// The alarm handler.
pub async fn run(
    unit: &Unit<DoSql>,
    state: &State,
    env: &Env,
    armed: &Cell<Armed>,
) -> worker::Result<()> {
    // The alarm that fired is no longer armed.
    armed.set(Some(None));
    let step = unit
        .alarm(now())
        .map_err(|e| worker::Error::RustError(format!("unit alarm: {e}")))?;
    let mut sent = AlarmSent {
        failed: false,
        handed_out: vec![false; step.handout.jobs.len()],
    };
    if !step.jobs.is_empty() || !step.handout.jobs.is_empty() {
        match sends(unit, env, &step) {
            Some(batches) => {
                // Each queue's batch on its own: a queue that refuses
                // does not keep the others from theirs.
                for out in &batches {
                    let ok = send(env, out).await;
                    for job in &out.handout {
                        match job {
                            Some(i) => sent.handed_out[*i] = ok,
                            None if !ok => sent.failed = true,
                            None => {}
                        }
                    }
                }
            }
            None => sent.failed = true,
        }
    }
    let next = unit
        .alarm_done(now(), &step, &sent)
        .map_err(|e| worker::Error::RustError(format!("unit alarm: {e}")))?;
    arm(state, armed, next).await
}

/// Arms `wanted` if nothing is armed or it is earlier than the armed
/// time. Reads the armed time once per wake.
pub async fn arm(state: &State, armed: &Cell<Armed>, wanted: Option<UnixMs>) -> worker::Result<()> {
    if wanted.is_none() {
        return Ok(());
    }
    let storage = state.storage();
    let current = match armed.get() {
        Some(known) => known,
        None => {
            let read = storage.get_alarm().await?;
            armed.set(Some(read));
            read
        }
    };
    if let Rearm::Set(at) = rearm(current.map(UnixMs), wanted) {
        let date = js_sys::Date::new(&JsValue::from_f64(at.0 as f64));
        storage.set_alarm(ScheduledTime::new(date)).await?;
        armed.set(Some(Some(at.0)));
    }
    Ok(())
}
