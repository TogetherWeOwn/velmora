//! The unit's alarm (`docs/units.md`, rules 4, 8 and 12): the one place
//! of the object class that sends to a queue or arms an alarm.
//!
//! - [`run`]: the alarm handler. The unit decides what to send
//!   (`Unit::alarm`): one `stamp_raise` per period with writes under a
//!   fresh lease, and with an expired lease one `renew` and nothing
//!   else. They go to the queue bound as [`UNIT_JOB_QUEUE`]. Then the
//!   unit records the run (`Unit::alarm_done`) and answers when to fire
//!   next, which is armed here.
//! - [`arm`]: after a call, the time the call asked for, armed only when
//!   nothing is armed or it is earlier than the armed one (rule 8: each
//!   `setAlarm` is a billed row write).
//!
//! A send that fails leaves its work due and counts a failed run; the
//! unit backs off. An alarm handler that fails is retried by the
//! platform.

use std::cell::Cell;

use velmora_bridge::unit::Unit;
use velmora_bridge::unit_lease::alarm::{rearm, Rearm};
use velmora_bridge::UnixMs;
use worker::js_sys;
use worker::wasm_bindgen::JsValue;
use worker::{Date, Env, MessageBuilder, QueueContentType, ScheduledTime, State};

use crate::DoSql;

/// The queue binding the alarm sends the unit's jobs to: the Worker's
/// aux queue, whose consumer reads format 2 (W0b). Unbound = every send
/// fails, and the alarm backs off.
pub const UNIT_JOB_QUEUE: &str = "AUX_Q";

/// The alarm as one wake knows it: `None` = not read yet; then the armed
/// time (`Some(None)` = none armed).
pub type Armed = Option<Option<i64>>;

fn now() -> UnixMs {
    UnixMs(Date::now().as_millis() as i64)
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
    let mut failed = false;
    if !step.jobs.is_empty() {
        match env.queue(UNIT_JOB_QUEUE) {
            Ok(queue) => {
                for text in &step.jobs {
                    let sent = match serde_json::from_str::<serde_json::Value>(text) {
                        Ok(body) => queue
                            .send(
                                MessageBuilder::new(body)
                                    .content_type(QueueContentType::Json)
                                    .build(),
                            )
                            .await
                            .is_ok(),
                        Err(_) => false,
                    };
                    if !sent {
                        failed = true;
                        break;
                    }
                }
            }
            Err(_) => failed = true,
        }
    }
    let next = unit
        .alarm_done(now(), &step, failed)
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
