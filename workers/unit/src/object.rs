//! The unit's Durable Object class (`docs/units.md`).
//!
//! One `POST` per call: the body is a [`UnitCall`] as JSON, the answer a
//! [`UnitReply`] as JSON with status 200 (the Worker maps answers to S3
//! statuses): the answer's object with `lease_left_ms` and, for a unit
//! that holds keys, `revoked` beside its own fields. A body that is not a
//! call answers 400 and touches nothing.
//!
//! The object's own name is the name it was made under
//! (`idFromName("<tenant>/<unit>")`), and its jurisdiction that of its
//! namespace. An object made any other way has no name a call can match,
//! and answers every call with a refusal.
//!
//! **The alarm** (rules 4, 8 and 12) lives in [`crate::alarm`], the only
//! code of the class that reaches out: it sends the unit's two jobs and
//! arms the alarm. A call sends nothing; after a call that made
//! something due (a first write since the last stamp raise, a renewal
//! with work waiting) the class has the alarm armed, only when that is
//! earlier than the armed one.
//!
//! Nothing here holds a key (rule 3).

use std::cell::Cell;

use velmora_bridge::unit::identity::Refusal;
use velmora_bridge::unit::restore::{self, PointInTimePort};
use velmora_bridge::unit::{Refused, Unit, UnitAnswer, UnitCall, UnitName, UnitReply};
use velmora_bridge::UnixMs;
use worker::js_sys::{self, Reflect};
use worker::wasm_bindgen::{self, JsCast, JsValue};
use worker::{
    console_error, durable_object, Date, DurableObject, Env, Method, Request, Response, State,
};

use crate::{DoSql, PointInTime};

#[durable_object]
pub struct UnitObject {
    unit: Option<Unit<DoSql>>,
    pitr: PointInTime,
    state: State,
    env: Env,
    /// The alarm as this wake knows it ([`crate::alarm::Armed`]).
    armed: Cell<crate::alarm::Armed>,
}

impl DurableObject for UnitObject {
    fn new(state: State, env: Env) -> Self {
        let name = state.id().name().and_then(|n| UnitName::parse(&n));
        let jurisdiction = jurisdiction(&state);
        let unit = name
            .map(|own| Unit::woken(DoSql::new(&state.storage()), own, &jurisdiction, wake_id()));
        let pitr = PointInTime::new(&state);
        UnitObject {
            unit,
            pitr,
            state,
            env,
            armed: Cell::new(None),
        }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let Some(call) = req
            .text()
            .await
            .ok()
            .and_then(|t| serde_json::from_str::<UnitCall>(&t).ok())
        else {
            return Response::error("not a unit call", 400);
        };
        let now = UnixMs(Date::now().as_millis() as i64);
        let reply = match &self.unit {
            // The two restore calls need the object's storage: the unit
            // checks first, then the bookmark calls run here (AM-2).
            Some(unit) if call.op.restore_call() => {
                let answer = restore::drive(unit.pitr_step(&call, now), &self.pitr).await;
                unit.wrap(answer, now)
            }
            Some(unit) => unit.reply(&call, now),
            None => UnitReply {
                answer: UnitAnswer::Refused {
                    reason: Refused::Identity(Refusal::WrongName),
                    alarm: true,
                },
                lease_left_ms: 0,
                revoked: None,
            },
        };
        if let Some(unit) = &self.unit {
            let wanted = unit.take_wake();
            if let Err(e) = crate::alarm::arm(&self.state, &self.armed, wanted).await {
                // The answer stands: the call committed. The next call
                // that writes, or the next renewal, asks again.
                console_error!("unit: arming the alarm failed: {e}");
            }
        }
        Response::from_json(&reply)
    }

    async fn alarm(&self) -> worker::Result<Response> {
        let Some(unit) = &self.unit else {
            return Response::ok("no unit");
        };
        crate::alarm::run(unit, &self.state, &self.env, &self.armed).await?;
        Response::ok("ran")
    }
}

/// 16 bytes of the platform's random source, new at each wake (the
/// unit's write mark, `unit_lease::mark`). Should the source be missing,
/// the bytes come from `Math.random` and the clock: still new at each
/// wake, which is what the mark needs.
fn wake_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let buf = js_sys::Uint8Array::new_with_length(16);
    let filled = Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
        .ok()
        .and_then(|crypto| {
            let f = Reflect::get(&crypto, &JsValue::from_str("getRandomValues")).ok()?;
            let f = f.dyn_into::<js_sys::Function>().ok()?;
            f.call1(&crypto, &buf).ok()
        })
        .is_some();
    if filled {
        buf.copy_to(&mut id);
    } else {
        let t = Date::now().as_millis().to_le_bytes();
        for (i, b) in id.iter_mut().enumerate() {
            *b = (js_sys::Math::random() * 256.0) as u8 ^ t[i % 8];
        }
    }
    id
}

/// The jurisdiction of the object's namespace (`ctx.id.jurisdiction`),
/// "" when it has none (rule 14).
fn jurisdiction(state: &State) -> String {
    let id: &JsValue = state.as_raw().as_ref();
    Reflect::get(id, &JsValue::from_str("id"))
        .ok()
        .and_then(|id| Reflect::get(&id, &JsValue::from_str("jurisdiction")).ok())
        .and_then(|j| j.as_string())
        .unwrap_or_default()
}

impl PointInTimePort for PointInTime {
    async fn current(&self) -> velmora_bridge::Result<String> {
        PointInTime::current(self).await
    }

    async fn at(&self, unix_ms: i64) -> velmora_bridge::Result<String> {
        PointInTime::at(self, unix_ms).await
    }

    async fn restore_now(&self, bookmark: &str) -> velmora_bridge::Result<()> {
        PointInTime::restore_now(self, bookmark).await
    }
}
