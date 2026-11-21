//! The unit's Durable Object class (`docs/units.md`).
//!
//! One `POST` per call: the body is a [`UnitCall`] as JSON, the answer a
//! [`UnitAnswer`] as JSON with status 200 (the Worker maps answers to S3
//! statuses). A body that is not a call answers 400 and touches nothing.
//!
//! The object's own name is the name it was made under
//! (`idFromName("<tenant>/<unit>")`), and its jurisdiction that of its
//! namespace. An object made any other way has no name a call can match,
//! and answers every call with a refusal.
//!
//! Nothing here sets a timer, opens a socket or sends to a queue (rule 4),
//! and nothing holds a key (rule 3).

use velmora_bridge::unit::identity::Refusal;
use velmora_bridge::unit::{Refused, Unit, UnitAnswer, UnitCall, UnitName};
use velmora_bridge::UnixMs;
use worker::js_sys::Reflect;
use worker::wasm_bindgen::{self, JsValue};
use worker::{durable_object, Date, DurableObject, Env, Method, Request, Response, State};

use crate::DoSql;

#[durable_object]
pub struct UnitObject {
    unit: Option<Unit<DoSql>>,
}

impl DurableObject for UnitObject {
    fn new(state: State, _env: Env) -> Self {
        let name = state.id().name().and_then(|n| UnitName::parse(&n));
        let jurisdiction = jurisdiction(&state);
        let unit = name.map(|own| Unit::new(DoSql::new(&state.storage()), own, &jurisdiction));
        UnitObject { unit }
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
        let answer = match &self.unit {
            Some(unit) => unit.handle(&call, UnixMs(Date::now().as_millis() as i64)),
            None => UnitAnswer::Refused {
                reason: Refused::Identity(Refusal::WrongName),
                alarm: true,
            },
        };
        Response::from_json(&answer)
    }
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
