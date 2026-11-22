//! The jobs of a managed tenant, run against the tenant's unit (round 3
//! L1-Q7; `docs/units.md`, "Jobs").
//!
//! **Off as shipped.** Only a Worker with the unit class bound under
//! [`UNIT_BINDING`] admits such a job (`jobmsg::admit_for` with
//! `Units::Bound`); the production config binds none, so there every
//! message of a managed tenant is refused as before (`other_tenant`).
//!
//! With the binding, a job message that names a managed tenant and its
//! unit runs on a bridge of its own ([`UnitBridge`]):
//!
//! - its catalogue is a `TenantCatalog`: the job calls go to the unit
//!   through [`UnitStub`], the unit object's `fetch` (one `POST` of a
//!   `UnitCall` as JSON), with the message's numbers; permits and
//!   provider health go to the shared database, with the isolate's
//!   permit gate;
//! - its configuration is tenant 0's with the unit's stamp id and the
//!   tenant's record layout (`BridgeConfig::for_unit`, from the unit's
//!   name, never from a string);
//! - its job messages name the tenant, the unit and the same numbers,
//!   always in format 2 (`QueueSink` refuses a `v` 1 message for a unit);
//! - its bytes come out of the isolate's one budget
//!   (`ByteBudget::shared`).
//!
//! After `run_job`, the first refusal the unit gave decides the delivery
//! (`velmora_bridge::unit_consumer`).

use velmora_bridge::jobmsg::{JobTenant, Units};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::tenant_catalog::{TenantCatalog, UnitPort};
use velmora_bridge::unit::{Seqs, TenantId, UnitAnswer, UnitCall, UnitName, UnitReply};
use velmora_bridge::{Bridge, BridgeError, Result};
use worker::wasm_bindgen::JsValue;
use worker::{Env, Method, ObjectNamespace, Request, RequestInit, Stub};

use crate::d1::D1Sql;
use crate::env::{WorkerBridge, WorkerClock};
use crate::nntp::WorkerConnector;
use crate::queues::QueueSink;
use crate::r2::R2Blobs;
use velmora_bridge::config::KekRing;

/// The binding of the unit class (a Durable Object namespace).
pub const UNIT_BINDING: &str = "UNIT";

/// The bridge of one managed tenant's unit, for one job.
pub type UnitBridge = Bridge<
    TenantCatalog<UnitStub, SqlCatalog<D1Sql>>,
    R2Blobs,
    WorkerConnector,
    QueueSink,
    KekRing,
    WorkerClock,
>;

/// Whether this Worker has the unit class bound.
pub fn units(env: &Env) -> Units {
    match env.durable_object(UNIT_BINDING) {
        Ok(_) => Units::Bound,
        Err(_) => Units::Unbound,
    }
}

/// One unit object, reached through its stub.
pub struct UnitStub {
    stub: Stub,
}

impl UnitStub {
    /// The object named `<tenant>/<unit>` in `namespace`, the name a unit
    /// is made under (`UnitName::object_name`).
    fn new(namespace: &ObjectNamespace, name: &UnitName) -> Result<UnitStub> {
        let stub = namespace
            .id_from_name(&name.object_name())
            .and_then(|id| id.get_stub())
            .map_err(|_| failed("no object"))?;
        Ok(UnitStub { stub })
    }
}

impl UnitPort for UnitStub {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
        let body = serde_json::to_string(call).map_err(|_| failed("call encode failed"))?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_body(Some(JsValue::from_str(&body)));
        let req = Request::new_with_init("https://unit/", &init)
            .map_err(|_| failed("request refused"))?;
        let mut resp = self
            .stub
            .fetch_with_request(req)
            .await
            .map_err(|_| failed("call failed"))?;
        // The object answers every call with 200 and a `UnitAnswer`; any
        // other status is a body it could not read or a method it refuses.
        if resp.status_code() != 200 {
            return Err(failed("call refused"));
        }
        let raw = resp.text().await.map_err(|_| failed("answer unreadable"))?;
        decode_answer(&raw)
    }
}

/// The object answers a [`UnitReply`]: the answer, flattened, with the
/// lease's `lease_left_ms` and `revoked` beside it (#225). `UnitAnswer`
/// refuses unknown fields, so it is read through the reply.
fn decode_answer(raw: &str) -> Result<UnitAnswer> {
    serde_json::from_str::<UnitReply>(raw)
        .map(|reply| reply.answer)
        .map_err(|_| failed("answer unreadable"))
}

/// A class-only error: no call, answer or name in it.
fn failed(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: {what}"))
}

/// The bridge of the unit that `tenant` names, for one job (see the
/// [module](self)). `tenant` is what the reader admitted: a managed
/// tenant with a unit. Class-only reasons.
pub fn unit_bridge(
    env: &Env,
    base: &WorkerBridge,
    tenant: &JobTenant,
) -> std::result::Result<UnitBridge, String> {
    let unit = tenant.unit().ok_or("no unit")?;
    let id = TenantId::parse(tenant.tenant()).ok_or("not a unit's tenant")?;
    let name = UnitName::new(id, unit);
    let cfg = base
        .cfg
        .for_unit(&name)
        .map_err(|e| format!("unit config refused: {e}"))?;
    let namespace = env
        .durable_object(UNIT_BINDING)
        .map_err(|_| format!("missing binding {UNIT_BINDING}"))?;
    let port = UnitStub::new(&namespace, &name).map_err(|_| "no unit object".to_string())?;
    let sends = JobTenant::of_unit(tenant.tenant(), unit, tenant.state_seq(), tenant.keys_seq())
        .ok_or("not a unit's tenant")?;
    let (shared, safety, cache, jobs) = crate::env::unit_parts(env, base, sends)?;
    let seqs = Seqs {
        state_seq: tenant.state_seq(),
        keys_seq: tenant.keys_seq(),
    };
    Ok(Bridge {
        catalog: TenantCatalog::new(port, shared, name, seqs),
        safety,
        cache,
        nntp: WorkerConnector::new(),
        jobs,
        kek: base.kek.clone(),
        clock: WorkerClock,
        budget: base.budget.shared(),
        cfg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// What the object sends (a `UnitReply`) is what the stub reads; the
    /// bare answer type alone refuses it.
    #[test]
    fn the_stub_reads_the_objects_reply() {
        let seqs = Seqs {
            state_seq: 3,
            keys_seq: 2,
        };
        for (answer, revoked) in [
            (
                UnitAnswer::Ok {
                    seqs,
                    body: json!({ "n": 1 }),
                },
                Some(4),
            ),
            (UnitAnswer::SyncNeeded { seqs }, None),
            (UnitAnswer::RenewNeeded { seqs, why: None }, Some(0)),
        ] {
            let raw = serde_json::to_string(&UnitReply {
                answer: answer.clone(),
                lease_left_ms: 1_234,
                revoked,
            })
            .unwrap();
            assert!(serde_json::from_str::<UnitAnswer>(&raw).is_err(), "{raw}");
            assert_eq!(decode_answer(&raw).unwrap(), answer, "{raw}");
        }
        assert!(decode_answer("{}").is_err());
    }
}
