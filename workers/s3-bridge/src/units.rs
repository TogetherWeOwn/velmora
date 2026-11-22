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
//! (`velmora_bridge::unit_consumer::deliver`, the AM-50 table); a
//! follow-up job carries the numbers of the unit's latest answer. A unit
//! job (`renew`, `stamp_raise`) runs through the unit client
//! (`deliver_unit_job`).
//!
//! The unit client is L2's `UnitClient`, built by the composition root
//! (`Root::unit_client`, `listed = false` for job calls, AM-50) over the
//! isolate's renewal state, with the root's key feed and finisher. The
//! tenant heads (an `Unborn` is decided by the verified head) come from
//! the root's door reader (`crate::root`). Never acknowledged on a read
//! that was not made.

use std::cell::Cell;
use std::rc::Rc;

use velmora::rng::SystemRng;
use velmora_bridge::jobmsg::{JobTenant, Units};
use velmora_bridge::request_catalog::RequestCatalog;
use velmora_bridge::root::request::RequestPort;
use velmora_bridge::root::Root;
use velmora_bridge::service::managed;
use velmora_bridge::service::KeyDispatch;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::tenant_catalog::{LatestSeqs, TenantCatalog, UnitPort};
use velmora_bridge::types::JobOutcome;
use velmora_bridge::unit::request_client::RequestClient;
use velmora_bridge::unit::{Seqs, TenantId, UnitAnswer, UnitCall, UnitName, UnitReply};
use velmora_bridge::unit_consumer::{Ran, UnitRun};
use velmora_bridge::unit_lease::client::UnitReplies;
use velmora_bridge::unit_router::KeyRoutes;
use velmora_bridge::{Bridge, BridgeError, Result};
use worker::wasm_bindgen::JsValue;
use worker::{Env, Method, ObjectNamespace, Request, RequestInit, Stub};

use crate::d1::D1Sql;
use crate::env::{WorkerBridge, WorkerClock};
use crate::nntp::WorkerConnector;
use crate::queues::QueueSink;
use crate::r2::R2Blobs;
use crate::root::WorkerPorts;
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
    pub(crate) fn new(namespace: &ObjectNamespace, name: &UnitName) -> Result<UnitStub> {
        let stub = namespace
            .id_from_name(&name.object_name())
            .and_then(|id| id.get_stub())
            .map_err(|_| failed("no object"))?;
        Ok(UnitStub { stub })
    }
}

impl UnitStub {
    /// One `POST` of `call` as JSON; the object's answer as text.
    async fn send(&self, call: &UnitCall) -> Result<String> {
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
        // The object answers every call with 200 and a `UnitReply`; any
        // other status is a body it could not read or a method it refuses.
        if resp.status_code() != 200 {
            return Err(failed("call refused"));
        }
        resp.text().await.map_err(|_| failed("answer unreadable"))
    }
}

impl UnitPort for UnitStub {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
        decode_answer(&self.send(call).await?)
    }
}

/// The unit client's port (`unit_lease::client`): the whole reply, with
/// the lease's `lease_left_ms` and `revoked`.
impl UnitReplies for UnitStub {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply> {
        let raw = self.send(call).await?;
        serde_json::from_str(&raw).map_err(|_| failed("answer unreadable"))
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
    let latest = LatestSeqs::new(seqs);
    let jobs = jobs.with_latest(latest.clone());
    Ok(Bridge {
        catalog: TenantCatalog::with_latest(port, shared, name, seqs, latest),
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

/// One run of a job on its unit's bridge, in the isolate's job table as
/// every job (`crate::jobs::run`).
pub struct OnUnit<'a> {
    pub bridge: std::rc::Rc<UnitBridge>,
    /// When the delivery's first run began: every run of the delivery is
    /// timed from it, so that all of them share one `JOB_WAIT_MS` and the
    /// table gives a late run up inside the invocation.
    pub started: velmora_bridge::UnixMs,
    pub scope: &'a velmora_bridge::TenantScope,
    pub job: &'a velmora_bridge::Job,
}

impl UnitRun for OnUnit<'_> {
    async fn run(&self, seqs: Seqs) -> Ran {
        self.bridge.catalog.run_again_with(seqs);
        let now = self.started;
        // Set when the job itself ended: the table can also answer a
        // retry of its own for a job it gave up.
        let ended = std::rc::Rc::new(std::cell::Cell::new(false));
        let (u, j, scope, done) = (
            std::rc::Rc::clone(&self.bridge),
            self.job.clone(),
            self.scope.clone(),
            std::rc::Rc::clone(&ended),
        );
        let outcome = match crate::jobs::run(now, crate::is_post(self.job), async move {
            let outcome = u.run_job(&scope, &j).await;
            done.set(true);
            outcome
        })
        .await
        {
            Some(outcome) => outcome,
            // `jobs::run` has logged it.
            None => JobOutcome::Retry {
                delay_secs: velmora_bridge::jobs::INFRA_RETRY_SECS,
            },
        };
        crate::log_post_trace(self.job, &outcome);
        Ran {
            outcome,
            refusal: self.bridge.catalog.refusal(),
            finished: ended.get(),
        }
    }

    async fn prepare(&self, seqs: Seqs) -> bool {
        self.bridge.catalog.run_again_with(seqs);
        let now = velmora_bridge::ports::Clock::now(&self.bridge.clock);
        let given = self.bridge.catalog.give_back(now).await.is_ok();
        // The run once more starts with no refusal of its own.
        self.bridge.catalog.run_again_with(seqs);
        given
    }
}

// ---------------------------------------------------------------------------
// The request router (design round 5, AM-51) and the request path on a
// unit (L6-6, AM-64)
// ---------------------------------------------------------------------------

/// The bridge of one managed tenant's S3 request: tenant 0's handlers
/// over the request catalogue, whose request calls go to the tenant's
/// unit through the root's router and unit client.
pub type RequestBridge = Bridge<
    RequestCatalog<RequestPort<WorkerPorts, SystemRng>, SqlCatalog<D1Sql>>,
    R2Blobs,
    WorkerConnector,
    QueueSink,
    KekRing,
    WorkerClock,
>;

/// What became of a request at the router.
pub enum Routed {
    /// Tenant 0's path, unchanged: the request back.
    TenantZero(velmora_bridge::S3Request),
    /// Answered at once (DUR-10, the host, a refused route or `key_row`).
    Answered(velmora_bridge::S3Response),
    /// A managed tenant's request on its unit: serve it detached
    /// ([`serve_on_unit`]).
    OnUnit(Rc<RequestBridge>, velmora_bridge::S3Request),
}

/// A request whose claimed access key routes to a managed tenant goes to
/// the tenant's unit (`velmora_bridge::service::managed`). Tenant 0's
/// path is unchanged for every request of a Worker without `UNIT` bound
/// (no route read at all), every request that claims no key or a key of
/// tenant 0 (the directory names no route for it), and, after a failed
/// directory read, a key tenant 0's catalogue holds. Any other key after a
/// failed directory read answers `503` (ADR §8.4, DUR-10:
/// `service::serve_unrouted`). `skip`: an admin route or a verified
/// fan-out piece, which never take a key route.
///
/// The key routes, the tenant heads and their cache, and the unit clients
/// come from the composition root (`velmora_bridge::root`, `crate::root`;
/// AM-71: one renewal state per isolate, `UnitClient::call` the only
/// retry layer).
pub async fn route_request(
    env: &Env,
    base: &Rc<WorkerBridge>,
    units: Units,
    skip: bool,
    req: velmora_bridge::S3Request,
) -> Routed {
    if units != Units::Bound || skip {
        return Routed::TenantZero(req);
    }
    // The host first (ADR §8.4 step 1), before any key route is read:
    // tenant 0's path gives the same refusal.
    if velmora_bridge::service::request_host_refused(&base.cfg, &req).is_some() {
        return Routed::TenantZero(req);
    }
    let Some(akid) = velmora_bridge::service::claimed_access_key(&base.cfg, &req) else {
        return Routed::TenantZero(req);
    };
    let ports = match WorkerPorts::from_env(env, base) {
        Ok(ports) => Rc::new(ports),
        Err(class) => {
            // The bridge was built from the same `SAFETY`: not reached.
            worker::console_error!("alert: unit request ({class})");
            return Routed::TenantZero(req);
        }
    };
    let cache = crate::root::cache();
    let root = Root::new(&*ports, &cache, SystemRng);
    let route = root.key_routes().tenant_of(&akid).await;
    let (tenant, floor) =
        match velmora_bridge::service::dispatch_key_route(route, &base.catalog, &akid).await {
            KeyDispatch::Managed { tenant, floor } => (tenant, floor),
            KeyDispatch::TenantZero => return Routed::TenantZero(req),
            // DUR-10: no route could be shown for the key.
            KeyDispatch::Answer(resp, line) => {
                log_request(line);
                return Routed::Answered(resp);
            }
        };
    let prepared = {
        let clients = root.clients();
        let heads = root.heads();
        let router = root.router(base.cfg.maintenance, &clients, &heads);
        managed::prepare(&router, &base.cfg, &tenant, floor, &akid, &req).await
    };
    let request = match prepared {
        managed::Prepared::Answer(resp, lines) => {
            lines.into_iter().for_each(log_request);
            return Routed::Answered(resp);
        }
        managed::Prepared::Serve(request) => request,
    };
    request.lines.iter().copied().for_each(log_request);
    match request_bridge(env, base, ports, cache, &akid, request) {
        Ok(bridge) => Routed::OnUnit(Rc::new(bridge), req),
        Err(class) => {
            worker::console_error!("alert: unit request not served ({class})");
            Routed::Answered(velmora_bridge::service::unit_unavailable())
        }
    }
}

/// The request bridge of a managed tenant's request: the unit's config
/// (`BridgeConfig::for_unit`, no fan-out: a fan-out piece is served on
/// tenant 0's path), its blob stores and a sink whose jobs name the unit,
/// and the request catalogue over the request port. Class-only reasons.
fn request_bridge(
    env: &Env,
    base: &Rc<WorkerBridge>,
    ports: Rc<WorkerPorts>,
    cache: Rc<velmora_bridge::root::RootCache>,
    akid: &str,
    request: managed::ManagedRequest,
) -> std::result::Result<RequestBridge, String> {
    // The unit the jobs and the config name: the bucket's, or the root
    // unit when the bucket's route was refused (every call then answers
    // that refusal).
    let unit = request.routed.as_ref().unwrap_or(&request.root).clone();
    let mut cfg = base
        .cfg
        .for_unit(&unit.unit)
        .map_err(|e| format!("unit config refused: {e}"))?;
    cfg.get_fanout_bytes = None;
    let sends = JobTenant::of_unit(
        unit.unit.tenant.as_str(),
        unit.unit.unit,
        unit.seqs.state_seq,
        unit.seqs.keys_seq,
    )
    .ok_or("not a unit's tenant")?;
    let (shared, safety, blobs, jobs) = crate::env::unit_parts(env, base, sends)?;
    let verified = Rc::new(Cell::new(false));
    let port = RequestPort::new(
        ports,
        cache,
        || SystemRng,
        base.cfg.maintenance,
        request.root.clone(),
        request.root_renew,
        request.routed,
        Rc::clone(&verified),
    );
    let client = RequestClient::new(port, unit.unit.clone(), unit.seqs);
    let catalog = RequestCatalog::new(
        client,
        shared,
        request.scope,
        akid,
        request.key_row,
        verified,
    );
    Ok(Bridge {
        catalog,
        safety,
        cache: blobs,
        nntp: WorkerConnector::new(),
        jobs,
        kek: base.kek.clone(),
        clock: WorkerClock,
        budget: base.budget.shared(),
        cfg,
    })
}

/// Serves a managed tenant's request on its bridge, then finishes it
/// (`service::managed::finish`: the refused publications' records
/// discarded, a unit's refusal as the answer). A background renewal the
/// unit asked for (rule 12) is the work left for after the response,
/// which the caller runs under `waitUntil` after a deferred body's work.
pub async fn serve_on_unit(
    bridge: Rc<RequestBridge>,
    req: velmora_bridge::S3Request,
) -> (velmora_bridge::S3Response, Option<crate::After>) {
    let resp = Rc::clone(&bridge).handle(req).await;
    let finished = managed::finish(bridge.catalog.client(), &bridge.safety, resp).await;
    finished.lines.into_iter().for_each(log_request);
    // Run after the response (and a deferred body's work): the renewal
    // a call asked for, also one asked for by the calls of the body's
    // work, which run after `finish` (their pages the port logs itself).
    let first = finished.renew;
    let after: crate::After = Box::pin(async move {
        let port = bridge.catalog.client().port();
        let mut due = managed::PortState::renew_due(port);
        for (unit, seqs) in first {
            if !due.iter().any(|(u, _)| u == &unit) {
                due.push((unit, seqs));
            }
        }
        let (ports, cache) = (Rc::clone(port.ports()), Rc::clone(port.cache()));
        for (unit, seqs) in due {
            let pages = velmora_bridge::root::request::renew_in_background(
                &*ports, &cache, SystemRng, &unit, seqs,
            )
            .await;
            for page in pages.iter().flatten() {
                worker::console_error!(
                    "alert: unit request ({})",
                    velmora_bridge::unit_consumer::page_code(page)
                );
            }
        }
    });
    (finished.resp, Some(after))
}

fn log_request(line: velmora_bridge::service::ManagedLine) {
    match line.alert {
        true => worker::console_error!("alert: unit request ({})", line.code),
        false => worker::console_log!("unit request ({})", line.code),
    }
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
