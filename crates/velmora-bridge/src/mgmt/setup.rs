//! The two managed-plane setup routes on today's operator path (AM-70b):
//! the first key-location record (AM-70) and the directory gate's first
//! open (AM-78).
//!
//! Each is a `POST` with no body and no query, under `/_admin` of the
//! default handler, opened by `ADMIN_TOKEN` only (never by
//! `ADMIN_READ_TOKEN`, which opens only `GET`s of its read routes; this
//! module checks the admin request again itself). Both move to the
//! operator entrypoint with the rest of `/_admin`. No new token or grant.
//!
//! **Who calls them.** The coordinator, once per environment from the
//! host: the key-location call after the deploy that binds `KEYS_A` and
//! `KEYS_B` (W5-lite), the gate call after the `DIRECTORY` deploy (W1a) and
//! after the key-location call. The drill runner, once per drill
//! environment, before its first tenant. **CI never calls them**, and no
//! request path writes `m/kl/` or runs a gate.
//!
//! - [`KEY_LOCATIONS_PATH`]: `keys::locations::init_locations`. It writes
//!   only [`two_in_account`](crate::keys::locations::two_in_account), and
//!   only into an empty chain. `200` with `{"key_locations": "written"}`
//!   for the call that wrote seq 1, `{"key_locations": "present"}` when a
//!   head already lists `KEYS_A` as the active synchronous arbiter and
//!   `KEYS_B` as active and synchronous; `409 locations_differ` (a page)
//!   for any other head. A head that does not open answers `503` with
//!   nothing written: a page for damage, none for a KEK version this
//!   Worker does not hold yet. A Worker that does not have both key
//!   bucket bindings answers `503 key_buckets_unbound` and writes nothing:
//!   the record is put once and names the bindings, so it is written only
//!   by a deploy that has them.
//! - [`GATE_FIRST_OPEN_PATH`]: `directory::first_open::first_open`, whose
//!   guard runs before any gate step: an open gate answers `200` with
//!   `{"gate": "open", "ran": false}` and runs nothing (a repeat never
//!   closes an open gate, and never empties `pending_ops`); a tenant chain
//!   of a managed tenant answers `409 gate_has_tenants` (a page) and runs
//!   nothing. Otherwise one gate run with `FirstOpen` steps: `200` with
//!   `{"gate": "open", "ran": true, "epoch": E}` when it opened, and
//!   `503 gate_not_opened` with the steps that are not done when it did
//!   not (a run that left the gate closed may be started again). With
//!   `DIRECTORY` unbound the gate counts as closed: `503
//!   directory_unbound`, nothing run.
//!
//! Every answer carries fixed words and numbers only, never a store's
//! text.

use serde_json::{json, Value};
use velmora::rng::FillRandom;

use crate::directory::first_open::{first_open, FirstOpenAnswer};
use crate::directory::gate::is_open;
use crate::ingress::{self, check_admin};
use crate::keys::locations::{init_locations, is_kek_not_held, two_in_account, InitLocations};
use crate::ports::Clock;
use crate::root::{Root, RootPorts};
use crate::types::{Body, BridgeError, Method, RespBody, S3Request, S3Response};
use crate::BridgeConfig;

/// The first key-location record (AM-70).
pub const KEY_LOCATIONS_PATH: &str = "/_admin/setup/key-locations";
/// The directory gate's first open (AM-78).
pub const GATE_FIRST_OPEN_PATH: &str = "/_admin/setup/directory-gate";

/// One of the two setup calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupCall {
    KeyLocations,
    GateFirstOpen,
}

/// The setup call a request target names, whatever its method or query
/// (both are checked by [`serve_setup`]); `None` for every other target,
/// which goes on to the admin handler unchanged.
pub fn setup_call(raw_target: &str) -> Option<SetupCall> {
    let path = raw_target.split_once('?').map_or(raw_target, |(p, _)| p);
    match path {
        KEY_LOCATIONS_PATH => Some(SetupCall::KeyLocations),
        GATE_FIRST_OPEN_PATH => Some(SetupCall::GateFirstOpen),
        _ => None,
    }
}

fn json_response(status: u16, value: &Value) -> S3Response {
    let mut resp = S3Response {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: RespBody::Bytes(value.to_string().into_bytes()),
    };
    ingress::no_store(&mut resp);
    resp
}

/// `code` and `message` are static text: never request or store data.
fn fail(status: u16, code: &'static str, message: &'static str) -> S3Response {
    json_response(status, &json!({ "error": code, "message": message }))
}

fn unavailable() -> S3Response {
    fail(503, "SlowDown", "Not available now; retry shortly.")
}

/// Whether the request carries a body: a declared length above 0, or a
/// stream. A setup call takes none.
fn has_body(req: &S3Request) -> bool {
    match &req.body {
        Body::Empty => false,
        Body::Stream { declared_len, .. } => *declared_len != Some(0),
    }
}

/// Serves one setup call: the admin check again (host, then `ADMIN_TOKEN`;
/// the read token opens no `POST`), then `POST` with no query and no body,
/// then the call. `ports` are the root's (its key bucket bindings); `rng`
/// seals the key-location record.
pub async fn serve_setup<P, R, G>(
    call: SetupCall,
    req: &S3Request,
    cfg: &BridgeConfig,
    ports: &P,
    root: &Root<'_, P, R>,
    rng: &mut G,
) -> S3Response
where
    P: RootPorts,
    R: FillRandom,
    G: FillRandom,
{
    if let Err(e) = check_admin(req, cfg) {
        let mut resp = e.response();
        ingress::no_store(&mut resp);
        return resp;
    }
    if req.method != Method::Post {
        return fail(405, "MethodNotAllowed", "This route takes POST only.");
    }
    if req.raw_target.contains('?') || has_body(req) {
        return fail(400, "BadRequest", "This route takes no query and no body.");
    }
    match call {
        SetupCall::KeyLocations => key_locations(ports, root, rng).await,
        SetupCall::GateFirstOpen => gate_first_open(root).await,
    }
}

async fn key_locations<P, R, G>(ports: &P, root: &Root<'_, P, R>, rng: &mut G) -> S3Response
where
    P: RootPorts,
    R: FillRandom,
    G: FillRandom,
{
    let bound = ports.key_buckets();
    let all_bound = two_in_account()
        .locations
        .iter()
        .all(|l| bound.by_name.iter().any(|(name, _)| *name == l.name));
    if !all_bound {
        return fail(
            503,
            "key_buckets_unbound",
            "This deployment does not bind both key buckets; nothing was written.",
        );
    }
    match init_locations(root.records(), root.kek(), rng).await {
        Ok(InitLocations::Written) => json_response(200, &json!({ "key_locations": "written" })),
        Ok(InitLocations::Same) => json_response(200, &json!({ "key_locations": "present" })),
        Ok(InitLocations::Differ) => {
            crate::trace::alert(|| {
                "setup: the key-location head names another set; nothing written".to_string()
            });
            fail(
                409,
                "locations_differ",
                "The key-location head names another set; nothing was written.",
            )
        }
        // A record of a newer deploy during a KEK rollout: may pass.
        Err(e) if is_kek_not_held(&e) => unavailable(),
        // A store that did not answer: nothing is known to be wrong.
        Err(BridgeError::Blob(_)) => unavailable(),
        Err(_) => {
            crate::trace::alert(|| {
                "setup: the key-location head does not open; nothing written".to_string()
            });
            unavailable()
        }
    }
}

async fn gate_first_open<P, R>(root: &Root<'_, P, R>) -> S3Response
where
    P: RootPorts,
    R: FillRandom,
{
    let Some(dir) = root.directory() else {
        return fail(
            503,
            "directory_unbound",
            "No directory is bound; the gate counts as closed.",
        );
    };
    // The route's own guard (AM-78, §R7-13 N1): an open gate answers
    // `200` and runs nothing, so a repeat never closes it or empties
    // `pending_ops`; a read that fails runs nothing either. `first_open`
    // checks the gate and the managed tenant chains again before its run.
    match is_open(root.records(), &dir).await {
        Ok(true) => return json_response(200, &json!({ "gate": "open", "ran": false })),
        Ok(false) => {}
        Err(_) => return unavailable(),
    }
    let now = root.clock().now();
    let chain = root.chain();
    match first_open(&chain, &dir, root.kek(), now).await {
        Ok(FirstOpenAnswer::AlreadyOpen) => {
            json_response(200, &json!({ "gate": "open", "ran": false }))
        }
        Ok(FirstOpenAnswer::HasTenants) => {
            crate::trace::alert(|| {
                "setup: first open refused: a managed tenant chain exists".to_string()
            });
            fail(
                409,
                "gate_has_tenants",
                "A managed tenant chain exists; nothing was run.",
            )
        }
        Ok(FirstOpenAnswer::Ran(run)) if run.opened => json_response(
            200,
            &json!({ "gate": "open", "ran": true, "epoch": run.epoch }),
        ),
        Ok(FirstOpenAnswer::Ran(run)) => {
            // The step names and their problem codes are fixed words.
            let not_done: Vec<Value> = run
                .steps
                .iter()
                .filter(|(_, s)| !s.done)
                .map(|(name, s)| json!({ "step": name, "problems": s.problems }))
                .collect();
            json_response(
                503,
                &json!({
                    "error": "gate_not_opened",
                    "message": "The run left the gate closed; it may be started again.",
                    "epoch": run.epoch,
                    "closed_over": run.closed_over,
                    "not_done": not_done,
                }),
            )
        }
        Err(_) => unavailable(),
    }
}
