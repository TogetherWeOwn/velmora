//! The management plane's side of `fetch`: a request that came in by the
//! named entrypoint `MgmtEntry` (`entry.mjs`) is answered here and never
//! reaches the S3 handler (`velmora_bridge::mgmt`).

use std::cell::RefCell;
use std::rc::Rc;

use velmora_bridge::entry::{names_mgmt, ENTRY_HEADER};
use velmora_bridge::mgmt::adapters::{HeadDoor, NoBucketNames};
use velmora_bridge::mgmt::serve::{serve_request, Answer, Either, NotBuilt, MISCONFIGURED};
use velmora_bridge::mgmt::tenant::TenantReadHandler;
use velmora_bridge::mgmt::token::{DisabledTokens, TokenHashes};
use velmora_bridge::S3Request;
use worker::{console_error, Env, Headers, Response, Result};

use crate::env::WorkerBridge;

thread_local! {
    /// The disabled tokens this isolate knows of (`m/rst/`).
    static DISABLED: Rc<RefCell<DisabledTokens>> = Rc::new(RefCell::new(DisabledTokens::default()));
}

/// Whether the request's entry marker names the management entry point,
/// read before anything else of the request.
pub fn marked(headers: &Headers) -> bool {
    headers
        .get(ENTRY_HEADER)
        .ok()
        .flatten()
        .is_some_and(|value| names_mgmt(&value))
}

/// The answer to a management request. Served: the tenant read, from the
/// tenant's verified head (the composition root's door reader over
/// `SAFETY` and the KEK ring). Every other call answers `503` until its
/// ports are in this Worker ([`NotBuilt`]): principal create needs the
/// unit client behind the router and the key writer's stores.
pub async fn answer(env: &Env, bridge: &WorkerBridge, method: &str, req: S3Request) -> Answer {
    // Read per request: two secrets, no I/O. A value that does not parse
    // shuts the plane; the log names the variable, never a value.
    let hashes = match TokenHashes::from_vars(|name| crate::env::lookup(env, name)) {
        Ok(hashes) => hashes,
        Err(class) => {
            console_error!("mgmt config refused: {class}");
            return MISCONFIGURED;
        }
    };
    let disabled = DISABLED.with(Rc::clone);
    let now = velmora_bridge::ports::Clock::now(&bridge.clock);
    let ports = match crate::root::WorkerPorts::from_env(env, &bridge.kek) {
        Ok(ports) => ports,
        Err(reason) => {
            // Only SAFETY is required, and the reason names the binding.
            console_error!("mgmt root refused: {reason}");
            return serve_request(
                &disabled,
                &hashes,
                &bridge.safety,
                &NotBuilt,
                method,
                req,
                now,
            )
            .await;
        }
    };
    let cache = crate::root::cache();
    let root = velmora_bridge::root::Root::new(&ports, &cache, velmora::rng::SystemRng);
    let heads = root.heads();
    let door = HeadDoor {
        heads: &heads,
        names: &NoBucketNames,
    };
    let handlers = Either(TenantReadHandler { heads: &door }, NotBuilt);
    serve_request(
        &disabled,
        &hashes,
        &bridge.safety,
        &handlers,
        method,
        req,
        now,
    )
    .await
}

/// The answer as a response: JSON, never stored by a cache.
pub fn response(answer: Answer, request_id: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "no-store")?;
    headers.set("x-request-id", request_id)?;
    if let Some(secs) = answer.retry_after {
        headers.set("retry-after", &secs.to_string())?;
    }
    if answer.status == 401 {
        headers.set("www-authenticate", "Bearer")?;
    }
    Ok(Response::ok(answer.body())?
        .with_status(answer.status)
        .with_headers(headers))
}
