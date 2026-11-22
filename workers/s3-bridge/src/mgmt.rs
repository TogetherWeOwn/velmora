//! The management plane's side of `fetch`: a request that came in by the
//! named entrypoint `MgmtEntry` (`entry.mjs`) is answered here and never
//! reaches the S3 handler (`velmora_bridge::mgmt`).

use std::cell::RefCell;
use std::rc::Rc;

use velmora_bridge::entry::{names_mgmt, ENTRY_HEADER};
use velmora_bridge::mgmt::serve::{serve_request, Answer, MISCONFIGURED};
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

/// The answer to a management request.
pub async fn answer(env: &Env, bridge: &WorkerBridge, method: &str, req: &S3Request) -> Answer {
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
    serve_request(&disabled, &hashes, &bridge.safety, method, req, now).await
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
