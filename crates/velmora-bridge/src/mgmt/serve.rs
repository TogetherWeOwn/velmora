//! One management request, from its method, path and token to its answer.
//!
//! The entrypoint hands every request it receives to [`serve`], which runs
//! the [gate](crate::mgmt::gate) and then the call's handler. The answer is
//! a status, a fixed code, an optional `Retry-After` and a JSON body
//! `{"code": "<code>"}`: nothing of the request, the token or a store's
//! own text is ever in it.
//!
//! **No handler is built yet.** Each one waits for the store it works on:
//! the tenant chain (W1), the tenant's units (W2) and the key chain's
//! callers (W5). Until its handler lands, a call that passed the gate
//! answers `503 service_unavailable` with `Retry-After`
//! ([`NOT_BUILT_RETRY_AFTER_SECS`]), the answer `kofra-api` already gives
//! for a storage write while its adapter is a stub. A caller therefore
//! sees "try again later", and nothing pretends to be stored or read.

use std::cell::RefCell;

use crate::mgmt::gate::{admit, Admitted, Shut};
use crate::mgmt::token::{DisabledTokens, TokenHashes};
use crate::ports::BlobStore;
use crate::types::UnixMs;

/// Seconds a call whose handler is not built asks the caller to wait.
pub const NOT_BUILT_RETRY_AFTER_SECS: u32 = 3600;

/// The answer to one management request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    /// A fixed code: the body says it, and so may the log.
    pub code: &'static str,
    /// `Retry-After`, in seconds, where the answer has one.
    pub retry_after: Option<u32>,
}

impl Answer {
    fn shut(shut: Shut) -> Answer {
        Answer {
            status: shut.status(),
            code: shut.code(),
            retry_after: shut.retry_after(),
        }
    }

    /// The body: `{"code":"<code>"}`. Codes are fixed lowercase words,
    /// so the text needs no escaping (a test holds every code to that).
    pub fn body(&self) -> String {
        format!("{{\"code\":\"{}\"}}", self.code)
    }
}

/// What a call's handler answers today: every call waits for its store.
fn handle(_admitted: &Admitted) -> Answer {
    Answer {
        status: 503,
        code: "service_unavailable",
        retry_after: Some(NOT_BUILT_RETRY_AFTER_SECS),
    }
}

/// Serves one management request. The arguments are those of
/// [`admit`]; `path` is the decoded path without its query.
pub async fn serve<B: BlobStore>(
    disabled: &RefCell<DisabledTokens>,
    hashes: &TokenHashes,
    records: &B,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    now: UnixMs,
) -> Answer {
    match admit(disabled, hashes, records, method, path, authorization, now).await {
        Ok(admitted) => handle(&admitted),
        Err(shut) => Answer::shut(shut),
    }
}
