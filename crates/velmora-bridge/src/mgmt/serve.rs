//! One management request, from its method, path and token to its answer.
//!
//! The entrypoint hands every request it receives to [`serve`], which runs
//! the [gate](crate::mgmt::gate), then the [checks](crate::mgmt::request)
//! of the acting header, the `Idempotency-Key` and the query, and then
//! the call's handler. The answer is
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

use velmora_mgmt_types::headers::{ACTING_OWNER_REF, IDEMPOTENCY_KEY};
use velmora_mgmt_types::Code;

use crate::mgmt::gate::{admit, Admitted, Shut};
use crate::mgmt::request::{check, Checked};
use crate::mgmt::token::{DisabledTokens, TokenHashes};
use crate::ports::BlobStore;
use crate::types::{S3Request, UnixMs};

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

    /// The answer of a contract code with no `Retry-After`: a refusal of
    /// the request itself.
    pub fn refused(code: Code) -> Answer {
        Answer {
            status: code.status(),
            code: code.as_str(),
            retry_after: None,
        }
    }

    /// The body: `{"code":"<code>"}`. Codes are fixed lowercase words,
    /// so the text needs no escaping (a test holds every code to that).
    pub fn body(&self) -> String {
        format!("{{\"code\":\"{}\"}}", self.code)
    }
}

/// One management request, as [`serve`] takes it.
#[derive(Clone, Copy, Debug)]
pub struct MgmtRequest<'a> {
    pub method: &'a str,
    /// The decoded path, without its query.
    pub path: &'a str,
    /// The query, without its `?` (empty without one).
    pub query: &'a str,
    pub authorization: Option<&'a str>,
    /// `Kofra-Acting-Owner-Ref`.
    pub acting: Option<&'a str>,
    /// `Idempotency-Key`.
    pub idempotency_key: Option<&'a str>,
}

/// What a call's handler answers today: every call waits for its store.
fn handle(_admitted: &Admitted, _checked: &Checked) -> Answer {
    Answer {
        status: 503,
        code: "service_unavailable",
        retry_after: Some(NOT_BUILT_RETRY_AFTER_SECS),
    }
}

/// Serves one management request: the gate (route, disable list, token,
/// least scope), then the request's checks, then the handler. The
/// arguments but `req` are those of [`admit`].
pub async fn serve<B: BlobStore>(
    disabled: &RefCell<DisabledTokens>,
    hashes: &TokenHashes,
    records: &B,
    req: MgmtRequest<'_>,
    now: UnixMs,
) -> Answer {
    let admitted = match admit(
        disabled,
        hashes,
        records,
        req.method,
        req.path,
        req.authorization,
        now,
    )
    .await
    {
        Ok(admitted) => admitted,
        Err(shut) => return Answer::shut(shut),
    };
    match check(&admitted.call, req.query, req.acting, req.idempotency_key) {
        Ok(checked) => handle(&admitted, &checked),
        Err(code) => Answer::refused(code),
    }
}

/// Serves a request that came in by the management entry point
/// ([`crate::entry::Entry::Mgmt`]). The path is the request target up to
/// its query, as received: the paths of this plane hold no character that
/// needs decoding, so an encoded one is no path and answers `404`. The
/// body is not read: no call reads one yet.
pub async fn serve_request<B: BlobStore>(
    disabled: &RefCell<DisabledTokens>,
    hashes: &TokenHashes,
    records: &B,
    method: &str,
    req: &S3Request,
    now: UnixMs,
) -> Answer {
    let (path, query) = req
        .raw_target
        .split_once('?')
        .unwrap_or((req.raw_target.as_str(), ""));
    let header = |name: &str| req.header(&name.to_ascii_lowercase());
    let request = MgmtRequest {
        method,
        path,
        query,
        authorization: req.header("authorization"),
        acting: header(ACTING_OWNER_REF),
        idempotency_key: header(IDEMPOTENCY_KEY),
    };
    serve(disabled, hashes, records, request, now).await
}

/// The answer when the token hashes cannot be read from the Worker's
/// configuration: no token can be checked, so nothing is served.
pub const MISCONFIGURED: Answer = Answer {
    status: 503,
    code: "service_unavailable",
    retry_after: Some(crate::mgmt::gate::RETRY_AFTER_SECS),
};

/// The answer to a request that came by the management entry point but
/// is not one this plane serves: a request target that is not origin
/// form, or headers that say the edge (only the caller can have added
/// them). Never handed to the S3 handler.
pub const BAD_REQUEST: Answer = Answer {
    status: 400,
    code: "bad_request",
    retry_after: None,
};
