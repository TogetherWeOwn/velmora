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
//! **Handlers come with their stores.** [`serve_with`] takes the
//! [`Handlers`] of the deployment. A call whose handler is not among them
//! answers `503 service_unavailable` with `Retry-After`
//! ([`NOT_BUILT_RETRY_AFTER_SECS`]), the answer `kofra-api` already gives
//! for a storage write while its adapter is a stub. A caller therefore
//! sees "try again later", and nothing pretends to be stored or read. The
//! Worker passes [`NotBuilt`] until the ports of the stores are wired
//! (L6's `UnitRouter`, L2's unit client, L4's writer); principal create
//! is built over them ([`crate::mgmt::principal`]).
//!
//! **The body is read only after the gate and the checks**, and only for
//! a call whose handler is built: at most
//! [`velmora_mgmt_types::wire::MAX_REQUEST_BYTES`]; a longer body, or one
//! whose stream fails, answers `400 bad_request`.

use std::cell::RefCell;

use futures_util::StreamExt;
use velmora_mgmt_types::headers::{ACTING_OWNER_REF, IDEMPOTENCY_KEY};
use velmora_mgmt_types::wire::MAX_REQUEST_BYTES;
use velmora_mgmt_types::Code;

use crate::mgmt::gate::{admit, Admitted, Shut};
use crate::mgmt::request::{check, Checked};
use crate::mgmt::route::Call;
use crate::mgmt::token::{DisabledTokens, TokenHashes};
use crate::ports::BlobStore;
use crate::types::{Body, S3Request, UnixMs};

/// Seconds a call whose handler is not built asks the caller to wait.
pub const NOT_BUILT_RETRY_AFTER_SECS: u32 = 3600;

/// The answer to one management request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    /// A fixed code: the body of an error says it, and so may the log.
    /// [`OK`] for an answer with a JSON body.
    pub code: &'static str,
    /// `Retry-After`, in seconds, where the answer has one.
    pub retry_after: Option<u32>,
    /// The JSON body of a `2xx` answer; `None` for an error.
    pub json: Option<String>,
}

/// The log code of an answer with a JSON body.
pub const OK: &str = "ok";

impl Answer {
    fn shut(shut: Shut) -> Answer {
        Answer {
            status: shut.status(),
            code: shut.code(),
            retry_after: shut.retry_after(),
            json: None,
        }
    }

    /// The answer of a contract code with no `Retry-After`: a refusal of
    /// the request itself.
    pub fn refused(code: Code) -> Answer {
        Answer::code(code, None)
    }

    /// The answer of a contract code. A code whose answer has a
    /// `Retry-After` always carries one, and no other code does.
    pub fn code(code: Code, retry_after: Option<u32>) -> Answer {
        let retry_after = match (code.retry_after(), retry_after) {
            (true, None) => Some(crate::mgmt::gate::RETRY_AFTER_SECS),
            (true, secs) => secs,
            (false, _) => None,
        };
        Answer {
            status: code.status(),
            code: code.as_str(),
            retry_after,
            json: None,
        }
    }

    /// A `2xx` answer with a JSON body. A status that is not `2xx`, or a
    /// body that is not UTF-8, is no answer of this plane: `500`.
    pub fn json(status: u16, body: Vec<u8>) -> Answer {
        match String::from_utf8(body) {
            Ok(json) if (200..300).contains(&status) => Answer {
                status,
                code: OK,
                retry_after: None,
                json: Some(json),
            },
            _ => Answer::code(Code::InternalError, None),
        }
    }

    /// The body: the JSON of a `2xx` answer, else `{"code":"<code>"}`.
    /// Codes are fixed lowercase words, so the text needs no escaping (a
    /// test holds every code to that).
    pub fn body(&self) -> String {
        match &self.json {
            Some(json) => json.clone(),
            None => format!("{{\"code\":\"{}\"}}", self.code),
        }
    }
}

/// One management request, as [`serve`] takes it. Its `Debug` shows
/// whether each header came, never its value: `authorization` holds the
/// service token.
#[derive(Clone, Copy)]
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

impl std::fmt::Debug for MgmtRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let present = |v: Option<&str>| if v.is_some() { "<present>" } else { "<absent>" };
        f.debug_struct("MgmtRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("authorization", &present(self.authorization))
            .field("acting", &present(self.acting))
            .field("idempotency_key", &present(self.idempotency_key))
            .finish()
    }
}

/// The answer of a call whose handler this deployment does not have.
pub fn not_built() -> Answer {
    Answer {
        status: 503,
        code: "service_unavailable",
        retry_after: Some(NOT_BUILT_RETRY_AFTER_SECS),
        json: None,
    }
}

/// What a call's handler reads besides its body.
#[derive(Clone, Copy, Debug)]
pub struct CallContext<'a> {
    pub admitted: &'a Admitted,
    pub checked: &'a Checked,
    pub method: &'a str,
    /// The path, without its query.
    pub path: &'a str,
    /// The query, without its `?` (empty without one).
    pub query: &'a str,
    pub now: UnixMs,
}

impl CallContext<'_> {
    /// The path with its query, as the fingerprint takes it.
    pub fn path_and_query(&self) -> String {
        match self.query.is_empty() {
            true => self.path.to_string(),
            false => format!("{}?{}", self.path, self.query),
        }
    }
}

/// The handlers of a deployment.
#[allow(async_fn_in_trait)]
pub trait Handlers {
    /// Whether `call` has a handler here. Only then is the body read.
    fn serves(&self, call: &Call) -> bool;
    /// Runs the handler of a call it [`serves`](Handlers::serves).
    async fn handle(&self, ctx: CallContext<'_>, body: &[u8]) -> Answer;
}

/// Two sets of handlers as one: a call goes to the first that serves it.
#[derive(Clone, Copy, Debug)]
pub struct Either<A, B>(pub A, pub B);

impl<A: Handlers, B: Handlers> Handlers for Either<A, B> {
    fn serves(&self, call: &Call) -> bool {
        self.0.serves(call) || self.1.serves(call)
    }

    async fn handle(&self, ctx: CallContext<'_>, body: &[u8]) -> Answer {
        match self.0.serves(&ctx.admitted.call) {
            true => self.0.handle(ctx, body).await,
            false => self.1.handle(ctx, body).await,
        }
    }
}

/// No handler: every call that passed the gate waits for its store.
#[derive(Clone, Copy, Debug, Default)]
pub struct NotBuilt;

impl Handlers for NotBuilt {
    fn serves(&self, _call: &Call) -> bool {
        false
    }

    async fn handle(&self, _ctx: CallContext<'_>, _body: &[u8]) -> Answer {
        not_built()
    }
}

/// Reads a request body of at most [`MAX_REQUEST_BYTES`]. `None`: longer,
/// or its stream failed.
async fn read_body(body: Body) -> Option<Vec<u8>> {
    match body {
        Body::Empty => Some(Vec::new()),
        Body::Stream {
            declared_len,
            mut stream,
        } => {
            if declared_len.is_some_and(|n| n > MAX_REQUEST_BYTES as u64) {
                return None;
            }
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.ok()?;
                if chunk.len() > MAX_REQUEST_BYTES - out.len() {
                    return None;
                }
                out.extend_from_slice(&chunk);
            }
            Some(out)
        }
    }
}

/// Serves one management request with no handler and no body: the gate
/// and the checks, then `503` for every call that passes them
/// ([`NotBuilt`]).
pub async fn serve<B: BlobStore>(
    disabled: &RefCell<DisabledTokens>,
    hashes: &TokenHashes,
    records: &B,
    req: MgmtRequest<'_>,
    now: UnixMs,
) -> Answer {
    serve_with(disabled, hashes, records, &NotBuilt, req, Body::Empty, now).await
}

/// Serves one management request: the gate (route, disable list, token,
/// least scope), then the request's checks, then the body and the call's
/// handler. The arguments but `handlers`, `req` and `body` are those of
/// [`admit`].
pub async fn serve_with<B: BlobStore, H: Handlers>(
    disabled: &RefCell<DisabledTokens>,
    hashes: &TokenHashes,
    records: &B,
    handlers: &H,
    req: MgmtRequest<'_>,
    body: Body,
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
    let checked = match check(&admitted.call, req.query, req.acting, req.idempotency_key) {
        Ok(checked) => checked,
        Err(code) => return Answer::refused(code),
    };
    if !handlers.serves(&admitted.call) {
        return not_built();
    }
    let Some(body) = read_body(body).await else {
        return Answer::refused(Code::BadRequest);
    };
    let ctx = CallContext {
        admitted: &admitted,
        checked: &checked,
        method: req.method,
        path: req.path,
        query: req.query,
        now,
    };
    handlers.handle(ctx, &body).await
}

/// Serves a request that came in by the management entry point
/// ([`crate::entry::Entry::Mgmt`]). The path is the request target up to
/// its query, as received: the paths of this plane hold no character that
/// needs decoding, so an encoded one is no path and answers `404`. The
/// body is read only for a call that `handlers` serve.
pub async fn serve_request<B: BlobStore, H: Handlers>(
    disabled: &RefCell<DisabledTokens>,
    hashes: &TokenHashes,
    records: &B,
    handlers: &H,
    method: &str,
    req: S3Request,
    now: UnixMs,
) -> Answer {
    let S3Request {
        raw_target,
        headers,
        body,
        ..
    } = req;
    let (path, query) = raw_target
        .split_once('?')
        .unwrap_or((raw_target.as_str(), ""));
    // The first header of that (lowercase) name, as `S3Request::header`.
    let header = |name: &str| {
        let name = name.to_ascii_lowercase();
        headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    };
    let request = MgmtRequest {
        method,
        path,
        query,
        authorization: header("authorization"),
        acting: header(ACTING_OWNER_REF),
        idempotency_key: header(IDEMPOTENCY_KEY),
    };
    serve_with(disabled, hashes, records, handlers, request, body, now).await
}

/// The answer when the token hashes cannot be read from the Worker's
/// configuration: no token can be checked, so nothing is served.
pub const MISCONFIGURED: Answer = Answer {
    status: 503,
    code: "service_unavailable",
    retry_after: Some(crate::mgmt::gate::RETRY_AFTER_SECS),
    json: None,
};

/// The answer to a request that came by the management entry point but
/// is not one this plane serves: a request target that is not origin
/// form, or headers that say the edge (only the caller can have added
/// them). Never handed to the S3 handler.
pub const BAD_REQUEST: Answer = Answer {
    status: 400,
    code: "bad_request",
    retry_after: None,
    json: None,
};
