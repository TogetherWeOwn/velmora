//! Outbound HTTPS for the recovery copy (`velmora_bridge::remote`) on
//! the runtime's `fetch`, as the `HttpSend` port asks:
//!
//! - every request is bounded by a timeout, the answer's body included;
//! - no redirect is followed: the request is signed for one host, so a
//!   3xx is returned as the answer and the bridge refuses it;
//! - at most `HttpRequest::max_answer` bytes of the body are read, and a
//!   longer body is no answer.
//!
//! Nothing of a request or an answer is logged.

use std::cell::Cell;
use std::time::Duration;

use futures_util::future::{select, Either};
use futures_util::StreamExt;
use velmora_bridge::remote::{
    HttpRequest, HttpResponse, HttpSend, Problem, TransportError, MAX_AUDIT_BYTES,
};

use worker::{
    js_sys::Uint8Array, AbortController, Delay, Fetch, Headers, Method, Request, RequestInit,
    RequestRedirect,
};

/// Bound of one request, the answer's body included.
const TIMEOUT: Duration = Duration::from_secs(15);
/// Answer headers the bridge reads.
const KEPT: [&str; 3] = ["content-length", "etag", "x-amz-error-code"];

#[derive(Default)]
pub struct FetchHttp {
    pub first_problem: Cell<Option<Problem>>,
}

fn status_only(request: &HttpRequest, status: u16) -> bool {
    // The audit only needs the status of non-200 replies. A long or
    // stalled error body must not turn a known 4xx into an unavailable GET.
    request.method == "GET" && request.max_answer == MAX_AUDIT_BYTES && status != 200
}

/// True while `have` bytes and `more` to come are within `most`.
fn fits(have: usize, more: usize, most: usize) -> bool {
    have.checked_add(more).is_some_and(|all| all <= most)
}

async fn exchange(
    request: &HttpRequest,
    signal: &worker::AbortSignal,
) -> worker::Result<Option<HttpResponse>> {
    let headers = Headers::new();
    for (name, value) in &request.headers {
        headers.set(name, value)?;
    }
    let mut init = RequestInit::new();
    init.with_method(match request.method {
        "PUT" => Method::Put,
        "HEAD" => Method::Head,
        "GET" => Method::Get,
        // Nothing else is ever signed: not sent as something it is not.
        _ => return Err(worker::Error::RustError("method".into())),
    })
    .with_headers(headers)
    .with_redirect(RequestRedirect::Manual);
    if !request.body.is_empty() {
        init.with_body(Some(Uint8Array::from(request.body.as_slice()).into()));
    }
    let outbound = Request::new_with_init(&request.url, &init)?;
    let mut answer = Fetch::Request(outbound).send_with_signal(signal).await?;
    let headers = KEPT
        .iter()
        .filter_map(|name| Some(((*name).to_string(), answer.headers().get(name).ok()??)))
        .collect();
    // None means the body exceeded the bound; keep that distinct from
    // a failed exchange so the audit can count a proved size mismatch.
    // A HEAD (and an audit error response) needs only status and headers.
    let mut body = Vec::new();
    let chunks = if request.method == "HEAD" || status_only(request, answer.status_code()) {
        None
    } else {
        answer.stream().ok()
    };
    if let Some(mut chunks) = chunks {
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk?;
            if !fits(body.len(), chunk.len(), request.max_answer) {
                return Ok(None);
            }
            body.extend_from_slice(&chunk);
        }
    }
    Ok(Some(HttpResponse {
        status: answer.status_code(),
        headers,
        body,
    }))
}

impl HttpSend for FetchHttp {
    async fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let controller = AbortController::default();
        let signal = controller.signal();
        let work = std::pin::pin!(exchange(request, &signal));
        let limit = std::pin::pin!(Delay::from(TIMEOUT));
        match select(work, limit).await {
            Either::Left((Ok(Some(answer)), _)) => {
                if status_only(request, answer.status) {
                    controller.abort();
                }
                Ok(answer)
            }
            Either::Left((Ok(None), _)) => {
                controller.abort();
                Err(TransportError::BodyTooLong)
            }
            _ => {
                // Cancel what is left of a timed-out or failed exchange.
                controller.abort();
                Err(TransportError::NoAnswer)
            }
        }
    }

    async fn pause(&self, ms: u64) {
        Delay::from(Duration::from_millis(ms)).await;
    }

    fn observe(&self, problem: Problem) {
        if self.first_problem.get().is_none() {
            self.first_problem.set(Some(problem));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fits;

    #[test]
    fn a_body_is_read_up_to_the_bound_and_not_past_it() {
        assert!(fits(0, 0, 0));
        assert!(fits(0, 16, 16));
        assert!(fits(10, 6, 16));
        assert!(!fits(10, 7, 16));
        assert!(!fits(0, 1, 0));
        assert!(!fits(usize::MAX, 1, usize::MAX));
    }
}
