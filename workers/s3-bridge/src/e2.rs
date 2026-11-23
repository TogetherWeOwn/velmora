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
use futures_util::{Stream, StreamExt};
use velmora_bridge::remote::{
    s3_error_code, HttpRequest, HttpResponse, HttpSend, Problem, TransportError, MAX_AUDIT_BYTES,
};

use worker::{
    js_sys::Uint8Array, AbortController, Delay, Fetch, Headers, Method, Request, RequestInit,
    RequestRedirect,
};

/// Bound of one request, the answer's body included.
const TIMEOUT: Duration = Duration::from_secs(15);
/// Answer headers the bridge reads.
const CODE_HEADER: &str = "x-amz-error-code";
const KEPT: [&str; 3] = ["content-length", "etag", CODE_HEADER];
const AUDIT_ERROR_LIMIT: usize = 4 * 1024;

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

// Keep at most 4 KiB while recovering an XML-only error code. A failed
// read does not invalidate the status, and the body never leaves here.
async fn attach_audit_code(
    mut response: HttpResponse,
    mut chunks: impl Stream<Item = worker::Result<Vec<u8>>> + Unpin,
) -> HttpResponse {
    while response.body.len() < AUDIT_ERROR_LIMIT {
        let Some(Ok(chunk)) = chunks.next().await else {
            break;
        };
        let take = chunk.len().min(AUDIT_ERROR_LIMIT - response.body.len());
        response.body.extend_from_slice(&chunk[..take]);
    }
    if let Some(code) = s3_error_code(&response) {
        response.headers.push((CODE_HEADER.into(), code.into()));
    }
    response.body = Vec::new();
    response
}

async fn exchange(
    request: &HttpRequest,
    signal: &worker::AbortSignal,
    status_on_timeout: &Cell<Option<u16>>,
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
    let status = answer.status_code();
    let headers: Vec<_> = KEPT
        .iter()
        .filter_map(|name| Some(((*name).to_string(), answer.headers().get(name).ok()??)))
        .collect();
    if status_only(request, status) {
        let ambiguous = (400..500).contains(&status)
            && status != 429
            && !headers.iter().any(|(name, _)| name == CODE_HEADER);
        let response = HttpResponse {
            status,
            headers,
            body: Vec::new(),
        };
        if ambiguous {
            status_on_timeout.set(Some(status));
            if let Ok(chunks) = answer.stream() {
                return Ok(Some(attach_audit_code(response, chunks).await));
            }
        }
        return Ok(Some(response));
    }
    // None means the body exceeded the bound; keep that distinct from
    // a failed exchange so the audit can count a proved size mismatch.
    let mut body = Vec::new();
    let chunks = if request.method == "HEAD" {
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
        status,
        headers,
        body,
    }))
}

impl HttpSend for FetchHttp {
    async fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let controller = AbortController::default();
        let signal = controller.signal();
        let status_on_timeout = Cell::new(None);
        let work = std::pin::pin!(exchange(request, &signal, &status_on_timeout));
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
                if let Some(status) = status_on_timeout.get() {
                    Ok(HttpResponse {
                        status,
                        headers: Vec::new(),
                        body: Vec::new(),
                    })
                } else {
                    Err(TransportError::NoAnswer)
                }
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
    use super::{attach_audit_code, fits, HttpResponse, AUDIT_ERROR_LIMIT};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn xml_only_audit_error_keeps_only_a_bounded_known_code_and_its_status() {
        let message = b"<Error><Code>SlowDown</Code><Message>untrusted</Message></Error>";
        for (chunks, want) in [
            (vec![Ok(message.to_vec())], Some("SlowDown")),
            (
                vec![Ok(vec![b' '; AUDIT_ERROR_LIMIT]), Ok(message.to_vec())],
                None,
            ),
            (
                vec![Err(worker::Error::RustError("broken stream".into()))],
                None,
            ),
        ] {
            let response = HttpResponse {
                status: 400,
                headers: vec![],
                body: vec![],
            };
            let future = attach_audit_code(response, futures_util::stream::iter(chunks));
            let Poll::Ready(answer) =
                std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("the fixture completes synchronously");
            };
            assert_eq!(answer.status, 400);
            assert!(answer.body.is_empty());
            assert_eq!(
                answer.headers.first().map(|(_, value)| value.as_str()),
                want
            );
        }
    }

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
