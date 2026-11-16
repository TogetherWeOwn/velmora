//! A `200` whose XML document is computed after its headers can be sent.
//!
//! A request whose work can outlast a client's read timeout (DeleteObjects
//! of many keys: one recovery record put a key) answers with a
//! [`Deferred`] body once nothing can fail it with a status code any
//! more. [`settle_response`] then waits [`BUFFER_WINDOW_MS`] for the
//! document: a document that is done by then is sent as it is, with its
//! length, as before. Otherwise the headers go out, the XML declaration
//! at once, then one newline every [`KEEPALIVE_INTERVAL_MS`] until the
//! document is done, and then the document. That is how S3 keeps such a
//! response alive. Whitespace between the declaration and the root
//! element is `Misc` in the XML grammar, so a strict parser takes it.
//!
//! The work is apart from the body. The adapter takes it
//! ([`Deferred::take_work`]) and drives it under `waitUntil`, so it does
//! not stop when the body is dropped. The runtime gives it at most 30 s
//! once the client is gone: what is left then is not done, and the client
//! sends the request again. Untaken, the work is driven by whoever polls
//! the body. The document never fails: a failure of the work is in it,
//! and work that ends without one (it was dropped) is answered with the
//! fallback document, as is work that is not done after
//! [`MAX_STREAM_MS`]. The body always ends with a whole document.

use std::cell::RefCell;
use std::fmt;
use std::future::{poll_fn, Future};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use futures_util::future::{FutureExt, LocalBoxFuture};
use futures_util::stream;

use crate::ingress::Sleeper;
use crate::types::{ByteStream, RespBody, S3Response};

/// The XML declaration a streamed document starts with.
pub const XML_DECLARATION: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
/// Time between two whitespace bytes of a streamed document.
pub const KEEPALIVE_INTERVAL_MS: u32 = 5_000;
/// How long [`settle_response`] waits for a document before it streams.
pub const BUFFER_WINDOW_MS: u32 = 2_000;
/// What is sent every [`KEEPALIVE_INTERVAL_MS`].
pub const KEEPALIVE_BYTE: &[u8] = b"\n";
/// Most time a streamed body waits for its document. Past it the body
/// ends with the fallback document: work that neither ends nor is
/// dropped (a call that is never answered) does not hold the client
/// forever.
pub const MAX_STREAM_MS: u32 = 600_000;

enum State {
    Running,
    Done(Vec<u8>),
    /// The work was dropped before it was done.
    Abandoned,
    /// The document went to the body.
    Taken,
}

struct Shared {
    state: State,
    waker: Option<Waker>,
}

/// Sets the state and wakes the body, outside the borrow: an executor
/// that polls inside `wake` finds the cell free.
fn set(shared: &RefCell<Shared>, state: State) {
    let waker = {
        let mut s = shared.borrow_mut();
        s.state = state;
        s.waker.take()
    };
    if let Some(w) = waker {
        w.wake();
    }
}

/// Marks the work done, or abandoned when it is dropped first.
struct Finish(Rc<RefCell<Shared>>);

impl Drop for Finish {
    fn drop(&mut self) {
        let running = matches!(self.0.borrow().state, State::Running);
        if running {
            set(&self.0, State::Abandoned);
        }
    }
}

/// A document that is still being computed. See the module docs.
pub struct Deferred {
    work: Option<LocalBoxFuture<'static, ()>>,
    shared: Rc<RefCell<Shared>>,
    fallback: Option<Box<dyn FnOnce() -> Vec<u8>>>,
}

impl Deferred {
    /// `doc` resolves to the whole document without an XML declaration
    /// (the bytes a buffered answer carries). `fallback` is the document
    /// when `doc` is dropped before it is done; it must not need the work.
    pub fn new(
        doc: impl Future<Output = Vec<u8>> + 'static,
        fallback: impl FnOnce() -> Vec<u8> + 'static,
    ) -> Deferred {
        let shared = Rc::new(RefCell::new(Shared {
            state: State::Running,
            waker: None,
        }));
        let finish = Finish(Rc::clone(&shared));
        let work = async move {
            let doc = doc.await;
            set(&finish.0, State::Done(doc));
            drop(finish);
        };
        Deferred {
            work: Some(Box::pin(work)),
            shared,
            fallback: Some(Box::new(fallback)),
        }
    }

    /// The work, once. Whoever takes it drives it to its end or drops it;
    /// the body then only waits for it. `None` when it was taken before.
    pub fn take_work(&mut self) -> Option<LocalBoxFuture<'static, ()>> {
        self.work.take()
    }

    /// The document once it is there; drives the work when it was not
    /// taken.
    fn poll_doc(&mut self, cx: &mut Context<'_>) -> Poll<Vec<u8>> {
        if let Some(work) = &mut self.work {
            if work.poll_unpin(cx).is_ready() {
                self.work = None;
            }
        }
        let mut s = self.shared.borrow_mut();
        match std::mem::replace(&mut s.state, State::Taken) {
            State::Done(doc) => Poll::Ready(doc),
            State::Abandoned => {
                drop(s);
                Poll::Ready(self.fallback())
            }
            // Never polled again once the document was taken.
            State::Taken => Poll::Ready(Vec::new()),
            State::Running => {
                s.state = State::Running;
                s.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// The fallback document, once (the state is `Taken` after it).
    fn fallback(&mut self) -> Vec<u8> {
        self.shared.borrow_mut().state = State::Taken;
        self.fallback.take().map(|f| f()).unwrap_or_default()
    }

    /// The document if it is done before `window` elapses, or `self`.
    pub async fn settle(
        mut self,
        mut window: LocalBoxFuture<'static, ()>,
    ) -> Result<Vec<u8>, Deferred> {
        let doc = poll_fn(|cx| {
            if let Poll::Ready(doc) = self.poll_doc(cx) {
                return Poll::Ready(Some(doc));
            }
            window.poll_unpin(cx).map(|()| None)
        })
        .await;
        doc.ok_or(self)
    }

    /// The streamed body: [`XML_DECLARATION`] at once, [`KEEPALIVE_BYTE`]
    /// every `interval_ms` (slept with `sleeper`) while the document is
    /// not done, then the document; the fallback document instead once
    /// [`MAX_STREAM_MS`] worth of ticks have passed. Never yields an error.
    pub fn into_stream(self, sleeper: Sleeper, interval_ms: u32) -> ByteStream {
        enum Phase {
            Head(Deferred),
            /// The ticks still allowed, and the next one.
            Wait(Deferred, u32, LocalBoxFuture<'static, ()>),
            End,
        }
        let max_ticks = (MAX_STREAM_MS / interval_ms.max(1)).max(1);
        let body = stream::unfold(Phase::Head(self), move |phase| {
            let sleeper = Rc::clone(&sleeper);
            async move {
                match phase {
                    Phase::Head(d) => {
                        let tick = sleeper(interval_ms);
                        let wait = Phase::Wait(d, max_ticks, tick);
                        Some((Ok(XML_DECLARATION.to_vec()), wait))
                    }
                    Phase::Wait(mut d, left, mut tick) => {
                        let ready = poll_fn(|cx| {
                            if let Poll::Ready(doc) = d.poll_doc(cx) {
                                return Poll::Ready(Some(doc));
                            }
                            tick.poll_unpin(cx).map(|()| None)
                        })
                        .await;
                        match ready {
                            Some(doc) => Some((Ok(doc), Phase::End)),
                            // Waited long enough: the keys are not known
                            // to be deleted.
                            None if left <= 1 => Some((Ok(d.fallback()), Phase::End)),
                            None => {
                                let tick = sleeper(interval_ms);
                                let wait = Phase::Wait(d, left - 1, tick);
                                Some((Ok(KEEPALIVE_BYTE.to_vec()), wait))
                            }
                        }
                    }
                    Phase::End => None,
                }
            }
        });
        Box::pin(body)
    }
}

impl fmt::Debug for Deferred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Deferred")
            .field("work_taken", &self.work.is_none())
            .finish_non_exhaustive()
    }
}

/// A response with a [`RespBody::Deferred`] body as it is sent: with the
/// document as bytes when it is done within [`BUFFER_WINDOW_MS`], else
/// streamed with keepalive whitespace ([`Deferred::into_stream`]) and
/// `cache-control: no-transform`, which keeps the edge from compressing
/// it (a compressor holds back the small chunks the keepalive is). Any
/// other response is returned as it is.
pub async fn settle_response(resp: S3Response, sleeper: Sleeper) -> S3Response {
    let S3Response {
        status,
        mut headers,
        body,
    } = resp;
    let body = match body {
        RespBody::Deferred(d) => match d.settle(sleeper(BUFFER_WINDOW_MS)).await {
            Ok(doc) => RespBody::Bytes(doc),
            Err(d) => {
                headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-length"));
                headers.push(("cache-control".to_string(), "no-transform".to_string()));
                RespBody::Stream(d.into_stream(sleeper, KEEPALIVE_INTERVAL_MS))
            }
        },
        other => other,
    };
    S3Response {
        status,
        headers,
        body,
    }
}
