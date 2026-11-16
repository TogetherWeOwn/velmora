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
//! ([`Deferred::take_work`]) and drives it to its end whatever becomes of
//! the client (`waitUntil`), so a client that goes away leaves what a
//! client that read the answer leaves. Untaken, it is driven by whoever
//! polls the body. The document never fails: a failure of the work is in
//! it, and work that ends without one (it was dropped) is answered with
//! the fallback document. The body always ends with a whole document.

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

impl Shared {
    fn set(&mut self, state: State) {
        self.state = state;
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }
}

/// Marks the work done, or abandoned when it is dropped first.
struct Finish(Rc<RefCell<Shared>>);

impl Drop for Finish {
    fn drop(&mut self) {
        let mut s = self.0.borrow_mut();
        if matches!(s.state, State::Running) {
            s.set(State::Abandoned);
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
            finish.0.borrow_mut().set(State::Done(doc));
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
                let fallback = self.fallback.take();
                Poll::Ready(fallback.map(|f| f()).unwrap_or_default())
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
    /// not done, then the document. Never yields an error.
    pub fn into_stream(self, sleeper: Sleeper, interval_ms: u32) -> ByteStream {
        enum Phase {
            Head(Deferred),
            Wait(Deferred, LocalBoxFuture<'static, ()>),
            End,
        }
        let body = stream::unfold(Phase::Head(self), move |phase| {
            let sleeper = Rc::clone(&sleeper);
            async move {
                match phase {
                    Phase::Head(d) => {
                        let tick = sleeper(interval_ms);
                        Some((Ok(XML_DECLARATION.to_vec()), Phase::Wait(d, tick)))
                    }
                    Phase::Wait(mut d, mut tick) => {
                        let ready = poll_fn(|cx| {
                            if let Poll::Ready(doc) = d.poll_doc(cx) {
                                return Poll::Ready(Some(doc));
                            }
                            tick.poll_unpin(cx).map(|()| None)
                        })
                        .await;
                        match ready {
                            Some(doc) => Some((Ok(doc), Phase::End)),
                            None => {
                                let tick = sleeper(interval_ms);
                                Some((Ok(KEEPALIVE_BYTE.to_vec()), Phase::Wait(d, tick)))
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
