//! A blob read as a stream, with a second try for one that stalls.
//!
//! A read from the cache or the safety copy answers in a fraction of a
//! second nearly always, and once in a long while not for half a minute.
//! A [`Source`] does not wait that out: when the store has not answered
//! after [`HEDGE_MS`], or a body that has begun brings nothing for that
//! long, the same bytes are asked for a second time and whichever read
//! brings them first is the one that goes on. The other is dropped.
//!
//! A second read of a body begins at the offset the first has reached,
//! and a read that lost is never looked at again: every byte of the span
//! is handed out once, in order. What the bytes are is not judged here.
//! The caller authenticates them before any of them is released.

use core::future::Future;
use core::pin::pin;
use core::task::Poll;

use futures_util::future::{poll_fn, select, Either, FusedFuture, FutureExt};
use futures_util::stream::StreamExt;

use crate::ingress::Sleeper;
use crate::ports::{BlobBody, BlobStore};
use crate::types::{BridgeError, ByteSpan, Result};

/// How long a read may bring nothing before it is asked for again.
pub const HEDGE_MS: u32 = 3_000;
/// How long a read may bring nothing, the second try included, before
/// it is given up.
pub const GIVE_UP_MS: u32 = 10_000;
/// Second tries per span.
pub const HEDGES: u32 = 2;
/// Chunks without a byte a body may bring in a row.
const EMPTY_CHUNKS: u32 = 16;

/// The first answer of `a` and `b` that is `good`; when neither is, the
/// later of the two.
async fn first_good<T>(
    a: impl Future<Output = T>,
    b: impl Future<Output = T>,
    good: impl Fn(&T) -> bool,
) -> T {
    let mut a = pin!(a.fuse());
    let mut b = pin!(b.fuse());
    let mut spare = None;
    poll_fn(|cx| {
        if !a.is_terminated() {
            if let Poll::Ready(out) = a.as_mut().poll(cx) {
                if good(&out) {
                    return Poll::Ready(out);
                }
                spare = Some(out);
            }
        }
        if !b.is_terminated() {
            if let Poll::Ready(out) = b.as_mut().poll(cx) {
                if good(&out) {
                    return Poll::Ready(out);
                }
                spare = Some(out);
            }
        }
        match (a.is_terminated() && b.is_terminated(), spare.take()) {
            (true, Some(out)) => Poll::Ready(out),
            (_, kept) => {
                spare = kept;
                Poll::Pending
            }
        }
    })
    .await
}

/// `f`, unless it takes longer than `ms`.
pub(super) async fn within<F: Future>(sleep: &Sleeper, ms: u32, f: F) -> Option<F::Output> {
    let f = pin!(f);
    match select(f, sleep(ms)).await {
        Either::Left((out, _)) => Some(out),
        Either::Right(_) => None,
    }
}

/// What asking a store for a span came to.
pub(super) enum Begun<'a, B: BlobStore> {
    /// The store answered that it has no such blob.
    Absent,
    /// The store did not answer, or with an error.
    Failed,
    Body(Source<'a, B>),
}

/// The bytes `[at, end)` of one blob, as they arrive.
pub(super) struct Source<'a, B: BlobStore> {
    store: &'a B,
    key: String,
    /// The offset in the blob of the next byte to hand out.
    at: u64,
    end: u64,
    body: BlobBody,
    /// Without a timer a read is waited for as long as it takes.
    sleep: Option<Sleeper>,
    /// Second tries left.
    hedges: u32,
}

impl<'a, B: BlobStore> Source<'a, B> {
    /// Asks `store` for `span` of `key`.
    pub(super) async fn begin(
        store: &'a B,
        key: String,
        span: ByteSpan,
        sleep: Option<Sleeper>,
    ) -> Begun<'a, B> {
        let mut hedges = HEDGES;
        let opened = match &sleep {
            None => store.open(&key, span).await,
            Some(sleep) => {
                let first = pin!(store.open(&key, span));
                match select(first, sleep(HEDGE_MS)).await {
                    Either::Left((out, _)) => out,
                    Either::Right((_, first)) => {
                        hedges -= 1;
                        let both = first_good(first, store.open(&key, span), Result::is_ok);
                        within(sleep, GIVE_UP_MS - HEDGE_MS, both)
                            .await
                            .unwrap_or_else(|| Err(BridgeError::Blob("read timed out".into())))
                    }
                }
            }
        };
        match opened {
            Ok(Some(body)) => Begun::Body(Source {
                store,
                key,
                at: span.start,
                end: span.end(),
                body,
                sleep,
                hedges,
            }),
            Ok(None) => Begun::Absent,
            Err(_) => Begun::Failed,
        }
    }

    /// Bytes of the span that were not handed out yet.
    pub(super) fn left(&self) -> u64 {
        self.end - self.at
    }

    /// The next bytes of the span, at least one. `None`: there are none
    /// to be had from this store (the body ended early, ran past the
    /// span, failed, or stalled for good), or the span is at its end.
    pub(super) async fn more(&mut self) -> Option<Vec<u8>> {
        let mut empty = 0;
        loop {
            if self.at >= self.end {
                return None;
            }
            let bytes = self.pull().await?;
            let n = bytes.len() as u64;
            if n == 0 {
                empty += 1;
                if empty > EMPTY_CHUNKS {
                    return None;
                }
                continue;
            }
            if n > self.end - self.at {
                return None;
            }
            self.at += n;
            return Some(bytes);
        }
    }

    /// The next chunk of the body, from a second read if the first
    /// brings nothing in time.
    async fn pull(&mut self) -> Option<Vec<u8>> {
        let Some(sleep) = self.sleep.clone() else {
            return self.body.next().await?.ok();
        };
        let span = ByteSpan {
            start: self.at,
            len: self.end - self.at,
        };
        let (store, key) = (self.store, self.key.as_str());
        let (swap, bytes) = {
            let mut old = self.body.next();
            match select(&mut old, sleep(HEDGE_MS)).await {
                Either::Left((got, _)) => return got?.ok(),
                Either::Right(_) => {}
            }
            let rest = GIVE_UP_MS - HEDGE_MS;
            if self.hedges == 0 {
                return within(&sleep, rest, old).await??.ok();
            }
            self.hedges -= 1;
            // The same bytes from where this body stands. The one that
            // brings some first goes on; the other is dropped with all
            // it read.
            let old = async { Some((None, old.await?.ok()?)) };
            let fresh = async {
                let mut body = store.open(key, span).await.ok()??;
                let first = body.next().await?.ok()?;
                Some((Some(body), first))
            };
            within(&sleep, rest, first_good(old, fresh, Option::is_some)).await??
        };
        if let Some(body) = swap {
            self.body = body;
        }
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    use futures_util::future::{pending, ready};
    use futures_util::stream;

    use crate::ports::BlobMeta;
    use crate::recovery::Unpublished;

    /// What a scripted body does at one step.
    #[derive(Clone)]
    enum Step {
        Bytes(Vec<u8>),
        Fail,
        /// Never brings anything again.
        Stall,
    }

    /// A store of one blob whose reads follow a script: one list of
    /// steps per `open`, in the order of the calls. A read without a
    /// script brings the whole span at once.
    #[derive(Default)]
    struct Scripted {
        blob: Vec<u8>,
        absent: bool,
        /// Per `open`: `None` = the open itself never answers.
        opens: RefCell<VecDeque<Option<Vec<Step>>>>,
        asked: RefCell<Vec<ByteSpan>>,
        failing_opens: Cell<u32>,
    }

    impl BlobStore for Scripted {
        async fn put(&self, _: &str, _: Vec<u8>, _: &BlobMeta<'_>) -> Result<()> {
            Ok(())
        }
        async fn get(&self, _: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
            if self.absent {
                return Ok(None);
            }
            Ok(Some(match span {
                Some(s) => self.blob[s.start as usize..s.end() as usize].to_vec(),
                None => self.blob.clone(),
            }))
        }
        async fn open(&self, key: &str, span: ByteSpan) -> Result<Option<BlobBody>> {
            self.asked.borrow_mut().push(span);
            if self.failing_opens.get() > 0 {
                self.failing_opens.set(self.failing_opens.get() - 1);
                return Err(BridgeError::Blob("down".into()));
            }
            let script = self.opens.borrow_mut().pop_front();
            let steps = match script {
                None => {
                    let whole = self.get(key, Some(span)).await?;
                    return Ok(whole.map(|bytes| stream::once(ready(Ok(bytes))).boxed_local()));
                }
                Some(None) => pending().await,
                Some(Some(steps)) => steps,
            };
            let body = stream::iter(steps).then(|step| async move {
                match step {
                    Step::Bytes(bytes) => Ok(bytes),
                    Step::Fail => Err(BridgeError::Blob("cut".into())),
                    Step::Stall => pending().await,
                }
            });
            Ok(Some(body.boxed_local()))
        }
        async fn head(&self, _: &str) -> Result<Option<u64>> {
            Ok(None)
        }
        async fn list(&self, _: &str, _: &str, _: u32) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn delete(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn delete_record(&self, _: &Unpublished) -> Result<()> {
            Ok(())
        }
    }

    /// A timer that is over at once: whatever does not answer when it
    /// is first asked counts as stalled.
    fn at_once() -> Option<Sleeper> {
        Some(Rc::new(|_| ready(()).boxed_local()))
    }

    fn store(len: usize) -> Scripted {
        Scripted {
            blob: (0..len).map(|i| (i % 251) as u8).collect(),
            ..Scripted::default()
        }
    }

    const SPAN: ByteSpan = ByteSpan { start: 10, len: 90 };

    /// Everything a source brings, and whether it reached the end of
    /// its span.
    async fn drain(src: &mut Source<'_, Scripted>) -> (Vec<u8>, bool) {
        let mut all = Vec::new();
        while let Some(bytes) = src.more().await {
            all.extend_from_slice(&bytes);
        }
        (all, src.left() == 0)
    }

    async fn begun(store: &Scripted, sleep: Option<Sleeper>) -> Source<'_, Scripted> {
        match Source::begin(store, "k".into(), SPAN, sleep).await {
            Begun::Body(src) => src,
            Begun::Absent => panic!("absent"),
            Begun::Failed => panic!("failed"),
        }
    }

    #[tokio::test]
    async fn a_body_that_stalls_is_taken_up_where_it_stood() {
        let s = store(200);
        let scripts = [
            Some(vec![Step::Bytes(s.blob[10..40].to_vec()), Step::Stall]),
            Some(vec![Step::Bytes(s.blob[40..100].to_vec())]),
        ];
        s.opens.borrow_mut().extend(scripts);
        let mut src = begun(&s, at_once()).await;
        let (all, whole) = drain(&mut src).await;
        // Each byte once, in order: the second read began at the offset
        // the first had reached.
        assert!(whole);
        assert_eq!(all, s.blob[10..100]);
        let second = ByteSpan { start: 40, len: 60 };
        assert_eq!(*s.asked.borrow(), [SPAN, second]);
    }

    #[tokio::test]
    async fn an_open_that_does_not_answer_is_asked_again() {
        let s = store(200);
        s.opens.borrow_mut().push_back(None);
        let mut src = begun(&s, at_once()).await;
        let (all, whole) = drain(&mut src).await;
        assert!(whole);
        assert_eq!(all, s.blob[10..100]);
        assert_eq!(*s.asked.borrow(), [SPAN, SPAN]);
    }

    #[tokio::test]
    async fn second_tries_are_bounded() {
        // Every read brings ten bytes and stalls.
        let s = store(200);
        let part = |from: usize| {
            Some(vec![
                Step::Bytes(s.blob[from..from + 10].to_vec()),
                Step::Stall,
            ])
        };
        let scripts = [part(10), part(20), part(30), part(40), part(50)];
        s.opens.borrow_mut().extend(scripts);
        let mut src = begun(&s, at_once()).await;
        let (all, whole) = drain(&mut src).await;
        // The first read and the second tries, no more; what they
        // brought is in order, each byte once.
        assert_eq!(s.asked.borrow().len(), 1 + HEDGES as usize);
        assert_eq!(all, s.blob[10..40]);
        assert!(!whole);
    }

    #[tokio::test]
    async fn a_second_try_that_stalls_too_ends_the_read() {
        let s = store(200);
        let stall = || Some(vec![Step::Stall]);
        s.opens.borrow_mut().extend([stall(), stall(), stall()]);
        let mut src = begun(&s, at_once()).await;
        let (all, whole) = drain(&mut src).await;
        assert!(all.is_empty() && !whole);
        assert_eq!(s.asked.borrow().len(), 2);
    }

    #[tokio::test]
    async fn without_a_timer_nothing_is_asked_twice() {
        let s = store(200);
        let steps = vec![
            Step::Bytes(s.blob[10..50].to_vec()),
            Step::Bytes(Vec::new()),
            Step::Bytes(s.blob[50..100].to_vec()),
        ];
        s.opens.borrow_mut().push_back(Some(steps));
        let mut src = begun(&s, None).await;
        let (all, whole) = drain(&mut src).await;
        assert!(whole);
        assert_eq!(all, s.blob[10..100]);
        assert_eq!(s.asked.borrow().len(), 1);
    }

    #[tokio::test]
    async fn a_short_failing_or_long_body_ends_without_its_span() {
        for steps in [
            vec![Step::Bytes(vec![1; 30])],
            vec![Step::Bytes(vec![1; 30]), Step::Fail],
            vec![Step::Bytes(vec![1; 30]), Step::Bytes(vec![1; 61])],
        ] {
            let s = store(200);
            s.opens.borrow_mut().push_back(Some(steps));
            let mut src = begun(&s, None).await;
            let (all, whole) = drain(&mut src).await;
            assert_eq!(all.len(), 30);
            assert!(!whole);
        }
    }

    #[tokio::test]
    async fn absent_and_failed_are_told_apart() {
        let gone = Scripted {
            absent: true,
            ..store(200)
        };
        assert!(matches!(
            Source::begin(&gone, "k".into(), SPAN, None).await,
            Begun::Absent
        ));
        let down = store(200);
        down.failing_opens.set(1);
        assert!(matches!(
            Source::begin(&down, "k".into(), SPAN, None).await,
            Begun::Failed
        ));
        // A failing first try and a second that answers: the answer.
        let s = store(200);
        s.opens.borrow_mut().push_back(None);
        assert!(matches!(
            Source::begin(&s, "k".into(), SPAN, at_once()).await,
            Begun::Body(_)
        ));
    }
}
