//! Bounded original-media reader. Transport and cancellation/deadlines belong
//! to the request authority; this seam neither dials nor authenticates users.
//! The verified prefix walk is deliberately the baseline even with a hint.

use std::{
    collections::VecDeque,
    future::{poll_fn, Future},
    io::{Cursor, Read},
    ops::Range,
    pin::pin,
    task::{Context, Poll},
};

use super::{OriginalSource, RangeHint, SourceError, MAX_ARTICLE_BYTES};
use crate::yenc::{self, DecodedPart};

/// Open exactly one private reference. Implementations must enforce their
/// own operation deadline, cancellation and bounded wire framing as well.
pub trait ArticleSource {
    type Body: Read;
    fn open(&mut self, reference: &str) -> Result<Self::Body, SourceError>;
}

pub trait ReadControl {
    /// Called before I/O, during collection and before releasing output.
    /// The authority must also cancel a blocked transport read itself.
    fn check(&mut self) -> Result<(), SourceError>;
}

struct Part {
    bytes: Vec<u8>,
    geometry: DecodedPart,
}

fn decode<C: ReadControl>(
    source: &OriginalSource,
    index: usize,
    decoded_budget: u64,
    mut body: impl Read,
    control: &mut C,
) -> Result<Part, SourceError> {
    control.check()?;
    if decoded_budget == 0 {
        return Err(SourceError::Integrity);
    }
    let mut encoded = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        control.check()?;
        let n = body.read(&mut chunk).map_err(|_| SourceError::Transport)?;
        if n > chunk.len() || n > MAX_ARTICLE_BYTES - encoded.len() {
            return Err(SourceError::Bounds);
        }
        if n == 0 {
            break;
        }
        encoded.extend_from_slice(&chunk[..n]);
    }
    control.check()?;
    let decode_cap = decoded_budget.min(MAX_ARTICLE_BYTES as u64) as usize;
    let mut decoded = vec![0u8; encoded.len().min(decode_cap)];
    let geometry = yenc::decode_part_to("original-source", &encoded, &mut decoded)
        .map_err(|_| SourceError::Integrity)?;
    decoded.truncate(geometry.written);
    if geometry.written == 0
        || geometry.file_size != source.file_size()
        || geometry.multipart != (source.article_count() > 1)
        || (geometry.multipart && geometry.part_number != Some(index as u64 + 1))
    {
        return Err(SourceError::Integrity);
    }
    let end = geometry
        .offset
        .checked_add(geometry.written as u64)
        .ok_or(SourceError::Integrity)?;
    if end > source.file_size()
        || (index + 1 == source.article_count() && end != source.file_size())
    {
        return Err(SourceError::Integrity);
    }
    Ok(Part {
        bytes: decoded,
        geometry,
    })
}

/// Half-open uniform candidates, usable only after actual endpoint proof.
#[derive(Clone, Copy, Debug)]
pub struct UniformRanges {
    part_size: u64,
    file_size: u64,
    count: usize,
}

impl UniformRanges {
    pub fn candidate(&self, index: usize) -> Result<Range<u64>, SourceError> {
        if index >= self.count {
            return Err(SourceError::Bounds);
        }
        let start = (index as u64)
            .checked_mul(self.part_size)
            .ok_or(SourceError::Bounds)?;
        let end = start
            .checked_add(self.part_size)
            .ok_or(SourceError::Bounds)?
            .min(self.file_size);
        Ok(start..end)
    }

    pub fn corroborates(&self, index: usize, actual: &DecodedPart) -> bool {
        self.candidate(index).is_ok_and(|r| {
            actual.file_size == self.file_size
                && actual.offset == r.start
                && actual.written as u64 == r.end - r.start
        })
    }
}

/// Reject an uncorroborated hint without mistaking it for verified media.
pub fn corroborate_hint(
    source: &OriginalSource,
    first: &DecodedPart,
    last: &DecodedPart,
) -> Option<UniformRanges> {
    let RangeHint {
        part_size,
        final_begin,
        final_end,
    } = source.range_hint()?;
    if part_size == 0 || part_size > MAX_ARTICLE_BYTES as u64 || part_size != first.written as u64 {
        return None;
    }
    let size = source.file_size();
    let count = (size - 1).checked_div(part_size)?.checked_add(1)?;
    if count != source.article_count() as u64 {
        return None;
    }
    let final_start = (count - 1).checked_mul(part_size)?;
    if final_begin != final_start || final_end != size {
        return None;
    }
    if first.multipart != (count > 1) || last.multipart != (count > 1) {
        return None;
    }
    let ranges = UniformRanges {
        part_size,
        file_size: size,
        count: source.article_count(),
    };
    (ranges.corroborates(0, first) && ranges.corroborates(source.article_count() - 1, last))
        .then_some(ranges)
}

/// Incremental bounded prefix walk for synchronous or asynchronous transports.
/// The authority awaits exactly the reference requested by `next_reference`,
/// then supplies its framed body to `push`. Final-part proof precedes output;
/// the last part is retained, not refetched. No reference or size is caller
/// selected. At most two decoded articles are retained, never a whole file.
/// A failed push poisons this walk: partial-output failures must abort the
/// response, not retry, finish or publish it as a complete file.
pub struct RangeReader<'a> {
    source: &'a OriginalSource,
    range: Range<u64>,
    last: Option<Part>,
    final_loaded: bool,
    index: usize,
    position: u64,
    total_decoded: u64,
    hint: Option<UniformRanges>,
    done: bool,
    failed: bool,
}

impl<'a> RangeReader<'a> {
    pub fn new(source: &'a OriginalSource, range: Range<u64>) -> Result<Self, SourceError> {
        if range.start >= range.end || range.end > source.file_size() {
            return Err(SourceError::Range);
        }
        Ok(Self {
            source,
            range,
            last: None,
            final_loaded: false,
            index: 0,
            position: 0,
            total_decoded: 0,
            hint: None,
            done: false,
            failed: false,
        })
    }

    fn request(&self) -> Result<Option<(usize, u64)>, SourceError> {
        if self.failed {
            return Err(SourceError::Integrity);
        }
        if self.done {
            return Ok(None);
        }
        if !self.final_loaded {
            return Ok(Some((
                self.source.article_count() - 1,
                self.source.file_size(),
            )));
        }
        let budget = self
            .source
            .file_size()
            .checked_sub(self.total_decoded)
            .filter(|&n| n > 0)
            .ok_or(SourceError::Integrity)?;
        Ok(Some((self.index, budget)))
    }

    pub fn next_reference(&self) -> Result<Option<&str>, SourceError> {
        self.request()?
            .map(|(index, _)| self.source.article(index).map(|a| a.reference()))
            .transpose()
    }

    /// A successful push can emit multiple slices (the current and retained
    /// final article). The sink must stream and propagate failure; it must not
    /// grow a file-sized buffer. `control` checks also guard each output slice.
    pub fn push<C: ReadControl>(
        &mut self,
        body: impl Read,
        control: &mut C,
        mut sink: impl FnMut(&[u8]) -> Result<(), SourceError>,
    ) -> Result<(), SourceError> {
        let (index, budget) = self.request()?.ok_or(SourceError::Integrity)?;
        self.failed = true;
        let part = decode(self.source, index, budget, body, control)?;
        self.total_decoded = self
            .total_decoded
            .checked_add(part.geometry.written as u64)
            .filter(|&n| n <= self.source.file_size())
            .ok_or(SourceError::Integrity)?;
        let last_index = self.source.article_count() - 1;
        if !self.final_loaded {
            self.final_loaded = true;
            self.last = Some(part);
        } else {
            self.emit(part, control, &mut sink)?;
            self.index += 1;
        }
        if !self.done && self.index == last_index {
            let part = self.last.take().ok_or(SourceError::Integrity)?;
            self.emit(part, control, &mut sink)?;
        }
        control.check()?;
        self.failed = false;
        Ok(())
    }

    fn emit<C: ReadControl>(
        &mut self,
        part: Part,
        control: &mut C,
        sink: &mut impl FnMut(&[u8]) -> Result<(), SourceError>,
    ) -> Result<(), SourceError> {
        let actual = part.geometry;
        if actual.offset != self.position {
            return Err(SourceError::Integrity);
        }
        let end = self
            .position
            .checked_add(actual.written as u64)
            .filter(|&n| n <= self.source.file_size())
            .ok_or(SourceError::Integrity)?;
        if self.index == 0 {
            let last_geometry = self.last.as_ref().map_or(actual, |p| p.geometry);
            self.hint = corroborate_hint(self.source, &actual, &last_geometry);
        }
        if self
            .hint
            .is_some_and(|h| !h.corroborates(self.index, &actual))
        {
            self.hint = None;
        }
        let start_out = self.range.start.max(self.position);
        let end_out = self.range.end.min(end);
        if start_out < end_out {
            control.check()?;
            let a = usize::try_from(start_out - self.position).map_err(|_| SourceError::Bounds)?;
            let b = usize::try_from(end_out - self.position).map_err(|_| SourceError::Bounds)?;
            sink(part.bytes.get(a..b).ok_or(SourceError::Integrity)?)?;
        }
        self.position = end;
        self.done = self.position >= self.range.end;
        Ok(())
    }
}

/// Stream a validated half-open range through the same incremental prefix
/// walk used by async callers. At most N opens occur; endpoint data is never
/// fetched twice. A sink error requires the authority to abort the response.
pub fn read_range<T: ArticleSource, C: ReadControl>(
    source: &OriginalSource,
    range: Range<u64>,
    transport: &mut T,
    control: &mut C,
    mut sink: impl FnMut(&[u8]) -> Result<(), SourceError>,
) -> Result<(), SourceError> {
    let mut reader = RangeReader::new(source, range)?;
    while let Some(reference) = reader.next_reference()? {
        control.check()?;
        let body = transport.open(reference)?;
        reader.push(body, control, &mut sink)?;
    }
    Ok(())
}

/// Async supplier for one complete, transfer-encoded article. The supplier
/// must cap collection at `MAX_ARTICLE_BYTES` before growing its buffer and
/// enforce its own operation timer. `index` is the trusted source ordinal,
/// not a client-selected article. Dropping the future cancels local work;
/// account capacity/physical close remain the supplier's responsibility.
pub trait AsyncArticleSource {
    fn open(
        &mut self,
        index: usize,
        reference: &str,
    ) -> impl Future<Output = Result<Vec<u8>, SourceError>>;
}

/// Request authority with a wakeable cancellation/deadline signal. A pending
/// implementation must register the waker; `check` alone cannot interrupt an
/// awaited article. Return the same redacted error that `check` would return.
pub trait AsyncReadControl: ReadControl {
    fn poll_cancel(&mut self, cx: &mut Context<'_>) -> Poll<SourceError>;
}

/// Lazy async wrapper over the shared incremental `RangeReader`. A push may
/// emit the current and retained final slice; at most two bounded article
/// slices are queued, and each pull releases only one. These are verified
/// bytes, not writer acknowledgements or delivery evidence.
/// An error or a dropped pending pull permanently stops the wrapper. Drop it
/// to discard buffers; an uncertain supplier operation is never retried.
pub struct AsyncRangeReader<'a> {
    walk: RangeReader<'a>,
    pending: VecDeque<Vec<u8>>,
    stopped: bool,
}

impl<'a> AsyncRangeReader<'a> {
    pub fn new(source: &'a OriginalSource, range: Range<u64>) -> Result<Self, SourceError> {
        Ok(Self {
            walk: RangeReader::new(source, range)?,
            pending: VecDeque::new(),
            stopped: false,
        })
    }

    pub async fn next<T: AsyncArticleSource, C: AsyncReadControl>(
        &mut self,
        transport: &mut T,
        control: &mut C,
    ) -> Result<Option<Vec<u8>>, SourceError> {
        if self.stopped {
            return Err(SourceError::Cancelled);
        }
        // Fail closed even when the caller drops an externally pending await.
        self.stopped = true;
        control.check()?;
        loop {
            // Also check the wakeable signal before releasing buffered output:
            // draining the retained final slice does not await the transport.
            poll_fn(|cx| match control.poll_cancel(cx) {
                Poll::Ready(error) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Ready(Ok(())),
            })
            .await?;
            if let Some(bytes) = self.pending.pop_front() {
                control.check()?;
                self.stopped = false;
                return Ok(Some(bytes));
            }
            let Some((index, _)) = self.walk.request()? else {
                self.stopped = false;
                return Ok(None);
            };
            let encoded = {
                let reference = self.walk.next_reference()?.ok_or(SourceError::Integrity)?;
                control.check()?;
                let mut opening = pin!(async { transport.open(index, reference).await });
                poll_fn(|cx| {
                    // Cancellation wins a simultaneous-ready article race.
                    if let Poll::Ready(error) = control.poll_cancel(cx) {
                        return Poll::Ready(Err(error));
                    }
                    opening.as_mut().poll(cx)
                })
                .await?
            };
            control.check()?;
            let walking_prefix = self.walk.final_loaded;
            self.walk.push(Cursor::new(encoded), control, |bytes| {
                // This is an article-sized adapter, never a file accumulator.
                if self.pending.len() == 2 || bytes.len() > MAX_ARTICLE_BYTES {
                    return Err(SourceError::Bounds);
                }
                self.pending.push_back(bytes.to_vec());
                Ok(())
            })?;
            if walking_prefix && self.pending.is_empty() && !self.walk.done {
                // Ready suppliers must not monopolize a poll while skipping a
                // long prefix. Retain progress, then recheck control next poll.
                let mut yielded = false;
                poll_fn(|cx| {
                    if yielded {
                        Poll::Ready(())
                    } else {
                        yielded = true;
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
            }
        }
    }
}
