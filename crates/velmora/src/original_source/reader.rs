//! Bounded original-media reader. Transport and cancellation/deadlines belong
//! to the request authority; this seam neither dials nor authenticates users.
//! The verified prefix walk is deliberately the baseline even with a hint.

use std::{io::Read, ops::Range};

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

fn fetch<T: ArticleSource, C: ReadControl>(
    source: &OriginalSource,
    index: usize,
    decoded_budget: u64,
    transport: &mut T,
    control: &mut C,
) -> Result<Part, SourceError> {
    control.check()?;
    if decoded_budget == 0 {
        return Err(SourceError::Integrity);
    }
    let article = source.article(index)?;
    let mut body = transport.open(article.reference())?;
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
    // At most one decoded article, never the yEnc whole-file size. The
    // decoder checks capacity on every write as well as declared lengths.
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

/// Stream a validated half-open range through a contiguous prefix walk.
/// No hint can bypass the baseline. Actual final-part corroboration happens
/// before output, and every covering/intermediate part is checked before
/// slicing. At most N BODY opens occur; endpoint data is not fetched twice.
/// An error after output requires the authority to abort the response, never
/// claim a complete file. The sink must stream, not retain a file-sized Vec.
pub fn read_range<T: ArticleSource, C: ReadControl>(
    source: &OriginalSource,
    range: Range<u64>,
    transport: &mut T,
    control: &mut C,
    mut sink: impl FnMut(&[u8]) -> Result<(), SourceError>,
) -> Result<(), SourceError> {
    if range.start >= range.end || range.end > source.file_size() {
        return Err(SourceError::Range);
    }
    let last_index = source.article_count() - 1;
    let mut last = Some(fetch(
        source,
        last_index,
        source.file_size(),
        transport,
        control,
    )?);
    let last_geometry = last.as_ref().ok_or(SourceError::Integrity)?.geometry;
    let mut position = 0u64;
    let mut total_decoded = last_geometry.written as u64;
    let mut hint = None;
    for index in 0..source.article_count() {
        let part = if index == last_index {
            last.take().ok_or(SourceError::Integrity)?
        } else {
            let remaining = source
                .file_size()
                .checked_sub(total_decoded)
                .ok_or(SourceError::Integrity)?;
            let part = fetch(source, index, remaining, transport, control)?;
            total_decoded = total_decoded
                .checked_add(part.geometry.written as u64)
                .filter(|&n| n <= source.file_size())
                .ok_or(SourceError::Integrity)?;
            part
        };
        let actual = part.geometry;
        if actual.offset != position {
            return Err(SourceError::Integrity);
        }
        let end = position
            .checked_add(actual.written as u64)
            .filter(|&n| n <= source.file_size())
            .ok_or(SourceError::Integrity)?;
        if index == 0 {
            hint = corroborate_hint(source, &actual, &last_geometry);
        }
        if hint.is_some_and(|h| !h.corroborates(index, &actual)) {
            // The actual contiguous geometry still has to pass above; a
            // stale uniform hint is merely discarded, never repairs media.
            hint = None;
        }
        let start_out = range.start.max(position);
        let end_out = range.end.min(end);
        if start_out < end_out {
            control.check()?;
            let a = usize::try_from(start_out - position).map_err(|_| SourceError::Bounds)?;
            let b = usize::try_from(end_out - position).map_err(|_| SourceError::Bounds)?;
            sink(part.bytes.get(a..b).ok_or(SourceError::Integrity)?)?;
        }
        position = end;
        if position >= range.end {
            return Ok(());
        }
    }
    Err(SourceError::Integrity)
}
