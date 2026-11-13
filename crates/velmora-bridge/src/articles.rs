//! Article plan geometry: where an extent's ciphertext is cut into
//! articles, and which articles a plaintext range needs.
//!
//! The cuts are the engine's fixed boundaries: article 0 holds the media
//! header plus 11 cipher chunks, every later article holds 11 cipher
//! chunks, and the last one holds the remainder. Each article therefore
//! decrypts on its own.

use core::ops::Range;

use velmora::article::{ARTICLE_CIPHER_BLOCKS, ARTICLE_PAYLOAD_BYTES, ARTICLE_ZERO_PAYLOAD_BYTES};
use velmora::media::PLAIN_CHUNK_SIZE;

use crate::types::ByteSpan;

/// Ciphertext span of every article of a `cipher_size`-byte extent, in
/// order. The spans are contiguous and cover `[0, cipher_size)` exactly.
/// An empty extent has no articles.
pub fn article_spans(cipher_size: u64) -> Vec<ByteSpan> {
    let mut spans = Vec::new();
    let mut start = 0u64;
    while start < cipher_size {
        let full = if start == 0 {
            ARTICLE_ZERO_PAYLOAD_BYTES
        } else {
            ARTICLE_PAYLOAD_BYTES
        };
        let len = full.min(cipher_size - start);
        spans.push(ByteSpan { start, len });
        start += len;
    }
    spans
}

/// Indexes of the articles that hold plaintext `[off, off + len)` of an
/// extent with `plain_size` plaintext bytes. The range is clamped to the
/// extent; an empty or out-of-range request gives an empty range. The
/// result is half-open.
pub fn articles_for_plain_range(plain_size: u64, off: u64, len: u64) -> Range<u32> {
    let end = off.saturating_add(len).min(plain_size);
    if len == 0 || off >= end {
        return 0..0;
    }
    let article_of = |plain: u64| {
        let chunk = plain / PLAIN_CHUNK_SIZE;
        u32::try_from(chunk / ARTICLE_CIPHER_BLOCKS as u64).unwrap_or(u32::MAX)
    };
    article_of(off)..article_of(end - 1).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora::article::ARTICLE_PLAINTEXT_BYTES;
    use velmora::media::{chunk_offset, ciphertext_size, HEADER_SIZE};

    const MIB: u64 = 1024 * 1024;

    fn cipher(plain: u64) -> u64 {
        ciphertext_size(plain).expect("fits")
    }

    #[test]
    fn spans_are_contiguous_and_cover_the_extent() {
        for plain in [0, 1, 65_536, 720_896, 720_897, 5 * MIB + 17, 16 * MIB] {
            let size = cipher(plain);
            let spans = article_spans(size);
            let mut next = 0;
            for s in &spans {
                assert_eq!(s.start, next, "plain {plain}");
                assert!(s.len > 0);
                next = s.end();
            }
            assert_eq!(next, size, "plain {plain}");
        }
        assert!(article_spans(0).is_empty());
    }

    #[test]
    fn spans_follow_the_fixed_article_boundaries() {
        let spans = article_spans(cipher(16 * MIB));
        assert_eq!(spans.len(), 24);
        assert_eq!(
            spans[0],
            ByteSpan {
                start: 0,
                len: 721_120
            }
        );
        for (k, s) in spans.iter().enumerate().skip(1) {
            // Article k starts at cipher chunk 11k.
            assert_eq!(Some(s.start), chunk_offset(11 * k as u64));
            assert_eq!(s.start, HEADER_SIZE + k as u64 * 721_072);
        }
        assert!(spans[1..23].iter().all(|s| s.len == 721_072));
        assert_eq!(article_spans(cipher(64 * MIB)).len(), 94);
        // A tiny extent is one short article.
        assert_eq!(
            article_spans(cipher(5)),
            vec![ByteSpan { start: 0, len: 69 }]
        );
    }

    /// A range read needs only the articles that cover it: the decoded
    /// payloads of exactly those articles hold every cipher chunk of the
    /// range.
    #[test]
    fn range_touches_only_covering_articles() {
        let plain = 5 * MIB + 17;
        let spans = article_spans(cipher(plain));
        let a = ARTICLE_PLAINTEXT_BYTES;
        assert_eq!(articles_for_plain_range(plain, 0, 1), 0..1);
        assert_eq!(articles_for_plain_range(plain, a - 1, 1), 0..1);
        assert_eq!(articles_for_plain_range(plain, a - 1, 2), 0..2);
        assert_eq!(articles_for_plain_range(plain, a, a), 1..2);
        assert_eq!(articles_for_plain_range(plain, 3 * a + 5, 2 * a), 3..6);
        let last = spans.len() as u32 - 1;
        assert_eq!(
            articles_for_plain_range(plain, plain - 1, 1),
            last..last + 1
        );
        assert_eq!(articles_for_plain_range(plain, 0, plain), 0..last + 1);
        // Clamped to the extent; empty and out-of-range requests are empty.
        assert_eq!(
            articles_for_plain_range(plain, plain - 1, 99),
            last..last + 1
        );
        assert!(articles_for_plain_range(plain, 10, 0).is_empty());
        assert!(articles_for_plain_range(plain, plain, 1).is_empty());
        assert!(articles_for_plain_range(0, 0, 1).is_empty());

        // The covering articles' spans contain the range's cipher chunks.
        for (off, len) in [(0, 1), (a - 1, 2), (3 * a + 5, 2 * a), (plain - 1, 1)] {
            let r = articles_for_plain_range(plain, off, len);
            let first_chunk = off / PLAIN_CHUNK_SIZE;
            let last_chunk = (off + len - 1) / PLAIN_CHUNK_SIZE;
            let lo = chunk_offset(first_chunk).expect("fits");
            let hi = chunk_offset(last_chunk + 1)
                .expect("fits")
                .min(cipher(plain));
            assert!(spans[r.start as usize].start <= lo);
            assert!(spans[r.end as usize - 1].end() >= hi);
            // Minimal: the first and last article each hold part of it.
            assert!(spans[r.start as usize].end() > lo);
            assert!(spans[r.end as usize - 1].start < hi);
        }
    }
}
