//! Test support: a writer of segmented generation records (format 2)
//! for the tests of the readers, apart from the production writer
//! (`recovery::SegmentWriter`), so that a reader is not only tested
//! against the code it ships with.
//!
//! A record is made from a format-1 record: the same bucket, the same
//! generation, the same extents, cut into segments of a size the test
//! picks.

#![allow(dead_code)]

use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;
use velmora_bridge::crypto::seal_manifest;
use velmora_bridge::ports::Kek;
use velmora_bridge::recovery::{
    GenerationHead, GenerationManifest, Layout, Segment, SegmentEntry, SEGMENTED_VERSION,
};

/// A set id as a writer would mint it: `s_`, 13 hex digits of the time
/// and 16 more.
pub fn set_id(ms: i64, tail: u64) -> String {
    format!("s_{ms:013x}{tail:016x}")
}

/// The extents of `m` in segments of `per`, the last one shorter.
pub fn split(m: &GenerationManifest, set: &str, per: usize) -> Vec<Segment> {
    m.extents
        .chunks(per)
        .enumerate()
        .map(|(index, extents)| Segment {
            v: SEGMENTED_VERSION,
            set: set.to_string(),
            index: index as u32,
            extents: extents.to_vec(),
        })
        .collect()
}

/// The head that names `segments`, whose sealed bytes have `digests`.
pub fn head_of(
    m: &GenerationManifest,
    set: &str,
    segments: &[Segment],
    digests: &[Vec<u8>],
) -> GenerationHead {
    GenerationHead {
        v: SEGMENTED_VERSION,
        bucket: m.bucket.clone(),
        generation: m.generation.clone(),
        set: set.to_string(),
        segments: segments
            .iter()
            .zip(digests)
            .map(|(s, sha256)| SegmentEntry {
                seq: s.extents[0].seq,
                count: s.extents.len() as u32,
                plain_offset: s.extents[0].plain_offset,
                plain_size: s.extents.iter().map(|e| e.plain_size).sum(),
                sha256: sha256.clone(),
            })
            .collect(),
    }
}

/// A segmented record, sealed: what to store, segments first.
pub struct Sealed {
    pub head: GenerationHead,
    pub head_key: String,
    pub head_sealed: Vec<u8>,
    /// Name and sealed bytes of each segment, in order.
    pub segments: Vec<(String, Vec<u8>)>,
    /// The segments as they were sealed.
    pub plain: Vec<Segment>,
}

/// Seals one segment under its name in `layout`.
pub fn seal_segment<K: Kek>(kek: &K, layout: &Layout, segment: &Segment) -> (String, Vec<u8>) {
    let name = layout.segment_key(&segment.set, segment.index);
    let plain = serde_json::to_vec(segment).unwrap();
    let sealed = seal_manifest(kek, &name, &plain, &mut SystemRng).unwrap();
    (name, sealed)
}

/// Seals `head` under `head_key`.
pub fn seal_head<K: Kek>(kek: &K, head_key: &str, head: &GenerationHead) -> Vec<u8> {
    let plain = serde_json::to_vec(head).unwrap();
    seal_manifest(kek, head_key, &plain, &mut SystemRng).unwrap()
}

/// The record `m`, stored at `head_key` of `layout`, as a segmented
/// record with segments of `per` extents.
pub fn seal<K: Kek>(
    kek: &K,
    layout: &Layout,
    head_key: &str,
    m: &GenerationManifest,
    set: &str,
    per: usize,
) -> Sealed {
    let plain = split(m, set, per);
    let segments: Vec<(String, Vec<u8>)> =
        plain.iter().map(|s| seal_segment(kek, layout, s)).collect();
    let digests: Vec<Vec<u8>> = segments
        .iter()
        .map(|(_, sealed)| Sha256::digest(sealed).to_vec())
        .collect();
    let head = head_of(m, set, &plain, &digests);
    let head_sealed = seal_head(kek, head_key, &head);
    Sealed {
        head,
        head_key: head_key.to_string(),
        head_sealed,
        segments,
        plain,
    }
}

impl Sealed {
    /// Seals the head again, after a test changed it.
    pub fn reseal_head<K: Kek>(&mut self, kek: &K) {
        self.head_sealed = seal_head(kek, &self.head_key, &self.head);
    }
}
