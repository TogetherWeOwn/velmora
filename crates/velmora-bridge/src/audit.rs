//! Independent read-only sample of the offsite recovery copy. No copy
//! cursor, marker, comparison, or decrypted data is used here.

use std::future::Future;

use serde::Serialize;

use crate::ports::Clock;
use crate::recovery::{start_after, Layout, RECORD_PREFIX, TENANT_KEY_PREFIX};
use crate::remote::{md5_hex, HttpSend, Problem, RemoteError, S3Remote, MAX_AUDIT_BYTES};
use crate::types::{Result, UnixMs};

const HOUR: i64 = 3_600_000;
const RECENT: usize = 10;
const OLD: usize = 5;
pub const PAGE_SIZE: u32 = 1_000;

pub struct AuditEntry {
    pub key: String,
    pub size: u64,
    pub uploaded: UnixMs,
}

pub struct AuditPage {
    pub objects: Vec<AuditEntry>,
    pub truncated: bool,
}

pub trait AuditSource {
    /// One listing page, in key order, with object size and upload time.
    fn page(&self, prefix: &str, after: &str) -> impl Future<Output = Result<AuditPage>>;
    /// Read the source body up to 1 MiB; absent or oversized is skipped.
    fn get(&self, key: &str) -> impl Future<Output = Result<Option<Vec<u8>>>>;
}

#[derive(Default, Serialize)]
pub struct AuditCounts {
    pub checked: u64,
    pub equal: u64,
    pub missing: u64,
    pub different: u64,
    pub refused: u64,
    pub unavailable: u64,
    pub source_errors: u64,
}

impl AuditCounts {
    pub fn problems(&self) -> u64 {
        self.missing + self.different + self.refused
    }
}

/// Keep the highest minted timestamps, with the key as a stable tiebreaker.
fn newest(entries: &mut Vec<(i64, AuditEntry)>) {
    entries.sort_unstable_by(|(a, ka), (b, kb)| (b, &kb.key).cmp(&(a, &ka.key)));
    entries.dedup_by(|a, b| a.1.key == b.1.key);
    entries.truncate(RECENT);
}

async fn recent(
    source: &impl AuditSource,
    prefix: &str,
    now: UnixMs,
    counts: &mut AuditCounts,
) -> Vec<(i64, AuditEntry)> {
    let (mut low, mut high) = (now.0 - 4 * HOUR, now.0 - 3 * HOUR / 2);
    let end = high;
    let mut from = low;
    let mut found = Vec::new();
    while low <= high {
        let after = start_after(prefix, UnixMs(from));
        let Ok(page) = source.page(prefix, &after).await else {
            counts.source_errors += 1;
            break;
        };
        let mut n = 0;
        let mut past_end = false;
        for object in page.objects {
            let Some(minted) = object
                .key
                .strip_prefix(prefix)
                .and_then(|id| id.get(..13))
                .and_then(|hex| i64::from_str_radix(hex, 16).ok())
            else {
                continue;
            };
            if minted > end {
                past_end = true;
                break;
            }
            if minted >= from && object.size <= MAX_AUDIT_BYTES as u64 {
                n += 1;
                found.push((minted, object));
            }
        }
        newest(&mut found);
        if (!page.truncated || past_end) && (from == low || n >= RECENT) {
            break;
        }
        // Normally one LIST per prefix. If a page fills before the end
        // of the time range, bisect by minted millisecond instead of
        // following an unbounded cursor. Each probe halves the range
        // (at most 25 LISTs per prefix including the first probe).
        if n >= RECENT {
            low = from + 1;
        } else {
            high = from - 1;
        }
        from = low + (high - low) / 2;
    }
    found
}

async fn old_page(
    source: &impl AuditSource,
    now: UnixMs,
    after: &str,
    counts: &mut AuditCounts,
) -> Vec<AuditEntry> {
    match source.page(RECORD_PREFIX, after).await {
        Ok(page) => page
            .objects
            .into_iter()
            .filter(|entry| {
                // The copier deliberately never sends even the name of a tenant key.
                !entry.key.starts_with(TENANT_KEY_PREFIX)
                    && entry.uploaded.0 < now.0 - 48 * HOUR
                    && entry.size <= MAX_AUDIT_BYTES as u64
            })
            .collect(),
        Err(_) => {
            counts.source_errors += 1;
            Vec::new()
        }
    }
}

/// Audit at most ten recent records and five old records from one random
/// page, with one fallback page if the probe produced no eligible keys.
/// Only successful source reads spend a destination GET.
pub async fn audit(
    source: &impl AuditSource,
    remote: &S3Remote<impl HttpSend>,
    clock: &impl Clock,
    now: UnixMs,
    random_after: &str,
    mut pick_old: impl FnMut(usize) -> usize,
) -> AuditCounts {
    let mut counts = AuditCounts::default();
    let mut recent_records = Vec::new();
    for layout in Layout::all() {
        for prefix in [layout.generation_prefix(), layout.tombstone_prefix()] {
            recent_records.extend(recent(source, &prefix, now, &mut counts).await);
        }
    }
    newest(&mut recent_records);
    let mut old = old_page(source, now, random_after, &mut counts).await;
    if old.is_empty() && random_after != RECORD_PREFIX {
        // From the start of m/ an empty flat layout naturally falls through
        // to the tenant layout; no second random anchor can skip both.
        old = old_page(source, now, RECORD_PREFIX, &mut counts).await;
    }
    // Select without replacement anywhere on the page, not just its first keys.
    for i in 0..old.len().min(OLD) {
        let remaining = old.len() - i;
        old.swap(i, i + pick_old(remaining) % remaining);
    }
    let recent = recent_records.into_iter().map(|(_, entry)| entry);
    for entry in recent.chain(old.into_iter().take(OLD)) {
        let bytes = match source.get(&entry.key).await {
            Ok(Some(bytes)) if bytes.len() <= MAX_AUDIT_BYTES => bytes,
            Ok(_) => continue,
            Err(_) => {
                counts.source_errors += 1;
                continue;
            }
        };
        counts.checked += 1;
        match remote.get(clock, &entry.key).await {
            Ok(None) => counts.missing += 1,
            Ok(Some(copy)) if bytes.len() == copy.len() && md5_hex(&bytes) == md5_hex(&copy) => {
                counts.equal += 1
            }
            Ok(Some(_)) => {
                counts.different += 1;
                remote.transport().observe(Problem {
                    operation: "get",
                    kind: "mismatch",
                    status: Some(200),
                    code: None,
                });
            }
            // A successful destination response that exceeds the body
            // bound already proves the size differs from this small source.
            Err(RemoteError::Mismatch) => counts.different += 1,
            Err(RemoteError::Refused(status)) if (400..500).contains(&status) => {
                counts.refused += 1
            }
            Err(_) => counts.unavailable += 1,
        }
    }
    counts
}
