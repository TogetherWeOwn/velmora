//! Scratch-object contract for Container repair, shared by the ingest
//! Worker (which stages inputs), the repair Worker (which streams them
//! into the Container) and the Container server (which materialises them
//! in its scratch directory).
//!
//! Layout under the `INGEST_SCRATCH` R2 bucket:
//!
//! - inputs: `ingest-scratch/{job_id}/r{round}/in/{sha256(file_name)}`
//!   plus `ingest-scratch/{job_id}/r{round}/in/manifest.json`
//! - outputs: `ingest-scratch/{job_id}/r{round}/out/{sha256(file_name)}`
//!   plus `ingest-scratch/{job_id}/r{round}/out/result.json`
//!
//! The prefix is derived, never trusted: callers validate an incoming
//! prefix by rebuilding it from `(job_id, round)` and comparing, so a
//! crafted prefix cannot point repair at another job's objects.
//!
//! `manifest.json` also carries a `staging_id`: the writer (verify)
//! derives it from every staged file's content hash, so identical
//! bytes keep the id and any byte change yields a new one. File names
//! and sizes alone do not identify a staging — a damaged file usually
//! keeps its full length — so repair idempotency keys on a digest that
//! includes the `staging_id`; otherwise a redriven job (which reuses
//! round 1) would replay the previous generation's verdict.

use sha2::{Digest, Sha256};

/// Root segment of every scratch prefix (matches the buckets' 7-day
/// lifecycle rule prefix).
pub const SCRATCH_ROOT: &str = "ingest-scratch";
/// One repair round stages at most this many files (data + par2).
pub const MAX_SCRATCH_FILES: usize = 1024;
/// Aggregate staged bytes per round, aligned with the default
/// `RepairLimits::max_workspace_bytes` ceiling.
pub const MAX_SCRATCH_TOTAL_BYTES: u64 = 8 << 30;
/// File names arrive from NZB/PAR2 metadata: one path component, bounded.
pub const MAX_FILE_NAME_BYTES: usize = 255;

/// Job ids travel in URLs and R2 keys: keep them narrow (same shape the
/// ingest job machine accepts).
fn validate_job_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Canonical scratch prefix for one repair round:
/// `ingest-scratch/{job_id}/r{round}/`. `None` for an unsafe job id or a
/// zero round (rounds are 1-based; the ingest budget caps the maximum).
pub fn scratch_prefix(job_id: &str, round: u32) -> Option<String> {
    if round == 0 || !validate_job_id(job_id) {
        return None;
    }
    Some(format!("{SCRATCH_ROOT}/{job_id}/r{round}/"))
}

/// True only when `prefix` is exactly the canonical prefix for
/// `(job_id, round)` — no extra segments, no traversal, no other job.
pub fn validate_scratch_prefix(prefix: &str, job_id: &str, round: u32) -> bool {
    scratch_prefix(job_id, round).as_deref() == Some(prefix)
}

/// A staged file name is a single path component: no separators, no
/// `.`/`..`, no NUL or control bytes, at most [`MAX_FILE_NAME_BYTES`].
pub fn validate_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE_NAME_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b != b'/' && b != b'\\' && b != 0 && !b.is_ascii_control())
}

/// Lowercase hex sha256 of `bytes` (64 chars).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Scratch object key for a staged file: lowercase hex sha256 of the
/// file name, so object keys never carry untrusted name bytes.
pub fn object_key_for_file_name(file_name: &str) -> String {
    sha256_hex(file_name.as_bytes())
}

/// A `staging_id` is the content-derived token for one staging
/// (verify hashes every staged file's index, content hash and size;
/// currently 64-char lowercase hex): 16–128 chars of `[A-Za-z0-9_-]`
/// are accepted, long enough that two stagings never collide in
/// practice. Anything else cannot prove which staging a stored
/// repair result belongs to, so it is rejected.
pub fn validate_staging_id(raw: &str) -> bool {
    (16..=128).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// True for a 64-char lowercase hex object key.
pub fn validate_object_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
