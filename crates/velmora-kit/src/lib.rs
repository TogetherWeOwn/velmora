//! Native-only codecs for the Velmora recovery kit. No network access or
//! key discovery; callers supply the key ring and a destination explicitly.

mod builder;
mod index;
mod packs;

pub use builder::{
    build_entries, cross_check, eligible_record, BuildAnnotations, Comparison, Release,
};
pub use packs::verify_packs;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use index::{read_index, write_index};

/// Deliberately excludes backend errors which might quote sealed metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io,
    Format,
    Authentication,
    Compression,
    Record,
    Coverage,
}

impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Io => "recovery kit I/O failed",
            Self::Format => "invalid recovery kit format",
            Self::Authentication => "recovery kit authentication failed",
            Self::Compression => "invalid recovery kit compression",
            Self::Record => "invalid or missing recovery record",
            Self::Coverage => "recovery record coverage check failed",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Entry {
    Bucket(Bucket),
    Object(Object),
    Extent(Extent),
    RecordRef(RecordRef),
}

// The index contains customer metadata. Debug never exposes entry content.
impl std::fmt::Debug for Entry {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Bucket(_) => "Entry::Bucket(<redacted>)",
            Self::Object(_) => "Entry::Object(<redacted>)",
            Self::Extent(_) => "Entry::Extent(<redacted>)",
            Self::RecordRef(_) => "Entry::RecordRef(<redacted>)",
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    pub id: String,
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub bdk_wrapped: Vec<u8>,
    pub kek_version: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Object {
    pub bucket_id: String,
    pub key: String,
    pub generation_id: String,
    pub size: u64,
    pub etag: String,
    pub content_type: Option<String>,
    pub user_meta: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_md5: Option<serde_bytes::ByteBuf>,
    pub extents: Vec<ExtentRef>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtentRef {
    pub id: String,
    pub plain_offset: u64,
    pub plain_size: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extent {
    pub id: String,
    pub bucket_id: String,
    pub plain_size: u64,
    pub cipher_size: u64,
    #[serde(with = "serde_bytes")]
    pub media_header: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub wrapped_file_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub plain_md5: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub plain_sha256: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub cipher_sha256: Vec<u8>,
    pub plan_rev: Option<u32>,
    pub articles: Vec<Article>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parity: Option<Parity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<Vec<Verified>>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Article {
    pub message_id: String,
    pub newsgroup: String,
    #[serde(with = "serde_bytes")]
    pub payload_sha256: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yenc_name: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parity {
    pub k: u16,
    pub shard_len: u32,
    pub rows: Vec<ParityRow>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityRow {
    pub row: u16,
    pub message_id: String,
    pub newsgroup: String,
    #[serde(with = "serde_bytes")]
    pub payload_sha256: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified {
    pub backbone: String,
    pub kind: String,
    pub at: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRef {
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub sha256: Vec<u8>,
}
