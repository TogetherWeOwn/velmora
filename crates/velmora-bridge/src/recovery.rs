//! Catalogue recovery records (DESIGN §A.8).
//!
//! The catalogue database can be lost or rolled back. Every acknowledged
//! PutObject, CopyObject, CompleteMultipartUpload and DeleteObject is
//! therefore also written to `SAFETY`, sealed, **before** its catalogue
//! batch runs:
//!
//! | Blob key | Record | Written |
//! |---|---|---|
//! | `m/<generation_id>` | [`GenerationManifest`]: bucket, generation, every extent | before the publication batch |
//! | `m/del/<tombstone_id>` | [`Tombstone`]: bucket, key | before the delete batch |
//! | `m/art/<extent_id>` | [`ArticleManifest`]: the article plan | after the plan is stored, before any POST |
//!
//! Generation and tombstone ids start with their mint time, so the blob
//! keys list in time order and a replay can start at a restore point.
//! Records are key-bearing copies: they hold wrapped keys, never plain
//! ones, and they open only under the KEK version that sealed them.
//!
//! No delete that the catalogue asks for removes a record: release,
//! garbage collection and evict delete blobs through [`delete_blob`],
//! which refuses `m/*`. The one other delete is by the writer itself: a
//! request whose batch was refused (a definite failure, answered as one)
//! removes the record it has just written, because nothing was published
//! under that id. A record of a request that failed with an unknown
//! outcome stays, and a replay may publish it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;

use crate::crypto::{open_manifest, seal_manifest};
use crate::ports::{BlobMeta, BlobStore, Kek};
use crate::types::{
    ArticleRow, ArticleState, BridgeError, Bucket, BucketId, ExtentId, ExtentRow, ExtentState,
    GenerationId, GenerationRow, GenerationState, Result, SafetyState, UnixMs,
};

/// Every recovery record lives under this prefix.
pub const RECORD_PREFIX: &str = "m/";
/// Generation manifests: `m/` + a generation id (`g_…`).
pub const GENERATION_PREFIX: &str = "m/g_";
/// Tombstones: `m/del/` + a tombstone id (`g_…`).
pub const TOMBSTONE_PREFIX: &str = "m/del/g_";
const TOMBSTONE_DIR: &str = "m/del/";
const ARTICLE_DIR: &str = "m/art/";

/// Format version of every record.
const RECORD_VERSION: u32 = 1;

const ERR_RECORD: BridgeError = BridgeError::Invalid("recovery record is malformed");

pub fn generation_key(id: &GenerationId) -> String {
    format!("{RECORD_PREFIX}{}", id.as_str())
}

pub fn tombstone_key(id: &GenerationId) -> String {
    format!("{TOMBSTONE_DIR}{}", id.as_str())
}

pub fn article_key(extent: &ExtentId) -> String {
    format!("{ARTICLE_DIR}{}", extent.as_str())
}

/// The first blob key of generation manifests (or tombstones, with
/// [`TOMBSTONE_PREFIX`]) minted at or after `since`: every such key sorts
/// after the returned one.
pub fn start_after(prefix: &str, since: UnixMs) -> String {
    let ms = since.0.clamp(0, 0x000f_ffff_ffff_ffff);
    format!("{prefix}{ms:013x}")
}

/// Whether `key` names a recovery record.
pub fn is_record_key(key: &str) -> bool {
    key.starts_with(RECORD_PREFIX)
}

/// Deletes a ciphertext blob. Release, garbage collection and evict
/// delete through this function only: it refuses every recovery record,
/// whatever the catalogue row that asked for the delete says.
pub async fn delete_blob<B: BlobStore>(store: &B, key: &str) -> Result<()> {
    if is_record_key(key) {
        return Err(BridgeError::Invalid("recovery records are never deleted"));
    }
    store.delete(key).await
}

/// Mint time of a generation or tombstone id (`g_` + 13 hex digits of
/// milliseconds + random hex).
fn minted_ms(id: &GenerationId) -> Option<i64> {
    let hex = id.as_str().strip_prefix("g_")?.get(..13)?;
    i64::from_str_radix(hex, 16).ok()
}

/// The id of the tombstone for a delete that saw `live` as the live
/// generation. It always sorts after `live`, also when this isolate's
/// clock is behind the one that minted `live`.
pub fn tombstone_id(now: UnixMs, live: &GenerationId, rand: [u8; 8]) -> GenerationId {
    id_after(now, live, rand)
}

/// The id of a copy of `source` that replaces `replaced`, the live
/// generation of the destination key, if there is one. It always sorts
/// after both, also when this isolate's clock is behind the ones that
/// minted them: a replay then applies the source first and never puts
/// the replaced generation back over the copy.
pub fn copy_id(
    now: UnixMs,
    source: &GenerationId,
    replaced: Option<&GenerationId>,
    rand: [u8; 8],
) -> GenerationId {
    let newest = match replaced {
        Some(r) if r > source => r,
        _ => source,
    };
    id_after(now, newest, rand)
}

fn id_after(now: UnixMs, older: &GenerationId, rand: [u8; 8]) -> GenerationId {
    let after = minted_ms(older).map_or(now.0, |ms| ms.saturating_add(1));
    GenerationId::mint(UnixMs(now.0.max(after)), rand)
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

/// `buckets` row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketRecord {
    pub id: String,
    pub name: String,
    pub owner: String,
    #[serde(with = "b64")]
    pub bdk_wrapped: Vec<u8>,
    pub kek_version: u32,
    pub disposable: bool,
    pub created_at: i64,
}

/// `generations` row of a live generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationRecord {
    pub id: String,
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub checksum_json: Option<String>,
    pub content_json: String,
    pub user_meta_json: String,
    pub created_at: i64,
}

/// One extent of a generation, with its place in that generation. The
/// extent may also belong to other generations; each manifest describes
/// it in full.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtentRecord {
    pub id: String,
    pub seq: u32,
    pub plain_offset: u64,
    pub plain_size: u64,
    pub cipher_size: u64,
    #[serde(with = "b64")]
    pub media_header: Vec<u8>,
    pub key_mode: u8,
    #[serde(with = "b64")]
    pub wrapped_file_key: Vec<u8>,
    #[serde(with = "b64")]
    pub plain_md5: Vec<u8>,
    #[serde(with = "b64")]
    pub plain_sha256: Vec<u8>,
    #[serde(with = "b64")]
    pub cipher_sha256: Vec<u8>,
    pub created_at: i64,
}

/// `m/<generation_id>`: everything the catalogue holds about one
/// published generation, except its article plans.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationManifest {
    pub v: u32,
    pub bucket: BucketRecord,
    pub generation: GenerationRecord,
    /// In `seq` order.
    pub extents: Vec<ExtentRecord>,
}

/// `m/del/<tombstone_id>`: the key had no object once every generation
/// older than the tombstone was applied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    pub v: u32,
    pub id: String,
    pub bucket_id: String,
    pub key: String,
    pub deleted_at: i64,
}

/// One planned article.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArticleRecord {
    pub idx: u32,
    pub message_id: String,
    pub newsgroup: String,
    #[serde(with = "b64")]
    pub headers: Vec<u8>,
    pub cipher_offset: u64,
    pub cipher_len: u64,
    #[serde(with = "b64")]
    pub payload_sha256: Vec<u8>,
}

/// `m/art/<extent_id>`: where the extent's ciphertext is on Usenet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArticleManifest {
    pub v: u32,
    pub extent_id: String,
    pub plan_rev: u32,
    /// In `idx` order.
    pub articles: Vec<ArticleRecord>,
}

fn digest<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| ERR_RECORD)
}

impl GenerationManifest {
    /// `extents` are the generation's extents in order; each row's `seq`
    /// and `plain_offset` are its place in **this** generation.
    pub fn new(bucket: &Bucket, generation: &GenerationRow, extents: &[ExtentRow]) -> Result<Self> {
        let extents = extents
            .iter()
            .map(|e| {
                Ok(ExtentRecord {
                    id: e.id.as_str().to_owned(),
                    seq: e.seq.ok_or(ERR_RECORD)?,
                    plain_offset: e.plain_offset.ok_or(ERR_RECORD)?,
                    plain_size: e.plain_size,
                    cipher_size: e.cipher_size,
                    media_header: e.media_header.clone(),
                    key_mode: e.key_mode,
                    // An extent without its key cannot be read back.
                    wrapped_file_key: e.wrapped_file_key.clone().ok_or(ERR_RECORD)?,
                    plain_md5: e.plain_md5.to_vec(),
                    plain_sha256: e.plain_sha256.to_vec(),
                    cipher_sha256: e.cipher_sha256.to_vec(),
                    created_at: e.created_at.0,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if generation.bucket_id != bucket.id
            || usize::try_from(generation.extent_count).ok() != Some(extents.len())
        {
            return Err(ERR_RECORD);
        }
        Ok(GenerationManifest {
            v: RECORD_VERSION,
            bucket: BucketRecord {
                id: bucket.id.as_str().to_owned(),
                name: bucket.name.clone(),
                owner: bucket.owner.clone(),
                bdk_wrapped: bucket.bdk_wrapped.clone(),
                kek_version: bucket.kek_version,
                disposable: bucket.disposable,
                created_at: bucket.created_at.0,
            },
            generation: GenerationRecord {
                id: generation.id.as_str().to_owned(),
                key: generation.key.clone(),
                size: generation.size,
                etag: generation.etag.clone(),
                checksum_json: generation.checksum_json.clone(),
                content_json: generation.content_json.clone(),
                user_meta_json: generation.user_meta_json.clone(),
                created_at: generation.created_at.0,
            },
            extents,
        })
    }

    pub fn bucket(&self) -> Bucket {
        let b = &self.bucket;
        Bucket {
            id: BucketId::new(b.id.clone()),
            name: b.name.clone(),
            owner: b.owner.clone(),
            bdk_wrapped: b.bdk_wrapped.clone(),
            kek_version: b.kek_version,
            disposable: b.disposable,
            created_at: UnixMs(b.created_at),
        }
    }

    /// The generation as it was published: live.
    pub fn generation(&self) -> Result<GenerationRow> {
        let g = &self.generation;
        Ok(GenerationRow {
            id: GenerationId::new(g.id.clone()),
            bucket_id: BucketId::new(self.bucket.id.clone()),
            key: g.key.clone(),
            state: GenerationState::Live,
            size: g.size,
            etag: g.etag.clone(),
            checksum_json: g.checksum_json.clone(),
            content_json: g.content_json.clone(),
            user_meta_json: g.user_meta_json.clone(),
            extent_count: u32::try_from(self.extents.len()).map_err(|_| ERR_RECORD)?,
            created_at: UnixMs(g.created_at),
            retired_at: None,
        })
    }

    /// Extent `index` as a committed row of this generation whose safety
    /// copy is held and that has no article plan yet.
    pub fn extent(&self, index: usize) -> Result<ExtentRow> {
        let e = self.extents.get(index).ok_or(ERR_RECORD)?;
        Ok(ExtentRow {
            id: ExtentId::new(e.id.clone()),
            bucket_id: BucketId::new(self.bucket.id.clone()),
            generation_id: Some(GenerationId::new(self.generation.id.clone())),
            state: ExtentState::Committed,
            seq: Some(e.seq),
            plain_offset: Some(e.plain_offset),
            plain_size: e.plain_size,
            cipher_size: e.cipher_size,
            media_header: e.media_header.clone(),
            key_mode: e.key_mode,
            wrapped_file_key: Some(e.wrapped_file_key.clone()),
            plain_md5: digest(&e.plain_md5)?,
            plain_sha256: digest(&e.plain_sha256)?,
            cipher_sha256: digest(&e.cipher_sha256)?,
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: UnixMs(e.created_at),
        })
    }
}

impl ArticleManifest {
    pub fn new(extent: &ExtentRow, plan: &[ArticleRow]) -> Self {
        ArticleManifest {
            v: RECORD_VERSION,
            extent_id: extent.id.as_str().to_owned(),
            // A stored plan has revision 1 or more; `extent` may have
            // been read before the plan was stored.
            plan_rev: extent.plan_rev.max(1),
            articles: plan
                .iter()
                .map(|a| ArticleRecord {
                    idx: a.idx,
                    message_id: a.message_id.clone(),
                    newsgroup: a.newsgroup.clone(),
                    headers: a.headers.clone(),
                    cipher_offset: a.cipher_offset,
                    cipher_len: a.cipher_len,
                    payload_sha256: a.payload_sha256.to_vec(),
                })
                .collect(),
        }
    }

    /// The plan as `articles` rows in `state`.
    pub fn rows(&self, state: ArticleState) -> Result<Vec<ArticleRow>> {
        self.articles
            .iter()
            .map(|a| {
                Ok(ArticleRow {
                    extent_id: ExtentId::new(self.extent_id.clone()),
                    idx: a.idx,
                    message_id: a.message_id.clone(),
                    newsgroup: a.newsgroup.clone(),
                    headers: a.headers.clone(),
                    cipher_offset: a.cipher_offset,
                    cipher_len: a.cipher_len,
                    payload_sha256: digest(&a.payload_sha256)?,
                    state,
                    provider_id: None,
                    posted_at: None,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Seals `record` under the active KEK and stores it at `name`. `bucket`
/// and `subject` are only the blob's descriptive metadata.
async fn write<B: BlobStore, K: Kek, R: Serialize>(
    safety: &B,
    kek: &K,
    name: &str,
    bucket: &BucketId,
    subject: &str,
    record: &R,
) -> Result<()> {
    let plain = serde_json::to_vec(record).map_err(|_| ERR_RECORD)?;
    let sealed = seal_manifest(kek, name, &plain, &mut SystemRng)?;
    let sha: [u8; 32] = Sha256::digest(&sealed).into();
    let meta = BlobMeta {
        bucket,
        extent: &ExtentId::new(subject),
        cipher_sha256: &sha,
    };
    safety.put(name, sealed, &meta).await
}

/// `None` = no record at `name`. A record that does not open or parse is
/// an error, never an empty result.
async fn read<B: BlobStore, K: Kek, R: for<'de> Deserialize<'de>>(
    safety: &B,
    kek: &K,
    name: &str,
) -> Result<Option<R>> {
    let Some(sealed) = safety.get(name, None).await? else {
        return Ok(None);
    };
    let plain = open_manifest(kek, name, &sealed)?;
    #[derive(Deserialize)]
    struct Versioned {
        v: u32,
    }
    let head: Versioned = serde_json::from_slice(&plain).map_err(|_| ERR_RECORD)?;
    if head.v != RECORD_VERSION {
        return Err(BridgeError::Invalid("recovery record version is unknown"));
    }
    serde_json::from_slice(&plain)
        .map(Some)
        .map_err(|_| ERR_RECORD)
}

/// Writes `m/<generation_id>`. The caller publishes the generation only
/// after this returned `Ok`.
pub async fn write_generation<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    bucket: &Bucket,
    generation: &GenerationRow,
    extents: &[ExtentRow],
) -> Result<()> {
    let record = GenerationManifest::new(bucket, generation, extents)?;
    let name = generation_key(&generation.id);
    write(
        safety,
        kek,
        &name,
        &bucket.id,
        generation.id.as_str(),
        &record,
    )
    .await
}

/// Writes `m/del/<id>`. The caller deletes only after this returned `Ok`.
pub async fn write_tombstone<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    bucket: &BucketId,
    key: &str,
    id: &GenerationId,
    now: UnixMs,
) -> Result<()> {
    let record = Tombstone {
        v: RECORD_VERSION,
        id: id.as_str().to_owned(),
        bucket_id: bucket.as_str().to_owned(),
        key: key.to_owned(),
        deleted_at: now.0,
    };
    write(
        safety,
        kek,
        &tombstone_key(id),
        bucket,
        id.as_str(),
        &record,
    )
    .await
}

/// Writes `m/art/<extent_id>` from the plan the catalogue holds. An
/// extent's plan never changes, so a second write stores the same plan
/// again; it also replaces a record that no longer opens. The caller
/// posts only after this returned `Ok`.
pub async fn write_article_plan<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    extent: &ExtentRow,
    plan: &[ArticleRow],
) -> Result<()> {
    let name = article_key(&extent.id);
    let record = ArticleManifest::new(extent, plan);
    write(
        safety,
        kek,
        &name,
        &extent.bucket_id,
        extent.id.as_str(),
        &record,
    )
    .await
}

/// Reads the record stored at `name` (a key from a listing).
pub async fn read_generation<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    name: &str,
) -> Result<Option<GenerationManifest>> {
    let record: Option<GenerationManifest> = read(safety, kek, name).await?;
    match &record {
        // The record must be the one its name promises.
        Some(m) if generation_key(&GenerationId::new(m.generation.id.clone())) != name => {
            Err(ERR_RECORD)
        }
        _ => Ok(record),
    }
}

pub async fn read_tombstone<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    name: &str,
) -> Result<Option<Tombstone>> {
    let record: Option<Tombstone> = read(safety, kek, name).await?;
    match &record {
        Some(t) if tombstone_key(&GenerationId::new(t.id.clone())) != name => Err(ERR_RECORD),
        _ => Ok(record),
    }
}

pub async fn read_article_plan<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    extent: &ExtentId,
) -> Result<Option<ArticleManifest>> {
    let record: Option<ArticleManifest> = read(safety, kek, &article_key(extent)).await?;
    match &record {
        Some(a) if a.extent_id != extent.as_str() => Err(ERR_RECORD),
        _ => Ok(record),
    }
}
