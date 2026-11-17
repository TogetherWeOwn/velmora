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
//! On one key the ids are also in commit order. Before a record is
//! stored, the catalogue raises the key's floor to the record's id
//! ([`Catalog::raise_floor`], inside [`write_generation`] and
//! [`write_tombstone`]), and a publication is refused unless its id
//! sorts after the live generation and is not below the floor
//! ([`id_after`]). Every id therefore sorts after every record stored
//! on the key before it: also after the tombstone of a delete that found
//! nothing left to delete, and after the record of a write whose batch
//! failed or whose record could not be removed. Replaying the records in
//! id order then rebuilds what the catalogue served, whatever the clocks
//! said and whatever became of the other writes.
//! Records are key-bearing copies: they hold wrapped keys, never plain
//! ones, and they open only under the KEK version that sealed them.
//!
//! Two rules are held by types, not by care at the call sites:
//!
//! - **Record before commit.** The catalogue publishes a generation
//!   only against a [`Recorded`], and only [`write_generation`] makes
//!   one, after the record is stored.
//! - **No delete removes a record.** [`BlobStore::delete`] refuses every
//!   key under `m/`, in the store adapter itself. The one way to remove
//!   a record is [`discard_generation`], and it takes an
//!   [`Unpublished`]: what the catalogue makes of the [`Recorded`] when
//!   it refused the publication (a definite failure: nothing was
//!   published under that id). A `Recorded` alone does not delete, so a
//!   record cannot be discarded before the catalogue was asked. When the
//!   outcome is unknown the proof is gone with the call, so the record
//!   stays, and so does one whose removal failed. A replay publishes
//!   such a record, in its place in the order: under every write and
//!   delete acknowledged after it.

use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;

use crate::crypto::{open_manifest, seal_manifest};
use crate::plan::StoredPlan;
use crate::ports::{BlobMeta, BlobStore, Catalog, Kek};
use crate::types::{
    valid_yenc_name, ArticleRow, ArticleState, BridgeError, Bucket, BucketId, ExtentId, ExtentRow,
    ExtentState, GenerationId, GenerationRow, GenerationState, Result, SafetyState, UnixMs,
};

/// Every recovery record lives under this prefix.
pub const RECORD_PREFIX: &str = "m/";
/// Generation manifests: `m/` + a generation id (`g_…`).
pub const GENERATION_PREFIX: &str = "m/g_";
/// Tombstones: `m/del/` + a tombstone id (`g_…`).
pub const TOMBSTONE_PREFIX: &str = "m/del/g_";
const TOMBSTONE_DIR: &str = "m/del/";
/// Article plans: `m/art/` + an extent id.
pub(crate) const ARTICLE_DIR: &str = "m/art/";

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

/// The blob keys of the article plans that a generation record names,
/// in the order of its extents, from the plaintext of the record.
/// `None` = the plaintext does not name its extents, or names one that
/// is not an extent id.
pub fn plan_keys(plain: &[u8]) -> Option<Vec<String>> {
    #[derive(Deserialize)]
    struct Extent {
        id: String,
    }
    #[derive(Deserialize)]
    struct Named {
        extents: Vec<Extent>,
    }
    let named: Named = serde_json::from_slice(plain).ok()?;
    let id = |id: &str| {
        id.strip_prefix("x_").is_some_and(|rest| {
            (1..=64).contains(&rest.len())
                && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    };
    named
        .extents
        .iter()
        .map(|e| id(&e.id).then(|| format!("{ARTICLE_DIR}{}", e.id)))
        .collect()
}

/// Reserved for tenant keys. It lies under [`RECORD_PREFIX`], so no
/// delete removes such a key, and none of the record kinds above match
/// it, so a replay does not read one as a record.
pub const TENANT_KEY_PREFIX: &str = "m/tk/";

/// Revoked access keys: `m/rk/` + an access key id. It lies under
/// [`RECORD_PREFIX`], so no delete removes one and the recovery copy
/// carries it, and none of the record kinds a replay reads match it.
pub const REVOKED_KEY_PREFIX: &str = "m/rk/";

/// Longest access key id the admin API takes (the ones it mints have 20
/// characters).
pub const MAX_KEY_ID_LEN: usize = 128;

/// An access key id the admin API accepts: 1 to [`MAX_KEY_ID_LEN`] ASCII
/// letters and digits. Nothing else reaches a catalogue query or a blob
/// name.
pub fn valid_key_id(akid: &str) -> bool {
    (1..=MAX_KEY_ID_LEN).contains(&akid.len()) && akid.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The name of the revocation record of `akid`.
pub fn revocation_key(akid: &str) -> String {
    format!("{REVOKED_KEY_PREFIX}{akid}")
}

/// The access key id a revocation record is named for; `None` for a
/// name that is not one.
pub fn revoked_key_id(name: &str) -> Option<&str> {
    name.strip_prefix(REVOKED_KEY_PREFIX)
        .filter(|akid| valid_key_id(akid))
}

/// Whether `key` names a recovery record.
pub fn is_record_key(key: &str) -> bool {
    key.starts_with(RECORD_PREFIX)
}

/// Whether `key` is one that no delete may remove: a recovery record
/// (which includes [`TENANT_KEY_PREFIX`]) or a rollback stamp.
pub fn is_protected_key(key: &str) -> bool {
    is_record_key(key) || crate::stamp::is_stamp_key(key)
}

/// What a store answers to a delete of a recovery record or of a
/// rollback stamp.
pub const ERR_RECORD_DELETE: BridgeError =
    BridgeError::Invalid("recovery records are never deleted");

/// Deletes a ciphertext blob for release, garbage collection and evict.
/// It refuses every recovery record before the store is asked, whatever
/// the catalogue row that asked for the delete says; the store refuses
/// them too ([`BlobStore::delete`]).
pub async fn delete_blob<B: BlobStore>(store: &B, key: &str) -> Result<()> {
    if is_protected_key(key) {
        return Err(ERR_RECORD_DELETE);
    }
    store.delete(key).await
}

/// Proof that the recovery record of one generation is stored in
/// `SAFETY`. [`write_generation`] is the only place that makes one; the
/// catalogue publishes a generation only against it, and turns it into
/// an [`Unpublished`] when it refused.
#[derive(Debug, PartialEq, Eq)]
pub struct Recorded {
    generation: GenerationId,
}

impl Recorded {
    /// The generation whose record is stored.
    pub fn generation(&self) -> &GenerationId {
        &self.generation
    }

    /// Blob key of the record.
    pub fn key(&self) -> String {
        generation_key(&self.generation)
    }

    /// The catalogue refused the publication and wrote nothing under
    /// the id. Only the SQL catalogue can say so: nothing outside
    /// `crate::sql` can make the `GuardRefused` this takes.
    pub(crate) fn refused(self, _: crate::sql::GuardRefused) -> Unpublished {
        Unpublished {
            generation: self.generation,
        }
    }

    /// A proof without a record, for catalogue tests that publish rows
    /// directly. Never compiled into the Worker.
    #[cfg(feature = "testkit")]
    pub fn for_test(generation: &GenerationId) -> Recorded {
        Recorded {
            generation: generation.clone(),
        }
    }
}

/// Proof that a stored record belongs to a generation the catalogue
/// refused to publish. Made only from a [`Recorded`] by a catalogue
/// whose publication batch wrote nothing; it is what
/// [`discard_generation`] takes.
#[derive(Debug, PartialEq, Eq)]
pub struct Unpublished {
    generation: GenerationId,
}

impl Unpublished {
    /// The generation that was not published.
    pub fn generation(&self) -> &GenerationId {
        &self.generation
    }

    /// Blob key of the record.
    pub fn key(&self) -> String {
        generation_key(&self.generation)
    }
}

/// Mint time of a generation or tombstone id (`g_` + 13 hex digits of
/// milliseconds + random hex).
fn minted_ms(id: &GenerationId) -> Option<i64> {
    let hex = id.as_str().strip_prefix("g_")?.get(..13)?;
    i64::from_str_radix(hex, 16).ok()
}

/// An id that sorts after `newest`, the newest id already on the key
/// (its live generation or its floor): at least one millisecond later,
/// also when this isolate's clock is behind the one that minted it.
pub fn id_after(now: UnixMs, newest: Option<&GenerationId>, rand: [u8; 8]) -> GenerationId {
    let floor = newest
        .and_then(minted_ms)
        .map_or(now.0, |ms| ms.saturating_add(1));
    GenerationId::mint(UnixMs(now.0.max(floor)), rand)
}

/// The id of the tombstone for a delete that saw `newest` as the newest
/// id of the key ([`Catalog::newest_id`], at or above the live
/// generation). It always sorts after it.
pub fn tombstone_id(now: UnixMs, newest: &GenerationId, rand: [u8; 8]) -> GenerationId {
    id_after(now, Some(newest), rand)
}

/// Removes the record of a generation whose publication batch was
/// refused: nothing was published under the id, so nothing may replay
/// it. The one delete of a record there is (see the module doc).
pub async fn discard_generation<B: BlobStore>(safety: &B, refused: &Unpublished) -> Result<()> {
    safety.delete_record(refused).await
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

mod opt_b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => s.serialize_str(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(text) => STANDARD
                .decode(text)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
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

/// `m/rk/<access_key_id>`: the key was revoked. A catalogue export made
/// before that still holds its row; a restore deletes every key named
/// by such a record before it replays anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRevocation {
    pub v: u32,
    pub access_key_id: String,
    pub revoked_at: i64,
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
    /// The article's own yEnc name (a standalone single-part article).
    /// Absent in a record of a row planned before standalone articles,
    /// and left out when the row has none, so such a record is the same
    /// bytes as before and a replayed row reposts in the form it was
    /// posted in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yenc_name: Option<String>,
}

/// `m/art/<extent_id>`: where the extent's ciphertext is on Usenet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArticleManifest {
    pub v: u32,
    pub extent_id: String,
    pub plan_rev: u32,
    /// In `idx` order.
    pub articles: Vec<ArticleRecord>,
    /// The same plan in its seeded packed form ([`crate::plan`]), when
    /// the catalogue holds it that way: a replay gives the catalogue the
    /// small form back, after it has checked it against `articles`. A
    /// reader from before this field skips it.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_b64")]
    pub packed: Option<Vec<u8>>,
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
    /// The record of a plan with its packed form, when it has a seeded
    /// one. The other packed form holds what `articles` holds, and is
    /// made from it again.
    pub fn of(extent: &ExtentRow, plan: &StoredPlan) -> Self {
        let packed = plan.packed.as_ref();
        ArticleManifest {
            packed: packed
                .filter(|p| crate::plan::seed_of(p).is_some())
                .cloned(),
            ..Self::new(extent, &plan.rows)
        }
    }

    pub fn new(extent: &ExtentRow, plan: &[ArticleRow]) -> Self {
        ArticleManifest {
            v: RECORD_VERSION,
            extent_id: extent.id.as_str().to_owned(),
            // A stored plan has revision 1 or more; `extent` may have
            // been read before the plan was stored.
            plan_rev: extent.plan_rev.max(1),
            packed: None,
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
                    yenc_name: a.yenc_name.clone(),
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
                    // The catalogue would refuse any other name, and a
                    // replay's insert skips a refused row without a word:
                    // such a record is unreadable instead.
                    yenc_name: match &a.yenc_name {
                        Some(name) if !valid_yenc_name(name) => return Err(ERR_RECORD),
                        name => name.clone(),
                    },
                    state,
                    provider_id: None,
                    posted_at: None,
                    reposted_at: None,
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

/// Writes `m/<generation_id>`, after it raised the floor of the key to
/// the id, and returns the proof of it, without which the catalogue
/// publishes nothing.
pub async fn write_generation<C: Catalog, B: BlobStore, K: Kek>(
    catalog: &C,
    safety: &B,
    kek: &K,
    bucket: &Bucket,
    generation: &GenerationRow,
    extents: &[ExtentRow],
) -> Result<Recorded> {
    let record = GenerationManifest::new(bucket, generation, extents)?;
    catalog
        .raise_floor(&bucket.id, &generation.key, &generation.id, true)
        .await?;
    let name = generation_key(&generation.id);
    write(
        safety,
        kek,
        &name,
        &bucket.id,
        generation.id.as_str(),
        &record,
    )
    .await?;
    Ok(Recorded {
        generation: generation.id.clone(),
    })
}

/// Writes `m/del/<id>`, after it raised the floor of the key to the id.
/// The caller deletes only after this returned `Ok`.
pub async fn write_tombstone<C: Catalog, B: BlobStore, K: Kek>(
    catalog: &C,
    safety: &B,
    kek: &K,
    bucket: &BucketId,
    key: &str,
    id: &GenerationId,
    now: UnixMs,
) -> Result<()> {
    catalog.raise_floor(bucket, key, id, false).await?;
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
    .await?;
    // On record: it covers every generation record of the key that was
    // stored under a lower id and never published.
    catalog.settle_floor(bucket, key, id).await
}

/// A tombstone to store: the key, the id and the time of the delete.
pub struct NewTombstone<'a> {
    pub key: &'a str,
    pub id: GenerationId,
    pub now: UnixMs,
}

/// How many tombstone records of one [`write_tombstones`] call are on
/// their way to the store at the same time.
const RECORD_WRITES: usize = 6;

/// [`write_tombstone`] for several keys of one bucket, each key once,
/// with the catalogue calls of all of them in one batch each: the
/// floors are raised, then every record is stored, then the floors of
/// the stored ones are settled. The answer has, for each tombstone in
/// its order, what `write_tombstone` would have answered; the caller
/// deletes a key only where it is `Ok`.
///
/// `Err` = a catalogue batch failed. Then no key may be deleted on its
/// tombstone: either no record was stored at all, or the records stand
/// with their floors raised and not settled, as after a
/// `write_tombstone` that failed at the same step.
pub async fn write_tombstones<C: Catalog, B: BlobStore, K: Kek>(
    catalog: &C,
    safety: &B,
    kek: &K,
    bucket: &BucketId,
    tombstones: &[NewTombstone<'_>],
) -> Result<Vec<Result<()>>> {
    if tombstones.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<(&str, &GenerationId)> = tombstones.iter().map(|t| (t.key, &t.id)).collect();
    catalog.raise_floors(bucket, &ids).await?;
    let stored: Vec<Result<()>> = stream::iter(tombstones)
        .map(|t| async move {
            let record = Tombstone {
                v: RECORD_VERSION,
                id: t.id.as_str().to_owned(),
                bucket_id: bucket.as_str().to_owned(),
                key: t.key.to_owned(),
                deleted_at: t.now.0,
            };
            write(
                safety,
                kek,
                &tombstone_key(&t.id),
                bucket,
                t.id.as_str(),
                &record,
            )
            .await
        })
        .buffered(RECORD_WRITES)
        .collect()
        .await;
    let on_record: Vec<(&str, &GenerationId)> = ids
        .iter()
        .zip(&stored)
        .filter(|(_, stored)| stored.is_ok())
        .map(|(id, _)| *id)
        .collect();
    if !on_record.is_empty() {
        catalog.settle_floors(bucket, &on_record).await?;
    }
    Ok(stored)
}

/// Writes `m/rk/<access_key_id>`. The caller deletes the key's rows only
/// after this returned `Ok`, so no key is gone from the catalogue
/// without the record that keeps it gone across a restore. Writing it
/// again (a revocation that is retried) stores the same facts.
pub async fn write_key_revocation<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    akid: &str,
    now: UnixMs,
) -> Result<()> {
    if !valid_key_id(akid) {
        return Err(BridgeError::Invalid("access key id is malformed"));
    }
    let record = KeyRevocation {
        v: RECORD_VERSION,
        access_key_id: akid.to_owned(),
        revoked_at: now.0,
    };
    // No bucket: the descriptive metadata says "-", as for the other
    // blobs that belong to none.
    write(
        safety,
        kek,
        &revocation_key(akid),
        &BucketId::new("-"),
        akid,
        &record,
    )
    .await
}

/// Whether a revocation record of `akid` is stored. By its name alone,
/// as a restore reads them: forging one needs write access to `SAFETY`
/// and could only refuse a key.
pub async fn revocation_recorded<B: BlobStore>(safety: &B, akid: &str) -> Result<bool> {
    if !valid_key_id(akid) {
        return Ok(false);
    }
    Ok(safety.head(&revocation_key(akid)).await?.is_some())
}

/// Reads the revocation record of `akid`; `None` when there is none.
pub async fn read_key_revocation<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    akid: &str,
) -> Result<Option<KeyRevocation>> {
    read(safety, kek, &revocation_key(akid)).await
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
    write_stored_plan(
        safety,
        kek,
        extent,
        &StoredPlan {
            rows: plan.to_vec(),
            packed: None,
        },
    )
    .await
}

/// [`write_article_plan`] for a plan as the catalogue holds it: the
/// record also carries its seeded packed form.
pub async fn write_stored_plan<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    extent: &ExtentRow,
    plan: &StoredPlan,
) -> Result<()> {
    let name = article_key(&extent.id);
    let record = ArticleManifest::of(extent, plan);
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
