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
//! | `m/seg/<set id>/<index>` | [`Segment`]: one run of the extents of a segmented generation record | before the head that names it |
//!
//! Those are the names of the **flat layout**, which every record
//! written before the tenant layout has and keeps: a record is never
//! renamed. The **tenant layout** ([`Layout`]) puts the same names
//! in a directory of their tenant, `m/x/<tenant id>/`, in place of
//! `m/`: `m/x/<tenant id>/g_…`, `m/x/<tenant id>/del/g_…`,
//! `m/x/<tenant id>/art/<extent_id>`, `m/x/<tenant id>/seg/…`. Which of
//! the two a new record gets is a setting (`RECORD_LAYOUT`); every
//! reader reads both, whatever the setting, and for ever.
//!
//! A generation record has one of two formats. **Format 1**
//! ([`GenerationManifest`]) is one document with every extent, and it
//! is what every write stores. **Format 2** is for an object of more
//! extents than one document should hold: the extents are cut into
//! [`Segment`]s in `seq` order, each sealed under its own name, and a
//! [`GenerationHead`] stands where the format-1 record stands. The head
//! has the object without its extents and, for every segment, where it
//! begins, how much it holds and the SHA-256 of its sealed bytes. The
//! segments are stored before the head. A reader takes every count from
//! the head and believes a segment only if it is the one the head
//! names ([`GenerationHead::open_segment`]); a record with a segment
//! that is missing, does not open or does not match is unreadable as a
//! whole. This version reads format 2 and does not write it.
//!
//! Generation and tombstone ids start with their mint time, so the blob
//! keys of one layout list in time order and a replay can start at a restore point.
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
/// Generation manifests of the flat layout: `m/` + a generation id
/// (`g_…`).
pub const GENERATION_PREFIX: &str = "m/g_";
/// Tombstones of the flat layout: `m/del/` + a tombstone id (`g_…`).
pub const TOMBSTONE_PREFIX: &str = "m/del/g_";
/// The records of the tenant layout: `m/x/` + a tenant id + `/`, then
/// what the flat layout has after its `m/`. It lies under
/// [`RECORD_PREFIX`], so no delete removes such a key, in a Worker of
/// any version, and the walk of the recovery copy reaches it. It sorts
/// after every other family under `m/` (`m/art/`, `m/del/`, `m/g_`,
/// `m/rk/`, `m/seg/`, `m/tk/`, and `m/k/`, `m/t/`, `m/tref/`, `m/u/`,
/// which are left free for records about a tenant itself), so the sweep of the
/// recovery copy that ends here passes over all of them, and holds
/// nothing but these records.
pub const TENANT_DIR: &str = "m/x/";
/// The one tenant there is: the owner of every bucket.
pub const DEFAULT_TENANT: &str = "t_0000000000000000";
/// Longest tenant id a record name takes, after its `t_`.
const MAX_TENANT_ID_LEN: usize = 64;

const GENERATION_NAME: &str = "g_";
const TOMBSTONE_NAME: &str = "del/g_";
const ARTICLE_NAME: &str = "art/";
const SEGMENT_NAME: &str = "seg/";

/// Format version of every record that is one document.
const RECORD_VERSION: u32 = 1;
/// Format version of a segmented generation record: of its head and of
/// each of its segments.
pub const SEGMENTED_VERSION: u32 = 2;
/// Most segments one head names: a head with more is malformed, and a
/// writer never makes one. Every reader has to get through all the
/// segments of a head in one go (the recovery copy before it sends the
/// head, a replay before it publishes), so this is what one job of each
/// can read, and the one bound for them all. At 4,096 extents to a
/// segment it is 786,432 extents. It bounds the reads, not the memory:
/// a reader holds the extent records of one segment at a time (the
/// call of a replay that publishes also holds a placement for every
/// extent of the record), and nothing here bounds the extents of one
/// segment (the writer does).
pub const MAX_SEGMENTS: usize = 192;

const ERR_RECORD: BridgeError = BridgeError::Invalid("recovery record is malformed");
const ERR_VERSION: BridgeError = BridgeError::Invalid("recovery record version is unknown");
const ERR_SEGMENT: BridgeError = BridgeError::Invalid("recovery record segment is missing");
const ERR_SEGMENT_OTHER: BridgeError =
    BridgeError::Invalid("recovery record segment is not the one its head names");

/// The id of a set of segments as a segment name takes it: `s_`, then
/// 1 to 64 lowercase ASCII letters and digits. It starts with its mint
/// time, as a generation id does.
pub fn valid_set_id(id: &str) -> bool {
    id.strip_prefix("s_").is_some_and(|rest| {
        (1..=64).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

/// A tenant id as a record name takes it: `t_`, then 1 to 64 lowercase
/// ASCII letters and digits.
pub fn valid_tenant_id(id: &str) -> bool {
    id.strip_prefix("t_").is_some_and(|rest| {
        (1..=MAX_TENANT_ID_LEN).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

/// Where the records of a write are stored: the directory their names
/// start with. The flat layout is `m/`; the tenant layout is
/// `m/x/<tenant id>/`. After it the names are the same in both.
///
/// A record is sealed under its whole name, so one moved from a layout
/// to the other does not open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    root: String,
}

impl Layout {
    /// The flat layout: every record written before the tenant layout.
    pub fn flat() -> Layout {
        Layout {
            root: RECORD_PREFIX.to_owned(),
        }
    }

    /// The layout of `tenant`; `None` for what is not a tenant id.
    pub fn tenant(tenant: &str) -> Option<Layout> {
        valid_tenant_id(tenant).then(|| Layout {
            root: format!("{TENANT_DIR}{tenant}/"),
        })
    }

    /// The layout of [`DEFAULT_TENANT`].
    pub fn default_tenant() -> Layout {
        Layout {
            root: format!("{TENANT_DIR}{DEFAULT_TENANT}/"),
        }
    }

    /// Every layout a record can be in, in the order readers look: the
    /// flat one first.
    pub fn all() -> [Layout; 2] {
        [Layout::flat(), Layout::default_tenant()]
    }

    /// The directory: every name of the layout starts with it.
    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn is_flat(&self) -> bool {
        self.root == RECORD_PREFIX
    }

    /// Every generation record of the layout starts with it.
    pub fn generation_prefix(&self) -> String {
        format!("{}{GENERATION_NAME}", self.root)
    }

    /// Every tombstone of the layout starts with it.
    pub fn tombstone_prefix(&self) -> String {
        format!("{}{TOMBSTONE_NAME}", self.root)
    }

    pub fn generation_key(&self, id: &GenerationId) -> String {
        format!("{}{}", self.root, id.as_str())
    }

    pub fn tombstone_key(&self, id: &GenerationId) -> String {
        format!("{}del/{}", self.root, id.as_str())
    }

    pub fn article_key(&self, extent: &ExtentId) -> String {
        format!("{}{ARTICLE_NAME}{}", self.root, extent.as_str())
    }

    /// Segment `index` of the set `set`: `seg/<set id>/<index>`, the
    /// index in five digits, so the segments of a set list in order.
    pub fn segment_key(&self, set: &str, index: u32) -> String {
        format!("{}{SEGMENT_NAME}{set}/{index:05}", self.root)
    }

    /// The key of this layout for the same record as `flat`, a key of
    /// the flat layout.
    pub fn of_flat(&self, flat: &str) -> String {
        format!(
            "{}{}",
            self.root,
            flat.strip_prefix(RECORD_PREFIX).unwrap_or(flat)
        )
    }
}

/// What a record name says the record is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Generation,
    Tombstone,
    ArticlePlan,
}

/// A record name taken apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordName<'a> {
    pub kind: RecordKind,
    pub layout: Layout,
    /// The generation id, tombstone id or extent id.
    pub id: &'a str,
}

impl RecordName<'_> {
    /// The name of the same record in the flat layout. Two names with
    /// the same flat form are of one id: readers put the records of
    /// both layouts in one order by it.
    pub fn flat(&self) -> String {
        let dir = match self.kind {
            RecordKind::Generation => "",
            RecordKind::Tombstone => "del/",
            RecordKind::ArticlePlan => ARTICLE_NAME,
        };
        format!("{RECORD_PREFIX}{dir}{}", self.id)
    }
}

/// Takes `key` apart when it is the name of a generation record, a
/// tombstone or an article plan, of either layout and of any tenant.
/// `None` for every other key, also for the other keys under `m/`: a
/// segment (`seg/…`) is no record of its own, and is read only through
/// the head that names it.
pub fn record_name(key: &str) -> Option<RecordName<'_>> {
    let (layout, rest) = match key.strip_prefix(TENANT_DIR) {
        Some(rest) => {
            let (tenant, rest) = rest.split_once('/')?;
            (Layout::tenant(tenant)?, rest)
        }
        None => (Layout::flat(), key.strip_prefix(RECORD_PREFIX)?),
    };
    let (kind, id) = if let Some(id) = rest.strip_prefix(ARTICLE_NAME) {
        (RecordKind::ArticlePlan, id)
    } else if let Some(id) = rest.strip_prefix("del/") {
        (RecordKind::Tombstone, id)
    } else {
        (RecordKind::Generation, rest)
    };
    let named = match kind {
        RecordKind::ArticlePlan => !id.is_empty(),
        RecordKind::Generation | RecordKind::Tombstone => id.starts_with(GENERATION_NAME),
    };
    (named && !id.contains('/')).then_some(RecordName { kind, layout, id })
}

/// The name of the article plan of the same extent in the other layout
/// of the two that [`Layout::all`] names; `None` when `key` is no
/// article plan of one of them.
pub fn other_plan_key(key: &str) -> Option<String> {
    let name = record_name(key).filter(|n| n.kind == RecordKind::ArticlePlan)?;
    let [flat, tenant] = Layout::all();
    let other = if name.layout == flat {
        tenant
    } else if name.layout == tenant {
        flat
    } else {
        return None;
    };
    Some(format!("{}{ARTICLE_NAME}{}", other.root, name.id))
}

/// The name of a generation record in the flat layout.
pub fn generation_key(id: &GenerationId) -> String {
    Layout::flat().generation_key(id)
}

/// The name of a tombstone in the flat layout.
pub fn tombstone_key(id: &GenerationId) -> String {
    Layout::flat().tombstone_key(id)
}

/// The name of an article plan in the flat layout.
pub fn article_key(extent: &ExtentId) -> String {
    Layout::flat().article_key(extent)
}

/// The first blob key of generation manifests (or tombstones, with
/// [`TOMBSTONE_PREFIX`]) minted at or after `since`: every such key sorts
/// after the returned one.
pub fn start_after(prefix: &str, since: UnixMs) -> String {
    let ms = since.0.clamp(0, 0x000f_ffff_ffff_ffff);
    format!("{prefix}{ms:013x}")
}

/// The blob keys of the article plans that a generation record names,
/// in the order of its extents, from the plaintext of the record, as
/// `layout` names them. `None` = the plaintext does not name its
/// extents, or names one that is not an extent id.
pub fn plan_keys(plain: &[u8], layout: &Layout) -> Option<Vec<String>> {
    #[derive(Deserialize)]
    struct Extent {
        id: String,
    }
    #[derive(Deserialize)]
    struct Named {
        extents: Vec<Extent>,
    }
    let named: Named = serde_json::from_slice(plain).ok()?;
    named
        .extents
        .iter()
        .map(|e| plan_key(&e.id, layout))
        .collect()
}

/// The blob key of the article plan of the extent a record names `id`,
/// as `layout` names it. `None` = `id` is not an extent id.
fn plan_key(id: &str, layout: &Layout) -> Option<String> {
    id.strip_prefix("x_")
        .is_some_and(|rest| {
            (1..=64).contains(&rest.len())
                && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        .then(|| format!("{}{ARTICLE_NAME}{id}", layout.root))
}

/// The blob keys of the article plans of `extents`, the extents of one
/// segment, in their order, as `layout` names them. `None` = one of
/// them is not named by an extent id.
pub fn segment_plan_keys(extents: &[ExtentRecord], layout: &Layout) -> Option<Vec<String>> {
    extents.iter().map(|e| plan_key(&e.id, layout)).collect()
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
    /// The name the record was stored under.
    key: String,
}

impl Recorded {
    /// The generation whose record is stored.
    pub fn generation(&self) -> &GenerationId {
        &self.generation
    }

    /// Blob key of the record: the name it was stored under, whatever
    /// the layout of new records is by now.
    pub fn key(&self) -> String {
        self.key.clone()
    }

    /// The catalogue refused the publication and wrote nothing under
    /// the id. Only the SQL catalogue can say so: nothing outside
    /// `crate::sql` can make the `GuardRefused` this takes.
    pub(crate) fn refused(self, _: crate::sql::GuardRefused) -> Unpublished {
        Unpublished {
            generation: self.generation,
            key: self.key,
        }
    }

    /// A proof without a record, for catalogue tests that publish rows
    /// directly. Never compiled into the Worker.
    #[cfg(feature = "testkit")]
    pub fn for_test(generation: &GenerationId) -> Recorded {
        Recorded {
            generation: generation.clone(),
            key: generation_key(generation),
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
    /// The name the record was stored under.
    key: String,
}

impl Unpublished {
    /// The generation that was not published.
    pub fn generation(&self) -> &GenerationId {
        &self.generation
    }

    /// Blob key of the record: the name it was stored under, whatever
    /// the layout of new records is by now.
    pub fn key(&self) -> String {
        self.key.clone()
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

/// One segment as the head of a segmented generation record names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentEntry {
    /// `seq` of its first extent.
    pub seq: u32,
    /// How many extents it holds.
    pub count: u32,
    /// Where its first extent begins in the object.
    pub plain_offset: u64,
    /// The plaintext bytes of its extents together.
    pub plain_size: u64,
    /// SHA-256 of the segment as it is stored: sealed.
    #[serde(with = "b64")]
    pub sha256: Vec<u8>,
}

/// `m/<generation_id>` of a segmented record (format 2): what
/// [`GenerationManifest`] holds, with the extents in [`Segment`]s of
/// their own that this names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationHead {
    pub v: u32,
    pub bucket: BucketRecord,
    pub generation: GenerationRecord,
    /// The id of the set of segments, minted with the record.
    pub set: String,
    /// In `seq` order: segment `i` is stored at
    /// [`Layout::segment_key`]`(set, i)`.
    pub segments: Vec<SegmentEntry>,
}

/// `m/seg/<set id>/<index>`: one run of the extents of a segmented
/// generation record, as format 1 lists them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub v: u32,
    pub set: String,
    pub index: u32,
    pub extents: Vec<ExtentRecord>,
}

/// A generation record as it is stored: in one document or segmented.
#[derive(Clone, PartialEq, Eq)]
pub enum StoredGeneration {
    Single(GenerationManifest),
    Segmented(GenerationHead),
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
    /// The parity addendum of the plan ([`crate::parity`]), when it has
    /// one: where the extent's parity articles are. `articles` holds the
    /// data articles only. A replay gives the catalogue the addendum
    /// back with the packed plan it is beside, after it has checked it
    /// against that plan. A reader from before this field skips it.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_b64")]
    pub parity: Option<Vec<u8>>,
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
        self.bucket.row()
    }

    /// The generation as it was published: live.
    pub fn generation(&self) -> Result<GenerationRow> {
        let count = u32::try_from(self.extents.len()).map_err(|_| ERR_RECORD)?;
        Ok(self.generation.row(&self.bucket, count))
    }

    /// Extent `index` as a committed row of this generation whose safety
    /// copy is held and that has no article plan yet.
    pub fn extent(&self, index: usize) -> Result<ExtentRow> {
        self.extents
            .get(index)
            .ok_or(ERR_RECORD)?
            .row(&self.bucket, &self.generation)
    }
}

impl BucketRecord {
    fn row(&self) -> Bucket {
        Bucket {
            id: BucketId::new(self.id.clone()),
            name: self.name.clone(),
            owner: self.owner.clone(),
            bdk_wrapped: self.bdk_wrapped.clone(),
            kek_version: self.kek_version,
            disposable: self.disposable,
            created_at: UnixMs(self.created_at),
        }
    }
}

impl GenerationRecord {
    /// The generation of `count` extents as it was published: live.
    fn row(&self, bucket: &BucketRecord, count: u32) -> GenerationRow {
        GenerationRow {
            id: GenerationId::new(self.id.clone()),
            bucket_id: BucketId::new(bucket.id.clone()),
            key: self.key.clone(),
            state: GenerationState::Live,
            size: self.size,
            etag: self.etag.clone(),
            checksum_json: self.checksum_json.clone(),
            content_json: self.content_json.clone(),
            user_meta_json: self.user_meta_json.clone(),
            extent_count: count,
            created_at: UnixMs(self.created_at),
            retired_at: None,
        }
    }
}

impl ExtentRecord {
    /// Whether its digests have the lengths [`Self::row`] takes.
    fn has_digests(&self) -> bool {
        digest::<16>(&self.plain_md5).is_ok()
            && digest::<32>(&self.plain_sha256).is_ok()
            && digest::<32>(&self.cipher_sha256).is_ok()
    }

    /// The extent as a committed row of `generation` whose safety copy
    /// is held and that has no article plan yet.
    fn row(&self, bucket: &BucketRecord, generation: &GenerationRecord) -> Result<ExtentRow> {
        Ok(ExtentRow {
            id: ExtentId::new(self.id.clone()),
            bucket_id: BucketId::new(bucket.id.clone()),
            generation_id: Some(GenerationId::new(generation.id.clone())),
            state: ExtentState::Committed,
            seq: Some(self.seq),
            plain_offset: Some(self.plain_offset),
            plain_size: self.plain_size,
            cipher_size: self.cipher_size,
            media_header: self.media_header.clone(),
            key_mode: self.key_mode,
            wrapped_file_key: Some(self.wrapped_file_key.clone()),
            plain_md5: digest(&self.plain_md5)?,
            plain_sha256: digest(&self.plain_sha256)?,
            cipher_sha256: digest(&self.cipher_sha256)?,
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: UnixMs(self.created_at),
            hot: Default::default(),
        })
    }
}

impl GenerationHead {
    /// The head stored at `name`, from its plaintext. `Err` unless it
    /// is a head of [`SEGMENTED_VERSION`], is the record its name
    /// promises, and names segments that tile the object: the first at
    /// `seq` 0 and offset 0, each one where the one before ends, none
    /// empty, and all of them together the size of the generation.
    pub fn parse(name: &str, plain: &[u8]) -> Result<GenerationHead> {
        if record_version(plain) != Some(SEGMENTED_VERSION) {
            return Err(ERR_VERSION);
        }
        let head: GenerationHead = serde_json::from_slice(plain).map_err(|_| ERR_RECORD)?;
        if !names(name, RecordKind::Generation, &head.generation.id)
            || !valid_set_id(&head.set)
            || head.segments.is_empty()
            || head.segments.len() > MAX_SEGMENTS
        {
            return Err(ERR_RECORD);
        }
        let (mut seq, mut offset) = (0u32, 0u64);
        for entry in &head.segments {
            if entry.seq != seq
                || entry.plain_offset != offset
                || entry.count == 0
                || entry.sha256.len() != 32
            {
                return Err(ERR_RECORD);
            }
            seq = seq.checked_add(entry.count).ok_or(ERR_RECORD)?;
            offset = offset.checked_add(entry.plain_size).ok_or(ERR_RECORD)?;
        }
        if offset != head.generation.size {
            return Err(ERR_RECORD);
        }
        Ok(head)
    }

    pub fn bucket(&self) -> Bucket {
        self.bucket.row()
    }

    /// How many extents the segments hold together.
    pub fn extent_count(&self) -> u32 {
        // `parse` added them up without overflow.
        self.segments.iter().map(|s| s.count).sum()
    }

    /// The generation as it was published: live.
    pub fn generation(&self) -> GenerationRow {
        self.generation.row(&self.bucket, self.extent_count())
    }

    /// The index of the segment that holds the extent with `seq`.
    pub fn segment_of(&self, seq: u32) -> Option<usize> {
        let after = self.segments.partition_point(|s| s.seq <= seq);
        let index = after.checked_sub(1)?;
        let entry = &self.segments[index];
        (seq - entry.seq < entry.count).then_some(index)
    }

    /// The name of segment `index` beside a head stored in `layout`.
    pub fn segment_key(&self, layout: &Layout, index: usize) -> String {
        layout.segment_key(&self.set, u32::try_from(index).unwrap_or(u32::MAX))
    }

    /// Opens `sealed`, the bytes stored at the name of segment `index`,
    /// and returns its extents. `Err` unless it is the segment this
    /// head names there: the bytes have the digest in the head, open
    /// under the name, say the set and the index, and hold the count of
    /// extents the head says, from its `seq` and offset on without a
    /// gap, of its size together.
    pub fn open_segment<K: Kek>(
        &self,
        kek: &K,
        layout: &Layout,
        index: usize,
        sealed: &[u8],
    ) -> Result<Vec<ExtentRecord>> {
        let entry = self.segments.get(index).ok_or(ERR_RECORD)?;
        let sha: [u8; 32] = Sha256::digest(sealed).into();
        if sha[..] != entry.sha256[..] {
            return Err(ERR_SEGMENT_OTHER);
        }
        let plain = open_manifest(kek, &self.segment_key(layout, index), sealed)?;
        if record_version(&plain) != Some(SEGMENTED_VERSION) {
            return Err(ERR_VERSION);
        }
        let segment: Segment = serde_json::from_slice(&plain).map_err(|_| ERR_RECORD)?;
        if segment.set != self.set
            || usize::try_from(segment.index).ok() != Some(index)
            || usize::try_from(entry.count).ok() != Some(segment.extents.len())
        {
            return Err(ERR_SEGMENT_OTHER);
        }
        let (mut seq, mut offset) = (entry.seq, entry.plain_offset);
        for e in &segment.extents {
            // Also what makes a row of every extent: a segment that
            // opens is one the whole of which can be replayed.
            if e.seq != seq || e.plain_offset != offset || !e.has_digests() {
                return Err(ERR_SEGMENT_OTHER);
            }
            // The head was checked: its counts and sizes do not overflow.
            seq = seq.wrapping_add(1);
            offset = offset.checked_add(e.plain_size).ok_or(ERR_SEGMENT_OTHER)?;
        }
        if offset - entry.plain_offset != entry.plain_size {
            return Err(ERR_SEGMENT_OTHER);
        }
        Ok(segment.extents)
    }

    /// `extent`, one of a segment of this head, as a committed row of
    /// the generation whose safety copy is held and that has no article
    /// plan yet.
    pub fn extent(&self, extent: &ExtentRecord) -> Result<ExtentRow> {
        extent.row(&self.bucket, &self.generation)
    }
}

/// The format version a record's plaintext states.
pub fn record_version(plain: &[u8]) -> Option<u32> {
    #[derive(Deserialize)]
    struct Versioned {
        v: u32,
    }
    serde_json::from_slice::<Versioned>(plain).ok().map(|r| r.v)
}

impl ArticleManifest {
    /// The record of a plan with its packed form, when it has a seeded
    /// one. The other packed form holds what `articles` holds, and is
    /// made from it again. The parity addendum of a packed plan goes
    /// with either form: it holds beside both.
    pub fn of(extent: &ExtentRow, plan: &StoredPlan) -> Self {
        let packed = plan.packed.as_ref();
        ArticleManifest {
            packed: packed
                .filter(|p| crate::plan::seed_of(p).is_some())
                .cloned(),
            parity: packed.and(plan.parity.clone()),
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
            parity: None,
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
    match record_version(&plain) {
        Some(RECORD_VERSION) => serde_json::from_slice(&plain)
            .map(Some)
            .map_err(|_| ERR_RECORD),
        Some(_) => Err(ERR_VERSION),
        None => Err(ERR_RECORD),
    }
}

/// Writes the generation record (`m/<generation_id>` in the flat
/// layout), after it raised the floor of the key to the id, and returns
/// the proof of it, without which the catalogue publishes nothing.
pub async fn write_generation<C: Catalog, B: BlobStore, K: Kek>(
    catalog: &C,
    safety: &B,
    kek: &K,
    layout: &Layout,
    bucket: &Bucket,
    generation: &GenerationRow,
    extents: &[ExtentRow],
) -> Result<Recorded> {
    let record = GenerationManifest::new(bucket, generation, extents)?;
    catalog
        .raise_floor(&bucket.id, &generation.key, &generation.id, true)
        .await?;
    let name = layout.generation_key(&generation.id);
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
        key: name,
    })
}

/// Writes the tombstone (`m/del/<id>` in the flat layout), after it
/// raised the floor of the key to the id. The caller deletes only after
/// this returned `Ok`.
#[allow(clippy::too_many_arguments)]
pub async fn write_tombstone<C: Catalog, B: BlobStore, K: Kek>(
    catalog: &C,
    safety: &B,
    kek: &K,
    layout: &Layout,
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
        &layout.tombstone_key(id),
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
    layout: &Layout,
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
                &layout.tombstone_key(&t.id),
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

/// Writes the article plan record (`m/art/<extent_id>` in the flat
/// layout) from the plan the catalogue holds. An
/// extent's plan never changes, so a second write stores the same plan
/// again; it also replaces a record that no longer opens. The caller
/// posts only after this returned `Ok`.
pub async fn write_article_plan<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    layout: &Layout,
    extent: &ExtentRow,
    plan: &[ArticleRow],
) -> Result<()> {
    write_stored_plan(
        safety,
        kek,
        layout,
        extent,
        &StoredPlan {
            rows: plan.to_vec(),
            packed: None,
            parity: None,
        },
    )
    .await
}

/// [`write_article_plan`] for a plan as the catalogue holds it: the
/// record also carries its seeded packed form and its parity addendum.
pub async fn write_stored_plan<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    layout: &Layout,
    extent: &ExtentRow,
    plan: &StoredPlan,
) -> Result<()> {
    let name = layout.article_key(&extent.id);
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

/// Whether `name` is the name of a record of `kind` with the id `id`,
/// in either layout.
fn names(name: &str, kind: RecordKind, id: &str) -> bool {
    record_name(name).is_some_and(|n| n.kind == kind && n.id == id)
}

/// Whether a generation record of `id` is stored, under the name of any
/// layout.
pub async fn generation_recorded<B: BlobStore>(safety: &B, id: &GenerationId) -> Result<bool> {
    for layout in Layout::all() {
        if safety.head(&layout.generation_key(id)).await?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Reads the format-1 record stored at `name` (a key from a listing, of
/// either layout). A segmented record is an error here, as a version
/// that is not known: [`read_stored_generation`] reads both.
pub async fn read_generation<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    name: &str,
) -> Result<Option<GenerationManifest>> {
    let record: Option<GenerationManifest> = read(safety, kek, name).await?;
    match &record {
        // The record must be the one its name promises.
        Some(m) if !names(name, RecordKind::Generation, &m.generation.id) => Err(ERR_RECORD),
        _ => Ok(record),
    }
}

/// Reads the generation record stored at `name` (a key from a listing,
/// of either layout), in whichever format it has: the whole of a
/// format-1 record, the head of a segmented one. `None` = no record at
/// `name`. Any other version is an error, as is a record that does not
/// open, does not parse or is not the one its name promises.
pub async fn read_stored_generation<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    name: &str,
) -> Result<Option<StoredGeneration>> {
    let Some(sealed) = safety.get(name, None).await? else {
        return Ok(None);
    };
    let plain = open_manifest(kek, name, &sealed)?;
    match record_version(&plain) {
        Some(RECORD_VERSION) => {
            let m: GenerationManifest = serde_json::from_slice(&plain).map_err(|_| ERR_RECORD)?;
            if !names(name, RecordKind::Generation, &m.generation.id) {
                return Err(ERR_RECORD);
            }
            Ok(Some(StoredGeneration::Single(m)))
        }
        Some(SEGMENTED_VERSION) => {
            GenerationHead::parse(name, &plain).map(|h| Some(StoredGeneration::Segmented(h)))
        }
        Some(_) => Err(ERR_VERSION),
        None => Err(ERR_RECORD),
    }
}

/// Reads segment `index` of `head`, a head stored in `layout`, and
/// returns its extents ([`GenerationHead::open_segment`]).
///
/// `Err(BridgeError::Blob)` = the store could not be asked. Every other
/// error says the record is unreadable: the segment is not stored, or
/// is not the one the head names.
pub async fn read_segment<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    layout: &Layout,
    head: &GenerationHead,
    index: usize,
) -> Result<Vec<ExtentRecord>> {
    let name = head.segment_key(layout, index);
    let Some(sealed) = safety.get(&name, None).await? else {
        return Err(ERR_SEGMENT);
    };
    head.open_segment(kek, layout, index, &sealed)
}

/// Reads the tombstone stored at `name` (a key from a listing, of
/// either layout).
pub async fn read_tombstone<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    name: &str,
) -> Result<Option<Tombstone>> {
    let record: Option<Tombstone> = read(safety, kek, name).await?;
    match &record {
        Some(t) if !names(name, RecordKind::Tombstone, &t.id) => Err(ERR_RECORD),
        _ => Ok(record),
    }
}

/// The article plan record of one extent, as [`read_article_plan`]
/// found it.
#[derive(Debug, Default)]
pub struct PlanRead {
    /// The record; `None` = there is none that opens.
    pub record: Option<ArticleManifest>,
    /// The name `record` was read from.
    pub name: Option<String>,
    /// The names of the records of the extent that are stored and did
    /// not open or parse.
    pub unreadable: Vec<String>,
}

/// Reads the article plan record of `extent`, whichever layout it was
/// written in: the name of `first` is looked at first, then those of
/// the other layouts, until a record opens. An extent has one plan, so
/// two records of it hold the same one.
///
/// `Err` = the store could not be asked. A record that does not open
/// is named in the answer and is no error.
pub async fn read_article_plan<B: BlobStore, K: Kek>(
    safety: &B,
    kek: &K,
    extent: &ExtentId,
    first: &Layout,
) -> Result<PlanRead> {
    let mut found = PlanRead::default();
    let others = Layout::all().into_iter().filter(|l| l != first);
    for layout in std::iter::once(first.clone()).chain(others) {
        let name = layout.article_key(extent);
        match read::<B, K, ArticleManifest>(safety, kek, &name).await {
            Ok(Some(a)) if a.extent_id == extent.as_str() => {
                found.record = Some(a);
                found.name = Some(name);
                break;
            }
            Ok(Some(_)) => found.unreadable.push(name),
            Ok(None) => {}
            Err(BridgeError::Blob(e)) => return Err(BridgeError::Blob(e)),
            Err(_) => found.unreadable.push(name),
        }
    }
    Ok(found)
}
