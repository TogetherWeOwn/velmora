//! The request calls of a unit (`docs/units.md`, "Requests"; ADR §2.7,
//! amendment AM-64; package L1-5).
//!
//! The S3 handlers run in the Worker, as today (`service/*`): they hold
//! the blob stores, the keys and the NNTP sessions (rules 3 and 4). What
//! they ask of the catalogue, a unit answers: each [`RequestCall`] is one
//! method of [`Catalog`], with its arguments as they cross `fetch`, run by
//! the unit's own [`SqlCatalog`] in one transaction (rules 1 and 2), as
//! [`super::jobcall::JobCall`] is for jobs. The Worker's request
//! `TenantCatalog` (L6-6) forwards the handlers' calls as these, so
//! `Bridge::handle` serves a managed tenant unchanged: conditional PUT,
//! the publication batches with their guards, the upload id bound to its
//! bucket and key (every [`UploadTarget`] names all three), and the
//! delete batches are the catalogue's own code, the same as tenant 0's.
//!
//! What a unit adds (`docs/units.md`, "Requests"):
//!
//! - a request call is a `request` call with the caller's numbers
//!   (rule 5) and `authenticated` (rule 11): the Worker sends one only
//!   after SigV4 verified (`signature_verified()`, AM-64). The only calls
//!   before it are `key_row` and `read_plan`;
//! - the tenant's state decides it: every call while `active`, the
//!   [`RequestCall::is_read`] calls while `suspended` with `read_only`,
//!   none otherwise (`403 AccountProblem`);
//! - a write that adds rows naming a bucket that is closing (AM-57) is
//!   refused `not_found`, and `bucket_by_name` and `buckets_for` leave
//!   closing buckets out, so the Worker answers `404 NoSuchBucket`;
//! - a call that adds extents, or rows, takes the size guard (ADR §2.6)
//!   in its own transaction before it writes;
//! - each list of a call has a bound ([`RequestCall::check`]): a call
//!   above it is a Worker bug, refused `out_of_bounds` with an alarm.
//!
//! Bucket create and delete, and the key and grant writes, are not
//! request calls: a managed tenant's buckets come from its tenant chain
//! and its keys from its key chain (AM-57, AM-12, AM-64). Provider
//! permits and provider health stay on the shared database.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::MAX_OBJECT_EXTENTS_LIMIT;
use crate::ports::{Catalog, PublishOutcome, Sql, UploadTarget};
use crate::recovery::Recorded;
use crate::sql::SqlCatalog;
use crate::types::*;

/// The most keys, ids or rows one listing or batch call names or asks
/// for: S3's own page and DeleteObjects bound.
pub const MAX_PAGE: u32 = 1_000;
/// The most extents one call carries or asks for: one object's bound
/// (`MAX_OBJECT_EXTENTS_LIMIT`), and one more for the handler's check of
/// it.
pub const MAX_EXTENTS: u32 = MAX_OBJECT_EXTENTS_LIMIT + 1;
/// The longest object key, prefix or marker a call names (bytes, S3's
/// key bound).
pub const MAX_KEY_BYTES: usize = 1_024;
/// The longest listing prefix, delimiter or marker a call names (bytes):
/// the request target's own bound (`service::common`), which is all that
/// bounds them on tenant 0.
pub const MAX_MARKER_BYTES: usize = 8 * 1_024;

/// The proof of a generation's recovery record, as a publication call
/// carries it: the generation and the name the record was stored under
/// ([`Recorded::generation`], [`Recorded::key`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordWire {
    pub generation: GenerationId,
    pub key: String,
}

impl RecordWire {
    /// The wire form of the proof the Worker holds; it keeps the proof.
    pub fn of(record: &Recorded) -> RecordWire {
        RecordWire {
            generation: record.generation().clone(),
            key: record.key(),
        }
    }
}

/// The answer of a publication call (`commit_generation`,
/// `commit_sliced`, `copy_generation`, `complete_upload`):
/// [`PublishOutcome`] without its proof. The Worker rebuilds the outcome
/// from the [`Recorded`] it kept ([`Published::outcome`]), so a refused
/// publication discards the Worker's own record and never one the unit
/// named.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Published {
    Applied,
    Refused,
    Fenced,
}

impl Published {
    fn of(o: &PublishOutcome) -> Published {
        match o {
            PublishOutcome::Applied => Published::Applied,
            PublishOutcome::Refused(_) => Published::Refused,
            PublishOutcome::Fenced(_) => Published::Fenced,
        }
    }

    /// The outcome with the Worker's own proof: `record` is the
    /// [`Recorded`] whose [`RecordWire`] the call carried.
    pub fn outcome(self, record: Recorded) -> PublishOutcome {
        match self {
            Published::Applied => PublishOutcome::Applied,
            Published::Refused => PublishOutcome::Refused(record.refused_on_unit()),
            Published::Fenced => PublishOutcome::Fenced(record.refused_on_unit()),
        }
    }
}

/// Why a request call was refused before it ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestRefusal {
    /// A list, a limit or a key of the call is above its bound.
    OutOfBounds,
}

/// One catalogue method of the S3 request path (and of W13-min's
/// reads), with its arguments. An upload target is spelt out as
/// `bucket`, `key` and `upload`.
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "m", deny_unknown_fields)]
pub enum RequestCall {
    // --- authorization and buckets (reads)
    access_key {
        akid: String,
    },
    grant {
        akid: String,
        bucket: BucketId,
    },
    bucket_by_name {
        name: String,
    },
    buckets_for {
        akid: String,
    },
    bucket_in_use {
        bucket: BucketId,
    },
    // --- objects (reads)
    live_object {
        bucket: BucketId,
        key: String,
    },
    live_generation {
        bucket: BucketId,
        key: String,
    },
    generation_by_id {
        bucket: BucketId,
        generation: GenerationId,
    },
    extents_in {
        generation: GenerationId,
        start: u64,
        end: u64,
    },
    newest_id {
        bucket: BucketId,
        key: String,
    },
    unpublished_floor {
        bucket: BucketId,
        key: String,
    },
    key_heads {
        bucket: BucketId,
        keys: Vec<String>,
    },
    list {
        bucket: BucketId,
        q: ListQuery,
    },
    list_heads {
        bucket: BucketId,
        q: ListQuery,
    },
    object_status {
        bucket: BucketId,
        key: String,
    },
    replay_probe {
        g: GenerationRow,
    },
    restore_pending {},
    articles {
        extent: ExtentId,
    },
    /// A read's own stamp: allowed where reads are.
    touch_read {
        extent: ExtentId,
        now: UnixMs,
        min_gap_ms: i64,
        from_cache: bool,
    },
    /// A cache fill of a read: allowed where reads are.
    record_cache_fill {
        extent: ExtentId,
        now: UnixMs,
    },
    // --- uploads (reads)
    upload {
        bucket: BucketId,
        key: String,
        upload: UploadId,
    },
    list_uploads {
        bucket: BucketId,
        q: UploadListQuery,
    },
    upload_extents {
        bucket: BucketId,
        key: String,
        upload: UploadId,
        limit: u32,
    },
    upload_extents_held {
        upload: UploadId,
        except: u16,
    },
    // --- W13-min's operator reads
    outbox_stats {},
    intent_stats {
        open_before: UnixMs,
    },
    usage_counters {},
    usage_snapshot {
        hours: u32,
    },
    usage_buckets {
        after: String,
        limit: u32,
    },
    usage_recounts {},
    hot_stats {},
    hot_seq {
        extent: ExtentId,
    },
    // --- the management plane's reads (`super::plane`; L1-Q16)
    bucket_names {
        ids: Vec<String>,
    },
    buckets_page {
        #[serde(default)]
        after: Option<String>,
        limit: u32,
    },
    buckets_named {
        names: Vec<String>,
    },
    bucket_by_id {
        id: String,
    },
    keys_page {
        kind: super::plane::ListedKind,
        #[serde(default)]
        after: Option<super::plane::KeysAfter>,
        limit: u32,
    },
    key_by_id {
        id: String,
    },
    reach {},
    // --- writes
    commit_generation {
        c: CommitGeneration,
        #[serde(default)]
        condition: Option<Precondition>,
        record: RecordWire,
    },
    commit_sliced {
        c: CommitGeneration,
        write: WriteId,
        #[serde(default)]
        condition: Option<Precondition>,
        record: RecordWire,
    },
    copy_generation {
        c: CopyGeneration,
        #[serde(default)]
        condition: Option<Precondition>,
        record: RecordWire,
    },
    open_intents {
        write: WriteId,
        extents: Vec<ExtentId>,
        now: UnixMs,
    },
    intents_generation {
        write: WriteId,
        generation: GenerationId,
        slices: u32,
    },
    abandon_intents {
        write: WriteId,
    },
    raise_floor {
        bucket: BucketId,
        key: String,
        id: GenerationId,
        generation: bool,
    },
    settle_floor {
        bucket: BucketId,
        key: String,
        id: GenerationId,
    },
    raise_floors {
        bucket: BucketId,
        ids: Vec<(String, GenerationId)>,
    },
    settle_floors {
        bucket: BucketId,
        ids: Vec<(String, GenerationId)>,
    },
    delete_object_before {
        bucket: BucketId,
        key: String,
        before: GenerationId,
        now: UnixMs,
    },
    delete_object_if {
        bucket: BucketId,
        key: String,
        before: GenerationId,
        condition: Precondition,
        now: UnixMs,
    },
    delete_objects_before {
        bucket: BucketId,
        deletes: Vec<(String, GenerationId, UnixMs)>,
    },
    create_upload {
        u: UploadRow,
    },
    put_upload_part {
        bucket: BucketId,
        key: String,
        upload: UploadId,
        part: UploadPartRow,
        extent: ExtentRow,
        now: UnixMs,
    },
    put_upload_part_sliced {
        bucket: BucketId,
        key: String,
        upload: UploadId,
        part: UploadPartRow,
        extents: Vec<ExtentRow>,
        write: WriteId,
        now: UnixMs,
    },
    complete_upload {
        bucket: BucketId,
        key: String,
        upload: UploadId,
        revision: u64,
        digest: [u8; 32],
        c: CompleteUpload,
        #[serde(default)]
        condition: Option<Precondition>,
        record: RecordWire,
    },
    abort_upload {
        bucket: BucketId,
        key: String,
        upload: UploadId,
        now: UnixMs,
    },
    /// Settles a `complete_upload` whose answer was lost: moves the
    /// upload to its next revision while it is still open at `revision`,
    /// and answers whether that applied (then the Complete had not, and
    /// never will). Complete's own settling of an unknown outcome on
    /// tenant 0, across `fetch`.
    fence_upload {
        bucket: BucketId,
        key: String,
        upload: UploadId,
        revision: u64,
    },
}

impl RequestCall {
    /// The method's name.
    pub fn name(&self) -> &'static str {
        match self {
            RequestCall::access_key { .. } => "access_key",
            RequestCall::grant { .. } => "grant",
            RequestCall::bucket_by_name { .. } => "bucket_by_name",
            RequestCall::buckets_for { .. } => "buckets_for",
            RequestCall::bucket_in_use { .. } => "bucket_in_use",
            RequestCall::live_object { .. } => "live_object",
            RequestCall::live_generation { .. } => "live_generation",
            RequestCall::generation_by_id { .. } => "generation_by_id",
            RequestCall::extents_in { .. } => "extents_in",
            RequestCall::newest_id { .. } => "newest_id",
            RequestCall::unpublished_floor { .. } => "unpublished_floor",
            RequestCall::key_heads { .. } => "key_heads",
            RequestCall::list { .. } => "list",
            RequestCall::list_heads { .. } => "list_heads",
            RequestCall::object_status { .. } => "object_status",
            RequestCall::replay_probe { .. } => "replay_probe",
            RequestCall::restore_pending {} => "restore_pending",
            RequestCall::articles { .. } => "articles",
            RequestCall::touch_read { .. } => "touch_read",
            RequestCall::record_cache_fill { .. } => "record_cache_fill",
            RequestCall::upload { .. } => "upload",
            RequestCall::list_uploads { .. } => "list_uploads",
            RequestCall::upload_extents { .. } => "upload_extents",
            RequestCall::upload_extents_held { .. } => "upload_extents_held",
            RequestCall::outbox_stats {} => "outbox_stats",
            RequestCall::intent_stats { .. } => "intent_stats",
            RequestCall::usage_counters {} => "usage_counters",
            RequestCall::usage_snapshot { .. } => "usage_snapshot",
            RequestCall::usage_buckets { .. } => "usage_buckets",
            RequestCall::usage_recounts {} => "usage_recounts",
            RequestCall::hot_stats {} => "hot_stats",
            RequestCall::hot_seq { .. } => "hot_seq",
            RequestCall::bucket_names { .. } => "bucket_names",
            RequestCall::buckets_page { .. } => "buckets_page",
            RequestCall::buckets_named { .. } => "buckets_named",
            RequestCall::bucket_by_id { .. } => "bucket_by_id",
            RequestCall::keys_page { .. } => "keys_page",
            RequestCall::key_by_id { .. } => "key_by_id",
            RequestCall::reach {} => "reach",
            RequestCall::commit_generation { .. } => "commit_generation",
            RequestCall::commit_sliced { .. } => "commit_sliced",
            RequestCall::copy_generation { .. } => "copy_generation",
            RequestCall::open_intents { .. } => "open_intents",
            RequestCall::intents_generation { .. } => "intents_generation",
            RequestCall::abandon_intents { .. } => "abandon_intents",
            RequestCall::raise_floor { .. } => "raise_floor",
            RequestCall::settle_floor { .. } => "settle_floor",
            RequestCall::raise_floors { .. } => "raise_floors",
            RequestCall::settle_floors { .. } => "settle_floors",
            RequestCall::delete_object_before { .. } => "delete_object_before",
            RequestCall::delete_object_if { .. } => "delete_object_if",
            RequestCall::delete_objects_before { .. } => "delete_objects_before",
            RequestCall::create_upload { .. } => "create_upload",
            RequestCall::put_upload_part { .. } => "put_upload_part",
            RequestCall::put_upload_part_sliced { .. } => "put_upload_part_sliced",
            RequestCall::complete_upload { .. } => "complete_upload",
            RequestCall::abort_upload { .. } => "abort_upload",
            RequestCall::fence_upload { .. } => "fence_upload",
        }
    }

    /// A call a `read_only` tenant may make: the reads, and the two
    /// stamps a read writes (its read stamp and its cache fill).
    pub fn is_read(&self) -> bool {
        match self {
            RequestCall::access_key { .. }
            | RequestCall::grant { .. }
            | RequestCall::bucket_by_name { .. }
            | RequestCall::buckets_for { .. }
            | RequestCall::bucket_in_use { .. }
            | RequestCall::live_object { .. }
            | RequestCall::live_generation { .. }
            | RequestCall::generation_by_id { .. }
            | RequestCall::extents_in { .. }
            | RequestCall::newest_id { .. }
            | RequestCall::unpublished_floor { .. }
            | RequestCall::key_heads { .. }
            | RequestCall::list { .. }
            | RequestCall::list_heads { .. }
            | RequestCall::object_status { .. }
            | RequestCall::replay_probe { .. }
            | RequestCall::restore_pending {}
            | RequestCall::articles { .. }
            | RequestCall::touch_read { .. }
            | RequestCall::record_cache_fill { .. }
            | RequestCall::upload { .. }
            | RequestCall::list_uploads { .. }
            | RequestCall::upload_extents { .. }
            | RequestCall::upload_extents_held { .. }
            | RequestCall::outbox_stats {}
            | RequestCall::intent_stats { .. }
            | RequestCall::usage_counters {}
            | RequestCall::usage_snapshot { .. }
            | RequestCall::usage_buckets { .. }
            | RequestCall::usage_recounts {}
            | RequestCall::hot_stats {}
            | RequestCall::hot_seq { .. }
            | RequestCall::bucket_names { .. }
            | RequestCall::buckets_page { .. }
            | RequestCall::buckets_named { .. }
            | RequestCall::bucket_by_id { .. }
            | RequestCall::keys_page { .. }
            | RequestCall::key_by_id { .. }
            | RequestCall::reach {} => true,
            RequestCall::commit_generation { .. }
            | RequestCall::commit_sliced { .. }
            | RequestCall::copy_generation { .. }
            | RequestCall::open_intents { .. }
            | RequestCall::intents_generation { .. }
            | RequestCall::abandon_intents { .. }
            | RequestCall::raise_floor { .. }
            | RequestCall::settle_floor { .. }
            | RequestCall::raise_floors { .. }
            | RequestCall::settle_floors { .. }
            | RequestCall::delete_object_before { .. }
            | RequestCall::delete_object_if { .. }
            | RequestCall::delete_objects_before { .. }
            | RequestCall::create_upload { .. }
            | RequestCall::put_upload_part { .. }
            | RequestCall::put_upload_part_sliced { .. }
            | RequestCall::complete_upload { .. }
            | RequestCall::abort_upload { .. }
            | RequestCall::fence_upload { .. } => false,
        }
    }

    /// The bucket a write adds rows to (a generation, extents, a floor, a
    /// tombstone, an upload or a part): refused while that bucket is
    /// closing (AM-57). The calls that only take rows away (an abandon,
    /// an abort, a settle) and the reads name none.
    pub fn bucket_written(&self) -> Option<&BucketId> {
        match self {
            RequestCall::commit_generation { c, .. } | RequestCall::commit_sliced { c, .. } => {
                Some(&c.generation.bucket_id)
            }
            RequestCall::copy_generation { c, .. } => Some(&c.generation.bucket_id),
            RequestCall::raise_floor { bucket, .. }
            | RequestCall::raise_floors { bucket, .. }
            | RequestCall::delete_object_before { bucket, .. }
            | RequestCall::delete_object_if { bucket, .. }
            | RequestCall::delete_objects_before { bucket, .. }
            | RequestCall::put_upload_part { bucket, .. }
            | RequestCall::put_upload_part_sliced { bucket, .. }
            | RequestCall::complete_upload { bucket, .. } => Some(bucket),
            RequestCall::create_upload { u } => Some(&u.bucket_id),
            _ => None,
        }
    }

    /// For a call that grows the database: the extents it adds (0 when
    /// it adds other rows only). The size guard runs before it (ADR
    /// §2.6). `None` for the reads (and their stamps), the deletes (a
    /// floor, then a tombstone: "reads, deletes and smaller overwrites
    /// go on") and the calls that only take rows away. A publication
    /// that replaces a live generation of at least as many extents is a
    /// smaller overwrite: `Unit::request` admits it past the guard.
    pub fn grows(&self) -> Option<u64> {
        let n = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
        match self {
            RequestCall::commit_generation { c, .. } | RequestCall::commit_sliced { c, .. } => {
                Some(n(c.extents.len()))
            }
            RequestCall::put_upload_part { .. } => Some(1),
            RequestCall::put_upload_part_sliced { extents, .. } => Some(n(extents.len())),
            // A copy and a Complete reference extents the unit holds; an
            // intent, a floor, a tombstone and an upload add rows only.
            RequestCall::copy_generation { .. }
            | RequestCall::complete_upload { .. }
            | RequestCall::open_intents { .. }
            | RequestCall::create_upload { .. } => Some(0),
            _ => None,
        }
    }

    /// Whether the call can add a row (a growth, or a delete's floor or
    /// tombstone): above the hard ceiling it does not run
    /// ([`super::size::HARD_BYTES`]).
    pub fn adds_rows(&self) -> bool {
        self.grows().is_some()
            || matches!(
                self,
                RequestCall::raise_floor { .. }
                    | RequestCall::raise_floors { .. }
                    | RequestCall::delete_object_before { .. }
                    | RequestCall::delete_object_if { .. }
                    | RequestCall::delete_objects_before { .. }
            )
    }

    /// The call's bounds (module doc): every list, limit and key within
    /// what the handlers send.
    pub fn check(&self) -> std::result::Result<(), RequestRefusal> {
        let page = |n: usize| n <= MAX_PAGE as usize;
        let extents = |n: usize| n <= MAX_EXTENTS as usize;
        let key = |k: &str| k.len() <= MAX_KEY_BYTES;
        let marker = |k: &str| k.len() <= MAX_MARKER_BYTES;
        let opt = |k: &Option<String>| k.as_deref().is_none_or(marker);
        let ok = match self {
            RequestCall::live_object { key: k, .. }
            | RequestCall::live_generation { key: k, .. }
            | RequestCall::newest_id { key: k, .. }
            | RequestCall::unpublished_floor { key: k, .. }
            | RequestCall::object_status { key: k, .. }
            | RequestCall::upload { key: k, .. }
            | RequestCall::raise_floor { key: k, .. }
            | RequestCall::settle_floor { key: k, .. }
            | RequestCall::delete_object_before { key: k, .. }
            | RequestCall::delete_object_if { key: k, .. }
            | RequestCall::put_upload_part { key: k, .. }
            | RequestCall::abort_upload { key: k, .. }
            | RequestCall::fence_upload { key: k, .. } => key(k),
            RequestCall::key_heads { keys, .. } => page(keys.len()) && keys.iter().all(|k| key(k)),
            // A page asks for one row more than it shows, to know whether
            // it is the last.
            RequestCall::list { q, .. } | RequestCall::list_heads { q, .. } => {
                q.max_keys <= MAX_PAGE + 1
                    && marker(&q.prefix)
                    && opt(&q.delimiter)
                    && opt(&q.after)
                    && opt(&q.skip_prefix)
            }
            RequestCall::list_uploads { q, .. } => {
                q.limit <= MAX_PAGE + 1
                    && marker(&q.prefix)
                    && opt(&q.skip_prefix)
                    && q.after.as_ref().is_none_or(|(k, id)| marker(k) && opt(id))
            }
            RequestCall::upload_extents { key: k, limit, .. } => key(k) && *limit <= MAX_EXTENTS,
            RequestCall::usage_buckets { after, limit } => {
                *limit <= MAX_PAGE && after.len() <= MAX_KEY_BYTES
            }
            RequestCall::raise_floors { ids, .. } | RequestCall::settle_floors { ids, .. } => {
                page(ids.len()) && ids.iter().all(|(k, _)| key(k))
            }
            RequestCall::delete_objects_before { deletes, .. } => {
                page(deletes.len()) && deletes.iter().all(|(k, _, _)| key(k))
            }
            RequestCall::commit_generation { c, .. } | RequestCall::commit_sliced { c, .. } => {
                extents(c.extents.len()) && key(&c.generation.key)
            }
            RequestCall::copy_generation { c, .. } => key(&c.generation.key) && key(&c.source_key),
            RequestCall::open_intents { extents: x, .. } => extents(x.len()),
            RequestCall::intents_generation { slices, .. } => *slices <= MAX_EXTENTS,
            RequestCall::put_upload_part_sliced {
                key: k, extents: x, ..
            } => key(k) && extents(x.len()),
            RequestCall::complete_upload { key: k, c, .. } => {
                key(k) && key(&c.generation.key) && extents(c.placements.len())
            }
            RequestCall::create_upload { u } => key(&u.key),
            RequestCall::replay_probe { g } => key(&g.key),
            // The plane's reads: lookups of at most 64, pages of 1 to
            // 1,000, and every name or id within the key bound.
            RequestCall::bucket_names { ids: v } | RequestCall::buckets_named { names: v } => {
                v.len() <= super::plane::MAX_LOOKUP && v.iter().all(|s| key(s))
            }
            RequestCall::buckets_page { after, limit } => {
                (1..=super::plane::MAX_ITEMS).contains(limit) && after.as_deref().is_none_or(key)
            }
            RequestCall::keys_page { after, limit, .. } => {
                (1..=super::plane::MAX_ITEMS).contains(limit)
                    && after
                        .as_ref()
                        .is_none_or(|a| key(&a.id) && i64::try_from(a.created_at).is_ok())
            }
            RequestCall::bucket_by_id { id } | RequestCall::key_by_id { id } => key(id),
            _ => true,
        };
        if ok {
            Ok(())
        } else {
            Err(RequestRefusal::OutOfBounds)
        }
    }

    /// Runs the method on the unit's catalogue. Its answer is the
    /// method's return value as JSON. The unit's own rules (state,
    /// closing buckets, size, bounds) are the caller's
    /// (`Unit::handle`); `bucket_by_name` and `buckets_for` leave out
    /// closing buckets here.
    pub async fn run<S: Sql>(self, cat: &SqlCatalog<S>) -> Result<Value> {
        match self {
            RequestCall::access_key { akid } => answer(Catalog::access_key(cat, &akid).await?),
            RequestCall::grant { akid, bucket } => {
                answer(Catalog::grant(cat, &akid, &bucket).await?)
            }
            RequestCall::bucket_by_name { name } => {
                let b = match Catalog::bucket_by_name(cat, &name).await? {
                    Some(b) if super::buckets::is_closing(&cat.sql, b.id.as_str())? => None,
                    other => other,
                };
                answer(b)
            }
            RequestCall::buckets_for { akid } => {
                let mut open = Vec::new();
                for b in Catalog::buckets_for(cat, &akid).await? {
                    if !super::buckets::is_closing(&cat.sql, b.id.as_str())? {
                        open.push(b);
                    }
                }
                answer(open)
            }
            RequestCall::bucket_in_use { bucket } => {
                answer(Catalog::bucket_in_use(cat, &bucket).await?)
            }
            RequestCall::live_object { bucket, key } => {
                answer(Catalog::live_object(cat, &bucket, &key).await?)
            }
            RequestCall::live_generation { bucket, key } => {
                answer(Catalog::live_generation(cat, &bucket, &key).await?)
            }
            RequestCall::generation_by_id { bucket, generation } => {
                answer(Catalog::generation_by_id(cat, &bucket, &generation).await?)
            }
            RequestCall::extents_in {
                generation,
                start,
                end,
            } => answer(Catalog::extents_in(cat, &generation, start, end).await?),
            RequestCall::newest_id { bucket, key } => {
                answer(Catalog::newest_id(cat, &bucket, &key).await?)
            }
            RequestCall::unpublished_floor { bucket, key } => {
                answer(Catalog::unpublished_floor(cat, &bucket, &key).await?)
            }
            RequestCall::key_heads { bucket, keys } => {
                let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
                answer(Catalog::key_heads(cat, &bucket, &keys).await?)
            }
            RequestCall::list { bucket, q } => answer(Catalog::list(cat, &bucket, &q).await?),
            RequestCall::list_heads { bucket, q } => {
                answer(Catalog::list_heads(cat, &bucket, &q).await?)
            }
            RequestCall::object_status { bucket, key } => {
                answer(Catalog::object_status(cat, &bucket, &key).await?)
            }
            RequestCall::replay_probe { g } => answer(Catalog::replay_probe(cat, &g).await?),
            RequestCall::restore_pending {} => answer(Catalog::restore_pending(cat).await?),
            RequestCall::articles { extent } => answer(Catalog::articles(cat, &extent).await?),
            RequestCall::touch_read {
                extent,
                now,
                min_gap_ms,
                from_cache,
            } => answer(Catalog::touch_read(cat, &extent, now, min_gap_ms, from_cache).await?),
            RequestCall::record_cache_fill { extent, now } => {
                answer(Catalog::record_cache_fill(cat, &extent, now).await?)
            }
            RequestCall::upload {
                bucket,
                key,
                upload,
            } => answer(Catalog::upload(cat, &target(&bucket, &key, &upload)).await?),
            RequestCall::list_uploads { bucket, q } => {
                answer(Catalog::list_uploads(cat, &bucket, &q).await?)
            }
            RequestCall::upload_extents {
                bucket,
                key,
                upload,
                limit,
            } => {
                answer(Catalog::upload_extents(cat, &target(&bucket, &key, &upload), limit).await?)
            }
            RequestCall::upload_extents_held { upload, except } => {
                answer(Catalog::upload_extents_held(cat, &upload, except).await?)
            }
            RequestCall::outbox_stats {} => answer(Catalog::outbox_stats(cat).await?),
            RequestCall::intent_stats { open_before } => {
                answer(Catalog::intent_stats(cat, open_before).await?)
            }
            RequestCall::usage_counters {} => answer(Catalog::usage_counters(cat).await?),
            RequestCall::usage_snapshot { hours } => {
                answer(Catalog::usage_snapshot(cat, hours).await?)
            }
            RequestCall::usage_buckets { after, limit } => {
                answer(Catalog::usage_buckets(cat, &after, limit).await?)
            }
            RequestCall::usage_recounts {} => answer(Catalog::usage_recounts(cat).await?),
            RequestCall::hot_stats {} => answer(Catalog::hot_stats(cat).await?),
            RequestCall::hot_seq { extent } => answer(Catalog::hot_seq(cat, &extent).await?),
            RequestCall::bucket_names { ids } => {
                answer(super::plane::bucket_names(&cat.sql, &ids)?)
            }
            RequestCall::buckets_page { after, limit } => answer(super::plane::buckets_page(
                &cat.sql,
                after.as_deref(),
                limit,
            )?),
            RequestCall::buckets_named { names } => {
                answer(super::plane::buckets_named(&cat.sql, &names)?)
            }
            RequestCall::bucket_by_id { id } => answer(super::plane::bucket_by_id(&cat.sql, &id)?),
            RequestCall::keys_page { kind, after, limit } => answer(super::plane::keys_page(
                &cat.sql,
                kind,
                after.as_ref(),
                limit,
            )?),
            RequestCall::key_by_id { id } => answer(super::plane::key_by_id(&cat.sql, &id)?),
            RequestCall::reach {} => answer(super::plane::reach(&cat.sql)?),
            RequestCall::commit_generation {
                c,
                condition,
                record,
            } => published(
                Catalog::commit_generation(cat, &c, condition.as_ref(), proof(record)).await?,
            ),
            RequestCall::commit_sliced {
                c,
                write,
                condition,
                record,
            } => published(
                Catalog::commit_sliced(cat, &c, &write, condition.as_ref(), proof(record)).await?,
            ),
            RequestCall::copy_generation {
                c,
                condition,
                record,
            } => published(
                Catalog::copy_generation(cat, &c, condition.as_ref(), proof(record)).await?,
            ),
            RequestCall::open_intents {
                write,
                extents,
                now,
            } => answer(Catalog::open_intents(cat, &write, &extents, now).await?),
            RequestCall::intents_generation {
                write,
                generation,
                slices,
            } => answer(
                Catalog::intents_generation(cat, &write, &generation, slices as usize).await?,
            ),
            RequestCall::abandon_intents { write } => {
                answer(Catalog::abandon_intents(cat, &write).await?)
            }
            RequestCall::raise_floor {
                bucket,
                key,
                id,
                generation,
            } => answer(Catalog::raise_floor(cat, &bucket, &key, &id, generation).await?),
            RequestCall::settle_floor { bucket, key, id } => {
                answer(Catalog::settle_floor(cat, &bucket, &key, &id).await?)
            }
            RequestCall::raise_floors { bucket, ids } => {
                let ids: Vec<(&str, &GenerationId)> =
                    ids.iter().map(|(k, g)| (k.as_str(), g)).collect();
                answer(Catalog::raise_floors(cat, &bucket, &ids).await?)
            }
            RequestCall::settle_floors { bucket, ids } => {
                let ids: Vec<(&str, &GenerationId)> =
                    ids.iter().map(|(k, g)| (k.as_str(), g)).collect();
                answer(Catalog::settle_floors(cat, &bucket, &ids).await?)
            }
            RequestCall::delete_object_before {
                bucket,
                key,
                before,
                now,
            } => answer(Catalog::delete_object_before(cat, &bucket, &key, &before, now).await?),
            RequestCall::delete_object_if {
                bucket,
                key,
                before,
                condition,
                now,
            } => answer(
                Catalog::delete_object_if(cat, &bucket, &key, &before, &condition, now).await?,
            ),
            RequestCall::delete_objects_before { bucket, deletes } => {
                let deletes: Vec<(&str, &GenerationId, UnixMs)> = deletes
                    .iter()
                    .map(|(k, g, t)| (k.as_str(), g, *t))
                    .collect();
                answer(Catalog::delete_objects_before(cat, &bucket, &deletes).await?)
            }
            RequestCall::create_upload { u } => answer(Catalog::create_upload(cat, &u).await?),
            RequestCall::put_upload_part {
                bucket,
                key,
                upload,
                part,
                extent,
                now,
            } => answer(
                Catalog::put_upload_part(cat, &target(&bucket, &key, &upload), &part, &extent, now)
                    .await?,
            ),
            RequestCall::put_upload_part_sliced {
                bucket,
                key,
                upload,
                part,
                extents,
                write,
                now,
            } => answer(
                Catalog::put_upload_part_sliced(
                    cat,
                    &target(&bucket, &key, &upload),
                    &part,
                    &extents,
                    &write,
                    now,
                )
                .await?,
            ),
            RequestCall::complete_upload {
                bucket,
                key,
                upload,
                revision,
                digest,
                c,
                condition,
                record,
            } => published(
                Catalog::complete_upload(
                    cat,
                    &target(&bucket, &key, &upload),
                    revision,
                    &digest,
                    &c,
                    condition.as_ref(),
                    proof(record),
                )
                .await?,
            ),
            RequestCall::abort_upload {
                bucket,
                key,
                upload,
                now,
            } => answer(Catalog::abort_upload(cat, &target(&bucket, &key, &upload), now).await?),
            RequestCall::fence_upload {
                bucket,
                key,
                upload,
                revision,
            } => answer(
                cat.fence_upload(&target(&bucket, &key, &upload), revision)
                    .await?,
            ),
        }
    }
}

/// What a presigned URL on entry point `presigned` names besides its
/// key (AM-64, SEC-1): the principal it was minted for (`x-kofra-p`),
/// the bucket of its target, and its create-only flag (`c`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presigned {
    pub principal: String,
    /// The bucket name of the URL's target.
    pub bucket: String,
    #[serde(default)]
    pub create_only: bool,
}

/// Why the presigned check failed. The row comes back all the same; the
/// Worker answers `403 SignatureDoesNotMatch` if SigV4 fails, and only
/// then `403 AccessDenied` for this (AM-64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresignRefusal {
    /// The key is not the unit's internal key (only it signs on this
    /// entry point, X-8).
    NotInternal,
    /// The internal key is not `active`, or is held.
    KeyInactive,
    /// The principal or the bucket name is not well formed.
    Malformed,
    /// No principal that is not revoked has this id.
    PrincipalUnknown,
    /// The principal is not `active`.
    PrincipalInactive,
    /// The principal is held (AM-9).
    PrincipalHeld,
    /// The principal's row carries an `owner_ref` conflict mark (AM-72):
    /// it resolves to no principal until an operator clears it.
    OwnerRefAmbiguous,
    /// The unit holds no open bucket of that name.
    NoSuchBucket,
    /// The principal's effective grant does not cover the bucket (for a
    /// create-only URL: not with `rw`).
    NoGrant,
}

/// The presigned part of a `key_row` answer (AM-64): the internal key's
/// row, and whether the principal may use the URL now. Read-only; run in
/// the `key_row`'s transaction.
pub(crate) fn presigned_check<S: Sql>(
    sql: &S,
    cat: &SqlCatalog<S>,
    access_key_id: &str,
    p: &Presigned,
) -> Result<(Value, Value)> {
    let key = match super::keys::internal_key(sql, access_key_id)? {
        Some(k) => serde_json::json!({
            "access_key_id": access_key_id,
            "principal": "",
            "secret_wrapped": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &k.secret_wrapped,
            ),
            "kek_version": k.kek_version,
            "status": if k.open { "active" } else { "disabled" },
            "created_at": k.created_at,
        }),
        None => Value::Null,
    };
    let verdict = |ok: std::result::Result<(String, super::keys::Access), PresignRefusal>| match ok
    {
        Ok((bucket_id, access)) => serde_json::json!({
            "ok": true,
            "refusal": Value::Null,
            "bucket_id": bucket_id,
            "access": access.as_str(),
        }),
        Err(r) => serde_json::json!({
            "ok": false,
            "refusal": r,
            "bucket_id": Value::Null,
            "access": Value::Null,
        }),
    };
    if key.is_null() {
        return Ok((key, verdict(Err(PresignRefusal::NotInternal))));
    }
    if key["status"] != "active" {
        return Ok((key, verdict(Err(PresignRefusal::KeyInactive))));
    }
    if !super::reserve::valid_id(&p.principal) || p.bucket.is_empty() || p.bucket.len() > 255 {
        return Ok((key, verdict(Err(PresignRefusal::Malformed))));
    }
    let acting = super::reserve::Acting::Principal(p.principal.clone());
    if let Err(r) = super::reserve::resolve(sql, &acting)? {
        use super::reserve::ReserveRefusal as R;
        let r = match r {
            R::ActingPrincipalInactive => PresignRefusal::PrincipalInactive,
            R::ActingPrincipalHeld => PresignRefusal::PrincipalHeld,
            R::Malformed => PresignRefusal::Malformed,
            R::OwnerRefAmbiguous => PresignRefusal::OwnerRefAmbiguous,
            _ => PresignRefusal::PrincipalUnknown,
        };
        return Ok((key, verdict(Err(r))));
    }
    let bucket = match super::object::poll_once(Catalog::bucket_by_name(cat, &p.bucket))?? {
        Some(b) if !super::buckets::is_closing(sql, b.id.as_str())? => b,
        _ => return Ok((key, verdict(Err(PresignRefusal::NoSuchBucket)))),
    };
    // The effective grant: the principal's unlimited grants, each lowered
    // along its `made_by` chain; none when one up the chain is not open.
    let access = super::keys::principal_effective(sql, &p.principal)?
        .unwrap_or_default()
        .into_iter()
        .find(|(b, _)| b == bucket.id.as_str())
        .map(|(_, a)| a);
    let ok = match access {
        Some(super::keys::Access::Ro) if p.create_only => Err(PresignRefusal::NoGrant),
        Some(a) => Ok((bucket.id.as_str().to_string(), a)),
        None => Err(PresignRefusal::NoGrant),
    };
    Ok((key, verdict(ok)))
}

fn target<'a>(bucket: &'a BucketId, key: &'a str, upload: &'a UploadId) -> UploadTarget<'a> {
    UploadTarget {
        bucket,
        key,
        id: upload,
    }
}

fn proof(r: RecordWire) -> Recorded {
    Recorded::across_unit(r.generation, r.key)
}

fn published(o: PublishOutcome) -> Result<Value> {
    answer(Published::of(&o))
}

fn answer<T: Serialize>(v: T) -> Result<Value> {
    serde_json::to_value(v).map_err(|_| BridgeError::Invalid("unit: request answer"))
}
