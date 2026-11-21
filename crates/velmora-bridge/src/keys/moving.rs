//! Moving tenant 0's data into a managed tenant: the key and record work.
//!
//! The move copies the catalogue into the new tenant's unit and changes
//! only what binds a tenant. This module does that part:
//!
//! - **re-wrap**: each bucket key from scheme 1 to scheme 2
//!   ([`moved_bucket`]), each S3 secret from `ak/v1` to `ak/v2`, with the
//!   same key id and the same secret ([`write_moved_keys`]);
//! - **re-seal**: generation records, article plans and tombstones as
//!   VMR2 records of the new tenant ([`reseal_generation`],
//!   [`reseal_article_plan`], [`reseal_tombstone`], [`put_sealed`]); the
//!   new tenant's key chain from the frozen key rows
//!   ([`write_moved_keys`]);
//! - **re-home**: a held safety copy from `x/<id>` to `x/<t>/<id>`, and a
//!   warm copy from `c/<id>` to `c/<t>/<id>`, each checked by its SHA-256
//!   ([`rehome_blob`]);
//! - **verify**: every file key opens under the new bucket key
//!   ([`check_file_keys`]); every held extent has its copy under the new
//!   name ([`verify_held`]); the new tenant's records open
//!   ([`count_records`]).
//!
//! Nothing here deletes, and nothing changes an extent id, a bucket id,
//! a file-key wrap, a ciphertext or an article: file-key wraps bind the
//! bucket id and the extent id and no tenant. Every function can be run
//! again: what is already there is read back and compared.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;

use super::chain::Put;
use super::checkpoint::read_key_chain;
use super::record::{
    key_chain, open_key_record, seal_key_record, Access, DoorGrant, KeyOp, KeyTable, PrivateGrant,
    SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus, TkRing,
};
use super::revocations::put_tenant_revocation;
use super::store::RecordStore;
use crate::crypto::scheme2::{
    open_record_v2, record_v2_header, rewrap_bdk_to_v2, rewrap_secret_to_v2, same_secret,
    seal_record_v2, unwrap_bdk_v2, Scheme, TenantId, TenantKey,
};
use crate::crypto::unwrap_file_key;
use crate::plan::StoredPlan;
use crate::ports::{BlobMeta, BlobStore, Kek};
use crate::recovery::{ArticleManifest, GenerationManifest, Layout, Tombstone};
use crate::types::{
    BridgeError, Bucket, BucketId, ExtentId, ExtentRow, GenerationId, GenerationRow, Result,
};

/// Another writer took a seq of the new tenant's key chain during the
/// move. Nothing else writes it in the window, so the move gives up.
pub const ERR_MOVE_RACE: BridgeError = BridgeError::Invalid("the key chain moved under the move");
/// What the target already holds differs from what the move would write.
pub const ERR_MOVE_DIFFERS: BridgeError =
    BridgeError::Invalid("the target holds something else under this name");
/// A safety or cache copy does not have the SHA-256 its row names.
pub const ERR_BLOB_DIGEST: BridgeError =
    BridgeError::Invalid("a copy does not match its catalogued digest");
/// The input is not what a move takes (a principal that is missing, a
/// bucket with another scheme, ...).
pub const ERR_MOVE_INPUT: BridgeError = BridgeError::Invalid("move input is not valid");

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// The safety copy of `extent` of a managed tenant: `x/<t>/<id>`.
pub fn tenant_safety_key(tenant: &TenantId, extent: &ExtentId) -> String {
    format!("x/{tenant}/{}", extent.as_str())
}

/// The cache copy of `extent` of a managed tenant: `c/<t>/<id>`.
pub fn tenant_cache_key(tenant: &TenantId, extent: &ExtentId) -> String {
    format!("c/{tenant}/{}", extent.as_str())
}

fn layout(tenant: &TenantId) -> Result<Layout> {
    Layout::tenant(tenant.as_str()).ok_or(ERR_MOVE_INPUT)
}

// ---------------------------------------------------------------------------
// Re-wrap and verify of a bucket
// ---------------------------------------------------------------------------

/// The bucket row as the new tenant holds it: the bucket key re-wrapped
/// to scheme 2 under `tk`, the row's key version set to `tk`'s, the
/// owner set to `owner`. Everything else is kept.
pub fn moved_bucket<K: Kek, R: FillRandom>(
    kek: &K,
    tk: &TenantKey,
    bucket: &Bucket,
    owner: &str,
    rng: &mut R,
) -> Result<Bucket> {
    Scheme::One.check(&bucket.bdk_wrapped)?;
    let wrapped = rewrap_bdk_to_v2(
        kek,
        bucket.kek_version,
        &bucket.id,
        &bucket.bdk_wrapped,
        tk,
        rng,
    )?;
    Ok(Bucket {
        bdk_wrapped: wrapped,
        kek_version: tk.version(),
        owner: owner.to_owned(),
        ..bucket.clone()
    })
}

/// What [`check_file_keys`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileKeyCheck {
    /// File keys that opened.
    pub opened: u64,
    /// Extents whose file key is gone (a deleted object's, past its
    /// grace): they can be read by nobody, before or after the move.
    pub without_key: u64,
    /// Extents whose file key did not open: the move stops.
    pub failed: Vec<ExtentId>,
}

/// Opens every file key of `extents` under the bucket key of the moved
/// bucket row `bucket` (scheme 2, `tk`). An extent of another bucket is a
/// failure.
pub fn check_file_keys<'a>(
    tk: &TenantKey,
    bucket: &Bucket,
    extents: impl IntoIterator<Item = &'a ExtentRow>,
) -> Result<FileKeyCheck> {
    let bdk = unwrap_bdk_v2(
        tk,
        tk.tenant(),
        bucket.kek_version,
        &bucket.id,
        &bucket.bdk_wrapped,
    )?;
    let mut check = FileKeyCheck::default();
    for extent in extents {
        if extent.bucket_id != bucket.id {
            check.failed.push(extent.id.clone());
            continue;
        }
        match &extent.wrapped_file_key {
            None => check.without_key += 1,
            Some(w) => match unwrap_file_key(&bdk, &bucket.id, &extent.id, w) {
                Ok(_) => check.opened += 1,
                Err(_) => check.failed.push(extent.id.clone()),
            },
        }
    }
    Ok(check)
}

// ---------------------------------------------------------------------------
// Re-seal of data records
// ---------------------------------------------------------------------------

/// A record sealed for the new tenant, with its name and its plaintext
/// (records hold wrapped keys only, never a plaintext key).
#[derive(Clone)]
pub struct Sealed {
    pub name: String,
    pub plain: Vec<u8>,
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("name", &self.name)
            .field("len", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

fn seal<R: FillRandom>(
    tk: &TenantKey,
    name: String,
    plain: Vec<u8>,
    rng: &mut R,
) -> Result<Sealed> {
    let sealed = seal_record_v2(tk, &name, &plain, rng)?;
    Ok(Sealed {
        name,
        plain,
        sealed,
    })
}

/// The generation record of the moved bucket row `bucket` (already
/// re-wrapped by [`moved_bucket`]), sealed as VMR2 under the new
/// tenant's record directory. The body is the one a v1 record of the
/// same rows has, with the scheme-2 bucket key.
pub fn reseal_generation<R: FillRandom>(
    tk: &TenantKey,
    bucket: &Bucket,
    generation: &GenerationRow,
    extents: &[ExtentRow],
    rng: &mut R,
) -> Result<Sealed> {
    Scheme::Two(tk.tenant().clone()).check(&bucket.bdk_wrapped)?;
    if bucket.kek_version != tk.version() || generation.bucket_id != bucket.id {
        return Err(ERR_MOVE_INPUT);
    }
    let manifest = GenerationManifest::new(bucket, generation, extents)?;
    let plain = serde_json::to_vec(&manifest).map_err(|_| ERR_MOVE_INPUT)?;
    let name = layout(tk.tenant())?.generation_key(&generation.id);
    seal(tk, name, plain, rng)
}

/// The article plan of `extent`, sealed as VMR2 for the new tenant.
pub fn reseal_article_plan<R: FillRandom>(
    tk: &TenantKey,
    extent: &ExtentRow,
    plan: &StoredPlan,
    rng: &mut R,
) -> Result<Sealed> {
    let plain =
        serde_json::to_vec(&ArticleManifest::of(extent, plan)).map_err(|_| ERR_MOVE_INPUT)?;
    let name = layout(tk.tenant())?.article_key(&extent.id);
    seal(tk, name, plain, rng)
}

/// A tombstone, sealed as VMR2 for the new tenant: for a generation
/// that was re-sealed before the freeze and is no longer servable at it.
pub fn reseal_tombstone<R: FillRandom>(
    tk: &TenantKey,
    tombstone: &Tombstone,
    rng: &mut R,
) -> Result<Sealed> {
    let plain = serde_json::to_vec(tombstone).map_err(|_| ERR_MOVE_INPUT)?;
    let name = layout(tk.tenant())?.tombstone_key(&GenerationId::new(&tombstone.id));
    seal(tk, name, plain, rng)
}

/// Where a sealed record went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placed {
    /// Stored by this call.
    Written,
    /// A record with the same plaintext was there already (a run that is
    /// resumed).
    Same,
}

/// Puts `sealed` once. A record already under the name is opened and
/// compared: the same plaintext is [`Placed::Same`]; anything else is
/// [`ERR_MOVE_DIFFERS`], and the move stops.
pub async fn put_sealed<S: RecordStore>(
    store: &S,
    tk: &TenantKey,
    sealed: &Sealed,
) -> Result<Placed> {
    let put = store
        .put_if_absent(&sealed.name, sealed.sealed.clone())
        .await;
    if let Ok(true) = put {
        return Ok(Placed::Written);
    }
    let Some(there) = store.get(&sealed.name).await? else {
        return match put {
            Err(e) => Err(e),
            Ok(_) => Err(ERR_MOVE_DIFFERS),
        };
    };
    if there == sealed.sealed {
        return Ok(Placed::Written);
    }
    let opened =
        open_record_v2(tk, tk.tenant(), &sealed.name, &there).map_err(|_| ERR_MOVE_DIFFERS)?;
    if *opened != *sealed.plain {
        return Err(ERR_MOVE_DIFFERS);
    }
    Ok(Placed::Same)
}

/// What [`count_records`] found under the new tenant's record directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordCount {
    pub generations: u64,
    pub tombstones: u64,
    pub plans: u64,
    pub other: u64,
    /// Names whose record does not open under the ring, or names another
    /// tenant: each is a failed check.
    pub failed: Vec<String>,
}

/// Opens every record under `m/x/<t>/` and counts them by kind. The
/// bucket configuration records (`m/x/<t>/b/`) are control records and
/// are left out.
pub async fn count_records<S: RecordStore, T: TkRing>(
    store: &S,
    ring: &T,
    tenant: &TenantId,
) -> Result<RecordCount> {
    let layout = layout(tenant)?;
    let root = layout.root().to_owned();
    let generations = layout.generation_prefix();
    let tombstones = layout.tombstone_prefix();
    let plans = format!("{root}art/");
    let config = format!("{root}b/");
    let mut count = RecordCount::default();
    let mut after = root.clone();
    loop {
        let names = store.list(&root, &after, 1000).await?;
        for name in &names {
            if name.starts_with(&config) {
                continue;
            }
            let Some(bytes) = store.get(name).await? else {
                continue;
            };
            let opens = record_v2_header(&bytes)
                .ok()
                .filter(|(t, _)| t == tenant)
                .and_then(|(_, v)| ring.key(v))
                .is_some_and(|tk| open_record_v2(tk, tenant, name, &bytes).is_ok());
            if !opens {
                count.failed.push(name.clone());
            } else if name.starts_with(&generations) {
                count.generations += 1;
            } else if name.starts_with(&tombstones) {
                count.tombstones += 1;
            } else if name.starts_with(&plans) {
                count.plans += 1;
            } else {
                count.other += 1;
            }
        }
        match names.last() {
            Some(last) if names.len() >= 1000 => after.clone_from(last),
            _ => return Ok(count),
        }
    }
}

// ---------------------------------------------------------------------------
// The new tenant's key chain, from the frozen key rows
// ---------------------------------------------------------------------------

/// One tenant-0 key that moves, as the frozen rows and the key map give
/// it.
#[derive(Clone)]
pub struct MovedKey {
    pub access_key_id: String,
    /// `S3` or `AppPassword`, from the key map.
    pub kind: SubjectKind,
    /// `Active` or `Disabled` from the row; `Revoked` when tenant 0 holds
    /// a revocation for the key.
    pub status: SubjectStatus,
    /// The `ak/v1` wrap and its KEK version, from the row.
    pub secret_wrapped_v1: Vec<u8>,
    pub kek_version: u32,
    /// Grants on moved buckets only: bucket id and access.
    pub grants: Vec<(String, Access)>,
    pub created_at: u64,
}

impl std::fmt::Debug for MovedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MovedKey")
            .field("access_key_id", &self.access_key_id)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// What [`write_moved_keys`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MovedKeys {
    /// Chain records written by this run.
    pub written: Vec<u64>,
    /// Keys already in the chain with the same content (a resumed run).
    pub present: Vec<String>,
    /// Revocations written under the new tenant.
    pub revoked: Vec<String>,
}

/// Writes the new tenant's key chain for the moved keys:
///
/// 1. the principal `principal` (made by the provisioning before the
///    window) gets `rw` on each moved bucket, one record per bucket, so
///    every moved key keeps exactly its effective grant;
/// 2. one create record per moved key, made under that principal, with
///    the same key id and the secret re-wrapped as `ak/v2`; a disabled
///    key is then disabled; a revoked key gets its revocation under the
///    new tenant and then its revoke record.
///
/// Each record is exactly the next seq; nothing else writes the chain in
/// the window, so a lost put gives up ([`ERR_MOVE_RACE`]). A key already
/// in the chain must hold the same kind, grants, principal and secret.
#[allow(clippy::too_many_arguments)]
pub async fn write_moved_keys<S, K, T, R>(
    store: &S,
    kek: &K,
    ring: &T,
    tenant: &TenantId,
    principal: &str,
    owner_ref: &str,
    buckets: &[String],
    keys: &[MovedKey],
    at: u64,
    rng: &mut R,
) -> Result<MovedKeys>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    R: FillRandom,
{
    let mut table = read_key_chain(store, kek, ring, tenant).await?.table;
    let mut out = MovedKeys::default();
    let moved: BTreeSet<&str> = buckets.iter().map(String::as_str).collect();

    // 1. The principal's grants.
    let entry = table.get(principal).ok_or(ERR_MOVE_INPUT)?;
    if entry.door.kind != SubjectKind::Principal || entry.private.is_none() {
        return Err(ERR_MOVE_INPUT);
    }
    for bucket in buckets {
        let entry = table.get(principal).ok_or(ERR_MOVE_INPUT)?;
        let has = entry
            .door
            .grants
            .iter()
            .zip(entry.private.iter().flat_map(|p| &p.grants))
            .any(|(d, p)| {
                d.bucket_id == *bucket
                    && d.access == Access::Rw
                    && d.expires_at.is_none()
                    && p.prefix.is_none()
                    && p.ip_list.is_empty()
            });
        if has {
            continue;
        }
        let mut door = entry.door.clone();
        let mut private = entry.private.clone().ok_or(ERR_MOVE_INPUT)?;
        // Replace any narrower grant on the bucket with the full one.
        let keep: Vec<bool> = door.grants.iter().map(|g| g.bucket_id != *bucket).collect();
        door.grants = door
            .grants
            .into_iter()
            .zip(&keep)
            .filter(|(_, k)| **k)
            .map(|(g, _)| g)
            .collect();
        private.grants = private
            .grants
            .into_iter()
            .zip(&keep)
            .filter(|(_, k)| **k)
            .map(|(g, _)| g)
            .collect();
        door.grants.push(DoorGrant {
            bucket_id: bucket.clone(),
            access: Access::Rw,
            expires_at: None,
        });
        private.grants.push(PrivateGrant {
            bucket_id: bucket.clone(),
            prefix: None,
            ip_list: Vec::new(),
        });
        let seq = append(
            store,
            kek,
            ring,
            tenant,
            &mut table,
            KeyOp::Grants,
            at,
            &door,
            Some(&private),
            false,
            rng,
        )
        .await?;
        out.written.push(seq);
    }

    // 2. The keys.
    for key in keys {
        let kind_ok = matches!(key.kind, SubjectKind::S3 | SubjectKind::AppPassword);
        let grants_ok = key.grants.iter().all(|(b, _)| moved.contains(b.as_str()));
        if !kind_ok || !grants_ok {
            return Err(ERR_MOVE_INPUT);
        }
        let door_grants: Vec<DoorGrant> = key
            .grants
            .iter()
            .map(|(b, a)| DoorGrant {
                bucket_id: b.clone(),
                access: *a,
                expires_at: None,
            })
            .collect();
        let private_grants: Vec<PrivateGrant> = key
            .grants
            .iter()
            .map(|(b, _)| PrivateGrant {
                bucket_id: b.clone(),
                prefix: None,
                ip_list: Vec::new(),
            })
            .collect();
        if let Some(entry) = table.get(&key.access_key_id) {
            // A resumed run: the key must be the one this run would write.
            let private = entry.private.as_ref().ok_or(ERR_MOVE_DIFFERS)?;
            let same = entry.door.kind == key.kind
                && entry.door.made_by.as_deref() == Some(principal)
                && entry.door.grants == door_grants
                && private.grants == private_grants
                && match (entry.door.secret_kek_version, &private.secret_wrapped) {
                    (Some(v2), Some(w2)) => same_secret(
                        kek,
                        key.kek_version,
                        &key.secret_wrapped_v1,
                        tenant,
                        v2,
                        w2,
                        &key.access_key_id,
                    )
                    .unwrap_or(false),
                    _ => false,
                };
            if !same {
                return Err(ERR_MOVE_DIFFERS);
            }
            out.present.push(key.access_key_id.clone());
        } else {
            let (v2, wrapped) = rewrap_secret_to_v2(
                kek,
                key.kek_version,
                &key.access_key_id,
                &key.secret_wrapped_v1,
                tenant,
                rng,
            )?;
            let door = SubjectDoor {
                id: key.access_key_id.clone(),
                kind: key.kind,
                status: SubjectStatus::Active,
                made_by: Some(principal.to_owned()),
                grants: door_grants,
                created_at: key.created_at,
                secret_kek_version: Some(v2),
            };
            let private = SubjectPrivate {
                owner_ref: Some(owner_ref.to_owned()),
                label: None,
                grants: private_grants,
                secret_wrapped: Some(wrapped),
            };
            let seq = append(
                store,
                kek,
                ring,
                tenant,
                &mut table,
                KeyOp::Create,
                at,
                &door,
                Some(&private),
                false,
                rng,
            )
            .await?;
            out.written.push(seq);
        }

        // The status, when it is not active.
        let entry = table.get(&key.access_key_id).ok_or(ERR_MOVE_INPUT)?;
        if key.status == SubjectStatus::Revoked {
            put_tenant_revocation(store, kek, tenant, &key.access_key_id, at, rng).await?;
            out.revoked.push(key.access_key_id.clone());
        }
        if entry.door.status != key.status {
            if entry.door.status == SubjectStatus::Revoked {
                return Err(ERR_MOVE_DIFFERS);
            }
            let mut door = entry.door.clone();
            door.status = key.status;
            let private = entry.private.clone();
            let seq = append(
                store,
                kek,
                ring,
                tenant,
                &mut table,
                KeyOp::Status,
                at,
                &door,
                private.as_ref(),
                key.status != SubjectStatus::Active,
                rng,
            )
            .await?;
            out.written.push(seq);
        }
    }
    Ok(out)
}

/// Writes one record at exactly the next seq and folds it in. `closes`:
/// the record closes a door (a disable or a revoke).
#[allow(clippy::too_many_arguments)]
async fn append<S: RecordStore, K: Kek, T: TkRing, R: FillRandom>(
    store: &S,
    kek: &K,
    ring: &T,
    tenant: &TenantId,
    table: &mut KeyTable,
    op: KeyOp,
    at: u64,
    door: &SubjectDoor,
    private: Option<&SubjectPrivate>,
    closes: bool,
    rng: &mut R,
) -> Result<u64> {
    table.admits(op, door, private)?;
    let seq = table.seq() + 1;
    let bytes = seal_key_record(kek, ring, tenant, seq, op, at, door, private, closes, rng)?;
    if key_chain(tenant).put(store, seq, bytes.clone()).await? != Put::Written {
        return Err(ERR_MOVE_RACE);
    }
    table.apply(&open_key_record(kek, ring, tenant, seq, &bytes)?)?;
    Ok(seq)
}

// ---------------------------------------------------------------------------
// Re-home of blobs
// ---------------------------------------------------------------------------

/// What [`rehome_blob`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rehomed {
    /// Copied and read back.
    Copied,
    /// The new name held the same bytes already.
    Present,
    /// The old name holds nothing: for a warm copy, nothing to do; for a
    /// held extent, a failed check.
    Missing,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Copies the blob at `from` to `to` in `store`, checking both against
/// `cipher_sha256`, the digest the extent's row names. The old name is
/// left as it is.
pub async fn rehome_blob<B: BlobStore>(
    store: &B,
    from: &str,
    to: &str,
    bucket: &BucketId,
    extent: &ExtentId,
    cipher_sha256: &[u8; 32],
) -> Result<Rehomed> {
    if let Some(there) = store.get(to, None).await? {
        return match sha256(&there) == *cipher_sha256 {
            true => Ok(Rehomed::Present),
            false => Err(ERR_BLOB_DIGEST),
        };
    }
    let Some(bytes) = store.get(from, None).await? else {
        return Ok(Rehomed::Missing);
    };
    if sha256(&bytes) != *cipher_sha256 {
        return Err(ERR_BLOB_DIGEST);
    }
    let meta = BlobMeta {
        bucket,
        extent,
        cipher_sha256,
    };
    store.put(to, bytes, &meta).await?;
    match store.get(to, None).await? {
        Some(back) if sha256(&back) == *cipher_sha256 => Ok(Rehomed::Copied),
        _ => Err(ERR_BLOB_DIGEST),
    }
}

/// Every held extent of `extents` (id and catalogued SHA-256) whose
/// safety copy under the new tenant's name is absent or does not match.
/// Empty means the check passes.
pub async fn verify_held<B: BlobStore>(
    store: &B,
    tenant: &TenantId,
    extents: &[(ExtentId, [u8; 32])],
) -> Result<Vec<ExtentId>> {
    let mut failed = Vec::new();
    for (id, digest) in extents {
        match store.get(&tenant_safety_key(tenant, id), None).await? {
            Some(bytes) if sha256(&bytes) == *digest => {}
            _ => failed.push(id.clone()),
        }
    }
    Ok(failed)
}
