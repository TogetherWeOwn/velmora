use crate::{
    Article, Bucket, Entry, Error, Extent, ExtentRef, Object, Parity, ParityRow, RecordRef,
    Verified,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use velmora_bridge::{
    articles::article_spans,
    crypto::open_manifest,
    parity, plan,
    ports::Kek,
    recovery::{
        self, ArticleManifest, ExtentRecord, GenerationHead, GenerationManifest, RecordKind,
        Tombstone,
    },
    types::{ArticleState, ExtentId},
};

#[derive(Default, Deserialize)]
pub struct BuildAnnotations {
    /// Optional independent whole-object digests, indexed by generation ID.
    #[serde(default)]
    pub source_md5: BTreeMap<String, Vec<u8>>,
    /// Optional Drive manifest identities, scoped to the named destination
    /// bucket and exact key/size, not to matching keys in every bucket.
    #[serde(default)]
    pub source_objects: Vec<SourceObject>,
    /// When provided, only a plan matching a released catalogue revision is
    /// usable. An unobserved extent is not assumed released.
    #[serde(default)]
    pub released: Option<BTreeMap<String, Release>>,
}

#[derive(Deserialize)]
pub struct SourceObject {
    pub bucket_name: String,
    pub key: String,
    pub size: u64,
    pub md5: Vec<u8>,
}

#[derive(Deserialize)]
pub struct Release {
    pub plan_rev: u32,
    pub verified: Option<Vec<Verified>>,
}

/// Names are also tar paths. A storage namespace is never a local path.
pub fn eligible_record(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("m/") else {
        return false;
    };
    if suffix
        .split('/')
        .any(|s| s.is_empty() || matches!(s, "." | ".."))
        || suffix
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b'\\' | b'|' | b':'))
    {
        return false;
    }
    let relative = if let Some(rest) = suffix.strip_prefix("x/") {
        let Some((_, tail)) = rest.split_once('/') else {
            return false;
        };
        tail
    } else {
        suffix
    };
    !relative.starts_with("tk/")
}

pub struct Comparison {
    pub safety_count: usize,
    pub e2_count: usize,
    pub missing_count: usize,
    pub e2_only_count: usize,
    pub missing_examples: Vec<String>,
}

/// Compare eligible names before building. The result contains names only
/// for a private diagnostic; never publish it in the plaintext manifest.
pub fn cross_check<'a>(
    safety: impl IntoIterator<Item = &'a str>,
    e2: impl IntoIterator<Item = &'a str>,
) -> Comparison {
    let safety: BTreeSet<_> = safety.into_iter().filter(|n| eligible_record(n)).collect();
    let e2: BTreeSet<_> = e2.into_iter().filter(|n| eligible_record(n)).collect();
    Comparison {
        safety_count: safety.len(),
        e2_count: e2.len(),
        missing_count: safety.difference(&e2).count(),
        e2_only_count: e2.difference(&safety).count(),
        missing_examples: safety
            .difference(&e2)
            .take(100)
            .map(|n| (*n).to_owned())
            .collect(),
    }
}

#[derive(Deserialize)]
struct GenerationIdentity {
    v: u32,
    bucket: recovery::BucketRecord,
    generation: recovery::GenerationRecord,
}

struct Winner {
    id: String,
    generation: Option<String>,
}

fn valid_extent(id: &str) -> bool {
    id.strip_prefix("x_").is_some_and(|s| {
        (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

fn valid_generation(id: &str) -> bool {
    id.strip_prefix("g_").is_some_and(|s| {
        s.len() == 29
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn load_checked(
    get: &mut impl FnMut(&str) -> Result<Option<Vec<u8>>, Error>,
    records: &BTreeMap<String, [u8; 32]>,
    name: &str,
) -> Result<Vec<u8>, Error> {
    let digest = records.get(name).ok_or(Error::Record)?;
    let sealed = get(name)?.ok_or(Error::Record)?;
    if <[u8; 32]>::from(Sha256::digest(&sealed)) != *digest {
        return Err(Error::Record);
    }
    Ok(sealed)
}

/// Build the full index from one immutable listing of a record store. A
/// store may be a local staging directory; the library performs no writes.
/// The caller cross-checks source listings and uses exactly those names for
/// packing and building. Records are opened with their exact original names.
pub fn build_entries(
    names: impl IntoIterator<Item = String>,
    get: impl FnMut(&str) -> Result<Option<Vec<u8>>, Error>,
    kek: &impl Kek,
    annotations: &BuildAnnotations,
) -> Result<Vec<Entry>, Error> {
    build_entries_with_stats(names, get, kek, annotations).map(|(entries, _)| entries)
}

#[derive(Default)]
pub struct BuildStats {
    /// Number of selected plans whose parity addendum could not be used.
    pub parity_omitted: u64,
}

pub fn build_entries_with_stats(
    names: impl IntoIterator<Item = String>,
    mut get: impl FnMut(&str) -> Result<Option<Vec<u8>>, Error>,
    kek: &impl Kek,
    annotations: &BuildAnnotations,
) -> Result<(Vec<Entry>, BuildStats), Error> {
    let mut stats = BuildStats::default();
    let mut records = BTreeMap::new();
    let mut winners: BTreeMap<(String, String), Winner> = BTreeMap::new();
    let mut plans: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in names {
        if !eligible_record(&name) || records.contains_key(&name) {
            return Err(Error::Record);
        }
        let sealed = get(&name)?.ok_or(Error::Record)?;
        records.insert(name.clone(), Sha256::digest(&sealed).into());
        let Some(record) = recovery::record_name(&name) else {
            continue;
        };
        if record.kind == RecordKind::ArticlePlan {
            if !valid_extent(record.id) {
                return Err(Error::Record);
            }
            plans.entry(record.id.to_owned()).or_default().push(name);
            continue;
        }
        if !valid_generation(record.id) {
            return Err(Error::Record);
        }
        let plain = open_manifest(kek, &name, &sealed).map_err(|_| Error::Authentication)?;
        let (object, id, generation) = match record.kind {
            RecordKind::Generation => {
                let ident: GenerationIdentity =
                    serde_json::from_slice(&plain).map_err(|_| Error::Record)?;
                if !matches!(ident.v, 1 | 2) || ident.generation.id != record.id {
                    return Err(Error::Record);
                }
                (
                    (ident.bucket.id, ident.generation.key),
                    ident.generation.id,
                    Some(name),
                )
            }
            RecordKind::Tombstone => {
                let t: Tombstone = serde_json::from_slice(&plain).map_err(|_| Error::Record)?;
                if t.v != 1 || t.id != record.id {
                    return Err(Error::Record);
                }
                ((t.bucket_id, t.key), t.id, None)
            }
            RecordKind::ArticlePlan => unreachable!(),
        };
        if let Some(old) = winners.get(&object) {
            if id < old.id {
                continue;
            }
            if id == old.id {
                match (&generation, &old.generation) {
                    (None, None) => continue,
                    (Some(a), Some(b)) => {
                        // A record can exist in both layouts; equal identities
                        // must not silently select different object data.
                        let prior = load_checked(&mut get, &records, b)?;
                        let prior =
                            open_manifest(kek, b, &prior).map_err(|_| Error::Authentication)?;
                        if a == b || *plain != *prior {
                            return Err(Error::Record);
                        }
                        continue;
                    }
                    _ => return Err(Error::Record),
                }
            }
        }
        winners.insert(object, Winner { id, generation });
    }

    let mut source_digests = BTreeMap::new();
    for source in &annotations.source_objects {
        let index = (
            source.bucket_name.as_str(),
            source.key.as_str(),
            source.size,
        );
        if source.md5.len() != 16 || source_digests.insert(index, &source.md5).is_some() {
            return Err(Error::Record);
        }
    }
    let mut buckets: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut extents: BTreeMap<String, Extent> = BTreeMap::new();
    let mut objects = Vec::new();
    for winner in winners.into_values() {
        let Some(name) = winner.generation else {
            continue;
        };
        let sealed = load_checked(&mut get, &records, &name)?;
        let plain = open_manifest(kek, &name, &sealed).map_err(|_| Error::Authentication)?;
        let ident: GenerationIdentity =
            serde_json::from_slice(&plain).map_err(|_| Error::Record)?;
        let (bucket_record, g, placement) = if ident.v == 2 {
            let head = GenerationHead::parse(&name, &plain).map_err(|_| Error::Record)?;
            let layout = recovery::record_name(&name).ok_or(Error::Record)?.layout;
            let mut placement = Vec::new();
            for i in 0..head.segments.len() {
                let seg = load_checked(&mut get, &records, &head.segment_key(&layout, i))?;
                placement.extend(
                    head.open_segment(kek, &layout, i, &seg)
                        .map_err(|_| Error::Record)?,
                );
            }
            (head.bucket, head.generation, placement)
        } else {
            let g: GenerationManifest =
                serde_json::from_slice(&plain).map_err(|_| Error::Record)?;
            (g.bucket, g.generation, g.extents)
        };
        if bucket_record.bdk_wrapped.len() != 73 || bucket_record.bdk_wrapped[0] != 1 {
            return Err(Error::Record);
        }
        if kek.version(bucket_record.kek_version).is_none() {
            return Err(Error::Authentication);
        }
        let bucket = Bucket {
            id: bucket_record.id,
            name: bucket_record.name,
            bdk_wrapped: bucket_record.bdk_wrapped,
            kek_version: bucket_record.kek_version,
        };
        if let Some(previous) = buckets.get(&bucket.id) {
            if previous != &bucket {
                return Err(Error::Record);
            }
        } else {
            buckets.insert(bucket.id.clone(), bucket.clone());
        }
        let mut refs = Vec::with_capacity(placement.len());
        let mut offset = 0u64;
        for (seq, e) in placement.into_iter().enumerate() {
            if usize::try_from(e.seq).ok() != Some(seq) || e.plain_offset != offset {
                return Err(Error::Record);
            }
            offset = offset.checked_add(e.plain_size).ok_or(Error::Record)?;
            let id = e.id.clone();
            refs.push(ExtentRef {
                id: id.clone(),
                plain_offset: e.plain_offset,
                plain_size: e.plain_size,
            });
            if let Some(old) = extents.get(&id) {
                let base = extent_base(&bucket.id, e)?;
                if base.bucket_id != old.bucket_id
                    || base.cipher_size != old.cipher_size
                    || base.plain_size != old.plain_size
                    || base.media_header != old.media_header
                    || base.wrapped_file_key != old.wrapped_file_key
                    || base.plain_md5 != old.plain_md5
                    || base.plain_sha256 != old.plain_sha256
                    || base.cipher_sha256 != old.cipher_sha256
                {
                    return Err(Error::Record);
                }
            } else {
                let mut extent = extent_base(&bucket.id, e)?;
                let released = annotations.released.as_ref().and_then(|m| m.get(&id));
                if annotations.released.is_none() || released.is_some() {
                    if let Some(names) = plans.get(&id) {
                        let mut candidates = Vec::new();
                        for name in names {
                            let sealed = load_checked(&mut get, &records, name)?;
                            let plain = open_manifest(kek, name, &sealed)
                                .map_err(|_| Error::Authentication)?;
                            let plan: ArticleManifest =
                                serde_json::from_slice(&plain).map_err(|_| Error::Record)?;
                            if plan.v != 1 || plan.extent_id != id || plan.plan_rev == 0 {
                                return Err(Error::Record);
                            }
                            if released.is_none_or(|r| r.plan_rev == plan.plan_rev) {
                                candidates.push(plan);
                            }
                        }
                        candidates.sort_by_key(|plan| plan.plan_rev);
                        if let Some(plan) = candidates.pop() {
                            if candidates
                                .last()
                                .is_some_and(|p| p.plan_rev == plan.plan_rev && p != &plan)
                            {
                                return Err(Error::Record);
                            }
                            stats.parity_omitted += u64::from(attach_plan(&mut extent, plan)?);
                            extent.verified = released.and_then(|r| r.verified.clone());
                        }
                    }
                }
                extents.insert(id, extent);
            }
        }
        if offset != g.size || refs.is_empty() {
            return Err(Error::Record);
        }
        let content: BTreeMap<String, String> =
            serde_json::from_str(&g.content_json).map_err(|_| Error::Record)?;
        let source_md5 = annotations
            .source_md5
            .get(&g.id)
            .or_else(|| {
                source_digests
                    .get(&(bucket.name.as_str(), g.key.as_str(), g.size))
                    .copied()
            })
            .map(|d| serde_bytes::ByteBuf::from(d.clone()));
        if source_md5.as_ref().is_some_and(|d| d.len() != 16) {
            return Err(Error::Record);
        }
        objects.push(Entry::Object(Object {
            bucket_id: bucket.id,
            key: g.key,
            generation_id: g.id,
            size: g.size,
            etag: g.etag,
            content_type: content
                .get("content-type")
                .or_else(|| content.get("content_type"))
                .cloned(),
            headers: content,
            checksum: g.checksum_json,
            user_meta: serde_json::from_str(&g.user_meta_json).map_err(|_| Error::Record)?,
            source_md5,
            extents: refs,
        }));
    }
    let entries = buckets
        .into_values()
        .map(Entry::Bucket)
        .chain(objects)
        .chain(extents.into_values().map(Entry::Extent))
        .chain(records.into_iter().map(|(name, sha256)| {
            Entry::RecordRef(RecordRef {
                name,
                sha256: sha256.to_vec(),
            })
        }))
        .collect();
    Ok((entries, stats))
}

fn extent_base(bucket_id: &str, e: ExtentRecord) -> Result<Extent, Error> {
    if !valid_extent(&e.id)
        || e.key_mode != 1
        || e.media_header.len() != 48
        || e.wrapped_file_key.len() != 73
        || e.wrapped_file_key[0] != 1
        || e.plain_md5.len() != 16
        || e.plain_sha256.len() != 32
        || e.cipher_sha256.len() != 32
        || velmora::media::ciphertext_size(e.plain_size) != Some(e.cipher_size)
    {
        return Err(Error::Record);
    }
    Ok(Extent {
        id: e.id,
        bucket_id: bucket_id.to_owned(),
        plain_size: e.plain_size,
        cipher_size: e.cipher_size,
        media_header: e.media_header,
        wrapped_file_key: e.wrapped_file_key,
        plain_md5: e.plain_md5,
        plain_sha256: e.plain_sha256,
        cipher_sha256: e.cipher_sha256,
        plan_rev: None,
        articles: Vec::new(),
        parity: None,
        verified: None,
    })
}

fn attach_plan(e: &mut Extent, plan: ArticleManifest) -> Result<bool, Error> {
    // Check count before expanding spans; a malformed gigantic size cannot
    // drive an allocation based only on the supplied numeric size.
    let subsequent = e
        .cipher_size
        .saturating_sub(velmora::article::ARTICLE_ZERO_PAYLOAD_BYTES);
    let count = 1 + subsequent.div_ceil(velmora::article::ARTICLE_PAYLOAD_BYTES);
    if u64::try_from(plan.articles.len()).ok() != Some(count) {
        return Err(Error::Record);
    }
    let spans = article_spans(e.cipher_size);
    let rows = plan
        .rows(ArticleState::Planned)
        .map_err(|_| Error::Record)?;
    for (i, (row, span)) in rows.iter().zip(spans).enumerate() {
        if usize::try_from(row.idx).ok() != Some(i)
            || row.cipher_offset != span.start
            || row.cipher_len != span.len
            || row.message_id.is_empty()
            || row.newsgroup.is_empty()
        {
            return Err(Error::Record);
        }
    }
    e.parity = plan.parity.as_ref().and_then(|blob| {
        let id = ExtentId::new(e.id.clone());
        let packed = plan::repack(&id, e.cipher_size, &rows, plan.packed.as_deref())?;
        let p = parity::expand(&id, e.cipher_size, &packed, blob).ok()?;
        Some(Parity {
            k: u16::try_from(count).ok()?,
            shard_len: p.shard_len,
            rows: p
                .rows
                .into_iter()
                .zip(p.articles)
                .map(|(row, a)| ParityRow {
                    row,
                    message_id: a.message_id,
                    newsgroup: a.newsgroup,
                    payload_sha256: a.payload_sha256.to_vec(),
                })
                .collect(),
        })
    });
    e.articles = rows
        .into_iter()
        .map(|row| Article {
            message_id: row.message_id,
            newsgroup: row.newsgroup,
            payload_sha256: row.payload_sha256.to_vec(),
            yenc_name: row.yenc_name,
        })
        .collect();
    e.plan_rev = Some(plan.plan_rev);
    Ok(plan.parity.is_some() && e.parity.is_none())
}
