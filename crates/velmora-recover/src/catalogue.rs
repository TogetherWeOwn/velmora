//! The restore view of an authenticated index. Ciphertext pack selection
//! and decoding stay in the kit reader, not in the restore path.

use crate::{
    extent::{open_extent, BodySource, Extent, ExtentError},
    resume::{ExtentCheck, ObjectCheck, OutputRoot},
};
use std::collections::{BTreeMap, BTreeSet};
use velmora_bridge::{
    crypto::{self, DataKey},
    ports::Kek,
    types::{BucketId, ExtentId},
};

pub struct Bucket {
    pub id: BucketId,
    pub name: String,
    pub wrapped: [u8; 73],
    pub kek_version: u32,
}

pub struct Object {
    pub bucket_id: BucketId,
    pub key: String,
    pub generation: String,
    pub size: u64,
    pub md5: Option<[u8; 16]>,
    pub extents: Vec<Reference>,
}

pub struct Reference {
    pub id: ExtentId,
    pub offset: u64,
    pub len: u64,
}

pub trait CatalogueReader {
    fn read(&self, kek: &impl Kek) -> Result<Catalogue, &'static str>;
}

pub struct Catalogue {
    buckets: BTreeMap<BucketId, Bucket>,
    objects: Vec<Object>,
    extents: BTreeMap<ExtentId, Extent>,
}

pub struct Selection<'a> {
    pub bucket: &'a Bucket,
    pub object: &'a Object,
}

#[derive(serde::Serialize)]
pub struct ObjectResult {
    pub md5: String,
    pub md5_status: &'static str,
    pub unmapped: bool,
    pub extents: usize,
}

impl Catalogue {
    pub fn new(
        buckets: Vec<Bucket>,
        mut objects: Vec<Object>,
        extents: Vec<Extent>,
    ) -> Result<Self, &'static str> {
        let duplicate = "duplicate bucket, object, generation or extent in index";
        let mut bucket_map = BTreeMap::new();
        let mut names = BTreeSet::new();
        for bucket in buckets {
            if bucket.name.len() > 255
                || !names.insert(bucket.name.clone())
                || bucket_map.insert(bucket.id.clone(), bucket).is_some()
            {
                return Err(duplicate);
            }
        }
        let mut extent_map = BTreeMap::new();
        for extent in extents {
            match extent.validate() {
                Ok(()) | Err(ExtentError::NotPosted) => (),
                Err(_) => return Err("invalid extent in index"),
            };
            if !bucket_map.contains_key(&extent.bucket) {
                return Err("extent bucket is missing");
            }
            if extent_map.insert(extent.id.clone(), extent).is_some() {
                return Err(duplicate);
            }
        }
        let mut generations = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for object in &objects {
            if object.key.len() > 1024 || !bucket_map.contains_key(&object.bucket_id) {
                return Err("invalid object in index");
            }
            if !generations.insert(&object.generation)
                || !keys.insert((&object.bucket_id, &object.key))
            {
                return Err(duplicate);
            }
            let mut offset = 0u64;
            for reference in &object.extents {
                let extent = extent_map
                    .get(&reference.id)
                    .ok_or("object extent missing from index")?;
                if object.bucket_id != extent.bucket
                    || reference.offset != offset
                    || reference.len != extent.plain_size
                {
                    return Err("invalid object extent placement");
                }
                offset = offset
                    .checked_add(reference.len)
                    .ok_or("object extent placement overflow")?;
            }
            if offset != object.size {
                return Err("object extents do not cover object size");
            }
        }
        objects.sort_unstable_by(|a, b| {
            (&bucket_map[&a.bucket_id].name, &a.key).cmp(&(&bucket_map[&b.bucket_id].name, &b.key))
        });
        Ok(Self {
            buckets: bucket_map,
            objects,
            extents: extent_map,
        })
    }

    pub fn select(
        &self,
        bucket: Option<&str>,
        key: Option<&str>,
        prefix: Option<&str>,
    ) -> Vec<Selection<'_>> {
        self.objects
            .iter()
            .filter_map(|object| {
                let b = &self.buckets[&object.bucket_id];
                (bucket.is_none_or(|n| b.name == n)
                    && key.is_none_or(|k| object.key == k)
                    && prefix.is_none_or(|p| object.key.starts_with(p)))
                .then_some(Selection { bucket: b, object })
            })
            .collect()
    }

    pub fn extent(&self, id: &ExtentId) -> &Extent {
        &self.extents[id]
    }

    pub fn recoverable(&self, object: &Object) -> bool {
        object
            .extents
            .iter()
            .all(|r| !self.extent(&r.id).articles.is_empty())
    }

    fn open_bucket(
        &self,
        kek: &impl Kek,
        selected: &Selection<'_>,
    ) -> Result<DataKey, &'static str> {
        if !self.recoverable(selected.object) {
            return Err("object is not recoverable: extent has no usable Usenet plan");
        }
        let b = selected.bucket;
        crypto::unwrap_bdk(kek, b.kek_version, &b.id, &b.wrapped)
            .map_err(|_| "bucket data key authentication failed")
    }

    pub async fn restore(
        &self,
        selected: &Selection<'_>,
        kek: &impl Kek,
        source: &mut impl BodySource,
        output: &mut OutputRoot,
    ) -> Result<ObjectResult, Box<dyn std::error::Error>> {
        let bdk = self.open_bucket(kek, selected)?;
        let object = selected.object;
        let checks: Vec<_> = object
            .extents
            .iter()
            .map(|r| ExtentCheck {
                id: r.id.as_str().to_owned(),
                offset: r.offset,
                len: r.len,
                sha256: self.extent(&r.id).plain_sha256,
            })
            .collect();
        let mut out = output.object(ObjectCheck {
            bucket: &selected.bucket.name,
            key: &object.key,
            generation: &object.generation,
            size: object.size,
            md5: object.md5,
            extents: &checks,
        })?;
        for (ordinal, reference) in object.extents.iter().enumerate() {
            if !out.verified(ordinal)? {
                let plaintext = open_extent(source, &bdk, self.extent(&reference.id)).await?;
                out.write_verified(ordinal, plaintext.as_slice())?;
            }
        }
        let unmapped = out.is_unmapped();
        Ok(result(object, out.finish()?, unmapped))
    }

    pub async fn check(
        &self,
        selected: &Selection<'_>,
        kek: &impl Kek,
        source: &mut impl BodySource,
    ) -> Result<ObjectResult, Box<dyn std::error::Error>> {
        let bdk = self.open_bucket(kek, selected)?;
        let object = selected.object;
        let mut hash = md5::Context::new();
        for reference in &object.extents {
            let plaintext = open_extent(source, &bdk, self.extent(&reference.id)).await?;
            hash.consume(plaintext.as_slice());
        }
        let md5 = hash.finalize().0;
        if object.md5.is_some_and(|expected| expected != md5) {
            return Err("whole-object MD5 mismatch".into());
        }
        Ok(result(object, md5, false))
    }
}

fn result(object: &Object, md5: [u8; 16], unmapped: bool) -> ObjectResult {
    ObjectResult {
        md5: hex(&md5),
        md5_status: if object.md5.is_some() {
            "verified"
        } else {
            "computed"
        },
        unmapped,
        extents: object.extents.len(),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            write!(out, "{b:02x}").expect("String is writable");
            out
        })
}

pub fn decode_hex<const N: usize>(input: &[u8]) -> Option<[u8; N]> {
    if input.len() != 2 * N {
        return None;
    }
    let value = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let mut out = [0; N];
    for (dst, input) in out.iter_mut().zip(input.as_chunks::<2>().0) {
        *dst = value(input[0])? << 4 | value(input[1])?;
    }
    Some(out)
}

pub fn expected_md5(
    source: Option<[u8; 16]>,
    etag: &str,
) -> Result<Option<[u8; 16]>, &'static str> {
    if source.is_some() {
        return Ok(source);
    }
    let etag = etag
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(etag);
    if let Some(digest) = decode_hex(etag.as_bytes()) {
        return Ok(Some(digest));
    }
    if let Some((digest, count)) = etag.split_once('-') {
        if decode_hex::<16>(digest.as_bytes()).is_some()
            && count.bytes().all(|b| b.is_ascii_digit())
            && count.parse::<u64>().is_ok_and(|n| n > 0)
        {
            return Ok(None);
        }
    }
    Err("authenticated index has invalid object ETag")
}
