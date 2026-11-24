//! Thin adapter around the kit library's authenticated reader.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::{
    catalogue::{decode_hex, Bucket, Catalogue, CatalogueReader, Object, Reference},
    extent::{Article, Extent, Parity},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use velmora_bridge::{
    ports::Kek,
    types::{BucketId, ExtentId},
};
use velmora_kit::Entry;

const MAX_MANIFEST: u64 = 4 * 1024 * 1024;
const MANIFEST: &str = "manifest.json";
const SHA256_HEX_LEN: usize = 64;
const MAX_MANIFEST_CHECKSUM: u64 = (SHA256_HEX_LEN + 2 + MANIFEST.len() + 1) as u64;
const INVALID: &str = "invalid recovery kit manifest";
const CHANGED: &str = "kit file size or SHA-256 mismatch";
const INDEX: &str = "index.vki";

#[derive(Deserialize)]
struct Manifest {
    format_version: u32,
    kit_id: String,
    files: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    path: String,
    bytes: u64,
    sha256: String,
}

pub struct Kit {
    root: PathBuf,
    id: String,
    files: BTreeMap<String, Item>,
}

impl Kit {
    pub fn open(root: &Path) -> Result<Self, &'static str> {
        if !fs::symlink_metadata(root).map_err(|_| INVALID)?.is_dir() {
            return Err(INVALID);
        }
        let bytes = read_bounded(open(root, MANIFEST)?, MAX_MANIFEST)?;
        let digest = read_bounded(open(root, "manifest.json.sha256")?, MAX_MANIFEST_CHECKSUM)?;
        let expected = manifest_checksum(&digest).ok_or(INVALID)?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != expected {
            return Err("kit manifest SHA-256 mismatch");
        }
        let decoded: Manifest = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
        if decoded.format_version != 1
            || decoded.kit_id.is_empty()
            || decoded.kit_id.len() > 256
            || !decoded
                .kit_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(INVALID);
        }
        let mut files = BTreeMap::new();
        for file in decoded.files {
            if !safe_path(&file.path)
                || decode_hex::<32>(file.sha256.as_bytes()).is_none()
                || files.insert(file.path.clone(), file).is_some()
            {
                return Err(INVALID);
            }
        }
        if !files.contains_key(INDEX) {
            return Err(INVALID);
        }
        Ok(Self {
            root: root.to_owned(),
            id: decoded.kit_id,
            files,
        })
    }

    fn entries(&self, kek: &impl Kek) -> Result<Vec<Entry>, &'static str> {
        let file = self.open_verified(&self.files[INDEX])?;
        velmora_kit::read_index(file, &self.id, kek)
            .map_err(|_| "kit index authentication or format check failed")
    }

    fn open_verified(&self, item: &Item) -> Result<File, &'static str> {
        let mut file = open(&self.root, &item.path)?;
        if file.metadata().map_err(|_| CHANGED)?.len() != item.bytes {
            return Err(CHANGED);
        }
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        let mut bounded = (&mut file).take(item.bytes.saturating_add(1));
        loop {
            let n = bounded.read(&mut buffer).map_err(|_| CHANGED)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
            bytes += n as u64;
        }
        if bytes != item.bytes
            || Some(<[u8; 32]>::from(hash.finalize())) != decode_hex(item.sha256.as_bytes())
        {
            return Err(CHANGED);
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| CHANGED)?;
        Ok(file)
    }

    fn check_records_directory(&self) -> Result<(), &'static str> {
        const UNREADABLE: &str = "kit records directory is not readable";
        let records = self.root.join("records");
        match fs::symlink_metadata(&records) {
            Ok(metadata) if metadata.is_dir() => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            _ => return Err(UNREADABLE),
        }
        for item in fs::read_dir(records).map_err(|_| UNREADABLE)? {
            let name = item.map_err(|_| UNREADABLE)?.file_name();
            let name = name
                .to_str()
                .ok_or("undeclared record pack in kit directory")?;
            let path = format!("records/{name}");
            if !record_pack_path(&path) || !self.files.contains_key(&path) {
                return Err("undeclared record pack in kit directory");
            }
        }
        Ok(())
    }

    pub fn verify(&self, kek: &impl Kek) -> Result<(), &'static str> {
        let entries = self.entries(kek)?;
        self.check_records_directory()?;
        let mut pack_paths = Vec::new();
        for (name, item) in &self.files {
            if name == INDEX {
                continue;
            }
            self.open_verified(item)?;
            if record_pack_path(name) {
                pack_paths.push(name.as_str());
            }
        }
        let packs = pack_paths.into_iter().map(|name| LazyPack {
            root: &self.root,
            name,
            file: None,
        });
        velmora_kit::verify_packs(packs, &entries)
            .map_err(|_| "kit record pack does not match authenticated index")?;
        Ok(())
    }
}

fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID)?;
    if bytes.len() as u64 > limit {
        return Err(INVALID);
    }
    Ok(bytes)
}

fn manifest_checksum(input: &[u8]) -> Option<[u8; 32]> {
    let (hex, suffix) = input.split_at_checked(SHA256_HEX_LEN)?;
    // A legacy bare digest may end in LF or CRLF. A sha256sum line must
    // contain the mode marker, the exact manifest basename, and a final LF.
    if !matches!(suffix, b"" | b"\n" | b"\r\n") {
        let filename = suffix
            .strip_prefix(b"  ")
            .or_else(|| suffix.strip_prefix(b" *"))?
            .strip_suffix(b"\n")?;
        if filename != MANIFEST.as_bytes() {
            return None;
        }
    }
    if hex.iter().any(u8::is_ascii_uppercase) {
        return None;
    }
    decode_hex(hex)
}

fn record_pack_path(path: &str) -> bool {
    path.strip_prefix("records/records-")
        .is_some_and(|name| !name.contains('/') && name.ends_with(".tar.zst"))
}

struct LazyPack<'a> {
    root: &'a Path,
    name: &'a str,
    file: Option<File>,
}
impl Read for LazyPack<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.file.is_none() {
            self.file = Some(open(self.root, self.name).map_err(io::Error::other)?);
        }
        self.file.as_mut().expect("opened above").read(out)
    }
}

impl CatalogueReader for Kit {
    fn read(&self, kek: &impl Kek) -> Result<Catalogue, &'static str> {
        let (mut buckets, mut objects, mut extents) = (Vec::new(), Vec::new(), Vec::new());
        for entry in self.entries(kek)? {
            match entry {
                Entry::Bucket(b) => buckets.push(Bucket {
                    id: BucketId::new(b.id),
                    name: b.name,
                    wrapped: bytes(&b.bdk_wrapped)?,
                    kek_version: b.kek_version,
                }),
                Entry::Object(o) => {
                    objects.push(Object {
                        bucket_id: BucketId::new(o.bucket_id),
                        key: o.key,
                        generation: o.generation_id,
                        size: o.size,
                        etag: o.etag,
                        checksum: o.checksum,
                        source_md5: o.source_md5.map(|md5| md5.into_vec()),
                        extents: o
                            .extents
                            .into_iter()
                            .map(|r| Reference {
                                id: ExtentId::new(r.id),
                                offset: r.plain_offset,
                                len: r.plain_size,
                            })
                            .collect(),
                    });
                }
                Entry::Extent(e) => {
                    if e.plan_rev.is_none() != e.articles.is_empty()
                        || (e.plan_rev.is_none() && e.parity.is_some())
                    {
                        return Err("invalid absent Usenet plan in index");
                    }
                    let articles = e
                        .articles
                        .into_iter()
                        .map(|a| article(a.message_id, a.payload_sha256, a.yenc_name, a.newsgroup))
                        .collect::<Result<_, _>>()?;
                    let parity = if let Some(p) = e.parity {
                        Some(Parity {
                            k: p.k as usize,
                            shard_len: p.shard_len as usize,
                            rows: p
                                .rows
                                .into_iter()
                                .map(|r| {
                                    Ok((
                                        r.row,
                                        article(r.message_id, r.payload_sha256, None, r.newsgroup)?,
                                    ))
                                })
                                .collect::<Result<_, &'static str>>()?,
                        })
                    } else {
                        None
                    };
                    extents.push(Extent {
                        id: ExtentId::new(e.id),
                        bucket: BucketId::new(e.bucket_id),
                        plain_size: e.plain_size,
                        cipher_size: e.cipher_size,
                        media_header: bytes(&e.media_header)?,
                        wrapped_file_key: bytes(&e.wrapped_file_key)?,
                        plain_md5: bytes(&e.plain_md5)?,
                        plain_sha256: bytes(&e.plain_sha256)?,
                        cipher_sha256: bytes(&e.cipher_sha256)?,
                        articles,
                        parity,
                    });
                }
                Entry::RecordRef(_) => (),
            }
        }
        Catalogue::new(buckets, objects, extents)
    }
}

fn bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], &'static str> {
    bytes
        .try_into()
        .map_err(|_| "invalid binary field length in authenticated index")
}

fn article(
    message_id: String,
    sha256: Vec<u8>,
    yenc_name: Option<String>,
    newsgroup: String,
) -> Result<Article, &'static str> {
    if newsgroup.is_empty()
        || newsgroup.len() > 255
        || !newsgroup
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.' | b'_'))
    {
        return Err("invalid newsgroup in authenticated index");
    }
    Ok(Article {
        message_id,
        sha256: bytes(&sha256)?,
        yenc_name,
        newsgroup,
    })
}

fn safe_path(path: &str) -> bool {
    path.len() <= 1024
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 240
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

fn open(root: &Path, name: &str) -> Result<File, &'static str> {
    if !safe_path(name) {
        return Err(INVALID);
    }
    let mut path = root.to_path_buf();
    let mut parts = name.split('/').peekable();
    while let Some(part) = parts.next() {
        path.push(part);
        let m = fs::symlink_metadata(&path).map_err(|_| "kit file is missing or unreadable")?;
        if (parts.peek().is_some() && !m.is_dir()) || (parts.peek().is_none() && !m.is_file()) {
            return Err("kit paths must be regular files and directories, not links");
        }
    }
    File::open(path).map_err(|_| "kit file is missing or unreadable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_manifest_checksum_read_stops_at_the_first_excess_byte() {
        let mut input = io::Cursor::new([b' '; 4096]);
        assert_eq!(
            read_bounded(&mut input, MAX_MANIFEST_CHECKSUM),
            Err(INVALID)
        );
        assert_eq!(input.position(), 81);
    }
}
