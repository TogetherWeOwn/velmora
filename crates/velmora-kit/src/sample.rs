use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use velmora_bridge::{
    crypto::open_manifest,
    ports::Kek,
    recovery::{record_name, GenerationHead, RecordKind, Tombstone},
};
use velmora_kit::{Entry, Error, Object};

/// Select from an already authenticated full index. The caller supplies
/// independent historical samples; this does not assert current release.
pub fn choose<'a>(
    entries: &'a [Entry],
    candidates: &[String],
    seed: &str,
) -> Result<Vec<&'a Object>, Error> {
    let candidate: BTreeSet<_> = candidates.iter().map(String::as_str).collect();
    let plans: BTreeSet<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Extent(e) if e.plan_rev.is_some() && !e.articles.is_empty() => {
                Some(e.id.as_str())
            }
            _ => None,
        })
        .collect();
    let mut bins = [vec![], vec![], vec![]];
    for entry in entries {
        let Entry::Object(o) = entry else { continue };
        if !candidate.contains(o.generation_id.as_str())
            || o.source_md5.as_ref().is_none_or(|d| d.len() != 16)
            || o.extents.is_empty()
            || !o.extents.iter().all(|r| plans.contains(r.id.as_str()))
        {
            continue;
        }
        let bin = match o.size {
            1..=1_048_575 => 0,
            1_048_576..=1_073_741_823 => 1,
            size if size > 1_073_741_824 && o.extents.len() > 1 => 2,
            _ => continue,
        };
        bins[bin].push(o);
    }
    let mut chosen = Vec::new();
    for (i, (mut bin, count)) in bins.into_iter().zip([10, 9, 1]).enumerate() {
        if bin.len() < count {
            return Err(Error::Coverage);
        }
        bin.sort_by_key(|o| {
            let mut h = Sha256::new();
            h.update(seed.as_bytes());
            h.update(o.generation_id.as_bytes());
            // Use the smallest qualifying multipart object to bound the
            // drill's download while still testing the required size bin.
            (
                if i == 2 { o.size } else { 0 },
                <[u8; 32]>::from(h.finalize()),
            )
        });
        chosen.extend(bin.into_iter().take(count));
    }
    Ok(chosen)
}

#[derive(serde::Deserialize)]
struct GenerationIdentity {
    v: u32,
    generation: velmora_bridge::recovery::GenerationRecord,
    bucket: velmora_bridge::recovery::BucketRecord,
}

pub struct SampleRecords {
    pub names: Vec<String>,
    pub overwritten: usize,
    pub deleted: bool,
}

/// Include selected article plans, historical generations/tombstones for
/// their keys, and one tombstoned key with a prior record when present.
pub fn records(
    entries: &[Entry],
    objects: &[&Object],
    mut get: impl FnMut(&str) -> Result<Option<Vec<u8>>, Error>,
    kek: &impl Kek,
) -> Result<SampleRecords, Error> {
    let refs: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::RecordRef(r) => Some((r.name.as_str(), r.sha256.as_slice())),
            _ => None,
        })
        .collect();
    let selected: BTreeMap<_, _> = objects
        .iter()
        .map(|o| {
            (
                (o.bucket_id.as_str(), o.key.as_str()),
                o.generation_id.as_str(),
            )
        })
        .collect();
    let live: BTreeSet<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Object(o) => Some((o.bucket_id.as_str(), o.key.as_str())),
            _ => None,
        })
        .collect();
    let extents: BTreeSet<_> = objects
        .iter()
        .flat_map(|o| &o.extents)
        .map(|r| r.id.as_str())
        .collect();
    let mut names = BTreeSet::new();
    let mut tombs: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
    let mut overwritten = BTreeSet::new();
    let mut deleted = false;
    let mut open = |name: &str| {
        let blob = get(name)?.ok_or(Error::Record)?;
        if refs.get(name).copied() != Some(Sha256::digest(&blob).as_slice()) {
            return Err(Error::Record);
        }
        open_manifest(kek, name, &blob).map_err(|_| Error::Authentication)
    };
    for &name in refs.keys() {
        let Some(r) = record_name(name) else { continue };
        match r.kind {
            RecordKind::ArticlePlan if extents.contains(r.id) => {
                names.insert(name.to_owned());
            }
            RecordKind::Tombstone => {
                let t: Tombstone =
                    serde_json::from_slice(&open(name)?).map_err(|_| Error::Record)?;
                if selected.contains_key(&(t.bucket_id.as_str(), t.key.as_str())) {
                    names.insert(name.to_owned());
                } else if !live.contains(&(t.bucket_id.as_str(), t.key.as_str())) {
                    let key = (t.bucket_id, t.key);
                    if tombs.get(&key).is_none_or(|(id, _)| id < &t.id) {
                        tombs.insert(key, (t.id, name.to_owned()));
                    }
                }
            }
            _ => {}
        }
    }
    for &name in refs.keys() {
        let Some(r) = record_name(name).filter(|r| r.kind == RecordKind::Generation) else {
            continue;
        };
        let plain = open(name)?;
        let g: GenerationIdentity = serde_json::from_slice(&plain).map_err(|_| Error::Record)?;
        let key = (g.bucket.id.as_str(), g.generation.key.as_str());
        let keep = if let Some(id) = selected.get(&key) {
            if *id != g.generation.id {
                overwritten.insert(*id);
            }
            true
        } else if !deleted {
            let key = (g.bucket.id, g.generation.key);
            if let Some((id, tomb)) = tombs.get(&key).filter(|(id, _)| id > &g.generation.id) {
                let _ = id;
                names.insert(tomb.clone());
                deleted = true;
                true
            } else {
                false
            }
        } else {
            false
        };
        if keep {
            names.insert(name.to_owned());
            if g.v == 2 {
                let h = GenerationHead::parse(name, &plain).map_err(|_| Error::Record)?;
                for i in 0..h.segments.len() {
                    names.insert(h.segment_key(&r.layout, i));
                }
            }
        }
    }
    Ok(SampleRecords {
        names: names.into_iter().collect(),
        overwritten: overwritten.len(),
        deleted,
    })
}

/// Translate independent evidence identities to generation IDs using a
/// bucket/key/size join plus an equal source MD5 in the authenticated index.
pub fn match_candidates(entries: &[Entry], evidence: &[Evidence]) -> Vec<String> {
    let names: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Bucket(b) => Some((b.id.as_str(), b.name.as_str())),
            _ => None,
        })
        .collect();
    let want: BTreeSet<_> = evidence
        .iter()
        .map(|e| {
            (
                (e.bucket_name.as_str(), e.key.as_str(), e.size),
                e.md5.as_slice(),
            )
        })
        .collect();
    entries
        .iter()
        .filter_map(|e| {
            let Entry::Object(o) = e else { return None };
            let name = names.get(o.bucket_id.as_str())?;
            let md5 = o.source_md5.as_ref()?;
            want.contains(&((*name, o.key.as_str(), o.size), md5.as_slice()))
                .then(|| o.generation_id.clone())
        })
        .collect()
}

#[derive(serde::Deserialize)]
pub struct Evidence {
    bucket_name: String,
    key: String,
    size: u64,
    md5: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora_kit::{Article, Extent, ExtentRef};

    #[test]
    fn drill_sample_needs_independent_evidence_and_complete_plans_for_each_bin() {
        let mut entries = vec![Entry::Extent(Extent {
            id: "extent".into(),
            bucket_id: "bucket".into(),
            plain_size: 1,
            cipher_size: 65,
            media_header: vec![0; 48],
            wrapped_file_key: vec![0; 73],
            plain_md5: vec![0; 16],
            plain_sha256: vec![0; 32],
            cipher_sha256: vec![0; 32],
            plan_rev: Some(1),
            articles: vec![Article {
                message_id: "message".into(),
                newsgroup: "alt.binaries.test".into(),
                payload_sha256: vec![0; 32],
                yenc_name: None,
            }],
            parity: None,
            verified: None,
        })];
        let mut evidence = vec![];
        for (size, count) in [(1, 10), (1 << 20, 9), ((1 << 30) + 1, 1)] {
            for i in 0..count {
                let id = format!("{size}_{i}");
                evidence.push(id.clone());
                entries.push(Entry::Object(Object {
                    bucket_id: "bucket".into(),
                    generation_id: id,
                    key: "key".into(),
                    size,
                    etag: "etag".into(),
                    content_type: None,
                    user_meta: BTreeMap::new(),
                    source_md5: Some(serde_bytes::ByteBuf::from(vec![0; 16])),
                    extents: vec![
                        ExtentRef {
                            id: "extent".into(),
                            plain_offset: 0,
                            plain_size: 1
                        };
                        if size > (1 << 30) { 2 } else { 1 }
                    ],
                }));
            }
        }
        assert_eq!(choose(&entries, &evidence, "seed").unwrap().len(), 20);
        assert!(choose(&entries, &evidence[1..], "seed").is_err());
        let Entry::Extent(e) = &mut entries[0] else {
            unreachable!()
        };
        e.plan_rev = None;
        assert!(choose(&entries, &evidence, "seed").is_err());
    }
}
