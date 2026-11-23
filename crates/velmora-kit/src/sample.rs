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
            1_048_576..=1_073_741_824 => 1,
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
fn match_candidates(entries: &[Entry], evidence: &[Evidence]) -> BTreeMap<String, i64> {
    let names: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Bucket(b) => Some((b.id.as_str(), b.name.as_str())),
            _ => None,
        })
        .collect();
    let mut want = BTreeMap::new();
    for e in evidence.iter().filter(|e| {
        e.md5.len() == 16
            && e.evidence_at > 0
            && match e.source {
                EvidenceSource::Run48Released => (1..=1_073_741_824).contains(&e.size),
                EvidenceSource::FullVerify => e.size > 1_073_741_824,
            }
    }) {
        let identity = (
            (e.bucket_name.as_str(), e.key.as_str(), e.size),
            e.md5.as_slice(),
        );
        let cutoff = want.entry(identity).or_insert(e.evidence_at);
        *cutoff = (*cutoff).max(e.evidence_at);
    }
    entries
        .iter()
        .filter_map(|e| {
            let Entry::Object(o) = e else { return None };
            let name = names.get(o.bucket_id.as_str())?;
            let md5 = o.source_md5.as_ref()?;
            want.get(&((*name, o.key.as_str(), o.size), md5.as_slice()))
                .map(|&at| (o.generation_id.clone(), at))
        })
        .collect()
}

#[derive(serde::Deserialize)]
pub struct Evidence {
    bucket_name: String,
    key: String,
    size: u64,
    md5: Vec<u8>,
    source: EvidenceSource,
    evidence_at: i64,
}

#[derive(serde::Deserialize)]
pub struct EvidenceFile {
    objects: Vec<Evidence>,
    /// Upper bound on original recording time, from the same e2 listing
    /// whose byte-exact sealed records were authenticated into the index.
    article_recorded_at: BTreeMap<String, i64>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceSource {
    Run48Released,
    FullVerify,
}

#[derive(Default)]
struct RecordedTimes {
    generations: BTreeMap<String, i64>,
    plans: BTreeMap<(String, u32), Option<i64>>,
}

impl RecordedTimes {
    fn permits(&self, object: &Object, evidence_at: i64, revisions: &BTreeMap<&str, u32>) -> bool {
        self.generations
            .get(&object.generation_id)
            .is_some_and(|&at| at >= 0 && at <= evidence_at)
            && object.extents.iter().all(|r| {
                let Some(rev) = revisions.get(r.id.as_str()) else {
                    return false;
                };
                self.plans
                    .get(&(r.id.clone(), *rev))
                    .copied()
                    .flatten()
                    .is_some_and(|at| at > 0 && at <= evidence_at)
            })
    }
}

pub fn temporal_candidates(
    entries: &[Entry],
    evidence: &EvidenceFile,
    mut get: impl FnMut(&str) -> Result<Option<Vec<u8>>, Error>,
    kek: &impl Kek,
) -> Result<Vec<String>, Error> {
    let joined = match_candidates(entries, &evidence.objects);
    let objects: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Object(o) if joined.contains_key(&o.generation_id) => {
                Some((o.generation_id.as_str(), o))
            }
            _ => None,
        })
        .collect();
    let requested: BTreeSet<_> = objects
        .values()
        .flat_map(|o| &o.extents)
        .map(|r| r.id.as_str())
        .collect();
    let extents: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Extent(e) if e.plan_rev.is_some() && requested.contains(e.id.as_str()) => {
                Some((e.id.as_str(), e))
            }
            _ => None,
        })
        .collect();
    let revisions = extents
        .iter()
        .filter_map(|(&id, e)| e.plan_rev.map(|rev| (id, rev)))
        .collect();
    let mut times = RecordedTimes::default();
    for entry in entries {
        let Entry::RecordRef(reference) = entry else {
            continue;
        };
        let Some(r) = record_name(&reference.name) else {
            continue;
        };
        match r.kind {
            RecordKind::Generation if objects.contains_key(r.id) => {}
            RecordKind::ArticlePlan if extents.contains_key(r.id) => {}
            _ => continue,
        }
        let sealed = get(&reference.name)?.ok_or(Error::Record)?;
        if Sha256::digest(&sealed).as_slice() != reference.sha256 {
            return Err(Error::Coverage);
        }
        let plain =
            open_manifest(kek, &reference.name, &sealed).map_err(|_| Error::Authentication)?;
        match r.kind {
            RecordKind::Generation => {
                let g: GenerationIdentity =
                    serde_json::from_slice(&plain).map_err(|_| Error::Record)?;
                let o = objects[r.id];
                if g.generation.id != o.generation_id
                    || g.bucket.id != o.bucket_id
                    || g.generation.key != o.key
                {
                    return Err(Error::Record);
                }
                let at = times
                    .generations
                    .entry(g.generation.id)
                    .or_insert(g.generation.created_at);
                *at = (*at).max(g.generation.created_at);
            }
            RecordKind::ArticlePlan => {
                let p: velmora_bridge::recovery::ArticleManifest =
                    serde_json::from_slice(&plain).map_err(|_| Error::Record)?;
                let e = extents[r.id];
                if p.extent_id != e.id {
                    return Err(Error::Record);
                }
                if Some(p.plan_rev) != e.plan_rev {
                    continue;
                }
                if p.articles.len() != e.articles.len()
                    || !p.articles.iter().zip(&e.articles).all(|(a, b)| {
                        a.message_id == b.message_id
                            && a.newsgroup == b.newsgroup
                            && a.payload_sha256 == b.payload_sha256
                            && a.yenc_name == b.yenc_name
                    })
                {
                    return Err(Error::Coverage);
                }
                let observed = evidence.article_recorded_at.get(&reference.name).copied();
                times
                    .plans
                    .entry((p.extent_id, p.plan_rev))
                    .and_modify(|at| {
                        // Multiple layouts can contain the same plan. Use the
                        // latest observed copy time; an unknown never votes yes.
                        *at = (*at).zip(observed).map(|(a, b)| a.max(b));
                    })
                    .or_insert(observed);
            }
            RecordKind::Tombstone => unreachable!(),
        }
    }
    Ok(objects
        .into_values()
        .filter(|o| times.permits(o, joined[&o.generation_id], &revisions))
        .map(|o| o.generation_id.clone())
        .collect())
}

/// A sample is a projection of an authenticated full index, never a new
/// interpretation of the raw packs (which may have other plan revisions).
pub struct Projection {
    buckets: BTreeSet<String>,
    generations: BTreeSet<String>,
    extents: BTreeSet<String>,
    records: BTreeSet<String>,
}

impl Projection {
    pub fn new(objects: &[&Object], records: &[String]) -> Self {
        Self {
            buckets: objects.iter().map(|o| o.bucket_id.clone()).collect(),
            generations: objects.iter().map(|o| o.generation_id.clone()).collect(),
            extents: objects
                .iter()
                .flat_map(|o| &o.extents)
                .map(|e| e.id.clone())
                .collect(),
            records: records.iter().cloned().collect(),
        }
    }

    pub fn apply(mut self, entries: Vec<Entry>) -> Result<Vec<Entry>, Error> {
        let mut result = Vec::new();
        for entry in entries {
            let keep = match &entry {
                Entry::Bucket(b) => self.buckets.remove(&b.id),
                Entry::Object(o) => self.generations.remove(&o.generation_id),
                Entry::Extent(e) => self.extents.remove(&e.id),
                Entry::RecordRef(r) => self.records.remove(&r.name),
            };
            if keep {
                result.push(entry);
            }
        }
        if !self.buckets.is_empty()
            || !self.generations.is_empty()
            || !self.extents.is_empty()
            || !self.records.is_empty()
        {
            return Err(Error::Coverage);
        }
        Ok(result)
    }
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
        for (size, count) in [(1, 10), (1 << 30, 9), ((1 << 30) + 1, 1)] {
            for i in 0..count {
                let id = format!("{size}_{i}");
                evidence.push(Evidence {
                    bucket_name: "name".into(),
                    key: id.clone(),
                    size,
                    md5: vec![0; 16],
                    evidence_at: 100,
                    source: if size > (1 << 30) {
                        EvidenceSource::FullVerify
                    } else {
                        EvidenceSource::Run48Released
                    },
                });
                entries.push(Entry::Object(Object {
                    bucket_id: "bucket".into(),
                    generation_id: id.clone(),
                    key: id,
                    size,
                    etag: "etag".into(),
                    content_type: None,
                    headers: BTreeMap::new(),
                    checksum: None,
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
        entries.push(Entry::Bucket(velmora_kit::Bucket {
            id: "bucket".into(),
            name: "name".into(),
            bdk_wrapped: vec![0; 73],
            kek_version: 1,
        }));
        for name in ["m/art/extent", "m/x/t_1/art/extent"] {
            entries.push(Entry::RecordRef(velmora_kit::RecordRef {
                name: name.into(),
                sha256: vec![0; 32],
            }));
        }
        let matched: Vec<_> = match_candidates(&entries, &evidence).into_keys().collect();
        let objects = choose(&entries, &matched, "seed").unwrap();
        assert_eq!(objects.len(), 20);
        assert_eq!(objects.iter().filter(|o| o.size == 1 << 30).count(), 9);
        let projection = Projection::new(
            &objects,
            &["m/art/extent".into(), "m/x/t_1/art/extent".into()],
        );
        let projected = projection.apply(entries.clone()).unwrap();
        // Both archived record names remain, but the sample's extent is an
        // exact copy of the full index plan, not re-selected from the pack.
        assert_eq!(projected[0], entries[0]);
        assert!(projected
            .iter()
            .any(|e| matches!(e, Entry::Extent(e) if e.plan_rev == Some(1))));
        assert_eq!(
            projected
                .iter()
                .filter(|e| matches!(e, Entry::RecordRef(_)))
                .count(),
            2
        );
        let eligible = |evidence: &[Evidence]| {
            let candidates: Vec<_> = match_candidates(&entries, evidence).into_keys().collect();
            choose(&entries, &candidates, "seed").is_ok()
        };
        assert!(!eligible(&evidence[1..]));
        assert!(!eligible(&[]));
        evidence.last_mut().unwrap().source = EvidenceSource::Run48Released;
        assert!(!eligible(&evidence));
        let Entry::Extent(e) = &mut entries[0] else {
            unreachable!()
        };
        e.plan_rev = None;
        assert!(choose(&entries, &matched, "seed").is_err());
    }

    #[test]
    fn evidence_file_requires_a_recognized_source() {
        for json in [
            r#"{"bucket_name":"b","key":"k","size":1,"md5":[]}"#,
            r#"{"bucket_name":"b","key":"k","size":1,"md5":[],"source":"article-plan","evidence_at":100}"#,
            r#"{"bucket_name":"b","key":"k","size":1,"md5":[],"source":"run48-released"}"#,
        ] {
            assert!(serde_json::from_str::<Evidence>(json).is_err());
        }
        assert!(serde_json::from_str::<Evidence>(
            r#"{"bucket_name":"b","key":"k","size":1,"md5":[],"source":"run48-released","evidence_at":100}"#
        )
        .is_ok());
    }

    fn timeline_case(created_at: i64, plan_rev: u32, recorded: Option<i64>) -> Vec<String> {
        use velmora::rng::SystemRng;
        use velmora_bridge::{crypto::seal_manifest, recovery, types::KekBytes};
        struct Key(KekBytes);
        impl Kek for Key {
            fn active(&self) -> (u32, &KekBytes) {
                (1, &self.0)
            }
            fn version(&self, v: u32) -> Option<&KekBytes> {
                (v == 1).then_some(&self.0)
            }
        }
        let key = Key(KekBytes::new([3; 32]));
        let gid = "g_00000000000000000000000000042";
        let gen = recovery::GenerationManifest {
            v: 1,
            bucket: recovery::BucketRecord {
                id: "b_test".into(),
                name: "bucket".into(),
                owner: "owner".into(),
                bdk_wrapped: vec![1; 73],
                kek_version: 1,
                disposable: false,
                created_at: 1,
            },
            generation: recovery::GenerationRecord {
                id: gid.into(),
                key: "same-bytes".into(),
                size: 1,
                etag: "unchanged-digest".into(),
                content_json: "{}".into(),
                user_meta_json: "{}".into(),
                checksum_json: None,
                created_at,
            },
            extents: vec![recovery::ExtentRecord {
                id: "x_test".into(),
                seq: 0,
                plain_offset: 0,
                plain_size: 1,
                cipher_size: 65,
                media_header: vec![0; 48],
                key_mode: 1,
                wrapped_file_key: vec![1; 73],
                plain_md5: vec![0; 16],
                plain_sha256: vec![0; 32],
                cipher_sha256: vec![0; 32],
                created_at: 1,
            }],
        };
        let article = |rev| recovery::ArticleManifest {
            v: 1,
            extent_id: "x_test".into(),
            plan_rev: rev,
            articles: vec![recovery::ArticleRecord {
                idx: 0,
                message_id: format!("article-{rev}"),
                newsgroup: "alt.binaries.test".into(),
                headers: vec![],
                cipher_offset: 0,
                cipher_len: 65,
                payload_sha256: vec![0; 32],
                yenc_name: None,
            }],
            packed: None,
            parity: None,
        };
        let new_plan = "m/x/t_1/art/x_test";
        let mut records = BTreeMap::new();
        for (name, body) in [
            (format!("m/{gid}"), serde_json::to_vec(&gen).unwrap()),
            (
                "m/art/x_test".into(),
                serde_json::to_vec(&article(1)).unwrap(),
            ),
            (
                new_plan.into(),
                serde_json::to_vec(&article(plan_rev)).unwrap(),
            ),
        ] {
            let sealed = seal_manifest(&key, &name, &body, &mut SystemRng).unwrap();
            records.insert(name, sealed);
        }
        let mut ann = velmora_kit::BuildAnnotations::default();
        ann.source_md5.insert(gid.into(), vec![0; 16]);
        let entries = velmora_kit::build_entries(
            records.keys().cloned(),
            |n| Ok(records.get(n).cloned()),
            &key,
            &ann,
        )
        .unwrap();
        let mut evidence = EvidenceFile {
            objects: vec![Evidence {
                bucket_name: "bucket".into(),
                key: "same-bytes".into(),
                size: 1,
                md5: vec![0; 16],
                source: EvidenceSource::Run48Released,
                evidence_at: 100,
            }],
            article_recorded_at: BTreeMap::from([("m/art/x_test".into(), 80)]),
        };
        if let Some(at) = recorded {
            evidence.article_recorded_at.insert(new_plan.into(), at);
        }
        temporal_candidates(&entries, &evidence, |n| Ok(records.get(n).cloned()), &key).unwrap()
    }

    #[test]
    fn identical_bytes_overwritten_after_evidence_do_not_match() {
        assert_eq!(timeline_case(100, 1, Some(90)).len(), 1);
        assert!(timeline_case(101, 1, Some(90)).is_empty());
    }

    #[test]
    fn sample_never_falls_back_to_old_revision_to_pass_time_check() {
        assert_eq!(timeline_case(90, 2, Some(100)).len(), 1);
        assert!(timeline_case(90, 2, Some(101)).is_empty());
        assert!(timeline_case(90, 2, None).is_empty());
    }
}
