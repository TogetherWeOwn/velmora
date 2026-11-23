use std::collections::BTreeMap;
use velmora::rng::SystemRng;
use velmora_bridge::{crypto::seal_manifest, ports::Kek, recovery, types::KekBytes};
use velmora_kit::{build_entries, cross_check, eligible_record, BuildAnnotations, Entry};

struct Key(KekBytes);
impl Kek for Key {
    fn active(&self) -> (u32, &KekBytes) {
        (1, &self.0)
    }
    fn version(&self, v: u32) -> Option<&KekBytes> {
        (v == 1).then_some(&self.0)
    }
}

fn generation(id: &str, key: &str) -> recovery::GenerationManifest {
    let extent = recovery::ExtentRecord {
        id: "x_1".into(),
        seq: 0,
        plain_offset: 0,
        plain_size: 1,
        cipher_size: 65,
        key_mode: 1,
        media_header: vec![0; 48],
        wrapped_file_key: vec![1; 73],
        plain_md5: vec![0; 16],
        plain_sha256: vec![0; 32],
        cipher_sha256: vec![0; 32],
        created_at: 1,
    };
    recovery::GenerationManifest {
        v: 1,
        bucket: recovery::BucketRecord {
            id: "b_1".into(),
            name: "bucket".into(),
            owner: "owner".into(),
            bdk_wrapped: vec![1; 73],
            kek_version: 1,
            disposable: false,
            created_at: 1,
        },
        generation: recovery::GenerationRecord {
            id: id.into(),
            key: key.into(),
            size: 1,
            etag: "etag".into(),
            checksum_json: None,
            content_json: r#"{"content-type":"application/octet-stream"}"#.into(),
            user_meta_json: "{}".into(),
            created_at: 1,
        },
        extents: vec![extent],
    }
}

#[test]
fn replay_across_layouts_with_tombstone_and_explicit_missing_plan() {
    let key = Key(KekBytes::new([1; 32]));
    let mut records = BTreeMap::new();
    let g0 = "g_00000000000000000000000000000";
    let g1 = "g_00000000000010000000000000000";
    let g2 = "g_00000000000020000000000000000";
    let g3 = "g_00000000000030000000000000000";
    for (layout, id, name) in [
        ("m/", g0, "overwritten"),
        ("m/x/t_1/", g1, "deleted"),
        ("m/x/t_1/", g2, "overwritten"),
    ] {
        let record = format!("{layout}{id}");
        let plain = serde_json::to_vec(&generation(id, name)).unwrap();
        records.insert(
            record.clone(),
            seal_manifest(&key, &record, &plain, &mut SystemRng).unwrap(),
        );
    }
    let tomb = format!("m/del/{g3}");
    let plain = serde_json::to_vec(&recovery::Tombstone {
        v: 1,
        id: g3.into(),
        bucket_id: "b_1".into(),
        key: "deleted".into(),
        deleted_at: 3,
    })
    .unwrap();
    records.insert(
        tomb.clone(),
        seal_manifest(&key, &tomb, &plain, &mut SystemRng).unwrap(),
    );
    let entries = build_entries(
        records.keys().cloned(),
        |name| Ok(records.get(name).cloned()),
        &key,
        &BuildAnnotations::default(),
    )
    .unwrap();
    let objects: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Object(o) => Some(o),
            _ => None,
        })
        .collect();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].generation_id, g2);
    assert!(entries
        .iter()
        .any(|e| matches!(e, Entry::Extent(e) if e.plan_rev.is_none() && e.articles.is_empty())));
    assert_eq!(
        entries
            .iter()
            .filter(|e| matches!(e, Entry::RecordRef(_)))
            .count(),
        4
    );
}

#[test]
fn catches_missing_mirror_record_but_excludes_non_kit_keys() {
    assert!(!eligible_record("m/x/t_1/tk/key"));
    assert!(!eligible_record("rs/stamp/1"));
    assert!(!eligible_record("m/../g_test"));
    let comparison = cross_check(["m/g_1", "m/art/x_1", "m/tk/key"], ["m/g_1", "m/g_extra"]);
    assert_eq!(comparison.safety_count, 2);
    assert_eq!(comparison.e2_count, 2);
    assert_eq!(comparison.missing_count, 1);
    assert_eq!(comparison.missing_examples, ["m/art/x_1"]);
}
