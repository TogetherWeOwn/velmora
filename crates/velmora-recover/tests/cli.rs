#![cfg(feature = "recovery-cli")]

use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use velmora::rng::{FillRandom, SystemRng};
use velmora_bridge::{
    crypto,
    ports::Kek,
    types::{BucketId, ExtentId, KekBytes},
};
use velmora_kit as kit;
use velmora_recover::catalogue::hex;

struct TestKey(KekBytes);
impl Kek for TestKey {
    fn active(&self) -> (u32, &KekBytes) {
        (1, &self.0)
    }
    fn version(&self, v: u32) -> Option<&KekBytes> {
        (v == 1).then_some(&self.0)
    }
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

impl Fixture {
    fn new() -> Self {
        let mut suffix = [0; 16];
        SystemRng.fill_bytes(&mut suffix).unwrap();
        let root = std::env::temp_dir().join(format!("velmora-cli-{}", hex(&suffix)));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn fixture(&self) -> Vec<u8> {
        let bucket = BucketId::new("b_test");
        let extent = ExtentId::new("x_test");
        let plaintext = b"recoverable sealed-kit fixture";
        let kek = TestKey(KekBytes::new([19; 32]));
        let bdk = crypto::DataKey::from_bytes([22; 32]);
        let (_, wrapped) = crypto::wrap_bdk(&kek, &bucket, &bdk, &mut SystemRng).unwrap();
        let sealed =
            crypto::seal_extent(&bdk, &bucket, &extent, plaintext, &mut SystemRng).unwrap();
        let entries = vec![
            kit::Entry::Bucket(kit::Bucket {
                id: "b_test".into(),
                name: "example".into(),
                bdk_wrapped: wrapped.to_vec(),
                kek_version: 1,
            }),
            kit::Entry::Object(serde_json::from_value(serde_json::json!({
                "bucket_id": "b_test",
                "key": "nested/example.bin",
                "generation_id": "g_live",
                "size": plaintext.len() as u64,
                "etag": hex(&sealed.plain_md5),
                "content_type": null,
                "headers": {},
                "checksum": null,
                "user_meta": {},
                "extents": [{"id": "x_test", "plain_offset": 0, "plain_size": plaintext.len() as u64}],
            })).unwrap()),
            kit::Entry::Extent(kit::Extent {
                id: "x_test".into(),
                bucket_id: "b_test".into(),
                plain_size: plaintext.len() as u64,
                cipher_size: sealed.ciphertext.len() as u64,
                media_header: sealed.media_header.to_vec(),
                wrapped_file_key: sealed.wrapped_file_key.to_vec(),
                plain_md5: sealed.plain_md5.to_vec(),
                plain_sha256: sealed.plain_sha256.to_vec(),
                cipher_sha256: sealed.cipher_sha256.to_vec(),
                plan_rev: Some(1),
                parity: None,
                verified: None,
                articles: vec![kit::Article {
                    message_id: "sample@example.invalid".into(),
                    newsgroup: "alt.test".into(),
                    payload_sha256: sealed.cipher_sha256.to_vec(),
                    yenc_name: Some("opaque.bin".into()),
                }],
            }),
        ];
        fs::write(self.0.join("key"), [19; 32]).unwrap();
        fs::write(self.0.join("wrong"), [20; 32]).unwrap();
        fs::create_dir(self.0.join("downloads")).unwrap();
        fs::write(self.0.join("downloads/opaque.bin"), sealed.ciphertext).unwrap();
        let mut index = Cursor::new(Vec::new());
        kit::write_index(&mut index, "fixture", &kek, &entries).unwrap();
        let index = index.into_inner();
        self.write_index(&index);
        index
    }

    fn write_index(&self, index: &[u8]) {
        fs::write(self.0.join("index.vki"), index).unwrap();
        let manifest = serde_json::json!({ "format_version": 1, "kit_id": "fixture", "built_at": "2026-01-01T00:00:00Z", "source_counts": {}, "tool_version": "test",
            "files": [{"path": "index.vki", "bytes": index.len(), "sha256": hex(&Sha256::digest(index))}] }).to_string();
        fs::write(self.0.join("manifest.json"), &manifest).unwrap();
        fs::write(
            self.0.join("manifest.json.sha256"),
            hex(&Sha256::digest(manifest)),
        )
        .unwrap();
    }

    fn run(&self, key: &str, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_velmora-recover"))
            .current_dir(&self.0)
            .args(["--kit", ".", "--kek-file", key])
            .args(args)
            .output()
            .unwrap()
    }
}

const DECRYPT: &[&str] = &["decrypt", "--from-dir", "downloads", "--out", "output"];

#[test]
fn standalone_cli_reads_sealed_kit_and_recovers_ciphertext_offline() {
    let kit = Fixture::new();
    kit.fixture();
    let result = kit.run("key", DECRYPT);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(kit.0.join("output/example/nested/example.bin")).unwrap(),
        b"recoverable sealed-kit fixture"
    );
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("\"md5_status\":\"verified\""));
}

fn assert_closed(kit: &Path, result: Output) {
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("kit index authentication or format check failed"));
    assert!(!kit.join("output").exists());
}

#[test]
fn wrong_kek_fails_before_creating_output() {
    let kit = Fixture::new();
    kit.fixture();
    assert_closed(&kit.0, kit.run("wrong", DECRYPT));
}

#[test]
fn changed_and_truncated_authenticated_index_frames_create_no_output() {
    let kit = Fixture::new();
    let mut index = kit.fixture();
    let last = index.len() - 1;
    index[last] ^= 1;
    kit.write_index(&index);
    assert_closed(&kit.0, kit.run("key", DECRYPT));
    index.pop();
    kit.write_index(&index);
    assert_closed(&kit.0, kit.run("key", DECRYPT));
}

#[test]
fn single_restore_does_not_require_packs_but_full_verification_does() {
    let kit = Fixture::new();
    kit.fixture();
    assert!(kit.run("key", &["verify-kit"]).status.success());
    let file = kit.0.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    manifest["files"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "path": "records/records-001.tar.zst", "bytes": 0, "sha256": hex(&Sha256::digest([])),
        }));
    let manifest = manifest.to_string();
    fs::write(file, &manifest).unwrap();
    fs::write(
        kit.0.join("manifest.json.sha256"),
        hex(&Sha256::digest(manifest)),
    )
    .unwrap();
    let verify = kit.run("key", &["verify-kit"]);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("kit file is missing or unreadable"));
    assert!(kit.run("key", DECRYPT).status.success());
}

#[test]
fn verify_kit_rejects_an_undeclared_record_pack() {
    let kit = Fixture::new();
    kit.fixture();
    fs::create_dir(kit.0.join("records")).unwrap();
    fs::write(
        kit.0.join("records/records-999.tar.zst"),
        b"undeclared pack",
    )
    .unwrap();
    let verify = kit.run("key", &["verify-kit"]);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("undeclared record pack"));
    assert!(kit.run("key", DECRYPT).status.success());
}

#[test]
fn decrypt_continues_after_a_whole_object_md5_mismatch() {
    let fixture = Fixture::new();
    let index = fixture.fixture();
    let kek = TestKey(KekBytes::new([19; 32]));
    let mut entries = kit::read_index(Cursor::new(index), "fixture", &kek).unwrap();
    let mut corrupt = entries
        .iter()
        .find_map(|e| match e {
            kit::Entry::Object(o) => Some(o.clone()),
            _ => None,
        })
        .unwrap();
    corrupt.key = "a-bad-md5".into();
    corrupt.generation_id = "g_bad".into();
    corrupt.etag = "00000000000000000000000000000000".into();
    entries.push(kit::Entry::Object(corrupt));
    let mut index = Vec::new();
    kit::write_index(&mut index, "fixture", &kek, &entries).unwrap();
    fixture.write_index(&index);
    let result = fixture.run("key", DECRYPT);
    assert!(!result.status.success());
    assert!(!fixture.0.join("output/example/a-bad-md5").exists());
    assert_eq!(
        fs::read(fixture.0.join("output/example/nested/example.bin")).unwrap(),
        b"recoverable sealed-kit fixture"
    );
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("\"failed\":1,\"recovered\":1"));
}

#[test]
fn keyring_recovers_an_older_bucket_from_a_newer_index() {
    use velmora_bridge::config::KekRing;
    let fixture = Fixture::new();
    let index = fixture.fixture();
    let entries = kit::read_index(
        Cursor::new(index),
        "fixture",
        &TestKey(KekBytes::new([19; 32])),
    )
    .unwrap();
    let ring = KekRing::from_keys(
        2,
        [(1, KekBytes::new([19; 32])), (2, KekBytes::new([20; 32]))].into(),
    )
    .unwrap();
    let mut index = Vec::new();
    kit::write_index(&mut index, "fixture", &ring, &entries).unwrap();
    fixture.write_index(&index);
    fs::write(
        fixture.0.join("ring"),
        format!(
            "export VELMORA_KEK_1='{}ExM='\nVELMORA_KEK_2 = \"{}FBQ=\"\n",
            "ExMT".repeat(10),
            "FBQU".repeat(10)
        ),
    )
    .unwrap();
    let result = fixture.run("ring", DECRYPT);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(fixture.0.join("output/example/nested/example.bin")).unwrap(),
        b"recoverable sealed-kit fixture"
    );
}

#[test]
fn selecting_active_version_one_keeps_a_version_two_bucket_key_available() {
    let fixture = Fixture::new();
    let index = fixture.fixture();
    let v1 = TestKey(KekBytes::new([19; 32]));
    let v2 = velmora_bridge::config::KekRing::from_keys(2, [(2, KekBytes::new([20; 32]))].into())
        .unwrap();
    let mut entries = kit::read_index(Cursor::new(index), "fixture", &v1).unwrap();
    let bucket = entries
        .iter_mut()
        .find_map(|entry| match entry {
            kit::Entry::Bucket(b) => Some(b),
            _ => None,
        })
        .unwrap();
    let id = BucketId::new(&bucket.id);
    let bdk = crypto::unwrap_bdk(&v1, bucket.kek_version, &id, &bucket.bdk_wrapped).unwrap();
    let (version, wrapped) = crypto::wrap_bdk(&v2, &id, &bdk, &mut SystemRng).unwrap();
    bucket.kek_version = version;
    bucket.bdk_wrapped = wrapped.to_vec();
    let mut index = Vec::new();
    kit::write_index(&mut index, "fixture", &v1, &entries).unwrap();
    fixture.write_index(&index);
    fs::write(
        fixture.0.join("ring"),
        format!(
            "VELMORA_KEK_1={}ExM=\nVELMORA_KEK_2={}FBQ=\n",
            "ExMT".repeat(10),
            "FBQU".repeat(10)
        ),
    )
    .unwrap();
    let result = fixture.run(
        "ring",
        &[["--kek-version", "1"].as_slice(), DECRYPT].concat(),
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(fixture.0.join("output/example/nested/example.bin")).unwrap(),
        b"recoverable sealed-kit fixture"
    );
}

#[test]
fn unmapped_conflict_and_unposted_object_do_not_abort_later_objects() {
    let fixture = Fixture::new();
    let index = fixture.fixture();
    let kek = TestKey(KekBytes::new([19; 32]));
    let mut entries = kit::read_index(Cursor::new(index), "fixture", &kek).unwrap();
    let mut conflict = entries
        .iter()
        .find_map(|e| match e {
            kit::Entry::Object(o) => Some(o.clone()),
            _ => None,
        })
        .unwrap();
    conflict.key = "a/../blocked".into();
    conflict.generation_id = "g_conflict".into();
    let mut unposted = conflict.clone();
    unposted.key = "b-unposted".into();
    unposted.generation_id = "g_unposted".into();
    unposted.extents[0].id = "x_unposted".into();
    let mut missing = entries
        .iter()
        .find_map(|e| match e {
            kit::Entry::Extent(x) => Some(x.clone()),
            _ => None,
        })
        .unwrap();
    missing.id = "x_unposted".into();
    missing.plan_rev = None;
    missing.articles.clear();
    entries.extend([
        kit::Entry::Object(conflict),
        kit::Entry::Object(unposted),
        kit::Entry::Extent(missing),
    ]);
    let mut index = Vec::new();
    kit::write_index(&mut index, "fixture", &kek, &entries).unwrap();
    fixture.write_index(&index);
    let dir = fixture.0.join("output/_unmapped/example");
    fs::create_dir_all(&dir).unwrap();
    let existing = dir.join("%61%2F%2E%2E%2F%62%6C%6F%63%6B%65%64");
    fs::write(&existing, b"keep this file").unwrap();
    let result = fixture.run("key", DECRYPT);
    assert!(!result.status.success());
    assert_eq!(fs::read(existing).unwrap(), b"keep this file");
    assert!(!fixture.0.join("output/example/b-unposted").exists());
    assert_eq!(
        fs::read(fixture.0.join("output/example/nested/example.bin")).unwrap(),
        b"recoverable sealed-kit fixture"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("one or more objects could not be recovered"));
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("unmapped destination already contains different data"));
    assert!(stdout.contains("extent has no usable Usenet plan"));
    assert!(stdout.contains("\"failed\":2,\"recovered\":1"));
}

#[test]
fn same_size_overwrite_recovers_current_bytes_despite_stale_source_md5() {
    let fixture = Fixture::new();
    let index = fixture.fixture();
    let kek = TestKey(KekBytes::new([19; 32]));
    let mut entries = kit::read_index(Cursor::new(index), "fixture", &kek).unwrap();
    let live = entries
        .iter_mut()
        .find_map(|entry| match entry {
            kit::Entry::Object(o) => Some(o),
            _ => None,
        })
        .unwrap();
    live.source_md5 = Some(md5::compute(vec![42; live.size as usize]).0.to_vec().into());
    let mut index = Vec::new();
    kit::write_index(&mut index, "fixture", &kek, &entries).unwrap();
    fixture.write_index(&index);
    let result = fixture.run("key", DECRYPT);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("source MD5 differs; object may have been overwritten since the annotation"));
    assert_eq!(
        fs::read(fixture.0.join("output/example/nested/example.bin")).unwrap(),
        b"recoverable sealed-kit fixture"
    );
}

#[test]
fn authenticated_full_object_checksum_mismatch_blocks_promotion() {
    let fixture = Fixture::new();
    let index = fixture.fixture();
    let kek = TestKey(KekBytes::new([19; 32]));
    let mut entries = kit::read_index(Cursor::new(index), "fixture", &kek).unwrap();
    let live = entries
        .iter_mut()
        .find_map(|entry| match entry {
            kit::Entry::Object(o) => Some(o),
            _ => None,
        })
        .unwrap();
    live.checksum = Some(serde_json::json!({"algorithm": "SHA256", "type": "FULL_OBJECT", "value": format!("{}=", "A".repeat(43))}).to_string());
    let mut index = Vec::new();
    kit::write_index(&mut index, "fixture", &kek, &entries).unwrap();
    fixture.write_index(&index);
    let result = fixture.run("key", DECRYPT);
    assert!(!result.status.success());
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("whole-object integrity check failed"));
    assert!(!fixture.0.join("output/example/nested/example.bin").exists());
}

#[test]
fn malformed_keyring_assignment_is_not_silently_ignored() {
    let fixture = Fixture::new();
    fixture.fixture();
    for malformed in [
        "VELMORA_KEK_typo=ignored",
        "VELMORA_KEK_+2=ignored",
        "VELMORA_KEK_0=ignored",
        "VELMORA_KEK_4294967296=ignored",
        "VELMORA_KEK_2",
    ] {
        fs::write(
            fixture.0.join("ring"),
            format!("VELMORA_KEK_1={}ExM=\n{malformed}\n", "ExMT".repeat(10)),
        )
        .unwrap();
        let result = fixture.run("ring", DECRYPT);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("invalid KEK input"));
        assert!(!fixture.0.join("output").exists());
    }
}
