//! A new record writer must come with a `family()` row and a native writer fixture.

mod record_registry_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use velmora::rng::SystemRng;
use velmora_bridge::crypto::scheme2::KCV_LEN;
use velmora_bridge::directory::chain::TenantChain;
use velmora_bridge::directory::gate::{close, run_gate_if_closed, NotBuilt};
use velmora_bridge::directory::seal::DoorSeal;
use velmora_bridge::directory::store::SqlDirectory;
use velmora_bridge::keys::audit::{audit, repair_missing};
use velmora_bridge::keys::escrow::{restore_escrow, EscrowCopy};
use velmora_bridge::keys::locations::two_in_account;
use velmora_bridge::keys::tk::{
    create_key_version, Claim, Commit, KeyBuckets, KeyCheck, KeyVersionClaims,
};
use velmora_bridge::records::MemRecords;
use velmora_bridge::recovery::check::{family, Family};
use velmora_bridge::testkit::{RusqliteSql, TestKek};
use velmora_bridge::{Result, TenantId, UnixMs};

// Counts: seal_control, seal_record_v2, seal_manifest, put, put_if_absent.
// Include *every* put-shaped call, rather than guessing whether a dynamic name
// can start with m/. This registers the indirections through Chain and BlobStore
// and fails closed on a new raw writer even if its name is built in another file.
// The last group are explicitly not producers of SAFETY recovery records.
// The reserved-subject and creator-grant writers are exercised against
// MemRecords in key_reserved.rs and key_writer.rs, which check their families.
const WRITERS: &[(&str, [usize; 5])] = &[
    ("directory/chain.rs", [0, 0, 0, 0, 1]), // TenantChain::write
    ("directory/gate.rs", [0, 0, 0, 0, 2]),  // close, run_gate_if_closed
    ("directory/seal.rs", [3, 0, 0, 0, 0]),  // ChainSeal::seal: zero, keyless, managed
    ("keys/buckets.rs", [0, 0, 0, 1, 0]),    // creator-grant put through key_chain
    ("keys/chain.rs", [0, 0, 0, 0, 1]),      // Chain::put, common chain storage
    ("keys/checkpoint.rs", [1, 0, 0, 0, 0]), // seal_checkpoint, used by finish_keys
    ("keys/frozen.rs", [0, 0, 0, 2, 0]),     // freeze/thaw marker writes through key_chain
    ("keys/locations.rs", [1, 0, 0, 1, 0]),  // seal_locations, write_locations
    ("keys/moving.rs", [0, 1, 0, 2, 1]), // seal, put_sealed, moved key-chain write; rehome_blob (x/, not m/)
    ("keys/record.rs", [2, 0, 0, 0, 0]), // seal_key_record_carrying, seal_marker_record
    ("keys/reserved.rs", [0, 0, 0, 1, 0]), // reserved subject put through key_chain
    ("keys/revocations.rs", [1, 0, 0, 0, 1]), // put_tenant_revocation
    ("keys/routes.rs", [1, 0, 0, 0, 1]), // put_route
    ("keys/writer.rs", [0, 0, 0, 2, 1]), // KeyEnv::change, finish_revocation, finish_keys
    ("recovery.rs", [0, 2, 3, 1, 0]), // RecordSeal impls, common write (generation/tombstone/revocation/plan)
    // Wrapped key blobs: run the writers, but the names are *only* TenantKey.
    ("keys/audit.rs", [0, 0, 0, 0, 1]),  // repair_missing
    ("keys/escrow.rs", [0, 0, 0, 0, 1]), // restore_escrow
    ("keys/tk.rs", [0, 0, 0, 0, 2]),     // create_key_version (arbiter, copy_to)
    // Adapters, non-recovery puts, or consumers that forward existing names.
    ("copy.rs", [0, 0, 0, 2, 1]), // rc/ marks, rc/key-page/ claims, and already-proved copies to the remote
    ("ports.rs", [0, 0, 0, 1, 0]), // BlobStore::put_if_absent's default, forwarding to put
    ("directory/fence.rs", [0, 0, 0, 1, 0]), // legacy stamp
    ("fetch.rs", [0, 0, 0, 1, 0]), // cache fill
    ("records.rs", [0, 0, 0, 0, 1]), // RecordStore forwarding impl
    ("root/client.rs", [0, 0, 0, 1, 0]), // cache forwarding impl
    ("service/multipart.rs", [0, 0, 0, 1, 0]), // extent staging
    ("service/put.rs", [0, 0, 0, 2, 0]), // ingress put entry point and extent staging
    ("service/slices.rs", [0, 0, 0, 1, 0]), // extent staging
    ("stamp.rs", [0, 0, 0, 1, 0]), // sealed catalogue stamp
    ("unit/keys.rs", [0, 0, 0, 1, 0]), // key row put in SQL
    ("unit_router.rs", [0, 0, 0, 1, 0]), // routing cache put
];

fn pre_test_code(text: &str) -> String {
    text.lines()
        .take_while(|line| line.trim() != "#[cfg(test)]")
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Keep identifiers and punctuation as separate tokens so qualification,
/// formatting and a turbofish do not hide an invocation.
fn tokens(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let c = bytes[i];
        i += 1;
        match c {
            c if c.is_ascii_whitespace() => continue,
            b'/' if bytes.get(i) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if bytes.get(i) == Some(&b'*') => {
                i += 1;
                let mut depth = 1;
                while i + 1 < bytes.len() && depth > 0 {
                    match &bytes[i..i + 2] {
                        b"/*" => {
                            depth += 1;
                            i += 2;
                        }
                        b"*/" => {
                            depth -= 1;
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
                continue;
            }
            b'"' => {
                while i < bytes.len() {
                    let ch = bytes[i];
                    i += 1;
                    if ch == b'"' {
                        break;
                    }
                    if ch == b'\\' {
                        i = (i + 1).min(bytes.len());
                    }
                }
            }
            b'r' if matches!(bytes.get(i), Some(b'"' | b'#')) => {
                while bytes.get(i) == Some(&b'#') {
                    i += 1;
                }
                if bytes.get(i) == Some(&b'"') {
                    let hashes = &bytes[start + 1..i];
                    i += 1;
                    while i < bytes.len() {
                        let ch = bytes[i];
                        i += 1;
                        if ch == b'"' && bytes[i..].starts_with(hashes) {
                            i += hashes.len();
                            break;
                        }
                    }
                } else {
                    // A raw identifier (`r#ident`), not a string.
                    continue;
                }
            }
            c if c.is_ascii_alphanumeric() || c == b'_' => {
                while bytes
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
                {
                    i += 1;
                }
            }
            c if !c.is_ascii() => continue,
            _ => {}
        }
        out.push(&text[start..i]);
    }
    out
}

fn followed_by_arguments(tokens: &[&str]) -> bool {
    if tokens.first() == Some(&"(") {
        return true;
    }
    if !tokens.starts_with(&[":", ":", "<"]) {
        return false;
    }
    let mut depth = 1;
    for (i, token) in tokens.iter().enumerate().skip(3) {
        match *token {
            "<" => depth += 1,
            ">" => {
                depth -= 1;
                if depth == 0 {
                    return tokens.get(i + 1) == Some(&"(");
                }
            }
            _ => {}
        }
    }
    false
}

fn counts(text: &str) -> [usize; 5] {
    let text = pre_test_code(text);
    let ts = tokens(&text);
    let names = [
        "seal_control",
        "seal_record_v2",
        "seal_manifest",
        "put",
        "put_if_absent",
    ];
    let mut result = [0; 5];
    for (i, token) in ts.iter().enumerate() {
        if let Some(kind) = names.iter().position(|name| name == token) {
            if ts.get(i.wrapping_sub(1)) != Some(&"fn") && followed_by_arguments(&ts[i + 1..]) {
                result[kind] += 1;
            }
        }
    }
    result
}

fn scan(root: &Path, dir: &Path, out: &mut BTreeMap<String, [usize; 5]>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            scan(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = fs::read_to_string(&path).unwrap();
            let found = counts(&text);
            if found != [0; 5] {
                out.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                    found,
                );
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_record_writer_calls_are_registered() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut actual = BTreeMap::new();
    scan(&root, &root, &mut actual);
    let expected: BTreeMap<_, _> = WRITERS
        .iter()
        .map(|(file, counts)| (file.to_string(), *counts))
        .collect();
    let mut differences = Vec::new();
    for file in actual
        .keys()
        .chain(expected.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if actual.get(file) != expected.get(file) {
            differences.push(format!(
                "{file}: found {:?}, registered {:?}",
                actual.get(file),
                expected.get(file)
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "update the writer fixture and family table:\n{}",
        differences.join("\n")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn scanner_tracks_qualified_calls_but_not_definitions_comments_or_tests() {
    let fixture = r###"
        fn put() {}
        // put("m/no", body);
        let _ = "seal_manifest(";
        let _ = r#"quoted \" seal_control("#;
        /* seal_manifest( */
        store.put (
            format!("m/new/{id}"), bytes
        );
        store.put_if_absent(&name, bytes);
        scheme2::seal_record_v2::<crate::Key>(key, name, body);
        #[cfg(test)]
        mod tests { fn x() { seal_control(a, b); } }
    "###;
    assert_eq!(counts(fixture), [0, 1, 0, 1, 1]);
}

// `create_key_version` owns both key-bucket puts. Only the chain's claim
// endpoint is stubbed; actual wrapping and storage run here.
struct NewClaim;

impl KeyVersionClaims for NewClaim {
    async fn claim(&self, _: &TenantId, from: u32) -> Result<Claim> {
        assert_eq!(from, 0);
        Ok(Claim::Claimed(1))
    }
    async fn void(&self, _: &TenantId, _: u32) -> Result<Claim> {
        panic!("fresh fixture must not void a claim")
    }
    async fn commit(&self, _: &TenantId, v: u32, _: [u8; KCV_LEN]) -> Result<Commit> {
        assert_eq!(v, 1);
        Ok(Commit::Committed)
    }
    async fn committed_kcv(&self, _: &TenantId, _: u32) -> Result<KeyCheck> {
        Ok(KeyCheck::NotCommitted)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn key_blob_creation_repair_and_escrow_write_only_the_excluded_family() {
    let kek = TestKek::new();
    let a = MemRecords::new();
    let b = MemRecords::new();
    let stores = KeyBuckets {
        by_name: vec![("KEYS_A", &a), ("KEYS_B", &b)],
    };
    let locations = two_in_account();
    let tenant = TenantId::parse(record_registry_support::A).unwrap();
    let created = create_key_version(
        &locations,
        &stores,
        &NewClaim,
        &kek,
        &tenant,
        0,
        &mut SystemRng,
    )
    .await
    .unwrap();
    let names = a.names();
    assert_eq!(names.len(), 1);
    assert_eq!(b.names(), names);
    let name = &names[0];
    assert!(matches!(family(name), Family::TenantKey));
    let copy = EscrowCopy::of_blob(&tenant, 1, created.kek_version, &a.raw(name).unwrap()).unwrap();

    assert!(b.lose(name));
    let report = audit(&locations, &stores, Some(&kek)).await.unwrap();
    repair_missing(&locations, &stores, &kek, &report)
        .await
        .unwrap();
    assert_eq!(
        b.names(),
        names,
        "key repair must write only the excluded name"
    );

    assert!(a.lose(name) && b.lose(name));
    restore_escrow(&copy, &kek, created.key.check_value(), &locations, &stores)
        .await
        .unwrap();
    assert_eq!(
        a.names(),
        names,
        "escrow restore must write only the excluded name"
    );
    assert_eq!(b.names(), names);
}

#[tokio::test(flavor = "current_thread")]
async fn native_writer_outputs_all_match_the_family_table() {
    use record_registry_support::{
        control_records, data_records, segmented_records, A, B, SHREDDED, ZERO,
    };

    let kek = TestKek::new();
    let mut outputs = control_records(&kek).await;
    outputs.extend(data_records(&kek).await);
    let segmented = segmented_records(&kek, B).await;
    outputs.extend(segmented.plans);
    outputs.extend(segmented.segments);
    outputs.push(segmented.head);

    // Exercise the alternate anchor writer on an empty chain and closed gate.
    let store = MemRecords::new();
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
    ))
    .unwrap();
    let dir = SqlDirectory { sql: &db };
    let now = UnixMs(1_800_000_000_000);
    let seal = DoorSeal::new(&kek);
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let first = close(&store, &dir, "fixture", now).await.unwrap();
    run_gate_if_closed(&chain, &dir, &NotBuilt, "resume fixture", now)
        .await
        .unwrap()
        .expect("closed gate resumes");
    let new_anchor = format!("m/dg/{:020}", first + 1);
    outputs.push((
        new_anchor.clone(),
        store.raw(&new_anchor).expect("resume wrote its anchor"),
    ));

    for (name, _) in &outputs {
        assert!(
            !matches!(family(name), Family::Unknown | Family::TenantKey),
            "unregistered recovery record: {name}"
        );
    }
    // Prevent empty or partially wired fixtures from becoming vacuous. All
    // current family shapes have a concrete witness; the native writers above
    // and wire fixtures for the not-yet-written families share the same check.
    for prefix in [
        format!("m/t/{ZERO}/"),
        format!("m/t/{A}/"),
        format!("m/t/{B}/"),
        format!("m/t/{SHREDDED}/"),
        format!("m/k/{A}/"),
        format!("m/kc/{A}/"),
        format!("m/rk/{A}/"),
        "m/rk/FLATV1".to_owned(),
        "m/rk/FLATVCR".to_owned(),
        "m/kl/".to_owned(),
        "m/kr/".to_owned(),
        "m/tref/".to_owned(),
        "m/ub/".to_owned(),
        "m/reg/".to_owned(),
        "m/rst/".to_owned(),
        "m/dg/".to_owned(),
        "m/g_".to_owned(),
        format!("m/x/{ZERO}/b/"),
        format!("m/x/{A}/b/"),
        format!("m/x/{A}/g_"),
        format!("m/x/{A}/del/"),
        format!("m/x/{B}/art/"),
        format!("m/x/{B}/seg/"),
    ] {
        assert!(
            outputs.iter().any(|(name, _)| name.starts_with(&prefix)),
            "missing writer fixture: {prefix}"
        );
    }
}
