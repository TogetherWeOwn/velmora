//! Key scheme 2 (managed tenants): tenant keys, scheme-2 wraps, VMR2
//! records and two-part control records.
//!
//! Test keys are never literals: each is the SHA-256 of a label, and the
//! "random" source is a SHA-256 counter stream, so runs are
//! reproducible. The format tests re-derive every key and AAD by hand
//! from the documented strings, with the cipher crate directly, so a
//! change of any byte of the format fails here and not only in a
//! round trip.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{
    is_record_v2, open_record_v2, parse_control, record_v2_header, seal_control, seal_record_v2,
    tk_blob_check_value, tk_blob_name, unwrap_bdk_v2, unwrap_secret_v2, unwrap_tenant_key,
    wrap_bdk_v2, wrap_secret_v2, wrap_tenant_key, wrap_tenant_key_as, ControlOwner, ControlSealer,
    PrivateKeyRef, Scheme, TenantId, TenantKey, CONTROL_HEADER_LEN, KCV_LEN, RECORD_V2_HEADER_LEN,
    TK_BLOB_LEN, WRAP_VERSION_2,
};
use velmora_bridge::crypto::{
    open_manifest, open_range, seal_extent, seal_manifest, unwrap_bdk, unwrap_secret, wrap_bdk,
    wrap_secret, DataKey, WrappedKey, WRAPPED_KEY_LEN, WRAP_OVERHEAD,
};
use velmora_bridge::testkit::TestKek;
use velmora_bridge::{
    BridgeError, BucketId, ExtentId, ExtentRow, ExtentState, SafetyState, UnixMs,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

impl TestRng {
    fn new(label: &str) -> Self {
        TestRng {
            seed: derived(label),
            counter: 0,
        }
    }
}

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(self.counter.to_be_bytes());
            self.counter += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

struct BrokenRng;

impl FillRandom for BrokenRng {
    fn fill_bytes(&mut self, _dest: &mut [u8]) -> velmora::Result<()> {
        Err(velmora::Error::Malformed("no entropy".into()))
    }
}

fn rng() -> TestRng {
    TestRng::new("scheme2")
}

fn kek_v1() -> TestKek {
    TestKek::with_versions(1, &[(1, derived("kek v1"))])
}

/// Versions 1 and 2 with 2 active: a KEK rotation in progress.
fn kek_v2() -> TestKek {
    TestKek::with_versions(2, &[(1, derived("kek v1")), (2, derived("kek v2"))])
}

fn tenant(n: u8) -> TenantId {
    TenantId::parse(&format!("t_00000000000000{n:02x}")).unwrap()
}

fn tk(label: &str) -> TenantKey {
    TenantKey::from_bytes(derived(label))
}

fn bucket(n: u8) -> BucketId {
    BucketId::mint([n; 8])
}

fn hkdf(ikm: &[u8; 32], info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info.as_bytes(), &mut out)
        .unwrap();
    out
}

/// Opens `version ‖ nonce ‖ ct ‖ tag` with the cipher crate directly.
fn raw_open(key: &[u8; 32], aad: &[u8], wrapped: &[u8], version: u8) -> Option<Vec<u8>> {
    if wrapped.len() < WRAP_OVERHEAD || wrapped[0] != version {
        return None;
    }
    let nonce = XNonce::from(<[u8; 24]>::try_from(&wrapped[1..25]).unwrap());
    let (ct, tag) = wrapped[25..].split_at(wrapped.len() - 25 - 16);
    let mut out = ct.to_vec();
    XChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .decrypt_inout_detached(
            &nonce,
            aad,
            out.as_mut_slice().into(),
            &Tag::from(<[u8; 16]>::try_from(tag).unwrap()),
        )
        .ok()?;
    Some(out)
}

fn hexs(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_crypto(e: &BridgeError, msg: &str) -> bool {
    matches!(e, BridgeError::Crypto(m) if *m == msg)
}

// ---------------------------------------------------------------------------
// Tenant keys
// ---------------------------------------------------------------------------

#[test]
fn a_tenant_key_blob_opens_under_its_own_name_only() {
    let kek = kek_v1();
    let t = tenant(1);
    let key = tk("tk a");
    let (v, blob) = wrap_tenant_key(&kek, &t, 1, &key, &mut rng()).unwrap();
    assert_eq!(v, 1);
    assert_eq!(blob.len(), TK_BLOB_LEN);
    assert_eq!(TK_BLOB_LEN, 81);
    assert_eq!(tk_blob_name(&t, 1, v), "m/tk/t_0000000000000001/1.1");
    assert_eq!(tk_blob_check_value(&blob).unwrap(), key.check_value());

    let opened = unwrap_tenant_key(&kek, 1, &t, 1, &blob).unwrap();
    assert_eq!(opened.check_value(), key.check_value());

    // Another tenant, key version or KEK version: the AAD differs.
    assert!(unwrap_tenant_key(&kek, 1, &tenant(2), 1, &blob).is_err());
    assert!(unwrap_tenant_key(&kek, 1, &t, 2, &blob).is_err());
    let both = kek_v2();
    assert!(unwrap_tenant_key(&both, 2, &t, 1, &blob).is_err());
    // An unknown KEK version and version 0 are refused.
    assert!(unwrap_tenant_key(&kek, 9, &t, 1, &blob).is_err());
    assert!(unwrap_tenant_key(&kek, 1, &t, 0, &blob).is_err());
    assert!(wrap_tenant_key(&kek, &t, 0, &key, &mut rng()).is_err());
}

#[test]
fn a_changed_byte_or_a_changed_check_value_does_not_open() {
    let kek = kek_v1();
    let t = tenant(1);
    let (_, blob) = wrap_tenant_key(&kek, &t, 1, &tk("tk a"), &mut rng()).unwrap();
    for i in 0..blob.len() {
        let mut bad = blob.clone();
        bad[i] ^= 0x01;
        assert!(unwrap_tenant_key(&kek, 1, &t, 1, &bad).is_err(), "byte {i}");
    }
    // A check value taken from another key, put in front of this wrap.
    let other = tk("tk b").check_value();
    let mut swapped = blob.clone();
    swapped[..KCV_LEN].copy_from_slice(&other);
    assert!(unwrap_tenant_key(&kek, 1, &t, 1, &swapped).is_err());
    assert!(tk_blob_check_value(&blob[..80]).is_err());
}

#[test]
fn a_kek_rewrap_keeps_the_check_value() {
    let both = kek_v2();
    let t = tenant(3);
    let key = tk("tk a");
    let old = wrap_tenant_key_as(&both, 1, &t, 1, &key, &mut rng()).unwrap();
    let (v, new) = wrap_tenant_key(&both, &t, 1, &key, &mut TestRng::new("other")).unwrap();
    assert_eq!(v, 2);
    assert_ne!(old, new);
    assert_eq!(
        tk_blob_check_value(&old).unwrap(),
        tk_blob_check_value(&new).unwrap()
    );
    let a = unwrap_tenant_key(&both, 1, &t, 1, &old).unwrap();
    let b = unwrap_tenant_key(&both, 2, &t, 1, &new).unwrap();
    assert_eq!(a.check_value(), b.check_value());
    // Each blob opens only under the KEK version of its name.
    assert!(unwrap_tenant_key(&both, 2, &t, 1, &old).is_err());
    assert!(unwrap_tenant_key(&both, 1, &t, 1, &new).is_err());
}

#[test]
fn different_keys_have_different_check_values() {
    assert_ne!(tk("tk a").check_value(), tk("tk b").check_value());
    let mut r = rng();
    let a = TenantKey::generate(&mut r).unwrap();
    let b = TenantKey::generate(&mut r).unwrap();
    assert_ne!(a.check_value(), b.check_value());
    assert!(TenantKey::generate(&mut BrokenRng).is_err());
    assert_eq!(format!("{a:?}"), "TenantKey(<redacted>)");
}

/// The blob, re-derived by hand from the documented strings.
#[test]
fn the_tenant_key_blob_has_the_documented_format() {
    let kek = kek_v1();
    let t = tenant(1);
    let key_bytes = derived("tk a");
    let key = TenantKey::from_bytes(key_bytes);
    let (_, blob) = wrap_tenant_key(&kek, &t, 7, &key, &mut rng()).unwrap();

    let kcv = &hkdf(&key_bytes, "velmora/tk-check/v1")[..8];
    assert_eq!(&blob[..8], kcv);
    let aad = format!("velmora/tk/v1|t_0000000000000001|7|1|{}", hexs(kcv));
    let plain = raw_open(&derived("kek v1"), aad.as_bytes(), &blob[8..], 0x01).unwrap();
    assert_eq!(plain, key_bytes);
}

// ---------------------------------------------------------------------------
// Bucket data keys
// ---------------------------------------------------------------------------

#[test]
fn a_scheme_two_bdk_opens_for_its_tenant_bucket_and_version_only() {
    let t = tenant(1);
    let key = tk("tk a");
    let bdk = DataKey::from_bytes(derived("bdk"));
    let wrapped = wrap_bdk_v2(&key, &t, 1, &bucket(1), &bdk, &mut rng()).unwrap();
    assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
    assert_eq!(wrapped[0], WRAP_VERSION_2);
    assert!(Scheme::Two(t.clone()).check(&wrapped).is_ok());
    assert!(Scheme::One.check(&wrapped).is_err());
    assert!(unwrap_bdk_v2(&key, &t, 1, &bucket(1), &wrapped).is_ok());

    assert!(unwrap_bdk_v2(&key, &tenant(2), 1, &bucket(1), &wrapped).is_err());
    assert!(unwrap_bdk_v2(&key, &t, 2, &bucket(1), &wrapped).is_err());
    assert!(unwrap_bdk_v2(&key, &t, 1, &bucket(2), &wrapped).is_err());
    assert!(unwrap_bdk_v2(&tk("tk b"), &t, 1, &bucket(1), &wrapped).is_err());
    assert!(unwrap_bdk_v2(&key, &t, 0, &bucket(1), &wrapped).is_err());
    assert!(wrap_bdk_v2(&key, &t, 0, &bucket(1), &bdk, &mut rng()).is_err());
    for i in 0..wrapped.len() {
        let mut bad = wrapped.clone();
        bad[i] ^= 0x80;
        assert!(
            unwrap_bdk_v2(&key, &t, 1, &bucket(1), &bad).is_err(),
            "byte {i}"
        );
    }
}

#[test]
fn the_two_bdk_schemes_never_open_each_other() {
    let kek = kek_v1();
    let t = tenant(1);
    let key = tk("tk a");
    let bdk = DataKey::from_bytes(derived("bdk"));

    // Scheme 1 bytes are refused by scheme 2, also with the byte changed.
    let (v, one) = wrap_bdk(&kek, &bucket(1), &bdk, &mut rng()).unwrap();
    assert!(unwrap_bdk_v2(&key, &t, 1, &bucket(1), one.as_bytes()).is_err());
    let mut relabelled = one.to_vec();
    relabelled[0] = WRAP_VERSION_2;
    assert!(unwrap_bdk_v2(&key, &t, 1, &bucket(1), &relabelled).is_err());

    // Scheme 2 bytes are refused by scheme 1, also with the byte changed.
    let two = wrap_bdk_v2(&key, &t, 1, &bucket(1), &bdk, &mut rng()).unwrap();
    assert!(WrappedKey::from_slice(&two).is_err());
    assert!(unwrap_bdk(&kek, v, &bucket(1), &two).is_err());
    let mut relabelled = two.clone();
    relabelled[0] = 0x01;
    assert!(unwrap_bdk(&kek, v, &bucket(1), &relabelled).is_err());
}

/// A file key wrapped under a BDK opens under the same BDK after a
/// re-wrap from scheme 1 to scheme 2: no extent changes at a move.
#[test]
fn an_extent_opens_under_a_bdk_rewrapped_to_scheme_two() {
    let kek = kek_v1();
    let t = tenant(1);
    let key = tk("tk a");
    let b = bucket(4);
    let x = ExtentId::mint([9; 13]);
    let bdk = DataKey::from_bytes(derived("bdk"));
    let plain: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let sealed = seal_extent(&bdk, &b, &x, &plain, &mut rng()).unwrap();

    let (v, one) = wrap_bdk(&kek, &b, &bdk, &mut rng()).unwrap();
    let from_one = unwrap_bdk(&kek, v, &b, one.as_bytes()).unwrap();
    let two = wrap_bdk_v2(&key, &t, 1, &b, &from_one, &mut rng()).unwrap();
    let from_two = unwrap_bdk_v2(&key, &t, 1, &b, &two).unwrap();

    let row = ExtentRow {
        id: x.clone(),
        bucket_id: b.clone(),
        generation_id: None,
        state: ExtentState::Staged,
        seq: None,
        plain_offset: None,
        plain_size: plain.len() as u64,
        cipher_size: sealed.ciphertext.len() as u64,
        media_header: sealed.media_header.to_vec(),
        key_mode: 1,
        wrapped_file_key: Some(sealed.wrapped_file_key.to_vec()),
        plain_md5: sealed.plain_md5,
        plain_sha256: sealed.plain_sha256,
        cipher_sha256: sealed.cipher_sha256,
        safety_state: SafetyState::Held,
        article_count: None,
        plan_rev: 0,
        last_verified_at: None,
        release_evidence: None,
        released_at: None,
        created_at: UnixMs::ZERO,
    };
    let mut out = vec![0u8; plain.len()];
    let n = open_range(&from_two, &b, &row, 0, &sealed.ciphertext, 0, &mut out).unwrap();
    assert_eq!(n, plain.len());
    assert_eq!(out, plain);
}

#[test]
fn the_scheme_two_bdk_wrap_has_the_documented_format() {
    let t = tenant(1);
    let key_bytes = derived("tk a");
    let key = TenantKey::from_bytes(key_bytes);
    let bdk_bytes = derived("bdk");
    let b = bucket(1);
    let wrapped =
        wrap_bdk_v2(&key, &t, 3, &b, &DataKey::from_bytes(bdk_bytes), &mut rng()).unwrap();
    let wrap_key = hkdf(&key_bytes, "velmora/tk-wrap/v1");
    let aad = format!("velmora/bdk/v2|t_0000000000000001|{}|3", b.as_str());
    let plain = raw_open(&wrap_key, aad.as_bytes(), &wrapped, 0x02).unwrap();
    assert_eq!(plain, bdk_bytes);
    // The TK itself is not the wrapping key.
    assert!(raw_open(&key_bytes, aad.as_bytes(), &wrapped, 0x02).is_none());
}

// ---------------------------------------------------------------------------
// S3 secrets
// ---------------------------------------------------------------------------

#[test]
fn an_ak_v2_secret_opens_for_its_key_id_tenant_and_kek_version_only() {
    let kek = kek_v1();
    let t = tenant(1);
    let secret = b"0123456789abcdefghijABCDEFGHIJ0123456789";
    let (v, wrapped) = wrap_secret_v2(&kek, &t, "AKVLAAAA", secret, &mut rng()).unwrap();
    assert_eq!(wrapped[0], WRAP_VERSION_2);
    assert_eq!(wrapped.len(), secret.len() + WRAP_OVERHEAD);
    assert_eq!(
        &unwrap_secret_v2(&kek, v, &t, "AKVLAAAA", &wrapped).unwrap()[..],
        secret
    );
    assert!(unwrap_secret_v2(&kek, v, &tenant(2), "AKVLAAAA", &wrapped).is_err());
    assert!(unwrap_secret_v2(&kek, v, &t, "AKVLAAAB", &wrapped).is_err());
    assert!(unwrap_secret_v2(&kek_v2(), 2, &t, "AKVLAAAA", &wrapped).is_err());
    assert!(unwrap_secret_v2(&kek_v2(), 1, &t, "AKVLAAAA", &wrapped).is_ok());
    assert!(wrap_secret_v2(&kek, &t, "AK|X", secret, &mut rng()).is_err());
    assert!(wrap_secret_v2(&kek, &t, "AKVL", b"", &mut rng()).is_err());

    // The documented AAD, by hand.
    let aad = format!("velmora/ak/v2|AKVLAAAA|t_0000000000000001|{v}");
    assert_eq!(
        raw_open(&derived("kek v1"), aad.as_bytes(), &wrapped, 0x02).unwrap(),
        secret
    );
}

#[test]
fn the_two_secret_schemes_never_open_each_other() {
    let kek = kek_v1();
    let t = tenant(1);
    let secret = b"same secret, same key id";
    let (v1, one) = wrap_secret(&kek, "AKVLAAAA", secret, &mut rng()).unwrap();
    let (v2, two) = wrap_secret_v2(&kek, &t, "AKVLAAAA", secret, &mut rng()).unwrap();
    assert!(unwrap_secret_v2(&kek, v1, &t, "AKVLAAAA", &one).is_err());
    assert!(unwrap_secret(&kek, v2, "AKVLAAAA", &two).is_err());
    let mut relabelled = one.clone();
    relabelled[0] = WRAP_VERSION_2;
    assert!(unwrap_secret_v2(&kek, v1, &t, "AKVLAAAA", &relabelled).is_err());
    let mut relabelled = two.clone();
    relabelled[0] = 0x01;
    assert!(unwrap_secret(&kek, v2, "AKVLAAAA", &relabelled).is_err());
}

// ---------------------------------------------------------------------------
// VMR2 data records
// ---------------------------------------------------------------------------

#[test]
fn a_v2_record_opens_under_its_name_tenant_and_key_version_only() {
    let t = tenant(1);
    let key = tk("tk a");
    let name = "m/x/t_0000000000000001/g_0195c2a4b3e7f00112233445566778";
    let sealed = seal_record_v2(&key, &t, 2, name, b"{\"v\":1}", &mut rng()).unwrap();
    assert!(is_record_v2(&sealed));
    assert_eq!(&sealed[..4], b"VMR2");
    assert_eq!(&sealed[4..22], b"t_0000000000000001");
    assert_eq!(&sealed[22..26], &2u32.to_be_bytes());
    assert_eq!(sealed[RECORD_V2_HEADER_LEN], 0x01);
    assert_eq!(record_v2_header(&sealed).unwrap(), (t.clone(), 2));
    assert_eq!(
        &open_record_v2(&key, &t, 2, name, &sealed).unwrap()[..],
        b"{\"v\":1}"
    );

    // Renamed within the tenant, another key, another version.
    let renamed = "m/x/t_0000000000000001/g_0195c2a4b3e7f00112233445566779";
    assert!(open_record_v2(&key, &t, 2, renamed, &sealed).is_err());
    assert!(open_record_v2(&tk("tk b"), &t, 2, name, &sealed).is_err());
    assert!(open_record_v2(&key, &t, 1, name, &sealed).is_err());
    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0x04;
        assert!(open_record_v2(&key, &t, 2, name, &bad).is_err(), "byte {i}");
    }
}

#[test]
fn a_v2_record_of_another_tenant_is_refused_by_its_own_error() {
    let a = tenant(1);
    let b = tenant(2);
    let key = tk("tk a");
    let name_a = "m/x/t_0000000000000001/g_1";
    let name_b = "m/x/t_0000000000000002/g_1";
    let sealed = seal_record_v2(&key, &a, 1, name_a, b"x", &mut rng()).unwrap();

    // Stored under b's prefix: the envelope names a.
    let e = open_record_v2(&key, &b, 1, name_b, &sealed).unwrap_err();
    assert!(is_crypto(&e, "record names another tenant"), "{e:?}");
    // Read as a's record under b's name, or under a flat name.
    let e = open_record_v2(&key, &a, 1, name_b, &sealed).unwrap_err();
    assert!(is_crypto(&e, "record names another tenant"), "{e:?}");
    let e = open_record_v2(&key, &a, 1, "m/g_1", &sealed).unwrap_err();
    assert!(is_crypto(&e, "record names another tenant"), "{e:?}");
    // The writer refuses a name outside its tenant.
    assert!(seal_record_v2(&key, &a, 1, name_b, b"x", &mut rng()).is_err());
    assert!(seal_record_v2(&key, &a, 1, "m/g_1", b"x", &mut rng()).is_err());
    assert!(seal_record_v2(&key, &a, 0, name_a, b"x", &mut rng()).is_err());
}

#[test]
fn v1_and_v2_records_are_never_taken_for_each_other() {
    let kek = kek_v1();
    let t = tenant(1);
    let key = tk("tk a");
    let name = "m/x/t_0000000000000001/g_1";
    let v1 = seal_manifest(&kek, name, b"x", &mut rng()).unwrap();
    assert!(!is_record_v2(&v1));
    assert!(record_v2_header(&v1).is_err());
    assert!(open_record_v2(&key, &t, 1, name, &v1).is_err());
    let v2 = seal_record_v2(&key, &t, 1, name, b"x", &mut rng()).unwrap();
    assert!(open_manifest(&kek, name, &v2).is_err());
}

#[test]
fn the_v2_record_has_the_documented_format() {
    let t = tenant(1);
    let key_bytes = derived("tk a");
    let key = TenantKey::from_bytes(key_bytes);
    let name = "m/x/t_0000000000000001/art/x_01";
    let sealed = seal_record_v2(&key, &t, 5, name, b"plan", &mut rng()).unwrap();
    let k = hkdf(&key_bytes, "velmora/manifest/v2");
    let aad = format!("velmora/manifest/v2|{name}|t_0000000000000001|5");
    assert_eq!(
        raw_open(&k, aad.as_bytes(), &sealed[26..], 0x01).unwrap(),
        b"plan"
    );
}

// ---------------------------------------------------------------------------
// Control records
// ---------------------------------------------------------------------------

const KEY_NAME: &str = "m/k/t_0000000000000001/00000000000000000001";
const KEY_NAME_0: &str = "m/k/t_0000000000000000/00000000000000000001";

fn managed<'a>(t: &'a TenantId, key: &'a TenantKey, v: u32) -> ControlSealer<'a> {
    ControlSealer::Managed {
        tenant: t,
        tk: key,
        tk_version: v,
    }
}

#[test]
fn a_managed_control_record_opens_its_door_without_the_tenant_key() {
    let kek = kek_v1();
    let t = tenant(1);
    let key = tk("tk a");
    let sealed = seal_control(
        &kek,
        KEY_NAME,
        &managed(&t, &key, 4),
        b"door",
        Some(b"private"),
        &mut rng(),
    )
    .unwrap();
    let env = parse_control(&sealed).unwrap();
    assert_eq!(env.kek_version(), 1);
    assert_eq!(env.private_key(), PrivateKeyRef::Tenant(4));
    assert_eq!(
        &env.open_door(&kek, KEY_NAME, ControlOwner::Managed(&t))
            .unwrap()[..],
        b"door"
    );
    assert_eq!(
        &env.open_private_managed(&key, KEY_NAME, &t).unwrap()[..],
        b"private"
    );
    // The private part needs the tenant key.
    assert!(env.open_private_managed(&tk("tk b"), KEY_NAME, &t).is_err());
    // A tenant-0 reader, a global reader or another tenant is refused.
    assert!(env
        .open_door(&kek, KEY_NAME, ControlOwner::TenantZero)
        .is_err());
    assert!(env.open_door(&kek, KEY_NAME, ControlOwner::Global).is_err());
    assert!(env
        .open_door(&kek, KEY_NAME, ControlOwner::Managed(&tenant(2)))
        .is_err());
    assert!(env.open_private_tenant_zero(&kek, KEY_NAME).is_err());
    // Another name.
    let other = "m/k/t_0000000000000001/00000000000000000002";
    assert!(env
        .open_door(&kek, other, ControlOwner::Managed(&t))
        .is_err());
    assert!(env.open_private_managed(&key, other, &t).is_err());
}

#[test]
fn a_tenant_zero_control_record_seals_its_private_part_under_the_kek() {
    let kek = kek_v1();
    let sealed = seal_control(
        &kek,
        KEY_NAME_0,
        &ControlSealer::TenantZero,
        b"door",
        Some(b"secrets"),
        &mut rng(),
    )
    .unwrap();
    let env = parse_control(&sealed).unwrap();
    assert_eq!(env.private_key(), PrivateKeyRef::Kek(1));
    assert_eq!(
        &env.open_door(&kek, KEY_NAME_0, ControlOwner::TenantZero)
            .unwrap()[..],
        b"door"
    );
    assert_eq!(
        &env.open_private_tenant_zero(&kek, KEY_NAME_0).unwrap()[..],
        b"secrets"
    );
    assert!(env
        .open_private_managed(&tk("tk a"), KEY_NAME_0, &tenant(1))
        .is_err());
}

#[test]
fn a_global_control_record_has_a_door_part_only() {
    let kek = kek_v1();
    let name = "m/kl/00000000000000000001";
    let sealed = seal_control(
        &kek,
        name,
        &ControlSealer::Global,
        b"locations",
        None,
        &mut rng(),
    )
    .unwrap();
    let env = parse_control(&sealed).unwrap();
    assert_eq!(env.private_key(), PrivateKeyRef::None);
    assert_eq!(
        &env.open_door(&kek, name, ControlOwner::Global).unwrap()[..],
        b"locations"
    );
    assert!(env.open_private_tenant_zero(&kek, name).is_err());
    // A global record takes no private part; a tenant's always has one.
    assert!(seal_control(
        &kek,
        name,
        &ControlSealer::Global,
        b"d",
        Some(b"p"),
        &mut rng()
    )
    .is_err());
    assert!(seal_control(
        &kek,
        KEY_NAME_0,
        &ControlSealer::TenantZero,
        b"d",
        None,
        &mut rng()
    )
    .is_err());
    let t = tenant(1);
    let key = tk("tk a");
    assert!(seal_control(
        &kek,
        KEY_NAME,
        &managed(&t, &key, 1),
        b"d",
        None,
        &mut rng()
    )
    .is_err());
    assert!(seal_control(
        &kek,
        KEY_NAME,
        &managed(&t, &key, 0),
        b"d",
        Some(b"p"),
        &mut rng()
    )
    .is_err());
}

#[test]
fn the_door_part_binds_the_private_part() {
    let kek = kek_v1();
    let t = tenant(1);
    let key = tk("tk a");
    let a = seal_control(
        &kek,
        KEY_NAME,
        &managed(&t, &key, 1),
        b"door a",
        Some(b"private a"),
        &mut rng(),
    )
    .unwrap();
    let b = seal_control(
        &kek,
        KEY_NAME,
        &managed(&t, &key, 1),
        b"door a",
        Some(b"private b"),
        &mut TestRng::new("b"),
    )
    .unwrap();
    // Same name, same header length: graft b's private part onto a.
    let door_len = u32::from_be_bytes(a[13..17].try_into().unwrap()) as usize;
    let split = CONTROL_HEADER_LEN + door_len;
    assert_eq!(a.len(), b.len());
    let mut grafted = a[..split].to_vec();
    grafted.extend_from_slice(&b[split..]);
    let env = parse_control(&grafted).unwrap();
    // The private part alone still opens (it is b's, under the same name
    // and header), but the door refuses the record as a whole.
    assert!(env.open_private_managed(&key, KEY_NAME, &t).is_ok());
    assert!(env
        .open_door(&kek, KEY_NAME, ControlOwner::Managed(&t))
        .is_err());

    // Every changed byte is refused by the door.
    for i in 0..a.len() {
        let mut bad = a.clone();
        bad[i] ^= 0x10;
        let opened = parse_control(&bad)
            .and_then(|env| env.open_door(&kek, KEY_NAME, ControlOwner::Managed(&t)));
        assert!(opened.is_err(), "byte {i}");
    }
    // Cut short, or with a byte added.
    assert!(parse_control(&a[..a.len() - 1]).is_err());
    let mut longer = a.clone();
    longer.push(0);
    assert!(parse_control(&longer).is_err());
}

#[test]
fn a_control_record_opens_after_the_kek_moves_on() {
    let t = tenant(1);
    let key = tk("tk a");
    let sealed = seal_control(
        &kek_v1(),
        KEY_NAME,
        &managed(&t, &key, 1),
        b"door",
        Some(b"p"),
        &mut rng(),
    )
    .unwrap();
    let both = kek_v2();
    let env = parse_control(&sealed).unwrap();
    assert_eq!(env.kek_version(), 1);
    assert!(env
        .open_door(&both, KEY_NAME, ControlOwner::Managed(&t))
        .is_ok());
    let resealed = seal_control(
        &both,
        KEY_NAME,
        &managed(&t, &key, 1),
        b"door",
        Some(b"p"),
        &mut rng(),
    )
    .unwrap();
    assert_eq!(parse_control(&resealed).unwrap().kek_version(), 2);
    // Without KEK 1 the old record's door does not open.
    let only_two = TestKek::with_versions(2, &[(2, derived("kek v2"))]);
    assert!(env
        .open_door(&only_two, KEY_NAME, ControlOwner::Managed(&t))
        .is_err());
}

#[test]
fn the_control_record_has_the_documented_format() {
    let kek_bytes = derived("kek v1");
    let kek = kek_v1();
    let t = tenant(1);
    let key_bytes = derived("tk a");
    let key = TenantKey::from_bytes(key_bytes);
    let sealed = seal_control(
        &kek,
        KEY_NAME,
        &managed(&t, &key, 6),
        b"door",
        Some(b"private"),
        &mut rng(),
    )
    .unwrap();
    let header = &sealed[..CONTROL_HEADER_LEN];
    assert_eq!(&header[..4], b"VCR1");
    assert_eq!(&header[4..8], &1u32.to_be_bytes());
    assert_eq!(header[8], 2);
    assert_eq!(&header[9..13], &6u32.to_be_bytes());
    let door_len = u32::from_be_bytes(header[13..17].try_into().unwrap()) as usize;
    let priv_len = u32::from_be_bytes(header[17..21].try_into().unwrap()) as usize;
    assert_eq!(door_len, 4 + WRAP_OVERHEAD);
    assert_eq!(priv_len, 7 + WRAP_OVERHEAD);
    assert_eq!(sealed.len(), CONTROL_HEADER_LEN + door_len + priv_len);
    let door = &sealed[CONTROL_HEADER_LEN..CONTROL_HEADER_LEN + door_len];
    let private = &sealed[CONTROL_HEADER_LEN + door_len..];

    let mut priv_aad =
        format!("velmora/control-private/v1|{KEY_NAME}|t_0000000000000001|").into_bytes();
    priv_aad.extend_from_slice(header);
    let priv_key = hkdf(&key_bytes, "velmora/control-private/v1");
    assert_eq!(
        raw_open(&priv_key, &priv_aad, private, 0x01).unwrap(),
        b"private"
    );

    let mut door_aad = format!("velmora/control/v1|{KEY_NAME}|t_0000000000000001|").into_bytes();
    door_aad.extend_from_slice(header);
    door_aad.extend_from_slice(&Sha256::digest(private));
    let door_key = hkdf(&kek_bytes, "velmora/control/v1");
    assert_eq!(raw_open(&door_key, &door_aad, door, 0x01).unwrap(), b"door");
}
