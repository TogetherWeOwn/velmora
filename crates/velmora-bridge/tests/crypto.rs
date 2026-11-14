//! Key wrapping and extent sealing tests.
//!
//! Test keys are never literals: each is the SHA-256 of a label, and the
//! "random" source is a SHA-256 counter stream, so runs are reproducible.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use velmora::media::{self, FileKey, ReadAt, CIPHER_CHUNK_SIZE, HEADER_SIZE, PLAIN_CHUNK_SIZE};
use velmora::rng::{FillRandom, SystemRng};
use velmora_bridge::crypto::{
    cipher_span, list_token_key, open_range, profile, seal_extent, unwrap_bdk, unwrap_file_key,
    unwrap_secret, wrap_bdk, wrap_file_key, wrap_secret, DataKey, OffsetBuf, SealedExtent,
    WrappedKey, MAX_SECRET_LEN, WRAPPED_KEY_LEN, WRAP_OVERHEAD,
};
use velmora_bridge::testkit::TestKek;
use velmora_bridge::{
    BridgeError, BucketId, ExtentId, ExtentRow, ExtentState, Kek, KekBytes, SafetyState, UnixMs,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CHUNK: usize = PLAIN_CHUNK_SIZE as usize;
const SEALED_CHUNK: usize = CIPHER_CHUNK_SIZE as usize;
const HEADER: usize = HEADER_SIZE as usize;
/// Chunks per article: an article boundary falls every 11 sealed chunks.
const ARTICLE_CHUNKS: usize = 11;
const MIB: usize = 1024 * 1024;

/// 32 test-key bytes derived from a label.
fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// Deterministic byte stream: SHA-256(seed ‖ counter) blocks.
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

/// A source that always fails.
struct BrokenRng;

impl FillRandom for BrokenRng {
    fn fill_bytes(&mut self, _dest: &mut [u8]) -> velmora::Result<()> {
        Err(velmora::Error::Malformed("no entropy".into()))
    }
}

fn kek_v1() -> TestKek {
    TestKek::with_versions(1, &[(1, derived("kek v1"))])
}

fn bucket(n: u8) -> BucketId {
    BucketId::mint([n; 8])
}

fn extent(n: u8) -> ExtentId {
    ExtentId::mint([n; 13])
}

fn bdk(label: &str) -> DataKey {
    DataKey::from_bytes(derived(label))
}

/// Cheap, non-repeating plaintext.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[3] ^ (i >> 16) as u8)
        .collect()
}

fn row(bucket: &BucketId, id: &ExtentId, plain_size: usize, sealed: &SealedExtent) -> ExtentRow {
    ExtentRow {
        id: id.clone(),
        bucket_id: bucket.clone(),
        generation_id: None,
        state: ExtentState::Staged,
        seq: None,
        plain_offset: None,
        plain_size: plain_size as u64,
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
    }
}

struct Fixture {
    bdk: DataKey,
    bucket: BucketId,
    plain: Vec<u8>,
    sealed: SealedExtent,
    row: ExtentRow,
}

fn fixture(len: usize) -> Fixture {
    let bdk = bdk("bdk fixture");
    let bucket = bucket(1);
    let id = extent(1);
    let plain = pattern(len);
    let sealed = seal_extent(&bdk, &bucket, &id, &plain, &mut TestRng::new("fixture")).unwrap();
    let row = row(&bucket, &id, len, &sealed);
    Fixture {
        bdk,
        bucket,
        plain,
        sealed,
        row,
    }
}

impl Fixture {
    /// Reads `[off, off + len)` from the whole ciphertext.
    fn read(&self, off: usize, len: usize) -> Result<Vec<u8>, BridgeError> {
        self.read_from(0, &self.sealed.ciphertext, off, len)
    }

    fn read_from(
        &self,
        base: u64,
        src: &[u8],
        off: usize,
        len: usize,
    ) -> Result<Vec<u8>, BridgeError> {
        let mut dst = vec![0xAA; len];
        let n = open_range(
            &self.bdk,
            &self.bucket,
            &self.row,
            base,
            src,
            off as u64,
            &mut dst,
        )?;
        dst.truncate(n);
        Ok(dst)
    }

    /// Reads `[off, off + len)` from exactly the span `cipher_span` asks for.
    fn read_span(&self, off: usize, len: usize) -> Result<Vec<u8>, BridgeError> {
        let span = cipher_span(self.plain.len() as u64, off as u64, len as u64).unwrap();
        let src = &self.sealed.ciphertext[span.start as usize..span.end() as usize];
        self.read_from(span.start, src, off, len)
    }
}

fn is_crypto(err: &BridgeError) -> bool {
    matches!(err, BridgeError::Crypto(_))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// True if `text` shows `secret` in any common rendering.
fn leaks(text: &str, secret: &[u8]) -> bool {
    let lower = text.to_lowercase();
    let decimal = format!("{secret:?}");
    lower.contains(&hex(secret))
        || lower.contains(&hex(&secret[..8]))
        || text.contains(&decimal)
        || text.contains(decimal.trim_matches(['[', ']']))
}

/// Opens a wrap with an independent XChaCha20-Poly1305 call.
fn independent_open(key: &[u8; 32], aad: &str, wrapped: &[u8]) -> Option<Vec<u8>> {
    assert_eq!(wrapped[0], 0x01, "version byte");
    let nonce: [u8; 24] = wrapped[1..25].try_into().unwrap();
    let (ct, tag) = wrapped[25..].split_at(wrapped.len() - 25 - 16);
    let tag: [u8; 16] = tag.try_into().unwrap();
    let mut out = ct.to_vec();
    XChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            aad.as_bytes(),
            out.as_mut_slice().into(),
            &Tag::from(tag),
        )
        .ok()?;
    Some(out)
}

// ---------------------------------------------------------------------------
// Bucket data keys
// ---------------------------------------------------------------------------

#[test]
fn bdk_wrap_roundtrips_and_matches_the_documented_format() {
    let kek = kek_v1();
    let b = bucket(1);
    let key_bytes = derived("bdk plain");
    let (version, wrapped) = wrap_bdk(
        &kek,
        &b,
        &DataKey::from_bytes(key_bytes),
        &mut TestRng::new("n"),
    )
    .unwrap();
    assert_eq!(version, 1);
    assert_eq!(wrapped.as_bytes().len(), 73);
    assert_eq!(WRAPPED_KEY_LEN, 73);

    // 0x01 ‖ nonce[24] ‖ ct[32] ‖ tag[16] under AAD "velmora/bdk/v1|<bucket>|<v>".
    let aad = format!("velmora/bdk/v1|{}|1", b.as_str());
    let opened = independent_open(&derived("kek v1"), &aad, wrapped.as_bytes()).unwrap();
    assert_eq!(opened, key_bytes);

    // The unwrapped key behaves as the original: it opens a file-key wrap
    // made under the original.
    let unwrapped = unwrap_bdk(&kek, 1, &b, wrapped.as_bytes()).unwrap();
    let fk = FileKey::from_bytes(derived("fk"));
    let w = wrap_file_key(
        &DataKey::from_bytes(key_bytes),
        &b,
        &extent(1),
        &fk,
        &mut TestRng::new("m"),
    )
    .unwrap();
    let back = unwrap_file_key(&unwrapped, &b, &extent(1), w.as_bytes()).unwrap();
    assert_eq!(back.expose_secret(), fk.expose_secret());
}

#[test]
fn bdk_wrong_kek_rejected() {
    let b = bucket(1);
    let (_, wrapped) = wrap_bdk(&kek_v1(), &b, &bdk("k"), &mut TestRng::new("n")).unwrap();
    let other = TestKek::with_versions(1, &[(1, derived("another kek"))]);
    let err = unwrap_bdk(&other, 1, &b, wrapped.as_bytes()).unwrap_err();
    assert!(is_crypto(&err));
}

#[test]
fn bdk_wrong_bucket_rejected() {
    let kek = kek_v1();
    let (_, wrapped) = wrap_bdk(&kek, &bucket(1), &bdk("k"), &mut TestRng::new("n")).unwrap();
    assert!(unwrap_bdk(&kek, 1, &bucket(2), wrapped.as_bytes()).is_err());
}

#[test]
fn bdk_kek_version_is_bound_into_the_aad() {
    // The same key bytes under two version numbers: a wrap made as v1 must
    // not open when the row claims v2.
    let same = derived("kek v1");
    let ring = TestKek::with_versions(1, &[(1, same), (2, same)]);
    let b = bucket(1);
    let (v, wrapped) = wrap_bdk(&ring, &b, &bdk("k"), &mut TestRng::new("n")).unwrap();
    assert_eq!(v, 1);
    assert!(unwrap_bdk(&ring, 1, &b, wrapped.as_bytes()).is_ok());
    assert!(unwrap_bdk(&ring, 2, &b, wrapped.as_bytes()).is_err());
}

#[test]
fn unwrap_with_non_active_kek_version_works() {
    let b = bucket(1);
    let key_bytes = derived("bdk plain");
    let old = kek_v1();
    let (v_old, wrapped_old) = wrap_bdk(
        &old,
        &b,
        &DataKey::from_bytes(key_bytes),
        &mut TestRng::new("n"),
    )
    .unwrap();
    let (_, secret_old) = wrap_secret(&old, "AKIDEXAMPLE", b"s3-secret", &mut TestRng::new("s"))
        .expect("wrap secret");

    // After a rotation v2 is active; v1 rows still open, new wraps use v2.
    let ring = TestKek::with_versions(2, &[(1, derived("kek v1")), (2, derived("kek v2"))]);
    assert_eq!(ring.active().0, 2);
    let reopened = unwrap_bdk(&ring, v_old, &b, wrapped_old.as_bytes()).unwrap();
    let (v_new, rewrapped) = wrap_bdk(&ring, &b, &reopened, &mut TestRng::new("o")).unwrap();
    assert_eq!(v_new, 2);
    let aad = format!("velmora/bdk/v1|{}|2", b.as_str());
    assert_eq!(
        independent_open(&derived("kek v2"), &aad, rewrapped.as_bytes()).unwrap(),
        key_bytes
    );
    assert_eq!(
        &unwrap_secret(&ring, 1, "AKIDEXAMPLE", &secret_old).unwrap()[..],
        b"s3-secret"
    );

    // A version the ring does not hold fails closed.
    let err = unwrap_bdk(&ring, 3, &b, wrapped_old.as_bytes()).unwrap_err();
    assert!(is_crypto(&err));
    assert!(unwrap_secret(&ring, 3, "AKIDEXAMPLE", &secret_old).is_err());
}

// ---------------------------------------------------------------------------
// File keys
// ---------------------------------------------------------------------------

#[test]
fn file_key_wrap_roundtrips_and_matches_the_documented_format() {
    let k = bdk("bdk");
    let fk = FileKey::from_bytes(derived("fk"));
    let (b, x) = (bucket(1), extent(1));
    let wrapped = wrap_file_key(&k, &b, &x, &fk, &mut TestRng::new("n")).unwrap();

    let aad = format!("velmora/fk/v1|{}|{}", b.as_str(), x.as_str());
    let opened = independent_open(&derived("bdk"), &aad, wrapped.as_bytes()).unwrap();
    assert_eq!(&opened[..], fk.expose_secret());

    let back = unwrap_file_key(&k, &b, &x, wrapped.as_bytes()).unwrap();
    assert_eq!(back.expose_secret(), fk.expose_secret());
}

#[test]
fn file_key_wrong_binding_rejected() {
    let k = bdk("bdk");
    let fk = FileKey::from_bytes(derived("fk"));
    let wrapped = wrap_file_key(&k, &bucket(1), &extent(1), &fk, &mut TestRng::new("n")).unwrap();
    let w = wrapped.as_bytes();

    assert!(
        unwrap_file_key(&k, &bucket(1), &extent(2), w).is_err(),
        "extent"
    );
    assert!(
        unwrap_file_key(&k, &bucket(2), &extent(1), w).is_err(),
        "bucket"
    );
    assert!(
        unwrap_file_key(&bdk("other bdk"), &bucket(1), &extent(1), w).is_err(),
        "bdk"
    );
    assert!(unwrap_file_key(&k, &bucket(1), &extent(1), w).is_ok());
}

#[test]
fn wrap_purposes_do_not_cross() {
    // One KEK, one id string used as a bucket id and as an access key id:
    // a wrap made for one purpose must not open as the other.
    let kek = kek_v1();
    let id = "b_0101010101010101";
    let b = BucketId::new(id);
    let key_bytes = derived("material");

    let (_, as_bdk) = wrap_bdk(
        &kek,
        &b,
        &DataKey::from_bytes(key_bytes),
        &mut TestRng::new("n"),
    )
    .unwrap();
    assert!(unwrap_secret(&kek, 1, id, as_bdk.as_bytes()).is_err());

    let (_, as_secret) = wrap_secret(&kek, id, &key_bytes, &mut TestRng::new("n")).unwrap();
    assert_eq!(as_secret.len(), WRAPPED_KEY_LEN);
    assert!(unwrap_bdk(&kek, 1, &b, &as_secret).is_err());

    // A file-key wrap under a BDK whose bytes equal the KEK still does not
    // open as a BDK wrap.
    let shared = DataKey::from_bytes(derived("kek v1"));
    let fk = FileKey::from_bytes(key_bytes);
    let as_fk = wrap_file_key(&shared, &b, &extent(1), &fk, &mut TestRng::new("n")).unwrap();
    assert!(unwrap_bdk(&kek, 1, &b, as_fk.as_bytes()).is_err());
}

#[test]
fn ids_that_would_make_the_aad_ambiguous_are_refused() {
    let kek = kek_v1();
    let k = bdk("bdk");
    let fk = FileKey::from_bytes(derived("fk"));
    let rng = &mut TestRng::new("n");

    // ("a|b", "c") and ("a", "b|c") would encode to one AAD.
    for (b, x) in [("a|b", "c"), ("a", "b|c"), ("", "c"), ("a", "")] {
        let (b, x) = (BucketId::new(b), ExtentId::new(x));
        assert!(wrap_file_key(&k, &b, &x, &fk, rng).is_err());
        assert!(unwrap_file_key(&k, &b, &x, &[0x01; WRAPPED_KEY_LEN]).is_err());
        assert!(seal_extent(&k, &b, &x, b"data", rng).is_err());
    }
    assert!(wrap_bdk(&kek, &BucketId::new("a|1"), &k, rng).is_err());
    assert!(wrap_bdk(&kek, &BucketId::new(""), &k, rng).is_err());
    assert!(wrap_secret(&kek, "AK|1", b"secret", rng).is_err());
    assert!(wrap_secret(&kek, "", b"secret", rng).is_err());
}

// ---------------------------------------------------------------------------
// Tampered wraps
// ---------------------------------------------------------------------------

#[test]
fn tampered_wrapped_key_rejected() {
    let kek = kek_v1();
    let b = bucket(1);
    let (_, wrapped) = wrap_bdk(&kek, &b, &bdk("k"), &mut TestRng::new("n")).unwrap();
    let good = wrapped.to_vec();
    assert!(unwrap_bdk(&kek, 1, &b, &good).is_ok());

    // Every single-bit change: version byte, nonce, ciphertext and tag.
    for i in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            assert!(unwrap_bdk(&kek, 1, &b, &bad).is_err(), "byte {i} bit {bit}");
        }
    }
    // Wrong lengths.
    assert!(unwrap_bdk(&kek, 1, &b, &good[..72]).is_err());
    assert!(unwrap_bdk(&kek, 1, &b, &[]).is_err());
    let mut long = good.clone();
    long.push(0);
    assert!(unwrap_bdk(&kek, 1, &b, &long).is_err());

    // `WrappedKey::from_slice` checks the shape only.
    assert!(WrappedKey::from_slice(&good).is_ok());
    assert!(WrappedKey::from_slice(&good[..72]).is_err());
    let mut v2 = good.clone();
    v2[0] = 0x02;
    assert!(WrappedKey::from_slice(&v2).is_err());
}

#[test]
fn every_unwrap_failure_is_the_same_error() {
    let kek = kek_v1();
    let b = bucket(1);
    let (_, wrapped) = wrap_bdk(&kek, &b, &bdk("k"), &mut TestRng::new("n")).unwrap();
    let good = wrapped.to_vec();

    let mut bad_tag = good.clone();
    bad_tag[72] ^= 1;
    let mut bad_version = good.clone();
    bad_version[0] = 0x02;
    let other = TestKek::with_versions(1, &[(1, derived("another kek"))]);

    let errors = [
        unwrap_bdk(&kek, 1, &b, &bad_tag).unwrap_err(),
        unwrap_bdk(&kek, 1, &b, &bad_version).unwrap_err(),
        unwrap_bdk(&kek, 1, &b, &good[..40]).unwrap_err(),
        unwrap_bdk(&kek, 1, &bucket(2), &good).unwrap_err(),
        unwrap_bdk(&other, 1, &b, &good).unwrap_err(),
    ];
    for e in &errors {
        assert_eq!(e.to_string(), errors[0].to_string());
    }
}

#[test]
fn wraps_use_a_fresh_nonce_each_time() {
    let kek = kek_v1();
    let b = bucket(1);
    let key = bdk("k");
    let mut rng = SystemRng;
    let (_, w1) = wrap_bdk(&kek, &b, &key, &mut rng).unwrap();
    let (_, w2) = wrap_bdk(&kek, &b, &key, &mut rng).unwrap();
    assert_ne!(w1.as_bytes()[1..25], w2.as_bytes()[1..25], "nonce");
    assert_ne!(w1.as_bytes()[25..], w2.as_bytes()[25..], "ciphertext");
    assert!(unwrap_bdk(&kek, 1, &b, w1.as_bytes()).is_ok());
    assert!(unwrap_bdk(&kek, 1, &b, w2.as_bytes()).is_ok());
}

#[test]
fn failing_random_source_fails_closed() {
    let kek = kek_v1();
    let k = bdk("k");
    assert!(DataKey::generate(&mut BrokenRng).is_err());
    assert!(wrap_bdk(&kek, &bucket(1), &k, &mut BrokenRng).is_err());
    assert!(wrap_secret(&kek, "AKID", b"secret", &mut BrokenRng).is_err());
    assert!(seal_extent(&k, &bucket(1), &extent(1), b"data", &mut BrokenRng).is_err());
}

// ---------------------------------------------------------------------------
// S3 secret access keys
// ---------------------------------------------------------------------------

#[test]
fn secret_wrap_roundtrips_and_matches_the_documented_format() {
    let kek = kek_v1();
    let secret = hex(&derived("an s3 secret access key"));
    let (version, wrapped) = wrap_secret(
        &kek,
        "AKIDEXAMPLE",
        secret.as_bytes(),
        &mut TestRng::new("n"),
    )
    .unwrap();
    assert_eq!(version, 1);
    assert_eq!(wrapped.len(), secret.len() + WRAP_OVERHEAD);
    assert_eq!(WRAP_OVERHEAD, 41);

    let opened =
        independent_open(&derived("kek v1"), "velmora/ak/v1|AKIDEXAMPLE|1", &wrapped).unwrap();
    assert_eq!(opened, secret.as_bytes());
    assert_eq!(
        &unwrap_secret(&kek, 1, "AKIDEXAMPLE", &wrapped).unwrap()[..],
        secret.as_bytes()
    );
}

#[test]
fn secret_wrong_binding_or_tamper_rejected() {
    let kek = kek_v1();
    let (_, wrapped) = wrap_secret(&kek, "AKIDEXAMPLE", b"s3-secret", &mut TestRng::new("n"))
        .expect("wrap secret");

    assert!(
        unwrap_secret(&kek, 1, "AKIDOTHER", &wrapped).is_err(),
        "akid"
    );
    let other = TestKek::with_versions(1, &[(1, derived("another kek"))]);
    assert!(
        unwrap_secret(&other, 1, "AKIDEXAMPLE", &wrapped).is_err(),
        "kek"
    );
    let same = derived("kek v1");
    let ring = TestKek::with_versions(1, &[(1, same), (2, same)]);
    assert!(
        unwrap_secret(&ring, 2, "AKIDEXAMPLE", &wrapped).is_err(),
        "version"
    );

    for i in 0..wrapped.len() {
        let mut bad = wrapped.clone();
        bad[i] ^= 0x01;
        assert!(
            unwrap_secret(&kek, 1, "AKIDEXAMPLE", &bad).is_err(),
            "byte {i}"
        );
    }
    // Truncation, including down to an empty secret.
    assert!(unwrap_secret(&kek, 1, "AKIDEXAMPLE", &wrapped[..wrapped.len() - 1]).is_err());
    assert!(unwrap_secret(&kek, 1, "AKIDEXAMPLE", &wrapped[..WRAP_OVERHEAD]).is_err());
    assert!(unwrap_secret(&kek, 1, "AKIDEXAMPLE", &[]).is_err());
}

#[test]
fn secret_length_limits() {
    let kek = kek_v1();
    let rng = &mut TestRng::new("n");
    assert!(wrap_secret(&kek, "AKID", b"", rng).is_err());
    assert!(wrap_secret(&kek, "AKID", &vec![b'a'; MAX_SECRET_LEN + 1], rng).is_err());
    let (_, w) = wrap_secret(&kek, "AKID", &vec![b'a'; MAX_SECRET_LEN], rng).unwrap();
    assert_eq!(
        unwrap_secret(&kek, 1, "AKID", &w).unwrap().len(),
        MAX_SECRET_LEN
    );
}

// ---------------------------------------------------------------------------
// List-token MAC key
// ---------------------------------------------------------------------------

#[test]
fn list_token_key_is_derived_per_kek() {
    let k1 = KekBytes::new(derived("kek v1"));
    let k2 = KekBytes::new(derived("kek v2"));
    let token = b"after=photos/2024/|scope=b_01";

    let tag = list_token_key(&k1).mac(token);
    assert_eq!(tag, list_token_key(&k1).mac(token), "deterministic");
    assert_ne!(tag, list_token_key(&k2).mac(token), "per KEK");
    assert_ne!(tag[..], derived("kek v1")[..]);

    let key = list_token_key(&k1);
    assert!(key.verify(token, &tag));
    assert!(!key.verify(b"after=photos/2025/|scope=b_01", &tag));
    assert!(!key.verify(token, &tag[..31]));
    let mut bad = tag;
    bad[0] ^= 1;
    assert!(!key.verify(token, &bad));
    assert!(!list_token_key(&k2).verify(token, &tag));
}

// ---------------------------------------------------------------------------
// Sealing and opening extents
// ---------------------------------------------------------------------------

#[test]
fn profile_is_the_bridge_context_random_only() {
    let p = profile();
    assert_eq!(p.ctx().as_str(), "velmora-s3/media");
    assert!(p.allows(media::KeyMode::Random));
    assert!(!p.allows(media::KeyMode::VaultConvergent));
    assert!(!p.allows(media::KeyMode::PublicConvergent));
}

fn check_size(len: usize) {
    let f = fixture(len);
    let ct = &f.sealed.ciphertext;

    assert_eq!(
        ct.len() as u64,
        media::ciphertext_size(len as u64).unwrap(),
        "cipher size"
    );
    assert_eq!(&ct[..HEADER], &f.sealed.media_header[..], "header first");
    assert_eq!(f.sealed.plain_md5, md5::compute(&f.plain).0);
    assert_eq!(f.sealed.plain_sha256[..], Sha256::digest(&f.plain)[..]);
    assert_eq!(f.sealed.cipher_sha256[..], Sha256::digest(ct)[..]);

    // The engine's full verification accepts the stream and agrees on the
    // plaintext digest.
    let fk = unwrap_file_key(
        &f.bdk,
        &f.bucket,
        &f.row.id,
        f.sealed.wrapped_file_key.as_bytes(),
    )
    .unwrap();
    let header = media::Header::from_bytes(&f.sealed.media_header);
    let verified =
        media::VerifiedHeader::verify(&profile(), media::KeyMode::Random, &fk, &header).unwrap();
    let digest = verified
        .reader(len as u64)
        .unwrap()
        .verify_all(ct.as_slice())
        .unwrap();
    assert_eq!(digest, f.sealed.plain_sha256);

    // Whole read, with a destination larger than the plaintext.
    assert_eq!(f.read(0, len + 10).unwrap(), f.plain);
    // Reading at the end returns nothing; past the end is an error.
    assert_eq!(f.read(len, 16).unwrap(), Vec::<u8>::new());
    assert!(f.read(len + 1, 16).is_err());
    assert_eq!(f.read(0, 0).unwrap(), Vec::<u8>::new());

    if len > 0 {
        assert_eq!(f.read(len - 1, 1).unwrap(), f.plain[len - 1..]);
        assert_eq!(f.read_span(0, len).unwrap(), f.plain);
        assert_eq!(f.read_span(len - 1, 100).unwrap(), f.plain[len - 1..]);
        // The plaintext does not appear in the ciphertext.
        if len >= 16 {
            assert!(!ct.windows(16).any(|w| w == &f.plain[..16]));
        }
    }
}

#[test]
fn empty_object() {
    check_size(0);
    let f = fixture(0);
    // Header plus one empty final chunk (tag only).
    assert_eq!(f.sealed.ciphertext.len(), HEADER + 16);
    assert_eq!(cipher_span(0, 0, 1), None);
    // The empty stream is still authenticated: a changed tag is caught by a
    // full verification even though no plaintext byte exists to read.
    let fk = unwrap_file_key(
        &f.bdk,
        &f.bucket,
        &f.row.id,
        f.sealed.wrapped_file_key.as_bytes(),
    )
    .unwrap();
    let header = media::Header::from_bytes(&f.sealed.media_header);
    let verified =
        media::VerifiedHeader::verify(&profile(), media::KeyMode::Random, &fk, &header).unwrap();
    let mut bad = f.sealed.ciphertext.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(verified
        .reader(0)
        .unwrap()
        .verify_all(bad.as_slice())
        .is_err());
}

#[test]
fn size_1_byte() {
    check_size(1);
}

#[test]
fn size_64_kib() {
    check_size(CHUNK);
    // Exactly one full chunk, flagged final: no empty trailing chunk.
    assert_eq!(
        fixture(CHUNK).sealed.ciphertext.len(),
        HEADER + SEALED_CHUNK
    );
}

#[test]
fn size_64_kib_plus_1() {
    check_size(CHUNK + 1);
    assert_eq!(
        fixture(CHUNK + 1).sealed.ciphertext.len(),
        HEADER + SEALED_CHUNK + 1 + 16
    );
}

#[test]
fn size_16_mib() {
    check_size(16 * MIB);
}

#[test]
fn open_range_equals_plaintext_slice_across_chunk_boundaries() {
    let len = 5 * CHUNK + 1234;
    let f = fixture(len);
    let cases = [
        (0, 1),
        (0, CHUNK),
        (CHUNK - 1, 2),
        (CHUNK - 1, 1),
        (CHUNK, 1),
        (CHUNK, CHUNK),
        (CHUNK + 7, 3 * CHUNK),
        (2 * CHUNK - 100, 2 * CHUNK + 200),
        (5 * CHUNK - 1, 2),
        (5 * CHUNK, 1234),
        (5 * CHUNK + 1233, 1),
        (17, len - 17),
    ];
    for (off, n) in cases {
        let want = &f.plain[off..off + n];
        assert_eq!(f.read(off, n).unwrap(), want, "whole source {off}+{n}");
        assert_eq!(f.read_span(off, n).unwrap(), want, "exact span {off}+{n}");
    }
    // Clamped at the end of the plaintext.
    assert_eq!(f.read_span(len - 10, 500).unwrap(), f.plain[len - 10..]);
}

#[test]
fn open_range_across_article_boundaries() {
    // Three articles' worth of chunks plus a short tail.
    let len = 3 * ARTICLE_CHUNKS * CHUNK + 4321;
    let f = fixture(len);
    let ct = &f.sealed.ciphertext;
    let article_start = |k: usize| {
        if k == 0 {
            0
        } else {
            HEADER + k * ARTICLE_CHUNKS * SEALED_CHUNK
        }
    };
    assert_eq!(article_start(1), 721_120);

    // A range straddling the article 0 / article 1 boundary, read from the
    // exact span and from the two whole articles.
    let boundary = ARTICLE_CHUNKS * CHUNK;
    let (off, n) = (boundary - 300, 600);
    assert_eq!(f.read_span(off, n).unwrap(), f.plain[off..off + n]);
    let two_articles = &ct[..article_start(2)];
    assert_eq!(
        f.read_from(0, two_articles, off, n).unwrap(),
        f.plain[off..off + n]
    );

    // A range inside article 1 only, from a source that holds only article
    // 1 (no header in the fetched bytes).
    let a1 = &ct[article_start(1)..article_start(2)];
    let (off, n) = (boundary + 5, 3 * CHUNK);
    assert_eq!(
        f.read_from(article_start(1) as u64, a1, off, n).unwrap(),
        f.plain[off..off + n]
    );

    // Articles 1..=3 (to the end), a range across two article boundaries.
    let tail = &ct[article_start(1)..];
    let (off, n) = (2 * boundary - 10, ARTICLE_CHUNKS * CHUNK + 4321 + 10 - 1);
    assert_eq!(
        f.read_from(article_start(1) as u64, tail, off, n).unwrap(),
        f.plain[off..off + n]
    );
    let (off, n) = (2 * boundary - 10, len - (2 * boundary - 10));
    assert_eq!(
        f.read_from(article_start(1) as u64, tail, off, n).unwrap(),
        f.plain[off..]
    );

    // A range that needs article 0 cannot be served from article 1 alone.
    assert!(f
        .read_from(article_start(1) as u64, a1, boundary - 1, 2)
        .is_err());
    // Nor one that runs past the fetched bytes.
    assert!(f
        .read_from(article_start(1) as u64, a1, 2 * boundary - 1, 2)
        .is_err());
}

#[test]
fn cipher_span_covers_whole_chunks_and_clamps() {
    let p = (2 * CHUNK + 10) as u64;
    let total = media::ciphertext_size(p).unwrap();
    let c = CIPHER_CHUNK_SIZE;

    let s = cipher_span(p, 0, 1).unwrap();
    assert_eq!((s.start, s.len), (HEADER_SIZE, c));
    let s = cipher_span(p, PLAIN_CHUNK_SIZE - 1, 2).unwrap();
    assert_eq!((s.start, s.len), (HEADER_SIZE, 2 * c));
    let s = cipher_span(p, 2 * PLAIN_CHUNK_SIZE, 10).unwrap();
    assert_eq!((s.start, s.end()), (HEADER_SIZE + 2 * c, total));
    assert_eq!(s.len, 10 + 16);
    let s = cipher_span(p, 0, u64::MAX).unwrap();
    assert_eq!((s.start, s.end()), (HEADER_SIZE, total));

    assert_eq!(cipher_span(p, p, 1), None);
    assert_eq!(cipher_span(p, 0, 0), None);
    assert_eq!(cipher_span(p, p + 5, 1), None);
}

#[test]
fn offset_buf_reads_only_inside_its_span() {
    let bytes = [10u8, 11, 12, 13];
    let src = OffsetBuf {
        base: 100,
        bytes: &bytes,
    };
    let mut buf = [0u8; 8];
    assert_eq!(src.read_at(&mut buf, 100).unwrap(), 4);
    assert_eq!(&buf[..4], &bytes);
    assert_eq!(src.read_at(&mut buf[..2], 102).unwrap(), 2);
    assert_eq!(&buf[..2], &[12, 13]);
    assert_eq!(src.read_at(&mut buf, 104).unwrap(), 0, "end of source");
    assert_eq!(src.read_at(&mut buf, u64::MAX).unwrap(), 0);
    assert!(src.read_at(&mut buf, 99).is_err(), "before the span");
    assert!(src.read_at(&mut buf, 0).is_err());
}

// ---------------------------------------------------------------------------
// Tamper, truncation, reordering, splicing
// ---------------------------------------------------------------------------

#[test]
fn tampered_ciphertext_rejected() {
    let len = 3 * CHUNK + 500;
    let f = fixture(len);
    let good = &f.sealed.ciphertext;

    // One changed bit in chunk 1 (body, then tag).
    for pos in [HEADER + SEALED_CHUNK + 5, HEADER + 2 * SEALED_CHUNK - 1] {
        let mut bad = good.clone();
        bad[pos] ^= 0x01;
        // Reads that touch chunk 1 fail and release nothing.
        let mut dst = vec![0xAA; len];
        let err = open_range(&f.bdk, &f.bucket, &f.row, 0, &bad, 0, &mut dst).unwrap_err();
        assert!(is_crypto(&err));
        assert!(dst.iter().all(|b| *b == 0), "no bytes released on failure");
        assert!(f.read_from(0, &bad, CHUNK + 10, 10).is_err());
        // Reads that touch only intact chunks still succeed.
        assert_eq!(f.read_from(0, &bad, 0, CHUNK).unwrap(), f.plain[..CHUNK]);
        assert_eq!(
            f.read_from(0, &bad, 2 * CHUNK, CHUNK + 500).unwrap(),
            f.plain[2 * CHUNK..]
        );
    }
}

#[test]
fn tampered_header_rejected() {
    let f = fixture(CHUNK + 10);

    // The catalogued header: every byte (nonce and commitment).
    for i in 0..HEADER {
        let mut bad = f.row.clone();
        bad.media_header[i] ^= 0x01;
        let mut dst = vec![0u8; 10];
        assert!(
            open_range(
                &f.bdk,
                &f.bucket,
                &bad,
                0,
                &f.sealed.ciphertext,
                0,
                &mut dst
            )
            .is_err(),
            "record header byte {i}"
        );
    }
    // A header of the wrong length.
    let mut short = f.row.clone();
    short.media_header.pop();
    let mut dst = vec![0u8; 10];
    assert!(open_range(
        &f.bdk,
        &f.bucket,
        &short,
        0,
        &f.sealed.ciphertext,
        0,
        &mut dst
    )
    .is_err());

    // The header as fetched (first 48 ciphertext bytes) must equal the
    // record, even though no chunk depends on those bytes.
    for i in [0, 15, 16, 47] {
        let mut bad = f.sealed.ciphertext.clone();
        bad[i] ^= 0x01;
        assert!(f.read_from(0, &bad, 0, 10).is_err(), "wire header byte {i}");
    }
    // Also when the fetched bytes start inside the header.
    let mut bad = f.sealed.ciphertext.clone();
    bad[40] ^= 0x01;
    assert!(f.read_from(20, &bad[20..], 0, 10).is_err());
    assert_eq!(
        f.read_from(20, &f.sealed.ciphertext[20..], 0, 10).unwrap(),
        f.plain[..10]
    );
}

#[test]
fn tampered_wrapped_file_key_rejected() {
    let f = fixture(100);
    for i in 0..WRAPPED_KEY_LEN {
        let mut bad = f.row.clone();
        bad.wrapped_file_key.as_mut().unwrap()[i] ^= 0x01;
        let mut dst = vec![0u8; 100];
        assert!(
            open_range(
                &f.bdk,
                &f.bucket,
                &bad,
                0,
                &f.sealed.ciphertext,
                0,
                &mut dst
            )
            .is_err(),
            "wrapped key byte {i}"
        );
    }
}

#[test]
fn wrong_bucket_or_extent_binding_rejected() {
    let f = fixture(1000);
    let ct = &f.sealed.ciphertext;
    let mut dst = vec![0u8; 1000];

    // The row is presented under another (authorized) bucket.
    assert!(open_range(&f.bdk, &bucket(2), &f.row, 0, ct, 0, &mut dst).is_err());
    // The row itself is rewritten to that bucket.
    let mut moved = f.row.clone();
    moved.bucket_id = bucket(2);
    assert!(open_range(&f.bdk, &bucket(2), &moved, 0, ct, 0, &mut dst).is_err());
    // The row is renamed to another extent id.
    let mut renamed = f.row.clone();
    renamed.id = extent(2);
    assert!(open_range(&f.bdk, &f.bucket, &renamed, 0, ct, 0, &mut dst).is_err());
    // Another bucket's data key.
    assert!(open_range(&bdk("other bdk"), &f.bucket, &f.row, 0, ct, 0, &mut dst).is_err());
    // Unchanged, it opens.
    assert_eq!(
        open_range(&f.bdk, &f.bucket, &f.row, 0, ct, 0, &mut dst).unwrap(),
        1000
    );
}

#[test]
fn cross_extent_splice_rejected() {
    // Two extents of one bucket, same size, same data key.
    let k = bdk("bdk");
    let b = bucket(1);
    let len = 2 * CHUNK;
    let (xa, xb) = (extent(1), extent(2));
    let pa = pattern(len);
    let pb: Vec<u8> = pa.iter().map(|v| v ^ 0x5a).collect();
    let sa = seal_extent(&k, &b, &xa, &pa, &mut TestRng::new("a")).unwrap();
    let sb = seal_extent(&k, &b, &xb, &pb, &mut TestRng::new("b")).unwrap();
    let ra = row(&b, &xa, len, &sa);
    let rb = row(&b, &xb, len, &sb);
    let mut dst = vec![0u8; len];
    let mut open = |r: &ExtentRow, ct: &[u8]| open_range(&k, &b, r, 0, ct, 0, &mut dst).is_ok();

    assert!(open(&ra, &sa.ciphertext));
    assert!(open(&rb, &sb.ciphertext));

    // B's ciphertext under A's record.
    assert!(!open(&ra, &sb.ciphertext));
    // A chunk of B spliced into A's ciphertext.
    let mut spliced = sa.ciphertext.clone();
    spliced[HEADER + SEALED_CHUNK..].copy_from_slice(&sb.ciphertext[HEADER + SEALED_CHUNK..]);
    assert!(!open(&ra, &spliced));
    // B's wrapped key in A's record.
    let mut key_swapped = ra.clone();
    key_swapped.wrapped_file_key = rb.wrapped_file_key.clone();
    assert!(!open(&key_swapped, &sa.ciphertext));
    assert!(!open(&key_swapped, &sb.ciphertext));
    // B's wrapped key and header in A's record, with B's ciphertext: the
    // whole of B presented as extent A.
    let mut all_swapped = key_swapped.clone();
    all_swapped.media_header = rb.media_header.clone();
    assert!(!open(&all_swapped, &sb.ciphertext));
    // B's header only.
    let mut header_swapped = ra.clone();
    header_swapped.media_header = rb.media_header.clone();
    assert!(!open(&header_swapped, &sa.ciphertext));
}

#[test]
fn truncation_and_reordering_within_an_extent_rejected() {
    let len = 4 * CHUNK;
    let f = fixture(len);
    let ct = &f.sealed.ciphertext;
    let chunk = |i: usize| HEADER + i * SEALED_CHUNK..HEADER + (i + 1) * SEALED_CHUNK;

    // Two chunks swapped.
    let mut swapped = ct.clone();
    let (c1, c2) = (ct[chunk(1)].to_vec(), ct[chunk(2)].to_vec());
    swapped[chunk(1)].copy_from_slice(&c2);
    swapped[chunk(2)].copy_from_slice(&c1);
    assert!(f.read_from(0, &swapped, CHUNK, CHUNK).is_err());
    assert!(f.read_from(0, &swapped, 2 * CHUNK, CHUNK).is_err());

    // A chunk duplicated over its neighbour.
    let mut duplicated = ct.clone();
    duplicated[chunk(2)].copy_from_slice(&c1);
    assert!(f.read_from(0, &duplicated, 2 * CHUNK, CHUNK).is_err());

    // The stream cut short: the missing chunk cannot be read.
    let cut = &ct[..HEADER + 3 * SEALED_CHUNK];
    assert!(f.read_from(0, cut, 0, len).is_err());
    assert!(f.read_from(0, cut, 3 * CHUNK, 1).is_err());

    // Cut short *and* the record's size lowered to match: chunk 2 is now
    // claimed to be final, but it was not sealed with the final flag.
    let mut shrunk = f.row.clone();
    shrunk.plain_size = (3 * CHUNK) as u64;
    shrunk.cipher_size = cut.len() as u64;
    let mut dst = vec![0u8; len];
    assert!(open_range(&f.bdk, &f.bucket, &shrunk, 0, cut, 0, &mut dst).is_err());
    assert!(dst.iter().all(|b| *b == 0));
    // Size lowered inside the final chunk: the final chunk no longer
    // authenticates.
    let mut shorter = f.row.clone();
    shorter.plain_size = (len - 1) as u64;
    shorter.cipher_size = (ct.len() - 1) as u64;
    assert!(open_range(
        &f.bdk,
        &f.bucket,
        &shorter,
        0,
        &ct[..ct.len() - 1],
        0,
        &mut dst
    )
    .is_err());
    // Size raised: the true final chunk is no longer final.
    let mut longer = f.row.clone();
    longer.plain_size = (len + 1) as u64;
    longer.cipher_size = (ct.len() + 1 + 16) as u64;
    let mut padded = ct.clone();
    padded.extend_from_slice(&[0u8; 17]);
    assert!(open_range(&f.bdk, &f.bucket, &longer, 0, &padded, 0, &mut dst).is_err());
}

#[test]
fn inconsistent_extent_records_rejected() {
    let f = fixture(1000);
    let ct = &f.sealed.ciphertext;
    let mut dst = vec![0u8; 1000];

    // Shredded key.
    let mut shredded = f.row.clone();
    shredded.wrapped_file_key = None;
    let err = open_range(&f.bdk, &f.bucket, &shredded, 0, ct, 0, &mut dst).unwrap_err();
    assert!(is_crypto(&err));

    // Key modes other than random are refused, known or not.
    for mode in [0u8, 2, 3, 0xff] {
        let mut bad = f.row.clone();
        bad.key_mode = mode;
        assert!(
            open_range(&f.bdk, &f.bucket, &bad, 0, ct, 0, &mut dst).is_err(),
            "mode {mode}"
        );
    }

    // Sizes that disagree with each other.
    let mut bad = f.row.clone();
    bad.cipher_size += 1;
    assert!(open_range(&f.bdk, &f.bucket, &bad, 0, ct, 0, &mut dst).is_err());
}

#[test]
fn sealing_twice_never_reuses_a_key_or_nonce() {
    let k = bdk("bdk");
    let b = bucket(1);
    let plain = pattern(CHUNK + 5);
    let mut rng = SystemRng;

    // The same plaintext, even under the same extent id.
    let s1 = seal_extent(&k, &b, &extent(1), &plain, &mut rng).unwrap();
    let s2 = seal_extent(&k, &b, &extent(1), &plain, &mut rng).unwrap();

    assert_ne!(s1.media_header, s2.media_header);
    assert_ne!(s1.media_header[..16], s2.media_header[..16], "stream nonce");
    assert_ne!(s1.wrapped_file_key, s2.wrapped_file_key);
    assert_ne!(s1.cipher_sha256, s2.cipher_sha256);
    assert_eq!(s1.plain_sha256, s2.plain_sha256);
    // No sealed chunk repeats (a repeat would mean a reused key stream).
    assert_ne!(
        s1.ciphertext[HEADER..HEADER + 64],
        s2.ciphertext[HEADER..HEADER + 64]
    );

    let fk1 = unwrap_file_key(&k, &b, &extent(1), s1.wrapped_file_key.as_bytes()).unwrap();
    let fk2 = unwrap_file_key(&k, &b, &extent(1), s2.wrapped_file_key.as_bytes()).unwrap();
    assert_ne!(fk1.expose_secret(), fk2.expose_secret(), "file key");

    // Each record opens its own ciphertext only.
    let r1 = row(&b, &extent(1), plain.len(), &s1);
    let mut dst = vec![0u8; plain.len()];
    assert!(open_range(&k, &b, &r1, 0, &s1.ciphertext, 0, &mut dst).is_ok());
    assert_eq!(dst, plain);
    assert!(open_range(&k, &b, &r1, 0, &s2.ciphertext, 0, &mut dst).is_err());
}

#[test]
fn media_context_separates_products() {
    // A stream sealed under the bridge profile does not verify under
    // another product's profile, even with the right file key.
    let f = fixture(100);
    let fk = unwrap_file_key(
        &f.bdk,
        &f.bucket,
        &f.row.id,
        f.sealed.wrapped_file_key.as_bytes(),
    )
    .unwrap();
    let header = media::Header::from_bytes(&f.sealed.media_header);
    for other in [media::Profile::nntune(), media::Profile::drive()] {
        assert!(
            media::VerifiedHeader::verify(&other, media::KeyMode::Random, &fk, &header).is_err()
        );
    }
    assert!(
        media::VerifiedHeader::verify(&profile(), media::KeyMode::Random, &fk, &header).is_ok()
    );
}

// ---------------------------------------------------------------------------
// Secrets stay out of Debug and errors
// ---------------------------------------------------------------------------

#[test]
fn debug_output_contains_no_key_bytes() {
    let key_bytes = derived("debug bdk");
    let data_key = DataKey::from_bytes(key_bytes);
    let text = format!("{data_key:?} {:#?}", data_key);
    assert!(!leaks(&text, &key_bytes), "{text}");
    assert!(text.contains("redacted"));

    let kek_bytes = derived("kek v1");
    let token_key = list_token_key(&KekBytes::new(kek_bytes));
    let text = format!("{token_key:?}");
    assert!(!leaks(&text, &kek_bytes), "{text}");
    assert!(!leaks(&text, &token_key.mac(b"")), "{text}");
    assert!(text.contains("redacted"));

    let kek = kek_v1();
    let (_, wrapped) = wrap_bdk(&kek, &bucket(1), &data_key, &mut TestRng::new("n")).unwrap();
    let text = format!("{wrapped:?}");
    assert!(!leaks(&text, wrapped.as_bytes()), "{text}");
    assert!(!leaks(&text, &wrapped.as_bytes()[25..57]), "{text}");

    let f = fixture(100);
    let fk = unwrap_file_key(
        &f.bdk,
        &f.bucket,
        &f.row.id,
        f.sealed.wrapped_file_key.as_bytes(),
    )
    .unwrap();
    let text = format!("{:?} {:?}", f.sealed, f.row);
    assert!(!leaks(&text, fk.expose_secret()), "{text}");
    assert!(
        !leaks(&text, f.sealed.wrapped_file_key.as_bytes()),
        "{text}"
    );
    assert!(!leaks(&text, &f.plain[..32]), "{text}");
}

#[test]
fn errors_contain_no_key_bytes() {
    let kek = kek_v1();
    let kek_bytes = derived("kek v1");
    let key_bytes = derived("error bdk");
    let data_key = DataKey::from_bytes(key_bytes);
    let b = bucket(1);
    let (_, wrapped) = wrap_bdk(&kek, &b, &data_key, &mut TestRng::new("n")).unwrap();
    let f = fixture(CHUNK);
    let mut bad_ct = f.sealed.ciphertext.clone();
    bad_ct[HEADER + 3] ^= 1;
    let mut bad_row = f.row.clone();
    bad_row.wrapped_file_key.as_mut().unwrap()[30] ^= 1;
    let mut dst = vec![0u8; 16];

    let errors = [
        unwrap_bdk(&kek, 1, &bucket(2), wrapped.as_bytes()).unwrap_err(),
        unwrap_bdk(&kek, 9, &b, wrapped.as_bytes()).unwrap_err(),
        unwrap_secret(&kek, 1, "AKID", wrapped.as_bytes()).unwrap_err(),
        wrap_secret(&kek, "A|B", &key_bytes, &mut TestRng::new("n")).unwrap_err(),
        unwrap_file_key(&data_key, &b, &extent(1), wrapped.as_bytes()).unwrap_err(),
        open_range(&f.bdk, &f.bucket, &f.row, 0, &bad_ct, 0, &mut dst).unwrap_err(),
        open_range(&f.bdk, &f.bucket, &bad_row, 0, &bad_ct, 0, &mut dst).unwrap_err(),
        open_range(&f.bdk, &f.bucket, &f.row, 0, &bad_ct[..60], 0, &mut dst).unwrap_err(),
    ];
    for err in &errors {
        assert!(is_crypto(err), "{err:?}");
        let text = format!("{err} {err:?}");
        for secret in [
            &kek_bytes[..],
            &key_bytes[..],
            &derived("bdk fixture")[..],
            &wrapped.as_bytes()[..],
            &f.sealed.media_header[..],
        ] {
            assert!(!leaks(&text, secret), "{text}");
        }
        // Fixed strings only: no id either.
        assert!(!text.contains(b.as_str()), "{text}");
        assert!(!text.contains("AKID"), "{text}");
    }
}

// ---------------------------------------------------------------------------
// Recovery records
// ---------------------------------------------------------------------------

#[test]
fn recovery_record_opens_only_under_its_name_and_key() {
    use velmora_bridge::crypto::{open_manifest, seal_manifest};

    let old = TestKek::with_versions(1, &[(1, [0x11; 32])]);
    let rotated = TestKek::with_versions(2, &[(1, [0x11; 32]), (2, [0x22; 32])]);
    let other = TestKek::with_versions(1, &[(1, [0x33; 32])]);
    let plain = b"{\"v\":1,\"key\":\"private/name.bin\"}";

    let sealed = seal_manifest(&old, "m/g_1", plain, &mut SystemRng).unwrap();
    assert_eq!(&sealed[..4], &1u32.to_be_bytes());
    assert_eq!(&open_manifest(&old, "m/g_1", &sealed).unwrap()[..], plain);
    // A record of an older KEK version still opens after a rotation, and
    // a new one names the active version.
    assert_eq!(
        &open_manifest(&rotated, "m/g_1", &sealed).unwrap()[..],
        plain
    );
    let newer = seal_manifest(&rotated, "m/g_2", plain, &mut SystemRng).unwrap();
    assert_eq!(&newer[..4], &2u32.to_be_bytes());
    assert!(open_manifest(&old, "m/g_2", &newer).is_err());

    // Nothing of the plaintext shows, and two seals differ.
    assert!(!sealed.windows(7).any(|w| w == b"private"));
    assert_ne!(
        sealed,
        seal_manifest(&old, "m/g_1", plain, &mut SystemRng).unwrap()
    );

    let mut errors = vec![
        open_manifest(&old, "m/g_2", &sealed).unwrap_err(),
        open_manifest(&old, "m/del/g_1", &sealed).unwrap_err(),
        open_manifest(&other, "m/g_1", &sealed).unwrap_err(),
        open_manifest(&old, "m/g_1", &sealed[..3]).unwrap_err(),
        open_manifest(&old, "m/g_1", &[]).unwrap_err(),
    ];
    for at in [0, 3, 4, 5, 30, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[at] ^= 1;
        errors.push(open_manifest(&old, "m/g_1", &bad).unwrap_err());
    }
    for err in &errors {
        assert!(matches!(err, BridgeError::Crypto(_)), "{err:?}");
    }
}
