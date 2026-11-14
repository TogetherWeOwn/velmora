//! Key wrapping and extent sealing.
//!
//! # Key hierarchy
//!
//! ```text
//! KEK_v (deployment secret, 32 random bytes, version v)
//!   ├─ wraps BDK (per bucket, 32 random bytes)   AAD "velmora/bdk/v1|<bucket_id>|<v>"
//!   │    └─ wraps FileKey (per extent, random)   AAD "velmora/fk/v1|<bucket_id>|<extent_id>"
//!   ├─ wraps S3 secret access keys               AAD "velmora/ak/v1|<access_key_id>|<v>"
//!   └─ HKDF-SHA256(info "velmora/list-token/v1") → HMAC key for list tokens
//! ```
//!
//! Every wrap is `0x01 ‖ nonce[24] ‖ XChaCha20-Poly1305(plaintext) ‖ tag[16]`
//! with a fresh random nonce, so a wrapped 32-byte key is 73 bytes
//! ([`WrappedKey`]). The AAD names the purpose and the row the wrap belongs
//! to; a wrap copied to another purpose, bucket, extent, access key or KEK
//! version does not open. Ids are refused if they are empty or contain the
//! `|` separator, so two different bindings never encode to the same AAD.
//!
//! # An object is N independent `velmora.media.v1` streams
//!
//! One request body (a whole PUT, or one multipart part) is an *extent*.
//! [`seal_extent`] seals each extent as its own complete `media.v1` stream
//! under its own freshly generated [`FileKey`]; an object is the ordered
//! list of its extents in the catalogue. The object as a whole is **not**
//! one `media.v1` stream and never claims to be. Why this composition is
//! sound:
//!
//! 1. **No key or nonce reuse.** Each extent draws a fresh 32-byte file key
//!    and a fresh 16-byte stream nonce; the payload key is
//!    `HKDF(file key, nonce)`. Chunk nonces are a counter plus a final-chunk
//!    flag under that one-use payload key. [`seal_extent`] builds the
//!    sealer, consumes it and drops it in one call, so a sealer is never
//!    resumed, shared or rewound, and re-sealing the same plaintext (a
//!    client retry) yields an unrelated key and ciphertext. Wraps use
//!    random 192-bit nonces, far below any collision bound for the number
//!    of keys a deployment can hold.
//! 2. **Truncation and reordering inside an extent** are caught by the
//!    stream itself: every chunk's nonce carries its index, and only the
//!    final chunk carries the final flag. The reader derives the chunk
//!    count from the catalogued plaintext size, so a dropped, duplicated,
//!    swapped or cut-short chunk fails authentication, and so does a
//!    changed plaintext size once the final chunk is read.
//! 3. **Substitution across extents** is caught by the key binding. The
//!    file key is wrapped under the bucket key with the bucket id and the
//!    extent id as AAD, and the 48-byte header commits to the file key. An
//!    extent's ciphertext therefore opens only with the header and wrapped
//!    key recorded under that same extent id in that same bucket; bytes or
//!    key material moved to another extent id or bucket are rejected
//!    ([`open_range`] also refuses a row whose bucket differs from the
//!    authorized one).
//! 4. **Order and completeness across extents** come from the catalogue:
//!    the extent list, each extent's sequence number, plaintext offset and
//!    plaintext size. Nothing in the ciphertext says which object an extent
//!    belongs to or where.
//!
//! ## What this does *not* protect (flagged for review)
//!
//! - **The catalogue is trusted for object assembly.** Point 4 is integrity
//!   by database, not by cryptography. Someone who can write catalogue rows
//!   can, without any key, reorder an object's extents, drop trailing
//!   extents, attach an extent to a different object *of the same bucket*,
//!   or roll an object back to an older generation, and every chunk will
//!   still authenticate. The wrap AAD does not cover generation, sequence
//!   number, offset or size. The plaintext digests recorded per object
//!   detect this only if a reader recomputes them. Binding
//!   `(generation, seq, plain_offset, plain_size)` needs an authenticated
//!   per-generation manifest; it cannot go into the file-key AAD because a
//!   multipart part is sealed before its generation exists.
//! - **Extent ids must never be reused.** The AAD binds an id, not a
//!   version of it. If one extent id were ever given to two seals in the
//!   same bucket, either full record (header, wrapped key, ciphertext)
//!   would be accepted for it.
//! - **A ranged read authenticates only the chunks it touches.** A wrong
//!   catalogued plaintext size is detected when the final chunk is read,
//!   not before.
//! - **Plaintext digests are stored in the clear.** The MD5 and SHA-256 of
//!   each extent's plaintext sit in the catalogue next to the ciphertext
//!   metadata; anyone who can read the catalogue can confirm a guess of the
//!   content without any key.
//! - **The KEK is used both as an XChaCha20-Poly1305 key and as HKDF input
//!   keying material.** The two uses are domain-separated by construction
//!   and no interaction is known, but a stricter design would derive every
//!   working key from the KEK through HKDF.
//! - **Secret lengths are visible.** A wrapped access-key secret is 41
//!   bytes longer than the secret.

use core::fmt;
use std::io;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use velmora::media::{
    self, FileKey, Header, KeyMode, Profile, ReadAt, Sealer, VerifiedHeader, CIPHER_CHUNK_SIZE,
    HEADER_SIZE, PLAIN_CHUNK_SIZE,
};
use velmora::rng::FillRandom;
use zeroize::{Zeroize, Zeroizing};

use crate::ports::Kek;
use crate::types::{BridgeError, BucketId, ByteSpan, ExtentId, ExtentRow, KekBytes, Result};

/// Context of the bridge's media profile. Distinct from every other
/// product's context, so ciphertexts cannot be confused across products.
pub const MEDIA_CTX: &str = "velmora-s3/media";

/// Version byte that starts every wrap.
pub const WRAP_VERSION: u8 = 0x01;
/// Wrap nonce length (XChaCha20-Poly1305).
pub const WRAP_NONCE_LEN: usize = 24;
/// Wrap tag length (Poly1305).
pub const WRAP_TAG_LEN: usize = 16;
/// Bytes a wrap adds to its plaintext: version, nonce and tag.
pub const WRAP_OVERHEAD: usize = 1 + WRAP_NONCE_LEN + WRAP_TAG_LEN;
/// Length of every data key and file key.
pub const KEY_LEN: usize = 32;
/// Length of a wrapped 32-byte key: `0x01 ‖ nonce[24] ‖ ct[32] ‖ tag[16]`.
pub const WRAPPED_KEY_LEN: usize = KEY_LEN + WRAP_OVERHEAD;
/// Longest S3 secret access key [`wrap_secret`] accepts.
pub const MAX_SECRET_LEN: usize = 1024;

const BDK_DOMAIN: &str = "velmora/bdk/v1";
const FILE_KEY_DOMAIN: &str = "velmora/fk/v1";
const ACCESS_KEY_DOMAIN: &str = "velmora/ak/v1";
const LIST_TOKEN_INFO: &[u8] = b"velmora/list-token/v1";
const MANIFEST_DOMAIN: &str = "velmora/manifest/v1";
/// A sealed recovery record starts with the KEK version, big-endian.
const MANIFEST_VERSION_LEN: usize = 4;
const AAD_SEPARATOR: char = '|';

// Every error below is a fixed string: no key, nonce, id or ciphertext byte
// ever reaches an error value.
const ERR_UNWRAP: BridgeError = BridgeError::Crypto("key unwrap failed");
const ERR_WRAP: BridgeError = BridgeError::Crypto("key wrap failed");
const ERR_RNG: BridgeError = BridgeError::Crypto("random source failed");
const ERR_BINDING: BridgeError = BridgeError::Crypto("invalid key binding id");
const ERR_KEK_VERSION: BridgeError = BridgeError::Crypto("kek version unavailable");
const ERR_SECRET_LEN: BridgeError = BridgeError::Crypto("secret length out of range");
const ERR_SEAL: BridgeError = BridgeError::Crypto("extent seal failed");
const ERR_EXTENT_RECORD: BridgeError = BridgeError::Crypto("extent record invalid");
const ERR_EXTENT_BUCKET: BridgeError = BridgeError::Crypto("extent belongs to another bucket");
const ERR_SHREDDED: BridgeError = BridgeError::Crypto("extent key shredded");
const ERR_SPAN: BridgeError = BridgeError::Crypto("ciphertext span does not cover the range");
const ERR_AUTH: BridgeError = BridgeError::Crypto("extent authentication failed");
const ERR_MANIFEST: BridgeError = BridgeError::Crypto("recovery record authentication failed");

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// A bucket data key (BDK): 32 random bytes that wrap the file keys of one
/// bucket. Zeroed on drop; never rendered by `Debug`; the bytes cannot be
/// read from outside this module.
pub struct DataKey(Zeroizing<[u8; KEY_LEN]>);

impl DataKey {
    /// Wraps existing key bytes (tests, recovery tooling). The caller's
    /// copy is its own to wipe.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        DataKey(Zeroizing::new(bytes))
    }

    /// A fresh random key.
    pub fn generate<R: FillRandom>(rng: &mut R) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        rng.fill_bytes(key.as_mut()).map_err(|_| ERR_RNG)?;
        Ok(DataKey(key))
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

/// A wrapped 32-byte key: `0x01 ‖ nonce[24] ‖ ct[32] ‖ tag[16]`, 73 bytes.
/// Not secret (it opens only under the wrapping key and the right
/// binding), but `Debug` still hides it so it stays out of logs.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedKey([u8; WRAPPED_KEY_LEN]);

impl WrappedKey {
    /// Accepts exactly 73 bytes starting with the version byte. Says
    /// nothing about whether the wrap will open.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes = <[u8; WRAPPED_KEY_LEN]>::try_from(bytes).map_err(|_| ERR_UNWRAP)?;
        if bytes[0] != WRAP_VERSION {
            return Err(ERR_UNWRAP);
        }
        Ok(WrappedKey(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; WRAPPED_KEY_LEN] {
        &self.0
    }

    /// The bytes to store in a catalogue column.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl AsRef<[u8]> for WrappedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrappedKey(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// AAD
// ---------------------------------------------------------------------------

fn binding_id(id: &str) -> Result<&str> {
    if id.is_empty() || id.contains(AAD_SEPARATOR) {
        return Err(ERR_BINDING);
    }
    Ok(id)
}

fn bdk_aad(bucket: &BucketId, kek_version: u32) -> Result<String> {
    Ok(format!(
        "{BDK_DOMAIN}|{}|{kek_version}",
        binding_id(bucket.as_str())?
    ))
}

fn file_key_aad(bucket: &BucketId, extent: &ExtentId) -> Result<String> {
    Ok(format!(
        "{FILE_KEY_DOMAIN}|{}|{}",
        binding_id(bucket.as_str())?,
        binding_id(extent.as_str())?
    ))
}

fn access_key_aad(access_key_id: &str, kek_version: u32) -> Result<String> {
    Ok(format!(
        "{ACCESS_KEY_DOMAIN}|{}|{kek_version}",
        binding_id(access_key_id)?
    ))
}

// ---------------------------------------------------------------------------
// Wrap primitive
// ---------------------------------------------------------------------------

fn wrap_cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    // The cipher wipes its key copy on drop (`zeroize` feature).
    XChaCha20Poly1305::new_from_slice(key).expect("XChaCha20-Poly1305 takes a 32-byte key")
}

/// `0x01 ‖ nonce ‖ ct ‖ tag` over `plaintext` with a fresh random nonce.
fn wrap_bytes<R: FillRandom>(
    key: &[u8; KEY_LEN],
    aad: &str,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    rng.fill_bytes(&mut nonce).map_err(|_| ERR_RNG)?;

    // Holds plaintext until encryption has run, so it is wiped on failure.
    let mut out = Zeroizing::new(Vec::with_capacity(plaintext.len() + WRAP_OVERHEAD));
    out.push(WRAP_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let body = &mut out[1 + WRAP_NONCE_LEN..];
    let tag = wrap_cipher(key)
        .encrypt_inout_detached(&XNonce::from(nonce), aad.as_bytes(), body.into())
        .map_err(|_| ERR_WRAP)?;
    out.extend_from_slice(tag.as_slice());
    // Ciphertext from here on: hand it out without the wipe.
    Ok(core::mem::take(&mut *out))
}

/// Opens a wrap. Every failure (length, version byte, key, binding, any
/// changed byte) is the same error.
fn unwrap_bytes(key: &[u8; KEY_LEN], aad: &str, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if wrapped.len() < WRAP_OVERHEAD || wrapped[0] != WRAP_VERSION {
        return Err(ERR_UNWRAP);
    }
    let (nonce, rest) = wrapped[1..].split_at(WRAP_NONCE_LEN);
    let (ct, tag) = rest.split_at(rest.len() - WRAP_TAG_LEN);
    let nonce = <[u8; WRAP_NONCE_LEN]>::try_from(nonce).map_err(|_| ERR_UNWRAP)?;
    let tag = <[u8; WRAP_TAG_LEN]>::try_from(tag).map_err(|_| ERR_UNWRAP)?;

    let mut out = Zeroizing::new(ct.to_vec());
    wrap_cipher(key)
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            aad.as_bytes(),
            out.as_mut_slice().into(),
            &Tag::from(tag),
        )
        .map_err(|_| ERR_UNWRAP)?;
    Ok(out)
}

fn wrap_key<R: FillRandom>(
    key: &[u8; KEY_LEN],
    aad: &str,
    plaintext: &[u8; KEY_LEN],
    rng: &mut R,
) -> Result<WrappedKey> {
    let wrapped = wrap_bytes(key, aad, plaintext, rng)?;
    <[u8; WRAPPED_KEY_LEN]>::try_from(wrapped.as_slice())
        .map(WrappedKey)
        .map_err(|_| ERR_WRAP)
}

fn unwrap_key(key: &[u8; KEY_LEN], aad: &str, wrapped: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(ERR_UNWRAP);
    }
    let plain = unwrap_bytes(key, aad, wrapped)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&plain);
    Ok(out)
}

fn kek_version<K: Kek>(kek: &K, version: u32) -> Result<&KekBytes> {
    kek.version(version).ok_or(ERR_KEK_VERSION)
}

// ---------------------------------------------------------------------------
// Bucket data keys
// ---------------------------------------------------------------------------

/// Wraps a bucket data key under the **active** KEK. Returns the KEK
/// version to store next to the wrap.
pub fn wrap_bdk<K: Kek, R: FillRandom>(
    kek: &K,
    bucket: &BucketId,
    bdk: &DataKey,
    rng: &mut R,
) -> Result<(u32, WrappedKey)> {
    let (version, key) = kek.active();
    let aad = bdk_aad(bucket, version)?;
    Ok((version, wrap_key(key.expose(), &aad, &bdk.0, rng)?))
}

/// Unwraps a bucket data key with the KEK version stored with it (which
/// need not be the active one).
pub fn unwrap_bdk<K: Kek>(
    kek: &K,
    kek_version_stored: u32,
    bucket: &BucketId,
    wrapped: &[u8],
) -> Result<DataKey> {
    let key = kek_version(kek, kek_version_stored)?;
    let aad = bdk_aad(bucket, kek_version_stored)?;
    unwrap_key(key.expose(), &aad, wrapped).map(DataKey)
}

// ---------------------------------------------------------------------------
// File keys
// ---------------------------------------------------------------------------

/// Wraps an extent's file key under its bucket's data key, bound to the
/// bucket id and the extent id.
pub fn wrap_file_key<R: FillRandom>(
    bdk: &DataKey,
    bucket: &BucketId,
    extent: &ExtentId,
    file_key: &FileKey,
    rng: &mut R,
) -> Result<WrappedKey> {
    let aad = file_key_aad(bucket, extent)?;
    wrap_key(&bdk.0, &aad, file_key.expose_secret(), rng)
}

/// Unwraps an extent's file key. Fails unless the wrap was made for this
/// bucket and this extent under this data key.
pub fn unwrap_file_key(
    bdk: &DataKey,
    bucket: &BucketId,
    extent: &ExtentId,
    wrapped: &[u8],
) -> Result<FileKey> {
    let aad = file_key_aad(bucket, extent)?;
    let mut key = unwrap_key(&bdk.0, &aad, wrapped)?;
    let file_key = FileKey::from_bytes(*key);
    key.zeroize();
    Ok(file_key)
}

// ---------------------------------------------------------------------------
// S3 secret access keys
// ---------------------------------------------------------------------------

/// Wraps an S3 secret access key under the **active** KEK, bound to its
/// access key id. Returns the KEK version to store next to the wrap. The
/// result is `secret.len() + 41` bytes.
pub fn wrap_secret<K: Kek, R: FillRandom>(
    kek: &K,
    access_key_id: &str,
    secret: &[u8],
    rng: &mut R,
) -> Result<(u32, Vec<u8>)> {
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(ERR_SECRET_LEN);
    }
    let (version, key) = kek.active();
    let aad = access_key_aad(access_key_id, version)?;
    Ok((version, wrap_bytes(key.expose(), &aad, secret, rng)?))
}

/// Unwraps an S3 secret access key with the KEK version stored with it.
/// The returned buffer is wiped on drop.
pub fn unwrap_secret<K: Kek>(
    kek: &K,
    kek_version_stored: u32,
    access_key_id: &str,
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if wrapped.len() <= WRAP_OVERHEAD || wrapped.len() > MAX_SECRET_LEN + WRAP_OVERHEAD {
        return Err(ERR_UNWRAP);
    }
    let key = kek_version(kek, kek_version_stored)?;
    let aad = access_key_aad(access_key_id, kek_version_stored)?;
    unwrap_bytes(key.expose(), &aad, wrapped)
}

// ---------------------------------------------------------------------------
// List-token MAC key
// ---------------------------------------------------------------------------

/// HMAC-SHA256 key for list continuation tokens, derived from one KEK
/// with HKDF-SHA256 (no salt, info `velmora/list-token/v1`). Zeroed on
/// drop; never rendered by `Debug`.
pub struct ListTokenKey(Zeroizing<[u8; KEY_LEN]>);

/// Derives the list-token MAC key from a KEK. Tokens signed under one KEK
/// version do not verify under another.
pub fn list_token_key(kek: &KekBytes) -> ListTokenKey {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, kek.expose())
        .expand(LIST_TOKEN_INFO, key.as_mut())
        .expect("HKDF-SHA256 output of 32 bytes");
    ListTokenKey(key)
}

impl ListTokenKey {
    fn mac_state(&self, message: &[u8]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&self.0[..])
            .expect("HMAC accepts a key of any length");
        mac.update(message);
        mac
    }

    /// HMAC-SHA256 tag over `message`.
    pub fn mac(&self, message: &[u8]) -> [u8; 32] {
        self.mac_state(message).finalize().into_bytes().into()
    }

    /// Constant-time check of a full 32-byte tag.
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> bool {
        tag.len() == 32 && bool::from(self.mac(message)[..].ct_eq(tag))
    }
}

impl fmt::Debug for ListTokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ListTokenKey(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Recovery records
// ---------------------------------------------------------------------------

/// The key that seals recovery records under one KEK version:
/// `HKDF-SHA256(KEK, "velmora/manifest/v1")`.
fn manifest_key(kek: &KekBytes) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, kek.expose())
        .expand(MANIFEST_DOMAIN.as_bytes(), key.as_mut())
        .expect("HKDF-SHA256 output of 32 bytes");
    key
}

fn manifest_aad(name: &str, kek_version: u32) -> Result<String> {
    Ok(format!(
        "{MANIFEST_DOMAIN}|{}|{kek_version}",
        binding_id(name)?
    ))
}

/// Seals a catalogue recovery record under the **active** KEK:
/// `kek_version (u32 BE) ‖ 0x01 ‖ nonce ‖ ct ‖ tag`. `name` is the blob
/// key the record is stored under; a record moved to another name does
/// not open.
pub fn seal_manifest<K: Kek, R: FillRandom>(
    kek: &K,
    name: &str,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (version, key) = kek.active();
    let aad = manifest_aad(name, version)?;
    let sealed = wrap_bytes(&manifest_key(key), &aad, plaintext, rng)?;
    let mut out = Vec::with_capacity(MANIFEST_VERSION_LEN + sealed.len());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a record sealed by [`seal_manifest`] under `name`. Every failure
/// (length, KEK version, name, any changed byte) is an error and returns
/// no plaintext.
pub fn open_manifest<K: Kek>(kek: &K, name: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let Some((version, body)) = sealed.split_first_chunk::<MANIFEST_VERSION_LEN>() else {
        return Err(ERR_MANIFEST);
    };
    let version = u32::from_be_bytes(*version);
    let key = kek_version(kek, version)?;
    let aad = manifest_aad(name, version)?;
    unwrap_bytes(&manifest_key(key), &aad, body).map_err(|_| ERR_MANIFEST)
}

// ---------------------------------------------------------------------------
// Extent sealing
// ---------------------------------------------------------------------------

/// The bridge's media profile: its own context, random file keys only.
pub fn profile() -> Profile {
    Profile::new(MEDIA_CTX, &[KeyMode::Random]).expect("the bridge media context is valid")
}

/// One sealed extent: everything the catalogue and the blob store need.
pub struct SealedExtent {
    /// The 48-byte stream header (also the first 48 bytes of `ciphertext`).
    pub media_header: [u8; HEADER_SIZE as usize],
    /// The complete stream: header, then every sealed chunk.
    pub ciphertext: Vec<u8>,
    pub plain_md5: [u8; 16],
    pub plain_sha256: [u8; 32],
    /// SHA-256 of `ciphertext`.
    pub cipher_sha256: [u8; 32],
    /// The extent's file key, wrapped for this bucket and extent.
    pub wrapped_file_key: WrappedKey,
}

impl fmt::Debug for SealedExtent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedExtent")
            .field("cipher_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Seals one request body as one independent media stream under a fresh
/// file key, and wraps that key for `(bucket, extent)`.
///
/// `extent` must be a newly minted id that has never been sealed before:
/// the wrap binds the id, not a version of it. The sealer lives only
/// inside this call, so no stream is ever resumed or extended.
pub fn seal_extent<R: FillRandom>(
    bdk: &DataKey,
    bucket: &BucketId,
    extent: &ExtentId,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedExtent> {
    // Refuse a bad binding before any key exists.
    file_key_aad(bucket, extent)?;

    let file_key = FileKey::generate(rng).map_err(|_| ERR_RNG)?;
    let sealer = Sealer::random(&profile(), &file_key, rng).map_err(|_| ERR_RNG)?;
    let media_header = sealer.header().to_bytes();
    let ciphertext = sealer.seal_to_vec(plaintext).map_err(|_| ERR_SEAL)?;
    let wrapped_file_key = wrap_file_key(bdk, bucket, extent, &file_key, rng)?;

    Ok(SealedExtent {
        media_header,
        plain_md5: md5::compute(plaintext).0,
        plain_sha256: Sha256::digest(plaintext).into(),
        cipher_sha256: Sha256::digest(&ciphertext).into(),
        ciphertext,
        wrapped_file_key,
    })
}

// ---------------------------------------------------------------------------
// Ranged open
// ---------------------------------------------------------------------------

/// A fetched slice of an extent's ciphertext: `bytes` holds the stream's
/// bytes `[base, base + bytes.len())`. Reads outside the slice return
/// end-of-source or an error, never bytes from another offset.
#[derive(Clone, Copy)]
pub struct OffsetBuf<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
}

impl fmt::Debug for OffsetBuf<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OffsetBuf")
            .field("base", &self.base)
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl ReadAt for OffsetBuf<'_> {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        let rel = off.checked_sub(self.base).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "offset before the fetched span",
            )
        })?;
        // Compare in u64 before narrowing: `usize` is 32 bits on wasm32.
        if rel >= self.bytes.len() as u64 {
            return Ok(0);
        }
        let rel = rel as usize;
        let n = buf.len().min(self.bytes.len() - rel);
        buf[..n].copy_from_slice(&self.bytes[rel..rel + n]);
        Ok(n)
    }
}

/// The ciphertext bytes needed to decrypt the plaintext range
/// `[plain_off, plain_off + len)` of a `plain_size`-byte extent: whole
/// sealed chunks, clamped to the stream. `None` when the range is empty or
/// starts at or past the end.
pub fn cipher_span(plain_size: u64, plain_off: u64, len: u64) -> Option<ByteSpan> {
    if len == 0 || plain_off >= plain_size {
        return None;
    }
    let end = plain_off.saturating_add(len).min(plain_size);
    let first = plain_off / PLAIN_CHUNK_SIZE;
    let last = (end - 1) / PLAIN_CHUNK_SIZE;
    let start = media::chunk_offset(first)?;
    let stop = media::chunk_offset(last)?
        .checked_add(CIPHER_CHUNK_SIZE)?
        .min(media::ciphertext_size(plain_size)?);
    Some(ByteSpan {
        start,
        len: stop - start,
    })
}

/// Decrypts the plaintext range `[plain_off, plain_off + dst.len())` of one
/// extent (clamped to its plaintext size) from a fetched ciphertext span.
///
/// - `bucket` is the bucket the request was authorized for; a row from
///   another bucket is refused.
/// - `src` holds the extent's ciphertext bytes starting at stream offset
///   `src_base` and must cover every chunk the range touches
///   ([`cipher_span`]).
/// - Returns the number of bytes written to the front of `dst`.
///
/// Only bytes whose chunk authenticated are released, and on any error
/// `dst` is zeroed. If `src` overlaps the stream header, those bytes must
/// equal the catalogued header.
pub fn open_range(
    bdk: &DataKey,
    bucket: &BucketId,
    extent: &ExtentRow,
    src_base: u64,
    src: &[u8],
    plain_off: u64,
    dst: &mut [u8],
) -> Result<usize> {
    let outcome = open_range_inner(bdk, bucket, extent, src_base, src, plain_off, dst);
    if outcome.is_err() {
        dst.zeroize();
    }
    outcome
}

fn open_range_inner(
    bdk: &DataKey,
    bucket: &BucketId,
    extent: &ExtentRow,
    src_base: u64,
    src: &[u8],
    plain_off: u64,
    dst: &mut [u8],
) -> Result<usize> {
    if extent.bucket_id != *bucket {
        return Err(ERR_EXTENT_BUCKET);
    }
    if media::ciphertext_size(extent.plain_size) != Some(extent.cipher_size) {
        return Err(ERR_EXTENT_RECORD);
    }
    let header_bytes = <[u8; HEADER_SIZE as usize]>::try_from(extent.media_header.as_slice())
        .map_err(|_| ERR_EXTENT_RECORD)?;
    let wrapped = extent.wrapped_file_key.as_deref().ok_or(ERR_SHREDDED)?;

    let file_key = unwrap_file_key(bdk, bucket, &extent.id, wrapped)?;
    let verified = VerifiedHeader::verify_record(
        &profile(),
        extent.key_mode,
        &file_key,
        &Header::from_bytes(&header_bytes),
    )
    .map_err(|_| ERR_AUTH)?;

    // Whatever part of the stream header was fetched must match the record.
    if src_base < HEADER_SIZE {
        let from = src_base as usize;
        let n = src.len().min(header_bytes.len() - from);
        if !bool::from(src[..n].ct_eq(&header_bytes[from..from + n])) {
            return Err(ERR_AUTH);
        }
    }

    let reader = verified.reader(extent.plain_size).map_err(|_| ERR_AUTH)?;
    let source = OffsetBuf {
        base: src_base,
        bytes: src,
    };
    reader
        .read_at(&source, dst, plain_off)
        .map_err(|e| match e {
            velmora::Error::Io(_) => ERR_SPAN,
            _ => ERR_AUTH,
        })
}
