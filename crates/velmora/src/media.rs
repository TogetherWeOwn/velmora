//! `velmora.media.v1`: the one encryption format every velmora product
//! writes to Usenet (media-format decision, approved 2026-11-07).
//!
//! The payload is the C2SP age v1 STREAM construction, unchanged:
//! `payload_key = HKDF-SHA256(salt = N, ikm = K, info = "payload")`,
//! ChaCha20-Poly1305 over 64 KiB chunks, chunk nonce = 11-byte big-endian
//! counter ‖ last-chunk flag. In front of it sits a 48-byte header, the
//! 16-byte nonce `N` and a 32-byte HKDF key commitment:
//!
//! ```text
//! offset 0   : N           16 bytes
//! offset 16  : commitment  32 bytes
//! offset 48  : chunk 0 … chunk L-1   (each ct ‖ 16-byte tag)
//! L = max(1, ceil(P / 65536))        P = plaintext length
//! ```
//!
//! There is no cleartext magic or version byte. Format, version, key mode
//! and product context (`ctx`) live in the trusted record (DB row or Drive
//! manifest) next to the wrapped key, and are bound into the commitment, so
//! a wrong one fails closed before any AEAD call.
//!
//! **Separation rests on the commitment check.** `payload_key` depends only
//! on `(K, N)`; mode, ctx and version separation is enforced only by the
//! commitment comparison (and the derived-`N` check in convergent modes).
//! The type system makes that comparison unskippable: chunk decryption is
//! reachable only through a [`ChunkReader`], which only a
//! [`VerifiedHeader`] can create, and [`VerifiedHeader::verify`] is the one
//! place that compares the commitment and derives the payload key.
//!
//! ```compile_fail
//! // A reader cannot be built around a header by hand: its fields are
//! // private (E0451), so `VerifiedHeader::reader` is the only constructor.
//! use velmora::media::{ChunkReader, VerifiedHeader};
//! fn forge(verified: &VerifiedHeader) -> ChunkReader<'_> {
//!     ChunkReader { verified, plaintext_size: 0 }
//! }
//! ```
//!
//! Key modes (all fixed in v1 so no later format change is needed):
//!
//! - [`KeyMode::Random`]: fresh CSPRNG `K` and `N` per file (NNTune; Drive
//!   private files without dedupe).
//! - [`KeyMode::VaultConvergent`]: `K` keyed by a client-only per-vault
//!   secret, `N` derived from `K`; dedupes within one vault only
//!   ([`ConvergentKey::vault`]).
//! - [`KeyMode::PublicConvergent`]: `K` from a server-aided OPRF output;
//!   Drive public share links only ([`ConvergentKey::public`]).

use std::io;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::rng::FillRandom;

/// Record value for this format (`media_format = 1`).
pub const FORMAT_ID: u8 = 1;
/// Version label bound into every HKDF info string of this format.
pub const FORMAT_LABEL: &str = "velmora.media.v1";

/// File nonce bytes (`N`).
pub const NONCE_SIZE: usize = 16;
/// Key commitment bytes.
pub const COMMITMENT_SIZE: usize = 32;
/// Header bytes in front of chunk 0: `N ‖ commitment`.
pub const HEADER_SIZE: u64 = (NONCE_SIZE + COMMITMENT_SIZE) as u64;
/// Plaintext bytes per STREAM chunk (all but the final chunk are full).
pub const PLAIN_CHUNK_SIZE: u64 = 64 * 1024;
/// Poly1305 tag bytes per chunk.
pub const TAG_SIZE: u64 = 16;
/// Ciphertext bytes per full chunk (`65,552`).
pub const CIPHER_CHUNK_SIZE: u64 = PLAIN_CHUNK_SIZE + TAG_SIZE;
/// File key bytes (`K`).
pub const KEY_SIZE: usize = 32;
/// RFC 9497 ristretto255-SHA512 OPRF output bytes (PublicConvergent input).
pub const OPRF_OUTPUT_SIZE: usize = 64;

/// HKDF info for the age payload key: byte-identical to age v1.
const PAYLOAD_INFO: &[u8] = b"payload";
const COMMIT_LABEL: &[u8] = b"velmora.media.v1/commit";
const CONVERGENT_NONCE_LABEL: &[u8] = b"velmora.media.v1/convergent-nonce";
const VAULT_K_LABEL: &[u8] = b"velmora.media.v1/vault-K";
const PUBLIC_K_LABEL: &[u8] = b"velmora.media.v1/public-K";

/// One generic error for every header-verification failure (wrong key,
/// mode, ctx, version, nonce or commitment): which one failed is never
/// revealed, and no key- or nonce-derived bytes are ever echoed.
fn header_rejected() -> Error {
    Error::Decrypt("media header verification failed".into())
}

fn media_error(reason: &str) -> Error {
    Error::Decrypt(format!("media: {reason}"))
}

// ---------------------------------------------------------------------------
// Key mode, context, profile
// ---------------------------------------------------------------------------

/// How the file key `K` (and, for convergent modes, the nonce `N`) is
/// derived. Stored out of band with the record as one byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyMode {
    /// Fresh CSPRNG `K` and `N` per file.
    Random = 0x01,
    /// `K = HMAC(vault_dedupe_key, …)`, `N` derived from `K`.
    VaultConvergent = 0x02,
    /// `K = HKDF(OPRF output)`, `N` derived from `K`.
    PublicConvergent = 0x03,
}

impl KeyMode {
    /// The record byte for this mode.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Parses a record byte; every value but `0x01..=0x03` is rejected.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(KeyMode::Random),
            0x02 => Ok(KeyMode::VaultConvergent),
            0x03 => Ok(KeyMode::PublicConvergent),
            _ => Err(media_error("unknown key mode")),
        }
    }

    fn is_convergent(self) -> bool {
        !matches!(self, KeyMode::Random)
    }
}

/// Product context bound into the commitment: 1–255 bytes of printable
/// ASCII (`0x21..=0x7E`). It never carries tenant, vault, object or user
/// IDs, nor any secret; per-vault secrecy lives in `K`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context(String);

impl Context {
    /// Validates a context string. Rejects empty, over-long, `0x00`,
    /// whitespace, control and non-ASCII bytes, so every HKDF info string
    /// parses one way only.
    pub fn new(ctx: &str) -> Result<Self> {
        let bytes = ctx.as_bytes();
        if bytes.is_empty() || bytes.len() > 255 || !bytes.iter().all(|b| (0x21..=0x7e).contains(b))
        {
            return Err(media_error("context must be 1-255 printable ASCII bytes"));
        }
        Ok(Context(ctx.to_owned()))
    }

    /// The context string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A product's context plus the key modes it may read and write.
#[derive(Clone, Debug)]
pub struct Profile {
    ctx: Context,
    modes: &'static [KeyMode],
}

/// NNTune media context (`nntune/media`).
pub const NNTUNE_CTX: &str = "nntune/media";
/// Cloudflare Drive media context (`drive/media`).
pub const DRIVE_CTX: &str = "drive/media";

impl Profile {
    /// A profile over `ctx` allowing exactly `modes` (must be non-empty).
    ///
    /// For tests and future products only: NNTune must use
    /// [`Profile::nntune`] and Drive [`Profile::drive`], which pin the
    /// decided ctx and mode allow-lists.
    pub fn new(ctx: &str, modes: &'static [KeyMode]) -> Result<Self> {
        if modes.is_empty() {
            return Err(media_error("profile must allow at least one key mode"));
        }
        Ok(Profile {
            ctx: Context::new(ctx)?,
            modes,
        })
    }

    /// NNTune: `nntune/media`, Random only (Drive crypto design L11: no convergent mode
    /// and no OPRF in NNTune).
    pub fn nntune() -> Self {
        Profile {
            ctx: Context(NNTUNE_CTX.to_owned()),
            modes: &[KeyMode::Random],
        }
    }

    /// Drive: `drive/media`, all three modes.
    pub fn drive() -> Self {
        Profile {
            ctx: Context(DRIVE_CTX.to_owned()),
            modes: &[
                KeyMode::Random,
                KeyMode::VaultConvergent,
                KeyMode::PublicConvergent,
            ],
        }
    }

    /// The bound context.
    pub fn ctx(&self) -> &Context {
        &self.ctx
    }

    /// True when this profile allows `mode`.
    pub fn allows(&self, mode: KeyMode) -> bool {
        self.modes.contains(&mode)
    }

    fn require(&self, mode: KeyMode) -> Result<()> {
        if self.allows(mode) {
            Ok(())
        } else {
            Err(media_error("key mode not allowed for this profile"))
        }
    }
}

// ---------------------------------------------------------------------------
// Keys and header
// ---------------------------------------------------------------------------

/// 32-byte file key `K`, zeroized on drop. `Debug` is redacted.
pub struct FileKey(Zeroizing<[u8; KEY_SIZE]>);

impl FileKey {
    /// Wraps existing key bytes (an unwrapped NNTune key, a Drive key).
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        FileKey(Zeroizing::new(bytes))
    }

    /// Fresh Random-mode key from `rng` (production: [`crate::rng::SystemRng`]).
    pub fn generate<R: FillRandom>(rng: &mut R) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        rng.fill_bytes(key.as_mut())?;
        Ok(FileKey(key))
    }

    /// The key bytes, for wrapping under a KEK. Never log them.
    pub fn expose_secret(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey(<redacted>)")
    }
}

/// The 48-byte header `N ‖ commitment`. Both halves are public and are
/// stored in the trusted record; article 0 also carries them on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// File nonce `N`.
    pub nonce: [u8; NONCE_SIZE],
    /// HKDF key commitment.
    pub commitment: [u8; COMMITMENT_SIZE],
}

impl Header {
    /// Wire/record encoding.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE as usize] {
        let mut out = [0u8; HEADER_SIZE as usize];
        out[..NONCE_SIZE].copy_from_slice(&self.nonce);
        out[NONCE_SIZE..].copy_from_slice(&self.commitment);
        out
    }

    /// Parses the 48-byte encoding.
    pub fn from_bytes(bytes: &[u8; HEADER_SIZE as usize]) -> Self {
        let mut nonce = [0u8; NONCE_SIZE];
        let mut commitment = [0u8; COMMITMENT_SIZE];
        nonce.copy_from_slice(&bytes[..NONCE_SIZE]);
        commitment.copy_from_slice(&bytes[NONCE_SIZE..]);
        Header { nonce, commitment }
    }

    /// Parses a slice that must be exactly 48 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; HEADER_SIZE as usize] = bytes
            .try_into()
            .map_err(|_| media_error("header must be 48 bytes"))?;
        Ok(Self::from_bytes(bytes))
    }
}

/// `label ‖ 0x00 ‖ mode ‖ ctx`: fixed label, separator, fixed-width mode,
/// then `ctx` last, so the encoding parses one way only.
fn mode_info(label: &[u8], mode: KeyMode, ctx: &Context) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 2 + ctx.0.len());
    info.extend_from_slice(label);
    info.push(0x00);
    info.push(mode.as_byte());
    info.extend_from_slice(ctx.0.as_bytes());
    info
}

/// `label ‖ 0x00 ‖ ctx ‖ 0x00 ‖ BE64(P) ‖ D`: the convergent-K input.
fn content_info(label: &[u8], ctx: &Context, content: &ContentIdentity) -> Zeroizing<Vec<u8>> {
    let mut info = Vec::with_capacity(label.len() + ctx.0.len() + 2 + 8 + 32);
    info.extend_from_slice(label);
    info.push(0x00);
    info.extend_from_slice(ctx.0.as_bytes());
    info.push(0x00);
    info.extend_from_slice(&content.plaintext_len.to_be_bytes());
    info.extend_from_slice(&content.digest[..]);
    Zeroizing::new(info)
}

fn hkdf_expand(hk: &Hkdf<Sha256>, info: &[u8], out: &mut [u8]) {
    // Every output here is 16 or 32 bytes, far below HKDF-SHA256's
    // 255 * 32 limit, so expansion cannot fail.
    hk.expand(info, out)
        .expect("HKDF-SHA256 output of at most 32 bytes");
}

/// Convergent nonce: `HKDF(ikm = K, salt = "", info = convergent-nonce ‖ 0 ‖ mode ‖ ctx, L = 16)`.
fn convergent_nonce(key: &FileKey, mode: KeyMode, ctx: &Context) -> [u8; NONCE_SIZE] {
    // salt = "": RFC 5869 treats an absent salt as HashLen zero bytes,
    // which HMAC pads identically to an empty key.
    let hk = Hkdf::<Sha256>::new(None, key.expose_secret());
    let mut nonce = [0u8; NONCE_SIZE];
    hkdf_expand(
        &hk,
        &mode_info(CONVERGENT_NONCE_LABEL, mode, ctx),
        &mut nonce,
    );
    nonce
}

/// `PRK = HKDF-Extract(salt = N, ikm)`; age uses exactly this with its
/// 16-byte file key, velmora with the 32-byte `K`.
fn extract(ikm: &[u8], nonce: &[u8; NONCE_SIZE]) -> Hkdf<Sha256> {
    Hkdf::<Sha256>::new(Some(nonce), ikm)
}

fn commitment(prk: &Hkdf<Sha256>, mode: KeyMode, ctx: &Context) -> [u8; COMMITMENT_SIZE] {
    let mut out = [0u8; COMMITMENT_SIZE];
    hkdf_expand(prk, &mode_info(COMMIT_LABEL, mode, ctx), &mut out);
    out
}

fn payload_cipher(prk: &Hkdf<Sha256>) -> Stream {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    hkdf_expand(prk, PAYLOAD_INFO, key.as_mut());
    Stream {
        aead: ChaCha20Poly1305::new_from_slice(&key[..])
            .expect("ChaCha20-Poly1305 takes a 32-byte key"),
    }
}

// ---------------------------------------------------------------------------
// STREAM core (private: reachable only through Sealer and VerifiedHeader)
// ---------------------------------------------------------------------------

/// The age STREAM layer over one payload key. Deliberately private: the
/// only ways to obtain one are [`Sealer`] and [`VerifiedHeader::verify`].
struct Stream {
    aead: ChaCha20Poly1305,
}

#[cfg(test)]
thread_local! {
    /// Chunk-open calls on this thread (instrumented zero-AEAD tests).
    static AEAD_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// `BE88(i) ‖ flag`.
fn chunk_nonce(index: u64, last: bool) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    Nonce::from(nonce)
}

impl Stream {
    /// Seals one chunk: returns `ct ‖ tag`. The buffer holds plaintext
    /// until encryption runs, so it is wiped if sealing fails.
    fn seal(&self, index: u64, last: bool, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_SIZE as usize));
        out.extend_from_slice(plaintext);
        let tag = self
            .aead
            .encrypt_inout_detached(&chunk_nonce(index, last), b"", out.as_mut_slice().into())
            .map_err(|_| media_error("chunk seal failed"))?;
        out.extend_from_slice(tag.as_slice());
        // Ciphertext from here on: hand it out without the wipe.
        Ok(std::mem::take(&mut *out))
    }

    /// Opens `ct ‖ tag` in place; on success the first `len - 16` bytes are
    /// the verified plaintext. On failure nothing is released: the buffer
    /// is zeroed so no unverified bytes can leak to a caller.
    fn open<'b>(&self, index: u64, last: bool, sealed: &'b mut [u8]) -> Result<&'b [u8]> {
        #[cfg(test)]
        AEAD_OPENS.with(|n| n.set(n.get() + 1));
        let ct_len = sealed
            .len()
            .checked_sub(TAG_SIZE as usize)
            .ok_or_else(|| media_error("chunk shorter than its tag"))?;
        let (ct, tag_bytes) = sealed.split_at_mut(ct_len);
        let mut tag = [0u8; TAG_SIZE as usize];
        tag.copy_from_slice(tag_bytes);
        let opened = self.aead.decrypt_inout_detached(
            &chunk_nonce(index, last),
            b"",
            (&mut *ct).into(),
            &Tag::from(tag),
        );
        if opened.is_err() {
            ct.fill(0);
            return Err(media_error("chunk authentication failed"));
        }
        Ok(&sealed[..ct_len])
    }
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// Chunk count `L = max(1, ceil(P / 65536))`.
pub fn chunk_count(plaintext_size: u64) -> u64 {
    plaintext_size.div_ceil(PLAIN_CHUNK_SIZE).max(1)
}

/// Total object size `48 + P + 16·L`; `None` if it does not fit in `u64`.
pub fn ciphertext_size(plaintext_size: u64) -> Option<u64> {
    chunk_count(plaintext_size)
        .checked_mul(TAG_SIZE)?
        .checked_add(plaintext_size)?
        .checked_add(HEADER_SIZE)
}

/// Ciphertext offset of chunk `index` (`48 + index · 65,552`).
pub fn chunk_offset(index: u64) -> Option<u64> {
    index
        .checked_mul(CIPHER_CHUNK_SIZE)?
        .checked_add(HEADER_SIZE)
}

/// Plaintext length of chunk `index` in a `plaintext_size`-byte file.
fn chunk_plain_len(plaintext_size: u64, index: u64) -> Option<u64> {
    let chunks = chunk_count(plaintext_size);
    if index >= chunks {
        return None;
    }
    if index + 1 < chunks {
        return Some(PLAIN_CHUNK_SIZE);
    }
    // Final chunk: the remainder, or a full chunk when P is a non-zero
    // multiple of 64 KiB (age rule), or empty only when P = 0.
    plaintext_size.checked_sub(index.checked_mul(PLAIN_CHUNK_SIZE)?)
}

// ---------------------------------------------------------------------------
// Convergent keys
// ---------------------------------------------------------------------------

/// Pass-1 content identity for the convergent modes: the plaintext length
/// `P`, its SHA-256 `D`, and the SHA-256 of every 64 KiB STREAM chunk,
/// all computed in the same hashing pass (so the chunk list is bound to
/// `D`). Built only by [`ContentHasher`] (or [`ContentIdentity::of`]).
///
/// The [`Sealer`] checks each chunk against its entry here *before*
/// sealing it (decision §2.4.3, per-chunk TOCTOU gate), so a chunk that
/// changed after this pass is never sealed under the canonical keystream.
/// Chunks before the first mismatch match the hashed content and may
/// already have been returned; the caller aborts the upload on error.
#[derive(Clone)]
pub struct ContentIdentity {
    plaintext_len: u64,
    digest: Zeroizing<[u8; 32]>,
    chunk_digests: Zeroizing<Vec<[u8; 32]>>,
}

impl ContentIdentity {
    /// Hashes a whole in-memory plaintext.
    pub fn of(plaintext: &[u8]) -> Self {
        let mut hasher = ContentHasher::new();
        hasher.update(plaintext);
        hasher.finish()
    }

    /// `P`, the plaintext length.
    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// `D`, the SHA-256 of the complete plaintext.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl std::fmt::Debug for ContentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `D` of private content is a confirmation oracle: never rendered.
        f.debug_struct("ContentIdentity")
            .field("plaintext_len", &self.plaintext_len)
            .finish_non_exhaustive()
    }
}

/// Streaming first pass that builds a [`ContentIdentity`]. Feed the
/// plaintext in order, in pieces of any size.
pub struct ContentHasher {
    whole: Sha256,
    chunk: Sha256,
    in_chunk: u64,
    plaintext_len: u64,
    chunk_digests: Zeroizing<Vec<[u8; 32]>>,
}

impl Default for ContentHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentHasher {
    /// An empty hashing pass.
    pub fn new() -> Self {
        ContentHasher {
            whole: Sha256::new(),
            chunk: Sha256::new(),
            in_chunk: 0,
            plaintext_len: 0,
            chunk_digests: Zeroizing::new(Vec::new()),
        }
    }

    /// Hashes the next plaintext bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.whole.update(data);
        self.plaintext_len = self.plaintext_len.saturating_add(data.len() as u64);
        while !data.is_empty() {
            // `in_chunk < PLAIN_CHUNK_SIZE` here, so the room fits in usize.
            let room = (PLAIN_CHUNK_SIZE - self.in_chunk) as usize;
            let take = room.min(data.len());
            self.chunk.update(&data[..take]);
            self.in_chunk += take as u64;
            data = &data[take..];
            if self.in_chunk == PLAIN_CHUNK_SIZE {
                self.chunk_digests
                    .push(std::mem::take(&mut self.chunk).finalize().into());
                self.in_chunk = 0;
            }
        }
    }

    /// Ends the pass. The chunk list has exactly `L = max(1, ceil(P / 64 KiB))`
    /// entries: a full final chunk adds no empty one, and `P = 0` has the
    /// one empty chunk.
    pub fn finish(mut self) -> ContentIdentity {
        if self.in_chunk > 0 || self.chunk_digests.is_empty() {
            self.chunk_digests
                .push(std::mem::take(&mut self.chunk).finalize().into());
        }
        ContentIdentity {
            plaintext_len: self.plaintext_len,
            digest: Zeroizing::new(std::mem::take(&mut self.whole).finalize().into()),
            chunk_digests: std::mem::take(&mut self.chunk_digests),
        }
    }
}

/// A convergent-mode file key plus the [`ContentIdentity`] it was derived
/// from. The [`Sealer`] checks every chunk against that identity before
/// sealing it (two-pass TOCTOU gate, decision §2.4.3).
pub struct ConvergentKey {
    key: FileKey,
    mode: KeyMode,
    ctx: Context,
    content: ContentIdentity,
}

impl ConvergentKey {
    /// VaultConvergent `K = HMAC-SHA256(vault_dedupe_key, "velmora.media.v1/vault-K" ‖ 0 ‖ ctx ‖ 0 ‖ BE64(P) ‖ D)`.
    ///
    /// `vault_dedupe_key` is client-only and never leaves the vault's
    /// clients. `content` is the first hashing pass over the complete,
    /// exact plaintext (`P` and `D`).
    pub fn vault(
        vault_dedupe_key: &[u8; KEY_SIZE],
        ctx: &str,
        content: ContentIdentity,
    ) -> Result<Self> {
        let ctx = Context::new(ctx)?;
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(vault_dedupe_key)
            .map_err(|_| media_error("vault dedupe key"))?;
        mac.update(&content_info(VAULT_K_LABEL, &ctx, &content));
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        hmac::digest::FixedOutput::finalize_into(mac, (&mut *key).into());
        Ok(ConvergentKey {
            key: FileKey(key),
            mode: KeyMode::VaultConvergent,
            ctx,
            content,
        })
    }

    /// PublicConvergent `K = HKDF(ikm = O, salt = "", info = "velmora.media.v1/public-K", L = 32)`,
    /// where `O` is the RFC 9497 ristretto255-SHA512 OPRF output over
    /// [`public_oprf_input`]`(ctx, content)`. The OPRF itself lives in the
    /// Drive crypto design, not here.
    pub fn public(
        oprf_output: &[u8; OPRF_OUTPUT_SIZE],
        ctx: &str,
        content: ContentIdentity,
    ) -> Result<Self> {
        let ctx = Context::new(ctx)?;
        let hk = Hkdf::<Sha256>::new(None, oprf_output);
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        hkdf_expand(&hk, PUBLIC_K_LABEL, key.as_mut());
        Ok(ConvergentKey {
            key: FileKey(key),
            mode: KeyMode::PublicConvergent,
            ctx,
            content,
        })
    }

    /// The content identity `(P, D)` this key was derived from.
    pub fn content(&self) -> &ContentIdentity {
        &self.content
    }

    /// The file key `K` (to wrap for the vault, or to put in a link fragment).
    pub fn file_key(&self) -> &FileKey {
        &self.key
    }

    /// The convergent mode this key belongs to.
    pub fn mode(&self) -> KeyMode {
        self.mode
    }
}

/// OPRF input for PublicConvergent:
/// `"velmora.media.v1/public-K" ‖ 0 ‖ ctx ‖ 0 ‖ BE64(P) ‖ D`.
pub fn public_oprf_input(ctx: &str, content: &ContentIdentity) -> Result<Zeroizing<Vec<u8>>> {
    let ctx = Context::new(ctx)?;
    Ok(content_info(PUBLIC_K_LABEL, &ctx, content))
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Per-chunk TOCTOU gate (decision §2.4.3): chunk `i` is sealed only if
/// its SHA-256 equals pass-1 entry `i`; the final chunk additionally needs
/// the running `(P, D)` to match.
struct ContentGate {
    expected: ContentIdentity,
    hasher: Sha256,
    seen: u64,
}

impl ContentGate {
    /// True when chunk `index` (with this `last` flag) is exactly the
    /// pass-1 content. Runs before the chunk is sealed.
    fn admits(&mut self, index: u64, last: bool, plaintext: &[u8]) -> bool {
        let chunks = &self.expected.chunk_digests;
        let Some(expected) = usize::try_from(index).ok().and_then(|i| chunks.get(i)) else {
            return false;
        };
        let final_index = index + 1 == chunks.len() as u64;
        let chunk_digest: [u8; 32] = Sha256::digest(plaintext).into();
        if last != final_index || !bool::from(chunk_digest[..].ct_eq(&expected[..])) {
            return false;
        }
        self.hasher.update(plaintext);
        self.seen = self.seen.saturating_add(plaintext.len() as u64);
        if !last {
            return true;
        }
        let digest: [u8; 32] = std::mem::take(&mut self.hasher).finalize().into();
        self.seen == self.expected.plaintext_len
            && bool::from(digest[..].ct_eq(&self.expected.digest[..]))
    }
}

/// Streaming writer. Emits the header, then one sealed chunk per call in
/// order. Every chunk but the last carries exactly 64 KiB of plaintext;
/// the last carries 1..=64 KiB, or 0 bytes only for an empty file.
pub struct Sealer {
    stream: Stream,
    header: Header,
    mode: KeyMode,
    next: u64,
    finished: bool,
    gate: Option<ContentGate>,
}

impl Sealer {
    /// Random mode: `N` comes fresh from `rng`. `key` must itself be fresh
    /// per file ([`FileKey::generate`]).
    pub fn random<R: FillRandom>(profile: &Profile, key: &FileKey, rng: &mut R) -> Result<Self> {
        profile.require(KeyMode::Random)?;
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce)?;
        Ok(Self::with_nonce(profile, KeyMode::Random, key, nonce, None))
    }

    /// Convergent mode: `N` is derived from `(K, mode, ctx)`, never chosen.
    /// The key's ctx must equal the profile's.
    pub fn convergent(profile: &Profile, key: &ConvergentKey) -> Result<Self> {
        profile.require(key.mode)?;
        if key.ctx != profile.ctx {
            return Err(media_error("convergent key context differs from profile"));
        }
        let nonce = convergent_nonce(&key.key, key.mode, &profile.ctx);
        let gate = ContentGate {
            expected: key.content.clone(),
            hasher: Sha256::new(),
            seen: 0,
        };
        Ok(Self::with_nonce(
            profile,
            key.mode,
            &key.key,
            nonce,
            Some(gate),
        ))
    }

    fn with_nonce(
        profile: &Profile,
        mode: KeyMode,
        key: &FileKey,
        nonce: [u8; NONCE_SIZE],
        gate: Option<ContentGate>,
    ) -> Self {
        let prk = extract(key.expose_secret(), &nonce);
        let header = Header {
            nonce,
            commitment: commitment(&prk, mode, &profile.ctx),
        };
        Sealer {
            stream: payload_cipher(&prk),
            header,
            mode,
            next: 0,
            finished: false,
            gate,
        }
    }

    /// The header to store in the record and to put in front of chunk 0.
    pub fn header(&self) -> Header {
        self.header
    }

    /// The key mode this writer seals under.
    pub fn mode(&self) -> KeyMode {
        self.mode
    }

    /// True once the final chunk has been emitted (or the writer failed).
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Seals the next chunk. `last` marks the final chunk. For convergent
    /// keys every chunk is checked against the key's [`ContentIdentity`]
    /// *before* it is sealed (and the final one against `(P, D)` too). On a
    /// mismatch the writer fails, nothing further is released, and the
    /// caller must abort the upload: the object has no valid final chunk,
    /// so it can never verify.
    pub fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>> {
        if self.finished {
            return Err(media_error("writer already finished"));
        }
        let len = plaintext.len() as u64;
        let len_ok = if last {
            (1..=PLAIN_CHUNK_SIZE).contains(&len) || (len == 0 && self.next == 0)
        } else {
            len == PLAIN_CHUNK_SIZE
        };
        if !len_ok {
            self.finished = true;
            return Err(media_error("chunk plaintext length violates the format"));
        }
        if let Some(gate) = self.gate.as_mut() {
            if !gate.admits(self.next, last, plaintext) {
                self.finished = true;
                return Err(media_error("content changed since the key was derived"));
            }
        }
        let index = self.next;
        let sealed = self.stream.seal(index, last, plaintext);
        if sealed.is_err() || last {
            self.finished = true;
        }
        self.next = index
            .checked_add(1)
            .ok_or_else(|| media_error("chunk counter overflow"))?;
        sealed
    }

    /// Seals a whole in-memory plaintext: `header ‖ chunk 0 … chunk L-1`.
    pub fn seal_to_vec(mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let total = ciphertext_size(plaintext.len() as u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| media_error("plaintext too large"))?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&self.header.to_bytes());
        if plaintext.is_empty() {
            out.extend_from_slice(&self.seal_chunk(&[], true)?);
            return Ok(out);
        }
        let mut chunks = plaintext.chunks(PLAIN_CHUNK_SIZE as usize).peekable();
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            out.extend_from_slice(&self.seal_chunk(chunk, last)?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Random-access byte source for ciphertext (fetch buffers, cache files…),
/// addressed in object coordinates (header at offset 0).
pub trait ReadAt {
    /// Reads up to `buf.len()` bytes at `off`; returns the byte count, `0`
    /// only at end of source.
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize>;
}

impl ReadAt for [u8] {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        // Compare in u64 first: `off as usize` truncates above 32 bits on
        // 32-bit targets (including wasm32), which would silently return the
        // wrong bytes instead of end-of-source.
        if off >= self.len() as u64 {
            return Ok(0);
        }
        let off = off as usize;
        let n = buf.len().min(self.len() - off);
        buf[..n].copy_from_slice(&self[off..off + n]);
        Ok(n)
    }
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.as_slice().read_at(buf, off)
    }
}

fn range_overflow() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "ciphertext range exceeds addressable offsets",
    )
}

pub(crate) fn read_exact_at(
    src: &(impl ReadAt + ?Sized),
    mut dst: &mut [u8],
    off: u64,
) -> io::Result<()> {
    if dst.is_empty() {
        return Ok(());
    }
    // The offset of the last byte read must be representable; reject
    // before issuing any source request that would need a wrapped offset.
    // `dst.len() as u64` is lossless (usize never exceeds 64 bits) and
    // `dst` is non-empty here, so the subtraction cannot underflow.
    off.checked_add(dst.len() as u64 - 1)
        .ok_or_else(range_overflow)?;
    let mut pos = off;
    while !dst.is_empty() {
        let n = src.read_at(dst, pos)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ciphertext source ended mid-range",
            ));
        }
        if n > dst.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ciphertext source returned more bytes than requested",
            ));
        }
        dst = &mut dst[n..];
        if !dst.is_empty() {
            pos = pos.checked_add(n as u64).ok_or_else(range_overflow)?;
        }
    }
    Ok(())
}

/// A header whose commitment (and, in convergent modes, derived nonce) has
/// been checked against `(K, mode, ctx)`. The payload key exists only in
/// here, and only this type can create a [`ChunkReader`].
pub struct VerifiedHeader {
    stream: Stream,
    header: Header,
    mode: KeyMode,
}

impl std::fmt::Debug for VerifiedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The payload key stays out of every rendering.
        f.debug_struct("VerifiedHeader")
            .field("header", &self.header)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl VerifiedHeader {
    /// Verifies a trusted-record header (decision §1.5 rules 2–4):
    /// mode allow-list first, then the derived-`N` check for convergent
    /// modes, then a constant-time commitment comparison. Only after all of
    /// them pass is the payload key derived. Every failure is the same
    /// generic error.
    pub fn verify(
        profile: &Profile,
        mode: KeyMode,
        key: &FileKey,
        header: &Header,
    ) -> Result<Self> {
        profile.require(mode)?;
        let mut ok = subtle::Choice::from(1u8);
        if mode.is_convergent() {
            ok &= convergent_nonce(key, mode, &profile.ctx)[..].ct_eq(&header.nonce[..]);
        }
        let prk = extract(key.expose_secret(), &header.nonce);
        ok &= commitment(&prk, mode, &profile.ctx)[..].ct_eq(&header.commitment[..]);
        if !bool::from(ok) {
            return Err(header_rejected());
        }
        Ok(VerifiedHeader {
            stream: payload_cipher(&prk),
            header: *header,
            mode,
        })
    }

    /// Like [`VerifiedHeader::verify`], taking the record's raw mode byte.
    pub fn verify_record(
        profile: &Profile,
        mode_byte: u8,
        key: &FileKey,
        header: &Header,
    ) -> Result<Self> {
        Self::verify(profile, KeyMode::from_byte(mode_byte)?, key, header)
    }

    /// The verified header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The verified key mode.
    pub fn mode(&self) -> KeyMode {
        self.mode
    }

    /// A chunk reader for a `plaintext_size`-byte file (`P` from the
    /// trusted record).
    pub fn reader(&self, plaintext_size: u64) -> Result<ChunkReader<'_>> {
        ciphertext_size(plaintext_size).ok_or_else(|| media_error("plaintext size too large"))?;
        Ok(ChunkReader {
            verified: self,
            plaintext_size,
        })
    }
}

/// Authenticated ranged reader over one verified object.
#[derive(Debug)]
pub struct ChunkReader<'a> {
    verified: &'a VerifiedHeader,
    plaintext_size: u64,
}

impl ChunkReader<'_> {
    /// Plaintext length `P`.
    pub fn plaintext_size(&self) -> u64 {
        self.plaintext_size
    }

    /// Total object length `48 + P + 16·L`.
    pub fn ciphertext_size(&self) -> u64 {
        // Checked in `VerifiedHeader::reader`.
        ciphertext_size(self.plaintext_size).unwrap_or(u64::MAX)
    }

    /// Rule 1: whenever article 0 is fetched, its first 48 bytes must equal
    /// the record header.
    pub fn check_wire_header(&self, wire: &[u8]) -> Result<()> {
        let expected = self.verified.header.to_bytes();
        let same = wire.len() == expected.len() && bool::from(wire.ct_eq(&expected[..]));
        if same {
            Ok(())
        } else {
            Err(header_rejected())
        }
    }

    /// Prechecks and authenticates one complete, exclusively owned sealed chunk.
    ///
    /// `index` and the exact ciphertext-plus-tag length are validated against
    /// this reader's trusted plaintext size before `precheck` is called. The
    /// callback receives an immutable view of every sealed byte, including the
    /// tag. If it fails, its error is returned without any AEAD call or
    /// plaintext output. The caller is responsible for choosing and trusting
    /// whatever expected digest or other policy the callback checks.
    ///
    /// After a successful callback, the existing STREAM AEAD opens **that same
    /// owned buffer in place**, immediately: there is no reread, replacement,
    /// copy, resize, or mutation between the callback and the open. The final
    /// flag is derived from the trusted size and index, not supplied by the
    /// caller. Plaintext is returned only after authentication, in a zeroizing
    /// buffer. Authentication failure releases no plaintext.
    ///
    /// An empty object has one final chunk at index 0, consisting of its
    /// 16-byte tag; it is prechecked and authenticated before returning an
    /// empty buffer. A full final chunk is final without an extra empty chunk.
    pub fn open_chunk_with_precheck(
        &self,
        index: u64,
        sealed: Vec<u8>,
        precheck: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut sealed = Zeroizing::new(sealed);
        let out_of_range = || media_error("chunk range out of bounds");
        let plain_len = chunk_plain_len(self.plaintext_size, index).ok_or_else(out_of_range)?;
        let sealed_len = usize::try_from(plain_len)
            .ok()
            .and_then(|n| n.checked_add(TAG_SIZE as usize))
            .ok_or_else(out_of_range)?;
        if sealed.len() != sealed_len {
            return Err(media_error("incorrect sealed chunk length"));
        }
        precheck(&sealed)?;
        let last = index + 1 == chunk_count(self.plaintext_size);
        let len = self.verified.stream.open(index, last, &mut sealed)?.len();
        sealed.truncate(len);
        Ok(sealed)
    }

    /// Reads one sealed chunk and opens it; returns the verified plaintext.
    fn open_chunk(
        &self,
        src: &(impl ReadAt + ?Sized),
        index: u64,
        buf: &mut Vec<u8>,
    ) -> Result<usize> {
        let out_of_range = || media_error("chunk range out of bounds");
        let plain_len = chunk_plain_len(self.plaintext_size, index).ok_or_else(out_of_range)?;
        let sealed_len = usize::try_from(plain_len)
            .ok()
            .and_then(|n| n.checked_add(TAG_SIZE as usize))
            .ok_or_else(out_of_range)?;
        let off = chunk_offset(index).ok_or_else(out_of_range)?;
        buf.clear();
        buf.resize(sealed_len, 0);
        read_exact_at(src, buf, off).map_err(Error::Io)?;
        let last = index + 1 == chunk_count(self.plaintext_size);
        let plain = self.verified.stream.open(index, last, buf)?;
        Ok(plain.len())
    }

    /// Authenticates and decrypts the plaintext range `[off, off + dst.len())`
    /// (clamped to `P`), touching only the chunks it covers. Returns the
    /// bytes written; only bytes of chunks whose tag verified are released.
    pub fn read_at(&self, src: &(impl ReadAt + ?Sized), dst: &mut [u8], off: u64) -> Result<usize> {
        if off > self.plaintext_size {
            return Err(media_error("offset past plaintext end"));
        }
        if off == self.plaintext_size || dst.is_empty() {
            return Ok(0);
        }
        let keep = (dst.len() as u64).min(self.plaintext_size - off) as usize;
        let dst = &mut dst[..keep];
        // `keep <= P - off`, so this cannot overflow.
        let range_end = off + keep as u64;
        let first = off / PLAIN_CHUNK_SIZE;
        let last = (range_end - 1) / PLAIN_CHUNK_SIZE;
        let mut buf = Zeroizing::new(Vec::new());
        let mut written = 0usize;
        for index in first..=last {
            let plain_len = self.open_chunk(src, index, &mut buf)?;
            let chunk_start = index * PLAIN_CHUNK_SIZE;
            let from = (off.max(chunk_start) - chunk_start) as usize;
            let to = (range_end.min(chunk_start + plain_len as u64) - chunk_start) as usize;
            let n = to - from;
            dst[written..written + n].copy_from_slice(&buf[from..to]);
            written += n;
        }
        Ok(written)
    }

    /// Full verification (post-verify and backup drill, rule 7): the wire
    /// header equals the record, every chunk decrypts with the final flag
    /// at index `L-1`, and the source ends immediately after it. Returns
    /// the SHA-256 of the plaintext.
    pub fn verify_all(&self, src: &(impl ReadAt + ?Sized)) -> Result<[u8; 32]> {
        let mut wire = [0u8; HEADER_SIZE as usize];
        read_exact_at(src, &mut wire, 0).map_err(Error::Io)?;
        self.check_wire_header(&wire)?;
        let mut hasher = Sha256::new();
        let mut buf = Zeroizing::new(Vec::new());
        for index in 0..chunk_count(self.plaintext_size) {
            let n = self.open_chunk(src, index, &mut buf)?;
            hasher.update(&buf[..n]);
        }
        let mut probe = [0u8; 1];
        if src
            .read_at(&mut probe, self.ciphertext_size())
            .map_err(Error::Io)?
            != 0
        {
            return Err(media_error("trailing bytes after the final chunk"));
        }
        Ok(hasher.finalize().into())
    }
}

// ---------------------------------------------------------------------------
// Tests that need the private STREAM layer (age CCTV vectors, AEAD counts)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Sequential age v1 payload decoder over velmora's STREAM primitives
    /// (`extract`, `payload_cipher`, `chunk_nonce`, `Stream::open`), for the
    /// C2SP CCTV vectors. age has no trusted length, so the final chunk is
    /// the one followed by end of input.
    fn age_open(file_key: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        if body.len() < NONCE_SIZE {
            return Err(media_error("missing nonce"));
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&body[..NONCE_SIZE]);
        let stream = payload_cipher(&extract(file_key, &nonce));
        let mut rest = &body[NONCE_SIZE..];
        let mut out = Vec::new();
        let mut index = 0u64;
        loop {
            let take = rest.len().min(CIPHER_CHUNK_SIZE as usize);
            let last = take == rest.len();
            let mut chunk = rest[..take].to_vec();
            let plain = stream.open(index, last, &mut chunk)?;
            if last && plain.is_empty() && index > 0 {
                return Err(media_error("empty final chunk"));
            }
            out.extend_from_slice(plain);
            rest = &rest[take..];
            if last {
                return Ok(out);
            }
            index += 1;
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    /// C2SP CCTV age vectors (Go reference), every `stream_*` case, pinned
    /// at CCTV `b88c4b2` (see testdata/README.md). Accept/reject and the
    /// payload SHA-256 must match.
    #[test]
    fn cctv_age_stream_vectors() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/cctv-age");
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names.len(), 28, "every CCTV stream_* vector is present");
        for name in names {
            let raw = std::fs::read(dir.join(&name)).unwrap();
            let split = find(&raw, b"\n\n").unwrap();
            let meta = std::str::from_utf8(&raw[..split]).unwrap();
            let mut content = raw[split + 2..].to_vec();
            let field = |k: &str| {
                meta.lines()
                    .find_map(|l| l.strip_prefix(&format!("{k}: ")))
                    .map(str::to_owned)
            };
            if field("compressed").as_deref() == Some("zlib") {
                content = miniz_oxide::inflate::decompress_to_vec_zlib(&content).unwrap();
            }
            let expect = field("expect").unwrap();
            let file_key = hex(&field("file key").unwrap());
            let mac_line = find(&content, b"\n--- ").expect(&name);
            let header_end = mac_line + 1 + find(&content[mac_line + 1..], b"\n").unwrap() + 1;
            let result = age_open(&file_key, &content[header_end..]);
            match expect.as_str() {
                "success" => {
                    let plain = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                    let digest: [u8; 32] = Sha256::digest(&plain).into();
                    assert_eq!(digest.to_vec(), hex(&field("payload").unwrap()), "{name}");
                }
                "payload failure" | "header failure" => {
                    assert!(result.is_err(), "{name} must be rejected");
                }
                other => panic!("{name}: unexpected expect {other}"),
            }
        }
    }

    struct Fixed(u8);
    impl FillRandom for Fixed {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            dest.fill(self.0);
            Ok(())
        }
    }

    fn opens() -> usize {
        AEAD_OPENS.with(|n| n.get())
    }

    /// Wrong key, mode, ctx or commitment: zero AEAD calls and zero chunk
    /// reads (the verifier never touches a source).
    #[test]
    fn rejected_header_makes_zero_aead_calls() {
        let profile = Profile::drive();
        let key = FileKey::from_bytes([7; 32]);
        let sealer = Sealer::random(&profile, &key, &mut Fixed(9)).unwrap();
        let header = sealer.header();
        let object = sealer.seal_to_vec(&[1u8; 100]).unwrap();
        let before = opens();

        let wrong_key = FileKey::from_bytes([8; 32]);
        assert!(VerifiedHeader::verify(&profile, KeyMode::Random, &wrong_key, &header).is_err());
        let other_ctx = Profile::new("other/media", &[KeyMode::Random]).unwrap();
        assert!(VerifiedHeader::verify(&other_ctx, KeyMode::Random, &key, &header).is_err());
        let mut flipped = header;
        flipped.commitment[0] ^= 1;
        assert!(VerifiedHeader::verify(&profile, KeyMode::Random, &key, &flipped).is_err());
        assert!(VerifiedHeader::verify(&profile, KeyMode::VaultConvergent, &key, &header).is_err());
        assert_eq!(opens(), before, "no AEAD call before the commitment passes");

        let ok = VerifiedHeader::verify(&profile, KeyMode::Random, &key, &header).unwrap();
        ok.reader(100).unwrap().verify_all(&object).unwrap();
        assert_eq!(opens(), before + 1);
    }

    #[test]
    fn precheck_precedes_same_buffer_open_and_failures_release_nothing() {
        let profile = Profile::nntune();
        let key = FileKey::from_bytes([3; 32]);
        let sealer = Sealer::random(&profile, &key, &mut Fixed(4)).unwrap();
        let header = sealer.header();
        let object = sealer.seal_to_vec(&[0x5a; 10]).unwrap();
        let verified = VerifiedHeader::verify(&profile, KeyMode::Random, &key, &header).unwrap();
        let reader = verified.reader(10).unwrap();
        let sealed = object[HEADER_SIZE as usize..].to_vec();
        let before = opens();

        assert!(reader
            .open_chunk_with_precheck(0, sealed.clone(), |_| {
                assert_eq!(opens(), before);
                Err(media_error("precheck rejected"))
            })
            .is_err());
        assert_eq!(opens(), before);
        for (index, bytes) in [
            (1, sealed.clone()),
            (u64::MAX, sealed.clone()),
            (0, sealed[..sealed.len() - 1].to_vec()),
        ] {
            assert!(reader
                .open_chunk_with_precheck(index, bytes, |_| panic!(
                    "invalid geometry reached precheck"
                ))
                .is_err());
        }
        assert_eq!(opens(), before);

        let ptr = sealed.as_ptr();
        let plain = reader
            .open_chunk_with_precheck(0, sealed, |bytes| {
                assert_eq!(opens(), before);
                assert_eq!(bytes.as_ptr(), ptr);
                assert_eq!(bytes, &object[HEADER_SIZE as usize..]);
                Ok(())
            })
            .unwrap();
        assert_eq!(opens(), before + 1);
        assert_eq!(plain.as_ptr(), ptr);
        assert_eq!(&plain[..], &[0x5a; 10]);

        let mut tampered = object[HEADER_SIZE as usize..].to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(reader
            .open_chunk_with_precheck(0, tampered, |_| Ok(()))
            .is_err());
        assert_eq!(opens(), before + 2);
    }

    #[test]
    fn failed_open_releases_nothing() {
        let profile = Profile::nntune();
        let key = FileKey::from_bytes([3; 32]);
        let sealer = Sealer::random(&profile, &key, &mut Fixed(4)).unwrap();
        let header = sealer.header();
        let mut object = sealer.seal_to_vec(&[0x5a; 10]).unwrap();
        object[HEADER_SIZE as usize] ^= 1;
        let mut chunk = object[HEADER_SIZE as usize..].to_vec();
        let verified = VerifiedHeader::verify(&profile, KeyMode::Random, &key, &header).unwrap();
        assert!(verified.stream.open(0, true, &mut chunk).is_err());
        assert!(
            chunk[..10].iter().all(|&b| b == 0),
            "unverified plaintext is wiped"
        );
    }

    /// age forbids an empty final chunk after data. With `P` an exact
    /// multiple of 64 KiB the full chunk is final, so an AEAD-valid empty
    /// chunk appended after it is trailing data, and a full chunk sealed
    /// non-final plus an empty final one does not open at all.
    #[test]
    fn empty_final_chunk_after_full_chunk_is_rejected() {
        let profile = Profile::nntune();
        let key = FileKey::from_bytes([5; 32]);
        let sealer = Sealer::random(&profile, &key, &mut Fixed(6)).unwrap();
        let header = sealer.header();
        let pt = vec![0x42u8; PLAIN_CHUNK_SIZE as usize];
        let object = sealer.seal_to_vec(&pt).unwrap();
        let verified = VerifiedHeader::verify(&profile, KeyMode::Random, &key, &header).unwrap();
        let reader = verified.reader(PLAIN_CHUNK_SIZE).unwrap();
        reader.verify_all(&object).unwrap();

        let mut appended = object.clone();
        appended.extend_from_slice(&verified.stream.seal(1, true, &[]).unwrap());
        assert!(
            reader.verify_all(&appended).is_err(),
            "empty chunk after a full final chunk"
        );

        let mut split = header.to_bytes().to_vec();
        split.extend_from_slice(&verified.stream.seal(0, false, &pt).unwrap());
        split.extend_from_slice(&verified.stream.seal(1, true, &[]).unwrap());
        assert!(
            reader.verify_all(&split).is_err(),
            "full chunk sealed non-final"
        );
        let mut dst = [0u8; 1];
        assert!(reader.read_at(&split, &mut dst, 0).is_err());
    }

    /// Scripted byte source: returns `script` counts in order, recording calls.
    struct Scripted {
        script: Vec<usize>,
        calls: std::cell::Cell<usize>,
    }

    impl ReadAt for Scripted {
        fn read_at(&self, _buf: &mut [u8], _off: u64) -> io::Result<usize> {
            let i = self.calls.get();
            self.calls.set(i + 1);
            Ok(self.script.get(i).copied().unwrap_or(0))
        }
    }

    #[test]
    fn over_returning_source_is_rejected_not_trusted() {
        // A source returning more than requested would panic the `dst[n..]`
        // slicing; the guard must reject it as corrupt input instead.
        let src = Scripted {
            script: vec![usize::MAX],
            calls: Default::default(),
        };
        let mut dst = [0u8; 8];
        let err = read_exact_at(&src, &mut dst, 0).expect_err("over-return must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn extent_ending_exactly_at_u64_max_is_allowed() {
        let src = Scripted {
            script: vec![1],
            calls: Default::default(),
        };
        let mut dst = [0u8; 1];
        read_exact_at(&src, &mut dst, u64::MAX).expect("a last byte of u64::MAX is representable");
        assert_eq!(src.calls.get(), 1);
    }

    #[test]
    fn extent_past_u64_max_fails_before_any_source_read() {
        let src = Scripted {
            script: vec![2],
            calls: Default::default(),
        };
        let mut dst = [0u8; 2];
        let err =
            read_exact_at(&src, &mut dst, u64::MAX).expect_err("unrepresentable extent must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            src.calls.get(),
            0,
            "no source request may use a wrapped offset"
        );
    }

    #[test]
    fn chunk_nonce_is_be88_counter_and_flag() {
        let n = chunk_nonce(0x0102_0304_0506_0708, true);
        assert_eq!(n.as_slice(), &[0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1]);
        assert_eq!(chunk_nonce(0, false).as_slice(), &[0u8; 12]);
    }

    // -----------------------------------------------------------------------
    // `age` crate oracle (decision §4): rage seals, velmora must open, and
    // velmora's writer must reproduce rage's chunks byte for byte under the
    // same file key and `N` (so rage opens velmora's payload). The vectors
    // are rage output frozen by `testdata/age-oracle/gen_age_vectors.py`:
    // the `age` crate itself cannot be a dev-dependency (cargo-deny and OSV
    // refuse its dependency tree). age's file key is 16 bytes, velmora's
    // `K` 32, so both sides use age's key as the HKDF input (any length is
    // valid); keys and nonces come from the vectors, never from literals.
    // -----------------------------------------------------------------------

    use crate::rng::SystemRng;

    /// Same pattern as `plaintext()` in `gen_age_vectors.py`.
    fn oracle_plaintext(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 9)) as u8)
            .collect()
    }

    /// The Random-mode writer, keyed by age's file key instead of a
    /// [`FileKey`]: [`Sealer::with_nonce`] without the 32-byte key type.
    fn age_keyed_sealer(file_key: &[u8], nonce: [u8; NONCE_SIZE]) -> Sealer {
        let prk = extract(file_key, &nonce);
        Sealer {
            stream: payload_cipher(&prk),
            header: Header {
                nonce,
                commitment: commitment(&prk, KeyMode::Random, Profile::nntune().ctx()),
            },
            mode: KeyMode::Random,
            next: 0,
            finished: false,
            gate: None,
        }
    }

    /// The reader side, keyed the same way.
    fn age_keyed_reader(file_key: &[u8], nonce: [u8; NONCE_SIZE]) -> VerifiedHeader {
        let prk = extract(file_key, &nonce);
        VerifiedHeader {
            stream: payload_cipher(&prk),
            header: Header {
                nonce,
                commitment: commitment(&prk, KeyMode::Random, Profile::nntune().ctx()),
            },
            mode: KeyMode::Random,
        }
    }

    #[test]
    fn age_crate_vectors_match_velmora_stream() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/age-oracle/vectors.txt");
        let text = std::fs::read_to_string(path).unwrap();
        let mut lengths = Vec::new();
        for record in text.split("\n\n").skip(1) {
            let field = |k: &str| {
                record
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("{k}: ")))
                    .map(str::to_owned)
            };
            let len: usize = field("len").unwrap().parse().unwrap();
            lengths.push(len);
            let file_key = hex(&field("file ikm").unwrap());
            assert_eq!(file_key.len(), 16, "len {len}: age file key");
            let nonce: [u8; NONCE_SIZE] = hex(&field("nonce").unwrap()).try_into().unwrap();
            let plaintext = oracle_plaintext(len);

            // velmora's writer reproduces rage's payload `N ‖ chunks`.
            let object = age_keyed_sealer(&file_key, nonce)
                .seal_to_vec(&plaintext)
                .unwrap();
            let mut payload = nonce.to_vec();
            payload.extend_from_slice(&object[HEADER_SIZE as usize..]);
            assert_eq!(
                payload.len().to_string(),
                field("payload length").unwrap(),
                "len {len}"
            );
            let digest: [u8; 32] = Sha256::digest(&payload).into();
            assert_eq!(
                digest.to_vec(),
                hex(&field("payload sha256").unwrap()),
                "len {len}"
            );

            // velmora's reader opens those (rage-identical) bytes.
            let verified = age_keyed_reader(&file_key, nonce);
            let reader = verified.reader(len as u64).unwrap();
            let mut opened = vec![0u8; len];
            assert_eq!(reader.read_at(&object, &mut opened, 0).unwrap(), len);
            assert!(opened == plaintext, "len {len}: velmora opens the payload");
            let expected: [u8; 32] = Sha256::digest(&plaintext).into();
            assert_eq!(reader.verify_all(&object).unwrap(), expected, "len {len}");

            // Short vectors carry the whole age file: open rage's own bytes.
            if let Some(age_file) = field("age file").map(|h| hex(&h)) {
                let at = find(&age_file, b"\n--- ").unwrap() + 1;
                let at = at + find(&age_file[at..], b"\n").unwrap() + 1;
                assert!(age_file[at..] == payload[..], "len {len}: rage's bytes");
                assert_eq!(age_open(&file_key, &age_file[at..]).unwrap(), plaintext);
            }
        }
        assert_eq!(
            lengths,
            [0, 1, 65_535, 65_536, 65_537, 131_072, 131_073, 200_003],
            "every chunk boundary is covered"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-key ChaCha20-Poly1305 fixture (decision §4): a chunk that opens
    // under the payload keys of two file keys sharing `N` (partitioning
    // oracle / invisible salamanders). The commitment binds the header to
    // one `K`, so the second key must be refused before any AEAD call.
    // -----------------------------------------------------------------------

    use chacha20::cipher::{KeyIvInit, StreamCipher};

    /// Arithmetic mod the Poly1305 prime `p = 2^130 - 5`.
    #[allow(clippy::needless_range_loop)]
    mod p1305 {
        /// Little-endian u64 limbs; reduced values are below `p`.
        pub type Fe = [u64; 3];

        pub const P: Fe = [0xffff_ffff_ffff_fffb, u64::MAX, 3];

        fn lt(a: Fe, b: Fe) -> bool {
            for i in (0..3).rev() {
                if a[i] != b[i] {
                    return a[i] < b[i];
                }
            }
            false
        }

        /// `a - b` for `a >= b`.
        pub fn sub_raw(a: Fe, b: Fe) -> Fe {
            let mut out = [0u64; 3];
            let mut borrow = false;
            for i in 0..3 {
                let (d, b1) = a[i].overflowing_sub(b[i]);
                let (d, b2) = d.overflowing_sub(u64::from(borrow));
                out[i] = d;
                borrow = b1 || b2;
            }
            out
        }

        /// Reduces a 384-bit value: `2^130 ≡ 5 (mod p)` folds the bits
        /// above 130 back in until none remain.
        fn reduce(mut w: [u64; 6]) -> Fe {
            loop {
                let hi = [
                    (w[2] >> 2) | (w[3] << 62),
                    (w[3] >> 2) | (w[4] << 62),
                    (w[4] >> 2) | (w[5] << 62),
                    w[5] >> 2,
                ];
                if hi == [0; 4] {
                    break;
                }
                let mut next = [w[0], w[1], w[2] & 3, 0, 0, 0];
                let mut carry = 0u128;
                for i in 0..6 {
                    let five_hi = if i < 4 { u128::from(hi[i]) * 5 } else { 0 };
                    let t = u128::from(next[i]) + five_hi + carry;
                    next[i] = t as u64;
                    carry = t >> 64;
                }
                w = next;
            }
            let r = [w[0], w[1], w[2]];
            if lt(r, P) {
                r
            } else {
                sub_raw(r, P)
            }
        }

        pub fn add(a: Fe, b: Fe) -> Fe {
            let mut w = [0u64; 6];
            let mut carry = 0u128;
            for i in 0..3 {
                let t = u128::from(a[i]) + u128::from(b[i]) + carry;
                w[i] = t as u64;
                carry = t >> 64;
            }
            w[3] = carry as u64;
            reduce(w)
        }

        /// `a - b` for reduced `b`.
        pub fn sub(a: Fe, b: Fe) -> Fe {
            add(a, sub_raw(P, b))
        }

        pub fn mul(a: Fe, b: Fe) -> Fe {
            let mut w = [0u64; 6];
            for i in 0..3 {
                let mut carry = 0u128;
                for j in 0..3 {
                    let t = u128::from(w[i + j]) + u128::from(a[i]) * u128::from(b[j]) + carry;
                    w[i + j] = t as u64;
                    carry = t >> 64;
                }
                w[i + 3] = carry as u64;
            }
            reduce(w)
        }

        /// `a^(p-2)`: the inverse of a non-zero `a` (Fermat).
        pub fn inv(a: Fe) -> Fe {
            let exp = sub_raw(P, [2, 0, 0]);
            let mut out = [1, 0, 0];
            for bit in (0..192).rev() {
                out = mul(out, out);
                if (exp[bit / 64] >> (bit % 64)) & 1 == 1 {
                    out = mul(out, a);
                }
            }
            out
        }

        pub fn from_u128(v: u128) -> Fe {
            [v as u64, (v >> 64) as u64, 0]
        }
    }

    #[test]
    fn p1305_inverse_round_trips() {
        let a = p1305::from_u128(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
        assert_eq!(p1305::mul(a, p1305::inv(a)), [1, 0, 0]);
        let top = p1305::sub_raw(p1305::P, [1, 0, 0]);
        assert_eq!(p1305::mul(top, top), [1, 0, 0], "(-1)^2 = 1");
        assert_eq!(p1305::add(top, [1, 0, 0]), [0, 0, 0], "p - 1 + 1 = 0");
    }

    /// Poly1305 `(r, s)` of final chunk 0 under `key`: ChaCha20 block 0 of
    /// the payload key, exactly as ChaCha20-Poly1305 derives it.
    fn poly1305_key(key: &FileKey, nonce: &[u8; NONCE_SIZE]) -> (p1305::Fe, p1305::Fe) {
        let mut payload_key = Zeroizing::new([0u8; KEY_SIZE]);
        hkdf_expand(
            &extract(key.expose_secret(), nonce),
            PAYLOAD_INFO,
            payload_key.as_mut(),
        );
        let mut block = [0u8; 64];
        chacha20::ChaCha20::new_from_slices(&payload_key[..], chunk_nonce(0, true).as_slice())
            .unwrap()
            .apply_keystream(&mut block);
        let le = |b: &[u8]| u128::from_le_bytes(b.try_into().unwrap());
        let r = le(&block[..16]) & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;
        (p1305::from_u128(r), p1305::from_u128(le(&block[16..32])))
    }

    /// Opens final chunk 0 with the raw STREAM layer of `key` (no header
    /// check), returning the plaintext.
    fn open_chunk0(key: &FileKey, nonce: &[u8; NONCE_SIZE], sealed: &[u8]) -> Result<Vec<u8>> {
        let mut buf = sealed.to_vec();
        let stream = payload_cipher(&extract(key.expose_secret(), nonce));
        Ok(stream.open(0, true, &mut buf)?.to_vec())
    }

    /// A sealed final chunk 0 (`ct ‖ tag`, 32-byte ciphertext) valid under
    /// the payload keys of both `k1` and `k2` with the same `N`. The
    /// Poly1305 equation is solved for the first ciphertext block (Len,
    /// Grubbs and Ristenpart, "Partitioning Oracle Attacks", USENIX
    /// Security 2021); the tag then comes from sealing under `k1`.
    fn two_key_chunk(nonce: &[u8; NONCE_SIZE], k1: &FileKey, k2: &FileKey) -> Vec<u8> {
        use p1305::{add, inv, mul, sub};
        let (r1, s1) = poly1305_key(k1, nonce);
        let (r2, s2) = poly1305_key(k2, nonce);
        let stream1 = payload_cipher(&extract(k1.expose_secret(), nonce));
        // Sealing zeros yields chunk 0's keystream under k1.
        let keystream1 = stream1.seal(0, true, &[0u8; 32]).unwrap();
        // Poly1305 blocks (each + 2^128): c0, c1, le64(|AD| = 0) ‖ le64(|C| = 32).
        let pad = [0, 0, 1];
        let lengths = add([0, 32, 0], pad);
        let cube = |r| mul(mul(r, r), r);
        for y in 0u64..4096 {
            let c1 = add([y, 0, 0], pad);
            // h(r) = c0·r³ + c1·r² + lengths·r; solve h(r1) + s1 = h(r2) + s2 for c0.
            let rest = |r| add(mul(c1, mul(r, r)), mul(lengths, r));
            let rhs = add(sub(s2, s1), sub(rest(r2), rest(r1)));
            let c0 = mul(rhs, inv(sub(cube(r1), cube(r2))));
            // c0 must be a 16-byte block plus the 2^128 pad bit.
            if c0[2] != 1 {
                continue;
            }
            let mut ciphertext = Vec::with_capacity(32);
            ciphertext.extend_from_slice(&c0[0].to_le_bytes());
            ciphertext.extend_from_slice(&c0[1].to_le_bytes());
            ciphertext.extend_from_slice(&y.to_le_bytes());
            ciphertext.resize(32, 0);
            // The k1 plaintext is ct ⊕ keystream; sealing it gives ct ‖ tag1.
            let plaintext: Vec<u8> = ciphertext
                .iter()
                .zip(&keystream1)
                .map(|(c, k)| c ^ k)
                .collect();
            let sealed = stream1.seal(0, true, &plaintext).unwrap();
            assert_eq!(sealed[..32], ciphertext[..]);
            // Equal mod p is not always equal mod 2^128: keep a y where it is.
            if open_chunk0(k2, nonce, &sealed).is_ok() {
                return sealed;
            }
        }
        panic!("no two-key chunk in 4096 tries");
    }

    /// The two-key chunk opens under both payload keys at the STREAM layer,
    /// yet [`VerifiedHeader::verify`] refuses the second file key in every
    /// mode, with zero AEAD calls.
    #[test]
    fn two_key_chunk_is_refused_before_any_aead_call() {
        let profile = Profile::drive();
        let k1 = FileKey::generate(&mut SystemRng).unwrap();
        let k2 = FileKey::generate(&mut SystemRng).unwrap();
        let header = Sealer::random(&profile, &k1, &mut SystemRng)
            .unwrap()
            .header();
        let chunk = two_key_chunk(&header.nonce, &k1, &k2);

        // The fixture really is multi-key: both keys open it, differently.
        let p1 = open_chunk0(&k1, &header.nonce, &chunk).expect("opens under k1");
        let p2 = open_chunk0(&k2, &header.nonce, &chunk).expect("opens under k2");
        assert_ne!(p1, p2);

        let mut object = header.to_bytes().to_vec();
        object.extend_from_slice(&chunk);
        let v1 = VerifiedHeader::verify(&profile, KeyMode::Random, &k1, &header).unwrap();
        let mut out = [0u8; 32];
        assert_eq!(
            v1.reader(32)
                .unwrap()
                .read_at(&object, &mut out, 0)
                .unwrap(),
            32
        );
        assert_eq!(out.to_vec(), p1);

        let before = opens();
        for mode in [
            KeyMode::Random,
            KeyMode::VaultConvergent,
            KeyMode::PublicConvergent,
        ] {
            assert!(
                VerifiedHeader::verify(&profile, mode, &k2, &header).is_err(),
                "{mode:?}"
            );
            assert!(
                VerifiedHeader::verify_record(&profile, mode.as_byte(), &k2, &header).is_err(),
                "{mode:?}"
            );
        }
        assert_eq!(opens(), before, "no AEAD call for the second key");
    }
}
