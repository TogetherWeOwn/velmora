//! Ranged decryption, ported from the v1 Go worker (`worker/internal/archive`).
//!
//! Both schemes decrypt arbitrary plaintext ranges without touching the rest
//! of the file — the streaming path fetches one byte range per NNTP article
//! window:
//!
//! - [`aes_cbc`]: AES-CBC with an explicit IV (v1 `aescbc.ReadAt`).
//! - [`rclone`]: rclone-crypt files (NaCl secretbox per 64 KiB block,
//!   v1 `rclonecrypt.ReadAt`). Takes the 80-byte scrypt output like v1 does;
//!   key derivation from the rclone config password happens at config-load
//!   time, outside this crate.

use std::io;

/// Random-access byte source for ciphertext (fetch buffers, memory-mapped
/// cache files, …).
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

fn read_exact_at(src: &impl ReadAt, mut dst: &mut [u8], off: u64) -> io::Result<()> {
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

/// AES-CBC ranged decryption (v1 `worker/internal/archive/aescbc`).
pub mod aes_cbc {
    use super::{read_exact_at, ReadAt};
    use crate::error::{Error, Result};
    use aes::{Aes128, Aes192, Aes256};
    use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
    use cbc::Decryptor;

    /// AES block size in bytes.
    pub const BLOCK_SIZE: usize = 16;

    /// Decrypts an arbitrary plaintext range from AES-CBC ciphertext.
    ///
    /// The source is addressed in ciphertext coordinates and must contain
    /// whole blocks. `initial_iv` is used only for block zero; later ranges
    /// read the preceding ciphertext block as their IV. Key length selects
    /// AES-128/192/256. Returns the bytes written (always `dst.len()`).
    pub fn read_at(
        src: &impl ReadAt,
        key: &[u8],
        initial_iv: &[u8; BLOCK_SIZE],
        dst: &mut [u8],
        off: u64,
    ) -> Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(Error::Decrypt(format!(
                "aes-cbc key length {}, want 16, 24, or 32",
                key.len()
            )));
        }

        let out_of_range = || Error::Decrypt("aes-cbc range out of bounds".into());
        let first_block = off / BLOCK_SIZE as u64;
        let discard = (off % BLOCK_SIZE as u64) as usize;
        let plain_blocks = discard
            .checked_add(dst.len())
            .ok_or_else(out_of_range)?
            .div_ceil(BLOCK_SIZE);
        let cipher_len = plain_blocks
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(out_of_range)?;
        // `first_block * BLOCK_SIZE <= off`, so this cannot overflow, but
        // keep the coordinate arithmetic checked like every other step.
        let mut cipher_off = first_block
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or_else(out_of_range)?;
        let mut iv = *initial_iv;
        if first_block > 0 {
            cipher_off = cipher_off
                .checked_sub(BLOCK_SIZE as u64)
                .ok_or_else(out_of_range)?;
            read_exact_at(src, &mut iv, cipher_off).map_err(Error::Io)?;
            cipher_off = cipher_off
                .checked_add(BLOCK_SIZE as u64)
                .ok_or_else(out_of_range)?;
        }

        let mut ciphertext = vec![0u8; cipher_len];
        read_exact_at(src, &mut ciphertext, cipher_off).map_err(Error::Io)?;
        // NoPadding: the range is always a whole number of blocks, so unpad
        // is the identity over the full buffer.
        let decrypt = |key: &[u8], iv: &[u8; BLOCK_SIZE], buf: &mut [u8]| -> Result<()> {
            let out: &[u8] = match key.len() {
                16 => Decryptor::<Aes128>::new_from_slices(key, iv)
                    .map_err(|e| Error::Decrypt(format!("aes-cbc key/iv: {e}")))?
                    .decrypt_padded::<NoPadding>(buf),
                24 => Decryptor::<Aes192>::new_from_slices(key, iv)
                    .map_err(|e| Error::Decrypt(format!("aes-cbc key/iv: {e}")))?
                    .decrypt_padded::<NoPadding>(buf),
                _ => Decryptor::<Aes256>::new_from_slices(key, iv)
                    .map_err(|e| Error::Decrypt(format!("aes-cbc key/iv: {e}")))?
                    .decrypt_padded::<NoPadding>(buf),
            }
            .map_err(|e| Error::Decrypt(format!("aes-cbc decrypt: {e}")))?;
            debug_assert_eq!(out.len(), buf.len());
            Ok(())
        };
        decrypt(key, &iv, &mut ciphertext)?;
        dst.copy_from_slice(&ciphertext[discard..discard + dst.len()]);
        Ok(dst.len())
    }
}

/// rclone-crypt ranged decryption (v1 `worker/internal/archive/rclonecrypt`).
pub mod rclone {
    use super::{read_exact_at, ReadAt};
    use crate::error::{Error, Result};
    use crypto_secretbox::aead::{AeadInPlace, KeyInit};
    use crypto_secretbox::{Nonce, XSalsa20Poly1305};

    /// File header size: 8-byte magic + 24-byte nonce.
    pub const HEADER_SIZE: u64 = 32;
    /// Plaintext bytes per secretbox block.
    pub const PLAIN_BLOCK_SIZE: u64 = 64 * 1024;
    /// secretbox authentication tag (MAC) bytes per block.
    pub const CIPHER_OVERHEAD: u64 = 16;
    /// Ciphertext bytes per block.
    pub const CIPHER_BLOCK_SIZE: u64 = PLAIN_BLOCK_SIZE + CIPHER_OVERHEAD;

    const MAGIC: [u8; 8] = *b"RCLONE\x00\x00";

    /// Authenticates and decrypts an arbitrary plaintext range from an
    /// rclone-crypt file. `derived` must be the 80-byte scrypt output; only
    /// its first 32 bytes (the data key) are used for file contents.
    /// `plaintext_size` is the plaintext file length (headers excluded).
    /// Returns the bytes written.
    pub fn read_at(
        src: &impl ReadAt,
        derived: &[u8],
        plaintext_size: u64,
        dst: &mut [u8],
        off: u64,
    ) -> Result<usize> {
        if derived.len() != 80 {
            return Err(Error::Decrypt(format!(
                "rclone derived key length {}, want 80",
                derived.len()
            )));
        }
        if off > plaintext_size {
            return Err(Error::Decrypt("rclone offset past plaintext end".into()));
        }
        if off == plaintext_size || dst.is_empty() {
            return Ok(0);
        }
        let keep = (dst.len() as u64).min(plaintext_size - off) as usize;
        let dst = &mut dst[..keep];

        let mut header = [0u8; HEADER_SIZE as usize];
        read_exact_at(src, &mut header, 0).map_err(Error::Io)?;
        if header[..MAGIC.len()] != MAGIC {
            return Err(Error::Decrypt("rclone header magic mismatch".into()));
        }
        let mut header_nonce = [0u8; 24];
        header_nonce.copy_from_slice(&header[MAGIC.len()..]);
        let cipher = XSalsa20Poly1305::new_from_slice(&derived[..32])
            .map_err(|e| Error::Decrypt(format!("rclone key: {e}")))?;

        // `dst` was truncated to `plaintext_size - off` above and is
        // non-empty here, so `off + dst.len()` cannot exceed
        // `plaintext_size`; keep the arithmetic checked regardless.
        let range_end = off
            .checked_add(dst.len() as u64)
            .ok_or_else(|| Error::Decrypt("rclone range out of bounds".into()))?;
        let first_block = off / PLAIN_BLOCK_SIZE;
        let last_block = (range_end - 1) / PLAIN_BLOCK_SIZE;
        let mut written = 0usize;
        for block_number in first_block..=last_block {
            let out_of_range = || {
                Error::Decrypt(format!(
                    "rclone block {block_number} ciphertext range out of bounds"
                ))
            };
            let block_plain_start = block_number
                .checked_mul(PLAIN_BLOCK_SIZE)
                .ok_or_else(out_of_range)?;
            let remaining = plaintext_size
                .checked_sub(block_plain_start)
                .ok_or_else(out_of_range)?;
            let plain_len = PLAIN_BLOCK_SIZE.min(remaining);
            // Expand the plaintext block index into ciphertext coordinates
            // with checked arithmetic and reject before allocating or
            // issuing a (wrapped) block request. The sealed-block extent
            // itself is validated by `read_exact_at`.
            let cipher_off = block_number
                .checked_mul(CIPHER_BLOCK_SIZE)
                .and_then(|base| base.checked_add(HEADER_SIZE))
                .ok_or_else(out_of_range)?;
            // `plain_len <= PLAIN_BLOCK_SIZE`, so both conversions fit.
            let sealed_len = usize::try_from(plain_len)
                .ok()
                .and_then(|n| n.checked_add(CIPHER_OVERHEAD as usize))
                .ok_or_else(out_of_range)?;
            let mut sealed = vec![0u8; sealed_len];
            read_exact_at(src, &mut sealed, cipher_off)
                .map_err(|e| Error::Decrypt(format!("rclone block {block_number}: {e}")))?;

            let mut block_nonce = header_nonce;
            add_nonce(&mut block_nonce, block_number);
            let nonce = Nonce::clone_from_slice(&block_nonce);
            // The sealed block is [16-byte tag | ciphertext]; the detached
            // API works on plain slices with no `Buffer` plumbing.
            let (tag_bytes, ciphertext) = sealed.split_at_mut(CIPHER_OVERHEAD as usize);
            let tag = crypto_secretbox::aead::Tag::<XSalsa20Poly1305>::clone_from_slice(tag_bytes);
            cipher
                .decrypt_in_place_detached(&nonce, b"", ciphertext, &tag)
                .map_err(|_| {
                    Error::Decrypt(format!("rclone block {block_number} authentication failed"))
                })?;

            // `block_plain_start + plain_len <= plaintext_size` because
            // `plain_len` was clamped to the remaining plaintext above.
            let block_plain_end = block_plain_start
                .checked_add(plain_len)
                .ok_or_else(out_of_range)?;
            let from = off.max(block_plain_start) - block_plain_start;
            let to = range_end.min(block_plain_end) - block_plain_start;
            written += copy_slice(&mut dst[written..], &ciphertext[from as usize..to as usize]);
        }
        Ok(written)
    }

    fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize {
        let n = dst.len().min(src.len());
        dst[..n].copy_from_slice(&src[..n]);
        n
    }

    /// Little-endian block counter folded into the header nonce, exactly like
    /// v1's `addNonce` (and rclone itself): the file nonce plus the block
    /// number, carried byte by byte from `nonce[0]`.
    fn add_nonce(nonce: &mut [u8; 24], mut blocks: u64) {
        for byte in nonce.iter_mut() {
            if blocks == 0 {
                break;
            }
            let total = *byte as u64 + (blocks & 0xff);
            *byte = total as u8;
            blocks = (blocks >> 8) + (total >> 8);
        }
    }

    /// Encrypts one plaintext block with the rclone construction (test and
    /// tooling helper — the data plane only ever decrypts). `sealed` must be
    /// `plaintext.len() + CIPHER_OVERHEAD` bytes; the tag is prepended.
    pub fn seal_block(
        derived: &[u8],
        header_nonce: &[u8; 24],
        block_number: u64,
        plaintext: &[u8],
        sealed: &mut [u8],
    ) -> Result<()> {
        if derived.len() != 80 {
            return Err(Error::Decrypt("rclone derived key length, want 80".into()));
        }
        if plaintext.len().checked_add(CIPHER_OVERHEAD as usize) != Some(sealed.len()) {
            return Err(Error::Decrypt(
                "rclone seal buffer has the wrong size".into(),
            ));
        }
        let cipher = XSalsa20Poly1305::new_from_slice(&derived[..32])
            .map_err(|e| Error::Decrypt(format!("rclone key: {e}")))?;
        let mut block_nonce = *header_nonce;
        add_nonce(&mut block_nonce, block_number);
        let nonce = Nonce::clone_from_slice(&block_nonce);
        let (tag_out, ciphertext) = sealed.split_at_mut(CIPHER_OVERHEAD as usize);
        ciphertext.copy_from_slice(plaintext);
        let tag = cipher
            .encrypt_in_place_detached(&nonce, b"", ciphertext)
            .map_err(|_| Error::Decrypt("rclone seal failed".into()))?;
        tag_out.copy_from_slice(tag.as_slice());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Scripted byte source: returns `script` counts in order, recording calls.
    struct Scripted {
        script: Vec<usize>,
        calls: Cell<usize>,
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
            calls: Cell::new(0),
        };
        let mut dst = [0u8; 8];
        let err = read_exact_at(&src, &mut dst, 0).expect_err("over-return must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn extent_ending_exactly_at_u64_max_is_allowed() {
        let src = Scripted {
            script: vec![1],
            calls: Cell::new(0),
        };
        let mut dst = [0u8; 1];
        read_exact_at(&src, &mut dst, u64::MAX).expect("a last byte of u64::MAX is representable");
        assert_eq!(src.calls.get(), 1);
    }

    #[test]
    fn extent_past_u64_max_fails_before_any_source_read() {
        let src = Scripted {
            script: vec![2],
            calls: Cell::new(0),
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
}
