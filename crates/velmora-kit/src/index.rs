use crate::{Entry, Error};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Read, Seek, Write};
use velmora::rng::{FillRandom, SystemRng};
use velmora_bridge::{ports::Kek, types::KekBytes};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"VKI1";
const DOMAIN: &str = "velmora/kit/v1";
const PLAIN_MAX: usize = 4 * 1024 * 1024;
const PREFIX: usize = 29; // KEK version, wrap version, nonce
const TAG: usize = 16;

fn check_id(id: &str) -> Result<(), Error> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(Error::Format);
    }
    Ok(())
}

fn aad(id: &str, number: u64, flags: u8) -> String {
    format!("{DOMAIN}|{id}|{number}|{flags}")
}

fn cipher(key: &KekBytes) -> XChaCha20Poly1305 {
    let mut derived = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, key.expose())
        .expand(DOMAIN.as_bytes(), derived.as_mut())
        .expect("32-byte HKDF output");
    XChaCha20Poly1305::new_from_slice(derived.as_ref()).expect("32-byte derived key")
}

/// Write a full sealed index. Use a fresh kit ID for every invocation.
/// The caller must not publish the destination unless this returns success.
pub fn write_index<'a>(
    mut writer: impl Write,
    kit_id: &str,
    kek: &impl Kek,
    entries: impl IntoIterator<Item = &'a Entry>,
) -> Result<(), Error> {
    check_id(kit_id)?;
    writer.write_all(MAGIC).map_err(|_| Error::Io)?;
    let (version, key) = kek.active();
    let mut framer = Framer {
        writer,
        kit_id,
        cipher: cipher(key),
        version,
        number: 0,
        slice: Zeroizing::new(Vec::with_capacity(PLAIN_MAX)),
    };
    for entry in entries {
        ciborium::into_writer(entry, &mut framer).map_err(|e| match e {
            ciborium::ser::Error::Io(_) => Error::Io,
            _ => Error::Format,
        })?;
    }
    framer.emit(1)?;
    framer.writer.flush().map_err(|_| Error::Io)
}

struct Framer<'a, W> {
    writer: W,
    kit_id: &'a str,
    cipher: XChaCha20Poly1305,
    version: u32,
    number: u64,
    slice: Zeroizing<Vec<u8>>,
}

impl<W: Write> Framer<'_, W> {
    fn emit(&mut self, flags: u8) -> Result<(), Error> {
        let mut body =
            Zeroizing::new(zstd::bulk::compress(&self.slice, 3).map_err(|_| Error::Compression)?);
        let mut nonce = [0u8; 24];
        SystemRng.fill_bytes(&mut nonce).map_err(|_| Error::Io)?;
        let tag = self
            .cipher
            .encrypt_inout_detached(
                &XNonce::from(nonce),
                aad(self.kit_id, self.number, flags).as_bytes(),
                body.as_mut_slice().into(),
            )
            .map_err(|_| Error::Authentication)?;
        let len = u32::try_from(body.len() + PREFIX + TAG).map_err(|_| Error::Format)?;
        self.writer
            .write_all(&[flags])
            .and_then(|_| self.writer.write_all(&len.to_be_bytes()))
            .and_then(|_| self.writer.write_all(&self.version.to_be_bytes()))
            .and_then(|_| self.writer.write_all(&[1]))
            .and_then(|_| self.writer.write_all(&nonce))
            .and_then(|_| self.writer.write_all(&body))
            .and_then(|_| self.writer.write_all(tag.as_slice()))
            .map_err(|_| Error::Io)?;
        self.slice.as_mut_slice().zeroize();
        self.slice.clear();
        self.number = self.number.checked_add(1).ok_or(Error::Format)?;
        Ok(())
    }
}

impl<W: Write> Write for Framer<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut rest = bytes;
        while !rest.is_empty() {
            if self.slice.len() == PLAIN_MAX {
                self.emit(0).map_err(io::Error::other)?;
            }
            let n = rest.len().min(PLAIN_MAX - self.slice.len());
            self.slice.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn next_frame(reader: &mut impl Read) -> Result<([u8; 5], Zeroizing<Vec<u8>>), Error> {
    let mut header = [0; 5];
    reader.read_exact(&mut header).map_err(|_| Error::Format)?;
    let len = u32::from_be_bytes(header[1..].try_into().expect("length field")) as usize;
    if header[0] > 1
        || !(PREFIX + TAG..=PREFIX + TAG + zstd::zstd_safe::compress_bound(PLAIN_MAX))
            .contains(&len)
    {
        return Err(Error::Format);
    }
    let mut body = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut body).map_err(|_| Error::Format)?;
    Ok((header, body))
}

fn fingerprint(header: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(header);
    hash.update(body);
    hash.finalize().into()
}

fn open_frame<'a>(
    body: &'a mut [u8],
    header: [u8; 5],
    kit_id: &str,
    number: u64,
    kek: &impl Kek,
) -> Result<&'a [u8], Error> {
    if body[4] != 1 {
        return Err(Error::Format);
    }
    let version = u32::from_be_bytes(body[..4].try_into().expect("version field"));
    let key = kek.version(version).ok_or(Error::Authentication)?;
    let (prefix, tail) = body.split_at_mut(PREFIX);
    let (packed, tag) = tail.split_at_mut(tail.len() - TAG);
    let nonce = <[u8; 24]>::try_from(&prefix[5..]).expect("nonce field");
    let tag = <[u8; 16]>::try_from(&*tag).expect("tag field");
    cipher(key)
        .decrypt_inout_detached(
            &XNonce::from(nonce),
            aad(kit_id, number, header[0]).as_bytes(),
            packed.into(),
            &Tag::from(tag),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(packed)
}

/// Authenticate a complete stream before interpreting any CBOR, then parse
/// an authenticated second pass. Fingerprints pin the exact bytes to the
/// first pass even if the underlying seekable source changes between reads.
/// No plaintext is persisted by the reader.
pub fn read_index(
    mut reader: impl Read + Seek,
    kit_id: &str,
    kek: &impl Kek,
) -> Result<Vec<Entry>, Error> {
    check_id(kit_id)?;
    let mut magic = [0; 4];
    reader.read_exact(&mut magic).map_err(|_| Error::Format)?;
    if &magic != MAGIC {
        return Err(Error::Format);
    }
    let start = reader.stream_position().map_err(|_| Error::Io)?;
    let mut frames = Vec::new();
    loop {
        let (header, mut body) = next_frame(&mut reader)?;
        let number = u64::try_from(frames.len()).map_err(|_| Error::Format)?;
        let digest = fingerprint(&header, &body);
        open_frame(&mut body, header, kit_id, number, kek)?;
        frames.push(digest);
        if header[0] == 1 {
            if reader.read(&mut [0]).map_err(|_| Error::Io)? != 0 {
                return Err(Error::Format);
            }
            break;
        }
    }
    reader
        .seek(io::SeekFrom::Start(start))
        .map_err(|_| Error::Io)?;
    let mut plain = BufReader::new(PlainFrames {
        reader,
        kit_id,
        kek,
        frames: &frames,
        number: 0,
        slice: Zeroizing::new(vec![]),
        offset: 0,
    });
    let mut entries = Vec::new();
    while !plain.fill_buf().map_err(|_| Error::Format)?.is_empty() {
        entries.push(ciborium::from_reader(&mut plain).map_err(|_| Error::Format)?);
    }
    Ok(entries)
}

struct PlainFrames<'a, R, K> {
    reader: R,
    kit_id: &'a str,
    kek: &'a K,
    frames: &'a [[u8; 32]],
    number: usize,
    slice: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl<R: Read, K: Kek> PlainFrames<'_, R, K> {
    fn next_slice(&mut self) -> Result<bool, Error> {
        let Some(expected) = self.frames.get(self.number) else {
            return Ok(false);
        };
        let (header, mut body) = next_frame(&mut self.reader)?;
        if &fingerprint(&header, &body) != expected {
            return Err(Error::Authentication);
        }
        let compressed = open_frame(&mut body, header, self.kit_id, self.number as u64, self.kek)?;
        if zstd::zstd_safe::find_frame_compressed_size(compressed)
            .map_err(|_| Error::Compression)?
            != compressed.len()
        {
            return Err(Error::Compression);
        }
        let mut decoder = zstd::bulk::Decompressor::new().map_err(|_| Error::Compression)?;
        decoder.window_log_max(22).map_err(|_| Error::Compression)?;
        self.slice = Zeroizing::new(
            decoder
                .decompress(compressed, PLAIN_MAX)
                .map_err(|_| Error::Compression)?,
        );
        self.offset = 0;
        self.number += 1;
        Ok(true)
    }
}

impl<R: Read, K: Kek> Read for PlainFrames<'_, R, K> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.offset == self.slice.len() {
            if !self.next_slice().map_err(io::Error::other)? {
                return Ok(0);
            }
        }
        let n = out.len().min(self.slice.len() - self.offset);
        out[..n].copy_from_slice(&self.slice[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}
