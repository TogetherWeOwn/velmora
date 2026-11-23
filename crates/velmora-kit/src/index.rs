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
const ENCODED_MAX: usize = 8 * 1024 * 1024;
const ITEM_MAX: usize = 16 * 1024 * 1024;
const INDEX_MAX: u64 = 8 * 1024 * 1024 * 1024;
const FRAMES_MAX: usize = 16_384;
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

fn validate_entry(entry: &Entry) -> Result<(), Error> {
    if matches!(entry, Entry::Extent(e) if e.plan_rev.is_none() && (!e.articles.is_empty() || e.parity.is_some()))
    {
        return Err(Error::Format);
    }
    Ok(())
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
        remaining: INDEX_MAX,
        item_remaining: ITEM_MAX,
    };
    for entry in entries {
        validate_entry(entry)?;
        framer.item_remaining = ITEM_MAX;
        ciborium::into_writer(entry, &mut framer).map_err(|e| match e {
            ciborium::ser::Error::Io(e) if e.kind() != io::ErrorKind::InvalidData => Error::Io,
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
    remaining: u64,
    item_remaining: usize,
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
        let len = body.len() + PREFIX + TAG;
        if len > ENCODED_MAX || self.number >= FRAMES_MAX as u64 {
            return Err(Error::Format);
        }
        let len = len as u32;
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
        if bytes.len() > self.item_remaining || bytes.len() as u64 > self.remaining {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.item_remaining -= bytes.len();
        self.remaining -= bytes.len() as u64;
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
    if header[0] > 1 || !(PREFIX + TAG..=ENCODED_MAX).contains(&len) {
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
    reader: impl Read + Seek,
    kit_id: &str,
    kek: &impl Kek,
) -> Result<Vec<Entry>, Error> {
    read_bounded(reader, kit_id, kek, ITEM_MAX as u64, INDEX_MAX)
}

fn read_bounded(
    mut reader: impl Read + Seek,
    kit_id: &str,
    kek: &impl Kek,
    item_max: u64,
    index_max: u64,
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
        if frames.len() >= FRAMES_MAX {
            return Err(Error::Format);
        }
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
        remaining: index_max,
    });
    let mut entries = Vec::new();
    while !plain.fill_buf().map_err(|_| Error::Format)?.is_empty() {
        let entry =
            ciborium::from_reader((&mut plain).take(item_max)).map_err(|_| Error::Format)?;
        validate_entry(&entry)?;
        entries.push(entry);
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
    remaining: u64,
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
        self.remaining = self
            .remaining
            .checked_sub(self.slice.len() as u64)
            .ok_or(Error::Format)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Article, Extent, Parity, RecordRef};
    use ciborium::value::Value;
    use std::io::Cursor;

    struct Key(KekBytes);
    impl Kek for Key {
        fn active(&self) -> (u32, &KekBytes) {
            (1, &self.0)
        }
        fn version(&self, v: u32) -> Option<&KekBytes> {
            (v == 1).then_some(&self.0)
        }
    }

    #[test]
    fn frame_reader_enforces_format_length_inclusive() {
        let mut exact = vec![0; 5 + ENCODED_MAX];
        exact[0] = 1;
        exact[1..5].copy_from_slice(&(ENCODED_MAX as u32).to_be_bytes());
        assert_eq!(
            next_frame(&mut exact.as_slice()).unwrap().1.len(),
            ENCODED_MAX
        );
        let mut oversized =
            Cursor::new([&[1], &((ENCODED_MAX + 1) as u32).to_be_bytes()[..], &[0]].concat());
        assert!(matches!(next_frame(&mut oversized), Err(Error::Format)));
        assert_eq!(oversized.position(), 5);
    }

    #[test]
    fn per_item_and_total_budgets_count_actual_cbor_bytes() {
        let key = Key(KekBytes::new([7; 32]));
        let item = Entry::RecordRef(RecordRef {
            name: "m/example".into(),
            sha256: vec![1; 32],
        });
        let mut raw = vec![];
        ciborium::into_writer(&item, &mut raw).unwrap();
        let bound = raw.len() as u64;
        let mut sealed = vec![];
        write_index(&mut sealed, "budgets", &key, [&item, &item]).unwrap();
        let open = |item_max, index_max| {
            read_bounded(Cursor::new(&sealed), "budgets", &key, item_max, index_max)
        };
        assert_eq!(open(bound, bound * 2).unwrap().len(), 2);
        assert_eq!(open(bound - 1, bound * 2).unwrap_err(), Error::Format);
        assert_eq!(open(bound, bound * 2 - 1).unwrap_err(), Error::Format);
    }

    fn null_extent() -> Extent {
        Extent {
            id: "x_test".into(),
            bucket_id: "b_test".into(),
            plain_size: 1,
            cipher_size: 65,
            media_header: vec![0; 48],
            wrapped_file_key: vec![0; 73],
            plain_md5: vec![0; 16],
            plain_sha256: vec![0; 32],
            cipher_sha256: vec![0; 32],
            plan_rev: None,
            articles: vec![],
            parity: None,
            verified: None,
        }
    }

    // Use the framing layer directly so all invalid CBOR fixtures are
    // nevertheless authenticated, without bypassing the reader's validation.
    fn read_raw(value: &Value) -> Result<Vec<Entry>, Error> {
        let key = Key(KekBytes::new([4; 32]));
        let mut output = MAGIC.to_vec();
        let mut framer = Framer {
            writer: &mut output,
            kit_id: "fixture",
            cipher: cipher(key.active().1),
            version: 1,
            number: 0,
            slice: Zeroizing::new(vec![]),
            remaining: INDEX_MAX,
            item_remaining: ITEM_MAX,
        };
        ciborium::into_writer(value, &mut framer).unwrap();
        framer.emit(1).unwrap();
        read_index(Cursor::new(output), "fixture", &key)
    }

    #[test]
    fn explicit_null_plan_is_valid_but_omitted_plan_is_not() {
        let mut value = Value::serialized(&Entry::Extent(null_extent())).unwrap();
        assert_eq!(read_raw(&value).unwrap().len(), 1);
        value
            .as_map_mut()
            .unwrap()
            .retain(|(k, _)| k.as_text() != Some("plan_rev"));
        assert_eq!(read_raw(&value).unwrap_err(), Error::Format);
    }

    #[test]
    fn null_plan_rejects_articles_or_parity_independently() {
        let mut articles = null_extent();
        articles.articles.push(Article {
            message_id: "article".into(),
            newsgroup: "alt.binaries.test".into(),
            payload_sha256: vec![0; 32],
            yenc_name: None,
        });
        let mut parity = null_extent();
        parity.parity = Some(Parity {
            k: 1,
            shard_len: 66,
            rows: vec![],
        });
        for e in [articles, parity] {
            let entry = Entry::Extent(e);
            assert_eq!(
                read_raw(&Value::serialized(&entry).unwrap()).unwrap_err(),
                Error::Format
            );
            let key = Key(KekBytes::new([4; 32]));
            assert_eq!(
                write_index(vec![], "fixture", &key, [&entry]).unwrap_err(),
                Error::Format
            );
        }
    }
}
