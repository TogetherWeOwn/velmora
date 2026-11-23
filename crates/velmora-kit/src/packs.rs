use crate::{eligible_record, Entry, Error};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

const MAX_RECORD: u64 = 64 * 1024 * 1024;
const MAX_UNPACKED_PACK: u64 = 8 * 1024 * 1024 * 1024;

/// Verify exact names and stored bytes of all packs against an index that
/// has already passed [`crate::read_index`]. Nothing is extracted, and
/// auxiliary records remain opaque. Use the manifest to check outer file
/// sizes and hashes separately.
pub fn verify_packs<R: Read>(
    packs: impl IntoIterator<Item = R>,
    entries: &[Entry],
) -> Result<(), Error> {
    let mut expected = BTreeMap::new();
    for entry in entries {
        let Entry::RecordRef(r) = entry else { continue };
        if !eligible_record(&r.name)
            || r.sha256.len() != 32
            || expected
                .insert(r.name.as_str(), r.sha256.as_slice())
                .is_some()
        {
            return Err(Error::Record);
        }
    }
    for pack in packs {
        let mut decoder = zstd::stream::read::Decoder::new(pack).map_err(|_| Error::Compression)?;
        decoder.window_log_max(23).map_err(|_| Error::Compression)?;
        let mut archive = tar::Archive::new(decoder.take(MAX_UNPACKED_PACK + 1));
        // Walk past end padding so trailing malicious members cannot hide
        // behind an early zero block. Every non-padding member must match.
        archive.set_ignore_zeros(true);
        // Raw entries expose GNU/PAX extension headers without buffering
        // their bodies. Only standalone regular USTAR headers are allowed.
        for member in archive.entries().map_err(|_| Error::Format)?.raw(true) {
            let mut member = member.map_err(|_| Error::Format)?;
            if member.header().as_ustar().is_none()
                || !member.header().entry_type().is_file()
                || member.size() > MAX_RECORD
            {
                return Err(Error::Format);
            }
            let name = member.path_bytes();
            let name = std::str::from_utf8(&name).map_err(|_| Error::Format)?;
            let digest = expected.remove(name).ok_or(Error::Coverage)?;
            let mut hash = Sha256::new();
            let bytes = io::copy(&mut member, &mut HashSink(&mut hash)).map_err(|_| Error::Io)?;
            if bytes != member.size() || hash.finalize().as_slice() != digest {
                return Err(Error::Coverage);
            }
        }
        if archive.into_inner().limit() == 0 {
            return Err(Error::Format);
        }
    }
    if !expected.is_empty() {
        return Err(Error::Coverage);
    }
    Ok(())
}

struct HashSink<'a>(&'a mut Sha256);
impl Write for HashSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
