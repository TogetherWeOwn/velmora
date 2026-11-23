//! Private CLI staging: publish completed files without clobbering paths.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use velmora::rng::{FillRandom, SystemRng};
use velmora_kit::Error;

pub struct Staged {
    destination: PathBuf,
    temporary: PathBuf,
    pub file: File,
}

impl Staged {
    pub fn new(destination: &Path) -> Result<Self, Error> {
        let parent = destination.parent().ok_or(Error::Io)?;
        let mut suffix = [0; 16];
        SystemRng.fill_bytes(&mut suffix).map_err(|_| Error::Io)?;
        let mut name = String::from(".vki-attempt-");
        for byte in suffix {
            write!(&mut name, "{byte:02x}").expect("format into String");
        }
        let temporary = parent.join(name);
        let mut options = File::options();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&temporary).map_err(|_| Error::Io)?;
        Ok(Self {
            destination: destination.to_owned(),
            temporary,
            file,
        })
    }

    pub fn reopen(&self) -> Result<File, Error> {
        File::open(&self.temporary).map_err(|_| Error::Io)
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

/// Stage in the caller's private output directory; link final names only
/// after each staged file has synced. Publish the index last. On a failed
/// link, unwind only earlier links created by this invocation.
pub fn publish(outputs: &[&Staged]) -> Result<(), Error> {
    for output in outputs {
        output.file.sync_all().map_err(|_| Error::Io)?;
    }
    let mut linked = Vec::new();
    for output in outputs {
        if fs::hard_link(&output.temporary, &output.destination).is_err() {
            for link in linked {
                let _ = fs::remove_file(link);
            }
            return Err(Error::Io);
        }
        linked.push(&output.destination);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn failed_publication_preserves_existing_file_and_cleans_earlier_links() {
        let mut nonce = [0; 8];
        SystemRng.fill_bytes(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("velmora-kit-{}", u64::from_be_bytes(nonce)));
        fs::create_dir(&dir).unwrap();
        let index_path = dir.join("index");
        let listing_path = dir.join("listing");
        fs::write(&index_path, b"existing").unwrap();
        let mut listing = Staged::new(&listing_path).unwrap();
        let mut index = Staged::new(&index_path).unwrap();
        listing.file.write_all(b"new listing").unwrap();
        index.file.write_all(b"new index").unwrap();
        assert_eq!(publish(&[&listing, &index]).unwrap_err(), Error::Io);
        assert!(!listing_path.exists());
        assert_eq!(fs::read(&index_path).unwrap(), b"existing");
        drop((listing, index));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_file(&index_path).unwrap();
        fs::remove_dir(&dir).unwrap();
    }
}
