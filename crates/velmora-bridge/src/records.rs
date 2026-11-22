//! The store that control records are written to, with the one write a chain
//! needs: put if absent.
//!
//! [`crate::ports::BlobStore`] has no conditional put, and its `put`
//! takes the metadata of a ciphertext blob. Control records need neither
//! that metadata nor an overwrite, so they get their own small port. The
//! R2 adapter implements it with a put conditioned on no object existing
//! under the name (R2 `onlyIf`, verify on the deployed binding); the
//! in-memory one is [`MemRecords`].
//!
//! One kind of record is replaced: a route record `m/kr/<akid>`, by the
//! owner move and its undo only ([`crate::keys::routes::replace_route`]).
//! That replace is conditioned on the ETag the caller read
//! ([`RecordStore::get_tagged`], [`RecordStore::replace_if_match`]; R2
//! `onlyIf` with `etagMatches`).

use crate::types::{BridgeError, Result};

/// A store of put-once records (and the one conditional replace the route
/// records need).
#[allow(async_fn_in_trait)]
pub trait RecordStore {
    /// Stores `bytes` under `name` only if nothing is stored there.
    /// `Ok(true)`: stored by this call. `Ok(false)`: a blob was already
    /// there, and it is left as it was. An `Err` says nothing about
    /// whether the bytes were stored; the caller reads the name back.
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool>;
    /// The bytes under `name`; `None` when absent.
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>>;
    /// Up to `limit` names that start with `prefix` and sort after
    /// `start_after`, in name order. Fewer than `limit` = no more names:
    /// an adapter whose store may answer a short page while more names
    /// exist (R2 with `truncated` set) pages on itself before it answers.
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>>;
    /// Whether something is stored under `name`. An adapter with a cheaper
    /// check (a HEAD) overrides it.
    async fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.get(name).await?.is_some())
    }
    /// The bytes under `name` with the ETag the store holds for them;
    /// `None` when absent. The ETag changes whenever the bytes do. The
    /// default refuses: a store that cannot name an ETag cannot replace.
    async fn get_tagged(&self, name: &str) -> Result<Option<Tagged>> {
        let _ = name;
        Err(ERR_NO_REPLACE)
    }
    /// Stores `bytes` under `name` only if a blob is stored there and its
    /// ETag is still `etag`. `Ok(true)`: replaced by this call.
    /// `Ok(false)`: nothing is stored under `name`, or its ETag is
    /// another one; it is left as it was. An `Err` says nothing about
    /// whether the bytes were stored; the caller reads the name back. The
    /// default refuses, and stores nothing.
    async fn replace_if_match(&self, name: &str, etag: &str, bytes: Vec<u8>) -> Result<bool> {
        let _ = (name, etag, bytes);
        Err(ERR_NO_REPLACE)
    }
}

/// The answer of a store without [`RecordStore::get_tagged`] or
/// [`RecordStore::replace_if_match`].
const ERR_NO_REPLACE: BridgeError = BridgeError::Invalid("record store has no conditional replace");

/// Bytes read with their ETag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tagged {
    pub bytes: Vec<u8>,
    pub etag: String,
}

impl<T: RecordStore> RecordStore for &T {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        (**self).put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        (**self).get(name).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        (**self).list(prefix, start_after, limit).await
    }
    async fn exists(&self, name: &str) -> Result<bool> {
        (**self).exists(name).await
    }
    async fn get_tagged(&self, name: &str) -> Result<Option<Tagged>> {
        (**self).get_tagged(name).await
    }
    async fn replace_if_match(&self, name: &str, etag: &str, bytes: Vec<u8>) -> Result<bool> {
        (**self).replace_if_match(name, etag, bytes).await
    }
}

#[cfg(feature = "testkit")]
pub use mem::MemRecords;

#[cfg(feature = "testkit")]
mod mem {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    use sha2::{Digest, Sha256};

    use super::{RecordStore, Tagged};
    use crate::types::{BridgeError, Result};

    /// The ETag of `bytes`: a digest of the bytes, like R2's MD5 of a
    /// single-part body, so equal bytes carry equal tags.
    fn etag_of(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// In-memory [`RecordStore`] with faults to inject. Single-threaded,
    /// like the Worker.
    #[derive(Default)]
    pub struct MemRecords {
        records: RefCell<BTreeMap<String, Vec<u8>>>,
        /// Puts under these prefixes fail before storing.
        refuse: RefCell<Vec<String>>,
        /// The next N puts store their bytes and then answer an error,
        /// as a put whose answer was lost does.
        lose_answers: Cell<u32>,
        /// Lists fail while set.
        refuse_lists: Cell<bool>,
        /// The next N replaces store their bytes (when the ETag matches)
        /// and then answer an error.
        lose_replace_answers: Cell<u32>,
        puts: Cell<u64>,
        replaces: Cell<u64>,
        lists: Cell<u64>,
    }

    impl MemRecords {
        pub fn new() -> Self {
            Self::default()
        }

        /// Every put under `prefix` fails and stores nothing, until
        /// [`Self::allow`].
        pub fn refuse(&self, prefix: &str) {
            self.refuse.borrow_mut().push(prefix.to_owned());
        }

        pub fn allow(&self, prefix: &str) {
            self.refuse.borrow_mut().retain(|p| p != prefix);
        }

        /// The next `n` puts store and then fail.
        pub fn lose_answers(&self, n: u32) {
            self.lose_answers.set(n);
        }

        /// The next `n` replaces store (when the ETag matches) and then
        /// fail.
        pub fn lose_replace_answers(&self, n: u32) {
            self.lose_replace_answers.set(n);
        }

        /// Replace calls so far, whatever they answered.
        pub fn replaces(&self) -> u64 {
            self.replaces.get()
        }

        pub fn refuse_lists(&self, on: bool) {
            self.refuse_lists.set(on);
        }

        pub fn names(&self) -> Vec<String> {
            self.records.borrow().keys().cloned().collect()
        }

        pub fn names_under(&self, prefix: &str) -> Vec<String> {
            self.records
                .borrow()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        }

        pub fn raw(&self, name: &str) -> Option<Vec<u8>> {
            self.records.borrow().get(name).cloned()
        }

        /// Stores bytes behind the writers' backs (planted records).
        pub fn plant(&self, name: &str, bytes: Vec<u8>) {
            self.records.borrow_mut().insert(name.to_owned(), bytes);
        }

        /// Removes a record behind the writers' backs (loss tests).
        pub fn lose(&self, name: &str) -> bool {
            self.records.borrow_mut().remove(name).is_some()
        }

        pub fn puts(&self) -> u64 {
            self.puts.get()
        }

        pub fn lists(&self) -> u64 {
            self.lists.get()
        }
    }

    impl RecordStore for MemRecords {
        async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
            self.puts.set(self.puts.get() + 1);
            if self.refuse.borrow().iter().any(|p| name.starts_with(p)) {
                return Err(BridgeError::Blob("mem: put refused".into()));
            }
            let stored = {
                let mut records = self.records.borrow_mut();
                if records.contains_key(name) {
                    false
                } else {
                    records.insert(name.to_owned(), bytes);
                    true
                }
            };
            if self.lose_answers.get() > 0 {
                self.lose_answers.set(self.lose_answers.get() - 1);
                return Err(BridgeError::Blob("mem: answer lost".into()));
            }
            Ok(stored)
        }

        async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.records.borrow().get(name).cloned())
        }

        async fn exists(&self, name: &str) -> Result<bool> {
            Ok(self.records.borrow().contains_key(name))
        }

        async fn get_tagged(&self, name: &str) -> Result<Option<Tagged>> {
            Ok(self.records.borrow().get(name).map(|b| Tagged {
                bytes: b.clone(),
                etag: etag_of(b),
            }))
        }

        async fn replace_if_match(&self, name: &str, etag: &str, bytes: Vec<u8>) -> Result<bool> {
            self.replaces.set(self.replaces.get() + 1);
            if self.refuse.borrow().iter().any(|p| name.starts_with(p)) {
                return Err(BridgeError::Blob("mem: replace refused".into()));
            }
            let stored = {
                let mut records = self.records.borrow_mut();
                match records.get_mut(name) {
                    Some(old) if etag_of(old) == etag => {
                        *old = bytes;
                        true
                    }
                    _ => false,
                }
            };
            if self.lose_replace_answers.get() > 0 {
                self.lose_replace_answers
                    .set(self.lose_replace_answers.get() - 1);
                return Err(BridgeError::Blob("mem: answer lost".into()));
            }
            Ok(stored)
        }

        async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
            self.lists.set(self.lists.get() + 1);
            if self.refuse_lists.get() {
                return Err(BridgeError::Blob("mem: list refused".into()));
            }
            Ok(self
                .records
                .borrow()
                .range::<str, _>((
                    std::ops::Bound::Excluded(start_after),
                    std::ops::Bound::Unbounded,
                ))
                .map(|(k, _)| k)
                .filter(|k| k.starts_with(prefix))
                .take(limit as usize)
                .cloned()
                .collect())
        }
    }
}
