//! The store that control records are written to, with the one write a chain
//! needs: put if absent.
//!
//! [`crate::ports::BlobStore`] has no conditional put, and its `put`
//! takes the metadata of a ciphertext blob. Control records need neither
//! that metadata nor an overwrite, so they get their own small port. The
//! R2 adapter implements it with a put conditioned on no object existing
//! under the name (R2 `onlyIf`, verify on the deployed binding); the
//! in-memory one is [`MemRecords`].

use crate::types::Result;

/// A store of put-once records.
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
}

#[cfg(feature = "testkit")]
pub use mem::MemRecords;

#[cfg(feature = "testkit")]
mod mem {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    use super::RecordStore;
    use crate::types::{BridgeError, Result};

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
        puts: Cell<u64>,
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
