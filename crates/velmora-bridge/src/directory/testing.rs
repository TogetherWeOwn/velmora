//! Test doubles for the directory module: an in-memory record store with
//! put-if-absent, and a seal that binds the name and the tenant without
//! any key. Native tests only (`testkit`).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::chain::{ControlSeal, OpenedParts, SealError};
use super::record::Tenant;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};

/// A hook that sees the store's objects just before a put.
type PutHook = Box<dyn FnMut(&str, &mut BTreeMap<String, Vec<u8>>)>;

/// In-memory [`RecordStore`]. A hook can run just before a put, so that a
/// test can let another writer take the seq first.
#[derive(Default)]
pub struct HookedRecords {
    objects: RefCell<BTreeMap<String, Vec<u8>>>,
    before_put: RefCell<Option<PutHook>>,
    fail_lists: Cell<bool>,
    lists: Cell<u64>,
    lost_answers: Cell<u32>,
}

impl HookedRecords {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn keys(&self) -> Vec<String> {
        self.objects.borrow().keys().cloned().collect()
    }

    pub fn raw(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.borrow().get(key).cloned()
    }

    /// Puts or replaces bytes behind the chain's back (damage tests).
    pub fn plant(&self, key: &str, bytes: Vec<u8>) {
        self.objects.borrow_mut().insert(key.to_string(), bytes);
    }

    /// Removes an object behind the chain's back (damage tests).
    pub fn lose(&self, key: &str) -> bool {
        self.objects.borrow_mut().remove(key).is_some()
    }

    /// Runs `hook` with the store's objects just before every put.
    pub fn before_put(&self, hook: impl FnMut(&str, &mut BTreeMap<String, Vec<u8>>) + 'static) {
        *self.before_put.borrow_mut() = Some(Box::new(hook));
    }

    /// The next `n` puts do what they do, then answer an error, as a put
    /// whose answer was lost.
    pub fn lose_answers(&self, n: u32) {
        self.lost_answers.set(n);
    }

    /// While set, every list fails.
    pub fn fail_lists(&self, fail: bool) {
        self.fail_lists.set(fail);
    }

    /// List calls so far.
    pub fn lists(&self) -> u64 {
        self.lists.get()
    }
}

impl RecordStore for HookedRecords {
    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>) -> Result<bool> {
        if let Some(hook) = self.before_put.borrow_mut().as_mut() {
            hook(key, &mut self.objects.borrow_mut());
        }
        let stored = {
            let mut objects = self.objects.borrow_mut();
            match objects.contains_key(key) {
                true => false,
                false => {
                    objects.insert(key.to_string(), bytes);
                    true
                }
            }
        };
        if self.lost_answers.get() > 0 {
            self.lost_answers.set(self.lost_answers.get() - 1);
            return Err(BridgeError::Blob("mem: answer lost".into()));
        }
        Ok(stored)
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.objects.borrow().get(key).cloned())
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.lists.set(self.lists.get() + 1);
        if self.fail_lists.get() {
            return Err(BridgeError::Blob("mem: list refused".into()));
        }
        Ok(self
            .objects
            .borrow()
            .keys()
            .filter(|k| k.starts_with(prefix) && k.as_str() > start_after)
            .take(limit as usize)
            .cloned()
            .collect())
    }
}

/// A [`ControlSeal`] with no key: the envelope is the name, the tenant and
/// both parts in clear, so a record moved to another name or tenant does
/// not open. With [`PlainSeal::lose_private`] the private part no longer
/// opens, as after a retired key version.
#[derive(Default)]
pub struct PlainSeal {
    private_lost: Cell<bool>,
    destroyed: RefCell<Vec<u32>>,
    unheld: RefCell<Vec<u32>>,
}

impl PlainSeal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lose_private(&self, lost: bool) {
        self.private_lost.set(lost);
    }

    /// While set, key version `v` is not held: a record under it does not
    /// open yet, as in an isolate that loaded its keys before `v`.
    pub fn not_held(&self, v: u32, unheld: bool) {
        let mut list = self.unheld.borrow_mut();
        list.retain(|x| *x != v);
        if unheld {
            list.push(v);
        }
    }

    /// Destroys tenant key version `v`, as a shred does: nothing is sealed
    /// under it any more, and what was sealed under it does not open its
    /// private part. Version 0 (no key) cannot be destroyed.
    pub fn destroy_version(&self, v: u32) {
        assert_ne!(v, 0, "version 0 is no key");
        self.destroyed.borrow_mut().push(v);
    }
}

const PLAIN_MAGIC: &[u8; 5] = b"PLN1\0";

fn push_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_be_bytes());
    out.extend_from_slice(part);
}

fn take_part<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let bad = || BridgeError::Crypto("plain seal");
    let (len, tail) = rest.split_first_chunk::<4>().ok_or_else(bad)?;
    let len = u32::from_be_bytes(*len) as usize;
    if tail.len() < len {
        return Err(bad());
    }
    let (part, tail) = tail.split_at(len);
    *rest = tail;
    Ok(part)
}

impl ControlSeal for PlainSeal {
    fn seal(
        &self,
        name: &str,
        tenant: &Tenant,
        key_version: u32,
        door: &[u8],
        private: &[u8],
    ) -> Result<Vec<u8>> {
        if self.destroyed.borrow().contains(&key_version) {
            return Err(BridgeError::Crypto("plain seal: key version destroyed"));
        }
        let mut out = PLAIN_MAGIC.to_vec();
        push_part(&mut out, name.as_bytes());
        push_part(&mut out, tenant.as_str().as_bytes());
        push_part(&mut out, &key_version.to_be_bytes());
        push_part(&mut out, door);
        push_part(&mut out, private);
        Ok(out)
    }

    fn open(
        &self,
        name: &str,
        tenant: &Tenant,
        sealed: &[u8],
    ) -> std::result::Result<OpenedParts, SealError> {
        let bad = |_| SealError::Damaged;
        let mut rest = sealed
            .strip_prefix(PLAIN_MAGIC.as_slice())
            .ok_or(SealError::Damaged)?;
        let sealed_name = take_part(&mut rest).map_err(bad)?;
        let sealed_tenant = take_part(&mut rest).map_err(bad)?;
        if sealed_name != name.as_bytes() || sealed_tenant != tenant.as_str().as_bytes() {
            return Err(SealError::Damaged);
        }
        let key_version = <[u8; 4]>::try_from(take_part(&mut rest).map_err(bad)?)
            .map(u32::from_be_bytes)
            .map_err(|_| SealError::Damaged)?;
        if self.unheld.borrow().contains(&key_version) {
            return Err(SealError::KeyNotHeld {
                version: key_version,
            });
        }
        let door = take_part(&mut rest).map_err(bad)?.to_vec();
        let private = take_part(&mut rest).map_err(bad)?.to_vec();
        if !rest.is_empty() {
            return Err(SealError::Damaged);
        }
        Ok(OpenedParts {
            door,
            private: (!self.private_lost.get() && !self.destroyed.borrow().contains(&key_version))
                .then(|| Zeroizing::new(private)),
            key_version,
        })
    }
}
