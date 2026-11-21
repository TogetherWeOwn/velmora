//! Test doubles for the directory module: an in-memory record store with
//! put-if-absent, and a seal that binds the name and the tenant without
//! any key. Native tests only (`testkit`).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::chain::{ControlSeal, OpenedParts, RecordStore};
use super::record::TenantId;
use crate::types::{BridgeError, Result};

/// A hook that sees the store's objects just before a put.
type PutHook = Box<dyn FnMut(&str, &mut BTreeMap<String, Vec<u8>>)>;

/// In-memory [`RecordStore`]. A hook can run just before a put, so that a
/// test can let another writer take the seq first.
#[derive(Default)]
pub struct MemRecords {
    objects: RefCell<BTreeMap<String, Vec<u8>>>,
    before_put: RefCell<Option<PutHook>>,
    fail_lists: Cell<bool>,
    lists: Cell<u64>,
}

impl MemRecords {
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

    /// While set, every list fails.
    pub fn fail_lists(&self, fail: bool) {
        self.fail_lists.set(fail);
    }

    /// List calls so far.
    pub fn lists(&self) -> u64 {
        self.lists.get()
    }
}

impl RecordStore for MemRecords {
    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>) -> Result<bool> {
        if let Some(hook) = self.before_put.borrow_mut().as_mut() {
            hook(key, &mut self.objects.borrow_mut());
        }
        let mut objects = self.objects.borrow_mut();
        if objects.contains_key(key) {
            return Ok(false);
        }
        objects.insert(key.to_string(), bytes);
        Ok(true)
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
}

impl PlainSeal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lose_private(&self, lost: bool) {
        self.private_lost.set(lost);
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
        tenant: &TenantId,
        key_version: u32,
        door: &[u8],
        private: &[u8],
    ) -> Result<Vec<u8>> {
        let mut out = PLAIN_MAGIC.to_vec();
        push_part(&mut out, name.as_bytes());
        push_part(&mut out, tenant.as_str().as_bytes());
        push_part(&mut out, &key_version.to_be_bytes());
        push_part(&mut out, door);
        push_part(&mut out, private);
        Ok(out)
    }

    fn open(&self, name: &str, tenant: &TenantId, sealed: &[u8]) -> Result<OpenedParts> {
        let mut rest = sealed
            .strip_prefix(PLAIN_MAGIC.as_slice())
            .ok_or(BridgeError::Crypto("plain seal"))?;
        let sealed_name = take_part(&mut rest)?;
        let sealed_tenant = take_part(&mut rest)?;
        if sealed_name != name.as_bytes() || sealed_tenant != tenant.as_str().as_bytes() {
            return Err(BridgeError::Crypto("plain seal binding"));
        }
        let key_version = <[u8; 4]>::try_from(take_part(&mut rest)?)
            .map(u32::from_be_bytes)
            .map_err(|_| BridgeError::Crypto("plain seal"))?;
        let door = take_part(&mut rest)?.to_vec();
        let private = take_part(&mut rest)?.to_vec();
        if !rest.is_empty() {
            return Err(BridgeError::Crypto("plain seal"));
        }
        Ok(OpenedParts {
            door,
            private: (!self.private_lost.get()).then(|| Zeroizing::new(private)),
            key_version,
        })
    }
}
