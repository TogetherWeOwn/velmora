//! The tenant chain `m/t/<tenant>/<seq>` in R2: names, head, reader and
//! writer.
//!
//! Each record is put once, at exactly the next seq, so the chain has no
//! gaps and the newest record is the tenant's state. The record decides;
//! every store (units, directory) is written after it and holds a copy.
//!
//! # Names
//!
//! `m/t/<tenant>/<seq>`, the seq as 20 decimal digits, so that a listing
//! in key order is a listing in seq order. The first record is seq 1.
//! The name and the sealed door part both carry the tenant and the seq; a
//! record whose door part names another tenant or another seq than its
//! name is refused, never read as the other one.
//!
//! # Finding the head
//!
//! A reader lists with `start_after` set to the last seq it knows, never
//! from seq 1. Every name it lists must be the next seq of the one
//! before it: a gap, or a name that is not a record of this chain under
//! the prefix, means the chain is damaged, and the reader fails closed.
//!
//! # Writing
//!
//! [`TenantChain::write`] reads the head, validates the change against it
//! ([`super::transition::next`]), seals the new record and puts it with
//! put-if-absent at the head's seq + 1. A lost put means another writer
//! took that seq: it reads the head again and validates the change again.
//! After [`MAX_PUT_TRIES`] lost puts it answers [`ChainError::Busy`],
//! which a caller turns into `503` with `Retry-After`.
//!
//! A put whose answer was lost but that did land is found on the retry as
//! the head. The change is then validated against its own record: a hold
//! or a `restoring` entry answers "unchanged", a claim answers
//! `claim_open`. Turning that into the first call's answer is the
//! idempotency layer's work (the management plane), not the chain's.

#![allow(async_fn_in_trait)]

use zeroize::Zeroizing;

use super::record::{Lifecycle, TenantDoor, TenantId, TenantPrivate, TenantRecord, RECORD_FORMAT};
use super::transition::{next, Actor, Change, Outcome, Refusal};
use crate::types::{BridgeError, UnixMs};

type BResult<T> = crate::types::Result<T>;

/// The prefix of every tenant chain.
pub const TENANT_CHAIN_PREFIX: &str = "m/t/";

/// How many lost puts a write takes before it answers [`ChainError::Busy`].
pub const MAX_PUT_TRIES: u32 = 3;

/// The page size of a head listing.
const LIST_PAGE: u32 = 1000;

/// The width of a seq in a record name.
const SEQ_DIGITS: usize = 20;

/// The R2 operations the chain needs. Put-if-absent is what makes a seq
/// one writer's: R2's conditional put on "no object" (verify the binding
/// form when the adapter is built).
pub trait RecordStore {
    /// Stores `bytes` at `key` only if no object is there. `true` = this
    /// call stored it; `false` = an object was already there and nothing
    /// was written.
    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>) -> BResult<bool>;
    /// `None` = absent.
    async fn get(&self, key: &str) -> BResult<Option<Vec<u8>>>;
    /// Up to `limit` keys that start with `prefix` and sort after
    /// `start_after`, in key order. Fewer than `limit` = no more keys.
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> BResult<Vec<String>>;
}

/// The two-part seal of a control record: the door part under
/// the control key, the private part under a key derived from the
/// tenant's key (for tenant 0, from the KEK), both bound to the record
/// name and to each other by one header that names the key version of the
/// private part. The keys are not this module's: an adapter in the crypto
/// layer implements this port.
pub trait ControlSeal {
    /// Seals the two parts of the record stored under `name`.
    fn seal(&self, name: &str, tenant: &TenantId, door: &[u8], private: &[u8]) -> BResult<Vec<u8>>;
    /// Opens the record stored under `name`. The door part opens or the
    /// call fails. The private part is `None` when its key is not there
    /// any more (a retired version, a shredded tenant).
    fn open(&self, name: &str, tenant: &TenantId, sealed: &[u8]) -> BResult<OpenedParts>;
}

/// The plaintext of an opened control record.
pub struct OpenedParts {
    pub door: Vec<u8>,
    pub private: Option<Zeroizing<Vec<u8>>>,
}

/// A record as it was read: the door part always, the private part when
/// it opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRecord {
    pub door: TenantDoor,
    pub private: Option<TenantPrivate>,
}

/// Why a chain call did not complete.
#[derive(Debug)]
pub enum ChainError {
    /// The change was refused against the head. Nothing was written.
    Refused(Refusal),
    /// Another writer took the seq [`MAX_PUT_TRIES`] times in a row.
    Busy,
    /// A record of the chain is missing, out of order, or does not say
    /// what its name says. The reader fails closed and pages.
    Damaged(&'static str),
    /// The head's private part did not open, so no record can follow it.
    PrivateUnreadable,
    /// The store or the seal failed.
    Store(BridgeError),
}

impl From<BridgeError> for ChainError {
    fn from(e: BridgeError) -> Self {
        ChainError::Store(e)
    }
}

/// What a write did.
#[derive(Clone, Debug, PartialEq)]
pub enum Written {
    /// This record was put at its seq.
    Wrote(TenantRecord),
    /// The head already carries the change: nothing was written. The
    /// caller still applies the head to its stores before it answers.
    Unchanged(ReadRecord),
}

/// The directory of a tenant's chain: `m/t/<tenant>/`.
pub fn chain_prefix(tenant: &TenantId) -> String {
    format!("{TENANT_CHAIN_PREFIX}{}/", tenant.as_str())
}

/// The name of record `seq` of a tenant's chain.
pub fn record_key(tenant: &TenantId, seq: u64) -> String {
    format!("{}{seq:0SEQ_DIGITS$}", chain_prefix(tenant))
}

/// The seq of a record name of `tenant`'s chain; `None` for any other
/// name.
pub fn record_seq(tenant: &TenantId, key: &str) -> Option<u64> {
    let digits = key.strip_prefix(&chain_prefix(tenant))?;
    if digits.len() != SEQ_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|&seq| seq > 0)
}

/// The tenant chain over a record store and a seal.
pub struct TenantChain<'a, S, C> {
    pub store: &'a S,
    pub seal: &'a C,
}

impl<S: RecordStore, C: ControlSeal> TenantChain<'_, S, C> {
    /// The seq of the newest record, listing after `known` (0 = from the
    /// start). `None` = the tenant has no chain. A `known` above the head
    /// is damage: the caller knew a record that is not there.
    pub async fn head_seq(&self, tenant: &TenantId, known: u64) -> Result<Option<u64>, ChainError> {
        let prefix = chain_prefix(tenant);
        let mut after = match known {
            0 => String::new(),
            n => record_key(tenant, n),
        };
        let mut last = known;
        loop {
            let keys = self.store.list(&prefix, &after, LIST_PAGE).await?;
            for key in &keys {
                match record_seq(tenant, key) {
                    Some(seq) if seq == last + 1 => last = seq,
                    _ => return Err(ChainError::Damaged("chain_gap_or_stray_name")),
                }
            }
            if (keys.len() as u32) < LIST_PAGE {
                break;
            }
            match keys.last() {
                Some(key) => after = key.clone(),
                None => break,
            }
        }
        match last {
            0 => Ok(None),
            n => Ok(Some(n)),
        }
    }

    /// Reads and checks record `seq`. `None` = no such record.
    pub async fn read(
        &self,
        tenant: &TenantId,
        seq: u64,
    ) -> Result<Option<ReadRecord>, ChainError> {
        let name = record_key(tenant, seq);
        let Some(sealed) = self.store.get(&name).await? else {
            return Ok(None);
        };
        let opened = self.seal.open(&name, tenant, &sealed)?;
        let door: TenantDoor =
            serde_json::from_slice(&opened.door).map_err(|_| ChainError::Damaged("door_part"))?;
        if door.v != RECORD_FORMAT {
            return Err(ChainError::Damaged("record_format"));
        }
        if &door.tenant != tenant || door.seq != seq {
            // The name and the envelope disagree: never read it as either.
            return Err(ChainError::Damaged("record_names_another"));
        }
        let private = match opened.private {
            None => None,
            Some(bytes) => {
                let p: TenantPrivate = serde_json::from_slice(&bytes)
                    .map_err(|_| ChainError::Damaged("private_part"))?;
                if p.v != RECORD_FORMAT {
                    return Err(ChainError::Damaged("record_format"));
                }
                Some(p)
            }
        };
        Ok(Some(ReadRecord { door, private }))
    }

    /// The newest record, listing after `known`.
    pub async fn head(
        &self,
        tenant: &TenantId,
        known: u64,
    ) -> Result<Option<ReadRecord>, ChainError> {
        let Some(seq) = self.head_seq(tenant, known).await? else {
            return Ok(None);
        };
        match self.read(tenant, seq).await? {
            Some(record) => Ok(Some(record)),
            // Listed a moment ago and gone now, or `known` above the head.
            None => Err(ChainError::Damaged("head_missing")),
        }
    }

    /// Validates `change` against the head and writes the record that
    /// follows it. See the [module](self).
    pub async fn write(
        &self,
        tenant: &TenantId,
        change: &Change,
        actor: Actor,
        now: UnixMs,
        known: u64,
    ) -> Result<Written, ChainError> {
        let mut known = known;
        for _ in 0..MAX_PUT_TRIES {
            let head = self.head(tenant, known).await?;
            let current = match &head {
                None => None,
                Some(read) => Some(writable(read)?),
            };
            let record = match next(tenant, current.as_ref(), change, actor, now) {
                Err(refusal) => return Err(ChainError::Refused(refusal)),
                Ok(Outcome::Unchanged) => {
                    let head = head.expect("a change is unchanged only against a head");
                    return Ok(Written::Unchanged(head));
                }
                Ok(Outcome::Next(record)) => record,
            };
            let name = record_key(tenant, record.door.seq);
            let door =
                serde_json::to_vec(&record.door).map_err(|_| ChainError::Damaged("encode"))?;
            let private = Zeroizing::new(
                serde_json::to_vec(&record.private).map_err(|_| ChainError::Damaged("encode"))?,
            );
            let sealed = self.seal.seal(&name, tenant, &door, &private)?;
            if self.store.put_if_absent(&name, sealed).await? {
                return Ok(Written::Wrote(record));
            }
            // Another writer took this seq: read on from it.
            known = record.door.seq;
        }
        Err(ChainError::Busy)
    }
}

/// The head as a record a change can follow. Its private part must have
/// opened, or the next record could not carry it; a shredding or
/// shredded tenant has none that matters.
fn writable(read: &ReadRecord) -> Result<TenantRecord, ChainError> {
    let private = match (&read.private, read.door.lifecycle) {
        (Some(p), _) => p.clone(),
        (None, Lifecycle::Shredding | Lifecycle::Shredded) => TenantPrivate {
            v: RECORD_FORMAT,
            external_ref: None,
        },
        (None, _) => return Err(ChainError::PrivateUnreadable),
    };
    Ok(TenantRecord {
        door: read.door.clone(),
        private,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_names() {
        let t = TenantId::parse("t_00000000000000a1").unwrap();
        assert_eq!(chain_prefix(&t), "m/t/t_00000000000000a1/");
        assert_eq!(
            record_key(&t, 1),
            "m/t/t_00000000000000a1/00000000000000000001"
        );
        assert_eq!(record_seq(&t, &record_key(&t, 42)), Some(42));
        assert_eq!(record_seq(&t, &record_key(&t, u64::MAX)), Some(u64::MAX));
        let other = TenantId::parse("t_00000000000000b2").unwrap();
        assert_eq!(record_seq(&other, &record_key(&t, 1)), None);
        for bad in [
            "m/t/t_00000000000000a1/1",
            "m/t/t_00000000000000a1/00000000000000000000",
            "m/t/t_00000000000000a1/0000000000000000001x",
            "m/t/t_00000000000000a1/000000000000000000001",
        ] {
            assert_eq!(record_seq(&t, bad), None, "{bad}");
        }
        // Not a name of any other record family, and never deleted.
        let key = record_key(&t, 1);
        assert!(crate::recovery::record_name(&key).is_none());
        assert!(crate::recovery::is_protected_key(&key));
        assert!(!key.starts_with(crate::recovery::TENANT_KEY_PREFIX));
        assert!(!key.starts_with(crate::recovery::REVOKED_KEY_PREFIX));
        // Tenant 0's chain sits beside the others.
        assert_eq!(
            record_key(&TenantId::zero(), 7),
            "m/t/t_0000000000000000/00000000000000000007"
        );
    }
}
