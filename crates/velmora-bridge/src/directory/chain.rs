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
//! A change that replaces a whole field (limits, features, units) names
//! the head it was built from, so on the new head it is refused
//! (`stale_base`) and its caller builds it again.
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

use super::record::{Lifecycle, Tenant, TenantDoor, TenantPrivate, TenantRecord, RECORD_FORMAT};
use super::transition::{next, Actor, Change, Outcome, Refusal};
use crate::records::RecordStore;
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

/// The two-part seal of a control record: the door part under
/// the control key, the private part under a key derived from the
/// tenant's key (for tenant 0, from the KEK), both bound to the record
/// name and to each other by one header that names the key version of the
/// private part. The keys are not this module's: an adapter in the crypto
/// layer implements this port.
///
/// The private part of a tenant record is sealed under the tenant key
/// version that the record itself names (`tk_version`), so the record
/// that commits a new version is the first under it and is the tenant
/// chain's re-statement under that version. Two kinds of record have no
/// tenant key and seal an empty private part under `key_version` 0: the
/// records of a tenant other than tenant 0 from before its version 1, and
/// the `shredded` stub, written after every version was destroyed. For
/// tenant 0 the adapter seals under the KEK and names the KEK version in
/// the header.
///
/// The port opens with the keys it holds and does no I/O. A record that
/// does not open is damage, and the chain reports it as such; a key
/// version that the port does not hold yet is a failure that may pass
/// ([`SealError::KeyNotHeld`]).
pub trait ControlSeal {
    /// Seals the two parts of the record stored under `name`, the private
    /// part under tenant key version `key_version`.
    fn seal(
        &self,
        name: &str,
        tenant: &Tenant,
        key_version: u32,
        door: &[u8],
        private: &[u8],
    ) -> BResult<Vec<u8>>;
    /// Opens the record stored under `name`. The door part opens or the
    /// call fails. The private part is `None` only when its key version
    /// is gone for good (retired, or destroyed by a shred): a head whose
    /// private part is `None` takes no next record.
    fn open(&self, name: &str, tenant: &Tenant, sealed: &[u8]) -> Result<OpenedParts, SealError>;
}

/// Why a control record did not open.
#[derive(Debug)]
pub enum SealError {
    /// It does not open: a changed byte, another name or tenant, a key
    /// that does not match. Damage of this record.
    Damaged,
    /// The key version it names is not held here yet (a version
    /// committed after this isolate loaded its keys). It may pass: load
    /// the keys again.
    KeyNotHeld { version: u32 },
    /// Any other failure. It may pass.
    Failed(BridgeError),
}

/// The plaintext of an opened control record.
pub struct OpenedParts {
    pub door: Vec<u8>,
    pub private: Option<Zeroizing<Vec<u8>>>,
    /// The key version the header names for the private part.
    pub key_version: u32,
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
    /// The record names a key version this isolate does not hold yet.
    /// It may pass: load the keys again.
    KeyNotHeld { version: u32 },
    /// The head's private part did not open, so no record can follow it.
    /// It pages: a live tenant whose key version is gone.
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
pub fn chain_prefix(tenant: &Tenant) -> String {
    format!("{TENANT_CHAIN_PREFIX}{}/", tenant.as_str())
}

/// The name of record `seq` of a tenant's chain.
pub fn record_key(tenant: &Tenant, seq: u64) -> String {
    format!("{}{seq:0SEQ_DIGITS$}", chain_prefix(tenant))
}

/// The seq of a record name of `tenant`'s chain; `None` for any other
/// name.
pub fn record_seq(tenant: &Tenant, key: &str) -> Option<u64> {
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
    pub async fn head_seq(&self, tenant: &Tenant, known: u64) -> Result<Option<u64>, ChainError> {
        let prefix = chain_prefix(tenant);
        // From the record before `known`, so that `known` itself must be
        // listed: a known seq above the head is damage, not the head.
        let mut last = known.saturating_sub(1);
        let mut after = match last {
            0 => String::new(),
            n => record_key(tenant, n),
        };
        let mut first_key = true;
        // A shred's purge deletes a chain from its first record up, and
        // leaves the stub: a gap below the first listed record is a purge
        // (done or under way) only if the chain ends in the stub.
        let mut purged = false;
        loop {
            let keys = self.store.list(&prefix, &after, LIST_PAGE).await?;
            for key in &keys {
                match record_seq(tenant, key) {
                    Some(seq) if seq == last + 1 => last = seq,
                    Some(seq) if first_key && seq > last + 1 => {
                        // A purge from below removed the record before
                        // `known` first: if it is still there, the gap is
                        // inside the chain.
                        if last > 0 && self.store.get(&record_key(tenant, last)).await?.is_some() {
                            return Err(ChainError::Damaged("chain_gap_or_stray_name"));
                        }
                        purged = true;
                        last = seq;
                    }
                    _ => return Err(ChainError::Damaged("chain_gap_or_stray_name")),
                }
                first_key = false;
            }
            if (keys.len() as u32) < LIST_PAGE {
                break;
            }
            match keys.last() {
                Some(key) => after = key.clone(),
                None => break,
            }
        }
        let head = match last {
            0 if known == 0 => return Ok(None),
            n if n >= known => n,
            _ => return Err(ChainError::Damaged("known_above_head")),
        };
        if purged {
            match self.read(tenant, head).await? {
                Some(r) if r.door.lifecycle == Lifecycle::Shredded => {}
                _ => return Err(ChainError::Damaged("chain_gap_or_stray_name")),
            }
        }
        Ok(Some(head))
    }

    /// Reads and checks record `seq`. `None` = no such record.
    pub async fn read(&self, tenant: &Tenant, seq: u64) -> Result<Option<ReadRecord>, ChainError> {
        let name = record_key(tenant, seq);
        let Some(sealed) = self.store.get(&name).await? else {
            return Ok(None);
        };
        let opened = self
            .seal
            .open(&name, tenant, &sealed)
            .map_err(|e| match e {
                SealError::Damaged => ChainError::Damaged("record_does_not_open"),
                SealError::KeyNotHeld { version } => ChainError::KeyNotHeld { version },
                SealError::Failed(e) => ChainError::Store(e),
            })?;
        let door: TenantDoor =
            serde_json::from_slice(&opened.door).map_err(|_| ChainError::Damaged("door_part"))?;
        if door.v != RECORD_FORMAT {
            return Err(ChainError::Damaged("record_format"));
        }
        if &door.tenant != tenant || door.seq != seq {
            // The name and the envelope disagree: never read it as either.
            return Err(ChainError::Damaged("record_names_another"));
        }
        if !tenant.is_zero() && opened.key_version != seal_version(&door) {
            return Err(ChainError::Damaged("private_part_version"));
        }
        let private = match opened.private {
            None => None,
            Some(bytes) => {
                let p: TenantPrivate = serde_json::from_slice(&bytes)
                    .map_err(|_| ChainError::Damaged("private_part"))?;
                if p.v != RECORD_FORMAT {
                    return Err(ChainError::Damaged("record_format"));
                }
                if keyless(&door) && p != empty_private() {
                    return Err(ChainError::Damaged("private_part_without_key"));
                }
                Some(p)
            }
        };
        Ok(Some(ReadRecord { door, private }))
    }

    /// The newest record, listing after `known`.
    pub async fn head(
        &self,
        tenant: &Tenant,
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
    ///
    /// Not for [`Change::PlaceMovedBuckets`]: that change is bound to
    /// tenant 0's head, which only [`Self::place_moved_buckets`] reads.
    pub async fn write(
        &self,
        tenant: &Tenant,
        change: &Change,
        actor: Actor,
        now: UnixMs,
        known: u64,
    ) -> Result<Written, ChainError> {
        // Both name tenant 0's head, which only the calls below read.
        if matches!(
            change,
            Change::PlaceMovedBuckets { .. } | Change::UnplaceMovedBuckets { .. }
        ) {
            return Err(ChainError::Refused(Refusal {
                status: 400,
                code: "invalid_change",
            }));
        }
        let mut known = known;
        for _ in 0..MAX_PUT_TRIES {
            match self.try_write(tenant, change, actor, now, known).await? {
                Try::Done(written) => return Ok(written),
                Try::Lost(seq) => known = seq,
            }
        }
        Err(ChainError::Busy)
    }

    /// Places the owner's buckets, moved from tenant 0 with their ids
    /// unchanged, on `unit` of `tenant` (the move's import, by the move
    /// tool). Tenant 0's head is read from its own chain here, before
    /// every try, so the change is bound to a verified head that is
    /// `moving` into `tenant`; the record names that head's seq.
    pub async fn place_moved_buckets(
        &self,
        tenant: &Tenant,
        buckets: &[String],
        unit: u32,
        now: UnixMs,
        known: u64,
    ) -> Result<Written, ChainError> {
        let mut known = known;
        for _ in 0..MAX_PUT_TRIES {
            let Some(zero) = self.head(&Tenant::Zero, 0).await? else {
                return Err(ChainError::Refused(Refusal {
                    status: 409,
                    code: "no_move_to_tenant",
                }));
            };
            let change = Change::PlaceMovedBuckets {
                buckets: buckets.to_vec(),
                unit,
                zero: Box::new(zero.door),
            };
            match self
                .try_write(tenant, &change, Actor::MoveTool, now, known)
                .await?
            {
                Try::Done(written) => return Ok(written),
                Try::Lost(seq) => known = seq,
            }
        }
        Err(ChainError::Busy)
    }

    /// Removes the placements a move put on `unit` of `tenant`: the last
    /// step of every exit of the move (AM-23), by the move tool. Tenant
    /// 0's head is read from its own chain before every try, as for
    /// [`Self::place_moved_buckets`]; the record names that head's seq.
    pub async fn unplace_moved_buckets(
        &self,
        tenant: &Tenant,
        buckets: &[String],
        unit: u32,
        now: UnixMs,
        known: u64,
    ) -> Result<Written, ChainError> {
        let mut known = known;
        for _ in 0..MAX_PUT_TRIES {
            let Some(zero) = self.head(&Tenant::Zero, 0).await? else {
                return Err(ChainError::Refused(Refusal {
                    status: 409,
                    code: "no_move_exit",
                }));
            };
            let change = Change::UnplaceMovedBuckets {
                buckets: buckets.to_vec(),
                unit,
                zero: Box::new(zero.door),
            };
            match self
                .try_write(tenant, &change, Actor::MoveTool, now, known)
                .await?
            {
                Try::Done(written) => return Ok(written),
                Try::Lost(seq) => known = seq,
            }
        }
        Err(ChainError::Busy)
    }

    /// One try: the record that follows the head, put at its seq.
    async fn try_write(
        &self,
        tenant: &Tenant,
        change: &Change,
        actor: Actor,
        now: UnixMs,
        known: u64,
    ) -> Result<Try, ChainError> {
        let head = self.head(tenant, known).await?;
        let current = match &head {
            None => None,
            Some(read) => Some(writable(read)?),
        };
        let record = match next(tenant, current.as_ref(), change, actor, now) {
            Err(refusal) => return Err(ChainError::Refused(refusal)),
            Ok(Outcome::Unchanged) => {
                let head = head.expect("a change is unchanged only against a head");
                return Ok(Try::Done(Written::Unchanged(head)));
            }
            Ok(Outcome::Next(record)) => record,
        };
        let name = record_key(tenant, record.door.seq);
        let door = serde_json::to_vec(&record.door).map_err(|_| ChainError::Damaged("encode"))?;
        let private = Zeroizing::new(
            serde_json::to_vec(&record.private).map_err(|_| ChainError::Damaged("encode"))?,
        );
        if keyless(&record.door) && record.private != empty_private() {
            return Err(ChainError::Damaged("private_part_without_key"));
        }
        let sealed = self
            .seal
            .seal(&name, tenant, seal_version(&record.door), &door, &private)?;
        let seq = record.door.seq;
        match self.store.put_if_absent(&name, sealed.clone()).await {
            Ok(true) => Ok(Try::Done(Written::Wrote(record))),
            // Another writer took this seq: read on from it.
            Ok(false) => Ok(Try::Lost(seq)),
            // An error says nothing about whether the bytes were stored:
            // read the name back. These exact bytes (the seal is never the
            // same twice) are this put's; other bytes are another writer's.
            Err(e) => match self.store.get(&name).await {
                Ok(Some(stored)) if stored == sealed => Ok(Try::Done(Written::Wrote(record))),
                Ok(Some(_)) => Ok(Try::Lost(seq)),
                Ok(None) | Err(_) => Err(e.into()),
            },
        }
    }
}

/// What one try of a write did.
// Short-lived: made and matched in one call, never stored.
#[allow(clippy::large_enum_variant)]
enum Try {
    Done(Written),
    /// The seq was taken by another writer.
    Lost(u64),
}

/// A record of a tenant other than tenant 0 from before its first key
/// version: its private part must be empty.
fn keyless(door: &TenantDoor) -> bool {
    !door.tenant.is_zero() && (door.tk_version == 0 || door.lifecycle == Lifecycle::Shredded)
}

/// The key version a record's private part is sealed under: its
/// `tk_version`, and 0 for a record with no tenant key.
fn seal_version(door: &TenantDoor) -> u32 {
    match keyless(door) {
        true => 0,
        false => door.tk_version,
    }
}

fn empty_private() -> TenantPrivate {
    TenantPrivate {
        v: RECORD_FORMAT,
        external_ref: None,
        bucket_created: None,
    }
}

/// The head as a record a change can follow. Its private part must have
/// opened, or the next record could not carry it; a shredding or
/// shredded tenant has none that matters.
fn writable(read: &ReadRecord) -> Result<TenantRecord, ChainError> {
    let private = match (&read.private, read.door.lifecycle) {
        (Some(p), _) => p.clone(),
        (None, Lifecycle::Shredding | Lifecycle::Shredded) => empty_private(),
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
        let t = Tenant::parse("t_00000000000000a1").unwrap();
        assert_eq!(chain_prefix(&t), "m/t/t_00000000000000a1/");
        assert_eq!(
            record_key(&t, 1),
            "m/t/t_00000000000000a1/00000000000000000001"
        );
        assert_eq!(record_seq(&t, &record_key(&t, 42)), Some(42));
        assert_eq!(record_seq(&t, &record_key(&t, u64::MAX)), Some(u64::MAX));
        let other = Tenant::parse("t_00000000000000b2").unwrap();
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
            record_key(&Tenant::zero(), 7),
            "m/t/t_0000000000000000/00000000000000000007"
        );
    }
}
