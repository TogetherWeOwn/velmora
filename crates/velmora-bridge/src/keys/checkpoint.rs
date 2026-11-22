//! Key-chain checkpoints `m/kc/<t>/<seq>` and the reader of the key
//! chain.
//!
//! A checkpoint states every subject of the tenant as of chain record
//! `seq`, so a reader need not walk the chain from seq 1. It is an object
//! **beside** the chain, not a seq of it: the finisher writes it when the head is
//! [`CHECKPOINT_EVERY`] records past the newest checkpoint, and no change
//! waits for one. It is built from the previous checkpoint and the
//! records after it, never from a unit's table.
//!
//! - Its door part names the seq and the SHA-256 of the chain record at
//!   that seq, so a checkpoint cannot be moved to another point of the
//!   chain; and, per subject, the door fields of a key record.
//! - Its private part, under the current tenant key, holds the private
//!   fields of every subject whose private part opened. A subject whose
//!   private part did not open is carried with its door fields only and
//!   is `disabled` wherever it is applied, until a reader whose ring
//!   holds its key opens it again from the record that holds its private
//!   part; the finisher reports such a subject as an attention
//!   condition.
//! - A reader takes the newest checkpoint that verifies, whose named
//!   record is the one in the chain and whose private part opens; with
//!   none it takes the one before, and at last the chain from seq 1.
//!   Every route gives the same table.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;

use super::chain::{parse_seq, seq_name, Chain, LIST_PAGE};
use super::record::{
    key_chain, open_key_record, Entry, KeyRecord, KeyTable, SubjectDoor, SubjectPrivate,
    SubjectStatus, TkRing,
};
use super::revocations::list_tenant_revocations;
use crate::crypto::scheme2::{
    parse_control, seal_control, ControlOwner, ControlSealer, PrivateKeyRef, TenantId,
};
use crate::ports::Kek;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};

/// Records between two checkpoints (an estimate; a dial).
pub const CHECKPOINT_EVERY: u64 = 256;

const CHECKPOINT_VERSION: u32 = 1;
const ERR_CHECKPOINT: BridgeError = BridgeError::Invalid("key checkpoint is malformed");

/// The directory of `tenant`'s checkpoints.
pub fn checkpoint_prefix(tenant: &TenantId) -> String {
    format!("m/kc/{tenant}/")
}

/// The checkpoint that covers the chain up to `seq`.
pub fn checkpoint_name(tenant: &TenantId, seq: u64) -> String {
    seq_name(&checkpoint_prefix(tenant), seq)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointDoor {
    v: u32,
    tenant: String,
    seq: u64,
    /// SHA-256 of the chain record at `seq`, lowercase hex.
    record_sha256: String,
    subjects: Vec<DoorEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DoorEntry {
    door: SubjectDoor,
    last_seq: u64,
    private_seq: u64,
    tk_version: u32,
    closes: bool,
    opened_seq: u64,
    /// Whether the private part below holds this subject.
    open: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointPrivate {
    v: u32,
    subjects: Vec<PrivateEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateEntry {
    id: String,
    private: SubjectPrivate,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seals the checkpoint of `table` (at `table.seq()`, whose chain record
/// has the bytes `record`) under the ring's current key version.
pub fn seal_checkpoint<K: Kek, T: TkRing, R: FillRandom>(
    kek: &K,
    ring: &T,
    table: &KeyTable,
    record: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let tenant = table.tenant();
    let tk = ring
        .current()
        .ok_or(BridgeError::Crypto("tenant key unavailable"))?;
    let door = CheckpointDoor {
        v: CHECKPOINT_VERSION,
        tenant: tenant.as_str().to_owned(),
        seq: table.seq(),
        record_sha256: hex(&Sha256::digest(record)),
        subjects: table
            .entries()
            .map(|e| DoorEntry {
                door: e.door.clone(),
                last_seq: e.last_seq,
                private_seq: e.private_seq,
                tk_version: e.tk_version,
                closes: e.closes,
                opened_seq: e.opened_seq,
                open: e.private.is_some(),
            })
            .collect(),
    };
    let private = CheckpointPrivate {
        v: CHECKPOINT_VERSION,
        subjects: table
            .entries()
            .filter_map(|e| {
                e.private.as_ref().map(|p| PrivateEntry {
                    id: e.door.id.clone(),
                    private: p.clone(),
                })
            })
            .collect(),
    };
    let door = serde_json::to_vec(&door).map_err(|_| ERR_CHECKPOINT)?;
    let private =
        zeroize::Zeroizing::new(serde_json::to_vec(&private).map_err(|_| ERR_CHECKPOINT)?);
    seal_control(
        kek,
        &checkpoint_name(tenant, table.seq()),
        &ControlSealer::Managed(tk),
        &door,
        Some(&private),
        rng,
    )
}

/// Opens a checkpoint stored for `seq`, given the bytes of the chain
/// record at `seq`. `Ok(None)` when it does not verify or its private
/// part does not open: the reader then tries the one before.
pub fn open_checkpoint<K: Kek, T: TkRing>(
    kek: &K,
    ring: &T,
    tenant: &TenantId,
    seq: u64,
    bytes: &[u8],
    record: &[u8],
) -> Option<KeyTable> {
    let name = checkpoint_name(tenant, seq);
    let opened = parse_control(bytes)
        .ok()?
        .open_door(kek, &name, ControlOwner::Managed(tenant))
        .ok()?;
    let door: CheckpointDoor = serde_json::from_slice(opened.door()).ok()?;
    let fits = door.v == CHECKPOINT_VERSION
        && door.tenant == tenant.as_str()
        && door.seq == seq
        && door.record_sha256 == hex(&Sha256::digest(record));
    let PrivateKeyRef::Tenant(version) = opened.private_key() else {
        return None;
    };
    if !fits {
        return None;
    }
    let private = opened.open_private_managed(ring.key(version)?).ok()?;
    let private: CheckpointPrivate = serde_json::from_slice(&private).ok()?;
    if private.v != CHECKPOINT_VERSION {
        return None;
    }
    let mut privates: BTreeMap<String, SubjectPrivate> = BTreeMap::new();
    for p in private.subjects {
        // An id twice: not a checkpoint this code wrote.
        if privates.insert(p.id, p.private).is_some() {
            return None;
        }
    }
    let mut subjects = BTreeMap::new();
    for d in door.subjects {
        let private = match d.open {
            true => Some(privates.remove(&d.door.id)?),
            false => None,
        };
        let seqs_fit = d.last_seq != 0
            && d.last_seq <= seq
            && d.private_seq != 0
            && d.private_seq <= d.last_seq
            && d.opened_seq <= d.last_seq;
        if !seqs_fit || subjects.contains_key(&d.door.id) {
            return None;
        }
        // The same rules as a record: grants aligned, ids, the secret.
        super::record::check_entry(tenant, &d.door, private.as_ref()).ok()?;
        subjects.insert(
            d.door.id.clone(),
            Entry {
                door: d.door,
                private,
                last_seq: d.last_seq,
                private_seq: d.private_seq,
                tk_version: d.tk_version,
                closes: d.closes,
                opened_seq: d.opened_seq,
            },
        );
    }
    // A private entry no door entry names: not a checkpoint this code
    // wrote.
    if !privates.is_empty() {
        return None;
    }
    Some(KeyTable::from_parts(tenant.clone(), seq, subjects))
}

/// The seqs of `tenant`'s checkpoints, oldest first.
pub async fn list_checkpoints<S: RecordStore>(store: &S, tenant: &TenantId) -> Result<Vec<u64>> {
    let prefix = checkpoint_prefix(tenant);
    let mut after = prefix.clone();
    let mut seqs = Vec::new();
    loop {
        let names = store.list(&prefix, &after, LIST_PAGE).await?;
        seqs.extend(names.iter().filter_map(|n| parse_seq(&prefix, n)));
        match names.last() {
            Some(last) if names.len() >= LIST_PAGE as usize => after.clone_from(last),
            _ => return Ok(seqs),
        }
    }
}

/// What a reader of the key chain found.
#[derive(Debug)]
pub struct KeyRead {
    /// The fold of the chain, as the records say (no `m/rk/` override).
    pub table: KeyTable,
    /// The checkpoint the read started from; `None` = seq 1.
    pub from_checkpoint: Option<u64>,
    /// Newer checkpoints that did not verify or open, skipped.
    pub skipped_checkpoints: Vec<u64>,
    /// The newest checkpoint that exists (verified or not).
    pub newest_checkpoint: Option<u64>,
    /// Access key ids with an `m/rk/` revocation.
    pub revoked: BTreeSet<String>,
}

impl KeyRead {
    /// Subjects revoked in `m/rk/` whose chain does not say so yet: the
    /// finisher appends their records.
    pub fn unrecorded_revocations(&self) -> Vec<String> {
        self.revoked
            .iter()
            .filter(|id| {
                self.table
                    .get(id)
                    .is_some_and(|e| e.door.status != super::record::SubjectStatus::Revoked)
            })
            .cloned()
            .collect()
    }

    /// Every entry with the `m/rk/` revocations in force: what a store
    /// applies. A view, not a table: no change is ever validated against
    /// it.
    pub fn in_force(&self) -> Vec<Entry> {
        self.table
            .entries()
            .map(|e| {
                let mut e = e.clone();
                if self.revoked.contains(&e.door.id) {
                    e.door.status = SubjectStatus::Revoked;
                }
                e
            })
            .collect()
    }
}

/// Reads `tenant`'s key chain to its head: from the newest checkpoint
/// that holds, then every record after it, then the revocations.
///
/// A checkpoint is skipped, for the next older one and at last for seq
/// 1, when it does not verify, does not name the chain's own record at
/// its seq, does not open, or does not fold into the records after it.
/// A subject that the checkpoint carries closed is opened again from its
/// own record when the ring now holds its key.
pub async fn read_key_chain<S: RecordStore, K: Kek, T: TkRing>(
    store: &S,
    kek: &K,
    ring: &T,
    tenant: &TenantId,
) -> Result<KeyRead> {
    let chain = key_chain(tenant);
    let checkpoints = list_checkpoints(store, tenant).await?;
    let mut skipped = Vec::new();
    // Candidates, newest first, then the start of the chain.
    let mut candidates: Vec<Option<u64>> = checkpoints.iter().rev().map(|s| Some(*s)).collect();
    candidates.push(None);
    for candidate in candidates {
        let mut table = match candidate {
            None => KeyTable::empty(tenant.clone()),
            Some(seq) => {
                let (Some(bytes), Some(record)) = (
                    store.get(&checkpoint_name(tenant, seq)).await?,
                    store.get(&chain.name(seq)).await?,
                ) else {
                    skipped.push(seq);
                    continue;
                };
                match open_checkpoint(kek, ring, tenant, seq, &bytes, &record) {
                    Some(t) => t,
                    None => {
                        skipped.push(seq);
                        continue;
                    }
                }
            }
        };
        reopen_closed(store, kek, ring, &chain, &mut table).await?;
        match advance(store, kek, ring, &chain, &mut table).await {
            Ok(_) => {
                if let Some(seq) = candidate {
                    reopen_from_older(store, kek, ring, tenant, &checkpoints, seq, &mut table)
                        .await?;
                }
                let revoked = list_tenant_revocations(store, tenant)
                    .await?
                    .into_iter()
                    .collect();
                return Ok(KeyRead {
                    table,
                    from_checkpoint: candidate,
                    skipped_checkpoints: skipped,
                    newest_checkpoint: checkpoints.last().copied(),
                    revoked,
                });
            }
            // A checkpoint that the records after it do not fold into is
            // not one this code wrote: the next older one.
            Err(e) if candidate.is_some() && is_record_error(&e) => {
                skipped.push(candidate.unwrap_or_default());
            }
            Err(e) => return Err(e),
        }
    }
    Err(ERR_CHECKPOINT)
}

/// Opens a subject that is still closed from an older checkpoint that
/// carries its private part: the same `private_seq` is the same private
/// part, whichever checkpoint holds it. A checkpoint written by a
/// Worker that could not open the subject carries it door-only, while
/// an older one, sealed under a key this ring holds, may carry it whole.
async fn reopen_from_older<S: RecordStore, K: Kek, T: TkRing>(
    store: &S,
    kek: &K,
    ring: &T,
    tenant: &TenantId,
    checkpoints: &[u64],
    from: u64,
    table: &mut KeyTable,
) -> Result<()> {
    let chain = key_chain(tenant);
    for seq in checkpoints.iter().rev().filter(|s| **s < from) {
        let closed: Vec<(String, u64)> = table
            .entries()
            .filter(|e| e.private.is_none() && e.door.status != SubjectStatus::Revoked)
            .map(|e| (e.door.id.clone(), e.private_seq))
            .collect();
        if closed.is_empty() {
            break;
        }
        let (Some(bytes), Some(record)) = (
            store.get(&checkpoint_name(tenant, *seq)).await?,
            store.get(&chain.name(*seq)).await?,
        ) else {
            continue;
        };
        let Some(older) = open_checkpoint(kek, ring, tenant, *seq, &bytes, &record) else {
            continue;
        };
        for (id, private_seq) in closed {
            if let Some(e) = older.get(&id) {
                if let (true, Some(private)) = (e.private_seq == private_seq, &e.private) {
                    table.reopen(&id, private.clone());
                }
            }
        }
    }
    Ok(())
}

fn is_record_error(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Invalid(m) if *m == "key record is malformed")
}

/// Opens again, from its own record, every subject of `table` that is
/// closed and not revoked, when the ring now holds its key.
pub(super) async fn reopen_closed<S: RecordStore, K: Kek, T: TkRing>(
    store: &S,
    kek: &K,
    ring: &T,
    chain: &Chain,
    table: &mut KeyTable,
) -> Result<()> {
    let closed: Vec<(String, u64)> = table
        .entries()
        .filter(|e| e.private.is_none() && e.door.status != SubjectStatus::Revoked)
        .filter(|e| ring.key(e.tk_version).is_some())
        .map(|e| (e.door.id.clone(), e.private_seq))
        .collect();
    for (id, seq) in closed {
        let bytes = chain.get(store, seq).await?;
        // A record that does not open, or is another subject's, leaves
        // the subject closed: the chain decides, not the checkpoint.
        let Ok(record) = open_key_record(kek, ring, table.tenant(), seq, &bytes) else {
            continue;
        };
        if let (true, Some(private)) = (record.door.id == id, record.private) {
            table.reopen(&id, private);
        }
    }
    Ok(())
}

/// Brings `table` to the head of its chain, record by record. Returns
/// the records it folded in.
pub async fn advance<S: RecordStore, K: Kek, T: TkRing>(
    store: &S,
    kek: &K,
    ring: &T,
    chain: &Chain,
    table: &mut KeyTable,
) -> Result<Vec<KeyRecord>> {
    let head = chain.head(store, table.seq()).await?;
    let mut folded = Vec::new();
    for seq in table.seq() + 1..=head {
        let bytes = chain.get(store, seq).await?;
        let record = open_key_record(kek, ring, table.tenant(), seq, &bytes)?;
        table.apply(&record)?;
        folded.push(record);
    }
    Ok(folded)
}
