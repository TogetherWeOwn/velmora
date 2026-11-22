//! The move's key steps on the owner's root unit (DS1 §3.4 steps 5(d),
//! 5(e), 8 and 9; AM-16, AM-31), and the revocations a give-up applies to
//! the thawed D1 (AM-31).
//!
//! - [`apply_owner_keys`] is step 5(e): the owner's key-chain records sent
//!   to the unit with a direct `apply(from_seq)`, one item per record:
//!   each entry as the head states its subject, stamped at the record's
//!   seq (`held = false`), and a `KeysFrozen`/`KeysThawed` record as a
//!   marker item (AM-62), not through the writer's bring-up. A
//!   `behind` answer re-reads from the unit's seq + 1. The unit is closed
//!   until 8(b) and no route names the owner until 8(c), so the hold of
//!   ADR §2.5 does not apply (AM-16).
//! - [`revocation_sweep`] (AM-31): every moved key with a flat
//!   `m/rk/<akid>` gets `m/rk/<t>/<akid>` and a revoke record in the
//!   owner's key chain, applied to the unit. The tool runs it at step
//!   5(d), before the 8(b) lift record ([`super::move_flip::flip`] does),
//!   and at 8(d) + 2 minutes, before step 9's lift deploy.
//! - [`assert_revoked_closed`] is step 9's check that no moved key with a
//!   revocation is active in the unit.
//! - [`revocations_to_d1`] is the give-up's: after the triggers are
//!   dropped and before the lift, every flat `m/rk/<akid>` and every
//!   `m/rk/<t>/<akid>` of a moved key is applied to D1 (status
//!   `disabled`, grants deleted), so a revoke made during `moving`, which
//!   the frozen D1 refused, is not lost.
//!
//! The key chain's writer and reader are the key lane's code
//! ([`OwnerKeys`]); the unit is reached through [`KeyUnit`].

use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result};
use crate::unit::keys::{Applied, ApplyEntry, KeyRefusal, MAX_ENTRIES};

/// The owner tenant's key chain and its revocations, as the move tool
/// holds them (the key lane's code in the Worker).
#[allow(async_fn_in_trait)]
pub trait OwnerKeys {
    /// The seq of the owner's key-chain head (0: no record).
    async fn head(&self) -> Result<u64>;
    /// The verified items of the records after `after`, in chain order,
    /// at most `limit`, with no gap: one per record, an entry stating its
    /// subject as the head holds it, stamped at the record's seq, or a
    /// marker for a record that changes no subject (AM-62).
    async fn entries(&self, after: u64, limit: usize) -> Result<Vec<ApplyEntry>>;
    /// Whether tenant 0's flat revocation `m/rk/<akid>` exists.
    async fn flat_revoked(&self, akid: &str) -> Result<bool>;
    /// Whether the owner's revocation `m/rk/<t>/<akid>` exists.
    async fn tenant_revoked(&self, akid: &str) -> Result<bool>;
    /// Puts `m/rk/<t>/<akid>`, or finds it there.
    async fn put_tenant_revocation(&self, akid: &str) -> Result<()>;
    /// A revoke record for `akid` in the owner's key chain, or finds the
    /// key already revoked there.
    async fn revoke(&self, akid: &str) -> Result<()>;
    /// Closing records that revoke every grant on `buckets` in the owner's
    /// key chain, of keys and principals alike, or finds none left (AM-23
    /// step 2).
    async fn revoke_grants(&self, buckets: &[String]) -> Result<()>;
    /// One page of tenant 0's flat revocations (a delimited listing of
    /// `m/rk/`, never a managed tenant's `m/rk/<t>/`): the key ids after
    /// `after`, and where the next page starts.
    async fn flat_revocations(&self, after: Option<&str>) -> Result<(Vec<String>, Option<String>)>;
}

/// The owner's root unit, for the key steps.
#[allow(async_fn_in_trait)]
pub trait KeyUnit {
    /// `ApplyKeys{from_seq, entries}` (AM-12, AM-62).
    async fn apply_keys(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied>;
    /// Whether the unit serves `akid` now: its key row is `active`, not
    /// held, through `KeyRow`.
    async fn key_active(&self, akid: &str) -> Result<bool>;
}

/// Why a key step stopped. Everything it did stays done and is found
/// again by the next run.
#[derive(Debug)]
pub enum KeyStepError {
    Store(BridgeError),
    /// The key lane handed a held entry: the move sends records as they
    /// state, never held.
    HeldEntry(String),
    /// The unit refused an apply.
    Refused(KeyRefusal),
    /// The chain has fewer records than its head says, or the unit keeps
    /// answering `behind`.
    Diverged,
    /// A moved key with a revocation is active in the unit.
    RevokedActive(String),
}

impl From<BridgeError> for KeyStepError {
    fn from(e: BridgeError) -> Self {
        KeyStepError::Store(e)
    }
}

/// Step 5(e): sends every record of the owner's key chain to the unit, in
/// pages of at most [`MAX_ENTRIES`], until the unit holds the head read at
/// the start. Records the unit has are skipped by the unit. Answers the
/// unit's `keys_seq`.
pub async fn apply_owner_keys<K: OwnerKeys, U: KeyUnit>(
    keys: &K,
    unit: &U,
) -> std::result::Result<u64, KeyStepError> {
    let head = keys.head().await?;
    let mut from = 0u64;
    let mut unit_seq = 0u64;
    // Each round moves `from` on by at least one record (a page may be
    // short), or is a `behind` answer, which moves it down to the unit's
    // seq once; a few more for those.
    let rounds = head.saturating_add(8);
    for _ in 0..rounds {
        if from >= head {
            return Ok(unit_seq.max(from));
        }
        let entries = keys.entries(from, MAX_ENTRIES).await?;
        let Some(last) = entries.last().map(ApplyEntry::seq) else {
            return Err(KeyStepError::Diverged);
        };
        if let Some(e) = entries.iter().filter_map(ApplyEntry::key).find(|e| e.held) {
            return Err(KeyStepError::HeldEntry(e.id.clone()));
        }
        match unit.apply_keys(from, &entries).await? {
            Applied::Done { keys_seq, .. } => {
                unit_seq = keys_seq;
                if last <= from {
                    return Err(KeyStepError::Diverged);
                }
                from = last;
            }
            Applied::Behind { keys_seq } => {
                if keys_seq >= from {
                    return Err(KeyStepError::Diverged);
                }
                from = keys_seq;
            }
            Applied::Refused(r) => return Err(KeyStepError::Refused(r)),
        }
    }
    Err(KeyStepError::Diverged)
}

/// The revocation sweep (AM-31) over the moved keys: answers the keys it
/// found revoked flat. Then the chain is applied to the unit.
pub async fn revocation_sweep<K: OwnerKeys, U: KeyUnit>(
    keys: &K,
    unit: &U,
    moved: &[String],
) -> std::result::Result<Vec<String>, KeyStepError> {
    let mut swept = Vec::new();
    for akid in moved {
        if keys.flat_revoked(akid).await? {
            // The revocation first: it wins on every read path, also if
            // the chain record below is lost.
            keys.put_tenant_revocation(akid).await?;
            keys.revoke(akid).await?;
            swept.push(akid.clone());
        }
    }
    apply_owner_keys(keys, unit).await?;
    Ok(swept)
}

/// Step 9's check (AM-31): no moved key with a revocation, flat or the
/// owner's, is active in the unit.
pub async fn assert_revoked_closed<K: OwnerKeys, U: KeyUnit>(
    keys: &K,
    unit: &U,
    moved: &[String],
) -> std::result::Result<(), KeyStepError> {
    for akid in moved {
        let revoked = keys.flat_revoked(akid).await? || keys.tenant_revoked(akid).await?;
        if revoked && unit.key_active(akid).await? {
            return Err(KeyStepError::RevokedActive(akid.clone()));
        }
    }
    Ok(())
}

/// Keys per D1 batch of [`revocations_to_d1`] (two statements each).
pub const REVOKE_CHUNK: usize = 50;

/// The most flat revocation pages [`revocations_to_d1`] reads.
pub const MAX_REVOCATION_PAGES: usize = 10_000;

/// The give-up's revocations (AM-31), on the thawed D1: every key with a
/// flat revocation, and every moved key with the owner's, is set
/// `disabled` and loses its grants. Run after the triggers are dropped
/// (the frozen D1 refuses the update) and before the lift. Idempotent.
/// Answers the key ids it applied.
pub async fn revocations_to_d1<S: Sql, K: OwnerKeys>(
    d1: &S,
    keys: &K,
    moved: &[String],
) -> std::result::Result<Vec<String>, KeyStepError> {
    let mut ids = std::collections::BTreeSet::new();
    let mut after: Option<String> = None;
    let mut pages = 0;
    loop {
        pages += 1;
        if pages > MAX_REVOCATION_PAGES {
            return Err(KeyStepError::Diverged);
        }
        let (page, next) = keys.flat_revocations(after.as_deref()).await?;
        ids.extend(page);
        match next {
            Some(n) if Some(&n) != after.as_ref() => after = Some(n),
            Some(_) => return Err(KeyStepError::Diverged),
            None => break,
        }
    }
    for akid in moved {
        if keys.tenant_revoked(akid).await? {
            ids.insert(akid.clone());
        }
    }
    let ids: Vec<String> = ids
        .into_iter()
        .filter(|id| crate::recovery::valid_key_id(id))
        .collect();
    for chunk in ids.chunks(REVOKE_CHUNK) {
        let mut stmts: Vec<(&'static str, Vec<SqlValue>)> = Vec::with_capacity(chunk.len() * 2);
        for id in chunk {
            let id = vec![SqlValue::Text(id.clone())];
            stmts.push(("DELETE FROM grants WHERE access_key_id = ?1", id.clone()));
            stmts.push((
                "UPDATE access_keys SET status = 'disabled' \
                 WHERE access_key_id = ?1 AND status <> 'disabled'",
                id,
            ));
        }
        d1.batch(stmts).await?;
    }
    Ok(ids)
}
