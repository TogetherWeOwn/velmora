//! The renewal proof: the Worker's side of a lease renewal
//! (ADR-TENANCY §2.4 rule 12, SEC-6, RD-12).
//!
//! Before it calls `renew(proof_start)` the Worker proves, from the
//! safety bucket and nothing else, that the unit
//!
//! 1. is at the head of its tenant chain: a HEAD of
//!    `m/t/<t>/<state_seq + 1>` answers `404`;
//! 2. is at the head of its key chain: a HEAD of
//!    `m/k/<t>/<keys_seq + 1>` answers `404` (both chains have no gaps,
//!    §8.5, so the next name absent means the unit's seq is the head);
//! 3. is not behind its rollback stamp: one list after the unit's stamp
//!    counter is empty (§8.5);
//! 4. holds every revocation: the count of `m/rk/<t>/` (one list page
//!    per 1,000 objects) equals the number of revoked keys the unit
//!    reports. This is done at the renewal of **every** unit of a
//!    tenant, root or not (SEC-6).
//!
//! `proof_start` is the Worker's clock just before the first of these
//! reads, and the unit sets `fresh_until = proof_start + T` from it
//! ([`super::lease::FreshLease::renew`]). The proof also returns the
//! state it was made for ([`Proven`]); `renew` carries it, and the unit
//! refuses when it no longer holds exactly that state.
//!
//! What a finding means:
//!
//! | Finding | The Worker then |
//! |---|---|
//! | a newer tenant or key record | `sync` first, then proves again |
//! | a stamp object after the unit's counter | confirms it through the unit's stamp counter ([`crate::stamp::Stamp::checked`]): a raise that ran after the unit answered moves the counter and is not a rollback; with the counter unchanged the rollback is recorded, the unit is closed and the restore gate is needed (§8.6) |
//! | more revocations listed than the unit holds | applies every listed id to that unit (setting `revoked` twice changes nothing), sends an `apply_control` message for the key chain so the finisher appends a missing record, then calls `renew` with the same `proof_start` |
//! | fewer revocations listed than the unit holds | does not renew, and pages: `m/rk/` is put-only, so the unit holds a revocation the bucket does not, which no correct history gives |
//!
//! Cost (P0a measured): 2 HEADs that answer `404`, 2 lists (the second
//! one per 1,000 revocations), and the unit's 1 row write.
//!
//! The names of the two chains and of the revocations belong to the
//! lanes that write them; this module takes them through [`ChainNames`].

use crate::ports::{BlobStore, Clock};
use crate::stamp::{stamp_key, STAMP_PREFIX};
use crate::types::{BridgeError, Result, UnixMs};

use super::lease::Proven;
use super::stamp_id::UnitStampId;

/// Keys per list call of the revocations.
pub const REVOCATION_PAGE: u32 = 1000;

const ERR_SEQ: BridgeError = BridgeError::Invalid("a chain seq is at its largest value");
const ERR_REVOCATION_KEY: BridgeError =
    BridgeError::Invalid("a revocation key under the tenant's directory is malformed");
const ERR_NAMES: BridgeError =
    BridgeError::Invalid("the revocation directory does not name the unit's tenant");

/// The names of a tenant's records, as their writers lay them out.
pub trait ChainNames {
    /// Record `seq` of the tenant chain `m/t/<tenant>/`.
    fn tenant_record(&self, tenant: &str, seq: u64) -> String;
    /// Record `seq` of the key chain `m/k/<tenant>/`.
    fn key_record(&self, tenant: &str, seq: u64) -> String;
    /// The directory of the tenant's revocations, ending in `/`: every
    /// key under it is `<dir><access key id>`.
    fn revocation_dir(&self, tenant: &str) -> String;
}

/// What the unit reported about itself in its last answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitView<'a> {
    pub stamp_id: &'a UnitStampId,
    pub state_seq: u64,
    pub keys_seq: u64,
    /// The unit's stamp counter; `None` = never raised.
    pub stamp_counter: Option<u64>,
    /// How many revoked keys the unit holds.
    pub revoked: u64,
}

/// What a proof found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proof {
    /// The unit may be renewed with `proof_start` and `proven`, after the
    /// listed revocations are applied to it. `revocations` is empty when
    /// the counts agree, and every id of the directory when they do not.
    Fresh {
        proof_start: UnixMs,
        proven: Proven,
        revocations: Vec<String>,
    },
    /// A newer record exists in the named chain(s): `sync`, then prove
    /// again.
    SyncNeeded { tenant_chain: bool, key_chain: bool },
    /// A stamp object exists after the counter the unit reported. Not yet
    /// a rollback: a raise that ran after the unit answered gives the same
    /// listing. The caller confirms with [`crate::stamp::Stamp::checked`]
    /// over the unit's counter, which records a rollback only while the
    /// counter is still `seen`, and otherwise proves again.
    StampAhead { seen: Option<u64> },
    /// The unit holds more revocations than the bucket lists. Not
    /// renewed; pages.
    RevocationsShort { listed: u64, held: u64 },
}

/// Runs the proof for `unit`. Reads only; writes nothing anywhere.
///
/// The precedence of the findings is: a stamp ahead, then a newer record,
/// then the revocations. The revocation list is read only when the rest
/// passed, so a unit that must sync first is not charged for it.
pub async fn prove<B, T, N>(safety: &B, clock: &T, names: &N, unit: &UnitView<'_>) -> Result<Proof>
where
    B: BlobStore,
    T: Clock,
    N: ChainNames,
{
    let tenant = unit.stamp_id.tenant();
    let next_state = unit.state_seq.checked_add(1).ok_or(ERR_SEQ)?;
    let next_keys = unit.keys_seq.checked_add(1).ok_or(ERR_SEQ)?;

    // Before the first read: the lease runs from here (RD-12).
    let proof_start = clock.now();

    let tenant_chain = safety
        .head(&names.tenant_record(tenant, next_state))
        .await?
        .is_some();
    let key_chain = safety
        .head(&names.key_record(tenant, next_keys))
        .await?
        .is_some();
    let dir = format!("{STAMP_PREFIX}{}/", unit.stamp_id.as_str());
    let after = match unit.stamp_counter {
        Some(c) => stamp_key(unit.stamp_id.as_str(), c),
        None => dir.clone(),
    };
    let stamp_ahead = !safety.list(&dir, &after, 1).await?.is_empty();

    if stamp_ahead {
        return Ok(Proof::StampAhead {
            seen: unit.stamp_counter,
        });
    }
    if tenant_chain || key_chain {
        return Ok(Proof::SyncNeeded {
            tenant_chain,
            key_chain,
        });
    }

    let ids = revocations(safety, names, tenant).await?;
    let listed = ids.len() as u64;
    let proven = Proven {
        state_seq: unit.state_seq,
        keys_seq: unit.keys_seq,
        stamp_counter: unit.stamp_counter,
    };
    match listed.cmp(&unit.revoked) {
        std::cmp::Ordering::Equal => Ok(Proof::Fresh {
            proof_start,
            proven,
            revocations: Vec::new(),
        }),
        std::cmp::Ordering::Greater => Ok(Proof::Fresh {
            proof_start,
            proven,
            revocations: ids,
        }),
        std::cmp::Ordering::Less => Ok(Proof::RevocationsShort {
            listed,
            held: unit.revoked,
        }),
    }
}

/// Every access key id under the tenant's revocation directory, in key
/// order.
pub async fn revocations<B: BlobStore, N: ChainNames>(
    safety: &B,
    names: &N,
    tenant: &str,
) -> Result<Vec<String>> {
    let dir = names.revocation_dir(tenant);
    // A directory that is not the tenant's own would list another
    // tenant's revocations, or tenant 0's whole flat prefix.
    if !dir.ends_with('/') || !dir.contains(&format!("/{tenant}/")) {
        return Err(ERR_NAMES);
    }
    let mut ids = Vec::new();
    let mut after = dir.clone();
    loop {
        let page = safety.list(&dir, &after, REVOCATION_PAGE).await?;
        for key in &page {
            let id = key
                .strip_prefix(&dir)
                .filter(|id| !id.is_empty() && !id.contains('/'))
                .ok_or(ERR_REVOCATION_KEY)?;
            ids.push(id.to_string());
        }
        match page.last() {
            Some(last) if page.len() as u64 >= u64::from(REVOCATION_PAGE) => after = last.clone(),
            _ => return Ok(ids),
        }
    }
}
