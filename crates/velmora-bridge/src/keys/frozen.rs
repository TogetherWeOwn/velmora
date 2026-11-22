//! The undo's key freeze on a managed tenant's key chain (AM-28 with
//! AM-54), and the key-chain side of the undo's D1 build.
//!
//! Operator plane only: the undo tool (DS1 §3.7 step 1 and the
//! fallback's first step), the next move's window step 2, and the exits
//! of AM-23 call these. Nothing here is reachable from a customer call.
//!
//! - **The freeze is a key-chain record.** [`freeze_keys`] puts
//!   `KeysFrozen` at the head + 1; `K_u` is its seq − 1. It and every
//!   later record carry `frozen_at = K_u` until `KeysThawed{ends: K_u}`.
//!   The chain's own put-once arbitration orders it against every other
//!   writer: a writer that loses its put to the freeze reads the head
//!   again and finds it frozen ([`super::gate`]), so no change made before
//!   the freeze lands above `K_u` unseen.
//! - **The thaw** ([`thaw_keys`]) names the freeze it ends, and is taken
//!   only while `<t>`'s tenant head no longer carries `keys_frozen`, so no
//!   thaw lands while an undo runs (AM-54 LOW 1).
//! - **The exit's grant removals** ([`drop_moved_grants`], AM-23 step 2)
//!   are the one change a frozen chain takes.
//! - **The D1 build** reads the chain to `K_u` and never further
//!   ([`table_at`]) and gives each key its effective grant there
//!   ([`d1_projection`]). The `m/rk/` override pass (flat and `<t>`) is
//!   the tool's, after the projection.

use std::collections::BTreeSet;

use velmora::rng::FillRandom;

use super::chain::Put;
use super::checkpoint::{advance, read_key_chain, read_key_chain_to};
use super::gate::MoveGate;
use super::ports::{ControlIntents, KeyAdmission, KeyTarget};
use super::record::{
    key_chain, open_chain_record, seal_key_record, seal_marker_record, Access, ChainRecord, Entry,
    Grant, KeyOp, KeyTable, Marker, SubjectKind, SubjectStatus, TkRing, ERR_KEY_RECORD,
};
use super::writer::{lost_subjects, KeyEnv};
use crate::crypto::scheme2::TenantId;
use crate::ports::{Clock, Kek};
use crate::records::RecordStore;
use crate::types::Result;

/// Puts of a marker or an exit record before the call answers busy (an
/// estimate; a dial). The tool runs it again.
pub const MAX_OPERATOR_PUTS: u32 = 8;

/// Records one [`drop_moved_grants`] run writes at most (an estimate; a
/// dial): every subject of a tenant holds at most 64 grants, and the
/// owner tenant has a few dozen subjects.
pub const MAX_EXIT_RECORDS: usize = 1024;

/// How far up a `made_by` chain the projection looks; a deeper or
/// circular chain is not carried open (the unit's rule, `unit::keys`).
pub const MAX_PRINCIPAL_DEPTH: usize = 8;

/// What [`freeze_keys`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freeze {
    /// `KeysFrozen` is written at `seq`; `K_u` = `seq − 1`. Write `k_u` to
    /// the undo's receipt before the next step.
    Frozen { k_u: u64, seq: u64 },
    /// The head carries the freeze the receipt names: a re-run.
    Adopted { k_u: u64 },
    /// The head moved on [`MAX_OPERATOR_PUTS`] times, or a store did not
    /// answer: run it again.
    Busy,
    /// A freeze this undo did not write is in force, and `<t>`'s tenant
    /// head still carries `keys_frozen`: it cannot be ended now.
    Refused { code: &'static str },
}

/// What [`thaw_keys`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Thaw {
    /// `KeysThawed{ends}` is written at `seq`.
    Thawed { seq: u64 },
    /// The head carries no freeze: a re-run, nothing to do.
    NotFrozen,
    /// `freeze_mismatch`: the freeze in force is another one;
    /// `tenant_keys_frozen`: `<t>`'s tenant head still carries
    /// `keys_frozen`.
    Refused { code: &'static str },
    /// Run it again.
    Busy,
}

/// What [`drop_moved_grants`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitDrops {
    /// The closing grants records written, in order. Empty on a re-run.
    pub written: Vec<u64>,
    /// Every subject's grants on the listed ids are gone at the head.
    pub done: bool,
    /// Every unit acknowledged the head (best effort; the unit is
    /// emptied by `UnplaceMovedBuckets` next).
    pub in_force: bool,
    /// `not_moved_in`, `not_placed`: refused before any record.
    pub refused: Option<&'static str>,
    /// Subjects that hold a listed grant but whose private part does not
    /// open now (a key version not loaded, or gone: AM-11): no record may
    /// drop a prefix, an IP list or a secret, so they are left, and the
    /// exit cannot go on to `UnplaceMovedBuckets` until they are dealt
    /// with. An attention condition: page, do not retry blindly.
    pub blocked: Vec<String>,
}

/// One key as D1 gets it from `<t>`'s chain at `K_u` (ADR §6.2, AM-28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct D1Key {
    pub id: String,
    pub kind: SubjectKind,
    /// `active` only when the key and every principal up its `made_by`
    /// chain are `active` with their private parts open; `revoked` as
    /// recorded; `disabled` otherwise.
    pub status: SubjectStatus,
    /// The effective grant: per bucket, the lower access of the key and
    /// every principal up its chain, also for a `disabled` key. Empty for
    /// a `revoked` key, or when a private part on the chain is closed.
    pub grants: Vec<(String, Access)>,
    /// Grants left out because the key or a principal limits them by a
    /// prefix, an expiry or an IP list (D1 cannot state one; AM-18 makes
    /// none): fail closed.
    pub limited_dropped: usize,
    /// The key's entry at `K_u`: its secret (scheme 2) and owner.
    pub entry: Entry,
}

/// Puts `marker` at `table`'s head + 1 and folds it in. `Ok(false)`:
/// another record holds the seq.
async fn put_marker<S, K, T, A, I, U, D, C, G, R>(
    env: &KeyEnv<'_, S, K, T, A, I, U, D, C, G>,
    table: &mut KeyTable,
    marker: Marker,
    rng: &mut R,
) -> Result<bool>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    A: KeyAdmission,
    I: ControlIntents,
    U: KeyTarget,
    D: KeyTarget,
    C: Clock,
    G: MoveGate,
    R: FillRandom,
{
    let seq = table.seq() + 1;
    let bytes = seal_marker_record(env.kek, env.ring, env.tenant, seq, env.now(), marker, rng)?;
    match key_chain(env.tenant)
        .put(env.store, seq, bytes.clone())
        .await?
    {
        Put::Lost => Ok(false),
        Put::Written => {
            let record = open_chain_record(env.kek, env.ring, env.tenant, seq, &bytes)?;
            table.apply_chain(&record)?;
            Ok(true)
        }
    }
}

/// Freezes `<t>`'s key chain for an undo (DS1 §3.7 step 1, and the
/// fallback's first step). `receipt_k_u`: the `K_u` the undo's own
/// receipt in R2 names, if a first run wrote one.
///
/// A head with no freeze gets `KeysFrozen` at head + 1 (a lost put reads
/// the head again and tries again). A head that carries a freeze is
/// adopted only when the receipt names it (a re-run, or the fallback
/// after this reverse move's step 1). Any other freeze is ended first
/// with `KeysThawed`, which needs `<t>`'s tenant head without
/// `keys_frozen`, and then a new `KeysFrozen` is put (AM-54 LOW 1).
pub async fn freeze_keys<S, K, T, A, I, U, D, C, G, R>(
    env: &KeyEnv<'_, S, K, T, A, I, U, D, C, G>,
    receipt_k_u: Option<u64>,
    rng: &mut R,
) -> Result<Freeze>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    A: KeyAdmission,
    I: ControlIntents,
    U: KeyTarget,
    D: KeyTarget,
    C: Clock,
    G: MoveGate,
    R: FillRandom,
{
    let chain = key_chain(env.tenant);
    let mut table = read_key_chain(env.store, env.kek, env.ring, env.tenant)
        .await?
        .table;
    for _ in 0..MAX_OPERATOR_PUTS {
        advance(env.store, env.kek, env.ring, &chain, &mut table).await?;
        match table.frozen_at() {
            Some(f) if receipt_k_u == Some(f) => return Ok(Freeze::Adopted { k_u: f }),
            Some(f) => {
                let Ok(door) = env.gate.tenant_door(env.tenant).await else {
                    return Ok(Freeze::Busy);
                };
                if door.keys_frozen.is_some() {
                    return Ok(Freeze::Refused {
                        code: "tenant_keys_frozen",
                    });
                }
                // Ended here; the next pass puts the new freeze.
                put_marker(env, &mut table, Marker::KeysThawed { ends: f }, rng).await?;
            }
            None => {
                if put_marker(env, &mut table, Marker::KeysFrozen, rng).await? {
                    return Ok(Freeze::Frozen {
                        k_u: table.seq() - 1,
                        seq: table.seq(),
                    });
                }
            }
        }
    }
    Ok(Freeze::Busy)
}

/// Ends the freeze `ends` of `<t>`'s key chain: after the tenant record
/// that clears `keys_frozen` (the next move's window step 2, or the
/// gate's lift record of an undo given up while tenant 0 is `moved`).
pub async fn thaw_keys<S, K, T, A, I, U, D, C, G, R>(
    env: &KeyEnv<'_, S, K, T, A, I, U, D, C, G>,
    ends: u64,
    rng: &mut R,
) -> Result<Thaw>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    A: KeyAdmission,
    I: ControlIntents,
    U: KeyTarget,
    D: KeyTarget,
    C: Clock,
    G: MoveGate,
    R: FillRandom,
{
    let chain = key_chain(env.tenant);
    let mut table = read_key_chain(env.store, env.kek, env.ring, env.tenant)
        .await?
        .table;
    for _ in 0..MAX_OPERATOR_PUTS {
        advance(env.store, env.kek, env.ring, &chain, &mut table).await?;
        match table.frozen_at() {
            None => return Ok(Thaw::NotFrozen),
            Some(f) if f != ends => {
                return Ok(Thaw::Refused {
                    code: "freeze_mismatch",
                })
            }
            Some(_) => {}
        }
        let Ok(door) = env.gate.tenant_door(env.tenant).await else {
            return Ok(Thaw::Busy);
        };
        if door.keys_frozen.is_some() {
            return Ok(Thaw::Refused {
                code: "tenant_keys_frozen",
            });
        }
        if put_marker(env, &mut table, Marker::KeysThawed { ends }, rng).await? {
            return Ok(Thaw::Thawed { seq: table.seq() });
        }
    }
    Ok(Thaw::Busy)
}

/// The exit's grant removals (AM-23 step 2): a closing grants record for
/// every subject that holds a grant on one of `buckets`, removing those
/// grants and nothing else. Accepted on a frozen chain and under every
/// tenant-0 state (the one exception of AM-28 and AM-31), but only for
/// ids that `<t>`'s tenant head places on its root unit while `moved_in`
/// is set. A re-run writes nothing more.
pub async fn drop_moved_grants<S, K, T, A, I, U, D, C, G, R>(
    env: &KeyEnv<'_, S, K, T, A, I, U, D, C, G>,
    buckets: &[String],
    rng: &mut R,
) -> Result<ExitDrops>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    A: KeyAdmission,
    I: ControlIntents,
    U: KeyTarget,
    D: KeyTarget,
    C: Clock,
    G: MoveGate,
    R: FillRandom,
{
    let door = env.gate.tenant_door(env.tenant).await?;
    let refused = |code| ExitDrops {
        refused: Some(code),
        ..ExitDrops::default()
    };
    if !door.moved_in {
        return Ok(refused("not_moved_in"));
    }
    if buckets.iter().any(|b| !door.root_placed.contains(b)) {
        return Ok(refused("not_placed"));
    }
    let listed: BTreeSet<&str> = buckets.iter().map(String::as_str).collect();
    let chain = key_chain(env.tenant);
    let read = read_key_chain(env.store, env.kek, env.ring, env.tenant).await?;
    let mut table = read.table.clone();
    let mut out = ExitDrops::default();
    let mut lost = 0;
    // A closed holder is dead only when its private part is lost for good
    // (AM-11's test: a full ring, and no checkpoint that may hold it).
    let gone = lost_subjects(env.store, env.kek, env.ring, &table).await;
    // The holders are found again at every head: on an exit that is not
    // frozen (a give-up), a subject may gain a listed grant meanwhile.
    loop {
        advance(env.store, env.kek, env.ring, &chain, &mut table).await?;
        let next = table
            .entries()
            .filter(|e| {
                // A revoked holder (on the chain or by `m/rk/`) and one
                // sealed under a gone key version hold nothing in force,
                // and no record can be written for them on a frozen chain.
                let dead = e.door.status == SubjectStatus::Revoked
                    || read.revoked.contains(&e.door.id)
                    || (e.private.is_none() && gone.get(&e.door.id) == Some(&e.private_seq));
                !dead
                    && e.door
                        .grants
                        .iter()
                        .any(|g| listed.contains(g.bucket_id.as_str()))
                    && !out.blocked.contains(&e.door.id)
            })
            .map(|e| (e.door.id.clone(), e.subject()))
            .next();
        let Some((id, subject)) = next else {
            break;
        };
        // A grant change needs the private part open.
        let Some(subject) = subject else {
            out.blocked.push(id);
            continue;
        };
        let grants: Vec<Grant> = subject
            .grants()
            .into_iter()
            .filter(|g| !listed.contains(g.bucket_id.as_str()))
            .collect();
        let mut next = subject.clone();
        next.set_grants(&grants);
        table.admits(KeyOp::Grants, &next.door, Some(&next.private))?;
        let seq = table.seq() + 1;
        let bytes = seal_key_record(
            env.kek,
            env.ring,
            env.tenant,
            seq,
            KeyOp::Grants,
            env.now(),
            &next.door,
            Some(&next.private),
            true,
            table.frozen_at(),
            rng,
        )?;
        match chain.put(env.store, seq, bytes.clone()).await? {
            Put::Written => {
                let record = open_chain_record(env.kek, env.ring, env.tenant, seq, &bytes)?;
                table.apply_chain(&record)?;
                out.written.push(seq);
                // Bounded: a run that keeps meeting new holders stops, and
                // the tool runs it again.
                if out.written.len() >= MAX_EXIT_RECORDS {
                    return Ok(out);
                }
            }
            Put::Lost => {
                lost += 1;
                if lost >= MAX_OPERATOR_PUTS {
                    return Ok(out);
                }
            }
        }
    }
    if !out.blocked.is_empty() {
        return Ok(out);
    }
    out.done = true;
    let acks = env.apply_all(&table, &read.revoked).await;
    out.in_force = acks.closed;
    Ok(out)
}

/// `<t>`'s key table at `K_u`, read from the chain up to `K_u` and never
/// further: every D1 build, every re-run and the mirrored V6 (AM-28).
/// Refused unless the record at `K_u + 1` is the `KeysFrozen` of `K_u`,
/// so a wrong cut is never built.
pub async fn table_at<S: RecordStore, K: Kek, T: TkRing>(
    store: &S,
    kek: &K,
    ring: &T,
    tenant: &TenantId,
    k_u: u64,
) -> Result<KeyTable> {
    let next = key_chain(tenant).get(store, k_u + 1).await?;
    match open_chain_record(kek, ring, tenant, k_u + 1, &next)? {
        ChainRecord::Marker(m) if m.marker == Marker::KeysFrozen && m.frozen_at == Some(k_u) => {}
        _ => return Err(ERR_KEY_RECORD),
    }
    Ok(read_key_chain_to(store, kek, ring, tenant, k_u)
        .await?
        .table)
}

/// Whether a grant is limited: a prefix, an expiry or an IP list.
fn limited(g: &Grant) -> bool {
    g.prefix.is_some() || g.expires_at.is_some() || !g.ip_list.is_empty()
}

/// The principals up `key`'s `made_by` chain, nearest first, each
/// `active` with its private part open; `None` when one is not, or the
/// chain is deeper than [`MAX_PRINCIPAL_DEPTH`] or circular.
fn principal_chain<'a>(table: &'a KeyTable, key: &Entry) -> Option<Vec<&'a Entry>> {
    let mut out: Vec<&Entry> = Vec::new();
    let mut next = key.door.made_by.as_deref();
    while let Some(id) = next {
        if out.len() >= MAX_PRINCIPAL_DEPTH || out.iter().any(|p| p.door.id == id) {
            return None;
        }
        let p = table.get(id)?;
        // Its grants must be readable whole; its status decides only the
        // key's status, not its grant.
        let readable = p.door.kind == SubjectKind::Principal
            && p.door.status != SubjectStatus::Revoked
            && p.private.is_some();
        if !readable {
            return None;
        }
        out.push(p);
        next = p.door.made_by.as_deref();
    }
    Some(out)
}

/// Each key of `table` as D1 gets it (ADR §6.2, AM-28): its grants ∩
/// every principal up its `made_by` chain, the lower access per bucket;
/// `disabled` when the key or a principal is not `active`, or a private
/// part is closed. A key with no `made_by` (the internal key) and the
/// principals are not carried: D1 has no principals, so the projection is
/// made once, here. Skips the markers by construction (they hold no
/// subject). `table` is the chain's own fold: the `m/rk/` override is the
/// caller's next pass.
pub fn d1_projection(table: &KeyTable) -> Vec<D1Key> {
    table
        .entries()
        .filter(|e| {
            matches!(e.door.kind, SubjectKind::S3 | SubjectKind::AppPassword)
                && e.door.made_by.is_some()
        })
        .map(|e| {
            let principals = principal_chain(table, e);
            let all_active = principals
                .as_ref()
                .is_some_and(|ps| ps.iter().all(|p| p.door.status == SubjectStatus::Active));
            let open = e.door.status == SubjectStatus::Active && e.private.is_some();
            let status = match (e.door.status, open && all_active) {
                (SubjectStatus::Revoked, _) => SubjectStatus::Revoked,
                (_, true) => SubjectStatus::Active,
                _ => SubjectStatus::Disabled,
            };
            // The grant is the key's effective grant whatever its status
            // (AM-28): a disabled key keeps it for a re-enable. None for a
            // revoked key, a closed private part or an unreadable chain.
            let mut grants = Vec::new();
            let mut limited_dropped = 0;
            if let (false, Some(principals), Some(subject)) =
                (status == SubjectStatus::Revoked, &principals, e.subject())
            {
                for g in subject.grants() {
                    let mut access = Some(g.access);
                    let mut lim = limited(&g);
                    for p in principals {
                        let held = p.subject().and_then(|s| {
                            s.grants().into_iter().find(|h| h.bucket_id == g.bucket_id)
                        });
                        match held {
                            Some(h) => {
                                lim |= limited(&h);
                                access = access.map(|a| a.min(h.access));
                            }
                            None => access = None,
                        }
                    }
                    match (access, lim) {
                        (Some(a), false) => grants.push((g.bucket_id.clone(), a)),
                        (Some(_), true) => limited_dropped += 1,
                        (None, _) => {}
                    }
                }
            }
            D1Key {
                id: e.door.id.clone(),
                kind: e.door.kind,
                status,
                grants,
                limited_dropped,
                entry: e.clone(),
            }
        })
        .collect()
}
