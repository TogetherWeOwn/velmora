//! The record-first key writer and the finisher of the key chain.
//!
//! Every key change runs its writes in a fixed order. Each step is
//! idempotent with the record's seq:
//!
//! | Change | Order |
//! |---|---|
//! | Closing: revoke, disable, narrow | intent → (`m/rk/` for a revoke) → record → units → directory |
//! | Opening: create, re-enable, widen | reservation → intent → (`m/kr/` for a new key) → record → units (held closed) → directory → units |
//!
//! Every bring-up runs the same three steps: the units get the head with
//! every entry whose record does not close sent closed (held `disabled`),
//! then the directory, then, only once the directory acknowledged, the
//! units in full. So a closing change is in force without the directory,
//! nothing opens at a unit before the directory has it, and a unit still
//! reaches the head (its lease renews) while the directory is down.
//!
//! - **The chain decides.** The writer validates against the head and
//!   writes exactly the next seq; a lost put reads the head again and
//!   validates again, at most [`MAX_PUTS`] times, then answers busy.
//! - **An opening record is bound to the reservation's `keys_seq`:** it
//!   must be exactly that seq + 1, or the reservation is asked for again
//!   at the new head. So no key is recorded against a grant that an
//!   earlier record has already narrowed or revoked. A key's grant is
//!   always checked against the principal it was made under.
//! - **A call whose effect the head already carries writes no record**,
//!   but still brings every store to the head, in the three steps above,
//!   and waits for each: a retry after a crash must not answer `200` for
//!   a key that a store still accepts, nor `409` for a key it created.
//! - **A closing change needs no directory.** The directory step and the
//!   `pending_ops` row are best effort; the units are the door. Stores
//!   apply per subject, in chain order (see [`KeyTarget::apply`]), so the
//!   order in which stores are brought up never lets a stale entry
//!   replace a newer one.
//! - **`m/rk/` wins.** A subject with a revocation takes no change but
//!   its revoke record, whatever its chain says.
//! - **A private part that does not open is never rewritten.** A revoke
//!   or a disable of such a subject is recorded without a private part,
//!   marked as keeping the one before; a narrowing, a re-enable or a
//!   retried create answer busy until the key can be loaded. No record
//!   ever drops a prefix, an IP list or a secret.
//! - **The answer.** `Done` only after the door stores acknowledged. A
//!   record that is written while a store cannot be reached answers
//!   [`KeyAnswer::Unfinished`] (`503`); the queue message, the lease
//!   renewal and the pending sweep finish it.
//!
//! [`finish_keys`] is the consumer of `apply_control(tenant, keys, seq)`.
//! It reads the head (never the message's seq), appends a revoke record
//! for every `m/rk/` revocation that the chain does not yet carry,
//! brings every store to the head in the three steps above, writes a
//! checkpoint when one is due, and clears the `pending_ops` rows up to
//! the head once every store holds it with every subject open. A step
//! that fails is reported and does not stop the others.

use std::collections::{BTreeMap, BTreeSet};

use subtle::ConstantTimeEq;
use velmora::rng::FillRandom;

use super::apply::{Feed, Mode};
use super::chain::Put;
use super::checkpoint::{
    advance, checkpoint_holds, checkpoint_name, read_key_chain, reopen_closed,
    reopen_from_checkpoints, seal_checkpoint, CHECKPOINT_EVERY,
};
use super::gate::{decide, needs_route, ChangeKind, Facts, Gate, MoveGate, ZeroHead};
use super::ports::{
    Admission, ControlChain, ControlIntents, KeyAdmission, KeyTarget, OpeningChange, Refusal,
};
use super::record::{
    grants_narrow, key_chain, open_key_record, seal_key_record, Entry, Grant, KeyOp, KeyTable,
    Subject, SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus, TkRing,
};
use super::revocations::{list_tenant_revocations, put_tenant_revocation};
use super::routes::{put_route, read_route, RoutePut};
use crate::crypto::scheme2::{unwrap_secret_v2, TenantId};
use crate::ports::{Clock, Kek};
use crate::records::RecordStore;
use crate::types::Result;

/// Puts of the next seq one call tries before it answers busy (an
/// estimate; a dial).
pub const MAX_PUTS: u32 = 3;

/// A key change asked for.
#[derive(Clone, Debug)]
pub enum KeyRequest {
    /// A new subject: an S3 key, an app password, a principal or the
    /// internal key. Its status must be `active`.
    Create(Subject),
    /// Revoke, disable or re-enable.
    SetStatus { id: String, status: SubjectStatus },
    /// Replace the grants. `acting` is the principal a widening is made
    /// under; for a key it must be the principal the key was made under
    /// (or absent, which means that one).
    SetGrants {
        id: String,
        grants: Vec<Grant>,
        acting: Option<String>,
    },
    /// Remove the grant on one bucket id, whatever else the subject holds
    /// at the head: a closing change. The revoke of an orphan creator
    /// grant (ADR §6.2, AM-8, AM-24), so that a concurrent change to the
    /// subject's other grants is never undone.
    DropGrant { id: String, bucket_id: String },
}

/// What a key change answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAnswer {
    /// In force in every door store. `seq` is the record that carries it
    /// (an earlier one when the head already did).
    Done { seq: u64 },
    /// Refused before any record.
    Refused(Refusal),
    /// `503` with `Retry-After`; nothing was recorded. The seq was lost
    /// [`MAX_PUTS`] times, the reservation's unit could not catch up, or
    /// the subject's private part cannot be opened now.
    Busy,
    /// The record `seq` is written, but a door store did not acknowledge:
    /// `503`. The change takes effect within the bound of the finishers.
    Unfinished { seq: u64 },
    /// `409 key_moved`: the key is tenant 0's for now (AM-20, AM-28,
    /// AM-31). Nothing was put, but an existing `m/rk/<t>/<akid>` of the
    /// key was applied to D1 first.
    KeyMoved,
    /// `200`: a revoke in force with no key-chain record: its `m/rk/` is
    /// stored and D1 refuses the key (tenant 0's path after an undo,
    /// AM-54 LOW 3; or the self-apply of a frozen chain, AM-28).
    RevokedOffChain,
    /// `503` with `Retry-After`: `<t>`'s key chain is frozen (AM-28). For
    /// a revoke, its `m/rk/<t>/<akid>` is stored and wins in every store;
    /// only its chain record is refused.
    Frozen,
}

/// Which grant limits a writer records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limits {
    /// Milestone 1 (ADR §6.2, AM-18): a create whose grant has a prefix,
    /// an expiry or an IP list, and a grant change that adds or changes
    /// one, are refused with [`Refusal::GrantLimitsNotServed`] before any
    /// reservation or record. The units cannot serve such a grant yet.
    NotServed,
    /// Every grant the record rules allow. A unit still refuses a
    /// limited grant at use (fail closed). For the record rules' own
    /// tests, and for the milestone that serves limits.
    Recorded,
}

/// Whether a grant has a prefix, an expiry or an IP list.
fn limited(g: &Grant) -> bool {
    g.prefix.is_some() || g.expires_at.is_some() || !g.ip_list.is_empty()
}

/// Whether `new` adds a limit to `current`: it holds a limited grant that
/// is not, limit for limit, the current grant of its bucket.
fn adds_limits(new: &[Grant], current: &[Grant]) -> bool {
    new.iter().any(|n| {
        limited(n)
            && !current.iter().any(|c| {
                c.bucket_id == n.bucket_id
                    && c.prefix == n.prefix
                    && c.expires_at == n.expires_at
                    && c.ip_list == n.ip_list
            })
    })
}

/// Everything a key change talks to.
pub struct KeyEnv<'a, S, K, T, A, I, U, D, C, G> {
    pub store: &'a S,
    pub kek: &'a K,
    pub ring: &'a T,
    pub tenant: &'a TenantId,
    pub admission: &'a A,
    pub intents: &'a I,
    /// Every unit that holds the tenant's key table, the root unit first.
    pub units: &'a [U],
    pub directory: &'a D,
    pub clock: &'a C,
    /// The Worker sets [`Limits::NotServed`] in milestone 1.
    pub limits: Limits,
    /// Tenant 0's head and the tenant head, read for every change
    /// ([`super::gate`]).
    pub gate: &'a G,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    Closing,
    Opening,
}

/// A change validated against the head.
pub(super) struct Plan {
    pub(super) op: KeyOp,
    pub(super) door: SubjectDoor,
    pub(super) private: Option<SubjectPrivate>,
    pub(super) class: Class,
    acting: Option<String>,
    /// A revoke: the `m/rk/` record comes first.
    revoke: bool,
}

impl Plan {
    pub(super) fn closes(&self) -> bool {
        self.class == Class::Closing
    }
}

pub(super) enum Planned {
    Change(Box<Plan>),
    /// The head already carries the effect; bring the stores up in this
    /// order.
    InHead(Class),
    Refused(Refusal),
    Busy,
}

/// Whether two wraps of `akid`'s secret hold the same secret. A wrap
/// that does not open is not the same.
fn same_secret<K: Kek>(
    kek: &K,
    tenant: &TenantId,
    akid: &str,
    a: (Option<u32>, Option<&Vec<u8>>),
    b: (Option<u32>, Option<&Vec<u8>>),
) -> bool {
    match (a, b) {
        ((None, None), (None, None)) => true,
        ((Some(va), Some(wa)), (Some(vb), Some(wb))) => {
            if wa == wb && va == vb {
                return true;
            }
            match (
                unwrap_secret_v2(kek, va, tenant, akid, wa),
                unwrap_secret_v2(kek, vb, tenant, akid, wb),
            ) {
                (Ok(x), Ok(y)) => x.len() == y.len() && bool::from(x[..].ct_eq(&y[..])),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Whether `subject` is what the head already holds for its id: the
/// retry of a create that was recorded.
fn same_create<K: Kek>(kek: &K, tenant: &TenantId, entry: &Entry, subject: &Subject) -> bool {
    let Some(private) = &entry.private else {
        return false;
    };
    let mut door = subject.door.clone();
    door.secret_kek_version = entry.door.secret_kek_version;
    door == entry.door
        && private.owner_ref == subject.private.owner_ref
        && private.label == subject.private.label
        && private.grants == subject.private.grants
        && same_secret(
            kek,
            tenant,
            &entry.door.id,
            (
                entry.door.secret_kek_version,
                private.secret_wrapped.as_ref(),
            ),
            (
                subject.door.secret_kek_version,
                subject.private.secret_wrapped.as_ref(),
            ),
        )
}

pub(super) fn plan<K: Kek>(
    kek: &K,
    table: &KeyTable,
    revoked: &BTreeSet<String>,
    request: &KeyRequest,
    limits: Limits,
) -> Planned {
    let not_served = limits == Limits::NotServed;
    match request {
        KeyRequest::Create(subject) => {
            if not_served && subject.grants().iter().any(limited) {
                return Planned::Refused(Refusal::GrantLimitsNotServed);
            }
            if revoked.contains(&subject.door.id) {
                return Planned::Refused(Refusal::Conflict);
            }
            if let Some(entry) = table.get(&subject.door.id) {
                // A retry: compared only with the private part open.
                if entry.private.is_none() {
                    return Planned::Busy;
                }
                return match same_create(kek, table.tenant(), entry, subject) {
                    true => Planned::InHead(Class::Opening),
                    false => Planned::Refused(Refusal::Conflict),
                };
            }
            match table.admits(KeyOp::Create, &subject.door, Some(&subject.private)) {
                Ok(()) => Planned::Change(Box::new(Plan {
                    op: KeyOp::Create,
                    door: subject.door.clone(),
                    private: Some(subject.private.clone()),
                    class: Class::Opening,
                    acting: subject.door.made_by.clone(),
                    revoke: false,
                })),
                Err(_) => Planned::Refused(Refusal::Conflict),
            }
        }
        KeyRequest::SetStatus { id, status } => {
            let Some(entry) = table.get(id) else {
                return Planned::Refused(Refusal::NotFound);
            };
            let revoking = *status == SubjectStatus::Revoked;
            // `m/rk/` wins: only the revoke record may follow it.
            if revoked.contains(id) && !revoking {
                return Planned::Refused(Refusal::Conflict);
            }
            let class = match status {
                SubjectStatus::Active => Class::Opening,
                _ => Class::Closing,
            };
            if entry.door.status == *status {
                // A re-enable of a subject that is closed is not in force.
                return match (class, &entry.private) {
                    (Class::Opening, None) => Planned::Busy,
                    _ => Planned::InHead(class),
                };
            }
            // A closing status change is recorded without the private part
            // when it cannot be opened (it keeps the one before); a
            // re-enable needs it.
            if entry.private.is_none() && class == Class::Opening {
                return Planned::Busy;
            }
            let mut door = entry.door.clone();
            door.status = *status;
            match table.admits(KeyOp::Status, &door, entry.private.as_ref()) {
                Ok(()) => Planned::Change(Box::new(Plan {
                    op: KeyOp::Status,
                    door,
                    private: entry.private.clone(),
                    class,
                    acting: entry.door.made_by.clone(),
                    revoke: revoking,
                })),
                Err(_) => Planned::Refused(Refusal::Conflict),
            }
        }
        KeyRequest::SetGrants { id, grants, acting } => {
            let Some(entry) = table.get(id) else {
                return Planned::Refused(Refusal::NotFound);
            };
            if revoked.contains(id) {
                return Planned::Refused(Refusal::Conflict);
            }
            let Some(subject) = entry.subject() else {
                return Planned::Busy;
            };
            // A key is bounded by the principal it was made under, and by
            // no other.
            let acting = match (&entry.door.made_by, acting) {
                (Some(p), Some(a)) if p != a => return Planned::Refused(Refusal::NotSubset),
                (Some(p), _) => Some(p.clone()),
                (None, a) => a.clone(),
            };
            let current = subject.grants();
            if current == *grants {
                // A retry is classed as the record that made it was.
                let class = match entry.closes {
                    true => Class::Closing,
                    false => Class::Opening,
                };
                return Planned::InHead(class);
            }
            // A narrowing that adds a limit is refused too: it would make a
            // key that cannot work.
            if not_served && adds_limits(grants, &current) {
                return Planned::Refused(Refusal::GrantLimitsNotServed);
            }
            // The class comes from the head, never from the caller.
            let class = match grants_narrow(grants, &current) {
                true => Class::Closing,
                false => Class::Opening,
            };
            let mut next = subject.clone();
            next.set_grants(grants);
            match table.admits(KeyOp::Grants, &next.door, Some(&next.private)) {
                Ok(()) => Planned::Change(Box::new(Plan {
                    op: KeyOp::Grants,
                    door: next.door,
                    private: Some(next.private),
                    class,
                    acting,
                    revoke: false,
                })),
                Err(_) => Planned::Refused(Refusal::Conflict),
            }
        }
        KeyRequest::DropGrant { id, bucket_id } => {
            let Some(entry) = table.get(id) else {
                return Planned::Refused(Refusal::NotFound);
            };
            // A revoked subject holds nothing in force; one without the
            // grant is where the change leads.
            let held = entry.door.grants.iter().any(|g| g.bucket_id == *bucket_id);
            if revoked.contains(id) || entry.door.status == SubjectStatus::Revoked || !held {
                return Planned::InHead(Class::Closing);
            }
            let Some(subject) = entry.subject() else {
                return Planned::Busy;
            };
            let grants: Vec<Grant> = subject
                .grants()
                .into_iter()
                .filter(|g| g.bucket_id != *bucket_id)
                .collect();
            let mut next = subject.clone();
            next.set_grants(&grants);
            match table.admits(KeyOp::Grants, &next.door, Some(&next.private)) {
                Ok(()) => Planned::Change(Box::new(Plan {
                    op: KeyOp::Grants,
                    door: next.door,
                    private: Some(next.private),
                    class: Class::Closing,
                    acting: entry.door.made_by.clone(),
                    revoke: false,
                })),
                Err(_) => Planned::Refused(Refusal::Conflict),
            }
        }
    }
}

/// What the stores acknowledged.
#[derive(Clone, Copy)]
pub(super) struct Acks {
    /// Every unit holds the head, with what does not close held closed.
    pub(super) closed: bool,
    /// The directory holds the head.
    pub(super) directory: bool,
    /// Every unit holds the head in full (only after the directory).
    pub(super) units: bool,
}

/// The subjects of `table` whose private part did not open, revoked ones
/// aside: held `disabled` wherever applied.
fn closed_subjects(table: &KeyTable) -> Vec<String> {
    table
        .entries()
        .filter(|e| e.private.is_none() && e.door.status != SubjectStatus::Revoked)
        .map(|e| e.door.id.clone())
        .collect()
}

/// The closed subjects of `table` whose private part is lost for good
/// (AM-11): sealed under a key version the ring marks gone, with a ring
/// that loaded every other committed version, and no checkpoint that may
/// still carry it. Anything less is a closed subject to retry. One pass
/// over the checkpoints, only when some subject is a candidate. Each
/// lost subject with the `private_seq` it was decided at.
pub(super) async fn lost_subjects<S: RecordStore, K: Kek, T: TkRing>(
    store: &S,
    kek: &K,
    ring: &T,
    table: &KeyTable,
) -> BTreeMap<String, u64> {
    if ring.partial() {
        return BTreeMap::new();
    }
    let candidates: Vec<&Entry> = table
        .entries()
        .filter(|e| {
            e.private.is_none()
                && e.door.status != SubjectStatus::Revoked
                && ring.gone(e.tk_version)
        })
        .collect();
    let Some(from) = candidates.iter().map(|e| e.private_seq).min() else {
        return BTreeMap::new();
    };
    let holds = checkpoint_holds(store, kek, ring, table.tenant(), from).await;
    candidates
        .into_iter()
        .filter(|e| !holds.may_hold(&e.door.id, e.private_seq))
        .map(|e| (e.door.id.clone(), e.private_seq))
        .collect()
}

impl<S, K, T, A, I, U, D, C, G> KeyEnv<'_, S, K, T, A, I, U, D, C, G>
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
{
    pub(super) fn now(&self) -> u64 {
        u64::try_from(self.clock.now().0).unwrap_or(0)
    }

    /// Brings every store to the head: the units with what closes, then
    /// the directory, then, once the directory acknowledged, the units
    /// with everything. So a closing change needs no directory, and no
    /// unit opens anything the directory does not have.
    pub(super) async fn apply_all(&self, table: &KeyTable, revoked: &BTreeSet<String>) -> Acks {
        let feed = Feed::new(self.store, self.kek, self.ring, table, revoked);
        let acked = self.directory.keys_seq().await.unwrap_or(0);
        let mut closed = true;
        for unit in self.units {
            closed &= feed.bring_up(unit, Mode::Closing { acked }).await.is_ok();
        }
        let directory = feed.bring_up(self.directory, Mode::Full).await.is_ok();
        let mut units = directory;
        if directory {
            for unit in self.units {
                units &= feed.bring_up(unit, Mode::Full).await.is_ok();
            }
        }
        Acks {
            closed,
            directory,
            units,
        }
    }

    /// The answer once the stores were brought up. Clears the pending
    /// rows up to `seq` when every store holds it with every subject open.
    pub(super) async fn answer(
        &self,
        class: Class,
        table: &KeyTable,
        seq: u64,
        acks: Acks,
    ) -> KeyAnswer {
        let done = match class {
            Class::Closing => acks.closed,
            Class::Opening => acks.units && acks.directory,
        };
        if acks.units && acks.directory && closed_subjects(table).is_empty() {
            let _ = self
                .intents
                .clear(self.tenant, ControlChain::Keys, seq)
                .await;
        }
        match done {
            true => KeyAnswer::Done { seq },
            false => KeyAnswer::Unfinished { seq },
        }
    }

    /// Runs one key change. `table` is the caller's copy of the key
    /// table (cached per isolate, any age); it is brought to the head
    /// here and left there.
    pub async fn change<R: FillRandom>(
        &self,
        table: &mut KeyTable,
        idempotency_key: &str,
        request: &KeyRequest,
        rng: &mut R,
    ) -> Result<KeyAnswer> {
        let chain = key_chain(self.tenant);
        let mut puts = 0;
        let mut caught_up = false;
        let mut caught_up_in_full = false;
        while puts < MAX_PUTS {
            // Read for every attempt: a retry validates against the
            // revocations as they are now.
            let mut revoked: BTreeSet<String> = list_tenant_revocations(self.store, self.tenant)
                .await?
                .into_iter()
                .collect();
            advance(self.store, self.kek, self.ring, &chain, table).await?;
            // A cached table opens what this ring can open now.
            reopen_closed(self.store, self.kek, self.ring, &chain, table).await?;
            // Best effort: a closing change never waits on a checkpoint.
            let _ = reopen_from_checkpoints(self.store, self.kek, self.ring, table).await;
            // Tenant 0's head, for every attempt and after the key chain: a
            // give-up writes tenant 0's `d1` record before its key-chain
            // records, so a writer that has folded one sees `d1` here.
            let Ok(zero) = self.gate.zero_head().await else {
                return Ok(KeyAnswer::Busy);
            };
            // The move rules, against this head: a writer that lost its
            // put reads the head again and checks again, so no record from
            // before a freeze lands above it.
            match self.move_rules(&zero, table, request).await {
                Gate::Go => {}
                Gate::KeyMoved { pre_apply } => {
                    let id = subject_of(request);
                    if pre_apply
                        && revoked.contains(id)
                        && self.gate.refuse_in_d1(id).await.is_err()
                    {
                        return Ok(KeyAnswer::Busy);
                    }
                    return Ok(KeyAnswer::KeyMoved);
                }
                Gate::ZeroRevoke => {
                    return Ok(match self.gate.zero_revoke(subject_of(request)).await {
                        Ok(()) => KeyAnswer::RevokedOffChain,
                        Err(_) => KeyAnswer::Busy,
                    })
                }
                Gate::FrozenRevoke => {
                    return self
                        .frozen_revoke(table, &mut revoked, subject_of(request), rng)
                        .await
                }
                Gate::Unavailable => {
                    return Ok(match table.frozen_at() {
                        Some(_) => KeyAnswer::Frozen,
                        None => KeyAnswer::Busy,
                    })
                }
            }
            let plan = match plan(self.kek, table, &revoked, request, self.limits) {
                Planned::Refused(r) => return Ok(KeyAnswer::Refused(r)),
                Planned::Busy => return Ok(KeyAnswer::Busy),
                Planned::InHead(class) => {
                    let acks = self.apply_all(table, &revoked).await;
                    return Ok(self.answer(class, table, table.seq(), acks).await);
                }
                Planned::Change(p) => p,
            };
            // Reservation, for an opening change: the record must be
            // exactly its keys_seq + 1.
            let seq = match plan.class {
                Class::Closing => table.seq() + 1,
                Class::Opening => {
                    // Opening plans always carry an open private part.
                    let Some(private) = plan.private.clone() else {
                        return Ok(KeyAnswer::Busy);
                    };
                    let subject = Subject {
                        door: plan.door.clone(),
                        private,
                    };
                    let change = OpeningChange {
                        op: plan.op,
                        subject: &subject,
                        acting: plan.acting.as_deref(),
                    };
                    match self
                        .admission
                        .admit(self.tenant, idempotency_key, &change)
                        .await?
                    {
                        // A refusal by a unit that is behind the head
                        // (restored, or down during a change) may be
                        // stale: bring the units up once and ask again.
                        Admission::Refused(Refusal::NotSubset | Refusal::CapFull) if !caught_up => {
                            caught_up = true;
                            caught_up_in_full = self.apply_all(table, &revoked).await.units;
                            puts += 1;
                            continue;
                        }
                        // A refusal after a catch-up that did not reach
                        // every unit in full may still be stale.
                        Admission::Refused(Refusal::NotSubset | Refusal::CapFull)
                            if !caught_up_in_full =>
                        {
                            return Ok(KeyAnswer::Busy)
                        }
                        Admission::Refused(r) => return Ok(KeyAnswer::Refused(r)),
                        Admission::Admitted { keys_seq } if keys_seq == table.seq() => keys_seq + 1,
                        Admission::Admitted { keys_seq } => {
                            // The unit is behind the head: bring it up and
                            // ask again. Ahead: our copy is stale; the loop
                            // reads the head again.
                            if keys_seq < table.seq() {
                                let _ = self.apply_all(table, &revoked).await;
                            }
                            puts += 1;
                            continue;
                        }
                    }
                }
            };

            // Intent: the message is the durable part.
            self.intents
                .send(self.tenant, ControlChain::Keys, seq)
                .await?;
            let _ = self
                .intents
                .note(self.tenant, ControlChain::Keys, seq, op_kind(&plan))
                .await;

            if plan.revoke {
                put_tenant_revocation(
                    self.store,
                    self.kek,
                    self.tenant,
                    &plan.door.id,
                    self.now(),
                    rng,
                )
                .await?;
                revoked.insert(plan.door.id.clone());
                // A revoke that read the move's window: the window may have
                // ended since (a give-up, whose sweep this `m/rk/` may have
                // missed). Decide by the head now (AM-31, AM-54 LOW 3).
                if matches!(&zero, ZeroHead::Moving { to } if to == self.tenant) {
                    let Ok(now) = self.gate.zero_head().await else {
                        return Ok(KeyAnswer::Busy);
                    };
                    match self.move_rules(&now, table, request).await {
                        Gate::KeyMoved { .. } => {
                            return Ok(match self.gate.refuse_in_d1(&plan.door.id).await {
                                Ok(()) => KeyAnswer::KeyMoved,
                                Err(_) => KeyAnswer::Busy,
                            })
                        }
                        Gate::ZeroRevoke => {
                            return Ok(match self.gate.zero_revoke(&plan.door.id).await {
                                Ok(()) => KeyAnswer::RevokedOffChain,
                                Err(_) => KeyAnswer::Busy,
                            })
                        }
                        Gate::FrozenRevoke => {
                            return self
                                .frozen_revoke(table, &mut revoked, &plan.door.id, rng)
                                .await
                        }
                        Gate::Unavailable => return Ok(KeyAnswer::Busy),
                        Gate::Go => {}
                    }
                }
            }
            if plan.op == KeyOp::Create && plan.door.kind.has_secret() {
                let routed = put_route(
                    self.store,
                    self.kek,
                    self.tenant,
                    &plan.door.id,
                    plan.door.kind,
                    self.now(),
                    rng,
                )
                .await?;
                if routed == RoutePut::Taken {
                    // No record will be written for this reservation; the
                    // finisher of this intent clears its row.
                    let _ = self.admission.release(self.tenant, idempotency_key).await;
                    return Ok(KeyAnswer::Refused(Refusal::IdTaken));
                }
            }

            let bytes = seal_key_record(
                self.kek,
                self.ring,
                self.tenant,
                seq,
                plan.op,
                self.now(),
                &plan.door,
                plan.private.as_ref(),
                plan.closes(),
                table.frozen_at(),
                rng,
            )?;
            match chain.put(self.store, seq, bytes.clone()).await? {
                Put::Lost => {
                    puts += 1;
                    continue;
                }
                Put::Written => {}
            }
            let record = open_key_record(self.kek, self.ring, self.tenant, seq, &bytes)?;
            table.apply(&record)?;

            let acks = self.apply_all(table, &revoked).await;
            return Ok(self.answer(plan.class, table, seq, acks).await);
        }
        Ok(KeyAnswer::Busy)
    }
}

impl<S, K, T, A, I, U, D, C, G> KeyEnv<'_, S, K, T, A, I, U, D, C, G>
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
{
    /// The move rules for `request` at `table`'s head ([`super::gate`]).
    pub(super) async fn move_rules(
        &self,
        zero: &ZeroHead,
        table: &KeyTable,
        request: &KeyRequest,
    ) -> Gate {
        let kind = change_kind(request);
        let id = subject_of(request);
        let key_held =
            kind != ChangeKind::Create && table.get(id).is_some_and(|e| e.door.kind.has_secret());
        // A missing or unverifiable route is not this tenant's (AM-31).
        let routed_here = match needs_route(zero, kind, key_held) {
            false => None,
            true => Some(matches!(
                read_route(self.store, self.kek, id).await,
                Ok(Some(r)) if r.tenant == self.tenant.as_str()
            )),
        };
        let internal = table
            .get(id)
            .is_some_and(|e| e.door.kind == SubjectKind::Internal);
        decide(&Facts {
            tenant: self.tenant,
            zero,
            frozen: table.frozen_at().is_some(),
            kind,
            key_held,
            internal,
            routed_here,
        })
    }

    /// A revoke on a frozen chain (AM-28): `m/rk/<t>/<akid>` is put (a
    /// revocation always wins), the chain record is refused, and tenant
    /// 0's head is read again. If it has become `d1` (after the undo, or a
    /// give-up), D1 is the store that serves the key: the revocation is
    /// applied to it here, and the answer is `200` once D1 refuses the
    /// key. Otherwise `503`; the stores get the revocation from its
    /// `m/rk/`, and the finisher records it after the thaw.
    async fn frozen_revoke<R: FillRandom>(
        &self,
        table: &KeyTable,
        revoked: &mut BTreeSet<String>,
        id: &str,
        rng: &mut R,
    ) -> Result<KeyAnswer> {
        // The gate sends only a key's revoke here; anything else is 503.
        match table.get(id) {
            None => return Ok(KeyAnswer::Refused(Refusal::NotFound)),
            Some(e) if !e.door.kind.has_secret() => return Ok(KeyAnswer::Frozen),
            Some(_) => {}
        }
        put_tenant_revocation(self.store, self.kek, self.tenant, id, self.now(), rng).await?;
        revoked.insert(id.to_owned());
        // Best effort: a unit that still holds the key closes it by the
        // override.
        let _ = self.apply_all(table, revoked).await;
        // `<t>`'s internal key: D1 never holds it; its `m/rk/<t>/` is the
        // revocation, and D1 refuses it already.
        let to_d1 = match self.gate.zero_head().await {
            Ok(ZeroHead::Undone { to }) => to == *self.tenant,
            Ok(ZeroHead::D1) => true,
            _ => false,
        };
        if to_d1 && self.gate.refuse_in_d1(id).await.is_ok() {
            return Ok(KeyAnswer::RevokedOffChain);
        }
        Ok(KeyAnswer::Frozen)
    }
}

/// The subject a request names.
pub(super) fn subject_of(request: &KeyRequest) -> &str {
    match request {
        KeyRequest::Create(s) => &s.door.id,
        KeyRequest::SetStatus { id, .. }
        | KeyRequest::SetGrants { id, .. }
        | KeyRequest::DropGrant { id, .. } => id,
    }
}

/// The gate's class of a request.
fn change_kind(request: &KeyRequest) -> ChangeKind {
    match request {
        KeyRequest::Create(_) => ChangeKind::Create,
        KeyRequest::SetStatus {
            status: SubjectStatus::Revoked,
            ..
        } => ChangeKind::Revoke,
        _ => ChangeKind::Other,
    }
}

pub(super) fn op_kind(plan: &Plan) -> &'static str {
    match (plan.op, plan.door.status) {
        (KeyOp::Create, _) => "key.create",
        (KeyOp::Status, SubjectStatus::Revoked) => "key.revoke",
        (KeyOp::Status, SubjectStatus::Disabled) => "key.disable",
        (KeyOp::Status, SubjectStatus::Active) => "key.enable",
        (KeyOp::Grants, _) => "key.grants",
        (KeyOp::Restate, _) => "key.restate",
    }
}

// ---------------------------------------------------------------------------
// Finisher
// ---------------------------------------------------------------------------

/// What one run of the finisher did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FinishReport {
    /// The head after the run.
    pub head: u64,
    /// Revoke records appended for `m/rk/` revocations.
    pub appended: Vec<u64>,
    /// Disable records appended for subjects under a gone key version.
    pub gone_disabled: Vec<u64>,
    /// Subjects whose revoke record (for an `m/rk/` revocation) or
    /// disable record (for a gone key version) could not be appended (the
    /// tenant key could not be loaded, a store error). A revocation is in
    /// force in the stores all the same, by its `m/rk/` record.
    pub append_failed: Vec<String>,
    /// Stores that did not acknowledge, by label; `chain` when the chain
    /// could not be read to its head.
    pub failed: Vec<String>,
    /// The checkpoint written by this run.
    pub checkpoint: Option<u64>,
    /// A checkpoint was due and was not written (closed subjects, a store
    /// error). Nothing waits for it.
    pub checkpoint_skipped: bool,
    /// Subjects whose private part did not open: disabled wherever
    /// applied; an attention condition.
    pub closed: Vec<String>,
    /// Subjects whose private part is sealed under a key version that is
    /// gone (`KeyVersionGone`, AM-11): applied `disabled` from the door
    /// part (a revoked one stays revoked), not retried, so their pending
    /// rows clear; one page each.
    pub gone: Vec<String>,
    /// The head carries the undo's freeze (AM-28): no record was
    /// appended; an `m/rk/` revocation without its chain record counts as
    /// done, and the `pending_ops` rows are cleared.
    pub frozen: bool,
}

impl FinishReport {
    /// Whether the run must be retried by the queue: a store failed, a
    /// revoke record is missing, or a subject is still closed (a run with
    /// its key must send it again).
    pub fn retry(&self) -> bool {
        !self.failed.is_empty() || !self.append_failed.is_empty() || !self.closed.is_empty()
    }
}

/// Appends a closing status record for `id` (`revoked` or `disabled`)
/// at the head, with its private part as the head holds it (none when it
/// does not open: the record keeps the one before). `Some(Some(seq))`:
/// written at `seq`; `Some(None)`: the head already carries it (or a
/// revoke, or no such subject); `None`: it could not be written.
async fn append_status<S, K, T, A, I, U, D, C, G, R>(
    env: &KeyEnv<'_, S, K, T, A, I, U, D, C, G>,
    table: &mut KeyTable,
    id: &str,
    status: SubjectStatus,
    lost_at: Option<u64>,
    rng: &mut R,
) -> Option<Option<u64>>
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
    for _ in 0..MAX_PUTS {
        advance(env.store, env.kek, env.ring, &chain, table)
            .await
            .ok()?;
        // A frozen head takes no record (AM-28): a revocation is done by
        // its `m/rk/`, which every store applies; a gone version's subject
        // stays closed, so disabled, until the thaw.
        if table.frozen_at().is_some() {
            return Some(None);
        }
        let entry = match table.get(id) {
            None => return Some(None),
            Some(e) if e.door.status == SubjectStatus::Revoked || e.door.status == status => {
                return Some(None)
            }
            Some(e) => e,
        };
        // A disable for a lost private part: only while the subject is
        // still closed with that private part under a gone version (a
        // record that landed since may have opened it).
        if let Some(private_seq) = lost_at {
            let still = entry.private.is_none()
                && entry.private_seq == private_seq
                && env.ring.gone(entry.tk_version)
                && entry.door.status == SubjectStatus::Active;
            if !still {
                return Some(None);
            }
        }
        let mut door = entry.door.clone();
        door.status = status;
        let private = entry.private.clone();
        let seq = table.seq() + 1;
        let bytes = seal_key_record(
            env.kek,
            env.ring,
            env.tenant,
            seq,
            KeyOp::Status,
            env.now(),
            &door,
            private.as_ref(),
            true,
            None,
            rng,
        )
        .ok()?;
        match chain.put(env.store, seq, bytes.clone()).await {
            Ok(Put::Written) => {
                let record = open_key_record(env.kek, env.ring, env.tenant, seq, &bytes).ok()?;
                table.apply(&record).ok()?;
                return Some(Some(seq));
            }
            Ok(Put::Lost) => {}
            Err(_) => return None,
        }
    }
    None
}

/// Finishes every key change of `tenant` whose record is written: the
/// consumer of `apply_control(tenant, keys, _)`, the lease renewal's
/// catch-up and the pending sweep all call it. An `Err` (the chain could
/// not be read), or a report that asks for a retry, makes the queue
/// retry.
pub async fn finish_keys<S, K, T, A, I, U, D, C, G, R>(
    env: &KeyEnv<'_, S, K, T, A, I, U, D, C, G>,
    rng: &mut R,
) -> Result<FinishReport>
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
    let read = read_key_chain(env.store, env.kek, env.ring, env.tenant).await?;
    let mut report = FinishReport::default();
    let mut table = read.table.clone();

    // A revocation whose chain record is missing: append it. A failure
    // here stops nothing below: the stores get the revocation from its
    // `m/rk/` record.
    for id in read.unrecorded_revocations() {
        match append_status(env, &mut table, &id, SubjectStatus::Revoked, None, rng).await {
            Some(Some(seq)) => report.appended.push(seq),
            Some(None) => {}
            None => report.append_failed.push(id),
        }
    }
    // A subject whose private part is sealed under a gone key version
    // (AM-11) never opens again: it is disabled by a record that keeps
    // its private part as it was, so every store closes it whatever row
    // it holds. A revoked one stays revoked.
    let mut lost = BTreeMap::new();
    if advance(env.store, env.kek, env.ring, &chain, &mut table)
        .await
        .is_ok()
    {
        lost = lost_subjects(env.store, env.kek, env.ring, &table).await;
        let gone: Vec<(String, u64)> = table
            .entries()
            .filter(|e| {
                lost.contains_key(&e.door.id)
                    && e.door.status == SubjectStatus::Active
                    && !read.revoked.contains(&e.door.id)
            })
            .map(|e| (e.door.id.clone(), e.private_seq))
            .collect();
        for (id, private_seq) in gone {
            let disabled = append_status(
                env,
                &mut table,
                &id,
                SubjectStatus::Disabled,
                Some(private_seq),
                rng,
            )
            .await;
            match disabled {
                Some(Some(seq)) => report.gone_disabled.push(seq),
                Some(None) => {}
                None => report.append_failed.push(id),
            }
        }
    }
    // A chain that cannot be read to its head is a failed run: the stores
    // get the verified prefix, and the queue retries.
    if advance(env.store, env.kek, env.ring, &chain, &mut table)
        .await
        .is_err()
    {
        report.failed.push("chain".to_owned());
    }

    // The units with what closes, the directory, then the units in full
    // once the directory has the head: nothing opens at a unit before the
    // directory has it.
    let feed = Feed::new(env.store, env.kek, env.ring, &table, &read.revoked);
    let acked = env.directory.keys_seq().await.unwrap_or(0);
    for unit in env.units {
        if feed.bring_up(unit, Mode::Closing { acked }).await.is_err() {
            report.failed.push(unit.label().to_owned());
        }
    }
    if feed.bring_up(env.directory, Mode::Full).await.is_err() {
        report.failed.push(env.directory.label().to_owned());
    } else {
        for unit in env.units {
            if feed.bring_up(unit, Mode::Full).await.is_err()
                && !report.failed.iter().any(|l| l == unit.label())
            {
                report.failed.push(unit.label().to_owned());
            }
        }
    }

    // A checkpoint when one is due, from the newest one that verified.
    // Best effort: nothing waits for it.
    let due = read
        .from_checkpoint
        .unwrap_or(0)
        .saturating_add(CHECKPOINT_EVERY);
    if table.seq() >= due {
        let written = async {
            let record = chain.get(env.store, table.seq()).await?;
            let sealed = seal_checkpoint(env.kek, env.ring, &table, &record, rng)?;
            env.store
                .put_if_absent(&checkpoint_name(env.tenant, table.seq()), sealed)
                .await
        }
        .await;
        match written {
            Ok(true) => report.checkpoint = Some(table.seq()),
            // Another finisher wrote it first.
            Ok(false) => {}
            Err(_) => report.checkpoint_skipped = true,
        }
    }

    report.head = table.seq();
    report.frozen = table.frozen_at().is_some();
    // Gone: decided above, and still closed with the same private part
    // under a gone version (a disable record keeps both). A record that
    // landed since makes it an ordinary closed subject, retried.
    let (gone, closed): (Vec<String>, Vec<String>) =
        closed_subjects(&table).into_iter().partition(|id| {
            table.get(id).is_some_and(|e| {
                lost.get(id) == Some(&e.private_seq)
                    && e.private.is_none()
                    && env.ring.gone(e.tk_version)
            })
        });
    report.closed = closed;
    report.gone = gone;
    if !report.retry() {
        let _ = env
            .intents
            .clear(env.tenant, ControlChain::Keys, report.head)
            .await;
    }
    Ok(report)
}
