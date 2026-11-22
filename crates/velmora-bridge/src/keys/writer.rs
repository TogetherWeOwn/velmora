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

use std::collections::BTreeSet;

use subtle::ConstantTimeEq;
use velmora::rng::FillRandom;

use super::chain::Put;
use super::checkpoint::{
    advance, checkpoint_name, read_key_chain, reopen_closed, reopen_from_checkpoints,
    seal_checkpoint, CHECKPOINT_EVERY,
};
use super::ports::{
    Admission, ControlChain, ControlIntents, KeyAdmission, KeyTarget, OpeningChange, Refusal,
};
use super::record::{
    grants_narrow, key_chain, open_key_record, seal_key_record, Entry, Grant, KeyOp, KeyTable,
    Subject, SubjectDoor, SubjectPrivate, SubjectStatus, TkRing,
};
use super::revocations::{list_tenant_revocations, put_tenant_revocation};
use super::routes::{put_route, RoutePut};
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
}

/// Everything a key change talks to.
pub struct KeyEnv<'a, S, K, T, A, I, U, D, C> {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Closing,
    Opening,
}

/// A change validated against the head.
struct Plan {
    op: KeyOp,
    door: SubjectDoor,
    private: Option<SubjectPrivate>,
    class: Class,
    acting: Option<String>,
    /// A revoke: the `m/rk/` record comes first.
    revoke: bool,
}

impl Plan {
    fn closes(&self) -> bool {
        self.class == Class::Closing
    }
}

enum Planned {
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

fn plan<K: Kek>(
    kek: &K,
    table: &KeyTable,
    revoked: &BTreeSet<String>,
    request: &KeyRequest,
) -> Planned {
    match request {
        KeyRequest::Create(subject) => {
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
    }
}

/// The status in force of an entry, `m/rk/` included.
fn in_force(e: &Entry, revoked: &BTreeSet<String>) -> Entry {
    let mut e = e.clone();
    if revoked.contains(&e.door.id) {
        e.door.status = SubjectStatus::Revoked;
    }
    e
}

/// The entries a store at `held`, holding `closed` closed, needs to reach
/// `table.seq()`, with the revocations in force.
fn entries_for(
    table: &KeyTable,
    held: u64,
    revoked: &BTreeSet<String>,
    closed: &BTreeSet<String>,
) -> Vec<Entry> {
    table
        .entries()
        .filter(|e| {
            e.last_seq > held || revoked.contains(&e.door.id) || closed.contains(&e.door.id)
        })
        .map(|e| in_force(e, revoked))
        .collect()
}

/// Brings one unit to the table's seq before the directory acknowledged
/// the head. `acked` is the seq the directory holds (0 when it cannot be
/// read). A subject whose newest opening record (`opened_seq`) is above
/// it is sent closed (held `disabled` until a run after the directory
/// opens it); any other is sent as it is. So nothing opens at a unit
/// before the directory has it, a closing record that follows an
/// unacknowledged opening one does not open it either, and the unit
/// still reaches the head.
async fn bring_up_closing<U: KeyTarget>(
    target: &U,
    table: &KeyTable,
    revoked: &BTreeSet<String>,
    acked: u64,
) -> Result<()> {
    let held = target.keys_seq().await?;
    if held >= table.seq() && revoked.is_empty() {
        return Ok(());
    }
    // What the unit holds closed: an opening it holds open at or below
    // its own seq was opened there after a directory acknowledged it.
    let closed: BTreeSet<String> = target.closed().await?.into_iter().collect();
    let none = BTreeSet::new();
    let entries: Vec<Entry> = entries_for(table, held, revoked, &none)
        .into_iter()
        .map(|mut e| {
            let acknowledged =
                e.opened_seq <= acked || (e.opened_seq <= held && !closed.contains(&e.door.id));
            if !acknowledged && e.door.status != SubjectStatus::Revoked {
                e.private = None;
            }
            e
        })
        .collect();
    target.apply(table.seq(), &entries).await
}

/// Brings one store to the table's seq.
async fn bring_up<U: KeyTarget>(
    target: &U,
    table: &KeyTable,
    revoked: &BTreeSet<String>,
) -> Result<()> {
    let held = target.keys_seq().await?;
    let closed: BTreeSet<String> = target.closed().await?.into_iter().collect();
    if held >= table.seq() && revoked.is_empty() && closed.is_empty() {
        return Ok(());
    }
    target
        .apply(table.seq(), &entries_for(table, held, revoked, &closed))
        .await
}

/// What the stores acknowledged.
#[derive(Clone, Copy)]
struct Acks {
    /// Every unit holds the head, with what does not close held closed.
    closed: bool,
    /// The directory holds the head.
    directory: bool,
    /// Every unit holds the head in full (only after the directory).
    units: bool,
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

impl<S, K, T, A, I, U, D, C> KeyEnv<'_, S, K, T, A, I, U, D, C>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    A: KeyAdmission,
    I: ControlIntents,
    U: KeyTarget,
    D: KeyTarget,
    C: Clock,
{
    fn now(&self) -> u64 {
        u64::try_from(self.clock.now().0).unwrap_or(0)
    }

    /// Brings every store to the head: the units with what closes, then
    /// the directory, then, once the directory acknowledged, the units
    /// with everything. So a closing change needs no directory, and no
    /// unit opens anything the directory does not have.
    async fn apply_all(&self, table: &KeyTable, revoked: &BTreeSet<String>) -> Acks {
        let acked = self.directory.keys_seq().await.unwrap_or(0);
        let mut closed = true;
        for unit in self.units {
            closed &= bring_up_closing(unit, table, revoked, acked).await.is_ok();
        }
        let directory = bring_up(self.directory, table, revoked).await.is_ok();
        let mut units = directory;
        if directory {
            for unit in self.units {
                units &= bring_up(unit, table, revoked).await.is_ok();
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
    async fn answer(&self, class: Class, table: &KeyTable, seq: u64, acks: Acks) -> KeyAnswer {
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
        let mut revoked: BTreeSet<String> = list_tenant_revocations(self.store, self.tenant)
            .await?
            .into_iter()
            .collect();
        let mut puts = 0;
        let mut caught_up = false;
        let mut caught_up_in_full = false;
        while puts < MAX_PUTS {
            advance(self.store, self.kek, self.ring, &chain, table).await?;
            // A cached table opens what this ring can open now.
            reopen_closed(self.store, self.kek, self.ring, &chain, table).await?;
            reopen_from_checkpoints(self.store, self.kek, self.ring, table).await?;
            let plan = match plan(self.kek, table, &revoked, request) {
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
                    // The finisher of this intent clears its row.
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

fn op_kind(plan: &Plan) -> &'static str {
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
    /// Revocations whose revoke record could not be appended (the tenant
    /// key could not be loaded, a store error): they are in force in the
    /// stores all the same, by their `m/rk/` record.
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
}

impl FinishReport {
    /// Whether the run must be retried by the queue: a store failed, a
    /// revoke record is missing, or a subject is still closed (a run with
    /// its key must send it again).
    pub fn retry(&self) -> bool {
        !self.failed.is_empty() || !self.append_failed.is_empty() || !self.closed.is_empty()
    }
}

/// Finishes every key change of `tenant` whose record is written: the
/// consumer of `apply_control(tenant, keys, _)`, the lease renewal's
/// catch-up and the pending sweep all call it. An `Err` (the chain could
/// not be read), or a report that asks for a retry, makes the queue
/// retry.
pub async fn finish_keys<S, K, T, A, I, U, D, C, R>(
    env: &KeyEnv<'_, S, K, T, A, I, U, D, C>,
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
        let mut appended = false;
        for _ in 0..MAX_PUTS {
            if advance(env.store, env.kek, env.ring, &chain, &mut table)
                .await
                .is_err()
            {
                break;
            }
            let Some(entry) = table.get(&id) else {
                appended = true;
                break;
            };
            if entry.door.status == SubjectStatus::Revoked {
                appended = true;
                break;
            }
            let mut door = entry.door.clone();
            door.status = SubjectStatus::Revoked;
            let private = entry.private.clone();
            let seq = table.seq() + 1;
            let Ok(bytes) = seal_key_record(
                env.kek,
                env.ring,
                env.tenant,
                seq,
                KeyOp::Status,
                env.now(),
                &door,
                private.as_ref(),
                true,
                rng,
            ) else {
                break;
            };
            match chain.put(env.store, seq, bytes.clone()).await {
                Ok(Put::Written) => {
                    if let Ok(record) = open_key_record(env.kek, env.ring, env.tenant, seq, &bytes)
                    {
                        if table.apply(&record).is_ok() {
                            report.appended.push(seq);
                            appended = true;
                        }
                    }
                    break;
                }
                Ok(Put::Lost) => {}
                Err(_) => break,
            }
        }
        if !appended {
            report.append_failed.push(id);
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
    let acked = env.directory.keys_seq().await.unwrap_or(0);
    for unit in env.units {
        if bring_up_closing(unit, &table, &read.revoked, acked)
            .await
            .is_err()
        {
            report.failed.push(unit.label().to_owned());
        }
    }
    if bring_up(env.directory, &table, &read.revoked)
        .await
        .is_err()
    {
        report.failed.push(env.directory.label().to_owned());
    } else {
        for unit in env.units {
            if bring_up(unit, &table, &read.revoked).await.is_err()
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
    report.closed = closed_subjects(&table);
    if !report.retry() {
        let _ = env
            .intents
            .clear(env.tenant, ControlChain::Keys, report.head)
            .await;
    }
    Ok(report)
}
