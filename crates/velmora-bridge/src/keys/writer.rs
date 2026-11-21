//! The record-first key writer and the finisher of the key chain.
//!
//! Every key change runs its writes in a fixed order. Each step is
//! idempotent with the record's seq:
//!
//! | Change | Order |
//! |---|---|
//! | Closing: revoke, disable, narrow | intent → (`m/rk/` for a revoke) → record → root unit → other units → directory |
//! | Opening: create, re-enable, widen | reservation → intent → (`m/kr/` for a new key) → record → directory → root unit → other units |
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
//!   but still brings every store to the head, in the order of its class,
//!   and waits for each: a retry after a crash must not answer `200` for
//!   a key that a store still accepts, nor `409` for a key it created.
//! - **A closing change needs no directory.** The directory step and the
//!   `pending_ops` row are best effort; the units are the door.
//! - **`m/rk/` wins.** A subject with a revocation takes no change but
//!   its revoke record, whatever its chain says.
//! - **A private part that does not open is never folded into a new
//!   record** but a revoke's: a disable, narrowing or re-enable of such a
//!   subject answers busy until its key can be loaded, so no record ever
//!   drops a prefix, an IP list or a secret for good.
//! - **The answer.** `Done` only after the door stores acknowledged. A
//!   record that is written while a store cannot be reached answers
//!   [`KeyAnswer::Unfinished`] (`503`); the queue message, the lease
//!   renewal and the pending sweep finish it.
//!
//! [`finish_keys`] is the consumer of `apply_control(tenant, keys, seq)`.
//! It reads the head (never the message's seq), appends a revoke record
//! for every `m/rk/` revocation that the chain does not yet carry,
//! brings every store to the head (the directory first; with the
//! directory down, the units get the closing entries only), writes a
//! checkpoint when one is due, and clears the `pending_ops` rows up to
//! the head once every store holds it. A step that fails is reported and
//! does not stop the others.

use std::collections::BTreeSet;

use subtle::ConstantTimeEq;
use velmora::rng::FillRandom;

use super::chain::Put;
use super::checkpoint::{
    advance, checkpoint_name, read_key_chain, seal_checkpoint, CHECKPOINT_EVERY,
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
use super::store::RecordStore;
use crate::crypto::scheme2::{unwrap_secret_v2, TenantId};
use crate::ports::{Clock, Kek};
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
            // Only a revoke may be recorded without the private part.
            if entry.private.is_none() && !revoking {
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
                return Planned::InHead(Class::Closing);
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

/// Applies the closing entries of the table to one store, without moving
/// its `keys_seq`: what a unit gets while the directory, which opening
/// changes go to first, cannot be reached.
async fn close_only<U: KeyTarget>(
    target: &U,
    table: &KeyTable,
    revoked: &BTreeSet<String>,
) -> Result<()> {
    let held = target.keys_seq().await?;
    let closing: Vec<Entry> = table
        .entries()
        .map(|e| in_force(e, revoked))
        .filter(|e| e.effective_status() != SubjectStatus::Active)
        .collect();
    target.apply(held, &closing).await
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

    /// Applies the head to the units, in order. `false` when one did not
    /// acknowledge.
    async fn apply_units(&self, table: &KeyTable, revoked: &BTreeSet<String>) -> bool {
        let mut all = true;
        for unit in self.units {
            all &= bring_up(unit, table, revoked).await.is_ok();
        }
        all
    }

    /// Brings every store to the head in the order of `class`. `units` is
    /// whether every unit acknowledged, `directory` whether it did.
    async fn apply_all(
        &self,
        class: Class,
        table: &KeyTable,
        revoked: &BTreeSet<String>,
    ) -> (bool, bool) {
        match class {
            Class::Closing => {
                let units = self.apply_units(table, revoked).await;
                let directory = bring_up(self.directory, table, revoked).await.is_ok();
                (units, directory)
            }
            Class::Opening => {
                let directory = bring_up(self.directory, table, revoked).await.is_ok();
                // Directory first: with it down, no unit opens anything.
                let units = directory && self.apply_units(table, revoked).await;
                (units, directory)
            }
        }
    }

    /// The answer once the stores were brought up. Clears the pending
    /// rows up to `seq` when every store holds it.
    async fn answer(&self, class: Class, seq: u64, (units, directory): (bool, bool)) -> KeyAnswer {
        let done = match class {
            Class::Closing => units,
            Class::Opening => units && directory,
        };
        if units && directory {
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
        while puts < MAX_PUTS {
            advance(self.store, self.kek, self.ring, &chain, table).await?;
            let plan = match plan(self.kek, table, &revoked, request) {
                Planned::Refused(r) => return Ok(KeyAnswer::Refused(r)),
                Planned::Busy => return Ok(KeyAnswer::Busy),
                Planned::InHead(class) => {
                    let acks = self.apply_all(class, table, &revoked).await;
                    return Ok(self.answer(class, table.seq(), acks).await);
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
                        Admission::Refused(r) => return Ok(KeyAnswer::Refused(r)),
                        Admission::Admitted { keys_seq } if keys_seq == table.seq() => keys_seq + 1,
                        Admission::Admitted { keys_seq } => {
                            // The unit is behind the head: bring it up and
                            // ask again. Ahead: our copy is stale; the loop
                            // reads the head again.
                            if keys_seq < table.seq() {
                                let _ = self.apply_units(table, &revoked).await;
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

            let acks = self.apply_all(plan.class, table, &revoked).await;
            return Ok(self.answer(plan.class, seq, acks).await);
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
    /// Stores that did not acknowledge, by label.
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
    /// Whether the run must be retried by the queue.
    pub fn retry(&self) -> bool {
        !self.failed.is_empty() || !self.append_failed.is_empty()
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
    let _ = advance(env.store, env.kek, env.ring, &chain, &mut table).await;

    // The directory first: opening entries go there before any unit.
    let directory = bring_up(env.directory, &table, &read.revoked).await.is_ok();
    if !directory {
        report.failed.push(env.directory.label().to_owned());
    }
    for unit in env.units {
        let applied = match directory {
            true => bring_up(unit, &table, &read.revoked).await,
            false => close_only(unit, &table, &read.revoked).await,
        };
        if applied.is_err() {
            report.failed.push(unit.label().to_owned());
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
    report.closed = table
        .entries()
        .filter(|e| e.private.is_none() && e.door.status != SubjectStatus::Revoked)
        .map(|e| e.door.id.clone())
        .collect();
    if !report.retry() {
        let _ = env
            .intents
            .clear(env.tenant, ControlChain::Keys, report.head)
            .await;
    }
    Ok(report)
}
