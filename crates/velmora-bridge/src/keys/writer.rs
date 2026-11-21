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
//!   earlier record has already narrowed or revoked.
//! - **A closing call is idempotent by the chain.** A request whose
//!   effect the head already carries writes no record, but still applies
//!   the head to every store and waits for each: a retry after a crash
//!   must not answer `200` for a key that a store still accepts.
//! - **A closing change needs no directory.** The directory step and the
//!   `pending_ops` row are best effort; the units are the door.
//! - **The answer.** `Done` only after the door stores acknowledged.
//!   A record that is written while a store cannot be reached answers
//!   [`KeyAnswer::Unfinished`] (`503`); the queue message, the lease
//!   renewal and the pending sweep finish it.
//!
//! [`finish_keys`] is the consumer of `apply_control(tenant, keys, seq)`.
//! It reads the head (never the message's seq), appends a revoke record
//! for every `m/rk/` revocation that the chain does not yet carry,
//! applies the head to every store, writes a checkpoint when one is due,
//! and clears the `pending_ops` row.

use std::collections::BTreeSet;

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
use crate::crypto::scheme2::TenantId;
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
    /// under.
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
    /// Lost the seq [`MAX_PUTS`] times, or the reservation's unit could
    /// not catch up: `503` with `Retry-After`. Nothing was recorded.
    Busy,
    /// The record `seq` is written, but a door store did not acknowledge:
    /// `503`. The finishers make it take effect within their bound.
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
    /// The head already carries the effect.
    InHead,
    Refused(Refusal),
}

fn plan(table: &KeyTable, request: &KeyRequest) -> Planned {
    match request {
        KeyRequest::Create(subject) => {
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
            if entry.door.status == *status {
                return Planned::InHead;
            }
            let class = match status {
                SubjectStatus::Active => Class::Opening,
                _ => Class::Closing,
            };
            // Re-enabling restates the private part; it must be open.
            if class == Class::Opening && entry.private.is_none() {
                return Planned::Refused(Refusal::Conflict);
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
                    revoke: *status == SubjectStatus::Revoked,
                })),
                Err(_) => Planned::Refused(Refusal::Conflict),
            }
        }
        KeyRequest::SetGrants { id, grants, acting } => {
            let Some(subject) = table.get(id).and_then(Entry::subject) else {
                return Planned::Refused(match table.get(id) {
                    None => Refusal::NotFound,
                    Some(_) => Refusal::Conflict,
                });
            };
            let current = subject.grants();
            if current == *grants {
                return Planned::InHead;
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
                    acting: acting.clone(),
                    revoke: false,
                })),
                Err(_) => Planned::Refused(Refusal::Conflict),
            }
        }
    }
}

/// The entries a store at `held` needs to reach `table.seq()`, with the
/// revocations in force.
fn entries_for(table: &KeyTable, held: u64, revoked: &BTreeSet<String>) -> Vec<Entry> {
    table
        .entries()
        .filter(|e| e.last_seq > held || revoked.contains(&e.door.id))
        .map(|e| {
            let mut e = e.clone();
            if revoked.contains(&e.door.id) {
                e.door.status = SubjectStatus::Revoked;
            }
            e
        })
        .collect()
}

/// Brings one store to the table's seq.
async fn bring_up<U: KeyTarget>(
    target: &U,
    table: &KeyTable,
    revoked: &BTreeSet<String>,
) -> Result<()> {
    let held = target.keys_seq().await?;
    if held >= table.seq() && revoked.is_empty() {
        return Ok(());
    }
    target
        .apply(table.seq(), &entries_for(table, held, revoked))
        .await
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
            let plan = match plan(table, request) {
                Planned::Refused(r) => return Ok(KeyAnswer::Refused(r)),
                Planned::InHead => {
                    // The head carries it; the stores are still brought up.
                    let seq = table.seq();
                    if !self.apply_units(table, &revoked).await {
                        return Ok(KeyAnswer::Unfinished { seq });
                    }
                    let _ = bring_up(self.directory, table, &revoked).await;
                    return Ok(KeyAnswer::Done { seq });
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
                        return Ok(KeyAnswer::Refused(Refusal::Conflict));
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
                    return Ok(KeyAnswer::Refused(Refusal::Conflict));
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

            let done = match plan.class {
                Class::Closing => {
                    let units = self.apply_units(table, &revoked).await;
                    let _ = bring_up(self.directory, table, &revoked).await;
                    units
                }
                Class::Opening => {
                    bring_up(self.directory, table, &revoked).await.is_ok()
                        && self.apply_units(table, &revoked).await
                }
            };
            if !done {
                return Ok(KeyAnswer::Unfinished { seq });
            }
            let _ = self
                .intents
                .clear(self.tenant, ControlChain::Keys, seq)
                .await;
            return Ok(KeyAnswer::Done { seq });
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
    /// Stores that did not acknowledge, by label.
    pub failed: Vec<String>,
    /// The checkpoint written by this run.
    pub checkpoint: Option<u64>,
    /// Subjects whose private part did not open: disabled wherever
    /// applied; an attention condition.
    pub closed: Vec<String>,
}

/// Finishes every key change of `tenant` whose record is written: the
/// consumer of `apply_control(tenant, keys, _)`, the lease renewal's
/// catch-up and the pending sweep all call it. An `Err`, or a report
/// with a failed store, makes the queue retry.
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

    // A revocation whose chain record is missing: append it.
    for id in read.unrecorded_revocations() {
        for _ in 0..MAX_PUTS {
            advance(env.store, env.kek, env.ring, &chain, &mut table).await?;
            let Some(entry) = table.get(&id) else { break };
            if entry.door.status == SubjectStatus::Revoked {
                break;
            }
            let mut door = entry.door.clone();
            door.status = SubjectStatus::Revoked;
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
                rng,
            )?;
            if chain.put(env.store, seq, bytes.clone()).await? == Put::Written {
                let record = open_key_record(env.kek, env.ring, env.tenant, seq, &bytes)?;
                table.apply(&record)?;
                report.appended.push(seq);
                break;
            }
        }
    }
    advance(env.store, env.kek, env.ring, &chain, &mut table).await?;

    for unit in env.units {
        if bring_up(unit, &table, &read.revoked).await.is_err() {
            report.failed.push(unit.label().to_owned());
        }
    }
    if bring_up(env.directory, &table, &read.revoked)
        .await
        .is_err()
    {
        report.failed.push(env.directory.label().to_owned());
    }

    let due = read.newest_checkpoint.unwrap_or(0) + CHECKPOINT_EVERY;
    if table.seq() >= due {
        let record = chain.get(env.store, table.seq()).await?;
        let sealed = seal_checkpoint(env.kek, env.ring, &table, &record, rng)?;
        // Another finisher may have written it first: same content.
        let _ = env
            .store
            .put_if_absent(&checkpoint_name(env.tenant, table.seq()), sealed)
            .await?;
        report.checkpoint = Some(table.seq());
    }

    report.head = table.seq();
    report.closed = table
        .entries()
        .filter(|e| e.private.is_none() && e.door.status != SubjectStatus::Revoked)
        .map(|e| e.door.id.clone())
        .collect();
    if report.failed.is_empty() {
        let _ = env
            .intents
            .clear(env.tenant, ControlChain::Keys, report.head)
            .await;
    }
    Ok(report)
}
