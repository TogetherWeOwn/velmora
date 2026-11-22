//! The key writer under a reservation the caller holds (AM-38, AM-72):
//! the management plane's opening calls. Every opening key-chain change
//! is a reserved call: a key or principal create
//! ([`KeyEnv::create_reserved`]), a widening and a grant change that adds
//! or widens ([`KeyEnv::change_reserved`]). A re-enable answers `503`
//! until the unit's reservation can name it (AM-72).
//!
//! The handler asks the root unit for the reservation itself
//! (`UnitOp::Reserve`, keyed by the key hash and the request's
//! fingerprint) and gets `admitted{rid, keys_seq, ..}`. The writer then
//! takes `(rid, keys_seq)` as given; it does not call
//! [`super::ports::KeyAdmission`].
//!
//! - **The record is exactly `keys_seq + 1`** and carries the `rid` in its
//!   door part ([`super::record::Rid`]). A head that moved past
//!   `keys_seq` with no record of this `rid` answers
//!   [`ReservedAnswer::Lost`] after bringing the stores to it: the handler
//!   asks the unit again.
//! - **A record of this `rid` wins.** Before it writes, and after a put
//!   that lost, the writer reads the record at `keys_seq + 1` and checks
//!   for the `rid` (one read, AM-55; [`KeyEnv::carrying`]). One that is this
//!   reservation's create, whoever wrote it: the writer brings the stores
//!   up to it and answers from it, and never writes its own bytes.
//! - **The kept answer only with the full apply.** The stores are brought
//!   up in the writer's three steps (units held closed, directory, units
//!   in full). Only once every one of them acknowledged, and the subject
//!   opens, does the root unit get the record's entry again with the
//!   answer to keep ([`super::ports::KeyTarget::apply_kept`]). A unit
//!   turns the reservation `applied` on a held apply too, so an answer
//!   sent there would be kept for a subject the unit holds closed.
//! - **`finish`** is the idempotent path of a subject the head already
//!   holds (§2.5, DUR-7, [`KeyEnv::finish_subject`]): every store brought
//!   to the head, and `Done` only when every door store holds the subject
//!   open.

use std::collections::BTreeSet;

use velmora::rng::FillRandom;

use super::chain::Put;
use super::checkpoint::{advance, reopen_closed, reopen_from_checkpoints};
use super::gate::{Gate, MoveGate};
use super::ports::{
    Applied, ApplyEntry, ControlChain, ControlIntents, KeptAnswer, KeyAdmission, KeyTarget, Refusal,
};
use super::record::{
    key_chain, open_chain_record, open_key_record, seal_key_record_carrying, ChainRecord, Entry,
    KeyOp, KeyTable, Rid, Subject, SubjectStatus, TkRing,
};
use super::revocations::list_tenant_revocations;
use super::routes::{put_route, RoutePut};
use super::writer::{op_kind, plan, subject_of, Class, KeyAnswer, KeyEnv, KeyRequest, Planned};
use crate::ports::{Clock, Kek};
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};

/// A record of a `rid` names another subject than the call's: the
/// reservation is not this call's.
pub const ERR_RID_SUBJECT: BridgeError =
    BridgeError::Invalid("a record of this reservation names another subject");

/// The reservation a create is bound to.
#[derive(Clone, Copy, Debug)]
pub struct Reserved<'a> {
    pub rid: Rid,
    /// The root unit's `keys_seq` when it admitted the reservation: the
    /// record is exactly this + 1.
    pub keys_seq: u64,
    /// The answer to keep (its `rid` must be [`Reserved::rid`]).
    pub answer: &'a KeptAnswer,
}

/// What a reserved create answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedAnswer {
    /// The record that carries the `rid` is at `seq` (this call's, or one
    /// of another call under the same reservation, whose bytes win). Every
    /// door store holds the head, the subject opens, and the root unit
    /// kept the answer.
    Done { seq: u64 },
    /// The record that carries the `rid` is at `seq`; a store did not
    /// acknowledge, the subject is held closed or revoked by an `m/rk/`
    /// not yet recorded, or the answer was not kept. `503`; the finishers
    /// apply it.
    Unfinished { seq: u64 },
    /// Another record, without the `rid`, took `keys_seq + 1`: nothing of
    /// this call is recorded, and the stores
    /// are brought to the head. Ask the unit again.
    Lost,
    /// Nothing recorded, and the chain cannot record now: `503`.
    Busy,
    /// Refused before any record.
    Refused(Refusal),
    /// `409 key_moved` (AM-31), nothing put.
    KeyMoved,
    /// `503`: the chain is frozen (AM-28), nothing put.
    Frozen,
    /// A change ([`KeyEnv::change_reserved`]) the head already states,
    /// from a record that does not carry the `rid`: nothing is recorded
    /// under the reservation, and the caller releases it. The stores were
    /// brought to the head; `done` is whether every door store holds it
    /// (as [`KeyAnswer::Done`]).
    InHead { seq: u64, done: bool },
    /// A change ([`KeyEnv::change_reserved`]) that closes at this head (a
    /// narrowing, a disable, a revoke, a dropped grant): not a reserved
    /// call. Nothing is recorded; the caller releases the reservation and
    /// sends the change through [`KeyEnv::change`], which takes none for a
    /// closing change.
    Closes,
}

/// A record above some seq that carries a `rid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    pub seq: u64,
    /// The subject it names; the table holds it as the head does.
    pub id: String,
}

/// What [`KeyEnv::finish_subject`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finished {
    /// Every door store holds the head and the subject open; `seq` is its
    /// newest record, and the table states the subject as the stores hold
    /// it.
    Done { seq: u64 },
    /// A store did not acknowledge, the subject is held closed (its
    /// private part does not open now), or an `m/rk/` revocation holds it
    /// revoked before its revoke record (the finisher writes that first).
    Unfinished,
    /// The head holds no such subject.
    NotHeld,
}

/// An `m/rk/` revocation of `entry` that the chain does not record yet
/// (the finisher's rule): the table still states the subject otherwise.
fn unrecorded_revoke(revoked: &BTreeSet<String>, entry: &Entry) -> bool {
    revoked.contains(&entry.door.id) && entry.door.status != SubjectStatus::Revoked
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
    /// `table` brought to the chain's head, and the `m/rk/` revocations.
    async fn read_head(&self, table: &mut KeyTable) -> Result<BTreeSet<String>> {
        let chain = key_chain(self.tenant);
        let revoked = list_tenant_revocations(self.store, self.tenant)
            .await?
            .into_iter()
            .collect();
        advance(self.store, self.kek, self.ring, &chain, table).await?;
        reopen_closed(self.store, self.kek, self.ring, &chain, table).await?;
        let _ = reopen_from_checkpoints(self.store, self.kek, self.ring, table).await;
        Ok(revoked)
    }

    /// The record at `above + 1`, if `table`'s head holds one and it
    /// carries `rid`. One read is enough (AM-55): the unit applies key
    /// records in seq order with no gap, so a record of a reservation can
    /// only sit at its `keys_seq + 1`, and once the unit applied it the
    /// reservation is `applied` and is not asked again.
    async fn find_carrying(
        &self,
        table: &KeyTable,
        rid: &Rid,
        above: u64,
    ) -> Result<Option<Carried>> {
        let seq = above + 1;
        if seq > table.seq() {
            return Ok(None);
        }
        let bytes = key_chain(self.tenant).get(self.store, seq).await?;
        Ok(
            match open_chain_record(self.kek, self.ring, self.tenant, seq, &bytes)? {
                ChainRecord::Key(r) if r.rid.as_ref() == Some(rid) => {
                    Some(Carried { seq, id: r.door.id })
                }
                _ => None,
            },
        )
    }

    /// The record at `above + 1` if it carries `rid` (AM-55), read from the
    /// chain's head now (`table` is brought there). `None`: no record there
    /// yet, or another record holds the seq.
    pub async fn carrying(
        &self,
        table: &mut KeyTable,
        rid: &Rid,
        above: u64,
    ) -> Result<Option<Carried>> {
        self.read_head(table).await?;
        self.find_carrying(table, rid, above).await
    }

    /// The idempotent path of a subject the head already holds (§2.5,
    /// DUR-7): every store brought to the head in the three steps, the
    /// pending rows cleared when every store holds it in full. Writes no
    /// record.
    pub async fn finish_subject(&self, table: &mut KeyTable, id: &str) -> Result<Finished> {
        let revoked = self.read_head(table).await?;
        if table.get(id).is_none() {
            return Ok(Finished::NotHeld);
        }
        let acks = self.apply_all(table, &revoked).await;
        let seq = table.seq();
        let _ = self.answer(Class::Opening, table, seq, acks).await;
        // A subject an `m/rk/` revocation holds revoked, with no revoke
        // record yet, is not answered as the table states it (`active`):
        // the finisher records the revoke first.
        let open = table
            .get(id)
            .is_some_and(|e| e.private.is_some() && !unrecorded_revoke(&revoked, e));
        Ok(match acks.units && acks.directory && open {
            true => Finished::Done {
                seq: table.get(id).map_or(seq, |e| e.last_seq),
            },
            false => Finished::Unfinished,
        })
    }

    /// The record of `rid` at `seq` is in `table`'s head: every store
    /// brought up to it, then the answer kept by the root unit's full
    /// apply.
    async fn settle(
        &self,
        table: &KeyTable,
        revoked: &BTreeSet<String>,
        carried: &Carried,
        answer: &KeptAnswer,
    ) -> ReservedAnswer {
        let seq = carried.seq;
        let acks = self.apply_all(table, revoked).await;
        let _ = self.answer(Class::Opening, table, seq, acks).await;
        let unfinished = ReservedAnswer::Unfinished { seq };
        if !(acks.units && acks.directory) {
            return unfinished;
        }
        // The head's state of the subject, stamped at the record's seq
        // (AM-62), with the record's `rid`; never a held entry.
        let Some(mut entry) = table.get(&carried.id).cloned() else {
            return unfinished;
        };
        // Held closed, or revoked by an `m/rk/` the chain does not record
        // yet: no answer is kept for a subject the head does not state as
        // the stores hold it.
        if entry.private.is_none() || unrecorded_revoke(revoked, &entry) {
            return unfinished;
        }
        entry.last_seq = seq;
        entry.rid = Some(answer.rid);
        let Some(root) = self.units.first() else {
            return unfinished;
        };
        match root
            .apply_kept(
                seq - 1,
                &[ApplyEntry::Subject(entry)],
                std::slice::from_ref(answer),
            )
            .await
        {
            Ok(Applied::Done { .. }) => ReservedAnswer::Done { seq },
            Ok(Applied::Behind { .. }) | Err(_) => unfinished,
        }
    }

    /// Creates `subject` under the reservation `reserved` the caller
    /// holds: the record at exactly `keys_seq + 1`, carrying the `rid`
    /// (see the module doc). `table` is the caller's copy of the key table
    /// (any age); it is brought to the head here and left there.
    pub async fn create_reserved<R: FillRandom>(
        &self,
        table: &mut KeyTable,
        subject: &Subject,
        reserved: Reserved<'_>,
        rng: &mut R,
    ) -> Result<ReservedAnswer> {
        let Reserved {
            rid,
            keys_seq,
            answer,
        } = reserved;
        if answer.rid != rid {
            return Err(BridgeError::Invalid(
                "the kept answer is another reservation's",
            ));
        }
        let id = subject.door.id.as_str();
        let mut revoked = self.read_head(table).await?;
        // A retry, or a call under the same reservation that got there
        // first: its record is the create.
        if let Some(carried) = self.find_carrying(table, &rid, keys_seq).await? {
            if carried.id != id {
                return Err(ERR_RID_SUBJECT);
            }
            return Ok(self.settle(table, &revoked, &carried, answer).await);
        }
        if table.seq() < keys_seq {
            // The unit holds more of the chain than it can be read now.
            return Ok(ReservedAnswer::Busy);
        }
        if table.seq() > keys_seq {
            let _ = self.apply_all(table, &revoked).await;
            return Ok(ReservedAnswer::Lost);
        }
        let Ok(zero) = self.gate.zero_head().await else {
            return Ok(ReservedAnswer::Busy);
        };
        let request = KeyRequest::Create(subject.clone());
        match self.move_rules(&zero, table, &request).await {
            Gate::Go => {}
            Gate::KeyMoved { .. } => return Ok(ReservedAnswer::KeyMoved),
            Gate::Unavailable => {
                return Ok(match table.frozen_at() {
                    Some(_) => ReservedAnswer::Frozen,
                    None => ReservedAnswer::Busy,
                })
            }
            // Revokes only: never a create.
            Gate::ZeroRevoke | Gate::FrozenRevoke => return Ok(ReservedAnswer::Busy),
        }
        let plan = match plan(self.kek, table, &revoked, &request, self.limits) {
            Planned::Change(p) if p.op == KeyOp::Create && !p.closes() => p,
            Planned::Refused(r) => return Ok(ReservedAnswer::Refused(r)),
            Planned::Busy => return Ok(ReservedAnswer::Busy),
            // The head holds this subject from a record of no record of
            // this reservation (the search above found none).
            Planned::InHead(_) | Planned::Change(_) => {
                return Ok(ReservedAnswer::Refused(Refusal::Conflict))
            }
        };
        let seq = keys_seq + 1;

        // Intent: the message is the durable part.
        self.intents
            .send(self.tenant, ControlChain::Keys, seq)
            .await?;
        let _ = self
            .intents
            .note(self.tenant, ControlChain::Keys, seq, op_kind(&plan))
            .await;
        if plan.door.kind.has_secret()
            && put_route(
                self.store,
                self.kek,
                self.tenant,
                &plan.door.id,
                plan.door.kind,
                self.now(),
                rng,
            )
            .await?
                == RoutePut::Taken
        {
            // The reservation is the caller's to release.
            return Ok(ReservedAnswer::Refused(Refusal::IdTaken));
        }
        let bytes = seal_key_record_carrying(
            self.kek,
            self.ring,
            self.tenant,
            seq,
            plan.op,
            self.now(),
            &plan.door,
            plan.private.as_ref(),
            false,
            table.frozen_at(),
            Some(rid),
            rng,
        )?;
        let chain = key_chain(self.tenant);
        match chain.put(self.store, seq, bytes.clone()).await? {
            Put::Written => {
                let record = open_key_record(self.kek, self.ring, self.tenant, seq, &bytes)?;
                table.apply(&record)?;
            }
            Put::Lost => {
                // Whoever took the seq: a record of this reservation wins,
                // any other one ends this call.
                revoked = self.read_head(table).await?;
                match self.find_carrying(table, &rid, keys_seq).await? {
                    Some(carried) if carried.id == id => {
                        return Ok(self.settle(table, &revoked, &carried, answer).await)
                    }
                    Some(_) => return Err(ERR_RID_SUBJECT),
                    None => {
                        let _ = self.apply_all(table, &revoked).await;
                        return Ok(ReservedAnswer::Lost);
                    }
                }
            }
        }
        let carried = Carried {
            seq,
            id: id.to_owned(),
        };
        Ok(self.settle(table, &revoked, &carried, answer).await)
    }

    /// Makes the opening change `request` under the reservation `reserved`
    /// the caller holds (AM-38 case 1, AM-72): a widening, a grant change
    /// that adds or widens, of a key or a principal. A re-enable answers
    /// [`ReservedAnswer::Busy`] (`503`) until the unit's reservation has an
    /// `Opening` for it (AM-72), and nothing is read or written. On the
    /// rules of [`KeyEnv::create_reserved`]: a record of this `rid` at
    /// `keys_seq + 1` wins; a head past `keys_seq` without one answers
    /// `Lost`; otherwise the record at exactly `keys_seq + 1` carries the
    /// `rid`, and the answer is kept only after the full apply. A create is
    /// [`KeyEnv::create_reserved`].
    ///
    /// The class comes from the head, never from the caller: a change that
    /// closes at this head answers [`ReservedAnswer::Closes`], and one the
    /// head already states [`ReservedAnswer::InHead`]; neither records
    /// anything under the reservation.
    pub async fn change_reserved<R: FillRandom>(
        &self,
        table: &mut KeyTable,
        request: &KeyRequest,
        reserved: Reserved<'_>,
        rng: &mut R,
    ) -> Result<ReservedAnswer> {
        if let KeyRequest::Create(subject) = request {
            return self.create_reserved(table, subject, reserved, rng).await;
        }
        // AM-72: a re-enable answers `503` until the unit's reservation has
        // an `Opening` for it (the unit cannot check it yet).
        if matches!(
            request,
            KeyRequest::SetStatus {
                status: SubjectStatus::Active,
                ..
            }
        ) {
            return Ok(ReservedAnswer::Busy);
        }
        let Reserved {
            rid,
            keys_seq,
            answer,
        } = reserved;
        if answer.rid != rid {
            return Err(BridgeError::Invalid(
                "the kept answer is another reservation's",
            ));
        }
        let id = subject_of(request);
        let mut revoked = self.read_head(table).await?;
        // A retry, or a call under the same reservation that got there
        // first: its record is the change.
        if let Some(carried) = self.find_carrying(table, &rid, keys_seq).await? {
            if carried.id != id {
                return Err(ERR_RID_SUBJECT);
            }
            return Ok(self.settle(table, &revoked, &carried, answer).await);
        }
        if table.seq() < keys_seq {
            return Ok(ReservedAnswer::Busy);
        }
        if table.seq() > keys_seq {
            let _ = self.apply_all(table, &revoked).await;
            return Ok(ReservedAnswer::Lost);
        }
        let Ok(zero) = self.gate.zero_head().await else {
            return Ok(ReservedAnswer::Busy);
        };
        match self.move_rules(&zero, table, request).await {
            Gate::Go => {}
            Gate::KeyMoved { pre_apply } => {
                // As the plain writer (AM-31): an existing `m/rk/<t>/` of
                // the key is applied to D1 first.
                if pre_apply && revoked.contains(id) && self.gate.refuse_in_d1(id).await.is_err() {
                    return Ok(ReservedAnswer::Busy);
                }
                return Ok(ReservedAnswer::KeyMoved);
            }
            Gate::Unavailable => {
                return Ok(match table.frozen_at() {
                    Some(_) => ReservedAnswer::Frozen,
                    None => ReservedAnswer::Busy,
                })
            }
            // Revokes only: they close.
            Gate::ZeroRevoke | Gate::FrozenRevoke => return Ok(ReservedAnswer::Closes),
        }
        let plan = match plan(self.kek, table, &revoked, request, self.limits) {
            Planned::Refused(r) => return Ok(ReservedAnswer::Refused(r)),
            Planned::Busy => return Ok(ReservedAnswer::Busy),
            Planned::InHead(class) => {
                let acks = self.apply_all(table, &revoked).await;
                let seq = table.seq();
                let done = matches!(
                    self.answer(class, table, seq, acks).await,
                    KeyAnswer::Done { .. }
                );
                return Ok(ReservedAnswer::InHead { seq, done });
            }
            Planned::Change(p) if p.closes() => return Ok(ReservedAnswer::Closes),
            Planned::Change(p) => p,
        };
        let seq = keys_seq + 1;

        // Intent: the message is the durable part.
        self.intents
            .send(self.tenant, ControlChain::Keys, seq)
            .await?;
        let _ = self
            .intents
            .note(self.tenant, ControlChain::Keys, seq, op_kind(&plan))
            .await;
        let bytes = seal_key_record_carrying(
            self.kek,
            self.ring,
            self.tenant,
            seq,
            plan.op,
            self.now(),
            &plan.door,
            plan.private.as_ref(),
            false,
            table.frozen_at(),
            Some(rid),
            rng,
        )?;
        let chain = key_chain(self.tenant);
        match chain.put(self.store, seq, bytes.clone()).await? {
            Put::Written => {
                let record = open_key_record(self.kek, self.ring, self.tenant, seq, &bytes)?;
                table.apply(&record)?;
            }
            Put::Lost => {
                revoked = self.read_head(table).await?;
                match self.find_carrying(table, &rid, keys_seq).await? {
                    Some(carried) if carried.id == id => {
                        return Ok(self.settle(table, &revoked, &carried, answer).await)
                    }
                    Some(_) => return Err(ERR_RID_SUBJECT),
                    None => {
                        let _ = self.apply_all(table, &revoked).await;
                        return Ok(ReservedAnswer::Lost);
                    }
                }
            }
        }
        let carried = Carried {
            seq,
            id: id.to_owned(),
        };
        Ok(self.settle(table, &revoked, &carried, answer).await)
    }
}
