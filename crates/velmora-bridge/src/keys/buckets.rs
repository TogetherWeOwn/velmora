//! The creator-grant writer: a bucket create of a managed tenant (DS1 A7,
//! ADR §6.2 with AM-8 and AM-24).
//!
//! The order is reservation → intent → creator grant (key chain) → bind
//! → `bucket_created` (tenant chain) → the stores.
//!
//! - **The creator grant is a key-chain record, written first.** It gives
//!   the acting principal `rw` on the new bucket id, and nothing else
//!   changes. It is bound to the reservation like every opening record:
//!   it must be exactly the reservation's `keys_seq + 1`.
//! - **The bucket id is derived from that seq**, K:
//!   [`crate::records::bucket_id`]. K is known before the put, and the
//!   writer takes it only from its own successful put, never from the
//!   head: a lost answer is read back by the chain (the same bytes are
//!   this writer's), and any other record at K is a lost put, after which
//!   the reservation is asked for again at the new head.
//! - **K is bound to the reservation after the put and before
//!   `bucket_created`.** A retry under the same `Idempotency-Key` is
//!   answered the bound K and places that grant's bucket again (the
//!   tenant chain answers a placed one as placed): one create never places
//!   two buckets, whichever answer was lost. A call that dies between its
//!   put and its bind leaves an unbound grant, which can never be placed.
//! - **A grant on the id that K derives, held by any other subject before
//!   the create, is dropped first** (closing records), so the new bucket
//!   is reachable by its creator alone (A7).
//! - **A create that loses the K order** (another create with a higher K
//!   was recorded first) revokes its orphan grant with a closing record,
//!   then writes a new creator grant at a new K under the same
//!   reservation, at most [`MAX_ORDER_TRIES`] times, then answers busy
//!   (`503` with `Retry-After`).
//! - **Every other refusal of `bucket_created`** (the tenant state,
//!   `restoring`, an unlisted unit) revokes the orphan grant, releases the
//!   reservation, and answers the refusal's `409` with its code.
//! - **The answer is `Created` only when the bucket is in force**: both
//!   records are acknowledged by every door store. Anything less is
//!   `Unfinished` (`503`), and the retry finishes it.
//! - **An orphan opens nothing** (a grant is served only on a bucket its
//!   unit holds), but it counts against the subject's 64 grants. The
//!   finisher of the grant's intent ([`finish_creator_grant`]) decides
//!   every creator grant by its reservation: it places the bucket of an
//!   open bound one, and revokes one that no open reservation is bound to.

use std::collections::BTreeSet;

use velmora::rng::FillRandom;

use super::chain::Put;
use super::checkpoint::{advance, reopen_closed, reopen_from_checkpoints};
use super::ports::{
    BucketAdmission, BucketPut, BucketRecords, BucketReservation, ControlChain, ControlIntents,
    KeyAdmission, KeyTarget, Refusal,
};
use super::record::{
    key_chain, open_key_record, seal_key_record, Access, Grant, KeyOp, KeyRecord, KeyTable,
    SubjectKind, SubjectStatus, TkRing, MAX_SUBJECT_GRANTS,
};
use super::revocations::list_tenant_revocations;
use super::writer::{Class, KeyAnswer, KeyEnv, KeyRequest, MAX_PUTS};
use crate::ports::{Clock, Kek};
use crate::records::{bucket_id, RecordStore};
use crate::types::{BridgeError, BucketId, Result};

/// Creates that lose the K order before the call answers busy (AM-8).
pub const MAX_ORDER_TRIES: u32 = 3;

/// The `pending_ops` kind of a creator grant's intent.
pub const BUCKET_CREATE_KIND: &str = "bucket.create";

/// A bound seq whose record is not this reservation's creator grant: the
/// unit's binding and the key chain disagree. Nothing is written.
pub const ERR_BINDING: BridgeError =
    BridgeError::Invalid("a bound creator-grant seq is not that creator's grant");

/// A bucket create asked for.
#[derive(Clone, Copy, Debug)]
pub struct BucketRequest<'a> {
    /// The bucket's name, unique in the tenant (held by the reservation).
    pub name: &'a str,
    /// The acting principal (its key-chain id).
    pub creator: &'a str,
    /// The unit to place the bucket on.
    pub unit: u32,
}

/// What a bucket create answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BucketAnswer {
    /// `200`: the bucket is in force: placed, and its creator grant held
    /// by every door store.
    Created { bucket: BucketId, grant_seq: u64 },
    /// Refused before any record: the creator, its grant count or the
    /// reservation. A reservation this call held is released.
    Refused(Refusal),
    /// The tenant chain refused the bucket: the orphan grant is revoked
    /// (or left to the finisher, which revokes it because the reservation
    /// is released) and the reservation released. Answer `status` with
    /// `code`.
    StateRefused { status: u16, code: &'static str },
    /// `503` with `Retry-After`: no bucket. The K order was lost
    /// [`MAX_ORDER_TRIES`] times, or the key-chain put [`MAX_PUTS`]
    /// times, or a private part cannot be opened now.
    Busy,
    /// `503`: the creator grant `grant_seq` is written; the bucket is not
    /// in force yet (a store did not acknowledge, the tenant chain or the
    /// binding could not be reached, an orphan could not be revoked). A
    /// retry under the same key, or the grant's intent, finishes it.
    Unfinished { grant_seq: u64 },
}

/// What the finisher did for one creator grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreatorGrant {
    /// The record at the seq is no creator grant.
    NotOne,
    /// Its bucket is placed: by an earlier call, or by this run for the
    /// open reservation bound to it.
    Placed,
    /// No open reservation can place its bucket: the grant is revoked by
    /// the record `seq` (the head when it already was).
    Revoked { seq: u64 },
    /// A step could not be done now (a store, or a private part that does
    /// not open): retry the message.
    Busy,
}

/// The creator grant on `bucket`: `rw`, the whole bucket, no expiry and
/// no address list.
fn creator_grant(bucket: &BucketId) -> Grant {
    Grant {
        bucket_id: bucket.as_str().to_owned(),
        access: Access::Rw,
        expires_at: None,
        prefix: None,
        ip_list: Vec::new(),
    }
}

/// Whether `record`, at its own seq, is a creator grant: an opening
/// grants change of a principal that holds the id its seq derives.
fn is_creator_grant(tenant: &crate::TenantId, record: &KeyRecord) -> bool {
    let bucket = bucket_id(tenant, record.seq);
    record.op == KeyOp::Grants
        && record.door.kind == SubjectKind::Principal
        && !record.closes
        && record
            .door
            .grants
            .iter()
            .any(|g| g.bucket_id == bucket.as_str())
}

/// The creator as the head holds it: an active principal with room for
/// one more grant, its private part open.
enum Creator {
    Ok(super::record::Subject),
    Refused(Refusal),
    Busy,
}

fn creator_at_head(table: &KeyTable, revoked: &BTreeSet<String>, id: &str) -> Creator {
    let Some(entry) = table.get(id) else {
        return Creator::Refused(Refusal::NotFound);
    };
    if entry.door.kind != SubjectKind::Principal
        || entry.door.status != SubjectStatus::Active
        || revoked.contains(id)
    {
        return Creator::Refused(Refusal::CreatorNotActive);
    }
    if entry.door.grants.len() >= MAX_SUBJECT_GRANTS {
        return Creator::Refused(Refusal::GrantCap);
    }
    match entry.subject() {
        Some(subject) => Creator::Ok(subject),
        None => Creator::Busy,
    }
}

/// How placing a written creator grant's bucket ended.
enum Placing {
    Done(BucketAnswer),
    /// The K order was lost and the orphan revoked: take a new K.
    Again,
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
    /// Revokes the grant on `bucket` of `subject` with a closing record:
    /// the seq of the record that carries it (the head when it already
    /// did), or `None` when none could be written now.
    async fn drop_grant<R: FillRandom>(
        &self,
        table: &mut KeyTable,
        subject: &str,
        bucket: &str,
        rng: &mut R,
    ) -> Option<u64> {
        let request = KeyRequest::DropGrant {
            id: subject.to_owned(),
            bucket_id: bucket.to_owned(),
        };
        // A closing change: the idempotency key is not used.
        match self.change(table, "", &request, rng).await {
            Ok(KeyAnswer::Done { seq } | KeyAnswer::Unfinished { seq }) => Some(seq),
            Ok(KeyAnswer::Refused(_) | KeyAnswer::Busy) | Err(_) => None,
        }
    }

    /// Whether every door store acknowledged the head.
    async fn keys_in_force(&self, table: &KeyTable, revoked: &BTreeSet<String>) -> bool {
        let acks = self.apply_all(table, revoked).await;
        matches!(
            self.answer(Class::Opening, table, table.seq(), acks).await,
            KeyAnswer::Done { .. }
        )
    }

    /// Places the bucket of the creator grant `k`, which this reservation
    /// wrote and bound, and answers for it.
    #[allow(clippy::too_many_arguments)]
    async fn place<B: BucketRecords, R: FillRandom>(
        &self,
        records: &B,
        table: &mut KeyTable,
        revoked: &BTreeSet<String>,
        idempotency_key: &str,
        request: &BucketRequest<'_>,
        k: u64,
        rng: &mut R,
    ) -> Placing {
        let bucket = bucket_id(self.tenant, k);
        // A lost answer is asked again with the same K: the tenant chain
        // answers a placed create as placed.
        let mut put = None;
        for _ in 0..MAX_PUTS {
            if let Ok(p) = records
                .bucket_created(self.tenant, &bucket, request.unit, request.creator, k)
                .await
            {
                put = Some(p);
                break;
            }
        }
        match put {
            Some(BucketPut::Placed { in_force }) => {
                let keys = self.keys_in_force(table, revoked).await;
                Placing::Done(match keys && in_force {
                    true => BucketAnswer::Created {
                        bucket,
                        grant_seq: k,
                    },
                    false => BucketAnswer::Unfinished { grant_seq: k },
                })
            }
            Some(BucketPut::OrderLost) => {
                match self
                    .drop_grant(table, request.creator, bucket.as_str(), rng)
                    .await
                {
                    Some(_) => Placing::Again,
                    None => Placing::Done(BucketAnswer::Unfinished { grant_seq: k }),
                }
            }
            Some(BucketPut::Refused { status, code }) => {
                // When the revoke cannot be written now, the finisher
                // revokes the grant: its reservation is released.
                let _ = self
                    .drop_grant(table, request.creator, bucket.as_str(), rng)
                    .await;
                let _ = self.admission.release(self.tenant, idempotency_key).await;
                Placing::Done(BucketAnswer::StateRefused { status, code })
            }
            None => {
                let _ = self.apply_all(table, revoked).await;
                Placing::Done(BucketAnswer::Unfinished { grant_seq: k })
            }
        }
    }

    /// Creates a bucket of a managed tenant under `idempotency_key`: the
    /// creator grant first, then `bucket_created` through `records`.
    /// `table` is the caller's copy of the key table, as for
    /// [`KeyEnv::change`].
    pub async fn create_bucket<B: BucketRecords, R: FillRandom>(
        &self,
        records: &B,
        table: &mut KeyTable,
        idempotency_key: &str,
        request: &BucketRequest<'_>,
        rng: &mut R,
    ) -> Result<BucketAnswer> {
        let chain = key_chain(self.tenant);
        let reservation = BucketReservation {
            name: request.name,
            creator: request.creator,
            unit: request.unit,
        };
        let mut lost_orders = 0;
        // Bound seqs this call found lost: the unit still answers the
        // newest bound seq until a new one is bound, and a lost one is
        // never placed again.
        let mut spent = BTreeSet::new();
        let mut puts = 0;
        let mut caught_up = false;
        let mut caught_up_in_full = false;
        while puts < MAX_PUTS {
            let revoked: BTreeSet<String> = list_tenant_revocations(self.store, self.tenant)
                .await?
                .into_iter()
                .collect();
            advance(self.store, self.kek, self.ring, &chain, table).await?;
            reopen_closed(self.store, self.kek, self.ring, &chain, table).await?;
            let _ = reopen_from_checkpoints(self.store, self.kek, self.ring, table).await;

            // Reservation first: a retry of a create is answered from it,
            // whatever the creator's state is now.
            let keys_seq = match self
                .admission
                .admit_bucket(self.tenant, idempotency_key, &reservation)
                .await?
            {
                BucketAdmission::Created { bucket, grant_seq } => {
                    // The id must be the derivation of its grant, or the
                    // answer is not one.
                    if bucket != bucket_id(self.tenant, grant_seq) {
                        return Err(ERR_BINDING);
                    }
                    return Ok(match self.keys_in_force(table, &revoked).await {
                        true => BucketAnswer::Created { bucket, grant_seq },
                        false => BucketAnswer::Unfinished { grant_seq },
                    });
                }
                BucketAdmission::Admitted {
                    bound: Some(k),
                    keys_seq: _,
                } if !spent.contains(&k) => {
                    // An earlier call under this key wrote and bound k:
                    // place that grant's bucket, never a second one.
                    let ours = match chain.get(self.store, k).await {
                        Ok(bytes) => open_key_record(self.kek, self.ring, self.tenant, k, &bytes)
                            .map(|r| {
                                is_creator_grant(self.tenant, &r) && r.door.id == request.creator
                            })
                            .unwrap_or(false),
                        Err(_) => false,
                    };
                    if !ours {
                        return Err(ERR_BINDING);
                    }
                    match self
                        .place(records, table, &revoked, idempotency_key, request, k, rng)
                        .await
                    {
                        Placing::Done(answer) => return Ok(answer),
                        Placing::Again => {
                            spent.insert(k);
                            lost_orders += 1;
                            if lost_orders >= MAX_ORDER_TRIES {
                                return Ok(BucketAnswer::Busy);
                            }
                            puts = 0;
                            caught_up = false;
                            caught_up_in_full = false;
                            continue;
                        }
                    }
                }
                // A refusal by a unit behind the head may be stale: bring
                // the units up once and ask again. (The bucket cap does not
                // depend on the key chain.)
                BucketAdmission::Refused(Refusal::NotFound | Refusal::CreatorNotActive)
                    if !caught_up =>
                {
                    caught_up = true;
                    caught_up_in_full = self.apply_all(table, &revoked).await.units;
                    puts += 1;
                    continue;
                }
                BucketAdmission::Refused(Refusal::NotFound | Refusal::CreatorNotActive)
                    if !caught_up_in_full =>
                {
                    return Ok(BucketAnswer::Busy)
                }
                BucketAdmission::Refused(r) => return Ok(BucketAnswer::Refused(r)),
                BucketAdmission::Admitted { keys_seq, .. } => keys_seq,
            };
            if keys_seq != table.seq() {
                // The unit is behind the head: bring it up and ask again.
                // Ahead: our copy is stale; the loop reads the head again.
                if keys_seq < table.seq() {
                    let _ = self.apply_all(table, &revoked).await;
                }
                puts += 1;
                continue;
            }
            let subject = match creator_at_head(table, &revoked, request.creator) {
                Creator::Ok(s) => s,
                Creator::Refused(r) => {
                    let _ = self.admission.release(self.tenant, idempotency_key).await;
                    return Ok(BucketAnswer::Refused(r));
                }
                Creator::Busy => return Ok(BucketAnswer::Busy),
            };
            let k = keys_seq + 1;
            let bucket = bucket_id(self.tenant, k);

            // A grant on this id held before the bucket exists (by any
            // subject but a revoked one) is dropped first, so only the
            // creator reaches the new bucket. The head moves; ask again.
            let holders: Vec<String> = table
                .entries()
                .filter(|e| {
                    e.door.status != SubjectStatus::Revoked
                        && !revoked.contains(&e.door.id)
                        && e.door.grants.iter().any(|g| g.bucket_id == bucket.as_str())
                })
                .map(|e| e.door.id.clone())
                .collect();
            if !holders.is_empty() {
                for holder in holders {
                    if self
                        .drop_grant(table, &holder, bucket.as_str(), rng)
                        .await
                        .is_none()
                    {
                        return Ok(BucketAnswer::Busy);
                    }
                }
                puts += 1;
                continue;
            }

            // Intent, then the creator grant at exactly K.
            self.intents
                .send(self.tenant, ControlChain::Keys, k)
                .await?;
            let _ = self
                .intents
                .note(self.tenant, ControlChain::Keys, k, BUCKET_CREATE_KIND)
                .await;
            let mut grants = subject.grants();
            grants.push(creator_grant(&bucket));
            let mut next = subject.clone();
            next.set_grants(&grants);
            table.admits(KeyOp::Grants, &next.door, Some(&next.private))?;
            let bytes = seal_key_record(
                self.kek,
                self.ring,
                self.tenant,
                k,
                KeyOp::Grants,
                self.now(),
                &next.door,
                Some(&next.private),
                false,
                rng,
            )?;
            match chain.put(self.store, k, bytes.clone()).await? {
                Put::Lost => {
                    puts += 1;
                    continue;
                }
                Put::Written => {}
            }
            // From here the grant is written: every failure answers
            // Unfinished with its seq.
            let applied = open_key_record(self.kek, self.ring, self.tenant, k, &bytes)
                .and_then(|record| table.apply(&record));
            if applied.is_err() {
                return Ok(BucketAnswer::Unfinished { grant_seq: k });
            }
            // Bind K to the reservation before the bucket is placed, so a
            // retry places this grant's bucket and no second one. An
            // unbound grant is never placed: the finisher revokes it.
            if self
                .admission
                .bind_bucket(self.tenant, idempotency_key, k)
                .await
                .is_err()
            {
                let _ = self.apply_all(table, &revoked).await;
                return Ok(BucketAnswer::Unfinished { grant_seq: k });
            }
            match self
                .place(records, table, &revoked, idempotency_key, request, k, rng)
                .await
            {
                Placing::Done(answer) => return Ok(answer),
                Placing::Again => {
                    spent.insert(k);
                    lost_orders += 1;
                    if lost_orders >= MAX_ORDER_TRIES {
                        return Ok(BucketAnswer::Busy);
                    }
                    // A new K under the same reservation.
                    puts = 0;
                    caught_up = false;
                    caught_up_in_full = false;
                }
            }
        }
        Ok(BucketAnswer::Busy)
    }
}

/// The finisher of a creator grant's intent (`apply_control(tenant,
/// keys, seq)`), run beside [`super::writer::finish_keys`]. The message
/// is retried while this answers [`CreatorGrant::Busy`].
///
/// - The record at `seq` is no creator grant: nothing.
/// - Its bucket is placed, or its reservation became the bucket: nothing.
/// - An open reservation is bound to it: the bucket is placed for it, as
///   the Worker would have; a refusal revokes the grant and releases the
///   reservation.
/// - No open reservation is bound to it: the grant is an orphan for good
///   and is revoked.
pub async fn finish_creator_grant<S, K, T, A, I, U, D, C, B, R>(
    env: &KeyEnv<'_, S, K, T, A, I, U, D, C>,
    records: &B,
    table: &mut KeyTable,
    seq: u64,
    rng: &mut R,
) -> Result<CreatorGrant>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    A: KeyAdmission,
    I: ControlIntents,
    U: KeyTarget,
    D: KeyTarget,
    C: Clock,
    B: BucketRecords,
    R: FillRandom,
{
    use super::ports::Binding;

    let chain = key_chain(env.tenant);
    let Some(bytes) = env.store.get(&chain.name(seq)).await? else {
        return Ok(CreatorGrant::NotOne);
    };
    let record = open_key_record(env.kek, env.ring, env.tenant, seq, &bytes)?;
    if !is_creator_grant(env.tenant, &record) {
        return Ok(CreatorGrant::NotOne);
    }
    let bucket = bucket_id(env.tenant, seq);
    let creator = record.door.id.as_str();
    if records.is_placed(env.tenant, &bucket).await? {
        return Ok(CreatorGrant::Placed);
    }
    let orphan = match env.admission.bucket_binding(env.tenant, seq).await? {
        Binding::Created => return Ok(CreatorGrant::Placed),
        Binding::None => None,
        Binding::Open {
            idempotency_key,
            creator: bound,
            unit,
        } => {
            if bound != creator {
                return Err(ERR_BINDING);
            }
            match records
                .bucket_created(env.tenant, &bucket, unit, creator, seq)
                .await
            {
                Ok(BucketPut::Placed { .. }) => return Ok(CreatorGrant::Placed),
                Ok(BucketPut::OrderLost | BucketPut::Refused { .. }) => Some(idempotency_key),
                Err(_) => return Ok(CreatorGrant::Busy),
            }
        }
    };
    let Some(revoke) = env.drop_grant(table, creator, bucket.as_str(), rng).await else {
        return Ok(CreatorGrant::Busy);
    };
    if let Some(key) = orphan {
        // Its create can never finish: the name and the cap slot go.
        let _ = env.admission.release(env.tenant, &key).await;
    }
    Ok(CreatorGrant::Revoked { seq: revoke })
}
