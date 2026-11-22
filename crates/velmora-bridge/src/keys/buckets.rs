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
//!   two buckets, whichever answer was lost. The bind is a compare-and-set
//!   on the binding the call was admitted with, so of two overlapping
//!   calls under one key only one binds; the other revokes its own grant
//!   and places the bound one's bucket. A call that dies between its put
//!   and its bind leaves an unbound grant, which is never placed. A bound
//!   grant its creator no longer holds is never placed either.
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
//!   records are acknowledged by every door store, on a retry answered
//!   from the reservation too. Anything less is `Unfinished` (`503`), and
//!   the retry finishes it.
//! - **An orphan opens nothing** (a grant is served only on a bucket its
//!   unit holds), but it counts against the subject's 64 grants. The
//!   finisher of the grant's intent ([`finish_creator_grant`]) decides
//!   every creator grant by its reservation: for an open bound one it runs
//!   the create again under that reservation, and it revokes one that no
//!   open reservation is bound to.
//! - **Residuals:** a call stalled for more than the intent's delay (30 s)
//!   between its put and its bind loses its grant to the finisher (its
//!   bucket is then never placed; the retry makes a new one); and the
//!   `pending_ops` row of a creator grant is cleared with the head by any
//!   later finished change, so the queue message, the durable part, is
//!   what finishes it.

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

    /// Asks the tenant chain to record `bucket_created` for `k`, asking
    /// again with the same K after an error (it answers a placed create as
    /// placed). `None`: no answer.
    async fn put_bucket<B: BucketRecords>(
        &self,
        records: &B,
        request: &BucketRequest<'_>,
        k: u64,
    ) -> Option<BucketPut> {
        let bucket = bucket_id(self.tenant, k);
        for _ in 0..MAX_PUTS {
            if let Ok(p) = records
                .bucket_created(self.tenant, &bucket, request.unit, request.creator, k)
                .await
            {
                return Some(p);
            }
        }
        None
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
        match self.put_bucket(records, request, k).await {
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
                // revokes the grant: its reservation is released, and a
                // retry never places a bound grant its creator lost.
                let _ = self
                    .drop_grant(table, request.creator, bucket.as_str(), rng)
                    .await;
                let _ = self
                    .admission
                    .release_bound(self.tenant, idempotency_key, Some(k))
                    .await;
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
        // Bound seqs this call found lost or revoked: the unit answers the
        // newest bound seq until a new one is bound, and such a seq is
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
            let (keys_seq, seen) = match self
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
                    // In force only when both chains' stores have it.
                    let in_force = match self.put_bucket(records, request, grant_seq).await {
                        Some(BucketPut::Placed { in_force }) => in_force,
                        Some(BucketPut::OrderLost | BucketPut::Refused { .. }) => {
                            return Err(ERR_BINDING)
                        }
                        None => false,
                    };
                    let keys = self.keys_in_force(table, &revoked).await;
                    return Ok(match keys && in_force {
                        true => BucketAnswer::Created { bucket, grant_seq },
                        false => BucketAnswer::Unfinished { grant_seq },
                    });
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
                BucketAdmission::Admitted { keys_seq, bound } => (keys_seq, bound),
            };

            if let Some(k) = seen.filter(|k| !spent.contains(k)) {
                // An earlier call under this key wrote and bound k: place
                // that grant's bucket, never a second one. It was bound
                // after its own put, so it is this reservation's grant.
                let bytes = self.store.get(&chain.name(k)).await?.ok_or(ERR_BINDING)?;
                let record = open_key_record(self.kek, self.ring, self.tenant, k, &bytes)?;
                if !is_creator_grant(self.tenant, &record) || record.door.id != request.creator {
                    return Err(ERR_BINDING);
                }
                // A bound grant its creator no longer holds (revoked after
                // a refusal) is never placed: take a new K.
                let bucket = bucket_id(self.tenant, k);
                let held = table
                    .get(request.creator)
                    .is_some_and(|e| e.door.grants.iter().any(|g| g.bucket_id == bucket.as_str()));
                if !held {
                    spent.insert(k);
                    continue;
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
                    let _ = self
                        .admission
                        .release_bound(self.tenant, idempotency_key, seen)
                        .await;
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
            // retry places this grant's bucket and no second one, and only
            // while no other call under the key bound one since: of two
            // calls, one binds and the other places that one's bucket. An
            // unbound grant is never placed: it is revoked.
            match self
                .admission
                .bind_bucket(self.tenant, idempotency_key, seen, k)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    if self
                        .drop_grant(table, request.creator, bucket.as_str(), rng)
                        .await
                        .is_none()
                    {
                        return Ok(BucketAnswer::Unfinished { grant_seq: k });
                    }
                    puts += 1;
                    continue;
                }
                Err(_) => {
                    let _ = self.apply_all(table, &revoked).await;
                    return Ok(BucketAnswer::Unfinished { grant_seq: k });
                }
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
/// is retried while this answers [`CreatorGrant::Busy`] or an error.
///
/// - The record at `seq` is no creator grant: nothing.
/// - Its bucket is placed, or its reservation became the bucket: nothing.
/// - An open reservation is bound to it: the create is run again under
///   that reservation, as the Worker would have ([`KeyEnv::create_bucket`]:
///   it places this grant's bucket, or after a lost order a new one);
///   when that does not place this grant's bucket, the grant is revoked.
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
    match env.admission.bucket_binding(env.tenant, seq).await? {
        Binding::Created => return Ok(CreatorGrant::Placed),
        Binding::None => {}
        Binding::Open {
            idempotency_key,
            name,
            creator: bound,
            unit,
        } => {
            if bound != creator {
                return Err(ERR_BINDING);
            }
            let request = BucketRequest {
                name: &name,
                creator,
                unit,
            };
            match env
                .create_bucket(records, table, &idempotency_key, &request, rng)
                .await?
            {
                BucketAnswer::Created { grant_seq, .. } if grant_seq == seq => {
                    return Ok(CreatorGrant::Placed)
                }
                BucketAnswer::Busy | BucketAnswer::Unfinished { .. } => {
                    return Ok(CreatorGrant::Busy)
                }
                // Placed under another K, or refused: this grant is an
                // orphan.
                BucketAnswer::Created { .. }
                | BucketAnswer::Refused(_)
                | BucketAnswer::StateRefused { .. } => {}
            }
            if records.is_placed(env.tenant, &bucket).await? {
                return Ok(CreatorGrant::Placed);
            }
        }
    }
    match env.drop_grant(table, creator, bucket.as_str(), rng).await {
        Some(revoke) => Ok(CreatorGrant::Revoked { seq: revoke }),
        None => Ok(CreatorGrant::Busy),
    }
}
