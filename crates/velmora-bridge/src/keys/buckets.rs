//! The creator-grant writer: a bucket create of a managed tenant (DS1 A7,
//! ADR §6.2 with AM-8 and AM-24).
//!
//! The order is reservation → intent → creator grant (key chain) →
//! `bucket_created` (tenant chain) → the stores.
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
//! - **A create that loses the K order** (another create with a higher K
//!   was recorded first) revokes its orphan grant with a closing record,
//!   then writes a new creator grant at a new K under the same
//!   reservation, at most [`MAX_ORDER_TRIES`] times, then answers busy
//!   (`503` with `Retry-After`).
//! - **Every other refusal of `bucket_created`** (the tenant state,
//!   `restoring`, an unlisted unit) revokes the orphan grant, releases the
//!   reservation, and answers the refusal's `409` with its code.
//! - **An orphan opens nothing** (a grant is served only on a bucket its
//!   unit holds), but it counts against the subject's 64 grants. The
//!   finisher of the grant's intent ([`finish_creator_grant`]) revokes one
//!   whose bucket can never be placed any more.

use std::collections::BTreeSet;

use velmora::rng::FillRandom;

use super::chain::Put;
use super::checkpoint::{advance, reopen_closed, reopen_from_checkpoints};
use super::ports::{
    BucketAdmission, BucketPut, BucketRecords, BucketReservation, ControlChain, ControlIntents,
    KeyAdmission, KeyTarget, Refusal,
};
use super::record::{
    key_chain, open_key_record, seal_key_record, Access, Grant, KeyOp, KeyTable, SubjectKind,
    SubjectStatus, TkRing, MAX_SUBJECT_GRANTS,
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
    /// The bucket is recorded in both chains. `in_force`: every door
    /// store acknowledged the creator grant; when not, the finisher
    /// brings them up within its bound. A retry under the same
    /// `Idempotency-Key` is answered from the reservation.
    Created {
        bucket: BucketId,
        grant_seq: u64,
        in_force: bool,
    },
    /// Refused before any record: the creator, its grant count or the
    /// reservation.
    Refused(Refusal),
    /// The tenant chain refused the bucket: the orphan grant is revoked
    /// (or left to the finisher when the revoke could not be written) and
    /// the reservation released. Answer `status` with `code`.
    StateRefused { status: u16, code: &'static str },
    /// `503` with `Retry-After`: no bucket. The K order was lost
    /// [`MAX_ORDER_TRIES`] times, or the key-chain put [`MAX_PUTS`]
    /// times, or the creator's private part cannot be opened now.
    Busy,
    /// `503`: the creator grant `grant_seq` is written, and either the
    /// tenant chain could not be reached or an orphan grant could not be
    /// revoked. The grant's intent finishes it.
    Unfinished { grant_seq: u64 },
}

/// What the finisher did for one creator grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreatorGrant {
    /// The record at the seq is no creator grant.
    NotOne,
    /// Its bucket is placed: nothing to do.
    Placed,
    /// Its bucket can never be placed: the grant is revoked (or already
    /// was) by the record `seq`.
    Revoked { seq: u64 },
    /// Its bucket is not placed and could still be: the Worker that wrote
    /// it may not have finished. Left for a later run (an attention entry
    /// when it stays).
    Undecided,
    /// The orphan could not be revoked now (the store, or the private
    /// part does not open): retry.
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
    /// Revokes the orphan creator grant on `bucket`: the seq of the record
    /// that carries the revoke (the head when it already did), or `None`
    /// when none could be written now.
    async fn drop_orphan<R: FillRandom>(
        &self,
        table: &mut KeyTable,
        creator: &str,
        bucket: &BucketId,
        rng: &mut R,
    ) -> Result<Option<u64>> {
        let request = KeyRequest::DropGrant {
            id: creator.to_owned(),
            bucket_id: bucket.as_str().to_owned(),
        };
        // A closing change: the idempotency key is not used.
        Ok(match self.change(table, "", &request, rng).await? {
            KeyAnswer::Done { seq } | KeyAnswer::Unfinished { seq } => Some(seq),
            KeyAnswer::Refused(_) | KeyAnswer::Busy => None,
        })
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
            let subject = match creator_at_head(table, &revoked, request.creator) {
                Creator::Ok(s) => s,
                Creator::Refused(r) => return Ok(BucketAnswer::Refused(r)),
                Creator::Busy => return Ok(BucketAnswer::Busy),
            };

            // Reservation: the grant must be exactly its keys_seq + 1.
            let k = match self
                .admission
                .admit_bucket(self.tenant, idempotency_key, &reservation)
                .await?
            {
                BucketAdmission::Created { bucket, grant_seq } => {
                    // A retry: the reservation is the bucket. Its id must be
                    // the derivation of its grant, or the answer is not one.
                    if bucket != bucket_id(self.tenant, grant_seq) {
                        return Err(BridgeError::Invalid(
                            "reservation names a bucket id that is not derived",
                        ));
                    }
                    let acks = self.apply_all(table, &revoked).await;
                    let in_force = matches!(
                        self.answer(Class::Opening, table, table.seq(), acks).await,
                        KeyAnswer::Done { .. }
                    );
                    return Ok(BucketAnswer::Created {
                        bucket,
                        grant_seq,
                        in_force,
                    });
                }
                // A refusal by a unit behind the head may be stale: bring
                // the units up once and ask again.
                // (The bucket cap does not depend on the key chain.)
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
                BucketAdmission::Admitted { keys_seq } if keys_seq == table.seq() => keys_seq + 1,
                BucketAdmission::Admitted { keys_seq } => {
                    if keys_seq < table.seq() {
                        let _ = self.apply_all(table, &revoked).await;
                    }
                    puts += 1;
                    continue;
                }
            };

            // Intent, then the creator grant at exactly K.
            self.intents
                .send(self.tenant, ControlChain::Keys, k)
                .await?;
            let _ = self
                .intents
                .note(self.tenant, ControlChain::Keys, k, BUCKET_CREATE_KIND)
                .await;
            let bucket = bucket_id(self.tenant, k);
            let mut grants = subject.grants();
            grants.push(creator_grant(&bucket));
            let mut next = subject.clone();
            next.set_grants(&grants);
            if table
                .admits(KeyOp::Grants, &next.door, Some(&next.private))
                .is_err()
            {
                // The derived id is already among the creator's grants: a
                // hash collision. Nothing is recorded; the reservation goes.
                let _ = self.admission.release(self.tenant, idempotency_key).await;
                return Ok(BucketAnswer::Refused(Refusal::Conflict));
            }
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
            let record = open_key_record(self.kek, self.ring, self.tenant, k, &bytes)?;
            table.apply(&record)?;

            // The tenant chain: K is this call's own.
            let placed = records
                .bucket_created(self.tenant, &bucket, request.unit, request.creator, k)
                .await;
            match placed {
                Ok(BucketPut::Placed) => {
                    let acks = self.apply_all(table, &revoked).await;
                    let in_force = matches!(
                        self.answer(Class::Opening, table, k, acks).await,
                        KeyAnswer::Done { .. }
                    );
                    return Ok(BucketAnswer::Created {
                        bucket,
                        grant_seq: k,
                        in_force,
                    });
                }
                Ok(BucketPut::OrderLost) => {
                    if self
                        .drop_orphan(table, request.creator, &bucket, rng)
                        .await?
                        .is_none()
                    {
                        return Ok(BucketAnswer::Unfinished { grant_seq: k });
                    }
                    lost_orders += 1;
                    if lost_orders >= MAX_ORDER_TRIES {
                        return Ok(BucketAnswer::Busy);
                    }
                    // A new K under the same reservation.
                    puts = 0;
                    caught_up = false;
                    caught_up_in_full = false;
                    continue;
                }
                Ok(BucketPut::Refused { status, code }) => {
                    // The orphan is revoked here when it can be; else by the
                    // finisher of its intent. The refusal stands either way.
                    let _ = self.drop_orphan(table, request.creator, &bucket, rng).await;
                    let _ = self.admission.release(self.tenant, idempotency_key).await;
                    return Ok(BucketAnswer::StateRefused { status, code });
                }
                Err(_) => {
                    let _ = self.apply_all(table, &revoked).await;
                    return Ok(BucketAnswer::Unfinished { grant_seq: k });
                }
            }
        }
        Ok(BucketAnswer::Busy)
    }
}

/// The finisher of a creator grant's intent (`apply_control(tenant,
/// keys, seq)`), run beside [`super::writer::finish_keys`]: when the
/// record at `seq` is a creator grant whose bucket can never be placed
/// (not placed, and `seq` at or below the tenant chain's
/// `last_grant_seq`), it revokes the grant. It never places a bucket.
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
    let chain = key_chain(env.tenant);
    let Some(bytes) = env.store.get(&chain.name(seq)).await? else {
        return Ok(CreatorGrant::NotOne);
    };
    let record = open_key_record(env.kek, env.ring, env.tenant, seq, &bytes)?;
    let bucket = bucket_id(env.tenant, seq);
    let creates = record.op == KeyOp::Grants
        && record.door.kind == SubjectKind::Principal
        && !record.closes
        && record
            .door
            .grants
            .iter()
            .any(|g| g.bucket_id == bucket.as_str());
    if !creates {
        return Ok(CreatorGrant::NotOne);
    }
    let order = records.grant_order(env.tenant, &bucket).await?;
    if order.placed {
        return Ok(CreatorGrant::Placed);
    }
    if seq > order.last_grant_seq {
        return Ok(CreatorGrant::Undecided);
    }
    Ok(
        match env
            .drop_orphan(table, &record.door.id, &bucket, rng)
            .await?
        {
            Some(seq) => CreatorGrant::Revoked { seq },
            None => CreatorGrant::Busy,
        },
    )
}
