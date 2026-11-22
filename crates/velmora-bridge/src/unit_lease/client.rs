//! The unit client: the Worker's side of `renew` and `sync` (ADR-TENANCY
//! §2.4 rules 5 and 12; round 5 §R5-4, AM-50, AM-51).
//!
//! A unit holds no key and does no I/O (rules 3 and 4), so the Worker
//! does the reads a unit needs and hands it the verified result:
//!
//! - **`renew`.** The unit's numbers, stamp counter and revoked count come
//!   from its own answers (a stamp read through the job path, which a unit
//!   with an expired lease still serves). The proof is
//!   [`super::renewal::prove`] over the safety bucket. Then the unit is
//!   called with `renew(proof_start, proven, revocations)`. A newer record
//!   means `sync` first. Stamp objects after the counter: the proof holds
//!   the newest one's counter, and the unit renews only if its own counter
//!   reached it; a `not_proven` refusal (or a full page ahead) is confirmed
//!   through the unit's own counter ([`crate::stamp::Stamp::checked`]),
//!   which records a rollback and closes the unit only if the counter has
//!   not moved.
//! - **`sync`.** The tenant chain's verified head ([`TenantHeads`]) and the
//!   key-chain records after the unit's `keys_seq` ([`KeyFeed`]): first
//!   the key apply (AM-12), then `sync` with both heads. The `sync` that
//!   would lift a `restoring` entry is the restore tool's (AM-45): it
//!   carries the lift, which no record here has, so the client reports
//!   [`Synced::LiftPending`] and changes nothing.
//! - **Rule 5 on the request path** ([`UnitClient::call`]): a
//!   `renew_needed` renews, a `sync_needed` syncs, a lower request number
//!   takes the unit's numbers; then the call runs once more. An answer
//!   with less than half of T left asks for a background renewal
//!   ([`Answered::renew_due`]; the caller runs
//!   [`UnitClient::renew_in_background`] under `waitUntil`). Unsigned
//!   calls and background renewals go through the isolate's spacing
//!   ([`InFlight`]): none while one runs, and after a failed attempt a
//!   backoff from 60 s doubling up to T (rule 11). Signed calls go through
//!   the same spacing with the backoff capped at 1 s.
//! - **The two unit jobs** ([`UnitClient::run_job`]): `renew` and
//!   `stamp_raise`, which the queue consumer hands here (AM-51). Under
//!   `MAINTENANCE = restore` the consumer acknowledges both without a call
//!   (AM-50); that check is the consumer's, before this.
//!
//! Every port is a trait, so native tests run the real unit
//! ([`crate::unit::Unit`]) behind a fake [`UnitReplies`].
//!
//! Errors: `Err` is a store or call that failed and may pass (the queue
//! hands the message back); an outcome is an answer. No error or outcome
//! carries a key, a secret or a caller's input.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use serde_json::Value;

use crate::crypto::scheme2::TenantId as KeyTenant;
use crate::directory::chain::{record_key, ChainError, ControlSeal, TenantChain};
use crate::directory::record::{
    HoldMode as DirHoldMode, Tenant, TenantDoor, TenantState as DirState,
};
use crate::jobmsg::UnitJob;
use crate::keys::record::key_chain;
use crate::keys::revocations::tenant_revocation_prefix;
use crate::ports::{BlobStore, Clock};
use crate::records::RecordStore;
use crate::stamp::{Stamp, StampLedger, StampRow, ERR_ROLLED_BACK};
use crate::types::{BridgeError, Result, UnixMs};
use crate::unit::call::HoldMode;
use crate::unit::identity::Refusal;
use crate::unit::jobcall::JobCall;
use crate::unit::keys::{ApplyEntry, KeptAnswer, MAX_ENTRIES};
use crate::unit::{
    CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, UnitAnswer, UnitCall, UnitName,
    UnitOp, UnitReply,
};

use super::alarm::{renew_retry_ms, AlarmRules};
use super::lease::{LeaseRefusal, LeaseRules};
use super::renewal::{prove, ChainNames, Proof, UnitView};
use super::stamp_id::UnitStampId;

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// The unit object as the Worker reaches it: one call, and the whole
/// reply ([`UnitReply`]: the answer, `lease_left_ms` and `revoked`). The
/// Worker's stub (`workers/s3-bridge/src/units.rs`) implements it beside
/// `tenant_catalog::UnitPort`.
#[allow(async_fn_in_trait)]
pub trait UnitReplies {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply>;
}

impl<T: UnitReplies> UnitReplies for &T {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply> {
        (**self).reply(call).await
    }
}

/// The verified head of a tenant's chain `m/t/<t>/` (L3's reader:
/// [`crate::directory::chain::TenantChain::head`], which this crate
/// implements the port for).
#[allow(async_fn_in_trait)]
pub trait TenantHeads {
    /// The newest record's door part, listing after `known`; `None` = the
    /// tenant has no chain.
    async fn head(
        &self,
        tenant: &TenantId,
        known: u64,
    ) -> std::result::Result<Option<TenantDoor>, ChainError>;
}

/// The key-chain records of a tenant after a seq, verified and in the
/// form the unit applies them (L4's reader and apply feed, AM-12).
#[allow(async_fn_in_trait)]
pub trait KeyFeed {
    /// The records of `m/k/<tenant>/` after `after`, one entry per record
    /// in chain order, up to the chain's head.
    async fn after(&self, tenant: &TenantId, after: u64) -> Result<KeyBatch>;
}

/// What [`KeyFeed::after`] read.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeyBatch {
    /// The chain's head seq (`after` when nothing follows it).
    pub head: u64,
    /// The items after `after`, up to `head`: a subject's entry, or a
    /// marker for a record that changes no subject (AM-62).
    pub entries: Vec<ApplyEntry>,
    /// The answers kept for the reservations whose records these are
    /// (AM-38), if the feed has them.
    pub answers: Vec<KeptAnswer>,
}

/// The key chain's finisher, told that a renewal listed revocations the
/// unit did not hold (ADR rule 12, SEC-6: "sends an `apply_control`
/// message for the key chain"). The Worker sends the `apply_control`
/// message; a failure is logged by the caller and changes nothing here.
#[allow(async_fn_in_trait)]
pub trait KeyFinisher {
    async fn revocations_unrecorded(&self, tenant: &TenantId) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Something the caller logs as an alert (it pages). Fixed words and
/// names only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Page {
    /// Names under `m/rk/<t>/` that are not an access key id: skipped.
    /// The first [`MAX_PAGED_NAMES`] of them, and how many there are.
    StrayRevocationNames { first: Vec<String>, total: usize },
    /// The unit holds more revocations than `m/rk/<t>/` lists: not
    /// renewed (no correct history gives it).
    RevocationsShort { listed: u64, held: u64 },
    /// A stamp object after the unit's counter, confirmed: the unit is
    /// rolled back and now closed; the restore gate is needed (§8.6).
    RolledBack,
    /// The unit refused a renewal for a reason that needs an operator
    /// (no lease table, a bad list).
    RenewRefused(LeaseRefusal),
    /// The finisher could not be told of unrecorded revocations; the
    /// unit holds them all the same.
    FinisherNotTold,
    /// The unit refused a call of the client in a way no rule expects
    /// (the fixed text of the error).
    UnitRefused(&'static str),
}

/// The most names one page carries.
pub const MAX_PAGED_NAMES: usize = 10;

impl Page {
    /// The page of `names`, stray under the revocations: the first few.
    fn stray(names: Vec<String>) -> Page {
        let total = names.len();
        Page::StrayRevocationNames {
            first: names.into_iter().take(MAX_PAGED_NAMES).collect(),
            total,
        }
    }
}

/// What [`UnitClient::renew`] came to.
#[derive(Clone, Debug, PartialEq)]
pub enum Renewal {
    /// The unit is fresh for `lease_left_ms` more, at `seqs`.
    Renewed { seqs: Seqs, lease_left_ms: u64 },
    /// The unit takes no renewal until the gate lifts it: a `restoring`
    /// entry, or a recorded rollback (`rolled_back`).
    Closed { rolled_back: bool },
    /// The unit has no certificate (rule 7): the caller decides from the
    /// tenant's verified head whether that pages.
    Unborn,
    /// The tenant's verified head does not list this unit (it was
    /// removed): nothing to renew.
    NotListed,
    /// Not renewed, and not retryable here: see the pages.
    Refused,
    /// The tenant is being shredded: its unit takes no job, and nothing
    /// pages (AM-50's shredding row).
    Shredding,
}

/// What [`UnitClient::sync`] came to.
#[derive(Clone, Debug, PartialEq)]
pub enum Synced {
    /// The unit holds both chain heads: `seqs`.
    Synced { seqs: Seqs },
    /// The head clears this unit's `restoring` entry. Only the restore
    /// tool's `sync`, which carries the lift, may clear it (AM-45); the
    /// unit stays closed and nothing changed.
    LiftPending { seqs: Seqs },
    /// The unit has no certificate.
    Unborn,
    /// The tenant's verified head does not list this unit.
    NotListed,
}

/// A request-path answer after rule 5 ([`UnitClient::call`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Answered {
    /// The unit's last reply.
    pub reply: UnitReply,
    /// The call ran again with the unit's numbers, which are above the
    /// caller's: the caller's view of the tenant head is old and is read
    /// again.
    pub refreshed: Option<Seqs>,
    /// Less than half of T is left: renew in the background (rule 12,
    /// [`UnitClient::renew_in_background`]).
    pub renew_due: bool,
    /// What a renewal this call made came to (`None`: it made none, or
    /// the spacing held it back). With the reply still `renew_needed`, it
    /// names the AM-50 row: `Closed`, `Unborn`, `NotListed`, `Shredding`
    /// or `Refused`.
    pub renewal: Option<Renewal>,
    /// What a sync this call made came to.
    pub synced: Option<Synced>,
}

/// What the queue does with a `renew` or `stamp_raise` message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Done, or nothing to do.
    Ack,
    /// Hand it back with the queue's retry delay (a failure that may pass).
    HandBack,
    /// The unit has no certificate: the consumer reads the tenant's
    /// verified head and applies AM-50's `Unborn` row.
    Unborn,
    /// The unit refused in a way no row of AM-50's table names (a wrong
    /// name, an unauthenticated call, a failed unit, a refused key apply):
    /// to the dead-letter queue, with a page (AM-50: "any other refusal").
    DeadLetter,
}

/// The delivery of one unit job, and its log line.
#[derive(Clone, Debug, PartialEq)]
pub struct JobResult {
    pub delivery: Delivery,
    /// A fixed word for the log line.
    pub code: &'static str,
    /// Alerts to log (each pages).
    pub pages: Vec<Page>,
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// The Worker's client of one unit. See the [module](self).
pub struct UnitClient<U, B, T, N, H, K, F> {
    /// The unit object.
    pub unit: U,
    /// The safety bucket: the proof's reads, and the stamp objects.
    pub safety: B,
    pub clock: T,
    /// The names of the tenant's records.
    pub names: N,
    /// The tenant chain's verified head.
    pub heads: H,
    /// The key chain's verified records.
    pub keys: K,
    /// The key chain's finisher.
    pub finisher: F,
    /// The unit's name.
    pub name: UnitName,
    /// Whether the caller reached the unit through a record that lists
    /// it (rule 7): the request path takes it from the head; job and
    /// Worker calls send `false` (AM-50).
    pub listed: bool,
    /// The lease dials (T): for the half-of-T rule.
    pub lease: LeaseRules,
    /// The isolate's renewals in flight and their attempts, by unit.
    pub flights: InFlight,
}

impl<U, B, T, N, H, K, F> UnitClient<U, B, T, N, H, K, F>
where
    U: UnitReplies,
    B: BlobStore,
    T: Clock,
    N: ChainNames,
    H: TenantHeads,
    K: KeyFeed,
    F: KeyFinisher,
{
    /// The unit's stamp id `<tenant>.<unit>`. `Err` for tenant 0, which
    /// has no unit.
    pub fn stamp_id(&self) -> Result<UnitStampId> {
        UnitStampId::new(self.name.tenant.as_str(), self.name.unit)
    }

    /// Proves the unit fresh and renews its lease (rule 12). `seen`: the
    /// unit's numbers as its last answer gave them (the job message's for
    /// a `renew` job). Syncs first when the proof finds a newer record.
    /// The pages come back whatever the outcome, an `Err` included.
    pub async fn renew(&self, seen: Seqs) -> (Result<Renewal>, Vec<Page>) {
        let mut pages = Vec::new();
        let outcome = self.renew_into(seen, &mut pages).await;
        (outcome, pages)
    }

    async fn renew_into(&self, seen: Seqs, pages: &mut Vec<Page>) -> Result<Renewal> {
        let id = self.stamp_id()?;
        let mut seqs = seen;
        let mut kicked = false;
        let mut strays_paged = false;
        for _ in 0..RENEW_ROUNDS {
            // The unit's counter, revoked count and numbers: one stamp
            // read through the job path, which an expired lease allows.
            let ledger = UnitLedger::new(self, seqs);
            let read = match ledger.read_stamp(id.as_str()).await? {
                Step::Done(read) => read,
                Step::Stop(stop) => match self.on_stop(stop).await? {
                    Flow::Again(now) => {
                        seqs = now;
                        continue;
                    }
                    Flow::Done(renewal) => return Ok(renewal),
                },
            };
            seqs = read.seqs;
            if read.row.rolled_back {
                // Closed until the restore gate lifts it. Paged on every
                // look (the page that recorded it may have been lost); the
                // request path tries at most once per unit and T unsigned.
                pages.push(Page::RolledBack);
                return Ok(Renewal::Closed { rolled_back: true });
            }
            let view = UnitView {
                stamp_id: &id,
                state_seq: seqs.state_seq,
                keys_seq: seqs.keys_seq,
                stamp_counter: read.row.counter,
                revoked: read.revoked,
            };
            match prove(&self.safety, &self.clock, &self.names, &view).await? {
                Proof::Fresh {
                    proof_start,
                    proven,
                    revocations,
                    stray,
                } => {
                    if !stray.is_empty() && !strays_paged {
                        strays_paged = true;
                        pages.push(Page::stray(stray));
                    }
                    // The finisher is told before the call: the unit keeps
                    // the listed ids whatever it answers, and an answer lost
                    // after it kept them would leave the next proof with
                    // equal counts and nothing to tell (`apply_control` is
                    // idempotent).
                    if !revocations.is_empty() && !kicked {
                        kicked = true;
                        if self
                            .finisher
                            .revocations_unrecorded(&self.name.tenant)
                            .await
                            .is_err()
                        {
                            pages.push(Page::FinisherNotTold);
                        }
                    }
                    // Stamp objects after the counter the unit reported:
                    // the proof holds the newest, and the unit renews only
                    // if its own counter reached it.
                    let stamp_moved = proven.stamp_counter != read.row.counter;
                    let op = UnitOp::Renew {
                        proof_start,
                        proven,
                        revocations,
                    };
                    let reply = self.unit.reply(&self.worker_call(seqs, op)).await?;
                    match reply.answer {
                        UnitAnswer::Ok { seqs, .. } => {
                            let lease_left_ms = reply.lease_left_ms;
                            return Ok(Renewal::Renewed {
                                seqs,
                                lease_left_ms,
                            });
                        }
                        UnitAnswer::RenewNeeded { seqs: now, why } => match why {
                            Some(LeaseRefusal::Restoring) => {
                                return Ok(Renewal::Closed { rolled_back: false })
                            }
                            Some(LeaseRefusal::RolledBack) => {
                                pages.push(Page::RolledBack);
                                return Ok(Renewal::Closed { rolled_back: true });
                            }
                            Some(r @ (LeaseRefusal::NoLeaseTable | LeaseRefusal::BadList)) => {
                                pages.push(Page::RenewRefused(r));
                                return Ok(Renewal::Refused);
                            }
                            // Behind the stamp it was proven at: confirmed
                            // through its own counter.
                            Some(LeaseRefusal::NotProven) if stamp_moved => {
                                match self.confirm_stamp(&id, now, pages).await? {
                                    Flow::Again(next) => seqs = next,
                                    Flow::Done(renewal) => return Ok(renewal),
                                }
                            }
                            // The unit moved (a sync, a key apply, a
                            // raise) or the proof aged: prove again.
                            _ => seqs = now,
                        },
                        UnitAnswer::Unborn { .. } => return Ok(Renewal::Unborn),
                        UnitAnswer::Failed { class } => return Err(unit_failed(&class)),
                        _ => return Err(ERR_RENEW_ANSWER),
                    }
                }
                Proof::SyncNeeded { .. } => match self.on_stop(Stop::SyncNeeded(seqs)).await? {
                    Flow::Again(now) => seqs = now,
                    Flow::Done(renewal) => return Ok(renewal),
                },
                // A full page of stamp objects after the counter: confirmed
                // before anything else.
                Proof::StampAhead { .. } => match self.confirm_stamp(&id, seqs, pages).await? {
                    Flow::Again(next) => seqs = next,
                    Flow::Done(renewal) => return Ok(renewal),
                },
                Proof::RevocationsShort {
                    listed,
                    held,
                    stray,
                } => {
                    if !stray.is_empty() && !strays_paged {
                        pages.push(Page::stray(stray));
                    }
                    pages.push(Page::RevocationsShort { listed, held });
                    return Ok(Renewal::Refused);
                }
            }
        }
        Err(ERR_RENEW_ROUNDS)
    }

    /// Stamp objects lie after the unit's counter. Not yet a rollback: a
    /// raise that ran after the read moves the counter. `checked` records
    /// one only while the counter is still the one it read; then the unit
    /// is closed and the client pages.
    async fn confirm_stamp(
        &self,
        id: &UnitStampId,
        seqs: Seqs,
        pages: &mut Vec<Page>,
    ) -> Result<Flow> {
        let ledger = UnitLedger::new(self, seqs);
        let stamp = Stamp {
            ledger: &ledger,
            safety: &self.safety,
            clock: &self.clock,
            id: id.as_str(),
        };
        let checked = stamp.checked().await;
        let seqs = ledger.seqs.get();
        match checked {
            Ok(None) => {
                pages.push(Page::RolledBack);
                Ok(Flow::Done(Renewal::Closed { rolled_back: true }))
            }
            Ok(Some(_)) => Ok(Flow::Again(seqs)),
            Err(e) => match ledger.stopped() {
                Some(stop) => self.on_stop(stop).await,
                None => Err(e),
            },
        }
    }

    /// What a renewal does when the unit's answer stops a stamp call, or
    /// the proof finds a newer record.
    async fn on_stop(&self, stop: Stop) -> Result<Flow> {
        Ok(match stop {
            Stop::Closed => Flow::Done(Renewal::Closed { rolled_back: false }),
            Stop::Unborn => Flow::Done(Renewal::Unborn),
            Stop::Shredding => Flow::Done(Renewal::Shredding),
            // The unit is behind (a newer record, or a rolled-back unit
            // found by the numbers, rule 5): sync it, then prove again.
            Stop::SyncNeeded(unit) => match self.sync(unit).await? {
                Synced::Synced { seqs } => Flow::Again(seqs),
                Synced::LiftPending { .. } => Flow::Done(Renewal::Closed { rolled_back: false }),
                Synced::Unborn => Flow::Done(Renewal::Unborn),
                Synced::NotListed => Flow::Done(Renewal::NotListed),
            },
            // Only `stamp_advance` waits for the lease; a renewal makes no
            // advance.
            Stop::RenewNeeded => return Err(ERR_LEASE_EXPIRED),
        })
    }

    /// Reads and verifies both chains up to their heads, applies the
    /// key-chain records (AM-12), then calls `sync` (rule 5). `seen`: the
    /// unit's numbers as its last answer gave them.
    pub async fn sync(&self, seen: Seqs) -> Result<Synced> {
        let tenant = &self.name.tenant;
        let mut unit = seen;
        for _ in 0..SYNC_ROUNDS {
            let door = match self.heads.head(tenant, unit.state_seq).await {
                Ok(Some(door)) => door,
                Ok(None) => return Ok(Synced::NotListed),
                Err(e) => return Err(chain_error(e)),
            };
            if !door.units.contains(&self.name.unit) {
                return Ok(Synced::NotListed);
            }
            // The key chain first: `sync` refuses a `keys_seq` the unit's
            // rows do not hold (`keys_not_applied`).
            let batch = self.keys.after(tenant, unit.keys_seq).await?;
            if batch.head < unit.keys_seq {
                return Err(ERR_KEYS_BELOW);
            }
            // In pages the unit takes (`keys::MAX_ENTRIES`), each from the
            // unit's own `keys_seq`; every page must move it on.
            let mut behind = false;
            while unit.keys_seq < batch.head {
                let page: Vec<ApplyEntry> = batch
                    .entries
                    .iter()
                    .filter(|e| e.seq() > unit.keys_seq)
                    .take(MAX_ENTRIES)
                    .cloned()
                    .collect();
                if page.is_empty() {
                    return Err(ERR_KEYS_GAP);
                }
                let answers: Vec<KeptAnswer> = batch
                    .answers
                    .iter()
                    .filter(|a| {
                        page.iter()
                            .filter_map(ApplyEntry::key)
                            .any(|e| e.rid.as_ref() == Some(&a.rid))
                    })
                    .cloned()
                    .collect();
                let op = UnitOp::ApplyKeys {
                    from_seq: unit.keys_seq,
                    entries: page,
                    answers,
                };
                let reply = self.unit.reply(&self.worker_call(unit, op)).await?;
                match reply.answer {
                    UnitAnswer::Ok { seqs, .. } if seqs.keys_seq > unit.keys_seq => unit = seqs,
                    UnitAnswer::Ok { .. } => return Err(ERR_KEYS_STUCK),
                    // The unit holds fewer records than it said (restored
                    // in between): read again from its own seq.
                    UnitAnswer::KeysBehind { seqs } => {
                        unit = seqs;
                        behind = true;
                        break;
                    }
                    UnitAnswer::Unborn { .. } => return Ok(Synced::Unborn),
                    UnitAnswer::Failed { class } => return Err(unit_failed(&class)),
                    _ => return Err(ERR_KEYS_ANSWER),
                }
            }
            if behind || unit.keys_seq != batch.head {
                continue;
            }
            let (tenant_state, tenant_mode) = unit_state(&door);
            let restoring_since = door.restoring_entry(self.name.unit).map(|r| r.since_seq);
            let next = SyncHead {
                seqs: Seqs {
                    state_seq: door.seq,
                    keys_seq: batch.head,
                },
                tenant_state,
                tenant_mode,
                restoring_since,
                lift: None,
            };
            let reply = self
                .unit
                .reply(&self.worker_call(unit, UnitOp::Sync { head: next }))
                .await?;
            match reply.answer {
                UnitAnswer::Ok { seqs, .. } => return Ok(Synced::Synced { seqs }),
                UnitAnswer::Unborn { .. } => return Ok(Synced::Unborn),
                // A head that clears this unit's entry: the lift is the
                // restore tool's (AM-45), with the proof no record here
                // carries.
                UnitAnswer::Refused {
                    reason: Refused::Gate(_),
                    ..
                } if restoring_since.is_none() => return Ok(Synced::LiftPending { seqs: unit }),
                // The unit moved past what was read (another sync, a key
                // apply): read its numbers and the heads again.
                UnitAnswer::Refused {
                    reason: Refused::StaleSync | Refused::KeysNotApplied,
                    ..
                } => match self.unit_seqs().await? {
                    Some(now) => unit = now,
                    None => return Ok(Synced::Unborn),
                },
                UnitAnswer::Failed { class } => return Err(unit_failed(&class)),
                _ => return Err(ERR_SYNC_ANSWER),
            }
        }
        Err(ERR_SYNC_ROUNDS)
    }

    /// Rule 5 on the request path: sends `call`; on `renew_needed` renews,
    /// on `sync_needed` syncs, on a lower number (`stale`) takes the
    /// unit's numbers; then sends it once more. Each fix runs at most once
    /// per call. The pages of a renewal it made come back whatever the
    /// outcome.
    pub async fn call(&self, call: UnitCall) -> (Result<Answered>, Vec<Page>) {
        let mut pages = Vec::new();
        let answered = self.call_into(call, &mut pages).await;
        (answered, pages)
    }

    async fn call_into(&self, mut call: UnitCall, pages: &mut Vec<Page>) -> Result<Answered> {
        let (mut renewed, mut synced, mut restaled) = (false, false, false);
        let mut refreshed = None;
        let mut renewal = None;
        let mut sync_outcome = None;
        loop {
            let reply = self.unit.reply(&call).await?;
            match reply.answer {
                UnitAnswer::RenewNeeded { seqs, why: None } if !renewed => {
                    renewed = true;
                    // Rule 11: an unsigned call renews only through the
                    // isolate's spacing (none while one runs, and after a
                    // failure a backoff up to T).
                    // Signed calls are spaced too, but after a failure by at
                    // most 1 s: a unit whose renewal fails every time costs
                    // one proof and one page per second per isolate, not
                    // one per request.
                    let max_gap = match call.authenticated {
                        true => SIGNED_RETRY_MS,
                        false => self.lease.term_ms,
                    };
                    let outcome = match self.renew_spaced_by(seqs, max_gap).await {
                        Some((renewal, more)) => {
                            pages.extend(more);
                            Some(renewal?)
                        }
                        None => None,
                    };
                    let again = matches!(outcome, Some(Renewal::Renewed { .. }));
                    renewal = outcome;
                    if again {
                        continue;
                    }
                }
                UnitAnswer::SyncNeeded { seqs } if !synced => {
                    synced = true;
                    let outcome = self.sync(seqs).await?;
                    let again = matches!(outcome, Synced::Synced { .. });
                    sync_outcome = Some(outcome);
                    if again {
                        continue;
                    }
                }
                UnitAnswer::Stale { seqs } if !restaled && call.kind == CallKind::Request => {
                    restaled = true;
                    call.seqs = Some(seqs);
                    refreshed = Some(seqs);
                    continue;
                }
                _ => {}
            }
            let renew_due = self.renew_due(&reply);
            return Ok(Answered {
                reply,
                refreshed,
                renew_due,
                renewal,
                synced: sync_outcome,
            });
        }
    }

    /// The background renewal of rule 12 (an answer with less than half of
    /// T left, [`Answered::renew_due`]): the caller runs it under
    /// `waitUntil`. Through the isolate's spacing, as an unsigned call's:
    /// `None` = one runs, or the last one failed too recently.
    pub async fn renew_in_background(&self, seen: Seqs) -> Option<(Result<Renewal>, Vec<Page>)> {
        self.renew_spaced(seen).await
    }

    async fn renew_spaced(&self, seen: Seqs) -> Option<(Result<Renewal>, Vec<Page>)> {
        self.renew_spaced_by(seen, self.lease.term_ms).await
    }

    async fn renew_spaced_by(
        &self,
        seen: Seqs,
        max_gap_ms: i64,
    ) -> Option<(Result<Renewal>, Vec<Page>)> {
        let guard = self
            .flights
            .attempt(&self.name, self.clock.now(), max_gap_ms)?;
        let (renewal, pages) = self.renew(seen).await;
        guard.done(matches!(renewal, Ok(Renewal::Renewed { .. })));
        Some((renewal, pages))
    }

    /// Whether `reply` asks for a background renewal: some lease, and
    /// less than half of T left (rule 12).
    pub fn renew_due(&self, reply: &UnitReply) -> bool {
        let half = u64::try_from(self.lease.term_ms / 2).unwrap_or(0);
        reply.lease_left_ms > 0 && reply.lease_left_ms < half
    }

    /// One `renew` or `stamp_raise` message of this unit, at the numbers
    /// it carries (AM-50, AM-51).
    pub async fn run_job(&self, job: UnitJob, seqs: Seqs) -> JobResult {
        match job {
            UnitJob::Renew { .. } => match self.renew(seqs).await {
                (Ok(renewal), pages) => renewal_result(renewal, pages),
                (Err(e), pages) => failed(&e, "renew_failed", pages),
            },
            UnitJob::StampRaise { .. } => self.raise(seqs).await,
        }
    }

    /// One raise of the unit's stamp (§8.5): the counter moves in the unit
    /// (`stamp_advance`), then its object is put in the safety bucket. A
    /// unit whose lease ran out refuses the advance: renew, then raise
    /// once more.
    async fn raise(&self, seqs: Seqs) -> JobResult {
        let Ok(id) = self.stamp_id() else {
            return job_result(Delivery::Ack, "no_unit", Vec::new());
        };
        let mut seqs = seqs;
        let mut pages = Vec::new();
        for attempt in 0..2 {
            let ledger = UnitLedger::new(self, seqs);
            let stamp = Stamp {
                ledger: &ledger,
                safety: &self.safety,
                clock: &self.clock,
                id: id.as_str(),
            };
            let raised = stamp.raise().await;
            seqs = ledger.seqs.get();
            let stop = ledger.stopped();
            match (raised, stop) {
                (Ok(()), _) => return job_result(Delivery::Ack, "raised", pages),
                (Err(e), _) if is_rolled_back(&e) => {
                    pages.push(Page::RolledBack);
                    return job_result(Delivery::Ack, "rolled_back", pages);
                }
                (Err(_), Some(Stop::RenewNeeded)) if attempt == 0 => {
                    let (renewal, more) = self.renew(seqs).await;
                    pages.extend(more);
                    match renewal {
                        Ok(Renewal::Renewed { seqs: now, .. }) => seqs = now,
                        Ok(renewal) => return renewal_result(renewal, pages),
                        Err(e) => return failed(&e, "renew_failed", pages),
                    }
                }
                (Err(_), Some(Stop::Closed)) => return job_result(Delivery::Ack, "closed", pages),
                (Err(_), Some(Stop::Unborn)) => {
                    return job_result(Delivery::Unborn, "unborn", pages)
                }
                (Err(_), Some(Stop::Shredding)) => {
                    return job_result(Delivery::Ack, "shredding", pages)
                }
                (Err(_), Some(Stop::SyncNeeded(unit))) if attempt == 0 => {
                    match self.sync(unit).await {
                        Ok(Synced::Synced { seqs: now }) => seqs = now,
                        Ok(Synced::LiftPending { .. }) => {
                            return job_result(Delivery::Ack, "closed", pages)
                        }
                        Ok(Synced::Unborn) => return job_result(Delivery::Unborn, "unborn", pages),
                        Ok(Synced::NotListed) => {
                            return job_result(Delivery::Ack, "not_listed", pages)
                        }
                        Err(e) => return failed(&e, "sync_failed", pages),
                    }
                }
                (Err(e), _) => return failed(&e, "raise_failed", pages),
            }
        }
        job_result(Delivery::HandBack, "raise_failed", pages)
    }

    /// The unit's numbers, from a read-only request call with the lowest
    /// numbers: every answer to it but `unborn` carries the unit's own.
    /// `None` = unborn.
    async fn unit_seqs(&self) -> Result<Option<Seqs>> {
        let call = UnitCall {
            name: self.name.clone(),
            kind: CallKind::Request,
            seqs: Some(Seqs {
                state_seq: 0,
                keys_seq: 0,
            }),
            authenticated: false,
            listed: self.listed,
            op: UnitOp::Ping {},
        };
        match self.unit.reply(&call).await?.answer {
            UnitAnswer::Ok { seqs, .. }
            | UnitAnswer::Stale { seqs }
            | UnitAnswer::RenewNeeded { seqs, .. }
            | UnitAnswer::Closed { seqs, .. }
            | UnitAnswer::SyncNeeded { seqs } => Ok(Some(seqs)),
            UnitAnswer::Unborn { .. } => Ok(None),
            UnitAnswer::Failed { class } => Err(unit_failed(&class)),
            _ => Err(ERR_PING_ANSWER),
        }
    }

    fn worker_call(&self, seqs: Seqs, op: UnitOp) -> UnitCall {
        UnitCall {
            name: self.name.clone(),
            kind: CallKind::Worker,
            seqs: Some(seqs),
            authenticated: true,
            listed: self.listed,
            op,
        }
    }

    fn job_call(&self, seqs: Seqs, call: JobCall) -> UnitCall {
        UnitCall {
            name: self.name.clone(),
            kind: CallKind::Job,
            seqs: Some(seqs),
            authenticated: true,
            // Job calls never page "catalogue lost" themselves (AM-50).
            listed: false,
            op: UnitOp::Job { call },
        }
    }
}

/// The longest wait of a signed call's renewal attempt after a failed
/// one (an unsigned call's is T).
const SIGNED_RETRY_MS: i64 = 1000;

/// Rounds of a renewal: a sync, a stamp confirmation and a proof that
/// aged are each one; more than this is a unit that keeps moving.
const RENEW_ROUNDS: usize = 4;
/// Rounds of a sync: a key apply behind, and a unit that moved.
const SYNC_ROUNDS: usize = 4;

const ERR_RENEW_ROUNDS: BridgeError = BridgeError::Invalid("unit renewal: the unit kept moving");
const ERR_RENEW_ANSWER: BridgeError = BridgeError::Invalid("unit renewal: unexpected answer");
const ERR_LEASE_EXPIRED: BridgeError =
    BridgeError::Invalid("unit renewal: the stamp read was refused for the lease");
const ERR_SYNC_ROUNDS: BridgeError = BridgeError::Invalid("unit sync: the unit kept moving");
const ERR_SYNC_ANSWER: BridgeError = BridgeError::Invalid("unit sync: unexpected answer");
const ERR_KEYS_ANSWER: BridgeError = BridgeError::Invalid("unit sync: key apply refused");
const ERR_KEYS_GAP: BridgeError =
    BridgeError::Invalid("unit sync: the key feed has no record after the unit's keys_seq");
const ERR_KEYS_STUCK: BridgeError =
    BridgeError::Invalid("unit sync: a key apply did not move the unit's keys_seq");
const ERR_KEYS_BELOW: BridgeError =
    BridgeError::Invalid("unit sync: the key chain ends below the unit's keys_seq");
const ERR_PING_ANSWER: BridgeError = BridgeError::Invalid("unit: unexpected answer to a ping");
const ERR_STAMP_ANSWER: BridgeError = BridgeError::Invalid("unit: unexpected stamp answer");
const ERR_STAMP_STALE: BridgeError = BridgeError::Invalid("unit: the stamp call was stale twice");
const ERR_STOPPED: BridgeError = BridgeError::Invalid("unit: stamp call stopped");

fn chain_error(e: ChainError) -> BridgeError {
    match e {
        ChainError::Store(e) => e,
        ChainError::Damaged(_) => BridgeError::Invalid("unit sync: the tenant chain is damaged"),
        ChainError::KeyNotHeld { .. } => {
            BridgeError::Invalid("unit sync: a tenant key version is not held yet")
        }
        ChainError::PrivateUnreadable => {
            BridgeError::Invalid("unit sync: the head's private part is unreadable")
        }
        ChainError::Refused(_) | ChainError::Busy => {
            BridgeError::Invalid("unit sync: the chain read failed")
        }
    }
}

/// The unit's form of a verified head's state.
fn unit_state(door: &TenantDoor) -> (TenantState, Option<HoldMode>) {
    let mode = |m: DirHoldMode| match m {
        DirHoldMode::ReadOnly => HoldMode::ReadOnly,
        DirHoldMode::Locked => HoldMode::Locked,
    };
    match door.state() {
        DirState::Provisioning => (TenantState::Provisioning, None),
        DirState::Active => (TenantState::Active, None),
        DirState::Suspended(m) => (TenantState::Suspended, Some(mode(m))),
        DirState::Deleting => (TenantState::Deleting, None),
        DirState::Shredding => (TenantState::Shredding, None),
        DirState::Shredded => (TenantState::Shredded, None),
    }
}

/// A unit's `Failed` answer: a failure inside the unit (its database), as
/// `TenantCatalog` reads it: a store failure, handed back (AM-45 counts a
/// `Failed` answer as a lost one). A fixed class only.
fn unit_failed(class: &str) -> BridgeError {
    match class {
        "guard" => BridgeError::GuardFailed,
        "catalogue_id" => crate::stamp::ERR_CATALOGUE_ID,
        _ => BridgeError::Sql("unit: failed".into()),
    }
}

/// The delivery of a job whose renewal, sync or raise failed with `e`: an
/// answer of the unit that no rule expects goes to the dead-letter queue
/// with a page (AM-50); anything else (a store or a call that failed) is
/// handed back to be retried.
fn failed(e: &BridgeError, code: &'static str, mut pages: Vec<Page>) -> JobResult {
    let unexpected = [
        ERR_RENEW_ANSWER,
        ERR_SYNC_ANSWER,
        ERR_KEYS_ANSWER,
        ERR_KEYS_STUCK,
        ERR_KEYS_GAP,
        ERR_KEYS_BELOW,
        ERR_PING_ANSWER,
        ERR_STAMP_ANSWER,
        ERR_LEASE_EXPIRED,
    ];
    let hit = unexpected.iter().find_map(|u| match (u, e) {
        (BridgeError::Invalid(a), BridgeError::Invalid(b)) if a == b => Some(*a),
        _ => None,
    });
    if matches!(e, BridgeError::Invalid(t) if *t == "unit: the stamp call was stale twice") {
        return job_result(Delivery::Ack, "stale", pages);
    }
    match hit {
        Some(text) => {
            pages.push(Page::UnitRefused(text));
            job_result(Delivery::DeadLetter, "unit_refused", pages)
        }
        None => job_result(Delivery::HandBack, code, pages),
    }
}

/// Whether `e` is the raise's [`ERR_ROLLED_BACK`]: the unit is behind its
/// stamp (now recorded).
fn is_rolled_back(e: &BridgeError) -> bool {
    match (e, ERR_ROLLED_BACK) {
        (BridgeError::Invalid(a), BridgeError::Invalid(b)) => *a == b,
        _ => false,
    }
}

fn job_result(delivery: Delivery, code: &'static str, pages: Vec<Page>) -> JobResult {
    JobResult {
        delivery,
        code,
        pages,
    }
}

/// The delivery of a `renew` job from what the renewal came to.
fn renewal_result(renewal: Renewal, pages: Vec<Page>) -> JobResult {
    match renewal {
        Renewal::Renewed { .. } => job_result(Delivery::Ack, "renewed", pages),
        Renewal::Closed { rolled_back: false } => job_result(Delivery::Ack, "closed", pages),
        Renewal::Closed { rolled_back: true } => job_result(Delivery::Ack, "rolled_back", pages),
        Renewal::Unborn => job_result(Delivery::Unborn, "unborn", pages),
        Renewal::NotListed => job_result(Delivery::Ack, "not_listed", pages),
        // Paged; a retry would page again and change nothing. The alarm
        // sends `renew` again on its backoff.
        Renewal::Refused => job_result(Delivery::Ack, "renew_refused", pages),
        Renewal::Shredding => job_result(Delivery::Ack, "shredding", pages),
    }
}

// ---------------------------------------------------------------------------
// The unit's stamp counter, through its job calls
// ---------------------------------------------------------------------------

/// Why a stamp call did not answer: the caller decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// Restoring or provisioning.
    Closed,
    Unborn,
    /// The tenant is shredding or shredded: jobs are refused.
    Shredding,
    /// The unit is behind the numbers it was called with (its own here).
    SyncNeeded(Seqs),
    /// The lease ran out (`stamp_advance` only; the reads are allowed).
    RenewNeeded,
}

enum Step<V> {
    Done(V),
    Stop(Stop),
}

/// The next move of a renewal.
enum Flow {
    /// Prove again at these numbers.
    Again(Seqs),
    Done(Renewal),
}

struct StampRead {
    row: StampRow,
    seqs: Seqs,
    revoked: u64,
}

/// [`StampLedger`] over the unit's job calls (`stamp`, `stamp_advance`,
/// `stamp_rolled_back`), at the unit's numbers: a lower number is taken
/// from the unit's answer and the call sent once more. A call the unit
/// stops is an `Err` with the reason kept in `stop`.
struct UnitLedger<'a, C> {
    client: &'a C,
    seqs: Cell<Seqs>,
    stop: Cell<Option<Stop>>,
}

impl<'a, U, B, T, N, H, K, F> UnitLedger<'a, UnitClient<U, B, T, N, H, K, F>>
where
    U: UnitReplies,
    B: BlobStore,
    T: Clock,
    N: ChainNames,
    H: TenantHeads,
    K: KeyFeed,
    F: KeyFinisher,
{
    fn new(client: &'a UnitClient<U, B, T, N, H, K, F>, seqs: Seqs) -> Self {
        UnitLedger {
            client,
            seqs: Cell::new(seqs),
            stop: Cell::new(None),
        }
    }

    /// The stop a call met, if any: every later call of this ledger
    /// fails at once, so a raise's or a check's rounds make no more calls.
    fn stopped(&self) -> Option<Stop> {
        self.stop.get()
    }

    /// One job call; a stale number is taken from the unit and sent once
    /// more.
    async fn job(&self, call: JobCall) -> Result<Step<(Value, Seqs, Option<u64>)>> {
        for _ in 0..2 {
            let c = self.client.job_call(self.seqs.get(), call.clone());
            let reply = self.client.unit.reply(&c).await?;
            match reply.answer {
                UnitAnswer::Ok { seqs, body } => {
                    self.seqs.set(seqs);
                    return Ok(Step::Done((body, seqs, reply.revoked)));
                }
                UnitAnswer::Stale { seqs } => self.seqs.set(seqs),
                // A job call refused as stale without numbers (before job
                // calls answer `Stale{seqs}`):
                // ask the unit for them.
                UnitAnswer::Refused {
                    reason: Refused::Identity(Refusal::StaleJob),
                    ..
                } => match self.client.unit_seqs().await? {
                    Some(seqs) => self.seqs.set(seqs),
                    None => return Ok(Step::Stop(Stop::Unborn)),
                },
                UnitAnswer::SyncNeeded { seqs } => return Ok(Step::Stop(Stop::SyncNeeded(seqs))),
                UnitAnswer::RenewNeeded { .. } => return Ok(Step::Stop(Stop::RenewNeeded)),
                UnitAnswer::Closed { .. } => return Ok(Step::Stop(Stop::Closed)),
                UnitAnswer::Unborn { .. } => return Ok(Step::Stop(Stop::Unborn)),
                UnitAnswer::Refused {
                    reason: Refused::AccountProblem,
                    ..
                } => return Ok(Step::Stop(Stop::Shredding)),
                UnitAnswer::Failed { class } => return Err(unit_failed(&class)),
                _ => return Err(ERR_STAMP_ANSWER),
            }
        }
        // Stale twice: the unit moved again in between (AM-50: a second
        // `Stale` is acknowledged; the alarm asks again).
        Err(ERR_STAMP_STALE)
    }

    async fn read_stamp(&self, id: &str) -> Result<Step<StampRead>> {
        let call = JobCall::stamp {
            catalogue: id.to_string(),
        };
        Ok(match self.job(call).await? {
            Step::Done((body, seqs, revoked)) => Step::Done(StampRead {
                row: serde_json::from_value(body).map_err(|_| ERR_STAMP_ANSWER)?,
                seqs,
                revoked: revoked.unwrap_or(0),
            }),
            Step::Stop(stop) => Step::Stop(stop),
        })
    }

    /// A job call whose stop is kept for the caller and answered as `Err`.
    async fn value<V: serde::de::DeserializeOwned>(&self, call: JobCall) -> Result<V> {
        if self.stop.get().is_some() {
            return Err(ERR_STOPPED);
        }
        match self.job(call).await? {
            Step::Done((body, ..)) => serde_json::from_value(body).map_err(|_| ERR_STAMP_ANSWER),
            Step::Stop(stop) => {
                self.stop.set(Some(stop));
                Err(ERR_STOPPED)
            }
        }
    }
}

impl<U, B, T, N, H, K, F> StampLedger for &UnitLedger<'_, UnitClient<U, B, T, N, H, K, F>>
where
    U: UnitReplies,
    B: BlobStore,
    T: Clock,
    N: ChainNames,
    H: TenantHeads,
    K: KeyFeed,
    F: KeyFinisher,
{
    async fn stamp(&self, id: &str) -> Result<StampRow> {
        self.value(JobCall::stamp {
            catalogue: id.to_string(),
        })
        .await
    }

    async fn stamp_advance(&self, from: Option<u64>, id: &str) -> Result<bool> {
        self.value(JobCall::stamp_advance {
            from,
            catalogue: id.to_string(),
        })
        .await
    }

    async fn stamp_rolled_back(&self, seen: Option<u64>, now: UnixMs, id: &str) -> Result<bool> {
        self.value(JobCall::stamp_rolled_back {
            seen,
            now,
            catalogue: id.to_string(),
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

/// L3's reader is the port: the head's door part.
impl<S: RecordStore, C: ControlSeal> TenantHeads for TenantChain<'_, S, C> {
    async fn head(
        &self,
        tenant: &TenantId,
        known: u64,
    ) -> std::result::Result<Option<TenantDoor>, ChainError> {
        let t = Tenant::parse(tenant.as_str()).ok_or(ChainError::Damaged("not_a_tenant_id"))?;
        Ok(TenantChain::head(self, &t, known).await?.map(|r| r.door))
    }
}

impl<T: TenantHeads> TenantHeads for &T {
    async fn head(
        &self,
        tenant: &TenantId,
        known: u64,
    ) -> std::result::Result<Option<TenantDoor>, ChainError> {
        (**self).head(tenant, known).await
    }
}

impl<T: KeyFeed> KeyFeed for &T {
    async fn after(&self, tenant: &TenantId, after: u64) -> Result<KeyBatch> {
        (**self).after(tenant, after).await
    }
}

impl<T: KeyFinisher> KeyFinisher for &T {
    async fn revocations_unrecorded(&self, tenant: &TenantId) -> Result<()> {
        (**self).revocations_unrecorded(tenant).await
    }
}

/// The names of the chains as their writers lay them out: L3's tenant
/// chain ([`crate::directory::chain::record_key`]), L4's key chain
/// ([`crate::keys::record::key_chain`]) and the tenant's revocations
/// ([`crate::keys::revocations::tenant_revocation_prefix`]). A name that
/// is not a managed tenant id gets a name no record has: the HEADs answer
/// `404`, and the revocation list refuses the directory.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecordNames;

const NO_TENANT: &str = "-";

impl ChainNames for RecordNames {
    fn tenant_record(&self, tenant: &str, seq: u64) -> String {
        match Tenant::parse(tenant) {
            Some(t) => record_key(&t, seq),
            None => format!("m/t/{NO_TENANT}/{seq}"),
        }
    }

    fn key_record(&self, tenant: &str, seq: u64) -> String {
        match KeyTenant::parse(tenant) {
            Ok(t) => key_chain(&t).name(seq),
            Err(_) => format!("m/k/{NO_TENANT}/{seq}"),
        }
    }

    fn revocation_dir(&self, tenant: &str) -> String {
        match KeyTenant::parse(tenant) {
            Ok(t) => tenant_revocation_prefix(&t),
            Err(_) => format!("m/rk/{NO_TENANT}/"),
        }
    }
}

/// The renewals in flight in one isolate, by unit, and the failed
/// attempts of each: a second renewal of a unit is not started while one
/// runs, and [`InFlight::attempt`] spaces the attempts after a failure
/// (a backoff from [`AlarmRules::renew_retry_ms`] that doubles up to T).
/// A success clears it. Cheap to clone; one per isolate.
#[derive(Clone, Debug, Default)]
pub struct InFlight(Rc<RefCell<Flights>>);

#[derive(Debug, Default)]
struct Flights {
    running: BTreeSet<String>,
    /// Per unit: the time of the last failed attempt, and how many failed
    /// in a row.
    failed: BTreeMap<String, (UnixMs, u32)>,
}

/// Held while one renewal runs. [`InFlightGuard::done`] says how it
/// ended; dropped without it, it counts as failed.
#[derive(Debug)]
pub struct InFlightGuard {
    set: Rc<RefCell<Flights>>,
    name: String,
    /// Spaced attempts record their outcome; `begin`'s do not.
    spaced: Option<UnixMs>,
    ended: bool,
}

/// Units whose failed attempts are remembered, at most: an isolate serves
/// far fewer; past it the oldest are forgotten.
const MAX_REMEMBERED: usize = 4096;

impl InFlight {
    /// Starts a renewal of `name`, or `None` when one is running.
    pub fn begin(&self, name: &UnitName) -> Option<InFlightGuard> {
        self.start(name, None, 0)
    }

    /// Starts a renewal attempt of `name` at `now`, or `None` when one is
    /// running, or when the last attempt failed less than the backoff for
    /// its failures in a row ago (60 s doubling, at most `max_gap_ms`).
    pub fn attempt(&self, name: &UnitName, now: UnixMs, max_gap_ms: i64) -> Option<InFlightGuard> {
        self.start(name, Some(now), max_gap_ms)
    }

    fn start(
        &self,
        name: &UnitName,
        spaced: Option<UnixMs>,
        max_gap: i64,
    ) -> Option<InFlightGuard> {
        let key = name.object_name();
        let mut f = self.0.borrow_mut();
        if f.running.contains(&key) {
            return None;
        }
        if let (Some(now), Some((at, fails))) = (spaced, f.failed.get(&key)) {
            let gap = renew_retry_ms(fails.saturating_sub(1), &AlarmRules::DEFAULT).min(max_gap);
            if now.0 < at.0.saturating_add(gap) {
                return None;
            }
        }
        f.running.insert(key.clone());
        Some(InFlightGuard {
            set: self.0.clone(),
            name: key,
            spaced,
            ended: false,
        })
    }
}

impl InFlightGuard {
    /// The attempt ended: renewed (`ok`), or not.
    pub fn done(mut self, ok: bool) {
        self.end(ok);
    }

    fn end(&mut self, ok: bool) {
        if self.ended {
            return;
        }
        self.ended = true;
        let mut f = self.set.borrow_mut();
        f.running.remove(&self.name);
        let Some(now) = self.spaced else {
            return;
        };
        if ok {
            f.failed.remove(&self.name);
            return;
        }
        if f.failed.len() >= MAX_REMEMBERED && !f.failed.contains_key(&self.name) {
            if let Some(oldest) = f
                .failed
                .iter()
                .min_by_key(|(_, (at, _))| at.0)
                .map(|(k, _)| k.clone())
            {
                f.failed.remove(&oldest);
            }
        }
        let fails = f.failed.get(&self.name).map_or(0, |(_, n)| *n);
        f.failed
            .insert(self.name.clone(), (now, fails.saturating_add(1)));
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.end(false);
    }
}
