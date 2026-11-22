//! The caller of a store's key-chain apply, `apply(from_seq, entries)`
//! (ADR §2.4 rule 5 with AM-12).
//!
//! A store (a unit, or the directory) takes the chain as **one entry per
//! record**, in chain order, after an exclusive base `from_seq`:
//!
//! - the entries run without a gap from `from_seq + 1`, at most
//!   [`MAX_APPLY`] per call;
//! - a base above the store's own `keys_seq` is answered
//!   [`Applied::Behind`] with the store's number, and the caller reads
//!   again from there;
//! - the store compares each entry, per subject, with its row's
//!   `last_seq` and skips one at or below it, except a revoke and an
//!   entry that opens, at the same seq, a row it holds closed.
//!
//! So a bring-up sends the records after the store's `keys_seq` up to the
//! head, page by page. **Every entry states the subject as the head table
//! holds it**, at the seq of the record it stands for: for a subject's
//! newest record that is that record's state exactly; for an older one it
//! is the head's state sent early. A store that stops between two pages
//! therefore never serves a subject other than as the head does (a disable
//! answered `Done` is never undone there, and a subject the head holds
//! open is not closed in between), and the closing step's hold rule, which
//! reads the head's newest opening, holds every entry the directory may
//! not have.
//!
//! Before the pages, every `m/rk/` revocation the chain does not record
//! yet whose subject's newest record the store already holds is sent alone
//! at that seq. One whose newest record is above the store's seq comes in
//! the pages, with the revocation in force; a store that a page cannot
//! reach gets it from the renewal's revocation check (ADR §2.4 rule 12). After the pages, every subject the store
//! holds closed whose private part now opens is sent again (the
//! bring-up's second send): alone at its own seq, or, when that takes
//! fewer calls, as one run of the records from the lowest such seq.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::chain::Chain;
use super::ports::{Applied, ApplyEntry, KeyTarget, MAX_APPLY};
use super::record::{
    key_chain, open_chain_record, ChainRecord, Entry, KeyTable, Marker, Rid, SubjectStatus, TkRing,
    ERR_KEY_RECORD,
};

use crate::ports::Kek;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};

/// Bring-ups of one store that may meet a `Behind` (the store was
/// restored between its `keys_seq` and the apply) before the call fails.
pub const MAX_BEHIND: u32 = 3;

/// What a feed keeps of each record it read: the subject it names, or the
/// marker it is. A few bytes per seq, so one run reads each record at most once
/// whatever the stores' lag (a store far behind costs one GET per record
/// it lacks, once).
#[derive(Clone, Debug)]
enum Slot {
    /// The subject's id, and the `rid` the record carries.
    Subject(String, Option<Rid>),
    Marker(Marker),
}

/// The store kept answering `Behind`.
pub const ERR_APPLY_BEHIND: BridgeError =
    BridgeError::Invalid("the key store kept falling behind the apply");

/// How a bring-up holds what opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Before the directory acknowledged the head: an entry whose newest
    /// opening is above `acked` is sent closed (held), unless the store
    /// already holds that opening open at or below its own seq.
    Closing { acked: u64 },
    /// Everything as the chain has it, and every subject the store holds
    /// closed that now opens is sent again.
    Full,
}

/// The records of one key chain as a store takes them, with the head
/// table and the `m/rk/` revocations in force.
pub struct Feed<'a, S, K, T> {
    store: &'a S,
    kek: &'a K,
    ring: &'a T,
    chain: Chain,
    table: &'a KeyTable,
    revoked: &'a BTreeSet<String>,
    memo: RefCell<BTreeMap<u64, Slot>>,
}

impl<'a, S: RecordStore, K: Kek, T: TkRing> Feed<'a, S, K, T> {
    pub fn new(
        store: &'a S,
        kek: &'a K,
        ring: &'a T,
        table: &'a KeyTable,
        revoked: &'a BTreeSet<String>,
    ) -> Self {
        Feed {
            store,
            kek,
            ring,
            chain: key_chain(table.tenant()),
            table,
            revoked,
            memo: RefCell::new(BTreeMap::new()),
        }
    }

    async fn slot(&self, seq: u64) -> Result<Slot> {
        if let Some(r) = self.memo.borrow().get(&seq) {
            return Ok(r.clone());
        }
        let bytes = self.chain.get(self.store, seq).await?;
        let slot = match open_chain_record(self.kek, self.ring, self.table.tenant(), seq, &bytes)? {
            ChainRecord::Key(r) => Slot::Subject(r.door.id, r.rid),
            ChainRecord::Marker(m) => Slot::Marker(m.marker),
        };
        self.memo.borrow_mut().insert(seq, slot.clone());
        Ok(slot)
    }

    /// How many of the records `(from, to]` this feed has not read yet.
    fn unread(&self, from: u64, to: u64) -> u64 {
        let memo = self.memo.borrow();
        (to - from) - memo.range(from + 1..=to).count() as u64
    }

    /// An entry with the `m/rk/` revocations in force.
    fn in_force(&self, mut e: Entry) -> Entry {
        if self.revoked.contains(&e.door.id) {
            e.door.status = SubjectStatus::Revoked;
        }
        e
    }

    /// The entries of the records `(from, to]`: each the head's entry of
    /// its subject, at the record's seq.
    async fn page(&self, from: u64, to: u64) -> Result<Vec<ApplyEntry>> {
        let mut out = Vec::with_capacity((to - from) as usize);
        for seq in from + 1..=to {
            let (id, rid) = match self.slot(seq).await? {
                Slot::Marker(marker) => {
                    out.push(ApplyEntry::Marker { seq, marker });
                    continue;
                }
                Slot::Subject(id, rid) => (id, rid),
            };
            let head = self.table.get(&id).ok_or(ERR_KEY_RECORD)?;
            let mut entry = head.clone();
            entry.last_seq = seq;
            // The reservation is the record's, not the head's newest.
            entry.rid = rid;
            out.push(ApplyEntry::Subject(self.in_force(entry)));
        }
        Ok(out)
    }

    /// Holds closed, in `mode`, an entry whose opening the directory may
    /// not have: the rule of the closing step.
    fn hold(mode: Mode, held: u64, closed: &BTreeSet<String>, entry: &mut ApplyEntry) {
        hold_rule(mode, held, closed, entry);
    }

    /// The `m/rk/` revocations the chain does not record yet, at or below
    /// `held` (the others are in the pages).
    fn unrecorded(&self, held: u64) -> Vec<Entry> {
        self.table
            .entries()
            .filter(|e| e.last_seq <= held)
            .filter(|e| {
                self.revoked.contains(&e.door.id) && e.door.status != SubjectStatus::Revoked
            })
            .map(|e| self.in_force(e.clone()))
            .collect()
    }

    /// The subjects the store holds closed that now open, at or below
    /// `held` (the second send).
    fn reopened(&self, held: u64, closed: &BTreeSet<String>) -> Vec<Entry> {
        self.table
            .entries()
            .filter(|e| {
                e.last_seq <= held
                    && closed.contains(&e.door.id)
                    && e.private.is_some()
                    && e.door.status != SubjectStatus::Revoked
            })
            .map(|e| self.in_force(e.clone()))
            .collect()
    }

    /// Sends `entries` alone, each at its own seq. `false`: `Behind`.
    async fn singly<U: KeyTarget>(&self, target: &U, entries: Vec<Entry>) -> Result<bool> {
        for e in entries {
            let base = e.last_seq - 1;
            if let Applied::Behind { .. } = target.apply(base, &[ApplyEntry::Subject(e)]).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Sends the records `(from, to]` page by page, held closed in `mode`.
    /// `false`: `Behind`.
    async fn run<U: KeyTarget>(
        &self,
        target: &U,
        mode: Mode,
        held: u64,
        closed: &BTreeSet<String>,
        mut from: u64,
        to: u64,
    ) -> Result<bool> {
        while from < to {
            let end = to.min(from + MAX_APPLY as u64);
            let mut entries = self.page(from, end).await?;
            for e in &mut entries {
                Self::hold(mode, held, closed, e);
            }
            if let Applied::Behind { .. } = target.apply(from, &entries).await? {
                return Ok(false);
            }
            from = end;
        }
        Ok(true)
    }

    /// One pass: the unrecorded revocations, the pages after the store's
    /// `keys_seq`, then (in [`Mode::Full`]) the second send. `false`: the
    /// store answered `Behind`.
    async fn pass<U: KeyTarget>(&self, target: &U, mode: Mode) -> Result<bool> {
        let held = target.keys_seq().await?;
        let closed: BTreeSet<String> = target.closed().await?.into_iter().collect();
        if !self.singly(target, self.unrecorded(held)).await? {
            return Ok(false);
        }
        if !self
            .run(target, mode, held, &closed, held, self.table.seq())
            .await?
        {
            return Ok(false);
        }
        if mode != Mode::Full {
            return Ok(true);
        }
        let reopened = self.reopened(held, &closed);
        let Some(lowest) = reopened.iter().map(|e| e.last_seq).min() else {
            return Ok(true);
        };
        // One run from the lowest such seq to the table's head (never
        // past it: a store may be ahead) takes ceil(span / 100) calls; the
        // store skips every other entry at or below its rows. It also
        // reads the span's records this feed has not read yet, so it is
        // taken only when calls plus those reads cost less than one call
        // per subject.
        let top = held.min(self.table.seq());
        let Some(span) = top.checked_sub(lowest - 1) else {
            return self.singly(target, reopened).await;
        };
        let cost = span.div_ceil(MAX_APPLY as u64) + self.unread(lowest - 1, top);
        if cost < reopened.len() as u64 {
            self.run(target, Mode::Full, held, &closed, lowest - 1, top)
                .await
        } else {
            self.singly(target, reopened).await
        }
    }

    /// The verified items of the records after `after`, in chain order,
    /// at most `limit` (and at most [`MAX_APPLY`]), never past the table's
    /// head, with no gap: one per record, a subject's entry as the head
    /// holds it, stamped at the record's seq, with the `m/rk/` revocations
    /// in force, or a [`ApplyEntry::Marker`] in place for a `KeysFrozen` or
    /// `KeysThawed` record (AM-62). Nothing is held: an entry whose private
    /// part does not open comes with `private: None`, and the caller sends
    /// it held or refuses it. Empty when `after` is at or above the head,
    /// or `limit` is 0. A record that is missing or does not verify is an
    /// error, never left out.
    ///
    /// This is the read behind the move tool's `OwnerKeys::entries`
    /// (step 5(e)'s direct apply, the undo's `entries_to`): the items map
    /// one to one onto the unit's `ApplyEntry`.
    pub async fn entries(&self, after: u64, limit: usize) -> Result<Vec<ApplyEntry>> {
        let head = self.table.seq();
        if after >= head || limit == 0 {
            return Ok(Vec::new());
        }
        let take = limit.min(MAX_APPLY) as u64;
        self.page(after, head.min(after.saturating_add(take))).await
    }

    /// Brings `target` to the head in `mode`. A store that answers
    /// `Behind` is read again and brought up from its own seq, at most
    /// [`MAX_BEHIND`] times.
    pub async fn bring_up<U: KeyTarget>(&self, target: &U, mode: Mode) -> Result<()> {
        for _ in 0..MAX_BEHIND {
            if self.pass(target, mode).await? {
                return Ok(());
            }
        }
        Err(ERR_APPLY_BEHIND)
    }
}

/// The rule of the closing step ([`Feed::bring_up`]): in
/// [`Mode::Closing`], an entry whose opening the directory has not
/// acknowledged (above `acked`) is held, unless the store holds that
/// opening open already (at or below `held`, and not in `closed`).
fn hold_rule(mode: Mode, held: u64, closed: &BTreeSet<String>, entry: &mut ApplyEntry) {
    let (Mode::Closing { acked }, ApplyEntry::Subject(e)) = (mode, entry) else {
        return;
    };
    let acknowledged =
        e.opened_seq <= acked || (e.opened_seq <= held && !closed.contains(&e.door.id));
    if !acknowledged && e.door.status != SubjectStatus::Revoked {
        e.private = None;
    }
}

/// The closing step's hold for a reader that sends [`Feed::entries`]
/// without the store's closed set (the unit client's `sync`, through the
/// composition root's key feed): as [`Feed::bring_up`]'s rule with no
/// subject counted as held open by the store, so an opening the directory
/// has not acknowledged is never sent open. A subject the store already
/// holds open is then sent held until the directory acknowledges it; it
/// cannot be one the directory has not, since the store got it open only
/// from a full send after the directory's acknowledgement.
pub fn hold_unacknowledged(mode: Mode, entry: &mut ApplyEntry) {
    hold_rule(mode, 0, &BTreeSet::new(), entry);
}

/// The move's direct apply (AM-16): `target` gets `table`'s chain in full
/// with nothing held, without the directory step. Only the move tool
/// calls it, for the unit it fills in the window.
pub async fn apply_direct<S: RecordStore, K: Kek, T: TkRing, U: KeyTarget>(
    store: &S,
    kek: &K,
    ring: &T,
    table: &KeyTable,
    revoked: &BTreeSet<String>,
    target: &U,
) -> Result<()> {
    Feed::new(store, kek, ring, table, revoked)
        .bring_up(target, Mode::Full)
        .await
}
