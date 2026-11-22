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
//! head, page by page, each record as the subject's state right after it.
//! A store that stops between two pages holds the chain exactly as of the
//! last page it took. Two kinds of entry are then sent again, alone, at
//! their own seq: a subject the store holds closed whose private part now
//! opens (the bring-up's second send), and a subject whose `m/rk/`
//! revocation the chain does not record yet.
//!
//! The entry of a record is the subject's state after that record. For a
//! subject's newest record it is the head table's entry, exactly. For an
//! older one it is built from the record: its private part is the
//! record's own, and when the record carries none (a close whose writer
//! could not open it) or it does not open now, the entry is sent closed,
//! which is what that record did anyway. Its newest opening at or below
//! the record is known when it lies in the range sent; otherwise it is at
//! or below the store's `keys_seq`, and that bound is used, which only
//! ever holds more closed.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::chain::Chain;
use super::ports::{Applied, ApplyEntry, KeyTarget, MAX_APPLY};
use super::record::{
    key_chain, open_chain_record, ChainRecord, Entry, KeyOp, KeyTable, SubjectStatus, TkRing,
    ERR_KEY_RECORD,
};
use crate::ports::Kek;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};

/// Bring-ups of one store that may meet a `Behind` (the store was
/// restored between its `keys_seq` and the apply) before the call fails.
pub const MAX_BEHIND: u32 = 3;

/// Records kept in memory by one feed: the stores of one change are
/// brought up three times from the same few records.
const MEMO_RECORDS: usize = 256;

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
    memo: RefCell<BTreeMap<u64, ChainRecord>>,
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

    async fn record(&self, seq: u64) -> Result<ChainRecord> {
        if let Some(r) = self.memo.borrow().get(&seq) {
            return Ok(r.clone());
        }
        let bytes = self.chain.get(self.store, seq).await?;
        let record = open_chain_record(self.kek, self.ring, self.table.tenant(), seq, &bytes)?;
        let mut memo = self.memo.borrow_mut();
        if memo.len() < MEMO_RECORDS {
            memo.insert(seq, record.clone());
        }
        Ok(record)
    }

    /// An entry with the `m/rk/` revocations in force.
    fn in_force(&self, mut e: Entry) -> Entry {
        if self.revoked.contains(&e.door.id) {
            e.door.status = SubjectStatus::Revoked;
        }
        e
    }

    /// The entries of the records `(from, to]`, for a pass whose range
    /// starts at `base`. `opened` carries, per subject seen in the pass,
    /// its newest opening so far (or `base`, a bound).
    async fn page(
        &self,
        base: u64,
        from: u64,
        to: u64,
        opened: &mut BTreeMap<String, u64>,
    ) -> Result<Vec<ApplyEntry>> {
        let mut out = Vec::with_capacity((to - from) as usize);
        for seq in from + 1..=to {
            let r = match self.record(seq).await? {
                ChainRecord::Marker(m) => {
                    out.push(ApplyEntry::Marker { seq: m.seq });
                    continue;
                }
                ChainRecord::Key(r) => r,
            };
            let head = self.table.get(&r.door.id).ok_or(ERR_KEY_RECORD)?;
            // Before its first record in the range, a subject's newest
            // opening is exact when the head's is at or below the base,
            // and at or below the base otherwise.
            let bound = opened
                .entry(r.door.id.clone())
                .or_insert(match head.opened_seq <= base {
                    true => head.opened_seq,
                    false => base,
                });
            if !r.closes && r.op != KeyOp::Restate {
                *bound = r.seq;
            }
            let entry = match head.last_seq == r.seq {
                true => head.clone(),
                false => Entry {
                    door: r.door,
                    private: r.private,
                    last_seq: r.seq,
                    private_seq: r.seq,
                    tk_version: r.tk_version,
                    closes: r.closes,
                    opened_seq: *bound,
                },
            };
            out.push(ApplyEntry::Subject(self.in_force(entry)));
        }
        Ok(out)
    }

    /// Holds closed, in `mode`, an entry whose opening the directory may
    /// not have: the rule of the closing step.
    fn hold(mode: Mode, held: u64, closed: &BTreeSet<String>, entry: &mut ApplyEntry) {
        let (Mode::Closing { acked }, ApplyEntry::Subject(e)) = (mode, entry) else {
            return;
        };
        let acknowledged =
            e.opened_seq <= acked || (e.opened_seq <= held && !closed.contains(&e.door.id));
        if !acknowledged && e.door.status != SubjectStatus::Revoked {
            e.private = None;
        }
    }

    /// The entries sent again, alone, at their own seq: a revocation the
    /// chain does not record yet, and (in [`Mode::Full`]) a subject the
    /// store holds closed that now opens. Only those at or below `held`;
    /// the others are in the pages.
    fn resends(&self, mode: Mode, held: u64, closed: &BTreeSet<String>) -> Vec<Entry> {
        self.table
            .entries()
            .filter(|e| e.last_seq <= held)
            .filter(|e| {
                let unrecorded =
                    self.revoked.contains(&e.door.id) && e.door.status != SubjectStatus::Revoked;
                let reopens = mode == Mode::Full
                    && closed.contains(&e.door.id)
                    && e.private.is_some()
                    && e.door.status != SubjectStatus::Revoked;
                unrecorded || reopens
            })
            .map(|e| self.in_force(e.clone()))
            .collect()
    }

    /// One pass: the pages after the store's `keys_seq`, then the
    /// resends. `false`: the store answered `Behind`.
    async fn pass<U: KeyTarget>(&self, target: &U, mode: Mode) -> Result<bool> {
        let held = target.keys_seq().await?;
        let closed: BTreeSet<String> = target.closed().await?.into_iter().collect();
        let to = self.table.seq();
        let mut opened = BTreeMap::new();
        let mut from = held;
        while from < to {
            let end = to.min(from + MAX_APPLY as u64);
            let mut entries = self.page(held, from, end, &mut opened).await?;
            for e in &mut entries {
                Self::hold(mode, held, &closed, e);
            }
            if let Applied::Behind { .. } = target.apply(from, &entries).await? {
                return Ok(false);
            }
            from = end;
        }
        for e in self.resends(mode, held, &closed) {
            let base = e.last_seq - 1;
            if let Applied::Behind { .. } = target.apply(base, &[ApplyEntry::Subject(e)]).await? {
                return Ok(false);
            }
        }
        Ok(true)
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
