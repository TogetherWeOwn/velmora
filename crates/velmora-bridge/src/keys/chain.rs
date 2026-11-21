//! A put-once chain of records: `<prefix><seq>`, seq 1, 2, 3, … with no
//! gap.
//!
//! The chain is the arbiter: a writer reads the head,
//! validates its change against that record, and writes exactly the next
//! seq with a put that succeeds only if the name is free. Two writers can
//! therefore never both write seq n; the loser reads the head again and
//! validates again. A seq is twenty decimal digits, so name order is seq
//! order and a reader finds the head by listing after the last seq it
//! knows, never by walking from seq 1.
//!
//! The key chain `m/k/<t>/` uses this module. The tenant chain `m/t/<t>/`
//! and the key-location chain `m/kl/` have the same shape and can use it
//! too.

use super::store::RecordStore;
use crate::types::{BridgeError, Result};

/// Digits of a seq in a record name.
pub const SEQ_DIGITS: usize = 20;
/// Names per list call.
pub const LIST_PAGE: u32 = 1000;

/// A chain has a gap, or a name under its prefix that is no seq. Records
/// are put once and never deleted outside a purge, so this is damage or a
/// planted name: the reader stops and alarms, it never skips.
pub const ERR_CHAIN_GAP: BridgeError = BridgeError::Invalid("record chain has a gap");
/// The caller's floor names a seq the chain does not hold: the chain is
/// behind what someone saw (a rollback or a loss).
pub const ERR_CHAIN_BEHIND: BridgeError =
    BridgeError::Invalid("record chain is behind the known seq");

/// The name of seq `seq` under `prefix`.
pub fn seq_name(prefix: &str, seq: u64) -> String {
    format!("{prefix}{seq:0width$}", width = SEQ_DIGITS)
}

/// The seq a name under `prefix` stands for; `None` for any other name.
pub fn parse_seq(prefix: &str, name: &str) -> Option<u64> {
    let digits = name.strip_prefix(prefix)?;
    if digits.len() != SEQ_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seq: u64 = digits.parse().ok()?;
    (seq > 0).then_some(seq)
}

/// The outcome of a put of the next seq.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Put {
    /// This writer's bytes are stored at the seq.
    Written,
    /// Another writer's record holds the seq. Read the head and
    /// validate again.
    Lost,
}

/// One chain: every record whose name is `prefix` plus a seq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    prefix: String,
}

impl Chain {
    /// `prefix` ends with `/`.
    pub fn new(prefix: String) -> Chain {
        debug_assert!(prefix.ends_with('/'));
        Chain { prefix }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn name(&self, seq: u64) -> String {
        seq_name(&self.prefix, seq)
    }

    /// The highest seq, found by listing after `known` (0 = from the
    /// start). Refuses a chain that is behind `known`, has a gap or holds
    /// a foreign name.
    pub async fn head<S: RecordStore>(&self, store: &S, known: u64) -> Result<u64> {
        let mut head = known;
        let mut after = if known == 0 {
            self.prefix.clone()
        } else {
            if !store.exists(&self.name(known)).await? {
                return Err(ERR_CHAIN_BEHIND);
            }
            self.name(known)
        };
        loop {
            let names = store.list(&self.prefix, &after, LIST_PAGE).await?;
            for name in &names {
                match parse_seq(&self.prefix, name) {
                    Some(seq) if seq == head + 1 => head = seq,
                    _ => return Err(ERR_CHAIN_GAP),
                }
            }
            match names.last() {
                Some(last) if names.len() >= LIST_PAGE as usize => after.clone_from(last),
                _ => return Ok(head),
            }
        }
    }

    /// Puts `bytes` at `seq` if the seq is free. A put whose answer was
    /// lost is read back: the same bytes mean it was this writer's.
    pub async fn put<S: RecordStore>(&self, store: &S, seq: u64, bytes: Vec<u8>) -> Result<Put> {
        let name = self.name(seq);
        match store.put_if_absent(&name, bytes.clone()).await {
            Ok(true) => Ok(Put::Written),
            // Also a retry of a put that was ours: the nonces of a seal
            // are random, so equal bytes are the same write.
            Ok(false) => Ok(match store.get(&name).await? {
                Some(stored) if stored == bytes => Put::Written,
                _ => Put::Lost,
            }),
            Err(e) => match store.get(&name).await? {
                Some(stored) if stored == bytes => Ok(Put::Written),
                Some(_) => Ok(Put::Lost),
                None => Err(e),
            },
        }
    }

    /// The bytes of seq `seq`; an error when it is absent.
    pub async fn get<S: RecordStore>(&self, store: &S, seq: u64) -> Result<Vec<u8>> {
        store.get(&self.name(seq)).await?.ok_or(ERR_CHAIN_GAP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_sort_as_seqs() {
        let c = Chain::new("m/k/t_00000000000000a1/".into());
        assert_eq!(c.name(1), "m/k/t_00000000000000a1/00000000000000000001");
        assert!(c.name(9) < c.name(10));
        assert!(c.name(999) < c.name(1000));
        assert_eq!(parse_seq(c.prefix(), &c.name(42)), Some(42));
        assert_eq!(parse_seq(c.prefix(), &c.name(u64::MAX)), Some(u64::MAX));
        assert_eq!(parse_seq(c.prefix(), &c.name(0)), None);
        assert_eq!(parse_seq(c.prefix(), "m/k/t_00000000000000a1/1"), None);
        assert_eq!(
            parse_seq(c.prefix(), "m/k/t_00000000000000a1/0000000000000000000x"),
            None
        );
        assert_eq!(parse_seq("m/k/other/", &c.name(1)), None);
    }
}
