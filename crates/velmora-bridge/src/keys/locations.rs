//! The closed set of key locations, `m/kl/<seq>`.
//!
//! A tenant key may be stored only in a location this set names, and
//! every location that ever held one stays in it. Each record of the
//! chain is the **whole** set with its statuses, put once at exactly the
//! next seq under the control key, with a door part only (it is global).
//! Every writer, loader and audit reads the head of this chain, never a
//! configuration value alone.
//!
//! Rules a set must keep:
//! - exactly one location is the **arbiter**: it is `active` and
//!   synchronous, and a new key version is created there and nowhere
//!   else;
//! - names are unique, and a name, once in the set, never leaves it;
//! - a status only moves forward: `proposed` → `active` → `retired`, and
//!   any of them → `lost`; nothing comes back from `retired` or `lost`;
//! - the arbiter cannot be `lost` and cannot change by a plain status
//!   change (a new arbiter is a bucket move, which is not built).

use serde::{Deserialize, Serialize};
use velmora::rng::FillRandom;

use super::chain::{Chain, Put};
use crate::config::MAX_KEK_VERSION;
use crate::crypto::scheme2::{parse_control, seal_control, ControlOwner, ControlSealer};
use crate::ports::Kek;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};

/// The chain of key-location sets.
pub fn locations_chain() -> Chain {
    Chain::new("m/kl/".to_owned())
}

const ERR_LOCATIONS: BridgeError = BridgeError::Invalid("key location set is invalid");
const ERR_LOCATIONS_MOVE: BridgeError =
    BridgeError::Invalid("key location set does not follow its head");

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LocationStatus {
    /// Holds nothing; no writer touches it.
    Proposed,
    /// Written, read, listed by the audit and by every shred.
    Active,
    /// Emptied and verified empty; never written again.
    Retired,
    /// Unreachable for good, by an operator's decision; never touched.
    Lost,
}

/// One location of the set.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyLocation {
    /// The binding name of the bucket (`KEYS_A`, `KEYS_B`).
    pub name: String,
    pub status: LocationStatus,
    /// Whether a new key version is created here and only here.
    pub arbiter: bool,
    /// Whether a new key version waits for its copy here (`true`), or is
    /// copied here after its commit by the repair job (`false`).
    pub synchronous: bool,
}

/// The whole set as one record states it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyLocations {
    pub v: u32,
    pub seq: u64,
    pub locations: Vec<KeyLocation>,
}

impl KeyLocations {
    /// The arbiter.
    pub fn arbiter(&self) -> &KeyLocation {
        // `check` holds that there is exactly one.
        self.locations
            .iter()
            .find(|l| l.arbiter)
            .expect("a checked set has an arbiter")
    }

    /// Every `active` location, the arbiter first.
    pub fn active(&self) -> Vec<&KeyLocation> {
        let mut out: Vec<&KeyLocation> = self
            .locations
            .iter()
            .filter(|l| l.status == LocationStatus::Active)
            .collect();
        out.sort_by_key(|l| !l.arbiter);
        out
    }

    /// Every `active` synchronous location, the arbiter first: where a
    /// key is read on the request path and where a writer checks for a
    /// marker. An asynchronous location (an escrow) is in neither.
    pub fn synchronous(&self) -> Vec<&KeyLocation> {
        self.active()
            .into_iter()
            .filter(|l| l.synchronous)
            .collect()
    }

    /// Every `active` synchronous location but the arbiter: where a new
    /// key version is copied before its commit.
    pub fn synchronous_copies(&self) -> Vec<&KeyLocation> {
        self.active()
            .into_iter()
            .filter(|l| !l.arbiter && l.synchronous)
            .collect()
    }

    /// The rules of one set on its own.
    pub fn check(&self) -> Result<()> {
        let arbiters: Vec<&KeyLocation> = self.locations.iter().filter(|l| l.arbiter).collect();
        let names_ok = self.locations.iter().enumerate().all(|(i, l)| {
            !l.name.is_empty()
                && l.name.len() <= 64
                && l.name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                && !self.locations[..i].iter().any(|m| m.name == l.name)
        });
        let arbiter_ok = arbiters.len() == 1
            && arbiters[0].status == LocationStatus::Active
            && arbiters[0].synchronous;
        if self.v != 1 || self.seq == 0 || !names_ok || !arbiter_ok {
            return Err(ERR_LOCATIONS);
        }
        Ok(())
    }

    /// Whether `next` may follow `self` as the next record.
    pub fn admits(&self, next: &KeyLocations) -> Result<()> {
        next.check()?;
        if next.seq != self.seq + 1 {
            return Err(ERR_LOCATIONS_MOVE);
        }
        for old in &self.locations {
            let Some(new) = next.locations.iter().find(|l| l.name == old.name) else {
                return Err(ERR_LOCATIONS_MOVE);
            };
            let forward = match (old.status, new.status) {
                (a, b) if a == b => true,
                (LocationStatus::Proposed, LocationStatus::Active) => true,
                (LocationStatus::Active, LocationStatus::Retired) => !old.arbiter,
                // A lost location that comes back is emptied, verified
                // empty and retired; it is never used again.
                (LocationStatus::Lost, LocationStatus::Retired) => true,
                (LocationStatus::Lost, _) => false,
                // A retired location that becomes unreachable is lost.
                (_, LocationStatus::Lost) => !old.arbiter,
                (LocationStatus::Retired, _) => false,
                _ => false,
            };
            if !forward || new.arbiter != old.arbiter || new.synchronous != old.synchronous {
                return Err(ERR_LOCATIONS_MOVE);
            }
        }
        // A location added later starts as `proposed`.
        let added_ok = next
            .locations
            .iter()
            .filter(|l| !self.locations.iter().any(|o| o.name == l.name))
            .all(|l| l.status == LocationStatus::Proposed && !l.arbiter);
        if !added_ok {
            return Err(ERR_LOCATIONS_MOVE);
        }
        Ok(())
    }
}

fn seal<K: Kek, R: FillRandom>(kek: &K, set: &KeyLocations, rng: &mut R) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(set).map_err(|_| ERR_LOCATIONS)?;
    seal_control(
        kek,
        &locations_chain().name(set.seq),
        &ControlSealer::Global,
        &body,
        None,
        rng,
    )
}

/// A key-location record sealed under a KEK version this Worker does not
/// hold yet: newer than its active one, and one a deploy can have
/// (`config::MAX_KEK_VERSION`). A record of a newer deploy during a KEK
/// rollout: a failure that may pass (`503`, no damage page). Not a
/// `Crypto` error, so callers tell it from damage ([`is_kek_not_held`]).
pub const ERR_LOCATIONS_KEK_NOT_HELD: BridgeError = BridgeError::Invalid(KEK_NOT_HELD);

const KEK_NOT_HELD: &str = "key location record is under a KEK version not held yet";

/// Whether `e`, from [`read_locations`] or [`init_locations`], is damage
/// (a page): a record that does not open, or does not hold a valid set.
/// Not the not-held error, and not a store error (`Blob`, `Sql`: a
/// failure that may pass, `503` with no page).
pub fn is_locations_damage(e: &BridgeError) -> bool {
    match e {
        BridgeError::Crypto(_) => true,
        BridgeError::Invalid(m) => *m != KEK_NOT_HELD,
        _ => false,
    }
}

/// Whether `e` is [`ERR_LOCATIONS_KEK_NOT_HELD`].
pub fn is_kek_not_held(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Invalid(m) if *m == KEK_NOT_HELD)
}

fn open<K: Kek>(kek: &K, seq: u64, bytes: &[u8]) -> Result<KeyLocations> {
    let name = locations_chain().name(seq);
    let env = parse_control(bytes)?;
    let v = env.kek_version();
    // The rule of the directory's seal (`kek_not_held`): any other version
    // this Worker does not hold is damage.
    if kek.version(v).is_none() && v > kek.active().0 && v <= MAX_KEK_VERSION {
        return Err(ERR_LOCATIONS_KEK_NOT_HELD);
    }
    let opened = env.open_door(kek, &name, ControlOwner::Global)?;
    let set: KeyLocations = serde_json::from_slice(opened.door()).map_err(|_| ERR_LOCATIONS)?;
    if set.seq != seq {
        return Err(ERR_LOCATIONS);
    }
    set.check()?;
    Ok(set)
}

/// The head of the key-location chain; `None` before its first record.
/// `known` is the last seq the caller read (0 = none).
pub async fn read_locations<S: RecordStore, K: Kek>(
    store: &S,
    kek: &K,
    known: u64,
) -> Result<Option<KeyLocations>> {
    let chain = locations_chain();
    let head = chain.head(store, known).await?;
    if head == 0 {
        return Ok(None);
    }
    let bytes = chain.get(store, head).await?;
    open(kek, head, &bytes).map(Some)
}

/// Writes `next` as the next record. The first record is any valid set
/// whose seq is 1 and whose locations are all `active` or `proposed`;
/// every later one must follow the head. `Ok(false)`: the head moved
/// before the put; read it again and decide again.
pub async fn write_locations<S: RecordStore, K: Kek, R: FillRandom>(
    store: &S,
    kek: &K,
    next: &KeyLocations,
    rng: &mut R,
) -> Result<bool> {
    let head = read_locations(store, kek, 0).await?;
    match &head {
        Some(h) => h.admits(next)?,
        None => {
            next.check()?;
            let first_ok = next.seq == 1
                && next
                    .locations
                    .iter()
                    .all(|l| matches!(l.status, LocationStatus::Active | LocationStatus::Proposed));
            if !first_ok {
                return Err(ERR_LOCATIONS_MOVE);
            }
        }
    }
    let bytes = seal(kek, next, rng)?;
    Ok(locations_chain().put(store, next.seq, bytes).await? == Put::Written)
}

/// The set of this milestone: `KEYS_A`, the arbiter, and `KEYS_B`, both
/// in the account and both synchronous. The off-account location is not
/// in it.
pub fn two_in_account() -> KeyLocations {
    KeyLocations {
        v: 1,
        seq: 1,
        locations: vec![
            KeyLocation {
                name: "KEYS_A".into(),
                status: LocationStatus::Active,
                arbiter: true,
                synchronous: true,
            },
            KeyLocation {
                name: "KEYS_B".into(),
                status: LocationStatus::Active,
                arbiter: false,
                synchronous: true,
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// The first record (AM-70, AM-70b)
// ---------------------------------------------------------------------------

/// What [`init_locations`] answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitLocations {
    /// Seq 1 is written: [`two_in_account`]. `200`.
    Written,
    /// The head lists `KEYS_A` as the active synchronous arbiter and
    /// `KEYS_B` as active and synchronous (whatever its seq and its other
    /// locations); nothing written. `200`.
    Same,
    /// The head names another set; nothing written. `409
    /// locations_differ`, and a page.
    Differ,
}

/// Whether `head` lists the milestone's two locations as AM-70 needs
/// them, whatever its seq and its other locations.
fn names_the_two(head: &KeyLocations) -> bool {
    let find = |name: &str| head.locations.iter().find(|l| l.name == name);
    let a_ok = find("KEYS_A")
        .is_some_and(|l| l.arbiter && l.synchronous && l.status == LocationStatus::Active);
    let b_ok = find("KEYS_B")
        .is_some_and(|l| !l.arbiter && l.synchronous && l.status == LocationStatus::Active);
    a_ok && b_ok
}

fn answer_for(head: &KeyLocations) -> InitLocations {
    match names_the_two(head) {
        true => InitLocations::Same,
        false => InitLocations::Differ,
    }
}

/// The first key-location record (AM-70): the operator call (`POST`, no
/// body, `ADMIN_TOKEN` only, AM-70b) that the coordinator makes once per
/// environment after the deploy that binds `KEYS_A` and `KEYS_B`, and the
/// drill runner once per drill environment. No request path calls it. It
/// writes only into an empty chain, and only [`two_in_account`]; it
/// writes no object to either key bucket.
///
/// - No head: seq 1, put once ([`write_locations`]). A lost put, or a
///   refusal because a head appeared since the read, reads the head again
///   and answers by the rules below.
/// - A head that opens: nothing is written; [`InitLocations::Same`] or
///   [`InitLocations::Differ`].
/// - A head that does not open, or a store error: an `Err`, nothing
///   written (`503`). [`is_locations_damage`] is the one that pages;
///   [`is_kek_not_held`] (a KEK version this Worker does not hold yet) and
///   store errors do not.
pub async fn init_locations<S, K, R>(store: &S, kek: &K, rng: &mut R) -> Result<InitLocations>
where
    S: RecordStore,
    K: Kek,
    R: FillRandom,
{
    if let Some(head) = read_locations(store, kek, 0).await? {
        return Ok(answer_for(&head));
    }
    let written = write_locations(store, kek, &two_in_account(), rng).await;
    if let Ok(true) = written {
        return Ok(InitLocations::Written);
    }
    // Lost, or refused: a head may have appeared. Without one, the
    // write's own error stands.
    match read_locations(store, kek, 0).await? {
        Some(head) => Ok(answer_for(&head)),
        None => written.and(Err(ERR_LOCATIONS_MOVE)),
    }
}
