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

fn open<K: Kek>(kek: &K, seq: u64, bytes: &[u8]) -> Result<KeyLocations> {
    let name = locations_chain().name(seq);
    let opened = parse_control(bytes)?.open_door(kek, &name, ControlOwner::Global)?;
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
// The first record (AM-70)
// ---------------------------------------------------------------------------

/// Where the probe objects of [`init_locations`] are written in a key
/// bucket: outside every tenant's key directory (`tk/<t>/`), so no key
/// load, audit or shred lists them.
pub const PROBE_PREFIX: &str = "probe/kl/";

/// A key bucket's delete, for the probe objects only.
#[allow(async_fn_in_trait)]
pub trait ProbeDelete {
    /// Deletes `name`; a missing object is not an error.
    async fn delete(&self, name: &str) -> Result<()>;
}

/// What [`init_locations`] answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitLocations {
    /// Seq 1 is written: [`two_in_account`]. `200`.
    Written,
    /// The head already names exactly that set; nothing written. `200`.
    Same,
    /// The head names another set; nothing written. `409 locations_differ`,
    /// and the operator is paged.
    Differ,
    /// A probe written through one binding is visible through the other:
    /// the two bindings are one bucket. Nothing written. The operator is
    /// paged.
    NotDistinct,
}

/// A probe read back through its own binding is not what was written.
pub const ERR_PROBE_READBACK: BridgeError =
    BridgeError::Invalid("a key bucket probe did not read back");

const ERR_PROBE_RNG: BridgeError = BridgeError::Crypto("random source failed");

fn probe_name<R: FillRandom>(rng: &mut R) -> Result<(String, Vec<u8>)> {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b).map_err(|_| ERR_PROBE_RNG)?;
    let hex: String = b[..16].iter().map(|x| format!("{x:02x}")).collect();
    Ok((format!("{PROBE_PREFIX}{hex}"), b[16..].to_vec()))
}

/// Whether the head names exactly `want`'s locations.
fn same_set(head: &KeyLocations, want: &KeyLocations) -> bool {
    head.v == want.v && head.locations == want.locations
}

/// The head now, answered against `want`.
async fn answer_head<S: RecordStore, K: Kek>(
    store: &S,
    kek: &K,
    want: &KeyLocations,
) -> Result<Option<InitLocations>> {
    Ok(read_locations(store, kek, 0).await?.map(|h| {
        if same_set(&h, want) {
            InitLocations::Same
        } else {
            InitLocations::Differ
        }
    }))
}

/// Writes one probe through `a`, and checks it reads back there and is
/// absent through `b`.
async fn probe_one<A: RecordStore, B: RecordStore>(
    a: &A,
    b: &B,
    name: &str,
    body: &[u8],
) -> Result<bool> {
    if !a.put_if_absent(name, body.to_vec()).await? {
        // A random 128-bit name already there: never by chance.
        return Err(ERR_PROBE_READBACK);
    }
    if a.get(name).await?.as_deref() != Some(body) {
        return Err(ERR_PROBE_READBACK);
    }
    Ok(b.get(name).await?.is_none())
}

/// The first key-location record (AM-70): the operator call of the deploy
/// step that binds `KEYS_A` and `KEYS_B`, run once per deployment (and by
/// the drill render). No request path calls it.
///
/// - A head that names exactly [`two_in_account`] answers
///   [`InitLocations::Same`]; another head [`InitLocations::Differ`].
///   Neither probes nor writes.
/// - Otherwise a probe object with a random name is written to each
///   bucket through its binding and read back there; the probe written
///   through `KEYS_A` must be absent through `KEYS_B`, and the reverse.
///   Both probes are deleted, whatever the outcome. Two bindings of one
///   bucket answer [`InitLocations::NotDistinct`], and nothing is
///   written.
/// - Then seq 1 is put once ([`write_locations`]). A put that lost reads
///   the head again and answers from it.
///
/// A store error is an `Err` (`503`): nothing is written after it, and a
/// re-run starts again.
pub async fn init_locations<S, K, A, B, R>(
    store: &S,
    kek: &K,
    keys_a: &A,
    keys_b: &B,
    rng: &mut R,
) -> Result<InitLocations>
where
    S: RecordStore,
    K: Kek,
    A: RecordStore + ProbeDelete,
    B: RecordStore + ProbeDelete,
    R: FillRandom,
{
    let want = two_in_account();
    if let Some(answer) = answer_head(store, kek, &want).await? {
        return Ok(answer);
    }
    let (name_a, body_a) = probe_name(rng)?;
    let (name_b, body_b) = probe_name(rng)?;
    let checked = async {
        let a_alone = probe_one(keys_a, keys_b, &name_a, &body_a).await?;
        let b_alone = probe_one(keys_b, keys_a, &name_b, &body_b).await?;
        Ok::<bool, BridgeError>(a_alone && b_alone)
    }
    .await;
    // Both probes go, whatever the checks found.
    let gone_a = keys_a.delete(&name_a).await;
    let gone_b = keys_b.delete(&name_b).await;
    if !checked? {
        return Ok(InitLocations::NotDistinct);
    }
    gone_a?;
    gone_b?;
    if write_locations(store, kek, &want, rng).await? {
        return Ok(InitLocations::Written);
    }
    Ok(answer_head(store, kek, &want)
        .await?
        .unwrap_or(InitLocations::Differ))
}
