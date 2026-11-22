//! Records of the key chain `m/k/<t>/<seq>` and the key table they fold
//! into.
//!
//! Each record is one change to one subject (an access key, an app
//! password, a principal or the internal key) and carries the subject's
//! **whole state after the change**, so the newest record of a subject
//! is its state. A record is a two-part control record
//! ([`crate::crypto::scheme2`]), split like this:
//!
//! | Part | Fields |
//! |---|---|
//! | door (control key) | seq, op, time, subject id, kind, status, `made_by`, per bucket id the access and the expiry, creation time, KEK version of the secret |
//! | private (tenant key) | `owner_ref`, label, per bucket id the prefix and the IP list, the wrapped secret |
//!
//! A record whose door part does not open stops every reader: the chain
//! is damaged. A record whose private part does not open (its key
//! version is gone, or it fails) is folded from its door part, and the
//! subject is then **disabled** wherever it is applied: a row built from
//! the door part alone would drop the prefix and the IP list and so widen
//! the grant.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use velmora::rng::FillRandom;

use super::chain::Chain;
use crate::crypto::scheme2::{
    parse_control, seal_control, ControlOwner, ControlSealer, PrivateKeyRef, Scheme, TenantId,
    TenantKey,
};
use crate::ports::Kek;
use crate::recovery::valid_key_id;
use crate::types::{BridgeError, Result};

/// Format version of a key-chain record body.
pub const KEY_RECORD_VERSION: u32 = 1;
/// Most grants one subject holds.
pub const MAX_SUBJECT_GRANTS: usize = 64;
/// Longest `owner_ref`, label, grant prefix or IP list entry.
pub const MAX_FIELD_LEN: usize = 1024;
/// Most entries of one IP list.
pub const MAX_IP_LIST: usize = 64;

/// A record that breaks a rule of the chain. Written by a bug or planted;
/// the reader stops and alarms.
pub const ERR_KEY_RECORD: BridgeError = BridgeError::Invalid("key record is malformed");
/// A change that the head does not admit: a change that is no longer
/// valid writes nothing.
pub const ERR_KEY_TRANSITION: BridgeError =
    BridgeError::Invalid("key change is not valid at the chain head");

/// The key chain of `tenant`.
pub fn key_chain(tenant: &TenantId) -> Chain {
    Chain::new(format!("m/k/{tenant}/"))
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// An S3 access key.
    S3,
    /// An app password: accepted on the WebDAV entry point only.
    AppPassword,
    /// A member's grants, with no secret.
    Principal,
    /// The tenant's internal key, for presigned URLs only.
    Internal,
}

impl SubjectKind {
    /// Whether a subject of this kind has a secret.
    pub fn has_secret(self) -> bool {
        !matches!(self, SubjectKind::Principal)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectStatus {
    Active,
    Disabled,
    /// Final. A revoked subject never changes again.
    Revoked,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Ro,
    Rw,
}

/// The change a record makes.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyOp {
    /// A new subject, `active`.
    Create,
    /// The status changes; nothing else.
    Status,
    /// The grants change; nothing else.
    Grants,
    /// The same content again under a newer key version (after a
    /// rotation). Opens or closes no door.
    Restate,
}

/// The door part of one grant.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DoorGrant {
    pub bucket_id: String,
    pub access: Access,
    /// Unix ms; `None` = no expiry.
    pub expires_at: Option<u64>,
}

/// The private part of one grant, in the same order as the door part.
/// `Debug` shows its shape only.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivateGrant {
    pub bucket_id: String,
    /// `None` = the whole bucket.
    pub prefix: Option<String>,
    /// Empty = any address.
    pub ip_list: Vec<String>,
}

/// What the door part says about a subject.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubjectDoor {
    pub id: String,
    pub kind: SubjectKind,
    pub status: SubjectStatus,
    /// The principal the subject was made under: a key never holds more
    /// than its principal's current grant. `None` for
    /// the internal key and for a principal with no parent.
    pub made_by: Option<String>,
    pub grants: Vec<DoorGrant>,
    /// Unix ms.
    pub created_at: u64,
    /// The KEK version of the wrapped secret; `None` for a principal.
    pub secret_kek_version: Option<u32>,
}

/// What the private part says about a subject.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubjectPrivate {
    pub owner_ref: Option<String>,
    pub label: Option<String>,
    pub grants: Vec<PrivateGrant>,
    /// The `ak/v2` wrap of the secret; `None` for a principal.
    #[serde(with = "opt_b64")]
    pub secret_wrapped: Option<Vec<u8>>,
}

impl std::fmt::Debug for SubjectPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only shapes: no owner, label, prefix, address or wrap.
        f.debug_struct("SubjectPrivate")
            .field("grants", &self.grants.len())
            .field("secret", &self.secret_wrapped.is_some())
            .finish_non_exhaustive()
    }
}

/// A subject's whole state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    pub door: SubjectDoor,
    pub private: SubjectPrivate,
}

/// One full grant, both parts joined. `Debug` leaves the prefix and the
/// IP list out.
#[derive(Clone, PartialEq, Eq)]
pub struct Grant {
    pub bucket_id: String,
    pub access: Access,
    pub expires_at: Option<u64>,
    pub prefix: Option<String>,
    pub ip_list: Vec<String>,
}

impl Subject {
    /// The grants with both parts joined.
    pub fn grants(&self) -> Vec<Grant> {
        self.door
            .grants
            .iter()
            .zip(&self.private.grants)
            .map(|(d, p)| Grant {
                bucket_id: d.bucket_id.clone(),
                access: d.access,
                expires_at: d.expires_at,
                prefix: p.prefix.clone(),
                ip_list: p.ip_list.clone(),
            })
            .collect()
    }

    /// Replaces the grants with `grants`, split into the two parts.
    pub fn set_grants(&mut self, grants: &[Grant]) {
        self.door.grants = grants
            .iter()
            .map(|g| DoorGrant {
                bucket_id: g.bucket_id.clone(),
                access: g.access,
                expires_at: g.expires_at,
            })
            .collect();
        self.private.grants = grants
            .iter()
            .map(|g| PrivateGrant {
                bucket_id: g.bucket_id.clone(),
                prefix: g.prefix.clone(),
                ip_list: g.ip_list.clone(),
            })
            .collect();
    }
}

impl std::fmt::Debug for PrivateGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateGrant")
            .field("bucket_id", &self.bucket_id)
            .field("prefix", &self.prefix.is_some())
            .field("ips", &self.ip_list.len())
            .finish()
    }
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("bucket_id", &self.bucket_id)
            .field("access", &self.access)
            .field("expires_at", &self.expires_at)
            .field("prefix", &self.prefix.is_some())
            .field("ips", &self.ip_list.len())
            .finish()
    }
}

/// Whether a record's `closes` fits its change: a create, a re-enable
/// and a restate open nothing closed; a disable or a revoke closes; a
/// grants change is classed by the writer from the head.
fn closes_fits(op: KeyOp, status: SubjectStatus, closes: bool) -> bool {
    match op {
        KeyOp::Create | KeyOp::Restate => !closes,
        KeyOp::Status => closes == (status != SubjectStatus::Active),
        KeyOp::Grants => true,
    }
}

/// The rules of a subject's state, for a reader that builds an entry from
/// something other than a record (a checkpoint).
pub(crate) fn check_entry(
    tenant: &TenantId,
    door: &SubjectDoor,
    private: Option<&SubjectPrivate>,
) -> Result<()> {
    check_subject(tenant, door, private)
}

fn short(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_FIELD_LEN
}

/// The rules of one subject's state that hold in every record.
fn check_subject(
    tenant: &TenantId,
    door: &SubjectDoor,
    private: Option<&SubjectPrivate>,
) -> Result<()> {
    let ids_ok = valid_key_id(&door.id) && door.made_by.as_deref().is_none_or(valid_key_id);
    let grants_ok = door.grants.len() <= MAX_SUBJECT_GRANTS
        && door.grants.iter().enumerate().all(|(i, g)| {
            short(&g.bucket_id) && !door.grants[..i].iter().any(|h| h.bucket_id == g.bucket_id)
        });
    let shape_ok = match door.kind {
        SubjectKind::Principal => door.secret_kek_version.is_none(),
        SubjectKind::Internal => door.secret_kek_version.is_some() && door.made_by.is_none(),
        SubjectKind::S3 | SubjectKind::AppPassword => {
            door.secret_kek_version.is_some() && door.made_by.is_some()
        }
    };
    let self_made = door.made_by.as_deref() == Some(door.id.as_str());
    if !ids_ok || !grants_ok || !shape_ok || self_made {
        return Err(ERR_KEY_RECORD);
    }
    let Some(p) = private else {
        return Ok(());
    };
    let aligned = p.grants.len() == door.grants.len()
        && p.grants.iter().zip(&door.grants).all(|(p, d)| {
            p.bucket_id == d.bucket_id
                && p.prefix.as_deref().is_none_or(|s| s.len() <= MAX_FIELD_LEN)
                && p.ip_list.len() <= MAX_IP_LIST
                && p.ip_list.iter().all(|ip| short(ip))
        });
    let fields_ok =
        p.owner_ref.as_deref().is_none_or(short) && p.label.as_deref().is_none_or(short);
    // The secret is there exactly when the door says so, and it is a
    // scheme-2 wrap: this is a managed tenant's chain.
    let secret_ok = match (&p.secret_wrapped, door.secret_kek_version) {
        (None, None) => true,
        (Some(w), Some(_)) => Scheme::Two(tenant.clone()).check(w).is_ok(),
        _ => false,
    };
    if !aligned || !fields_ok || !secret_ok {
        return Err(ERR_KEY_RECORD);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// One record of the key chain, opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    pub seq: u64,
    pub op: KeyOp,
    /// Unix ms the writer recorded the change.
    pub at: u64,
    pub door: SubjectDoor,
    /// `None` when the private part did not open, or when the record
    /// carries none ([`Self::private_unchanged`]).
    pub private: Option<SubjectPrivate>,
    /// The tenant key version that seals the private part.
    pub tk_version: u32,
    /// The record closes a door (revoke, disable, narrow), as its writer
    /// classed it from the head. A retry of the same change is classed the
    /// same way.
    pub closes: bool,
    /// The record carries no private part: the subject's private part is
    /// the one it had before (a closing status change whose writer could
    /// not open it).
    pub private_unchanged: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DoorBody {
    v: u32,
    tenant: String,
    seq: u64,
    op: KeyOp,
    at: u64,
    subject: SubjectDoor,
    closes: bool,
    private_unchanged: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateBody {
    v: u32,
    id: String,
    /// `None`: written by a closing change that could not open the
    /// subject's previous private part.
    subject: Option<SubjectPrivate>,
}

/// The tenant keys a reader can use, by version, and the one a writer
/// seals new records under. Every key a ring hands out is a key of the
/// ring's tenant; the open functions check it again.
pub trait TkRing {
    /// The key of the newest committed key version.
    fn current(&self) -> Option<&TenantKey>;
    /// The key of `version`, if it can be loaded.
    fn key(&self, version: u32) -> Option<&TenantKey>;
    /// Whether `version` is gone: a record marks it retired or lost (ADR
    /// §3.5, AM-11). A private part sealed under it never opens again, so
    /// its subject is an outcome to report, not a load to retry.
    fn gone(&self, _version: u32) -> bool {
        false
    }
    /// Whether some committed version did not load now (a transient
    /// error). A reader with a partial ring must not take a private part
    /// for lost: what it cannot open may be in a checkpoint sealed under
    /// the missing version.
    fn partial(&self) -> bool {
        false
    }
}

/// A ring with one key version (tests, and a tenant before its first
/// rotation).
pub struct OneKey(pub TenantKey);

impl TkRing for OneKey {
    fn current(&self) -> Option<&TenantKey> {
        Some(&self.0)
    }
    fn key(&self, version: u32) -> Option<&TenantKey> {
        (version == self.0.version()).then_some(&self.0)
    }
}

/// No key at all: every private part stays closed.
pub struct NoKeys;

impl TkRing for NoKeys {
    fn current(&self) -> Option<&TenantKey> {
        None
    }
    fn key(&self, _version: u32) -> Option<&TenantKey> {
        None
    }
}

/// Seals the record of `op` at `seq` under the ring's current key
/// version. `private` is `None` only for a closing status change whose
/// writer could not open the subject's private part: the record then
/// carries none and says so ([`KeyRecord::private_unchanged`]), and a
/// reader keeps the private part the subject had before. `closes` is the
/// writer's class of the change.
#[allow(clippy::too_many_arguments)]
pub fn seal_key_record<K: Kek, T: TkRing, R: FillRandom>(
    kek: &K,
    ring: &T,
    tenant: &TenantId,
    seq: u64,
    op: KeyOp,
    at: u64,
    door: &SubjectDoor,
    private: Option<&SubjectPrivate>,
    closes: bool,
    rng: &mut R,
) -> Result<Vec<u8>> {
    check_subject(tenant, door, private)?;
    let closing_status = op == KeyOp::Status && door.status != SubjectStatus::Active && closes;
    if (private.is_none() && !closing_status) || !closes_fits(op, door.status, closes) {
        return Err(ERR_KEY_RECORD);
    }
    let tk = ring
        .current()
        .ok_or(BridgeError::Crypto("tenant key unavailable"))?;
    let door_body = serde_json::to_vec(&DoorBody {
        v: KEY_RECORD_VERSION,
        tenant: tenant.as_str().to_owned(),
        seq,
        op,
        at,
        subject: door.clone(),
        closes,
        private_unchanged: private.is_none(),
    })
    .map_err(|_| ERR_KEY_RECORD)?;
    let private_body = zeroize::Zeroizing::new(
        serde_json::to_vec(&PrivateBody {
            v: KEY_RECORD_VERSION,
            id: door.id.clone(),
            subject: private.cloned(),
        })
        .map_err(|_| ERR_KEY_RECORD)?,
    );
    let name = key_chain(tenant).name(seq);
    seal_control(
        kek,
        &name,
        &ControlSealer::Managed(tk),
        &door_body,
        Some(&private_body),
        rng,
    )
}

/// Opens the record stored at `seq` of `tenant`'s key chain. An error
/// means the door part does not open or breaks a rule: the reader stops.
pub fn open_key_record<K: Kek, T: TkRing>(
    kek: &K,
    ring: &T,
    tenant: &TenantId,
    seq: u64,
    bytes: &[u8],
) -> Result<KeyRecord> {
    let name = key_chain(tenant).name(seq);
    let opened = parse_control(bytes)?.open_door(kek, &name, ControlOwner::Managed(tenant))?;
    let door: DoorBody = serde_json::from_slice(opened.door()).map_err(|_| ERR_KEY_RECORD)?;
    if door.v != KEY_RECORD_VERSION || door.tenant != tenant.as_str() || door.seq != seq {
        return Err(ERR_KEY_RECORD);
    }
    let PrivateKeyRef::Tenant(tk_version) = opened.private_key() else {
        return Err(ERR_KEY_RECORD);
    };
    check_subject(tenant, &door.subject, None)?;
    // A private part that does not open, or opens into something that
    // does not match its door part, is folded as closed.
    let private = ring
        .key(tk_version)
        .and_then(|tk| opened.open_private_managed(tk).ok())
        .and_then(|plain| serde_json::from_slice::<PrivateBody>(&plain).ok())
        .filter(|p| p.v == KEY_RECORD_VERSION && p.id == door.subject.id)
        .and_then(|p| p.subject)
        .filter(|p| check_subject(tenant, &door.subject, Some(p)).is_ok());
    // A record without a private part must be a closing status change.
    let closing_status = door.op == KeyOp::Status && door.subject.status != SubjectStatus::Active;
    if door.private_unchanged && (!closing_status || !door.closes) {
        return Err(ERR_KEY_RECORD);
    }
    if !closes_fits(door.op, door.subject.status, door.closes) {
        return Err(ERR_KEY_RECORD);
    }
    let private = match door.private_unchanged {
        true => None,
        false => private,
    };
    Ok(KeyRecord {
        seq,
        op: door.op,
        at: door.at,
        door: door.subject,
        private,
        tk_version,
        closes: door.closes,
        private_unchanged: door.private_unchanged,
    })
}

// ---------------------------------------------------------------------------
// The key table
// ---------------------------------------------------------------------------

/// One subject in the key table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub door: SubjectDoor,
    /// `None`: the private part did not open.
    pub private: Option<SubjectPrivate>,
    /// The seq of the subject's newest record.
    pub last_seq: u64,
    /// The seq of the record that holds the subject's private part: the
    /// newest one, or an older one when the newer ones carry none.
    pub private_seq: u64,
    /// The key version that seals that record's private part.
    pub tk_version: u32,
    /// The newest record closes a door.
    pub closes: bool,
    /// The seq of the subject's newest record that opens a door (a
    /// create, a re-enable, a widening). A store whose directory has not
    /// acknowledged this seq must not hold the subject open.
    pub opened_seq: u64,
}

impl Entry {
    /// The status a store applies: the recorded one, except that a
    /// subject whose private part is closed is `disabled`.
    pub fn effective_status(&self) -> SubjectStatus {
        match (self.door.status, &self.private) {
            (SubjectStatus::Revoked, _) => SubjectStatus::Revoked,
            (_, None) => SubjectStatus::Disabled,
            (status, Some(_)) => status,
        }
    }

    /// The whole subject, when its private part is open.
    pub fn subject(&self) -> Option<Subject> {
        self.private.as_ref().map(|p| Subject {
            door: self.door.clone(),
            private: p.clone(),
        })
    }
}

/// Every subject of a tenant as of one seq of its key chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyTable {
    tenant: TenantId,
    seq: u64,
    subjects: BTreeMap<String, Entry>,
}

impl KeyTable {
    /// The table before seq 1.
    pub fn empty(tenant: TenantId) -> KeyTable {
        KeyTable {
            tenant,
            seq: 0,
            subjects: BTreeMap::new(),
        }
    }

    pub(super) fn from_parts(
        tenant: TenantId,
        seq: u64,
        subjects: BTreeMap<String, Entry>,
    ) -> KeyTable {
        KeyTable {
            tenant,
            seq,
            subjects,
        }
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The seq the table is at (`keys_seq`).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.subjects.get(id)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.subjects.values()
    }

    pub fn len(&self) -> usize {
        self.subjects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.subjects.is_empty()
    }

    /// The entry of `id` with its private part now opened by `private`
    /// (a checkpoint carried it closed; the record opens with the current
    /// ring).
    pub(super) fn reopen(&mut self, id: &str, private: SubjectPrivate) {
        if let Some(e) = self.subjects.get_mut(id) {
            e.private = Some(private);
        }
    }

    /// Whether `op` with the door part `door` (and the private part
    /// `private`, when known) is a valid next record.
    pub fn admits(
        &self,
        op: KeyOp,
        door: &SubjectDoor,
        private: Option<&SubjectPrivate>,
    ) -> Result<()> {
        check_subject(&self.tenant, door, private)?;
        let current = self.subjects.get(&door.id);
        let ok = match (op, current) {
            (KeyOp::Create, None) => {
                door.status == SubjectStatus::Active
                    && door.made_by.as_deref().is_none_or(|p| {
                        self.subjects.get(p).is_some_and(|e| {
                            e.door.kind == SubjectKind::Principal
                                && e.door.status == SubjectStatus::Active
                        })
                    })
            }
            (KeyOp::Create, Some(_)) | (_, None) => false,
            (_, Some(cur)) if cur.door.status == SubjectStatus::Revoked => false,
            (KeyOp::Status, Some(cur)) => {
                door.status != cur.door.status
                    && same_but(door, &cur.door, |d| d.status = cur.door.status)
                    && same_private(private, cur.private.as_ref(), false)
            }
            (KeyOp::Grants, Some(cur)) => {
                // With a private part closed on either side, a change of
                // a prefix or an IP list cannot be seen; it is accepted.
                let changed = door.grants != cur.door.grants
                    || match (private, cur.private.as_ref()) {
                        (Some(a), Some(b)) => a.grants != b.grants,
                        _ => true,
                    };
                changed
                    && same_but(door, &cur.door, |d| d.grants.clone_from(&cur.door.grants))
                    && same_private(private, cur.private.as_ref(), true)
            }
            (KeyOp::Restate, Some(cur)) => {
                *door == cur.door && same_private(private, cur.private.as_ref(), false)
            }
        };
        if !ok {
            return Err(ERR_KEY_TRANSITION);
        }
        Ok(())
    }

    /// Folds the next record into the table.
    pub fn apply(&mut self, record: &KeyRecord) -> Result<()> {
        if record.seq != self.seq + 1 {
            return Err(ERR_KEY_RECORD);
        }
        // A restate moves a private part to a newer key version, never
        // back: an older one may be retired.
        if record.op == KeyOp::Restate {
            let before = self.subjects.get(&record.door.id).ok_or(ERR_KEY_RECORD)?;
            if record.private_unchanged || record.tk_version <= before.tk_version {
                return Err(ERR_KEY_RECORD);
            }
        }
        self.admits(record.op, &record.door, record.private.as_ref())
            .map_err(|_| ERR_KEY_RECORD)?;
        // A record that carries no private part keeps the one before.
        let (private, private_seq, tk_version) =
            match (record.private_unchanged, self.subjects.get(&record.door.id)) {
                (true, Some(before)) => (
                    before.private.clone(),
                    before.private_seq,
                    before.tk_version,
                ),
                (true, None) => return Err(ERR_KEY_RECORD),
                (false, _) => (record.private.clone(), record.seq, record.tk_version),
            };
        // A restate re-seals the private part and changes no policy.
        let opens = !record.closes && record.op != KeyOp::Restate;
        let opened_seq = match (opens, self.subjects.get(&record.door.id)) {
            (true, _) => record.seq,
            (false, Some(before)) => before.opened_seq,
            (false, None) => 0,
        };
        self.subjects.insert(
            record.door.id.clone(),
            Entry {
                door: record.door.clone(),
                private,
                last_seq: record.seq,
                private_seq,
                tk_version,
                closes: record.closes,
                opened_seq,
            },
        );
        self.seq = record.seq;
        Ok(())
    }

    /// Marks `id` revoked by its `m/rk/` record, which overrides every
    /// chain status. The chain is not changed; the finisher
    /// appends the missing record. `false` when no such subject exists.
    pub fn override_revoked(&mut self, id: &str) -> bool {
        match self.subjects.get_mut(id) {
            Some(e) => {
                e.door.status = SubjectStatus::Revoked;
                true
            }
            None => false,
        }
    }
}

/// Whether `a` equals `b` once `fix` has made the field that may differ
/// the same.
fn same_but(a: &SubjectDoor, b: &SubjectDoor, fix: impl FnOnce(&mut SubjectDoor)) -> bool {
    let mut a = a.clone();
    fix(&mut a);
    a == *b
}

/// Whether the private parts agree. A side that is closed cannot be
/// compared and is accepted; the door rules still hold. With `grants`,
/// the grant part may differ.
fn same_private(a: Option<&SubjectPrivate>, b: Option<&SubjectPrivate>, grants: bool) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            a.owner_ref == b.owner_ref
                && a.label == b.label
                && a.secret_wrapped == b.secret_wrapped
                && (grants || a.grants == b.grants)
        }
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Narrowing
// ---------------------------------------------------------------------------

/// Whether `inner` is no wider than `outer` on every one of the five
/// tests: same bucket id, access no higher, prefix inside, expiry no
/// later, IP list no wider. An empty IP list allows every address.
pub fn grant_within(inner: &Grant, outer: &Grant) -> bool {
    let prefix_ok = match (&outer.prefix, &inner.prefix) {
        (None, _) => true,
        (Some(o), Some(i)) => i.starts_with(o.as_str()),
        (Some(_), None) => false,
    };
    let expiry_ok = match (outer.expires_at, inner.expires_at) {
        (None, _) => true,
        (Some(o), Some(i)) => i <= o,
        (Some(_), None) => false,
    };
    let ip_ok = outer.ip_list.is_empty()
        || (!inner.ip_list.is_empty() && inner.ip_list.iter().all(|ip| outer.ip_list.contains(ip)));
    inner.bucket_id == outer.bucket_id
        && inner.access <= outer.access
        && prefix_ok
        && expiry_ok
        && ip_ok
}

/// Whether the grant list `new` narrows `current`: every new grant lies
/// within the current grant of its bucket. Adding a bucket is a
/// widening; dropping one is a narrowing.
pub fn grants_narrow(new: &[Grant], current: &[Grant]) -> bool {
    new.iter().all(|n| {
        current
            .iter()
            .find(|c| c.bucket_id == n.bucket_id)
            .is_some_and(|c| grant_within(n, c))
    })
}

// ---------------------------------------------------------------------------
// Base64 of an optional byte string
// ---------------------------------------------------------------------------

mod opt_b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .transpose()
    }
}
