//! The unit side of the reservation (`docs/units.md`, "Reservations";
//! ADR §2.5 step 0, §6.2, §6.3; amendments AM-18, AM-35, AM-36, AM-38).
//!
//! A capped opening call (create a key, an app password, a principal or
//! a bucket; a widening grant change) first asks the tenant's root unit
//! for a reservation, before any intent or record. The ask carries the
//! request's `Idempotency-Key` as its SHA-256 and the request's
//! fingerprint (the Worker computes both), a fresh random `rid`, the
//! acting principal as the `Kofra-Acting-Owner-Ref` header named it (or
//! its key-chain id), and the change. In one transaction the unit:
//!
//! 1. refuses a malformed ask, more than 64 grants, and any grant with a
//!    prefix, an expiry or an address list (`grant_limits_not_served`:
//!    milestone 1 serves unlimited grants only, AM-18);
//! 2. resolves the acting principal in its own `unit_keys` (AM-35): no
//!    such principal that is not revoked, `acting_principal_unknown`;
//! 3. finds the row of the scope (that principal's id, or `''` for none;
//!    the key hash): another fingerprint is `reused`; an `applied` row
//!    answers the kept answer; a `reserved` one is asked again: checked
//!    again at the unit's head (`again`), with the same `rid`;
//! 4. otherwise checks the principal is `active` and not held, the
//!    subset rule (every grant no wider than the acting principal's
//!    effective grant, §6.2), the name or `owner_ref` the call must hold
//!    alone, and the caps, then keeps a `reserved` row.
//!
//! The answer carries the unit's `keys_seq`: the call's record must be
//! exactly `keys_seq + 1` (SEC-2). So does a `narrowing` answer, which
//! keeps nothing. A re-ask is checked, and answered, for the subject the
//! reservation holds. In a held or deleting tenant only what keeps no
//! reservation is answered; a shred refuses every ask. The key-chain apply turns the row
//! `applied` when it applies a record that carries the row's `rid`, and
//! keeps the answer the Worker passes with it (2xx, a JSON object of at
//! most 16 KiB, no `secret_access_key`). A record that closes or narrows
//! a principal cancels that principal's open reservations in the same
//! transaction (§2.5). A `reserved` row is released after 1 hour, an
//! `applied` one is kept 24 hours after its apply (AM-38); each ask
//! sweeps first.
//!
//! Whether a record above the row's `keys_seq` already carries its `rid`
//! (`409 idempotency_key_in_use`) is the Worker's to read: the unit
//! knows only the records it holds. On an answer with `again` set, the
//! Worker reads the chain above `keys_seq` for the `rid` before it goes
//! on.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};

use super::keys::{self, KeyGrant, KeyKind, SubjectStatus, MAX_GRANTS};
use super::object::poll_once;
use crate::ports::{Row, Sql, SqlValue};
use crate::types::{BridgeError, Result, UnixMs};

/// How long a reservation that no record turned into a row is kept.
pub const RESERVED_MS: i64 = 3_600_000;
/// How long an applied reservation and its answer are kept (AM-38).
pub const KEPT_MS: i64 = 86_400_000;
/// Key, app-password and principal creates and widening grant changes
/// per hour (ADR §6.3).
pub const CHANGES_PER_HOUR: i64 = 30;
const HOUR_MS: i64 = 3_600_000;
/// Bucket creates per day (ADR §6.3).
pub const BUCKETS_PER_DAY: i64 = 50;
const DAY_MS: i64 = 86_400_000;
/// Active S3 keys per tenant (ADR §6.2).
pub const S3_KEYS: i64 = 20;
/// Active app passwords per tenant (ADR §6.2).
pub const APP_PASSWORDS: i64 = 20;
/// The largest answer kept (AM-38).
pub const MAX_ANSWER: usize = 16 * 1024;

/// 32 bytes as 64 lowercase hex digits: the key hash and the fingerprint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash32(pub [u8; 32]);

/// The reservation's id: 16 random bytes as 32 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rid(pub [u8; 16]);

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({}..)", &hex(&self.0)[..8])
    }
}

impl fmt::Debug for Rid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rid({})", hex(&self.0))
    }
}

impl Rid {
    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 15)] as char);
    }
    out
}

/// Exactly `2 * N` lowercase hex digits.
fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != 2 * N {
        return None;
    }
    let val = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, pair) in digits.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (val(pair[0])? << 4) | val(pair[1])?;
    }
    Some(out)
}

macro_rules! hex_serde {
    ($t:ident, $n:literal) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(&hex(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                unhex::<$n>(&text)
                    .map($t)
                    .ok_or_else(|| serde::de::Error::custom(concat!("not ", $n, " hex bytes")))
            }
        }
    };
}

hex_serde!(Hash32, 32);
hex_serde!(Rid, 16);

/// The acting principal of an ask: as the header names it, or by its
/// key-chain id. `Debug` does not show the `owner_ref`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Acting {
    OwnerRef(String),
    Principal(String),
}

impl fmt::Debug for Acting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Acting::OwnerRef(_) => f.write_str("Acting::OwnerRef(..)"),
            Acting::Principal(id) => write!(f, "Acting::Principal({id})"),
        }
    }
}

/// The change an ask reserves for. `Debug` does not show the
/// `owner_ref`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub enum Opening {
    /// A new S3 key or app password `id`, made by the acting principal.
    Key {
        kind: KeyKind,
        id: String,
        grants: Vec<KeyGrant>,
    },
    /// A new principal `id` for `owner_ref`. Without an acting principal
    /// its grant list is empty (sign-up, AM-36).
    Principal {
        id: String,
        owner_ref: String,
        grants: Vec<KeyGrant>,
    },
    /// New grants of the key or principal `subject`. The unit decides
    /// whether this is a narrowing (no reservation) or a widening (SEC-8).
    Grants {
        subject: String,
        grants: Vec<KeyGrant>,
    },
    /// A new bucket `name`, placed on `unit`; the acting principal is its
    /// creator.
    Bucket { name: String, unit: u32 },
}

impl fmt::Debug for Opening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Opening::Key { kind, id, grants } => f
                .debug_struct("Key")
                .field("kind", kind)
                .field("id", id)
                .field("grants", grants)
                .finish(),
            Opening::Principal { id, grants, .. } => f
                .debug_struct("Principal")
                .field("id", id)
                .field("grants", grants)
                .finish_non_exhaustive(),
            Opening::Grants { subject, grants } => f
                .debug_struct("Grants")
                .field("subject", subject)
                .field("grants", grants)
                .finish(),
            Opening::Bucket { name, unit } => f
                .debug_struct("Bucket")
                .field("name", name)
                .field("unit", unit)
                .finish(),
        }
    }
}

impl Opening {
    fn class(&self) -> &'static str {
        match self {
            Opening::Key {
                kind: KeyKind::AppPassword,
                ..
            } => "app_password",
            Opening::Key { .. } => "s3",
            Opening::Principal { .. } => "principal",
            Opening::Grants { .. } => "grants",
            Opening::Bucket { .. } => "bucket",
        }
    }

    fn grants(&self) -> &[KeyGrant] {
        match self {
            Opening::Key { grants, .. }
            | Opening::Principal { grants, .. }
            | Opening::Grants { grants, .. } => grants,
            Opening::Bucket { .. } => &[],
        }
    }
}

/// Why an ask, or the read of an acting principal, was refused. Nothing
/// is kept. The Worker's answer for each is its `code` (the contract's
/// list, `velmora-mgmt-types`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveRefusal {
    /// A cap of ADR §6.3 is full: `429 cap_reached`.
    CapReached,
    /// A grant is wider than the acting principal's: `403 grant_not_held`.
    GrantNotHeld,
    /// A grant with a prefix, an expiry or an address list (AM-18):
    /// `400 grant_limits_not_served`.
    GrantLimitsNotServed,
    /// More than 64 grants: `400 too_many_grants`.
    TooManyGrants,
    /// No principal that is not revoked answers to the acting principal
    /// named: `403 acting_principal_unknown`.
    ActingPrincipalUnknown,
    /// The acting principal is `disabled`: `403 acting_principal_inactive`.
    ActingPrincipalInactive,
    /// The acting principal is held (AM-9): `503 service_unavailable`
    /// with `Retry-After`.
    ActingPrincipalHeld,
    /// Two principals that are not revoked hold one `owner_ref`: never
    /// resolved (fails closed, and alarms).
    OwnerRefAmbiguous,
    /// The name is a bucket's, or another call holds it:
    /// `409 bucket_already_exists`.
    BucketAlreadyExists,
    /// Another call holds the `owner_ref` for a principal create:
    /// `409 principal_exists`.
    PrincipalExists,
    /// The id the call would make exists: `409 conflict`.
    Conflict,
    /// A grant change of the internal key, which no token of this plane
    /// may change (SEC-8): `403 internal_key_refused`.
    InternalKeyRefused,
    /// The subject of a grant change is not held, or is revoked:
    /// `404 key_not_found`.
    NotFound,
    /// The `rid` is another reservation's: the Worker draws again.
    RidTaken,
    /// The ask cannot be one: `400 bad_request`.
    Malformed,
}

/// A principal as the unit holds it (an acting principal, or the one a
/// principal create found). `Debug` shows no grant detail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalView {
    pub id: String,
    pub status: SubjectStatus,
    pub held: bool,
    pub grants: Vec<KeyGrant>,
}

/// An ask, as [`super::call::UnitOp::Reserve`] carries it.
#[derive(Clone, Copy, Debug)]
pub struct Ask<'a> {
    pub key_hash: &'a Hash32,
    pub fingerprint: &'a Hash32,
    pub rid: &'a Rid,
    pub acting: Option<&'a Acting>,
    pub opening: &'a Opening,
}

/// What an ask did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Reserved (or asked again with `again`): the record must be
    /// `keys_seq + 1` and carry `rid`. `scope`: the acting principal's
    /// id. `bound`: the creator-grant seq a bucket create bound.
    /// `subject` and `unit`: what the reservation holds (the key or
    /// principal id, the subject of a grant change; a bucket's unit). A
    /// call asked again uses them, not ids it drew again: the row turns
    /// `applied` only by a record for its own subject.
    Admitted {
        rid: Rid,
        keys_seq: u64,
        again: bool,
        scope: Option<String>,
        bound: Option<u64>,
        subject: Option<String>,
        unit: Option<u32>,
    },
    /// The row was applied: the answer kept (none yet, if the record was
    /// applied without one), and what the call made.
    Applied {
        status: Option<u16>,
        body: Option<String>,
        subject: Option<String>,
        bucket: Option<String>,
        grant_seq: Option<u64>,
    },
    /// The same key with another request: no row, no record.
    Reused,
    /// The grant change is a narrowing of the subject's grants at the
    /// unit's `keys_seq`: it takes no reservation and no cap (a closing
    /// change, §2.5). Its record must be exactly `keys_seq + 1`, so a
    /// narrowing judged on a stale key table is never recorded on a newer
    /// head (a lost put asks again).
    Narrowing {
        keys_seq: u64,
    },
    /// The tenant's state refuses an opening ask (`403`): a hold or a
    /// deletion refuses opening writes only. Nothing is kept.
    NotOpen,
    /// A principal that is not revoked already holds the `owner_ref`
    /// (AM-36): `200` with it when the grant sets are equal, else
    /// `409 principal_exists`, decided by the Worker.
    Exists(PrincipalView),
    Refused(ReserveRefusal),
    /// The ask again failed its check at the head: refused, and the
    /// reservation is dropped, so the refusal leaves no row (§2.5 (c)).
    /// The caller drops it in a transaction of its own.
    RefusedDrop(ReserveRefusal, Rid),
}

impl Admit {
    /// The answer's body for a kept outcome.
    pub fn body(&self) -> Option<Value> {
        Some(match self {
            Admit::Admitted {
                rid,
                keys_seq,
                again,
                scope,
                bound,
                subject,
                unit,
            } => json!({ "admitted": {
                "rid": rid.hex(), "keys_seq": keys_seq, "again": again,
                "scope": scope, "bound": bound, "subject": subject, "unit": unit,
            }}),
            Admit::Applied {
                status,
                body,
                subject,
                bucket,
                grant_seq,
            } => json!({ "applied": {
                "status": status, "body": body, "subject": subject,
                "bucket": bucket, "grant_seq": grant_seq,
            }}),
            Admit::Reused => json!({ "reused": true }),
            Admit::Narrowing { keys_seq } => json!({ "narrowing": { "keys_seq": keys_seq } }),
            Admit::Exists(p) => json!({ "exists": p }),
            Admit::Refused(_) | Admit::RefusedDrop(..) | Admit::NotOpen => return None,
        })
    }
}

/// What the reservations say of one creator-grant seq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binding {
    /// An open bucket reservation is bound to it.
    Open {
        rid: Rid,
        name: String,
        creator: String,
        unit: u32,
    },
    /// The reservation bound to it became `bucket`.
    Created { bucket: String },
    /// No reservation is bound to it; the seq is fenced from now on.
    None,
}

impl Binding {
    pub fn body(&self) -> Value {
        match self {
            Binding::Open {
                rid,
                name,
                creator,
                unit,
            } => json!({ "binding": "open", "rid": rid.hex(), "name": name,
                         "creator": creator, "unit": unit }),
            Binding::Created { bucket } => json!({ "binding": "created", "bucket": bucket }),
            Binding::None => json!({ "binding": "none" }),
        }
    }
}

/// An id as the key chain names a subject or a bucket.
fn valid_id(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_graphic())
}

/// `Kofra-Acting-Owner-Ref`: 1 to 128 of `[A-Za-z0-9_:-]` (AM-35).
pub fn valid_owner_ref(r: &str) -> bool {
    (1..=128).contains(&r.len())
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-'))
}

/// An S3 bucket name as the catalogue holds one: 3 to 63 of
/// `[a-z0-9.-]`, a letter or digit at each end.
fn valid_bucket_name(n: &str) -> bool {
    let b = n.as_bytes();
    (3..=63).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-'))
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
}

/// The checks that need no database, in the order they answer.
fn shape(ask: &Ask) -> std::result::Result<(), ReserveRefusal> {
    use ReserveRefusal::*;
    match ask.acting {
        Some(Acting::OwnerRef(r)) if !valid_owner_ref(r) => return Err(Malformed),
        Some(Acting::Principal(id)) if !valid_id(id) => return Err(Malformed),
        _ => {}
    }
    match ask.opening {
        Opening::Key { kind, id, .. } => {
            if !matches!(kind, KeyKind::S3 | KeyKind::AppPassword) || !valid_id(id) {
                return Err(Malformed);
            }
        }
        Opening::Principal { id, owner_ref, .. } => {
            if !valid_id(id) || !valid_owner_ref(owner_ref) {
                return Err(Malformed);
            }
        }
        Opening::Grants { subject, .. } => {
            if !valid_id(subject) {
                return Err(Malformed);
            }
        }
        Opening::Bucket { name, .. } => {
            if !valid_bucket_name(name) {
                return Err(Malformed);
            }
        }
    }
    let grants = ask.opening.grants();
    if grants.iter().any(|g| !valid_id(&g.bucket_id)) {
        return Err(Malformed);
    }
    if grants.len() > MAX_GRANTS {
        return Err(TooManyGrants);
    }
    if grants
        .iter()
        .any(|g| g.prefix.is_some() || g.expires_at.is_some() || !g.ip_list.is_empty())
    {
        return Err(GrantLimitsNotServed);
    }
    // Every write names its acting principal, but for a sign-up's empty
    // principal (AM-35, AM-36).
    let needs_acting = match ask.opening {
        Opening::Principal { grants, .. } => !grants.is_empty(),
        _ => true,
    };
    if needs_acting && ask.acting.is_none() {
        return Err(Malformed);
    }
    Ok(())
}

/// The principal an ask or a read names, whatever its status: a
/// principal that is not revoked for an `owner_ref`, the principal of
/// that id otherwise.
fn find_principal<S: Sql>(
    sql: &S,
    acting: &Acting,
) -> Result<std::result::Result<PrincipalView, ReserveRefusal>> {
    let rows = match acting {
        Acting::OwnerRef(r) => poll_once(sql.query(
            "SELECT id, status, held FROM unit_keys \
              WHERE kind = 'principal' AND owner_ref = ?1 AND status <> 'revoked' LIMIT 2",
            &[SqlValue::Text(r.clone())],
        ))??,
        Acting::Principal(id) => poll_once(sql.query(
            "SELECT id, status, held FROM unit_keys \
              WHERE id = ?1 AND kind = 'principal' AND status <> 'revoked'",
            &[SqlValue::Text(id.clone())],
        ))??,
    };
    if rows.len() > 1 {
        return Ok(Err(ReserveRefusal::OwnerRefAmbiguous));
    }
    let Some(r) = rows.into_iter().next() else {
        return Ok(Err(ReserveRefusal::ActingPrincipalUnknown));
    };
    let (SqlValue::Text(id), SqlValue::Text(status), SqlValue::Int(held)) = (&r[0], &r[1], &r[2])
    else {
        return Err(decode("unit_keys principal"));
    };
    Ok(Ok(PrincipalView {
        id: id.clone(),
        status: SubjectStatus::parse(status).ok_or_else(|| decode("unit_keys status"))?,
        held: *held == 1,
        grants: keys::grants_of(sql, id)?,
    }))
}

/// The acting principal of a read (`objects.list`, `objects.presign`):
/// refused unless it is `active` and not held (AM-35). Read-only.
pub fn resolve<S: Sql>(
    sql: &S,
    acting: &Acting,
) -> Result<std::result::Result<PrincipalView, ReserveRefusal>> {
    match acting {
        Acting::OwnerRef(r) if !valid_owner_ref(r) => return Ok(Err(ReserveRefusal::Malformed)),
        Acting::Principal(id) if !valid_id(id) => return Ok(Err(ReserveRefusal::Malformed)),
        _ => {}
    }
    let p = match find_principal(sql, acting)? {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    Ok(match open(&p) {
        Ok(()) => Ok(p),
        Err(r) => Err(r),
    })
}

fn open(p: &PrincipalView) -> std::result::Result<(), ReserveRefusal> {
    if p.status != SubjectStatus::Active {
        return Err(ReserveRefusal::ActingPrincipalInactive);
    }
    if p.held {
        return Err(ReserveRefusal::ActingPrincipalHeld);
    }
    Ok(())
}

/// Every grant no wider than the acting principal's effective grant
/// (ADR §6.2): the same bucket id, access no higher. (Prefix, expiry and
/// address list are refused before this, AM-18.)
fn subset<S: Sql>(sql: &S, acting: &str, grants: &[KeyGrant]) -> Result<bool> {
    let held = keys::principal_effective(sql, acting)?.unwrap_or_default();
    Ok(grants.iter().all(|g| {
        held.iter()
            .any(|(b, a)| *b == g.bucket_id && g.access <= *a)
    }))
}

/// Whether `grants` are a narrowing of the subject's current grants
/// (SEC-8): each one inside a current grant on the same bucket, access no
/// higher, and the current grant unlimited (a new grant has no limit, so
/// it is no narrower than a limited one).
fn narrowing<S: Sql>(sql: &S, subject: &str, grants: &[KeyGrant]) -> Result<bool> {
    let current = keys::grants_of(sql, subject)?;
    Ok(grants.iter().all(|g| {
        current.iter().any(|c| {
            c.bucket_id == g.bucket_id
                && g.access <= c.access
                && c.prefix.is_none()
                && c.expires_at.is_none()
                && c.ip_list.is_empty()
        })
    }))
}

/// The subject a grant change names: its kind and status, if held.
fn subject_of<S: Sql>(sql: &S, id: &str) -> Result<Option<(KeyKind, SubjectStatus)>> {
    let rows = poll_once(sql.query(
        "SELECT kind, status FROM unit_keys WHERE id = ?1",
        &[SqlValue::Text(id.to_string())],
    ))??;
    let Some(r) = rows.into_iter().next() else {
        return Ok(None);
    };
    let (SqlValue::Text(kind), SqlValue::Text(status)) = (&r[0], &r[1]) else {
        return Err(decode("unit_keys row"));
    };
    Ok(Some((
        KeyKind::parse(kind).ok_or_else(|| decode("unit_keys kind"))?,
        SubjectStatus::parse(status).ok_or_else(|| decode("unit_keys status"))?,
    )))
}

fn exists<S: Sql>(sql: &S, text: &'static str, params: &[SqlValue]) -> Result<bool> {
    Ok(!poll_once(sql.query(text, params))??.is_empty())
}

fn count<S: Sql>(sql: &S, text: &'static str, params: &[SqlValue]) -> Result<i64> {
    let rows = poll_once(sql.query(text, params))??;
    match rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Int(n)) => Ok(*n),
        _ => Err(decode("count")),
    }
}

/// Releases the reservations that are due: `reserved` after 1 hour,
/// `applied` 24 hours after the apply. Inside the caller's transaction.
pub fn sweep<S: Sql>(sql: &S, now: UnixMs) -> Result<u64> {
    poll_once(sql.exec(
        "DELETE FROM unit_cap_uses WHERE at <= ?1",
        &[SqlValue::Int(now.0.saturating_sub(DAY_MS))],
    ))??;
    poll_once(sql.exec(
        "DELETE FROM unit_reservations \
          WHERE (state = 'reserved' AND reserved_at <= ?1) \
             OR (state = 'applied' AND applied_at <= ?2)",
        &[
            SqlValue::Int(now.0.saturating_sub(RESERVED_MS)),
            SqlValue::Int(now.0.saturating_sub(KEPT_MS)),
        ],
    ))?
}

/// The stored row of a scope, as the ask reads it.
struct Stored {
    fingerprint: Vec<u8>,
    rid: Rid,
    class: String,
    applied: bool,
    subject: Option<String>,
    bound: Option<u64>,
    bucket_id: Option<String>,
    answer: Option<(u16, String)>,
    owner_ref: Option<String>,
    name: Option<String>,
    unit: Option<u32>,
}

fn stored<S: Sql>(sql: &S, scope: &str, key_hash: &Hash32) -> Result<Option<Stored>> {
    let rows = poll_once(sql.query(
        "SELECT fingerprint, rid, class, state, subject, bound, bucket_id, answer_status, \
           answer_body, owner_ref, name, unit FROM unit_reservations \
          WHERE scope = ?1 AND key_hash = ?2",
        &[
            SqlValue::Text(scope.to_string()),
            SqlValue::Blob(key_hash.0.to_vec()),
        ],
    ))??;
    let Some(r) = rows.into_iter().next() else {
        return Ok(None);
    };
    row_stored(r).map(Some)
}

fn row_stored(r: Row) -> Result<Stored> {
    let text = |v: &SqlValue| match v {
        SqlValue::Text(s) => Ok(Some(s.clone())),
        SqlValue::Null => Ok(None),
        _ => Err(decode("unit_reservations text")),
    };
    let (SqlValue::Blob(fp), SqlValue::Blob(rid), SqlValue::Text(class), SqlValue::Text(state)) =
        (&r[0], &r[1], &r[2], &r[3])
    else {
        return Err(decode("unit_reservations row"));
    };
    let rid: [u8; 16] = rid
        .as_slice()
        .try_into()
        .map_err(|_| decode("unit_reservations rid"))?;
    let bound = match &r[5] {
        SqlValue::Null => None,
        SqlValue::Int(n) => Some(u64::try_from(*n).map_err(|_| decode("bound"))?),
        _ => return Err(decode("unit_reservations bound")),
    };
    let answer = match (&r[7], &r[8]) {
        (SqlValue::Int(s), SqlValue::Text(b)) => Some((
            u16::try_from(*s).map_err(|_| decode("answer_status"))?,
            b.clone(),
        )),
        (SqlValue::Null, SqlValue::Null) => None,
        _ => return Err(decode("unit_reservations answer")),
    };
    Ok(Stored {
        fingerprint: fp.clone(),
        rid: Rid(rid),
        class: class.clone(),
        applied: state == "applied",
        subject: text(&r[4])?,
        bound,
        bucket_id: text(&r[6])?,
        answer,
        owner_ref: text(&r[9])?,
        name: text(&r[10])?,
        unit: match &r[11] {
            SqlValue::Null => None,
            SqlValue::Int(n) => Some(u32::try_from(*n).map_err(|_| decode("unit"))?),
            _ => return Err(decode("unit_reservations unit")),
        },
    })
}

impl Stored {
    /// The ask's change with what this reservation holds in place of the
    /// ids the call drew: a re-ask is checked for its own subject.
    fn opening(&self, asked: &Opening) -> Result<Opening> {
        let missing = || decode("unit_reservations held values");
        Ok(match asked {
            Opening::Key { kind, grants, .. } => Opening::Key {
                kind: *kind,
                id: self.subject.clone().ok_or_else(missing)?,
                grants: grants.clone(),
            },
            Opening::Principal { grants, .. } => Opening::Principal {
                id: self.subject.clone().ok_or_else(missing)?,
                owner_ref: self.owner_ref.clone().ok_or_else(missing)?,
                grants: grants.clone(),
            },
            Opening::Grants { grants, .. } => Opening::Grants {
                subject: self.subject.clone().ok_or_else(missing)?,
                grants: grants.clone(),
            },
            Opening::Bucket { .. } => Opening::Bucket {
                name: self.name.clone().ok_or_else(missing)?,
                unit: self.unit.ok_or_else(missing)?,
            },
        })
    }
}

/// One ask (module doc), inside the caller's transaction. `keys_seq` is
/// the unit's own; `may_open`: the tenant's state allows opening writes
/// (`active`). Otherwise only what keeps no reservation is answered (a
/// narrowing, a reused key, a kept answer). A refusal writes nothing; the
/// caller rolls back.
pub fn admit<S: Sql>(
    sql: &S,
    keys_seq: u64,
    may_open: bool,
    ask: &Ask,
    now: UnixMs,
) -> Result<Admit> {
    if let Err(r) = shape(ask) {
        return Ok(Admit::Refused(r));
    }
    sweep(sql, now)?;
    let acting = match ask.acting {
        None => None,
        Some(a) => match find_principal(sql, a)? {
            Ok(p) => Some(p),
            Err(r) => return Ok(Admit::Refused(r)),
        },
    };
    let scope = acting.as_ref().map_or(String::new(), |p| p.id.clone());
    if let Some(row) = stored(sql, &scope, ask.key_hash)? {
        if row.fingerprint != ask.fingerprint.0 || row.class != ask.opening.class() {
            return Ok(Admit::Reused);
        }
        if row.applied {
            let (status, body) = row.answer.map_or((None, None), |(s, b)| (Some(s), Some(b)));
            return Ok(Admit::Applied {
                status,
                body,
                subject: row.subject,
                bucket: row.bucket_id,
                grant_seq: row.bound,
            });
        }
        if !may_open {
            return Ok(Admit::NotOpen);
        }
        // A bound bucket reservation is answered so whatever its creator
        // is now: its creator grant was recorded first (`bind_bucket`).
        if row.bound.is_some() {
            return Ok(Admit::Admitted {
                rid: row.rid,
                keys_seq,
                again: true,
                scope: Some(scope),
                bound: row.bound,
                subject: None,
                unit: row.unit,
            });
        }
        // Asked again: checked again at the head (§2.5 step 0, SEC-2),
        // for what the reservation holds.
        let held = row.opening(ask.opening)?;
        let again = Ask {
            opening: &held,
            ..*ask
        };
        let checked = check(sql, &again, acting.as_ref(), Some(&row.rid))?;
        if let Err(r) = checked {
            return Ok(Admit::RefusedDrop(r, row.rid));
        }
        poll_once(sql.exec(
            "UPDATE unit_reservations SET keys_seq = ?1 WHERE rid = ?2 AND state = 'reserved'",
            &[int(keys_seq)?, SqlValue::Blob(row.rid.0.to_vec())],
        ))??;
        return Ok(Admit::Admitted {
            rid: row.rid,
            keys_seq,
            again: true,
            scope: acting.map(|p| p.id),
            bound: None,
            subject: row.subject,
            unit: row.unit,
        });
    }
    // A grant change that narrows takes no reservation (SEC-8): it is a
    // closing change, which a held principal may make too, and in any
    // tenant state but a shred; a disabled one may not.
    if let Opening::Grants { subject, grants } = ask.opening {
        match subject_of(sql, subject)? {
            None | Some((_, SubjectStatus::Revoked)) => {
                return Ok(Admit::Refused(ReserveRefusal::NotFound))
            }
            Some((KeyKind::Internal, _)) => {
                return Ok(Admit::Refused(ReserveRefusal::InternalKeyRefused))
            }
            Some(_) => {}
        }
        if narrowing(sql, subject, grants)? {
            if acting
                .as_ref()
                .is_some_and(|p| p.status != SubjectStatus::Active)
            {
                return Ok(Admit::Refused(ReserveRefusal::ActingPrincipalInactive));
            }
            return Ok(Admit::Narrowing { keys_seq });
        }
    }
    if !may_open {
        return Ok(Admit::NotOpen);
    }
    if let Some(p) = &acting {
        if let Err(r) = open(p) {
            return Ok(Admit::Refused(r));
        }
    }
    // A principal create that finds its principal answers it (AM-36).
    if let Opening::Principal { owner_ref, .. } = ask.opening {
        if let Ok(p) = find_principal(sql, &Acting::OwnerRef(owner_ref.clone()))? {
            return Ok(Admit::Exists(p));
        }
    }
    if let Err(r) = check(sql, ask, acting.as_ref(), None)? {
        return Ok(Admit::Refused(r));
    }
    if let Err(r) = caps(sql, ask.opening, now)? {
        return Ok(Admit::Refused(r));
    }
    if exists(
        sql,
        "SELECT 1 FROM unit_reservations WHERE rid = ?1 \
         UNION ALL SELECT 1 FROM unit_cap_uses WHERE rid = ?1",
        &[SqlValue::Blob(ask.rid.0.to_vec())],
    )? {
        return Ok(Admit::Refused(ReserveRefusal::RidTaken));
    }
    let (subject, owner_ref, name, unit) = match ask.opening {
        Opening::Key { id, .. } | Opening::Principal { id, .. } => (
            SqlValue::Text(id.clone()),
            match ask.opening {
                Opening::Principal { owner_ref, .. } => SqlValue::Text(owner_ref.clone()),
                _ => SqlValue::Null,
            },
            SqlValue::Null,
            SqlValue::Null,
        ),
        Opening::Grants { subject, .. } => (
            SqlValue::Text(subject.clone()),
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
        ),
        Opening::Bucket { name, unit } => (
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Text(name.clone()),
            SqlValue::Int(i64::from(*unit)),
        ),
    };
    poll_once(sql.exec(
        "INSERT INTO unit_reservations(scope, key_hash, fingerprint, rid, class, state, \
           keys_seq, subject, owner_ref, name, unit, reserved_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'reserved', ?6, ?7, ?8, ?9, ?10, ?11)",
        &[
            SqlValue::Text(scope.clone()),
            SqlValue::Blob(ask.key_hash.0.to_vec()),
            SqlValue::Blob(ask.fingerprint.0.to_vec()),
            SqlValue::Blob(ask.rid.0.to_vec()),
            SqlValue::Text(ask.opening.class().into()),
            int(keys_seq)?,
            subject,
            owner_ref,
            name,
            unit,
            SqlValue::Int(now.0),
        ],
    ))??;
    // The cap slot, kept for its window (`unit_cap_uses`).
    poll_once(sql.exec(
        "INSERT INTO unit_cap_uses(rid, class, at) VALUES (?1, ?2, ?3)",
        &[
            SqlValue::Blob(ask.rid.0.to_vec()),
            SqlValue::Text(ask.opening.class().into()),
            SqlValue::Int(now.0),
        ],
    ))??;
    let (subject, unit) = match ask.opening {
        Opening::Key { id, .. } | Opening::Principal { id, .. } => (Some(id.clone()), None),
        Opening::Grants { subject, .. } => (Some(subject.clone()), None),
        Opening::Bucket { unit, .. } => (None, Some(*unit)),
    };
    Ok(Admit::Admitted {
        rid: *ask.rid,
        keys_seq,
        again: false,
        scope: acting.map(|p| p.id),
        bound: None,
        subject,
        unit,
    })
}

/// The checks of an ask against the unit's tables at its head: the
/// acting principal open, what the call makes not there yet, the name or
/// `owner_ref` held by no other call, the subset rule. `own`: the
/// reservation being asked again, which holds its own name.
fn check<S: Sql>(
    sql: &S,
    ask: &Ask,
    acting: Option<&PrincipalView>,
    own: Option<&Rid>,
) -> Result<std::result::Result<(), ReserveRefusal>> {
    use ReserveRefusal::*;
    if let Some(p) = acting {
        if let Err(r) = open(p) {
            return Ok(Err(r));
        }
    }
    let own_rid = own.map_or(SqlValue::Null, |r| SqlValue::Blob(r.0.to_vec()));
    match ask.opening {
        Opening::Key { id, .. } | Opening::Principal { id, .. } => {
            if exists(
                sql,
                "SELECT 1 FROM unit_keys WHERE id = ?1",
                &[SqlValue::Text(id.clone())],
            )? || exists(
                sql,
                "SELECT 1 FROM unit_reservations WHERE subject = ?1 AND class <> 'grants' \
                   AND rid IS NOT ?2",
                &[SqlValue::Text(id.clone()), own_rid.clone()],
            )? {
                return Ok(Err(Conflict));
            }
        }
        Opening::Grants { subject, .. } => match subject_of(sql, subject)? {
            None | Some((_, SubjectStatus::Revoked)) => return Ok(Err(NotFound)),
            Some((KeyKind::Internal, _)) => return Ok(Err(InternalKeyRefused)),
            Some(_) => {}
        },
        Opening::Bucket { name, .. } => {
            if exists(
                sql,
                "SELECT 1 FROM buckets WHERE name = ?1",
                &[SqlValue::Text(name.clone())],
            )? || exists(
                sql,
                "SELECT 1 FROM unit_reservations WHERE name = ?1 AND state = 'reserved' \
                   AND rid IS NOT ?2",
                &[SqlValue::Text(name.clone()), own_rid.clone()],
            )? {
                return Ok(Err(BucketAlreadyExists));
            }
        }
    }
    if let Opening::Principal { owner_ref, .. } = ask.opening {
        // At most one principal per `owner_ref` that is not revoked
        // (AM-35): none held, and no other open create for it.
        if exists(
            sql,
            "SELECT 1 FROM unit_keys WHERE kind = 'principal' AND owner_ref = ?1 \
               AND status <> 'revoked'",
            &[SqlValue::Text(owner_ref.clone())],
        )? || exists(
            sql,
            "SELECT 1 FROM unit_reservations WHERE owner_ref = ?1 AND state = 'reserved' \
               AND rid IS NOT ?2",
            &[SqlValue::Text(owner_ref.clone()), own_rid],
        )? {
            return Ok(Err(PrincipalExists));
        }
    }
    let grants = ask.opening.grants();
    if !grants.is_empty() {
        let Some(p) = acting else {
            return Ok(Err(Malformed));
        };
        if !subset(sql, &p.id, grants)? {
            return Ok(Err(GrantNotHeld));
        }
    }
    Ok(Ok(()))
}

/// The per-tenant caps of ADR §6.2 and §6.3, for a new reservation.
fn caps<S: Sql>(
    sql: &S,
    opening: &Opening,
    now: UnixMs,
) -> Result<std::result::Result<(), ReserveRefusal>> {
    if let Opening::Bucket { .. } = opening {
        let day = count(
            sql,
            "SELECT count(*) FROM unit_cap_uses WHERE at > ?1 AND class = 'bucket'",
            &[SqlValue::Int(now.0.saturating_sub(DAY_MS))],
        )?;
        return Ok(if day >= BUCKETS_PER_DAY {
            Err(ReserveRefusal::CapReached)
        } else {
            Ok(())
        });
    }
    let hour = count(
        sql,
        "SELECT count(*) FROM unit_cap_uses WHERE at > ?1 AND class <> 'bucket'",
        &[SqlValue::Int(now.0.saturating_sub(HOUR_MS))],
    )?;
    if hour >= CHANGES_PER_HOUR {
        return Ok(Err(ReserveRefusal::CapReached));
    }
    if let Opening::Key { kind, .. } = opening {
        let cap = if *kind == KeyKind::AppPassword {
            APP_PASSWORDS
        } else {
            S3_KEYS
        };
        let kind = SqlValue::Text(kind.as_str().into());
        let active = count(
            sql,
            "SELECT (SELECT count(*) FROM unit_keys WHERE kind = ?1 AND status = 'active') \
                  + (SELECT count(*) FROM unit_reservations \
                      WHERE state = 'reserved' AND class = ?1)",
            &[kind],
        )?;
        if active >= cap {
            return Ok(Err(ReserveRefusal::CapReached));
        }
    }
    Ok(Ok(()))
}

/// Drops the `reserved` row `rid`: a call that ends with no record
/// (`release`), or a re-ask refused at the head. An applied or missing
/// one changes nothing. `free_slot`: the call ended with no record, so its
/// cap slot is given back too; a re-ask's refusal keeps it (its record may
/// exist after a lost answer).
pub fn release<S: Sql>(sql: &S, rid: &Rid, free_slot: bool) -> Result<bool> {
    let n = poll_once(sql.exec(
        "DELETE FROM unit_reservations WHERE rid = ?1 AND state = 'reserved'",
        &[SqlValue::Blob(rid.0.to_vec())],
    ))??;
    if n == 1 && free_slot {
        poll_once(sql.exec(
            "DELETE FROM unit_cap_uses WHERE rid = ?1",
            &[SqlValue::Blob(rid.0.to_vec())],
        ))??;
    }
    Ok(n == 1)
}

fn fenced<S: Sql>(sql: &S, grant_seq: u64) -> Result<bool> {
    exists(
        sql,
        "SELECT 1 FROM unit_bucket_fences WHERE grant_seq = ?1",
        &[int(grant_seq)?],
    )
}

/// Binds the bucket reservation `rid` to the creator grant `grant_seq`
/// only while it is bound to `expected`: a compare-and-set. Binding the
/// same seq again answers `true`; a fenced seq, or a seq another
/// reservation holds, `false`.
pub fn bind_bucket<S: Sql>(
    sql: &S,
    rid: &Rid,
    expected: Option<u64>,
    grant_seq: u64,
) -> Result<bool> {
    if grant_seq == 0 || fenced(sql, grant_seq)? {
        return Ok(false);
    }
    let rows = poll_once(sql.query(
        "SELECT class, state, bound FROM unit_reservations WHERE rid = ?1",
        &[SqlValue::Blob(rid.0.to_vec())],
    ))??;
    let Some(r) = rows.into_iter().next() else {
        return Ok(false);
    };
    let (SqlValue::Text(class), SqlValue::Text(state)) = (&r[0], &r[1]) else {
        return Err(decode("unit_reservations row"));
    };
    let bound = match &r[2] {
        SqlValue::Null => None,
        SqlValue::Int(n) => Some(u64::try_from(*n).map_err(|_| decode("bound"))?),
        _ => return Err(decode("unit_reservations bound")),
    };
    if class != "bucket" {
        return Ok(false);
    }
    if bound == Some(grant_seq) {
        return Ok(true);
    }
    if state != "reserved" || bound != expected {
        return Ok(false);
    }
    if exists(
        sql,
        "SELECT 1 FROM unit_reservations WHERE bound = ?1",
        &[int(grant_seq)?],
    )? {
        return Ok(false);
    }
    let n = poll_once(sql.exec(
        "UPDATE unit_reservations SET bound = ?1 WHERE rid = ?2 AND state = 'reserved'",
        &[int(grant_seq)?, SqlValue::Blob(rid.0.to_vec())],
    ))??;
    Ok(n == 1)
}

/// Releases the bucket reservation `rid` only while it is bound to
/// `bound`.
pub fn release_bound<S: Sql>(sql: &S, rid: &Rid, bound: Option<u64>) -> Result<bool> {
    let n = poll_once(sql.exec(
        "DELETE FROM unit_reservations \
          WHERE rid = ?1 AND state = 'reserved' AND class = 'bucket' AND bound IS ?2",
        &[
            SqlValue::Blob(rid.0.to_vec()),
            bound.map_or(Ok(SqlValue::Null), int)?,
        ],
    ))??;
    // The create ended with no bucket: its slot is given back.
    if n == 1 {
        poll_once(sql.exec(
            "DELETE FROM unit_cap_uses WHERE rid = ?1",
            &[SqlValue::Blob(rid.0.to_vec())],
        ))??;
    }
    Ok(n == 1)
}

/// What the reservations say of the creator grant `grant_seq`. An answer
/// of [`Binding::None`] fences the seq in the same transaction.
pub fn bucket_binding<S: Sql>(sql: &S, grant_seq: u64) -> Result<Binding> {
    if grant_seq == 0 {
        return Ok(Binding::None);
    }
    let rows = poll_once(sql.query(
        "SELECT rid, state, name, scope, unit, bucket_id FROM unit_reservations \
          WHERE bound = ?1",
        &[int(grant_seq)?],
    ))??;
    if let Some(r) = rows.into_iter().next() {
        return match (&r[0], &r[1], &r[2], &r[3], &r[4], &r[5]) {
            (_, SqlValue::Text(s), _, _, _, SqlValue::Text(bucket)) if s == "applied" => {
                Ok(Binding::Created {
                    bucket: bucket.clone(),
                })
            }
            (
                SqlValue::Blob(rid),
                SqlValue::Text(s),
                SqlValue::Text(name),
                SqlValue::Text(creator),
                SqlValue::Int(unit),
                SqlValue::Null,
            ) if s == "reserved" => Ok(Binding::Open {
                rid: Rid(rid
                    .as_slice()
                    .try_into()
                    .map_err(|_| decode("unit_reservations rid"))?),
                name: name.clone(),
                creator: creator.clone(),
                unit: u32::try_from(*unit).map_err(|_| decode("unit"))?,
            }),
            _ => Err(decode("unit_reservations binding")),
        };
    }
    poll_once(sql.exec(
        "INSERT OR IGNORE INTO unit_bucket_fences(grant_seq) VALUES (?1)",
        &[int(grant_seq)?],
    ))??;
    Ok(Binding::None)
}

/// Turns the bucket reservation bound to `grant_seq` into the bucket
/// `bucket`, with its answer: called by the apply of the tenant record
/// `bucket_created` for that seq, in its transaction. `false`: no open
/// reservation is bound to it.
pub fn bucket_created<S: Sql>(
    sql: &S,
    grant_seq: u64,
    bucket: &str,
    answer: Option<(u16, &str)>,
    now: UnixMs,
) -> Result<bool> {
    if !valid_id(bucket) {
        return Err(BridgeError::Invalid("unit: bucket id"));
    }
    let n = poll_once(sql.exec(
        "UPDATE unit_reservations SET state = 'applied', applied_at = ?1, bucket_id = ?2 \
          WHERE bound = ?3 AND state = 'reserved' AND class = 'bucket'",
        &[
            SqlValue::Int(now.0),
            SqlValue::Text(bucket.into()),
            int(grant_seq)?,
        ],
    ))??;
    if n != 1 {
        return Ok(false);
    }
    if let Some((status, body)) = answer {
        let rows = poll_once(sql.query(
            "SELECT rid FROM unit_reservations WHERE bound = ?1",
            &[int(grant_seq)?],
        ))??;
        if let Some(SqlValue::Blob(rid)) =
            rows.into_iter().next().and_then(|r| r.into_iter().next())
        {
            let rid = Rid(rid
                .as_slice()
                .try_into()
                .map_err(|_| decode("unit_reservations rid"))?);
            keep_answer(sql, &rid, status, body)?;
        }
    }
    Ok(true)
}

/// Turns the reservation `rid` `applied`: the key-chain apply holds a
/// record that carries it, for `subject`. A bucket reservation turns by
/// [`bucket_created`] only. `false`: none open for that subject.
pub fn applied<S: Sql>(sql: &S, rid: &Rid, subject: &str, now: UnixMs) -> Result<bool> {
    let n = poll_once(sql.exec(
        "UPDATE unit_reservations SET state = 'applied', applied_at = ?1 \
          WHERE rid = ?2 AND state = 'reserved' AND class <> 'bucket' AND subject = ?3",
        &[
            SqlValue::Int(now.0),
            SqlValue::Blob(rid.0.to_vec()),
            SqlValue::Text(subject.into()),
        ],
    ))??;
    Ok(n == 1)
}

/// Whether an answer may be kept (AM-38): a 2xx status, a JSON object of
/// at most [`MAX_ANSWER`] bytes, and no `secret_access_key` with a value
/// at any depth.
pub fn keepable(status: u16, body: &str) -> bool {
    fn no_secret(v: &Value) -> bool {
        match v {
            Value::Object(map) => map
                .iter()
                .all(|(k, v)| (k != "secret_access_key" || v.is_null()) && no_secret(v)),
            Value::Array(items) => items.iter().all(no_secret),
            _ => true,
        }
    }
    (200..300).contains(&status)
        && body.len() <= MAX_ANSWER
        && serde_json::from_str::<Value>(body).is_ok_and(|v| v.is_object() && no_secret(&v))
}

/// Keeps the answer of the applied reservation `rid`, once: the first
/// answer kept is never replaced. `false`: not kept (not applied, one
/// kept already, or not [`keepable`]).
pub fn keep_answer<S: Sql>(sql: &S, rid: &Rid, status: u16, body: &str) -> Result<bool> {
    if !keepable(status, body) {
        return Ok(false);
    }
    let n = poll_once(sql.exec(
        "UPDATE unit_reservations SET answer_status = ?1, answer_body = ?2 \
          WHERE rid = ?3 AND state = 'applied' AND answer_status IS NULL",
        &[
            SqlValue::Int(i64::from(status)),
            SqlValue::Text(body.into()),
            SqlValue::Blob(rid.0.to_vec()),
        ],
    ))??;
    Ok(n == 1)
}

/// Cancels the open reservations of the acting principal `principal`
/// (§2.5: a record that revokes, disables or narrows a principal), but
/// the one whose record this is.
pub fn cancel_open<S: Sql>(sql: &S, principal: &str, except: Option<&Rid>) -> Result<u64> {
    poll_once(sql.exec(
        "DELETE FROM unit_reservations \
          WHERE scope = ?1 AND state = 'reserved' AND bound IS NULL AND rid IS NOT ?2",
        &[
            SqlValue::Text(principal.into()),
            except.map_or(SqlValue::Null, |r| SqlValue::Blob(r.0.to_vec())),
        ],
    ))?
}

fn int(n: u64) -> Result<SqlValue> {
    i64::try_from(n)
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("number out of range"))
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_another_form() {
        let r = Rid([0xab; 16]);
        let text = serde_json::to_string(&r).unwrap();
        assert_eq!(text, format!("\"{}\"", "ab".repeat(16)));
        assert_eq!(serde_json::from_str::<Rid>(&text).unwrap(), r);
        for bad in ["\"AB\"", "\"abab\"", &format!("\"{}\"", "AB".repeat(16))] {
            assert!(serde_json::from_str::<Rid>(bad).is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<Hash32>(&format!("\"{}\"", "0".repeat(64))).is_ok());
        assert!(serde_json::from_str::<Hash32>(&format!("\"{}\"", "0".repeat(63))).is_err());
    }

    #[test]
    fn an_answer_is_kept_only_without_a_secret_and_small() {
        assert!(keepable(201, r#"{"id":"k","secret_access_key":null}"#));
        assert!(!keepable(201, r#"{"id":"k","secret_access_key":"s"}"#));
        assert!(!keepable(201, r#"{"a":[{"secret_access_key":"s"}]}"#));
        assert!(!keepable(409, r#"{"code":"x"}"#));
        assert!(!keepable(200, "[1]"));
        assert!(!keepable(200, "not json"));
        let big = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_ANSWER));
        assert!(!keepable(200, &big));
    }

    #[test]
    fn an_unknown_field_is_refused_in_every_new_shape() {
        for text in [
            r#"{"class":"bucket","name":"abc","unit":0,"x":1}"#,
            r#"{"class":"key","kind":"s3","id":"AK","grants":[],"x":1}"#,
            r#"{"class":"grants","subject":"AK","grants":[{"bucket_id":"b","access":"ro","x":1}]}"#,
        ] {
            assert!(serde_json::from_str::<Opening>(text).is_err(), "{text}");
        }
        assert!(serde_json::from_str::<Acting>(r#"{"owner_ref":"m","x":1}"#).is_err());
        assert!(
            serde_json::from_str::<Opening>(r#"{"class":"bucket","name":"abc","unit":0}"#).is_ok()
        );
    }

    #[test]
    fn debug_shows_no_owner_ref() {
        let a = Acting::OwnerRef("member-secretive".into());
        assert!(!format!("{a:?}").contains("secretive"));
        let o = Opening::Principal {
            id: "p".into(),
            owner_ref: "member-secretive".into(),
            grants: vec![],
        };
        assert!(!format!("{o:?}").contains("secretive"));
    }

    #[test]
    fn owner_refs_and_bucket_names_have_their_forms() {
        assert!(valid_owner_ref("user_01:a-b"));
        assert!(!valid_owner_ref(""));
        assert!(!valid_owner_ref("a b"));
        assert!(!valid_owner_ref(&"a".repeat(129)));
        assert!(valid_bucket_name("my-bucket.1"));
        assert!(!valid_bucket_name("ab"));
        assert!(!valid_bucket_name("-ab"));
        assert!(!valid_bucket_name("Abc"));
    }
}
