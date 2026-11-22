//! Request and answer bodies.
//!
//! **Requests** refuse unknown fields (`400 bad_request`), and each has a
//! [`Validate`] check for what serde cannot say: forms, bounds and the
//! largest integer. [`parse_request`] does both. **Answers** accept
//! unknown fields, so that velmora can add one without breaking a caller;
//! removing or changing a field is a breaking change of this crate.
//!
//! A field written `x | null` in the contract is always present in an
//! answer, as `null` when it has no value. Times are Unix ms.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::codes::Code;
use crate::ids::{
    valid_bucket_id, valid_bucket_name, valid_external_ref, valid_key_name, valid_label,
    valid_object_key, valid_owner_ref, MAX_SAFE_INTEGER,
};
use crate::position::{Day, ObjectPosition};

/// The most bytes in a request body.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// The most bytes in an answer that the root unit keeps for a replay
/// (`Idempotency-Key`, capped opening calls). A `Key` with 64 grants fits.
pub const MAX_STORED_ANSWER_BYTES: usize = 16 * 1024;

/// The most grants of a key or a principal (a record rule). Beyond it:
/// `409 grant_limit_reached`.
pub const MAX_GRANTS: usize = 64;

/// The most seconds a presigned URL is valid.
pub const MAX_PRESIGN_EXPIRES_S: u32 = 900;

/// The checks of a request after it parsed.
pub trait Validate {
    /// `Err` with the code of the refusal.
    fn validate(&self) -> Result<(), Code>;
}

/// A request body: JSON of at most [`MAX_REQUEST_BYTES`], with no unknown
/// field, that passes its [`Validate`] check. Any other body answers
/// `400 bad_request`, or the code its check gives.
pub fn parse_request<T: DeserializeOwned + Validate>(body: &[u8]) -> Result<T, Code> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(Code::BadRequest);
    }
    let req: T = serde_json::from_slice(body).map_err(|_| Code::BadRequest)?;
    req.validate()?;
    Ok(req)
}

fn check(ok: bool) -> Result<(), Code> {
    if ok {
        Ok(())
    } else {
        Err(Code::BadRequest)
    }
}

fn safe(n: u64) -> Result<(), Code> {
    check(n <= MAX_SAFE_INTEGER)
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// What a grant lets a key do in its bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Read and list. `kofra-api`'s `read`.
    Ro,
    /// Read, list, write and delete. `kofra-api`'s `read_write`.
    Rw,
}

/// A grant in a request: a bucket by id, and the access.
///
/// A prefix, an expiry or an address list (`prefix`, `expires_at_ms`,
/// `ip_list`) is not served yet and answers `400 grant_limits_not_served`.
/// The fields are named here so that the refusal is that code, and not
/// `bad_request` for an unknown field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantIn {
    pub bucket_id: String,
    pub access: Access,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_list: Option<Value>,
}

impl GrantIn {
    /// A grant of `access` on `bucket_id`, and nothing more.
    pub fn new(bucket_id: impl Into<String>, access: Access) -> GrantIn {
        GrantIn {
            bucket_id: bucket_id.into(),
            access,
            prefix: None,
            expires_at_ms: None,
            ip_list: None,
        }
    }
}

/// A grant list of a request: at most [`MAX_GRANTS`], one per bucket id,
/// each id of its form, and none with a limit.
pub fn validate_grants(grants: &[GrantIn]) -> Result<(), Code> {
    for (i, g) in grants.iter().enumerate() {
        check(valid_bucket_id(&g.bucket_id))?;
        check(!grants[..i].iter().any(|h| h.bucket_id == g.bucket_id))?;
        if g.prefix.is_some() || g.expires_at_ms.is_some() || g.ip_list.is_some() {
            return Err(Code::GrantLimitsNotServed);
        }
    }
    if grants.len() > MAX_GRANTS {
        return Err(Code::GrantLimitReached);
    }
    Ok(())
}

/// A grant in an answer. `bucket_name` is `null` for a bucket that is
/// gone; `kofra-api` leaves such a grant out of its own answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub bucket_id: String,
    pub bucket_name: Option<String>,
    pub access: Access,
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

/// The one jurisdiction milestone 1 serves (AM-58): no Durable Object
/// jurisdiction. Also what an absent `jurisdiction` means.
pub const JURISDICTION_NONE: &str = "none";

/// `POST /v1/tenants`. Without `limits` and `rate_class`: the registry's
/// free allowance and default class. `Idempotency-Key` = the workspace id.
/// A create with an `external_ref` that has a tenant answers `200` with
/// it (adopted); one whose tenant was shredded answers
/// `409 external_ref_retired`.
///
/// `jurisdiction`: absent means [`JURISDICTION_NONE`] (AM-58). Milestone 1
/// serves `none` only; any other value answers
/// `400 jurisdiction_not_served`. `kofra-api` sends none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantCreate {
    pub external_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitsIn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_class: Option<String>,
}

impl Validate for TenantCreate {
    fn validate(&self) -> Result<(), Code> {
        check(valid_external_ref(&self.external_ref))?;
        check(self.jurisdiction.as_deref().is_none_or(valid_label))?;
        if let Some(l) = &self.limits {
            l.validate()?;
        }
        check(self.rate_class.as_deref().is_none_or(valid_label))
    }
}

/// A tenant's limits, in an answer. `null`: no limit of that kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub storage_bytes: Option<u64>,
    pub upload_24h_bytes: Option<u64>,
    pub download_allowance_bytes: Option<u64>,
    pub active_keys: u32,
}

/// A tenant's limits, in a request: the fields of [`Limits`] (a size that
/// is absent or `null`: no limit of that kind).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsIn {
    pub storage_bytes: Option<u64>,
    pub upload_24h_bytes: Option<u64>,
    pub download_allowance_bytes: Option<u64>,
    pub active_keys: u32,
}

impl From<LimitsIn> for Limits {
    fn from(l: LimitsIn) -> Limits {
        Limits {
            storage_bytes: l.storage_bytes,
            upload_24h_bytes: l.upload_24h_bytes,
            download_allowance_bytes: l.download_allowance_bytes,
            active_keys: l.active_keys,
        }
    }
}

impl Validate for LimitsIn {
    fn validate(&self) -> Result<(), Code> {
        for n in [
            self.storage_bytes,
            self.upload_24h_bytes,
            self.download_allowance_bytes,
        ]
        .into_iter()
        .flatten()
        {
            safe(n)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    Active,
    Suspended,
    Deleting,
}

/// What the tenant's keys may do now. Velmora computes it from the
/// holds; a caller does not derive it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantAccess {
    Full,
    ReadOnly,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspensionMode {
    ReadOnly,
    /// The tenancy design's `locked`.
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspensionReason {
    NonPayment,
    /// `kofra-api`'s `other`.
    Operator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suspension {
    pub mode: SuspensionMode,
    pub reason: SuspensionReason,
    pub since_ms: u64,
}

/// Who asked for a deletion. `billing` is `kofra-api`'s reason
/// `non_payment`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionActor {
    Customer,
    Billing,
    Operator,
}

/// A deletion that is set. `seq` is the tenant-chain seq of the record
/// that set it: the `deletion_seq` that [`TenantRestore`] names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deletion {
    pub seq: u64,
    pub actor: DeletionActor,
    pub requested_at_ms: u64,
    pub shred_due_at_ms: u64,
}

/// A tenant (tenant create, read, delete and restore).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub state: TenantState,
    pub access: TenantAccess,
    pub limits: Limits,
    pub suspension: Option<Suspension>,
    pub deletion: Option<Deletion>,
    pub created_at_ms: u64,
}

/// `GET …/reach`: what a delete of the tenant would reach (a dry run).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reach {
    pub buckets: u64,
    pub objects: u64,
    pub stored_bytes: u64,
    pub keys: u64,
}

/// `POST …/restore`: the undo of the deletion that the record at
/// `deletion_seq` set, as `GET` showed it (`Tenant.deletion.seq`). A late
/// retry can never cancel a newer deletion: that one has another seq and
/// answers `409 deletion_not_requested`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRestore {
    pub deletion_seq: u64,
}

impl Validate for TenantRestore {
    fn validate(&self) -> Result<(), Code> {
        safe(self.deletion_seq)
    }
}

// ---------------------------------------------------------------------------
// Principals
// ---------------------------------------------------------------------------

/// `POST …/principals`: create, or find, the principal of `owner_ref`.
///
/// One principal that is not `revoked` per `owner_ref`. A create that
/// finds it answers `200` with it when its grants equal the request's
/// (as a set), and `409 principal_exists` otherwise. After a revoke, a
/// create makes a new principal with a new id. Without the acting header
/// the list must be empty (sign-up); with it, every grant must be held by
/// the acting principal (`403 grant_not_held` otherwise).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalCreate {
    pub owner_ref: String,
    pub grants: Vec<GrantIn>,
}

impl Validate for PrincipalCreate {
    fn validate(&self) -> Result<(), Code> {
        check(valid_owner_ref(&self.owner_ref))?;
        validate_grants(&self.grants)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalStatus {
    Active,
    Disabled,
    Revoked,
}

/// A principal: a member's grants, with no secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub owner_ref: String,
    pub status: PrincipalStatus,
    pub grants: Vec<Grant>,
}

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

/// `POST …/buckets`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketCreate {
    pub name: String,
}

impl Validate for BucketCreate {
    fn validate(&self) -> Result<(), Code> {
        check(valid_bucket_name(&self.name))
    }
}

/// A bucket. The counters are the unit's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    pub id: String,
    pub name: String,
    pub created_at_ms: u64,
    pub stored_bytes: u64,
    pub object_count: u64,
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The kind of a key in an answer. Lists and reads never show a
/// principal or the tenant's internal key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    S3,
    AppPassword,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKind::S3 => "s3",
            KeyKind::AppPassword => "app_password",
        }
    }

    pub fn parse(s: &str) -> Option<KeyKind> {
        match s {
            "s3" => Some(KeyKind::S3),
            "app_password" => Some(KeyKind::AppPassword),
            _ => None,
        }
    }
}

/// The kind a key create may name: `s3` only, in this contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyCreateKind {
    S3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Disabled,
    Revoked,
}

/// A key, never with its secret. `seq` is the key's newest key-chain seq,
/// which a grant change names as `if_seq`. `last_used_at_ms` is `null`
/// until velmora records use.
///
/// `GET`, `PATCH` and `DELETE` on `…/keys/{k}` with a principal's id
/// answer `404 key_not_found` and write nothing; on the tenant's internal
/// key they answer `403 internal_key_refused`. A list never shows a
/// `revoked` key; a read can. `kofra-api` answers `KeyNotFound` for a
/// `revoked` key on its `key` and `update_key`. Its `revoke_key` always
/// sends the `DELETE`, and a `204`, first or repeat, is `Ok`: a repeat
/// runs the stores again, so a revoke that died half-way is finished.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    pub id: String,
    pub kind: KeyKind,
    pub name: Option<String>,
    pub status: KeyStatus,
    pub grants: Vec<Grant>,
    pub created_at_ms: u64,
    pub last_used_at_ms: Option<u64>,
    pub seq: u64,
}

/// `POST …/keys`. `keys:write` on the standard token when every grant is
/// `ro`; `keys:write_rw` on the confirmed token otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCreate {
    pub kind: KeyCreateKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub grants: Vec<GrantIn>,
}

impl Validate for KeyCreate {
    fn validate(&self) -> Result<(), Code> {
        check(self.name.as_deref().is_none_or(valid_key_name))?;
        validate_grants(&self.grants)
    }
}

/// The answer of a key create: the key and its secret. The secret is in
/// the first answer only; a replay of the same request answers `null`.
/// Its `Debug` never shows the secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCreated {
    #[serde(flatten)]
    pub key: Key,
    pub secret_access_key: Option<String>,
}

impl fmt::Debug for KeyCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyCreated")
            .field("key", &self.key)
            .field(
                "secret_access_key",
                &self.secret_access_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// `PATCH …/keys/{k}`: a rename, a grant change, or both. `grants` is the
/// **whole new list**, never a delta; `if_seq` is the `seq` the caller
/// read.
///
/// The unit checks in this order: (1) the same scope and the same
/// fingerprint: the answer of [`crate::idem`], case 1 (the stored answer
/// once applied; `409 idempotency_key_in_use` or a re-admission while
/// reserved); (2) the key already has
/// exactly this list and name: `200`, and nothing is written; (3) the
/// same scope with another fingerprint: `422 idempotency_key_reused`;
/// (4) `if_seq` is not the key's `seq`: `409 key_changed`; (5) otherwise
/// it classifies the change (a narrowing, or a widening on the confirmed
/// token) and writes it. A principal id answers `404 key_not_found` and
/// writes nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<GrantIn>>,
    pub if_seq: u64,
}

impl Validate for KeyUpdate {
    fn validate(&self) -> Result<(), Code> {
        check(self.name.is_some() || self.grants.is_some())?;
        check(self.name.as_deref().is_none_or(valid_key_name))?;
        if let Some(g) = &self.grants {
            validate_grants(g)?;
        }
        safe(self.if_seq)
    }
}

impl KeyUpdate {
    /// The body the fingerprint is taken over: this request without
    /// `if_seq`, as compact JSON with `name` then `grants`, an absent one
    /// left out, and the grants in `bucket_id` order (a list holds a
    /// bucket once, so the order is total). A re-read that brings a new
    /// `if_seq`, or the same list in another order, is the same request.
    pub fn fingerprint_body(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Body<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            name: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            grants: Option<&'a [GrantIn]>,
        }
        let grants = self.grants.as_ref().map(|g| {
            let mut g = g.clone();
            g.sort_by(|a, b| a.bucket_id.cmp(&b.bucket_id));
            g
        });
        let body = Body {
            name: self.name.as_deref(),
            grants: grants.as_deref(),
        };
        // A struct of strings and enums: serializing it cannot fail.
        serde_json::to_vec(&body).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

/// `POST …/objects/list`: a read, though it is a `POST` (it keeps no
/// record, and needs no `Idempotency-Key`). The acting principal needs a
/// grant on the bucket (`403 grant_not_held` otherwise). `after` is an
/// [`ObjectPosition`]; it travels here, never in a URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectList {
    pub bucket_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    pub limit: u32,
}

impl Validate for ObjectList {
    fn validate(&self) -> Result<(), Code> {
        check(valid_bucket_id(&self.bucket_id))?;
        check(self.prefix.as_ref().is_none_or(|p| p.len() <= 1024))?;
        check(self.delimiter.as_deref().is_none_or(valid_object_key))?;
        check(crate::query::LIMITS.contains(&self.limit))?;
        if let Some(a) = &self.after {
            ObjectPosition::parse(a).map_err(|_| Code::InvalidPosition)?;
        }
        Ok(())
    }
}

/// One object of a listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectEntry {
    pub key: String,
    pub size_bytes: u64,
    pub last_modified_ms: u64,
}

/// The answer of `objects/list`: objects and, with a delimiter, common
/// prefixes, at most `limit` entries together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPage {
    pub objects: Vec<ObjectEntry>,
    pub prefixes: Vec<String>,
    pub next: Option<String>,
}

/// The operation of a presigned URL: a read only, in this contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresignOp {
    GetObject,
}

/// `POST …/objects/presign`. Each call mints a new URL, and no URL is
/// ever stored, so it takes no `Idempotency-Key`. The acting principal
/// needs a grant on the bucket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presign {
    pub bucket_id: String,
    pub key: String,
    pub op: PresignOp,
    pub expires_s: u32,
}

impl Validate for Presign {
    fn validate(&self) -> Result<(), Code> {
        check(valid_bucket_id(&self.bucket_id))?;
        check(valid_object_key(&self.key))?;
        check((1..=MAX_PRESIGN_EXPIRES_S).contains(&self.expires_s))
    }
}

/// A presigned URL: a bearer credential until it expires. Its `Debug`
/// never shows it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presigned {
    pub url: String,
    pub expires_at_ms: u64,
}

impl fmt::Debug for Presigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presigned")
            .field("url", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

/// The upload allowance of a rolling 24 hours.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upload24h {
    pub limit_bytes: Option<u64>,
    pub used_bytes: u64,
    pub resets_at_ms: u64,
}

/// The download allowance of the current period.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Downloads {
    pub period_start_ms: u64,
    pub allowance_bytes: Option<u64>,
    pub used_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenUploads {
    pub count: u64,
    pub limit: u64,
}

/// `GET …/usage`. A `null` part is not built yet; a caller answers it as
/// used 0 with no limit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub as_of_ms: u64,
    pub stored_bytes: u64,
    pub object_count: u64,
    pub storage_limit_bytes: Option<u64>,
    pub upload_24h: Option<Upload24h>,
    pub downloads: Option<Downloads>,
    pub open_uploads: OpenUploads,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DayStatus {
    Provisional,
    Final,
    UnderReview,
}

/// One day of usage. The list is empty until velmora builds the days.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageDay {
    pub day: Day,
    pub status: DayStatus,
    pub peak_stored_bytes: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub requests_approx: u64,
}

/// The usage of one bucket; `bucket` is its name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketUsage {
    pub bucket_id: String,
    pub bucket: String,
    pub stored_bytes: u64,
    pub object_count: u64,
    pub as_of_ms: u64,
}

// ---------------------------------------------------------------------------
// Events and pages
// ---------------------------------------------------------------------------

/// The event types velmora writes today. A caller passes a type it does
/// not know on: the list grows without a breaking change.
pub const EVENT_TYPES: [&str; 16] = [
    "bucket.created",
    "bucket.deleted",
    "key.created",
    "key.updated",
    "key.disabled",
    "key.revoked",
    "principal.created",
    "principal.updated",
    "principal.revoked",
    "tenant.suspended",
    "tenant.resumed",
    "tenant.deletion_scheduled",
    "tenant.deletion_cancelled",
    "presign.write",
    "presign.read_hour",
    "presign.refused",
];

/// One event of a tenant. `type` matches
/// [`valid_event_type`](crate::ids::valid_event_type). `data` names
/// `bucket_id` and `bucket` (the name) where a bucket is concerned, and
/// `key_id` or `principal_id` where a credential is. It never carries a
/// secret or a URL. `kofra-api` builds its id as `evt_<epoch>x<seq>`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub epoch: u64,
    pub seq: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub at_ms: u64,
    pub data: Map<String, Value>,
}

/// `GET …/events`: oldest first. `position` is never `null`: the last
/// item's position, or `after` itself when nothing follows it; without
/// `after` and with nothing returned, the feed's current head.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventPage {
    pub items: Vec<Event>,
    pub position: String,
}

/// One page of a list. `next` is `null` at the end; otherwise it is the
/// `after` of the next page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<String>,
}
