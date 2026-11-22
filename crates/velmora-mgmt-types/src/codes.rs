//! The error codes of the management plane, with their statuses and the
//! `kofra-api` error each one maps to.
//!
//! An error answer is `{"code": "<code>"}` ([`ErrorBody`]) and, where the
//! table says so, a `Retry-After` header. It carries nothing of the
//! request. A code that a caller does not know (a newer velmora) is
//! [`KofraMapping::Upstream`]. A new code is a change of this crate, and
//! the caller maps it in the change that takes that crate version.
//!
//! | Code | Status | Retry-After | When | `kofra-api` |
//! |---|---|---|---|---|
//! | `bad_request`, `grant_limits_not_served`, `idempotency_key_required` | 400 | — | malformed or not served | `Upstream` |
//! | `invalid_position` | 400 | — | a position that does not parse | `InvalidCursor` |
//! | `unauthenticated` | 401 | — | token | `Upstream` |
//! | `insufficient_scope`, `internal_key_refused`, `acting_principal_unknown`, `acting_principal_inactive` | 403 | — | wrong token class; the tenant's internal key; the acting header | `Upstream` |
//! | `grant_not_held` | 403 | — | the subset rule: a grant wider than the acting principal's, or an object call with no grant | `GrantNotHeld` |
//! | `not_found`, `method_not_allowed` | 404, 405 | — | no such call | `Upstream` |
//! | `tenant_not_found`, `principal_not_found` | 404 | — | an id the tenant does not have | `Upstream` |
//! | `bucket_not_found`, `key_not_found` | 404 | — | | same-named variant |
//! | `bucket_already_exists`, `bucket_not_empty`, `key_limit_reached`, `grant_limit_reached`, `feed_reset`, `deletion_already_requested`, `deletion_not_requested`, `deletion_final` | 409 | — | | same-named variant |
//! | `deletion_replayed` | 409 | — | the key of a deletion that was undone | `IdempotencyKeyReused` |
//! | `tenant_read_only` | 409 | — | an opening write while suspended `read_only`; never the undo of a deletion | `AccountReadOnly` |
//! | `tenant_unavailable` | 409 | — | while `blocked`, any write but the hold and deletion changes; any call while `shredding` or `shredded`; an opening write while `deleting`. Never a revoke, a disable, a narrowing or the undo of a deletion | `AccountUnavailable` |
//! | `tenant_restoring` | 409 | yes | a `restoring` entry is set | `Unavailable` |
//! | `key_changed` | 409 | — | `if_seq` is not the key's `seq` | re-read and retry at most 3 times, then `Unavailable { retry_after: 1 }` |
//! | `principal_exists` | 409 | — | another principal for that `owner_ref` | `Upstream` |
//! | `actor_not_permitted` | 403 | — | a deletion or hold this actor class did not set | `DeletionNotCancellable` |
//! | `key_moved` | 409 | yes | the key belongs to tenant 0 for now | `Unavailable` |
//! | `external_ref_retired` | 409 | — | the `external_ref` names a shredded tenant | `TenancyError::Gone` |
//! | `idempotency_key_in_use` | 409 | yes | the same request is still being applied | `IdempotencyKeyInUse { retry_after }` |
//! | `idempotency_key_reused` | 422 | — | the key with another request | `IdempotencyKeyReused` |
//! | `cap_reached` | 429 | yes | a per-tenant or per-token cap | `Busy` |
//! | `service_unavailable` | 503 | yes | the `m/rst/` bound, the directory gate, a unit that cannot be reached | `Unavailable` |
//! | `internal_error` | 500 | — | | `Upstream` |
//!
//! **Never stored as a final answer.** Every code with a `Retry-After`
//! ([`Code::retry_after`]) is a "not now": `kofra-api` releases its own
//! idempotency claim and passes `Retry-After` on, so the client's retry
//! reaches storage again.
//!
//! **Gate codes stay `Upstream`.** `unauthenticated`, `insufficient_scope`,
//! `not_found`, `method_not_allowed` and `bad_request` each mean a
//! `kofra-api` bug or a deploy fault, never a client mistake: the client
//! sees `internal_error` and `kofra-api` pages.

use serde::{Deserialize, Serialize};

/// One error code of the plane. See the [module](self) for the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    BadRequest,
    GrantLimitsNotServed,
    IdempotencyKeyRequired,
    InvalidPosition,
    Unauthenticated,
    InsufficientScope,
    InternalKeyRefused,
    ActingPrincipalUnknown,
    ActingPrincipalInactive,
    GrantNotHeld,
    NotFound,
    MethodNotAllowed,
    TenantNotFound,
    PrincipalNotFound,
    BucketNotFound,
    KeyNotFound,
    BucketAlreadyExists,
    BucketNotEmpty,
    KeyLimitReached,
    GrantLimitReached,
    FeedReset,
    DeletionAlreadyRequested,
    DeletionNotRequested,
    DeletionFinal,
    DeletionReplayed,
    TenantReadOnly,
    TenantUnavailable,
    TenantRestoring,
    KeyChanged,
    PrincipalExists,
    ActorNotPermitted,
    KeyMoved,
    ExternalRefRetired,
    IdempotencyKeyInUse,
    IdempotencyKeyReused,
    CapReached,
    ServiceUnavailable,
    InternalError,
}

/// The `kofra-api` error a code maps to: a variant of its `StorageError`
/// (same name), or a rule of its adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KofraMapping {
    /// `internal_error` to the client, and a page in `kofra-api`.
    Upstream,
    InvalidCursor,
    GrantNotHeld,
    BucketNotFound,
    KeyNotFound,
    BucketAlreadyExists,
    BucketNotEmpty,
    KeyLimitReached,
    GrantLimitReached,
    FeedReset,
    DeletionAlreadyRequested,
    DeletionNotRequested,
    DeletionFinal,
    DeletionNotCancellable,
    IdempotencyKeyReused,
    IdempotencyKeyInUse,
    AccountReadOnly,
    AccountUnavailable,
    /// `Unavailable { retry_after }`, with the answer's `Retry-After`.
    Unavailable,
    /// `Busy { retry_after }`, with the answer's `Retry-After`.
    Busy,
    /// The adapter re-reads the key, merges again and retries, at most 3
    /// times; then `Unavailable { retry_after: 1 }`.
    RereadKey,
    /// `TenancyError::Gone` (tenant create only).
    TenancyGone,
}

/// What `kofra-api`'s `Tenancy` port (sign-up and its retry cron) does
/// with a code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TenancyMapping {
    /// `Retry`.
    Retry,
    /// `Retry`, and a page: the same `Idempotency-Key` came with another
    /// request, which is a `kofra-api` fault.
    RetryAndPage,
    /// `Gone`: the workspace is closed.
    Gone,
}

impl Code {
    /// Every code, in the order of the table.
    pub const ALL: [Code; 38] = [
        Code::BadRequest,
        Code::GrantLimitsNotServed,
        Code::IdempotencyKeyRequired,
        Code::InvalidPosition,
        Code::Unauthenticated,
        Code::InsufficientScope,
        Code::InternalKeyRefused,
        Code::ActingPrincipalUnknown,
        Code::ActingPrincipalInactive,
        Code::GrantNotHeld,
        Code::NotFound,
        Code::MethodNotAllowed,
        Code::TenantNotFound,
        Code::PrincipalNotFound,
        Code::BucketNotFound,
        Code::KeyNotFound,
        Code::BucketAlreadyExists,
        Code::BucketNotEmpty,
        Code::KeyLimitReached,
        Code::GrantLimitReached,
        Code::FeedReset,
        Code::DeletionAlreadyRequested,
        Code::DeletionNotRequested,
        Code::DeletionFinal,
        Code::DeletionReplayed,
        Code::TenantReadOnly,
        Code::TenantUnavailable,
        Code::TenantRestoring,
        Code::KeyChanged,
        Code::PrincipalExists,
        Code::ActorNotPermitted,
        Code::KeyMoved,
        Code::ExternalRefRetired,
        Code::IdempotencyKeyInUse,
        Code::IdempotencyKeyReused,
        Code::CapReached,
        Code::ServiceUnavailable,
        Code::InternalError,
    ];

    /// The code as it is on the wire.
    pub fn as_str(self) -> &'static str {
        use Code::*;
        match self {
            BadRequest => "bad_request",
            GrantLimitsNotServed => "grant_limits_not_served",
            IdempotencyKeyRequired => "idempotency_key_required",
            InvalidPosition => "invalid_position",
            Unauthenticated => "unauthenticated",
            InsufficientScope => "insufficient_scope",
            InternalKeyRefused => "internal_key_refused",
            ActingPrincipalUnknown => "acting_principal_unknown",
            ActingPrincipalInactive => "acting_principal_inactive",
            GrantNotHeld => "grant_not_held",
            NotFound => "not_found",
            MethodNotAllowed => "method_not_allowed",
            TenantNotFound => "tenant_not_found",
            PrincipalNotFound => "principal_not_found",
            BucketNotFound => "bucket_not_found",
            KeyNotFound => "key_not_found",
            BucketAlreadyExists => "bucket_already_exists",
            BucketNotEmpty => "bucket_not_empty",
            KeyLimitReached => "key_limit_reached",
            GrantLimitReached => "grant_limit_reached",
            FeedReset => "feed_reset",
            DeletionAlreadyRequested => "deletion_already_requested",
            DeletionNotRequested => "deletion_not_requested",
            DeletionFinal => "deletion_final",
            DeletionReplayed => "deletion_replayed",
            TenantReadOnly => "tenant_read_only",
            TenantUnavailable => "tenant_unavailable",
            TenantRestoring => "tenant_restoring",
            KeyChanged => "key_changed",
            PrincipalExists => "principal_exists",
            ActorNotPermitted => "actor_not_permitted",
            KeyMoved => "key_moved",
            ExternalRefRetired => "external_ref_retired",
            IdempotencyKeyInUse => "idempotency_key_in_use",
            IdempotencyKeyReused => "idempotency_key_reused",
            CapReached => "cap_reached",
            ServiceUnavailable => "service_unavailable",
            InternalError => "internal_error",
        }
    }

    /// The code named `s`; `None` for a code this crate does not know,
    /// which a caller treats as [`KofraMapping::Upstream`].
    pub fn parse(s: &str) -> Option<Code> {
        Code::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// The HTTP status of an answer with this code.
    pub fn status(self) -> u16 {
        use Code::*;
        match self {
            BadRequest | GrantLimitsNotServed | IdempotencyKeyRequired | InvalidPosition => 400,
            Unauthenticated => 401,
            InsufficientScope
            | InternalKeyRefused
            | ActingPrincipalUnknown
            | ActingPrincipalInactive
            | GrantNotHeld
            | ActorNotPermitted => 403,
            NotFound | TenantNotFound | PrincipalNotFound | BucketNotFound | KeyNotFound => 404,
            MethodNotAllowed => 405,
            BucketAlreadyExists
            | BucketNotEmpty
            | KeyLimitReached
            | GrantLimitReached
            | FeedReset
            | DeletionAlreadyRequested
            | DeletionNotRequested
            | DeletionFinal
            | DeletionReplayed
            | TenantReadOnly
            | TenantUnavailable
            | TenantRestoring
            | KeyChanged
            | PrincipalExists
            | KeyMoved
            | ExternalRefRetired
            | IdempotencyKeyInUse => 409,
            IdempotencyKeyReused => 422,
            CapReached => 429,
            InternalError => 500,
            ServiceUnavailable => 503,
        }
    }

    /// Whether an answer with this code carries `Retry-After`. Each such
    /// answer is a "not now" that `kofra-api` never stores as final.
    pub fn retry_after(self) -> bool {
        matches!(
            self,
            Code::TenantRestoring
                | Code::KeyMoved
                | Code::IdempotencyKeyInUse
                | Code::CapReached
                | Code::ServiceUnavailable
        )
    }

    /// The `kofra-api` storage error this code maps to.
    pub fn kofra(self) -> KofraMapping {
        use Code::*;
        use KofraMapping as K;
        match self {
            BadRequest
            | GrantLimitsNotServed
            | IdempotencyKeyRequired
            | Unauthenticated
            | InsufficientScope
            | InternalKeyRefused
            | ActingPrincipalUnknown
            | ActingPrincipalInactive
            | NotFound
            | MethodNotAllowed
            | TenantNotFound
            | PrincipalNotFound
            | PrincipalExists
            | InternalError => K::Upstream,
            InvalidPosition => K::InvalidCursor,
            GrantNotHeld => K::GrantNotHeld,
            BucketNotFound => K::BucketNotFound,
            KeyNotFound => K::KeyNotFound,
            BucketAlreadyExists => K::BucketAlreadyExists,
            BucketNotEmpty => K::BucketNotEmpty,
            KeyLimitReached => K::KeyLimitReached,
            GrantLimitReached => K::GrantLimitReached,
            FeedReset => K::FeedReset,
            DeletionAlreadyRequested => K::DeletionAlreadyRequested,
            DeletionNotRequested => K::DeletionNotRequested,
            DeletionFinal => K::DeletionFinal,
            DeletionReplayed | IdempotencyKeyReused => K::IdempotencyKeyReused,
            TenantReadOnly => K::AccountReadOnly,
            TenantUnavailable => K::AccountUnavailable,
            TenantRestoring | KeyMoved | ServiceUnavailable => K::Unavailable,
            KeyChanged => K::RereadKey,
            ActorNotPermitted => K::DeletionNotCancellable,
            ExternalRefRetired => K::TenancyGone,
            IdempotencyKeyInUse => K::IdempotencyKeyInUse,
            CapReached => K::Busy,
        }
    }

    /// What the `Tenancy` port does with this code: `Gone` for
    /// `external_ref_retired`, a `Retry` with a page for a reused key,
    /// and `Retry` for every other code.
    pub fn tenancy(self) -> TenancyMapping {
        match self.kofra() {
            KofraMapping::TenancyGone => TenancyMapping::Gone,
            KofraMapping::IdempotencyKeyReused => TenancyMapping::RetryAndPage,
            _ => TenancyMapping::Retry,
        }
    }

    /// The error body of this code.
    pub fn body(self) -> ErrorBody {
        ErrorBody {
            code: self.as_str().to_string(),
        }
    }
}

/// The body of every error answer: the code and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
}

impl ErrorBody {
    /// The code of this body; `None` for a code this crate does not know.
    pub fn known(&self) -> Option<Code> {
        Code::parse(&self.code)
    }
}
