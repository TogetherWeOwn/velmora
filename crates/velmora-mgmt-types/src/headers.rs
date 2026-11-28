//! The header names of the contract.
//!
//! - [`AUTHORIZATION`]: `Bearer <service token>`. `kofra-api` picks the
//!   token class (standard or confirmed); the plane checks the scope.
//! - [`ACTING_OWNER_REF`]: the member who acts, by `owner_ref`
//!   ([`crate::ids::valid_owner_ref`]). Required on every write except
//!   tenant create and a principal create with an empty grant list, and
//!   on `objects/list` and `objects/presign`. The root unit resolves it to
//!   a principal in its own key rows, in the transaction of the call:
//!   none answers `403 acting_principal_unknown`; one that is not `active`
//!   answers `403 acting_principal_inactive`; one whose opening record the
//!   directory has not acknowledged yet answers `503 service_unavailable`
//!   for an opening write, `objects/list` and `objects/presign`, and lets a
//!   closing call proceed. The directory's copy of `owner_ref` is never
//!   used to resolve it.
//! - [`IDEMPOTENCY_KEY`]: required on every write except
//!   `objects/presign` ([`crate::ids::valid_idempotency_key`]); missing,
//!   it answers `400 idempotency_key_required`. See [`crate::idem`].
//! - [`RETRY_AFTER`]: seconds, on the answers whose code says so
//!   ([`crate::codes::Code::retry_after`]).

/// `Authorization: Bearer <service token>`.
pub const AUTHORIZATION: &str = "Authorization";

/// The acting member, by `owner_ref`.
pub const ACTING_OWNER_REF: &str = "Kofra-Acting-Owner-Ref";

/// The caller's key for a write.
pub const IDEMPOTENCY_KEY: &str = "Idempotency-Key";

/// Seconds to wait, on a "not now" answer.
pub const RETRY_AFTER: &str = "Retry-After";

/// `application/json`: every body of the plane, both ways.
pub const JSON: &str = "application/json";
