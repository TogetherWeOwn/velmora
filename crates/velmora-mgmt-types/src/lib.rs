//! The wire contract of the velmora management plane, as `kofra-api`
//! calls it.
//!
//! This crate is the contract: paths ([`paths`]), request and answer
//! types ([`wire`]), codes ([`codes`]), positions ([`position`]), query
//! strings ([`query`]), header names ([`headers`]), id forms ([`ids`]) and
//! the request fingerprint ([`idem`]), with one example per call
//! ([`examples`]). A caller depends on it at a pinned velmora commit. A
//! path and its types change together, in one change of this crate, and
//! a change that breaks a caller bumps its major version.
//!
//! **Transport.** A service binding to velmora's management entry point,
//! `Authorization: Bearer <service token>`, JSON bodies (UTF-8,
//! `Content-Type: application/json`). Unknown body fields are refused
//! with `400 bad_request`. Times are Unix ms integers, and every integer
//! is within ±(2^53 − 1) ([`ids::MAX_SAFE_INTEGER`]). An error is
//! `{"code": "<code>"}` ([`codes::ErrorBody`]), with `Retry-After` where
//! the code says so, and nothing of the request.
//!
//! **Ids, never names, in paths and bodies.** A caller that knows a bucket
//! by name resolves it first with the name lookup
//! (`GET /v1/tenants/{t}/buckets?name=`, [`query::BucketQuery`]). A
//! resolved id that went stale (the bucket was deleted, or deleted and
//! made again) answers `404 bucket_not_found`; it never reaches the new
//! bucket. Answers name both: buckets `{id, name}`, grants `{bucket_id,
//! bucket_name}` (`null` for a bucket that is gone) and events
//! (`data.bucket_id`, `data.bucket`).
//!
//! **Who acts.** [`headers::ACTING_OWNER_REF`] names the member; the root
//! unit resolves it to a principal. Velmora takes grants, never a role:
//! the caller maps a role to a grant list. A grant asked for with the
//! header must be held by the acting principal (`403 grant_not_held`).
//!
//! **Idempotency.** See [`idem`]: the scope, the fingerprint, and which
//! store keeps a key for which call. A replay never returns a secret: a
//! key create answers `secret_access_key: null` the second time.
//!
//! **Lists.** `?after=&limit=` (`limit` 1 to 1,000, default 100) and
//! `{items, next}`; see [`query`] and [`position`].
//!
//! **Rollout.** The caller keeps its stub for every call until velmora
//! serves all of them on the deployment it binds to, and then switches
//! reads and writes together. There is no per-call mix.

pub mod codes;
pub mod examples;
pub mod headers;
pub mod idem;
pub mod ids;
pub mod paths;
pub mod position;
pub mod query;
pub mod wire;

pub use codes::{Code, ErrorBody, KofraMapping, TenancyMapping};
pub use idem::{fingerprint, key_hash, TokenClass};
pub use wire::{parse_request, Validate};
