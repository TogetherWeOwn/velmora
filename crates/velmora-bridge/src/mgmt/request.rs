//! What a call takes from the request beyond its path and token: the
//! acting member, the `Idempotency-Key` and the query string. Checked
//! after the [gate](crate::mgmt::gate), so nothing of this reaches a
//! caller that has no valid token, and before any handler reads a store.
//!
//! The forms and names are the contract's ([`velmora_mgmt_types`]):
//!
//! - **`Kofra-Acting-Owner-Ref`** is required on every write but tenant
//!   create and principal create, and on `objects/list` and
//!   `objects/presign`. A principal create with grants needs it too; its
//!   handler checks that once it has read the body. Tenant create refuses
//!   it: no member of a tenant that does not exist yet can act. A value
//!   of the wrong form answers `400 bad_request` wherever it is sent.
//! - **`Idempotency-Key`** is required on every write but
//!   `objects/presign` (`400 idempotency_key_required` without it).
//!   `objects/list` is a read, though it is a `POST`. A value of the wrong
//!   form answers `400 bad_request`; on a read, the key is not used.
//! - **The query** is parsed for the call ([`CallQuery`]). A call that
//!   takes none refuses one. A parameter a call does not take, a repeated
//!   one, a value that does not decode, a `limit` out of 1 to 1,000 and a
//!   hold out of 7 to 3,650 days answer `400 bad_request`. On the lists
//!   of the contract, an `after` that is not that list's position answers
//!   `400 invalid_position`.
//!
//! A header that came twice reaches here joined by `, `, which is no
//! valid form of either, so it is refused.

use velmora_mgmt_types::ids::{valid_external_ref, valid_idempotency_key, valid_owner_ref};
use velmora_mgmt_types::position::{DayPosition, EventPosition, KeyPosition, NamePosition};
use velmora_mgmt_types::query::{
    decode, parse_hold_days, BucketQuery, KeyQuery, List, UsageDaysQuery,
};
use velmora_mgmt_types::Code;

use crate::mgmt::route::Call;

/// What a call's handler reads besides its path: checked and parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    /// `Kofra-Acting-Owner-Ref`, of its form; `None` when absent.
    pub acting: Option<String>,
    /// `Idempotency-Key` of a write, of its form. `None` on a read and on
    /// `objects/presign`, which keep no record of it.
    pub idempotency_key: Option<String>,
    pub query: CallQuery,
}

/// The query of a call, parsed for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallQuery {
    /// The call takes no query, and none came.
    None,
    /// `GET /v1/tenants`: `?external_ref=`, if given.
    TenantList { external_ref: Option<String> },
    /// `DELETE /v1/tenants/{t}?hold_days=`.
    HoldDays(u32),
    /// `GET …/buckets`: a page, or the name lookup.
    Buckets(BucketQuery),
    /// `GET …/keys`.
    Keys(KeyQuery),
    /// `GET …/usage/days`.
    UsageDays(UsageDaysQuery),
    /// Any other list: `?after=&limit=`.
    List(List),
}

impl Call {
    /// A write: every call but the reads (`GET`) and `objects/list`, which
    /// is a read sent as a `POST`. `objects/presign` is a write that keeps
    /// no record (no `Idempotency-Key`).
    pub fn writes(&self) -> bool {
        use Call::*;
        !matches!(
            self,
            TenantList
                | TenantRead { .. }
                | TenantReach { .. }
                | TenantEvents { .. }
                | BucketList { .. }
                | BucketRead { .. }
                | KeyList { .. }
                | KeyRead { .. }
                | ObjectList { .. }
                | UploadParts { .. }
                | Usage { .. }
                | UsageDays { .. }
                | UsageDownloads { .. }
                | UsageBuckets { .. }
                | Events
        )
    }

    /// Whether the call needs `Kofra-Acting-Owner-Ref` whatever its body
    /// says. Principal create needs it only with grants (its handler).
    pub fn needs_acting(&self) -> bool {
        match self {
            Call::TenantCreate | Call::PrincipalCreate { .. } => false,
            Call::ObjectList { .. } | Call::Presign { .. } => true,
            call => call.writes(),
        }
    }

    /// Whether the call needs an `Idempotency-Key`.
    pub fn needs_idempotency_key(&self) -> bool {
        self.writes() && !matches!(self, Call::Presign { .. })
    }
}

/// Checks the headers and the query of an admitted `call`. `query` is the
/// part of the request target after `?` (empty without one).
pub fn check(
    call: &Call,
    query: &str,
    acting: Option<&str>,
    idempotency_key: Option<&str>,
) -> Result<Checked, Code> {
    let acting = match acting {
        Some(v) if !valid_owner_ref(v) => return Err(Code::BadRequest),
        Some(_) if matches!(call, Call::TenantCreate) => return Err(Code::BadRequest),
        Some(v) => Some(v.to_string()),
        None if call.needs_acting() => return Err(Code::BadRequest),
        None => None,
    };
    let idempotency_key = match idempotency_key {
        Some(v) if !valid_idempotency_key(v) => return Err(Code::BadRequest),
        Some(v) if call.needs_idempotency_key() => Some(v.to_string()),
        Some(_) => None,
        None if call.needs_idempotency_key() => return Err(Code::IdempotencyKeyRequired),
        None => None,
    };
    Ok(Checked {
        acting,
        idempotency_key,
        query: call_query(call, query)?,
    })
}

fn call_query(call: &Call, query: &str) -> Result<CallQuery, Code> {
    use Call::*;
    Ok(match call {
        TenantList => CallQuery::TenantList {
            external_ref: tenant_list(query)?,
        },
        TenantDelete { .. } => CallQuery::HoldDays(parse_hold_days(query)?),
        BucketList { .. } => {
            let q = BucketQuery::parse(query)?;
            if let BucketQuery::Page(list) = &q {
                list.after_as(NamePosition::parse)?;
            }
            CallQuery::Buckets(q)
        }
        KeyList { .. } => {
            let q = KeyQuery::parse(query)?;
            q.list.after_as(KeyPosition::parse)?;
            CallQuery::Keys(q)
        }
        UsageDays { .. } => {
            let q = UsageDaysQuery::parse(query)?;
            q.list.after_as(DayPosition::parse)?;
            CallQuery::UsageDays(q)
        }
        UsageBuckets { .. } => {
            let list = List::parse(query)?;
            list.after_as(NamePosition::parse)?;
            CallQuery::List(list)
        }
        TenantEvents { .. } => {
            let list = List::parse(query)?;
            list.after_as(EventPosition::parse)?;
            CallQuery::List(list)
        }
        // Not calls of the contract: their handlers parse their position.
        Events | UsageDownloads { .. } | UploadParts { .. } => CallQuery::List(List::parse(query)?),
        _ if query.is_empty() => CallQuery::None,
        _ => return Err(Code::BadRequest),
    })
}

/// `?external_ref=<ref>` or nothing.
fn tenant_list(query: &str) -> Result<Option<String>, Code> {
    if query.is_empty() {
        return Ok(None);
    }
    let value = query
        .strip_prefix("external_ref=")
        .and_then(decode)
        .ok_or(Code::BadRequest)?;
    if !valid_external_ref(&value) {
        return Err(Code::BadRequest);
    }
    Ok(Some(value))
}
