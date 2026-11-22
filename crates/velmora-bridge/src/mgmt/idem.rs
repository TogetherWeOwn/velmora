//! `Idempotency-Key` for the capped opening calls (create a bucket, a key
//! or a principal; a widening grant change), through the root unit's
//! reservation (tenancy design §2.5 step 0; the contract's
//! [`velmora_mgmt_types::idem`], case 1).
//!
//! The Worker builds the [`IdemRequest`] (the hash of the key and the
//! fingerprint of the request) and sends it with the reservation ask. The
//! root unit resolves the acting principal and keys the reservation row by
//! (that principal's id, or none; the key hash), in the transaction of the
//! ask. It answers a [`Reservation`], and [`next`] turns that into what
//! the call does: go on under the reservation, or answer now.
//!
//! **No replay returns a secret.** The answer the unit keeps is made by
//! [`stored_answer`], which sets every `secret_access_key` to `null`, and
//! a replay is cleaned again by [`next`] before it is sent. The secret of
//! a key is in the first answer only. A refused call (`4xx` or `5xx`)
//! keeps no answer, so a refusal is never replayed as the answer to a
//! later request.

use serde_json::Value;
use velmora_mgmt_types::idem::{fingerprint, key_hash, TokenClass};
use velmora_mgmt_types::wire::MAX_STORED_ANSWER_BYTES;
use velmora_mgmt_types::Code;

/// `Retry-After` of `409 idempotency_key_in_use`: the delay of the
/// intent (§2.5 step 1), after which the finisher has applied the record.
pub const IN_USE_RETRY_AFTER_SECS: u32 = 30;

/// What the reservation ask carries for `Idempotency-Key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdemRequest {
    /// SHA-256 of the key: the row keeps this, never the key.
    pub key_hash: [u8; 32],
    /// The request's fingerprint.
    pub fingerprint: [u8; 32],
}

impl IdemRequest {
    /// `body` is the request body as received; for a key update, the
    /// contract's `KeyUpdate::fingerprint_body` (without `if_seq`).
    pub fn new(
        class: TokenClass,
        method: &str,
        path_and_query: &str,
        acting: Option<&str>,
        body: &[u8],
        idempotency_key: &str,
    ) -> IdemRequest {
        IdemRequest {
            key_hash: key_hash(idempotency_key),
            fingerprint: fingerprint(class, method, path_and_query, acting, body),
        }
    }
}

/// The id a reservation gets at its first admit, kept by every re-ask.
/// Every record of a reserved call carries it in its door part. The
/// Worker draws it; the unit keeps the first one (L1, #231).
pub use crate::unit::reserve::Rid;

/// What the root unit answers to a reservation ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// A new reservation, or a re-ask of a `reserved` one that no record
    /// names yet: go on under it. `keys_seq` is the key-chain head the
    /// grant check ran at; the record must be exactly `keys_seq + 1`.
    Admitted { rid: Rid, keys_seq: u64 },
    /// Same scope and fingerprint, `applied`: the answer the unit kept.
    Applied { status: u16, body: Vec<u8> },
    /// Same scope and fingerprint, `reserved`, and a record above the
    /// reservation's `keys_seq` carries its `rid`: the finisher applies it.
    InUse,
    /// Same scope, another fingerprint. No reservation, no record.
    Reused,
    /// Refused before any reservation: a full cap (`cap_reached`), a grant
    /// the acting principal does not hold (`grant_not_held`), the acting
    /// principal (`acting_principal_unknown`, `acting_principal_inactive`,
    /// or `service_unavailable` while it is held), a name that is taken.
    Refused {
        code: Code,
        retry_after: Option<u32>,
    },
}

/// The answer of a call that does not go on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// A kept answer, cleaned of every secret.
    Stored { status: u16, body: Vec<u8> },
    /// An error answer: `{"code": …}`, with `Retry-After` if set.
    Code {
        code: Code,
        retry_after: Option<u32>,
    },
}

/// What a call does after its reservation ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next {
    /// Go on: intent, record (`keys_seq + 1`), stores.
    Proceed { rid: Rid, keys_seq: u64 },
    /// Answer now.
    Reply(Reply),
}

/// What the call does with the unit's answer.
pub fn next(reservation: Reservation) -> Next {
    let code =
        |code: Code, retry_after: Option<u32>| Next::Reply(Reply::Code { code, retry_after });
    match reservation {
        Reservation::Admitted { rid, keys_seq } => Next::Proceed { rid, keys_seq },
        Reservation::Applied { status, body } => match clean(status, &body) {
            Ok(body) => Next::Reply(Reply::Stored { status, body }),
            // A kept answer that is not one this plane keeps: never sent.
            Err(_) => code(Code::InternalError, None),
        },
        Reservation::InUse => code(Code::IdempotencyKeyInUse, Some(IN_USE_RETRY_AFTER_SECS)),
        Reservation::Reused => code(Code::IdempotencyKeyReused, None),
        Reservation::Refused {
            code: c,
            retry_after,
        } => {
            // A code whose answer has `Retry-After` always carries one.
            let retry_after = match (c.retry_after(), retry_after) {
                (true, None) => Some(crate::mgmt::gate::RETRY_AFTER_SECS),
                (true, secs) => secs,
                (false, _) => None,
            };
            code(c, retry_after)
        }
    }
}

/// Why an answer is not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotStored {
    /// Not a `2xx`: a refused call keeps no answer.
    Refusal,
    /// Not a JSON object.
    NotJson,
    /// Over [`MAX_STORED_ANSWER_BYTES`] once cleaned.
    TooLarge,
}

/// The answer the root unit keeps for a capped opening call, from the
/// answer the call sends the first time: every `secret_access_key` set to
/// `null`, at most [`MAX_STORED_ANSWER_BYTES`].
pub fn stored_answer(status: u16, body: &[u8]) -> Result<Vec<u8>, NotStored> {
    clean(status, body)
}

fn clean(status: u16, body: &[u8]) -> Result<Vec<u8>, NotStored> {
    if !(200..300).contains(&status) {
        return Err(NotStored::Refusal);
    }
    let mut value: Value = serde_json::from_slice(body).map_err(|_| NotStored::NotJson)?;
    if !value.is_object() {
        return Err(NotStored::NotJson);
    }
    null_secrets(&mut value);
    let bytes = serde_json::to_vec(&value).map_err(|_| NotStored::NotJson)?;
    if bytes.len() > MAX_STORED_ANSWER_BYTES {
        return Err(NotStored::TooLarge);
    }
    Ok(bytes)
}

/// Sets every `secret_access_key`, at any depth, to `null`.
fn null_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (name, v) in map.iter_mut() {
                if name == "secret_access_key" {
                    *v = Value::Null;
                } else {
                    null_secrets(v);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(null_secrets),
        _ => {}
    }
}
