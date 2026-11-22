//! `Idempotency-Key`: the scope, the fingerprint, and what each call
//! class keeps.
//!
//! The header ([`crate::headers::IDEMPOTENCY_KEY`]) is required on every
//! write of the plane except `objects/presign`, which keeps no record of
//! its key: each call mints a new URL, and a URL is a bearer credential
//! that is never stored. `objects/list` is a read, though it is a `POST`.
//!
//! **Scope:** (tenant, the acting principal's resolved **id** or none,
//! [`key_hash`] of the key). **Fingerprint:** [`fingerprint`] over the
//! token class, method, path with its query, acting header and body. For
//! `PATCH …/keys/{k}` the body is [`KeyUpdate::fingerprint_body`]
//! (without `if_seq`).
//!
//! What keeps the key, per call class:
//!
//! 1. **Capped opening calls** (create a bucket, a key or a principal; a
//!    widening grant change): the root unit's reservation row holds the
//!    scope, the fingerprint, the state (`reserved` or `applied`) and,
//!    once applied, the answer (status and body, at most
//!    [`MAX_STORED_ANSWER_BYTES`], **never a secret**). It is kept 24 h
//!    after the apply; an unapplied reservation is released after 1 h.
//!    - same scope and fingerprint, `applied`: the stored answer, with
//!      `secret_access_key: null` for a key;
//!    - same scope and fingerprint, `reserved`: `409
//!      idempotency_key_in_use` with `Retry-After: 30` if a record names
//!      the reservation (the finisher applies it); otherwise the call is
//!      admitted again under the same reservation. A put that loses to a
//!      record of its own reservation answers from that record and never
//!      applies its own bytes;
//!    - same scope, another fingerprint: `422 idempotency_key_reused`,
//!      with no reservation and no record.
//!
//!    A refused call (`4xx`) leaves no row.
//! 2. **Tenant create:** `m/tref/` (create or adopt by `external_ref`).
//! 3. **Closing calls** (revoke, disable, narrowing, bucket delete, the
//!    tenant delete request): the chain. A tenant delete whose key hash
//!    equals the set deletion's answers `200` with the tenant. Otherwise a
//!    reused key on another closing request is not refused: that request
//!    is evaluated on its own. A repeated key revoke answers `204`; a
//!    repeated bucket delete answers `404 bucket_not_found`.
//! 4. **Tenant restore:** bound to the `deletion_seq` it undoes
//!    ([`crate::wire::TenantRestore`]). The key of an undone deletion,
//!    sent again as a delete, answers `409 deletion_replayed`.
//! 5. **Rename and grant changes that set what the key already has:** the
//!    state. `200`, and nothing is written.
//!
//! **Known limit:** if a reservation's apply is delayed past the 1 h
//! release, a retry after that can make a second key or bucket. The extra
//! key has a secret nobody holds and counts against the key cap; nothing
//! opens.
//!
//! [`KeyUpdate::fingerprint_body`]: crate::wire::KeyUpdate::fingerprint_body
//! [`MAX_STORED_ANSWER_BYTES`]: crate::wire::MAX_STORED_ANSWER_BYTES

use sha2::{Digest, Sha256};

/// The class of the service token a request came with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenClass {
    Standard,
    Confirmed,
}

impl TokenClass {
    /// The class as the fingerprint takes it.
    pub fn as_str(self) -> &'static str {
        match self {
            TokenClass::Standard => "standard",
            TokenClass::Confirmed => "confirmed",
        }
    }
}

/// SHA-256 of an `Idempotency-Key`: what the scope and a deletion's
/// record keep, never the key itself.
pub fn key_hash(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// The fingerprint of a request: SHA-256 over five fields, each as its
/// length in bytes (8 bytes, big-endian) and then its bytes:
///
/// 1. the token class ([`TokenClass::as_str`]);
/// 2. the method, as sent (`POST`);
/// 3. the path with its query, as sent (`/v1/tenants/t_…/keys`);
/// 4. the value of `Kofra-Acting-Owner-Ref`, empty when absent;
/// 5. the body bytes (for `PATCH …/keys/{k}`:
///    [`KeyUpdate::fingerprint_body`](crate::wire::KeyUpdate::fingerprint_body)).
pub fn fingerprint(
    class: TokenClass,
    method: &str,
    path_and_query: &str,
    acting: Option<&str>,
    body: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    for field in [
        class.as_str().as_bytes(),
        method.as_bytes(),
        path_and_query.as_bytes(),
        acting.unwrap_or("").as_bytes(),
        body,
    ] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    h.finalize().into()
}

/// Lowercase hex of a hash, for a log line or a test.
pub fn hex(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 0xf)] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/v1/tenants/t_1a2b3c4d5e6f7a8b/keys";

    #[test]
    fn the_fingerprint_is_fixed() {
        // A change to this value breaks every stored reservation row: it
        // is a breaking change of the crate.
        let f = fingerprint(
            TokenClass::Standard,
            "POST",
            PATH,
            Some("usr_01HZX"),
            br#"{"kind":"s3","grants":[]}"#,
        );
        assert_eq!(
            hex(&f),
            "02713e03b35d0b1fb2f84ebc1ef2281ed80405d5a8bb5cef608cd659ec394d75"
        );
    }

    #[test]
    fn every_field_binds_the_fingerprint() {
        let base = fingerprint(TokenClass::Standard, "POST", PATH, Some("u1"), b"{}");
        let others = [
            fingerprint(TokenClass::Confirmed, "POST", PATH, Some("u1"), b"{}"),
            fingerprint(TokenClass::Standard, "PATCH", PATH, Some("u1"), b"{}"),
            fingerprint(
                TokenClass::Standard,
                "POST",
                "/v1/tenants/t_1a2b3c4d5e6f7a8b/keys?x",
                Some("u1"),
                b"{}",
            ),
            fingerprint(TokenClass::Standard, "POST", PATH, Some("u2"), b"{}"),
            fingerprint(TokenClass::Standard, "POST", PATH, None, b"{}"),
            fingerprint(TokenClass::Standard, "POST", PATH, Some("u1"), b"{ }"),
        ];
        for o in others {
            assert_ne!(o, base);
        }
        // An absent header is the empty value.
        assert_eq!(
            fingerprint(TokenClass::Standard, "POST", PATH, None, b"{}"),
            fingerprint(TokenClass::Standard, "POST", PATH, Some(""), b"{}")
        );
    }

    #[test]
    fn the_length_prefix_keeps_fields_apart() {
        // Without the prefix both would hash the bytes "POST/v1/x".
        assert_ne!(
            fingerprint(TokenClass::Standard, "POST", "/v1/x", None, b""),
            fingerprint(TokenClass::Standard, "POS", "T/v1/x", None, b"")
        );
        assert_ne!(
            fingerprint(TokenClass::Standard, "POST", "/v1/x", Some("a"), b""),
            fingerprint(TokenClass::Standard, "POST", "/v1/x", None, b"a")
        );
    }

    #[test]
    fn the_key_hash_is_sha256() {
        assert_eq!(
            hex(&key_hash("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
