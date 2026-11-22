//! The forms of ids, names and header values. A value that fails its
//! form answers `400 bad_request` in a body or a header, and `404
//! not_found` in a path (no call has that path).

/// The largest integer on the wire: every integer is within
/// ±(2^53 − 1), so a JavaScript caller reads it exactly.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Tenant 0: the operator's tenant. It is not a tenant of this plane, and
/// a path that names it answers like a path that names no tenant.
pub const TENANT_ZERO: &str = "t_0000000000000000";

/// The most bytes in an access key id.
pub const MAX_KEY_ID_BYTES: usize = 128;

/// The most bytes in a principal id.
pub const MAX_PRINCIPAL_ID_BYTES: usize = 64;

/// The most characters in a key name.
pub const MAX_KEY_NAME_CHARS: usize = 64;

/// The most bytes in an object key.
pub const MAX_OBJECT_KEY_BYTES: usize = 1024;

fn hex16(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A tenant id of this plane: `t_` and 16 lowercase hex characters, and
/// not [`TENANT_ZERO`].
pub fn valid_tenant_id(s: &str) -> bool {
    s.strip_prefix("t_").is_some_and(hex16) && s != TENANT_ZERO
}

/// A bucket id: `b_` and 16 lowercase hex characters.
pub fn valid_bucket_id(s: &str) -> bool {
    s.strip_prefix("b_").is_some_and(hex16)
}

/// An access key id: 1 to 128 ASCII letters or digits.
pub fn valid_key_id(s: &str) -> bool {
    (1..=MAX_KEY_ID_BYTES).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A principal id. Opaque to a caller: 1 to 64 ASCII letters, digits,
/// `_` or `-`.
pub fn valid_principal_id(s: &str) -> bool {
    (1..=MAX_PRINCIPAL_ID_BYTES).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A bucket name of this plane: 3 to 63 of `a-z`, `0-9` and `-`,
/// starting and ending with a letter or a digit (S3's rule without dots).
pub fn valid_bucket_name(s: &str) -> bool {
    let b = s.as_bytes();
    let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (3..=63).contains(&b.len())
        && b.iter().all(|c| edge(c) || *c == b'-')
        && b.first().is_some_and(edge)
        && b.last().is_some_and(edge)
}

/// A key name: 1 to 64 characters, none of them a control character.
pub fn valid_key_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=MAX_KEY_NAME_CHARS).contains(&n) && !s.chars().any(char::is_control)
}

/// An object key: 1 to 1,024 bytes of UTF-8.
pub fn valid_object_key(s: &str) -> bool {
    (1..=MAX_OBJECT_KEY_BYTES).contains(&s.len())
}

/// An `owner_ref` (the value of [`crate::headers::ACTING_OWNER_REF`] and
/// of a principal's `owner_ref`): 1 to 128 of `[A-Za-z0-9_:-]`.
pub fn valid_owner_ref(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-'))
}

/// An `external_ref` (the workspace id at tenant create): the form of an
/// `owner_ref`. It must be a random id, never personal data: its hash
/// outlives the tenant's shred.
pub fn valid_external_ref(s: &str) -> bool {
    valid_owner_ref(s)
}

/// A jurisdiction or a rate class: 1 to 32 of `a-z`, `0-9` and `_`. Which
/// values are served is the registry's (an unknown one answers
/// `400 bad_request`).
pub fn valid_label(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// An `Idempotency-Key`: 1 to 255 printable ASCII characters (`!` to
/// `~`; no space), the form `kofra-api` takes from its own clients.
pub fn valid_idempotency_key(s: &str) -> bool {
    (1..=255).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// An event type: `^[a-z_]+(\.[a-z_]+)+$`.
pub fn valid_event_type(s: &str) -> bool {
    let mut parts = 0;
    for part in s.split('.') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            return false;
        }
        parts += 1;
    }
    parts >= 2
}
