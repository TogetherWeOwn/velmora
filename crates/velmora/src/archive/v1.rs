//! Portable archive identity atoms.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backend {
    Nntp,
    S3,
}

/// An access-controlled identifier or credential *reference*, never a secret.
/// Redacted in diagnostics; callers must also avoid logging serialized records.
/// The 1024-byte limit applies to accepted values, not deserializer allocations;
/// callers must bound untrusted input before deserialization.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);

impl Id {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 1024
            || !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(Failure::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Id {
    type Error = Failure;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<Id> for String {
    fn from(value: Id) -> Self {
        value.0
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Id([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Disabled,
    Configuration,
    Denied,
    Cancelled,
    Deadline,
    Invalid,
    Limit,
    Integrity,
    Conflict,
    Missing,
    Unsupported,
    /// A caller may schedule one bounded retry of the same operation.
    Transient,
    /// A remote effect may have happened. Reconcile; never auto-abort/reallocate.
    Uncertain,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "archive operation failed: {self:?}")
    }
}
impl std::error::Error for Failure {}
pub type Result<T> = std::result::Result<T, Failure>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_validate_on_construction_and_deserialization() {
        let invalid = [
            String::new(),
            "x".repeat(1025),
            "a b".into(),
            "a\nb".into(),
            "é".into(),
        ];
        for value in invalid {
            assert_eq!(Id::new(&value), Err(Failure::Invalid));
            let json = serde_json::to_string(&value).unwrap();
            assert!(serde_json::from_str::<Id>(&json).is_err());
        }
        for byte in 0u8..=127 {
            let value = String::from(char::from(byte));
            assert_eq!(Id::new(value).is_ok(), (0x21..=0x7e).contains(&byte));
        }
    }

    #[test]
    fn identifier_round_trip_and_debug_redaction() {
        for value in ["!~".to_string(), "x".repeat(1024)] {
            let id = Id::new(&value).unwrap();
            let json = serde_json::to_string(&id).unwrap();
            let decoded: Id = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.as_str(), value);
            assert_eq!(format!("{decoded:?}"), "Id([redacted])");
        }
        for backend in [Backend::Nntp, Backend::S3] {
            let json = serde_json::to_string(&backend).unwrap();
            assert_eq!(serde_json::from_str::<Backend>(&json).unwrap(), backend);
        }
    }
}
