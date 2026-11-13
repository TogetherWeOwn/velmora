//! Versioned, portable ciphertext archive contract: identities only.
//!
//! In a complete archive implementation, callers durably record intent before
//! I/O and each remote session, part, and result before acknowledging it. These
//! serializable values are journal inputs, not a database, authority token, or
//! proof of durability. Dropping a future does not roll back effects; reconcile
//! uncertain effects under the same intent before a bounded retry, and never
//! mint a new target. This module does not implement providers or I/O.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, future::Future};

pub mod s3;

/// Version of the portable archive contract.
pub const API_VERSION: u16 = 1;
/// Maximum ciphertext bytes in one part.
pub const MAX_PART_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of parts in a manifest.
pub const MAX_PARTS: usize = 10_000;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionIdentity {
    pub format: Id,
    pub mode: u8,
    pub key_epoch: Id,
    /// Tenant/vault-scoped wrapping identity; contains no key material.
    pub envelope: Id,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub tenant: Id,
    pub backend: Backend,
    pub account: Id,
    /// Immutable generation-qualified allocation, never a reusable logical key.
    pub locator: Id,
    pub generation: Id,
    pub encryption: EncryptionIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    pub target: Target,
    /// Exact remote version (S3 VersionId or immutable NNTP manifest revision).
    pub version: Id,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

impl ObjectIdentity {
    /// Domain-separated, length-prefixed cache identity. Internal only: never
    /// expose this as a public ETag, existence check or authorization decision.
    pub fn cache_key(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"velmora.archive.v1/cache\0");
        hash.update([match self.target.backend {
            Backend::Nntp => 1,
            Backend::S3 => 2,
        }]);
        for field in [
            &self.target.tenant,
            &self.target.account,
            &self.target.locator,
            &self.target.generation,
            &self.version,
            &self.target.encryption.format,
            &self.target.encryption.key_epoch,
            &self.target.encryption.envelope,
        ] {
            hash.update((field.0.len() as u64).to_be_bytes());
            hash.update(field.0.as_bytes());
        }
        hash.update([self.target.encryption.mode]);
        hash.update(self.bytes.to_be_bytes());
        hash.update(self.sha256);
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    pub offset: u64,
    pub bytes: u32,
    pub sha256: [u8; 32],
    /// Stable article identity for NNTP; stable part identity for S3.
    pub reference: Id,
}

/// A journal input; callers must bound and authorize serialized data before decoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteIntent {
    pub target: Target,
    /// Tenant-scoped operation ID bound to this exact serialized intent.
    pub operation: Id,
    pub bytes: u64,
    pub sha256: [u8; 32],
    pub parts: Vec<Part>,
}

impl WriteIntent {
    pub fn validate(&self) -> Result<()> {
        if self.parts.is_empty() || self.parts.len() > MAX_PARTS {
            return Err(Failure::Limit);
        }
        let mut offset = 0u64;
        let mut references = std::collections::HashSet::with_capacity(self.parts.len());
        for part in &self.parts {
            if part.offset != offset
                || part.bytes as usize > MAX_PART_BYTES
                || (part.bytes == 0 && (self.bytes != 0 || self.parts.len() != 1))
                || !references.insert(&part.reference)
            {
                return Err(Failure::Invalid);
            }
            offset = offset
                .checked_add(u64::from(part.bytes))
                .ok_or(Failure::Limit)?;
        }
        if offset != self.bytes {
            return Err(Failure::Integrity);
        }
        Ok(())
    }

    pub fn binding(&self) -> Result<[u8; 32]> {
        self.validate()?;
        // Struct fields, byte arrays and vectors have deterministic order; there
        // are no maps or floats. Version labels prevent cross-contract replays.
        let mut hash = Sha256::new();
        hash.update(b"velmora.archive.v1/intent\0");
        hash.update(serde_json::to_vec(self).map_err(|_| Failure::Invalid)?);
        Ok(hash.finalize().into())
    }

    pub fn check_part(&self, index: usize, bytes: &[u8]) -> Result<&Part> {
        self.validate()?;
        let part = self.parts.get(index).ok_or(Failure::Invalid)?;
        if bytes.len() != part.bytes as usize || digest(bytes) != part.sha256 {
            return Err(Failure::Integrity);
        }
        Ok(part)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteSession {
    pub intent: WriteIntent,
    /// Remote upload ID, or NNTP manifest allocation. Persist before part I/O.
    pub remote: Id,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartReceipt {
    pub index: usize,
    pub intent_binding: [u8; 32],
    pub acknowledgement: Id,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRecord {
    pub identity: ObjectIdentity,
    pub operation: Id,
    pub parts: Vec<Part>,
}

impl ObjectRecord {
    pub fn intent(&self) -> WriteIntent {
        WriteIntent {
            target: self.identity.target.clone(),
            operation: self.operation.clone(),
            bytes: self.identity.bytes,
            sha256: self.identity.sha256,
            parts: self.parts.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if (self.identity.target.backend == Backend::Nntp
            && self.identity.version != self.identity.target.generation)
            || (self.identity.target.backend == Backend::S3
                && self.identity.version.as_str() == "null")
        {
            return Err(Failure::Integrity);
        }
        self.intent().validate()
    }
}

/// A byte range within a committed ciphertext object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub offset: u64,
    pub bytes: u64,
}

impl Range {
    pub fn end(self, total: u64) -> Result<u64> {
        let end = self
            .offset
            .checked_add(self.bytes)
            .ok_or(Failure::Invalid)?;
        if end > total {
            return Err(Failure::Invalid);
        }
        Ok(end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    AbortIncomplete,
    Health,
}

/// Trusted product authority and invocation control. Derive this from verified
/// authentication and current policy, never client-supplied boolean fields.
/// Transports must enforce it during I/O, including physical closure and pool
/// leases until closure is proven. Boundary checks cannot cancel remote effects.
/// `check` is synchronous and fail closed.
pub trait Control {
    fn check(&self, target: &Target, action: Action) -> Result<()>;

    /// Wait for cancellation, expiry or revocation of this exact action. Register
    /// the wake source before checking policy to avoid a lost notification. The
    /// future must wake even when the underlying socket makes no progress.
    fn cancelled<'a>(
        &'a self,
        target: &'a Target,
        action: Action,
    ) -> impl Future<Output = Failure> + 'a;
}

pub trait Sink {
    /// Receives only complete-part-verified ciphertext, in <=64 KiB blocks.
    /// A later error can leave an earlier prefix: stage invisibly, never publish
    /// or serve a prefix as a complete object. Cancellation does not undo writes.
    fn write<'a>(&'a mut self, bytes: &'a [u8]) -> impl Future<Output = Result<()>> + 'a;
}

/// SHA-256 of the supplied bytes, without any authentication claim.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
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

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn identity() -> ObjectIdentity {
        ObjectIdentity {
            target: Target {
                tenant: id("tenant-a"),
                backend: Backend::S3,
                account: id("account-a"),
                locator: id("allocation-a"),
                generation: id("generation-a"),
                encryption: EncryptionIdentity {
                    format: id("format-a"),
                    mode: 1,
                    key_epoch: id("epoch-a"),
                    envelope: id("envelope-a"),
                },
            },
            version: id("version-a"),
            bytes: 17,
            sha256: digest(b"ciphertext"),
        }
    }

    #[test]
    fn manifests_validate_bounds_contiguity_and_unique_references() {
        let part = |offset, bytes, reference| Part {
            offset,
            bytes,
            sha256: digest(b"part"),
            reference: id(reference),
        };
        let mut intent = WriteIntent {
            target: identity().target,
            operation: id("operation"),
            bytes: 3,
            sha256: digest(b"all"),
            parts: vec![part(0, 1, "one"), part(1, 2, "two")],
        };
        assert_eq!(intent.validate(), Ok(()));
        let json = serde_json::to_string(&intent).unwrap();
        assert_eq!(serde_json::from_str::<WriteIntent>(&json).unwrap(), intent);
        let original = intent.clone();
        intent.parts[1].offset = 2;
        assert_eq!(intent.validate(), Err(Failure::Invalid));
        intent = original.clone();
        intent.parts[1].reference = intent.parts[0].reference.clone();
        assert_eq!(intent.validate(), Err(Failure::Invalid));
        intent = original.clone();
        intent.parts[0].bytes = MAX_PART_BYTES as u32 + 1;
        assert_eq!(intent.validate(), Err(Failure::Invalid));
        intent = original.clone();
        intent.parts[0].bytes = 0;
        assert_eq!(intent.validate(), Err(Failure::Invalid));
        intent = original.clone();
        intent.bytes = 4;
        assert_eq!(intent.validate(), Err(Failure::Integrity));
        intent.parts.clear();
        assert_eq!(intent.validate(), Err(Failure::Limit));
        intent.parts = vec![part(0, 1, "one"); MAX_PARTS + 1];
        assert_eq!(intent.validate(), Err(Failure::Limit));
        intent.bytes = 0;
        intent.parts = vec![part(0, 0, "empty")];
        assert_eq!(intent.validate(), Ok(()));
        intent.bytes = MAX_PART_BYTES as u64;
        intent.parts = vec![part(0, MAX_PART_BYTES as u32, "maximum")];
        assert_eq!(intent.validate(), Ok(()));
    }

    #[test]
    fn intent_binding_and_part_checks_are_stable_and_fail_closed() {
        let mut intent = WriteIntent {
            target: identity().target,
            operation: id("operation"),
            bytes: 3,
            sha256: digest(b"abc"),
            parts: vec![Part {
                offset: 0,
                bytes: 3,
                sha256: digest(b"abc"),
                reference: id("part"),
            }],
        };
        let binding = intent.binding().unwrap();
        let restored: WriteIntent =
            serde_json::from_str(&serde_json::to_string(&intent).unwrap()).unwrap();
        assert_eq!(restored.binding(), Ok(binding));
        assert_eq!(intent.check_part(0, b"abc"), Ok(&intent.parts[0]));
        assert_eq!(intent.check_part(1, b"abc"), Err(Failure::Invalid));
        assert_eq!(intent.check_part(0, b"ab"), Err(Failure::Integrity));
        assert_eq!(intent.check_part(0, b"abd"), Err(Failure::Integrity));
        intent.operation = id("other-operation");
        assert_ne!(intent.binding(), Ok(binding));
        intent.parts[0].offset = 1;
        assert_eq!(intent.binding(), Err(Failure::Invalid));
        assert_eq!(intent.check_part(0, b"abc"), Err(Failure::Invalid));
    }

    #[test]
    fn journal_records_round_trip_and_validate_versions_and_manifest() {
        let mut record = ObjectRecord {
            identity: identity(),
            operation: id("operation"),
            parts: vec![Part {
                offset: 0,
                bytes: 17,
                sha256: digest(b"part"),
                reference: id("part"),
            }],
        };
        assert_eq!(record.validate(), Ok(()));
        let session = WriteSession {
            intent: record.intent(),
            remote: id("upload"),
        };
        let receipt = PartReceipt {
            index: 0,
            intent_binding: session.intent.binding().unwrap(),
            acknowledgement: id("ack"),
        };
        let json =
            serde_json::to_string(&(record.clone(), session.clone(), receipt.clone())).unwrap();
        let decoded: (ObjectRecord, WriteSession, PartReceipt) =
            serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, (record.clone(), session, receipt));
        record.identity.version = id("null");
        assert_eq!(record.validate(), Err(Failure::Integrity));
        record.identity.target.backend = Backend::Nntp;
        assert_eq!(record.validate(), Err(Failure::Integrity));
        record.identity.version = record.identity.target.generation.clone();
        assert_eq!(record.validate(), Ok(()));
        record.parts[0].offset = 1;
        assert_eq!(record.validate(), Err(Failure::Invalid));
        record.parts[0].offset = 0;
        record.identity.bytes += 1;
        assert_eq!(record.validate(), Err(Failure::Integrity));
        record.parts.clear();
        assert_eq!(record.validate(), Err(Failure::Limit));
    }

    #[test]
    fn ranges_check_bounds_and_overflow() {
        let end = |offset, bytes, total| Range { offset, bytes }.end(total);
        assert_eq!(end(2, 3, 5), Ok(5));
        assert_eq!(end(5, 0, 5), Ok(5));
        assert_eq!(end(0, 0, 0), Ok(0));
        assert_eq!(end(6, 0, 5), Err(Failure::Invalid));
        assert_eq!(end(4, 2, 5), Err(Failure::Invalid));
        assert_eq!(
            Range {
                offset: u64::MAX,
                bytes: 2
            }
            .end(u64::MAX),
            Err(Failure::Invalid)
        );
        assert_eq!(
            Range {
                offset: u64::MAX,
                bytes: 0
            }
            .end(u64::MAX),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn cache_identity_separates_every_coordinate() {
        let identity = identity();
        let mut variants = vec![identity.clone(); 12];
        variants[0].target.tenant = id("tenant-b");
        variants[1].target.backend = Backend::Nntp;
        variants[2].target.account = id("account-b");
        variants[3].target.locator = id("allocation-b");
        variants[4].target.generation = id("generation-b");
        variants[5].version = id("version-b");
        variants[6].target.encryption.format = id("format-b");
        variants[7].target.encryption.mode = 2;
        variants[8].target.encryption.key_epoch = id("epoch-b");
        variants[9].target.encryption.envelope = id("envelope-b");
        variants[10].bytes += 1;
        variants[11].sha256[0] ^= 1;
        for variant in variants {
            assert_ne!(identity.cache_key(), variant.cache_key());
        }
        let json = serde_json::to_string(&identity).unwrap();
        let restored: ObjectIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(identity, restored);
        assert_eq!(identity.cache_key(), restored.cache_key());
        assert!(!format!("{identity:?}").contains("tenant-a"));
    }

    #[test]
    fn cache_identity_frames_adjacent_identifiers() {
        let mut a = identity();
        a.target.tenant = id("a");
        a.target.account = id("bc");
        let mut b = a.clone();
        b.target.tenant = id("ab");
        b.target.account = id("c");
        assert_ne!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn digest_matches_sha256_vector() {
        assert_eq!(
            digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn api_version_is_one() {
        let version: u16 = crate::archive::v1::API_VERSION;
        assert_eq!(version, 1);
    }

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
