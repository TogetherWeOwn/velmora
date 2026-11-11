//! Versioned, portable ciphertext archive contract.
//!
//! The caller durably records the complete intent before I/O, then each remote
//! session/part/result before acknowledging it. These serializable values are
//! journal inputs, not a database, authority token or proof of durability.
//! Dropping a future never means rollback. Retry one bounded operation only after
//! reconciling uncertain effects under the same intent; never mint a new target.

pub mod nntp;
pub mod s3;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, future::Future};

pub const API_VERSION: u16 = 1;
pub const MAX_PART_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PARTS: usize = 10_000;
pub const STREAM_BLOCK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backend {
    Nntp,
    S3,
}

/// An access-controlled identifier or credential *reference*, never a secret.
/// Redacted in diagnostics; callers must also avoid logging serialized records.
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
/// authentication/current policy, never from client-supplied boolean fields.
/// Transports must also enforce it *during* I/O, including physical closure and
/// preserving pool leases until closure is proven. Boundary checks alone cannot
/// cancel an already-issued remote effect. `check` is synchronous and fail closed.
pub trait Control {
    fn check(&self, target: &Target, action: Action) -> Result<()>;

    /// Wait for cancellation, expiry or revocation of this exact action. Register
    /// the wake source before checking policy to avoid a lost notification. This
    /// future must wake even when the underlying socket makes no progress; a
    /// polling-only or never-woken implementation is not a valid live control.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub write: bool,
    pub range: bool,
    pub reconcile: bool,
    pub physical_delete: bool,
    pub max_part_bytes: usize,
}

/// Observations only, never an eviction permit or a live durability guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteProof {
    pub record: ObjectRecord,
    pub acknowledged: bool,
    pub full_ciphertext_readback: bool,
    /// NNTP observation has no independence or authenticated client proof.
    pub backend: Backend,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reconciled {
    Verified(Box<WriteProof>),
    /// Proven not committed *at observation time*, not safe to race a pending
    /// request. A transport must settle all issued requests before returning it.
    Absent,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortOutcome {
    IncompleteRemoved,
    /// Already posted/committed bytes cannot be recalled by abort.
    Irreversible,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// Configured transport is available; no object durability is implied.
    Available,
    Unavailable,
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

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// No destructive delete method: logical tombstones belong to the catalogue;
/// physical retirement requires its independently fenced, retained-copy protocol.
/// There are no implicit retries, timers, alternate-account or cache fallbacks.
#[allow(async_fn_in_trait)]
pub trait ArchiveProvider {
    fn capabilities(&self) -> Capabilities;
    async fn begin(&mut self, intent: &WriteIntent, control: &impl Control)
        -> Result<WriteSession>;
    async fn write_part(
        &mut self,
        session: &WriteSession,
        index: usize,
        bytes: &[u8],
        control: &impl Control,
    ) -> Result<PartReceipt>;
    async fn commit(
        &mut self,
        session: &WriteSession,
        receipts: &[PartReceipt],
        control: &impl Control,
    ) -> Result<WriteProof>;
    async fn abort(
        &mut self,
        session: &WriteSession,
        control: &impl Control,
    ) -> Result<AbortOutcome>;
    async fn stat(
        &mut self,
        record: &ObjectRecord,
        control: &impl Control,
    ) -> Result<ObjectIdentity>;
    async fn read_range(
        &mut self,
        record: &ObjectRecord,
        range: Range,
        sink: &mut impl Sink,
        control: &impl Control,
    ) -> Result<()>;
    async fn reconcile(
        &mut self,
        session: &WriteSession,
        control: &impl Control,
    ) -> Result<Reconciled>;
    async fn health(&mut self, target: &Target, control: &impl Control) -> Result<Health>;
}

pub(crate) fn check_receipts(session: &WriteSession, receipts: &[PartReceipt]) -> Result<()> {
    let binding = session.intent.binding()?;
    if receipts.len() != session.intent.parts.len()
        || receipts
            .iter()
            .enumerate()
            .any(|(i, receipt)| receipt.index != i || receipt.intent_binding != binding)
    {
        return Err(Failure::Conflict);
    }
    Ok(())
}

/// Races `operation` against cancellation/deadline/revocation of `action`:
/// the control is checked before the first poll and again before a completed
/// result is accepted, and the registered `cancelled` future is polled
/// alongside the operation so a stalled operation still observes the signal
/// even when its own I/O never wakes. On interruption the operation future
/// is dropped; callers must treat that as abandonment (poison/uncertainty),
/// never as proof that nothing happened.
pub(crate) async fn supervised<F: Future>(
    operation: F,
    target: &Target,
    action: Action,
    control: &impl Control,
) -> Result<F::Output> {
    let mut operation = std::pin::pin!(operation);
    let mut cancelled = std::pin::pin!(control.cancelled(target, action));
    std::future::poll_fn(|cx| {
        if let Err(error) = control.check(target, action) {
            return std::task::Poll::Ready(Err(error));
        }
        if let std::task::Poll::Ready(error) = cancelled.as_mut().poll(cx) {
            return std::task::Poll::Ready(Err(error));
        }
        match operation.as_mut().poll(cx) {
            std::task::Poll::Ready(result) => {
                std::task::Poll::Ready(control.check(target, action).map(|()| result))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

pub(crate) async fn emit(
    bytes: &[u8],
    target: &Target,
    sink: &mut impl Sink,
    control: &impl Control,
) -> Result<()> {
    for block in bytes.chunks(STREAM_BLOCK_BYTES) {
        control.check(target, Action::Read)?;
        // A sink has no control of its own and may never wake, so each pending
        // write is supervised with Read control: cancellation, deadline or
        // revocation ends the read instead of retaining the fetched part
        // forever. Interruption drops the sink future; the invisible-prefix
        // rule on `Sink` still applies and success is never published.
        supervised(sink.write(block), target, Action::Read, control).await??;
    }
    control.check(target, Action::Read)
}
