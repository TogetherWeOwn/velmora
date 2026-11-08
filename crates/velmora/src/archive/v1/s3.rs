//! Outbound S3 multipart object adapter over an injected safe transport.
//!
//! This is not a public S3 protocol server or an R2 adapter. No networking or
//! credentials are created here. The transport implements authenticated S3
//! operations, endpoint/DNS pinning, TLS, no redirects, response size bounds,
//! in-call cancellation/deadlines, and durable remote-request reconciliation.
//! A transport timeout after issuing a mutation MUST be `Failure::Uncertain`.
//! Constructors perform no I/O. Only explicitly enabled configurations operate.

use super::*;

pub const MIN_MULTIPART_BYTES: usize = 5 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub enabled: bool,
    pub account: Id,
    /// TLS DNS name only, never a URL, path, IP literal or caller-controlled host.
    pub host: Id,
    pub region: Id,
    pub bucket: Id,
    pub credential_ref: Id,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Err(Failure::Disabled);
        }
        let host = self.host.as_str();
        if host.len() > 253
            || !host.contains('.')
            || host.parse::<std::net::IpAddr>().is_ok()
            || host.ends_with('.')
            || host.eq_ignore_ascii_case("localhost")
            || [".localhost", ".local", ".internal", ".invalid", ".test"]
                .iter()
                .any(|suffix| host.to_ascii_lowercase().ends_with(suffix))
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(Failure::Configuration);
        }
        // These checks do not establish public resolution: the safe transport
        // must resolve/vet/pin every connection and deny special/private peers.
        let bucket = self.bucket.as_str();
        if !(3..=63).contains(&bucket.len())
            || bucket.parse::<std::net::IpAddr>().is_ok()
            || bucket.contains("..")
            || !bucket.as_bytes()[0].is_ascii_alphanumeric()
            || !bucket.as_bytes()[bucket.len() - 1].is_ascii_alphanumeric()
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
            || !self
                .region
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Failure::Configuration);
        }
        if !self
            .credential_ref
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
        {
            return Err(Failure::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderChecksum {
    FullSha256([u8; 32]),
    /// Multipart composite checksum is NOT the full ciphertext SHA-256.
    CompositeSha256,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub version: Id,
    pub bytes: u64,
    /// Persisted as object metadata; binds the exact intent, not just its ID.
    pub intent_binding: [u8; 32],
    pub checksum: ProviderChecksum,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartAck {
    pub etag: Id,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeReply {
    pub bytes: usize,
    pub offset: u64,
    pub total: u64,
    pub version: Id,
}

/// Trusted infrastructure port, not deserialized client assertions. Every method
/// uses HTTPS:443 to the configured pinned endpoint with scoped signing from the
/// credential reference. Never forward credentials across hosts/redirects.
///
/// `begin` reconciles the durable intent/remote-upload binding before returning
/// an existing upload or issuing CreateMultipartUpload. Persist the request and
/// returned upload ID before ack; a lost response is uncertain, not a new upload.
/// `upload_part` executes UploadPart with SHA-256 and the exact index+1; retry is
/// only the same bytes/part/upload. `complete` executes ordered CompleteMultipartUpload
/// with a create-only condition (If-None-Match:* or equivalent atomic guarantee).
/// It checks HTTP and embedded XML errors and returns the server's VersionId,
/// checksum type and persisted binding. It must never overwrite a different
/// generation. Only versioned buckets with non-null VersionIds are supported.
///
/// `head` uses HeadObject with the exact VersionId when supplied. `get_range`
/// sends GET with that VersionId and Range, accepts only the exact response
/// interval/length/version, bounds reads to `out`, and rejects redirects/extra
/// bytes. Return metadata from the same response, not a separate unpinned HEAD.
/// `reconcile` settles ALL issued requests for this operation before `Absent`;
/// S3 404 alone does not prove quiescence. No hidden retries or account fallback.
#[allow(async_fn_in_trait)]
pub trait SafeTransport {
    async fn begin(
        &mut self,
        config: &Config,
        intent: &WriteIntent,
        control: &impl Control,
    ) -> Result<Id>;
    async fn upload_part(
        &mut self,
        config: &Config,
        session: &WriteSession,
        index: usize,
        bytes: &[u8],
        control: &impl Control,
    ) -> Result<PartAck>;
    async fn complete(
        &mut self,
        config: &Config,
        session: &WriteSession,
        receipts: &[PartReceipt],
        control: &impl Control,
    ) -> Result<Metadata>;
    async fn abort_incomplete(
        &mut self,
        config: &Config,
        session: &WriteSession,
        control: &impl Control,
    ) -> Result<AbortOutcome>;
    async fn head(
        &mut self,
        config: &Config,
        intent: &WriteIntent,
        version: &Id,
        control: &impl Control,
    ) -> Result<Metadata>;
    async fn get_range(
        &mut self,
        config: &Config,
        record: &ObjectRecord,
        range: Range,
        out: &mut [u8],
        control: &impl Control,
    ) -> Result<RangeReply>;
    /// `None` means settled absence, `Uncertain` means not yet settled.
    async fn reconcile(
        &mut self,
        config: &Config,
        session: &WriteSession,
        control: &impl Control,
    ) -> Result<Option<Metadata>>;
    async fn health(
        &mut self,
        config: &Config,
        target: &Target,
        control: &impl Control,
    ) -> Result<Health>;
}

pub struct Provider<T> {
    config: Config,
    transport: T,
}

impl<T: SafeTransport> Provider<T> {
    pub fn new(config: Option<Config>, transport: T) -> Result<Self> {
        let config = config.ok_or(Failure::Configuration)?;
        config.validate()?;
        Ok(Self { config, transport })
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn check(&self, target: &Target, action: Action, control: &impl Control) -> Result<()> {
        self.config.validate()?;
        if target.backend != Backend::S3 || target.account != self.config.account {
            return Err(Failure::Configuration);
        }
        control.check(target, action)
    }

    fn validate_intent(&self, intent: &WriteIntent) -> Result<()> {
        intent.validate()?;
        if intent.parts[..intent.parts.len() - 1]
            .iter()
            .any(|part| (part.bytes as usize) < MIN_MULTIPART_BYTES)
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }

    fn record(&self, intent: &WriteIntent, metadata: Metadata) -> Result<ObjectRecord> {
        self.validate_intent(intent)?;
        if metadata.version.as_str() == "null"
            || metadata.bytes != intent.bytes
            || metadata.intent_binding != intent.binding()?
            || matches!(metadata.checksum, ProviderChecksum::FullSha256(d) if d != intent.sha256)
        {
            return Err(Failure::Integrity);
        }
        Ok(ObjectRecord {
            identity: ObjectIdentity {
                target: intent.target.clone(),
                version: metadata.version,
                bytes: intent.bytes,
                sha256: intent.sha256,
            },
            operation: intent.operation.clone(),
            parts: intent.parts.clone(),
        })
    }

    async fn fetch_part(
        &mut self,
        record: &ObjectRecord,
        part: &Part,
        control: &impl Control,
    ) -> Result<Vec<u8>> {
        self.check(&record.identity.target, Action::Read, control)?;
        // The caller validates the manifest before allocation. The transport
        // fills a fixed slice and cannot over-return into a growing Vec.
        let mut out = vec![0; part.bytes as usize];
        if part.bytes == 0 {
            // There is no byte range to GET, but the exact empty version must
            // still exist with the expected length, checksum and intent binding.
            self.stat(record, control).await?;
        } else {
            let reply = self
                .transport
                .get_range(
                    &self.config,
                    record,
                    Range {
                        offset: part.offset,
                        bytes: u64::from(part.bytes),
                    },
                    &mut out,
                    control,
                )
                .await?;
            if reply.bytes != out.len()
                || reply.offset != part.offset
                || reply.total != record.identity.bytes
                || reply.version != record.identity.version
            {
                return Err(Failure::Integrity);
            }
        }
        self.check(&record.identity.target, Action::Read, control)?;
        if digest(&out) != part.sha256 {
            return Err(Failure::Integrity);
        }
        Ok(out)
    }

    async fn prove(&mut self, record: ObjectRecord, control: &impl Control) -> Result<WriteProof> {
        record.validate()?;
        let mut hash = Sha256::new();
        for part in &record.parts {
            hash.update(self.fetch_part(&record, part, control).await?);
        }
        let actual: [u8; 32] = hash.finalize().into();
        if actual != record.identity.sha256 {
            return Err(Failure::Integrity);
        }
        self.check(&record.identity.target, Action::Read, control)?;
        self.check(&record.identity.target, Action::Write, control)
            .map_err(|_| Failure::Uncertain)?;
        Ok(WriteProof {
            record,
            acknowledged: true,
            full_ciphertext_readback: true,
            backend: Backend::S3,
        })
    }
}

impl<T: SafeTransport> ArchiveProvider for Provider<T> {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            write: true,
            range: true,
            reconcile: true,
            physical_delete: false,
            max_part_bytes: MAX_PART_BYTES,
        }
    }

    async fn begin(
        &mut self,
        intent: &WriteIntent,
        control: &impl Control,
    ) -> Result<WriteSession> {
        self.check(&intent.target, Action::Write, control)?;
        self.validate_intent(intent)?;
        let remote = self.transport.begin(&self.config, intent, control).await?;
        // Once issued, late cancellation/expiry cannot turn a successful remote
        // effect into a "nothing happened" error. Reconcile before cleanup.
        self.check(&intent.target, Action::Write, control)
            .map_err(|_| Failure::Uncertain)?;
        Ok(WriteSession {
            intent: intent.clone(),
            remote,
        })
    }

    async fn write_part(
        &mut self,
        session: &WriteSession,
        index: usize,
        bytes: &[u8],
        control: &impl Control,
    ) -> Result<PartReceipt> {
        self.check(&session.intent.target, Action::Write, control)?;
        self.validate_intent(&session.intent)?;
        let part = session.intent.check_part(index, bytes)?;
        let ack = self
            .transport
            .upload_part(&self.config, session, index, bytes, control)
            .await?;
        if ack.sha256 != part.sha256 {
            return Err(Failure::Uncertain);
        }
        self.check(&session.intent.target, Action::Write, control)
            .map_err(|_| Failure::Uncertain)?;
        Ok(PartReceipt {
            index,
            intent_binding: session.intent.binding()?,
            acknowledgement: ack.etag,
        })
    }

    async fn commit(
        &mut self,
        session: &WriteSession,
        receipts: &[PartReceipt],
        control: &impl Control,
    ) -> Result<WriteProof> {
        self.check(&session.intent.target, Action::Write, control)?;
        self.validate_intent(&session.intent)?;
        check_receipts(session, receipts)?;
        let metadata = self
            .transport
            .complete(&self.config, session, receipts, control)
            .await?;
        // Completion may be durable even when validation/readback/cancellation
        // fails. Preserve session+receipts and reconcile the same allocation.
        let record = self
            .record(&session.intent, metadata)
            .map_err(|_| Failure::Uncertain)?;
        self.prove(record, control)
            .await
            .map_err(|_| Failure::Uncertain)
    }

    async fn abort(
        &mut self,
        session: &WriteSession,
        control: &impl Control,
    ) -> Result<AbortOutcome> {
        self.check(&session.intent.target, Action::AbortIncomplete, control)?;
        self.validate_intent(&session.intent)?;
        let outcome = self
            .transport
            .abort_incomplete(&self.config, session, control)
            .await?;
        self.check(&session.intent.target, Action::AbortIncomplete, control)
            .map_err(|_| Failure::Uncertain)?;
        Ok(outcome)
    }

    async fn stat(
        &mut self,
        record: &ObjectRecord,
        control: &impl Control,
    ) -> Result<ObjectIdentity> {
        self.check(&record.identity.target, Action::Read, control)?;
        record.validate()?;
        let intent = record.intent();
        let metadata = self
            .transport
            .head(&self.config, &intent, &record.identity.version, control)
            .await?;
        self.check(&record.identity.target, Action::Read, control)?;
        let observed = self.record(&intent, metadata)?;
        if observed.identity != record.identity {
            return Err(Failure::Integrity);
        }
        Ok(observed.identity)
    }

    async fn read_range(
        &mut self,
        record: &ObjectRecord,
        range: Range,
        sink: &mut impl Sink,
        control: &impl Control,
    ) -> Result<()> {
        self.check(&record.identity.target, Action::Read, control)?;
        record.validate()?;
        self.validate_intent(&record.intent())?;
        let end = range.end(record.identity.bytes)?;
        for part in &record.parts {
            let part_end = part.offset + u64::from(part.bytes);
            let start = range.offset.max(part.offset);
            let stop = end.min(part_end);
            if start < stop {
                let bytes = self.fetch_part(record, part, control).await?;
                emit(
                    &bytes[(start - part.offset) as usize..(stop - part.offset) as usize],
                    &record.identity.target,
                    sink,
                    control,
                )
                .await?;
            }
        }
        self.check(&record.identity.target, Action::Read, control)
    }

    async fn reconcile(
        &mut self,
        session: &WriteSession,
        control: &impl Control,
    ) -> Result<Reconciled> {
        self.check(&session.intent.target, Action::Write, control)?;
        self.validate_intent(&session.intent)?;
        match self
            .transport
            .reconcile(&self.config, session, control)
            .await
        {
            Ok(Some(metadata)) => {
                // Completion is a remote effect even if metadata or ciphertext
                // cannot be verified. Keep the allocation and safety copy.
                let Ok(record) = self.record(&session.intent, metadata) else {
                    return Ok(Reconciled::Uncertain);
                };
                match self.prove(record, control).await {
                    Ok(proof) => Ok(Reconciled::Verified(Box::new(proof))),
                    Err(_) => Ok(Reconciled::Uncertain),
                }
            }
            Ok(None) => {
                self.check(&session.intent.target, Action::Write, control)?;
                Ok(Reconciled::Absent)
            }
            Err(Failure::Uncertain) => Ok(Reconciled::Uncertain),
            Err(error) => Err(error),
        }
    }

    async fn health(&mut self, target: &Target, control: &impl Control) -> Result<Health> {
        self.check(target, Action::Health, control)?;
        let health = self.transport.health(&self.config, target, control).await?;
        self.check(target, Action::Health, control)?;
        Ok(health)
    }
}
