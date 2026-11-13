//! Outbound S3 multipart object adapter over an injected safe transport.
//!
//! This is not a public S3 protocol server or an R2 adapter. No networking or
//! credentials are created here. The transport implements authenticated S3
//! operations, endpoint/DNS pinning, TLS, no redirects, response size bounds,
//! in-call cancellation/deadlines, and durable remote-request reconciliation.
//! A transport timeout after issuing a mutation MUST be `Failure::Uncertain`.
//! Constructors perform no I/O. Only explicitly enabled configurations operate.
//!
//! This slice ships multipart begin/write_part and health ops only; abort,
//! completion, readback and reconciliation arrive with their own ops.

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
            || host.split('.').all(numeric_address_label)
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

fn numeric_address_label(label: &str) -> bool {
    if let Some(hex) = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    {
        return hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit())
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
/// `upload_part` executes UploadPart with SHA-256 and the exact index+1; retry
/// is only the same bytes/part/upload. `abort_incomplete` removes at most
/// staging for this exact upload; a completed object is `Irreversible`. A
/// transport must treat a dropped in-flight call as abandoned (publish no
/// success from it) and keep any already-issued mutation's outcome
/// `Failure::Uncertain`, never absent or rolled back. Abort, completion,
/// readback and settlement arrive with their operations; no hidden retries or
/// account fallback.
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

    /// Issues or rebinds the remote multipart upload for this exact intent.
    pub async fn begin(
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

    /// Uploads the exact checksummed manifest part. Retry is only the same
    /// bytes/part/upload; an unacknowledged effect stays `Uncertain`.
    pub async fn write_part(
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

    /// Adapter availability only; never a whole-object durability signal.
    pub async fn health(&mut self, target: &Target, control: &impl Control) -> Result<Health> {
        self.check(target, Action::Health, control)?;
        let health = self.transport.health(&self.config, target, control).await?;
        self.check(target, Action::Health, control)?;
        Ok(health)
    }
}
