//! Outbound S3 multipart object adapter over an injected safe transport.
//!
//! This is not a public S3 protocol server or an R2 adapter. No networking or
//! credentials are created here. The transport implements authenticated S3
//! operations, endpoint/DNS pinning, TLS, no redirects, response size bounds,
//! in-call cancellation/deadlines, and durable remote-request reconciliation.
//! A transport timeout after issuing a mutation MUST be `Failure::Uncertain`.
//! Constructors perform no I/O. Only explicitly enabled configurations operate.
//!
//! This slice ships the explicit configuration and transport-owned types only;
//! the `SafeTransport` port and adapter arrive with their first operations.

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
