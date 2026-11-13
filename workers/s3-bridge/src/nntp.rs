//! `impl NntpConnector` over `velmora::transports::WorkerTransport`
//! (adapter lane; `max_article_bytes` = 1 MiB). Sessions become
//! `velmora::nntp::NntpClient<WorkerTransport>` once the blanket
//! `NntpSession` impl lands.
//!
//! Walking-skeleton stub: `connect` answers `NotImplemented`, so no socket
//! is ever opened.

use velmora_bridge::{
    BodyOutcome, BridgeError, NntpConnector, NntpSession, Permit, ProviderConfig, Result,
};

/// Placeholder session type: uninhabited, so it can never be used.
pub enum NoSession {}

impl NntpSession for NoSession {
    async fn post(
        &mut self,
        _message_id: &str,
        _article: &[u8],
    ) -> Result<velmora::nntp::PostOutcome> {
        match *self {}
    }

    async fn stat(&mut self, _message_id: &str) -> Result<bool> {
        match *self {}
    }

    async fn body(&mut self, _message_id: &str, _out: &mut Vec<u8>) -> Result<BodyOutcome> {
        match *self {}
    }

    async fn quit(self) {
        match self {}
    }
}

pub struct WorkerConnector;

impl WorkerConnector {
    pub fn new() -> Self {
        WorkerConnector
    }
}

impl NntpConnector for WorkerConnector {
    type Session = NoSession;

    async fn connect(&self, _provider: &ProviderConfig, _permit: &Permit) -> Result<NoSession> {
        Err(BridgeError::NotImplemented("nntp::connect"))
    }
}
