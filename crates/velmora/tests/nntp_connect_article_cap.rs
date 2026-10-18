//! Connect-time pins for `NntpConfig.max_article_bytes`.
//!
//! Sibling of the pinned `max_pipelined == 0` arm: [`NntpClient::connect`]
//! fails closed when the cap is `0` or above
//! [`MAX_ARTICLE_BYTES`](nntune_core::transport::MAX_ARTICLE_BYTES), before any
//! I/O. Fake transport only; no network.

#[path = "review_support/nntp.rs"]
mod support;

use std::io;

use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transport::{Transport, MAX_ARTICLE_BYTES};

/// Inert transport: connect-time validation runs before any I/O, so the
/// rejection arms never touch the wire.
struct Unused;

impl Transport for Unused {
    async fn read(&mut self, _out: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "unused"))
    }

    async fn write_all(&mut self, _bytes: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "unused"))
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "unused"))
    }
}

fn config_with(max_article_bytes: usize) -> NntpConfig {
    NntpConfig {
        max_article_bytes,
        ..NntpConfig::default()
    }
}

async fn connect_err(max_article_bytes: usize) -> String {
    let Err(err) = NntpClient::connect(Unused, &config_with(max_article_bytes)).await else {
        panic!("connect must reject out-of-range max_article_bytes");
    };
    err.to_string()
}

#[tokio::test]
async fn zero_article_cap_rejected_at_connect() {
    let msg = connect_err(0).await;
    assert!(
        msg.contains("max_article_bytes"),
        "unexpected message: {msg}"
    );
}

#[tokio::test]
async fn above_ceiling_article_cap_rejected_at_connect() {
    let msg = connect_err(MAX_ARTICLE_BYTES + 1).await;
    assert!(
        msg.contains("max_article_bytes"),
        "unexpected message: {msg}"
    );
}

#[tokio::test]
async fn usize_max_article_cap_rejected_at_connect() {
    let msg = connect_err(usize::MAX).await;
    assert!(
        msg.contains("max_article_bytes"),
        "unexpected message: {msg}"
    );
}

#[tokio::test]
async fn ceiling_article_cap_connects_ok() {
    let config = config_with(MAX_ARTICLE_BYTES);
    let (_client, _) = support::connect(b"", 4096, &config).await;
}
