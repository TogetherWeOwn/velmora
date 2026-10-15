//! Synthetic NNTP test server + fixture corpus for NNTune v2 CI.
//!
//! No real Usenet is used in CI. Integration tests spawn [`TestNntpServer`]
//! on an ephemeral loopback port and speak a small RFC 3977 subset over TCP.
//!
//! ```no_run
//! # #[tokio::main] async fn main() {
//! let server = nntune_test_nntp::TestNntpServer::spawn_for_test().await;
//! println!("NNTP fixture server on {}", server.addr());
//! # }
//! ```

pub mod fixtures;
pub mod server;
pub mod yenc;

pub use fixtures::{default_corpus, generate_wav_bytes, nzb_for, Article};
pub use server::{ServerConfig, TestNntpServer, UserConfig};
