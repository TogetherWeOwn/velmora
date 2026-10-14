//! Shared Usenet data-plane core for NNTune v2.
//!
//! Compiles for `wasm32-unknown-unknown` (Cloudflare Workers via `workers-rs`)
//! **and** native targets (ingest/streaming services, Container batch jobs).
//!
//! Modules:
//!
//! - [`nntp`]: NNTP client over a portable [`transport::Transport`] trait.
//! - [`yenc`]: yEnc encode/decode with an explicit SIMD fast path (x86_64 SSE2,
//!   wasm32 simd128) and scalar fallback, plus CRC32.
//! - [`nzb`]: streaming NZB parser with hard resource bounds.
//! - [`decrypt`]: AES-CBC and rclone-crypt ranged decryption.
//! - [`par2`]: PAR2 recovery-set parsing and verification. Repair is
//!   native-only (it shells out to `par2cmdline-turbo` in a Container).
//!
//! The protocol/parser core uses injected transports. Transport implementations
//! own network I/O and per-operation timeouts (see [`transport`] and
//! [`transports`]); the native repair runner owns its subprocess deadline.

pub mod decrypt;
pub mod error;
pub mod nntp;
pub mod nzb;
pub mod par2;
pub mod transport;
pub mod transports;
pub mod yenc;

pub use error::{Error, Result};
