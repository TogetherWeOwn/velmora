//! Runtime-agnostic core of the velmora S3 bridge.
//!
//! The service is generic over the ports in [`ports`] (catalogue SQL, blob
//! stores, NNTP, job queue, clock, KEK), so the same code runs in the
//! Cloudflare Worker and in native tests (`testkit` feature).
//!
//! Contract modules (`types`, `ports`, `config`, `testkit`, the migration)
//! are frozen; every other module belongs to one build lane.

pub mod articles;
pub mod config;
pub mod crypto;
pub mod fetch;
pub mod ingress;
pub mod jobs;
pub mod ports;
pub mod post;
pub mod service;
pub mod sql;
pub mod types;
pub mod verify;

#[cfg(feature = "testkit")]
pub mod testkit;

pub use config::{BridgeConfig, KekRing, REAL_DATA_READY};
pub use ports::*;
pub use types::*;
