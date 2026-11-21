//! Core of the WebDAV gateway (RFC 4918 classes 1, 2 and 3), independent
//! of the runtime.
//!
//! The gateway stores no file data and no credential. A client logs in
//! with HTTP Basic: the user name is an app password's id, the password
//! its secret. Every request becomes S3 calls signed with that pair and
//! sent to the storage Worker through its WebDAV entry point, which
//! accepts app passwords and nothing else. Locks and dead properties
//! live in one `DavState` object per bucket ([`state`]).
//!
//! Ports: [`s3::Upstream`] (the storage Worker, the clock, randomness)
//! and [`handler::StatePort`] (the state objects).

pub mod handler;
pub mod http;
pub mod ifhdr;
pub mod path;
pub mod props;
pub mod s3;
pub mod sigv4;
pub mod state;
pub mod time;
pub mod xml;

pub use handler::{Config, Dav, StatePort};
