//! Standalone recovery engine. Not linked into the service.

pub mod catalogue;
pub mod extent;
#[cfg(feature = "recovery-cli")]
pub mod keys;
#[cfg(feature = "recovery-cli")]
pub mod kit;
pub mod nzb;
pub mod resume;
pub mod source;
