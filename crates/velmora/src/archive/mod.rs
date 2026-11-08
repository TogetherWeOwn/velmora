//! Default-off archive adapters, separate from catalogue and hot-cache policy.
//!
//! Providers store opaque ciphertext. Their integrity checks are not media
//! authentication: plaintext still requires `media::VerifiedHeader` and its
//! reader. No provider receipt grants serving authority or cache eviction.

pub mod v1;
