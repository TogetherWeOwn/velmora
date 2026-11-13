//! Key wrapping and extent sealing (crypto lane, DESIGN §A.9, §B.1).
//!
//! Walking-skeleton stub. Planned API: `WrappedKey`, `DataKey`;
//! `wrap_bdk`/`unwrap_bdk`, `wrap_file_key`/`unwrap_file_key`,
//! `wrap_secret`/`unwrap_secret` (XChaCha20-Poly1305, AAD per §A.9);
//! `seal_extent` -> `SealedExtent`; `open_range`; `profile()`.
