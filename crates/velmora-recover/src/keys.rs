//! Bounds secret input and keeps the read and decode buffers zeroizing.

use std::{
    collections::BTreeMap,
    io::{self, Read},
};
use velmora_bridge::{config::KekRing, ports::Kek, types::KekBytes};
use zeroize::Zeroizing;

const KEY_INPUT_MAX: usize = 1024 * 1024;
const INVALID: &str = "invalid KEK input: expected a raw/hex key or a versioned KEK ring";

pub fn read_secret(reader: impl Read, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let capacity = limit
        .checked_add(1)
        .ok_or_else(|| io::Error::other("invalid size limit"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    reader.take(capacity as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("input exceeds size limit"));
    }
    Ok(bytes)
}

pub struct RecoveryKeys {
    inner: KekRing,
    active: u32,
}

impl RecoveryKeys {
    fn new(active: u32, keys: BTreeMap<u32, KekBytes>) -> Result<Self, &'static str> {
        if !keys.contains_key(&active) {
            return Err(INVALID);
        }
        // The bridge ring uses the production active key as an upper bound.
        // Recovery exposes every held version, even if the caller prefers an older one.
        let newest = *keys.last_key_value().ok_or(INVALID)?.0;
        let inner = KekRing::from_keys(newest, keys).map_err(|_| INVALID)?;
        Ok(Self { inner, active })
    }
}

impl Kek for RecoveryKeys {
    fn active(&self) -> (u32, &KekBytes) {
        (
            self.active,
            self.inner
                .version(self.active)
                .expect("required at construction"),
        )
    }
    fn version(&self, version: u32) -> Option<&KekBytes> {
        self.inner.version(version)
    }
}

/// Single-key input defaults to version 1. A ring defaults to its declared
/// active version or, if absent, its highest present version.
pub fn read_keyring(
    reader: impl Read,
    requested: Option<u32>,
) -> Result<RecoveryKeys, &'static str> {
    let bytes = read_secret(reader, KEY_INPUT_MAX).map_err(|_| "could not read KEK")?;
    let text = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(&bytes);
    let mut decoded = Zeroizing::new([0u8; 32]);
    if bytes.len() == decoded.len() {
        decoded.copy_from_slice(&bytes);
    } else if text.len() == 2 * decoded.len() && text.iter().all(u8::is_ascii_hexdigit) {
        fn digit(b: u8) -> u8 {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b.to_ascii_lowercase() - b'a' + 10
            }
        }
        for (target, pair) in decoded.iter_mut().zip(text.as_chunks::<2>().0) {
            *target = digit(pair[0]) << 4 | digit(pair[1]);
        }
    } else {
        return parse_ring(text, requested);
    }
    let active = requested.unwrap_or(1);
    RecoveryKeys::new(active, [(active, KekBytes::new(*decoded))].into())
}

fn parse_ring(bytes: &[u8], requested: Option<u32>) -> Result<RecoveryKeys, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| INVALID)?;
    let mut keys = BTreeMap::new();
    let mut declared = None;
    for line in text.lines().map(str::trim) {
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((name, value)) = line.split_once('=') else {
            if line.starts_with("VELMORA_KEK_") {
                return Err(INVALID);
            }
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(value);
        if name == "VELMORA_KEK_ACTIVE" {
            if declared
                .replace(value.parse::<u32>().map_err(|_| INVALID)?)
                .is_some()
            {
                return Err(INVALID);
            }
            continue;
        }
        let Some(suffix) = name.strip_prefix("VELMORA_KEK_") else {
            continue;
        };
        if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
            return Err(INVALID);
        }
        let version = suffix
            .parse::<u32>()
            .ok()
            .filter(|&v| v > 0)
            .ok_or(INVALID)?;
        let key = KekRing::decode_key(value).ok_or(INVALID)?;
        if keys.insert(version, key).is_some() {
            return Err(INVALID);
        }
    }
    let active = requested
        .or(declared)
        .or_else(|| keys.last_key_value().map(|(version, _)| *version))
        .ok_or(INVALID)?;
    RecoveryKeys::new(active, keys)
}
