//! Bounds secret input and keeps the read and decode buffers zeroizing.

use std::{
    collections::BTreeMap,
    io::{self, Read},
};
use velmora_bridge::{config::KekRing, types::KekBytes};
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

/// Single-key input defaults to version 1. A ring defaults to its declared
/// active version or, if absent, its highest present version.
pub fn read_keyring(reader: impl Read, requested: Option<u32>) -> Result<KekRing, &'static str> {
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
    KekRing::from_keys(active, [(active, KekBytes::new(*decoded))].into()).map_err(|_| INVALID)
}

fn parse_ring(bytes: &[u8], requested: Option<u32>) -> Result<KekRing, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| INVALID)?;
    let mut keys = BTreeMap::new();
    let mut declared = None;
    for line in text.lines().map(str::trim) {
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
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
        let Some(version) = name
            .strip_prefix("VELMORA_KEK_")
            .and_then(|v| v.parse::<u32>().ok())
        else {
            continue;
        };
        let key = KekRing::decode_key(value).ok_or(INVALID)?;
        if keys.insert(version, key).is_some() {
            return Err(INVALID);
        }
    }
    let active = requested
        .or(declared)
        .or_else(|| keys.last_key_value().map(|(version, _)| *version))
        .ok_or(INVALID)?;
    KekRing::from_keys(active, keys).map_err(|_| INVALID)
}
