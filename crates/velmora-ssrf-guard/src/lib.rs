//! Shared SSRF address guard and test vectors.
//!
//! Single owner for the `ip_is_forbidden` / `v4_is_forbidden` predicate
//! previously copy-pasted in `workers/ingest/src/nzb_fetch.rs`,
//! `workers/ingest/src/indexer_fetch.rs` and `workers/api/src/vault.rs`
//! (keep those call sites delegating here; do not fork the predicate).
//! `std`-only, native + wasm32 compatible: no Worker runtime imports.
//!
//! The predicate rejects every non-public destination: v4 loopback,
//! link-local (incl. the cloud metadata endpoint), private, carrier-grade
//! NAT, multicast, broadcast, documentation, `0.0.0.0/8`, IETF protocol
//! assignments, benchmarking and reserved space; v6 anything outside
//! native global unicast plus transition/special-use space inside it
//! (mapped, translated, compatible, NAT64, 6to4, Teredo/ORCHID,
//! site-local, discard, documentation). Resolve-ALL callers reject when
//! ANY answer is forbidden; IP literals are checked directly with no DNS.

use std::net::{IpAddr, Ipv4Addr};

/// True when the four v4 octets are a forbidden destination (see module docs).
pub fn v4_is_forbidden(o: &[u8; 4]) -> bool {
    let v4 = Ipv4Addr::from(*o);
    v4.is_loopback()         // 127/8
        || v4.is_multicast() // 224.0.0.0/4
        || v4.is_link_local() // 169.254/16 (incl. the cloud metadata endpoint)
        || v4.is_private() // 10/8, 172.16/12, 192.168/16
        || v4.is_broadcast()
        || v4.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || o[0] == 0 // 0.0.0.0/8 ("this network")
        || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64/10 carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 (IETF protocol assignments)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking
        || o[0] >= 240 // 240.0.0.0/4 reserved + 255.255.255.255 broadcast
}

/// True when `ip` must never be dialed/fetched (see module docs).
pub fn ip_is_forbidden(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_forbidden(&v4.octets()),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // Only native global unicast (2000::/3). This excludes NAT64,
            // mapped/translated/compatible IPv4, site-local and discard.
            // Also reject transition and special-use space inside that range
            // rather than trusting a translator's embedded IPv4 destination.
            (s[0] & 0xE000) != 0x2000
                || s[0] == 0x2002 // 6to4 (2002::/16)
                || (s[0] == 0x2001 && s[1] < 0x0200) // IETF special-use, incl. Teredo/ORCHID
                || (s[0] == 0x2001 && s[1] == 0x0DB8) // documentation
                || (s[0] == 0x3FFF && (s[1] & 0xF000) == 0) // documentation (3fff::/20)
        }
    }
}

// --- Shared test vectors (single owner; test files import, never copy) ---

/// Forbidden destinations, one per required family. Every entry parses as
/// an `IpAddr` and is forbidden by [`ip_is_forbidden`]. Payloads are
/// public-looking on purpose: a translator embedding a public address is
/// still blocked.
///
/// - `::ffff:0:0/96` mapped (public payload, still blocked)
/// - `2002::/16` 6to4
/// - `2001:db8::/32` documentation
/// - Teredo (`2001::/32`, realistic Teredo address)
/// - `64:ff9b::/96` NAT64 well-known prefix (public payload, still blocked)
pub const FORBIDDEN_VECTORS: &[&str] = &[
    "::ffff:93.184.216.34",
    "2002:a00:1::1",
    "2001:db8::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "64:ff9b::5db8:d822",
];

/// Public-address controls. Every entry parses as an `IpAddr` and is NOT
/// forbidden by [`ip_is_forbidden`]: a guard that blocks these is broken.
pub const PUBLIC_CONTROL_VECTORS: &[&str] = &["93.184.216.34", "2606:4700:4700::1111"];

/// Parse [`FORBIDDEN_VECTORS`] to addresses (panics on a malformed vector;
/// vectors are pinned literals, so a panic is a programming error).
pub fn forbidden_addrs() -> Vec<IpAddr> {
    FORBIDDEN_VECTORS
        .iter()
        .map(|s| s.parse().expect("forbidden vector must parse"))
        .collect()
}

/// Parse [`PUBLIC_CONTROL_VECTORS`] to addresses (panics on a malformed vector).
pub fn public_addrs() -> Vec<IpAddr> {
    PUBLIC_CONTROL_VECTORS
        .iter()
        .map(|s| s.parse().expect("public control must parse"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_vectors_have_the_promised_verdicts() {
        for raw in FORBIDDEN_VECTORS {
            let ip: IpAddr = raw.parse().expect("forbidden vector must parse");
            assert!(ip_is_forbidden(&ip), "must be forbidden: {raw}");
        }
        for raw in PUBLIC_CONTROL_VECTORS {
            let ip: IpAddr = raw.parse().expect("public control must parse");
            assert!(!ip_is_forbidden(&ip), "must NOT be blocked: {raw}");
        }
    }

    #[test]
    fn shared_table_covers_every_required_family() {
        let table = FORBIDDEN_VECTORS.join(" ");
        // One vector per acceptance family, matched by prefix literal.
        for family in ["::ffff:", "2002:", "2001:db8::", "2001:0:", "64:ff9b::"] {
            assert!(
                table.contains(family),
                "shared table must cover family {family}"
            );
        }
        assert!(!PUBLIC_CONTROL_VECTORS.is_empty());
    }
}
