//! Minimal yEnc encode/decode helpers for fixtures and tests.
//!
//! yEnc (http://www.yenc.org): each source byte `b` is emitted as
//! `(b + 42) % 256`, with `0x00`, `0x0A`, `0x0D`, `0x3D` escaped as
//! `=`, followed by `(c + 64) % 256`.
//!
//! All functions are byte-oriented: yEnc output is raw bytes 0-255, not
//! UTF-8 text, so `encode` returns `Vec<u8>`.

/// Encode raw bytes into a yEnc body (no framing), wrapped at `line_len`.
///
/// Escape pairs are written atomically: `=` and its escaped byte never split
/// across a line break. A line may therefore run to `line_len + 1` bytes,
/// per the yEnc spec (the line grows by one for the escape).
pub fn encode(data: &[u8], line_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut col = 0usize;
    for &b in data {
        let c = b.wrapping_add(42);
        match c {
            0x00 | 0x0A | 0x0D | 0x3D => {
                out.push(b'=');
                out.push(c.wrapping_add(64));
                col += 2;
                if col >= line_len {
                    out.extend_from_slice(b"\r\n");
                    col = 0;
                }
            }
            _ => {
                out.push(c);
                col += 1;
                if col >= line_len {
                    out.extend_from_slice(b"\r\n");
                    col = 0;
                }
            }
        }
    }
    out
}

/// Decode a yEnc body (framing lines ignored) back to raw bytes.
///
/// Decodes line by line: an escape pair never spans lines from our encoder,
/// so a trailing `=` is a dangling (non-standard) escape and is ignored.
pub fn decode(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in body.split(|&b| b == b'\n') {
        let line = if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        };
        if line.starts_with(b"=y") {
            continue;
        }
        let mut it = line.iter();
        while let Some(&b) = it.next() {
            if b == b'=' {
                if let Some(&n) = it.next() {
                    out.push(n.wrapping_sub(64).wrapping_sub(42));
                }
                // Dangling '=' at end of line: ignore (non-standard input).
            } else {
                out.push(b.wrapping_sub(42));
            }
        }
    }
    out
}

/// CRC-32 (IEEE, polynomial 0xEDB88320) over raw bytes.
///
/// Used for `=yend crc32=` / `pcrc32=` framing without pulling a `crc` crate.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_escaped_bytes() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let enc = encode(&data, 128);
        assert_eq!(decode(&enc), data);
    }

    #[test]
    fn roundtrip_with_framing() {
        let data = b"hello nntune binary \x00\xff\x0a\x0d=";
        let mut framed = b"=ybegin line=128 size=22 name=test.bin\r\n".to_vec();
        framed.extend(encode(data, 128));
        framed.extend_from_slice(b"\r\n=yend\r\n");
        assert_eq!(decode(&framed), data);
    }

    #[test]
    fn encoder_never_splits_escape_pair() {
        // Exhaustive byte range plus pseudo-random blobs: no line may end
        // with a dangling '=' (the escape pair stays on one line).
        let data: Vec<u8> = (0u8..=255u8).collect();
        for payload in [
            data.clone(),
            crate::fixtures::generate_wav_bytes(440.0, 120, 8000),
            crate::fixtures::generate_wav_bytes(660.0, 210, 8000),
        ] {
            let enc = encode(&payload, 128);
            for line in enc.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                assert!(
                    !line.ends_with(b"="),
                    "encoded line ends with dangling escape: {line:?}"
                );
            }
            assert_eq!(decode(&enc), payload);
        }
    }

    #[test]
    fn crc32_matches_reference_vector() {
        // Standard IEEE check value for "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
