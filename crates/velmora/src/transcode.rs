//! `opus-64` transcode profile: the pinned encoder contract both the
//! pre-compute and the on-demand paths execute (spec §4, `docs/adr/0003`).
//!
//! One profile, no negotiation matrix: Opus audio in an Ogg container at
//! 64 kbps, 48 kHz, stereo. The encoder is ffmpeg (`libopus`) with the
//! argv pinned by [`ffmpeg_argv`]; the Ogg page serial ffmpeg randomises
//! is rewritten to [`OGG_FIXED_SERIAL`] by [`normalize_ogg_serial`] so
//! the stored bytes — and therefore the SHA-256 the publication rows
//! key on — are identical whichever path produced them.
//!
//! Why ffmpeg plus a normaliser instead of `opusenc --serial`:
//!
//! - `opusenc --serial <fixed>` is byte-deterministic, but it preserves
//!   the input's rate and channel count (verified: 8 kHz mono in yields
//!   1 ch / 8 kHz out, 44.1 kHz stereo yields 2 ch / 44.1 kHz), so it
//!   cannot pin the 48 kHz stereo profile without a resample pre-pass.
//!   It also only reads WAV/FLAC/AIFF, while verified release bytes may
//!   be MP3 or other ffmpeg-decodable formats.
//! - ffmpeg pins rate/channels/codec exactly (`-ar 48000 -ac 2 -c:a
//!   libopus -b:a 64k`) but randomises the Ogg page serial on every
//!   run, including under `-fflags +bitexact` and `-serial_offset`
//!   (verified on ffmpeg 7.0.2: two runs differ ONLY in the 4 serial
//!   bytes per page plus the CRC32s covering them).
//!
//! The normaliser closes that last gap: rewriting the serial and the
//! CRC32 is mathematically safe (the serial is arbitrary per RFC 3533
//! §6 and the CRC is a defined function of the page), version-pinned
//! by the container image, and unit-tested here without any encoder
//! binary. The container build additionally self-tests determinism by
//! encoding the staging fixture twice and comparing hashes.
//!
//! [`artifact_r2_key`] derives the content-addressed R2 key in the ADR
//! 0003 layout (`audio/{hh}/{hh}/{sha}`); format is distinguished by
//! `track_media(format, bitrate)`, never by key prefix, so opus
//! artifacts share the audio bucket with source bytes.

/// Profile name carried on grant bindings and API `?profile=` values.
pub const PROFILE_NAME: &str = "opus-64";
/// `track_media.format` for artifacts of this profile.
pub const FORMAT: &str = "opus";
/// `track_media.bitrate` for artifacts of this profile (kbps).
pub const BITRATE_KBPS: u32 = 64;
/// Output sample rate in Hz (OpusHead rate field).
pub const SAMPLE_RATE_HZ: u32 = 48000;
/// Output channel count.
pub const CHANNELS: u32 = 2;

/// Fixed Ogg page serial every artifact normalises to. Serials only
/// need uniqueness within one chained stream (RFC 3533 §6) and each
/// artifact is a single logical stream, so a constant is safe and is
/// exactly what makes cross-path bytes identical.
pub const OGG_FIXED_SERIAL: u32 = 1;

/// Pinned ffmpeg invocation for the profile. `input` is the verified
/// source audio path, `output` the artifact path; both are passed as
/// single argv elements (no shell). Flags, in order:
///
/// - `-v error`: diagnostics only, never stdout bytes.
/// - `-fflags +bitexact`: no encoder-version strings or timestamps
///   beyond what the pinned binary already stabilises.
/// - `-map 0:a:0 -vn`: first audio stream only; embedded cover art
///   (a video stream in tagged FLAC/MP3) must never reach the muxer.
/// - `-map_metadata -1`: input tags differ between rips of identical
///   audio and would otherwise break byte-identical output.
/// - `-c:a libopus -b:a 64k -vbr off -ar 48000 -ac 2`: the §4.1 profile.
///   Explicit CBR keeps packet bitrate at 64k; libopus's default VBR
///   treats `-b:a` as a target and can exceed the profile's envelope.
///
/// The exact argv is pinned by tests: any flag change alters artifact
/// bytes and therefore every content hash, so it is a deliberate,
/// reviewed decision, never a drive-by edit.
pub fn ffmpeg_argv(input: &str, output: &str) -> Vec<String> {
    vec![
        "-v".to_string(),
        "error".to_string(),
        "-fflags".to_string(),
        "+bitexact".to_string(),
        "-i".to_string(),
        input.to_string(),
        "-map".to_string(),
        "0:a:0".to_string(),
        "-vn".to_string(),
        "-map_metadata".to_string(),
        "-1".to_string(),
        "-c:a".to_string(),
        "libopus".to_string(),
        "-b:a".to_string(),
        "64k".to_string(),
        "-vbr".to_string(),
        "off".to_string(),
        "-ar".to_string(),
        "48000".to_string(),
        "-ac".to_string(),
        "2".to_string(),
        output.to_string(),
    ]
}

/// Ogg page framing offsets (RFC 3533 §6).
const OGG_CAPTURE: &[u8; 4] = b"OggS";
const OGG_MIN_HEADER: usize = 27;
const OGG_SERIAL_OFFSET: usize = 14;
const OGG_CRC_OFFSET: usize = 22;
const OGG_NSEG_OFFSET: usize = 26;

/// Ogg page CRC lookup table (RFC 3533 §6, the libogg direct
/// algorithm): polynomial `0x04C11DB7`, MSB-first, initial value 0,
/// no reflection, no final XOR. This is NOT the IEEE 802.3 / zlib
/// CRC-32 (`crc32fast`): same nominal polynomial, genuinely
/// different checksum — a page stamped with the IEEE value fails
/// decoder verification and is rejected or skipped.
const fn ogg_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut r = (i as u32) << 24;
        let mut j = 0;
        while j < 8 {
            r = if r & 0x8000_0000 != 0 {
                (r << 1) ^ 0x04C1_1DB7
            } else {
                r << 1
            };
            j += 1;
        }
        table[i] = r;
        i += 1;
    }
    table
}

static OGG_CRC_TABLE: [u32; 256] = ogg_crc_table();

/// Ogg page CRC over `data` (normally a page with the CRC field
/// zeroed). Direct MSB-first CRC-32, poly `0x04C11DB7`, init 0, no
/// final XOR — see [`OGG_CRC_TABLE`].
fn ogg_crc(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |crc, &b| {
        (crc << 8) ^ OGG_CRC_TABLE[(((crc >> 24) as u8) ^ b) as usize]
    })
}

/// Why an Ogg byte string cannot be normalised. Offsets are byte
/// positions into the input; no input bytes are ever echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OggNormalizeError {
    /// Zero-length input is not an Ogg stream.
    Empty,
    /// Bytes at `offset` do not start with the `OggS` capture pattern.
    BadCapture { offset: usize },
    /// Page version is not the RFC 3533 version 0 this parser reads.
    UnsupportedVersion { offset: usize, version: u8 },
    /// A page starting at `offset` runs past the end of the input.
    Truncated { offset: usize },
}

/// Split validated Ogg page spans (`(offset, len)`) for `ogg`.
///
/// Every page's capture pattern, version and framing lengths are
/// checked; the CRC itself is NOT verified (the normaliser rewrites
/// it, and a corrupt page still normalises to a well-formed page —
/// corruption detection is the hash comparison against the published
/// `artifact_sha256`, not the page CRC).
pub fn split_ogg_pages(ogg: &[u8]) -> Result<Vec<(usize, usize)>, OggNormalizeError> {
    if ogg.is_empty() {
        return Err(OggNormalizeError::Empty);
    }
    let mut spans = Vec::new();
    let mut offset = 0;
    while offset < ogg.len() {
        let rest = &ogg[offset..];
        if rest.len() < OGG_MIN_HEADER {
            // A short tail starting with a capture is a cut page;
            // anything else is trailing garbage after the last page.
            if rest.starts_with(OGG_CAPTURE) {
                return Err(OggNormalizeError::Truncated { offset });
            }
            return Err(OggNormalizeError::BadCapture { offset });
        }
        if !rest.starts_with(OGG_CAPTURE) {
            return Err(OggNormalizeError::BadCapture { offset });
        }
        if rest[4] != 0 {
            return Err(OggNormalizeError::UnsupportedVersion {
                offset,
                version: rest[4],
            });
        }
        let nseg = rest[OGG_NSEG_OFFSET] as usize;
        let table_end = OGG_MIN_HEADER + nseg;
        if rest.len() < table_end {
            return Err(OggNormalizeError::Truncated { offset });
        }
        let body_len: usize = rest[OGG_MIN_HEADER..table_end]
            .iter()
            .map(|&b| b as usize)
            .sum();
        let page_len = table_end + body_len;
        if rest.len() < page_len {
            return Err(OggNormalizeError::Truncated { offset });
        }
        spans.push((offset, page_len));
        offset += page_len;
    }
    Ok(spans)
}

/// Rewrite every Ogg page serial in `ogg` to `serial`, recomputing
/// each page's CRC (the Ogg direct CRC-32, [`ogg_crc`], over the page
/// with the CRC field zeroed). All other bytes — headers, packets,
/// granule positions — pass through untouched, so normalising the
/// same logical stream twice (or normalising an already-normalised
/// artifact) is idempotent.
///
/// Fails closed on anything that is not a clean run of Ogg pages;
/// the caller treats that as an undecodable encode, never as bytes
/// to publish.
pub fn normalize_ogg_serial(ogg: &[u8], serial: u32) -> Result<Vec<u8>, OggNormalizeError> {
    let spans = split_ogg_pages(ogg)?;
    let mut out = Vec::with_capacity(ogg.len());
    for (offset, len) in spans {
        let mut page = ogg[offset..offset + len].to_vec();
        page[OGG_SERIAL_OFFSET..OGG_SERIAL_OFFSET + 4].copy_from_slice(&serial.to_le_bytes());
        page[OGG_CRC_OFFSET..OGG_CRC_OFFSET + 4].copy_from_slice(&[0, 0, 0, 0]);
        let crc = ogg_crc(&page);
        page[OGG_CRC_OFFSET..OGG_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&page);
    }
    Ok(out)
}

/// Why a SHA-256 hex string cannot name an artifact key. Offsets are
/// byte positions; no input bytes are ever echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Input is not exactly 64 hex chars.
    BadLength { len: usize },
    /// Non-hex byte at `offset`.
    NonHex { offset: usize },
}

/// Canonical lowercase hex for a 64-char hex digest. Accepts either
/// case on input (producers emit lowercase via `hex::encode`; the
/// canonicaliser makes case confusion impossible downstream).
pub fn canonical_sha256_hex(raw: &str) -> Result<String, KeyError> {
    if raw.len() != 64 {
        return Err(KeyError::BadLength { len: raw.len() });
    }
    let mut out = String::with_capacity(64);
    for (offset, b) in raw.bytes().enumerate() {
        if !b.is_ascii_hexdigit() {
            return Err(KeyError::NonHex { offset });
        }
        out.push((b as char).to_ascii_lowercase());
    }
    Ok(out)
}

/// Content-addressed R2 key for artifact bytes in the ADR 0003
/// layout: `audio/{hh}/{hh}/{sha256hex}`. The hash is canonicalised
/// (see [`canonical_sha256_hex`]) so differently-cased spellings of
/// one digest name one object.
pub fn artifact_r2_key(artifact_sha256_hex: &str) -> Result<String, KeyError> {
    let sha = canonical_sha256_hex(artifact_sha256_hex)?;
    Ok(format!("audio/{}/{}/{}", &sha[0..2], &sha[2..4], sha))
}

/// Staged transcode input object name: `{index:04}-{sha256(file_name)}`
/// (69 chars), exactly the verify-staged name
/// (`VerifyProgress::file_key`) the front reads back from
/// `{scratch_prefix}in/`. The index keeps two files that share a name
/// from sharing one staged object; the name hash keeps hostile NZB
/// bytes out of key space entirely.
///
/// Shared by the ingest dispatch, the transcode front contract and the
/// Container staging path so the three can never disagree on what an
/// input key looks like. The bare 64-hex core-contract shape is NOT
/// accepted: no producer stages it, and accepting two shapes would let
/// a forged key address bytes the job never staged.
pub fn validate_transcode_input_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.len() != 69 || bytes[4] != b'-' {
        return false;
    }
    if !bytes[..4].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    bytes[5..]
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// Scratch round-dir prefixes are short by construction
/// (`ingest-scratch/{job_id}/r{round}/`); anything longer is not one.
pub const MAX_TRANSCODE_PREFIX_BYTES: usize = 256;

/// True only for the round dir the job's verify staging lives in:
/// `ingest-scratch/{job_id}/.../` with a trailing slash, a safe
/// charset, and the length cap. The job containment is the point: a
/// forged prefix must never address another job's staged bytes.
///
/// Shared by the ingest dispatch and the transcode front parse so the
/// two can never disagree on the containment rule.
pub fn validate_transcode_prefix(prefix: &str, job_id: &str) -> bool {
    if prefix.len() > MAX_TRANSCODE_PREFIX_BYTES || !prefix.ends_with('/') {
        return false;
    }
    let root = format!("ingest-scratch/{job_id}/");
    if !prefix.starts_with(&root) {
        return false;
    }
    prefix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'_' || b == b'-' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffmpeg_argv_is_pinned() {
        assert_eq!(
            ffmpeg_argv("/in/flac", "/out/ogg"),
            vec![
                "-v",
                "error",
                "-fflags",
                "+bitexact",
                "-i",
                "/in/flac",
                "-map",
                "0:a:0",
                "-vn",
                "-map_metadata",
                "-1",
                "-c:a",
                "libopus",
                "-b:a",
                "64k",
                "-vbr",
                "off",
                "-ar",
                "48000",
                "-ac",
                "2",
                "/out/ogg",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn profile_consts_match_section_4_1() {
        assert_eq!(PROFILE_NAME, "opus-64");
        assert_eq!(FORMAT, "opus");
        assert_eq!(BITRATE_KBPS, 64);
        assert_eq!(SAMPLE_RATE_HZ, 48000);
        assert_eq!(CHANNELS, 2);
    }

    /// One synthetic Ogg page with `serial` and `body`, CRC correct.
    fn test_page(serial: u32, body: &[u8], sequence: u32) -> Vec<u8> {
        let mut page = Vec::new();
        page.extend_from_slice(b"OggS");
        page.push(0); // version
        page.push(0); // header type
        page.extend_from_slice(&0u64.to_le_bytes()); // granule
        page.extend_from_slice(&serial.to_le_bytes());
        page.extend_from_slice(&sequence.to_le_bytes());
        page.extend_from_slice(&[0, 0, 0, 0]); // crc placeholder
                                               // Segment table: body in 255-byte lacing values.
        let mut rest = body.len();
        let mut table = Vec::new();
        if rest == 0 {
            table.push(0);
        }
        while rest > 0 {
            let take = rest.min(255);
            table.push(take as u8);
            rest -= take;
        }
        page.push(table.len() as u8);
        page.extend_from_slice(&table);
        page.extend_from_slice(body);
        let crc = ogg_crc(&page);
        page[OGG_CRC_OFFSET..OGG_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        page
    }

    /// CRC of every page verifies with the CRC field zeroed.
    fn crcs_verify(ogg: &[u8]) -> bool {
        let Ok(spans) = split_ogg_pages(ogg) else {
            return false;
        };
        spans.iter().all(|&(offset, len)| {
            let mut page = ogg[offset..offset + len].to_vec();
            let stored =
                u32::from_le_bytes(page[OGG_CRC_OFFSET..OGG_CRC_OFFSET + 4].try_into().unwrap());
            page[OGG_CRC_OFFSET..OGG_CRC_OFFSET + 4].copy_from_slice(&[0, 0, 0, 0]);
            ogg_crc(&page) == stored
        })
    }

    /// First page of a real encoder-made Vorbis stream: beginning-of-
    /// stream identification header, serial `0x47b3c05d`, stored CRC
    /// `0x271310d6` exactly as the encoder wrote it. Pinning a page no
    /// test helper produced is the point: without it the suite only
    /// checks the implementation against itself, which is how the IEEE
    /// CRC-32 confusion shipped in the first place.
    const REAL_ENCODER_PAGE: &[u8; 58] = &[
        0x4f, 0x67, 0x67, 0x53, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5d,
        0xc0, 0xb3, 0x47, 0x00, 0x00, 0x00, 0x00, 0xd6, 0x10, 0x13, 0x27, 0x01, 0x1e, 0x01, 0x76,
        0x6f, 0x72, 0x62, 0x69, 0x73, 0x00, 0x00, 0x00, 0x00, 0x02, 0x44, 0xac, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x71, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x01,
    ];

    #[test]
    fn ogg_crc_matches_a_real_encoder_page() {
        // The encoder's stored CRC verifies under our implementation.
        assert!(crcs_verify(REAL_ENCODER_PAGE));
        let mut zeroed = REAL_ENCODER_PAGE.to_vec();
        zeroed[OGG_CRC_OFFSET..OGG_CRC_OFFSET + 4].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(ogg_crc(&zeroed), 0x2713_10d6);
        // ...and it is NOT the IEEE CRC-32 of the same bytes: the
        // confusion this test exists to prevent from recurring.
        assert_ne!(crc32fast::hash(&zeroed), 0x2713_10d6);

        // Normalising the real page keeps it verifiable: fixed serial,
        // recomputed CRC, identical body (nseg = 1, so the body starts
        // one byte past the 27-byte header).
        let out = normalize_ogg_serial(REAL_ENCODER_PAGE, OGG_FIXED_SERIAL).unwrap();
        assert!(crcs_verify(&out));
        let serial = u32::from_le_bytes(
            out[OGG_SERIAL_OFFSET..OGG_SERIAL_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(serial, OGG_FIXED_SERIAL);
        assert_eq!(
            &out[OGG_MIN_HEADER + 1..],
            &REAL_ENCODER_PAGE[OGG_MIN_HEADER + 1..]
        );
    }

    #[test]
    fn normalise_rewrites_serial_and_crc_only() {
        let mut ogg = test_page(0xDEAD_BEEF, b"OpusHead-payload", 0);
        ogg.extend_from_slice(&test_page(0xDEAD_BEEF, &vec![0xABu8; 600], 1));
        assert!(crcs_verify(&ogg));

        let out = normalize_ogg_serial(&ogg, OGG_FIXED_SERIAL).unwrap();
        assert_eq!(out.len(), ogg.len());
        assert!(crcs_verify(&out));

        // Both pages carry the fixed serial now.
        let spans = split_ogg_pages(&out).unwrap();
        assert_eq!(spans.len(), 2);
        for (offset, _) in &spans {
            let serial = u32::from_le_bytes(out[*offset + 14..*offset + 18].try_into().unwrap());
            assert_eq!(serial, OGG_FIXED_SERIAL);
        }
        // Payloads are untouched: strip framing, compare bodies.
        let strip = |bytes: &[u8]| -> Vec<u8> {
            split_ogg_pages(bytes)
                .unwrap()
                .iter()
                .flat_map(|&(o, l)| {
                    let nseg = bytes[o + OGG_NSEG_OFFSET] as usize;
                    bytes[o + OGG_MIN_HEADER + nseg..o + l].to_vec()
                })
                .collect()
        };
        assert_eq!(strip(&out), strip(&ogg));
    }

    #[test]
    fn normalise_is_idempotent() {
        let ogg = test_page(0x1234_5678, b"packet", 0);
        let once = normalize_ogg_serial(&ogg, OGG_FIXED_SERIAL).unwrap();
        let twice = normalize_ogg_serial(&once, OGG_FIXED_SERIAL).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn normalise_rejects_non_ogg() {
        assert_eq!(normalize_ogg_serial(&[], 1), Err(OggNormalizeError::Empty));
        assert_eq!(
            normalize_ogg_serial(b"RIFF....", 1),
            Err(OggNormalizeError::BadCapture { offset: 0 })
        );
        // Truncated header with a capture.
        assert_eq!(
            normalize_ogg_serial(b"OggS", 1),
            Err(OggNormalizeError::Truncated { offset: 0 })
        );
        // Bad version.
        let mut bad_ver = test_page(1, b"x", 0);
        bad_ver[4] = 7;
        assert_eq!(
            normalize_ogg_serial(&bad_ver, 1),
            Err(OggNormalizeError::UnsupportedVersion {
                offset: 0,
                version: 7
            })
        );
        // Trailing garbage after a good page.
        let mut trailing = test_page(1, b"x", 0);
        trailing.extend_from_slice(b"junk");
        assert_eq!(
            normalize_ogg_serial(&trailing, 1),
            Err(OggNormalizeError::BadCapture {
                offset: test_page(1, b"x", 0).len()
            })
        );
        // Body cut short.
        let mut cut = test_page(1, b"longer-body", 0);
        cut.truncate(cut.len() - 3);
        assert_eq!(
            normalize_ogg_serial(&cut, 1),
            Err(OggNormalizeError::Truncated { offset: 0 })
        );
    }

    #[test]
    fn artifact_key_layout_and_canonicalisation() {
        let sha = "9d70f11bc759d734ebb343f5932f005cebb343f5932f005c9d70f11bc759d734";
        assert_eq!(artifact_r2_key(sha).unwrap(), format!("audio/9d/70/{sha}"));
        // Uppercase input canonicalises to the same key.
        assert_eq!(
            artifact_r2_key(&sha.to_ascii_uppercase()).unwrap(),
            format!("audio/9d/70/{sha}")
        );
        assert_eq!(artifact_r2_key("abc"), Err(KeyError::BadLength { len: 3 }));
        let mut non_hex = "0".repeat(64);
        non_hex.replace_range(7..8, "z");
        assert_eq!(
            artifact_r2_key(&non_hex),
            Err(KeyError::NonHex { offset: 7 })
        );
    }

    #[test]
    fn transcode_input_key_shape_is_indexed_staged_name() {
        let hex = "9d70f11bc759d734ebb343f5932f005cebb343f5932f005c9d70f11bc759d734";
        // Exactly what verify stages: `{index:04}-{sha256(file_name)}`.
        assert!(validate_transcode_input_key(&format!("0007-{hex}")));
        assert!(validate_transcode_input_key(&format!("1023-{hex}")));
        // Bare object keys, wrong shapes, traversal and hostile bytes fail.
        assert!(!validate_transcode_input_key(hex));
        assert!(!validate_transcode_input_key("7-9d70"));
        assert!(!validate_transcode_input_key(&format!("0007_{hex}")));
        assert!(!validate_transcode_input_key(&format!(
            "0007-{}",
            hex.to_ascii_uppercase()
        )));
        assert!(!validate_transcode_input_key(&format!("0007-{hex}/")));
        assert!(!validate_transcode_input_key("../0007-x"));
        assert!(!validate_transcode_input_key(""));
        assert!(!validate_transcode_input_key(&format!("0007-{hex}x")));
    }

    #[test]
    fn transcode_prefix_containment_pins_job_root() {
        const JOB: &str = "job_01J9ZQ8K2M";
        assert!(validate_transcode_prefix(
            "ingest-scratch/job_01J9ZQ8K2M/r1/",
            JOB
        ));
        assert!(validate_transcode_prefix(
            "ingest-scratch/job_01J9ZQ8K2M/r12/",
            JOB
        ));
        // Another job, missing slash, hostile bytes fail. Dots pass
        // the charset (R2 keys are flat strings, so `..` traverses
        // nothing) but containment still holds: the prefix must start
        // with this job's root.
        assert!(!validate_transcode_prefix(
            "ingest-scratch/job_other/r1/",
            JOB
        ));
        assert!(!validate_transcode_prefix(
            "ingest-scratch/job_01J9ZQ8K2M/r1",
            JOB
        ));
        assert!(validate_transcode_prefix(
            "ingest-scratch/job_01J9ZQ8K2M/r1.backup/",
            JOB
        ));
        assert!(!validate_transcode_prefix(
            "ingest-scratch/job_01J9ZQ8K2M/r1/\0",
            JOB
        ));
        assert!(!validate_transcode_prefix("", JOB));
        let long = format!("ingest-scratch/{JOB}/r1/{}", "x".repeat(256));
        assert!(long.len() > MAX_TRANSCODE_PREFIX_BYTES);
        assert!(!validate_transcode_prefix(&long, JOB));
    }
}
