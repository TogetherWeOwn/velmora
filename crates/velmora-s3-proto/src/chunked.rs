//! The `aws-chunked` content coding of streaming uploads.
//!
//! ```text
//! chunk   = hex-size [";chunk-signature=" 64HEX] CRLF data CRLF
//! final   = "0" [";chunk-signature=" 64HEX] CRLF
//! trailer = *(name ":" value CRLF) ["x-amz-trailer-signature:" 64HEX CRLF] CRLF
//! ```
//!
//! Three `x-amz-content-sha256` values select the variant:
//!
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: every chunk is signed, chained
//!   from the seed (request) signature; no trailer.
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: as above, plus one
//!   trailing checksum signed by `x-amz-trailer-signature`.
//! - `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: no chunk signatures; the
//!   trailing checksum is the integrity check (TLS protects it in transit).
//!
//! [`ChunkedDecoder`] is incremental: it takes the encoded body in pieces
//! of any size and hands decoded bytes to a sink as they arrive, keeping
//! only one bounded header or trailer line. A chunk's bytes reach the sink
//! before that chunk's signature is checked, so callers must not publish
//! anything until [`ChunkedDecoder::finish`] (via
//! [`crate::UploadValidator::finish`]) succeeds.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{hex, unhex, ChecksumAlgorithm, ErrorCode, Result};

pub(crate) const SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub(crate) const SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
pub(crate) const UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Longest chunk-header or trailer line, CRLF excluded. A signed header is
/// at most 16 hex digits + `;chunk-signature=` + 64 hex digits = 97 bytes.
pub const MAX_LINE_BYTES: usize = 256;
/// Most trailer lines: one checksum and one trailer signature.
const MAX_TRAILER_LINES: usize = 2;
/// Smallest non-final chunk of the signed variants (AWS: 8 KiB). It bounds
/// the HMAC work per decoded byte.
pub const MIN_SIGNED_CHUNK_BYTES: u64 = 8192;

/// Which `aws-chunked` variant the signed `x-amz-content-sha256` selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Streaming {
    Signed,
    SignedTrailer,
    UnsignedTrailer,
}

impl Streaming {
    pub fn from_payload(payload: &str) -> Option<Self> {
        match payload {
            SIGNED => Some(Self::Signed),
            SIGNED_TRAILER => Some(Self::SignedTrailer),
            UNSIGNED_TRAILER => Some(Self::UnsignedTrailer),
            _ => None,
        }
    }
    pub fn signed(self) -> bool {
        !matches!(self, Self::UnsignedTrailer)
    }
    pub fn trailer(self) -> bool {
        !matches!(self, Self::Signed)
    }
}

/// What a signed stream chains from: the verified request's signing key,
/// timestamp, scope and seed signature. Deliberately not Debug-printing
/// the key.
#[derive(Clone)]
pub struct StreamingSeed {
    pub(crate) key: [u8; 32],
    pub(crate) timestamp: String,
    pub(crate) scope: String,
    pub(crate) signature: String,
}

impl fmt::Debug for StreamingSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingSeed")
            .field("timestamp", &self.timestamp)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl StreamingSeed {
    fn sign(&self, kind: &str, previous: &str, last_line: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key");
        let empty = if kind == "AWS4-HMAC-SHA256-PAYLOAD" {
            format!("{EMPTY_SHA256}\n")
        } else {
            String::new()
        };
        mac.update(
            format!(
                "{kind}\n{}\n{}\n{previous}\n{empty}{last_line}",
                self.timestamp, self.scope
            )
            .as_bytes(),
        );
        hex(&mac.finalize().into_bytes())
    }
}

/// The trailing checksum a stream carried, base64 as sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trailer {
    pub algorithm: ChecksumAlgorithm,
    pub value: String,
}

enum State {
    /// Reading a chunk header line.
    Header,
    /// Inside chunk data; this many bytes remain.
    Data(u64),
    /// After chunk data; this many bytes of its CRLF have been read.
    DataEnd(u8),
    /// Reading trailer lines.
    Trailer,
    Done,
}

/// Incremental `aws-chunked` decoder. See the module documentation.
pub struct ChunkedDecoder {
    mode: Streaming,
    seed: Option<StreamingSeed>,
    /// The previous signature in the chain (hex).
    previous: String,
    /// Declared trailer, from the signed `x-amz-trailer`.
    declared: Option<ChecksumAlgorithm>,
    expected: u64,
    decoded: u64,
    state: State,
    line: Vec<u8>,
    /// Signature claimed by the current chunk's header.
    claimed: Option<[u8; 32]>,
    chunk: Sha256,
    /// Length of the previous data chunk, for the signed minimum.
    last_len: Option<u64>,
    trailer: Option<Trailer>,
    trailer_signature: Option<[u8; 32]>,
    trailer_lines: usize,
    /// The last trailer line ended in a bare LF; a CRLF right after it is
    /// that line's terminator, not the blank line that ends the trailer.
    bare_lf: bool,
    failed: bool,
}

impl ChunkedDecoder {
    /// `seed` is required for the signed variants and ignored otherwise.
    /// `declared` is the algorithm named by `x-amz-trailer`.
    pub fn new(
        mode: Streaming,
        seed: Option<StreamingSeed>,
        declared: Option<ChecksumAlgorithm>,
        expected: u64,
    ) -> Result<Self> {
        if mode.signed() != seed.is_some()
            || declared.is_some() && !mode.trailer()
            || mode == Streaming::SignedTrailer && declared.is_none()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let previous = seed
            .as_ref()
            .map(|s| s.signature.clone())
            .unwrap_or_default();
        Ok(Self {
            mode,
            seed: seed.filter(|_| mode.signed()),
            previous,
            declared,
            expected,
            decoded: 0,
            state: State::Header,
            line: Vec::new(),
            claimed: None,
            chunk: Sha256::new(),
            last_len: None,
            trailer: None,
            trailer_signature: None,
            trailer_lines: 0,
            bare_lf: false,
            failed: false,
        })
    }

    /// Decodes the next piece of the encoded body, handing decoded bytes to
    /// `sink`. The first error is sticky.
    pub fn push(
        &mut self,
        mut input: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if self.failed {
            return Err(ErrorCode::InvalidRequest);
        }
        let result = (|| {
            while !input.is_empty() {
                input = self.step(input, sink)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// The stream is complete: the final chunk and the trailer section were
    /// read and every signature matched. Returns the trailing checksum.
    pub fn finish(self) -> Result<Option<Trailer>> {
        if self.failed {
            return Err(ErrorCode::InvalidRequest);
        }
        if !matches!(self.state, State::Done) || self.decoded != self.expected {
            return Err(ErrorCode::IncompleteBody);
        }
        Ok(self.trailer)
    }

    fn step<'a>(
        &mut self,
        input: &'a [u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<&'a [u8]> {
        match self.state {
            State::Header | State::Trailer => {
                let trailer = matches!(self.state, State::Trailer);
                let Some((rest, bare)) = self.take_line(input, trailer)? else {
                    return Ok(&[]);
                };
                let line = std::mem::take(&mut self.line);
                if !trailer {
                    self.header(&line)?;
                } else if std::mem::replace(&mut self.bare_lf, bare) && line.is_empty() {
                    // The CRLF that follows a bare-LF trailer line
                    // (`name:value\n\r\n`, a documented variant).
                } else {
                    self.trailer_line(&line)?;
                }
                Ok(rest)
            }
            State::Data(remaining) => {
                let n = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(input.len());
                let (data, rest) = input.split_at(n);
                if self.seed.is_some() {
                    self.chunk.update(data);
                }
                sink(data)?;
                let left = remaining - n as u64;
                self.state = if left == 0 {
                    State::DataEnd(0)
                } else {
                    State::Data(left)
                };
                Ok(rest)
            }
            State::DataEnd(seen) => {
                let want = b"\r\n"[usize::from(seen)];
                if input[0] != want {
                    return Err(ErrorCode::InvalidRequest);
                }
                if seen == 0 {
                    self.state = State::DataEnd(1);
                } else {
                    // Only the signed variants hash chunks.
                    if self.seed.is_some() {
                        let digest = hex(&std::mem::take(&mut self.chunk).finalize());
                        self.check_chunk(&digest)?;
                    }
                    self.state = State::Header;
                }
                Ok(&input[1..])
            }
            State::Done => Err(ErrorCode::InvalidRequest),
        }
    }

    /// Accumulates one CRLF-terminated line; `None` while incomplete.
    /// One line. Chunk headers must end in CRLF; a trailer line may also end
    /// in a bare LF (`bare` = true), which some clients send before the CRLF.
    fn take_line<'a>(
        &mut self,
        input: &'a [u8],
        trailer: bool,
    ) -> Result<Option<(&'a [u8], bool)>> {
        let end = input.iter().position(|&b| b == b'\n');
        let piece = &input[..end.map_or(input.len(), |i| i + 1)];
        if self.line.len() + piece.len() > MAX_LINE_BYTES + 2 {
            return Err(ErrorCode::InvalidRequest);
        }
        self.line.extend_from_slice(piece);
        let Some(i) = end else { return Ok(None) };
        let crlf = self.line.len() >= 2 && self.line[self.line.len() - 2] == b'\r';
        let bare = !crlf && trailer && self.line.len() >= 2;
        if !crlf && !bare {
            return Err(ErrorCode::InvalidRequest);
        }
        self.line
            .truncate(self.line.len() - if crlf { 2 } else { 1 });
        if self.line.contains(&b'\r') {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Some((&input[i + 1..], bare)))
    }

    fn header(&mut self, line: &[u8]) -> Result<()> {
        let line = std::str::from_utf8(line).map_err(|_| ErrorCode::InvalidRequest)?;
        let (size, signature) = match line.split_once(';') {
            Some((size, ext)) => {
                let sig = ext
                    .strip_prefix("chunk-signature=")
                    .ok_or(ErrorCode::InvalidRequest)?;
                (size, Some(sig))
            }
            None => (line, None),
        };
        if size.is_empty() || size.len() > 16 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ErrorCode::InvalidRequest);
        }
        let size = u64::from_str_radix(size, 16).map_err(|_| ErrorCode::InvalidRequest)?;
        self.claimed = match (self.mode.signed(), signature) {
            (true, Some(sig)) if sig.len() == 64 => Some(
                unhex(sig)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or(ErrorCode::SignatureDoesNotMatch)?,
            ),
            (true, Some(_)) => return Err(ErrorCode::SignatureDoesNotMatch),
            (true, None) | (false, Some(_)) => return Err(ErrorCode::InvalidRequest),
            (false, None) => None,
        };
        // Only the last data chunk may be shorter than the signed minimum.
        if size > 0
            && self.mode.signed()
            && self.last_len.is_some_and(|n| n < MIN_SIGNED_CHUNK_BYTES)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        if size > self.expected - self.decoded {
            return Err(ErrorCode::IncompleteBody);
        }
        if size == 0 {
            self.check_chunk(EMPTY_SHA256)?;
            self.state = State::Trailer;
        } else {
            self.decoded += size;
            self.last_len = Some(size);
            self.state = State::Data(size);
        }
        Ok(())
    }

    /// Checks the current chunk's claimed signature against its data
    /// digest and advances the chain.
    fn check_chunk(&mut self, digest: &str) -> Result<()> {
        let Some(seed) = &self.seed else {
            return Ok(());
        };
        let expected = seed.sign("AWS4-HMAC-SHA256-PAYLOAD", &self.previous, digest);
        let claimed = self.claimed.take().ok_or(ErrorCode::InvalidRequest)?;
        if !bool::from(hex(&claimed).as_bytes().ct_eq(expected.as_bytes())) {
            return Err(ErrorCode::SignatureDoesNotMatch);
        }
        self.previous = expected;
        Ok(())
    }

    fn trailer_line(&mut self, line: &[u8]) -> Result<()> {
        if line.is_empty() {
            return self.end_trailer();
        }
        self.trailer_lines += 1;
        if self.trailer_lines > MAX_TRAILER_LINES || self.trailer_signature.is_some() {
            return Err(ErrorCode::InvalidRequest);
        }
        let line = std::str::from_utf8(line).map_err(|_| ErrorCode::InvalidRequest)?;
        let (name, value) = line.split_once(':').ok_or(ErrorCode::InvalidRequest)?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "x-amz-trailer-signature" {
            if self.mode != Streaming::SignedTrailer || self.trailer.is_none() {
                return Err(ErrorCode::InvalidRequest);
            }
            let sig = unhex(value)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or(ErrorCode::SignatureDoesNotMatch)?;
            self.trailer_signature = Some(sig);
            return Ok(());
        }
        let algorithm = self.declared.ok_or(ErrorCode::InvalidRequest)?;
        if self.trailer.is_some() || name != algorithm.header() {
            return Err(ErrorCode::InvalidRequest);
        }
        super::upload::digest_value(value, algorithm.size())?;
        self.trailer = Some(Trailer {
            algorithm,
            value: value.to_owned(),
        });
        Ok(())
    }

    fn end_trailer(&mut self) -> Result<()> {
        if self.declared.is_some() && self.trailer.is_none() {
            return Err(ErrorCode::IncompleteBody);
        }
        if self.mode == Streaming::SignedTrailer {
            let (Some(seed), Some(trailer), Some(claimed)) =
                (&self.seed, &self.trailer, self.trailer_signature)
            else {
                return Err(ErrorCode::SignatureDoesNotMatch);
            };
            let canonical = format!("{}:{}\n", trailer.algorithm.header(), trailer.value);
            let expected = seed.sign(
                "AWS4-HMAC-SHA256-TRAILER",
                &self.previous,
                &hex(&Sha256::digest(canonical.as_bytes())),
            );
            if !bool::from(hex(&claimed).as_bytes().ct_eq(expected.as_bytes())) {
                return Err(ErrorCode::SignatureDoesNotMatch);
            }
        }
        self.state = State::Done;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! The worked examples of the AWS S3 API reference, "Signature
    //! Calculations for the Authorization Header: Transferring Payload in
    //! Multiple Chunks" and its trailing-headers variant: secret
    //! `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, 2013-05-24, us-east-1,
    //! `PUT /examplebucket/chunkObject.txt`, 65536 + 1024 bytes of `a`.

    use super::*;
    use crate::{canonical_request, Headers, Limits, Policy, Target};

    const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const TIMESTAMP: &str = "20130524T000000Z";
    const SCOPE: &str = "20130524/us-east-1/s3/aws4_request";

    fn policy() -> Policy {
        Policy::new(
            "s3.amazonaws.com".into(),
            "us-east-1".into(),
            Limits {
                target_bytes: 8192,
                control_xml_bytes: 4096,
                header_bytes: 16384,
                header_count: 64,
                query_pairs: 64,
                upload_bytes: 1 << 20,
                clock_skew_seconds: 900,
                presign_seconds: 60,
            },
        )
        .unwrap()
    }

    fn seed_from_request(headers: &[(&str, &str)], payload: &str) -> StreamingSeed {
        let policy = policy();
        let target = Target::parse("/examplebucket/chunkObject.txt", &policy).unwrap();
        let h = Headers::new(headers, &policy).unwrap();
        let signed: Vec<_> = headers.iter().map(|(k, _)| *k).collect();
        let canonical =
            canonical_request("PUT", &target, &h, &signed.join(";"), payload, false).unwrap();
        let key = crate::auth::signing_key(SECRET, "20130524", "us-east-1");
        let signature = crate::auth::sign(
            &key,
            &format!(
                "AWS4-HMAC-SHA256\n{TIMESTAMP}\n{SCOPE}\n{}",
                hex(&Sha256::digest(canonical.as_bytes()))
            ),
        );
        StreamingSeed {
            key,
            timestamp: TIMESTAMP.into(),
            scope: SCOPE.into(),
            signature: hex(&signature),
        }
    }

    fn signed_seed() -> StreamingSeed {
        seed_from_request(
            &[
                ("content-encoding", "aws-chunked"),
                ("content-length", "66824"),
                ("host", "s3.amazonaws.com"),
                ("x-amz-content-sha256", SIGNED),
                ("x-amz-date", TIMESTAMP),
                ("x-amz-decoded-content-length", "66560"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            SIGNED,
        )
    }

    fn trailer_seed() -> StreamingSeed {
        seed_from_request(
            &[
                ("content-encoding", "aws-chunked"),
                ("host", "s3.amazonaws.com"),
                ("x-amz-content-sha256", SIGNED_TRAILER),
                ("x-amz-date", TIMESTAMP),
                ("x-amz-decoded-content-length", "66560"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                ("x-amz-trailer", "x-amz-checksum-crc32c"),
            ],
            SIGNED_TRAILER,
        )
    }

    fn body(sigs: [&str; 3], trailer: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(format!("10000;chunk-signature={}\r\n", sigs[0]).as_bytes());
        b.extend_from_slice(&[b'a'; 65536]);
        b.extend_from_slice(format!("\r\n400;chunk-signature={}\r\n", sigs[1]).as_bytes());
        b.extend_from_slice(&[b'a'; 1024]);
        b.extend_from_slice(format!("\r\n0;chunk-signature={}\r\n", sigs[2]).as_bytes());
        b.extend_from_slice(trailer.as_bytes());
        b.extend_from_slice(b"\r\n");
        b
    }

    const CHUNK_SIGS: [&str; 3] = [
        "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
        "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
        "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
    ];
    const TRAILER_CHUNK_SIGS: [&str; 3] = [
        "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2",
        "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7",
        "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992",
    ];
    const TRAILER: &str = "x-amz-checksum-crc32c:sOO8/Q==\r\nx-amz-trailer-signature:d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435\r\n";

    fn decode(
        mode: Streaming,
        seed: Option<StreamingSeed>,
        declared: Option<ChecksumAlgorithm>,
        expected: u64,
        encoded: &[u8],
        piece: usize,
    ) -> Result<(Vec<u8>, Option<Trailer>)> {
        let mut d = ChunkedDecoder::new(mode, seed, declared, expected)?;
        let mut out = Vec::new();
        for p in encoded.chunks(piece) {
            d.push(p, &mut |b| {
                out.extend_from_slice(b);
                Ok(())
            })?;
        }
        Ok((out, d.finish()?))
    }

    #[test]
    fn aws_example_seed_signatures() {
        assert_eq!(
            signed_seed().signature,
            "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
        );
        assert_eq!(
            trailer_seed().signature,
            "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e"
        );
    }

    #[test]
    fn aws_example_signed_chunks_decode_in_any_piece_size() {
        let encoded = body(CHUNK_SIGS, "");
        for piece in [1, 2, 7, 97, 4096, encoded.len()] {
            let (out, trailer) = decode(
                Streaming::Signed,
                Some(signed_seed()),
                None,
                66560,
                &encoded,
                piece,
            )
            .unwrap();
            assert_eq!(out, vec![b'a'; 66560], "piece {piece}");
            assert_eq!(trailer, None);
        }
    }

    #[test]
    fn aws_example_signed_trailer_decodes() {
        let encoded = body(TRAILER_CHUNK_SIGS, TRAILER);
        for piece in [1, 13, 65536, encoded.len()] {
            let (out, trailer) = decode(
                Streaming::SignedTrailer,
                Some(trailer_seed()),
                Some(ChecksumAlgorithm::Crc32c),
                66560,
                &encoded,
                piece,
            )
            .unwrap();
            assert_eq!(out.len(), 66560);
            assert_eq!(
                trailer,
                Some(Trailer {
                    algorithm: ChecksumAlgorithm::Crc32c,
                    value: "sOO8/Q==".into()
                })
            );
        }
    }

    #[test]
    fn tampered_signatures_are_refused() {
        let signed = |sigs: [&str; 3], data_flip: bool| {
            let mut encoded = body(sigs, "");
            if data_flip {
                let i = encoded.len() / 2;
                encoded[i] = b'b';
            }
            decode(
                Streaming::Signed,
                Some(signed_seed()),
                None,
                66560,
                &encoded,
                4096,
            )
            .unwrap_err()
        };
        let mut bad = CHUNK_SIGS;
        bad[1] = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5498";
        assert_eq!(signed(bad, false), ErrorCode::SignatureDoesNotMatch);
        let mut bad = CHUNK_SIGS;
        bad[2] = CHUNK_SIGS[1];
        assert_eq!(signed(bad, false), ErrorCode::SignatureDoesNotMatch);
        assert_eq!(signed(CHUNK_SIGS, true), ErrorCode::SignatureDoesNotMatch);
        let mut bad = CHUNK_SIGS;
        bad[0] = "zz";
        assert_eq!(signed(bad, false), ErrorCode::SignatureDoesNotMatch);
        // A chain seeded from another request does not verify.
        let encoded = body(TRAILER_CHUNK_SIGS, TRAILER);
        assert_eq!(
            decode(
                Streaming::SignedTrailer,
                Some(signed_seed()),
                Some(ChecksumAlgorithm::Crc32c),
                66560,
                &encoded,
                4096
            )
            .unwrap_err(),
            ErrorCode::SignatureDoesNotMatch
        );
        // Trailer value changed under a valid trailer signature.
        let encoded = body(TRAILER_CHUNK_SIGS, &TRAILER.replace("sOO8/Q==", "AAAAAA=="));
        assert_eq!(
            decode(
                Streaming::SignedTrailer,
                Some(trailer_seed()),
                Some(ChecksumAlgorithm::Crc32c),
                66560,
                &encoded,
                4096
            )
            .unwrap_err(),
            ErrorCode::SignatureDoesNotMatch
        );
        // The trailer signature is required.
        let unsigned_trailer = TRAILER.split_inclusive("\r\n").next().unwrap();
        let encoded = body(TRAILER_CHUNK_SIGS, unsigned_trailer);
        assert_eq!(
            decode(
                Streaming::SignedTrailer,
                Some(trailer_seed()),
                Some(ChecksumAlgorithm::Crc32c),
                66560,
                &encoded,
                4096
            )
            .unwrap_err(),
            ErrorCode::SignatureDoesNotMatch
        );
    }

    #[test]
    fn decoded_length_must_match() {
        let encoded = body(CHUNK_SIGS, "");
        for expected in [66559, 66561, 0] {
            assert_eq!(
                decode(
                    Streaming::Signed,
                    Some(signed_seed()),
                    None,
                    expected,
                    &encoded,
                    4096
                )
                .unwrap_err(),
                ErrorCode::IncompleteBody,
                "{expected}"
            );
        }
    }

    fn unsigned(encoded: &[u8], expected: u64) -> Result<(Vec<u8>, Option<Trailer>)> {
        decode(
            Streaming::UnsignedTrailer,
            None,
            Some(ChecksumAlgorithm::Crc64Nvme),
            expected,
            encoded,
            3,
        )
    }

    #[test]
    fn unsigned_trailer_as_aws_cli_sends_it() {
        // Captured from aws-cli 2.31.23 (PutObject over HTTPS, defaults).
        let wire = b"21\r\nhello world, this is a test body\n\r\n0\r\nx-amz-checksum-crc64nvme:bgGah9vCkZ4=\r\n\r\n";
        let (out, trailer) = unsigned(wire, 33).unwrap();
        assert_eq!(out, b"hello world, this is a test body\n");
        assert_eq!(trailer.unwrap().value, "bgGah9vCkZ4=");
    }

    #[test]
    fn trailer_line_may_end_in_lf_before_crlf() {
        // `name:value\n\r\n\r\n`, the documented trailing-LF variant.
        let wire = b"3\r\nabc\r\n0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\n\r\n\r\n";
        let (_, trailer) = unsigned(wire, 3).unwrap();
        assert_eq!(trailer.unwrap().value, "AAAAAAAAAAA=");
        // A bare LF on its own is still not a blank line, and chunk headers
        // stay strict CRLF.
        for bad in [
            &b"3\r\nabc\r\n0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\n\n"[..],
            &b"3\nabc\r\n0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\n\r\n"[..],
        ] {
            assert!(unsigned(bad, 3).is_err());
        }
    }

    #[test]
    fn malformed_framing_is_refused() {
        let ok = b"3\r\nabc\r\n0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\n\r\n";
        assert!(unsigned(ok, 3).is_ok());
        for (bad, code) in [
            // Missing final 0-chunk / truncated anywhere.
            (&b"3\r\nabc\r\n"[..], ErrorCode::IncompleteBody),
            (b"3\r\nabc\r\n0\r\n", ErrorCode::IncompleteBody),
            (b"3\r\nab", ErrorCode::IncompleteBody),
            // Trailer missing although declared.
            (b"3\r\nabc\r\n0\r\n\r\n", ErrorCode::IncompleteBody),
            // Bad CRLFs, sizes and extensions.
            (b"3\nabc\r\n0\r\n\r\n", ErrorCode::InvalidRequest),
            (b"3\r\nabcX\n0\r\n\r\n", ErrorCode::InvalidRequest),
            (b"x\r\nabc\r\n", ErrorCode::InvalidRequest),
            (b"\r\nabc\r\n", ErrorCode::InvalidRequest),
            (b"+3\r\nabc\r\n", ErrorCode::InvalidRequest),
            (b"3;chunk-signature=00\r\nabc\r\n", ErrorCode::InvalidRequest),
            (b"3;foo=bar\r\nabc\r\n", ErrorCode::InvalidRequest),
            (b"00000000000000003\r\nabc\r\n", ErrorCode::InvalidRequest),
            // More data than declared.
            (b"4\r\nabcd\r\n", ErrorCode::IncompleteBody),
            // Unknown or repeated trailers, bytes after the end.
            (
                b"3\r\nabc\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n",
                ErrorCode::InvalidRequest,
            ),
            (
                b"3\r\nabc\r\n0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\n\r\n",
                ErrorCode::InvalidRequest,
            ),
            (
                b"3\r\nabc\r\n0\r\nx-amz-checksum-crc64nvme:AAAA\r\n\r\n",
                ErrorCode::InvalidDigest,
            ),
            (
                b"3\r\nabc\r\n0\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\n\r\nX",
                ErrorCode::InvalidRequest,
            ),
            (
                b"3\r\nabc\r\n0\r\nx-amz-trailer-signature:00\r\n\r\n",
                ErrorCode::InvalidRequest,
            ),
        ] {
            assert_eq!(
                unsigned(bad, 3).unwrap_err(),
                code,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // An oversize header line fails before the line ends.
        let long = vec![b'0'; MAX_LINE_BYTES + 3];
        let mut d = ChunkedDecoder::new(Streaming::UnsignedTrailer, None, None, 3).unwrap();
        assert_eq!(
            d.push(&long, &mut |_| Ok(())).unwrap_err(),
            ErrorCode::InvalidRequest
        );
        // Errors are sticky.
        assert!(d.push(b"0\r\n\r\n", &mut |_| Ok(())).is_err());
        assert!(d.finish().is_err());
    }

    #[test]
    fn signed_chunks_below_the_minimum_are_refused() {
        // Two 1-byte data chunks: the first is non-final and too small. Its
        // signature is checked first, so sign it properly.
        let seed = signed_seed();
        let first = seed.sign(
            "AWS4-HMAC-SHA256-PAYLOAD",
            &seed.signature,
            &hex(&Sha256::digest(b"a")),
        );
        let encoded =
            format!("1;chunk-signature={first}\r\na\r\n1;chunk-signature={first}\r\na\r\n");
        assert_eq!(
            decode(
                Streaming::Signed,
                Some(seed),
                None,
                2,
                encoded.as_bytes(),
                5
            )
            .unwrap_err(),
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn construction_rules() {
        let seed = signed_seed();
        assert!(ChunkedDecoder::new(Streaming::Signed, None, None, 1).is_err());
        assert!(
            ChunkedDecoder::new(Streaming::UnsignedTrailer, Some(seed.clone()), None, 1).is_err()
        );
        assert!(ChunkedDecoder::new(
            Streaming::Signed,
            Some(seed.clone()),
            Some(ChecksumAlgorithm::Crc32),
            1
        )
        .is_err());
        assert!(
            ChunkedDecoder::new(Streaming::SignedTrailer, Some(seed.clone()), None, 1).is_err()
        );
        // Debug output never carries the signing key.
        let shown = format!("{seed:?}");
        assert!(shown.contains("StreamingSeed") && !shown.contains("key"));
    }
}
