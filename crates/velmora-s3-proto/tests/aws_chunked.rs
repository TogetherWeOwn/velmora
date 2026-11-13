//! aws-chunked uploads through the public API: `verify` then
//! `UploadValidator::push_body`/`finish`, for the three streaming variants,
//! with requests and chunk chains signed here.

use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use velmora_s3_proto::mutation::UploadMetadata;
use velmora_s3_proto::*;

const NOW: i64 = 1369353600; // 2013-05-24T00:00:00Z
const DATE: &str = "20130524T000000Z";
const SCOPE: &str = "20130524/us-east-1/s3/aws4_request";
const HOST: &str = "s3.us-east-1.amazonaws.com";
const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
const SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
const UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

fn policy() -> Policy {
    Policy::new(
        HOST.into(),
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

struct Auth;
impl Authority for Auth {
    fn credential(&self, key: &str) -> Option<Credential<'_>> {
        (key == "AKIDEXAMPLE").then_some(Credential {
            secret: SECRET,
            principal: "p",
        })
    }
    fn authorize(&self, _: &str, _: &str, _: &Target) -> bool {
        true
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().to_vec()
}
fn key() -> Vec<u8> {
    let mut k = hmac(&[b"AWS4", SECRET].concat(), b"20130524");
    for part in [&b"us-east-1"[..], b"s3", b"aws4_request"] {
        k = hmac(&k, part);
    }
    k
}

/// A signed request: header list (with Authorization) and its signature.
fn request(fields: &[(&str, &str)], payload: &str) -> (Vec<(String, String)>, String) {
    let mut all: Vec<(String, String)> = vec![
        ("host".into(), HOST.into()),
        ("x-amz-date".into(), DATE.into()),
        ("x-amz-content-sha256".into(), payload.into()),
    ];
    all.extend(fields.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let mut names: Vec<_> = all
        .iter()
        .map(|(k, _)| k.clone())
        .filter(|k| k != "transfer-encoding" && k != "content-length")
        .collect();
    names.sort();
    let signed = names.join(";");
    let target = Target::parse("/bucket/key", &policy()).unwrap();
    let canonical =
        canonical_request("PUT", &target, &headers(&all), &signed, payload, false).unwrap();
    let sts = format!(
        "AWS4-HMAC-SHA256\n{DATE}\n{SCOPE}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let signature = hex(&hmac(&key(), sts.as_bytes()));
    all.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{SCOPE}, SignedHeaders={signed}, Signature={signature}"
        ),
    ));
    (all, signature)
}

fn headers(all: &[(String, String)]) -> Headers {
    let pairs: Vec<_> = all.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    Headers::new(&pairs, &policy()).unwrap()
}

fn chunk_sig(previous: &str, data: &[u8]) -> String {
    let sts = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{DATE}\n{SCOPE}\n{previous}\n{EMPTY_SHA}\n{}",
        hex(&Sha256::digest(data))
    );
    hex(&hmac(&key(), sts.as_bytes()))
}

/// Signed aws-chunked body: `chunks`, then the final chunk, then an
/// optional signed trailer `name:value`.
fn signed_body(seed: &str, chunks: &[&[u8]], trailer: Option<(&str, &str)>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut previous = seed.to_owned();
    for c in chunks.iter().copied().chain([&b""[..]]) {
        previous = chunk_sig(&previous, c);
        out.extend_from_slice(format!("{:x};chunk-signature={previous}\r\n", c.len()).as_bytes());
        if !c.is_empty() {
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
    }
    if let Some((name, value)) = trailer {
        let canonical = format!("{name}:{value}\n");
        let sts = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{DATE}\n{SCOPE}\n{previous}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let sig = hex(&hmac(&key(), sts.as_bytes()));
        out.extend_from_slice(
            format!("{name}:{value}\r\nx-amz-trailer-signature:{sig}\r\n").as_bytes(),
        );
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn unsigned_body(chunks: &[&[u8]], trailer: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for c in chunks {
        out.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        out.extend_from_slice(c);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n");
    if !trailer.is_empty() {
        out.extend_from_slice(format!("{trailer}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn crc32c_b64(data: &[u8]) -> String {
    let mut c: u32 = !0;
    for b in data {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
        }
    }
    STANDARD.encode((!c).to_be_bytes())
}

/// Runs the request through verify and the validator, feeding the body
/// in `piece`-byte reads. Returns the decoded bytes and the receipt.
fn upload(all: &[(String, String)], body: &[u8], piece: usize) -> Result<(Vec<u8>, DecodedUpload)> {
    let target = Target::parse("/bucket/key", &policy()).unwrap();
    let h = headers(all);
    let verified = verify("PUT", &target, &h, true, NOW, &policy(), &Auth)?;
    let mut v = UploadValidator::new(&h, &verified, &policy())?;
    let mut out = Vec::new();
    for p in body.chunks(piece.max(1)) {
        v.push_body(p, &mut |d| out.extend_from_slice(d))?;
    }
    Ok((out, v.finish()?))
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn signed_chunks_round_trip() {
    let d = data(20000);
    let (all, seed) = request(
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "20000"),
            ("transfer-encoding", "chunked"),
        ],
        SIGNED,
    );
    let body = signed_body(&seed, &[&d[..8192], &d[8192..16384], &d[16384..]], None);
    for piece in [1, 100, 8193, body.len()] {
        let (out, receipt) = upload(&all, &body, piece).unwrap();
        assert_eq!(out, d);
        assert_eq!(receipt.length(), 20000);
        assert_eq!(receipt.sha256(), &<[u8; 32]>::from(Sha256::digest(&d)));
        assert!(receipt.checksum().is_none());
    }
}

#[test]
fn signed_trailer_round_trip_and_tampering() {
    let d = data(9000);
    let crc = crc32c_b64(&d);
    let (all, seed) = request(
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "9000"),
            ("x-amz-trailer", "x-amz-checksum-crc32c"),
            ("x-amz-sdk-checksum-algorithm", "CRC32C"),
        ],
        SIGNED_TRAILER,
    );
    let body = signed_body(
        &seed,
        &[&d[..8192], &d[8192..]],
        Some(("x-amz-checksum-crc32c", &crc)),
    );
    let (out, receipt) = upload(&all, &body, 333).unwrap();
    assert_eq!(out, d);
    assert_eq!(
        receipt.checksum(),
        Some(&(ChecksumAlgorithm::Crc32c, crc.clone()))
    );

    // A flipped data byte breaks its chunk signature.
    let mut bad = body.clone();
    let i = bad.len() / 3;
    bad[i] ^= 1;
    assert_eq!(
        upload(&all, &bad, 333).unwrap_err(),
        ErrorCode::SignatureDoesNotMatch
    );
    // A correctly signed trailer whose checksum does not match the data.
    let wrong = crc32c_b64(b"other");
    let body = signed_body(
        &seed,
        &[&d[..8192], &d[8192..]],
        Some(("x-amz-checksum-crc32c", &wrong)),
    );
    assert_eq!(upload(&all, &body, 333).unwrap_err(), ErrorCode::BadDigest);
}

#[test]
fn tampered_chunk_signature_is_signature_does_not_match() {
    let d = data(100);
    let (all, seed) = request(
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "100"),
        ],
        SIGNED,
    );
    let body = signed_body(&seed, &[&d], None);
    let text = String::from_utf8_lossy(&body[..90]).into_owned();
    let sig = &text[text.find('=').unwrap() + 1..][..64];
    let forged = format!(
        "{}{}",
        &sig[..63],
        if sig.ends_with('0') { '1' } else { '0' }
    );
    let mut bad = body.clone();
    let at = text.find(sig).unwrap();
    bad[at..at + 64].copy_from_slice(forged.as_bytes());
    assert_eq!(
        upload(&all, &bad, 7).unwrap_err(),
        ErrorCode::SignatureDoesNotMatch
    );
    // The chain is bound to this request: another seed fails too.
    let other = signed_body(&"0".repeat(64), &[&d], None);
    assert_eq!(
        upload(&all, &other, 7).unwrap_err(),
        ErrorCode::SignatureDoesNotMatch
    );
}

#[test]
fn wrong_decoded_length_is_incomplete_body() {
    let d = data(100);
    for declared in ["99", "101"] {
        let (all, seed) = request(
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", declared),
            ],
            SIGNED,
        );
        let body = signed_body(&seed, &[&d], None);
        assert_eq!(
            upload(&all, &body, 10).unwrap_err(),
            ErrorCode::IncompleteBody,
            "{declared}"
        );
    }
}

#[test]
fn unsigned_trailer_checksums() {
    let d = b"hello world, this is a test body\n";
    let (all, _) = request(
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "33"),
            ("x-amz-trailer", "x-amz-checksum-crc64nvme"),
            ("x-amz-sdk-checksum-algorithm", "CRC64NVME"),
            ("transfer-encoding", "chunked"),
        ],
        UNSIGNED_TRAILER,
    );
    // The value aws-cli 2.31.23 sent for this body.
    let good = unsigned_body(&[d], "x-amz-checksum-crc64nvme:bgGah9vCkZ4=");
    let (out, receipt) = upload(&all, &good, 4).unwrap();
    assert_eq!(out, d);
    assert_eq!(
        receipt.checksum(),
        Some(&(ChecksumAlgorithm::Crc64Nvme, "bgGah9vCkZ4=".into()))
    );
    let bad = unsigned_body(&[d], "x-amz-checksum-crc64nvme:AAAAAAAAAAA=");
    assert_eq!(upload(&all, &bad, 4).unwrap_err(), ErrorCode::BadDigest);
    // Other algorithms by trailer, and Content-MD5 over the decoded bytes.
    for (alg, name, value) in [
        (
            "x-amz-checksum-sha256",
            "SHA256",
            STANDARD.encode(Sha256::digest(d)),
        ),
        ("x-amz-checksum-crc32c", "CRC32C", crc32c_b64(d)),
    ] {
        let md5 = STANDARD.encode(md5::compute(d).0);
        let (all, _) = request(
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", "33"),
                ("x-amz-trailer", alg),
                ("x-amz-sdk-checksum-algorithm", name),
                ("content-md5", &md5),
            ],
            UNSIGNED_TRAILER,
        );
        let body = unsigned_body(&[&d[..10], &d[10..]], &format!("{alg}:{value}"));
        upload(&all, &body, 5).unwrap();
        // Content-MD5 is signed, so a mismatch needs a fresh signature.
        let (all, _) = request(
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", "33"),
                ("x-amz-trailer", alg),
                ("content-md5", &STANDARD.encode([0u8; 16])),
            ],
            UNSIGNED_TRAILER,
        );
        assert_eq!(upload(&all, &body, 5).unwrap_err(), ErrorCode::BadDigest);
    }
}

#[test]
fn framing_must_agree_with_the_signed_payload() {
    let d = b"abc";
    let body = unsigned_body(&[d], "");
    let refused = |fields: &[(&str, &str)], payload: &str| {
        let (all, _) = request(fields, payload);
        upload(&all, &body, 3).unwrap_err()
    };
    // Streaming payload without aws-chunked, and the reverse.
    assert_eq!(
        refused(&[("x-amz-decoded-content-length", "3")], UNSIGNED_TRAILER),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        refused(
            &[("content-encoding", "aws-chunked"), ("content-length", "3"),],
            "UNSIGNED-PAYLOAD"
        ),
        ErrorCode::InvalidRequest
    );
    // No decoded length.
    assert_eq!(
        refused(&[("content-encoding", "aws-chunked")], UNSIGNED_TRAILER),
        ErrorCode::InvalidRequest
    );
    // Decoded length over the policy limit.
    assert_eq!(
        refused(
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", "1048577"),
            ],
            UNSIGNED_TRAILER
        ),
        ErrorCode::EntityTooLarge
    );
    // A trailer on the no-trailer variant, an unknown trailer, a trailer
    // and a header checksum together, the signed trailer variant without one.
    for (fields, payload) in [
        (vec![("x-amz-trailer", "x-amz-checksum-crc32")], SIGNED),
        (vec![("x-amz-trailer", "x-amz-meta-a")], UNSIGNED_TRAILER),
        (
            vec![
                ("x-amz-trailer", "x-amz-checksum-crc32"),
                ("x-amz-checksum-crc32", "NSRBwg=="),
            ],
            UNSIGNED_TRAILER,
        ),
        (vec![], SIGNED_TRAILER),
        (
            vec![
                ("x-amz-trailer", "x-amz-checksum-crc32"),
                ("x-amz-sdk-checksum-algorithm", "SHA256"),
            ],
            UNSIGNED_TRAILER,
        ),
    ] {
        let mut f = vec![
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "3"),
        ];
        f.extend(fields.iter().copied());
        assert_eq!(refused(&f, payload), ErrorCode::InvalidRequest, "{f:?}");
    }
    // HTTP chunked without aws-chunked is not accepted.
    let (all, _) = request(
        &[("transfer-encoding", "chunked")],
        &hex(&Sha256::digest(d)),
    );
    assert_eq!(upload(&all, d, 3).unwrap_err(), ErrorCode::InvalidRequest);
    // Presigned URLs have no seed for a chunk chain.
    let target = Target::parse(
        "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
        &policy(),
    )
    .unwrap();
    let h = headers(&[
        ("host".into(), HOST.into()),
        ("x-amz-content-sha256".into(), UNSIGNED_TRAILER.into()),
    ]);
    assert_eq!(
        verify("PUT", &target, &h, true, NOW, &policy(), &Auth).unwrap_err(),
        ErrorCode::InvalidRequest
    );
}

#[test]
fn identity_put_with_crc64nvme_header() {
    // What aws-cli 2.31.23 sends by default over plain HTTP.
    let d = b"hello world, this is a test body\n";
    let (all, _) = request(
        &[
            ("content-length", "33"),
            ("x-amz-checksum-crc64nvme", "bgGah9vCkZ4="),
            ("x-amz-sdk-checksum-algorithm", "CRC64NVME"),
        ],
        &hex(&Sha256::digest(d)),
    );
    let (out, receipt) = upload(&all, d, 5).unwrap();
    assert_eq!(out, d);
    assert_eq!(
        receipt.checksum(),
        Some(&(ChecksumAlgorithm::Crc64Nvme, "bgGah9vCkZ4=".into()))
    );
    let (all, _) = request(
        &[
            ("content-length", "33"),
            ("x-amz-checksum-crc64nvme", "AAAAAAAAAAA="),
        ],
        &hex(&Sha256::digest(d)),
    );
    assert_eq!(upload(&all, d, 5).unwrap_err(), ErrorCode::BadDigest);
}

#[test]
fn aws_chunked_is_not_stored_as_content_encoding() {
    let meta = |value: &str| {
        let h = Headers::new(&[("host", HOST), ("content-encoding", value)], &policy()).unwrap();
        UploadMetadata::from_headers(&h).unwrap().headers
    };
    assert!(meta("aws-chunked").is_empty());
    assert_eq!(
        meta("gzip,aws-chunked").into_iter().collect::<Vec<_>>(),
        [("content-encoding".to_string(), "gzip".to_string())]
    );
}
