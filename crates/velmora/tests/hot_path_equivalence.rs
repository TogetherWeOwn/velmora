//! The fast article paths must give the bytes the plain ones give.
//!
//! `encode_body` / `encode_segment` (one byte at a time through
//! `io::Write`) are the reference encoders; `encode_body_vec` /
//! `encode_segment_vec` are the vector forms the posting path uses. The
//! decoder is checked against a byte-at-a-time model written out here.
//! Golden digests pin the wire bytes themselves, so a change that moved
//! both forms together would still fail.

use sha2::{Digest, Sha256};
use velmora::article::{assemble_article, assemble_article_with};
use velmora::error::Error;
use velmora::yenc::{
    decode_part_to, decode_to, encode_body, encode_body_vec, encode_segment, encode_segment_vec,
    SegmentParams, LINE_LENGTH,
};

/// The four input bytes whose `+42` value is NUL, LF, CR or `=`.
const CRITICAL: [u8; 4] = [214, 224, 227, 19];

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Bytes where about one in `one_in` is critical (`one_in == 0`: none).
    fn bytes_with_critical(&mut self, len: usize, one_in: u64) -> Vec<u8> {
        let mut out = self.bytes(len);
        for b in &mut out {
            let roll = self.next();
            if one_in != 0 && roll.is_multiple_of(one_in) {
                *b = CRITICAL[(roll >> 32) as usize % 4];
            } else if CRITICAL.contains(b) {
                *b = b'a';
            }
        }
        out
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn assert_body_matches(data: &[u8], what: &str) {
    let mut want = Vec::new();
    let want_crc = encode_body(&mut want, data).unwrap();
    // A prefix already in the buffer must stay as it is.
    let mut got = b"prefix".to_vec();
    let got_crc = encode_body_vec(&mut got, data);
    assert_eq!(got_crc, want_crc, "crc differs: {what}");
    assert_eq!(&got[..6], b"prefix", "prefix touched: {what}");
    assert!(got[6..] == want[..], "encoded bytes differ: {what}");
}

#[test]
fn body_encoders_agree_on_every_short_length_and_density() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for len in 0..=700usize {
        for one_in in [0u64, 1, 2, 3, 7, 16, 64, 256] {
            let data = rng.bytes_with_critical(len, one_in);
            assert_body_matches(&data, &format!("len {len}, critical 1 in {one_in}"));
        }
        assert_body_matches(&rng.bytes(len), &format!("len {len}, random"));
    }
}

#[test]
fn body_encoders_agree_with_a_critical_byte_at_every_column() {
    // One critical byte at each position of the first three lines, alone
    // and next to a second one, over clean filler: every way an escape can
    // meet a line end (`=` is never stranded in the last column).
    for len in [LINE_LENGTH * 3 + 5, 4096 + 300] {
        for at in 0..LINE_LENGTH * 3 {
            for critical in CRITICAL {
                let mut data = vec![b'a'; len];
                data[at] = critical;
                assert_body_matches(&data, &format!("len {len}, one at {at}"));
                data[at + 1] = critical;
                assert_body_matches(&data, &format!("len {len}, two at {at}"));
                data[(at + 17) % len] = critical;
                assert_body_matches(&data, &format!("len {len}, three near {at}"));
            }
        }
    }
}

#[test]
fn body_encoders_agree_on_large_and_block_edge_lengths() {
    let mut rng = XorShift(0x0123_4567_89ab_cdef);
    for len in [
        4095, 4096, 4097, 8191, 8192, 8193, 65_535, 65_536, 65_537, 700_000, 716_800, 1_048_576,
    ] {
        assert_body_matches(&rng.bytes(len), &format!("len {len}, random"));
        assert_body_matches(
            &rng.bytes_with_critical(len, 5),
            &format!("len {len}, dense"),
        );
    }
    assert_body_matches(&vec![214u8; 70_000], "all critical");
    assert_body_matches(&vec![0u8; 70_000], "all zero");
}

fn multipart(len: usize) -> SegmentParams {
    SegmentParams {
        name: "a1b2c3d4e5f6".into(),
        part: 3,
        total: 24,
        begin: 1_433_601,
        end: 1_433_600 + len as u64,
        file_size: 16_777_216 + 1024,
    }
}

#[test]
fn segment_encoders_agree_single_and_multipart() {
    let mut rng = XorShift(0xfeed_face_cafe_beef);
    for len in [1usize, 2, 127, 128, 129, 1000, 4096, 100_000, 716_800] {
        let data = rng.bytes(len);
        for params in [SegmentParams::single("file.bin"), multipart(len)] {
            let mut want = Vec::new();
            encode_segment(&mut want, &params, &data).unwrap();
            let mut got = Vec::new();
            encode_segment_vec(&mut got, &params, &data).unwrap();
            assert!(got == want, "segment differs at len {len}");

            let mut dst = vec![0u8; len];
            assert_eq!(decode_to("<m@x>", &got, &mut dst).unwrap(), len);
            assert!(dst == data, "round trip differs at len {len}");
        }
    }
}

#[test]
fn segment_encoders_refuse_the_same_parameters_and_append_nothing() {
    let data = [1u8; 10];
    let mut wrong_range = multipart(11);
    wrong_range.name = "x".into();
    let mut bad_name = SegmentParams::single("bad\r\nname");
    bad_name.total = 0;
    for params in [wrong_range, bad_name] {
        let want = encode_segment(&mut Vec::new(), &params, &data).unwrap_err();
        let mut got_out = b"keep".to_vec();
        let got = encode_segment_vec(&mut got_out, &params, &data).unwrap_err();
        assert_eq!(got.to_string(), want.to_string());
        assert_eq!(got_out, b"keep");
    }
}

#[test]
fn golden_wire_bytes() {
    // Digests of the wire bytes, taken from the reference encoder before
    // the vector form existed. Both forms must still produce them.
    let data = XorShift(0x1234_5678_9abc_def1).bytes(716_800);
    let cases = [
        (
            SegmentParams::single("golden.bin"),
            "4f5d88ea6c185bad7de4cbac04cb904587d41110ba551c144930eb2644cc8932",
        ),
        (
            multipart(data.len()),
            "2b39a1322f1c22891abab394be8a14f995c23d01b78fd695feda202a3d599278",
        ),
    ];
    for (params, want) in cases {
        let mut reference = Vec::new();
        encode_segment(&mut reference, &params, &data).unwrap();
        let mut fast = Vec::new();
        encode_segment_vec(&mut fast, &params, &data).unwrap();
        assert_eq!(sha256_hex(&reference), want, "reference encoder");
        assert_eq!(sha256_hex(&fast), want, "vector encoder");
    }
    assert_eq!(
        sha256_hex(&data),
        "d417294b5a96046deb610c3f246e9b8ba5b33737c3522ee7a5259b2fae1554de",
        "the input itself"
    );
}

#[test]
fn article_assembly_forms_agree() {
    let headers = b"From: a@b\r\nSubject: s\r\nMessage-ID: <m@x>\r\n";
    let mut rng = XorShift(7);
    let data = rng.bytes(5000);
    let params = SegmentParams::single("n");
    let mut body = Vec::new();
    encode_segment(&mut body, &params, &data).unwrap();
    let want = assemble_article(headers, &body).unwrap();
    let got =
        assemble_article_with(headers, 16, |out| encode_segment_vec(out, &params, &data)).unwrap();
    assert!(got == want);

    // The same framing refusals, with the same text.
    for bad in [&b"a\rb\r\n"[..], b"a\nb\r\n", b"line\r", b"\n", b"ok\r\n\r"] {
        let want = assemble_article(headers, bad).unwrap_err().to_string();
        let got = assemble_article_with(headers, 0, |out| {
            out.extend_from_slice(bad);
            Ok(())
        })
        .unwrap_err()
        .to_string();
        assert_eq!(got, want, "{bad:?}");
    }
    // A body writer's own error comes back untouched.
    let err = assemble_article_with(headers, 0, |_| Err(Error::Malformed("mine".into())))
        .unwrap_err()
        .to_string();
    assert!(err.contains("mine"), "{err}");
}

// ---------------------------------------------------------------------------
// Decoder against a byte-at-a-time model
// ---------------------------------------------------------------------------

/// One body line decoded one byte at a time (the decoder's scalar rules).
fn model_line(line: &[u8], room: usize, out: &mut Vec<u8>) -> Result<(), &'static str> {
    let start = out.len();
    let mut i = 0;
    while i < line.len() {
        let mut b = line[i];
        i += 1;
        if b == b'=' {
            if i >= line.len() {
                return Err("yenc escape at end of line");
            }
            b = line[i].wrapping_sub(64);
            i += 1;
        }
        if out.len() - start >= room {
            return Err("decoded article exceeds destination");
        }
        out.push(b.wrapping_sub(42));
    }
    Ok(())
}

/// Random body lines over an alphabet heavy in `=`, with no line breaks
/// inside a line and no line that could be read as a `=y` keyword line.
fn hostile_lines(rng: &mut XorShift) -> Vec<Vec<u8>> {
    let count = rng.next() % 6;
    (0..count)
        .map(|_| {
            let len = (rng.next() % 150) as usize;
            let mut line: Vec<u8> = (0..len)
                .map(|_| {
                    let roll = rng.next();
                    match roll % 9 {
                        0 | 1 => b'=',
                        2 => b'}', // `=}` decodes to `=`-like values
                        _ => {
                            let b = (roll >> 24) as u8;
                            if b == b'\n' || b == b'\r' {
                                b'x'
                            } else {
                                b
                            }
                        }
                    }
                })
                .collect();
            if line.starts_with(b"=y") {
                line[1] = b'z';
            }
            line
        })
        .collect()
}

#[test]
fn decoder_matches_the_byte_model_on_hostile_lines() {
    let mut rng = XorShift(0xdead_beef_0bad_f00d);
    let mut accepted = 0;
    let mut refused = 0;
    for round in 0..40_000 {
        let lines = hostile_lines(&mut rng);
        // Destination sizes around the decoded length, to cross the
        // "exceeds destination" edge both ways.
        let mut full = Vec::new();
        let mut full_ok = true;
        for line in &lines {
            if model_line(line, usize::MAX, &mut full).is_err() {
                full_ok = false;
                break;
            }
        }
        let dst_len = match rng.next() % 4 {
            0 => full.len(),
            1 => full.len().saturating_sub((rng.next() % 20) as usize),
            2 => full.len() + (rng.next() % 40) as usize,
            _ => (rng.next() % 300) as usize,
        };

        // The model, with the decoder's destination rule.
        let mut model = Vec::new();
        let mut model_result = Ok(());
        for line in &lines {
            let room = dst_len - model.len();
            if let Err(reason) = model_line(line, room, &mut model) {
                model_result = Err(reason);
                break;
            }
        }

        // An article with no size or CRC in the trailer, so only the line
        // decoding decides. `size=` in the header is the model's length
        // when it fits (a larger one is refused before any line is read).
        let declared = if full_ok {
            full.len()
        } else {
            dst_len.min(full.len())
        };
        let mut article = format!("=ybegin line=128 size={declared} name=t\r\n").into_bytes();
        for line in &lines {
            article.extend_from_slice(line);
            article.extend_from_slice(b"\r\n");
        }
        article.extend_from_slice(b"=yend\r\n");

        // The destination is a window of a larger buffer: a store past
        // either end of it shows in the guard bytes around it.
        const GUARD: usize = 32;
        let mut whole = vec![0x3Cu8; GUARD + dst_len + GUARD];
        whole[GUARD..GUARD + dst_len].fill(0xA5);
        let got = decode_part_to("<m@x>", &article, &mut whole[GUARD..GUARD + dst_len]);
        assert!(
            whole[..GUARD]
                .iter()
                .chain(&whole[GUARD + dst_len..])
                .all(|&b| b == 0x3C),
            "round {round}: the decoder wrote outside its destination"
        );
        let dst = &whole[GUARD..GUARD + dst_len];
        if declared > dst_len {
            assert!(got.is_err(), "round {round}: oversize must be refused");
            assert!(
                dst.iter().all(|&b| b == 0xA5),
                "round {round}: wrote on refusal"
            );
            refused += 1;
            continue;
        }
        match (model_result, got) {
            (Ok(()), Ok(part)) => {
                assert_eq!(part.written, model.len(), "round {round}");
                assert!(
                    dst[..part.written] == model[..],
                    "round {round}: bytes differ"
                );
                assert!(
                    dst[part.written..].iter().all(|&b| b == 0xA5),
                    "round {round}: wrote past the decoded bytes"
                );
                accepted += 1;
            }
            (Ok(()), Err(err)) => {
                // Only the length check after the lines may refuse here.
                assert_ne!(model.len(), declared, "round {round}: {err}");
                assert!(dst[..model.len()] == model[..], "round {round}");
                assert!(
                    dst[model.len()..].iter().all(|&b| b == 0xA5),
                    "round {round}: wrote past the decoded bytes"
                );
                refused += 1;
            }
            (Err(reason), Err(err)) => {
                assert!(
                    err.to_string().contains(reason),
                    "round {round}: {err} vs {reason}"
                );
                // Lines before the bad one are in place; nothing lands
                // past the end of what the bad line managed to decode.
                assert!(dst[..model.len()] == model[..], "round {round}");
                assert!(
                    dst[model.len()..].iter().all(|&b| b == 0xA5),
                    "round {round}: wrote past the decoded bytes"
                );
                refused += 1;
            }
            (Err(reason), Ok(_)) => panic!("round {round}: accepted, model says {reason}"),
        }
    }
    assert!(accepted > 2_000, "accepted {accepted}");
    assert!(refused > 2_000, "refused {refused}");
}

#[test]
fn decoder_checks_the_crc_over_all_lines() {
    let mut rng = XorShift(99);
    let data = rng.bytes_with_critical(10_000, 9);
    let mut article = Vec::new();
    encode_segment_vec(&mut article, &multipart(data.len()), &data).unwrap();
    let mut dst = vec![0u8; data.len()];
    let part = decode_part_to("<m@x>", &article, &mut dst).unwrap();
    assert_eq!(part.written, data.len());
    assert!(dst == data);

    // Flip one plain encoded byte in the middle of the body (not part of an
    // escape pair or a line end): the CRC must catch it.
    let at = (article.len() / 2..article.len())
        .find(|&at| {
            article[at - 1..=at + 1]
                .iter()
                .all(|b| !matches!(b, b'=' | b'\r' | b'\n'))
        })
        .unwrap();
    let flipped = if article[at] == b'a' { b'b' } else { b'a' };
    article[at] = flipped;
    let err = decode_part_to("<m@x>", &article, &mut dst).unwrap_err();
    assert!(matches!(err, Error::CrcMismatch { .. }), "{err}");
}
