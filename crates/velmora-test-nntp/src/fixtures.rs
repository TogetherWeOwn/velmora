//! Synthetic fixture corpus.
//!
//! All audio bytes are **synthesized sine tones generated at runtime**
//! (8-bit PCM WAV, 8 kHz, ≤ 0.25 s). No sampled, copyrighted, or
//! network-fetched audio is embedded: the corpus is CC0 by construction
//! and safe to run in CI. "Encrypted rar/7z-style payloads" are marker
//! bytes (`Rar!`, `7z\xbc\xaf`) + deterministic pseudorandom filler so the
//! decrypt/par2 paths have something to parse — not real archives.

use std::collections::HashMap;

/// A single servable article.
#[derive(Clone, Debug)]
pub struct Article {
    pub message_id: String,
    pub number: u32,
    pub group: String,
    pub subject: String,
    pub from: String,
    pub date: String,
    /// Full article text (headers + blank line + body), CRLF, no dot-stuffing.
    pub raw: Vec<u8>,
    /// Raw payload bytes before yEnc (for test assertions).
    pub payload: Vec<u8>,
}

/// Generate a tiny 8-bit PCM WAV sine tone. Deterministic, CC0.
pub fn generate_wav_bytes(freq_hz: f32, duration_ms: u32, sample_rate: u32) -> Vec<u8> {
    let n = (sample_rate * duration_ms / 1000) as usize;
    let mut data = Vec::with_capacity(n);
    for i in 0..n {
        let t = i as f32 / sample_rate as f32;
        let s = (0.5 * (1.0 + (2.0 * std::f32::consts::PI * freq_hz * t).sin()) * 255.0) as u8;
        data.push(s);
    }
    let mut wav = Vec::with_capacity(44 + n);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + n as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&1u16.to_le_bytes()); // mono
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&(sample_rate).to_le_bytes()); // byte rate (8-bit mono)
    wav.extend_from_slice(&1u16.to_le_bytes()); // block align
    wav.extend_from_slice(&8u16.to_le_bytes()); // bits per sample
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&(n as u32).to_le_bytes());
    wav.extend_from_slice(&data);
    wav
}

/// Deterministic pseudorandom filler (xorshift32) — no `rand` dependency.
pub fn pseudo_random(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.max(1);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out.push((x & 0xFF) as u8);
    }
    out
}

/// Single-part article with spec-conformant framing (`size` + `crc32`).
fn article_single(
    number: u32,
    group: &str,
    subject: &str,
    message_id: &str,
    payload: Vec<u8>,
    yenc_file: &str,
) -> Article {
    let total = payload.len() as u64;
    let crc = crate::yenc::crc32(&payload);
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(
        format!("=ybegin line=128 size={total} name={yenc_file}\r\n").as_bytes(),
    );
    body.extend_from_slice(&crate::yenc::encode(&payload, 128));
    body.extend_from_slice(format!("\r\n=yend size={total} crc32={crc:08x}\r\n").as_bytes());
    finish_article(number, group, subject, message_id, payload, body)
}

/// Multi-part article: `=ybegin size=` is the whole file size, `=ypart`
/// carries this part's 1-based byte offset range, and `=yend` carries the
/// part length plus `pcrc32`. All parts of one file share `yenc_file` so
/// name-based grouping sees a single file.
#[allow(clippy::too_many_arguments)]
fn article_part(
    number: u32,
    group: &str,
    subject: &str,
    message_id: &str,
    part_payload: Vec<u8>,
    yenc_file: &str,
    n: u32,
    total_parts: u32,
    full_size: u64,
    offset: u64,
) -> Article {
    let part_len = part_payload.len() as u64;
    let begin = offset + 1;
    let end = offset + part_len;
    let pcrc = crate::yenc::crc32(&part_payload);
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(
        format!(
            "=ybegin part={n} total={total_parts} line=128 size={full_size} name={yenc_file}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("=ypart begin={begin} end={end}\r\n").as_bytes());
    body.extend_from_slice(&crate::yenc::encode(&part_payload, 128));
    body.extend_from_slice(
        format!("\r\n=yend size={part_len} part={n} pcrc32={pcrc:08x}\r\n").as_bytes(),
    );
    finish_article(number, group, subject, message_id, part_payload, body)
}

fn finish_article(
    number: u32,
    group: &str,
    subject: &str,
    message_id: &str,
    payload: Vec<u8>,
    body: Vec<u8>,
) -> Article {
    let mut raw = format!(
        "From: fixture@nntune.test\r\nNewsgroups: {group}\r\nSubject: {subject}\r\nDate: Mon, 13 Oct 2026 00:00:00 +0000\r\nMessage-ID: {message_id}\r\nLines: 8\r\n\r\n"
    )
    .into_bytes();
    raw.extend_from_slice(&body);
    Article {
        message_id: message_id.to_string(),
        number,
        group: group.to_string(),
        subject: subject.to_string(),
        from: "fixture@nntune.test".to_string(),
        date: "Mon, 13 Oct 2026 00:00:00 +0000".to_string(),
        raw,
        payload,
    }
}

/// Build the default corpus. Group: `alt.binaries.nntune.test`.
pub fn default_corpus() -> Vec<Article> {
    let group = "alt.binaries.nntune.test";
    let mut articles = Vec::new();
    let mut number = 1u32;

    // 1. Single-part yEnc WAV (440 Hz, 120 ms).
    let wav = generate_wav_bytes(440.0, 120, 8000);
    articles.push(article_single(
        number,
        group,
        "NNTune-Fixture sine-440 [01/01] - \"sine-440.wav\" yEnc (1/1)",
        "<single-yenc-001@nntune.test>",
        wav,
        "sine-440.wav",
    ));
    number += 1;

    // 2. Multi-part (3 parts) 660 Hz tone, split into thirds. All parts share
    // one yEnc file name; offsets are 1-based byte ranges into the full file.
    let wav3 = generate_wav_bytes(660.0, 210, 8000);
    let full3 = wav3.len() as u64;
    let chunk = wav3.len().div_ceil(3);
    let mut offset3 = 0u64;
    for (i, part) in wav3.chunks(chunk).enumerate() {
        let n = (i + 1) as u32;
        articles.push(article_part(
            number,
            group,
            &format!("NNTune-Fixture sine-660 [0{n}/03] - \"sine-660.wav\" yEnc ({n}/3)"),
            &format!("<multi-660-part{n}-of-3@nntune.test>"),
            part.to_vec(),
            "sine-660.wav",
            n,
            3,
            full3,
            offset3,
        ));
        offset3 += part.len() as u64;
        number += 1;
    }

    // 3. Obfuscated subjects (same 550 Hz payload, 3 parts). Subjects stay
    // opaque per part, but the yEnc file name is shared so name-based
    // grouping sees one 3-part file.
    let wav_obf = generate_wav_bytes(550.0, 180, 8000);
    let full_obf = wav_obf.len() as u64;
    let chunk = wav_obf.len().div_ceil(3);
    let opaque = ["a8f3k2m9zq71", "q7w2e9r4t6y1", "z1x2c3v4b5n6"];
    let shared_name = format!("{}.dat", opaque[0]);
    let mut offset_obf = 0u64;
    for (i, part) in wav_obf.chunks(chunk).enumerate() {
        let n = (i + 1) as u32;
        articles.push(article_part(
            number,
            group,
            &format!("{} [0{n}/03] - \"{shared_name}\" yEnc", opaque[i]),
            &format!("<obf-550-part{n}-of-3@nntune.test>"),
            part.to_vec(),
            &shared_name,
            n,
            3,
            full_obf,
            offset_obf,
        ));
        offset_obf += part.len() as u64;
        number += 1;
    }

    // 4. Rar-style payload: "Rar!" marker + filler (simulated encrypted header).
    let mut rar_payload = b"Rar!\x1a\x07\x01\x00".to_vec();
    rar_payload.extend(pseudo_random(0xC0FFEE, 512));
    articles.push(article_single(
        number,
        group,
        "NNTune-Fixture enc-rar [01/01] - \"enc-audio.rar\" yEnc (1/1)",
        "<enc-rar-001@nntune.test>",
        rar_payload,
        "enc-audio.rar",
    ));
    number += 1;

    // 5. 7z-style payload: "7z" marker + filler.
    let mut seven_payload = b"7z\xbc\xaf\x27\x1c".to_vec();
    seven_payload.extend(pseudo_random(0x7E57, 512));
    articles.push(article_single(
        number,
        group,
        "NNTune-Fixture enc-7z [01/01] - \"enc-audio.7z\" yEnc (1/1)",
        "<enc-7z-001@nntune.test>",
        seven_payload,
        "enc-audio.7z",
    ));
    number += 1;

    // 6. Plain-text article (non-yEnc control).
    let text_raw = "From: fixture@nntune.test\r\nNewsgroups: alt.binaries.nntune.test\r\nSubject: NNTune-Fixture hello [01/01]\r\nDate: Mon, 13 Oct 2026 00:00:00 +0000\r\nMessage-ID: <plain-hello-001@nntune.test>\r\nLines: 2\r\n\r\nhello nntune\r\n".to_string();
    articles.push(Article {
        message_id: "<plain-hello-001@nntune.test>".to_string(),
        number,
        group: group.to_string(),
        subject: "NNTune-Fixture hello [01/01]".to_string(),
        from: "fixture@nntune.test".to_string(),
        date: "Mon, 13 Oct 2026 00:00:00 +0000".to_string(),
        raw: text_raw.clone().into_bytes(),
        payload: b"hello nntune\r\n".to_vec(),
    });

    articles
}

/// Render a minimal NZB 1.1 document for the given articles.
pub fn nzb_for(articles: &[&Article], group: &str) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/nzb/nzb-1.1\">\n");
    for a in articles {
        out.push_str(&format!(
            "  <file poster=\"fixture@nntune.test\" date=\"1760313600\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n      <segment bytes=\"{}\" number=\"1\">&lt;{}&gt;</segment>\n    </segments>\n  </file>\n",
            xml_escape(&a.subject),
            group,
            a.payload.len(),
            a.message_id.trim_matches(|c| c == '<' || c == '>'),
        ));
    }
    out.push_str("</nzb>\n");
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Message-IDs the server must answer `430` for even if present (fault injection).
pub fn always_missing_ids() -> Vec<String> {
    vec!["<missing-430@nntune.test>".to_string()]
}

/// Lookup helpers shared by server and tests.
pub fn index_by_id(articles: &[Article]) -> HashMap<String, Article> {
    articles
        .iter()
        .map(|a| (a.message_id.clone(), a.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yenc;

    #[test]
    fn corpus_covers_required_shapes() {
        let c = default_corpus();
        let ids: Vec<_> = c.iter().map(|a| a.message_id.as_str()).collect();
        assert!(ids.contains(&"<single-yenc-001@nntune.test>"));
        assert!(ids.contains(&"<multi-660-part1-of-3@nntune.test>"));
        assert!(ids.contains(&"<obf-550-part1-of-3@nntune.test>"));
        assert!(ids.contains(&"<enc-rar-001@nntune.test>"));
        assert!(ids.contains(&"<enc-7z-001@nntune.test>"));
        // yEnc round-trips through the served body (after the header blank line).
        let single = c
            .iter()
            .find(|a| a.message_id == "<single-yenc-001@nntune.test>")
            .unwrap();
        let sep = single
            .raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header sep");
        let body = &single.raw[sep + 4..];
        assert_eq!(yenc::decode(body), single.payload);
    }

    #[test]
    fn wav_header_is_valid() {
        let wav = generate_wav_bytes(440.0, 100, 8000);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
    }
}
