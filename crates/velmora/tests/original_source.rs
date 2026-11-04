//! Generated source references and byte patterns only; no media fixtures.
use nntune_core::{
    nzb::{File, Segment},
    original_source::{reader::*, *},
    yenc,
};
use std::{collections::HashMap, io::Cursor};

const TRACK: &str = "00000000-0000-0000-0000-000000000001";
const OTHER: &str = "00000000-0000-0000-0000-000000000002";
const JOB: &str = "job_generated";

fn file(count: usize) -> File {
    File {
        ordinal: 2,
        subject: String::new(),
        filename: None,
        role: "content".into(),
        container: "flac".into(),
        posted_at_unix: 0,
        segments: (0..count)
            .map(|i| Segment {
                ordinal: i,
                number: i + 1,
                message_id: format!("generated-{i}@fixture.invalid"),
                encoded_bytes: 512,
            })
            .collect(),
    }
}
fn source(sizes: &[usize], hint: Option<RangeHint>) -> OriginalSource {
    OriginalSource::from_file(
        TRACK,
        JOB,
        &file(sizes.len()),
        sizes.iter().sum::<usize>() as u64,
        hint,
    )
    .unwrap()
}
fn parse(bytes: &[u8]) -> Result<OriginalSource, SourceError> {
    OriginalSource::parse(1, bytes, TRACK, JOB)
}
fn change(source: &OriginalSource, edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut v = serde_json::from_slice(&source.encode().unwrap()).unwrap();
    edit(&mut v);
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn round_trip_is_per_track_job_file_and_index() {
    let s = source(&[3, 3, 1], None);
    let bytes = s.encode().unwrap();
    let read = parse(&bytes).unwrap();
    assert!(read.track_id() == TRACK && read.file_ordinal() == 2 && read.article_count() == 3);
    assert_eq!(read.article(2).unwrap().number(), 3);
    assert!(read.article(3).is_err());
    assert!(OriginalSource::parse(1, &bytes, OTHER, JOB).is_err());
    assert!(OriginalSource::parse(1, &bytes, TRACK, "job_other").is_err());
    for fmt in [i16::MIN, 0, 2, i16::MAX] {
        assert!(OriginalSource::parse(fmt, &bytes, TRACK, JOB).is_err());
    }
}

#[test]
fn strict_shape_rejects_order_count_size_and_identity_disagreements() {
    let s = source(&[3, 3, 1], None);
    for bytes in [
        change(&s, |v| v["article_count"] = 1000000000u64.into()),
        change(&s, |v| v["file_ordinal"] = 1024.into()),
        change(&s, |v| v["file_size"] = 0.into()),
        change(&s, |v| v["file_size"] = (MAX_FILE_BYTES + 1).into()),
        change(&s, |v| v["file_size"] = (-1).into()),
        change(&s, |v| v["file_size"] = 1.5.into()),
        change(&s, |v| v["articles"][0]["number"] = 2.into()),
        change(&s, |v| v["articles"][0]["encoded_bytes"] = 0.into()),
        change(&s, |v| v["articles"][0]["encoded_bytes"] = u64::MAX.into()),
        change(&s, |v| v["articles"][1] = v["articles"][0].clone()),
        change(&s, |v| {
            v["articles"][0]["reference"] = "<generated@fixture.invalid>".into()
        }),
        change(&s, |v| {
            v["articles"][0]["reference"] = "bad\nreference".into()
        }),
        change(&s, |v| v["unexpected"] = 1.into()),
        change(&s, |v| v["articles"][0]["unexpected"] = 1.into()),
    ] {
        assert!(parse(&bytes).is_err());
    }
    let bytes = s.encode().unwrap();
    for i in 0..bytes.len() {
        assert!(parse(&bytes[..i]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b" {}");
    assert!(parse(&trailing).is_err());
    let mut duplicate = b"{\"track_id\":\"00000000-0000-0000-0000-000000000001\",".to_vec();
    duplicate.extend_from_slice(&bytes[1..]);
    assert!(parse(&duplicate).is_err());
    assert!(parse(b"{\"articles\":[[[[]]]]}").is_err());
    assert!(parse(&[0xff]).is_err());
}

#[test]
fn object_contract_accepts_valid_objects_and_optional_hints() {
    let hint = RangeHint {
        part_size: 3,
        final_begin: 6,
        final_end: 7,
    };
    for range_hint in [None, Some(hint)] {
        let s = source(&[3, 3, 1], range_hint);
        let read = parse(&s.encode().unwrap()).unwrap();
        assert_eq!(read.range_hint(), range_hint);
        assert_eq!(read.article_count(), 3);
        assert_eq!(
            read.article(2).unwrap().reference(),
            "generated-2@fixture.invalid"
        );
    }
    let without_hint = change(&source(&[1], None), |v| {
        v.as_object_mut().unwrap().remove("range_hint");
    });
    assert!(parse(&without_hint).unwrap().range_hint().is_none());
}

#[test]
fn object_contract_rejects_positional_root_arrays() {
    let s = source(&[1], None);
    let bytes = change(&s, |v| {
        *v = serde_json::json!([
            v["track_id"],
            v["source_job_id"],
            v["file_ordinal"],
            v["file_size"],
            v["article_count"],
            v["articles"],
            v["range_hint"]
        ]);
    });
    assert!(matches!(parse(&bytes), Err(SourceError::Shape)));
}

#[test]
fn object_contract_rejects_positional_article_arrays() {
    let s = source(&[3, 3, 1], None);
    for index in 0..3 {
        let bytes = change(&s, |v| {
            let a = &v["articles"][index];
            v["articles"][index] =
                serde_json::json!([a["number"], a["reference"], a["encoded_bytes"]]);
        });
        assert!(matches!(parse(&bytes), Err(SourceError::Shape)));
    }
}

#[test]
fn object_contract_rejects_positional_range_hint_arrays() {
    let s = source(&[3, 3, 1], None);
    let bytes = change(&s, |v| v["range_hint"] = serde_json::json!([3, 6, 7]));
    assert!(matches!(parse(&bytes), Err(SourceError::Shape)));
}

#[test]
fn object_contract_retains_nested_field_validation() {
    let s = source(
        &[3, 3, 1],
        Some(RangeHint {
            part_size: 3,
            final_begin: 6,
            final_end: 7,
        }),
    );
    let raw = String::from_utf8(s.encode().unwrap()).unwrap();
    for (field, value) in [
        ("number", 1),
        ("part_size", 3),
        ("final_begin", 6),
        ("final_end", 7),
    ] {
        let key = format!("\"{field}\":{value}");
        let duplicate = raw.replacen(&key, &format!("{key},{key}"), 1);
        assert_ne!(duplicate, raw);
        assert!(matches!(
            parse(duplicate.as_bytes()),
            Err(SourceError::Shape)
        ));
    }
    for bytes in [
        change(&s, |v| v["range_hint"]["unexpected"] = 1.into()),
        change(&s, |v| {
            v["range_hint"].as_object_mut().unwrap().remove("final_end");
        }),
        change(&s, |v| {
            v["articles"][0]
                .as_object_mut()
                .unwrap()
                .remove("encoded_bytes");
        }),
    ] {
        assert!(matches!(parse(&bytes), Err(SourceError::Shape)));
    }
}

#[test]
fn strings_and_collections_are_capped_before_growth() {
    let s = source(&[1], None);
    let max = "a".repeat(MAX_REFERENCE_BYTES);
    assert!(parse(&change(&s, |v| v["articles"][0]["reference"] = max.clone().into())).is_ok());
    assert!(parse(&change(&s, |v| v["articles"][0]["reference"] =
        format!("{max}a").into()))
    .is_err());
    let raw = String::from_utf8(s.encode().unwrap()).unwrap();
    let escaped = raw.replace(
        "generated-0@fixture.invalid",
        &"\\u0061".repeat(MAX_REFERENCE_BYTES),
    );
    assert!(parse(escaped.as_bytes()).is_ok());
    let escaped = raw.replace(
        "generated-0@fixture.invalid",
        &"\\u0061".repeat(MAX_REFERENCE_BYTES + 1),
    );
    assert!(parse(escaped.as_bytes()).is_err());
    assert!(parse(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
    let max = source(&vec![1; MAX_ARTICLES], None);
    assert!(parse(&max.encode().unwrap()).is_ok());
    let too_many = change(&max, |v| {
        let a = v["articles"][0].clone();
        v["articles"].as_array_mut().unwrap().push(a);
    });
    assert!(parse(&too_many).is_err());
    let mut large = file(33);
    for s in &mut large.segments {
        s.encoded_bytes = nntune_core::nzb::MAX_SEGMENT_BYTES;
    }
    assert!(OriginalSource::from_file(TRACK, JOB, &large, MAX_FILE_BYTES, None).is_err());
}

#[test]
fn producer_declared_article_sizes_fit_the_reader_cap() {
    for index in 0..3 {
        let mut f = file(3);
        f.segments[index].encoded_bytes = MAX_ARTICLE_BYTES as i64;
        assert!(OriginalSource::from_file(TRACK, JOB, &f, 3, None).is_ok());
        for bytes in [0, -1, MAX_ARTICLE_BYTES as i64 + 1, 17 * 1024 * 1024] {
            f.segments[index].encoded_bytes = bytes;
            assert!(OriginalSource::from_file(TRACK, JOB, &f, 3, None).is_err());
        }
    }
}

#[test]
fn parser_declared_article_sizes_fit_the_reader_cap() {
    let s = source(&[1, 1, 1], None);
    for index in 0..3 {
        let at_cap = change(&s, |v| {
            v["articles"][index]["encoded_bytes"] = MAX_ARTICLE_BYTES.into()
        });
        assert!(parse(&at_cap).is_ok());
        for bytes in [0, MAX_ARTICLE_BYTES + 1, 17 * 1024 * 1024] {
            let over_cap = change(&s, |v| v["articles"][index]["encoded_bytes"] = bytes.into());
            assert!(parse(&over_cap).is_err());
        }
    }
}

#[test]
fn producer_rechecks_parser_invariants_before_clone() {
    let mut f = file(1);
    f.ordinal = 1024;
    assert!(OriginalSource::from_file(TRACK, JOB, &f, 1, None).is_err());
    f.ordinal = 0;
    f.segments[0].ordinal = 1;
    assert!(OriginalSource::from_file(TRACK, JOB, &f, 1, None).is_err());
    f.segments[0].ordinal = 0;
    f.container = "rar".into();
    assert!(OriginalSource::from_file(TRACK, JOB, &f, 1, None).is_err());
}

struct Control {
    remaining: usize,
}
impl ReadControl for Control {
    fn check(&mut self) -> Result<(), SourceError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(SourceError::Cancelled)?;
        Ok(())
    }
}
struct Transport {
    bodies: HashMap<String, Vec<u8>>,
    opened: Vec<String>,
}
impl ArticleSource for Transport {
    type Body = Cursor<Vec<u8>>;
    fn open(&mut self, reference: &str) -> Result<Self::Body, SourceError> {
        self.opened.push(reference.into());
        Ok(Cursor::new(
            self.bodies
                .get(reference)
                .ok_or(SourceError::Transport)?
                .clone(),
        ))
    }
}
fn article(data: &[u8], index: usize, count: usize, offset: usize, size: usize) -> Vec<u8> {
    let mut out = if count == 1 {
        format!("=ybegin line=128 size={size} name=generated\r\n").into_bytes()
    } else {
        format!("=ybegin part={} total={count} line=128 size={size} name=generated\r\n=ypart begin={} end={}\r\n", index+1, offset+1, offset+data.len()).into_bytes()
    };
    let mut encoded = Vec::new();
    yenc::encode_body(&mut encoded, data).unwrap();
    out.extend(encoded);
    out.extend(
        format!(
            "\r\n=yend size={} {}={:08x}\r\n",
            data.len(),
            if count == 1 { "crc32" } else { "pcrc32" },
            crc32fast::hash(data)
        )
        .bytes(),
    );
    out
}
fn transport(sizes: &[usize]) -> Transport {
    let mut offset = 0;
    let size: usize = sizes.iter().sum();
    let mut bodies = HashMap::new();
    for (i, &n) in sizes.iter().enumerate() {
        let data: Vec<u8> = (offset..offset + n).map(|n| n as u8).collect();
        bodies.insert(
            format!("generated-{i}@fixture.invalid"),
            article(&data, i, sizes.len(), offset, size),
        );
        offset += n;
    }
    Transport {
        bodies,
        opened: Vec::new(),
    }
}
fn read(
    s: &OriginalSource,
    r: std::ops::Range<u64>,
    t: &mut Transport,
) -> Result<Vec<u8>, SourceError> {
    let mut out = Vec::new();
    read_range(s, r, t, &mut Control { remaining: 100000 }, |bytes| {
        out.extend_from_slice(bytes);
        Ok(())
    })?;
    Ok(out)
}

#[test]
fn ranges_use_actual_intervals_and_never_encoded_offsets() {
    for hint in [
        None,
        Some(RangeHint {
            part_size: 3,
            final_begin: 6,
            final_end: 8,
        }),
        Some(RangeHint {
            part_size: u64::MAX,
            final_begin: 0,
            final_end: 1,
        }),
    ] {
        let s = source(&[3, 3, 2], hint);
        let mut t = transport(&[3, 3, 2]);
        assert_eq!(read(&s, 2..7, &mut t).unwrap(), vec![2, 3, 4, 5, 6]);
        assert_eq!(t.opened.len(), 3);
    }
    // Actual nonuniform middle parts contradict a uniform hint, not each
    // other. Prefix fallback succeeds without refetching any article.
    let s = source(
        &[3, 2, 4, 2],
        Some(RangeHint {
            part_size: 3,
            final_begin: 9,
            final_end: 11,
        }),
    );
    let mut t = transport(&[3, 2, 4, 2]);
    assert_eq!(
        read(&s, 4..10, &mut t).unwrap(),
        (4..10).collect::<Vec<u8>>()
    );
    assert_eq!(t.opened.len(), 4);
}

#[test]
fn unsatisfiable_ranges_and_cancelled_reads_release_no_output() {
    let s = source(&[3], None);
    for r in [
        0..0,
        3..4,
        std::ops::Range { start: 2, end: 1 },
        0..u64::MAX,
    ] {
        let mut t = transport(&[3]);
        assert_eq!(read(&s, r, &mut t), Err(SourceError::Range));
        assert!(t.opened.is_empty());
    }
    let mut t = transport(&[3]);
    let mut output = false;
    assert_eq!(
        read_range(&s, 0..3, &mut t, &mut Control { remaining: 0 }, |_| {
            output = true;
            Ok(())
        }),
        Err(SourceError::Cancelled)
    );
    assert!(!output && t.opened.is_empty());
}

#[test]
fn single_part_does_not_fabricate_multipart_geometry() {
    let s = source(
        &[3],
        Some(RangeHint {
            part_size: 3,
            final_begin: 0,
            final_end: 3,
        }),
    );
    let mut t = transport(&[3]);
    assert_eq!(read(&s, 0..3, &mut t).unwrap(), vec![0, 1, 2]);
    assert_eq!(t.opened.len(), 1);
    t.bodies.insert(
        "generated-0@fixture.invalid".into(),
        article(&[0, 1, 2], 0, 2, 0, 3),
    );
    assert_eq!(read(&s, 0..3, &mut t), Err(SourceError::Integrity));
}

#[test]
fn actual_integrity_or_geometry_contradictions_never_become_hint_fallback() {
    let s = source(&[3, 3, 2], None);
    for bad in [
        article(&[6, 7], 2, 3, 5, 8), // final ends prematurely
        article(&[6, 7], 2, 3, 6, 9), // file-size disagreement
        b"=ybegin part=3 size=8 name=generated\r\n=ypart begin=7 end=8\r\n01".to_vec(), // truncated
    ] {
        let mut t = transport(&[3, 3, 2]);
        t.bodies.insert("generated-2@fixture.invalid".into(), bad);
        assert_eq!(read(&s, 0..8, &mut t), Err(SourceError::Integrity));
    }
    let mut t = transport(&[3, 3, 2]);
    t.bodies.insert(
        "generated-1@fixture.invalid".into(),
        article(&[3, 4, 5], 1, 3, 2, 8),
    );
    assert_eq!(read(&s, 3..6, &mut t), Err(SourceError::Integrity));
    let mut t = transport(&[3, 3, 2]);
    let body = t.bodies.get_mut("generated-2@fixture.invalid").unwrap();
    let i = body.windows(7).position(|w| w == b"pcrc32=").unwrap();
    body[i + 7] = b'z';
    assert_eq!(read(&s, 0..8, &mut t), Err(SourceError::Integrity));
}

#[test]
fn uniform_candidates_require_endpoint_corroboration_and_checked_indices() {
    let s = source(
        &[3, 3, 2],
        Some(RangeHint {
            part_size: 3,
            final_begin: 6,
            final_end: 8,
        }),
    );
    let first = yenc::DecodedPart {
        written: 3,
        file_size: 8,
        offset: 0,
        multipart: true,
        part_number: Some(1),
    };
    let last = yenc::DecodedPart {
        written: 2,
        file_size: 8,
        offset: 6,
        multipart: true,
        part_number: Some(3),
    };
    let ranges = corroborate_hint(&s, &first, &last).unwrap();
    assert_eq!(ranges.candidate(1), Ok(3..6));
    assert!(ranges.candidate(3).is_err() && ranges.candidate(usize::MAX).is_err());
    assert!(!ranges.corroborates(
        1,
        &yenc::DecodedPart {
            offset: 4,
            part_number: Some(2),
            ..first
        }
    ));
    assert!(corroborate_hint(&s, &first, &yenc::DecodedPart { written: 1, ..last }).is_none());
    let s = source(
        &[3],
        Some(RangeHint {
            part_size: 4,
            final_begin: 0,
            final_end: 3,
        }),
    );
    let single = yenc::DecodedPart {
        written: 3,
        file_size: 3,
        offset: 0,
        multipart: false,
        part_number: None,
    };
    assert!(corroborate_hint(&s, &single, &single).is_none());
}

#[test]
fn aggregate_decoded_budget_is_enforced_before_another_article_open() {
    let s = source(&[1, 1], None);
    let mut t = transport(&[1, 1]);
    // Both parts individually claim the entire file. The final fetch spends
    // the full decoded budget; the prefix must never be opened or decoded.
    for i in 0..2 {
        t.bodies.insert(
            format!("generated-{i}@fixture.invalid"),
            article(&[0, 1], i, 2, 0, 2),
        );
    }
    assert_eq!(read(&s, 0..2, &mut t), Err(SourceError::Integrity));
    assert_eq!(t.opened.len(), 1);
}

#[test]
fn collection_cap_is_enforced_during_reads() {
    let s = source(&[1], None);
    let mut t = transport(&[1]);
    t.bodies.insert(
        "generated-0@fixture.invalid".into(),
        vec![b'x'; MAX_ARTICLE_BYTES + 1],
    );
    assert_eq!(read(&s, 0..1, &mut t), Err(SourceError::Bounds));
}
