//! Document limits must stop the reader, not just check after XML events.

use std::io::{self, BufRead, Read};

use nntune_core::error::Error;
use nntune_core::nzb::{Limits, Parser};

const FILE_START: &str = "<file poster=\"p\" date=\"1\" subject=\"s\"><segments>";
const SEGMENT: &str = "<segment bytes=\"1\" number=\"1\">a@x</segment>";
const FILE_END: &str = "</segments></file>";

// Virtual prefix + repeated unit + suffix. Even a large single XML event
// needs only this fixed buffer; consume() measures advancement, not read-ahead.
struct Chunked<'a> {
    prefix: &'a [u8],
    unit: &'a [u8],
    repetitions: usize,
    suffix: &'a [u8],
    consumed: usize,
    chunk: usize,
    buffer: [u8; 31],
}

impl<'a> Chunked<'a> {
    fn new(
        prefix: &'a str,
        unit: &'a str,
        repetitions: usize,
        suffix: &'a str,
        chunk: usize,
    ) -> Self {
        Self {
            prefix: prefix.as_bytes(),
            unit: unit.as_bytes(),
            repetitions,
            suffix: suffix.as_bytes(),
            consumed: 0,
            chunk,
            buffer: [0; 31],
        }
    }

    fn len(&self) -> usize {
        self.prefix.len() + self.unit.len() * self.repetitions + self.suffix.len()
    }

    fn byte_at(&self, offset: usize) -> u8 {
        if offset < self.prefix.len() {
            self.prefix[offset]
        } else {
            let offset = offset - self.prefix.len();
            if offset < self.unit.len() * self.repetitions {
                self.unit[offset % self.unit.len()]
            } else {
                self.suffix[offset - self.unit.len() * self.repetitions]
            }
        }
    }
}

impl Read for Chunked<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let bytes = self.fill_buf()?;
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Chunked<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let n = (self.len() - self.consumed)
            .min(self.chunk)
            .min(self.buffer.len());
        for i in 0..n {
            self.buffer[i] = self.byte_at(self.consumed + i);
        }
        Ok(&self.buffer[..n])
    }

    fn consume(&mut self, n: usize) {
        assert!(
            n <= (self.len() - self.consumed)
                .min(self.chunk)
                .min(self.buffer.len())
        );
        self.consumed += n;
    }
}

fn assert_stops_in(prefix: &str, unit: &str, suffix: &str) {
    // Prove the surrounding document is valid without the oversized region.
    let mut control = Chunked::new(prefix, unit, 1, suffix, 7);
    Parser::new(Limits::default())
        .unwrap()
        .parse(&mut control)
        .unwrap();
    let limit = (prefix.len() + 16) as u64;
    for chunk in [1, 7, 31] {
        let mut input = Chunked::new(prefix, unit, 16 * 1024, suffix, chunk);
        let result = Parser::new(Limits {
            document_bytes: limit,
            ..Limits::default()
        })
        .unwrap()
        .parse(&mut input);
        assert!(
            matches!(&result, Err(Error::Bounds { bound: "document bytes", limit: actual }) if *actual == limit as i64),
            "expected document byte bound {limit}, consumed {}, got {result:?}",
            input.consumed
        );
        assert!(
            input.consumed as u64 <= limit + 1,
            "consumed {} bytes for limit {limit}; checking after the event is too late",
            input.consumed
        );
    }
}

#[test]
fn exact_limit_accepts_complete_document_including_trailing_whitespace() {
    let xml = format!("<nzb>{FILE_START}{SEGMENT}{FILE_END}</nzb>\r\n ");
    for chunk in [1, 7, 31] {
        let mut input = Chunked::new(&xml, "", 0, "", chunk);
        let document = Parser::new(Limits {
            document_bytes: xml.len() as u64,
            ..Limits::default()
        })
        .unwrap()
        .parse(&mut input)
        .unwrap();
        assert_eq!(document.files.len(), 1);
        assert_eq!(document.files[0].segments[0].message_id, "a@x");
        assert_eq!(input.consumed, xml.len());
    }
}

#[test]
fn one_trailing_byte_beyond_exact_limit_is_a_bounds_error() {
    let xml = format!("<nzb>{FILE_START}{SEGMENT}{FILE_END}</nzb>");
    let mut input = Chunked::new(&xml, " ", 1, "", 7);
    let result = Parser::new(Limits {
        document_bytes: xml.len() as u64,
        ..Limits::default()
    })
    .unwrap()
    .parse(&mut input);
    assert!(
        matches!(result, Err(Error::Bounds { bound: "document bytes", limit }) if limit == xml.len() as i64)
    );
    assert!(input.consumed <= xml.len() + 1);
}

#[test]
fn bounds_many_small_events_inside_head() {
    assert_stops_in(
        "<nzb><head>",
        "<meta/>",
        &format!("</head>{FILE_START}{SEGMENT}{FILE_END}</nzb>"),
    );
}

#[test]
fn bounds_single_large_metadata_text_event() {
    assert_stops_in(
        "<nzb><head><meta type=\"title\">",
        "x",
        &format!("</meta></head>{FILE_START}{SEGMENT}{FILE_END}</nzb>"),
    );
}

#[test]
fn bounds_password_metadata_skip_loop() {
    assert_stops_in(
        "<nzb><head><outer><meta type=\"password\">",
        "<part/>",
        &format!("</meta></outer></head>{FILE_START}{SEGMENT}{FILE_END}</nzb>"),
    );
}

#[test]
fn bounds_single_large_segment_text_event() {
    assert_stops_in(
        &format!("<nzb>{FILE_START}<segment bytes=\"1\" number=\"1\">"),
        "a",
        &format!("@x</segment>{FILE_END}</nzb>"),
    );
}

#[test]
fn bounds_single_large_segment_cdata_event() {
    assert_stops_in(
        &format!("<nzb>{FILE_START}<segment bytes=\"1\" number=\"1\"><![CDATA["),
        "a",
        &format!("@x]]></segment>{FILE_END}</nzb>"),
    );
}

#[test]
fn bounds_many_small_comments_inside_segments() {
    assert_stops_in(
        &format!("<nzb>{FILE_START}"),
        "<!--x-->",
        &format!("{SEGMENT}{FILE_END}</nzb>"),
    );
}

#[test]
fn bounds_single_large_attribute_event() {
    assert_stops_in(
        "<nzb><head><meta type=\"",
        "a",
        &format!("\"/></head>{FILE_START}{SEGMENT}{FILE_END}</nzb>"),
    );
}

#[test]
fn bounds_trailing_comments_after_complete_document() {
    assert_stops_in(
        &format!("<nzb>{FILE_START}{SEGMENT}{FILE_END}</nzb>"),
        "<!--x-->",
        "",
    );
}

#[test]
fn bounds_single_large_trailing_whitespace_event() {
    assert_stops_in(
        &format!("<nzb>{FILE_START}{SEGMENT}{FILE_END}</nzb>"),
        " ",
        "",
    );
}
