//! Streaming NZB parser, ported from the v1 Go worker (`worker/internal/ingest/nzb`).
//!
//! Event-based (`quick-xml`) with bounded buffering: the input is never
//! materialised as a DOM, text accumulation is capped, and every resource
//! dimension (files, segments per file, declared bytes, document bytes, XML
//! prolog, metadata nesting) has a hard bound from [`Limits`].
//!
//! Two deliberate differences from v1:
//!
//! - No canonical-XML re-serialisation: that exists in v1 to give the ingest
//!   pipeline a stable document hash for storage dedup. The content-addressing
//!   primitive the data plane needs — the SHA-256 [`Document::segment_digest`]
//!   over sorted Message-IDs — is preserved exactly (same length-prefix
//!   scheme), and canonicalisation belongs to the ingest worker, not the
//!   shared core.
//! - Timestamps are Unix seconds (`i64`), not calendar types: no `time`/`chrono`
//!   dependency on wasm.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, BufRead, Read};

use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesRef, Event};
use quick_xml::Reader;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Compiled-in absolute bounds. [`Limits`] values must be positive and within
/// these.
pub const MAX_FILES: usize = 1024;
/// Maximum segments accepted in one file.
pub const MAX_SEGMENTS_PER_FILE: usize = 4096;
/// Maximum total declared `bytes=` across the document.
pub const MAX_ENCODED_BYTES: i64 = 64 << 30;
/// Maximum accepted input document size.
pub const MAX_DOCUMENT_BYTES: u64 = 32 << 20;
/// Maximum bytes before the root element (XML prolog).
pub const MAX_PROLOG_BYTES: u64 = 4096;
/// Maximum declared `bytes=` of a single segment.
pub const MAX_SEGMENT_BYTES: i64 = (1 << 31) - 1;
/// Maximum accumulated character data inside one `<segment>`.
pub const MAX_SEGMENT_TEXT_BYTES: usize = 1 << 20;
/// Maximum nesting depth of metadata elements (bounds quadratic expansion).
pub const MAX_METADATA_DEPTH: usize = 64;

/// Parser resource limits. Start from [`Limits::default`] (the compiled-in
/// maxima) and tighten per call-site.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum `<file>` elements.
    pub files: usize,
    /// Maximum `<segment>` elements per file.
    pub segments_per_file: usize,
    /// Maximum total declared segment bytes.
    pub encoded_bytes: i64,
    /// Maximum input document bytes.
    pub document_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            files: MAX_FILES,
            segments_per_file: MAX_SEGMENTS_PER_FILE,
            encoded_bytes: MAX_ENCODED_BYTES,
            document_bytes: MAX_DOCUMENT_BYTES,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<()> {
        if self.files == 0
            || self.files > MAX_FILES
            || self.segments_per_file == 0
            || self.segments_per_file > MAX_SEGMENTS_PER_FILE
            || self.encoded_bytes < 1
            || self.encoded_bytes > MAX_ENCODED_BYTES
            || self.document_bytes == 0
            || self.document_bytes > MAX_DOCUMENT_BYTES
        {
            return Err(Error::Malformed(
                "parser limits must be positive and cannot exceed the compiled-in bounds".into(),
            ));
        }
        Ok(())
    }
}

/// One `<segment>`: a single article reference.
#[derive(Debug, Clone)]
pub struct Segment {
    /// 0-based index within the file.
    pub ordinal: usize,
    /// 1-based `number=` attribute (must be contiguous from 1).
    pub number: usize,
    /// Normalised bare Message-ID (no brackets, no whitespace).
    pub message_id: String,
    /// Declared `bytes=` (encoded size on the wire).
    pub encoded_bytes: i64,
}

/// One `<file>` in the NZB document.
#[derive(Debug, Clone)]
pub struct File {
    /// 0-based index within the document.
    pub ordinal: usize,
    /// Raw `subject=` attribute.
    pub subject: String,
    /// Filename guessed from the first/last quoted span of the subject.
    pub filename: Option<String>,
    /// Coarse role (`par2`, `nfo`, `archive`, `content`, `unknown`, …).
    pub role: String,
    /// Container hint (`flac`, `mp3`, `rar`, `par2`, `other`, …).
    pub container: String,
    /// `date=` attribute as Unix seconds.
    pub posted_at_unix: i64,
    /// Ordered segments.
    pub segments: Vec<Segment>,
}

/// A parsed NZB document.
#[derive(Debug, Clone)]
pub struct Document {
    /// Files in document order.
    pub files: Vec<File>,
    /// SHA-256 over sorted Message-IDs (length-prefixed scheme, identical to
    /// v1's `DigestMessageIDs`): the content identity of the segment set.
    pub segment_digest: [u8; 32],
    /// Earliest file `date=` as Unix seconds.
    pub posted_at_unix: i64,
    /// Whether `<meta type="password">` was present in `<head>`.
    pub has_password: bool,
    /// Total declared segment bytes.
    pub encoded_bytes: i64,
}

/// Parses an NZB document with default [`Limits`].
pub fn parse(xml: &[u8]) -> Result<Document> {
    Parser::with_default_limits()?.parse(xml)
}

// Enforce the limit at the BufRead boundary: quick-xml may accumulate a
// complete event before returning control to any of the parser's loops.
struct BoundedReader<R> {
    inner: R,
    remaining: u64,
    exceeded: bool,
}

impl<R: BufRead> BufRead for BoundedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let bytes = self.inner.fill_buf()?;
        if self.remaining == 0 && !bytes.is_empty() {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NZB document byte limit exceeded",
            ));
        }
        let len = (bytes.len() as u64).min(self.remaining) as usize;
        Ok(&bytes[..len])
    }

    fn consume(&mut self, amount: usize) {
        self.remaining -= amount as u64;
        self.inner.consume(amount);
    }
}

impl<R: BufRead> Read for BoundedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let bytes = self.fill_buf()?;
        let len = out.len().min(bytes.len());
        out[..len].copy_from_slice(&bytes[..len]);
        self.consume(len);
        Ok(len)
    }
}

/// Streaming parser over any buffered byte source.
pub struct Parser {
    limits: Limits,
}

impl Parser {
    /// Builds a parser with default limits.
    pub fn with_default_limits() -> Result<Self> {
        Ok(Parser {
            limits: Limits::default(),
        })
    }

    /// Builds a parser with explicit limits (validated against the maxima).
    pub fn new(limits: Limits) -> Result<Self> {
        limits.validate()?;
        Ok(Parser { limits })
    }

    /// Parses one NZB document. A bounded byte source covers every XML event
    /// (including large comments/attributes and trailing input), not just
    /// transitions between events. The reusable event buffer is at most
    /// `document_bytes`; the caller's own BufRead buffering is separate.
    pub fn parse<R: BufRead>(&self, reader: R) -> Result<Document> {
        let mut bounded = BoundedReader {
            inner: reader,
            remaining: self.limits.document_bytes,
            exceeded: false,
        };
        let result = self.parse_bounded(&mut bounded);
        if bounded.exceeded {
            Err(Error::Bounds {
                bound: "document bytes",
                limit: self.limits.document_bytes as i64,
            })
        } else {
            result
        }
    }

    fn parse_bounded<R: BufRead>(&self, reader: R) -> Result<Document> {
        let mut reader = Reader::from_reader(reader);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::with_capacity(8192);
        // The root must appear within the prolog bound; quick-xml reports the
        // stream position so a gigabyte of comments/PIs before <nzb> fails.
        let root_name = loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    if reader.buffer_position() > MAX_PROLOG_BYTES {
                        return Err(Error::Bounds {
                            bound: "XML prolog bytes",
                            limit: MAX_PROLOG_BYTES as i64,
                        });
                    }
                    break local_name(&e.name());
                }
                Ok(Event::Decl(_)) | Ok(Event::Comment(_)) => {
                    buf.clear();
                    continue;
                }
                Ok(Event::DocType(_)) | Ok(Event::PI(_)) => {
                    return Err(Error::Malformed(
                        "NZB XML directives are not allowed".into(),
                    ));
                }
                Ok(Event::Text(_)) | Ok(Event::CData(_)) | Ok(Event::GeneralRef(_)) => {
                    buf.clear();
                    continue;
                }
                Ok(Event::End(_)) => {
                    return Err(Error::Malformed(
                        "unexpected end element before NZB root".into(),
                    ));
                }
                Ok(Event::Eof) => {
                    return Err(Error::Malformed("parse NZB XML: unexpected EOF".into()))
                }
                Err(e) => return Err(Error::Malformed(format!("parse NZB XML: {e}"))),
            }
        };
        if root_name != "nzb" {
            return Err(Error::Malformed(format!(
                "expected NZB root element, got {root_name:?}"
            )));
        }

        let mut doc = Document {
            files: Vec::new(),
            segment_digest: [0u8; 32],
            posted_at_unix: 0,
            has_password: false,
            encoded_bytes: 0,
        };
        let mut message_ids: Vec<String> = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = local_name(&e.name());
                    let attrs = collect_attrs(&e)?;
                    match name.as_str() {
                        "head" => {
                            if parse_head(&mut reader, &mut buf, 1)? {
                                doc.has_password = true;
                            }
                        }
                        "file" => {
                            if doc.files.len() >= self.limits.files {
                                return Err(Error::Bounds {
                                    bound: "file count",
                                    limit: self.limits.files as i64,
                                });
                            }
                            let ordinal = doc.files.len();
                            let (file, ids) = self.parse_file(
                                &mut reader,
                                &mut buf,
                                attrs,
                                ordinal,
                                &mut doc.encoded_bytes,
                            )?;
                            if doc.files.is_empty() || file.posted_at_unix < doc.posted_at_unix {
                                doc.posted_at_unix = file.posted_at_unix;
                            }
                            doc.files.push(file);
                            message_ids.extend(ids);
                        }
                        _ => {
                            if copy_metadata(&mut reader, &mut buf, &name, attrs, 1)? {
                                doc.has_password = true;
                            }
                        }
                    }
                }
                Ok(Event::Empty(e)) => {
                    let name = local_name(&e.name());
                    if name == "file" {
                        return Err(Error::Malformed(format!(
                            "file {} has no segments",
                            doc.files.len()
                        )));
                    }
                    let attrs = collect_attrs(&e)?;
                    if name == "head" {
                        continue;
                    }
                    if is_password_meta(&name, &attrs) {
                        doc.has_password = true;
                    }
                }
                Ok(Event::End(e)) => {
                    if local_name(&e.name()) != "nzb" {
                        return Err(Error::Malformed(format!(
                            "unexpected root child end element {:?}",
                            e.name().as_ref().to_string()
                        )));
                    }
                    break;
                }
                Ok(Event::DocType(_)) | Ok(Event::PI(_)) => {
                    return Err(Error::Malformed(
                        "NZB XML directives are not allowed".into(),
                    ));
                }
                Ok(Event::Eof) => {
                    return Err(Error::Malformed("parse NZB XML: unexpected EOF".into()))
                }
                Err(e) => return Err(Error::Malformed(format!("parse NZB XML: {e}"))),
                _ => {}
            }
            buf.clear();
        }

        // Trailing garbage after the root element is rejected.
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Text(e)) => {
                    if !e.xml10_content().trim().is_empty() {
                        return Err(Error::Malformed(
                            "NZB contains data after its root element".into(),
                        ));
                    }
                }
                Ok(Event::Comment(_)) | Ok(Event::Decl(_)) => {}
                Ok(_) => {
                    return Err(Error::Malformed(
                        "NZB contains data after its root element".into(),
                    ))
                }
                Err(e) => return Err(Error::Malformed(format!("parse trailing NZB XML: {e}"))),
            }
            buf.clear();
        }

        if doc.files.is_empty() {
            return Err(Error::Malformed(
                "NZB must contain at least one file".into(),
            ));
        }
        doc.segment_digest = digest_message_ids(&message_ids)?;
        Ok(doc)
    }

    fn parse_file<R: BufRead>(
        &self,
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
        attrs: HashMap<String, String>,
        ordinal: usize,
        total_encoded: &mut i64,
    ) -> Result<(File, Vec<String>)> {
        let date: i64 = attrs
            .get("date")
            .and_then(|d| d.parse().ok())
            .filter(|&d| d >= 0)
            .ok_or_else(|| Error::Malformed(format!("file {ordinal} has invalid date")))?;
        let subject = attrs.get("subject").cloned().unwrap_or_default();
        if subject.trim().is_empty() {
            return Err(Error::Malformed(format!("file {ordinal} has no subject")));
        }
        let mut file = File {
            ordinal,
            role: classify_role(&subject),
            container: classify_container(&subject),
            filename: filename_from_subject(&subject),
            subject,
            posted_at_unix: date,
            segments: Vec::new(),
        };
        let mut message_ids = Vec::new();

        loop {
            match reader.read_event_into(buf) {
                Ok(Event::Start(e)) => {
                    let name = local_name(&e.name());
                    let child_attrs = collect_attrs(&e)?;
                    if name == "segments" {
                        continue;
                    }
                    if name != "segment" {
                        if copy_metadata(reader, buf, &name, child_attrs, 1)? {
                            return Err(Error::Malformed(format!(
                                "file {ordinal} carries password metadata outside the NZB head"
                            )));
                        }
                        buf.clear();
                        continue;
                    }
                    if file.segments.len() >= self.limits.segments_per_file {
                        return Err(Error::Bounds {
                            bound: "segments in file",
                            limit: self.limits.segments_per_file as i64,
                        });
                    }
                    let segment =
                        parse_segment(reader, buf, child_attrs, file.segments.len(), ordinal)?;
                    if segment.encoded_bytes > self.limits.encoded_bytes - *total_encoded {
                        return Err(Error::Bounds {
                            bound: "declared encoded bytes",
                            limit: self.limits.encoded_bytes,
                        });
                    }
                    *total_encoded += segment.encoded_bytes;
                    message_ids.push(segment.message_id.clone());
                    file.segments.push(segment);
                }
                Ok(Event::Empty(e)) => {
                    let name = local_name(&e.name());
                    if name == "segment" {
                        return Err(Error::Malformed(format!(
                            "file {ordinal}: empty segment element"
                        )));
                    }
                    if name != "segments" {
                        let child_attrs = collect_attrs(&e)?;
                        if is_password_meta(&name, &child_attrs) {
                            return Err(Error::Malformed(format!(
                                "file {ordinal} carries password metadata outside the NZB head"
                            )));
                        }
                    }
                }
                Ok(Event::End(e)) => {
                    let name = local_name(&e.name());
                    if name == "segments" {
                        buf.clear();
                        continue;
                    }
                    if name != "file" {
                        return Err(Error::Malformed(format!(
                            "unexpected end element {name:?} in file {ordinal}"
                        )));
                    }
                    break;
                }
                Ok(Event::DocType(_)) | Ok(Event::PI(_)) => {
                    return Err(Error::Malformed(
                        "NZB XML directives are not allowed".into(),
                    ));
                }
                Ok(Event::Eof) => {
                    return Err(Error::Malformed(format!(
                        "parse file {ordinal}: unexpected EOF"
                    )))
                }
                Err(e) => return Err(Error::Malformed(format!("parse file {ordinal}: {e}"))),
                _ => {}
            }
            buf.clear();
        }
        if file.segments.is_empty() {
            return Err(Error::Malformed(format!("file {ordinal} has no segments")));
        }
        Ok((file, message_ids))
    }
}

/// Parses `<head>`: returns true when password metadata was seen (and skips it).
fn parse_head<R: BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    _depth: usize,
) -> Result<bool> {
    let mut has_password = false;
    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Start(e)) => {
                let name = local_name(&e.name());
                let attrs = collect_attrs(&e)?;
                if copy_metadata(reader, buf, &name, attrs, 1)? {
                    has_password = true;
                }
            }
            Ok(Event::Empty(e)) => {
                let name = local_name(&e.name());
                let attrs = collect_attrs(&e)?;
                if is_password_meta(&name, &attrs) {
                    has_password = true;
                }
            }
            Ok(Event::End(e)) => {
                if local_name(&e.name()) != "head" {
                    return Err(Error::Malformed(
                        "unexpected end element in NZB head".into(),
                    ));
                }
                break;
            }
            Ok(Event::DocType(_)) | Ok(Event::PI(_)) => {
                return Err(Error::Malformed(
                    "NZB XML directives are not allowed".into(),
                ));
            }
            Ok(Event::Eof) => {
                return Err(Error::Malformed("parse NZB head: unexpected EOF".into()))
            }
            Err(e) => return Err(Error::Malformed(format!("parse NZB head: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    Ok(has_password)
}

/// Skips one metadata element (already opened), returning true when it — or
/// any nested element — is password metadata. Depth-bounded like v1.
fn copy_metadata<R: BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    name: &str,
    attrs: HashMap<String, String>,
    depth: usize,
) -> Result<bool> {
    if depth > MAX_METADATA_DEPTH {
        return Err(Error::Bounds {
            bound: "metadata nesting depth",
            limit: MAX_METADATA_DEPTH as i64,
        });
    }
    let mut has_password = is_password_meta(name, &attrs);
    let mut inner_depth = 1usize;
    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Start(e)) => {
                let child = local_name(&e.name());
                let child_attrs = collect_attrs(&e)?;
                if is_password_meta(&child, &child_attrs) {
                    has_password = true;
                    skip_element(reader, buf, &child)?;
                } else {
                    inner_depth += 1;
                    if depth + inner_depth > MAX_METADATA_DEPTH + 1 {
                        return Err(Error::Bounds {
                            bound: "metadata nesting depth",
                            limit: MAX_METADATA_DEPTH as i64,
                        });
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let child = local_name(&e.name());
                let child_attrs = collect_attrs(&e)?;
                if is_password_meta(&child, &child_attrs) {
                    has_password = true;
                }
            }
            Ok(Event::End(e)) => {
                inner_depth -= 1;
                if inner_depth == 0 {
                    debug_assert_eq!(local_name(&e.name()), name);
                    break;
                }
            }
            Ok(Event::DocType(_)) | Ok(Event::PI(_)) => {
                return Err(Error::Malformed(
                    "NZB XML directives are not allowed".into(),
                ));
            }
            Ok(Event::Eof) => return Err(Error::Malformed("parse NZB XML: unexpected EOF".into())),
            Err(e) => return Err(Error::Malformed(format!("parse NZB XML: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    Ok(has_password)
}

/// Skips one already-opened element (used to drop password metadata).
fn skip_element<R: BufRead>(reader: &mut Reader<R>, buf: &mut Vec<u8>, _name: &str) -> Result<()> {
    let mut depth = 1usize;
    while depth > 0 {
        match reader.read_event_into(buf) {
            Ok(Event::Start(_)) => {
                depth += 1;
                if depth > MAX_METADATA_DEPTH {
                    return Err(Error::Bounds {
                        bound: "metadata nesting depth",
                        limit: MAX_METADATA_DEPTH as i64,
                    });
                }
            }
            Ok(Event::End(_)) => depth -= 1,
            Ok(Event::DocType(_)) | Ok(Event::PI(_)) => {
                return Err(Error::Malformed(
                    "NZB XML directives are not allowed".into(),
                ));
            }
            Ok(Event::Eof) => return Err(Error::Malformed("parse NZB XML: unexpected EOF".into())),
            Err(e) => return Err(Error::Malformed(format!("parse NZB XML: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_segment<R: BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    attrs: HashMap<String, String>,
    ordinal: usize,
    file_ordinal: usize,
) -> Result<Segment> {
    let encoded_bytes: i64 = attrs
        .get("bytes")
        .and_then(|b| b.parse().ok())
        .filter(|&b| b >= 1)
        .ok_or_else(|| Error::Malformed("segment has invalid bytes".into()))?;
    if encoded_bytes > MAX_SEGMENT_BYTES {
        return Err(Error::Bounds {
            bound: "encoded bytes in one segment",
            limit: MAX_SEGMENT_BYTES,
        });
    }
    let number: usize = attrs
        .get("number")
        .and_then(|n| n.parse().ok())
        .filter(|&n| n == ordinal + 1)
        .ok_or_else(|| {
            Error::Malformed(format!(
                "segment number {:?} is not contiguous",
                attrs.get("number").unwrap_or(&String::new())
            ))
        })?;

    // The reader trims each Text event independently, which would silently
    // delete whitespace adjacent to a reference or CDATA section from the
    // middle of the ID; the embedded-whitespace rejection must see the true
    // resolved text. Accumulate untrimmed and let `normalize_message_id`
    // trim the edges. Error returns abort the whole parse, so the saved
    // settings only need restoring on the success path below.
    let saved_trim = (
        reader.config().trim_text_start,
        reader.config().trim_text_end,
    );
    reader.config_mut().trim_text(false);
    let mut text = String::new();
    loop {
        match reader.read_event_into(buf) {
            Ok(Event::Text(e)) => {
                push_segment_text(&mut text, &e.xml10_content())?;
            }
            Ok(Event::CData(e)) => {
                let chunk: &str = e.as_ref();
                push_segment_text(&mut text, chunk)?;
            }
            Ok(Event::GeneralRef(e)) => {
                // Character/predefined references are part of the ID text:
                // resolve them (expanded output counts against the same
                // bound) instead of silently dropping them.
                let resolved = resolve_segment_reference(&e)?;
                push_segment_text(&mut text, &resolved)?;
            }
            Ok(Event::End(e)) => {
                if local_name(&e.name()) != "segment" {
                    return Err(Error::Malformed("unexpected end element in segment".into()));
                }
                break;
            }
            Ok(Event::Start(e)) => {
                return Err(Error::Malformed(format!(
                    "unexpected child element {:?} in segment",
                    e.name().as_ref().to_string()
                )));
            }
            Ok(Event::Empty(_)) => {
                return Err(Error::Malformed(
                    "unexpected child element in segment".into(),
                ));
            }
            Ok(Event::DocType(_)) | Ok(Event::PI(_)) => {
                return Err(Error::Malformed(
                    "NZB XML directives are not allowed".into(),
                ));
            }
            Ok(Event::Eof) => {
                return Err(Error::Malformed(format!(
                    "file {file_ordinal}: unexpected EOF in segment"
                )))
            }
            Err(e) => {
                return Err(Error::Malformed(format!(
                    "file {file_ordinal}: segment text: {e}"
                )))
            }
            _ => {}
        }
        buf.clear();
    }
    reader.config_mut().trim_text_start = saved_trim.0;
    reader.config_mut().trim_text_end = saved_trim.1;
    Ok(Segment {
        ordinal,
        number,
        message_id: normalize_message_id(&text)?,
        encoded_bytes,
    })
}

/// Appends one piece of `<segment>` character data, enforcing
/// [`MAX_SEGMENT_TEXT_BYTES`] on the accumulated (already reference-expanded)
/// text.
fn push_segment_text(text: &mut String, chunk: &str) -> Result<()> {
    if chunk.len() > MAX_SEGMENT_TEXT_BYTES - text.len() {
        return Err(Error::Malformed("segment text is too large".into()));
    }
    text.push_str(chunk);
    Ok(())
}

/// Resolves a `&...;` reference inside `<segment>` text.
///
/// Only decimal/hex character references and the five predefined XML
/// entities (`lt`, `gt`, `amp`, `apos`, `quot`) resolve; DTDs are rejected
/// before this point, so nothing else is defined — unknown names, malformed
/// numbers, non-scalars and characters outside the XML 1.0 `Char`
/// production are explicit errors, never empty text. No external or
/// network resolution is ever attempted.
fn resolve_segment_reference(reference: &BytesRef<'_>) -> Result<Cow<'static, str>> {
    if reference.is_char_ref() {
        // `resolve_char_ref` also errors on malformed numbers, surrogates,
        // code points above U+10FFFF and NUL, but does not enforce the
        // XML 1.0 legal-char production (e.g. U+FFFE).
        let ch = reference
            .resolve_char_ref()
            .map_err(|e| {
                Error::Malformed(format!(
                    "invalid character reference &{}; in segment: {e}",
                    reference.as_ref()
                ))
            })?
            .ok_or_else(|| {
                Error::Malformed(format!(
                    "invalid character reference &{}; in segment",
                    reference.as_ref()
                ))
            })?;
        if !matches!(
            ch,
            '\u{9}'
                | '\u{a}'
                | '\u{d}'
                | '\u{20}'..='\u{d7ff}'
                | '\u{e000}'..='\u{fffd}'
                | '\u{10000}'..='\u{10ffff}'
        ) {
            return Err(Error::Malformed(format!(
                "character reference &{}; is not a valid XML 1.0 character",
                reference.as_ref()
            )));
        }
        let mut buf = [0u8; 4];
        return Ok(Cow::Owned(ch.encode_utf8(&mut buf).to_string()));
    }
    resolve_xml_entity(reference.as_ref())
        .map(Cow::Borrowed)
        .ok_or_else(|| {
            Error::Malformed(format!(
                "unknown entity reference &{}; in segment",
                reference.as_ref()
            ))
        })
}

fn local_name(name: &quick_xml::name::QName<'_>) -> String {
    name.local_name().as_ref().to_string()
}

fn collect_attrs(e: &quick_xml::events::BytesStart<'_>) -> Result<HashMap<String, String>> {
    let mut attrs = HashMap::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|e| Error::Malformed(format!("bad NZB attribute: {e}")))?;
        let key = attr.key.as_ref().to_string();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| Error::Malformed(format!("bad NZB attribute value: {e}")))?
            .into_owned();
        if attrs.insert(key.clone(), value).is_some() {
            return Err(Error::Malformed(format!(
                "element has duplicate attribute {key:?}"
            )));
        }
    }
    Ok(attrs)
}

fn is_password_meta(name: &str, attrs: &HashMap<String, String>) -> bool {
    name == "meta"
        && attrs
            .get("type")
            .is_some_and(|t| t.eq_ignore_ascii_case("password"))
}

/// Normalises a Message-ID to its bare form (no brackets, no surrounding
/// whitespace). Mirrors v1's `NormalizeMessageID`.
pub fn normalize_message_id(value: &str) -> Result<String> {
    let mut id = value.trim().to_string();
    if id.starts_with('<') && id.ends_with('>') && id.len() >= 2 {
        id = id[1..id.len() - 1].trim().to_string();
    }
    if id.is_empty() || id.len() > 998 || id.contains(['<', '>']) {
        return Err(Error::Malformed(
            "Message-ID must be bare, non-empty, and at most 998 bytes".into(),
        ));
    }
    if id.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(Error::Malformed(
            "Message-ID contains whitespace or a control byte".into(),
        ));
    }
    Ok(id)
}

/// SHA-256 over sorted Message-IDs with 4-byte big-endian length prefixes.
/// Byte-identical to v1's `DigestMessageIDs`, including the duplicate-ID error.
pub fn digest_message_ids(message_ids: &[String]) -> Result<[u8; 32]> {
    let mut ordered = message_ids.to_vec();
    ordered.sort();
    let mut hash = Sha256::new();
    let mut previous: Option<&str> = None;
    for id in &ordered {
        if previous == Some(id.as_str()) {
            return Err(Error::Malformed(format!(
                "Message-ID {id:?} appears more than once"
            )));
        }
        previous = Some(id);
        hash.update((id.len() as u32).to_be_bytes());
        hash.update(id.as_bytes());
    }
    Ok(hash.finalize().into())
}

fn filename_from_subject(subject: &str) -> Option<String> {
    let first = subject.find('"')?;
    let last = subject.rfind('"')?;
    if last <= first + 1 {
        return None;
    }
    Some(subject[first + 1..last].to_string())
}

fn classify_role(subject: &str) -> String {
    let lower = subject.to_lowercase();
    if lower.contains(".par2") {
        "par2"
    } else if lower.contains(".nfo") {
        "nfo"
    } else if lower.contains(".cue") {
        "cue"
    } else if lower.contains(".rar") || lower.contains(".7z") || lower.contains(".r00") {
        "archive"
    } else if lower.contains(".flac") || lower.contains(".opus") || lower.contains(".mp3") {
        "content"
    } else {
        "unknown"
    }
    .to_string()
}

fn classify_container(subject: &str) -> String {
    let lower = subject.to_lowercase();
    if lower.contains(".flac") {
        "flac"
    } else if lower.contains(".opus") {
        "opus"
    } else if lower.contains(".mp3") {
        "mp3"
    } else if lower.contains(".rar") || lower.contains(".r00") {
        "rar"
    } else if lower.contains(".7z") {
        "7z"
    } else if lower.contains(".par2") {
        "par2"
    } else {
        "other"
    }
    .to_string()
}
