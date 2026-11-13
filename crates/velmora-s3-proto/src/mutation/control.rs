// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/mutation/control.rs. License: MIT.
// Copied verbatim except: line 4 `use crate::s3::{...}` -> `use crate::{...}`; this header.

use quick_xml::{events::Event, Reader};

use super::{MultipartChecksum, PartEvidence};
use crate::{decimal, upload::digest_value, ErrorCode, Policy, Result};

#[derive(Clone, Debug)]
pub struct DeleteRequest {
    pub keys: Vec<String>,
    pub quiet: bool,
}

struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn leaf(&self) -> Result<&str> {
        if !self.children.is_empty() {
            return Err(ErrorCode::MalformedXML);
        }
        Ok(&self.text)
    }
    fn container(&self) -> Result<()> {
        if !xml_space(&self.text) {
            return Err(ErrorCode::MalformedXML);
        }
        Ok(())
    }
}

fn xml_space(text: &str) -> bool {
    text.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
}

pub(super) fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

/// Bounded control XML, not a general XML object mapper. No DTD, external
/// entities, CDATA, PI, comments, unknown namespaces or mixed-content fields.
/// Preserve key whitespace; decode only XML predefined/numeric references.
fn tree(bytes: &[u8], policy: &Policy) -> Result<Node> {
    if bytes.len() > policy.limits.control_xml_bytes {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut reader = Reader::from_reader(bytes);
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut declared = false;
    loop {
        match reader.read_event().map_err(|_| ErrorCode::MalformedXML)? {
            Event::Start(e) => {
                if stack.len() >= 3 || (stack.is_empty() && root.is_some()) {
                    return Err(ErrorCode::MalformedXML);
                }
                for attr in e.attributes() {
                    let attr = attr.map_err(|_| ErrorCode::MalformedXML)?;
                    if !stack.is_empty()
                        || attr.key.as_ref() != "xmlns"
                        || attr.value.as_ref() != "http://s3.amazonaws.com/doc/2006-03-01/"
                    {
                        return Err(ErrorCode::InvalidRequest);
                    }
                }
                stack.push(Node {
                    name: e.name().as_ref().to_owned(),
                    text: String::new(),
                    children: vec![],
                });
            }
            Event::Text(e) => {
                let text = e.xml10_content();
                if !text.chars().all(xml_char) {
                    return Err(ErrorCode::MalformedXML);
                }
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&text);
                } else if !xml_space(&text) {
                    return Err(ErrorCode::MalformedXML);
                }
            }
            Event::GeneralRef(e) => {
                let entity = e.as_ref();
                let c = match entity {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    s if s.starts_with('#') => {
                        let (digits, radix) = if let Some(digits) = s.strip_prefix("#x") {
                            (digits, 16)
                        } else {
                            (&s[1..], 10)
                        };
                        if digits.is_empty()
                            || !digits.bytes().all(|b| {
                                if radix == 16 {
                                    b.is_ascii_hexdigit()
                                } else {
                                    b.is_ascii_digit()
                                }
                            })
                        {
                            return Err(ErrorCode::MalformedXML);
                        }
                        u32::from_str_radix(digits, radix)
                            .ok()
                            .and_then(char::from_u32)
                            .ok_or(ErrorCode::MalformedXML)?
                    }
                    _ => return Err(ErrorCode::InvalidRequest),
                };
                if !xml_char(c) {
                    return Err(ErrorCode::MalformedXML);
                }
                stack
                    .last_mut()
                    .ok_or(ErrorCode::MalformedXML)?
                    .text
                    .push(c);
            }
            Event::End(_) => {
                let node = stack.pop().ok_or(ErrorCode::MalformedXML)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return Err(ErrorCode::MalformedXML);
                }
            }
            Event::Decl(e) => {
                if declared || root.is_some() || !stack.is_empty() {
                    return Err(ErrorCode::MalformedXML);
                }
                declared = true;
                let attrs = quick_xml::events::BytesStart::from_content(e.as_ref(), 3);
                let mut position = 0;
                for attr in attrs.attributes() {
                    let attr = attr.map_err(|_| ErrorCode::MalformedXML)?;
                    position = match attr.key.as_ref() {
                        "version" if position == 0 && attr.value == "1.0" => 1,
                        "encoding" if position == 1 && attr.value.eq_ignore_ascii_case("UTF-8") => {
                            2
                        }
                        "standalone"
                            if (1..=2).contains(&position)
                                && matches!(attr.value.as_ref(), "yes" | "no") =>
                        {
                            3
                        }
                        _ => return Err(ErrorCode::MalformedXML),
                    };
                }
                if position == 0 {
                    return Err(ErrorCode::MalformedXML);
                }
            }
            Event::Eof => break,
            _ => return Err(ErrorCode::InvalidRequest),
        }
    }
    if !stack.is_empty() {
        return Err(ErrorCode::MalformedXML);
    }
    root.ok_or(ErrorCode::MalformedXML)
}

pub fn parse_delete(bytes: &[u8], policy: &Policy, maximum: usize) -> Result<DeleteRequest> {
    let root = tree(bytes, policy)?;
    if root.name != "Delete" {
        return Err(ErrorCode::MalformedXML);
    }
    root.container()?;
    let mut quiet = None;
    let mut keys = Vec::new();
    for node in root.children {
        match node.name.as_str() {
            "Quiet" if quiet.is_none() => {
                quiet = Some(match node.leaf()? {
                    "true" => true,
                    "false" => false,
                    _ => return Err(ErrorCode::InvalidArgument),
                })
            }
            "Object" => {
                node.container()?;
                if node.children.len() != 1 || node.children[0].name != "Key" {
                    return Err(ErrorCode::InvalidRequest);
                }
                let key = node.children[0].leaf()?;
                if key.is_empty() || keys.len() >= maximum.min(1000) {
                    return Err(ErrorCode::InvalidRequest);
                }
                keys.push(key.to_owned());
            }
            _ => return Err(ErrorCode::InvalidRequest),
        }
    }
    if keys.is_empty() {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(DeleteRequest {
        keys,
        quiet: quiet.unwrap_or(false),
    })
}

/// Version IDs, unknown integrity algorithms and duplicate/missing part fields
/// are rejected. The adapter compares every returned field to stored evidence.
pub fn parse_complete(
    bytes: &[u8],
    policy: &Policy,
    maximum: u16,
    checksum: MultipartChecksum,
) -> Result<Vec<PartEvidence>> {
    let root = tree(bytes, policy)?;
    if root.name != "CompleteMultipartUpload" {
        return Err(ErrorCode::MalformedXML);
    }
    root.container()?;
    let mut parts = Vec::new();
    for node in root.children {
        if node.name != "Part" || parts.len() >= usize::from(maximum.min(10_000)) {
            return Err(ErrorCode::InvalidPart);
        }
        node.container()?;
        let mut number = None;
        let mut etag = None;
        let mut value = None;
        for field in node.children {
            let text = field.leaf()?;
            match field.name.as_str() {
                "PartNumber" if number.is_none() => {
                    let n = decimal(text)?;
                    if n == 0 || n > u64::from(maximum) {
                        return Err(ErrorCode::InvalidPart);
                    }
                    number = Some(n as u16);
                }
                "ETag" if etag.is_none() => etag = Some(text.to_owned()),
                name if value.is_none() => {
                    let (expected, size) = match checksum {
                        MultipartChecksum::None => return Err(ErrorCode::InvalidRequest),
                        MultipartChecksum::CompositeSha256
                        | MultipartChecksum::Full(super::ChecksumAlgorithm::Sha256) => {
                            ("ChecksumSHA256", 32)
                        }
                        MultipartChecksum::Full(super::ChecksumAlgorithm::Crc32) => {
                            ("ChecksumCRC32", 4)
                        }
                    };
                    if name != expected {
                        return Err(ErrorCode::InvalidRequest);
                    }
                    value = Some(digest_value(text, size)?);
                }
                _ => return Err(ErrorCode::InvalidRequest),
            }
        }
        if (checksum != MultipartChecksum::None) != value.is_some() {
            return Err(ErrorCode::InvalidPart);
        }
        parts.push(PartEvidence {
            number: number.ok_or(ErrorCode::InvalidPart)?,
            etag: etag.ok_or(ErrorCode::InvalidPart)?,
            checksum: value,
        });
    }
    if parts.is_empty() {
        return Err(ErrorCode::InvalidPart);
    }
    if parts.windows(2).any(|w| w[0].number >= w[1].number) {
        return Err(ErrorCode::InvalidPartOrder);
    }
    Ok(parts)
}

/// Client-side classification: an HTTP 200 with an embedded Error is failure,
/// not a completed upload. This reference server never emits an early 200.
pub fn completion_result(status: u16, bytes: &[u8], policy: &Policy) -> Result<String> {
    let root = tree(bytes, policy)?;
    root.container()?;
    if root.name == "Error" {
        let code = root
            .children
            .iter()
            .find(|n| n.name == "Code")
            .ok_or(ErrorCode::MalformedXML)?
            .leaf()?;
        return Err(match code {
            "InvalidPart" => ErrorCode::InvalidPart,
            "InvalidPartOrder" => ErrorCode::InvalidPartOrder,
            "EntityTooSmall" => ErrorCode::EntityTooSmall,
            "BadDigest" => ErrorCode::BadDigest,
            "AccessDenied" => ErrorCode::AccessDenied,
            "SlowDown" => ErrorCode::SlowDown,
            "PreconditionFailed" => ErrorCode::PreconditionFailed,
            "ConditionalRequestConflict" => ErrorCode::ConditionalRequestConflict,
            "NoSuchUpload" => ErrorCode::NoSuchUpload,
            _ => ErrorCode::InternalError,
        });
    }
    if status != 200 || root.name != "CompleteMultipartUploadResult" {
        return Err(ErrorCode::InternalError);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut etag = None;
    for field in &root.children {
        if !matches!(
            field.name.as_str(),
            "Location"
                | "Bucket"
                | "Key"
                | "ETag"
                | "ChecksumSHA256"
                | "ChecksumCRC32"
                | "ChecksumType"
        ) || !seen.insert(field.name.as_str())
        {
            return Err(ErrorCode::MalformedXML);
        }
        let text = field.leaf()?;
        if field.name == "ETag" {
            if text.is_empty() {
                return Err(ErrorCode::MalformedXML);
            }
            etag = Some(text.to_owned());
        }
    }
    etag.ok_or(ErrorCode::MalformedXML)
}
