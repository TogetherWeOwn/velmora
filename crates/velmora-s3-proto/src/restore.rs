// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/restore.rs. License: MIT.
// Copied verbatim except: this header only. Kept only so the copied contract test compiles.

use chrono::{DateTime, Utc};
use quick_xml::{events::Event, Reader};

use super::{ErrorCode, Policy, Result};

/// Strict regular RestoreObject subset. Unknown elements, attributes, DTDs,
/// entities, CDATA and duplicate fields fail closed. No XML-side effects.
pub fn parse_restore(xml: &[u8], policy: &Policy) -> Result<u32> {
    if xml.len() > policy.limits.control_xml_bytes {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut root_seen = false;
    let mut declaration_seen = false;
    let mut parameters_seen = false;
    let mut days = None;
    let mut tier = None;
    let mut text = String::new();
    loop {
        match reader.read_event().map_err(|_| ErrorCode::MalformedXML)? {
            Event::Start(e) => {
                let name = e.name().as_ref().as_bytes().to_vec();
                let parent = stack.last().map(Vec::as_slice);
                let allowed = match (parent, name.as_slice()) {
                    (None, b"RestoreRequest") if !root_seen => {
                        root_seen = true;
                        true
                    }
                    (Some(b"RestoreRequest"), b"Days") if days.is_none() => true,
                    (Some(b"RestoreRequest"), b"GlacierJobParameters") if !parameters_seen => {
                        parameters_seen = true;
                        true
                    }
                    (Some(b"GlacierJobParameters"), b"Tier") if tier.is_none() => true,
                    _ => false,
                };
                if !allowed {
                    return Err(ErrorCode::InvalidRequest);
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
                text.clear();
                stack.push(name);
            }
            Event::Text(e) => {
                if !matches!(stack.last().map(Vec::as_slice), Some(b"Days" | b"Tier")) {
                    return Err(ErrorCode::InvalidRequest);
                }
                text.push_str(e.as_ref());
            }
            Event::End(_) => {
                let name = stack.pop().ok_or(ErrorCode::MalformedXML)?;
                match name.as_slice() {
                    b"Days" => days = Some(std::mem::take(&mut text)),
                    b"Tier" => tier = Some(std::mem::take(&mut text)),
                    _ => {}
                }
            }
            Event::Decl(e) => {
                if root_seen || declaration_seen {
                    return Err(ErrorCode::MalformedXML);
                }
                validate_declaration(&e)?;
                declaration_seen = true;
            }
            Event::Eof => break,
            _ => return Err(ErrorCode::InvalidRequest),
        }
    }
    if !root_seen || !stack.is_empty() {
        return Err(ErrorCode::MalformedXML);
    }
    policy.restore(
        days.as_deref().ok_or(ErrorCode::InvalidArgument)?,
        tier.as_deref(),
    )
}

pub(super) fn validate_declaration(e: &quick_xml::events::BytesDecl<'_>) -> Result<()> {
    if e.version().map_err(|_| ErrorCode::MalformedXML)? != "1.0" {
        return Err(ErrorCode::MalformedXML);
    }
    let attributes = quick_xml::events::BytesStart::from_content(e.as_ref(), 3);
    let mut position = 0;
    for attr in attributes.attributes() {
        let attr = attr.map_err(|_| ErrorCode::MalformedXML)?;
        position = match attr.key.as_ref() {
            "version" if position == 0 && attr.value == "1.0" => 1,
            "encoding" if position == 1 && attr.value.eq_ignore_ascii_case("UTF-8") => 2,
            "standalone"
                if (1..=2).contains(&position) && matches!(attr.value.as_ref(), "yes" | "no") =>
            {
                3
            }
            _ => return Err(ErrorCode::MalformedXML),
        };
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreStatus {
    Unavailable,
    Pending,
    Available { expiry: i64 },
}

impl RestoreStatus {
    /// Adapter renders this only for an authorized logical reference + G.
    /// Expired/failed/never-restored states omit the header entirely.
    pub fn header(&self, now: i64) -> Result<Option<String>> {
        match self {
            Self::Unavailable => Ok(None),
            Self::Pending => Ok(Some("ongoing-request=\"true\"".into())),
            Self::Available { expiry } if now < *expiry => {
                let expiry = DateTime::<Utc>::from_timestamp(*expiry, 0)
                    .ok_or(ErrorCode::InvalidArgument)?;
                Ok(Some(format!(
                    "ongoing-request=\"false\", expiry-date=\"{}\"",
                    expiry.format("%a, %d %b %Y %H:%M:%S GMT")
                )))
            }
            Self::Available { .. } => Ok(None),
        }
    }
}
