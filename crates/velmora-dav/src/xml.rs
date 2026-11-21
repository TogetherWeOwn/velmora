//! A small namespace-aware XML tree for WebDAV request bodies, and the
//! escaping used to write responses.
//!
//! Request bodies are small (PROPFIND, PROPPATCH, LOCK), so they are read
//! whole into a tree with every element and attribute name resolved to
//! its namespace. A body that is not well-formed XML, not UTF-8, uses an
//! undeclared prefix, declares a DTD, or is deeper or larger than the
//! limits below is refused.

use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;

/// The DAV: namespace.
pub const DAV: &str = "DAV:";

/// The XML namespace, bound to the `xml` prefix by definition.
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Deepest element nesting accepted in a request body.
const MAX_DEPTH: usize = 64;

/// Most elements accepted in one request body.
const MAX_NODES: usize = 20_000;

/// One element: its namespace (`None` = no namespace), local name,
/// attributes and children in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    pub ns: Option<String>,
    pub name: String,
    /// `(namespace, local name, value)`; namespace declarations are not
    /// attributes and are not kept.
    pub attrs: Vec<(Option<String>, String, String)>,
    pub children: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Text(String),
}

impl Element {
    pub fn is(&self, ns: &str, name: &str) -> bool {
        self.ns.as_deref() == Some(ns) && self.name == name
    }

    /// Child elements, in order.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    /// The first child element with this name.
    pub fn child(&self, ns: &str, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.is(ns, name))
    }

    /// The text of this element and its descendants.
    pub fn text(&self) -> String {
        let mut out = String::new();
        fn walk(e: &Element, out: &mut String) {
            for n in &e.children {
                match n {
                    Node::Text(t) => out.push_str(t),
                    Node::Element(c) => walk(c, out),
                }
            }
        }
        walk(self, &mut out);
        out
    }

    /// `xml:lang` on this element, if any.
    pub fn lang(&self) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(ns, name, _)| ns.as_deref() == Some(XML_NS) && name == "lang")
            .map(|(_, _, v)| v.as_str())
    }

    /// The element as standalone XML: every element carries its own
    /// default namespace declaration, so the text means the same wherever
    /// it is placed. `xml:lang` stays `xml:lang`; other namespaced
    /// attributes get a prefix declared on their element.
    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, None);
        out
    }

    fn write(&self, out: &mut String, parent_ns: Option<&Option<String>>) {
        out.push('<');
        out.push_str(&self.name);
        if parent_ns != Some(&self.ns) {
            out.push_str(" xmlns=\"");
            out.push_str(&escape_attr(self.ns.as_deref().unwrap_or("")));
            out.push('"');
        }
        let mut declared = 0;
        for (ns, name, value) in &self.attrs {
            out.push(' ');
            match ns.as_deref() {
                None => {}
                Some(XML_NS) => out.push_str("xml:"),
                Some(other) => {
                    let prefix = format!("a{declared}");
                    declared += 1;
                    out.push_str(&format!(
                        "xmlns:{prefix}=\"{}\" {prefix}:",
                        escape_attr(other)
                    ));
                }
            }
            out.push_str(name);
            out.push_str("=\"");
            out.push_str(&escape_attr(value));
            out.push('"');
        }
        if self.children.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        for n in &self.children {
            match n {
                Node::Text(t) => out.push_str(&escape_text(t)),
                Node::Element(c) => c.write(out, Some(&self.ns)),
            }
        }
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
    }
}

/// Why a body was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlError {
    NotUtf8,
    Malformed,
    TooLarge,
}

fn resolved(r: ResolveResult<'_>) -> Result<Option<String>, XmlError> {
    match r {
        ResolveResult::Unbound => Ok(None),
        ResolveResult::Bound(ns) => Ok(Some(ns.0.to_owned()).filter(|s| !s.is_empty())),
        ResolveResult::Unknown(_) => Err(XmlError::Malformed),
    }
}

/// A character XML 1.0 can carry.
fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

fn reference(entity: &str) -> Result<char, XmlError> {
    let c = match entity {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        s if s.starts_with("#x") => u32::from_str_radix(&s[2..], 16)
            .ok()
            .and_then(char::from_u32)
            .ok_or(XmlError::Malformed)?,
        s if s.starts_with('#') => s[1..]
            .parse::<u32>()
            .ok()
            .and_then(char::from_u32)
            .ok_or(XmlError::Malformed)?,
        _ => return Err(XmlError::Malformed),
    };
    if xml_char(c) {
        Ok(c)
    } else {
        Err(XmlError::Malformed)
    }
}

/// Parses a whole document. Whitespace-only text between elements is
/// kept (a dead property value may be whitespace).
pub fn parse(body: &[u8]) -> Result<Element, XmlError> {
    let text = std::str::from_utf8(body).map_err(|_| XmlError::NotUtf8)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = NsReader::from_str(text);
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut nodes = 0usize;
    loop {
        let event = reader.read_event().map_err(|_| XmlError::Malformed)?;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                if root.is_some() {
                    return Err(XmlError::Malformed);
                }
                nodes += 1;
                if nodes > MAX_NODES || stack.len() >= MAX_DEPTH {
                    return Err(XmlError::TooLarge);
                }
                let (ns, local) = reader.resolver().resolve_element(e.name());
                let ns = resolved(ns)?;
                // `xmlns:p=""` cannot bind a prefix (Namespaces in XML
                // 1.0): an element named with it is not well-formed.
                if ns.is_none() && e.name().0.contains(':') {
                    return Err(XmlError::Malformed);
                }
                let mut attrs = Vec::new();
                for attr in e.attributes() {
                    let attr = attr.map_err(|_| XmlError::Malformed)?;
                    let key = attr.key.0;
                    if key == "xmlns" || key.starts_with("xmlns:") {
                        continue;
                    }
                    let (ans, alocal) = reader.resolver().resolve_attribute(attr.key);
                    let ans = if key.starts_with("xml:") {
                        Some(XML_NS.to_owned())
                    } else {
                        resolved(ans)?
                    };
                    let value = attr
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|_| XmlError::Malformed)?;
                    attrs.push((ans, alocal.as_ref().to_owned(), value.into_owned()));
                }
                let el = Element {
                    ns,
                    name: local.as_ref().to_owned(),
                    attrs,
                    children: Vec::new(),
                };
                if matches!(event, Event::Empty(_)) {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(Node::Element(el)),
                        None => root = Some(el),
                    }
                } else {
                    stack.push(el);
                }
            }
            Event::End(_) => {
                let el = stack.pop().ok_or(XmlError::Malformed)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(el)),
                    None => root = Some(el),
                }
            }
            Event::Text(e) => {
                let t = e.xml10_content();
                if !t.chars().all(xml_char) {
                    return Err(XmlError::Malformed);
                }
                push_text(&mut stack, &t)?;
            }
            Event::CData(e) => {
                let t: &str = e.as_ref();
                push_text(&mut stack, t)?;
            }
            Event::GeneralRef(e) => {
                let c = reference(e.as_ref())?;
                let mut buf = [0u8; 4];
                push_text(&mut stack, c.encode_utf8(&mut buf))?;
            }
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::DocType(_) => return Err(XmlError::Malformed),
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(XmlError::Malformed);
    }
    root.ok_or(XmlError::Malformed)
}

fn push_text(stack: &mut [Element], t: &str) -> Result<(), XmlError> {
    match stack.last_mut() {
        Some(el) => {
            if let Some(Node::Text(prev)) = el.children.last_mut() {
                prev.push_str(t);
            } else {
                el.children.push(Node::Text(t.to_owned()));
            }
            Ok(())
        }
        None if t.trim().is_empty() => Ok(()),
        None => Err(XmlError::Malformed),
    }
}

/// Text as XML character data; characters XML cannot carry become U+FFFD.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            c if xml_char(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
    out
}

/// Text as an attribute value in double quotes.
pub fn escape_attr(s: &str) -> String {
    escape_text(s)
        .replace('"', "&quot;")
        .replace('\n', "&#10;")
        .replace('\t', "&#9;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_resolve_to_namespaces() {
        let doc = br#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:z="http://z/"><D:prop><z:a/><b xmlns="urn:b"/><c/></D:prop></D:propfind>"#;
        let root = parse(doc).unwrap();
        assert!(root.is(DAV, "propfind"));
        let prop = root.child(DAV, "prop").unwrap();
        let names: Vec<(Option<&str>, &str)> = prop
            .elements()
            .map(|e| (e.ns.as_deref(), e.name.as_str()))
            .collect();
        assert_eq!(
            names,
            [(Some("http://z/"), "a"), (Some("urn:b"), "b"), (None, "c")]
        );
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        assert_eq!(parse(b"<a><b></a>"), Err(XmlError::Malformed));
        assert_eq!(parse(b"<x:a/>"), Err(XmlError::Malformed));
        assert_eq!(
            parse(br#"<a xmlns:bar=""><bar:foo/></a>"#),
            Err(XmlError::Malformed)
        );
        assert_eq!(parse(b"\xff<a/>"), Err(XmlError::NotUtf8));
        assert_eq!(parse(b""), Err(XmlError::Malformed));
        assert_eq!(parse(b"<a/><b/>"), Err(XmlError::Malformed));
        assert_eq!(parse(b"text<a/>"), Err(XmlError::Malformed));
        assert_eq!(
            parse(b"<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>"),
            Err(XmlError::Malformed)
        );
        let deep = "<a>".repeat(100) + &"</a>".repeat(100);
        assert_eq!(parse(deep.as_bytes()), Err(XmlError::TooLarge));
    }

    #[test]
    fn values_round_trip_with_their_namespaces() {
        let doc = r#"<D:set xmlns:D="DAV:" xmlns:p="urn:p" xmlns:q="urn:q"><p:v xml:lang="en">a &amp; b<q:in q:at="1">x</q:in><plain/></p:v></D:set>"#;
        let root = parse(doc.as_bytes()).unwrap();
        let v = root.child("urn:p", "v").unwrap();
        assert_eq!(v.lang(), Some("en"));
        let xml = v.to_xml();
        assert_eq!(
            xml,
            r#"<v xmlns="urn:p" xml:lang="en">a &amp; b<in xmlns="urn:q" xmlns:a0="urn:q" a0:at="1">x</in><plain xmlns=""/></v>"#
        );
        // What was written reads back as the same tree.
        assert_eq!(&parse(xml.as_bytes()).unwrap(), v);
        // An element in no namespace under one in a namespace.
        let e = parse(br#"<a xmlns="urn:a"><b xmlns=""/></a>"#).unwrap();
        assert_eq!(parse(e.to_xml().as_bytes()).unwrap(), e);
    }

    #[test]
    fn escaping() {
        assert_eq!(escape_text("a<b>&\u{1}"), "a&lt;b&gt;&amp;\u{FFFD}");
        assert_eq!(escape_attr("\"x\"\n"), "&quot;x&quot;&#10;");
    }
}
