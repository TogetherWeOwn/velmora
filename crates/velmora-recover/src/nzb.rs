//! Emit standard NZBs without exposing logical object names.

use crate::{
    catalogue::{hex, Catalogue, Selection},
    extent::{sha256, Article},
};
use quick_xml::{
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
    Writer,
};
use std::{
    collections::BTreeSet,
    io::{self, Write},
};
use velmora_bridge::articles::article_spans;

pub fn write_nzb(
    out: impl Write,
    catalog: &Catalogue,
    objects: &[Selection<'_>],
) -> io::Result<()> {
    let reject = |message| io::Error::new(io::ErrorKind::InvalidData, message);
    if objects.is_empty() {
        return Err(reject("no matching objects"));
    }
    if objects
        .iter()
        .any(|entry| !catalog.recoverable(entry.object))
    {
        return Err(reject(
            "selection includes objects without usable Usenet plans",
        ));
    }
    let mut xml = Writer::new(out);
    xml.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
    let mut root = BytesStart::new("nzb");
    root.push_attribute(("xmlns", "http://www.newzbin.com/DTD/2003/nzb"));
    xml.write_event(Event::Start(root))?;
    let mut seen = BTreeSet::new();
    for entry in objects {
        for reference in &entry.object.extents {
            if !seen.insert(&reference.id) {
                continue;
            }
            let extent = catalog.extent(&reference.id);
            let spans = article_spans(extent.cipher_size);
            let mut legacy = Vec::new();
            for (span, article) in spans.iter().zip(&extent.articles) {
                if article.yenc_name.is_some() {
                    let name = opaque_name(&article.message_id);
                    file(&mut xml, &name, &[(article, span.len)])?;
                } else {
                    legacy.push((article, span.len));
                }
            }
            if !legacy.is_empty() {
                let name = opaque_name(&legacy[0].0.message_id);
                file(&mut xml, &name, &legacy)?;
            }
            if let Some(parity) = &extent.parity {
                for (_, article) in &parity.rows {
                    let name = opaque_name(&article.message_id);
                    file(&mut xml, &name, &[(article, parity.shard_len as u64)])?;
                }
            }
        }
    }
    xml.write_event(Event::End(BytesEnd::new("nzb")))?;
    Ok(())
}

fn opaque_name(id: &str) -> String {
    format!("{}.bin", hex(&sha256(id.as_bytes())[..16]))
}

fn file(
    xml: &mut Writer<impl Write>,
    filename: &str,
    segments: &[(&Article, u64)],
) -> io::Result<()> {
    let mut start = BytesStart::new("file");
    let subject = format!("\"{filename}\" yEnc (1/{})", segments.len());
    start.push_attribute(("poster", "recovery@example.invalid"));
    // The index need not record posting dates. Do not invent a timestamp.
    start.push_attribute(("date", "0"));
    start.push_attribute(("subject", &*subject));
    xml.write_event(Event::Start(start))?;
    xml.write_event(Event::Start(BytesStart::new("groups")))?;
    let groups: BTreeSet<_> = segments
        .iter()
        .map(|(article, _)| &article.newsgroup)
        .collect();
    for group in groups {
        xml.write_event(Event::Start(BytesStart::new("group")))?;
        xml.write_event(Event::Text(BytesText::new(group)))?;
        xml.write_event(Event::End(BytesEnd::new("group")))?;
    }
    xml.write_event(Event::End(BytesEnd::new("groups")))?;
    xml.write_event(Event::Start(BytesStart::new("segments")))?;
    for (index, (article, payload_len)) in segments.iter().enumerate() {
        let mut start = BytesStart::new("segment");
        // NZB sizes are advisory wire sizes. Sealed plans have exact decoded
        // sizes only; use a conservative bound including escaped bytes and CRLF.
        let size = (payload_len * 2 + (payload_len * 2).div_ceil(128) * 2 + 2048).to_string();
        let number = (index + 1).to_string();
        start.push_attribute(("bytes", &*size));
        start.push_attribute(("number", &*number));
        xml.write_event(Event::Start(start))?;
        xml.write_event(Event::Text(BytesText::new(&article.message_id)))?;
        xml.write_event(Event::End(BytesEnd::new("segment")))?;
    }
    xml.write_event(Event::End(BytesEnd::new("segments")))?;
    xml.write_event(Event::End(BytesEnd::new("file")))?;
    Ok(())
}
