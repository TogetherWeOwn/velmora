//! Live properties, multistatus bodies and content types.

use crate::path::href;
use crate::state::{DeadProp, Lock};
use crate::time::{http_date, ms_to_iso};
use crate::xml::{escape_text, DAV};

/// Live properties: computed by the gateway, never stored, protected.
pub const LIVE: &[&str] = &[
    "creationdate",
    "getcontentlength",
    "getcontenttype",
    "getetag",
    "getlastmodified",
    "lockdiscovery",
    "resourcetype",
    "supportedlock",
];

/// What PROPFIND reports of one resource.
#[derive(Clone, Debug)]
pub struct Resource {
    pub bucket: Option<String>,
    /// The key (collection form for a collection); `""` for a bucket.
    pub key: String,
    pub collection: bool,
    pub size: u64,
    pub etag: Option<String>,
    pub modified_ms: Option<i64>,
    pub content_type: Option<String>,
}

impl Resource {
    pub fn href(&self) -> String {
        match &self.bucket {
            None => "/".to_owned(),
            Some(b) => href(b, &self.key),
        }
    }

    /// The value of a live property, as the inner XML of its element;
    /// `None` when this resource has none.
    pub fn live(&self, name: &str) -> Option<String> {
        match name {
            "resourcetype" => Some(if self.collection {
                "<D:collection/>".to_owned()
            } else {
                String::new()
            }),
            "getcontentlength" if !self.collection => Some(self.size.to_string()),
            "getetag" if !self.collection => self.etag.as_deref().map(escape_text),
            "getlastmodified" => self.modified_ms.map(http_date),
            "creationdate" => self.modified_ms.map(ms_to_iso),
            "getcontenttype" if !self.collection => Some(escape_text(
                self.content_type
                    .as_deref()
                    .unwrap_or_else(|| guess_type(&self.key)),
            )),
            "supportedlock" => Some(SUPPORTED_LOCK.to_owned()),
            _ => None,
        }
    }
}

pub const SUPPORTED_LOCK: &str = "<D:lockentry><D:lockscope><D:exclusive/></D:lockscope>\
<D:locktype><D:write/></D:locktype></D:lockentry><D:lockentry><D:lockscope><D:shared/>\
</D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>";

/// One `<D:activelock>`.
pub fn active_lock(lock: &Lock, bucket: &str, now_secs: i64) -> String {
    let left = (lock.expires_at - now_secs).max(0);
    format!(
        "<D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:{}/></D:lockscope>\
<D:depth>{}</D:depth>{}<D:timeout>Second-{left}</D:timeout>\
<D:locktoken><D:href>{}</D:href></D:locktoken><D:lockroot><D:href>{}</D:href></D:lockroot>\
</D:activelock>",
        if lock.exclusive {
            "exclusive"
        } else {
            "shared"
        },
        if lock.depth_inf { "infinity" } else { "0" },
        lock.owner_xml.as_deref().unwrap_or(""),
        escape_text(&lock.token),
        escape_text(&href(bucket, &lock.root)),
    )
}

pub fn lock_discovery(locks: &[Lock], bucket: &str, now_secs: i64) -> String {
    locks
        .iter()
        .map(|l| active_lock(l, bucket, now_secs))
        .collect()
}

/// An empty element naming a property, for a propstat.
pub fn prop_name(ns: &str, name: &str) -> String {
    if ns == DAV {
        format!("<D:{name}/>")
    } else {
        format!("<{name} xmlns=\"{}\"/>", crate::xml::escape_attr(ns))
    }
}

/// A live property with its value.
pub fn live_element(name: &str, inner: &str) -> String {
    if inner.is_empty() {
        format!("<D:{name}/>")
    } else {
        format!("<D:{name}>{inner}</D:{name}>")
    }
}

/// A dead property as stored.
pub fn dead_element(p: &DeadProp) -> String {
    p.xml.clone()
}

/// One `<D:response>` with a propstat per status.
pub fn response(href_value: &str, groups: &[(u16, Vec<String>)]) -> String {
    let mut out = format!("<D:response><D:href>{}</D:href>", escape_text(href_value));
    for (status, props) in groups {
        if props.is_empty() {
            continue;
        }
        out.push_str("<D:propstat><D:prop>");
        for p in props {
            out.push_str(p);
        }
        out.push_str(&format!(
            "</D:prop><D:status>HTTP/1.1 {status} {}</D:status></D:propstat>",
            crate::http::reason(*status)
        ));
    }
    out.push_str("</D:response>");
    out
}

/// A `<D:response>` with a status and no properties.
pub fn status_response(href_value: &str, status: u16) -> String {
    status_response_with_description(href_value, status, None)
}

pub(crate) fn status_response_with_description(
    href_value: &str,
    status: u16,
    description: Option<&str>,
) -> String {
    let mut response = format!(
        "<D:response><D:href>{}</D:href><D:status>HTTP/1.1 {status} {}</D:status>",
        escape_text(href_value),
        crate::http::reason(status)
    );
    if let Some(description) = description {
        response.push_str("<D:responsedescription>");
        response.push_str(&escape_text(description));
        response.push_str("</D:responsedescription>");
    }
    response.push_str("</D:response>");
    response
}

pub fn multistatus(responses: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">{responses}</D:multistatus>"
    )
    .into_bytes()
}

/// A `<D:error>` body with one precondition element.
pub fn error_body(inner: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error xmlns:D=\"DAV:\">{inner}</D:error>"
    )
    .into_bytes()
}

/// A content type from the file extension, for a file stored without one.
pub fn guess_type(key: &str) -> &'static str {
    let ext = key
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "txt" | "text" | "log" | "md" | "csv" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "svg" => "image/svg+xml",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "m4a" => "audio/mp4",
        "ogg" => "audio/ogg",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_and_names() {
        assert_eq!(guess_type("a/b.JPG"), "image/jpeg");
        assert_eq!(guess_type("noext"), "application/octet-stream");
        assert_eq!(prop_name(DAV, "getetag"), "<D:getetag/>");
        assert_eq!(prop_name("urn:x", "a"), "<a xmlns=\"urn:x\"/>");
    }

    #[test]
    fn file_and_collection_props() {
        let f = Resource {
            bucket: Some("b".into()),
            key: "d/a b.txt".into(),
            collection: false,
            size: 3,
            etag: Some("\"e\"".into()),
            modified_ms: Some(0),
            content_type: None,
        };
        assert_eq!(f.href(), "/b/d/a%20b.txt");
        assert_eq!(f.live("getcontentlength").as_deref(), Some("3"));
        assert_eq!(f.live("getcontenttype").as_deref(), Some("text/plain"));
        assert_eq!(f.live("resourcetype").as_deref(), Some(""));
        assert_eq!(
            f.live("getlastmodified").as_deref(),
            Some("Thu, 01 Jan 1970 00:00:00 GMT")
        );
        let c = Resource {
            collection: true,
            key: "d/".into(),
            ..f
        };
        assert_eq!(c.live("getcontentlength"), None);
        assert_eq!(c.live("resourcetype").as_deref(), Some("<D:collection/>"));
    }
}
