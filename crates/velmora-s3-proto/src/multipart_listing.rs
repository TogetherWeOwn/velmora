//! ListMultipartUploads and ListParts: request parsing, the delimiter fold
//! over rows the caller fetches in `(key, upload id)` order, and the XML
//! renderers. Pure: no I/O.
//!
//! Uploads list in `(key, upload id)` order. S3 orders the uploads of one
//! key by initiation time; the markers a client sends back work the same
//! either way, because they only name the last entry it was given.

use crate::listing::{url_encode, xml_character, NS};
use crate::{decimal, iso_date_ms, xml, xml_response, ErrorCode, Response, Result, Target};

/// S3's page cap for both listings.
const MAX_PAGE: u32 = 1000;

fn page_size(target: &Target, name: &str) -> Result<u32> {
    Ok(target
        .one(name)?
        .map(|v| decimal(v).map_err(|_| ErrorCode::InvalidArgument))
        .transpose()?
        .map_or(MAX_PAGE, |n| n.min(u64::from(MAX_PAGE)) as u32))
}

fn url_encoding(target: &Target) -> Result<bool> {
    match target.one("encoding-type")? {
        None => Ok(false),
        Some("url") => Ok(true),
        Some(_) => Err(ErrorCode::InvalidArgument),
    }
}

/// XML 1.0 cannot carry every key; such a page needs `encoding-type=url`.
fn field(value: &str, url_encoding: bool) -> Result<String> {
    if url_encoding {
        Ok(xml(&url_encode(value)))
    } else if value.chars().all(xml_character) {
        Ok(xml(value))
    } else {
        Err(ErrorCode::InvalidArgument)
    }
}

// ---------------------------------------------------------------------------
// ListMultipartUploads
// ---------------------------------------------------------------------------

/// One open upload as the catalogue returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadEntry {
    pub key: String,
    pub upload_id: String,
    pub initiated_ms: i64,
}

#[derive(Clone, Debug)]
enum Entry {
    Upload(UploadEntry),
    CommonPrefix(String),
}

/// Where a scan stands: the last row consumed and the CommonPrefix whose
/// remaining members are skipped.
#[derive(Clone, Debug, Default)]
struct Position {
    key: Option<String>,
    upload_id: Option<String>,
    skip_prefix: Option<String>,
}

/// One ListMultipartUploads page. The caller loops: query the open uploads
/// of the bucket whose key starts with [`Self::prefix`], sorts after
/// [`Self::after`] and is not under [`Self::skip_prefix`], in ascending
/// `(key, upload id)` order; `push` each while `wants_more()`; then
/// `finish(exhausted)`, where `exhausted` means the scan reached the end
/// of the prefix range (false = the caller's query budget ran out, which
/// yields a valid truncated page).
#[derive(Clone, Debug)]
pub struct ListUploads {
    bucket: String,
    prefix: String,
    delimiter: String,
    key_marker: Option<String>,
    upload_id_marker: Option<String>,
    url_encoding: bool,
    max_uploads: u32,
    position: Position,
    scanned: usize,
    entries: Vec<(Entry, Position)>,
}

impl ListUploads {
    pub fn parse(target: &Target) -> Result<Self> {
        let max_uploads = page_size(target, "max-uploads")?;
        let url_encoding = url_encoding(target)?;
        let prefix = target.one("prefix")?.unwrap_or("").to_owned();
        let delimiter = target.one("delimiter")?.unwrap_or("").to_owned();
        let key_marker = target
            .one("key-marker")?
            .filter(|m| !m.is_empty())
            .map(str::to_owned);
        // As at S3, an upload id marker without a key marker is ignored.
        let upload_id_marker = target
            .one("upload-id-marker")?
            .filter(|m| !m.is_empty() && key_marker.is_some())
            .map(str::to_owned);
        // A key marker that is exactly one CommonPrefix under this prefix
        // and delimiter is the `NextKeyMarker` of a page that ended on that
        // group: the group is delivered, its members are skipped.
        let skip_prefix = match (&key_marker, &upload_id_marker) {
            (Some(marker), None) => marker
                .strip_prefix(prefix.as_str())
                .filter(|rest| {
                    !delimiter.is_empty()
                        && rest.find(delimiter.as_str()) == rest.len().checked_sub(delimiter.len())
                })
                .map(|_| marker.clone()),
            _ => None,
        };
        Ok(Self {
            bucket: target.bucket.clone(),
            prefix,
            delimiter,
            position: Position {
                key: key_marker.clone(),
                upload_id: upload_id_marker.clone(),
                skip_prefix,
            },
            key_marker,
            upload_id_marker,
            url_encoding,
            max_uploads,
            scanned: 0,
            entries: Vec::new(),
        })
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Exclusive lower bound of the next query: every key after this key,
    /// and with an upload id also the later uploads of the key itself.
    /// `None` = from the start of the prefix.
    pub fn after(&self) -> Option<(&str, Option<&str>)> {
        self.position
            .key
            .as_deref()
            .map(|key| (key, self.position.upload_id.as_deref()))
    }

    /// CommonPrefix already emitted; rows under it are skipped, so the
    /// caller seeks past it instead of scanning them.
    pub fn skip_prefix(&self) -> Option<&str> {
        self.position.skip_prefix.as_deref()
    }

    /// False once the page holds `max-uploads` entries plus one lookahead.
    pub fn wants_more(&self) -> bool {
        self.max_uploads > 0 && self.entries.len() <= self.max_uploads as usize
    }

    pub fn push(&mut self, row: UploadEntry) -> Result<()> {
        let in_order = match self.after() {
            None => true,
            Some((key, id)) => {
                row.key.as_str() > key
                    || (row.key == key && id.is_some_and(|id| row.upload_id.as_str() > id))
            }
        };
        if !self.wants_more() || !row.key.starts_with(&self.prefix) || !in_order {
            return Err(ErrorCode::InternalError);
        }
        self.scanned += 1;
        // Even a skipped group member advances a budget-limited page.
        self.position.key = Some(row.key.clone());
        self.position.upload_id = Some(row.upload_id.clone());
        if self
            .position
            .skip_prefix
            .as_ref()
            .is_some_and(|p| row.key.starts_with(p))
        {
            return Ok(());
        }
        let plen = self.prefix.len();
        let common = (!self.delimiter.is_empty())
            .then(|| {
                row.key[plen..]
                    .find(&self.delimiter)
                    .map(|i| row.key[..plen + i + self.delimiter.len()].to_owned())
            })
            .flatten();
        self.position.skip_prefix = common.clone();
        let entry = match common {
            Some(p) => Entry::CommonPrefix(p),
            None => Entry::Upload(row),
        };
        self.entries.push((entry, self.position.clone()));
        Ok(())
    }

    pub fn finish(mut self, exhausted: bool) -> Result<Response> {
        let max = self.max_uploads as usize;
        let overflow = self.entries.len() > max;
        let budget = !overflow && !exhausted && max > 0;
        if budget && self.scanned == 0 {
            // A truncated page that scanned nothing would loop the client forever.
            return Err(ErrorCode::InternalError);
        }
        let truncated = overflow || budget;
        if overflow {
            self.entries.pop();
            // Revisit the lookahead entry: only delivered entries are consumed.
            self.position = self
                .entries
                .last()
                .ok_or(ErrorCode::InternalError)?
                .1
                .clone();
        }
        let enc = self.url_encoding;
        let mut out = format!(
            "<ListMultipartUploadsResult xmlns=\"{NS}\"><Bucket>{}</Bucket><KeyMarker>{}</KeyMarker><UploadIdMarker>{}</UploadIdMarker>",
            xml(&self.bucket),
            field(self.key_marker.as_deref().unwrap_or(""), enc)?,
            xml(self.upload_id_marker.as_deref().unwrap_or(""))
        );
        if truncated {
            // After a CommonPrefix the marker is the prefix itself, so the
            // next page skips the whole group; otherwise it is the last
            // upload scanned, which is also right for a page cut short by
            // the query budget.
            let (key, upload_id) = match &self.position.skip_prefix {
                Some(p) => (p.as_str(), ""),
                None => (
                    self.position.key.as_deref().unwrap_or(""),
                    self.position.upload_id.as_deref().unwrap_or(""),
                ),
            };
            // A page that names its own marker would loop the client; a
            // caller that seeks past `skip_prefix` never gets here.
            if self.key_marker.as_deref() == Some(key)
                && self.upload_id_marker.as_deref().unwrap_or("") == upload_id
            {
                return Err(ErrorCode::InternalError);
            }
            out.push_str(&format!(
                "<NextKeyMarker>{}</NextKeyMarker><NextUploadIdMarker>{}</NextUploadIdMarker>",
                field(key, enc)?,
                xml(upload_id)
            ));
        }
        out.push_str(&format!("<Prefix>{}</Prefix>", field(&self.prefix, enc)?));
        if !self.delimiter.is_empty() {
            out.push_str(&format!(
                "<Delimiter>{}</Delimiter>",
                field(&self.delimiter, enc)?
            ));
        }
        if enc {
            out.push_str("<EncodingType>url</EncodingType>");
        }
        out.push_str(&format!(
            "<MaxUploads>{max}</MaxUploads><IsTruncated>{truncated}</IsTruncated>"
        ));
        for (entry, _) in &self.entries {
            match entry {
                Entry::Upload(u) => out.push_str(&format!(
                    "<Upload><Key>{}</Key><UploadId>{}</UploadId><StorageClass>STANDARD</StorageClass><Initiated>{}</Initiated></Upload>",
                    field(&u.key, enc)?,
                    xml(&u.upload_id),
                    iso_date_ms(u.initiated_ms)?
                )),
                Entry::CommonPrefix(p) => out.push_str(&format!(
                    "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                    field(p, enc)?
                )),
            }
        }
        out.push_str("</ListMultipartUploadsResult>");
        Ok(xml_response(out))
    }
}

// ---------------------------------------------------------------------------
// ListParts
// ---------------------------------------------------------------------------

/// One stored part of an upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartEntry {
    pub part_number: u16,
    pub size: u64,
    pub etag: String,
    pub last_modified_ms: i64,
}

/// The paging of one ListParts request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListParts {
    /// Parts with a number above this are listed. 0 = from the first.
    pub part_number_marker: u64,
    pub max_parts: u32,
}

impl ListParts {
    pub fn parse(target: &Target) -> Result<Self> {
        Ok(Self {
            part_number_marker: target
                .one("part-number-marker")?
                .map(|v| decimal(v).map_err(|_| ErrorCode::InvalidArgument))
                .transpose()?
                .unwrap_or(0),
            max_parts: page_size(target, "max-parts")?,
        })
    }

    /// The page over `parts`, every stored part of the upload in ascending
    /// part number order. `key` and `upload_id` are those of the request;
    /// a key a request can name is one XML can carry.
    pub fn respond(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[PartEntry],
    ) -> Result<Response> {
        if parts
            .windows(2)
            .any(|w| w[0].part_number >= w[1].part_number)
        {
            return Err(ErrorCode::InternalError);
        }
        let max = self.max_parts as usize;
        let mut rest = parts
            .iter()
            .filter(|p| u64::from(p.part_number) > self.part_number_marker);
        let page: Vec<&PartEntry> = rest.by_ref().take(max).collect();
        let truncated = max > 0 && rest.next().is_some();
        let mut out = format!(
            "<ListPartsResult xmlns=\"{NS}\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><PartNumberMarker>{}</PartNumberMarker>",
            xml(bucket),
            field(key, false)?,
            xml(upload_id),
            self.part_number_marker
        );
        if let (true, Some(last)) = (truncated, page.last()) {
            out.push_str(&format!(
                "<NextPartNumberMarker>{}</NextPartNumberMarker>",
                last.part_number
            ));
        }
        out.push_str(&format!(
            "<MaxParts>{max}</MaxParts><IsTruncated>{truncated}</IsTruncated>"
        ));
        for p in page {
            out.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Part>",
                p.part_number,
                iso_date_ms(p.last_modified_ms)?,
                xml(&p.etag),
                p.size
            ));
        }
        out.push_str("<StorageClass>STANDARD</StorageClass></ListPartsResult>");
        Ok(xml_response(out))
    }
}
