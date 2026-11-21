//! The S3 calls the gateway makes, signed with the caller's app password
//! and sent to the storage Worker over the service binding.
//!
//! Every byte and every listing comes from the storage Worker through the
//! same S3 operations any customer tool uses, so its authentication,
//! grants and limits apply to WebDAV with no second implementation.

use futures_util::future::LocalBoxFuture;

use crate::http::{header, Body, Response};
use crate::path::decode;
use crate::sigv4::{sign, Credentials, Unsigned};
use crate::time::{iso_to_ms, parse_http_date};
use crate::xml::{self, Element};

/// Why the storage Worker could not be asked, or what it refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Error {
    /// The HTTP status of the answer; `0` when there was none.
    pub status: u16,
    /// The S3 error code, when the answer had one.
    pub code: String,
}

impl S3Error {
    pub fn transport() -> Self {
        S3Error {
            status: 0,
            code: "Transport".into(),
        }
    }

    pub fn is(&self, code: &str) -> bool {
        self.code == code
    }
}

/// The runtime's way to the storage Worker.
pub trait Upstream {
    /// A body of the runtime: an upload passed through, or a download.
    type Body;

    /// Sends one request. `target` is origin-form; `headers` include
    /// `host` and the authorization. `len` is the body's length, when
    /// known (a passed-through body is sent with exactly this length).
    fn send(
        &self,
        method: &str,
        target: &str,
        headers: Vec<(String, String)>,
        body: Body<Self::Body>,
        len: Option<u64>,
    ) -> LocalBoxFuture<'_, Result<Response<Self::Body>, S3Error>>;

    /// Reads up to `max` bytes of a body; fewer only at its end, and none
    /// once it is done.
    fn read<'a>(
        &'a self,
        body: &'a mut Self::Body,
        max: usize,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>, S3Error>>;

    /// Now, in Unix milliseconds.
    fn now_ms(&self) -> i64;

    /// A fresh random UUID (version 4), lower case.
    fn uuid(&self) -> String;

    /// Waits this long.
    fn sleep(&self, ms: u64) -> LocalBoxFuture<'_, ()>;
}

/// What a HEAD says about an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub size: u64,
    /// Quoted, as sent.
    pub etag: String,
    pub modified_ms: i64,
    pub content_type: Option<String>,
}

/// One key of a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub modified_ms: i64,
}

/// One page of ListObjectsV2.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    pub entries: Vec<Entry>,
    pub prefixes: Vec<String>,
    pub next: Option<String>,
}

/// A whole listing, up to a cap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub prefixes: Vec<String>,
    /// More keys exist than the cap allowed.
    pub capped: bool,
}

/// A condition on the destination of a write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cond {
    /// `If-None-Match: *`: only if nothing is there.
    Absent,
    /// `If-Match: <etag>`: only if this is what is there.
    Is(String),
}

impl Cond {
    fn header(&self) -> (String, String) {
        match self {
            Cond::Absent => ("if-none-match".into(), "*".into()),
            Cond::Is(etag) => ("if-match".into(), etag.clone()),
        }
    }
}

/// The client for one request: one app password.
pub struct S3<'a, U: Upstream> {
    pub up: &'a U,
    pub creds: &'a Credentials,
    pub host: &'a str,
    pub region: &'a str,
}

fn local<'e>(el: &'e Element, name: &str) -> Option<&'e Element> {
    el.elements().find(|e| e.name == name)
}

fn text_of(el: &Element, name: &str) -> Option<String> {
    local(el, name).map(Element::text)
}

/// The error an answer carries: its status and its `<Code>`.
pub async fn error_of<U: Upstream>(up: &U, resp: Response<U::Body>) -> S3Error {
    let status = resp.status;
    let bytes = match resp.body {
        Body::Native(mut b) => up.read(&mut b, 64 * 1024).await.unwrap_or_default(),
        Body::Bytes(b) => b,
        Body::Shared(b) => b.to_vec(),
        Body::Empty => Vec::new(),
    };
    let code = xml::parse(&bytes)
        .ok()
        .and_then(|e| text_of(&e, "Code"))
        .unwrap_or_default();
    S3Error { status, code }
}

/// Reads a whole (small) body.
pub async fn read_all<U: Upstream>(
    up: &U,
    body: Body<U::Body>,
    max: usize,
) -> Result<Vec<u8>, S3Error> {
    match body {
        Body::Empty => Ok(Vec::new()),
        Body::Bytes(b) => Ok(b),
        Body::Shared(b) => Ok(b.to_vec()),
        Body::Native(mut b) => {
            let mut out = Vec::new();
            loop {
                let chunk = up.read(&mut b, 256 * 1024).await?;
                if chunk.is_empty() {
                    return Ok(out);
                }
                if out.len() + chunk.len() > max {
                    return Err(S3Error {
                        status: 0,
                        code: "TooLarge".into(),
                    });
                }
                out.extend_from_slice(&chunk);
            }
        }
    }
}

impl<'a, U: Upstream> S3<'a, U> {
    /// Signs and sends one request.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        headers: Vec<(String, String)>,
        body: Body<U::Body>,
        len: Option<u64>,
    ) -> Result<Response<U::Body>, S3Error> {
        let signed = sign(
            &Unsigned {
                method,
                host: self.host,
                path,
                query,
                headers: &headers,
            },
            self.creds,
            self.region,
            self.up.now_ms(),
        );
        let mut send_headers = signed.headers;
        if let Some(len) = len {
            send_headers.push(("content-length".into(), len.to_string()));
        }
        self.up
            .send(method, &signed.target, send_headers, body, len)
            .await
    }

    async fn ok_xml(&self, resp: Response<U::Body>) -> Result<Element, S3Error> {
        if !(200..300).contains(&resp.status) {
            return Err(error_of(self.up, resp).await);
        }
        let bytes = read_all(self.up, resp.body, 16 * 1024 * 1024).await?;
        xml::parse(&bytes).map_err(|_| S3Error {
            status: 502,
            code: "MalformedAnswer".into(),
        })
    }

    pub async fn list_buckets(&self) -> Result<Vec<(String, i64)>, S3Error> {
        let resp = self
            .call("GET", "/", &[], Vec::new(), Body::Empty, None)
            .await?;
        let doc = self.ok_xml(resp).await?;
        let Some(buckets) = local(&doc, "Buckets") else {
            return Ok(Vec::new());
        };
        Ok(buckets
            .elements()
            .filter(|b| b.name == "Bucket")
            .filter_map(|b| {
                let name = text_of(b, "Name")?;
                let created = text_of(b, "CreationDate")
                    .and_then(|d| iso_to_ms(&d))
                    .unwrap_or(0);
                Some((name, created))
            })
            .collect())
    }

    /// Whether the bucket exists and the key holds a grant on it.
    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool, S3Error> {
        let resp = self
            .call(
                "HEAD",
                &format!("/{bucket}"),
                &[],
                Vec::new(),
                Body::Empty,
                None,
            )
            .await?;
        match resp.status {
            200..=299 => Ok(true),
            404 => Ok(false),
            // HEAD has no body. A key with any grant may HEAD, so a 403
            // is the credential refused.
            401 | 403 => Err(S3Error {
                status: 401,
                code: "InvalidAccessKeyId".into(),
            }),
            s => Err(S3Error {
                status: s,
                code: String::new(),
            }),
        }
    }

    pub async fn head(&self, bucket: &str, key: &str) -> Result<Option<Meta>, S3Error> {
        let resp = self
            .call(
                "HEAD",
                &format!("/{bucket}/{key}"),
                &[],
                Vec::new(),
                Body::Empty,
                None,
            )
            .await?;
        match resp.status {
            200..=299 => Ok(Some(meta_of(&resp.headers))),
            404 => Ok(None),
            // See `bucket_exists`: a 403 to a HEAD is the credential.
            401 | 403 => Err(S3Error {
                status: 401,
                code: "InvalidAccessKeyId".into(),
            }),
            s => Err(S3Error {
                status: s,
                code: String::new(),
            }),
        }
    }

    /// GET passed through: the answer as the storage Worker gave it.
    pub async fn get(
        &self,
        method: &str,
        bucket: &str,
        key: &str,
        headers: Vec<(String, String)>,
    ) -> Result<Response<U::Body>, S3Error> {
        self.call(
            method,
            &format!("/{bucket}/{key}"),
            &[],
            headers,
            Body::Empty,
            None,
        )
        .await
    }

    pub async fn list_page(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        max: u32,
    ) -> Result<Page, S3Error> {
        let max = max.to_string();
        let mut query: Vec<(&str, &str)> = vec![
            ("list-type", "2"),
            ("encoding-type", "url"),
            ("prefix", prefix),
            ("max-keys", &max),
        ];
        if delimiter {
            query.push(("delimiter", "/"));
        }
        if let Some(token) = token {
            query.push(("continuation-token", token));
        }
        let resp = self
            .call(
                "GET",
                &format!("/{bucket}"),
                &query,
                Vec::new(),
                Body::Empty,
                None,
            )
            .await?;
        let doc = self.ok_xml(resp).await?;
        let encoded = text_of(&doc, "EncodingType").as_deref() == Some("url");
        let name = |raw: String| -> Result<String, S3Error> {
            if encoded {
                decode(&raw).map_err(|_| S3Error {
                    status: 502,
                    code: "MalformedAnswer".into(),
                })
            } else {
                Ok(raw)
            }
        };
        let mut page = Page::default();
        for el in doc.elements() {
            match el.name.as_str() {
                "Contents" => {
                    let key = name(text_of(el, "Key").unwrap_or_default())?;
                    page.entries.push(Entry {
                        key,
                        size: text_of(el, "Size")
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(0),
                        etag: text_of(el, "ETag").unwrap_or_default(),
                        modified_ms: text_of(el, "LastModified")
                            .and_then(|d| iso_to_ms(&d))
                            .unwrap_or(0),
                    });
                }
                "CommonPrefixes" => {
                    if let Some(p) = text_of(el, "Prefix") {
                        page.prefixes.push(name(p)?);
                    }
                }
                _ => {}
            }
        }
        if text_of(&doc, "IsTruncated").as_deref() == Some("true") {
            page.next = text_of(&doc, "NextContinuationToken").filter(|t| !t.is_empty());
        }
        Ok(page)
    }

    /// Every page of a listing, up to `cap` keys and prefixes together.
    pub async fn list_all(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: bool,
        cap: usize,
    ) -> Result<Listing, S3Error> {
        let mut out = Listing::default();
        let mut token: Option<String> = None;
        loop {
            let page = self
                .list_page(bucket, prefix, delimiter, token.as_deref(), 1000)
                .await?;
            out.entries.extend(page.entries);
            out.prefixes.extend(page.prefixes);
            if out.entries.len() + out.prefixes.len() > cap {
                out.capped = true;
                return Ok(out);
            }
            match page.next {
                Some(next) => token = Some(next),
                None => return Ok(out),
            }
        }
    }

    /// Whether any key starts with `prefix`.
    pub async fn any_under(&self, bucket: &str, prefix: &str) -> Result<bool, S3Error> {
        let page = self.list_page(bucket, prefix, false, None, 1).await?;
        Ok(!page.entries.is_empty() || !page.prefixes.is_empty())
    }

    /// PutObject. Answers the new ETag.
    #[allow(clippy::too_many_arguments)]
    pub async fn put(
        &self,
        bucket: &str,
        key: &str,
        body: Body<U::Body>,
        len: u64,
        content_type: &str,
        meta: &[(String, String)],
        cond: Option<&Cond>,
    ) -> Result<String, S3Error> {
        let mut headers = vec![("content-type".to_string(), content_type.to_string())];
        headers.extend(meta.iter().cloned());
        if let Some(c) = cond {
            headers.push(c.header());
        }
        let resp = self
            .call(
                "PUT",
                &format!("/{bucket}/{key}"),
                &[],
                headers,
                body,
                Some(len),
            )
            .await?;
        if !(200..300).contains(&resp.status) {
            return Err(error_of(self.up, resp).await);
        }
        Ok(header(&resp.headers, "etag").unwrap_or_default().to_owned())
    }

    /// CopyObject in one bucket. Answers the new ETag.
    pub async fn copy(
        &self,
        bucket: &str,
        from: &str,
        to: &str,
        cond: Option<&Cond>,
    ) -> Result<String, S3Error> {
        let mut headers = vec![(
            "x-amz-copy-source".to_string(),
            crate::path::encode(&format!("/{bucket}/{from}"), true),
        )];
        if let Some(c) = cond {
            headers.push(c.header());
        }
        let resp = self
            .call(
                "PUT",
                &format!("/{bucket}/{to}"),
                &[],
                headers,
                Body::Empty,
                Some(0),
            )
            .await?;
        let doc = self.ok_xml(resp).await?;
        if doc.name != "CopyObjectResult" {
            // A 200 that carries an error, as S3 may send on a copy.
            return Err(S3Error {
                status: 500,
                code: text_of(&doc, "Code").unwrap_or_default(),
            });
        }
        Ok(text_of(&doc, "ETag").unwrap_or_default())
    }

    /// DeleteObject; a key that is not there is no error.
    pub async fn delete(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        let resp = self
            .call(
                "DELETE",
                &format!("/{bucket}/{key}"),
                &[],
                Vec::new(),
                Body::Empty,
                None,
            )
            .await?;
        if (200..300).contains(&resp.status) || resp.status == 404 {
            Ok(())
        } else {
            Err(error_of(self.up, resp).await)
        }
    }

    /// DeleteObjects of up to 1,000 keys. Answers the keys that failed.
    pub async fn delete_many(
        &self,
        bucket: &str,
        keys: &[String],
    ) -> Result<Vec<(String, String)>, S3Error> {
        let mut body = String::from("<Delete><Quiet>true</Quiet>");
        for key in keys {
            body.push_str("<Object><Key>");
            body.push_str(&xml::escape_text(key));
            body.push_str("</Key></Object>");
        }
        body.push_str("</Delete>");
        let bytes = body.into_bytes();
        let md5 = base64_md5(&bytes);
        let len = bytes.len() as u64;
        let resp = self
            .call(
                "POST",
                &format!("/{bucket}"),
                &[("delete", "")],
                vec![
                    ("content-md5".into(), md5),
                    ("content-type".into(), "application/xml".into()),
                ],
                Body::Bytes(bytes),
                Some(len),
            )
            .await?;
        let doc = self.ok_xml(resp).await?;
        Ok(doc
            .elements()
            .filter(|e| e.name == "Error")
            .map(|e| {
                (
                    text_of(e, "Key").unwrap_or_default(),
                    text_of(e, "Code").unwrap_or_default(),
                )
            })
            .collect())
    }

    pub async fn create_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        meta: &[(String, String)],
    ) -> Result<String, S3Error> {
        let mut headers = vec![("content-type".to_string(), content_type.to_string())];
        headers.extend(meta.iter().cloned());
        let resp = self
            .call(
                "POST",
                &format!("/{bucket}/{key}"),
                &[("uploads", "")],
                headers,
                Body::Empty,
                Some(0),
            )
            .await?;
        let doc = self.ok_xml(resp).await?;
        text_of(&doc, "UploadId").ok_or(S3Error {
            status: 502,
            code: "MalformedAnswer".into(),
        })
    }

    pub async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        number: u32,
        bytes: std::rc::Rc<Vec<u8>>,
    ) -> Result<String, S3Error> {
        let n = number.to_string();
        let len = bytes.len() as u64;
        let resp = self
            .call(
                "PUT",
                &format!("/{bucket}/{key}"),
                &[("partNumber", &n), ("uploadId", upload_id)],
                Vec::new(),
                Body::Shared(bytes),
                Some(len),
            )
            .await?;
        if !(200..300).contains(&resp.status) {
            return Err(error_of(self.up, resp).await);
        }
        Ok(header(&resp.headers, "etag").unwrap_or_default().to_owned())
    }

    pub async fn complete_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[(u32, String)],
        cond: Option<&Cond>,
    ) -> Result<String, S3Error> {
        let mut body = String::from("<CompleteMultipartUpload>");
        for (n, etag) in parts {
            body.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
                xml::escape_text(etag)
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let bytes = body.into_bytes();
        let len = bytes.len() as u64;
        let mut headers = vec![("content-type".to_string(), "application/xml".to_string())];
        if let Some(c) = cond {
            headers.push(c.header());
        }
        let resp = self
            .call(
                "POST",
                &format!("/{bucket}/{key}"),
                &[("uploadId", upload_id)],
                headers,
                Body::Bytes(bytes),
                Some(len),
            )
            .await?;
        let doc = self.ok_xml(resp).await?;
        if doc.name != "CompleteMultipartUploadResult" {
            return Err(S3Error {
                status: if text_of(&doc, "Code").as_deref() == Some("PreconditionFailed") {
                    412
                } else {
                    500
                },
                code: text_of(&doc, "Code").unwrap_or_default(),
            });
        }
        Ok(text_of(&doc, "ETag").unwrap_or_default())
    }

    /// Whether the key may write to the bucket, asked without writing:
    /// an AbortMultipartUpload of an upload id that cannot exist. The
    /// storage Worker checks write permission first (every multipart call
    /// needs it) and then answers `NoSuchUpload` for an id that is not 32
    /// hex digits, before any catalogue read. A read-only key gets
    /// `AccessDenied`.
    pub async fn can_write(&self, bucket: &str, key: &str) -> Result<bool, S3Error> {
        let key = if key.is_empty() { "-" } else { key };
        let resp = self
            .call(
                "DELETE",
                &format!("/{bucket}/{key}"),
                &[("uploadId", "write-probe")],
                Vec::new(),
                Body::Empty,
                None,
            )
            .await?;
        if (200..300).contains(&resp.status) {
            return Ok(true);
        }
        let e = error_of(self.up, resp).await;
        match e.code.as_str() {
            "NoSuchUpload" => Ok(true),
            "AccessDenied" => Ok(false),
            _ => Err(e),
        }
    }

    pub async fn abort_upload(&self, bucket: &str, key: &str, upload_id: &str) {
        // Best effort: an upload left open is collected by the storage
        // Worker's own sweep of stale uploads.
        let _ = self
            .call(
                "DELETE",
                &format!("/{bucket}/{key}"),
                &[("uploadId", upload_id)],
                Vec::new(),
                Body::Empty,
                None,
            )
            .await;
    }
}

/// Base64 of the MD5 of `bytes`: a `Content-MD5` value.
fn base64_md5(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(md5::compute(bytes).0)
}

/// What a HEAD or GET answer says about the object.
pub fn meta_of(headers: &[(String, String)]) -> Meta {
    Meta {
        size: header(headers, "content-length")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
        etag: header(headers, "etag").unwrap_or_default().to_owned(),
        modified_ms: header(headers, "last-modified")
            .and_then(parse_http_date)
            .unwrap_or(0),
        content_type: header(headers, "content-type").map(str::to_owned),
    }
}
