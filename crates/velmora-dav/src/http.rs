//! Requests, responses and bodies, independent of the runtime.
//!
//! `B` is the runtime's own body (a JavaScript stream in the Worker, a
//! buffer in tests). A body the gateway passes through, such as a
//! download or an upload, stays a `B` from end to end and is never read
//! by the gateway.

/// A body: nothing, bytes the gateway made, or a body of the runtime.
pub enum Body<B> {
    Empty,
    Bytes(Vec<u8>),
    Native(B),
}

impl<B> Body<B> {
    pub fn is_empty_body(&self) -> bool {
        match self {
            Body::Empty => true,
            Body::Bytes(b) => b.is_empty(),
            Body::Native(_) => false,
        }
    }
}

/// One request from a WebDAV client.
pub struct Request<B> {
    pub method: String,
    /// The URL path as sent, still percent-encoded.
    pub path: String,
    /// Header names in lower case; values as sent.
    pub headers: Vec<(String, String)>,
    pub body: Body<B>,
}

impl<B> Request<B> {
    /// The first header of this (lower-case) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}

/// One response, to the client or from the storage Worker.
pub struct Response<B> {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Body<B>,
}

impl<B> Response<B> {
    pub fn new(status: u16) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: Body::Empty,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.set_header(name, value);
        self
    }

    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.to_ascii_lowercase(), value.into()));
    }

    pub fn with_bytes(mut self, content_type: &str, bytes: Vec<u8>) -> Self {
        self.set_header("content-type", content_type);
        self.set_header("content-length", bytes.len().to_string());
        self.body = Body::Bytes(bytes);
        self
    }
}

/// The first header of this name, compared without case.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Text of an HTTP status line.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        207 => "Multi-Status",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        423 => "Locked",
        424 => "Failed Dependency",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Unknown",
    }
}
