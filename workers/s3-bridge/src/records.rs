//! [`RecordStore`] over an R2 bucket: the put-once store of the control
//! records (`m/` of the safety bucket, and the key buckets).
//!
//! - `put_if_absent` is one R2 put with the conditional header
//!   `If-None-Match: *`. R2 evaluates it atomically against the committed
//!   state of the bucket, and of competing conditional puts of an absent
//!   name at most one succeeds while its object exists (R2 consistency
//!   model, "Conditional writes"). A failed condition answers `null`:
//!   `Ok(false)`, and the stored object is left as it was. Any other
//!   failure is an error, which says nothing about whether the bytes were
//!   stored; the caller reads the name back (the port's rule).
//! - A record above [`MAX_RECORD_BYTES`] is refused before its put, and
//!   one found above it is an error, never read: no record is stored
//!   that a get could not read back. The largest records are the key
//!   checkpoints (every subject a tenant has had, about 0.5 KiB each).
//! - `list` pages on R2's `truncated` and `cursor`, at most
//!   [`R2_LIST_MAX`] names a page, until it has `limit` names or R2 has
//!   no more. A page that says "more" and gives no
//!   cursor is an error, never the end: a short listing would read as
//!   the whole one.
//! - `exists` is a head.
//!
//! Errors are `BridgeError::Blob` with a class only: no name, no bytes,
//! no R2 message.
//!
//! No binding uses this yet: the key chain, the tenant chain and the key
//! buckets are wired by later packages.

use velmora_bridge::records::RecordStore;
use velmora_bridge::{BridgeError, Result};
use worker::js_sys::{Object, Reflect, Uint8Array};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::worker_sys::R2Bucket as EdgeBucket;
use worker::{Bucket, Headers};

/// The largest record that is stored or read: 32 MiB, far above a key
/// checkpoint of 10,000 subjects (about 5 MiB) and far below the memory
/// of an isolate (128 MB).
pub const MAX_RECORD_BYTES: u64 = 32 << 20;

/// The most names R2 answers in one page (it refuses a larger limit).
pub const R2_LIST_MAX: u32 = 1000;

/// A bucket as a store of put-once records.
pub struct R2Records {
    bucket: Bucket,
}

impl R2Records {
    pub fn new(bucket: Bucket) -> Self {
        R2Records { bucket }
    }
}

fn err(class: &'static str) -> impl Fn(worker::Error) -> BridgeError {
    move |_| BridgeError::Blob(format!("records: {class}"))
}

fn js_err(class: &'static str) -> impl Fn(JsValue) -> BridgeError {
    move |_| BridgeError::Blob(format!("records: {class}"))
}

/// The options of a put that stores only where nothing is stored:
/// `{ onlyIf: Headers { "If-None-Match": "*" } }`.
fn only_if_absent() -> Result<JsValue> {
    let headers = Headers::new();
    headers
        .set("If-None-Match", "*")
        .map_err(err("put options"))?;
    let options = Object::new();
    Reflect::set(&options, &JsValue::from_str("onlyIf"), headers.as_ref())
        .map_err(js_err("put options"))?;
    Ok(options.into())
}

impl RecordStore for R2Records {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(BridgeError::Blob("records: record too large".into()));
        }
        let edge: &EdgeBucket = self.bucket.as_ref().unchecked_ref();
        let body: JsValue = Uint8Array::from(bytes.as_slice()).into();
        let put = edge
            .put(name.to_owned(), body, only_if_absent()?)
            .map_err(js_err("put"))?;
        let stored = JsFuture::from(put).await.map_err(js_err("put"))?;
        // `null`: the condition failed, so an object is there already.
        Ok(!stored.is_null() && !stored.is_undefined())
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(object) = self.bucket.get(name).execute().await.map_err(err("get"))? else {
            return Ok(None);
        };
        if object.size() > MAX_RECORD_BYTES {
            return Err(BridgeError::Blob("records: record too large".into()));
        }
        let body = object
            .body()
            .ok_or_else(|| BridgeError::Blob("records: get returned no body".into()))?;
        body.bytes().await.map(Some).map_err(err("get body"))
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let mut cursor: Option<String> = None;
        while (names.len() as u64) < u64::from(limit) {
            let want = (limit - names.len() as u32).min(R2_LIST_MAX);
            let mut req = self.bucket.list().prefix(prefix).limit(want);
            req = match &cursor {
                Some(c) => req.cursor(c.clone()),
                None => req.start_after(start_after),
            };
            let page = req.execute().await.map_err(err("list"))?;
            names.extend(page.objects().iter().map(worker::Object::key));
            cursor = match next_cursor(page.truncated(), page.cursor())? {
                Some(c) => Some(c),
                None => break,
            };
        }
        // R2 answers at most `want` per page; keep the port's bound even so.
        names.truncate(limit as usize);
        Ok(names)
    }

    async fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.bucket.head(name).await.map_err(err("head"))?.is_some())
    }
}

/// Where a listing goes on after a page: `Some` = ask again from this
/// cursor, `None` = the last page. A page that says "more to come" and
/// gives no cursor is an error.
fn next_cursor(truncated: bool, cursor: Option<String>) -> Result<Option<String>> {
    match (truncated, cursor) {
        (true, Some(c)) => Ok(Some(c)),
        (true, None) => Err(BridgeError::Blob(
            "records: list: more to come and no cursor".into(),
        )),
        (false, _) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_with_more_and_no_cursor_is_an_error() {
        assert_eq!(
            next_cursor(true, Some("c".into())).unwrap(),
            Some("c".into())
        );
        assert_eq!(next_cursor(false, None).unwrap(), None);
        assert_eq!(next_cursor(false, Some("stale".into())).unwrap(), None);
        assert!(matches!(next_cursor(true, None), Err(BridgeError::Blob(_))));
    }
}
