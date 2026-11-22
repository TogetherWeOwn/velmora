//! `impl BlobStore` over an R2 bucket.
//!
//! `put` stores the custom metadata (`bucket`, `extent`, `cipher-sha256`
//! in hex) and asks R2 to check the body against `cipher_sha256`, so a
//! corrupted upload is refused rather than stored. A ranged `get` returns
//! exactly the span or fails. Errors carry the operation class only.
//!
//! Dev only: `DEV_TOMBSTONE_PUT_DELAY_MS` makes every put of a tombstone
//! record to the safety store wait that long first (a slow store), so the
//! local acceptance run can make a DeleteObjects outlast a client's read
//! timeout. Outside `ENVIRONMENT=dev` the variable is ignored.

use std::collections::HashMap;

use futures_util::StreamExt;

use velmora_bridge::recovery::{
    is_protected_key, record_name, RecordKind, Unpublished, ERR_RECORD_DELETE,
};
use velmora_bridge::{BlobEntry, BlobMeta, BlobStore, BridgeError, ByteSpan, Result};
use worker::{Bucket, Range};

/// R2 range offsets travel as JS numbers (workers-rs panics above this).
const MAX_SAFE_OFFSET: u64 = (1 << 53) - 1;

/// The most a `get` reserves up front; a larger body grows as it arrives.
const MAX_PRESIZE: u64 = 32 * 1024 * 1024;

pub struct R2Blobs {
    bucket: Bucket,
    /// Dev only: the wait before a tombstone put, in milliseconds.
    tombstone_delay_ms: u32,
}

/// Name of the dev-only tombstone put delay variable.
pub const DEV_TOMBSTONE_PUT_DELAY_MS: &str = "DEV_TOMBSTONE_PUT_DELAY_MS";

/// Most a tombstone put may be held back.
const MAX_TOMBSTONE_DELAY_MS: u32 = 60_000;

/// `dev` is the validated environment. Outside dev the value is never
/// read (0). In dev, absent or empty is 0, and anything other than an
/// integer up to [`MAX_TOMBSTONE_DELAY_MS`] is refused.
pub fn tombstone_delay_from_var(dev: bool, raw: Option<&str>) -> std::result::Result<u32, String> {
    if !dev {
        return Ok(0);
    }
    match raw.map(str::trim) {
        None | Some("") => Ok(0),
        Some(v) => v
            .parse::<u32>()
            .ok()
            .filter(|ms| *ms <= MAX_TOMBSTONE_DELAY_MS)
            .ok_or_else(|| format!("invalid {DEV_TOMBSTONE_PUT_DELAY_MS}")),
    }
}

impl R2Blobs {
    pub fn new(bucket: Bucket) -> Self {
        R2Blobs {
            bucket,
            tombstone_delay_ms: 0,
        }
    }

    /// Dev only (see the module docs).
    pub fn with_tombstone_delay(mut self, ms: u32) -> Self {
        self.tombstone_delay_ms = ms;
        self
    }
}

fn blob_err(class: &'static str) -> impl Fn(worker::Error) -> BridgeError {
    move |_| BridgeError::Blob(format!("r2: {class} failed"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn custom_metadata(meta: &BlobMeta<'_>) -> HashMap<String, String> {
    HashMap::from([
        ("bucket".to_string(), meta.bucket.as_str().to_string()),
        ("extent".to_string(), meta.extent.as_str().to_string()),
        ("cipher-sha256".to_string(), hex(meta.cipher_sha256)),
    ])
}

/// The R2 range for a non-empty span; refuses offsets R2 cannot address.
fn r2_range(span: ByteSpan) -> Result<Range> {
    if span
        .start
        .checked_add(span.len)
        .is_none_or(|end| end > MAX_SAFE_OFFSET)
    {
        return Err(BridgeError::Blob("r2: range out of bounds".into()));
    }
    Ok(Range::OffsetWithLength {
        offset: span.start,
        length: span.len,
    })
}

/// An empty span is valid up to and including the end of the object.
fn empty_span(span: ByteSpan, size: u64) -> Result<Vec<u8>> {
    if span.start > size {
        return Err(BridgeError::Blob("r2: range past end".into()));
    }
    Ok(Vec::new())
}

impl BlobStore for R2Blobs {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        if self.tombstone_delay_ms > 0
            && record_name(key).is_some_and(|n| n.kind == RecordKind::Tombstone)
        {
            let wait = std::time::Duration::from_millis(u64::from(self.tombstone_delay_ms));
            worker::Delay::from(wait).await;
        }
        self.bucket
            .put(key, bytes)
            .custom_metadata(custom_metadata(meta))
            .sha256(meta.cipher_sha256.to_vec())
            .execute()
            .await
            .map_err(blob_err("put"))?;
        Ok(())
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        let mut req = self.bucket.get(key);
        match span {
            // R2 has no empty range: answer from a head.
            Some(s) if s.len == 0 => {
                return match self.head(key).await? {
                    None => Ok(None),
                    Some(size) => empty_span(s, size).map(Some),
                };
            }
            Some(s) => req = req.range(r2_range(s)?),
            None => {}
        }
        let Some(object) = req.execute().await.map_err(blob_err("get"))? else {
            return Ok(None);
        };
        let body = object
            .body()
            .ok_or_else(|| BridgeError::Blob("r2: get returned no body".into()))?;
        // Read the body chunk by chunk into one buffer of the final size.
        // Taking it as a single array buffer and copying that would hold
        // the object twice, and the second copy is outside the byte budget.
        let expected = span.map_or_else(|| object.size(), |s| s.len);
        let mut bytes = Vec::with_capacity(expected.min(MAX_PRESIZE) as usize);
        let mut stream = body.stream().map_err(blob_err("get body"))?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(blob_err("get body"))?;
            if (bytes.len() + chunk.len()) as u64 > expected {
                return Err(BridgeError::Blob("r2: long body".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() as u64 != expected {
            return Err(BridgeError::Blob(
                if span.is_some() {
                    "r2: short range"
                } else {
                    "r2: short body"
                }
                .into(),
            ));
        }
        Ok(Some(bytes))
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        let object = self.bucket.head(key).await.map_err(blob_err("head"))?;
        Ok(object.map(|o| o.size()))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        if is_protected_key(key) {
            return Err(ERR_RECORD_DELETE);
        }
        self.bucket.delete(key).await.map_err(blob_err("delete"))
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.bucket
            .delete(refused.key())
            .await
            .map_err(blob_err("delete"))
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut cursor: Option<String> = None;
        // R2 may return a short page that is not the last one.
        while (keys.len() as u64) < u64::from(limit) {
            let want = limit - keys.len() as u32;
            let mut req = self.bucket.list().prefix(prefix).limit(want);
            req = match &cursor {
                Some(c) => req.cursor(c.clone()),
                None => req.start_after(start_after),
            };
            let page = req.execute().await.map_err(blob_err("list"))?;
            keys.extend(page.objects().iter().map(worker::Object::key));
            cursor = match next_cursor(page.truncated(), page.cursor())? {
                Some(c) => Some(c),
                None => break,
            };
        }
        Ok(keys)
    }

    /// Sizes and MD5s from the listing itself, with no read per key:
    /// R2's etag of an object written by one put is the MD5 of its
    /// bytes. As in the default, only an empty answer is the end: a
    /// limit of 0 is read as 1, and a page that says "more" and gives
    /// no cursor is an error.
    async fn list_entries(
        &self,
        prefix: &str,
        start_after: &str,
        limit: u32,
    ) -> Result<Vec<BlobEntry>> {
        let limit = limit.max(1);
        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;
        while (entries.len() as u64) < u64::from(limit) {
            let want = limit - entries.len() as u32;
            let mut req = self.bucket.list().prefix(prefix).limit(want);
            req = match &cursor {
                Some(c) => req.cursor(c.clone()),
                None => req.start_after(start_after),
            };
            let page = req.execute().await.map_err(blob_err("list"))?;
            entries.extend(page.objects().iter().map(|o| BlobEntry {
                key: o.key(),
                size: o.size(),
                md5: o.etag(),
            }));
            cursor = match next_cursor(page.truncated(), page.cursor())? {
                Some(c) => Some(c),
                None => break,
            };
        }
        Ok(entries)
    }
}

/// Where a listing goes on after a page: `Some` = ask again from this
/// cursor, `None` = the last page. A page that says "more to come"
/// (`truncated`) and gives no cursor is an error, never the end: a
/// listing that stopped there would be silently incomplete.
fn next_cursor(truncated: bool, cursor: Option<String>) -> Result<Option<String>> {
    match (truncated, cursor) {
        (true, Some(c)) => Ok(Some(c)),
        (true, None) => Err(BridgeError::Blob("list: more to come and no cursor".into())),
        (false, _) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_with_more_and_no_cursor_is_an_error() {
        assert_eq!(
            next_cursor(true, Some("c1".into())).unwrap(),
            Some("c1".into())
        );
        assert_eq!(next_cursor(false, None).unwrap(), None);
        assert_eq!(next_cursor(false, Some("stale".into())).unwrap(), None);
        assert!(matches!(next_cursor(true, None), Err(BridgeError::Blob(_))));
    }
    use velmora_bridge::{BucketId, ExtentId};

    #[test]
    fn metadata_names_bucket_extent_and_digest() {
        let bucket = BucketId::new("b_0123456789abcdef");
        let extent = ExtentId::new("e_00112233445566778899aabbccddeeff");
        let digest = [0xab; 32];
        let m = custom_metadata(&BlobMeta {
            bucket: &bucket,
            extent: &extent,
            cipher_sha256: &digest,
        });
        assert_eq!(m.len(), 3);
        assert_eq!(m["bucket"], "b_0123456789abcdef");
        assert_eq!(m["extent"], extent.as_str());
        assert_eq!(m["cipher-sha256"], "ab".repeat(32));
    }

    #[test]
    fn range_is_exact_and_bounded() {
        match r2_range(ByteSpan { start: 10, len: 5 }).unwrap() {
            Range::OffsetWithLength { offset, length } => assert_eq!((offset, length), (10, 5)),
            _ => panic!("wrong range kind"),
        }
        let empty = |start| empty_span(ByteSpan { start, len: 0 }, 10);
        assert!(empty(0).is_ok() && empty(10).is_ok() && empty(11).is_err());
        assert!(r2_range(ByteSpan {
            start: MAX_SAFE_OFFSET,
            len: 1
        })
        .is_err());
        assert!(r2_range(ByteSpan {
            start: u64::MAX,
            len: 1
        })
        .is_err());
    }
}
