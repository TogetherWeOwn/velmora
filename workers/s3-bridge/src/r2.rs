//! `impl BlobStore` over an R2 bucket.
//!
//! `put` stores the custom metadata (`bucket`, `extent`, `cipher-sha256`
//! in hex) and asks R2 to check the body against `cipher_sha256`, so a
//! corrupted upload is refused rather than stored. A ranged `get` returns
//! exactly the span or fails. Errors carry the operation class only.

use std::collections::HashMap;

use velmora_bridge::{BlobMeta, BlobStore, BridgeError, ByteSpan, Result};
use worker::{Bucket, Range};

/// R2 range offsets travel as JS numbers (workers-rs panics above this).
const MAX_SAFE_OFFSET: u64 = (1 << 53) - 1;

pub struct R2Blobs {
    bucket: Bucket,
}

impl R2Blobs {
    pub fn new(bucket: Bucket) -> Self {
        R2Blobs { bucket }
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

impl BlobStore for R2Blobs {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
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
                return Ok(self.head(key).await?.map(|_| Vec::new()));
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
        let bytes = body.bytes().await.map_err(blob_err("get body"))?;
        if let Some(s) = span {
            if bytes.len() as u64 != s.len {
                return Err(BridgeError::Blob("r2: short range".into()));
            }
        }
        Ok(Some(bytes))
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        let object = self.bucket.head(key).await.map_err(blob_err("head"))?;
        Ok(object.map(|o| o.size()))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.bucket.delete(key).await.map_err(blob_err("delete"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
