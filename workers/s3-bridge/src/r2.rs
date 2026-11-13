//! `impl BlobStore` over R2 (adapter lane): custom metadata, ranged get.
//!
//! Walking-skeleton stub: every call answers `NotImplemented`.

use velmora_bridge::{BlobMeta, BlobStore, BridgeError, ByteSpan, Result};
use worker::Bucket;

pub struct R2Blobs {
    #[allow(dead_code)] // read once the adapter lands
    bucket: Bucket,
}

impl R2Blobs {
    pub fn new(bucket: Bucket) -> Self {
        R2Blobs { bucket }
    }
}

impl BlobStore for R2Blobs {
    async fn put(&self, _key: &str, _bytes: Vec<u8>, _meta: &BlobMeta<'_>) -> Result<()> {
        Err(BridgeError::NotImplemented("r2::put"))
    }

    async fn get(&self, _key: &str, _span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        Err(BridgeError::NotImplemented("r2::get"))
    }

    async fn head(&self, _key: &str) -> Result<Option<u64>> {
        Err(BridgeError::NotImplemented("r2::head"))
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        Err(BridgeError::NotImplemented("r2::delete"))
    }
}
