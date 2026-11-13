//! ListObjectsV2 and ListBuckets.
//!
//! The catalogue returns raw rows in key order; the protocol crate folds
//! common prefixes and renders the page. Continuation tokens are tagged
//! with a key derived from the active KEK, so a token is only good for
//! the listing that issued it.

use std::rc::Rc;

use velmora_s3_proto::listing::{list_buckets_response, BucketEntry, ListObjectsV2, ObjectEntry};
use velmora_s3_proto::ErrorCode;
use zeroize::Zeroizing;

use super::common::{authenticate, from_proto, internal, s3_error};
use crate::crypto::list_token_key;
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{ListQuery, S3Request, S3Response};

/// Rows asked of the catalogue per query.
const BATCH: u32 = 1000;
/// Catalogue queries one page may spend. A listing that needs more ends
/// as a valid truncated page.
const QUERY_BUDGET: u32 = 200;
/// Domain label of the token-tag key handed to the protocol crate.
const TOKEN_LABEL: &[u8] = b"velmora/list-objects-v2/token-key/v1";

pub(super) async fn list_buckets<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
) -> S3Response {
    match buckets(bridge, req).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn buckets<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Result<S3Response, S3Response> {
    let authed = authenticate(bridge, &req).await?;
    let granted = bridge
        .catalog
        .buckets_for(&authed.verified.access_key)
        .await
        .map_err(|_| internal())?;
    let mut entries: Vec<BucketEntry> = granted
        .into_iter()
        .map(|b| BucketEntry {
            name: b.name,
            created_ms: b.created_at.0,
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    list_buckets_response(&entries)
        .map(from_proto)
        .map_err(s3_error)
}

pub(super) async fn list_objects<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
) -> S3Response {
    match objects(bridge, req).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn objects<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Result<S3Response, S3Response> {
    let authed = authenticate(bridge, &req).await?;
    let Some(bucket) = &authed.bucket else {
        return Err(s3_error(ErrorCode::InvalidRequest));
    };
    // Only the V2 listing is served; V1 has different paging fields.
    let v2 = authed
        .target
        .query()
        .iter()
        .any(|(k, v)| k == b"list-type" && v == b"2");
    if !v2 {
        return Err(S3Response::not_implemented());
    }
    let token_key = Zeroizing::new(list_token_key(bridge.kek.active().1).mac(TOKEN_LABEL));
    let mut page = ListObjectsV2::parse(&authed.target, &token_key[..]).map_err(s3_error)?;

    let mut exhausted = false;
    let mut queries = 0;
    while page.wants_more() && queries < QUERY_BUDGET {
        queries += 1;
        let rows = bridge
            .catalog
            .list(
                &bucket.id,
                &ListQuery {
                    prefix: page.prefix().to_owned(),
                    delimiter: None,
                    after: page.after().map(str::to_owned),
                    skip_prefix: page.skip_prefix().map(str::to_owned),
                    max_keys: BATCH,
                },
            )
            .await
            .map_err(|_| internal())?;
        let more_rows = rows.next.is_some();
        let mut consumed_all = true;
        let mut entries = rows.entries.into_iter().peekable();
        while let Some(e) = entries.next() {
            page.push(ObjectEntry {
                key: e.key,
                size: e.size,
                etag: e.etag,
                last_modified_ms: e.last_modified.0,
            })
            .map_err(s3_error)?;
            let Some(next) = entries.peek() else { break };
            // Stop at a full page, and after a common prefix whose other
            // keys follow: the next query seeks past them.
            if !page.wants_more() || page.skip_prefix().is_some_and(|p| next.key.starts_with(p)) {
                consumed_all = false;
                break;
            }
        }
        if consumed_all && !more_rows {
            exhausted = true;
            break;
        }
    }
    page.finish(exhausted, &token_key[..])
        .map(from_proto)
        .map_err(s3_error)
}
