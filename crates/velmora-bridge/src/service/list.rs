//! ListObjectsV2, ListObjects (V1) and ListBuckets.
//!
//! The catalogue returns rows in key order, one per group when the
//! listing has a delimiter; the protocol crate folds common prefixes and
//! renders the page. Continuation tokens are tagged
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

/// Catalogue queries one page may spend. One is the rule; a listing
/// that needs more than these ends as a valid truncated page.
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
    // `list-type=2` is V2; no `list-type` is V1 (marker paging). Any
    // other value is not a listing this service knows.
    let token_key = Zeroizing::new(list_token_key(bridge.kek.active().1).mac(TOKEN_LABEL));
    let mut list_type = authed
        .target
        .query()
        .iter()
        .filter(|(k, _)| k == b"list-type")
        .map(|(_, v)| v.as_slice());
    let version = list_type.next();
    if list_type.next().is_some() {
        return Err(s3_error(ErrorCode::InvalidRequest));
    }
    let mut page = match version {
        Some(b"2") => ListObjectsV2::parse(&authed.target, &token_key[..]),
        None => ListObjectsV2::parse_v1(&authed.target),
        Some(_) => return Err(S3Response::not_implemented()),
    }
    .map_err(s3_error)?;

    let mut exhausted = false;
    let mut queries = 0;
    while page.wants_more() && queries < QUERY_BUDGET {
        queries += 1;
        // Only what the page still takes is asked for: with a delimiter
        // the catalogue returns one row per group, so this is one query
        // per page but for the rare row the page ignores.
        let wanted = page.wanted();
        let rows = bridge
            .catalog
            .list_heads(
                &bucket.id,
                &ListQuery {
                    prefix: page.prefix().to_owned(),
                    delimiter: page.delimiter().map(str::to_owned),
                    after: page.after().map(str::to_owned),
                    skip_prefix: page.skip_prefix().map(str::to_owned),
                    max_keys: wanted,
                },
            )
            .await
            .map_err(|_| internal())?;
        let complete = u32::try_from(rows.len()).is_ok_and(|n| n >= wanted);
        for e in rows {
            if !page.wants_more() {
                break;
            }
            page.push(ObjectEntry {
                key: e.key,
                size: e.size,
                etag: e.etag,
                last_modified_ms: e.last_modified.0,
            })
            .map_err(s3_error)?;
        }
        if !complete {
            exhausted = true;
            break;
        }
    }
    page.finish(exhausted, &token_key[..])
        .map(from_proto)
        .map_err(s3_error)
}
