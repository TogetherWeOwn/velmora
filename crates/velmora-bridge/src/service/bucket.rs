//! Bucket-level probes clients make before they touch objects:
//! HeadBucket, GetBucketLocation and a SigV4-signed CreateBucket.
//!
//! All three authenticate exactly like an object request. A bucket that
//! does not exist and one the key holds no grant on are indistinguishable
//! (`AccessDenied`), so none of them tells a caller which names exist.
//! None of them changes state.

use std::rc::Rc;

use super::common::authenticate;
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{RespBody, S3Request, S3Response};

/// `HEAD /bucket`: 200 for a key with a grant on the bucket (restic's
/// `BucketExists`, rclone's bucket check).
pub(super) async fn head_bucket<
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
    match authenticate(bridge, &req).await {
        Ok(_) => S3Response {
            status: 200,
            headers: vec![("x-amz-bucket-region".into(), bridge.cfg.region.clone())],
            body: RespBody::Empty,
        },
        // HEAD answers carry no body.
        Err(resp) => S3Response {
            body: RespBody::Empty,
            ..resp
        },
    }
}

/// `GET /bucket?location`: the configured region.
pub(super) async fn get_bucket_location<
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
    if let Err(resp) = authenticate(bridge, &req).await {
        return resp;
    }
    // The region is validated at config load (ASCII letters, digits, `-`),
    // so it needs no XML escaping.
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}</LocationConstraint>",
        bridge.cfg.region
    );
    S3Response {
        status: 200,
        headers: vec![("content-type".into(), "application/xml".into())],
        body: RespBody::Bytes(body.into_bytes()),
    }
}

/// `PUT /bucket` signed with an access key. Keys cannot create buckets
/// (that stays an admin call), but clients such as rclone create the
/// bucket before every upload and accept `BucketAlreadyOwnedByYou`. A key
/// with write on an existing bucket gets exactly that; anything else is
/// `AccessDenied`. The request body (a `CreateBucketConfiguration`) is
/// never read.
pub(super) async fn create_bucket_signed<
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
    // `authenticate` verifies the signature and, for PUT, requires a
    // read-write grant on an existing bucket.
    match authenticate(bridge, &req).await {
        Ok(_) => S3Response::error(
            409,
            "BucketAlreadyOwnedByYou",
            "The bucket you tried to create already exists, and you own it.",
        ),
        Err(resp) => resp,
    }
}

/// `true` when the request carries SigV4 credentials (header or presigned
/// query) rather than the admin bearer.
pub(super) fn is_sigv4(req: &S3Request) -> bool {
    let header = req.headers.iter().any(|(n, v)| {
        n.eq_ignore_ascii_case("authorization") && v.trim_start().starts_with("AWS4-HMAC-SHA256")
    });
    let presigned = req
        .raw_target
        .split_once('?')
        .and_then(|(_, q)| super::query_names(q))
        .is_some_and(|names| names.iter().any(|n| n == b"X-Amz-Algorithm"));
    header || presigned
}
