//! Bucket-level calls clients make with an access key: HeadBucket,
//! GetBucketLocation, and a SigV4-signed CreateBucket or DeleteBucket.
//!
//! All four authenticate exactly like an object request. A bucket that
//! does not exist and one the key holds no grant on are indistinguishable
//! (`AccessDenied`), so none of them tells a caller which names exist.
//! None of them changes state: buckets are created and deleted with the
//! admin bearer token.

use std::rc::Rc;

use velmora_s3_proto::ErrorCode;

use super::common::{authenticate, internal, s3_error};
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

/// `DELETE /<bucket>` signed with an access key. Deleting a bucket is an
/// admin action (the admin bearer token), so this never changes state.
/// A key that may write the bucket learns `BucketNotEmpty` while the
/// bucket could not be deleted anyway, as S3 clients expect of a bucket
/// that still holds objects; otherwise the answer is `AccessDenied`.
pub(super) async fn delete_bucket_signed<
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
    // `authenticate` verifies the signature and, for DELETE, requires a
    // read-write grant on an existing bucket.
    let authed = match authenticate(bridge, &req).await {
        Ok(authed) => authed,
        Err(resp) => return resp,
    };
    let Some(bucket) = &authed.bucket else {
        return s3_error(ErrorCode::InvalidRequest);
    };
    match bridge.catalog.bucket_in_use(&bucket.id).await {
        Ok(true) => bucket_not_empty(),
        Ok(false) => S3Response::error(
            403,
            "AccessDenied",
            "Only the administrator can delete a bucket.",
        ),
        Err(_) => internal(),
    }
}

/// `409 BucketNotEmpty`. A bucket goes only while nothing of it is on
/// record, see [`Catalog::delete_bucket`].
pub(super) fn bucket_not_empty() -> S3Response {
    S3Response::error(
        409,
        "BucketNotEmpty",
        "The bucket you tried to delete is not empty, or has held data: a bucket that ever \
         stored an object or opened a multipart upload is kept.",
    )
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
