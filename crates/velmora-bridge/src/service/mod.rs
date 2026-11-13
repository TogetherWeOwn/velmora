//! Request router: path-style S3 and `/_admin` (DESIGN §A.3–§A.6, §A.10).
//!
//! [`classify`] maps method, path shape and sub-resource query names to a
//! [`Route`]. It never decodes the bucket or key: the handlers parse and
//! authenticate the raw target themselves. Every operation outside the
//! slice is `NotImplemented`.

mod admin;
mod delete;
mod get;
mod list;
mod multipart;
mod put;

use std::rc::Rc;

use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{Method, S3Request, S3Response};

/// One routed operation. Bucket and key are raw (still percent-encoded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route<'a> {
    /// `/_admin` or `/_admin/...`; `rest` is the path after `/_admin`.
    Admin {
        rest: &'a str,
    },
    ListBuckets,
    /// Admin-only in the slice.
    CreateBucket {
        bucket: &'a str,
    },
    ListObjects {
        bucket: &'a str,
    },
    PutObject {
        bucket: &'a str,
        key: &'a str,
    },
    GetObject {
        bucket: &'a str,
        key: &'a str,
    },
    HeadObject {
        bucket: &'a str,
        key: &'a str,
    },
    DeleteObject {
        bucket: &'a str,
        key: &'a str,
    },
    CreateMultipartUpload {
        bucket: &'a str,
        key: &'a str,
    },
    UploadPart {
        bucket: &'a str,
        key: &'a str,
    },
    CompleteMultipartUpload {
        bucket: &'a str,
        key: &'a str,
    },
    AbortMultipartUpload {
        bucket: &'a str,
        key: &'a str,
    },
    /// Recognised S3 shape outside the slice (versioning, ACLs, copy, …).
    NotImplemented,
}

/// Query parameter names that select an S3 sub-resource. A request
/// carrying one the slice does not serve is `NotImplemented`, never
/// silently treated as the plain operation.
const SUBRESOURCES: &[&str] = &[
    "accelerate",
    "acl",
    "analytics",
    "attributes",
    "cors",
    "delete",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "legal-hold",
    "lifecycle",
    "location",
    "logging",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "partNumber",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "restore",
    "retention",
    "select",
    "session",
    "tagging",
    "torrent",
    "uploadId",
    "uploads",
    "versionId",
    "versioning",
    "versions",
    "website",
];

fn query_names(query: &str) -> impl Iterator<Item = &str> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').map_or(p, |(n, _)| n))
}

/// Classifies an origin-form target (`/path?query`).
pub fn classify<'a>(method: &Method, raw_target: &'a str) -> Route<'a> {
    let (path, query) = raw_target.split_once('?').unwrap_or((raw_target, ""));
    if path == "/_admin" || path.starts_with("/_admin/") {
        return Route::Admin {
            rest: &path["/_admin".len()..],
        };
    }
    let Some(path) = path.strip_prefix('/') else {
        return Route::NotImplemented;
    };
    let mut sub: Vec<&str> = query_names(query)
        .filter(|n| SUBRESOURCES.contains(n))
        .collect();
    sub.sort_unstable();
    sub.dedup();

    let (bucket, key) = match path.split_once('/') {
        Some((b, k)) if !k.is_empty() => (b, Some(k)),
        Some((b, _)) => (b, None),
        None => (path, None),
    };

    if bucket.is_empty() {
        return match (method, sub.as_slice()) {
            (Method::Get, []) => Route::ListBuckets,
            _ => Route::NotImplemented,
        };
    }

    let Some(key) = key else {
        return match (method, sub.as_slice()) {
            (Method::Get, []) => Route::ListObjects { bucket },
            (Method::Put, []) => Route::CreateBucket { bucket },
            _ => Route::NotImplemented,
        };
    };

    match (method, sub.as_slice()) {
        (Method::Put, []) => Route::PutObject { bucket, key },
        (Method::Put, ["partNumber", "uploadId"]) => Route::UploadPart { bucket, key },
        (Method::Get, []) => Route::GetObject { bucket, key },
        (Method::Head, []) => Route::HeadObject { bucket, key },
        (Method::Delete, []) => Route::DeleteObject { bucket, key },
        (Method::Delete, ["uploadId"]) => Route::AbortMultipartUpload { bucket, key },
        (Method::Post, ["uploads"]) => Route::CreateMultipartUpload { bucket, key },
        (Method::Post, ["uploadId"]) => Route::CompleteMultipartUpload { bucket, key },
        _ => Route::NotImplemented,
    }
}

impl<C, B, N, J, K, T> Bridge<C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    /// Entry point for every fetch: S3 and `/_admin`.
    pub async fn handle(self: Rc<Self>, req: S3Request) -> S3Response {
        let target = req.raw_target.clone();
        match classify(&req.method, &target) {
            Route::Admin { rest } => admin::handle(&self, req, rest).await,
            Route::ListBuckets => list::list_buckets(&self, req).await,
            Route::CreateBucket { bucket } => admin::create_bucket_s3(&self, req, bucket).await,
            Route::ListObjects { bucket } => list::list_objects(&self, req, bucket).await,
            Route::PutObject { bucket, key } => put::put_object(&self, req, bucket, key).await,
            Route::GetObject { bucket, key } => get::get_object(&self, req, bucket, key).await,
            Route::HeadObject { bucket, key } => get::head_object(&self, req, bucket, key).await,
            Route::DeleteObject { bucket, key } => {
                delete::delete_object(&self, req, bucket, key).await
            }
            Route::CreateMultipartUpload { bucket, key } => {
                multipart::create(&self, req, bucket, key).await
            }
            Route::UploadPart { bucket, key } => {
                multipart::upload_part(&self, req, bucket, key).await
            }
            Route::CompleteMultipartUpload { bucket, key } => {
                multipart::complete(&self, req, bucket, key).await
            }
            Route::AbortMultipartUpload { bucket, key } => {
                multipart::abort(&self, req, bucket, key).await
            }
            Route::NotImplemented => S3Response::not_implemented(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, Route};
    use crate::types::Method;

    #[test]
    fn route_table() {
        use Method::*;
        let cases: &[(Method, &str, Route<'_>)] = &[
            (Get, "/", Route::ListBuckets),
            (Get, "/_admin/status", Route::Admin { rest: "/status" }),
            (Post, "/_admin", Route::Admin { rest: "" }),
            (
                Get,
                "/_adminx/k",
                Route::GetObject {
                    bucket: "_adminx",
                    key: "k",
                },
            ),
            (Get, "/b", Route::ListObjects { bucket: "b" }),
            (
                Get,
                "/b/?list-type=2&prefix=a%2F",
                Route::ListObjects { bucket: "b" },
            ),
            (Put, "/b", Route::CreateBucket { bucket: "b" }),
            (
                Put,
                "/b/a/k",
                Route::PutObject {
                    bucket: "b",
                    key: "a/k",
                },
            ),
            (
                Get,
                "/b/a/../k",
                Route::GetObject {
                    bucket: "b",
                    key: "a/../k",
                },
            ),
            (
                Head,
                "/b/k%2Fx",
                Route::HeadObject {
                    bucket: "b",
                    key: "k%2Fx",
                },
            ),
            (
                Get,
                "/b//double",
                Route::GetObject {
                    bucket: "b",
                    key: "/double",
                },
            ),
            (
                Delete,
                "/b/k",
                Route::DeleteObject {
                    bucket: "b",
                    key: "k",
                },
            ),
            (
                Post,
                "/b/k?uploads",
                Route::CreateMultipartUpload {
                    bucket: "b",
                    key: "k",
                },
            ),
            (
                Put,
                "/b/k?partNumber=1&uploadId=u",
                Route::UploadPart {
                    bucket: "b",
                    key: "k",
                },
            ),
            (
                Put,
                "/b/k?uploadId=u&partNumber=1",
                Route::UploadPart {
                    bucket: "b",
                    key: "k",
                },
            ),
            (
                Post,
                "/b/k?uploadId=u",
                Route::CompleteMultipartUpload {
                    bucket: "b",
                    key: "k",
                },
            ),
            (
                Delete,
                "/b/k?uploadId=u",
                Route::AbortMultipartUpload {
                    bucket: "b",
                    key: "k",
                },
            ),
            (
                Get,
                "/b/k?x-id=GetObject",
                Route::GetObject {
                    bucket: "b",
                    key: "k",
                },
            ),
            // Outside the slice: never silently the plain operation.
            (Get, "/b/k?acl", Route::NotImplemented),
            (Get, "/b/k?versionId=1", Route::NotImplemented),
            (Get, "/b?versions", Route::NotImplemented),
            (Get, "/b?uploads", Route::NotImplemented),
            (Get, "/b/k?uploadId=u", Route::NotImplemented),
            (Post, "/b?delete", Route::NotImplemented),
            (Put, "/b/k?tagging", Route::NotImplemented),
            (Put, "/b/k?uploadId=u", Route::NotImplemented),
            (Post, "/b/k", Route::NotImplemented),
            (Delete, "/b", Route::NotImplemented),
            (Head, "/b", Route::NotImplemented),
            (Other("PATCH".into()), "/b/k", Route::NotImplemented),
            (Get, "b/k", Route::NotImplemented),
        ];
        for (method, target, want) in cases {
            assert_eq!(&classify(method, target), want, "{method:?} {target}");
        }
    }
}
