//! Request router: path-style S3 and `/_admin` (DESIGN §A.3–§A.6, §A.10).
//!
//! [`classify`] maps method, path shape and sub-resource query names to a
//! [`Route`]. It never decodes the bucket or key: the handlers parse and
//! authenticate the raw target themselves. Every operation that is not
//! served is `NotImplemented`.

mod admin;
mod bucket;
mod common;
mod copy;
mod delete;
mod get;
pub use get::{INTERRUPTED_RETRIES, PIECE_WAIT_MS, READ_STAMP_MS};
mod list;
mod multipart;
mod multipart_list;
mod put;
mod slices;

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
    /// Created with the admin bearer. Signed with an access key it only
    /// answers `BucketAlreadyOwnedByYou` for a bucket the key may write.
    CreateBucket {
        bucket: &'a str,
    },
    /// Deleted with the admin bearer, and only while nothing of the
    /// bucket is on record. Signed with an access key it never deletes.
    DeleteBucket {
        bucket: &'a str,
    },
    HeadBucket {
        bucket: &'a str,
    },
    GetBucketLocation {
        bucket: &'a str,
    },
    ListObjects {
        bucket: &'a str,
    },
    /// `POST /<bucket>?delete`.
    DeleteObjects {
        bucket: &'a str,
    },
    /// `GET /<bucket>?uploads`.
    ListMultipartUploads {
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
    /// `GET /<bucket>/<key>?uploadId=`.
    ListParts {
        bucket: &'a str,
        key: &'a str,
    },
    /// Recognised S3 shape outside the slice (versioning, ACLs, …).
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

/// Percent-decodes a query parameter name the way the SigV4 target parser
/// does (`%XX` in either case, `+` literal). `None` on a malformed escape.
fn decode_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len());
    let mut bytes = name.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = (bytes.next()? as char).to_digit(16)?;
            let lo = (bytes.next()? as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
        } else {
            out.push(b);
        }
    }
    Some(out)
}

/// Decoded query parameter names; `None` if any name is malformed.
pub(crate) fn query_names(query: &str) -> Option<Vec<Vec<u8>>> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| decode_name(p.split_once('=').map_or(p, |(n, _)| n)))
        .collect()
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
    // Names are compared decoded and exactly (case-sensitive), as the
    // handlers' target parser will see them: `?%75ploads` is `uploads`.
    let Some(names) = query_names(query) else {
        return Route::NotImplemented;
    };
    let mut sub: Vec<&str> = SUBRESOURCES
        .iter()
        .copied()
        .filter(|s| names.iter().any(|n| n.as_slice() == s.as_bytes()))
        .collect();
    sub.sort_unstable();
    sub.dedup();

    let (bucket, key) = match path.split_once('/') {
        Some((b, k)) if !k.is_empty() => (b, Some(k)),
        Some((b, _)) => (b, None),
        None => (path, None),
    };

    if bucket.is_empty() {
        // Only the bare service root is ListBuckets; `//k` is not.
        return match (method, sub.as_slice(), path.is_empty()) {
            (Method::Get, [], true) => Route::ListBuckets,
            _ => Route::NotImplemented,
        };
    }

    let Some(key) = key else {
        return match (method, sub.as_slice()) {
            (Method::Get, []) => Route::ListObjects { bucket },
            (Method::Put, []) => Route::CreateBucket { bucket },
            (Method::Head, []) => Route::HeadBucket { bucket },
            (Method::Get, ["location"]) => Route::GetBucketLocation { bucket },
            (Method::Delete, []) => Route::DeleteBucket { bucket },
            (Method::Post, ["delete"]) => Route::DeleteObjects { bucket },
            (Method::Get, ["uploads"]) => Route::ListMultipartUploads { bucket },
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
        (Method::Get, ["uploadId"]) => Route::ListParts { bucket, key },
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
    pub async fn handle(self: Rc<Self>, req: S3Request) -> S3Response
    where
        Self: 'static,
    {
        let target = req.raw_target.clone();
        // A sub-range of a large GET, asked for by another invocation of
        // this Worker. It is told apart by its target alone and admitted
        // by its token alone, before any S3 routing.
        if crate::fanout::is_internal_target(&target) {
            return get::fanout_piece(&self, req).await;
        }
        match classify(&req.method, &target) {
            Route::Admin { rest } => admin::handle(&self, req, rest).await,
            Route::ListBuckets => list::list_buckets(&self, req).await,
            Route::CreateBucket { bucket } => {
                if bucket::is_sigv4(&req) {
                    bucket::create_bucket_signed(&self, req).await
                } else {
                    admin::create_bucket_s3(&self, req, bucket).await
                }
            }
            Route::DeleteBucket { bucket } => {
                if bucket::is_sigv4(&req) {
                    bucket::delete_bucket_signed(&self, req).await
                } else {
                    admin::delete_bucket_s3(&self, req, bucket).await
                }
            }
            Route::DeleteObjects { bucket } => delete::delete_objects(&self, req, bucket).await,
            Route::ListMultipartUploads { bucket } => {
                multipart_list::list_uploads(&self, req, bucket).await
            }
            Route::ListParts { bucket, key } => {
                multipart_list::list_parts(&self, req, bucket, key).await
            }
            Route::HeadBucket { .. } => bucket::head_bucket(&self, req).await,
            Route::GetBucketLocation { .. } => bucket::get_bucket_location(&self, req).await,
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
            // A host that is not this endpoint is the likelier cause
            // (virtual-hosted style shifts the bucket out of the path), so
            // it is named first, as on the routes that parse a target.
            Route::NotImplemented => req
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                .and_then(|(_, host)| common::host_value_refused(host, &self.cfg))
                .unwrap_or_else(S3Response::not_implemented),
        }
    }
}

// ---------------------------------------------------------------------------
// A managed tenant's request (design round 5, AM-51)
// ---------------------------------------------------------------------------

pub use common::{claimed_access_key, writes_refused};

impl Route<'_> {
    /// The operation changes stored state: the maintenance gate refuses
    /// it (`open_gate`, and for a unit `serve_managed`).
    pub fn writes(&self) -> bool {
        matches!(
            self,
            Route::CreateBucket { .. }
                | Route::DeleteBucket { .. }
                | Route::DeleteObjects { .. }
                | Route::PutObject { .. }
                | Route::DeleteObject { .. }
                | Route::CreateMultipartUpload { .. }
                | Route::UploadPart { .. }
                | Route::CompleteMultipartUpload { .. }
                | Route::AbortMultipartUpload { .. }
        )
    }

    /// The bucket the operation names, raw.
    pub fn bucket(&self) -> Option<&str> {
        match *self {
            Route::Admin { .. } | Route::ListBuckets | Route::NotImplemented => None,
            Route::CreateBucket { bucket }
            | Route::DeleteBucket { bucket }
            | Route::HeadBucket { bucket }
            | Route::GetBucketLocation { bucket }
            | Route::ListObjects { bucket }
            | Route::DeleteObjects { bucket }
            | Route::ListMultipartUploads { bucket }
            | Route::PutObject { bucket, .. }
            | Route::GetObject { bucket, .. }
            | Route::HeadObject { bucket, .. }
            | Route::DeleteObject { bucket, .. }
            | Route::CreateMultipartUpload { bucket, .. }
            | Route::UploadPart { bucket, .. }
            | Route::CompleteMultipartUpload { bucket, .. }
            | Route::AbortMultipartUpload { bucket, .. }
            | Route::ListParts { bucket, .. } => Some(bucket),
        }
    }
}

/// The fixed code of a managed tenant's request that the unit cannot take
/// yet: the unit has no S3 request operations in this build.
pub const UNIT_REQUESTS_NOT_BUILT: &str = "unit_requests_not_built";

/// What became of a managed tenant's request, for the log line: a fixed
/// code, and whether it pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedLine {
    pub code: &'static str,
    pub alert: bool,
}

/// A request whose access key routes to the managed tenant `tenant`
/// (`unit_router::KeyRoutes`), through `router` to its unit.
///
/// Under `MAINTENANCE=restore` a request that writes ([`Route::writes`])
/// answers `503` with `Retry-After` before anything is read: no unit
/// call, no head read (AM-50; DS1 §3.4 from 8(b) to step 9). Any other
/// request is routed to its unit ([`crate::unit_router::UnitRouter::route`]);
/// a refusal answers `503`. This build has no S3 request operations on a
/// unit, so a routed request answers `503` ([`UNIT_REQUESTS_NOT_BUILT`])
/// as well, and the signature is never checked: nothing is read or
/// written for it.
pub async fn serve_managed<R: crate::unit_router::UnitRouter>(
    router: &R,
    maintenance: crate::config::Maintenance,
    tenant: &crate::unit::TenantId,
    req: &S3Request,
) -> (S3Response, ManagedLine) {
    let route = classify(&req.method, &req.raw_target);
    let line = |code, alert| ManagedLine { code, alert };
    match route {
        Route::NotImplemented => {
            return (
                S3Response::not_implemented(),
                line("not_implemented", false),
            )
        }
        // The admin plane takes its bearer, never an access key.
        Route::Admin { .. } => {
            return (
                common::s3_error(velmora_s3_proto::ErrorCode::AccessDenied),
                line("admin_with_key", false),
            )
        }
        _ => {}
    }
    if maintenance == crate::config::Maintenance::Restore && route.writes() {
        return (writes_refused(), line("maintenance", false));
    }
    match router.route(tenant, route.bucket()).await {
        Err(refusal) => (
            common::unit_refused(),
            line(refusal.code(), refusal.alert()),
        ),
        Ok(_) => (common::unit_refused(), line(UNIT_REQUESTS_NOT_BUILT, false)),
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
            (
                Get,
                "/b?uploads",
                Route::ListMultipartUploads { bucket: "b" },
            ),
            (
                Get,
                "/b/?uploads&prefix=a%2F&max-uploads=2",
                Route::ListMultipartUploads { bucket: "b" },
            ),
            (
                Get,
                "/b/k?uploadId=u",
                Route::ListParts {
                    bucket: "b",
                    key: "k",
                },
            ),
            (Post, "/b?delete", Route::DeleteObjects { bucket: "b" }),
            (Post, "/b/?%64elete", Route::DeleteObjects { bucket: "b" }),
            // Each of the new shapes only under its own method and
            // sub-resource set.
            (Put, "/b?delete", Route::NotImplemented),
            (Get, "/b?delete", Route::NotImplemented),
            (Post, "/b/k?delete", Route::NotImplemented),
            (Post, "/b?delete&versionId=1", Route::NotImplemented),
            (Post, "/b?uploads", Route::NotImplemented),
            (Get, "/b/k?uploads", Route::NotImplemented),
            (Get, "/b?uploadId=u", Route::NotImplemented),
            (Get, "/b/k?uploadId=u&partNumber=1", Route::NotImplemented),
            (Delete, "/b?delete", Route::NotImplemented),
            (Delete, "/b?versionId=1", Route::NotImplemented),
            (Put, "/b/k?tagging", Route::NotImplemented),
            (Put, "/b/k?uploadId=u", Route::NotImplemented),
            (Post, "/b/k", Route::NotImplemented),
            (Delete, "/b", Route::DeleteBucket { bucket: "b" }),
            (Delete, "/b/", Route::DeleteBucket { bucket: "b" }),
            (Head, "/b", Route::HeadBucket { bucket: "b" }),
            (Head, "/b/", Route::HeadBucket { bucket: "b" }),
            (Get, "/b?location", Route::GetBucketLocation { bucket: "b" }),
            (
                Get,
                "/b/?location=",
                Route::GetBucketLocation { bucket: "b" },
            ),
            (Put, "/b?location", Route::NotImplemented),
            (Get, "/b/k?location", Route::NotImplemented),
            (Other("PATCH".into()), "/b/k", Route::NotImplemented),
            (Get, "b/k", Route::NotImplemented),
            // Only `/` is the service root.
            (Get, "//k", Route::NotImplemented),
            (Get, "//", Route::NotImplemented),
            (Get, "/?x-id=ListBuckets", Route::ListBuckets),
            // Sub-resource names compare decoded and exactly.
            (
                Post,
                "/b/k?%75ploads",
                Route::CreateMultipartUpload {
                    bucket: "b",
                    key: "k",
                },
            ),
            (
                Delete,
                "/b/k?upload%49d=u",
                Route::AbortMultipartUpload {
                    bucket: "b",
                    key: "k",
                },
            ),
            (Get, "/b/k?%61cl", Route::NotImplemented),
            (Get, "/b/k?%zz", Route::NotImplemented),
            (
                Get,
                "/b/k?ACL",
                Route::GetObject {
                    bucket: "b",
                    key: "k",
                },
            ),
            (Post, "/b/k?Uploads", Route::NotImplemented),
        ];
        for (method, target, want) in cases {
            assert_eq!(&classify(method, target), want, "{method:?} {target}");
        }
    }
}
