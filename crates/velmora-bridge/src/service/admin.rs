//! `/_admin/*` routes and S3 CreateBucket (jobs/admin lane, DESIGN §A.10).
//!
//! Walking-skeleton stub: answers `501 NotImplemented`.

use std::rc::Rc;

use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{S3Request, S3Response};

pub(super) async fn handle<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    _bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    _req: S3Request,
    _rest: &str,
) -> S3Response {
    S3Response::not_implemented()
}

pub(super) async fn create_bucket_s3<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    _bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    _req: S3Request,
    _bucket: &str,
) -> S3Response {
    S3Response::not_implemented()
}
