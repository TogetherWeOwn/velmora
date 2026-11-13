//! GetObject and HeadObject: cache hit, cold fetch, ranges (S3 lane A, DESIGN §A.5).
//!
//! Walking-skeleton stub: answers `501 NotImplemented`.

use std::rc::Rc;

use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{S3Request, S3Response};

pub(super) async fn get_object<
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
    _key: &str,
) -> S3Response {
    S3Response::not_implemented()
}

pub(super) async fn head_object<
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
    _key: &str,
) -> S3Response {
    S3Response::not_implemented()
}
