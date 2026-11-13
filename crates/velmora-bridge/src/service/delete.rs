//! DeleteObject: retire the live generation. Idempotent, so a key that
//! does not exist is also `204`.

use std::rc::Rc;

use super::common::{authenticate, internal, mutation_gate};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{RespBody, S3Request, S3Response};

pub(super) async fn delete_object<
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
    _key: &str,
) -> S3Response {
    match delete(bridge, req).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn delete<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Result<S3Response, S3Response> {
    let authed = authenticate(bridge, &req).await?;
    let (bucket, key) = authed.object()?;
    mutation_gate(&bridge.cfg, &authed.headers, bucket)?;
    bridge
        .catalog
        .delete_object(&bucket.id, key, bridge.clock.now())
        .await
        .map_err(|_| internal())?;
    Ok(S3Response {
        status: 204,
        headers: Vec::new(),
        body: RespBody::Empty,
    })
}
