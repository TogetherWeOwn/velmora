//! ListMultipartUploads and ListParts.
//!
//! Both only read, so a read-only key may call them, like ListObjects.
//! ListParts addresses the upload like every other upload call: through
//! an [`UploadTarget`] built from the authorized bucket, the decoded key
//! and the upload id. An id presented under another bucket or key is an
//! unknown upload (`NoSuchUpload`), and so is one that was completed or
//! aborted.
//!
//! Uploads are listed in `(key, upload id)` order; the protocol crate
//! folds common prefixes and renders the page.

use std::rc::Rc;

use velmora_s3_proto::multipart_listing::{ListParts, ListUploads, PartEntry, UploadEntry};
use velmora_s3_proto::{ErrorCode, Target};

use super::common::{authenticate, from_proto, internal, s3_error};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector, UploadTarget};
use crate::types::{S3Request, S3Response, UploadId, UploadListQuery, UploadState};

/// Rows asked of the catalogue per query.
const BATCH: u32 = 1000;
/// Catalogue queries one page may spend. A listing that needs more ends
/// as a valid truncated page.
const QUERY_BUDGET: u32 = 20;

pub(super) async fn list_uploads<
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
    match uploads(bridge, req).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn uploads<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Result<S3Response, S3Response> {
    let authed = authenticate(bridge, &req).await?;
    let Some(bucket) = &authed.bucket else {
        return Err(s3_error(ErrorCode::InvalidRequest));
    };
    let mut page = ListUploads::parse(&authed.target).map_err(s3_error)?;

    let mut exhausted = false;
    let mut queries = 0;
    while page.wants_more() && queries < QUERY_BUDGET {
        queries += 1;
        let rows = bridge
            .catalog
            .list_uploads(
                &bucket.id,
                &UploadListQuery {
                    prefix: page.prefix().to_owned(),
                    after: page
                        .after()
                        .map(|(key, id)| (key.to_owned(), id.map(str::to_owned))),
                    skip_prefix: page.skip_prefix().map(str::to_owned),
                    limit: BATCH,
                },
            )
            .await
            .map_err(|_| internal())?;
        let last_batch = rows.len() < BATCH as usize;
        for row in rows {
            if !page.wants_more() {
                break;
            }
            page.push(UploadEntry {
                key: row.key,
                upload_id: row.id.as_str().to_owned(),
                initiated_ms: row.initiated_at.0,
            })
            .map_err(s3_error)?;
        }
        if last_batch {
            // Rows left unpushed make the page a full one, which is
            // truncated whatever this says.
            exhausted = true;
            break;
        }
    }
    page.finish(exhausted).map(from_proto).map_err(s3_error)
}

/// The `uploadId` of the request. One this service never issued (not 32
/// lowercase hex digits) is an unknown upload.
fn upload_id(target: &Target) -> Result<UploadId, S3Response> {
    let mut values = target
        .query()
        .iter()
        .filter(|(name, _)| name.as_slice() == b"uploadId")
        .map(|(_, value)| value.as_slice());
    let (Some(raw), None) = (values.next(), values.next()) else {
        return Err(s3_error(ErrorCode::InvalidRequest));
    };
    if raw.len() != 32
        || !raw
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(s3_error(ErrorCode::NoSuchUpload));
    }
    // Hex digits are ASCII.
    Ok(UploadId::new(String::from_utf8_lossy(raw).into_owned()))
}

pub(super) async fn list_parts<
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
    match parts(bridge, req).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn parts<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Result<S3Response, S3Response> {
    let authed = authenticate(bridge, &req).await?;
    let (bucket, key) = authed.object()?;
    let id = upload_id(&authed.target)?;
    let paging = ListParts::parse(&authed.target).map_err(s3_error)?;
    let found = bridge
        .catalog
        .upload(&UploadTarget {
            bucket: &bucket.id,
            key,
            id: &id,
        })
        .await
        .map_err(|_| internal())?;
    let Some((_, stored)) = found.filter(|(upload, _)| upload.state == UploadState::Open) else {
        return Err(s3_error(ErrorCode::NoSuchUpload));
    };
    let entries: Vec<PartEntry> = stored
        .into_iter()
        .map(|p| PartEntry {
            part_number: p.part_number,
            size: p.size,
            etag: p.etag,
            last_modified_ms: p.uploaded_at.0,
        })
        .collect();
    paging
        .respond(&bucket.name, key, id.as_str(), &entries)
        .map(from_proto)
        .map_err(s3_error)
}
