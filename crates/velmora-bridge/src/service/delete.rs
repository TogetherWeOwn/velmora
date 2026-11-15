//! DeleteObject: retire the live generation. Idempotent, so a key that
//! does not exist is also `204`.

use std::rc::Rc;

use velmora::rng::{FillRandom, SystemRng};

use super::common::{authenticate, internal, mutation_gate, restore_gate, writes_refused};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::recovery::{tombstone_id, write_tombstone};
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
    restore_gate(bridge).await?;
    let live = bridge
        .catalog
        .live_object(&bucket.id, key)
        .await
        .map_err(|_| internal())?;
    let seen = match live {
        Some((live, _)) => live.id,
        // Nothing live. A write that was not published may still have
        // its record (its batch failed, or the record could not be
        // removed): a replay would publish it, over this delete. The
        // floor of the key says so, and then the delete leaves a
        // tombstone as if the object were live. Otherwise there is
        // nothing to delete and nothing to record.
        None => match bridge
            .catalog
            .unpublished_floor(&bucket.id, key)
            .await
            .map_err(|_| internal())?
        {
            Some(floor) => floor,
            None => return Ok(no_content()),
        },
    };
    // The newest id on the key: the live generation, or a floor above
    // it, left by the record of a write or a delete that did not commit.
    // The tombstone sorts after that record too, so a replay cannot
    // apply it over this delete.
    let newest = bridge
        .catalog
        .newest_id(&bucket.id, key)
        .await
        .map_err(|_| internal())?
        .map_or(seen.clone(), |n| n.max(seen.clone()));
    let now = bridge.clock.now();
    let mut rand = [0u8; 8];
    SystemRng.fill_bytes(&mut rand).map_err(|_| internal())?;
    // The tombstone is durable before the catalogue batch, so an
    // acknowledged delete stays deleted in a restored catalogue. It
    // covers every generation older than itself; a generation published
    // after it (a racing PUT) survives, here and in a replay. The floor
    // of the key is raised to the tombstone before the record is stored:
    // when the batch below finds nothing left to delete (another delete
    // was faster), the record stays, and every later write sorts after it.
    let tombstone = tombstone_id(now, &newest, rand);
    write_tombstone(
        &bridge.catalog,
        &bridge.safety,
        &bridge.kek,
        &bucket.id,
        key,
        &tombstone,
        now,
    )
    .await
    .map_err(|_| internal())?;
    let deleted = bridge
        .catalog
        .delete_object_before(&bucket.id, key, &tombstone, now)
        .await
        .map_err(|_| internal())?;
    if deleted {
        return Ok(no_content());
    }
    // Nothing was changed. Either nothing older than the tombstone is
    // live any more (another delete was faster, or a PUT that sorts
    // after the tombstone), and the delete holds. Or a replay started
    // after this request passed the gate: then the object is still
    // live under its older id, and the delete was not done.
    let live = bridge
        .catalog
        .live_object(&bucket.id, key)
        .await
        .map_err(|_| internal())?;
    match live {
        Some((live, _)) if live.id < tombstone => Err(writes_refused()),
        _ => Ok(no_content()),
    }
}

fn no_content() -> S3Response {
    S3Response {
        status: 204,
        headers: Vec::new(),
        body: RespBody::Empty,
    }
}
