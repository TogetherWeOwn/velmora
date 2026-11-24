use crate::{Family, Job};
use std::cell::RefCell;
use tokio_postgres::{types::Type, Client};
use velmora_bridge::pg::{PgConnect, PgSql};
use velmora_bridge::ports::{
    BlobMeta, BlobStore, Catalog, Guard, Kek, Lease, Permit, PermitClass, PublishOutcome,
    UploadTarget,
};
use velmora_bridge::recovery::{write_generation, Layout, Unpublished};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::types::*;

pub(crate) const READ_KEYS: usize = 128;
const DISPATCH_KEYS: usize = 100;
const USAGE_CHUNK: u32 = 4_000;
const BUCKET: &str = "b_70676c6f61640001";
const PROVIDER: &str = "pg-load";
const ETAG: &str = "\"pg-load\"";

pub(crate) enum OpError {
    Refused,
    Overloaded,
    Failed,
}
impl From<BridgeError> for OpError {
    fn from(error: BridgeError) -> Self {
        match error {
            BridgeError::Sql(ref code) if code == "pg: overloaded" => Self::Overloaded,
            BridgeError::GuardFailed => Self::Refused,
            _ => Self::Failed,
        }
    }
}

type Cat<C> = SqlCatalog<PgSql<C>>;

pub(crate) fn sql_error(step: &str, error: tokio_postgres::Error) -> String {
    let code = error.code().map_or("transport", |code| code.code());
    format!("{step}: {code}") // never format SQL text, server detail, or connection strings
}

pub(crate) async fn seed(client: &Client, jobs: &[Job]) -> std::result::Result<(), String> {
    client
        .execute_typed(
            "INSERT INTO buckets (id,name,owner,bdk_wrapped,kek_version,disposable,created_at) \
        VALUES ($1,'pg-load-fixture','pg-load',decode(repeat('00',73),'hex'),1,1,1)",
            &[(&BUCKET, Type::TEXT)],
        )
        .await
        .map_err(|e| sql_error("create fixture bucket", e))?;
    if jobs.iter().any(|job| job.family == Family::Usage) {
        // A fresh local schema needs a full first recount chunk. A clone
        // already has real extents beyond the seeded rows.
        client.execute_typed("INSERT INTO extents (id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) \
             SELECT 'x_ffffffffff'||lpad(to_hex(n),16,'0'),$1,'staged',1,65,decode(repeat('00',48),'hex'), \
             decode(repeat('00',16),'hex'),decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),'held',1 \
             FROM generate_series(0,$2::bigint) AS n", &[(&BUCKET, Type::TEXT), (&i64::from(USAGE_CHUNK), Type::INT8)])
            .await.map_err(|e| sql_error("seed recount extents", e))?;
    }
    // Bound each setup transaction separately from the measured write load.
    const CHUNK: usize = 4096;
    for (offset, group) in jobs.chunks(CHUNK).enumerate() {
        seed_group(client, offset * CHUNK, group).await?;
    }
    Ok(())
}

async fn seed_group(
    client: &Client,
    offset: usize,
    jobs: &[Job],
) -> std::result::Result<(), String> {
    // This dedicated setup connection is dropped on failure, rolling back its transaction.
    client.batch_execute("BEGIN; CREATE TEMP TABLE load_seed (n bigint, family text, stage text, held boolean, key text, gen text, extent text, upload text) ON COMMIT DROP")
        .await.map_err(|e| sql_error("create seed table", e))?;
    let mut n = Vec::new();
    let mut families = Vec::new();
    let mut stages = Vec::new();
    let mut held = Vec::new();
    let initial = if offset == 0 { READ_KEYS } else { 0 };
    for (i, family) in (0..initial).map(|i| (i, None)).chain(
        jobs.iter()
            .enumerate()
            .map(|(i, j)| (offset + i + READ_KEYS, Some(j.family))),
    ) {
        let (label, stage, is_held) = match family {
            None => ("read", "", false),
            Some(Family::Delete) => ("delete", "", false),
            Some(Family::MultipartPart) => ("part", "", false),
            Some(Family::MultipartComplete) => ("complete", "", false),
            Some(Family::MultipartAbort) => ("abort", "", false),
            Some(Family::Gc) => ("gc", "", false),
            Some(Family::PermitsAcquire) => ("permit_acquire", "", false),
            Some(Family::PermitsRelease) => ("permit_release", "", false),
            Some(f) => match outbox_operation(f) {
                Some((stage, next)) => ("outbox", stage.as_str(), next.is_some()),
                None => continue,
            },
        };
        n.push(i64::try_from(i).expect("bounded workload"));
        families.push(label);
        stages.push(stage);
        held.push(is_held);
    }
    client.execute_typed("INSERT INTO load_seed SELECT n, family, stage, held, 'pg-load/'||lpad(to_hex(n),16,'0'), \
         'g_0000000000001'||lpad(to_hex(n),16,'0'), 'x_'||lpad(to_hex(n),26,'0'), lpad(to_hex(n),32,'0') \
         FROM unnest($1::bigint[], $2::text[], $3::text[], $4::boolean[]) AS t(n,family,stage,held)",
        &[(&n, Type::INT8_ARRAY), (&families, Type::TEXT_ARRAY), (&stages, Type::TEXT_ARRAY), (&held, Type::BOOL_ARRAY)])
        .await.map_err(|e| sql_error("populate seed table", e))?;
    client
        .batch_execute(include_str!("seed.sql"))
        .await
        .map_err(|e| sql_error("seed catalogue", e))?;
    client
        .batch_execute("COMMIT")
        .await
        .map_err(|e| sql_error("commit seed", e))
}

fn key(i: usize) -> String {
    format!("pg-load/{i:016x}")
}
fn bucket() -> BucketId {
    BucketId::new(BUCKET)
}
fn id(i: usize, now: UnixMs) -> GenerationId {
    GenerationId::mint(now, (i as u64).to_be_bytes())
}
fn extent_id(i: usize) -> ExtentId {
    ExtentId::new(format!("x_{i:026x}"))
}
fn upload_id(i: usize) -> UploadId {
    UploadId::new(format!("{i:032x}"))
}

fn outbox_operation(family: Family) -> Option<(OutboxStage, Option<OutboxStage>)> {
    use OutboxStage::{Done, Post, Release, Verify};
    Some(match family {
        Family::OutboxPostClaim => (Post, None),
        Family::OutboxPostAdvance => (Post, Some(Verify)),
        Family::OutboxVerifyClaim => (Verify, None),
        Family::OutboxVerifyAdvance => (Verify, Some(Release)),
        Family::OutboxReleaseClaim => (Release, None),
        Family::OutboxReleaseAdvance => (Release, Some(Done)),
        _ => return None,
    })
}

struct Row {
    i: usize,
    bucket: BucketId,
    key: String,
    now: UnixMs,
    upload: UploadId,
}

impl Row {
    fn new(i: usize, now: UnixMs) -> Self {
        Self {
            i,
            bucket: bucket(),
            key: key(i),
            now,
            upload: upload_id(i),
        }
    }
    fn target(&self) -> UploadTarget<'_> {
        UploadTarget {
            bucket: &self.bucket,
            key: &self.key,
            id: &self.upload,
        }
    }
    fn extent(&self, published: bool) -> ExtentRow {
        ExtentRow {
            id: extent_id(self.i),
            bucket_id: self.bucket.clone(),
            generation_id: published.then(|| id(self.i, self.now)),
            state: if published {
                ExtentState::Committed
            } else {
                ExtentState::Staged
            },
            seq: published.then_some(0),
            plain_offset: published.then_some(0),
            plain_size: 1,
            cipher_size: 65,
            media_header: vec![0; 48],
            key_mode: 1,
            wrapped_file_key: Some(vec![0; 73]),
            plain_md5: [0; 16],
            plain_sha256: [0; 32],
            cipher_sha256: [0; 32],
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: self.now,
        }
    }
    fn generation(&self) -> GenerationRow {
        GenerationRow {
            id: id(self.i, self.now),
            bucket_id: self.bucket.clone(),
            key: self.key.clone(),
            state: GenerationState::Live,
            size: 1,
            etag: ETAG.into(),
            checksum_json: None,
            content_json: "{}".into(),
            user_meta_json: "{}".into(),
            extent_count: 1,
            created_at: self.now,
            retired_at: None,
        }
    }
    fn upload(&self) -> UploadRow {
        UploadRow {
            id: self.upload.clone(),
            bucket_id: self.bucket.clone(),
            key: self.key.clone(),
            content_json: "{}".into(),
            user_meta_json: "{}".into(),
            state: UploadState::Open,
            revision: 0,
            completed_generation_id: None,
            complete_digest: None,
            result_etag: None,
            initiated_at: self.now,
        }
    }
    fn part(&self) -> UploadPartRow {
        UploadPartRow {
            upload_id: self.upload.clone(),
            part_number: 1,
            extent_id: extent_id(self.i),
            size: 1,
            etag: ETAG.into(),
            uploaded_at: self.now,
        }
    }
}

// The synthetic record is stored only for the duration of one catalogue operation.
// The real write_generation path issues the floor transaction and constructs its proof.
#[derive(Default)]
struct RecordBuffer(RefCell<Option<(String, Vec<u8>)>>);
impl BlobStore for RecordBuffer {
    async fn put(&self, key: &str, bytes: Vec<u8>, _: &BlobMeta<'_>) -> Result<()> {
        self.0.replace(Some((key.to_owned(), bytes)));
        Ok(())
    }
    async fn get(&self, _: &str, _: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        Err(unsupported())
    }
    async fn head(&self, _: &str) -> Result<Option<u64>> {
        Err(unsupported())
    }
    async fn delete(&self, _: &str) -> Result<()> {
        Err(unsupported())
    }
    async fn delete_record(&self, _: &Unpublished) -> Result<()> {
        Err(unsupported())
    }
    async fn list(&self, _: &str, _: &str, _: u32) -> Result<Vec<String>> {
        Err(unsupported())
    }
}
fn unsupported() -> BridgeError {
    BridgeError::Invalid("unsupported synthetic record operation")
}
struct SyntheticKey(KekBytes);
impl Kek for SyntheticKey {
    fn active(&self) -> (u32, &KekBytes) {
        (1, &self.0)
    }
    fn version(&self, v: u32) -> Option<&KekBytes> {
        (v == 1).then_some(&self.0)
    }
}

fn applied(value: bool) -> std::result::Result<(), OpError> {
    if value {
        Ok(())
    } else {
        Err(OpError::Refused)
    }
}

async fn publish<C: PgConnect>(
    cat: &Cat<C>,
    row: &Row,
    family: Family,
    count: &mut impl FnMut(),
) -> std::result::Result<(), OpError> {
    let generation = row.generation();
    let extents = vec![row.extent(true)];
    let bucket = Bucket {
        id: row.bucket.clone(),
        name: "pg-load-fixture".into(),
        owner: PROVIDER.into(),
        bdk_wrapped: vec![0; 73],
        kek_version: 1,
        disposable: true,
        created_at: UnixMs(1),
    };
    let safety = RecordBuffer::default();
    let record = write_generation(
        cat,
        &safety,
        &SyntheticKey(KekBytes::new([0x23; 32])),
        &Layout::flat(),
        &bucket,
        &generation,
        &extents,
    )
    .await?;
    count(); // floor transaction is separate, including when publish fails
    let outcome = if family == Family::PutPublish {
        cat.commit_generation(
            &CommitGeneration {
                generation,
                extents,
                now: row.now,
            },
            None,
            record,
        )
        .await?
    } else {
        cat.complete_upload(
            &row.target(),
            1,
            &[0; 32],
            &CompleteUpload {
                generation,
                placements: vec![ExtentPlacement {
                    extent_id: extent_id(row.i),
                    seq: 0,
                    plain_offset: 0,
                }],
                now: row.now,
            },
            None,
            record,
        )
        .await?
    };
    applied(matches!(outcome, PublishOutcome::Applied))
}

pub(crate) fn provider() -> ProviderConfig {
    // No provider credentials or transports in this Worker. Slots are SQL-only.
    serde_json::from_value(serde_json::json!({
        "id":PROVIDER,"host":"invalid.example","port":563,"tls":true,"user":"","pass":"",
        "backbone":PROVIDER,"post":true,"read":true,"max_conns":1_000_000
    }))
    .expect("static provider fixture")
}

pub(crate) async fn write<C: PgConnect>(
    cat: &Cat<C>,
    provider: &ProviderConfig,
    family: Family,
    index: usize,
    now: UnixMs,
    mut count: impl FnMut(),
) -> std::result::Result<(), OpError> {
    let row = Row::new(index + READ_KEYS, now);
    match family {
        Family::PutPublish | Family::MultipartComplete => {
            publish(cat, &row, family, &mut count).await?
        }
        Family::MultipartCreate => cat.create_upload(&row.upload()).await?,
        Family::MultipartPart => applied(
            cat.put_upload_part(&row.target(), &row.part(), &row.extent(false), now)
                .await?
                == Guard::Applied(()),
        )?,
        Family::MultipartAbort => {
            applied(cat.abort_upload(&row.target(), now).await? == Guard::Applied(()))?
        }
        Family::Delete => {
            let tombstone = id(row.i, now);
            // Catalogue writes of write_tombstone; no blob I/O is in this drill.
            cat.raise_floor(&row.bucket, &row.key, &tombstone, false)
                .await?;
            count();
            cat.settle_floor(&row.bucket, &row.key, &tombstone).await?;
            count();
            applied(
                cat.delete_object_before(&row.bucket, &row.key, &tombstone, now)
                    .await?,
            )?;
        }
        Family::PermitsAcquire => applied(
            cat.acquire_permit(provider, PermitClass::Background, PROVIDER, now)
                .await?
                .is_some(),
        )?,
        Family::PermitsRelease => {
            cat.release_permit(&Permit {
                provider: PROVIDER.into(),
                slot: row.i as u32,
                token: 1,
                class: PermitClass::Background,
            })
            .await?
        }
        Family::Gc => cat.gc_done(-(row.i as i64) - 1, now).await?,
        Family::Usage => {
            applied(cat.usage_recount_start(now, false, true, false).await?)?;
            count();
            applied(!cat.usage_recount_step(USAGE_CHUNK, now).await?.idle)?;
        }
        Family::Dispatch => {
            cat.bury_exhausted(50, now).await?;
            count();
            let due: Vec<_> = (0..DISPATCH_KEYS).map(extent_id).collect();
            applied(cat.mark_sent(&due, now).await? >= DISPATCH_KEYS as u64)?;
            count();
            cat.record_dispatch(now).await?;
        }
        family => {
            let (stage, next) = outbox_operation(family).expect("outbox family");
            let extent = extent_id(row.i);
            let generation = id(row.i, UnixMs(1));
            if let Some(next) = next {
                let lease = Lease {
                    extent,
                    generation,
                    stage,
                    token: 1,
                    attempts: 1,
                    cursor: 0,
                    claimed_at: now,
                };
                applied(cat.advance(&lease, next, now, now).await?)?;
            } else {
                applied(
                    cat.claim(&extent, &generation, stage, PROVIDER, now)
                        .await?
                        .is_some(),
                )?;
            }
        }
    }
    count();
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum Read {
    Get,
    Head,
    List,
}
pub(crate) async fn read<C: PgConnect>(
    cat: &Cat<C>,
    operation: Read,
    index: usize,
) -> std::result::Result<(), OpError> {
    let i = index % READ_KEYS;
    applied(match operation {
        Read::Get => !cat.extents_in(&id(i, UnixMs(1)), 0, 1).await?.is_empty(),
        Read::Head => cat.live_generation(&bucket(), &key(i)).await?.is_some(),
        Read::List => !cat
            .list_heads(
                &bucket(),
                &ListQuery {
                    prefix: "pg-load/".into(),
                    delimiter: None,
                    after: None,
                    skip_prefix: None,
                    max_keys: 101,
                },
            )
            .await?
            .is_empty(),
    })
}
