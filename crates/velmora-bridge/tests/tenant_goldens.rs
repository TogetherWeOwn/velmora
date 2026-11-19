//! Goldens for the tenant seams: what goes on a queue and what is named
//! in a bucket is, byte for byte, what it was before the seams.
//!
//! Every literal in this file was taken from the build before the
//! seams and this file was committed against that build, unchanged
//! since. A change that makes one of these tests fail has changed a
//! wire format or a stored name. That is never a part of a code-only
//! change: a queue message of another shape is dropped by the Worker
//! version next to it during a deploy and after a rollback, and a
//! stored name that moved is a record, a blob or a stamp that the
//! other version does not find.
//!
//! So: do not edit a literal here to make a test pass.

mod service_support;

use serde_json::json;
use service_support::*;
use velmora_bridge::recovery::{
    article_key, generation_key, record_name, revocation_key, tombstone_key, write_article_plan,
    Layout,
};
use velmora_bridge::stamp::stamp_key;
use velmora_bridge::*;

const BUCKET: &str = "vault";

// ---------------------------------------------------------------------------
// Queue messages
// ---------------------------------------------------------------------------

fn extent() -> ExtentId {
    ExtentId::new("x_000102030405060708090a0b0c")
}

fn generation() -> GenerationId {
    GenerationId::new("g_0195c2a4b3e7f00112233445566778")
}

/// Every job, with every stage an extent job can carry, next to the
/// bytes it is sent as.
fn jobs() -> Vec<(Job, &'static str)> {
    let v = JOB_VERSION;
    let extent_job = |stage| Job::Extent {
        v,
        extent: extent(),
        generation: generation(),
        stage,
    };
    let wake_job = |stage, at| Job::Wake {
        v,
        extent: extent(),
        generation: generation(),
        stage,
        at: UnixMs(at),
    };
    vec![
        (
            extent_job(OutboxStage::Post),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"post"}"#,
        ),
        (
            extent_job(OutboxStage::Verify),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"verify"}"#,
        ),
        (
            extent_job(OutboxStage::Release),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"release"}"#,
        ),
        (
            extent_job(OutboxStage::Done),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"done"}"#,
        ),
        (
            extent_job(OutboxStage::Cancelled),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"cancelled"}"#,
        ),
        (
            extent_job(OutboxStage::Dead),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"dead"}"#,
        ),
        (
            wake_job(OutboxStage::Post, 1_800_000_000_123),
            r#"{"t":"wake","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"post","at":1800000000123}"#,
        ),
        (
            wake_job(OutboxStage::Verify, 0),
            r#"{"t":"wake","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"verify","at":0}"#,
        ),
        (
            wake_job(OutboxStage::Release, -1),
            r#"{"t":"wake","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"release","at":-1}"#,
        ),
        (Job::Gc { v }, r#"{"t":"gc","v":1}"#),
        (
            Job::Evict { v, remaining: 0 },
            r#"{"t":"evict","v":1,"remaining":0}"#,
        ),
        (
            Job::Evict {
                v,
                remaining: u64::MAX,
            },
            r#"{"t":"evict","v":1,"remaining":18446744073709551615}"#,
        ),
        (
            Job::Sweep {
                v,
                write: WriteId::new("w_000102030405060708090a0b0c0d0e0f"),
            },
            r#"{"t":"sweep","v":1,"write":"w_000102030405060708090a0b0c0d0e0f"}"#,
        ),
        (
            Job::RecoveryCopy {
                v,
                pass: UnixMs(1_800_000_000_000),
                cursor: String::new(),
            },
            r#"{"t":"recovery_copy","v":1,"pass":1800000000000,"cursor":""}"#,
        ),
        (
            Job::RecoveryCopy {
                v,
                pass: UnixMs(1_800_000_000_000),
                cursor: "walk:m/x/t_0000000000000000/art/x_1".into(),
            },
            r#"{"t":"recovery_copy","v":1,"pass":1800000000000,"cursor":"walk:m/x/t_0000000000000000/art/x_1"}"#,
        ),
    ]
}

/// The version is the one every deployed consumer runs, and each job is
/// sent as the bytes it always was.
#[test]
fn every_job_is_sent_as_the_bytes_it_was() {
    assert_eq!(JOB_VERSION, 1);
    let jobs = jobs();
    // Every kind of job there is has a line above: a new variant fails
    // to compile here until it is given its bytes.
    let mut kinds = [0u32; 6];
    for (job, _) in &jobs {
        let kind = match job {
            Job::Extent { .. } => 0,
            Job::Wake { .. } => 1,
            Job::Gc { .. } => 2,
            Job::Evict { .. } => 3,
            Job::Sweep { .. } => 4,
            Job::RecoveryCopy { .. } => 5,
        };
        kinds[kind] += 1;
    }
    assert!(kinds.iter().all(|n| *n > 0), "{kinds:?}");
    for (job, bytes) in &jobs {
        assert_eq!(job.to_json(), *bytes);
        // What the queue binding sends: the same value through serde.
        assert_eq!(serde_json::to_string(job).unwrap(), *bytes);
        assert_eq!(serde_json::to_vec(job).unwrap(), bytes.as_bytes());
        assert_eq!(&Job::from_json(bytes).unwrap(), job);
    }
}

/// A message says nothing about a tenant, and a consumer of this format
/// refuses one that does: the field belongs to a later format, with its
/// own version.
#[test]
fn a_job_has_no_field_for_a_tenant() {
    for (job, bytes) in jobs() {
        let value: serde_json::Value = serde_json::from_str(bytes).unwrap();
        let fields = value.as_object().unwrap();
        for name in ["tenant", "tenant_id", "unit", "scope"] {
            assert!(!fields.contains_key(name), "{job:?}");
            let mut with = fields.clone();
            with.insert(name.to_string(), json!("t_0000000000000000"));
            let text = serde_json::Value::Object(with).to_string();
            assert!(Job::from_json(&text).is_err(), "{text}");
        }
    }
}

// ---------------------------------------------------------------------------
// Stored names
// ---------------------------------------------------------------------------

/// The directory of the layout that `RECORD_LAYOUT=tenant` chooses
/// (`record_layout_is_flat_unless_tenant_is_asked_for` in `contract.rs`
/// holds the setting to it).
const TENANT_ROOT: &str = "m/x/t_0000000000000000/";

/// The layout of `RECORD_LAYOUT=tenant`, from one of its names.
fn tenant_layout() -> Layout {
    let name = format!("{TENANT_ROOT}art/x_1");
    let layout = record_name(&name).expect("a record name").layout;
    assert_eq!(layout.root(), TENANT_ROOT);
    layout
}

/// Every name the Worker gives an object in the safety or the cache
/// bucket, for fixed ids.
#[test]
fn every_stored_name_is_the_one_it_was() {
    let (x, g) = (extent(), generation());

    // The ciphertext of an extent: one name, whatever the record layout.
    assert_eq!(x.safety_key(), "x/x_000102030405060708090a0b0c");
    assert_eq!(x.cache_key(), "c/x_000102030405060708090a0b0c");

    // Recovery records, `RECORD_LAYOUT` unset (or `flat`).
    let flat = Layout::flat();
    assert_eq!(flat.root(), "m/");
    assert_eq!(
        flat.generation_key(&g),
        "m/g_0195c2a4b3e7f00112233445566778"
    );
    assert_eq!(
        flat.tombstone_key(&g),
        "m/del/g_0195c2a4b3e7f00112233445566778"
    );
    assert_eq!(flat.article_key(&x), "m/art/x_000102030405060708090a0b0c");
    assert_eq!(flat.generation_prefix(), "m/g_");
    assert_eq!(flat.tombstone_prefix(), "m/del/g_");
    assert_eq!(generation_key(&g), flat.generation_key(&g));
    assert_eq!(tombstone_key(&g), flat.tombstone_key(&g));
    assert_eq!(article_key(&x), flat.article_key(&x));

    // Recovery records, `RECORD_LAYOUT=tenant`.
    let tenant = tenant_layout();
    assert_eq!(
        tenant.generation_key(&g),
        "m/x/t_0000000000000000/g_0195c2a4b3e7f00112233445566778"
    );
    assert_eq!(
        tenant.tombstone_key(&g),
        "m/x/t_0000000000000000/del/g_0195c2a4b3e7f00112233445566778"
    );
    assert_eq!(
        tenant.article_key(&x),
        "m/x/t_0000000000000000/art/x_000102030405060708090a0b0c"
    );
    assert_eq!(tenant.generation_prefix(), "m/x/t_0000000000000000/g_");
    assert_eq!(tenant.tombstone_prefix(), "m/x/t_0000000000000000/del/g_");

    // A revocation and a stamp have one name under either setting.
    assert_eq!(
        revocation_key("AKIDTESTKEY000000001"),
        "m/rk/AKIDTESTKEY000000001"
    );
    assert_eq!(stamp_key("main", 0), "rs/main/00000000000000000000");
    assert_eq!(stamp_key("main", 1), "rs/main/00000000000000000001");
    assert_eq!(stamp_key("main", 6_000_000), "rs/main/00000000000006000000");
    assert_eq!(stamp_key("main", u64::MAX), "rs/main/18446744073709551615");
    assert_eq!(velmora_bridge::config::DEFAULT_CATALOGUE_ID, "main");

    // The marks of the recovery copy.
    use velmora_bridge::copy::*;
    assert_eq!(
        [WALK_KEY, WALKED_KEY, BEGAN_KEY, WANT_KEY, DOWN_KEY, SWEPT_KEY, STORE_KEY, SWEEP_KEY],
        [
            "rc/walk",
            "rc/walk-ended",
            "rc/walk-began",
            "rc/walk-wanted",
            "rc/down",
            "rc/swept",
            "rc/store",
            "rc/sweep"
        ]
    );
}

/// A stored name with its ids taken out: `g_<29 hex>` and `x_<26 hex>`
/// are ids, the 20 digits of a stamp its counter.
fn shape(key: &str) -> String {
    let mut out = String::new();
    let mut rest = key;
    while !rest.is_empty() {
        let hex = |n: usize| {
            rest.len() >= 2 + n && rest.as_bytes()[2..2 + n].iter().all(u8::is_ascii_hexdigit)
        };
        if rest.starts_with("g_") && hex(29) {
            out.push_str("<generation>");
            rest = &rest[31..];
        } else if rest.starts_with("x_") && hex(26) {
            out.push_str("<extent>");
            rest = &rest[28..];
        } else {
            let c = rest.chars().next().unwrap();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out
}

async fn request(
    rig: &Rig,
    signer: &Signer,
    method: Method,
    key: &str,
    query: &[(&str, &str)],
    body: &[u8],
) -> Resp {
    rig.call(signer, method, &path(BUCKET, key), query, &[], body)
        .await
}

async fn admin(rig: &Rig, method: Method, target: &str) -> Resp {
    let mut req = Req {
        method,
        target: target.to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    req.set_header("host", HOST);
    req.set_header("content-length", "0");
    req.set_header(
        "authorization",
        &format!("Bearer {}", rig.bridge.cfg.admin_token.expose()),
    );
    rig.send(req).await
}

/// One of everything that stores an object, through the service: two
/// PUTs (the write intents on), a multipart upload of two parts, a
/// copy (which stores a record and no ciphertext), a DELETE, the
/// article plan of an extent, the revocation of a key and a raise of
/// the stamp.
/// Returns the shapes of the names in the safety bucket and in the
/// cache bucket, each sorted.
///
/// A write intent is a row of the catalogue: it has no name in a store.
/// What a sliced write leaves there besides its extents is the raise
/// of the stamp it makes (`rs/main/...`), which is why the lists hold
/// five of them. Nothing here writes to the cache store; the one name
/// it gets is held by `tenant_cache_name.rs`.
async fn names_written(records: Layout) -> (Vec<String>, Vec<String>) {
    let mut cfg = config(Vec::new());
    cfg.records = records;
    cfg.intent_sweep = true;
    cfg.slice_bytes = 4 * 1024 * 1024;
    // Above this a write is cut in slices: the 6 MiB PUT and the 5 MiB
    // part are two extents each, written by the sliced path under
    // write intents.
    cfg.max_extent_bytes = 4 * 1024 * 1024;
    let rig = rig_with(NoNntp, cfg);
    let (bucket, signer) = rig.standard(BUCKET).await;

    rig.put(&signer, BUCKET, "single", b"one extent")
        .await
        .expect(200);
    rig.put(&signer, BUCKET, "sliced", &pattern(1, 6 * MIB))
        .await
        .expect(200);

    let created = request(
        &rig,
        &signer,
        Method::Post,
        "parts",
        &[("uploads", "")],
        b"",
    )
    .await;
    created.expect(200);
    let id = created.values("UploadId").remove(0);
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (n, body) in [(1, pattern(2, 5 * MIB)), (2, pattern(3, 1024))] {
        let number = n.to_string();
        let query = [("partNumber", number.as_str()), ("uploadId", id.as_str())];
        let part = request(&rig, &signer, Method::Put, "parts", &query, &body).await;
        part.expect(200);
        let etag = part.header("etag").unwrap().replace('"', "&quot;");
        xml.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    let query = [("uploadId", id.as_str())];
    request(&rig, &signer, Method::Post, "parts", &query, xml.as_bytes())
        .await
        .expect(200);

    let source = format!("/{BUCKET}/single");
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "copy"),
        &[],
        &[("x-amz-copy-source", &source)],
        b"",
    )
    .await
    .expect(200);

    request(&rig, &signer, Method::Delete, "single", &[], b"")
        .await
        .expect(204);

    // The plan record of an extent, written as the post stage writes
    // it: under the layout of the configuration.
    let (_, extents) = rig.live(&bucket, "copy").await.unwrap();
    let plan: Vec<ArticleRow> = Vec::new();
    write_article_plan(
        &rig.bridge.safety,
        &rig.bridge.kek,
        &rig.bridge.cfg.records,
        &extents[0],
        &plan,
    )
    .await
    .unwrap();

    admin(&rig, Method::Delete, &format!("/_admin/keys/{AKID}"))
        .await
        .expect(204);
    rig.bridge.raise_stamp().await.unwrap();

    let shapes = |keys: Vec<String>| {
        let mut shapes: Vec<String> = keys.iter().map(|k| shape(k)).collect();
        shapes.sort();
        shapes
    };
    (
        shapes(rig.bridge.safety.keys()),
        shapes(rig.bridge.cache.keys()),
    )
}

fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| n.to_string()).collect()
}

/// With `RECORD_LAYOUT` unset the service stores what it stored before.
#[tokio::test(flavor = "current_thread")]
async fn the_service_stores_the_same_names_with_the_layout_unset() {
    let (safety, cache) = names_written(Layout::flat()).await;
    assert_eq!(
        safety,
        owned(&[
            "m/<generation>",
            "m/<generation>",
            "m/<generation>",
            "m/<generation>",
            "m/art/<extent>",
            "m/del/<generation>",
            "m/rk/AKIDTESTKEY000000001",
            "rs/main/00000000000000000001",
            "rs/main/00000000000000000002",
            "rs/main/00000000000000000003",
            "rs/main/00000000000000000004",
            "rs/main/00000000000000000005",
            "x/<extent>",
            "x/<extent>",
            "x/<extent>",
            "x/<extent>",
            "x/<extent>",
            "x/<extent>",
        ])
    );
    assert_eq!(cache, Vec::<String>::new());
}

/// With `RECORD_LAYOUT=tenant` the three kinds of record move to the
/// directory of the tenant, and nothing else moves.
#[tokio::test(flavor = "current_thread")]
async fn the_service_stores_the_same_names_with_the_tenant_layout() {
    let (safety, cache) = names_written(tenant_layout()).await;
    assert_eq!(
        safety,
        owned(&[
            "m/rk/AKIDTESTKEY000000001",
            "m/x/t_0000000000000000/<generation>",
            "m/x/t_0000000000000000/<generation>",
            "m/x/t_0000000000000000/<generation>",
            "m/x/t_0000000000000000/<generation>",
            "m/x/t_0000000000000000/art/<extent>",
            "m/x/t_0000000000000000/del/<generation>",
            "rs/main/00000000000000000001",
            "rs/main/00000000000000000002",
            "rs/main/00000000000000000003",
            "rs/main/00000000000000000004",
            "rs/main/00000000000000000005",
            "x/<extent>",
            "x/<extent>",
            "x/<extent>",
            "x/<extent>",
            "x/<extent>",
            "x/<extent>",
        ])
    );
    assert_eq!(cache, Vec::<String>::new());
}
