//! The tenant seams on a catalogue that is older than they are.
//!
//! A fresh catalogue proves nothing here: it would take any catalogue
//! id, because the first raise writes the id into the row. Production
//! has a stamp row that says `main` and stamp objects under `rs/main/`,
//! made by the build before the seams. A build that worked out its
//! catalogue id in another way (from a tenant, say) would pass every
//! test that starts empty and then refuse every raise, every cron job
//! and every delete in production. So these tests start from the row
//! and the objects of the old build, written here as literals.

mod service_support;

use serde_json::Value;
use service_support::*;
use velmora_bridge::config::DEFAULT_CATALOGUE_ID;
use velmora_bridge::stamp::{is_catalogue_id_error, StampRow};
use velmora_bridge::*;

const BUCKET: &str = "vault";

/// The stamp row as the build before the seams wrote it, after three
/// raises (`sql/replay.rs`: the first raise inserts the row with the
/// catalogue id, every later one moves the counter).
const OLD_ROW: &str =
    "INSERT INTO rollback_stamp(id, counter, catalogue_id) VALUES (1, 3, 'main');";

/// The stamp objects of those three raises.
const OLD_OBJECTS: [&str; 3] = [
    "rs/main/00000000000000000001",
    "rs/main/00000000000000000002",
    "rs/main/00000000000000000003",
];

fn sql(rig: &Rig, script: &str) {
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(script).unwrap());
}

fn stamps(rig: &Rig) -> Vec<String> {
    let mut keys: Vec<String> = rig
        .bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| k.starts_with("rs/"))
        .collect();
    keys.sort();
    keys
}

/// A catalogue with the stamp of the old build, under a Worker whose
/// catalogue id is `id`.
async fn upgraded(id: &str) -> Rig {
    let mut cfg = config(Vec::new());
    cfg.catalogue_id = id.to_string();
    let rig = rig_with(NoNntp, cfg);
    sql(&rig, OLD_ROW);
    for key in OLD_OBJECTS {
        // The body of a stamp object is the time of its raise.
        let body = (T0.0 - 60_000).to_string().into_bytes();
        let meta = BlobMeta {
            bucket: &BucketId::new("-"),
            extent: &ExtentId::new("rollback-stamp"),
            cipher_sha256: &sha256(&body),
        };
        rig.bridge.safety.put(key, body, &meta).await.unwrap();
    }
    rig
}

async fn status(rig: &Rig) -> Value {
    let mut req = Req {
        method: Method::Get,
        target: "/_admin/status".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    req.set_header("host", HOST);
    req.set_header("content-length", "0");
    req.set_header(
        "authorization",
        &format!("Bearer {}", rig.bridge.cfg.admin_token.expose()),
    );
    let r = rig.send(req).await;
    r.expect(200);
    serde_json::from_slice(&r.body).unwrap()
}

/// The id of a Worker that sets no `CATALOGUE_ID` is the literal the
/// old build used.
#[test]
fn the_catalogue_id_is_still_main() {
    assert_eq!(DEFAULT_CATALOGUE_ID, "main");
}

/// The first raise after the deploy, a write, a cron tick, a GC batch
/// and an eviction all run on the old stamp: none of them answers that
/// the catalogue id is wrong, and the new stamp objects go where the
/// old ones are.
#[tokio::test(flavor = "current_thread")]
async fn the_first_raise_gc_and_eviction_run_on_a_stamp_of_the_old_build() {
    let rig = upgraded(DEFAULT_CATALOGUE_ID).await;
    let level = |counter| StampRow {
        counter: Some(counter),
        rolled_back: false,
    };
    assert_eq!(rig.bridge.catalog.stamp("main").await.unwrap(), level(3));
    assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());

    // The first raise.
    rig.bridge.raise_stamp().await.unwrap();
    assert_eq!(rig.bridge.catalog.stamp("main").await.unwrap(), level(4));
    let mut expected: Vec<String> = OLD_OBJECTS.iter().map(|k| k.to_string()).collect();
    expected.push("rs/main/00000000000000000004".to_string());
    assert_eq!(stamps(&rig), expected);

    // A write and a delete, so that garbage collection has work.
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "a", b"a").await.expect(200);
    rig.put(&signer, BUCKET, "b", b"b").await.expect(200);
    rig.call(&signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
        .await
        .expect(204);
    assert!(rig.count("gc") > 0);

    // A cron tick: it checks the stamp before anything else.
    let report = rig.bridge.dispatch().await.unwrap();
    assert!(!report.rolled_back);

    // A GC batch: the blob of the deleted object goes.
    let blobs = |rig: &Rig| {
        let keys = rig.bridge.safety.keys();
        keys.iter().filter(|k| k.starts_with("x/")).count()
    };
    assert_eq!(blobs(&rig), 2);
    rig.bridge.clock.advance_secs(30 * 24 * 3600);
    assert_eq!(
        rig.bridge
            .run_job(&TENANT_ZERO, &Job::Gc { v: JOB_VERSION })
            .await,
        JobOutcome::Ack
    );
    assert_eq!(blobs(&rig), 1);

    // An eviction step. Nothing here is released, so it frees nothing;
    // `hot_tier.rs` (`an_eviction_frees_bytes_on_a_stamp_of_the_old_build`
    // and its control) evicts a released extent on the same stamp.
    assert_eq!(rig.bridge.evict_batch(&TENANT_ZERO, 0).await.unwrap(), 0);
    assert!(rig.bridge.evict_batch(&TENANT_ZERO, 1).await.is_ok());

    let s = status(&rig).await;
    assert_eq!(s["catalogue_id_mismatch"], false, "{s}");
    assert_eq!(s["catalogue_rolled_back"], false, "{s}");
    // Nothing was written under another id.
    assert!(stamps(&rig).iter().all(|k| k.starts_with("rs/main/")));
}

/// The control for the test above: it does tell a build apart that
/// names its catalogue after the tenant. Such a build is stopped by
/// the old row at every one of the same steps.
#[tokio::test(flavor = "current_thread")]
async fn a_catalogue_id_made_from_the_tenant_would_be_refused_by_the_old_stamp() {
    for id in ["t_0000000000000000", "t_0000000000000000.main", "main0"] {
        let rig = upgraded(id).await;
        let wrong_id = |e: BridgeError| is_catalogue_id_error(&e);
        assert!(
            wrong_id(rig.bridge.raise_stamp().await.unwrap_err()),
            "{id}"
        );
        assert!(wrong_id(rig.bridge.dispatch().await.unwrap_err()), "{id}");
        assert_ne!(
            rig.bridge
                .run_job(&TENANT_ZERO, &Job::Gc { v: JOB_VERSION })
                .await,
            JobOutcome::Ack,
            "{id}"
        );
        assert!(
            wrong_id(rig.bridge.evict_batch(&TENANT_ZERO, 0).await.unwrap_err()),
            "{id}"
        );
        assert_eq!(status(&rig).await["catalogue_id_mismatch"], true, "{id}");
        assert_eq!(stamps(&rig), OLD_OBJECTS, "{id}");
    }
}

/// The one tenant there is.
static TENANT_ZERO: velmora_bridge::TenantScope = velmora_bridge::TenantScope::tenant_zero();
