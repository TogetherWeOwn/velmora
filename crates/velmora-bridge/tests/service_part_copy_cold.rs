//! UploadPartCopy from a source that is no longer in the cache or the
//! safety store: the range comes back from Usenet, verified, within the
//! isolate's byte budget.

mod nntp_support;
mod service_support;

use nntp_support::{TcpConnector, PASS, USER};
use service_support::*;
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const BUCKET: &str = "bkt-part-copy-cold";
/// The smallest extent cap a two-part source allows.
const CAP: usize = 5 * MIB;

type ColdRig = Rig<TcpConnector>;

async fn create(rig: &ColdRig, signer: &Signer, key: &str) -> String {
    let created = rig
        .call(
            signer,
            Method::Post,
            &path(BUCKET, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    created.expect(200);
    created.values("UploadId").remove(0)
}

async fn complete(rig: &ColdRig, signer: &Signer, key: &str, id: &str, etags: &[String]) {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in etags.iter().enumerate() {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
            i + 1
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        signer,
        Method::Post,
        &path(BUCKET, key),
        &[("uploadId", id)],
        &[("content-type", "application/xml")],
        xml.as_bytes(),
    )
    .await
    .expect(200);
}

/// A range that takes all but one byte of a part from one cold extent and
/// its last byte from the next, which is cold and full-size. Reading that
/// extent back needs twice its size; beside the piece already held that
/// is more than the budget has. It is read on its own first.
#[tokio::test(flavor = "current_thread")]
async fn a_range_that_ends_in_a_cold_full_size_extent_fits_the_budget() {
    let mut server_cfg = ServerConfig::for_test();
    server_cfg.articles = Vec::new();
    server_cfg.missing_ids.clear();
    server_cfg.users.insert(
        USER.to_string(),
        UserConfig {
            password: PASS.to_string(),
            max_connections: 4,
        },
    );
    let server = TestNntpServer::spawn(server_cfg).await;
    let mut cfg = config(vec![ProviderConfig {
        id: "p0".to_string(),
        host: server.addr().ip().to_string(),
        port: server.addr().port(),
        tls: false,
        user: USER.to_string(),
        pass: PASS.to_string(),
        backbone: "alpha".to_string(),
        post: true,
        read: true,
        max_conns: 2,
        priority: 0,
        retention_days: None,
        pool: None,
        pool_max_conns: None,
        enabled: true,
    }]);
    // The shipped ratio: the budget is three extents.
    cfg.max_extent_bytes = CAP as u64;
    cfg.inflight_budget_bytes = 3 * CAP as u64;
    let budget = ByteBudget::new(cfg.inflight_budget_bytes);
    let rig = rig_with_budget(TcpConnector::default(), cfg, budget);
    rig.bridge
        .catalog
        .seed_permits(&rig.bridge.cfg.providers)
        .await
        .unwrap();
    let (bucket, signer) = rig.standard(BUCKET).await;

    // A source of two full-size extents, posted, then gone from both stores.
    let halves = [pattern(1, CAP), pattern(2, CAP)];
    let id = create(&rig, &signer, "src").await;
    let mut etags = Vec::new();
    for (i, half) in halves.iter().enumerate() {
        let n = (i + 1).to_string();
        let sent = rig
            .call(
                &signer,
                Method::Put,
                &path(BUCKET, "src"),
                &[("partNumber", &n), ("uploadId", &id)],
                &[],
                half,
            )
            .await;
        sent.expect(200);
        etags.push(sent.header("etag").unwrap().to_owned());
    }
    complete(&rig, &signer, "src", &id, &etags).await;
    let (generation, extents) = rig.live(&bucket, "src").await.unwrap();
    assert_eq!(extents.len(), 2);
    let catalog = &rig.bridge.catalog;
    for extent in &extents {
        let lease = catalog
            .claim(
                &extent.id,
                &generation.id,
                OutboxStage::Post,
                "test-worker",
                rig.now(),
            )
            .await
            .unwrap()
            .expect("the commit left a claimable posting obligation");
        let job = catalog
            .job_extent(&extent.id, &generation.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rig.bridge.post_stage(&lease, &job).await, JobOutcome::Ack);
        for (store, key) in [
            (&rig.bridge.cache, extent.id.cache_key()),
            (&rig.bridge.safety, extent.id.safety_key()),
        ] {
            store.delete(&key).await.unwrap();
        }
    }
    assert!(rig.bridge.cache.keys().is_empty());
    // Only recovery records are left: no ciphertext is held anywhere.
    assert!(rig
        .bridge
        .safety
        .keys()
        .iter()
        .all(|k| recovery::is_record_key(k)));

    let id = create(&rig, &signer, "dst").await;
    let range = format!("bytes=1-{CAP}");
    let copied = rig
        .call(
            &signer,
            Method::Put,
            &path(BUCKET, "dst"),
            &[("partNumber", "1"), ("uploadId", &id)],
            &[
                ("x-amz-copy-source", &format!("/{BUCKET}/src")),
                ("x-amz-copy-source-range", &range),
            ],
            b"",
        )
        .await;
    copied.expect(200);
    assert_eq!(rig.bridge.budget.in_use(), 0);
    assert!(rig.bridge.budget.peak() <= rig.bridge.budget.capacity());
    let etag = copied.values("ETag").remove(0).replace("&quot;", "\"");
    complete(&rig, &signer, "dst", &id, &[etag]).await;

    let read = rig
        .call(&signer, Method::Get, &path(BUCKET, "dst"), &[], &[], b"")
        .await;
    read.expect(200);
    assert!(read.body == [&halves[0][1..], &halves[1][..1]].concat());
}
