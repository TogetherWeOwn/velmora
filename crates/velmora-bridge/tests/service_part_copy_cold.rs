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

/// What a copy reads from: the rig, its provider, and a source of two
/// full-size extents with their plaintext.
struct Source {
    rig: ColdRig,
    server: TestNntpServer,
    signer: Signer,
    halves: [Vec<u8>; 2],
    extents: Vec<ExtentRow>,
}

/// A source of two full-size extents that are only on Usenet (with
/// their parity, if `parity`), under a byte budget of `budget`.
async fn cold_source(budget: u64, parity: bool) -> Source {
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
        hosts: Vec::new(),
        host_select: Default::default(),
        port: server.addr().port(),
        tls: false,
        user: USER.to_string(),
        pass: PASS.to_string(),
        backbone: "alpha".to_string(),
        post: true,
        read: true,
        max_conns: 2,
        max_ips: None,
        drill_conns: 0,
        priority: 0,
        retention_days: None,
        pool: None,
        pool_max_conns: None,
        proxies: Vec::new(),
        enabled: true,
        release: true,
    }]);
    cfg.max_extent_bytes = CAP as u64;
    cfg.inflight_budget_bytes = budget;
    cfg.packed_plans = parity;
    cfg.parity = parity;
    cfg.hot_ctl.mode = velmora_bridge::config::HotCtlMode::Shadow;
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

    Source {
        rig,
        server,
        signer,
        halves,
        extents,
    }
}

/// Copies all but the first byte of the first extent and the first byte
/// of the second into a new object, and reads that back.
async fn copy_across(src: &Source) {
    let Source {
        rig,
        signer,
        halves,
        ..
    } = src;
    let id = create(rig, signer, "dst").await;
    let range = format!("bytes=1-{CAP}");
    let copied = rig
        .call(
            signer,
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
    assert_eq!(
        rig.bridge
            .catalog
            .hot_ctl_load(&velmora_bridge::hotctl::MISS_KEYS)
            .await
            .unwrap(),
        vec![None; velmora_bridge::hotctl::MISS_BUCKETS],
        "server-side copies are not customer misses"
    );
    assert_eq!(rig.bridge.budget.in_use(), 0);
    assert!(rig.bridge.budget.peak() <= rig.bridge.budget.capacity());
    let etag = copied.values("ETag").remove(0).replace("&quot;", "\"");
    complete(rig, signer, "dst", &id, &[etag]).await;

    let read = rig
        .call(signer, Method::Get, &path(BUCKET, "dst"), &[], &[], b"")
        .await;
    read.expect(200);
    assert!(read.body == [&halves[0][1..], &halves[1][..1]].concat());
}

#[tokio::test(flavor = "current_thread")]
async fn copy_part_without_a_provider_slot_reports_slot_wait() {
    use std::rc::Rc;
    use velmora_bridge::metrics::{request_point, Request, RequestObservation};

    let src = cold_source(3 * CAP as u64, false).await;
    let rig = &src.rig;
    let id = create(rig, &src.signer, "dst").await;
    let provider = &rig.bridge.cfg.providers[0];
    let mut held = Vec::new();
    for n in 0..provider.max_conns {
        held.push(
            rig.bridge
                .catalog
                .acquire_permit(
                    provider,
                    PermitClass::Read,
                    &format!("reader-{n}"),
                    rig.now(),
                )
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let request = src.signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, "dst"),
        &[("partNumber", "1"), ("uploadId", &id)],
        &[
            ("x-amz-copy-source", &format!("/{BUCKET}/src")),
            ("x-amz-copy-source-range", "bytes=0-0"),
        ],
        vec![],
    );
    let mut get = RequestObservation::default();
    let raw = Rc::clone(&rig.bridge)
        .handle_observed(request.into_request(), &mut get)
        .await;
    let resp = Resp::collect(raw).await;
    resp.expect_error(503, "SlowDown");
    for permit in &held {
        rig.bridge.catalog.release_permit(permit).await.unwrap();
    }
    let point = request_point(
        &Request {
            method: "PUT",
            admin: false,
            sub: false,
            status: resp.status,
            latency_ms: 0,
            bytes_in: 0,
            bytes_out: 0,
            colo: "IAD",
            get,
        },
        1,
    );
    assert_eq!(
        point.analytics_blobs().collect::<Vec<_>>(),
        ["req", "PUT", "5xx", "s3", "IAD", "slot_wait", "unknown"]
    );
}

/// A range that takes all but one byte of a part from one cold extent and
/// its last byte from the next, which is cold and full-size. Reading that
/// extent back needs twice its size; beside the piece already held that
/// is more than the budget has. It is read on its own first.
#[tokio::test(flavor = "current_thread")]
async fn a_range_that_ends_in_a_cold_full_size_extent_fits_the_budget() {
    // The shipped ratio: the budget is three extents.
    let src = cold_source(3 * CAP as u64, false).await;
    copy_across(&src).await;
}

/// The same range where the budget has room for the read of the second
/// extent beside the piece already held, but not for that and a rebuild
/// from its parity, and the extent lost as many articles as it has parity. It is
/// read on its own first as well: the rebuild fits when nothing else is
/// held.
#[tokio::test(flavor = "current_thread")]
async fn a_range_that_ends_in_a_cold_extent_to_rebuild_fits_the_budget() {
    let budget = 20 * MIB as u64;
    let src = cold_source(budget, true).await;
    let extent = &src.extents[1];
    let catalog = &src.rig.bridge.catalog;
    let stored = catalog.stored_plan(&extent.id).await.unwrap();
    let parity = stored
        .parity_plan(&extent.id, extent.cipher_size)
        .unwrap()
        .expect("the extent has parity");
    let sockets = src.rig.bridge.cfg.cold_sockets;
    let held = CAP as u64 - 1;
    let read = velmora_bridge::fetch::cold_read_bytes(extent.cipher_size, sockets);
    let step = velmora_bridge::fetch::cold_step_bytes(extent.cipher_size, sockets);
    let most = parity.articles.len();
    assert_eq!(most, 2);
    let rebuild = velmora_bridge::fetch::cold_rebuild_bytes(u64::from(parity.shard_len), 2);
    assert!(
        held + read <= budget && held + step + rebuild > budget,
        "{held} {read} {step} {rebuild}"
    );
    assert!(step + rebuild <= budget);
    for row in &stored.rows[1..=most] {
        src.server.hide(&format!("<{}>", row.message_id)).await;
    }

    copy_across(&src).await;
}

/// A GET whose cold read fails on the catalogue (the provider slot it
/// takes) logs the stage, the variant and the class of that failure.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_cold_read_logs_its_stage_variant_and_code() {
    use std::rc::Rc;
    use velmora_bridge::metrics::RequestObservation;

    let src = cold_source(3 * CAP as u64, false).await;
    let rig = &src.rig;
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() =
        Some(("UPDATE provider_permits SET token = token + 1", 0));
    let request = src.signer.sign(
        rig.now(),
        Method::Get,
        &path(BUCKET, "src"),
        &[],
        &[("range", "bytes=0-0")],
        vec![],
    );
    let mut observed = RequestObservation::default();
    let raw = Rc::clone(&rig.bridge)
        .handle_observed(request.into_request(), &mut observed)
        .await;
    let resp = Resp::collect(raw).await;
    rig.bridge.catalog.sql.fail_matching.borrow_mut().take();
    resp.expect_error(500, "InternalError");
    assert_eq!(observed.log_fields(), "stage=lookup err=Sql code=sql_other");
}
