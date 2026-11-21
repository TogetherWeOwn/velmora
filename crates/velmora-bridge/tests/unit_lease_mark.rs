//! The write mark: every write of the catalogue goes through
//! [`MarkedSql`], the one function that raises it (ADR-TENANCY §8.6,
//! RD-8).
//!
//! The catalogue runs over `MarkedSql<AuditSql>`. `AuditSql` sits below
//! the mark and, for every call that reaches the database, compares the
//! database's change count before and after: a call that changed a row
//! while no write was under way in the mark ([`WriteMark::writing`]) is a
//! violation. The S3
//! paths, multipart, the cron dispatcher, GC and the stamp all run over
//! it. A second test runs a write beside the mark and shows that the
//! audit catches it, so the first test cannot pass by auditing nothing.

#![allow(async_fn_in_trait)]

mod nntp_support;
mod service_support;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use service_support::*;
use velmora::rng::SystemRng;
use velmora_bridge::crypto::{wrap_bdk, wrap_secret, DataKey};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FixedClock, RusqliteSql, TestKek};
use velmora_bridge::unit_lease::mark::{exact, MarkedSql, WriteMark};
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const BUCKET: &str = "marked";

/// The database below the mark. See the module text.
struct AuditSql {
    inner: RusqliteSql,
    mark: Rc<WriteMark>,
    /// Calls that changed a row.
    changing: Cell<u64>,
    /// Statements that changed a row without the mark moving.
    violations: RefCell<Vec<String>>,
}

impl AuditSql {
    fn new(mark: Rc<WriteMark>) -> AuditSql {
        AuditSql {
            inner: RusqliteSql::with_schema().unwrap(),
            mark,
            changing: Cell::new(0),
            violations: RefCell::new(Vec::new()),
        }
    }

    fn changes(&self) -> u64 {
        self.inner.with_conn(|c| c.total_changes())
    }

    /// Runs one call and checks it.
    async fn audit<V>(
        &self,
        what: &str,
        call: impl std::future::Future<Output = Result<V>>,
    ) -> Result<V> {
        let raised = self.mark.writing();
        let before = self.changes();
        let out = call.await;
        if self.changes() != before {
            self.changing.set(self.changing.get() + 1);
            if !raised {
                self.violations.borrow_mut().push(what.to_string());
            }
        }
        out
    }
}

impl Sql for AuditSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.audit(sql, self.inner.query(sql, params)).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.audit(sql, self.inner.exec(sql, params)).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        let what = stmts.first().map_or("", |s| s.0).to_string();
        self.audit(&what, self.inner.batch(stmts)).await
    }
    async fn query_after_refusal(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.audit(sql, self.inner.query_after_refusal(sql, params))
            .await
    }
    fn limits(&self) -> SqlLimits {
        self.inner.limits()
    }
}

type MarkedBridge<N> = Bridge<SqlCatalog<MarkedSql<AuditSql>>, Blobs, N, Jobs, TestKek, FixedClock>;

struct MarkRig<N: NntpConnector + 'static = NoNntp> {
    bridge: Rc<MarkedBridge<N>>,
    mark: Rc<WriteMark>,
}

impl MarkRig {
    fn new() -> MarkRig {
        MarkRig::with(NoNntp, Vec::new())
    }
}

impl<N: NntpConnector + 'static> MarkRig<N> {
    fn with(nntp: N, providers: Vec<ProviderConfig>) -> MarkRig<N> {
        let mark = Rc::new(WriteMark::new([7; 16]));
        let cfg = config(providers);
        let bridge = Rc::new(Bridge {
            catalog: SqlCatalog::new(MarkedSql::new(AuditSql::new(mark.clone()), mark.clone())),
            safety: Blobs::default(),
            cache: Blobs::default(),
            nntp,
            jobs: Jobs::default(),
            kek: TestKek::new(),
            clock: FixedClock::new(T0),
            budget: ByteBudget::new(cfg.inflight_budget_bytes),
            cfg,
        });
        MarkRig { bridge, mark }
    }

    fn audit(&self) -> &AuditSql {
        self.bridge.catalog.sql.unmarked()
    }

    async fn setup(&self) -> Signer {
        let mut rng = SystemRng;
        let id = BucketId::mint([9; 8]);
        let bdk = DataKey::generate(&mut rng).unwrap();
        let (kek_version, wrapped) = wrap_bdk(&self.bridge.kek, &id, &bdk, &mut rng).unwrap();
        let bucket = Bucket {
            id,
            name: BUCKET.to_string(),
            owner: "owner".to_string(),
            bdk_wrapped: wrapped.to_vec(),
            kek_version,
            disposable: true,
            created_at: T0,
        };
        let c = &self.bridge.catalog;
        assert_eq!(c.create_bucket(&bucket).await.unwrap(), Guard::Applied(()));
        let (kek_version, secret_wrapped) =
            wrap_secret(&self.bridge.kek, AKID, secret().as_bytes(), &mut rng).unwrap();
        c.create_access_key(&AccessKeyRow {
            access_key_id: AKID.to_string(),
            principal: format!("principal-{AKID}"),
            secret_wrapped,
            kek_version,
            status: KeyStatus::Active,
            created_at: T0,
        })
        .await
        .unwrap();
        c.put_grant(AKID, &bucket.id, Perm::Rw).await.unwrap();
        Signer::new(AKID, secret())
    }

    async fn call(
        &self,
        signer: &Signer,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Resp {
        let req = signer.sign(
            self.bridge.clock.now(),
            method,
            &path(BUCKET, key),
            query,
            headers,
            body.to_vec(),
        );
        Resp::collect(Rc::clone(&self.bridge).handle(req.into_request()).await).await
    }
}

/// The S3 paths, multipart, the dispatcher, GC and the stamp write only
/// through the mark: no call below it changes a row unless the mark
/// moved for that call.
#[tokio::test(flavor = "current_thread")]
async fn every_write_of_the_catalogue_raises_the_mark() {
    let rig = MarkRig::new();
    let signer = rig.setup().await;

    rig.call(&signer, Method::Put, "small", &[], &[], b"hello")
        .await
        .expect(200);
    let big = pattern(3, 6 * MIB);
    rig.call(&signer, Method::Put, "big", &[], &[], &big)
        .await
        .expect(200);
    rig.call(&signer, Method::Head, "small", &[], &[], b"")
        .await
        .expect(200);
    rig.call(&signer, Method::Get, "big", &[], &[], b"")
        .await
        .expect(200);
    rig.call(
        &signer,
        Method::Put,
        "copy",
        &[],
        &[("x-amz-copy-source", &format!("/{BUCKET}/small"))],
        b"",
    )
    .await
    .expect(200);
    rig.call(&signer, Method::Get, "", &[("list-type", "2")], &[], b"")
        .await
        .expect(200);

    // Multipart: create, two parts, complete; a second upload aborted.
    let created = rig
        .call(&signer, Method::Post, "parts", &[("uploads", "")], &[], b"")
        .await;
    created.expect(200);
    let id = created.values("UploadId").remove(0);
    let mut etags = Vec::new();
    for (n, bytes) in [("1", pattern(4, 5 * MIB)), ("2", pattern(5, 1000))] {
        let sent = rig
            .call(
                &signer,
                Method::Put,
                "parts",
                &[("partNumber", n), ("uploadId", &id)],
                &[],
                &bytes,
            )
            .await;
        sent.expect(200);
        etags.push(sent.header("etag").unwrap().to_owned());
    }
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in etags.iter().enumerate() {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
            i + 1
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        &signer,
        Method::Post,
        "parts",
        &[("uploadId", &id)],
        &[("content-type", "application/xml")],
        xml.as_bytes(),
    )
    .await
    .expect(200);
    let other = rig
        .call(
            &signer,
            Method::Post,
            "dropped",
            &[("uploads", "")],
            &[],
            b"",
        )
        .await
        .values("UploadId")
        .remove(0);
    rig.call(
        &signer,
        Method::Put,
        "dropped",
        &[("partNumber", "1"), ("uploadId", &other)],
        &[],
        b"part",
    )
    .await
    .expect(200);
    rig.call(
        &signer,
        Method::Delete,
        "dropped",
        &[("uploadId", &other)],
        &[],
        b"",
    )
    .await
    .expect(204);

    // Overwrite and delete: rows for GC.
    rig.call(&signer, Method::Put, "small", &[], &[], b"again")
        .await
        .expect(200);
    rig.call(&signer, Method::Delete, "copy", &[], &[], b"")
        .await
        .expect(204);

    // The cron work, GC and the stamp.
    rig.bridge.clock.advance_secs(3600);
    rig.bridge.dispatch().await.unwrap();
    assert_eq!(
        rig.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    rig.bridge.raise_stamp().await.unwrap();
    rig.bridge.dispatch().await.unwrap();

    let audit = rig.audit();
    assert_eq!(
        audit.violations.borrow().as_slice(),
        &[] as &[String],
        "statements that wrote past the mark"
    );
    assert!(
        audit.changing.get() >= 30,
        "the workload wrote: {} changing calls",
        audit.changing.get()
    );
    assert!(rig.mark.mark().writes >= audit.changing.get());
}

/// The job pipeline: post, verify and release over a test NNTP server,
/// with the dispatcher handing the jobs out, write only through the mark.
#[tokio::test(flavor = "current_thread")]
async fn the_post_verify_release_pipeline_writes_only_through_the_mark() {
    let mut server_cfg = ServerConfig::for_test();
    server_cfg.articles = Vec::new();
    server_cfg.missing_ids.clear();
    server_cfg.users.insert(
        nntp_support::USER.to_string(),
        UserConfig {
            password: nntp_support::PASS.to_string(),
            max_connections: 2,
        },
    );
    let server = TestNntpServer::spawn(server_cfg).await;
    let provider = ProviderConfig {
        id: "p0".to_string(),
        host: server.addr().ip().to_string(),
        hosts: Vec::new(),
        host_select: Default::default(),
        port: server.addr().port(),
        tls: false,
        user: nntp_support::USER.to_string(),
        pass: nntp_support::PASS.to_string(),
        backbone: "bb0".to_string(),
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
    };
    let rig = MarkRig::with(nntp_support::TcpConnector::default(), vec![provider]);
    let signer = rig.setup().await;
    let body = nntp_support::marked_plaintext(2 * 1024 * 1024 + 4321);
    rig.call(&signer, Method::Put, "posted", &[], &[], &body)
        .await
        .expect(200);

    rig.bridge.dispatch().await.unwrap();
    let mut queue: Vec<(UnixMs, Job)> = Vec::new();
    let mut runs = 0;
    loop {
        let now = rig.bridge.clock.now();
        for sent in rig.bridge.jobs.inner.take() {
            queue.push((now.plus_secs(sent.delay_secs), sent.job));
        }
        if queue.is_empty() {
            break;
        }
        queue.sort_by_key(|(due, _)| *due);
        let (due, job) = queue.remove(0);
        if due > rig.bridge.clock.now() {
            rig.bridge.clock.set(due);
        }
        runs += 1;
        assert!(runs < 200, "the queue does not drain");
        if let JobOutcome::Retry { delay_secs } = rig.bridge.run_job(&job).await {
            queue.push((rig.bridge.clock.now().plus_secs(delay_secs), job));
        }
    }
    rig.bridge.dispatch().await.unwrap();

    let state = rig
        .bridge
        .catalog
        .sql
        .query("SELECT safety_state FROM extents", &[])
        .await
        .unwrap();
    assert_eq!(
        state,
        vec![vec![SqlValue::Text("released".to_string())]],
        "posted, verified and released"
    );
    assert!(server.posted_count().await >= 3);
    let audit = rig.audit();
    assert_eq!(
        audit.violations.borrow().as_slice(),
        &[] as &[String],
        "statements that wrote past the mark"
    );
    assert!(audit.changing.get() >= 10);
}

/// A write run beside the mark is caught by the audit: the test above
/// would fail for any catalogue path that reached the database past the
/// mark.
#[tokio::test(flavor = "current_thread")]
async fn a_write_beside_the_mark_is_caught() {
    let rig = MarkRig::new();
    rig.setup().await;
    assert!(rig.audit().violations.borrow().is_empty());

    let before = rig.mark.mark();
    rig.audit()
        .exec("UPDATE buckets SET name = name", &[])
        .await
        .unwrap();
    assert_eq!(rig.mark.mark(), before, "the mark did not see it");
    assert_eq!(rig.audit().violations.borrow().len(), 1);
}

/// A read moves no mark, so a dump over reads only is `exact`; one write
/// between two pages makes it `fuzzy`; a new wake does too.
#[tokio::test(flavor = "current_thread")]
async fn pages_with_one_mark_are_exact() {
    let rig = MarkRig::new();
    rig.setup().await;
    let c = &rig.bridge.catalog;

    let first = rig.mark.mark();
    c.stamp(&rig.bridge.cfg.catalogue_id).await.unwrap();
    c.sql
        .query(
            "SELECT count(*) FROM buckets WHERE updated_at IS NULL OR 1",
            &[],
        )
        .await
        .ok();
    let second = rig.mark.mark();
    assert!(exact(&[first, second]));

    rig.bridge.raise_stamp().await.unwrap();
    let third = rig.mark.mark();
    assert!(!exact(&[first, second, third]));

    let woken = WriteMark::new([8; 16]).mark();
    assert_eq!(woken.writes, 0);
    assert!(!exact(&[WriteMark::new([7; 16]).mark(), woken]));
}
