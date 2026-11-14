//! `SqlCatalog` outbox leases, article plans, verification counting,
//! release and GC rows over SQLite with the D1 schema.
//!
//! Objects are published through the multipart path, so the rows under
//! test are the ones the catalogue itself writes. Every statement goes
//! through [`Probe`], which refuses more than 100 bound parameters.

use std::cell::Cell;

use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{PublishUnrecorded, RusqliteSql};
use velmora_bridge::*;

const T0: UnixMs = UnixMs(1_762_992_000_123);
const LEASE_MS: i64 = 600_000;
const HOUR_MS: i64 = 3_600_000;

struct Probe(RusqliteSql);

fn check_params(params: &[SqlValue]) {
    assert!(params.len() <= 100, "statement binds {}", params.len());
}

impl Sql for Probe {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        check_params(params);
        self.0.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        check_params(params);
        self.0.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        stmts.iter().for_each(|(_, p)| check_params(p));
        self.0.batch(stmts).await
    }
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}

struct Fx {
    cat: SqlCatalog<Probe>,
    seed: Cell<u8>,
    bucket: BucketId,
    real_bucket: BucketId,
}

/// A published single-extent object.
struct Obj {
    extent: ExtentId,
    generation: GenerationId,
}

impl Fx {
    async fn new() -> Fx {
        let fx = Fx {
            cat: SqlCatalog::new(Probe(RusqliteSql::with_schema().unwrap())),
            seed: Cell::new(1),
            bucket: BucketId::mint([0xb1; 8]),
            real_bucket: BucketId::mint([0xb2; 8]),
        };
        for (id, name, disposable) in [(&fx.bucket, "scratch", 1), (&fx.real_bucket, "real", 0)] {
            fx.run(
                "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, \
                 created_at) VALUES (?1, ?2, 'owner', x'07', 1, ?3, 0)",
                &[text(id.as_str()), text(name), SqlValue::Int(disposable)],
            )
            .await;
        }
        fx
    }

    fn next(&self) -> u8 {
        let n = self.seed.get();
        self.seed.set(n + 1);
        n
    }

    async fn run(&self, sql: &str, params: &[SqlValue]) -> u64 {
        self.cat.sql.0.exec(sql, params).await.unwrap()
    }

    async fn count(&self, sql: &str) -> i64 {
        match self.cat.sql.0.query(sql, &[]).await.unwrap()[0][0] {
            SqlValue::Int(n) => n,
            ref other => panic!("not an integer: {other:?}"),
        }
    }

    /// Every row of the tables a job writes, for "nothing changed" checks.
    async fn dump(&self) -> Vec<Row> {
        let mut out = Vec::new();
        for sql in [
            "SELECT * FROM outbox ORDER BY extent_id",
            "SELECT * FROM articles ORDER BY extent_id, idx",
            "SELECT * FROM verifications ORDER BY extent_id, backbone, verified_at",
            "SELECT id, safety_state, article_count, plan_rev, last_verified_at, \
             release_evidence, released_at, wrapped_file_key FROM extents ORDER BY id",
        ] {
            out.extend(self.cat.sql.0.query(sql, &[]).await.unwrap());
        }
        out
    }

    /// One outbox column of an object's row, as text.
    async fn outbox(&self, o: &Obj, column: &str) -> String {
        let sql = format!("SELECT CAST({column} AS TEXT) FROM outbox WHERE extent_id = ?1");
        let rows = self
            .cat
            .sql
            .0
            .query(&sql, &[text(o.extent.as_str())])
            .await
            .unwrap();
        match &rows[0][0] {
            SqlValue::Text(s) => s.clone(),
            SqlValue::Null => "NULL".into(),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Publishes a one-part object under `key` through the multipart path.
    async fn publish(&self, bucket: &BucketId, key: &str) -> Obj {
        let n = self.next();
        let id = UploadId::mint([n; 16]);
        self.cat
            .create_upload(&UploadRow {
                id: id.clone(),
                bucket_id: bucket.clone(),
                key: key.into(),
                content_json: "{}".into(),
                user_meta_json: "{}".into(),
                state: UploadState::Open,
                revision: 0,
                completed_generation_id: None,
                complete_digest: None,
                result_etag: None,
                initiated_at: T0,
            })
            .await
            .unwrap();
        let t = UploadTarget {
            bucket,
            key,
            id: &id,
        };
        let extent = ExtentRow {
            id: ExtentId::mint([n; 13]),
            bucket_id: bucket.clone(),
            generation_id: None,
            state: ExtentState::Staged,
            seq: None,
            plain_offset: None,
            plain_size: 1000,
            cipher_size: 1064,
            media_header: vec![n; 48],
            key_mode: 1,
            wrapped_file_key: Some(vec![n; 73]),
            plain_md5: [n; 16],
            plain_sha256: [n; 32],
            cipher_sha256: [n; 32],
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: T0,
        };
        let part = UploadPartRow {
            upload_id: id.clone(),
            part_number: 1,
            extent_id: extent.id.clone(),
            size: 1000,
            etag: "\"p\"".into(),
            uploaded_at: T0,
        };
        assert_eq!(
            self.cat
                .put_upload_part(&t, &part, &extent, T0)
                .await
                .unwrap(),
            Guard::Applied(())
        );
        let generation = GenerationRow {
            id: GenerationId::mint(T0, [n; 8]),
            bucket_id: bucket.clone(),
            key: key.into(),
            state: GenerationState::Live,
            size: 1000,
            etag: "\"e-1\"".into(),
            checksum_json: None,
            content_json: "{}".into(),
            user_meta_json: "{}".into(),
            extent_count: 1,
            created_at: T0,
            retired_at: None,
        };
        let c = CompleteUpload {
            generation: generation.clone(),
            placements: vec![ExtentPlacement {
                extent_id: extent.id.clone(),
                seq: 0,
                plain_offset: 0,
            }],
            now: T0,
        };
        assert_eq!(
            self.cat.publish_upload(&t, 1, &[n; 32], &c).await.unwrap(),
            Guard::Applied(())
        );
        Obj {
            extent: extent.id,
            generation: generation.id,
        }
    }

    async fn claim(&self, o: &Obj, stage: OutboxStage, now: UnixMs) -> Option<Lease> {
        self.cat
            .claim(&o.extent, &o.generation, stage, "job", now)
            .await
            .unwrap()
    }

    /// A plan of `n` articles whose message-ids start with `tag`.
    fn plan(&self, o: &Obj, tag: &str, n: u32) -> Vec<ArticleRow> {
        (0..n)
            .map(|idx| ArticleRow {
                extent_id: o.extent.clone(),
                idx,
                message_id: format!("{tag}-{idx}@example.invalid"),
                newsgroup: "alt.binaries.test".into(),
                headers: format!("Subject: {tag}-{idx}\r\n").into_bytes(),
                cipher_offset: u64::from(idx) * 100,
                cipher_len: 100,
                payload_sha256: [idx as u8; 32],
                state: ArticleState::Planned,
                provider_id: None,
                posted_at: None,
            })
            .collect()
    }

    /// Claims, plans `n` articles, marks them posted and advances to
    /// verify (due at once). Returns the verify lease.
    async fn posted(&self, o: &Obj, n: u32, now: UnixMs) -> Lease {
        let post = self.claim(o, OutboxStage::Post, now).await.unwrap();
        let plan = self.plan(o, o.extent.as_str(), n);
        self.cat.plan_articles(&post, &plan).await.unwrap().unwrap();
        for idx in 0..n {
            assert!(self.cat.mark_posted(&post, idx, "p1", now).await.unwrap());
        }
        assert!(self
            .cat
            .advance(&post, OutboxStage::Verify, now, now)
            .await
            .unwrap());
        self.claim(o, OutboxStage::Verify, now).await.unwrap()
    }

    #[allow(clippy::too_many_arguments)] // a test shorthand, one argument per column
    async fn verify(
        &self,
        l: &Lease,
        backbone: &str,
        provider: &str,
        at: UnixMs,
        ok: u32,
        total: u32,
        result: VerifyResult,
    ) -> bool {
        let v = VerificationRow {
            extent_id: l.extent.clone(),
            backbone: backbone.into(),
            provider_id: provider.into(),
            verified_at: at,
            plan_rev: 1,
            articles_ok: ok,
            articles_total: total,
            result,
        };
        self.cat.record_verification(l, &v).await.unwrap()
    }

    /// Backbones that count, in order.
    async fn counting(&self, o: &Obj) -> Vec<String> {
        let all = self.cat.backbone_status(&o.extent).await.unwrap();
        all.into_iter()
            .filter(|b| b.counts)
            .map(|b| b.backbone)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claim_takes_a_due_row_once_and_tokens_only_grow() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;

    // Wrong stage, wrong generation, terminal stage: nothing.
    assert!(fx.claim(&o, OutboxStage::Verify, T0).await.is_none());
    let other = GenerationId::mint(T0, [0xaa; 8]);
    let wrong = fx
        .cat
        .claim(&o.extent, &other, OutboxStage::Post, "job", T0)
        .await
        .unwrap();
    assert!(wrong.is_none());
    assert!(fx.claim(&o, OutboxStage::Done, T0).await.is_none());
    assert_eq!(fx.outbox(&o, "lease_token").await, "0");

    let a = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();
    assert_eq!((a.token, a.attempts, a.cursor), (1, 1, 0));
    assert_eq!(a.stage, OutboxStage::Post);
    assert_eq!(
        fx.outbox(&o, "lease_until").await,
        (T0.0 + LEASE_MS).to_string()
    );
    // Duplicate delivery while leased, up to and including the expiry instant.
    assert!(fx.claim(&o, OutboxStage::Post, T0).await.is_none());
    assert!(fx
        .claim(&o, OutboxStage::Post, T0.plus_ms(LEASE_MS))
        .await
        .is_none());
    // A renewal moves the expiry.
    assert!(fx.cat.renew(&a, T0.plus_ms(LEASE_MS)).await.unwrap());
    assert!(fx
        .claim(&o, OutboxStage::Post, T0.plus_ms(LEASE_MS + 1))
        .await
        .is_none());
    let b = fx
        .claim(&o, OutboxStage::Post, T0.plus_ms(2 * LEASE_MS + 1))
        .await
        .unwrap();
    assert_eq!((b.token, b.attempts), (2, 2));
}

#[tokio::test]
async fn next_at_backoff_is_respected() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let a = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();
    let retry_at = T0.plus_secs(120);
    assert!(fx
        .cat
        .fail(&a, FailClass::NntpError, retry_at, T0.plus_ms(10))
        .await
        .unwrap());
    assert_eq!(fx.outbox(&o, "last_error").await, "nntp-error");
    // Giving the lease up spends it at once, before anyone else claims.
    let before = fx.dump().await;
    assert!(!fx.cat.set_cursor(&a, 7, T0).await.unwrap());
    assert!(!fx.cat.mark_posted(&a, 0, "p1", T0).await.unwrap());
    assert!(!fx
        .cat
        .advance(&a, OutboxStage::Verify, T0, T0)
        .await
        .unwrap());
    assert_eq!(fx.dump().await, before);
    assert_eq!(fx.outbox(&o, "lease_until").await, "NULL");

    // The lease is free, but the row is not due: no claim, not in `due`.
    let early = retry_at.plus_ms(-1);
    assert!(fx.claim(&o, OutboxStage::Post, early).await.is_none());
    assert!(fx.cat.due(early, 100).await.unwrap().is_empty());
    assert_eq!(fx.outbox(&o, "attempts").await, "1");

    assert_eq!(
        fx.cat.due(retry_at, 100).await.unwrap(),
        vec![DueRow {
            extent_id: o.extent.clone(),
            generation_id: o.generation.clone(),
            stage: OutboxStage::Post
        }]
    );
    let b = fx.claim(&o, OutboxStage::Post, retry_at).await.unwrap();
    assert_eq!(b.attempts, 2);
    assert!(b.token > a.token);
    // The lease that failed is dead, even though no one else had claimed yet.
    assert!(!fx.cat.renew(&a, retry_at).await.unwrap());

    // `defer` (no permit) backs off without consuming the attempt.
    let later = retry_at.plus_secs(30);
    assert!(fx.cat.defer(&b, later, retry_at).await.unwrap());
    assert_eq!(fx.outbox(&o, "attempts").await, "1");
    assert!(!fx.cat.fail(&b, FailClass::Internal, T0, T0).await.unwrap());
    assert!(!fx.cat.renew(&b, retry_at).await.unwrap());
    assert!(fx
        .claim(&o, OutboxStage::Post, later.plus_ms(-1))
        .await
        .is_none());
    let c = fx.claim(&o, OutboxStage::Post, later).await.unwrap();
    assert_eq!(c.attempts, 2);
    assert!(c.token > b.token);
}

#[tokio::test]
async fn advance_restarts_attempts_and_cursor_and_carries_next_at() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let a = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();
    assert!(fx.cat.set_cursor(&a, 3, T0).await.unwrap());
    let verify_at = T0.plus_secs(30);
    assert!(fx
        .cat
        .advance(&a, OutboxStage::Verify, verify_at, T0)
        .await
        .unwrap());
    // The old lease is spent; the new stage is not due yet.
    assert!(!fx
        .cat
        .advance(&a, OutboxStage::Verify, T0, T0)
        .await
        .unwrap());
    assert!(fx.claim(&o, OutboxStage::Post, verify_at).await.is_none());
    assert!(fx.claim(&o, OutboxStage::Verify, T0).await.is_none());
    let v = fx.claim(&o, OutboxStage::Verify, verify_at).await.unwrap();
    assert_eq!((v.attempts, v.cursor), (1, 0));
    assert!(v.token > a.token);
    // The cursor survives a re-claim within the stage.
    assert!(fx.cat.set_cursor(&v, 2, verify_at).await.unwrap());
    assert!(fx.cat.defer(&v, verify_at, verify_at).await.unwrap());
    let v2 = fx.claim(&o, OutboxStage::Verify, verify_at).await.unwrap();
    assert_eq!((v2.attempts, v2.cursor), (1, 2));
}

// ---------------------------------------------------------------------------
// Fencing
// ---------------------------------------------------------------------------

/// The lease expires while its holder is stuck in a POST; another job
/// takes the row over. Nothing the old holder does afterwards is written.
#[tokio::test]
async fn stale_lease_is_fenced() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let stale = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();
    let plan = fx.plan(&o, "first", 3);
    let stored = fx.cat.plan_articles(&stale, &plan).await.unwrap().unwrap();
    assert_eq!(stored.len(), 3);
    assert!(fx.cat.mark_posted(&stale, 0, "p1", T0).await.unwrap());

    let t1 = T0.plus_ms(LEASE_MS + 1);
    let owner = fx.claim(&o, OutboxStage::Post, t1).await.unwrap();
    assert!(owner.token > stale.token);
    let before = fx.dump().await;

    let c = &fx.cat;
    assert!(!c.renew(&stale, t1).await.unwrap());
    assert!(!c.mark_posted(&stale, 1, "p1", t1).await.unwrap());
    assert!(!c.set_cursor(&stale, 9, t1).await.unwrap());
    assert_eq!(
        c.plan_articles(&stale, &fx.plan(&o, "other", 2))
            .await
            .unwrap(),
        None
    );
    assert!(
        !fx.verify(&stale, "bb", "p1", t1, 3, 3, VerifyResult::Ok)
            .await
    );
    assert!(!c
        .advance(&stale, OutboxStage::Verify, t1, t1)
        .await
        .unwrap());
    assert!(!c.fail(&stale, FailClass::Internal, t1, t1).await.unwrap());
    assert!(!c.defer(&stale, t1, t1).await.unwrap());
    assert!(!c.finish_release(&stale, t1).await.unwrap());
    assert_eq!(fx.dump().await, before, "a stale lease wrote something");

    // The owner is unaffected and finishes the stage.
    assert!(c.mark_posted(&owner, 1, "p1", t1).await.unwrap());
    assert!(c.mark_posted(&owner, 2, "p1", t1).await.unwrap());
    assert!(c
        .advance(&owner, OutboxStage::Verify, t1, t1)
        .await
        .unwrap());

    // Same in the later stages: a stale verify or release lease records
    // no verification and cannot start or finish a release.
    let stale_v = fx.claim(&o, OutboxStage::Verify, t1).await.unwrap();
    let t2 = t1.plus_ms(LEASE_MS + 1);
    let v = fx.claim(&o, OutboxStage::Verify, t2).await.unwrap();
    assert!(
        !fx.verify(&stale_v, "bb", "p1", t2, 3, 3, VerifyResult::Ok)
            .await
    );
    assert!(fx.verify(&v, "bb", "p1", t2, 3, 3, VerifyResult::Ok).await);
    assert!(c.advance(&v, OutboxStage::Release, t2, t2).await.unwrap());
    let stale_r = fx.claim(&o, OutboxStage::Release, t2).await.unwrap();
    let t3 = t2.plus_ms(LEASE_MS + 1);
    let r = fx.claim(&o, OutboxStage::Release, t3).await.unwrap();
    assert!(fx.verify(&r, "bb", "p1", t3, 3, 3, VerifyResult::Ok).await);
    let before = fx.dump().await;
    assert_eq!(
        c.begin_release(&stale_r, 1, "[]", t3).await.unwrap(),
        Guard::Lost
    );
    assert!(!c.finish_release(&stale_r, t3).await.unwrap());
    assert_eq!(
        fx.dump().await,
        before,
        "a stale release lease wrote something"
    );
    assert_eq!(
        c.begin_release(&r, 1, "[]", t3).await.unwrap(),
        Guard::Applied(())
    );
    // The owner began; the stale lease still cannot finish for it.
    let before = fx.dump().await;
    assert!(!c.finish_release(&stale_r, t3).await.unwrap());
    assert_eq!(fx.dump().await, before);
    assert!(c.finish_release(&r, t3).await.unwrap());
}

/// The object is overwritten while a job holds the lease. The cancelled
/// row stays cancelled: the job's completion writes nothing.
#[tokio::test]
async fn cancellation_beats_stale_completion() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let lease = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();
    let plan = fx.plan(&o, "m", 2);
    fx.cat.plan_articles(&lease, &plan).await.unwrap().unwrap();

    // Overwrite: the first generation is retired and its row cancelled.
    let newer = fx.publish(&fx.bucket, "k").await;
    assert_eq!(fx.outbox(&o, "stage").await, "cancelled");
    let before = fx.dump().await;

    let c = &fx.cat;
    assert!(!c.mark_posted(&lease, 0, "p1", T0).await.unwrap());
    assert!(!c
        .advance(&lease, OutboxStage::Verify, T0, T0)
        .await
        .unwrap());
    assert!(!c.fail(&lease, FailClass::NntpError, T0, T0).await.unwrap());
    assert!(!c.renew(&lease, T0).await.unwrap());
    assert_eq!(fx.dump().await, before);
    assert_eq!(fx.outbox(&o, "stage").await, "cancelled");

    // A redelivered job for the cancelled extent claims nothing, at any
    // stage and any time; the dispatcher does not list it.
    let late = T0.plus_ms(10 * LEASE_MS);
    for stage in OutboxStage::ALL {
        assert!(fx.claim(&o, *stage, late).await.is_none());
    }
    let due = fx.cat.due(late, 100).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].extent_id, newer.extent);
}

// ---------------------------------------------------------------------------
// Article plan
// ---------------------------------------------------------------------------

/// Two jobs plan the same extent with different message-ids. The first
/// stored plan is the plan; the second job gets it back and must post it.
#[tokio::test]
async fn concurrent_plan_articles_loser_reloads_winner() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let first = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();
    let winner = fx.plan(&o, "winner", 3);
    let stored = fx
        .cat
        .plan_articles(&first, &winner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored, winner);

    // The first job dies; a second one built its own plan before looking.
    let t1 = T0.plus_ms(LEASE_MS + 1);
    let second = fx.claim(&o, OutboxStage::Post, t1).await.unwrap();
    let loser = fx.plan(&o, "loser", 5);
    let got = fx
        .cat
        .plan_articles(&second, &loser)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, winner, "the loser must post the winner's message-ids");
    assert_eq!(fx.cat.articles(&o.extent).await.unwrap(), winner);
    assert_eq!(fx.count("SELECT COUNT(*) FROM articles").await, 3);
    assert_eq!(
        fx.count("SELECT article_count * 10 + plan_rev FROM extents WHERE article_count = 3")
            .await,
        31
    );

    // Posted state survives a later re-plan attempt.
    assert!(fx.cat.mark_posted(&second, 1, "p9", t1).await.unwrap());
    let again = fx
        .cat
        .plan_articles(&second, &loser)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again[1].state, ArticleState::Posted);
    assert_eq!(again[1].provider_id.as_deref(), Some("p9"));
    assert_eq!(again[1].posted_at, Some(t1));
    assert_eq!(again[0].state, ArticleState::Planned);
    assert_eq!(again[1].message_id, winner[1].message_id);
}

#[tokio::test]
async fn plan_articles_is_all_or_nothing_and_chunk_free() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let other = fx.publish(&fx.bucket, "other").await;
    let lease = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();

    // Shape errors: empty, a gap in idx, a row of another extent.
    let mut gap = fx.plan(&o, "g", 3);
    gap[2].idx = 5;
    let mut foreign = fx.plan(&o, "f", 2);
    foreign[1].extent_id = other.extent.clone();
    for bad in [vec![], gap, foreign] {
        assert!(matches!(
            fx.cat.plan_articles(&lease, &bad).await,
            Err(BridgeError::Invalid(_))
        ));
    }
    // A message-id collision in the last row rolls the whole plan back.
    let mut dup = fx.plan(&o, "d", 3);
    dup[2].message_id = dup[0].message_id.clone();
    assert!(matches!(
        fx.cat.plan_articles(&lease, &dup).await,
        Err(BridgeError::Sql(_))
    ));
    assert_eq!(fx.count("SELECT COUNT(*) FROM articles").await, 0);
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM extents WHERE article_count IS NOT NULL")
            .await,
        0
    );

    // A plan far larger than one 100-parameter statement could carry.
    let big = fx.plan(&o, "big", 64);
    let stored = fx.cat.plan_articles(&lease, &big).await.unwrap().unwrap();
    assert_eq!(stored, big);
}

// ---------------------------------------------------------------------------
// Verification counting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn newer_failure_cancels_pass() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let l = fx.posted(&o, 3, T0).await;
    assert!(
        fx.verify(&l, "bb-a", "p1", T0, 3, 3, VerifyResult::Ok)
            .await
    );
    assert_eq!(fx.counting(&o).await, vec!["bb-a"]);
    assert_eq!(
        fx.count("SELECT last_verified_at FROM extents WHERE article_count = 3")
            .await,
        T0.0
    );

    // Old ok + newer missing on the same backbone: not counted.
    let t1 = T0.plus_secs(60);
    assert!(
        fx.verify(&l, "bb-a", "p1", t1, 2, 3, VerifyResult::Missing)
            .await
    );
    assert!(fx.counting(&o).await.is_empty());
    let status = fx.cat.backbone_status(&o.extent).await.unwrap();
    assert_eq!(status.len(), 1, "one row per backbone: the latest");
    assert_eq!(
        (status[0].result, status[0].verified_at, status[0].counts),
        (VerifyResult::Missing, t1, false)
    );
    // Health keeps the newest full pass; a failure does not move it.
    assert_eq!(
        fx.count("SELECT last_verified_at FROM extents WHERE article_count = 3")
            .await,
        T0.0
    );

    // Each other failure kind hides the pass too; a newer pass restores it.
    for (i, result) in [VerifyResult::Corrupt, VerifyResult::Error]
        .iter()
        .enumerate()
    {
        let t = t1.plus_secs(60 * (i as u32 + 1));
        assert!(
            fx.verify(&l, "bb-a", "p1", t.plus_ms(-1), 3, 3, VerifyResult::Ok)
                .await
        );
        assert_eq!(fx.counting(&o).await, vec!["bb-a"]);
        assert!(fx.verify(&l, "bb-a", "p1", t, 3, 3, *result).await);
        assert!(fx.counting(&o).await.is_empty());
    }
}

#[tokio::test]
async fn partial_ok_does_not_count() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let l = fx.posted(&o, 3, T0).await;
    // `ok` must mean every article of the stored plan: neither fewer ok
    // than total, nor a total that is not the plan's count, in either direction.
    for (i, (ok, total)) in [(2, 3), (2, 2), (4, 4), (0, 0)].into_iter().enumerate() {
        let at = T0.plus_ms(i as i64);
        assert!(
            fx.verify(&l, "bb-a", "p1", at, ok, total, VerifyResult::Ok)
                .await
        );
        assert!(fx.counting(&o).await.is_empty(), "{ok}/{total} counted");
    }
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM extents WHERE last_verified_at IS NOT NULL")
            .await,
        0
    );
    // A row for another plan revision is not about the current plan.
    let v = VerificationRow {
        extent_id: o.extent.clone(),
        backbone: "bb-b".into(),
        provider_id: "p2".into(),
        verified_at: T0,
        plan_rev: 2,
        articles_ok: 3,
        articles_total: 3,
        result: VerifyResult::Ok,
    };
    assert!(fx.cat.record_verification(&l, &v).await.unwrap());
    assert!(fx
        .cat
        .backbone_status(&o.extent)
        .await
        .unwrap()
        .iter()
        .all(|b| b.backbone != "bb-b"));

    assert!(
        fx.verify(&l, "bb-a", "p1", T0.plus_ms(9), 3, 3, VerifyResult::Ok)
            .await
    );
    assert_eq!(fx.counting(&o).await, vec!["bb-a"]);

    // A verification for another extent is refused outright.
    let other = fx.publish(&fx.bucket, "other").await;
    let v = VerificationRow {
        extent_id: other.extent.clone(),
        plan_rev: 1,
        ..v
    };
    assert!(matches!(
        fx.cat.record_verification(&l, &v).await,
        Err(BridgeError::Invalid(_))
    ));
}

#[tokio::test]
async fn same_backbone_counts_once() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let l = fx.posted(&o, 2, T0).await;
    assert!(
        fx.verify(&l, "bb-a", "p1", T0, 2, 2, VerifyResult::Ok)
            .await
    );
    assert!(
        fx.verify(&l, "bb-a", "p2", T0.plus_ms(1), 2, 2, VerifyResult::Ok)
            .await
    );
    assert_eq!(fx.counting(&o).await, vec!["bb-a"]);

    // Two providers, one backbone: not enough for a two-backbone release.
    assert!(fx
        .cat
        .advance(&l, OutboxStage::Release, T0, T0)
        .await
        .unwrap());
    let r = fx.claim(&o, OutboxStage::Release, T0).await.unwrap();
    assert!(
        fx.verify(&r, "bb-a", "p1", T0.plus_ms(2), 2, 2, VerifyResult::Ok)
            .await
    );
    assert!(
        fx.verify(&r, "bb-a", "p2", T0.plus_ms(3), 2, 2, VerifyResult::Ok)
            .await
    );
    assert_eq!(
        fx.cat
            .begin_release(&r, 2, "[]", T0.plus_ms(4))
            .await
            .unwrap(),
        Guard::Lost
    );
    // The newer provider on that backbone failing hides the older pass.
    assert!(
        fx.verify(&r, "bb-a", "p2", T0.plus_ms(5), 1, 2, VerifyResult::Missing)
            .await
    );
    assert!(fx.counting(&o).await.is_empty());
    assert_eq!(
        fx.cat
            .begin_release(&r, 1, "[]", T0.plus_ms(6))
            .await
            .unwrap(),
        Guard::Lost
    );

    // A second backbone and a fresh pass on the first: two count.
    assert!(
        fx.verify(&r, "bb-a", "p1", T0.plus_ms(7), 2, 2, VerifyResult::Ok)
            .await
    );
    assert!(
        fx.verify(&r, "bb-b", "p3", T0.plus_ms(7), 2, 2, VerifyResult::Ok)
            .await
    );
    assert_eq!(fx.counting(&o).await, vec!["bb-a", "bb-b"]);
    assert_eq!(
        fx.cat
            .begin_release(&r, 2, "[]", T0.plus_ms(8))
            .await
            .unwrap(),
        Guard::Applied(())
    );
}

// ---------------------------------------------------------------------------
// Release
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_needs_fresh_evidence() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let l = fx.posted(&o, 2, T0).await;
    assert!(
        fx.verify(&l, "bb-a", "p1", T0, 2, 2, VerifyResult::Ok)
            .await
    );
    // Only a release lease may release.
    assert!(matches!(
        fx.cat.begin_release(&l, 1, "[]", T0).await,
        Err(BridgeError::Invalid(_))
    ));
    let week = T0.plus_ms(7 * 24 * HOUR_MS);
    assert!(fx
        .cat
        .advance(&l, OutboxStage::Release, week, T0)
        .await
        .unwrap());
    assert!(fx
        .claim(&o, OutboxStage::Release, week.plus_ms(-1))
        .await
        .is_none());
    let r = fx.claim(&o, OutboxStage::Release, week).await.unwrap();

    // The verify-stage pass still counts for status, but it is a week old:
    // it does not authorize unpinning the safety copy.
    assert_eq!(fx.counting(&o).await, vec!["bb-a"]);
    let before = fx.dump().await;
    assert_eq!(
        fx.cat
            .begin_release(&r, 1, "[\"old\"]", week)
            .await
            .unwrap(),
        Guard::Lost
    );
    assert!(
        !fx.cat.finish_release(&r, week).await.unwrap(),
        "never began"
    );
    assert_eq!(fx.dump().await, before);
    // Zero required backbones is never a valid release.
    assert!(matches!(
        fx.cat.begin_release(&r, 0, "[]", week).await,
        Err(BridgeError::Invalid(_))
    ));

    // Re-verified in this job: the release may begin.
    let now = week.plus_secs(20);
    assert!(
        fx.verify(&r, "bb-a", "p1", now, 2, 2, VerifyResult::Ok)
            .await
    );
    assert_eq!(
        fx.cat.begin_release(&r, 2, "[]", now).await.unwrap(),
        Guard::Lost,
        "one backbone is not two"
    );
    assert_eq!(
        fx.cat
            .begin_release(&r, 1, "[{\"backbone\":\"bb-a\"}]", now)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    let je = fx
        .cat
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(je.extent.safety_state, SafetyState::Releasing);
    assert_eq!(
        je.extent.release_evidence.as_deref(),
        Some("[{\"backbone\":\"bb-a\"}]")
    );
    assert_eq!(je.extent.released_at, None);
    assert_eq!(fx.outbox(&o, "stage").await, "release");

    // A crash after the blob delete is re-driven: begin again, then finish.
    assert_eq!(
        fx.cat
            .begin_release(&r, 1, "[{\"backbone\":\"bb-a\"}]", now)
            .await
            .unwrap(),
        Guard::Applied(())
    );
    let done_at = now.plus_ms(5);
    assert!(fx.cat.finish_release(&r, done_at).await.unwrap());
    let je = fx
        .cat
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(je.extent.safety_state, SafetyState::Released);
    assert_eq!(je.extent.released_at, Some(done_at));
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.outbox(&o, "lease_until").await, "NULL");
    // Done is final.
    assert!(!fx.cat.finish_release(&r, done_at).await.unwrap());
    assert_eq!(
        fx.cat.begin_release(&r, 1, "[]", done_at).await.unwrap(),
        Guard::Lost
    );
    assert!(fx
        .cat
        .due(done_at.plus_ms(HOUR_MS), 100)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn release_refuses_a_retired_generation_and_a_missing_safety_copy() {
    let fx = Fx::new().await;
    // An evicted safety copy (`deleted`) cannot be "released".
    let o = fx.publish(&fx.bucket, "evicted").await;
    let l = fx.posted(&o, 1, T0).await;
    assert!(fx
        .cat
        .advance(&l, OutboxStage::Release, T0, T0)
        .await
        .unwrap());
    let r = fx.claim(&o, OutboxStage::Release, T0).await.unwrap();
    assert!(
        fx.verify(&r, "bb-a", "p1", T0, 1, 1, VerifyResult::Ok)
            .await
    );
    fx.run("UPDATE extents SET safety_state = 'deleted'", &[])
        .await;
    assert_eq!(
        fx.cat.begin_release(&r, 1, "[]", T0).await.unwrap(),
        Guard::Lost
    );

    // A generation retired without its row being cancelled (defence in
    // depth: the publication batch cancels it) is not released either.
    let o = fx.publish(&fx.bucket, "retired").await;
    let l = fx.posted(&o, 1, T0).await;
    assert!(fx
        .cat
        .advance(&l, OutboxStage::Release, T0, T0)
        .await
        .unwrap());
    let r = fx.claim(&o, OutboxStage::Release, T0).await.unwrap();
    assert!(
        fx.verify(&r, "bb-a", "p1", T0, 1, 1, VerifyResult::Ok)
            .await
    );
    fx.run(
        "UPDATE generations SET state = 'deleted' WHERE id = ?1",
        &[text(o.generation.as_str())],
    )
    .await;
    assert_eq!(
        fx.cat.begin_release(&r, 1, "[]", T0).await.unwrap(),
        Guard::Lost
    );
    let je = fx
        .cat
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(je.generation_state, GenerationState::Deleted);
    assert_eq!(je.extent.safety_state, SafetyState::Held);
}

// ---------------------------------------------------------------------------
// Job reads and dispatcher
// ---------------------------------------------------------------------------

#[tokio::test]
async fn job_extent_joins_extent_bucket_and_generation() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.real_bucket, "k").await;
    let je = fx
        .cat
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(je.extent.id, o.extent);
    assert_eq!(je.extent.generation_id, Some(o.generation.clone()));
    assert_eq!(je.extent.state, ExtentState::Committed);
    assert_eq!((je.extent.seq, je.extent.plain_offset), (Some(0), Some(0)));
    assert_eq!((je.extent.plain_size, je.extent.cipher_size), (1000, 1064));
    assert_eq!(je.extent.media_header.len(), 48);
    assert_eq!(je.extent.wrapped_file_key.as_ref().map(Vec::len), Some(73));
    assert_eq!(je.extent.article_count, None);
    assert_eq!(je.bucket.id, fx.real_bucket);
    assert_eq!(
        (je.bucket.name.as_str(), je.bucket.disposable),
        ("real", false)
    );
    assert_eq!(je.generation_state, GenerationState::Live);

    // The job names both ids: a mismatch is no row.
    let other = GenerationId::mint(T0, [0xaa; 8]);
    assert!(fx
        .cat
        .job_extent(&o.extent, &other)
        .await
        .unwrap()
        .is_none());
    assert!(fx.cat.articles(&o.extent).await.unwrap().is_empty());
}

#[tokio::test]
async fn dispatcher_reads_are_bounded_and_bury_only_exhausted_rows() {
    let fx = Fx::new().await;
    let mut objs = Vec::new();
    for i in 0..5 {
        objs.push(fx.publish(&fx.bucket, &format!("k{i}")).await);
    }
    assert_eq!(fx.cat.due(T0, 100).await.unwrap().len(), 5);
    assert_eq!(fx.cat.due(T0, 2).await.unwrap().len(), 2);
    assert!(fx.cat.due(T0.plus_ms(-1), 100).await.unwrap().is_empty());

    // Leased rows are not re-sent until the lease expires.
    let held = fx.claim(&objs[0], OutboxStage::Post, T0).await.unwrap();
    assert_eq!(fx.cat.due(T0, 100).await.unwrap().len(), 4);
    assert_eq!(
        fx.cat
            .due(T0.plus_ms(LEASE_MS + 1), 100)
            .await
            .unwrap()
            .len(),
        5
    );

    // Bury: strictly more than the cap, and never a row a job holds.
    let o1 = text(objs[1].extent.as_str());
    fx.run(
        "UPDATE outbox SET attempts = 51 WHERE extent_id = ?1",
        &[o1],
    )
    .await;
    let o2 = text(objs[2].extent.as_str());
    fx.run(
        "UPDATE outbox SET attempts = 50 WHERE extent_id = ?1",
        &[o2],
    )
    .await;
    let o0 = text(objs[0].extent.as_str());
    fx.run(
        "UPDATE outbox SET attempts = 99 WHERE extent_id = ?1",
        &[o0],
    )
    .await;
    assert_eq!(fx.cat.bury_exhausted(50, T0).await.unwrap(), 1);
    assert_eq!(fx.outbox(&objs[1], "stage").await, "dead");
    assert_eq!(fx.outbox(&objs[2], "stage").await, "post");
    assert_eq!(fx.outbox(&objs[0], "stage").await, "post");
    assert!(fx.cat.renew(&held, T0).await.unwrap());
    assert_eq!(fx.cat.bury_exhausted(50, T0).await.unwrap(), 0);
    // Dead rows are neither due nor claimable.
    assert!(fx.claim(&objs[1], OutboxStage::Post, T0).await.is_none());
    assert_eq!(
        fx.cat
            .due(T0.plus_ms(LEASE_MS + 1), 100)
            .await
            .unwrap()
            .len(),
        4
    );

    let stats = fx.cat.outbox_stats().await.unwrap();
    assert_eq!(
        stats.by_stage,
        vec![(OutboxStage::Post, 4), (OutboxStage::Dead, 1)]
    );
    assert_eq!(stats.dead, 1);
    assert_eq!(stats.last_dispatch_at, None);
    fx.cat.record_dispatch(T0).await.unwrap();
    fx.cat.record_dispatch(T0.plus_secs(300)).await.unwrap();
    let stats = fx.cat.outbox_stats().await.unwrap();
    assert_eq!(stats.last_dispatch_at, Some(T0.plus_secs(300)));
}

// ---------------------------------------------------------------------------
// GC rows
// ---------------------------------------------------------------------------

async fn gc_rows(fx: &Fx, now: UnixMs, disposable_only: bool) -> Vec<GcRow> {
    fx.cat.gc_due(now, 50, disposable_only).await.unwrap()
}

#[tokio::test]
async fn gc_disposable_skips_real_buckets() {
    let fx = Fx::new().await;
    // An overwrite in each bucket retires one generation each.
    let scratch_old = fx.publish(&fx.bucket, "k").await;
    fx.publish(&fx.bucket, "k").await;
    let real_old = fx.publish(&fx.real_bucket, "k").await;
    fx.publish(&fx.real_bucket, "k").await;

    let all = gc_rows(&fx, T0, false).await;
    assert_eq!(all.len(), 4, "cache and safety deletes are due at once");
    let disposable = gc_rows(&fx, T0, true).await;
    assert_eq!(disposable.len(), 2);
    assert!(disposable.iter().all(|r| r.extent_id == scratch_old.extent));
    assert!(disposable.iter().all(|r| r.done_at.is_none()));
    // The key shred is due a day later, and only then.
    let day = T0.plus_ms(24 * HOUR_MS);
    assert_eq!(gc_rows(&fx, day.plus_ms(-1), true).await.len(), 2);
    let later = gc_rows(&fx, day, true).await;
    assert_eq!(later.len(), 3);
    assert_eq!(later[2].action, GcAction::ShredKey);
    assert_eq!(gc_rows(&fx, day, true).await[..1].len(), 1);
    assert_eq!(fx.cat.gc_due(day, 1, true).await.unwrap().len(), 1);
    assert!(gc_rows(&fx, day, false)
        .await
        .iter()
        .any(|r| r.extent_id == real_old.extent));
}

#[tokio::test]
async fn gc_runs_each_action_once_and_records_it() {
    let fx = Fx::new().await;
    let old = fx.publish(&fx.bucket, "k").await;
    let lease = fx.claim(&old, OutboxStage::Post, T0).await.unwrap();
    let plan = fx.plan(&old, "m", 2);
    fx.cat.plan_articles(&lease, &plan).await.unwrap().unwrap();
    let live = fx.publish(&fx.bucket, "k").await;
    let day = T0.plus_ms(24 * HOUR_MS);

    let rows = gc_rows(&fx, day, true).await;
    assert_eq!(rows.len(), 3);
    for row in &rows {
        let step = fx.cat.gc_begin(row, day).await.unwrap();
        match row.action {
            GcAction::DeleteCache => assert_eq!(
                step,
                GcStep::DeleteBlob {
                    store: BlobStoreKind::Cache,
                    key: old.extent.cache_key()
                }
            ),
            GcAction::DeleteSafety => assert_eq!(
                step,
                GcStep::DeleteBlob {
                    store: BlobStoreKind::Safety,
                    key: old.extent.safety_key()
                }
            ),
            // Catalogue-only: applied and closed by `gc_begin` itself.
            _ => assert_eq!(step, GcStep::Done),
        }
    }
    // Blob rows stay open until the caller reports the delete.
    assert_eq!(gc_rows(&fx, day, true).await.len(), 2);
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'")
            .await,
        0
    );
    for row in rows.iter().filter(|r| r.action != GcAction::ShredKey) {
        fx.cat.gc_done(row.id, day).await.unwrap();
        fx.cat.gc_done(row.id, day.plus_ms(9)).await.unwrap();
    }
    assert!(gc_rows(&fx, day.plus_ms(HOUR_MS), true).await.is_empty());
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM gc WHERE done_at IS NULL")
            .await,
        0
    );
    assert_eq!(
        fx.count(&format!(
            "SELECT COUNT(*) FROM gc WHERE done_at = {}",
            day.0
        ))
        .await,
        3
    );

    // The retired extent lost its key and its safety copy; the live one
    // kept both.
    let retired = fx
        .cat
        .job_extent(&old.extent, &old.generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.extent.wrapped_file_key, None);
    assert_eq!(retired.extent.safety_state, SafetyState::Deleted);
    let kept = fx
        .cat
        .job_extent(&live.extent, &live.generation)
        .await
        .unwrap()
        .unwrap();
    assert!(kept.extent.wrapped_file_key.is_some());
    assert_eq!(kept.extent.safety_state, SafetyState::Held);

    // `drop_articles_meta` removes the retired extent's article rows.
    fx.run(
        "INSERT INTO gc(extent_id, action, due_at) VALUES (?1, 'drop_articles_meta', 0)",
        &[text(old.extent.as_str())],
    )
    .await;
    let rows = gc_rows(&fx, day, true).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(fx.cat.gc_begin(&rows[0], day).await.unwrap(), GcStep::Done);
    assert!(fx.cat.articles(&old.extent).await.unwrap().is_empty());
}

/// A GC row must never act on an extent that is in service, whatever put
/// the row there.
#[tokio::test]
async fn gc_refuses_an_extent_in_service() {
    let fx = Fx::new().await;
    let live = fx.publish(&fx.bucket, "k").await;
    let lease = fx.claim(&live, OutboxStage::Post, T0).await.unwrap();
    let plan = fx.plan(&live, "m", 2);
    fx.cat.plan_articles(&lease, &plan).await.unwrap().unwrap();
    for action in GcAction::ALL {
        fx.run(
            "INSERT INTO gc(extent_id, action, due_at) VALUES (?1, ?2, 0)",
            &[text(live.extent.as_str()), text(action.as_str())],
        )
        .await;
    }
    let before = fx.dump().await;
    let rows = gc_rows(&fx, T0, true).await;
    assert_eq!(rows.len(), 4);
    for row in &rows {
        assert_eq!(fx.cat.gc_begin(row, T0).await.unwrap(), GcStep::Skipped);
    }
    assert_eq!(fx.dump().await, before, "GC touched a live extent");
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL")
            .await,
        0
    );
    // Refused rows step aside for an hour instead of blocking the window.
    assert!(gc_rows(&fx, T0.plus_ms(HOUR_MS - 1), true).await.is_empty());
    assert_eq!(gc_rows(&fx, T0.plus_ms(HOUR_MS), true).await.len(), 4);

    // The current part of an open upload is in service too.
    let id = UploadId::mint([0xc1; 16]);
    fx.run(
        "INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, \
         initiated_at) VALUES (?1, ?2, 'open-key', '{}', '{}', 'open', 0)",
        &[text(id.as_str()), text(fx.bucket.as_str())],
    )
    .await;
    fx.run(
        "INSERT INTO extents(id, bucket_id, state, plain_size, cipher_size, media_header, \
         wrapped_file_key, plain_md5, plain_sha256, cipher_sha256, safety_state, created_at) \
         VALUES ('x_part', ?1, 'staged', 1, 1, x'00', x'01', x'00', x'00', x'00', 'held', 0)",
        &[text(fx.bucket.as_str())],
    )
    .await;
    fx.run(
        "INSERT INTO upload_parts(upload_id, part_number, extent_id, size, etag, uploaded_at) \
         VALUES (?1, 1, 'x_part', 1, 'e', 0)",
        &[text(id.as_str())],
    )
    .await;
    fx.run(
        "INSERT INTO gc(extent_id, action, due_at) VALUES ('x_part', 'shred_key', 0)",
        &[],
    )
    .await;
    let row = gc_rows(&fx, T0, true).await.pop().unwrap();
    assert_eq!(row.extent_id.as_str(), "x_part");
    assert_eq!(fx.cat.gc_begin(&row, T0).await.unwrap(), GcStep::Skipped);
    assert_eq!(
        fx.count(
            "SELECT COUNT(*) FROM extents WHERE id = 'x_part' AND wrapped_file_key IS NOT NULL"
        )
        .await,
        1
    );
    // Once the upload is aborted the same row goes through.
    fx.run(
        "UPDATE uploads SET state = 'aborted' WHERE id = ?1",
        &[text(id.as_str())],
    )
    .await;
    assert_eq!(fx.cat.gc_begin(&row, T0).await.unwrap(), GcStep::Done);
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM extents WHERE id = 'x_part' AND wrapped_file_key IS NULL")
            .await,
        1
    );
}

// ---------------------------------------------------------------------------
// Review regressions
// ---------------------------------------------------------------------------

/// Evidence for a release is what this claim recorded: a pass from the
/// verify stage does not count however recent it is, and neither does a
/// row stamped after `now`.
#[tokio::test]
async fn release_evidence_must_come_from_this_claim() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let l = fx.posted(&o, 2, T0).await;
    assert!(
        fx.verify(&l, "bb-a", "p1", T0, 2, 2, VerifyResult::Ok)
            .await
    );
    assert!(fx
        .cat
        .advance(&l, OutboxStage::Release, T0, T0)
        .await
        .unwrap());
    // Claimed one millisecond after the verify-stage pass.
    let t1 = T0.plus_ms(1);
    let r = fx.claim(&o, OutboxStage::Release, t1).await.unwrap();
    assert_eq!(fx.counting(&o).await, vec!["bb-a"]);
    assert_eq!(
        fx.cat.begin_release(&r, 1, "[]", t1).await.unwrap(),
        Guard::Lost
    );
    assert_eq!(
        fx.cat
            .begin_release(&r, 1, "[]", t1.plus_ms(9 * 60_000))
            .await
            .unwrap(),
        Guard::Lost
    );

    // A pass stamped ahead of the clock is not evidence yet.
    let t2 = t1.plus_secs(60);
    assert!(
        fx.verify(&r, "bb-a", "p1", t2.plus_secs(5), 2, 2, VerifyResult::Ok)
            .await
    );
    assert_eq!(
        fx.cat.begin_release(&r, 1, "[]", t2).await.unwrap(),
        Guard::Lost
    );

    // Renewing and moving the cursor do not move the claim time: a pass
    // recorded under this claim before them still counts after them.
    let other = fx.publish(&fx.bucket, "other").await;
    let l = fx.posted(&other, 1, T0).await;
    assert!(fx
        .cat
        .advance(&l, OutboxStage::Release, T0, T0)
        .await
        .unwrap());
    let r = fx.claim(&other, OutboxStage::Release, t1).await.unwrap();
    assert!(
        fx.verify(&r, "bb-a", "p1", t1, 1, 1, VerifyResult::Ok)
            .await
    );
    assert!(fx.cat.set_cursor(&r, 1, t2).await.unwrap());
    assert!(fx.cat.renew(&r, t2).await.unwrap());
    assert_eq!(
        fx.cat.begin_release(&r, 1, "[]", t2).await.unwrap(),
        Guard::Applied(())
    );
}

/// An expired lease that nobody has taken over yet may be taken over at
/// any moment, so it authorizes neither step of a release.
#[tokio::test]
async fn expired_release_lease_cannot_release() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let l = fx.posted(&o, 1, T0).await;
    assert!(fx
        .cat
        .advance(&l, OutboxStage::Release, T0, T0)
        .await
        .unwrap());
    let r = fx.claim(&o, OutboxStage::Release, T0).await.unwrap();
    assert!(
        fx.verify(&r, "bb-a", "p1", T0, 1, 1, VerifyResult::Ok)
            .await
    );
    let expired = T0.plus_ms(LEASE_MS + 1);
    let before = fx.dump().await;
    assert_eq!(
        fx.cat.begin_release(&r, 1, "[]", expired).await.unwrap(),
        Guard::Lost
    );
    assert_eq!(fx.dump().await, before);
    // Begun in time, but the delete outlived the lease: not finished.
    let last = T0.plus_ms(LEASE_MS);
    assert_eq!(
        fx.cat.begin_release(&r, 1, "[]", last).await.unwrap(),
        Guard::Applied(())
    );
    let before = fx.dump().await;
    assert!(!fx.cat.finish_release(&r, expired).await.unwrap());
    assert_eq!(fx.dump().await, before);
    assert!(fx.cat.finish_release(&r, last).await.unwrap());
}

/// Two results for one backbone in the same millisecond: the failure
/// stands, whichever arrived first.
#[tokio::test]
async fn same_instant_failure_is_not_overwritten() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let l = fx.posted(&o, 2, T0).await;
    assert!(
        fx.verify(&l, "bb-a", "p1", T0, 1, 2, VerifyResult::Missing)
            .await
    );
    assert!(
        fx.verify(&l, "bb-a", "p2", T0, 2, 2, VerifyResult::Ok)
            .await
    );
    assert!(fx.counting(&o).await.is_empty());
    assert!(
        fx.verify(&l, "bb-b", "p1", T0, 2, 2, VerifyResult::Ok)
            .await
    );
    assert!(
        fx.verify(&l, "bb-b", "p2", T0, 0, 2, VerifyResult::Corrupt)
            .await
    );
    assert!(fx.counting(&o).await.is_empty());
    assert_eq!(fx.count("SELECT COUNT(*) FROM verifications").await, 2);
}

/// `gc_begin` acts on the stored row, not on the caller's copy of it.
#[tokio::test]
async fn gc_trusts_the_stored_row_only() {
    let fx = Fx::new().await;
    let old = fx.publish(&fx.bucket, "k").await;
    fx.publish(&fx.bucket, "k").await;
    let rows = gc_rows(&fx, T0, true).await;
    let cache = rows
        .iter()
        .find(|r| r.action == GcAction::DeleteCache)
        .unwrap();

    // A copy that names another action or extent is refused.
    let forged = GcRow {
        action: GcAction::ShredKey,
        ..cache.clone()
    };
    assert_eq!(fx.cat.gc_begin(&forged, T0).await.unwrap(), GcStep::Skipped);
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM extents WHERE wrapped_file_key IS NULL")
            .await,
        0
    );
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL")
            .await,
        0
    );
    assert_eq!(gc_rows(&fx, T0, true).await.len(), 2, "nothing postponed");

    // Closing a cache delete does not record a safety delete.
    assert!(matches!(
        fx.cat.gc_begin(cache, T0).await.unwrap(),
        GcStep::DeleteBlob { .. }
    ));
    fx.cat.gc_done(cache.id, T0).await.unwrap();
    assert_eq!(
        fx.count("SELECT COUNT(*) FROM extents WHERE safety_state = 'deleted'")
            .await,
        0
    );
    // A closed row is not handed out again.
    assert_eq!(fx.cat.gc_begin(cache, T0).await.unwrap(), GcStep::Skipped);
    let job = fx
        .cat
        .job_extent(&old.extent, &old.generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.extent.safety_state, SafetyState::Held);
}

/// What the verify and release jobs rely on: the cursor (backbone index
/// * 8 + retries used) survives `fail` and `defer` within a stage and is
/// zero after `advance`; backbone labels come back exactly as recorded;
/// a job may advance straight to a terminal stage.
#[tokio::test]
async fn cursor_and_labels_behave_as_the_jobs_expect() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let v = fx.posted(&o, 1, T0).await;

    // Backbone 1, second missing retry; then the job fails with a wait.
    assert!(fx.cat.set_cursor(&v, 8 + 2, T0).await.unwrap());
    let t1 = T0.plus_secs(30);
    assert!(fx
        .cat
        .fail(&v, FailClass::MissingPending, t1, T0)
        .await
        .unwrap());
    let v = fx.claim(&o, OutboxStage::Verify, t1).await.unwrap();
    assert_eq!((v.cursor, v.attempts), (10, 2));
    // Next backbone, handed to a fresh job without spending an attempt.
    assert!(fx.cat.set_cursor(&v, 2 * 8, t1).await.unwrap());
    assert!(fx.cat.defer(&v, t1, t1).await.unwrap());
    let v = fx.claim(&o, OutboxStage::Verify, t1).await.unwrap();
    assert_eq!((v.cursor, v.attempts), (16, 2));

    assert!(
        fx.verify(&v, "bb-a", "p1", t1, 1, 1, VerifyResult::Ok)
            .await
    );
    assert!(
        fx.verify(&v, "bb-b", "p2", t1, 1, 1, VerifyResult::Ok)
            .await
    );
    let labels: Vec<String> = fx
        .cat
        .backbone_status(&o.extent)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.backbone)
        .collect();
    assert_eq!(labels, vec!["bb-a", "bb-b"]);

    // Advance without clearing the cursor first: the next stage starts at 0.
    assert!(fx
        .cat
        .advance(&v, OutboxStage::Release, t1, t1)
        .await
        .unwrap());
    let r = fx.claim(&o, OutboxStage::Release, t1).await.unwrap();
    assert_eq!((r.cursor, r.attempts), (0, 1));
    // Back to verify (a backbone lost the extent): again from 0.
    assert!(fx.cat.set_cursor(&r, 5, t1).await.unwrap());
    assert!(fx
        .cat
        .advance(&r, OutboxStage::Verify, t1, t1)
        .await
        .unwrap());
    let v = fx.claim(&o, OutboxStage::Verify, t1).await.unwrap();
    assert_eq!((v.cursor, v.attempts), (0, 1));

    // Straight to a terminal stage: final, and the safety copy is untouched.
    assert!(fx.cat.advance(&v, OutboxStage::Done, t1, t1).await.unwrap());
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    for stage in OutboxStage::ALL {
        assert!(fx.claim(&o, *stage, t1.plus_secs(3600)).await.is_none());
    }
    let job = fx
        .cat
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.extent.safety_state, SafetyState::Held);
}

// ---------------------------------------------------------------------------
// Re-drive
// ---------------------------------------------------------------------------

impl Fx {
    /// Publishes an object, verifies it on `bb1` only and parks its outbox
    /// row at `done` with the safety copy still held: what a deployment
    /// with one backbone leaves behind.
    async fn done_on_one_backbone(&self, key: &str) -> Obj {
        let o = self.publish(&self.bucket, key).await;
        let lease = self.posted(&o, 2, T0).await;
        assert!(
            self.verify(&lease, "bb1", "p1", T0, 2, 2, VerifyResult::Ok)
                .await
        );
        assert!(self
            .cat
            .advance(&lease, OutboxStage::Done, T0, T0)
            .await
            .unwrap());
        o
    }

    async fn redrive(&self, backbones: &[&str], required: u32, limit: u32, now: UnixMs) -> u64 {
        let labels: Vec<String> = backbones.iter().map(|b| b.to_string()).collect();
        self.cat
            .redrive_underverified(&labels, required, limit, now)
            .await
            .unwrap()
    }
}

/// A `done` extent whose safety copy is held and that counts on fewer
/// backbones than required goes back to verify, as a fresh obligation.
#[tokio::test]
async fn redrive_requeues_underverified_done_extents() {
    let fx = Fx::new().await;
    let o = fx.done_on_one_backbone("k").await;
    let later = T0.plus_ms(HOUR_MS);
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert!(fx.cat.due(later, 100).await.unwrap().is_empty());

    // Enough backbones count: nothing to do.
    assert_eq!(fx.redrive(&["bb1", "bb2"], 1, 100, later).await, 0);
    // A backbone that is no longer configured does not count.
    assert_eq!(fx.redrive(&["bb2"], 1, 100, later).await, 1);
    assert_eq!(fx.outbox(&o, "stage").await, "verify");
    assert_eq!(fx.outbox(&o, "attempts").await, "0");
    assert_eq!(fx.outbox(&o, "cursor").await, "0");
    assert_eq!(fx.outbox(&o, "lease_until").await, "NULL");
    assert_eq!(fx.outbox(&o, "next_at").await, later.0.to_string());
    assert_eq!(fx.cat.due(later, 100).await.unwrap().len(), 1);
    // Moved once: the row is no longer `done`.
    assert_eq!(fx.redrive(&["bb2"], 1, 100, later).await, 0);

    // The verify job can claim it, and the earlier evidence is kept.
    let lease = fx.claim(&o, OutboxStage::Verify, later).await.unwrap();
    assert_eq!(fx.counting(&o).await, ["bb1"]);
    assert!(
        fx.verify(&lease, "bb2", "p2", later, 2, 2, VerifyResult::Ok)
            .await
    );
    assert_eq!(fx.counting(&o).await, ["bb1", "bb2"]);
}

/// The second backbone arrives: two are required, one counts.
#[tokio::test]
async fn redrive_is_bounded_per_run() {
    let fx = Fx::new().await;
    let mut objs = Vec::new();
    for i in 0..5 {
        objs.push(fx.done_on_one_backbone(&format!("k{i}")).await);
    }
    let later = T0.plus_ms(HOUR_MS);
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 2, later).await, 2);
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 2, later).await, 2);
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 2, later).await, 1);
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 2, later).await, 0);
    for o in &objs {
        assert_eq!(fx.outbox(o, "stage").await, "verify");
    }
}

/// The scan rotates: extents that need nothing do not hide later ones.
#[tokio::test(flavor = "current_thread")]
async fn redrive_window_moves_past_extents_that_need_nothing() {
    let fx = Fx::new().await;
    let mut objs = Vec::new();
    for i in 0..5 {
        objs.push(fx.done_on_one_backbone(&format!("k{i}")).await);
    }
    let later = T0.plus_ms(HOUR_MS);
    // One backbone is enough: nothing moves, but the window advances.
    assert_eq!(fx.redrive(&["bb1"], 1, 2, later).await, 0);
    assert_eq!(fx.redrive(&["bb1"], 1, 2, later).await, 0);
    // A second backbone is now required: the runs cover all five, the
    // last three first and then, from the start again, the other two.
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 2, later).await, 1);
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 2, later).await, 2);
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 2, later).await, 2);
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 2, later).await, 0);
    for o in &objs {
        assert_eq!(fx.outbox(o, "stage").await, "verify");
    }
}

/// Rows that are not an open obligation stay where they are.
#[tokio::test]
async fn redrive_leaves_everything_else_alone() {
    let fx = Fx::new().await;
    let later = T0.plus_ms(HOUR_MS);

    // Safety copy already released.
    let released = fx.done_on_one_backbone("released").await;
    fx.run(
        "UPDATE extents SET safety_state = 'released' WHERE id = ?1",
        &[text(released.extent.as_str())],
    )
    .await;
    // Generation deleted.
    let deleted = fx.done_on_one_backbone("deleted").await;
    fx.run(
        "UPDATE generations SET state = 'deleted' WHERE id = ?1",
        &[text(deleted.generation.as_str())],
    )
    .await;
    // Not finished: still at post, and at verify.
    let posting = fx.publish(&fx.bucket, "posting").await;
    let verifying = fx.publish(&fx.bucket, "verifying").await;
    fx.posted(&verifying, 2, T0).await;
    // Buried.
    let dead = fx.done_on_one_backbone("dead").await;
    fx.run(
        "UPDATE outbox SET stage = 'dead' WHERE extent_id = ?1",
        &[text(dead.extent.as_str())],
    )
    .await;

    let before = fx.dump().await;
    assert_eq!(fx.redrive(&["bb1", "bb2"], 2, 100, later).await, 0);
    assert_eq!(fx.dump().await, before);
    assert_eq!(fx.outbox(&posting, "stage").await, "post");
    assert_eq!(fx.outbox(&released, "stage").await, "done");
    assert_eq!(fx.outbox(&deleted, "stage").await, "done");
}

fn poster(id: &str, max_conns: u32) -> ProviderConfig {
    let json = format!(
        "{{\"id\":\"{id}\",\"host\":\"news.example.invalid\",\"port\":563,\"tls\":true,\
         \"user\":\"u\",\"pass\":\"p\",\"backbone\":\"bb\",\"post\":true,\"read\":true,\
         \"max_conns\":{max_conns}}}"
    );
    serde_json::from_str(&json).unwrap()
}

/// A batch of posted articles is written as a whole under a live lease
/// and not at all under a stale one.
#[tokio::test]
async fn mark_posted_many_is_fenced_and_all_or_nothing() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let stale = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();
    let plan = fx.plan(&o, "first", 5);
    fx.cat.plan_articles(&stale, &plan).await.unwrap().unwrap();

    let c = &fx.cat;
    let at = T0.plus_ms(5);
    assert!(c
        .mark_posted_many(&stale, &[(0, "p1"), (3, "p2")], at)
        .await
        .unwrap());
    let rows = c.articles(&o.extent).await.unwrap();
    let seen: Vec<_> = rows
        .iter()
        .map(|a| (a.state, a.provider_id.as_deref(), a.posted_at))
        .collect();
    let planned = (ArticleState::Planned, None, None);
    assert_eq!(
        seen,
        [
            (ArticleState::Posted, Some("p1"), Some(at)),
            planned,
            planned,
            (ArticleState::Posted, Some("p2"), Some(at)),
            planned,
        ]
    );
    // Nothing to write: still an answer about the lease.
    assert!(c.mark_posted_many(&stale, &[], at).await.unwrap());

    let t1 = T0.plus_ms(LEASE_MS + 1);
    let owner = fx.claim(&o, OutboxStage::Post, t1).await.unwrap();
    let before = fx.dump().await;
    assert!(!c
        .mark_posted_many(&stale, &[(1, "p1"), (2, "p1"), (4, "p1")], t1)
        .await
        .unwrap());
    assert!(!c.mark_posted_many(&stale, &[], t1).await.unwrap());
    assert_eq!(fx.dump().await, before);
    assert_eq!(c.articles(&o.extent).await.unwrap(), rows);

    // The owner writes the rest in one go.
    assert!(c
        .mark_posted_many(&owner, &[(1, "p1"), (2, "p1"), (4, "p1")], t1)
        .await
        .unwrap());
    let rows = c.articles(&o.extent).await.unwrap();
    assert!(rows.iter().all(|a| a.state == ArticleState::Posted));
}

/// One round trip renews the lease and every permit; each answer stands
/// for itself.
#[tokio::test]
async fn renew_all_renews_the_lease_and_each_permit_on_its_own() {
    let fx = Fx::new().await;
    let o = fx.publish(&fx.bucket, "k").await;
    let c = &fx.cat;
    let p = poster("p1", 3);
    c.seed_permits(core::slice::from_ref(&p)).await.unwrap();
    let lease = fx.claim(&o, OutboxStage::Post, T0).await.unwrap();
    let mut permits = Vec::new();
    for _ in 0..2 {
        let got = c.acquire_permit(&p, PermitClass::Background, "h", T0).await;
        permits.push(got.unwrap().unwrap());
    }

    let t1 = T0.plus_secs(20);
    assert_eq!(
        c.renew_all(&lease, &permits, t1).await.unwrap(),
        (true, vec![true, true])
    );
    assert_eq!(
        fx.outbox(&o, "lease_until").await,
        t1.plus_ms(LEASE_MS).0.to_string()
    );
    let until = fx
        .count("SELECT MIN(lease_until) FROM provider_permits WHERE token > 0 AND lease_until > 0")
        .await;
    assert_eq!(until, t1.plus_secs(PERMIT_SECS).0);
    // No permits: the lease alone.
    assert_eq!(c.renew_all(&lease, &[], t1).await.unwrap(), (true, vec![]));

    // One slot is given back and taken by someone else.
    c.release_permit(&permits[0]).await.unwrap();
    let other = c.acquire_permit(&p, PermitClass::Background, "o", t1).await;
    assert_eq!(other.unwrap().unwrap().slot, permits[0].slot);
    assert_eq!(
        c.renew_all(&lease, &permits, t1).await.unwrap(),
        (true, vec![false, true])
    );

    // The lease is taken over: the old holder learns it, and its live
    // permit is still its own.
    let t2 = t1.plus_ms(LEASE_MS + 1);
    assert!(c
        .renew_permit(&permits[1], t1.plus_secs(PERMIT_SECS))
        .await
        .unwrap());
    let t_claim = t1.plus_ms(LEASE_MS + 1);
    let owner = fx.claim(&o, OutboxStage::Post, t_claim).await.unwrap();
    let live = [permits[1].clone()];
    let before = fx.outbox(&o, "lease_until").await;
    let (held, slots) = c.renew_all(&lease, &live, t2).await.unwrap();
    assert!(!held);
    // That permit ran out long ago: an expired slot is never extended.
    assert_eq!(slots, vec![false]);
    assert_eq!(fx.outbox(&o, "lease_until").await, before);
    assert_eq!(fx.outbox(&o, "lease_token").await, owner.token.to_string());
}
