//! Contended catalogue outcomes through the production adapter on PostgreSQL.
//! These are not SQL reimplementations of the paths under test.

#![cfg(feature = "testkit-pg")]

mod pg_commit_fault;

use futures_util::future::join_all;
use velmora_bridge::pg::{PgConfig, PgSql};
use velmora_bridge::recovery::Recorded;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::TestSql;
use velmora_bridge::*;

const C: u8 = 8;
const NOW: UnixMs = UnixMs(1_762_992_000_123);

fn catalogue() -> Option<SqlCatalog<TestSql>> {
    TestSql::postgres_selected().then(|| SqlCatalog::new(TestSql::with_schema().unwrap()))
}

async fn bucket(c: &SqlCatalog<TestSql>, seed: u8) -> Bucket {
    let bucket = Bucket {
        id: BucketId::mint([seed; 8]),
        name: format!("test-bucket-{seed}"),
        owner: "fixture".into(),
        bdk_wrapped: vec![0],
        kek_version: 1,
        disposable: true,
        created_at: NOW,
    };
    assert_eq!(c.create_bucket(&bucket).await.unwrap(), Guard::Applied(()));
    bucket
}

fn extent(bucket: &Bucket, seed: u8) -> ExtentRow {
    ExtentRow {
        id: ExtentId::mint([seed; 13]),
        bucket_id: bucket.id.clone(),
        generation_id: None,
        state: ExtentState::Staged,
        seq: None,
        plain_offset: None,
        plain_size: 5,
        cipher_size: 69,
        media_header: vec![0; 48],
        key_mode: 1,
        wrapped_file_key: Some(vec![0; 73]),
        plain_md5: [seed; 16],
        plain_sha256: [seed; 32],
        cipher_sha256: [seed; 32],
        safety_state: SafetyState::Held,
        article_count: None,
        plan_rev: 0,
        last_verified_at: None,
        release_evidence: None,
        released_at: None,
        created_at: NOW,
    }
}

fn generation(bucket: &Bucket, key: &str, seed: u8) -> GenerationRow {
    let at = NOW.plus_ms(i64::from(seed));
    GenerationRow {
        id: GenerationId::mint(at, [seed; 8]),
        bucket_id: bucket.id.clone(),
        key: key.into(),
        state: GenerationState::Live,
        size: 5,
        etag: format!("\"etag-{seed}\""),
        checksum_json: None,
        content_json: "{}".into(),
        user_meta_json: "{}".into(),
        extent_count: 1,
        created_at: at,
        retired_at: None,
    }
}

fn put(bucket: &Bucket, key: &str, seed: u8) -> CommitGeneration {
    let generation = generation(bucket, key, seed);
    let mut row = extent(bucket, seed);
    row.generation_id = Some(generation.id.clone());
    row.state = ExtentState::Committed;
    row.seq = Some(0);
    row.plain_offset = Some(0);
    CommitGeneration {
        now: generation.created_at,
        generation,
        extents: vec![row],
    }
}

async fn publish(
    c: &SqlCatalog<TestSql>,
    put: &CommitGeneration,
    cond: Option<&Precondition>,
) -> bool {
    match c
        .commit_generation(put, cond, Recorded::for_test(&put.generation.id))
        .await
        .unwrap()
    {
        PublishOutcome::Applied => true,
        PublishOutcome::Refused(_) => false,
        other => panic!("PUT unexpectedly fenced: {other:?}"),
    }
}

async fn rows(c: &SqlCatalog<TestSql>, query: &str, params: &[SqlValue]) -> Vec<Row> {
    c.sql.fixture_query(query, params).await.unwrap()
}

#[tokio::test]
async fn u1_lost_commit_acknowledgements_are_not_guard_refusals() {
    let Some(c) = catalogue() else { return };
    let b = bucket(&c, 5).await;
    let name = rows(&c, "SELECT current_schema()::text", &[]).await;
    let [SqlValue::Text(schema)] = name[0].as_slice() else {
        panic!("expected test schema")
    };
    let puts: Vec<_> = (0..C)
        .map(|i| put(&b, &format!("unknown-{i}"), 175 + i))
        .collect();
    let lock_key = c.sql.postgres_lock_key().unwrap();
    let results = join_all(puts.iter().map(|put| async move {
        let socket = pg_commit_fault::DropCommitAck::for_schema(schema);
        let faulted = SqlCatalog::new(PgSql::new(
            socket.clone(),
            socket.clone(),
            PgConfig {
                lock_key,
                ..PgConfig::default()
            },
        ));
        let result = faulted
            .commit_generation(put, None, Recorded::for_test(&put.generation.id))
            .await;
        assert!(
            socket.saw_commit(),
            "test transport never observed a COMMIT acknowledgement"
        );
        result
    }))
    .await;
    for (put, result) in puts.iter().zip(results) {
        assert!(
            matches!(result, Err(BridgeError::Sql(ref error)) if error == "pg: statement failed"),
            "{result:?}"
        );
        let (head, extents) = c
            .live_object(&b.id, &put.generation.key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.id, put.generation.id);
        assert_eq!(extents[0].id, put.extents[0].id);
        assert!(
            !publish(&c, put, None).await,
            "duplicate retry must not republish"
        );
    }
}

#[tokio::test]
async fn s1_conditional_put_has_no_wrong_outcomes_at_eight_contenders() {
    let Some(c) = catalogue() else { return };
    let b = bucket(&c, 1).await;
    for (case, key) in ["new", "match", "missing", "mixed"].into_iter().enumerate() {
        let base = 10 + u8::try_from(case).unwrap() * 10;
        let initial = put(&b, key, base);
        if matches!(key, "match" | "mixed") {
            assert!(publish(&c, &initial, None).await);
        }
        let guard = if key == "new" {
            Precondition::Absent
        } else {
            Precondition::Etag(initial.generation.etag.clone())
        };
        // Give the unconditional request the greatest generation ID, so it
        // can still succeed if an ETag match runs first.
        let writes: Vec<_> = (1..=C).rev().map(|i| put(&b, key, base + i)).collect();
        let outcomes = join_all(writes.iter().enumerate().map(|(i, put)| {
            let cond = if key == "mixed" && i == 0 {
                None
            } else {
                Some(&guard)
            };
            publish(&c, put, cond)
        }))
        .await;
        let successes: Vec<_> = writes
            .iter()
            .zip(outcomes)
            .filter_map(|(put, applied)| applied.then_some(&put.generation.id))
            .collect();
        let current = c.live_object(&b.id, key).await.unwrap();
        if key == "missing" {
            assert!(successes.is_empty() && current.is_none());
        } else if key == "mixed" {
            // An ETag match may commit before an unconditional write. When
            // the unconditional write runs first, every match must lose.
            assert!(matches!(successes.len(), 1 | 2), "{key}: {successes:?}");
            assert_eq!(successes[0], &writes[0].generation.id);
            assert_eq!(current.unwrap().0.id, writes[0].generation.id);
        } else {
            assert_eq!(successes.len(), 1, "{key}: {successes:?}");
            assert_eq!(&current.unwrap().0.id, successes[0]);
        }
        let key_bind = [SqlValue::Text(key.into())];
        let committed = successes.len() + usize::from(matches!(key, "match" | "mixed"));
        let actual = rows(
            &c,
            "SELECT count(*) FROM generations WHERE key = ?1",
            &key_bind,
        )
        .await;
        assert_eq!(actual, vec![vec![SqlValue::Int(committed as i64)]]);
        let missing_refs = rows(
            &c,
            "SELECT count(*) FROM generations g WHERE g.key = ?1 AND NOT EXISTS (\
             SELECT 1 FROM generation_extents ge JOIN outbox o ON o.extent_id = ge.extent_id \
             WHERE ge.generation_id = g.id AND o.generation_id = g.id)",
            &key_bind,
        )
        .await;
        assert_eq!(missing_refs, vec![vec![SqlValue::Int(0)]]);
    }
}

#[tokio::test]
async fn s2_eight_takeover_contenders_leave_one_owner_and_fence_stale_writes() {
    let Some(c) = catalogue() else { return };
    let b = bucket(&c, 3).await;
    let p = put(&b, "lease", 50);
    assert!(publish(&c, &p, None).await);
    let at = p.now;
    let lease = c
        .claim(
            &p.extents[0].id,
            &p.generation.id,
            OutboxStage::Post,
            "original",
            at,
        )
        .await
        .unwrap()
        .unwrap();
    let later = at.plus_ms(600_001);
    let contenders: Vec<_> = (0..C).map(|i| format!("contender-{i}")).collect();
    let claims = join_all(contenders.iter().map(|name| {
        c.claim(
            &lease.extent,
            &lease.generation,
            OutboxStage::Post,
            name,
            later,
        )
    }))
    .await;
    let winners: Vec<_> = claims
        .into_iter()
        .filter_map(|claim| claim.unwrap())
        .collect();
    assert_eq!(winners.len(), 1);
    assert!(winners[0].token > lease.token);

    let bound = [SqlValue::Text(lease.extent.as_str().into())];
    let snapshot = "SELECT lease_token, lease_owner, lease_until, next_at, stage, cursor FROM outbox WHERE extent_id = ?1";
    let before = rows(&c, snapshot, &bound).await;
    let cipher_size = p.extents[0].cipher_size;
    let (packed, articles) = velmora_bridge::plan::plan_seeded(
        &mut velmora::rng::SystemRng,
        NOW.0 / 1000,
        &["alt.binaries.test"],
        &lease.extent,
        cipher_size,
        |_| Some([0; 32]),
    )
    .unwrap();
    assert!(!c.renew(&lease, later).await.unwrap());
    assert!(!c
        .advance(&lease, OutboxStage::Verify, later, later)
        .await
        .unwrap());
    assert!(!c
        .fail(&lease, FailClass::Internal, later, later)
        .await
        .unwrap());
    assert!(!c.defer(&lease, later, later).await.unwrap());
    assert!(!c.defer_at(&lease, 1, later, later).await.unwrap());
    assert!(!c.set_cursor(&lease, 1, later).await.unwrap());
    assert!(c.plan_articles(&lease, &articles).await.unwrap().is_none());
    assert!(c
        .plan_packed(&lease, cipher_size, &packed, None)
        .await
        .unwrap()
        .is_none());
    assert!(!c.mark_posted(&lease, 0, "p1", later).await.unwrap());
    assert!(!c
        .mark_posted_many(&lease, &[(0, "p1")], later)
        .await
        .unwrap());
    assert!(!c.mark_reposted_many(&lease, &[0], later).await.unwrap());
    assert_eq!(
        c.renew_all(&lease, &[], later).await.unwrap(),
        (false, vec![])
    );
    assert_eq!(rows(&c, snapshot, &bound).await, before);
    assert!(c.articles(&lease.extent).await.unwrap().is_empty());
    let owner = &winners[0];
    assert!(c.plan_articles(owner, &articles).await.unwrap().is_some());
    for article in &articles {
        assert!(c
            .mark_posted(owner, article.idx, "p1", later)
            .await
            .unwrap());
    }
    assert!(c
        .advance(owner, OutboxStage::Verify, later, later)
        .await
        .unwrap());
    let claim = |stage, time, who: &'static str| {
        c.claim(&lease.extent, &lease.generation, stage, who, time)
    };
    let stale_verify = claim(OutboxStage::Verify, later, "verifier-old")
        .await
        .unwrap()
        .unwrap();
    let t2 = later.plus_ms(600_001);
    let pass = |at, backbone: &str| VerificationRow {
        extent_id: lease.extent.clone(),
        backbone: backbone.into(),
        provider_id: "p1".into(),
        verified_at: at,
        plan_rev: 1,
        articles_ok: articles.len() as u32,
        articles_total: articles.len() as u32,
        result: VerifyResult::Ok,
        kind: VerifyKind::Body,
    };
    // The old holder records a full pass immediately before the takeover,
    // in the same millisecond. It is still fresh even after updated_at moves.
    assert!(matches!(
        c.record_verification(&stale_verify, &pass(t2, "bb")).await,
        Ok(VerifyRecord::Stored)
    ));
    let verify = claim(OutboxStage::Verify, t2, "verifier-new")
        .await
        .unwrap()
        .unwrap();
    assert!(verify.token > stale_verify.token);
    assert!(matches!(
        c.record_verification(&stale_verify, &pass(t2, "other"))
            .await,
        Ok(VerifyRecord::Fenced)
    ));
    for mode in [None, Some(false), Some(true)] {
        let outcome = c
            .release_at_verify(&stale_verify, 1, &["bb".into()], "[]", t2, mode)
            .await;
        assert!(
            matches!(outcome, Ok(Guard::Lost)),
            "release at verify ({mode:?}): {outcome:?}"
        );
    }
    assert!(c
        .advance(&verify, OutboxStage::Release, t2, t2)
        .await
        .unwrap());
    let stale_release = claim(OutboxStage::Release, t2, "releaser-old")
        .await
        .unwrap()
        .unwrap();
    let t3 = t2.plus_ms(600_001);
    assert!(matches!(
        c.record_verification(&stale_release, &pass(t3, "bb")).await,
        Ok(VerifyRecord::Stored)
    ));
    let release = claim(OutboxStage::Release, t3, "releaser-new")
        .await
        .unwrap()
        .unwrap();
    assert!(release.token > stale_release.token);
    let before = rows(&c, snapshot, &bound).await;
    let outcome = c
        .begin_release(&stale_release, 1, &["bb".into()], "[]", t3)
        .await;
    assert!(
        matches!(outcome, Ok(Guard::Lost)),
        "begin release: {outcome:?}"
    );
    for need_full in [false, true] {
        let outcome = c
            .begin_release_light(&stale_release, 1, &["bb".into()], "[]", t3, need_full)
            .await;
        assert!(
            matches!(outcome, Ok(Guard::Lost)),
            "begin light release ({need_full}): {outcome:?}"
        );
    }
    assert_eq!(rows(&c, snapshot, &bound).await, before);

    let t4 = t3.plus_ms(1);
    assert!(matches!(
        c.record_verification(&release, &pass(t4, "bb")).await,
        Ok(VerifyRecord::Stored)
    ));
    assert!(matches!(
        c.begin_release(&release, 1, &["bb".into()], "[]", t4).await,
        Ok(Guard::Applied(()))
    ));
    let state = "SELECT safety_state FROM extents WHERE id = ?1";
    let releasing = vec![vec![SqlValue::Text("releasing".into())]];
    assert_eq!(rows(&c, state, &bound).await, releasing);
    assert!(
        matches!(c.finish_release(&stale_release, t4).await, Ok(false)),
        "stale finish changed a releasing extent"
    );
    assert!(
        matches!(c.reopen_release(&stale_release, t4).await, Ok(false)),
        "stale reopen changed a releasing extent"
    );
    assert_eq!(rows(&c, state, &bound).await, releasing);
}

#[tokio::test]
async fn s3_complete_abort_and_replacement_leave_a_consistent_upload() {
    let Some(c) = catalogue() else { return };
    let b = bucket(&c, 2).await;
    for i in 0..C {
        let id = UploadId::mint([i; 16]);
        let key = format!("upload-{i}");
        let t = UploadTarget {
            bucket: &b.id,
            key: &key,
            id: &id,
        };
        c.create_upload(&UploadRow {
            id: id.clone(),
            bucket_id: b.id.clone(),
            key: key.clone(),
            content_json: "{}".into(),
            user_meta_json: "{}".into(),
            state: UploadState::Open,
            revision: 0,
            completed_generation_id: None,
            complete_digest: None,
            result_etag: None,
            initiated_at: NOW,
        })
        .await
        .unwrap();
        let old = extent(&b, 70 + i);
        let part = |row: &ExtentRow| UploadPartRow {
            upload_id: id.clone(),
            part_number: 1,
            extent_id: row.id.clone(),
            size: 5,
            etag: "\"part\"".into(),
            uploaded_at: NOW,
        };
        assert_eq!(
            c.put_upload_part(&t, &part(&old), &old, NOW).await.unwrap(),
            Guard::Applied(())
        );
        let commit = CompleteUpload {
            generation: generation(&b, &key, 70 + i),
            placements: vec![ExtentPlacement {
                extent_id: old.id.clone(),
                seq: 0,
                plain_offset: 0,
            }],
            now: NOW,
        };
        let replacements: Vec<_> = (0..C - 2)
            .map(|n| {
                let row = extent(&b, 100 + i * C + n);
                (part(&row), row)
            })
            .collect();
        let (done, aborted, replaced) = tokio::join!(
            c.complete_upload(
                &t,
                1,
                &[42; 32],
                &commit,
                None,
                Recorded::for_test(&commit.generation.id)
            ),
            c.abort_upload(&t, NOW),
            join_all(
                replacements
                    .iter()
                    .map(|(part, row)| c.put_upload_part(&t, part, row, NOW))
            ),
        );
        let head = c.live_object(&b.id, &key).await.unwrap();
        let (upload, _) = c
            .upload(&t)
            .await
            .unwrap()
            .expect("persisted upload receipt");
        match done.unwrap() {
            PublishOutcome::Applied => {
                assert_eq!(upload.state, UploadState::Completed);
                assert_eq!(
                    upload.completed_generation_id.as_ref(),
                    Some(&commit.generation.id)
                );
                assert_eq!(aborted.unwrap(), Guard::Lost);
                assert!(replaced
                    .into_iter()
                    .all(|result| result.unwrap() == Guard::Lost));
                let (head, extents) = head.unwrap();
                assert_eq!(head.id, commit.generation.id);
                assert_eq!(extents.len(), 1);
                assert_eq!(extents[0].id, old.id);
                assert_eq!(extents[0].safety_state, SafetyState::Held);
            }
            PublishOutcome::Refused(_) => {
                assert_eq!(upload.state, UploadState::Aborted);
                assert!(upload.completed_generation_id.is_none());
                assert_eq!(aborted.unwrap(), Guard::Applied(()));
                // A replacement can win before Abort, but none may return a SQL error.
                for result in replaced {
                    let _ = result.unwrap();
                }
                assert!(head.is_none());
            }
            other => panic!("unexpected unknown outcome: {other:?}"),
        }
    }
}

#[tokio::test]
async fn bucket_delete_and_put_cannot_both_succeed() {
    let Some(c) = catalogue() else { return };
    let mut buckets = Vec::new();
    for i in 0..C {
        buckets.push(bucket(&c, 100 + i).await);
    }
    for (batch, group) in buckets.chunks(usize::from(C / 2)).enumerate() {
        join_all(group.iter().enumerate().map(|(i, b)| {
            let c = &c;
            async move {
                let put = put(b, "key", 100 + batch as u8 * (C / 2) + i as u8);
                let (deleted, outcome) = tokio::join!(
                    c.delete_bucket(b),
                    c.commit_generation(&put, None, Recorded::for_test(&put.generation.id)),
                );
                let deleted = deleted.unwrap() == Guard::Applied(());
                let stored = match outcome {
                    Ok(PublishOutcome::Applied) => true,
                    Ok(PublishOutcome::Refused(_)) => false,
                    Err(BridgeError::Sql(error)) if error == "pg: constraint violation" => false,
                    other => panic!("unexpected concurrent PUT result: {other:?}"),
                };
                assert_ne!(deleted, stored);
                assert_eq!(c.bucket_by_name(&b.name).await.unwrap().is_some(), stored);
                assert_eq!(c.live_object(&b.id, "key").await.unwrap().is_some(), stored);
            }
        }))
        .await;
    }
}

#[tokio::test]
async fn orphan_claim_cannot_delete_a_concurrently_published_extent() {
    use velmora_bridge::replay::{ReplayExtent, ReplayPublish};

    let Some(c) = catalogue() else { return };
    let b = bucket(&c, 4).await;
    let now = NOW.plus_ms(32 * 86_400_000);
    // Four pairs put eight requests in flight against the same schema.
    join_all((0..C / 2).map(|i| {
        let c = &c;
        let b = &b;
        async move {
            let source = extent(b, 200 + i);
            let taken = c.replay_extents(b, &[ReplayExtent {
                row: source.clone(), plan: None, packed: None, parity: None, safety_present: true,
            }], NOW).await.unwrap();
            assert!(taken.is_empty());
            let inserted = rows(c,
                "INSERT INTO gc(extent_id, action, due_at) VALUES (?1, 'delete_safety', ?2) RETURNING id",
                &[SqlValue::Text(source.id.as_str().into()), SqlValue::Int(NOW.0)],
            ).await;
            let [SqlValue::Int(id)] = inserted[0].as_slice() else { panic!("expected GC row ID") };
            let gc = [GcRow { id: *id, extent_id: source.id.clone(), action: GcAction::DeleteSafety, due_at: NOW, done_at: None }];
            let key = format!("replay-{i}");
            let gen = generation(b, &key, 200 + i);
            let placements = [ExtentPlacement { extent_id: source.id.clone(), seq: 0, plain_offset: 0 }];
            let (published, (claim, status)) = tokio::join!(
                c.replay_publish(&gen, &placements, now),
                c.gc_orphan_claim(&gc, now, NOW.plus_ms(1)),
            );
            status.unwrap();
            let live = c.live_object(&b.id, &key).await.unwrap();
            match published.unwrap() {
                ReplayPublish::Published => {
                    assert_eq!(claim, [false]);
                    let (head, extents) = live.unwrap();
                    assert_eq!(head.id, gen.id);
                    assert_eq!(extents[0].safety_state, SafetyState::Held);
                }
                ReplayPublish::Damaged => {
                    assert_eq!(claim, [true]);
                    assert!(live.is_none());
                }
                other => panic!("unexpected replay result: {other:?}"),
            }
        }
    })).await;
}
