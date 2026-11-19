//! The one-statement lookups (`Catalog::auth_lookup`,
//! `Catalog::read_lookup`, `Catalog::pinned_read`) answer what the
//! single reads they stand for answer, for every key, bucket, object
//! and window.

mod service_support;

use service_support::*;
use velmora::media::PLAIN_CHUNK_SIZE;
use velmora_bridge::*;

const CHUNK: u64 = PLAIN_CHUNK_SIZE;

fn rows(extents: &[ReadExtent]) -> Vec<&ExtentRow> {
    extents.iter().map(|e| &e.row).collect()
}

async fn same(rig: &Rig, q: &ReadQuery<'_>) -> ReadLookup {
    let catalog = &rig.bridge.catalog;
    let before = catalog.sql.trips.get();
    let one = catalog.read_lookup(q).await.unwrap();
    assert_eq!(catalog.sql.trips.get() - before, 1, "{q:?}");
    let parts = read_lookup_by_parts(catalog, q).await.unwrap();
    assert!(one.key == parts.key, "{q:?}");
    assert_eq!(one.bucket, parts.bucket, "{q:?}");
    assert_eq!(one.perm, parts.perm, "{q:?}");
    assert_eq!(one.generation, parts.generation, "{q:?}");
    assert_eq!(rows(&one.extents), rows(&parts.extents), "{q:?}");
    one
}

#[tokio::test(flavor = "current_thread")]
async fn one_statement_answers_what_the_single_reads_answer() {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = 2 * CHUNK;
    cfg.slice_bytes = 2 * CHUNK;
    let rig = rig_with(NoNntp, cfg);
    let (bucket, signer) = rig.standard("bkt-one").await;
    let other = rig.bucket("bkt-two", true).await;
    rig.key("AKIDTESTKEY000000002", secret(), KeyStatus::Disabled)
        .await;
    rig.grant("AKIDTESTKEY000000002", &bucket, Perm::Rw).await;
    rig.key("AKIDTESTKEY000000003", secret(), KeyStatus::Active)
        .await;
    rig.grant("AKIDTESTKEY000000003", &other, Perm::Ro).await;

    let size = 7 * CHUNK + 4321;
    let body = pattern(21, size as usize);
    rig.put(&signer, "bkt-one", "big", &body).await.expect(200);
    rig.put(&signer, "bkt-one", "small", b"x").await.expect(200);
    rig.put(&signer, "bkt-one", "empty", b"").await.expect(200);

    let edges = [
        0,
        1,
        CHUNK,
        2 * CHUNK - 1,
        2 * CHUNK,
        2 * CHUNK + 1,
        6 * CHUNK,
        size - 1,
        size,
        size + 1,
        u64::MAX,
    ];
    let mut windows = vec![ReadWindow::Nothing];
    for start in edges {
        for end in edges {
            windows.push(ReadWindow::Span { start, end });
        }
        windows.push(ReadWindow::Tail { len: start });
    }
    let mut with_extents = 0;
    for akid in [
        AKID,
        "AKIDTESTKEY000000002",
        "AKIDTESTKEY000000003",
        "AKIDUNKNOWN",
        "",
    ] {
        for name in ["bkt-one", "bkt-two", "bkt-none", ""] {
            for key in ["big", "small", "empty", "absent", ""] {
                for window in &windows {
                    for max_len in [0, 1, 2 * CHUNK, size - 1, size, u64::MAX] {
                        let q = ReadQuery {
                            akid,
                            bucket: name,
                            key,
                            window: *window,
                            max_len,
                        };
                        let found = same(&rig, &q).await;
                        let granted = akid == AKID && name == "bkt-one";
                        assert!(granted || found.generation.is_none(), "{q:?}");
                        assert!(granted || found.extents.is_empty(), "{q:?}");
                        with_extents += usize::from(!found.extents.is_empty());
                    }
                }
            }
        }
    }
    assert!(with_extents > 100, "{with_extents}");

    // A whole read of the object: every extent, in order, each with
    // what is known of its last read.
    let q = ReadQuery {
        akid: AKID,
        bucket: "bkt-one",
        key: "big",
        window: ReadWindow::Span {
            start: 0,
            end: u64::MAX,
        },
        max_len: u64::MAX,
    };
    let found = same(&rig, &q).await;
    let (generation, extents) = rig.live(&bucket, "big").await.unwrap();
    assert_eq!(found.generation.as_ref(), Some(&generation));
    assert_eq!(rows(&found.extents), extents.iter().collect::<Vec<_>>());
    assert_eq!(extents.len(), 4);

    // The read pinned to a generation.
    let catalog = &rig.bridge.catalog;
    for start in edges {
        for end in edges {
            if start > i64::MAX as u64 || end > i64::MAX as u64 {
                continue;
            }
            let before = catalog.sql.trips.get();
            let one = catalog
                .pinned_read(&bucket.id, &generation.id, start, end)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(catalog.sql.trips.get() - before, 1);
            let parts = pinned_read_by_parts(catalog, &bucket.id, &generation.id, start, end)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(one.bucket, parts.bucket);
            assert_eq!(one.generation, parts.generation);
            assert_eq!(rows(&one.extents), rows(&parts.extents), "{start} {end}");
        }
    }
    // A generation is found only in its own bucket.
    let none = catalog
        .pinned_read(&other.id, &generation.id, 0, size)
        .await
        .unwrap();
    assert!(none.is_none());
    let none = pinned_read_by_parts(catalog, &other.id, &generation.id, 0, size)
        .await
        .unwrap();
    assert!(none.is_none());
}

/// The test database refuses what D1 refuses: a compound SELECT of more
/// than five terms. The read lookup is five arms, so a sixth would fail
/// here as it would fail every GET on D1.
#[tokio::test(flavor = "current_thread")]
async fn a_compound_select_has_no_more_terms_than_d1_takes() {
    let sql = velmora_bridge::testkit::RusqliteSql::open_in_memory().unwrap();
    let terms = |n: i32| {
        (0..n)
            .map(|i| format!("SELECT {i}"))
            .collect::<Vec<_>>()
            .join(" UNION ALL ")
    };
    let most = velmora_bridge::testkit::D1_MAX_COMPOUND_SELECT;
    assert_eq!(
        sql.query(&terms(most), &[]).await.unwrap().len(),
        most as usize
    );
    assert!(sql.query(&terms(most + 1), &[]).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn one_statement_answers_who_asks_as_the_single_reads_do() {
    let rig = rig_with(NoNntp, config(Vec::new()));
    let (bucket, _) = rig.standard("bkt-one").await;
    let other = rig.bucket("bkt-two", true).await;
    rig.key("AKIDTESTKEY000000002", secret(), KeyStatus::Disabled)
        .await;
    rig.grant("AKIDTESTKEY000000002", &bucket, Perm::Rw).await;
    rig.key("AKIDTESTKEY000000003", secret(), KeyStatus::Active)
        .await;
    rig.grant("AKIDTESTKEY000000003", &other, Perm::Ro).await;
    let catalog = &rig.bridge.catalog;
    let script = |text: &str| catalog.sql.with_conn(|c| c.execute_batch(text).unwrap());

    // What makes writes refused: a replay that did not end, and a
    // recorded rollback. A replay that ended does not.
    for (state, refused) in [
        ("", false),
        ("begin", true),
        ("UPDATE restore_state SET state = 'complete';", false),
        (
            "INSERT OR REPLACE INTO rollback_stamp VALUES (1, 0, 'c', 1);",
            true,
        ),
        ("UPDATE rollback_stamp SET rolled_back_at = NULL;", false),
    ] {
        match state {
            "begin" => {
                let now = rig.now();
                let _ = catalog.restore_begin(UnixMs(0), now).await.unwrap();
            }
            text => script(text),
        }
        let mut seen = Vec::new();
        for akid in [
            AKID,
            "AKIDTESTKEY000000002",
            "AKIDTESTKEY000000003",
            "AKIDTESTKEY00000NONE",
            "",
            "' OR 1=1 --",
        ] {
            for name in ["bkt-one", "bkt-two", "bkt-none", ""] {
                for gate in [false, true] {
                    let what = format!("{akid} {name} {gate} {state}");
                    let before = catalog.sql.trips.get();
                    let one = catalog.auth_lookup(akid, name, gate).await.unwrap();
                    assert_eq!(catalog.sql.trips.get() - before, 1, "{what}");
                    let parts = auth_lookup_by_parts(catalog, akid, name, gate)
                        .await
                        .unwrap();
                    assert!(one.key == parts.key, "{what}");
                    assert_eq!(one.bucket, parts.bucket, "{what}");
                    assert_eq!(one.perm, parts.perm, "{what}");
                    assert_eq!(one.restore_pending, parts.restore_pending, "{what}");
                    assert_eq!(one.restore_pending, gate.then_some(refused), "{what}");
                    assert!(one.key.iter().all(|k| k.status == KeyStatus::Active));
                    if gate {
                        seen.push((one.key.is_some(), one.bucket.is_some(), one.perm));
                    }
                }
            }
        }
        // The rows that tell callers apart are all there.
        assert_eq!(seen[0], (true, true, Some(Perm::Rw)));
        assert_eq!(seen[1], (true, true, None));
        assert_eq!(seen[2], (true, false, None));
        assert_eq!(seen[3], (true, false, None));
        // A disabled key has no row and no grant, whatever it was given.
        assert_eq!(seen[4], (false, true, None));
        assert_eq!(seen[8], (true, true, None));
        assert_eq!(seen[9], (true, true, Some(Perm::Ro)));
        assert_eq!(seen[12], (false, true, None));
        assert_eq!(seen[20], (false, true, None));
    }

    // Who asks is answered without the tables of a replay, unless the
    // answer is to say whether writes are refused.
    *catalog.sql.fail_matching.borrow_mut() = Some(("FROM restore_state", 0));
    assert!(catalog.auth_lookup(AKID, "bkt-one", false).await.is_ok());
    assert!(catalog.auth_lookup(AKID, "bkt-one", true).await.is_err());
}
