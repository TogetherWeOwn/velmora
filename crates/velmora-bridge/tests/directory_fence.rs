//! The move's fence on tenant 0's D1 catalogue: the marker, the freeze
//! triggers on every catalogue table, reads that still serve under them
//! (from Usenet too), the legacy stamp, and the thaw of a move that is
//! given up.

mod nntp_support;
mod service_support;

use nntp_support::{TcpConnector, PASS, USER};
use service_support::*;
use velmora_bridge::directory::fence::{
    catalogue_tables, freeze, freeze_state, marker, put_legacy_stamp, stamp_row, thaw,
    FROZEN_MESSAGE, OPERATIONAL_TABLES,
};
use velmora_bridge::directory::tenant_zero::database_facts;
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const BUCKET: &str = "vault";

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn frozen_error(e: &BridgeError) -> bool {
    e.to_string().contains(FROZEN_MESSAGE)
}

/// A rig with one object in it, and the stamp raised once.
async fn loaded() -> (Rig, Signer, Vec<u8>) {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(7, 300_000);
    let r = rig.put(&signer, BUCKET, "kept.bin", &body).await;
    assert_eq!(r.status, 200, "{}", r.status);
    rig.bridge.raise_stamp().await.unwrap();
    (rig, signer, body)
}

/// A catalogue whose stamp was never raised has no catalogue id for the
/// window to name: the freeze refuses it before writing anything.
#[test]
fn a_catalogue_without_its_stamp_row_is_not_frozen() {
    block_on(async {
        let rig = rig();
        let (_, signer) = rig.standard(BUCKET).await;
        let r = rig
            .put(&signer, BUCKET, "kept.bin", &pattern(7, 1_000))
            .await;
        assert_eq!(r.status, 200, "{}", r.status);
        let sql = &rig.bridge.catalog.sql;
        assert_eq!(stamp_row(sql).await.unwrap(), None);
        assert!(freeze(sql, 1).await.is_err());
        assert_eq!(marker(sql).await.unwrap(), None);
        assert!(!freeze_state(sql).await.unwrap().frozen());
        rig.bridge.raise_stamp().await.unwrap();
        freeze(sql, 1).await.unwrap();
    });
}

#[test]
fn every_write_to_every_catalogue_table_aborts_and_reads_go_on() {
    block_on(async {
        let (rig, signer, body) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        let tables = freeze(sql, 1).await.unwrap();
        for t in [
            "objects",
            "generations",
            "extents",
            "access_keys",
            "meta",
            "rollback_stamp",
            "outbox",
        ] {
            assert!(tables.contains(&t.to_string()), "{t}");
        }
        for t in OPERATIONAL_TABLES {
            assert!(!tables.contains(&t.to_string()), "{t}");
        }
        assert!(freeze_state(sql).await.unwrap().frozen());
        assert_eq!(
            database_facts(&rig.bridge.catalog.sql.inner)
                .await
                .unwrap()
                .marker,
            Some(1)
        );

        // Every table refuses a delete, an update and an insert. The
        // triggers fire per row: on an empty table a delete or an update
        // changes nothing and has nothing to refuse.
        let mut refused = 0;
        for t in &tables {
            let n = rig.count(t);
            let r = sql.exec(&format!("DELETE FROM {t}"), &[]).await;
            match n {
                0 => assert_eq!(r.unwrap(), 0, "{t}"),
                _ => {
                    assert!(frozen_error(&r.unwrap_err()), "{t}");
                    refused += 1;
                }
            }
            assert_eq!(rig.count(t), n, "{t}");
            let col = sql
                .query(
                    &format!("SELECT name FROM pragma_table_info('{t}') LIMIT 1"),
                    &[],
                )
                .await
                .unwrap();
            let SqlValue::Text(col) = &col[0][0] else {
                panic!("{t}")
            };
            let r = sql
                .exec(&format!("UPDATE {t} SET {col} = {col}"), &[])
                .await;
            match n {
                0 => assert!(r.is_ok(), "{t}"),
                _ => assert!(frozen_error(&r.unwrap_err()), "{t}"),
            }
            let e = sql
                .exec(&format!("INSERT INTO {t} DEFAULT VALUES"), &[])
                .await
                .unwrap_err();
            assert!(
                frozen_error(&e) || e.to_string().contains("constraint"),
                "{t}"
            );
        }
        // The loaded catalogue has rows in most tables.
        assert!(refused >= 8, "{refused}");
        let e = sql
            .exec("INSERT INTO meta (k, v) VALUES ('x', 1)", &[])
            .await
            .unwrap_err();
        assert!(frozen_error(&e));

        // Reads go on: GET, a ranged GET, HEAD and a listing.
        let get = rig
            .call(
                &signer,
                Method::Get,
                &path(BUCKET, "kept.bin"),
                &[],
                &[],
                b"",
            )
            .await;
        assert_eq!(get.status, 200);
        assert_eq!(get.body, body);
        let ranged = rig
            .call(
                &signer,
                Method::Get,
                &path(BUCKET, "kept.bin"),
                &[],
                &[("range", "bytes=1000-1999")],
                b"",
            )
            .await;
        assert_eq!(ranged.status, 206);
        assert_eq!(ranged.body, body[1000..2000]);
        assert_eq!(rig.head(&signer, BUCKET, "kept.bin").await.status, 200);
        let list = rig
            .call(
                &signer,
                Method::Get,
                &format!("/{BUCKET}"),
                &[("list-type", "2")],
                &[],
                b"",
            )
            .await;
        assert_eq!(list.status, 200);
        assert!(String::from_utf8_lossy(&list.body).contains("kept.bin"));

        // A write is refused and leaves no row.
        let objects = rig.count("objects");
        let put = rig.put(&signer, BUCKET, "new.bin", b"nope").await;
        assert!(put.status >= 500, "{}", put.status);
        assert_eq!(rig.count("objects"), objects);
    });
}

/// A trigger of a freeze name that does not abort, or that fences less
/// than its whole operation, is not counted, and the next freeze replaces
/// it.
#[test]
fn a_trigger_that_only_looks_like_a_freeze_trigger_is_replaced() {
    block_on(async {
        let (rig, _, _) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        sql.exec(
            &format!(
                "CREATE TRIGGER move_freeze_meta_ins BEFORE INSERT ON meta \
                 BEGIN SELECT '{FROZEN_MESSAGE}'; END"
            ),
            &[],
        )
        .await
        .unwrap();
        sql.exec(
            &format!(
                "CREATE TRIGGER move_freeze_meta_upd BEFORE UPDATE OF v ON meta \
                 BEGIN SELECT RAISE(ABORT, '{FROZEN_MESSAGE}'); END"
            ),
            &[],
        )
        .await
        .unwrap();
        let state = freeze_state(sql).await.unwrap();
        assert!(!state.frozen());
        assert!(state.unfenced.contains(&"meta.INSERT".to_string()));
        assert!(state.unfenced.contains(&"meta.UPDATE".to_string()));
        freeze(sql, 1).await.unwrap();
        assert!(freeze_state(sql).await.unwrap().frozen());
        let e = sql
            .exec("INSERT INTO meta (k, v) VALUES ('x', 1)", &[])
            .await
            .unwrap_err();
        assert!(frozen_error(&e));
        let e = sql
            .exec("UPDATE meta SET k = 'gone' WHERE k = 'cutover_marker'", &[])
            .await
            .unwrap_err();
        assert!(frozen_error(&e));
        // A trigger under the prefix on no catalogue table is a stray.
        sql.exec(
            "CREATE TRIGGER move_freeze_extra BEFORE INSERT ON provider_health BEGIN SELECT 1; END",
            &[],
        )
        .await
        .unwrap();
        let state = freeze_state(sql).await.unwrap();
        assert_eq!(state.stray, ["move_freeze_extra"]);
        assert!(!state.frozen());
    });
}

#[test]
fn the_freeze_can_be_run_again_and_finds_what_it_does_not_fence() {
    block_on(async {
        let (rig, _, _) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        let first = freeze(sql, 1).await.unwrap();
        let again = freeze(sql, 1).await.unwrap();
        assert_eq!(first, again);
        // Another move's marker is not written over.
        assert!(freeze(sql, 2).await.is_err());
        assert_eq!(marker(sql).await.unwrap(), Some(1));
        // A table that appears after the freeze is not fenced, and the
        // state says so; DDL is not stopped by the triggers.
        sql.exec("CREATE TABLE later_t (x INTEGER)", &[])
            .await
            .unwrap();
        let state = freeze_state(sql).await.unwrap();
        assert!(!state.frozen());
        assert_eq!(
            state.unfenced,
            ["later_t.INSERT", "later_t.UPDATE", "later_t.DELETE"]
        );
        freeze(sql, 1).await.unwrap();
        assert!(freeze_state(sql).await.unwrap().frozen());
    });
}

#[test]
fn a_thaw_leaves_nothing_of_the_fence() {
    block_on(async {
        let (rig, signer, _) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        let tables_before = catalogue_tables(sql).await.unwrap();
        freeze(sql, 1).await.unwrap();
        thaw(sql).await.unwrap();
        let state = freeze_state(sql).await.unwrap();
        assert!(state.thawed());
        assert_eq!(state.tables, tables_before);
        assert_eq!(marker(sql).await.unwrap(), None);
        thaw(sql).await.unwrap();
        let put = rig.put(&signer, BUCKET, "after.bin", b"back").await;
        assert_eq!(put.status, 200);
    });
}

/// The legacy stamp makes every stamp check on the frozen database say
/// "rolled back": no raise, and so no destructive batch.
#[test]
fn the_legacy_stamp_marks_the_frozen_database_rolled_back() {
    block_on(async {
        let (rig, _, _) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        let safety = &rig.bridge.safety;
        assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());
        let (counter, id) = stamp_row(sql).await.unwrap().unwrap();
        assert_eq!(id, "main");
        // Not before the freeze, and never under another id.
        let e = put_legacy_stamp(sql, safety, "main", rig.now()).await;
        assert!(e.is_err());
        freeze(sql, 1).await.unwrap();
        assert!(put_legacy_stamp(sql, safety, "wrongid", rig.now())
            .await
            .is_err());
        assert!(safety.keys().iter().all(|k| !k.starts_with("rs/wrongid/")));
        let stamp = put_legacy_stamp(sql, safety, "main", rig.now())
            .await
            .unwrap();
        assert_eq!(stamp, counter + 1);
        let key = stamp::stamp_key("main", stamp);
        let body = safety.stored(&key).unwrap().bytes;
        // Run again (step 8 after a crash): the object and its time stay.
        rig.bridge.clock.advance_secs(60);
        assert_eq!(
            put_legacy_stamp(sql, safety, "main", rig.now())
                .await
                .unwrap(),
            stamp
        );
        assert_eq!(safety.stored(&key).unwrap().bytes, body);
        // Under the triggers the check cannot record what it found: an
        // error, which every caller that would delete treats as true.
        let rolled = rig.bridge.catalogue_rolled_back().await;
        assert!(!matches!(rolled, Ok(false)));
        assert!(rig.bridge.raise_stamp().await.is_err());
        // Thawed (a give-up after the flip), the check finds the rollback
        // and records it; writes stay refused until the stamp is levelled.
        thaw(sql).await.unwrap();
        assert!(rig.bridge.catalogue_rolled_back().await.unwrap());
        assert!(rig.bridge.raise_stamp().await.is_err());
    });
}

/// A read from Usenet writes only the operational permits: it serves its
/// verified bytes under the freeze.
#[tokio::test(flavor = "current_thread")]
async fn a_read_from_usenet_serves_under_the_freeze() {
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
    let cfg = config(vec![ProviderConfig {
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
    let budget = ingress::ByteBudget::new(cfg.inflight_budget_bytes);
    let rig = rig_with_budget(TcpConnector::default(), cfg, budget);
    rig.bridge
        .catalog
        .seed_permits(&rig.bridge.cfg.providers)
        .await
        .unwrap();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(3, 200_000);
    rig.put(&signer, BUCKET, "cold.bin", &body)
        .await
        .expect(200);
    let (generation, extents) = rig.live(&bucket, "cold.bin").await.unwrap();
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
            .expect("a posting obligation");
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
    rig.bridge.raise_stamp().await.unwrap();
    freeze(&rig.bridge.catalog.sql, 1).await.unwrap();
    let get = rig
        .call(
            &signer,
            Method::Get,
            &path(BUCKET, "cold.bin"),
            &[],
            &[],
            b"",
        )
        .await;
    assert_eq!(get.status, 200, "{}", get.status);
    assert_eq!(get.body, body);
}
