//! The move's fence on tenant 0's D1 catalogue: the marker, the freeze
//! triggers on every table, reads that still serve under them, the legacy
//! stamp, and the thaw of a move that is given up.

mod service_support;

use service_support::*;
use velmora_bridge::directory::fence::{
    catalogue_tables, freeze, freeze_state, frozen_counter, put_legacy_stamp, thaw, FROZEN_MESSAGE,
};
use velmora_bridge::directory::tenant_zero::database_facts;
use velmora_bridge::*;

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
    assert_eq!(r.status, 200, "{r:?}");
    rig.bridge.raise_stamp().await.unwrap();
    (rig, signer, body)
}

#[test]
fn every_write_to_every_table_aborts_and_reads_go_on() {
    block_on(async {
        let (rig, signer, body) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        let tables = freeze(sql, rig.now()).await.unwrap();
        for t in [
            "objects",
            "generations",
            "extents",
            "access_keys",
            "meta",
            "rollback_stamp",
            "outbox",
        ] {
            assert!(tables.contains(&t.to_string()), "{t} in {tables:?}");
        }
        let state = freeze_state(sql).await.unwrap();
        assert!(state.frozen(), "{state:?}");
        assert!(
            database_facts(&rig.bridge.catalog.sql.inner)
                .await
                .unwrap()
                .marker
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
            // An update that would change no value still fires the trigger
            // when a row matches.
            let r = sql
                .exec(&format!("UPDATE {t} SET {col} = {col}"), &[])
                .await;
            match n {
                0 => assert!(r.is_ok(), "{t}: {r:?}"),
                _ => assert!(frozen_error(&r.unwrap_err()), "{t}"),
            }
            let e = sql
                .exec(&format!("INSERT INTO {t} DEFAULT VALUES"), &[])
                .await
                .unwrap_err();
            assert!(
                frozen_error(&e) || e.to_string().contains("constraint"),
                "{t}: {e}"
            );
        }
        // The loaded catalogue has rows in most tables.
        assert!(refused >= 8, "{refused}");
        let e = sql
            .exec("INSERT INTO meta (k, v) VALUES ('x', 1)", &[])
            .await
            .unwrap_err();
        assert!(frozen_error(&e), "{e}");

        // Reads go on: GET, HEAD and a listing serve what was committed.
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
        assert_eq!(get.status, 200, "{get:?}");
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
        assert_eq!(ranged.status, 206, "{ranged:?}");
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
        assert_eq!(list.status, 200, "{list:?}");
        assert!(String::from_utf8_lossy(&list.body).contains("kept.bin"));

        // A write is refused and leaves no row.
        let objects = rig.count("objects");
        let put = rig.put(&signer, BUCKET, "new.bin", b"nope").await;
        assert!(put.status >= 500, "{put:?}");
        assert_eq!(rig.count("objects"), objects);
    });
}

#[test]
fn the_freeze_can_be_run_again_and_finds_what_it_does_not_fence() {
    block_on(async {
        let (rig, _, _) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        let first = freeze(sql, rig.now()).await.unwrap();
        let again = freeze(sql, rig.now()).await.unwrap();
        assert_eq!(first, again);
        assert!(freeze_state(sql).await.unwrap().frozen());
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
        // The next freeze fences it too.
        freeze(sql, rig.now()).await.unwrap();
        assert!(freeze_state(sql).await.unwrap().frozen());
    });
}

#[test]
fn a_thaw_leaves_nothing_of_the_fence() {
    block_on(async {
        let (rig, signer, _) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        let tables_before = catalogue_tables(sql).await.unwrap();
        freeze(sql, rig.now()).await.unwrap();
        thaw(sql).await.unwrap();
        let state = freeze_state(sql).await.unwrap();
        assert!(state.thawed(), "{state:?}");
        assert_eq!(state.tables, tables_before);
        assert!(
            !database_facts(&rig.bridge.catalog.sql.inner)
                .await
                .unwrap()
                .marker
        );
        thaw(sql).await.unwrap();
        // Writes work again.
        let put = rig.put(&signer, BUCKET, "after.bin", b"back").await;
        assert_eq!(put.status, 200, "{put:?}");
    });
}

/// The legacy stamp makes every stamp check on the frozen database say
/// "rolled back": no raise, and so no destructive batch.
#[test]
fn the_legacy_stamp_marks_the_frozen_database_rolled_back() {
    block_on(async {
        let (rig, _, _) = loaded().await;
        let sql = &rig.bridge.catalog.sql;
        assert!(!rig.bridge.catalogue_rolled_back().await.unwrap());
        let counter = frozen_counter(sql).await.unwrap().unwrap();
        freeze(sql, rig.now()).await.unwrap();
        let stamp = put_legacy_stamp(sql, &rig.bridge.safety, "main", rig.now())
            .await
            .unwrap();
        assert_eq!(stamp, counter + 1);
        assert!(rig.bridge.safety.contains(&stamp::stamp_key("main", stamp)));
        // Under the triggers the check cannot even record what it found:
        // an error, which every caller that would delete treats as true.
        let rolled = rig.bridge.catalogue_rolled_back().await;
        assert!(!matches!(rolled, Ok(false)), "{rolled:?}");
        assert!(rig.bridge.raise_stamp().await.is_err());
        // Thawed (a give-up after the flip), the check finds the rollback
        // and records it; writes stay refused until the stamp is levelled.
        thaw(sql).await.unwrap();
        assert!(rig.bridge.catalogue_rolled_back().await.unwrap());
        assert!(rig.bridge.raise_stamp().await.is_err());
    });
}
