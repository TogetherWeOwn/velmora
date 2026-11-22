//! The move's fence on the catalogue schema as the binding runs it (DS1
//! §3.3 P7, AM-74, Q31): `sqlite_master` read through the binding,
//! `CREATE TRIGGER` and `DROP TRIGGER` through `exec`, the stored trigger
//! text equal to its source, and one freeze, refused write and thaw.
//!
//! On native SQLite in CI. Under `VELMORA_D1_PROBE` the catalogue is a D1
//! database reached through the probe Worker (`workers/directory-d1-probe`:
//! local D1 under `wrangler dev`, or a throwaway remote D1), with the
//! catalogue's migrations applied statement by statement, their own
//! triggers included.

use velmora_bridge::directory::fence::{
    catalogue_tables, freeze, freeze_state, marker, stamp_row, thaw, FREEZE_TRIGGER_PREFIX,
    FROZEN_MESSAGE, OPERATIONAL_TABLES,
};
use velmora_bridge::ports::{Sql, SqlValue};
use velmora_bridge::BridgeError;

mod directory_support;
use directory_support::{catalogue_database, catalogue_migrations, on_d1, split_sql};

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn frozen(e: &BridgeError) -> bool {
    e.to_string().contains(FROZEN_MESSAGE)
}

/// The splitter keeps a trigger's body whole, `CASE … END` included, and
/// drops comments.
#[test]
fn the_migrations_split_into_whole_statements() {
    let s = split_sql(
        "-- a; comment\nCREATE TABLE a (x TEXT DEFAULT 'a;b'); \
         CREATE TRIGGER t AFTER INSERT ON a BEGIN \
           UPDATE a SET x = CASE WHEN x = 'e' THEN 'f' END; \
           SELECT RAISE(ABORT, 'no;'); \
         END;\nCREATE INDEX i ON a (x);",
    );
    assert_eq!(s.len(), 3, "{s:#?}");
    assert!(
        s[1].starts_with("CREATE TRIGGER t") && s[1].ends_with("END"),
        "{}",
        s[1]
    );
    assert!(!s[0].contains("comment"));
    let all: usize = catalogue_migrations()
        .iter()
        .map(|(_, sql)| split_sql(sql).len())
        .sum();
    let triggers: usize = catalogue_migrations()
        .iter()
        .flat_map(|(_, sql)| split_sql(sql))
        .filter(|s| s.to_ascii_uppercase().starts_with("CREATE TRIGGER"))
        .count();
    let sources: usize = catalogue_migrations()
        .iter()
        .map(|(_, sql)| sql.to_ascii_uppercase().matches("CREATE TRIGGER").count())
        .sum();
    assert_eq!(triggers, sources);
    assert!(all > 50, "{all}");
}

#[test]
fn the_fence_freezes_refuses_and_thaws_through_the_binding() {
    let db = catalogue_database();
    let where_ = if on_d1() { "d1" } else { "sqlite" };
    block_on(async {
        // `sqlite_master` read through the binding.
        let tables = catalogue_tables(&db).await.unwrap();
        println!(
            "fence {where_}: {} catalogue tables: {tables:?}",
            tables.len()
        );
        for t in [
            "objects",
            "generations",
            "extents",
            "access_keys",
            "meta",
            "outbox",
        ] {
            assert!(tables.contains(&t.to_string()), "{t}");
        }
        for t in OPERATIONAL_TABLES {
            assert!(!tables.contains(&t.to_string()), "{t}");
        }
        assert!(tables
            .iter()
            .all(|t| !t.starts_with("_cf_") && t != "d1_migrations"));

        // The migrations' own triggers came through the binding.
        let own = db
            .query(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'",
                &[],
            )
            .await
            .unwrap();
        println!("fence {where_}: migration triggers {:?}", own[0][0]);
        assert!(matches!(own[0][0], SqlValue::Int(n) if n > 0));

        // The stamp row the window names.
        db.exec(
            "INSERT INTO rollback_stamp (id, counter, catalogue_id) VALUES (1, 4, 'main')",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(stamp_row(&db).await.unwrap(), Some((4, "main".into())));

        // The freeze: the marker, then CREATE TRIGGER through `exec`.
        let fenced = freeze(&db, 1).await.unwrap();
        assert_eq!(fenced, tables);
        let state = freeze_state(&db).await.unwrap();
        assert!(state.frozen(), "{state:?}");
        assert_eq!(marker(&db).await.unwrap(), Some(1));

        // The stored text of a trigger, exactly as its source.
        let rows = db
            .query(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                &[SqlValue::Text(format!("{FREEZE_TRIGGER_PREFIX}meta_ins"))],
            )
            .await
            .unwrap();
        let stored = match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Text(s)) => s.clone(),
            other => panic!("{other:?}"),
        };
        println!("fence {where_}: stored trigger text: {stored}");
        assert_eq!(
            stored,
            format!(
                "CREATE TRIGGER {FREEZE_TRIGGER_PREFIX}meta_ins BEFORE INSERT ON meta BEGIN SELECT RAISE(ABORT, '{FROZEN_MESSAGE}'); END"
            )
        );

        // A refused write of each kind, reads go on, the operational
        // tables still take writes.
        let insert = db
            .exec("INSERT INTO meta (k, v) VALUES ('probe', 1)", &[])
            .await
            .unwrap_err();
        println!("fence {where_}: refused insert: {insert}");
        assert!(frozen(&insert), "{insert}");
        let update = db
            .exec("UPDATE rollback_stamp SET counter = 5 WHERE id = 1", &[])
            .await
            .unwrap_err();
        assert!(frozen(&update), "{update}");
        let delete = db
            .exec("DELETE FROM rollback_stamp WHERE id = 1", &[])
            .await
            .unwrap_err();
        assert!(frozen(&delete), "{delete}");
        let batch = db
            .batch(vec![
                (
                    "INSERT INTO provider_health (provider_id) VALUES ('p1')",
                    vec![],
                ),
                ("INSERT INTO meta (k, v) VALUES ('probe', 2)", vec![]),
            ])
            .await
            .unwrap_err();
        assert!(frozen(&batch), "{batch}");
        assert_eq!(stamp_row(&db).await.unwrap(), Some((4, "main".into())));
        db.exec(
            "INSERT INTO provider_health (provider_id) VALUES ('p1')",
            &[],
        )
        .await
        .unwrap();

        // A second freeze changes nothing: every trigger is already exact.
        freeze(&db, 1).await.unwrap();
        assert!(freeze_state(&db).await.unwrap().frozen());

        // The thaw: DROP TRIGGER through `exec`, then the marker.
        thaw(&db).await.unwrap();
        let state = freeze_state(&db).await.unwrap();
        assert!(state.thawed(), "{state:?}");
        db.exec("INSERT INTO meta (k, v) VALUES ('probe', 3)", &[])
            .await
            .unwrap();
        let own_after = db
            .query(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(own_after, own, "the thaw dropped a migration trigger");
    });
}
