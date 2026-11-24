//! Native adapter contracts. The same fixture creates a private catalogue for each test.

#![cfg(feature = "testkit-pg")]

use velmora_bridge::testkit::TestSql;
use velmora_bridge::{BridgeError, Dialect, Sql, SqlValue};

fn test_db() -> Option<TestSql> {
    if !TestSql::postgres_selected() {
        return None;
    }
    let db = TestSql::with_schema_unrecorded().expect("Postgres test catalogue");
    assert_eq!(db.dialect(), Dialect::Postgres);
    Some(db)
}

#[tokio::test]
async fn postgresql_schemas_and_lock_keys_are_isolated() {
    let Some(a) = test_db() else { return };
    let b = test_db().unwrap();
    assert_ne!(a.postgres_lock_key(), b.postgres_lock_key());
    let schema = "SELECT current_schema()::text";
    assert_ne!(
        a.query(schema, &[]).await.unwrap(),
        b.query(schema, &[]).await.unwrap()
    );
    a.exec("INSERT INTO tx_guard(ok) VALUES (1)", &[])
        .await
        .unwrap();
    assert!(b
        .query("SELECT ok FROM tx_guard", &[])
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn postgresql_guard_refusal_is_atomic_and_does_not_poison_the_next_call() {
    let Some(db) = test_db() else { return };
    assert!(matches!(
        db.batch(vec![
            ("INSERT INTO tx_guard(ok) VALUES (1)", vec![]),
            ("INSERT INTO tx_guard(ok) VALUES (0)", vec![]),
            ("INSERT INTO tx_guard(ok) VALUES (1)", vec![]),
        ])
        .await,
        Err(BridgeError::GuardFailed)
    ));
    assert!(db
        .query("SELECT ok FROM tx_guard", &[])
        .await
        .unwrap()
        .is_empty());
    assert_eq!(db.exec("SELECT 1", &[]).await.unwrap(), 0);
}

#[tokio::test]
async fn postgresql_usage_trigger_runs_but_exec_counts_only_target_rows() {
    let Some(db) = test_db() else { return };
    let arguments = [SqlValue::Text("b_fixture".into()), SqlValue::Blob(vec![0])];
    db.exec(
        "INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,disposable,created_at) \
         VALUES (?1,'fixture','principal',?2,1,1,0)",
        &arguments,
    )
    .await
    .unwrap();
    let rows = db
        .exec(
            "INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at) \
             VALUES ('g_fixture',?1,'key','live',4,'etag','{}','{}',0,0)",
            &arguments[..1],
        )
        .await
        .unwrap();
    assert_eq!(rows, 1);
    assert_eq!(
        db.query(
            "SELECT live_objects FROM usage_buckets WHERE bucket_id = ?1",
            &arguments[..1]
        )
        .await
        .unwrap(),
        vec![vec![SqlValue::Int(1)]]
    );
}
