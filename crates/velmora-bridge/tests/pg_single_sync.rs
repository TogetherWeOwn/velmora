//! Failure semantics of the single-Sync write transport on a real server
//! (`VELMORA_TEST_PG_URL`), some through a framing proxy that injects the
//! faults a pooler can cause. Each case names the outcome the caller sees
//! and what is left in the database.

#![cfg(feature = "testkit-pg")]

mod pg_support;

use std::time::{Duration, Instant};

use pg_support::{connect, unique, Delay, Direct, Fault, Proxy, Schema};
use velmora_bridge::pg::{
    oversize_fallbacks, single_sync_request_bytes, PgSql, WriteTx, MAX_SINGLE_SYNC_BYTES,
};
use velmora_bridge::{BridgeError, Sql, SqlValue};

const SETUP: &str = "CREATE TABLE m (n bigint PRIMARY KEY, t text, b bytea);
    CREATE TABLE tx_guard (ok BIGINT NOT NULL CONSTRAINT tx_guard_ok CHECK (ok = 1));
    CREATE TABLE d (n bigint, CONSTRAINT d_once UNIQUE (n) DEFERRABLE INITIALLY DEFERRED);";

const INSERT: &str = "INSERT INTO m(n) VALUES (?1)";
const GUARD: &str = "INSERT INTO tx_guard(ok) SELECT CASE WHEN ?1 = 1 THEN 1 ELSE 0 END";

fn int(n: i64) -> SqlValue {
    SqlValue::Int(n)
}

fn insert(n: i64) -> (&'static str, Vec<SqlValue>) {
    (INSERT, vec![int(n)])
}

fn is(result: &velmora_bridge::Result<Vec<u64>>, expected: &str) -> bool {
    matches!(result, Err(BridgeError::Sql(e)) if e == expected)
}

const FAILED: &str = "pg: statement failed";

async fn schema() -> Option<Schema> {
    Schema::new(SETUP).await
}

async fn proxied(s: &Schema, fault: Fault) -> (Proxy, PgSql<Direct>) {
    let proxy = Proxy::start(&s.base, Delay::None, fault).await;
    let pg = s.pg(Direct(proxy.config(&s.config())), WriteTx::SingleSync);
    (proxy, pg)
}

#[tokio::test]
async fn a_write_transaction_is_one_request_with_one_sync() {
    let Some(s) = schema().await else { return };
    let (proxy, pg) = proxied(&s, Fault::None).await;
    let counts = pg
        .batch(vec![
            insert(1),
            insert(2),
            (
                "UPDATE m SET t = ?2 WHERE n >= ?1",
                vec![int(1), SqlValue::Text("x".into())],
            ),
            ("SELECT n FROM m", vec![]),
        ])
        .await
        .unwrap();
    assert_eq!(counts, [1, 1, 2, 0]);
    let trace = proxy.trace.lock().unwrap();
    assert_eq!(trace.single_syncs, 1);
    assert_eq!(trace.syncs, 1, "one Sync for the whole transaction");
    assert_eq!(trace.queries, 0, "no simple query on the success path");
    // Prelude (6), four statements, COMMIT: one unnamed Parse each.
    let parses = trace.frontend.iter().filter(|t| **t == b'P').count();
    assert_eq!(parses, 6 + 4 + 1);
    assert_eq!(trace.named_parses, 0);
    assert_eq!(trace.rollbacks, 0);
}

#[tokio::test]
async fn a_guard_at_statement_k_is_a_refusal_and_leaves_no_rows() {
    let Some(s) = schema().await else { return };
    let pg = s.pg(Direct(s.config()), WriteTx::SingleSync);
    // Every position, the last catalogue statement (just before COMMIT)
    // included.
    for k in 0..=3 {
        let mut stmts = vec![insert(10), insert(11), insert(12)];
        stmts.insert(k, (GUARD, vec![int(0)]));
        let r = pg.batch(stmts).await;
        assert!(matches!(r, Err(BridgeError::GuardFailed)), "k={k}: {r:?}");
        assert_eq!(s.count("m").await, 0, "k={k}");
    }
    // The same guard passing commits everything.
    assert_eq!(
        pg.batch(vec![insert(10), (GUARD, vec![int(1)])])
            .await
            .unwrap(),
        [1, 1]
    );
    assert_eq!(s.count("m").await, 1);
}

#[tokio::test]
async fn w1_held_elsewhere_is_overloaded_and_leaves_no_rows() {
    let Some(s) = schema().await else { return };
    let holder = connect(&s.config()).await;
    holder
        .batch_execute(&format!(
            "BEGIN; SELECT pg_advisory_xact_lock({}::bigint)",
            s.lock_key
        ))
        .await
        .unwrap();
    let pg = s.pg(Direct(s.config()), WriteTx::SingleSync);
    let start = Instant::now();
    let r = pg.batch(vec![insert(1)]).await;
    assert!(is(&r, "pg: overloaded"), "{r:?}");
    assert!(
        start.elapsed() >= Duration::from_millis(1900),
        "lock_timeout is 2 s"
    );
    holder.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(s.count("m").await, 0);
}

#[tokio::test]
async fn type_and_syntax_errors_are_statement_failed_and_leave_no_rows() {
    let Some(s) = schema().await else { return };
    let pg = s.pg(Direct(s.config()), WriteTx::SingleSync);
    let bad_type = (
        "INSERT INTO m(n) VALUES (?1)",
        vec![SqlValue::Text("x".into())],
    );
    let r = pg.batch(vec![insert(1), bad_type]).await;
    assert!(is(&r, FAILED), "{r:?}");
    let r = pg.batch(vec![insert(2), ("SELECT 1 +", vec![])]).await;
    assert!(is(&r, FAILED), "{r:?}");
    let r = pg
        .batch(vec![
            insert(3),
            ("SELECT no_such_function(?1)", vec![int(1)]),
        ])
        .await;
    assert!(is(&r, FAILED), "{r:?}");
    assert_eq!(s.count("m").await, 0);
}

#[tokio::test]
async fn a_deferred_constraint_failure_at_commit_is_statement_failed() {
    let Some(s) = schema().await else { return };
    for write_tx in [WriteTx::SingleSync, WriteTx::Pipeline] {
        let pg = s.pg(Direct(s.config()), write_tx);
        let dup = "INSERT INTO d(n) VALUES (?1)";
        let r = pg
            .batch(vec![(dup, vec![int(1)]), (dup, vec![int(1)]), insert(1)])
            .await;
        // Not "constraint violation": the COMMIT position is unknown, as
        // a COMMIT failure always was.
        assert!(is(&r, FAILED), "{write_tx:?}: {r:?}");
        assert_eq!(s.count("d").await, 0);
        assert_eq!(s.count("m").await, 0);
    }
}

#[tokio::test]
async fn an_error_the_proxy_makes_up_after_forwarding_is_statement_failed() {
    let Some(s) = schema().await else { return };
    // The proxy forwards the message, swallows the server's replies (it
    // committed) and answers 08006 with no CommandComplete.
    let (proxy, pg) = proxied(&s, Fault::LostAfterForward).await;
    let r = pg.batch(vec![insert(1)]).await;
    assert!(is(&r, FAILED), "{r:?}");
    assert_eq!(proxy.trace.lock().unwrap().single_syncs, 1);
    assert_eq!(
        s.count("m").await,
        1,
        "the write committed: never a refusal"
    );
}

#[tokio::test]
async fn a_cut_after_forwarding_is_statement_failed() {
    let Some(s) = schema().await else { return };
    let (_proxy, pg) = proxied(&s, Fault::CutAfterForward).await;
    let r = pg.batch(vec![insert(1)]).await;
    assert!(is(&r, FAILED), "{r:?}");
    // Either outcome is possible; wait for the server to settle it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(s.count("m").await <= 1);
}

#[tokio::test]
async fn a_58000_before_any_reply_is_statement_failed_until_proven_earlier() {
    let Some(s) = schema().await else { return };
    let (proxy, pg) = proxied(&s, Fault::Refuse58000).await;
    let r = pg.batch(vec![insert(1)]).await;
    // Until the message-mode pool probe shows Hyperdrive sends 58000
    // before forwarding, it may hide a committed write.
    assert!(is(&r, FAILED), "{r:?}");
    assert_eq!(proxy.trace.lock().unwrap().rollbacks, 1);
    assert_eq!(s.count("m").await, 0);
}

#[tokio::test]
async fn a_missing_command_complete_is_an_unknown_outcome() {
    let Some(s) = schema().await else { return };
    let (_proxy, pg) = proxied(&s, Fault::DropOneComplete).await;
    let r = pg.batch(vec![insert(1), insert(2)]).await;
    // The replies no longer match the statements: a protocol error, so the
    // outcome is unknown, never a refusal.
    assert!(is(&r, FAILED), "{r:?}");
    // The server committed.
    assert_eq!(s.count("m").await, 2);
}

#[tokio::test]
async fn a_commit_without_an_idle_session_is_an_unexpected_shape() {
    let Some(s) = schema().await else { return };
    // Every reply arrives, COMMIT's included, but the ReadyForQuery says
    // the session is still in a transaction: not a confirmed commit.
    let (_proxy, pg) = proxied(&s, Fault::StatusInTransaction).await;
    let r = pg.batch(vec![insert(1)]).await;
    assert!(is(&r, "pg: unexpected result shape"), "{r:?}");
}

#[tokio::test]
async fn a_reply_the_driver_cannot_parse_after_sending_still_ends_the_transaction() {
    let Some(s) = schema().await else { return };
    // The request was sent (and here committed); a malformed row in the
    // reply is an unknown outcome, and the adapter still sends ROLLBACK.
    let (proxy, pg) = proxied(&s, Fault::BadDataRow).await;
    let r = pg
        .query("INSERT INTO m(n) VALUES (?1) RETURNING n", &[int(1)])
        .await;
    assert!(
        matches!(&r, Err(BridgeError::Sql(e)) if e == FAILED),
        "{r:?}"
    );
    {
        let trace = proxy.trace.lock().unwrap();
        assert_eq!(trace.rollbacks, 1, "ROLLBACK sent");
        assert_eq!(trace.rollbacks_done, 1, "and answered before the result");
    }
    // The malformed reply hid a committed write.
    assert_eq!(s.count("m").await, 1);
}

#[tokio::test]
async fn a_refusal_without_the_servers_failed_status_is_statement_failed() {
    let Some(s) = schema().await else { return };
    // A guard refusal is a known rollback only with the server's
    // ReadyForQuery E after it. Cut before it, or said idle, the write
    // may have committed: unknown, not a refusal.
    for fault in [Fault::ErrorThenClose, Fault::ErrorThenIdle] {
        let (_proxy, pg) = proxied(&s, fault).await;
        let r = pg.batch(vec![insert(1), (GUARD, vec![int(0)])]).await;
        assert!(is(&r, FAILED), "{fault:?}: {r:?}");
    }
    // The same refusal through an honest connection.
    let (_proxy, pg) = proxied(&s, Fault::None).await;
    let r = pg.batch(vec![insert(1), (GUARD, vec![int(0)])]).await;
    assert!(matches!(r, Err(BridgeError::GuardFailed)), "{r:?}");
    assert_eq!(s.count("m").await, 0);
}

#[tokio::test]
async fn an_error_in_place_of_commit_is_statement_failed() {
    let Some(s) = schema().await else { return };
    let (_proxy, pg) = proxied(&s, Fault::RejectCommit).await;
    let r = pg.batch(vec![insert(1)]).await;
    assert!(is(&r, FAILED), "57014 at COMMIT is not an overload: {r:?}");
    assert_eq!(s.count("m").await, 1);
}

#[tokio::test]
async fn the_prelude_settings_hold_and_statement_timeout_is_per_statement() {
    let Some(s) = schema().await else { return };
    // A session whose default would log bind values on error: the prelude
    // must override it for the transaction.
    let mut config = s.config();
    let options = config.get_options().unwrap_or_default().to_owned();
    config.options(format!("{options} -c log_parameter_max_length_on_error=-1"));
    let pg = s.pg(Direct(config), WriteTx::SingleSync);
    let settings = "INSERT INTO tx_guard(ok) SELECT CASE WHEN \
        current_setting('statement_timeout') = '20s' AND current_setting('lock_timeout') = '2s' \
        AND current_setting('idle_in_transaction_session_timeout') = '5s' \
        AND current_setting('log_parameter_max_length_on_error') = '0' \
        AND current_setting('transaction_isolation') = 'read committed' \
        AND current_setting('transaction_read_only') = 'off' \
        AND EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted) \
        THEN 1 ELSE 0 END";
    assert_eq!(pg.batch(vec![(settings, vec![])]).await.unwrap(), [1]);
    // A later statement of the same Sync group runs under a timeout set by
    // an earlier one: each statement gets its own timer.
    let start = Instant::now();
    let r = pg
        .batch(vec![
            insert(1),
            (
                "SELECT set_config('statement_timeout', '200ms', true)",
                vec![],
            ),
            ("SELECT pg_sleep(3)", vec![]),
            insert(2),
        ])
        .await;
    assert!(is(&r, "pg: overloaded"), "57014 in a statement: {r:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(s.count("m").await, 0);
}

#[tokio::test]
async fn w1_is_released_at_the_error_before_rollback() {
    let Some(s) = schema().await else { return };
    let proxy = Proxy::start(&s.base, Delay::None, Fault::None).await;
    *proxy.hold_rollback.lock().unwrap() = true;
    let pg = s.pg(Direct(proxy.config(&s.config())), WriteTx::SingleSync);
    let held = proxy.held.clone();
    let release = proxy.release.clone();
    let other = connect(&s.config()).await;
    let key = s.lock_key;
    let probe = async {
        held.notified().await;
        // The failed transaction's ROLLBACK is held at the proxy.
        let row = other
            .query_one("SELECT pg_try_advisory_lock($1::bigint)", &[&key])
            .await
            .unwrap();
        let acquired: bool = row.get(0);
        other
            .query_one("SELECT pg_advisory_unlock($1::bigint)", &[&key])
            .await
            .unwrap();
        release.notify_one();
        acquired
    };
    // A missing ROLLBACK must fail the test, not hang it.
    let (r, acquired) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(pg.batch(vec![insert(1), ("SELECT 1/0", vec![])]), probe)
    })
    .await
    .expect("the adapter sends ROLLBACK after the error");
    assert!(is(&r, FAILED), "22012: {r:?}");
    assert!(acquired, "another writer takes W1 before ROLLBACK");
    {
        let trace = proxy.trace.lock().unwrap();
        assert_eq!(
            (trace.rollbacks, trace.rollbacks_done),
            (1, 1),
            "ROLLBACK went and was answered"
        );
    }
    assert_eq!(s.count("m").await, 0);
}

#[tokio::test]
async fn a_write_without_the_prelude_is_refused_by_the_read_only_default() {
    let Some(s) = schema().await else { return };
    let role = unique("velmora_a1_ro");
    // A throwaway password, so the role also logs in where the test server
    // asks for one.
    let password = {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        format!(
            "{:016x}{:016x}",
            h.finish(),
            std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish()
        )
    };
    s.admin
        .batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}'; ALTER ROLE {role} SET default_transaction_read_only = on;
             GRANT USAGE ON SCHEMA {schema} TO {role};
             GRANT SELECT, INSERT ON {schema}.m TO {role};",
            schema = s.name
        ))
        .await
        .unwrap();
    let mut config = s.config();
    config.user(&role).password(password.as_bytes());
    let bare = connect(&config).await;
    let e = bare
        .batch_execute("INSERT INTO m(n) VALUES (1)")
        .await
        .unwrap_err();
    assert_eq!(e.code().map(|c| c.code()), Some("25006"));
    let pg = s.pg(Direct(config), WriteTx::SingleSync);
    assert_eq!(pg.batch(vec![insert(2)]).await.unwrap(), [1]);
    assert_eq!(s.count("m").await, 1);
    drop(bare);
    s.admin
        .batch_execute(&format!(
            "REVOKE ALL ON {schema}.m FROM {role}; REVOKE USAGE ON SCHEMA {schema} FROM {role}; DROP ROLE {role}",
            schema = s.name
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn statements_may_end_in_a_comment_or_a_semicolon() {
    let Some(s) = schema().await else { return };
    let pg = s.pg(Direct(s.config()), WriteTx::SingleSync);
    let counts = pg
        .batch(vec![
            (
                "INSERT INTO m(n) VALUES (?1) -- a trailing comment",
                vec![int(1)],
            ),
            ("INSERT INTO m(n) VALUES (?1);", vec![int(2)]),
            (
                "INSERT INTO m(n) VALUES (?1) /* ?2 */ ; -- ?3",
                vec![int(3)],
            ),
            ("UPDATE m SET t = '?1 -- ' WHERE n = ?1", vec![int(3)]),
        ])
        .await
        .unwrap();
    assert_eq!(counts, [1, 1, 1, 1]);
    let row = s
        .admin
        .query_one(&format!("SELECT t FROM {}.m WHERE n = 3", s.name), &[])
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "?1 -- ");
}

#[tokio::test]
async fn large_values_round_trip_in_one_request() {
    let Some(s) = schema().await else { return };
    let proxy = Proxy::start(&s.base, Delay::None, Fault::None).await;
    let pg = s.pg(Direct(proxy.config(&s.config())), WriteTx::SingleSync);
    // A 2 MB placement-sized JSON text and a 2 MB blob.
    let json: String = (0..)
        .map(|i| format!("{{\"p\":{i},\"e\":\"x_{i:08}\"}},"))
        .take_while({
            let mut len = 0;
            move |s: &String| {
                len += s.len();
                len < 1_999_000
            }
        })
        .collect();
    let blob: Vec<u8> = (0..2_000_000_u32).map(|i| (i * 7 % 251) as u8).collect();
    let counts = pg
        .batch(vec![(
            "INSERT INTO m(n, t, b) VALUES (?1, ?2, ?3)",
            vec![
                int(1),
                SqlValue::Text(json.clone()),
                SqlValue::Blob(blob.clone()),
            ],
        )])
        .await
        .unwrap();
    assert_eq!(counts, [1]);
    let row = s
        .admin
        .query_one(&format!("SELECT t, b FROM {}.m WHERE n = 1", s.name), &[])
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), json);
    assert_eq!(row.get::<_, Vec<u8>>(1), blob);
    // Five 2 MB blobs (10 MB of binds) are still one request.
    let stmts: Vec<(&'static str, Vec<SqlValue>)> = (10..15)
        .map(|n| {
            (
                "INSERT INTO m(n, b) VALUES (?1, ?2)",
                vec![int(n), SqlValue::Blob(blob.clone())],
            )
        })
        .collect();
    let sized = stmts.clone();
    let before = oversize_fallbacks();
    assert_eq!(pg.batch(stmts).await.unwrap(), [1; 5]);
    {
        let trace = proxy.trace.lock().unwrap();
        assert_eq!((trace.single_syncs, trace.syncs, trace.queries), (2, 2, 0));
        // The size bound is computed exactly, before anything is sent.
        let expected = single_sync_request_bytes(Some(s.lock_key), &sized).unwrap();
        assert_eq!(trace.last_request_bytes, expected);
    }
    assert_eq!(oversize_fallbacks(), before);
    // Nine 2 MB blobs (18 MB) are over the bound: the transaction uses the
    // one-Sync-per-statement transport and still commits.
    let stmts: Vec<(&'static str, Vec<SqlValue>)> = (20..29)
        .map(|n| {
            (
                "INSERT INTO m(n, b) VALUES (?1, ?2)",
                vec![int(n), SqlValue::Blob(blob.clone())],
            )
        })
        .collect();
    assert!(single_sync_request_bytes(Some(s.lock_key), &stmts).unwrap() > MAX_SINGLE_SYNC_BYTES);
    assert_eq!(pg.batch(stmts).await.unwrap(), [1; 9]);
    assert_eq!(oversize_fallbacks(), before + 1);
    {
        let trace = proxy.trace.lock().unwrap();
        assert_eq!(trace.single_syncs, 2, "not sent as one request");
        assert_eq!(trace.syncs, 2 + 9, "one Sync per statement");
    }
    assert_eq!(s.count("m").await, 15);
}

#[tokio::test]
async fn write_query_rows_keep_their_binary_types() {
    let Some(s) = schema().await else { return };
    let pg = s.pg(Direct(s.config()), WriteTx::SingleSync);
    let rows = pg
        .query(
            "INSERT INTO m(n, t, b) VALUES (?1, ?2, ?3) \
             RETURNING n, t, b, 1::int2, 2::int4, true, 5.00::numeric, 'v'::varchar, 'n'::name, NULL::text",
            &[int(9), SqlValue::Text("1".into()), SqlValue::Blob(vec![0, 255])],
        )
        .await
        .unwrap();
    assert_eq!(
        rows,
        [vec![
            int(9),
            SqlValue::Text("1".into()),
            SqlValue::Blob(vec![0, 255]),
            int(1),
            int(2),
            int(1),
            int(5),
            SqlValue::Text("v".into()),
            SqlValue::Text("n".into()),
            SqlValue::Null,
        ]]
    );
    // A type the driver's built-in table does not know: no lookup, and the
    // decoder refuses it as today, after the write committed.
    s.admin
        .batch_execute(&format!("CREATE TYPE {}.mood AS ENUM ('ok')", s.name))
        .await
        .unwrap();
    let proxy = Proxy::start(&s.base, Delay::None, Fault::None).await;
    let pg = s.pg(Direct(proxy.config(&s.config())), WriteTx::SingleSync);
    let r = pg
        .query(
            "INSERT INTO m(n) VALUES (?1) RETURNING 'ok'::mood",
            &[int(10)],
        )
        .await;
    assert!(
        matches!(&r, Err(BridgeError::Sql(e)) if e == "pg: unexpected result shape"),
        "{r:?}"
    );
    // exec takes no rows: the same statement succeeds.
    let n = pg
        .exec(
            "INSERT INTO m(n) VALUES (?1) RETURNING 'ok'::mood",
            &[int(11)],
        )
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        proxy.trace.lock().unwrap().named_parses,
        0,
        "no type lookup"
    );
    assert_eq!(s.count("m").await, 3);
}

#[cfg(feature = "pg-test-unlocked")]
#[tokio::test]
async fn the_unlocked_negative_control_has_five_prelude_statements() {
    let Some(s) = schema().await else { return };
    let pg = s
        .pg(Direct(s.config()), WriteTx::SingleSync)
        .without_write_lock_for_test();
    // A wrong prelude count would be an unexpected result shape.
    assert_eq!(pg.batch(vec![insert(1), insert(2)]).await.unwrap(), [1, 1]);
    assert_eq!(s.count("m").await, 2);
}
