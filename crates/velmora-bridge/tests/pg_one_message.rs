//! Failure semantics of the one-message write transport on a real server
//! (`VELMORA_TEST_PG_URL`), some through a framing proxy that injects the
//! faults a pooler can cause. Each case names the outcome the caller sees
//! and what is left in the database.

#![cfg(feature = "testkit-pg")]

mod pg_support;

use std::time::{Duration, Instant};

use pg_support::{connect, unique, Delay, Direct, Fault, Proxy, Schema};
use velmora_bridge::pg::{oversize_fallbacks, PgSql, WriteTx, MAX_WRITE_MESSAGE_BYTES};
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
    let pg = s.pg(Direct(proxy.config(&s.config())), WriteTx::Message);
    (proxy, pg)
}

#[tokio::test]
async fn a_write_transaction_is_one_query_message() {
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
    assert_eq!(trace.messages, 1);
    assert_eq!(trace.frontend.iter().filter(|t| **t == b'Q').count(), 1);
    assert!(!trace.frontend.contains(&b'P'), "no extended request");
    assert_eq!(trace.rollbacks, 0);
}

#[tokio::test]
async fn a_guard_at_statement_k_is_a_refusal_and_leaves_no_rows() {
    let Some(s) = schema().await else { return };
    let pg = s.pg(Direct(s.config()), WriteTx::Message);
    for k in 0..3 {
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
    let pg = s.pg(Direct(s.config()), WriteTx::Message);
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
    let pg = s.pg(Direct(s.config()), WriteTx::Message);
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
    for write_tx in [WriteTx::Message, WriteTx::Pipeline] {
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
    assert_eq!(proxy.trace.lock().unwrap().messages, 1);
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
async fn a_missing_command_complete_is_an_unexpected_shape() {
    let Some(s) = schema().await else { return };
    let (_proxy, pg) = proxied(&s, Fault::DropOneComplete).await;
    let r = pg.batch(vec![insert(1), insert(2)]).await;
    assert!(is(&r, "pg: unexpected result shape"), "{r:?}");
    // The server committed; the reply count told the adapter it cannot know.
    assert_eq!(s.count("m").await, 2);
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
    let pg = s.pg(Direct(s.config()), WriteTx::Message);
    let settings = "INSERT INTO tx_guard(ok) SELECT CASE WHEN \
        current_setting('statement_timeout') = '20s' AND current_setting('lock_timeout') = '2s' \
        AND current_setting('idle_in_transaction_session_timeout') = '5s' \
        AND current_setting('bytea_output') = 'hex' \
        AND current_setting('transaction_isolation') = 'read committed' \
        AND current_setting('transaction_read_only') = 'off' \
        AND EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted) \
        THEN 1 ELSE 0 END";
    assert_eq!(pg.batch(vec![(settings, vec![])]).await.unwrap(), [1]);
    // A later statement of the same message runs under a timeout set by an
    // earlier one: each statement gets its own timer.
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
    let pg = s.pg(Direct(proxy.config(&s.config())), WriteTx::Message);
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
    let (r, acquired) = tokio::join!(pg.batch(vec![insert(1), ("SELECT 1/0", vec![])]), probe);
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
    s.admin
        .batch_execute(&format!(
            "CREATE ROLE {role} LOGIN; ALTER ROLE {role} SET default_transaction_read_only = on;
             GRANT USAGE ON SCHEMA {schema} TO {role};
             GRANT SELECT, INSERT ON {schema}.m TO {role};",
            schema = s.name
        ))
        .await
        .unwrap();
    let mut config = s.config();
    config.user(&role);
    let bare = connect(&config).await;
    let e = bare
        .batch_execute("INSERT INTO m(n) VALUES (1)")
        .await
        .unwrap_err();
    assert_eq!(e.code().map(|c| c.code()), Some("25006"));
    let pg = s.pg(Direct(config), WriteTx::Message);
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
    let pg = s.pg(Direct(s.config()), WriteTx::Message);
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
async fn large_values_round_trip_and_an_oversize_batch_goes_typed() {
    let Some(s) = schema().await else { return };
    let proxy = Proxy::start(&s.base, Delay::None, Fault::None).await;
    let pg = s.pg(Direct(proxy.config(&s.config())), WriteTx::Message);
    // A 2 MB placement-sized JSON text and a 2 MB blob: one message.
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
    let before = oversize_fallbacks();
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
    assert_eq!(oversize_fallbacks(), before);
    let row = s
        .admin
        .query_one(&format!("SELECT t, b FROM {}.m WHERE n = 1", s.name), &[])
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), json);
    assert_eq!(row.get::<_, Vec<u8>>(1), blob);
    assert_eq!(proxy.trace.lock().unwrap().messages, 1);
    // Five 2 MB blobs render to about 20 MB, over the bound: the batch uses
    // the typed transport and still commits.
    assert!(5 * (2 * blob.len()) > MAX_WRITE_MESSAGE_BYTES);
    let stmts = (10..15)
        .map(|n| {
            (
                "INSERT INTO m(n, b) VALUES (?1, ?2)",
                vec![int(n), SqlValue::Blob(blob.clone())],
            )
        })
        .collect();
    assert_eq!(pg.batch(stmts).await.unwrap(), [1; 5]);
    assert_eq!(oversize_fallbacks(), before + 1);
    {
        let trace = proxy.trace.lock().unwrap();
        assert_eq!(trace.messages, 1, "the oversize batch was not one message");
        assert!(trace.frontend.contains(&b'P'), "typed requests");
    }
    assert_eq!(s.count("m").await, 6);
}

#[cfg(feature = "pg-test-unlocked")]
#[tokio::test]
async fn the_unlocked_negative_control_has_five_prelude_statements() {
    let Some(s) = schema().await else { return };
    let pg = s
        .pg(Direct(s.config()), WriteTx::Message)
        .without_write_lock_for_test();
    // A wrong prelude count would be an unexpected result shape.
    assert_eq!(pg.batch(vec![insert(1), insert(2)]).await.unwrap(), [1, 1]);
    assert_eq!(s.count("m").await, 2);
}
