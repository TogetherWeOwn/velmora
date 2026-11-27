//! The vendored driver's `Client::pipeline_typed` on a real server
//! (`VELMORA_TEST_PG_URL`), through the framing proxy: one request, one
//! Sync, one ReadyForQuery; the exact index of an error; nothing sent on
//! an encode error; binary binds and rows as `query_typed_raw` has them.

#![cfg(feature = "testkit-pg")]

mod pg_support;

use std::time::Duration;

use pg_support::{base_config, connect, Delay, Fault, Proxy, Schema};
use tokio_postgres::types::{IsNull, ToSql, Type};
use tokio_postgres::{Client, PipelineOutcome, PipelineStatement};

fn stmt(query: &str) -> PipelineStatement<'_> {
    PipelineStatement {
        query,
        params: Vec::new(),
    }
}

async fn proxied(s: &Schema) -> (Proxy, Client) {
    let proxy = Proxy::start(&s.base, Delay::None, Fault::None).await;
    let client = connect(&proxy.config(&s.config())).await;
    (proxy, client)
}

fn tags(o: &PipelineOutcome) -> Vec<&str> {
    o.replies.iter().map(|r| r.tag.as_str()).collect()
}

const SETUP: &str = "CREATE TABLE p (n bigint PRIMARY KEY, t text);
    CREATE TABLE d (n bigint, CONSTRAINT d_once UNIQUE (n) DEFERRABLE INITIALLY DEFERRED);
    CREATE TYPE mood AS ENUM ('ok');";

#[tokio::test]
async fn statements_complete_in_order_with_one_sync() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let (proxy, client) = proxied(&s).await;
    for n in [1_i64, 3, 11, 200] {
        let values: Vec<i64> = (0..n).map(|i| n * 1000 + i).collect();
        let mut stmts = vec![stmt("BEGIN")];
        stmts.extend(values.iter().map(|v| PipelineStatement {
            query: "INSERT INTO p(n) VALUES ($1)",
            params: vec![(v as &(dyn ToSql + Sync), Type::INT8)],
        }));
        stmts.push(stmt("COMMIT"));
        let syncs = proxy.trace.lock().unwrap().syncs;
        let o = client.pipeline_typed(&stmts, false).await.unwrap();
        assert!(o.error.is_none());
        assert_eq!(o.status, Some(b'I'));
        assert_eq!(o.replies.len(), n as usize + 2);
        assert_eq!(tags(&o)[0], "BEGIN");
        assert_eq!(*tags(&o).last().unwrap(), "COMMIT");
        assert!(o.replies[1..=n as usize]
            .iter()
            .all(|r| r.tag == "INSERT 0 1" && r.rows_affected == 1));
        let trace = proxy.trace.lock().unwrap();
        assert_eq!(trace.syncs, syncs + 1, "n={n}: one Sync");
        assert_eq!(trace.named_parses, 0);
    }
    assert_eq!(s.count("p").await, 1 + 3 + 11 + 200);
}

#[tokio::test]
async fn an_error_reports_its_exact_statement_index() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let (_proxy, client) = proxied(&s).await;
    let ok = [
        "BEGIN",
        "SET LOCAL lock_timeout = '2s'",
        "INSERT INTO p(n) VALUES (1)",
        "UPDATE p SET t = 'x'",
        "SELECT n FROM p",
        "COMMIT",
    ];
    for k in 0..ok.len() - 1 {
        let mut texts = ok.to_vec();
        texts[k] = if k == 1 {
            // A prelude statement that fails: an invalid setting.
            "SET LOCAL lock_timeout = 'never'"
        } else {
            "SELECT 1/0"
        };
        let stmts: Vec<_> = texts.iter().map(|t| stmt(t)).collect();
        let o = client.pipeline_typed(&stmts, true).await.unwrap();
        let (index, error) = o.error.as_ref().expect("an error");
        assert_eq!(*index, k, "{texts:?}");
        assert_eq!(o.replies.len(), k);
        assert!(error.as_db_error().is_some());
        // Inside the explicit block the session is in a failed transaction;
        // a failed BEGIN position leaves the implicit block, rolled back.
        assert_eq!(o.status, Some(if k == 0 { b'I' } else { b'E' }), "k={k}");
        client.batch_execute("ROLLBACK").await.unwrap();
        assert_eq!(s.count("p").await, 0);
    }
    // COMMIT itself: a deferred unique constraint fails there.
    let stmts = [
        stmt("BEGIN"),
        stmt("INSERT INTO d VALUES (1)"),
        stmt("INSERT INTO d VALUES (1)"),
        stmt("COMMIT"),
    ];
    let o = client.pipeline_typed(&stmts, false).await.unwrap();
    let (index, error) = o.error.as_ref().unwrap();
    assert_eq!(*index, 3);
    assert_eq!(error.code().map(|c| c.code()), Some("23505"));
    assert_eq!(o.status, Some(b'I'), "COMMIT failed and ended the block");
    assert_eq!(s.count("d").await, 0);
}

#[derive(Debug)]
struct Refuse;

impl ToSql for Refuse {
    fn to_sql(
        &self,
        _: &Type,
        _: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        Err("refused".into())
    }
    fn accepts(_: &Type) -> bool {
        true
    }
    tokio_postgres::types::to_sql_checked!();
}

#[tokio::test]
async fn an_encode_error_sends_nothing() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let (proxy, client) = proxied(&s).await;
    client.batch_execute("SELECT 1").await.unwrap();
    let before = proxy.trace.lock().unwrap().frontend.len();
    let one = 1_i64;
    let stmts = [
        stmt("BEGIN"),
        PipelineStatement {
            query: "INSERT INTO p(n) VALUES ($1)",
            params: vec![(&one as &(dyn ToSql + Sync), Type::INT8)],
        },
        PipelineStatement {
            query: "INSERT INTO p(n) VALUES ($1)",
            params: vec![(&Refuse as &(dyn ToSql + Sync), Type::INT8)],
        },
        stmt("COMMIT"),
    ];
    assert!(client.pipeline_typed(&stmts, false).await.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        proxy.trace.lock().unwrap().frontend.len(),
        before,
        "zero bytes sent"
    );
    // The connection is still usable and nothing was written.
    client.batch_execute("SELECT 1").await.unwrap();
    assert_eq!(s.count("p").await, 0);
}

#[tokio::test]
async fn binds_and_rows_are_binary_and_typed() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let (_proxy, client) = proxied(&s).await;
    // 100 parameters.
    let values: Vec<i64> = (1..=100).collect();
    let sum = (1..=100)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(" + ");
    let query = format!("SELECT {sum}");
    let stmts = [PipelineStatement {
        query: &query,
        params: values
            .iter()
            .map(|v| (v as &(dyn ToSql + Sync), Type::INT8))
            .collect(),
    }];
    let o = client.pipeline_typed(&stmts, true).await.unwrap();
    assert_eq!(o.replies[0].rows[0].get::<_, i64>(0), 5050);
    assert_eq!(o.replies[0].tag, "SELECT 1");
    // 2,000,000-byte TEXT and BYTEA round-trip byte for byte.
    let text: String = (0..2_000_000)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    let blob: Vec<u8> = (0..2_000_000_u32).map(|i| (i % 251) as u8).collect();
    let stmts = [PipelineStatement {
        query: "SELECT $1::text, $2::bytea",
        params: vec![
            (&text as &(dyn ToSql + Sync), Type::TEXT),
            (&blob, Type::BYTEA),
        ],
    }];
    let o = client.pipeline_typed(&stmts, true).await.unwrap();
    let row = &o.replies[0].rows[0];
    assert_eq!(row.get::<_, String>(0), text);
    assert_eq!(row.get::<_, Vec<u8>>(1), blob);
    // Built-in result types keep their OIDs.
    let stmts = [stmt(
        "SELECT 1::int2, 2::int4, 3::int8, true, 5.00::numeric, 't'::text, 'v'::varchar, 'n'::name, '\\x00ff'::bytea",
    )];
    let o = client.pipeline_typed(&stmts, true).await.unwrap();
    let types: Vec<Type> = o.replies[0].rows[0]
        .columns()
        .iter()
        .map(|c| c.type_().clone())
        .collect();
    assert_eq!(
        types,
        [
            Type::INT2,
            Type::INT4,
            Type::INT8,
            Type::BOOL,
            Type::NUMERIC,
            Type::TEXT,
            Type::VARCHAR,
            Type::NAME,
            Type::BYTEA
        ]
    );
    let row = &o.replies[0].rows[0];
    assert_eq!(
        (
            row.get::<_, i16>(0),
            row.get::<_, i32>(1),
            row.get::<_, i64>(2),
            row.get::<_, bool>(3)
        ),
        (1, 2, 3, true)
    );
    assert_eq!(row.get::<_, Vec<u8>>(8), [0, 255]);
    // Without collecting rows, only tags and counts come back.
    client
        .batch_execute("INSERT INTO p(n) VALUES (1), (2), (3)")
        .await
        .unwrap();
    let stmts = [
        stmt("UPDATE p SET t = 'x'"),
        stmt("SELECT n FROM p"),
        stmt("DELETE FROM p WHERE n = 1"),
    ];
    let o = client.pipeline_typed(&stmts, false).await.unwrap();
    assert_eq!(tags(&o), ["UPDATE 3", "SELECT 3", "DELETE 1"]);
    assert_eq!(
        o.replies
            .iter()
            .map(|r| r.rows_affected)
            .collect::<Vec<_>>(),
        [3, 3, 1]
    );
    assert!(o.replies.iter().all(|r| r.rows.is_empty()));
}

#[tokio::test]
async fn an_unknown_column_type_is_never_looked_up() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let (proxy, client) = proxied(&s).await;
    let stmts = [stmt("SELECT 'ok'::mood, 1::int8")];
    let o = client.pipeline_typed(&stmts, true).await.unwrap();
    assert!(o.error.is_none());
    let row = &o.replies[0].rows[0];
    assert!(
        row.try_get::<_, String>(0).is_err(),
        "no FromSql accepts it"
    );
    assert_eq!(row.get::<_, i64>(1), 1);
    let trace = proxy.trace.lock().unwrap();
    assert_eq!(trace.named_parses, 0, "no typeinfo statement");
    assert_eq!(trace.syncs, 1);
}

#[tokio::test]
async fn dropping_the_reply_early_leaves_the_connection_usable() {
    let Some(config) = base_config() else { return };
    let client = connect(&config).await;
    let stmts = [
        stmt("BEGIN"),
        stmt("SELECT pg_sleep(0.5)"),
        stmt("SELECT 1"),
    ];
    let r = tokio::time::timeout(
        Duration::from_millis(50),
        client.pipeline_typed(&stmts, true),
    )
    .await;
    assert!(r.is_err(), "dropped before the reply");
    // The connection reads the rest of the request's replies up to its
    // ReadyForQuery, then answers the next request.
    client.batch_execute("ROLLBACK").await.unwrap();
    let row = client.query_one("SELECT 2::int8", &[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 2);
}

#[tokio::test]
async fn every_reply_form_has_its_exact_tag_rows_and_index() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let (_proxy, client) = proxied(&s).await;
    client
        .batch_execute("INSERT INTO p(n) VALUES (1)")
        .await
        .unwrap();
    let stmts = [
        stmt("BEGIN"),                                        // NoData
        stmt("SELECT n FROM p WHERE false"),                  // zero-row SELECT
        stmt("UPDATE p SET t = 'x' WHERE false"),             // zero-row DML
        stmt("UPDATE p SET t = 'x' WHERE false RETURNING n"), // zero rows, RETURNING
        stmt(""),                                             // EmptyQueryResponse
        stmt("UPDATE p SET t = 'y' RETURNING n, t"),          // one row
        stmt("SELECT 1/0"),                                   // fails at Execute
        stmt("COMMIT"),
    ];
    let o = client.pipeline_typed(&stmts, true).await.unwrap();
    assert_eq!(
        tags(&o),
        ["BEGIN", "SELECT 0", "UPDATE 0", "UPDATE 0", "", "UPDATE 1"]
    );
    let counts: Vec<u64> = o.replies.iter().map(|r| r.rows_affected).collect();
    assert_eq!(counts, [0, 0, 0, 0, 0, 1]);
    let rows: Vec<usize> = o.replies.iter().map(|r| r.rows.len()).collect();
    assert_eq!(rows, [0, 0, 0, 0, 0, 1]);
    assert_eq!(o.replies[5].rows[0].get::<_, String>(1), "y");
    let (index, error) = o.error.as_ref().unwrap();
    assert_eq!((*index, error.code().map(|c| c.code())), (6, Some("22012")));
    assert_eq!(o.status, Some(b'E'));
    client.batch_execute("ROLLBACK").await.unwrap();
    let t: Option<String> = client
        .query_one("SELECT t FROM p", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(t, None, "rolled back");
}

/// Writes 3 bytes for an INT8: the server refuses it at Bind.
#[derive(Debug)]
struct Short;

impl ToSql for Short {
    fn to_sql(
        &self,
        _: &Type,
        out: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        out.extend_from_slice(&[1, 2, 3]);
        Ok(IsNull::No)
    }
    fn accepts(_: &Type) -> bool {
        true
    }
    tokio_postgres::types::to_sql_checked!();
}

#[tokio::test]
async fn an_error_in_each_protocol_phase_has_its_index_and_rolls_back() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let (_proxy, client) = proxied(&s).await;
    let phases: [(&str, PipelineStatement<'_>, &str); 3] = [
        ("Parse", stmt("SELEC 1"), "42601"),
        (
            "Bind",
            PipelineStatement {
                query: "SELECT $1::int8",
                params: vec![(&Short as &(dyn ToSql + Sync), Type::INT8)],
            },
            // A malformed binary value is a protocol violation at Bind.
            "08P01",
        ),
        ("Execute", stmt("SELECT 1/0"), "22012"),
    ];
    for (phase, failing, code) in phases {
        let stmts = [
            stmt("BEGIN"),
            stmt("INSERT INTO p(n) VALUES (7)"),
            failing,
            stmt("COMMIT"),
        ];
        let o = client.pipeline_typed(&stmts, false).await.unwrap();
        let (index, error) = o.error.as_ref().expect(phase);
        assert_eq!(
            (*index, error.code().map(|c| c.code())),
            (2, Some(code)),
            "{phase}"
        );
        assert_eq!(o.status, Some(b'E'), "{phase}");
        client.batch_execute("ROLLBACK").await.unwrap();
        assert_eq!(s.count("p").await, 0, "{phase}: rolled back");
        // The connection answers the next request.
        assert_eq!(
            client
                .query_one("SELECT 3::int8", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            3
        );
    }
}

#[tokio::test]
async fn a_describe_error_has_its_index_and_leaves_the_connection_usable() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    // The proxy fails the second statement's Describe and ends the request
    // as a server would (the real server ran it; only the reply is faked).
    let proxy = Proxy::start(&s.base, Delay::None, Fault::DescribeError).await;
    let client = connect(&proxy.config(&s.config())).await;
    let stmts = [
        stmt("BEGIN READ WRITE"),
        stmt("SELECT 1"),
        stmt("SELECT 2"),
        stmt("COMMIT"),
    ];
    let o = client.pipeline_typed(&stmts, true).await.unwrap();
    let (index, error) = o.error.as_ref().unwrap();
    assert_eq!((*index, error.code().map(|c| c.code())), (1, Some("42P18")));
    assert_eq!(o.status, Some(b'E'));
    client.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(
        client
            .query_one("SELECT 4::int8", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        4
    );
}

#[tokio::test]
async fn asynchronous_messages_anywhere_in_the_reply_change_nothing() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    // From the server: notices, a ParameterStatus and a notification.
    let (_proxy, client) = proxied(&s).await;
    client.batch_execute("LISTEN velmora_a3").await.unwrap();
    let notice = "DO $$ BEGIN RAISE NOTICE 'a notice'; END $$";
    let stmts = [
        stmt(notice),
        stmt("BEGIN"),
        stmt(notice),
        stmt("SET LOCAL application_name = 'a3'"),
        stmt("INSERT INTO p(n) VALUES (1)"),
        stmt("NOTIFY velmora_a3, 'x'"),
        stmt(notice),
        stmt("COMMIT"),
    ];
    let o = client.pipeline_typed(&stmts, false).await.unwrap();
    assert!(o.error.is_none());
    assert_eq!(o.replies.len(), 8);
    assert_eq!(o.status, Some(b'I'));
    let stmts = [
        stmt("BEGIN"),
        stmt(notice),
        stmt("SELECT 1/0"),
        stmt("COMMIT"),
    ];
    let o = client.pipeline_typed(&stmts, false).await.unwrap();
    assert_eq!(o.error.as_ref().map(|(i, _)| *i), Some(2));
    assert_eq!(o.status, Some(b'E'));
    client.batch_execute("ROLLBACK").await.unwrap();
    // From the proxy, before and after every reply message, on success and
    // around an error.
    for failing in [false, true] {
        let proxy = Proxy::start(&s.base, Delay::None, Fault::InjectAsync).await;
        let client = connect(&proxy.config(&s.config())).await;
        let insert = if failing {
            "INSERT INTO p(n) VALUES (3)"
        } else {
            "INSERT INTO p(n) VALUES (2)"
        };
        let mut stmts = vec![stmt("BEGIN READ WRITE"), stmt(insert)];
        if failing {
            stmts.push(stmt("SELECT 1/0"));
        }
        stmts.push(stmt("COMMIT"));
        let o = client.pipeline_typed(&stmts, true).await.unwrap();
        if failing {
            let (index, error) = o.error.as_ref().unwrap();
            assert_eq!(
                (*index, error.code().map(|c| c.code())),
                (2, Some("22012")),
                "{error:?}"
            );
            assert_eq!(o.status, Some(b'E'));
            client.batch_execute("ROLLBACK").await.unwrap();
        } else {
            assert!(o.error.is_none());
            assert_eq!(tags(&o), ["BEGIN", "INSERT 0 1", "COMMIT"]);
            assert_eq!(o.status, Some(b'I'));
        }
        assert_eq!(
            client
                .query_one("SELECT 5::int8", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            5
        );
    }
    assert_eq!(s.count("p").await, 2);
}

#[tokio::test]
async fn copy_is_refused_before_sending_and_a_sync_error_has_the_full_count() {
    let Some(s) = Schema::new(SETUP).await else {
        return;
    };
    let (proxy, client) = proxied(&s).await;
    client.batch_execute("SELECT 1").await.unwrap();
    let before = proxy.trace.lock().unwrap().frontend.len();
    for copy in [
        "COPY p FROM STDIN",
        "  -- a comment\n copy p TO STDOUT",
        "/* a /* nested */ comment */ COPY p FROM STDIN",
    ] {
        let stmts = [stmt("SELECT 1"), stmt(copy)];
        assert!(
            client.pipeline_typed(&stmts, false).await.is_err(),
            "{copy:?}"
        );
    }
    assert_eq!(
        proxy.trace.lock().unwrap().frontend.len(),
        before,
        "zero bytes sent"
    );
    // Without BEGIN the statements run in one implicit transaction, and a
    // deferred constraint fails at the Sync: after every statement.
    let stmts = [
        stmt("INSERT INTO d VALUES (5)"),
        stmt("INSERT INTO d VALUES (5)"),
    ];
    let o = client.pipeline_typed(&stmts, false).await.unwrap();
    let (index, error) = o.error.as_ref().unwrap();
    assert_eq!((*index, error.code().map(|c| c.code())), (2, Some("23505")));
    assert_eq!(o.replies.len(), 2);
    assert_eq!(o.status, Some(b'I'));
    assert_eq!(s.count("d").await, 0);
}
