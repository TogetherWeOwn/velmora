//! The rig's "rows written" meter against D1's own counter.
//!
//! `MEASURED` is a statement list run, in this order, through a D1 binding
//! of the local Workers runtime over this schema; the figure beside each
//! statement is the `meta.rows_written` D1 returned for it (`None`: D1
//! refused the statement). The meter must give the same figure for every
//! statement, so what the rig reports per extent is what D1 bills.
//!
//! The list covers what the catalogue does: inserts into tables with one,
//! two and three indexes, partial indexes a row enters and leaves, an
//! assignment that keeps the value, trigger writes, `WITHOUT ROWID`
//! tables, `REPLACE` over an existing row, upserts, deletes, statements
//! that change nothing and a statement a trigger refuses.

use velmora_bridge::ports::Sql;
use velmora_bridge::testkit::RusqliteSql;

const MEASURED: &[(&str, Option<u64>)] = &[
    (
        r#"INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) VALUES ('b_c','calc','o',x'00',1,1)"#,
        Some(3),
    ),
    (
        r#"INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at) VALUES ('g_c','b_c','k','live',1,'e','{}','{}',1,1)"#,
        Some(3),
    ),
    (
        r#"INSERT INTO extents(id,bucket_id,generation_id,state,seq,plain_offset,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) VALUES ('x_c','b_c','g_c','committed',0,0,1,1,x'00',x'00',x'00',x'00','held',1)"#,
        Some(7),
    ),
    (
        r#"INSERT INTO extents(id,bucket_id,generation_id,state,seq,plain_offset,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) VALUES ('x_d','b_c',NULL,'staged',NULL,NULL,1,1,x'00',x'00',x'00',x'00','held',1)"#,
        Some(5),
    ),
    (
        r#"UPDATE extents SET generation_id='g_c', state='committed', seq=1, plain_offset=1 WHERE id='x_d'"#,
        Some(4),
    ),
    (
        r#"INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at) VALUES ('x_c','g_c','post',1,1)"#,
        Some(3),
    ),
    (
        r#"UPDATE outbox SET lease_token = lease_token + 1, lease_owner='a', lease_until=5 WHERE extent_id='x_c'"#,
        Some(1),
    ),
    (
        r#"UPDATE outbox SET stage='verify', next_at=7 WHERE extent_id='x_c'"#,
        Some(2),
    ),
    (
        r#"UPDATE outbox SET next_at=9 WHERE extent_id='x_c'"#,
        Some(2),
    ),
    (
        r#"UPDATE outbox SET stage='verify', next_at=9 WHERE extent_id='x_c'"#,
        Some(2),
    ),
    (
        r#"INSERT INTO articles(extent_id,idx,message_id,newsgroup,headers,cipher_offset,cipher_len,payload_sha256,state) VALUES ('x_c',0,'c0','g',x'00',0,1,x'00','planned'),('x_c',1,'c1','g',x'00',0,1,x'00','planned')"#,
        Some(4),
    ),
    (
        r#"UPDATE articles SET state='posted', provider_id='p', posted_at=3 WHERE extent_id='x_c' AND idx=0"#,
        Some(1),
    ),
    (
        r#"INSERT INTO verifications(extent_id,backbone,provider_id,verified_at,plan_rev,articles_ok,articles_total,result) VALUES ('x_c','b','p',1,1,2,2,'ok')"#,
        Some(1),
    ),
    (
        r#"UPDATE extents SET last_verified_at=3 WHERE id='x_c'"#,
        Some(1),
    ),
    (
        r#"UPDATE extents SET last_verified_at=3 WHERE id='x_c'"#,
        Some(1),
    ),
    (
        r#"UPDATE extents SET last_verified_at=3 WHERE id='x_nope'"#,
        Some(0),
    ),
    (
        r#"UPDATE extents SET cipher_size=cipher_size WHERE id='x_c'"#,
        Some(2),
    ),
    (
        r#"UPDATE extents SET safety_state='held' WHERE id='x_c'"#,
        Some(3),
    ),
    (
        r#"UPDATE extents SET safety_state='releasing', release_evidence='[]', evict_seq=evict_seq+1 WHERE id='x_c'"#,
        Some(2),
    ),
    (
        r#"UPDATE extents SET safety_state='released', released_at=2, hot_safety_bytes=cipher_size, last_read_at=COALESCE(last_read_at, created_at), evict_seq=evict_seq+1 WHERE id='x_c'"#,
        Some(2),
    ),
    (
        r#"INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE extent_id='x_c')"#,
        Some(0),
    ),
    (
        r#"DELETE FROM articles WHERE extent_id='x_c' AND idx=1"#,
        None,
    ),
    (
        r#"INSERT OR REPLACE INTO meta(k,v) VALUES ('cal_a',1)"#,
        Some(1),
    ),
    (
        r#"INSERT OR REPLACE INTO meta(k,v) VALUES ('cal_a',2)"#,
        Some(1),
    ),
    (
        r#"INSERT INTO meta(k,v) VALUES ('cal_a',3) ON CONFLICT(k) DO UPDATE SET v = excluded.v"#,
        Some(1),
    ),
    (
        r#"INSERT OR IGNORE INTO meta(k,v) VALUES ('cal_a',4)"#,
        Some(0),
    ),
    (
        r#"INSERT INTO write_intents(extent_id,write_id,state,created_at) VALUES ('x_w','w_c','open',1)"#,
        Some(3),
    ),
    (
        r#"UPDATE write_intents SET generation_id='g_c' WHERE extent_id='x_w'"#,
        Some(1),
    ),
    (
        r#"DELETE FROM write_intents WHERE extent_id='x_w'"#,
        Some(1),
    ),
    (
        r#"INSERT INTO uploads(id,bucket_id,key,content_json,user_meta_json,state,initiated_at) VALUES ('u_c','b_c','k','{}','{}','open',1)"#,
        Some(3),
    ),
    (
        r#"INSERT INTO upload_parts(upload_id,part_number,extent_id,size,etag,uploaded_at) VALUES ('u_c',1,'x_c',1,'e',1)"#,
        Some(2),
    ),
    (
        r#"INSERT OR REPLACE INTO upload_parts(upload_id,part_number,extent_id,size,etag,uploaded_at) VALUES ('u_c',1,'x_d',1,'e',2)"#,
        Some(2),
    ),
    (r#"DELETE FROM upload_parts WHERE upload_id='u_c'"#, Some(1)),
    (
        r#"UPDATE outbox SET stage='done' WHERE extent_id='x_c'"#,
        Some(2),
    ),
    (
        r#"INSERT OR REPLACE INTO outbox(extent_id,generation_id,stage,next_at,updated_at) VALUES ('x_c','g_c','post',2,2)"#,
        Some(3),
    ),
    (r#"DELETE FROM outbox WHERE extent_id='x_c'"#, Some(1)),
    (
        r#"INSERT INTO provider_permits(provider_id,slot) VALUES ('p_c',0),('p_c',1)"#,
        Some(2),
    ),
    (
        r#"UPDATE provider_permits SET token=token+1, holder='h', lease_until=9 WHERE provider_id='p_c' AND slot=0"#,
        Some(1),
    ),
    (
        r#"UPDATE provider_permits SET holder=NULL, lease_until=0 WHERE provider_id='p_c' AND slot=0"#,
        Some(1),
    ),
    (
        r#"INSERT INTO gc(extent_id,action,due_at) VALUES ('x_c','delete_cache',5)"#,
        Some(2),
    ),
    (r#"UPDATE gc SET done_at=6 WHERE extent_id='x_c'"#, Some(1)),
    (
        r#"INSERT INTO scan_cursors(k,v) VALUES ('cal','a') ON CONFLICT(k) DO UPDATE SET v=excluded.v"#,
        Some(1),
    ),
    (
        r#"INSERT INTO scan_cursors(k,v) VALUES ('cal','b') ON CONFLICT(k) DO UPDATE SET v=excluded.v"#,
        Some(1),
    ),
];

/// A release as one write of the extent row, measured the same way on
/// a new database: `held` to `released` in one statement (the last one,
/// on `x_b`) is two, where the two statements of the older release (on
/// `x_a`) are two each.
const RELEASE: &[(&str, Option<u64>)] = &[
    (
        r#"INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) VALUES ('b_c','calc','o',x'00',1,1)"#,
        Some(3),
    ),
    (
        r#"INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at) VALUES ('g_c','b_c','k','live',1,'e','{}','{}',1,1)"#,
        Some(3),
    ),
    (
        r#"INSERT INTO extents(id,bucket_id,generation_id,state,seq,plain_offset,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) VALUES ('x_a','b_c','g_c','committed',0,0,1,1,x'00','m','s','c','held',1)"#,
        Some(7),
    ),
    (
        r#"INSERT INTO extents(id,bucket_id,generation_id,state,seq,plain_offset,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) VALUES ('x_b','b_c','g_c','committed',1,0,1,1,x'00','m','s','c','held',1)"#,
        Some(7),
    ),
    (
        r#"UPDATE extents SET safety_state='releasing', release_evidence='[]', evict_seq=evict_seq+1 WHERE id='x_a'"#,
        Some(2),
    ),
    (
        r#"UPDATE extents SET safety_state='released', released_at=2, hot_safety_bytes=cipher_size, last_read_at=COALESCE(last_read_at, created_at), evict_seq=evict_seq+1 WHERE id='x_a'"#,
        Some(2),
    ),
    (
        r#"UPDATE extents SET safety_state = 'released', release_evidence = '[]', released_at = 2, hot_safety_bytes = cipher_size, last_read_at = COALESCE(last_read_at, created_at), evict_seq = evict_seq + 1 WHERE id = 'x_b'"#,
        Some(2),
    ),
];

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(f)
}

#[test]
fn the_meter_matches_d1_statement_by_statement() {
    matches_d1(MEASURED);
}

#[test]
fn the_meter_matches_d1_on_a_release_in_one_write() {
    matches_d1(RELEASE);
}

/// Runs `list` on a new database: the meter must give D1's figure for
/// every statement.
fn matches_d1(list: &[(&str, Option<u64>)]) {
    let db = RusqliteSql::with_schema().expect("schema");
    db.meter_writes().expect("meter");
    let mut wrong = Vec::new();
    let mut total = 0u64;
    for (sql, measured) in list {
        let before = db.writes();
        let ran = block_on(db.exec(sql, &[]));
        let metered = db.writes().since(&before).billed();
        match (measured, ran) {
            (Some(want), Ok(_)) => {
                total += want;
                if metered != *want {
                    wrong.push(format!("D1 {want}, meter {metered}: {sql}"));
                }
            }
            (None, Err(_)) => {
                if metered != 0 {
                    wrong.push(format!("refused, yet metered {metered}: {sql}"));
                }
            }
            (Some(_), Err(e)) => wrong.push(format!("failed here ({e}), ran on D1: {sql}")),
            (None, Ok(_)) => wrong.push(format!("ran here, refused on D1: {sql}")),
        }
    }
    assert!(
        wrong.is_empty(),
        "the meter disagrees with D1 on {} of {} statements:\n{}",
        wrong.len(),
        list.len(),
        wrong.join("\n")
    );
    assert_eq!(db.writes().billed(), total, "the report's total");
}

#[test]
fn a_rolled_back_batch_is_not_metered() {
    let db = RusqliteSql::with_schema().expect("schema");
    db.meter_writes().expect("meter");
    let failed = block_on(db.batch(vec![
        ("INSERT INTO meta(k, v) VALUES ('a', 1)", vec![]),
        ("INSERT INTO tx_guard(ok) SELECT 0", vec![]),
    ]));
    assert!(failed.is_err(), "the guard must fail the batch");
    assert_eq!(db.writes().billed(), 0, "nothing was written");
    block_on(db.batch(vec![
        ("INSERT INTO meta(k, v) VALUES ('a', 1)", vec![]),
        ("INSERT INTO meta(k, v) VALUES ('b', 1)", vec![]),
    ]))
    .expect("batch");
    let report = db.writes();
    assert_eq!(report.billed(), 2);
    assert_eq!(report.table("meta"), 2);
    assert_eq!(report.writing_statements, 2);
}

/// A statement with RETURNING that fails after it wrote a row is undone
/// as a whole: it is not metered, and what it left behind is not put on
/// the next statement.
#[test]
fn a_failed_query_is_not_metered() {
    let db = RusqliteSql::with_schema().expect("schema");
    db.meter_writes().expect("meter");
    let failed = block_on(db.query(
        "INSERT INTO meta(k, v) VALUES ('a', 1), ('a', 2) RETURNING k",
        &[],
    ));
    assert!(failed.is_err(), "the second row has the key of the first");
    assert_eq!(db.writes().billed(), 0, "nothing was written");
    block_on(db.exec("INSERT INTO meta(k, v) VALUES ('b', 1)", &[])).expect("exec");
    assert_eq!(db.writes().billed(), 1, "one row");
    // The same before a batch.
    let failed = block_on(db.query(
        "INSERT INTO meta(k, v) VALUES ('c', 1), ('c', 2) RETURNING k",
        &[],
    ));
    assert!(failed.is_err());
    block_on(db.batch(vec![("INSERT INTO meta(k, v) VALUES ('c', 1)", vec![])])).expect("batch");
    let report = db.writes();
    assert_eq!(report.billed(), 2, "one row each");
    assert_eq!(report.table("meta"), 2);
}
