//! The event feed of the directory (AM-37): one tenant's part of it, its
//! epochs and its prune. Under `VELMORA_D1_PROBE` every test runs on D1.

use serde_json::{json, Map, Value};
use velmora_bridge::directory::feed::{
    Appended, EventPage, FeedPosition, FeedReset, NewEvent, APPEND, EVENT_KEEP_MS, FEED_STATE,
    MAX_EVENTS_PAGE, PRUNE_CUT, PRUNE_MARKS, PRUNE_ROWS, PURGE_MARK, PURGE_ROWS, START_EPOCH,
    TENANT_RANGE,
};
use velmora_bridge::directory::record::Tenant;
use velmora_bridge::directory::store::SqlDirectory;
use velmora_bridge::ports::{Sql, SqlValue};
use velmora_bridge::UnixMs;

mod directory_support;
use directory_support::{database, on_d1, Db};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const A1: &str = "t_00000000000000a1";
const B2: &str = "t_00000000000000b2";

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn t(id: &str) -> Tenant {
    Tenant::parse(id).unwrap()
}

fn data(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => panic!("not an object"),
    }
}

fn event(tenant: &str, source: &str, at: i64) -> NewEvent {
    NewEvent {
        tenant: t(tenant),
        kind: "bucket.created".into(),
        source: source.into(),
        at: UnixMs(at),
        data: data(json!({"bucket_id": "b_00000000000000aa", "bucket": "photos"})),
    }
}

async fn append(dir: &SqlDirectory<'_, Db>, tenant: &str, source: &str, at: i64) {
    assert_eq!(
        dir.append_event(&event(tenant, source, at)).await.unwrap(),
        Appended::Appended
    );
}

async fn page(
    dir: &SqlDirectory<'_, Db>,
    tenant: &str,
    after: Option<FeedPosition>,
    limit: u32,
) -> Result<EventPage, FeedReset> {
    dir.tenant_events(&t(tenant), after, limit).await.unwrap()
}

fn seqs(p: &EventPage) -> Vec<u64> {
    p.items.iter().map(|e| e.seq).collect()
}

fn pos(epoch: u64, seq: u64) -> FeedPosition {
    FeedPosition { epoch, seq }
}

#[test]
fn a_tenant_reads_its_own_events_oldest_first_in_pages() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        // Seqs 1..=6: a1, b2, a1, a1, b2, a1.
        for (i, tenant) in [A1, B2, A1, A1, B2, A1].into_iter().enumerate() {
            append(&dir, tenant, &format!("t/{}", i + 1), NOW.0 + i as i64).await;
        }
        let all = page(&dir, A1, None, 10).await.unwrap();
        assert_eq!(seqs(&all), [1, 3, 4, 6]);
        assert_eq!(all.position, pos(0, 6));
        let first = &all.items[0];
        assert_eq!((first.epoch, first.kind.as_str()), (0, "bucket.created"));
        assert_eq!(first.at, NOW);
        assert_eq!(first.data["bucket"], "photos");
        // Pages of two: each position is its last item's.
        let p1 = page(&dir, A1, None, 2).await.unwrap();
        assert_eq!((seqs(&p1), p1.position), (vec![1, 3], pos(0, 3)));
        let p2 = page(&dir, A1, Some(p1.position), 2).await.unwrap();
        assert_eq!((seqs(&p2), p2.position), (vec![4, 6], pos(0, 6)));
        // Nothing follows: the position is `after` itself.
        let p3 = page(&dir, A1, Some(p2.position), 2).await.unwrap();
        assert!(p3.items.is_empty());
        assert_eq!(p3.position, pos(0, 6));
        let b = page(&dir, B2, None, MAX_EVENTS_PAGE).await.unwrap();
        assert_eq!(seqs(&b), [2, 5]);
        // A tenant with no event: the feed's head, so the next read
        // starts after everything there is now.
        let c = page(&dir, "t_00000000000000c3", None, 5).await.unwrap();
        assert!(c.items.is_empty());
        assert_eq!(c.position, pos(0, 6));
        append(&dir, "t_00000000000000c3", "t/1", NOW.0).await;
        let c = page(&dir, "t_00000000000000c3", Some(c.position), 5)
            .await
            .unwrap();
        assert_eq!(seqs(&c), [7]);
    });
}

#[test]
fn a_repeated_source_writes_one_event_and_a_bad_event_none() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        append(&dir, A1, "t/4", NOW.0).await;
        assert_eq!(
            dir.append_event(&event(A1, "t/4", NOW.0 + 9))
                .await
                .unwrap(),
            Appended::Repeated
        );
        // The same source of another tenant is another event.
        append(&dir, B2, "t/4", NOW.0).await;
        let mut bad = Vec::new();
        for kind in ["bucket", "Bucket.created", "bucket.created2", ""] {
            bad.push(NewEvent {
                kind: kind.into(),
                ..event(A1, "t/5", NOW.0)
            });
        }
        for source in ["", "t 5", &"s".repeat(129)] {
            bad.push(event(A1, source, NOW.0));
        }
        for d in [
            json!({"secret_access_key": "x"}),
            json!({"bucket": "p", "nested": {"presign_url": "https://x"}}),
            json!({"list": [{"session_token": 1}]}),
            json!({"blob": "x".repeat(4_100)}),
        ] {
            bad.push(NewEvent {
                data: data(d),
                ..event(A1, "t/6", NOW.0)
            });
        }
        for e in bad {
            assert!(dir.append_event(&e).await.is_err(), "{e:?}");
        }
        let a = page(&dir, A1, None, 10).await.unwrap();
        assert_eq!(seqs(&a), [1]);
        assert_eq!(a.items[0].at, NOW);
        for limit in [0, MAX_EVENTS_PAGE + 1] {
            assert!(dir.tenant_events(&t(A1), None, limit).await.is_err());
        }
    });
}

#[test]
fn a_new_epoch_resets_every_older_position() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        append(&dir, A1, "t/1", NOW.0).await;
        append(&dir, A1, "t/2", NOW.0).await;
        assert_eq!(dir.feed_epoch().await.unwrap(), 0);
        let before = page(&dir, A1, None, 10).await.unwrap();
        assert_eq!(before.position, pos(0, 2));
        // Epoch 0 is the feed before any gate run; the gate's step 8
        // starts its epoch once.
        assert!(!dir.start_feed_epoch(0).await.unwrap());
        assert!(dir.start_feed_epoch(3).await.unwrap());
        assert!(!dir.start_feed_epoch(3).await.unwrap());
        assert!(!dir.start_feed_epoch(2).await.unwrap());
        assert_eq!(dir.feed_epoch().await.unwrap(), 3);
        // A position of the old epoch is reset, whatever its seq.
        for seq in [0, 2, 99] {
            assert_eq!(page(&dir, A1, Some(pos(0, seq)), 10).await, Err(FeedReset));
        }
        assert_eq!(page(&dir, A1, Some(pos(4, 2)), 10).await, Err(FeedReset));
        // The old epoch's rows are not served again.
        let fresh = page(&dir, A1, None, 10).await.unwrap();
        assert!(fresh.items.is_empty());
        assert_eq!(fresh.position, pos(3, 2));
        append(&dir, A1, "t/3", NOW.0).await;
        let next = page(&dir, A1, Some(fresh.position), 10).await.unwrap();
        assert_eq!(seqs(&next), [3]);
        assert_eq!(next.items[0].epoch, 3);
        assert_eq!(next.position, pos(3, 3));
        // A forged position of this epoch below its base starts at the base.
        let low = page(&dir, A1, Some(pos(3, 0)), 10).await.unwrap();
        assert_eq!(seqs(&low), [3]);
    });
}

#[test]
fn the_prune_marks_each_tenant_and_never_skips_silently() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let old = NOW.0 - EVENT_KEEP_MS - 1;
        // Seqs 1..=4 old (a1, b2, a1, b2), 5 young (a1), 6 old again (b2):
        // the prune takes a prefix and stops at the first young row.
        for (i, (tenant, at)) in [
            (A1, old),
            (B2, old),
            (A1, old),
            (B2, old),
            (A1, NOW.0),
            (B2, old),
        ]
        .into_iter()
        .enumerate()
        {
            append(&dir, tenant, &format!("t/{}", i + 1), at).await;
        }
        let a_pos = page(&dir, A1, None, 1).await.unwrap().position;
        assert_eq!(a_pos, pos(0, 1));
        let cutoff = UnixMs(NOW.0 - EVENT_KEEP_MS);
        assert!(dir.prune_events(cutoff, 0).await.is_err());
        // Bounded: at most `limit` rows per step.
        assert_eq!(dir.prune_events(cutoff, 3).await.unwrap(), 3);
        assert_eq!(dir.prune_events(cutoff, 3).await.unwrap(), 1);
        assert_eq!(dir.prune_events(cutoff, 3).await.unwrap(), 0);
        // a1's position at seq 1 is below its mark (3): reset. At the mark
        // or above it: served.
        assert_eq!(page(&dir, A1, Some(a_pos), 10).await, Err(FeedReset));
        let a = page(&dir, A1, Some(pos(0, 3)), 10).await.unwrap();
        assert_eq!(seqs(&a), [5]);
        let a = page(&dir, A1, None, 10).await.unwrap();
        assert_eq!(seqs(&a), [5]);
        // b2's mark is 4; seq 6 stays behind the young row.
        assert_eq!(page(&dir, B2, Some(pos(0, 2)), 10).await, Err(FeedReset));
        let b = page(&dir, B2, None, 10).await.unwrap();
        assert_eq!(seqs(&b), [6]);
        // A tenant none of whose events was pruned is never reset.
        append(&dir, "t_00000000000000c3", "t/1", NOW.0).await;
        let c = page(&dir, "t_00000000000000c3", Some(pos(0, 0)), 10)
            .await
            .unwrap();
        assert_eq!(seqs(&c), [7]);
    });
}

#[test]
fn a_seq_is_never_used_twice_after_the_prune_empties_the_feed() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let old = NOW.0 - EVENT_KEEP_MS - 1;
        append(&dir, A1, "t/1", old).await;
        append(&dir, A1, "t/2", old).await;
        assert_eq!(dir.prune_events(UnixMs(NOW.0), 10).await.unwrap(), 2);
        // The empty answer's position is never below the tenant's mark,
        // so the next read from it is not reset (no reset loop).
        let empty = page(&dir, A1, None, 10).await.unwrap();
        assert!(empty.items.is_empty());
        assert_eq!(empty.position, pos(0, 2));
        assert!(page(&dir, A1, Some(empty.position), 10).await.is_ok());
        append(&dir, A1, "t/3", NOW.0).await;
        let next = page(&dir, A1, Some(empty.position), 10).await.unwrap();
        assert_eq!(seqs(&next), [3]);
    });
}

/// Every statement of the feed is a point read, one bounded index or key
/// range, or one row; printed for the receipt (`--nocapture`).
#[test]
fn every_feed_statement_has_a_bounded_plan() {
    block_on(async {
        let db = database();
        let one = SqlValue::Int(1);
        let text = SqlValue::Text(A1.into());
        let three = vec![text.clone(), one.clone(), one.clone()];
        let cases: [(&str, &str, Vec<SqlValue>, &[&str]); 9] = [
            (
                "PURGE_MARK",
                PURGE_MARK,
                three.clone(),
                &["tenant_events_tenant (tenant=? AND seq<?)"],
            ),
            (
                "PURGE_ROWS",
                PURGE_ROWS,
                three.clone(),
                &["tenant_events_tenant (tenant=? AND seq<?)"],
            ),
            ("FEED_STATE", FEED_STATE, vec![text.clone()], &[]),
            (
                "TENANT_RANGE",
                TENANT_RANGE,
                vec![text.clone(), one.clone(), one.clone(), one.clone()],
                &["tenant_events_tenant (tenant=? AND seq>?)"],
            ),
            (
                "APPEND",
                APPEND,
                vec![
                    text.clone(),
                    SqlValue::Text("a.b".into()),
                    SqlValue::Text("t/1".into()),
                    one.clone(),
                    SqlValue::Text("{}".into()),
                ],
                &[],
            ),
            ("START_EPOCH", START_EPOCH, vec![one.clone()], &[]),
            // The one scan: the oldest `?2` rows in key order, bounded by
            // its LIMIT.
            ("PRUNE_CUT", PRUNE_CUT, vec![one.clone(), one.clone()], &[]),
            (
                "PRUNE_MARKS",
                PRUNE_MARKS,
                vec![one.clone()],
                &["INTEGER PRIMARY KEY (rowid<?)"],
            ),
            (
                "PRUNE_ROWS",
                PRUNE_ROWS,
                vec![one.clone()],
                &["INTEGER PRIMARY KEY (rowid<?)"],
            ),
        ];
        for (name, sql, params, wants) in cases {
            let rows = db
                .query(&format!("EXPLAIN QUERY PLAN {sql}"), &params)
                .await
                .unwrap();
            let lines: Vec<String> = rows
                .iter()
                .map(|r| match r.last() {
                    Some(SqlValue::Text(s)) => s.clone(),
                    other => panic!("{other:?}"),
                })
                .collect();
            println!(
                "plan {} {name}: {}",
                if on_d1() { "d1" } else { "sqlite" },
                lines.join(" | ")
            );
            for want in wants {
                assert!(lines.iter().any(|l| l.contains(want)), "{name}: {lines:?}");
            }
            for l in &lines {
                let scan = l.starts_with("SCAN ") && !l.starts_with("SCAN CONSTANT ROW");
                // PRUNE_CUT and the purge scan their own subqueries of at most
                // `LIMIT` rows.
                let bounded = (name == "PRUNE_CUT" && l == "SCAN tenant_events")
                    || ((name == "PRUNE_CUT" || name.starts_with("PURGE"))
                        && l.starts_with("SCAN (subquery"));
                assert!(!scan || bounded, "{name}: {l}");
            }
        }
    });
}

/// Review r1 LOW 6: the shred purges one tenant's events, bounded, and
/// raises its mark, so a poller below it is reset and nothing of another
/// tenant moves.
#[test]
fn the_shred_purges_one_tenants_events_and_marks_them() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        // a1: 1, 3, 4; b2: 2; a1's final shred event: 5.
        for (i, tenant) in [A1, B2, A1, A1, A1].into_iter().enumerate() {
            append(&dir, tenant, &format!("t/{}", i + 1), NOW.0).await;
        }
        assert!(dir.purge_tenant_events(&t(A1), 4, 0).await.is_err());
        assert_eq!(dir.purge_tenant_events(&t(A1), 4, 2).await.unwrap(), 2);
        assert_eq!(dir.purge_tenant_events(&t(A1), 4, 2).await.unwrap(), 1);
        assert_eq!(dir.purge_tenant_events(&t(A1), 4, 2).await.unwrap(), 0);
        let a = page(&dir, A1, None, 10).await.unwrap();
        assert_eq!(seqs(&a), [5]);
        assert_eq!(page(&dir, A1, Some(pos(0, 3)), 10).await, Err(FeedReset));
        assert!(page(&dir, A1, Some(pos(0, 4)), 10).await.is_ok());
        let b = page(&dir, B2, Some(pos(0, 0)), 10).await.unwrap();
        assert_eq!(seqs(&b), [2]);
    });
}

/// A database that runs one prune step right after the read's index range
/// and before its second state read: the race of AM-37's reset rule.
struct PruneDuringRead<'a> {
    db: &'a Db,
    cutoff: UnixMs,
    armed: std::cell::Cell<bool>,
}

impl Sql for PruneDuringRead<'_> {
    async fn query(
        &self,
        sql: &str,
        params: &[SqlValue],
    ) -> velmora_bridge::Result<Vec<Vec<SqlValue>>> {
        let rows = self.db.query(sql, params).await?;
        if sql == TENANT_RANGE && self.armed.replace(false) {
            SqlDirectory { sql: self.db }
                .prune_events(self.cutoff, 1)
                .await?;
        }
        Ok(rows)
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> velmora_bridge::Result<u64> {
        self.db.exec(sql, params).await
    }

    async fn batch(
        &self,
        stmts: Vec<(&'static str, Vec<SqlValue>)>,
    ) -> velmora_bridge::Result<Vec<u64>> {
        self.db.batch(stmts).await
    }
}

/// Review r2 LOW: a prune during a read resets a position below its new
/// mark, and never a read without one (it starts at the oldest kept event).
#[test]
fn a_prune_during_a_read_resets_a_position_and_never_a_read_without_one() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let old = NOW.0 - EVENT_KEEP_MS - 1;
        // a1: 1 (old), 2, 3 (young).
        append(&dir, A1, "t/1", old).await;
        append(&dir, A1, "t/2", NOW.0).await;
        append(&dir, A1, "t/3", NOW.0).await;
        let cutoff = UnixMs(NOW.0 - EVENT_KEEP_MS);
        let racing = PruneDuringRead {
            db: &db,
            cutoff,
            armed: std::cell::Cell::new(true),
        };
        let r = SqlDirectory { sql: &racing };
        // Without `after`: no reset; the row the prune took meanwhile is
        // dropped, so the position is never below the new mark.
        let p = r.tenant_events(&t(A1), None, 10).await.unwrap().unwrap();
        assert_eq!(seqs(&p), [2, 3]);
        assert_eq!(p.position, pos(0, 3));
        // The prune ran: seq 1 is gone, the mark is 1.
        let after = dir.tenant_events(&t(A1), None, 10).await.unwrap().unwrap();
        assert_eq!(seqs(&after), [2, 3]);
        // A position at the mark, and a prune during the read that takes
        // seq 2 (a later cutoff) and raises the mark above it: reset.
        let racing = PruneDuringRead {
            db: &db,
            cutoff: UnixMs(NOW.0 + 1),
            armed: std::cell::Cell::new(true),
        };
        let r = SqlDirectory { sql: &racing };
        assert_eq!(
            r.tenant_events(&t(A1), Some(pos(0, 1)), 10).await.unwrap(),
            Err(FeedReset)
        );
    });
}

/// A first page whose only row the prune took during the read answers the
/// prune mark, and the next read from it is not reset and skips nothing.
#[test]
fn a_first_page_pruned_during_the_read_answers_the_mark() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let old = NOW.0 - EVENT_KEEP_MS - 1;
        append(&dir, A1, "t/1", old).await;
        append(&dir, A1, "t/2", NOW.0).await;
        let racing = PruneDuringRead {
            db: &db,
            cutoff: UnixMs(NOW.0 - EVENT_KEEP_MS),
            armed: std::cell::Cell::new(true),
        };
        let r = SqlDirectory { sql: &racing };
        let p = r.tenant_events(&t(A1), None, 1).await.unwrap().unwrap();
        assert!(p.items.is_empty());
        assert_eq!(p.position, pos(0, 1));
        let next = page(&dir, A1, Some(p.position), 10).await.unwrap();
        assert_eq!(seqs(&next), [2]);
    });
}
