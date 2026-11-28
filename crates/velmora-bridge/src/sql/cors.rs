//! Bucket CORS catalogue rows and isolate-local, bounded lookup cache.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora_s3_proto::mutation::{CorsConfiguration, MAX_CORS_BYTES};

use super::auth::guard_bucket_id;
use super::objects::{ms, text};
use super::replay::guard_no_replay;
use super::uploads::guarded;
use super::SqlCatalog;
use crate::{BridgeError, Bucket, Guard, Result, Sql, SqlValue, UnixMs};

// One round trip whether the name is unknown, has no config, or has a rule.
const CORS_BY_NAME: &str = "SELECT c.doc, c.doc_sha256, c.rules FROM buckets b \
    LEFT JOIN bucket_cors c ON c.bucket_id = b.id WHERE b.name = ?1";
const BUCKET_CORS: &str = "SELECT doc, doc_sha256, rules FROM bucket_cors WHERE bucket_id = ?1";
const PUT_BUCKET_CORS: &str =
    "INSERT INTO bucket_cors(bucket_id, doc, doc_sha256, rules, updated_at_ms) \
    VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(bucket_id) DO UPDATE SET \
    doc = excluded.doc, doc_sha256 = excluded.doc_sha256, rules = excluded.rules, \
    updated_at_ms = excluded.updated_at_ms";
pub(super) const DELETE_BUCKET_CORS: &str = "DELETE FROM bucket_cors WHERE bucket_id = ?1";

const TTL_MS: i64 = 60_000;
// At most 64 documents of at most 64 KiB, even when many unauthenticated
// requests name different buckets.
const CAPACITY: usize = 64;

struct Entry {
    loaded_at: UnixMs,
    configuration: Option<Rc<CorsConfiguration>>,
}

impl Entry {
    fn fresh(&self, now: UnixMs) -> bool {
        (0..TTL_MS).contains(&now.0.saturating_sub(self.loaded_at.0))
    }
}

#[derive(Default)]
pub(super) struct Cache {
    entries: RefCell<BTreeMap<String, Entry>>,
    // A read started before a write must not repopulate its invalidated cache.
    epoch: Cell<u64>,
}

impl Cache {
    pub(super) fn invalidate(&self, name: &str) {
        self.epoch.set(self.epoch.get().wrapping_add(1));
        self.entries.borrow_mut().remove(name);
    }

    fn insert(&self, name: &str, entry: Entry) {
        let mut entries = self.entries.borrow_mut();
        if entries.len() >= CAPACITY && !entries.contains_key(name) {
            let oldest = entries
                .iter()
                .min_by_key(|(_, value)| value.loaded_at.0)
                .map(|(key, _)| key.clone())
                .expect("nonempty at capacity");
            entries.remove(&oldest);
        }
        entries.insert(name.to_owned(), entry);
    }
}

fn digest(doc: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(doc.as_bytes()) {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 15)]));
    }
    hex
}

fn corrupt() -> BridgeError {
    BridgeError::Sql("invalid stored CORS configuration".into())
}

fn decode(row: &[SqlValue]) -> Result<(&str, CorsConfiguration)> {
    let [SqlValue::Text(doc), SqlValue::Text(sha), SqlValue::Int(rules)] = row else {
        return Err(corrupt());
    };
    if doc.len() > MAX_CORS_BYTES || digest(doc) != *sha {
        return Err(corrupt());
    }
    let configuration = CorsConfiguration::parse(doc.as_bytes()).map_err(|_| corrupt())?;
    if configuration.rule_count() as i64 != *rules {
        return Err(corrupt());
    }
    Ok((doc, configuration))
}

pub(super) async fn document<S: Sql>(c: &SqlCatalog<S>, id: &str) -> Result<Option<String>> {
    let rows = c.sql.query(BUCKET_CORS, &[text(id)]).await?;
    rows.first()
        .map(|row| decode(row).map(|(doc, _)| doc.to_owned()))
        .transpose()
}

pub(super) async fn cached<S: Sql>(
    c: &SqlCatalog<S>,
    name: &str,
    now: UnixMs,
) -> Result<Option<Rc<CorsConfiguration>>> {
    if let Some(entry) = c
        .cors_cache
        .entries
        .borrow()
        .get(name)
        .filter(|e| e.fresh(now))
    {
        return Ok(entry.configuration.clone());
    }
    let epoch = c.cors_cache.epoch.get();
    let rows = c.sql.query(CORS_BY_NAME, &[text(name)]).await?;
    let configuration = match rows.first().map(Vec::as_slice) {
        None | Some([SqlValue::Null, SqlValue::Null, SqlValue::Null]) => None,
        Some(row) => Some(Rc::new(decode(row)?.1)),
    };
    if epoch == c.cors_cache.epoch.get() {
        c.cors_cache.insert(
            name,
            Entry {
                loaded_at: now,
                configuration: configuration.clone(),
            },
        );
    }
    Ok(configuration)
}

pub(super) async fn set<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &Bucket,
    doc_and_rules: Option<(&str, usize)>,
    now: UnixMs,
) -> Result<Guard<()>> {
    let id = text(bucket.id.as_str());
    let change = match doc_and_rules {
        Some((doc, rules)) => (
            PUT_BUCKET_CORS,
            vec![
                id,
                text(doc),
                text(&digest(doc)),
                SqlValue::Int(rules as i64),
                ms(now),
            ],
        ),
        None => (DELETE_BUCKET_CORS, vec![id]),
    };
    guarded(c, vec![guard_bucket_id(bucket), guard_no_replay(), change]).await
}

#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(&'static str, Vec<SqlValue>)> {
    super::pg_manifest(&[
        (CORS_BY_NAME, "T"),
        (BUCKET_CORS, "T"),
        (PUT_BUCKET_CORS, "TTTII"),
        (DELETE_BUCKET_CORS, "T"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{RusqliteSql, MIGRATION_BUCKET_CORS};

    #[tokio::test(flavor = "current_thread")]
    async fn sqlite_migration_repeats_and_lookups_use_point_indexes() {
        let db = RusqliteSql::with_schema().unwrap();
        for _ in 0..2 {
            db.apply(MIGRATION_BUCKET_CORS).unwrap();
        }
        for (query, indexes) in [
            (
                CORS_BY_NAME,
                &[
                    "sqlite_autoindex_buckets_2",
                    "sqlite_autoindex_bucket_cors_1",
                ][..],
            ),
            (BUCKET_CORS, &["sqlite_autoindex_bucket_cors_1"][..]),
        ] {
            let plan = db
                .query(&format!("EXPLAIN QUERY PLAN {query}"), &[text("cors-test")])
                .await
                .unwrap();
            assert_eq!(plan.len(), indexes.len(), "{plan:?}");
            for (row, index) in plan.iter().zip(indexes) {
                assert!(
                    matches!(row.last(), Some(SqlValue::Text(s)) if s.starts_with("SEARCH ") && s.contains(index)),
                    "{plan:?}"
                );
            }
        }
    }
}
