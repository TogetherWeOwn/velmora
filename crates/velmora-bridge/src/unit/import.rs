//! The import of the owner move (`docs/units.md`, "Import"; DS1 §2.3,
//! §3.2, §3.4 step 3).
//!
//! The move tool pages the rows of the frozen D1 and sends them, as the
//! rules of DS1 §3.2 transform them, into the owner's root unit `<t>/0`
//! in batches ([`UnitOp::Import`](super::call::UnitOp)). The unit accepts
//! a batch only while all of these hold (DS1 §2.3):
//!
//! - it is the root unit of a tenant other than tenant 0;
//! - its own `restoring` entry is set, and the batch names that entry's
//!   `since_seq`;
//! - the verified head of **tenant 0** that the Worker passes says
//!   `moving` with `move.to` = this tenant, and its seq is not below the
//!   newest tenant-0 head an import was bound to;
//! - the caller's numbers pass rule 5 as a job's do: equal to the unit's
//!   (above: `sync_needed`; missing or below: refused).
//!
//! That binds the import to one move: no other tenant is filled, and no
//! import runs outside a window.
//!
//! **What a batch is.** One table, its column list (it must be the
//! unit's own, in schema order: a schema that differs from the frozen
//! D1's is found at the first batch), at most [`MAX_ROWS`] rows of typed
//! values (the type class of every value is kept, so V1 can hash both
//! sides alike), and two cursors: `after`, the cursor of the batch it
//! follows (none for a table's first), and `cursor`, its own. A batch is
//! applied when `after` is the table's stored cursor; one whose `cursor`
//! is the stored cursor is the last batch sent again (its answer was
//! lost) and changes nothing; any other is refused. So every batch is
//! applied once and in order, and the import resumes by table and cursor.
//!
//! **What is imported.** The data tables of DS1 §3.2 ([`ImportTable`]).
//! Not imported: `access_keys` and `grants` (the owner's key chain is
//! applied to the unit instead, so the unit's `keys_seq` and its keys
//! agree; V6 compares them), the pipeline and bookkeeping tables DS1
//! §3.2 leaves out, and the usage counters `usage_global` and
//! `usage_buckets`: they are the unit's own, kept by its triggers while
//! they are on and filled by the recount when they are off (AM-3), so
//! the import never double-counts a row. An `outbox` row must come with
//! its lease cleared. An extent's `plan_rev` is bound through
//! [`crate::plan_rev::bound`].

use serde::{Deserialize, Serialize};

use super::name::TenantId;
use super::object::poll_once;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result};

/// The most rows one batch may carry (est).
pub const MAX_ROWS: usize = 500;
/// The longest cursor. The move's copy names the primary key of the last
/// row it read, as typed JSON: for `objects` that is a bucket id and an
/// object key. The S3 path bounds a key only by its request target
/// (8 KiB, `service::common`), and JSON escapes a control character in
/// 6 bytes (`\u0001`), so a stored key can need about 48 KiB here. A
/// cursor this bound refuses stops the move (`Shape`); it never stops it
/// quietly.
pub const MAX_CURSOR: usize = 64 * 1024;

/// The verified head of tenant 0, as far as the import reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveHead {
    /// The seq of tenant 0's head record.
    pub seq: u64,
    /// Tenant 0's selector: `d1`, `moving`, `moved` or `retired`.
    pub selector: String,
    /// `move.to`, when the record has a move.
    #[serde(default)]
    pub to: Option<TenantId>,
    /// The record's `flips` (AM-7): this window's move ordinal is
    /// `flips + 1` (AM-29).
    pub flips: u64,
}

/// One value with its SQLite type class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportValue {
    #[serde(rename = "n")]
    Null,
    #[serde(rename = "i")]
    Int(i64),
    #[serde(rename = "t")]
    Text(String),
    #[serde(rename = "b", with = "b64")]
    Blob(Vec<u8>),
}

impl ImportValue {
    fn sql(&self) -> SqlValue {
        match self {
            ImportValue::Null => SqlValue::Null,
            ImportValue::Int(n) => SqlValue::Int(*n),
            ImportValue::Text(s) => SqlValue::Text(s.clone()),
            ImportValue::Blob(b) => SqlValue::Blob(b.clone()),
        }
    }
}

/// One batch of one table. `Debug` shows its shape only: rows hold
/// object names and wrapped keys.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportBatch {
    pub table: ImportTable,
    pub columns: Vec<String>,
    /// The cursor of the batch this one follows; none for the first.
    #[serde(default)]
    pub after: Option<String>,
    /// This batch's own cursor (the tool's position in the frozen D1).
    pub cursor: String,
    pub rows: Vec<Vec<ImportValue>>,
}

impl std::fmt::Debug for ImportBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportBatch")
            .field("table", &self.table)
            .field("after", &self.after)
            .field("cursor", &self.cursor)
            .field("rows", &self.rows.len())
            .finish_non_exhaustive()
    }
}

/// The tables an import fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportTable {
    Buckets,
    Generations,
    Objects,
    Extents,
    GenerationExtents,
    Articles,
    Verifications,
    VerifyRaises,
    VerifyEscalations,
    Outbox,
    Uploads,
    UploadParts,
    UploadPartExtents,
    Gc,
    UsageHours,
    UsageRecounts,
}

impl ImportTable {
    pub const ALL: [ImportTable; 16] = [
        ImportTable::Buckets,
        ImportTable::Generations,
        ImportTable::Objects,
        ImportTable::Extents,
        ImportTable::GenerationExtents,
        ImportTable::Articles,
        ImportTable::Verifications,
        ImportTable::VerifyRaises,
        ImportTable::VerifyEscalations,
        ImportTable::Outbox,
        ImportTable::Uploads,
        ImportTable::UploadParts,
        ImportTable::UploadPartExtents,
        ImportTable::Gc,
        ImportTable::UsageHours,
        ImportTable::UsageRecounts,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ImportTable::Buckets => "buckets",
            ImportTable::Generations => "generations",
            ImportTable::Objects => "objects",
            ImportTable::Extents => "extents",
            ImportTable::GenerationExtents => "generation_extents",
            ImportTable::Articles => "articles",
            ImportTable::Verifications => "verifications",
            ImportTable::VerifyRaises => "verify_raises",
            ImportTable::VerifyEscalations => "verify_escalations",
            ImportTable::Outbox => "outbox",
            ImportTable::Uploads => "uploads",
            ImportTable::UploadParts => "upload_parts",
            ImportTable::UploadPartExtents => "upload_part_extents",
            ImportTable::Gc => "gc",
            ImportTable::UsageHours => "usage_hours",
            ImportTable::UsageRecounts => "usage_recounts",
        }
    }

    /// The table's columns, in schema order (a test holds them to the
    /// schema).
    pub fn columns(self) -> &'static [&'static str] {
        match self {
            ImportTable::Buckets => &[
                "id",
                "name",
                "owner",
                "bdk_wrapped",
                "kek_version",
                "disposable",
                "created_at",
            ],
            ImportTable::Generations => &[
                "id",
                "bucket_id",
                "key",
                "state",
                "size",
                "etag",
                "checksum_json",
                "content_json",
                "user_meta_json",
                "extent_count",
                "created_at",
                "retired_at",
            ],
            ImportTable::Objects => &["bucket_id", "key", "generation_id"],
            ImportTable::Extents => &[
                "id",
                "bucket_id",
                "generation_id",
                "state",
                "seq",
                "plain_offset",
                "plain_size",
                "cipher_size",
                "media_header",
                "key_mode",
                "wrapped_file_key",
                "plain_md5",
                "plain_sha256",
                "cipher_sha256",
                "safety_state",
                "article_count",
                "plan_rev",
                "last_verified_at",
                "release_evidence",
                "released_at",
                "created_at",
                "hot_safety_bytes",
                "hot_cache_bytes",
                "last_read_at",
                "evict_seq",
                "plan",
                "posted_at",
                "reposted_at",
                "parity",
                "parity_count",
            ],
            ImportTable::GenerationExtents => {
                &["generation_id", "seq", "extent_id", "plain_offset"]
            }
            ImportTable::Articles => &[
                "extent_id",
                "idx",
                "message_id",
                "newsgroup",
                "headers",
                "cipher_offset",
                "cipher_len",
                "payload_sha256",
                "state",
                "provider_id",
                "posted_at",
                "yenc_name",
                "reposted_at",
            ],
            ImportTable::Verifications => &[
                "extent_id",
                "backbone",
                "provider_id",
                "verified_at",
                "plan_rev",
                "articles_ok",
                "articles_total",
                "result",
                "kind",
                "articles_present",
                "mode",
            ],
            ImportTable::VerifyRaises => &["extent_id", "backbone", "plan_rev", "raised_at"],
            ImportTable::VerifyEscalations => {
                &["backbone", "until", "raised_at", "extent_id", "result"]
            }
            ImportTable::Outbox => &[
                "extent_id",
                "generation_id",
                "stage",
                "attempts",
                "next_at",
                "lease_token",
                "lease_owner",
                "lease_until",
                "cursor",
                "last_error",
                "updated_at",
                "sent_at",
            ],
            ImportTable::Uploads => &[
                "id",
                "bucket_id",
                "key",
                "content_json",
                "user_meta_json",
                "state",
                "revision",
                "completed_generation_id",
                "complete_digest",
                "result_etag",
                "initiated_at",
            ],
            ImportTable::UploadParts => &[
                "upload_id",
                "part_number",
                "extent_id",
                "size",
                "etag",
                "uploaded_at",
            ],
            ImportTable::UploadPartExtents => &[
                "upload_id",
                "part_number",
                "piece",
                "tenant_id",
                "extent_id",
            ],
            ImportTable::Gc => &["id", "extent_id", "action", "due_at", "done_at"],
            ImportTable::UsageHours => {
                &["hour", "posts", "verifies", "releases", "dead", "failures"]
            }
            ImportTable::UsageRecounts => &[
                "id",
                "started_at",
                "finished_at",
                "rows",
                "adopted",
                "drift",
                "detail",
            ],
        }
    }

    /// The one statement that writes a row of this table, word for word
    /// (the extents insert is on the `plan_rev` contract's list).
    fn insert(self) -> &'static str {
        match self {
            ImportTable::Buckets => {
                "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, \
                 created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)"
            }
            ImportTable::Generations => {
                "INSERT INTO generations(id, bucket_id, key, state, size, etag, checksum_json, \
                 content_json, user_meta_json, extent_count, created_at, retired_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
            }
            ImportTable::Objects => {
                "INSERT INTO objects(bucket_id, key, generation_id) VALUES (?1,?2,?3)"
            }
            ImportTable::Extents => {
                "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, last_verified_at, release_evidence, released_at, created_at, hot_safety_bytes, hot_cache_bytes, last_read_at, evict_seq, plan, posted_at, reposted_at, parity, parity_count) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30)"
            }
            // The extents insert trigger writes the same row first: a row
            // already there is kept only if it is equal (checked after).
            ImportTable::GenerationExtents => {
                "INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
                 VALUES (?1,?2,?3,?4) ON CONFLICT(generation_id, seq) DO NOTHING"
            }
            ImportTable::Articles => {
                "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, \
                 cipher_offset, cipher_len, payload_sha256, state, provider_id, posted_at, \
                 yenc_name, reposted_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)"
            }
            ImportTable::Verifications => {
                "INSERT INTO verifications(extent_id, backbone, provider_id, verified_at, \
                 plan_rev, articles_ok, articles_total, result, kind, articles_present, mode) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
            }
            ImportTable::VerifyRaises => {
                "INSERT INTO verify_raises(extent_id, backbone, plan_rev, raised_at) \
                 VALUES (?1,?2,?3,?4)"
            }
            ImportTable::VerifyEscalations => {
                "INSERT INTO verify_escalations(backbone, until, raised_at, extent_id, result) \
                 VALUES (?1,?2,?3,?4,?5)"
            }
            ImportTable::Outbox => {
                "INSERT INTO outbox(extent_id, generation_id, stage, attempts, next_at, \
                 lease_token, lease_owner, lease_until, cursor, last_error, updated_at, sent_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
            }
            ImportTable::Uploads => {
                "INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, \
                 revision, completed_generation_id, complete_digest, result_etag, initiated_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
            }
            ImportTable::UploadParts => {
                "INSERT INTO upload_parts(upload_id, part_number, extent_id, size, etag, \
                 uploaded_at) VALUES (?1,?2,?3,?4,?5,?6)"
            }
            ImportTable::UploadPartExtents => {
                "INSERT INTO upload_part_extents(upload_id, part_number, piece, tenant_id, \
                 extent_id) VALUES (?1,?2,?3,?4,?5)"
            }
            ImportTable::Gc => {
                "INSERT INTO gc(id, extent_id, action, due_at, done_at) VALUES (?1,?2,?3,?4,?5)"
            }
            ImportTable::UsageHours => {
                "INSERT INTO usage_hours(hour, posts, verifies, releases, dead, failures) \
                 VALUES (?1,?2,?3,?4,?5,?6)"
            }
            ImportTable::UsageRecounts => {
                "INSERT INTO usage_recounts(id, started_at, finished_at, rows, adopted, drift, \
                 detail) VALUES (?1,?2,?3,?4,?5,?6,?7)"
            }
        }
    }

    pub fn parse(name: &str) -> Option<ImportTable> {
        ImportTable::ALL.into_iter().find(|t| t.name() == name)
    }

    /// The table's primary key, in index order: what an export pages by
    /// (a test holds them to the schema).
    pub fn key_columns(self) -> &'static [&'static str] {
        match self {
            ImportTable::Buckets
            | ImportTable::Generations
            | ImportTable::Extents
            | ImportTable::Uploads
            | ImportTable::Gc
            | ImportTable::UsageRecounts => &["id"],
            ImportTable::Objects => &["bucket_id", "key"],
            ImportTable::GenerationExtents => &["generation_id", "seq"],
            ImportTable::Articles => &["extent_id", "idx"],
            ImportTable::Verifications => &["extent_id", "backbone", "verified_at"],
            ImportTable::VerifyRaises => &["extent_id", "backbone", "plan_rev"],
            ImportTable::VerifyEscalations => &["backbone"],
            ImportTable::Outbox => &["extent_id"],
            ImportTable::UploadParts => &["upload_id", "part_number"],
            ImportTable::UploadPartExtents => &["upload_id", "part_number", "piece"],
            ImportTable::UsageHours => &["hour"],
        }
    }
}

/// One table's row count at the end of the import, as the move tool
/// states it in `import_seal` (AM-29).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportCount {
    pub table: ImportTable,
    pub rows: u64,
}

/// Why a batch was refused. Nothing of it is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportRefusal {
    /// The unit is not the root unit of a tenant other than tenant 0,
    /// its `restoring` entry is not set or not the one named, or tenant
    /// 0's head is not `moving` to this tenant (or is older than one an
    /// import was already bound to). The Worker alarms.
    NotBound,
    /// The column list is not the unit's, or a row has another length,
    /// a value the table refuses here (a leased outbox row, a `plan_rev`
    /// above 1, a key value that is null, a blob, or not of its column's
    /// class), or the batch is empty or too large.
    Shape,
    /// `after` is not the table's stored cursor, and the batch is not
    /// the last one sent again.
    OutOfOrder,
    /// The import is sealed: no batch is taken after `import_seal`.
    Sealed,
    /// `import_seal` did not name every import table once, or named a
    /// row count other than the unit holds (a batch is missing, or the
    /// tool counted another run). Nothing is kept.
    CountMismatch,
}

/// What a batch did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Imported {
    /// The batch was applied (`applied`), or was the last batch sent
    /// again and changed nothing; `cursor` and `rows` are the table's.
    Done {
        cursor: String,
        rows: u64,
        applied: bool,
    },
    Refused(ImportRefusal),
}

/// The binding checks of DS1 §2.3 that need no rows. `restoring_since`
/// is the unit's own entry; `since` the batch's.
pub fn bound_to_move(
    own_tenant: &TenantId,
    own_unit: u32,
    restoring_since: Option<u64>,
    since: u64,
    head: &MoveHead,
) -> bool {
    !own_tenant.is_zero()
        && own_unit == 0
        && restoring_since == Some(since)
        && head.selector == "moving"
        && head.to.as_ref() == Some(own_tenant)
}

/// Applies one batch inside the caller's transaction, after
/// [`bound_to_move`] passed. Checks and stores the tenant-0 seq bound.
pub fn apply<S: Sql>(
    sql: &S,
    since: u64,
    head: &MoveHead,
    batch: &ImportBatch,
) -> Result<Imported> {
    if sealed(sql)?.is_some() {
        return Ok(Imported::Refused(ImportRefusal::Sealed));
    }
    if !move_seq_ok(sql, since, head.seq)? {
        return Ok(Imported::Refused(ImportRefusal::NotBound));
    }
    let t = batch.table;
    let want = t.columns();
    let shape_ok = batch.columns.len() == want.len()
        && batch.columns.iter().zip(want).all(|(a, b)| a == b)
        && !batch.rows.is_empty()
        && batch.rows.len() <= MAX_ROWS
        && !batch.cursor.is_empty()
        && batch.cursor.len() <= MAX_CURSOR
        && batch
            .after
            .as_ref()
            .is_none_or(|a| !a.is_empty() && a.len() <= MAX_CURSOR)
        && batch.rows.iter().all(|r| r.len() == want.len());
    if !shape_ok {
        return Ok(Imported::Refused(ImportRefusal::Shape));
    }
    let stored = progress_of(sql, t)?;
    let stored_cursor = stored.as_ref().map(|(c, _)| c.clone());
    if batch.after != stored_cursor {
        if let Some((cursor, rows)) = stored {
            if cursor == batch.cursor {
                return Ok(Imported::Done {
                    cursor,
                    rows,
                    applied: false,
                });
            }
        }
        return Ok(Imported::Refused(ImportRefusal::OutOfOrder));
    }
    for row in &batch.rows {
        let Some(params) = params(t, row)? else {
            return Ok(Imported::Refused(ImportRefusal::Shape));
        };
        poll_once(sql.exec(t.insert(), &params))??;
        if t == ImportTable::GenerationExtents && !generation_extent_is(sql, &params)? {
            return Ok(Imported::Refused(ImportRefusal::Shape));
        }
    }
    let rows = stored.map_or(0, |(_, n)| n) + batch.rows.len() as u64;
    poll_once(sql.exec(
        "INSERT INTO unit_import(tbl, cursor, rows) VALUES (?1, ?2, ?3) \
         ON CONFLICT(tbl) DO UPDATE SET cursor = excluded.cursor, rows = excluded.rows",
        &[
            SqlValue::Text(t.name().into()),
            SqlValue::Text(batch.cursor.clone()),
            int(rows)?,
        ],
    ))??;
    Ok(Imported::Done {
        cursor: batch.cursor.clone(),
        rows,
        applied: true,
    })
}

/// What `import_seal` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seal {
    /// The import is sealed for `move_ordinal`; `newly`: by this call.
    Done {
        move_ordinal: u64,
        newly: bool,
    },
    Refused(ImportRefusal),
}

/// Seals the import (AM-29), inside the caller's transaction, after
/// [`bound_to_move`] passed: `tables` must name every import table once,
/// each with the rows the unit took (a table without a batch: 0). Sets
/// `final` and `move_ordinal` = the head's `flips + 1`. From then on no
/// batch is taken, and a `move` gate report ([`super::lift::open_move`])
/// may be opened for that ordinal. A repeat with the same counts and
/// ordinal changes nothing.
pub fn seal<S: Sql>(sql: &S, since: u64, head: &MoveHead, tables: &[ImportCount]) -> Result<Seal> {
    if !move_seq_ok(sql, since, head.seq)? {
        return Ok(Seal::Refused(ImportRefusal::NotBound));
    }
    let Some(ordinal) = head.flips.checked_add(1) else {
        return Ok(Seal::Refused(ImportRefusal::NotBound));
    };
    let held: std::collections::BTreeMap<String, u64> =
        progress(sql)?.into_iter().map(|(t, _, n)| (t, n)).collect();
    let mut named = std::collections::BTreeSet::new();
    for c in tables {
        let have = held.get(c.table.name()).copied().unwrap_or(0);
        if !named.insert(c.table.name()) || c.rows != have {
            return Ok(Seal::Refused(ImportRefusal::CountMismatch));
        }
    }
    if named.len() != ImportTable::ALL.len() {
        return Ok(Seal::Refused(ImportRefusal::CountMismatch));
    }
    match sealed(sql)? {
        Some(o) if o == ordinal => {
            return Ok(Seal::Done {
                move_ordinal: o,
                newly: false,
            })
        }
        Some(_) => return Ok(Seal::Refused(ImportRefusal::NotBound)),
        None => {}
    }
    let n = poll_once(sql.exec(
        "UPDATE unit_import_move SET final = 1, move_ordinal = ?1 WHERE id = 1",
        &[int(ordinal)?],
    ))??;
    if n != 1 {
        return Err(decode("unit_import_move"));
    }
    Ok(Seal::Done {
        move_ordinal: ordinal,
        newly: true,
    })
}

/// The sealed import's `move_ordinal`, or `None` while it is not sealed.
pub fn sealed<S: Sql>(sql: &S) -> Result<Option<u64>> {
    let rows = poll_once(sql.query(
        "SELECT final, move_ordinal FROM unit_import_move WHERE id = 1",
        &[],
    ))??;
    match rows.first().map(|r| (&r[0], &r[1])) {
        None | Some((SqlValue::Int(0), _)) => Ok(None),
        Some((SqlValue::Int(1), SqlValue::Int(o))) => u64::try_from(*o)
            .map(Some)
            .map_err(|_| decode("unit_import_move move_ordinal")),
        Some(_) => Err(decode("unit_import_move final")),
    }
}

/// The `since_seq` of the entry the import filled (its first S), if an
/// import was ever bound to this unit.
pub fn import_since<S: Sql>(sql: &S) -> Result<Option<u64>> {
    let rows = poll_once(sql.query("SELECT since_seq FROM unit_import_move WHERE id = 1", &[]))??;
    match rows.first().and_then(|r| r.first()) {
        None => Ok(None),
        Some(SqlValue::Int(n)) => u64::try_from(*n)
            .map(Some)
            .map_err(|_| decode("unit_import_move since_seq")),
        Some(_) => Err(decode("unit_import_move since_seq")),
    }
}

/// Whether a `move` report has lifted this unit (the seal is used up).
pub fn move_lifted<S: Sql>(sql: &S) -> Result<bool> {
    let rows = poll_once(sql.query("SELECT move_lifted FROM unit_import_move WHERE id = 1", &[]))??;
    match rows.first().and_then(|r| r.first()) {
        None => Ok(false),
        Some(SqlValue::Int(n)) => Ok(*n == 1),
        Some(_) => Err(decode("unit_import_move move_lifted")),
    }
}

/// Uses the seal up: called in the `sync` that a `move` report lifted.
pub fn mark_move_lifted<S: Sql>(sql: &S, now: crate::types::UnixMs) -> Result<()> {
    let n = poll_once(sql.exec(
        "UPDATE unit_import_move SET move_lifted = 1, lifted_at = ?1 WHERE id = 1 AND final = 1",
        &[SqlValue::Int(now.0)],
    ))??;
    if n != 1 {
        return Err(decode("unit_import_move seal"));
    }
    Ok(())
}

/// The unit's time of the move's lift, once a `move` report lifted it.
pub fn move_lifted_at<S: Sql>(sql: &S) -> Result<Option<i64>> {
    let rows = poll_once(sql.query("SELECT lifted_at FROM unit_import_move WHERE id = 1", &[]))??;
    match rows.first().and_then(|r| r.first()) {
        None | Some(SqlValue::Null) => Ok(None),
        Some(SqlValue::Int(t)) => Ok(Some(*t)),
        Some(_) => Err(decode("unit_import_move lifted_at")),
    }
}

/// The newest tenant-0 head seq the import was bound to, if any.
pub fn seen_t0_seq<S: Sql>(sql: &S) -> Result<Option<u64>> {
    let rows = poll_once(sql.query("SELECT t0_seq FROM unit_import_move WHERE id = 1", &[]))??;
    match rows.first().and_then(|r| r.first()) {
        None => Ok(None),
        Some(SqlValue::Int(n)) => u64::try_from(*n)
            .map(Some)
            .map_err(|_| decode("unit_import_move t0_seq")),
        Some(_) => Err(decode("unit_import_move t0_seq")),
    }
}

/// Raises the newest tenant-0 head seq the unit has seen (never lowers
/// it). The row exists once the import is sealed.
pub fn see_t0_seq<S: Sql>(sql: &S, t0_seq: u64) -> Result<()> {
    poll_once(sql.exec(
        "UPDATE unit_import_move SET t0_seq = max(t0_seq, ?1) WHERE id = 1",
        &[int(t0_seq)?],
    ))??;
    Ok(())
}

/// The move's record as `ImportProgress` answers it (AM-47): `None`
/// when no import was ever bound to this unit (no `unit_import_move`
/// row).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoveRecord {
    /// The newest tenant-0 head seq a batch, the seal or a `move` report
    /// was bound to: a window's copy resumes only an import at or above
    /// its own first record (L3, AM-53).
    pub t0_seq: u64,
    /// The `since_seq` of the entry the import fills.
    pub since_seq: u64,
    /// A `move` report lifted this unit (the seal is used up).
    pub move_lifted: bool,
}

/// The move's record, if an import was ever bound to this unit.
pub fn move_record<S: Sql>(sql: &S) -> Result<Option<MoveRecord>> {
    let rows = poll_once(sql.query(
        "SELECT t0_seq, since_seq, move_lifted FROM unit_import_move WHERE id = 1",
        &[],
    ))??;
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    match (&r[0], &r[1], &r[2]) {
        (SqlValue::Int(t0), SqlValue::Int(since), SqlValue::Int(lifted))
            if *t0 >= 0 && *since >= 0 && (*lifted == 0 || *lifted == 1) =>
        {
            Ok(Some(MoveRecord {
                t0_seq: *t0 as u64,
                since_seq: *since as u64,
                move_lifted: *lifted == 1,
            }))
        }
        _ => Err(decode("unit_import_move")),
    }
}

/// Whether an import exists that no `move` report has lifted yet
/// (`unit_import_move` with `move_lifted = 0`). While it does, the unit
/// takes no undo bookmark (`restore_prepare`, AM-46) and runs no schema
/// migration ([`super::schema::migration_allowed`]).
pub fn unlifted_import<S: Sql>(sql: &S) -> Result<bool> {
    Ok(move_record(sql)?.is_some_and(|m| !m.move_lifted))
}

/// Every table's stored cursor and row count, by table name.
pub fn progress<S: Sql>(sql: &S) -> Result<Vec<(String, String, u64)>> {
    let rows = poll_once(sql.query(
        "SELECT tbl, cursor, rows FROM unit_import ORDER BY tbl",
        &[],
    ))??;
    rows.into_iter()
        .map(|r| match (&r[0], &r[1], &r[2]) {
            (SqlValue::Text(t), SqlValue::Text(c), SqlValue::Int(n)) if *n >= 0 => {
                Ok((t.clone(), c.clone(), *n as u64))
            }
            _ => Err(decode("unit_import row")),
        })
        .collect()
}

fn progress_of<S: Sql>(sql: &S, t: ImportTable) -> Result<Option<(String, u64)>> {
    let rows = poll_once(sql.query(
        "SELECT cursor, rows FROM unit_import WHERE tbl = ?1",
        &[SqlValue::Text(t.name().into())],
    ))??;
    match rows.into_iter().next() {
        None => Ok(None),
        Some(r) => match (&r[0], &r[1]) {
            (SqlValue::Text(c), SqlValue::Int(n)) if *n >= 0 => Ok(Some((c.clone(), *n as u64))),
            _ => Err(decode("unit_import row")),
        },
    }
}

/// The tenant-0 head only moves forward, and every batch fills the same
/// restore entry.
fn move_seq_ok<S: Sql>(sql: &S, since: u64, t0_seq: u64) -> Result<bool> {
    let rows = poll_once(sql.query(
        "SELECT t0_seq, since_seq FROM unit_import_move WHERE id = 1",
        &[],
    ))??;
    if let Some(r) = rows.first() {
        let (SqlValue::Int(seen), SqlValue::Int(s)) = (&r[0], &r[1]) else {
            return Err(decode("unit_import_move"));
        };
        if (t0_seq as i128) < i128::from(*seen) || i128::from(*s) != since as i128 {
            return Ok(false);
        }
    }
    poll_once(sql.exec(
        "INSERT INTO unit_import_move(id, t0_seq, since_seq) VALUES (1, ?1, ?2) \
         ON CONFLICT(id) DO UPDATE SET t0_seq = excluded.t0_seq",
        &[int(t0_seq)?, int(since)?],
    ))??;
    Ok(true)
}

/// The bound values of one row, or `None` for a row the table refuses
/// here.
fn params(t: ImportTable, row: &[ImportValue]) -> Result<Option<Vec<SqlValue>>> {
    let col = |name: &str| t.columns().iter().position(|c| *c == name).map(|i| &row[i]);
    // Every key value of its column's class: the unit never holds a key
    // that `export` cannot page after (a null, a blob, or the other class).
    let table = super::export::ExportTable::Data(t);
    if !table.is_key(&super::export::key_of(table, row)) {
        return Ok(None);
    }
    match t {
        // Leases are cleared before the window (P11); a leased row would
        // hand a job to a holder that no longer exists.
        ImportTable::Outbox => {
            let leased = |c| !matches!(col(c), Some(ImportValue::Null));
            if leased("lease_owner") || leased("lease_until") {
                return Ok(None);
            }
        }
        ImportTable::Extents => {
            let Some(ImportValue::Int(rev)) = col("plan_rev") else {
                return Ok(None);
            };
            let Ok(rev) = u32::try_from(*rev) else {
                return Ok(None);
            };
            if !crate::plan_rev::readable(rev) {
                return Ok(None);
            }
            let i = t
                .columns()
                .iter()
                .position(|c| *c == "plan_rev")
                .ok_or(BridgeError::Invalid("plan_rev column"))?;
            let mut out: Vec<SqlValue> = row.iter().map(ImportValue::sql).collect();
            out[i] = crate::plan_rev::bound(rev)?;
            return Ok(Some(out));
        }
        _ => {}
    }
    Ok(Some(row.iter().map(ImportValue::sql).collect()))
}

/// After the conflict-tolerant insert: the stored row equals the batch's.
fn generation_extent_is<S: Sql>(sql: &S, p: &[SqlValue]) -> Result<bool> {
    let rows = poll_once(sql.query(
        "SELECT count(*) FROM generation_extents WHERE generation_id = ?1 AND seq = ?2 \
           AND extent_id IS ?3 AND plain_offset IS ?4",
        p,
    ))??;
    Ok(matches!(
        rows.first().and_then(|r| r.first()),
        Some(SqlValue::Int(1))
    ))
}

fn int(n: u64) -> Result<SqlValue> {
    i64::try_from(n)
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("number out of range"))
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}

mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}
