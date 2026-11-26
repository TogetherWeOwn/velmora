//! Declared result columns of the write-routed statements that return rows.
//!
//! The one-message transport reads replies as text, and the driver's
//! simple-query API does not keep the column type OIDs. So each such
//! statement declares its columns here, keyed by its normalized text, and
//! every cell is decoded exactly as `value::decode` decodes the binary
//! value of that type. A CI test checks each declaration against the OIDs
//! PostgreSQL's Describe returns, and that every write-routed manifest
//! statement with result columns is declared. A write `query` of an
//! undeclared statement is refused before any I/O.

use crate::{BridgeError, Result, Row, SqlValue};

use super::error;

/// The result types `value::decode` accepts.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultType {
    Int2,
    Int4,
    Int8,
    Bool,
    Numeric,
    Text,
    Varchar,
    Name,
    Bytea,
}

impl ResultType {
    /// The PostgreSQL type OID.
    pub fn oid(self) -> u32 {
        match self {
            Self::Int2 => 21,
            Self::Int4 => 23,
            Self::Int8 => 20,
            Self::Bool => 16,
            Self::Numeric => 1700,
            Self::Text => 25,
            Self::Varchar => 1043,
            Self::Name => 19,
            Self::Bytea => 17,
        }
    }
}

#[doc(hidden)]
pub struct Declared {
    /// The normalized statement text (`normalize_statement`).
    pub sql: &'static str,
    /// Column names and types, in order.
    pub columns: &'static [(&'static str, ResultType)],
}

use ResultType::*;

/// Every write-routed statement that returns rows. CI keeps this list
/// equal to the statement manifests (`tests/pg_statements.rs`).
#[doc(hidden)]
pub static WRITE_RESULTS: &[Declared] = &[
    Declared {
        sql: "UPDATE outbox SET lease_token = lease_token + 1, lease_owner = $4, lease_until = $5, attempts = attempts + 1, updated_at = $6, sent_at = NULL WHERE extent_id = $1 AND generation_id = $2 AND stage = $3 AND next_at <= $6 AND (lease_until IS NULL OR lease_until < $6) RETURNING lease_token, attempts, cursor",
        columns: &[("lease_token", Int8), ("attempts", Int8), ("cursor", Int8)],
    },
    Declared {
        sql: "UPDATE outbox SET stage = 'dead', updated_at = $2 WHERE attempts > 50 AND stage IN ('post', 'verify', 'release') AND attempts > $1 AND (lease_until IS NULL OR lease_until < $2) RETURNING 1",
        columns: &[("?column?", Int4)],
    },
    Declared {
        sql: "UPDATE outbox SET stage = 'dead', updated_at = $2 WHERE stage IN ('post', 'verify', 'release') AND attempts > $1 AND (lease_until IS NULL OR lease_until < $2) RETURNING 1",
        columns: &[("?column?", Int4)],
    },
    Declared {
        sql: "UPDATE outbox SET stage = 'verify', next_at = $1, cursor = 0, attempts = 0, last_error = NULL, updated_at = $1, sent_at = NULL, lease_token = lease_token + 1, lease_owner = NULL, lease_until = NULL WHERE extent_id = ANY (ARRAY(SELECT jsonb_array_elements_text($4::jsonb))) AND CASE WHEN stage = 'done' THEN 1 = (SELECT 1 FROM extents e WHERE e.id = outbox.extent_id AND e.safety_state = 'held' AND 1 = (SELECT 1 FROM generation_extents lr JOIN generations lg ON lg.id = lr.generation_id WHERE lr.extent_id = e.id AND lg.state = 'live' LIMIT 1) AND (SELECT COUNT(*) FROM verifications v WHERE v.extent_id = e.id AND v.backbone IN (SELECT value FROM jsonb_array_elements_text($2::jsonb) AS j(value)) AND v.plan_rev = e.plan_rev AND v.verified_at = (SELECT MAX(w.verified_at) FROM verifications w WHERE w.extent_id = v.extent_id AND w.backbone = v.backbone AND w.plan_rev = e.plan_rev) AND (v.result = 'ok' AND (CASE v.kind WHEN 'stat' THEN v.articles_present ELSE v.articles_ok END) = v.articles_total AND v.articles_total = COALESCE((e.article_count + COALESCE(e.parity_count, 0)), -1))) < $3) ELSE FALSE END RETURNING 1",
        columns: &[("?column?", Int4)],
    },
    Declared {
        sql: "UPDATE outbox SET stage = CASE (SELECT e.safety_state FROM extents e WHERE e.id = outbox.extent_id) WHEN 'held' THEN 'post' WHEN 'releasing' THEN 'release' ELSE 'done' END, attempts = 0, cursor = 0, last_error = NULL, next_at = $1, updated_at = $1, sent_at = NULL, lease_token = lease_token + 1, lease_owner = NULL, lease_until = NULL WHERE seq > $2 AND seq <= $3 AND stage = 'cancelled' AND EXISTS (SELECT 1 FROM generation_extents lr JOIN generations lg ON lg.id = lr.generation_id WHERE lr.extent_id = outbox.extent_id AND lg.state = 'live') RETURNING 1",
        columns: &[("?column?", Int4)],
    },
    Declared {
        sql: "UPDATE provider_permits SET token = token + 1, holder = $2, lease_until = $3,                    pool = NULL, background = 0                  WHERE provider_id = $1 AND slot = (SELECT slot FROM provider_permits                    WHERE provider_id = $1 AND slot < $4 AND lease_until < $5                    ORDER BY slot LIMIT 1)                  RETURNING slot, token",
        columns: &[("slot", Int8), ("token", Int8)],
    },
    Declared {
        sql: "UPDATE provider_permits SET token = token + 1, holder = $2, lease_until = $3, pool = $6, background = $9 WHERE provider_id = $1 AND slot = (SELECT slot FROM provider_permits WHERE provider_id = $1 AND slot < $4 AND lease_until < $5 ORDER BY slot ASC LIMIT 1) AND ($6::text IS NULL OR (SELECT COUNT(*) FROM provider_permits WHERE pool = $6 AND lease_until >= $5) < $7) AND ($8::bigint IS NULL OR ((EXISTS (SELECT 1 FROM provider_permits WHERE provider_id = $1 AND holder = $2 AND lease_until >= $5) OR (SELECT COUNT(DISTINCT holder) FROM provider_permits WHERE provider_id = $1 AND lease_until >= $5) < $8) AND ($9 = 0 OR EXISTS (SELECT 1 FROM provider_permits WHERE provider_id = $1 AND holder = $2 AND lease_until >= $5 AND background = 1) OR (SELECT COUNT(DISTINCT holder) FROM provider_permits WHERE provider_id = $1 AND lease_until >= $5 AND background = 1) < $10))) RETURNING slot, token",
        columns: &[("slot", Int8), ("token", Int8)],
    },
    Declared {
        sql: "UPDATE provider_permits SET token = token + 1, holder = $2, lease_until = $3, pool = $6, background = $9 WHERE provider_id = $1 AND slot = (SELECT slot FROM provider_permits WHERE provider_id = $1 AND slot < $4 AND lease_until < $5 ORDER BY slot DESC LIMIT 1) AND ($6::text IS NULL OR (SELECT COUNT(*) FROM provider_permits WHERE pool = $6 AND lease_until >= $5) < $7) AND ($8::bigint IS NULL OR ((EXISTS (SELECT 1 FROM provider_permits WHERE provider_id = $1 AND holder = $2 AND lease_until >= $5) OR (SELECT COUNT(DISTINCT holder) FROM provider_permits WHERE provider_id = $1 AND lease_until >= $5) < $8) AND ($9 = 0 OR EXISTS (SELECT 1 FROM provider_permits WHERE provider_id = $1 AND holder = $2 AND lease_until >= $5 AND background = 1) OR (SELECT COUNT(DISTINCT holder) FROM provider_permits WHERE provider_id = $1 AND lease_until >= $5 AND background = 1) < $10))) RETURNING slot, token",
        columns: &[("slot", Int8), ("token", Int8)],
    },
];

pub(super) fn declared(sql: &str) -> Option<&'static Declared> {
    WRITE_RESULTS.iter().find(|d| d.sql == sql)
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// An optional `-` and decimal digits only.
fn integer(s: &str) -> Option<i64> {
    let body = s.strip_prefix('-').unwrap_or(s);
    if !digits(body) {
        return None;
    }
    s.parse().ok()
}

/// Integral NUMERIC in the i64 range, as `value::numeric` accepts it: a
/// zero fraction (`5.00`) passes; a fraction, `NaN`, `Infinity` and
/// overflow fail.
fn numeric(s: &str) -> Option<i64> {
    let (negative, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (whole, fraction) = match body.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (body, None),
    };
    if !digits(whole) || fraction.is_some_and(|f| !digits(f) || f.bytes().any(|b| b != b'0')) {
        return None;
    }
    let magnitude: u64 = whole.parse().ok()?;
    if !negative {
        return i64::try_from(magnitude).ok();
    }
    if magnitude == 1 << 63 {
        return Some(i64::MIN);
    }
    i64::try_from(magnitude).ok().map(|v| -v)
}

/// `\x` and an even number of hex digits, either case.
fn bytea(s: &str) -> Option<Vec<u8>> {
    let hex = s.strip_prefix("\\x")?.as_bytes();
    if hex.len() % 2 != 0 {
        return None;
    }
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let (pairs, rest) = hex.as_chunks::<2>();
    debug_assert!(rest.is_empty());
    pairs
        .iter()
        .map(|&[hi, lo]| Some(nibble(hi)? << 4 | nibble(lo)?))
        .collect()
}

pub(super) fn cell(ty: ResultType, text: Option<&str>) -> Result<SqlValue> {
    let Some(text) = text else {
        return Ok(SqlValue::Null);
    };
    let value = match ty {
        Int2 => integer(text)
            .filter(|v| i16::try_from(*v).is_ok())
            .map(SqlValue::Int),
        Int4 => integer(text)
            .filter(|v| i32::try_from(*v).is_ok())
            .map(SqlValue::Int),
        Int8 => integer(text).map(SqlValue::Int),
        Bool => match text {
            "t" => Some(SqlValue::Int(1)),
            "f" => Some(SqlValue::Int(0)),
            _ => None,
        },
        Numeric => numeric(text).map(SqlValue::Int),
        Text | Varchar | Name => Some(SqlValue::Text(text.to_owned())),
        Bytea => bytea(text).map(SqlValue::Blob),
    };
    value.ok_or_else(error::shape)
}

/// Decode one statement's text rows: the column count and names must
/// equal the declaration, and every cell must parse as its declared type.
pub(super) fn decode(
    declared: &Declared,
    columns: Option<&[tokio_postgres::SimpleColumn]>,
    rows: &[tokio_postgres::SimpleQueryRow],
) -> Result<Vec<Row>> {
    let Some(columns) = columns else {
        // No RowDescription: a statement without result columns.
        return if rows.is_empty() && declared.columns.is_empty() {
            Ok(Vec::new())
        } else {
            Err(error::shape())
        };
    };
    if columns.len() != declared.columns.len()
        || columns
            .iter()
            .zip(declared.columns)
            .any(|(got, (name, _))| got.name() != *name)
    {
        return Err(error::shape());
    }
    rows.iter()
        .map(|row| {
            if row.len() != declared.columns.len() {
                return Err(error::shape());
            }
            declared
                .columns
                .iter()
                .enumerate()
                .map(|(i, (_, ty))| cell(*ty, row.try_get(i).map_err(|_| error::shape())?))
                .collect()
        })
        .collect()
}

pub(super) fn undeclared() -> BridgeError {
    BridgeError::Sql("pg: undeclared write result".into())
}
