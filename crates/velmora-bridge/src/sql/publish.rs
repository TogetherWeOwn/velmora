//! The set-based publish: the statements that give a generation its
//! extents, shared by CompleteMultipartUpload and a recovery replay.
//!
//! The placements of a generation travel as JSON text, one bound value
//! per statement: `[["<extent id>",<seq>,<plain offset>],...]`. A value
//! holds as many placements as the database takes in one statement
//! ([`SqlLimits`], read from the [`crate::ports::Sql`] adapter), so the
//! batch has one adopt statement per value instead of one per extent.
//! Everything else in the batch is unchanged: its guards, in their
//! order, decide whether what was adopted is the object.
//!
//! The statements are plain SQLite (`json_each`, `UPDATE ... FROM`).
//!
//! Join order and the unary `+` are part of the statement, not style.
//! The values are the outer loop (`CROSS JOIN`, and `FROM m` in the
//! update), and the `+` keeps the filters on `extents` from being used
//! as an index: the planner must find each extent by its primary key.
//! Driven from an index on the generation instead
//! (`extents_by_generation`, while it exists), the adopt scans the whole
//! value once per extent row. `tests/sql_publish.rs` asserts the plan.

use super::objects::{text, Stmt};
use crate::ports::{SqlLimits, SqlValue};
use crate::types::{BridgeError, BucketId, ExtentPlacement, GenerationId, Result, UploadId};

/// The placements of one statement as `m(extent_id, seq, off)`, read
/// from the value bound as `?2`.
macro_rules! placed {
    () => {
        "WITH m(extent_id, seq, off) AS (SELECT json_extract(value,'$[0]'), \
           json_extract(value,'$[1]'), json_extract(value,'$[2]') FROM json_each(?2)) "
    };
}

/// Adopts the staged extents of the value into generation `?1` of bucket
/// `?3`.
macro_rules! adopt {
    () => {
        concat!(
            placed!(),
            "UPDATE extents SET generation_id = ?1, seq = m.seq, plain_offset = m.off, \
               state = 'committed' FROM m \
              WHERE extents.id = m.extent_id AND +extents.bucket_id = ?3 \
                AND +extents.state = 'staged' AND +extents.generation_id IS NULL"
        )
    };
}

/// A replay adopts whatever staged extent of the bucket the record
/// names: its extents were put there, staged, from the same record.
const ADOPT_RECORD: &str = adopt!();

/// A Complete adopts an extent only if a part of upload `?4` names it.
const ADOPT_UPLOAD: &str = concat!(
    adopt!(),
    " AND (EXISTS (SELECT 1 FROM upload_parts \
                    WHERE extent_id = m.extent_id AND upload_id = ?4) \
           OR EXISTS (SELECT 1 FROM upload_part_extents \
                       WHERE extent_id = m.extent_id AND upload_id = ?4))"
);

/// References the extents of the value that another generation of the
/// bucket holds: the two share them through a copy. An extent this
/// generation adopted has its reference already (trigger
/// `generation_extents_on_adopt`) and does not match.
const REFERENCE_SHARED: &str = concat!(
    placed!(),
    "INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
     SELECT ?1, m.seq, e.id, m.off FROM m CROSS JOIN extents e ON e.id = m.extent_id \
      WHERE +e.bucket_id = ?3 AND +e.state = 'committed' AND +e.generation_id <> ?1"
);

/// Whose extents a generation takes.
#[derive(Clone, Copy)]
pub(super) enum Source<'a> {
    /// The parts of this upload, and nothing else.
    Upload(&'a UploadId),
    /// The extents a recovery record names, shared ones included.
    Record,
}

/// The placements as bound values: JSON arrays in `seq` order of the
/// slice, each within `limits`.
///
/// A value is closed when the next placement would take it past either
/// limit, so none is ever built above `limits.value_bytes`. A single
/// placement that does not fit a value is refused.
pub(super) fn placement_values(
    placements: &[ExtentPlacement],
    limits: SqlLimits,
) -> Result<Vec<String>> {
    const TOO_LARGE: BridgeError =
        BridgeError::Invalid("an extent placement does not fit one statement value");
    let rows = limits.set_rows.max(1);
    let mut values = Vec::with_capacity(placements.len() / rows + 1);
    let mut value = String::new();
    let mut held = 0usize;
    for p in placements {
        // `serde_json` escapes the id: it comes from a recovery record on
        // the replay path, and is text like any other there.
        let id = serde_json::to_string(p.extent_id.as_str())
            .map_err(|_| BridgeError::Invalid("an extent id that is not JSON text"))?;
        // Offsets are stored as SQLite integers; JSON carries no more.
        let offset = i64::try_from(p.plain_offset)
            .map_err(|_| BridgeError::Invalid("integer out of SQL range"))?;
        let entry = format!("[{id},{},{offset}]", p.seq);
        // The brackets of the value and the comma before this entry.
        if entry.len().saturating_add(2) > limits.value_bytes {
            return Err(TOO_LARGE);
        }
        let full = held == rows
            || value.len().saturating_add(entry.len()).saturating_add(2) > limits.value_bytes;
        if held > 0 && full {
            value.push(']');
            values.push(core::mem::take(&mut value));
            held = 0;
        }
        value.push(if held == 0 { '[' } else { ',' });
        value.push_str(&entry);
        held += 1;
    }
    if held > 0 {
        value.push(']');
        values.push(value);
    }
    Ok(values)
}

/// The statements that give generation `g` of `bucket` the extents of
/// `values` ([`placement_values`]): one per value for an upload, two per
/// value for a record. They follow the insert of the generation row and
/// come before the guards that count and measure what was taken.
///
/// Running them again changes nothing: an adopted extent is no longer
/// staged, and a reference that exists is ignored.
pub(super) fn adopt(
    g: &GenerationId,
    bucket: &BucketId,
    source: Source<'_>,
    values: &[String],
) -> Vec<Stmt> {
    let bound = |value: &String| {
        vec![
            text(g.as_str()),
            SqlValue::Text(value.clone()),
            text(bucket.as_str()),
        ]
    };
    let mut stmts = Vec::with_capacity(2 * values.len());
    for value in values {
        match source {
            Source::Upload(upload) => {
                let mut params = bound(value);
                params.push(text(upload.as_str()));
                stmts.push((ADOPT_UPLOAD, params));
            }
            Source::Record => {
                stmts.push((ADOPT_RECORD, bound(value)));
                stmts.push((REFERENCE_SHARED, bound(value)));
            }
        }
    }
    stmts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ExtentId;

    fn placements(n: u32) -> Vec<ExtentPlacement> {
        (0..n)
            .map(|i| ExtentPlacement {
                extent_id: ExtentId::new(format!("x_{i:026x}")),
                seq: i,
                plain_offset: u64::from(i) * (16 << 20),
            })
            .collect()
    }

    /// The values, parsed and put end to end.
    fn parsed(values: &[String]) -> Vec<(String, u32, u64)> {
        values
            .iter()
            .flat_map(|v| serde_json::from_str::<Vec<(String, u32, u64)>>(v).unwrap())
            .collect()
    }

    fn expected(placements: &[ExtentPlacement]) -> Vec<(String, u32, u64)> {
        placements
            .iter()
            .map(|p| (p.extent_id.as_str().to_owned(), p.seq, p.plain_offset))
            .collect()
    }

    #[test]
    fn values_hold_every_placement_once_and_in_order() {
        let all = placements(250);
        let limits = SqlLimits {
            value_bytes: 1_900_000,
            set_rows: 100,
            result_bytes: SqlLimits::D1.result_bytes,
        };
        let values = placement_values(&all, limits).unwrap();
        assert_eq!(values.len(), 3);
        let rows: Vec<usize> = values
            .iter()
            .map(|v| {
                serde_json::from_str::<Vec<serde_json::Value>>(v)
                    .unwrap()
                    .len()
            })
            .collect();
        assert_eq!(rows, [100, 100, 50]);
        assert_eq!(parsed(&values), expected(&all));
        // Nothing to place is no value, and so no statement.
        assert!(placement_values(&[], limits).unwrap().is_empty());
        // A row limit of 0 is read as 1, never as "no rows".
        let one = SqlLimits {
            set_rows: 0,
            ..limits
        };
        assert_eq!(placement_values(&all[..3], one).unwrap().len(), 3);
    }

    #[test]
    fn no_value_is_built_above_the_byte_limit() {
        let all = placements(1_000);
        let whole = placement_values(&all, SqlLimits::D1).unwrap();
        assert_eq!(whole.len(), 1);
        let size = whole[0].len();
        // At the border: the limit is the size of the whole list, then
        // one byte less.
        let exact = SqlLimits {
            value_bytes: size,
            set_rows: 25_000,
            result_bytes: SqlLimits::D1.result_bytes,
        };
        let values = placement_values(&all, exact).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].len(), size);
        let short = SqlLimits {
            value_bytes: size - 1,
            ..exact
        };
        let values = placement_values(&all, short).unwrap();
        assert_eq!(values.len(), 2);
        assert!(values.iter().all(|v| v.len() < size));
        assert_eq!(parsed(&values), expected(&all));
        // Every limit below it holds as well.
        for value_bytes in [64, 65, 100, 1_000, 4_096, 50_000] {
            let limits = SqlLimits {
                value_bytes,
                set_rows: 25_000,
                result_bytes: SqlLimits::D1.result_bytes,
            };
            let values = placement_values(&all, limits).unwrap();
            assert!(
                values.iter().all(|v| v.len() <= value_bytes),
                "{value_bytes}"
            );
            assert_eq!(parsed(&values), expected(&all), "{value_bytes}");
        }
    }

    #[test]
    fn the_d1_limits_keep_a_value_under_what_d1_takes() {
        // The largest object standard clients can send, at 8 MiB slices.
        let all = placements(131_072);
        let values = placement_values(&all, SqlLimits::D1).unwrap();
        assert_eq!(values.len(), 6);
        assert!(values.iter().all(|v| v.len() <= SqlLimits::D1.value_bytes));
    }

    #[test]
    fn a_placement_that_fits_no_value_is_refused() {
        let all = placements(2);
        let entry = placement_values(&all[..1], SqlLimits::D1).unwrap()[0].len();
        let limits = SqlLimits {
            value_bytes: entry - 1,
            set_rows: 25_000,
            result_bytes: SqlLimits::D1.result_bytes,
        };
        assert!(matches!(
            placement_values(&all, limits),
            Err(BridgeError::Invalid(_))
        ));
        let limits = SqlLimits {
            value_bytes: entry,
            ..limits
        };
        assert_eq!(placement_values(&all[..1], limits).unwrap().len(), 1);
        // An offset SQLite cannot hold is refused, not rounded.
        let mut far = placements(1);
        far[0].plain_offset = u64::MAX;
        assert!(placement_values(&far, SqlLimits::D1).is_err());
    }

    #[test]
    fn an_id_is_carried_as_json_text_whatever_it_holds() {
        let odd = vec![ExtentPlacement {
            extent_id: ExtentId::new("x_\"],[\"y\\\u{1}".to_owned()),
            seq: 0,
            plain_offset: 0,
        }];
        let values = placement_values(&odd, SqlLimits::D1).unwrap();
        assert_eq!(parsed(&values), expected(&odd));
    }

    #[test]
    fn an_upload_takes_one_statement_a_value_and_a_record_two() {
        let (g, b, u) = (
            GenerationId::new("g_1".to_owned()),
            BucketId::new("b_1".to_owned()),
            UploadId::new("u_1".to_owned()),
        );
        let values = vec!["[]".to_owned(), "[]".to_owned(), "[]".to_owned()];
        let live = adopt(&g, &b, Source::Upload(&u), &values);
        assert_eq!(live.len(), 3);
        assert!(live
            .iter()
            .all(|(sql, p)| *sql == ADOPT_UPLOAD && p.len() == 4));
        let replay = adopt(&g, &b, Source::Record, &values);
        assert_eq!(replay.len(), 6);
        for pair in replay.chunks(2) {
            assert_eq!((pair[0].0, pair[1].0), (ADOPT_RECORD, REFERENCE_SHARED));
        }
    }
}
