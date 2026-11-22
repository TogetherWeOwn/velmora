use velmora_bridge::unit::poll_once;
use velmora_bridge::{Sql, SqlValue};

/// Supplies placements for tests that seed bucket rows directly and do not
/// change placements in the tenant head.
pub fn fixture_placements(sql: &impl Sql) -> Vec<String> {
    poll_once(sql.query(
        "SELECT b.id FROM buckets b LEFT JOIN unit_bucket_closing c ON c.bucket_id = b.id \
         WHERE c.bucket_id IS NULL ORDER BY b.id",
        &[],
    ))
    .unwrap()
    .unwrap()
    .into_iter()
    .map(|row| match row.as_slice() {
        [SqlValue::Text(id)] => id.clone(),
        _ => panic!("expected one bucket id"),
    })
    .collect()
}
