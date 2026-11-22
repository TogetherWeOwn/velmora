//! The schema a unit is born with: today's catalogue schema, and the
//! unit's own tables after it.
//!
//! [`CATALOGUE`] is every migration of the D1 catalogue, in order, from
//! `workers/s3-bridge/migrations/` (a test holds that the list is the
//! whole directory). [`UNIT`] is the unit's own, from `migrations/` here.
//! A unit applies both at birth, in one transaction, and records
//! [`SCHEMA_VERSION`] in its certificate.

/// Every catalogue migration, in order.
pub const CATALOGUE: &[&str] = &[
    include_str!("../../../../workers/s3-bridge/migrations/0001_init.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0002_provider_health.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0003_extents_held.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0004_hot_tier.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0005_generation_extents.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0006_permit_class.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0007_key_floors.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0008_restore_state.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0009_article_yenc_name.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0010_rollback_stamp.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0011_write_intents.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0012_provider_health_reason.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0013_verification_kind.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0014_article_reposted_at.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0015_outbox_sent_at.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0016_packed_plan.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0017_packed_plan_rows.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0018_upload_part_extents.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0019_verify_mode.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0020_usage_counters.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0021_ingest_indexes.sql"),
    include_str!("../../../../workers/s3-bridge/migrations/0022_parity.sql"),
];

/// The unit's own migrations, in order.
pub const UNIT: &[&str] = &[
    include_str!("migrations/u0001_identity.sql"),
    include_str!("migrations/u0003_keys_import.sql"),
    include_str!("migrations/u0004_restore.sql"),
    include_str!("migrations/u0005_move_lift.sql"),
    include_str!("migrations/u0006_key_scheme.sql"),
    include_str!("migrations/u0007_reservations.sql"),
    include_str!("migrations/u0008_move_lift_time.sql"),
];

/// The schema a token must name: every migration a unit applies.
pub const SCHEMA_VERSION: u32 = (CATALOGUE.len() + UNIT.len()) as u32;

/// The migrations in the order a birth applies them.
pub fn all() -> impl Iterator<Item = &'static str> {
    CATALOGUE.iter().chain(UNIT.iter()).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_list_is_the_whole_migrations_directory_in_order() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../workers/s3-bridge/migrations"
        );
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".sql"))
            .collect();
        names.sort();
        assert_eq!(
            names.len(),
            CATALOGUE.len(),
            "a migration is missing from the unit's list"
        );
        for (name, text) in names.iter().zip(CATALOGUE) {
            let on_disk = std::fs::read_to_string(format!("{dir}/{name}")).unwrap();
            assert_eq!(&on_disk, text, "{name} is not in its place");
        }
    }

    #[test]
    fn the_unit_list_is_the_whole_unit_migrations_directory_in_order() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/unit/migrations");
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".sql"))
            .collect();
        names.sort();
        assert_eq!(
            names.len(),
            UNIT.len(),
            "a unit migration is missing from the list"
        );
        for (name, text) in names.iter().zip(UNIT) {
            let on_disk = std::fs::read_to_string(format!("{dir}/{name}")).unwrap();
            assert_eq!(&on_disk, text, "{name} is not in its place");
        }
    }

    #[test]
    fn the_version_counts_every_migration() {
        assert_eq!(SCHEMA_VERSION as usize, all().count());
    }
}
