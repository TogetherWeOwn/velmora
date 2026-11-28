//! Selects the SQL adapter for both the Worker and the PermitGate object.

use velmora_bridge::pg::{is_postgres_read_only, is_read_only, PgConfig, PgSql, WriteTx};
use velmora_bridge::{BridgeError, Dialect, Result, Row, Sql, SqlValue};
use worker::{js_sys::Reflect, wasm_bindgen::JsValue, Env};

use crate::d1::D1Sql;
use crate::pgsql::HyperdriveConnect;

#[cfg(feature = "pg-test-unlocked")]
compile_error!("pg-test-unlocked must not be enabled in the S3 Worker");
// Also reject a dependency feature enabled via a workspace build.
const _: () = assert!(
    !velmora_bridge::pg::TEST_UNLOCKED,
    "pg-test-unlocked must not be enabled in the S3 Worker"
);

// Direct-origin budget for a 25-connection instance with 3
// superuser-reserved connections. The drill is absent at production rollout.
const PG_WRITE_LIMIT: u16 = 5; // Hyperdrive minimum
const PG_READ_LIMIT: u16 = 8;
const PG_DRILL_LIMIT: u16 = 5; // Hyperdrive minimum
const PG_OPS_RESERVE: u16 = 4;
const PG_UNASSIGNED_MIN: u16 = 3;

/// Checks the source budget only; cutover deploy preflight must check the
/// actual Hyperdrive configurations and origin capacity against this budget.
const fn connection_budget_ok(max_connections: u16, superuser_reserved: u16, drill: u16) -> bool {
    let usable = max_connections.saturating_sub(superuser_reserved);
    let pooled = PG_WRITE_LIMIT + PG_READ_LIMIT + drill;
    pooled + PG_UNASSIGNED_MIN <= usable && pooled + PG_OPS_RESERVE <= usable
}
const _: () = assert!(connection_budget_ok(25, 3, PG_DRILL_LIMIT));
const _: () = assert!(connection_budget_ok(25, 3, 0));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    D1,
    D1Frozen,
    Pg,
    PgFrozen,
}

impl Backend {
    fn from_env(env: &Env) -> core::result::Result<Self, &'static str> {
        Self::parse(optional_text(env, "CATALOG_BACKEND", "invalid CATALOG_BACKEND")?.as_deref())
    }

    fn is_frozen(self) -> bool {
        matches!(self, Self::D1Frozen | Self::PgFrozen)
    }

    fn parse(value: Option<&str>) -> core::result::Result<Self, &'static str> {
        match value {
            None | Some("d1") => Ok(Self::D1),
            Some("d1-frozen") => Ok(Self::D1Frozen),
            Some("pg") => Ok(Self::Pg),
            Some("pg-frozen") => Ok(Self::PgFrozen),
            _ => Err("invalid CATALOG_BACKEND"),
        }
    }
}

fn optional_text(
    env: &Env,
    name: &str,
    invalid: &'static str,
) -> core::result::Result<Option<String>, &'static str> {
    let name = JsValue::from_str(name);
    if !Reflect::has(env, &name).map_err(|_| invalid)? {
        return Ok(None);
    }
    Reflect::get(env, &name)
        .map_err(|_| invalid)?
        .as_string()
        .map(Some)
        .ok_or(invalid)
}

/// `SCRUB=on` needs a PostgreSQL catalogue, and with it
/// `D1_ROLLBACK_RETIRED=1`.
///
/// The frozen D1 catalogue has none of the scrub's schema (it ships as
/// PostgreSQL stages only), so on D1 the Worker refuses `SCRUB=on`; with
/// it off nothing reads the scrub's tables or columns.
///
/// A scrub repair moves a released extent of any age back to `held` and
/// writes its repair only to the catalogue it runs on. A rollback to the
/// frozen D1 replays only extents created after the cutover, so it would
/// bring such an extent back as released, counted on a backbone that
/// lacks it.
/// The setting says the frozen D1 is no longer a rollback target; until
/// then the Worker refuses this configuration.
pub fn scrub_backend_allowed(
    postgres: bool,
    scrub: bool,
    retired: Option<&str>,
) -> core::result::Result<(), &'static str> {
    let retired = match retired.map(str::trim) {
        None | Some("") | Some("0") => false,
        Some("1") => true,
        Some(_) => return Err("invalid D1_ROLLBACK_RETIRED"),
    };
    if scrub && !postgres {
        return Err("SCRUB needs the PostgreSQL catalogue");
    }
    if scrub && !retired {
        return Err("SCRUB on PostgreSQL needs D1_ROLLBACK_RETIRED=1");
    }
    Ok(())
}

/// One line per write transaction over the single-Sync size bound, which
/// then goes one Sync per statement. No SQL and no values.
fn log_oversize(statements: usize) {
    worker::console_warn!(
        "pg: oversize write transaction sent one Sync per statement ({statements} statements)"
    );
}

pub enum CatalogSql {
    D1(D1Sql),
    D1Frozen(D1Sql),
    Pg(PgSql<HyperdriveConnect>),
    PgFrozen(PgSql<HyperdriveConnect>),
}

impl CatalogSql {
    pub fn from_env(env: &Env) -> core::result::Result<Self, &'static str> {
        let backend = Backend::from_env(env)?;
        match backend {
            Backend::D1 | Backend::D1Frozen => Self::d1_from_env(env, backend.is_frozen()),
            Backend::Pg | Backend::PgFrozen => {
                let config = PgConfig {
                    write_tx: WriteTx::parse(
                        optional_text(env, "PG_WRITE_TX", "invalid PG_WRITE_TX")?.as_deref(),
                    )?,
                    on_oversize: Some(log_oversize),
                    ..PgConfig::default()
                };
                let writer = HyperdriveConnect::new(
                    env.hyperdrive("CATALOG_PG_W")
                        .map_err(|_| "missing binding CATALOG_PG_W")?,
                );
                let reader = HyperdriveConnect::new(
                    env.hyperdrive("CATALOG_PG_R")
                        .map_err(|_| "missing binding CATALOG_PG_R")?,
                );
                let pg = PgSql::new(writer, reader, config);
                Ok(if backend.is_frozen() {
                    Self::PgFrozen(pg)
                } else {
                    Self::Pg(pg)
                })
            }
        }
    }

    /// Recovery telemetry still uses D1's SQL and binding, regardless of the
    /// primary catalogue backend. Apply the same freeze policy to it.
    pub fn recovery_log_from_env(env: &Env) -> core::result::Result<Self, &'static str> {
        Self::d1_from_env(env, Backend::from_env(env)?.is_frozen())
    }

    fn d1_from_env(env: &Env, frozen: bool) -> core::result::Result<Self, &'static str> {
        let db = D1Sql::new(env.d1("CATALOG").map_err(|_| "missing binding CATALOG")?);
        Ok(if frozen {
            Self::D1Frozen(db)
        } else {
            Self::D1(db)
        })
    }

    fn reject_mutation(&self, query: Option<&str>) -> Result<()> {
        let allowed = match self {
            Self::D1(_) | Self::Pg(_) => true,
            Self::D1Frozen(_) => query.is_some_and(is_read_only),
            Self::PgFrozen(_) => query.is_some_and(is_postgres_read_only),
        };
        if allowed {
            Ok(())
        } else {
            Err(BridgeError::Sql("catalog: frozen".into()))
        }
    }
}

impl Sql for CatalogSql {
    fn supports_bucket_cors(&self) -> bool {
        matches!(self, Self::Pg(_) | Self::PgFrozen(_))
    }

    fn is_frozen(&self) -> bool {
        matches!(self, Self::D1Frozen(_) | Self::PgFrozen(_))
    }

    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.reject_mutation(Some(sql))?;
        match self {
            Self::D1(db) | Self::D1Frozen(db) => db.query(sql, params).await,
            Self::Pg(db) | Self::PgFrozen(db) => db.query(sql, params).await,
        }
    }

    async fn query_after_refusal(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.reject_mutation(Some(sql))?;
        match self {
            Self::D1(db) | Self::D1Frozen(db) => db.query_after_refusal(sql, params).await,
            Self::Pg(db) | Self::PgFrozen(db) => db.query_after_refusal(sql, params).await,
        }
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.reject_mutation(None)?;
        match self {
            Self::D1(db) | Self::D1Frozen(db) => db.exec(sql, params).await,
            Self::Pg(db) | Self::PgFrozen(db) => db.exec(sql, params).await,
        }
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        self.reject_mutation(None)?;
        match self {
            Self::D1(db) | Self::D1Frozen(db) => db.batch(stmts).await,
            Self::Pg(db) | Self::PgFrozen(db) => db.batch(stmts).await,
        }
    }

    fn dialect(&self) -> Dialect {
        match self {
            Self::D1(_) | Self::D1Frozen(_) => Dialect::Sqlite,
            Self::Pg(_) | Self::PgFrozen(_) => Dialect::Postgres,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_on_postgres_waits_for_the_d1_rollback_target_to_retire() {
        let refused = Err("SCRUB on PostgreSQL needs D1_ROLLBACK_RETIRED=1");
        assert_eq!(scrub_backend_allowed(true, true, None), refused);
        assert_eq!(scrub_backend_allowed(true, true, Some("0")), refused);
        assert_eq!(scrub_backend_allowed(true, true, Some("1")), Ok(()));
        assert_eq!(scrub_backend_allowed(true, false, None), Ok(()));
        let d1 = Err("SCRUB needs the PostgreSQL catalogue");
        assert_eq!(scrub_backend_allowed(false, true, None), d1);
        assert_eq!(scrub_backend_allowed(false, true, Some("1")), d1);
        assert_eq!(scrub_backend_allowed(false, false, None), Ok(()));
        assert_eq!(
            scrub_backend_allowed(false, false, Some("yes")),
            Err("invalid D1_ROLLBACK_RETIRED")
        );
    }

    #[test]
    fn backend_defaults_to_d1_and_refuses_typos() {
        assert_eq!(Backend::parse(None), Ok(Backend::D1));
        assert_eq!(Backend::parse(Some("d1-frozen")), Ok(Backend::D1Frozen));
        assert_eq!(Backend::parse(Some("pg")), Ok(Backend::Pg));
        assert_eq!(Backend::parse(Some("pg-frozen")), Ok(Backend::PgFrozen));
        assert_eq!(
            Backend::parse(Some("postgres")),
            Err("invalid CATALOG_BACKEND")
        );
        assert_eq!(WriteTx::parse(None), Ok(WriteTx::SingleSync));
        assert_eq!(WriteTx::parse(Some("single-sync")), Ok(WriteTx::SingleSync));
        assert_eq!(WriteTx::parse(Some("pipeline")), Ok(WriteTx::Pipeline));
        // The sequential transport is gone; its old switch values are typos.
        for old in ["0", "1", "sequential", "message", "SingleSync"] {
            assert_eq!(WriteTx::parse(Some(old)), Err("invalid PG_WRITE_TX"));
        }
    }

    #[test]
    fn only_frozen_backends_freeze_recovery_telemetry() {
        for (backend, frozen) in [
            (None, false),
            (Some("d1"), false),
            (Some("d1-frozen"), true),
            (Some("pg"), false),
            (Some("pg-frozen"), true),
        ] {
            assert_eq!(Backend::parse(backend).unwrap().is_frozen(), frozen);
        }
    }

    #[test]
    fn direct_origin_budget_keeps_ops_capacity() {
        assert!(connection_budget_ok(25, 3, PG_DRILL_LIMIT));
        assert!(!connection_budget_ok(24, 3, PG_DRILL_LIMIT));
        assert!(!connection_budget_ok(25, 3, 6));
        assert!(connection_budget_ok(25, 3, 0));
    }
}
