//! Selects the SQL adapter for both the Worker and the PermitGate object.

use velmora_bridge::pg::{is_postgres_read_only, is_read_only, PgConfig, PgSql};
use velmora_bridge::{BridgeError, Dialect, Result, Row, Sql, SqlValue};
use worker::Env;

use crate::d1::D1Sql;
use crate::pgsql::HyperdriveConnect;

#[cfg(feature = "pg-test-unlocked")]
compile_error!("pg-test-unlocked must not be enabled in the S3 Worker");
// Also reject a dependency feature enabled via a workspace build.
const _: () = assert!(
    !velmora_bridge::pg::TEST_UNLOCKED,
    "pg-test-unlocked must not be enabled in the S3 Worker"
);

// Fallback direct-origin budget for a 25-connection instance with 3
// superuser-reserved connections. The drill is absent at production rollout.
const PG_WRITE_LIMIT: u16 = 5; // Hyperdrive minimum
const PG_READ_LIMIT: u16 = 8;
const PG_DRILL_LIMIT: u16 = 5; // Hyperdrive minimum
const PG_OPS_RESERVE: u16 = 4;
const PG_UNASSIGNED_MIN: u16 = 3;

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

fn pipeline(value: Option<&str>) -> core::result::Result<bool, &'static str> {
    match value {
        None | Some("1") => Ok(true),
        Some("0") => Ok(false),
        _ => Err("invalid PG_PIPELINE"),
    }
}

pub enum CatalogSql {
    D1(D1Sql),
    D1Frozen(D1Sql),
    Pg(PgSql<HyperdriveConnect>),
    PgFrozen(PgSql<HyperdriveConnect>),
}

impl CatalogSql {
    pub fn from_env(env: &Env) -> core::result::Result<Self, &'static str> {
        let var = |name| env.var(name).ok().map(|v| v.to_string());
        let backend = Backend::parse(var("CATALOG_BACKEND").as_deref())?;
        match backend {
            Backend::D1 | Backend::D1Frozen => {
                let d1 = D1Sql::new(env.d1("CATALOG").map_err(|_| "missing binding CATALOG")?);
                Ok(if backend == Backend::D1 {
                    Self::D1(d1)
                } else {
                    Self::D1Frozen(d1)
                })
            }
            Backend::Pg | Backend::PgFrozen => {
                let config = PgConfig {
                    pipeline: pipeline(var("PG_PIPELINE").as_deref())?,
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
                Ok(if backend == Backend::Pg {
                    Self::Pg(pg)
                } else {
                    Self::PgFrozen(pg)
                })
            }
        }
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
    fn backend_defaults_to_d1_and_refuses_typos() {
        assert_eq!(Backend::parse(None), Ok(Backend::D1));
        assert_eq!(Backend::parse(Some("d1-frozen")), Ok(Backend::D1Frozen));
        assert_eq!(Backend::parse(Some("pg")), Ok(Backend::Pg));
        assert_eq!(Backend::parse(Some("pg-frozen")), Ok(Backend::PgFrozen));
        assert_eq!(
            Backend::parse(Some("postgres")),
            Err("invalid CATALOG_BACKEND")
        );
        assert_eq!(pipeline(None), Ok(true));
        assert_eq!(pipeline(Some("0")), Ok(false));
        assert_eq!(pipeline(Some("false")), Err("invalid PG_PIPELINE"));
    }

    #[test]
    fn direct_origin_budget_keeps_ops_capacity() {
        assert!(connection_budget_ok(25, 3, PG_DRILL_LIMIT));
        assert!(!connection_budget_ok(24, 3, PG_DRILL_LIMIT));
        assert!(!connection_budget_ok(25, 3, 6));
        assert!(connection_budget_ok(25, 3, 0));
    }
}
