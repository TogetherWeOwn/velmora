use crate::BridgeError;

pub(super) fn statement_failed() -> BridgeError {
    BridgeError::Sql("pg: statement failed".into())
}

fn overloaded() -> BridgeError {
    BridgeError::Sql("pg: overloaded".into())
}

/// Hyperdrive's measured pool-wait failure is 58000. Only classify it as
/// overload at startup or BEGIN, before catalogue statements can execute.
/// A later statement success still overrides the prelude's classification.
pub(super) fn before_catalogue(error: tokio_postgres::Error) -> BridgeError {
    if error.code().is_some_and(|code| code.code() == "58000") {
        overloaded()
    } else {
        without_guard(from_driver(error))
    }
}

pub(super) fn shape() -> BridgeError {
    BridgeError::Sql("pg: unexpected result shape".into())
}

/// Ignore server message, detail, hint, SQL and bound values. They can
/// contain credentials or catalogue data.
pub(super) fn from_driver(error: tokio_postgres::Error) -> BridgeError {
    error.as_db_error().map_or_else(statement_failed, |db| {
        classify(db.code().code(), db.constraint())
    })
}

pub(super) fn classify(code: &str, constraint: Option<&str>) -> BridgeError {
    match code {
        "23514" if constraint == Some("tx_guard_ok") => BridgeError::GuardFailed,
        "VL001" => BridgeError::Sql("pg: constraint violation".into()),
        c if c.starts_with("23") => BridgeError::Sql("pg: constraint violation".into()),
        "55P03" | "57014" | "53300" | "53400" | "40001" | "40P01" => overloaded(),
        _ => statement_failed(),
    }
}

/// A guard is only a refusal if observed in the ordered write transaction,
/// not at startup, while finishing, or on a lock-free query.
pub(super) fn without_guard(error: BridgeError) -> BridgeError {
    match error {
        BridgeError::GuardFailed => statement_failed(),
        other => other,
    }
}
