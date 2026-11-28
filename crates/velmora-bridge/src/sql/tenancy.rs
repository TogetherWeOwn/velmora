//! Account catalogue; not used by the S3 or operator request paths.

use velmora::rng::{FillRandom, SystemRng};

use super::auth::bucket_row;
use super::objects::{ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Row, Sql, SqlValue};
use crate::types::{
    BridgeError, Bucket, Result, Tenant, TenantState, TenantSuspensionMode, UnixMs,
};

fn lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn check_tenant_id(id: &str) -> Result<()> {
    if id
        .strip_prefix("t_")
        .is_some_and(|s| lowercase_hex(s, 16) && s != "0000000000000000")
    {
        Ok(())
    } else {
        Err(BridgeError::Invalid("invalid tenant id"))
    }
}

fn new_tenant_id() -> Result<String> {
    loop {
        let mut raw = [0u8; 8];
        SystemRng
            .fill_bytes(&mut raw)
            .map_err(|_| BridgeError::Sql("tenant id randomness unavailable".into()))?;
        let value = u64::from_be_bytes(raw);
        if value != 0 {
            return Ok(format!("t_{value:016x}"));
        }
    }
}

fn check_external_ref(external_ref: &str) -> Result<()> {
    // Matches the management contract's external reference validator.
    if (1..=126).contains(&external_ref.len())
        && external_ref
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err(BridgeError::Invalid("invalid tenant external reference"))
    }
}

fn check_digest(sha256: &str) -> Result<()> {
    if lowercase_hex(sha256, 64) {
        Ok(())
    } else {
        Err(BridgeError::Invalid("invalid management token digest"))
    }
}

fn tenant_row(row: Row) -> Result<Tenant> {
    let mut cols = Cols::new(row);
    let id = cols.text()?;
    let external_ref = cols.text()?;
    let (state, suspension_mode) = match (cols.text()?.as_str(), cols.opt_text()?.as_deref()) {
        ("active", None) => (TenantState::Active, None),
        ("deleting", None) => (TenantState::Deleting, None),
        ("suspended", Some("read_only")) => {
            (TenantState::Suspended, Some(TenantSuspensionMode::ReadOnly))
        }
        ("suspended", Some("blocked")) => {
            (TenantState::Suspended, Some(TenantSuspensionMode::Blocked))
        }
        _ => {
            return Err(BridgeError::Sql(
                "invalid stored tenant state or suspension mode".into(),
            ))
        }
    };
    Ok(Tenant {
        id,
        external_ref,
        state,
        suspension_mode,
        display_name: cols.opt_text()?,
        created_at: cols.ms()?,
        updated_at: cols.ms()?,
    })
}

pub(super) async fn tenant_create<S: Sql>(
    catalogue: &SqlCatalog<S>,
    external_ref: &str,
    display_name: Option<&str>,
    now: UnixMs,
) -> Result<Tenant> {
    check_external_ref(external_ref)?;
    if display_name.is_some_and(|name| name.len() > 200 || name.contains('\0')) {
        return Err(BridgeError::Invalid("invalid tenant display name"));
    }
    catalogue
        .sql
        .exec(
            TENANT_CREATE,
            &[
                SqlValue::Text(new_tenant_id()?),
                text(external_ref),
                display_name.map_or(SqlValue::Null, text),
                ms(now),
            ],
        )
        .await?;
    // This is a separate statement so it sees the committed winner even
    // when the unique constraint made this insert wait on another create.
    tenant_lookup(catalogue, TENANT_BY_EXTERNAL_REF, external_ref)
        .await?
        .ok_or_else(|| BridgeError::Sql("tenant missing after create".into()))
}

pub(super) async fn tenant_get<S: Sql>(
    catalogue: &SqlCatalog<S>,
    id: &str,
) -> Result<Option<Tenant>> {
    check_tenant_id(id)?;
    tenant_lookup(catalogue, TENANT_GET, id).await
}

pub(super) async fn tenant_by_external_ref<S: Sql>(
    catalogue: &SqlCatalog<S>,
    external_ref: &str,
) -> Result<Option<Tenant>> {
    check_external_ref(external_ref)?;
    tenant_lookup(catalogue, TENANT_BY_EXTERNAL_REF, external_ref).await
}

async fn tenant_lookup<S: Sql>(
    catalogue: &SqlCatalog<S>,
    sql: &str,
    value: &str,
) -> Result<Option<Tenant>> {
    let rows = catalogue.sql.query(sql, &[text(value)]).await?;
    rows.into_iter().next().map(tenant_row).transpose()
}

pub(super) async fn buckets_by_owner<S: Sql>(
    catalogue: &SqlCatalog<S>,
    owner: &str,
    after_name: Option<&str>,
    limit: u32,
) -> Result<Vec<Bucket>> {
    check_tenant_id(owner)?;
    if limit > 1000 || after_name.is_some_and(|name| name.len() > 63 || name.contains('\0')) {
        return Err(BridgeError::Invalid("invalid tenant bucket page"));
    }
    let limit = SqlValue::Int(i64::from(limit));
    let rows = match after_name {
        Some(name) => {
            catalogue
                .sql
                .query(BUCKETS_AFTER, &[text(owner), text(name), limit])
                .await?
        }
        None => {
            catalogue
                .sql
                .query(BUCKETS_FIRST, &[text(owner), limit])
                .await?
        }
    };
    rows.into_iter().map(bucket_row).collect()
}

pub(super) async fn mgmt_token_is_disabled<S: Sql>(
    catalogue: &SqlCatalog<S>,
    sha256: &str,
) -> Result<bool> {
    check_digest(sha256)?;
    let rows = catalogue
        .sql
        .query(TOKEN_IS_DISABLED, &[text(sha256)])
        .await?;
    Ok(!rows.is_empty())
}

pub(super) async fn mgmt_token_disable<S: Sql>(
    catalogue: &SqlCatalog<S>,
    sha256: &str,
    token_class: &str,
    reason: &str,
    now: UnixMs,
) -> Result<()> {
    check_digest(sha256)?;
    if !matches!(token_class, "standard" | "confirmed") {
        return Err(BridgeError::Invalid("invalid management token class"));
    }
    if !matches!(reason, "rotated" | "revoked" | "leaked") {
        return Err(BridgeError::Invalid(
            "invalid management token disable reason",
        ));
    }
    catalogue
        .sql
        .exec(
            TOKEN_DISABLE,
            &[text(sha256), text(token_class), ms(now), text(reason)],
        )
        .await?;
    Ok(())
}

const TENANT_CREATE: &str =
    "INSERT INTO tenants (id, external_ref, display_name, created_at_ms, updated_at_ms) \
     VALUES (?1, ?2, ?3, ?4, ?4) ON CONFLICT (external_ref) DO NOTHING";
const TENANT_GET: &str =
    "SELECT id, external_ref, state, suspension_mode, display_name, created_at_ms, updated_at_ms \
     FROM tenants WHERE id = ?1";
const TENANT_BY_EXTERNAL_REF: &str =
    "SELECT id, external_ref, state, suspension_mode, display_name, created_at_ms, updated_at_ms \
     FROM tenants WHERE external_ref = ?1";
const BUCKETS_FIRST: &str =
    "SELECT id, name, owner, bdk_wrapped, kek_version, disposable, created_at \
     FROM buckets WHERE owner = ?1 ORDER BY name LIMIT ?2";
const BUCKETS_AFTER: &str =
    "SELECT id, name, owner, bdk_wrapped, kek_version, disposable, created_at \
     FROM buckets WHERE owner = ?1 AND name > ?2 ORDER BY name LIMIT ?3";
const TOKEN_IS_DISABLED: &str = "SELECT 1 FROM mgmt_tokens_disabled WHERE token_sha256 = ?1";
const TOKEN_DISABLE: &str =
    "INSERT INTO mgmt_tokens_disabled (token_sha256, token_class, disabled_at_ms, reason) \
     VALUES (?1, ?2, ?3, ?4) ON CONFLICT (token_sha256) DO NOTHING";

#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(&'static str, Vec<SqlValue>)> {
    super::pg_manifest(&[
        (TENANT_CREATE, "TTTI"),
        (TENANT_GET, "T"),
        (TENANT_BY_EXTERNAL_REF, "T"),
        (BUCKETS_FIRST, "TI"),
        (BUCKETS_AFTER, "TTI"),
        (TOKEN_IS_DISABLED, "T"),
        (TOKEN_DISABLE, "TTIT"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TestSql;

    #[tokio::test]
    async fn the_disabled_token_lookup_uses_the_primary_key() {
        let db = TestSql::with_schema().unwrap();
        let digest = "a".repeat(64);
        #[cfg(feature = "testkit-pg")]
        if let Some(pg) = db.postgres() {
            let client = pg.client().await.unwrap();
            let sql = crate::pg::normalize_statement(TOKEN_IS_DISABLED).unwrap();
            let plan: Vec<String> = client
                .query(&format!("EXPLAIN (COSTS OFF) {sql}"), &[&digest])
                .await
                .unwrap()
                .iter()
                .map(|row| row.get(0))
                .collect();
            assert!(
                plan.iter()
                    .any(|line| line.contains("mgmt_tokens_disabled_pkey")),
                "{plan:?}"
            );
            assert!(
                plan.iter().any(|line| line
                    .trim_start()
                    .starts_with("Index Cond: (token_sha256 = ")),
                "{plan:?}"
            );
            return;
        }

        let plan = db
            .fixture_query(
                &format!("EXPLAIN QUERY PLAN {TOKEN_IS_DISABLED}"),
                &[text(&digest)],
            )
            .await
            .unwrap();
        assert!(
            plan.iter().flatten().any(|v| matches!(v, SqlValue::Text(s)
            if s.starts_with("SEARCH mgmt_tokens_disabled ")
                && s.contains("sqlite_autoindex_mgmt_tokens_disabled_1")
                && s.ends_with("(token_sha256=?)"))),
            "{plan:?}"
        );
    }
}
