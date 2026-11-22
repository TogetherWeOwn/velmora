//! The directory database: tenant rows, unit rows, key routes, pending
//! operations and the gate, over the [`Sql`] port.
//!
//! The schema is `workers/s3-bridge/migrations-directory/`. Every tenant
//! row is a copy of a chain head ([`super::chain`]): it is written from a
//! [`TenantDoor`] and nothing else, and an older head never replaces a
//! newer one. The directory decides nothing on the S3 path; it is read
//! for a route on a cache miss, by the management plane, and by the
//! operator.

use super::record::{Tenant, TenantDoor};
use crate::ports::{Row, Sql, SqlValue};
use crate::types::{BridgeError, Result, UnixMs};

/// The directory over one database.
pub struct SqlDirectory<'a, S> {
    pub sql: &'a S,
}

/// A tenant row as stored.
#[derive(Clone, Debug, PartialEq)]
pub struct TenantRow {
    pub id: Tenant,
    pub record_seq: u64,
    pub keys_seq: u64,
    pub door: TenantDoor,
    pub updated_at: UnixMs,
}

/// A unit row as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitRow {
    pub unit: u32,
    pub restoring_since: Option<u64>,
}

/// What [`SqlDirectory::apply_tenant`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The row now copies this head.
    Applied,
    /// The row already copies this head or a newer one: nothing changed.
    NotNewer,
}

/// The kind of credential a route leads to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    S3,
    AppPassword,
    Internal,
    Principal,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::S3 => "s3",
            RouteKind::AppPassword => "app_password",
            RouteKind::Internal => "internal",
            RouteKind::Principal => "principal",
        }
    }

    fn parse(s: &str) -> Option<RouteKind> {
        Some(match s {
            "s3" => RouteKind::S3,
            "app_password" => RouteKind::AppPassword,
            "internal" => RouteKind::Internal,
            "principal" => RouteKind::Principal,
            _ => return None,
        })
    }
}

/// An access key id and the tenant it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRoute {
    pub akid: String,
    pub tenant: Tenant,
    pub kind: RouteKind,
    pub owner_ref: Option<String>,
    pub created_at: UnixMs,
}

/// What [`SqlDirectory::put_route`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutePut {
    /// Stored now.
    Inserted,
    /// The same route was there.
    Same,
    /// A route to another tenant or of another kind was there. A route
    /// does not change but by [`SqlDirectory::move_route`]: this is
    /// damage or a forged call, and it pages.
    Conflict,
    /// The tenant has no row, or is shredded: no route was stored.
    NoTenant,
    /// The kind does not fit the id: an `APVL…` id is an app password and
    /// every app password has one, for life. Nothing was stored.
    WrongKind,
}

/// The id prefix of an app password.
pub const APP_PASSWORD_PREFIX: &str = "APVL";

/// Whether `kind` fits `akid`: the prefix fixes the kind for life.
pub fn kind_fits(akid: &str, kind: RouteKind) -> bool {
    akid.starts_with(APP_PASSWORD_PREFIX) == (kind == RouteKind::AppPassword)
}

/// Which chain a pending operation is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainKind {
    Tenant,
    Keys,
}

impl ChainKind {
    fn as_str(self) -> &'static str {
        match self {
            ChainKind::Tenant => "t",
            ChainKind::Keys => "k",
        }
    }

    fn parse(s: &str) -> Option<ChainKind> {
        match s {
            "t" => Some(ChainKind::Tenant),
            "k" => Some(ChainKind::Keys),
            _ => None,
        }
    }
}

/// A control change that is not yet applied everywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOp {
    pub tenant: Tenant,
    pub chain: ChainKind,
    pub seq: u64,
    pub kind: String,
    pub created_at: UnixMs,
}

/// The directory gate as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateState {
    pub closed: bool,
    pub epoch: u64,
}

const ERR_ROW: BridgeError = BridgeError::Invalid("directory row");

const UPSERT_TENANT: &str = "INSERT INTO tenants (id, record_seq, state, hold_mode, shred_due_at, tk_version, rotating_to, selector, synthetic, jurisdiction, door_json, updated_at) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
     ON CONFLICT (id) DO UPDATE SET record_seq = excluded.record_seq, state = excluded.state, hold_mode = excluded.hold_mode, shred_due_at = excluded.shred_due_at, tk_version = excluded.tk_version, rotating_to = excluded.rotating_to, selector = excluded.selector, synthetic = excluded.synthetic, jurisdiction = excluded.jurisdiction, door_json = excluded.door_json, updated_at = excluded.updated_at \
     WHERE excluded.record_seq > tenants.record_seq";

/// The gate's form: the row takes the head whatever seq it held, a higher
/// one included (a restored or damaged row is not trusted over R2), but
/// only if the row still holds the seq the gate saw (`?13`, NULL for no
/// row): a head that a closing call applied in between is newer than the
/// gate's and stays. A row the gate saw that is gone since is not made
/// again either.
const REPLACE_TENANT: &str = "INSERT INTO tenants (id, record_seq, state, hold_mode, shred_due_at, tk_version, rotating_to, selector, synthetic, jurisdiction, door_json, updated_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12 \
     WHERE ?13 IS NULL OR EXISTS (SELECT 1 FROM tenants WHERE id = ?1) \
     ON CONFLICT (id) DO UPDATE SET record_seq = excluded.record_seq, state = excluded.state, hold_mode = excluded.hold_mode, shred_due_at = excluded.shred_due_at, tk_version = excluded.tk_version, rotating_to = excluded.rotating_to, selector = excluded.selector, synthetic = excluded.synthetic, jurisdiction = excluded.jurisdiction, door_json = excluded.door_json, updated_at = excluded.updated_at \
     WHERE tenants.record_seq IS ?13";

// The unit statements run only when the tenant row holds exactly this
// head after the upsert (its seq and its door), so an older head, or
// another door at the same seq, changes no unit row.
const DROP_UNLISTED_UNITS: &str = "DELETE FROM units WHERE tenant = ?1 \
     AND (SELECT door_json FROM tenants WHERE id = ?1 AND record_seq = ?2) = ?4 \
     AND unit NOT IN (SELECT value FROM json_each(?3))";

const ADD_LISTED_UNITS: &str = "INSERT INTO units (tenant, unit) \
     SELECT ?1, value FROM json_each(?3) WHERE (SELECT door_json FROM tenants WHERE id = ?1 AND record_seq = ?2) = ?4 \
     ON CONFLICT (tenant, unit) DO NOTHING";

const SET_RESTORING: &str = "UPDATE units SET restoring_since = \
     (SELECT json_extract(r.value, '$.since_seq') FROM json_each(?3) r WHERE json_extract(r.value, '$.unit') = units.unit) \
     WHERE tenant = ?1 AND (SELECT door_json FROM tenants WHERE id = ?1 AND record_seq = ?2) = ?4";

// A shredded tenant keeps its row and loses every route and label.
const DROP_SHREDDED_ROUTES: &str = "DELETE FROM key_routes WHERE tenant = ?1 \
     AND (SELECT state FROM tenants WHERE id = ?1 AND record_seq = ?2) = 'shredded'";

const DROP_SHREDDED_LABELS: &str = "DELETE FROM bucket_index WHERE tenant = ?1 \
     AND (SELECT state FROM tenants WHERE id = ?1 AND record_seq = ?2) = 'shredded'";

const TENANT_COLUMNS: &str = "id, record_seq, keys_seq, door_json, updated_at";

/// The columns that are taken from the door, in the order of
/// [`tenant_params`] from its third value on.
const DERIVED_COLUMNS: &str =
    "state, hold_mode, shred_due_at, tk_version, rotating_to, selector, synthetic, jurisdiction";

/// A tenant row as the gate reads it: its seq, and its door only if the
/// row is whole (the door parses, names the row's id and seq, and every
/// column taken from it says what the door says).
#[derive(Clone, Debug, PartialEq)]
pub struct RawTenant {
    /// `None` when the column holds no seq.
    pub record_seq: Option<u64>,
    pub door: Option<TenantDoor>,
}

/// The seq column of a tenant row exactly as stored (`NULL` for no row),
/// for a write that must find the row as the gate saw it.
#[derive(Clone, Debug, PartialEq)]
pub struct RowSeq(SqlValue);

/// The values of a tenant row for `door`, in the order of the columns of
/// the upsert statements.
fn tenant_params(door: &TenantDoor, now: UnixMs) -> Result<Vec<SqlValue>> {
    let hold_mode = door.holds.mode().map(|m| match m {
        super::record::HoldMode::ReadOnly => "read_only",
        super::record::HoldMode::Locked => "locked",
    });
    let selector = door.tenant_zero.as_ref().map(|z| z.selector.as_str());
    Ok(vec![
        SqlValue::Text(door.tenant.as_str().to_string()),
        int(door.seq)?,
        SqlValue::Text(door.state().name().to_string()),
        opt_text(hold_mode),
        door.deletion
            .as_ref()
            .map_or(SqlValue::Null, |d| SqlValue::Int(d.shred_due_at.0)),
        SqlValue::Int(i64::from(door.tk_version)),
        door.rotating_to
            .map_or(SqlValue::Null, |v| SqlValue::Int(i64::from(v))),
        opt_text(selector),
        SqlValue::Int(i64::from(door.synthetic)),
        SqlValue::Text(door.jurisdiction.clone()),
        SqlValue::Text(serde_json::to_string(door).map_err(|_| ERR_ROW)?),
        SqlValue::Int(now.0),
    ])
}

impl<S: Sql> SqlDirectory<'_, S> {
    /// Copies a chain head into the tenant's row and unit rows, if it is
    /// newer than what the row holds. One atomic batch.
    pub async fn apply_tenant(&self, door: &TenantDoor, now: UnixMs) -> Result<Applied> {
        let changed = self.write_tenant(UPSERT_TENANT, None, door, now).await?;
        Ok(match changed {
            0 => Applied::NotNewer,
            _ => Applied::Applied,
        })
    }

    /// The seq column of `tenant`'s row as stored, `NULL` for no row.
    pub async fn row_seq(&self, tenant: &Tenant) -> Result<RowSeq> {
        let rows = self
            .sql
            .query(
                "SELECT record_seq FROM tenants WHERE id = ?1",
                &[SqlValue::Text(tenant.as_str().to_string())],
            )
            .await?;
        Ok(RowSeq(
            rows.into_iter()
                .next()
                .and_then(|r| r.into_iter().next())
                .unwrap_or(SqlValue::Null),
        ))
    }

    /// The gate's copy of a head: the row takes it whatever seq it held,
    /// if it still holds `observed`. `false` = the row changed since the
    /// gate read it, and nothing was written.
    pub async fn replace_tenant(
        &self,
        door: &TenantDoor,
        observed: &RowSeq,
        now: UnixMs,
    ) -> Result<bool> {
        let changed = self
            .write_tenant(REPLACE_TENANT, Some(observed.0.clone()), door, now)
            .await?;
        Ok(changed > 0)
    }

    async fn write_tenant(
        &self,
        upsert: &'static str,
        observed: Option<SqlValue>,
        door: &TenantDoor,
        now: UnixMs,
    ) -> Result<u64> {
        let mut params = tenant_params(door, now)?;
        let id = params[0].clone();
        let seq = params[1].clone();
        let door_json = params[10].clone();
        if let Some(observed) = observed {
            params.push(observed);
        }
        let units = SqlValue::Text(serde_json::to_string(&door.units).map_err(|_| ERR_ROW)?);
        let restoring =
            SqlValue::Text(serde_json::to_string(&door.restoring).map_err(|_| ERR_ROW)?);
        let unit_params = |list: SqlValue| vec![id.clone(), seq.clone(), list, door_json.clone()];
        let changed = self
            .sql
            .batch(vec![
                (upsert, params),
                (DROP_UNLISTED_UNITS, unit_params(units.clone())),
                (ADD_LISTED_UNITS, unit_params(units)),
                (SET_RESTORING, unit_params(restoring)),
                (DROP_SHREDDED_ROUTES, vec![id.clone(), seq.clone()]),
                (DROP_SHREDDED_LABELS, vec![id, seq]),
            ])
            .await?;
        Ok(changed.first().copied().unwrap_or(0))
    }

    /// The row of `tenant` as the gate reads it: a row that does not parse
    /// or whose columns disagree with its door is a row without a door,
    /// never an error, so that the gate can write it again.
    pub async fn raw_tenant(&self, tenant: &Tenant) -> Result<Option<RawTenant>> {
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT record_seq, door_json, {DERIVED_COLUMNS} FROM tenants WHERE id = ?1"
                ),
                &[SqlValue::Text(tenant.as_str().to_string())],
            )
            .await?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let record_seq = int_at(&row, 0).ok().and_then(|v| u64::try_from(v).ok());
        let door = text(&row, 1)
            .ok()
            .and_then(|json| serde_json::from_str::<TenantDoor>(&json).ok())
            .filter(|door| &door.tenant == tenant && Some(door.seq) == record_seq)
            .filter(|door| {
                tenant_params(door, UnixMs(0))
                    .map(|expected| expected[2..10] == row[2..10])
                    .unwrap_or(false)
            });
        Ok(Some(RawTenant { record_seq, door }))
    }

    /// The row of `tenant`, `None` = no row.
    pub async fn tenant(&self, tenant: &Tenant) -> Result<Option<TenantRow>> {
        let rows = self
            .sql
            .query(
                &format!("SELECT {TENANT_COLUMNS} FROM tenants WHERE id = ?1"),
                &[SqlValue::Text(tenant.as_str().to_string())],
            )
            .await?;
        rows.into_iter().next().map(tenant_row).transpose()
    }

    /// Up to `limit` tenant ids after `after`, in id order.
    pub async fn tenant_ids(&self, after: &str, limit: u32) -> Result<Vec<Tenant>> {
        let rows = self
            .sql
            .query(
                "SELECT id FROM tenants WHERE id > ?1 ORDER BY id LIMIT ?2",
                &[
                    SqlValue::Text(after.to_string()),
                    SqlValue::Int(i64::from(limit)),
                ],
            )
            .await?;
        rows.into_iter()
            .map(|row| text(&row, 0).and_then(|s| Tenant::parse(&s).ok_or(ERR_ROW)))
            .collect()
    }

    /// Removes a tenant row that no chain backs, with its units, routes
    /// and labels, if the row still holds the seq the gate saw. Only the
    /// gate calls this. `false` = the row changed, nothing was removed.
    pub async fn remove_tenant(&self, tenant: &Tenant, observed: &RowSeq) -> Result<bool> {
        if observed.0 == SqlValue::Null {
            return Ok(false);
        }
        let p = || {
            Ok::<_, BridgeError>(vec![
                SqlValue::Text(tenant.as_str().to_string()),
                observed.0.clone(),
            ])
        };
        let changed = self
            .sql
            .batch(vec![
                (
                    "DELETE FROM units WHERE tenant = ?1 AND (SELECT record_seq FROM tenants WHERE id = ?1) = ?2",
                    p()?,
                ),
                (
                    "DELETE FROM key_routes WHERE tenant = ?1 AND (SELECT record_seq FROM tenants WHERE id = ?1) = ?2",
                    p()?,
                ),
                (
                    "DELETE FROM bucket_index WHERE tenant = ?1 AND (SELECT record_seq FROM tenants WHERE id = ?1) = ?2",
                    p()?,
                ),
                ("DELETE FROM tenants WHERE id = ?1 AND record_seq = ?2", p()?),
            ])
            .await?;
        Ok(changed.last().copied().unwrap_or(0) > 0)
    }

    /// The unit rows of `tenant`, by unit number.
    pub async fn units(&self, tenant: &Tenant) -> Result<Vec<UnitRow>> {
        let rows = self
            .sql
            .query(
                "SELECT unit, restoring_since FROM units WHERE tenant = ?1 ORDER BY unit",
                &[SqlValue::Text(tenant.as_str().to_string())],
            )
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(UnitRow {
                    unit: u32::try_from(int_at(&row, 0)?).map_err(|_| ERR_ROW)?,
                    restoring_since: match row.get(1) {
                        Some(SqlValue::Null) => None,
                        _ => Some(u64::try_from(int_at(&row, 1)?).map_err(|_| ERR_ROW)?),
                    },
                })
            })
            .collect()
    }

    /// Raises the tenant's key chain head; a lower seq changes nothing.
    pub async fn raise_keys_seq(&self, tenant: &Tenant, keys_seq: u64) -> Result<bool> {
        let changed = self
            .sql
            .exec(
                "UPDATE tenants SET keys_seq = ?2 WHERE id = ?1 AND keys_seq < ?2",
                &[SqlValue::Text(tenant.as_str().to_string()), int(keys_seq)?],
            )
            .await?;
        Ok(changed > 0)
    }

    /// Sets the tenant's key chain head as the gate rebuilt it, lower
    /// included (a floor that is too high is not harmless), if the row
    /// still holds `observed`: a raise that an admitted closing call made
    /// meanwhile stays.
    pub async fn set_keys_seq(
        &self,
        tenant: &Tenant,
        keys_seq: u64,
        observed: u64,
    ) -> Result<bool> {
        let changed = self
            .sql
            .exec(
                "UPDATE tenants SET keys_seq = ?2 WHERE id = ?1 AND keys_seq = ?3",
                &[
                    SqlValue::Text(tenant.as_str().to_string()),
                    int(keys_seq)?,
                    int(observed)?,
                ],
            )
            .await?;
        Ok(changed > 0)
    }

    /// Stores a route. A route does not change: an existing one to another
    /// tenant or of another kind is [`RoutePut::Conflict`], and stays. A
    /// tenant with no row, or a shredded one, gets no route. The two
    /// exceptions, the move of tenant 0's data and its undo, go through
    /// [`SqlDirectory::move_route`]. A kind that does not fit the id is
    /// [`RoutePut::WrongKind`].
    pub async fn put_route(&self, route: &KeyRoute) -> Result<RoutePut> {
        if !kind_fits(&route.akid, route.kind) {
            return Ok(RoutePut::WrongKind);
        }
        let changed = self
            .sql
            .exec(
                "INSERT INTO key_routes (akid, tenant, kind, owner_ref, created_at) \
                 SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM tenants WHERE id = ?2 AND state <> 'shredded') \
                 ON CONFLICT (akid) DO NOTHING",
                &[
                    SqlValue::Text(route.akid.clone()),
                    SqlValue::Text(route.tenant.as_str().to_string()),
                    SqlValue::Text(route.kind.as_str().to_string()),
                    opt_text(route.owner_ref.as_deref()),
                    SqlValue::Int(route.created_at.0),
                ],
            )
            .await?;
        if changed > 0 {
            return Ok(RoutePut::Inserted);
        }
        match self.route(&route.akid).await? {
            Some(old) if old.tenant == route.tenant && old.kind == route.kind => Ok(RoutePut::Same),
            Some(_) => Ok(RoutePut::Conflict),
            None => Ok(RoutePut::NoTenant),
        }
    }

    /// Moves a route from tenant `from` to tenant `to`, if it names `from`:
    /// the move of tenant 0's data and its undo, under maintenance. So one
    /// of the two is tenant 0 and the other is not. The kind stays: the id
    /// fixes it for life.
    /// `false` = the route did not name `from`, the target has no live
    /// row, or neither or both of the two are tenant 0; nothing changed.
    pub async fn move_route(&self, akid: &str, from: &Tenant, to: &Tenant) -> Result<bool> {
        let zero = Tenant::zero();
        if (*from == zero) == (*to == zero) {
            return Ok(false);
        }
        let changed = self
            .sql
            .exec(
                "UPDATE key_routes SET tenant = ?3 WHERE akid = ?1 AND tenant = ?2 \
                 AND EXISTS (SELECT 1 FROM tenants WHERE id = ?3 AND state <> 'shredded')",
                &[
                    SqlValue::Text(akid.to_string()),
                    SqlValue::Text(from.as_str().to_string()),
                    SqlValue::Text(to.as_str().to_string()),
                ],
            )
            .await?;
        Ok(changed > 0)
    }

    /// The tenant `akid` routes to, with the tenant row's `record_seq`
    /// and `keys_seq` (`None` when the row is gone), in one read: the
    /// request router's miss (ADR §8.4 step 2). `None` = no route.
    pub async fn route_tenant(&self, akid: &str) -> Result<Option<(Tenant, Option<(u64, u64)>)>> {
        let rows = self
            .sql
            .query(
                "SELECT r.tenant, t.record_seq, t.keys_seq FROM key_routes r \
                 LEFT JOIN tenants t ON t.id = r.tenant WHERE r.akid = ?1",
                &[SqlValue::Text(akid.to_string())],
            )
            .await?;
        rows.into_iter()
            .next()
            .map(|row| {
                let tenant = Tenant::parse(&text(&row, 0)?).ok_or(ERR_ROW)?;
                let seqs = match (row.get(1), row.get(2)) {
                    (Some(SqlValue::Null), Some(SqlValue::Null)) => None,
                    _ => Some((
                        u64::try_from(int_at(&row, 1)?).map_err(|_| ERR_ROW)?,
                        u64::try_from(int_at(&row, 2)?).map_err(|_| ERR_ROW)?,
                    )),
                };
                Ok((tenant, seqs))
            })
            .transpose()
    }

    /// The route of `akid`, `None` = no tenant has such a key.
    pub async fn route(&self, akid: &str) -> Result<Option<KeyRoute>> {
        let rows = self
            .sql
            .query(
                "SELECT akid, tenant, kind, owner_ref, created_at FROM key_routes WHERE akid = ?1",
                &[SqlValue::Text(akid.to_string())],
            )
            .await?;
        rows.into_iter()
            .next()
            .map(|row| {
                Ok(KeyRoute {
                    akid: text(&row, 0)?,
                    tenant: Tenant::parse(&text(&row, 1)?).ok_or(ERR_ROW)?,
                    kind: RouteKind::parse(&text(&row, 2)?).ok_or(ERR_ROW)?,
                    owner_ref: match row.get(3) {
                        Some(SqlValue::Null) => None,
                        _ => Some(text(&row, 3)?),
                    },
                    created_at: UnixMs(int_at(&row, 4)?),
                })
            })
            .transpose()
    }

    /// Records a pending operation; the same one twice is one row.
    pub async fn add_pending(&self, op: &PendingOp) -> Result<()> {
        self.sql
            .exec(
                "INSERT INTO pending_ops (tenant, chain, seq, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (tenant, chain, seq) DO NOTHING",
                &[
                    SqlValue::Text(op.tenant.as_str().to_string()),
                    SqlValue::Text(op.chain.as_str().to_string()),
                    int(op.seq)?,
                    SqlValue::Text(op.kind.clone()),
                    SqlValue::Int(op.created_at.0),
                ],
            )
            .await
            .map(|_| ())
    }

    /// Clears every pending operation of the chain up to `seq`: the
    /// finisher applies a chain up to its head, which covers them all.
    pub async fn clear_pending(&self, tenant: &Tenant, chain: ChainKind, seq: u64) -> Result<u64> {
        self.sql
            .exec(
                "DELETE FROM pending_ops WHERE tenant = ?1 AND chain = ?2 AND seq <= ?3",
                &[
                    SqlValue::Text(tenant.as_str().to_string()),
                    SqlValue::Text(chain.as_str().to_string()),
                    int(seq)?,
                ],
            )
            .await
    }

    /// Up to `limit` pending operations created before `before`, oldest
    /// first: the pending sweep's work.
    pub async fn pending_before(&self, before: UnixMs, limit: u32) -> Result<Vec<PendingOp>> {
        let rows = self
            .sql
            .query(
                "SELECT tenant, chain, seq, kind, created_at FROM pending_ops WHERE created_at < ?1 \
                 ORDER BY created_at, tenant, chain, seq LIMIT ?2",
                &[SqlValue::Int(before.0), SqlValue::Int(i64::from(limit))],
            )
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok(PendingOp {
                    tenant: Tenant::parse(&text(&row, 0)?).ok_or(ERR_ROW)?,
                    chain: ChainKind::parse(&text(&row, 1)?).ok_or(ERR_ROW)?,
                    seq: u64::try_from(int_at(&row, 2)?).map_err(|_| ERR_ROW)?,
                    kind: text(&row, 3)?,
                    created_at: UnixMs(int_at(&row, 4)?),
                })
            })
            .collect()
    }

    /// When the oldest pending operation was created, `None` = none.
    pub async fn oldest_pending(&self) -> Result<Option<UnixMs>> {
        let rows = self
            .sql
            .query("SELECT MIN(created_at) FROM pending_ops", &[])
            .await?;
        match rows.first().and_then(|r| r.first()) {
            None | Some(SqlValue::Null) => Ok(None),
            Some(SqlValue::Int(ms)) => Ok(Some(UnixMs(*ms))),
            Some(_) => Err(ERR_ROW),
        }
    }

    /// Empties the pending table (the gate rebuilds it empty), only while
    /// the gate is closed at `epoch`: a run that a newer one closed over,
    /// or one whose gate opened meanwhile, removes nothing.
    pub async fn clear_pending_in_gate(&self, epoch: u64) -> Result<u64> {
        self.sql
            .exec(
                "DELETE FROM pending_ops WHERE EXISTS \
                 (SELECT 1 FROM directory_gate WHERE id = 1 AND closed = 1 AND epoch = ?1)",
                &[int(epoch)?],
            )
            .await
    }

    /// The gate row as stored. No row = closed at epoch 0. Whether the
    /// gate is open also depends on its anchor in R2
    /// ([`super::gate::is_open`]).
    pub async fn gate(&self) -> Result<GateState> {
        let rows = self
            .sql
            .query("SELECT closed, epoch FROM directory_gate WHERE id = 1", &[])
            .await?;
        match rows.first() {
            None => Ok(GateState {
                closed: true,
                epoch: 0,
            }),
            Some(row) => Ok(GateState {
                closed: int_at(row, 0)? != 0,
                epoch: u64::try_from(int_at(row, 1)?).map_err(|_| ERR_ROW)?,
            }),
        }
    }

    /// Marks the gate closed at `epoch`, which the caller has anchored in
    /// R2. An older epoch changes nothing; the caller reads the row back.
    pub async fn mark_closed(&self, epoch: u64, reason: &str, now: UnixMs) -> Result<()> {
        self.sql
            .exec(
                "INSERT INTO directory_gate (id, closed, epoch, reason, closed_at) VALUES (1, 1, ?1, ?2, ?3) \
                 ON CONFLICT (id) DO UPDATE SET closed = 1, epoch = excluded.epoch, reason = excluded.reason, closed_at = excluded.closed_at \
                 WHERE excluded.epoch >= directory_gate.epoch",
                &[int(epoch)?, SqlValue::Text(reason.to_string()), SqlValue::Int(now.0)],
            )
            .await
            .map(|_| ())
    }

    /// Opens the gate closed at `epoch`. A gate closed again since (a
    /// newer epoch) stays closed: `false`.
    pub async fn open_gate(&self, epoch: u64, now: UnixMs) -> Result<bool> {
        let changed = self
            .sql
            .exec(
                "UPDATE directory_gate SET closed = 0, opened_at = ?2 WHERE id = 1 AND epoch = ?1",
                &[int(epoch)?, SqlValue::Int(now.0)],
            )
            .await?;
        Ok(changed > 0)
    }
}

fn tenant_row(row: Row) -> Result<TenantRow> {
    let id = Tenant::parse(&text(&row, 0)?).ok_or(ERR_ROW)?;
    let door: TenantDoor = serde_json::from_str(&text(&row, 3)?).map_err(|_| ERR_ROW)?;
    let record_seq = u64::try_from(int_at(&row, 1)?).map_err(|_| ERR_ROW)?;
    if door.tenant != id || door.seq != record_seq {
        return Err(ERR_ROW);
    }
    Ok(TenantRow {
        id,
        record_seq,
        keys_seq: u64::try_from(int_at(&row, 2)?).map_err(|_| ERR_ROW)?,
        door,
        updated_at: UnixMs(int_at(&row, 4)?),
    })
}

pub(super) fn int(v: u64) -> Result<SqlValue> {
    i64::try_from(v).map(SqlValue::Int).map_err(|_| ERR_ROW)
}

fn opt_text(v: Option<&str>) -> SqlValue {
    v.map_or(SqlValue::Null, |s| SqlValue::Text(s.to_string()))
}

pub(super) fn text(row: &Row, i: usize) -> Result<String> {
    match row.get(i) {
        Some(SqlValue::Text(s)) => Ok(s.clone()),
        _ => Err(ERR_ROW),
    }
}

pub(super) fn int_at(row: &Row, i: usize) -> Result<i64> {
    match row.get(i) {
        Some(SqlValue::Int(v)) => Ok(*v),
        _ => Err(ERR_ROW),
    }
}
