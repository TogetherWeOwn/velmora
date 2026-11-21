//! The unit: one call in, one answer out (tenancy ADR §2.4 rules 1 to 7
//! and 11).
//!
//! - **Rule 1, same code.** The unit is a [`SqlCatalog`] over its own
//!   database; every operation is the catalogue's code.
//! - **Rule 2, one transaction.** A whole call runs inside
//!   [`UnitSql::atomically`]: all of its writes or none. A batch inside
//!   it is a nested transaction (a savepoint), as before.
//! - **Rule 3, no key.** Nothing here opens a seal or holds a key: the
//!   birth token comes verified by the Worker and is stored as given.
//! - **Rule 4, no I/O inside a call.** The call's future is polled
//!   **once** ([`poll_once`]). The catalogue over a unit's own SQLite
//!   never waits, so it is done in that poll; a call that waits on
//!   anything (network, timer) is refused and rolled back instead of
//!   holding the object awake.
//! - **Rule 5, identity.** [`super::identity::check`], against the
//!   numbers in `unit_head`.
//! - **Rule 6, birth.** Only `provision` makes a unit, with a token the
//!   unit checks ([`super::birth::check_token`]); a unit holds its
//!   certificate in `unit_birth`. A second `provision` is refused.
//! - **Rule 7, unborn is not empty.** A unit without a certificate
//!   answers [`UnitAnswer::Unborn`] to every call but `provision` and
//!   writes nothing: no table is made before a birth.
//! - **Rule 11, unauthenticated calls are read-only.** Only `key_row`
//!   and `read_plan` run without `authenticated`, and their transaction
//!   is rolled back and refused if it changed a row (counted by SQLite's
//!   `total_changes()`).

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use base64::Engine as _;
use serde_json::{json, Value};

use super::birth::{check_token, BirthKind, BirthToken, ProvisionRefusal};
use super::call::{
    Closed, HoldMode, Reader, Refused, SyncHead, TenantState, UnitAnswer, UnitCall, UnitOp,
};
use super::identity::{self, CallKind, Seqs, Verdict};
use super::name::UnitName;
use super::schema;
use crate::ports::{Catalog, Sql, SqlValue};
use crate::sql::SqlCatalog;
use crate::types::{BridgeError, BucketId, ExtentId, KeyStatus, Result, UnixMs};

/// The database of a unit: [`Sql`] with whole-call transactions.
pub trait UnitSql: Sql {
    /// Runs `f` as one transaction: every write `f` made is kept if it
    /// returns `Ok`, and none if it returns `Err`. Batches inside `f`
    /// nest (a refused batch rolls back only itself).
    fn atomically(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()>;

    /// Runs a script of several statements (a migration), inside the
    /// current transaction if there is one.
    fn apply_script(&self, script: &str) -> Result<()>;
}

/// The class of a call that waited inside the unit (rule 4).
pub const AWAITED: &str = "unit call waited on I/O";

/// Drives `f` with one poll. The unit's catalogue never waits, so a
/// `Pending` here is a call that reached for I/O.
pub fn poll_once<F: Future>(f: F) -> Result<F::Output> {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Ok(v),
        Poll::Pending => Err(BridgeError::Invalid(AWAITED)),
    }
}

/// Minimum time between two read stamps of one extent, as on the GET path.
const READ_STAMP_MS: i64 = 60_000;

/// An internal signal: roll the call back and refuse it with this reason.
const ROLLBACK: &str = "unit: roll back";

/// What the unit holds of its tenant (`unit_head`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub seqs: Seqs,
    pub tenant_state: TenantState,
    pub tenant_mode: Option<HoldMode>,
    pub restoring_since: Option<u64>,
}

/// One unit over its database.
pub struct Unit<S: UnitSql> {
    cat: SqlCatalog<S>,
    own: UnitName,
}

impl<S: UnitSql> Unit<S> {
    /// `own`: the name the object was made under.
    pub fn new(sql: S, own: UnitName) -> Self {
        Unit {
            cat: SqlCatalog::new(sql),
            own,
        }
    }

    pub fn sql(&self) -> &S {
        &self.cat.sql
    }

    pub fn name(&self) -> &UnitName {
        &self.own
    }

    /// One call. Never panics on a caller's input; a failure of the
    /// database is [`UnitAnswer::Failed`] with a class only.
    pub fn handle(&self, call: &UnitCall, now: UnixMs) -> UnitAnswer {
        match self.dispatch(call, now) {
            Ok(answer) => answer,
            Err(e) => failed(&e),
        }
    }

    fn dispatch(&self, call: &UnitCall, now: UnixMs) -> Result<UnitAnswer> {
        if call.name != self.own {
            return Ok(refused(
                Refused::Identity(identity::Refusal::WrongName),
                true,
            ));
        }
        let born = self.born()?;
        let UnitOp::Provision { token, sealed } = &call.op else {
            let Some(cert) = born else {
                // Rule 7: nothing is made, nothing is written.
                return Ok(UnitAnswer::Unborn {
                    listed: call.listed,
                });
            };
            if cert != self.own {
                // The certificate names another unit than the object: a
                // copied or forged database. Never served.
                return Ok(refused(
                    Refused::Identity(identity::Refusal::WrongName),
                    true,
                ));
            }
            return self.born_call(call, now);
        };
        if born.is_some() {
            return Ok(refused(
                Refused::Provision(ProvisionRefusal::AlreadyBorn),
                false,
            ));
        }
        if call.kind != CallKind::Worker {
            return Ok(refused(Refused::Unauthenticated, false));
        }
        self.provision(token, sealed, call.seqs.map(|s| s.state_seq), now)
    }

    /// The name in the certificate, if the unit is born. Reads only; an
    /// unborn object has no tables, and none is made here.
    fn born(&self) -> Result<Option<UnitName>> {
        let sql = self.sql();
        let has = poll_once(sql.query(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'unit_birth'",
            &[],
        ))??;
        if int(&has, 0, 0)? == 0 {
            return Ok(None);
        }
        let rows = poll_once(sql.query("SELECT tenant, unit FROM unit_birth WHERE id = 1", &[]))??;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let (SqlValue::Text(tenant), SqlValue::Int(unit)) = (&row[0], &row[1]) else {
            return Err(decode("unit_birth"));
        };
        let name = format!("{tenant}/{unit}");
        UnitName::parse(&name)
            .map(Some)
            .ok_or_else(|| decode("unit_birth name"))
    }

    pub fn head(&self) -> Result<Head> {
        let rows = poll_once(self.sql().query(
            "SELECT state_seq, keys_seq, tenant_state, tenant_mode, restoring_since \
               FROM unit_head WHERE id = 1",
            &[],
        ))??;
        let row = rows.first().ok_or_else(|| decode("unit_head"))?;
        let u = |i: usize| match &row[i] {
            SqlValue::Int(n) if *n >= 0 => Ok(*n as u64),
            _ => Err(decode("unit_head number")),
        };
        let tenant_state = match &row[2] {
            SqlValue::Text(s) => TenantState::parse(s).ok_or_else(|| decode("tenant_state"))?,
            _ => return Err(decode("tenant_state")),
        };
        let tenant_mode = match &row[3] {
            SqlValue::Null => None,
            SqlValue::Text(s) => Some(HoldMode::parse(s).ok_or_else(|| decode("tenant_mode"))?),
            _ => return Err(decode("tenant_mode")),
        };
        let restoring_since = match &row[4] {
            SqlValue::Null => None,
            SqlValue::Int(n) if *n >= 0 => Some(*n as u64),
            _ => return Err(decode("restoring_since")),
        };
        Ok(Head {
            seqs: Seqs {
                state_seq: u(0)?,
                keys_seq: u(1)?,
            },
            tenant_state,
            tenant_mode,
            restoring_since,
        })
    }

    fn provision(
        &self,
        token: &BirthToken,
        sealed: &[u8],
        caller_state_seq: Option<u64>,
        now: UnixMs,
    ) -> Result<UnitAnswer> {
        if let Err(reason) = check_token(&self.own, token, caller_state_seq) {
            let alarm = reason == ProvisionRefusal::WrongName;
            return Ok(refused(Refused::Provision(reason), alarm));
        }
        let restoring = (token.kind == BirthKind::Restore).then_some(token.record_seq);
        let sql = self.sql();
        let mut run = || -> Result<()> {
            for script in schema::all() {
                sql.apply_script(script)?;
            }
            // A born unit is empty: zero is the right count of nothing,
            // so its usage counters start on. A restored one is filled by
            // its replay and recounted by the gate, so they start off.
            if token.kind == BirthKind::Birth {
                poll_once(sql.exec(
                    "UPDATE usage_global SET all_x = 1, all_o = 1, all_g = 1 WHERE id = 1",
                    &[],
                ))??;
            }
            let birth = poll_once(sql.exec(
                "INSERT INTO unit_birth(id, tenant, unit, jurisdiction, record_seq, \
                   schema_version, key_scheme, kind, token, born_at) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &[
                    SqlValue::Text(self.own.tenant.to_string()),
                    SqlValue::Int(i64::from(self.own.unit)),
                    SqlValue::Text(token.jurisdiction.clone()),
                    int_param(token.record_seq)?,
                    SqlValue::Int(i64::from(token.schema_version)),
                    SqlValue::Int(i64::from(token.key_scheme)),
                    SqlValue::Text(token.kind.as_str().into()),
                    SqlValue::Blob(sealed.to_vec()),
                    SqlValue::Int(now.0),
                ],
            ))??;
            let head = poll_once(sql.exec(
                "INSERT INTO unit_head(id, state_seq, keys_seq, tenant_state, tenant_mode, \
                   restoring_since) VALUES (1, ?1, 0, 'provisioning', NULL, ?2)",
                &[
                    int_param(token.record_seq)?,
                    match restoring {
                        Some(s) => int_param(s)?,
                        None => SqlValue::Null,
                    },
                ],
            ))??;
            if birth != 1 || head != 1 {
                return Err(decode("birth rows"));
            }
            Ok(())
        };
        sql.atomically(&mut run)?;
        let head = self.head()?;
        Ok(UnitAnswer::Ok {
            seqs: head.seqs,
            body: json!({ "born": token.kind.as_str(), "restoring": head.restoring_since }),
        })
    }

    fn born_call(&self, call: &UnitCall, now: UnixMs) -> Result<UnitAnswer> {
        let head = self.head()?;
        let verdict = identity::check(&self.own, head.seqs, &call.name, call.kind, call.seqs);
        // The Worker's own calls carry verified records, not a view.
        // and only they skip the numbers: a Worker call is exactly a
        // Worker operation.
        let worker_op = call.op.worker_call();
        if worker_op != (call.kind == CallKind::Worker) {
            return Ok(refused(Refused::Unauthenticated, false));
        }
        let fanout_check = match verdict {
            Verdict::Proceed => false,
            Verdict::FanoutCheck => true,
            Verdict::SyncNeeded => return Ok(UnitAnswer::SyncNeeded { seqs: head.seqs }),
            Verdict::Stale => return Ok(UnitAnswer::Stale { seqs: head.seqs }),
            Verdict::Refused { reason, alarm } => {
                return Ok(refused(Refused::Identity(reason), alarm))
            }
        };
        if let UnitOp::Sync { head: next } = &call.op {
            return self.sync(&head, next);
        }
        if head.restoring_since.is_some() {
            return Ok(UnitAnswer::Closed {
                seqs: head.seqs,
                why: Closed::Restoring,
            });
        }
        if head.tenant_state == TenantState::Provisioning {
            return Ok(UnitAnswer::Closed {
                seqs: head.seqs,
                why: Closed::Provisioning,
            });
        }
        if !call.authenticated && !call.op.read_only() {
            return Ok(refused(Refused::Unauthenticated, false));
        }
        // The tenant's state decides an authenticated call here. An
        // unauthenticated read gets the state with its answer, and the
        // Worker applies it after the signature verified (ADR §8.4).
        if call.authenticated && !allows(&head, call.op.is_read()) {
            return Ok(refused(Refused::AccountProblem, false));
        }
        if fanout_check
            && !matches!(
                call.op,
                UnitOp::ReadPlan {
                    reader: Some(_),
                    ..
                }
            )
        {
            // Lower numbers are served only to a fan-out read that the
            // unit's own tables still allow.
            return Ok(refused(Refused::AccessDenied, false));
        }
        self.run(call, &head, fanout_check, now)
    }

    /// Runs one operation as one transaction. Without `authenticated`, a
    /// changed row rolls the call back and refuses it.
    fn run(
        &self,
        call: &UnitCall,
        head: &Head,
        fanout_check: bool,
        now: UnixMs,
    ) -> Result<UnitAnswer> {
        let mut op = || poll_once(self.operate(call, head, fanout_check, now))?;
        match transact(self.sql(), call.authenticated, &mut op)? {
            Ok(body) => Ok(UnitAnswer::Ok {
                seqs: head.seqs,
                body,
            }),
            Err(reason) => {
                let alarm = matches!(
                    reason,
                    Refused::WroteWithoutAuthentication | Refused::AwaitedInside
                );
                Ok(refused(reason, alarm))
            }
        }
    }

    async fn operate(
        &self,
        call: &UnitCall,
        head: &Head,
        fanout_check: bool,
        now: UnixMs,
    ) -> Result<std::result::Result<Value, Refused>> {
        let state = json!({
            "tenant_state": head.tenant_state.as_str(),
            "tenant_mode": head.tenant_mode.map(HoldMode::as_str),
        });
        match &call.op {
            UnitOp::Ping => Ok(Ok(state)),
            UnitOp::KeyRow { access_key_id } => {
                let row = self.cat.access_key(access_key_id).await?;
                Ok(Ok(
                    json!({ "key": row.as_ref().map(key_json), "state": state }),
                ))
            }
            UnitOp::ReadPlan {
                bucket,
                key,
                start,
                end,
                access_key_id,
                reader,
            } => {
                let Some(b) = self.cat.bucket_by_name(bucket).await? else {
                    return Ok(Err(Refused::NotFound));
                };
                if fanout_check {
                    let reader = reader.as_ref().ok_or(BridgeError::Invalid("no reader"))?;
                    if !self.reader_allowed(head, &b.id, reader).await? {
                        return Ok(Err(Refused::AccessDenied));
                    }
                }
                let key_row = match access_key_id {
                    Some(akid) => match self.cat.access_key(akid).await? {
                        Some(row) => {
                            let grant = self.cat.grant(akid, &b.id).await?;
                            Some(json!({
                                "key": key_json(&row),
                                "grant": grant.map(|p| p.as_str()),
                            }))
                        }
                        None => Some(Value::Null),
                    },
                    None => None,
                };
                let Some(generation) = self.cat.live_generation(&b.id, key).await? else {
                    return Ok(Ok(json!({
                        "bucket": b.id.as_str(),
                        "generation": Value::Null,
                        "key_row": key_row,
                        "state": state,
                    })));
                };
                let extents = self.cat.extents_in(&generation.id, *start, *end).await?;
                if call.authenticated {
                    for x in &extents {
                        self.cat
                            .touch_read(&ExtentId::new(x.id.as_str()), now, READ_STAMP_MS, false)
                            .await?;
                    }
                }
                Ok(Ok(json!({
                    "bucket": b.id.as_str(),
                    "generation": generation.id.as_str(),
                    "size": generation.size,
                    "extents": extents.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
                    "key_row": key_row,
                    "state": state,
                })))
            }
            UnitOp::Provision { .. } | UnitOp::Sync { .. } => {
                Err(BridgeError::Invalid("worker call routed as an operation"))
            }
        }
    }

    /// The third case of rule 5: a sub-request under an earlier grant is
    /// served only while the unit's own tables still allow its reader:
    /// the tenant may read, the bucket exists (the caller looked it up),
    /// and the key is `active` with a grant on that bucket. A public read
    /// needs a public flag, which no bucket has yet, so it is refused.
    async fn reader_allowed(
        &self,
        head: &Head,
        bucket: &BucketId,
        reader: &Reader,
    ) -> Result<bool> {
        if !allows(head, true) {
            return Ok(false);
        }
        match reader {
            Reader::Public => Ok(false),
            Reader::Key { access_key_id } => {
                let Some(row) = self.cat.access_key(access_key_id).await? else {
                    return Ok(false);
                };
                if row.status != KeyStatus::Active {
                    return Ok(false);
                }
                Ok(self.cat.grant(access_key_id, bucket).await?.is_some())
            }
        }
    }

    /// `sync` (rule 5): copies a verified record. Numbers never go back.
    /// The key records themselves are applied by the key-chain apply; until
    /// it exists here, a `keys_seq` above the unit's is refused, so the
    /// unit never claims a key table it does not hold.
    fn sync(&self, head: &Head, next: &SyncHead) -> Result<UnitAnswer> {
        if next.seqs.state_seq < head.seqs.state_seq || next.seqs.keys_seq < head.seqs.keys_seq {
            return Ok(refused(Refused::StaleSync, false));
        }
        if next.seqs.keys_seq > head.seqs.keys_seq {
            return Ok(refused(Refused::KeysNotApplied, false));
        }
        let mode_ok = (next.tenant_state == TenantState::Suspended) == next.tenant_mode.is_some();
        if !mode_ok {
            return Err(BridgeError::Invalid("sync: mode without suspension"));
        }
        let sql = self.sql();
        let mut run = || -> Result<()> {
            let n = poll_once(sql.exec(
                "UPDATE unit_head SET state_seq = ?1, tenant_state = ?2, tenant_mode = ?3, \
                   restoring_since = ?4 WHERE id = 1",
                &[
                    int_param(next.seqs.state_seq)?,
                    SqlValue::Text(next.tenant_state.as_str().into()),
                    match next.tenant_mode {
                        Some(m) => SqlValue::Text(m.as_str().into()),
                        None => SqlValue::Null,
                    },
                    match next.restoring_since {
                        Some(s) => int_param(s)?,
                        None => SqlValue::Null,
                    },
                ],
            ))??;
            if n != 1 {
                return Err(decode("unit_head"));
            }
            Ok(())
        };
        sql.atomically(&mut run)?;
        let head = self.head()?;
        Ok(UnitAnswer::Ok {
            seqs: head.seqs,
            body: json!({ "synced": head.seqs.state_seq }),
        })
    }
}

/// One operation as one transaction (rules 2, 4 and 11). `op` answers a
/// value or a refusal. Kept: the writes of an `Ok` value. Rolled back:
/// everything, for a refusal; for an unauthenticated call that changed a
/// row (refused as `WroteWithoutAuthentication`); and for a call that
/// waited on I/O (refused as `AwaitedInside`).
pub fn transact<S: UnitSql>(
    sql: &S,
    authenticated: bool,
    op: &mut dyn FnMut() -> Result<std::result::Result<Value, Refused>>,
) -> Result<std::result::Result<Value, Refused>> {
    let mut answer = None;
    let mut why = None;
    let mut run = || -> Result<()> {
        let before = total_changes(sql)?;
        let out = match op() {
            Err(BridgeError::Invalid(AWAITED)) => Err(Refused::AwaitedInside),
            other => other?,
        };
        if out.is_ok() && !authenticated && total_changes(sql)? != before {
            why = Some(Refused::WroteWithoutAuthentication);
            return Err(BridgeError::Invalid(ROLLBACK));
        }
        match out {
            Ok(v) => {
                answer = Some(v);
                Ok(())
            }
            Err(reason) => {
                why = Some(reason);
                Err(BridgeError::Invalid(ROLLBACK))
            }
        }
    };
    match sql.atomically(&mut run) {
        Ok(()) => Ok(Ok(answer.unwrap_or(Value::Null))),
        Err(BridgeError::Invalid(ROLLBACK)) => Ok(Err(
            why.ok_or(BridgeError::Invalid("rollback without a reason"))?
        )),
        Err(e) => Err(e),
    }
}

/// What the tenant's state lets an S3 call do (ADR §2.8).
fn allows(head: &Head, read: bool) -> bool {
    match head.tenant_state {
        TenantState::Active => true,
        TenantState::Suspended => read && head.tenant_mode == Some(HoldMode::ReadOnly),
        _ => false,
    }
}

fn total_changes<S: Sql>(sql: &S) -> Result<i64> {
    let rows = poll_once(sql.query("SELECT total_changes()", &[]))??;
    int(&rows, 0, 0)
}

fn int(rows: &[crate::ports::Row], r: usize, c: usize) -> Result<i64> {
    match rows.get(r).and_then(|row| row.get(c)) {
        Some(SqlValue::Int(n)) => Ok(*n),
        _ => Err(decode("integer")),
    }
}

fn int_param(n: u64) -> Result<SqlValue> {
    i64::try_from(n)
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("number out of range"))
}

fn key_json(row: &crate::types::AccessKeyRow) -> Value {
    json!({
        "access_key_id": row.access_key_id,
        "principal": row.principal,
        "secret_wrapped": base64::engine::general_purpose::STANDARD.encode(&row.secret_wrapped),
        "kek_version": row.kek_version,
        "status": row.status.as_str(),
        "created_at": row.created_at.0,
    })
}

fn refused(reason: Refused, alarm: bool) -> UnitAnswer {
    UnitAnswer::Refused { reason, alarm }
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}

fn failed(e: &BridgeError) -> UnitAnswer {
    let class = match e {
        BridgeError::Sql(_) => "sql",
        BridgeError::GuardFailed => "guard",
        BridgeError::Invalid(_) => "invalid",
        _ => "other",
    };
    UnitAnswer::Failed {
        class: class.into(),
    }
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::testkit::RusqliteSql;

    fn db() -> RusqliteSql {
        let db = RusqliteSql::open_in_memory().unwrap();
        db.apply("CREATE TABLE t (n INTEGER NOT NULL)").unwrap();
        db
    }

    fn rows(db: &RusqliteSql) -> i64 {
        db.with_conn(|c| c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)))
            .unwrap()
    }

    /// Pending once, then ready: a call that reached for I/O.
    struct Waits(bool);

    impl Future for Waits {
        type Output = ();
        fn poll(mut self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                Poll::Pending
            }
        }
    }

    #[test]
    fn a_future_that_waits_is_refused_by_the_single_poll() {
        assert!(matches!(
            poll_once(Waits(false)),
            Err(BridgeError::Invalid(AWAITED))
        ));
        assert!(poll_once(Waits(true)).is_ok());
    }

    #[test]
    fn an_unauthenticated_call_that_writes_is_rolled_back_and_refused() {
        let db = db();
        let mut op = || {
            poll_once(db.exec("INSERT INTO t(n) VALUES (1)", &[]))??;
            Ok(Ok(Value::Null))
        };
        assert_eq!(
            transact(&db, false, &mut op).unwrap(),
            Err(Refused::WroteWithoutAuthentication)
        );
        assert_eq!(rows(&db), 0);
        // The same call authenticated keeps its row.
        assert_eq!(transact(&db, true, &mut op).unwrap(), Ok(Value::Null));
        assert_eq!(rows(&db), 1);
    }

    #[test]
    fn a_call_that_waits_after_a_write_keeps_nothing() {
        let db = db();
        let mut op = || {
            poll_once(db.exec("INSERT INTO t(n) VALUES (1)", &[]))??;
            poll_once(Waits(false))?;
            Ok(Ok(Value::Null))
        };
        assert_eq!(
            transact(&db, true, &mut op).unwrap(),
            Err(Refused::AwaitedInside)
        );
        assert_eq!(rows(&db), 0);
    }

    #[test]
    fn a_refusal_keeps_nothing_the_call_began() {
        let db = db();
        let mut op = || {
            poll_once(db.exec("INSERT INTO t(n) VALUES (1)", &[]))??;
            Ok(Err(Refused::AccessDenied))
        };
        assert_eq!(
            transact(&db, true, &mut op).unwrap(),
            Err(Refused::AccessDenied)
        );
        assert_eq!(rows(&db), 0);
    }

    #[test]
    fn a_refused_batch_inside_a_call_rolls_back_only_itself() {
        let db = db();
        db.apply("CREATE TABLE tx_guard (ok INTEGER NOT NULL CHECK (ok = 1))")
            .unwrap();
        let mut op = || {
            poll_once(db.exec("INSERT INTO t(n) VALUES (1)", &[]))??;
            let refused = poll_once(db.batch(vec![
                ("INSERT INTO t(n) VALUES (2)", vec![]),
                ("INSERT INTO tx_guard(ok) VALUES (0)", vec![]),
            ]))?;
            assert!(matches!(refused, Err(BridgeError::GuardFailed)));
            Ok(Ok(Value::Null))
        };
        assert_eq!(transact(&db, true, &mut op).unwrap(), Ok(Value::Null));
        assert_eq!(rows(&db), 1);
    }
}
