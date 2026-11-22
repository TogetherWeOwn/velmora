//! The unit: one call in, one answer out (`docs/units.md`, rules 1 to 7
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
use super::export::{self, ExportMode, ExportTable};
use super::identity::{self, CallKind, Seqs, Verdict};
use super::import::{
    self, ImportBatch, ImportCount, ImportRefusal, ImportTable, ImportValue, Imported, MoveHead,
    Seal,
};
use super::keys::{self, Applied, KeptAnswer, KeyEntry};
use super::lift::{self, GateRefusal};
use super::name::UnitName;
use super::recount::{self, RecountCall};
use super::reserve::{self, Admit, Ask};
use super::restore::{self, PitrStep, RestoreRefusal};
use super::schema;
use super::size::{self, SizeLimits};
use crate::ports::{Catalog, Sql, SqlValue};
use crate::sql::SqlCatalog;
use crate::types::{BridgeError, BucketId, ExtentId, GenerationId, KeyStatus, Result, UnixMs};

/// The database of a unit: [`Sql`] with whole-call transactions.
pub trait UnitSql: Sql {
    /// Runs `f` as one transaction: every write `f` made is kept if it
    /// returns `Ok`, and none if it returns `Err`. Batches inside `f`
    /// nest (a refused batch rolls back only itself).
    fn atomically(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()>;

    /// Runs a script of several statements (a migration), inside the
    /// current transaction if there is one.
    fn apply_script(&self, script: &str) -> Result<()>;

    /// The database's size in bytes (the object's `databaseSize`), for
    /// the size guard (ADR §2.6).
    fn database_size(&self) -> Result<u64>;
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
    /// The unit's time of the `sync` that set `restoring_since` (a
    /// restore birth: its birth); none while the entry is not set.
    pub closed_at: Option<i64>,
}

/// One unit over its database.
pub struct Unit<S: UnitSql> {
    cat: SqlCatalog<S>,
    own: UnitName,
    /// The jurisdiction the object was made under ("" for none).
    jurisdiction: String,
    /// Where the size guard stands (ADR §2.6).
    size: SizeLimits,
}

impl<S: UnitSql> Unit<S> {
    /// `own`: the name the object was made under; `jurisdiction`: the
    /// jurisdiction of its namespace ("" for none).
    pub fn new(sql: S, own: UnitName, jurisdiction: &str) -> Self {
        Unit {
            cat: SqlCatalog::new(sql),
            own,
            jurisdiction: jurisdiction.to_string(),
            size: SizeLimits::default(),
        }
    }

    /// The same unit with the size guard at `limits` (tests lower it).
    pub fn with_size_limits(mut self, limits: SizeLimits) -> Self {
        self.size = limits;
        self
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
                // Rule 7: nothing is made, nothing is written. The move
                // tool's P12 read of `import_progress` sends `listed =
                // false` where its heads say an unborn unit is expected.
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

    /// The unit's clock at its birth (`unit_birth.born_at`).
    fn born_at(&self) -> Result<i64> {
        let rows = poll_once(
            self.sql()
                .query("SELECT born_at FROM unit_birth WHERE id = 1", &[]),
        )??;
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Int(t)) => Ok(*t),
            _ => Err(decode("unit_birth born_at")),
        }
    }

    pub fn head(&self) -> Result<Head> {
        let rows = poll_once(self.sql().query(
            "SELECT state_seq, keys_seq, tenant_state, tenant_mode, restoring_since, closed_at \
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
        let closed_at = match &row[5] {
            SqlValue::Null => None,
            SqlValue::Int(n) => Some(*n),
            _ => return Err(decode("closed_at")),
        };
        Ok(Head {
            seqs: Seqs {
                state_seq: u(0)?,
                keys_seq: u(1)?,
            },
            tenant_state,
            tenant_mode,
            restoring_since,
            closed_at,
        })
    }

    fn provision(
        &self,
        token: &BirthToken,
        sealed: &[u8],
        caller_state_seq: Option<u64>,
        now: UnixMs,
    ) -> Result<UnitAnswer> {
        if let Err(reason) = check_token(&self.own, &self.jurisdiction, token, caller_state_seq) {
            let alarm = reason == ProvisionRefusal::WrongName;
            return Ok(refused(Refused::Provision(reason), alarm));
        }
        let restoring = (token.kind == BirthKind::Restore).then_some(token.record_seq);
        let sql = self.sql();
        let mut born = None;
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
                   restoring_since, closed_at) VALUES (1, ?1, 0, 'provisioning', NULL, ?2, ?3)",
                &[
                    int_param(token.record_seq)?,
                    match restoring {
                        Some(s) => int_param(s)?,
                        None => SqlValue::Null,
                    },
                    // A unit born closed has been closed since its birth,
                    // and has never issued a lease (AM-2).
                    match restoring {
                        Some(_) => SqlValue::Int(now.0),
                        None => SqlValue::Null,
                    },
                ],
            ))??;
            if birth != 1 || head != 1 {
                return Err(decode("birth rows"));
            }
            // The answer is read inside the call: a failed read rolls
            // the birth back, so a failure answer never hides a birth.
            born = Some(self.head()?);
            Ok(())
        };
        sql.atomically(&mut run)?;
        let head = born.ok_or_else(|| decode("unit_head"))?;
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
        // The Worker's own calls run whatever the unit's state: they copy
        // verified records, or (the import) fill a closed unit.
        match &call.op {
            UnitOp::Sync { head: next } => return self.sync(&head, next, now),
            UnitOp::RestorePrepare { .. } | UnitOp::Restore { .. } => {
                // Restores need the object's storage: the object class
                // runs them through `pitr_step`.
                return Ok(refused(
                    Refused::Restore(RestoreRefusal::NoPointInTime),
                    false,
                ));
            }
            UnitOp::GateOpen { replay_id } => {
                return self.gate_write(&head, &mut || {
                    Ok(lift::open(self.sql(), head.restoring_since, replay_id)?
                        .map(|opened| json!({ "opened": opened })))
                })
            }
            UnitOp::GateReport { replay_id, summary } => {
                return self.gate_write(&head, &mut || {
                    Ok(
                        lift::report(self.sql(), head.restoring_since, replay_id, summary)?
                            .map(|()| json!({ "reported": true })),
                    )
                })
            }
            UnitOp::GateBlockers {
                replay_id,
                list,
                ids,
            } => {
                return self.gate_write(&head, &mut || {
                    Ok(
                        lift::blockers(self.sql(), head.restoring_since, replay_id, *list, ids)?
                            .map(|()| json!({ "listed": ids.len() })),
                    )
                })
            }
            UnitOp::GateAck {
                replay_id,
                class,
                ids,
            } => {
                return self.gate_write(&head, &mut || {
                    Ok(
                        lift::ack(self.sql(), head.restoring_since, replay_id, *class, ids)?
                            .map(|()| json!({ "acknowledged": ids.len() })),
                    )
                })
            }
            UnitOp::GateOpenMove {
                replay_id,
                head: mover,
            } => {
                if let Some(answer) = self.move_numbers(call, &head) {
                    return Ok(answer);
                }
                return self.gate_write(&head, &mut || {
                    Ok(lift::open_move(
                        self.sql(),
                        self.managed_root(),
                        &self.own.tenant,
                        head.restoring_since,
                        replay_id,
                        mover,
                    )?
                    .map(|opened| json!({ "opened": opened })))
                });
            }
            UnitOp::GateStatus {} => {
                return self.read_only(&head, &mut || {
                    lift::status(self.sql(), self.managed_root(), head.restoring_since)
                })
            }
            UnitOp::Export {
                table,
                after,
                limit,
                mode,
            } => return self.export(&head, *table, after.as_deref(), *limit, *mode),
            UnitOp::ImportSeal {
                head: mover,
                since,
                tables,
            } => return self.import_seal(call, &head, mover, *since, tables),
            UnitOp::ApplyKeys {
                from_seq,
                entries,
                answers,
            } => return self.apply_keys(&head, *from_seq, entries, answers, now),
            UnitOp::Recount {
                call: step,
                head: mover,
            } => return self.recount(call, &head, step, mover.as_ref(), now),
            UnitOp::HeldKeys {} => {
                return self.read_only(&head, &mut || {
                    Ok(json!({ "held": keys::held(self.sql())? }))
                })
            }
            UnitOp::Import {
                head: mover,
                since,
                batch,
            } => return self.import(call, &head, mover, *since, batch),
            UnitOp::ImportProgress {} => {
                return self.read_only(&head, &mut || {
                    let tables: Vec<Value> = import::progress(self.sql())?
                        .into_iter()
                        .map(|(t, c, n)| json!({ "table": t, "cursor": c, "rows": n }))
                        .collect();
                    // AM-47: the move's record; all null when no import
                    // was ever bound to this unit.
                    let record = import::move_record(self.sql())?;
                    Ok(json!({
                        "tables": tables,
                        "sealed": import::sealed(self.sql())?,
                        "t0_seq": record.map(|m| m.t0_seq),
                        "since_seq": record.map(|m| m.since_seq),
                        "move_lifted": record.map(|m| m.move_lifted),
                        "schema_tables": schema::tables(self.sql())?,
                    }))
                });
            }
            _ => {}
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
        if call.op.reservation_call() {
            return self.reservation(call, &head, now);
        }
        // A job call (W2-jobs): only from the consumer, authenticated,
        // with the job's numbers (checked above as a job's); it runs in
        // any tenant state but a shred.
        if let UnitOp::Job { .. } = &call.op {
            if call.kind != CallKind::Job || !call.authenticated {
                return Ok(refused(Refused::Unauthenticated, false));
            }
            if matches!(
                head.tenant_state,
                TenantState::Shredding | TenantState::Shredded
            ) {
                return Ok(refused(Refused::AccountProblem, false));
            }
            return self.run(call, &head, false, now);
        }
        // A fan-out read names a grant: it is never a cold read, so it
        // is refused without `authenticated` (rule 11).
        if !call.authenticated && (!call.op.read_only() || call.kind == CallKind::Fanout) {
            return Ok(refused(Refused::Unauthenticated, false));
        }
        // The tenant's state decides an authenticated call here. An
        // unauthenticated read gets the state with its answer, and the
        // Worker applies it after the signature verified.
        if call.authenticated && !allows(&head, call.op.is_read()) {
            return Ok(refused(Refused::AccountProblem, false));
        }
        if call.kind == CallKind::Fanout
            && !matches!(
                call.op,
                UnitOp::ReadPlan {
                    reader: Some(_),
                    generation: Some(_),
                    ..
                }
            )
        {
            // A fan-out call is a piece of a granted read, whatever its
            // numbers: it names its reader and the generation its grant
            // was made for. With lower numbers it is served only while
            // the unit's own tables still allow the reader.
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
            UnitOp::Ping {} => Ok(Ok(state)),
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
                generation: named,
            } => {
                // A fan-out piece reads the generation its grant names.
                if reader.is_some() && named.is_none() {
                    return Ok(Err(Refused::AccessDenied));
                }
                let Some(b) = self.cat.bucket_by_name(bucket).await? else {
                    // A missing bucket is decided by the Worker after the
                    // signature (a missing bucket and a missing
                    // grant both answer AccessDenied), so the answer
                    // carries the key row like any other. A fan-out read
                    // was granted on a bucket that is gone.
                    if fanout_check {
                        return Ok(Err(Refused::AccessDenied));
                    }
                    let key_row = match access_key_id {
                        Some(akid) => Some(self.cat.access_key(akid).await?.as_ref().map_or(
                            Value::Null,
                            |row| json!({ "key": key_json(row), "grant": Value::Null }),
                        )),
                        None => None,
                    };
                    return Ok(Ok(json!({
                        "bucket": Value::Null,
                        "generation": Value::Null,
                        "key_row": key_row,
                        "state": state,
                    })));
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
                let generation = match named {
                    Some(g) => self
                        .cat
                        .generation_by_id(&b.id, &GenerationId::new(g.as_str()))
                        .await?
                        .map(|(_, g)| g)
                        // The generation named is one of this key's.
                        .filter(|g| g.key == *key),
                    None => self.cat.live_generation(&b.id, key).await?,
                };
                let Some(generation) = generation else {
                    return Ok(Ok(json!({
                        "bucket": b.id.as_str(),
                        "generation": Value::Null,
                        "key_row": key_row,
                        "state": state,
                    })));
                };
                // An empty range holds no extent (and stamps none).
                let extents = if start < end {
                    self.cat.extents_in(&generation.id, *start, *end).await?
                } else {
                    Vec::new()
                };
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
            UnitOp::Job { call } => {
                // The stamp row of a unit carries its own name (ADR §8.5):
                // a Worker configured with another id raises nothing here.
                if call
                    .stamp_id()
                    .is_some_and(|id| id != super::jobcall::stamp_id(&self.own))
                {
                    return Err(crate::stamp::ERR_CATALOGUE_ID);
                }
                Ok(Ok(call.clone().run(&self.cat).await?))
            }
            UnitOp::Provision { .. }
            | UnitOp::Sync { .. }
            | UnitOp::ApplyKeys { .. }
            | UnitOp::HeldKeys {}
            | UnitOp::Import { .. }
            | UnitOp::ImportProgress {}
            | UnitOp::ImportSeal { .. }
            | UnitOp::Export { .. }
            | UnitOp::RestorePrepare { .. }
            | UnitOp::Restore { .. }
            | UnitOp::GateOpen { .. }
            | UnitOp::GateOpenMove { .. }
            | UnitOp::GateReport { .. }
            | UnitOp::GateBlockers { .. }
            | UnitOp::GateAck { .. }
            | UnitOp::GateStatus {}
            | UnitOp::Recount { .. }
            | UnitOp::Reserve { .. }
            | UnitOp::ResolveActing { .. }
            | UnitOp::Release { .. }
            | UnitOp::BindBucket { .. }
            | UnitOp::ReleaseBound { .. }
            | UnitOp::BucketBinding { .. } => {
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

    /// A gate call that writes: one transaction; a refusal keeps nothing.
    fn gate_write(
        &self,
        head: &Head,
        f: &mut dyn FnMut() -> Result<std::result::Result<Value, GateRefusal>>,
    ) -> Result<UnitAnswer> {
        let mut op = || Ok(f()?.map_err(Refused::Gate));
        Ok(match transact(self.sql(), true, &mut op)? {
            Ok(body) => UnitAnswer::Ok {
                seqs: head.seqs,
                body,
            },
            Err(reason) => refused(reason, false),
        })
    }

    /// The restore calls (AM-2): the unit's own checks 1 to 3, read-only,
    /// and what the object class does next with its storage
    /// ([`restore::drive`]). Every other call is answered as by
    /// [`Unit::handle`].
    pub fn pitr_step(&self, call: &UnitCall, now: UnixMs) -> PitrStep {
        match self.pitr_checks(call, now) {
            Ok(step) => step,
            Err(e) => PitrStep::Answer(failed(&e)),
        }
    }

    fn pitr_checks(&self, call: &UnitCall, now: UnixMs) -> Result<PitrStep> {
        let (since, restore) = match &call.op {
            UnitOp::RestorePrepare { since } => (*since, None),
            UnitOp::Restore {
                token,
                target,
                expect_undo,
            } => (token.record_seq, Some((token, target, expect_undo))),
            _ => return Ok(PitrStep::Answer(self.handle(call, now))),
        };
        if call.name != self.own {
            return Ok(PitrStep::Answer(refused(
                Refused::Identity(identity::Refusal::WrongName),
                true,
            )));
        }
        match self.born()? {
            None => {
                return Ok(PitrStep::Answer(UnitAnswer::Unborn {
                    listed: call.listed,
                }))
            }
            Some(cert) if cert != self.own => {
                return Ok(PitrStep::Answer(refused(
                    Refused::Identity(identity::Refusal::WrongName),
                    true,
                )))
            }
            Some(_) => {}
        }
        if call.kind != CallKind::Worker {
            return Ok(PitrStep::Answer(refused(Refused::Unauthenticated, false)));
        }
        let head = self.head()?;
        let no = |r: RestoreRefusal| Ok(PitrStep::Answer(refused(Refused::Restore(r), false)));
        if let Some((token, _, expect_undo)) = restore {
            // The token is a restore certificate for this unit and this
            // entry; the Worker verified its seal.
            let ours = token.kind == BirthKind::Restore
                && check_token(
                    &self.own,
                    &self.jurisdiction,
                    token,
                    Some(head.seqs.state_seq),
                )
                .is_ok();
            if !ours {
                return no(RestoreRefusal::WrongToken);
            }
            if expect_undo.0.is_empty() || expect_undo.0.len() > restore::MAX_BOOKMARK {
                return no(RestoreRefusal::Malformed);
            }
        }
        if let Some((_, restore::RestoreTarget::Bookmark { bookmark }, _)) = &restore {
            if bookmark.0.is_empty() || bookmark.0.len() > restore::MAX_BOOKMARK {
                return no(RestoreRefusal::Malformed);
            }
        }
        // AM-46: no undo bookmark while an import is not lifted, so no
        // bookmark from before the move's lift can exist. `restore` needs
        // the bookmark `restore_prepare` answered, so it is refused too.
        if import::unlifted_import(self.sql())? {
            return no(RestoreRefusal::MoveNotLifted);
        }
        // Open (design question, 4c review): between the close by a
        // move's entry and its first batch there is no move record, and
        // the unit cannot tell that entry from a restore's, so an undo
        // bookmark can still be taken in that span.
        let born_at = self.born_at()?;
        if let Some((_, restore::RestoreTarget::Time { at_ms }, _)) = &restore {
            // Never back into the owner move's window: a time before the
            // move's lift would bring back its unused seal. The lift's
            // time is the call's clock, a little before its commit: a
            // margin covers it.
            if import::move_lifted_at(self.sql())?
                .is_some_and(|lifted| *at_ms < lifted.saturating_add(restore::LIFT_SLACK_MS))
            {
                return no(RestoreRefusal::BeforeMoveLift);
            }
            // Never back before this incarnation's birth (AM-46), with the
            // same margin: the birth's time is its call's clock too.
            if *at_ms < born_at.saturating_add(restore::LIFT_SLACK_MS) {
                return no(RestoreRefusal::BeforeBirth);
            }
        }
        let lease = restore::lease_view(self.sql())?;
        if let Err(r) =
            restore::closed_long_enough(head.restoring_since, head.closed_at, lease, since, now)
        {
            return no(r);
        }
        Ok(match restore {
            None => PitrStep::Prepare { seqs: head.seqs },
            Some((_, target, expect_undo)) => PitrStep::Restore {
                target: target.clone(),
                expect_undo: expect_undo.clone(),
            },
        })
    }

    /// A Worker call that only reads: run as an unauthenticated
    /// transaction, so a write in it is refused and rolled back.
    fn read_only(&self, head: &Head, f: &mut dyn FnMut() -> Result<Value>) -> Result<UnitAnswer> {
        let mut op = || f().map(Ok);
        Ok(match transact(self.sql(), false, &mut op)? {
            Ok(body) => UnitAnswer::Ok {
                seqs: head.seqs,
                body,
            },
            Err(reason) => refused(reason, true),
        })
    }

    /// The key-chain apply (AM-12): [`keys::apply`], then the unit's
    /// `keys_seq`, in one transaction.
    fn apply_keys(
        &self,
        head: &Head,
        from_seq: u64,
        entries: &[KeyEntry],
        answers: &[KeptAnswer],
        now: UnixMs,
    ) -> Result<UnitAnswer> {
        let sql = self.sql();
        let mut behind = false;
        let mut now_seqs = head.seqs;
        let mut op = || -> Result<std::result::Result<Value, Refused>> {
            match keys::apply(
                sql,
                head.seqs.keys_seq,
                from_seq,
                entries,
                self.own.tenant.is_zero(),
                answers,
                now,
            )? {
                Applied::Behind { .. } => {
                    behind = true;
                    Ok(Ok(Value::Null))
                }
                Applied::Refused(r) => Ok(Err(Refused::Keys(r))),
                Applied::Done {
                    keys_seq,
                    applied,
                    skipped,
                    reserved,
                    kept,
                } => {
                    let n = poll_once(sql.exec(
                        "UPDATE unit_head SET keys_seq = ?1 WHERE id = 1",
                        &[int_param(keys_seq)?],
                    ))??;
                    if n != 1 {
                        return Err(decode("unit_head"));
                    }
                    now_seqs = self.head()?.seqs;
                    Ok(Ok(json!({
                        "applied": applied,
                        "skipped": skipped,
                        "revoked": keys::revoked(sql)?,
                        "reserved": reserved,
                        "answers_kept": kept,
                    })))
                }
            }
        };
        let out = transact(sql, true, &mut op)?;
        if behind {
            return Ok(UnitAnswer::KeysBehind { seqs: head.seqs });
        }
        Ok(match out {
            Ok(body) => UnitAnswer::Ok {
                seqs: now_seqs,
                body,
            },
            Err(reason) => refused(reason, false),
        })
    }

    /// One import batch (DS1 §2.3): bound to the move, then
    /// [`import::apply`] in one transaction.
    fn import(
        &self,
        call: &UnitCall,
        head: &Head,
        mover: &MoveHead,
        since: u64,
        batch: &ImportBatch,
    ) -> Result<UnitAnswer> {
        if let Some(answer) = self.move_numbers(call, head) {
            return Ok(answer);
        }
        // A sealed import takes no batch, under any entry: its own code,
        // so a resumed copy knows the import is done (AM-29).
        if import::sealed(self.sql())?.is_some() {
            return Ok(refused(Refused::Import(ImportRefusal::Sealed), false));
        }
        if !import::bound_to_move(
            &self.own.tenant,
            self.own.unit,
            head.restoring_since,
            since,
            mover,
        ) {
            return Ok(refused(Refused::Import(ImportRefusal::NotBound), true));
        }
        let sql = self.sql();
        let adding = if batch.table == ImportTable::Extents {
            batch.rows.len() as u64
        } else {
            0
        };
        let database_size = sql.database_size()?;
        let mut op = || -> Result<std::result::Result<Value, Refused>> {
            // The size guard (ADR §2.6): a batch never takes a full unit.
            if let Err(r) = size::admit(sql, self.size, database_size, adding)? {
                return Ok(Err(Refused::Size(r)));
            }
            match import::apply(sql, since, mover, batch)? {
                Imported::Refused(r) => Ok(Err(Refused::Import(r))),
                Imported::Done {
                    cursor,
                    rows,
                    applied,
                } => {
                    if applied && batch.table == ImportTable::Buckets {
                        let ids: Vec<String> = batch
                            .rows
                            .iter()
                            .filter_map(|r| match r.first() {
                                Some(import::ImportValue::Text(id)) => Some(id.clone()),
                                _ => None,
                            })
                            .collect();
                        keys::project_buckets(sql, &ids)?;
                    }
                    Ok(Ok(json!({
                        "table": batch.table.name(),
                        "cursor": cursor,
                        "rows": rows,
                        "applied": applied,
                    })))
                }
            }
        };
        Ok(match transact(sql, true, &mut op)? {
            Ok(body) => UnitAnswer::Ok {
                seqs: head.seqs,
                body,
            },
            Err(reason) => {
                let alarm = matches!(
                    reason,
                    Refused::Import(ImportRefusal::NotBound) | Refused::Size(_)
                );
                refused(reason, alarm)
            }
        })
    }

    /// `Recount` (AM-27): bound as [`recount::bound`] says, then one step
    /// of the catalogue's recount, in one transaction.
    fn recount(
        &self,
        call: &UnitCall,
        head: &Head,
        step: &RecountCall,
        mover: Option<&MoveHead>,
        now: UnixMs,
    ) -> Result<UnitAnswer> {
        // It writes: only an authenticated Worker call (rule 11).
        if !call.authenticated {
            return Ok(refused(Refused::Unauthenticated, false));
        }
        if recount::is_move(self.sql(), head.restoring_since)? {
            if let Some(answer) = self.move_numbers(call, head) {
                return Ok(answer);
            }
        }
        let sql = self.sql();
        let mut op = || -> Result<std::result::Result<Value, Refused>> {
            if let Err(r) = recount::bound(
                sql,
                &self.own.tenant,
                self.own.unit,
                head.restoring_since,
                mover,
            )? {
                return Ok(Err(Refused::Recount(r)));
            }
            let mut body = match step {
                RecountCall::Start {} => {
                    let started = poll_once(self.cat.usage_recount_start(now, true, true, false))??;
                    json!({ "started": started })
                }
                RecountCall::Step { chunk } => {
                    serde_json::to_value(poll_once(self.cat.usage_recount_step(*chunk, now))??)
                        .map_err(|_| BridgeError::Invalid("unit: recount step"))?
                }
            };
            body["counters_on"] = json!(lift::counters_on(sql)?);
            Ok(Ok(body))
        };
        Ok(match transact(sql, true, &mut op)? {
            Ok(body) => UnitAnswer::Ok {
                seqs: head.seqs,
                body,
            },
            Err(reason) => refused(reason, false),
        })
    }

    /// The reservation calls (ADR §2.5 step 0, AM-35, AM-38), on an open
    /// unit, `authenticated`. An opening ask needs an active tenant (a
    /// hold or a deletion refuses opening writes only); a release, a bind
    /// and the finisher's binding read run in any state.
    fn reservation(&self, call: &UnitCall, head: &Head, now: UnixMs) -> Result<UnitAnswer> {
        if !call.authenticated {
            return Ok(refused(Refused::Unauthenticated, false));
        }
        let sql = self.sql();
        let ok = |body| UnitAnswer::Ok {
            seqs: head.seqs,
            body,
        };
        if let UnitOp::ResolveActing { acting } = &call.op {
            // Read-only: run as an unauthenticated transaction, so a write
            // in it is refused and rolled back.
            let mut op = || {
                Ok(reserve::resolve(sql, acting)?
                    .map(|p| json!({ "principal": p }))
                    .map_err(Refused::Reserve))
            };
            return Ok(match transact(sql, false, &mut op)? {
                Ok(body) => ok(body),
                Err(reason) => {
                    let alarm = matches!(
                        reason,
                        Refused::WroteWithoutAuthentication
                            | Refused::AwaitedInside
                            | Refused::Reserve(reserve::ReserveRefusal::OwnerRefAmbiguous)
                    );
                    refused(reason, alarm)
                }
            });
        }
        if let UnitOp::Reserve {
            key_hash,
            fingerprint,
            rid,
            acting,
            opening,
        } = &call.op
        {
            // A shred refuses everything; a hold or a deletion refuses
            // only what keeps a reservation (`may_open`).
            if matches!(
                head.tenant_state,
                TenantState::Shredding | TenantState::Shredded
            ) {
                return Ok(refused(Refused::AccountProblem, false));
            }
            let may_open = head.tenant_state == TenantState::Active;
            let ask = Ask {
                key_hash,
                fingerprint,
                rid,
                acting: acting.as_ref(),
                opening,
            };
            let mut outcome = None;
            let mut op = || -> Result<std::result::Result<Value, Refused>> {
                let admit = reserve::admit(sql, head.seqs.keys_seq, may_open, &ask, now)?;
                let body = admit.body();
                outcome = Some(admit.clone());
                Ok(match (admit, body) {
                    (_, Some(body)) => Ok(body),
                    (Admit::Refused(r) | Admit::RefusedDrop(r, _), None) => {
                        Err(Refused::Reserve(r))
                    }
                    (Admit::NotOpen { .. }, None) => Err(Refused::AccountProblem),
                    (_, None) => Err(Refused::Reserve(reserve::ReserveRefusal::Malformed)),
                })
            };
            let out = transact(sql, true, &mut op)?;
            // A re-ask that failed at the head leaves no row (§2.5 (c)):
            // the drop is its own transaction, as the refusal rolled the
            // ask back.
            if let Some(Admit::RefusedDrop(_, rid)) = outcome {
                let mut drop = || {
                    Ok(Ok(
                        json!({ "released": reserve::release(sql, &rid, false)? }),
                    ))
                };
                // Dropped, or already gone: either way no row is left.
                let _ = transact(sql, true, &mut drop)?;
            }
            return Ok(match out {
                Ok(body) => ok(body),
                Err(reason) => {
                    let alarm =
                        reason == Refused::Reserve(reserve::ReserveRefusal::OwnerRefAmbiguous);
                    refused(reason, alarm)
                }
            });
        }
        let mut op = || -> Result<std::result::Result<Value, Refused>> {
            Ok(Ok(match &call.op {
                UnitOp::Release { rid } => {
                    json!({ "released": reserve::release(sql, rid, true)? })
                }
                UnitOp::BindBucket {
                    rid,
                    expected,
                    grant_seq,
                } => json!({ "bound": reserve::bind_bucket(sql, rid, *expected, *grant_seq)? }),
                UnitOp::ReleaseBound { rid, bound } => {
                    json!({ "released": reserve::release_bound(sql, rid, *bound)? })
                }
                UnitOp::BucketBinding { grant_seq } => {
                    reserve::bucket_binding(sql, *grant_seq)?.body()
                }
                _ => return Err(BridgeError::Invalid("not a reservation call")),
            }))
        };
        Ok(match transact(sql, true, &mut op)? {
            Ok(body) => ok(body),
            Err(reason) => refused(reason, false),
        })
    }

    /// The caller's numbers of a move call (an import batch, the seal, the
    /// `move` report), judged as a job's: equal, or the answer to give.
    fn move_numbers(&self, call: &UnitCall, head: &Head) -> Option<UnitAnswer> {
        match identity::check(&self.own, head.seqs, &call.name, CallKind::Job, call.seqs) {
            Verdict::Proceed => None,
            Verdict::SyncNeeded => Some(UnitAnswer::SyncNeeded { seqs: head.seqs }),
            Verdict::Refused { reason, alarm } => Some(refused(Refused::Identity(reason), alarm)),
            Verdict::Stale | Verdict::FanoutCheck => Some(refused(
                Refused::Identity(identity::Refusal::StaleJob),
                false,
            )),
        }
    }

    /// The unit is the root unit of a tenant other than tenant 0: the only
    /// unit a move fills and a `move` report lifts.
    fn managed_root(&self) -> bool {
        !self.own.tenant.is_zero() && self.own.unit == 0
    }

    /// The import's seal (AM-29): bound and numbered as a batch, then
    /// [`import::seal`] in one transaction.
    fn import_seal(
        &self,
        call: &UnitCall,
        head: &Head,
        mover: &MoveHead,
        since: u64,
        tables: &[ImportCount],
    ) -> Result<UnitAnswer> {
        if let Some(answer) = self.move_numbers(call, head) {
            return Ok(answer);
        }
        if !import::bound_to_move(
            &self.own.tenant,
            self.own.unit,
            head.restoring_since,
            since,
            mover,
        ) {
            return Ok(refused(Refused::Import(ImportRefusal::NotBound), true));
        }
        let sql = self.sql();
        let mut op = || -> Result<std::result::Result<Value, Refused>> {
            Ok(match import::seal(sql, since, mover, tables)? {
                Seal::Done {
                    move_ordinal,
                    newly,
                } => Ok(json!({ "sealed": move_ordinal, "newly": newly })),
                Seal::Refused(r) => Err(Refused::Import(r)),
            })
        };
        Ok(match transact(sql, true, &mut op)? {
            Ok(body) => UnitAnswer::Ok {
                seqs: head.seqs,
                body,
            },
            Err(reason) => {
                let alarm = reason == Refused::Import(ImportRefusal::NotBound);
                refused(reason, alarm)
            }
        })
    }

    /// `export` (AM-26): read-only, refused unless the unit is closed.
    fn export(
        &self,
        head: &Head,
        table: ExportTable,
        after: Option<&[ImportValue]>,
        limit: u32,
        mode: ExportMode,
    ) -> Result<UnitAnswer> {
        let sql = self.sql();
        let mut op = || {
            Ok(
                export::export(sql, head.restoring_since, table, after, limit, mode)?
                    .map_err(Refused::Export),
            )
        };
        Ok(match transact(sql, false, &mut op)? {
            Ok(body) => UnitAnswer::Ok {
                seqs: head.seqs,
                body,
            },
            Err(reason) => {
                let alarm = matches!(
                    reason,
                    Refused::WroteWithoutAuthentication | Refused::AwaitedInside
                );
                refused(reason, alarm)
            }
        })
    }

    /// `sync` (rule 5): copies a verified record. Numbers never go back.
    /// The key records themselves are applied by the key-chain apply; until
    /// it exists here, a `keys_seq` above the unit's is refused, so the
    /// unit never claims a key table it does not hold.
    fn sync(&self, head: &Head, next: &SyncHead, now: UnixMs) -> Result<UnitAnswer> {
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
        // The entry's close time: kept while the same entry stays, the
        // unit's clock when an entry is set (or changed), none once
        // cleared.
        let closed_at = match (head.restoring_since, next.restoring_since) {
            (_, None) => None,
            (Some(was), Some(s)) if was == s => head.closed_at.or(Some(now.0)),
            (_, Some(_)) => Some(now.0),
        };
        let lifting = head.restoring_since.is_some() && next.restoring_since.is_none();
        let mut synced = None;
        let mut why = None;
        let mut run = || -> Result<()> {
            if lifting {
                // AM-2: the entry is cleared only on the unit's own lift
                // check, against the report of this restore's replay.
                if let Err(r) = lift::check_named(
                    sql,
                    self.managed_root(),
                    head.restoring_since,
                    next.lift.as_ref(),
                )? {
                    why = Some(r);
                    return Err(BridgeError::Invalid(ROLLBACK));
                }
                lift::lifted(sql, now)?;
            }
            let n = poll_once(sql.exec(
                "UPDATE unit_head SET state_seq = ?1, tenant_state = ?2, tenant_mode = ?3, \
                   restoring_since = ?4, closed_at = ?5 WHERE id = 1",
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
                    closed_at.map_or(SqlValue::Null, SqlValue::Int),
                ],
            ))??;
            if n != 1 {
                return Err(decode("unit_head"));
            }
            // Read inside the call, as in `provision`.
            synced = Some(self.head()?);
            Ok(())
        };
        match sql.atomically(&mut run) {
            Err(BridgeError::Invalid(ROLLBACK)) => {
                let r = why.ok_or(BridgeError::Invalid("rollback without a reason"))?;
                return Ok(refused(Refused::Gate(r), false));
            }
            other => other?,
        }
        let head = synced.ok_or_else(|| decode("unit_head"))?;
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

/// What the tenant's state lets an S3 call do (`docs/units.md`).
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

/// The message of the key-scheme triggers (rule 13, `u0006`): a wrap of
/// the other scheme. The unit answers it as its own failure class, and
/// the Worker pages (ADR §3.2: an error and an alarm, never a fallback).
pub const KEY_SCHEME: &str = "unit: key scheme";

fn failed(e: &BridgeError) -> UnitAnswer {
    let class = match e {
        BridgeError::Sql(m) if m.contains(KEY_SCHEME) => "key_scheme",
        BridgeError::Sql(_) => "sql",
        BridgeError::GuardFailed => "guard",
        e if crate::stamp::is_catalogue_id_error(e) => "catalogue_id",
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
