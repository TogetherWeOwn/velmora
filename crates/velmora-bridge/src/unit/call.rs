//! A call to a unit and its answer, as they cross `fetch`
//! (`docs/units.md`, rules 1, 5, 7, 11).
//!
//! Both are JSON. A call names the unit it is for, who makes it, the
//! chain numbers the caller knows, whether the Worker has verified the
//! caller (`authenticated`, rule 11), whether a record lists the unit
//! (`listed`, rule 7), and one operation. Unknown fields are refused, so
//! a newer Worker cannot slip a field past an older unit.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::birth::{BirthToken, ProvisionRefusal};
use super::export::{ExportMode, ExportRefusal, ExportTable};
use super::identity::{CallKind, Refusal, Seqs};
use super::import::{ImportBatch, ImportCount, ImportRefusal, ImportValue, MoveHead};
use super::jobcall::JobCall;
use super::keys::{KeptAnswer, KeyEntry, KeyRefusal};
use super::lift::{AckClass, FindingList, GateRefusal, GateSummary, LiftProof, ReplayId};
use super::name::UnitName;
use super::recount::{RecountCall, RecountRefusal};
use super::reserve::{Acting, Hash32, Opening, ReserveRefusal, Rid};
use super::restore::{Bookmark, RestoreRefusal, RestoreTarget};
use super::size::SizeRefusal;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitCall {
    pub name: UnitName,
    pub kind: CallKind,
    #[serde(default)]
    pub seqs: Option<Seqs>,
    /// Set by the Worker only after SigV4, the service token or a fan-out
    /// grant verified. Without it the call is read-only (rule 11).
    #[serde(default)]
    pub authenticated: bool,
    /// The Worker reached this unit through a record that lists it. An
    /// unborn unit answers so, and the Worker pages "catalogue lost"
    /// (rule 7); without it an unborn unit is a name nobody made.
    #[serde(default)]
    pub listed: bool,
    pub op: UnitOp,
}

/// What a verified tenant record says, as `sync` copies it into the unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncHead {
    pub seqs: Seqs,
    pub tenant_state: TenantState,
    /// `read_only` or `locked` while the state is `suspended`, else none.
    #[serde(default)]
    pub tenant_mode: Option<HoldMode>,
    /// The since_seq of this unit's `restoring` entry, if the record has one.
    #[serde(default)]
    pub restoring_since: Option<u64>,
    /// The lift a record that removes this unit's entry carries (its
    /// replay id, and per class the count and hash of the acknowledged
    /// ids): the unit lifts only when its own check gives the same.
    #[serde(default)]
    pub lift: Option<LiftProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    Provisioning,
    Active,
    Suspended,
    Deleting,
    Shredding,
    Shredded,
}

impl TenantState {
    pub fn as_str(self) -> &'static str {
        match self {
            TenantState::Provisioning => "provisioning",
            TenantState::Active => "active",
            TenantState::Suspended => "suspended",
            TenantState::Deleting => "deleting",
            TenantState::Shredding => "shredding",
            TenantState::Shredded => "shredded",
        }
    }

    pub fn parse(s: &str) -> Option<TenantState> {
        Some(match s {
            "provisioning" => TenantState::Provisioning,
            "active" => TenantState::Active,
            "suspended" => TenantState::Suspended,
            "deleting" => TenantState::Deleting,
            "shredding" => TenantState::Shredding,
            "shredded" => TenantState::Shredded,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldMode {
    ReadOnly,
    Locked,
}

impl HoldMode {
    pub fn as_str(self) -> &'static str {
        match self {
            HoldMode::ReadOnly => "read_only",
            HoldMode::Locked => "locked",
        }
    }

    pub fn parse(s: &str) -> Option<HoldMode> {
        match s {
            "read_only" => Some(HoldMode::ReadOnly),
            "locked" => Some(HoldMode::Locked),
            _ => None,
        }
    }
}

/// Who a fan-out sub-request reads for (rule 5, the fan-out case).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Reader {
    /// An access key; its grant must still cover the bucket.
    Key { access_key_id: String },
    /// A public read; the bucket must still be public.
    Public,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnitOp {
    /// Makes the unit (rule 6). A Worker call. `sealed`: the token as
    /// sealed under the control key, verified by the Worker; the unit
    /// stores it.
    Provision {
        token: BirthToken,
        #[serde(with = "b64")]
        sealed: Vec<u8>,
    },
    /// Copies a verified tenant record into the unit (rule 5). A Worker
    /// call.
    Sync { head: SyncHead },
    /// The unit's numbers and state, and nothing else. A struct variant,
    /// so that an unknown field next to it is refused.
    Ping {},
    /// The key row of an access key: the first of the two calls of a cold
    /// isolate. Allowed without `authenticated`.
    KeyRow { access_key_id: String },
    /// The key-chain apply (AM-12): the records after `from_seq`, one
    /// entry per record, in chain order. A Worker call: the entries are
    /// records the Worker verified. It runs while the unit is closed too
    /// (a restore re-applies the chain at its gate).
    ApplyKeys {
        from_seq: u64,
        entries: Vec<KeyEntry>,
        /// The answers to keep for the reservations whose records these
        /// are (AM-38).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        answers: Vec<KeptAnswer>,
    },
    /// The subjects the unit holds closed (`KeyTarget::closed`). A
    /// Worker call.
    HeldKeys {},
    /// One batch of the owner move's import (DS1 §2.3). A Worker call
    /// that also carries the caller's numbers, judged as a job's are.
    /// `head`: tenant 0's verified head; `since`: the `since_seq` of the
    /// unit's `restoring` entry the import fills.
    Import {
        head: MoveHead,
        since: u64,
        batch: ImportBatch,
    },
    /// Every table's import cursor and row count, and whether the import
    /// is final. A Worker call.
    ImportProgress {},
    /// Seals the import (AM-29): `tables` names every import table once
    /// with the rows the unit took. Bound and numbered as an import
    /// batch; records `move_ordinal` = the head's `flips + 1`; after it no
    /// batch is taken. A Worker call.
    ImportSeal {
        head: MoveHead,
        since: u64,
        tables: Vec<ImportCount>,
    },
    /// Pages one table's rows, read-only, while the unit is closed
    /// (AM-26): `hash` answers a digest, `rows` the rows (not on the key
    /// tables). `after`: the key of the last row of the page before. A
    /// Worker call.
    Export {
        table: ExportTable,
        #[serde(default)]
        after: Option<Vec<ImportValue>>,
        limit: u32,
        mode: ExportMode,
    },
    /// The first of the two restore calls (AM-2): refused unless the unit
    /// is closed under the entry at `since` long enough; answers the undo
    /// bookmark. A Worker call, run by the object class (it needs the
    /// object's storage).
    RestorePrepare { since: u64 },
    /// The second restore call (AM-2): refused unless the unit is closed
    /// under the token's entry long enough and still at `expect_undo`;
    /// then restores to `target` and restarts. A Worker call, run by the
    /// object class. It never answers `ok`.
    Restore {
        token: BirthToken,
        target: RestoreTarget,
        expect_undo: Bookmark,
    },
    /// Starts the gate report of one replay, discarding any other.
    GateOpen { replay_id: ReplayId },
    /// Starts the owner move's lift report (AM-15), discarding any other:
    /// only under the import's binding, with tenant 0's verified head;
    /// numbered as an import batch.
    GateOpenMove { replay_id: ReplayId, head: MoveHead },
    /// What that replay found besides its id lists.
    GateReport {
        replay_id: ReplayId,
        summary: GateSummary,
    },
    /// One page of ids of one list of that replay's findings.
    GateBlockers {
        replay_id: ReplayId,
        list: FindingList,
        ids: Vec<String>,
    },
    /// One page of acknowledged blocker ids of one class.
    GateAck {
        replay_id: ReplayId,
        class: AckClass,
        ids: Vec<String>,
    },
    /// The stored report and whether a lift would pass now, with the
    /// counts and hashes for the lift record. A Worker call.
    GateStatus {},
    /// One step of the usage recount of a closed unit (AM-27): the
    /// restore gate's, or the move's with tenant 0's verified head,
    /// numbered as an import batch. A Worker call.
    Recount {
        call: RecountCall,
        #[serde(default)]
        head: Option<MoveHead>,
    },
    /// The reservation of a capped opening call (ADR §2.5 step 0, AM-38):
    /// the `Idempotency-Key`'s hash, the request's fingerprint, a fresh
    /// `rid` (kept only by a new reservation), the acting principal and
    /// the change. A Worker call, `authenticated`, on an open unit.
    Reserve {
        key_hash: Hash32,
        fingerprint: Hash32,
        rid: Rid,
        #[serde(default)]
        acting: Option<Acting>,
        opening: Opening,
    },
    /// The acting principal of `objects.list` and `objects.presign`
    /// (AM-35), read-only. A Worker call.
    ResolveActing { acting: Acting },
    /// Releases the `reserved` reservation `rid`. A Worker call.
    Release { rid: Rid },
    /// Binds the bucket reservation `rid` to the creator grant
    /// `grant_seq` while it is bound to `expected`. A Worker call.
    BindBucket {
        rid: Rid,
        #[serde(default)]
        expected: Option<u64>,
        grant_seq: u64,
    },
    /// Releases the bucket reservation `rid` while it is bound to
    /// `bound`. A Worker call.
    ReleaseBound {
        rid: Rid,
        #[serde(default)]
        bound: Option<u64>,
    },
    /// What the reservations say of the creator grant `grant_seq`; an
    /// answer of none fences it. A Worker call.
    BucketBinding { grant_seq: u64 },
    /// One catalogue method of the job path (W2-jobs). A `job` call:
    /// the job's numbers must equal the unit's, and it is
    /// `authenticated`.
    Job { call: JobCall },
    /// The read plan of a range of an object: the live generation (or
    /// the one named) and its extents in `[start, end)`. Allowed without
    /// `authenticated`, and then it writes nothing (no read stamp).
    /// `access_key_id`: the key row comes back with it (one call for a
    /// cold isolate's read). `reader`: set on a fan-out sub-request, which
    /// also names the `generation` its grant was made for, so that a piece
    /// of a large GET is read from the object the GET began on, not from
    /// one that replaced it since.
    ReadPlan {
        bucket: String,
        key: String,
        start: u64,
        end: u64,
        #[serde(default)]
        access_key_id: Option<String>,
        #[serde(default)]
        reader: Option<Reader>,
        #[serde(default)]
        generation: Option<String>,
    },
}

impl UnitOp {
    /// The two operations an unauthenticated call may run (rule 11).
    pub fn read_only(&self) -> bool {
        matches!(self, UnitOp::KeyRow { .. } | UnitOp::ReadPlan { .. })
    }

    /// The Worker's own calls: their content is a verified record, never
    /// a caller's input.
    pub fn worker_call(&self) -> bool {
        matches!(
            self,
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
                | UnitOp::BucketBinding { .. }
        )
    }

    /// The reservation calls (ADR §2.5 step 0): on an open unit only.
    pub fn reservation_call(&self) -> bool {
        matches!(
            self,
            UnitOp::Reserve { .. }
                | UnitOp::ResolveActing { .. }
                | UnitOp::Release { .. }
                | UnitOp::BindBucket { .. }
                | UnitOp::ReleaseBound { .. }
                | UnitOp::BucketBinding { .. }
        )
    }

    /// The two restore calls, which the object class runs with its
    /// storage.
    pub fn restore_call(&self) -> bool {
        matches!(self, UnitOp::RestorePrepare { .. } | UnitOp::Restore { .. })
    }

    /// A read, for the tenant-state rule (`read_only` serves
    /// reads only).
    pub fn is_read(&self) -> bool {
        matches!(
            self,
            UnitOp::Ping {} | UnitOp::KeyRow { .. } | UnitOp::ReadPlan { .. }
        )
    }
}

/// Why a unit is closed to a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Closed {
    /// The tenant record carries `restoring` for this unit: `503` until
    /// the restore gate lifts it.
    Restoring,
    /// The tenant is `provisioning`: `503`.
    Provisioning,
}

/// Why a call was refused, beyond the identity check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refused {
    Identity(Refusal),
    Provision(ProvisionRefusal),
    /// An operation that needs `authenticated` came without it.
    Unauthenticated,
    /// An unauthenticated call changed a row; it was rolled back. A bug
    /// in the unit, so the Worker pages.
    WroteWithoutAuthentication,
    /// A call waited on I/O inside the unit (rule 4); it was rolled back.
    AwaitedInside,
    /// `sync` carried numbers below the unit's own.
    StaleSync,
    /// `sync` carried a `keys_seq` above the unit's without the key
    /// records: the key-chain apply moves it, together with the rows.
    KeysNotApplied,
    /// The tenant's state does not allow this call: `403 AccountProblem`
    /// once the signature verified. On a reservation ask the Worker
    /// answers `409 tenant_read_only` or `409 tenant_unavailable` instead
    /// (`docs/units.md`, "Reservations").
    AccountProblem,
    /// The fan-out reader is no longer allowed (`403 AccessDenied`, as
    /// the full request would get).
    AccessDenied,
    /// The call names no object or bucket the unit holds.
    NotFound,
    /// The key-chain apply was refused (AM-12).
    Keys(KeyRefusal),
    /// An import batch was refused (DS1 §2.3).
    Import(ImportRefusal),
    /// A restore call was refused; nothing was armed (AM-2).
    Restore(RestoreRefusal),
    /// A gate call, or the `sync` that would lift, was refused (AM-2).
    Gate(GateRefusal),
    /// An export was refused (AM-26).
    Export(ExportRefusal),
    /// A recount was refused (AM-27).
    Recount(RecountRefusal),
    /// A reservation, or the read of an acting principal, was refused
    /// (ADR §2.5 step 0, AM-18, AM-35, AM-38).
    Reserve(ReserveRefusal),
    /// The size guard refused a call that adds extents (ADR §2.6).
    Size(SizeRefusal),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnitAnswer {
    Ok {
        seqs: Seqs,
        body: Value,
    },
    /// The caller knows a newer record (rule 5).
    SyncNeeded {
        seqs: Seqs,
    },
    /// The caller is behind; nothing was done (rule 5). A job runs once
    /// more with these numbers (AM-50).
    Stale {
        seqs: Seqs,
    },
    /// A key-chain apply whose base is above the unit's `keys_seq`:
    /// nothing was done; the caller reads again from `keys_seq + 1`
    /// (AM-12).
    KeysBehind {
        seqs: Seqs,
    },
    Refused {
        reason: Refused,
        alarm: bool,
    },
    /// `restore_prepare`: the undo bookmark. The tool seals it before it
    /// stores it anywhere (AM-1).
    UndoBookmark {
        seqs: Seqs,
        bookmark: Bookmark,
    },
    /// No certificate (rule 7). `listed`: as the call said; the Worker
    /// answers `503` and pages when it is set, `404` when not. The move
    /// tool's P12 read of `import_progress` sends `listed = false` where
    /// its verified heads say an unborn unit is expected.
    Unborn {
        listed: bool,
    },
    Closed {
        seqs: Seqs,
        why: Closed,
    },
    /// The unit failed; a class only.
    Failed {
        class: String,
    },
}

mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}
