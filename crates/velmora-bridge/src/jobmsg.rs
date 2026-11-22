//! The queue message of a job, in two formats.
//!
//! A [`Job`] names an outbox row; the message that carries it is one of
//! two formats:
//!
//! | `v` | Format | Written while |
//! |---|---|---|
//! | 1 | the [`Job`] as it is, byte for byte | `JOB_FORMAT` is `1` or unset |
//! | 2 | the same fields, and the tenant the job is for: `tenant`, `unit` (absent for a tenant whose catalogue is not a unit), `state_seq` and `keys_seq` | `JOB_FORMAT` is `2` |
//!
//! A consumer reads both ([`admit`]). The format is switched in three
//! steps, each one deploy with an undo of its own:
//!
//! 1. **The reader first.** This module, with `JOB_FORMAT` unset: every
//!    writer still sends `v` 1, byte for byte.
//! 2. **The writer switch.** A deploy that sets `JOB_FORMAT=2` and
//!    nothing else. Its undo sets it back to 1; both formats stay
//!    readable. While it is 2 a Worker from before step 1 must not be
//!    deployed: it drops every `v` 2 message as malformed. A job with an
//!    outbox row is then sent again by the dispatcher after the row's
//!    resend timeout. A job with no outbox row (an eviction step, a step
//!    of a recovery-copy pass, a copy hint) is lost, and its work waits
//!    for the next cron run or the next pass.
//! 3. **The default removed** (later): a `v` 1 message is refused. Only
//!    after the count of `v` 1 messages ([`FormatCount`]) has stayed at
//!    zero for a queue-retention period.
//!
//! The next change of a job's body takes `v` 3: a body of `v` 2 could not
//! be told from this format (a compile-time check holds it).
//!
//! # What is never run
//!
//! A `v` 2 message runs only for a tenant this Worker can serve. That is
//! tenant 0, whose catalogue is the D1 database: it has no unit, so its
//! message names none. When the Worker has the unit class bound
//! ([`Units::Bound`], [`admit_for`]; not in the production config), it
//! is also a managed tenant (a [`crate::unit::TenantId`] other than
//! tenant 0) whose message names its unit: the job runs in that tenant's
//! scope against its unit. A `v` 2 message with no tenant, with a
//! tenant this Worker cannot serve, with a unit for tenant 0, with no
//! unit for a managed tenant, or with fields this build does not know is
//! **refused** ([`Refusal`]): the consumer
//! hands it back to the queue until its deliveries are used up, so it
//! lands in the dead-letter queue, which pages (in production; the
//! dead-letter queues of `wrangler dev` and of drills have no consumer
//! that pages). It is never run under another tenant's scope, and it is
//! never dropped in silence ([`Admission::disposition`]).
//!
//! **The outbox row of a refused message is left as it is.** The
//! message's job never claims its row, so the dispatcher sends the row
//! again after its resend timeout, through the writer of the Worker that
//! runs then. That writer and the reader of the same build agree on
//! every message (a test holds it for every job), so the message sent
//! again runs. A refusal that comes back for one row means two builds
//! that disagree are deployed side by side, and it lasts as long as that
//! deploy does. The row is not marked: a refused message may name no
//! tenant, or another tenant, and the reader marks nothing in tenant 0's
//! catalogue on the word of such a message.
//!
//! Tenant 0's `state_seq` and `keys_seq` are carried and not checked:
//! the D1 catalogue has no identity check to make with them. A unit
//! will (a later package); until then the reader takes any value, so
//! that a later writer that sends tenant 0's real numbers is not
//! refused by this reader.
//!
//! A message of another `v` (neither 1 nor 2) is read as a [`Job`], as
//! before this module: `run_job` drops it and the outbox sends its row
//! again in the current format.
//!
//! A `v` 2 message whose kind (`t`) is none this build knows is refused
//! as [`Refusal::UnknownKind`], so the dead-letter queue says why.
//!
//! # Unit jobs
//!
//! Two kinds exist in format 2 only: [`UnitJob::Renew`] (a unit's alarm
//! asks the Worker to prove the unit's lease and renew it) and
//! [`UnitJob::StampRaise`] (the alarm's one raise of the unit's stamp per
//! period with writes). Only a unit writes them, so each names its
//! tenant **and** its unit; they have no `v` 1 form, and a `v` 1 message
//! of either kind is malformed, as before this module. Every reader from
//! this one on knows them ([`read_unit_job`]), long before a unit can
//! write one.
//!
//! A Worker with the unit class bound admits a well-formed one of a
//! managed tenant as [`Admission::Unit`]; the consumer runs it through
//! the unit client (`unit_consumer::deliver_unit_job`). It is refused
//! here as [`Refusal::OtherTenant`] for a unit of another tenant when the
//! unit class is not bound, [`Refusal::UnitOfTenantZero`] or
//! [`Refusal::NoUnit`] for tenant 0, and [`Refusal::BadBody`] when its
//! fields are not those of its kind. A lost
//! `renew` closes the unit when its lease runs out (an outage, never a
//! wrong answer); the alarm's backoff sends it again.
//!
//! # Inside the Worker
//!
//! The body of a `v` 2 message is the body of a `v` 1 message plus the
//! tenant fields. [`admit`] takes the tenant fields off and returns the
//! [`Job`] with `v` = [`JOB_VERSION`], so the job path, which runs only
//! that version, needs no change. `v` inside a [`Job`] is the version of
//! its body; the format of the message it came in is this module's
//! business alone.

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::tenant::TenantScope;
use crate::types::{ExtentId, GenerationId, Job, OutboxStage, UnixMs, WriteId, JOB_VERSION};

/// `v` of a message that names its tenant.
pub const TENANT_FORMAT_VERSION: u8 = 2;

// A body of the version of this format could not be told from it.
const _: () = assert!(JOB_VERSION < TENANT_FORMAT_VERSION);

/// The delay of the retry that hands a refused message back to its queue:
/// none, so that its deliveries are used up at once and it reaches the
/// dead-letter queue within seconds.
pub const REFUSED_RETRY_DELAY_SECS: u32 = 0;

/// Name of the configuration switch of the writers' format.
pub const JOB_FORMAT_VAR: &str = "JOB_FORMAT";

/// The kinds (`t`) of a [`Job`], in either format. It only names a
/// refusal (`unknown_kind` or `bad_body`): the parse alone decides what
/// runs, so a kind missing here cannot stop a job.
pub const JOB_KINDS: [&str; 6] = ["extent", "wake", "gc", "evict", "sweep", "recovery_copy"];

/// The kinds (`t`) of a [`UnitJob`]: format 2 only. No [`Job`] kind has
/// one of these names (a test holds it).
pub const UNIT_JOB_KINDS: [&str; 2] = ["renew", "stamp_raise"];

/// The four fields a `v` 2 message adds. A body field of a [`Job`] never
/// has one of these names (a test holds it).
pub const TENANT_FIELDS: [&str; 4] = ["tenant", "unit", "state_seq", "keys_seq"];

/// The format the writers send (`JOB_FORMAT`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JobFormat {
    /// `v` 1: the [`Job`] as it is. The default.
    #[default]
    Plain,
    /// `v` 2: the job and its tenant.
    Tenant,
}

impl JobFormat {
    /// `JOB_FORMAT`: unset, empty or `1` is [`JobFormat::Plain`], `2` is
    /// [`JobFormat::Tenant`]. Anything else is refused, so that a typo
    /// cannot leave the switch in a state nobody chose.
    pub fn from_var(raw: Option<&str>) -> std::result::Result<JobFormat, String> {
        match raw.map(str::trim) {
            None | Some("") | Some("1") => Ok(JobFormat::Plain),
            Some("2") => Ok(JobFormat::Tenant),
            Some(_) => Err(format!("invalid {JOB_FORMAT_VAR}: must be 1 or 2")),
        }
    }

    /// The message to send for `job`, of `tenant`. A job whose body is
    /// of another version than [`JOB_VERSION`] is sent as it is: only
    /// a current body is wrapped.
    pub fn message<'a>(self, job: &'a Job, tenant: &'a JobTenant) -> JobMessage<'a> {
        match self {
            JobFormat::Tenant if body_version(job) == JOB_VERSION => {
                JobMessage::Tenant(TenantMessage::of(job, tenant))
            }
            _ => JobMessage::Plain(job),
        }
    }
}

/// The tenant fields of a `v` 2 message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTenant {
    tenant: String,
    unit: Option<u32>,
    state_seq: u64,
    keys_seq: u64,
}

impl JobTenant {
    /// The fields for a job of `scope`. Tenant 0 has no unit, and no
    /// tenant chain or key chain yet: its numbers are 0. Tenant 0 is the
    /// only scope there is; a second one brings its unit and its numbers
    /// with it, and this function changes then.
    pub fn of(scope: &TenantScope) -> JobTenant {
        debug_assert!(scope.is_tenant_zero(), "a job tenant other than tenant 0");
        JobTenant {
            tenant: scope.tenant_id().to_string(),
            unit: None,
            state_seq: 0,
            keys_seq: 0,
        }
    }

    /// The fields for a job of `unit` of `tenant`, at the unit's
    /// `state_seq` and `keys_seq`. `None` for tenant 0, which has no
    /// unit, and for a name that is not a tenant id.
    pub fn of_unit(tenant: &str, unit: u32, state_seq: u64, keys_seq: u64) -> Option<JobTenant> {
        (crate::recovery::valid_tenant_id(tenant) && !is_unitless_tenant(tenant)).then(|| {
            JobTenant {
                tenant: tenant.to_string(),
                unit: Some(unit),
                state_seq,
                keys_seq,
            }
        })
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn unit(&self) -> Option<u32> {
        self.unit
    }

    pub fn state_seq(&self) -> u64 {
        self.state_seq
    }

    pub fn keys_seq(&self) -> u64 {
        self.keys_seq
    }
}

/// A message to send. It serialises as a plain object (a struct, never
/// a map), which is what a JSON queue message must be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobMessage<'a> {
    /// `v` 1.
    Plain(&'a Job),
    /// `v` 2.
    Tenant(TenantMessage<'a>),
}

impl JobMessage<'_> {
    /// The message as JSON text.
    pub fn to_json(&self) -> String {
        // Plain strings and integers only: it cannot fail.
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl Serialize for JobMessage<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            JobMessage::Plain(job) => job.serialize(s),
            JobMessage::Tenant(message) => message.serialize(s),
        }
    }
}

/// The body of a `v` 2 message: each variant of [`Job`] with the
/// tenant fields after its own. Every variant is a struct with the
/// fields written out, never `flatten`: a flattened struct serialises as
/// a map, and the Worker's queue binding turns a map into a JS `Map`,
/// which a JSON message sends as `{}` (a source test holds it). [`TenantMessage::of`] and
/// [`TenantMessage::into_job`] match every variant, so a variant added to
/// [`Job`] does not compile until it is added here too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum TenantMessage<'a> {
    Extent {
        v: u8,
        extent: &'a ExtentId,
        generation: &'a GenerationId,
        stage: OutboxStage,
        tenant: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<u32>,
        state_seq: u64,
        keys_seq: u64,
    },
    Wake {
        v: u8,
        extent: &'a ExtentId,
        generation: &'a GenerationId,
        stage: OutboxStage,
        at: UnixMs,
        tenant: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<u32>,
        state_seq: u64,
        keys_seq: u64,
    },
    Gc {
        v: u8,
        tenant: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<u32>,
        state_seq: u64,
        keys_seq: u64,
    },
    Evict {
        v: u8,
        remaining: u64,
        tenant: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<u32>,
        state_seq: u64,
        keys_seq: u64,
    },
    Sweep {
        v: u8,
        write: &'a WriteId,
        tenant: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<u32>,
        state_seq: u64,
        keys_seq: u64,
    },
    RecoveryCopy {
        v: u8,
        pass: UnixMs,
        cursor: &'a str,
        tenant: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<u32>,
        state_seq: u64,
        keys_seq: u64,
    },
}

impl<'a> TenantMessage<'a> {
    fn of(job: &'a Job, t: &'a JobTenant) -> TenantMessage<'a> {
        let v = TENANT_FORMAT_VERSION;
        let (tenant, unit, state_seq, keys_seq) =
            (t.tenant.as_str(), t.unit, t.state_seq, t.keys_seq);
        match job {
            Job::Extent {
                extent,
                generation,
                stage,
                ..
            } => TenantMessage::Extent {
                v,
                extent,
                generation,
                stage: *stage,
                tenant,
                unit,
                state_seq,
                keys_seq,
            },
            Job::Wake {
                extent,
                generation,
                stage,
                at,
                ..
            } => TenantMessage::Wake {
                v,
                extent,
                generation,
                stage: *stage,
                at: *at,
                tenant,
                unit,
                state_seq,
                keys_seq,
            },
            Job::Gc { .. } => TenantMessage::Gc {
                v,
                tenant,
                unit,
                state_seq,
                keys_seq,
            },
            Job::Evict { remaining, .. } => TenantMessage::Evict {
                v,
                remaining: *remaining,
                tenant,
                unit,
                state_seq,
                keys_seq,
            },
            Job::Sweep { write, .. } => TenantMessage::Sweep {
                v,
                write,
                tenant,
                unit,
                state_seq,
                keys_seq,
            },
            Job::RecoveryCopy { pass, cursor, .. } => TenantMessage::RecoveryCopy {
                v,
                pass: *pass,
                cursor,
                tenant,
                unit,
                state_seq,
                keys_seq,
            },
        }
    }
}

/// A job that only a unit sends, for itself: format 2 only. See the
/// [module](self#unit-jobs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitJob {
    /// Prove the unit's lease from the stores and renew it (ADR rule
    /// 12). `at` is the unit's clock when its alarm sent the job: a
    /// hint for the lag line only, never part of the proof, which starts
    /// at the Worker's own clock.
    Renew { at: UnixMs },
    /// Raise the unit's stamp once (§8.5). `at` as for `Renew`.
    StampRaise { at: UnixMs },
}

impl UnitJob {
    /// The message for this job of the unit of `tenant`, whatever
    /// `JOB_FORMAT` says: a unit job has no `v` 1 form. `None` when
    /// `tenant` names no unit ([`JobTenant::of_unit`] always names one).
    pub fn message(&self, tenant: &JobTenant) -> Option<String> {
        let unit = tenant.unit?;
        let (v, t) = (TENANT_FORMAT_VERSION, tenant.tenant.as_str());
        let (state_seq, keys_seq) = (tenant.state_seq, tenant.keys_seq);
        let message = match *self {
            UnitJob::Renew { at } => UnitMessage::Renew {
                v,
                at,
                tenant: t,
                unit,
                state_seq,
                keys_seq,
            },
            UnitJob::StampRaise { at } => UnitMessage::StampRaise {
                v,
                at,
                tenant: t,
                unit,
                state_seq,
                keys_seq,
            },
        };
        // Plain strings and integers only: it cannot fail.
        Some(serde_json::to_string(&message).unwrap_or_default())
    }
}

/// The bytes of a unit job: a struct per kind, never `flatten` (see
/// [`TenantMessage`]).
#[derive(Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum UnitMessage<'a> {
    Renew {
        v: u8,
        at: UnixMs,
        tenant: &'a str,
        unit: u32,
        state_seq: u64,
        keys_seq: u64,
    },
    StampRaise {
        v: u8,
        at: UnixMs,
        tenant: &'a str,
        unit: u32,
        state_seq: u64,
        keys_seq: u64,
    },
}

/// The body of a unit job without its tenant fields.
#[derive(Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
enum UnitBody {
    Renew {
        #[allow(dead_code)]
        v: u8,
        at: UnixMs,
    },
    StampRaise {
        #[allow(dead_code)]
        v: u8,
        at: UnixMs,
    },
}

/// Reads a unit job: a `v` 2 message of a kind in [`UNIT_JOB_KINDS`],
/// of a tenant other than tenant 0, naming its unit, with the fields of
/// its kind and nothing else. It says nothing of whether this Worker
/// serves that unit: [`admit`] decides that.
pub fn read_unit_job(body: &Value) -> std::result::Result<(UnitJob, JobTenant), Refusal> {
    let Some(fields) = body.as_object() else {
        return Err(Refusal::BadBody);
    };
    if fields.get("v").and_then(Value::as_u64) != Some(u64::from(TENANT_FORMAT_VERSION)) {
        return Err(Refusal::BadBody);
    }
    let (tenant, numbers) = tenant_fields(fields)?;
    if !crate::recovery::valid_tenant_id(&tenant) {
        return Err(Refusal::BadTenant);
    }
    if is_unitless_tenant(&tenant) && numbers.unit.is_some() {
        return Err(Refusal::UnitOfTenantZero);
    }
    let mut rest = fields.clone();
    for name in TENANT_FIELDS {
        rest.remove(name);
    }
    // The parse decides; the list of kinds only names the refusal.
    let job = match serde_json::from_value::<UnitBody>(Value::Object(rest)) {
        Ok(UnitBody::Renew { at, .. }) => UnitJob::Renew { at },
        Ok(UnitBody::StampRaise { at, .. }) => UnitJob::StampRaise { at },
        Err(_) => {
            let kind = fields.get("t").and_then(Value::as_str);
            return Err(match kind.is_some_and(|k| UNIT_JOB_KINDS.contains(&k)) {
                true => Refusal::BadBody,
                false => Refusal::UnknownKind,
            });
        }
    };
    let Some(unit) = numbers.unit else {
        return Err(Refusal::NoUnit);
    };
    Ok((
        job,
        JobTenant {
            tenant,
            unit: Some(unit),
            state_seq: numbers.state_seq,
            keys_seq: numbers.keys_seq,
        },
    ))
}

/// Whether `tenant` is tenant 0's id. Tenant 0 has no unit.
fn is_unitless_tenant(tenant: &str) -> bool {
    tenant == TenantScope::tenant_zero().tenant_id()
}

/// `v` of a job's body.
fn body_version(job: &Job) -> u8 {
    match job {
        Job::Extent { v, .. }
        | Job::Wake { v, .. }
        | Job::Gc { v }
        | Job::Evict { v, .. }
        | Job::Sweep { v, .. }
        | Job::RecoveryCopy { v, .. } => *v,
    }
}

/// How many deliveries of each format a consumer read, said in a log
/// line at the isolate's first delivery, at once for a kind not seen in
/// the current minute, and otherwise at most once every
/// [`FormatCount::EVERY_MS`]. It is the check line of the switch (both formats are read after step 1; no `v` 1
/// message is left before step 3) and costs no storage.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FormatCount {
    /// Deliveries since the last line: `v1`, `v2`, refused.
    counts: [u64; 3],
    /// The kinds seen since the window began.
    seen: [bool; 3],
    /// When the window began: the isolate's first delivery, then each
    /// line said because a minute had passed.
    window: Option<crate::types::UnixMs>,
    /// When the last line was said.
    last: Option<crate::types::UnixMs>,
}

impl FormatCount {
    /// The shortest time between two lines, but for a kind not yet seen.
    pub const EVERY_MS: i64 = 60_000;

    /// Counts one delivery at `now`. Returns the line to log: for the
    /// first delivery an isolate reads (so that every isolate says which
    /// formats it sees), at once for a kind (`v1`, `v2`, refused) that has
    /// not been seen in the current minute, and otherwise once
    /// [`FormatCount::EVERY_MS`] has passed. So a kind that is delivered
    /// at all is said within a delivery, and the absence of a kind in the
    /// lines is its absence in the deliveries. A line counts the
    /// deliveries since the last line, this one included; a message
    /// handed back counts once per delivery. A malformed message is not
    /// counted: it has no format.
    pub fn count(&mut self, admission: &Admission, now: crate::types::UnixMs) -> Option<String> {
        let kind = match admission {
            Admission::Run { tenant: None, .. } => 0,
            Admission::Run {
                tenant: Some(_), ..
            }
            | Admission::Unit { .. } => 1,
            Admission::Refused(_) => 2,
            Admission::Malformed => return None,
        };
        self.counts[kind] += 1;
        let new_window = match self.window {
            None => true,
            Some(start) => now.0.saturating_sub(start.0) >= Self::EVERY_MS,
        };
        if new_window {
            self.window = Some(now);
            self.seen = [false; 3];
        } else if self.seen[kind] {
            return None;
        }
        self.seen[kind] = true;
        let over = self.last.map_or(0, |last| now.0.saturating_sub(last.0));
        let [plain, tenant, refused] = self.counts;
        let line = format!(
            "job message formats: v1={plain} v2={tenant} refused={refused} over {} s",
            over / 1000
        );
        self.counts = [0; 3];
        self.last = Some(now);
        Some(line)
    }
}

/// What the consumer does with a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Run `job` in `scope`. `tenant` holds the fields of a `v` 2
    /// message, `None` for any other.
    Run {
        scope: TenantScope,
        job: Job,
        tenant: Option<JobTenant>,
    },
    /// A unit job of a managed tenant, with the unit class bound: run
    /// through the unit client, never through `run_job`.
    Unit { job: UnitJob, tenant: JobTenant },
    /// Not a job: acknowledged and dropped, as before this module. The
    /// dispatcher sends its row again.
    Malformed,
    /// A `v` 2 message that must not run: handed back to the queue until
    /// it reaches the dead-letter queue, which pages.
    Refused(Refusal),
}

/// What the consumer does with a message's delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Run the job; its outcome says ack or retry.
    Run,
    /// Acknowledge without running: the message is no job.
    Drop,
    /// Hand it back with [`REFUSED_RETRY_DELAY_SECS`], never acknowledge
    /// it: it reaches the dead-letter queue when its deliveries are used
    /// up.
    Refuse,
}

impl Admission {
    pub fn disposition(&self) -> Disposition {
        match self {
            Admission::Run { .. } | Admission::Unit { .. } => Disposition::Run,
            Admission::Malformed => Disposition::Drop,
            Admission::Refused(_) => Disposition::Refuse,
        }
    }
}

/// Why a `v` 2 message is refused. [`Refusal::code`] is what the log
/// says: a fixed word, never a field of the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It names no tenant.
    NoTenant,
    /// Its tenant is not a tenant id.
    BadTenant,
    /// Its tenant is one this Worker cannot serve.
    OtherTenant,
    /// It names a unit of tenant 0, which has none.
    UnitOfTenantZero,
    /// Its fields are not a job of this build.
    BadBody,
    /// Its kind (`t`) is none this build knows.
    UnknownKind,
    /// A unit job ([`UnitJob`]), or a job of a managed tenant, that
    /// names no unit.
    NoUnit,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::NoTenant => "no_tenant",
            Refusal::BadTenant => "bad_tenant",
            Refusal::OtherTenant => "other_tenant",
            Refusal::UnitOfTenantZero => "unit_of_tenant_0",
            Refusal::BadBody => "bad_body",
            Refusal::UnknownKind => "unknown_kind",
            Refusal::NoUnit => "no_unit",
        }
    }
}

/// Whether this Worker has the unit class bound, so that it can run the
/// jobs of a managed tenant against its unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Units {
    /// No unit binding (the production config): tenant 0 only.
    Unbound,
    /// The unit class is bound: a managed tenant's job that names its
    /// unit runs too.
    Bound,
}

/// Reads a queue message, for a Worker without the unit class bound.
/// See the [module](self).
pub fn admit(body: &Value) -> Admission {
    admit_for(body, Units::Unbound)
}

/// Reads a queue message. With [`Units::Bound`], a `v` 2 message of a
/// managed tenant that names its unit is admitted in that tenant's scope
/// ([`TenantScope::managed`]), its tenant fields in `tenant`. See the
/// [module](self).
pub fn admit_for(body: &Value, units: Units) -> Admission {
    // A message of `v` 1 names no tenant: it is tenant 0's, the only
    // tenant there was when it could be written.
    let scope = TenantScope::tenant_zero();
    if body.get("v").and_then(Value::as_u64) != Some(u64::from(TENANT_FORMAT_VERSION)) {
        return match serde_json::from_value::<Job>(body.clone()) {
            Ok(job) => Admission::Run {
                scope,
                job,
                tenant: None,
            },
            Err(_) => Admission::Malformed,
        };
    }
    match tenant_message(body, units, scope) {
        Ok(Admitted::Job(scope, job, tenant)) => Admission::Run {
            scope,
            job,
            tenant: Some(tenant),
        },
        Ok(Admitted::Unit(job, tenant)) => Admission::Unit { job, tenant },
        Err(refusal) => Admission::Refused(refusal),
    }
}

/// What [`tenant_message`] admits.
#[derive(Debug, PartialEq)]
enum Admitted {
    Job(TenantScope, Job, JobTenant),
    Unit(UnitJob, JobTenant),
}

/// A `v` 2 message of a tenant this Worker serves as the job's scope, its
/// job and its tenant fields, or a unit job. `zero` is tenant 0's scope.
fn tenant_message(
    body: &Value,
    units: Units,
    zero: TenantScope,
) -> std::result::Result<Admitted, Refusal> {
    let Some(fields) = body.as_object() else {
        return Err(Refusal::BadBody);
    };
    let (tenant, numbers) = tenant_fields(fields)?;
    let scope = if tenant == zero.tenant_id() {
        zero
    } else {
        // A managed tenant: served only with the unit class bound, and
        // only for an id a unit can be named by.
        let managed = crate::unit::TenantId::parse(&tenant)
            .as_ref()
            .and_then(TenantScope::managed);
        match (units, managed) {
            (Units::Bound, Some(scope)) => scope,
            _ => {
                return Err(match crate::recovery::Layout::tenant(&tenant) {
                    Some(_) => Refusal::OtherTenant,
                    None => Refusal::BadTenant,
                })
            }
        }
    };
    // Tenant 0's catalogue is the D1 database, not a unit; a managed
    // tenant's catalogue is its unit, so its job must name one.
    if scope.is_tenant_zero() && numbers.unit.is_some() {
        return Err(Refusal::UnitOfTenantZero);
    }
    let kind = fields.get("t").and_then(Value::as_str);
    // A unit job: run through the unit client, never as a `Job`. The
    // reader says whether it was well formed.
    if kind.is_some_and(|kind| UNIT_JOB_KINDS.contains(&kind)) {
        return match read_unit_job(body) {
            Err(refusal) => Err(refusal),
            Ok(_) if scope.is_tenant_zero() => Err(Refusal::NoUnit),
            Ok((job, tenant)) => Ok(Admitted::Unit(job, tenant)),
        };
    }
    if !scope.is_tenant_zero() && numbers.unit.is_none() {
        return Err(Refusal::NoUnit);
    }
    // The body without the tenant fields is a body of the current
    // version; `Job` refuses any field it does not know.
    let mut job = fields.clone();
    for name in TENANT_FIELDS {
        job.remove(name);
    }
    job.insert("v".to_string(), Value::from(JOB_VERSION));
    // The parse decides what runs; the list of kinds only names the
    // refusal, so a kind left out of it can never stop a job.
    let job = serde_json::from_value::<Job>(Value::Object(job)).map_err(|_| {
        match kind.is_some_and(|kind| JOB_KINDS.contains(&kind)) {
            true => Refusal::BadBody,
            false => Refusal::UnknownKind,
        }
    })?;
    Ok(Admitted::Job(
        scope,
        job,
        JobTenant {
            tenant,
            unit: numbers.unit,
            state_seq: numbers.state_seq,
            keys_seq: numbers.keys_seq,
        },
    ))
}

/// The tenant and the tenant fields of a `v` 2 message.
fn tenant_fields(
    fields: &serde_json::Map<String, Value>,
) -> std::result::Result<(String, Numbers), Refusal> {
    let tenant = match fields.get("tenant") {
        None | Some(Value::Null) => return Err(Refusal::NoTenant),
        Some(Value::String(tenant)) => tenant.clone(),
        Some(_) => return Err(Refusal::BadTenant),
    };
    let numbers: Numbers = serde_json::from_value(Value::Object(
        TENANT_FIELDS
            .iter()
            .filter_map(|name| Some(((*name).to_string(), fields.get(*name)?.clone())))
            .collect(),
    ))
    .map_err(|_| Refusal::BadBody)?;
    Ok((tenant, numbers))
}

/// The tenant fields as a `v` 2 message must carry them: both numbers
/// present, the unit absent or a number.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Numbers {
    #[allow(dead_code)]
    tenant: String,
    #[serde(default)]
    unit: Option<u32>,
    state_seq: u64,
    keys_seq: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_switch_reads_one_and_two_only() {
        for raw in [None, Some(""), Some("1"), Some(" 1 ")] {
            assert_eq!(JobFormat::from_var(raw), Ok(JobFormat::Plain), "{raw:?}");
        }
        assert_eq!(JobFormat::from_var(Some("2")), Ok(JobFormat::Tenant));
        for raw in ["0", "3", "v2", "tenant", "2,1", "true"] {
            assert!(JobFormat::from_var(Some(raw)).is_err(), "{raw}");
        }
        assert_eq!(JobFormat::default(), JobFormat::Plain);
    }

    #[test]
    fn the_format_line_comes_at_most_once_a_minute() {
        let mut count = FormatCount::default();
        let t = |ms: i64| crate::types::UnixMs(1_000_000 + ms);
        let Admission::Run { scope, job, .. } = admit(&json!({"t": "gc", "v": 1})) else {
            panic!("a gc job of v 1 runs");
        };
        let plain = Admission::Run {
            scope: scope.clone(),
            job: job.clone(),
            tenant: None,
        };
        let tenant = admit(
            &json!({"t": "gc", "v": 2, "tenant": scope.tenant_id(), "state_seq": 0, "keys_seq": 0}),
        );
        assert!(matches!(
            tenant,
            Admission::Run {
                tenant: Some(_),
                ..
            }
        ));
        let refused = Admission::Refused(Refusal::NoTenant);
        let line = |v1: u64, v2: u64, refused: u64, over: i64| {
            Some(format!(
                "job message formats: v1={v1} v2={v2} refused={refused} over {over} s"
            ))
        };
        // The isolate's first delivery is said at once.
        assert_eq!(count.count(&plain, t(0)), line(1, 0, 0, 0));
        assert_eq!(count.count(&plain, t(1)), None);
        // A kind not seen in this minute is said at once.
        assert_eq!(count.count(&tenant, t(2)), line(1, 1, 0, 0));
        assert_eq!(count.count(&tenant, t(3)), None);
        assert_eq!(count.count(&Admission::Malformed, t(70_000)), None);
        assert_eq!(count.count(&refused, t(59_999)), line(0, 1, 1, 59));
        // A new minute: the next delivery is said, whatever its kind.
        assert_eq!(count.count(&refused, t(60_000)), line(0, 0, 1, 0));
        assert_eq!(count.count(&refused, t(119_999)), None);
        assert_eq!(count.count(&plain, t(120_000)), line(1, 0, 1, 60));
        assert_eq!(count.count(&plain, t(179_999)), None);
        assert_eq!(count.count(&plain, t(180_000)), line(2, 0, 0, 60));
    }

    #[test]
    fn a_refused_message_is_never_run_nor_acknowledged() {
        for refusal in [
            Refusal::NoTenant,
            Refusal::BadTenant,
            Refusal::OtherTenant,
            Refusal::UnitOfTenantZero,
            Refusal::BadBody,
            Refusal::UnknownKind,
            Refusal::NoUnit,
        ] {
            assert_eq!(
                Admission::Refused(refusal).disposition(),
                Disposition::Refuse
            );
        }
        assert_eq!(Admission::Malformed.disposition(), Disposition::Drop);
        assert_eq!(
            admit(&json!({"t": "gc", "v": 1})).disposition(),
            Disposition::Run
        );
        assert_eq!(
            admit(&json!({"t": "gc", "v": 2})).disposition(),
            Disposition::Refuse
        );
        assert_eq!(REFUSED_RETRY_DELAY_SECS, 0);
    }

    #[test]
    fn refusals_have_fixed_codes() {
        let all = [
            Refusal::NoTenant,
            Refusal::BadTenant,
            Refusal::OtherTenant,
            Refusal::UnitOfTenantZero,
            Refusal::BadBody,
            Refusal::UnknownKind,
            Refusal::NoUnit,
        ];
        let codes: std::collections::BTreeSet<_> = all.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn a_v2_message_that_is_not_a_job_object_is_refused() {
        assert_eq!(
            admit(&json!({"v": 2})),
            Admission::Refused(Refusal::NoTenant)
        );
        let Admission::Run { .. } = admit(&json!({"t": "gc", "v": 1})) else {
            panic!("a gc job of v 1 runs");
        };
        for units in [Units::Unbound, Units::Bound] {
            assert_eq!(
                tenant_message(&json!([2]), units, TenantScope::tenant_zero()),
                Err(Refusal::BadBody)
            );
        }
    }

    const MANAGED: &str = "t_00000000000000a7";

    fn managed_gc(unit: Option<u32>) -> Value {
        let mut body = json!({"t": "gc", "v": 2, "tenant": MANAGED, "state_seq": 7, "keys_seq": 3});
        if let Some(unit) = unit {
            body["unit"] = json!(unit);
        }
        body
    }

    /// With the unit class bound, a managed tenant's job that names its
    /// unit runs in that tenant's scope, with its numbers; without the
    /// binding it is refused as before.
    #[test]
    fn a_managed_tenants_job_runs_only_with_units_bound() {
        let Admission::Run { scope, job, tenant } = admit_for(&managed_gc(Some(0)), Units::Bound)
        else {
            panic!("a managed tenant's gc job runs with units bound");
        };
        assert_eq!(scope.tenant_id(), MANAGED);
        assert!(!scope.is_tenant_zero());
        assert_eq!(job, Job::Gc { v: JOB_VERSION });
        let tenant = tenant.unwrap();
        assert_eq!(
            (
                tenant.tenant(),
                tenant.unit(),
                tenant.state_seq(),
                tenant.keys_seq()
            ),
            (MANAGED, Some(0), 7, 3)
        );
        assert_eq!(
            admit_for(&managed_gc(Some(0)), Units::Unbound),
            Admission::Refused(Refusal::OtherTenant)
        );
        assert_eq!(
            admit(&managed_gc(Some(0))),
            Admission::Refused(Refusal::OtherTenant)
        );
        // A managed tenant's catalogue is its unit: no unit, no job.
        assert_eq!(
            admit_for(&managed_gc(None), Units::Bound),
            Admission::Refused(Refusal::NoUnit)
        );
    }

    /// The binding changes nothing for tenant 0, and admits no tenant id
    /// a unit cannot be named by.
    #[test]
    fn units_bound_leave_tenant_zero_and_bad_ids_as_they_were() {
        let zero = TenantScope::tenant_zero().tenant_id().to_string();
        let v2 = json!({"t": "gc", "v": 2, "tenant": zero, "state_seq": 0, "keys_seq": 0});
        let v1 = json!({"t": "gc", "v": 1});
        for body in [&v1, &v2] {
            assert_eq!(admit_for(body, Units::Bound), admit(body), "{body}");
        }
        let mut with_unit = v2.clone();
        with_unit["unit"] = json!(0);
        assert_eq!(
            admit_for(&with_unit, Units::Bound),
            Admission::Refused(Refusal::UnitOfTenantZero)
        );
        // A record-name tenant id that is not a unit's tenant id (`t_` and
        // 16 lowercase hex digits) is another tenant; what is no tenant id
        // at all is a bad one.
        for (tenant, want) in [
            ("t_1", Refusal::OtherTenant),
            ("t_00000000000000a7x", Refusal::OtherTenant),
            ("t_00000000000000A7", Refusal::BadTenant),
            ("not a tenant", Refusal::BadTenant),
        ] {
            let mut body = managed_gc(Some(0));
            body["tenant"] = json!(tenant);
            assert_eq!(
                admit_for(&body, Units::Bound),
                Admission::Refused(want),
                "{tenant}"
            );
        }
    }

    /// A unit job (renew, stamp_raise): with units bound a well-formed one
    /// is admitted for the unit client, a malformed one says why.
    #[test]
    fn unit_jobs_are_admitted_with_units_bound_only() {
        let renew = json!({"t": "renew", "v": 2, "at": 1_800_000_000_000_i64, "tenant": MANAGED,
                           "unit": 0, "state_seq": 1, "keys_seq": 1});
        let (job, tenant) = read_unit_job(&renew).unwrap();
        assert_eq!(
            admit_for(&renew, Units::Bound),
            Admission::Unit { job, tenant }
        );
        assert_eq!(
            admit_for(&renew, Units::Bound).disposition(),
            Disposition::Run
        );
        assert_eq!(
            admit_for(&renew, Units::Unbound),
            Admission::Refused(Refusal::OtherTenant)
        );
        let mut no_unit = renew.clone();
        no_unit.as_object_mut().unwrap().remove("unit");
        assert_eq!(
            admit_for(&no_unit, Units::Bound),
            Admission::Refused(Refusal::NoUnit)
        );
        let mut extra = renew.clone();
        extra["extra"] = json!(1);
        assert_eq!(
            admit_for(&extra, Units::Bound),
            Admission::Refused(Refusal::BadBody)
        );
    }

    /// What a managed tenant's unit sends (its own tenant fields, always
    /// `v` 2) is admitted as that unit's job again, field for field.
    #[test]
    fn a_units_message_reads_back_as_the_same_units_job() {
        let tenant = JobTenant::of_unit(MANAGED, 4, 11, 12).unwrap();
        let job = Job::Gc { v: JOB_VERSION };
        let text = JobFormat::Tenant.message(&job, &tenant).to_json();
        let body: Value = serde_json::from_str(&text).unwrap();
        let Admission::Run {
            scope,
            job: read,
            tenant: Some(read_tenant),
        } = admit_for(&body, Units::Bound)
        else {
            panic!("{text}");
        };
        assert_eq!(
            (scope.tenant_id(), read, read_tenant),
            (MANAGED, job, tenant)
        );
    }
}
