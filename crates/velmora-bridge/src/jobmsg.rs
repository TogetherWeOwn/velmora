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
//!    deployed: it drops every `v` 2 message as malformed, and the
//!    outbox sends the rows again only after their resend timeout.
//! 3. **The default removed** (later): a `v` 1 message is refused.
//!
//! # What is never run
//!
//! A `v` 2 message runs only for a tenant this Worker can serve. Today
//! that is tenant 0, whose catalogue is the D1 database: it has no unit,
//! so its message names none. A `v` 2 message with no tenant, with a
//! tenant that is not tenant 0, with a unit for tenant 0, or with fields
//! this build does not know is **refused** ([`Refusal`]): the consumer
//! hands it back to the queue until its deliveries are used up, so it
//! lands in the dead-letter queue, which pages. It is never run under
//! another tenant's scope, and it is never dropped in silence.
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

/// Name of the configuration switch of the writers' format.
pub const JOB_FORMAT_VAR: &str = "JOB_FORMAT";

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
    /// tenant chain or key chain yet: its numbers are 0.
    pub fn of(scope: &TenantScope) -> JobTenant {
        JobTenant {
            tenant: scope.tenant_id().to_string(),
            unit: None,
            state_seq: 0,
            keys_seq: 0,
        }
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
    /// Not a job: acknowledged and dropped, as before this module. The
    /// dispatcher sends its row again.
    Malformed,
    /// A `v` 2 message that must not run: handed back to the queue until
    /// it reaches the dead-letter queue, which pages.
    Refused(Refusal),
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
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::NoTenant => "no_tenant",
            Refusal::BadTenant => "bad_tenant",
            Refusal::OtherTenant => "other_tenant",
            Refusal::UnitOfTenantZero => "unit_of_tenant_0",
            Refusal::BadBody => "bad_body",
        }
    }
}

/// Reads a queue message. See the [module](self).
pub fn admit(body: &Value) -> Admission {
    // The one tenant this Worker serves. A message of `v` 1 names no
    // tenant: it is tenant 0's, the only tenant there was when it could
    // be written.
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
    match tenant_message(body, &scope) {
        Ok((job, tenant)) => Admission::Run {
            scope,
            job,
            tenant: Some(tenant),
        },
        Err(refusal) => Admission::Refused(refusal),
    }
}

/// A `v` 2 message of the tenant of `served` as its job and its tenant
/// fields.
fn tenant_message(
    body: &Value,
    served: &TenantScope,
) -> std::result::Result<(Job, JobTenant), Refusal> {
    let Some(fields) = body.as_object() else {
        return Err(Refusal::BadBody);
    };
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
    if tenant != served.tenant_id() {
        return Err(match crate::recovery::Layout::tenant(&tenant) {
            Some(_) => Refusal::OtherTenant,
            None => Refusal::BadTenant,
        });
    }
    // Tenant 0's catalogue is the D1 database, not a unit.
    if served.is_tenant_zero() && numbers.unit.is_some() {
        return Err(Refusal::UnitOfTenantZero);
    }
    // The body without the tenant fields is a body of the current
    // version; `Job` refuses any field it does not know.
    let mut job = fields.clone();
    for name in TENANT_FIELDS {
        job.remove(name);
    }
    job.insert("v".to_string(), Value::from(JOB_VERSION));
    let job = serde_json::from_value::<Job>(Value::Object(job)).map_err(|_| Refusal::BadBody)?;
    Ok((
        job,
        JobTenant {
            tenant,
            unit: numbers.unit,
            state_seq: numbers.state_seq,
            keys_seq: numbers.keys_seq,
        },
    ))
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
    fn refusals_have_fixed_codes() {
        let all = [
            Refusal::NoTenant,
            Refusal::BadTenant,
            Refusal::OtherTenant,
            Refusal::UnitOfTenantZero,
            Refusal::BadBody,
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
        let Admission::Run { scope, .. } = admit(&json!({"t": "gc", "v": 1})) else {
            panic!("a gc job of v 1 runs");
        };
        assert_eq!(tenant_message(&json!([2]), &scope), Err(Refusal::BadBody));
    }
}
