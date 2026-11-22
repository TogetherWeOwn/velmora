//! The two formats of a queue message (`velmora_bridge::jobmsg`): the
//! bytes of each, what the reader runs, and what it refuses.

use serde_json::{json, Value};
use velmora_bridge::jobmsg::{
    admit, read_unit_job, Admission, JobFormat, JobTenant, Refusal, UnitJob, JOB_KINDS,
    TENANT_FIELDS, UNIT_JOB_KINDS,
};
use velmora_bridge::{
    ExtentId, GenerationId, Job, OutboxStage, TenantScope, UnixMs, WriteId, JOB_VERSION,
};

fn extent() -> ExtentId {
    ExtentId::new("x_000102030405060708090a0b0c")
}

fn generation() -> GenerationId {
    GenerationId::new("g_0195c2a4b3e7f00112233445566778")
}

/// Every job, with every stage an extent job can carry, next to the
/// bytes it is sent as.
fn jobs() -> Vec<(Job, &'static str, &'static str)> {
    let v = JOB_VERSION;
    let extent_job = |stage| Job::Extent {
        v,
        extent: extent(),
        generation: generation(),
        stage,
    };
    let wake_job = |stage, at| Job::Wake {
        v,
        extent: extent(),
        generation: generation(),
        stage,
        at: UnixMs(at),
    };
    vec![
        (
            extent_job(OutboxStage::Post),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"post"}"#,
            r#"{"t":"extent","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"post","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            extent_job(OutboxStage::Verify),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"verify"}"#,
            r#"{"t":"extent","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"verify","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            extent_job(OutboxStage::Release),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"release"}"#,
            r#"{"t":"extent","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"release","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            extent_job(OutboxStage::Done),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"done"}"#,
            r#"{"t":"extent","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"done","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            extent_job(OutboxStage::Cancelled),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"cancelled"}"#,
            r#"{"t":"extent","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"cancelled","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            extent_job(OutboxStage::Dead),
            r#"{"t":"extent","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"dead"}"#,
            r#"{"t":"extent","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"dead","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            wake_job(OutboxStage::Post, 1_800_000_000_123),
            r#"{"t":"wake","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"post","at":1800000000123}"#,
            r#"{"t":"wake","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"post","at":1800000000123,"tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            wake_job(OutboxStage::Verify, 0),
            r#"{"t":"wake","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"verify","at":0}"#,
            r#"{"t":"wake","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"verify","at":0,"tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            wake_job(OutboxStage::Release, -1),
            r#"{"t":"wake","v":1,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"release","at":-1}"#,
            r#"{"t":"wake","v":2,"extent":"x_000102030405060708090a0b0c","generation":"g_0195c2a4b3e7f00112233445566778","stage":"release","at":-1,"tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            Job::Gc { v },
            r#"{"t":"gc","v":1}"#,
            r#"{"t":"gc","v":2,"tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            Job::Evict { v, remaining: 0 },
            r#"{"t":"evict","v":1,"remaining":0}"#,
            r#"{"t":"evict","v":2,"remaining":0,"tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            Job::Evict {
                v,
                remaining: u64::MAX,
            },
            r#"{"t":"evict","v":1,"remaining":18446744073709551615}"#,
            r#"{"t":"evict","v":2,"remaining":18446744073709551615,"tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            Job::Sweep {
                v,
                write: WriteId::new("w_000102030405060708090a0b0c0d0e0f"),
            },
            r#"{"t":"sweep","v":1,"write":"w_000102030405060708090a0b0c0d0e0f"}"#,
            r#"{"t":"sweep","v":2,"write":"w_000102030405060708090a0b0c0d0e0f","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            Job::RecoveryCopy {
                v,
                pass: UnixMs(1_800_000_000_000),
                cursor: String::new(),
            },
            r#"{"t":"recovery_copy","v":1,"pass":1800000000000,"cursor":""}"#,
            r#"{"t":"recovery_copy","v":2,"pass":1800000000000,"cursor":"","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
        (
            Job::RecoveryCopy {
                v,
                pass: UnixMs(1_800_000_000_000),
                cursor: "walk:m/x/t_0000000000000000/art/x_1".into(),
            },
            r#"{"t":"recovery_copy","v":1,"pass":1800000000000,"cursor":"walk:m/x/t_0000000000000000/art/x_1"}"#,
            r#"{"t":"recovery_copy","v":2,"pass":1800000000000,"cursor":"walk:m/x/t_0000000000000000/art/x_1","tenant":"t_0000000000000000","state_seq":0,"keys_seq":0}"#,
        ),
    ]
}

fn parse(json: &str) -> Value {
    serde_json::from_str(json).unwrap()
}

fn tenant_body(job: &Job) -> Value {
    let tenant = JobTenant::of(&TenantScope::tenant_zero());
    parse(&JobFormat::Tenant.message(job, &tenant).to_json())
}

fn gc() -> Job {
    Job::Gc { v: JOB_VERSION }
}

/// Plain messages preserve the original job bytes for every fixture.
#[test]
fn plain_messages_match_the_original_bytes() {
    let tenant = JobTenant::of(&TenantScope::tenant_zero());
    for (job, plain, _) in jobs() {
        let message = JobFormat::Plain.message(&job, &tenant).to_json();
        assert_eq!(message, job.to_json(), "{job:?}");
        assert_eq!(message, plain, "{job:?}");
    }
}

/// Tenant messages append the tenant fields in order and omit tenant zero's unit.
#[test]
fn tenant_messages_match_the_expected_bytes() {
    let tenant = JobTenant::of(&TenantScope::tenant_zero());
    for (job, _, expected) in jobs() {
        assert_eq!(
            JobFormat::Tenant.message(&job, &tenant).to_json(),
            expected,
            "{job:?}"
        );
    }
}

/// Removing the tenant fields and restoring version one recovers the original body.
#[test]
fn tenant_messages_preserve_the_job_body() {
    for (job, _, _) in jobs() {
        let mut body = tenant_body(&job);
        let fields = body.as_object_mut().unwrap();
        for name in TENANT_FIELDS {
            fields.remove(name);
        }
        fields.insert("v".into(), json!(1));
        assert_eq!(body, parse(&job.to_json()), "{job:?}");
    }
}

/// Both formats admit the same job in tenant zero and only version two carries tenant metadata.
#[test]
fn both_formats_admit_the_original_job() {
    let scope = TenantScope::tenant_zero();
    let tenant = JobTenant::of(&scope);
    for (job, _, _) in jobs() {
        for (body, expected_tenant) in [
            (tenant_body(&job), Some(tenant.clone())),
            (parse(&job.to_json()), None),
        ] {
            let admission = admit(&body);
            let Admission::Run {
                scope,
                job: admitted_job,
                tenant,
            } = admission
            else {
                panic!("expected to run {body}, got {admission:?}");
            };
            assert!(scope.is_tenant_zero(), "{body}");
            assert_eq!(admitted_job, job, "{body}");
            assert_eq!(tenant, expected_tenant, "{body}");
        }
    }
}

/// Original job bodies reserve all four tenant field names.
#[test]
fn job_bodies_have_no_tenant_fields() {
    for (job, _, _) in jobs() {
        let body = parse(&job.to_json());
        let fields = body.as_object().unwrap();
        for name in TENANT_FIELDS {
            assert!(!fields.contains_key(name), "{job:?} contains {name}");
        }
    }
}

fn assert_refused(body: &Value, refusal: Refusal, message: &str) {
    let admission = admit(body);
    assert!(!matches!(admission, Admission::Run { .. }), "{message}");
    assert_eq!(admission, Admission::Refused(refusal), "{message}");
}

/// Invalid tenant messages are refused with the reason for each invalid field.
#[test]
fn invalid_tenant_messages_are_refused() {
    use Refusal::{BadBody, BadTenant, NoTenant, OtherTenant, UnitOfTenantZero};

    let gc = tenant_body(&gc());
    let extent = tenant_body(&Job::Extent {
        v: JOB_VERSION,
        extent: extent(),
        generation: generation(),
        stage: OutboxStage::Post,
    });

    let without = |body: &Value, name: &str| {
        let mut body = body.clone();
        body.as_object_mut().unwrap().remove(name);
        body
    };
    let with = |body: &Value, name: &str, value: Value| {
        let mut body = body.clone();
        body[name] = value;
        body
    };

    assert_refused(&without(&gc, "tenant"), NoTenant, "missing tenant");
    assert_refused(&with(&gc, "tenant", Value::Null), NoTenant, "null tenant");
    assert_refused(&with(&gc, "tenant", json!(7)), BadTenant, "numeric tenant");
    assert_refused(
        &with(&gc, "tenant", json!("x/../y")),
        BadTenant,
        "invalid tenant path",
    );
    assert_refused(&with(&gc, "tenant", json!("")), BadTenant, "empty tenant");
    assert_refused(
        &with(&gc, "tenant", json!("t_0000000000000001")),
        OtherTenant,
        "a well-formed tenant id belonging to another tenant",
    );
    assert_refused(
        &with(&gc, "unit", json!(0)),
        UnitOfTenantZero,
        "unit zero in tenant zero",
    );
    assert_refused(
        &with(&gc, "unit", json!(5)),
        UnitOfTenantZero,
        "unit five in tenant zero",
    );
    assert_refused(
        &without(&gc, "state_seq"),
        BadBody,
        "missing state sequence",
    );
    assert_refused(&without(&gc, "keys_seq"), BadBody, "missing keys sequence");
    assert_refused(
        &with(&gc, "keys_seq", json!(-1)),
        BadBody,
        "negative keys sequence",
    );
    assert_refused(
        &with(&gc, "state_seq", json!("0")),
        BadBody,
        "string state sequence",
    );
    assert_refused(&with(&gc, "unit", json!("a")), BadBody, "string unit");
    assert_refused(&with(&gc, "x", json!(1)), BadBody, "unknown field");
    assert_refused(
        &with(&gc, "t", json!("nope")),
        Refusal::UnknownKind,
        "unknown job type",
    );
    assert_refused(&without(&gc, "t"), Refusal::UnknownKind, "no job type");
    assert_refused(
        &with(&gc, "t", json!(7)),
        Refusal::UnknownKind,
        "numeric job type",
    );
    assert_refused(&without(&extent, "extent"), BadBody, "missing extent");
    assert_refused(
        &with(&extent, "stage", json!("nope")),
        BadBody,
        "unknown extent stage",
    );
}

/// Tenant zero carries sequence numbers unchanged, even when they are large.
#[test]
fn tenant_zero_carries_large_sequence_numbers() {
    let mut body = tenant_body(&gc());
    let state_seq = 9_007_199_254_740_991_u64;
    body["state_seq"] = json!(state_seq);
    body["keys_seq"] = json!(12);
    let Admission::Run {
        scope,
        job,
        tenant: Some(tenant),
    } = admit(&body)
    else {
        panic!("expected to run {body}");
    };
    assert!(scope.is_tenant_zero());
    assert_eq!(job, gc());
    assert_eq!(tenant.state_seq(), state_seq);
    assert_eq!(tenant.keys_seq(), 12);
}

/// Adding any tenant field to a version-one job makes it malformed.
#[test]
fn plain_messages_with_tenant_fields_are_malformed() {
    let plain = parse(&gc().to_json());
    let mut named_tenant = plain.clone();
    named_tenant["tenant"] = json!("t_0000000000000000");
    assert_eq!(admit(&named_tenant), Admission::Malformed);

    let mut state_seq = plain;
    state_seq["state_seq"] = json!(0);
    assert_eq!(admit(&state_seq), Admission::Malformed);
}

/// Other inputs retain the original job decoder's admission behavior.
#[test]
fn other_inputs_keep_their_original_admission_behavior() {
    assert_eq!(admit(&json!({"t": "gc"})), Admission::Malformed);
    assert_eq!(admit(&json!("gc")), Admission::Malformed);
    assert_eq!(admit(&json!({})), Admission::Malformed);
    assert_eq!(
        admit(&json!({"t": "gc", "v": 3})),
        Admission::Run {
            scope: TenantScope::tenant_zero(),
            job: Job::Gc { v: 3 },
            tenant: None,
        }
    );
    assert_eq!(admit(&json!({"t": "gc", "v": "2"})), Admission::Malformed);
}

/// Only current job bodies get wrapped, and an unwrapped version-two body is refused.
#[test]
fn a_body_of_another_version_stays_unwrapped() {
    let job = Job::Gc { v: JOB_VERSION + 1 };
    let tenant = JobTenant::of(&TenantScope::tenant_zero());
    let text = JobFormat::Tenant.message(&job, &tenant).to_json();
    assert_eq!(text, r#"{"t":"gc","v":2}"#);
    assert_eq!(text, Job::Gc { v: 2 }.to_json());
    assert_refused(
        &parse(&text),
        Refusal::NoTenant,
        "unwrapped version-two body",
    );
}

/// A flattened struct serialises as a map, which the Worker's queue binding sends as an empty object.
#[test]
fn job_messages_avoid_map_serialization() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/jobmsg.rs");
    let source = std::fs::read_to_string(path).unwrap();
    for (index, line) in source.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for forbidden in ["flatten", "serialize_map", "HashMap", "BTreeMap"] {
            assert!(
                !line.contains(forbidden),
                "jobmsg.rs line {} contains {forbidden}: {line}",
                index + 1
            );
        }
    }
}

/// The writer switch accepts supported values and keeps invalid values out of errors.
#[test]
fn the_format_switch_reports_errors_without_raw_values() {
    assert_eq!(JobFormat::from_var(None), Ok(JobFormat::Plain));
    assert_eq!(JobFormat::from_var(Some("2")), Ok(JobFormat::Tenant));
    for raw in ["02", "two"] {
        let error = JobFormat::from_var(Some(raw)).unwrap_err();
        assert!(error.contains("JOB_FORMAT"), "{error}");
        assert!(!error.contains(raw), "{error}");
    }
}

const OTHER_TENANT: &str = "t_0123456789abcdef";
const AT: UnixMs = UnixMs(1_800_000_000_000);

fn unit_tenant() -> JobTenant {
    JobTenant::of_unit(OTHER_TENANT, 3, u64::MAX, 9_007_199_254_740_993).unwrap()
}

/// Both unit jobs, next to the bytes they are sent as.
fn unit_jobs() -> Vec<(UnitJob, &'static str)> {
    vec![
        (
            UnitJob::Renew { at: AT },
            r#"{"t":"renew","v":2,"at":1800000000000,"tenant":"t_0123456789abcdef","unit":3,"state_seq":18446744073709551615,"keys_seq":9007199254740993}"#,
        ),
        (
            UnitJob::StampRaise { at: AT },
            r#"{"t":"stamp_raise","v":2,"at":1800000000000,"tenant":"t_0123456789abcdef","unit":3,"state_seq":18446744073709551615,"keys_seq":9007199254740993}"#,
        ),
    ]
}

/// Every job kind is listed, and no unit job kind is a job kind.
#[test]
fn the_kind_lists_are_complete_and_apart() {
    let tags: std::collections::BTreeSet<String> = jobs()
        .iter()
        .map(|(job, _, _)| parse(&job.to_json())["t"].as_str().unwrap().to_string())
        .collect();
    let listed: std::collections::BTreeSet<String> =
        JOB_KINDS.iter().map(|kind| kind.to_string()).collect();
    assert_eq!(tags, listed);
    let unit_tags: std::collections::BTreeSet<String> = unit_jobs()
        .iter()
        .map(|(_, bytes)| parse(bytes)["t"].as_str().unwrap().to_string())
        .collect();
    let unit_listed: std::collections::BTreeSet<String> =
        UNIT_JOB_KINDS.iter().map(|kind| kind.to_string()).collect();
    assert_eq!(unit_tags, unit_listed);
    assert!(listed.is_disjoint(&unit_listed));
}

/// A unit job is sent in format 2 with its tenant and unit, and reads back as itself.
#[test]
fn unit_jobs_match_the_expected_bytes_and_read_back() {
    let tenant = unit_tenant();
    for (job, expected) in unit_jobs() {
        let text = job.message(&tenant).unwrap();
        assert_eq!(text, expected, "{job:?}");
        assert_eq!(read_unit_job(&parse(&text)), Ok((job, tenant.clone())));
    }
}

/// Only a unit of a tenant other than tenant 0 can name a unit job.
#[test]
fn unit_job_tenants_name_a_unit_of_another_tenant() {
    let zero = TenantScope::tenant_zero();
    assert_eq!(JobTenant::of_unit(zero.tenant_id(), 0, 0, 0), None);
    for bad in ["", "x", "t_", "t_ABC", "t_0123/../x"] {
        assert_eq!(JobTenant::of_unit(bad, 0, 0, 0), None, "{bad}");
    }
    let tenant = unit_tenant();
    assert_eq!(tenant.tenant(), OTHER_TENANT);
    assert_eq!(tenant.unit(), Some(3));
    // Tenant 0's fields name no unit, so no unit job can be written for them.
    let zero = JobTenant::of(&zero);
    for (job, _) in unit_jobs() {
        assert_eq!(job.message(&zero), None, "{job:?}");
    }
}

/// This Worker serves no unit: every unit job is refused, with the reason the reader gives.
#[test]
fn unit_jobs_are_refused_by_a_worker_that_serves_no_unit() {
    let zero = TenantScope::tenant_zero();
    for (job, bytes) in unit_jobs() {
        let body = parse(bytes);
        assert_refused(&body, Refusal::OtherTenant, "a unit of another tenant");
        let mut zero_unit = body.clone();
        zero_unit["tenant"] = json!(zero.tenant_id());
        assert_refused(&zero_unit, Refusal::UnitOfTenantZero, "a unit of tenant 0");
        let mut zero_none = zero_unit.clone();
        zero_none.as_object_mut().unwrap().remove("unit");
        assert_refused(&zero_none, Refusal::NoUnit, "tenant 0 names no unit");
        let mut zero_extra = zero_none.clone();
        zero_extra["extent"] = json!(extent().as_str());
        assert_refused(&zero_extra, Refusal::BadBody, "a field of no unit job");
        let mut zero_no_at = zero_none.clone();
        zero_no_at.as_object_mut().unwrap().remove("at");
        assert_refused(&zero_no_at, Refusal::BadBody, "no time");
        // A unit job has no format 1: it is malformed there, as before.
        let mut plain = body.clone();
        plain["v"] = json!(1);
        assert_eq!(admit(&plain), Admission::Malformed, "{job:?}");
        for name in TENANT_FIELDS {
            plain.as_object_mut().unwrap().remove(name);
        }
        assert_eq!(admit(&plain), Admission::Malformed, "{job:?}");
    }
}

/// The unit job reader refuses each field it cannot take, with its reason.
#[test]
fn the_unit_job_reader_refuses_what_is_not_a_unit_job() {
    let (_, bytes) = unit_jobs().remove(0);
    let body = parse(bytes);
    let with = |name: &str, value: Value| {
        let mut body = body.clone();
        body[name] = value;
        body
    };
    let without = |name: &str| {
        let mut body = body.clone();
        body.as_object_mut().unwrap().remove(name);
        body
    };
    assert_eq!(read_unit_job(&without("unit")), Err(Refusal::NoUnit));
    assert_eq!(read_unit_job(&without("tenant")), Err(Refusal::NoTenant));
    assert_eq!(
        read_unit_job(&with("tenant", json!("x"))),
        Err(Refusal::BadTenant)
    );
    assert_eq!(
        read_unit_job(&with("tenant", json!(1))),
        Err(Refusal::BadTenant)
    );
    assert_eq!(
        read_unit_job(&with("unit", json!(-1))),
        Err(Refusal::BadBody)
    );
    assert_eq!(read_unit_job(&without("keys_seq")), Err(Refusal::BadBody));
    assert_eq!(
        read_unit_job(&with("at", json!("1"))),
        Err(Refusal::BadBody)
    );
    assert_eq!(
        read_unit_job(&with("cursor", json!("x"))),
        Err(Refusal::BadBody)
    );
    assert_eq!(read_unit_job(&with("v", json!(1))), Err(Refusal::BadBody));
    assert_eq!(
        read_unit_job(&with("t", json!("gc"))),
        Err(Refusal::UnknownKind)
    );
    assert_eq!(read_unit_job(&without("t")), Err(Refusal::UnknownKind));
    assert_eq!(read_unit_job(&json!([2])), Err(Refusal::BadBody));
    // A job of a tenant's own kind is not a unit job.
    assert_eq!(
        read_unit_job(&tenant_body(&gc())),
        Err(Refusal::UnknownKind)
    );
}

// ---------------------------------------------------------------------------
// apply_control: a control intent, v 2 only, for the finisher of its chain
// ---------------------------------------------------------------------------

mod control {
    use super::*;
    use velmora_bridge::jobmsg::{
        ControlIntent, Disposition, FormatCount, IntentChain, APPLY_CONTROL_DELAY_SECS,
    };

    const TENANT: &str = "t_00000000000000a1";

    fn intent(chain: IntentChain, seq: u64) -> ControlIntent {
        ControlIntent::new(TENANT, chain, seq).unwrap()
    }

    #[test]
    fn an_intent_is_sent_as_its_golden_body_and_read_back_as_it_is() {
        for (chain, word) in [(IntentChain::Keys, "keys"), (IntentChain::Tenant, "tenant")] {
            let sent = intent(chain, 42);
            let text = sent.message().to_json();
            assert_eq!(
                text,
                format!(
                    r#"{{"t":"apply_control","v":2,"tenant":"{TENANT}","chain":"{word}","seq":42}}"#
                )
            );
            let admission = admit(&serde_json::from_str::<Value>(&text).unwrap());
            assert_eq!(admission, Admission::Control(sent.clone()));
            // No finisher in this build: handed back to the dead-letter
            // queue, never run and never dropped.
            assert_eq!(admission.disposition(), Disposition::Refuse);
            assert_eq!(
                (sent.tenant(), sent.chain(), sent.seq()),
                (TENANT, chain, 42)
            );
        }
        assert_eq!(APPLY_CONTROL_DELAY_SECS, 30);
        assert_eq!(Refusal::NoFinisher.code(), "no_finisher");
    }

    #[test]
    fn tenant_zero_and_ids_that_are_no_tenant_have_no_intent() {
        let zero = TenantScope::tenant_zero();
        for tenant in [
            zero.tenant_id(),
            "",
            "t_",
            "default",
            "t_ABC",
            "x_00000000000000a1",
            "t_zz",
            "t_00000000000000a",
            "t_00000000000000a1f",
            "t_0123456789abcdeg",
            "t_00000000000000A1",
        ] {
            assert!(
                ControlIntent::new(tenant, IntentChain::Keys, 1).is_none(),
                "{tenant}"
            );
        }
    }

    #[test]
    fn a_control_message_that_is_not_one_of_this_build_is_refused() {
        use Refusal::{BadBody, BadTenant, NoTenant};
        let good =
            json!({"t": "apply_control", "v": 2, "tenant": TENANT, "chain": "keys", "seq": 7});
        let with = |key: &str, value: Value| {
            let mut body = good.clone();
            body[key] = value;
            body
        };
        let without = |key: &str| {
            let mut body = good.clone();
            body.as_object_mut().unwrap().remove(key);
            body
        };
        let zero = TenantScope::tenant_zero();
        for (body, refusal, what) in [
            (without("tenant"), NoTenant, "no tenant"),
            (with("tenant", Value::Null), NoTenant, "null tenant"),
            (with("tenant", json!(7)), BadTenant, "tenant not a string"),
            (
                with("tenant", json!(zero.tenant_id())),
                BadTenant,
                "tenant 0",
            ),
            (with("tenant", json!("t_A1")), BadTenant, "not a tenant id"),
            (
                with("tenant", json!("t_zz")),
                BadTenant,
                "record-name syntax, not an id",
            ),
            (
                with("tenant", json!("t_00000000000000a")),
                BadTenant,
                "15 hex digits",
            ),
            (
                with("tenant", json!("t_00000000000000a1f")),
                BadTenant,
                "17 hex digits",
            ),
            (with("chain", json!("grants")), BadBody, "unknown chain"),
            (without("chain"), BadBody, "no chain"),
            (with("seq", json!(-1)), BadBody, "negative seq"),
            (with("seq", json!("7")), BadBody, "seq as text"),
            (without("seq"), BadBody, "no seq"),
            (with("unit", json!(1)), BadBody, "a unit"),
            (with("state_seq", json!(0)), BadBody, "a state_seq"),
            (with("keys_seq", json!(0)), BadBody, "a keys_seq"),
            (with("extra", json!(true)), BadBody, "an unknown field"),
        ] {
            assert_refused(&body, refusal, what);
        }
    }

    #[test]
    fn a_control_message_of_another_format_is_refused_never_dropped() {
        for v in [json!(1), json!(3), json!("2"), Value::Null] {
            let body =
                json!({"t": "apply_control", "v": v, "tenant": TENANT, "chain": "keys", "seq": 7});
            assert_refused(&body, Refusal::BadBody, &body.to_string());
        }
        let body = json!({"t": "apply_control", "tenant": TENANT, "chain": "keys", "seq": 7});
        assert_refused(&body, Refusal::BadBody, "no v");
    }

    #[test]
    fn the_format_count_counts_an_intent_as_refused() {
        let mut count = FormatCount::default();
        let line = count.count(
            &Admission::Control(intent(IntentChain::Tenant, 1)),
            velmora_bridge::UnixMs(1_000),
        );
        assert_eq!(
            line.as_deref(),
            Some("job message formats: v1=0 v2=0 refused=1 over 0 s")
        );
    }
}
