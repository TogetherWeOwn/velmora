//! The two formats of a queue message (`velmora_bridge::jobmsg`): the
//! bytes of each, what the reader runs, and what it refuses.

use serde_json::{json, Value};
use velmora_bridge::jobmsg::{admit, Admission, JobFormat, JobTenant, Refusal, TENANT_FIELDS};
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
    assert_refused(&with(&gc, "t", json!("nope")), BadBody, "unknown job type");
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
