//! The S3 request path on a unit (`docs/units.md`, "Requests"; AM-64,
//! package L1-5).
//!
//! The first half sends S3 requests through `Bridge::handle` with a
//! catalogue whose request methods are request calls to a unit, through
//! JSON (`service_support::unit_rig`): objects, conditional PUT, the
//! multipart upload bound to its bucket and key, Complete's publication,
//! and a Complete whose answer was lost. The whole handler suite runs the
//! same way with `VELMORA_UNIT_REQUESTS=1`.
//!
//! The second half calls a managed tenant's unit directly: who may make
//! a request call, the tenant's state, closing buckets, the size guard,
//! the bounds, the presigned `key_row` and `key_row` under an expired
//! lease.

mod service_support;

use std::rc::Rc;

use serde_json::Value;
use service_support::*;
use velmora_bridge::recovery::Recorded;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::call::HoldMode;
use velmora_bridge::unit::identity::Refusal;
use velmora_bridge::unit::keys::{Access, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::request::{
    PresignRefusal, Presigned, Published, RecordWire, RequestCall, RequestRefusal, MAX_EXTENTS,
    MAX_KEY_BYTES, MAX_PAGE,
};
use velmora_bridge::unit::request_client::{RequestClient, REQUEST_REFUSED};
use velmora_bridge::unit::size::{SizeLimits, SizeRefusal};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::*;

const BUCKET: &str = "vault";

// ---------------------------------------------------------------------------
// Through Bridge::handle, on a unit
// ---------------------------------------------------------------------------

fn calls(rig: &Rig) -> u64 {
    rig.bridge.catalog.unit_calls().expect("a unit rig")
}

async fn get(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
        .await
}

async fn create_upload(rig: &Rig, signer: &Signer, bucket: &str, key: &str) -> String {
    let r = rig
        .call(
            signer,
            Method::Post,
            &path(bucket, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    r.expect(200);
    r.values("UploadId").remove(0)
}

async fn upload_part(
    rig: &Rig,
    signer: &Signer,
    bucket: &str,
    key: &str,
    id: &str,
    n: u16,
    body: &[u8],
) -> Resp {
    rig.call(
        signer,
        Method::Put,
        &path(bucket, key),
        &[("partNumber", &n.to_string()), ("uploadId", id)],
        &[],
        body,
    )
    .await
}

async fn complete(
    rig: &Rig,
    signer: &Signer,
    bucket: &str,
    key: &str,
    id: &str,
    etags: &[String],
) -> Resp {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in etags.iter().enumerate() {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
            i + 1,
            etag.replace('"', "&quot;")
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        signer,
        Method::Post,
        &path(bucket, key),
        &[("uploadId", id)],
        &[],
        xml.as_bytes(),
    )
    .await
}

fn records(rig: &Rig) -> Vec<String> {
    let mut keys: Vec<String> = rig
        .bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| !k.starts_with("x/"))
        .collect();
    keys.sort();
    keys
}

#[tokio::test(flavor = "current_thread")]
async fn objects_round_trip_through_request_calls() {
    let rig = unit_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let before = calls(&rig);
    let body = pattern(7, 70_000);
    rig.put(&signer, BUCKET, "a/one", &body).await.expect(200);
    rig.put(&signer, BUCKET, "a/two", b"two").await.expect(200);
    assert!(calls(&rig) > before, "the PUT went to the unit");

    let r = rig.head(&signer, BUCKET, "a/one").await;
    r.expect(200);
    assert_eq!(r.header("content-length"), Some("70000"));
    let r = get(&rig, &signer, "a/one").await;
    r.expect(200);
    assert_eq!(r.body, body);

    let r = rig
        .call(
            &signer,
            Method::Get,
            &format!("/{BUCKET}"),
            &[("list-type", "2"), ("prefix", "a/")],
            &[],
            b"",
        )
        .await;
    r.expect(200);
    assert_eq!(r.values("Key"), ["a/one", "a/two"]);

    let r = rig
        .call(
            &signer,
            Method::Put,
            &path(BUCKET, "b/copy"),
            &[],
            &[("x-amz-copy-source", &format!("/{BUCKET}/a/one"))],
            b"",
        )
        .await;
    r.expect(200);
    assert_eq!(get(&rig, &signer, "b/copy").await.body, body);

    rig.call(
        &signer,
        Method::Delete,
        &path(BUCKET, "a/one"),
        &[],
        &[],
        b"",
    )
    .await
    .expect(204);
    get(&rig, &signer, "a/one")
        .await
        .expect_error(404, "NoSuchKey");

    let doc =
        "<Delete><Object><Key>a/two</Key></Object><Object><Key>b/copy</Key></Object></Delete>";
    let md5 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        md5::compute(doc.as_bytes()).0,
    );
    rig.call(
        &signer,
        Method::Post,
        &format!("/{BUCKET}"),
        &[("delete", "")],
        &[("content-md5", &md5)],
        doc.as_bytes(),
    )
    .await
    .expect(200);
    get(&rig, &signer, "b/copy")
        .await
        .expect_error(404, "NoSuchKey");
    let r = rig.call(&signer, Method::Get, "/", &[], &[], b"").await;
    r.expect(200);
    assert_eq!(r.values("Name"), [BUCKET]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_conditional_put_is_decided_in_the_units_batch() {
    let rig = unit_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let put_if = |h: &'static str, v: String, body: &'static [u8]| {
        let rig = &rig;
        let signer = &signer;
        async move {
            rig.call(
                signer,
                Method::Put,
                &path(BUCKET, "k"),
                &[],
                &[(h, &v)],
                body,
            )
            .await
        }
    };
    put_if("if-none-match", "*".into(), b"first")
        .await
        .expect(200);
    put_if("if-none-match", "*".into(), b"second")
        .await
        .expect_error(412, "PreconditionFailed");
    assert_eq!(get(&rig, &signer, "k").await.body, b"first");
    let etag = rig.head(&signer, BUCKET, "k").await;
    let etag = etag.header("etag").unwrap().to_string();
    put_if("if-match", "\"0000\"".into(), b"third")
        .await
        .expect_error(412, "PreconditionFailed");
    put_if("if-match", etag, b"fourth").await.expect(200);
    assert_eq!(get(&rig, &signer, "k").await.body, b"fourth");
    rig.call(
        &signer,
        Method::Put,
        &path(BUCKET, "absent"),
        &[],
        &[("if-match", "*")],
        b"x",
    )
    .await
    .expect_error(404, "NoSuchKey");
}

#[tokio::test(flavor = "current_thread")]
async fn an_upload_id_is_bound_to_its_bucket_and_key_and_publishes_whole() {
    let rig = unit_rig();
    let alpha = rig.bucket("alpha", true).await;
    let beta = rig.bucket("beta", true).await;
    let signer = rig.key(AKID, secret(), KeyStatus::Active).await;
    rig.grant(AKID, &alpha, Perm::Rw).await;
    rig.grant(AKID, &beta, Perm::Rw).await;

    let id = create_upload(&rig, &signer, "alpha", "big").await;
    let one = pattern(1, 5 * MIB);
    let two = pattern(2, 1024);
    let r = upload_part(&rig, &signer, "alpha", "big", &id, 1, &one).await;
    r.expect(200);
    let e1 = r.header("etag").unwrap().to_string();
    // Alpha's upload id under beta, or under another key, names nothing.
    upload_part(&rig, &signer, "beta", "big", &id, 2, &two)
        .await
        .expect_error(404, "NoSuchUpload");
    upload_part(&rig, &signer, "alpha", "other", &id, 2, &two)
        .await
        .expect_error(404, "NoSuchUpload");
    complete(&rig, &signer, "beta", "big", &id, std::slice::from_ref(&e1))
        .await
        .expect_error(404, "NoSuchUpload");
    rig.call(
        &signer,
        Method::Delete,
        &path("beta", "big"),
        &[("uploadId", &id)],
        &[],
        b"",
    )
    .await
    .expect_error(404, "NoSuchUpload");

    let r = upload_part(&rig, &signer, "alpha", "big", &id, 2, &two).await;
    r.expect(200);
    let e2 = r.header("etag").unwrap().to_string();
    // Nothing is published before the Complete.
    assert!(rig.live(&alpha, "big").await.is_none());
    let r = complete(
        &rig,
        &signer,
        "alpha",
        "big",
        &id,
        &[e1.clone(), e2.clone()],
    )
    .await;
    r.expect(200);
    let etag = r.values("ETag").remove(0);
    let (generation, extents) = rig.live(&alpha, "big").await.unwrap();
    assert_eq!(generation.extent_count as usize, extents.len());
    assert_eq!(extents.len(), 2);
    let r = rig
        .call(&signer, Method::Get, &path("alpha", "big"), &[], &[], b"")
        .await;
    r.expect(200);
    assert_eq!(r.body, [one, two].concat());
    // A retry answers the receipt.
    let r = complete(&rig, &signer, "alpha", "big", &id, &[e1, e2]).await;
    r.expect(200);
    assert_eq!(r.values("ETag").remove(0), etag);
    assert!(rig.live(&beta, "big").await.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn a_complete_whose_answer_is_lost_is_settled_by_the_fence() {
    let rig = unit_rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let id = create_upload(&rig, &signer, BUCKET, "big").await;
    let r = upload_part(&rig, &signer, BUCKET, "big", &id, 1, b"part one").await;
    let etags = vec![r.header("etag").unwrap().to_string()];
    let before = records(&rig);

    // The call never reached the unit: the fence applies, so the
    // record goes and the upload is still open.
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::NotApplied));
    complete(&rig, &signer, BUCKET, "big", &id, &etags)
        .await
        .expect(500);
    assert_eq!(records(&rig), before);
    assert!(rig.live(&bucket, "big").await.is_none());

    // The unit committed and its answer was lost: the fence finds the
    // upload completed, so the record stays and the object is there.
    rig.bridge
        .catalog
        .sql
        .fail_publish
        .set(Some(PublishFault::Applied));
    complete(&rig, &signer, BUCKET, "big", &id, &etags)
        .await
        .expect(500);
    assert_eq!(records(&rig).len(), before.len() + 1);
    assert_eq!(get(&rig, &signer, "big").await.body, b"part one");
    // And a retry answers the receipt.
    complete(&rig, &signer, BUCKET, "big", &id, &etags)
        .await
        .expect(200);
}

// ---------------------------------------------------------------------------
// A managed tenant's unit, called directly
// ---------------------------------------------------------------------------

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const B1: &str = "b_00000000000000e1";
const B2: &str = "b_00000000000000e2";
const P: &str = "p_member";
const K: &str = "AKREQS00000000000001";
const INTERNAL: &str = "AKINTERNAL0000000001";

fn own() -> UnitName {
    UnitName::new(TenantId::parse("t_0000000000000e01").unwrap(), 0)
}

fn s(state_seq: u64, keys_seq: u64) -> Seqs {
    Seqs {
        state_seq,
        keys_seq,
    }
}

fn worker(u: &Unit<RusqliteSql>, op: UnitOp) -> UnitAnswer {
    u.handle(
        &UnitCall {
            name: own(),
            kind: CallKind::Worker,
            seqs: None,
            authenticated: true,
            listed: true,
            op,
        },
        NOW,
    )
}

fn sync(u: &Unit<RusqliteSql>, seqs: Seqs, state: TenantState, mode: Option<HoldMode>) {
    let a = worker(
        u,
        UnitOp::Sync {
            head: SyncHead {
                seqs,
                tenant_state: state,
                tenant_mode: mode,
                restoring_since: None,
                lift: None,
            },
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
}

fn born_with(limits: SizeLimits) -> Unit<RusqliteSql> {
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "").with_size_limits(limits);
    let a = u.handle(
        &UnitCall {
            name: own(),
            kind: CallKind::Worker,
            seqs: Some(s(3, 0)),
            authenticated: true,
            listed: true,
            op: UnitOp::Provision {
                token: BirthToken {
                    name: own(),
                    jurisdiction: String::new(),
                    record_seq: 3,
                    schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
                    key_scheme: 2,
                    kind: BirthKind::Birth,
                },
                sealed: b"sealed".to_vec(),
            },
        },
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    sync(&u, s(3, 0), TenantState::Active, None);
    u.sql()
        .apply(&format!(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('{B1}', 'alpha', 'o', x'02', 1, 1), ('{B2}', 'beta', 'o', x'02', 1, 1);"
        ))
        .unwrap();
    u
}

fn born() -> Unit<RusqliteSql> {
    born_with(SizeLimits::default())
}

fn request(seqs: Seqs, call: RequestCall) -> UnitCall {
    UnitCall {
        name: own(),
        kind: CallKind::Request,
        seqs: Some(seqs),
        authenticated: true,
        listed: true,
        op: UnitOp::Request {
            call: Box::new(call),
        },
    }
}

fn ask(u: &Unit<RusqliteSql>, seqs: Seqs, call: RequestCall) -> UnitAnswer {
    u.handle(&request(seqs, call), NOW)
}

fn ok(a: UnitAnswer) -> Value {
    match a {
        UnitAnswer::Ok { body, .. } => body,
        other => panic!("not ok: {other:?}"),
    }
}

fn refused(a: &UnitAnswer) -> (Refused, bool) {
    match a {
        UnitAnswer::Refused { reason, alarm } => (*reason, *alarm),
        other => panic!("not refused: {other:?}"),
    }
}

fn changes(u: &Unit<RusqliteSql>) -> i64 {
    u.sql()
        .with_conn(|c| c.query_row("SELECT total_changes()", [], |r| r.get(0)))
        .unwrap()
}

fn live_generation() -> RequestCall {
    RequestCall::live_generation {
        bucket: BucketId::new(B1),
        key: "k".into(),
    }
}

fn raise_floor(bucket: &str) -> RequestCall {
    RequestCall::raise_floor {
        bucket: BucketId::new(bucket),
        key: "k".into(),
        id: GenerationId::new("g_0019a00000000e1e1e1e1e1e1e1e1"),
        generation: false,
    }
}

fn extent(bucket: &str, g: &GenerationId) -> ExtentRow {
    ExtentRow {
        id: ExtentId::new("x_0000000000000000000000e001"),
        bucket_id: BucketId::new(bucket),
        generation_id: Some(g.clone()),
        state: ExtentState::Committed,
        seq: Some(0),
        plain_offset: Some(0),
        plain_size: 3,
        cipher_size: 19,
        media_header: vec![0; 48],
        key_mode: 1,
        wrapped_file_key: Some(vec![3; 40]),
        plain_md5: [5; 16],
        plain_sha256: [6; 32],
        cipher_sha256: [7; 32],
        safety_state: SafetyState::Held,
        article_count: None,
        plan_rev: 0,
        last_verified_at: None,
        release_evidence: None,
        released_at: None,
        created_at: NOW,
    }
}

fn commit(bucket: &str) -> RequestCall {
    let g = GenerationId::new("g_0019a00000000e2e2e2e2e2e2e2e2");
    RequestCall::commit_generation {
        c: CommitGeneration {
            generation: GenerationRow {
                id: g.clone(),
                bucket_id: BucketId::new(bucket),
                key: "k".into(),
                state: GenerationState::Live,
                size: 3,
                etag: "\"e\"".into(),
                checksum_json: None,
                content_json: "{}".into(),
                user_meta_json: "{}".into(),
                extent_count: 1,
                created_at: NOW,
                retired_at: None,
            },
            extents: vec![extent(bucket, &g)],
            now: NOW,
        },
        condition: Some(Precondition::Absent),
        record: RecordWire {
            generation: g,
            key: "m/g".into(),
        },
    }
}

#[test]
fn a_request_call_needs_the_request_kind_authentication_and_numbers() {
    let u = born();
    let mut c = request(s(3, 0), live_generation());
    assert!(matches!(u.handle(&c, NOW), UnitAnswer::Ok { .. }));

    c.authenticated = false;
    assert_eq!(refused(&u.handle(&c, NOW)).0, Refused::Unauthenticated);
    c.authenticated = true;
    for kind in [CallKind::Job, CallKind::Fanout, CallKind::Worker] {
        c.kind = kind;
        assert_eq!(
            refused(&u.handle(&c, NOW)).0,
            Refused::Unauthenticated,
            "{kind:?}"
        );
    }
    c.kind = CallKind::Request;
    c.seqs = None;
    assert_eq!(
        refused(&u.handle(&c, NOW)).0,
        Refused::Identity(Refusal::NoNumbers)
    );
    c.seqs = Some(s(4, 0));
    assert!(matches!(u.handle(&c, NOW), UnitAnswer::SyncNeeded { .. }));
    sync(&u, s(5, 0), TenantState::Active, None);
    c.seqs = Some(s(4, 0));
    assert!(matches!(
        u.handle(&c, NOW),
        UnitAnswer::Stale { seqs } if seqs == s(5, 0)
    ));
    c.seqs = Some(s(5, 0));
    assert!(matches!(u.handle(&c, NOW), UnitAnswer::Ok { .. }));
}

#[test]
fn the_tenant_state_decides_reads_and_writes() {
    let u = born();
    assert!(matches!(
        ask(&u, s(3, 0), raise_floor(B1)),
        UnitAnswer::Ok { .. }
    ));
    sync(
        &u,
        s(4, 0),
        TenantState::Suspended,
        Some(HoldMode::ReadOnly),
    );
    ok(ask(&u, s(4, 0), live_generation()));
    ok(ask(
        &u,
        s(4, 0),
        RequestCall::touch_read {
            extent: ExtentId::new("x_0000000000000000000000e001"),
            now: NOW,
            min_gap_ms: 1,
            from_cache: false,
        },
    ));
    let before = changes(&u);
    assert_eq!(
        refused(&ask(&u, s(4, 0), raise_floor(B1))).0,
        Refused::AccountProblem
    );
    assert_eq!(changes(&u), before, "a refused write keeps nothing");
    for (n, state, mode) in [
        (5, TenantState::Suspended, Some(HoldMode::Locked)),
        (6, TenantState::Deleting, None),
        (7, TenantState::Shredding, None),
    ] {
        sync(&u, s(n, 0), state, mode);
        for call in [live_generation(), raise_floor(B1)] {
            assert_eq!(
                refused(&ask(&u, s(n, 0), call)).0,
                Refused::AccountProblem,
                "{state:?}"
            );
        }
    }
}

#[test]
fn a_restoring_or_provisioning_unit_is_closed_to_request_calls() {
    let u = born();
    let a = worker(
        &u,
        UnitOp::Sync {
            head: SyncHead {
                seqs: s(4, 0),
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: Some(4),
                lift: None,
            },
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    assert!(matches!(
        ask(&u, s(4, 0), live_generation()),
        UnitAnswer::Closed { .. }
    ));
}

#[test]
fn a_closing_bucket_is_not_found_and_takes_no_rows() {
    let u = born();
    let a = worker(
        &u,
        UnitOp::BucketClose {
            bucket_id: B2.into(),
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    let seqs = s(3, 0);
    assert_eq!(
        ok(ask(
            &u,
            seqs,
            RequestCall::bucket_by_name {
                name: "beta".into()
            }
        )),
        Value::Null
    );
    assert_ne!(
        ok(ask(
            &u,
            seqs,
            RequestCall::bucket_by_name {
                name: "alpha".into()
            }
        )),
        Value::Null
    );
    // Every write that adds a row naming it.
    let before = changes(&u);
    for call in [
        raise_floor(B2),
        commit(B2),
        RequestCall::delete_object_before {
            bucket: BucketId::new(B2),
            key: "k".into(),
            before: GenerationId::new("g_0019a00000000e1e1e1e1e1e1e1e1"),
            now: NOW,
        },
        RequestCall::create_upload {
            u: UploadRow {
                id: UploadId::new("u_00000000000000e1"),
                bucket_id: BucketId::new(B2),
                key: "k".into(),
                content_json: "{}".into(),
                user_meta_json: "{}".into(),
                state: UploadState::Open,
                revision: 0,
                completed_generation_id: None,
                complete_digest: None,
                result_etag: None,
                initiated_at: NOW,
            },
        },
    ] {
        let name = call.name();
        assert_eq!(refused(&ask(&u, seqs, call)).0, Refused::NotFound, "{name}");
    }
    assert_eq!(changes(&u), before);
    // Taking rows away still runs.
    ok(ask(
        &u,
        seqs,
        RequestCall::settle_floor {
            bucket: BucketId::new(B2),
            key: "k".into(),
            id: GenerationId::new("g_0019a00000000e1e1e1e1e1e1e1e1"),
        },
    ));
    // The open bucket takes them.
    ok(ask(&u, seqs, raise_floor(B1)));
}

#[test]
fn a_full_unit_refuses_calls_that_add_extents_or_rows() {
    let u = born_with(SizeLimits {
        bytes: u64::MAX,
        extents: 0,
    });
    let seqs = s(3, 0);
    assert_eq!(
        refused(&ask(&u, seqs, commit(B1))).0,
        Refused::Size(SizeRefusal::TooManyExtents)
    );
    ok(ask(&u, seqs, raise_floor(B1)));
    ok(ask(&u, seqs, live_generation()));

    let u = born_with(SizeLimits {
        bytes: 0,
        extents: u64::MAX,
    });
    let before = changes(&u);
    for call in [commit(B1), raise_floor(B1)] {
        assert_eq!(
            refused(&ask(&u, seqs, call)).0,
            Refused::Size(SizeRefusal::DatabaseFull)
        );
    }
    assert_eq!(changes(&u), before);
    // Reads, and calls that only take rows away, still run.
    ok(ask(&u, seqs, live_generation()));
    ok(ask(
        &u,
        seqs,
        RequestCall::abandon_intents {
            write: WriteId::new("w_00000000000000e1"),
        },
    ));
}

#[test]
fn a_call_above_its_bounds_is_refused_with_an_alarm() {
    let u = born();
    let seqs = s(3, 0);
    let keys = |n: usize| RequestCall::key_heads {
        bucket: BucketId::new(B1),
        keys: (0..n).map(|i| format!("k{i}")).collect(),
    };
    ok(ask(&u, seqs, keys(MAX_PAGE as usize)));
    let list = |max_keys: u32, prefix: String| RequestCall::list_heads {
        bucket: BucketId::new(B1),
        q: ListQuery {
            prefix,
            delimiter: None,
            after: None,
            skip_prefix: None,
            max_keys,
        },
    };
    ok(ask(&u, seqs, list(MAX_PAGE + 1, String::new())));
    ok(ask(&u, seqs, list(1, "p".repeat(MAX_KEY_BYTES))));
    let upload_extents = |limit: u32| RequestCall::upload_extents {
        bucket: BucketId::new(B1),
        key: "k".into(),
        upload: UploadId::new("u_00000000000000e1"),
        limit,
    };
    ok(ask(&u, seqs, upload_extents(MAX_EXTENTS)));
    for call in [
        keys(MAX_PAGE as usize + 1),
        list(MAX_PAGE + 2, String::new()),
        list(1, "p".repeat(MAX_KEY_BYTES + 1)),
        upload_extents(MAX_EXTENTS + 1),
        RequestCall::live_generation {
            bucket: BucketId::new(B1),
            key: "k".repeat(MAX_KEY_BYTES + 1),
        },
        RequestCall::usage_buckets {
            after: String::new(),
            limit: MAX_PAGE + 1,
        },
    ] {
        let name = call.name();
        assert_eq!(
            refused(&ask(&u, seqs, call)),
            (Refused::Request(RequestRefusal::OutOfBounds), true),
            "{name}"
        );
    }
}

#[test]
fn the_operator_reads_answer_on_a_unit() {
    let u = born();
    let seqs = s(3, 0);
    for call in [
        RequestCall::outbox_stats {},
        RequestCall::intent_stats { open_before: NOW },
        RequestCall::usage_counters {},
        RequestCall::usage_snapshot { hours: 24 },
        RequestCall::usage_buckets {
            after: String::new(),
            limit: 200,
        },
        RequestCall::usage_recounts {},
        RequestCall::hot_stats {},
        RequestCall::restore_pending {},
    ] {
        let name = call.name();
        let before = changes(&u);
        let a = ask(&u, seqs, call);
        assert!(matches!(a, UnitAnswer::Ok { .. }), "{name}: {a:?}");
        assert_eq!(changes(&u), before, "{name} wrote");
    }
}

// --- the Worker's side: RequestClient over a unit, through JSON

struct Port(Rc<Unit<RusqliteSql>>);

impl velmora_bridge::tenant_catalog::UnitPort for Port {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
        let call: UnitCall = serde_json::from_str(&serde_json::to_string(call).unwrap()).unwrap();
        let a = self.0.handle(&call, NOW);
        Ok(serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_client_reads_answers_back_and_keeps_the_first_refusal() {
    let u = Rc::new(born());
    let client = RequestClient::new(Port(Rc::clone(&u)), own(), s(3, 0));
    let b = client.bucket_by_name("alpha").await.unwrap().unwrap();
    assert_eq!(b.id.as_str(), B1);
    assert!(client.bucket_by_name("nope").await.unwrap().is_none());
    assert!(client.live_generation(&b.id, "k").await.unwrap().is_none());
    assert_eq!(client.buckets_for(K).await.unwrap(), Vec::new());
    assert!(client.refusal().is_none());

    // A publication answers without its proof; the Worker's own comes
    // back as the refused one.
    let g = GenerationId::new("g_0019a00000000e3e3e3e3e3e3e3e3");
    let record = Recorded::for_test(&g);
    let RequestCall::commit_generation { mut c, .. } = commit(B1) else {
        unreachable!()
    };
    c.generation.id = g.clone();
    c.extents[0].generation_id = Some(g.clone());
    assert_eq!(
        client
            .commit_generation(&c, Some(&Precondition::Absent), record)
            .await
            .unwrap(),
        PublishOutcome::Applied
    );
    let again = Recorded::for_test(&g);
    match client
        .commit_generation(&c, Some(&Precondition::Absent), again)
        .await
        .unwrap()
    {
        PublishOutcome::Refused(r) => assert_eq!(r.generation(), &g),
        other => panic!("{other:?}"),
    }

    sync(
        &u,
        s(4, 0),
        TenantState::Suspended,
        Some(HoldMode::ReadOnly),
    );
    let client = RequestClient::new(Port(Rc::clone(&u)), own(), s(4, 0));
    let e = client.raise_floor(&b.id, "k", &g, false).await.unwrap_err();
    assert!(matches!(e, BridgeError::Invalid(REQUEST_REFUSED)), "{e:?}");
    assert!(matches!(
        client.refusal(),
        Some(UnitAnswer::Refused {
            reason: Refused::AccountProblem,
            ..
        })
    ));
    // Only the first refusal is kept.
    let stale = RequestClient::new(Port(Rc::clone(&u)), own(), s(3, 0));
    assert!(stale.bucket_by_name("alpha").await.is_err());
    assert!(matches!(stale.refusal(), Some(UnitAnswer::Stale { .. })));
}

#[test]
fn published_rebuilds_the_outcome_from_the_workers_record() {
    let g = GenerationId::new("g_0019a00000000e4e4e4e4e4e4e4e4");
    assert_eq!(
        Published::Applied.outcome(Recorded::for_test(&g)),
        PublishOutcome::Applied
    );
    for p in [Published::Refused, Published::Fenced] {
        let (PublishOutcome::Refused(u) | PublishOutcome::Fenced(u)) =
            p.outcome(Recorded::for_test(&g))
        else {
            panic!("{p:?}");
        };
        assert_eq!(u.generation(), &g);
        assert_eq!(u.key(), Recorded::for_test(&g).key());
    }
}

// --- key_row: presigned (AM-64) and under an expired lease (AM-63)

fn grant(bucket: &str, access: Access) -> KeyGrant {
    KeyGrant {
        bucket_id: bucket.into(),
        access,
        expires_at: None,
        prefix: None,
        ip_list: vec![],
    }
}

fn subject(id: &str, kind: KeyKind, seq: u64) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        kind,
        status: SubjectStatus::Active,
        held: false,
        made_by: None,
        grants: vec![],
        created_at: 1,
        secret_wrapped: None,
        secret_kek_version: None,
        owner_ref: None,
        last_seq: seq,
        rid: None,
    }
}

/// The unit with its internal key (seq 1), the principal `P` with `rw`
/// on alpha and `ro` on beta (seq 2), and an S3 key under it (seq 3).
fn with_keys() -> Unit<RusqliteSql> {
    let u = born();
    let internal = KeyEntry {
        secret_wrapped: Some(vec![2, 0xcc, 0xdd]),
        secret_kek_version: Some(1),
        ..subject(INTERNAL, KeyKind::Internal, 1)
    };
    let principal = KeyEntry {
        grants: vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        owner_ref: Some("member-1".into()),
        ..subject(P, KeyKind::Principal, 2)
    };
    let key = KeyEntry {
        made_by: Some(P.into()),
        grants: vec![grant(B1, Access::Rw)],
        secret_wrapped: Some(vec![2, 0xaa, 0xbb]),
        secret_kek_version: Some(1),
        ..subject(K, KeyKind::S3, 3)
    };
    apply(&u, 0, vec![internal, principal, key]);
    sync(&u, s(3, 3), TenantState::Active, None);
    u
}

fn apply(u: &Unit<RusqliteSql>, from_seq: u64, entries: Vec<KeyEntry>) {
    let a = worker(
        u,
        UnitOp::ApplyKeys {
            from_seq,
            entries: entries.into_iter().map(Into::into).collect(),
            answers: vec![],
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
}

fn key_row(akid: &str, presigned: Option<Presigned>, seqs: Seqs) -> UnitCall {
    UnitCall {
        name: own(),
        kind: CallKind::Request,
        seqs: Some(seqs),
        // The first call of a request: before SigV4.
        authenticated: false,
        listed: true,
        op: UnitOp::KeyRow {
            access_key_id: akid.into(),
            presigned,
        },
    }
}

fn presigned(principal: &str, bucket: &str, create_only: bool) -> Option<Presigned> {
    Some(Presigned {
        principal: principal.into(),
        bucket: bucket.into(),
        create_only,
    })
}

#[test]
fn the_presigned_key_row_checks_the_principal_and_never_withholds_the_row() {
    let u = with_keys();
    let seqs = s(3, 3);
    let check = |akid: &str, p: Option<Presigned>| {
        let before = changes(&u);
        let body = ok(u.handle(&key_row(akid, p, seqs), NOW));
        assert_eq!(changes(&u), before, "read-only");
        assert_eq!(body["lease_expired"], false);
        assert_eq!(body["state"]["tenant_state"], "active");
        body
    };
    let body = check(INTERNAL, presigned(P, "alpha", false));
    assert_eq!(body["key"]["access_key_id"], INTERNAL);
    assert_eq!(body["key"]["status"], "active");
    assert_eq!(
        body["presigned"],
        serde_json::json!({ "ok": true, "refusal": null, "bucket_id": B1, "access": "rw" })
    );
    let body = check(INTERNAL, presigned(P, "beta", false));
    assert_eq!(body["presigned"]["access"], "ro");
    assert_eq!(body["presigned"]["ok"], true);

    let refusal = |r: PresignRefusal| serde_json::to_value(r).unwrap();
    for (p, why) in [
        // A create-only URL needs rw.
        (presigned(P, "beta", true), PresignRefusal::NoGrant),
        (
            presigned("p_nobody", "alpha", false),
            PresignRefusal::PrincipalUnknown,
        ),
        (presigned(P, "nope", false), PresignRefusal::NoSuchBucket),
        (
            presigned("not an id!", "alpha", false),
            PresignRefusal::Malformed,
        ),
    ] {
        let body = check(INTERNAL, p);
        // The row is never withheld: the Worker checks SigV4 first.
        assert_eq!(body["key"]["access_key_id"], INTERNAL);
        assert_eq!(body["presigned"]["ok"], false);
        assert_eq!(body["presigned"]["refusal"], refusal(why));
        assert_eq!(body["presigned"]["access"], Value::Null);
    }
    // Only the internal key signs on this entry point.
    let body = check(K, presigned(P, "alpha", false));
    assert_eq!(body["key"], Value::Null);
    assert_eq!(
        body["presigned"]["refusal"],
        refusal(PresignRefusal::NotInternal)
    );
    // On the s3 entry point the internal key is no key at all.
    let body = check(INTERNAL, None);
    assert_eq!(body["key"], Value::Null);
    assert!(body.get("presigned").is_none());
    assert_eq!(check(K, None)["key"]["access_key_id"], K);

    // A member that is disabled, or held, or narrowed off the bucket.
    let mut p = KeyEntry {
        grants: vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
        owner_ref: Some("member-1".into()),
        status: SubjectStatus::Disabled,
        ..subject(P, KeyKind::Principal, 4)
    };
    apply(&u, 3, vec![p.clone()]);
    sync(&u, s(3, 4), TenantState::Active, None);
    let seqs = s(3, 4);
    let body = ok(u.handle(&key_row(INTERNAL, presigned(P, "alpha", false), seqs), NOW));
    assert_eq!(
        body["presigned"]["refusal"],
        refusal(PresignRefusal::PrincipalInactive)
    );
    p.status = SubjectStatus::Active;
    p.held = true;
    p.last_seq = 5;
    apply(&u, 4, vec![p.clone()]);
    sync(&u, s(3, 5), TenantState::Active, None);
    let body = ok(u.handle(
        &key_row(INTERNAL, presigned(P, "alpha", false), s(3, 5)),
        NOW,
    ));
    assert_eq!(
        body["presigned"]["refusal"],
        refusal(PresignRefusal::PrincipalHeld)
    );
    p.held = false;
    p.grants = vec![grant(B2, Access::Ro)];
    p.last_seq = 6;
    apply(&u, 5, vec![p]);
    sync(&u, s(3, 6), TenantState::Active, None);
    let body = ok(u.handle(
        &key_row(INTERNAL, presigned(P, "alpha", false), s(3, 6)),
        NOW,
    ));
    assert_eq!(
        body["presigned"]["refusal"],
        refusal(PresignRefusal::NoGrant)
    );
}

#[test]
fn the_presigned_check_leaves_a_closing_bucket_out() {
    let u = with_keys();
    let a = worker(
        &u,
        UnitOp::BucketClose {
            bucket_id: B1.into(),
        },
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    let body = ok(u.handle(
        &key_row(INTERNAL, presigned(P, "alpha", false), s(3, 3)),
        NOW,
    ));
    assert_eq!(
        body["presigned"]["refusal"],
        serde_json::to_value(PresignRefusal::NoSuchBucket).unwrap()
    );
}

#[test]
fn key_row_under_an_expired_lease_is_read_only_and_marked() {
    let u = with_keys();
    let head = u.head().unwrap();
    for c in [
        key_row(K, None, s(3, 3)),
        key_row(INTERNAL, presigned(P, "alpha", false), s(3, 3)),
    ] {
        let before = changes(&u);
        let body = ok(u.key_row_expired(&c, &head).unwrap());
        assert_eq!(changes(&u), before);
        assert_eq!(body["lease_expired"], true);
        assert!(!body["key"].is_null());
    }
    // Only an unauthenticated request call's key_row.
    let mut c = key_row(K, None, s(3, 3));
    c.authenticated = true;
    assert_eq!(
        refused(&u.key_row_expired(&c, &head).unwrap()).0,
        Refused::Unauthenticated
    );
    let mut c = key_row(K, None, s(3, 3));
    c.kind = CallKind::Job;
    assert_eq!(
        refused(&u.key_row_expired(&c, &head).unwrap()).0,
        Refused::Unauthenticated
    );
    let mut c = request(s(3, 3), live_generation());
    c.authenticated = false;
    assert_eq!(
        refused(&u.key_row_expired(&c, &head).unwrap()).0,
        Refused::Unauthenticated
    );
}
