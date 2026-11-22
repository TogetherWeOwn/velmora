//! The contract against its own examples: every body parses into its
//! type and back, every request passes its checks, and the rules the
//! crate states hold.

use std::collections::HashSet;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use velmora_mgmt_types::codes::{Code, KofraMapping, TenancyMapping};
use velmora_mgmt_types::examples::{Example, BUCKET, EXAMPLES, KEY, TENANT};
use velmora_mgmt_types::idem::{fingerprint, TokenClass};
use velmora_mgmt_types::ids::{self, MAX_SAFE_INTEGER};
use velmora_mgmt_types::position::{
    DayPosition, EventPosition, KeyPosition, NamePosition, ObjectPosition,
};
use velmora_mgmt_types::query::{self, BucketQuery, KeyQuery, List, UsageDaysQuery};
use velmora_mgmt_types::wire::*;
use velmora_mgmt_types::{headers, paths, Validate};

/// `json` parses as `T`, and `T` serializes back to the same JSON value.
fn round_trip<T: DeserializeOwned + Serialize>(json: &str) -> T {
    let typed: T = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}: {json}"));
    let back = serde_json::to_value(&typed).unwrap();
    let want: Value = serde_json::from_str(json).unwrap();
    assert_eq!(back, want, "{json}");
    typed
}

fn request<T: DeserializeOwned + Serialize + Validate>(json: &str) {
    round_trip::<T>(json);
    parse_request::<T>(json.as_bytes()).unwrap_or_else(|c| panic!("{}: {json}", c.as_str()));
}

fn check_request(ex: &Example) {
    let Some(json) = ex.request else { return };
    match ex.call {
        "Tenancy::create_tenant" => request::<TenantCreate>(json),
        "Tenancy::create_principal" => request::<PrincipalCreate>(json),
        "restore_tenant" => request::<TenantRestore>(json),
        "create_bucket" => request::<BucketCreate>(json),
        "create_key" => request::<KeyCreate>(json),
        "update_key" => request::<KeyUpdate>(json),
        "objects" => request::<ObjectList>(json),
        "presign" => request::<Presign>(json),
        other => panic!("no request type for {other}"),
    }
}

fn check_answer(ex: &Example) {
    let Some(json) = ex.answer else {
        assert_eq!(ex.status, 204, "{}", ex.call);
        return;
    };
    match ex.call {
        "Tenancy::create_tenant" | "tenant" | "delete_tenant" | "restore_tenant" => {
            round_trip::<Tenant>(json);
        }
        "Tenancy::create_principal" => {
            round_trip::<Principal>(json);
        }
        "tenant_reach" => {
            round_trip::<Reach>(json);
        }
        "buckets" | "(name lookup)" => {
            round_trip::<Page<Bucket>>(json);
        }
        "bucket" | "create_bucket" => {
            round_trip::<Bucket>(json);
        }
        "keys" => {
            round_trip::<Page<Key>>(json);
        }
        "key" | "update_key" => {
            round_trip::<Key>(json);
        }
        "create_key" => {
            let k = round_trip::<KeyCreated>(json);
            assert!(k.secret_access_key.is_some());
        }
        "usage" => {
            round_trip::<Usage>(json);
        }
        "usage_days" => {
            let p = round_trip::<Page<UsageDay>>(json);
            DayPosition::parse(p.next.as_deref().unwrap()).unwrap();
        }
        "usage_buckets" => {
            round_trip::<Page<BucketUsage>>(json);
        }
        "events" => {
            let p = round_trip::<EventPage>(json);
            EventPosition::parse(&p.position).unwrap();
            for e in &p.items {
                assert!(ids::valid_event_type(&e.kind));
                assert!(EVENT_TYPES.contains(&e.kind.as_str()));
            }
        }
        "objects" => {
            let p = round_trip::<ObjectPage>(json);
            ObjectPosition::parse(p.next.as_deref().unwrap()).unwrap();
        }
        "presign" => {
            round_trip::<Presigned>(json);
        }
        other => panic!("no answer type for {other}"),
    }
}

/// The path of each example, built with [`paths`] and [`query`].
fn built_path(ex: &Example) -> String {
    let list = |limit| List { after: None, limit };
    match ex.call {
        "Tenancy::create_tenant" => paths::tenants(),
        "Tenancy::create_principal" => paths::principals(TENANT),
        "tenant" => paths::tenant(TENANT),
        "tenant_reach" => paths::tenant_reach(TENANT),
        "delete_tenant" => paths::tenant_delete(TENANT, 30),
        "restore_tenant" => paths::tenant_restore(TENANT),
        "buckets" => paths::with_query(
            paths::buckets(TENANT),
            &BucketQuery::Page(list(100)).to_query(),
        ),
        "(name lookup)" => paths::with_query(
            paths::buckets(TENANT),
            &BucketQuery::Names(vec!["photos".into(), "gone".into()]).to_query(),
        ),
        "bucket" | "delete_bucket" => paths::bucket(TENANT, BUCKET),
        "create_bucket" => paths::buckets(TENANT),
        "keys" => paths::with_query(
            paths::keys(TENANT),
            &KeyQuery {
                kind: Some(KeyKind::S3),
                list: list(100),
            }
            .to_query(),
        ),
        "key" | "update_key" | "revoke_key" => paths::key(TENANT, KEY),
        "create_key" => paths::keys(TENANT),
        "usage" => paths::usage(TENANT),
        "usage_days" => paths::with_query(
            paths::usage_days(TENANT),
            &UsageDaysQuery {
                after_day: velmora_mgmt_types::position::Day::new(2026, 11, 1),
                list: list(1),
            }
            .to_query(),
        ),
        "usage_buckets" => paths::with_query(paths::usage_buckets(TENANT), &list(100).to_query()),
        "events" => paths::with_query(
            paths::events(TENANT),
            &List {
                after: Some(EventPosition { epoch: 1, seq: 40 }.encode()),
                limit: 100,
            }
            .to_query(),
        ),
        "objects" => paths::objects_list(TENANT),
        "presign" => paths::objects_presign(TENANT),
        other => panic!("no path for {other}"),
    }
}

/// The calls of the contract that write. Every one but `presign` needs an
/// `Idempotency-Key`; `objects` is a read.
fn writes(call: &str) -> bool {
    matches!(
        call,
        "Tenancy::create_tenant"
            | "Tenancy::create_principal"
            | "delete_tenant"
            | "restore_tenant"
            | "create_bucket"
            | "delete_bucket"
            | "create_key"
            | "update_key"
            | "revoke_key"
    )
}

#[test]
fn every_example_parses_into_its_types_and_back() {
    assert_eq!(EXAMPLES.len(), 22, "21 calls and the name lookup");
    let names: HashSet<&str> = EXAMPLES.iter().map(|e| e.call).collect();
    assert_eq!(names.len(), EXAMPLES.len(), "one example per call");
    for ex in EXAMPLES {
        check_request(ex);
        check_answer(ex);
        assert_eq!(built_path(ex), ex.path, "{}", ex.call);
        assert!(ex.path.starts_with(paths::PREFIX));
        assert!(
            ex.idempotency_key.is_some() == writes(ex.call),
            "{}: Idempotency-Key on every write, and only there",
            ex.call
        );
        if let Some(k) = ex.idempotency_key {
            assert!(ids::valid_idempotency_key(k));
        }
        if let Some(a) = ex.acting {
            assert!(ids::valid_owner_ref(a));
        }
        // The acting header is on every write but the two sign-up calls,
        // and on the object calls.
        let acting = (writes(ex.call) && !ex.call.starts_with("Tenancy::"))
            || matches!(ex.call, "objects" | "presign");
        assert_eq!(ex.acting.is_some(), acting, "{}", ex.call);
    }
}

#[test]
fn the_confirmed_token_is_used_where_the_contract_says() {
    for ex in EXAMPLES {
        let confirmed = matches!(
            ex.call,
            "Tenancy::create_tenant"
                | "Tenancy::create_principal"
                | "delete_tenant"
                | "restore_tenant"
                | "delete_bucket"
                // The example's update is a widening.
                | "update_key"
        );
        assert_eq!(ex.token == TokenClass::Confirmed, confirmed, "{}", ex.call);
    }
}

/// A request parser, for a table of bodies.
type Parse = fn(&[u8]) -> Result<(), Code>;

#[test]
fn a_request_refuses_unknown_fields() {
    let bad: &[(&str, Parse)] = &[
        (
            r#"{"external_ref":"ws_1","jurisdiction":"us","role":"owner"}"#,
            |b| parse_request::<TenantCreate>(b).map(|_| ()),
        ),
        (
            r#"{"external_ref":"ws_1","jurisdiction":"us","limits":{"storage_bytes":null,"upload_24h_bytes":null,"download_allowance_bytes":null,"active_keys":20,"x":1}}"#,
            |b| parse_request::<TenantCreate>(b).map(|_| ()),
        ),
        (r#"{"owner_ref":"u1","grants":[],"role":"admin"}"#, |b| {
            parse_request::<PrincipalCreate>(b).map(|_| ())
        }),
        (r#"{"deletion_seq":7,"force":true}"#, |b| {
            parse_request::<TenantRestore>(b).map(|_| ())
        }),
        (r#"{"name":"photos","public":true}"#, |b| {
            parse_request::<BucketCreate>(b).map(|_| ())
        }),
        (r#"{"kind":"s3","grants":[],"secret":"x"}"#, |b| {
            parse_request::<KeyCreate>(b).map(|_| ())
        }),
        (r#"{"name":"a","if_seq":1,"status":"active"}"#, |b| {
            parse_request::<KeyUpdate>(b).map(|_| ())
        }),
        (
            r#"{"bucket_id":"b_00aa11bb22cc33dd","limit":1,"versions":true}"#,
            |b| parse_request::<ObjectList>(b).map(|_| ()),
        ),
        (
            r#"{"bucket_id":"b_00aa11bb22cc33dd","key":"a","op":"GetObject","expires_s":60,"url":"x"}"#,
            |b| parse_request::<Presign>(b).map(|_| ()),
        ),
        (
            r#"{"owner_ref":"u1","grants":[{"bucket_id":"b_00aa11bb22cc33dd","access":"ro","x":1}]}"#,
            |b| parse_request::<PrincipalCreate>(b).map(|_| ()),
        ),
    ];
    for (json, parse) in bad {
        assert_eq!(parse(json.as_bytes()), Err(Code::BadRequest), "{json}");
    }
}

#[test]
fn an_answer_takes_a_field_it_does_not_know() {
    let json = r#"{"id":"b_00aa11bb22cc33dd","name":"photos","created_at_ms":1,"stored_bytes":0,"object_count":0,"region":"x"}"#;
    let b: Bucket = serde_json::from_str(json).unwrap();
    assert_eq!(b.name, "photos");
}

#[test]
fn request_checks() {
    let tc = |j: &str| parse_request::<TenantCreate>(j.as_bytes()).map(|_| ());
    assert_eq!(
        tc(r#"{"external_ref":"ws 1","jurisdiction":"us"}"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        tc(r#"{"external_ref":"ws_1","jurisdiction":"US"}"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        tc(r#"{"external_ref":"ws_1","jurisdiction":"us","rate_class":"a b"}"#),
        Err(Code::BadRequest)
    );
    let over = MAX_SAFE_INTEGER + 1;
    assert_eq!(
        tc(&format!(
            r#"{{"external_ref":"ws_1","jurisdiction":"eu","limits":{{"storage_bytes":{over},"upload_24h_bytes":null,"download_allowance_bytes":null,"active_keys":20}}}}"#
        )),
        Err(Code::BadRequest)
    );
    assert_eq!(
        tc(
            r#"{"external_ref":"ws_1","jurisdiction":"eu","limits":{"storage_bytes":-1,"active_keys":20}}"#
        ),
        Err(Code::BadRequest)
    );
    assert_eq!(tc("not json"), Err(Code::BadRequest));
    let huge = format!(
        r#"{{"external_ref":"ws_1","jurisdiction":"eu","rate_class":"{}"}}"#,
        "a".repeat(MAX_REQUEST_BYTES)
    );
    assert_eq!(tc(&huge), Err(Code::BadRequest));

    let restore = |n: u64| {
        parse_request::<TenantRestore>(format!(r#"{{"deletion_seq":{n}}}"#).as_bytes()).map(|_| ())
    };
    assert_eq!(restore(MAX_SAFE_INTEGER), Ok(()));
    assert_eq!(restore(MAX_SAFE_INTEGER + 1), Err(Code::BadRequest));

    let bucket = |n: &str| {
        parse_request::<BucketCreate>(format!(r#"{{"name":"{n}"}}"#).as_bytes()).map(|_| ())
    };
    assert_eq!(bucket("photos"), Ok(()));
    for bad in [
        "ab",
        "Photos",
        "-photos",
        "photos-",
        "pho.tos",
        "pho_tos",
        &"a".repeat(64),
    ] {
        assert_eq!(bucket(bad), Err(Code::BadRequest), "{bad}");
    }

    let ku = |j: &str| parse_request::<KeyUpdate>(j.as_bytes()).map(|_| ());
    assert_eq!(
        ku(r#"{"if_seq":3}"#),
        Err(Code::BadRequest),
        "an update that changes nothing"
    );
    assert_eq!(ku(r#"{"name":"x","if_seq":3}"#), Ok(()));
    assert_eq!(ku(r#"{"name":"","if_seq":3}"#), Err(Code::BadRequest));
    assert_eq!(
        ku(&format!(r#"{{"name":"{}","if_seq":3}}"#, "é".repeat(64))),
        Ok(())
    );
    assert_eq!(
        ku(&format!(r#"{{"name":"{}","if_seq":3}}"#, "é".repeat(65))),
        Err(Code::BadRequest)
    );
    assert_eq!(
        ku(r#"{"name":"a\u0007","if_seq":3}"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        ku(r#"{"grants":[],"if_seq":3}"#),
        Ok(()),
        "a narrowing to nothing"
    );

    let kc = |j: &str| parse_request::<KeyCreate>(j.as_bytes()).map(|_| ());
    assert_eq!(
        kc(r#"{"kind":"app_password","grants":[]}"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        kc(r#"{"kind":"internal","grants":[]}"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        kc(r#"{"kind":"principal","grants":[]}"#),
        Err(Code::BadRequest)
    );

    let ol = |j: &str| parse_request::<ObjectList>(j.as_bytes()).map(|_| ());
    assert_eq!(
        ol(r#"{"bucket_id":"b_00aa11bb22cc33dd","limit":0}"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        ol(r#"{"bucket_id":"b_00aa11bb22cc33dd","limit":1001}"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        ol(r#"{"bucket_id":"photos","limit":1}"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        ol(r#"{"bucket_id":"b_00aa11bb22cc33dd","limit":1,"after":"x"}"#),
        Err(Code::InvalidPosition)
    );
    assert_eq!(
        ol(r#"{"bucket_id":"b_00aa11bb22cc33dd","limit":1,"after":"ka"}"#),
        Ok(())
    );

    let ps = |s: u32| {
        parse_request::<Presign>(
            format!(
                r#"{{"bucket_id":"b_00aa11bb22cc33dd","key":"a","op":"GetObject","expires_s":{s}}}"#
            )
            .as_bytes(),
        )
        .map(|_| ())
    };
    assert_eq!(ps(1), Ok(()));
    assert_eq!(ps(900), Ok(()));
    assert_eq!(ps(0), Err(Code::BadRequest));
    assert_eq!(ps(901), Err(Code::BadRequest));
    assert_eq!(
        parse_request::<Presign>(
            br#"{"bucket_id":"b_00aa11bb22cc33dd","key":"a","op":"PutObject","expires_s":60}"#
        )
        .map(|_| ()),
        Err(Code::BadRequest),
        "a presign is a read only"
    );
}

#[test]
fn grant_lists() {
    let pc = |grants: &str| {
        parse_request::<PrincipalCreate>(
            format!(r#"{{"owner_ref":"usr_1","grants":{grants}}}"#).as_bytes(),
        )
        .map(|_| ())
    };
    assert_eq!(
        pc(r#"[{"bucket_id":"b_00aa11bb22cc33dd","access":"rw"}]"#),
        Ok(())
    );
    for field in [
        r#""prefix":"a/""#,
        r#""expires_at_ms":1"#,
        r#""ip_list":["10.0.0.0/8"]"#,
    ] {
        assert_eq!(
            pc(&format!(
                r#"[{{"bucket_id":"b_00aa11bb22cc33dd","access":"ro",{field}}}]"#
            )),
            Err(Code::GrantLimitsNotServed),
            "{field}"
        );
    }
    assert_eq!(
        pc(r#"[{"bucket_id":"b_00aa11bb22cc33dd","access":"rx"}]"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        pc(r#"[{"bucket_id":"photos","access":"ro"}]"#),
        Err(Code::BadRequest)
    );
    assert_eq!(
        pc(
            r#"[{"bucket_id":"b_00aa11bb22cc33dd","access":"ro"},{"bucket_id":"b_00aa11bb22cc33dd","access":"rw"}]"#
        ),
        Err(Code::BadRequest),
        "one grant per bucket"
    );
    let n_grants = |n: usize| {
        let g: Vec<String> = (0..n)
            .map(|i| format!(r#"{{"bucket_id":"b_{i:016x}","access":"ro"}}"#))
            .collect();
        format!("[{}]", g.join(","))
    };
    assert_eq!(pc(&n_grants(MAX_GRANTS)), Ok(()));
    assert_eq!(pc(&n_grants(MAX_GRANTS + 1)), Err(Code::GrantLimitReached));
}

#[test]
fn the_largest_key_fits_the_stored_answer() {
    // The answer of a key create, as a replay stores it: 64 grants with
    // the longest names, the longest key id and name.
    let grants = (0..MAX_GRANTS)
        .map(|i| Grant {
            bucket_id: format!("b_{i:016x}"),
            bucket_name: Some(format!("{}{i:02}", "a".repeat(61))),
            access: Access::Rw,
        })
        .collect();
    let key = Key {
        id: "A".repeat(ids::MAX_KEY_ID_BYTES),
        kind: KeyKind::S3,
        name: Some("\u{FFFF}".repeat(ids::MAX_KEY_NAME_CHARS)),
        status: KeyStatus::Active,
        grants,
        created_at_ms: MAX_SAFE_INTEGER,
        last_used_at_ms: Some(MAX_SAFE_INTEGER),
        seq: MAX_SAFE_INTEGER,
    };
    let stored = KeyCreated {
        key,
        secret_access_key: None,
    };
    let bytes = serde_json::to_vec(&stored).unwrap();
    assert!(
        bytes.len() <= MAX_STORED_ANSWER_BYTES,
        "{} bytes",
        bytes.len()
    );
    // A replay names the secret as null; it is never left out.
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["secret_access_key"], Value::Null);
}

#[test]
fn debug_never_shows_a_secret_or_a_url() {
    let ex = EXAMPLES.iter().find(|e| e.call == "create_key").unwrap();
    let k: KeyCreated = serde_json::from_str(ex.answer.unwrap()).unwrap();
    let secret = k.secret_access_key.clone().unwrap();
    assert!(!format!("{k:?}").contains(&secret));
    let ex = EXAMPLES.iter().find(|e| e.call == "presign").unwrap();
    let p: Presigned = serde_json::from_str(ex.answer.unwrap()).unwrap();
    assert!(!format!("{p:?}").contains(&p.url));
}

#[test]
fn the_key_update_fingerprint_leaves_out_if_seq() {
    let a: KeyUpdate = serde_json::from_str(
        r#"{"grants":[{"bucket_id":"b_00aa11bb22cc33dd","access":"rw"}],"if_seq":12}"#,
    )
    .unwrap();
    let b: KeyUpdate = serde_json::from_str(
        r#"{ "if_seq": 13, "grants": [ {"access":"rw", "bucket_id":"b_00aa11bb22cc33dd"} ] }"#,
    )
    .unwrap();
    assert_eq!(a.fingerprint_body(), b.fingerprint_body());
    assert_eq!(
        a.fingerprint_body(),
        br#"{"grants":[{"bucket_id":"b_00aa11bb22cc33dd","access":"rw"}]}"#
    );
    let path = paths::key(TENANT, KEY);
    let f = |u: &KeyUpdate| {
        fingerprint(
            TokenClass::Confirmed,
            "PATCH",
            &path,
            Some("usr_1"),
            &u.fingerprint_body(),
        )
    };
    assert_eq!(f(&a), f(&b));
    let renamed = KeyUpdate {
        name: Some("x".into()),
        ..a.clone()
    };
    assert_ne!(f(&renamed), f(&a));
    let narrowed = KeyUpdate {
        grants: Some(vec![GrantIn::new(BUCKET, Access::Ro)]),
        ..a.clone()
    };
    assert_ne!(f(&narrowed), f(&a));
}

#[test]
fn the_code_table() {
    let mut seen = HashSet::new();
    for c in Code::ALL {
        let s = c.as_str();
        assert!(seen.insert(s), "{s} twice");
        assert!(
            s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{s}"
        );
        assert_eq!(Code::parse(s), Some(c));
        assert_eq!(c.body().known(), Some(c));
        let body = serde_json::to_string(&c.body()).unwrap();
        assert_eq!(body, format!(r#"{{"code":"{s}"}}"#));
    }
    assert_eq!(Code::parse("rate_limited"), None);
    let status = |s: &str| Code::parse(s).unwrap().status();
    for (codes, want) in [
        (
            &[
                "bad_request",
                "grant_limits_not_served",
                "idempotency_key_required",
                "invalid_position",
            ][..],
            400,
        ),
        (&["unauthenticated"][..], 401),
        (
            &[
                "insufficient_scope",
                "internal_key_refused",
                "acting_principal_unknown",
                "acting_principal_inactive",
                "grant_not_held",
                "actor_not_permitted",
            ][..],
            403,
        ),
        (
            &[
                "not_found",
                "tenant_not_found",
                "principal_not_found",
                "bucket_not_found",
                "key_not_found",
            ][..],
            404,
        ),
        (&["method_not_allowed"][..], 405),
        (
            &[
                "bucket_already_exists",
                "bucket_not_empty",
                "key_limit_reached",
                "grant_limit_reached",
                "feed_reset",
                "deletion_already_requested",
                "deletion_not_requested",
                "deletion_final",
                "deletion_replayed",
                "tenant_read_only",
                "tenant_unavailable",
                "tenant_restoring",
                "key_changed",
                "principal_exists",
                "key_moved",
                "external_ref_retired",
                "idempotency_key_in_use",
            ][..],
            409,
        ),
        (&["idempotency_key_reused"][..], 422),
        (&["cap_reached"][..], 429),
        (&["internal_error"][..], 500),
        (&["service_unavailable"][..], 503),
    ] {
        for c in codes {
            assert_eq!(status(c), want, "{c}");
        }
    }
    let retry: HashSet<&str> = Code::ALL
        .into_iter()
        .filter(|c| c.retry_after())
        .map(Code::as_str)
        .collect();
    assert_eq!(
        retry,
        HashSet::from([
            "tenant_restoring",
            "key_moved",
            "idempotency_key_in_use",
            "cap_reached",
            "service_unavailable"
        ])
    );
}

#[test]
fn the_kofra_api_mapping() {
    use KofraMapping as K;
    // Gate codes and every velmora fault are Upstream: never a client
    // mistake, and the client must not see "unauthenticated".
    for c in [
        "bad_request",
        "grant_limits_not_served",
        "idempotency_key_required",
        "unauthenticated",
        "insufficient_scope",
        "internal_key_refused",
        "acting_principal_unknown",
        "acting_principal_inactive",
        "not_found",
        "method_not_allowed",
        "tenant_not_found",
        "principal_not_found",
        "principal_exists",
        "internal_error",
    ] {
        assert_eq!(Code::parse(c).unwrap().kofra(), K::Upstream, "{c}");
    }
    let m = |c: &str| Code::parse(c).unwrap().kofra();
    assert_eq!(m("invalid_position"), K::InvalidCursor);
    assert_eq!(m("grant_not_held"), K::GrantNotHeld);
    assert_eq!(m("deletion_replayed"), K::IdempotencyKeyReused);
    assert_eq!(m("idempotency_key_reused"), K::IdempotencyKeyReused);
    assert_eq!(m("tenant_read_only"), K::AccountReadOnly);
    assert_eq!(m("tenant_unavailable"), K::AccountUnavailable);
    assert_eq!(m("actor_not_permitted"), K::DeletionNotCancellable);
    assert_eq!(m("key_changed"), K::RereadKey);
    assert_eq!(m("external_ref_retired"), K::TenancyGone);
    assert_eq!(m("idempotency_key_in_use"), K::IdempotencyKeyInUse);
    assert_eq!(m("cap_reached"), K::Busy);
    for c in ["tenant_restoring", "key_moved", "service_unavailable"] {
        assert_eq!(m(c), K::Unavailable, "{c}");
    }
    // Every "not now" carries Retry-After, and maps to a variant that has
    // one: none of them is stored by kofra-api as a final answer.
    for c in Code::ALL.into_iter().filter(|c| c.retry_after()) {
        assert!(
            matches!(c.kofra(), K::Unavailable | K::Busy | K::IdempotencyKeyInUse),
            "{}",
            c.as_str()
        );
    }
    // The sign-up port.
    assert_eq!(Code::ExternalRefRetired.tenancy(), TenancyMapping::Gone);
    assert_eq!(
        Code::IdempotencyKeyReused.tenancy(),
        TenancyMapping::RetryAndPage
    );
    for c in [
        Code::CapReached,
        Code::ServiceUnavailable,
        Code::IdempotencyKeyInUse,
        Code::InternalError,
        Code::Unauthenticated,
    ] {
        assert_eq!(c.tenancy(), TenancyMapping::Retry, "{}", c.as_str());
    }
}

#[test]
fn id_and_header_forms() {
    assert!(ids::valid_tenant_id(TENANT));
    assert!(
        !ids::valid_tenant_id(ids::TENANT_ZERO),
        "tenant 0 is not a tenant of this plane"
    );
    assert!(!ids::valid_tenant_id("t_1A2B3C4D5E6F7A8B"));
    assert!(!ids::valid_tenant_id("t_1a2b3c4d5e6f7a8"));
    assert!(ids::valid_bucket_id(BUCKET));
    assert!(!ids::valid_bucket_id("photos"));
    assert!(ids::valid_key_id(KEY));
    assert!(!ids::valid_key_id(&"A".repeat(129)));
    assert!(!ids::valid_key_id("AK-1"));
    assert!(ids::valid_principal_id("p_4f2a9c1d0e7b6a35"));
    assert!(!ids::valid_principal_id("p/1"));
    assert!(ids::valid_owner_ref("usr_01JD2Q9A7M"));
    assert!(ids::valid_owner_ref("org:team-1"));
    assert!(ids::valid_owner_ref(&"a".repeat(128)));
    assert!(!ids::valid_owner_ref(&"a".repeat(129)));
    for bad in ["", "a b", "a/b", "a@b", "é"] {
        assert!(!ids::valid_owner_ref(bad), "{bad:?}");
    }
    assert!(ids::valid_idempotency_key("ws_01JD2Q8V5X/usr_01JD2Q9A7M"));
    assert!(ids::valid_idempotency_key(&"~".repeat(255)));
    for bad in [
        String::new(),
        "a b".into(),
        "a\tb".into(),
        "é".into(),
        "a".repeat(256),
    ] {
        assert!(!ids::valid_idempotency_key(&bad), "{bad:?}");
    }
    for t in EVENT_TYPES {
        assert!(ids::valid_event_type(t), "{t}");
    }
    for bad in [
        "bucket",
        "bucket.",
        ".x",
        "bucket..created",
        "Bucket.created",
        "bucket.created2",
    ] {
        assert!(!ids::valid_event_type(bad), "{bad}");
    }
    assert_eq!(headers::ACTING_OWNER_REF, "Kofra-Acting-Owner-Ref");
    assert_eq!(headers::IDEMPOTENCY_KEY, "Idempotency-Key");
}

#[test]
fn positions_of_the_lists() {
    // Each list's position round-trips through a query string.
    let positions = [
        NamePosition {
            name: "photos".into(),
        }
        .encode(),
        KeyPosition {
            created_ms: 1_763_800_300_000,
            id: KEY.into(),
        }
        .encode(),
        DayPosition {
            day: velmora_mgmt_types::position::Day::new(2026, 11, 21).unwrap(),
        }
        .encode(),
        EventPosition { epoch: 1, seq: 41 }.encode(),
    ];
    for p in positions {
        let q = List {
            after: Some(p.clone()),
            limit: 5,
        }
        .to_query();
        assert_eq!(List::parse(&q).unwrap().after, Some(p));
    }
    assert_eq!(query::DEFAULT_LIMIT, 100);
    assert_eq!(query::LIMITS, 1..=1000);
}
