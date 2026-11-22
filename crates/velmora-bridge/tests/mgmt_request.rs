//! The acting header, the `Idempotency-Key` and the query of each call.

use velmora_bridge::mgmt::request::{check, CallQuery};
use velmora_bridge::mgmt::route::{route, Call};
use velmora_mgmt_types::query::{BucketQuery, List};
use velmora_mgmt_types::wire::KeyKind;
use velmora_mgmt_types::Code;

const T: &str = "/v1/tenants/t_00000000000000a1";
const ACTING: &str = "usr_01JD2Q9A7M";
const KEY: &str = "req_01JD2R0001";

/// Every call: method, path, and whether it writes, needs the acting
/// member, and needs an `Idempotency-Key`.
fn calls() -> Vec<(&'static str, String, bool, bool, bool)> {
    let b = format!("{T}/buckets/b_0123456789abcdef");
    let k = format!("{T}/keys/AKVL0123");
    let p = format!("{T}/principals/p_1");
    let u = format!("{T}/uploads/0123456789abcdef0123456789abcdef");
    vec![
        ("GET", "/v1/tenants".into(), false, false, false),
        ("POST", "/v1/tenants".into(), true, false, true),
        ("GET", T.into(), false, false, false),
        ("DELETE", T.into(), true, true, true),
        ("GET", format!("{T}/reach"), false, false, false),
        ("GET", format!("{T}/events"), false, false, false),
        ("POST", format!("{T}/restore"), true, true, true),
        ("GET", format!("{T}/buckets"), false, false, false),
        ("POST", format!("{T}/buckets"), true, true, true),
        ("GET", b.clone(), false, false, false),
        ("PATCH", b.clone(), true, true, true),
        ("DELETE", b, true, true, true),
        ("GET", format!("{T}/keys"), false, false, false),
        ("POST", format!("{T}/keys"), true, true, true),
        ("GET", k.clone(), false, false, false),
        ("PATCH", k.clone(), true, true, true),
        ("DELETE", k.clone(), true, true, true),
        ("POST", format!("{k}/disable"), true, true, true),
        ("POST", format!("{T}/principals"), true, false, true),
        ("PATCH", p.clone(), true, true, true),
        ("DELETE", p.clone(), true, true, true),
        ("POST", format!("{p}/disable"), true, true, true),
        // A write that keeps no record: no key.
        ("POST", format!("{T}/objects/presign"), true, true, false),
        // A read sent as a POST.
        ("POST", format!("{T}/objects/list"), false, true, false),
        ("POST", format!("{T}/objects/delete"), true, true, true),
        ("POST", format!("{T}/uploads"), true, true, true),
        ("POST", format!("{u}/complete"), true, true, true),
        ("DELETE", u.clone(), true, true, true),
        ("GET", format!("{u}/parts"), false, false, false),
        ("GET", format!("{T}/usage"), false, false, false),
        ("GET", format!("{T}/usage/days"), false, false, false),
        ("GET", format!("{T}/usage/downloads"), false, false, false),
        ("GET", format!("{T}/usage/buckets"), false, false, false),
        ("GET", "/v1/events".into(), false, false, false),
    ]
}

fn call(method: &str, path: &str) -> Call {
    route(method, path).unwrap_or_else(|e| panic!("{method} {path}: {e:?}"))
}

/// The query each call accepts when it has no parameters, or the one it requires.
fn base_query(c: &Call) -> &'static str {
    match c {
        Call::TenantDelete { .. } => "hold_days=30",
        _ => "",
    }
}

#[test]
fn every_call_says_what_it_needs() {
    let all = calls();
    assert_eq!(all.len(), 34, "every call of the route table");
    for (method, path, writes, acting, key) in all {
        let c = call(method, &path);
        assert_eq!(c.writes(), writes, "{method} {path}: writes");
        assert_eq!(c.needs_acting(), acting, "{method} {path}: acting");
        assert_eq!(c.needs_idempotency_key(), key, "{method} {path}: key");
        let q = base_query(&c);

        let full = check(&c, q, Some(ACTING), Some(KEY));
        match (&c, full) {
            (Call::TenantCreate, r) => assert_eq!(r.map(|_| ()), Err(Code::BadRequest)),
            (_, Ok(checked)) => {
                assert_eq!(checked.acting.as_deref(), Some(ACTING));
                // A key is kept only where it is used.
                assert_eq!(checked.idempotency_key.is_some(), key, "{method} {path}");
            }
            (_, Err(e)) => panic!("{method} {path}: {e:?}"),
        }
        let without_acting = check(&c, q, None, Some(KEY)).map(|_| ());
        assert_eq!(
            without_acting,
            if acting {
                Err(Code::BadRequest)
            } else {
                Ok(())
            },
            "{method} {path}: no acting header"
        );
        let without_key = check(
            &c,
            q,
            (!matches!(c, Call::TenantCreate)).then_some(ACTING),
            None,
        )
        .map(|_| ());
        assert_eq!(
            without_key,
            if key {
                Err(Code::IdempotencyKeyRequired)
            } else {
                Ok(())
            },
            "{method} {path}: no key"
        );
        // A value of the wrong form is refused wherever it is sent.
        for bad in ["", "a b", "a, b", "é"] {
            assert_eq!(
                check(&c, q, Some(bad), Some(KEY)).map(|_| ()),
                Err(Code::BadRequest),
                "{method} {path}: acting {bad:?}"
            );
        }
        for bad in ["", "a b", "a, b", "é"] {
            assert_eq!(
                check(&c, q, Some(ACTING), Some(bad)).map(|_| ()),
                Err(Code::BadRequest),
                "{method} {path}: key {bad:?}"
            );
        }
        // A call refuses a parameter it does not take; the two calls whose
        // handlers parse their own query get it raw.
        if matches!(c, Call::UsageDownloads { .. } | Call::UploadParts { .. }) {
            assert_eq!(
                check(&c, "period=2026-11", Some(ACTING), None).map(|c| c.query),
                Ok(CallQuery::Raw("period=2026-11".into()))
            );
            continue;
        }
        let extra = if q.is_empty() {
            "x=1".to_string()
        } else {
            format!("{q}&x=1")
        };
        assert_eq!(
            check(&c, &extra, Some(ACTING), Some(KEY)).map(|_| ()),
            Err(Code::BadRequest),
            "{method} {path}: ?{extra}"
        );
    }
}

#[test]
fn queries_of_the_lists() {
    let q = |method: &str, path: &str, query: &str| {
        check(&call(method, path), query, Some(ACTING), None).map(|c| c.query)
    };
    let buckets = format!("{T}/buckets");
    assert_eq!(
        q("GET", &buckets, ""),
        Ok(CallQuery::Buckets(BucketQuery::Page(List::default())))
    );
    assert_eq!(
        q("GET", &buckets, "name=photos&name=gone"),
        Ok(CallQuery::Buckets(BucketQuery::Names(vec![
            "photos".into(),
            "gone".into()
        ])))
    );
    assert_eq!(
        q("GET", &buckets, "name=photos&after=nx"),
        Err(Code::BadRequest)
    );
    assert_eq!(
        q("GET", &buckets, "after=nphotos&limit=2").map(|_| ()),
        Ok(())
    );
    assert_eq!(q("GET", &buckets, "after=k1.A"), Err(Code::InvalidPosition));

    let keys = format!("{T}/keys");
    match q("GET", &keys, "kind=app_password&after=k1.AKVL0123") {
        Ok(CallQuery::Keys(k)) => {
            assert_eq!(k.kind, Some(KeyKind::AppPassword));
            assert_eq!(k.list.after.as_deref(), Some("k1.AKVL0123"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(q("GET", &keys, "kind=principal"), Err(Code::BadRequest));
    assert_eq!(q("GET", &keys, "kind=internal"), Err(Code::BadRequest));

    let events = format!("{T}/events");
    assert_eq!(
        q("GET", &events, "after=e1.40&limit=1000").map(|_| ()),
        Ok(())
    );
    assert_eq!(
        q("GET", &events, "after=e1.040"),
        Err(Code::InvalidPosition)
    );
    assert_eq!(q("GET", &events, "limit=1001"), Err(Code::BadRequest));

    let days = format!("{T}/usage/days");
    assert_eq!(
        q("GET", &days, "after_day=2026-11-01&after=d2026-11-21").map(|_| ()),
        Ok(())
    );
    assert_eq!(q("GET", &days, "after=nx"), Err(Code::InvalidPosition));
    assert_eq!(
        q("GET", &days, "after_day=2026-13-01"),
        Err(Code::BadRequest)
    );

    let per_bucket = format!("{T}/usage/buckets");
    assert_eq!(q("GET", &per_bucket, "after=nphotos").map(|_| ()), Ok(()));
    assert_eq!(
        q("GET", &per_bucket, "after=e1.1"),
        Err(Code::InvalidPosition)
    );

    for (query, want) in [
        ("hold_days=30", Ok(CallQuery::HoldDays(30))),
        ("hold_days=6", Err(Code::BadRequest)),
        ("", Err(Code::BadRequest)),
    ] {
        assert_eq!(
            check(&call("DELETE", T), query, Some(ACTING), Some(KEY)).map(|c| c.query),
            want,
            "{query}"
        );
    }

    let list = |query: &str| check(&call("GET", "/v1/tenants"), query, None, None).map(|c| c.query);
    assert_eq!(list(""), Ok(CallQuery::TenantList { external_ref: None }));
    assert_eq!(
        list("external_ref=ws_01JD2Q8V5X"),
        Ok(CallQuery::TenantList {
            external_ref: Some("ws_01JD2Q8V5X".into())
        })
    );
    assert_eq!(list("external_ref=a&x=1"), Err(Code::BadRequest));
    assert_eq!(list("external_ref="), Err(Code::BadRequest));
}

#[test]
fn debug_never_shows_a_header_value() {
    use velmora_bridge::mgmt::serve::MgmtRequest;
    let req = MgmtRequest {
        method: "POST",
        path: "/v1/tenants",
        query: "",
        authorization: Some("Bearer secret-token-value"),
        acting: Some("usr_secret_ref"),
        idempotency_key: Some("key-secret-value"),
    };
    let shown = format!("{req:?}");
    for value in ["secret-token-value", "usr_secret_ref", "key-secret-value"] {
        assert!(!shown.contains(value), "{shown}");
    }
    assert!(shown.contains("<present>"));
}
