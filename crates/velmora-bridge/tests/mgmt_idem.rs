//! `Idempotency-Key` through the root unit's reservation: what each
//! answer of the unit makes the call do, and that no kept answer or
//! replay carries a secret.

use serde_json::{json, Value};
use velmora_bridge::mgmt::idem::{
    next, stored_answer, IdemRequest, Next, NotStored, Reply, Reservation, Rid,
    IN_USE_RETRY_AFTER_SECS,
};
use velmora_mgmt_types::examples::EXAMPLES;
use velmora_mgmt_types::idem::{fingerprint, key_hash, TokenClass};
use velmora_mgmt_types::wire::{KeyCreated, KeyUpdate, MAX_STORED_ANSWER_BYTES};
use velmora_mgmt_types::Code;

fn key_created() -> &'static str {
    EXAMPLES
        .iter()
        .find(|e| e.call == "create_key")
        .and_then(|e| e.answer)
        .unwrap()
}

#[test]
fn the_request_is_the_contracts_fingerprint() {
    let path = "/v1/tenants/t_1a2b3c4d5e6f7a8b/keys";
    let body = br#"{"kind":"s3","grants":[]}"#;
    let r = IdemRequest::new(
        TokenClass::Standard,
        "POST",
        path,
        Some("usr_1"),
        body,
        "req-1",
    );
    assert_eq!(r.key_hash, key_hash("req-1"));
    assert_eq!(
        r.fingerprint,
        fingerprint(TokenClass::Standard, "POST", path, Some("usr_1"), body)
    );
    // The other token class is another request.
    let c = IdemRequest::new(
        TokenClass::Confirmed,
        "POST",
        path,
        Some("usr_1"),
        body,
        "req-1",
    );
    assert_ne!(c.fingerprint, r.fingerprint);
    // A key update re-read with a new if_seq is the same request.
    let a: KeyUpdate = serde_json::from_str(r#"{"name":"x","if_seq":1}"#).unwrap();
    let b: KeyUpdate = serde_json::from_str(r#"{"name":"x","if_seq":2}"#).unwrap();
    let f = |u: &KeyUpdate| {
        IdemRequest::new(
            TokenClass::Standard,
            "PATCH",
            path,
            None,
            &u.fingerprint_body(),
            "k",
        )
    };
    assert_eq!(f(&a), f(&b));
}

#[test]
fn a_kept_answer_never_holds_a_secret() {
    let first = key_created();
    let v: Value = serde_json::from_str(first).unwrap();
    assert!(
        v["secret_access_key"].is_string(),
        "the first answer has it"
    );
    let kept = stored_answer(201, first.as_bytes()).unwrap();
    let k: KeyCreated = serde_json::from_slice(&kept).unwrap();
    assert_eq!(k.secret_access_key, None);
    // The rest of the answer is kept as it was.
    let mut want = v.clone();
    want["secret_access_key"] = Value::Null;
    assert_eq!(serde_json::from_slice::<Value>(&kept).unwrap(), want);
    // At any depth.
    let nested = json!({"items": [{"secret_access_key": "s"}], "a": {"secret_access_key": "s"}});
    let kept = stored_answer(200, nested.to_string().as_bytes()).unwrap();
    assert!(!String::from_utf8(kept).unwrap().contains("\"s\""));
}

#[test]
fn a_refusal_is_never_kept() {
    for status in [400, 403, 404, 409, 422, 429, 500, 503] {
        assert_eq!(
            stored_answer(status, br#"{"code":"x"}"#),
            Err(NotStored::Refusal),
            "{status}"
        );
    }
    assert_eq!(stored_answer(201, b"not json"), Err(NotStored::NotJson));
    assert_eq!(stored_answer(201, b"[1]"), Err(NotStored::NotJson));
    let big = json!({"name": "a".repeat(MAX_STORED_ANSWER_BYTES)});
    assert_eq!(
        stored_answer(201, big.to_string().as_bytes()),
        Err(NotStored::TooLarge)
    );
}

#[test]
fn what_each_reservation_answer_makes_the_call_do() {
    let rid = Rid([7; 16]);
    assert_eq!(
        next(Reservation::Admitted { rid, keys_seq: 12 }),
        Next::Proceed { rid, keys_seq: 12 }
    );
    assert_eq!(
        next(Reservation::InUse),
        Next::Reply(Reply::Code {
            code: Code::IdempotencyKeyInUse,
            retry_after: Some(IN_USE_RETRY_AFTER_SECS)
        })
    );
    assert_eq!(IN_USE_RETRY_AFTER_SECS, 30);
    assert_eq!(
        next(Reservation::Reused),
        Next::Reply(Reply::Code {
            code: Code::IdempotencyKeyReused,
            retry_after: None
        })
    );
    // A code with Retry-After always carries one; one without never does.
    assert_eq!(
        next(Reservation::Refused {
            code: Code::CapReached,
            retry_after: None
        }),
        Next::Reply(Reply::Code {
            code: Code::CapReached,
            retry_after: Some(5)
        })
    );
    assert_eq!(
        next(Reservation::Refused {
            code: Code::ServiceUnavailable,
            retry_after: Some(60)
        }),
        Next::Reply(Reply::Code {
            code: Code::ServiceUnavailable,
            retry_after: Some(60)
        })
    );
    assert_eq!(
        next(Reservation::Refused {
            code: Code::GrantNotHeld,
            retry_after: Some(60)
        }),
        Next::Reply(Reply::Code {
            code: Code::GrantNotHeld,
            retry_after: None
        })
    );
}

#[test]
fn a_replay_is_cleaned_again() {
    // A kept answer with a secret (a row written by a faulty build) is
    // cleaned before it is sent.
    let replay = next(Reservation::Applied {
        status: 201,
        body: key_created().as_bytes().to_vec(),
    });
    let Next::Reply(Reply::Stored { status, body }) = replay else {
        panic!("{replay:?}")
    };
    assert_eq!(status, 201);
    let k: KeyCreated = serde_json::from_slice(&body).unwrap();
    assert_eq!(k.secret_access_key, None);
    // A kept answer that is not one this plane keeps is never sent.
    assert_eq!(
        next(Reservation::Applied {
            status: 201,
            body: b"garbage".to_vec()
        }),
        Next::Reply(Reply::Code {
            code: Code::InternalError,
            retry_after: None
        })
    );
    assert_eq!(
        next(Reservation::Applied {
            status: 403,
            body: br#"{"code":"grant_not_held"}"#.to_vec()
        }),
        Next::Reply(Reply::Code {
            code: Code::InternalError,
            retry_after: None
        })
    );
}
