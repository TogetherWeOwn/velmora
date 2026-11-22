//! Management-plane read conformance through the managed unit request path.

use serde_json::{json, Value};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::call::HoldMode;
use velmora_bridge::unit::request::{RequestCall, RequestRefusal};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const ACTIVE: Seqs = Seqs {
    state_seq: 3,
    keys_seq: 0,
};
const SUSPENDED: Seqs = Seqs {
    state_seq: 4,
    keys_seq: 0,
};

const ALPHA: &str = "b_00000000000000e4";
const BRAVO: &str = "b_00000000000000e2";
const CHARLIE: &str = "b_00000000000000e3";
const ZULU: &str = "b_00000000000000e1";
const MISSING: &str = "b_00000000000000ff";

const EARLY: &str = "AKPLAN0000000000000Z";
const TIE_A: &str = "AKPLAN0000000000000A";
const TIE_B: &str = "AKPLAN0000000000000B";
const REVOKED: &str = "AKPLAN0000000000000R";
const APP: &str = "app_fixture";
const REVOKED_APP: &str = "app_revoked_fixture";
const PRINCIPAL: &str = "p_fixture";
const INTERNAL: &str = "AKINTERNAL0000000001";

fn name() -> UnitName {
    UnitName::new(TenantId::parse("t_0000000000000e01").unwrap(), 0)
}

fn send(unit: &Unit<RusqliteSql>, kind: CallKind, seqs: Option<Seqs>, op: UnitOp) -> UnitAnswer {
    unit.handle(
        &UnitCall {
            name: name(),
            kind,
            seqs,
            authenticated: true,
            listed: true,
            op,
        },
        NOW,
    )
}

fn ok(answer: UnitAnswer, context: &str) -> Value {
    match answer {
        UnitAnswer::Ok { body, .. } => body,
        other => panic!("{context}: expected ok, got {other:?}"),
    }
}

fn worker(unit: &Unit<RusqliteSql>, op: UnitOp) -> Value {
    ok(send(unit, CallKind::Worker, None, op), "worker setup")
}

fn sync(
    unit: &Unit<RusqliteSql>,
    seqs: Seqs,
    tenant_state: TenantState,
    tenant_mode: Option<HoldMode>,
) {
    worker(
        unit,
        UnitOp::Sync {
            head: SyncHead {
                seqs,
                tenant_state,
                tenant_mode,
                restoring_since: None,
                lift: None,
            },
        },
    );
}

fn request(unit: &Unit<RusqliteSql>, seqs: Seqs, wire: Value) -> UnitAnswer {
    let call: RequestCall = serde_json::from_value(wire).expect("valid request fixture");
    send(
        unit,
        CallKind::Request,
        Some(seqs),
        UnitOp::Request {
            call: Box::new(call),
        },
    )
}

fn read(unit: &Unit<RusqliteSql>, wire: Value) -> Value {
    let method = wire["m"].as_str().unwrap().to_owned();
    ok(request(unit, ACTIVE, wire), &method)
}

fn fixture() -> Unit<RusqliteSql> {
    let unit = Unit::new(RusqliteSql::open_in_memory().unwrap(), name(), "");
    ok(
        send(
            &unit,
            CallKind::Worker,
            Some(ACTIVE),
            UnitOp::Provision {
                token: BirthToken {
                    name: name(),
                    jurisdiction: String::new(),
                    record_seq: 3,
                    schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
                    key_scheme: 2,
                    kind: BirthKind::Birth,
                },
                sealed: b"fixture".to_vec(),
            },
        ),
        "birth",
    );
    sync(&unit, ACTIVE, TenantState::Active, None);
    // The names, IDs and creation times are in different orders.
    unit.sql()
        .apply(&format!(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) VALUES
           ('{CHARLIE}', 'charlie', 'owner', x'02', 1, 30),
           ('{BRAVO}', 'bravo', 'owner', x'02', 1, 20),
           ('{ZULU}', 'zulu', 'owner', x'02', 1, 10),
           ('{ALPHA}', 'alpha', 'owner', x'02', 1, 40);
         INSERT INTO unit_keys(id, kind, status, held, made_by, created_at,
                               secret_wrapped, secret_kek_version, last_seq) VALUES
           ('{TIE_B}', 's3', 'disabled', 1, '{PRINCIPAL}', 20, x'0201', 1, 4),
           ('{EARLY}', 's3', 'active', 0, '{PRINCIPAL}', 10, x'0201', 1, 2),
           ('{TIE_A}', 's3', 'active', 0, '{PRINCIPAL}', 20, x'0201', 1, 3),
           ('{REVOKED}', 's3', 'revoked', 0, '{PRINCIPAL}', 15, NULL, NULL, 9),
           ('{APP}', 'app_password', 'active', 0, '{PRINCIPAL}', 5, x'0201', 1, 5),
           ('{REVOKED_APP}', 'app_password', 'revoked', 0, '{PRINCIPAL}', 6, NULL, NULL, 8),
           ('{PRINCIPAL}', 'principal', 'active', 0, NULL, 1, NULL, NULL, 1),
           ('{INTERNAL}', 'internal', 'active', 0, NULL, 2, x'0201', 1, 1);
         INSERT INTO unit_key_grants(subject_id, idx, bucket_id, access)
           VALUES ('{EARLY}', 0, '{ALPHA}', 'rw');"
        ))
        .unwrap();
    worker(
        &unit,
        UnitOp::BucketClose {
            bucket_id: BRAVO.into(),
        },
    );
    unit
}

fn bucket(id: &str, name: &str, created_at: u64, usage: Option<(u64, u64)>) -> Value {
    json!({
        "id": id, "name": name, "created_at": created_at,
        "stored_bytes": usage.map(|(bytes, _)| bytes),
        "object_count": usage.map(|(_, objects)| objects),
    })
}

#[test]
fn buckets_page_orders_by_name_and_advances_past_the_cursor() {
    let unit = fixture();
    assert_eq!(
        read(&unit, json!({"m":"buckets_page", "limit":2})),
        json!({
            "items": [bucket(ALPHA, "alpha", 40, Some((0, 0))), bucket(CHARLIE, "charlie", 30, Some((0, 0)))],
            "more": true,
        })
    );
    assert_eq!(
        read(
            &unit,
            json!({"m":"buckets_page", "limit":1, "after":"charlie"})
        ),
        json!({
            "items": [bucket(ZULU, "zulu", 10, Some((0, 0)))], "more": false,
        })
    );
    assert_eq!(
        read(
            &unit,
            json!({"m":"buckets_page", "limit":1, "after":"zulu"})
        ),
        json!({
            "items": [], "more": false,
        })
    );
}

#[test]
fn bucket_lookups_keep_asked_order_and_treat_closing_as_absent() {
    let unit = fixture();
    assert_eq!(
        read(
            &unit,
            json!({"m":"bucket_names", "ids":[ZULU, MISSING, ALPHA, BRAVO, ZULU]})
        ),
        json!(["zulu", null, "alpha", null, "zulu"])
    );
    let alpha = bucket(ALPHA, "alpha", 40, Some((0, 0)));
    let zulu = bucket(ZULU, "zulu", 10, Some((0, 0)));
    assert_eq!(
        read(
            &unit,
            json!({"m":"buckets_named", "names":["zulu", "missing", "alpha", "bravo", "zulu"]})
        ),
        json!([zulu, null, alpha, null, zulu])
    );
    assert_eq!(read(&unit, json!({"m":"bucket_by_id", "id":ALPHA})), alpha);
    for id in [BRAVO, MISSING] {
        assert_eq!(
            read(&unit, json!({"m":"bucket_by_id", "id":id})),
            Value::Null,
            "{id}"
        );
    }
}

fn partial_usage(unit: &Unit<RusqliteSql>) {
    // Birth starts seeded. Simulate an incomplete recount with rows that reach must not sum.
    unit.sql()
        .apply(&format!(
            "INSERT INTO usage_buckets(kind, bucket_id, live_objects, live_bytes) VALUES
           (1, '{ALPHA}', 2, 71), (1, '{CHARLIE}', 3, 120), (1, '{BRAVO}', 9, 901),
           (1, '{MISSING}', 8, 801), (2, '{ALPHA}', 7, 701);
         UPDATE usage_global SET all_g = 0 WHERE id = 1;"
        ))
        .unwrap();
}

fn finish_usage_fixture(unit: &Unit<RusqliteSql>) {
    unit.sql()
        .apply("UPDATE usage_global SET all_g = 1 WHERE id = 1;")
        .unwrap();
}

#[test]
fn all_bucket_items_report_null_until_usage_is_seeded_then_numbers() {
    let unit = fixture();
    partial_usage(&unit);
    for seeded in [false, true] {
        if seeded {
            finish_usage_fixture(&unit);
        }
        let alpha = bucket(ALPHA, "alpha", 40, seeded.then_some((71, 2)));
        let zulu = bucket(ZULU, "zulu", 10, seeded.then_some((0, 0)));
        assert_eq!(read(&unit, json!({"m":"bucket_by_id", "id":ALPHA})), alpha);
        assert_eq!(
            read(
                &unit,
                json!({"m":"buckets_named", "names":["zulu", "alpha"]})
            ),
            json!([zulu, alpha])
        );
        assert_eq!(
            read(&unit, json!({"m":"buckets_page", "limit":1})),
            json!({"items":[alpha], "more":true})
        );
    }
}

fn assert_fields(value: &Value, fields: &[&str]) {
    let object = value.as_object().expect("expected an object");
    // Do not dump a key response on failure: an unexpected field could contain a secret.
    assert_eq!(object.len(), fields.len(), "unexpected field count");
    for field in fields {
        assert!(object.contains_key(*field), "missing {field}");
    }
}

fn assert_key_item_fields(item: &Value) {
    assert_fields(
        item,
        &[
            "id",
            "kind",
            "status",
            "held",
            "made_by",
            "grants",
            "created_at",
            "last_seq",
        ],
    );
    for grant in item["grants"].as_array().expect("expected grants array") {
        assert_fields(
            grant,
            &["bucket_id", "access", "expires_at", "prefix", "ip_list"],
        );
    }
}

fn assert_key_page(page: &Value, expected: &[(&str, u64)], more: bool) {
    assert_fields(page, &["items", "more"]);
    assert_eq!(page["more"].as_bool(), Some(more));
    let items = page["items"].as_array().expect("expected key items array");
    assert_eq!(items.len(), expected.len());
    for (item, (id, created_at)) in items.iter().zip(expected) {
        assert_key_item_fields(item);
        assert!(item["id"] == *id, "expected item {id}");
        assert_eq!(item["created_at"].as_u64(), Some(*created_at), "{id}");
    }
}

#[test]
fn keys_page_orders_by_creation_then_id_and_the_cursor_needs_no_row() {
    let unit = fixture();
    assert_key_page(
        &read(&unit, json!({"m":"keys_page", "kind":"s3", "limit":2})),
        &[(EARLY, 10), (TIE_A, 20)],
        true,
    );
    // Remove the cursor row while leaving another key at the same creation time.
    unit.sql()
        .apply(&format!("DELETE FROM unit_keys WHERE id = '{TIE_A}';"))
        .unwrap();
    assert_key_page(
        &read(
            &unit,
            json!({
                "m":"keys_page", "kind":"s3", "limit":1, "after":{"created_at":20, "id":TIE_A},
            }),
        ),
        &[(TIE_B, 20)],
        false,
    );
    assert_key_page(
        &read(
            &unit,
            json!({"m":"keys_page", "kind":"app_password", "limit":10}),
        ),
        &[(APP, 5)],
        false,
    );
}

#[test]
fn keys_page_does_not_decode_principal_kind() {
    let invalid = json!({"op":"request", "call":{"m":"keys_page", "kind":"principal", "limit":1}});
    assert!(serde_json::from_value::<UnitOp>(invalid).is_err());
}

#[test]
fn key_by_id_returns_only_non_revoked_customer_keys_and_no_secret() {
    let unit = fixture();
    for id in [PRINCIPAL, INTERNAL, REVOKED, REVOKED_APP, "missing"] {
        assert!(
            read(&unit, json!({"m":"key_by_id", "id":id})).is_null(),
            "{id} must be absent"
        );
    }
    let s3 = read(&unit, json!({"m":"key_by_id", "id":EARLY}));
    assert_key_item_fields(&s3);
    assert!(
        s3 == json!({
            "id":EARLY, "kind":"s3", "status":"active", "held":false, "made_by":PRINCIPAL,
            "grants":[{"bucket_id":ALPHA, "access":"rw", "expires_at":null, "prefix":null, "ip_list":[]}],
            "created_at":10, "last_seq":2,
        }),
        "unexpected S3 key metadata"
    );
    let app = read(&unit, json!({"m":"key_by_id", "id":APP}));
    assert_key_item_fields(&app);
    assert!(
        app["id"] == APP && app["kind"] == "app_password",
        "expected the app password item"
    );
    let held = read(&unit, json!({"m":"key_by_id", "id":TIE_B}));
    assert_key_item_fields(&held);
    assert!(
        held["status"] == "disabled" && held["held"] == true,
        "expected a disabled, held key"
    );
}

#[test]
fn reach_counts_only_open_buckets_live_usage_and_non_revoked_customer_keys() {
    let unit = fixture();
    partial_usage(&unit);
    assert_eq!(
        read(&unit, json!({"m":"reach"})),
        json!({
            "buckets":3, "keys":4, "objects":null, "stored_bytes":null,
        })
    );
    finish_usage_fixture(&unit);
    assert_eq!(
        read(&unit, json!({"m":"reach"})),
        json!({
            "buckets":3, "keys":4, "objects":5, "stored_bytes":191,
        })
    );
}

#[test]
fn lookups_and_pages_enforce_their_bounds() {
    let unit = fixture();
    let bounds = [
        json!({"m":"bucket_names", "ids":vec![ALPHA; 65]}),
        json!({"m":"buckets_named", "names":vec!["alpha"; 65]}),
        json!({"m":"buckets_page", "limit":0}),
        json!({"m":"buckets_page", "limit":1001}),
        json!({"m":"keys_page", "kind":"s3", "limit":0}),
        json!({"m":"keys_page", "kind":"s3", "limit":1001}),
    ];
    for wire in bounds {
        let result = request(&unit, ACTIVE, wire.clone());
        assert!(
            matches!(
                result,
                UnitAnswer::Refused {
                    reason: Refused::Request(RequestRefusal::OutOfBounds),
                    alarm: true,
                }
            ),
            "expected out_of_bounds for {wire}"
        );
    }
    assert_eq!(
        read(&unit, json!({"m":"bucket_names", "ids":vec![ALPHA; 64]})),
        json!(vec!["alpha"; 64])
    );
    assert_eq!(
        read(
            &unit,
            json!({"m":"buckets_named", "names":vec!["alpha"; 64]})
        )
        .as_array()
        .unwrap()
        .len(),
        64
    );
    assert_eq!(
        read(&unit, json!({"m":"buckets_page", "limit":1000}))["more"],
        false
    );
    assert_key_page(
        &read(&unit, json!({"m":"keys_page", "kind":"s3", "limit":1000})),
        &[(EARLY, 10), (TIE_A, 20), (TIE_B, 20)],
        false,
    );
}

#[test]
fn all_seven_reads_are_served_unchanged_while_suspended_read_only() {
    let unit = fixture();
    let cases = [
        json!({"m":"bucket_names", "ids":[ALPHA]}),
        json!({"m":"buckets_page", "limit":1}),
        json!({"m":"buckets_named", "names":["alpha"]}),
        json!({"m":"bucket_by_id", "id":ALPHA}),
        json!({"m":"keys_page", "kind":"s3", "limit":1}),
        json!({"m":"key_by_id", "id":EARLY}),
        json!({"m":"reach"}),
    ];
    let active = cases.each_ref().map(|wire| read(&unit, wire.clone()));
    sync(
        &unit,
        SUSPENDED,
        TenantState::Suspended,
        Some(HoldMode::ReadOnly),
    );
    for (wire, expected) in cases.into_iter().zip(active) {
        let method = wire["m"].as_str().unwrap().to_owned();
        let suspended = ok(request(&unit, SUSPENDED, wire), &method);
        assert!(
            suspended == expected,
            "{method} answer changed while suspended read_only"
        );
    }
}
