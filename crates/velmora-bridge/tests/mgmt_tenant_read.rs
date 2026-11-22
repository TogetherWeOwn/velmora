//! `GET /v1/tenants/{t}` (`mgmt::tenant`): the tenant as its verified
//! head says, through the plane's `serve_with` and the `HeadDoor` adapter
//! (AM-59's carried door fields).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use futures_util::StreamExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use velmora_bridge::directory::chain::ChainError;
use velmora_bridge::directory::record::{
    ActorClass, BillingHold, Deletion, DeletionReason, HoldMode, Lifecycle, OperatorHold,
    OperatorReason, Restoring, TenantDoor as Door,
};
use velmora_bridge::mgmt::adapters::{HeadDoor, NoBucketNames};
use velmora_bridge::mgmt::serve::{serve_with, Answer, Either, MgmtRequest, NotBuilt};
use velmora_bridge::mgmt::tenant::{tenant_of, Read, TenantReadHandler, DEFAULT_ACTIVE_KEYS};
use velmora_bridge::mgmt::token::{DisabledTokens, TokenHashes};
use velmora_bridge::testkit::MemBlobStore;
use velmora_bridge::types::Body;
use velmora_bridge::unit::TenantId;
use velmora_bridge::unit_lease::client::TenantHeads;
use velmora_bridge::unit_router::test_door;
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const TENANT: &str = "t_0000000000000f01";
const STANDARD: &str = "std-token-0123456789abcdef0123456789abcdef";
const CONFIRMED: &str = "conf-token-0123456789abcdef0123456789abcdef";
/// `created_at` of the test heads.
const BORN: i64 = 1_790_000_000_000;

fn hash(token: &str) -> String {
    Sha256::digest(token)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hashes() -> TokenHashes {
    let (standard, confirmed) = (hash(STANDARD), hash(CONFIRMED));
    TokenHashes::from_vars(|name| match name {
        "MGMT_TOKEN_SHA256_STANDARD" => Some(standard.clone()),
        "MGMT_TOKEN_SHA256_CONFIRMED" => Some(confirmed.clone()),
        _ => None,
    })
    .unwrap()
}

fn tenant() -> TenantId {
    TenantId::parse(TENANT).unwrap()
}

fn door() -> Door {
    let mut d = test_door(&tenant(), 7, Lifecycle::Live, &[0]);
    d.created_at = UnixMs(BORN);
    d
}

struct Heads {
    door: RefCell<Option<Door>>,
    down: Cell<bool>,
}

impl Heads {
    fn of(door: Door) -> Heads {
        Heads {
            door: RefCell::new(Some(door)),
            down: Cell::new(false),
        }
    }
}

impl TenantHeads for Heads {
    async fn head(&self, t: &TenantId, _: u64) -> Result<Option<Door>, ChainError> {
        if self.down.get() {
            return Err(ChainError::Damaged("fake: down"));
        }
        Ok(self.door.borrow().clone().filter(|_| t.as_str() == TENANT))
    }
}

async fn get(heads: &Heads, path: &str, token: &str) -> Answer {
    let door = HeadDoor {
        heads,
        names: &NoBucketNames,
    };
    let handlers = Either(TenantReadHandler { heads: &door }, NotBuilt);
    let disabled = RefCell::new(DisabledTokens::default());
    let authorization = format!("Bearer {token}");
    let req = MgmtRequest {
        method: "GET",
        path,
        query: "",
        authorization: Some(&authorization),
        acting: None,
        idempotency_key: None,
    };
    let body = Body::Stream {
        declared_len: Some(0),
        stream: futures_util::stream::iter(Vec::<velmora_bridge::Result<Vec<u8>>>::new())
            .boxed_local(),
    };
    serve_with(
        &disabled,
        &hashes(),
        &MemBlobStore::new(),
        &handlers,
        req,
        body,
        NOW,
    )
    .await
}

async fn read(heads: &Heads) -> Answer {
    get(heads, &format!("/v1/tenants/{TENANT}"), STANDARD).await
}

fn json_of(a: &Answer) -> Value {
    serde_json::from_str(a.json.as_deref().expect("a JSON answer")).unwrap()
}

fn expect(a: &Answer, status: u16, code: &str) {
    assert_eq!((a.status, a.code), (status, code), "{a:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn an_active_tenant_reads_as_its_head_says() {
    let mut d = door();
    d.limits = BTreeMap::from([
        ("storage_bytes".to_string(), 5_000_000_000),
        ("upload_24h_bytes".to_string(), 1_000),
        ("rate_class_unused".to_string(), 9),
    ]);
    let a = read(&Heads::of(d)).await;
    expect(&a, 200, "ok");
    let t = json_of(&a);
    assert_eq!(
        t,
        json!({
            "id": TENANT,
            "state": "active",
            "access": "full",
            "limits": {
                "storage_bytes": 5_000_000_000u64,
                "upload_24h_bytes": 1_000,
                "download_allowance_bytes": null,
                "active_keys": DEFAULT_ACTIVE_KEYS,
            },
            "suspension": null,
            "deletion": null,
            "created_at_ms": BORN,
        })
    );
    // The contract crate reads it as a `Tenant`.
    let _: velmora_mgmt_types::wire::Tenant = serde_json::from_value(t).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn the_heads_key_limit_is_answered() {
    let mut d = door();
    d.limits = BTreeMap::from([("active_keys".to_string(), 3)]);
    let t = json_of(&read(&Heads::of(d)).await);
    assert_eq!(t["limits"]["active_keys"], 3);
    let mut d = door();
    d.limits = BTreeMap::from([("active_keys".to_string(), u64::MAX)]);
    let t = json_of(&read(&Heads::of(d)).await);
    assert_eq!(t["limits"]["active_keys"], u32::MAX);
}

#[tokio::test(flavor = "current_thread")]
async fn holds_read_as_a_suspension_with_its_reason_and_since() {
    let mut d = door();
    d.holds.billing = Some(BillingHold {
        mode: HoldMode::ReadOnly,
        since: UnixMs(BORN + 10),
    });
    let t = json_of(&read(&Heads::of(d.clone())).await);
    assert_eq!(t["state"], "suspended");
    assert_eq!(t["access"], "read_only");
    assert_eq!(
        t["suspension"],
        json!({"mode": "read_only", "reason": "non_payment", "since_ms": BORN + 10})
    );
    // A locked operator hold is the mode in force.
    d.holds.operator = Some(OperatorHold {
        mode: HoldMode::Locked,
        reason: OperatorReason::Security,
        preserve: false,
        since: UnixMs(BORN + 20),
    });
    let t = json_of(&read(&Heads::of(d.clone())).await);
    assert_eq!(t["access"], "none");
    assert_eq!(
        t["suspension"],
        json!({"mode": "blocked", "reason": "operator", "since_ms": BORN + 20})
    );
    // Both in the same mode: the earlier one.
    d.holds.billing = Some(BillingHold {
        mode: HoldMode::Locked,
        since: UnixMs(BORN + 5),
    });
    let t = json_of(&read(&Heads::of(d.clone())).await);
    assert_eq!(
        t["suspension"],
        json!({"mode": "blocked", "reason": "non_payment", "since_ms": BORN + 5})
    );
    d.holds.billing = Some(BillingHold {
        mode: HoldMode::Locked,
        since: UnixMs(BORN + 20),
    });
    let t = json_of(&read(&Heads::of(d)).await);
    assert_eq!(
        t["suspension"]["reason"], "operator",
        "a tie: the operator's"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_deletion_reads_with_its_seq_and_times() {
    let mut d = door();
    d.deletion = Some(Deletion {
        seq: 5,
        requested_at: UnixMs(BORN + 100),
        shred_due_at: UnixMs(BORN + 200),
        reason: DeletionReason::NonPayment,
        actor: ActorClass::Billing,
        key_hash: "ab".repeat(32),
    });
    let t = json_of(&read(&Heads::of(d.clone())).await);
    assert_eq!(t["state"], "deleting");
    assert_eq!(t["access"], "none");
    assert_eq!(
        t["deletion"],
        json!({"seq": 5, "actor": "billing", "requested_at_ms": BORN + 100,
               "shred_due_at_ms": BORN + 200})
    );
    // The key hash never leaves the head.
    assert!(!read(&Heads::of(d.clone())).await.body().contains("abab"));
    d.lifecycle = Lifecycle::Shredding;
    let t = json_of(&read(&Heads::of(d)).await);
    assert_eq!(
        (t["state"].clone(), t["access"].clone()),
        (json!("deleting"), json!("none"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_restoring_entry_changes_no_field() {
    let mut d = door();
    let before = json_of(&read(&Heads::of(d.clone())).await);
    d.restoring = vec![Restoring {
        unit: 0,
        since_seq: 6,
    }];
    assert_eq!(json_of(&read(&Heads::of(d)).await), before);
}

#[tokio::test(flavor = "current_thread")]
async fn not_yet_gone_unreadable_and_absent() {
    let mut d = door();
    d.lifecycle = Lifecycle::Provisioning;
    let a = read(&Heads::of(d)).await;
    expect(&a, 503, "service_unavailable");
    assert!(a.retry_after.is_some());
    let mut d = door();
    d.lifecycle = Lifecycle::Shredded;
    expect(&read(&Heads::of(d)).await, 404, "tenant_not_found");
    let heads = Heads::of(door());
    heads.down.set(true);
    expect(&read(&heads).await, 503, "service_unavailable");
    let heads = Heads::of(door());
    *heads.door.borrow_mut() = None;
    expect(&read(&heads).await, 404, "tenant_not_found");
    // Another tenant id: no chain.
    expect(
        &get(
            &Heads::of(door()),
            "/v1/tenants/t_0000000000000f02",
            STANDARD,
        )
        .await,
        404,
        "tenant_not_found",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_head_of_another_tenant_is_damage() {
    let other = TenantId::parse("t_0000000000000f02").unwrap();
    let mut d = test_door(&other, 7, Lifecycle::Live, &[0]);
    d.created_at = UnixMs(BORN);
    expect(&read(&Heads::of(d)).await, 500, "internal_error");
}

#[tokio::test(flavor = "current_thread")]
async fn the_gate_runs_first() {
    let heads = Heads::of(door());
    // No token, a wrong token, tenant 0's path.
    expect(
        &get(
            &heads,
            &format!("/v1/tenants/{TENANT}"),
            "nope-0123456789abcdef0123456789abcdef",
        )
        .await,
        401,
        "unauthenticated",
    );
    expect(
        &get(&heads, "/v1/tenants/t_0000000000000000", STANDARD).await,
        404,
        "not_found",
    );
    // The confirmed token reads too.
    expect(
        &get(&heads, &format!("/v1/tenants/{TENANT}"), CONFIRMED).await,
        200,
        "ok",
    );
}

#[test]
fn a_time_before_1970_is_damage() {
    let mut d = door();
    d.created_at = UnixMs(-1);
    assert_eq!(tenant_of(TENANT, &d), Read::Damaged);
    let mut d = door();
    d.holds.billing = Some(BillingHold {
        mode: HoldMode::ReadOnly,
        since: UnixMs(-5),
    });
    assert_eq!(tenant_of(TENANT, &d), Read::Damaged);
}
