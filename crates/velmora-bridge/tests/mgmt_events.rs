//! `GET /v1/tenants/{t}/events` (`mgmt::events`): one tenant's events
//! from the directory's feed (AM-37), through the plane's `serve_with`,
//! over a native directory database with the real schema.

use std::cell::{Cell, RefCell};

use futures_util::StreamExt;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use velmora_bridge::directory::chain::ChainError;
use velmora_bridge::directory::feed::{NewEvent, MAX_EVENTS_PAGE};
use velmora_bridge::directory::record::{Lifecycle, Tenant, TenantDoor as Door};
use velmora_bridge::directory::store::SqlDirectory;
use velmora_bridge::mgmt::adapters::{HeadDoor, NoBucketNames};
use velmora_bridge::mgmt::events::TenantEventsHandler;
use velmora_bridge::mgmt::serve::{serve_with, Answer, Either, MgmtRequest, NotBuilt};
use velmora_bridge::mgmt::token::{DisabledTokens, TokenHashes};
use velmora_bridge::testkit::{MemBlobStore, RusqliteSql};
use velmora_bridge::types::Body;
use velmora_bridge::unit::TenantId;
use velmora_bridge::unit_lease::client::TenantHeads;
use velmora_bridge::unit_router::test_door;
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const TENANT: &str = "t_00000000000000a1";
const OTHER: &str = "t_00000000000000b2";
const STANDARD: &str = "std-token-0123456789abcdef0123456789abcdef";
const CONFIRMED: &str = "conf-token-0123456789abcdef0123456789abcdef";

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

fn directory() -> RusqliteSql {
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
    ))
    .unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0002_tenant_events.sql"
    ))
    .unwrap();
    db
}

struct Heads {
    tenants: Vec<String>,
    down: Cell<bool>,
}

impl TenantHeads for Heads {
    async fn head(&self, t: &TenantId, _: u64) -> Result<Option<Door>, ChainError> {
        if self.down.get() {
            return Err(ChainError::Store(velmora_bridge::BridgeError::Sql(
                "fake: down".into(),
            )));
        }
        Ok(self
            .tenants
            .iter()
            .any(|x| x == t.as_str())
            .then(|| test_door(t, 3, Lifecycle::Live, &[0])))
    }
}

fn heads() -> Heads {
    Heads {
        tenants: vec![TENANT.into(), OTHER.into()],
        down: Cell::new(false),
    }
}

fn data(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => panic!("not an object"),
    }
}

async fn append(sql: &RusqliteSql, tenant: &str, source: &str, at: i64) {
    let dir = SqlDirectory { sql };
    dir.append_event(&NewEvent {
        tenant: Tenant::parse(tenant).unwrap(),
        kind: "bucket.created".into(),
        source: source.into(),
        at: UnixMs(at),
        data: data(json!({"bucket_id": "b_00000000000000aa", "bucket": "photos"})),
    })
    .await
    .unwrap();
}

async fn get(heads: &Heads, sql: Option<&RusqliteSql>, tenant: &str, query: &str) -> Answer {
    let door = HeadDoor {
        heads,
        names: &NoBucketNames,
    };
    let dir = sql.map(|sql| SqlDirectory { sql });
    let handlers = Either(
        TenantEventsHandler {
            heads: &door,
            feed: dir.as_ref(),
        },
        NotBuilt,
    );
    let disabled = RefCell::new(DisabledTokens::default());
    let authorization = format!("Bearer {STANDARD}");
    let path = format!("/v1/tenants/{tenant}/events");
    let req = MgmtRequest {
        method: "GET",
        path: &path,
        query,
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

fn json_of(a: &Answer) -> Value {
    serde_json::from_str(a.json.as_deref().expect("a JSON answer")).unwrap()
}

fn expect(a: &Answer, status: u16, code: &str) {
    assert_eq!((a.status, a.code), (status, code), "{a:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_tenants_events_page_oldest_first_and_resume_from_the_position() {
    let sql = directory();
    append(&sql, TENANT, "t/2", NOW.0 + 1).await;
    append(&sql, OTHER, "t/2", NOW.0 + 2).await;
    append(&sql, TENANT, "t/3", NOW.0 + 3).await;
    append(&sql, TENANT, "t/4", NOW.0 + 4).await;
    let h = heads();
    let a = get(&h, Some(&sql), TENANT, "limit=2").await;
    expect(&a, 200, "ok");
    let page = json_of(&a);
    let _: velmora_mgmt_types::wire::EventPage = serde_json::from_value(page.clone()).unwrap();
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["type"], "bucket.created");
    assert_eq!(items[0]["at_ms"], NOW.0 + 1);
    assert_eq!(items[1]["at_ms"], NOW.0 + 3);
    assert_eq!(
        items[0]["data"],
        json!({"bucket_id": "b_00000000000000aa", "bucket": "photos"})
    );
    let position = page["position"].as_str().unwrap().to_string();
    assert!(position.starts_with('e'), "{position}");
    // Resume: only the tenant's own last event, never the other tenant's.
    let next = json_of(&get(&h, Some(&sql), TENANT, &format!("after={position}")).await);
    let items = next["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["at_ms"], NOW.0 + 4);
    let last = next["position"].as_str().unwrap().to_string();
    // Nothing after the last: `after` itself.
    let end = json_of(&get(&h, Some(&sql), TENANT, &format!("after={last}")).await);
    assert_eq!(end["items"], json!([]));
    assert_eq!(end["position"], last);
    // The other tenant sees its one event.
    let other = json_of(&get(&h, Some(&sql), OTHER, "").await);
    assert_eq!(other["items"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn an_empty_feed_answers_its_head() {
    let sql = directory();
    let page = json_of(&get(&heads(), Some(&sql), TENANT, "").await);
    assert_eq!(page["items"], json!([]));
    assert!(page["position"].as_str().unwrap().starts_with('e'));
}

#[tokio::test(flavor = "current_thread")]
async fn an_older_epoch_is_a_feed_reset() {
    let sql = directory();
    append(&sql, TENANT, "t/2", NOW.0 + 1).await;
    let page = json_of(&get(&heads(), Some(&sql), TENANT, "").await);
    let position = page["position"].as_str().unwrap();
    let (epoch, seq) = position[1..].split_once('.').unwrap();
    let older = format!("e{}.{seq}", epoch.parse::<u64>().unwrap() + 7);
    expect(
        &get(&heads(), Some(&sql), TENANT, &format!("after={older}")).await,
        409,
        "feed_reset",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn bad_queries_unknown_tenants_and_missing_stores() {
    let sql = directory();
    let h = heads();
    expect(
        &get(&h, Some(&sql), TENANT, "after=nope").await,
        400,
        "invalid_position",
    );
    expect(
        &get(
            &h,
            Some(&sql),
            TENANT,
            &format!("limit={}", MAX_EVENTS_PAGE + 1),
        )
        .await,
        400,
        "bad_request",
    );
    expect(
        &get(&h, Some(&sql), "t_00000000000000c3", "").await,
        404,
        "tenant_not_found",
    );
    // No directory bound, or a head that cannot be read: 503.
    expect(&get(&h, None, TENANT, "").await, 503, "service_unavailable");
    h.down.set(true);
    expect(
        &get(&h, Some(&sql), TENANT, "").await,
        503,
        "service_unavailable",
    );
}
