//! The request router (ADR-TENANCY §2.7; design round 5, AM-51): a
//! managed tenant's request to its unit, and the maintenance gate before
//! any unit call (AM-50, the L6-2 acceptance).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use std::collections::BTreeMap;

use base64::Engine as _;
use velmora_bridge::config::{BridgeConfig, Maintenance};
use velmora_bridge::directory::chain::ChainError;
use velmora_bridge::directory::record::{Lifecycle, Placement, TenantDoor};
use velmora_bridge::service::{serve_managed, ManagedLine, UNIT_REQUESTS_NOT_BUILT};
use velmora_bridge::testkit::FixedClock;
use velmora_bridge::unit::{
    CallKind, Seqs, SyncHead, TenantId, TenantState, UnitAnswer, UnitCall, UnitName, UnitOp,
    UnitReply,
};
use velmora_bridge::unit_lease::client::{Answered, Page, TenantHeads};
use velmora_bridge::unit_router::{
    test_door, HeadCache, RequestClient, RequestClients, RouteRefusal, Routed, Router, UnitRouter,
    HEAD_MAX_AGE_MS,
};
use velmora_bridge::{Body, BridgeError, Method, Result, S3Request, UnixMs};

fn tenant() -> TenantId {
    TenantId::parse("t_00000000000000a7").unwrap()
}

fn unit(n: u32) -> UnitName {
    UnitName::new(tenant(), n)
}

fn seqs(state_seq: u64, keys_seq: u64) -> Seqs {
    Seqs {
        state_seq,
        keys_seq,
    }
}

fn answered(answer: UnitAnswer, refreshed: Option<Seqs>) -> Answered {
    Answered {
        reply: UnitReply {
            answer,
            lease_left_ms: 600_000,
            revoked: None,
        },
        refreshed,
        renew_due: false,
        renewal: None,
        synced: None,
    }
}

fn ok(s: Seqs) -> UnitAnswer {
    UnitAnswer::Ok {
        seqs: s,
        body: serde_json::json!(null),
    }
}

/// The unit clients: each call is kept, each answer is scripted.
#[derive(Default)]
struct Clients {
    made: Cell<u32>,
    calls: Rc<RefCell<Vec<UnitCall>>>,
    answers: Rc<RefCell<Vec<Answered>>>,
    routed: RefCell<Vec<Routed>>,
}

struct Client {
    calls: Rc<RefCell<Vec<UnitCall>>>,
    answers: Rc<RefCell<Vec<Answered>>>,
}

impl RequestClient for Client {
    async fn call(&self, call: UnitCall) -> (Result<Answered>, Vec<Page>) {
        self.calls.borrow_mut().push(call);
        let mut answers = self.answers.borrow_mut();
        match answers.is_empty() {
            true => (
                Err(BridgeError::Sql("no answer".into())),
                vec![Page::UnitRefused("down")],
            ),
            false => (Ok(answers.remove(0)), vec![]),
        }
    }
}

impl RequestClients for Clients {
    type Client = Client;
    fn client(&self, routed: &Routed) -> Result<Client> {
        self.made.set(self.made.get() + 1);
        self.routed.borrow_mut().push(routed.clone());
        Ok(Client {
            calls: Rc::clone(&self.calls),
            answers: Rc::clone(&self.answers),
        })
    }
}

impl Clients {
    fn answering(answers: Vec<Answered>) -> Clients {
        let clients = Clients::default();
        *clients.answers.borrow_mut() = answers;
        clients
    }
    fn calls(&self) -> Vec<UnitCall> {
        self.calls.borrow().clone()
    }
}

/// Tenant heads, read in turn (the last one stays); each read keeps the
/// `known` it was given.
struct Heads {
    heads: RefCell<Vec<Option<Option<TenantDoor>>>>,
    known: RefCell<Vec<u64>>,
}

impl Heads {
    fn of(doors: Vec<Option<Option<TenantDoor>>>) -> Heads {
        Heads {
            heads: RefCell::new(doors),
            known: RefCell::default(),
        }
    }
    fn one(seq: u64, units: &[u32]) -> Heads {
        Heads::of(vec![Some(Some(door(seq, units)))])
    }
    fn reads(&self) -> usize {
        self.known.borrow().len()
    }
}

fn door(seq: u64, units: &[u32]) -> TenantDoor {
    test_door(&tenant(), seq, Lifecycle::Live, units)
}

impl TenantHeads for Heads {
    async fn head(
        &self,
        _: &TenantId,
        known: u64,
    ) -> std::result::Result<Option<TenantDoor>, ChainError> {
        self.known.borrow_mut().push(known);
        let mut heads = self.heads.borrow_mut();
        let next = match heads.len() {
            0 => None,
            1 => heads[0].clone(),
            _ => heads.remove(0),
        };
        next.ok_or(ChainError::Busy)
    }
}

const S3_HOST: &str = "s3.example";

/// The configuration a managed request is judged under.
fn cfg(maintenance: Maintenance) -> BridgeConfig {
    let providers = serde_json::json!([{
        "id": "unused", "host": "127.0.0.1", "port": 1, "tls": false,
        "user": "nobody", "pass": "unused", "backbone": "none",
        "post": true, "read": true, "max_conns": 1,
    }])
    .to_string();
    let maintenance = match maintenance {
        Maintenance::Off => "off",
        Maintenance::Restore => "restore",
    };
    let vars: BTreeMap<&str, String> = [
        ("ENVIRONMENT", "dev".to_string()),
        ("S3_HOST", S3_HOST.to_string()),
        ("S3_REGION", "us-east-1".to_string()),
        ("MAX_EXTENT_BYTES", "16777216".to_string()),
        ("REQUIRED_BACKBONES", "1".to_string()),
        ("SAFETY_MIN_AGE_SECS", "0".to_string()),
        ("VERIFY_DELAY_SECS", "1".to_string()),
        ("DEV_TRUST_HTTP", "1".to_string()),
        ("NEWSGROUPS", "alt.binaries.test".to_string()),
        ("VELMORA_KEK_ACTIVE", "1".to_string()),
        ("INFLIGHT_BUDGET_BYTES", "50331648".to_string()),
        ("GC_MODE", "disposable".to_string()),
        ("MAINTENANCE", maintenance.to_string()),
        ("SERVER_SIDE_COPY", "on".to_string()),
        (
            "ADMIN_TOKEN",
            "router-test-admin-token-0123456789abcdef".to_string(),
        ),
        ("NNTP_PROVIDERS", providers),
        (
            "VELMORA_KEK_1",
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
        ),
    ]
    .into_iter()
    .collect();
    BridgeConfig::from_vars(|k| vars.get(k).cloned()).expect("test configuration is valid")
}

/// No floor: a call that knows no numbers.
const NONE: Seqs = Seqs {
    state_seq: 0,
    keys_seq: 0,
};

fn router<'a>(
    maintenance: Maintenance,
    clients: &'a Clients,
    heads: &'a Heads,
    cache: &'a HeadCache,
    clock: &'a FixedClock,
) -> Router<'a, Clients, Heads, FixedClock> {
    Router {
        maintenance,
        clients,
        heads,
        cache,
        clock,
    }
}

fn at(now: i64) -> FixedClock {
    FixedClock::new(UnixMs(now))
}

fn request(method: Method, target: &str) -> S3Request {
    S3Request {
        method,
        raw_target: target.to_string(),
        headers: vec![("host".into(), S3_HOST.into())],
        body: Body::Empty,
    }
}

/// The acceptance of L6-2: under `restore`, a PUT, a DELETE and a
/// multipart create to a unit answer `503` and make no unit call. Nor
/// does any other write; no head is read for one either.
#[tokio::test]
async fn under_restore_writes_answer_503_with_no_unit_call() {
    let clock = at(1);
    let clients = Clients::default();
    let heads = Heads::one(3, &[0]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Restore, &clients, &heads, &cache, &clock);
    for (method, target) in [
        (Method::Put, "/b/k"),
        (Method::Delete, "/b/k"),
        (Method::Post, "/b/k?uploads"),
        (Method::Put, "/b/k?partNumber=1&uploadId=u"),
        (Method::Post, "/b/k?uploadId=u"),
        (Method::Delete, "/b/k?uploadId=u"),
        (Method::Post, "/b?delete"),
        (Method::Put, "/b"),
        (Method::Delete, "/b"),
    ] {
        let req = request(method.clone(), target);
        let (resp, line) =
            serve_managed(&r, &cfg(Maintenance::Restore), &tenant(), NONE, &req).await;
        assert_eq!(resp.status, 503, "{method:?} {target}");
        assert!(
            resp.headers
                .iter()
                .any(|(n, v)| n == "retry-after" && v == "30"),
            "{method:?} {target}"
        );
        assert_eq!(
            line,
            ManagedLine {
                code: "maintenance",
                alert: false
            }
        );
    }
    assert_eq!(clients.made.get(), 0);
    assert!(clients.calls().is_empty());
    assert_eq!(heads.reads(), 0);
    // Through the port too: a request call that writes is refused before
    // any client is made; a read and the Worker's own calls go on.
    let routed = r.route(&tenant(), Some("b"), NONE).await.unwrap();
    assert_eq!(
        r.call(&routed, CallKind::Request, true, UnitOp::HeldKeys {})
            .await
            .0,
        Err(RouteRefusal::Maintenance)
    );
    assert_eq!(clients.made.get(), 0);
    *clients.answers.borrow_mut() = vec![
        answered(ok(seqs(3, 1)), None),
        answered(ok(seqs(3, 1)), None),
    ];
    let read = UnitOp::KeyRow {
        access_key_id: "AKIA".into(),
        presigned: None,
    };
    assert!(r
        .call(&routed, CallKind::Request, false, read)
        .await
        .0
        .is_ok());
    let sync = UnitOp::Sync {
        head: SyncHead {
            seqs: seqs(3, 1),
            tenant_state: TenantState::Active,
            tenant_mode: None,
            restoring_since: None,
            lift: None,
        },
    };
    assert!(r
        .call(&routed, CallKind::Worker, true, sync)
        .await
        .0
        .is_ok());
    assert_eq!(clients.calls().len(), 2);
}

#[tokio::test]
async fn reads_go_on_under_restore_and_nothing_is_served_by_this_build() {
    let clock = at(1);
    let clients = Clients::default();
    let heads = Heads::one(3, &[0]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Restore, &clients, &heads, &cache, &clock);
    for (method, target) in [
        (Method::Get, "/b/k"),
        (Method::Head, "/b/k"),
        (Method::Get, "/b"),
    ] {
        let req = request(method, target);
        let (resp, line) =
            serve_managed(&r, &cfg(Maintenance::Restore), &tenant(), NONE, &req).await;
        assert_eq!(resp.status, 503);
        assert_eq!(line.code, UNIT_REQUESTS_NOT_BUILT);
    }
    // One head read, cached; no unit call.
    assert_eq!(heads.reads(), 1);
    assert!(clients.calls().is_empty());
    let req = request(Method::Get, "/_admin/status");
    let (resp, line) = serve_managed(&r, &cfg(Maintenance::Off), &tenant(), NONE, &req).await;
    assert_eq!((resp.status, line.code), (403, "admin_with_key"));
}

/// A bucket goes to the unit its placement names, or to the root unit;
/// the unit must be listed. A head that cannot be read, a tenant with no
/// chain and tenant 0 are refusals.
#[tokio::test]
async fn placements_name_the_unit() {
    let clock = at(1);
    let clients = Clients::default();
    let mut placed = door(3, &[0, 1]);
    placed.placements = vec![Placement {
        bucket: "far".into(),
        unit: 1,
        epoch: 1,
    }];
    let heads = Heads::of(vec![Some(Some(placed))]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    let on = |n| Routed {
        unit: unit(n),
        seqs: seqs(3, 0),
        listed: true,
    };
    assert_eq!(r.route(&tenant(), Some("far"), NONE).await, Ok(on(1)));
    assert_eq!(r.route(&tenant(), Some("near"), NONE).await, Ok(on(0)));
    assert_eq!(r.route(&tenant(), None, NONE).await, Ok(on(0)));
    // A placement on a unit the head does not list.
    let mut stray = door(3, &[0]);
    stray.placements = vec![Placement {
        bucket: "far".into(),
        unit: 2,
        epoch: 1,
    }];
    let (heads, cache) = (Heads::of(vec![Some(Some(stray))]), HeadCache::default());
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    assert_eq!(
        r.route(&tenant(), Some("far"), NONE).await,
        Err(RouteRefusal::NotPlaced)
    );
    for (heads, want) in [
        (Heads::one(3, &[1]), RouteRefusal::NotPlaced),
        (Heads::of(vec![Some(None)]), RouteRefusal::NotPlaced),
        (Heads::of(vec![None]), RouteRefusal::Unavailable),
    ] {
        let cache = HeadCache::default();
        let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
        assert_eq!(r.route(&tenant(), None, NONE).await, Err(want));
    }
    let (heads, cache) = (Heads::one(3, &[0]), HeadCache::default());
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    assert_eq!(
        r.route(&TenantId::zero(), None, NONE).await,
        Err(RouteRefusal::NotPlaced)
    );
    assert_eq!(heads.reads(), 0);
    assert!(clients.calls().is_empty());
}

/// A head is used for less than 60 s, then read again from the seq it
/// knew; a clock that went back reads it again too.
#[tokio::test]
async fn a_head_is_cached_for_less_than_sixty_seconds() {
    let clock = at(1_000_000);
    let clients = Clients::default();
    let cache = HeadCache::default();
    let heads = Heads::of(vec![
        Some(Some(door(3, &[0]))),
        Some(Some(door(4, &[0]))),
        Some(Some(door(5, &[0]))),
    ]);
    // One router for every route: it reads the clock at each.
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    let seq = |r: Routed| r.seqs.state_seq;
    let t0 = 1_000_000;
    assert_eq!(seq(r.route(&tenant(), None, NONE).await.unwrap()), 3);
    clock.set(UnixMs(t0 + HEAD_MAX_AGE_MS - 1));
    assert_eq!(seq(r.route(&tenant(), None, NONE).await.unwrap()), 3);
    assert_eq!(heads.reads(), 1);
    clock.set(UnixMs(t0 + HEAD_MAX_AGE_MS));
    assert_eq!(seq(r.route(&tenant(), None, NONE).await.unwrap()), 4);
    clock.set(UnixMs(t0 + HEAD_MAX_AGE_MS - 5));
    assert_eq!(seq(r.route(&tenant(), None, NONE).await.unwrap()), 5);
    assert_eq!(*heads.known.borrow(), [0, 3, 4]);
}

/// The key route's numbers are a floor (rule 5, §8.4 step 2; review of
/// L6-2): the call carries at least its `keys_seq`, a cached head below
/// its `state_seq` is read again, and a head that stays below is refused.
#[tokio::test]
async fn the_key_routes_numbers_are_a_floor() {
    let clock = at(1);
    let clients = Clients::default();
    let cache = HeadCache::default();
    let heads = Heads::of(vec![
        Some(Some(door(3, &[0]))),
        Some(Some(door(6, &[0]))),
        Some(Some(door(6, &[0]))),
    ]);
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    assert_eq!(
        r.route(&tenant(), None, seqs(3, 5)).await.unwrap().seqs,
        seqs(3, 5)
    );
    // A floor above the cached head: read again.
    assert_eq!(
        r.route(&tenant(), None, seqs(6, 1)).await.unwrap().seqs,
        seqs(6, 5)
    );
    assert_eq!(heads.reads(), 2);
    // A verified head that stays below the floor is never routed by.
    assert_eq!(
        r.route(&tenant(), None, seqs(7, 0)).await,
        Err(RouteRefusal::Unavailable)
    );
    // An older head read late does not replace a newer one.
    assert_eq!(
        r.route(&tenant(), None, NONE).await.unwrap().seqs,
        seqs(6, 5)
    );
}

/// The management plane's reservation writes are Worker calls: the
/// maintenance gate refuses them too (review of L6-2, MEDIUM); the tools'
/// own calls pass.
#[tokio::test]
async fn under_restore_the_reservation_writes_are_refused() {
    use velmora_bridge::unit::call::UnitOp as Op;
    let clock = at(1);
    let clients = Clients::default();
    let heads = Heads::one(3, &[0]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Restore, &clients, &heads, &cache, &clock);
    let routed = r.route(&tenant(), None, NONE).await.unwrap();
    let writes = [
        Op::Release {
            rid: velmora_bridge::unit::reserve::Rid([7; 16]),
        },
        Op::BucketBinding { grant_seq: 1 },
    ];
    for op in writes {
        assert!(
            velmora_bridge::unit_router::writes(CallKind::Worker, &op),
            "{op:?}"
        );
        assert_eq!(
            r.call(&routed, CallKind::Worker, true, op).await.0,
            Err(RouteRefusal::Maintenance)
        );
    }
    assert_eq!(clients.made.get(), 0);
    // The tools' own calls pass: the move's window runs on them.
    let import_progress = Op::ImportProgress {};
    assert!(!velmora_bridge::unit_router::writes(
        CallKind::Worker,
        &import_progress
    ));
}

/// The host is judged first, as on tenant 0's path: a virtual-hosted
/// request is refused before any route (review of L6-2, LOW).
#[tokio::test]
async fn a_virtual_hosted_request_is_refused_before_routing() {
    let clock = at(1);
    let clients = Clients::default();
    let heads = Heads::one(3, &[0]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    let mut req = request(Method::Get, "/k");
    req.headers = vec![("host".into(), format!("b.{S3_HOST}"))];
    let (resp, line) = serve_managed(&r, &cfg(Maintenance::Off), &tenant(), NONE, &req).await;
    assert_eq!(line.code, "host_refused");
    assert_ne!(resp.status, 200);
    assert_eq!(heads.reads(), 0);
}

#[tokio::test]
async fn a_call_carries_the_numbers_and_listed_through_the_client() {
    let clock = at(1);
    let clients = Clients::answering(vec![answered(ok(seqs(3, 2)), None)]);
    let heads = Heads::one(3, &[0]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    let routed = r.route(&tenant(), Some("b"), NONE).await.unwrap();
    let op = UnitOp::Ping {};
    let got = r
        .call(&routed, CallKind::Request, true, op.clone())
        .await
        .0
        .unwrap();
    assert_eq!(got.reply.answer, ok(seqs(3, 2)));
    let calls = clients.calls();
    let c = &calls[0];
    assert_eq!(
        (&c.name, c.kind, c.seqs, c.authenticated, c.listed, &c.op),
        (
            &unit(0),
            CallKind::Request,
            Some(seqs(3, 0)),
            true,
            true,
            &op
        )
    );
    assert_eq!(*clients.routed.borrow(), [routed]);
    // The unit's keys_seq is kept: the next route carries it.
    assert_eq!(
        r.route(&tenant(), None, NONE).await.unwrap().seqs,
        seqs(3, 2)
    );
}

/// The client ran rule 5 with newer numbers: kept for the next call; a
/// `state_seq` above the head's makes the head be read again.
#[tokio::test]
async fn refreshed_numbers_are_kept_and_a_newer_state_reads_the_head_again() {
    let clock = at(1);
    let clients = Clients::answering(vec![
        answered(ok(seqs(3, 5)), Some(seqs(3, 5))),
        answered(ok(seqs(4, 5)), Some(seqs(4, 5))),
    ]);
    let heads = Heads::of(vec![Some(Some(door(3, &[0]))), Some(Some(door(4, &[0])))]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    let routed = r.route(&tenant(), None, NONE).await.unwrap();
    r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
        .await
        .0
        .unwrap();
    assert_eq!(
        r.route(&tenant(), None, NONE).await.unwrap().seqs,
        seqs(3, 5)
    );
    assert_eq!(heads.reads(), 1);
    r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
        .await
        .0
        .unwrap();
    assert_eq!(
        r.route(&tenant(), None, NONE).await.unwrap().seqs,
        seqs(4, 5)
    );
    assert_eq!(heads.reads(), 2);
}

#[tokio::test]
async fn closed_unborn_stale_and_an_unreachable_unit_are_refusals() {
    let clock = at(1);
    let heads = Heads::one(3, &[0]);
    for (answer, want) in [
        (
            UnitAnswer::Closed {
                seqs: seqs(3, 0),
                why: velmora_bridge::unit::call::Closed::Restoring,
            },
            RouteRefusal::Closed,
        ),
        (
            UnitAnswer::Unborn { listed: true },
            RouteRefusal::CatalogueLost,
        ),
        (
            UnitAnswer::Unborn { listed: false },
            RouteRefusal::NotPlaced,
        ),
        (
            UnitAnswer::Stale { seqs: seqs(4, 0) },
            RouteRefusal::NotFresh,
        ),
        (
            UnitAnswer::SyncNeeded { seqs: seqs(2, 0) },
            RouteRefusal::NotFresh,
        ),
        (
            UnitAnswer::RenewNeeded {
                seqs: seqs(3, 0),
                why: None,
            },
            RouteRefusal::NotFresh,
        ),
    ] {
        let clients = Clients::answering(vec![answered(answer.clone(), None)]);
        let cache = HeadCache::default();
        let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
        let routed = r.route(&tenant(), None, NONE).await.unwrap();
        assert_eq!(
            r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
                .await
                .0,
            Err(want),
            "{answer:?}"
        );
    }
    // The client's fix names the refusal when the unit still refuses.
    use velmora_bridge::unit_lease::client::{Renewal, Synced};
    for (renewal, synced, want) in [
        (Some(Renewal::Unborn), None, RouteRefusal::CatalogueLost),
        (
            Some(Renewal::Closed { rolled_back: true }),
            None,
            RouteRefusal::Closed,
        ),
        (
            None,
            Some(Synced::LiftPending { seqs: seqs(3, 0) }),
            RouteRefusal::Closed,
        ),
        (None, Some(Synced::NotListed), RouteRefusal::NotPlaced),
        (Some(Renewal::Refused), None, RouteRefusal::NotFresh),
        (Some(Renewal::Shredding), None, RouteRefusal::AccountProblem),
    ] {
        let mut a = answered(
            UnitAnswer::RenewNeeded {
                seqs: seqs(3, 0),
                why: None,
            },
            None,
        );
        a.renewal = renewal;
        a.synced = synced;
        let clients = Clients::answering(vec![a]);
        let cache = HeadCache::default();
        let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
        let routed = r.route(&tenant(), None, NONE).await.unwrap();
        assert_eq!(
            r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
                .await
                .0,
            Err(want)
        );
    }
    // AM-58: a provisioning tenant's unborn root unit is expected, so
    // it answers 503 with no page.
    let provisioning = Heads::of(vec![Some(Some(test_door(
        &tenant(),
        1,
        Lifecycle::Provisioning,
        &[0],
    )))]);
    let clients = Clients::answering(vec![answered(UnitAnswer::Unborn { listed: true }, None)]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &provisioning, &cache, &clock);
    let routed = r.route(&tenant(), None, NONE).await.unwrap();
    assert_eq!(
        r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
            .await
            .0,
        Err(RouteRefusal::Unavailable)
    );
    assert!(RouteRefusal::CatalogueLost.alert());
    assert!(!RouteRefusal::Closed.alert());
    let clients = Clients::default();
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, &clock);
    let routed = r.route(&tenant(), None, NONE).await.unwrap();
    let (result, pages) = r
        .call(&routed, CallKind::Request, true, UnitOp::Ping {})
        .await;
    assert_eq!(result, Err(RouteRefusal::Unavailable));
    // The client's pages come with the refusal, for the caller to log.
    assert_eq!(pages, [Page::UnitRefused("down")]);
}

#[test]
fn refusal_codes_are_fixed_and_distinct() {
    let all = [
        RouteRefusal::Maintenance,
        RouteRefusal::NotPlaced,
        RouteRefusal::Unavailable,
        RouteRefusal::Closed,
        RouteRefusal::CatalogueLost,
        RouteRefusal::NotFresh,
        RouteRefusal::AccountProblem,
    ];
    let codes: std::collections::BTreeSet<_> = all.iter().map(|r| r.code()).collect();
    assert_eq!(codes.len(), all.len());
}
