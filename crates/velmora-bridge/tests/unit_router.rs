//! The request router (ADR-TENANCY §2.7; design round 5, AM-51): a
//! managed tenant's request to its unit, and the maintenance gate before
//! any unit call (AM-50, the L6-2 acceptance).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use velmora_bridge::config::Maintenance;
use velmora_bridge::directory::chain::ChainError;
use velmora_bridge::directory::record::{Lifecycle, Placement, TenantDoor};
use velmora_bridge::service::{serve_managed, ManagedLine, UNIT_REQUESTS_NOT_BUILT};
use velmora_bridge::unit::{
    CallKind, Seqs, SyncHead, TenantId, TenantState, UnitAnswer, UnitCall, UnitName, UnitOp,
    UnitReply,
};
use velmora_bridge::unit_lease::client::{Answered, TenantHeads};
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
    async fn call(&self, call: UnitCall) -> Result<Answered> {
        self.calls.borrow_mut().push(call);
        let mut answers = self.answers.borrow_mut();
        match answers.is_empty() {
            true => Err(BridgeError::Sql("no answer".into())),
            false => Ok(answers.remove(0)),
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

fn router<'a>(
    maintenance: Maintenance,
    clients: &'a Clients,
    heads: &'a Heads,
    cache: &'a HeadCache,
    now: i64,
) -> Router<'a, Clients, Heads> {
    Router {
        maintenance,
        clients,
        heads,
        cache,
        now: UnixMs(now),
    }
}

fn request(method: Method, target: &str) -> S3Request {
    S3Request {
        method,
        raw_target: target.to_string(),
        headers: vec![("host".into(), "s3.example".into())],
        body: Body::Empty,
    }
}

/// The acceptance of L6-2: under `restore`, a PUT, a DELETE and a
/// multipart create to a unit answer `503` and make no unit call. Nor
/// does any other write; no head is read for one either.
#[tokio::test]
async fn under_restore_writes_answer_503_with_no_unit_call() {
    let clients = Clients::default();
    let heads = Heads::one(3, &[0]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Restore, &clients, &heads, &cache, 1);
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
        let (resp, line) = serve_managed(&r, Maintenance::Restore, &tenant(), &req).await;
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
    let routed = r.route(&tenant(), Some("b")).await.unwrap();
    assert_eq!(
        r.call(&routed, CallKind::Request, true, UnitOp::HeldKeys {})
            .await,
        Err(RouteRefusal::Maintenance)
    );
    assert_eq!(clients.made.get(), 0);
    *clients.answers.borrow_mut() = vec![
        answered(ok(seqs(3, 1)), None),
        answered(ok(seqs(3, 1)), None),
    ];
    let read = UnitOp::KeyRow {
        access_key_id: "AKIA".into(),
    };
    assert!(r
        .call(&routed, CallKind::Request, false, read)
        .await
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
    assert!(r.call(&routed, CallKind::Worker, true, sync).await.is_ok());
    assert_eq!(clients.calls().len(), 2);
}

#[tokio::test]
async fn reads_go_on_under_restore_and_nothing_is_served_by_this_build() {
    let clients = Clients::default();
    let heads = Heads::one(3, &[0]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Restore, &clients, &heads, &cache, 1);
    for (method, target) in [
        (Method::Get, "/b/k"),
        (Method::Head, "/b/k"),
        (Method::Get, "/b"),
    ] {
        let req = request(method, target);
        let (resp, line) = serve_managed(&r, Maintenance::Restore, &tenant(), &req).await;
        assert_eq!(resp.status, 503);
        assert_eq!(line.code, UNIT_REQUESTS_NOT_BUILT);
    }
    // One head read, cached; no unit call.
    assert_eq!(heads.reads(), 1);
    assert!(clients.calls().is_empty());
    let req = request(Method::Get, "/_admin/status");
    let (resp, line) = serve_managed(&r, Maintenance::Off, &tenant(), &req).await;
    assert_eq!((resp.status, line.code), (403, "admin_with_key"));
}

/// A bucket goes to the unit its placement names, or to the root unit;
/// the unit must be listed. A head that cannot be read, a tenant with no
/// chain and tenant 0 are refusals.
#[tokio::test]
async fn placements_name_the_unit() {
    let clients = Clients::default();
    let mut placed = door(3, &[0, 1]);
    placed.placements = vec![Placement {
        bucket: "far".into(),
        unit: 1,
        epoch: 1,
    }];
    let heads = Heads::of(vec![Some(Some(placed))]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, 1);
    let at = |n| Routed {
        unit: unit(n),
        seqs: seqs(3, 0),
        listed: true,
    };
    assert_eq!(r.route(&tenant(), Some("far")).await, Ok(at(1)));
    assert_eq!(r.route(&tenant(), Some("near")).await, Ok(at(0)));
    assert_eq!(r.route(&tenant(), None).await, Ok(at(0)));
    // A placement on a unit the head does not list.
    let mut stray = door(3, &[0]);
    stray.placements = vec![Placement {
        bucket: "far".into(),
        unit: 2,
        epoch: 1,
    }];
    let (heads, cache) = (Heads::of(vec![Some(Some(stray))]), HeadCache::default());
    let r = router(Maintenance::Off, &clients, &heads, &cache, 1);
    assert_eq!(
        r.route(&tenant(), Some("far")).await,
        Err(RouteRefusal::NotPlaced)
    );
    for (heads, want) in [
        (Heads::one(3, &[1]), RouteRefusal::NotPlaced),
        (Heads::of(vec![Some(None)]), RouteRefusal::NotPlaced),
        (Heads::of(vec![None]), RouteRefusal::Unavailable),
    ] {
        let cache = HeadCache::default();
        let r = router(Maintenance::Off, &clients, &heads, &cache, 1);
        assert_eq!(r.route(&tenant(), None).await, Err(want));
    }
    let (heads, cache) = (Heads::one(3, &[0]), HeadCache::default());
    let r = router(Maintenance::Off, &clients, &heads, &cache, 1);
    assert_eq!(
        r.route(&TenantId::zero(), None).await,
        Err(RouteRefusal::NotPlaced)
    );
    assert_eq!(heads.reads(), 0);
    assert!(clients.calls().is_empty());
}

/// A head is used for less than 60 s, then read again from the seq it
/// knew; a clock that went back reads it again too.
#[tokio::test]
async fn a_head_is_cached_for_less_than_sixty_seconds() {
    let clients = Clients::default();
    let cache = HeadCache::default();
    let heads = Heads::of(vec![
        Some(Some(door(3, &[0]))),
        Some(Some(door(4, &[0]))),
        Some(Some(door(5, &[0]))),
    ]);
    let at = |now| router(Maintenance::Off, &clients, &heads, &cache, now);
    let t0 = 1_000_000;
    let seq = |r: Routed| r.seqs.state_seq;
    assert_eq!(seq(at(t0).route(&tenant(), None).await.unwrap()), 3);
    let last = t0 + HEAD_MAX_AGE_MS - 1;
    assert_eq!(seq(at(last).route(&tenant(), None).await.unwrap()), 3);
    assert_eq!(heads.reads(), 1);
    let past = t0 + HEAD_MAX_AGE_MS;
    assert_eq!(seq(at(past).route(&tenant(), None).await.unwrap()), 4);
    assert_eq!(seq(at(past - 5).route(&tenant(), None).await.unwrap()), 5);
    assert_eq!(*heads.known.borrow(), [0, 3, 4]);
}

#[tokio::test]
async fn a_call_carries_the_numbers_and_listed_through_the_client() {
    let clients = Clients::answering(vec![answered(ok(seqs(3, 2)), None)]);
    let heads = Heads::one(3, &[0]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, 1);
    let routed = r.route(&tenant(), Some("b")).await.unwrap();
    let op = UnitOp::Ping {};
    let got = r
        .call(&routed, CallKind::Request, true, op.clone())
        .await
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
    assert_eq!(r.route(&tenant(), None).await.unwrap().seqs, seqs(3, 2));
}

/// The client ran rule 5 with newer numbers: kept for the next call; a
/// `state_seq` above the head's makes the head be read again.
#[tokio::test]
async fn refreshed_numbers_are_kept_and_a_newer_state_reads_the_head_again() {
    let clients = Clients::answering(vec![
        answered(ok(seqs(3, 5)), Some(seqs(3, 5))),
        answered(ok(seqs(4, 5)), Some(seqs(4, 5))),
    ]);
    let heads = Heads::of(vec![Some(Some(door(3, &[0]))), Some(Some(door(4, &[0])))]);
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, 1);
    let routed = r.route(&tenant(), None).await.unwrap();
    r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
        .await
        .unwrap();
    assert_eq!(r.route(&tenant(), None).await.unwrap().seqs, seqs(3, 5));
    assert_eq!(heads.reads(), 1);
    r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
        .await
        .unwrap();
    assert_eq!(r.route(&tenant(), None).await.unwrap().seqs, seqs(4, 5));
    assert_eq!(heads.reads(), 2);
}

#[tokio::test]
async fn closed_unborn_stale_and_an_unreachable_unit_are_refusals() {
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
        let r = router(Maintenance::Off, &clients, &heads, &cache, 1);
        let routed = r.route(&tenant(), None).await.unwrap();
        assert_eq!(
            r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
                .await,
            Err(want),
            "{answer:?}"
        );
    }
    assert!(RouteRefusal::CatalogueLost.alert());
    assert!(!RouteRefusal::Closed.alert());
    let clients = Clients::default();
    let cache = HeadCache::default();
    let r = router(Maintenance::Off, &clients, &heads, &cache, 1);
    let routed = r.route(&tenant(), None).await.unwrap();
    assert_eq!(
        r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
            .await,
        Err(RouteRefusal::Unavailable)
    );
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
    ];
    let codes: std::collections::BTreeSet<_> = all.iter().map(|r| r.code()).collect();
    assert_eq!(codes.len(), all.len());
}
