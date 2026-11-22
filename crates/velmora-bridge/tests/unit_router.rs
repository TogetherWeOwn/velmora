//! The request router (ADR-TENANCY §2.7; design round 5, AM-51): a
//! managed tenant's request to its unit, and the maintenance gate before
//! any unit call (AM-50, the L6-2 acceptance).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use velmora_bridge::config::Maintenance;
use velmora_bridge::service::{serve_managed, ManagedLine, UNIT_REQUESTS_NOT_BUILT};
use velmora_bridge::tenant_catalog::UnitPort;
use velmora_bridge::unit::{
    CallKind, Seqs, SyncHead, TenantId, TenantState, UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::unit_consumer::ConsumerClient;
use velmora_bridge::unit_router::{
    HeadCache, HeadView, RouteRefusal, Routed, Router, TenantHeads, UnitPorts, UnitRouter,
    HEAD_MAX_AGE_MS,
};
use velmora_bridge::{Body, BridgeError, Method, Result, S3Request, UnixMs};

fn tenant() -> TenantId {
    TenantId::parse("t_00000000000000a7").unwrap()
}

fn root() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn seqs(state_seq: u64, keys_seq: u64) -> Seqs {
    Seqs {
        state_seq,
        keys_seq,
    }
}

/// The unit objects: each call is kept, each answer is scripted.
#[derive(Default)]
struct Units {
    opens: Cell<u32>,
    calls: Rc<RefCell<Vec<UnitCall>>>,
    answers: Rc<RefCell<Vec<UnitAnswer>>>,
}

struct Port {
    calls: Rc<RefCell<Vec<UnitCall>>>,
    answers: Rc<RefCell<Vec<UnitAnswer>>>,
}

impl UnitPort for Port {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
        self.calls.borrow_mut().push(call.clone());
        let mut answers = self.answers.borrow_mut();
        match answers.is_empty() {
            true => Err(BridgeError::Sql("no answer".into())),
            false => Ok(answers.remove(0)),
        }
    }
}

impl UnitPorts for Units {
    type Port = Port;
    fn open(&self, _: &UnitName) -> Result<Port> {
        self.opens.set(self.opens.get() + 1);
        Ok(Port {
            calls: Rc::clone(&self.calls),
            answers: Rc::clone(&self.answers),
        })
    }
}

impl Units {
    fn answering(answers: Vec<UnitAnswer>) -> Units {
        let units = Units::default();
        *units.answers.borrow_mut() = answers;
        units
    }
    fn calls(&self) -> Vec<UnitCall> {
        self.calls.borrow().clone()
    }
}

/// Tenant heads, read in turn; the last one stays.
struct Heads {
    heads: RefCell<Vec<Option<HeadView>>>,
    reads: Cell<u32>,
}

impl Heads {
    fn of(views: Vec<Option<HeadView>>) -> Heads {
        Heads {
            heads: RefCell::new(views),
            reads: Cell::new(0),
        }
    }
    fn one(units: &[u32], s: Seqs) -> Heads {
        Heads::of(vec![Some(view(units, s))])
    }
}

fn view(units: &[u32], s: Seqs) -> HeadView {
    HeadView {
        seqs: s,
        state: TenantState::Active,
        units: units.to_vec(),
    }
}

impl TenantHeads for Heads {
    async fn head(&self, _: &TenantId) -> Result<HeadView> {
        self.reads.set(self.reads.get() + 1);
        let mut heads = self.heads.borrow_mut();
        let next = match heads.len() {
            0 => None,
            1 => heads[0].clone(),
            _ => heads.remove(0),
        };
        next.ok_or(BridgeError::Sql("unreadable".into()))
    }
}

#[derive(Default)]
struct Client {
    syncs: Cell<u32>,
    fail: bool,
    after: Option<Seqs>,
}

impl ConsumerClient for Client {
    async fn renew(&self, _: &UnitName) -> Result<()> {
        Ok(())
    }
    async fn sync(&self, _: &UnitName) -> Result<Seqs> {
        self.syncs.set(self.syncs.get() + 1);
        match self.fail {
            true => Err(BridgeError::Sql("down".into())),
            false => Ok(self.after.unwrap_or(seqs(9, 9))),
        }
    }
    async fn stamp_raise(&self, _: &UnitName) -> Result<()> {
        Ok(())
    }
}

fn router<'a>(
    maintenance: Maintenance,
    units: &'a Units,
    heads: &'a Heads,
    client: &'a Client,
    cache: &'a HeadCache,
    now: i64,
) -> Router<'a, Units, Heads, Client> {
    Router {
        maintenance,
        ports: units,
        heads,
        client,
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

fn ok(s: Seqs) -> UnitAnswer {
    UnitAnswer::Ok {
        seqs: s,
        body: serde_json::json!(null),
    }
}

/// The acceptance of L6-2: under `restore`, a PUT, a DELETE and a
/// multipart create to a unit answer `503` and make no unit call. Nor
/// does any other write; no head is read for one either.
#[tokio::test]
async fn under_restore_writes_answer_503_with_no_unit_call() {
    let units = Units::default();
    let heads = Heads::one(&[0], seqs(3, 1));
    let (client, cache) = (Client::default(), HeadCache::default());
    let r = router(Maintenance::Restore, &units, &heads, &client, &cache, 1);
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
        let (resp, line) = serve_managed(
            &r,
            Maintenance::Restore,
            &tenant(),
            &request(method.clone(), target),
        )
        .await;
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
    assert_eq!(units.opens.get(), 0);
    assert!(units.calls().is_empty());
    assert_eq!(heads.reads.get(), 0);
    // Through the port too: a request call that writes is refused before
    // the unit is reached; a read and the Worker's own calls go on.
    let routed = r.route(&tenant(), Some("b")).await.unwrap();
    assert_eq!(
        r.call(&routed, CallKind::Request, true, UnitOp::HeldKeys {})
            .await,
        Err(RouteRefusal::Maintenance)
    );
    assert_eq!(units.opens.get(), 0);
    *units.answers.borrow_mut() = vec![ok(seqs(3, 1)), ok(seqs(3, 1))];
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
    assert_eq!(units.calls().len(), 2);
}

#[tokio::test]
async fn reads_go_on_under_restore_and_nothing_is_served_by_this_build() {
    let units = Units::default();
    let heads = Heads::one(&[0], seqs(3, 1));
    let (client, cache) = (Client::default(), HeadCache::default());
    let r = router(Maintenance::Restore, &units, &heads, &client, &cache, 1);
    for (method, target) in [
        (Method::Get, "/b/k"),
        (Method::Head, "/b/k"),
        (Method::Get, "/b"),
    ] {
        let (resp, line) = serve_managed(
            &r,
            Maintenance::Restore,
            &tenant(),
            &request(method, target),
        )
        .await;
        assert_eq!(resp.status, 503);
        assert_eq!(line.code, UNIT_REQUESTS_NOT_BUILT);
    }
    // One head read, cached; no unit call.
    assert_eq!(heads.reads.get(), 1);
    assert!(units.calls().is_empty());
    let (resp, line) = serve_managed(
        &r,
        Maintenance::Off,
        &tenant(),
        &request(Method::Get, "/_admin/status"),
    )
    .await;
    assert_eq!((resp.status, line.code), (403, "admin_with_key"));
}

#[tokio::test]
async fn the_root_unit_holds_every_bucket_of_a_one_unit_tenant() {
    let units = Units::default();
    let (client, cache) = (Client::default(), HeadCache::default());
    let heads = Heads::one(&[0], seqs(3, 1));
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    let want = Routed {
        unit: root(),
        seqs: seqs(3, 1),
        listed: true,
    };
    assert_eq!(r.route(&tenant(), Some("b")).await, Ok(want.clone()));
    assert_eq!(r.route(&tenant(), None).await, Ok(want));
    // Two units: the placement list is not read by this build.
    let cache = HeadCache::default();
    let heads = Heads::one(&[0, 1], seqs(3, 1));
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    assert_eq!(
        r.route(&tenant(), Some("b")).await,
        Err(RouteRefusal::NotPlaced)
    );
    assert!(r.route(&tenant(), None).await.is_ok());
    // No root unit listed, a head that cannot be read, tenant 0.
    let cache = HeadCache::default();
    let heads = Heads::one(&[1], seqs(3, 1));
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    assert_eq!(r.route(&tenant(), None).await, Err(RouteRefusal::NotPlaced));
    let cache = HeadCache::default();
    let heads = Heads::of(vec![None]);
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    assert_eq!(
        r.route(&tenant(), None).await,
        Err(RouteRefusal::Unavailable)
    );
    assert_eq!(
        r.route(&TenantId::zero(), None).await,
        Err(RouteRefusal::NotPlaced)
    );
    assert!(units.calls().is_empty());
}

/// A head is used for less than 60 s, then read again; a clock that went
/// back reads it again too.
#[tokio::test]
async fn a_head_is_cached_for_less_than_sixty_seconds() {
    let units = Units::default();
    let (client, cache) = (Client::default(), HeadCache::default());
    let heads = Heads::of(vec![
        Some(view(&[0], seqs(3, 1))),
        Some(view(&[0], seqs(4, 1))),
        Some(view(&[0], seqs(5, 1))),
    ]);
    let at = |now| router(Maintenance::Off, &units, &heads, &client, &cache, now);
    let t0 = 1_000_000;
    assert_eq!(
        at(t0).route(&tenant(), None).await.unwrap().seqs,
        seqs(3, 1)
    );
    let last = t0 + HEAD_MAX_AGE_MS - 1;
    assert_eq!(
        at(last).route(&tenant(), None).await.unwrap().seqs,
        seqs(3, 1)
    );
    assert_eq!(heads.reads.get(), 1);
    let past = t0 + HEAD_MAX_AGE_MS;
    assert_eq!(
        at(past).route(&tenant(), None).await.unwrap().seqs,
        seqs(4, 1)
    );
    assert_eq!(
        at(past - 5).route(&tenant(), None).await.unwrap().seqs,
        seqs(5, 1)
    );
    assert_eq!(heads.reads.get(), 3);
}

#[tokio::test]
async fn a_call_carries_the_numbers_and_listed() {
    let units = Units::answering(vec![ok(seqs(3, 1))]);
    let (client, cache) = (Client::default(), HeadCache::default());
    let heads = Heads::one(&[0], seqs(3, 1));
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    let routed = r.route(&tenant(), Some("b")).await.unwrap();
    let op = UnitOp::Ping {};
    assert_eq!(
        r.call(&routed, CallKind::Request, true, op.clone()).await,
        Ok(ok(seqs(3, 1)))
    );
    let calls = units.calls();
    assert_eq!(calls.len(), 1);
    let c = &calls[0];
    assert_eq!(
        (&c.name, c.kind, c.seqs, c.authenticated, c.listed, &c.op),
        (
            &root(),
            CallKind::Request,
            Some(seqs(3, 1)),
            true,
            true,
            &op
        )
    );
}

/// Rule 5: a request with lower numbers re-reads the head and is sent
/// once more; a request the unit is behind on syncs first. Once only.
#[tokio::test]
async fn stale_and_sync_needed_are_refreshed_once() {
    let (client, cache) = (Client::default(), HeadCache::default());
    let heads = Heads::of(vec![
        Some(view(&[0], seqs(3, 1))),
        Some(view(&[0], seqs(5, 2))),
    ]);
    let units = Units::answering(vec![UnitAnswer::Stale { seqs: seqs(5, 2) }, ok(seqs(5, 2))]);
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    let routed = r.route(&tenant(), None).await.unwrap();
    assert!(r
        .call(&routed, CallKind::Request, true, UnitOp::Ping {})
        .await
        .is_ok());
    let sent: Vec<_> = units.calls().iter().map(|c| c.seqs).collect();
    assert_eq!(sent, [Some(seqs(3, 1)), Some(seqs(5, 2))]);
    assert_eq!(heads.reads.get(), 2);
    // The refreshed head is the cached one now.
    assert_eq!(r.route(&tenant(), None).await.unwrap().seqs, seqs(5, 2));
    assert_eq!(heads.reads.get(), 2);

    let units = Units::answering(vec![
        UnitAnswer::Stale { seqs: seqs(5, 2) },
        UnitAnswer::Stale { seqs: seqs(6, 2) },
    ]);
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    assert_eq!(
        r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
            .await,
        Err(RouteRefusal::NotFresh)
    );
    assert_eq!(units.calls().len(), 2);

    let client = Client {
        after: Some(seqs(7, 3)),
        ..Client::default()
    };
    let units = Units::answering(vec![
        UnitAnswer::SyncNeeded { seqs: seqs(2, 1) },
        ok(seqs(7, 3)),
    ]);
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    assert!(r
        .call(&routed, CallKind::Request, true, UnitOp::Ping {})
        .await
        .is_ok());
    assert_eq!(client.syncs.get(), 1);
    assert_eq!(units.calls()[1].seqs, Some(seqs(7, 3)));

    let client = Client {
        fail: true,
        ..Client::default()
    };
    let units = Units::answering(vec![UnitAnswer::SyncNeeded { seqs: seqs(2, 1) }]);
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
    assert_eq!(
        r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
            .await,
        Err(RouteRefusal::NotFresh)
    );
    assert_eq!(units.calls().len(), 1);
}

#[tokio::test]
async fn closed_unborn_and_an_unreachable_unit_are_refusals() {
    let (client, cache) = (Client::default(), HeadCache::default());
    let heads = Heads::one(&[0], seqs(3, 1));
    for (answer, want) in [
        (
            UnitAnswer::Closed {
                seqs: seqs(3, 1),
                why: velmora_bridge::unit::call::Closed::Restoring,
            },
            RouteRefusal::Closed,
        ),
        (
            UnitAnswer::Unborn { listed: true },
            RouteRefusal::CatalogueLost,
        ),
    ] {
        let units = Units::answering(vec![answer]);
        let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
        let routed = r.route(&tenant(), None).await.unwrap();
        assert_eq!(
            r.call(&routed, CallKind::Request, true, UnitOp::Ping {})
                .await,
            Err(want)
        );
    }
    assert!(RouteRefusal::CatalogueLost.alert());
    assert!(!RouteRefusal::Closed.alert());
    let units = Units::default();
    let r = router(Maintenance::Off, &units, &heads, &client, &cache, 1);
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
