//! The request catalogue (package L6-6, AM-64, AM-63) and
//! `service::managed::finish`, over a scripted port: the `key_row`
//! answer, no request call before the signature, the tenant's state, the
//! re-read of a row answered under an expired lease, the methods that are
//! not on a unit's request path, and a unit's refusal as the request's
//! answer.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use base64::Engine as _;
use serde_json::json;
use velmora_bridge::keys::tk::LoadedRing;
use velmora_bridge::ports::Catalog;
use velmora_bridge::request_catalog::{
    is_account_problem, is_key_changed, KeyRow, RequestCatalog, TenantRing, ERR_BEFORE_SIGNATURE,
    ERR_NOT_ON_REQUEST_PATH,
};
use velmora_bridge::service::managed::{finish, PortState};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::tenant_catalog::UnitPort;
use velmora_bridge::testkit::{MemBlobStore, RusqliteSql};
use velmora_bridge::unit::call::HoldMode;
use velmora_bridge::unit::request_client::RequestClient;
use velmora_bridge::unit::size::SizeRefusal;
use velmora_bridge::unit::{
    Refused, Seqs, TenantId, TenantState, UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::unit_lease::client::Page;
use velmora_bridge::unit_router::RouteRefusal;
use velmora_bridge::{
    BridgeError, Bucket, BucketId, KeyStatus, Result, S3Response, TenantScope, UnixMs,
};

const T: &str = "t_00000000000000d1";
const AKID: &str = "AKIDREQUESTCAT000001";

fn tenant() -> TenantId {
    TenantId::parse(T).unwrap()
}

fn unit() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn seqs() -> Seqs {
    Seqs {
        state_seq: 3,
        keys_seq: 2,
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn body(status: &str, state: &str, mode: Option<&str>, expired: bool) -> serde_json::Value {
    json!({
        "key": {
            "access_key_id": AKID,
            "principal": "p_1",
            "secret_wrapped": base64::engine::general_purpose::STANDARD.encode([2u8, 7]),
            "kek_version": 1,
            "status": status,
            "created_at": 9,
        },
        "state": { "tenant_state": state, "tenant_mode": mode },
        "lease_expired": expired,
    })
}

fn row(status: &str, state: &str, mode: Option<&str>, expired: bool) -> KeyRow {
    KeyRow::from_body(&body(status, state, mode, expired), AKID).unwrap()
}

/// A scripted port: answers in turn (then `ok` with a null body), every
/// call kept; and the port state `finish` reads.
#[derive(Default)]
struct Port {
    calls: RefCell<Vec<UnitCall>>,
    answers: RefCell<Vec<Result<UnitAnswer>>>,
    refusal: Cell<Option<RouteRefusal>>,
    pages: RefCell<Vec<Page>>,
}

impl UnitPort for Port {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
        self.calls.borrow_mut().push(call.clone());
        let mut answers = self.answers.borrow_mut();
        match answers.is_empty() {
            true => Ok(UnitAnswer::Ok {
                seqs: seqs(),
                body: serde_json::Value::Null,
            }),
            false => answers.remove(0),
        }
    }
}

impl TenantRing for Port {
    async fn tenant_ring(
        &self,
        _: &velmora_bridge::crypto::scheme2::TenantId,
    ) -> Result<LoadedRing> {
        Err(BridgeError::Crypto("no ring here"))
    }
}

impl PortState for Port {
    fn route_refusal(&self) -> Option<RouteRefusal> {
        self.refusal.get()
    }
    fn take_pages(&self) -> Vec<Page> {
        std::mem::take(&mut *self.pages.borrow_mut())
    }
    fn renew_due(&self) -> Option<(UnitName, Seqs)> {
        None
    }
}

type Cat = RequestCatalog<Port, SqlCatalog<RusqliteSql>>;

fn catalog(key_row: KeyRow) -> (Cat, Rc<Cell<bool>>) {
    let verified = Rc::new(Cell::new(true));
    let cat = RequestCatalog::new(
        RequestClient::new(Port::default(), unit(), seqs()),
        SqlCatalog::new(RusqliteSql::with_schema().unwrap()),
        TenantScope::managed(&tenant()).unwrap(),
        AKID,
        key_row,
        Rc::clone(&verified),
    );
    (cat, verified)
}

fn calls(cat: &Cat) -> Vec<UnitCall> {
    cat.client().port().calls.borrow().clone()
}

#[test]
fn the_key_row_reads_the_claimed_key_and_the_state() {
    let r = row("active", "active", None, false);
    let key = r.key.as_ref().unwrap();
    assert_eq!(key.access_key_id, AKID);
    assert_eq!(key.secret_wrapped, vec![2, 7]);
    assert_eq!(key.status, KeyStatus::Active);
    assert_eq!(key.created_at, UnixMs(9));
    assert_eq!(r.tenant_state, TenantState::Active);
    assert!(!r.lease_expired);
    // Another key's row, a status this build does not know, no key.
    assert!(KeyRow::from_body(
        &body("active", "active", None, false),
        "AKIDOTHER0000000001"
    )
    .unwrap()
    .key
    .is_none());
    assert!(row("revoked", "active", None, false).key.is_none());
    let none = json!({"key": null, "state": {"tenant_state": "active", "tenant_mode": null}});
    assert!(KeyRow::from_body(&none, AKID).unwrap().key.is_none());
    // A state that does not read is the call's error.
    assert!(KeyRow::from_body(&body("active", "melting", None, false), AKID).is_err());
    assert!(KeyRow::from_body(&body("active", "suspended", Some("frozen"), false), AKID).is_err());
    assert!(KeyRow::from_body(&json!({"key": null}), AKID).is_err());
    // The unit's rule for a call.
    for (state, mode, read, serves) in [
        ("active", None, true, true),
        ("active", None, false, true),
        ("suspended", Some("read_only"), true, true),
        ("suspended", Some("read_only"), false, false),
        ("suspended", Some("locked"), true, false),
        ("suspended", None, true, false),
        ("provisioning", None, true, false),
        ("deleting", None, true, false),
        ("shredding", None, true, false),
        ("shredded", None, true, false),
    ] {
        assert_eq!(
            row("active", state, mode, false).serves(read),
            serves,
            "{state} {mode:?} {read}"
        );
    }
    assert_eq!(
        row("active", "suspended", Some("read_only"), false).tenant_mode,
        Some(HoldMode::ReadOnly)
    );
}

#[test]
fn no_request_call_goes_before_the_signature() {
    let (cat, _) = catalog(row("active", "active", None, false));
    // `new` clears the flag: nothing is verified yet.
    let bucket = BucketId::mint([1; 8]);
    let err = block_on(cat.grant(AKID, &bucket)).unwrap_err();
    assert_eq!(err.to_string(), ERR_BEFORE_SIGNATURE.to_string());
    assert!(block_on(cat.bucket_by_name("alpha")).is_err());
    assert!(calls(&cat).is_empty());
    // The key row answers `access_key` with no call: for the claimed key
    // only.
    let key = block_on(cat.access_key(AKID)).unwrap().unwrap();
    assert_eq!(key.principal, "p_1");
    assert!(block_on(cat.access_key("AKIDOTHER0000000001"))
        .unwrap()
        .is_none());
    assert!(calls(&cat).is_empty());
    // After the signature, calls go out authenticated through the port.
    block_on(cat.signature_verified(true)).unwrap();
    let _ = block_on(cat.bucket_by_name("alpha"));
    assert_eq!(calls(&cat).len(), 1);
    assert!(matches!(calls(&cat)[0].op, UnitOp::Request { .. }));
}

#[test]
fn the_tenants_state_refuses_before_any_call() {
    let (cat, verified) = catalog(row("active", "suspended", Some("read_only"), false));
    let e = block_on(cat.signature_verified(false)).unwrap_err();
    assert!(is_account_problem(&e));
    assert!(!verified.get());
    assert!(calls(&cat).is_empty());
    block_on(cat.signature_verified(true)).unwrap();
    assert!(verified.get());
    let (cat, verified) = catalog(row("active", "deleting", None, false));
    assert!(is_account_problem(
        &block_on(cat.signature_verified(true)).unwrap_err()
    ));
    assert!(!verified.get());
}

/// AM-63: a row answered under an expired lease checked the signature
/// only; it is read again, authenticated, before anything is served.
#[test]
fn a_row_read_under_an_expired_lease_is_read_again() {
    let ok = |b| {
        Ok(UnitAnswer::Ok {
            seqs: seqs(),
            body: b,
        })
    };
    // The same row: served.
    let (cat, verified) = catalog(row("active", "active", None, true));
    *cat.client().port().answers.borrow_mut() = vec![ok(body("active", "active", None, false))];
    block_on(cat.signature_verified(true)).unwrap();
    assert!(verified.get());
    let c = calls(&cat);
    assert_eq!(c.len(), 1);
    assert!(matches!(c[0].op, UnitOp::KeyRow { .. }) && c[0].authenticated);
    // The key disabled since: refused, not verified.
    let (cat, verified) = catalog(row("active", "active", None, true));
    *cat.client().port().answers.borrow_mut() = vec![ok(body("disabled", "active", None, false))];
    assert!(is_key_changed(
        &block_on(cat.signature_verified(true)).unwrap_err()
    ));
    assert!(!verified.get());
    // The tenant suspended since: AccountProblem.
    let (cat, _) = catalog(row("active", "active", None, true));
    *cat.client().port().answers.borrow_mut() =
        vec![ok(body("active", "suspended", Some("locked"), false))];
    assert!(is_account_problem(
        &block_on(cat.signature_verified(true)).unwrap_err()
    ));
    // No answer: the request's error (503).
    let (cat, verified) = catalog(row("active", "active", None, true));
    *cat.client().port().answers.borrow_mut() = vec![Err(BridgeError::Sql("down".into()))];
    let e = block_on(cat.signature_verified(true)).unwrap_err();
    assert!(!is_account_problem(&e) && !is_key_changed(&e));
    assert!(!verified.get());
}

#[test]
fn methods_off_the_request_path_are_refused_and_permits_are_shared() {
    let (cat, _) = catalog(row("active", "active", None, false));
    block_on(cat.signature_verified(true)).unwrap();
    let bucket = Bucket {
        id: BucketId::mint([2; 8]),
        name: "beta".into(),
        owner: "p_1".into(),
        bdk_wrapped: vec![2],
        kek_version: 1,
        created_at: UnixMs(1),
        disposable: true,
    };
    let refused = block_on(cat.create_bucket(&bucket)).unwrap_err();
    assert_eq!(refused.to_string(), ERR_NOT_ON_REQUEST_PATH.to_string());
    assert!(block_on(cat.delete_bucket(&bucket)).is_err());
    assert!(block_on(cat.access_key_exists(AKID)).is_err());
    assert!(calls(&cat).is_empty());
    // The shared catalogue's permits.
    assert!(block_on(cat.seed_permits(&[])).is_ok());
    assert!(calls(&cat).is_empty());
    // The scope is the tenant's.
    assert_eq!(cat.request_scope().unwrap().tenant_id(), T);
    // The bucket key needs the ring, which this port refuses: an error,
    // never the KEK's unwrap.
    assert!(matches!(block_on(cat.bucket_key(&bucket)), Some(Err(_))));
}

fn resp(status: u16) -> S3Response {
    S3Response::error(status, "Test", "test")
}

fn client_refusing(answer: UnitAnswer) -> RequestClient<Port> {
    let port = Port::default();
    *port.answers.borrow_mut() = vec![Ok(answer)];
    let client = RequestClient::new(port, unit(), seqs());
    let _ = block_on(client.bucket_by_name("alpha"));
    client
}

fn refused(reason: Refused) -> UnitAnswer {
    UnitAnswer::Refused {
        reason,
        alarm: false,
    }
}

/// A unit's refusal answers the request when the handler failed on it;
/// a handler that answered anyway keeps its answer, and the line says
/// what the unit refused.
#[test]
fn finish_answers_with_the_units_refusal_when_the_handler_failed() {
    let safety = MemBlobStore::default();
    for (answer, status, code, alert) in [
        (
            refused(Refused::AccountProblem),
            403,
            "account_problem",
            false,
        ),
        (refused(Refused::NotFound), 404, "not_found", false),
        (
            refused(Refused::Size(SizeRefusal::DatabaseFull)),
            503,
            "unit_full",
            true,
        ),
        (
            refused(Refused::Size(SizeRefusal::TooManyExtents)),
            503,
            "unit_extents_full",
            true,
        ),
        (refused(Refused::Unauthenticated), 500, "unit_refused", true),
    ] {
        let client = client_refusing(answer.clone());
        let f = block_on(finish(&client, &safety, resp(500)));
        assert_eq!(
            (f.resp.status, f.lines[0].code, f.lines[0].alert),
            (status, code, alert),
            "{answer:?}"
        );
        // The same refusal under an answer the handler made: kept.
        let client = client_refusing(answer.clone());
        let f = block_on(finish(&client, &safety, resp(200)));
        assert_eq!((f.resp.status, f.lines[0].code), (200, code), "{answer:?}");
    }
    // A router refusal: 503, or 403 for a shredding tenant; the pages
    // follow as alerts.
    let client = RequestClient::new(Port::default(), unit(), seqs());
    client.port().refusal.set(Some(RouteRefusal::Closed));
    client.port().pages.borrow_mut().push(Page::RolledBack);
    let f = block_on(finish(&client, &safety, resp(500)));
    assert_eq!((f.resp.status, f.lines[0].code), (503, "closed"));
    assert!(f
        .resp
        .headers
        .iter()
        .any(|(n, v)| n == "retry-after" && v == "30"));
    assert_eq!((f.lines[1].code, f.lines[1].alert), ("rolled_back", true));
    let client = RequestClient::new(Port::default(), unit(), seqs());
    client
        .port()
        .refusal
        .set(Some(RouteRefusal::AccountProblem));
    let f = block_on(finish(&client, &safety, resp(500)));
    assert_eq!(f.resp.status, 403);
    // Nothing refused: the handler's answer.
    let client = RequestClient::new(Port::default(), unit(), seqs());
    let f = block_on(finish(&client, &safety, resp(204)));
    assert_eq!((f.resp.status, f.lines[0].code), (204, "served"));
    assert!(f.renew.is_none());
}
