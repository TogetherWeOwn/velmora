//! The request port of a managed tenant's S3 request (lane L6, package
//! L6-6; AM-64, AM-71): the [`UnitPort`] that the request catalogue's
//! request client sends through, over the router and the unit client the
//! composition root builds.
//!
//! `Bridge::handle` holds its bridge for the whole request (`'static`),
//! so the port owns what it needs: the root's ports and the isolate's
//! cache, by `Rc`. Each call builds a [`Root`] over them (no I/O) and
//! calls through its router, so the renewal state, the head cache and the
//! key routes stay the isolate's (AM-71). `UnitClient::call` is the only
//! retry layer: the port adds none.
//!
//! - Before the signature verified, the port sends only `key_row`
//!   (unauthenticated); every request call is refused before it is sent.
//! - Every call after it is authenticated and carries the routed unit's
//!   numbers, raised to what the unit answered (rule 5's numbers, kept
//!   for the request's later calls).
//! - A router refusal (`503`, or `403 AccountProblem`) is kept, the first
//!   one, for `service::managed::finish`; so are the unit client's pages
//!   and an answer that asked for a background renewal (rule 12).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use velmora::rng::FillRandom;

use crate::config::Maintenance;
use crate::keys::tk::LoadedRing;
use crate::request_catalog::TenantRing;
use crate::service::managed::PortState;
use crate::tenant_catalog::UnitPort;
use crate::types::{BridgeError, Result};
use crate::unit::{Seqs, UnitAnswer, UnitCall, UnitName, UnitOp};
use crate::unit_lease::client::Page;
use crate::unit_router::{RouteRefusal, Routed, UnitRouter};

use super::client::UnitPorts;
use super::{Root, RootCache};

/// A request call before the signature verified: not sent.
pub const ERR_UNSIGNED_CALL: BridgeError =
    BridgeError::Invalid("unit request: a call before the signature verified");
/// The router refused the call; the refusal is kept.
pub const ERR_ROUTE_REFUSED: BridgeError = BridgeError::Invalid("unit request: route refused");

/// The port of one managed tenant's request (see the [module](self)).
pub struct RequestPort<P: UnitPorts, R> {
    ports: Rc<P>,
    cache: Rc<RootCache>,
    rng: fn() -> R,
    maintenance: Maintenance,
    routed: RefCell<std::result::Result<Routed, RouteRefusal>>,
    verified: Rc<Cell<bool>>,
    refusal: Cell<Option<RouteRefusal>>,
    pages: RefCell<Vec<Page>>,
    renew: Cell<Option<Seqs>>,
}

impl<P: UnitPorts, R: FillRandom> RequestPort<P, R> {
    /// The port of a request routed to `routed` (or refused there).
    /// `verified` is the request catalogue's flag.
    pub fn new(
        ports: Rc<P>,
        cache: Rc<RootCache>,
        rng: fn() -> R,
        maintenance: Maintenance,
        routed: std::result::Result<Routed, RouteRefusal>,
        verified: Rc<Cell<bool>>,
    ) -> Self {
        RequestPort {
            ports,
            cache,
            rng,
            maintenance,
            routed: RefCell::new(routed),
            verified,
            refusal: Cell::new(None),
            pages: RefCell::new(Vec::new()),
            renew: Cell::new(None),
        }
    }

    /// The root's ports (for a background renewal after the request).
    pub fn ports(&self) -> &Rc<P> {
        &self.ports
    }

    /// The isolate's root cache.
    pub fn cache(&self) -> &Rc<RootCache> {
        &self.cache
    }

    /// The unit and numbers the request client starts from; `None` when
    /// the route was refused (every call then answers that refusal).
    pub fn routed(&self) -> Option<Routed> {
        self.routed.borrow().as_ref().ok().cloned()
    }

    fn keep(&self, refusal: RouteRefusal) {
        if self.refusal.get().is_none() {
            self.refusal.set(Some(refusal));
        }
    }
}

impl<P: UnitPorts, R: FillRandom> UnitPort for RequestPort<P, R> {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
        let authenticated = self.verified.get();
        if !authenticated && !matches!(call.op, UnitOp::KeyRow { .. }) {
            return Err(ERR_UNSIGNED_CALL);
        }
        let routed = match &*self.routed.borrow() {
            Ok(routed) => routed.clone(),
            Err(refusal) => {
                self.keep(*refusal);
                return Err(ERR_ROUTE_REFUSED);
            }
        };
        let root = Root::new(&*self.ports, &self.cache, (self.rng)());
        let clients = root.clients();
        let heads = root.heads();
        let router = root.router(self.maintenance, &clients, &heads);
        let (answered, pages) = router
            .call(&routed, call.kind, authenticated, call.op.clone())
            .await;
        self.pages.borrow_mut().extend(pages);
        let answered = match answered {
            Ok(answered) => answered,
            Err(refusal) => {
                self.keep(refusal);
                return Err(ERR_ROUTE_REFUSED);
            }
        };
        // The unit's numbers carry to this request's later calls (rule 5):
        // never lower than the head's.
        if let UnitAnswer::Ok { seqs, .. } = &answered.reply.answer {
            if let Ok(r) = &mut *self.routed.borrow_mut() {
                r.seqs = Seqs {
                    state_seq: r.seqs.state_seq.max(seqs.state_seq),
                    keys_seq: r.seqs.keys_seq.max(seqs.keys_seq),
                };
            }
            if answered.renew_due {
                self.renew.set(Some(*seqs));
            }
        }
        Ok(answered.reply.answer)
    }
}

impl<P: UnitPorts, R: FillRandom> TenantRing for RequestPort<P, R> {
    async fn tenant_ring(&self, tenant: &crate::crypto::scheme2::TenantId) -> Result<LoadedRing> {
        Root::new(&*self.ports, &self.cache, (self.rng)())
            .tenant_keys(tenant)
            .await
    }
}

impl<P: UnitPorts, R: FillRandom> PortState for RequestPort<P, R> {
    fn route_refusal(&self) -> Option<RouteRefusal> {
        self.refusal.get()
    }

    fn take_pages(&self) -> Vec<Page> {
        std::mem::take(&mut *self.pages.borrow_mut())
    }

    fn renew_due(&self) -> Option<(UnitName, Seqs)> {
        let seqs = self.renew.get()?;
        let unit = self.routed.borrow().as_ref().ok()?.unit.clone();
        Some((unit, seqs))
    }
}

/// The background renewal of rule 12 for `unit`, from `seqs` (an answer
/// with less than half of T left asked for it): the Worker runs it under
/// `waitUntil`. Through the isolate's spacing, so at most one runs per
/// unit. The pages come back for the log; `None`: none was run.
pub async fn renew_in_background<P: UnitPorts, R: FillRandom>(
    ports: &P,
    cache: &RootCache,
    rng: R,
    unit: &UnitName,
    seqs: Seqs,
) -> Option<Vec<Page>> {
    let root = Root::new(ports, cache, rng);
    let client = root.unit_client(unit, true).ok()?;
    let (_, pages) = client.renew_in_background(seqs).await?;
    Some(pages)
}
