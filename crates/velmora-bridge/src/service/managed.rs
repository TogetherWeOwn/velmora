//! A managed tenant's S3 request on its unit (lane L6, package L6-6;
//! tenancy ADR §2.7, AM-64): the steps before and after
//! `Bridge::handle`, which serves the request over the request catalogue
//! (`crate::request_catalog`) with tenant 0's handler code.
//!
//! **Order (AM-64).** The key id routes to its tenant (the Worker, before
//! this). Then [`prepare`]:
//! 1. the host, a route this endpoint does not serve and the admin plane
//!    are answered from the request alone;
//! 2. the root unit is routed (`route(tenant, None)`), and its `key_row`
//!    for the claimed key is read: an unauthenticated read, allowed under
//!    `MAINTENANCE=restore`. When it cannot be read (no head, the unit
//!    closed, unborn or unreachable) the request answers `503` before its
//!    signature is checked, as tenant 0 does in a D1 outage;
//! 3. the unit of the request's bucket is routed. A refusal here is kept,
//!    not answered: it comes after the signature, as the first call's.
//!
//! Then `Bridge::handle` checks the signature against the `key_row`'s
//! secret, applies the tenant's state (`403 AccountProblem`), and only
//! then reads the bucket and the grant and runs the handler. Its own
//! gates answer the maintenance `503` for a write, before any write call;
//! the router refuses a write call under `restore` as well.
//!
//! [`finish`] then discards the recovery records of publications the unit
//! refused before running them, and turns a unit's refusal into the
//! request's answer when the handler failed on it (the table in
//! `docs/units.md`, "Requests").

use velmora_s3_proto::ErrorCode;

use super::common::{self, s3_error, unit_refused};
use super::{classify, ManagedLine, Route};
use crate::config::BridgeConfig;
use crate::ports::BlobStore;
use crate::recovery::discard_generation;
use crate::request_catalog::KeyRow;
use crate::tenant::TenantScope;
use crate::tenant_catalog::UnitPort;
use crate::types::{S3Request, S3Response};
use crate::unit::request::RequestRefusal;
use crate::unit::size::SizeRefusal;
use crate::unit::{CallKind, Refused, Seqs, TenantId, UnitAnswer, UnitName, UnitOp};
use crate::unit_consumer::page_code;
use crate::unit_lease::client::Page;
use crate::unit_router::{RouteRefusal, Routed, UnitRouter};

const fn line(code: &'static str, alert: bool) -> ManagedLine {
    ManagedLine { code, alert }
}

/// What [`prepare`] found: the request to serve, or its answer.
pub enum Prepared {
    /// Serve it over the request catalogue.
    Serve(ManagedRequest),
    /// Answered here, with its log line, and the lines of the unit
    /// client's pages.
    Answer(S3Response, Vec<ManagedLine>),
}

/// A managed tenant's request ready for `Bridge::handle`.
pub struct ManagedRequest {
    /// The tenant's scope: the request catalogue names its blobs through
    /// it. Made here, the one maker of a managed scope on the request
    /// path.
    pub scope: TenantScope,
    /// The root unit, which answered the `key_row`.
    pub root: Routed,
    /// The `key_row`'s answer asked for a background renewal of the root
    /// unit (rule 12): its numbers.
    pub root_renew: Option<Seqs>,
    /// The unit of the request's bucket (the root unit with none), or the
    /// router's refusal, which the first call after the signature answers.
    pub routed: std::result::Result<Routed, RouteRefusal>,
    /// The root unit's `key_row` for the claimed key.
    pub key_row: KeyRow,
    /// The unit client's pages so far (alerts).
    pub lines: Vec<ManagedLine>,
}

/// The steps before `Bridge::handle` (see the [module](self)).
/// `access_key_id` is the key the request claims, which routed it to
/// `tenant`; `floor` the route's numbers.
pub async fn prepare<R: UnitRouter>(
    router: &R,
    cfg: &BridgeConfig,
    tenant: &TenantId,
    floor: Seqs,
    access_key_id: &str,
    req: &S3Request,
) -> Prepared {
    let answer = |resp, l: ManagedLine, mut lines: Vec<ManagedLine>| {
        lines.insert(0, l);
        Prepared::Answer(resp, lines)
    };
    // The host first, as on tenant 0's path: on a virtual-hosted request
    // the path's first segment is a key, never a bucket to route by.
    if let Some(resp) = common::request_host_refused(cfg, req) {
        return answer(resp, line("host_refused", false), Vec::new());
    }
    let route = classify(&req.method, &req.raw_target);
    match route {
        Route::NotImplemented => {
            return answer(
                S3Response::not_implemented(),
                line("not_implemented", false),
                Vec::new(),
            )
        }
        // The admin plane takes its bearer, never an access key.
        Route::Admin { .. } => {
            return answer(
                s3_error(ErrorCode::AccessDenied),
                line("admin_with_key", false),
                Vec::new(),
            )
        }
        _ => {}
    }
    // Tenant 0 is never routed here (its keys keep tenant 0's path).
    let Some(scope) = TenantScope::managed(tenant) else {
        return answer(
            unit_refused(),
            line("not_a_managed_tenant", true),
            Vec::new(),
        );
    };
    // Before the signature every refusal is `503`: a `403 AccountProblem`
    // here would tell a caller who knows only a key id that its tenant is
    // being shredded (ADR §2.8: after the signature verifies).
    let root = match router.route(tenant, None, floor).await {
        Ok(root) => root,
        Err(refusal) => {
            return answer(
                unit_refused(),
                line(refusal.code(), refusal.alert()),
                Vec::new(),
            )
        }
    };
    let op = UnitOp::KeyRow {
        access_key_id: access_key_id.to_owned(),
        presigned: None,
    };
    let (answered, pages) = router.call(&root, CallKind::Request, false, op).await;
    let lines = page_lines(&pages);
    let answered = match answered {
        Ok(answered) => answered,
        Err(refusal) => {
            return answer(unit_refused(), line(refusal.code(), refusal.alert()), lines)
        }
    };
    let root_renew = match (&answered.reply.answer, answered.renew_due) {
        (UnitAnswer::Ok { seqs, .. }, true) => Some(*seqs),
        _ => None,
    };
    let key_row = match &answered.reply.answer {
        UnitAnswer::Ok { body, .. } => KeyRow::from_body(body, access_key_id),
        _ => Err(crate::request_catalog::ERR_KEY_ROW),
    };
    let Ok(key_row) = key_row else {
        return answer(unit_refused(), line("key_row_refused", true), lines);
    };
    let routed = match route.bucket() {
        None => Ok(root.clone()),
        Some(bucket) => router.route(tenant, Some(bucket), floor).await,
    };
    Prepared::Serve(ManagedRequest {
        scope,
        root,
        root_renew,
        routed,
        key_row,
        lines,
    })
}

/// The request port's state after the handler ran: what [`finish`]
/// reads (`root::request::RequestPort`).
pub trait PortState: UnitPort {
    /// The first router refusal of a call of this request.
    fn route_refusal(&self) -> Option<RouteRefusal>;
    /// The unit client's pages of this request's calls so far. Pages of
    /// calls after this (a streamed body's reads, a deferred delete's
    /// work) are logged by the port itself as alerts.
    fn take_pages(&self) -> Vec<Page>;
    /// A call's answer asked for a background renewal (rule 12): the unit
    /// and the numbers it answered.
    fn renew_due(&self) -> Option<(UnitName, Seqs)>;
}

/// What became of a managed tenant's request.
pub struct Finished {
    pub resp: S3Response,
    /// The first is the request's; the others are pages and alerts.
    pub lines: Vec<ManagedLine>,
    /// Renew this unit in the background, from these numbers (rule 12).
    pub renew: Option<(UnitName, Seqs)>,
}

/// The steps after `Bridge::handle` (see the [module](self)). `unit`'s
/// refusal (the request client's first answer that was not `ok` or
/// `failed`) and the port's router refusal decide the answer only when the
/// handler failed (`5xx`): a best-effort call that a unit refused (a cache
/// fill, a read's touch) does not undo an answer the handler made.
pub async fn finish<P: PortState, B: BlobStore>(
    client: &crate::unit::request_client::RequestClient<P>,
    safety: &B,
    resp: S3Response,
) -> Finished {
    let mut lines = Vec::new();
    // Nothing was written under these ids: the unit refused them before
    // running them.
    for refused in client.take_unpublished() {
        if discard_generation(safety, &refused).await.is_err() {
            lines.push(line("unpublished_record_kept", true));
        }
    }
    let port = client.port();
    lines.extend(page_lines(&port.take_pages()));
    let renew = port.renew_due();
    let failed = resp.status >= 500;
    let (resp, first) = match (port.route_refusal(), client.refusal()) {
        (Some(refusal), _) => {
            let l = line(refusal.code(), refusal.alert());
            match failed {
                true => (refused(refusal), l),
                false => (resp, l),
            }
        }
        (None, Some(answer)) => {
            let (mapped, l) = unit_answer(&answer);
            match failed {
                true => (mapped, l),
                false => (resp, l),
            }
        }
        (None, None) => (resp, line("served", false)),
    };
    lines.insert(0, first);
    Finished { resp, lines, renew }
}

/// A router refusal after the signature, as the request's answer: `503`
/// with `Retry-After`, but `403 AccountProblem` for a shredding tenant.
fn refused(refusal: RouteRefusal) -> S3Response {
    match refusal {
        RouteRefusal::AccountProblem => common::account_problem(),
        _ => unit_refused(),
    }
}

/// A unit's refusal of a request call as the request's answer
/// (`docs/units.md`, "Requests").
fn unit_answer(answer: &UnitAnswer) -> (S3Response, ManagedLine) {
    match answer {
        UnitAnswer::Closed { .. } => (unit_refused(), line("closed", false)),
        UnitAnswer::Unborn { .. } => (unit_refused(), line("unborn", true)),
        UnitAnswer::Refused { reason, .. } => match reason {
            Refused::AccountProblem => (common::account_problem(), line("account_problem", false)),
            Refused::NotFound => (s3_error(ErrorCode::NoSuchBucket), line("not_found", false)),
            Refused::Size(SizeRefusal::DatabaseFull) => {
                (s3_error(ErrorCode::SlowDown), line("unit_full", true))
            }
            // ADR §2.6: at the unit's guard the answer is `503 SlowDown`
            // and the operator is paged (a bucket can be moved out);
            // `403 QuotaExceeded` for one bucket alone filling a unit
            // waits on the owner's decision.
            Refused::Size(SizeRefusal::TooManyExtents) => (
                s3_error(ErrorCode::SlowDown),
                line("unit_extents_full", true),
            ),
            Refused::Request(RequestRefusal::OutOfBounds) => {
                (common::internal(), line("request_out_of_bounds", true))
            }
            _ => (common::internal(), line("unit_refused", true)),
        },
        _ => (unit_refused(), line("unit_answer", true)),
    }
}

fn page_lines(pages: &[Page]) -> Vec<ManagedLine> {
    pages.iter().map(|p| line(page_code(p), true)).collect()
}
