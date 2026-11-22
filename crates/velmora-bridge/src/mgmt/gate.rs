//! What every management call passes before its handler runs.
//!
//! In this order, each step answering before the next is tried:
//!
//! 1. **The path is a call** ([`route`]): `404` or `405`. A path that
//!    names tenant 0 is not one.
//! 2. **The list of disabled tokens is fresh.** Listed now if it is due
//!    ([`DisabledTokens::begin`]); with no good list, or one older than
//!    the bound, `503` with `Retry-After`. While the door is shut a
//!    listing is due again after a few seconds, so that a failed or hung
//!    listing does not keep an isolate shut for a minute.
//! 3. **The token is one of a class, and not disabled** ([`authenticate`]):
//!    `401`.
//! 4. **The class carries the call's least scope** ([`Call::scope`]):
//!    `403`. A handler that reads more from the body asks for the wider
//!    scope itself ([`Admitted::require`]).
//!
//! The isolate's [`DisabledTokens`] is held in a `RefCell` and never
//! borrowed across the listing, which is the only await.

use std::cell::RefCell;

use crate::mgmt::route::{route, Call, NoCall};
use crate::mgmt::token::{
    authenticate, list_disabled, Actor, DisabledTokens, Listing, Refused, Scope, TokenHashes,
    TokenId,
};
use crate::ports::BlobStore;
use crate::types::{Result as BridgeResult, UnixMs};
use std::collections::BTreeSet;

/// Seconds a `503` asks the caller to wait: a listing is due again by
/// then.
pub const RETRY_AFTER_SECS: u32 = 5;

/// A call that passed the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub actor: Actor,
    pub call: Call,
}

impl Admitted {
    /// `Ok` when the actor's class also carries `scope`: for a handler
    /// whose body asks for more than the call's least scope.
    pub fn require(&self, scope: Scope) -> Result<(), Shut> {
        self.actor.may(scope).map_err(Shut::Refused)
    }
}

/// Why the gate shut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shut {
    NoCall(NoCall),
    Refused(Refused),
}

impl Shut {
    pub fn status(self) -> u16 {
        match self {
            Shut::NoCall(n) => n.status(),
            Shut::Refused(r) => r.status(),
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Shut::NoCall(n) => n.code(),
            Shut::Refused(r) => r.code(),
        }
    }

    /// `Retry-After` for the answer, in seconds, where it has one.
    pub fn retry_after(self) -> Option<u32> {
        matches!(self, Shut::Refused(Refused::Unavailable)).then_some(RETRY_AFTER_SECS)
    }
}

/// Runs the gate for one request. `records` is the store that holds
/// `m/rst/`; `authorization` is the `Authorization` header, if any.
pub async fn admit<B: BlobStore>(
    disabled: &RefCell<DisabledTokens>,
    hashes: &TokenHashes,
    records: &B,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    now: UnixMs,
) -> Result<Admitted, Shut> {
    let call = route(method, path).map_err(Shut::NoCall)?;
    let listing = disabled.borrow_mut().begin(now);
    if let Some(listing) = listing {
        // Should this request go away during the listing, the ticket is
        // given back, so that the next call lists at once.
        let guard = Abandon {
            disabled,
            listing: Some(listing),
        };
        let listed = list_disabled(records).await;
        guard.finish(listed);
    }
    let actor =
        authenticate(hashes, &disabled.borrow(), authorization, now).map_err(Shut::Refused)?;
    actor.may(call.scope()).map_err(Shut::Refused)?;
    Ok(Admitted { actor, call })
}

/// Gives a listing's ticket back if it is dropped before [`Abandon::finish`].
struct Abandon<'a> {
    disabled: &'a RefCell<DisabledTokens>,
    listing: Option<Listing>,
}

impl Abandon<'_> {
    fn finish(mut self, listed: BridgeResult<BTreeSet<TokenId>>) {
        if let Some(listing) = self.listing.take() {
            self.disabled.borrow_mut().record(listing, listed);
        }
    }
}

impl Drop for Abandon<'_> {
    fn drop(&mut self) {
        if let Some(listing) = self.listing.take() {
            self.disabled.borrow_mut().abandon(listing);
        }
    }
}
