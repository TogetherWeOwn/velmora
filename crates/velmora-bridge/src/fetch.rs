//! Permit-scoped provider sessions: every NNTP path holds a provider
//! connection slot before it opens a socket ("no permit, no socket").

use crate::ports::{Catalog, Clock, Lease, NntpConnector, NntpSession, Permit, PermitClass};
use crate::post::Stop;
use crate::types::{BridgeError, ProviderConfig, Result};

/// One provider connection slot and the session opened under it.
///
/// The session connects lazily and is replaced after [`Self::discard`], so
/// a caller reconnects by discarding and asking for the session again; the
/// slot stays the same, so reconnects never add a connection. Call
/// [`Self::close`] on every exit path: there is no async drop. If the job
/// dies first, the slot frees itself when the permit expires.
pub(crate) struct ProviderSession<'a, C: Catalog, N: NntpConnector, T: Clock> {
    catalog: &'a C,
    nntp: &'a N,
    clock: &'a T,
    pub(crate) provider: &'a ProviderConfig,
    permit: Permit,
    session: Option<N::Session>,
}

impl<'a, C: Catalog, N: NntpConnector, T: Clock> ProviderSession<'a, C, N, T> {
    /// Takes a slot for `provider`. `None` = every slot of this class is
    /// held: the caller backs off without opening a socket.
    pub(crate) async fn open(
        catalog: &'a C,
        nntp: &'a N,
        clock: &'a T,
        provider: &'a ProviderConfig,
        class: PermitClass,
        holder: &str,
    ) -> Result<Option<Self>> {
        let permit = catalog
            .acquire_permit(provider, class, holder, clock.now())
            .await?;
        Ok(permit.map(|permit| ProviderSession {
            catalog,
            nntp,
            clock,
            provider,
            permit,
            session: None,
        }))
    }

    /// Renews the job's lease (if it has one) and then the permit. Call it
    /// before every article and before every reconnect: no POST, read or
    /// new socket happens on a lease or a slot that now belongs to someone
    /// else. On a lost permit the socket is dropped at once.
    pub(crate) async fn keep(&mut self, lease: Option<&Lease>) -> core::result::Result<(), Stop> {
        let now = self.clock.now();
        if let Some(lease) = lease {
            if !self.catalog.renew(lease, now).await? {
                return Err(Stop::Fenced);
            }
        }
        match self.catalog.renew_permit(&self.permit, now).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.session = None;
                Err(Stop::NoPermit)
            }
            Err(e) => {
                self.session = None;
                Err(e.into())
            }
        }
    }

    /// The live session, connecting first when there is none. A provider
    /// that refuses the connection with `502` ("too many connections") is
    /// reported as "no slot".
    pub(crate) async fn session(&mut self) -> core::result::Result<&mut N::Session, Stop> {
        if self.session.is_none() {
            let session = match self.nntp.connect(self.provider, &self.permit).await {
                Ok(session) => session,
                Err(BridgeError::Nntp(velmora::Error::NoPermission(_))) => {
                    return Err(Stop::NoPermit);
                }
                Err(e) => return Err(Stop::Session(e)),
            };
            self.session = Some(session);
        }
        self.session
            .as_mut()
            .ok_or(Stop::fail(crate::types::FailClass::Internal))
    }

    /// Drops the session without reuse or `QUIT` (after any session error).
    pub(crate) fn discard(&mut self) {
        self.session = None;
    }

    /// Ends the session and frees the slot. The release is fenced by the
    /// permit token, so a holder that lost its slot frees nothing.
    pub(crate) async fn close(mut self) {
        if let Some(session) = self.session.take() {
            session.quit().await;
        }
        // A failed release is safe: the permit expires on its own.
        let _ = self.catalog.release_permit(&self.permit).await;
    }
}
