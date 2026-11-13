//! Permit-scoped provider sessions: every NNTP path holds a provider
//! connection slot before it opens a socket ("no permit, no socket").

use crate::ports::{Catalog, Clock, NntpConnector, NntpSession, Permit, PermitClass};
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

    /// Extends the permit. `false` = the slot now belongs to someone else:
    /// the socket is dropped at once and the caller must stop.
    pub(crate) async fn renew(&mut self) -> Result<bool> {
        match self
            .catalog
            .renew_permit(&self.permit, self.clock.now())
            .await
        {
            Ok(true) => Ok(true),
            other => {
                self.session = None;
                other
            }
        }
    }

    /// The live session, connecting first when there is none.
    pub(crate) async fn session(&mut self) -> Result<&mut N::Session> {
        if self.session.is_none() {
            self.session = Some(self.nntp.connect(self.provider, &self.permit).await?);
        }
        self.session
            .as_mut()
            .ok_or(BridgeError::Invalid("nntp session"))
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
