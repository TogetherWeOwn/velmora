//! NNTP port over a borrowed authenticated client or existing bounded broker.
//! No account selection, dialing, pool or repair process is installed here.

use super::*;
use crate::{nntp::NntpClient, transport::Transport};

#[cfg(test)]
mod tests;

/// Trusted product authority must bind each Message-ID to the target's trusted manifest.
/// Part revocation must wake target Read cancellation with Denied, even if target authorization remains valid.
pub trait ReadControl: Control {
    fn check_part(&self, target: &Target, message_id: &str) -> Result<()>;
}

/// Does not dial or release a pool slot. Construct only after existing guarded
/// authentication and resource admission; the caller retains close authority.
/// STAT replies are subject to the transport's per-line limit.
///
/// On interruption this adapter synchronously invalidates the client and returns
/// without awaiting cleanup. The caller owns any later `shutdown_unusable`
/// attempt and its separate bounded cleanup budget; no background task is spawned.
/// Invalidation is not physical-close proof (a successful shutdown may be only a
/// write-half shutdown of a socket this borrowed client still owns): retain
/// the pool lease/account charge until physical closure is independently
/// confirmed, even after successful shutdown or client/transport destruction.
/// Destruction may only request asynchronous close. For Worker pinned TLS,
/// retain the external `WorkerSocketControl` and charge until its `close`
/// succeeds; transport drop alone does not confirm closure.
pub struct ClientIo<'a, T: Transport> {
    client: &'a mut NntpClient<T>,
    account: &'a Id,
}

impl<'a, T: Transport> ClientIo<'a, T> {
    /// The caller attests that this client is authenticated for `account`.
    pub fn new(client: &'a mut NntpClient<T>, account: &'a Id) -> Self {
        Self { client, account }
    }

    /// Dropping an in-flight request poisons the session; it proves neither
    /// rollback nor physical closure.
    pub async fn stat(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl ReadControl,
    ) -> Result<()> {
        if target.backend != Backend::Nntp || &target.account != self.account {
            return Err(Failure::Denied);
        }
        control.check(target, Action::Read)?;
        if !crate::segment_identity::valid_segment_id(message_id) {
            return Err(Failure::Invalid);
        }
        control.check_part(target, message_id)?;
        let result = supervised(self.client.stat(message_id), target, Action::Read, control).await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                self.client.invalidate();
                control.check(target, Action::Read)?;
                control.check_part(target, message_id)?;
                return Err(read_error(error));
            }
            Err(error) => {
                self.client.invalidate();
                return Err(error);
            }
        }
        control.check(target, Action::Read)?;
        control.check_part(target, message_id)
    }
}

fn read_error(error: crate::Error) -> Failure {
    match error {
        crate::Error::ArticleNotFound(_) => Failure::Missing,
        crate::Error::AuthFailed(_) | crate::Error::NoPermission(_) => Failure::Denied,
        crate::Error::Io(ref error)
            if crate::transport::is_article_limit_error(error)
                || crate::transport::is_line_limit_error(error) =>
        {
            Failure::Limit
        }
        crate::Error::Io(_) => Failure::Transient,
        crate::Error::Bounds { .. } => Failure::Limit,
        crate::Error::NntpReply {
            code: 400..=499, ..
        } => Failure::Transient,
        _ => Failure::Integrity,
    }
}
