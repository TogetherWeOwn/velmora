//! NNTP port over a borrowed authenticated client or existing bounded broker.
//! No account selection, dialing, pool or repair process is installed here.

use super::*;
use crate::{nntp::NntpClient, transport::Transport};

#[cfg(test)]
mod tests;

/// The product owns journaling, admission, leases and physical close. In-flight
/// operations remain charged until closure/settlement is proven. POST I/O failures
/// are uncertain; absence after STAT never settles an in-flight POST.
///
/// Any in-flight operation future may be dropped by an outer supervisor —
/// including a proof `body` dropped when the enclosing Write action is
/// revoked mid-readback. Dropping must poison the session (no later command
/// may reuse it or consume the abandoned reply); it is never physical-close
/// or rollback evidence.
#[allow(async_fn_in_trait)]
pub trait Io {
    async fn post(
        &mut self,
        target: &Target,
        message_id: &str,
        article: &[u8],
        control: &impl Control,
    ) -> Result<()>;
    async fn body(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl Control,
    ) -> Result<Vec<u8>>;
    async fn stat(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl Control,
    ) -> Result<()>;

    /// Effective cap, in bytes, on one encoded BODY this `Io` can read back.
    /// The provider rejects an encoded body above this bound *before* the
    /// irreversible POST, so a same-configuration write can never strand an
    /// object its own readback must refuse. `None` declares no bound tighter
    /// than the contract maximum; an implementation with a tighter receive
    /// cap MUST report it here.
    fn max_encoded_body_bytes(&self) -> Option<usize> {
        None
    }
}

/// Does not dial or release a pool slot. Construct only after existing guarded
/// authentication and resource admission; the caller retains close authority.
/// The client's configured article cap remains enforced (hard maximum 64 MiB),
/// including as the pre-POST encoded-body admission bound.
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
    pub client: &'a mut NntpClient<T>,
}

fn read_error(error: crate::Error) -> Failure {
    match error {
        crate::Error::ArticleNotFound(_) => Failure::Missing,
        crate::Error::AuthFailed(_) | crate::Error::NoPermission(_) => Failure::Denied,
        crate::Error::Io(ref error) if crate::transport::is_article_limit_error(error) => {
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

impl<T: Transport> Io for ClientIo<'_, T> {
    async fn post(
        &mut self,
        target: &Target,
        message_id: &str,
        article: &[u8],
        control: &impl Control,
    ) -> Result<()> {
        control.check(target, Action::Write)?;
        let result = supervised(
            self.client.post_article(message_id, article),
            target,
            Action::Write,
            control,
        )
        .await;
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                self.client.invalidate();
                return Err(Failure::Uncertain);
            }
        };
        result.map_err(|error| match error {
            crate::Error::AuthFailed(_)
            | crate::Error::NoPermission(_)
            | crate::Error::PostProhibited(_) => Failure::Denied,
            _ => Failure::Uncertain,
        })?;
        control
            .check(target, Action::Write)
            .map_err(|_| Failure::Uncertain)
    }

    async fn body(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl Control,
    ) -> Result<Vec<u8>> {
        control.check(target, Action::Read)?;
        let mut out = Vec::new();
        let result = supervised(
            self.client.body_to(message_id, &mut out),
            target,
            Action::Read,
            control,
        )
        .await;
        match result {
            Ok(result) => result.map_err(read_error)?,
            Err(error) => {
                self.client.invalidate();
                return Err(error);
            }
        }
        control.check(target, Action::Read)?;
        Ok(out)
    }

    async fn stat(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl Control,
    ) -> Result<()> {
        control.check(target, Action::Read)?;
        let result = supervised(self.client.stat(message_id), target, Action::Read, control).await;
        match result {
            Ok(result) => {
                result.map_err(read_error)?;
            }
            Err(error) => {
                self.client.invalidate();
                return Err(error);
            }
        }
        control.check(target, Action::Read)
    }

    fn max_encoded_body_bytes(&self) -> Option<usize> {
        Some(self.client.max_article_bytes())
    }
}
