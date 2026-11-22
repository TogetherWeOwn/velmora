//! Adapters from the composition root to the control-chain finishers.

use std::ops::AsyncFn;

use velmora::rng::FillRandom;

use crate::crypto::scheme2::TenantId;
use crate::directory::finish::{TenantUnits, UnitHolds};
use crate::directory::keys::{DirectoryKeys, UnboundDirectory};
use crate::keys::ports::{Applied, ApplyEntry, KeyTarget};
use crate::keys::record::TkRing;
use crate::ports::{Kek, Sql};
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};
use crate::unit::UnitName;
use crate::unit_lease::client::Synced;

use super::{Root, RootPorts, UnitPorts};

struct RootTenantUnits<'r, 'a, P: UnitPorts, R, B> {
    root: &'r Root<'a, P, R>,
    mark_born: B,
}

impl<P, R, B> TenantUnits for RootTenantUnits<'_, '_, P, R, B>
where
    P: UnitPorts,
    R: FillRandom,
    B: AsyncFn(&TenantId, u32) -> Result<()>,
{
    async fn bring_up(&self, tenant: &TenantId, unit: u32) -> Result<UnitHolds> {
        let id = crate::unit::TenantId::parse(tenant.as_str())
            .ok_or(BridgeError::Invalid("tenant finisher: invalid unit tenant"))?;
        let name = UnitName::new(id, unit);
        let client = self.root.unit_client(&name, false)?;
        let Some(seen) = client.unit_seqs().await? else {
            return Ok(UnitHolds::Unborn);
        };
        match client.sync(seen).await? {
            Synced::Synced { seqs } | Synced::LiftPending { seqs } => Ok(UnitHolds::Seq {
                state_seq: seqs.state_seq,
            }),
            Synced::Unborn => Ok(UnitHolds::Unborn),
            Synced::NotListed => Err(BridgeError::Invalid("tenant finisher: unit not listed")),
        }
    }

    async fn held(&self, tenant: &TenantId, unit: u32) -> Result<UnitHolds> {
        let id = crate::unit::TenantId::parse(tenant.as_str())
            .ok_or(BridgeError::Invalid("tenant finisher: invalid unit tenant"))?;
        let name = UnitName::new(id, unit);
        let client = self.root.unit_client(&name, false)?;
        let seqs = client
            .unit_seqs()
            .await?
            .ok_or(BridgeError::Invalid("tenant finisher: unit is unborn"))?;
        Ok(UnitHolds::Seq {
            state_seq: seqs.state_seq,
        })
    }

    async fn mark_born(&self, tenant: &TenantId, unit: u32) -> Result<()> {
        (self.mark_born)(tenant, unit).await
    }
}

impl<'a, P: UnitPorts, R: FillRandom> Root<'a, P, R> {
    /// The tenant finisher's unit port. `mark_born` is the caller's
    /// idempotent born-marker writer, supplied by the provisioning path.
    pub fn tenant_units<B>(&self, mark_born: B) -> impl TenantUnits + use<'_, 'a, P, R, B>
    where
        B: AsyncFn(&TenantId, u32) -> Result<()>,
    {
        RootTenantUnits {
            root: self,
            mark_born,
        }
    }
}

// Keep the unbound target explicit: a missing row in a bound directory is
// still a refusal. Only the lack of a binding acknowledges everything.
enum RootDirectoryKeys<'a, D> {
    Bound { dir: D, tenant: &'a TenantId },
    Unbound(UnboundDirectory),
}

impl<Q: Sql, S: RecordStore, K: Kek, T: TkRing> KeyTarget
    for RootDirectoryKeys<'_, DirectoryKeys<'_, Q, S, K, T>>
{
    fn label(&self) -> &str {
        match self {
            Self::Bound { dir, .. } => dir.label(),
            Self::Unbound(dir) => dir.label(),
        }
    }

    async fn keys_seq(&self) -> Result<u64> {
        match self {
            Self::Bound { dir, .. } => dir.keys_seq().await,
            Self::Unbound(dir) => dir.keys_seq().await,
        }
    }

    async fn closed(&self) -> Result<Vec<String>> {
        match self {
            Self::Bound { dir, .. } => dir.closed().await,
            Self::Unbound(dir) => dir.closed().await,
        }
    }

    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        match self {
            Self::Bound { dir, tenant } => {
                let result = dir.apply(from_seq, entries).await;
                for code in dir.take_pages() {
                    crate::trace::alert(|| format!("key finisher ({code}) tenant={tenant}"));
                }
                result
            }
            Self::Unbound(dir) => dir.apply(from_seq, entries).await,
        }
    }
}

impl<P: RootPorts, R: FillRandom> Root<'_, P, R> {
    /// The per-tenant target for `KeyEnv.directory`, separate from the
    /// unit targets. The caller passes the same ring as `KeyEnv.ring`.
    pub fn directory_key_target<'r, T: TkRing>(
        &'r self,
        tenant: &'r TenantId,
        ring: &'r T,
    ) -> impl KeyTarget + 'r {
        match self.directory() {
            Some(dir) => RootDirectoryKeys::Bound {
                dir: DirectoryKeys::new(dir, tenant, self.records(), self.kek(), ring),
                tenant,
            },
            None => RootDirectoryKeys::Unbound(UnboundDirectory),
        }
    }
}
