//! Revocations: `m/rk/<t>/<akid>` for a managed tenant, `m/rk/<akid>`
//! for tenant 0.
//!
//! A revocation is put once, after the intent and before the chain
//! record, and **overrides every `m/k/` status, whatever the order or
//! the seq**. It is read by its name alone. A managed tenant's names are
//! its subjects' ids: an access key id, or a principal's plane id
//! (`p_` and 16 hex digits, [`is_principal_id`]). Tenant 0's are access
//! key ids only.
//!
//! Tenant 0's revocations sit directly under `m/rk/`, beside the
//! directories of the managed tenants. Every listing of tenant 0's
//! revocations therefore uses [`list_tenant_zero_revocations`], which
//! returns names directly under the prefix and nothing below a `/`, as
//! a listing with the delimiter `/` does. It
//! skips each tenant directory with one list call: an access key id has
//! no `_`, so no tenant-0 name begins with `t_`, and `<dir>0` sorts after
//! every name below `<dir>/`. That is one list call per tenant; an
//! adapter whose store lists with a delimiter should do this in one.

use serde::{Deserialize, Serialize};
use velmora::rng::FillRandom;

use super::record::is_principal_id;
use crate::crypto::scheme2::{parse_control, seal_control, ControlOwner, ControlSealer, TenantId};
use crate::ports::{BlobStore, Kek};
use crate::records::RecordStore;
use crate::recovery::{revoked_key_id, valid_key_id, REVOKED_KEY_PREFIX};
use crate::types::{BridgeError, Result};

/// Names per list call.
pub const REVOCATION_PAGE: u32 = 1000;

const ERR_REVOCATION: BridgeError = BridgeError::Invalid("revocation record is malformed");

/// Whether `id` may name a managed tenant's revocation: an access key id
/// or a principal's plane id.
pub fn revocable_id(id: &str) -> bool {
    valid_key_id(id) || is_principal_id(id)
}

/// The directory of `tenant`'s revocations.
pub fn tenant_revocation_prefix(tenant: &TenantId) -> String {
    format!("{REVOKED_KEY_PREFIX}{tenant}/")
}

/// The revocation of `akid` of `tenant`.
pub fn tenant_revocation_name(tenant: &TenantId, akid: &str) -> String {
    format!("{}{akid}", tenant_revocation_prefix(tenant))
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RevocationBody {
    v: u32,
    tenant: String,
    access_key_id: String,
    revoked_at: u64,
}

/// Puts the revocation of `akid`. A revocation that is already stored
/// is kept as it is: revoking twice changes nothing.
pub async fn put_tenant_revocation<S: RecordStore, K: Kek, R: FillRandom>(
    store: &S,
    kek: &K,
    tenant: &TenantId,
    akid: &str,
    at: u64,
    rng: &mut R,
) -> Result<()> {
    if !revocable_id(akid) {
        return Err(ERR_REVOCATION);
    }
    let name = tenant_revocation_name(tenant, akid);
    let body = serde_json::to_vec(&RevocationBody {
        v: 1,
        tenant: tenant.as_str().to_owned(),
        access_key_id: akid.to_owned(),
        revoked_at: at,
    })
    .map_err(|_| ERR_REVOCATION)?;
    // Door part only: a revocation must be writable without the tenant
    // key. The name binds the tenant.
    let sealed = seal_control(kek, &name, &ControlSealer::Global, &body, None, rng)?;
    match store.put_if_absent(&name, sealed).await {
        Ok(_) => Ok(()),
        // An answer that was lost: the name decides, not the bytes.
        Err(e) => match store.exists(&name).await? {
            true => Ok(()),
            false => Err(e),
        },
    }
}

/// When a revocation was written, read from its record; `None` when
/// there is none. Proves the record with the control key.
pub async fn read_tenant_revocation<S: RecordStore, K: Kek>(
    store: &S,
    kek: &K,
    tenant: &TenantId,
    akid: &str,
) -> Result<Option<u64>> {
    let name = tenant_revocation_name(tenant, akid);
    let Some(bytes) = store.get(&name).await? else {
        return Ok(None);
    };
    let opened = parse_control(&bytes)?.open_door(kek, &name, ControlOwner::Global)?;
    let body: RevocationBody = serde_json::from_slice(opened.door()).map_err(|_| ERR_REVOCATION)?;
    if body.tenant != tenant.as_str() || body.access_key_id != akid {
        return Err(ERR_REVOCATION);
    }
    Ok(Some(body.revoked_at))
}

/// Every subject id with a revocation for `tenant`, by name. A name below
/// the prefix that is no subject id ([`revocable_id`]) is skipped: it
/// cannot name a subject.
pub async fn list_tenant_revocations<S: RecordStore>(
    store: &S,
    tenant: &TenantId,
) -> Result<Vec<String>> {
    let prefix = tenant_revocation_prefix(tenant);
    let mut after = prefix.clone();
    let mut ids = Vec::new();
    loop {
        let names = store.list(&prefix, &after, REVOCATION_PAGE).await?;
        ids.extend(
            names
                .iter()
                .filter_map(|n| n.strip_prefix(&prefix))
                .filter(|id| revocable_id(id))
                .map(str::to_owned),
        );
        match names.last() {
            Some(last) if names.len() >= REVOCATION_PAGE as usize => after.clone_from(last),
            _ => return Ok(ids),
        }
    }
}

/// One page of tenant 0's revocations: the access key ids directly under
/// `m/rk/`, after the name `after` (`m/rk/` for the first page), with the
/// name to continue from, or `None` at the end. Never an id of another
/// tenant, however many there are.
pub async fn list_tenant_zero_revocations<B: BlobStore>(
    store: &B,
    after: &str,
    limit: u32,
) -> Result<(Vec<String>, Option<String>)> {
    let limit = limit.max(1);
    let mut after = after.to_owned();
    let mut ids = Vec::new();
    loop {
        let names = store.list(REVOKED_KEY_PREFIX, &after, limit).await?;
        if names.is_empty() {
            return Ok((ids, None));
        }
        let full = names.len() >= limit as usize;
        let mut jumped = false;
        for name in &names {
            let rest = name.strip_prefix(REVOKED_KEY_PREFIX).unwrap_or_default();
            // Below a tenant's directory: skip the whole directory with
            // the next list. `<dir>0` cannot be a key id (a tenant id has
            // a `_`), so nothing of tenant 0 is skipped. `after` only ever
            // grows, so the loop ends.
            if let Some((dir, _)) = rest.split_once('/') {
                if TenantId::parse(dir).is_ok() {
                    after = format!("{REVOKED_KEY_PREFIX}{dir}0");
                    jumped = true;
                    break;
                }
                // A stray name below something else: no key id; step over
                // it alone.
                after.clone_from(name);
                continue;
            }
            if let Some(id) = revoked_key_id(name) {
                ids.push(id.to_owned());
            }
            after.clone_from(name);
            if ids.len() >= limit as usize {
                return Ok((ids, Some(after)));
            }
        }
        if !full && !jumped {
            return Ok((ids, None));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_skip_lands_after_every_name_below_it() {
        let dir = "m/rk/t_00000000000000a1";
        let skip = format!("{dir}0");
        assert!(format!("{dir}/ZZZZZZZZ").as_str() < skip.as_str());
        assert!(format!("{dir}/zzzzzzzz").as_str() < skip.as_str());
        // A tenant-0 name never starts with `t_`: an id has no `_`.
        assert!(!valid_key_id("t_00000000000000a1"));
    }
}
