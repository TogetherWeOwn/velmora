//! An offline escrow copy of one tenant key, and its restore.
//!
//! The copy is the key blob exactly as the arbiter holds it: the tenant
//! key wrapped under a KEK version. It opens nothing without that KEK,
//! and with the KEK it opens the tenant's data, so it is kept like the
//! KEK's own offline copy (a file of mode 0600, outside any repository).
//! It is written for one tenant on purpose, by an operator, and only
//! for a tenant whose owner chose it: a tenant with such a copy cannot
//! be fully erased unless the copy is destroyed too.
//!
//! # Format
//!
//! Seven lines of text, so that it survives being printed or copied by
//! hand:
//!
//! ```text
//! velmora tenant key escrow v1
//! tenant: t_<16 hex>
//! version: <key version>
//! kek-version: <KEK version>
//! kcv: <16 hex>
//! blob: <base64 of the 81-byte blob>
//! sha256: <hex of the six lines above, each ending in \n>
//! ```
//!
//! The last line catches a damaged copy before anyone tries the KEK on
//! it. The KEK proves the rest: [`EscrowCopy::open`] unwraps the blob
//! under the name it claims, and the key's check value must equal the
//! `kcv` line.
//!
//! # Restore
//!
//! [`restore_escrow`] puts the blob back, with put-if-absent, into every
//! active location that lacks it. It never overwrites, never deletes,
//! and refuses a tenant whose key directory holds a name that is no key
//! blob (a shred marker among them): a shredded tenant is never brought
//! back from escrow.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::locations::KeyLocations;
use super::record::{open_key_record, OneKey};
use super::tk::{list_tenant_blobs, KeyBuckets};
use crate::crypto::scheme2::{
    open_record_v2, tk_blob_check_value, tk_blob_name, unwrap_tenant_key, TenantId, TenantKey,
    KCV_LEN,
};
use crate::ports::Kek;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};

const MAGIC: &str = "velmora tenant key escrow v1";
const ERR_ESCROW: BridgeError = BridgeError::Invalid("tenant key escrow copy is malformed");
const ERR_ESCROW_KEY: BridgeError =
    BridgeError::Crypto("tenant key escrow copy does not match its key");

/// One escrow copy, parsed. Nothing in it is trusted before
/// [`EscrowCopy::open`] succeeded.
#[derive(Clone, PartialEq, Eq)]
pub struct EscrowCopy {
    pub tenant: TenantId,
    pub version: u32,
    pub kek_version: u32,
    pub kcv: [u8; KCV_LEN],
    blob: Vec<u8>,
}

impl std::fmt::Debug for EscrowCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EscrowCopy")
            .field("tenant", &self.tenant)
            .field("version", &self.version)
            .field("kek_version", &self.kek_version)
            .finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn body(tenant: &TenantId, version: u32, kek_version: u32, kcv: &[u8], blob: &[u8]) -> String {
    format!(
        "{MAGIC}\ntenant: {tenant}\nversion: {version}\nkek-version: {kek_version}\nkcv: {}\nblob: {}\n",
        hex(kcv),
        STANDARD.encode(blob)
    )
}

impl EscrowCopy {
    /// The copy of the blob stored as `m/tk/<tenant>/<version>.<kek_version>`.
    pub fn of_blob(
        tenant: &TenantId,
        version: u32,
        kek_version: u32,
        blob: &[u8],
    ) -> Result<EscrowCopy> {
        let kcv = tk_blob_check_value(blob)?;
        if version == 0 || kek_version == 0 {
            return Err(ERR_ESCROW);
        }
        Ok(EscrowCopy {
            tenant: tenant.clone(),
            version,
            kek_version,
            kcv,
            blob: blob.to_vec(),
        })
    }

    /// The name the blob is stored under in a key bucket.
    pub fn name(&self) -> String {
        tk_blob_name(&self.tenant, self.version, self.kek_version)
    }

    /// The text of the copy.
    pub fn to_text(&self) -> String {
        let body = body(
            &self.tenant,
            self.version,
            self.kek_version,
            &self.kcv,
            &self.blob,
        );
        let sum = hex(&Sha256::digest(body.as_bytes()));
        format!("{body}sha256: {sum}\n")
    }

    /// Parses a copy. Refuses any other text, a changed byte included.
    pub fn parse(text: &str) -> Result<EscrowCopy> {
        let lines: Vec<&str> = text
            .strip_suffix('\n')
            .ok_or(ERR_ESCROW)?
            .split('\n')
            .collect();
        let [magic, tenant, version, kek_version, kcv, blob, sum] = lines[..] else {
            return Err(ERR_ESCROW);
        };
        let field = |line: &'_ str, key: &str| -> Option<String> {
            line.strip_prefix(key)?
                .strip_prefix(": ")
                .map(str::to_owned)
        };
        let number = |s: Option<String>| -> Option<u32> {
            let s = s?;
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && !s.starts_with('0'))
                .then(|| s.parse().ok())
                .flatten()
        };
        let copy = (|| {
            if magic != MAGIC {
                return None;
            }
            let tenant = TenantId::parse(&field(tenant, "tenant")?).ok()?;
            let version = number(field(version, "version"))?;
            let kek_version = number(field(kek_version, "kek-version"))?;
            let kcv = unhex::<KCV_LEN>(&field(kcv, "kcv")?)?;
            let blob = STANDARD.decode(field(blob, "blob")?).ok()?;
            let sum = unhex::<32>(&field(sum, "sha256")?)?;
            let expected: [u8; 32] =
                Sha256::digest(body(&tenant, version, kek_version, &kcv, &blob).as_bytes()).into();
            (expected == sum && tk_blob_check_value(&blob).ok()? == kcv).then_some(EscrowCopy {
                tenant,
                version,
                kek_version,
                kcv,
                blob,
            })
        })();
        copy.ok_or(ERR_ESCROW)
    }

    /// Opens the copy with the KEK: proves it is the key it says it is.
    pub fn open<K: Kek>(&self, kek: &K) -> Result<TenantKey> {
        let key = unwrap_tenant_key(
            kek,
            self.kek_version,
            &self.tenant,
            self.version,
            &self.blob,
        )?;
        if key.check_value() != self.kcv {
            return Err(ERR_ESCROW_KEY);
        }
        Ok(key)
    }

    /// The blob, as a key bucket holds it.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant
    }
}

/// What a restore did in each location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreStep {
    /// The location held the key already, in a copy that opens.
    Present,
    /// A copy of the key was put back.
    Restored,
    /// The location holds another key of that version, or a copy that
    /// does not open under the KEK: nothing was written anywhere. An
    /// alarm.
    Conflict,
    /// The location holds a copy under a KEK version this Worker lacks:
    /// it could not be opened, so nothing is written to it.
    Unverified,
    /// Not written, because a location is in conflict.
    Withheld,
}

/// Puts the tenant key back into every synchronous location of `set`
/// that lacks it, from the escrow copy, after reading every active
/// location (asynchronous ones included) first:
/// - the copy must open under the KEK and hold the key whose check value
///   the tenant chain committed (`committed`);
/// - one location in conflict means nothing is written anywhere, so no
///   location ever holds a key the arbiter does not;
/// - when a location still holds the key, its newest copy is what is put
///   back, so an old KEK name is never brought back beside a newer one;
/// - a marker or a foreign name refuses the tenant before any write, and
///   one that appears during a write is an error.
pub async fn restore_escrow<S: RecordStore, K: Kek>(
    copy: &EscrowCopy,
    kek: &K,
    committed: [u8; KCV_LEN],
    set: &KeyLocations,
    buckets: &KeyBuckets<'_, S>,
) -> Result<Vec<(String, RestoreStep)>> {
    copy.open(kek)?;
    if copy.kcv != committed {
        return Err(ERR_ESCROW_KEY);
    }
    let mut decided = Vec::new();
    // The newest copy of the key that opens, wherever it is; the escrow
    // copy counts as one.
    let mut newest: Option<(u32, String, Vec<u8>)> =
        Some((copy.kek_version, copy.name(), copy.blob.clone()));
    // The newest KEK version of a copy this Worker could not open.
    let mut unopened: u32 = 0;
    // Every active location is read (an asynchronous one may hold the
    // newest name, or a copy in conflict); only synchronous ones are
    // written.
    let mut conflict_elsewhere = Vec::new();
    for location in set.active() {
        let store = buckets.get(location)?;
        let mut conflict = false;
        let mut present = false;
        let mut unverified = false;
        for (other, n, v) in list_tenant_blobs(store, &copy.tenant).await? {
            if n != copy.version {
                continue;
            }
            let bytes = store.get(&other).await?.ok_or(ERR_ESCROW)?;
            let same_key = tk_blob_check_value(&bytes).is_ok_and(|k| k == copy.kcv);
            if !same_key {
                conflict = true;
                continue;
            }
            if kek.version(v).is_none() {
                unverified = true;
                unopened = unopened.max(v);
                continue;
            }
            // A copy that does not open is not a copy of the key.
            if unwrap_tenant_key(kek, v, &copy.tenant, n, &bytes).is_err() {
                conflict = true;
                continue;
            }
            present = true;
            if newest.as_ref().is_none_or(|(nv, _, _)| v > *nv) {
                newest = Some((v, other.clone(), bytes));
            }
        }
        let step = if conflict {
            RestoreStep::Conflict
        } else if present {
            RestoreStep::Present
        } else if unverified {
            RestoreStep::Unverified
        } else {
            RestoreStep::Restored
        };
        if location.synchronous {
            decided.push((location, step));
        } else if step == RestoreStep::Conflict {
            conflict_elsewhere.push(location.name.clone());
        }
    }
    let (newest_v, name, blob) =
        newest.unwrap_or((copy.kek_version, copy.name(), copy.blob.clone()));
    // A conflict anywhere, or a copy under a newer KEK than the one we
    // would write, stops every write: no older name beside a newer one.
    let mut stop = !conflict_elsewhere.is_empty()
        || decided.iter().any(|(_, s)| *s == RestoreStep::Conflict)
        || unopened > newest_v;
    let mut out = Vec::new();
    for (location, step) in decided {
        let step = match step {
            RestoreStep::Restored if stop => RestoreStep::Withheld,
            RestoreStep::Restored => {
                let store = buckets.get(location)?;
                let step = if store.put_if_absent(&name, blob.clone()).await? {
                    RestoreStep::Restored
                } else {
                    // Someone put it in between: read it back.
                    match store.get(&name).await? {
                        Some(b)
                            if tk_blob_check_value(&b).is_ok_and(|k| k == copy.kcv)
                                && unwrap_tenant_key(
                                    kek,
                                    newest_v,
                                    &copy.tenant,
                                    copy.version,
                                    &b,
                                )
                                .is_ok_and(|k| k.check_value() == copy.kcv) =>
                        {
                            RestoreStep::Present
                        }
                        _ => RestoreStep::Conflict,
                    }
                };
                // A conflict found while writing stops the writes after it.
                stop |= step == RestoreStep::Conflict;
                // A marker that appeared during the write wins: an error.
                list_tenant_blobs(store, &copy.tenant).await?;
                step
            }
            other => other,
        };
        out.push((location.name.clone(), step));
    }
    // An asynchronous location in conflict is named too: it is never
    // written, but it is what withheld the writes.
    out.extend(
        conflict_elsewhere
            .into_iter()
            .map(|name| (name, RestoreStep::Conflict)),
    );
    Ok(out)
}

/// The restore test of an escrow copy, run before the move by a local
/// process that holds the copy and the KEK. Each check answers only
/// "match" (`true`) or "mismatch" (`false`); nothing of a key, a secret
/// or a record's content leaves this function.
///
/// - `open`: the copy opens under the KEK as the key it names.
/// - `key_buckets`: one blob per key bucket, labelled with the bucket's
///   name, at least two buckets, each opening under the KEK as the key of
///   the copy. (The blobs are the ones under the copy's own name.)
/// - `key_chain`: the copy's key opens the private part of the given key
///   chain record (`seq`, bytes) of the tenant.
/// - `data_record`: the copy's key opens the given VMR2 record (name,
///   bytes) of the tenant.
///
/// Every check is always answered: a missing input is a mismatch.
pub fn restore_check<K: Kek>(
    copy: &EscrowCopy,
    kek: &K,
    bucket_blobs: &[(&str, Vec<u8>)],
    key_record: Option<(u64, &[u8])>,
    data_record: Option<(&str, &[u8])>,
) -> Vec<(&'static str, bool)> {
    let key = copy.open(kek).ok();
    let mut out = vec![("open", key.is_some())];
    // Two key buckets, each named once, each copy opening as the key.
    let mut names: Vec<&str> = bucket_blobs.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    names.dedup();
    let buckets_ok = names.len() >= 2
        && names.len() == bucket_blobs.len()
        && bucket_blobs.iter().all(|(_, b)| {
            // A bucket copy may be wrapped under a newer KEK than the
            // escrow copy; the wrap binds its version, so trying each
            // version the ring holds opens it only under its own.
            tk_blob_check_value(b).is_ok_and(|k| k == copy.kcv)
                && (1..=kek.active().0).rev().any(|v| {
                    kek.version(v).is_some()
                        && unwrap_tenant_key(kek, v, &copy.tenant, copy.version, b)
                            .is_ok_and(|k| k.check_value() == copy.kcv)
                })
        });
    out.push(("key_buckets", buckets_ok));
    let (chain_ok, data_ok) = match key {
        // A check whose input is missing is a mismatch, never left out.
        None => (false, false),
        Some(key) => {
            let tenant = key.tenant().clone();
            let ring = OneKey(key);
            let chain_ok = key_record.is_some_and(|(seq, bytes)| {
                open_key_record(kek, &ring, &tenant, seq, bytes).is_ok_and(|r| r.private.is_some())
            });
            let data_ok = data_record
                .is_some_and(|(name, bytes)| open_record_v2(&ring.0, &tenant, name, bytes).is_ok());
            (chain_ok, data_ok)
        }
    };
    out.push(("key_chain", chain_ok));
    out.push(("data_record", data_ok));
    out
}
