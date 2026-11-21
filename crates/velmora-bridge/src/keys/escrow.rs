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
use super::store::RecordStore;
use super::tk::{list_tenant_blobs, KeyBuckets};
use crate::crypto::scheme2::{
    open_record_v2, tk_blob_check_value, tk_blob_name, unwrap_tenant_key, TenantId, TenantKey,
    KCV_LEN,
};
use crate::ports::Kek;
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
    /// The location held the same key already.
    Present,
    /// The copy was put back.
    Restored,
    /// The location holds another key under that name, or another key of
    /// that version: nothing was written. An alarm.
    Conflict,
}

/// Puts the escrow copy back into every active location of `set` that
/// lacks it. Opens it with `kek` first.
pub async fn restore_escrow<S: RecordStore, K: Kek>(
    copy: &EscrowCopy,
    kek: &K,
    set: &KeyLocations,
    buckets: &KeyBuckets<'_, S>,
) -> Result<Vec<(String, RestoreStep)>> {
    copy.open(kek)?;
    let name = copy.name();
    // A marker or a foreign name anywhere: refused before any write.
    let mut seen = Vec::new();
    for location in set.active() {
        seen.push((
            location,
            list_tenant_blobs(buckets.get(location)?, &copy.tenant).await?,
        ));
    }
    let mut out = Vec::new();
    for (location, blobs) in seen {
        let store = buckets.get(location)?;
        let mut conflict = false;
        let mut present = false;
        for (other, n, _) in blobs {
            if n != copy.version {
                continue;
            }
            let bytes = store.get(&other).await?.ok_or(ERR_ESCROW)?;
            let same = tk_blob_check_value(&bytes)? == copy.kcv;
            conflict |= !same;
            present |= same && other == name;
        }
        let step = if conflict {
            RestoreStep::Conflict
        } else if present {
            RestoreStep::Present
        } else if store.put_if_absent(&name, copy.blob.clone()).await? {
            RestoreStep::Restored
        } else {
            // Someone put it in between: read it back.
            match store.get(&name).await? {
                Some(b) if tk_blob_check_value(&b)? == copy.kcv => RestoreStep::Present,
                _ => RestoreStep::Conflict,
            }
        };
        out.push((location.name.clone(), step));
    }
    Ok(out)
}

/// The restore test of an escrow copy, run before the move by a local
/// process that holds the copy and the KEK. Each check answers only
/// "match" (`true`) or "mismatch" (`false`); nothing of a key, a secret
/// or a record's content leaves this function.
///
/// - `open`: the copy opens under the KEK as the key it names.
/// - `key_buckets`: every blob given, as read from the key buckets, has
///   the copy's check value (and at least one is given).
/// - `key_chain`: the copy's key opens the private part of the given key
///   chain record (`seq`, bytes) of the tenant.
/// - `data_record`: the copy's key opens the given VMR2 record (name,
///   bytes) of the tenant.
pub fn restore_check<K: Kek>(
    copy: &EscrowCopy,
    kek: &K,
    bucket_blobs: &[Vec<u8>],
    key_record: Option<(u64, &[u8])>,
    data_record: Option<(&str, &[u8])>,
) -> Vec<(&'static str, bool)> {
    let key = copy.open(kek).ok();
    let mut out = vec![("open", key.is_some())];
    out.push((
        "key_buckets",
        !bucket_blobs.is_empty()
            && bucket_blobs
                .iter()
                .all(|b| tk_blob_check_value(b).is_ok_and(|k| k == copy.kcv)),
    ));
    let Some(key) = key else {
        out.push(("key_chain", false));
        out.push(("data_record", false));
        return out;
    };
    if let Some((seq, bytes)) = key_record {
        let tenant = key.tenant().clone();
        let ring = OneKey(key);
        let opened =
            open_key_record(kek, &ring, &tenant, seq, bytes).is_ok_and(|r| r.private.is_some());
        out.push(("key_chain", opened));
        if let Some((name, bytes)) = data_record {
            out.push((
                "data_record",
                open_record_v2(&ring.0, &tenant, name, bytes).is_ok(),
            ));
        }
        return out;
    }
    if let Some((name, bytes)) = data_record {
        out.push((
            "data_record",
            open_record_v2(&key, copy.tenant_id(), name, bytes).is_ok(),
        ));
    }
    out
}
