//! The key-location audit: every copy of every tenant key, compared
//! across the locations of the set.
//!
//! It lists `m/tk/` in every location the set names that is not `lost`,
//! groups the blobs by name, and reports:
//! - a copy missing from an `active` location;
//! - copies of one name, or of one key version, whose check values
//!   differ;
//! - a name that is no key blob (a marker, or something no writer of
//!   this code put there);
//! - a blob in a location that is `proposed` or `retired`, which must
//!   hold nothing;
//! - with a KEK, a copy that does not open under it.
//!
//! It deletes nothing. [`repair_missing`] restores a missing copy, with
//! put-if-absent, only when every copy that exists has the same check
//! value and the tenant's directory holds no other name.

use std::collections::{BTreeMap, BTreeSet};

use super::locations::{KeyLocations, LocationStatus};
use super::store::RecordStore;
use super::tk::{list_tenant_blobs, parse_tk_name, KeyBuckets};
use crate::crypto::scheme2::{
    tk_blob_check_value, unwrap_tenant_key, TenantId, KCV_LEN, TK_PREFIX,
};
use crate::ports::Kek;
use crate::types::Result;

const PAGE: u32 = 1000;

/// One thing the audit found.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Finding {
    /// `location` is `active` and lacks a copy of `name`.
    Missing { location: String, name: String },
    /// The copies of `name` across locations differ.
    Mismatch { name: String },
    /// The copies of key version `version` of `tenant` (under any KEK
    /// version) hold different keys.
    VersionMismatch { tenant: String, version: u32 },
    /// A name below `m/tk/` that is no key blob.
    Foreign { location: String, name: String },
    /// A blob in a location that must hold nothing.
    Inactive { location: String, name: String },
    /// A copy that does not open under the KEK.
    Unopenable { location: String, name: String },
}

/// What the audit saw and found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Key blob names, with the check value of the copy in each location.
    pub blobs: BTreeMap<String, BTreeMap<String, [u8; KCV_LEN]>>,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    pub fn clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// The tenant and versions of a key blob name below `m/tk/`.
fn split_name(name: &str) -> Option<(TenantId, u32, u32)> {
    let rest = name.strip_prefix(TK_PREFIX)?;
    let (tenant, _) = rest.split_once('/')?;
    let tenant = TenantId::parse(tenant).ok()?;
    let (n, v) = parse_tk_name(&tenant, name)?;
    Some((tenant, n, v))
}

async fn list_all<S: RecordStore>(store: &S) -> Result<Vec<String>> {
    let mut after = TK_PREFIX.to_owned();
    let mut out = Vec::new();
    loop {
        let names = store.list(TK_PREFIX, &after, PAGE).await?;
        out.extend(names.iter().cloned());
        match names.last() {
            Some(last) if names.len() >= PAGE as usize => after.clone_from(last),
            _ => return Ok(out),
        }
    }
}

/// Audits every location of `set`. With `kek`, also opens every copy.
pub async fn audit<S: RecordStore, K: Kek>(
    set: &KeyLocations,
    buckets: &KeyBuckets<'_, S>,
    kek: Option<&K>,
) -> Result<AuditReport> {
    let mut report = AuditReport::default();
    for location in set
        .locations
        .iter()
        .filter(|l| l.status != LocationStatus::Lost)
    {
        let store = buckets.get(location)?;
        for name in list_all(store).await? {
            let Some((tenant, n, v)) = split_name(&name) else {
                report.findings.push(Finding::Foreign {
                    location: location.name.clone(),
                    name,
                });
                continue;
            };
            if location.status != LocationStatus::Active {
                report.findings.push(Finding::Inactive {
                    location: location.name.clone(),
                    name: name.clone(),
                });
            }
            let Some(bytes) = store.get(&name).await? else {
                continue;
            };
            let Ok(kcv) = tk_blob_check_value(&bytes) else {
                report.findings.push(Finding::Unopenable {
                    location: location.name.clone(),
                    name,
                });
                continue;
            };
            if let Some(kek) = kek {
                if kek.version(v).is_some()
                    && unwrap_tenant_key(kek, v, &tenant, n, &bytes).is_err()
                {
                    report.findings.push(Finding::Unopenable {
                        location: location.name.clone(),
                        name: name.clone(),
                    });
                }
            }
            report
                .blobs
                .entry(name)
                .or_default()
                .insert(location.name.clone(), kcv);
        }
    }

    let active: Vec<&str> = set.active().iter().map(|l| l.name.as_str()).collect();
    // Every check value seen for each key version, over every name and
    // every copy: more than one is a version that holds two keys.
    let mut by_version: BTreeMap<(String, u32), BTreeSet<[u8; KCV_LEN]>> = BTreeMap::new();
    for (name, copies) in &report.blobs {
        let mut values = copies.values();
        let first = values.next().copied();
        if values.any(|k| Some(*k) != first) {
            report
                .findings
                .push(Finding::Mismatch { name: name.clone() });
        }
        for location in &active {
            if !copies.contains_key(*location) {
                report.findings.push(Finding::Missing {
                    location: (*location).to_owned(),
                    name: name.clone(),
                });
            }
        }
        if let Some((tenant, n, _)) = split_name(name) {
            by_version
                .entry((tenant.as_str().to_owned(), n))
                .or_default()
                .extend(copies.values().copied());
        }
    }
    for ((tenant, version), values) in by_version {
        if values.len() > 1 {
            report
                .findings
                .push(Finding::VersionMismatch { tenant, version });
        }
    }
    report.findings.sort();
    Ok(report)
}

/// Restores the copies the audit found missing, from a copy that exists,
/// when every copy of that name and of its key version agrees and the
/// tenant's directory holds no foreign name in any active location.
/// Returns the names restored.
pub async fn repair_missing<S: RecordStore>(
    set: &KeyLocations,
    buckets: &KeyBuckets<'_, S>,
    report: &AuditReport,
) -> Result<Vec<(String, String)>> {
    let refused: Vec<&str> = report
        .findings
        .iter()
        .filter_map(|f| match f {
            Finding::Mismatch { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let mut restored = Vec::new();
    for finding in &report.findings {
        let Finding::Missing { location, name } = finding else {
            continue;
        };
        let Some((tenant, n, _)) = split_name(name) else {
            continue;
        };
        let version_bad = report.findings.iter().any(|f| {
            matches!(f, Finding::VersionMismatch { tenant: t, version } if t == tenant.as_str() && *version == n)
        });
        if refused.contains(&name.as_str()) || version_bad {
            continue;
        }
        // A marker or a foreign name in any active location: no writer
        // touches this tenant.
        let mut clean = true;
        for l in set.active() {
            if list_tenant_blobs(buckets.get(l)?, &tenant).await.is_err() {
                clean = false;
            }
        }
        if !clean {
            continue;
        }
        let Some(source) = set.active().into_iter().find(|l| {
            report
                .blobs
                .get(name)
                .is_some_and(|c| c.contains_key(&l.name))
        }) else {
            continue;
        };
        let Some(bytes) = buckets.get(source)?.get(name).await? else {
            continue;
        };
        let target = set
            .active()
            .into_iter()
            .find(|l| l.name == *location)
            .map(|l| buckets.get(l))
            .transpose()?;
        if let Some(target) = target {
            if target.put_if_absent(name, bytes).await? {
                restored.push((location.clone(), name.clone()));
            }
        }
    }
    Ok(restored)
}
