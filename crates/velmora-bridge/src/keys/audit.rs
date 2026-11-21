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
    /// A copy under a KEK version this Worker does not hold: it could not
    /// be opened, so it is not known to be good.
    NoKek { location: String, name: String },
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

/// The tenant prefix (`m/tk/<t>`, no slash) of a name below `m/tk/`.
fn tenant_of(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(TK_PREFIX)?;
    let (tenant, _) = rest.split_once('/')?;
    Some(&name[..TK_PREFIX.len() + tenant.len()])
}

/// Audits every location of `set`, page by page. With `kek`, also opens
/// every copy.
pub async fn audit<S: RecordStore, K: Kek>(
    set: &KeyLocations,
    buckets: &KeyBuckets<'_, S>,
    kek: Option<&K>,
) -> Result<AuditReport> {
    let mut report = AuditReport::default();
    let mut after = TK_PREFIX.to_owned();
    loop {
        let (page, next) = audit_page(set, buckets, kek, &after, PAGE).await?;
        report.blobs.extend(page.blobs);
        report.findings.extend(page.findings);
        match next {
            Some(n) => after = n,
            None => {
                report.findings.sort();
                return Ok(report);
            }
        }
    }
}

/// One bounded page of the audit: the names after `after` (`m/tk/` for
/// the first page), at most `limit` per location, cut at a tenant's
/// boundary so that every copy of a tenant's key versions is compared in
/// one page. Returns the cursor of the next page, `None` at the end.
pub async fn audit_page<S: RecordStore, K: Kek>(
    set: &KeyLocations,
    buckets: &KeyBuckets<'_, S>,
    kek: Option<&K>,
    after: &str,
    limit: u32,
) -> Result<(AuditReport, Option<String>)> {
    let limit = limit.max(1);
    let listed: Vec<_> = set
        .locations
        .iter()
        .filter(|l| l.status != LocationStatus::Lost)
        .collect();
    let mut names = Vec::new();
    // The smallest last name of a full page: names after it may be
    // missing from that location's page.
    let mut bound: Option<String> = None;
    for location in &listed {
        let store = buckets.get(location)?;
        let page = store.list(TK_PREFIX, after, limit).await?;
        if page.len() >= limit as usize {
            let last = page.last().cloned().unwrap_or_default();
            bound = Some(bound.map_or(last.clone(), |b: String| b.min(last)));
        }
        names.push((*location, page));
    }
    // Cut before the bound's tenant, which the next page takes whole.
    let (cut, next) = match &bound {
        None => (None, None),
        Some(b) => match tenant_of(b) {
            Some(t) if t > after => (Some(format!("{t}/")), Some(t.to_owned())),
            // One tenant fills a page: take the page as it is.
            _ => (Some(format!("{b}\u{1}")), Some(b.clone())),
        },
    };
    let mut report = AuditReport::default();
    for (location, page) in names {
        let store = buckets.get(location)?;
        for name in page {
            if cut.as_deref().is_some_and(|c| name.as_str() >= c) {
                continue;
            }
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
                let finding = match kek.version(v) {
                    None => Some(Finding::NoKek {
                        location: location.name.clone(),
                        name: name.clone(),
                    }),
                    Some(_) if unwrap_tenant_key(kek, v, &tenant, n, &bytes).is_err() => {
                        Some(Finding::Unopenable {
                            location: location.name.clone(),
                            name: name.clone(),
                        })
                    }
                    Some(_) => None,
                };
                report.findings.extend(finding);
            }
            report
                .blobs
                .entry(name)
                .or_default()
                .insert(location.name.clone(), kcv);
        }
    }
    compare(set, &mut report);
    report.findings.sort();
    Ok((report, next))
}

/// The findings across locations: missing copies, mismatched copies,
/// versions that hold two keys.
fn compare(set: &KeyLocations, report: &mut AuditReport) {
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
}

/// Restores the copies the audit found missing, into synchronous
/// locations only, from a copy that opens under the KEK. Nothing is done
/// for a name or a key version with any other finding, nor for a tenant
/// whose directory holds a foreign name in a synchronous location; a
/// marker that appears during the write is reported. Returns the names
/// restored.
pub async fn repair_missing<S: RecordStore, K: Kek>(
    set: &KeyLocations,
    buckets: &KeyBuckets<'_, S>,
    kek: &K,
    report: &AuditReport,
) -> Result<Vec<(String, String)>> {
    let doubtful = |name: &str, tenant: &TenantId, n: u32| {
        report.findings.iter().any(|f| match f {
            Finding::Mismatch { name: m }
            | Finding::Unopenable { name: m, .. }
            | Finding::NoKek { name: m, .. }
            | Finding::Inactive { name: m, .. } => m == name,
            Finding::VersionMismatch { tenant: t, version } => {
                t == tenant.as_str() && *version == n
            }
            Finding::Foreign { name: m, .. } => tenant_of(m) == tenant_of(name),
            Finding::Missing { .. } => false,
        })
    };
    let synchronous = set.synchronous();
    let mut restored = Vec::new();
    for finding in &report.findings {
        let Finding::Missing { location, name } = finding else {
            continue;
        };
        let Some(target) = synchronous.iter().find(|l| l.name == *location) else {
            continue;
        };
        let Some((tenant, n, v)) = split_name(name) else {
            continue;
        };
        let Some(expected) = report
            .blobs
            .get(name)
            .and_then(|c| c.values().next().copied())
        else {
            continue;
        };
        if doubtful(name, &tenant, n) {
            continue;
        }
        // A marker or a foreign name in a synchronous location: no writer
        // touches this tenant.
        let mut clean = true;
        for l in &synchronous {
            clean &= list_tenant_blobs(buckets.get(l)?, &tenant).await.is_ok();
        }
        if !clean {
            continue;
        }
        // A source that opens, and still has the check value the audit saw.
        let mut source = None;
        for l in &synchronous {
            if let Some(bytes) = buckets.get(l)?.get(name).await? {
                let good = tk_blob_check_value(&bytes).is_ok_and(|k| k == expected)
                    && unwrap_tenant_key(kek, v, &tenant, n, &bytes).is_ok();
                if good {
                    source = Some(bytes);
                    break;
                }
            }
        }
        let Some(bytes) = source else {
            continue;
        };
        let store = buckets.get(target)?;
        if store.put_if_absent(name, bytes).await? {
            restored.push((location.clone(), name.clone()));
        }
        // A writer always loses to the marker: one that appeared during
        // the write is an alarm for the operator.
        list_tenant_blobs(store, &tenant).await?;
    }
    Ok(restored)
}
