//! The key-chain apply on the unit (`docs/units.md`, "Keys"; ADR §2.4
//! rule 5, amendment AM-12).
//!
//! The Worker reads and verifies the tenant's key chain `m/k/<t>/` and
//! sends it on in [`UnitOp::ApplyKeys`](super::call::UnitOp): one
//! [`KeyEntry`] per record, in chain order, after a base `from_seq`.
//!
//! - `from_seq` is the **exclusive base**. The entries run without a gap
//!   from `from_seq + 1`; a gap is refused ([`KeyRefusal::Gap`]).
//! - A base above the unit's own `keys_seq` is answered
//!   [`Applied::Behind`] with the unit's number: the unit lacks records
//!   below the base, and the caller reads again from the unit's seq + 1.
//! - Each entry is compared, per subject, with the row's `last_seq`. An
//!   entry at or below it is skipped, except an entry that revokes, and
//!   one that opens, at the same seq, a row held closed (the bring-up's
//!   second send). `revoked` is final: a row once revoked stays so.
//! - The unit's `keys_seq` becomes the larger of its own and the last
//!   entry's seq.
//!
//! The catalogue's own `access_keys` and `grants` (what the S3 path
//! reads) are then rebuilt for every subject the call touched and every
//! key made under one of them, as the **effective grant** (ADR §6.2): a
//! key is served only while it is `active`, not held, has its secret, and
//! every principal up its `made_by` chain is `active` and not held; a
//! grant is served only on a bucket this unit holds, only when it has no
//! prefix, address list or expiry (the catalogue's `grants` cannot say
//! them, so such a grant waits for the check that can), and only when
//! every principal up the chain holds such a grant on the bucket with at
//! least that access. Anything else is not served: the build fails
//! toward closed.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::object::poll_once;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result};

/// The most entries one call may carry (est): a page of the chain.
pub const MAX_ENTRIES: usize = 100;
/// The most grants a subject may hold (record rule, ADR §6.2).
pub const MAX_GRANTS: usize = 64;
/// How far up a `made_by` chain the effective grant looks. A deeper or
/// circular chain is not served.
pub const MAX_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    S3,
    AppPassword,
    Principal,
    Internal,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKind::S3 => "s3",
            KeyKind::AppPassword => "app_password",
            KeyKind::Principal => "principal",
            KeyKind::Internal => "internal",
        }
    }

    fn parse(s: &str) -> Option<KeyKind> {
        Some(match s {
            "s3" => KeyKind::S3,
            "app_password" => KeyKind::AppPassword,
            "principal" => KeyKind::Principal,
            "internal" => KeyKind::Internal,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectStatus {
    Active,
    Disabled,
    Revoked,
}

impl SubjectStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectStatus::Active => "active",
            SubjectStatus::Disabled => "disabled",
            SubjectStatus::Revoked => "revoked",
        }
    }

    fn parse(s: &str) -> Option<SubjectStatus> {
        Some(match s {
            "active" => SubjectStatus::Active,
            "disabled" => SubjectStatus::Disabled,
            "revoked" => SubjectStatus::Revoked,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Ro,
    Rw,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Ro => "ro",
            Access::Rw => "rw",
        }
    }

    fn parse(s: &str) -> Option<Access> {
        match s {
            "ro" => Some(Access::Ro),
            "rw" => Some(Access::Rw),
            _ => None,
        }
    }
}

/// One grant, door and private part joined. `Debug` shows the bucket
/// and the access only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyGrant {
    pub bucket_id: String,
    pub access: Access,
    /// Unix ms; `None` = no expiry.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// `None` = the whole bucket.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Empty = any address.
    #[serde(default)]
    pub ip_list: Vec<String>,
}

impl fmt::Debug for KeyGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyGrant")
            .field("bucket_id", &self.bucket_id)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

impl KeyGrant {
    /// A grant the catalogue's `grants` can state: no prefix, no address
    /// list, no expiry.
    fn whole(&self) -> bool {
        self.prefix.is_none() && self.ip_list.is_empty() && self.expires_at.is_none()
    }
}

/// One subject as of one record of the key chain: the Worker's
/// `keys::record::Entry`, as it crosses `fetch`. `held`: the store must
/// hold it closed (its private part did not open, or the directory has
/// not acknowledged its opening record); a held entry may come without
/// its secret and its private grant parts. `Debug` shows no secret,
/// owner, prefix or address.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    pub id: String,
    pub kind: KeyKind,
    pub status: SubjectStatus,
    #[serde(default)]
    pub held: bool,
    #[serde(default)]
    pub made_by: Option<String>,
    #[serde(default)]
    pub grants: Vec<KeyGrant>,
    pub created_at: u64,
    #[serde(default, with = "opt_b64")]
    pub secret_wrapped: Option<Vec<u8>>,
    #[serde(default)]
    pub secret_kek_version: Option<u32>,
    #[serde(default)]
    pub owner_ref: Option<String>,
    /// The seq of the record this entry is.
    pub last_seq: u64,
}

impl fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("held", &self.held)
            .field("grants", &self.grants.len())
            .field("secret", &self.secret_wrapped.is_some())
            .field("last_seq", &self.last_seq)
            .finish_non_exhaustive()
    }
}

/// Why an apply was refused. Nothing of the call is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRefusal {
    /// The entries do not run from `from_seq + 1` without a gap.
    Gap,
    /// An entry that cannot be a record: a principal with a secret, an
    /// open key without one, too many grants, an empty id, too many
    /// entries.
    Malformed,
}

/// What an apply did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Applied; the unit's `keys_seq` is now this.
    Done {
        keys_seq: u64,
        applied: u64,
        skipped: u64,
    },
    /// The base is above the unit's `keys_seq`: nothing was done; read
    /// again from `keys_seq + 1`.
    Behind {
        keys_seq: u64,
    },
    Refused(KeyRefusal),
}

/// The checks that need no database.
pub fn check_entries(from_seq: u64, entries: &[KeyEntry]) -> std::result::Result<(), KeyRefusal> {
    if entries.len() > MAX_ENTRIES {
        return Err(KeyRefusal::Malformed);
    }
    for (i, e) in entries.iter().enumerate() {
        let want = from_seq.checked_add(1 + i as u64).ok_or(KeyRefusal::Gap)?;
        if e.last_seq != want {
            return Err(KeyRefusal::Gap);
        }
        if e.id.is_empty() || e.id.len() > 128 || e.grants.len() > MAX_GRANTS {
            return Err(KeyRefusal::Malformed);
        }
        if e.made_by.as_deref() == Some(e.id.as_str()) {
            return Err(KeyRefusal::Malformed);
        }
        if e.secret_wrapped.is_some() != e.secret_kek_version.is_some() {
            return Err(KeyRefusal::Malformed);
        }
        let secret = e.secret_wrapped.is_some();
        match e.kind {
            KeyKind::Principal if secret => return Err(KeyRefusal::Malformed),
            // An open key carries its secret; a held or revoked one may not.
            KeyKind::S3 | KeyKind::AppPassword | KeyKind::Internal
                if !secret && !e.held && e.status != SubjectStatus::Revoked =>
            {
                return Err(KeyRefusal::Malformed)
            }
            _ => {}
        }
        if i64::try_from(e.created_at).is_err()
            || e.grants
                .iter()
                .any(|g| g.expires_at.is_some_and(|t| i64::try_from(t).is_err()))
        {
            return Err(KeyRefusal::Malformed);
        }
    }
    Ok(())
}

/// The stored row of a subject, as far as the apply rule reads it.
struct Row {
    status: SubjectStatus,
    held: bool,
    last_seq: u64,
}

/// Applies `entries` after `from_seq` inside the caller's transaction.
/// `keys_seq` is the unit's own. Writes `unit_keys`, `unit_key_grants`
/// and the effective `access_keys` and `grants`; the caller moves
/// `unit_head.keys_seq` to the answer's number.
pub fn apply<S: Sql>(
    sql: &S,
    keys_seq: u64,
    from_seq: u64,
    entries: &[KeyEntry],
) -> Result<Applied> {
    if from_seq > keys_seq {
        return Ok(Applied::Behind { keys_seq });
    }
    if let Err(r) = check_entries(from_seq, entries) {
        return Ok(Applied::Refused(r));
    }
    let mut touched = BTreeSet::new();
    let (mut applied, mut skipped) = (0, 0);
    for e in entries {
        let row = stored(sql, &e.id)?;
        let write = match &row {
            None => true,
            Some(r) => e.last_seq > r.last_seq || (e.last_seq == r.last_seq && r.held && !e.held),
        };
        let was_revoked = row
            .as_ref()
            .is_some_and(|r| r.status == SubjectStatus::Revoked);
        if write {
            put(sql, e, was_revoked)?;
            applied += 1;
            touched.insert(e.id.clone());
        } else if e.status == SubjectStatus::Revoked && !was_revoked {
            // A revocation is applied whatever its seq.
            poll_once(sql.exec(
                "UPDATE unit_keys SET status = 'revoked' WHERE id = ?1",
                &[SqlValue::Text(e.id.clone())],
            ))??;
            applied += 1;
            touched.insert(e.id.clone());
        } else {
            skipped += 1;
        }
    }
    project(sql, &touched)?;
    let last = from_seq + entries.len() as u64;
    Ok(Applied::Done {
        keys_seq: keys_seq.max(last),
        applied,
        skipped,
    })
}

/// The subjects the unit holds closed and not revoked: they are sent
/// again once their private part opens (`KeyTarget::closed`).
pub fn held<S: Sql>(sql: &S) -> Result<Vec<String>> {
    let rows = poll_once(sql.query(
        "SELECT id FROM unit_keys WHERE held = 1 AND status <> 'revoked' ORDER BY id",
        &[],
    ))??;
    rows.into_iter()
        .map(|r| match r.into_iter().next() {
            Some(SqlValue::Text(id)) => Ok(id),
            _ => Err(decode("unit_keys id")),
        })
        .collect()
}

/// The number of revoked subjects the unit holds (ADR §2.4 rule 12).
pub fn revoked<S: Sql>(sql: &S) -> Result<u64> {
    let rows = poll_once(sql.query(
        "SELECT count(*) FROM unit_keys WHERE status = 'revoked'",
        &[],
    ))??;
    match rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Int(n)) if *n >= 0 => Ok(*n as u64),
        _ => Err(decode("revoked count")),
    }
}

fn stored<S: Sql>(sql: &S, id: &str) -> Result<Option<Row>> {
    let rows = poll_once(sql.query(
        "SELECT status, held, last_seq FROM unit_keys WHERE id = ?1",
        &[SqlValue::Text(id.to_string())],
    ))??;
    let Some(r) = rows.into_iter().next() else {
        return Ok(None);
    };
    let (SqlValue::Text(status), SqlValue::Int(held), SqlValue::Int(last)) = (&r[0], &r[1], &r[2])
    else {
        return Err(decode("unit_keys row"));
    };
    Ok(Some(Row {
        status: SubjectStatus::parse(status).ok_or_else(|| decode("unit_keys status"))?,
        held: *held == 1,
        last_seq: u64::try_from(*last).map_err(|_| decode("unit_keys last_seq"))?,
    }))
}

/// Writes the subject's row and grants as the entry states them; a row
/// that was revoked stays revoked.
fn put<S: Sql>(sql: &S, e: &KeyEntry, was_revoked: bool) -> Result<()> {
    let status = if was_revoked {
        SubjectStatus::Revoked
    } else {
        e.status
    };
    let opt_text = |s: &Option<String>| s.clone().map_or(SqlValue::Null, SqlValue::Text);
    poll_once(
        sql.exec(
            "INSERT INTO unit_keys(id, kind, status, held, made_by, created_at, secret_wrapped, \
           secret_kek_version, owner_ref, last_seq) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, status = excluded.status, \
           held = excluded.held, made_by = excluded.made_by, created_at = excluded.created_at, \
           secret_wrapped = excluded.secret_wrapped, \
           secret_kek_version = excluded.secret_kek_version, owner_ref = excluded.owner_ref, \
           last_seq = excluded.last_seq",
            &[
                SqlValue::Text(e.id.clone()),
                SqlValue::Text(e.kind.as_str().into()),
                SqlValue::Text(status.as_str().into()),
                SqlValue::Int(i64::from(e.held)),
                opt_text(&e.made_by),
                int(e.created_at)?,
                e.secret_wrapped
                    .clone()
                    .map_or(SqlValue::Null, SqlValue::Blob),
                e.secret_kek_version
                    .map_or(SqlValue::Null, |v| SqlValue::Int(i64::from(v))),
                opt_text(&e.owner_ref),
                int(e.last_seq)?,
            ],
        ),
    )??;
    poll_once(sql.exec(
        "DELETE FROM unit_key_grants WHERE subject_id = ?1",
        &[SqlValue::Text(e.id.clone())],
    ))??;
    for (i, g) in e.grants.iter().enumerate() {
        let ips =
            serde_json::to_string(&g.ip_list).map_err(|_| BridgeError::Invalid("unit: ip list"))?;
        poll_once(sql.exec(
            "INSERT INTO unit_key_grants(subject_id, idx, bucket_id, access, expires_at, prefix, \
               ip_list) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                SqlValue::Text(e.id.clone()),
                SqlValue::Int(i as i64),
                SqlValue::Text(g.bucket_id.clone()),
                SqlValue::Text(g.access.as_str().into()),
                match g.expires_at {
                    Some(t) => int(t)?,
                    None => SqlValue::Null,
                },
                opt_text(&g.prefix),
                SqlValue::Text(ips),
            ],
        ))??;
    }
    Ok(())
}

/// One subject as the effective grant reads it.
struct Subject {
    kind: KeyKind,
    open: bool,
    made_by: Option<String>,
    secret: Option<(Vec<u8>, i64)>,
    created_at: i64,
}

fn subject<S: Sql>(sql: &S, id: &str) -> Result<Option<Subject>> {
    let rows = poll_once(sql.query(
        "SELECT kind, status, held, made_by, secret_wrapped, secret_kek_version, created_at \
           FROM unit_keys WHERE id = ?1",
        &[SqlValue::Text(id.to_string())],
    ))??;
    let Some(r) = rows.into_iter().next() else {
        return Ok(None);
    };
    let kind = match &r[0] {
        SqlValue::Text(k) => KeyKind::parse(k).ok_or_else(|| decode("unit_keys kind"))?,
        _ => return Err(decode("unit_keys kind")),
    };
    let open = matches!((&r[1], &r[2]), (SqlValue::Text(s), SqlValue::Int(0)) if s == "active");
    let made_by = match &r[3] {
        SqlValue::Text(p) => Some(p.clone()),
        SqlValue::Null => None,
        _ => return Err(decode("unit_keys made_by")),
    };
    let secret = match (&r[4], &r[5]) {
        (SqlValue::Blob(b), SqlValue::Int(v)) => Some((b.clone(), *v)),
        (SqlValue::Null, SqlValue::Null) => None,
        _ => return Err(decode("unit_keys secret")),
    };
    let SqlValue::Int(created_at) = r[6] else {
        return Err(decode("unit_keys created_at"));
    };
    Ok(Some(Subject {
        kind,
        open,
        made_by,
        secret,
        created_at,
    }))
}

/// A subject's grants that the catalogue can state, per bucket, with the
/// widest access among them.
fn whole_grants<S: Sql>(sql: &S, id: &str) -> Result<Vec<(String, Access)>> {
    let rows = poll_once(sql.query(
        "SELECT bucket_id, access, expires_at, prefix, ip_list FROM unit_key_grants \
          WHERE subject_id = ?1 ORDER BY idx",
        &[SqlValue::Text(id.to_string())],
    ))??;
    let mut out: Vec<(String, Access)> = Vec::new();
    for r in rows {
        let (SqlValue::Text(bucket), SqlValue::Text(access), SqlValue::Text(ips)) =
            (&r[0], &r[1], &r[4])
        else {
            return Err(decode("unit_key_grants row"));
        };
        let g = KeyGrant {
            bucket_id: bucket.clone(),
            access: Access::parse(access).ok_or_else(|| decode("unit_key_grants access"))?,
            expires_at: match r[2] {
                SqlValue::Null => None,
                SqlValue::Int(t) => Some(t.max(0) as u64),
                _ => return Err(decode("unit_key_grants expires_at")),
            },
            prefix: match &r[3] {
                SqlValue::Null => None,
                SqlValue::Text(p) => Some(p.clone()),
                _ => return Err(decode("unit_key_grants prefix")),
            },
            ip_list: serde_json::from_str(ips).map_err(|_| decode("unit_key_grants ip_list"))?,
        };
        if !g.whole() {
            continue;
        }
        match out.iter_mut().find(|(b, _)| *b == g.bucket_id) {
            Some((_, a)) => *a = (*a).max(g.access),
            None => out.push((g.bucket_id, g.access)),
        }
    }
    Ok(out)
}

/// Rebuilds the effective rows of every subject with a grant on one of
/// `buckets`: called when buckets arrive after the keys (an import), so
/// a grant on a bucket the unit did not hold yet is served once it does.
pub fn project_buckets<S: Sql>(sql: &S, buckets: &[String]) -> Result<()> {
    let mut touched = BTreeSet::new();
    for b in buckets {
        let rows = poll_once(sql.query(
            "SELECT DISTINCT subject_id FROM unit_key_grants WHERE bucket_id = ?1",
            &[SqlValue::Text(b.clone())],
        ))??;
        for r in rows {
            if let Some(SqlValue::Text(id)) = r.into_iter().next() {
                touched.insert(id);
            }
        }
    }
    project(sql, &touched)
}

/// Rebuilds the catalogue's `access_keys` and `grants` for `touched` and
/// every key made under one of them, down the `made_by` chains.
fn project<S: Sql>(sql: &S, touched: &BTreeSet<String>) -> Result<()> {
    let mut all: BTreeSet<String> = touched.clone();
    let mut frontier: Vec<String> = touched.iter().cloned().collect();
    for _ in 0..MAX_DEPTH {
        let mut next = Vec::new();
        for p in &frontier {
            let rows = poll_once(sql.query(
                "SELECT id FROM unit_keys WHERE made_by = ?1",
                &[SqlValue::Text(p.clone())],
            ))??;
            for r in rows {
                if let Some(SqlValue::Text(id)) = r.into_iter().next() {
                    if all.insert(id.clone()) {
                        next.push(id);
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    for id in &all {
        build(sql, id)?;
    }
    Ok(())
}

/// The effective rows of one subject: none unless it is a key that is
/// served (module doc).
fn build<S: Sql>(sql: &S, id: &str) -> Result<()> {
    let idv = || SqlValue::Text(id.to_string());
    poll_once(sql.exec("DELETE FROM grants WHERE access_key_id = ?1", &[idv()]))??;
    poll_once(sql.exec("DELETE FROM access_keys WHERE access_key_id = ?1", &[idv()]))??;
    let Some(key) = subject(sql, id)? else {
        return Ok(());
    };
    if key.kind == KeyKind::Principal || !key.open {
        return Ok(());
    }
    let Some((secret, kek_version)) = key.secret.clone() else {
        return Ok(());
    };
    // The principals up the chain, each open.
    let mut chain = Vec::new();
    let mut up = key.made_by.clone();
    let mut seen = BTreeSet::from([id.to_string()]);
    while let Some(p) = up {
        if chain.len() >= MAX_DEPTH || !seen.insert(p.clone()) {
            return Ok(());
        }
        let Some(ps) = subject(sql, &p)? else {
            return Ok(());
        };
        if ps.kind != KeyKind::Principal || !ps.open {
            return Ok(());
        }
        up = ps.made_by.clone();
        chain.push(p);
    }
    let mut grants = whole_grants(sql, id)?;
    for p in &chain {
        let theirs = whole_grants(sql, p)?;
        grants.retain(|(b, a)| theirs.iter().any(|(pb, pa)| pb == b && pa >= a));
    }
    poll_once(sql.exec(
        "INSERT INTO access_keys(access_key_id, principal, secret_wrapped, kek_version, status, \
           created_at) VALUES (?1, ?2, ?3, ?4, 'active', ?5)",
        &[
            idv(),
            SqlValue::Text(key.made_by.clone().unwrap_or_default()),
            SqlValue::Blob(secret),
            SqlValue::Int(kek_version),
            SqlValue::Int(key.created_at),
        ],
    ))??;
    for (bucket, access) in grants {
        // Only a bucket this unit holds: another unit's bucket has its
        // own copy of the key there.
        poll_once(sql.exec(
            "INSERT INTO grants(access_key_id, bucket_id, perm) \
             SELECT ?1, id, ?3 FROM buckets WHERE id = ?2",
            &[
                idv(),
                SqlValue::Text(bucket),
                SqlValue::Text(access.as_str().into()),
            ],
        ))??;
    }
    Ok(())
}

fn int(n: u64) -> Result<SqlValue> {
    i64::try_from(n)
        .map(SqlValue::Int)
        .map_err(|_| BridgeError::Invalid("number out of range"))
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}

mod opt_b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&base64::engine::general_purpose::STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        s.map(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(serde::de::Error::custom)
        })
        .transpose()
    }
}
