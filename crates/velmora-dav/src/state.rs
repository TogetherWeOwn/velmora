//! Locks, write leases and dead properties of one bucket: the rules of
//! the `DavState` Durable Object, over a SQL port.
//!
//! One object per bucket. Its requests run one at a time and each runs
//! to its end without waiting (the port is synchronous), so every batch
//! of operations is atomic: a lock check and the lease that follows it
//! see the same state, and a property update is all or nothing.
//!
//! Paths are keys inside the bucket: a file is `a/b.txt`, a collection
//! `a/` (with its slash), the bucket itself `""`. A lock with depth
//! infinity on a collection covers every path under it, members added
//! later included.
//!
//! Expired locks, leases and reservations are deleted at the start of
//! the next batch, so no alarm is needed.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A value of the SQL port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Val {
    Null,
    Int(i64),
    Text(String),
}

impl Val {
    fn text(&self) -> String {
        match self {
            Val::Text(s) => s.clone(),
            Val::Int(i) => i.to_string(),
            Val::Null => String::new(),
        }
    }

    fn opt_text(&self) -> Option<String> {
        match self {
            Val::Null => None,
            other => Some(other.text()),
        }
    }

    fn int(&self) -> i64 {
        match self {
            Val::Int(i) => *i,
            Val::Text(s) => s.parse().unwrap_or(0),
            Val::Null => 0,
        }
    }
}

fn t(s: &str) -> Val {
    Val::Text(s.to_owned())
}

/// SQLite with no waits: the Durable Object's storage, or an in-memory
/// database in tests.
pub trait Sql {
    fn exec(&self, sql: &str, params: &[Val]) -> Result<Vec<Vec<Val>>, String>;
}

pub const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS locks (\
       token TEXT PRIMARY KEY, root TEXT NOT NULL, depth_inf INTEGER NOT NULL, \
       scope TEXT NOT NULL CHECK (scope IN ('exclusive','shared')), owner_xml TEXT, \
       principal TEXT NOT NULL, timeout_secs INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS locks_root ON locks(root)",
    "CREATE TABLE IF NOT EXISTS write_leases (\
       holder TEXT NOT NULL, path TEXT NOT NULL, recursive INTEGER NOT NULL, \
       expires_at INTEGER NOT NULL, PRIMARY KEY (holder, path)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS write_leases_path ON write_leases(path)",
    "CREATE TABLE IF NOT EXISTS mutation_reservations (\
       holder TEXT NOT NULL, path TEXT NOT NULL, recursive INTEGER NOT NULL, \
       expires_at INTEGER NOT NULL, PRIMARY KEY (holder, path)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS moved_capacity (\
       holder TEXT PRIMARY KEY, amount INTEGER NOT NULL, expires_at INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS dav_props (\
       path TEXT NOT NULL, ns TEXT NOT NULL, name TEXT NOT NULL, value_xml TEXT NOT NULL, \
       etag TEXT, PRIMARY KEY (path, ns, name)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS moved_members (\
       destination TEXT PRIMARY KEY, etag TEXT NOT NULL, source TEXT NOT NULL) WITHOUT ROWID",
];
// Keep even JSON-escaped maximum-length keys well below the SQL value limit.
const MOVED_MEMBER_SQL_BATCH: usize = 32;

/// Caps. A dead property is stored as one row of the object's SQLite
/// storage, read whole on every PROPFIND that asks for it: 64 KiB a value
/// and 256 KiB a resource keep such a read small. Locks are few by
/// nature; the caps stop a client that never unlocks from filling the
/// object.
pub const MAX_PROP_BYTES: usize = 64 * 1024;
pub const MAX_PROPS_PER_RESOURCE: usize = 256 * 1024;
const MAX_PROPFIND_PROP_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LOCKS_PER_BUCKET: i64 = 5_000;
pub const MAX_MOVED_MEMBERS_PER_BUCKET: i64 = 10_000;
pub const MAX_LOCKS_PER_KEY: i64 = 500;
pub const MAX_OWNER_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub token: String,
    pub root: String,
    pub depth_inf: bool,
    pub exclusive: bool,
    pub owner_xml: Option<String>,
    pub principal: String,
    pub timeout_secs: u32,
    pub expires_at: i64,
}

/// How a path is checked before a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// The path itself: locks on it and depth-infinity locks above it.
    Exact,
    /// The path and everything under it (a collection operation).
    Tree,
    /// A collection whose members change: locks covering the collection.
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub path: String,
    pub scope: Scope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadProp {
    pub ns: String,
    pub name: String,
    /// The whole property element as standalone XML.
    pub xml: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Patch {
    Set(DeadProp),
    Remove { ns: String, name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MovedMember {
    pub destination: String,
    pub etag: String,
    pub source: String,
}

/// One operation. A batch of them runs atomically.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// Locks that cover each path (lockdiscovery, `If` evaluation).
    Discover {
        paths: Vec<String>,
    },
    /// A new lock. `token` is drawn by the caller (`urn:uuid:` v4).
    Lock {
        token: String,
        root: String,
        depth_inf: bool,
        exclusive: bool,
        owner_xml: Option<String>,
        principal: String,
        timeout_secs: u32,
        holder: Option<String>,
        /// Judged first as for a write, with `tokens`: a LOCK that
        /// creates a file changes its folder's members.
        checks: Vec<Check>,
        tokens: Vec<String>,
    },
    /// Refreshes a lock that covers `path`, by one of `tokens`.
    Refresh {
        path: String,
        tokens: Vec<String>,
        principal: String,
        timeout_secs: u32,
    },
    Unlock {
        path: String,
        token: String,
        principal: String,
    },
    /// Checks the locks for a write and, if it may go ahead, records a
    /// lease that blocks new locks on the same paths until `EndWrite` or
    /// until it expires.
    BeginWrite {
        checks: Vec<Check>,
        tokens: Vec<String>,
        principal: String,
        holder: String,
        ttl_secs: u32,
    },
    /// Serialize overlapping DAV mutations independently of LOCK checks.
    Reserve {
        holder: String,
        roots: Vec<(String, bool)>,
        ttl_secs: u32,
    },
    /// Extends the holder's lease, reservation and capacity claim.
    /// `Lost` when its reservation or its lease rows are gone (expired
    /// and purged, or ended): the request must stop.
    RenewWrite {
        holder: String,
        ttl_secs: u32,
    },
    EndWrite {
        holder: String,
    },
    /// Deletes the locks rooted at `path` (and under it with `tree`).
    DropLocks {
        path: String,
        tree: bool,
    },
    /// Dead properties of each `(path, etag)`; rows with a different
    /// stamp are skipped, not deleted. `names`: only these (`None`: all).
    /// `names_only` omits values. Replies `Full` rather than returning a
    /// partial result over the budget.
    PropGet {
        paths: Vec<(String, Option<String>)>,
        names: Option<Vec<(String, String)>>,
        #[serde(default)]
        names_only: bool,
    },
    PropPatch {
        path: String,
        etag: Option<String>,
        patches: Vec<Patch>,
    },
    /// Replaces the destination properties with rows for `from_etag`
    /// stamped with `to_etag`. With `tree`, also copies descendant
    /// collection rows; copied files each carry their own ETag.
    PropCopy {
        from: String,
        to: String,
        tree: bool,
        from_etag: Option<String>,
        to_etag: Option<String>,
    },
    PropDrop {
        path: String,
        tree: bool,
    },
    /// The object was replaced through WebDAV: its properties stamped
    /// with `from` (the etag it had) carry `to` (the new one) from now.
    PropRestamp {
        path: String,
        from: String,
        to: String,
    },
    /// Copies properties only for collections represented by these successful
    /// destination keys (including explicit markers and implicit ancestors).
    PropCopyFolders {
        from: String,
        to: String,
        members: Vec<String>,
    },
    /// Hold room for a MOVE before copying, including against disjoint MOVEs.
    ReserveMoved {
        holder: String,
        destinations: Vec<String>,
        ttl_secs: u32,
    },
    /// Publish all copied versions atomically before deleting any source member.
    RecordMoved {
        holder: Option<String>,
        members: Vec<MovedMember>,
    },
    /// Reconcile ledger rows against a complete destination listing and keep
    /// only matching versions. `exact` covers a same-named file outside `root`.
    FindMoved {
        holder: String,
        root: Option<String>,
        listed: Vec<(String, String)>,
        exact: Option<(String, String)>,
    },
    /// Every collection at or under one of `roots` that holds DAV state:
    /// a lock rooted at it or at a file directly in it, or a dead property
    /// on either. `Full` when there are more than `limit`.
    FoldersWithState {
        roots: Vec<String>,
        limit: usize,
    },
    /// Remove the matching ledger rows after all source deletes succeeded.
    FinishMove(Vec<MovedMember>),
    /// A tree MOVE completed: earlier partial attempts of the same move
    /// (source under `src_root`, destination under `dst_root`, the same
    /// path below each) are done.
    FinishMoveTree {
        src_root: String,
        dst_root: String,
    },
    /// A successful WebDAV write or delete superseded these exact keys.
    ClearMoved(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Done,
    Locks(Vec<Vec<Lock>>),
    Locked(Lock),
    /// A lock or lease in the way, at this path.
    Conflict {
        path: String,
    },
    /// No lock matches (refresh, unlock).
    NoLock,
    /// The lock belongs to another principal.
    NotOwner,
    /// Over a cap (`507`).
    Full,
    Granted,
    Props(Vec<Vec<DeadProp>>),
    /// One status per patch, in order (`200`, `403`, `424`, `507`).
    Patched(Vec<u16>),
    /// Protected ledger rows: `(destination, source)`.
    Moved(Vec<(String, String)>),
    /// The new expiry, Unix seconds.
    Renewed {
        expires_at: i64,
    },
    Lost,
    StatefulFolders(Vec<String>),
    Busy,
}

/// The bucket's state over a SQL port.
pub struct Engine<'a, S: Sql> {
    pub sql: &'a S,
    /// Now, in Unix seconds.
    pub now: i64,
}

/// Every collection above `path`, the bucket itself (`""`) included.
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    let body = path.strip_suffix('/').unwrap_or(path);
    std::iter::once("").chain(body.match_indices('/').map(move |(i, _)| &body[..=i]))
}

/// The end of the key range under a collection (`a/` -> `a0`).
fn range_end(prefix: &str) -> Option<String> {
    prefix
        .strip_suffix('/')
        .map(|p| format!("{p}0"))
        .filter(|_| !prefix.is_empty())
}

fn within(outer: &str, inner: &str) -> bool {
    crate::path::within(outer, inner)
}

/// For one affected resource, every exclusive lock and at least one
/// shared lock (if any) must have an owned, submitted token.
fn blocking_lock<'a>(
    locks: impl IntoIterator<Item = &'a Lock>,
    holds: impl Fn(&Lock) -> bool,
    inherited_shared: impl FnOnce() -> bool,
) -> Option<&'a str> {
    let mut missing_shared = None;
    let mut held_shared = false;
    for lock in locks {
        let held = holds(lock);
        if lock.exclusive {
            if !held {
                return Some(&lock.root);
            }
        } else if held {
            held_shared = true;
        } else {
            missing_shared.get_or_insert(lock.root.as_str());
        }
    }
    missing_shared.filter(|_| !held_shared && !inherited_shared())
}

const LOCK_COLS: &str =
    "token, root, depth_inf, scope, owner_xml, principal, timeout_secs, expires_at";

fn lock_of(row: &[Val]) -> Lock {
    Lock {
        token: row[0].text(),
        root: row[1].text(),
        depth_inf: row[2].int() != 0,
        exclusive: row[3].text() == "exclusive",
        owner_xml: row[4].opt_text(),
        principal: row[5].text(),
        timeout_secs: u32::try_from(row[6].int()).unwrap_or(0),
        expires_at: row[7].int(),
    }
}

impl<S: Sql> Engine<'_, S> {
    pub fn init(&self) -> Result<(), String> {
        for stmt in SCHEMA {
            self.sql.exec(stmt, &[])?;
        }
        Ok(())
    }

    fn purge(&self) -> Result<(), String> {
        let now = Val::Int(self.now);
        self.sql.exec(
            "DELETE FROM locks WHERE expires_at <= ?1",
            std::slice::from_ref(&now),
        )?;
        self.sql.exec(
            "DELETE FROM write_leases WHERE expires_at <= ?1",
            std::slice::from_ref(&now),
        )?;
        self.sql.exec(
            "DELETE FROM mutation_reservations WHERE expires_at <= ?1",
            std::slice::from_ref(&now),
        )?;
        self.sql
            .exec("DELETE FROM moved_capacity WHERE expires_at <= ?1", &[now])?;
        Ok(())
    }

    /// Runs a batch.
    pub fn run(&self, ops: Vec<Op>) -> Result<Vec<Reply>, String> {
        self.init()?;
        self.purge()?;
        ops.into_iter().map(|op| self.one(op)).collect()
    }

    /// Locks that cover `path`: rooted at it, or depth infinity above it
    /// (one indexed lookup per segment).
    pub fn covering(&self, path: &str) -> Result<Vec<Lock>, String> {
        // The ancestors go as one JSON parameter: a deep path must not
        // run into the limit on bound parameters of a statement.
        let above: Vec<&str> = ancestors(path).filter(|&a| a != path).collect();
        let above = serde_json::to_string(&above).map_err(|e| e.to_string())?;
        let rows = self.sql.exec(
            &format!(
                "SELECT {LOCK_COLS} FROM locks WHERE root = ?1 \
                 OR (depth_inf = 1 AND root IN (SELECT value FROM json_each(?2)))"
            ),
            &[t(path), t(&above)],
        )?;
        Ok(rows.iter().map(|r| lock_of(r)).collect())
    }

    /// Check each affected resource independently, including each lock
    /// root under a recursive operation.
    fn blocked(
        &self,
        checks: &[Check],
        tokens: &[String],
        principal: &str,
    ) -> Result<Option<String>, String> {
        let tokens: HashSet<&str> = tokens.iter().map(String::as_str).collect();
        let holds =
            |lock: &Lock| lock.principal == principal && tokens.contains(lock.token.as_str());
        for check in checks {
            let covering = self.covering(&check.path)?;
            if let Some(root) = blocking_lock(&covering, holds, || false) {
                return Ok(Some(root.to_owned()));
            }
            if check.scope != Scope::Tree || (!check.path.is_empty() && !check.path.ends_with('/'))
            {
                continue;
            }
            // Scope::Tree includes descendants even if no lock is rooted
            // at their exact path. A depth-zero token can satisfy the
            // check above but cannot authorize the inherited lock scope.
            if let Some(root) =
                blocking_lock(covering.iter().filter(|l| l.depth_inf), holds, || false)
            {
                return Ok(Some(root.to_owned()));
            }
            let mut under = self.under(&check.path)?;
            under.sort_unstable_by(|a, b| a.root.cmp(&b.root));
            let inherited: HashSet<&str> = covering
                .iter()
                .chain(&under)
                .filter(|lock| lock.depth_inf && !lock.exclusive && holds(lock))
                .map(|lock| lock.root.as_str())
                .collect();
            // Ancestor exclusive locks are checked at their own root (or
            // already cover the checked path). Only authorized depth-infinity
            // shared locks can satisfy the requirement at a descendant root.
            for rooted in under.chunk_by(|a, b| a.root == b.root) {
                let holds_ancestor = || ancestors(&rooted[0].root).any(|p| inherited.contains(p));
                let blocked = blocking_lock(rooted, holds, holds_ancestor).or_else(|| {
                    blocking_lock(rooted.iter().filter(|l| l.depth_inf), holds, holds_ancestor)
                });
                if let Some(root) = blocked {
                    return Ok(Some(root.to_owned()));
                }
            }
        }
        Ok(None)
    }

    /// Locks rooted strictly under the collection `path`.
    fn under(&self, path: &str) -> Result<Vec<Lock>, String> {
        let rows = match range_end(path) {
            Some(end) => self.sql.exec(
                &format!("SELECT {LOCK_COLS} FROM locks WHERE root > ?1 AND root < ?2"),
                &[t(path), t(&end)],
            )?,
            None if path.is_empty() => self.sql.exec(
                &format!("SELECT {LOCK_COLS} FROM locks WHERE root <> ''"),
                &[],
            )?,
            None => Vec::new(),
        };
        Ok(rows.iter().map(|r| lock_of(r)).collect())
    }

    /// Whether a lease of another holder overlaps a new lock on `root`.
    fn lease_in_the_way(
        &self,
        root: &str,
        depth_inf: bool,
        holder: Option<&str>,
    ) -> Result<bool, String> {
        let rows = self
            .sql
            .exec("SELECT holder, path, recursive FROM write_leases", &[])?;
        Ok(rows.iter().any(|r| {
            let (h, p, rec) = (r[0].text(), r[1].text(), r[2].int() != 0);
            holder != Some(h.as_str())
                && (p == root || (depth_inf && within(root, &p)) || (rec && within(&p, root)))
        }))
    }

    fn one(&self, op: Op) -> Result<Reply, String> {
        match op {
            Op::Discover { paths } => {
                let mut out = Vec::with_capacity(paths.len());
                for p in &paths {
                    out.push(self.covering(p)?);
                }
                Ok(Reply::Locks(out))
            }
            Op::Lock {
                token,
                root,
                depth_inf,
                exclusive,
                owner_xml,
                principal,
                timeout_secs,
                holder,
                checks,
                tokens,
            } => {
                if owner_xml
                    .as_ref()
                    .is_some_and(|o| o.len() > MAX_OWNER_BYTES)
                {
                    return Ok(Reply::Full);
                }
                if let Some(path) = self.blocked(&checks, &tokens, &principal)? {
                    return Ok(Reply::Conflict { path });
                }
                let depth_inf = depth_inf && (root.is_empty() || root.ends_with('/'));
                let mut seen = self.covering(&root)?;
                if depth_inf {
                    seen.extend(self.under(&root)?);
                }
                if let Some(other) = seen.iter().find(|l| exclusive || l.exclusive) {
                    return Ok(Reply::Conflict {
                        path: other.root.clone(),
                    });
                }
                if self.lease_in_the_way(&root, depth_inf, holder.as_deref())? {
                    return Ok(Reply::Conflict { path: root });
                }
                let total = self.sql.exec("SELECT count(*) FROM locks", &[])?;
                let mine = self.sql.exec(
                    "SELECT count(*) FROM locks WHERE principal = ?1",
                    &[t(&principal)],
                )?;
                if total[0][0].int() >= MAX_LOCKS_PER_BUCKET
                    || mine[0][0].int() >= MAX_LOCKS_PER_KEY
                {
                    return Ok(Reply::Full);
                }
                let lock = Lock {
                    token,
                    root,
                    depth_inf,
                    exclusive,
                    owner_xml,
                    principal,
                    timeout_secs,
                    expires_at: self.now + i64::from(timeout_secs),
                };
                self.sql.exec(
                    &format!("INSERT INTO locks ({LOCK_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"),
                    &[
                        t(&lock.token),
                        t(&lock.root),
                        Val::Int(i64::from(lock.depth_inf)),
                        t(if lock.exclusive {
                            "exclusive"
                        } else {
                            "shared"
                        }),
                        lock.owner_xml.as_deref().map_or(Val::Null, t),
                        t(&lock.principal),
                        Val::Int(i64::from(lock.timeout_secs)),
                        Val::Int(lock.expires_at),
                    ],
                )?;
                Ok(Reply::Locked(lock))
            }
            Op::Refresh {
                path,
                tokens,
                principal,
                timeout_secs,
            } => {
                let covering = self.covering(&path)?;
                let Some(lock) = covering.into_iter().find(|l| tokens.contains(&l.token)) else {
                    return Ok(Reply::NoLock);
                };
                if lock.principal != principal {
                    return Ok(Reply::NotOwner);
                }
                let expires_at = self.now + i64::from(timeout_secs);
                self.sql.exec(
                    "UPDATE locks SET timeout_secs = ?2, expires_at = ?3 WHERE token = ?1",
                    &[
                        t(&lock.token),
                        Val::Int(i64::from(timeout_secs)),
                        Val::Int(expires_at),
                    ],
                )?;
                Ok(Reply::Locked(Lock {
                    timeout_secs,
                    expires_at,
                    ..lock
                }))
            }
            Op::Unlock {
                path,
                token,
                principal,
            } => {
                let covering = self.covering(&path)?;
                let Some(lock) = covering.into_iter().find(|l| l.token == token) else {
                    return Ok(Reply::NoLock);
                };
                if lock.principal != principal {
                    return Ok(Reply::NotOwner);
                }
                self.sql
                    .exec("DELETE FROM locks WHERE token = ?1", &[t(&lock.token)])?;
                Ok(Reply::Done)
            }
            Op::BeginWrite {
                checks,
                tokens,
                principal,
                holder,
                ttl_secs,
            } => {
                if let Some(path) = self.blocked(&checks, &tokens, &principal)? {
                    return Ok(Reply::Conflict { path });
                }
                let expires = Val::Int(self.now + i64::from(ttl_secs));
                for check in &checks {
                    self.sql.exec(
                        "INSERT OR REPLACE INTO write_leases (holder, path, recursive, expires_at) \
                         VALUES (?1, ?2, ?3, ?4)",
                        &[
                            t(&holder),
                            t(&check.path),
                            Val::Int(i64::from(check.scope == Scope::Tree)),
                            expires.clone(),
                        ],
                    )?;
                }
                Ok(Reply::Granted)
            }
            Op::Reserve {
                holder,
                roots,
                ttl_secs,
            } => {
                for row in self.sql.exec(
                    "SELECT path, recursive FROM mutation_reservations WHERE holder <> ?1",
                    &[t(&holder)],
                )? {
                    let path = row[0].text();
                    if roots.iter().any(|(root, recursive)| {
                        root == &path
                            || (*recursive && within(root, &path))
                            || (row[1].int() != 0 && within(&path, root))
                    }) {
                        return Ok(Reply::Busy);
                    }
                }
                for (root, recursive) in roots {
                    self.sql.exec(
                        "INSERT OR REPLACE INTO mutation_reservations VALUES (?1, ?2, ?3, ?4)",
                        &[
                            t(&holder),
                            t(&root),
                            Val::Int(i64::from(recursive)),
                            Val::Int(self.now + i64::from(ttl_secs)),
                        ],
                    )?;
                }
                Ok(Reply::Granted)
            }
            Op::RenewWrite { holder, ttl_secs } => {
                let leased = !self
                    .sql
                    .exec(
                        "SELECT 1 FROM write_leases WHERE holder = ?1 LIMIT 1",
                        &[t(&holder)],
                    )?
                    .is_empty();
                if !leased || !self.live_reservation(&holder)? {
                    return Ok(Reply::Lost);
                }
                let expires_at = self.now + i64::from(ttl_secs);
                let params = [t(&holder), Val::Int(expires_at)];
                for table in ["write_leases", "mutation_reservations", "moved_capacity"] {
                    self.sql.exec(
                        &format!("UPDATE {table} SET expires_at = ?2 WHERE holder = ?1"),
                        &params,
                    )?;
                }
                Ok(Reply::Renewed { expires_at })
            }
            Op::EndWrite { holder } => {
                for table in ["write_leases", "mutation_reservations", "moved_capacity"] {
                    self.sql.exec(
                        &format!("DELETE FROM {table} WHERE holder = ?1"),
                        &[t(&holder)],
                    )?;
                }
                Ok(Reply::Done)
            }
            Op::DropLocks { path, tree } => {
                self.sql
                    .exec("DELETE FROM locks WHERE root = ?1", &[t(&path)])?;
                if tree {
                    for l in self.under(&path)? {
                        self.sql
                            .exec("DELETE FROM locks WHERE token = ?1", &[t(&l.token)])?;
                    }
                }
                Ok(Reply::Done)
            }
            Op::PropGet {
                paths,
                names,
                names_only,
            } => {
                let mut out = Vec::with_capacity(paths.len());
                let mut remaining = MAX_PROPFIND_PROP_BYTES;
                let select = if names_only {
                    "SELECT ns, name, '' FROM dav_props WHERE path = ?1 AND etag IS ?2 ORDER BY ns, name"
                } else {
                    "SELECT ns, name, value_xml FROM dav_props \
                     WHERE path = ?1 AND etag IS ?2 ORDER BY ns, name"
                };
                // Read one resource at a time; propname does not read XML.
                for (path, etag) in &paths {
                    let rows = self
                        .sql
                        .exec(select, &[t(path), etag.as_deref().map_or(Val::Null, t)])?;
                    let mut props = Vec::new();
                    for row in rows {
                        let Ok([Val::Text(ns), Val::Text(name), Val::Text(xml)]) =
                            <[Val; 3]>::try_from(row)
                        else {
                            return Err("invalid dead property row".into());
                        };
                        if names.as_ref().is_some_and(|n| {
                            !n.iter()
                                .any(|(want_ns, want_name)| want_ns == &ns && want_name == &name)
                        }) {
                            continue;
                        }
                        let bytes = if names_only {
                            ns.len() + name.len()
                        } else {
                            xml.len()
                        };
                        let Some(left) = remaining.checked_sub(bytes) else {
                            return Ok(Reply::Full);
                        };
                        remaining = left;
                        props.push(DeadProp { ns, name, xml });
                    }
                    out.push(props);
                }
                Ok(Reply::Props(out))
            }
            Op::PropPatch {
                path,
                etag,
                patches,
            } => self.patch(&path, etag.as_deref(), &patches),
            Op::PropCopy {
                from,
                to,
                tree,
                from_etag,
                to_etag,
            } => {
                self.prop_drop(&to, tree)?;
                let rows = self.prop_rows(&from, tree, from_etag.as_deref())?;
                for r in rows {
                    let path = r[0].text();
                    let dest = format!("{to}{}", &path[from.len()..]);
                    let stamp = if path == from {
                        to_etag.as_deref().map_or(Val::Null, t)
                    } else {
                        r[4].clone()
                    };
                    self.sql.exec(
                        "INSERT OR REPLACE INTO dav_props (path, ns, name, value_xml, etag) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        &[t(&dest), r[1].clone(), r[2].clone(), r[3].clone(), stamp],
                    )?;
                }
                Ok(Reply::Done)
            }
            Op::PropDrop { path, tree } => {
                self.prop_drop(&path, tree)?;
                Ok(Reply::Done)
            }
            Op::PropRestamp { path, from, to } => {
                // Leave other stamps alone. A write lease blocks new LOCKs,
                // not other saves, so a different stamp might be newer.
                self.sql.exec(
                    "UPDATE dav_props SET etag = ?3 WHERE path = ?1 AND etag = ?2",
                    &[t(&path), t(&from), t(&to)],
                )?;
                Ok(Reply::Done)
            }
            Op::PropCopyFolders { from, to, members } => {
                self.copy_folder_props(&from, &to, members)?;
                Ok(Reply::Done)
            }
            Op::ReserveMoved {
                holder,
                destinations,
                ttl_secs,
            } => {
                if !self.live_reservation(&holder)? {
                    return Ok(Reply::Busy);
                }
                let used = self.sql.exec(
                    "SELECT (SELECT count(*) FROM moved_members) + \
                            (SELECT coalesce(sum(amount), 0) FROM moved_capacity WHERE holder <> ?1)",
                    &[t(&holder)],
                )?[0][0].int();
                let missing = self.missing_moved_keys(&destinations)?;
                if used + missing > MAX_MOVED_MEMBERS_PER_BUCKET {
                    return Ok(Reply::Full);
                }
                self.sql.exec(
                    "INSERT OR REPLACE INTO moved_capacity VALUES (?1, ?2, ?3)",
                    &[
                        t(&holder),
                        Val::Int(missing),
                        Val::Int(self.now + i64::from(ttl_secs)),
                    ],
                )?;
                Ok(Reply::Granted)
            }
            Op::RecordMoved { holder, members } => {
                if let Some(holder) = &holder {
                    if !self.live_reservation(holder)?
                        || self
                            .sql
                            .exec(
                                "SELECT 1 FROM moved_capacity WHERE holder = ?1",
                                &[t(holder)],
                            )?
                            .is_empty()
                    {
                        return Ok(Reply::Busy);
                    }
                }
                let keys: Vec<_> = members.iter().map(|m| m.destination.as_str()).collect();
                let used = self.sql.exec("SELECT count(*) FROM moved_members", &[])?[0][0].int();
                if used + self.missing_moved_keys(&keys)? > MAX_MOVED_MEMBERS_PER_BUCKET {
                    return Ok(Reply::Full);
                }
                for chunk in members.chunks(MOVED_MEMBER_SQL_BATCH) {
                    let json = serde_json::to_string(chunk).map_err(|e| e.to_string())?;
                    self.sql.exec(
                        "INSERT OR REPLACE INTO moved_members (destination, etag, source) \
                         SELECT json_extract(value, '$.destination'), json_extract(value, '$.etag'), \
                                json_extract(value, '$.source') FROM json_each(?1)",
                        &[Val::Text(json)],
                    )?;
                }
                if let Some(holder) = holder {
                    self.sql.exec(
                        "DELETE FROM moved_capacity WHERE holder = ?1",
                        &[t(&holder)],
                    )?;
                }
                Ok(Reply::Done)
            }
            Op::FindMoved {
                holder,
                root,
                listed,
                exact,
            } => {
                if !self.live_reservation(&holder)? {
                    return Ok(Reply::Busy);
                }
                let mut rows = Vec::new();
                if let Some(root) = root {
                    let end = range_end(&root).ok_or("not a collection")?;
                    rows.extend(self.sql.exec(
                        "SELECT destination, etag, source FROM moved_members WHERE destination >= ?1 AND destination < ?2",
                        &[t(&root), t(&end)],
                    )?);
                }
                if let Some((key, _)) = &exact {
                    rows.extend(self.sql.exec(
                        "SELECT destination, etag, source FROM moved_members WHERE destination = ?1",
                        &[t(key)],
                    )?);
                }
                let listed: std::collections::HashMap<_, _> =
                    listed.into_iter().chain(exact).collect();
                let mut kept = Vec::new();
                let mut stale = Vec::new();
                for row in rows {
                    let key = row[0].text();
                    if listed.get(&key).is_some_and(|etag| *etag == row[1].text()) {
                        kept.push((key, row[2].text()));
                    } else {
                        stale.push(key);
                    }
                }
                self.one(Op::ClearMoved(stale))?;
                Ok(Reply::Moved(kept))
            }
            Op::FoldersWithState { roots, limit } => {
                let mut stateful = std::collections::BTreeSet::new();
                let cap = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
                for root in roots {
                    // Indexed range lookups. `rtrim(p, replace(p, '/', ''))`
                    // is `p` up to its last '/': a collection itself, or the
                    // collection a file is in.
                    let end = range_end(&root).ok_or("not a collection")?;
                    for query in [
                        "SELECT DISTINCT rtrim(root, replace(root, '/', '')) FROM locks \
                         WHERE root >= ?1 AND root < ?2 LIMIT ?3",
                        "SELECT DISTINCT rtrim(path, replace(path, '/', '')) FROM dav_props \
                         WHERE path >= ?1 AND path < ?2 LIMIT ?3",
                    ] {
                        let rows = self.sql.exec(query, &[t(&root), t(&end), Val::Int(cap)])?;
                        stateful.extend(rows.into_iter().map(|row| row[0].text()));
                        if stateful.len() > limit {
                            return Ok(Reply::Full);
                        }
                    }
                }
                Ok(Reply::StatefulFolders(stateful.into_iter().collect()))
            }
            Op::FinishMove(members) => {
                for chunk in members.chunks(MOVED_MEMBER_SQL_BATCH) {
                    let json = serde_json::to_string(chunk).map_err(|e| e.to_string())?;
                    self.sql.exec(
                        "DELETE FROM moved_members WHERE destination IN (\
                           SELECT m.destination FROM json_each(?1) AS candidate \
                           JOIN moved_members AS m ON m.destination = json_extract(candidate.value, '$.destination') \
                            AND m.etag = json_extract(candidate.value, '$.etag') \
                            AND m.source = json_extract(candidate.value, '$.source'))",
                        &[Val::Text(json)],
                    )?;
                }
                Ok(Reply::Done)
            }
            Op::FinishMoveTree { src_root, dst_root } => {
                let src_end = range_end(&src_root).ok_or("not a source collection")?;
                let dst_end = range_end(&dst_root).ok_or("not a destination collection")?;
                // Only the same move: the same path below each root, so a
                // row from a move with another mapping stays protected.
                self.sql.exec(
                    "DELETE FROM moved_members WHERE destination >= ?1 AND destination < ?2 \
                     AND source >= ?3 AND source < ?4 \
                     AND substr(destination, length(?1) + 1) = substr(source, length(?3) + 1)",
                    &[t(&dst_root), t(&dst_end), t(&src_root), t(&src_end)],
                )?;
                Ok(Reply::Done)
            }
            Op::ClearMoved(paths) => {
                for chunk in paths.chunks(MOVED_MEMBER_SQL_BATCH) {
                    let json = serde_json::to_string(chunk).map_err(|e| e.to_string())?;
                    self.sql.exec(
                        "DELETE FROM moved_members WHERE destination IN (SELECT value FROM json_each(?1))",
                        &[Val::Text(json)],
                    )?;
                }
                Ok(Reply::Done)
            }
        }
    }

    fn live_reservation(&self, holder: &str) -> Result<bool, String> {
        Ok(!self
            .sql
            .exec(
                "SELECT 1 FROM mutation_reservations WHERE holder = ?1 LIMIT 1",
                &[t(holder)],
            )?
            .is_empty())
    }

    fn missing_moved_keys<T: Serialize>(&self, keys: &[T]) -> Result<i64, String> {
        let mut missing = 0;
        for chunk in keys.chunks(MOVED_MEMBER_SQL_BATCH) {
            let json = serde_json::to_string(chunk).map_err(|e| e.to_string())?;
            missing += self.sql.exec(
                "SELECT count(*) FROM json_each(?1) AS k WHERE NOT EXISTS \
                 (SELECT 1 FROM moved_members WHERE destination = k.value)",
                &[Val::Text(json)],
            )?[0][0]
                .int();
        }
        Ok(missing)
    }

    fn copy_folder_props(
        &self,
        from: &str,
        to: &str,
        mut members: Vec<String>,
    ) -> Result<(), String> {
        members.sort_unstable();
        // Look up only existing property paths, not every ancestor of every
        // copied key. The successful keys tell us which collections exist.
        let mut copied = HashSet::new();
        for root in [from, to] {
            let end = range_end(root).ok_or("not a collection")?;
            for row in self.sql.exec(
                "SELECT DISTINCT path FROM dav_props WHERE path >= ?1 AND path < ?2 AND etag IS NULL",
                &[t(root), t(&end)],
            )? {
                let path = row[0].text();
                let suffix = &path[root.len()..];
                let dest = format!("{to}{suffix}");
                if crate::path::has_prefix_member(&members, &dest) {
                    copied.insert(suffix.to_owned());
                }
            }
        }
        for suffix in copied {
            let src = format!("{from}{suffix}");
            let dest = format!("{to}{suffix}");
            self.prop_drop(&dest, false)?;
            self.sql.exec(
                "INSERT INTO dav_props (path, ns, name, value_xml, etag) \
                 SELECT ?2, ns, name, value_xml, NULL FROM dav_props WHERE path = ?1 AND etag IS NULL",
                &[t(&src), t(&dest)],
            )?;
        }
        Ok(())
    }

    fn prop_rows(
        &self,
        path: &str,
        tree: bool,
        etag: Option<&str>,
    ) -> Result<Vec<Vec<Val>>, String> {
        let mut rows = self.sql.exec(
            "SELECT path, ns, name, value_xml, etag FROM dav_props WHERE path = ?1 AND etag IS ?2",
            &[t(path), etag.map_or(Val::Null, t)],
        )?;
        if tree {
            match range_end(path) {
                Some(end) => rows.extend(self.sql.exec(
                    "SELECT path, ns, name, value_xml, etag FROM dav_props \
                     WHERE path > ?1 AND path < ?2 AND etag IS NULL",
                    &[t(path), t(&end)],
                )?),
                None if path.is_empty() => rows.extend(self.sql.exec(
                    "SELECT path, ns, name, value_xml, etag FROM dav_props WHERE path <> '' AND etag IS NULL",
                    &[],
                )?),
                None => {}
            }
        }
        Ok(rows)
    }

    fn prop_drop(&self, path: &str, tree: bool) -> Result<(), String> {
        self.sql
            .exec("DELETE FROM dav_props WHERE path = ?1", &[t(path)])?;
        if tree {
            match range_end(path) {
                Some(end) => {
                    self.sql.exec(
                        "DELETE FROM dav_props WHERE path > ?1 AND path < ?2",
                        &[t(path), t(&end)],
                    )?;
                }
                None if path.is_empty() => {
                    self.sql.exec("DELETE FROM dav_props", &[])?;
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Reclaim mismatched rows before replacing properties under the write lease.
    fn drop_stale(&self, path: &str, etag: Option<&str>) -> Result<(), String> {
        self.sql.exec(
            "DELETE FROM dav_props WHERE path = ?1 AND etag IS NOT ?2",
            &[t(path), etag.map_or(Val::Null, t)],
        )?;
        Ok(())
    }

    fn patch(&self, path: &str, etag: Option<&str>, patches: &[Patch]) -> Result<Reply, String> {
        self.drop_stale(path, etag)?;
        let rows = self.sql.exec(
            "SELECT ns, name, length(value_xml) FROM dav_props WHERE path = ?1",
            &[t(path)],
        )?;
        let mut sizes: Vec<((String, String), usize)> = rows
            .iter()
            .map(|r| {
                (
                    (r[0].text(), r[1].text()),
                    usize::try_from(r[2].int()).unwrap_or(0),
                )
            })
            .collect();
        // Apply to the sizes first: all or nothing.
        let mut status = vec![200u16; patches.len()];
        let mut failed = false;
        for (i, p) in patches.iter().enumerate() {
            match p {
                Patch::Set(prop) => {
                    let key = (prop.ns.clone(), prop.name.clone());
                    sizes.retain(|(k, _)| *k != key);
                    sizes.push((key, prop.xml.len()));
                    let total: usize = sizes.iter().map(|(_, s)| s).sum();
                    if prop.xml.len() > MAX_PROP_BYTES || total > MAX_PROPS_PER_RESOURCE {
                        status[i] = 507;
                        failed = true;
                    }
                }
                Patch::Remove { ns, name } => {
                    sizes.retain(|((n, m), _)| !(n == ns && m == name));
                }
            }
        }
        if failed {
            for s in &mut status {
                if *s == 200 {
                    *s = 424;
                }
            }
            return Ok(Reply::Patched(status));
        }
        for p in patches {
            match p {
                Patch::Set(prop) => {
                    self.sql.exec(
                        "INSERT OR REPLACE INTO dav_props (path, ns, name, value_xml, etag) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        &[
                            t(path),
                            t(&prop.ns),
                            t(&prop.name),
                            t(&prop.xml),
                            etag.map_or(Val::Null, t),
                        ],
                    )?;
                }
                Patch::Remove { ns, name } => {
                    self.sql.exec(
                        "DELETE FROM dav_props WHERE path = ?1 AND ns = ?2 AND name = ?3",
                        &[t(path), t(ns), t(name)],
                    )?;
                }
            }
        }
        Ok(Reply::Patched(status))
    }
}
