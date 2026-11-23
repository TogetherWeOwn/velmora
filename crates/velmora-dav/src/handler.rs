//! The WebDAV methods (RFC 4918 classes 1, 2 and 3) over the S3 calls of
//! [`crate::s3`] and the bucket state of [`crate::state`].

use std::collections::{HashMap, HashSet};

use base64::Engine;
use futures_util::future::{join_all, select, Either, LocalBoxFuture};
use futures_util::stream::{self, StreamExt};
use velmora_s3_proto::storable_key;

use crate::http::{header, Body, Request, Response};
use crate::ifhdr::{self, IfHeader};
use crate::path::{self, as_collection, as_file, parent, Loc, PathError};
use crate::props::{self, Resource, LIVE};
use crate::s3::{Cond, Entry, Meta, S3Error, Upstream, S3};
use crate::sigv4::Credentials;
use crate::slots::Slot;
use crate::state::{Check, DeadProp, Lock, MovedMember, Op, Patch, Reply, Scope};
use crate::xml::{self, Element, DAV};

/// The prefix of an app password's id (velmora_bridge::entry). An S3 key
/// is refused here before anything is sent; the storage Worker refuses
/// it again on the WebDAV entry point.
pub const APP_PASSWORD_PREFIX: &str = "APVL";

/// The way to a bucket's `DavState` object.
pub trait StatePort {
    /// Runs a batch of operations on the object named `name`.
    fn call<'a>(
        &'a self,
        name: &'a str,
        ops: Vec<Op>,
    ) -> LocalBoxFuture<'a, Result<Vec<Reply>, String>>;
}

/// Settings. Every limit names the mechanism it comes from.
#[derive(Clone, Debug)]
pub struct Config {
    /// The host the storage Worker answers for (its `S3_HOST`).
    pub s3_host: String,
    pub region: String,
    /// The tenant the gateway serves; today there is one. The name of a
    /// bucket's state object starts with it, so serving more tenants (a
    /// gateway each, or a lookup by app password) changes no stored name.
    pub tenant: String,
    /// Part size of an upload sent in parts: the storage Worker's extent
    /// (MAX_EXTENT_BYTES, 16 MiB), so each part is one extent; a single
    /// PutObject above it is stored in half-size slices.
    pub part_bytes: usize,
    /// Parts held in memory at once, across every upload of the isolate
    /// ([`crate::slots`]): a part costs its 16 MiB and the runtime's copy
    /// while it is sent, so two are 64 MiB of the isolate's 128 MB. Two
    /// is also within the storage Worker's per-isolate request budget
    /// (INFLIGHT_BUDGET_BYTES, 48 MiB, three parts).
    pub parts_in_flight: usize,
    /// Copies or deletes at once: the Workers limit of six simultaneous
    /// open connections per invocation.
    pub fan_out: usize,
    /// Most keys a collection COPY, MOVE or DELETE handles in one request.
    /// Each key is one or two storage calls at six at a time, and the
    /// client waits for all of them in one request: 2,000 keys is minutes
    /// of work, which is as long as clients wait. Larger folders are moved
    /// with an S3 tool.
    pub max_tree: usize,
    /// Most storage and state calls one COPY, MOVE or DELETE plans:
    /// copies, deletes, folder probes and renewals. A plan over it is
    /// refused with `507` before any change. The Workers paid plan
    /// allows 10,000 subrequests an invocation; this leaves room for
    /// the calls around the plan.
    pub max_mutation_calls: usize,
    /// Keys of one DeleteObjects call in a collection DELETE. Each call
    /// must settle within a quarter lease (see `lease_secs`); the
    /// storage Worker works on four chunks of 50 keys at a time, so 200
    /// keys are one round of its work rather than five.
    pub delete_keys: usize,
    /// Most entries a Depth 1 PROPFIND lists: its multistatus is built in
    /// memory, about 400 bytes an entry, and 50,000 is 20 MB of the
    /// isolate's 128 MB.
    pub max_listing: usize,
    /// Largest XML request body (PROPFIND, PROPPATCH, LOCK): dead
    /// properties are capped at 256 KiB per resource.
    pub max_xml_body: usize,
    pub lock_default_secs: u32,
    pub lock_max_secs: u32,
    /// Lifetime of a write lease and mutation reservation; renewed every
    /// third of it while the write runs, and before every batch of
    /// storage mutations of a collection operation. Each call of such a
    /// batch is given a quarter of it.
    pub lease_secs: u32,
    /// The realm of the Basic challenge: the name a client shows when it
    /// asks for the login.
    pub realm: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            s3_host: "s3.invalid".into(),
            region: "auto".into(),
            tenant: "t0".into(),
            part_bytes: 16 * 1024 * 1024,
            parts_in_flight: 2,
            fan_out: 6,
            max_tree: 2_000,
            max_mutation_calls: 9_000,
            delete_keys: 200,
            max_listing: 50_000,
            max_xml_body: 1024 * 1024,
            lock_default_secs: 600,
            lock_max_secs: 3_600,
            lease_secs: 30,
            realm: "WebDAV".into(),
        }
    }
}

pub struct Dav<U: Upstream, S: StatePort> {
    pub up: U,
    pub state: S,
    pub cfg: Config,
}

type Resp<B> = Response<B>;
type Out<B> = Result<Response<B>, Response<B>>;

const ALLOW: &str =
    "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK";

fn status<B>(code: u16) -> Resp<B> {
    Response::new(code).with_header("content-length", "0")
}

fn xml_resp<B>(code: u16, body: Vec<u8>) -> Resp<B> {
    Response::new(code).with_bytes("application/xml; charset=utf-8", body)
}

fn precondition<B>(code: u16, inner: &str) -> Resp<B> {
    xml_resp(code, props::error_body(inner))
}

fn locked<B>(bucket: &str, path: &str) -> Resp<B> {
    precondition(
        423,
        &format!(
            "<D:lock-token-submitted><D:href>{}</D:href></D:lock-token-submitted>",
            xml::escape_text(&path::href(bucket, path))
        ),
    )
}

/// The client answer for an S3 refusal.
fn from_s3<B>(e: &S3Error) -> Resp<B> {
    let code = match e.code.as_str() {
        "InvalidAccessKeyId" | "SignatureDoesNotMatch" => 401,
        "AccessDenied" => 403,
        "NoSuchBucket" | "NoSuchKey" | "NoSuchUpload" => 404,
        "PreconditionFailed" => 412,
        "EntityTooLarge" => 413,
        "InvalidRange" => 416,
        "SlowDown" | "ServiceUnavailable" => 503,
        "NotImplemented" => 501,
        _ => match e.status {
            401 => 401,
            403 => 403,
            404 => 404,
            412 => 412,
            503 => 503,
            0 => 502,
            s if s >= 500 => 502,
            s => s,
        },
    };
    if code == 401 {
        return unauthorized();
    }
    let mut r = status(code);
    if code == 503 {
        r.set_header("retry-after", "1");
    }
    r
}

/// `401`; [`Dav::handle`] adds the challenge with the configured realm.
fn unauthorized<B>() -> Resp<B> {
    status(401)
}

/// `user:password` of a Basic authorization.
pub fn basic_credentials(value: &str) -> Option<Credentials> {
    let (scheme, rest) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, pass) = text.split_once(':')?;
    if user.is_empty() || pass.is_empty() {
        return None;
    }
    Some(Credentials {
        access_key: user.to_owned(),
        secret: pass.to_owned(),
    })
}

/// What a URL resolved to.
#[derive(Clone, Debug)]
enum Res {
    Bucket,
    File(Meta),
    /// A collection; `key` in collection form.
    Coll {
        key: String,
    },
    Missing,
}

impl Res {
    fn exists(&self) -> bool {
        !matches!(self, Res::Missing)
    }
}

/// One request's context: its app password and its bucket.
struct Ctx<'a, U: Upstream, S: StatePort> {
    dav: &'a Dav<U, S>,
    s3: S3<'a, U>,
    principal: String,
    origin: String,
}

fn depth(req_headers: &[(String, String)]) -> Result<Option<u8>, ()> {
    // `None` = infinity.
    match header(req_headers, "depth").map(str::trim) {
        None => Ok(None),
        Some("0") => Ok(Some(0)),
        Some("1") => Ok(Some(1)),
        Some(v) if v.eq_ignore_ascii_case("infinity") => Ok(None),
        Some(_) => Err(()),
    }
}

/// The DavState path of a resolved resource.
fn state_path(res: &Res, key: &str) -> String {
    match res {
        Res::Bucket => String::new(),
        Res::File(_) => as_file(key).to_owned(),
        Res::Coll { key } => key.clone(),
        Res::Missing => key.to_owned(),
    }
}

/// The path of a URL taken from a header (`Destination`, an `If` tag):
/// an absolute URL on this origin, or an absolute path.
fn header_url_path(value: &str, origin: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with('/') && !value.starts_with("//") {
        return Some(value.split(['?', '#']).next()?.to_owned());
    }
    let (scheme, rest) = value.split_once("://")?;
    let (actual_scheme, actual_authority) = origin.split_once("://")?;
    if !scheme.eq_ignore_ascii_case(actual_scheme) {
        return None;
    }
    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        return None;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    if origin_authority(authority, default_port)?
        != origin_authority(actual_authority, default_port)?
    {
        return None;
    }
    let path = path.split(['?', '#']).next()?;
    Some(if path.is_empty() { "/" } else { path }.to_owned())
}

fn origin_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(ip) = authority.strip_prefix('[') {
        let (ip, suffix) = ip.split_once(']')?;
        let host = ip.parse::<std::net::Ipv6Addr>().ok()?.to_string();
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix.strip_prefix(':')?.parse().ok()?
        };
        (host, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (authority, default_port),
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return None;
        }
        (host.to_ascii_lowercase(), port)
    };
    Some((host, port))
}

fn timeout_secs(value: Option<&str>, cfg: &Config) -> u32 {
    let Some(value) = value else {
        return cfg.lock_default_secs;
    };
    for part in value.split(',') {
        let part = part.trim();
        if part.eq_ignore_ascii_case("infinite") {
            return cfg.lock_max_secs;
        }
        if let Some(n) = part
            .strip_prefix("Second-")
            .or_else(|| part.strip_prefix("second-"))
        {
            if let Ok(n) = n.trim().parse::<u64>() {
                return u32::try_from(n.min(u64::from(cfg.lock_max_secs)))
                    .unwrap_or(cfg.lock_max_secs)
                    .max(1);
            }
        }
    }
    cfg.lock_default_secs
}

impl<U: Upstream, S: StatePort> Dav<U, S> {
    /// Answers one request. Every answer carries `nosniff` and a sandbox
    /// policy: a browser that remembers the Basic credentials for the
    /// host must never run a stored page against it.
    pub async fn handle(&self, req: Request<U::Body>) -> Response<U::Body> {
        let mut resp = match self.route(req).await {
            Ok(r) | Err(r) => r,
        };
        if resp.status == 401 {
            let realm = self.cfg.realm.replace(['"', '\\'], "");
            resp.set_header(
                "www-authenticate",
                format!("Basic realm=\"{realm}\", charset=\"UTF-8\""),
            );
        }
        resp.set_header("x-content-type-options", "nosniff");
        resp.set_header("content-security-policy", "sandbox; default-src 'none'");
        if !resp.headers.iter().any(|(n, _)| n == "content-length")
            && matches!(resp.body, Body::Empty)
        {
            resp.set_header("content-length", "0");
        }
        resp
    }

    fn state_name(&self, bucket: &str) -> String {
        format!("{}/{bucket}", self.cfg.tenant)
    }

    async fn route(&self, req: Request<U::Body>) -> Out<U::Body> {
        let method = req.method.to_ascii_uppercase();
        if method == "OPTIONS" {
            return Ok(status(200)
                .with_header("dav", "1, 2, 3")
                .with_header("allow", ALLOW)
                .with_header("ms-author-via", "DAV"));
        }
        let loc = match Loc::parse(&req.path) {
            Ok(l) => l,
            Err(PathError::Bad) => return Err(status(400)),
            Err(PathError::Hidden) => return Err(status(404)),
        };
        let creds = req
            .header("authorization")
            .and_then(basic_credentials)
            .ok_or_else(unauthorized)?;
        if !creds.access_key.starts_with(APP_PASSWORD_PREFIX) {
            return Err(unauthorized());
        }
        let origin = req.origin.clone();
        let ctx = Ctx {
            dav: self,
            s3: S3 {
                up: &self.up,
                creds: &creds,
                host: &self.cfg.s3_host,
                region: &self.cfg.region,
            },
            principal: creds.access_key.clone(),
            origin,
        };
        match method.as_str() {
            "GET" | "HEAD" => ctx.get(&method, &loc, req).await,
            "PROPFIND" => ctx.propfind(&loc, req).await,
            "PUT" => ctx.put(&loc, req).await,
            "DELETE" => ctx.delete(&loc, req).await,
            "MKCOL" => ctx.mkcol(&loc, req).await,
            "COPY" => ctx.copy_move(&loc, req, false).await,
            "MOVE" => ctx.copy_move(&loc, req, true).await,
            "LOCK" => ctx.lock(&loc, req).await,
            "UNLOCK" => ctx.unlock(&loc, req).await,
            "PROPPATCH" => ctx.proppatch(&loc, req).await,
            _ => Err(status(405).with_header("allow", ALLOW)),
        }
    }
}

impl<U: Upstream, S: StatePort> Ctx<'_, U, S> {
    fn cfg(&self) -> &Config {
        &self.dav.cfg
    }

    async fn state(&self, bucket: &str, ops: Vec<Op>) -> Result<Vec<Reply>, Resp<U::Body>> {
        let name = self.dav.state_name(bucket);
        self.dav
            .state
            .call(&name, ops)
            .await
            .map_err(|_| status(503).with_header("retry-after", "1"))
    }

    async fn resolve(&self, bucket: &str, key: &str) -> Result<Res, Resp<U::Body>> {
        if key.is_empty() {
            return match self.s3.bucket_exists(bucket).await {
                Ok(true) => Ok(Res::Bucket),
                Ok(false) => Ok(Res::Missing),
                Err(e) => Err(from_s3(&e)),
            };
        }
        if !key.ends_with('/') {
            if let Some(meta) = self.s3.head(bucket, key).await.map_err(|e| from_s3(&e))? {
                return Ok(Res::File(meta));
            }
        }
        let coll = as_collection(key);
        match self.s3.any_under(bucket, &coll).await {
            Ok(true) => Ok(Res::Coll { key: coll }),
            Ok(false) => Ok(Res::Missing),
            Err(e) if e.is("NoSuchBucket") => Ok(Res::Missing),
            Err(e) => Err(from_s3(&e)),
        }
    }

    /// Whether the collection that would hold `key` exists.
    async fn parent_exists(&self, bucket: &str, key: &str) -> Result<bool, Resp<U::Body>> {
        let p = parent(key);
        if p.is_empty() {
            return self.s3.bucket_exists(bucket).await.map_err(|e| from_s3(&e));
        }
        match self.s3.any_under(bucket, &p).await {
            Ok(b) => Ok(b),
            Err(e) if e.is("NoSuchBucket") => Ok(false),
            Err(e) => Err(from_s3(&e)),
        }
    }

    /// Writes the marker of `coll` when nothing is left under it, so a
    /// folder does not vanish with its last member.
    async fn keep_folder(&self, bucket: &str, coll: &str) {
        if coll.is_empty() {
            return;
        }
        if let Ok(false) = self.s3.any_under(bucket, coll).await {
            let result = self
                .s3
                .put(
                    bucket,
                    coll,
                    Body::Empty,
                    0,
                    "application/x-directory",
                    &[],
                    Some(&Cond::Absent),
                )
                .await;
            if result.is_ok() {
                let _ = self
                    .state(bucket, vec![Op::ClearMoved(vec![coll.to_owned()])])
                    .await;
            }
        }
    }

    fn parse_if(&self, req: &Request<U::Body>) -> Result<Option<IfHeader>, Resp<U::Body>> {
        match req.header("if") {
            None => Ok(None),
            Some(v) => ifhdr::parse(v).map(Some).map_err(|_| status(400)),
        }
    }

    /// Evaluates an `If` header against the request resource and every
    /// tagged one. `412` when it is false; otherwise returns the guard
    /// if the matching list tested the request resource's ETag.
    async fn check_if(
        &self,
        bucket: &str,
        req_path: &str,
        req_res: &Res,
        h: &IfHeader,
    ) -> Result<Option<Cond>, Resp<U::Body>> {
        // The state of each resource the header names.
        let mut targets: Vec<(Option<String>, String, Option<String>)> = Vec::new();
        let req_etag = match req_res {
            Res::File(m) => Some(m.etag.clone()),
            _ => None,
        };
        targets.push((None, req_path.to_owned(), req_etag.clone()));
        for tag in h.tags() {
            let resolved = header_url_path(&tag, &self.origin).and_then(|p| Loc::parse(&p).ok());
            match resolved {
                Some(Loc::Item { bucket: b, key }) if b == bucket => {
                    if key == req_path && req_res.exists() {
                        // A tag for the request resource uses the same snapshot.
                        targets.push((Some(tag), key, req_etag.clone()));
                        continue;
                    }
                    let res = self.resolve(bucket, &key).await?;
                    let etag = match &res {
                        Res::File(m) => Some(m.etag.clone()),
                        _ => None,
                    };
                    let p = state_path(&res, &key);
                    if res.exists() {
                        targets.push((Some(tag.clone()), p, etag));
                    }
                }
                _ => {}
            }
        }
        let replies = self
            .state(
                bucket,
                vec![Op::Discover {
                    paths: targets.iter().map(|(_, p, _)| p.clone()).collect(),
                }],
            )
            .await?;
        let Some(Reply::Locks(locks)) = replies.into_iter().next() else {
            return Err(status(500));
        };
        let states: Vec<_> = targets
            .into_iter()
            .zip(locks)
            .map(|((tag, path, etag), locks)| {
                (
                    tag,
                    path,
                    ifhdr::State {
                        etag,
                        tokens: locks.into_iter().map(|l| l.token).collect(),
                    },
                )
            })
            .collect();
        let lookup = |tag: Option<&str>| states.iter().find(|(t, _, _)| t.as_deref() == tag);
        let list = h
            .matching_list(|tag| lookup(tag).map(|(_, _, s)| s.clone()).unwrap_or_default())
            .ok_or_else(|| status(412))?;
        let guard = lookup(list.tag.as_deref())
            .filter(|(_, p, _)| p == req_path)
            .filter(|_| {
                list.conditions
                    .iter()
                    .any(|c| matches!(c.cond, ifhdr::Cond::ETag(_)))
            })
            .and_then(|(_, _, s)| s.etag.clone())
            .map(Cond::Is);
        Ok(guard)
    }

    /// Checks the locks for a write and takes a lease. Answers the lease
    /// holder, to end it with.
    /// The lock check comes before the `If` evaluation: a locked
    /// resource whose lock was not submitted answers `423`, also when
    /// the `If` header would be false (litmus `cond_put_corrupt_token`).
    /// A false `If` header then ends the lease and answers `412`.
    async fn begin_write(
        &self,
        bucket: &str,
        checks: Vec<Check>,
        h: Option<&IfHeader>,
        target: (&str, &Res),
    ) -> Result<String, Resp<U::Body>> {
        self.begin_write_with_guard(bucket, checks, h, target)
            .await
            .map(|(holder, _)| holder)
    }

    async fn begin_write_with_guard(
        &self,
        bucket: &str,
        checks: Vec<Check>,
        h: Option<&IfHeader>,
        target: (&str, &Res),
    ) -> Result<(String, Option<Cond>), Resp<U::Body>> {
        let holder = self.dav.up.uuid();
        let tokens = h.map(IfHeader::submitted).unwrap_or_default();
        let replies = self
            .state(
                bucket,
                vec![Op::BeginWrite {
                    checks,
                    tokens,
                    principal: self.principal.clone(),
                    holder: holder.clone(),
                    ttl_secs: self.cfg().lease_secs,
                }],
            )
            .await?;
        match replies.into_iter().next() {
            Some(Reply::Granted) => {}
            Some(Reply::Conflict { path }) => {
                // A header that names no lock at all (only `DAV:no-lock`,
                // or only entity tags) and is false is a failed
                // precondition first (litmus `fail_cond_put`).
                if let Some(h) = h {
                    let names_a_lock = h.submitted().iter().any(|t| t != "DAV:no-lock");
                    if !names_a_lock && self.check_if(bucket, target.0, target.1, h).await.is_err()
                    {
                        return Err(status(412));
                    }
                }
                return Err(locked(bucket, &path));
            }
            _ => return Err(status(500)),
        }
        let guard = if let Some(h) = h {
            match self.check_if(bucket, target.0, target.1, h).await {
                Ok(guard) => guard,
                Err(refused) => {
                    self.end_write(bucket, &holder, Vec::new()).await;
                    return Err(refused);
                }
            }
        } else {
            None
        };
        Ok((holder, guard))
    }

    async fn end_write(&self, bucket: &str, holder: &str, more: Vec<Op>) {
        let mut ops = more;
        ops.push(Op::EndWrite {
            holder: holder.to_owned(),
        });
        let _ = self.state(bucket, ops).await;
    }

    /// Fence other DAV mutations while the request plans and changes storage.
    /// Direct S3 writers do not use this state; their races are guarded by ETags.
    async fn reserve(
        &self,
        bucket: &str,
        holder: &str,
        roots: Vec<(String, bool)>,
    ) -> Result<(), Resp<U::Body>> {
        let replies = self
            .state(
                bucket,
                vec![Op::Reserve {
                    holder: holder.to_owned(),
                    roots,
                    ttl_secs: self.cfg().lease_secs,
                }],
            )
            .await?;
        match replies.as_slice() {
            [Reply::Granted] => Ok(()),
            [Reply::Busy] => Err(reservation_busy()),
            _ => Err(status(500)),
        }
    }

    /// Renews the reservation before a batch of storage mutations and
    /// requires at least half a lease left on it, so the batch (each call
    /// bounded by a quarter lease, see [`Ctx::bounded`]) settles while the
    /// reservation still holds. A request that was paused past its
    /// reservation finds it lost here and stops (`503`) before it
    /// dispatches anything more.
    ///
    /// Residual: storage does not check the reservation. A delete that
    /// storage commits more than half a lease (15 s by default) after the
    /// gateway's last successful renewal is not fenced. The airtight fence
    /// is a generation check in storage itself (an ETag names content, not
    /// a version); until it exists the gateway is not enabled for users.
    async fn fence(&self, bucket: &str, holder: &str) -> Result<(), Resp<U::Body>> {
        let lease = self.cfg().lease_secs;
        let replies = self
            .state(
                bucket,
                vec![Op::RenewWrite {
                    holder: holder.to_owned(),
                    ttl_secs: lease,
                }],
            )
            .await
            .map_err(|_| reservation_busy())?;
        match replies.as_slice() {
            [Reply::Renewed { expires_at }]
                if expires_at.saturating_mul(1000) - self.dav.up.now_ms()
                    >= i64::from(lease) * 500 =>
            {
                Ok(())
            }
            _ => Err(reservation_busy()),
        }
    }

    /// One storage call of a mutation batch, given a quarter lease.
    /// `None`: no answer in time, so its outcome is unknown and the batch
    /// dispatches nothing more.
    async fn bounded<T>(&self, call: impl std::future::Future<Output = T>) -> Option<T> {
        let ms = u64::from(self.cfg().lease_secs) * 250;
        match select(std::pin::pin!(call), self.dav.up.sleep(ms)).await {
            Either::Left((out, _)) => Some(out),
            Either::Right(((), _)) => None,
        }
    }

    /// Runs `work` while renewing the lease every third of its life.
    /// `None` when a renewal fails or finds the reservation lost: `work`
    /// is dropped at its next wait, so nothing after that point changes
    /// storage or state.
    async fn under_lease<T>(
        &self,
        bucket: &str,
        holder: &str,
        work: impl std::future::Future<Output = T>,
    ) -> Option<T> {
        let renew = async {
            let every = u64::from(self.cfg().lease_secs) * 1000 / 3;
            loop {
                self.dav.up.sleep(every).await;
                let renewed = self
                    .state(
                        bucket,
                        vec![Op::RenewWrite {
                            holder: holder.to_owned(),
                            ttl_secs: self.cfg().lease_secs,
                        }],
                    )
                    .await;
                if !matches!(renewed.as_deref(), Ok([Reply::Renewed { .. }])) {
                    return;
                }
            }
        };
        let work = std::pin::pin!(work);
        let renew = std::pin::pin!(renew);
        match select(work, renew).await {
            Either::Left((out, _)) => Some(out),
            Either::Right(((), _)) => None,
        }
    }

    /// `403` unless the key may write to the bucket (see
    /// [`S3::can_write`]).
    async fn require_write(&self, bucket: &str, key: &str) -> Result<(), Resp<U::Body>> {
        match self.s3.can_write(bucket, key).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(status(403)),
            Err(e) => Err(from_s3(&e)),
        }
    }

    fn item<'l>(&self, loc: &'l Loc) -> Result<(&'l str, &'l str), Resp<U::Body>> {
        match loc {
            Loc::Root => Err(status(403)),
            Loc::Item { bucket, key } => Ok((bucket, key)),
        }
    }

    // -----------------------------------------------------------------
    // GET, HEAD
    // -----------------------------------------------------------------

    async fn get(&self, method: &str, loc: &Loc, req: Request<U::Body>) -> Out<U::Body> {
        let Loc::Item { bucket, key } = loc else {
            let buckets = self.s3.list_buckets().await.map_err(|e| from_s3(&e))?;
            let rows: Vec<(String, String)> = buckets
                .into_iter()
                .map(|(b, _)| (path::href(&b, ""), format!("{b}/")))
                .collect();
            return Ok(self.index(method, "/", &rows));
        };
        if !key.is_empty() && !key.ends_with('/') {
            let mut headers = Vec::new();
            for name in [
                "range",
                "if-match",
                "if-none-match",
                "if-modified-since",
                "if-unmodified-since",
            ] {
                if let Some(v) = req.header(name) {
                    headers.push((name.to_owned(), v.to_owned()));
                }
            }
            // If-Range is judged here: the storage Worker does not
            // take it. A validator that does not match drops the range.
            if let (Some(cond), true) = (req.header("if-range"), req.header("range").is_some()) {
                let meta = self.s3.head(bucket, key).await.map_err(|e| from_s3(&e))?;
                let holds = meta.as_ref().is_some_and(|m| {
                    if cond.trim_start().starts_with('"') {
                        cond.trim() == m.etag
                    } else {
                        crate::time::parse_http_date(cond) == Some(m.modified_ms)
                    }
                });
                if !holds {
                    headers.retain(|(n, _)| n != "range");
                }
            }
            let up = self
                .s3
                .get(method, bucket, key, headers)
                .await
                .map_err(|e| from_s3(&e))?;
            match up.status {
                404 => {}
                // The answers a client acts on as they are.
                200..=399 | 412 | 416 => return Ok(self.download(up, key)),
                _ => return Err(from_s3(&crate::s3::error_of(&self.dav.up, up).await)),
            }
        }
        match self.resolve(bucket, key).await? {
            Res::Bucket | Res::Coll { .. } => {
                let coll = as_collection(key);
                let listing = self
                    .s3
                    .list_all(bucket, &coll, true, self.cfg().max_listing)
                    .await
                    .map_err(|e| from_s3(&e))?;
                let mut rows: Vec<(String, String)> = Vec::new();
                for p in listing.prefixes.iter().filter(|p| path::addressable(p)) {
                    rows.push((path::href(bucket, p), format!("{}/", path::leaf(p))));
                }
                for e in listing
                    .entries
                    .iter()
                    .filter(|e| !e.key.ends_with('/') && path::addressable(&e.key))
                {
                    rows.push((path::href(bucket, &e.key), path::leaf(&e.key).to_owned()));
                }
                Ok(self.index(method, &path::href(bucket, &coll), &rows))
            }
            Res::File(_) => Err(status(409)),
            Res::Missing => Err(status(404)),
        }
    }

    /// A download as the storage Worker answered it, with only the
    /// headers a client needs, and as an attachment: a stored page is
    /// never shown inline on the WebDAV host.
    fn download(&self, up: Response<U::Body>, key: &str) -> Resp<U::Body> {
        let mut out = Response::new(up.status);
        for name in [
            "content-length",
            "content-range",
            "content-type",
            "etag",
            "last-modified",
            "accept-ranges",
            "content-encoding",
            "content-language",
            "cache-control",
        ] {
            if let Some(v) = up.header(name) {
                out.set_header(name, v);
            }
        }
        if (200..300).contains(&up.status) {
            let name = path::leaf(key);
            let ascii: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            out.set_header(
                "content-disposition",
                format!(
                    "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
                    path::encode(name, false)
                ),
            );
        }
        out.body = up.body;
        out
    }

    /// A minimal HTML index of a collection.
    fn index(&self, method: &str, title: &str, rows: &[(String, String)]) -> Resp<U::Body> {
        let mut html = format!(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{0}</title></head>\
<body><h1>{0}</h1><ul>",
            xml::escape_text(&path::decode(title).unwrap_or_default())
        );
        for (href, name) in rows {
            html.push_str(&format!(
                "<li><a href=\"{}\">{}</a></li>",
                xml::escape_attr(href),
                xml::escape_text(name)
            ));
        }
        html.push_str("</ul></body></html>");
        let bytes = html.into_bytes();
        let len = bytes.len();
        let mut r = Response::new(200).with_bytes("text/html; charset=utf-8", bytes);
        if method == "HEAD" {
            r.body = Body::Empty;
            r.set_header("content-length", len.to_string());
        }
        r
    }

    // -----------------------------------------------------------------
    // PROPFIND
    // -----------------------------------------------------------------

    async fn read_xml(&self, body: Body<U::Body>) -> Result<Option<Element>, Resp<U::Body>> {
        let bytes = crate::s3::read_all(&self.dav.up, body, self.cfg().max_xml_body)
            .await
            .map_err(|e| {
                if e.code == "TooLarge" {
                    status(413)
                } else {
                    status(400)
                }
            })?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        xml::parse(&bytes).map(Some).map_err(|_| status(400))
    }

    async fn propfind(&self, loc: &Loc, req: Request<U::Body>) -> Out<U::Body> {
        let depth = depth(&req.headers).map_err(|()| status(400))?;
        let Some(depth) = depth else {
            return Err(precondition(403, "<D:propfind-finite-depth/>"));
        };
        let doc = self.read_xml(req.body).await?;
        let want = Want::of(doc.as_ref()).map_err(|()| status(400))?;

        let mut resources: Vec<Resource> = Vec::new();
        let bucket = match loc {
            Loc::Root => {
                let buckets = self.s3.list_buckets().await.map_err(|e| from_s3(&e))?;
                resources.push(Resource {
                    bucket: None,
                    key: String::new(),
                    collection: true,
                    size: 0,
                    etag: None,
                    modified_ms: None,
                    content_type: None,
                });
                if depth == 1 {
                    for (b, created) in buckets {
                        resources.push(Resource {
                            bucket: Some(b),
                            key: String::new(),
                            collection: true,
                            size: 0,
                            etag: None,
                            modified_ms: Some(created),
                            content_type: None,
                        });
                    }
                }
                None
            }
            Loc::Item { bucket, key } => {
                let res = self.resolve(bucket, key).await?;
                match res {
                    Res::Missing => return Err(status(404)),
                    Res::File(m) => resources.push(Resource {
                        bucket: Some(bucket.clone()),
                        key: as_file(key).to_owned(),
                        collection: false,
                        size: m.size,
                        etag: Some(m.etag),
                        modified_ms: Some(m.modified_ms),
                        content_type: m.content_type,
                    }),
                    Res::Bucket | Res::Coll { .. } => {
                        let coll = as_collection(key);
                        resources.push(Resource {
                            bucket: Some(bucket.clone()),
                            key: coll.clone(),
                            collection: true,
                            size: 0,
                            etag: None,
                            modified_ms: None,
                            content_type: None,
                        });
                        if depth == 1 {
                            self.children(bucket, &coll, &mut resources).await?;
                        }
                    }
                }
                Some(bucket.clone())
            }
        };

        // Dead properties and lockdiscovery come from the bucket's state
        // object: one call for the whole answer, and none when the
        // request asks for neither.
        let mut dead: Vec<Vec<DeadProp>> = vec![Vec::new(); resources.len()];
        let mut locks: Vec<Vec<Lock>> = vec![Vec::new(); resources.len()];
        let now = self.dav.up.now_ms() / 1000;
        if let (Some(bucket), true) = (&bucket, want.needs_state()) {
            let paths: Vec<String> = resources.iter().map(|r| r.key.clone()).collect();
            let mut ops = vec![Op::Discover {
                paths: paths.clone(),
            }];
            if want.needs_dead() {
                ops.push(Op::PropGet {
                    paths: resources
                        .iter()
                        .map(|r| (r.key.clone(), r.etag.clone()))
                        .collect(),
                    names: want.dead_names(),
                    names_only: matches!(want, Want::PropName),
                });
            }
            let replies = self.state(bucket, ops).await?;
            for reply in replies {
                match reply {
                    Reply::Locks(l) => locks = l,
                    Reply::Props(p) => dead = p,
                    Reply::Full => return Err(status(507)),
                    _ => {}
                }
            }
        }

        let mut body = String::new();
        for (i, r) in resources.iter().enumerate() {
            let bucket_name = r.bucket.as_deref().unwrap_or("");
            let discovery = props::lock_discovery(&locks[i], bucket_name, now);
            body.push_str(&want.render(r, &dead[i], &discovery));
        }
        Ok(xml_resp(207, props::multistatus(&body)))
    }

    /// The members of a collection, for Depth 1.
    async fn children(
        &self,
        bucket: &str,
        coll: &str,
        out: &mut Vec<Resource>,
    ) -> Result<(), Resp<U::Body>> {
        let listing = self
            .s3
            .list_all(bucket, coll, true, self.cfg().max_listing)
            .await
            .map_err(|e| from_s3(&e))?;
        if listing.capped {
            return Err(status(507));
        }
        let folders: Vec<&String> = listing
            .prefixes
            .iter()
            .filter(|p| path::addressable(p))
            .collect();
        let folder_names: std::collections::HashSet<&str> =
            folders.iter().map(|p| path::as_file(p)).collect();
        for p in &folders {
            out.push(Resource {
                bucket: Some(bucket.to_owned()),
                key: (*p).clone(),
                collection: true,
                size: 0,
                etag: None,
                modified_ms: None,
                content_type: None,
            });
        }
        for e in &listing.entries {
            // The marker itself, hidden keys, and a file shadowed by a
            // folder of the same name.
            if e.key == coll
                || e.key.ends_with('/')
                || !path::addressable(&e.key)
                || folder_names.contains(e.key.as_str())
            {
                continue;
            }
            out.push(Resource {
                bucket: Some(bucket.to_owned()),
                key: e.key.clone(),
                collection: false,
                size: e.size,
                etag: Some(e.etag.clone()),
                modified_ms: Some(e.modified_ms),
                content_type: None,
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // PUT
    // -----------------------------------------------------------------

    async fn put(&self, loc: &Loc, mut req: Request<U::Body>) -> Out<U::Body> {
        let (bucket, key) = self.item(loc)?;
        if key.is_empty() || key.ends_with('/') {
            return Err(status(405).with_header("allow", ALLOW));
        }
        let existing = self.s3.head(bucket, key).await.map_err(|e| from_s3(&e))?;
        if existing.is_none() {
            if self
                .s3
                .any_under(bucket, &as_collection(key))
                .await
                .map_err(|e| from_s3(&e))?
            {
                return Err(status(405).with_header("allow", ALLOW));
            }
            if !self.parent_exists(bucket, key).await? {
                return Err(status(409));
            }
        }
        let res = existing.clone().map_or(Res::Missing, Res::File);
        // Authorization comes before any precondition (RFC 4918 §10.6)
        // and before any lease.
        self.require_write(bucket, key).await?;
        // HTTP conditions, judged against what is there now; the write
        // then carries a guard on exactly that, which closes the race.
        let mut guard = http_conditions(&req, existing.as_ref(), existing.is_some())?;
        let ifh = self.parse_if(&req)?;
        if let Some(h) = &ifh {
            if h.lists.iter().any(|l| {
                l.conditions
                    .iter()
                    .any(|c| matches!(c.cond, ifhdr::Cond::ETag(_)))
            }) {
                guard = Some(guard_for(existing.as_ref()));
            }
        }
        let mut checks = vec![Check {
            path: key.to_owned(),
            scope: Scope::Exact,
        }];
        if existing.is_none() {
            checks.push(Check {
                path: parent(key),
                scope: Scope::Member,
            });
        }
        let holder = self
            .begin_write(bucket, checks, ifh.as_ref(), (key, &res))
            .await?;
        if let Err(r) = self
            .reserve(bucket, &holder, vec![(key.to_owned(), false)])
            .await
        {
            self.end_write(bucket, &holder, Vec::new()).await;
            return Err(r);
        }

        let content_type = req
            .header("content-type")
            .map(str::to_owned)
            .unwrap_or_else(|| props::guess_type(key).to_owned());
        let mut meta = Vec::new();
        if let Some(mtime) = req.header("x-oc-mtime") {
            if mtime.trim().parse::<u64>().is_ok() {
                meta.push(("x-amz-meta-mtime".to_owned(), mtime.trim().to_owned()));
            }
        }
        let len = req
            .header("content-length")
            .and_then(|v| v.trim().parse::<u64>().ok());
        let body = std::mem::replace(&mut req.body, Body::Empty);
        let result = self
            .under_lease(
                bucket,
                &holder,
                self.upload(bucket, key, body, len, &content_type, &meta, guard.as_ref()),
            )
            .await
            .unwrap_or_else(|| Err(reservation_busy()));
        // An object replaced through WebDAV keeps its dead properties.
        let mut keep = match (&existing, &result) {
            (Some(old), Ok(new)) if !new.is_empty() => vec![Op::PropRestamp {
                path: key.to_owned(),
                from: old.etag.clone(),
                to: new.clone(),
            }],
            _ => Vec::new(),
        };
        if result.is_ok() {
            keep.push(Op::ClearMoved(vec![key.to_owned()]));
        }
        self.end_write(bucket, &holder, keep).await;
        let etag = result?;
        let mut r = status(if existing.is_some() { 204 } else { 201 });
        if !etag.is_empty() {
            r.set_header("etag", etag);
        }
        Ok(r)
    }

    /// Stores a body: one PutObject up to a part, else parts.
    #[allow(clippy::too_many_arguments)]
    async fn upload(
        &self,
        bucket: &str,
        key: &str,
        body: Body<U::Body>,
        len: Option<u64>,
        content_type: &str,
        meta: &[(String, String)],
        guard: Option<&Cond>,
    ) -> Result<String, Resp<U::Body>> {
        let part = self.cfg().part_bytes;
        match (body, len) {
            (Body::Native(b), Some(len)) if len <= part as u64 => self
                .s3
                .put(bucket, key, Body::Native(b), len, content_type, meta, guard)
                .await
                .map_err(|e| from_s3(&e)),
            (Body::Native(b), _) => {
                self.upload_parts(bucket, key, b, content_type, meta, guard)
                    .await
            }
            (body @ (Body::Bytes(_) | Body::Shared(_)), _) => {
                let len = match &body {
                    Body::Bytes(b) => b.len() as u64,
                    Body::Shared(b) => b.len() as u64,
                    _ => 0,
                };
                self.s3
                    .put(bucket, key, body, len, content_type, meta, guard)
                    .await
                    .map_err(|e| from_s3(&e))
            }
            (Body::Empty, _) => self
                .s3
                .put(bucket, key, Body::Empty, 0, content_type, meta, guard)
                .await
                .map_err(|e| from_s3(&e)),
        }
    }

    /// Reads up to one part; shorter only at the end of the body.
    async fn read_part(&self, body: &mut U::Body) -> Result<Vec<u8>, Resp<U::Body>> {
        let part = self.cfg().part_bytes;
        let mut buf = Vec::new();
        while buf.len() < part {
            let chunk = self
                .dav
                .up
                .read(body, part - buf.len())
                .await
                .map_err(|_| status(400))?;
            if chunk.is_empty() {
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }

    /// An upload in parts of `part_bytes`, several at once. Each part
    /// held in memory takes a slot of the isolate first ([`Slot`]); the
    /// body is read only when one is free.
    async fn upload_parts(
        &self,
        bucket: &str,
        key: &str,
        mut body: U::Body,
        content_type: &str,
        meta: &[(String, String)],
        guard: Option<&Cond>,
    ) -> Result<String, Resp<U::Body>> {
        let slot = Slot::acquire(self.cfg().parts_in_flight).await;
        let first = self.read_part(&mut body).await?;
        if first.len() < self.cfg().part_bytes {
            // The whole body fit in one part.
            let len = first.len() as u64;
            let r = self
                .s3
                .put(
                    bucket,
                    key,
                    Body::Bytes(first),
                    len,
                    content_type,
                    meta,
                    guard,
                )
                .await
                .map_err(|e| from_s3(&e));
            drop(slot);
            return r;
        }
        let upload_id = self
            .s3
            .create_upload(bucket, key, content_type, meta)
            .await
            .map_err(|e| from_s3(&e))?;
        let result = self
            .send_parts(bucket, key, &upload_id, (first, slot), &mut body)
            .await;
        let parts = match result {
            Ok(parts) => parts,
            Err(e) => {
                self.s3.abort_upload(bucket, key, &upload_id).await;
                return Err(e);
            }
        };
        match self
            .s3
            .complete_upload(bucket, key, &upload_id, &parts, guard)
            .await
        {
            Ok(etag) => Ok(etag),
            Err(e) => {
                self.s3.abort_upload(bucket, key, &upload_id).await;
                Err(from_s3(&e))
            }
        }
    }

    async fn send_parts(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        first: (Vec<u8>, Slot),
        body: &mut U::Body,
    ) -> Result<Vec<(u32, String)>, Resp<U::Body>> {
        let max = self.cfg().parts_in_flight;
        let part = self.cfg().part_bytes;
        let mut inflight = futures_util::stream::FuturesUnordered::new();
        let mut done: Vec<(u32, String)> = Vec::new();
        let mut number = 1u32;
        let mut next = Some(first);
        loop {
            if let Some((bytes, slot)) = next.take() {
                let more = bytes.len() == part;
                inflight.push(self.send_part(bucket, key, upload_id, number, bytes, slot));
                number += 1;
                if more {
                    // A slot for the next part, while the parts in flight
                    // go on.
                    let slot = loop {
                        if let Some(slot) = Slot::try_acquire(max) {
                            break slot;
                        }
                        match select(std::pin::pin!(Slot::acquire(max)), inflight.next()).await {
                            Either::Left((slot, _)) => break slot,
                            Either::Right((Some(r), _)) => done.push(r?),
                            Either::Right((None, _)) => break Slot::acquire(max).await,
                        }
                    };
                    let bytes = self.read_part(body).await?;
                    if !bytes.is_empty() {
                        next = Some((bytes, slot));
                    }
                    continue;
                }
            }
            match inflight.next().await {
                Some(r) => done.push(r?),
                None => break,
            }
        }
        done.sort_by_key(|(n, _)| *n);
        Ok(done)
    }

    /// One part, sent again on `503 SlowDown` as the AWS SDKs' standard
    /// retry mode does: three attempts, backoff 1 s then 2 s. The bytes
    /// are shared with each attempt, never copied; the slot is let go
    /// when the part is done.
    async fn send_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        n: u32,
        bytes: Vec<u8>,
        slot: Slot,
    ) -> Result<(u32, String), Resp<U::Body>> {
        let bytes = std::rc::Rc::new(bytes);
        let mut attempt = 0;
        let out = loop {
            match self
                .s3
                .upload_part(bucket, key, upload_id, n, std::rc::Rc::clone(&bytes))
                .await
            {
                Ok(etag) => break Ok((n, etag)),
                Err(e) if (e.status == 503 || e.is("SlowDown")) && attempt < 2 => {
                    self.dav.up.sleep(1000 << attempt).await;
                    attempt += 1;
                }
                Err(e) => break Err(from_s3(&e)),
            }
        };
        drop(slot);
        out
    }

    // -----------------------------------------------------------------
    // DELETE
    // -----------------------------------------------------------------

    async fn delete(&self, loc: &Loc, req: Request<U::Body>) -> Out<U::Body> {
        let (bucket, key) = self.item(loc)?;
        if key.is_empty() {
            return Err(status(403));
        }
        let res = self.resolve(bucket, key).await?;
        let path = state_path(&res, key);
        let ifh = self.parse_if(&req)?;
        match &res {
            Res::Missing => Err(status(404)),
            Res::Bucket => Err(status(403)),
            Res::File(meta) => {
                self.require_write(bucket, &path).await?;
                let http_guard = http_conditions(&req, Some(meta), true)?;
                let (holder, dav_guard) = self
                    .begin_write_with_guard(
                        bucket,
                        vec![
                            Check {
                                path: path.clone(),
                                scope: Scope::Exact,
                            },
                            Check {
                                path: parent(&path),
                                scope: Scope::Member,
                            },
                        ],
                        ifh.as_ref(),
                        (&path, &res),
                    )
                    .await?;
                let guard = http_guard.or(dav_guard);
                if let Err(r) = self
                    .reserve(bucket, &holder, vec![(path.clone(), false)])
                    .await
                {
                    self.end_write(bucket, &holder, Vec::new()).await;
                    return Err(r);
                }
                let r = self
                    .under_lease(
                        bucket,
                        &holder,
                        self.s3.delete(bucket, &path, guard.as_ref()),
                    )
                    .await;
                // Properties and locks go with the file, and only when it
                // went.
                let mut drops = Vec::new();
                if let Some(Ok(())) = r {
                    drops.extend(forget(std::slice::from_ref(&path)));
                    drops.push(Op::ClearMoved(vec![path.clone()]));
                }
                self.end_write(bucket, &holder, drops).await;
                r.ok_or_else(reservation_busy)?.map_err(|e| from_s3(&e))?;
                self.keep_folder(bucket, &parent(&path)).await;
                Ok(status(204))
            }
            Res::Coll { key: coll } => {
                if depth(&req.headers) != Ok(None) {
                    return Err(status(400));
                }
                self.require_write(bucket, coll).await?;
                http_conditions(&req, None, true)?;
                let holder = self
                    .begin_write(
                        bucket,
                        vec![
                            Check {
                                path: coll.clone(),
                                scope: Scope::Tree,
                            },
                            Check {
                                path: parent(coll),
                                scope: Scope::Member,
                            },
                        ],
                        ifh.as_ref(),
                        (coll, &res),
                    )
                    .await?;
                if let Err(r) = self
                    .reserve(bucket, &holder, vec![(coll.clone(), true)])
                    .await
                {
                    self.end_write(bucket, &holder, Vec::new()).await;
                    return Err(r);
                }
                let work = async {
                    let entries = self.list_tree(bucket, coll).await?;
                    require_visible_tree(&entries)?;
                    let stateful = self.folders_with_state(bucket, &[coll.as_str()]).await?;
                    let files = entries.iter().filter(|e| !e.key.ends_with('/')).count();
                    let markers = entries.len() - files;
                    let gone = gone_folders(
                        Some(coll),
                        &stateful,
                        entries.iter().map(|e| e.key.as_str()),
                        std::iter::empty(),
                    );
                    let mut plan = Plan::default();
                    plan.batches(files.div_ceil(self.cfg().delete_keys.max(1)), 1);
                    plan.batches(markers, self.cfg().fan_out);
                    plan.calls += gone.len();
                    self.within_budget(&plan)?;
                    let (deleted, failed) = self.delete_tree(bucket, &holder, entries).await?;
                    let drops = self
                        .forget_removed(
                            bucket,
                            Some(coll),
                            &deleted,
                            failed.iter().map(|(key, _)| key.as_str()),
                            &stateful,
                        )
                        .await;
                    if !drops.is_empty() {
                        self.state(bucket, drops).await?;
                    }
                    Ok(failed)
                };
                let out = self.under_lease(bucket, &holder, work).await;
                self.end_write(bucket, &holder, Vec::new()).await;
                let failed = out.ok_or_else(reservation_busy)??;
                if !failed.is_empty() {
                    return Ok(failed_members(bucket, &failed));
                }
                self.keep_folder(bucket, &parent(coll)).await;
                Ok(status(204))
            }
        }
    }

    /// The collections at or under `roots` that carry DAV state (see
    /// [`Op::FoldersWithState`]); more than `max_tree` of them is refused
    /// with `507` before any change.
    async fn folders_with_state(
        &self,
        bucket: &str,
        roots: &[&str],
    ) -> Result<Vec<String>, Resp<U::Body>> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let replies = self
            .state(
                bucket,
                vec![Op::FoldersWithState {
                    roots: roots.iter().map(|r| (*r).to_owned()).collect(),
                    limit: self.cfg().max_tree,
                }],
            )
            .await?;
        match replies.into_iter().next() {
            Some(Reply::StatefulFolders(folders)) => Ok(folders),
            Some(Reply::Full) => Err(status(507)),
            _ => Err(status(500)),
        }
    }

    /// `507` before any change when a plan needs more calls than
    /// `max_mutation_calls`.
    fn within_budget(&self, plan: &Plan) -> Result<(), Resp<U::Body>> {
        if plan.calls > self.cfg().max_mutation_calls {
            return Err(Response::new(507).with_bytes(
                "text/plain; charset=utf-8",
                format!(
                    "This change needs about {} storage calls, more than one WebDAV request may \
                     make. Use the S3 endpoint for a change this size.",
                    plan.calls
                )
                .into_bytes(),
            ));
        }
        Ok(())
    }

    /// The removal state ops for the deleted keys, and the state of every
    /// stateful collection the plan removed whose own prefix probe finds
    /// nothing. A collection that still holds a key, or whose probe fails,
    /// keeps its state.
    async fn forget_removed<'a>(
        &self,
        bucket: &str,
        tree: Option<&str>,
        deleted: &[String],
        remaining: impl Iterator<Item = &'a str>,
        stateful: &[String],
    ) -> Vec<Op> {
        let mut ops = removal_plan(deleted);
        let gone = gone_folders(
            tree,
            stateful,
            deleted.iter().map(String::as_str),
            remaining,
        );
        let mut probes = stream::iter(gone)
            .map(|folder| async move {
                let absent = matches!(self.s3.any_under(bucket, &folder).await, Ok(false));
                (folder, absent)
            })
            .buffer_unordered(self.cfg().fan_out.max(1));
        while let Some((folder, absent)) = probes.next().await {
            if absent {
                // Nothing is left under it, so no state under it applies.
                ops.extend(forget_tree(&folder));
            }
        }
        ops
    }

    async fn list_tree(&self, bucket: &str, coll: &str) -> Result<Vec<Entry>, Resp<U::Body>> {
        let listing = self
            .s3
            .list_all(bucket, coll, false, self.cfg().max_tree)
            .await
            .map_err(|e| from_s3(&e))?;
        if listing.capped {
            return Err(too_many(self.cfg().max_tree));
        }
        Ok(listing.entries)
    }

    /// Deletes the preflighted keys of a collection, markers last, in
    /// batches: each renews the reservation first ([`Ctx::fence`]), each
    /// call is bounded ([`Ctx::bounded`]), and nothing is dispatched after
    /// a call that did not answer in time.
    async fn delete_tree(
        &self,
        bucket: &str,
        holder: &str,
        entries: Vec<Entry>,
    ) -> Result<(Vec<String>, Vec<(String, u16)>), Resp<U::Body>> {
        let (markers, files): (Vec<_>, Vec<_>) =
            entries.into_iter().partition(|e| e.key.ends_with('/'));
        let files: Vec<_> = files.into_iter().map(|e| e.key).collect();
        let mut failed = Vec::new();
        let mut deleted = Vec::new();
        let mut batches = files.chunks(self.cfg().delete_keys.max(1));
        while let Some(batch) = batches.next() {
            self.fence(bucket, holder).await?;
            match self.bounded(self.s3.delete_many(bucket, batch)).await {
                Some(Ok(errors)) => {
                    for k in batch {
                        if !errors.iter().any(|(e, _)| e == k) {
                            deleted.push(k.clone());
                        }
                    }
                    failed.extend(errors.into_iter().map(|(k, _)| (k, 500)));
                }
                Some(Err(e)) => {
                    let code = from_s3::<U::Body>(&e).status;
                    if code == 401 {
                        return Err(unauthorized());
                    }
                    failed.extend(batch.iter().map(|k| (k.clone(), code)));
                }
                None => {
                    let undone = batches.flatten().chain(batch).map(|k| (k.clone(), 504));
                    failed.extend(undone);
                    failed.extend(markers.into_iter().map(|e| (e.key, 504)));
                    return Ok((deleted, failed));
                }
            }
        }
        // Another S3 writer can replace a visible zero-byte marker with
        // a hidden nonempty object without going through the DAV lease.
        let (removed, conflicts) = self
            .delete_matching_members(
                bucket,
                holder,
                markers.into_iter().map(|e| (e.key, e.etag)).collect(),
                409,
            )
            .await?;
        deleted.extend(removed);
        failed.extend(conflicts);
        Ok((deleted, failed))
    }

    // -----------------------------------------------------------------
    // MKCOL
    // -----------------------------------------------------------------

    async fn mkcol(&self, loc: &Loc, req: Request<U::Body>) -> Out<U::Body> {
        let (bucket, key) = match loc {
            Loc::Root => return Err(status(403)),
            Loc::Item { key, .. } if key.is_empty() => return Err(status(403)),
            Loc::Item { bucket, key } => (bucket.as_str(), key.as_str()),
        };
        let ifh = self.parse_if(&req)?;
        if !req.body.is_empty_body() {
            let bytes = crate::s3::read_all(&self.dav.up, req.body, 1)
                .await
                .unwrap_or_else(|_| vec![0]);
            if !bytes.is_empty() {
                return Err(status(415));
            }
        }
        let coll = as_collection(key);
        if self.resolve(bucket, as_file(key)).await?.exists() {
            return Err(status(405).with_header("allow", ALLOW));
        }
        if !self.parent_exists(bucket, &coll).await? {
            return Err(status(409));
        }
        self.require_write(bucket, &coll).await?;
        let holder = self
            .begin_write(
                bucket,
                vec![
                    Check {
                        path: coll.clone(),
                        scope: Scope::Exact,
                    },
                    Check {
                        path: parent(&coll),
                        scope: Scope::Member,
                    },
                ],
                ifh.as_ref(),
                (&coll, &Res::Missing),
            )
            .await?;
        if let Err(r) = self
            .reserve(bucket, &holder, vec![(coll.clone(), false)])
            .await
        {
            self.end_write(bucket, &holder, Vec::new()).await;
            return Err(r);
        }
        let r = self
            .under_lease(
                bucket,
                &holder,
                self.s3.put(
                    bucket,
                    &coll,
                    Body::Empty,
                    0,
                    "application/x-directory",
                    &[],
                    Some(&Cond::Absent),
                ),
            )
            .await;
        let ops = if let Some(Ok(_)) = &r {
            vec![Op::ClearMoved(vec![coll])]
        } else {
            Vec::new()
        };
        self.end_write(bucket, &holder, ops).await;
        match r.ok_or_else(reservation_busy)? {
            Ok(_) => Ok(status(201)),
            Err(e) if e.status == 412 || e.is("PreconditionFailed") => {
                Err(status(405).with_header("allow", ALLOW))
            }
            Err(e) => Err(from_s3(&e)),
        }
    }

    // -----------------------------------------------------------------
    // COPY, MOVE
    // -----------------------------------------------------------------

    async fn copy_move(&self, loc: &Loc, req: Request<U::Body>, is_move: bool) -> Out<U::Body> {
        let (bucket, key) = self.item(loc)?;
        if key.is_empty() {
            return Err(status(403));
        }
        let dest = req.header("destination").ok_or_else(|| status(400))?;
        let dest_path = header_url_path(dest, &self.origin).ok_or_else(|| status(502))?;
        let dest_loc = match Loc::parse(&dest_path) {
            Ok(l) => l,
            Err(PathError::Bad) => return Err(status(400)),
            Err(PathError::Hidden) => return Err(status(403)),
        };
        let (dbucket, dkey) = match &dest_loc {
            Loc::Root => return Err(status(403)),
            Loc::Item { bucket: b, key: k } => (b.as_str(), k.as_str()),
        };
        if dkey.is_empty() {
            return Err(status(403));
        }
        if dbucket != bucket {
            // The storage Worker copies inside one bucket only.
            return Err(status(502));
        }
        let overwrite = match req.header("overwrite").map(str::trim) {
            None | Some("T") | Some("t") => true,
            Some("F") | Some("f") => false,
            Some(_) => return Err(status(400)),
        };
        let depth = depth(&req.headers).map_err(|()| status(400))?;
        let src = self.resolve(bucket, key).await?;
        let src_coll = matches!(src, Res::Coll { .. });
        match (&src, depth) {
            (Res::Missing, _) => return Err(status(404)),
            (Res::Bucket, _) => return Err(status(403)),
            (_, Some(1)) => return Err(status(400)),
            (Res::Coll { .. }, Some(0)) if is_move => return Err(status(400)),
            _ => {}
        }
        let src_meta = match &src {
            Res::File(meta) => Some(meta),
            _ => None,
        };
        let src_path = state_path(&src, key);
        let dst_path = if src_coll {
            as_collection(dkey)
        } else {
            as_file(dkey).to_owned()
        };
        if src_path == dst_path || as_collection(&src_path) == as_collection(&dst_path) {
            return Err(status(403));
        }
        if src_coll && path::within(&src_path, &dst_path) {
            return Err(status(403));
        }
        if !storable_key(&dst_path) {
            return Err(status(409));
        }
        // Authorization comes before any precondition (RFC 4918 §10.6),
        // the Overwrite: F test included, and before any lease.
        self.require_write(bucket, &dst_path).await?;
        if is_move {
            self.require_write(bucket, &src_path).await?;
        }
        let http_source_guard = match http_conditions(&req, src_meta, true)? {
            Some(Cond::Is(etag)) => Some(etag),
            _ => None,
        };
        let dst = self.resolve(bucket, as_file(dkey)).await?;
        // A destination that holds the source (its own folder, or one
        // above it) is not a valid replacement target.
        if path::within(&as_collection(&dst_path), &src_path)
            || matches!(&dst, Res::Coll { key: d } if path::within(d, &src_path))
        {
            return Err(status(403));
        }
        if dst.exists() && !overwrite {
            return Err(status(412));
        }
        if !self.parent_exists(bucket, &dst_path).await? {
            return Err(status(409));
        }
        let ifh = self.parse_if(&req)?;
        let dst_existing = state_path(&dst, as_file(dkey));
        let mut checks = vec![
            Check {
                path: dst_path.clone(),
                scope: if src_coll { Scope::Tree } else { Scope::Exact },
            },
            Check {
                path: parent(&dst_path),
                scope: Scope::Member,
            },
        ];
        if dst.exists() && dst_existing != dst_path {
            checks.push(Check {
                path: dst_existing.clone(),
                scope: Scope::Tree,
            });
        }
        if is_move {
            checks.push(Check {
                path: src_path.clone(),
                scope: if src_coll { Scope::Tree } else { Scope::Exact },
            });
            checks.push(Check {
                path: parent(&src_path),
                scope: Scope::Member,
            });
        }
        let mut roots = vec![(dst_path.clone(), src_coll)];
        if src_coll {
            roots.push((as_file(&dst_path).to_owned(), false));
        }
        if let Res::Coll { key } = &dst {
            roots.push((key.clone(), true));
        }
        if is_move {
            roots.push((src_path.clone(), src_coll));
        }
        let (holder, dav_guard) = self
            .begin_write_with_guard(bucket, checks, ifh.as_ref(), (&src_path, &src))
            .await?;
        // An ETag the `If` header tested on a file source guards the copied
        // version as If-Match does. With both, the HTTP one, judged against
        // the same snapshot.
        let source_guard = http_source_guard.or(match dav_guard {
            Some(Cond::Is(tag)) if !src_coll => Some(tag),
            _ => None,
        });
        if let Err(r) = self.reserve(bucket, &holder, roots).await {
            self.end_write(bucket, &holder, Vec::new()).await;
            return Err(r);
        }
        let work = async {
            let fan = self.cfg().fan_out.max(1);
            // Plan and validate every mapped key before changing either tree.
            let mut members = Vec::new();
            let mut markers = Vec::new();
            if src_coll && depth != Some(0) {
                let entries = self.list_tree(bucket, &src_path).await?;
                let hidden = hidden_tree_keys(&entries);
                if is_move && !hidden.is_empty() {
                    return Err(hidden_folder());
                }
                for entry in entries {
                    if hidden.contains(&entry.key) {
                        // The hidden object bytes are never copied, but its
                        // addressable collection prefixes can still be visible.
                        if let Some(suffix) =
                            visible_collection_prefix(&entry.key).strip_prefix(&src_path)
                        {
                            if !suffix.is_empty() {
                                markers.push(format!("{dst_path}{suffix}"));
                            }
                        }
                        continue;
                    }
                    let suffix = entry
                        .key
                        .strip_prefix(&src_path)
                        .ok_or_else(|| status(502))?;
                    let dest = format!("{dst_path}{suffix}");
                    if !storable_key(&dest) {
                        return Err(status(409));
                    }
                    members.push((entry, dest));
                }
                markers = empty_copy_markers(markers, &members);
            }
            // Materialize the root of an implied or depth-zero collection.
            if src_coll && !members.iter().any(|(_, dest)| dest == &dst_path) {
                markers.push(dst_path.clone());
            }
            if markers.iter().any(|key| !storable_key(key)) {
                return Err(status(409));
            }
            let dest_collection = match &dst {
                Res::Coll { key } => Some(key.as_str()),
                // A same-named file can mask the collection in resolve().
                Res::File(_) if src_coll => Some(dst_path.as_str()),
                _ => None,
            };
            let mut obsolete = Vec::new();
            let mut listed = Vec::new();
            let mut destination_markers = HashMap::new();
            if let Some(dcoll) = dest_collection {
                let entries = self.list_tree(bucket, dcoll).await?;
                require_visible_tree(&entries)?;
                let mut new_keys = HashSet::from([dst_path.as_str()]);
                new_keys.extend(members.iter().map(|(_, dest)| dest.as_str()));
                new_keys.extend(markers.iter().map(String::as_str));
                for e in entries {
                    listed.push((e.key.clone(), e.etag.clone()));
                    if !new_keys.contains(e.key.as_str()) {
                        obsolete.push((e.key, e.etag));
                    } else if e.key.ends_with('/') {
                        destination_markers.insert(e.key, e.etag);
                    }
                }
            }
            let exact = match (src_coll, &dst) {
                (true, Res::File(meta)) => Some((dst_existing, meta.etag.clone())),
                _ => None,
            };
            obsolete.extend(exact.clone());
            // The complete listing can also reclaim rows whose keys are no
            // longer present. The mutation reservation covers the whole handoff.
            // `kept`: (destination, source) of each protected member.
            let mut kept: Vec<(String, String)> = Vec::new();
            if dest_collection.is_some() || exact.is_some() {
                let replies = self
                    .state(
                        bucket,
                        vec![Op::FindMoved {
                            holder: holder.clone(),
                            root: dest_collection.map(str::to_owned),
                            listed,
                            exact,
                        }],
                    )
                    .await?;
                let protected = match replies.into_iter().next() {
                    Some(Reply::Moved(protected)) => protected,
                    Some(Reply::Busy) => return Err(reservation_busy()),
                    _ => return Err(status(500)),
                };
                let protected: HashMap<_, _> = protected.into_iter().collect();
                obsolete.retain(|(key, _)| match protected.get(key) {
                    Some(source) => {
                        kept.push((key.clone(), source.clone()));
                        false
                    }
                    None => true,
                });
            }

            // Every call the plan can make, judged before any change.
            let claim_root = src_coll && !overwrite;
            let mut state_roots = Vec::new();
            if let (Some(dcoll), false) = (dest_collection, obsolete.is_empty()) {
                state_roots.push(dcoll);
            }
            if is_move && src_coll {
                state_roots.push(src_path.as_str());
            }
            let stateful = self.folders_with_state(bucket, &state_roots).await?;
            let mut plan = Plan::default();
            plan.batches(if src_coll { members.len() } else { 1 }, fan);
            plan.batches(usize::from(claim_root), 1);
            plan.batches(markers.len(), fan);
            for group in split_markers(obsolete.iter().map(|(k, _)| k.as_str())) {
                plan.batches(group, fan);
            }
            if is_move && src_coll {
                for group in split_markers(members.iter().map(|(e, _)| e.key.as_str())) {
                    plan.batches(group, fan);
                }
            } else if is_move {
                plan.batches(1, 1);
            }
            // The renewal before the state of the copies is written.
            plan.calls += 1;
            plan.calls += gone_folders(
                dest_collection,
                &stateful,
                obsolete.iter().map(|(k, _)| k.as_str()),
                members
                    .iter()
                    .map(|(_, dest)| dest.as_str())
                    .chain(markers.iter().map(String::as_str))
                    .chain(kept.iter().map(|(k, _)| k.as_str()))
                    .chain([dst_path.as_str()]),
            )
            .len();
            if is_move && src_coll {
                plan.calls += gone_folders(
                    Some(&src_path),
                    &stateful,
                    members.iter().map(|(e, _)| e.key.as_str()),
                    std::iter::empty(),
                )
                .len();
            }
            self.within_budget(&plan)?;

            if is_move && src_coll {
                let replies = self
                    .state(
                        bucket,
                        vec![Op::ReserveMoved {
                            holder: holder.clone(),
                            destinations: members.iter().map(|(_, key)| key.clone()).collect(),
                            ttl_secs: self.cfg().lease_secs,
                        }],
                    )
                    .await?;
                match replies.as_slice() {
                    [Reply::Granted] => {}
                    [Reply::Busy] => return Err(reservation_busy()),
                    [Reply::Full] => return Err(status(507)),
                    _ => return Err(status(500)),
                }
            }
            let mut written = Vec::new();
            if claim_root {
                // Overwrite: F holds for the root as well: claim it before
                // any member or property is copied. A destination that
                // appeared since the check above is not written to.
                self.fence(bucket, &holder).await?;
                let claim = self
                    .bounded(self.s3.put(
                        bucket,
                        &dst_path,
                        Body::Empty,
                        0,
                        "application/x-directory",
                        &[],
                        Some(&Cond::Absent),
                    ))
                    .await;
                match claim {
                    Some(Ok(etag)) => {
                        // The source's own root marker replaces exactly
                        // the claimed one.
                        destination_markers.insert(dst_path.clone(), etag);
                        markers.retain(|marker| marker != &dst_path);
                        written.push(dst_path.clone());
                    }
                    Some(Err(e)) => {
                        let r = from_s3(&e);
                        return Err(if r.status == 412 { status(412) } else { r });
                    }
                    None => return Err(status(504)),
                }
            }
            let etag = if src_coll {
                None
            } else {
                self.fence(bucket, &holder).await?;
                let cond = (!overwrite).then_some(Cond::Absent);
                let copied = self
                    .bounded(self.s3.copy(
                        bucket,
                        &src_path,
                        &dst_path,
                        cond.as_ref(),
                        source_guard.as_deref(),
                    ))
                    .await
                    .ok_or_else(|| status(504))?;
                Some(copied.map_err(|e| from_s3(&e))?)
            };
            let TreeCopy {
                versions,
                mut properties,
                mut failed,
            } = self
                .copy_tree(bucket, &holder, &members, &destination_markers, overwrite)
                .await?;
            let claimed = written.len();
            written.extend(versions.iter().map(|m| m.destination.clone()));
            let copied_version_count = versions.len();
            if let Some(tag) = &etag {
                properties.push(copied_file_props(&src_path, &dst_path, tag));
                written.push(dst_path.clone());
            }
            let mut copied_keys = written.clone();
            // Materialize empty collections before deleting anything. Only
            // folders represented by a successful copy or marker get props.
            if failed.is_empty() {
                for chunk in markers.chunks(fan) {
                    self.fence(bucket, &holder).await?;
                    let results = join_all(chunk.iter().map(|marker| {
                        self.bounded(self.s3.put(
                            bucket,
                            marker,
                            Body::Empty,
                            0,
                            "application/x-directory",
                            &[],
                            Some(&Cond::Absent),
                        ))
                    }))
                    .await;
                    for (marker, result) in chunk.iter().zip(results) {
                        match result {
                            Some(Ok(_)) => written.push(marker.clone()),
                            // A marker already exists; we did not replace it.
                            Some(Err(e)) if from_s3::<U::Body>(&e).status == 412 => {}
                            Some(Err(e)) => {
                                failed.push((marker.clone(), from_s3::<U::Body>(&e).status));
                                continue;
                            }
                            None => {
                                failed.push((marker.clone(), 504));
                                continue;
                            }
                        }
                        copied_keys.push(marker.clone());
                    }
                    if !failed.is_empty() {
                        break;
                    }
                }
            }
            if src_coll && !copied_keys.is_empty() {
                properties.push(Op::PropCopyFolders {
                    from: src_path.clone(),
                    to: dst_path.clone(),
                    members: copied_keys.clone(),
                });
            }
            // A renewal outage can expire a suspended request. Do not let it
            // reconcile state or dispatch its prune after another holder enters.
            self.fence(bucket, &holder).await?;
            let pending_move_keys = if is_move && src_coll && failed.is_empty() {
                // Do not give up these existing ledger slots before the
                // reserved versions replace them in RecordMoved.
                written
                    .drain(claimed..claimed + copied_version_count)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            if !written.is_empty() {
                properties.push(Op::ClearMoved(written));
            }
            if !properties.is_empty() {
                self.state(bucket, properties).await?;
            }
            if !failed.is_empty() {
                return Ok(failed_members(bucket, &failed));
            }

            // Do not prune obsolete keys until the copies and their state
            // have succeeded. Protected keys were excluded under the
            // reservation, which every batch of the prune renews first.
            let (removed, failed) = self
                .delete_matching_members(bucket, &holder, obsolete, 412)
                .await?;
            if !removed.is_empty() {
                let ops = self
                    .forget_removed(
                        bucket,
                        dest_collection,
                        &removed,
                        copied_keys
                            .iter()
                            .map(String::as_str)
                            .chain(kept.iter().map(|(k, _)| k.as_str()))
                            .chain(failed.iter().map(|(key, _)| key.as_str())),
                        &stateful,
                    )
                    .await;
                self.state(bucket, ops).await?;
            }
            if !failed.is_empty() {
                if !pending_move_keys.is_empty() {
                    self.state(bucket, vec![Op::ClearMoved(pending_move_keys)])
                        .await?;
                }
                return Ok(failed_members_with_kept(bucket, &failed, &kept));
            }

            if is_move {
                if let Some(etag) = &etag {
                    self.fence(bucket, &holder).await?;
                    self.bounded(
                        self.s3
                            .delete(bucket, &src_path, Some(&Cond::Is(etag.clone()))),
                    )
                    .await
                    .ok_or_else(|| status(504))?
                    .map_err(|e| {
                        let r = from_s3(&e);
                        if r.status == 412 {
                            status(409)
                        } else {
                            r
                        }
                    })?;
                    let mut ops = forget(std::slice::from_ref(&src_path));
                    ops.push(Op::ClearMoved(vec![src_path.clone()]));
                    self.state(bucket, ops).await?;
                } else {
                    let source_versions = versions
                        .iter()
                        .map(|m| (m.source.clone(), m.etag.clone()))
                        .collect();
                    // A failed state batch must abort before the first source
                    // delete. If interrupted afterward, matching records stay.
                    let replies = self
                        .state(
                            bucket,
                            vec![Op::RecordMoved {
                                holder: Some(holder.clone()),
                                members: versions.clone(),
                            }],
                        )
                        .await?;
                    match replies.as_slice() {
                        [Reply::Done] => {}
                        [Reply::Busy] => return Err(reservation_busy()),
                        [Reply::Full] => return Err(status(507)),
                        _ => return Err(status(500)),
                    }
                    let (removed, failed) = self
                        .delete_matching_members(bucket, &holder, source_versions, 409)
                        .await?;
                    let mut ops = self
                        .forget_removed(
                            bucket,
                            Some(&src_path),
                            &removed,
                            failed.iter().map(|(key, _)| key.as_str()),
                            &stateful,
                        )
                        .await;
                    if failed.is_empty() {
                        // The move is complete, earlier partial attempts of
                        // it included: their members are no longer kept.
                        ops.push(Op::FinishMove(versions));
                        ops.push(Op::FinishMoveTree {
                            src_root: src_path.clone(),
                            dst_root: dst_path.clone(),
                        });
                        kept.retain(|(destination, source)| {
                            !(path::within(&src_path, source)
                                && path::within(&dst_path, destination))
                        });
                    }
                    if !ops.is_empty() {
                        self.state(bucket, ops).await?;
                    }
                    if !failed.is_empty() {
                        return Ok(failed_members_with_kept(bucket, &failed, &kept));
                    }
                }
            }
            if !kept.is_empty() {
                return Ok(failed_members_with_kept(bucket, &[], &kept));
            }
            Ok(status(if dst.exists() { 204 } else { 201 }))
        };
        let out = self.under_lease(bucket, &holder, work).await;
        self.end_write(bucket, &holder, Vec::new()).await;
        let out = out.ok_or_else(reservation_busy)??;
        if is_move && out.status < 300 {
            self.keep_folder(bucket, &parent(&src_path)).await;
        }
        Ok(out)
    }

    /// Copy the preflighted members in batches: each renews the
    /// reservation first, each call is bounded, and no further batch is
    /// scheduled after a failed one.
    async fn copy_tree(
        &self,
        bucket: &str,
        holder: &str,
        members: &[(Entry, String)],
        destination_markers: &HashMap<String, String>,
        overwrite: bool,
    ) -> Result<TreeCopy, Resp<U::Body>> {
        let mut copied = TreeCopy::default();
        for batch in members.chunks(self.cfg().fan_out.max(1)) {
            self.fence(bucket, holder).await?;
            let outcomes = join_all(batch.iter().map(|(src, dst)| async move {
                let marker_etag = src.key.ends_with('/').then_some(src.etag.as_str());
                // A same-named destination marker can also become hidden
                // after preflight. Replace only the listed (or claimed)
                // empty object; with Overwrite: F nothing else.
                let condition = match (marker_etag, destination_markers.get(dst)) {
                    (Some(_), Some(tag)) => Some(Cond::Is(tag.clone())),
                    _ if !overwrite => Some(Cond::Absent),
                    (Some(_), None) => Some(Cond::Absent),
                    (None, _) => None,
                };
                self.bounded(
                    self.s3
                        .copy(bucket, &src.key, dst, condition.as_ref(), marker_etag),
                )
                .await
            }))
            .await;
            for ((src, dst), result) in batch.iter().zip(outcomes) {
                match result {
                    Some(Ok(etag)) => {
                        if !src.key.ends_with('/') {
                            copied
                                .properties
                                .push(copied_file_props(&src.key, dst, &etag));
                        }
                        copied.versions.push(MovedMember {
                            destination: dst.clone(),
                            etag,
                            source: src.key.clone(),
                        });
                    }
                    Some(Err(e)) => copied
                        .failed
                        .push((src.key.clone(), from_s3::<U::Body>(&e).status)),
                    None => copied.failed.push((src.key.clone(), 504)),
                }
            }
            if !copied.failed.is_empty() {
                break;
            }
        }
        Ok(copied)
    }

    /// Delete only the listed or copied versions, files before markers,
    /// in batches: each renews the reservation first, each call is
    /// bounded, and nothing is dispatched after a call that did not answer
    /// in time (it and every undispatched key are reported as `504`).
    async fn delete_matching_members(
        &self,
        bucket: &str,
        holder: &str,
        members: Vec<(String, String)>,
        changed_status: u16,
    ) -> Result<(Vec<String>, Vec<(String, u16)>), Resp<U::Body>> {
        let (mut markers, files): (Vec<_>, Vec<_>) =
            members.into_iter().partition(|(k, _)| k.ends_with('/'));
        markers.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
        let mut failed = Vec::new();
        let mut deleted = Vec::new();
        let fan = self.cfg().fan_out.max(1);
        let mut rest = files
            .into_iter()
            .map(Some)
            .chain([None])
            .chain(markers.into_iter().map(Some));
        loop {
            // A batch stays within one group: files, then markers.
            let mut batch = Vec::new();
            for next in rest.by_ref() {
                match next {
                    Some(member) => {
                        batch.push(member);
                        if batch.len() == fan {
                            break;
                        }
                    }
                    None if batch.is_empty() => {}
                    None => break,
                }
            }
            if batch.is_empty() {
                return Ok((deleted, failed));
            }
            self.fence(bucket, holder).await?;
            let results = join_all(batch.iter().map(|(key, etag)| async move {
                let cond = Cond::Is(etag.clone());
                self.bounded(self.s3.delete(bucket, key, Some(&cond))).await
            }))
            .await;
            let mut timed_out = false;
            for ((key, _), result) in batch.into_iter().zip(results) {
                match result {
                    Some(Ok(())) => deleted.push(key),
                    Some(Err(e)) => {
                        let code = from_s3::<U::Body>(&e).status;
                        failed.push((key, if code == 412 { changed_status } else { code }));
                    }
                    None => {
                        timed_out = true;
                        failed.push((key, 504));
                    }
                }
            }
            if timed_out {
                failed.extend(rest.flatten().map(|(key, _)| (key, 504)));
                return Ok((deleted, failed));
            }
        }
    }

    // -----------------------------------------------------------------
    // LOCK, UNLOCK
    // -----------------------------------------------------------------

    async fn lock(&self, loc: &Loc, req: Request<U::Body>) -> Out<U::Body> {
        let (bucket, key) = self.item(loc)?;
        let depth_inf = match depth(&req.headers) {
            Ok(None) => true,
            Ok(Some(0)) => false,
            _ => return Err(status(400)),
        };
        let timeout = timeout_secs(req.header("timeout"), self.cfg());
        let ifh = self.parse_if(&req)?;
        let doc = self
            .read_xml(std::mem::replace(&mut { req.body }, Body::Empty))
            .await?;
        let res = self.resolve(bucket, key).await?;
        let lock_path = match &res {
            Res::Missing => as_file(key).to_owned(),
            other => state_path(other, key),
        };
        let now = self.dav.up.now_ms() / 1000;

        let Some(doc) = doc else {
            // A refresh: the lock is named in the If header.
            let h = ifh.ok_or_else(|| status(400))?;
            if !res.exists() {
                return Err(status(412));
            }
            let replies = self
                .state(
                    bucket,
                    vec![Op::Refresh {
                        path: lock_path,
                        tokens: h.submitted(),
                        principal: self.principal.clone(),
                        timeout_secs: timeout,
                    }],
                )
                .await?;
            return match replies.into_iter().next() {
                Some(Reply::Locked(lock)) => Ok(lock_answer(200, &lock, bucket, now, false)),
                Some(Reply::NotOwner) => Err(status(403)),
                _ => Err(precondition(412, "<D:lock-token-matches-request-uri/>")),
            };
        };
        if !doc.is(DAV, "lockinfo") {
            return Err(status(400));
        }
        let scope = doc.child(DAV, "lockscope").ok_or_else(|| status(400))?;
        let exclusive = if scope.child(DAV, "exclusive").is_some() {
            true
        } else if scope.child(DAV, "shared").is_some() {
            false
        } else {
            return Err(status(400));
        };
        if doc
            .child(DAV, "locktype")
            .and_then(|t| t.child(DAV, "write"))
            .is_none()
        {
            return Err(status(400));
        }
        let owner_xml = doc.child(DAV, "owner").map(Element::to_xml);
        // A lock is a write: a read-only key may not take one.
        self.require_write(bucket, &lock_path).await?;
        if let (Some(h), true) = (&ifh, res.exists()) {
            self.check_if(bucket, &lock_path, &res, h).await?;
        }
        if !res.exists() && !self.parent_exists(bucket, &lock_path).await? {
            return Err(status(409));
        }
        let token = format!("urn:uuid:{}", self.dav.up.uuid());
        let replies = self
            .state(
                bucket,
                vec![Op::Lock {
                    token,
                    root: lock_path.clone(),
                    depth_inf: depth_inf && !matches!(res, Res::File(_) | Res::Missing),
                    exclusive,
                    owner_xml,
                    principal: self.principal.clone(),
                    timeout_secs: timeout,
                    holder: None,
                    // Creating the file adds a member to its folder, as a
                    // PUT would.
                    checks: if res.exists() {
                        Vec::new()
                    } else {
                        vec![Check {
                            path: parent(&lock_path),
                            scope: Scope::Member,
                        }]
                    },
                    tokens: ifh.as_ref().map(IfHeader::submitted).unwrap_or_default(),
                }],
            )
            .await?;
        let lock = match replies.into_iter().next() {
            Some(Reply::Locked(lock)) => lock,
            Some(Reply::Conflict { .. }) => {
                return Err(precondition(423, "<D:no-conflicting-lock/>"))
            }
            Some(Reply::Full) => return Err(status(507)),
            _ => return Err(status(500)),
        };
        if res.exists() {
            return Ok(lock_answer(200, &lock, bucket, now, true));
        }
        // LOCK on an unmapped URL makes an empty file (RFC 4918 §7.3).
        match self
            .s3
            .put(
                bucket,
                &lock_path,
                Body::Empty,
                0,
                props::guess_type(&lock_path),
                &[],
                Some(&Cond::Absent),
            )
            .await
        {
            Ok(_) => {
                let _ = self
                    .state(bucket, vec![Op::ClearMoved(vec![lock_path])])
                    .await;
                Ok(lock_answer(201, &lock, bucket, now, true))
            }
            Err(e) if e.status == 412 || e.is("PreconditionFailed") => {
                Ok(lock_answer(200, &lock, bucket, now, true))
            }
            Err(e) => {
                let _ = self
                    .state(
                        bucket,
                        vec![Op::Unlock {
                            path: lock_path,
                            token: lock.token.clone(),
                            principal: self.principal.clone(),
                        }],
                    )
                    .await;
                Err(from_s3(&e))
            }
        }
    }

    async fn unlock(&self, loc: &Loc, req: Request<U::Body>) -> Out<U::Body> {
        let (bucket, key) = self.item(loc)?;
        // Windows sends the token without its angle brackets.
        let token = req
            .header("lock-token")
            .map(|t| {
                t.trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_owned()
            })
            .filter(|t| !t.is_empty())
            .ok_or_else(|| status(400))?;
        let res = self.resolve(bucket, key).await?;
        // The state object of a bucket the key cannot see is never asked.
        if !res.exists()
            && !self
                .s3
                .bucket_exists(bucket)
                .await
                .map_err(|e| from_s3(&e))?
        {
            return Err(status(404));
        }
        let path = match &res {
            Res::Missing => as_file(key).to_owned(),
            other => state_path(other, key),
        };
        let replies = self
            .state(
                bucket,
                vec![Op::Unlock {
                    path,
                    token,
                    principal: self.principal.clone(),
                }],
            )
            .await?;
        match replies.into_iter().next() {
            Some(Reply::Done) => Ok(status(204)),
            Some(Reply::NotOwner) => Err(status(403)),
            _ => Err(precondition(409, "<D:lock-token-matches-request-uri/>")),
        }
    }

    // -----------------------------------------------------------------
    // PROPPATCH
    // -----------------------------------------------------------------

    async fn proppatch(&self, loc: &Loc, mut req: Request<U::Body>) -> Out<U::Body> {
        let (bucket, key) = self.item(loc)?;
        let ifh = self.parse_if(&req)?;
        let doc = self
            .read_xml(std::mem::replace(&mut req.body, Body::Empty))
            .await?
            .ok_or_else(|| status(400))?;
        if !doc.is(DAV, "propertyupdate") {
            return Err(status(400));
        }
        let res = self.resolve(bucket, key).await?;
        if !res.exists() {
            return Err(status(404));
        }
        let path = state_path(&res, key);
        let etag = match &res {
            Res::File(m) => Some(m.etag.clone()),
            _ => None,
        };
        // Instructions in document order.
        let mut patches: Vec<Patch> = Vec::new();
        let mut names: Vec<(String, String)> = Vec::new();
        let mut protected: Vec<bool> = Vec::new();
        for instr in doc.elements() {
            let set = if instr.is(DAV, "set") {
                true
            } else if instr.is(DAV, "remove") {
                false
            } else {
                continue;
            };
            let prop = instr.child(DAV, "prop").ok_or_else(|| status(400))?;
            let inherited_lang = prop.lang().or_else(|| instr.lang()).or_else(|| doc.lang());
            for p in prop.elements() {
                let ns = p.ns.clone().unwrap_or_default();
                protected.push(ns == DAV && LIVE.contains(&p.name.as_str()));
                names.push((ns.clone(), p.name.clone()));
                patches.push(if set {
                    let xml = match (p.lang(), inherited_lang) {
                        (None, Some(lang)) => {
                            let mut root = p.clone();
                            root.attrs.push((
                                Some(xml::XML_NS.to_owned()),
                                "lang".to_owned(),
                                lang.to_owned(),
                            ));
                            root.to_xml()
                        }
                        _ => p.to_xml(),
                    };
                    Patch::Set(DeadProp {
                        ns,
                        name: p.name.clone(),
                        xml,
                    })
                } else {
                    Patch::Remove {
                        ns,
                        name: p.name.clone(),
                    }
                });
            }
        }
        if patches.is_empty() {
            return Err(status(400));
        }
        // Dead properties are writes: a read-only key may not change them.
        self.require_write(bucket, &path).await?;
        let statuses: Vec<u16> = if protected.iter().any(|p| *p) {
            protected
                .iter()
                .map(|p| if *p { 403 } else { 424 })
                .collect()
        } else {
            let holder = self
                .begin_write(
                    bucket,
                    vec![Check {
                        path: path.clone(),
                        scope: Scope::Exact,
                    }],
                    ifh.as_ref(),
                    (&path, &res),
                )
                .await?;
            let replies = self
                .state(
                    bucket,
                    vec![
                        Op::PropPatch {
                            path: path.clone(),
                            etag,
                            patches,
                        },
                        Op::EndWrite { holder },
                    ],
                )
                .await?;
            match replies.into_iter().next() {
                Some(Reply::Patched(s)) => s,
                _ => return Err(status(500)),
            }
        };
        let mut groups: Vec<(u16, Vec<String>)> = Vec::new();
        for ((ns, name), code) in names.iter().zip(statuses) {
            let el = props::prop_name(ns, name);
            match groups.iter_mut().find(|(c, _)| *c == code) {
                Some((_, v)) => v.push(el),
                None => groups.push((code, vec![el])),
            }
        }
        let href = match &res {
            Res::Bucket => path::href(bucket, ""),
            _ => path::href(bucket, &path),
        };
        let mut body = props::response(&href, &groups);
        if groups.iter().any(|(c, _)| *c == 403) {
            body = body.replace(
                "<D:status>HTTP/1.1 403 Forbidden</D:status>",
                "<D:status>HTTP/1.1 403 Forbidden</D:status><D:error><D:cannot-modify-protected-property/></D:error>",
            );
        }
        Ok(xml_resp(207, props::multistatus(&body)))
    }
}

fn lock_answer<B>(code: u16, lock: &Lock, bucket: &str, now: i64, with_token: bool) -> Resp<B> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>{}</D:lockdiscovery></D:prop>",
        props::active_lock(lock, bucket, now)
    );
    let mut r = xml_resp(code, body.into_bytes());
    if with_token {
        r.set_header("lock-token", format!("<{}>", lock.token));
    }
    r
}

fn forget_tree(path: &str) -> [Op; 2] {
    [
        Op::PropDrop {
            path: path.to_owned(),
            tree: true,
        },
        Op::DropLocks {
            path: path.to_owned(),
            tree: true,
        },
    ]
}

/// Drops the properties and locks of exactly these paths.
fn forget(paths: &[String]) -> Vec<Op> {
    paths
        .iter()
        .flat_map(|p| {
            [
                Op::PropDrop {
                    path: p.clone(),
                    tree: false,
                },
                Op::DropLocks {
                    path: p.clone(),
                    tree: false,
                },
            ]
        })
        .collect()
}

/// The state ops for keys a mutation deleted: their ledger rows, and the
/// properties and locks of each deleted file.
fn removal_plan(deleted: &[String]) -> Vec<Op> {
    if deleted.is_empty() {
        return Vec::new();
    }
    let mut ops = vec![Op::ClearMoved(deleted.to_vec())];
    for key in deleted.iter().filter(|k| !k.ends_with('/')) {
        ops.extend(forget(std::slice::from_ref(key)));
    }
    ops
}

/// The stateful collections a plan removes: each at or under `tree`, with
/// a deleted key under it and no remaining one. Each is judged on its own,
/// so a parent that survives does not keep a removed child's state, and
/// each is then probed on its own ([`Ctx::forget_removed`]).
fn gone_folders<'d, 'r>(
    tree: Option<&str>,
    stateful: &[String],
    deleted: impl Iterator<Item = &'d str>,
    remaining: impl Iterator<Item = &'r str>,
) -> Vec<String> {
    let Some(root) = tree else {
        return Vec::new();
    };
    let mut deleted: Vec<_> = deleted.collect();
    deleted.sort_unstable();
    let mut remaining: Vec<_> = remaining.collect();
    remaining.sort_unstable();
    stateful
        .iter()
        .filter(|folder| {
            folder.ends_with('/')
                && path::within(root, folder)
                && path::has_prefix_member(&deleted, folder)
                && !path::has_prefix_member(&remaining, folder)
        })
        .cloned()
        .collect()
}

/// Files and markers among `keys`: deletes run in these two groups.
fn split_markers<'a>(keys: impl Iterator<Item = &'a str>) -> [usize; 2] {
    let mut groups = [0, 0];
    for key in keys {
        groups[usize::from(key.ends_with('/'))] += 1;
    }
    groups
}

/// The calls a collection operation plans, judged against
/// `max_mutation_calls` before any change.
#[derive(Default)]
struct Plan {
    calls: usize,
}

impl Plan {
    /// `n` storage calls in batches of `per`, each batch renewing the
    /// reservation first.
    fn batches(&mut self, n: usize, per: usize) {
        self.calls += n + n.div_ceil(per.max(1));
    }
}

fn copied_file_props(from: &str, to: &str, etag: &str) -> Op {
    // The bridge preserves the copied source's ETag on the destination.
    Op::PropCopy {
        from: from.to_owned(),
        to: to.to_owned(),
        tree: false,
        from_etag: Some(etag.to_owned()),
        to_etag: Some(etag.to_owned()),
    }
}

#[derive(Default)]
struct TreeCopy {
    versions: Vec<MovedMember>,
    properties: Vec<Op>,
    failed: Vec<(String, u16)>,
}

fn visible_collection_prefix(key: &str) -> &str {
    let bytes = key
        .split_inclusive('/')
        .take_while(|part| part.strip_suffix('/').is_some_and(path::addressable))
        .map(str::len)
        .sum();
    &key[..bytes]
}

fn empty_copy_markers(mut candidates: Vec<String>, members: &[(Entry, String)]) -> Vec<String> {
    candidates.sort_unstable();
    candidates.dedup();
    let mut keys: Vec<_> = members.iter().map(|(_, key)| key.as_str()).collect();
    keys.sort_unstable();
    candidates
        .iter()
        .enumerate()
        .filter_map(|(i, prefix)| {
            // A copied member or a deeper marker already implies this folder.
            let first = keys.partition_point(|key| *key < prefix.as_str());
            let implied = keys.get(first).is_some_and(|key| key.starts_with(prefix))
                || candidates
                    .get(i + 1)
                    .is_some_and(|key| key.starts_with(prefix));
            (!implied).then(|| prefix.clone())
        })
        .collect()
}

fn hidden_tree_keys(entries: &[Entry]) -> HashSet<String> {
    let mut keys: Vec<_> = entries.iter().map(|e| e.key.as_str()).collect();
    keys.sort_unstable();
    entries
        .iter()
        .filter(|e| {
            if !path::addressable(&e.key) {
                return true;
            }
            if e.key.ends_with('/') {
                return e.size != 0;
            }
            // As in children(), a collection (explicit marker or any
            // descendant) shadows a same-named file.
            let prefix = as_collection(&e.key);
            let first = keys.partition_point(|k| *k < prefix.as_str());
            keys.get(first).is_some_and(|k| k.starts_with(&prefix))
        })
        .map(|e| e.key.clone())
        .collect()
}

fn hidden_folder<B>() -> Resp<B> {
    Response::new(409).with_bytes(
        "text/plain; charset=utf-8",
        b"this folder holds objects WebDAV cannot show; use an S3 tool".to_vec(),
    )
}

fn require_visible_tree<B>(entries: &[Entry]) -> Result<(), Resp<B>> {
    if !hidden_tree_keys(entries).is_empty() {
        return Err(hidden_folder());
    }
    Ok(())
}

fn too_many<B>(cap: usize) -> Resp<B> {
    let msg = format!(
        "This folder holds more than {cap} items, more than one WebDAV request may copy, move or \
         delete. Use the S3 endpoint for a folder this size."
    );
    Response::new(403).with_bytes("text/plain; charset=utf-8", msg.into_bytes())
}

/// `207` naming the members that failed.
fn reservation_busy<B>() -> Resp<B> {
    status(503).with_header("retry-after", "2")
}

fn failed_members<B>(bucket: &str, failed: &[(String, u16)]) -> Resp<B> {
    failed_members_with_kept(bucket, failed, &[])
}

/// `kept`: `(destination, source)` of members a partial MOVE left.
fn failed_members_with_kept<B>(
    bucket: &str,
    failed: &[(String, u16)],
    kept: &[(String, String)],
) -> Resp<B> {
    let mut body: String = failed
        .iter()
        .map(|(k, code)| props::status_response(&path::href(bucket, k), *code))
        .collect();
    for (key, _) in kept {
        body.push_str(&props::status_response_with_description(
            &path::href(bucket, key),
            409,
            Some("kept after a partial MOVE"),
        ));
    }
    xml_resp(207, props::multistatus(&body))
}

/// The guard a write carries once its conditions were judged against
/// `existing`.
fn guard_for(existing: Option<&Meta>) -> Cond {
    match existing {
        Some(m) => Cond::Is(m.etag.clone()),
        None => Cond::Absent,
    }
}

/// Mirrors the private `matches_tag`/`valid_tag` parser in
/// velmora-s3-proto/src/read.rs. Weak comparison ignores the prefix on
/// either side; strong comparison only matches two strong tags.
fn matches_etag(list: &str, etag: Option<&str>, weak: bool) -> Result<bool, ()> {
    let mut rest = list.trim();
    if rest == "*" {
        return Ok(etag.is_some());
    }
    let etag = etag.and_then(|tag| match tag.strip_prefix("W/") {
        Some(opaque) => weak.then_some(opaque),
        None => Some(tag),
    });
    let mut found = false;
    loop {
        let (tag, is_weak) = rest.strip_prefix("W/").map_or((rest, false), |t| (t, true));
        let inner = tag.strip_prefix('"').ok_or(())?;
        let end = inner.find('"').ok_or(())?;
        if !inner.as_bytes()[..end]
            .iter()
            .all(|c| *c == 0x21 || (0x23..=0x7e).contains(c))
        {
            return Err(());
        }
        found |= (weak || !is_weak) && etag == Some(&tag[..end + 2]);
        rest = inner[end + 1..].trim_start();
        if rest.is_empty() {
            return Ok(found);
        }
        rest = rest.strip_prefix(',').ok_or(())?.trim_start();
    }
}

#[cfg(test)]
mod etag_tests {
    use super::matches_etag;

    #[test]
    fn validator_lists_use_opaque_tags_and_reject_invalid_syntax() {
        assert_eq!(
            matches_etag(r#"  W/"other" , "a,b"  "#, Some(r#"W/"a,b""#), true),
            Ok(true)
        );
        assert_eq!(
            matches_etag(r#""a,b""#, Some(r#"W/"a,b""#), false),
            Ok(false)
        );
        assert_eq!(
            matches_etag(r#"W/"a,b""#, Some(r#""a,b""#), false),
            Ok(false)
        );
        assert_eq!(matches_etag(" * ", Some(r#"W/"a,b""#), false), Ok(true));
        assert_eq!(matches_etag(" * ", None, true), Ok(false));
        assert_eq!(matches_etag(r#""a,b", "#, Some(r#""a,b""#), true), Err(()));
        assert_eq!(matches_etag(r#""a b""#, Some(r#""a,b""#), true), Err(()));
    }
}

/// `If-Match`, `If-None-Match` and `If-Unmodified-Since` of a write,
/// judged against what is there. `Some(guard)` when there were any.
fn http_conditions<B>(
    req: &Request<B>,
    existing: Option<&Meta>,
    exists: bool,
) -> Result<Option<Cond>, Resp<B>> {
    let etag = existing.map(|m| m.etag.as_str());
    let mut any = false;
    let matches = |v: &str, weak| {
        if v.trim() == "*" {
            Ok(exists)
        } else {
            matches_etag(v, etag, weak).map_err(|()| status(400))
        }
    };
    if let Some(v) = req.header("if-match") {
        any = true;
        if !matches(v, false)? {
            return Err(status(412));
        }
    }
    if let Some(v) = req.header("if-none-match") {
        any = true;
        if matches(v, true)? {
            return Err(status(412));
        }
    }
    if let Some(v) = req
        .header("if-unmodified-since")
        .filter(|_| req.header("if-match").is_none())
    {
        any = true;
        if let (Some(m), Some(t)) = (existing, crate::time::parse_http_date(v)) {
            if m.modified_ms / 1000 > t / 1000 {
                return Err(status(412));
            }
        }
    }
    Ok(any.then(|| guard_for(existing)))
}

/// What a PROPFIND asks for.
enum Want {
    /// `allprop`; an `include` names nothing beyond it here, since every
    /// live property is in allprop already.
    AllProp,
    PropName,
    Props(Vec<(String, String)>),
}

impl Want {
    fn of(doc: Option<&Element>) -> Result<Want, ()> {
        let Some(doc) = doc else {
            return Ok(Want::AllProp);
        };
        if !doc.is(DAV, "propfind") {
            return Err(());
        }
        let names = |e: &Element| -> Vec<(String, String)> {
            e.elements()
                .map(|p| (p.ns.clone().unwrap_or_default(), p.name.clone()))
                .collect()
        };
        if doc.child(DAV, "allprop").is_some() {
            return Ok(Want::AllProp);
        }
        if doc.child(DAV, "propname").is_some() {
            return Ok(Want::PropName);
        }
        match doc.child(DAV, "prop") {
            Some(p) => Ok(Want::Props(names(p))),
            None => Err(()),
        }
    }

    fn needs_state(&self) -> bool {
        match self {
            Want::AllProp | Want::PropName => true,
            Want::Props(names) => names
                .iter()
                .any(|(ns, n)| ns != DAV || !LIVE.contains(&n.as_str()) || n == "lockdiscovery"),
        }
    }

    fn needs_dead(&self) -> bool {
        match self {
            Want::AllProp | Want::PropName => true,
            Want::Props(names) => names
                .iter()
                .any(|(ns, n)| ns != DAV || !LIVE.contains(&n.as_str())),
        }
    }

    fn dead_names(&self) -> Option<Vec<(String, String)>> {
        match self {
            Want::Props(names) => Some(names.clone()),
            _ => None,
        }
    }

    fn render(&self, r: &Resource, dead: &[DeadProp], discovery: &str) -> String {
        let live_value = |name: &str| -> Option<String> {
            if name == "lockdiscovery" {
                Some(discovery.to_owned())
            } else {
                r.live(name)
            }
        };
        let href = r.href();
        match self {
            Want::AllProp => {
                let mut ok = Vec::new();
                for name in LIVE {
                    if let Some(v) = live_value(name) {
                        ok.push(props::live_element(name, &v));
                    }
                }
                ok.extend(dead.iter().map(props::dead_element));
                props::response(&href, &[(200, ok)])
            }
            Want::PropName => {
                let mut ok = Vec::new();
                for name in LIVE {
                    if live_value(name).is_some() {
                        ok.push(props::prop_name(DAV, name));
                    }
                }
                ok.extend(dead.iter().map(|p| props::prop_name(&p.ns, &p.name)));
                props::response(&href, &[(200, ok)])
            }
            Want::Props(names) => {
                let mut ok = Vec::new();
                let mut missing = Vec::new();
                for (ns, name) in names {
                    let live = (ns == DAV && LIVE.contains(&name.as_str()))
                        .then(|| live_value(name))
                        .flatten();
                    if let Some(v) = live {
                        ok.push(props::live_element(name, &v));
                    } else if let Some(p) = dead.iter().find(|p| p.ns == *ns && p.name == *name) {
                        ok.push(props::dead_element(p));
                    } else {
                        missing.push(props::prop_name(ns, name));
                    }
                }
                props::response(&href, &[(200, ok), (404, missing)])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth() {
        let v = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("APVLX:se:cret")
        );
        let c = basic_credentials(&v).unwrap();
        assert_eq!(
            (c.access_key.as_str(), c.secret.as_str()),
            ("APVLX", "se:cret")
        );
        assert!(basic_credentials("Bearer x").is_none());
        assert!(basic_credentials("Basic !!!").is_none());
        let empty = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(":x")
        );
        assert!(basic_credentials(&empty).is_none());
    }

    #[test]
    fn destination_urls() {
        assert_eq!(
            header_url_path("https://dav.test/b/x%20y", "https://dav.test").as_deref(),
            Some("/b/x%20y")
        );
        assert_eq!(header_url_path("https://other/b/x", "dav.test"), None);
        assert_eq!(
            header_url_path("/b/x?q", "dav.test").as_deref(),
            Some("/b/x")
        );
        assert_eq!(header_url_path("b/x", "dav.test"), None);
    }

    #[test]
    fn timeouts() {
        let cfg = Config::default();
        assert_eq!(timeout_secs(None, &cfg), 600);
        assert_eq!(timeout_secs(Some("Second-30"), &cfg), 30);
        assert_eq!(
            timeout_secs(Some("Infinite, Second-4100000000"), &cfg),
            3600
        );
        assert_eq!(timeout_secs(Some("Second-4100000000"), &cfg), 3600);
        assert_eq!(timeout_secs(Some("bogus"), &cfg), 600);
    }
}
