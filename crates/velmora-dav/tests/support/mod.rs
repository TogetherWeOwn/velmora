//! The gateway over the real storage core, in process: every WebDAV
//! request becomes S3 requests that the bridge authenticates (SigV4 with
//! the app password, through the WebDAV entry point), authorises and
//! serves from an in-memory catalogue and blob store. Bucket state
//! objects are in-memory SQLite databases running the same SQL as the
//! Durable Object.

#![allow(dead_code)]

#[path = "../../../velmora-bridge/tests/service_support/mod.rs"]
pub mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;
use futures_util::stream::{self, StreamExt};
use service_support::{rig, Resp, Rig, Signer, HOST};
use velmora_bridge::entry::{ENTRY_HEADER, WEBDAV};
use velmora_bridge::{Body as BBody, KeyStatus, Method, Perm, S3Request};
use velmora_dav::handler::{Config, Dav, StatePort};
use velmora_dav::http::{Body, Request, Response};
use velmora_dav::s3::{S3Error, Upstream};
use velmora_dav::state::{Engine, Op, Reply, Sql, Val};

pub const BUCKET: &str = "dav";
pub const APP: &str = "APVLAPPPASSWORD00001";
pub const APP_SECRET: &str = "app-password-secret-000000000000000001";
pub const APP2: &str = "APVLAPPPASSWORD00002";
pub const APP2_SECRET: &str = "app-password-secret-000000000000000002";
pub const RO: &str = "APVLREADONLY00000001";
pub const RO_SECRET: &str = "app-password-secret-read-only-00000001";
pub const S3KEY: &str = "AKVLS3KEY00000000001";
pub const S3KEY_SECRET: &str = "s3-key-secret-00000000000000000000001";
pub const DAV_HOST: &str = "dav.test";
pub const MIB: usize = 1024 * 1024;

/// A body of the test runtime: bytes and how far they were read.
pub struct TBody {
    bytes: Vec<u8>,
    pos: usize,
}

impl TBody {
    pub fn new(bytes: Vec<u8>) -> Self {
        TBody { bytes, pos: 0 }
    }
}

/// The storage Worker in process, reached as through `DavEntry`.
pub struct Up {
    pub rig: Rc<Rig>,
    uuids: Cell<u64>,
    /// Every request sent: method and target.
    pub sent: RefCell<Vec<(String, String)>>,
    /// Requests sent with no entry marker (as the default entrypoint
    /// would): an app password must then be refused.
    pub unmarked: Cell<bool>,
}

impl Upstream for Up {
    type Body = TBody;

    fn send(
        &self,
        method: &str,
        target: &str,
        mut headers: Vec<(String, String)>,
        body: Body<TBody>,
        len: Option<u64>,
    ) -> LocalBoxFuture<'_, Result<Response<TBody>, S3Error>> {
        self.sent
            .borrow_mut()
            .push((method.to_owned(), target.to_owned()));
        if !self.unmarked.get() {
            headers.push((ENTRY_HEADER.to_owned(), WEBDAV.to_owned()));
        }
        let bytes = match body {
            Body::Empty => Vec::new(),
            Body::Bytes(b) => b,
            Body::Native(b) => b.bytes[b.pos..].to_vec(),
        };
        let body = if bytes.is_empty() && len.is_none() {
            BBody::Empty
        } else {
            BBody::Stream {
                declared_len: len,
                stream: stream::iter(
                    bytes
                        .chunks(64 * 1024)
                        .map(|c| Ok(c.to_vec()))
                        .collect::<Vec<_>>(),
                )
                .boxed_local(),
            }
        };
        let req = S3Request {
            method: Method::parse(method),
            raw_target: target.to_owned(),
            headers,
            body,
        };
        let bridge = Rc::clone(&self.rig.bridge);
        Box::pin(async move {
            let resp = Resp::collect(bridge.handle(req).await).await;
            Ok(Response {
                status: resp.status,
                headers: resp.headers,
                body: Body::Native(TBody::new(resp.body)),
            })
        })
    }

    fn read<'a>(
        &'a self,
        body: &'a mut TBody,
        max: usize,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>, S3Error>> {
        // Hands out at most 1 MiB at a time, as a stream would.
        let n = max.min(MIB).min(body.bytes.len() - body.pos);
        let out = body.bytes[body.pos..body.pos + n].to_vec();
        body.pos += n;
        Box::pin(async move { Ok(out) })
    }

    fn now_ms(&self) -> i64 {
        self.rig.now().0
    }

    fn uuid(&self) -> String {
        let n = self.uuids.get() + 1;
        self.uuids.set(n);
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    fn sleep(&self, ms: u64) -> LocalBoxFuture<'_, ()> {
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(ms)))
    }
}

/// SQLite in memory, the same SQL as the Durable Object.
pub struct MemSql(pub rusqlite::Connection);

impl Sql for MemSql {
    fn exec(&self, sql: &str, params: &[Val]) -> Result<Vec<Vec<Val>>, String> {
        let mut stmt = self.0.prepare(sql).map_err(|e| e.to_string())?;
        let cols = stmt.column_count();
        let params: Vec<rusqlite::types::Value> = params
            .iter()
            .map(|v| match v {
                Val::Null => rusqlite::types::Value::Null,
                Val::Int(i) => rusqlite::types::Value::Integer(*i),
                Val::Text(s) => rusqlite::types::Value::Text(s.clone()),
            })
            .collect();
        let mut rows = stmt
            .query(rusqlite::params_from_iter(params))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let mut r = Vec::with_capacity(cols);
            for i in 0..cols {
                let v: rusqlite::types::Value = row.get(i).map_err(|e| e.to_string())?;
                r.push(match v {
                    rusqlite::types::Value::Null => Val::Null,
                    rusqlite::types::Value::Integer(i) => Val::Int(i),
                    rusqlite::types::Value::Text(s) => Val::Text(s),
                    other => Val::Text(format!("{other:?}")),
                });
            }
            out.push(r);
        }
        Ok(out)
    }
}

/// One in-memory state object per name. Each batch goes through JSON,
/// as it does to the Durable Object.
#[derive(Default)]
pub struct States {
    pub dbs: RefCell<HashMap<String, Rc<MemSql>>>,
    /// Unix seconds the objects see.
    pub now: Cell<i64>,
    pub calls: Cell<u32>,
}

impl StatePort for States {
    fn call<'a>(
        &'a self,
        name: &'a str,
        ops: Vec<Op>,
    ) -> LocalBoxFuture<'a, Result<Vec<Reply>, String>> {
        self.calls.set(self.calls.get() + 1);
        let db = Rc::clone(
            self.dbs
                .borrow_mut()
                .entry(name.to_owned())
                .or_insert_with(|| {
                    Rc::new(MemSql(rusqlite::Connection::open_in_memory().unwrap()))
                }),
        );
        let wire = serde_json::to_string(&ops).unwrap();
        let ops: Vec<Op> = serde_json::from_str(&wire).unwrap();
        let out = Engine {
            sql: db.as_ref(),
            now: self.now.get(),
        }
        .run(ops);
        let out = out.map(|r| {
            let wire = serde_json::to_string(&r).unwrap();
            serde_json::from_str(&wire).unwrap()
        });
        Box::pin(async move { out })
    }
}

/// A client answer, collected.
pub struct Got {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Got {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    #[track_caller]
    pub fn expect(&self, status: u16) -> &Self {
        assert_eq!(self.status, status, "body: {}", self.text());
        self
    }

    /// Every `<D:href>` of a multistatus, in order.
    pub fn hrefs(&self) -> Vec<String> {
        values(&self.text(), "D:href")
    }
}

/// The text of every `<tag>…</tag>`, in order.
pub fn values(text: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(&open) {
        rest = &rest[i + open.len()..];
        let Some(j) = rest.find(&close) else { break };
        out.push(rest[..j].to_string());
        rest = &rest[j + close.len()..];
    }
    out
}

pub struct World {
    pub dav: Dav<Up, States>,
    pub rig: Rc<Rig>,
    /// An S3 key on the same bucket, through the S3 entry point.
    pub s3: Signer,
}

pub fn basic(user: &str, secret: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"))
    )
}

impl World {
    pub async fn new() -> World {
        Self::with(Config::default()).await
    }

    pub async fn with(mut cfg: Config) -> World {
        let rig = rig();
        let b = rig.bucket(BUCKET, true).await;
        let other = rig.bucket("other", true).await;
        for (akid, secret, perm) in [
            (APP, APP_SECRET, Perm::Rw),
            (APP2, APP2_SECRET, Perm::Rw),
            (RO, RO_SECRET, Perm::Ro),
            (S3KEY, S3KEY_SECRET, Perm::Rw),
        ] {
            rig.key(akid, secret, KeyStatus::Active).await;
            rig.grant(akid, &b, perm).await;
        }
        rig.grant(APP, &other, Perm::Rw).await;
        let rig = Rc::new(rig);
        cfg.s3_host = HOST.to_owned();
        let states = States::default();
        states.now.set(rig.now().0 / 1000);
        World {
            dav: Dav {
                up: Up {
                    rig: Rc::clone(&rig),
                    uuids: Cell::new(0),
                    sent: RefCell::new(Vec::new()),
                    unmarked: Cell::new(false),
                },
                state: states,
                cfg,
            },
            rig,
            s3: Signer::new(S3KEY, S3KEY_SECRET),
        }
    }

    /// Sends a request as `APP`.
    pub async fn req(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Got {
        self.req_as(APP, APP_SECRET, method, path, headers, body)
            .await
    }

    pub async fn req_as(
        &self,
        user: &str,
        secret: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Got {
        let mut h: Vec<(String, String)> = vec![
            ("host".into(), DAV_HOST.into()),
            ("authorization".into(), basic(user, secret)),
        ];
        let mut with_len = true;
        for (n, v) in headers {
            if *n == "-content-length" {
                with_len = false;
                continue;
            }
            if *n == "authorization" {
                h.retain(|(k, _)| k != "authorization");
                if v.is_empty() {
                    continue;
                }
            }
            h.push((n.to_ascii_lowercase(), v.to_string()));
        }
        if with_len && !body.is_empty() {
            h.push(("content-length".into(), body.len().to_string()));
        }
        let resp = self
            .dav
            .handle(Request {
                method: method.to_owned(),
                path: path.to_owned(),
                headers: h,
                body: if body.is_empty() {
                    Body::Empty
                } else {
                    Body::Native(TBody::new(body.to_vec()))
                },
            })
            .await;
        let body = match resp.body {
            Body::Empty => Vec::new(),
            Body::Bytes(b) => b,
            Body::Native(b) => b.bytes[b.pos..].to_vec(),
        };
        Got {
            status: resp.status,
            headers: resp.headers,
            body,
        }
    }

    /// The object as the S3 entry point sees it: status, body, ETag.
    pub async fn s3_get(&self, key: &str) -> (u16, Vec<u8>, Option<String>) {
        let r = self
            .rig
            .call(
                &self.s3,
                Method::Get,
                &service_support::path(BUCKET, key),
                &[],
                &[],
                b"",
            )
            .await;
        let etag = r.header("etag").map(str::to_owned);
        (r.status, r.body, etag)
    }

    pub async fn s3_put(&self, key: &str, body: &[u8]) -> u16 {
        self.rig.put(&self.s3, BUCKET, key, body).await.status
    }

    /// `(key, size, etag)` of every object, through ListObjectsV2.
    pub async fn s3_list(&self, prefix: &str) -> Vec<(String, u64, String)> {
        let r = self
            .rig
            .call(
                &self.s3,
                Method::Get,
                &format!("/{BUCKET}"),
                &[("list-type", "2"), ("prefix", prefix)],
                &[],
                b"",
            )
            .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let keys = r.values("Key");
        let sizes = r.values("Size");
        let etags = r.values("ETag");
        keys.into_iter()
            .zip(sizes)
            .zip(etags)
            .map(|((k, s), e)| (unescape(&k), s.parse().unwrap(), unescape(&e)))
            .collect()
    }

    /// Advances the clock of the storage core and of the state objects.
    pub fn advance_secs(&self, secs: u32) {
        self.rig.bridge.clock.advance_secs(secs);
        self.dav.state.now.set(self.rig.now().0 / 1000);
    }
}

pub fn propfind_body(props: &[&str]) -> Vec<u8> {
    let mut s = String::from("<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:prop>");
    for p in props {
        s.push_str(&format!("<D:{p}/>"));
    }
    s.push_str("</D:prop></D:propfind>");
    s.into_bytes()
}

pub fn lockinfo(scope: &str, owner: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?><D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:{scope}/></D:lockscope>\
<D:locktype><D:write/></D:locktype><D:owner><D:href>{owner}</D:href></D:owner></D:lockinfo>"
    )
    .into_bytes()
}

pub fn pattern(seed: u8, len: usize) -> Vec<u8> {
    service_support::pattern(seed, len)
}

/// XML character data to text (the five predefined entities).
pub fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}
