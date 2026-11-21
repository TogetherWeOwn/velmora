//! The WebDAV gateway Worker: `fetch` -> `velmora_dav::Dav::handle`.
//!
//! Bindings:
//! - `STORAGE`: a service binding to the storage Worker's named
//!   entrypoint `DavEntry`, the one entry point that accepts app
//!   passwords. Every S3 call goes there, signed with the caller's own
//!   app password; the gateway holds no credential of its own.
//! - `DAV_STATE`: the `DavState` Durable Object class, one object per
//!   bucket: locks, write leases and dead properties.
//! - vars `S3_HOST` (the storage Worker's `S3_HOST`, which every request
//!   is signed for), `S3_REGION`, and `DAV_REALM` (the name clients show
//!   at login; default `WebDAV`).
//!
//! Logs carry the method, the status and the time taken; never a path,
//! a header or a body (the Authorization header holds the password).

use std::time::Duration;

use futures_util::future::LocalBoxFuture;
use futures_util::StreamExt;
use velmora_dav::handler::{Config, Dav, StatePort};
use velmora_dav::http::{Body, Request as DavRequest, Response as DavResponse};
use velmora_dav::s3::{S3Error, Upstream};
use velmora_dav::state::{Engine, Op, Reply, Sql, Val};
use worker::js_sys::{self, Reflect};
use worker::wasm_bindgen::{self, JsCast, JsValue};
use worker::{
    console_log, durable_object, event, Context, Delay, DurableObject, EncodeBody, Env, Fetcher,
    FixedLengthStream, Headers, Method, ObjectNamespace, Request, RequestInit, Response,
    ResponseBody, Result, SqlStorage, SqlStorageValue, State,
};

/// A body of the runtime: a JavaScript stream passed through untouched,
/// or the same stream being read from Rust (an upload in parts).
pub enum WBody {
    Js(worker::web_sys::ReadableStream),
    Reading {
        stream: worker::ByteStream,
        left: Vec<u8>,
    },
}

/// The storage Worker behind `STORAGE`.
struct Storage {
    fetcher: Fetcher,
}

fn transport() -> S3Error {
    S3Error::transport()
}

fn method_of(m: &str) -> Method {
    match m {
        "HEAD" => Method::Head,
        "PUT" => Method::Put,
        "POST" => Method::Post,
        "DELETE" => Method::Delete,
        _ => Method::Get,
    }
}

/// A body as a stream the runtime can send with a known length.
fn js_body(body: Body<WBody>, len: Option<u64>) -> Result<Option<JsValue>> {
    Ok(match body {
        // An empty body that must say so (`Content-Length: 0`): a write.
        // Without a body the runtime sends no length, and the storage
        // Worker refuses a write without one (411).
        Body::Empty if len == Some(0) => Some(js_sys::Uint8Array::new_with_length(0).into()),
        Body::Empty => None,
        Body::Bytes(b) => Some(js_sys::Uint8Array::from(b.as_slice()).into()),
        Body::Native(WBody::Js(stream)) => match len {
            Some(len) => {
                let s = worker::ByteStream::from(stream);
                let fixed: worker::worker_sys::FixedLengthStream =
                    FixedLengthStream::wrap(s, len).into();
                Some(fixed.readable().into())
            }
            None => Some(stream.into()),
        },
        Body::Native(WBody::Reading { stream, left }) => {
            let head = futures_util::stream::once(async move { Ok(left) });
            let s = head.chain(stream);
            match len {
                Some(len) => {
                    let fixed: worker::worker_sys::FixedLengthStream =
                        FixedLengthStream::wrap(s, len).into();
                    Some(fixed.readable().into())
                }
                None => Some(Response::from_stream(s)?.body_stream()?.into()),
            }
        }
    })
}

trait BodyStream {
    fn body_stream(self) -> Result<worker::web_sys::ReadableStream>;
}

impl BodyStream for Response {
    fn body_stream(self) -> Result<worker::web_sys::ReadableStream> {
        match self.body() {
            ResponseBody::Stream(s) => Ok(s.clone()),
            _ => Err(worker::Error::RustError("no stream".into())),
        }
    }
}

impl Upstream for Storage {
    type Body = WBody;

    fn send(
        &self,
        method: &str,
        target: &str,
        headers: Vec<(String, String)>,
        body: Body<WBody>,
        len: Option<u64>,
    ) -> LocalBoxFuture<'_, std::result::Result<DavResponse<WBody>, S3Error>> {
        let host = headers
            .iter()
            .find(|(n, _)| n == "host")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let url = format!("https://{host}{target}");
        let method = method.to_owned();
        Box::pin(async move {
            let h = Headers::new();
            for (n, v) in &headers {
                // `host` comes from the URL; `content-length` from the body.
                if n == "host" || n == "content-length" {
                    continue;
                }
                h.append(n, v).map_err(|_| transport())?;
            }
            let mut init = RequestInit::new();
            init.with_method(method_of(&method)).with_headers(h);
            let js = js_body(body, len).map_err(|_| transport())?;
            init.with_body(js);
            let req = Request::new_with_init(&url, &init).map_err(|_| transport())?;
            let resp = self
                .fetcher
                .fetch_request(req)
                .await
                .map_err(|_| transport())?;
            let status = resp.status_code();
            let headers: Vec<(String, String)> = resp.headers().entries().collect();
            let body = match resp.body() {
                ResponseBody::Stream(s) => Body::Native(WBody::Js(s.clone())),
                ResponseBody::Body(b) => Body::Bytes(b.clone()),
                ResponseBody::Empty => Body::Empty,
            };
            Ok(DavResponse {
                status,
                headers,
                body,
            })
        })
    }

    fn read<'a>(
        &'a self,
        body: &'a mut WBody,
        max: usize,
    ) -> LocalBoxFuture<'a, std::result::Result<Vec<u8>, S3Error>> {
        Box::pin(async move {
            if let WBody::Js(s) = body {
                *body = WBody::Reading {
                    stream: worker::ByteStream::from(s.clone()),
                    left: Vec::new(),
                };
            }
            let WBody::Reading { stream, left } = body else {
                unreachable!("made a reader above");
            };
            if left.is_empty() {
                match stream.next().await {
                    None => return Ok(Vec::new()),
                    Some(Ok(chunk)) => *left = chunk,
                    Some(Err(_)) => return Err(transport()),
                }
            }
            let n = max.min(left.len());
            let rest = left.split_off(n);
            Ok(std::mem::replace(left, rest))
        })
    }

    fn now_ms(&self) -> i64 {
        worker::Date::now().as_millis() as i64
    }

    fn uuid(&self) -> String {
        random_uuid().unwrap_or_default()
    }

    fn sleep(&self, ms: u64) -> LocalBoxFuture<'_, ()> {
        Box::pin(Delay::from(Duration::from_millis(ms)))
    }
}

/// `crypto.randomUUID()`.
fn random_uuid() -> Option<String> {
    let crypto = Reflect::get(&js_sys::global(), &JsValue::from_str("crypto")).ok()?;
    let f = Reflect::get(&crypto, &JsValue::from_str("randomUUID")).ok()?;
    f.dyn_into::<js_sys::Function>()
        .ok()?
        .call0(&crypto)
        .ok()?
        .as_string()
}

/// The bucket state objects behind `DAV_STATE`.
struct States {
    namespace: ObjectNamespace,
}

impl StatePort for States {
    fn call<'a>(
        &'a self,
        name: &'a str,
        ops: Vec<Op>,
    ) -> LocalBoxFuture<'a, std::result::Result<Vec<Reply>, String>> {
        Box::pin(async move {
            let body = serde_json::to_string(&ops).map_err(|_| "encode".to_owned())?;
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_body(Some(JsValue::from_str(&body)));
            let req = Request::new_with_init("https://dav-state/", &init)
                .map_err(|_| "request".to_owned())?;
            let stub = self
                .namespace
                .id_from_name(name)
                .and_then(|id| id.get_stub())
                .map_err(|_| "no object".to_owned())?;
            let mut resp = stub
                .fetch_with_request(req)
                .await
                .map_err(|_| "call failed".to_owned())?;
            if resp.status_code() != 200 {
                return Err("call refused".to_owned());
            }
            let raw = resp.text().await.map_err(|_| "reply".to_owned())?;
            serde_json::from_str(&raw).map_err(|_| "reply".to_owned())
        })
    }
}

fn config(env: &Env) -> Option<Config> {
    let var = |name: &str| env.var(name).ok().map(|v| v.to_string());
    Some(Config {
        s3_host: var("S3_HOST").filter(|h| !h.is_empty())?,
        region: var("S3_REGION").unwrap_or_else(|| "auto".to_owned()),
        realm: var("DAV_REALM").unwrap_or_else(|| "WebDAV".to_owned()),
        ..Config::default()
    })
}

fn to_response(resp: DavResponse<WBody>) -> Result<Response> {
    let headers = Headers::new();
    for (n, v) in &resp.headers {
        headers.append(n, v)?;
    }
    let out = match resp.body {
        Body::Empty => Response::empty()?,
        Body::Bytes(b) => Response::from_bytes(b)?,
        Body::Native(WBody::Js(s)) => Response::from_body(ResponseBody::Stream(s))?,
        Body::Native(WBody::Reading { stream, left }) => {
            let head = futures_util::stream::once(async move { Ok(left) });
            Response::from_stream(head.chain(stream))?
        }
    };
    // `manual`: a download is sent as stored; a `content-encoding` header
    // describes the stored bytes and must not be applied again.
    Ok(out
        .with_status(resp.status)
        .with_headers(headers)
        .with_encode_body(EncodeBody::Manual))
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let started = worker::Date::now().as_millis();
    let method = req.inner().method();
    let (Some(cfg), Ok(fetcher), Ok(namespace)) = (
        config(&env),
        env.service("STORAGE"),
        env.durable_object("DAV_STATE"),
    ) else {
        console_log!("webdav: configuration refused");
        return Ok(Response::empty()?.with_status(500));
    };
    let url = req.inner().url();
    // The path as sent: after the authority, before any query.
    let path = url
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or("/");
    // A fragment stays in: the handler refuses a target that has one.
    let path = path.split('?').next().unwrap_or("/").to_owned();
    let mut headers: Vec<(String, String)> = req.headers().entries().collect();
    if !headers.iter().any(|(n, _)| n == "host") {
        if let Some(host) = url.split_once("://").and_then(|(_, r)| r.split('/').next()) {
            headers.push(("host".into(), host.to_owned()));
        }
    }
    let body = match req.inner().body() {
        Some(s) => Body::Native(WBody::Js(s)),
        None => Body::Empty,
    };
    let dav = Dav {
        up: Storage { fetcher },
        state: States { namespace },
        cfg,
    };
    let resp = dav
        .handle(DavRequest {
            method: method.clone(),
            path,
            headers,
            body,
        })
        .await;
    let status = resp.status;
    console_log!(
        "webdav {} {} {}ms",
        method,
        status,
        worker::Date::now().as_millis().saturating_sub(started)
    );
    to_response(resp)
}

/// The Durable Object's SQLite storage as the state engine's port.
struct DoSql(SqlStorage);

impl Sql for DoSql {
    fn exec(&self, sql: &str, params: &[Val]) -> std::result::Result<Vec<Vec<Val>>, String> {
        let bindings: Vec<SqlStorageValue> = params
            .iter()
            .map(|v| match v {
                Val::Null => SqlStorageValue::Null,
                Val::Int(i) => SqlStorageValue::Integer(*i),
                Val::Text(s) => SqlStorageValue::String(s.clone()),
            })
            .collect();
        let cursor = self
            .0
            .exec(sql, Some(bindings))
            .map_err(|_| "sql".to_owned())?;
        let mut rows = Vec::new();
        for row in cursor.raw() {
            let row = row.map_err(|_| "sql row".to_owned())?;
            rows.push(
                row.into_iter()
                    .map(|v| match v {
                        SqlStorageValue::Null => Val::Null,
                        SqlStorageValue::Integer(i) => Val::Int(i),
                        SqlStorageValue::Float(f) => Val::Int(f as i64),
                        SqlStorageValue::Boolean(b) => Val::Int(i64::from(b)),
                        SqlStorageValue::String(s) => Val::Text(s),
                        SqlStorageValue::Blob(b) => {
                            Val::Text(String::from_utf8_lossy(&b).into_owned())
                        }
                    })
                    .collect(),
            );
        }
        Ok(rows)
    }
}

/// Locks, write leases and dead properties of one bucket.
#[durable_object]
pub struct DavState {
    state: State,
}

impl DurableObject for DavState {
    fn new(state: State, _env: Env) -> Self {
        DavState { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let raw = req.text().await?;
        let Ok(ops) = serde_json::from_str::<Vec<Op>>(&raw) else {
            return Ok(Response::empty()?.with_status(400));
        };
        let sql = DoSql(self.state.storage().sql());
        let engine = Engine {
            sql: &sql,
            now: (worker::Date::now().as_millis() / 1000) as i64,
        };
        match engine.run(ops) {
            Ok(replies) => Response::from_json(&replies),
            Err(_) => {
                console_log!("dav state: storage error");
                Ok(Response::empty()?.with_status(500))
            }
        }
    }
}
