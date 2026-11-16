//! A large GET served in sub-ranges (`velmora_bridge::fanout`), over the
//! Worker's service binding to itself (`SELF`).
//!
//! The front invocation holds the client's response: a
//! `FixedLengthStream` of the whole body's length. Each sub-range is a
//! request through `SELF`, handled by another invocation of this Worker
//! with its own CPU limit, and its body is moved into the client's stream
//! by the runtime (`pipeTo`), never through this module's memory. The
//! declared length makes a download that stops early fail at the client:
//! a stream that is aborted, or closed short, is not a complete response.
//!
//! A sub-request carries the token and nothing else. A request through
//! the binding has no edge headers; `fanout::admit` refuses one that has.

use std::time::Duration;

use velmora_bridge::fanout::{
    FanoutError, SubPipe, SubRequest, SubResponse, INTERNAL_TARGET, TOKEN_HEADER,
};
use velmora_bridge::ingress::IngressError;
use velmora_bridge::{RespBody, S3Response};
use worker::js_sys::{BigInt, Function, Object, Promise, Reflect, Uint8Array};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::{console_error, Context, Env, Headers, Response, ResponseBody};

/// The binding of this Worker to itself.
const BINDING: &str = "SELF";
/// The host of a sub-request's URL. Never resolved: the binding delivers
/// the request to this Worker whatever it says.
const ORIGIN: &str = "https://fanout.invalid";

fn key(name: &str) -> JsValue {
    JsValue::from_str(name)
}

/// `target.name(args...)`, awaited if it returns a promise.
async fn call(target: &JsValue, name: &str, args: &[&JsValue]) -> Result<JsValue, JsValue> {
    let f: Function = Reflect::get(target, &key(name))?.dyn_into()?;
    let out = match args {
        [] => f.call0(target)?,
        [a] => f.call1(target, a)?,
        [a, b] => f.call2(target, a, b)?,
        _ => return Err(JsValue::NULL),
    };
    match out.dyn_into::<Promise>() {
        Ok(promise) => JsFuture::from(promise).await,
        Err(value) => Ok(value),
    }
}

/// The service binding and the client's stream.
pub struct SelfPipe {
    binding: JsValue,
    writable: JsValue,
}

impl SelfPipe {
    /// The pipe and the readable end the client's response is made of.
    /// `None` without the binding or the stream (fail closed).
    fn new(env: &Env, len: u64) -> Option<(SelfPipe, worker::web_sys::ReadableStream)> {
        let binding = Reflect::get(env.as_ref(), &key(BINDING)).ok()?;
        if !Reflect::get(&binding, &key("fetch")).ok()?.is_function() {
            return None;
        }
        let fixed = worker::worker_sys::FixedLengthStream::new_big_int(BigInt::from(len)).ok()?;
        let writable = fixed.writable().into();
        Some((SelfPipe { binding, writable }, fixed.readable()))
    }
}

impl SubPipe for SelfPipe {
    /// The sub-response's `ReadableStream`, or `null`.
    type Body = JsValue;

    async fn open(&self, sub: &SubRequest) -> Result<SubResponse<JsValue>, FanoutError> {
        let transport = |_| FanoutError::Transport;
        let headers = Object::new();
        Reflect::set(&headers, &key(TOKEN_HEADER), &key(&sub.token)).map_err(transport)?;
        let init = Object::new();
        Reflect::set(&init, &key("method"), &key("GET")).map_err(transport)?;
        Reflect::set(&init, &key("headers"), &headers).map_err(transport)?;
        let url = key(&format!("{ORIGIN}{INTERNAL_TARGET}"));
        let resp = call(&self.binding, "fetch", &[&url, &init])
            .await
            .map_err(transport)?;
        let status = Reflect::get(&resp, &key("status"))
            .ok()
            .and_then(|s| s.as_f64())
            .filter(|s| (100.0..1000.0).contains(s))
            .ok_or(FanoutError::Transport)? as u16;
        let headers = Reflect::get(&resp, &key("headers")).map_err(transport)?;
        let length = call(&headers, "get", &[&key("content-length")])
            .await
            .ok()
            .and_then(|v| v.as_string())
            .and_then(|v| v.parse::<u64>().ok());
        let body = Reflect::get(&resp, &key("body")).map_err(transport)?;
        Ok(SubResponse {
            status,
            length,
            body,
        })
    }

    /// The runtime moves the bytes. The sub-response has a declared
    /// length, so a body that ends early is an error here, and an error
    /// aborts the client's stream.
    async fn pipe(&self, body: JsValue) -> Result<(), FanoutError> {
        let options = Object::new();
        Reflect::set(&options, &key("preventClose"), &JsValue::TRUE)
            .map_err(|_| FanoutError::Pipe)?;
        call(&body, "pipeTo", &[&self.writable, &options])
            .await
            .map(|_| ())
            .map_err(|_| FanoutError::Pipe)
    }

    async fn refusal(&self, body: JsValue, cap: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let Ok(reader) = call(&body, "getReader", &[]).await else {
            return out;
        };
        while out.len() < cap {
            let Ok(step) = call(&reader, "read", &[]).await else {
                break;
            };
            let done = Reflect::get(&step, &key("done"))
                .map(|d| d.is_truthy())
                .unwrap_or(true);
            let Ok(chunk) =
                Reflect::get(&step, &key("value")).and_then(|v| v.dyn_into::<Uint8Array>())
            else {
                break;
            };
            let take = (cap - out.len()).min(chunk.length() as usize);
            out.extend_from_slice(&chunk.subarray(0, take as u32).to_vec());
            if done {
                break;
            }
        }
        let _ = call(&reader, "cancel", &[]).await;
        out
    }

    async fn sleep(&self, ms: u32) {
        worker::Delay::from(Duration::from_millis(u64::from(ms))).await;
    }

    /// Fails if fewer bytes were written than the response declared.
    async fn close(&self) -> Result<(), FanoutError> {
        call(&self.writable, "close", &[])
            .await
            .map(|_| ())
            .map_err(|_| FanoutError::Pipe)
    }

    async fn abort(&self) {
        let _ = call(&self.writable, "abort", &[&key("sub-range failed")]).await;
    }
}

fn error_class(e: FanoutError) -> &'static str {
    match e {
        FanoutError::Mint => "mint",
        FanoutError::Transport => "transport",
        FanoutError::Status(_) => "status",
        FanoutError::Length => "length",
        FanoutError::Pipe => "pipe",
    }
}

/// The client's response and its status. Any body but one in sub-ranges
/// is converted as it is. For a body in sub-ranges the
/// first sub-range is opened before the status line is sent: an object
/// that cannot be read is an error response, not a `200` that breaks.
/// The rest is piped under `waitUntil`, in order; a failure aborts the
/// stream.
pub async fn respond(env: &Env, ctx: &Context, resp: S3Response) -> (u16, Response) {
    let (status, headers) = (resp.status, resp.headers);
    let fan = match resp.body {
        RespBody::Fanout(fan) => fan,
        body => {
            let resp = S3Response {
                status,
                headers,
                body,
            };
            return (status, crate::http::to_response(resp));
        }
    };
    let refuse = |resp: S3Response| (resp.status, crate::http::to_response(resp));
    let Some((pipe, readable)) = SelfPipe::new(env, fan.len()) else {
        console_error!("fanout: no service binding or stream");
        return refuse(IngressError::Internal.response());
    };
    let first = match fan
        .open_first(&pipe, || IngressError::Internal.response())
        .await
    {
        Ok(first) => first,
        Err(resp) => {
            console_error!("fanout: first sub-range refused, status {}", resp.status);
            return refuse(resp);
        }
    };
    let built = (|| -> worker::Result<Response> {
        let out = Headers::new();
        for (name, value) in &headers {
            out.append(name, value)?;
        }
        Ok(Response::from_body(ResponseBody::Stream(readable))?
            .with_status(status)
            .with_headers(out))
    })();
    let Ok(resp) = built else {
        pipe.abort().await;
        return refuse(IngressError::Internal.response());
    };
    ctx.wait_until(async move {
        if let Err(e) = fan.pump(&pipe, first).await {
            match e {
                FanoutError::Status(s) => {
                    console_error!("fanout: download aborted (status {s})")
                }
                e => console_error!("fanout: download aborted ({})", error_class(e)),
            }
        }
    });
    (status, resp)
}
