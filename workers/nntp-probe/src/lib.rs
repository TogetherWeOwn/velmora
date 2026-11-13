//! Throwaway reachability probe: can a Cloudflare Worker reach a Usenet
//! provider over implicit TLS, authenticate, POST one velmora-shaped article,
//! and read it back with STAT + BODY? Also reports what the runtime preserves
//! of the raw request target (for SigV4 canonical-request reconstruction).
//!
//! Routes (every route requires `Authorization: Bearer <PROBE_TOKEN>`):
//!
//! - `POST /probe/post?size=<bytes>&payload=media|random`: connect, auth,
//!   POST, STAT, BODY, yEnc decode, SHA-256 compare.
//! - `GET /probe/body?mid=<message-id>`: STAT + BODY of an earlier post.
//! - `GET|PUT /raw/<anything>`: echoes the request target as seen.
//!
//! Responses carry reply-code classes only. Provider reply text, hostnames
//! and credentials never reach a response body or a log line.

use std::cell::Cell;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use velmora::article::{
    assemble_article, obfuscate_article, render_obfuscated_headers, ARTICLE_PLAINTEXT_BYTES,
};
use velmora::media::{ciphertext_size, FileKey, Profile, Sealer};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::rng::{FillRandom, SystemRng};
use velmora::transports::WorkerTransport;
use velmora::yenc::{decode_to, encode_segment, SegmentParams};
use worker::{
    event, Context, Date, Env, Method, Request, Response, Result, SecureTransport, Socket,
};

/// Upper bound for one probe payload. The probe exists to find the
/// provider's article-size behaviour, not to stress isolate memory.
const MAX_PROBE_BYTES: u64 = 8 * 1024 * 1024;

/// Per-operation socket timeout. Generous: a multi-MB POST is one write.
const OP_TIMEOUT: Duration = Duration::from_secs(60);

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if !authorized(&req, &env) {
        return json_response(&json!({"error": "unauthorized"}), 401);
    }
    let path = req.path();
    match req.method() {
        Method::Post if path == "/probe/post" => probe_post(&req, &env).await,
        Method::Get if path == "/probe/body" => probe_body(&req, &env).await,
        Method::Get | Method::Put if path.starts_with("/raw/") => raw(req).await,
        _ => json_response(&json!({"error": "not_found"}), 404),
    }
}

// ---------------------------------------------------------------------------
// Auth, config, helpers
// ---------------------------------------------------------------------------

fn authorized(req: &Request, env: &Env) -> bool {
    let Ok(expected) = env.secret("PROBE_TOKEN") else {
        return false;
    };
    let expected = expected.to_string();
    if expected.is_empty() {
        return false;
    }
    let Ok(Some(header)) = req.headers().get("authorization") else {
        return false;
    };
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

fn secret(env: &Env, name: &str) -> std::result::Result<String, Value> {
    env.secret(name)
        .map(|s| s.to_string())
        .map_err(|_| json!({"class": "config", "missing": name}))
}

fn nntp_config(env: &Env) -> std::result::Result<NntpConfig, Value> {
    let host = secret(env, "NNTP_HOST")?;
    let port = secret(env, "NNTP_PORT")?
        .trim()
        .parse::<u16>()
        .map_err(|_| json!({"class": "config", "invalid": "NNTP_PORT"}))?;
    Ok(NntpConfig {
        host,
        port,
        tls: true,
        username: Some(secret(env, "NNTP_USER")?),
        password: Some(secret(env, "NNTP_PASS")?),
        timeout: OP_TIMEOUT,
        ..NntpConfig::default()
    })
}

fn now_ms() -> u64 {
    Date::now().as_millis()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Removes every configured connection value from a diagnostic string, so
/// a runtime error that quotes the host or account never leaves the Worker.
fn redact(msg: &str, cfg: &NntpConfig) -> String {
    let mut out = msg.to_string();
    for value in [
        Some(cfg.host.as_str()),
        cfg.username.as_deref(),
        cfg.password.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !value.is_empty() {
            out = out.replace(value, "<redacted>");
        }
    }
    out
}

/// Error class and numeric code only; provider reply text is never echoed.
fn classify(err: &velmora::Error, cfg: &NntpConfig) -> Value {
    use velmora::Error as E;
    match err {
        E::Io(io) => json!({
            "class": "io",
            "kind": format!("{:?}", io.kind()),
            "detail": redact(&io.to_string(), cfg),
        }),
        E::NntpReply { code, .. } => json!({"class": "nntp_reply", "code": code}),
        E::AuthFailed(_) => json!({"class": "auth_failed"}),
        E::NoPermission(_) => json!({"class": "no_permission", "code": 502}),
        E::ArticleNotFound(_) => json!({"class": "article_not_found", "code": 430}),
        E::PostProhibited(_) => json!({"class": "post_prohibited", "code": 440}),
        // The engine embeds the raw server line in this message; never echo it.
        E::Malformed(m) if m.starts_with("NNTP reply is not") => {
            json!({"class": "malformed", "detail": "unparseable reply line"})
        }
        E::Malformed(m) => json!({"class": "malformed", "detail": redact(m, cfg)}),
        E::CrcMismatch { want, got, .. } => {
            json!({"class": "crc_mismatch", "want": want, "got": got})
        }
        _ => json!({"class": "other"}),
    }
}

fn json_response(body: &Value, status: u16) -> Result<Response> {
    let mut resp = Response::from_json(body)?.with_status(status);
    resp.headers_mut().set("cache-control", "no-store")?;
    Ok(resp)
}

fn query_param(req: &Request, name: &str) -> Option<String> {
    let url = req.url().ok()?;
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

// ---------------------------------------------------------------------------
// Session setup: connect (TLS) -> greeting + MODE READER -> AUTHINFO
// ---------------------------------------------------------------------------

struct Session {
    client: NntpClient<WorkerTransport>,
}

/// Opens one socket and runs the engine handshake, recording each step.
/// The auth guard fires right before `AUTHINFO USER`, which splits the
/// greeting/MODE READER time from the AUTHINFO time.
async fn open_session(
    cfg: &NntpConfig,
    steps: &mut Vec<Value>,
) -> std::result::Result<Session, Value> {
    let t0 = now_ms();
    let socket = Socket::builder()
        .secure_transport(SecureTransport::On)
        .connect(cfg.host.clone(), cfg.port)
        .map_err(|e| {
            json!({"step": "connect", "class": "socket_create", "detail": redact(&e.to_string(), cfg)})
        })?;
    if let Err(e) = socket.opened().await {
        return Err(json!({
            "step": "connect_tls",
            "class": "socket_open",
            "detail": redact(&e.to_string(), cfg),
            "ms": now_ms() - t0,
        }));
    }
    let t_open = now_ms();
    steps.push(json!({"step": "connect_tls", "ok": true, "ms": t_open - t0}));

    let auth_start = Cell::new(None::<u64>);
    let transport = WorkerTransport::from_socket(socket, cfg.timeout);
    let result = NntpClient::connect_with_auth_guard(transport, cfg, || {
        if auth_start.get().is_none() {
            auth_start.set(Some(now_ms()));
        }
        Ok(())
    })
    .await;
    let t_done = now_ms();
    let t_auth = auth_start.get();
    if let Some(t_auth) = t_auth {
        steps.push(json!({"step": "greeting_mode_reader", "ok": true, "ms": t_auth - t_open}));
    }
    match result {
        Ok(client) => {
            steps.push(json!({
                "step": "authinfo",
                "ok": true,
                "ms": t_done - t_auth.unwrap_or(t_open),
            }));
            Ok(Session { client })
        }
        Err(e) => {
            let step = if t_auth.is_some() {
                "authinfo"
            } else {
                "greeting_mode_reader"
            };
            Err(json!({
                "step": step,
                "error": classify(&e, cfg),
                "ms": t_done - t_auth.unwrap_or(t_open),
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

/// Largest plaintext whose `velmora.media.v1` ciphertext fits in `size`.
fn plaintext_for_ciphertext(size: u64) -> u64 {
    let mut p = size.saturating_sub(48) * 65_536 / 65_552;
    while p > 0 && ciphertext_size(p).is_none_or(|c| c > size) {
        p -= 1;
    }
    p
}

fn make_payload(kind: &str, size: Option<u64>) -> velmora::Result<Vec<u8>> {
    let mut rng = SystemRng;
    match kind {
        "random" => {
            let len = size.unwrap_or(velmora::article::ARTICLE_ZERO_PAYLOAD_BYTES) as usize;
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf)?;
            Ok(buf)
        }
        _ => {
            // "media": real media.v1 ciphertext (random key, random plaintext): article 0
            // of a file, i.e. the 48-byte header plus 11 chunks by default.
            let plain_len = match size {
                Some(s) => plaintext_for_ciphertext(s),
                None => ARTICLE_PLAINTEXT_BYTES,
            } as usize;
            let mut plain = vec![0u8; plain_len];
            rng.fill_bytes(&mut plain)?;
            let key = FileKey::generate(&mut rng)?;
            let sealer = Sealer::random(&Profile::drive(), &key, &mut rng)?;
            sealer.seal_to_vec(&plain)
        }
    }
}

// ---------------------------------------------------------------------------
// POST /probe/post
// ---------------------------------------------------------------------------

async fn probe_post(req: &Request, env: &Env) -> Result<Response> {
    let cfg = match nntp_config(env) {
        Ok(cfg) => cfg,
        Err(e) => return json_response(&json!({"ok": false, "error": e}), 500),
    };
    let size = match query_param(req, "size").map(|s| s.parse::<u64>()) {
        None => None,
        Some(Ok(s)) if s > 0 && s <= MAX_PROBE_BYTES => Some(s),
        Some(_) => return json_response(&json!({"ok": false, "error": "size out of range"}), 400),
    };
    let kind = query_param(req, "payload").unwrap_or_else(|| "media".into());
    if kind != "media" && kind != "random" {
        return json_response(
            &json!({"ok": false, "error": "payload must be media or random"}),
            400,
        );
    }
    let groups_var = env
        .var("NEWSGROUPS")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let groups: Vec<&str> = groups_var
        .split(',')
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .collect();

    let mut steps = Vec::new();
    let t_build = now_ms();

    // Build the article before dialing so CPU work is not charged to the
    // socket's idle time.
    let payload = match make_payload(&kind, size) {
        Ok(p) => p,
        Err(e) => {
            return fail(
                steps,
                json!({"step": "payload", "error": classify(&e, &cfg)}),
            )
        }
    };
    let payload_sha = sha256_hex(&payload);
    let now_secs = (now_ms() / 1000) as i64;
    let ob = match obfuscate_article(&mut SystemRng, now_secs, &groups) {
        Ok(ob) => ob,
        Err(e) => {
            return fail(
                steps,
                json!({"step": "obfuscate", "error": classify(&e, &cfg)}),
            )
        }
    };
    let mut yenc_body = Vec::with_capacity(payload.len() + payload.len() / 32 + 256);
    if let Err(e) = encode_segment(
        &mut yenc_body,
        &SegmentParams::single(ob.yenc_name.clone()),
        &payload,
    ) {
        return fail(
            steps,
            json!({"step": "yenc_encode", "error": classify(&e, &cfg)}),
        );
    }
    let article =
        match render_obfuscated_headers(&ob).and_then(|h| assemble_article(&h, &yenc_body)) {
            Ok(a) => a,
            Err(e) => {
                return fail(
                    steps,
                    json!({"step": "assemble", "error": classify(&e, &cfg)}),
                )
            }
        };
    steps.push(json!({"step": "build_article", "ok": true, "ms": now_ms() - t_build}));

    let summary = json!({
        "payload_kind": kind,
        "payload_bytes": payload.len(),
        "yenc_body_bytes": yenc_body.len(),
        "article_bytes": article.len(),
        "newsgroup": ob.newsgroup,
        "message_id": ob.message_id,
        "payload_sha256": payload_sha,
    });

    let mut session = match open_session(&cfg, &mut steps).await {
        Ok(s) => s,
        Err(e) => return fail_with(steps, e, summary),
    };
    let client = &mut session.client;

    // POST
    let t = now_ms();
    let post = client.post_article(&ob.message_id, &article).await;
    let post_ms = now_ms() - t;
    match &post {
        Ok(outcome) => steps.push(json!({
            "step": "post",
            "ok": true,
            "outcome": match outcome { PostOutcome::Posted => "240_posted", PostOutcome::Duplicate => "duplicate_confirmed" },
            "ms": post_ms,
        })),
        Err(e) => {
            steps.push(json!({"step": "post", "ok": false, "error": classify(e, &cfg), "ms": post_ms}));
            client.shutdown_unusable().await.ok();
            return fail_with(steps, json!({"step": "post"}), summary);
        }
    }

    // STAT (immediately after POST, same connection)
    let t = now_ms();
    let stat = client.stat(&ob.message_id).await;
    steps.push(match &stat {
        Ok(_) => json!({"step": "stat", "ok": true, "code": 223, "ms": now_ms() - t}),
        Err(e) => {
            json!({"step": "stat", "ok": false, "error": classify(e, &cfg), "ms": now_ms() - t})
        }
    });

    // BODY + decode + compare
    let (body_step, readback) = read_body(client, &ob.message_id, &cfg).await;
    steps.push(body_step);
    let sha_match = readback
        .as_ref()
        .map(|r| r.decoded_sha256 == payload_sha && r.decoded_len == payload.len());
    let raw_body_match = readback
        .as_ref()
        .map(|r| r.raw_sha256 == sha256_hex(&yenc_body));

    let t = now_ms();
    session.client.quit().await;
    steps.push(json!({"step": "quit", "ms": now_ms() - t}));

    json_response(
        &json!({
            "ok": sha_match == Some(true),
            "summary": summary,
            "sha256_match": sha_match,
            "raw_yenc_body_match": raw_body_match,
            "readback": readback.map(|r| r.to_json()),
            "steps": steps,
        }),
        200,
    )
}

fn fail(steps: Vec<Value>, error: Value) -> Result<Response> {
    json_response(&json!({"ok": false, "error": error, "steps": steps}), 200)
}

fn fail_with(steps: Vec<Value>, error: Value, summary: Value) -> Result<Response> {
    json_response(
        &json!({"ok": false, "error": error, "summary": summary, "steps": steps}),
        200,
    )
}

struct Readback {
    raw_len: usize,
    raw_sha256: String,
    decoded_len: usize,
    decoded_sha256: String,
}

impl Readback {
    fn to_json(&self) -> Value {
        json!({
            "raw_body_bytes": self.raw_len,
            "raw_body_sha256": self.raw_sha256,
            "decoded_bytes": self.decoded_len,
            "decoded_sha256": self.decoded_sha256,
        })
    }
}

async fn read_body(
    client: &mut NntpClient<WorkerTransport>,
    message_id: &str,
    cfg: &NntpConfig,
) -> (Value, Option<Readback>) {
    let t = now_ms();
    let mut raw = Vec::new();
    if let Err(e) = client.body_to(message_id, &mut raw).await {
        return (
            json!({"step": "body", "ok": false, "error": classify(&e, cfg), "ms": now_ms() - t}),
            None,
        );
    }
    let body_ms = now_ms() - t;
    let mut dst = vec![0u8; raw.len()];
    match decode_to(message_id, &raw, &mut dst) {
        Ok(n) => {
            let rb = Readback {
                raw_len: raw.len(),
                raw_sha256: sha256_hex(&raw),
                decoded_len: n,
                decoded_sha256: sha256_hex(&dst[..n]),
            };
            (
                json!({"step": "body", "ok": true, "code": 222, "ms": body_ms}),
                Some(rb),
            )
        }
        Err(e) => (
            json!({"step": "body", "ok": false, "phase": "yenc_decode", "error": classify(&e, cfg), "ms": body_ms}),
            None,
        ),
    }
}

// ---------------------------------------------------------------------------
// GET /probe/body?mid=
// ---------------------------------------------------------------------------

async fn probe_body(req: &Request, env: &Env) -> Result<Response> {
    let cfg = match nntp_config(env) {
        Ok(cfg) => cfg,
        Err(e) => return json_response(&json!({"ok": false, "error": e}), 500),
    };
    let Some(mid) = query_param(req, "mid") else {
        return json_response(&json!({"ok": false, "error": "mid required"}), 400);
    };
    let mut steps = Vec::new();
    let mut session = match open_session(&cfg, &mut steps).await {
        Ok(s) => s,
        Err(e) => return fail(steps, e),
    };
    let t = now_ms();
    let stat = session.client.stat(&mid).await;
    let found = stat.is_ok();
    steps.push(match &stat {
        Ok(_) => json!({"step": "stat", "ok": true, "code": 223, "ms": now_ms() - t}),
        Err(e) => {
            json!({"step": "stat", "ok": false, "error": classify(e, &cfg), "ms": now_ms() - t})
        }
    });
    let (body_step, readback) = read_body(&mut session.client, &mid, &cfg).await;
    steps.push(body_step);
    session.client.quit().await;
    json_response(
        &json!({
            "ok": readback.is_some(),
            "stat_found": found,
            "readback": readback.map(|r| r.to_json()),
            "steps": steps,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// GET|PUT /raw/<anything>
// ---------------------------------------------------------------------------

/// Header values echoed verbatim; every other header is reported by name
/// only, so client addresses and the bearer token never come back.
fn echo_value(name: &str) -> bool {
    name.starts_with("x-amz-")
        || name.starts_with("content-")
        || matches!(name, "host" | "user-agent" | "accept" | "expect" | "range")
}

async fn raw(req: Request) -> Result<Response> {
    let inner_url = req.inner().url();
    let parsed = req.url();
    let headers: Vec<Value> = req
        .headers()
        .entries()
        .map(|(name, value)| {
            if echo_value(&name) {
                json!([name, value])
            } else {
                json!([name, "<omitted>"])
            }
        })
        .collect();
    let body_len = if req.method() == Method::Put {
        // Report the declared length; buffering the body is not needed.
        req.headers()
            .get("content-length")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0)
    } else {
        0
    };
    json_response(
        &json!({
            "method": format!("{:?}", req.method()),
            "inner_url": inner_url,
            "url": parsed.as_ref().map(|u| u.to_string()).unwrap_or_else(|e| format!("parse error: {e}")),
            "url_path": parsed.as_ref().map(|u| u.path().to_string()).ok(),
            "url_query": parsed.as_ref().ok().and_then(|u| u.query().map(str::to_string)),
            "query_pairs": parsed.as_ref().map(|u| u.query_pairs().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()).unwrap_or_default(),
            "path": req.path(),
            "headers": headers,
            "body_len": body_len,
        }),
        200,
    )
}
