//! Worker routes (wasm32 only). See the crate docs for the route list.

use crate::discovery;

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use futures_util::future::{self, Either};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use velmora::article::{
    assemble_article, obfuscate_article, render_obfuscated_headers, ARTICLE_PLAINTEXT_BYTES,
};
use velmora::media::{ciphertext_size, FileKey, Profile, Sealer};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::rng::{FillRandom, SystemRng};
use velmora::transports::WorkerTransport;
use velmora::yenc::{decode_to, encode_segment, SegmentParams};
use worker::{
    event, Context, Date, Delay, Env, Method, Request, Response, Result, SecureTransport, Socket,
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
    // Where this invocation ran: a number measured from one data centre
    // says nothing about another.
    let colo = req.cf().map(|cf| cf.colo());
    let mut resp = match req.method() {
        Method::Post if path == "/probe/post" => probe_post(&req, &env).await,
        Method::Post if path == "/probe/postrun" => probe_postrun(&req, &env).await,
        Method::Get if path == "/probe/body" => probe_body(&req, &env).await,
        Method::Get if path == "/probe/caps" => probe_caps(&req, &env).await,
        Method::Get if path == "/probe/head" => probe_head(&req, &env).await,
        Method::Get if path == "/probe/ramp" => probe_ramp(&req, &env).await,
        Method::Get | Method::Put if path.starts_with("/raw/") => raw(req).await,
        _ => json_response(&json!({"error": "not_found"}), 404),
    }?;
    if let Some(colo) = colo {
        resp.headers_mut().set(COLO_HEADER, &colo)?;
    }
    Ok(resp)
}

/// Response header with the Cloudflare data centre (`request.cf.colo`)
/// the invocation ran in.
const COLO_HEADER: &str = "x-probe-colo";

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

/// A secret with surrounding whitespace (e.g. a trailing newline from a
/// piped `secret put`) removed. A value with an inner CR or LF is rejected:
/// spliced into an NNTP command it would split the line.
fn secret(env: &Env, name: &str) -> std::result::Result<String, Value> {
    let value = env
        .secret(name)
        .map(|s| s.to_string())
        .map_err(|_| json!({"class": "config", "missing": name}))?;
    let value = value.trim().to_string();
    if value.contains(['\r', '\n']) {
        return Err(json!({"class": "config", "invalid": name}));
    }
    Ok(value)
}

/// Error response for a failed config lookup: 400 for a bad request
/// parameter, 500 for a deployment problem.
fn config_error(e: Value) -> Result<Response> {
    let status = if e["class"] == "request" { 400 } else { 500 };
    json_response(&json!({"ok": false, "error": e}), status)
}

/// Secret-name prefix for the account selected by `?p=<n>`: `NNTP_P<n>_`
/// for `n` in 1..=9, or the legacy `NNTP_` when `p` is absent.
fn account_prefix(req: &Request) -> std::result::Result<String, Value> {
    match query_param(req, "p") {
        None => Ok("NNTP_".into()),
        Some(p) => match p.parse::<u8>() {
            Ok(n) if (1..=MAX_ACCOUNTS).contains(&n) => Ok(format!("NNTP_P{n}_")),
            _ => Err(json!({"class": "request", "invalid": "p"})),
        },
    }
}

/// Highest account index accepted in `?p=`.
const MAX_ACCOUNTS: u8 = 9;

fn nntp_config(req: &Request, env: &Env) -> std::result::Result<NntpConfig, Value> {
    let prefix = account_prefix(req)?;
    let (host, port) = match query_param(req, "alt") {
        None => {
            let host = secret(env, &format!("{prefix}HOST"))?;
            let port = secret(env, &format!("{prefix}PORT"))?
                .trim()
                .parse::<u16>()
                .map_err(|_| json!({"class": "config", "invalid": format!("{prefix}PORT")}))?;
            (host, port)
        }
        // Alternate endpoints come only from the operator-set
        // `<prefix>ALT` list, so the account's credentials are never sent
        // to a host named in the request.
        Some(k) => {
            let k: usize = k
                .parse()
                .map_err(|_| json!({"class": "request", "invalid": "alt"}))?;
            let list = secret(env, &format!("{prefix}ALT"))?;
            discovery::alt_endpoint(&list, k)
                .ok_or_else(|| json!({"class": "request", "invalid": "alt"}))?
        }
    };
    Ok(NntpConfig {
        host,
        port,
        tls: true,
        username: Some(secret(env, &format!("{prefix}USER"))?),
        password: Some(secret(env, &format!("{prefix}PASS"))?),
        timeout: OP_TIMEOUT,
        max_article_bytes: MAX_READ_BYTES,
        ..NntpConfig::default()
    })
}

/// Largest article body `/probe/body` and `/probe/post` will buffer.
const MAX_READ_BYTES: usize = 16 * 1024 * 1024;

/// Every configured host, user and password across all accounts, with the
/// label that replaces it in provider free text. Bundle accounts can name
/// each other's hosts, so redaction covers all of them, not just the
/// selected one.
fn all_configured_values(env: &Env) -> Vec<(String, String)> {
    let mut prefixes = vec![("NNTP_".to_string(), "legacy".to_string())];
    prefixes.extend((1..=MAX_ACCOUNTS).map(|n| (format!("NNTP_P{n}_"), format!("p{n}"))));
    let mut out = Vec::new();
    for (prefix, account) in prefixes {
        for (field, label) in [
            ("PASS", "<password>".to_string()),
            ("USER", "<user>".to_string()),
            // The account index is kept so a Path element equal to an
            // account's own host is attributable without naming the host.
            ("HOST", format!("<configured-host:{account}>")),
        ] {
            if let Ok(v) = env.secret(&format!("{prefix}{field}")) {
                let v = v.to_string().trim().to_string();
                if !v.is_empty() {
                    out.push((v, label));
                }
            }
        }
        if let Ok(list) = env.secret(&format!("{prefix}ALT")) {
            let list = list.to_string();
            let mut k = 0;
            while let Some((host, _)) = discovery::alt_endpoint(&list, k) {
                out.push((host, format!("<alt-host:{account}:{k}>")));
                k += 1;
            }
        }
    }
    // Longest first, so a host that contains another value is replaced whole.
    out.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
    out
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
    let mut values: Vec<(String, String)> = [
        (Some(cfg.host.as_str()), "<host>"),
        (cfg.username.as_deref(), "<user>"),
        (cfg.password.as_deref(), "<password>"),
    ]
    .into_iter()
    .filter_map(|(v, label)| v.map(|v| (v.to_string(), label.to_string())))
    .collect();
    values.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
    discovery::redact_ips(&discovery::redact_values(msg, &values))
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
    let opened = with_timeout_for(OP_TIMEOUT, async {
        socket
            .opened()
            .await
            .map_err(|e| std::io::Error::other(redact(&e.to_string(), cfg)))
    })
    .await;
    if let Err(e) = opened {
        let mut socket = socket;
        let _ = socket.close().await;
        return Err(json!({
            "step": "connect_tls",
            "class": "socket_open",
            "detail": e.to_string(),
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
    let cfg = match nntp_config(req, env) {
        Ok(cfg) => cfg,
        Err(e) => return config_error(e),
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
    let cfg = match nntp_config(req, env) {
        Ok(cfg) => cfg,
        Err(e) => return config_error(e),
    };
    let Some(mid) = query_param(req, "mid").and_then(|m| discovery::normalize_message_id(&m))
    else {
        return json_response(&json!({"ok": false, "error": "valid mid required"}), 400);
    };
    // The engine adds the angle brackets itself.
    let mid = mid[1..mid.len() - 1].to_string();
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
// Discovery session: a minimal line-level NNTP client over the raw socket.
// The engine's handshake hides the greeting code and folds AUTHINFO codes
// into one error class; discovery needs the exact codes, so these routes
// speak the few commands they need directly.
// ---------------------------------------------------------------------------

/// Per-operation timeout for discovery sessions (no large transfers).
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);

/// Longest reply line accepted.
const MAX_LINE: usize = 4096;

/// Most lines accepted in one dot-block (HEAD, CAPABILITIES).
const MAX_BLOCK_LINES: usize = 512;

/// Deadline for a whole dot-block, so a server dribbling one line at a
/// time cannot hold a session for `MAX_BLOCK_LINES` x the line timeout.
const BLOCK_DEADLINE: Duration = Duration::from_secs(30);

/// Concurrent sessions per `/probe/ramp` call. The Workers runtime documents
/// six simultaneous open connections per invocation; the ramp shows what it
/// does with more.
const MAX_RAMP: u32 = 30;

/// Longest hold in `/probe/ramp`, in seconds.
const MAX_HOLD_SECS: u64 = 30;

struct Mini {
    io: BufReader<Socket>,
    /// Remote address the runtime reports for the open socket, if any.
    peer: Option<String>,
}

fn timed_out() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "discovery op timed out")
}

async fn with_timeout<T>(
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    with_timeout_for(DISCOVERY_TIMEOUT, fut).await
}

async fn with_timeout_for<T>(
    limit: Duration,
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    let fut = std::pin::pin!(fut);
    let delay = std::pin::pin!(Delay::from(limit));
    match future::select(fut, delay).await {
        Either::Left((out, _)) => out,
        Either::Right(_) => Err(timed_out()),
    }
}

/// I/O failure as a class only; the runtime's message can quote the host.
fn io_error(step: &str, e: &std::io::Error) -> Value {
    json!({"step": step, "class": "io", "kind": format!("{:?}", e.kind())})
}

/// Reply code of a status line, or `None` if it is not `ddd...`.
fn reply_code(line: &[u8]) -> Option<u16> {
    if line.len() >= 3 && line[..3].iter().all(u8::is_ascii_digit) {
        std::str::from_utf8(&line[..3]).ok()?.parse().ok()
    } else {
        None
    }
}

impl Mini {
    /// Connects with implicit TLS and reads the greeting line.
    async fn open(cfg: &NntpConfig) -> std::result::Result<(Self, Vec<u8>), Value> {
        let socket = Socket::builder()
            .secure_transport(SecureTransport::On)
            .connect(cfg.host.clone(), cfg.port)
            .map_err(|_| json!({"step": "connect", "class": "socket_create"}))?;
        let opened = with_timeout(async {
            socket
                .opened()
                .await
                .map_err(|_| std::io::Error::other("open"))
        })
        .await;
        let Ok(info) = opened else {
            // worker's Socket has no Drop; close it so a failed attempt
            // does not hold a socket (and a provider slot) until the
            // invocation ends.
            let mut socket = socket;
            let _ = socket.close().await;
            return Err(json!({"step": "connect_tls", "class": "socket_open"}));
        };
        let mut mini = Mini {
            io: BufReader::new(socket),
            peer: info.remote_address,
        };
        match mini.line().await {
            Ok(greeting) => Ok((mini, greeting)),
            Err(e) => {
                mini.quit().await;
                Err(io_error("greeting", &e))
            }
        }
    }

    /// One CRLF line without the terminator, capped at [`MAX_LINE`].
    async fn line(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let n = with_timeout(async {
            let mut limited = (&mut self.io).take(MAX_LINE as u64 + 2);
            limited.read_until(b'\n', &mut buf).await
        })
        .await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if !buf.ends_with(b"\n") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        Ok(buf)
    }

    /// Sends one command and returns the reply code and the raw reply line.
    async fn command(&mut self, cmd: &str) -> std::io::Result<(Option<u16>, Vec<u8>)> {
        with_timeout(async {
            self.io.write_all(cmd.as_bytes()).await?;
            self.io.write_all(b"\r\n").await?;
            self.io.flush().await
        })
        .await?;
        let line = self.line().await?;
        Ok((reply_code(&line), line))
    }

    /// Reads a dot-terminated block, dot-unstuffed.
    async fn dot_block(&mut self) -> std::io::Result<Vec<Vec<u8>>> {
        with_timeout_for(BLOCK_DEADLINE, self.dot_block_inner()).await
    }

    async fn dot_block_inner(&mut self) -> std::io::Result<Vec<Vec<u8>>> {
        let mut lines = Vec::new();
        loop {
            let mut line = self.line().await?;
            if line == b"." {
                return Ok(lines);
            }
            if line.starts_with(b"..") {
                line.remove(0);
            }
            if lines.len() >= MAX_BLOCK_LINES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "block too long",
                ));
            }
            lines.push(line);
        }
    }

    /// `AUTHINFO USER` / `PASS`; returns both codes (`pass` is `None` when the
    /// server answered USER with anything but 381).
    async fn auth(
        &mut self,
        cfg: &NntpConfig,
    ) -> std::result::Result<(Option<u16>, Option<u16>), Value> {
        self.auth_with_reply(cfg).await.map(|(u, p, _)| (u, p))
    }

    /// As [`Mini::auth`], plus the last reply line: when the login is
    /// refused, its text says why (too many connections, bad login, ...).
    async fn auth_with_reply(
        &mut self,
        cfg: &NntpConfig,
    ) -> std::result::Result<(Option<u16>, Option<u16>, Vec<u8>), Value> {
        let user = cfg.username.as_deref().unwrap_or_default();
        let pass = cfg.password.as_deref().unwrap_or_default();
        let (u, line) = self
            .command(&format!("AUTHINFO USER {user}"))
            .await
            .map_err(|e| io_error("authinfo_user", &e))?;
        if u != Some(381) {
            return Ok((u, None, line));
        }
        let (p, line) = self
            .command(&format!("AUTHINFO PASS {pass}"))
            .await
            .map_err(|e| io_error("authinfo_pass", &e))?;
        Ok((u, p, line))
    }

    /// Best-effort QUIT, then always shut down and close the socket, even
    /// when the QUIT write fails.
    async fn quit(mut self) {
        let _ = with_timeout(async {
            self.io.write_all(b"QUIT\r\n").await?;
            self.io.flush().await
        })
        .await;
        let _ = with_timeout(self.io.shutdown()).await;
        let _ = with_timeout(async {
            self.io
                .get_mut()
                .close()
                .await
                .map_err(|_| std::io::Error::other("close"))
        })
        .await;
    }
}

fn text(line: &[u8], values: &[(String, String)]) -> String {
    discovery::redact_line(&String::from_utf8_lossy(line), values)
}

fn bad_request(msg: &str) -> Result<Response> {
    json_response(&json!({"ok": false, "error": msg}), 400)
}

// ---------------------------------------------------------------------------
// GET /probe/caps
// ---------------------------------------------------------------------------

/// Address records of `host` as Cloudflare's public resolver answers them
/// from this data centre (DNS over HTTPS, JSON form). The provider's own
/// address is public; it shows which server farm a geolocated name picks.
/// `host` always comes from an operator-set secret, never from the request.
async fn resolve(host: &str) -> Value {
    let mut out = serde_json::Map::new();
    for kind in ["A", "AAAA"] {
        let url = format!("https://cloudflare-dns.com/dns-query?name={host}&type={kind}");
        let answer = async {
            let headers = worker::Headers::new();
            headers.set("accept", "application/dns-json")?;
            let mut init = worker::RequestInit::new();
            init.with_headers(headers);
            let req = Request::new_with_init(&url, &init)?;
            let mut resp = worker::Fetch::Request(req).send().await?;
            resp.json::<Value>().await
        }
        .await;
        let records: Vec<Value> = match answer {
            Ok(v) => v["Answer"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter(|r| matches!(r["type"].as_u64(), Some(1 | 28)))
                        .filter_map(|r| r["data"].as_str().map(|d| json!(d)))
                        .collect()
                })
                .unwrap_or_default(),
            Err(_) => vec![json!("lookup_failed")],
        };
        out.insert(kind.to_string(), Value::Array(records));
    }
    Value::Object(out)
}

async fn probe_caps(req: &Request, env: &Env) -> Result<Response> {
    let cfg = match nntp_config(req, env) {
        Ok(cfg) => cfg,
        Err(e) => return config_error(e),
    };
    let values = all_configured_values(env);
    let t0 = now_ms();
    let (mut mini, greeting) = match Mini::open(&cfg).await {
        Ok(v) => v,
        Err(e) => {
            return json_response(&json!({"ok": false, "error": e, "ms": now_ms() - t0}), 200)
        }
    };
    let t_greet = now_ms();
    let greeting_code = reply_code(&greeting);
    let mut out = json!({
        "greeting_code": greeting_code,
        "posting_allowed_by_greeting": greeting_code.map(|c| c == 200),
        "greeting_text": text(&greeting, &values),
        "connect_tls_greeting_ms": t_greet - t0,
        "peer": mini.peer.as_deref().map(|p| text(p.as_bytes(), &values)),
        "resolved": resolve(&cfg.host).await,
    });
    let result: std::result::Result<(), Value> = async {
        let caps_pre = capabilities(&mut mini, &values).await?;
        out["capabilities_pre_auth"] = caps_pre;
        let (mode, mode_line) = mini
            .command("MODE READER")
            .await
            .map_err(|e| io_error("mode_reader", &e))?;
        out["mode_reader_code"] = json!(mode);
        out["mode_reader_text"] = json!(text(&mode_line, &values));
        let t = now_ms();
        let (u, p) = mini.auth(&cfg).await?;
        out["authinfo_user_code"] = json!(u);
        out["authinfo_pass_code"] = json!(p);
        out["authinfo_ms"] = json!(now_ms() - t);
        out["auth_ok"] = json!(p == Some(281) || u == Some(281));
        out["capabilities_post_auth"] = capabilities(&mut mini, &values).await?;
        Ok(())
    }
    .await;
    if let Err(e) = result {
        out["error"] = e;
    }
    mini.quit().await;
    out["ok"] = json!(out.get("error").is_none() && out["auth_ok"] == json!(true));
    out["total_ms"] = json!(now_ms() - t0);
    json_response(&out, 200)
}

async fn capabilities(
    mini: &mut Mini,
    values: &[(String, String)],
) -> std::result::Result<Value, Value> {
    let (code, _) = mini
        .command("CAPABILITIES")
        .await
        .map_err(|e| io_error("capabilities", &e))?;
    if code != Some(101) {
        return Ok(json!({"code": code}));
    }
    let lines = mini
        .dot_block()
        .await
        .map_err(|e| io_error("capabilities_block", &e))?;
    let caps: Vec<String> = lines.iter().map(|l| text(l, values)).collect();
    let has = |kw: &str| caps.iter().any(|c| c.split_whitespace().next() == Some(kw));
    Ok(json!({
        "code": code,
        "lines": caps,
        "post": has("POST"),
        "reader": has("READER"),
        "ihave": has("IHAVE"),
    }))
}

// ---------------------------------------------------------------------------
// GET /probe/head?mid=...
// ---------------------------------------------------------------------------

async fn probe_head(req: &Request, env: &Env) -> Result<Response> {
    let cfg = match nntp_config(req, env) {
        Ok(cfg) => cfg,
        Err(e) => return config_error(e),
    };
    let mids: Vec<String> = req
        .url()
        .map(|u| {
            u.query_pairs()
                .filter(|(k, _)| k == "mid")
                .map(|(_, v)| discovery::normalize_message_id(&v))
                .collect::<Option<Vec<_>>>()
        })
        .ok()
        .flatten()
        .unwrap_or_default();
    if mids.is_empty() || mids.len() > 3 {
        return bad_request("1 to 3 valid mid parameters required");
    }
    let values = all_configured_values(env);
    let t0 = now_ms();
    let (mut mini, greeting) = match Mini::open(&cfg).await {
        Ok(v) => v,
        Err(e) => return json_response(&json!({"ok": false, "error": e}), 200),
    };
    let greeting_code = reply_code(&greeting);
    let mut articles = Vec::new();
    let result: std::result::Result<(), Value> = async {
        let _ = mini
            .command("MODE READER")
            .await
            .map_err(|e| io_error("mode_reader", &e))?;
        let (u, p) = mini.auth(&cfg).await?;
        if !(p == Some(281) || u == Some(281)) {
            return Err(json!({"step": "authinfo", "user_code": u, "pass_code": p}));
        }
        for (i, mid) in mids.iter().enumerate() {
            let t = now_ms();
            let (code, _) = mini
                .command(&format!("HEAD {mid}"))
                .await
                .map_err(|e| io_error("head", &e))?;
            if code != Some(221) {
                articles.push(json!({"index": i, "code": code, "ms": now_ms() - t}));
                continue;
            }
            let lines = mini
                .dot_block()
                .await
                .map_err(|e| io_error("head_block", &e))?;
            let ms = now_ms() - t;
            let mut headers = serde_json::Map::new();
            let mut path_head = Vec::new();
            let mut xref_server = None;
            for (name, value) in discovery::select_headers(&lines) {
                if name == "Path" {
                    path_head = discovery::path_head(&value, 3)
                        .iter()
                        .map(|e| discovery::redact_header("Path", e, &values))
                        .collect();
                }
                if name == "Xref" {
                    xref_server =
                        discovery::xref_server(&value).map(|s| discovery::redact_line(&s, &values));
                }
                headers.insert(
                    name.clone(),
                    json!(discovery::redact_header(&name, &value, &values)),
                );
            }
            articles.push(json!({
                "index": i,
                "code": code,
                "ms": ms,
                "path_head": path_head,
                "xref_server": xref_server,
                "headers": headers,
            }));
        }
        Ok(())
    }
    .await;
    mini.quit().await;
    let mut out = json!({
        "ok": result.is_ok(),
        "greeting_code": greeting_code,
        "articles": articles,
        "total_ms": now_ms() - t0,
    });
    if let Err(e) = result {
        out["error"] = e;
    }
    json_response(&out, 200)
}

// ---------------------------------------------------------------------------
// GET /probe/ramp?n=&hold=
// ---------------------------------------------------------------------------

async fn ramp_session(
    cfg: &NntpConfig,
    values: &[(String, String)],
    idx: u32,
    hold: Duration,
) -> Value {
    let t0 = now_ms();
    let (mut mini, greeting) = match Mini::open(cfg).await {
        Ok(v) => v,
        Err(e) => return json!({"i": idx, "ok": false, "error": e, "ms": now_ms() - t0}),
    };
    let t_greet = now_ms();
    let greeting_code = reply_code(&greeting);
    let mut out = json!({
        "i": idx,
        "greeting_code": greeting_code,
        "connect_tls_greeting_ms": t_greet - t0,
        "peer": mini.peer.as_deref().map(|p| text(p.as_bytes(), values)),
    });
    if !matches!(greeting_code, Some(200 | 201)) {
        out["ok"] = json!(false);
        mini.quit().await;
        return out;
    }
    let t = now_ms();
    let auth = async {
        let (mode, _) = mini
            .command("MODE READER")
            .await
            .map_err(|e| io_error("mode_reader", &e))?;
        let (u, p, line) = mini.auth_with_reply(cfg).await?;
        Ok::<_, Value>((mode, u, p, line))
    }
    .await;
    match auth {
        Err(e) => {
            out["ok"] = json!(false);
            out["error"] = e;
            mini.quit().await;
            return out;
        }
        Ok((mode, u, p, line)) => {
            if !(p == Some(281) || u == Some(281)) {
                out["refusal_text"] = json!(text(&line, values));
            }
            out["mode_reader_code"] = json!(mode);
            out["authinfo_user_code"] = json!(u);
            out["authinfo_pass_code"] = json!(p);
            out["mode_auth_ms"] = json!(now_ms() - t);
            out["connect_auth_ms"] = json!(now_ms() - t0);
            if !(p == Some(281) || u == Some(281)) {
                out["ok"] = json!(false);
                mini.quit().await;
                return out;
            }
        }
    }
    Delay::from(hold).await;
    // Still alive after the hold? Some servers accept a session and drop it
    // shortly after when the account is over its limit.
    match mini.command("DATE").await {
        Ok((code, _)) => {
            out["after_hold_date_code"] = json!(code);
            out["ok"] = json!(code == Some(111));
        }
        Err(e) => {
            out["after_hold_error"] = io_error("date", &e);
            out["ok"] = json!(false);
        }
    }
    mini.quit().await;
    out
}

async fn probe_ramp(req: &Request, env: &Env) -> Result<Response> {
    let cfg = match nntp_config(req, env) {
        Ok(cfg) => cfg,
        Err(e) => return config_error(e),
    };
    let n = match query_param(req, "n").map(|s| s.parse::<u32>()) {
        Some(Ok(n)) if (1..=MAX_RAMP).contains(&n) => n,
        _ => return bad_request("n must be 1-30"),
    };
    let hold = match query_param(req, "hold").map(|s| s.parse::<u64>()) {
        None => 5,
        Some(Ok(h)) if h <= MAX_HOLD_SECS => h,
        _ => return bad_request("hold must be 0-30"),
    };
    let t0 = now_ms();
    let values = all_configured_values(env);
    let sessions =
        future::join_all((0..n).map(|i| ramp_session(&cfg, &values, i, Duration::from_secs(hold))))
            .await;
    let succeeded = sessions.iter().filter(|s| s["ok"] == json!(true)).count();
    json_response(
        &json!({
            "ok": succeeded == n as usize,
            "requested": n,
            "succeeded": succeeded,
            "hold_secs": hold,
            "sessions": sessions,
            "total_ms": now_ms() - t0,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /probe/postrun?n=&secs=&size=&max_mb=&arts=
// ---------------------------------------------------------------------------

/// Most sockets one posting run opens. Above the runtime's six open
/// connections on purpose: the run shows what the runtime does with more.
const MAX_RUN_SOCKETS: u32 = 30;
/// Longest posting run.
const MAX_RUN_SECS: u64 = 60;
/// Most payload one run may post, whatever the caller asks for.
const MAX_RUN_MB: u64 = 400;

/// What the sockets of one run share.
struct RunShared {
    /// Wall-clock end of the run.
    deadline_ms: u64,
    /// Payload bytes the run may still start to post.
    budget: Cell<u64>,
    size: u64,
    /// Articles per socket before it idles to the deadline (0 = no cap).
    arts: u32,
    groups: Vec<String>,
}

fn build_random_article(shared: &RunShared) -> velmora::Result<(String, Vec<u8>)> {
    let payload = make_payload("random", Some(shared.size))?;
    let groups: Vec<&str> = shared.groups.iter().map(String::as_str).collect();
    let ob = obfuscate_article(&mut SystemRng, (now_ms() / 1000) as i64, &groups)?;
    let mut body = Vec::with_capacity(payload.len() + payload.len() / 32 + 256);
    encode_segment(
        &mut body,
        &SegmentParams::single(ob.yenc_name.clone()),
        &payload,
    )?;
    let article = assemble_article(&render_obfuscated_headers(&ob)?, &body)?;
    Ok((ob.message_id, article))
}

/// One socket of a posting run: connect, then POST fresh random articles
/// back to back until the deadline, the byte budget or the first error.
/// With an article cap the socket then idles to the deadline and posts
/// one last article, which shows it was still usable.
async fn run_socket(cfg: &NntpConfig, idx: u32, shared: Rc<RunShared>) -> Value {
    let mut steps = Vec::new();
    let t0 = now_ms();
    let mut session = match open_session(cfg, &mut steps).await {
        Ok(s) => s,
        Err(e) => return json!({"i": idx, "ok": false, "connect_error": e, "ms": now_ms() - t0}),
    };
    let connect_ms = now_ms() - t0;
    let mut post_ms: Vec<u64> = Vec::new();
    let mut wire_bytes = 0u64;
    let mut duplicates = 0u32;
    let mut error = None;
    let mut first_post = None;
    let mut last_reply = now_ms();
    let mut lingered = false;
    loop {
        if shared.arts > 0 && post_ms.len() as u32 >= shared.arts {
            if lingered {
                break;
            }
            lingered = true;
            let left = shared.deadline_ms.saturating_sub(now_ms());
            Delay::from(Duration::from_millis(left)).await;
        } else if now_ms() >= shared.deadline_ms {
            break;
        }
        if shared.budget.get() < shared.size {
            break;
        }
        shared.budget.set(shared.budget.get() - shared.size);
        let (mid, article) = match build_random_article(&shared) {
            Ok(a) => a,
            Err(e) => {
                error = Some(json!({"step": "build", "error": classify(&e, cfg)}));
                break;
            }
        };
        let t = now_ms();
        first_post.get_or_insert(t);
        match session.client.post_article(&mid, &article).await {
            Ok(outcome) => {
                last_reply = now_ms();
                post_ms.push(last_reply - t);
                wire_bytes += article.len() as u64;
                if outcome == PostOutcome::Duplicate {
                    duplicates += 1;
                }
            }
            Err(e) => {
                error = Some(json!({
                    "step": "post",
                    "after_posts": post_ms.len(),
                    "ms": now_ms() - t,
                    "error": classify(&e, cfg),
                }));
                break;
            }
        }
    }
    match error {
        None => session.client.quit().await,
        Some(_) => {
            session.client.shutdown_unusable().await.ok();
        }
    }
    let mut sorted = post_ms.clone();
    sorted.sort_unstable();
    let pct = |p: usize| sorted.get((sorted.len() * p / 100).min(sorted.len().saturating_sub(1)));
    json!({
        "i": idx,
        "ok": error.is_none(),
        "connect_auth_ms": connect_ms,
        "posted": post_ms.len(),
        "duplicates": duplicates,
        "payload_bytes": post_ms.len() as u64 * shared.size,
        "wire_bytes": wire_bytes,
        "first_post_at": first_post,
        "last_reply_at": last_reply,
        "post_ms": {"min": sorted.first(), "p50": pct(50), "p90": pct(90), "max": sorted.last()},
        "last_post_ms": post_ms.last(),
        "error": error,
    })
}

async fn probe_postrun(req: &Request, env: &Env) -> Result<Response> {
    let cfg = match nntp_config(req, env) {
        Ok(cfg) => cfg,
        Err(e) => return config_error(e),
    };
    let num = |name: &str, default: u64| match query_param(req, name) {
        None => Some(default),
        Some(v) => v.parse::<u64>().ok(),
    };
    let n = match num("n", 1) {
        Some(n) if (1..=u64::from(MAX_RUN_SOCKETS)).contains(&n) => n as u32,
        _ => return bad_request("n must be 1-30"),
    };
    let secs = match num("secs", 10) {
        Some(s) if (1..=MAX_RUN_SECS).contains(&s) => s,
        _ => return bad_request("secs must be 1-60"),
    };
    let size = match num("size", velmora::article::ARTICLE_ZERO_PAYLOAD_BYTES) {
        Some(s) if s > 0 && s <= MAX_PROBE_BYTES => s,
        _ => return bad_request("size out of range"),
    };
    let max_mb = match num("max_mb", 50) {
        Some(m) if (1..=MAX_RUN_MB).contains(&m) => m,
        _ => return bad_request("max_mb must be 1-400"),
    };
    let arts = match num("arts", 0) {
        Some(a) if a <= 1000 => a as u32,
        _ => return bad_request("arts must be 0-1000"),
    };
    let groups: Vec<String> = env
        .var("NEWSGROUPS")
        .map(|v| v.to_string())
        .unwrap_or_default()
        .split(',')
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .collect();
    let t0 = now_ms();
    let shared = Rc::new(RunShared {
        deadline_ms: t0 + secs * 1000,
        budget: Cell::new(max_mb * 1024 * 1024),
        size,
        arts,
        groups,
    });
    let sockets = future::join_all((0..n).map(|i| run_socket(&cfg, i, Rc::clone(&shared)))).await;
    let sum = |key: &str| sockets.iter().filter_map(|s| s[key].as_u64()).sum::<u64>();
    let first = sockets
        .iter()
        .filter_map(|s| s["first_post_at"].as_u64())
        .min();
    let last = sockets
        .iter()
        .filter_map(|s| s["last_reply_at"].as_u64())
        .max();
    let window_ms = match (first, last) {
        (Some(a), Some(b)) if b > a => b - a,
        _ => 0,
    };
    let payload_bytes = sum("payload_bytes");
    let mb_s = match window_ms {
        0 => 0.0,
        w => payload_bytes as f64 / 1_048_576.0 / (w as f64 / 1000.0),
    };
    json_response(
        &json!({
            "ok": sockets.iter().all(|s| s["ok"] == json!(true)),
            "sockets_requested": n,
            "sockets_ok": sockets.iter().filter(|s| s["ok"] == json!(true)).count(),
            "secs": secs,
            "article_payload_bytes": size,
            "posted": sum("posted"),
            "payload_bytes": payload_bytes,
            "wire_bytes": sum("wire_bytes"),
            "posting_window_ms": window_ms,
            "payload_mib_per_s": (mb_s * 1000.0).round() / 1000.0,
            "started_at": t0,
            "total_ms": now_ms() - t0,
            "sockets": sockets,
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
