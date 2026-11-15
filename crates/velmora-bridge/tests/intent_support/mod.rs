//! Shared by the tests of sliced writes: a rig with small limits, the
//! body modes of a PutObject, requests that stop at a chosen call, a
//! snapshot of the catalogue, and the sweep.

#![allow(dead_code)]

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use serde_json::{json, Value};
use velmora_bridge::config::{BridgeConfig, Maintenance};
use velmora_bridge::*;

use crate::service_support::*;

pub const BUCKET: &str = "vault";
/// The limits of [`small_rig`].
pub const EXTENT: usize = 8 * 1024;
pub const SLICE: usize = 4 * 1024;
pub const MAX_PUT: usize = 64 * 1024;
/// The smallest chunk a signed aws-chunked body may have before its last.
pub const CHUNK: usize = 8 * 1024;
pub const HOUR_MS: i64 = 60 * 60 * 1000;
pub const DEFAULT_TENANT: &str = "t_0000000000000000";

pub const SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
pub const UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
pub const CRC32C: &str = "x-amz-checksum-crc32c";

/// One extent up to 8 KiB, slices of 4 KiB, bodies up to 64 KiB, the
/// sweep switched on.
pub fn small_config() -> BridgeConfig {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = EXTENT as u64;
    cfg.slice_bytes = SLICE as u64;
    cfg.max_put_bytes = MAX_PUT as u64;
    cfg.intent_sweep = true;
    cfg
}

pub fn small_rig() -> Rig {
    rig_with(NoNntp, small_config())
}

// ---------------------------------------------------------------------------
// Body modes
// ---------------------------------------------------------------------------

/// How a client sends the body of a PutObject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `x-amz-content-sha256` is the SHA-256 of the body.
    Literal,
    /// `UNSIGNED-PAYLOAD`.
    Unsigned,
    /// aws-chunked with a signature per chunk.
    SignedChunks,
    /// The same with a signed CRC-32C trailer.
    SignedTrailer,
    /// aws-chunked without signatures and with a CRC-32C trailer, sent
    /// without `Content-Length`: the default of aws-cli over HTTPS.
    UnsignedTrailer,
}

pub const MODES: [Mode; 5] = [
    Mode::Literal,
    Mode::Unsigned,
    Mode::SignedChunks,
    Mode::SignedTrailer,
    Mode::UnsignedTrailer,
];

fn with_length(mut req: Req, body: Vec<u8>) -> Req {
    req.set_header("content-length", &body.len().to_string());
    req.body = body;
    req
}

/// A PutObject of `body` to `key` in [`BUCKET`], sent as `mode` sends it.
pub fn mode_req(rig: &Rig, signer: &Signer, key: &str, body: &[u8], mode: Mode) -> Req {
    let now = rig.now();
    let path = path(BUCKET, key);
    let decoded = body.len().to_string();
    let chunked = [
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", decoded.as_str()),
    ];
    let with_trailer = [chunked[0], chunked[1], ("x-amz-trailer", CRC32C)];
    let put = |extra: &[(&str, &str)], payload: &str| {
        signer.sign_as(
            now,
            Method::Put,
            &path,
            &[],
            extra,
            Vec::new(),
            Some(payload),
        )
    };
    match mode {
        Mode::Literal => signer.sign(now, Method::Put, &path, &[], &[], body.to_vec()),
        Mode::Unsigned => with_length(put(&[], "UNSIGNED-PAYLOAD").0, body.to_vec()),
        Mode::SignedChunks => {
            let (req, seed) = put(&chunked, SIGNED);
            with_length(req, signer.signed_chunks(now, &seed, body, CHUNK, None))
        }
        Mode::SignedTrailer => {
            let (req, seed) = put(&with_trailer, SIGNED_TRAILER);
            let trailer = Some((CRC32C, crc32c_b64(body)));
            with_length(req, signer.signed_chunks(now, &seed, body, CHUNK, trailer))
        }
        Mode::UnsignedTrailer => {
            let (mut req, _) = put(&with_trailer, UNSIGNED_TRAILER);
            req.set_header("transfer-encoding", "chunked");
            let trailer = format!("{CRC32C}:{}", crc32c_b64(body));
            req.body = unsigned_chunks(body, 64 * 1024, &trailer);
            req
        }
    }
}

/// The headers of a PutObject of `len` bytes in `mode`, without a body.
pub fn declared_req(rig: &Rig, signer: &Signer, key: &str, len: u64, mode: Mode) -> Req {
    let now = rig.now();
    let path = path(BUCKET, key);
    let decoded = len.to_string();
    let chunked = [
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", decoded.as_str()),
    ];
    let with_trailer = [chunked[0], chunked[1], ("x-amz-trailer", CRC32C)];
    let none = hex(&sha256(b""));
    let (extra, payload): (&[(&str, &str)], &str) = match mode {
        Mode::Literal => (&[], none.as_str()),
        Mode::Unsigned => (&[], "UNSIGNED-PAYLOAD"),
        Mode::SignedChunks => (&chunked, SIGNED),
        Mode::SignedTrailer => (&with_trailer, SIGNED_TRAILER),
        Mode::UnsignedTrailer => (&with_trailer, UNSIGNED_TRAILER),
    };
    let (mut req, _) = signer.sign_as(
        now,
        Method::Put,
        &path,
        &[],
        extra,
        Vec::new(),
        Some(payload),
    );
    match mode {
        Mode::Literal | Mode::Unsigned => req.set_header("content-length", &decoded),
        // The framing is longer than what it carries.
        Mode::SignedChunks | Mode::SignedTrailer => {
            req.set_header("content-length", &(len + 1024).to_string());
        }
        Mode::UnsignedTrailer => req.set_header("transfer-encoding", "chunked"),
    }
    req
}

/// The ETag S3 gives a PutObject: the MD5 of its body, quoted.
pub fn md5_etag(body: &[u8]) -> String {
    format!("\"{:x}\"", md5::compute(body))
}

pub async fn get(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
        .await
}

// ---------------------------------------------------------------------------
// What the stores hold
// ---------------------------------------------------------------------------

pub fn sql(rig: &Rig, script: &str) {
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(script).unwrap());
}

/// The first column of every row of `query`.
pub fn column(rig: &Rig, query: &str) -> Vec<String> {
    rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c.prepare(query).unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        rows.collect::<std::result::Result<Vec<_>, _>>().unwrap()
    })
}

pub fn number(rig: &Rig, query: &str) -> i64 {
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.query_row(query, [], |r| r.get(0)).unwrap())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub extent: String,
    pub write: String,
    pub tenant: String,
    pub generation: Option<String>,
    pub state: String,
    pub created_at: i64,
}

pub fn intents(rig: &Rig) -> Vec<Intent> {
    rig.bridge.catalog.sql.with_conn(|c| {
        let mut stmt = c
            .prepare(
                "SELECT extent_id, write_id, tenant_id, generation_id, state, created_at \
                 FROM write_intents ORDER BY extent_id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok(Intent {
                    extent: r.get(0)?,
                    write: r.get(1)?,
                    tenant: r.get(2)?,
                    generation: r.get(3)?,
                    state: r.get(4)?,
                    created_at: r.get(5)?,
                })
            })
            .unwrap();
        rows.collect::<std::result::Result<Vec<_>, _>>().unwrap()
    })
}

/// The states of the intent rows, one entry per state with its count.
pub fn states(rig: &Rig) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    for i in intents(rig) {
        match out.iter_mut().find(|(s, _)| *s == i.state) {
            Some((_, n)) => *n += 1,
            None => out.push((i.state, 1)),
        }
    }
    out.sort();
    out
}

fn keys_under(rig: &Rig, prefix: &str) -> Vec<String> {
    let mut keys: Vec<String> = rig
        .bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| k.starts_with(prefix))
        .collect();
    keys.sort();
    keys
}

/// The ids of the extents with a safety copy.
pub fn blobs(rig: &Rig) -> Vec<String> {
    keys_under(rig, "x/")
        .into_iter()
        .map(|k| k[2..].to_string())
        .collect()
}

/// The generation ids with a recovery record.
pub fn records(rig: &Rig) -> Vec<String> {
    keys_under(rig, "m/g_")
        .into_iter()
        .map(|k| k[2..].to_string())
        .collect()
}

pub fn stamps(rig: &Rig) -> Vec<String> {
    keys_under(rig, "rs/")
}

/// Safety copies that no extent row names.
pub fn orphans(rig: &Rig) -> Vec<String> {
    let named = column(rig, "SELECT id FROM extents");
    blobs(rig)
        .into_iter()
        .filter(|id| !named.contains(id))
        .collect()
}

/// Extent rows without their safety copy. Nothing is posted in these
/// tests, so every extent has one.
pub fn broken(rig: &Rig) -> Vec<String> {
    let have = blobs(rig);
    column(rig, "SELECT id FROM extents")
        .into_iter()
        .filter(|id| !have.contains(id))
        .collect()
}

// ---------------------------------------------------------------------------
// Requests that stop at a chosen call
// ---------------------------------------------------------------------------

pub type Running<'a, V> = Pin<Box<dyn Future<Output = V> + 'a>>;

/// How far a future got.
pub enum Ran<'a, V> {
    Done(V),
    /// Stopped at the armed call. Dropping it is a handler that was
    /// killed there; [`resume`] lets it go on.
    Stalled(Running<'a, V>),
}

impl<V> Ran<'_, V> {
    pub fn done(self) -> Option<V> {
        match self {
            Ran::Done(v) => Some(v),
            Ran::Stalled(_) => None,
        }
    }
}

/// Runs `fut` with the wire armed for the call after `skip` more.
pub async fn run_until<'a, V>(
    rig: &Rig,
    fut: impl Future<Output = V> + 'a,
    skip: u64,
    trip: Trip,
) -> Ran<'a, V> {
    rig.trip().arm(skip, trip);
    let mut fut: Running<'a, V> = Box::pin(fut);
    match std::future::poll_fn(|cx| Poll::Ready(fut.as_mut().poll(cx))).await {
        Poll::Ready(v) => Ran::Done(v),
        Poll::Pending => Ran::Stalled(fut),
    }
}

/// Lets a stalled future run to its end.
pub async fn resume<V>(rig: &Rig, fut: Running<'_, V>) -> V {
    rig.trip().release();
    fut.await
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// The sweep jobs one cron tick sends.
pub async fn sweep_jobs(rig: &Rig) -> Vec<Job> {
    rig.bridge.jobs.inner.take();
    let report = rig.bridge.dispatch().await.unwrap();
    let jobs: Vec<Job> = rig
        .bridge
        .jobs
        .inner
        .take()
        .into_iter()
        .map(|s| s.job)
        .filter(|j| matches!(j, Job::Sweep { .. }))
        .collect();
    assert!(!report.sweep_failed);
    assert_eq!(report.sweeps_enqueued as usize, jobs.len());
    jobs
}

/// One cron tick and every sweep job it sent. Returns their number.
pub async fn sweep_tick(rig: &Rig) -> usize {
    let jobs = sweep_jobs(rig).await;
    for job in &jobs {
        assert_eq!(rig.bridge.run_job(job).await, JobOutcome::Ack);
    }
    jobs.len()
}

pub fn sweep_job(write: &str) -> Job {
    Job::Sweep {
        v: JOB_VERSION,
        write: WriteId::new(write),
    }
}

// ---------------------------------------------------------------------------
// The catalogue at an earlier point
// ---------------------------------------------------------------------------

fn tables(rig: &Rig) -> Vec<String> {
    column(
        rig,
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'snap\\_%' ESCAPE '\\' \
         AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name <> 'tx_guard' ORDER BY name",
    )
}

/// Copies every catalogue table aside.
pub fn snapshot(rig: &Rig) {
    for t in tables(rig) {
        sql(
            rig,
            &format!("DROP TABLE IF EXISTS snap_{t}; CREATE TABLE snap_{t} AS SELECT * FROM {t};"),
        );
    }
}

/// Every table is as it was at the snapshot: what a Time Travel restore
/// or an import of an older export does. The stores keep what they hold.
pub fn rollback(rig: &Rig) {
    sql(rig, "PRAGMA foreign_keys = OFF;");
    for t in tables(rig) {
        sql(
            rig,
            &format!("DELETE FROM {t}; INSERT INTO {t} SELECT * FROM snap_{t};"),
        );
    }
    sql(rig, "PRAGMA foreign_keys = ON;");
}

pub async fn admin(rig: &Rig, method: Method, path: &str, body: &[u8]) -> Resp {
    let mut req = Req {
        method,
        target: format!("/_admin{path}"),
        headers: Vec::new(),
        body: body.to_vec(),
    };
    req.set_header("host", HOST);
    req.set_header("content-length", &req.body.len().to_string());
    req.set_header(
        "authorization",
        &format!("Bearer {}", rig.bridge.cfg.admin_token.expose()),
    );
    rig.send(req).await
}

pub async fn status(rig: &Rig) -> Value {
    let r = admin(rig, Method::Get, "/status", b"").await;
    r.expect(200);
    serde_json::from_slice(&r.body).unwrap()
}

/// The `write_intents` figures of the status report.
pub async fn intent_status(rig: &Rig) -> Value {
    status(rig).await["write_intents"].clone()
}

fn maintenance(rig: &mut Rig, mode: Maintenance) {
    Rc::get_mut(&mut rig.bridge)
        .expect("no request is running")
        .cfg
        .maintenance = mode;
}

/// The runbook's restore: maintenance on, the replay of every recovery
/// record to its end, maintenance off.
pub async fn restore(rig: &mut Rig) {
    restore_from(rig, 0).await;
}

/// The same, of the records minted at or after `since_ms` only.
pub async fn restore_from(rig: &mut Rig, since_ms: i64) {
    maintenance(rig, Maintenance::Restore);
    let mut body = json!({ "since_ms": since_ms, "margin_ms": 0 });
    loop {
        let r = admin(rig, Method::Post, "/restore", body.to_string().as_bytes()).await;
        r.expect(200);
        let report: Value = serde_json::from_slice(&r.body).unwrap();
        if report["next"].is_null() {
            break;
        }
        body = json!({ "cursor": report["next"] });
    }
    maintenance(rig, Maintenance::Off);
}

/// Sends `req` with its body arriving `piece` bytes at a time, so that a
/// fault at the end of the body is met after the slices before it.
pub async fn send_in_pieces(rig: &Rig, req: Req, piece: usize) -> Resp {
    use futures_util::stream::{self, StreamExt as _};
    let declared_len = req
        .headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok());
    let pieces: Vec<_> = req.body.chunks(piece).map(|c| Ok(c.to_vec())).collect();
    let request = S3Request {
        method: req.method,
        raw_target: req.target,
        headers: req.headers,
        body: Body::Stream {
            declared_len,
            stream: stream::iter(pieces).boxed_local(),
        },
    };
    Resp::collect(Rc::clone(&rig.bridge).handle(request).await).await
}

impl<'a, V> Ran<'a, V> {
    /// The stopped future; panics when it ran to its end.
    pub fn stalled(self) -> Running<'a, V> {
        match self {
            Ran::Stalled(fut) => fut,
            Ran::Done(_) => panic!("ran to its end"),
        }
    }
}

/// Lets a stalled future go on, with the wire armed again for the call
/// after `skip` more.
pub async fn resume_until<'a, V>(
    rig: &Rig,
    mut fut: Running<'a, V>,
    skip: u64,
    trip: Trip,
) -> Ran<'a, V> {
    rig.trip().arm(skip, trip);
    rig.trip().release();
    match std::future::poll_fn(|cx| Poll::Ready(fut.as_mut().poll(cx))).await {
        Poll::Ready(v) => Ran::Done(v),
        Poll::Pending => Ran::Stalled(fut),
    }
}

/// Runs `fut` one call at a time until `at` holds: it is then stopped
/// before its next call.
pub async fn step_to<'a, V>(
    rig: &Rig,
    fut: impl Future<Output = V> + 'a,
    at: impl Fn(&Rig) -> bool,
) -> Ran<'a, V> {
    let mut ran = run_until(rig, fut, 0, Trip::Stall).await;
    loop {
        match ran {
            Ran::Stalled(fut) if !at(rig) => ran = resume_until(rig, fut, 0, Trip::Stall).await,
            other => return other,
        }
    }
}

/// A request that does not borrow the rig, so that it can be kept
/// while the rig is used.
pub fn start(rig: &Rig, req: Req) -> Running<'static, Resp> {
    let bridge = Rc::clone(&rig.bridge);
    Box::pin(async move { Resp::collect(bridge.handle(req.into_request()).await).await })
}

/// A queue job, likewise.
pub fn start_job(rig: &Rig, job: Job) -> Running<'static, JobOutcome> {
    let bridge = Rc::clone(&rig.bridge);
    Box::pin(async move { bridge.run_job(&job).await })
}
