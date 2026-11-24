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

pub fn small_rig_selected() -> Rig {
    rig_with_selected(NoNntp, small_config())
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
    mode_req_at(rig, signer, key, &[], body, mode)
}

/// The same body modes on `PUT key?query`: an UploadPart.
pub fn mode_req_at(
    rig: &Rig,
    signer: &Signer,
    key: &str,
    query: &[(&str, &str)],
    body: &[u8],
    mode: Mode,
) -> Req {
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
            query,
            extra,
            Vec::new(),
            Some(payload),
        )
    };
    match mode {
        Mode::Literal => signer.sign(now, Method::Put, &path, query, &[], body.to_vec()),
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
    declared_req_at(rig, signer, key, &[], len, mode)
}

/// The same headers on `PUT key?query`.
pub fn declared_req_at(
    rig: &Rig,
    signer: &Signer,
    key: &str,
    query: &[(&str, &str)],
    len: u64,
    mode: Mode,
) -> Req {
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
        query,
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

/// A request whose body is refused: what is wrong with it, the request,
/// and the status and code S3 answers.
pub type RefusedBody = (&'static str, Req, u16, &'static str);

/// PutObjects whose body is refused. Each of them fails at or after the
/// last [`CHUNK`] of the body.
pub fn refused_bodies(rig: &Rig, signer: &Signer, key: &str, body: &[u8]) -> Vec<RefusedBody> {
    refused_bodies_at(rig, signer, key, &[], body)
}

/// The same bodies on `PUT key?query`: an UploadPart.
pub fn refused_bodies_at(
    rig: &Rig,
    signer: &Signer,
    key: &str,
    query: &[(&str, &str)],
    body: &[u8],
) -> Vec<RefusedBody> {
    use base64::Engine as _;
    let now = rig.now();
    let p = path(BUCKET, key);
    let mut other = body.to_vec();
    *other.last_mut().unwrap() ^= 1;
    let mut out = Vec::new();

    let md5 = base64::engine::general_purpose::STANDARD.encode(md5::compute(&other).0);
    let req = signer.sign(
        now,
        Method::Put,
        &p,
        query,
        &[("content-md5", &md5)],
        body.to_vec(),
    );
    out.push(("a wrong Content-MD5", req, 400, "BadDigest"));

    let mut req = signer.sign(now, Method::Put, &p, query, &[], other.clone());
    req.body = body.to_vec();
    out.push(("a wrong payload hash", req, 400, "BadDigest"));

    let sum = base64::engine::general_purpose::STANDARD.encode(sha256(&other));
    let req = signer.sign(
        now,
        Method::Put,
        &p,
        query,
        &[("x-amz-checksum-sha256", &sum)],
        body.to_vec(),
    );
    out.push(("a wrong checksum header", req, 400, "BadDigest"));

    let mut req = mode_req_at(rig, signer, key, query, &other, Mode::UnsignedTrailer);
    let trailer = format!("{CRC32C}:{}", crc32c_b64(&other));
    req.body = unsigned_chunks(body, 64 * 1024, &trailer);
    out.push(("a wrong unsigned trailer checksum", req, 400, "BadDigest"));

    let decoded = body.len().to_string();
    let chunked = [
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", decoded.as_str()),
    ];
    let with_trailer = [chunked[0], chunked[1], ("x-amz-trailer", CRC32C)];
    let sized = |mut req: Req, body: Vec<u8>| {
        req.set_header("content-length", &body.len().to_string());
        req.body = body;
        req
    };

    let (req, seed) = signer.sign_as(
        now,
        Method::Put,
        &p,
        query,
        &with_trailer,
        Vec::new(),
        Some(SIGNED_TRAILER),
    );
    let wire = signer.signed_chunks(now, &seed, body, CHUNK, Some((CRC32C, crc32c_b64(&other))));
    out.push((
        "a wrong signed trailer checksum",
        sized(req, wire),
        400,
        "BadDigest",
    ));

    // The signature of the last chunk that carries data.
    let (req, seed) = signer.sign_as(
        now,
        Method::Put,
        &p,
        query,
        &chunked,
        Vec::new(),
        Some(SIGNED),
    );
    let mut wire = signer.signed_chunks(now, &seed, body, CHUNK, None);
    let last_data = body.len() - (body.len() - 1) % CHUNK - 1;
    let good = signer.signed_chunks(now, &seed, &body[..last_data], CHUNK, None);
    // `good` and `wire` agree up to the header of that chunk.
    let header_at = good.len() - "0;chunk-signature=".len() - 64 - 4;
    let sig_at = header_at + wire[header_at..].iter().position(|b| *b == b'=').unwrap() + 1;
    wire[sig_at] = if wire[sig_at] == b'0' { b'1' } else { b'0' };
    out.push((
        "a bad signature on the last data chunk",
        sized(req, wire),
        403,
        "SignatureDoesNotMatch",
    ));

    // The signature of the empty chunk that ends the body.
    let (req, seed) = signer.sign_as(
        now,
        Method::Put,
        &p,
        query,
        &chunked,
        Vec::new(),
        Some(SIGNED),
    );
    let mut wire = signer.signed_chunks(now, &seed, body, CHUNK, None);
    let sig_at = wire.len() - 64 - 4;
    wire[sig_at] = if wire[sig_at] == b'0' { b'1' } else { b'0' };
    out.push((
        "a bad signature on the final chunk",
        sized(req, wire),
        403,
        "SignatureDoesNotMatch",
    ));

    let mut req = mode_req_at(rig, signer, key, query, body, Mode::Unsigned);
    req.body.pop();
    out.push(("a body one byte short", req, 400, "IncompleteBody"));

    let mut req = mode_req_at(rig, signer, key, query, body, Mode::Unsigned);
    req.body.push(0);
    out.push(("a body one byte long", req, 400, "EntityTooLarge"));

    out
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
    rig.bridge.catalog.sql.inner.fixture_script(script).unwrap();
}

/// The first column of every row of `query`.
pub fn column(rig: &Rig, query: &str) -> Vec<String> {
    rig.bridge
        .catalog
        .sql
        .inner
        .fixture_query_now(query, &[])
        .unwrap()
        .into_iter()
        .map(|mut row| match row.remove(0) {
            SqlValue::Text(value) => value,
            _ => panic!("expected fixture text column"),
        })
        .collect()
}

pub fn number(rig: &Rig, query: &str) -> i64 {
    match rig
        .bridge
        .catalog
        .sql
        .inner
        .fixture_query_now(query, &[])
        .unwrap()
        .remove(0)
        .remove(0)
    {
        SqlValue::Int(value) => value,
        _ => panic!("expected fixture integer column"),
    }
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
    rig.bridge.catalog.sql.inner.fixture_query_now(
        "SELECT extent_id, write_id, tenant_id, generation_id, state, created_at \
         FROM write_intents ORDER BY extent_id", &[],
    ).unwrap().into_iter().map(|row| {
        let [SqlValue::Text(extent), SqlValue::Text(write), SqlValue::Text(tenant), generation,
             SqlValue::Text(state), SqlValue::Int(created_at)] = row.as_slice() else {
            panic!("unexpected write intent row shape")
        };
        let generation = match generation {
            SqlValue::Text(id) => Some(id.clone()),
            SqlValue::Null => None,
            _ => panic!("expected nullable generation ID"),
        };
        Intent { extent: extent.clone(), write: write.clone(), tenant: tenant.clone(), generation,
                 state: state.clone(), created_at: *created_at }
    }).collect()
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

pub fn keys_under(rig: &Rig, prefix: &str) -> Vec<String> {
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
    let fut: Running<'a, V> = Box::pin(fut);
    wait_for_trip(rig, fut, trip).await
}

async fn wait_for_trip<'a, V>(rig: &Rig, mut fut: Running<'a, V>, trip: Trip) -> Ran<'a, V> {
    let wire = rig.trip();
    // A real PostgreSQL call can yield before reaching the injected fault.
    // Pending alone cannot tell a normal socket wait from a held tripwire.
    let trip_or_done = std::future::poll_fn(|cx| match fut.as_mut().poll(cx) {
        Poll::Ready(value) => Poll::Ready(Some(value)),
        Poll::Pending if trip == Trip::Stall && wire.tripped() => Poll::Ready(None),
        Poll::Pending => Poll::Pending,
    });
    match tokio::time::timeout(std::time::Duration::from_secs(10), trip_or_done)
        .await
        .expect("fixture request never reached its injected fault or completed")
    {
        Some(value) => Ran::Done(value),
        None => Ran::Stalled(fut),
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
    let db = &rig.bridge.catalog.sql.inner;
    column(rig, db.fixture(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'snap\\_%' ESCAPE '\\' \
         AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name <> 'tx_guard' ORDER BY name",
        "SELECT table_name::text FROM information_schema.tables WHERE table_schema = current_schema() \
         AND table_type = 'BASE TABLE' AND left(table_name, 5) <> 'snap_' \
         AND table_name <> 'tx_guard' ORDER BY table_name",
    ))
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
    if rig.bridge.catalog.sql.dialect() == Dialect::Postgres {
        rollback_postgres(rig);
        return;
    }
    sql(rig, "PRAGMA foreign_keys = OFF;");
    for t in tables(rig) {
        sql(
            rig,
            &format!("DELETE FROM {t}; INSERT INTO {t} SELECT * FROM snap_{t};"),
        );
    }
    sql(rig, "PRAGMA foreign_keys = ON;");
}

/// Restore only this fixture schema, in FK order, without a privileged trigger bypass.
fn rollback_postgres(rig: &Rig) {
    use std::fmt::Write as _;
    let all = tables(rig);
    let db = &rig.bridge.catalog.sql.inner;
    let refs = db
        .fixture_query_now(
            "SELECT child.relname::text, parent.relname::text FROM pg_constraint fk \
         JOIN pg_class child ON child.oid = fk.conrelid \
         JOIN pg_class parent ON parent.oid = fk.confrelid \
         JOIN pg_namespace n ON child.relnamespace = n.oid \
         WHERE fk.contype = 'f' AND n.nspname = current_schema()",
            &[],
        )
        .unwrap();
    let refs: Vec<_> = refs
        .iter()
        .map(|row| {
            let [SqlValue::Text(child), SqlValue::Text(parent)] = row.as_slice() else {
                panic!("unexpected foreign key fixture row")
            };
            (child.as_str(), parent.as_str())
        })
        .collect();
    let mut pending: Vec<_> = all
        .iter()
        .filter(|name| !name.starts_with("usage_"))
        .collect();
    let mut order = Vec::new();
    while !pending.is_empty() {
        let index = pending
            .iter()
            .position(|name| {
                !refs.iter().any(|(child, parent)| {
                    *child == name.as_str() && pending.iter().any(|p| p.as_str() == *parent)
                })
            })
            .expect("cyclic fixture foreign keys");
        order.push(pending.remove(index));
    }
    // The counter tables are restored last. With no usage_global row during
    // the data insert, the usage triggers do not double-count the snapshot.
    order.extend(all.iter().filter(|name| name.starts_with("usage_")));
    let mut script = format!("BEGIN; TRUNCATE TABLE {};", all.join(","));
    for table in order {
        let conflict = if table == "generation_extents" {
            " ON CONFLICT DO NOTHING"
        } else {
            ""
        };
        writeln!(
            &mut script,
            "INSERT INTO {table} SELECT * FROM snap_{table}{conflict};"
        )
        .unwrap();
    }
    script.push_str("COMMIT;");
    sql(rig, &script);
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
    fut: Running<'a, V>,
    skip: u64,
    trip: Trip,
) -> Ran<'a, V> {
    rig.trip().arm(skip, trip);
    rig.trip().release();
    wait_for_trip(rig, fut, trip).await
}

/// Runs `fut` one call at a time until `at` holds: it is then stopped
/// before its next call.
pub async fn step_to<'a, V>(
    rig: &Rig,
    fut: impl Future<Output = V> + 'a,
    at: impl Fn(&Rig) -> bool,
) -> Ran<'a, V> {
    let mut ran = resume_until(rig, Box::pin(fut), 0, Trip::Stall).await;
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
