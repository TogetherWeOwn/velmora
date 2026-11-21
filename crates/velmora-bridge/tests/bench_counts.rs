//! Work and cost meter of the S3 operations and of the pipeline stages:
//! layer 1 of the benchmark (`bench/README.md`), local and deterministic.
//!
//! The real [`Bridge`] runs over the SQLite catalogue, in-memory blob
//! stores and a real NNTP client talking to the in-process fake server,
//! with the variables of the production `[vars]` of `wrangler.toml`
//! (VERIFY_MODE, PACKED_PLANS, REQUIRED_BACKBONES, SAFETY_MIN_AGE_SECS,
//! MAX_PUT_BYTES, ...). Every port is wrapped by a meter that charges what
//! crosses it to the operation or stage that is running:
//!
//! - D1: calls (round trips), statements, batches, rows returned, and rows
//!   written as D1 bills them (the meter of `tests/rows_written.rs`). The
//!   statements are also written to a trace, which `bench/d1-replay.mjs`
//!   runs through the local D1 runtime to read D1's own `rows_read` and
//!   `rows_written` for each of them;
//! - R2: operations by R2 price class (A: put, list; B: get, head; free:
//!   delete) and bytes in each direction, per store;
//! - Queues: send calls and messages, and redeliveries of a retried job;
//! - NNTP: connects, posts and bytes posted, STAT/size asks, bodies and
//!   bytes read;
//! - invocations (one per S3 request, queue message and cron run) and the
//!   wall time of the native run (indicative only: not the Worker's CPU).
//!
//! Operations run one after another and jobs run in turn, so each figure
//! belongs to exactly one label. `bench_counts_full` (ignored) writes
//! `counts.json` and `d1-trace.jsonl` into `$VELMORA_BENCH_OUT`;
//! `bench/run-local.sh` runs it. `bench_counts_smoke` runs the same
//! scenario at a small scale on every `cargo test`, so the harness keeps
//! compiling and running as the code changes.

mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::rc::Rc;
use std::time::Instant;

use base64::Engine as _;
use serde::Serialize;
use service_support::{path, Resp, Signer, AKID, HOST, MIB, T0};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::rng::SystemRng;
use velmora::transports::NativeTlsTransport;
use velmora_bridge::config::BridgeConfig;
use velmora_bridge::crypto::{wrap_bdk, wrap_secret, DataKey};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::recovery::Unpublished;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const GROUP: &str = "alt.binaries.test";
const PASS: &str = "bench-pass";
const ADMIN_TOKEN: &str = "bench-admin-token-0123456789abcdef0123";
const CRON_SECS: u32 = 300;
const DAY: u32 = 86_400;
const MAX_ROUNDS: u32 = 2_000;
/// How a job's claim of its outbox row begins (`sql/outbox.rs`).
const CLAIM_SQL: &str = "UPDATE outbox SET lease_token = lease_token + 1, lease_owner = ?4";
/// The late queue (`VELMORA_BENCH_LATE_QUEUE`): every message of the ingest
/// loop is delivered this long after it is due, so a dispatcher run always
/// comes first. (`ticks`, for the release and delete phases, gets the same
/// order by delivering what is queued after its dispatcher run.)
const LATE_SECS: u32 = CRON_SECS + 60;

// ---------------------------------------------------------------------------
// The meter
// ---------------------------------------------------------------------------

/// What crossed the ports under one label.
#[derive(Clone, Debug, Default, Serialize)]
struct Counts {
    invocations: u64,
    wall_us: u64,
    d1_calls: u64,
    d1_statements: u64,
    d1_batches: u64,
    d1_rows_returned: u64,
    d1_rows_written: u64,
    d1_errors: u64,
    r2_class_a: u64,
    r2_class_b: u64,
    r2_free: u64,
    r2_bytes_in: u64,
    r2_bytes_out: u64,
    r2_safety_ops: u64,
    r2_cache_ops: u64,
    r2_puts: u64,
    r2_gets: u64,
    r2_heads: u64,
    r2_deletes: u64,
    r2_lists: u64,
    queue_sends: u64,
    queue_messages: u64,
    queue_redeliveries: u64,
    nntp_connects: u64,
    nntp_posts: u64,
    nntp_post_bytes: u64,
    nntp_asks: u64,
    nntp_bodies: u64,
    nntp_body_bytes: u64,
    /// Outbox claims by a job, and those that found nothing to do (the
    /// row was not due, leased, or already past the job's stage).
    outbox_claims: u64,
    outbox_empty_claims: u64,
}

/// The label in force and everything charged so far.
#[derive(Default)]
struct Hub {
    label: RefCell<String>,
    counts: RefCell<BTreeMap<String, Counts>>,
    calls: RefCell<BTreeMap<String, u64>>,
    trace: RefCell<Option<BufWriter<File>>>,
    seq: Cell<u64>,
}

impl Hub {
    fn set(&self, label: &str) {
        *self.label.borrow_mut() = label.to_string();
    }

    fn label(&self) -> String {
        self.label.borrow().clone()
    }

    fn add(&self, f: impl FnOnce(&mut Counts)) {
        let label = self.label();
        f(self.counts.borrow_mut().entry(label).or_default());
    }

    /// One D1 call into the trace: its statements, their parameters and
    /// whether the native run took it.
    fn trace(&self, kind: &str, stmts: &[(&str, &[SqlValue])], ok: bool) {
        let mut trace = self.trace.borrow_mut();
        let Some(out) = trace.as_mut() else {
            return;
        };
        let i = self.seq.get();
        self.seq.set(i + 1);
        let s: Vec<serde_json::Value> = stmts
            .iter()
            .map(|(sql, params)| {
                serde_json::json!({
                    "q": sql,
                    "p": params.iter().map(param_json).collect::<Vec<_>>(),
                })
            })
            .collect();
        let line = serde_json::json!({
            "i": i, "l": self.label(), "k": kind, "ok": ok, "s": s,
        });
        writeln!(out, "{line}").expect("trace write");
    }
}

fn param_json(v: &SqlValue) -> serde_json::Value {
    match v {
        SqlValue::Null => serde_json::Value::Null,
        SqlValue::Int(i) => serde_json::json!(i),
        SqlValue::Text(t) => serde_json::json!(t),
        SqlValue::Blob(b) => {
            serde_json::json!({ "b": base64::engine::general_purpose::STANDARD.encode(b) })
        }
    }
}

/// D1 behind the meter.
struct MeterSql {
    inner: RusqliteSql,
    hub: Rc<Hub>,
}

impl MeterSql {
    fn written(&self) -> u64 {
        self.inner.writes().billed()
    }

    fn charge(&self, statements: u64, batch: bool, returned: u64, written: u64, ok: bool) {
        self.hub.add(|c| {
            c.d1_calls += 1;
            c.d1_statements += statements;
            c.d1_batches += u64::from(batch);
            c.d1_rows_returned += returned;
            c.d1_rows_written += written;
            c.d1_errors += u64::from(!ok);
        });
    }
}

impl Sql for MeterSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let before = self.written();
        let out = self.inner.query(sql, params).await;
        let returned = out.as_ref().map_or(0, |r| r.len() as u64);
        self.charge(1, false, returned, self.written() - before, out.is_ok());
        if sql.starts_with(CLAIM_SQL) {
            self.hub.add(|c| {
                c.outbox_claims += 1;
                c.outbox_empty_claims += u64::from(returned == 0);
            });
        }
        self.hub.trace("q", &[(sql, params)], out.is_ok());
        out
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let before = self.written();
        let out = self.inner.exec(sql, params).await;
        self.charge(1, false, 0, self.written() - before, out.is_ok());
        self.hub.trace("e", &[(sql, params)], out.is_ok());
        out
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        let traced: Vec<(&'static str, Vec<SqlValue>)> = stmts.clone();
        let n = stmts.len() as u64;
        let before = self.written();
        let out = self.inner.batch(stmts).await;
        self.charge(n, true, 0, self.written() - before, out.is_ok());
        let view: Vec<(&str, &[SqlValue])> =
            traced.iter().map(|(q, p)| (*q, p.as_slice())).collect();
        self.hub.trace("b", &view, out.is_ok());
        out
    }

    fn limits(&self) -> SqlLimits {
        self.inner.limits()
    }
}

/// An R2 bucket behind the meter. Classes as R2 prices them: a put or a
/// list page is class A, a get (whole or ranged) or a head is class B, a
/// delete is free.
struct MeterBlobs {
    inner: MemBlobStore,
    safety: bool,
    hub: Rc<Hub>,
}

impl MeterBlobs {
    fn charge(&self, f: impl FnOnce(&mut Counts)) {
        let safety = self.safety;
        self.hub.add(|c| {
            if safety {
                c.r2_safety_ops += 1;
            } else {
                c.r2_cache_ops += 1;
            }
            f(c);
        });
    }
}

/// R2 answers a list in pages of up to 1,000 keys.
fn list_pages(n: usize) -> u64 {
    (n as u64).div_ceil(1000).max(1)
}

impl BlobStore for MeterBlobs {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        let len = bytes.len() as u64;
        self.charge(|c| {
            c.r2_class_a += 1;
            c.r2_puts += 1;
            c.r2_bytes_in += len;
        });
        self.inner.put(key, bytes, meta).await
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        let out = self.inner.get(key, span).await;
        let len = match &out {
            Ok(Some(b)) => b.len() as u64,
            _ => 0,
        };
        self.charge(|c| {
            c.r2_class_b += 1;
            c.r2_gets += 1;
            c.r2_bytes_out += len;
        });
        out
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.charge(|c| {
            c.r2_class_b += 1;
            c.r2_heads += 1;
        });
        self.inner.head(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.charge(|c| {
            c.r2_free += 1;
            c.r2_deletes += 1;
        });
        self.inner.delete(key).await
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.charge(|c| {
            c.r2_free += 1;
            c.r2_deletes += 1;
        });
        self.inner.delete_record(refused).await
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        let out = self.inner.list(prefix, start_after, limit).await;
        let pages = list_pages(out.as_ref().map_or(0, Vec::len));
        self.charge(|c| {
            c.r2_class_a += pages;
            c.r2_lists += pages;
        });
        out
    }

    async fn list_entries(
        &self,
        prefix: &str,
        start_after: &str,
        limit: u32,
    ) -> Result<Vec<BlobEntry>> {
        // R2 gives size and MD5 in the listing: no read per key.
        let out = self.inner.list_entries(prefix, start_after, limit).await;
        let pages = list_pages(out.as_ref().map_or(0, Vec::len));
        self.charge(|c| {
            c.r2_class_a += pages;
            c.r2_lists += pages;
        });
        out
    }
}

/// Queues behind the meter. A message is billed three operations (write,
/// read, delete), and each redelivery one more read.
struct MeterJobs {
    inner: FakeJobs,
    hub: Rc<Hub>,
}

impl JobSink for MeterJobs {
    async fn send(&self, job: &Job, delay_secs: u32) -> Result<()> {
        self.hub.add(|c| {
            c.queue_sends += 1;
            c.queue_messages += 1;
        });
        self.inner.send(job, delay_secs).await
    }

    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        let n = jobs.len() as u64;
        self.hub.add(|c| {
            c.queue_sends += 1;
            c.queue_messages += n;
        });
        self.inner.send_many(jobs).await
    }

    async fn backlog(&self) -> Backlog {
        self.inner.backlog().await
    }
}

/// Plaintext dial to the fake server, every command counted.
struct MeterNntp {
    hub: Rc<Hub>,
}

struct MeterSession {
    client: Option<NntpClient<NativeTlsTransport>>,
    hub: Rc<Hub>,
}

impl MeterSession {
    fn client(&mut self) -> Result<&mut NntpClient<NativeTlsTransport>> {
        self.client
            .as_mut()
            .ok_or(BridgeError::Invalid("session used after quit"))
    }
}

impl NntpSession for MeterSession {
    async fn post(&mut self, message_id: &str, article: &[u8]) -> Result<PostOutcome> {
        let len = article.len() as u64;
        self.hub.add(|c| {
            c.nntp_posts += 1;
            c.nntp_post_bytes += len;
        });
        NntpSession::post(self.client()?, message_id, article).await
    }

    async fn stat(&mut self, message_id: &str) -> Result<bool> {
        self.hub.add(|c| c.nntp_asks += 1);
        NntpSession::stat(self.client()?, message_id).await
    }

    async fn size(&mut self, message_id: &str, how: SizeCommand) -> Result<SizeOutcome> {
        self.hub.add(|c| c.nntp_asks += 1);
        NntpSession::size(self.client()?, message_id, how).await
    }

    async fn ask_many(
        &mut self,
        message_ids: &[&str],
        how: Option<SizeCommand>,
    ) -> Result<Vec<SizeOutcome>> {
        let n = message_ids.len() as u64;
        self.hub.add(|c| c.nntp_asks += n);
        NntpSession::ask_many(self.client()?, message_ids, how).await
    }

    async fn body(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome> {
        let before = out.len();
        let found = NntpSession::body(self.client()?, message_id, out).await;
        let len = (out.len() - before) as u64;
        self.hub.add(|c| {
            c.nntp_bodies += 1;
            c.nntp_body_bytes += len;
        });
        found
    }

    async fn quit(mut self) {
        if let Some(client) = self.client.take() {
            NntpSession::quit(client).await;
        }
    }
}

impl NntpConnector for MeterNntp {
    type Session = MeterSession;

    async fn connect(&self, p: &ProviderConfig, _permit: &Permit) -> Result<MeterSession> {
        self.hub.add(|c| c.nntp_connects += 1);
        let cfg = NntpConfig {
            host: p.host.clone(),
            port: p.port,
            tls: false,
            allow_insecure_plaintext: true,
            username: Some(p.user.clone()),
            password: Some(p.pass.clone()),
            timeout: std::time::Duration::from_secs(20),
            max_article_bytes: 4 * MIB,
            ..NntpConfig::default()
        };
        let transport = velmora::transports::tokio_tls::connect(&cfg)
            .await
            .map_err(velmora::Error::Io)?;
        let client = NntpClient::connect(transport, &cfg).await?;
        Ok(MeterSession {
            client: Some(client),
            hub: Rc::clone(&self.hub),
        })
    }
}

type BenchBridge =
    Bridge<SqlCatalog<MeterSql>, MeterBlobs, MeterNntp, MeterJobs, TestKek, FixedClock>;

// ---------------------------------------------------------------------------
// Configuration: production's [vars], fake providers
// ---------------------------------------------------------------------------

/// The `KEY = "value"` lines of the top-level `[vars]` of the Worker's
/// `wrangler.toml` (the production configuration).
fn production_vars() -> BTreeMap<String, String> {
    let file = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../workers/s3-bridge/wrangler.toml"
    );
    let text = std::fs::read_to_string(file).expect("wrangler.toml");
    let mut vars = BTreeMap::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[vars]";
            continue;
        }
        if !inside || line.starts_with('#') {
            continue;
        }
        let Some((k, rest)) = line.split_once('=') else {
            continue;
        };
        let rest = rest.trim();
        let Some(rest) = rest.strip_prefix('"') else {
            continue;
        };
        let Some(end) = rest.find('"') else {
            continue;
        };
        vars.insert(k.trim().to_string(), rest[..end].to_string());
    }
    assert!(
        vars.contains_key("MAX_EXTENT_BYTES"),
        "no [vars] read from {file}"
    );
    vars
}

/// What the run changes from production's `[vars]`, and why.
fn overrides(server: &TestNntpServer) -> Vec<(&'static str, String)> {
    let addr = server.addr();
    // As production: a post-only provider on a backbone that does not
    // count, and two read providers on two backbones that do.
    let provider =
        |id: &str, user: &str, bb: &str, post: bool, read: bool, prio: u8, release: bool| {
            serde_json::json!({
                "id": id, "host": addr.ip().to_string(), "port": addr.port(), "tls": false,
                "user": user, "pass": PASS, "backbone": bb, "post": post, "read": read,
                "max_conns": 8, "priority": prio, "release": release,
            })
        };
    let providers = serde_json::json!([
        provider("f7", "poster", "usenetfarm", true, false, 0, false),
        provider("f1", "reader1", "highwinds", true, true, 1, true),
        provider("f3", "reader3", "giganews", false, true, 2, true),
    ]);
    vec![
        // Plaintext providers on the loopback are a dev-only allowance.
        ("ENVIRONMENT", "dev".into()),
        ("S3_HOST", HOST.into()),
        ("NEWSGROUPS", GROUP.into()),
        // Production runs light verification (a deployment variable).
        ("VERIFY_MODE", "light".into()),
        // Production has GC off; the sweep stage is measured on a
        // disposable bucket, the only kind GC may touch here.
        ("GC_MODE", "disposable".into()),
        ("NNTP_PROVIDERS", providers.to_string()),
        ("ADMIN_TOKEN", ADMIN_TOKEN.into()),
        (
            "VELMORA_KEK_1",
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
        ),
    ]
}

/// Variables the rig needs as set above: overriding them would break the
/// run itself (fake providers, request signing, the admin route, sealing).
const FIXED_VARS: [&str; 5] = [
    "ENVIRONMENT",
    "S3_HOST",
    "NNTP_PROVIDERS",
    "ADMIN_TOKEN",
    "VELMORA_KEK_1",
];

/// `VELMORA_BENCH_VARS=KEY=VALUE,KEY=VALUE` (`bench/run-local.sh` sets it
/// from `BENCH_VARS`): Worker variables changed for one run, applied after
/// [`overrides`]. A value may hold commas: a new pair starts only at
/// `,KEY=` with KEY in `[A-Z][A-Z0-9_]*`.
fn parse_bench_vars(spec: &str) -> Vec<(String, String)> {
    fn is_key(k: &str) -> bool {
        let mut c = k.chars();
        c.next().is_some_and(|f| f.is_ascii_uppercase())
            && c.all(|x| x.is_ascii_uppercase() || x.is_ascii_digit() || x == '_')
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for piece in spec.split(',') {
        match piece.split_once('=') {
            Some((k, v)) if is_key(k) => out.push((k.to_string(), v.to_string())),
            _ => match out.last_mut() {
                Some((_, v)) => {
                    v.push(',');
                    v.push_str(piece);
                }
                None if spec.trim().is_empty() => {}
                None => panic!("VELMORA_BENCH_VARS: not KEY=VALUE: {piece:?}"),
            },
        }
    }
    for (k, _) in &out {
        assert!(
            !FIXED_VARS.contains(&k.as_str()) && !k.starts_with("VELMORA_KEK"),
            "VELMORA_BENCH_VARS: {k} is fixed by the rig"
        );
        // A secret would be written into counts.json and the report.
        let secret = ["TOKEN", "SECRET", "PASS", "KEK", "CREDENTIAL"]
            .iter()
            .any(|w| k.contains(w))
            || k.ends_with("_KEY");
        assert!(!secret, "VELMORA_BENCH_VARS: {k} looks like a secret");
        // The rig collects whole bodies; a fan-out answer it cannot.
        assert!(
            k != "GET_FANOUT_BYTES",
            "VELMORA_BENCH_VARS: GET_FANOUT_BYTES is not measured by the rig"
        );
    }
    out
}

#[test]
fn bench_vars_parse() {
    assert!(parse_bench_vars("").is_empty());
    assert_eq!(
        parse_bench_vars("PARITY=on,NEWSGROUPS=a.b,c.d,POST_SOCKETS=6"),
        vec![
            ("PARITY".to_string(), "on".to_string()),
            ("NEWSGROUPS".to_string(), "a.b,c.d".to_string()),
            ("POST_SOCKETS".to_string(), "6".to_string()),
        ]
    );
    assert_eq!(
        parse_bench_vars("X=a=b"),
        vec![("X".to_string(), "a=b".to_string())]
    );
    assert!(std::panic::catch_unwind(|| parse_bench_vars("bad")).is_err());
    assert!(std::panic::catch_unwind(|| parse_bench_vars("ADMIN_TOKEN=x")).is_err());
    assert!(std::panic::catch_unwind(|| parse_bench_vars("VELMORA_KEK_2=x")).is_err());
    assert!(std::panic::catch_unwind(|| parse_bench_vars("ADMIN_READ_TOKEN=x")).is_err());
    assert!(std::panic::catch_unwind(|| parse_bench_vars("E2_SECRET_ACCESS_KEY=x")).is_err());
    assert!(std::panic::catch_unwind(|| parse_bench_vars("GET_FANOUT_BYTES=8388608")).is_err());
}

// ---------------------------------------------------------------------------
// Scenario sizes
// ---------------------------------------------------------------------------

struct Scale {
    big: usize,
    part: usize,
    parts: usize,
    small: usize,
    smalls: usize,
    mid: usize,
    mids: usize,
    sliced: usize,
    tiny: usize,
    range: usize,
}

const FULL: Scale = Scale {
    big: 16 * MIB,
    part: 16 * MIB,
    parts: 5,
    small: 4 * 1024,
    smalls: 10,
    mid: MIB,
    mids: 4,
    sliced: 64 * MIB,
    tiny: 1000,
    range: MIB,
};

const SMOKE: Scale = Scale {
    big: 2 * MIB,
    part: 5 * MIB,
    parts: 2,
    small: 4 * 1024,
    smalls: 2,
    mid: 256 * 1024,
    mids: 1,
    sliced: 0,
    tiny: 12,
    range: 64 * 1024,
};

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

struct Bench {
    _server: TestNntpServer,
    bridge: Rc<BenchBridge>,
    hub: Rc<Hub>,
    signer: Signer,
    vars: BTreeMap<String, String>,
    /// What `VELMORA_BENCH_VARS` changed for this run.
    bench_vars: Vec<(String, String)>,
    /// Distinct extents, plaintext bytes and objects, by class.
    classes: BTreeMap<String, (u64, u64, u64)>,
    /// The queue delivers late: see [`LATE_SECS`].
    late: bool,
}

/// Deterministic incompressible bytes.
fn bytes(seed: u64, len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(len + 32);
    let mut block: [u8; 32] = Sha256::digest(seed.to_le_bytes()).into();
    while out.len() < len {
        out.extend_from_slice(&block);
        block = Sha256::digest(block).into();
    }
    out.truncate(len);
    out
}

impl Bench {
    async fn new(trace: Option<File>, late: bool) -> Bench {
        let mut cfg = ServerConfig::for_test();
        cfg.group = GROUP.to_string();
        cfg.users.clear();
        for user in ["poster", "reader1", "reader3"] {
            cfg.users.insert(
                user.to_string(),
                UserConfig {
                    password: PASS.to_string(),
                    max_connections: 16,
                },
            );
        }
        let server = TestNntpServer::spawn(cfg).await;

        let mut vars = production_vars();
        for (k, v) in overrides(&server) {
            vars.insert(k.to_string(), v);
        }
        let bench_vars = parse_bench_vars(&std::env::var("VELMORA_BENCH_VARS").unwrap_or_default());
        for (k, v) in &bench_vars {
            vars.insert(k.clone(), v.clone());
        }
        let asked = RefCell::new(std::collections::BTreeSet::new());
        let cfg = BridgeConfig::from_vars(|k| {
            asked.borrow_mut().insert(k.to_string());
            vars.get(k).cloned()
        })
        .expect("bench configuration");
        // A BENCH_VARS key the configuration never reads changed nothing:
        // a typo, or a variable the measured commit does not have.
        let asked = asked.into_inner();
        for (k, _) in &bench_vars {
            assert!(
                asked.contains(k),
                "VELMORA_BENCH_VARS: {k} is not read by this commit's configuration"
            );
        }

        let hub = Rc::new(Hub::default());
        hub.set("setup");
        let sql = RusqliteSql::with_schema().expect("schema");
        sql.meter_writes().expect("write meter");
        let bridge = Rc::new(Bridge {
            catalog: SqlCatalog::new(MeterSql {
                inner: sql,
                hub: Rc::clone(&hub),
            }),
            safety: MeterBlobs {
                inner: MemBlobStore::new(),
                safety: true,
                hub: Rc::clone(&hub),
            },
            cache: MeterBlobs {
                inner: MemBlobStore::new(),
                safety: false,
                hub: Rc::clone(&hub),
            },
            nntp: MeterNntp {
                hub: Rc::clone(&hub),
            },
            jobs: MeterJobs {
                inner: FakeJobs::new(),
                hub: Rc::clone(&hub),
            },
            kek: TestKek::new(),
            clock: FixedClock::new(T0),
            budget: ByteBudget::new(cfg.inflight_budget_bytes),
            cfg,
        });
        // The schema is in place before the trace starts: the replay
        // applies the same migrations itself.
        *hub.trace.borrow_mut() = trace.map(BufWriter::new);

        // One disposable bucket and one read-write key, as the admin API
        // makes them.
        // A secret drawn fresh for each test thread (the shared helper).
        let secret = service_support::secret();
        let mut rng = SystemRng;
        let id = BucketId::mint([7u8; 8]);
        let bdk = DataKey::generate(&mut rng).expect("data key");
        let (kek_version, wrapped) = wrap_bdk(&bridge.kek, &id, &bdk, &mut rng).expect("wrap bdk");
        let bucket = Bucket {
            id: id.clone(),
            name: "bench".to_string(),
            owner: "owner".to_string(),
            bdk_wrapped: wrapped.to_vec(),
            kek_version,
            disposable: true,
            created_at: T0,
        };
        bridge.catalog.create_bucket(&bucket).await.expect("bucket");
        let (kek_version, secret_wrapped) =
            wrap_secret(&bridge.kek, AKID, secret.as_bytes(), &mut rng).expect("wrap secret");
        bridge
            .catalog
            .create_access_key(&AccessKeyRow {
                access_key_id: AKID.to_string(),
                principal: "bench".to_string(),
                secret_wrapped,
                kek_version,
                status: KeyStatus::Active,
                created_at: T0,
            })
            .await
            .expect("key");
        bridge
            .catalog
            .put_grant(AKID, &id, Perm::Rw)
            .await
            .expect("grant");

        Bench {
            _server: server,
            bridge,
            hub,
            signer: Signer::new(AKID, secret),
            vars,
            bench_vars,
            classes: BTreeMap::new(),
            late,
        }
    }

    fn sql_rows(&self, sql: &str) -> Vec<(String, i64)> {
        self.bridge.catalog.sql.inner.with_conn(|c| {
            let mut stmt = c.prepare(sql).expect("bench query");
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .expect("bench query")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("bench rows");
            rows
        })
    }

    fn sql_count(&self, sql: &str) -> i64 {
        self.bridge
            .catalog
            .sql
            .inner
            .with_conn(|c| c.query_row(sql, [], |r| r.get(0)))
            .expect("count")
    }

    /// One S3 request under `label`, signed at the rig's clock.
    async fn s3(
        &self,
        label: &str,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Resp {
        let raw = if key.is_empty() {
            "/bench".to_string()
        } else {
            path("bench", key)
        };
        let req = self
            .signer
            .sign(self.bridge.clock.now(), method, &raw, query, extra, body);
        self.hub.set(&format!("op:{label}"));
        *self
            .hub
            .calls
            .borrow_mut()
            .entry(format!("op:{label}"))
            .or_default() += 1;
        let t = Instant::now();
        let resp = Rc::clone(&self.bridge).handle(req.into_request()).await;
        let resp = Resp::collect(resp).await;
        let us = t.elapsed().as_micros() as u64;
        self.hub.add(|c| {
            c.invocations += 1;
            c.wall_us += us;
        });
        self.hub.set("idle");
        resp
    }

    async fn expect(&self, label: &str, want: u16, r: Resp) -> Resp {
        if r.status != want {
            panic!(
                "BENCH FAILED at {label}: status {} (want {want}): {}",
                r.status,
                String::from_utf8_lossy(&r.body[..r.body.len().min(600)])
            );
        }
        r
    }

    async fn put(&self, label: &str, key: &str, body: Vec<u8>) {
        let r = self.s3(label, Method::Put, key, &[], &[], body).await;
        self.expect(label, 200, r).await;
    }

    async fn get(&self, label: &str, key: &str, range: Option<(usize, usize)>, len: usize) {
        let header = range.map(|(a, b)| format!("bytes={a}-{}", b - 1));
        let extra: Vec<(&str, &str)> = header.iter().map(|h| ("range", h.as_str())).collect();
        let r = self
            .s3(label, Method::Get, key, &[], &extra, Vec::new())
            .await;
        let want = if range.is_some() { 206 } else { 200 };
        let r = self.expect(label, want, r).await;
        assert_eq!(r.body.len(), len, "BENCH FAILED at {label}: body length");
    }

    async fn multipart(&self, key: &str, part: usize, parts: usize, seed: u64) -> u64 {
        let r = self
            .s3(
                "mpu_create",
                Method::Post,
                key,
                &[("uploads", "")],
                &[],
                Vec::new(),
            )
            .await;
        let r = self.expect("mpu_create", 200, r).await;
        let upload = r.values("UploadId").into_iter().next().expect("UploadId");
        let mut xml = String::from("<CompleteMultipartUpload>");
        for n in 1..=parts {
            let body = bytes(seed * 100 + n as u64, part);
            let num = n.to_string();
            let r = self
                .s3(
                    "mpu_upload_part",
                    Method::Put,
                    key,
                    &[("partNumber", &num), ("uploadId", &upload)],
                    &[],
                    body,
                )
                .await;
            let r = self.expect("mpu_upload_part", 200, r).await;
            let etag = r.header("etag").expect("part etag").to_string();
            xml.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
                etag.replace('"', "&quot;")
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let r = self
            .s3(
                "mpu_complete",
                Method::Post,
                key,
                &[("uploadId", &upload)],
                &[("content-type", "application/xml")],
                xml.into_bytes(),
            )
            .await;
        self.expect("mpu_complete", 200, r).await;
        (part * parts) as u64
    }

    /// The class of an extent job: the first segment of its object's key.
    fn job_label(&self, job: &Job) -> String {
        let (generation, stage) = match job {
            Job::Extent {
                generation, stage, ..
            } => (Some(generation), stage.as_str()),
            Job::Wake {
                generation, stage, ..
            } => (Some(generation), stage.as_str()),
            Job::Gc { .. } => (None, "gc"),
            Job::Evict { .. } => (None, "evict"),
            Job::Sweep { .. } => (None, "sweep"),
            _ => (None, "other"),
        };
        let Some(g) = generation else {
            return format!("stage:{stage}");
        };
        let class = self
            .bridge
            .catalog
            .sql
            .inner
            .with_conn(|c| {
                c.query_row(
                    "SELECT key FROM generations WHERE id = ?1",
                    [g.as_str()],
                    |r| r.get::<_, String>(0),
                )
            })
            .ok()
            .and_then(|k| k.split('/').next().map(str::to_string))
            .unwrap_or_else(|| "gone".to_string());
        format!("stage:{class}:{stage}")
    }

    async fn run_job(&self, job: &Job, redelivery: bool) -> JobOutcome {
        let label = self.job_label(job);
        self.hub.set(&label);
        *self.hub.calls.borrow_mut().entry(label).or_default() += 1;
        let t = Instant::now();
        let outcome = self.bridge.run_job(job).await;
        let us = t.elapsed().as_micros() as u64;
        self.hub.add(|c| {
            c.invocations += 1;
            c.wall_us += us;
            c.queue_redeliveries += u64::from(redelivery);
        });
        self.hub.set("idle");
        outcome
    }

    async fn cron(&self) {
        self.cron_as("stage:cron").await;
    }

    async fn cron_as(&self, label: &str) {
        self.hub.set(label);
        *self
            .hub
            .calls
            .borrow_mut()
            .entry(label.to_string())
            .or_default() += 1;
        let t = Instant::now();
        self.bridge.dispatch().await.expect("dispatch");
        let us = t.elapsed().as_micros() as u64;
        self.hub.add(|c| {
            c.invocations += 1;
            c.wall_us += us;
        });
        self.hub.set("idle");
    }

    fn open_rows(&self) -> i64 {
        self.sql_count("SELECT count(*) FROM outbox WHERE stage IN ('post', 'verify')")
    }

    fn outbox_dump(&self) -> String {
        format!(
            "{:?}",
            self.sql_rows("SELECT stage, count(*) FROM outbox GROUP BY stage")
        )
    }

    /// Queued jobs run in turn, delays honoured by moving the clock, and
    /// the dispatcher on simulated cron ticks, until no outbox row is in
    /// `post` or `verify` (the pump of `tests/slice.rs`).
    async fn pump(&self) {
        if self.late {
            return self.pump_late().await;
        }
        let b = &self.bridge;
        let mut pending: Vec<(UnixMs, Job, bool)> = Vec::new();
        for _ in 0..MAX_ROUNDS {
            assert_eq!(
                self.sql_count("SELECT count(*) FROM outbox WHERE stage = 'dead'"),
                0,
                "BENCH FAILED: dead outbox rows: {}",
                self.outbox_dump()
            );
            if self.open_rows() == 0 {
                return;
            }
            let now = b.clock.now();
            for s in b.jobs.inner.take() {
                pending.push((now.plus_secs(s.delay_secs), s.job, false));
            }
            let (due, later): (Vec<_>, Vec<_>) =
                pending.into_iter().partition(|(t, _, _)| *t <= now);
            pending = later;
            if due.is_empty() {
                match pending.iter().map(|(t, _, _)| *t).min() {
                    Some(t) if t <= now.plus_secs(CRON_SECS) => b.clock.set(t),
                    _ => {
                        b.clock.advance_secs(CRON_SECS);
                        self.cron().await;
                    }
                }
                continue;
            }
            for (_, job, redelivery) in due {
                if let JobOutcome::Retry { delay_secs } = self.run_job(&job, redelivery).await {
                    pending.push((now.plus_secs(delay_secs), job, true));
                }
            }
        }
        panic!("BENCH FAILED: outbox not drained: {}", self.outbox_dump());
    }

    /// The pump with a late queue: the dispatcher runs every `CRON_SECS`
    /// whatever is queued, and a message (a retried one too) is delivered
    /// `LATE_SECS` after it is due. So every row a handler left due is
    /// seen by a dispatcher run before the handler's own job arrives: the
    /// state of a queue with a backlog.
    async fn pump_late(&self) {
        let b = &self.bridge;
        let mut pending: Vec<(UnixMs, Job, bool)> = Vec::new();
        let mut next_cron = b.clock.now().plus_secs(CRON_SECS);
        for _ in 0..10 * MAX_ROUNDS {
            assert_eq!(
                self.sql_count("SELECT count(*) FROM outbox WHERE stage = 'dead'"),
                0,
                "BENCH FAILED: dead outbox rows: {}",
                self.outbox_dump()
            );
            let now = b.clock.now();
            for s in b.jobs.inner.take() {
                pending.push((now.plus_secs(s.delay_secs + LATE_SECS), s.job, false));
            }
            if self.open_rows() == 0 {
                // What is still queued: a second message for a row that
                // is past its stage is delivered now (it finds nothing);
                // the rest goes back to the queue for the next phase.
                for (at, job, redelivery) in pending {
                    let open = matches!(&job, Job::Extent { stage, .. }
                        if matches!(stage, OutboxStage::Post | OutboxStage::Verify));
                    if open {
                        self.run_job(&job, redelivery).await;
                    } else {
                        let left = u32::try_from((at.0 - now.0).max(0) / 1000).expect("delay");
                        // (A wake-up that comes early sends itself on.)
                        let left = left.min(MAX_QUEUE_DELAY_SECS);
                        b.jobs.inner.send(&job, left).await.expect("requeue");
                    }
                }
                return;
            }
            match pending.iter().map(|(t, _, _)| *t).min() {
                Some(t) if t < next_cron => {
                    let now = t.max(now);
                    b.clock.set(now);
                    let (due, later): (Vec<_>, Vec<_>) =
                        pending.into_iter().partition(|(t, _, _)| *t <= now);
                    pending = later;
                    for (_, job, redelivery) in due {
                        if let JobOutcome::Retry { delay_secs } =
                            self.run_job(&job, redelivery).await
                        {
                            pending.push((now.plus_secs(delay_secs + LATE_SECS), job, true));
                        }
                    }
                }
                _ => {
                    b.clock.set(next_cron.max(now));
                    self.cron().await;
                    next_cron = next_cron.plus_secs(CRON_SECS);
                }
            }
        }
        panic!("BENCH FAILED: outbox not drained: {}", self.outbox_dump());
    }

    /// Cron runs (charged to `cron_label`) and the jobs they send, until
    /// `done`. The release phase charges its dispatcher runs to ingest
    /// (`stage:cron`), the delete phase to `stage:cron_gc`.
    async fn ticks(&self, what: &str, cron_label: &str, done: impl Fn(&Bench) -> bool) {
        for _ in 0..60 {
            if done(self) {
                return;
            }
            // Jobs already queued (the last verify round's release wakes,
            // due after the clock jump) are delivered before the
            // dispatcher runs, so it does not send their work again. A
            // late queue delivers them after it.
            if !self.late {
                for sent in self.bridge.jobs.inner.take() {
                    self.run_job(&sent.job, false).await;
                }
            }
            if done(self) {
                return;
            }
            self.cron_as(cron_label).await;
            for sent in self.bridge.jobs.inner.take() {
                self.run_job(&sent.job, false).await;
            }
            self.bridge.clock.advance_secs(CRON_SECS);
        }
        panic!("BENCH FAILED: {what} not done: {}", self.outbox_dump());
    }

    fn note_class(&mut self, class: &str, objects: u64) {
        let (n, size): (i64, i64) = self.bridge.catalog.sql.inner.with_conn(|c| {
            c.query_row(
                &format!(
                    "SELECT count(DISTINCT x.extent_id), IFNULL(SUM(e.plain_size), 0) FROM \
                     (SELECT ge.extent_id FROM generation_extents ge JOIN generations g \
                      ON g.id = ge.generation_id WHERE g.key LIKE '{class}/%' \
                      UNION SELECT e.id FROM extents e JOIN generations g \
                      ON g.id = e.generation_id WHERE g.key LIKE '{class}/%') x \
                     JOIN extents e ON e.id = x.extent_id"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("class extents")
        });
        self.classes
            .insert(class.to_string(), (n as u64, size as u64, objects));
    }
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

async fn scenario(s: &Scale, trace: Option<File>, late: bool) -> Bench {
    let mut b = Bench::new(trace, late).await;
    let big_parts = s.part * s.parts;

    // Ingest. `big/`: whole extents (PutObject and a multipart upload);
    // `mix/`: small and mid objects and a sliced PutObject; `tiny/`: the
    // keys of the listing.
    b.put("put_big", "big/p0", bytes(1, s.big)).await;
    b.put("put_big", "big/p1", bytes(2, s.big)).await;
    b.multipart("big/mpu", s.part, s.parts, 3).await;
    b.note_class("big", 3);
    for i in 0..s.smalls {
        b.put(
            "put_small",
            &format!("mix/s{i}"),
            bytes(10 + i as u64, s.small),
        )
        .await;
    }
    for i in 0..s.mids {
        b.put("put_mid", &format!("mix/m{i}"), bytes(30 + i as u64, s.mid))
            .await;
    }
    let mut mix_objects = (s.smalls + s.mids) as u64;
    if s.sliced > 0 {
        b.put("put_sliced", "mix/sliced", bytes(50, s.sliced)).await;
        mix_objects += 1;
    }
    b.note_class("mix", mix_objects);
    for i in 0..s.tiny {
        b.put(
            "put_tiny",
            &format!("tiny/{i:05}"),
            bytes(1000 + i as u64, 100),
        )
        .await;
    }
    b.note_class("tiny", s.tiny as u64);

    // Metadata reads while everything is still pinned.
    for i in 0..s.mids.max(1) {
        let key = if s.mids > 0 {
            format!("mix/m{i}")
        } else {
            "big/p0".into()
        };
        let r = b.s3("head", Method::Head, &key, &[], &[], Vec::new()).await;
        b.expect("head", 200, r).await;
    }
    // One page: S3 answers at most 1,000 keys.
    let page = s.tiny.min(1000);
    let max_keys = page.to_string();
    for _ in 0..2 {
        let r = b
            .s3(
                "list_1k",
                Method::Get,
                "",
                &[
                    ("list-type", "2"),
                    ("prefix", "tiny/"),
                    ("max-keys", &max_keys),
                ],
                &[],
                Vec::new(),
            )
            .await;
        let r = b.expect("list_1k", 200, r).await;
        assert_eq!(r.values("Key").len(), page, "BENCH FAILED: list_1k keys");
    }
    for _ in 0..2 {
        let r = b
            .s3(
                "list_delimiter",
                Method::Get,
                "",
                &[("list-type", "2"), ("delimiter", "/")],
                &[],
                Vec::new(),
            )
            .await;
        b.expect("list_delimiter", 200, r).await;
    }
    let r = b
        .s3(
            "copy_big",
            Method::Put,
            "big/copy",
            &[],
            &[("x-amz-copy-source", "/bench/big/p0")],
            Vec::new(),
        )
        .await;
    // SERVER_SIDE_COPY=off (a BENCH_VARS run) answers 501 NotImplemented.
    let copy_status = if b.vars["SERVER_SIDE_COPY"] == "on" {
        200
    } else {
        501
    };
    b.expect("copy_big", copy_status, r).await;
    // A GET before the post: served from the pinned safety copy.
    b.get("get_pinned_big", "big/p0", None, s.big).await;

    // Post and verify, then the release after SAFETY_MIN_AGE_SECS.
    b.pump().await;
    // The validated value (the reader trims it), widened before the sum.
    let min_age = u64::from(b.bridge.cfg.safety_min_age_secs);
    b.bridge
        .clock
        .advance_secs(u32::try_from(min_age + 600).expect("min age + 600 s"));
    b.ticks("release", "stage:cron", |b| {
        b.sql_count("SELECT count(*) FROM outbox WHERE stage <> 'done'") == 0
    })
    .await;

    // Hot reads: the released copy is still in R2 until the hot tier
    // evicts it.
    for _ in 0..2 {
        b.get("get_hot_big", "big/p0", None, s.big).await;
    }
    for i in 0..4 {
        let start = (i * big_parts / 4) / 2;
        b.get(
            "get_hot_range",
            "big/mpu",
            Some((start, start + s.range)),
            s.range,
        )
        .await;
    }
    if s.mids > 0 {
        for i in 0..s.mids {
            b.get("get_hot_mid", &format!("mix/m{i}"), None, s.mid)
                .await;
        }
    }

    // Evict everything evictable, then cold reads from Usenet, then the
    // same read again from the cache it filled.
    b.hub.set("stage:evict");
    // The largest integer D1 takes (JavaScript's safe range).
    let all = (1u64 << 53) - 1;
    b.bridge
        .catalog
        .hot_drain_set(all)
        .await
        .expect("drain set");
    let t = Instant::now();
    b.bridge.evict_batch(all).await.expect("evict");
    let us = t.elapsed().as_micros() as u64;
    b.hub.add(|c| {
        c.invocations += 1;
        c.wall_us += us;
    });
    *b.hub
        .calls
        .borrow_mut()
        .entry("stage:evict".into())
        .or_default() += 1;
    b.hub.set("idle");
    // A drain goes on in steps, each one a job the step before sent.
    for _ in 0..MAX_ROUNDS {
        let sent = b.bridge.jobs.inner.take();
        if sent.is_empty() {
            break;
        }
        for s in sent {
            b.run_job(&s.job, false).await;
        }
    }
    assert_eq!(
        b.sql_count(
            "SELECT count(*) FROM extents WHERE hot_cache_bytes > 0 OR (hot_safety_bytes > 0 \
             AND safety_state NOT IN ('held', 'releasing'))"
        ),
        0,
        "BENCH FAILED: eviction left released copies in SAFETY"
    );
    b.get("get_cold_big", "big/p1", None, s.big).await;
    let start = big_parts / 2;
    b.get(
        "get_cold_range",
        "big/mpu",
        Some((start, start + s.range)),
        s.range,
    )
    .await;
    if s.mids > 0 {
        b.get("get_cold_mid", "mix/m0", None, s.mid).await;
    }
    b.get("get_cache_big", "big/p1", None, s.big).await;

    // Deletes, then the sweep of what they left.
    for i in 0..s.smalls {
        let r = b
            .s3(
                "delete_small",
                Method::Delete,
                &format!("mix/s{i}"),
                &[],
                &[],
                Vec::new(),
            )
            .await;
        b.expect("delete_small", 204, r).await;
    }
    for key in ["big/p1", "big/mpu"] {
        let r = b
            .s3("delete_big", Method::Delete, key, &[], &[], Vec::new())
            .await;
        b.expect("delete_big", 204, r).await;
    }
    b.bridge.clock.advance_secs(30 * DAY);
    let now = b.bridge.clock.now().0;
    // GC_MODE=off (a BENCH_VARS run) never sends a GC job: nothing to wait for.
    if b.vars["GC_MODE"] != "off" {
        b.ticks("gc", "stage:cron_gc", move |b| {
            b.sql_count(&format!(
                "SELECT count(*) FROM gc WHERE done_at IS NULL AND due_at <= {now}"
            )) == 0
        })
        .await;
    }
    // Cron runs with nothing due: the fixed cost of the dispatcher, which
    // grows with the catalogue only through what its queries read.
    for _ in 0..3 {
        b.bridge.clock.advance_secs(CRON_SECS);
        b.cron_as("stage:cron_idle").await;
        // Whatever it sends is charged to it too.
        let sent = b.bridge.jobs.inner.take();
        b.hub.set("stage:cron_idle");
        for s in sent {
            b.bridge.run_job(&s.job).await;
            b.hub.add(|c| c.invocations += 1);
        }
        b.hub.set("idle");
    }
    if let Some(out) = b.hub.trace.borrow_mut().as_mut() {
        out.flush().expect("trace flush");
    }
    b
}

fn report(b: &Bench, scale: &str) -> serde_json::Value {
    let keep = [
        "ENVIRONMENT",
        "MAX_EXTENT_BYTES",
        "MAX_PUT_BYTES",
        "REQUIRED_BACKBONES",
        "SAFETY_MIN_AGE_SECS",
        "RELEASE_AT_VERIFY",
        "VERIFY_DELAY_SECS",
        "VERIFY_MODE",
        "PACKED_PLANS",
        "POST_SOCKETS",
        "COLD_SOCKETS",
        "GC_MODE",
        "HOT_CAP_BYTES",
        "SERVER_SIDE_COPY",
        "GET_FANOUT_BYTES",
        "INTENT_SWEEP",
        "PARITY",
    ];
    let vars: BTreeMap<&str, &String> = keep
        .iter()
        .copied()
        .chain(b.bench_vars.iter().map(|(k, _)| k.as_str()))
        .filter_map(|k| b.vars.get(k).map(|v| (k, v)))
        .collect();
    let bench_vars: BTreeMap<&String, &String> = b.bench_vars.iter().map(|(k, v)| (k, v)).collect();
    let classes: BTreeMap<&String, serde_json::Value> = b
        .classes
        .iter()
        .map(|(k, (n, size, objects))| {
            (
                k,
                serde_json::json!({"extents": n, "plain_bytes": size, "objects": objects}),
            )
        })
        .collect();
    // Bytes in use in the catalogue (pages less their free part).
    let used = b.sql_count("SELECT SUM(pgsize - unused) FROM dbstat");
    let extents = b.sql_count("SELECT count(*) FROM extents");
    serde_json::json!({
        "scale": scale,
        "vars": vars,
        "bench_vars": bench_vars,
        "late_queue_secs": if b.late { LATE_SECS } else { 0 },
        "classes": classes,
        "calls": *b.hub.calls.borrow(),
        "counts": *b.hub.counts.borrow(),
        "catalogue_bytes": {
            "total": used,
            "per_extent": used / extents.max(1),
        },
        "catalogue_rows": {
            "extents": b.sql_count("SELECT count(*) FROM extents"),
            "articles": b.sql_count("SELECT count(*) FROM articles"),
            "verifications": b.sql_count("SELECT count(*) FROM verifications"),
            "outbox": b.sql_count("SELECT count(*) FROM outbox"),
        },
    })
}

fn sanity(b: &Bench) {
    let counts = b.hub.counts.borrow();
    let sum = |f: fn(&Counts) -> u64| counts.values().map(f).sum::<u64>();
    assert!(sum(|c| c.d1_rows_written) > 0, "no D1 write metered");
    assert!(sum(|c| c.r2_class_a) > 0, "no R2 put metered");
    assert!(sum(|c| c.nntp_posts) > 0, "no post metered");
    assert!(sum(|c| c.nntp_bodies) > 0, "no cold read metered");
    assert!(sum(|c| c.queue_messages) > 0, "no queue message metered");
    // RELEASE_AT_VERIFY=on without a minimum age: the verify job releases
    // (its figures hold the release), and no release job runs. Read from
    // the variables, so a commit from before the switch is measured too.
    let var = |k: &str| b.vars.get(k).map(|v| v.trim());
    let at_verify =
        var("RELEASE_AT_VERIFY") == Some("on") && var("SAFETY_MIN_AGE_SECS") == Some("0");
    let release = (!at_verify).then_some("stage:big:release");
    for label in [
        "op:get_cold_big",
        "op:put_big",
        "stage:big:post",
        "stage:big:verify",
    ]
    .into_iter()
    .chain(release)
    {
        assert!(
            counts.contains_key(label),
            "no figures for {label}: {:?}",
            counts.keys()
        );
    }
    if at_verify {
        assert!(
            !counts.contains_key("stage:big:release"),
            "a release job ran under RELEASE_AT_VERIFY=on without a minimum age"
        );
    }
    // A cold read comes from Usenet and refills the cache; the read
    // after it does not touch Usenet.
    assert!(counts["op:get_cold_big"].nntp_bodies > 0);
    assert_eq!(counts["op:get_cache_big"].nntp_bodies, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn bench_counts_smoke() {
    let b = scenario(&SMOKE, None, false).await;
    sanity(&b);
    let json = report(&b, "smoke");
    assert!(
        json["counts"]["op:put_big"]["d1_calls"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
}

/// With a late queue (every message delivered after a dispatcher run),
/// the dispatcher does not send again what a handler has sent: no second
/// message (and so no mark, which it writes per message sent) and no
/// claim that finds nothing.
#[tokio::test(flavor = "current_thread")]
async fn bench_counts_late_queue_smoke() {
    let b = scenario(&SMOKE, None, true).await;
    sanity(&b);
    let counts = b.hub.counts.borrow();
    let cron = &counts["stage:cron"];
    assert_eq!(cron.queue_messages, 0, "the dispatcher sent a job again");
    let empty: u64 = counts.values().map(|c| c.outbox_empty_claims).sum();
    assert_eq!(empty, 0, "a claim found nothing to do");
}

/// The full run: `VELMORA_BENCH_OUT=<dir> cargo test -p velmora-bridge
/// --test bench_counts -- --ignored` (what `bench/run-local.sh` does).
#[tokio::test(flavor = "current_thread")]
#[ignore = "benchmark: run by bench/run-local.sh"]
async fn bench_counts_full() {
    let out =
        std::env::var("VELMORA_BENCH_OUT").expect("VELMORA_BENCH_OUT names the output directory");
    let dir = std::path::Path::new(&out);
    std::fs::create_dir_all(dir).expect("output directory");
    let trace = File::create(dir.join("d1-trace.jsonl")).expect("trace file");
    // VELMORA_BENCH_TINY: more (or fewer) keys under `tiny/`, to see how
    // a figure grows with the size of the catalogue.
    let tiny = std::env::var("VELMORA_BENCH_TINY")
        .ok()
        .map(|v| v.parse().expect("VELMORA_BENCH_TINY is a count"))
        .unwrap_or(FULL.tiny);
    let scale = Scale { tiny, ..FULL };
    // VELMORA_BENCH_LATE_QUEUE=1: every message is delivered after a
    // dispatcher run (`bench/run-local.sh --late-queue`).
    let late = std::env::var("VELMORA_BENCH_LATE_QUEUE").is_ok_and(|v| v == "1");
    let b = scenario(&scale, Some(trace), late).await;
    sanity(&b);
    let json = report(&b, "full");
    std::fs::write(
        dir.join("counts.json"),
        serde_json::to_string_pretty(&json).expect("json"),
    )
    .expect("counts.json");
    println!("bench: wrote {}", dir.display());
}
