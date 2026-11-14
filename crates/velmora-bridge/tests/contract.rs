//! Contract tests for the walking skeleton (frozen with the contract):
//!
//! - `RusqliteSql::batch` is all-or-nothing, and the `tx_guard` CHECK maps
//!   to `GuardFailed`;
//! - `BridgeConfig::from_vars` loads the documented `wrangler.toml` vars
//!   and fails closed on every missing or unsafe value;
//! - `UnixMs` / `UnixSecs` conversions at fixed times;
//! - the D1 schema applies cleanly and agrees with the row types;
//! - every port method is callable through the testkit.

use std::collections::BTreeMap;
use std::rc::Rc;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use velmora_bridge::config::{
    BridgeConfig, ConfigError, Environment, GcMode, KekRing, Maintenance, DEFAULT_HOT_CAP_BYTES,
    DEFAULT_POST_SOCKETS, MAX_EXTENT_BYTES_LIMIT,
};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{
    FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek, MIGRATION_0001,
};
use velmora_bridge::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 2025-11-13T00:00:00.123Z.
const T0: UnixMs = UnixMs(1_762_992_000_123);

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

fn count(db: &RusqliteSql, table: &str) -> i64 {
    db.with_conn(|c| {
        c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    })
}

/// Seeds one bucket row.
fn seed_bucket(db: &RusqliteSql, id: &str, name: &str) {
    db.with_conn(|c| {
        c.execute(
            "INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,disposable,created_at) \
             VALUES (?1,?2,'p',x'00',1,1,?3)",
            (id, name, T0.0),
        )
        .unwrap()
    });
}

// ---------------------------------------------------------------------------
// RusqliteSql::batch atomicity
// ---------------------------------------------------------------------------

const GUARD_BUCKET_EXISTS: &str =
    "INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM buckets WHERE id = ?1)";
const INSERT_GC_MARKER: &str =
    "INSERT INTO gc(extent_id, action, due_at) VALUES (?1, 'delete_cache', ?2)";

#[tokio::test(flavor = "current_thread")]
async fn batch_commits_when_guard_holds() {
    let db = RusqliteSql::with_schema().unwrap();
    seed_bucket(&db, "b_0000000000000001", "one");
    let changed = db
        .batch(vec![
            (GUARD_BUCKET_EXISTS, vec![text("b_0000000000000001")]),
            (INSERT_GC_MARKER, vec![text("x_a"), SqlValue::Int(T0.0)]),
            (INSERT_GC_MARKER, vec![text("x_b"), SqlValue::Int(T0.0)]),
        ])
        .await
        .unwrap();
    assert_eq!(changed, vec![0, 1, 1]);
    assert_eq!(count(&db, "gc"), 2);
    assert_eq!(count(&db, "tx_guard"), 0, "a held guard inserts nothing");
}

#[tokio::test(flavor = "current_thread")]
async fn batch_guard_failure_rolls_back_everything() {
    let db = RusqliteSql::with_schema().unwrap();
    // A statement before the guard and one after it: neither may survive.
    let err = db
        .batch(vec![
            (
                INSERT_GC_MARKER,
                vec![text("x_before"), SqlValue::Int(T0.0)],
            ),
            (GUARD_BUCKET_EXISTS, vec![text("b_missing")]),
            (INSERT_GC_MARKER, vec![text("x_after"), SqlValue::Int(T0.0)]),
        ])
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::GuardFailed), "{err:?}");
    assert_eq!(count(&db, "gc"), 0);
    assert_eq!(count(&db, "tx_guard"), 0);
    // The connection is usable afterwards (no transaction left open).
    db.exec(INSERT_GC_MARKER, &[text("x_later"), SqlValue::Int(T0.0)])
        .await
        .unwrap();
    assert_eq!(count(&db, "gc"), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn batch_statement_failure_rolls_back_and_is_not_a_guard_loss() {
    let db = RusqliteSql::with_schema().unwrap();
    seed_bucket(&db, "b_0000000000000001", "one");
    // Third statement violates the UNIQUE bucket name.
    let insert_bucket = "INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) \
                         VALUES (?1,?2,'p',x'00',1,?3)";
    let err = db
        .batch(vec![
            (INSERT_GC_MARKER, vec![text("x_a"), SqlValue::Int(T0.0)]),
            (
                insert_bucket,
                vec![text("b_0000000000000002"), text("two"), SqlValue::Int(T0.0)],
            ),
            (
                insert_bucket,
                vec![text("b_0000000000000003"), text("one"), SqlValue::Int(T0.0)],
            ),
        ])
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Sql(_)), "{err:?}");
    assert_eq!(count(&db, "gc"), 0);
    assert_eq!(count(&db, "buckets"), 1);

    // A CHECK on another table is a plain SQL error, not a guard loss.
    let err = db
        .batch(vec![(
            "INSERT INTO gc(extent_id, action, due_at) VALUES ('x_c', 'bogus', 0)",
            vec![],
        )])
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Sql(_)), "{err:?}");
}

#[test]
fn guard_violation_rule_matches_sqlite_and_d1_text() {
    assert!(is_tx_guard_violation("CHECK constraint failed: ok = 1"));
    assert!(is_tx_guard_violation(
        "D1_ERROR: CHECK constraint failed: ok = 1: SQLITE_CONSTRAINT"
    ));
    assert!(!is_tx_guard_violation(
        "CHECK constraint failed: action IN ('delete_cache')"
    ));
    assert!(!is_tx_guard_violation(
        "UNIQUE constraint failed: buckets.name"
    ));
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// The real-data gate stays closed until the catalogue recovery drill lands.
const _: () = assert!(!REAL_DATA_READY, "real-data gate must stay closed");

/// `[vars]` and `[env.dev] vars = { … }` of the shipped `wrangler.toml`.
fn wrangler_vars() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../workers/s3-bridge/wrangler.toml"
    );
    let toml = std::fs::read_to_string(path).unwrap();
    let quoted = |s: &str| -> String {
        let s = s.trim();
        assert!(s.starts_with('"'), "unquoted value: {s}");
        s[1..s[1..].find('"').unwrap() + 1].to_string()
    };
    let (mut prod, mut dev) = (BTreeMap::new(), BTreeMap::new());
    let mut section = String::new();
    for line in toml.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if section == "[vars]" {
            if let Some((k, v)) = line.split_once('=') {
                prod.insert(k.trim().to_string(), quoted(v));
            }
        } else if section == "[env.dev]" {
            if let Some(inner) = line.strip_prefix("vars = {") {
                for pair in inner.trim_end_matches('}').split(',') {
                    let (k, v) = pair.split_once('=').unwrap();
                    dev.insert(k.trim().to_string(), quoted(v));
                }
            }
        }
    }
    assert!(
        !prod.is_empty() && !dev.is_empty(),
        "wrangler.toml shape changed"
    );
    (prod, dev)
}

const PROVIDER_TLS: &str = r#"[{"id":"p1","host":"nntp.invalid","port":563,"tls":true,"user":"u-fixture","pass":"p-fixture","backbone":"bb1","post":true,"read":true,"max_conns":2}]"#;
const PROVIDER_PLAIN: &str = r#"[{"id":"p1","host":"127.0.0.1","port":11119,"tls":false,"user":"testuser","pass":"testpass","backbone":"fake","post":true,"read":true,"max_conns":2}]"#;
const ADMIN_TOKEN_FIXTURE: &str = "admin-token-fixture-admin-token-fixture";

fn kek_b64(byte: u8, len: usize) -> String {
    base64::engine::general_purpose::STANDARD.encode(vec![byte; len])
}

/// The shipped prod `S3_HOST` is a placeholder that config refuses (see
/// `config_loads_from_documented_vars`); fixtures use a concrete host.
const PROD_HOST_FIXTURE: &str = "velmora-s3.example.workers.dev";

fn with_secrets(mut vars: BTreeMap<String, String>, providers: &str) -> BTreeMap<String, String> {
    if vars.get("S3_HOST").is_some_and(|h| h.contains('<')) {
        vars.insert("S3_HOST".into(), PROD_HOST_FIXTURE.into());
    }
    vars.insert("VELMORA_KEK_1".into(), kek_b64(0x11, 32));
    vars.insert("NNTP_PROVIDERS".into(), providers.into());
    vars.insert("ADMIN_TOKEN".into(), ADMIN_TOKEN_FIXTURE.into());
    vars
}

fn load(vars: &BTreeMap<String, String>) -> std::result::Result<BridgeConfig, ConfigError> {
    BridgeConfig::from_vars(|k| vars.get(k).cloned())
}

#[test]
fn config_loads_from_documented_vars() {
    let (prod, dev) = wrangler_vars();

    // Until deploy fills in the account subdomain, prod refuses to start.
    let mut shipped = with_secrets(prod.clone(), PROVIDER_TLS);
    shipped.insert("S3_HOST".into(), prod["S3_HOST"].clone());
    assert_eq!(
        load(&shipped).unwrap_err(),
        ConfigError::Invalid("S3_HOST".into())
    );

    let cfg = load(&with_secrets(prod, PROVIDER_TLS)).unwrap();
    assert_eq!(cfg.environment, Environment::Prod);
    assert_eq!(cfg.s3_host, PROD_HOST_FIXTURE);
    assert_eq!(cfg.required_backbones, 2);
    assert_eq!(cfg.max_extent_bytes, 16 * 1024 * 1024);
    assert_eq!(cfg.inflight_budget_bytes, 48 * 1024 * 1024);
    assert_eq!(cfg.safety_min_age_secs, 604_800);
    assert_eq!(cfg.verify_delay_secs, 120);
    assert_eq!(cfg.newsgroups, vec!["alt.binaries.test".to_string()]);
    assert_eq!(cfg.kek_active, 1);
    assert_eq!(cfg.gc_mode, GcMode::Off);
    assert_eq!(cfg.hot_cap_bytes, 100 * 1024 * 1024 * 1024);
    assert_eq!(cfg.hot_cap_bytes, DEFAULT_HOT_CAP_BYTES);
    assert_eq!(cfg.maintenance, Maintenance::Off);
    assert!(!cfg.server_side_copy);
    assert!(!cfg.dev_trust_http);
    assert_eq!(cfg.providers.len(), 1);
    // Production posts on eight sockets per job; the grace keeps its default.
    assert_eq!(cfg.post_sockets, 8);
    assert_eq!(cfg.propagation_grace_secs, 21_600);

    // The dev environment is complete on its own (envs do not inherit vars).
    let cfg = load(&with_secrets(dev.clone(), PROVIDER_PLAIN)).unwrap();
    assert_eq!(cfg.environment, Environment::Dev);
    assert!(cfg.is_dev());
    assert_eq!(cfg.required_backbones, 1);
    assert_eq!(cfg.safety_min_age_secs, 0);
    assert_eq!(cfg.verify_delay_secs, 1);
    assert_eq!(cfg.gc_mode, GcMode::Disposable);
    assert!(cfg.server_side_copy);
    // Absent or empty is the default; any other size is taken as given.
    assert_eq!(cfg.hot_cap_bytes, DEFAULT_HOT_CAP_BYTES);
    let mut sized = with_secrets(dev, PROVIDER_PLAIN);
    for (value, want) in [("", DEFAULT_HOT_CAP_BYTES), ("0", 0), (" 4096 ", 4096)] {
        sized.insert("HOT_CAP_BYTES".to_string(), value.to_string());
        assert_eq!(load(&sized).unwrap().hot_cap_bytes, want, "{value:?}");
    }
    assert!(cfg.dev_trust_http);
    assert!(!cfg.providers[0].tls);
}

#[test]
fn missing_secret_fails_closed() {
    let (prod, _) = wrangler_vars();
    let full = with_secrets(prod, PROVIDER_TLS);
    for name in full.keys() {
        let mut vars = full.clone();
        vars.remove(name);
        // The one setting with a default: without it the cap is 100 GiB.
        // No value of it can cost data, so there is nothing to fail closed.
        if name == "HOT_CAP_BYTES" {
            assert_eq!(load(&vars).unwrap().hot_cap_bytes, DEFAULT_HOT_CAP_BYTES);
            continue;
        }
        // Sockets per post job: absent or blank is the default of four.
        if name == "POST_SOCKETS" {
            assert_eq!(load(&vars).unwrap().post_sockets, DEFAULT_POST_SOCKETS);
            vars.insert(name.clone(), "  ".into());
            assert_eq!(load(&vars).unwrap().post_sockets, DEFAULT_POST_SOCKETS);
            continue;
        }
        assert_eq!(
            load(&vars).unwrap_err(),
            ConfigError::Missing(name.clone()),
            "removing {name}"
        );
        vars.insert(name.clone(), "  ".into());
        assert_eq!(
            load(&vars).unwrap_err(),
            ConfigError::Missing(name.clone()),
            "blank {name}"
        );
    }
}

#[test]
fn config_rejects_invalid_and_unsafe_values() {
    let (prod, dev) = wrangler_vars();
    let prod = with_secrets(prod, PROVIDER_TLS);
    let dev = with_secrets(dev, PROVIDER_PLAIN);
    let set = |base: &BTreeMap<String, String>, k: &str, v: &str| {
        let mut m = base.clone();
        m.insert(k.to_string(), v.to_string());
        load(&m).unwrap_err()
    };
    let invalid = |k: &str| ConfigError::Invalid(k.to_string());

    // Safety rules (the gate itself is pinned at compile time below).
    assert!(matches!(
        set(&prod, "GC_MODE", "full"),
        ConfigError::Refused(_)
    ));
    assert!(matches!(
        set(&dev, "GC_MODE", "full"),
        ConfigError::Refused(_)
    ));
    assert!(matches!(
        set(&prod, "REQUIRED_BACKBONES", "1"),
        ConfigError::Refused(_)
    ));
    assert!(matches!(
        set(&prod, "DEV_TRUST_HTTP", "1"),
        ConfigError::Refused(_)
    ));
    assert!(matches!(
        set(&prod, "NNTP_PROVIDERS", PROVIDER_PLAIN),
        ConfigError::Refused(_)
    ));

    // Optional settings: a value that is set must be valid.
    for (name, bad) in [
        ("POST_SOCKETS", "0"),
        ("POST_SOCKETS", "9"),
        ("POST_SOCKETS", "four"),
        ("PROPAGATION_GRACE_SECS", "-1"),
        ("PROPAGATION_GRACE_SECS", "6h"),
    ] {
        assert_eq!(set(&prod, name, bad), invalid(name), "{name}={bad}");
    }
    let mut tuned = prod.clone();
    tuned.insert("POST_SOCKETS".into(), "8".into());
    tuned.insert("PROPAGATION_GRACE_SECS".into(), "0".into());
    let cfg = load(&tuned).unwrap();
    assert_eq!((cfg.post_sockets, cfg.propagation_grace_secs), (8, 0));

    // Shape and range.
    assert_eq!(set(&prod, "ENVIRONMENT", "staging"), invalid("ENVIRONMENT"));
    assert_eq!(set(&prod, "GC_MODE", "on"), invalid("GC_MODE"));
    for bad in ["100GiB", "-1", "1.5", "9223372036854775808"] {
        assert_eq!(set(&prod, "HOT_CAP_BYTES", bad), invalid("HOT_CAP_BYTES"));
    }
    assert_eq!(set(&prod, "MAINTENANCE", "yes"), invalid("MAINTENANCE"));
    assert_eq!(
        set(&prod, "SERVER_SIDE_COPY", "1"),
        invalid("SERVER_SIDE_COPY")
    );
    assert_eq!(
        set(&dev, "DEV_TRUST_HTTP", "true"),
        invalid("DEV_TRUST_HTTP")
    );
    assert_eq!(
        set(&prod, "REQUIRED_BACKBONES", "0"),
        invalid("REQUIRED_BACKBONES")
    );
    assert_eq!(
        set(&prod, "REQUIRED_BACKBONES", "two"),
        invalid("REQUIRED_BACKBONES")
    );
    assert_eq!(
        set(&prod, "MAX_EXTENT_BYTES", "0"),
        invalid("MAX_EXTENT_BYTES")
    );
    assert_eq!(
        set(
            &prod,
            "MAX_EXTENT_BYTES",
            &(MAX_EXTENT_BYTES_LIMIT + 1).to_string()
        ),
        invalid("MAX_EXTENT_BYTES")
    );
    assert_eq!(
        set(&prod, "INFLIGHT_BUDGET_BYTES", "33554431"),
        invalid("INFLIGHT_BUDGET_BYTES")
    );
    assert_eq!(
        set(&prod, "SAFETY_MIN_AGE_SECS", "-1"),
        invalid("SAFETY_MIN_AGE_SECS")
    );
    assert_eq!(
        set(&prod, "NEWSGROUPS", "alt.binaries.test,"),
        invalid("NEWSGROUPS")
    );
    assert_eq!(set(&prod, "NEWSGROUPS", "Alt.Bad"), invalid("NEWSGROUPS"));
    assert_eq!(
        set(&prod, "VELMORA_KEK_ACTIVE", "0"),
        invalid("VELMORA_KEK_ACTIVE")
    );
    assert_eq!(
        set(&prod, "VELMORA_KEK_1", &kek_b64(0x11, 31)),
        invalid("VELMORA_KEK_1")
    );
    assert_eq!(
        set(&prod, "VELMORA_KEK_1", "not base64!"),
        invalid("VELMORA_KEK_1")
    );
    assert_eq!(set(&prod, "ADMIN_TOKEN", "short"), invalid("ADMIN_TOKEN"));
    assert_eq!(
        set(&prod, "NNTP_PROVIDERS", "[]"),
        invalid("NNTP_PROVIDERS")
    );
    assert_eq!(set(&prod, "NNTP_PROVIDERS", "{"), invalid("NNTP_PROVIDERS"));
    let unknown_field = PROVIDER_TLS.replace("\"max_conns\":2", "\"max_conns\":2,\"x\":1");
    assert_eq!(
        set(&prod, "NNTP_PROVIDERS", &unknown_field),
        invalid("NNTP_PROVIDERS")
    );
    let zero_conns = PROVIDER_TLS.replace("\"max_conns\":2", "\"max_conns\":0");
    assert_eq!(
        set(&prod, "NNTP_PROVIDERS", &zero_conns),
        invalid("NNTP_PROVIDERS")
    );
    let one = &PROVIDER_TLS[1..PROVIDER_TLS.len() - 1];
    assert_eq!(
        set(&prod, "NNTP_PROVIDERS", &format!("[{one},{one}]")),
        invalid("NNTP_PROVIDERS"),
        "duplicate provider ids"
    );
    let read_only = PROVIDER_TLS.replace("\"post\":true", "\"post\":false");
    assert_eq!(
        set(&prod, "NNTP_PROVIDERS", &read_only),
        invalid("NNTP_PROVIDERS")
    );

    // The active KEK version must exist.
    assert_eq!(
        set(&prod, "VELMORA_KEK_ACTIVE", "2"),
        ConfigError::Missing("VELMORA_KEK_2".into())
    );
}

#[test]
fn config_errors_and_debug_never_show_secret_values() {
    let (prod, _) = wrangler_vars();
    let vars = with_secrets(prod, PROVIDER_TLS);
    let cfg = load(&vars).unwrap();
    let dbg = format!("{cfg:?}");
    for secret in [
        "nntp.invalid",
        "u-fixture",
        "p-fixture",
        ADMIN_TOKEN_FIXTURE,
    ] {
        assert!(!dbg.contains(secret), "Debug leaks a secret value");
    }
    let kek = KekRing::from_vars(1, |k| vars.get(k).cloned()).unwrap();
    assert!(!format!("{kek:?}").contains(&kek_b64(0x11, 32)));
    assert_eq!(kek.active().0, 1);
    assert_eq!(kek.active().1.expose(), &[0x11; 32]);
    assert!(kek.version(2).is_none());

    let mut bad = vars.clone();
    bad.insert("VELMORA_KEK_1".into(), "c2VjcmV0LXZhbHVl".into());
    let msg = load(&bad).unwrap_err().to_string();
    assert_eq!(msg, "invalid VELMORA_KEK_1");
}

// ---------------------------------------------------------------------------
// Time newtypes (fixed instants)
// ---------------------------------------------------------------------------

#[test]
fn fixed_time_ms_secs_conversions() {
    assert_eq!(T0.secs(), UnixSecs(1_762_992_000));
    assert_eq!(T0.secs().ms(), UnixMs(1_762_992_000_000));
    assert_eq!(UnixMs(999).secs(), UnixSecs(0));
    assert_eq!(UnixMs(1000).secs(), UnixSecs(1));
    // Floor, not truncation: just before the epoch is second -1.
    assert_eq!(UnixMs(-1).secs(), UnixSecs(-1));
    assert_eq!(T0.plus_secs(120), UnixMs(1_762_992_120_123));
    assert_eq!(T0.plus_secs(604_800).secs(), UnixSecs(1_763_596_800));
    assert_eq!(T0.plus_ms(-123), UnixMs(1_762_992_000_000));
    assert_eq!(UnixMs(i64::MAX).plus_secs(1), UnixMs(i64::MAX));
    assert_eq!(UnixSecs(i64::MAX).ms(), UnixMs(i64::MAX));
    // Both serialize as bare JSON numbers.
    assert_eq!(serde_json::to_string(&T0).unwrap(), "1762992000123");
    assert_eq!(serde_json::to_string(&T0.secs()).unwrap(), "1762992000");
}

#[test]
fn ids_have_documented_shapes() {
    let g = GenerationId::mint(T0, [0xab; 8]);
    assert_eq!(g.as_str(), "g_0019a7a830c7babababababababab");
    assert_eq!(g.as_str().len(), 31);
    assert!(GenerationId::mint(T0, [0xff; 8]) < GenerationId::mint(T0.plus_ms(1), [0; 8]));
    assert_eq!(BucketId::mint([0x01; 8]).as_str(), "b_0101010101010101");
    let x = ExtentId::mint([0xcd; 13]);
    assert_eq!(x.as_str().len(), 28);
    assert_eq!(x.safety_key(), format!("x/{x}"));
    assert_eq!(x.cache_key(), format!("c/{x}"));
    assert_eq!(UploadId::mint([0xef; 16]).as_str().len(), 32);
}

#[test]
fn job_json_is_small_and_strict() {
    let job = Job::Extent {
        v: JOB_VERSION,
        extent: ExtentId::mint([0xff; 13]),
        generation: GenerationId::mint(T0, [0xff; 8]),
        stage: OutboxStage::Cancelled,
    };
    let json = job.to_json();
    assert!(json.len() < 200, "{} bytes", json.len());
    assert_eq!(Job::from_json(&json).unwrap(), job);
    let gc = Job::Gc { v: JOB_VERSION };
    assert_eq!(gc.to_json(), r#"{"t":"gc","v":1}"#);
    assert!(Job::from_json(r#"{"t":"gc","v":1,"x":0}"#).is_err());
    let evict = Job::Evict {
        v: JOB_VERSION,
        remaining: 4096,
    };
    assert_eq!(evict.to_json(), r#"{"t":"evict","v":1,"remaining":4096}"#);
    assert_eq!(Job::from_json(&evict.to_json()).unwrap(), evict);
    assert!(Job::from_json(r#"{"t":"evict","v":1}"#).is_err());
    assert!(Job::from_json(r#"{"t":"nope","v":1}"#).is_err());
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// `(table, column) -> CHECK IN list` from the migration text.
fn check_lists() -> BTreeMap<(String, String), Vec<String>> {
    let mut out = BTreeMap::new();
    let mut table = String::new();
    for line in MIGRATION_0001.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("CREATE TABLE ") {
            table = rest.split_whitespace().next().unwrap().to_string();
        }
        let Some(pos) = line.find("CHECK (") else {
            continue;
        };
        let check = &line[pos + "CHECK (".len()..];
        let Some((column, rest)) = check.split_once(" IN (") else {
            continue;
        };
        let list = rest.split(')').next().unwrap();
        let values = list
            .split(',')
            .map(|v| v.trim().trim_matches('\'').to_string())
            .collect();
        out.insert((table.clone(), column.trim().to_string()), values);
    }
    out
}

fn strs<T: Copy>(all: &[T], f: fn(T) -> &'static str) -> Vec<String> {
    all.iter().map(|v| f(*v).to_string()).collect()
}

#[test]
fn ddl_enums_match_row_types() {
    let lists = check_lists();
    let expect = [
        (
            "outbox",
            "stage",
            strs(OutboxStage::ALL, OutboxStage::as_str),
        ),
        (
            "extents",
            "safety_state",
            strs(SafetyState::ALL, SafetyState::as_str),
        ),
        (
            "extents",
            "state",
            strs(ExtentState::ALL, ExtentState::as_str),
        ),
        ("grants", "perm", strs(Perm::ALL, Perm::as_str)),
        (
            "access_keys",
            "status",
            strs(KeyStatus::ALL, KeyStatus::as_str),
        ),
        (
            "generations",
            "state",
            strs(GenerationState::ALL, GenerationState::as_str),
        ),
        (
            "articles",
            "state",
            strs(ArticleState::ALL, ArticleState::as_str),
        ),
        (
            "verifications",
            "result",
            strs(VerifyResult::ALL, VerifyResult::as_str),
        ),
        (
            "uploads",
            "state",
            strs(UploadState::ALL, UploadState::as_str),
        ),
        ("gc", "action", strs(GcAction::ALL, GcAction::as_str)),
    ];
    assert_eq!(
        lists.len(),
        expect.len(),
        "a CHECK list has no enum: {lists:?}"
    );
    for stage in OutboxStage::ALL {
        assert_eq!(OutboxStage::parse(stage.as_str()), Some(*stage));
    }
    assert_eq!(OutboxStage::parse("Post"), None);
    for (table, column, values) in expect {
        assert_eq!(
            lists.get(&(table.to_string(), column.to_string())),
            Some(&values),
            "{table}.{column}"
        );
    }
}

/// Inserts one complete row into every table with fixed millisecond
/// timestamps, then reads the times back unchanged. A renamed or retyped
/// column fails here.
#[tokio::test(flavor = "current_thread")]
async fn ddl_applies_cleanly_with_fixed_times() {
    let db = RusqliteSql::with_schema().unwrap();
    let tables: Vec<String> = db
        .query(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|r| match &r[0] {
            SqlValue::Text(t) => t.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        tables,
        [
            "access_keys",
            "articles",
            "buckets",
            "extents",
            "gc",
            "generation_extents",
            "generations",
            "grants",
            "meta",
            "objects",
            "outbox",
            "provider_health",
            "provider_permits",
            "scan_cursors",
            "tx_guard",
            "upload_parts",
            "uploads",
            "verifications",
        ]
    );

    let t = SqlValue::Int(T0.0);
    let blob = |n: usize| SqlValue::Blob(vec![7; n]);
    let i = SqlValue::Int;
    let rows: Vec<(&'static str, Vec<SqlValue>)> = vec![
        ("INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,disposable,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
         vec![text("b_1"), text("slice"), text("owner"), blob(73), i(1), i(1), t.clone()]),
        ("INSERT INTO access_keys(access_key_id,principal,secret_wrapped,kek_version,status,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
         vec![text("AKVL0000000000000001"), text("owner"), blob(73), i(1), text(KeyStatus::Active.as_str()), t.clone()]),
        ("INSERT INTO grants(access_key_id,bucket_id,perm) VALUES (?1,?2,?3)",
         vec![text("AKVL0000000000000001"), text("b_1"), text(Perm::Rw.as_str())]),
        ("INSERT INTO generations(id,bucket_id,key,state,size,etag,checksum_json,content_json,user_meta_json,extent_count,created_at,retired_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
         vec![text("g_1"), text("b_1"), text("a/k"), text(GenerationState::Live.as_str()), i(5), text("\"e\""), SqlValue::Null, text("{}"), text("{}"), i(1), t.clone(), SqlValue::Null]),
        ("INSERT INTO objects(bucket_id,key,generation_id) VALUES (?1,?2,?3)",
         vec![text("b_1"), text("a/k"), text("g_1")]),
        ("INSERT INTO extents(id,bucket_id,generation_id,state,seq,plain_offset,plain_size,cipher_size,media_header,key_mode,wrapped_file_key,plain_md5,plain_sha256,cipher_sha256,safety_state,article_count,plan_rev,last_verified_at,release_evidence,released_at,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
         vec![text("x_1"), text("b_1"), text("g_1"), text(ExtentState::Committed.as_str()), i(0), i(0), i(5), i(69), blob(48), i(1), blob(73), blob(16), blob(32), blob(32), text(SafetyState::Held.as_str()), i(1), i(1), t.clone(), SqlValue::Null, SqlValue::Null, t.clone()]),
        ("INSERT INTO articles(extent_id,idx,message_id,newsgroup,headers,cipher_offset,cipher_len,payload_sha256,state,provider_id,posted_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
         vec![text("x_1"), i(0), text("m1@example.invalid"), text("alt.binaries.test"), blob(200), i(0), i(69), blob(32), text(ArticleState::Posted.as_str()), text("p1"), t.clone()]),
        ("INSERT INTO verifications(extent_id,backbone,provider_id,verified_at,plan_rev,articles_ok,articles_total,result) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
         vec![text("x_1"), text("bb1"), text("p1"), t.clone(), i(1), i(1), i(1), text(VerifyResult::Ok.as_str())]),
        ("INSERT INTO outbox(extent_id,generation_id,stage,attempts,next_at,lease_token,lease_owner,lease_until,cursor,last_error,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
         vec![text("x_1"), text("g_1"), text(OutboxStage::Post.as_str()), i(0), t.clone(), i(0), SqlValue::Null, SqlValue::Null, i(0), SqlValue::Null, t.clone()]),
        ("INSERT INTO uploads(id,bucket_id,key,content_json,user_meta_json,state,revision,completed_generation_id,complete_digest,result_etag,initiated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
         vec![text("u_1"), text("b_1"), text("a/mp"), text("{}"), text("{}"), text(UploadState::Open.as_str()), i(0), SqlValue::Null, SqlValue::Null, SqlValue::Null, t.clone()]),
        ("INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
         vec![text("x_2"), text("b_1"), text(ExtentState::Staged.as_str()), i(5), i(69), blob(48), blob(16), blob(32), blob(32), text(SafetyState::Held.as_str()), t.clone()]),
        ("INSERT INTO upload_parts(upload_id,part_number,extent_id,size,etag,uploaded_at) VALUES (?1,?2,?3,?4,?5,?6)",
         vec![text("u_1"), i(1), text("x_2"), i(5), text("\"e\""), t.clone()]),
        ("INSERT INTO gc(extent_id,action,due_at,done_at) VALUES (?1,?2,?3,?4)",
         vec![text("x_2"), text(GcAction::ShredKey.as_str()), SqlValue::Int(T0.plus_secs(86_400).0), SqlValue::Null]),
        ("INSERT INTO provider_permits(provider_id,slot,token,holder,lease_until) VALUES (?1,?2,?3,?4,?5)",
         vec![text("p1"), i(0), i(0), SqlValue::Null, i(0)]),
        ("INSERT INTO meta(k,v) VALUES (?1,?2)", vec![text("last_dispatch_at"), t.clone()]),
    ];
    let changed = db.batch(rows).await.unwrap();
    // The committed extent (statement 5) also gets its reference row
    // in `generation_extents`, written by the migration's trigger.
    let want: Vec<u64> = (0..changed.len()).map(|n| 1 + u64::from(n == 5)).collect();
    assert_eq!(changed, want);
    let refs = db
        .query(
            "SELECT generation_id, seq, extent_id, plain_offset FROM generation_extents",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(refs, vec![vec![text("g_1"), i(0), text("x_1"), i(0)]]);

    let back = db
        .query(
            "SELECT g.created_at, e.created_at, o.next_at, gc.due_at \
             FROM generations g JOIN extents e ON e.generation_id = g.id \
             JOIN outbox o ON o.extent_id = e.id, gc",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        back,
        vec![vec![
            SqlValue::Int(T0.0),
            SqlValue::Int(T0.0),
            SqlValue::Int(T0.0),
            SqlValue::Int(T0.plus_secs(86_400).0),
        ]]
    );

    // Foreign keys are enforced, as on D1.
    let err = db
        .exec(
            "INSERT INTO objects(bucket_id,key,generation_id) VALUES ('b_1','k2','g_missing')",
            &[],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Sql(_)));
}

// ---------------------------------------------------------------------------
// Every port through the testkit
// ---------------------------------------------------------------------------

/// A connector that never connects (the real one is the engine client).
struct NoConnector;
enum NoSession {}

impl NntpSession for NoSession {
    async fn post(
        &mut self,
        _: &str,
        _: &[u8],
    ) -> velmora_bridge::Result<velmora::nntp::PostOutcome> {
        match *self {}
    }
    async fn stat(&mut self, _: &str) -> velmora_bridge::Result<bool> {
        match *self {}
    }
    async fn body(&mut self, _: &str, _: &mut Vec<u8>) -> velmora_bridge::Result<BodyOutcome> {
        match *self {}
    }
    async fn quit(self) {
        match self {}
    }
}

impl NntpConnector for NoConnector {
    type Session = NoSession;
    async fn connect(&self, _: &ProviderConfig, _: &Permit) -> velmora_bridge::Result<NoSession> {
        Err(BridgeError::NotImplemented("test connector"))
    }
}

fn sample_extent(bucket: &BucketId) -> ExtentRow {
    ExtentRow {
        id: ExtentId::mint([1; 13]),
        bucket_id: bucket.clone(),
        generation_id: None,
        state: ExtentState::Staged,
        seq: None,
        plain_offset: None,
        plain_size: 5,
        cipher_size: 69,
        media_header: vec![0; 48],
        key_mode: 1,
        wrapped_file_key: Some(vec![0; 73]),
        plain_md5: [0; 16],
        plain_sha256: [0; 32],
        cipher_sha256: [0; 32],
        safety_state: SafetyState::Held,
        article_count: None,
        plan_rev: 0,
        last_verified_at: None,
        release_evidence: None,
        released_at: None,
        created_at: T0,
    }
}

/// One call per `Catalog` method. Results are not asserted here: the
/// catalogue lanes own its behaviour; this proves the contract is callable.
async fn exercise_catalog<C: Catalog>(c: &C) {
    let bucket = Bucket {
        id: BucketId::mint([1; 8]),
        name: "slice".into(),
        owner: "owner".into(),
        bdk_wrapped: vec![0; 73],
        kek_version: 1,
        disposable: true,
        created_at: T0,
    };
    let b = &bucket.id;
    let akid = "AKVL0000000000000001";
    let extent = sample_extent(b);
    let gen = GenerationRow {
        id: GenerationId::mint(T0, [1; 8]),
        bucket_id: b.clone(),
        key: "a/k".into(),
        state: GenerationState::Live,
        size: 5,
        etag: "\"e\"".into(),
        checksum_json: None,
        content_json: "{}".into(),
        user_meta_json: "{}".into(),
        extent_count: 1,
        created_at: T0,
        retired_at: None,
    };
    let commit = CommitGeneration {
        generation: gen.clone(),
        extents: vec![extent.clone()],
        now: T0,
    };
    let complete = CompleteUpload {
        generation: gen.clone(),
        placements: vec![ExtentPlacement {
            extent_id: extent.id.clone(),
            seq: 0,
            plain_offset: 0,
        }],
        now: T0,
    };
    let uid = UploadId::mint([1; 16]);
    let target = UploadTarget {
        bucket: b,
        key: "a/mp",
        id: &uid,
    };
    let upload = UploadRow {
        id: uid.clone(),
        bucket_id: b.clone(),
        key: "a/mp".into(),
        content_json: "{}".into(),
        user_meta_json: "{}".into(),
        state: UploadState::Open,
        revision: 0,
        completed_generation_id: None,
        complete_digest: None,
        result_etag: None,
        initiated_at: T0,
    };
    let part = UploadPartRow {
        upload_id: uid.clone(),
        part_number: 1,
        extent_id: extent.id.clone(),
        size: 5,
        etag: "\"e\"".into(),
        uploaded_at: T0,
    };
    let lease = Lease {
        extent: extent.id.clone(),
        generation: gen.id.clone(),
        stage: OutboxStage::Post,
        token: 1,
        attempts: 1,
        cursor: 0,
    };
    let article = ArticleRow {
        extent_id: extent.id.clone(),
        idx: 0,
        message_id: "m1@example.invalid".into(),
        newsgroup: "alt.binaries.test".into(),
        headers: vec![],
        cipher_offset: 0,
        cipher_len: 69,
        payload_sha256: [0; 32],
        state: ArticleState::Planned,
        provider_id: None,
        posted_at: None,
    };
    let verification = VerificationRow {
        extent_id: extent.id.clone(),
        backbone: "bb1".into(),
        provider_id: "p1".into(),
        verified_at: T0,
        plan_rev: 1,
        articles_ok: 1,
        articles_total: 1,
        result: VerifyResult::Ok,
    };
    let gc_row = GcRow {
        id: 1,
        extent_id: extent.id.clone(),
        action: GcAction::DeleteCache,
        due_at: T0,
        done_at: None,
    };
    let provider: ProviderConfig =
        serde_json::from_str(&PROVIDER_TLS[1..PROVIDER_TLS.len() - 1]).unwrap();
    let permit = Permit {
        provider: "p1".into(),
        slot: 0,
        token: 1,
    };
    let query = ListQuery {
        prefix: "a/".into(),
        delimiter: Some("/".into()),
        after: None,
        skip_prefix: None,
        max_keys: 1000,
    };

    let _ = c.create_bucket(&bucket).await;
    let _ = c
        .create_access_key(&AccessKeyRow {
            access_key_id: akid.into(),
            principal: "owner".into(),
            secret_wrapped: vec![0; 73],
            kek_version: 1,
            status: KeyStatus::Active,
            created_at: T0,
        })
        .await;
    let _ = c.put_grant(akid, b, Perm::Rw).await;
    let _ = c.bucket_by_name("slice").await;
    let _ = c.buckets_for(akid).await;
    let _ = c.access_key(akid).await;
    let _ = c.grant(akid, b).await;
    let _ = c.live_object(b, "a/k").await;
    let _ = c.commit_generation(&commit).await;
    let _ = c.delete_object(b, "a/k", T0).await;
    let _ = c.list(b, &query).await;
    let _ = c.object_status(b, "a/k").await;
    let _ = c
        .set_safety_state(&extent.id, SafetyState::Held, SafetyState::Deleted)
        .await;
    let _ = c.create_upload(&upload).await;
    let _ = c.upload(&target).await;
    let _ = c.put_upload_part(&target, &part, &extent, T0).await;
    let _ = c.complete_upload(&target, 1, &[0; 32], &complete).await;
    let _ = c.abort_upload(&target, T0).await;
    let _ = c
        .claim(&extent.id, &gen.id, OutboxStage::Post, "owner-1", T0)
        .await;
    let _ = c.renew(&lease, T0).await;
    let _ = c.advance(&lease, OutboxStage::Verify, T0, T0).await;
    let _ = c.fail(&lease, FailClass::NntpError, T0, T0).await;
    let _ = c.set_cursor(&lease, 1, T0).await;
    let _ = c.defer(&lease, T0, T0).await;
    let _ = c.job_extent(&extent.id, &gen.id).await;
    let _ = c
        .plan_articles(&lease, std::slice::from_ref(&article))
        .await;
    let _ = c.articles(&extent.id).await;
    let _ = c.mark_posted(&lease, 0, "p1", T0).await;
    let _ = c.record_verification(&lease, &verification).await;
    let _ = c.backbone_status(&extent.id).await;
    let _ = c.begin_release(&lease, 1, "[]", T0).await;
    let _ = c.finish_release(&lease, T0).await;
    let _ = c.due(T0, 100).await;
    let _ = c.bury_exhausted(50, T0).await;
    let _ = c.record_dispatch(T0).await;
    let _ = c.outbox_stats().await;
    let _ = c.guard_selftest().await;
    let _ = c.gc_due(T0, 50, true).await;
    let _ = c.gc_begin(&gc_row, T0).await;
    let _ = c.gc_done(1, T0).await;
    let _ = c.seed_permits(std::slice::from_ref(&provider)).await;
    let _ = c
        .acquire_permit(&provider, PermitClass::Read, "holder", T0)
        .await;
    let _ = c.renew_permit(&permit, T0).await;
    let _ = c.release_permit(&permit).await;
}

#[tokio::test(flavor = "current_thread")]
async fn contract_compiles_against_fakes() {
    // Blob store: put with metadata, ranged get, head, delete.
    let blobs = MemBlobStore::new();
    let (b, x) = (BucketId::mint([2; 8]), ExtentId::mint([2; 13]));
    let digest: [u8; 32] = Sha256::digest(b"0123456789").into();
    let meta = BlobMeta {
        bucket: &b,
        extent: &x,
        cipher_sha256: &digest,
    };
    blobs
        .put(&x.safety_key(), b"0123456789".to_vec(), &meta)
        .await
        .unwrap();
    assert_eq!(blobs.head(&x.safety_key()).await.unwrap(), Some(10));
    let span = ByteSpan { start: 2, len: 3 };
    assert_eq!(
        blobs.get(&x.safety_key(), Some(span)).await.unwrap(),
        Some(b"234".to_vec())
    );
    assert!(blobs
        .get(&x.safety_key(), Some(ByteSpan { start: 8, len: 3 }))
        .await
        .is_err());
    assert_eq!(blobs.stored(&x.safety_key()).unwrap().cipher_sha256, digest);
    blobs.delete(&x.safety_key()).await.unwrap();
    blobs.delete(&x.safety_key()).await.unwrap();
    assert_eq!(blobs.get(&x.safety_key(), None).await.unwrap(), None);
    assert_eq!(blobs.head(&x.cache_key()).await.unwrap(), None);

    // Clock.
    let clock = FixedClock::new(T0);
    clock.advance_secs(2);
    clock.advance_ms(-1);
    assert_eq!(clock.now(), UnixMs(T0.0 + 1999));

    // Job sink with lost notifications.
    let jobs = FakeJobs::new();
    let job = Job::Gc { v: JOB_VERSION };
    jobs.drop_next(1);
    jobs.send(&job, 5).await.unwrap();
    jobs.send(&job, 7).await.unwrap();
    assert_eq!(jobs.dropped(), 1);
    assert_eq!(jobs.sent().len(), 1);
    assert_eq!(jobs.sent()[0].delay_secs, 7);
    jobs.send_many(&vec![job.clone(); 100]).await.unwrap();
    assert!(jobs.send_many(&vec![job.clone(); 101]).await.is_err());
    assert_eq!(jobs.take().len(), 101);
    assert!(jobs.sent().is_empty());

    // KEK.
    let kek = TestKek::with_versions(2, &[(1, [1; 32]), (2, [2; 32])]);
    assert_eq!(kek.active().0, 2);
    assert_eq!(kek.version(1).unwrap().expose(), &[1; 32]);
    assert!(kek.version(3).is_none());
    assert!(!format!("{:?}", kek.active().1).contains('2'));

    // Catalogue over rusqlite, every method.
    let catalog = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
    exercise_catalog(&catalog).await;

    // The service core over the fakes: handle, run_job, dispatch.
    let (_, dev) = wrangler_vars();
    let vars = with_secrets(dev, PROVIDER_PLAIN);
    let cfg = load(&vars).unwrap();
    let bridge = Rc::new(Bridge {
        catalog,
        safety: MemBlobStore::new(),
        cache: MemBlobStore::new(),
        nntp: NoConnector,
        jobs,
        kek,
        clock,
        budget: ByteBudget::new(cfg.inflight_budget_bytes),
        cfg,
    });
    let _ = bridge.run_job(&job).await;
    let _ = bridge.dispatch().await;
    let resp = Rc::clone(&bridge)
        .handle(S3Request {
            method: Method::Get,
            raw_target: "/slice/a/k".into(),
            headers: vec![("host".into(), "s3.example.invalid".into())],
            body: Body::Empty,
        })
        .await;
    assert!((200..600).contains(&resp.status));
}

// ---------------------------------------------------------------------------
// Regressions from the contract review
// ---------------------------------------------------------------------------

/// The verify stage's missing-article backoff (2 min, 10 min, 1 h, 6 h,
/// then record `missing`) is derived from the lease alone: `attempts`
/// counts the claim that produced the lease, `cursor` is the backbone
/// resume point.
#[test]
fn lease_carries_attempts_and_cursor() {
    const BACKOFF_SECS: [u32; 4] = [120, 600, 3_600, 21_600];
    let backoff = |l: &Lease| BACKOFF_SECS.get(l.attempts as usize - 1).copied();
    let mut lease = Lease {
        extent: ExtentId::mint([3; 13]),
        generation: GenerationId::mint(T0, [3; 8]),
        stage: OutboxStage::Verify,
        token: 7,
        attempts: 1,
        cursor: 2,
    };
    assert_eq!(backoff(&lease), Some(120));
    lease.attempts = 4;
    assert_eq!(backoff(&lease), Some(21_600));
    lease.attempts = 5;
    assert_eq!(backoff(&lease), None, "after the last step: record missing");
    assert_eq!(lease.cursor, 2);
}

/// Complete publishes staged extents in place from placements only: the
/// input type has no field that could carry hashes, keys or headers.
#[test]
fn complete_upload_takes_placements_not_extent_rows() {
    let gen = GenerationId::mint(T0, [4; 8]);
    let placements: Vec<ExtentPlacement> = (0..3u32)
        .map(|i| ExtentPlacement {
            extent_id: ExtentId::mint([i as u8; 13]),
            seq: i,
            plain_offset: u64::from(i) * 8 * 1024 * 1024,
        })
        .collect();
    let complete = CompleteUpload {
        generation: GenerationRow {
            id: gen,
            bucket_id: BucketId::mint([4; 8]),
            key: "a/big.bin".into(),
            state: GenerationState::Live,
            size: 3 * 8 * 1024 * 1024,
            etag: "\"x-3\"".into(),
            checksum_json: None,
            content_json: "{}".into(),
            user_meta_json: "{}".into(),
            extent_count: 3,
            created_at: T0,
            retired_at: None,
        },
        placements,
        now: T0,
    };
    // Exhaustive destructuring: adding a field to either type fails here.
    let CompleteUpload {
        generation,
        placements,
        now,
    } = complete;
    for ExtentPlacement {
        extent_id,
        seq,
        plain_offset,
    } in &placements
    {
        assert!(extent_id.as_str().starts_with("x_"));
        assert_eq!(*plain_offset, u64::from(*seq) * 8 * 1024 * 1024);
    }
    assert_eq!(generation.extent_count as usize, placements.len());
    assert_eq!(now, T0);
}

#[tokio::test(flavor = "current_thread")]
async fn sql_rejects_more_than_100_params_like_d1() {
    let db = RusqliteSql::with_schema().unwrap();
    let in_list = |n: usize| {
        let marks: Vec<String> = (1..=n).map(|i| format!("?{i}")).collect();
        format!(
            "SELECT count(*) FROM gc WHERE extent_id IN ({})",
            marks.join(",")
        )
    };
    let params = |n: usize| (0..n).map(|i| text(&format!("x_{i}"))).collect::<Vec<_>>();
    let sql100: &'static str = Box::leak(in_list(100).into_boxed_str());
    let sql101: &'static str = Box::leak(in_list(101).into_boxed_str());

    db.query(sql100, &params(100)).await.unwrap();
    db.exec(sql100, &params(100)).await.unwrap();
    db.batch(vec![(sql100, params(100))]).await.unwrap();

    for err in [
        db.query(sql101, &params(101)).await.unwrap_err(),
        db.exec(sql101, &params(101)).await.unwrap_err(),
        db.batch(vec![
            (INSERT_GC_MARKER, vec![text("x_a"), SqlValue::Int(T0.0)]),
            (sql101, params(101)),
        ])
        .await
        .unwrap_err(),
    ] {
        assert!(
            matches!(&err, BridgeError::Sql(m) if m.contains("too many bound parameters")),
            "{err:?}"
        );
    }
    assert_eq!(
        count(&db, "gc"),
        0,
        "an over-limit statement rolls back its batch"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn exec_and_batch_run_returning_and_select_to_completion() {
    let db = RusqliteSql::with_schema().unwrap();
    let returning =
        "INSERT INTO gc(extent_id, action, due_at) VALUES (?1, 'delete_cache', ?2) RETURNING id";
    assert_eq!(
        db.exec(returning, &[text("x_a"), SqlValue::Int(T0.0)])
            .await
            .unwrap(),
        1
    );
    assert_eq!(db.exec("SELECT * FROM gc", &[]).await.unwrap(), 0);
    let changed = db
        .batch(vec![
            (returning, vec![text("x_b"), SqlValue::Int(T0.0)]),
            ("SELECT id FROM gc", vec![]),
            (
                "UPDATE gc SET done_at = ?1 RETURNING id",
                vec![SqlValue::Int(T0.0)],
            ),
        ])
        .await
        .unwrap();
    assert_eq!(changed, vec![1, 0, 2]);
}

#[tokio::test(flavor = "current_thread")]
async fn guard_selftest_reports_rollback() {
    let catalog = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
    assert!(catalog.guard_selftest().await.unwrap());
    assert!(catalog.guard_selftest().await.unwrap(), "repeatable");
    assert_eq!(count(&catalog.sql, "meta"), 0, "no marker left behind");
}

#[test]
fn kek_ring_loads_every_version_up_to_active() {
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    vars.insert("VELMORA_KEK_1".into(), kek_b64(0x01, 32));
    vars.insert("VELMORA_KEK_3".into(), kek_b64(0x03, 32));
    vars.insert("VELMORA_KEK_4".into(), kek_b64(0x04, 32));
    let ring = KekRing::from_vars(3, |k| vars.get(k).cloned()).unwrap();
    assert_eq!(ring.active().0, 3);
    assert_eq!(ring.active().1.expose(), &[0x03; 32]);
    assert_eq!(ring.version(1).unwrap().expose(), &[0x01; 32]);
    assert!(
        ring.version(2).is_none(),
        "absent older versions are skipped"
    );
    assert!(
        ring.version(4).is_none(),
        "nothing above the active version"
    );

    // Only the active version is mandatory.
    assert_eq!(
        KekRing::from_vars(2, |k| vars.get(k).cloned()).unwrap_err(),
        ConfigError::Missing("VELMORA_KEK_2".into())
    );
    // A present but malformed older key still fails closed.
    vars.insert("VELMORA_KEK_2".into(), kek_b64(0x02, 16));
    assert_eq!(
        KekRing::from_vars(3, |k| vars.get(k).cloned()).unwrap_err(),
        ConfigError::Invalid("VELMORA_KEK_2".into())
    );
}

#[test]
fn s3_host_allows_only_hostname_and_port() {
    let (_, dev) = wrangler_vars();
    let base = with_secrets(dev, PROVIDER_PLAIN);
    let host = |h: &str| {
        let mut m = base.clone();
        m.insert("S3_HOST".into(), h.into());
        load(&m).map(|c| c.s3_host)
    };
    for ok in [
        "s3.example.com",
        "velmora-s3.Sub-1.workers.dev",
        "127.0.0.1:8787",
        "h:1",
        "h:65535",
    ] {
        assert_eq!(host(ok).unwrap(), ok);
    }
    for bad in [
        "velmora-s3.<account>.workers.dev",
        "h/path",
        "user@h",
        "h h",
        "h:",
        "h:0",
        "h:65536",
        "h:80:80",
        "h:+80",
        ":80",
        "h_1",
        "[::1]:80",
        "h\u{e9}",
    ] {
        assert_eq!(
            host(bad).unwrap_err(),
            ConfigError::Invalid("S3_HOST".into()),
            "{bad}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fake_jobs_reject_delays_over_12_hours() {
    let jobs = FakeJobs::new();
    let job = Job::Gc { v: JOB_VERSION };
    jobs.send(&job, MAX_QUEUE_DELAY_SECS).await.unwrap();
    assert!(matches!(
        jobs.send(&job, MAX_QUEUE_DELAY_SECS + 1).await,
        Err(BridgeError::Queue(_))
    ));
    assert_eq!(jobs.sent().len(), 1);
}

#[test]
fn fail_classes_are_fixed_strings() {
    assert_eq!(FailClass::DupUnconfirmed.as_str(), "dup-unconfirmed");
    assert_eq!(FailClass::MissingPending.as_str(), "missing-pending");
    for c in FailClass::ALL {
        assert_eq!(FailClass::parse(c.as_str()), Some(*c));
        assert!(c
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'-'));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn mem_blob_store_refuses_a_digest_mismatch() {
    // Same rule as the R2 adapter: the store checks the bytes against
    // `cipher_sha256` and refuses a mismatch without storing anything.
    let blobs = MemBlobStore::new();
    let (b, x) = (BucketId::mint([3; 8]), ExtentId::mint([3; 13]));
    let good: [u8; 32] = Sha256::digest(b"original").into();
    let meta = |d| BlobMeta {
        bucket: &b,
        extent: &x,
        cipher_sha256: d,
    };

    // A wrong digest on an absent key stores nothing.
    let wrong = [0u8; 32];
    let err = blobs
        .put(&x.cache_key(), b"original".to_vec(), &meta(&wrong))
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Blob(_)), "{err:?}");
    assert!(!blobs.contains(&x.cache_key()));

    // A matching digest stores; one flipped byte against the same digest
    // is refused and leaves the stored blob untouched.
    blobs
        .put(&x.cache_key(), b"original".to_vec(), &meta(&good))
        .await
        .unwrap();
    let err = blobs
        .put(&x.cache_key(), b"origina1".to_vec(), &meta(&good))
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Blob(_)), "{err:?}");
    assert_eq!(
        blobs.get(&x.cache_key(), None).await.unwrap(),
        Some(b"original".to_vec())
    );

    // The empty blob has a digest too.
    let empty: [u8; 32] = Sha256::digest(b"").into();
    blobs
        .put(&x.safety_key(), Vec::new(), &meta(&empty))
        .await
        .unwrap();
    assert_eq!(blobs.head(&x.safety_key()).await.unwrap(), Some(0));
}

// ---------------------------------------------------------------------------
// Provider pool settings in `NNTP_PROVIDERS`
// ---------------------------------------------------------------------------

/// One provider entry with the old fields, then `extra` (JSON members).
fn provider_json(id: &str, extra: &str) -> String {
    let sep = if extra.is_empty() { "" } else { "," };
    format!(
        r#"{{"id":"{id}","host":"nntp.invalid","port":563,"tls":true,"user":"u-fixture","pass":"p-fixture","backbone":"bb-{id}","post":true,"read":true,"max_conns":2{sep}{extra}}}"#
    )
}

fn providers_of(entries: &[String]) -> std::result::Result<Vec<ProviderConfig>, ConfigError> {
    let (prod, _) = wrangler_vars();
    let json = format!("[{}]", entries.join(","));
    load(&with_secrets(prod, &json)).map(|cfg| cfg.providers)
}

/// A provider list written before the pool settings existed still loads,
/// and means what it meant: first priority, no retention limit, no pool,
/// enabled.
#[test]
fn old_provider_config_parses_with_pool_defaults() {
    let (prod, _) = wrangler_vars();
    let cfg = load(&with_secrets(prod, PROVIDER_TLS)).unwrap();
    assert_eq!(cfg.providers.len(), 1);
    let p = &cfg.providers[0];
    assert_eq!(
        (p.id.as_str(), p.max_conns, p.post, p.read),
        ("p1", 2, true, true)
    );
    assert_eq!(p.priority, 0);
    assert_eq!(p.retention_days, None);
    assert_eq!(p.pool, None);
    assert_eq!(p.pool_max_conns, None);
    assert_eq!(p.max_ips, None);
    assert!(p.enabled);
    // No retention limit: every article is in reach, whatever its age.
    let now = UnixMs(1_800_000_000_000);
    assert!(p.retains(Some(UnixMs(0)), now));
    assert!(p.retains(None, now));
}

/// `max_ips` is the number of source addresses an account may be
/// connected from at once. It is optional, at least one, and no more
/// than the largest connection limit; it may be larger than the
/// account's own `max_conns`, where it limits nothing.
#[test]
fn provider_address_limit_parses_and_fails_closed() {
    let invalid = Err(ConfigError::Invalid("NNTP_PROVIDERS".into()));
    let one = |extra: &str| providers_of(&[provider_json("a", extra)]);

    let providers = providers_of(&[
        provider_json("a", r#""max_ips":1"#),
        provider_json("b", r#""max_ips":64"#),
        provider_json("c", r#""max_ips":null"#),
        provider_json("d", ""),
    ])
    .unwrap();
    let limits: Vec<Option<u32>> = providers.iter().map(|p| p.max_ips).collect();
    assert_eq!(limits, [Some(1), Some(64), None, None]);

    for bad in ["0", "65", "100000", "-1", "1.5", r#""4""#, "true"] {
        assert_eq!(one(&format!(r#""max_ips":{bad}"#)), invalid, "{bad}");
    }
    // The setting is not a secret, and shows when a provider is printed.
    assert!(format!("{:?}", providers[0]).contains("max_ips: Some(1)"));
}

#[test]
fn provider_pool_settings_parse() {
    let pool = r#""pool":"bundle","pool_max_conns":3"#;
    let providers = providers_of(&[
        provider_json("a", &format!(r#""priority":1,"retention_days":30,{pool}"#)),
        provider_json("b", &format!(r#"{pool},"enabled":false"#)),
        provider_json("c", ""),
    ])
    .unwrap();
    let a = &providers[0];
    assert_eq!((a.priority, a.retention_days), (1, Some(30)));
    assert_eq!(
        (a.pool.as_deref(), a.pool_max_conns),
        (Some("bundle"), Some(3))
    );
    assert!(a.enabled && !providers[1].enabled && providers[2].enabled);

    // Retention is counted from the article's posting time.
    const DAY_MS: i64 = 86_400_000;
    let now = UnixMs(1_800_000_000_000);
    assert!(a.retains(Some(now.plus_ms(-30 * DAY_MS)), now));
    assert!(!a.retains(Some(now.plus_ms(-30 * DAY_MS - 1)), now));
    // An article with no posting time is not ruled out.
    assert!(a.retains(None, now));
}

/// Two spellings of one pool name are one pool: the name is stored
/// trimmed and lower case, and the members must agree on the limit.
#[test]
fn provider_pool_names_are_normalised() {
    let pool = |name: &str, max: u32| format!(r#""pool":"{name}","pool_max_conns":{max}"#);
    let providers = providers_of(&[
        provider_json("a", &pool(" Bundle ", 3)),
        provider_json("b", &pool("bundle", 3)),
    ])
    .unwrap();
    assert_eq!(providers[0].pool.as_deref(), Some("bundle"));
    assert_eq!(providers[0].pool, providers[1].pool);

    let invalid = Err(ConfigError::Invalid("NNTP_PROVIDERS".into()));
    let mixed = [
        provider_json("a", &pool("BUNDLE", 3)),
        provider_json("b", &pool("bundle", 4)),
    ];
    assert_eq!(providers_of(&mixed), invalid);
    // Only blanks is no name.
    assert_eq!(providers_of(&[provider_json("a", &pool("  ", 3))]), invalid);
}

#[test]
fn provider_pool_settings_fail_closed() {
    let invalid = Err(ConfigError::Invalid("NNTP_PROVIDERS".into()));
    let one = |extra: &str| providers_of(&[provider_json("a", extra)]);
    let pool = |max: &str| format!(r#""pool":"bundle","pool_max_conns":{max}"#);

    // A pool and its limit come together.
    assert_eq!(one(r#""pool":"bundle""#), invalid);
    assert_eq!(one(r#""pool_max_conns":3"#), invalid);
    assert_eq!(one(r#""pool":"","pool_max_conns":3"#), invalid);
    assert_eq!(one(&pool("0")), invalid);
    assert_eq!(one(&pool("100000")), invalid);
    let long = format!(r#""pool":"{}","pool_max_conns":3"#, "x".repeat(65));
    assert_eq!(one(&long), invalid);
    // Every account of a pool states the same limit.
    assert_eq!(
        providers_of(&[
            provider_json("a", &pool("3")),
            provider_json("b", &pool("4"))
        ]),
        invalid
    );
    assert!(providers_of(&[
        provider_json("a", &pool("3")),
        provider_json("b", &pool("3"))
    ])
    .is_ok());

    // Values of the wrong shape or range.
    assert_eq!(one(r#""retention_days":0"#), invalid);
    assert_eq!(one(r#""retention_days":-1"#), invalid);
    assert_eq!(one(r#""priority":256"#), invalid);
    assert_eq!(one(r#""priority":"high""#), invalid);
    assert_eq!(one(r#""enabled":"no""#), invalid);
    assert_eq!(one(r#""prority":1"#), invalid, "unknown field");

    // A disabled provider cannot be the only one that posts or reads.
    assert_eq!(one(r#""enabled":false"#), invalid);
    let read_only = provider_json("b", "").replace(r#""post":true"#, r#""post":false"#);
    assert_eq!(
        providers_of(&[provider_json("a", r#""enabled":false"#), read_only.clone()]),
        invalid
    );
    assert!(providers_of(&[provider_json("a", ""), read_only]).is_ok());

    // The list itself is bounded.
    let many: Vec<String> = (0..33)
        .map(|i| provider_json(&format!("p{i}"), ""))
        .collect();
    assert_eq!(providers_of(&many), invalid);
    assert!(providers_of(&many[..32]).is_ok());
}
