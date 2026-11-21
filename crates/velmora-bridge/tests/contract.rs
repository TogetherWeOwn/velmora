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
    BridgeConfig, ConfigError, Environment, GcMode, KekRing, Maintenance, DEFAULT_COLD_SOCKETS,
    DEFAULT_HOT_CAP_BYTES, DEFAULT_POST_SOCKETS, DEFAULT_SLICE_BYTES, MAX_EXTENT_BYTES_LIMIT,
    MAX_JOB_BUDGET_BYTES, MAX_PUT_BYTES_LIMIT,
};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::jobs::RESEND_SECS;
use velmora_bridge::recovery::Recorded;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{
    FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek, TestSql, MIGRATION_0001,
};
use velmora_bridge::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 2025-11-13T00:00:00.123Z.
const T0: UnixMs = UnixMs(1_762_992_000_123);

/// The backbones that count toward a release in these tests.
fn bbs() -> Vec<String> {
    ["bb", "bb-a", "bb-b", "bb1", "bb2"]
        .map(String::from)
        .to_vec()
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

async fn count(db: &TestSql, table: &str) -> i64 {
    let rows = db
        .fixture_query(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .unwrap();
    let [SqlValue::Int(count)] = rows[0].as_slice() else {
        panic!("count(*) returned a non-integer")
    };
    *count
}

/// Both engines bind the fixture blob, avoiding SQLite's x'00' syntax.
const INSERT_BUCKET: &str =
    "INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,disposable,created_at) \
                             VALUES (?1,?2,'p',?3,1,1,?4)";

fn bucket_values(id: &str, name: &str) -> Vec<SqlValue> {
    vec![
        text(id),
        text(name),
        SqlValue::Blob(vec![0]),
        SqlValue::Int(T0.0),
    ]
}

async fn seed_bucket(db: &TestSql, id: &str, name: &str) {
    db.fixture_exec(INSERT_BUCKET, &bucket_values(id, name))
        .await
        .unwrap();
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
    let db = TestSql::with_schema_unrecorded().unwrap();
    seed_bucket(&db, "b_0000000000000001", "one").await;
    let changed = db
        .batch(vec![
            (GUARD_BUCKET_EXISTS, vec![text("b_0000000000000001")]),
            (INSERT_GC_MARKER, vec![text("x_a"), SqlValue::Int(T0.0)]),
            (INSERT_GC_MARKER, vec![text("x_b"), SqlValue::Int(T0.0)]),
        ])
        .await
        .unwrap();
    assert_eq!(changed, vec![0, 1, 1]);
    assert_eq!(count(&db, "gc").await, 2);
    assert_eq!(
        count(&db, "tx_guard").await,
        0,
        "a held guard inserts nothing"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn batch_guard_failure_rolls_back_everything() {
    let db = TestSql::with_schema_unrecorded().unwrap();
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
    assert_eq!(count(&db, "gc").await, 0);
    assert_eq!(count(&db, "tx_guard").await, 0);
    // The connection is usable afterwards (no transaction left open).
    db.exec(INSERT_GC_MARKER, &[text("x_later"), SqlValue::Int(T0.0)])
        .await
        .unwrap();
    assert_eq!(count(&db, "gc").await, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn batch_statement_failure_rolls_back_and_is_not_a_guard_loss() {
    let db = TestSql::with_schema_unrecorded().unwrap();
    seed_bucket(&db, "b_0000000000000001", "one").await;
    // Third statement violates the UNIQUE bucket name.
    let err = db
        .batch(vec![
            (INSERT_GC_MARKER, vec![text("x_a"), SqlValue::Int(T0.0)]),
            (INSERT_BUCKET, bucket_values("b_0000000000000002", "two")),
            (INSERT_BUCKET, bucket_values("b_0000000000000003", "one")),
        ])
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Sql(_)), "{err:?}");
    assert_eq!(count(&db, "gc").await, 0);
    assert_eq!(count(&db, "buckets").await, 1);

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

// The real-data gate is open: catalogue recovery landed and its drills
// passed. Closing it again must be a deliberate change.
const _: () = assert!(REAL_DATA_READY, "real-data gate is open");

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
/// A second backbone, read only: outside dev a release needs two backbones
/// that count toward it, and a configuration with fewer is refused.
const SECOND_BACKBONE: &str = r#"{"id":"p2","host":"nntp2.invalid","port":563,"tls":true,"user":"u-fixture","pass":"p-fixture","backbone":"bb2","post":false,"read":true,"max_conns":2}"#;
const PROVIDER_PLAIN: &str = r#"[{"id":"p1","host":"127.0.0.1","port":11119,"tls":false,"user":"testuser","pass":"testpass","backbone":"fake","post":true,"read":true,"max_conns":2}]"#;
const ADMIN_TOKEN_FIXTURE: &str = "admin-token-fixture-admin-token-fixture";

fn kek_b64(byte: u8, len: usize) -> String {
    base64::engine::general_purpose::STANDARD.encode(vec![byte; len])
}

/// The shipped prod `S3_HOST` is a placeholder that config refuses (see
/// `config_loads_from_documented_vars`); fixtures use a concrete host.
const PROD_HOST_FIXTURE: &str = "velmora-s3.example.workers.dev";

/// `PROVIDER_TLS` and the second backbone: the smallest list prod accepts.
fn prod_providers() -> String {
    format!(
        "{},{SECOND_BACKBONE}]",
        &PROVIDER_TLS[..PROVIDER_TLS.len() - 1]
    )
}

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
    // The file sets no GC_ORPHANS, in either environment: the collector
    // of orphaned upload parts is turned on by the operator alone.
    assert!(!prod.contains_key("GC_ORPHANS") && !dev.contains_key("GC_ORPHANS"));

    // Until deploy fills in the account subdomain, prod refuses to start.
    let mut shipped = with_secrets(prod.clone(), &prod_providers());
    shipped.insert("S3_HOST".into(), prod["S3_HOST"].clone());
    assert_eq!(
        load(&shipped).unwrap_err(),
        ConfigError::Invalid("S3_HOST".into())
    );

    let prod = with_secrets(prod, &prod_providers());
    let cfg = load(&prod).unwrap();
    assert_eq!(cfg.environment, Environment::Prod);
    assert_eq!(cfg.s3_host, PROD_HOST_FIXTURE);
    assert_eq!(cfg.required_backbones, 2);
    assert_eq!(cfg.max_extent_bytes, 16 * 1024 * 1024);
    assert_eq!(cfg.inflight_budget_bytes, 48 * 1024 * 1024);
    assert_eq!(cfg.job_budget_bytes, 90 * 1024 * 1024);
    // No wait after the two-backbone verify: the release job's own STAT
    // of every backbone that counts is the last check.
    assert_eq!(cfg.safety_min_age_secs, 0);
    assert_eq!(cfg.verify_delay_secs, 120);
    // Production keeps the two-stage release; the dev fixture opts in.
    assert!(!cfg.release_at_verify);
    assert_eq!(
        cfg.newsgroups,
        [
            "alt.binaries.boneless",
            "alt.binaries.misc",
            "alt.binaries.multimedia",
            "alt.binaries.test"
        ]
    );
    assert_eq!(cfg.kek_active, 1);
    assert_eq!(cfg.gc_mode, GcMode::Off);
    assert_eq!(cfg.hot_cap_bytes, 100 * 1024 * 1024 * 1024);
    assert_eq!(cfg.hot_cap_bytes, DEFAULT_HOT_CAP_BYTES);
    let expected_maintenance = match prod["MAINTENANCE"].as_str() {
        "off" => Maintenance::Off,
        "restore" => Maintenance::Restore,
        value => panic!("undocumented MAINTENANCE value: {value:?}"),
    };
    assert_eq!(cfg.maintenance, expected_maintenance);
    assert!(cfg.server_side_copy);
    assert!(cfg.packed_plans);
    // No parity until it is turned on.
    assert!(!cfg.parity);
    // A GET above 1 GiB is served in sub-ranges of 1 GiB.
    assert_eq!(cfg.get_fanout_bytes, Some(1 << 30));
    assert!(!cfg.dev_trust_http);
    assert_eq!(cfg.providers.len(), 2);
    // Production posts on six sockets per job, so that three post jobs fit
    // one isolate (see below); the grace keeps its default.
    assert_eq!(cfg.post_sockets, 6);
    assert_eq!(cfg.propagation_grace_secs, 21_600);
    // A PutObject body may be 99 MiB, stored in slices of 8 MiB. The
    // sweep of writes that were never published ships off in production.
    assert_eq!(cfg.max_put_bytes, 99 * 1024 * 1024);
    assert_eq!(cfg.max_put_bytes, MAX_PUT_BYTES_LIMIT);
    assert_eq!(cfg.slice_bytes, DEFAULT_SLICE_BYTES);
    assert!(!cfg.intent_sweep);
    // Upload parts that left their upload are not collected.
    assert!(!cfg.gc_orphans);
    // One object holds at most 10 000 extents unless the variable says
    // fewer.
    assert_eq!(cfg.max_object_extents, 10_000);

    // The dev environment is complete on its own (envs do not inherit vars).
    let cfg = load(&with_secrets(dev.clone(), PROVIDER_PLAIN)).unwrap();
    assert_eq!(cfg.environment, Environment::Dev);
    assert!(cfg.is_dev());
    assert_eq!(cfg.required_backbones, 1);
    assert_eq!(cfg.safety_min_age_secs, 0);
    assert!(cfg.release_at_verify);
    assert_eq!(cfg.verify_delay_secs, 1);
    assert_eq!(cfg.gc_mode, GcMode::Disposable);
    assert!(cfg.server_side_copy);
    assert_eq!(
        (cfg.max_put_bytes, cfg.slice_bytes, cfg.intent_sweep),
        (MAX_PUT_BYTES_LIMIT, DEFAULT_SLICE_BYTES, true)
    );
    assert!(!cfg.gc_orphans);
    // Dev sets no job budget: jobs and requests share the one limit.
    assert_eq!(cfg.job_budget_bytes, cfg.inflight_budget_bytes);
    // Absent or empty is the default; any other size is taken as given.
    assert_eq!(cfg.hot_cap_bytes, DEFAULT_HOT_CAP_BYTES);
    let mut sized = with_secrets(dev, PROVIDER_PLAIN);
    for (value, want) in [("", DEFAULT_HOT_CAP_BYTES), ("0", 0), (" 4096 ", 4096)] {
        sized.insert("HOT_CAP_BYTES".to_string(), value.to_string());
        assert_eq!(load(&sized).unwrap().hot_cap_bytes, want, "{value:?}");
    }
    assert_eq!(cfg.hot_ctl, velmora_bridge::config::HotCtlConfig::default());
    assert_eq!(cfg.hot_ctl.min_bytes, 10 << 30);
    assert_eq!(cfg.hot_ctl.max_bytes, Some(1 << 40));
    assert_eq!(cfg.hot_ctl.hit_floor, 0.95);
    assert_eq!(cfg.hot_ctl.hit_margin, 0.02);
    assert_eq!(cfg.hot_ctl.horizon_h, 168);
    assert_eq!(cfg.hot_ctl.min_reads, 200);
    for (key, value) in [
        ("HOT_CAP_MODE", "shadow"),
        ("HOT_CAP_MIN_BYTES", "1073741824"),
        ("HOT_CAP_MAX_BYTES", "none"),
        ("HOT_HIT_FLOOR", "0.91"),
        ("HOT_HIT_MARGIN", "0.04"),
        ("HOT_CX_HORIZON_H", "24"),
        ("MIN_READS", "400"),
    ] {
        sized.insert(key.into(), value.into());
    }
    let custom = load(&sized).unwrap().hot_ctl;
    assert_eq!(custom.mode, velmora_bridge::config::HotCtlMode::Shadow);
    assert_eq!(custom.min_bytes, 1 << 30);
    assert_eq!(custom.max_bytes, None);
    assert_eq!(custom.hit_floor, 0.91);
    assert_eq!(custom.hit_margin, 0.04);
    assert_eq!(custom.horizon_h, 24);
    assert_eq!(custom.min_reads, 400);
    sized.insert("HOT_CAP_MAX_BYTES".into(), "2147483648".into());
    assert_eq!(load(&sized).unwrap().hot_ctl.max_bytes, Some(2 << 30));
    for (key, value) in [
        ("HOT_CAP_MODE", "on"),
        ("HOT_CAP_MIN_BYTES", "0"),
        ("HOT_CAP_MIN_BYTES", "2147483649"),
        ("HOT_CAP_MAX_BYTES", "9223372036854775808"),
        ("HOT_HIT_FLOOR", "NaN"),
        ("HOT_HIT_FLOOR", "1.01"),
        ("HOT_CX_HORIZON_H", "25"),
        ("HOT_HIT_MARGIN", "-0.1"),
        ("MIN_READS", "0"),
    ] {
        let mut bad = sized.clone();
        bad.insert(key.into(), value.into());
        assert_eq!(load(&bad).unwrap_err(), ConfigError::Invalid(key.into()));
    }
    // Dev serves a GET above 8 MiB in sub-ranges. Absent, empty or 0:
    // never in sub-ranges; a size outside 1 MiB..=2 GiB is refused.
    assert_eq!(cfg.get_fanout_bytes, Some(8 << 20));
    for (value, want) in [
        ("", Some(None)),
        ("0", Some(None)),
        ("1048575", None),
        ("1048576", Some(Some(1 << 20))),
        ("2147483648", Some(Some(1 << 31))),
        ("2147483649", None),
        ("1g", None),
        ("-1", None),
    ] {
        sized.insert("GET_FANOUT_BYTES".to_string(), value.to_string());
        let got = load(&sized).map(|c| c.get_fanout_bytes);
        match want {
            Some(want) => assert_eq!(got.unwrap(), want, "{value:?}"),
            None => assert_eq!(
                got.unwrap_err(),
                ConfigError::Invalid("GET_FANOUT_BYTES".into()),
                "{value:?}"
            ),
        }
    }
    sized.remove("GET_FANOUT_BYTES");
    assert_eq!(load(&sized).unwrap().get_fanout_bytes, None);
    assert!(!load(&sized).unwrap().grant_refusal_reasons);
    for value in ["on", "off", "", "ON", " on", "typo"] {
        sized.insert("GRANT_REFUSAL_REASONS".into(), value.into());
        assert_eq!(load(&sized).unwrap().grant_refusal_reasons, value == "on");
    }
    sized.remove("GRANT_REFUSAL_REASONS");
    // A cold read uses four connections unless told otherwise, from one
    // to eight, and never more than fit the byte budget beside one extent
    // and its copy: 48 MiB less 32 MiB leaves room for ten more.
    assert_eq!(cfg.cold_sockets, 4);
    for (value, want) in [
        ("", Some(4)),
        ("1", Some(1)),
        ("8", Some(8)),
        ("0", None),
        ("9", None),
        ("many", None),
    ] {
        sized.insert("COLD_SOCKETS".to_string(), value.to_string());
        let got = load(&sized).map(|c| c.cold_sockets);
        match want {
            Some(want) => assert_eq!(got.unwrap(), want, "{value:?}"),
            None => assert_eq!(
                got.unwrap_err(),
                ConfigError::Invalid("COLD_SOCKETS".into()),
                "{value:?}"
            ),
        }
    }
    // A budget that fits the rebuild but not all eight sockets lowers
    // the count. The eighth socket's limit is counted from the
    // ciphertext: two plaintext extents and seven buffers fall short.
    sized.insert("COLD_SOCKETS".to_string(), "8".to_string());
    for (budget, want) in [("44572768", 8), ("44572767", 7), ("44564480", 7)] {
        sized.insert("INFLIGHT_BUDGET_BYTES".to_string(), budget.to_string());
        let cfg = load(&sized).unwrap();
        assert_eq!(cfg.cold_sockets, want, "{budget}");
        let cipher = velmora::media::ciphertext_size(cfg.max_extent_bytes).unwrap();
        assert!(
            velmora_bridge::fetch::cold_read_bytes(cipher, want) <= cfg.inflight_budget_bytes,
            "{budget}"
        );
    }
    sized.remove("COLD_SOCKETS");
    sized.insert("INFLIGHT_BUDGET_BYTES".to_string(), "50331648".to_string());
    // The catalogue id is one path segment of the stamp keys.
    assert_eq!(cfg.catalogue_id, "main");
    for (value, want) in [("", Some("main")), (" eu-1 ", Some("eu-1")), ("a/b", None)] {
        sized.insert("CATALOGUE_ID".to_string(), value.to_string());
        let got = load(&sized).ok().map(|c| c.catalogue_id);
        assert_eq!(got.as_deref(), want, "{value:?}");
    }
    assert!(cfg.dev_trust_http);
    assert!(!cfg.providers[0].tls);
}

/// Turning parity off for new plans does not remove the room needed to
/// rebuild extents whose parity is already stored.
#[test]
fn stored_parity_needs_rebuild_room_even_with_parity_off() {
    use velmora_bridge::fetch::{cold_read_bytes, cold_rebuild_bytes, cold_step_bytes};

    let (prod, _) = wrangler_vars();
    let mut vars = with_secrets(prod, &prod_providers());
    let cfg = load(&vars).unwrap();
    let cipher = velmora::media::ciphertext_size(cfg.max_extent_bytes).unwrap();
    let (k, shard) = velmora_bridge::parity::stripe_of(cipher).unwrap();
    let most = velmora_bridge::parity::parity_count(usize::from(k)) as u64;
    assert_eq!((k, most), (24, 4));
    let read = cold_read_bytes(cipher, 1);
    let both = cold_step_bytes(cipher, 1) + cold_rebuild_bytes(u64::from(shard), most);
    assert!(read < both && both <= cfg.inflight_budget_bytes);

    // The job budget follows the request budget.
    vars.remove("JOB_BUDGET_BYTES");
    vars.insert("PACKED_PLANS".into(), "on".into());
    vars.insert("COLD_SOCKETS".into(), "1".into());
    for parity in ["on", "off"] {
        vars.insert("PARITY".into(), parity.into());
        vars.insert("INFLIGHT_BUDGET_BYTES".into(), (both - 1).to_string());
        assert_eq!(
            load(&vars).map(|cfg| cfg.cold_sockets),
            Err(ConfigError::Invalid("INFLIGHT_BUDGET_BYTES".into())),
            "PARITY={parity}"
        );
        vars.insert("INFLIGHT_BUDGET_BYTES".into(), both.to_string());
        assert_eq!(load(&vars).unwrap().cold_sockets, 1, "PARITY={parity}");
    }
}

/// The recovery copy is no part of the service's configuration: off
/// when unset or blank, and a copy that is refused does not stop the
/// service.
#[test]
fn recovery_copy_is_off_by_default_and_cannot_stop_the_service() {
    use velmora_bridge::remote::RemoteConfig;
    let (prod, _) = wrangler_vars();
    let mut vars = with_secrets(prod, PROVIDER_TLS);
    for name in [
        "RECOVERY_COPY",
        "E2_ENDPOINT",
        "E2_REGION",
        "E2_BUCKET",
        "E2_ACCESS_KEY",
        "E2_SECRET_KEY",
        "RECOVERY_PREFIX",
    ] {
        vars.remove(name);
    }
    let copy = |vars: &BTreeMap<String, String>| RemoteConfig::from_vars(|n| vars.get(n).cloned());
    for (value, off) in [
        (None, true),
        (Some(""), true),
        (Some("  "), true),
        (Some("off"), true),
        (Some("on"), false),
        (Some("true"), false),
    ] {
        match value {
            Some(v) => vars.insert("RECOVERY_COPY".into(), v.into()),
            None => vars.remove("RECOVERY_COPY"),
        };
        load(&vars).unwrap();
        match copy(&vars) {
            Ok(none) => assert!(off && none.is_none(), "{value:?}"),
            Err(_) => assert!(!off, "{value:?}"),
        }
    }
}

#[test]
fn replay_read_ahead_requires_explicit_opt_in() {
    let (prod, dev) = wrangler_vars();
    for shipped in [&prod, &dev] {
        assert!(!shipped.contains_key("REPLAY_READ_AHEAD"));
    }
    let mut vars = with_secrets(prod, &prod_providers());
    assert!(!load(&vars).unwrap().replay_read_ahead);
    for (setting, expected) in [("", false), ("off", false), ("on", true)] {
        vars.insert("REPLAY_READ_AHEAD".into(), setting.into());
        assert_eq!(load(&vars).unwrap().replay_read_ahead, expected);
    }
    vars.insert("REPLAY_READ_AHEAD".into(), "true".into());
    assert_eq!(
        load(&vars).unwrap_err(),
        ConfigError::Invalid("REPLAY_READ_AHEAD".into()),
    );
}

/// `RECORD_LAYOUT` chooses where new recovery records are written. The
/// shipped configuration does not set it, so a deploy keeps the flat
/// names until an operator turns the tenant layout on, and a value that
/// is neither of the two refuses to start instead of picking one.
#[test]
fn record_layout_is_flat_unless_tenant_is_asked_for() {
    use velmora_bridge::recovery::Layout;
    let (prod, dev) = wrangler_vars();
    for shipped in [&prod, &dev] {
        assert!(
            !shipped.contains_key("RECORD_LAYOUT"),
            "the shipped configuration must not choose a record layout"
        );
    }
    let mut vars = with_secrets(prod, &prod_providers());
    assert!(load(&vars).unwrap().records.is_flat());
    for flat in ["", "  ", "flat", " flat "] {
        vars.insert("RECORD_LAYOUT".into(), flat.into());
        assert_eq!(load(&vars).unwrap().records, Layout::flat(), "{flat:?}");
    }
    for tenant in ["tenant", " tenant "] {
        vars.insert("RECORD_LAYOUT".into(), tenant.into());
        let records = load(&vars).unwrap().records;
        assert_eq!(records, Layout::default_tenant(), "{tenant:?}");
        assert_eq!(records.root(), "m/x/t_0000000000000000/");
    }
    for bad in ["on", "off", "TENANT", "Flat", "t_1", "m/x/", "tenant,flat"] {
        vars.insert("RECORD_LAYOUT".into(), bad.into());
        assert_eq!(
            load(&vars).unwrap_err(),
            ConfigError::Invalid("RECORD_LAYOUT".into()),
            "{bad:?}"
        );
    }
}

#[test]
fn missing_secret_fails_closed() {
    // Worker-only optional variables, validated by the Worker catalogue
    // selector instead of BridgeConfig. Nothing BridgeConfig reads may
    // be added here to bypass its missing-variable checks.
    const WORKER_ONLY_OPTIONAL: [&str; 2] = ["CATALOG_BACKEND", "PG_PIPELINE"];
    let (prod, dev) = wrangler_vars();
    let full = with_secrets(prod, &prod_providers());
    let dev = with_secrets(dev, PROVIDER_PLAIN);
    for config in [&full, &dev] {
        BridgeConfig::from_vars(|key| {
            assert!(
                !WORKER_ONLY_OPTIONAL.contains(&key),
                "BridgeConfig reads {key}"
            );
            config.get(key).cloned()
        })
        .unwrap();
    }
    for name in full
        .keys()
        .filter(|name| !WORKER_ONLY_OPTIONAL.contains(&name.as_str()))
    {
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
        // Connections of a read from Usenet: absent or blank is the
        // default of four.
        if name == "COLD_SOCKETS" {
            assert_eq!(load(&vars).unwrap().cold_sockets, DEFAULT_COLD_SOCKETS);
            vars.insert(name.clone(), "  ".into());
            assert_eq!(load(&vars).unwrap().cold_sockets, DEFAULT_COLD_SOCKETS);
            continue;
        }
        // Sliced PutObject: absent or blank, a PUT is one extent as
        // before, and nothing is swept.
        if name == "MAX_PUT_BYTES" || name == "INTENT_SWEEP" {
            for _ in 0..2 {
                let cfg = load(&vars).unwrap();
                if name == "MAX_PUT_BYTES" {
                    assert_eq!(cfg.max_put_bytes, cfg.max_extent_bytes);
                    assert!(!cfg.intent_sweep);
                } else {
                    assert_eq!(cfg.max_put_bytes, MAX_PUT_BYTES_LIMIT);
                    assert!(!cfg.intent_sweep);
                }
                vars.insert(name.clone(), "  ".into());
            }
            continue;
        }
        // The recovery copy: absent or blank is off. It is no part of
        // this configuration and cannot stop the service.
        if name == "RECOVERY_COPY" {
            for _ in 0..2 {
                load(&vars).unwrap();
                let copy =
                    velmora_bridge::remote::RemoteConfig::from_vars(|n| vars.get(n).cloned());
                assert!(copy.unwrap().is_none());
                vars.insert(name.clone(), "  ".into());
            }
            continue;
        }
        // The verify mode: absent or blank is the full read of every
        // extent, the stage as it was before the switch existed.
        if name == "VERIFY_MODE" {
            for _ in 0..2 {
                assert_eq!(
                    load(&vars).unwrap().verify.mode,
                    velmora_bridge::config::VerifyMode::Body
                );
                vars.insert(name.clone(), "  ".into());
            }
            continue;
        }
        // Packed plans: absent or blank is off, the way a catalogue was
        // before the switch existed.
        if name == "PACKED_PLANS" {
            for _ in 0..2 {
                assert!(!load(&vars).unwrap().packed_plans);
                vars.insert(name.clone(), "  ".into());
            }
            continue;
        }
        // Who releases after a verify round: absent or blank is the
        // release job, as before the switch existed.
        if name == "RELEASE_AT_VERIFY" {
            for _ in 0..2 {
                assert!(!load(&vars).unwrap().release_at_verify);
                vars.insert(name.clone(), "  ".into());
            }
            continue;
        }
        // Absent or blank: every GET is served by one invocation, as
        // before the variable existed.
        if name == "GET_FANOUT_BYTES" {
            for _ in 0..2 {
                assert_eq!(load(&vars).unwrap().get_fanout_bytes, None);
                vars.insert(name.clone(), "  ".into());
            }
            continue;
        }
        // Grant refusal reasons: absent or blank is off. Logging only;
        // no value of it changes an admission decision.
        if name == "GRANT_REFUSAL_REASONS" {
            for _ in 0..2 {
                assert!(!load(&vars).unwrap().grant_refusal_reasons);
                vars.insert(name.clone(), "  ".into());
            }
            continue;
        }
        // Where permits come from: absent or blank is the catalogue's
        // slot rows, as before the switch existed. The Worker reads it,
        // not this configuration.
        if name == "PERMITS" {
            use velmora_bridge::gate::PermitMode;
            for _ in 0..2 {
                load(&vars).unwrap();
                let mode = PermitMode::from_var(vars.get(name).map(String::as_str));
                assert_eq!(mode, Ok(PermitMode::Catalog));
                vars.insert(name.clone(), "  ".into());
            }
            continue;
        }
        // The job budget: absent or blank is the request budget, which
        // is the smaller of the two bounds, so nothing fails open.
        if name == "JOB_BUDGET_BYTES" {
            let cfg = load(&vars).unwrap();
            assert_eq!(cfg.job_budget_bytes, cfg.inflight_budget_bytes);
            vars.insert(name.clone(), "  ".into());
            let cfg = load(&vars).unwrap();
            assert_eq!(cfg.job_budget_bytes, cfg.inflight_budget_bytes);
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

/// The light check: `body` unless asked for, and every value of it
/// checked when the Worker starts.
#[test]
fn verify_mode_is_body_unless_light_is_asked_for() {
    use velmora_bridge::config::{VerifyConfig, VerifyMode};
    let (prod, dev) = wrangler_vars();
    let prod = with_secrets(prod, &prod_providers());
    let dev = with_secrets(dev, PROVIDER_PLAIN);
    let with = |base: &BTreeMap<String, String>, pairs: &[(&str, &str)]| {
        let mut m = base.clone();
        for (k, v) in pairs {
            m.insert(k.to_string(), v.to_string());
        }
        load(&m).map(|c| c.verify)
    };
    let invalid = |k: &str| Err(ConfigError::Invalid(k.to_string()));

    // Nothing set: the full read of every extent.
    let unset = with(&prod, &[]).unwrap();
    assert_eq!(unset, VerifyConfig::default());
    assert_eq!(unset.mode, VerifyMode::Body);
    assert_eq!((unset.sample_ppm, unset.escalate_secs), (20_000, 86_400));
    assert_eq!(with(&prod, &[("VERIFY_MODE", "body")]).unwrap(), unset);
    assert_eq!(with(&prod, &[("VERIFY_MODE", "")]).unwrap(), unset);

    let light = with(
        &prod,
        &[
            ("VERIFY_MODE", "light"),
            ("VERIFY_SAMPLE_PERCENT", "1.5"),
            ("VERIFY_ESCALATE_SECS", "3600"),
            ("VERIFY_SIZE_COMMANDS", r#"{"p2":"head","p1":"hdr"}"#),
        ],
    )
    .unwrap();
    assert_eq!(light.mode, VerifyMode::Light);
    assert_eq!((light.sample_ppm, light.escalate_secs), (15_000, 3_600));
    assert_eq!(light.size_command("p1"), Some(SizeCommand::Hdr));
    assert_eq!(light.size_command("p2"), Some(SizeCommand::Head));
    assert_eq!(light.size_command("p3"), None);
    let over = with(&prod, &[("VERIFY_SIZE_COMMANDS", r#"{"p1":"over"}"#)]).unwrap();
    assert_eq!(over.size_command("p1"), Some(SizeCommand::Over));
    assert_eq!(over.size_command("p2"), None);

    // No mode but the two.
    for mode in ["Light", "stat", "off", "sampled"] {
        assert_eq!(
            with(&prod, &[("VERIFY_MODE", mode)]),
            invalid("VERIFY_MODE")
        );
    }
    // The sample: a number of percent, at most 100.
    for (percent, ppm) in [
        ("2", 20_000),
        ("100", 1_000_000),
        ("1", 10_000),
        ("2.0625", 20_625),
    ] {
        let got = with(&prod, &[("VERIFY_SAMPLE_PERCENT", percent)]).unwrap();
        assert_eq!(got.sample_ppm, ppm, "{percent}");
    }
    for percent in [
        "101", "-1", "2%", "1.", ".5", "1.00001", "two", "1e2", "1000",
    ] {
        assert_eq!(
            with(&prod, &[("VERIFY_SAMPLE_PERCENT", percent)]),
            invalid("VERIFY_SAMPLE_PERCENT"),
            "{percent}"
        );
    }
    // Less than 1 % is a test setting.
    for percent in ["0", "0.5", "0.9999"] {
        assert!(matches!(
            with(&prod, &[("VERIFY_SAMPLE_PERCENT", percent)]),
            Err(ConfigError::Refused(_))
        ));
    }
    let none = with(&dev, &[("VERIFY_SAMPLE_PERCENT", "0")]).unwrap();
    assert_eq!(none.sample_ppm, 0);
    // The period of full reads after a failed sample.
    for secs in ["59", "0", "2592001", "day"] {
        assert_eq!(
            with(&prod, &[("VERIFY_ESCALATE_SECS", secs)]),
            invalid("VERIFY_ESCALATE_SECS"),
            "{secs}"
        );
    }
    // The size commands: known providers, known commands. A typo would
    // leave the provider on `STAT` without a word.
    for json in [
        r#"{"p9":"head"}"#,
        r#"{"p1":"xhdr"}"#,
        r#"{"p1":"HEAD"}"#,
        r#"{"p1":1}"#,
        r#"["p1"]"#,
        "head",
    ] {
        assert_eq!(
            with(&prod, &[("VERIFY_SIZE_COMMANDS", json)]),
            invalid("VERIFY_SIZE_COMMANDS"),
            "{json}"
        );
    }
}

#[test]
fn config_rejects_invalid_and_unsafe_values() {
    let (prod, dev) = wrangler_vars();
    let prod = with_secrets(prod, &prod_providers());
    let dev = with_secrets(dev, PROVIDER_PLAIN);
    let set = |base: &BTreeMap<String, String>, k: &str, v: &str| {
        let mut m = base.clone();
        m.insert(k.to_string(), v.to_string());
        load(&m).unwrap_err()
    };
    let invalid = |k: &str| ConfigError::Invalid(k.to_string());

    // Safety rules (the gate itself is pinned at compile time below).
    // There is no full GC yet: the name is not a mode.
    assert_eq!(set(&prod, "GC_MODE", "full"), invalid("GC_MODE"));
    assert_eq!(set(&dev, "GC_MODE", "full"), invalid("GC_MODE"));
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
        ("COLD_SOCKETS", "0"),
        ("COLD_SOCKETS", "9"),
        ("PROPAGATION_GRACE_SECS", "-1"),
        ("PROPAGATION_GRACE_SECS", "6h"),
        // Below one extent, above what the edge lets through, not a number.
        ("MAX_PUT_BYTES", "16777215"),
        ("MAX_PUT_BYTES", "103809025"),
        ("MAX_PUT_BYTES", "99MiB"),
        // No slice, a slice above one extent, more than 16 slices in
        // the largest body (99 MiB in slices of 6 MiB are 17).
        ("SLICE_BYTES", "0"),
        ("SLICE_BYTES", "16777217"),
        ("SLICE_BYTES", "6291456"),
        ("SLICE_BYTES", "8m"),
        ("MAX_OBJECT_EXTENTS", "0"),
        ("MAX_OBJECT_EXTENTS", "10001"),
        ("MAX_OBJECT_EXTENTS", "10k"),
        ("INTENT_SWEEP", "1"),
        ("INTENT_SWEEP", "ON"),
        ("INTENT_SWEEP", "disposable"),
        ("GC_ORPHANS", "1"),
        ("GC_ORPHANS", "ON"),
        ("GC_ORPHANS", "true"),
        ("GC_ORPHANS", "disposable"),
        ("PARITY", "1"),
        ("PARITY", "ON"),
        ("PARITY", "true"),
        ("RELEASE_AT_VERIFY", "1"),
        ("RELEASE_AT_VERIFY", "ON"),
        ("RELEASE_AT_VERIFY", "true"),
    ] {
        assert_eq!(set(&prod, name, bad), invalid(name), "{name}={bad}");
    }
    let mut tuned = prod.clone();
    tuned.insert("POST_SOCKETS".into(), "8".into());
    tuned.insert("PROPAGATION_GRACE_SECS".into(), "0".into());
    let cfg = load(&tuned).unwrap();
    assert_eq!((cfg.post_sockets, cfg.propagation_grace_secs), (8, 0));
    // Who releases after a verify round: absent, blank and `off` leave
    // it to the release job.
    let mut tuned = prod.clone();
    tuned.remove("RELEASE_AT_VERIFY");
    assert!(!load(&tuned).unwrap().release_at_verify);
    for (value, on) in [("", false), ("  ", false), ("off", false), (" on ", true)] {
        tuned.insert("RELEASE_AT_VERIFY".into(), value.into());
        let cfg = load(&tuned).unwrap();
        assert_eq!(cfg.release_at_verify, on, "RELEASE_AT_VERIFY={value:?}");
    }
    // The parity switch: absent, blank and `off` are off.
    for (value, on) in [("", false), ("  ", false), ("off", false), (" on ", true)] {
        let mut tuned = prod.clone();
        tuned.insert("PARITY".into(), value.into());
        assert_eq!(load(&tuned).unwrap().parity, on, "PARITY={value:?}");
    }
    // Parity is stored beside a packed plan: on without packed plans it
    // would give no extent parity, so it is refused.
    for packed in ["off", ""] {
        let mut tuned = prod.clone();
        tuned.insert("PARITY".into(), "on".into());
        tuned.insert("PACKED_PLANS".into(), packed.into());
        assert_eq!(
            load(&tuned).unwrap_err(),
            ConfigError::Refused("PARITY without PACKED_PLANS")
        );
        tuned.insert("PARITY".into(), "off".into());
        assert!(!load(&tuned).unwrap().packed_plans);
    }
    // A packed plan counts its newsgroups in one byte; with parity on a
    // longer list would fall back to plans of rows, without parity.
    let many = |n: usize| {
        (0..n)
            .map(|i| format!("alt.binaries.g{i}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    for (n, parity, ok) in [(255, "on", true), (256, "on", false), (256, "off", true)] {
        let mut tuned = prod.clone();
        tuned.insert("PARITY".into(), parity.into());
        tuned.insert("PACKED_PLANS".into(), "on".into());
        tuned.insert("NEWSGROUPS".into(), many(n));
        match load(&tuned) {
            Ok(cfg) => assert!(
                ok && cfg.newsgroups.len() == n,
                "{n} groups, PARITY={parity}"
            ),
            Err(e) => {
                assert!(!ok, "{n} groups, PARITY={parity}: {e:?}");
                assert_eq!(
                    e,
                    ConfigError::Refused("PARITY with more than 255 NEWSGROUPS")
                );
            }
        }
    }
    // The limits of the slice settings themselves are accepted, and the
    // default slice is never above one extent.
    for (put, slice, sweep) in [
        ("16777216", "16777216", "off"),
        ("103809024", "6488064", " on "),
        ("103809024", "16777216", ""),
    ] {
        let mut tuned = prod.clone();
        tuned.insert("MAX_PUT_BYTES".into(), put.into());
        tuned.insert("SLICE_BYTES".into(), slice.into());
        tuned.insert("INTENT_SWEEP".into(), sweep.into());
        let cfg = load(&tuned).unwrap();
        assert_eq!(cfg.max_put_bytes.to_string(), put);
        assert_eq!(cfg.slice_bytes.to_string(), slice);
        assert_eq!(cfg.intent_sweep, sweep.trim() == "on");
    }
    // The collector of orphaned upload parts: its own switch, whatever
    // GC_MODE says.
    for (orphans, on) in [
        ("off", false),
        ("", false),
        ("  ", false),
        ("on", true),
        (" on ", true),
    ] {
        for mode in ["off", "disposable"] {
            let mut tuned = prod.clone();
            tuned.insert("GC_ORPHANS".into(), orphans.into());
            tuned.insert("GC_MODE".into(), mode.into());
            let cfg = load(&tuned).unwrap();
            assert_eq!(cfg.gc_orphans, on, "{orphans:?}");
            assert_eq!(cfg.gc_mode == GcMode::Disposable, mode == "disposable");
        }
    }
    for n in ["1", "10000"] {
        let mut capped = prod.clone();
        capped.insert("MAX_OBJECT_EXTENTS".into(), n.into());
        assert_eq!(load(&capped).unwrap().max_object_extents.to_string(), n);
    }
    let mut small = prod.clone();
    small.insert("MAX_EXTENT_BYTES".into(), "4194304".into());
    small.remove("MAX_PUT_BYTES");
    let cfg = load(&small).unwrap();
    assert_eq!((cfg.max_put_bytes, cfg.slice_bytes), (4_194_304, 4_194_304));
    // More than 16 slices (99 MiB in slices of 4 MiB are 25): the error
    // names the variable that was set, not the slice that followed from
    // the extent.
    small.remove("SLICE_BYTES");
    assert_eq!(
        set(&small, "MAX_PUT_BYTES", "103809024"),
        invalid("MAX_PUT_BYTES")
    );
    small.insert("MAX_PUT_BYTES".into(), "103809024".into());
    assert_eq!(
        set(&small, "SLICE_BYTES", "4194304"),
        invalid("SLICE_BYTES")
    );

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
    // Twice the plaintext is not enough: a cold read charges twice the
    // ciphertext (33,562,720 bytes for the largest extent), and a budget
    // under that could never charge one.
    for short in ["33554432", "33562719"] {
        assert_eq!(
            set(&prod, "INFLIGHT_BUDGET_BYTES", short),
            invalid("INFLIGHT_BUDGET_BYTES"),
            "{short}"
        );
    }
    // The job budget: from the request budget to 1.5 times it or
    // MAX_JOB_BUDGET_BYTES (90 MiB), whichever is more. At the shipped
    // 48 MiB request budget that is 90 MiB, not 72.
    assert_eq!(MAX_JOB_BUDGET_BYTES, 94_371_840);
    for bad in ["50331647", "94371841", "72MiB", "-1"] {
        assert_eq!(
            set(&prod, "JOB_BUDGET_BYTES", bad),
            invalid("JOB_BUDGET_BYTES"),
            "{bad}"
        );
    }
    for (good, want) in [
        ("50331648", 50_331_648),
        ("75497472", 75_497_472),
        ("75497473", 75_497_473),
        ("94371840", 94_371_840),
        ("", 50_331_648),
    ] {
        let mut vars = with_secrets(prod.clone(), PROVIDER_TLS);
        vars.insert("JOB_BUDGET_BYTES".into(), good.into());
        assert_eq!(load(&vars).unwrap().job_budget_bytes, want, "{good:?}");
    }
    // A request budget whose 1.5 times is above 90 MiB keeps that bound:
    // 64 MiB allows 96 MiB and not a byte more.
    for (job, ok) in [("100663296", true), ("100663297", false)] {
        let mut vars = with_secrets(prod.clone(), PROVIDER_TLS);
        vars.insert("INFLIGHT_BUDGET_BYTES".into(), "67108864".into());
        vars.insert("JOB_BUDGET_BYTES".into(), job.into());
        match ok {
            true => assert_eq!(load(&vars).unwrap().job_budget_bytes, 100_663_296),
            false => assert_eq!(load(&vars).unwrap_err(), invalid("JOB_BUDGET_BYTES")),
        }
    }
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

/// The dashboard's settings: a read-only token, the admin host and the
/// metrics sample. All three are optional.
#[test]
fn admin_read_token_host_and_metrics_sample() {
    let (prod, _) = wrangler_vars();
    let prod = with_secrets(prod, &prod_providers());
    let with = |pairs: &[(&str, &str)]| {
        let mut m = prod.clone();
        for (k, v) in pairs {
            m.insert(k.to_string(), v.to_string());
        }
        load(&m)
    };
    let invalid = |k: &str| ConfigError::Invalid(k.to_string());

    let unset = with(&[]).unwrap();
    assert!(unset.admin_read_token.is_none() && unset.admin_host.is_none());
    assert_eq!(unset.metrics_sample, 10);

    let read = "read-token-fixture-read-token-fixture";
    let set = with(&[
        ("ADMIN_READ_TOKEN", read),
        ("ADMIN_HOST", "admin.internal"),
        ("METRICS_SAMPLE", "1"),
    ])
    .unwrap();
    assert_eq!(
        set.admin_read_token.as_ref().map(|t| t.expose()),
        Some(read)
    );
    assert_eq!(set.admin_host.as_deref(), Some("admin.internal"));
    // The root's dot is the same name: kept as a request is compared.
    let dotted = with(&[("ADMIN_HOST", "admin.internal.")]).unwrap();
    assert_eq!(dotted.admin_host.as_deref(), Some("admin.internal"));
    assert_eq!(set.metrics_sample, 1);
    assert!(
        !format!("{set:?}").contains(read),
        "Debug leaks the read token"
    );

    // A read token as long as the admin token, and never the same one:
    // that would hand the dashboard every route.
    for bad in ["short", ADMIN_TOKEN_FIXTURE] {
        assert_eq!(
            with(&[("ADMIN_READ_TOKEN", bad)]).unwrap_err(),
            invalid("ADMIN_READ_TOKEN")
        );
    }
    for bad in [
        "Admin.Internal",
        "admin internal",
        "admin/x",
        "admin:443",
        "admin.internal..",
        "admin..internal",
        ".admin.internal",
    ] {
        assert_eq!(
            with(&[("ADMIN_HOST", bad)]).unwrap_err(),
            invalid("ADMIN_HOST")
        );
    }
    for bad in ["0", "-1", "ten", "10001"] {
        assert_eq!(
            with(&[("METRICS_SAMPLE", bad)]).unwrap_err(),
            invalid("METRICS_SAMPLE")
        );
    }
}

#[test]
fn config_errors_and_debug_never_show_secret_values() {
    let (prod, _) = wrangler_vars();
    let vars = with_secrets(prod, &prod_providers());
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
    let wake = Job::Wake {
        v: JOB_VERSION,
        extent: ExtentId::mint([0xff; 13]),
        generation: GenerationId::mint(T0, [0xff; 8]),
        stage: OutboxStage::Release,
        at: UnixMs(i64::MAX),
    };
    let json = wake.to_json();
    assert!(json.len() < 200, "{} bytes", json.len());
    assert!(json.starts_with(r#"{"t":"wake","v":1,"#), "{json}");
    assert_eq!(Job::from_json(&json).unwrap(), wake);
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
            "key_floors",
            "meta",
            "objects",
            "outbox",
            "provider_health",
            "provider_permits",
            "restore_state",
            "rollback_stamp",
            "scan_cursors",
            "scrub_state",
            "tx_guard",
            "upload_part_extents",
            "upload_parts",
            "uploads",
            "usage_buckets",
            "usage_global",
            "usage_hours",
            "usage_recounts",
            "verifications",
            "verify_escalations",
            "verify_raises",
            "write_intents",
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
        ("INSERT INTO verifications(extent_id,backbone,provider_id,verified_at,plan_rev,articles_ok,articles_total,result,kind,mode) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
         vec![text("x_1"), text("bb2"), text("p2"), t.clone(), i(1), i(1), i(1), text(VerifyResult::Ok.as_str()), text(VerifyKind::Size.column()), text(VerifyKind::Size.mode_column().unwrap())]),
        ("INSERT INTO verify_escalations(backbone,until,raised_at,extent_id,result) VALUES (?1,?2,?3,?4,?5)",
         vec![text("bb1"), SqlValue::Int(T0.plus_secs(86_400).0), t.clone(), text("x_1"), text(VerifyResult::Corrupt.as_str())]),
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
        ("INSERT INTO write_intents(extent_id,write_id,generation_id,state,created_at) VALUES (?1,?2,?3,?4,?5)",
         vec![text("x_3"), text("w_1"), SqlValue::Null, text("open"), t.clone()]),
    ];
    let changed = db.batch(rows).await.unwrap();
    // The committed extent (statement 5) also gets its reference row
    // in `generation_extents`, written by the migration's trigger.
    // The usage counters are on in this rig: the generation (3), both
    // extents (5, 12) and the outbox row (10) each move one counter row.
    let want: Vec<u64> = (0..changed.len())
        .map(|n| 1 + u64::from(n == 5) + u64::from([3, 5, 10, 12].contains(&n)))
        .collect();
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
        claimed_at: T0,
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
        yenc_name: Some("k3v9q0zx7m2a".into()),
        state: ArticleState::Planned,
        provider_id: None,
        posted_at: None,
        reposted_at: None,
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
        kind: VerifyKind::Body,
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
        class: PermitClass::Read,
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
    let _ = c
        .commit_generation(
            &commit,
            Some(&Precondition::Absent),
            Recorded::for_test(&commit.generation.id),
        )
        .await;
    let _ = c
        .delete_object_if(b, "a/k", &gen.id, &Precondition::Etag("\"e\"".into()), T0)
        .await;
    let _ = c.list(b, &query).await;
    let _ = c.object_status(b, "a/k").await;
    let _ = c
        .set_safety_state(&extent.id, SafetyState::Held, SafetyState::Deleted)
        .await;
    let _ = c.create_upload(&upload).await;
    let _ = c.upload(&target).await;
    let _ = c.put_upload_part(&target, &part, &extent, T0).await;
    let _ = c
        .complete_upload(
            &target,
            1,
            &[0; 32],
            &complete,
            Some(&Precondition::Exists),
            Recorded::for_test(&complete.generation.id),
        )
        .await;
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
    let _ = c.mark_reposted_many(&lease, &[0], T0).await;
    let _ = c.record_verification(&lease, &verification).await;
    let _ = c.backbone_status(&extent.id).await;
    let _ = c.body_checks(&extent.id).await;
    let _ = c.begin_release(&lease, 1, &bbs(), "[]", T0).await;
    let _ = c.finish_release(&lease, T0).await;
    let _ = c.due(T0, Resend::after(RESEND_SECS), 100).await;
    let _ = c.mark_sent(std::slice::from_ref(&extent.id), T0).await;
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

    // Catalogue over the selected test backend, every method.
    let catalog = SqlCatalog::new(TestSql::with_schema().unwrap());
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
        claimed_at: T0,
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
    let db = TestSql::with_schema_unrecorded().unwrap();
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
        let expected = db.fixture("too many bound parameters", "pg: bind failed");
        assert!(
            matches!(&err, BridgeError::Sql(m) if m.contains(expected)),
            "{err:?}"
        );
    }
    assert_eq!(
        count(&db, "gc").await,
        0,
        "an over-limit statement rolls back its batch"
    );

    // An integer crosses to D1 as a JS number: one that a number does
    // not hold exactly is refused, by the fixture as by the adapter.
    for ok in [MAX_SQL_INT, -MAX_SQL_INT, 0] {
        db.query("SELECT ?1", &[SqlValue::Int(ok)]).await.unwrap();
    }
    for bad in [MAX_SQL_INT + 1, -MAX_SQL_INT - 1, i64::MAX, i64::MIN] {
        for err in [
            db.query("SELECT ?1", &[SqlValue::Int(bad)])
                .await
                .unwrap_err(),
            db.exec(INSERT_GC_MARKER, &[text("x_a"), SqlValue::Int(bad)])
                .await
                .unwrap_err(),
            db.batch(vec![
                (INSERT_GC_MARKER, vec![text("x_a"), SqlValue::Int(T0.0)]),
                (INSERT_GC_MARKER, vec![text("x_b"), SqlValue::Int(bad)]),
            ])
            .await
            .unwrap_err(),
        ] {
            assert!(
                matches!(&err, BridgeError::Sql(m) if m.contains("outside JS safe range")),
                "{bad}: {err:?}"
            );
        }
    }
    assert_eq!(
        count(&db, "gc").await,
        0,
        "an out-of-range integer rolls back its batch"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn exec_and_batch_run_returning_and_select_to_completion() {
    let db = TestSql::with_schema_unrecorded().unwrap();
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
    let catalog = SqlCatalog::new(TestSql::with_schema().unwrap());
    assert!(catalog.guard_selftest().await.unwrap());
    assert!(catalog.guard_selftest().await.unwrap(), "repeatable");
    assert_eq!(
        count(&catalog.sql, "meta").await,
        0,
        "no marker left behind"
    );
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

#[test]
fn s3_hosts_lists_more_hosts_with_a_class() {
    use velmora_bridge::config::{HostClass, S3Host};

    let (_, dev) = wrangler_vars();
    let base = with_secrets(dev, PROVIDER_PLAIN);
    let primary = base["S3_HOST"].as_str();
    let hosts = |value: Option<&str>| {
        let mut m = base.clone();
        if let Some(value) = value {
            m.insert("S3_HOSTS".into(), value.into());
        }
        load(&m)
    };

    for value in [None, Some(""), Some(" \t ")] {
        let cfg = hosts(value).unwrap();
        assert!(cfg.s3_hosts.is_empty(), "{value:?}");
        assert_eq!(cfg.s3_host_for(primary), Some((primary, HostClass::Legacy)));
    }

    let cfg = hosts(Some("s3.customer.example=customer")).unwrap();
    assert_eq!(
        cfg.s3_hosts,
        [S3Host {
            name: "s3.customer.example".into(),
            class: HostClass::Customer,
        }]
    );
    assert_eq!(
        cfg.s3_host_for("S3.Customer.Example"),
        Some(("s3.customer.example", HostClass::Customer))
    );
    assert_eq!(cfg.s3_host_for("other.example"), None);
    assert_eq!(cfg.s3_host_for("s3.customer.example:443"), None);

    let cfg = hosts(Some(" a.example=legacy , b.example:8443=customer ")).unwrap();
    assert_eq!(
        cfg.s3_hosts,
        [
            S3Host {
                name: "a.example".into(),
                class: HostClass::Legacy,
            },
            S3Host {
                name: "b.example:8443".into(),
                class: HostClass::Customer,
            },
        ]
    );
    assert_eq!(
        cfg.all_s3_hosts().collect::<Vec<_>>(),
        [primary, "a.example", "b.example:8443"]
    );

    let cfg = hosts(Some("a.example=legacy,b-a.example=customer")).unwrap();
    assert_eq!(
        cfg.all_s3_hosts().collect::<Vec<_>>(),
        [primary, "a.example", "b-a.example"]
    );

    let eight = (1..=8)
        .map(|i| format!("s3-{i}.example=legacy"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(hosts(Some(&eight)).unwrap().s3_hosts.len(), 8);

    for bad in [
        "a.example",
        "a.example=",
        "=customer",
        "a.example=Customer",
        "a.example=public",
        "A.example=customer",
        "a.example=customer,",
        ",a.example=customer",
        "a.example=customer,a.example=legacy",
        &format!("{}=customer", primary.to_ascii_uppercase()),
        &format!("{primary}=customer"),
        &format!("eu.{primary}=customer"),
        "a.example=legacy,x.a.example=customer",
        "x.a.example=customer,a.example=legacy",
        "a.example:8443=legacy,x.a.example=customer",
        "a b.example=customer",
        "a.example:0=customer",
        "a.example.=customer",
        "a.example.:8443=customer",
        "a..example=customer",
        ".a.example=legacy",
        "a.example=customer=legacy",
        &format!("{eight},s3-9.example=legacy"),
    ] {
        assert_eq!(
            hosts(Some(bad)).unwrap_err(),
            ConfigError::Invalid("S3_HOSTS".into()),
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
    // A list of one gets the second backbone prod asks for; the entries
    // under test stay first.
    let second = match entries.len() {
        1 => format!(",{SECOND_BACKBONE}"),
        _ => String::new(),
    };
    let json = format!("[{}{second}]", entries.join(","));
    load(&with_secrets(prod, &json)).map(|cfg| cfg.providers)
}

/// `release` says whether a provider's backbone counts toward releasing
/// the safety copy. It is optional and true when absent; one provider
/// saying false speaks for its whole backbone. A list with fewer
/// counting, readable backbones than `REQUIRED_BACKBONES` still loads,
/// so the Worker keeps serving, and says that the release is paused.
#[test]
fn release_backbones_are_counted_and_too_few_pause_the_release() {
    let invalid = Err(ConfigError::Invalid("NNTP_PROVIDERS".into()));
    // `on` puts the provider on a named backbone.
    let on = |id: &str, backbone: &str, extra: &str| {
        provider_json(id, extra).replace(&format!("bb-{id}"), backbone)
    };
    let off = r#""release":false"#;
    let flags = |entries: &[String]| -> std::result::Result<Vec<bool>, ConfigError> {
        let (prod, _) = wrangler_vars();
        let json = format!("[{}]", entries.join(","));
        let cfg = load(&with_secrets(prod, &json))?;
        Ok(cfg.providers.iter().map(|p| p.release).collect())
    };
    // Whether the list loads with the release paused.
    let paused = |entries: &[String]| -> std::result::Result<bool, ConfigError> {
        let (prod, _) = wrangler_vars();
        let json = format!("[{}]", entries.join(","));
        let cfg = load(&with_secrets(prod, &json))?;
        let warning = cfg.release_paused();
        if let Some(text) = &warning {
            assert!(text.starts_with("release paused: "), "{text}");
            assert!(text.contains("REQUIRED_BACKBONES is 2"), "{text}");
        }
        Ok(warning.is_some())
    };

    // Absent means it counts; so does an explicit true.
    assert_eq!(
        flags(&[
            provider_json("a", ""),
            provider_json("b", r#""release":true"#)
        ]),
        Ok(vec![true, true])
    );
    // Two that count and one that does not.
    assert_eq!(
        flags(&[
            provider_json("a", off),
            provider_json("b", ""),
            provider_json("c", "")
        ]),
        Ok(vec![false, true, true])
    );
    for bad in [r#""no""#, "0", "1", "null", r#""false""#] {
        let entry = provider_json("a", &format!(r#""release":{bad}"#));
        assert_eq!(flags(&[entry, provider_json("b", "")]), invalid, "{bad}");
    }

    // One backbone, however many accounts.
    assert_eq!(paused(&[provider_json("a", "")]), Ok(true));
    assert_eq!(
        paused(&[on("a", "one", ""), on("b", " ONE ", "")]),
        Ok(true)
    );
    // Two backbones, one of them marked.
    assert_eq!(
        paused(&[provider_json("a", ""), provider_json("b", off)]),
        Ok(true)
    );
    // One account's mark is its backbone's: the other account on it does
    // not bring the backbone back, whichever comes first, and whether the
    // marked one reads, only posts, or is disabled.
    let unread = |json: String| json.replace(r#""read":true"#, r#""read":false"#);
    for marked in [
        on("b", "two", off),
        unread(on("b", "two", off)),
        on("b", "two", &format!(r#"{off},"enabled":false"#)),
    ] {
        let pair = [marked.clone(), on("c", "Two", "")];
        let mut list = vec![provider_json("a", "")];
        list.extend(pair.clone());
        assert_eq!(paused(&list), Ok(true), "{marked}");
        list = vec![pair[1].clone(), pair[0].clone(), provider_json("a", "")];
        assert_eq!(paused(&list), Ok(true), "{marked}");
        // A third backbone that counts makes the two.
        list.push(provider_json("d", ""));
        assert_eq!(paused(&list), Ok(false), "{marked}");
    }
    // A backbone nothing can be read from, or whose reader is disabled,
    // proves nothing and does not count.
    for other in [
        unread(provider_json("b", "")),
        provider_json("b", r#""enabled":false"#),
    ] {
        let list = [provider_json("a", ""), other];
        assert_eq!(paused(&list), Ok(true), "{}", list[1]);
    }

    // Dev asks for one backbone: one that counts, and not one that does not.
    let (_, dev) = wrangler_vars();
    let dev_load = |extra: &str| {
        let json = PROVIDER_PLAIN.replace(r#""max_conns":2"#, &format!(r#""max_conns":2{extra}"#));
        load(&with_secrets(dev.clone(), &json)).map(|cfg| cfg.release_paused())
    };
    assert_eq!(dev_load(""), Ok(None));
    let warning = dev_load(r#","release":false"#).unwrap().unwrap();
    assert_eq!(
        warning,
        "release paused: 0 backbone(s) count toward release, REQUIRED_BACKBONES is 1; \
         pinned copies stay held"
    );
}

/// A provider list written before the pool settings existed still loads,
/// and means what it meant: first priority, no retention limit, no pool,
/// enabled.
#[test]
fn old_provider_config_parses_with_pool_defaults() {
    let (prod, _) = wrangler_vars();
    let cfg = load(&with_secrets(prod, &prod_providers())).unwrap();
    assert_eq!(cfg.providers.len(), 2);
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

fn proxy_json(host: &str, port: u32, user: &str, pass: &str) -> String {
    format!(r#"{{"host":"{host}","port":{port},"user":"{user}","pass":"{pass}"}}"#)
}

/// `proxies` is optional: without it a provider is connected directly.
/// With it, every entry is a SOCKS5 proxy with a login, kept in order.
/// Neither the provider's nor a proxy's `Debug` shows a proxy's host or
/// login.
#[test]
fn provider_proxies_parse_in_order_and_are_redacted() {
    let direct = providers_of(&[provider_json("a", "")]).unwrap();
    assert!(direct[0].proxies.is_empty());

    let proxies = format!(
        r#""max_ips":2,"proxies":[{},{}]"#,
        proxy_json("first.proxy.example", 1080, "proxy-login", "proxy-secret"),
        proxy_json("203.0.113.9", 40000, "other-login", "other-secret"),
    );
    let providers = providers_of(&[provider_json("a", &proxies)]).unwrap();
    let got = &providers[0].proxies;
    assert_eq!(got.len(), 2);
    assert_eq!(
        (got[0].host.as_str(), got[0].port, got[0].user.as_str()),
        ("first.proxy.example", 1080, "proxy-login")
    );
    assert_eq!(got[0].pass, "proxy-secret");
    assert_eq!((got[1].host.as_str(), got[1].port), ("203.0.113.9", 40000));

    let shown = format!("{:?} {:?} {:?}", providers[0], got, got[0]);
    for secret in [
        "first.proxy.example",
        "203.0.113.9",
        "40000",
        "proxy-login",
        "proxy-secret",
        "other-login",
        "other-secret",
    ] {
        assert!(!shown.contains(secret), "{shown}");
    }
    assert!(shown.contains("proxies: 2"), "{shown}");
}

/// A `proxies` list that cannot be used as written is refused as a
/// whole: nothing in it is dropped or guessed, and a provider is never
/// left to connect directly because its proxy entry was wrong.
#[test]
fn provider_proxies_fail_closed() {
    let invalid = Err(ConfigError::Invalid("NNTP_PROVIDERS".into()));
    let ok = proxy_json("proxy.example", 1080, "u", "p");
    let with = |list: &[String]| {
        let extra = format!(r#""max_ips":4,"proxies":[{}]"#, list.join(","));
        providers_of(&[provider_json("a", &extra)])
    };
    assert!(with(std::slice::from_ref(&ok)).is_ok());
    // A list that is there and empty is refused: only a provider
    // without the field is connected directly.
    assert_eq!(with(&[]), invalid);

    let long = "x".repeat(256);
    let bad = [
        // Port, login and host that SOCKS5 or the network cannot carry.
        proxy_json("proxy.example", 0, "u", "p"),
        proxy_json("proxy.example", 65536, "u", "p"),
        proxy_json("proxy.example", 1080, "", "p"),
        proxy_json("proxy.example", 1080, "u", ""),
        proxy_json("proxy.example", 1080, &long, "p"),
        proxy_json("proxy.example", 1080, "u", &long),
        proxy_json("", 1080, "u", "p"),
        proxy_json("proxy example", 1080, "u", "p"),
        proxy_json("proxy.example:1080", 1080, "u", "p"),
        proxy_json("socks5://proxy.example", 1080, "u", "p"),
        // Addresses no proxy of the bridge can have.
        proxy_json("127.0.0.1", 1080, "u", "p"),
        proxy_json("10.1.2.3", 1080, "u", "p"),
        proxy_json("100.64.0.1", 1080, "u", "p"),
        proxy_json("100.127.255.254", 1080, "u", "p"),
        proxy_json("192.168.1.1", 1080, "u", "p"),
        proxy_json("169.254.1.1", 1080, "u", "p"),
        proxy_json("0.0.0.0", 1080, "u", "p"),
        proxy_json("::1", 1080, "u", "p"),
        proxy_json("fd00::1", 1080, "u", "p"),
        proxy_json("::ffff:10.0.0.1", 1080, "u", "p"),
    ];
    for entry in bad {
        assert_eq!(with(std::slice::from_ref(&entry)), invalid, "{entry}");
        // Not next to a good one either.
        assert_eq!(with(&[ok.clone(), entry.clone()]), invalid, "{entry}");
    }
    // Next to the shared range, on both sides: public.
    for host in ["100.63.255.255", "100.128.0.1"] {
        assert!(with(&[proxy_json(host, 1080, "u", "p")]).is_ok(), "{host}");
    }
    // A login of the longest length SOCKS5 carries is in order.
    let longest = "x".repeat(255);
    assert!(with(&[proxy_json("proxy.example", 1080, &longest, &longest)]).is_ok());

    // The same proxy twice, also in another case; more than the most.
    assert_eq!(with(&[ok.clone(), ok.clone()]), invalid);
    let upper = proxy_json("PROXY.example", 1080, "u2", "p2");
    assert_eq!(with(&[ok.clone(), upper]), invalid);
    let many: Vec<String> = (0..=velmora_bridge::config::MAX_PROXIES)
        .map(|i| proxy_json(&format!("p{i}.proxy.example"), 1080, "u", "p"))
        .collect();
    assert_eq!(with(&many), invalid);
    assert!(with(&many[1..]).is_ok());

    // Every proxy may be in use at the same time, each with its own
    // address: more proxies than the address limit are refused, and so
    // is a list without the limit, which nothing could be checked
    // against.
    for list in [&many[1..], &many[1..2]] {
        let extra = format!(r#""proxies":[{}]"#, list.join(","));
        assert_eq!(providers_of(&[provider_json("a", &extra)]), invalid);
    }
    let capped = |ips: u32, list: &[String]| {
        let extra = format!(r#""max_ips":{ips},"proxies":[{}]"#, list.join(","));
        providers_of(&[provider_json("a", &extra)])
    };
    let three = &many[1..];
    assert_eq!(three.len(), 3);
    assert_eq!(capped(1, three), invalid);
    assert_eq!(capped(2, three), invalid);
    assert!(capped(3, three).is_ok());
    assert!(capped(4, three).is_ok());
    assert_eq!(capped(1, &three[..2]), invalid);
    assert!(capped(2, &three[..2]).is_ok());
    assert!(capped(1, &three[..1]).is_ok());

    // The proxy is given the provider's host as a name, and the
    // certificate is checked against that name: a provider known by an
    // address, or by a name the request cannot carry, takes no proxy.
    for host in ["203.0.113.5", "nntp", "nntp_1.invalid"] {
        let entry = |extra: &str| {
            let json = provider_json("a", extra).replace("nntp.invalid", host);
            assert!(json.contains(host));
            providers_of(&[json])
        };
        assert!(entry("").is_ok(), "{host}");
        let extra = format!(r#""max_ips":4,"proxies":[{ok}]"#);
        assert_eq!(entry(&extra), invalid, "{host}");
        // The same entry on a provider known by a name is accepted.
        assert!(providers_of(&[provider_json("a", &extra)]).is_ok());
    }

    // Unknown or missing members, and the wrong shape.
    for extra in [
        r#""proxies":[{"host":"proxy.example","port":1080,"user":"u","pass":"p","fallback":"direct"}]"#,
        r#""proxies":[{"host":"proxy.example","port":1080,"user":"u"}]"#,
        r#""proxies":[{"host":"proxy.example","port":1080}]"#,
        r#""proxies":{"host":"proxy.example","port":1080,"user":"u","pass":"p"}"#,
        r#""proxies":["proxy.example:1080"]"#,
        r#""proxies":null"#,
        r#""proxy":{"host":"proxy.example","port":1080,"user":"u","pass":"p"}"#,
        r#""proxy_fallback":"direct""#,
    ] {
        // With the address limit, so that the entry is the only fault.
        let extra = format!(r#""max_ips":4,{extra}"#);
        assert_eq!(
            providers_of(&[provider_json("a", &extra)]),
            invalid,
            "{extra}"
        );
    }
}

/// Through a proxy there is no plaintext: `proxies` on a provider
/// without TLS is refused, in every environment.
#[test]
fn provider_proxies_need_tls() {
    let (prod, dev) = wrangler_vars();
    let entry = |tls: bool, extra: &str| {
        format!(
            r#"[{{"id":"a","host":"nntp.invalid","port":563,"tls":{tls},"user":"u","pass":"p","backbone":"bb","post":true,"read":true,"max_conns":2{extra}}}]"#
        )
    };
    let proxies = format!(
        r#","max_ips":4,"proxies":[{}]"#,
        proxy_json("proxy.example", 1080, "u", "p")
    );
    let loads = |vars: &_, json: &str| load(&with_secrets(Clone::clone(vars), json)).map(|_| ());
    for vars in [&prod, &dev] {
        assert_eq!(loads(vars, &entry(true, &proxies)), Ok(()));
        assert_eq!(
            loads(vars, &entry(false, &proxies)),
            Err(ConfigError::Invalid("NNTP_PROVIDERS".into()))
        );
    }
    // The same plaintext provider without a proxy is in order in dev:
    // it is the proxy that is refused.
    assert_eq!(loads(&dev, &entry(false, "")), Ok(()));
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

/// `hosts` lists more host names of one account next to `host`. It is
/// optional: an entry without it has `host` alone, as before.
#[test]
fn provider_hosts_parse_and_extend_host() {
    let providers = providers_of(&[
        provider_json("a", r#""hosts":["us.nntp.invalid","eu.nntp.invalid"]"#),
        provider_json("b", r#""hosts":[]"#),
        provider_json("c", ""),
    ])
    .unwrap();
    assert_eq!(
        providers[0].endpoints(),
        ["nntp.invalid", "us.nntp.invalid", "eu.nntp.invalid"]
    );
    assert_eq!(providers[1].endpoints(), ["nntp.invalid"]);
    assert_eq!(providers[2].endpoints(), ["nntp.invalid"]);
    // Host names stay out of `Debug`, like `host`: only their number shows.
    let shown = format!("{:?}", providers[0]);
    assert!(
        !shown.contains("us.nntp.invalid") && shown.contains("hosts: 2"),
        "{shown}"
    );
}

/// `host_select` is `fastest` (the default) or `ordered`.
#[test]
fn provider_host_select_parses_and_fails_closed() {
    let invalid = Err(ConfigError::Invalid("NNTP_PROVIDERS".into()));
    let hosts = r#""hosts":["us.nntp.invalid"]"#;
    let providers = providers_of(&[
        provider_json("a", hosts),
        provider_json("b", &format!(r#"{hosts},"host_select":"fastest""#)),
        provider_json("c", &format!(r#"{hosts},"host_select":"ordered""#)),
    ])
    .unwrap();
    let modes: Vec<HostSelect> = providers.iter().map(|p| p.host_select).collect();
    assert_eq!(
        modes,
        [
            HostSelect::Fastest,
            HostSelect::Fastest,
            HostSelect::Ordered
        ]
    );
    let one = |extra: &str| providers_of(&[provider_json("a", extra)]);
    for bad in [r#""Ordered""#, r#""nearest""#, "1", "null", "true"] {
        assert_eq!(one(&format!(r#""host_select":{bad}"#)), invalid, "{bad}");
    }
}

#[test]
fn provider_hosts_fail_closed() {
    let invalid = Err(ConfigError::Invalid("NNTP_PROVIDERS".into()));
    let one = |extra: &str| providers_of(&[provider_json("a", extra)]);

    // Not a list of names.
    for bad in [
        r#""hosts":"us.nntp.invalid""#,
        r#""hosts":[1]"#,
        r#""hosts":null"#,
        r#""hosts":[""]"#,
        r#""hosts":["us.nntp.invalid:5563"]"#,
        r#""hosts":["us nntp"]"#,
        r#""hosts":["-us.nntp.invalid"]"#,
        r#""hosts":["user@us.nntp.invalid"]"#,
        r#""hosts":["us-.nntp.invalid"]"#,
        r#""hosts":["us..nntp.invalid"]"#,
        r#""hosts":[".us.nntp.invalid"]"#,
        r#""hosts":["us.nntp.invalid."]"#,
        r#""hosts":["localhost"]"#,
        r#""hosts":["192.0.2.1"]"#,
        r#""hosts":["news.123"]"#,
    ] {
        assert_eq!(one(bad), invalid, "{bad}");
    }
    // A label is at most 63 bytes, the name at most 253.
    let label = |n: usize| format!(r#""hosts":["{}.nntp.invalid"]"#, "a".repeat(n));
    assert!(one(&label(63)).is_ok());
    assert!(one(r#""hosts":["news.example","n1.example.co"]"#).is_ok());
    assert_eq!(one(&label(64)), invalid);
    assert!(one(&format!(r#""hosts":["{}"]"#, labels_of(4))).is_ok()); // 251 bytes
    let long = format!(r#""hosts":["{}.a.b"]"#, labels_of(4));
    assert_eq!(one(&long), invalid); // 255 bytes
                                     // No host twice, whatever its case, and not `host` again.
    assert_eq!(
        one(r#""hosts":["us.nntp.invalid","US.nntp.invalid"]"#),
        invalid
    );
    assert_eq!(one(r#""hosts":["NNTP.invalid"]"#), invalid);
    // At most `MAX_HOSTS`.
    let names = |n: usize| -> String {
        let list: Vec<String> = (0..n).map(|i| format!(r#""h{i}.nntp.invalid""#)).collect();
        format!(r#""hosts":[{}]"#, list.join(","))
    };
    assert!(one(&names(velmora_bridge::config::MAX_HOSTS)).is_ok());
    assert_eq!(one(&names(velmora_bridge::config::MAX_HOSTS + 1)), invalid);
}

/// `n` labels of 62 bytes, joined with dots.
fn labels_of(n: usize) -> String {
    (0..n).map(|_| "a".repeat(62)).collect::<Vec<_>>().join(".")
}

/// The local fake server is one plaintext loopback host: `hosts` is for
/// TLS providers only.
#[test]
fn provider_hosts_only_on_tls() {
    let (_, dev) = wrangler_vars();
    let plain = r#"[{"id":"p1","host":"127.0.0.1","hosts":["localhost"],"port":11119,"tls":false,"user":"","pass":"","backbone":"bb","post":true,"read":true,"max_conns":2}]"#;
    assert_eq!(
        load(&with_secrets(dev.clone(), plain)).map(|_| ()),
        Err(ConfigError::Invalid("NNTP_PROVIDERS".into()))
    );
    let one_host = plain.replace(r#""hosts":["localhost"],"#, "");
    assert!(load(&with_secrets(dev, &one_host)).is_ok());
}

/// `drill_conns` is optional and `0` without it: a drill then reads
/// over one connection of the provider's own. Stated, it is refused
/// where a drill connection could take something from production: on a
/// provider that is not read, and on a direct account with an address
/// limit, where it would be one more address. No provider may have the
/// name the drill slots are kept under.
#[test]
fn provider_drill_conns_parse_and_fail_closed() {
    let invalid = Err(ConfigError::Invalid("NNTP_PROVIDERS".into()));
    let one = |extra: &str| providers_of(&[provider_json("a", extra)]);

    let plain = one("").unwrap();
    assert_eq!(plain[0].drill_conns, 0);
    let with = one(r#""drill_conns":4"#).unwrap();
    assert_eq!((with[0].drill_conns, with[0].max_conns), (4, 2));
    assert_eq!(with[0].drill_key(), "a/drill");
    assert!(format!("{:?}", with[0]).contains("drill_conns: 4"));

    assert_eq!(one(r#""drill_conns":100000"#), invalid);
    assert_eq!(one(r#""drill_conns":-1"#), invalid);
    assert_eq!(one(r#""drill_conns":"4""#), invalid);
    // Not read: nothing to drill over.
    let unread =
        provider_json("a", r#""drill_conns":1"#).replace(r#""read":true"#, r#""read":false"#);
    assert_eq!(providers_of(std::slice::from_ref(&unread)), invalid);
    assert!(providers_of(&[unread.replace(r#""drill_conns":1"#, r#""drill_conns":0"#)]).is_ok());
    // An address limit: only through the account's proxies.
    assert_eq!(one(r#""max_ips":1,"drill_conns":1"#), invalid);
    let proxied = format!(
        r#""max_ips":1,"drill_conns":1,"proxies":[{}]"#,
        proxy_json("proxy.example", 1080, "proxy-login", "proxy-secret")
    );
    assert_eq!(one(&proxied).unwrap()[0].drill_conns, 1);
    // The name of a provider's drill slots is no provider's id.
    assert_eq!(providers_of(&[provider_json("a/drill", "")]), invalid);
    assert_eq!(
        providers_of(&[provider_json("a", ""), provider_json("a/drill", "")]),
        invalid
    );
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

/// The shipped `POST_SOCKETS` and `JOB_BUDGET_BYTES` let three post jobs
/// of full-size extents and a verify job share one isolate's byte budget,
/// with parity (`PARITY`) and without, and never a fourth post job of
/// either kind. The queue's invocations share isolates (and so do the
/// post queues), so with a larger socket count or a smaller job budget a
/// post job waits for another: with parity at 72 MiB only two fitted, and
/// posting was 20% slower than without. Three post jobs with parity at
/// once is what the shipped limit was measured with.
#[test]
fn three_post_jobs_and_a_verify_job_fit_the_shipped_budget() {
    use velmora::media::{FileKey, Profile, Sealer};
    use velmora::rng::SystemRng;
    use velmora_bridge::articles::article_spans;
    use velmora_bridge::jobs::{job_bytes, parity_job_bytes};
    use velmora_bridge::parity::parity_count;

    let (prod, _) = wrangler_vars();
    let budget: u64 = prod["JOB_BUDGET_BYTES"].parse().unwrap();
    let sockets: u32 = prod["POST_SOCKETS"].parse().unwrap();
    let max_extent: usize = prod["MAX_EXTENT_BYTES"].parse().unwrap();
    let key = FileKey::generate(&mut SystemRng).unwrap();
    let sealer = Sealer::random(&Profile::drive(), &key, &mut SystemRng).unwrap();
    let cipher_size = sealer.seal_to_vec(&vec![0u8; max_extent]).unwrap().len() as u64;

    // What `run_leased` charges a post job of a new plan with the switch
    // on: the job, and the parity of its articles.
    let plain = job_bytes(OutboxStage::Post, cipher_size, sockets);
    let parity = parity_count(article_spans(cipher_size).len());
    let with_parity = plain + parity_job_bytes(cipher_size, parity);
    let verify = job_bytes(OutboxStage::Verify, cipher_size, sockets);
    assert_eq!(
        (parity, plain),
        (4, 26_218_544),
        "a 16 MiB extent at 6 sockets: 25.00 MiB"
    );
    assert_eq!(
        with_parity, 30_545_264,
        "29.13 MiB with its 4 parity shards and the codec's 2"
    );
    let budget_of = || {
        ByteBudget::new(prod["INFLIGHT_BUDGET_BYTES"].parse().unwrap()).with_job_capacity(budget)
    };
    for post in [plain, with_parity] {
        assert!(
            3 * post + verify <= budget,
            "three post jobs ({post} B each) and a verify job ({verify} B) exceed {budget} B"
        );
        let jobs = budget_of();
        let held: Vec<_> = [post, post, post, verify]
            .into_iter()
            .map(|bytes| jobs.try_charge_job(bytes).expect("fits"))
            .collect();
        assert!(jobs.try_charge_job(post).is_none());
        drop(held);
    }
    // No fourth post job, of any kind and in any mix, even with nothing
    // else charged.
    for fourth in [plain, with_parity] {
        let jobs = budget_of();
        let held: Vec<_> = [plain, plain, plain]
            .into_iter()
            .map(|bytes| jobs.try_charge_job(bytes).expect("fits"))
            .collect();
        assert!(jobs.try_charge_job(fourth).is_none(), "{fourth}");
        drop(held);
    }
    // The shipped budget is the most a deployment may set, and no more
    // than the three jobs with parity and the verify job need, rounded
    // up to a MiB.
    assert_eq!(budget, MAX_JOB_BUDGET_BYTES);
    assert_eq!(budget, (3 * with_parity + verify).div_ceil(1 << 20) << 20);
}

/// The queue tables of the shipped `wrangler.toml`: producers as
/// (binding, queue) and the queues with a consumer, for production
/// (`env` empty) or `env.dev.`.
fn wrangler_queues(env: &str) -> (Vec<(String, String)>, Vec<String>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../workers/s3-bridge/wrangler.toml"
    );
    let toml = std::fs::read_to_string(path).unwrap();
    let value = |line: &str, key: &str| -> Option<String> {
        let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
        Some(rest.trim().trim_matches('"').to_string())
    };
    let (mut producers, mut consumers) = (Vec::new(), Vec::new());
    let (mut section, mut binding) = (String::new(), None);
    for line in toml.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line.to_string();
            binding = None;
        } else if section == format!("[[{env}queues.producers]]") {
            if let Some(name) = value(line, "binding") {
                binding = Some(name);
            } else if let Some(queue) = value(line, "queue") {
                producers.push((binding.take().expect("binding before queue"), queue));
            }
        } else if section == format!("[[{env}queues.consumers]]") {
            consumers.extend(value(line, "queue"));
        }
    }
    (producers, consumers)
}

/// Every queue the shipped configuration sends jobs to has exactly one
/// consumer (a queue that is only read is being emptied), and the bindings of a kind are numbered without a gap: an
/// extent's jobs always go to the same queue, so a queue nobody reads
/// would hold the same extents back for good. Production also binds the
/// queue of the jobs without an extent (`AUX_Q`); dev leaves it out, which
/// keeps the fallback to the first verify queue in use.
#[test]
fn every_shipped_job_queue_has_one_consumer_and_bindings_have_no_gap() {
    for env in ["", "env.dev."] {
        let (producers, consumers) = wrangler_queues(env);
        let aux = producers.iter().filter(|(b, _)| b == "AUX_Q").count();
        assert_eq!(aux, usize::from(env.is_empty()), "{env}AUX_Q bindings");
        for kind in ["POST_Q", "VERIFY_Q"] {
            let mut numbers: Vec<u32> = producers
                .iter()
                .filter_map(|(binding, _)| binding.strip_prefix(kind))
                .map(|n| if n.is_empty() { 1 } else { n.parse().unwrap() })
                .collect();
            numbers.sort_unstable();
            let expected: Vec<u32> = (1..=numbers.len() as u32).collect();
            assert!(!numbers.is_empty(), "{env}{kind} is not bound");
            assert!(
                numbers.len() <= 8,
                "{env}{kind}: more than the Worker reads"
            );
            assert_eq!(numbers, expected, "{env}{kind} bindings");
            assert!(!numbers.contains(&0));
        }
        assert_eq!(
            producers.len(),
            producers
                .iter()
                .filter(|(b, _)| {
                    b.starts_with("POST_Q") || b.starts_with("VERIFY_Q") || b == "AUX_Q"
                })
                .count(),
            "{env}: a producer of another kind"
        );
        // A consumer without a producer is a queue being emptied before
        // it is taken away; a producer without a consumer is never right.
        let mut sent: Vec<&String> = producers.iter().map(|(_, queue)| queue).collect();
        for queue in &sent {
            let readers = consumers.iter().filter(|c| c == queue).count();
            assert_eq!(readers, 1, "{env}: consumers of {queue}");
        }
        let mut read: Vec<&String> = consumers.iter().collect();
        read.sort();
        read.dedup();
        assert_eq!(read.len(), consumers.len(), "{env}: a queue read twice");
        sent.sort();
        sent.dedup();
        assert_eq!(sent.len(), producers.len(), "{env}: a queue bound twice");
    }
}

/// The tables of the shipped `wrangler.toml` by their first key, split
/// into production's and those of an `[env.*]` environment, plus the
/// first key of every line above the first table (root keys, which
/// may name a table inline or dotted, e.g. `exports.X.type = ...`). A
/// TOML header names its table from the root wherever it stands, so a
/// table is production's by its name, not by its place in the file.
/// Spaces, quotes and a trailing comment do not change a name.
/// The keys and values of one table of the shipped `wrangler.toml`, as
/// `key=value` with the value's quotes removed, sorted. The table is
/// found by its header with spaces removed (`[exports . X]` is
/// `[exports.X]`); a value keeps its inner spaces, so `"sql ite"` is not
/// `sqlite`.
fn table_body(header: &str) -> Vec<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../workers/s3-bridge/wrangler.toml"
    );
    let toml = std::fs::read_to_string(path).unwrap();
    let squeeze = |s: &str| -> String { s.chars().filter(|c| !c.is_whitespace()).collect() };
    let want = squeeze(header);
    let mut body = Vec::new();
    let mut inside = false;
    for line in toml.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            inside = squeeze(line) == want;
            continue;
        }
        if !inside || line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').expect("a key = value line");
        let value = value.trim();
        let unquoted = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        body.push(format!("{}={unquoted}", key.trim()));
    }
    body.sort();
    body
}

fn wrangler_tables() -> (Vec<String>, Vec<String>, Vec<String>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../workers/s3-bridge/wrangler.toml"
    );
    let toml = std::fs::read_to_string(path).unwrap();
    let name = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
            .collect()
    };
    let (mut prod, mut env, mut root) = (Vec::new(), Vec::new(), Vec::new());
    let mut seen_table = false;
    for line in toml.lines() {
        // No name in this file holds a `#`, so a comment starts at the first.
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            seen_table = true;
            let header = line[..line.rfind(']').unwrap() + 1].to_string();
            let path = name(header.trim_matches(|c| c == '[' || c == ']'));
            if path.starts_with("env.") {
                env.push(path);
            } else {
                prod.push(path);
            }
        } else if !seen_table {
            if let Some((key, _)) = line.split_once('=') {
                root.push(name(key));
            }
        }
    }
    (prod, env, root)
}

/// A Durable Object class can never be rolled back past, so production
/// declares and binds the permit gate in deploys of their own, after the
/// code that knows `PERMITS` has run ("Shipping the gate" in
/// ops/README.md). Deploy 2 declared the class `PermitGate`; deploy 3
/// added the `PERMIT_GATE` binding and `[version_metadata]`; deploy 4,
/// a deploy of its own, set production's `PERMITS` to `"do"` (dev keeps
/// `"d1"`; its end-to-end run sets `do` itself). The legacy
/// `[[migrations]]` array is never used: once a class is declared by
/// `exports`, a deploy that declares one by `[[migrations]]` is refused.
#[test]
fn production_declares_and_binds_the_gate_and_takes_permits_from_it() {
    let (prod, env, root) = wrangler_tables();
    let gate = |key: &str| {
        let first = key.split('.').next().unwrap_or_default();
        [
            "exports",
            "durable_objects",
            "migrations",
            "version_metadata",
        ]
        .contains(&first)
    };
    let declared: Vec<&String> = prod.iter().chain(&root).filter(|k| gate(k)).collect();
    assert_eq!(
        declared,
        [
            "exports.PermitGate",
            "durable_objects.bindings",
            "version_metadata"
        ],
        "production declares the class, binds it and has version metadata, nothing else"
    );
    assert_eq!(
        table_body("[[durable_objects.bindings]]"),
        ["class_name=PermitGate", "name=PERMIT_GATE"]
    );
    assert_eq!(
        table_body("[version_metadata]"),
        ["binding=CF_VERSION_METADATA"]
    );
    // The storage of a class is fixed when it is created, and a deletion
    // has no rollback: the table holds exactly these two keys, in
    // production and in dev.
    for header in ["[exports.PermitGate]", "[env.dev.exports.PermitGate]"] {
        assert_eq!(
            table_body(header),
            ["storage=sqlite", "type=durable-object"],
            "{header}"
        );
    }
    let (vars, dev) = wrangler_vars();
    assert_eq!(vars.get("PERMITS").map(String::as_str), Some("do"));
    assert_eq!(dev.get("PERMITS").map(String::as_str), Some("d1"));
    assert!(
        !env.iter().any(|t| t.ends_with(".migrations")),
        "a legacy [[migrations]] table"
    );
    // Dev (the end-to-end run with PERMITS = "do") declares and binds it.
    for table in [
        "env.dev.exports.PermitGate",
        "env.dev.durable_objects.bindings",
        "env.dev.version_metadata",
    ] {
        assert!(env.iter().any(|t| t == table), "dev lacks [{table}]");
    }
}

/// Production runs its fetch handler next to its D1 and R2 (both ENAM):
/// one `[placement]` table, region `aws:us-east-1`, nowhere else in the
/// production section, and no inline `placement =` key at the root. An
/// environment inherits `[placement]`, so dev says `off` for itself.
#[test]
fn production_places_the_fetch_handler_in_us_east_1_and_dev_does_not() {
    let (prod, env, root) = wrangler_tables();
    let placed: Vec<&String> = prod.iter().filter(|t| t.starts_with("placement")).collect();
    assert_eq!(placed, ["placement"], "one production [placement] table");
    assert!(
        !root.iter().any(|k| k.starts_with("placement")),
        "an inline placement key at the root"
    );
    assert_eq!(
        table_body("[placement]"),
        ["mode=targeted", "region=aws:us-east-1"]
    );
    let dev: Vec<&String> = env
        .iter()
        .filter(|t| t.starts_with("env.dev.placement"))
        .collect();
    assert_eq!(dev, ["env.dev.placement"], "dev states its own placement");
    assert_eq!(table_body("[env.dev.placement]"), ["mode=off"]);
}
