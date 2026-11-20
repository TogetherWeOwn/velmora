//! Phase timings of write requests: one line per PutObject and
//! UploadPart, whose phases add up to its wall time, only while the
//! Worker asked for them, and without a catalogue call of its own.

mod service_support;

use std::cell::RefCell;

use service_support::*;
use velmora_bridge::testkit::FixedClock;
use velmora_bridge::*;

const BUCKET: &str = "vault";

thread_local! {
    static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static CLOCK: RefCell<Option<FixedClock>> = const { RefCell::new(None) };
}

fn keep(line: &str) {
    LINES.with(|l| l.borrow_mut().push(line.to_string()));
}

/// A timer of 0 ms on a clock that only moves when told: each tick moves
/// it by 1 ms, so every phase closed by a tick has at least 1 ms.
fn tick() -> futures_util::future::LocalBoxFuture<'static, ()> {
    CLOCK.with(|c| {
        if let Some(c) = c.borrow().as_ref() {
            c.advance_ms(1);
        }
    });
    Box::pin(async {})
}

fn lines() -> Vec<String> {
    LINES.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split(' ')
        .find_map(|kv| kv.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
        .unwrap_or_else(|| panic!("{name} missing in {line}"))
}

fn num(line: &str, name: &str) -> i64 {
    field(line, name).parse().unwrap()
}

const PHASES: [&str; 8] = [
    "auth_ms", "wait_ms", "read_ms", "hash_ms", "seal_ms", "r2_ms", "d1_ms", "other_ms",
];

/// Every phase is there, and together they are the wall time.
fn check_sum(line: &str) {
    let sum: i64 = PHASES.iter().map(|p| num(line, p)).sum();
    assert_eq!(sum, num(line, "wall_ms"), "{line}");
}

/// One extent up to 1 MiB, slices of 512 KiB: small bodies take every
/// path of the production sizes.
fn small_rig() -> Rig {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = MIB as u64;
    cfg.slice_bytes = MIB as u64 / 2;
    cfg.max_put_bytes = 4 * MIB as u64;
    rig_with(NoNntp, cfg)
}

async fn create(rig: &Rig, signer: &Signer, key: &str) -> String {
    let created = rig
        .call(
            signer,
            Method::Post,
            &path(BUCKET, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    created.expect(200);
    created.values("UploadId").remove(0)
}

async fn part(rig: &Rig, signer: &Signer, key: &str, id: &str, n: u16, bytes: &[u8]) -> Resp {
    let n = n.to_string();
    rig.call(
        signer,
        Method::Put,
        &path(BUCKET, key),
        &[("partNumber", &n), ("uploadId", id)],
        &[],
        bytes,
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn each_put_and_part_logs_one_line_whose_phases_add_up() {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    CLOCK.with(|c| *c.borrow_mut() = Some(rig.bridge.clock.clone()));
    trace::log_writes(keep, tick);

    // One extent.
    rig.put(&signer, BUCKET, "one", &pattern(1, MIB - 7))
        .await
        .expect(200);
    // Slices: 3 of at most 512 KiB.
    rig.put(&signer, BUCKET, "sliced", &pattern(2, MIB + MIB / 2 - 1))
        .await
        .expect(200);
    let id = create(&rig, &signer, "mp").await;
    part(&rig, &signer, "mp", &id, 1, &pattern(3, MIB))
        .await
        .expect(200);
    part(&rig, &signer, "mp", &id, 2, &pattern(4, 2 * MIB))
        .await
        .expect(200);

    let got = lines();
    assert_eq!(got.len(), 4, "{got:#?}");
    let want = [
        ("put", MIB as u64 - 7, 1),
        ("put", MIB as u64 + MIB as u64 / 2 - 1, 3),
        ("part", MIB as u64, 1),
        ("part", 2 * MIB as u64, 4),
    ];
    for (line, (kind, bytes, extents)) in got.iter().zip(want) {
        assert_eq!(field(line, "kind"), kind, "{line}");
        assert_eq!(field(line, "outcome"), "ok", "{line}");
        assert_eq!(num(line, "bytes"), bytes as i64, "{line}");
        assert_eq!(num(line, "extents"), extents, "{line}");
        check_sum(line);
        // Each phase the request went through was closed by a tick.
        for p in ["auth_ms", "wait_ms", "hash_ms", "seal_ms", "r2_ms", "d1_ms"] {
            assert!(num(line, p) >= 1, "{p}: {line}");
        }
        // A seal and a store per extent.
        assert!(num(line, "seal_ms") >= extents, "{line}");
        assert!(num(line, "r2_ms") >= extents, "{line}");
        assert!(num(line, "pieces") >= 1, "{line}");
        assert_eq!(num(line, "wall_ms"), num(line, "ticks"), "{line}");
        // No key, bucket or id.
        assert!(!line.contains(BUCKET) && !line.contains("mp") && !line.contains(&id));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_write_is_logged_as_an_error() {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    CLOCK.with(|c| *c.borrow_mut() = Some(rig.bridge.clock.clone()));
    trace::log_writes(keep, tick);

    // An upload that does not exist.
    part(&rig, &signer, "mp", "no-such-upload", 1, &pattern(5, 1000))
        .await
        .expect(404);
    // A key that is not known.
    let stranger = Signer::new("AKIDNOTKNOWN00000001", secret());
    let refused = rig.put(&stranger, BUCKET, "k", b"x").await;
    assert_eq!(refused.status, 403);

    let got = lines();
    assert_eq!(got.len(), 2, "{got:#?}");
    assert_eq!(field(&got[0], "kind"), "part");
    assert_eq!(field(&got[1], "kind"), "put");
    for line in &got {
        assert_eq!(field(line, "outcome"), "error", "{line}");
        check_sum(line);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_is_logged_or_written_more_unless_asked() {
    // The same writes with and without the trace: the catalogue sees the
    // same calls, and without it no line is made.
    async fn run(on: bool) -> (Vec<String>, u64) {
        let rig = small_rig();
        let (_, signer) = rig.standard(BUCKET).await;
        if on {
            CLOCK.with(|c| *c.borrow_mut() = Some(rig.bridge.clock.clone()));
            trace::log_writes(keep, tick);
        }
        let before = rig.trip().calls();
        rig.put(&signer, BUCKET, "one", &pattern(1, MIB / 2))
            .await
            .expect(200);
        rig.put(&signer, BUCKET, "sliced", &pattern(2, 3 * MIB / 2))
            .await
            .expect(200);
        let id = create(&rig, &signer, "mp").await;
        part(&rig, &signer, "mp", &id, 1, &pattern(3, 2 * MIB))
            .await
            .expect(200);
        (lines(), rig.trip().calls() - before)
    }
    let (off_lines, off_calls) = run(false).await;
    assert!(off_lines.is_empty(), "{off_lines:#?}");
    let (on_lines, on_calls) = run(true).await;
    assert_eq!(on_lines.len(), 3);
    assert_eq!(on_calls, off_calls);
}
