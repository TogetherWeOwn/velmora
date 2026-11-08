//! Agreed RepairLimits API: finite fake workloads, never a real par2 provider.
#![cfg(target_os = "linux")]

#[path = "review_support/repair.rs"]
mod support;

use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use support::Fixture;
use velmora::error::Result;
use velmora::par2::repair::{repair_with_limits, RepairLimits, RepairReport};

fn limits() -> RepairLimits {
    RepairLimits {
        timeout: Duration::from_secs(2),
        max_output_bytes: 1024,
        max_workspace_bytes: 1024 * 1024,
        max_memory_bytes: 128 * 1024 * 1024,
        cpu_seconds: 1,
    }
}

fn assert_not_success(result: &Result<RepairReport>) {
    if let Ok(report) = result {
        assert!(
            !report.success,
            "budget violation reported success: {report:?}"
        );
    }
}

#[test]
fn default_limits_are_finite_and_nonzero() {
    let limits = RepairLimits::default();
    assert!(!limits.timeout.is_zero() && limits.timeout < Duration::MAX);
    assert!(limits.max_output_bytes > 0 && limits.max_output_bytes < usize::MAX);
    assert!(limits.max_workspace_bytes > 0 && limits.max_workspace_bytes < u64::MAX);
    assert!(limits.max_memory_bytes > 0 && limits.max_memory_bytes < u64::MAX);
    assert!(limits.cpu_seconds > 0 && limits.cpu_seconds < u64::MAX);
}

#[test]
fn bounded_success_is_not_rejected_by_custom_limits() {
    // No count is reported at `-q` verbosity: success without a healthy line
    // is -1 (repaired or unknown), even when a count-like line is present.
    let f = Fixture::new("printf 'Repair complete.\\n'");
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits()).unwrap();
    assert!(result.success);
    assert_eq!(result.repaired_blocks, -1);
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.signal, None);
    assert!(result.tail.contains("Repair complete."));
}

fn check_output_budget(stderr: bool) {
    // 128 KiB total, finite even if every limit is broken. A single long line
    // catches an implementation that retains '20 lines' without a byte cap.
    let redirect = if stderr { " >&2" } else { "" };
    let script = format!(
        "i=0; while [ \"$i\" -lt 8192 ]; do printf '0123456789abcdef'{redirect}; i=$((i+1)); done\nprintf '\\nRepair complete.\\n'"
    );
    let f = Fixture::new(&script);
    let limits = limits();
    match repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits) {
        Ok(result) => assert!(
            result.tail.len() <= limits.max_output_bytes,
            "unbounded retained output: {}",
            result.tail.len()
        ),
        Err(err) => assert!(
            err.to_string().len() <= limits.max_output_bytes + 512,
            "unbounded output escaped through error text"
        ),
    }
}

#[test]
fn stdout_capture_is_byte_bounded_even_without_newlines() {
    check_output_budget(false);
}

#[test]
fn stderr_capture_is_byte_bounded_even_without_newlines() {
    check_output_budget(true);
}

#[test]
fn combined_stdout_and_stderr_share_one_output_budget() {
    let f = Fixture::new("i=0; while [ \"$i\" -lt 48 ]; do printf '0123456789abcdef'; printf 'fedcba9876543210' >&2; i=$((i+1)); done");
    let limits = limits();
    match repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits) {
        Ok(result) => assert!(result.tail.len() <= limits.max_output_bytes),
        Err(err) => assert!(err.to_string().len() <= limits.max_output_bytes + 512),
    }
}

#[test]
fn invalid_bytes_at_raw_limit_have_a_decoded_tail_budget() {
    let f = Fixture::new("i=0; while [ \"$i\" -lt 1024 ]; do printf '\\377'; i=$((i+1)); done");
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits()).unwrap();
    assert!(result.success);
    assert_eq!(result.tail, "\u{fffd}".repeat(341));
    assert!(result.tail.len() <= limits().max_output_bytes);
}

#[test]
fn valid_multibyte_output_at_raw_limit_is_preserved() {
    let f = Fixture::new("i=0; while [ \"$i\" -lt 512 ]; do printf '\\303\\251'; i=$((i+1)); done");
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits()).unwrap();
    assert!(result.success);
    assert_eq!(result.tail, "é".repeat(512));
}

#[test]
fn valid_multibyte_output_over_raw_limit_is_rejected() {
    let f = Fixture::new("i=0; while [ \"$i\" -lt 513 ]; do printf '\\303\\251'; i=$((i+1)); done");
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits());
    assert!(
        result.is_err(),
        "raw output cap must not become truncation-only"
    );
}

#[test]
fn invalid_output_over_combined_raw_limit_is_rejected() {
    let f = Fixture::new(
        "i=0; while [ \"$i\" -lt 513 ]; do printf '\\377'; printf '\\377' >&2; i=$((i+1)); done",
    );
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits());
    assert!(result.is_err(), "stdout and stderr must share the raw cap");
}

// Fixtures save their identities while alive, before repair cleanup. These
// observations never signal PIDs, even on assertion failure; fixtures are finite.
struct ObservedProcess {
    pid: u32,
    start: String,
}

fn parse_state(stat: &str) -> Option<(char, String)> {
    let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    Some((fields.first()?.chars().next()?, fields.get(19)?.to_string()))
}

impl ObservedProcess {
    fn from_file(path: &Path) -> Self {
        let stat = fs::read_to_string(path).expect("fake process recorded its identity");
        Self {
            pid: stat.split_once(' ').unwrap().0.parse().unwrap(),
            start: parse_state(&stat).unwrap().1,
        }
    }

    fn state(&self) -> Option<char> {
        let stat = fs::read_to_string(format!("/proc/{}/stat", self.pid)).ok()?;
        let (state, start) = parse_state(&stat)?;
        (self.start == start).then_some(state)
    }

    fn running(&self) -> bool {
        self.state()
            .is_some_and(|state| state != 'Z' && state != 'X')
    }
}

#[test]
fn timeout_returns_promptly_reaps_child_and_stops_descendants() {
    // Three-second fallback means this fixture cannot hang even without limits.
    let f = Fixture::new("cat /proc/$$/stat > parent.stat\nsleep 3 &\nchild=$!\ncat /proc/$child/stat > child.stat\nwait \"$child\"\nprintf 'late write' > escaped-timeout\nprintf 'Repair complete.\\n'");
    let limits = RepairLimits {
        timeout: Duration::from_millis(500),
        ..limits()
    };
    let started = Instant::now();
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits);
    let elapsed = started.elapsed();
    let parent = ObservedProcess::from_file(&f.scratch.join("parent.stat"));
    let child = ObservedProcess::from_file(&f.scratch.join("child.stat"));
    let grace = Instant::now();
    while (parent.running() || child.running()) && grace.elapsed() < Duration::from_millis(500) {
        thread::sleep(Duration::from_millis(10));
    }
    assert_not_success(&result);
    assert!(
        elapsed < Duration::from_secs(2),
        "timeout waited {elapsed:?} for fake process"
    );
    assert!(!parent.running(), "repair process survived timeout");
    assert!(parent.state().is_none(), "direct child was not reaped");
    assert!(!child.running(), "repair descendant survived timeout");
    assert!(!f.scratch.join("escaped-timeout").exists());
}

fn assert_family_stopped(f: &Fixture) {
    let parent = ObservedProcess::from_file(&f.scratch.join("parent.stat"));
    let child = ObservedProcess::from_file(&f.scratch.join("child.stat"));
    let deadline = Instant::now() + Duration::from_millis(500);
    while (parent.running() || child.running()) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(parent.state().is_none(), "leader was not reaped");
    assert!(!child.running(), "descendant survived cleanup");
}

#[test]
fn successful_leader_cleans_up_descendant_holding_output_open() {
    let f = Fixture::new("cat /proc/$$/stat > parent.stat\nsleep 3 &\ncat /proc/$!/stat > child.stat\nprintf 'Repair complete.\\n'\nexit 0");
    let started = Instant::now();
    let report = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits()).unwrap();
    assert!(report.success);
    assert_eq!(report.exit_code, Some(0));
    assert!(report.tail.contains("Repair complete."));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_family_stopped(&f);
}

#[test]
fn output_limit_error_reaps_leader_and_stops_descendants() {
    let f = Fixture::new("cat /proc/$$/stat > parent.stat\nsleep 3 &\ncat /proc/$!/stat > child.stat\ni=0; while [ \"$i\" -lt 8192 ]; do printf '0123456789abcdef'; i=$((i+1)); done\nwait");
    let started = Instant::now();
    let err = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits()).unwrap_err();
    assert!(err.to_string().contains("output limit exceeded"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_family_stopped(&f);
}

#[test]
fn existing_workspace_over_budget_is_rejected_before_spawn() {
    let f = Fixture::new("printf 'invoked' > invoked; printf 'Repair complete.\\n'");
    fs::write(f.scratch.join("staged-data"), [0u8; 2048]).unwrap();
    let limits = RepairLimits {
        max_workspace_bytes: 1024,
        ..limits()
    };
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits);
    assert!(
        result.is_err(),
        "oversized staged workspace accepted: {result:?}"
    );
    assert!(!f.scratch.join("invoked").exists());
}

#[test]
fn generated_file_is_capped_and_not_reported_successful() {
    let f = Fixture::new(
        "dd if=/dev/zero of=growth bs=1024 count=64 2>/dev/null\nprintf 'Repair complete.\\n'",
    );
    let limits = RepairLimits {
        max_workspace_bytes: 4096,
        ..limits()
    };
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits);
    assert_not_success(&result);
    let bytes = fs::metadata(f.scratch.join("growth"))
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(
        bytes <= limits.max_workspace_bytes,
        "file grew to {bytes} bytes past its ceiling"
    );
}

#[test]
fn multiple_generated_files_cannot_bypass_aggregate_workspace_budget() {
    // Each 1 KiB file is under the 4 KiB ceiling; together they exceed it.
    let f = Fixture::new("i=0; while [ \"$i\" -lt 16 ]; do dd if=/dev/zero of=\"part-$i\" bs=1024 count=1 2>/dev/null; i=$((i+1)); done\nprintf 'Repair complete.\\n'");
    let limits = RepairLimits {
        max_workspace_bytes: 4096,
        ..limits()
    };
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits);
    assert_not_success(&result);
}

#[test]
fn subprocess_inherits_hard_cpu_memory_and_file_limits() {
    // Inspect kernel-enforced limits without allocating memory or burning CPU.
    let f = Fixture::new(
        "cat /proc/$$/limits > inherited-limits.txt\nprintf 'Repair is not required.\\n'",
    );
    let limits = RepairLimits {
        max_workspace_bytes: 8192,
        ..limits()
    };
    let result = repair_with_limits(&f.binary, &f.scratch, &[f.input()], &limits).unwrap();
    assert!(result.success);
    let text = fs::read_to_string(f.scratch.join("inherited-limits.txt")).unwrap();
    for (label, ceiling) in [
        ("Max cpu time", limits.cpu_seconds),
        ("Max file size", limits.max_workspace_bytes),
        ("Max address space", limits.max_memory_bytes),
    ] {
        let row = text
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .expect("Linux limit row");
        let values: Vec<_> = row.split_whitespace().collect();
        for value in &values[..2] {
            let value: u64 = value
                .parse()
                .unwrap_or_else(|_| panic!("{label} is not finite: {row}"));
            assert!(
                value > 0 && value <= ceiling,
                "{label}: {row}; expected <= {ceiling}"
            );
        }
    }
}
