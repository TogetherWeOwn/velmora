//! Bounded repair in a Linux Container, using a deployment-pinned par2 binary.

use crate::error::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;

/// Per-run resource budgets. Defaults match the v1 repair runner. A private,
/// quota-backed scratch volume and an unprivileged Container remain required:
/// polling aggregate size is not a filesystem quota or a sandbox.
#[derive(Debug, Clone)]
pub struct RepairLimits {
    /// Wall-clock deadline, including output draining and workspace checks.
    pub timeout: Duration,
    /// Maximum combined stdout/stderr bytes retained or accepted.
    pub max_output_bytes: usize,
    /// Aggregate workspace ceiling and the kernel's per-file size ceiling.
    pub max_workspace_bytes: u64,
    /// Kernel address-space limit for the subprocess.
    pub max_memory_bytes: u64,
    /// Kernel CPU time limit (seconds).
    pub cpu_seconds: u64,
}

impl Default for RepairLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            max_output_bytes: 1 << 20,
            max_workspace_bytes: 8 << 30,
            max_memory_bytes: 512 << 20,
            cpu_seconds: 60,
        }
    }
}

/// Outcome of one `par2 repair` run.
#[derive(Debug, Clone)]
pub struct RepairReport {
    /// Whether the binary reported success (exit status 0).
    pub success: bool,
    /// Process exit code (`None` when killed by a signal). Matches
    /// par2cmdline-turbo: 0 is success; 1/2/4 mean the inputs are permanently
    /// unusable for this set (dead-letter, do not retry — unrecoverable,
    /// missing target, `Main packet not found`); 6 with a
    /// `Recovery will not be possible` line is a corrupt set (dead-letter,
    /// do not retry); only 8 (out of memory) and signal kills (including the
    /// `prlimit` CPU/file-size/address-space ceilings) are resource failures.
    /// Any other code is unexpected: bound retries and run `par2 verify`
    /// first to separate unusable sets from transient failures. Combine with
    /// `signal` to separate OOM/IO/limit kills.
    pub exit_code: Option<i32>,
    /// Terminating signal number on Unix (`None` on a normal exit). Set when
    /// the kernel (including the `prlimit` CPU/file-size/address-space
    /// ceilings) kills the repair process.
    pub signal: Option<i32>,
    /// Repaired-block count: 0 when the binary reports nothing needed, -1
    /// when repair completed (the real binary prints no count at `-q`
    /// verbosity) or when the run failed/unknown. Never use this for
    /// retry/dead-letter decisions; use `exit_code`.
    pub repaired_blocks: i64,
    /// Target PAR2 paths supplied by the caller.
    pub targets: Vec<PathBuf>,
    /// Last 20 lines of bounded stdout/stderr, in capture order.
    pub tail: String,
}

/// Runs with the v1 default budgets. `par2_bin` must be the trusted, pinned
/// executable supplied by the Container image, never an uploaded program.
/// `scratch_dir` must be exclusive to this job, with all inputs staged there.
/// Linux requires `/usr/bin/prlimit`; other native platforms fail closed.
pub fn repair_with_binary(
    par2_bin: &Path,
    scratch_dir: &Path,
    par2_files: &[&Path],
) -> Result<RepairReport> {
    repair_with_limits(par2_bin, scratch_dir, par2_files, &RepairLimits::default())
}

/// Runs with explicit positive budgets, no greater than the default ceilings.
/// Paths are canonicalised and checked against the private scratch directory.
/// A budget breach terminates the process group and never reports success.
/// Kernel-enforced termination may appear as an unsuccessful report; other
/// limit violations return errors. Files are preserved for diagnosis.
pub fn repair_with_limits(
    par2_bin: &Path,
    scratch_dir: &Path,
    par2_files: &[&Path],
    limits: &RepairLimits,
) -> Result<RepairReport> {
    #[cfg(target_os = "linux")]
    {
        linux::run(par2_bin, scratch_dir, par2_files, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (par2_bin, scratch_dir, par2_files, limits);
        #[cfg(target_arch = "wasm32")]
        return Err(crate::error::Error::UnsupportedOnWasm("par2 repair"));
        #[cfg(not(target_arch = "wasm32"))]
        return Err(crate::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "par2 repair requires Linux resource limits",
        )));
    }
}
