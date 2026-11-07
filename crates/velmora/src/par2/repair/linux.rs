use super::{RepairLimits, RepairReport};
use crate::error::{Error, Result};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::{
    fs::MetadataExt,
    process::{CommandExt, ExitStatusExt},
};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn limit_error(name: &str) -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("par2 repair: {name} limit exceeded"),
    ))
}

fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "par2 repair: timeout limit exceeded",
        )))
    } else {
        Ok(())
    }
}

// A dedicated process group is killed on every exit path, including errors
// setting up the pipes and descendants that outlive a successful parent.
struct Process(Child);
impl Process {
    fn kill_group(&mut self) {
        // SAFETY: process_group(0) made this child's PID its group ID. Negative
        // kill targets only that group; no signal handler or shared state.
        unsafe {
            libc::kill(-(self.0.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = self.0.kill();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.kill_group();
        let _ = self.0.wait();
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fd belongs to a live owned pipe. F_GETFL takes no third argument;
    // F_SETFL receives integer flags and preserves all existing status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn drain(pipe: &mut impl Read, out: &mut Vec<u8>, limit: usize, deadline: Instant) -> Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        check_deadline(deadline)?;
        match pipe.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if n > limit.saturating_sub(out.len()) {
                    return Err(limit_error("output"));
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

fn workspace_size(root: &Path, limit: u64, deadline: Instant) -> Result<()> {
    fn walk(
        path: &Path,
        remaining: &mut u64,
        entries: &mut usize,
        depth: usize,
        deadline: Instant,
    ) -> Result<()> {
        check_deadline(deadline)?;
        if depth > 64 || *entries == 0 {
            return Err(limit_error("workspace entries/depth"));
        }
        *entries -= 1;
        let meta = std::fs::symlink_metadata(path).map_err(Error::Io)?;
        if meta.is_dir() {
            for entry in std::fs::read_dir(path).map_err(Error::Io)? {
                walk(
                    &entry.map_err(Error::Io)?.path(),
                    remaining,
                    entries,
                    depth + 1,
                    deadline,
                )?;
            }
        } else if !meta.is_file() || meta.nlink() != 1 {
            return Err(limit_error("workspace link/special file"));
        } else {
            *remaining = remaining
                .checked_sub(meta.len())
                .ok_or_else(|| limit_error("workspace disk"))?;
        }
        Ok(())
    }
    walk(root, &mut { limit }, &mut 100_000, 0, deadline)
}

pub(super) fn run(
    par2_bin: &Path,
    scratch_dir: &Path,
    par2_files: &[&Path],
    limits: &RepairLimits,
) -> Result<RepairReport> {
    let max = RepairLimits::default();
    if limits.timeout.is_zero()
        || limits.timeout > max.timeout
        || limits.max_output_bytes == 0
        || limits.max_output_bytes > max.max_output_bytes
        || limits.max_workspace_bytes == 0
        || limits.max_workspace_bytes > max.max_workspace_bytes
        || limits.max_memory_bytes == 0
        || limits.max_memory_bytes > max.max_memory_bytes
        || limits.cpu_seconds == 0
        || limits.cpu_seconds > max.cpu_seconds
        || par2_files.is_empty()
    {
        return Err(Error::Malformed(
            "par2 repair: require inputs and positive budgets within default ceilings".into(),
        ));
    }
    let deadline = Instant::now() + limits.timeout;
    let root = scratch_dir.canonicalize().map_err(Error::Io)?;
    if !root.is_dir() {
        return Err(Error::Malformed(
            "par2 scratch path is not a directory".into(),
        ));
    }
    workspace_size(&root, limits.max_workspace_bytes, deadline)?;
    let binary = par2_bin.canonicalize().map_err(Error::Io)?;
    let mut inputs = Vec::new();
    for path in par2_files {
        let staged = if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(path)
        };
        let canonical = staged.canonicalize().map_err(Error::Io)?;
        if !canonical.starts_with(&root) || !canonical.is_file() {
            return Err(Error::Malformed(
                "par2 input must be a regular file inside scratch".into(),
            ));
        }
        inputs.push(canonical);
    }

    // The limiter is an image contract, not a PATH lookup or an optional best
    // effort. Never fall back to an unbounded process when it is unavailable.
    let mut cmd = Command::new("/usr/bin/prlimit");
    cmd.arg(format!("--cpu={0}:{0}", limits.cpu_seconds))
        .arg(format!("--fsize={0}:{0}", limits.max_workspace_bytes))
        .arg(format!("--as={0}:{0}", limits.max_memory_bytes))
        .arg("--")
        .arg(binary)
        .arg("repair")
        .arg(format!("-B{}", root.display()))
        // Single `-q`: suppresses progress spam but still emits the
        // terminal summary lines (`Repair complete.`,
        // `All files are correct, repair is not required.`). The
        // `<N> recovery blocks will be used to repair.` count line is
        // suppressed at this verbosity, so a real repair never reports a
        // positive count: `repaired_blocks` is 0 when nothing was needed
        // and -1 when repair completed or the count is unknown. A second
        // `-q` selects `nlSilent`, which prints nothing on success and
        // leaves `tail` permanently empty against the real binary.
        .args(["-m256", "-t1", "-T1", "-q", "--"])
        .args(&inputs)
        .current_dir(&root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut process = Process(cmd.spawn().map_err(Error::Io)?);
    let mut stdout = process.0.stdout.take().expect("piped stdout");
    let mut stderr = process.0.stderr.take().expect("piped stderr");
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut output = Vec::new();
    let status = loop {
        check_deadline(deadline)?;
        drain(&mut stdout, &mut output, limits.max_output_bytes, deadline)?;
        drain(&mut stderr, &mut output, limits.max_output_bytes, deadline)?;
        workspace_size(&root, limits.max_workspace_bytes, deadline)?;
        if let Some(status) = process.0.try_wait().map_err(Error::Io)? {
            process.kill_group();
            drain(&mut stdout, &mut output, limits.max_output_bytes, deadline)?;
            drain(&mut stderr, &mut output, limits.max_output_bytes, deadline)?;
            workspace_size(&root, limits.max_workspace_bytes, deadline)?;
            break status;
        }
        std::thread::sleep(
            Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
        );
    };
    let combined = String::from_utf8_lossy(&output);
    let mut lines = combined.lines().rev().take(20).collect::<Vec<_>>();
    lines.reverse();
    Ok(RepairReport {
        success: status.success(),
        exit_code: status.code(),
        signal: status.signal(),
        repaired_blocks: if status.success() {
            parse_repaired(&combined)
        } else {
            -1
        },
        targets: par2_files.iter().map(|p| p.to_path_buf()).collect(),
        tail: lines.join("\n"),
    })
}

fn parse_repaired(output: &str) -> i64 {
    // Whole-trimmed-line equality only. par2 echoes untrusted target file
    // names in `Target: "<name>"` lines, so any substring or integer scan
    // is spoofable (a file named `9 more recovery blocks.bin` or
    // `x - repair is not required.bin` would set the count). A `Target:`
    // line never equals a bare summary sentence, so exact matches are safe.
    // At single `-q` the real binary prints no repair count: healthy sets
    // print exactly `All files are correct, repair is not required.`,
    // repaired sets print exactly `Repair complete.`. Report 0 when nothing
    // was needed, -1 (repaired or unknown) otherwise.
    let mut healthy = false;
    for line in output.lines() {
        match line.trim() {
            "All files are correct, repair is not required." | "Repair is not required." => {
                healthy = true;
            }
            _ => {}
        }
    }
    if healthy {
        0
    } else {
        -1
    }
}
