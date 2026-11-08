#[cfg(test)]
mod tests;

use super::{RepairLimits, RepairReport};
use crate::error::{Error, Result};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::{
    fs::MetadataExt,
    process::{CommandExt, ExitStatusExt},
};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

const MAX_OWNED_CHILDREN: usize = 32;
static OWNED_CHILDREN: AtomicUsize = AtomicUsize::new(0);

struct CleanupSlot {
    counter: &'static AtomicUsize,
    reusable: bool,
}
impl CleanupSlot {
    fn reserve() -> io::Result<Self> {
        Self::reserve_from(&OWNED_CHILDREN)
    }

    fn reserve_from(counter: &'static AtomicUsize) -> io::Result<Self> {
        let mut count = counter.load(Ordering::Relaxed);
        loop {
            if count >= MAX_OWNED_CHILDREN {
                return Err(io::Error::other("par2 repair: cleanup capacity exhausted"));
            }
            match counter.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(Self {
                        counter,
                        reusable: true,
                    })
                }
                Err(current) => count = current,
            }
        }
    }
}
impl Drop for CleanupSlot {
    fn drop(&mut self) {
        if self.reusable {
            self.counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct OwnedChild {
    child: Child,
    slot: CleanupSlot,
}
type Reaper = Arc<Mutex<Vec<OwnedChild>>>;

fn reaper_with(
    cache: &Mutex<Option<Reaper>>,
    start_worker: impl FnOnce(Reaper) -> io::Result<()>,
) -> io::Result<Reaper> {
    // Serialize startup, but cache only success so transient thread exhaustion
    // rejects this attempt without disabling repair for the process lifetime.
    let mut cached = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pending) = cached.as_ref() {
        return Ok(Arc::clone(pending));
    }
    let pending: Reaper = Arc::new(Mutex::new(Vec::with_capacity(MAX_OWNED_CHILDREN)));
    start_worker(Arc::clone(&pending))?;
    *cached = Some(Arc::clone(&pending));
    Ok(pending)
}

fn reaper() -> io::Result<Reaper> {
    static REAPER: Mutex<Option<Reaper>> = Mutex::new(None);
    reaper_with(&REAPER, |worker| {
        let _ = std::thread::Builder::new()
            .name("par2-reaper".into())
            .spawn(move || loop {
                {
                    let mut children = worker.lock().unwrap_or_else(|e| e.into_inner());
                    children.retain_mut(|owned| match owned.child.try_wait() {
                        Ok(Some(_)) => false,
                        Err(err) if err.raw_os_error() == Some(libc::ECHILD) => false,
                        _ => true,
                    });
                }
                std::thread::sleep(Duration::from_millis(20));
            })?;
        Ok(())
    })
}

enum ProcessState {
    Reserved,
    Signalled,
    Reaped(ExitStatus),
    Unavailable,
}

// As in the group-before-reap guard, WNOWAIT reserves the numeric PID/PGID
// until all signal attempts finish. Exclusive child ownership is required:
// callers must not ignore SIGCHLD or externally reap this child.
struct Process {
    owned: Option<OwnedChild>,
    reaper: Reaper,
    state: ProcessState,
    #[cfg(test)]
    signal_spy: Option<Box<dyn FnMut(libc::pid_t) -> io::Result<()>>>,
}
impl Process {
    fn spawn(cmd: &mut Command) -> io::Result<Self> {
        // Reserve bounded deferred-cleanup capacity and start the worker before
        // spawning. Denied signals cannot create unbounded threads or zombies.
        let slot = CleanupSlot::reserve()?;
        let reaper = reaper()?;
        let child = cmd.spawn()?;
        Ok(Self {
            owned: Some(OwnedChild { child, slot: slot }),
            reaper,
            state: ProcessState::Reserved,
            #[cfg(test)]
            signal_spy: None,
        })
    }

    fn child(&mut self) -> &mut Child {
        &mut self.owned.as_mut().expect("owned child").child
    }

    fn exited(&mut self) -> io::Result<bool> {
        match self.state {
            ProcessState::Reaped(_) => return Ok(true),
            ProcessState::Unavailable => return Err(io::Error::from_raw_os_error(libc::ECHILD)),
            _ => {}
        }
        // SAFETY: zeroed siginfo_t is valid and waitid initializes it. WNOWAIT
        // observes only our child, without releasing its PID reservation.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child().id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                self.state = ProcessState::Unavailable;
                self.owned = None;
            }
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        // SAFETY: waitid succeeded; si_pid is zero when WNOHANG saw no exit.
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn signal(&mut self, pid: libc::pid_t) -> io::Result<()> {
        #[cfg(test)]
        if let Some(spy) = &mut self.signal_spy {
            return spy(pid);
        }
        // SAFETY: called only before reaping our exclusively owned leader.
        // process_group(0) made its PID the PGID; both IDs remain reserved.
        if unsafe { libc::kill(pid, libc::SIGKILL) } == -1 {
            let err = io::Error::last_os_error();
            // An already-exited leader or empty group needs no signal.
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err);
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<ExitStatus> {
        let mut signal_error = None;
        match self.state {
            ProcessState::Reaped(status) => return Ok(status),
            ProcessState::Unavailable => return Err(io::Error::from_raw_os_error(libc::ECHILD)),
            ProcessState::Reserved => {
                self.state = ProcessState::Signalled;
                let pid = self.child().id() as libc::pid_t;
                let group = self.signal(-pid);
                if group.is_err() {
                    // Reaping the leader cannot prove its descendants exited.
                    // Permanently charge this counter, retaining no stale IDs
                    // or handles once reaped and never signalling them later.
                    self.owned.as_mut().expect("owned child").slot.reusable = false;
                }
                let leader = self.signal(pid);
                signal_error = group.err().or_else(|| leader.err());
            }
            ProcessState::Signalled => {}
        }
        // Never block on wait, even after successful kill: denied signals or
        // uninterruptible sleep need not produce an exit before our deadline.
        let waited = self.child().try_wait();
        match waited {
            Ok(Some(status)) => {
                self.state = ProcessState::Reaped(status);
                self.owned = None;
                signal_error.map_or(Ok(status), Err)
            }
            Err(err) if err.raw_os_error() == Some(libc::ECHILD) => {
                self.state = ProcessState::Unavailable;
                self.owned = None;
                Err(err)
            }
            other => {
                let owned = self.owned.take().expect("owned child");
                // The worker owns the child until reap, never signals, and
                // retains the slot so repeated failures eventually fail closed.
                self.reaper
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(owned);
                self.state = ProcessState::Unavailable;
                Err(signal_error.unwrap_or_else(|| match other {
                    Err(err) => err,
                    _ => io::Error::new(io::ErrorKind::WouldBlock, "par2 repair: cleanup deferred"),
                }))
            }
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.finish();
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
    let mut process = Process::spawn(&mut cmd).map_err(Error::Io)?;
    let mut stdout = process.child().stdout.take().expect("piped stdout");
    let mut stderr = process.child().stderr.take().expect("piped stderr");
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut output = Vec::new();
    let status = loop {
        check_deadline(deadline)?;
        drain(&mut stdout, &mut output, limits.max_output_bytes, deadline)?;
        drain(&mut stderr, &mut output, limits.max_output_bytes, deadline)?;
        workspace_size(&root, limits.max_workspace_bytes, deadline)?;
        if process.exited().map_err(Error::Io)? {
            let status = process.finish().map_err(Error::Io)?;
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
        tail: retained_tail(&combined, limits.max_output_bytes),
    })
}

fn retained_tail(combined: &str, limit: usize) -> String {
    let mut lines = combined.lines().rev().take(20).collect::<Vec<_>>();
    lines.reverse();
    let tail = lines.join("\n");
    // Lossy decoding can triple the raw size. Keep the newest complete UTF-8
    // characters, independently of the combined raw stdout/stderr acceptance cap.
    let mut start = tail.len().saturating_sub(limit);
    while !tail.is_char_boundary(start) {
        start += 1;
    }
    tail[start..].to_owned()
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
