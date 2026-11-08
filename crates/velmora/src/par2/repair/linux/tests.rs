use super::*;
use std::cell::RefCell;
use std::rc::Rc;

fn spawn(script: &str) -> Process {
    Process::spawn(
        Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0),
    )
    .unwrap()
}

fn observe_exit(process: &mut Process) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !process.exited().unwrap() {
        assert!(Instant::now() < deadline, "finite fixture did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn assert_eventually_reaped(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: asks only about our direct child without reaping or signalling.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            return;
        }
        assert!(Instant::now() < deadline, "finite child was not reaped");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn denied_signals_return_promptly_and_deferred_reaper_owns_finite_child() {
    let mut process = spawn("exec sleep 1");
    let pid = process.child().id();
    let targets = Rc::new(RefCell::new(Vec::new()));
    let captured = Rc::clone(&targets);
    process.signal_spy = Some(Box::new(move |target| {
        captured.borrow_mut().push(target);
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }));
    let start = Instant::now();
    assert_eq!(
        process.finish().unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    assert!(start.elapsed() < Duration::from_millis(500));
    assert!(
        process.owned.is_none(),
        "cleanup ownership must be transferred"
    );
    drop(process);
    assert_eq!(
        *targets.borrow(),
        vec![-(pid as libc::pid_t), pid as libc::pid_t]
    );
    assert_eventually_reaped(pid);
}

#[test]
fn accepted_signals_without_exit_also_defer_without_waiting() {
    let mut process = spawn("exec sleep 1");
    let pid = process.child().id();
    // A successful syscall does not guarantee prompt exit (e.g. kernel sleep).
    // Replace the syscall rather than trying to create uninterruptible tasks.
    process.signal_spy = Some(Box::new(|_| Ok(())));
    let start = Instant::now();
    assert_eq!(
        process.finish().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(start.elapsed() < Duration::from_millis(500));
    process.signal_spy = Some(Box::new(|_| panic!("signal after ownership transfer")));
    drop(process);
    assert_eventually_reaped(pid);
}

#[test]
fn cleanup_capacity_fails_closed_and_recovers_when_ownership_is_released() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let mut slots = (0..MAX_OWNED_CHILDREN)
        .map(|_| CleanupSlot::reserve_from(&COUNT).unwrap())
        .collect::<Vec<_>>();
    assert!(CleanupSlot::reserve_from(&COUNT).is_err());
    assert_eq!(COUNT.load(Ordering::Relaxed), MAX_OWNED_CHILDREN);
    slots.pop();
    let recovered = CleanupSlot::reserve_from(&COUNT).unwrap();
    assert!(CleanupSlot::reserve_from(&COUNT).is_err());
    drop(recovered);
    drop(slots);
    assert_eq!(COUNT.load(Ordering::Relaxed), 0);
}

fn denied_group_cleanup_retains_admission(counter: &'static AtomicUsize, deferred: bool) {
    use std::io::Write;

    let slots = (0..MAX_OWNED_CHILDREN - 1)
        .map(|_| CleanupSlot::reserve_from(counter).unwrap())
        .collect::<Vec<_>>();
    // The descendant holds stdout open, announcing startup and finite exit.
    // Stdin holds the deferred leader alive until after cleanup returns.
    let script = if deferred {
        "(printf ready; sleep 2; printf done) & read -r release; exit 0"
    } else {
        "(printf ready; sleep 2; printf done) & exit 0"
    };
    let mut process = Process::spawn(
        Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0),
    )
    .unwrap();
    process.owned.as_mut().unwrap().slot = CleanupSlot::reserve_from(counter).unwrap();
    let pid = process.child().id();
    let mut release = process.child().stdin.take().unwrap();
    let mut output = process.child().stdout.take().unwrap();
    let mut ready = [0; 5];
    output.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready");
    nonblocking(&output).unwrap();
    if !deferred {
        observe_exit(&mut process);
    }
    let targets = Rc::new(RefCell::new(Vec::new()));
    let captured = Rc::clone(&targets);
    process.signal_spy = Some(Box::new(move |target| {
        captured.borrow_mut().push(target);
        if target < 0 || deferred {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        } else {
            Ok(())
        }
    }));
    let start = Instant::now();
    assert_eq!(
        process.finish().unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    assert!(start.elapsed() < Duration::from_millis(500));
    assert_eq!(matches!(process.state, ProcessState::Unavailable), deferred);
    assert!(process.owned.is_none());
    process.signal_spy = Some(Box::new(|_| panic!("signal after cleanup handoff or reap")));
    drop(process);
    if deferred {
        release.write_all(b"release\n").unwrap();
    }
    drop(release);
    assert_eventually_reaped(pid);
    // Synchronize with removal, not just the worker's successful wait syscall.
    let worker = reaper().unwrap();
    let pending = worker.lock().unwrap();
    assert!(!pending.iter().any(|owned| owned.child.id() == pid));
    drop(pending);
    let mut byte = [0];
    assert_eq!(
        output.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "descendant must still be running after leader reap"
    );
    assert_eq!(counter.load(Ordering::Relaxed), MAX_OWNED_CHILDREN);
    assert!(CleanupSlot::reserve_from(counter).is_err());
    assert_eq!(
        *targets.borrow(),
        vec![-(pid as libc::pid_t), pid as libc::pid_t]
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut done = Vec::new();
    loop {
        match output.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => done.extend_from_slice(&byte),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "finite descendant did not exit");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => panic!("descendant output: {err}"),
        }
    }
    assert_eq!(done, b"done");
    // Even finite exit cannot safely be inferred from a stale numeric PGID.
    assert!(CleanupSlot::reserve_from(counter).is_err());
    drop(slots);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[test]
fn denied_group_cleanup_retains_admission_after_immediate_leader_reap() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    denied_group_cleanup_retains_admission(&COUNT, false);
}

#[test]
fn denied_group_cleanup_retains_admission_after_deferred_leader_reap() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    denied_group_cleanup_retains_admission(&COUNT, true);
}

#[test]
fn reaper_initialization_retries_after_worker_start_failure_and_caches_success() {
    let cache = Mutex::new(None);
    let err = reaper_with(&cache, |_| Err(io::Error::from_raw_os_error(libc::EAGAIN)))
        .err()
        .expect("worker startup must fail closed");
    assert_eq!(err.raw_os_error(), Some(libc::EAGAIN));
    assert!(cache.lock().unwrap().is_none());

    let pending = reaper_with(&cache, |worker| {
        assert!(worker.lock().unwrap().is_empty());
        Ok(())
    })
    .unwrap();
    let cached = reaper_with(&cache, |_| panic!("successful worker must not restart")).unwrap();
    assert!(Arc::ptr_eq(&pending, &cached));
}

#[test]
fn setup_error_drops_guard_and_reaps_running_child() {
    struct InvalidPipe;
    impl AsRawFd for InvalidPipe {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            -1
        }
    }
    fn setup(process: Process) -> Result<()> {
        let _guard = process;
        nonblocking(&InvalidPipe)?;
        Ok(())
    }
    let mut process = spawn("exec sleep 3");
    let pid = process.child().id();
    let start = Instant::now();
    assert!(setup(process).is_err());
    assert_eventually_reaped(pid);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn setup_error_drop_does_not_wait_after_denied_signals() {
    struct InvalidPipe;
    impl AsRawFd for InvalidPipe {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            -1
        }
    }
    fn setup(process: Process) -> Result<()> {
        let _guard = process;
        nonblocking(&InvalidPipe)?;
        Ok(())
    }
    let mut process = spawn("exec sleep 1");
    let pid = process.child().id();
    process.signal_spy = Some(Box::new(|_| Err(io::Error::from_raw_os_error(libc::EPERM))));
    let start = Instant::now();
    assert!(setup(process).is_err());
    assert!(start.elapsed() < Duration::from_millis(500));
    assert_eventually_reaped(pid);
}

#[test]
fn signals_only_while_leader_is_reserved_never_after_reap() {
    let mut process = spawn("exit 7");
    let pid = process.child().id();
    let targets = Rc::new(RefCell::new(Vec::new()));
    let captured = Rc::clone(&targets);
    process.signal_spy = Some(Box::new(move |target| {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: WNOWAIT observes our zombie, never consumes its reservation.
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0,
            "signal attempted after reap"
        );
        // SAFETY: successful waitid initialized info.
        assert_eq!(unsafe { info.si_pid() }, pid as libc::pid_t);
        captured.borrow_mut().push(target);
        Ok(())
    }));
    observe_exit(&mut process);
    assert!(process.exited().unwrap());
    let status = process.finish().unwrap();
    assert_eq!(status.code(), Some(7));
    assert_eq!(process.finish().unwrap(), status);
    drop(process);
    assert_eq!(
        *targets.borrow(),
        vec![-(pid as libc::pid_t), pid as libc::pid_t]
    );
    assert_eventually_reaped(pid);
}

#[test]
fn denied_group_signal_cannot_report_success_even_for_exited_leader() {
    let mut process = spawn("exit 0");
    let pid = process.child().id();
    observe_exit(&mut process);
    process.signal_spy = Some(Box::new(|target| {
        if target < 0 {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        } else {
            Ok(())
        }
    }));
    assert_eq!(
        process.finish().unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    process.signal_spy = Some(Box::new(|_| panic!("signal after reap")));
    drop(process);
    assert_eventually_reaped(pid);
}

#[test]
fn missing_child_disarms_cleanup_without_signalling() {
    let mut process = spawn("exit 0");
    observe_exit(&mut process);
    process.child().wait().unwrap();
    process.signal_spy = Some(Box::new(|_| panic!("signal after ECHILD")));
    assert_eq!(
        process.exited().unwrap_err().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert_eq!(
        process.finish().unwrap_err().raw_os_error(),
        Some(libc::ECHILD)
    );
    drop(process);
}

#[test]
fn decoded_tail_preserves_only_complete_characters_within_budget() {
    assert_eq!(retained_tail("é🙂z", 7), "é🙂z");
    assert_eq!(retained_tail("é🙂z", 6), "🙂z");
    assert_eq!(retained_tail("é🙂z", 4), "z");
    assert_eq!(retained_tail("🙂", 3), "");
    assert_eq!(retained_tail("é", 0), "");
    let lines = (0..25)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(retained_tail(&lines, 1024).lines().count(), 20);
    assert!(retained_tail(&lines, 1024).starts_with("5\n"));
}

#[test]
fn invalid_bytes_cannot_expand_retained_tail_past_raw_budget() {
    let raw = vec![0xff; 1024];
    let decoded = String::from_utf8_lossy(&raw);
    assert_eq!(decoded.len(), 3072);
    let tail = retained_tail(&decoded, raw.len());
    assert_eq!(tail, "\u{fffd}".repeat(341));
    assert!(tail.len() <= raw.len());
}
