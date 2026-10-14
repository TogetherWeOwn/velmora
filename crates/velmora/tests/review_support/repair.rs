use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

static NEXT: AtomicUsize = AtomicUsize::new(0);

// Serializes fake-binary repair tests within this test binary. `repair_with_*`
// forks (via `/usr/bin/prlimit`); a fork in one libtest thread can inherit
// another thread's still-open write fd to its script, so that thread's exec
// fails with ETXTBSY (exit 126) and asserts on `exit_code`/`signal` flake.
// Holding the guard for the fixture's lifetime keeps fixture setup, extra
// staging writes, and the fork/exec from overlapping. Cross-process overlap
// is harmless: fork only inherits fds of its own process.
static SERIAL: Mutex<()> = Mutex::new(());

pub struct Fixture {
    pub root: PathBuf,
    pub scratch: PathBuf,
    pub binary: PathBuf,
    // Held for the test's lifetime; field order keeps it dropped last.
    _serial: MutexGuard<'static, ()>,
}

impl Fixture {
    pub fn new(script: &str) -> Self {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::var_os("PAPERCLIP_RUN_SCRATCH_DIR")
            .or_else(|| std::env::var_os("PAPERCLIP_SCRATCH_DIR"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let mut sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = loop {
            let root = base.join(format!(
                "nntune-repair-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => break root,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    sequence = NEXT.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => panic!("create owned test directory: {err}"),
            }
        };
        let scratch = root.join("job space");
        fs::create_dir(&scratch).unwrap();
        let binary = root.join("fake-par2.sh");
        fs::write(&binary, format!("#!/bin/sh\nset -eu\n{script}\n")).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(scratch.join("set.par2"), b"fake binary fixture\n").unwrap();
        Self {
            root,
            scratch,
            binary,
            _serial,
        }
    }

    pub fn input(&self) -> &Path {
        Path::new("set.par2")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this uniquely created, test-owned tree is removed.
        let _ = fs::remove_dir_all(&self.root);
    }
}
