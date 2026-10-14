//! Native wrapper behavior, using only fake executables in owned directories.
#![cfg(target_os = "linux")]

#[path = "review_support/repair.rs"]
mod support;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use nntune_core::par2::repair::repair_with_binary;
use support::Fixture;

#[test]
fn no_repair_required_reports_zero_blocks() {
    let f = Fixture::new("printf 'Repair is not required.\\n'");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(result.success);
    assert_eq!(result.repaired_blocks, 0);
}

#[test]
fn full_healthy_sentence_reports_zero_blocks() {
    let f = Fixture::new("printf 'All files are correct, repair is not required.\\n'");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(result.success);
    assert_eq!(result.repaired_blocks, 0);
}

#[test]
fn needed_recovery_blocks_line_reports_unknown_at_quiet_verbosity() {
    // The real binary suppresses the `<N> more recovery blocks` count line at
    // single `-q`; a count must never be extracted from it (and never from a
    // `Target:` filename echo). Success without a healthy line is -1.
    let f = Fixture::new(
        "printf 'Need 7 more recovery blocks to be able to repair.\\nRepair complete.\\n'",
    );
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(result.success);
    assert_eq!(result.repaired_blocks, -1);
}

#[test]
fn used_recovery_blocks_line_reports_unknown_at_quiet_verbosity() {
    // Same as above: `<N> recovery blocks will be used to repair.` is not
    // printed at `-q` by par2cmdline-turbo, so it reports -1 here.
    let f =
        Fixture::new("printf '7 recovery blocks will be used to repair.\\nRepair complete.\\n'");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(result.success);
    assert_eq!(result.repaired_blocks, -1);
}

#[test]
fn hostile_target_name_cannot_spoof_healthy_zero() {
    // par2 echoes untrusted PAR2 target names in `Target: "<name>"` lines.
    // A file named `x - repair is not required.bin` must not report 0.
    let f = Fixture::new(
        "printf 'Target: \"x - repair is not required.bin\" - damaged.\\nRepair complete.\\n'",
    );
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(result.success);
    assert_eq!(result.repaired_blocks, -1);
}

#[test]
fn hostile_target_name_cannot_spoof_block_count() {
    // A file named `9 more recovery blocks.bin` must not report 9.
    let f = Fixture::new(
        "printf 'Target: \"9 more recovery blocks.bin\" - damaged.\\nRepair complete.\\n'",
    );
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(result.success);
    assert_eq!(result.repaired_blocks, -1);
}

#[test]
fn exit_code_and_signal_are_reported_on_success() {
    let f = Fixture::new("printf 'Repair complete.\\n'");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(result.success);
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.signal, None);
}

#[test]
fn exit_code_is_reported_on_unrecoverable_failure() {
    let f = Fixture::new("printf 'Repair failed.\\n'; exit 2");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(!result.success);
    assert_eq!(result.exit_code, Some(2));
    assert_eq!(result.signal, None);
    assert_eq!(result.repaired_blocks, -1);
}

#[test]
fn exit_code_is_reported_on_corrupt_par2_input() {
    let f = Fixture::new("printf 'Main packet not found.\\n'; exit 4");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(!result.success);
    assert_eq!(result.exit_code, Some(4));
    assert_eq!(result.signal, None);
}

#[test]
fn signal_is_reported_when_killed() {
    let f = Fixture::new("kill -9 $$");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(!result.success);
    assert_eq!(result.exit_code, None);
    assert_eq!(result.signal, Some(9));
}

#[test]
fn repair_complete_without_a_known_count_reports_unknown() {
    let f = Fixture::new("printf 'Repair complete.\\n'");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert!(result.success);
    assert_eq!(
        result.repaired_blocks, -1,
        "success alone is not proof of zero repaired blocks"
    );
}

#[test]
fn unrecognized_output_is_not_invented_as_a_count() {
    let f = Fixture::new("printf 'unrecognized progress report\\n'");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()]).unwrap();
    assert_eq!(result.repaired_blocks, -1);
}

#[test]
fn nonzero_exit_cannot_claim_success_even_with_success_text() {
    let f = Fixture::new("printf 'Repair complete.\\n'; exit 2");
    let result = repair_with_binary(&f.binary, &f.scratch, &[f.input()])
        .expect("wrapper reports nonzero exits as a report, not an error");
    assert!(!result.success);
    assert_eq!(result.exit_code, Some(2));
    assert_eq!(result.signal, None);
    assert_eq!(result.repaired_blocks, -1);
}

#[test]
fn option_looking_input_is_after_double_dash_and_base_is_pinned_to_scratch() {
    let f = Fixture::new("printf '%s\\n' \"$@\" > argv.txt; printf 'Repair is not required.\\n'");
    fs::write(f.scratch.join("-rf.par2"), b"fake fixture").unwrap();
    let result = repair_with_binary(&f.binary, &f.scratch, &[Path::new("-rf.par2")]).unwrap();
    assert!(result.success);
    let text = fs::read_to_string(f.scratch.join("argv.txt")).unwrap();
    let args: Vec<_> = text.lines().collect();
    assert_eq!(args.first().copied(), Some("repair"));
    let separator = args
        .iter()
        .position(|arg| *arg == "--")
        .expect("missing -- before untrusted paths");
    let base = args[..separator]
        .iter()
        .enumerate()
        .find_map(|(i, arg)| {
            if *arg == "-B" {
                args.get(i + 1).copied()
            } else {
                arg.strip_prefix("-B").filter(|value| !value.is_empty())
            }
        })
        .expect("missing -B scratch containment option");
    assert_eq!(
        Path::new(base).canonicalize().unwrap(),
        f.scratch.canonicalize().unwrap()
    );
    assert_eq!(args[separator + 1..].len(), 1);
    let input = Path::new(args[separator + 1]);
    let resolved = if input.is_absolute() {
        input.to_path_buf()
    } else {
        f.scratch.join(input)
    };
    assert_eq!(
        resolved.canonicalize().unwrap(),
        f.scratch.join("-rf.par2").canonicalize().unwrap()
    );
}

#[test]
fn ordinary_scratch_input_still_runs() {
    let f = Fixture::new("printf 'invoked' > invoked; printf 'Repair is not required.\\n'");
    assert!(
        repair_with_binary(&f.binary, &f.scratch, &[f.input()])
            .unwrap()
            .success
    );
    assert_eq!(fs::read(f.scratch.join("invoked")).unwrap(), b"invoked");
}

#[test]
fn absolute_input_outside_scratch_is_rejected_before_spawn() {
    let f = Fixture::new("printf 'invoked' > invoked");
    let outside = f.root.join("outside.par2");
    fs::write(&outside, b"outside sentinel").unwrap();
    let result = repair_with_binary(&f.binary, &f.scratch, &[&outside]);
    assert!(result.is_err(), "outside input accepted: {result:?}");
    assert!(!f.scratch.join("invoked").exists());
    assert_eq!(fs::read(outside).unwrap(), b"outside sentinel");
}

#[test]
fn parent_traversal_input_is_rejected_before_spawn() {
    let f = Fixture::new("printf 'invoked' > invoked");
    fs::write(f.root.join("outside.par2"), b"outside sentinel").unwrap();
    let result = repair_with_binary(&f.binary, &f.scratch, &[Path::new("../outside.par2")]);
    assert!(result.is_err(), "parent traversal accepted: {result:?}");
    assert!(!f.scratch.join("invoked").exists());
}

#[test]
fn symlink_file_escape_is_rejected_before_spawn() {
    let f = Fixture::new("printf 'invoked' > invoked");
    let outside = f.root.join("outside.par2");
    fs::write(&outside, b"outside sentinel").unwrap();
    symlink(&outside, f.scratch.join("escape.par2")).unwrap();
    let result = repair_with_binary(&f.binary, &f.scratch, &[Path::new("escape.par2")]);
    assert!(result.is_err(), "symlink escape accepted: {result:?}");
    assert!(!f.scratch.join("invoked").exists());
}

#[test]
fn symlink_directory_escape_is_rejected_before_spawn() {
    let f = Fixture::new("printf 'invoked' > invoked");
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("file.par2"), b"outside sentinel").unwrap();
    symlink(&outside, f.scratch.join("link")).unwrap();
    let result = repair_with_binary(&f.binary, &f.scratch, &[Path::new("link/file.par2")]);
    assert!(
        result.is_err(),
        "directory symlink escape accepted: {result:?}"
    );
    assert!(!f.scratch.join("invoked").exists());
}
