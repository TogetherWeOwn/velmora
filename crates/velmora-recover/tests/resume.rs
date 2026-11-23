use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use velmora_recover::resume::{ExtentCheck, ObjectCheck, Output, OutputRoot};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut random = [0; 16];
        velmora::rng::FillRandom::fill_bytes(&mut velmora::rng::SystemRng, &mut random).unwrap();
        let name = format!("velmora-resume-{:032x}", u128::from_be_bytes(random));
        let root = std::env::temp_dir().join(name);
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

const FIRST: &[u8] = b"first verified extent";
const SECOND: &[u8] = b"second verified extent";
fn extent(offset: u64, bytes: &[u8]) -> ExtentCheck {
    ExtentCheck {
        id: format!("x_fixture_{offset}"),
        offset,
        len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}
fn checks() -> ([ExtentCheck; 2], [u8; 16]) {
    (
        [extent(0, FIRST), extent(FIRST.len() as u64, SECOND)],
        md5::compute([FIRST, SECOND].concat()).0,
    )
}
fn new_session(root: &Path) -> OutputRoot {
    OutputRoot::open(root).unwrap()
}
fn open<'a, 's>(
    root: &'s mut OutputRoot,
    extents: &'a [ExtentCheck],
    md5: [u8; 16],
) -> Output<'s, 'a> {
    root.object(ObjectCheck {
        bucket: "bucket",
        key: "prefix/file",
        generation: "generation",
        size: (FIRST.len() + SECOND.len()) as u64,
        md5: Some(md5),
        extents,
    })
    .unwrap()
}

#[test]
fn resume_process_child() {
    let Some(root) = std::env::var_os("VELMORA_RECOVER_TEST_CHILD") else {
        return;
    };
    let (checks, expected) = checks();
    let mut session = new_session(Path::new(&root));
    let mut output = open(&mut session, &checks, expected);
    output.write_verified(0, FIRST).unwrap();
    println!("first extent committed");
    // Block deterministically after fsync, not on a timing guess.
    std::thread::park();
}

#[cfg(unix)]
#[test]
fn kill9_leaves_no_final_and_resume_skips_verified_extent() {
    use std::os::unix::process::ExitStatusExt;
    let root = Scratch::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "resume_process_child", "--nocapture"])
        .env("VELMORA_RECOVER_TEST_CHILD", &root.0)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let reached = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
        .any(|line| line == "first extent committed");
    let final_path = root.0.join("bucket/prefix/file");
    let premature_final = final_path.exists();
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(9));
    assert!(reached);
    assert!(!premature_final);
    let (checks, expected) = checks();
    let mut session = new_session(&root.0);
    let mut output = open(&mut session, &checks, expected);
    assert!(output.verified(0).unwrap());
    assert!(!output.verified(1).unwrap());
    output.write_verified(1, SECOND).unwrap();
    assert_eq!(output.finish().unwrap(), expected);
    assert_eq!(fs::read(final_path).unwrap(), [FIRST, SECOND].concat());
}

#[test]
fn wrong_extent_sha_and_whole_md5_are_not_promoted() {
    let root = Scratch::new();
    let (checks, mut expected) = checks();
    expected[0] ^= 1;
    let mut session = new_session(&root.0);
    let mut output = open(&mut session, &checks, expected);
    let mut bad = FIRST.to_vec();
    bad[0] ^= 1;
    assert!(output.write_verified(0, &bad).is_err());
    assert!(!output.verified(0).unwrap());
    output.write_verified(0, FIRST).unwrap();
    output.write_verified(1, SECOND).unwrap();
    assert!(output.finish().is_err());
    assert!(!root.0.join("bucket/prefix/file").exists());
}

#[test]
fn journal_marks_do_not_trust_tampered_part_or_torn_line() {
    use std::io::{Seek, SeekFrom, Write};
    let root = Scratch::new();
    let (checks, expected) = checks();
    let mut session = new_session(&root.0);
    let mut output = open(&mut session, &checks, expected);
    output.write_verified(0, FIRST).unwrap();
    drop(output);
    drop(session);
    let part = fs::read_dir(root.0.join(".velmora-recover-parts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut f = fs::OpenOptions::new().write(true).open(part).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(b"?").unwrap();
    let journal = root.0.join(".velmora-recover.jsonl");
    fs::OpenOptions::new()
        .append(true)
        .open(journal)
        .unwrap()
        .write_all(b"{\"torn")
        .unwrap();
    let mut session = new_session(&root.0);
    let mut output = open(&mut session, &checks, expected);
    assert!(!output.verified(0).unwrap());
    output.write_verified(0, FIRST).unwrap();
    output.write_verified(1, SECOND).unwrap();
    output.finish().unwrap();
    assert_eq!(
        fs::read(root.0.join("bucket/prefix/file")).unwrap(),
        [FIRST, SECOND].concat()
    );
}

#[test]
fn maps_traversal_and_a_different_existing_file_without_losing_data() {
    let root = Scratch::new();
    let (checks, expected) = checks();
    let mut session = new_session(&root.0);
    let unsafe_key = session
        .object(ObjectCheck {
            bucket: "bucket",
            key: "../escape",
            generation: "other",
            size: 0,
            md5: None,
            extents: &[],
        })
        .unwrap();
    assert!(unsafe_key.is_unmapped());
    assert_eq!(
        unsafe_key.path().file_name().unwrap(),
        "%2E%2E%2F%65%73%63%61%70%65"
    );
    unsafe_key.finish().unwrap();
    assert!(!root.0.join("escape").exists());
    fs::create_dir_all(root.0.join("bucket/prefix")).unwrap();
    let final_path = root.0.join("bucket/prefix/file");
    fs::write(&final_path, b"unrelated").unwrap();
    let mut output = open(&mut session, &checks, expected);
    assert!(output.is_unmapped());
    output.write_verified(0, FIRST).unwrap();
    output.write_verified(1, SECOND).unwrap();
    let recovered = output.path().to_owned();
    output.finish().unwrap();
    assert_eq!(fs::read(final_path).unwrap(), b"unrelated");
    assert_eq!(fs::read(recovered).unwrap(), [FIRST, SECOND].concat());
    let report = fs::read_to_string(root.0.join("_unmapped/_report/INDEX.tsv")).unwrap();
    assert!(report.contains("bucket\t../escape\t_unmapped/"));
    assert!(report.contains("bucket\tprefix/file\t_unmapped/"));
}

#[test]
fn unmapped_report_does_not_collide_with_bucket_names() {
    let root = Scratch::new();
    let mut session = new_session(&root.0);
    for bucket in ["index.tsv", "_RePoRt"] {
        let output = session
            .object(ObjectCheck {
                bucket,
                key: "..",
                generation: "g_test",
                size: 0,
                md5: None,
                extents: &[],
            })
            .unwrap();
        let path = output.path().to_owned();
        assert_eq!(path.file_name().unwrap(), "%2E%2E");
        output.finish().unwrap();
        assert!(path.is_file());
    }
    let report = fs::read_to_string(root.0.join("_unmapped/_report/INDEX.tsv")).unwrap();
    assert!(report.contains("index.tsv\t..\t"));
    assert!(report.contains("_RePoRt\t..\t"));
}

#[test]
fn case_variants_with_equal_bytes_keep_distinct_recovery_paths() {
    let root = Scratch::new();
    let mut session = new_session(&root.0);
    let checks = [extent(0, FIRST)];
    let check = |key, generation| ObjectCheck {
        bucket: "bucket",
        key,
        generation,
        size: FIRST.len() as u64,
        md5: None,
        extents: &checks,
    };
    let mut first = session.object(check("Photo.jpg", "a")).unwrap();
    first.write_verified(0, FIRST).unwrap();
    let first_path = first.path().to_owned();
    first.finish().unwrap();
    let aliases = root.0.join("bucket/photo.jpg").exists();
    let mut second = session.object(check("photo.jpg", "b")).unwrap();
    assert_eq!(second.is_unmapped(), aliases);
    let second_path = second.path().to_owned();
    second.write_verified(0, FIRST).unwrap();
    second.finish().unwrap();
    assert_ne!(first_path, second_path);
    if aliases {
        assert!(
            fs::read_to_string(root.0.join("_unmapped/_report/INDEX.tsv"))
                .unwrap()
                .contains("\tphoto.jpg\t")
        );
    }
    let first_again = session.object(check("Photo.jpg", "a")).unwrap();
    assert!(!first_again.is_unmapped());
    assert_eq!(first_again.path(), first_path);
    first_again.finish().unwrap();
}

#[test]
fn refuses_second_writer_until_lock_is_released() {
    let root = Scratch::new();
    let first = OutputRoot::open(&root.0).unwrap();
    assert!(OutputRoot::open(&root.0).is_err());
    drop(first);
    assert!(OutputRoot::open(&root.0).is_ok());
}

#[cfg(unix)]
#[test]
fn a_part_hard_linked_to_an_edited_file_is_recreated_without_overwriting_it() {
    let root = Scratch::new();
    let (checks, expected) = checks();
    {
        let mut session = new_session(&root.0);
        let mut output = open(&mut session, &checks, expected);
        output.write_verified(0, FIRST).unwrap();
        output.write_verified(1, SECOND).unwrap();
    }
    let stage = fs::read_dir(root.0.join(".velmora-recover-parts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let user_file = root.0.join("bucket/prefix/file");
    // Reproduce a crash after publication linked the part but before removal.
    fs::hard_link(stage, &user_file).unwrap();
    fs::write(&user_file, b"independent user edit").unwrap();
    let mut session = new_session(&root.0);
    let mut output = open(&mut session, &checks, expected);
    assert!(output.is_unmapped());
    let recovered = output.path().to_owned();
    output.write_verified(0, FIRST).unwrap();
    output.write_verified(1, SECOND).unwrap();
    output.finish().unwrap();
    assert_eq!(fs::read(user_file).unwrap(), b"independent user edit");
    assert_eq!(fs::read(recovered).unwrap(), [FIRST, SECOND].concat());
}

#[cfg(unix)]
#[test]
fn rejects_group_writable_staging_directory() {
    use std::os::unix::fs::PermissionsExt;
    let root = Scratch::new();
    let dir = root.0.join(".velmora-recover-parts");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(OutputRoot::open(&root.0).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_ancestor_is_never_followed_and_long_key_is_preserved() {
    let root = Scratch::new();
    let external = Scratch::new();
    fs::create_dir(root.0.join("bucket")).unwrap();
    std::os::unix::fs::symlink(&external.0, root.0.join("bucket/alias")).unwrap();
    let mut session = new_session(&root.0);
    let long = "x".repeat(512);
    for (key, generation) in [("alias/escaped", "a"), (&long, "b")] {
        let extent = [extent(0, FIRST)];
        let mut output = session
            .object(ObjectCheck {
                bucket: "bucket",
                key,
                generation,
                size: FIRST.len() as u64,
                md5: None,
                extents: &extent,
            })
            .unwrap();
        assert!(output.is_unmapped());
        output.write_verified(0, FIRST).unwrap();
        let path = output.path().to_owned();
        if key == long {
            let leaf = path.file_name().unwrap().to_str().unwrap();
            let (prefix, digest) = leaf.split_once('~').unwrap();
            assert_eq!(prefix, "%78".repeat(58));
            assert_eq!(
                digest,
                velmora_recover::catalogue::hex(&Sha256::digest(long.as_bytes()))
            );
            assert!(leaf.len() <= 240);
        }
        output.finish().unwrap();
        assert_eq!(fs::read(path).unwrap(), FIRST);
    }
    assert!(fs::read_dir(&external.0).unwrap().next().is_none());
    assert!(
        fs::read_to_string(root.0.join("_unmapped/_report/INDEX.tsv"))
            .unwrap()
            .contains(&long)
    );
}
