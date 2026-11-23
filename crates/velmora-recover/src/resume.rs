//! Recover into a caller-controlled directory with one writer and no clobber.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PARTS: &str = ".velmora-recover-parts";
const JOURNAL: &str = ".velmora-recover.jsonl";
const UNMAPPED: &str = "_unmapped";
const REPORT_DIR: &str = "_report";
const REPORT: &str = "INDEX.tsv";
const MAX_COMPONENT_BYTES: usize = 240;

pub struct ObjectCheck<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub generation: &'a str,
    pub size: u64,
    pub md5: Option<[u8; 16]>,
    pub extents: &'a [ExtentCheck],
}

pub struct ExtentCheck {
    pub id: String,
    pub offset: u64,
    pub len: u64,
    pub sha256: [u8; 32],
}

#[derive(Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
struct Mark {
    generation: [u8; 32],
    ordinal: usize,
    extent_id: String,
    sha256: [u8; 32],
}

impl Mark {
    fn new(generation: [u8; 32], ordinal: usize, extent: &ExtentCheck) -> Self {
        Self {
            generation,
            ordinal,
            extent_id: extent.id.clone(),
            sha256: extent.sha256,
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn private_dir(path: &Path) -> io::Result<bool> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {
            sync_parent(path)?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            Ok(fs::symlink_metadata(path)?.is_dir())
        }
        Err(e) => Err(e),
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        })?
        .sync_all()?;
    }
    let _ = path;
    Ok(())
}

/// No symlinks, devices or pipes. As with any local restore, the caller
/// must control the output root and not let another program mutate it.
fn metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn state_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts
}

fn create_state_file(path: &Path) -> io::Result<File> {
    let file = state_options().create_new(true).open(path)?;
    sync_parent(path)?;
    Ok(file)
}

fn open_state_file(path: &Path) -> io::Result<File> {
    match create_state_file(path) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if !metadata(path)?.is_some_and(|m| m.is_file()) {
                return Err(invalid("recovery state path is not a regular file"));
            }
            let file = state_options().open(path)?;
            if !file.metadata()?.is_file() {
                return Err(invalid("recovery state handle is not a regular file"));
            }
            Ok(file)
        }
        Err(e) => Err(e),
    }
}

fn single_link(file: &File) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(file.metadata()?.nlink() == 1)
    }
    #[cfg(windows)]
    {
        use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;
        let mut info = MaybeUninit::uninit();
        // The file owns a live handle, and the API initializes the output on success.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { info.assume_init() }.nNumberOfLinks == 1)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(io::Error::other(
            "cannot inspect link count on this platform",
        ))
    }
}

fn require_single_link(file: &File) -> io::Result<()> {
    if single_link(file)? {
        Ok(())
    } else {
        Err(invalid("recovery state file has multiple links"))
    }
}

fn private_file(path: &Path) -> io::Result<File> {
    let file = open_state_file(path)?;
    require_single_link(&file)?;
    Ok(file)
}

fn open_part(path: &Path) -> io::Result<File> {
    let file = open_state_file(path)?;
    if single_link(&file)? {
        return Ok(file);
    }
    // A previous process can die after publication links the inode, but
    // before it unlinks the stage name. Never write through that inode.
    drop(file);
    fs::remove_file(path)?;
    create_state_file(path)
}

fn check_stage(path: &Path) -> io::Result<()> {
    if !private_dir(path)? {
        return Err(invalid("recovery stage is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::symlink_metadata(path)?;
        // geteuid does not access memory, and returns the process's effective UID.
        let uid = unsafe { libc::geteuid() };
        if !m.is_dir() || m.uid() != uid || m.mode() & 0o022 != 0 {
            return Err(invalid(
                "recovery stage must be owned by this user and not group- or world-writable",
            ));
        }
    }
    Ok(())
}

/// Replay only newline-terminated records. A SIGKILL can leave the final
/// record torn; truncate that incomplete tail under the writer lock.
fn read_lines(
    file: &mut File,
    max_line: u64,
    mut each: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut complete = 0;
    let mut reader = BufReader::new(&mut *file);
    let mut line = Vec::new();
    loop {
        line.clear();
        let len = (&mut reader)
            .take(max_line + 1)
            .read_until(b'\n', &mut line)? as u64;
        if len > max_line {
            return Err(invalid("recovery state line too large"));
        }
        if line.last() != Some(&b'\n') {
            break;
        }
        each(&line)?;
        complete += len;
    }
    if complete < file.metadata()?.len() {
        file.set_len(complete)?;
        file.sync_data()?;
    }
    file.seek(SeekFrom::End(0))?;
    Ok(())
}

pub struct OutputRoot {
    root: PathBuf,
    journal: File,
    marks: BTreeSet<Mark>,
    report: Option<File>,
    report_rows: BTreeSet<Vec<u8>>,
    directory_names: BTreeMap<PathBuf, BTreeSet<OsString>>,
}

impl OutputRoot {
    pub fn open(root: &Path) -> io::Result<Self> {
        if !private_dir(root)? {
            return Err(invalid("output root is not a directory"));
        }
        let root = root.canonicalize()?;
        check_stage(&root.join(PARTS))?;
        let mut journal = private_file(&root.join(JOURNAL))?;
        journal.try_lock().map_err(|_| {
            io::Error::other("recovery output is already locked or does not support locking")
        })?;
        let mut marks = BTreeSet::new();
        read_lines(&mut journal, 1024, |line| {
            marks.insert(
                serde_json::from_slice(line)
                    .map_err(|_| invalid("invalid recovery journal line"))?,
            );
            Ok(())
        })?;
        Ok(Self {
            root,
            journal,
            marks,
            report: None,
            report_rows: BTreeSet::new(),
            directory_names: BTreeMap::new(),
        })
    }

    /// Metadata can resolve a differently spelled entry on a case-folding
    /// or Unicode-normalizing filesystem. Accept only its exact stored name.
    fn exact_name(&mut self, path: &Path) -> io::Result<bool> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("missing output parent"))?;
        let leaf = path
            .file_name()
            .ok_or_else(|| invalid("missing output name"))?;
        if !self.directory_names.contains_key(parent) {
            let entries: BTreeSet<_> = fs::read_dir(parent)?
                .map(|r| r.map(|e| e.file_name()))
                .collect::<io::Result<_>>()?;
            self.directory_names.insert(parent.to_path_buf(), entries);
        }
        Ok(self.directory_names[parent].contains(leaf))
    }

    fn remember_name(&mut self, path: &Path) {
        if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            if let Some(entries) = self.directory_names.get_mut(parent) {
                entries.insert(name.to_owned());
            }
        }
    }

    fn direct_path(&mut self, bucket: &str, key: &str) -> io::Result<Option<PathBuf>> {
        if !normal_component(bucket)
            || [PARTS, JOURNAL, UNMAPPED]
                .iter()
                .any(|s| bucket.eq_ignore_ascii_case(s))
            || !key.split('/').all(normal_component)
        {
            return Ok(None);
        }
        let mut path = self.root.join(bucket);
        for component in key.split('/') {
            match metadata(&path)? {
                Some(m) if m.is_dir() && self.exact_name(&path)? => (),
                Some(_) => return Ok(None),
                None if private_dir(&path)? => self.remember_name(&path),
                None => return Ok(None),
            }
            path.push(component);
        }
        Ok(Some(path))
    }

    pub fn object<'s, 'a>(&'s mut self, check: ObjectCheck<'a>) -> io::Result<Output<'s, 'a>> {
        let mut offset = 0u64;
        for extent in check.extents {
            if extent.offset != offset {
                return Err(invalid("object extent placement is not contiguous"));
            }
            offset = offset
                .checked_add(extent.len)
                .ok_or_else(|| invalid("object size overflow"))?;
        }
        if offset != check.size {
            return Err(invalid("object extent placement does not cover its size"));
        }
        let mut hash = Sha256::new();
        for field in [check.generation, check.bucket, check.key] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        let generation: [u8; 32] = hash.finalize().into();
        let part_path = self
            .root
            .join(PARTS)
            .join(format!("{}.part", sha_hex(&generation)));
        let (dest, done, unmapped) = match self.direct_path(check.bucket, check.key)? {
            Some(dest) => match existing(&dest, &check)? {
                Existing::Same(md5) if self.exact_name(&dest)? => (dest, Some(md5), false),
                Existing::Absent => (dest, None, false),
                Existing::Same(_) | Existing::Different => self.fallback(&check)?,
            },
            None => self.fallback(&check)?,
        };
        let file = if done.is_none() {
            Some(open_part(&part_path)?)
        } else {
            None
        };
        Ok(Output {
            session: self,
            check,
            generation,
            dest,
            done,
            unmapped,
            part_path,
            file,
        })
    }

    fn fallback(&self, check: &ObjectCheck<'_>) -> io::Result<(PathBuf, Option<[u8; 16]>, bool)> {
        let mut dest = self.root.join(UNMAPPED);
        if !private_dir(&dest)? {
            return Err(invalid("unmapped output root is not a directory"));
        }
        dest.push(
            if normal_component(check.bucket) && !check.bucket.eq_ignore_ascii_case(REPORT_DIR) {
                check.bucket.to_owned()
            } else {
                format!("b-{}", escaped(check.bucket))
            },
        );
        if !private_dir(&dest)? {
            return Err(invalid("unmapped bucket path is not a directory"));
        }
        // Percent-encode every byte so case-insensitive filesystems do not
        // collapse distinct keys. Long leaves keep a full SHA-256 suffix;
        // the report retains the original key for lookup in either direction.
        let escaped = escaped(check.key);
        if escaped.is_empty() {
            dest.push("%"); // not a complete escape sequence
        } else if escaped.len() <= MAX_COMPONENT_BYTES {
            dest.push(escaped);
        } else {
            const PREFIX: usize = ((MAX_COMPONENT_BYTES - 1 - 64) / 3) * 3;
            let digest = sha_hex(&crate::extent::sha256(check.key.as_bytes()));
            dest.push(format!("{}~{digest}", &escaped[..PREFIX]));
        }
        let done = match existing(&dest, check)? {
            Existing::Absent => None,
            Existing::Same(md5) => Some(md5),
            Existing::Different => {
                return Err(invalid(
                    "unmapped destination already contains different data",
                ))
            }
        };
        Ok((dest, done, true))
    }

    fn write_report(&mut self, bucket: &str, key: &str, dest: &Path) -> io::Result<()> {
        if self.report.is_none() {
            let dir = self.root.join(UNMAPPED).join(REPORT_DIR);
            if !private_dir(&dir)? {
                return Err(invalid("unmapped report path is not a directory"));
            }
            let mut report = private_file(&dir.join(REPORT))?;
            read_lines(&mut report, 16384, |line| {
                self.report_rows.insert(line.to_vec());
                Ok(())
            })?;
            self.report = Some(report);
        }
        let relative = dest
            .strip_prefix(&self.root)
            .map_err(|_| invalid("unmapped path outside output"))?;
        let row = format!(
            "{}\t{}\t{}\n",
            tsv(bucket),
            tsv(key),
            tsv(&relative.to_string_lossy())
        )
        .into_bytes();
        if !self.report_rows.contains(&row) {
            let report = self.report.as_mut().expect("report opened above");
            require_single_link(report)?;
            report.write_all(&row)?;
            report.sync_data()?;
            self.report_rows.insert(row);
        }
        Ok(())
    }
}

fn sha_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            write!(out, "{b:02x}").expect("String is writable");
            out
        })
}

fn escaped(s: &str) -> String {
    use std::fmt::Write;
    s.bytes()
        .fold(String::with_capacity(s.len() * 3), |mut out, b| {
            write!(out, "%{b:02X}").expect("String is writable");
            out
        })
}

fn tsv(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\0', "\\0")
}

fn normal_component(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." || s.len() > 240 || s.contains(['/', '\\', '\0']) {
        return false;
    }
    #[cfg(windows)]
    {
        let base = s.split('.').next().unwrap_or_default().to_ascii_uppercase();
        if s.ends_with(['.', ' '])
            || s.chars()
                .any(|c| c.is_ascii_control() || "<>:\"|?*".contains(c))
            || matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ((base.starts_with("COM") || base.starts_with("LPT")) && base.chars().count() == 4)
        {
            return false;
        }
    }
    true
}

enum Existing {
    Absent,
    Same([u8; 16]),
    Different,
}

fn existing(path: &Path, check: &ObjectCheck<'_>) -> io::Result<Existing> {
    match metadata(path)? {
        None => Ok(Existing::Absent),
        Some(m) if m.is_file() && m.len() == check.size => {
            match verify_file(&mut File::open(path)?, check)? {
                Some(md5) => Ok(Existing::Same(md5)),
                None => Ok(Existing::Different),
            }
        }
        Some(_) => Ok(Existing::Different),
    }
}

fn verify_file(file: &mut File, check: &ObjectCheck<'_>) -> io::Result<Option<[u8; 16]>> {
    if file.metadata()?.len() != check.size {
        return Ok(None);
    }
    let mut md5 = md5::Context::new();
    for extent in check.extents {
        if extent_hash(file, extent, Some(&mut md5))? != Some(extent.sha256) {
            return Ok(None);
        }
    }
    let md5 = md5.finalize().0;
    Ok(check
        .md5
        .is_none_or(|expected| expected == md5)
        .then_some(md5))
}

fn extent_hash(
    file: &mut File,
    extent: &ExtentCheck,
    mut md5: Option<&mut md5::Context>,
) -> io::Result<Option<[u8; 32]>> {
    file.seek(SeekFrom::Start(extent.offset))?;
    let mut sha = Sha256::new();
    let mut left = extent.len;
    let mut buf = Zeroizing::new([0u8; 64 * 1024]);
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        match file.read_exact(&mut buf[..n]) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        sha.update(&buf[..n]);
        if let Some(hash) = &mut md5 {
            hash.consume(&buf[..n]);
        }
        left -= n as u64;
    }
    Ok(Some(sha.finalize().into()))
}

#[derive(Debug)]
struct ObjectIntegrity;

impl std::fmt::Display for ObjectIntegrity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("whole-object integrity check failed")
    }
}

impl std::error::Error for ObjectIntegrity {}

pub struct Output<'s, 'a> {
    session: &'s mut OutputRoot,
    check: ObjectCheck<'a>,
    generation: [u8; 32],
    dest: PathBuf,
    done: Option<[u8; 16]>,
    unmapped: bool,
    part_path: PathBuf,
    file: Option<File>,
}

impl Output<'_, '_> {
    pub fn is_unmapped(&self) -> bool {
        self.unmapped
    }
    pub fn path(&self) -> &Path {
        &self.dest
    }

    pub fn verified(&mut self, ordinal: usize) -> io::Result<bool> {
        let extent = self
            .check
            .extents
            .get(ordinal)
            .ok_or_else(|| invalid("unknown extent ordinal"))?;
        let Some(file) = &mut self.file else {
            return Ok(true);
        };
        let mark = Mark::new(self.generation, ordinal, extent);
        Ok(self.session.marks.contains(&mark)
            && extent_hash(file, extent, None)? == Some(extent.sha256))
    }

    pub fn write_verified(&mut self, ordinal: usize, bytes: &[u8]) -> io::Result<()> {
        let extent = self
            .check
            .extents
            .get(ordinal)
            .ok_or_else(|| invalid("unknown extent ordinal"))?;
        if extent.len != bytes.len() as u64 || extent.sha256 != crate::extent::sha256(bytes) {
            return Err(invalid("extent is not verified; not written"));
        }
        let Some(file) = &mut self.file else {
            return Ok(());
        };
        require_single_link(file)?;
        file.seek(SeekFrom::Start(extent.offset))?;
        file.write_all(bytes)?;
        file.sync_data()?;
        let mark = Mark::new(self.generation, ordinal, extent);
        if !self.session.marks.contains(&mark) {
            let mut line = serde_json::to_vec(&mark).map_err(io::Error::other)?;
            line.push(b'\n');
            require_single_link(&self.session.journal)?;
            self.session.journal.write_all(&line)?;
            self.session.journal.sync_data()?;
            self.session.marks.insert(mark);
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<[u8; 16], Box<dyn std::error::Error>> {
        let md5 = match self.done {
            Some(md5) => md5,
            None => {
                for i in 0..self.check.extents.len() {
                    let extent = &self.check.extents[i];
                    let mark = Mark::new(self.generation, i, extent);
                    if !self.session.marks.contains(&mark) {
                        return Err(invalid(
                            "cannot promote an object before every extent was verified",
                        )
                        .into());
                    }
                }
                let mut file = self
                    .file
                    .take()
                    .ok_or_else(|| invalid("missing staged object"))?;
                require_single_link(&file)?;
                file.set_len(self.check.size)?;
                let md5 = verify_file(&mut file, &self.check)?.ok_or(ObjectIntegrity)?;
                file.sync_all()?;
                drop(file);
                // Atomic no-clobber publication on the same filesystem. An
                // interruption after the link is safe: reopen verifies the
                // final file and then removes the leftover staging name.
                fs::hard_link(&self.part_path, &self.dest)?;
                self.session.remember_name(&self.dest);
                md5
            }
        };
        sync_parent(&self.dest)?;
        if metadata(&self.part_path)?.is_some_and(|m| m.is_file()) {
            fs::remove_file(&self.part_path)?;
            sync_parent(&self.part_path)?;
        }
        if self.unmapped {
            self.session
                .write_report(self.check.bucket, self.check.key, &self.dest)?;
        }
        Ok(md5)
    }
}
