//! PAR2 recovery-set parsing and verification, ported from the v1 Go worker
//! (`worker/internal/ingest/par2`: `recoveryset.go`, `crc32combine.go`).
//!
//! [`RecoverySet::parse`] verifies every packet checksum and cross-checks the
//! set identity (the set ID must be the MD5 of the Main packet body), the
//! Main-packet membership list, per-file ID derivation, and duplicate packets
//! — the same checks v1 performs before trusting any metadata.
//!
//! Two verification paths, mirroring v1:
//!
//! - [`RecoverySet::verify`]: recomputes per-block CRC32s over candidate bytes
//!   (each slice zero-padded to the block size, per the PAR2 spec) plus the
//!   whole-file MD5. Runs anywhere, including wasm.
//! - [`RecoverySet::precheck`]: recombines independently computed per-segment
//!   CRC32s via [`crc32_combine`] (zlib's `crc32_combine`, ported from v1's
//!   `Combine`) and compares against the recovery set — proves a file intact
//!   without re-hashing, so the repair binary never runs for healthy files.
//!
//! Actual repair (Reed-Solomon over recovery slices) stays native-only:
//! [`repair`] shells out to `par2cmdline-turbo` inside a scratch directory,
//! which is a Container batch job, never a Worker.

use std::collections::HashMap;

use crate::error::{Error, Result};

const PACKET_HEADER_SIZE: usize = 64;
const PACKET_MAGIC: [u8; 8] = *b"PAR2\0PKT";
const MAIN_HEADER_SIZE: usize = 12;
const IFSC_ENTRY_SIZE: usize = 20;

/// Largest accepted Main-packet slice size (256 MiB). The PAR2 spec sets no
/// bound, but `verify`/`precheck` hash up to one slice of zeroes for the
/// last-block padding, so an unbounded slice size turns a ~200-byte packet
/// into unbounded CPU work (and, before chunked hashing, unbounded memory).
/// 256 MiB slices imply multi-terabyte files at par2cmdline's block-count
/// limits — far outside anything on Usenet, let alone music posts. A set
/// beyond this must go straight to the repair binary (the reconstruction
/// authority), never through in-Worker verification.
pub const MAX_BLOCK_SIZE: u64 = 256 << 20;

/// Streaming zero-run hasher chunk: zero padding is hashed in pieces of this
/// size so verification never holds a slice-sized zero allocation.
const ZERO_CHUNK_SIZE: usize = 8192;

fn packet_type(suffix: &[u8]) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(b"PAR 2.0\0");
    t[8..8 + suffix.len().min(8)].copy_from_slice(&suffix[..suffix.len().min(8)]);
    t
}

fn main_type() -> [u8; 16] {
    packet_type(b"Main\0\0\0\0")
}
fn filedesc_type() -> [u8; 16] {
    packet_type(b"FileDesc")
}
fn ifsc_type() -> [u8; 16] {
    packet_type(b"IFSC\0\0\0\0")
}
fn recv_slic_type() -> [u8; 16] {
    packet_type(b"RecvSlic")
}

/// One source file described by the recovery set.
#[derive(Debug, Clone)]
pub struct RecoveryFile {
    /// PAR2 File ID: MD5(16k-hash ‖ length ‖ name).
    pub file_id: [u8; 16],
    /// MD5 of the whole file.
    pub whole_md5: [u8; 16],
    /// MD5 of the first 16 KiB.
    pub first16k_md5: [u8; 16],
    /// Lossy display name (PAR2 metadata, never a storage key).
    pub filename: String,
    /// Original filename bytes, excluding NUL padding; authoritative identity.
    pub filename_bytes: Vec<u8>,
    /// Declared file length in bytes.
    pub length: u64,
    /// Per-block CRC32s from the IFSC packet (each covers a full
    /// block-size slice, zero-padded past end-of-file).
    pub block_crc32s: Vec<u32>,
    /// True when the Main packet lists this file among its recoverable
    /// (first-N) IDs. Only protected files may vouch for bytes.
    pub protected: bool,
    /// True when a FileDesc packet supplied name/length/hashes.
    pub has_file_desc: bool,
}

/// A verified PAR2 recovery set: the metadata subset repair and
/// deobfuscation need.
#[derive(Debug, Clone, Default)]
pub struct RecoverySet {
    /// MD5 of the Main packet body; every packet must carry it.
    pub set_id: [u8; 16],
    /// Main-packet slice size. Never assumed — always read from the set.
    pub block_size: u64,
    /// Number of recovery-slice packets seen.
    pub recovery_blocks: usize,
    /// Files by File ID.
    pub files: HashMap<[u8; 16], RecoveryFile>,
}

/// Incremental counterpart of [`RecoverySet::parse`]: packet streams
/// (whole `.par2` objects, or chunks split at packet boundaries) are fed
/// one at a time with [`add_stream`](Self::add_stream) and validated as
/// one set by [`finish`](Self::finish). This lets a memory-bounded caller
/// restore a large set from storage object by object instead of holding
/// every staged byte at once; only the parsed metadata (plus per-packet
/// digests for duplicate validation) is retained.
#[derive(Debug, Clone, Default)]
pub struct RecoverySetBuilder {
    set: RecoverySet,
    members: HashMap<[u8; 16], ()>,
    protected: HashMap<[u8; 16], ()>,
    filenames: HashMap<Vec<u8>, [u8; 16]>,
    recovery_packets: HashMap<u32, [u8; 16]>,
    set_id_seen: bool,
    main_seen: bool,
    main_digest: [u8; 16],
    // (file_id -> (packet md5, kind)) for duplicate validation.
    filedesc_digests: HashMap<[u8; 16], [u8; 16]>,
    ifsc_digests: HashMap<[u8; 16], [u8; 16]>,
}

/// Set id carried by the first packet in `data`, without validating the
/// stream: enough for a caller restoring several sets to route each
/// object to its [`RecoverySetBuilder`] (which then fully validates it).
/// `None` when `data` does not start with a PAR2 packet header.
pub fn peek_set_id(data: &[u8]) -> Option<[u8; 16]> {
    if data.len() < PACKET_HEADER_SIZE || data[..8] != PACKET_MAGIC {
        return None;
    }
    data[32..48].try_into().ok()
}

impl RecoverySetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The set id seen so far, once any packet has been accepted.
    pub fn set_id(&self) -> Option<[u8; 16]> {
        self.set_id_seen.then_some(self.set.set_id)
    }

    /// Feed one packet stream. `data` must begin and end on packet
    /// boundaries (splitting between packets is fine, splitting inside
    /// one is not). Packets are checksum- and set-verified before they
    /// are applied, so an error leaves earlier accepted packets intact;
    /// the caller decides whether the offending stream dooms the set.
    pub fn add_stream(&mut self, data: &[u8]) -> Result<()> {
        let Self {
            set,
            members,
            protected,
            filenames,
            recovery_packets,
            set_id_seen,
            main_seen,
            main_digest,
            filedesc_digests,
            ifsc_digests,
        } = self;
        let mut offset = 0usize;
        while offset < data.len() {
            let remaining = &data[offset..];
            if remaining.len() < PACKET_HEADER_SIZE {
                return Err(malformed(format!(
                    "truncated packet header at offset {offset}"
                )));
            }
            if remaining[..8] != PACKET_MAGIC {
                return Err(malformed(format!("bad magic at offset {offset}")));
            }
            let length = u64::from_le_bytes(remaining[8..16].try_into().unwrap()) as usize;
            if length < PACKET_HEADER_SIZE || length % 4 != 0 || length > remaining.len() {
                return Err(malformed(format!(
                    "invalid packet length at offset {offset}"
                )));
            }
            let packet = &remaining[..length];
            let declared_md5: [u8; 16] = packet[16..32].try_into().unwrap();
            if md5::compute(&packet[32..]).0 != declared_md5 {
                return Err(malformed(format!(
                    "packet checksum mismatch at offset {offset}"
                )));
            }
            let set_id: [u8; 16] = packet[32..48].try_into().unwrap();
            if !*set_id_seen {
                set.set_id = set_id;
                *set_id_seen = true;
            } else if set.set_id != set_id {
                return Err(malformed(format!("mixed recovery set at offset {offset}")));
            }

            let mut kind = [0u8; 16];
            kind.copy_from_slice(&packet[48..64]);
            let body = &packet[64..];
            if kind == main_type() {
                parse_main_body(
                    body,
                    members,
                    protected,
                    main_seen,
                    main_digest,
                    set,
                    set_id,
                )?;
            } else if kind == filedesc_type() {
                parse_filedesc_body(body, set, filenames, filedesc_digests)?;
            } else if kind == ifsc_type() {
                parse_ifsc_body(body, set, ifsc_digests)?;
            } else if kind == recv_slic_type() {
                if body.len() < 4 {
                    return Err(malformed("recovery slice body too short"));
                }
                let exponent = u32::from_le_bytes(body[..4].try_into().unwrap());
                let digest = md5::compute(body).0;
                match recovery_packets.get(&exponent) {
                    Some(prev) if *prev != digest => {
                        return Err(malformed("conflicting duplicate recovery slice"));
                    }
                    Some(_) => {}
                    None => {
                        recovery_packets.insert(exponent, digest);
                        set.recovery_blocks += 1;
                    }
                }
            }
            // Unknown packet types are ignored (forward compatibility), but
            // their checksum and set-ID checks above still applied.
            offset += length;
        }
        Ok(())
    }

    /// Validate the accumulated streams as one recovery set: a Main
    /// packet must have been seen, and it is the only authority on
    /// membership (checked last because packet order is not fixed).
    pub fn finish(mut self) -> Result<RecoverySet> {
        if !self.main_seen || self.set.block_size == 0 {
            return Err(malformed("no Main packet found"));
        }
        for (id, file) in self.set.files.iter_mut() {
            if !self.members.contains_key(id) {
                return Err(malformed(format!(
                    "file ID {} is not listed in the Main packet",
                    hex16(id)
                )));
            }
            file.protected = self.protected.contains_key(id);
        }
        let _ = self.main_digest;
        Ok(self.set)
    }
}

impl RecoverySet {
    /// Parses and fully validates a concatenated PAR2 packet stream (one or
    /// more `.par2` objects back to back). Repeated metadata packets are
    /// normal across volume files, but only byte-identical repeats pass.
    pub fn parse(data: &[u8]) -> Result<RecoverySet> {
        let mut builder = RecoverySetBuilder::new();
        builder.add_stream(data)?;
        builder.finish()
    }

    /// Resolves a display name only when it identifies exactly one file.
    /// Distinct legacy encodings may have the same lossy display name.
    pub fn file_by_name(&self, name: &str) -> Option<&RecoveryFile> {
        let mut matches = self
            .files
            .values()
            .filter(|f| f.has_file_desc && f.filename == name);
        let file = matches.next()?;
        if matches.next().is_some() {
            None
        } else {
            Some(file)
        }
    }

    /// Resolves the original NUL-trimmed filename without lossy conversion.
    pub fn file_by_name_bytes(&self, name: &[u8]) -> Option<&RecoveryFile> {
        self.files
            .values()
            .find(|f| f.has_file_desc && f.filename_bytes == name)
    }

    /// Resolves a name only when the set actually protects that file. A
    /// non-recovery description carries a real name and real hashes but no
    /// recovery blocks: accepting one as repair metadata would let a crafted
    /// Main packet certify bytes the set cannot reconstruct.
    pub fn protected_file_by_name(&self, name: &str) -> Option<&RecoveryFile> {
        self.file_by_name(name)
            .filter(|f| f.protected && f.has_file_desc)
    }

    /// Byte-precise counterpart of [`Self::protected_file_by_name`].
    pub fn protected_file_by_name_bytes(&self, name: &[u8]) -> Option<&RecoveryFile> {
        self.file_by_name_bytes(name).filter(|f| f.protected)
    }

    /// Verifies candidate bytes against a protected file's metadata: length,
    /// whole-file MD5, and every per-block CRC32 (each block zero-padded to
    /// the set's block size, per the PAR2 spec). `Ok(())` means healthy.
    pub fn verify(&self, name: &str, data: &[u8]) -> Result<()> {
        let file = self
            .protected_file_by_name(name)
            .ok_or_else(|| Error::Par2Unhealthy {
                filename: name.to_string(),
                detail: "no protected recovery-set entry for this file".into(),
            })?;
        self.verify_file(file, data)
    }

    /// Like [`Self::verify`], selecting by the original filename bytes rather
    /// than a potentially ambiguous display name.
    pub fn verify_bytes(&self, name: &[u8], data: &[u8]) -> Result<()> {
        let file = self
            .protected_file_by_name_bytes(name)
            .ok_or_else(|| Error::Par2Unhealthy {
                filename: String::from_utf8_lossy(name).into_owned(),
                detail: "no protected recovery-set entry for this file".into(),
            })?;
        self.verify_file(file, data)
    }

    fn verify_file(&self, file: &RecoveryFile, data: &[u8]) -> Result<()> {
        let name = &file.filename;
        if data.len() as u64 != file.length {
            return Err(Error::Par2Unhealthy {
                filename: name.to_string(),
                detail: format!(
                    "size {} differs from recovery-set length {}",
                    data.len(),
                    file.length
                ),
            });
        }
        if md5::compute(data).0 != file.whole_md5 {
            return Err(Error::Par2Unhealthy {
                filename: name.to_string(),
                detail: "whole-file MD5 mismatch".into(),
            });
        }
        if self.block_size == 0 {
            // `parse` never produces this (Main requires a non-zero slice
            // size), but a hand-built set could — and `div_ceil` below would
            // divide by zero.
            return Err(Error::Par2Unhealthy {
                filename: name.to_string(),
                detail: "recovery set block size must be positive".into(),
            });
        }
        if file.block_crc32s.is_empty() {
            return Err(Error::Par2Unhealthy {
                filename: name.to_string(),
                detail: "recovery set carries no block checksums for this file".into(),
            });
        }
        // A crafted IFSC may carry more (or fewer) checksums than the file's
        // length admits. Without this check the loop below indexes past the
        // data and panics — a remote panic from a ~200-byte packet.
        let bs = self.block_size;
        let blocks = file.length.div_ceil(bs);
        if file.block_crc32s.len() as u64 != blocks {
            return Err(Error::Par2Unhealthy {
                filename: name.to_string(),
                detail: format!(
                    "recovery set carries {} block checksums for a {}-byte file at {}-byte slices (want {blocks})",
                    file.block_crc32s.len(),
                    file.length,
                    bs
                ),
            });
        }
        for (i, &want) in file.block_crc32s.iter().enumerate() {
            // u64 arithmetic throughout: `block_size` is parse-capped, and
            // `start`/`end` never exceed `data.len()` (which equals
            // `file.length`, checked above), so the `as usize` casts below
            // cannot truncate on any target.
            let start = i as u64 * bs;
            let end = (start + bs).min(data.len() as u64);
            let mut hash = crc32fast::Hasher::new();
            hash.update(&data[start as usize..end as usize]);
            if end - start < bs {
                // Last slice is checksummed zero-padded to the full size,
                // hashed in fixed chunks so verification never allocates a
                // slice-sized zero buffer from an untrusted size.
                update_zero_run(&mut hash, bs - (end - start));
            }
            if hash.finalize() != want {
                return Err(Error::Par2Unhealthy {
                    filename: name.to_string(),
                    detail: format!("block {i} CRC32 mismatch"),
                });
            }
        }
        Ok(())
    }

    /// Whole-file precheck without re-hashing: recombines independently
    /// computed per-segment CRC32s (captured at yEnc-decode time) via
    /// [`crc32_combine`], recombines the recovery set's per-block CRC32s the
    /// same way, and reports whether they match. A match proves the file
    /// intact without ever invoking the repair binary. `segments` is
    /// `(crc32, length)` in file order.
    ///
    /// Like v1, only protected files with block checksums qualify; anything
    /// else is an error, never a silent pass.
    pub fn precheck(&self, name: &str, segments: &[(u32, u64)]) -> Result<bool> {
        let file = self.protected_file_by_name(name).ok_or_else(|| {
            Error::Malformed(format!("par2 precheck: no protected entry for {name:?}"))
        })?;
        self.precheck_file(file, segments)
    }

    /// Like [`Self::precheck`], selecting by the original filename bytes.
    pub fn precheck_bytes(&self, name: &[u8], segments: &[(u32, u64)]) -> Result<bool> {
        let file = self.protected_file_by_name_bytes(name).ok_or_else(|| {
            Error::Malformed(format!("par2 precheck: no protected entry for {name:?}"))
        })?;
        self.precheck_file(file, segments)
    }

    fn precheck_file(&self, file: &RecoveryFile, segments: &[(u32, u64)]) -> Result<bool> {
        if self.block_size == 0 {
            return Err(Error::Malformed(
                "par2 precheck: block size must be positive".into(),
            ));
        }
        if file.block_crc32s.is_empty() {
            return Err(Error::Malformed(
                "par2 precheck: recovery set carries no block checksums for this file".into(),
            ));
        }
        // Same count check as `verify`: a crafted IFSC must not change the
        // padding arithmetic below (which assumes exactly ceil(len/bs) blocks).
        if file.block_crc32s.len() as u64 != file.length.div_ceil(self.block_size) {
            return Err(Error::Malformed(format!(
                "par2 precheck: recovery set carries {} block checksums for a {}-byte file",
                file.block_crc32s.len(),
                file.length
            )));
        }
        let mut actual_len = 0u64;
        let mut actual_crc = 0u32;
        for (i, &(crc, len)) in segments.iter().enumerate() {
            actual_crc = if i == 0 {
                crc
            } else {
                crc32_combine(actual_crc, crc, len)
            };
            actual_len = actual_len.checked_add(len).ok_or_else(|| {
                Error::Malformed("par2 precheck: segment length sum overflows u64".into())
            })?;
        }
        if actual_len != file.length {
            return Err(Error::Malformed(
                "par2 precheck: segment lengths do not sum to the recovery set's file length"
                    .into(),
            ));
        }
        let mut expected_crc = 0u32;
        for (i, &block_crc) in file.block_crc32s.iter().enumerate() {
            expected_crc = if i == 0 {
                block_crc
            } else {
                crc32_combine(expected_crc, block_crc, self.block_size)
            };
        }
        // Block checksums cover each block zero-padded to the full size, so
        // pad our combined CRC the same way instead of trying to "un-pad"
        // the recovery set's value (which would require an invertible combine).
        let padded = file.block_crc32s.len() as u64 * self.block_size;
        if padded > actual_len {
            let pad = padded - actual_len;
            actual_crc = crc32_combine(actual_crc, zero_run_crc32(pad), pad);
        }
        Ok(actual_crc == expected_crc)
    }
}

fn malformed(detail: impl Into<String>) -> Error {
    Error::Malformed(format!("par2: malformed recovery set: {}", detail.into()))
}

fn hex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_main_body(
    body: &[u8],
    members: &mut HashMap<[u8; 16], ()>,
    protected: &mut HashMap<[u8; 16], ()>,
    main_seen: &mut bool,
    main_digest: &mut [u8; 16],
    set: &mut RecoverySet,
    set_id: [u8; 16],
) -> Result<()> {
    if body.len() < MAIN_HEADER_SIZE {
        return Err(malformed("Main packet body too short"));
    }
    if (body.len() - MAIN_HEADER_SIZE) % 16 != 0 {
        return Err(malformed(
            "Main packet file ID list is not a whole number of 16-byte IDs",
        ));
    }
    let listed = (body.len() - MAIN_HEADER_SIZE) / 16;
    let recoverable = u32::from_le_bytes(body[8..12].try_into().unwrap());
    if recoverable == 0 || recoverable as usize > listed {
        return Err(malformed(format!(
            "Main packet declares {recoverable} recovery files but lists {listed} file IDs"
        )));
    }
    let block_size = u64::from_le_bytes(body[0..8].try_into().unwrap());
    if block_size == 0 || block_size % 4 != 0 {
        return Err(malformed(format!(
            "Main packet slice size {block_size} is not a non-zero multiple of 4"
        )));
    }
    if block_size > MAX_BLOCK_SIZE {
        return Err(malformed(format!(
            "Main packet slice size {block_size} exceeds the supported bound of {MAX_BLOCK_SIZE}"
        )));
    }
    // PAR2 derives the set ID from the Main packet: setid == MD5(body). A set
    // whose declared ID does not derive from its own Main packet is forged or
    // corrupt however many individual packet checksums agree.
    let digest = md5::compute(body).0;
    if digest != set_id {
        return Err(malformed(
            "recovery set ID is not the MD5 of the Main packet body",
        ));
    }
    if *main_seen {
        return Ok(());
    }
    for (index, chunk) in body[MAIN_HEADER_SIZE..].chunks_exact(16).enumerate() {
        let mut id = [0u8; 16];
        id.copy_from_slice(chunk);
        if members.contains_key(&id) {
            return Err(malformed(format!(
                "Main packet lists file ID {} twice",
                hex16(&id)
            )));
        }
        members.insert(id, ());
        if index < recoverable as usize {
            protected.insert(id, ());
        }
    }
    set.block_size = block_size;
    *main_digest = digest;
    *main_seen = true;
    Ok(())
}

fn parse_filedesc_body(
    body: &[u8],
    set: &mut RecoverySet,
    filenames: &mut HashMap<Vec<u8>, [u8; 16]>,
    digests: &mut HashMap<[u8; 16], [u8; 16]>,
) -> Result<()> {
    if body.len() < 56 {
        return Err(malformed("FileDesc packet body too short"));
    }
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&body[0..16]);
    let mut whole_md5 = [0u8; 16];
    whole_md5.copy_from_slice(&body[16..32]);
    let mut first16k = [0u8; 16];
    first16k.copy_from_slice(&body[32..48]);
    let length = u64::from_le_bytes(body[48..56].try_into().unwrap());
    let name = &body[56..];
    let end = name.iter().rposition(|&b| b != 0).map_or(0, |n| n + 1);
    let name = &name[..end];
    let filename = String::from_utf8_lossy(name).into_owned();

    // Identity uses original bytes, not a UTF-8 replacement character. Legacy
    // PAR2 writers commonly put ANSI filenames in the FileDesc packet.
    let mut seed = Vec::with_capacity(24 + name.len());
    seed.extend_from_slice(&body[32..56]);
    seed.extend_from_slice(name);
    if md5::compute(&seed).0 != file_id {
        return Err(malformed(
            "FileDesc file ID is not derived from its own 16k hash, length, and name",
        ));
    }
    if let Some(&other) = filenames.get(name) {
        if other != file_id {
            return Err(malformed(
                "duplicate filename belongs to different file IDs",
            ));
        }
    }
    let digest = md5::compute(body).0;
    if let Some(&prev) = digests.get(&file_id) {
        if prev != digest {
            return Err(malformed("conflicting duplicate FileDesc packet"));
        }
        return Ok(());
    }
    digests.insert(file_id, digest);
    let file = set.files.entry(file_id).or_insert(RecoveryFile {
        file_id,
        whole_md5: [0; 16],
        first16k_md5: [0; 16],
        filename: String::new(),
        filename_bytes: Vec::new(),
        length: 0,
        block_crc32s: Vec::new(),
        protected: false,
        has_file_desc: false,
    });
    file.whole_md5 = whole_md5;
    file.first16k_md5 = first16k;
    file.length = length;
    file.filename = filename;
    file.filename_bytes = name.to_vec();
    file.has_file_desc = true;
    filenames.insert(name.to_vec(), file_id);
    Ok(())
}

fn parse_ifsc_body(
    body: &[u8],
    set: &mut RecoverySet,
    digests: &mut HashMap<[u8; 16], [u8; 16]>,
) -> Result<()> {
    if body.len() < 16 {
        return Err(malformed("IFSC packet body too short"));
    }
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&body[0..16]);
    let entries = &body[16..];
    if entries.len() % IFSC_ENTRY_SIZE != 0 {
        return Err(malformed(
            "IFSC packet body is not a whole number of slice checksums",
        ));
    }
    let digest = md5::compute(body).0;
    if let Some(&prev) = digests.get(&file_id) {
        if prev != digest {
            return Err(malformed("conflicting duplicate IFSC packet"));
        }
        return Ok(());
    }
    digests.insert(file_id, digest);
    let crc32s = entries
        .chunks_exact(IFSC_ENTRY_SIZE)
        .map(|e| u32::from_le_bytes(e[16..20].try_into().unwrap()))
        .collect();
    let file = set.files.entry(file_id).or_insert(RecoveryFile {
        file_id,
        whole_md5: [0; 16],
        first16k_md5: [0; 16],
        filename: String::new(),
        filename_bytes: Vec::new(),
        length: 0,
        block_crc32s: Vec::new(),
        protected: false,
        has_file_desc: false,
    });
    file.block_crc32s = crc32s;
    Ok(())
}

// ---------------------------------------------------------------------------
// CRC32 combine (zlib's crc32_combine via GF(2) matrices, ported from v1)
// ---------------------------------------------------------------------------

const GF2_DIMENSION: usize = 32;

/// CRC-32 (IEEE) of the concatenation of two byte sequences, given the CRC-32
/// of each and the byte length of the second. Lets a whole-file CRC32 be
/// recombined from independently computed per-segment CRC32s without
/// re-reading the bytes.
pub fn crc32_combine(crc1: u32, crc2: u32, len2: u64) -> u32 {
    if len2 == 0 {
        return crc1;
    }
    let mut even = [0u32; GF2_DIMENSION];
    let mut odd = [0u32; GF2_DIMENSION];

    // Operator for one zero bit.
    odd[0] = 0xedb88320;
    let mut row = 1u32;
    for slot in odd.iter_mut().skip(1) {
        *slot = row;
        row <<= 1;
    }

    // Operator for two zero bits, then four.
    gf2_matrix_square(&mut even, &odd);
    gf2_matrix_square(&mut odd, &even);

    let mut crc = crc1;
    let mut len = len2;
    loop {
        // Turns "odd" (4 zero bits) into a one-zero-byte operator on the
        // first iteration, doubling the byte count every iteration after.
        gf2_matrix_square(&mut even, &odd);
        if len & 1 != 0 {
            crc = gf2_matrix_times(&even, crc);
        }
        len >>= 1;
        if len == 0 {
            break;
        }
        gf2_matrix_square(&mut odd, &even);
        if len & 1 != 0 {
            crc = gf2_matrix_times(&odd, crc);
        }
        len >>= 1;
        if len == 0 {
            break;
        }
    }
    crc ^ crc2
}

fn gf2_matrix_times(matrix: &[u32; GF2_DIMENSION], mut vec: u32) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while vec != 0 {
        if vec & 1 != 0 {
            sum ^= matrix[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

fn gf2_matrix_square(square: &mut [u32; GF2_DIMENSION], mat: &[u32; GF2_DIMENSION]) {
    for i in 0..GF2_DIMENSION {
        square[i] = gf2_matrix_times(mat, mat[i]);
    }
}

/// Feeds `n` zero bytes into the hasher in fixed chunks, so padding work
/// never allocates proportionally to an untrusted block size.
fn update_zero_run(hash: &mut crc32fast::Hasher, mut n: u64) {
    let zeros = [0u8; ZERO_CHUNK_SIZE];
    while n > 0 {
        let take = n.min(ZERO_CHUNK_SIZE as u64) as usize;
        hash.update(&zeros[..take]);
        n -= take as u64;
    }
}

/// CRC-32 of a run of `n` zero bytes (used to pad the last block; `n` is
/// bounded by the block size, hashed in chunks, so this stays a small
/// one-off computation even at the [`MAX_BLOCK_SIZE`] cap).
fn zero_run_crc32(n: u64) -> u32 {
    if n == 0 {
        return 0;
    }
    let mut hash = crc32fast::Hasher::new();
    update_zero_run(&mut hash, n);
    hash.finalize()
}

// ---------------------------------------------------------------------------
// Native-only repair
// ---------------------------------------------------------------------------

/// Repair via an external `par2` binary (`par2cmdline-turbo`). This spawns a
/// subprocess and needs a writable scratch directory: it is a Container batch
/// job, never a Worker. On wasm32 the function exists but always reports
/// [`Error::UnsupportedOnWasm`].
pub mod repair;
/// Scratch-object layout shared by ingest, the repair Worker and the
/// repair Container (prefix derivation, file-name and key validation).
pub mod scratch;
