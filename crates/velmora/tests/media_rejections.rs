//! `velmora.media.v1` rejection and behaviour tests (format decision §4).
//!
//! Every rejection asserts the error and that no plaintext of the affected
//! chunk reaches the caller's buffer (the destination is pre-filled with a
//! sentinel and must keep it for every byte of a failed chunk).
//!
//! The zero-AEAD-call and released-nothing checks that need the private
//! STREAM layer, and the C2SP CCTV age vectors, live in `src/media.rs`.

use std::cell::RefCell;
use std::io;

use sha2::{Digest, Sha256};
use velmora::media::{
    chunk_count, chunk_offset, ciphertext_size, Context, ConvergentKey, FileKey, Header, KeyMode,
    Profile, ReadAt, Sealer, VerifiedHeader, CIPHER_CHUNK_SIZE, HEADER_SIZE, PLAIN_CHUNK_SIZE,
};
use velmora::rng::FillRandom;
use velmora::{Error, Result};

const SENTINEL: u8 = 0xEE;
const CHUNK: usize = PLAIN_CHUNK_SIZE as usize;
const SEALED: usize = CIPHER_CHUNK_SIZE as usize;
const HDR: usize = HEADER_SIZE as usize;

struct Counter(u8);

impl FillRandom for Counter {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        for b in dest {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}

fn plaintext(size: usize, salt: u8) -> Vec<u8> {
    (0..size).map(|i| (i % 253) as u8 ^ salt).collect()
}

fn digest(pt: &[u8]) -> [u8; 32] {
    Sha256::digest(pt).into()
}

/// One Random-mode object under the NNTune profile.
struct Obj {
    key: FileKey,
    header: Header,
    pt: Vec<u8>,
    ct: Vec<u8>,
}

fn random_obj(size: usize, seed: u8) -> Obj {
    let profile = Profile::nntune();
    let key = FileKey::generate(&mut Counter(seed)).unwrap();
    let sealer = Sealer::random(&profile, &key, &mut Counter(seed.wrapping_add(100))).unwrap();
    let header = sealer.header();
    let pt = plaintext(size, seed);
    let ct = sealer.seal_to_vec(&pt).unwrap();
    Obj {
        key,
        header,
        pt,
        ct,
    }
}

fn verify(obj: &Obj) -> VerifiedHeader {
    VerifiedHeader::verify(&Profile::nntune(), KeyMode::Random, &obj.key, &obj.header).unwrap()
}

/// Full verify must fail, and a full ranged read must fail without writing
/// a single plaintext byte past the last good chunk before `bad_chunk`.
fn assert_rejected(verified: &VerifiedHeader, p: u64, ct: &[u8], bad_chunk: u64, what: &str) {
    let reader = verified.reader(p).unwrap();
    assert!(
        reader.verify_all(&ct.to_vec()).is_err(),
        "{what}: verify_all"
    );
    let mut dst = vec![SENTINEL; p as usize];
    let res = reader.read_at(ct, &mut dst, 0);
    assert!(res.is_err(), "{what}: read_at");
    let from = (bad_chunk as usize * CHUNK).min(dst.len());
    assert!(
        dst[from..].iter().all(|&b| b == SENTINEL),
        "{what}: plaintext of the failing chunk was released"
    );
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

#[test]
fn geometry_matches_decision() {
    assert_eq!(HEADER_SIZE, 48);
    assert_eq!(CIPHER_CHUNK_SIZE, 65_552);
    assert_eq!(velmora::article::ARTICLE_CIPHER_BLOCKS, 11);
    assert_eq!(velmora::article::ARTICLE_ZERO_PAYLOAD_BYTES, 721_120);
    for (p, total) in [(0u64, 64u64), (1, 65), (65_536, 65_600), (65_537, 65_617)] {
        assert_eq!(ciphertext_size(p), Some(total), "P = {p}");
        assert_eq!(
            random_obj(p as usize, 1).ct.len() as u64,
            total,
            "sealed P = {p}"
        );
    }
    assert_eq!(chunk_count(0), 1);
    assert_eq!(chunk_count(65_536), 1);
    assert_eq!(chunk_count(65_537), 2);
    assert_eq!(chunk_offset(1), Some(48 + 65_552));
    assert_eq!(ciphertext_size(u64::MAX), None);
}

// ---------------------------------------------------------------------------
// Truncation, extension, reorder, splice
// ---------------------------------------------------------------------------

#[test]
fn truncation_is_rejected_with_true_and_shortened_lengths() {
    let p = 3 * CHUNK + 100;
    let obj = random_obj(p, 2);
    let v = verify(&obj);
    let p64 = p as u64;
    let cuts: [(&str, usize, u64); 4] = [
        ("drop final chunk", HDR + 3 * SEALED, 3),
        ("drop two chunks", HDR + 2 * SEALED, 2),
        ("cut mid-chunk", HDR + 2 * SEALED + 1000, 2),
        ("cut inside header", 20, 0),
    ];
    for (what, len, bad) in cuts {
        let ct = &obj.ct[..len];
        assert_rejected(&v, p64, ct, bad, what);
    }
    // Attacker-shortened record lengths over the intact object.
    for short in [p64 - PLAIN_CHUNK_SIZE, p64 - 1, 3 * PLAIN_CHUNK_SIZE] {
        let reader = v.reader(short).unwrap();
        assert!(reader.verify_all(&obj.ct).is_err(), "P' = {short}");
        let last = chunk_count(short) - 1;
        let mut dst = vec![SENTINEL; short as usize];
        assert!(
            reader.read_at(&obj.ct, &mut dst, 0).is_err(),
            "P' = {short}"
        );
        assert!(dst[(last as usize * CHUNK)..]
            .iter()
            .all(|&b| b == SENTINEL));
    }
}

#[test]
fn extension_is_rejected() {
    let p = CHUNK + 10;
    let obj = random_obj(p, 3);
    let v = verify(&obj);
    let reader = v.reader(p as u64).unwrap();
    reader.verify_all(&obj.ct).unwrap();

    let mut trailing = obj.ct.clone();
    trailing.push(0);
    assert!(reader.verify_all(&trailing).is_err(), "trailing byte");

    // An extra chunk appended: with the true P it is trailing data; with
    // P grown to cover it, the formerly final chunk no longer opens.
    let mut extended = obj.ct.clone();
    extended.extend_from_slice(&obj.ct[HDR..HDR + SEALED]);
    assert!(reader.verify_all(&extended).is_err(), "appended chunk");
    assert_rejected(
        &v,
        (2 * CHUNK + CHUNK) as u64,
        &extended,
        1,
        "appended chunk, grown P",
    );

    // An empty final chunk when P > 0 (exact multiple): sealing refuses it,
    // and a hand-built one is trailing data.
    let profile = Profile::nntune();
    let mut s = Sealer::random(&profile, &obj.key, &mut Counter(9)).unwrap();
    s.seal_chunk(&vec![1; CHUNK], false).unwrap();
    assert!(
        s.seal_chunk(&[], true).is_err(),
        "empty final chunk after data"
    );
}

#[test]
fn reorder_and_duplicate_are_rejected() {
    let p = 4 * CHUNK;
    let obj = random_obj(p, 4);
    let v = verify(&obj);
    let chunk = |i: usize| obj.ct[HDR + i * SEALED..HDR + (i + 1) * SEALED].to_vec();

    let mut swapped = obj.ct.clone();
    swapped[HDR..HDR + SEALED].copy_from_slice(&chunk(1));
    swapped[HDR + SEALED..HDR + 2 * SEALED].copy_from_slice(&chunk(0));
    assert_rejected(&v, p as u64, &swapped, 0, "swap 0/1");

    let mut repeated = obj.ct.clone();
    repeated[HDR + 2 * SEALED..HDR + 3 * SEALED].copy_from_slice(&chunk(1));
    assert_rejected(&v, p as u64, &repeated, 2, "repeat chunk 1 at 2");
}

#[test]
fn article_chunks_moved_between_articles_are_rejected() {
    // Two articles of 11 chunks: move article 1's first chunk into article 0.
    let k = velmora::article::ARTICLE_CIPHER_BLOCKS;
    let p = (k + 2) * CHUNK;
    let obj = random_obj(p, 5);
    let v = verify(&obj);
    let mut moved = obj.ct.clone();
    let src = HDR + k * SEALED;
    let dst = HDR + 3 * SEALED;
    let bytes = obj.ct[src..src + SEALED].to_vec();
    moved[dst..dst + SEALED].copy_from_slice(&bytes);
    assert_rejected(&v, p as u64, &moved, 3, "article 1 chunk in article 0");
}

#[test]
fn cross_file_splice_is_rejected() {
    let p = 2 * CHUNK;
    let profile = Profile::drive();
    let pt = plaintext(p, 6);
    // Same K, different N.
    let key = FileKey::from_bytes([0x11; 32]);
    let a = Sealer::random(&profile, &key, &mut Counter(1)).unwrap();
    let b = Sealer::random(&profile, &key, &mut Counter(50)).unwrap();
    let ha = a.header();
    let ca = a.seal_to_vec(&pt).unwrap();
    let cb = b.seal_to_vec(&pt).unwrap();
    let va = VerifiedHeader::verify(&profile, KeyMode::Random, &key, &ha).unwrap();
    let mut spliced = ca.clone();
    spliced[HDR + SEALED..].copy_from_slice(&cb[HDR + SEALED..]);
    assert_rejected(&va, p as u64, &spliced, 1, "same K, different N");

    // Different K, same plaintext.
    let other = FileKey::from_bytes([0x22; 32]);
    let c = Sealer::random(&profile, &other, &mut Counter(1)).unwrap();
    let cc = c.seal_to_vec(&pt).unwrap();
    let mut spliced = ca.clone();
    spliced[HDR..HDR + SEALED].copy_from_slice(&cc[HDR..HDR + SEALED]);
    assert_rejected(&va, p as u64, &spliced, 0, "different K, same plaintext");

    // Every pair of modes over the same content.
    let objs = all_modes(&pt);
    for (i, (mi, ki, hi, ci)) in objs.iter().enumerate() {
        let vi = VerifiedHeader::verify(&profile, *mi, ki, hi).unwrap();
        for (j, (mj, _, hj, cj)) in objs.iter().enumerate() {
            if i == j {
                continue;
            }
            assert_ne!(ci, cj, "{mi:?} and {mj:?} never produce equal bytes");
            let mut spliced = ci.clone();
            spliced[HDR..].copy_from_slice(&cj[HDR..]);
            assert_rejected(&vi, p as u64, &spliced, 0, "cross-mode splice");
            // The other mode's header under this key and mode: commitment.
            assert!(VerifiedHeader::verify(&profile, *mi, ki, hj).is_err());
        }
        // Same K and N presented under every other mode.
        for other in [
            KeyMode::Random,
            KeyMode::VaultConvergent,
            KeyMode::PublicConvergent,
        ] {
            if other != *mi {
                assert!(VerifiedHeader::verify(&profile, other, ki, hi).is_err());
            }
        }
    }
}

fn all_modes(pt: &[u8]) -> Vec<(KeyMode, FileKey, Header, Vec<u8>)> {
    let profile = Profile::drive();
    let d = digest(pt);
    let p = pt.len() as u64;
    let random_key = FileKey::from_bytes([0x33; 32]);
    let r = Sealer::random(&profile, &random_key, &mut Counter(7)).unwrap();
    let rh = r.header();
    let rc = r.seal_to_vec(pt).unwrap();
    let vk = ConvergentKey::vault(&[0x44; 32], "drive/media", p, &d).unwrap();
    let vs = Sealer::convergent(&profile, &vk).unwrap();
    let vh = vs.header();
    let vc = vs.seal_to_vec(pt).unwrap();
    let pk = ConvergentKey::public(&[0x55; 64], "drive/media", p, &d).unwrap();
    let ps = Sealer::convergent(&profile, &pk).unwrap();
    let ph = ps.header();
    let pc = ps.seal_to_vec(pt).unwrap();
    vec![
        (KeyMode::Random, random_key, rh, rc),
        (
            KeyMode::VaultConvergent,
            FileKey::from_bytes(*vk.file_key().expose_secret()),
            vh,
            vc,
        ),
        (
            KeyMode::PublicConvergent,
            FileKey::from_bytes(*pk.file_key().expose_secret()),
            ph,
            pc,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Header: wrong key, ctx, mode, profile; bit flips
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_ctx_mode_and_profile_fail_at_the_header() {
    let obj = random_obj(100, 8);
    let nntune = Profile::nntune();
    let generic = |e: Error| match e {
        Error::Decrypt(m) => m,
        other => panic!("unexpected {other:?}"),
    };
    let wrong_key = FileKey::from_bytes([0x99; 32]);
    let e1 = generic(
        VerifiedHeader::verify(&nntune, KeyMode::Random, &wrong_key, &obj.header).unwrap_err(),
    );
    let drive_random = Profile::new("drive/media", &[KeyMode::Random]).unwrap();
    let e2 = generic(
        VerifiedHeader::verify(&drive_random, KeyMode::Random, &obj.key, &obj.header).unwrap_err(),
    );
    assert_eq!(e1, e2, "one generic error, no hint which input was wrong");

    // NNTune allows Random only; unknown mode bytes never parse.
    for mode in [KeyMode::VaultConvergent, KeyMode::PublicConvergent] {
        assert!(VerifiedHeader::verify(&nntune, mode, &obj.key, &obj.header).is_err());
        assert!(!nntune.allows(mode));
    }
    for byte in [0u8, 4, 0x81, 0xff] {
        assert!(KeyMode::from_byte(byte).is_err());
        assert!(VerifiedHeader::verify_record(&nntune, byte, &obj.key, &obj.header).is_err());
    }
    assert!(VerifiedHeader::verify_record(&nntune, 1, &obj.key, &obj.header).is_ok());
    // NNTune may not write convergent objects either.
    let ck = ConvergentKey::vault(&[1; 32], "nntune/media", 0, &digest(&[])).unwrap();
    assert!(Sealer::convergent(&nntune, &ck).is_err());
}

#[test]
fn header_bit_flips_fail_in_record_and_on_the_wire() {
    let obj = random_obj(1000, 10);
    let bytes = obj.header.to_bytes();
    for i in 0..HDR {
        for bit in [0x01u8, 0x80] {
            let mut flipped = bytes;
            flipped[i] ^= bit;
            let h = Header::from_bytes(&flipped);
            assert!(
                VerifiedHeader::verify(&Profile::nntune(), KeyMode::Random, &obj.key, &h).is_err(),
                "record header byte {i}"
            );
            let mut wire = obj.ct.clone();
            wire[i] ^= bit;
            let v = verify(&obj);
            let reader = v.reader(1000).unwrap();
            assert!(reader.verify_all(&wire).is_err(), "wire header byte {i}");
            assert!(reader.check_wire_header(&wire[..HDR]).is_err());
        }
    }
    assert!(Header::from_slice(&bytes[..47]).is_err());
}

#[test]
fn every_byte_bit_flip_is_rejected() {
    let p = 300;
    let obj = random_obj(p, 11);
    let v = verify(&obj);
    let reader = v.reader(p as u64).unwrap();
    for i in 0..obj.ct.len() {
        let mut ct = obj.ct.clone();
        ct[i] ^= 0x04;
        assert!(reader.verify_all(&ct).is_err(), "byte {i}");
        if i >= HDR {
            let mut dst = vec![SENTINEL; p];
            assert!(reader.read_at(&ct, &mut dst, 0).is_err(), "ranged byte {i}");
            assert!(
                dst.iter().all(|&b| b == SENTINEL),
                "byte {i}: nothing released"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Convergent modes
// ---------------------------------------------------------------------------

#[test]
fn convergent_modes_are_deterministic_and_scoped() {
    let profile = Profile::drive();
    let pt = plaintext(70_000, 12);
    let d = digest(&pt);
    let p = pt.len() as u64;
    let seal = |ck: &ConvergentKey| {
        Sealer::convergent(&profile, ck)
            .unwrap()
            .seal_to_vec(&pt)
            .unwrap()
    };
    let vault = |key: [u8; 32]| ConvergentKey::vault(&key, "drive/media", p, &d).unwrap();
    assert_eq!(
        seal(&vault([1; 32])),
        seal(&vault([1; 32])),
        "same vault dedupes"
    );
    assert_ne!(
        seal(&vault([1; 32])),
        seal(&vault([2; 32])),
        "other vault never converges"
    );
    let public = |o: [u8; 64]| ConvergentKey::public(&o, "drive/media", p, &d).unwrap();
    assert_eq!(seal(&public([3; 64])), seal(&public([3; 64])));
    assert_ne!(seal(&public([3; 64])), seal(&vault([3; 32])));

    // Another ctx gives another K and another N.
    let other_profile = Profile::new("other/media", &[KeyMode::VaultConvergent]).unwrap();
    let other = ConvergentKey::vault(&[1; 32], "other/media", p, &d).unwrap();
    let other_ct = Sealer::convergent(&other_profile, &other)
        .unwrap()
        .seal_to_vec(&pt)
        .unwrap();
    assert_ne!(other_ct, seal(&vault([1; 32])));
    // A convergent key may not be sealed under a different profile ctx.
    assert!(Sealer::convergent(&profile, &other).is_err());
}

#[test]
fn convergent_non_derived_nonce_is_rejected() {
    let profile = Profile::drive();
    let pt = plaintext(500, 13);
    let ck = ConvergentKey::vault(&[7; 32], "drive/media", 500, &digest(&pt)).unwrap();
    let key = FileKey::from_bytes(*ck.file_key().expose_secret());
    // A Random-mode encoding under the convergent K: valid commitment for
    // mode Random, but presented as VaultConvergent its N is not derived.
    let rogue = Sealer::random(
        &Profile::new("drive/media", &[KeyMode::Random]).unwrap(),
        &key,
        &mut Counter(3),
    )
    .unwrap();
    let rh = rogue.header();
    assert!(VerifiedHeader::verify(&profile, KeyMode::VaultConvergent, &key, &rh).is_err());
    // The canonical encoding verifies.
    let good = Sealer::convergent(&profile, &ck).unwrap().header();
    VerifiedHeader::verify(&profile, KeyMode::VaultConvergent, &key, &good).unwrap();
}

#[test]
fn toctou_content_change_withholds_the_final_chunk() {
    let profile = Profile::drive();
    let first = plaintext(CHUNK + 10, 14);
    let ck =
        ConvergentKey::vault(&[9; 32], "drive/media", first.len() as u64, &digest(&first)).unwrap();
    // Same length, one byte changed between the hashing pass and sealing.
    let mut changed = first.clone();
    changed[CHUNK + 5] ^= 1;
    let mut s = Sealer::convergent(&profile, &ck).unwrap();
    s.seal_chunk(&changed[..CHUNK], false).unwrap();
    assert!(
        s.seal_chunk(&changed[CHUNK..], true).is_err(),
        "final chunk withheld"
    );
    assert!(s.is_finished());
    assert!(
        s.seal_chunk(&changed[CHUNK..], true).is_err(),
        "no retry after failure"
    );
    // Longer and shorter content.
    let s = Sealer::convergent(&profile, &ck).unwrap();
    assert!(s.seal_to_vec(&first[..CHUNK + 9]).is_err());
    let mut longer = first.clone();
    longer.push(0);
    let s = Sealer::convergent(&profile, &ck).unwrap();
    assert!(s.seal_to_vec(&longer).is_err());
    // Unchanged content seals.
    Sealer::convergent(&profile, &ck)
        .unwrap()
        .seal_to_vec(&first)
        .unwrap();
}

#[test]
fn context_validation_and_k_helpers_reject_bad_ctx() {
    let d = digest(b"x");
    for bad in [
        "",
        "nntune\0media",
        "has space",
        "tab\there",
        "nl\n",
        "é",
        &"a".repeat(256),
    ] {
        assert!(Context::new(bad).is_err(), "{bad:?}");
        assert!(Profile::new(bad, &[KeyMode::Random]).is_err(), "{bad:?}");
        assert!(
            ConvergentKey::vault(&[1; 32], bad, 1, &d).is_err(),
            "vault {bad:?}"
        );
        assert!(
            ConvergentKey::public(&[1; 64], bad, 1, &d).is_err(),
            "public {bad:?}"
        );
        assert!(
            velmora::media::public_oprf_input(bad, 1, &d).is_err(),
            "oprf {bad:?}"
        );
    }
    assert!(Context::new(&"a".repeat(255)).is_ok());
    assert!(Context::new("!~").is_ok());
    assert!(Profile::new("x", &[]).is_err());
}

// ---------------------------------------------------------------------------
// Writer contract
// ---------------------------------------------------------------------------

#[test]
fn sealer_enforces_chunk_shape_and_order() {
    let profile = Profile::nntune();
    let key = FileKey::from_bytes([1; 32]);
    let mut s = Sealer::random(&profile, &key, &mut Counter(0)).unwrap();
    assert!(
        s.seal_chunk(&[0; 10], false).is_err(),
        "short non-final chunk"
    );
    assert!(s.is_finished());
    let mut s = Sealer::random(&profile, &key, &mut Counter(0)).unwrap();
    assert!(
        s.seal_chunk(&vec![0; CHUNK + 1], true).is_err(),
        "oversized final chunk"
    );
    let mut s = Sealer::random(&profile, &key, &mut Counter(0)).unwrap();
    s.seal_chunk(&[0; 5], true).unwrap();
    assert!(
        s.seal_chunk(&[0; 5], true).is_err(),
        "nothing after the final chunk"
    );
    assert_eq!(format!("{key:?}"), "FileKey(<redacted>)");
}

#[test]
fn random_mode_never_repeats_header() {
    let profile = Profile::nntune();
    let key = FileKey::from_bytes([1; 32]);
    let mut rng = velmora::rng::SystemRng;
    let a = Sealer::random(&profile, &key, &mut rng).unwrap().header();
    let b = Sealer::random(&profile, &key, &mut rng).unwrap().header();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.commitment, b.commitment);
}

// ---------------------------------------------------------------------------
// Ranged reads and coordinates
// ---------------------------------------------------------------------------

#[test]
fn ranged_reads_across_chunks_and_articles() {
    let k = velmora::article::ARTICLE_CIPHER_BLOCKS;
    for p in [1usize, CHUNK - 1, CHUNK, CHUNK + 1, (k + 1) * CHUNK + 7] {
        let obj = random_obj(p, 15);
        let v = verify(&obj);
        let reader = v.reader(p as u64).unwrap();
        let boundary = (k * CHUNK).min(p);
        let ranges = [
            (0, p),
            (0, 1),
            (p - 1, 1),
            (CHUNK.min(p) - 1, 2.min(p - (CHUNK.min(p) - 1))),
            (
                boundary.saturating_sub(3),
                6.min(p - boundary.saturating_sub(3)),
            ),
        ];
        for (off, len) in ranges {
            let mut dst = vec![0u8; len];
            let n = reader.read_at(&obj.ct, &mut dst, off as u64).unwrap();
            assert_eq!(n, len, "P {p} off {off}");
            assert_eq!(dst, obj.pt[off..off + len], "P {p} off {off}");
        }
        // Clamped at P, zero at P, error past P.
        let mut big = vec![0u8; 10];
        assert_eq!(reader.read_at(&obj.ct, &mut big, p as u64 - 1).unwrap(), 1);
        assert_eq!(reader.read_at(&obj.ct, &mut big, p as u64).unwrap(), 0);
        assert!(reader.read_at(&obj.ct, &mut big, p as u64 + 1).is_err());
    }
    // P = 0 reads nothing and verifies.
    let empty = random_obj(0, 16);
    let v = verify(&empty);
    let reader = v.reader(0).unwrap();
    assert_eq!(reader.read_at(&empty.ct, &mut [0u8; 4], 0).unwrap(), 0);
    assert_eq!(reader.verify_all(&empty.ct).unwrap(), digest(&[]));
}

/// Article-window source: only the chunks of one article are present, at
/// their object offsets (the stream path fetches one article per range).
struct Window<'a> {
    ct: &'a [u8],
    from: u64,
    to: u64,
}

impl ReadAt for Window<'_> {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        if off < self.from || off >= self.to {
            return Err(io::Error::other("outside the fetched article"));
        }
        let end = (off + buf.len() as u64).min(self.to);
        let n = (end - off) as usize;
        buf[..n].copy_from_slice(&self.ct[off as usize..end as usize]);
        Ok(n)
    }
}

#[test]
fn each_article_decrypts_on_its_own_without_article_zero() {
    let k = velmora::article::ARTICLE_CIPHER_BLOCKS as u64;
    let p = (2 * k * PLAIN_CHUNK_SIZE + 99) as usize;
    let obj = random_obj(p, 17);
    let v = verify(&obj);
    let reader = v.reader(p as u64).unwrap();
    // Article 1 = chunks k..2k, read without touching the header bytes.
    let window = Window {
        ct: &obj.ct,
        from: chunk_offset(k).unwrap(),
        to: chunk_offset(2 * k).unwrap(),
    };
    let off = k * PLAIN_CHUNK_SIZE;
    let len = (k * PLAIN_CHUNK_SIZE) as usize;
    let mut dst = vec![0u8; len];
    assert_eq!(reader.read_at(&window, &mut dst, off).unwrap(), len);
    assert_eq!(dst, obj.pt[off as usize..off as usize + len]);
}

/// Records every requested offset; serves zeros forever.
struct Recording(RefCell<Vec<u64>>);

impl ReadAt for Recording {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        self.0.borrow_mut().push(off);
        buf.fill(0);
        Ok(buf.len())
    }
}

#[test]
fn huge_plaintext_sizes_are_bounded_and_never_wrap() {
    let obj = random_obj(10, 18);
    let v = verify(&obj);
    // P whose object size is not representable is refused up front.
    assert!(v.reader(u64::MAX).is_err());
    assert!(v.reader(u64::MAX - 100).is_err());
    // The largest representable P: reads near the top address the right
    // chunk, never a wrapped low offset, and fail on the forged bytes.
    let (mut lo, mut hi) = (0u64, u64::MAX);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if ciphertext_size(mid).is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let max_p = lo;
    assert!(ciphertext_size(max_p + 1).is_none());
    let reader = v.reader(max_p).unwrap();
    assert!(v.reader(max_p + 1).is_err());
    let src = Recording(RefCell::new(Vec::new()));
    let mut dst = [SENTINEL; 4];
    assert!(reader.read_at(&src, &mut dst, max_p - 2).is_err());
    assert_eq!(dst, [SENTINEL; 4]);
    let offs = src.0.borrow();
    let first_chunk = chunk_offset((max_p - 2) / PLAIN_CHUNK_SIZE).unwrap();
    assert_eq!(offs.first(), Some(&first_chunk));
    assert!(offs.iter().all(|&o| o >= first_chunk), "no wrapped request");
}

/// Short reads (one byte at a time) still decrypt.
struct Trickle<'a>(&'a [u8]);

impl ReadAt for Trickle<'_> {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        if buf.is_empty() || off >= self.0.len() as u64 {
            return Ok(0);
        }
        buf[0] = self.0[off as usize];
        Ok(1)
    }
}

#[test]
fn short_reads_and_lying_sources() {
    let obj = random_obj(200, 19);
    let v = verify(&obj);
    let reader = v.reader(200).unwrap();
    let mut dst = vec![0u8; 200];
    assert_eq!(reader.read_at(&Trickle(&obj.ct), &mut dst, 0).unwrap(), 200);
    assert_eq!(dst, obj.pt);
    assert_eq!(
        reader.verify_all(&Trickle(&obj.ct)).unwrap(),
        digest(&obj.pt)
    );

    struct Lying;
    impl ReadAt for Lying {
        fn read_at(&self, buf: &mut [u8], _off: u64) -> io::Result<usize> {
            Ok(buf.len() + 1)
        }
    }
    let mut dst = [SENTINEL; 8];
    match reader.read_at(&Lying, &mut dst, 0) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
        other => panic!("lying source must be InvalidData, got {other:?}"),
    }
    assert_eq!(dst, [SENTINEL; 8]);
}
