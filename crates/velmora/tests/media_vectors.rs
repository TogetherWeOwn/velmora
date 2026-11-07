//! `velmora.media.v1` known-answer vectors from an independent
//! implementation (TWO-3698 decision §4.2).
//!
//! `testdata/media-v1/vectors.txt` comes from `gen_vectors.py`, which uses
//! only pyca `cryptography` (OpenSSL HKDF, HMAC and ChaCha20-Poly1305). For
//! every mode, both product contexts and P ∈ {0, 1, 65,535, 65,536, 65,537,
//! 720,896, 720,897, 196,608} this test checks, byte for byte:
//!
//! - the convergent `K` (VaultConvergent from the vault dedupe key,
//!   PublicConvergent from the OPRF output) and the OPRF input encoding;
//! - the header (`N`, commitment) and the whole sealed object: equal to the
//!   generator's bytes for the small objects, equal SHA-256 for the rest;
//! - that opening those exact bytes (full verify and every-chunk ranged
//!   reads) returns the plaintext.
//!
//! The age payload layer itself is pinned against the C2SP CCTV vectors in
//! `src/media.rs` (`cctv_age_stream_vectors`).

use sha2::{Digest, Sha256};
use velmora::media::{
    public_oprf_input, ConvergentKey, FileKey, Header, KeyMode, Profile, Sealer, VerifiedHeader,
    PLAIN_CHUNK_SIZE,
};
use velmora::rng::FillRandom;
use velmora::Result;

const ALL_MODES: &[KeyMode] = &[
    KeyMode::Random,
    KeyMode::VaultConvergent,
    KeyMode::PublicConvergent,
];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

/// Replays fixed bytes as the "CSPRNG" so Random-mode `N` is the vector's.
struct Replay(Vec<u8>);

impl FillRandom for Replay {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        let take: Vec<u8> = self.0.drain(..dest.len()).collect();
        dest.copy_from_slice(&take);
        Ok(())
    }
}

fn plaintext(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn records() -> Vec<Vec<(String, String)>> {
    let text = include_str!("../testdata/media-v1/vectors.txt");
    text.split("\n\n")
        .map(|block| {
            block
                .lines()
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                .map(|l| {
                    let (k, v) = l.split_once('=').unwrap();
                    (k.to_owned(), v.to_owned())
                })
                .collect::<Vec<_>>()
        })
        .filter(|r| !r.is_empty())
        .collect()
}

#[test]
fn independent_vectors_match_byte_for_byte() {
    let records = records();
    assert_eq!(records.len(), 3 * 2 * 8, "every mode x ctx x size record");
    for rec in records {
        let get = |k: &str| {
            rec.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("missing {k}"))
        };
        let mode = KeyMode::from_byte(get("mode").parse().unwrap()).unwrap();
        let ctx = get("ctx");
        let size: u64 = get("p").parse().unwrap();
        let label = format!("mode {mode:?} ctx {ctx} P {size}");
        let pt = plaintext(size as usize);
        let digest: [u8; 32] = Sha256::digest(&pt).into();
        assert_eq!(digest, arr::<32>(get("d")), "{label}: D");
        let profile = Profile::new(ctx, ALL_MODES).unwrap();

        let (key_bytes, sealer) = match mode {
            KeyMode::Random => {
                let key = FileKey::from_bytes(arr(get("k")));
                let sealer = Sealer::random(&profile, &key, &mut Replay(hex(get("n")))).unwrap();
                (*key.expose_secret(), sealer)
            }
            KeyMode::VaultConvergent => {
                let ck = ConvergentKey::vault(&arr(get("vault_dedupe_key")), ctx, size, &digest)
                    .unwrap();
                (
                    *ck.file_key().expose_secret(),
                    Sealer::convergent(&profile, &ck).unwrap(),
                )
            }
            KeyMode::PublicConvergent => {
                assert_eq!(
                    public_oprf_input(ctx, size, &digest).unwrap(),
                    hex(get("oprf_input")),
                    "{label}: OPRF input"
                );
                let ck =
                    ConvergentKey::public(&arr(get("oprf_output")), ctx, size, &digest).unwrap();
                (
                    *ck.file_key().expose_secret(),
                    Sealer::convergent(&profile, &ck).unwrap(),
                )
            }
        };
        assert_eq!(key_bytes, arr::<32>(get("k")), "{label}: K");
        let header = sealer.header();
        assert_eq!(header.nonce, arr::<16>(get("n")), "{label}: N");
        assert_eq!(
            header.commitment,
            arr::<32>(get("commitment")),
            "{label}: commitment"
        );

        let object = sealer.seal_to_vec(&pt).unwrap();
        assert_eq!(
            object.len() as u64,
            get("ct_len").parse::<u64>().unwrap(),
            "{label}"
        );
        let ct_sha: [u8; 32] = Sha256::digest(&object).into();
        assert_eq!(ct_sha, arr::<32>(get("ct_sha256")), "{label}: ciphertext");
        if let Some((_, ct)) = rec.iter().find(|(k, _)| k == "ct") {
            assert_eq!(object, hex(ct), "{label}: full ciphertext");
        }

        // `object` is now proven equal to the generator's bytes; open them.
        let key = FileKey::from_bytes(arr(get("k")));
        let parsed = Header::from_slice(&object[..48]).unwrap();
        let verified = VerifiedHeader::verify(&profile, mode, &key, &parsed).unwrap();
        let reader = verified.reader(size).unwrap();
        assert_eq!(
            reader.verify_all(&object).unwrap(),
            digest,
            "{label}: verify_all"
        );
        let mut all = vec![0u8; pt.len()];
        assert_eq!(reader.read_at(&object, &mut all, 0).unwrap(), pt.len());
        assert_eq!(all, pt, "{label}: full read");
        // One byte from every chunk, and the first/last byte.
        let mut offsets: Vec<u64> = (0..size).step_by(PLAIN_CHUNK_SIZE as usize).collect();
        offsets.extend(size.checked_sub(1));
        for off in offsets {
            let mut one = [0u8; 1];
            assert_eq!(reader.read_at(&object, &mut one, off).unwrap(), 1);
            assert_eq!(one[0], pt[off as usize], "{label}: byte {off}");
        }
    }
}
