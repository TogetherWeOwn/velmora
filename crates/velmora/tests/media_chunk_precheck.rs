//! Public contract for opening an already-fetched sealed chunk with a precheck.

use std::cell::Cell;

use sha2::{Digest, Sha256};
use velmora::media::{
    chunk_offset, FileKey, KeyMode, Profile, Sealer, VerifiedHeader, HEADER_SIZE, PLAIN_CHUNK_SIZE,
    TAG_SIZE,
};
use velmora::rng::FillRandom;
use velmora::{Error, Result};
use zeroize::Zeroizing;

const CHUNK: usize = PLAIN_CHUNK_SIZE as usize;
const TAG: usize = TAG_SIZE as usize;

struct Counter(u8);

impl FillRandom for Counter {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        for byte in dest {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

fn object(plaintext: &[u8]) -> (VerifiedHeader, Vec<u8>) {
    let profile = Profile::nntune();
    let key = FileKey::generate(&mut Counter(1)).unwrap();
    let sealer = Sealer::random(&profile, &key, &mut Counter(101)).unwrap();
    let header = sealer.header();
    let wire = sealer.seal_to_vec(plaintext).unwrap();
    let verified = VerifiedHeader::verify(&profile, KeyMode::Random, &key, &header).unwrap();
    (verified, wire)
}

fn sealed(wire: &[u8], index: u64, plain_len: usize) -> Vec<u8> {
    let start = chunk_offset(index).unwrap() as usize;
    wire[start..start + plain_len + TAG].to_vec()
}

#[test]
fn opens_chunks_and_precheck_sees_all_ciphertext_and_tag() {
    let plaintext: Vec<u8> = (0..CHUNK + 37).map(|i| (i % 251) as u8).collect();
    let (verified, wire) = object(&plaintext);
    let reader = verified.reader(plaintext.len() as u64).unwrap();

    for (index, expected) in [(0, &plaintext[..CHUNK]), (1, &plaintext[CHUNK..])] {
        let input = sealed(&wire, index, expected.len());
        let called = Cell::new(0);
        let opened: Zeroizing<Vec<u8>> = reader
            .open_chunk_with_precheck(index, input.clone(), |bytes| {
                called.set(called.get() + 1);
                assert_eq!(bytes, input.as_slice());
                assert_eq!(bytes.len(), expected.len() + TAG);
                assert_eq!(&bytes[bytes.len() - TAG..], &input[input.len() - TAG..]);
                Ok(())
            })
            .unwrap();
        assert_eq!(called.get(), 1);
        assert_eq!(opened.as_slice(), expected);
    }
}

#[test]
fn opens_empty_and_exact_boundary_final_chunks() {
    for size in [0, CHUNK, 2 * CHUNK] {
        let plaintext = vec![0x5a; size];
        let (verified, wire) = object(&plaintext);
        let reader = verified.reader(size as u64).unwrap();
        let index = if size == 0 {
            0
        } else {
            (size / CHUNK - 1) as u64
        };
        let expected = if size == 0 {
            &plaintext[..]
        } else {
            &plaintext[size - CHUNK..]
        };
        let input = sealed(&wire, index, expected.len());
        if size == 0 {
            assert_eq!(wire.len(), HEADER_SIZE as usize + TAG);
            assert_eq!(input.len(), TAG);
        }
        let called = Cell::new(false);
        let opened = reader
            .open_chunk_with_precheck(index, input.clone(), |bytes| {
                called.set(true);
                assert_eq!(bytes, input.as_slice());
                Ok(())
            })
            .unwrap();
        assert!(called.get());
        assert_eq!(opened.as_slice(), expected);
    }
}

#[test]
fn rejecting_precheck_returns_no_plaintext() {
    let plaintext = b"precheck must approve this ciphertext";
    let (verified, wire) = object(plaintext);
    let reader = verified.reader(plaintext.len() as u64).unwrap();
    let input = sealed(&wire, 0, plaintext.len());
    let called = Cell::new(false);
    let result = reader.open_chunk_with_precheck(0, input.clone(), |bytes| {
        called.set(true);
        assert_eq!(bytes, input.as_slice());
        Err(Error::Malformed("precheck rejected".into()))
    });
    assert!(called.get());
    assert!(matches!(result, Err(Error::Malformed(message)) if message == "precheck rejected"));
}

#[test]
fn tampered_ciphertext_and_tag_are_visible_to_precheck_but_not_opened() {
    let plaintext = b"authenticated data";
    let (verified, wire) = object(plaintext);
    let reader = verified.reader(plaintext.len() as u64).unwrap();
    let original = sealed(&wire, 0, plaintext.len());
    for offset in [0, original.len() - 1] {
        let mut tampered = original.clone();
        tampered[offset] ^= 1;
        let called = Cell::new(false);
        let result = reader.open_chunk_with_precheck(0, tampered.clone(), |bytes| {
            called.set(true);
            assert_eq!(bytes, tampered.as_slice());
            Ok(())
        });
        assert!(called.get());
        assert!(result.is_err());
    }
}

#[test]
fn digest_approval_cannot_override_authentication_and_empty_is_checked() {
    for plaintext in [&b""[..], &b"payload"[..]] {
        let (verified, wire) = object(plaintext);
        let reader = verified.reader(plaintext.len() as u64).unwrap();
        let mut input = sealed(&wire, 0, plaintext.len());
        let expected = Sha256::digest(&input);
        assert!(reader
            .open_chunk_with_precheck(0, input.clone(), |bytes| {
                if Sha256::digest(bytes) != expected {
                    return Err(Error::Malformed("digest mismatch".into()));
                }
                Ok(())
            })
            .is_ok());
        *input.last_mut().unwrap() ^= 1;
        assert!(reader
            .open_chunk_with_precheck(0, input.clone(), |bytes| {
                if Sha256::digest(bytes) != expected {
                    return Err(Error::Malformed("digest mismatch".into()));
                }
                Ok(())
            })
            .is_err());
        let tampered_digest = Sha256::digest(&input);
        assert!(reader
            .open_chunk_with_precheck(0, input, |bytes| {
                assert_eq!(Sha256::digest(bytes), tampered_digest);
                Ok(())
            })
            .is_err());
    }
}

#[test]
fn wrong_trusted_size_changes_finality_and_fails_authentication() {
    let plaintext = vec![0x42; CHUNK];
    let (verified, wire) = object(&plaintext);
    let reader = verified.reader((CHUNK + 1) as u64).unwrap();
    let input = sealed(&wire, 0, CHUNK);
    assert!(reader
        .open_chunk_with_precheck(0, input, |_| Ok(()))
        .is_err());
    assert!(verified.reader(u64::MAX).is_err());
}

#[test]
fn invalid_lengths_and_indices_do_not_reach_precheck() {
    let plaintext = vec![0x42; CHUNK + 7];
    let (verified, wire) = object(&plaintext);
    let reader = verified.reader(plaintext.len() as u64).unwrap();
    let first = sealed(&wire, 0, CHUNK);
    let last = sealed(&wire, 1, 7);
    let mut long = last.clone();
    long.push(0);
    for (index, input) in [
        (0, first[..first.len() - 1].to_vec()),
        (1, last[..last.len() - 1].to_vec()),
        (1, long),
        (1, first.clone()),
        (2, last.clone()),
        (u64::MAX, last),
    ] {
        let called = Cell::new(false);
        let result = reader.open_chunk_with_precheck(index, input, |_| {
            called.set(true);
            Ok(())
        });
        assert!(result.is_err(), "index {index}");
        assert!(
            !called.get(),
            "invalid geometry reached precheck for index {index}"
        );
    }
}

#[test]
fn chunk_index_is_authenticated_even_for_equal_length_chunks() {
    let plaintext = vec![0x35; 2 * CHUNK];
    let (verified, wire) = object(&plaintext);
    let reader = verified.reader(plaintext.len() as u64).unwrap();
    for (wrong_index, input) in [(0, sealed(&wire, 1, CHUNK)), (1, sealed(&wire, 0, CHUNK))] {
        let called = Cell::new(false);
        let result = reader.open_chunk_with_precheck(wrong_index, input.clone(), |bytes| {
            called.set(true);
            assert_eq!(bytes, input.as_slice());
            Ok(())
        });
        assert!(called.get());
        assert!(result.is_err());
    }
}
