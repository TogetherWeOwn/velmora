//! A request body stored as slices: each slice is sealed as its own
//! extent and put into `SAFETY` while the rest of the body is still on
//! the wire. Only one slice of plaintext and one of ciphertext are held
//! at a time, whatever the length of the body.
//!
//! Nothing here publishes: the caller recorded the extent ids before the
//! first put and decides after `validator.finish()` what becomes of the
//! slices.

use futures_util::StreamExt;
use velmora::rng::FillRandom;
use velmora_s3_proto::{ErrorCode, UploadValidator};
use zeroize::Zeroize;

use crate::crypto::{seal_extent, DataKey, SealedExtent};
use crate::ingress::{Charge, IngressError, UploadLengths};
use crate::metrics::Fault;
use crate::ports::{BlobMeta, BlobStore};
use crate::types::{Body, BucketId, ExtentId};

/// Most encoded bytes handed to the validator at once. What it decodes
/// from them is at most as long, so the buffer below never holds more
/// than one slice and one piece.
const PIECE_BYTES: usize = 64 * 1024;

/// Why a body could not be stored as slices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SliceError {
    /// A transport or length refusal.
    Ingress(IngressError),
    /// The validator refused the body (framing, signature, digest).
    Proto(ErrorCode),
    /// The blob store failed, the last attempt with this fault. Slices
    /// stored so far stay.
    Store(Fault),
    /// A seal or local invariant failed.
    Internal,
}

impl From<IngressError> for SliceError {
    fn from(e: IngressError) -> Self {
        SliceError::Ingress(e)
    }
}

impl From<ErrorCode> for SliceError {
    fn from(e: ErrorCode) -> Self {
        SliceError::Proto(e)
    }
}

/// One stored slice: what its extent row needs. The ciphertext is in
/// `SAFETY` under the extent's key.
pub(super) struct StoredSlice {
    pub(super) plain_size: u64,
    pub(super) cipher_size: u64,
    pub(super) sealed: SealedExtent,
}

/// Where the slices go and how they are sealed.
pub(super) struct SliceSink<'a, B: BlobStore, R: FillRandom> {
    pub(super) safety: &'a B,
    pub(super) bdk: &'a DataKey,
    pub(super) bucket: &'a BucketId,
    /// One id per slice, in body order; each has its intent row.
    pub(super) ids: &'a [ExtentId],
    /// Plaintext bytes of every slice but the last.
    pub(super) slice_bytes: u64,
    pub(super) rng: &'a mut R,
}

/// Puts of one slice before the write fails. A put is safe to send
/// again: the key is the slice's own, and every attempt carries the same
/// bytes.
const PUT_ATTEMPTS: usize = 3;

/// Most bytes one seal may draw. A seal draws a file key, a stream
/// nonce and a wrap nonce, 72 bytes in all.
const REPLAY_CAP: usize = 128;

/// Randomness that can be drawn a second time. `put` takes the
/// ciphertext, so a put that is sent again needs the slice sealed
/// again, and it must come out byte for byte the same: an earlier
/// attempt whose answer was lost may still land, before or after the
/// later one, and the extent row must describe whichever is stored.
struct Replay<'a, R: FillRandom> {
    rng: &'a mut R,
    /// What the first seal drew: a file key among it. It is allocated
    /// once with room for `REPLAY_CAP` bytes and never grows: a buffer
    /// that grows is copied to a new place, and the old place is freed
    /// with the key still in it.
    drawn: Vec<u8>,
    at: usize,
}

impl<'a, R: FillRandom> Replay<'a, R> {
    fn new(rng: &'a mut R) -> Self {
        Self {
            rng,
            drawn: Vec::with_capacity(REPLAY_CAP),
            at: 0,
        }
    }
}

impl<R: FillRandom> FillRandom for Replay<'_, R> {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        let have = self.drawn.get(self.at..).unwrap_or_default();
        let n = have.len().min(dest.len());
        let (old, new) = dest.split_at_mut(n);
        old.copy_from_slice(&have[..n]);
        if !new.is_empty() {
            // Refused before a byte is drawn: the buffer stays where
            // it is.
            if self.drawn.len() + new.len() > REPLAY_CAP {
                return Err(velmora::Error::Bounds {
                    bound: "randomness of one seal",
                    limit: REPLAY_CAP as i64,
                });
            }
            let room = self.drawn.capacity();
            self.rng.fill_bytes(new)?;
            self.drawn.extend_from_slice(new);
            debug_assert_eq!(self.drawn.capacity(), room);
        }
        self.at += n + new.len();
        Ok(())
    }
}

impl<R: FillRandom> Drop for Replay<'_, R> {
    fn drop(&mut self) {
        self.drawn.zeroize();
    }
}

impl<B: BlobStore, R: FillRandom> SliceSink<'_, B, R> {
    /// Seals `plain` as slice `stored.len()` and stores it.
    async fn store(
        &mut self,
        plain: &[u8],
        stored: &mut Vec<StoredSlice>,
    ) -> Result<(), SliceError> {
        let id = self.ids.get(stored.len()).ok_or(SliceError::Internal)?;
        let mut rng = Replay::new(&mut *self.rng);
        let mut fault = Fault::named("NoAttempt");
        for _ in 0..PUT_ATTEMPTS {
            rng.at = 0;
            let mut sealed = seal_extent(self.bdk, self.bucket, id, plain, &mut rng)
                .map_err(|_| SliceError::Internal)?;
            let ciphertext = std::mem::take(&mut sealed.ciphertext);
            let cipher_size = ciphertext.len() as u64;
            let put = self
                .safety
                .put(
                    &id.safety_key(),
                    ciphertext,
                    &BlobMeta {
                        bucket: self.bucket,
                        extent: id,
                        cipher_sha256: &sealed.cipher_sha256,
                    },
                )
                .await;
            match put {
                Ok(()) => {
                    stored.push(StoredSlice {
                        plain_size: plain.len() as u64,
                        cipher_size,
                        sealed,
                    });
                    return Ok(());
                }
                Err(e) => fault = Fault::of(&e),
            }
        }
        Err(SliceError::Store(fault))
    }
}

/// Reads the body through `validator` and stores it as `sink.ids.len()`
/// slices. The lengths are checked as in [`crate::ingress::read_upload`]:
/// with `Content-Length` the stream carries exactly that many bytes. The
/// caller still calls `validator.finish()`, and must treat every stored
/// slice as unpublished until it has.
///
/// `charge` covers one slice of plaintext and one of ciphertext.
pub(super) async fn store_slices<B: BlobStore, R: FillRandom>(
    mut sink: SliceSink<'_, B, R>,
    body: Body,
    lengths: UploadLengths,
    charge: &Charge,
    validator: &mut UploadValidator,
) -> Result<Vec<StoredSlice>, SliceError> {
    let slice = usize::try_from(sink.slice_bytes).map_err(|_| SliceError::Internal)?;
    let count = lengths.decoded.div_ceil(sink.slice_bytes.max(1));
    if slice == 0
        || charge.bytes() < sink.slice_bytes.saturating_mul(2)
        || validator.decoded_length() != lengths.decoded
        || count != sink.ids.len() as u64
    {
        return Err(SliceError::Internal);
    }
    let piece = PIECE_BYTES.min(slice);
    let mut stored = Vec::with_capacity(sink.ids.len());
    let mut plain: Vec<u8> = Vec::with_capacity(slice + piece);
    let mut received: u64 = 0;
    if let Body::Stream { mut stream, .. } = body {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| IngressError::IncompleteBody)?;
            received = received.saturating_add(chunk.len() as u64);
            if lengths.encoded.is_some_and(|n| received > n) {
                return Err(IngressError::EntityTooLarge.into());
            }
            for encoded in chunk.chunks(piece) {
                validator.push_body(encoded, &mut |decoded| plain.extend_from_slice(decoded))?;
                while plain.len() >= slice {
                    sink.store(&plain[..slice], &mut stored).await?;
                    plain.drain(..slice);
                }
            }
        }
    }
    if lengths.encoded.is_some_and(|n| received != n) {
        return Err(IngressError::IncompleteBody.into());
    }
    if !plain.is_empty() {
        sink.store(&plain, &mut stored).await?;
    }
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts up from zero: the next byte is the number of bytes drawn.
    struct Count(u8);

    impl FillRandom for Count {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
            for b in dest {
                *b = self.0;
                self.0 += 1;
            }
            Ok(())
        }
    }

    /// Where the buffer is and how much it holds.
    fn place<R: FillRandom>(rng: &Replay<'_, R>) -> (*const u8, usize) {
        (rng.drawn.as_ptr(), rng.drawn.capacity())
    }

    /// The buffer holds a file key. It must stay in the one place it
    /// was allocated at, so that the wipe on drop reaches every copy.
    #[test]
    fn replayed_randomness_stays_in_one_buffer() {
        let bdk = DataKey::from_bytes([7; 32]);
        let (bucket, id) = (BucketId::new("b_1"), ExtentId::new("x_1"));
        let mut inner = Count(0);
        let mut rng = Replay::new(&mut inner);
        let at_first = place(&rng);
        assert!(at_first.1 >= REPLAY_CAP);

        let first = seal_extent(&bdk, &bucket, &id, b"slice", &mut rng).unwrap();
        // A file key, a stream nonce and a wrap nonce.
        assert_eq!(rng.drawn.len(), 32 + 16 + 24);
        assert_eq!(place(&rng), at_first);

        // The second seal draws the same bytes and nothing new.
        rng.at = 0;
        let second = seal_extent(&bdk, &bucket, &id, b"slice", &mut rng).unwrap();
        assert!(first.ciphertext == second.ciphertext);
        assert!(first.wrapped_file_key == second.wrapped_file_key);
        assert_eq!(rng.drawn.len(), 32 + 16 + 24);
        assert_eq!(place(&rng), at_first);
        drop(rng);
        assert_eq!(inner.0, 32 + 16 + 24);
    }

    #[test]
    fn a_draw_past_the_buffer_is_refused_before_anything_is_drawn() {
        let mut inner = Count(0);
        let mut rng = Replay::new(&mut inner);
        let at_first = place(&rng);

        // The buffer takes exactly what it was allocated for.
        let mut all = [0u8; REPLAY_CAP];
        rng.fill_bytes(&mut all).unwrap();
        assert_eq!(rng.drawn.len(), REPLAY_CAP);
        let mut one = [0xaa];
        assert!(rng.fill_bytes(&mut one).is_err());
        assert_eq!(one, [0xaa]);

        // A draw that is partly a replay is refused as a whole.
        rng.at = REPLAY_CAP - 8;
        let mut both = [0xaa; 16];
        assert!(rng.fill_bytes(&mut both).is_err());
        assert_eq!(both[8..], [0xaa; 8]);
        assert_eq!(rng.at, REPLAY_CAP - 8);

        assert_eq!(rng.drawn.len(), REPLAY_CAP);
        assert_eq!(place(&rng), at_first);
        drop(rng);
        assert_eq!(usize::from(inner.0), REPLAY_CAP);
    }
}
