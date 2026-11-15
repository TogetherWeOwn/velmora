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

use crate::crypto::{seal_extent, DataKey, SealedExtent};
use crate::ingress::{Charge, IngressError, UploadLengths};
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
    /// Sealing or the store failed. Slices stored so far stay.
    Store,
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

impl<B: BlobStore, R: FillRandom> SliceSink<'_, B, R> {
    /// Seals `plain` as slice `stored.len()` and stores it.
    async fn store(
        &mut self,
        plain: &[u8],
        stored: &mut Vec<StoredSlice>,
    ) -> Result<(), SliceError> {
        let id = self.ids.get(stored.len()).ok_or(SliceError::Store)?;
        let mut sealed = seal_extent(self.bdk, self.bucket, id, plain, self.rng)
            .map_err(|_| SliceError::Store)?;
        let ciphertext = std::mem::take(&mut sealed.ciphertext);
        let cipher_size = ciphertext.len() as u64;
        self.safety
            .put(
                &id.safety_key(),
                ciphertext,
                &BlobMeta {
                    bucket: self.bucket,
                    extent: id,
                    cipher_sha256: &sealed.cipher_sha256,
                },
            )
            .await
            .map_err(|_| SliceError::Store)?;
        stored.push(StoredSlice {
            plain_size: plain.len() as u64,
            cipher_size,
            sealed,
        });
        Ok(())
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
    let slice = usize::try_from(sink.slice_bytes).map_err(|_| SliceError::Store)?;
    let count = lengths.decoded.div_ceil(sink.slice_bytes.max(1));
    if slice == 0
        || charge.bytes() < sink.slice_bytes.saturating_mul(2)
        || validator.decoded_length() != lengths.decoded
        || count != sink.ids.len() as u64
    {
        return Err(SliceError::Store);
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
