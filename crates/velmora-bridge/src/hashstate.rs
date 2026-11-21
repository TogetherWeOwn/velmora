//! A running SHA-256 and MD5 of one byte stream that can leave a request
//! and go on in the next.
//!
//! A drill of a byte range (`POST /_admin/drill`, `range=`) hashes that
//! range only. To get the digests of a whole object out of several such
//! requests, each answer carries the state of both hashes after its last
//! byte as a token, and the request for the bytes that follow hands it
//! back: its `running` digests are then those of everything from the
//! first request on.
//!
//! The token is not a secret of the bridge and is not authenticated. A
//! token that was changed, or that is handed to a request for other
//! bytes than those that follow, gives digests that match nothing; it
//! cannot make a wrong read look right, because the digests are compared
//! with ones the caller has from elsewhere.
//!
//! A token carries the bytes the hashes have not yet compressed: up to
//! 63 of the last plaintext bytes it covers. It goes only to a caller
//! that may read the object.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use md_5::Md5;
use sha2::digest::common::hazmat::{SerializableState, SerializedState};
use sha2::{Digest, Sha256};

/// First bytes of a decoded token: the layout that follows.
const VERSION: &[u8; 2] = b"h1";

/// The longest token text [`Running::from_token`] looks at.
pub const MAX_TOKEN_LEN: usize = 512;

/// SHA-256 and MD5 over the same bytes, and how many there were.
#[derive(Clone, Default)]
pub struct Running {
    bytes: u64,
    sha256: Sha256,
    md5: Md5,
}

impl Running {
    pub fn update(&mut self, data: &[u8]) {
        self.bytes = self.bytes.saturating_add(data.len() as u64);
        self.sha256.update(data);
        self.md5.update(data);
    }

    /// Bytes hashed so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The digests of the bytes so far; the hashes go on after it.
    pub fn digests(&self) -> ([u8; 32], [u8; 16]) {
        (
            self.sha256.clone().finalize().into(),
            self.md5.clone().finalize().into(),
        )
    }

    /// The state as text for a query string.
    pub fn token(&self) -> String {
        let sha256 = self.sha256.serialize();
        let md5 = self.md5.serialize();
        let mut raw = Vec::with_capacity(VERSION.len() + 8 + sha256.len() + md5.len());
        raw.extend_from_slice(VERSION);
        raw.extend_from_slice(&self.bytes.to_be_bytes());
        raw.extend_from_slice(&sha256);
        raw.extend_from_slice(&md5);
        URL_SAFE_NO_PAD.encode(raw)
    }

    /// The state a token of [`Self::token`] carries. `None`: not such a
    /// token.
    pub fn from_token(token: &str) -> Option<Running> {
        if token.len() > MAX_TOKEN_LEN {
            return None;
        }
        let raw = URL_SAFE_NO_PAD.decode(token).ok()?;
        let rest = raw.strip_prefix(VERSION.as_slice())?;
        let (bytes, rest) = rest.split_first_chunk::<8>()?;
        let sha_len = SerializedState::<Sha256>::default().len();
        if rest.len() < sha_len {
            return None;
        }
        let (sha256, md5) = rest.split_at(sha_len);
        let sha256 = SerializedState::<Sha256>::try_from(sha256).ok()?;
        let md5 = SerializedState::<Md5>::try_from(md5).ok()?;
        Some(Running {
            bytes: u64::from_be_bytes(*bytes),
            sha256: Sha256::deserialize(&sha256).ok()?,
            md5: Md5::deserialize(&md5).ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_stream_hashed_in_pieces_across_tokens_has_the_digests_of_the_whole() {
        let data: Vec<u8> = (0..200_003u32).map(|i| (i * 31 % 251) as u8).collect();
        // Cuts inside a block, on a block edge, and an empty piece.
        for cuts in [
            vec![1usize],
            vec![64, 64, 128],
            vec![63, 100_000],
            vec![0, 199_999],
        ] {
            let mut run = Running::default();
            let mut at = 0;
            for cut in cuts.iter().copied().chain([data.len()]) {
                let cut = cut.max(at);
                run.update(&data[at..cut]);
                at = cut;
                run = Running::from_token(&run.token()).expect("own token");
            }
            let (sha256, md5) = run.digests();
            assert_eq!(run.bytes(), data.len() as u64);
            assert_eq!(sha256, <[u8; 32]>::from(Sha256::digest(&data)));
            assert_eq!(md5, md5::compute(&data).0);
        }
    }

    #[test]
    fn known_digests() {
        let mut run = Running::default();
        run.update(b"abc");
        let (sha256, md5) = run.digests();
        assert_eq!(
            hex(&sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex(&md5), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn text_that_is_no_token_is_refused() {
        let good = Running::default().token();
        assert!(Running::from_token(&good).is_some());
        assert!(Running::from_token("").is_none());
        assert!(Running::from_token("not base64 !").is_none());
        assert!(Running::from_token(&good[..good.len() - 4]).is_none());
        assert!(Running::from_token(&format!("{good}AAAA")).is_none());
        let other = URL_SAFE_NO_PAD.encode(b"h2 some other layout");
        assert!(Running::from_token(&other).is_none());
        assert!(Running::from_token(&"A".repeat(MAX_TOKEN_LEN + 1)).is_none());
    }

    #[test]
    fn a_token_fits_a_query_string() {
        let mut run = Running::default();
        run.update(&[7u8; 63]);
        assert!(run.token().len() <= MAX_TOKEN_LEN);
    }
}
