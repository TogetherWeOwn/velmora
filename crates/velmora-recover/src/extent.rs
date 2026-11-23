//! Assemble only hash-verified articles, and release only digest-verified plaintext.

use sha2::{Digest, Sha256};
use velmora::{media, rs, yenc};
use velmora_bridge::{
    articles::article_spans,
    config::MAX_EXTENT_BYTES_LIMIT,
    crypto::{self, DataKey},
    types::{BucketId, ExtentId},
};
use zeroize::Zeroizing;

/// Bounds even a worst-case escaped yEnc body, including framing.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct Article {
    pub message_id: String,
    pub sha256: [u8; 32],
    pub yenc_name: Option<String>,
    pub newsgroup: String,
}

pub struct Parity {
    pub k: usize,
    pub shard_len: usize,
    pub rows: Vec<(u16, Article)>,
}

pub struct Extent {
    pub id: ExtentId,
    pub bucket: BucketId,
    pub plain_size: u64,
    pub cipher_size: u64,
    pub media_header: [u8; 48],
    pub wrapped_file_key: [u8; crypto::WRAPPED_KEY_LEN],
    pub plain_md5: [u8; 16],
    pub plain_sha256: [u8; 32],
    pub cipher_sha256: [u8; 32],
    /// Empty if and only if the authenticated kit has no usable plan.
    pub articles: Vec<Article>,
    pub parity: Option<Parity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentError {
    NotPosted,
    InvalidPlan,
    MissingArticle,
    InvalidCiphertext,
    AuthenticationFailed,
    InvalidPlaintext,
}

impl std::fmt::Display for ExtentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotPosted => "extent has no usable Usenet plan",
            Self::InvalidPlan => "invalid extent or article plan",
            Self::MissingArticle => "article missing or corrupt after retries and parity recovery",
            Self::InvalidCiphertext => "extent ciphertext SHA-256 mismatch",
            Self::AuthenticationFailed => "extent key, header or media authentication failed",
            Self::InvalidPlaintext => "extent plaintext digest mismatch",
        })
    }
}

impl std::error::Error for ExtentError {}

#[derive(Clone, Copy)]
pub struct Placement {
    pub offset: u64,
    pub len: usize,
    pub total: u64,
    pub number: u64,
    pub parity: bool,
}

pub trait BodySource {
    /// Upper bound on attempts to retrieve and verify an article. Sources may
    /// visit multiple providers, but never count an unverified body as a hit.
    fn attempts(&self) -> usize {
        2
    }

    fn body(
        &mut self,
        message_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, FetchError>>;

    /// Called after a failed retrieval or a rejected candidate.
    fn rejected(&mut self) {}

    fn candidate(
        &mut self,
        article: &Article,
        place: Placement,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, FetchError>> {
        async move { decode_candidate(self.body(&article.message_id).await?, article, place) }
    }
}

fn decode_candidate(
    wire: Vec<u8>,
    article: &Article,
    place: Placement,
) -> Result<Vec<u8>, FetchError> {
    if wire.len() > MAX_BODY_BYTES {
        return Err(FetchError::Unavailable);
    }
    let mut bytes = vec![0; place.len];
    let decoded = yenc::decode_part_to(&article.message_id, &wire, &mut bytes)
        .map_err(|_| FetchError::Unavailable)?;
    let geometry_ok = if decoded.multipart {
        !place.parity
            && article.yenc_name.is_none()
            && decoded.file_size == place.total
            && decoded.offset == place.offset
            && decoded.part_number == Some(place.number)
    } else {
        // Legacy rows may omit the filename even for a standalone post.
        decoded.file_size == place.len as u64 && decoded.offset == 0
    };
    if !geometry_ok || decoded.written != place.len {
        return Err(FetchError::Unavailable);
    }
    Ok(bytes)
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn valid_message_id(id: &str) -> bool {
    id.len() <= 250
        && id
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'<' && b != b'>')
        && id
            .split_once('@')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && !b.contains('@'))
}

async fn fetch(
    source: &mut impl BodySource,
    article: &Article,
    place: Placement,
) -> Option<Vec<u8>> {
    for _ in 0..source.attempts() {
        if let Ok(bytes) = source.candidate(article, place).await {
            if bytes.len() == place.len && sha256(&bytes) == article.sha256 {
                return Some(bytes);
            }
        }
        source.rejected();
    }
    None
}

impl Extent {
    pub fn validate(&self) -> Result<(), ExtentError> {
        if self.plain_size > MAX_EXTENT_BYTES_LIMIT
            || media::ciphertext_size(self.plain_size) != Some(self.cipher_size)
        {
            return Err(ExtentError::InvalidPlan);
        }
        if self.articles.is_empty() {
            return Err(ExtentError::NotPosted);
        }
        let spans = article_spans(self.cipher_size);
        if spans.len() != self.articles.len()
            || self
                .articles
                .iter()
                .any(|a| !valid_message_id(&a.message_id))
        {
            return Err(ExtentError::InvalidPlan);
        }
        if let Some(p) = &self.parity {
            let mut seen = std::collections::BTreeSet::new();
            if p.k != spans.len()
                || Some(p.shard_len) != rs::shard_len(spans.iter().map(|s| s.len as usize))
                || p.rows.is_empty()
                || p.rows.len() > rs::MAX_PARITY_SHARDS
                || p.rows.iter().any(|(row, a)| {
                    *row > rs::MAX_PARITY_ROW
                        || !seen.insert(*row)
                        || !valid_message_id(&a.message_id)
                })
            {
                return Err(ExtentError::InvalidPlan);
            }
        }
        Ok(())
    }
}

pub async fn open_extent(
    source: &mut impl BodySource,
    bdk: &DataKey,
    extent: &Extent,
) -> Result<Zeroizing<Vec<u8>>, ExtentError> {
    extent.validate()?;
    let file_key =
        crypto::unwrap_file_key(bdk, &extent.bucket, &extent.id, &extent.wrapped_file_key)
            .map_err(|_| ExtentError::AuthenticationFailed)?;
    let header = media::Header::from_bytes(&extent.media_header);
    let verified = media::VerifiedHeader::verify(
        &crypto::profile(),
        media::KeyMode::Random,
        &file_key,
        &header,
    )
    .map_err(|_| ExtentError::AuthenticationFailed)?;
    let reader = verified
        .reader(extent.plain_size)
        .map_err(|_| ExtentError::AuthenticationFailed)?;

    let spans = article_spans(extent.cipher_size);
    let mut cipher = vec![0; extent.cipher_size as usize];
    let mut lost = Vec::new();
    for (i, (span, article)) in spans.iter().zip(&extent.articles).enumerate() {
        let place = Placement {
            offset: span.start,
            len: span.len as usize,
            total: extent.cipher_size,
            number: (i + 1) as u64,
            parity: false,
        };
        if let Some(bytes) = fetch(source, article, place).await {
            cipher[span.start as usize..][..place.len].copy_from_slice(&bytes);
        } else {
            lost.push(i);
        }
    }
    if !lost.is_empty() {
        let parity = extent
            .parity
            .as_ref()
            .filter(|p| p.rows.len() >= lost.len())
            .ok_or(ExtentError::MissingArticle)?;
        let mut shards = Vec::new();
        for (row, article) in &parity.rows {
            let place = Placement {
                offset: 0,
                len: parity.shard_len,
                total: parity.shard_len as u64,
                number: 1,
                parity: true,
            };
            if let Some(bytes) = fetch(source, article, place).await {
                shards.push((*row, bytes));
                if shards.len() == lost.len() {
                    break;
                }
            }
        }
        let parity_shards: Vec<_> = shards
            .iter()
            .map(|(row, bytes)| rs::ParityShard { row: *row, bytes })
            .collect();
        let data: Vec<_> = spans
            .iter()
            .enumerate()
            .map(|(i, span)| {
                let len = span.len as usize;
                if lost.binary_search(&i).is_ok() {
                    rs::DataShard::Lost { len }
                } else {
                    rs::DataShard::Present(&cipher[span.start as usize..][..len])
                }
            })
            .collect();
        let rebuilt =
            rs::reconstruct(&data, &parity_shards).map_err(|_| ExtentError::MissingArticle)?;
        for (i, bytes) in lost.into_iter().zip(rebuilt) {
            let span = spans[i];
            if bytes.len() != span.len as usize || sha256(&bytes) != extent.articles[i].sha256 {
                return Err(ExtentError::MissingArticle);
            }
            cipher[span.start as usize..][..bytes.len()].copy_from_slice(&bytes);
        }
    }
    if sha256(&cipher) != extent.cipher_sha256 {
        return Err(ExtentError::InvalidCiphertext);
    }
    reader
        .check_wire_header(&cipher[..extent.media_header.len()])
        .map_err(|_| ExtentError::AuthenticationFailed)?;

    let mut plaintext = Zeroizing::new(vec![0; extent.plain_size as usize]);
    if plaintext.is_empty() {
        // read_at does not open chunks for empty ranges. The final empty tag
        // must still authenticate before an empty object can be recovered.
        reader
            .verify_all(cipher.as_slice())
            .map_err(|_| ExtentError::AuthenticationFailed)?;
    } else if reader
        .read_at(cipher.as_slice(), &mut plaintext, 0)
        .map_err(|_| ExtentError::AuthenticationFailed)?
        != plaintext.len()
    {
        return Err(ExtentError::AuthenticationFailed);
    }
    if sha256(&plaintext) != extent.plain_sha256 || md5::compute(&plaintext).0 != extent.plain_md5 {
        return Err(ExtentError::InvalidPlaintext);
    }
    Ok(plaintext)
}
