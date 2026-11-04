//! OriginalSourceV1: one backed file in a shared `track_sources` row.
//! This is private source metadata, not a media cipher or a public manifest.
//! The API owns seal/open; ingest and stream never receive its keys.

use std::collections::HashSet;
use std::fmt;

use serde::{
    de::{self, value::MapAccessDeserializer, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

use crate::nzb::{self, File};

pub mod reader;

pub const PAYLOAD_FORMAT: i16 = 1;
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_RECORD_BYTES + 16;
pub const MAX_ARTICLE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_ARTICLES: usize = 4096;
pub const MAX_REFERENCE_BYTES: usize = 998;

/// Errors intentionally never carry a source value or a parser diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    Shape,
    Bounds,
    Binding,
    Integrity,
    Range,
    Cancelled,
    Transport,
}

/// Optional geometry only. It gains no authority until actual first/final
/// articles corroborate it; every subsequently fetched part is checked too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RangeHint {
    pub part_size: u64,
    pub final_begin: u64,
    pub final_end: u64,
}

impl<'de> Deserialize<'de> for RangeHint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            part_size: u64,
            final_begin: u64,
            final_end: u64,
        }
        let fields: Fields = deserialize_object(d)?;
        Ok(Self {
            part_size: fields.part_size,
            final_begin: fields.final_begin,
            final_end: fields.final_end,
        })
    }
}

#[derive(Clone, Serialize)]
pub struct Article {
    number: usize,
    reference: String,
    encoded_bytes: u64,
}

impl<'de> Deserialize<'de> for Article {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            number: usize,
            reference: String,
            encoded_bytes: u64,
        }
        let fields: Fields = deserialize_object(d)?;
        Ok(Self {
            number: fields.number,
            reference: fields.reference,
            encoded_bytes: fields.encoded_bytes,
        })
    }
}

impl Article {
    pub fn number(&self) -> usize {
        self.number
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
}

/// No Debug or public Deserialize: callers cannot bypass the bounded parser.
#[derive(Clone, Serialize)]
pub struct OriginalSource {
    track_id: String,
    source_job_id: String,
    file_ordinal: usize,
    file_size: u64,
    article_count: usize,
    articles: Vec<Article>,
    range_hint: Option<RangeHint>,
}

struct SourceRecord {
    track_id: String,
    source_job_id: String,
    file_ordinal: usize,
    file_size: u64,
    article_count: usize,
    articles: Vec<Article>,
    range_hint: Option<RangeHint>,
}

impl<'de> Deserialize<'de> for SourceRecord {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            track_id: String,
            source_job_id: String,
            file_ordinal: usize,
            file_size: u64,
            article_count: usize,
            #[serde(deserialize_with = "bounded_articles")]
            articles: Vec<Article>,
            range_hint: Option<RangeHint>,
        }
        let fields: Fields = deserialize_object(d)?;
        Ok(Self {
            track_id: fields.track_id,
            source_job_id: fields.source_job_id,
            file_ordinal: fields.file_ordinal,
            file_size: fields.file_size,
            article_count: fields.article_count,
            articles: fields.articles,
            range_hint: fields.range_hint,
        })
    }
}

// Derived structs also accept positional sequences. Require a map first, then
// retain derived field/type/duplicate checks without buffering a generic value.
fn deserialize_object<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("source object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }
    d.deserialize_map(Object(std::marker::PhantomData))
}

fn bounded_articles<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Article>, D::Error> {
    struct Articles;
    impl<'de> Visitor<'de> for Articles {
        type Value = Vec<Article>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bounded article sequence")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            // Never reserve a stored size_hint/count. A rejected extra element
            // is bounded independently and never grows the sequence past N.
            let mut out = Vec::new();
            while let Some(article) = seq.next_element()? {
                if out.len() == MAX_ARTICLES {
                    return Err(de::Error::custom("source bounds"));
                }
                out.push(article);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Articles)
}

pub fn canonical_track_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

pub fn valid_source_job(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl OriginalSource {
    /// Trusted producer seam. The caller must select the winning persisted
    /// track/job and verify its natural identity before calling this function.
    /// It must never accept a browser-selected file ordinal.
    pub fn from_file(
        track_id: &str,
        source_job_id: &str,
        file: &File,
        file_size: u64,
        range_hint: Option<RangeHint>,
    ) -> Result<Self, SourceError> {
        if !canonical_track_id(track_id) || !valid_source_job(source_job_id) {
            return Err(SourceError::Binding);
        }
        if file.role != "content" || file.container != "flac" {
            return Err(SourceError::Binding);
        }
        if file.segments.len() > MAX_ARTICLES {
            return Err(SourceError::Bounds);
        }
        let mut articles = Vec::new();
        for (i, s) in file.segments.iter().enumerate() {
            if s.ordinal != i || s.number != i + 1 {
                return Err(SourceError::Shape);
            }
            // Check before cloning even a caller-constructed parser File.
            if s.message_id.len() > MAX_REFERENCE_BYTES {
                return Err(SourceError::Bounds);
            }
            articles.push(Article {
                number: s.number,
                reference: s.message_id.clone(),
                encoded_bytes: u64::try_from(s.encoded_bytes).map_err(|_| SourceError::Shape)?,
            });
        }
        let out = Self {
            track_id: track_id.into(),
            source_job_id: source_job_id.into(),
            file_ordinal: file.ordinal,
            file_size,
            article_count: articles.len(),
            articles,
            range_hint,
        };
        out.validate()?;
        Ok(out)
    }

    pub fn track_id(&self) -> &str {
        &self.track_id
    }
    pub fn source_job_id(&self) -> &str {
        &self.source_job_id
    }
    pub fn file_ordinal(&self) -> usize {
        self.file_ordinal
    }
    pub fn file_size(&self) -> u64 {
        self.file_size
    }
    pub fn article_count(&self) -> usize {
        self.articles.len()
    }
    pub fn article(&self, index: usize) -> Result<&Article, SourceError> {
        self.articles.get(index).ok_or(SourceError::Bounds)
    }
    pub fn range_hint(&self) -> Option<RangeHint> {
        self.range_hint
    }

    fn validate(&self) -> Result<(), SourceError> {
        if !canonical_track_id(&self.track_id) || !valid_source_job(&self.source_job_id) {
            return Err(SourceError::Shape);
        }
        if self.file_ordinal >= nzb::MAX_FILES
            || self.file_size == 0
            || self.file_size > MAX_FILE_BYTES
            || self.articles.is_empty()
            || self.articles.len() > MAX_ARTICLES
        {
            return Err(SourceError::Bounds);
        }
        if self.article_count != self.articles.len() {
            return Err(SourceError::Shape);
        }
        let mut sum = 0u64;
        let mut seen = HashSet::new();
        for (i, a) in self.articles.iter().enumerate() {
            if a.number != i + 1
                || a.reference.len() > MAX_REFERENCE_BYTES
                || a.encoded_bytes == 0
                || a.encoded_bytes > MAX_ARTICLE_BYTES as u64
            {
                return Err(SourceError::Shape);
            }
            let normalized =
                nzb::normalize_message_id(&a.reference).map_err(|_| SourceError::Shape)?;
            if normalized != a.reference || !seen.insert(a.reference.as_str()) {
                return Err(SourceError::Shape);
            }
            sum = sum
                .checked_add(a.encoded_bytes)
                .ok_or(SourceError::Bounds)?;
            if sum > MAX_FILE_BYTES {
                return Err(SourceError::Bounds);
            }
        }
        // A bad hint is discarded by the reader, not confused with corrupt
        // actual media. It cannot influence allocation or direct slicing.
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, SourceError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SourceError::Shape)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(SourceError::Bounds);
        }
        Ok(bytes)
    }

    /// Fixed-shape parsing after authenticated open. Lexical preflight caps
    /// strings (including escaped input) and depth before serde can allocate.
    pub fn parse(
        format: i16,
        bytes: &[u8],
        track_id: &str,
        source_job_id: &str,
    ) -> Result<Self, SourceError> {
        if format != PAYLOAD_FORMAT {
            return Err(SourceError::Shape);
        }
        preflight_json(bytes)?;
        let record: SourceRecord = serde_json::from_slice(bytes).map_err(|_| SourceError::Shape)?;
        let source = Self {
            track_id: record.track_id,
            source_job_id: record.source_job_id,
            file_ordinal: record.file_ordinal,
            file_size: record.file_size,
            article_count: record.article_count,
            articles: record.articles,
            range_hint: record.range_hint,
        };
        source.validate()?;
        if source.track_id != track_id || source.source_job_id != source_job_id {
            return Err(SourceError::Binding);
        }
        Ok(source)
    }
}

fn preflight_json(bytes: &[u8]) -> Result<(), SourceError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(SourceError::Bounds);
    }
    std::str::from_utf8(bytes).map_err(|_| SourceError::Shape)?;
    let (mut i, mut depth) = (0, 0usize);
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let start = i;
                i += 1;
                loop {
                    let b = *bytes.get(i).ok_or(SourceError::Shape)?;
                    if i - start > 6 * MAX_REFERENCE_BYTES + 1 {
                        return Err(SourceError::Bounds);
                    }
                    i += 1;
                    if b == b'"' {
                        break;
                    }
                    if b == b'\\' {
                        // Skip one escaped byte only; serde validates Unicode
                        // and escapes in this bounded token below.
                        i = i
                            .checked_add(1)
                            .filter(|&n| n <= bytes.len())
                            .ok_or(SourceError::Shape)?;
                    }
                }
                let s: String =
                    serde_json::from_slice(&bytes[start..i]).map_err(|_| SourceError::Shape)?;
                if s.len() > MAX_REFERENCE_BYTES {
                    return Err(SourceError::Bounds);
                }
            }
            b'{' | b'[' => {
                depth += 1;
                if depth > 3 {
                    return Err(SourceError::Bounds);
                }
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(SourceError::Shape)?;
                i += 1;
            }
            b'0'..=b'9' | b'-' => {
                let start = i;
                while bytes.get(i).is_some_and(|b| {
                    b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-')
                }) {
                    i += 1;
                    if i - start > 20 {
                        return Err(SourceError::Bounds);
                    }
                }
            }
            _ => i += 1,
        }
    }
    if depth != 0 {
        return Err(SourceError::Shape);
    }
    Ok(())
}
