//! Journal inputs for stable NNTP posting metadata, not a provider or I/O.

use super::{Failure, Id, Result};
use crate::article;
use serde::{Deserialize, Serialize};

/// Persist before POST together with the intent. Mint these fields with
/// `article::obfuscate_article` once, not afresh on retry. No payload is stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostHeaders {
    pub message_id: Id,
    pub from: Id,
    pub subject: Id,
    pub date: String,
    pub newsgroup: Id,
    pub yenc_name: Id,
}

impl PostHeaders {
    pub fn from_obfuscated(value: &article::ObfuscatedArticle) -> Result<Self> {
        let result = Self {
            message_id: Id::new(value.message_id.clone())?,
            from: Id::new(value.from.clone())?,
            subject: Id::new(value.subject.clone())?,
            date: value.date.clone(),
            newsgroup: Id::new(value.newsgroup.clone())?,
            yenc_name: Id::new(value.yenc_name.clone())?,
        };
        result.render()?;
        Ok(result)
    }

    /// Validate and render the exact persisted header values.
    pub fn render(&self) -> Result<Vec<u8>> {
        if self.date.len() > 128 {
            return Err(Failure::Invalid);
        }
        article::ArticleHeaders::new(
            self.from.as_str(),
            &[self.newsgroup.as_str()],
            self.subject.as_str(),
            &self.date,
            self.message_id.as_str(),
        )
        .and_then(|headers| headers.render())
        .map_err(|_| Failure::Invalid)
    }
}

/// Persist with the intent; consumers must validate the binding and headers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostingPlan {
    pub intent_binding: [u8; 32],
    pub headers: Vec<PostHeaders>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> article::ObfuscatedArticle {
        article::ObfuscatedArticle {
            message_id: "part@example.invalid".into(),
            from: "sender@example.invalid".into(),
            subject: "subject".into(),
            date: "Thu, 1 Jan 1970 00:00:00 +0000".into(),
            newsgroup: "alt.test".into(),
            yenc_name: "payload".into(),
        }
    }

    #[test]
    fn headers_round_trip_and_render_stably() {
        let headers = PostHeaders::from_obfuscated(&metadata()).unwrap();
        let plan = PostingPlan {
            intent_binding: [7; 32],
            headers: vec![headers.clone()],
        };
        let decoded: PostingPlan =
            serde_json::from_str(&serde_json::to_string(&plan).unwrap()).unwrap();
        assert_eq!(decoded, plan);
        assert_eq!(decoded.headers[0].render(), headers.render());
        assert_eq!(
            headers.render().unwrap(),
            article::render_obfuscated_headers(&metadata()).unwrap()
        );
    }

    #[test]
    fn headers_reject_invalid_fields_and_deserialized_dates() {
        let mut value = metadata();
        value.message_id = "bad id".into();
        assert_eq!(PostHeaders::from_obfuscated(&value), Err(Failure::Invalid));
        value = metadata();
        value.newsgroup = "bad/group".into();
        assert_eq!(PostHeaders::from_obfuscated(&value), Err(Failure::Invalid));
        let mut headers = PostHeaders::from_obfuscated(&metadata()).unwrap();
        headers.date = "x".repeat(129);
        assert_eq!(headers.render(), Err(Failure::Invalid));
        headers.date = "date\r\nInjected: value".into();
        let decoded: PostHeaders =
            serde_json::from_str(&serde_json::to_string(&headers).unwrap()).unwrap();
        assert_eq!(decoded.render(), Err(Failure::Invalid));
    }
}
