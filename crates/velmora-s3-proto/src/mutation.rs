// Provenance: carved (not verbatim) from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/mutation.rs. License: MIT.
// Source lines taken:
//   - mutation.rs:10-11   `mod control;` and the `pub use control::{...}` re-export
//   - mutation.rs:149-186 `DestinationConditions` (doc comment, struct, impl;
//     the design names 149-185, line 186 is the closing brace of the impl)
//   - mutation.rs:191-203 `MultipartChecksum` and `PartEvidence`
// Edits to the carved lines:
//   - the module doc (mutation.rs:1-8) and the catalogue-bound imports
//     (mutation.rs:13-20) are not copied; the `use` below names only what the
//     carved items need, from `crate::` instead of `super::`;
//   - `DestinationConditions::evaluate` takes the current ETag as `Option<&str>`
//     instead of `Option<&WriteTarget>` (`v.validator != *tag` becomes `v != tag`),
//     and is `pub` (was private) because its only caller in the source file is not
//     copied.
// Everything else in the source file depends on the catalogue and archive
// modules and is not copied, except the two blocks below that carry their own
// provenance notes (`UploadMetadata`, `CommitResult`).

mod control;
pub use control::{completion_result, parse_complete, parse_delete, DeleteRequest};

use std::collections::BTreeMap;

use crate::{
    iso_date_ms, xml, xml_response, ChecksumAlgorithm, ErrorCode, Headers, ObjectMetadata, Policy,
    Response, Result, StoredChecksum, Target,
};

/// Mutation predicates are deliberately limited to strong If-Match or
/// If-None-Match: *. Unknown/multiple/weak predicates are rejected, not ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DestinationConditions {
    pub if_match: Option<String>,
    pub if_none_match: bool,
}

impl DestinationConditions {
    pub fn from_headers(headers: &Headers) -> Result<Self> {
        if headers.get("if-modified-since").is_some()
            || headers.get("if-unmodified-since").is_some()
            || headers.get("if-none-match").is_some_and(|v| v != "*")
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            if_match: headers.get("if-match").map(str::to_owned),
            if_none_match: headers.get("if-none-match").is_some(),
        })
    }

    pub fn evaluate(&self, view: Option<&str>) -> Result<()> {
        if self.if_none_match && self.if_match.is_some() {
            return Err(ErrorCode::InvalidRequest);
        }
        if let Some(tag) = &self.if_match {
            ObjectMetadata::new("predicate".into(), 0, tag.clone(), 0, vec![], None)?;
            if view.is_none_or(|v| v != tag) {
                return Err(ErrorCode::PreconditionFailed);
            }
        }
        if self.if_none_match && view.is_some() {
            return Err(ErrorCode::PreconditionFailed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultipartChecksum {
    None,
    Full(ChecksumAlgorithm),
    CompositeSha256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartEvidence {
    pub number: u16,
    pub etag: String,
    pub checksum: Option<Vec<u8>>,
}

// Provenance: carved from TogetherWeOwn/qerith at commit fc09396c,
// crates/qerith-core/src/s3/mutation.rs lines 107-148 (`UploadMetadata`). License: MIT.
// Re-typed: the archive-only `recovery_ref` and `encryption_context` fields are
// dropped, so `from_headers` takes only the headers; `validate` is folded into it;
// the `aws-chunked` coding is removed from a stored `content-encoding`.

/// Persistent object metadata captured from an upload request (Content-Type and
/// friends, `x-amz-meta-*`), validated with the same rules as stored metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadMetadata {
    pub headers: BTreeMap<String, String>,
}

impl UploadMetadata {
    pub fn from_headers(headers: &Headers) -> Result<Self> {
        headers.validate_features()?;
        let value = Self {
            headers: headers
                .iter()
                .filter(|(k, _)| crate::wire::persistent_metadata(k))
                .filter_map(|(k, v)| {
                    if k != "content-encoding" {
                        return Some((k.to_owned(), v.to_owned()));
                    }
                    // `aws-chunked` is the transfer framing, not a coding of
                    // the stored object: S3 drops it from the metadata.
                    let kept: Vec<_> = v
                        .split(',')
                        .filter(|e| !e.trim().eq_ignore_ascii_case("aws-chunked"))
                        .collect();
                    (!kept.is_empty()).then(|| (k.to_owned(), kept.join(",")))
                })
                .collect(),
        };
        ObjectMetadata::new(
            "validation".into(),
            0,
            "\"validation\"".into(),
            0,
            value.headers.clone().into_iter().collect(),
            None,
        )?;
        Ok(value)
    }
}

// Provenance: carved from TogetherWeOwn/qerith at commit fc09396c,
// crates/qerith-core/src/s3/mutation.rs lines 261-340 (`CommitResult`) and the
// helper `checksum_value` (lines 342-349). License: MIT.
// Re-typed away from the catalogue: the destination `Reference` becomes `bucket` +
// `key`, `GenerationId` is dropped, the catalogue `Checksum` becomes `StoredChecksum`
// (whose value already carries the composite `-N` suffix), and `modified_at` is Unix
// milliseconds rendered at the edge. The module-local `xml`/`xml_response` helpers
// are the crate ones (same CR escaping).

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitResult {
    pub bucket: String,
    pub key: String,
    pub etag: String,
    pub checksum: Option<StoredChecksum>,
    pub modified_ms: i64,
}

/// The answer to UploadPartCopy: the ETag of the part that was stored.
pub fn copy_part_response(etag: &str, modified_ms: i64) -> Result<Response> {
    Ok(xml_response(format!(
        "<CopyPartResult><LastModified>{}</LastModified><ETag>{}</ETag></CopyPartResult>",
        iso_date_ms(modified_ms)?,
        xml(etag)
    )))
}

impl CommitResult {
    /// Render the committed destination, never a caller-selected replacement key.
    /// The policy host is trusted ingress configuration, not a request Host header.
    pub fn complete_response(&self, target: &Target, policy: &Policy) -> Result<Response> {
        let key = target.key.as_deref().ok_or(ErrorCode::InvalidArgument)?;
        if target.bucket != self.bucket || key != self.key {
            return Err(ErrorCode::InvalidArgument);
        }
        let location = format!("https://{}{}", policy.host, target.canonical_path());
        Ok(self.result_response(
            "CompleteMultipartUploadResult",
            &format!(
                "<Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key>",
                xml(&location),
                xml(&target.bucket),
                xml(key)
            ),
        ))
    }

    pub fn copy_response(&self) -> Result<Response> {
        Ok(self.result_response(
            "CopyObjectResult",
            &format!(
                "<LastModified>{}</LastModified>",
                iso_date_ms(self.modified_ms)?
            ),
        ))
    }

    fn result_response(&self, root: &str, fields: &str) -> Response {
        let checksum = self.checksum.as_ref().map_or(String::new(), |c| {
            let name = checksum_name(c.algorithm());
            format!(
                "<Checksum{name}>{}</Checksum{name}><ChecksumType>{}</ChecksumType>",
                xml(c.value()),
                c.checksum_type()
            )
        });
        xml_response(format!(
            "<{root}>{fields}<ETag>{}</ETag>{checksum}</{root}>",
            xml(&self.etag)
        ))
    }

    pub fn put_response(&self) -> Response {
        let mut headers = vec![("etag".into(), self.etag.clone())];
        if let Some(c) = &self.checksum {
            headers.push((c.algorithm().header().into(), c.value().into()));
            headers.push(("x-amz-checksum-type".into(), c.checksum_type().into()));
        }
        Response {
            status: 200,
            headers,
            body: vec![],
        }
    }
}

fn checksum_name(algorithm: ChecksumAlgorithm) -> &'static str {
    algorithm.name()
}
