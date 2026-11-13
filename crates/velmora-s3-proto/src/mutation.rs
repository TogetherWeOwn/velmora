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
// modules and is not copied.

mod control;
pub use control::{completion_result, parse_complete, parse_delete, DeleteRequest};

use crate::{ChecksumAlgorithm, ErrorCode, Headers, ObjectMetadata, Result};

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
