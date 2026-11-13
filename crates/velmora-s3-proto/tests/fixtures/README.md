# Fixture provenance

`s3-static.json` and `published-crypto.json` are copied byte-for-byte from
TogetherWeOwn/qerith at commit fc09396c, original paths
`crates/qerith-core/tests/fixtures/s3-static.json` and
`crates/qerith-core/tests/fixtures/published-crypto.json`. License: MIT.

They are test vectors, not credentials: `published-crypto.json` holds
published vectors (RFC 4231 HMAC-SHA256 and a botocore SigV4 example, each
with its source URL), and `s3-static.json` holds static request and
canonical-request cases for the contract test.
