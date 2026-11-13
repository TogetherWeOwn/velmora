# Archive identities v1

Write-target policy belongs to the product, separate from old-object read
routing. Resolve an old object's backend, account, locator, version and crypto
identity from its trusted record, not today's write selection. Missing or
disabled storage must fail closed, not substitute another account or backend.

`Target` binds tenant, backend, stable account, immutable allocation/generation,
and encryption format, mode, key epoch and envelope reference. Account is an
immutable routing-configuration identity, not a login name: it binds endpoint,
region, bucket and logical credential binding. Changing those coordinates mints
a new identity while preserving the old lookup; rotating a credential through
the same scoped reference must not redirect old objects. Encryption references
contain no keys, OPRF output, private dedupe digest or secret.

`ObjectIdentity` adds exact remote version, ciphertext length and SHA-256.
`cache_key()` includes every coordinate with domain separation and length
prefixes. It is internal, not a public validator, existence oracle, serving
grant or authorization decision. A digest alone does not authenticate media.
These serializable records are not proof of durability; callers must bound
untrusted input before deserialization. Provider operations are not implemented.

`WriteIntent::validate` accepts at most 10,000 uniquely referenced, contiguous
parts of at most 8 MiB each and checks their combined length. An empty object
uses one explicit empty part. Callers must compute the manifest from staged
ciphertext and bound and authorize serialized metadata before decoding it;
validation after deserialization cannot prevent an unbounded decoder allocation.
Validation does not establish digest correctness or durability.

`Range::end` checks offset plus byte count against the committed length before
I/O, including arithmetic overflow. A zero-byte range is valid at EOF; validation
of a range is not authorization to read the object.
