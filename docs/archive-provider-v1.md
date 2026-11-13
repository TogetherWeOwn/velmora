# Archive identities v1

The archive boundary concerns opaque ciphertext objects and bounded transfer.
Media authentication and commitment-before-decrypt remain separate obligations;
an archive hash or receipt does not establish valid media or authorize a download.
The product owns authentication, account admission, durable jobs, cancellation,
retention and publication. Temporary or delivery caches are not permanent archive
fallbacks. Client-facing REST, MCP and S3 interfaces are independent ingress
adapters, not outbound archive transports.

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

`Control` declares the bridge from trusted product authority to each exact
`Target` and `Action`; neither serialized records nor client-supplied flags
confer authority. Live transports must enforce cancellation and revocation
throughout I/O, register the wake source before checking policy, and retain
leases until physical closure is proven. Checks at operation boundaries alone
cannot undo remote effects. `Sink` declares that only complete-part-verified
ciphertext is emitted in blocks of at most 64 KiB; callers must stage prefixes
invisibly because an error or cancellation can leave an incomplete output.

`ArchiveProvider` declares capabilities, begin, part write, commit, abort,
stat, range read, reconcile and health. Except for capabilities, operations are
async and take trusted control; the trait is generic, not object-safe, and does
not require `Send`. No method has a default implementation. A write proof is an
observation, not an eviction permit or durability guarantee; an absent reconcile
result is valid only after issued requests settle. No physical deletion or
eviction operation is provided.

Implementations must check authority before and after I/O and enforce it while
I/O is pending. Begin, part write, commit and reconcile require `Write`; abort
requires `AbortIncomplete`; stat and range read require `Read`; health requires
`Health`. Proof readback remains under the enclosing write authority as well as
read authority; sink writes remain under read authority. A lost response
or cancellation after a possible remote effect is uncertain: preserve the same
intent and session, reconcile before a bounded retry, and never automatically
abort, reallocate or report success. No alternate account or cache fallback is
permitted.

These are interface obligations, not an implementation of authorization,
revocation, transport closure or output verification. Provider adapters and
consumer integration are still pending. Each first implementation of an operation
must include its positive and negative tenant/action isolation and event-driven
revocation tests alongside the operation.
