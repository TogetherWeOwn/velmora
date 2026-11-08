# Archive provider v1 (experimental, default off)

Enable the **compile-time** `archive-provider` feature for
`velmora::archive::v1`. It adds no dependencies, networking, credentials, runtime,
installation or enabled product call site. S3 additionally requires an explicit
`enabled` configuration. This is a fixture-development contract, not provider
qualification, production enablement or a supported-product announcement.

## Boundaries

- Archive provider: opaque ciphertext object operations, immutable locators,
  integrity checks and bounded transfer through an injected transport.
- Media: the existing `media::VerifiedHeader`, commitment-before-decrypt,
  chunk-authenticated reader and per-chunk pre-seal gate. Archive hashes do not
  replace these mechanisms or prove that arbitrary input is valid ciphertext.
- Product: authenticated authority, account admission/pool leases, durable jobs,
  operation/outbox transactions, current fences, retention, moderation, upload
  admission, cancellation subscriptions, restore publication and serving pins.
- R2: the common temporary/hot/staging/cache/delivery layer for **both** archive
  backends, implemented by each product. No R2 permanent-archive fallback exists.
- Public REST/MCP/S3 clients: independent ingress/protocol adapters. In particular,
  a product's client-facing S3 catalogue/read adapter is not an outbound archive
  storage transport, and an archive receipt is not an authorized download URL.

Write-target policy is product-owned and separate from old-object read routing.
Resolve every old object's backend, account, locator, version and crypto identity
from its trusted record, not today's new-write selection. A read-only NNTP
adapter remains possible while new writes select S3. Missing/disabled S3 fails
closed, never substitutes another account/backend or authorizes new charges.

## Rust API bridge

`API_VERSION = 1`. `ArchiveProvider` exposes:

- `capabilities()`;
- `begin(&WriteIntent, &impl Control) -> Result<WriteSession>`;
- `write_part(&WriteSession, index, &[u8], &impl Control) -> Result<PartReceipt>`;
- `commit(&WriteSession, &[PartReceipt], &impl Control) -> Result<WriteProof>`;
- `abort(&WriteSession, &impl Control) -> Result<AbortOutcome>`;
- `stat(&ObjectRecord, &impl Control) -> Result<ObjectIdentity>`;
- `read_range(&ObjectRecord, Range, &mut impl Sink, &impl Control)`;
- `reconcile(&WriteSession, &impl Control) -> Result<Reconciled>`;
- `health(&Target, &impl Control) -> Result<Health>`.

All operations except capabilities are async. These are portable generic traits,
not object-safe interfaces or a requirement for `Send` in Workers. The API version
names persisted bindings as well as Rust types; breaking persisted semantics
require a new version, not interpreting an old record through a new write policy.
Pin an exact reviewed source SHA when adopting it; do not float consumer branches.

`Target` binds tenant, backend, stable account, immutable allocation/generation,
encryption format/mode/key epoch/envelope reference. **Account is an immutable
routing-configuration identity, not a login name.** It must bind endpoint,
region, bucket and logical credential binding; changing those storage coordinates
mints a new identity while retaining the old lookup for old objects. Credential
rotation through the same scoped reference must not redirect old objects.
`ObjectIdentity` adds the exact remote version, ciphertext length and SHA-256.
`cache_key()` includes all these fields with domain-separated length prefixes;
it is internal, never a public validator, existence oracle or authorization.
Encryption references contain no keys, OPRF output, private dedupe digest or secret.

The caller computes a complete bounded manifest from its staged ciphertext,
not a client-asserted digest. Persist the exact intent and operation binding before
I/O, the remote upload/session before parts, and each receipt before acknowledging
it. `Id` serializes access-controlled references, not secrets; Debug redacts it.
Bound and authorize serialized metadata before decoding: Rust validation cannot
undo an unbounded allocation already made by an external JSON decoder.

## Retry, cancellation and reconciliation

There is no automatic retry loop or hidden account/backend fallback. The product
owns durable attempt/byte/time budgets and bounded backoff. `Transient` permits
scheduling a bounded attempt, not an unlimited retry. `Uncertain` means remote
work may have happened: preserve the original intent/session/receipts, reconcile
under current authority and never auto-abort, reallocate or publish success.
Changed content under the same part/intent conflicts before effects.

`Control` is trusted current authority plus cancellation/deadline/resource checks,
not a deserialized request boolean. Boundary checks run before I/O and after it;
transports additionally enforce those controls *inside* I/O. `Control::cancelled`
is a required event-driven future for the exact target/action; it must register
cancellation, current-policy revocation and deadline wakeups before rechecking
policy, including when the socket never progresses. `ClientIo` races every NNTP
operation against it and rechecks authority on each poll and after completion;
revocation drops the command then invalidates and shuts down the client without
sending QUIT into an incomplete exchange. A failed or dropped shutdown is not
close proof: the product retains the lease and owns physical-close confirmation.
Dropping a future is not remote rollback or physical-close proof. Pool slots remain charged until
socket closure/settlement is proven. A late cancellation after completion is
uncertain, not "nothing committed". The product's own journal/outbox must survive
process loss; the library's serializable values are not a database implementation.

`Absent` requires settlement of every issued request. A HEAD/STAT 404 alone cannot
prove quiescence. An NNTP partial post/propagation failure always remains uncertain,
never absent. `abort` removes at most incomplete S3 multipart staging, not a
completed object or another attempt. NNTP abort is explicitly irreversible; there
is no article-erasure claim. Logical delete/tombstone is catalogue work. No
physical-delete API or timer-based cache eviction is provided.

## Transfer/resource limits

At most 10,000 unique contiguous parts, each at most 8 MiB; arithmetic and supplied
lengths are checked. S3 non-final multipart parts require at least 5 MiB. Zero
length is one explicit empty part. Ranges use offset + byte count, checked against
the committed length before I/O; a zero-byte range is valid at EOF.

A range fetch verifies every covering **whole ciphertext part** before emitting
its requested slice to `Sink` in at most 64 KiB blocks. Buffers are bounded by a
part, not by the range or whole object; range amplification can be one full part
for a one-byte request. A sink error/cancellation can leave an earlier verified
prefix, which must stay invisible staging, never a complete published object.
S3 supplies a fixed output slice to its transport. NNTP preserves the existing
configured wire cap (hard maximum 64 MiB) and bounded decoded destination. NNTP
posting temporarily holds the encoded body and assembled article in addition to
the caller's part; these are bounded, not zero-copy or measured memory claims.

## Executable adapter semantics and proof limits

### NNTP

`nntp::Provider<Io>` renders a persisted `PostingPlan` using the existing
`article::ArticleHeaders`, `yenc::encode_segment`, and assembler. Mint obfuscated
fields once with `article::obfuscate_article`; retries reuse those fields and
Message-IDs. `ClientIo` borrows an already leased/authenticated `NntpClient<T>`:
POST and BODY run through its existing framing, correlation, bounds and connection
poisoning. The client/pool/optimized batch APIs are unchanged. Other products may
implement `Io` through their existing broker without creating a second pool.

POST/duplicate acknowledgement is not durability. Commit reconstructs all parts,
checks yEnc CRCs and SHA-256/length, and hashes the complete ciphertext. STAT is
presence-only metadata from the trusted manifest. The receipt is one account's
ciphertext readback observation, **not** independent backbone evidence, client
media authentication, future retention, PAR2 repair or eviction permission.
Existing exact-generation, two-independently-established-backbone full
reconstruction and authenticated-readability safety proof remains mandatory.

### S3-compatible archive

`s3::Provider<SafeTransport>` executes CreateMultipartUpload, UploadPart,
CompleteMultipartUpload, exact-version HEAD/GET range, incomplete abort and
reconciliation through the injected transport, not just a configuration enum.
Only explicitly configured HTTPS:443 endpoints are supported. The transport
resolves/vets/pins public peers, signs through the credential reference, refuses
redirects and enforces response/body/deadline/cancellation limits. Host syntax
validation here is not DNS/peer qualification. There is no shipped live signer,
HTTP implementation, credential resolution or provider probe in this slice.

The safe transport journals stable operation/request/upload IDs; completion is
create-only and checks embedded S3 XML errors as well as HTTP status. Only
versioned buckets with a non-null immutable VersionId are supported. UploadPart
must acknowledge the submitted SHA-256; ETags remain opaque. A supplied full-object
SHA-256 must match. A multipart **composite** checksum is never misrepresented as
the full-object digest. Regardless of checksum availability/type, commit and
successful reconciliation read every part from that exact version, verify each
part and compute the full SHA-256 before returning a proof. Ranged replies must
match exact version, offset, total and count; corruption/over-return releases no
bytes from that part. Successful remote completion followed by failed readback
remains uncertain and retains the safety copy.

This is backend-specific acknowledgement/version/ciphertext-readback evidence,
not a supplier durability SLA, client cryptographic readability, future retention,
Object Lock/legal-hold support or an invented two-backbone equivalent. Products
must retain their existing safety-copy requirements until independently reviewed
S3-specific qualification and retention policy are accepted. A health result only
indicates adapter availability, never whole-object safety.

## Evidence and operations

`tests/archive_provider.rs` and its generated client script cover bounded identity,
configuration, ranges, corrupt/over-returned bytes, tenant rejection, receipt
binding, lost responses, same-session retry, serialized-session restart, partial
NNTP propagation, irreversible abort and real client POST/BODY plus real yEnc.
All bytes/transcripts are generated in code; no stored media or NZB fixtures.
These are fixture assertions, not live-provider receipts or product acceptance.
Full checks run only on exact-head GitHub Actions, including feature-on native
clippy/tests, portable wasm and MSRV. Independent security/crypto and consumer
integration receipts remain separate gates.

No staging/preview runtime, alarm, schedule, keep-alive, container or compute is
created; idle runtime cost is zero because this library installs no runtime.
No production change, migration, data deletion, supplier qualification or
provider activation is authorized by compiling the feature.
