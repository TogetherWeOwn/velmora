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
untrusted input before deserialization. Complete provider operations remain pending.

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

`nntp::ClientIo` borrows an admitted authenticated client and races each command
against event-driven control. Interruption invalidates the session without
waiting for cleanup or sending QUIT; BODY and STAT retain the read failure.
This slice exposes no archive POST operation. A caller owns the cleanup budget and must retain
its lease/account charge until physical closure is independently confirmed.
Even successful shutdown can be only a write-half shutdown, and dropping the
client or transport may only request asynchronous close. For Worker pinned TLS,
retain `WorkerSocketControl` until its close succeeds; pending or failed close
confirmation does not release capacity. Dropping a command is neither rollback
nor closure proof.

These are interface obligations, not an implementation of authorization,
transport closure or output verification. Consumer integration and the complete
provider trait remain pending; no physical deletion or eviction API is provided.
